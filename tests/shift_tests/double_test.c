#include "../tests.h"

int32_t curve25519_key_x2_test(void) {
	printf("Key Doubling Test\n");
	curve25519_key_t k1 = {.key64 = {
		0x411BA059A5F36B63ULL,
		0xC7EEDEC9039C3EE4ULL,
		0xF94C9FF25AE413BDULL,
		0xCE2676C3D55EF8E7ULL,
		0x56EA1C94B2E1240DULL,
		0x07CD962AAD029681ULL,
		0xBF8DBDE5EE0672B3ULL,
		0x1CD09D36DCC52B62ULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0x823740B34BE6D6C6ULL,
		0x8FDDBD9207387DC8ULL,
		0xF2993FE4B5C8277BULL,
		0x9C4CED87AABDF1CFULL,
		0xADD4392965C2481BULL,
		0x0F9B2C555A052D02ULL,
		0x7F1B7BCBDC0CE566ULL,
		0x39A13A6DB98A56C5ULL
	}};
	curve25519_key_t r = {};
	printf("Test Case 1\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	int32_t res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 1 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -1;
	} else {
		printf("Test Case 1 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBE7A5948DF64BF20ULL,
		0x12BA543B0C82692EULL,
		0xFE7AAEFA054AE967ULL,
		0xFBB2AF122D53EC2DULL,
		0x904BFDA32365B3C2ULL,
		0x2DD55CDB4EADF125ULL,
		0x6914C63718C91676ULL,
		0x36D2B5CC846B2C40ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7CF4B291BEC97E40ULL,
		0x2574A8761904D25DULL,
		0xFCF55DF40A95D2CEULL,
		0xF7655E245AA7D85BULL,
		0x2097FB4646CB6785ULL,
		0x5BAAB9B69D5BE24BULL,
		0xD2298C6E31922CECULL,
		0x6DA56B9908D65880ULL
	}};
	printf("Test Case 2\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 2 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -2;
	} else {
		printf("Test Case 2 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB7BA690824E1A8C9ULL,
		0x5829D1D5C9AB602BULL,
		0x7DA30B709E51C6B0ULL,
		0x2444EF18CD7B3D77ULL,
		0xE9800E2312BD65B5ULL,
		0x992933464929AD02ULL,
		0x34B72219A812C573ULL,
		0x2E862451CDF61467ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6F74D21049C35192ULL,
		0xB053A3AB9356C057ULL,
		0xFB4616E13CA38D60ULL,
		0x4889DE319AF67AEEULL,
		0xD3001C46257ACB6AULL,
		0x3252668C92535A05ULL,
		0x696E443350258AE7ULL,
		0x5D0C48A39BEC28CEULL
	}};
	printf("Test Case 3\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 3 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -3;
	} else {
		printf("Test Case 3 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x427E5FF8DE8AAC6FULL,
		0x649A80A4B0508106ULL,
		0x655BF26B0680E3B8ULL,
		0xBB8742F8DAC80DB4ULL,
		0x919A96CC36661AD3ULL,
		0xA790BFBCD2325592ULL,
		0x0D9E914CCEB0C7DFULL,
		0x0CD1B702507008A7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x84FCBFF1BD1558DEULL,
		0xC935014960A1020CULL,
		0xCAB7E4D60D01C770ULL,
		0x770E85F1B5901B68ULL,
		0x23352D986CCC35A7ULL,
		0x4F217F79A464AB25ULL,
		0x1B3D22999D618FBFULL,
		0x19A36E04A0E0114EULL
	}};
	printf("Test Case 4\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 4 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -4;
	} else {
		printf("Test Case 4 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFCE737A386D5F844ULL,
		0x23E0F88955E4A389ULL,
		0xB078924781DDC399ULL,
		0x7F2346CF64009C92ULL,
		0xFA35790E1887A2ABULL,
		0x683ED747784DD914ULL,
		0x15999A24952DE55AULL,
		0x2668A08AA08D4E65ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF9CE6F470DABF088ULL,
		0x47C1F112ABC94713ULL,
		0x60F1248F03BB8732ULL,
		0xFE468D9EC8013925ULL,
		0xF46AF21C310F4556ULL,
		0xD07DAE8EF09BB229ULL,
		0x2B3334492A5BCAB4ULL,
		0x4CD14115411A9CCAULL
	}};
	printf("Test Case 5\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 5 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -5;
	} else {
		printf("Test Case 5 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0D75D1F114B44BC7ULL,
		0xE7F13F2C549FF502ULL,
		0xCA6242A221873DD0ULL,
		0xFE4C83A1C5408A5EULL,
		0x624A834F36E73C59ULL,
		0x513781CFE98AF53BULL,
		0xF6F79510094F5E6EULL,
		0x330913334DDCE055ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1AEBA3E22968978EULL,
		0xCFE27E58A93FEA04ULL,
		0x94C48544430E7BA1ULL,
		0xFC9907438A8114BDULL,
		0xC495069E6DCE78B3ULL,
		0xA26F039FD315EA76ULL,
		0xEDEF2A20129EBCDCULL,
		0x661226669BB9C0ABULL
	}};
	printf("Test Case 6\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 6 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -6;
	} else {
		printf("Test Case 6 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x28AE169718A09800ULL,
		0x4274DEF471BD5700ULL,
		0x230C47C0988E18C8ULL,
		0x5F147637B19183BFULL,
		0xBFA8E15F59DF2CE5ULL,
		0x90B33A8298DF2574ULL,
		0x478F115DDA02FF3AULL,
		0x09A990D9A563ECCDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x515C2D2E31413000ULL,
		0x84E9BDE8E37AAE00ULL,
		0x46188F81311C3190ULL,
		0xBE28EC6F6323077EULL,
		0x7F51C2BEB3BE59CAULL,
		0x2166750531BE4AE9ULL,
		0x8F1E22BBB405FE75ULL,
		0x135321B34AC7D99AULL
	}};
	printf("Test Case 7\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 7 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -7;
	} else {
		printf("Test Case 7 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB96BD19A3C9C57F1ULL,
		0xE192FD94EA79A92CULL,
		0xBC734958F2050E02ULL,
		0x1A4CCBB9030BC76BULL,
		0x13ECCF035BA8B639ULL,
		0x53D8343115BAEDD1ULL,
		0x720A53BE717901EEULL,
		0x083929421FB66190ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x72D7A3347938AFE2ULL,
		0xC325FB29D4F35259ULL,
		0x78E692B1E40A1C05ULL,
		0x3499977206178ED7ULL,
		0x27D99E06B7516C72ULL,
		0xA7B068622B75DBA2ULL,
		0xE414A77CE2F203DCULL,
		0x107252843F6CC320ULL
	}};
	printf("Test Case 8\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 8 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -8;
	} else {
		printf("Test Case 8 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x328500FF30A824E2ULL,
		0xA621251C8BED28EEULL,
		0xA133D9568D665B3BULL,
		0x935265C50322530BULL,
		0x1844D0EED69EF542ULL,
		0x0BFEACED35FCC77DULL,
		0x3633EAF9BF8F2A66ULL,
		0x3DE272C3BC48A38DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x650A01FE615049C4ULL,
		0x4C424A3917DA51DCULL,
		0x4267B2AD1ACCB677ULL,
		0x26A4CB8A0644A617ULL,
		0x3089A1DDAD3DEA85ULL,
		0x17FD59DA6BF98EFAULL,
		0x6C67D5F37F1E54CCULL,
		0x7BC4E5877891471AULL
	}};
	printf("Test Case 9\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 9 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -9;
	} else {
		printf("Test Case 9 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9024EE4DF2EB5A40ULL,
		0x93E9C57EBB2600BDULL,
		0xB32EBFF06C45F88AULL,
		0xFCF207D1367B2EE6ULL,
		0xF76E37230548ABE5ULL,
		0x6EB38393279FDE78ULL,
		0x84192AC198A892E2ULL,
		0x2F63D2B29A70AA33ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2049DC9BE5D6B480ULL,
		0x27D38AFD764C017BULL,
		0x665D7FE0D88BF115ULL,
		0xF9E40FA26CF65DCDULL,
		0xEEDC6E460A9157CBULL,
		0xDD6707264F3FBCF1ULL,
		0x08325583315125C4ULL,
		0x5EC7A56534E15467ULL
	}};
	printf("Test Case 10\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 10 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -10;
	} else {
		printf("Test Case 10 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x48110866C021CEF9ULL,
		0xCBE22D30AD7CA6F3ULL,
		0xEBAD972DD378B157ULL,
		0x10DD2633FA14D2F8ULL,
		0x5EAF6676811F7031ULL,
		0x5BB65C4168F41805ULL,
		0xC7CE407BCFA31880ULL,
		0x2B42152B5CA7D05CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x902210CD80439DF2ULL,
		0x97C45A615AF94DE6ULL,
		0xD75B2E5BA6F162AFULL,
		0x21BA4C67F429A5F1ULL,
		0xBD5ECCED023EE062ULL,
		0xB76CB882D1E8300AULL,
		0x8F9C80F79F463100ULL,
		0x56842A56B94FA0B9ULL
	}};
	printf("Test Case 11\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 11 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -11;
	} else {
		printf("Test Case 11 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x42F7A17A8BD4DCEBULL,
		0x8FCFA6B980AB77DEULL,
		0x27CF1F382E424434ULL,
		0x5F1FFAC3F1D8128BULL,
		0xCF1880DF3B14FD19ULL,
		0x0B9E70BAB4E3299CULL,
		0x569CACBA559152A7ULL,
		0x26C8251852249172ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x85EF42F517A9B9D6ULL,
		0x1F9F4D730156EFBCULL,
		0x4F9E3E705C848869ULL,
		0xBE3FF587E3B02516ULL,
		0x9E3101BE7629FA32ULL,
		0x173CE17569C65339ULL,
		0xAD395974AB22A54EULL,
		0x4D904A30A44922E4ULL
	}};
	printf("Test Case 12\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 12 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -12;
	} else {
		printf("Test Case 12 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x653377460EA1894EULL,
		0x27CE84376BF41047ULL,
		0x1F08A35282AF29ABULL,
		0x4C8FD20C6FA12E8BULL,
		0xB4B1467466A371F9ULL,
		0x67280BE514E723F5ULL,
		0xB49067196EDB2705ULL,
		0x0072170361F121CAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCA66EE8C1D43129CULL,
		0x4F9D086ED7E8208EULL,
		0x3E1146A5055E5356ULL,
		0x991FA418DF425D16ULL,
		0x69628CE8CD46E3F2ULL,
		0xCE5017CA29CE47EBULL,
		0x6920CE32DDB64E0AULL,
		0x00E42E06C3E24395ULL
	}};
	printf("Test Case 13\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 13 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -13;
	} else {
		printf("Test Case 13 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB432E8C6AF96C16AULL,
		0x23054118A0447418ULL,
		0x3603D703F1347AC0ULL,
		0x4F5F6054E24CDD60ULL,
		0x35D7571998BC4CE2ULL,
		0xEDBF6DF977B9BEB7ULL,
		0x810CE14AC12E3B3CULL,
		0x1D5CBD22653B0DDCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6865D18D5F2D82D4ULL,
		0x460A82314088E831ULL,
		0x6C07AE07E268F580ULL,
		0x9EBEC0A9C499BAC0ULL,
		0x6BAEAE33317899C4ULL,
		0xDB7EDBF2EF737D6EULL,
		0x0219C295825C7679ULL,
		0x3AB97A44CA761BB9ULL
	}};
	printf("Test Case 14\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 14 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -14;
	} else {
		printf("Test Case 14 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE74EA4199C326064ULL,
		0x14CD6CC4A29D4F4CULL,
		0x52E2F4B7666B0ABFULL,
		0xBD523EAD4E3DDF47ULL,
		0x97B7A652191AB43AULL,
		0x1933B1746D562FD6ULL,
		0xDEE85CE47FB5DCF4ULL,
		0x1099162AA5F926BBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCE9D48333864C0C8ULL,
		0x299AD989453A9E99ULL,
		0xA5C5E96ECCD6157EULL,
		0x7AA47D5A9C7BBE8EULL,
		0x2F6F4CA432356875ULL,
		0x326762E8DAAC5FADULL,
		0xBDD0B9C8FF6BB9E8ULL,
		0x21322C554BF24D77ULL
	}};
	printf("Test Case 15\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 15 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -15;
	} else {
		printf("Test Case 15 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6F0BD9BED87C55ADULL,
		0x1863040DBF790DE7ULL,
		0x26FD80A672FC8259ULL,
		0x32FAF95323740822ULL,
		0x17ED28E43888BECCULL,
		0x0A09AA3F334B7D7AULL,
		0x03A7DC8538CBC84CULL,
		0x1E26D40C77C8F7D4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDE17B37DB0F8AB5AULL,
		0x30C6081B7EF21BCEULL,
		0x4DFB014CE5F904B2ULL,
		0x65F5F2A646E81044ULL,
		0x2FDA51C871117D98ULL,
		0x1413547E6696FAF4ULL,
		0x074FB90A71979098ULL,
		0x3C4DA818EF91EFA8ULL
	}};
	printf("Test Case 16\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 16 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -16;
	} else {
		printf("Test Case 16 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC48BF726314A267CULL,
		0x3FBBE560BBB3CB28ULL,
		0xC0B1FEFA95E1448EULL,
		0x99F1C93C7BA99EC8ULL,
		0x71B4BF3796009807ULL,
		0x516322928D7B4A87ULL,
		0x39A90E5B070FCFB3ULL,
		0x0C925A2AFAC5788CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8917EE4C62944CF8ULL,
		0x7F77CAC177679651ULL,
		0x8163FDF52BC2891CULL,
		0x33E39278F7533D91ULL,
		0xE3697E6F2C01300FULL,
		0xA2C645251AF6950EULL,
		0x73521CB60E1F9F66ULL,
		0x1924B455F58AF118ULL
	}};
	printf("Test Case 17\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 17 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -17;
	} else {
		printf("Test Case 17 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5C2A30FCD303D1A7ULL,
		0x6D6339F7AFA5E6F1ULL,
		0x2CE8C78E2E50939EULL,
		0x2E6F4A2D4FF95AE2ULL,
		0xB47C2FC3B8A448E9ULL,
		0x6C598CA51E217EB2ULL,
		0x8B77C80618B41FC6ULL,
		0x148DDD451BD5987FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB85461F9A607A34EULL,
		0xDAC673EF5F4BCDE2ULL,
		0x59D18F1C5CA1273CULL,
		0x5CDE945A9FF2B5C4ULL,
		0x68F85F87714891D2ULL,
		0xD8B3194A3C42FD65ULL,
		0x16EF900C31683F8CULL,
		0x291BBA8A37AB30FFULL
	}};
	printf("Test Case 18\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 18 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -18;
	} else {
		printf("Test Case 18 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE8366FA3907A18B0ULL,
		0x77C3580BA0483E49ULL,
		0x17EC9EF2A56C8802ULL,
		0x47D16EAA3D9B9D6FULL,
		0x9EF2B3A2F09B9272ULL,
		0x47164DB02911EB47ULL,
		0x53595F39191F49B0ULL,
		0x2115EFD10567BB90ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD06CDF4720F43160ULL,
		0xEF86B01740907C93ULL,
		0x2FD93DE54AD91004ULL,
		0x8FA2DD547B373ADEULL,
		0x3DE56745E13724E4ULL,
		0x8E2C9B605223D68FULL,
		0xA6B2BE72323E9360ULL,
		0x422BDFA20ACF7720ULL
	}};
	printf("Test Case 19\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 19 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -19;
	} else {
		printf("Test Case 19 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEAEF9F5B66FBFA11ULL,
		0xF0AEF54E17057B46ULL,
		0x36B0D7DAEEF7E075ULL,
		0xF15316328BA19236ULL,
		0x4546E5AC1EBF17A3ULL,
		0x237EFDCB36C9F444ULL,
		0x51C039E7AE9BB995ULL,
		0x284E422EA94374B3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD5DF3EB6CDF7F422ULL,
		0xE15DEA9C2E0AF68DULL,
		0x6D61AFB5DDEFC0EBULL,
		0xE2A62C651743246CULL,
		0x8A8DCB583D7E2F47ULL,
		0x46FDFB966D93E888ULL,
		0xA38073CF5D37732AULL,
		0x509C845D5286E966ULL
	}};
	printf("Test Case 20\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 20 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -20;
	} else {
		printf("Test Case 20 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF1C116C8FC0E246BULL,
		0x554CB7C47A4FCC5AULL,
		0xEF11B4B38B57324FULL,
		0x68660C424CBD5873ULL,
		0xB87E381F46994428ULL,
		0x485BC4596E46503EULL,
		0x654C4DBBD5758A16ULL,
		0x0907561E7942EA02ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE3822D91F81C48D6ULL,
		0xAA996F88F49F98B5ULL,
		0xDE23696716AE649EULL,
		0xD0CC1884997AB0E7ULL,
		0x70FC703E8D328850ULL,
		0x90B788B2DC8CA07DULL,
		0xCA989B77AAEB142CULL,
		0x120EAC3CF285D404ULL
	}};
	printf("Test Case 21\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 21 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -21;
	} else {
		printf("Test Case 21 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6C82D73BBA6B2CF7ULL,
		0x6BAFC598E6BB9382ULL,
		0xBA58B6CF2B0DF588ULL,
		0x9C657B8E1FF5F0FCULL,
		0x4DC76B3951DE9F6AULL,
		0xEA3DA854042E1BE3ULL,
		0x48381855494AD60DULL,
		0x1824EFADFFEC183DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD905AE7774D659EEULL,
		0xD75F8B31CD772704ULL,
		0x74B16D9E561BEB10ULL,
		0x38CAF71C3FEBE1F9ULL,
		0x9B8ED672A3BD3ED5ULL,
		0xD47B50A8085C37C6ULL,
		0x907030AA9295AC1BULL,
		0x3049DF5BFFD8307AULL
	}};
	printf("Test Case 22\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 22 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -22;
	} else {
		printf("Test Case 22 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x184B944DF36E5959ULL,
		0x2EF5106218ECD236ULL,
		0xB81263F254C539B0ULL,
		0xE19C145BD8357946ULL,
		0x5A1CB6B4A42C13EDULL,
		0x6DFC9719D159A7B5ULL,
		0x4A359239E402D834ULL,
		0x3B4AAECB8322CAF4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3097289BE6DCB2B2ULL,
		0x5DEA20C431D9A46CULL,
		0x7024C7E4A98A7360ULL,
		0xC33828B7B06AF28DULL,
		0xB4396D69485827DBULL,
		0xDBF92E33A2B34F6AULL,
		0x946B2473C805B068ULL,
		0x76955D97064595E8ULL
	}};
	printf("Test Case 23\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 23 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -23;
	} else {
		printf("Test Case 23 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0BFAAEF83CF0F7B4ULL,
		0xB625D467643B20C3ULL,
		0x23EA168A94E92A26ULL,
		0x7172D79D7CC513C9ULL,
		0xA69BFF069C26E567ULL,
		0xD315D395CE8842EBULL,
		0xD1F9EB88564C0689ULL,
		0x3BB2DB625DA27281ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x17F55DF079E1EF68ULL,
		0x6C4BA8CEC8764186ULL,
		0x47D42D1529D2544DULL,
		0xE2E5AF3AF98A2792ULL,
		0x4D37FE0D384DCACEULL,
		0xA62BA72B9D1085D7ULL,
		0xA3F3D710AC980D13ULL,
		0x7765B6C4BB44E503ULL
	}};
	printf("Test Case 24\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 24 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -24;
	} else {
		printf("Test Case 24 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE3C16F217DA3D30BULL,
		0x2E4C7EF8474DB8F3ULL,
		0x8ABF3D54BEFE4DCCULL,
		0xEA698CC7F28ABCF1ULL,
		0xF45DCC8CC8C11C25ULL,
		0x8A0DE3465897C59EULL,
		0x9A0FF169B4623CA3ULL,
		0x1394DFE8A8E02CF6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC782DE42FB47A616ULL,
		0x5C98FDF08E9B71E7ULL,
		0x157E7AA97DFC9B98ULL,
		0xD4D3198FE51579E3ULL,
		0xE8BB99199182384BULL,
		0x141BC68CB12F8B3DULL,
		0x341FE2D368C47947ULL,
		0x2729BFD151C059EDULL
	}};
	printf("Test Case 25\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 25 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -25;
	} else {
		printf("Test Case 25 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1AEA4D78146614B2ULL,
		0x09E446BDBC75C0B5ULL,
		0xA062D1F37D60DA49ULL,
		0x777AA3EAD0956EF3ULL,
		0xAD84C671E46DCB3BULL,
		0xB8510C77C3C72944ULL,
		0xACAE1DC822F2BDEDULL,
		0x07B2260DF7D507EEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x35D49AF028CC2964ULL,
		0x13C88D7B78EB816AULL,
		0x40C5A3E6FAC1B492ULL,
		0xEEF547D5A12ADDE7ULL,
		0x5B098CE3C8DB9676ULL,
		0x70A218EF878E5289ULL,
		0x595C3B9045E57BDBULL,
		0x0F644C1BEFAA0FDDULL
	}};
	printf("Test Case 26\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 26 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -26;
	} else {
		printf("Test Case 26 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x11AD039BEB472B13ULL,
		0xC59321CDA8407205ULL,
		0x3AE20E9D7B00CEA4ULL,
		0xBA3B2B51854F0719ULL,
		0x42B959F234B73B8AULL,
		0x1976D27664F8A19EULL,
		0x011AC5465198BD9DULL,
		0x12F69371A374A0F9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x235A0737D68E5626ULL,
		0x8B26439B5080E40AULL,
		0x75C41D3AF6019D49ULL,
		0x747656A30A9E0E32ULL,
		0x8572B3E4696E7715ULL,
		0x32EDA4ECC9F1433CULL,
		0x02358A8CA3317B3AULL,
		0x25ED26E346E941F2ULL
	}};
	printf("Test Case 27\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 27 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -27;
	} else {
		printf("Test Case 27 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAB6C2806CA1B1FD8ULL,
		0x9612B199C598699AULL,
		0xCBE9A357F27A8880ULL,
		0x8456050499E09C3BULL,
		0x0D4FECEF9BBABA11ULL,
		0x75A96557278A4CB4ULL,
		0x9E961357F12C1561ULL,
		0x0ECD71B475C109A9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x56D8500D94363FB0ULL,
		0x2C2563338B30D335ULL,
		0x97D346AFE4F51101ULL,
		0x08AC0A0933C13877ULL,
		0x1A9FD9DF37757423ULL,
		0xEB52CAAE4F149968ULL,
		0x3D2C26AFE2582AC2ULL,
		0x1D9AE368EB821353ULL
	}};
	printf("Test Case 28\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 28 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -28;
	} else {
		printf("Test Case 28 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x262AF1BE6395A796ULL,
		0x1399601D67B1EEC2ULL,
		0xDDE119AAF74824EEULL,
		0xDFA33B3723BFC65CULL,
		0xD32852899C437DF2ULL,
		0x4DA5C87ED953C5C0ULL,
		0x1151B3D0F3421C7BULL,
		0x1B6B9E4F3CC5540DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4C55E37CC72B4F2CULL,
		0x2732C03ACF63DD84ULL,
		0xBBC23355EE9049DCULL,
		0xBF46766E477F8CB9ULL,
		0xA650A5133886FBE5ULL,
		0x9B4B90FDB2A78B81ULL,
		0x22A367A1E68438F6ULL,
		0x36D73C9E798AA81AULL
	}};
	printf("Test Case 29\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 29 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -29;
	} else {
		printf("Test Case 29 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC13823037CF4AC12ULL,
		0x73FE39052DED2453ULL,
		0x9BBBE97253A01AB7ULL,
		0xBCC9A42088902EB1ULL,
		0x82C936ECCDE18279ULL,
		0xB697F877BA36E386ULL,
		0xC2EB76DCB54A32E7ULL,
		0x3E16A05B07AA83A4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x82704606F9E95824ULL,
		0xE7FC720A5BDA48A7ULL,
		0x3777D2E4A740356EULL,
		0x7993484111205D63ULL,
		0x05926DD99BC304F3ULL,
		0x6D2FF0EF746DC70DULL,
		0x85D6EDB96A9465CFULL,
		0x7C2D40B60F550749ULL
	}};
	printf("Test Case 30\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 30 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -30;
	} else {
		printf("Test Case 30 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x73A2655BFD5E6687ULL,
		0x476016D692046732ULL,
		0xFBB590FE4FFF8CBFULL,
		0x2F8B01299D244CCCULL,
		0xB0B70E1B5AD5B418ULL,
		0xD4A1929CFB2DCF0AULL,
		0xB871CD53D8A86F44ULL,
		0x34B8D82D8D3FFCA2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE744CAB7FABCCD0EULL,
		0x8EC02DAD2408CE64ULL,
		0xF76B21FC9FFF197EULL,
		0x5F1602533A489999ULL,
		0x616E1C36B5AB6830ULL,
		0xA9432539F65B9E15ULL,
		0x70E39AA7B150DE89ULL,
		0x6971B05B1A7FF945ULL
	}};
	printf("Test Case 31\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 31 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -31;
	} else {
		printf("Test Case 31 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x52759CF40E039533ULL,
		0x2C5E0A942C7CEF6FULL,
		0xBEA1A785E39FE073ULL,
		0x983020F6B9D33DBBULL,
		0x90175E9E4BCD49D5ULL,
		0x34D5C6C89BC53BB7ULL,
		0xAC85AA8326AD63B1ULL,
		0x3D1ADDAC478CB085ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA4EB39E81C072A66ULL,
		0x58BC152858F9DEDEULL,
		0x7D434F0BC73FC0E6ULL,
		0x306041ED73A67B77ULL,
		0x202EBD3C979A93ABULL,
		0x69AB8D91378A776FULL,
		0x590B55064D5AC762ULL,
		0x7A35BB588F19610BULL
	}};
	printf("Test Case 32\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 32 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -32;
	} else {
		printf("Test Case 32 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAF703C786D6A8C0AULL,
		0xE20CACC450C34152ULL,
		0x56B0611B2AF0F08DULL,
		0x89B1C97059F5F42FULL,
		0xA3AD1534A3C8992AULL,
		0x35B32F54EA72441DULL,
		0x9745ADED3388EC1CULL,
		0x363FD0E7C9E41FE5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5EE078F0DAD51814ULL,
		0xC4195988A18682A5ULL,
		0xAD60C23655E1E11BULL,
		0x136392E0B3EBE85EULL,
		0x475A2A6947913255ULL,
		0x6B665EA9D4E4883BULL,
		0x2E8B5BDA6711D838ULL,
		0x6C7FA1CF93C83FCBULL
	}};
	printf("Test Case 33\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 33 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -33;
	} else {
		printf("Test Case 33 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1D804A4F02A82916ULL,
		0xAEF8AED908F4467FULL,
		0x5A0D81CCA8428FD5ULL,
		0x514795521D9F0CECULL,
		0x6A4EA6447028C3FEULL,
		0x30BE28F47737CED5ULL,
		0xF13C0E1AFA0AEB07ULL,
		0x02669FA042DA2DEFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3B00949E0550522CULL,
		0x5DF15DB211E88CFEULL,
		0xB41B039950851FABULL,
		0xA28F2AA43B3E19D8ULL,
		0xD49D4C88E05187FCULL,
		0x617C51E8EE6F9DAAULL,
		0xE2781C35F415D60EULL,
		0x04CD3F4085B45BDFULL
	}};
	printf("Test Case 34\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 34 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -34;
	} else {
		printf("Test Case 34 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0B41E42DF6D40824ULL,
		0x2CC91E365B01C98AULL,
		0x0E5B78C5079197DDULL,
		0x62D17E7FB66EEF82ULL,
		0x22AD38462EF5AF45ULL,
		0x3E023CF63CB1D681ULL,
		0x67788846468ED67DULL,
		0x1A213F0F7E5D48A7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1683C85BEDA81048ULL,
		0x59923C6CB6039314ULL,
		0x1CB6F18A0F232FBAULL,
		0xC5A2FCFF6CDDDF04ULL,
		0x455A708C5DEB5E8AULL,
		0x7C0479EC7963AD02ULL,
		0xCEF1108C8D1DACFAULL,
		0x34427E1EFCBA914EULL
	}};
	printf("Test Case 35\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 35 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -35;
	} else {
		printf("Test Case 35 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEE845D2A29897507ULL,
		0x4C43A0B9314C5163ULL,
		0x92C027A0DC75388BULL,
		0xA1B721D2FEA714EDULL,
		0xF97CDF4518F6BD8EULL,
		0x60F00C88800FA7F3ULL,
		0x9FE40156DE7328C6ULL,
		0x023DBA14302806A5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDD08BA545312EA0EULL,
		0x988741726298A2C7ULL,
		0x25804F41B8EA7116ULL,
		0x436E43A5FD4E29DBULL,
		0xF2F9BE8A31ED7B1DULL,
		0xC1E01911001F4FE7ULL,
		0x3FC802ADBCE6518CULL,
		0x047B742860500D4BULL
	}};
	printf("Test Case 36\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 36 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -36;
	} else {
		printf("Test Case 36 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF85E2444276F98D5ULL,
		0x676080EB9755A57EULL,
		0xDA6A4953F5808817ULL,
		0xC5AF84A3A1A9D27FULL,
		0xFE5413A351A5F7D7ULL,
		0x12DDFB74BCA4E42AULL,
		0x93E368F484DBC5DDULL,
		0x27B1697D41FD1307ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF0BC48884EDF31AAULL,
		0xCEC101D72EAB4AFDULL,
		0xB4D492A7EB01102EULL,
		0x8B5F09474353A4FFULL,
		0xFCA82746A34BEFAFULL,
		0x25BBF6E97949C855ULL,
		0x27C6D1E909B78BBAULL,
		0x4F62D2FA83FA260FULL
	}};
	printf("Test Case 37\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 37 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -37;
	} else {
		printf("Test Case 37 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4E96FD27942EEB79ULL,
		0xAA746A30B654A795ULL,
		0xDC0FBD95C8550370ULL,
		0xA6794AA68856A303ULL,
		0xB2854D4E116357BDULL,
		0x84B3E682F5EF46D6ULL,
		0x7C1F51CD2BF8CFCEULL,
		0x151C2B51504EBC71ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9D2DFA4F285DD6F2ULL,
		0x54E8D4616CA94F2AULL,
		0xB81F7B2B90AA06E1ULL,
		0x4CF2954D10AD4607ULL,
		0x650A9A9C22C6AF7BULL,
		0x0967CD05EBDE8DADULL,
		0xF83EA39A57F19F9DULL,
		0x2A3856A2A09D78E2ULL
	}};
	printf("Test Case 38\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 38 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -38;
	} else {
		printf("Test Case 38 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x975A23A55FB52C8BULL,
		0x143DCA46297FE8EBULL,
		0x78D5A4F5FA6F1F42ULL,
		0xFA33982904D8BAA3ULL,
		0x1623CEF88634D991ULL,
		0xD8A658C64753385EULL,
		0xE863529FB2496132ULL,
		0x2855AF48F6295ED5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2EB4474ABF6A5916ULL,
		0x287B948C52FFD1D7ULL,
		0xF1AB49EBF4DE3E84ULL,
		0xF467305209B17546ULL,
		0x2C479DF10C69B323ULL,
		0xB14CB18C8EA670BCULL,
		0xD0C6A53F6492C265ULL,
		0x50AB5E91EC52BDABULL
	}};
	printf("Test Case 39\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 39 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -39;
	} else {
		printf("Test Case 39 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA17411520FE8FC96ULL,
		0x728A9BC2C35A67F9ULL,
		0x5AC32689B1DBAA6DULL,
		0x253F4544D22F026AULL,
		0x0F0182FF7BDCAA0BULL,
		0x5D275839A00FDCD2ULL,
		0x8F6C55CEF72B1859ULL,
		0x2011B35F892A34ACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x42E822A41FD1F92CULL,
		0xE515378586B4CFF3ULL,
		0xB5864D1363B754DAULL,
		0x4A7E8A89A45E04D4ULL,
		0x1E0305FEF7B95416ULL,
		0xBA4EB073401FB9A4ULL,
		0x1ED8AB9DEE5630B2ULL,
		0x402366BF12546959ULL
	}};
	printf("Test Case 40\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 40 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -40;
	} else {
		printf("Test Case 40 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x13D0DF21A17E1057ULL,
		0x1CD29AE5D12886C7ULL,
		0x9F4DF03A2EA6C8A2ULL,
		0x6953A634B908DEDDULL,
		0x56C7367587518169ULL,
		0x1E457D5D9CB8E0A6ULL,
		0x5E0B7D0F12DAEA1AULL,
		0x265CF595BEDC0665ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x27A1BE4342FC20AEULL,
		0x39A535CBA2510D8EULL,
		0x3E9BE0745D4D9144ULL,
		0xD2A74C697211BDBBULL,
		0xAD8E6CEB0EA302D2ULL,
		0x3C8AFABB3971C14CULL,
		0xBC16FA1E25B5D434ULL,
		0x4CB9EB2B7DB80CCAULL
	}};
	printf("Test Case 41\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 41 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -41;
	} else {
		printf("Test Case 41 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA5BEED62ACB92094ULL,
		0x159D44E24E9BFABAULL,
		0x092020A99439A9DFULL,
		0x437850CD4C18D45FULL,
		0xA7C1C95EC7EE5FFEULL,
		0x3A5C9813ADCBC4E5ULL,
		0xC52AF658050CE12CULL,
		0x261F71B6A7788B8BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4B7DDAC559724128ULL,
		0x2B3A89C49D37F575ULL,
		0x12404153287353BEULL,
		0x86F0A19A9831A8BEULL,
		0x4F8392BD8FDCBFFCULL,
		0x74B930275B9789CBULL,
		0x8A55ECB00A19C258ULL,
		0x4C3EE36D4EF11717ULL
	}};
	printf("Test Case 42\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 42 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -42;
	} else {
		printf("Test Case 42 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9687237169F5A5B5ULL,
		0xBBE9E485F8AADA74ULL,
		0x339EA7CAC4BF848CULL,
		0xA82CBD5B91DCD2C0ULL,
		0xB57396E0B463A756ULL,
		0x13E0CDAA854F72A0ULL,
		0x3305FDC8ED80E9BFULL,
		0x038FA4E74CC294CAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2D0E46E2D3EB4B6AULL,
		0x77D3C90BF155B4E9ULL,
		0x673D4F95897F0919ULL,
		0x50597AB723B9A580ULL,
		0x6AE72DC168C74EADULL,
		0x27C19B550A9EE541ULL,
		0x660BFB91DB01D37EULL,
		0x071F49CE99852994ULL
	}};
	printf("Test Case 43\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 43 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -43;
	} else {
		printf("Test Case 43 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD523090C164BC792ULL,
		0xC853094CFE7A19B1ULL,
		0x532EC8E3F1A59101ULL,
		0xF9AC17B8BFACC752ULL,
		0x97D7AB23C3D91C6BULL,
		0x28C4AA310DF36B83ULL,
		0xBD2140E0DFF06BCAULL,
		0x1C1C871740217272ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAA4612182C978F24ULL,
		0x90A61299FCF43363ULL,
		0xA65D91C7E34B2203ULL,
		0xF3582F717F598EA4ULL,
		0x2FAF564787B238D7ULL,
		0x518954621BE6D707ULL,
		0x7A4281C1BFE0D794ULL,
		0x38390E2E8042E4E5ULL
	}};
	printf("Test Case 44\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 44 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -44;
	} else {
		printf("Test Case 44 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8AD3ACE154589326ULL,
		0x9639AAC6C59E3977ULL,
		0x0ACF5D07E3D0A093ULL,
		0x753C62FF60204D9FULL,
		0xD54F4D3A641FAFBAULL,
		0x216AFCE08E5F5654ULL,
		0x0C2C16924447EE31ULL,
		0x3B937C282A1716DAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x15A759C2A8B1264CULL,
		0x2C73558D8B3C72EFULL,
		0x159EBA0FC7A14127ULL,
		0xEA78C5FEC0409B3EULL,
		0xAA9E9A74C83F5F74ULL,
		0x42D5F9C11CBEACA9ULL,
		0x18582D24888FDC62ULL,
		0x7726F850542E2DB4ULL
	}};
	printf("Test Case 45\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 45 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -45;
	} else {
		printf("Test Case 45 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x48A211B27D99DF77ULL,
		0xAB396E810664DFAAULL,
		0x386DBC0F35B9C246ULL,
		0xBF119BD05C278FBAULL,
		0x4E6CF135D8F50143ULL,
		0x060252FB4092B009ULL,
		0x817E4FDA9BB224E1ULL,
		0x3CA113D410E22E2BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x91442364FB33BEEEULL,
		0x5672DD020CC9BF54ULL,
		0x70DB781E6B73848DULL,
		0x7E2337A0B84F1F74ULL,
		0x9CD9E26BB1EA0287ULL,
		0x0C04A5F681256012ULL,
		0x02FC9FB5376449C2ULL,
		0x794227A821C45C57ULL
	}};
	printf("Test Case 46\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 46 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -46;
	} else {
		printf("Test Case 46 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD6E431867F2DC4C0ULL,
		0xCF003D1156B195B5ULL,
		0xF0DEC2C1CF47531EULL,
		0x93609A40CA5888C4ULL,
		0xA768675E5ADFAEB5ULL,
		0x80D5A67C18AB39DCULL,
		0x4BBBB75856A097A0ULL,
		0x0E79B2B86728D4E2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xADC8630CFE5B8980ULL,
		0x9E007A22AD632B6BULL,
		0xE1BD85839E8EA63DULL,
		0x26C1348194B11189ULL,
		0x4ED0CEBCB5BF5D6BULL,
		0x01AB4CF8315673B9ULL,
		0x97776EB0AD412F41ULL,
		0x1CF36570CE51A9C4ULL
	}};
	printf("Test Case 47\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 47 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -47;
	} else {
		printf("Test Case 47 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x669A4139BBD7E02FULL,
		0xC0C13D3D58D8C0DEULL,
		0x279D3484B0EDDD19ULL,
		0x4E9CCF50C5D5F0DAULL,
		0x05136F4EF2E50800ULL,
		0x5C4E0B65C85EE09DULL,
		0x69548AC2BF65C8BDULL,
		0x1426D397C82BF466ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCD34827377AFC05EULL,
		0x81827A7AB1B181BCULL,
		0x4F3A690961DBBA33ULL,
		0x9D399EA18BABE1B4ULL,
		0x0A26DE9DE5CA1000ULL,
		0xB89C16CB90BDC13AULL,
		0xD2A915857ECB917AULL,
		0x284DA72F9057E8CCULL
	}};
	printf("Test Case 48\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 48 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -48;
	} else {
		printf("Test Case 48 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE551DB7E9B82B5DEULL,
		0x443D44DA3E6FE2BFULL,
		0xCD2FF4F4C8B524C4ULL,
		0xCA7AFC3C561B05B4ULL,
		0xC37C5CC980C5B757ULL,
		0x0D2E189ED37FB3CBULL,
		0xB7CABBC8615D29D0ULL,
		0x16C7F9DA4C7DDAFDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCAA3B6FD37056BBCULL,
		0x887A89B47CDFC57FULL,
		0x9A5FE9E9916A4988ULL,
		0x94F5F878AC360B69ULL,
		0x86F8B993018B6EAFULL,
		0x1A5C313DA6FF6797ULL,
		0x6F957790C2BA53A0ULL,
		0x2D8FF3B498FBB5FBULL
	}};
	printf("Test Case 49\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 49 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -49;
	} else {
		printf("Test Case 49 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB76F8074B4ADFC4BULL,
		0xDDA29FC05D585BE7ULL,
		0x996930142909CBAAULL,
		0xC12F8A6665BBEF8CULL,
		0x604EEB021F2AE974ULL,
		0xA3328B824FC71618ULL,
		0xE966F61AA2339152ULL,
		0x14B99C5B501F46C4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6EDF00E9695BF896ULL,
		0xBB453F80BAB0B7CFULL,
		0x32D2602852139755ULL,
		0x825F14CCCB77DF19ULL,
		0xC09DD6043E55D2E9ULL,
		0x466517049F8E2C30ULL,
		0xD2CDEC35446722A5ULL,
		0x297338B6A03E8D89ULL
	}};
	printf("Test Case 50\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 50 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -50;
	} else {
		printf("Test Case 50 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x624F118FA7C95337ULL,
		0xFD7235C94F6EBED9ULL,
		0xA996A0F099C672CEULL,
		0x32986076CCC3C8C8ULL,
		0x39615F1FE84DAD5FULL,
		0x9715355AAC7A47F1ULL,
		0xEDFAEE40BE253A71ULL,
		0x27360FCB788A457DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC49E231F4F92A66EULL,
		0xFAE46B929EDD7DB2ULL,
		0x532D41E1338CE59DULL,
		0x6530C0ED99879191ULL,
		0x72C2BE3FD09B5ABEULL,
		0x2E2A6AB558F48FE2ULL,
		0xDBF5DC817C4A74E3ULL,
		0x4E6C1F96F1148AFBULL
	}};
	printf("Test Case 51\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 51 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -51;
	} else {
		printf("Test Case 51 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0FE6FC15433F3E0FULL,
		0x496CCDE05D2E77A5ULL,
		0x5F43AAE8E7997465ULL,
		0xEC828A2D024D1C20ULL,
		0x069422D54ED6ADC6ULL,
		0xAFE8EA8668238CAEULL,
		0x94FF7A8038C26781ULL,
		0x13DDDDC8328F0DBBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1FCDF82A867E7C1EULL,
		0x92D99BC0BA5CEF4AULL,
		0xBE8755D1CF32E8CAULL,
		0xD905145A049A3840ULL,
		0x0D2845AA9DAD5B8DULL,
		0x5FD1D50CD047195CULL,
		0x29FEF5007184CF03ULL,
		0x27BBBB90651E1B77ULL
	}};
	printf("Test Case 52\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 52 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -52;
	} else {
		printf("Test Case 52 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x39F17D13F559B4B0ULL,
		0x671E00A7145B98A8ULL,
		0x91923DA0351633FEULL,
		0x8F95F353F0F5DF3CULL,
		0x60AFD31B6FAD151DULL,
		0x8C7CA378B596D042ULL,
		0xDDA565639E1A397BULL,
		0x30F001B96F47A11CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x73E2FA27EAB36960ULL,
		0xCE3C014E28B73150ULL,
		0x23247B406A2C67FCULL,
		0x1F2BE6A7E1EBBE79ULL,
		0xC15FA636DF5A2A3BULL,
		0x18F946F16B2DA084ULL,
		0xBB4ACAC73C3472F7ULL,
		0x61E00372DE8F4239ULL
	}};
	printf("Test Case 53\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 53 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -53;
	} else {
		printf("Test Case 53 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC31FB8ADCC81B08BULL,
		0xCA4C2D2D19477A1EULL,
		0xAB4EAB9801EC68B3ULL,
		0xFCF3FD197D1019D1ULL,
		0x11FBFD57A5DD9551ULL,
		0x4CBDF756460ACA15ULL,
		0x99D00407402AF11AULL,
		0x391E5075BC4B48FBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x863F715B99036116ULL,
		0x94985A5A328EF43DULL,
		0x569D573003D8D167ULL,
		0xF9E7FA32FA2033A3ULL,
		0x23F7FAAF4BBB2AA3ULL,
		0x997BEEAC8C15942AULL,
		0x33A0080E8055E234ULL,
		0x723CA0EB789691F7ULL
	}};
	printf("Test Case 54\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 54 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -54;
	} else {
		printf("Test Case 54 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0D82A8DA635492FEULL,
		0xE8C4A183DEE27E9FULL,
		0x766867E10B07AC91ULL,
		0x5F24607CCCA15806ULL,
		0x9F05078AD373C533ULL,
		0xAA56A1DE88C79206ULL,
		0xAE2F9090F4303CB7ULL,
		0x05AD3DE5B787D567ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1B0551B4C6A925FCULL,
		0xD1894307BDC4FD3EULL,
		0xECD0CFC2160F5923ULL,
		0xBE48C0F99942B00CULL,
		0x3E0A0F15A6E78A66ULL,
		0x54AD43BD118F240DULL,
		0x5C5F2121E860796FULL,
		0x0B5A7BCB6F0FAACFULL
	}};
	printf("Test Case 55\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 55 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -55;
	} else {
		printf("Test Case 55 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7D1B603FAAF7A232ULL,
		0x162CC34A0C6527D4ULL,
		0xB72F0C46CEA1254EULL,
		0xDAE57022F85FD832ULL,
		0xBA1B097313962329ULL,
		0xE44879662831E1FAULL,
		0x54AC74E20396995AULL,
		0x393CE1DA96FBD86FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFA36C07F55EF4464ULL,
		0x2C59869418CA4FA8ULL,
		0x6E5E188D9D424A9CULL,
		0xB5CAE045F0BFB065ULL,
		0x743612E6272C4653ULL,
		0xC890F2CC5063C3F5ULL,
		0xA958E9C4072D32B5ULL,
		0x7279C3B52DF7B0DEULL
	}};
	printf("Test Case 56\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 56 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -56;
	} else {
		printf("Test Case 56 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7D0BCAD2E35544F5ULL,
		0xA8B7D9605FB2BAF7ULL,
		0xFF413A006D6B8399ULL,
		0xE35A5B5C1B3B01EAULL,
		0xDE05E462A59DB624ULL,
		0x7BCC15C1C0DBF536ULL,
		0x75607427E71E63D6ULL,
		0x2476450DEA88F2F4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFA1795A5C6AA89EAULL,
		0x516FB2C0BF6575EEULL,
		0xFE827400DAD70733ULL,
		0xC6B4B6B8367603D5ULL,
		0xBC0BC8C54B3B6C49ULL,
		0xF7982B8381B7EA6DULL,
		0xEAC0E84FCE3CC7ACULL,
		0x48EC8A1BD511E5E8ULL
	}};
	printf("Test Case 57\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 57 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -57;
	} else {
		printf("Test Case 57 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x83BA98F91D68604DULL,
		0x70C9FADE32B4B7CAULL,
		0xDF902DC69170E095ULL,
		0xF2D886BD0BE4D38EULL,
		0x69D3B7C5F3257A27ULL,
		0x9F362422C0A80A83ULL,
		0xCCCA96E986005361ULL,
		0x3BF0C2A68CCEAD12ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x077531F23AD0C09AULL,
		0xE193F5BC65696F95ULL,
		0xBF205B8D22E1C12AULL,
		0xE5B10D7A17C9A71DULL,
		0xD3A76F8BE64AF44FULL,
		0x3E6C484581501506ULL,
		0x99952DD30C00A6C3ULL,
		0x77E1854D199D5A25ULL
	}};
	printf("Test Case 58\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 58 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -58;
	} else {
		printf("Test Case 58 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3B47076169C6DF29ULL,
		0xA23EE612708E0191ULL,
		0x6F842B57706B37BDULL,
		0x28061B60F95B3DADULL,
		0xB4942C800066EDDAULL,
		0x8D39A563B5A1B81BULL,
		0xC304F2B3D6C01ED2ULL,
		0x0BD75D02A3D35174ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x768E0EC2D38DBE52ULL,
		0x447DCC24E11C0322ULL,
		0xDF0856AEE0D66F7BULL,
		0x500C36C1F2B67B5AULL,
		0x6928590000CDDBB4ULL,
		0x1A734AC76B437037ULL,
		0x8609E567AD803DA5ULL,
		0x17AEBA0547A6A2E9ULL
	}};
	printf("Test Case 59\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 59 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -59;
	} else {
		printf("Test Case 59 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB53F1D7DC26D4917ULL,
		0x7CCE73EFF331763DULL,
		0x67BAE23A96559C74ULL,
		0x0903D366C3D64B57ULL,
		0x9CF7D399CF4D5F8EULL,
		0xFFA272BA16D56B46ULL,
		0xC6502A59E6E2C962ULL,
		0x17C7AB6F169E566BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6A7E3AFB84DA922EULL,
		0xF99CE7DFE662EC7BULL,
		0xCF75C4752CAB38E8ULL,
		0x1207A6CD87AC96AEULL,
		0x39EFA7339E9ABF1CULL,
		0xFF44E5742DAAD68DULL,
		0x8CA054B3CDC592C5ULL,
		0x2F8F56DE2D3CACD7ULL
	}};
	printf("Test Case 60\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 60 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -60;
	} else {
		printf("Test Case 60 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5183372CE5D9143EULL,
		0x1FC9539C7FBDFF67ULL,
		0x72630741EF6992C0ULL,
		0x6C808E68D145910BULL,
		0x13F58BDB11AF56B9ULL,
		0xB79FC20A78327D39ULL,
		0xC02C6D9ECB224DA1ULL,
		0x253FFD5D109FA06FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA3066E59CBB2287CULL,
		0x3F92A738FF7BFECEULL,
		0xE4C60E83DED32580ULL,
		0xD9011CD1A28B2216ULL,
		0x27EB17B6235EAD72ULL,
		0x6F3F8414F064FA72ULL,
		0x8058DB3D96449B43ULL,
		0x4A7FFABA213F40DFULL
	}};
	printf("Test Case 61\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 61 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -61;
	} else {
		printf("Test Case 61 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6F779DB358634F41ULL,
		0x199F5EBD07FB1D4BULL,
		0xCD8032ED97742639ULL,
		0x7480C8F14197D33FULL,
		0x7DAE9ABC3F709B2FULL,
		0xF851373764019A44ULL,
		0xAFEF5426CF8365F9ULL,
		0x11601FC2DCF58770ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDEEF3B66B0C69E82ULL,
		0x333EBD7A0FF63A96ULL,
		0x9B0065DB2EE84C72ULL,
		0xE90191E2832FA67FULL,
		0xFB5D35787EE1365EULL,
		0xF0A26E6EC8033488ULL,
		0x5FDEA84D9F06CBF3ULL,
		0x22C03F85B9EB0EE1ULL
	}};
	printf("Test Case 62\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 62 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -62;
	} else {
		printf("Test Case 62 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x340AD381734ADBC6ULL,
		0xA5F978CE6EC2C4BFULL,
		0x73AC9EFA6D2AEA58ULL,
		0x9C5F494985164130ULL,
		0x3AC8832DE675E83BULL,
		0xE33837ECD4C45C3BULL,
		0x9E1ECA2728502130ULL,
		0x0119BB9B01086943ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6815A702E695B78CULL,
		0x4BF2F19CDD85897EULL,
		0xE7593DF4DA55D4B1ULL,
		0x38BE92930A2C8260ULL,
		0x7591065BCCEBD077ULL,
		0xC6706FD9A988B876ULL,
		0x3C3D944E50A04261ULL,
		0x023377360210D287ULL
	}};
	printf("Test Case 63\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 63 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -63;
	} else {
		printf("Test Case 63 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x93F1718E4481ADFBULL,
		0xA816F69C6A71A946ULL,
		0x927EC98EF5499689ULL,
		0xA8E18CD33BAB482CULL,
		0xAB2C7934278C76E9ULL,
		0x186079F2EF383041ULL,
		0x56CE22BD7D1EAA6AULL,
		0x2C9DC00789C43AA4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x27E2E31C89035BF6ULL,
		0x502DED38D4E3528DULL,
		0x24FD931DEA932D13ULL,
		0x51C319A677569059ULL,
		0x5658F2684F18EDD3ULL,
		0x30C0F3E5DE706083ULL,
		0xAD9C457AFA3D54D4ULL,
		0x593B800F13887548ULL
	}};
	printf("Test Case 64\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 64 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -64;
	} else {
		printf("Test Case 64 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4BB00AB2656E5530ULL,
		0x3F5573D80B3D7478ULL,
		0xAF431E3982AC0D82ULL,
		0x1E577773DB606E57ULL,
		0x0F8F3981BFF542A9ULL,
		0x0988BBC638E8CB1BULL,
		0xF4513D7F78DE4CC1ULL,
		0x381DB561393210D0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x97601564CADCAA60ULL,
		0x7EAAE7B0167AE8F0ULL,
		0x5E863C7305581B04ULL,
		0x3CAEEEE7B6C0DCAFULL,
		0x1F1E73037FEA8552ULL,
		0x1311778C71D19636ULL,
		0xE8A27AFEF1BC9982ULL,
		0x703B6AC2726421A1ULL
	}};
	printf("Test Case 65\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 65 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -65;
	} else {
		printf("Test Case 65 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x57329290E087C7AEULL,
		0x628E47516BB182E0ULL,
		0xF7DE0BF58406F7BFULL,
		0x202BD71A699C12F3ULL,
		0xC1BC8DC5F89FA7F8ULL,
		0xAACB49B5E4D9CAEEULL,
		0x6BB2C15870A11DD8ULL,
		0x31E7D38C91547339ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAE652521C10F8F5CULL,
		0xC51C8EA2D76305C0ULL,
		0xEFBC17EB080DEF7EULL,
		0x4057AE34D33825E7ULL,
		0x83791B8BF13F4FF0ULL,
		0x5596936BC9B395DDULL,
		0xD76582B0E1423BB1ULL,
		0x63CFA71922A8E672ULL
	}};
	printf("Test Case 66\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 66 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -66;
	} else {
		printf("Test Case 66 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x986C367D77FB8326ULL,
		0x691E1967FB5CE02EULL,
		0xF14E1945C19B17D6ULL,
		0xDA9B8EEB3AA12180ULL,
		0x9BE5B2D3922572DAULL,
		0xC0EEB791294E4BBBULL,
		0xB8C59873068F3923ULL,
		0x226BA7FBC689700AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x30D86CFAEFF7064CULL,
		0xD23C32CFF6B9C05DULL,
		0xE29C328B83362FACULL,
		0xB5371DD675424301ULL,
		0x37CB65A7244AE5B5ULL,
		0x81DD6F22529C9777ULL,
		0x718B30E60D1E7247ULL,
		0x44D74FF78D12E015ULL
	}};
	printf("Test Case 67\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 67 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -67;
	} else {
		printf("Test Case 67 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA1E620A3E990CC3DULL,
		0xC72AF3FF8D70BBF5ULL,
		0x30D94EA9940EDBC9ULL,
		0x68B0325C45E54821ULL,
		0x6D3C81106A0D4D60ULL,
		0x690B6BB82A4640FFULL,
		0xBB7715D437424E3BULL,
		0x308A7873D1380195ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x43CC4147D321987AULL,
		0x8E55E7FF1AE177EBULL,
		0x61B29D53281DB793ULL,
		0xD16064B88BCA9042ULL,
		0xDA790220D41A9AC0ULL,
		0xD216D770548C81FEULL,
		0x76EE2BA86E849C76ULL,
		0x6114F0E7A270032BULL
	}};
	printf("Test Case 68\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 68 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -68;
	} else {
		printf("Test Case 68 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x53BFAC92EECAB46EULL,
		0xC4DB89F23F72196BULL,
		0x371A92A224D02040ULL,
		0x17CF136383CE3A48ULL,
		0x6058757D16D63428ULL,
		0x2C71B86957342958ULL,
		0x44FBF1AE4C365CBCULL,
		0x33ABAFECA6DDA140ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA77F5925DD9568DCULL,
		0x89B713E47EE432D6ULL,
		0x6E35254449A04081ULL,
		0x2F9E26C7079C7490ULL,
		0xC0B0EAFA2DAC6850ULL,
		0x58E370D2AE6852B0ULL,
		0x89F7E35C986CB978ULL,
		0x67575FD94DBB4280ULL
	}};
	printf("Test Case 69\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 69 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -69;
	} else {
		printf("Test Case 69 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1BF19363029F1EECULL,
		0x31A21B477EDA7AC3ULL,
		0x545B90100ABF8E1FULL,
		0x575D0E6EA59CAF4AULL,
		0x64D157B1A2B995B8ULL,
		0x7F06987336372085ULL,
		0x3FAA87E3474AB640ULL,
		0x3596DAEC707F22A5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x37E326C6053E3DD8ULL,
		0x6344368EFDB4F586ULL,
		0xA8B72020157F1C3EULL,
		0xAEBA1CDD4B395E94ULL,
		0xC9A2AF6345732B70ULL,
		0xFE0D30E66C6E410AULL,
		0x7F550FC68E956C80ULL,
		0x6B2DB5D8E0FE454AULL
	}};
	printf("Test Case 70\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 70 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -70;
	} else {
		printf("Test Case 70 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBD6669F91C334FF8ULL,
		0x501DA16DABA301F5ULL,
		0x922584FC646821DCULL,
		0x2EDE7767C74C282AULL,
		0xEC9AE321C023591CULL,
		0xD50ACEC5002FDB3FULL,
		0xC674FDAE4180BE9BULL,
		0x046425254BCC015CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7ACCD3F238669FF0ULL,
		0xA03B42DB574603EBULL,
		0x244B09F8C8D043B8ULL,
		0x5DBCEECF8E985055ULL,
		0xD935C6438046B238ULL,
		0xAA159D8A005FB67FULL,
		0x8CE9FB5C83017D37ULL,
		0x08C84A4A979802B9ULL
	}};
	printf("Test Case 71\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 71 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -71;
	} else {
		printf("Test Case 71 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x50AEFB0582E12B15ULL,
		0x7DA1FC6ED739AB25ULL,
		0xE3A5B36E669F962BULL,
		0x6780F1C530B98F05ULL,
		0xA16FC62CC3BE34ABULL,
		0x133BDA9661853F76ULL,
		0x35FA91503756697AULL,
		0x3E5ACD598CA1F296ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA15DF60B05C2562AULL,
		0xFB43F8DDAE73564AULL,
		0xC74B66DCCD3F2C56ULL,
		0xCF01E38A61731E0BULL,
		0x42DF8C59877C6956ULL,
		0x2677B52CC30A7EEDULL,
		0x6BF522A06EACD2F4ULL,
		0x7CB59AB31943E52CULL
	}};
	printf("Test Case 72\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 72 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -72;
	} else {
		printf("Test Case 72 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFF735615B041C69CULL,
		0x27F11A4F44CE1B28ULL,
		0x373C003140A776B7ULL,
		0x217031017F657105ULL,
		0xB27482EA586C6D06ULL,
		0x5DF2D13D24BD1EE3ULL,
		0xDCCD1DE5B588D5E4ULL,
		0x1E846F894E1F9259ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFEE6AC2B60838D38ULL,
		0x4FE2349E899C3651ULL,
		0x6E780062814EED6EULL,
		0x42E06202FECAE20AULL,
		0x64E905D4B0D8DA0CULL,
		0xBBE5A27A497A3DC7ULL,
		0xB99A3BCB6B11ABC8ULL,
		0x3D08DF129C3F24B3ULL
	}};
	printf("Test Case 73\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 73 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -73;
	} else {
		printf("Test Case 73 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0EBE1043A926D34CULL,
		0x7C0E549AF3A75DFFULL,
		0xA8A225956F4B37C0ULL,
		0xC13B67D3A64133A0ULL,
		0xC70A3ABF64CD63D1ULL,
		0x7A58B1EDB4C7B82CULL,
		0xF67061BE4C5FCB7FULL,
		0x214B45D8D1DD0F2BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1D7C2087524DA698ULL,
		0xF81CA935E74EBBFEULL,
		0x51444B2ADE966F80ULL,
		0x8276CFA74C826741ULL,
		0x8E14757EC99AC7A3ULL,
		0xF4B163DB698F7059ULL,
		0xECE0C37C98BF96FEULL,
		0x42968BB1A3BA1E57ULL
	}};
	printf("Test Case 74\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 74 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -74;
	} else {
		printf("Test Case 74 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAE261ADDF96A1612ULL,
		0x130B1E882A20F42EULL,
		0x5AFAE7DD1470B691ULL,
		0x09D4BA76C4627920ULL,
		0x5041DBFB9836DC90ULL,
		0x8258A9695EC5A5A3ULL,
		0x0AD2B85F6CF95BC6ULL,
		0x24BAC1E7B017AF5FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5C4C35BBF2D42C24ULL,
		0x26163D105441E85DULL,
		0xB5F5CFBA28E16D22ULL,
		0x13A974ED88C4F240ULL,
		0xA083B7F7306DB920ULL,
		0x04B152D2BD8B4B46ULL,
		0x15A570BED9F2B78DULL,
		0x497583CF602F5EBEULL
	}};
	printf("Test Case 75\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 75 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -75;
	} else {
		printf("Test Case 75 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x63E2A16C9C4A9627ULL,
		0xFA4995F9AEAE0EF2ULL,
		0x8C00E7FFB2F8C574ULL,
		0xAD7C61ADF14F1B24ULL,
		0x6FA7DDF26EE501AFULL,
		0x925A8F990DB4799DULL,
		0x846CAAAA74CC3FE2ULL,
		0x087F7C25EA0AC3C3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC7C542D938952C4EULL,
		0xF4932BF35D5C1DE4ULL,
		0x1801CFFF65F18AE9ULL,
		0x5AF8C35BE29E3649ULL,
		0xDF4FBBE4DDCA035FULL,
		0x24B51F321B68F33AULL,
		0x08D95554E9987FC5ULL,
		0x10FEF84BD4158787ULL
	}};
	printf("Test Case 76\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 76 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -76;
	} else {
		printf("Test Case 76 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x57FDE0B244663905ULL,
		0xA6710F7AB81CBC31ULL,
		0xE79B36AB0ADA3CFEULL,
		0xA7BDFD06E74E40B6ULL,
		0x8452B5F74C977803ULL,
		0x6B2A30BD83581196ULL,
		0x28092FB90F2519B3ULL,
		0x2755874263E1AA7EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAFFBC16488CC720AULL,
		0x4CE21EF570397862ULL,
		0xCF366D5615B479FDULL,
		0x4F7BFA0DCE9C816DULL,
		0x08A56BEE992EF007ULL,
		0xD654617B06B0232DULL,
		0x50125F721E4A3366ULL,
		0x4EAB0E84C7C354FCULL
	}};
	printf("Test Case 77\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 77 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -77;
	} else {
		printf("Test Case 77 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4E32A6D70B67D080ULL,
		0xE38595DFB15254C6ULL,
		0xC3129B94571E789CULL,
		0x55F312E0CF8E3568ULL,
		0xCE6F54511E468671ULL,
		0xB51D49D4B9D67360ULL,
		0x5BF60C54C6E6D7C5ULL,
		0x3636696B49F9AF67ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9C654DAE16CFA100ULL,
		0xC70B2BBF62A4A98CULL,
		0x86253728AE3CF139ULL,
		0xABE625C19F1C6AD1ULL,
		0x9CDEA8A23C8D0CE2ULL,
		0x6A3A93A973ACE6C1ULL,
		0xB7EC18A98DCDAF8BULL,
		0x6C6CD2D693F35ECEULL
	}};
	printf("Test Case 78\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 78 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -78;
	} else {
		printf("Test Case 78 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCFA8696843B88FEEULL,
		0x287FA1B9639A2FD4ULL,
		0xF582C8E77D45B353ULL,
		0x7F5755827A00E448ULL,
		0xC8FB849937294035ULL,
		0x7C8CA47EF6CD63A4ULL,
		0x5813349F833404E5ULL,
		0x2C7AD8A21097673EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9F50D2D087711FDCULL,
		0x50FF4372C7345FA9ULL,
		0xEB0591CEFA8B66A6ULL,
		0xFEAEAB04F401C891ULL,
		0x91F709326E52806AULL,
		0xF91948FDED9AC749ULL,
		0xB026693F066809CAULL,
		0x58F5B144212ECE7CULL
	}};
	printf("Test Case 79\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 79 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -79;
	} else {
		printf("Test Case 79 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCCA775B384AE19EAULL,
		0x7DAB34E9C391C7D5ULL,
		0xF860DB9BD813D7A5ULL,
		0x703CC2E6438D8921ULL,
		0x3A57D08C3D04D9A1ULL,
		0x53EE063B86BDA790ULL,
		0xA1566EAD9E9DFB42ULL,
		0x0520FB63D7157B0EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x994EEB67095C33D4ULL,
		0xFB5669D387238FABULL,
		0xF0C1B737B027AF4AULL,
		0xE07985CC871B1243ULL,
		0x74AFA1187A09B342ULL,
		0xA7DC0C770D7B4F20ULL,
		0x42ACDD5B3D3BF684ULL,
		0x0A41F6C7AE2AF61DULL
	}};
	printf("Test Case 80\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 80 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -80;
	} else {
		printf("Test Case 80 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB4391EA5515359EFULL,
		0x1E7E9E266E6085CDULL,
		0x9EEB3BE68AD43BE3ULL,
		0x5670F12788E625D0ULL,
		0xD59BA845F9EFC2BAULL,
		0xFA5DF47A46A4C3A6ULL,
		0x2ACF2F3189849142ULL,
		0x1BFE1674E5568A94ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x68723D4AA2A6B3DEULL,
		0x3CFD3C4CDCC10B9BULL,
		0x3DD677CD15A877C6ULL,
		0xACE1E24F11CC4BA1ULL,
		0xAB37508BF3DF8574ULL,
		0xF4BBE8F48D49874DULL,
		0x559E5E6313092285ULL,
		0x37FC2CE9CAAD1528ULL
	}};
	printf("Test Case 81\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 81 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -81;
	} else {
		printf("Test Case 81 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6F293DCDD2ADE0C8ULL,
		0xF407594964AAA918ULL,
		0x665422EE519A206AULL,
		0xD2D41ED87818C39BULL,
		0x40296922FE601890ULL,
		0x91900F288A363AD4ULL,
		0x21F37D6F7001CBD2ULL,
		0x301011EC977FEDA5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDE527B9BA55BC190ULL,
		0xE80EB292C9555230ULL,
		0xCCA845DCA33440D5ULL,
		0xA5A83DB0F0318736ULL,
		0x8052D245FCC03121ULL,
		0x23201E51146C75A8ULL,
		0x43E6FADEE00397A5ULL,
		0x602023D92EFFDB4AULL
	}};
	printf("Test Case 82\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 82 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -82;
	} else {
		printf("Test Case 82 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB7D422F9ECFA5A5CULL,
		0xCBADE6CA168E1D48ULL,
		0x512DAFA957051EE1ULL,
		0xCD13893E36F42019ULL,
		0xD1C8877688B19AEAULL,
		0xBA713C9AE412AADDULL,
		0x227899B6D4EA8785ULL,
		0x13AA719276576B89ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6FA845F3D9F4B4B8ULL,
		0x975BCD942D1C3A91ULL,
		0xA25B5F52AE0A3DC3ULL,
		0x9A27127C6DE84032ULL,
		0xA3910EED116335D5ULL,
		0x74E27935C82555BBULL,
		0x44F1336DA9D50F0BULL,
		0x2754E324ECAED712ULL
	}};
	printf("Test Case 83\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 83 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -83;
	} else {
		printf("Test Case 83 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBA037336A4B2EE9FULL,
		0x90939AD51107CAB6ULL,
		0x6AB710D3D0AEB627ULL,
		0xE43D63A1E31A7C31ULL,
		0xA9D4933047E1C5C3ULL,
		0xE828308C1E2C4AEFULL,
		0x6EE38D5F94EB2533ULL,
		0x24CF649710D1DF96ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7406E66D4965DD3EULL,
		0x212735AA220F956DULL,
		0xD56E21A7A15D6C4FULL,
		0xC87AC743C634F862ULL,
		0x53A926608FC38B87ULL,
		0xD05061183C5895DFULL,
		0xDDC71ABF29D64A67ULL,
		0x499EC92E21A3BF2CULL
	}};
	printf("Test Case 84\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 84 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -84;
	} else {
		printf("Test Case 84 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8FB48BC756982DABULL,
		0x08423039A219300EULL,
		0xE9E904B7C4EA7ED9ULL,
		0xC0C81B8287B84B8EULL,
		0x162BB06CA95AD2F4ULL,
		0xB6F4B1A6EC8CC7C7ULL,
		0x291F35F3169EAB22ULL,
		0x22DF00584B748CE2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1F69178EAD305B56ULL,
		0x108460734432601DULL,
		0xD3D2096F89D4FDB2ULL,
		0x819037050F70971DULL,
		0x2C5760D952B5A5E9ULL,
		0x6DE9634DD9198F8EULL,
		0x523E6BE62D3D5645ULL,
		0x45BE00B096E919C4ULL
	}};
	printf("Test Case 85\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 85 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -85;
	} else {
		printf("Test Case 85 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x593F34E53D5BECBAULL,
		0xCB2C4D8893A17279ULL,
		0x617BCF1C46916938ULL,
		0x571246C986906CA7ULL,
		0xC91353149DA57FE5ULL,
		0x29CE4F33BBD235B5ULL,
		0x9CBCFBE540F09459ULL,
		0x02F9183C59048ED4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB27E69CA7AB7D974ULL,
		0x96589B112742E4F2ULL,
		0xC2F79E388D22D271ULL,
		0xAE248D930D20D94EULL,
		0x9226A6293B4AFFCAULL,
		0x539C9E6777A46B6BULL,
		0x3979F7CA81E128B2ULL,
		0x05F23078B2091DA9ULL
	}};
	printf("Test Case 86\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 86 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -86;
	} else {
		printf("Test Case 86 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3BC58C3B3EDF6F5FULL,
		0x7DD090A0178F3C53ULL,
		0x6EE26DFD8AE7AD01ULL,
		0x8D6606927677A8DCULL,
		0xCF8214F993F84BCCULL,
		0x5A781278D7981F00ULL,
		0xD911DBBEBD0419F4ULL,
		0x17EB3ADC17BEA7DBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x778B18767DBEDEBEULL,
		0xFBA121402F1E78A6ULL,
		0xDDC4DBFB15CF5A02ULL,
		0x1ACC0D24ECEF51B8ULL,
		0x9F0429F327F09799ULL,
		0xB4F024F1AF303E01ULL,
		0xB223B77D7A0833E8ULL,
		0x2FD675B82F7D4FB7ULL
	}};
	printf("Test Case 87\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 87 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -87;
	} else {
		printf("Test Case 87 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x399B302A1B8200EAULL,
		0x55547F64773242C5ULL,
		0x9C6EC2948AF49F4EULL,
		0xA8D7415D366EDC9AULL,
		0x44C458C2054B3D64ULL,
		0x4795674D039CDA99ULL,
		0x1424D92CF394A54CULL,
		0x0A4E58A5FD06212DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x73366054370401D4ULL,
		0xAAA8FEC8EE64858AULL,
		0x38DD852915E93E9CULL,
		0x51AE82BA6CDDB935ULL,
		0x8988B1840A967AC9ULL,
		0x8F2ACE9A0739B532ULL,
		0x2849B259E7294A98ULL,
		0x149CB14BFA0C425AULL
	}};
	printf("Test Case 88\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 88 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -88;
	} else {
		printf("Test Case 88 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x28471B558404E234ULL,
		0x3A716B6975665725ULL,
		0xE4AAD134014C7EE9ULL,
		0x152AEC187C27F115ULL,
		0xF7BE7A2AC171DCF7ULL,
		0x3DF85C8CF9A4864DULL,
		0xFF3A347D968F69E0ULL,
		0x0A8BB9942209339EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x508E36AB0809C468ULL,
		0x74E2D6D2EACCAE4AULL,
		0xC955A2680298FDD2ULL,
		0x2A55D830F84FE22BULL,
		0xEF7CF45582E3B9EEULL,
		0x7BF0B919F3490C9BULL,
		0xFE7468FB2D1ED3C0ULL,
		0x151773284412673DULL
	}};
	printf("Test Case 89\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 89 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -89;
	} else {
		printf("Test Case 89 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x69428F0B8A7259F9ULL,
		0xBCC36CD3ABFD09D2ULL,
		0xC4DE40DB9F310B1BULL,
		0x0068A63FE22B9189ULL,
		0x338904227EF90222ULL,
		0xF15405F6B29BEBDBULL,
		0x0F3E2150023834C3ULL,
		0x30F86D52CE30908FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD2851E1714E4B3F2ULL,
		0x7986D9A757FA13A4ULL,
		0x89BC81B73E621637ULL,
		0x00D14C7FC4572313ULL,
		0x67120844FDF20444ULL,
		0xE2A80BED6537D7B6ULL,
		0x1E7C42A004706987ULL,
		0x61F0DAA59C61211EULL
	}};
	printf("Test Case 90\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 90 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -90;
	} else {
		printf("Test Case 90 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3AEB2B4548834A2EULL,
		0xEE4720C5F415E6F1ULL,
		0xBD5C3FF8C6F2566DULL,
		0x01D0888C051ECB2EULL,
		0xBD1161BB45D55380ULL,
		0xAD4838EC65E32566ULL,
		0xBE93DA683BDA780AULL,
		0x09935EF4187CA397ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x75D6568A9106945CULL,
		0xDC8E418BE82BCDE2ULL,
		0x7AB87FF18DE4ACDBULL,
		0x03A111180A3D965DULL,
		0x7A22C3768BAAA700ULL,
		0x5A9071D8CBC64ACDULL,
		0x7D27B4D077B4F015ULL,
		0x1326BDE830F9472FULL
	}};
	printf("Test Case 91\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 91 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -91;
	} else {
		printf("Test Case 91 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7784D971D1B8D1A2ULL,
		0xF49D29AA3AC4B516ULL,
		0xE408D0503940C6E9ULL,
		0xBEBFF80F1995BBC9ULL,
		0x2DA61AB1FF6CE85AULL,
		0xF37B7A49CEBC4DC0ULL,
		0x49F6834EB2EDE2F4ULL,
		0x24FB92E4B66F824BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEF09B2E3A371A344ULL,
		0xE93A535475896A2CULL,
		0xC811A0A072818DD3ULL,
		0x7D7FF01E332B7793ULL,
		0x5B4C3563FED9D0B5ULL,
		0xE6F6F4939D789B80ULL,
		0x93ED069D65DBC5E9ULL,
		0x49F725C96CDF0496ULL
	}};
	printf("Test Case 92\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 92 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -92;
	} else {
		printf("Test Case 92 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7806F9B68D043014ULL,
		0xEEF37591A2170C08ULL,
		0x0F3732F5A0FF42D8ULL,
		0x75C866E310A767DDULL,
		0x4445169BE94A8E48ULL,
		0xEF80429731B25D0EULL,
		0x27CF6919904FBF4DULL,
		0x36DEEA9AE04DDAE2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF00DF36D1A086028ULL,
		0xDDE6EB23442E1810ULL,
		0x1E6E65EB41FE85B1ULL,
		0xEB90CDC6214ECFBAULL,
		0x888A2D37D2951C90ULL,
		0xDF00852E6364BA1CULL,
		0x4F9ED233209F7E9BULL,
		0x6DBDD535C09BB5C4ULL
	}};
	printf("Test Case 93\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 93 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -93;
	} else {
		printf("Test Case 93 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x26B2F2ADE6042247ULL,
		0xBD1401E51940BCB2ULL,
		0xA105F62E8942B07EULL,
		0xBAE4BB66F90C635AULL,
		0x5C1B7B1F892DB264ULL,
		0x72788663A67A175BULL,
		0x53BD4F1302B667F9ULL,
		0x038B46BA784F8C47ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4D65E55BCC08448EULL,
		0x7A2803CA32817964ULL,
		0x420BEC5D128560FDULL,
		0x75C976CDF218C6B5ULL,
		0xB836F63F125B64C9ULL,
		0xE4F10CC74CF42EB6ULL,
		0xA77A9E26056CCFF2ULL,
		0x07168D74F09F188EULL
	}};
	printf("Test Case 94\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 94 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -94;
	} else {
		printf("Test Case 94 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6F990342EB55BFD1ULL,
		0x10ED2E3A108D9FAEULL,
		0xDFE673FE510FF66EULL,
		0x0939ACB7DFEFDC86ULL,
		0x39B181FEF143EEB6ULL,
		0xB57C05C850DE18FFULL,
		0xBA4F563499FDDBF8ULL,
		0x2D0D0A0FA70CDC0DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDF320685D6AB7FA2ULL,
		0x21DA5C74211B3F5CULL,
		0xBFCCE7FCA21FECDCULL,
		0x1273596FBFDFB90DULL,
		0x736303FDE287DD6CULL,
		0x6AF80B90A1BC31FEULL,
		0x749EAC6933FBB7F1ULL,
		0x5A1A141F4E19B81BULL
	}};
	printf("Test Case 95\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 95 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -95;
	} else {
		printf("Test Case 95 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x24798892C8594C15ULL,
		0x6DDA13B4F3952367ULL,
		0x4DB669CD7ABDCE40ULL,
		0xAB26A1A4BA4A1B9FULL,
		0x84528B40A00EA249ULL,
		0xDF69199A1D7C642BULL,
		0x5892AA9F2041ED0EULL,
		0x05BE2109CD6CB077ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x48F3112590B2982AULL,
		0xDBB42769E72A46CEULL,
		0x9B6CD39AF57B9C80ULL,
		0x564D43497494373EULL,
		0x08A51681401D4493ULL,
		0xBED233343AF8C857ULL,
		0xB125553E4083DA1DULL,
		0x0B7C42139AD960EEULL
	}};
	printf("Test Case 96\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 96 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -96;
	} else {
		printf("Test Case 96 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAA5EC69EEFD9372EULL,
		0xC7CDF7FCA925979DULL,
		0x78111394E7C1E624ULL,
		0x5A695204942C59A6ULL,
		0xB215C17C484A3368ULL,
		0x4B818B167861FC55ULL,
		0x0C582AD628F66A5DULL,
		0x0D0A97144287175AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x54BD8D3DDFB26E5CULL,
		0x8F9BEFF9524B2F3BULL,
		0xF0222729CF83CC49ULL,
		0xB4D2A4092858B34CULL,
		0x642B82F8909466D0ULL,
		0x9703162CF0C3F8ABULL,
		0x18B055AC51ECD4BAULL,
		0x1A152E28850E2EB4ULL
	}};
	printf("Test Case 97\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 97 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -97;
	} else {
		printf("Test Case 97 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3AE61AFCA1F284C5ULL,
		0xF16C27FBE4BE5B88ULL,
		0x38D1C8B76C2BA62EULL,
		0xA0478C3C97973EADULL,
		0xED211C8F83D46319ULL,
		0x9FC3BEFA190763F0ULL,
		0xCEF07751112AC0B6ULL,
		0x0D9A41470CB9E306ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x75CC35F943E5098AULL,
		0xE2D84FF7C97CB710ULL,
		0x71A3916ED8574C5DULL,
		0x408F18792F2E7D5AULL,
		0xDA42391F07A8C633ULL,
		0x3F877DF4320EC7E1ULL,
		0x9DE0EEA22255816DULL,
		0x1B34828E1973C60DULL
	}};
	printf("Test Case 98\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 98 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -98;
	} else {
		printf("Test Case 98 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1AE8B169FDB83D10ULL,
		0xB9B892D3C262502CULL,
		0x418F88F31FE6A739ULL,
		0xDCD42EF178328D36ULL,
		0xD8ACF7F23A1BE319ULL,
		0xCFEF87B4BE50A344ULL,
		0xF1F54D361B28EF8AULL,
		0x259E136FDC85CAC7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x35D162D3FB707A20ULL,
		0x737125A784C4A058ULL,
		0x831F11E63FCD4E73ULL,
		0xB9A85DE2F0651A6CULL,
		0xB159EFE47437C633ULL,
		0x9FDF0F697CA14689ULL,
		0xE3EA9A6C3651DF15ULL,
		0x4B3C26DFB90B958FULL
	}};
	printf("Test Case 99\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 99 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -99;
	} else {
		printf("Test Case 99 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x043D9A3D2057F707ULL,
		0xB2815F41B1566915ULL,
		0xF7F8380B48A8E92CULL,
		0x7B352EF112446176ULL,
		0x7C9BDBB69EE27EE9ULL,
		0x0CBE1C5793D90C04ULL,
		0xF135E52835A5D2FAULL,
		0x0FB6219DEF19A6E2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x087B347A40AFEE0EULL,
		0x6502BE8362ACD22AULL,
		0xEFF070169151D259ULL,
		0xF66A5DE22488C2EDULL,
		0xF937B76D3DC4FDD2ULL,
		0x197C38AF27B21808ULL,
		0xE26BCA506B4BA5F4ULL,
		0x1F6C433BDE334DC5ULL
	}};
	printf("Test Case 100\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 100 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -100;
	} else {
		printf("Test Case 100 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5B560D5A0F79D0EAULL,
		0x5E5C0F8DC8C5C8D7ULL,
		0x89B8AEF3A82CE947ULL,
		0x61841429EF848A9DULL,
		0xEC561EF6A9F04B12ULL,
		0x9F2212FF7C8303F3ULL,
		0x2FD3C874EFC2F647ULL,
		0x16A0F4F5AABA213CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB6AC1AB41EF3A1D4ULL,
		0xBCB81F1B918B91AEULL,
		0x13715DE75059D28EULL,
		0xC3082853DF09153BULL,
		0xD8AC3DED53E09624ULL,
		0x3E4425FEF90607E7ULL,
		0x5FA790E9DF85EC8FULL,
		0x2D41E9EB55744278ULL
	}};
	printf("Test Case 101\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 101 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -101;
	} else {
		printf("Test Case 101 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF8A347123C515826ULL,
		0xD3E30EFB7974261CULL,
		0x9EA3A0927FEE91B6ULL,
		0x8C8F1F839EACEF35ULL,
		0x7556B851614DFED3ULL,
		0xEA605A3C029EF197ULL,
		0x3C1A81B8E7416EF3ULL,
		0x2FC36A63A15974C5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF1468E2478A2B04CULL,
		0xA7C61DF6F2E84C39ULL,
		0x3D474124FFDD236DULL,
		0x191E3F073D59DE6BULL,
		0xEAAD70A2C29BFDA7ULL,
		0xD4C0B478053DE32EULL,
		0x78350371CE82DDE7ULL,
		0x5F86D4C742B2E98AULL
	}};
	printf("Test Case 102\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 102 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -102;
	} else {
		printf("Test Case 102 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6D6AA85BCD1FCC12ULL,
		0xDEEE75A3C233E711ULL,
		0xD8CD3BE57741CB15ULL,
		0x914FF0A557DE6EFEULL,
		0x874F5E81DD49AB73ULL,
		0xEFD031C057EF6E95ULL,
		0x3561AC565A87DE2AULL,
		0x04D960C952AE24D1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDAD550B79A3F9824ULL,
		0xBDDCEB478467CE22ULL,
		0xB19A77CAEE83962BULL,
		0x229FE14AAFBCDDFDULL,
		0x0E9EBD03BA9356E7ULL,
		0xDFA06380AFDEDD2BULL,
		0x6AC358ACB50FBC55ULL,
		0x09B2C192A55C49A2ULL
	}};
	printf("Test Case 103\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 103 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -103;
	} else {
		printf("Test Case 103 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEAEAB73D2C32CC59ULL,
		0xE63E3C3E0410A7D1ULL,
		0x90362AA721D48AD3ULL,
		0x26DCC6CA2601CB90ULL,
		0x5A7FB54C7B443FC5ULL,
		0x5B7B1FB9BBB7BD1AULL,
		0x3EB5E29E12F9B48BULL,
		0x08CFD5F3FAF13593ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD5D56E7A586598B2ULL,
		0xCC7C787C08214FA3ULL,
		0x206C554E43A915A7ULL,
		0x4DB98D944C039721ULL,
		0xB4FF6A98F6887F8AULL,
		0xB6F63F73776F7A34ULL,
		0x7D6BC53C25F36916ULL,
		0x119FABE7F5E26B26ULL
	}};
	printf("Test Case 104\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 104 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -104;
	} else {
		printf("Test Case 104 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4354AB994B0A26F3ULL,
		0x32D2C72C1A48D05AULL,
		0x50ECEE85665BF2A1ULL,
		0x3BE5254E777B784BULL,
		0x4076579822D82E4CULL,
		0xBF26448DBE7C7724ULL,
		0xBFCFB4126B4754F4ULL,
		0x0D09957412EF2867ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x86A9573296144DE6ULL,
		0x65A58E583491A0B4ULL,
		0xA1D9DD0ACCB7E542ULL,
		0x77CA4A9CEEF6F096ULL,
		0x80ECAF3045B05C98ULL,
		0x7E4C891B7CF8EE48ULL,
		0x7F9F6824D68EA9E9ULL,
		0x1A132AE825DE50CFULL
	}};
	printf("Test Case 105\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 105 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -105;
	} else {
		printf("Test Case 105 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3CCCD987D37305EAULL,
		0x315EC30AF7420600ULL,
		0xB7099CB84C7155CEULL,
		0x9389A6FB196BFFB1ULL,
		0xF59AD83E030DFE4DULL,
		0xE09953E7BE10D371ULL,
		0xB2474F631833093CULL,
		0x3B659BC34F376A98ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7999B30FA6E60BD4ULL,
		0x62BD8615EE840C00ULL,
		0x6E13397098E2AB9CULL,
		0x27134DF632D7FF63ULL,
		0xEB35B07C061BFC9BULL,
		0xC132A7CF7C21A6E3ULL,
		0x648E9EC630661279ULL,
		0x76CB37869E6ED531ULL
	}};
	printf("Test Case 106\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 106 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -106;
	} else {
		printf("Test Case 106 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF0DDD7F36C646F8EULL,
		0xC6C96D02DC41C16AULL,
		0xADFBF75F0F889593ULL,
		0xFA89A77421329B10ULL,
		0xCA576DD6B6D66462ULL,
		0x738C04851A366C28ULL,
		0xEE4A24DD9CF3083BULL,
		0x0D489C6C4C6A2647ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE1BBAFE6D8C8DF1CULL,
		0x8D92DA05B88382D5ULL,
		0x5BF7EEBE1F112B27ULL,
		0xF5134EE842653621ULL,
		0x94AEDBAD6DACC8C5ULL,
		0xE718090A346CD851ULL,
		0xDC9449BB39E61076ULL,
		0x1A9138D898D44C8FULL
	}};
	printf("Test Case 107\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 107 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -107;
	} else {
		printf("Test Case 107 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x078630C2CBAFB37FULL,
		0x456B4326461AB519ULL,
		0x1D41BC2FA80312FAULL,
		0xD4132FED75479CB9ULL,
		0xB42EBE51CBF477AEULL,
		0x311F22B95EE9269FULL,
		0xFF5BD8A8A6EA91EBULL,
		0x3388FACE6E5616ACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F0C6185975F66FEULL,
		0x8AD6864C8C356A32ULL,
		0x3A83785F500625F4ULL,
		0xA8265FDAEA8F3972ULL,
		0x685D7CA397E8EF5DULL,
		0x623E4572BDD24D3FULL,
		0xFEB7B1514DD523D6ULL,
		0x6711F59CDCAC2D59ULL
	}};
	printf("Test Case 108\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 108 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -108;
	} else {
		printf("Test Case 108 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x25A7D4C7019701DFULL,
		0x389C617B4DBABD12ULL,
		0xBCED0BA94DCA5D9CULL,
		0x15ABA905DA6DDD06ULL,
		0x97E1CD48FCBDDD2AULL,
		0x3A3AEB2179F14A95ULL,
		0xDF805DBC60DEF3E1ULL,
		0x2690D09B9982A864ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4B4FA98E032E03BEULL,
		0x7138C2F69B757A24ULL,
		0x79DA17529B94BB38ULL,
		0x2B57520BB4DBBA0DULL,
		0x2FC39A91F97BBA54ULL,
		0x7475D642F3E2952BULL,
		0xBF00BB78C1BDE7C2ULL,
		0x4D21A137330550C9ULL
	}};
	printf("Test Case 109\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 109 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -109;
	} else {
		printf("Test Case 109 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x58421310F7544E22ULL,
		0xC581B7C97E5A9890ULL,
		0x391D4179D6C18C0FULL,
		0x9BACD2C71284D342ULL,
		0x74755DC36E102CE7ULL,
		0xAE1F3F3952E7769EULL,
		0xA06CDE31599123A0ULL,
		0x00C68A53772292B9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB0842621EEA89C44ULL,
		0x8B036F92FCB53120ULL,
		0x723A82F3AD83181FULL,
		0x3759A58E2509A684ULL,
		0xE8EABB86DC2059CFULL,
		0x5C3E7E72A5CEED3CULL,
		0x40D9BC62B3224741ULL,
		0x018D14A6EE452573ULL
	}};
	printf("Test Case 110\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 110 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -110;
	} else {
		printf("Test Case 110 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x022D815B37A15A0DULL,
		0xAF0581DFD051058EULL,
		0x6E96DA6D1150B917ULL,
		0xCD9FFF91EB26A194ULL,
		0x312453E650DE0615ULL,
		0xB787E24577D5770EULL,
		0x27E3BBA37E0BB5ECULL,
		0x0592993FBB7C8A3FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x045B02B66F42B41AULL,
		0x5E0B03BFA0A20B1CULL,
		0xDD2DB4DA22A1722FULL,
		0x9B3FFF23D64D4328ULL,
		0x6248A7CCA1BC0C2BULL,
		0x6F0FC48AEFAAEE1CULL,
		0x4FC77746FC176BD9ULL,
		0x0B25327F76F9147EULL
	}};
	printf("Test Case 111\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 111 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -111;
	} else {
		printf("Test Case 111 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0FA1F097435BDDB2ULL,
		0xF1D3D34B3B294FC0ULL,
		0xF6B4082D9E0F48B9ULL,
		0x158535C2AF5C8CD0ULL,
		0x436F243C4F0B6AF3ULL,
		0x505B0A39C61EC6CAULL,
		0x3C420A87B9A77C0CULL,
		0x1EC6B1FE3C834EBBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1F43E12E86B7BB64ULL,
		0xE3A7A69676529F80ULL,
		0xED68105B3C1E9173ULL,
		0x2B0A6B855EB919A1ULL,
		0x86DE48789E16D5E6ULL,
		0xA0B614738C3D8D94ULL,
		0x7884150F734EF818ULL,
		0x3D8D63FC79069D76ULL
	}};
	printf("Test Case 112\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 112 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -112;
	} else {
		printf("Test Case 112 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8EB7368E8D81C232ULL,
		0x17DB95011347B892ULL,
		0x024CE13F00812824ULL,
		0x857DD1273E985D95ULL,
		0xD6EC094FC895D24BULL,
		0x978E3C482D19ECB6ULL,
		0x25B14D12E2CEDFFBULL,
		0x2C47F04847793685ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1D6E6D1D1B038464ULL,
		0x2FB72A02268F7125ULL,
		0x0499C27E01025048ULL,
		0x0AFBA24E7D30BB2AULL,
		0xADD8129F912BA497ULL,
		0x2F1C78905A33D96DULL,
		0x4B629A25C59DBFF7ULL,
		0x588FE0908EF26D0AULL
	}};
	printf("Test Case 113\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 113 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -113;
	} else {
		printf("Test Case 113 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x00D6AB00076B3D3BULL,
		0x7FF12D2129A82AA7ULL,
		0x53F979A20BA099ABULL,
		0xF7B36BAD568ECFCAULL,
		0x1ADD6B90218AB2A2ULL,
		0xF3B2F9C1545E3C14ULL,
		0x6136A59239308F69ULL,
		0x11CF7EE1FD1AD86DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x01AD56000ED67A76ULL,
		0xFFE25A425350554EULL,
		0xA7F2F34417413356ULL,
		0xEF66D75AAD1D9F94ULL,
		0x35BAD72043156545ULL,
		0xE765F382A8BC7828ULL,
		0xC26D4B2472611ED3ULL,
		0x239EFDC3FA35B0DAULL
	}};
	printf("Test Case 114\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 114 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -114;
	} else {
		printf("Test Case 114 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE24D1612D7CC0015ULL,
		0x1AD804AE0D19F2BAULL,
		0x07BF1572140B6132ULL,
		0x8F196801AC1BFFACULL,
		0xEF708BD8D610AB9DULL,
		0x6825AB062CC5E677ULL,
		0x782C0E388C6E0F60ULL,
		0x359FBA49D8C6E732ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC49A2C25AF98002AULL,
		0x35B0095C1A33E575ULL,
		0x0F7E2AE42816C264ULL,
		0x1E32D0035837FF58ULL,
		0xDEE117B1AC21573BULL,
		0xD04B560C598BCCEFULL,
		0xF0581C7118DC1EC0ULL,
		0x6B3F7493B18DCE64ULL
	}};
	printf("Test Case 115\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 115 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -115;
	} else {
		printf("Test Case 115 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x73D153FDE00C7065ULL,
		0xA9B6727BCBCA5D77ULL,
		0x12CFAC49A1FDA7A3ULL,
		0x9DE1806F8A25EABEULL,
		0xD19F61106EDD1B75ULL,
		0x5306B6B53EC51BEAULL,
		0x3D3F06BCDE3E4C96ULL,
		0x3B97AC76F10C5448ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE7A2A7FBC018E0CAULL,
		0x536CE4F79794BAEEULL,
		0x259F589343FB4F47ULL,
		0x3BC300DF144BD57CULL,
		0xA33EC220DDBA36EBULL,
		0xA60D6D6A7D8A37D5ULL,
		0x7A7E0D79BC7C992CULL,
		0x772F58EDE218A890ULL
	}};
	printf("Test Case 116\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 116 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -116;
	} else {
		printf("Test Case 116 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9E89B6B140606582ULL,
		0x575EA8EFD93FFE54ULL,
		0x7714C9DD91DA4396ULL,
		0x17F2EBC913AAA03CULL,
		0x1525E0C3491ADCF5ULL,
		0x4018375046B573D2ULL,
		0x33B21807AB1E5081ULL,
		0x38398A9E5A6744E9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3D136D6280C0CB04ULL,
		0xAEBD51DFB27FFCA9ULL,
		0xEE2993BB23B4872CULL,
		0x2FE5D79227554078ULL,
		0x2A4BC1869235B9EAULL,
		0x80306EA08D6AE7A4ULL,
		0x6764300F563CA102ULL,
		0x7073153CB4CE89D2ULL
	}};
	printf("Test Case 117\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 117 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -117;
	} else {
		printf("Test Case 117 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8FAF448897DF8938ULL,
		0xCAFA236AD11EDAA2ULL,
		0xBF12C4757AF2A838ULL,
		0x6AA0B678ADC56B62ULL,
		0x65BF84FDC4153875ULL,
		0x74D62635BBA5C97AULL,
		0xF7A7AE1AA9921C3AULL,
		0x0EA6D9FEA2FF6F68ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1F5E89112FBF1270ULL,
		0x95F446D5A23DB545ULL,
		0x7E2588EAF5E55071ULL,
		0xD5416CF15B8AD6C5ULL,
		0xCB7F09FB882A70EAULL,
		0xE9AC4C6B774B92F4ULL,
		0xEF4F5C3553243874ULL,
		0x1D4DB3FD45FEDED1ULL
	}};
	printf("Test Case 118\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 118 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -118;
	} else {
		printf("Test Case 118 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5B825F5EA4959692ULL,
		0x8D93AFC51897596EULL,
		0x87D44B5C79AB426EULL,
		0x4F467EDF7F417635ULL,
		0x08CF5C3076FEF904ULL,
		0x5D1213C51FAA153DULL,
		0x221332D308715AE5ULL,
		0x1DC62E7F01634343ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB704BEBD492B2D24ULL,
		0x1B275F8A312EB2DCULL,
		0x0FA896B8F35684DDULL,
		0x9E8CFDBEFE82EC6BULL,
		0x119EB860EDFDF208ULL,
		0xBA24278A3F542A7AULL,
		0x442665A610E2B5CAULL,
		0x3B8C5CFE02C68686ULL
	}};
	printf("Test Case 119\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 119 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -119;
	} else {
		printf("Test Case 119 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x067782629ABB6C5AULL,
		0xAA5642881A975EE0ULL,
		0x270EBCEE693E57D5ULL,
		0x201CA0F5BDA54BE0ULL,
		0xD6CF51D6FA3629A6ULL,
		0xD0282E9CF3B442C2ULL,
		0xD1A414754F0D04DAULL,
		0x35268F6BD66C560CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0CEF04C53576D8B4ULL,
		0x54AC8510352EBDC0ULL,
		0x4E1D79DCD27CAFABULL,
		0x403941EB7B4A97C0ULL,
		0xAD9EA3ADF46C534CULL,
		0xA0505D39E7688585ULL,
		0xA34828EA9E1A09B5ULL,
		0x6A4D1ED7ACD8AC19ULL
	}};
	printf("Test Case 120\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 120 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -120;
	} else {
		printf("Test Case 120 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF58610ADB11D283FULL,
		0x8D204CD9C70DC78DULL,
		0x7CCD178ECA3E6D7FULL,
		0xB32F3C77462FB404ULL,
		0x69B7B15D096AFFA6ULL,
		0x980525F6ACDD230EULL,
		0x1A779485B66AAC90ULL,
		0x3C306B93EFC470C6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEB0C215B623A507EULL,
		0x1A4099B38E1B8F1BULL,
		0xF99A2F1D947CDAFFULL,
		0x665E78EE8C5F6808ULL,
		0xD36F62BA12D5FF4DULL,
		0x300A4BED59BA461CULL,
		0x34EF290B6CD55921ULL,
		0x7860D727DF88E18CULL
	}};
	printf("Test Case 121\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 121 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -121;
	} else {
		printf("Test Case 121 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA250DC3544A348E1ULL,
		0xB8B8B763F94355B0ULL,
		0x4DCC1D77194A9200ULL,
		0x3F00DAD91B9B406EULL,
		0xFAC2A2F437137B70ULL,
		0x12DBC03321F54F5EULL,
		0xD3C86E90ECA57DAEULL,
		0x3419E8D482D449F2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x44A1B86A894691C2ULL,
		0x71716EC7F286AB61ULL,
		0x9B983AEE32952401ULL,
		0x7E01B5B2373680DCULL,
		0xF58545E86E26F6E0ULL,
		0x25B7806643EA9EBDULL,
		0xA790DD21D94AFB5CULL,
		0x6833D1A905A893E5ULL
	}};
	printf("Test Case 122\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 122 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -122;
	} else {
		printf("Test Case 122 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x509D36ECC1B51448ULL,
		0x2B614B642B7BC41EULL,
		0x72C28D7723AC98B3ULL,
		0x295E8264CDE1D8F3ULL,
		0xD7FF7499E0A3E411ULL,
		0x65585B17F2CCB41FULL,
		0xFA4C3A6256CEFAF9ULL,
		0x11E071DC68E8201CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA13A6DD9836A2890ULL,
		0x56C296C856F7883CULL,
		0xE5851AEE47593166ULL,
		0x52BD04C99BC3B1E6ULL,
		0xAFFEE933C147C822ULL,
		0xCAB0B62FE599683FULL,
		0xF49874C4AD9DF5F2ULL,
		0x23C0E3B8D1D04039ULL
	}};
	printf("Test Case 123\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 123 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -123;
	} else {
		printf("Test Case 123 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x58BC346FEDAFD8EBULL,
		0xECDB37F003FA5557ULL,
		0x560B6AFD6C9D9001ULL,
		0xA73911E970443629ULL,
		0x66C18921FA460795ULL,
		0xC14384786B3F5167ULL,
		0x5EBDC21EDC458515ULL,
		0x0DAF6C27C1D45894ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB17868DFDB5FB1D6ULL,
		0xD9B66FE007F4AAAEULL,
		0xAC16D5FAD93B2003ULL,
		0x4E7223D2E0886C52ULL,
		0xCD831243F48C0F2BULL,
		0x828708F0D67EA2CEULL,
		0xBD7B843DB88B0A2BULL,
		0x1B5ED84F83A8B128ULL
	}};
	printf("Test Case 124\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 124 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -124;
	} else {
		printf("Test Case 124 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3EC62FC8EA94A013ULL,
		0x18CEC89812CE625AULL,
		0xE6534E4FA4F7C685ULL,
		0xDCA1072D8D9214F5ULL,
		0x33CA3F06B8830B40ULL,
		0x6A9F73F70C7F6800ULL,
		0x71CFEACBF6383CC4ULL,
		0x0D730BDA3A3DD0EEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7D8C5F91D5294026ULL,
		0x319D9130259CC4B4ULL,
		0xCCA69C9F49EF8D0AULL,
		0xB9420E5B1B2429EBULL,
		0x67947E0D71061681ULL,
		0xD53EE7EE18FED000ULL,
		0xE39FD597EC707988ULL,
		0x1AE617B4747BA1DCULL
	}};
	printf("Test Case 125\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 125 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -125;
	} else {
		printf("Test Case 125 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8C057739F6597E28ULL,
		0x1921B5B9BD22A984ULL,
		0xB7A2C6023E51F689ULL,
		0xF8AD2A082D177316ULL,
		0x91EBAF8EC076A718ULL,
		0x0AAC6D80B0C02760ULL,
		0x0664AACE8FA19D72ULL,
		0x1D6993228E0C92E9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x180AEE73ECB2FC50ULL,
		0x32436B737A455309ULL,
		0x6F458C047CA3ED12ULL,
		0xF15A54105A2EE62DULL,
		0x23D75F1D80ED4E31ULL,
		0x1558DB0161804EC1ULL,
		0x0CC9559D1F433AE4ULL,
		0x3AD326451C1925D2ULL
	}};
	printf("Test Case 126\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 126 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -126;
	} else {
		printf("Test Case 126 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF59833395E93495CULL,
		0xAABDC9C4E7212CE7ULL,
		0x69D0AEF784CED25EULL,
		0xDFEB8C65A022554BULL,
		0xD8BEC1EA1C589E83ULL,
		0xFEC20E035408A367ULL,
		0x208E2CACCCD54893ULL,
		0x2BDD85418734B80AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEB306672BD2692B8ULL,
		0x557B9389CE4259CFULL,
		0xD3A15DEF099DA4BDULL,
		0xBFD718CB4044AA96ULL,
		0xB17D83D438B13D07ULL,
		0xFD841C06A81146CFULL,
		0x411C595999AA9127ULL,
		0x57BB0A830E697014ULL
	}};
	printf("Test Case 127\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 127 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -127;
	} else {
		printf("Test Case 127 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x34551270F48475B4ULL,
		0x6434E378A68DFE34ULL,
		0x769B1A2CD0E33BCBULL,
		0xF14A59843A0DC93EULL,
		0x58E04C0A03971F1BULL,
		0xF407112091232770ULL,
		0xD5CA11B6A839DB79ULL,
		0x08C74616276B8E1AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x68AA24E1E908EB68ULL,
		0xC869C6F14D1BFC68ULL,
		0xED363459A1C67796ULL,
		0xE294B308741B927CULL,
		0xB1C09814072E3E37ULL,
		0xE80E224122464EE0ULL,
		0xAB94236D5073B6F3ULL,
		0x118E8C2C4ED71C35ULL
	}};
	printf("Test Case 128\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 128 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -128;
	} else {
		printf("Test Case 128 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x90F53BC06C6398AAULL,
		0xF5AC5E6F1D33C17DULL,
		0x17F64040F28353D7ULL,
		0x37D7574242DD68FDULL,
		0x306C9306C54991AFULL,
		0xAC8A4B14DFD12822ULL,
		0x5D321E02340AA989ULL,
		0x111AD16BD74EDF0DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x21EA7780D8C73154ULL,
		0xEB58BCDE3A6782FBULL,
		0x2FEC8081E506A7AFULL,
		0x6FAEAE8485BAD1FAULL,
		0x60D9260D8A93235EULL,
		0x59149629BFA25044ULL,
		0xBA643C0468155313ULL,
		0x2235A2D7AE9DBE1AULL
	}};
	printf("Test Case 129\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 129 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -129;
	} else {
		printf("Test Case 129 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x48C353C9BC23254DULL,
		0xCF5EC9501DD20367ULL,
		0x14E737C855898EB5ULL,
		0xE4BDDF801BDFF3D4ULL,
		0x24135ABCBAAFE9A7ULL,
		0x669D1F1B2E30C8C4ULL,
		0x98E300A753C81F2AULL,
		0x0BDD299A7FAFC1F6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9186A79378464A9AULL,
		0x9EBD92A03BA406CEULL,
		0x29CE6F90AB131D6BULL,
		0xC97BBF0037BFE7A8ULL,
		0x4826B579755FD34FULL,
		0xCD3A3E365C619188ULL,
		0x31C6014EA7903E54ULL,
		0x17BA5334FF5F83EDULL
	}};
	printf("Test Case 130\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 130 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -130;
	} else {
		printf("Test Case 130 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x842D5D13BB6EB429ULL,
		0x08D61FB380392147ULL,
		0xE8EE45F623646CAAULL,
		0x65E38051151EEEE6ULL,
		0xA7B78BCC63EC6546ULL,
		0x6598D47BC425ACFEULL,
		0x438B043C862AE059ULL,
		0x3E87BB5812F2B957ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x085ABA2776DD6852ULL,
		0x11AC3F670072428FULL,
		0xD1DC8BEC46C8D954ULL,
		0xCBC700A22A3DDDCDULL,
		0x4F6F1798C7D8CA8CULL,
		0xCB31A8F7884B59FDULL,
		0x871608790C55C0B2ULL,
		0x7D0F76B025E572AEULL
	}};
	printf("Test Case 131\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 131 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -131;
	} else {
		printf("Test Case 131 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x57CDD485A6640369ULL,
		0x935B24AA6B8353BDULL,
		0x067FF6C9A6B89A51ULL,
		0xAF241689CB205A94ULL,
		0x09CC3251394806A6ULL,
		0xF7D5ACAA6E27F622ULL,
		0x6208C76062B00DCBULL,
		0x3838DC81A26B2589ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF9BA90B4CC806D2ULL,
		0x26B64954D706A77AULL,
		0x0CFFED934D7134A3ULL,
		0x5E482D139640B528ULL,
		0x139864A272900D4DULL,
		0xEFAB5954DC4FEC44ULL,
		0xC4118EC0C5601B97ULL,
		0x7071B90344D64B12ULL
	}};
	printf("Test Case 132\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 132 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -132;
	} else {
		printf("Test Case 132 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5592E20B9B5CA8E4ULL,
		0x0B4228B9BE237984ULL,
		0xD31F214056638AD1ULL,
		0x45DB79ECC633774BULL,
		0x6DD77CB2F157C4B0ULL,
		0x4030921D7A7D23AFULL,
		0x86BF3A1B083E8CF2ULL,
		0x1D9944EA4ED9164FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAB25C41736B951C8ULL,
		0x168451737C46F308ULL,
		0xA63E4280ACC715A2ULL,
		0x8BB6F3D98C66EE97ULL,
		0xDBAEF965E2AF8960ULL,
		0x8061243AF4FA475EULL,
		0x0D7E7436107D19E4ULL,
		0x3B3289D49DB22C9FULL
	}};
	printf("Test Case 133\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 133 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -133;
	} else {
		printf("Test Case 133 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x46B10B7846E48EBCULL,
		0x140A42E99FEBE3CBULL,
		0x2C580EE46C4D9B2FULL,
		0x49568F3C825B56FEULL,
		0x20EF8F9FCC882546ULL,
		0xCA9B9A8EF2CD85CAULL,
		0xBAE48EB81513D4B2ULL,
		0x073F16ABD1F195FAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8D6216F08DC91D78ULL,
		0x281485D33FD7C796ULL,
		0x58B01DC8D89B365EULL,
		0x92AD1E7904B6ADFCULL,
		0x41DF1F3F99104A8CULL,
		0x9537351DE59B0B94ULL,
		0x75C91D702A27A965ULL,
		0x0E7E2D57A3E32BF5ULL
	}};
	printf("Test Case 134\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 134 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -134;
	} else {
		printf("Test Case 134 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9DD4ABA3648198FAULL,
		0xC212C54B9712CCE4ULL,
		0xA3B1A5645BFF2E63ULL,
		0xEF4CE4CF77004EA7ULL,
		0x15131938294342C7ULL,
		0x8CA0BC928B99B57AULL,
		0x84D5F4D3A1AF048FULL,
		0x0CCBFAB9CCEAE108ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3BA95746C90331F4ULL,
		0x84258A972E2599C9ULL,
		0x47634AC8B7FE5CC7ULL,
		0xDE99C99EEE009D4FULL,
		0x2A2632705286858FULL,
		0x1941792517336AF4ULL,
		0x09ABE9A7435E091FULL,
		0x1997F57399D5C211ULL
	}};
	printf("Test Case 135\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 135 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -135;
	} else {
		printf("Test Case 135 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8B49C20F3E6D1E8EULL,
		0x30D31A5E154E55EBULL,
		0x46F198032D6E1D32ULL,
		0x703C112944E90FB8ULL,
		0xE28ABE4C8B475320ULL,
		0x1A678D5425976D07ULL,
		0xF85AA608654B34BFULL,
		0x2C348C2BF31A846EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1693841E7CDA3D1CULL,
		0x61A634BC2A9CABD7ULL,
		0x8DE330065ADC3A64ULL,
		0xE078225289D21F70ULL,
		0xC5157C99168EA640ULL,
		0x34CF1AA84B2EDA0FULL,
		0xF0B54C10CA96697EULL,
		0x58691857E63508DDULL
	}};
	printf("Test Case 136\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 136 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -136;
	} else {
		printf("Test Case 136 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBD727E8891224548ULL,
		0xA69C4F59347C2ACEULL,
		0xB1ADEA46263A1D8DULL,
		0x1C67CFB7A1F39296ULL,
		0xECDE2E2430335FE8ULL,
		0x9D2C714510550023ULL,
		0xADA05BD0D5299A53ULL,
		0x39D5F2888780132BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7AE4FD1122448A90ULL,
		0x4D389EB268F8559DULL,
		0x635BD48C4C743B1BULL,
		0x38CF9F6F43E7252DULL,
		0xD9BC5C486066BFD0ULL,
		0x3A58E28A20AA0047ULL,
		0x5B40B7A1AA5334A7ULL,
		0x73ABE5110F002657ULL
	}};
	printf("Test Case 137\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 137 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -137;
	} else {
		printf("Test Case 137 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x957402212FEBD56BULL,
		0xA7CCAA13F9C56EB6ULL,
		0xDC0F67B7AEE5E1B1ULL,
		0xE3D0D594961581E8ULL,
		0xDAEDBBA212494F41ULL,
		0xFA7FF6729037F7CDULL,
		0x6136D4967C7347E8ULL,
		0x39240C0AF9E24349ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2AE804425FD7AAD6ULL,
		0x4F995427F38ADD6DULL,
		0xB81ECF6F5DCBC363ULL,
		0xC7A1AB292C2B03D1ULL,
		0xB5DB774424929E83ULL,
		0xF4FFECE5206FEF9BULL,
		0xC26DA92CF8E68FD1ULL,
		0x72481815F3C48692ULL
	}};
	printf("Test Case 138\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 138 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -138;
	} else {
		printf("Test Case 138 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0A70CD94825AA177ULL,
		0xCD2440B58BC57E73ULL,
		0x1202DC135180BEEAULL,
		0x389F6C3E2B595163ULL,
		0xB99F6446660D7D59ULL,
		0xB89875064DE7A589ULL,
		0x22473155B37B8AD8ULL,
		0x1AC99A94207680E4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x14E19B2904B542EEULL,
		0x9A48816B178AFCE6ULL,
		0x2405B826A3017DD5ULL,
		0x713ED87C56B2A2C6ULL,
		0x733EC88CCC1AFAB2ULL,
		0x7130EA0C9BCF4B13ULL,
		0x448E62AB66F715B1ULL,
		0x3593352840ED01C8ULL
	}};
	printf("Test Case 139\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 139 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -139;
	} else {
		printf("Test Case 139 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3483C2FBFF87855EULL,
		0x5C76640589A408FEULL,
		0xECCDB8412649CBEDULL,
		0x336749BA1E767701ULL,
		0xB4271ABA1CFE73ADULL,
		0xC2408C8E2776BFECULL,
		0x90634E01F6823794ULL,
		0x3350AFE61B18D6D6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x690785F7FF0F0ABCULL,
		0xB8ECC80B134811FCULL,
		0xD99B70824C9397DAULL,
		0x66CE93743CECEE03ULL,
		0x684E357439FCE75AULL,
		0x8481191C4EED7FD9ULL,
		0x20C69C03ED046F29ULL,
		0x66A15FCC3631ADADULL
	}};
	printf("Test Case 140\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 140 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -140;
	} else {
		printf("Test Case 140 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1E3B4FCD3E74819EULL,
		0xC048CDC5B91A172EULL,
		0xE9306EAC1F2D8689ULL,
		0x2F602BF5F64868A9ULL,
		0xDCD17EEF54456759ULL,
		0x4BB8482AB0FA8EF3ULL,
		0xD7D22918546C8801ULL,
		0x173F799C95E233E4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3C769F9A7CE9033CULL,
		0x80919B8B72342E5CULL,
		0xD260DD583E5B0D13ULL,
		0x5EC057EBEC90D153ULL,
		0xB9A2FDDEA88ACEB2ULL,
		0x9770905561F51DE7ULL,
		0xAFA45230A8D91002ULL,
		0x2E7EF3392BC467C9ULL
	}};
	printf("Test Case 141\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 141 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -141;
	} else {
		printf("Test Case 141 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x87B816A7AA8B37EDULL,
		0xAFAA4C143E02C11EULL,
		0x1A7F59858ADB1BF1ULL,
		0x97E21912F15611DBULL,
		0xB6210E02D7E2D95BULL,
		0x91910A5697AD4827ULL,
		0xFCB838AB41A60E15ULL,
		0x3F868354AB6F4D8CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F702D4F55166FDAULL,
		0x5F5498287C05823DULL,
		0x34FEB30B15B637E3ULL,
		0x2FC43225E2AC23B6ULL,
		0x6C421C05AFC5B2B7ULL,
		0x232214AD2F5A904FULL,
		0xF9707156834C1C2BULL,
		0x7F0D06A956DE9B19ULL
	}};
	printf("Test Case 142\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 142 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -142;
	} else {
		printf("Test Case 142 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7366DD33837C0318ULL,
		0xFFD0D495A7A677EFULL,
		0x980F053ACF1C03EFULL,
		0x0ABBED1AB772816FULL,
		0xE4CBD543A19A3DBBULL,
		0x900871A5192E74C6ULL,
		0x2E652D5157501090ULL,
		0x18E117DE4DD7BC02ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE6CDBA6706F80630ULL,
		0xFFA1A92B4F4CEFDEULL,
		0x301E0A759E3807DFULL,
		0x1577DA356EE502DFULL,
		0xC997AA8743347B76ULL,
		0x2010E34A325CE98DULL,
		0x5CCA5AA2AEA02121ULL,
		0x31C22FBC9BAF7804ULL
	}};
	printf("Test Case 143\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 143 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -143;
	} else {
		printf("Test Case 143 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x836A91604BBB1706ULL,
		0x9E7660CAD51BB576ULL,
		0xA0450EC1036DC4B4ULL,
		0x4791A5CEBEC30D2CULL,
		0xD197E1DB3BFA8BC4ULL,
		0x771881D1F5226A0CULL,
		0xD86F83741576C355ULL,
		0x0E8AC1404BAFF932ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x06D522C097762E0CULL,
		0x3CECC195AA376AEDULL,
		0x408A1D8206DB8969ULL,
		0x8F234B9D7D861A59ULL,
		0xA32FC3B677F51788ULL,
		0xEE3103A3EA44D419ULL,
		0xB0DF06E82AED86AAULL,
		0x1D158280975FF265ULL
	}};
	printf("Test Case 144\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 144 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -144;
	} else {
		printf("Test Case 144 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9B274475D7885527ULL,
		0x47321CD760EB722BULL,
		0x3A56ABE97ECDE796ULL,
		0xEBA9805E7AB9332DULL,
		0x37965037E7976084ULL,
		0xB4E44E55CC0A9AC2ULL,
		0x133150D18F704C84ULL,
		0x05FC8BBB4B8BED4AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x364E88EBAF10AA4EULL,
		0x8E6439AEC1D6E457ULL,
		0x74AD57D2FD9BCF2CULL,
		0xD75300BCF572665AULL,
		0x6F2CA06FCF2EC109ULL,
		0x69C89CAB98153584ULL,
		0x2662A1A31EE09909ULL,
		0x0BF917769717DA94ULL
	}};
	printf("Test Case 145\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 145 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -145;
	} else {
		printf("Test Case 145 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x01318F53337149A9ULL,
		0x53039C0136C38944ULL,
		0x52BF415CF805EC6EULL,
		0x4724D31DD1408D47ULL,
		0xB21FAD807309E1BCULL,
		0x347526E3223EF535ULL,
		0xFB8FBCA6BCA5B425ULL,
		0x131B5DBF156D6371ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x02631EA666E29352ULL,
		0xA60738026D871288ULL,
		0xA57E82B9F00BD8DCULL,
		0x8E49A63BA2811A8EULL,
		0x643F5B00E613C378ULL,
		0x68EA4DC6447DEA6BULL,
		0xF71F794D794B684AULL,
		0x2636BB7E2ADAC6E3ULL
	}};
	printf("Test Case 146\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 146 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -146;
	} else {
		printf("Test Case 146 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x98AB7CB6F68C4759ULL,
		0x19A328A6755C361DULL,
		0x6E18F57E17D287ADULL,
		0x58DDDF1747767BC9ULL,
		0xD35683C067E41153ULL,
		0x4B0357048EA3E1CDULL,
		0x025F8232CB102E75ULL,
		0x10A5A9D39E2090C8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3156F96DED188EB2ULL,
		0x3346514CEAB86C3BULL,
		0xDC31EAFC2FA50F5AULL,
		0xB1BBBE2E8EECF792ULL,
		0xA6AD0780CFC822A6ULL,
		0x9606AE091D47C39BULL,
		0x04BF046596205CEAULL,
		0x214B53A73C412190ULL
	}};
	printf("Test Case 147\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 147 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -147;
	} else {
		printf("Test Case 147 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x103C9E8135A7918AULL,
		0x02755426A5A390BDULL,
		0xCBC2464F91BB8873ULL,
		0x77AD98DCDA249E95ULL,
		0xD90C2756003908EDULL,
		0x36B7CEEB7992B81AULL,
		0x85300B7EA7AF5B28ULL,
		0x39D4D6542898D879ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x20793D026B4F2314ULL,
		0x04EAA84D4B47217AULL,
		0x97848C9F237710E6ULL,
		0xEF5B31B9B4493D2BULL,
		0xB2184EAC007211DAULL,
		0x6D6F9DD6F3257035ULL,
		0x0A6016FD4F5EB650ULL,
		0x73A9ACA85131B0F3ULL
	}};
	printf("Test Case 148\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 148 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -148;
	} else {
		printf("Test Case 148 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x62AA6E665CDA20FEULL,
		0x25A619ACAD34BDC8ULL,
		0xB708F7D34C92A0A4ULL,
		0xF638B32A11FD82A6ULL,
		0x91BAEFDA07E6199EULL,
		0x8D2D55775221B902ULL,
		0x19B6AA0931C2B6D0ULL,
		0x1593B2F1F39FD799ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC554DCCCB9B441FCULL,
		0x4B4C33595A697B90ULL,
		0x6E11EFA699254148ULL,
		0xEC71665423FB054DULL,
		0x2375DFB40FCC333DULL,
		0x1A5AAAEEA4437205ULL,
		0x336D541263856DA1ULL,
		0x2B2765E3E73FAF32ULL
	}};
	printf("Test Case 149\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 149 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -149;
	} else {
		printf("Test Case 149 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC9B61C12864895D5ULL,
		0x3B28E4F7955DC6BEULL,
		0xC96A5A0C2A152FF5ULL,
		0x285EC8A698DBEBA7ULL,
		0xEA7D8DA0818F1A82ULL,
		0x8E3E4B80497491A9ULL,
		0x3D31015EA0874322ULL,
		0x0A556602B48BEF98ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x936C38250C912BAAULL,
		0x7651C9EF2ABB8D7DULL,
		0x92D4B418542A5FEAULL,
		0x50BD914D31B7D74FULL,
		0xD4FB1B41031E3504ULL,
		0x1C7C970092E92353ULL,
		0x7A6202BD410E8645ULL,
		0x14AACC056917DF30ULL
	}};
	printf("Test Case 150\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 150 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -150;
	} else {
		printf("Test Case 150 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1DDE5FDA7670D4B4ULL,
		0x9F6C688F9A43751DULL,
		0xDCA322BA478FEFBEULL,
		0x7839DAD5F136CA22ULL,
		0x4CC276756D6C8B8CULL,
		0x8FF635221C0EBC33ULL,
		0xEDE0DB43AE8DACF2ULL,
		0x38654CD5EEC999EAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3BBCBFB4ECE1A968ULL,
		0x3ED8D11F3486EA3AULL,
		0xB94645748F1FDF7DULL,
		0xF073B5ABE26D9445ULL,
		0x9984ECEADAD91718ULL,
		0x1FEC6A44381D7866ULL,
		0xDBC1B6875D1B59E5ULL,
		0x70CA99ABDD9333D5ULL
	}};
	printf("Test Case 151\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 151 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -151;
	} else {
		printf("Test Case 151 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE24E31F0F1BC7BCFULL,
		0x183798D79AE0D5BFULL,
		0xCC5AB341AC5315BEULL,
		0x1CD6248A5FD9A563ULL,
		0x9C0AD9DEC9D994F1ULL,
		0x3F01B2FE61626464ULL,
		0x82D71418D56007FEULL,
		0x3E1B3837A8DC9821ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC49C63E1E378F79EULL,
		0x306F31AF35C1AB7FULL,
		0x98B5668358A62B7CULL,
		0x39AC4914BFB34AC7ULL,
		0x3815B3BD93B329E2ULL,
		0x7E0365FCC2C4C8C9ULL,
		0x05AE2831AAC00FFCULL,
		0x7C36706F51B93043ULL
	}};
	printf("Test Case 152\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 152 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -152;
	} else {
		printf("Test Case 152 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3A177292E3751995ULL,
		0x2CF8B7BE64D2495EULL,
		0xFB28373CC79B1D40ULL,
		0x90DFE3DDD6E2086DULL,
		0x4133EAF149B8C0E7ULL,
		0x223390CD8C789F98ULL,
		0xF41D45EBC254A4D2ULL,
		0x1FF936A34C248D4DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x742EE525C6EA332AULL,
		0x59F16F7CC9A492BCULL,
		0xF6506E798F363A80ULL,
		0x21BFC7BBADC410DBULL,
		0x8267D5E2937181CFULL,
		0x4467219B18F13F30ULL,
		0xE83A8BD784A949A4ULL,
		0x3FF26D4698491A9BULL
	}};
	printf("Test Case 153\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 153 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -153;
	} else {
		printf("Test Case 153 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7D60C716194BA896ULL,
		0xEF163F6249D9B2AAULL,
		0x22F635B665F959ABULL,
		0x497FBB6C8E1E71F5ULL,
		0x2C67DCA63BC301C9ULL,
		0xF380B7C6139B2D8BULL,
		0xA8F5944D73F2DADFULL,
		0x291032F77CE9C138ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFAC18E2C3297512CULL,
		0xDE2C7EC493B36554ULL,
		0x45EC6B6CCBF2B357ULL,
		0x92FF76D91C3CE3EAULL,
		0x58CFB94C77860392ULL,
		0xE7016F8C27365B16ULL,
		0x51EB289AE7E5B5BFULL,
		0x522065EEF9D38271ULL
	}};
	printf("Test Case 154\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 154 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -154;
	} else {
		printf("Test Case 154 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4546B7C333167451ULL,
		0xBD02C6E473D16CFCULL,
		0xEC67CBAAEA1D4F70ULL,
		0xA333196FF4C576ADULL,
		0xF17ED78982AD7679ULL,
		0x44DC3AB3C7465DC6ULL,
		0xD73E83C7823F6424ULL,
		0x334C3C0619F3FD16ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8A8D6F86662CE8A2ULL,
		0x7A058DC8E7A2D9F8ULL,
		0xD8CF9755D43A9EE1ULL,
		0x466632DFE98AED5BULL,
		0xE2FDAF13055AECF3ULL,
		0x89B875678E8CBB8DULL,
		0xAE7D078F047EC848ULL,
		0x6698780C33E7FA2DULL
	}};
	printf("Test Case 155\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 155 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -155;
	} else {
		printf("Test Case 155 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x689BCC77C47554F1ULL,
		0x96CE730CCAFCD16FULL,
		0x999D5A5BA80E7346ULL,
		0x531F93501363EC35ULL,
		0x7CDE6B0F423A0898ULL,
		0xA8293F43D3AB4E2BULL,
		0x0F950E5876102CBBULL,
		0x1260B2EE84B5C3F7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD13798EF88EAA9E2ULL,
		0x2D9CE61995F9A2DEULL,
		0x333AB4B7501CE68DULL,
		0xA63F26A026C7D86BULL,
		0xF9BCD61E84741130ULL,
		0x50527E87A7569C56ULL,
		0x1F2A1CB0EC205977ULL,
		0x24C165DD096B87EEULL
	}};
	printf("Test Case 156\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 156 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -156;
	} else {
		printf("Test Case 156 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB9ECF257B03035B1ULL,
		0xF49C64A231D2434AULL,
		0xF608E74DFBEE13C0ULL,
		0x7F8722389D96AE6CULL,
		0x85F43AC7DC0EBE73ULL,
		0x309617578A5A90A2ULL,
		0xCF336223E0DC417FULL,
		0x20729899C34D5193ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x73D9E4AF60606B62ULL,
		0xE938C94463A48695ULL,
		0xEC11CE9BF7DC2781ULL,
		0xFF0E44713B2D5CD9ULL,
		0x0BE8758FB81D7CE6ULL,
		0x612C2EAF14B52145ULL,
		0x9E66C447C1B882FEULL,
		0x40E53133869AA327ULL
	}};
	printf("Test Case 157\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 157 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -157;
	} else {
		printf("Test Case 157 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7A5E6E85A34B4745ULL,
		0x586A69B988507ED7ULL,
		0xDD805AE21BB28A42ULL,
		0x185969ADD00E0453ULL,
		0x6FFB25C95A776AC5ULL,
		0x65FC2C7979B8A844ULL,
		0x1657979C45496C07ULL,
		0x25E31EE447B0D3E7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF4BCDD0B46968E8AULL,
		0xB0D4D37310A0FDAEULL,
		0xBB00B5C437651484ULL,
		0x30B2D35BA01C08A7ULL,
		0xDFF64B92B4EED58AULL,
		0xCBF858F2F3715088ULL,
		0x2CAF2F388A92D80EULL,
		0x4BC63DC88F61A7CEULL
	}};
	printf("Test Case 158\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 158 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -158;
	} else {
		printf("Test Case 158 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x986F50A08D0EDF5AULL,
		0x86F903361A18C90BULL,
		0xF601E5955C869302ULL,
		0x1D99495F056A64B8ULL,
		0xDE280CDE10B02A22ULL,
		0x1C9264C054C2874FULL,
		0x60D610B7D5497D8EULL,
		0x177CB9864813552CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x30DEA1411A1DBEB4ULL,
		0x0DF2066C34319217ULL,
		0xEC03CB2AB90D2605ULL,
		0x3B3292BE0AD4C971ULL,
		0xBC5019BC21605444ULL,
		0x3924C980A9850E9FULL,
		0xC1AC216FAA92FB1CULL,
		0x2EF9730C9026AA58ULL
	}};
	printf("Test Case 159\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 159 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -159;
	} else {
		printf("Test Case 159 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBC7C3A10DC4104EBULL,
		0xFAC8283F04CB8CE2ULL,
		0x6B150D36BC78291FULL,
		0xF6A8397220B6F0FBULL,
		0x6EAFDFA930551537ULL,
		0xA54B0160B643337FULL,
		0x8B044269151F9C05ULL,
		0x22B46415D360EBD9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x78F87421B88209D6ULL,
		0xF590507E099719C5ULL,
		0xD62A1A6D78F0523FULL,
		0xED5072E4416DE1F6ULL,
		0xDD5FBF5260AA2A6FULL,
		0x4A9602C16C8666FEULL,
		0x160884D22A3F380BULL,
		0x4568C82BA6C1D7B3ULL
	}};
	printf("Test Case 160\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 160 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -160;
	} else {
		printf("Test Case 160 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x60F166AF0C202614ULL,
		0x1E5AF68CBC0A7700ULL,
		0x01AE7D2CA846768FULL,
		0xFC61FE52CD98C62DULL,
		0xF0CC9D7608DAB3ECULL,
		0x54CFBF1ABDB6D006ULL,
		0x151D570871E89EDEULL,
		0x1691190EE70732E8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC1E2CD5E18404C28ULL,
		0x3CB5ED197814EE00ULL,
		0x035CFA59508CED1EULL,
		0xF8C3FCA59B318C5AULL,
		0xE1993AEC11B567D9ULL,
		0xA99F7E357B6DA00DULL,
		0x2A3AAE10E3D13DBCULL,
		0x2D22321DCE0E65D0ULL
	}};
	printf("Test Case 161\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 161 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -161;
	} else {
		printf("Test Case 161 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAE889ECB78791D1EULL,
		0xEE55FB5A260B73B5ULL,
		0xFB093212390358A4ULL,
		0xF34452907EBBF685ULL,
		0x5CCE0730B37B741BULL,
		0x88A40DEF4F018797ULL,
		0x96A597441191DE00ULL,
		0x3119C1D4AFECF2BCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5D113D96F0F23A3CULL,
		0xDCABF6B44C16E76BULL,
		0xF61264247206B149ULL,
		0xE688A520FD77ED0BULL,
		0xB99C0E6166F6E837ULL,
		0x11481BDE9E030F2EULL,
		0x2D4B2E882323BC01ULL,
		0x623383A95FD9E579ULL
	}};
	printf("Test Case 162\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 162 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -162;
	} else {
		printf("Test Case 162 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x244A6C90EA66118BULL,
		0x74687388E45A3B38ULL,
		0x8C10AC9D7968AAE9ULL,
		0xCF32DDCE3D69AA4CULL,
		0x05C84A7FFAFBFDEEULL,
		0x0C7A163275A69490ULL,
		0x20F98984DFF85AD2ULL,
		0x14B7F3B30082314CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4894D921D4CC2316ULL,
		0xE8D0E711C8B47670ULL,
		0x1821593AF2D155D2ULL,
		0x9E65BB9C7AD35499ULL,
		0x0B9094FFF5F7FBDDULL,
		0x18F42C64EB4D2920ULL,
		0x41F31309BFF0B5A4ULL,
		0x296FE76601046298ULL
	}};
	printf("Test Case 163\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 163 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -163;
	} else {
		printf("Test Case 163 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD4DF20345249948AULL,
		0x172AFF184FFBA23DULL,
		0xAB3896AFF5F42966ULL,
		0x10DCEBF725FE8F49ULL,
		0x09BCCAF8303A00A2ULL,
		0x15DB6FB29318D396ULL,
		0x0A485616CA1E52E4ULL,
		0x3B33A71B7203B44BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA9BE4068A4932914ULL,
		0x2E55FE309FF7447BULL,
		0x56712D5FEBE852CCULL,
		0x21B9D7EE4BFD1E93ULL,
		0x137995F060740144ULL,
		0x2BB6DF652631A72CULL,
		0x1490AC2D943CA5C8ULL,
		0x76674E36E4076896ULL
	}};
	printf("Test Case 164\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 164 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -164;
	} else {
		printf("Test Case 164 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC91457D0ED279347ULL,
		0xBBE8AB5513C91315ULL,
		0x580ECD6720C55DE9ULL,
		0xD405E19EDEF50F71ULL,
		0xD250935345566974ULL,
		0x76EA76A0442D8A85ULL,
		0xB968955F8318B0A1ULL,
		0x12DA81BDA21ABBE0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9228AFA1DA4F268EULL,
		0x77D156AA2792262BULL,
		0xB01D9ACE418ABBD3ULL,
		0xA80BC33DBDEA1EE2ULL,
		0xA4A126A68AACD2E9ULL,
		0xEDD4ED40885B150BULL,
		0x72D12ABF06316142ULL,
		0x25B5037B443577C1ULL
	}};
	printf("Test Case 165\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 165 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -165;
	} else {
		printf("Test Case 165 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC69FA5E19B73F408ULL,
		0x917A6308FA3C6983ULL,
		0xFD33822AA671AF37ULL,
		0x0570367CDD0D3196ULL,
		0x8D7326F20594AB90ULL,
		0xED4F9CCEF3CC9E1CULL,
		0xA2249CDF16A4E8F2ULL,
		0x24E0B881ED5C8DC4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8D3F4BC336E7E810ULL,
		0x22F4C611F478D307ULL,
		0xFA6704554CE35E6FULL,
		0x0AE06CF9BA1A632DULL,
		0x1AE64DE40B295720ULL,
		0xDA9F399DE7993C39ULL,
		0x444939BE2D49D1E5ULL,
		0x49C17103DAB91B89ULL
	}};
	printf("Test Case 166\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 166 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -166;
	} else {
		printf("Test Case 166 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1CC71B2C1E71108AULL,
		0xA6E2D3C95C5989A8ULL,
		0xDFC1C90408354816ULL,
		0xBDAFF1B2E0B8C3C5ULL,
		0x7BF7EEB4900E0C6CULL,
		0x175E876CA44650ABULL,
		0x755D1231AD67F286ULL,
		0x142C4B4C9B57C612ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x398E36583CE22114ULL,
		0x4DC5A792B8B31350ULL,
		0xBF839208106A902DULL,
		0x7B5FE365C171878BULL,
		0xF7EFDD69201C18D9ULL,
		0x2EBD0ED9488CA156ULL,
		0xEABA24635ACFE50CULL,
		0x2858969936AF8C24ULL
	}};
	printf("Test Case 167\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 167 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -167;
	} else {
		printf("Test Case 167 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE88EBE76D7489F80ULL,
		0x51CD70CCFE2B8A7DULL,
		0xE9ED3602FCB95DB7ULL,
		0x3ACF5611620ABCBEULL,
		0xB21E51D7F760FF54ULL,
		0x7A0E433F01E794D1ULL,
		0x1764B91294AA72FBULL,
		0x191C1AD7BB97D790ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD11D7CEDAE913F00ULL,
		0xA39AE199FC5714FBULL,
		0xD3DA6C05F972BB6EULL,
		0x759EAC22C415797DULL,
		0x643CA3AFEEC1FEA8ULL,
		0xF41C867E03CF29A3ULL,
		0x2EC972252954E5F6ULL,
		0x323835AF772FAF20ULL
	}};
	printf("Test Case 168\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 168 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -168;
	} else {
		printf("Test Case 168 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x60D4E0FECBBFA56AULL,
		0x580A23F41F3C9982ULL,
		0xD1D6D62C7206EA62ULL,
		0x81F3F70D870D32F0ULL,
		0x1AED7C83A75DC9F1ULL,
		0xB9E0DC0FF8DF7483ULL,
		0xEB369C94CC7D9B0FULL,
		0x1B727EDA45A6D4FFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC1A9C1FD977F4AD4ULL,
		0xB01447E83E793304ULL,
		0xA3ADAC58E40DD4C4ULL,
		0x03E7EE1B0E1A65E1ULL,
		0x35DAF9074EBB93E3ULL,
		0x73C1B81FF1BEE906ULL,
		0xD66D392998FB361FULL,
		0x36E4FDB48B4DA9FFULL
	}};
	printf("Test Case 169\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 169 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -169;
	} else {
		printf("Test Case 169 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8C68FDDDF0A1E565ULL,
		0xD4835E35953F5C12ULL,
		0x96762E94A95F92A0ULL,
		0x60CF32E8EE1A1CA4ULL,
		0xF1A192F73F615FFDULL,
		0x69FB364115FC8126ULL,
		0x7A106270F8792080ULL,
		0x07E2F2BB7EBF3A54ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x18D1FBBBE143CACAULL,
		0xA906BC6B2A7EB825ULL,
		0x2CEC5D2952BF2541ULL,
		0xC19E65D1DC343949ULL,
		0xE34325EE7EC2BFFAULL,
		0xD3F66C822BF9024DULL,
		0xF420C4E1F0F24100ULL,
		0x0FC5E576FD7E74A8ULL
	}};
	printf("Test Case 170\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 170 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -170;
	} else {
		printf("Test Case 170 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0FFB30CAB19949A9ULL,
		0xD621280A653588E1ULL,
		0xFCC2846963B1BFA2ULL,
		0x96EAE4B27B9BDC8AULL,
		0xFFC0DDA517391AD9ULL,
		0xBB9801AC3C188FB0ULL,
		0xD42EB03FDBB23A27ULL,
		0x1164F5AFFAF778D8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1FF6619563329352ULL,
		0xAC425014CA6B11C2ULL,
		0xF98508D2C7637F45ULL,
		0x2DD5C964F737B915ULL,
		0xFF81BB4A2E7235B3ULL,
		0x7730035878311F61ULL,
		0xA85D607FB764744FULL,
		0x22C9EB5FF5EEF1B1ULL
	}};
	printf("Test Case 171\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 171 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -171;
	} else {
		printf("Test Case 171 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8BC5E9B7EA8CBC72ULL,
		0xCC5F362D2C66B132ULL,
		0xA3B8C68E6230A39DULL,
		0x3782647C1CFE3D18ULL,
		0xD13ED687A40573E9ULL,
		0x7F78ECF184E2FE82ULL,
		0x8F679E06D813E8E9ULL,
		0x0AA7E31E4E80AD3FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x178BD36FD51978E4ULL,
		0x98BE6C5A58CD6265ULL,
		0x47718D1CC461473BULL,
		0x6F04C8F839FC7A31ULL,
		0xA27DAD0F480AE7D2ULL,
		0xFEF1D9E309C5FD05ULL,
		0x1ECF3C0DB027D1D2ULL,
		0x154FC63C9D015A7FULL
	}};
	printf("Test Case 172\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 172 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -172;
	} else {
		printf("Test Case 172 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCAE93EE96830306FULL,
		0x939AC0A8B0790959ULL,
		0x223AB17E203700CFULL,
		0x70CB8A236177D968ULL,
		0x37A51DBE47EF633CULL,
		0xCE635DA48EE164DCULL,
		0xD06B17265E6A5C8EULL,
		0x19B08C12A0DA215AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x95D27DD2D06060DEULL,
		0x2735815160F212B3ULL,
		0x447562FC406E019FULL,
		0xE1971446C2EFB2D0ULL,
		0x6F4A3B7C8FDEC678ULL,
		0x9CC6BB491DC2C9B8ULL,
		0xA0D62E4CBCD4B91DULL,
		0x3361182541B442B5ULL
	}};
	printf("Test Case 173\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 173 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -173;
	} else {
		printf("Test Case 173 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC2B79E5CDAFC989FULL,
		0x809E7FDB1F22DD8BULL,
		0xBD9D278DD9BE85A4ULL,
		0xFB2E99412A513697ULL,
		0x2CF0886D518C45E7ULL,
		0xF0318A5C02A6272CULL,
		0xAA5584AA51844310ULL,
		0x0F4D1EF15EA23004ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x856F3CB9B5F9313EULL,
		0x013CFFB63E45BB17ULL,
		0x7B3A4F1BB37D0B49ULL,
		0xF65D328254A26D2FULL,
		0x59E110DAA3188BCFULL,
		0xE06314B8054C4E58ULL,
		0x54AB0954A3088621ULL,
		0x1E9A3DE2BD446009ULL
	}};
	printf("Test Case 174\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 174 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -174;
	} else {
		printf("Test Case 174 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4D63C805212A5885ULL,
		0x4407076935E7F964ULL,
		0xA19B0AEC63C6EF7DULL,
		0x60C6755EF8985566ULL,
		0x8C837CDAD3ADE612ULL,
		0xDED449D95CD942DAULL,
		0xDAA1BD97DA0EDE49ULL,
		0x317A70D70848A2B6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9AC7900A4254B10AULL,
		0x880E0ED26BCFF2C8ULL,
		0x433615D8C78DDEFAULL,
		0xC18CEABDF130AACDULL,
		0x1906F9B5A75BCC24ULL,
		0xBDA893B2B9B285B5ULL,
		0xB5437B2FB41DBC93ULL,
		0x62F4E1AE1091456DULL
	}};
	printf("Test Case 175\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 175 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -175;
	} else {
		printf("Test Case 175 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA68AB06A77091267ULL,
		0x5523E9C071F0B560ULL,
		0x4CBF59A45CE8BD4CULL,
		0xF7246E960932DA1DULL,
		0xDD4384A9FEB25D35ULL,
		0x71D1F77DED837FA6ULL,
		0xDBA1AB1ABBA5FFFFULL,
		0x357C8104F60D63B6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4D1560D4EE1224CEULL,
		0xAA47D380E3E16AC1ULL,
		0x997EB348B9D17A98ULL,
		0xEE48DD2C1265B43AULL,
		0xBA870953FD64BA6BULL,
		0xE3A3EEFBDB06FF4DULL,
		0xB7435635774BFFFEULL,
		0x6AF90209EC1AC76DULL
	}};
	printf("Test Case 176\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 176 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -176;
	} else {
		printf("Test Case 176 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB6E8981756853CBBULL,
		0x7C26D11F7E99101CULL,
		0xD3F608ECF57708CCULL,
		0x893A67D426B2498EULL,
		0x2065E1A62EC7F3ADULL,
		0x61FA9F1D2F9E18D3ULL,
		0x9C462979841ACDEFULL,
		0x0330A8F9DA294660ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6DD1302EAD0A7976ULL,
		0xF84DA23EFD322039ULL,
		0xA7EC11D9EAEE1198ULL,
		0x1274CFA84D64931DULL,
		0x40CBC34C5D8FE75BULL,
		0xC3F53E3A5F3C31A6ULL,
		0x388C52F308359BDEULL,
		0x066151F3B4528CC1ULL
	}};
	printf("Test Case 177\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 177 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -177;
	} else {
		printf("Test Case 177 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE995508101FBA640ULL,
		0x62D3ED6968FF51F3ULL,
		0x6B684B832697A166ULL,
		0x380949BD2976B08AULL,
		0x00996168237539ECULL,
		0x8DF92818C5156E5CULL,
		0x4EA5BCC500BBF012ULL,
		0x352154256CFC4DF7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD32AA10203F74C80ULL,
		0xC5A7DAD2D1FEA3E7ULL,
		0xD6D097064D2F42CCULL,
		0x7012937A52ED6114ULL,
		0x0132C2D046EA73D8ULL,
		0x1BF250318A2ADCB8ULL,
		0x9D4B798A0177E025ULL,
		0x6A42A84AD9F89BEEULL
	}};
	printf("Test Case 178\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 178 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -178;
	} else {
		printf("Test Case 178 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x56217881804012F0ULL,
		0xB56E59AA94FE2AA6ULL,
		0xC0573ABC3E812245ULL,
		0x7556564449934DBAULL,
		0x56FA5A2A79F91203ULL,
		0x0507A43329428540ULL,
		0xDF9DC061EE78D85CULL,
		0x0CB1CB97E60EF135ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAC42F103008025E0ULL,
		0x6ADCB35529FC554CULL,
		0x80AE75787D02448BULL,
		0xEAACAC8893269B75ULL,
		0xADF4B454F3F22406ULL,
		0x0A0F486652850A80ULL,
		0xBF3B80C3DCF1B0B8ULL,
		0x1963972FCC1DE26BULL
	}};
	printf("Test Case 179\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 179 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -179;
	} else {
		printf("Test Case 179 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE2823A3BA9BF058BULL,
		0x7F855D141C193800ULL,
		0xE054294480B07353ULL,
		0x30DCF6F1DDDB4976ULL,
		0x386E9DA1A92D6700ULL,
		0xD8CC96CB2D872023ULL,
		0x7C80938154BEF2BEULL,
		0x1ACC823C9997FD17ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC5047477537E0B16ULL,
		0xFF0ABA2838327001ULL,
		0xC0A852890160E6A6ULL,
		0x61B9EDE3BBB692EDULL,
		0x70DD3B43525ACE00ULL,
		0xB1992D965B0E4046ULL,
		0xF9012702A97DE57DULL,
		0x35990479332FFA2EULL
	}};
	printf("Test Case 180\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 180 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -180;
	} else {
		printf("Test Case 180 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB09AD87A7A7F1464ULL,
		0x50583B2A1D2D5A98ULL,
		0x77962155F626CA99ULL,
		0xFC1E0B8DD3763D10ULL,
		0x4C4D2F1E833EFA37ULL,
		0xC1CDDF6B86BEB1A6ULL,
		0x94349ADC7382AE2BULL,
		0x1C49D43F44796A86ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6135B0F4F4FE28C8ULL,
		0xA0B076543A5AB531ULL,
		0xEF2C42ABEC4D9532ULL,
		0xF83C171BA6EC7A20ULL,
		0x989A5E3D067DF46FULL,
		0x839BBED70D7D634CULL,
		0x286935B8E7055C57ULL,
		0x3893A87E88F2D50DULL
	}};
	printf("Test Case 181\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 181 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -181;
	} else {
		printf("Test Case 181 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x60C8033F722E0B98ULL,
		0x3AC6B4F776E4FC1EULL,
		0x6C54F47BF48291E0ULL,
		0x57D128C37F17E1A0ULL,
		0x222C94B166B90AE6ULL,
		0x9A5E62F014BA3E9FULL,
		0x296CE1C1E514E771ULL,
		0x2D96157ED337FB75ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC190067EE45C1730ULL,
		0x758D69EEEDC9F83CULL,
		0xD8A9E8F7E90523C0ULL,
		0xAFA25186FE2FC340ULL,
		0x44592962CD7215CCULL,
		0x34BCC5E029747D3EULL,
		0x52D9C383CA29CEE3ULL,
		0x5B2C2AFDA66FF6EAULL
	}};
	printf("Test Case 182\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 182 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -182;
	} else {
		printf("Test Case 182 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x13B631807B0D9655ULL,
		0x02604CEA408E3409ULL,
		0x8BE008FBF3CA6351ULL,
		0x2688241572A2FBCBULL,
		0x470D7852E547891EULL,
		0x57C943997D00A3FAULL,
		0x42012ED1842BF845ULL,
		0x29602814D20F23B1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x276C6300F61B2CAAULL,
		0x04C099D4811C6812ULL,
		0x17C011F7E794C6A2ULL,
		0x4D10482AE545F797ULL,
		0x8E1AF0A5CA8F123CULL,
		0xAF928732FA0147F4ULL,
		0x84025DA30857F08AULL,
		0x52C05029A41E4762ULL
	}};
	printf("Test Case 183\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 183 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -183;
	} else {
		printf("Test Case 183 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x46C290279097CB6BULL,
		0x7F7BC688A88EA875ULL,
		0x299670705B7912EEULL,
		0xA21E4480FC48A45DULL,
		0x7B851D23255B5836ULL,
		0x5AC72538263B9EAAULL,
		0x9ABB352397ABD172ULL,
		0x13713485A303A07EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8D85204F212F96D6ULL,
		0xFEF78D11511D50EAULL,
		0x532CE0E0B6F225DCULL,
		0x443C8901F89148BAULL,
		0xF70A3A464AB6B06DULL,
		0xB58E4A704C773D54ULL,
		0x35766A472F57A2E4ULL,
		0x26E2690B460740FDULL
	}};
	printf("Test Case 184\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 184 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -184;
	} else {
		printf("Test Case 184 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2D43D1D15CF7C986ULL,
		0xEB655AA8D11FF820ULL,
		0x0E757E33CB50F7D9ULL,
		0x10DDD50F40218CA9ULL,
		0xC342E0E1BCA3E07BULL,
		0x50D752EDD738C9F0ULL,
		0x0069EE70F721FAB6ULL,
		0x19668514AC8FCF9BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5A87A3A2B9EF930CULL,
		0xD6CAB551A23FF040ULL,
		0x1CEAFC6796A1EFB3ULL,
		0x21BBAA1E80431952ULL,
		0x8685C1C37947C0F6ULL,
		0xA1AEA5DBAE7193E1ULL,
		0x00D3DCE1EE43F56CULL,
		0x32CD0A29591F9F36ULL
	}};
	printf("Test Case 185\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 185 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -185;
	} else {
		printf("Test Case 185 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB71B2E869ED42ACFULL,
		0xBAD1DD099DB14653ULL,
		0xC14ABA73FAC7BE8BULL,
		0x68275884800B89A8ULL,
		0x7B9929FAF3AEEC41ULL,
		0x683C97B6C03D5F38ULL,
		0xA9DAFE6CEB07C552ULL,
		0x1927710CEABBCA35ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6E365D0D3DA8559EULL,
		0x75A3BA133B628CA7ULL,
		0x829574E7F58F7D17ULL,
		0xD04EB10900171351ULL,
		0xF73253F5E75DD882ULL,
		0xD0792F6D807ABE70ULL,
		0x53B5FCD9D60F8AA4ULL,
		0x324EE219D577946BULL
	}};
	printf("Test Case 186\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 186 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -186;
	} else {
		printf("Test Case 186 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD741D7AC5222C590ULL,
		0xE852E339C346C5DBULL,
		0x68D3BB344A6AFC1FULL,
		0xC3DE71CDB5A6B335ULL,
		0x9C5BA89C133E05BCULL,
		0x11C8DF14926102AAULL,
		0xBB57E01786E4FD3EULL,
		0x056DC967216BF724ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAE83AF58A4458B20ULL,
		0xD0A5C673868D8BB7ULL,
		0xD1A7766894D5F83FULL,
		0x87BCE39B6B4D666AULL,
		0x38B75138267C0B79ULL,
		0x2391BE2924C20555ULL,
		0x76AFC02F0DC9FA7CULL,
		0x0ADB92CE42D7EE49ULL
	}};
	printf("Test Case 187\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 187 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -187;
	} else {
		printf("Test Case 187 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE1497B3C1A08FA91ULL,
		0xFCB27D856BB82A34ULL,
		0x614FC0754E1DF43EULL,
		0xF8096D736E912A0AULL,
		0x3B1B8480D2C73481ULL,
		0x7A60EF05E1A529FDULL,
		0x7609477118171F2FULL,
		0x21B44749D5E9F981ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC292F6783411F522ULL,
		0xF964FB0AD7705469ULL,
		0xC29F80EA9C3BE87DULL,
		0xF012DAE6DD225414ULL,
		0x76370901A58E6903ULL,
		0xF4C1DE0BC34A53FAULL,
		0xEC128EE2302E3E5EULL,
		0x43688E93ABD3F302ULL
	}};
	printf("Test Case 188\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 188 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -188;
	} else {
		printf("Test Case 188 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9A8B7DF30F598716ULL,
		0x112C9A3C3A872277ULL,
		0x4C1445902C01F1F6ULL,
		0x4F34B4387D23B171ULL,
		0x753F4AF52CD09FE1ULL,
		0x7F2C1873BC1257ACULL,
		0x3BC74389ABC223CAULL,
		0x11C13567120B8601ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3516FBE61EB30E2CULL,
		0x22593478750E44EFULL,
		0x98288B205803E3ECULL,
		0x9E696870FA4762E2ULL,
		0xEA7E95EA59A13FC2ULL,
		0xFE5830E77824AF58ULL,
		0x778E871357844794ULL,
		0x23826ACE24170C02ULL
	}};
	printf("Test Case 189\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 189 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -189;
	} else {
		printf("Test Case 189 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x484F8F78C7F59FD4ULL,
		0x0369C5112640891EULL,
		0x6315266746B8B366ULL,
		0x5B843475E06B323FULL,
		0x550C09C3CA573BFCULL,
		0x3E570FAD02A59810ULL,
		0xF15468F6A2D7C791ULL,
		0x37311E2F9F82D038ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x909F1EF18FEB3FA8ULL,
		0x06D38A224C81123CULL,
		0xC62A4CCE8D7166CCULL,
		0xB70868EBC0D6647EULL,
		0xAA18138794AE77F8ULL,
		0x7CAE1F5A054B3020ULL,
		0xE2A8D1ED45AF8F22ULL,
		0x6E623C5F3F05A071ULL
	}};
	printf("Test Case 190\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 190 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -190;
	} else {
		printf("Test Case 190 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD51C73316CCB2FF8ULL,
		0xB6C96634C03FFA8EULL,
		0xA1E72E808C38E348ULL,
		0x25453B0AA43F6E4FULL,
		0x9C9454191B7470A2ULL,
		0xCC06FBCEC642325CULL,
		0x5A028C7693308B2CULL,
		0x3ECFF1F2FB58329EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAA38E662D9965FF0ULL,
		0x6D92CC69807FF51DULL,
		0x43CE5D011871C691ULL,
		0x4A8A7615487EDC9FULL,
		0x3928A83236E8E144ULL,
		0x980DF79D8C8464B9ULL,
		0xB40518ED26611659ULL,
		0x7D9FE3E5F6B0653CULL
	}};
	printf("Test Case 191\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 191 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -191;
	} else {
		printf("Test Case 191 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDB07A3D79982B3C3ULL,
		0x7BC5071C293B0192ULL,
		0x222108EEAB763942ULL,
		0x035BC11152747A35ULL,
		0x9C8E377EFFF14BF2ULL,
		0x992E6C9962A2A377ULL,
		0x53BBC09CF9B4DA55ULL,
		0x0D46B3941F2E1357ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB60F47AF33056786ULL,
		0xF78A0E3852760325ULL,
		0x444211DD56EC7284ULL,
		0x06B78222A4E8F46AULL,
		0x391C6EFDFFE297E4ULL,
		0x325CD932C54546EFULL,
		0xA7778139F369B4ABULL,
		0x1A8D67283E5C26AEULL
	}};
	printf("Test Case 192\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 192 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -192;
	} else {
		printf("Test Case 192 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8D0590E7BE6EFD50ULL,
		0x90167686B0E7421FULL,
		0xCE2509A94217D680ULL,
		0x6D69082AD1B82D8FULL,
		0xA4C59B19DE264E76ULL,
		0xC2E877169562B713ULL,
		0x924C4402D4AEB987ULL,
		0x0FD73D578266C50CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1A0B21CF7CDDFAA0ULL,
		0x202CED0D61CE843FULL,
		0x9C4A1352842FAD01ULL,
		0xDAD21055A3705B1FULL,
		0x498B3633BC4C9CECULL,
		0x85D0EE2D2AC56E27ULL,
		0x24988805A95D730FULL,
		0x1FAE7AAF04CD8A19ULL
	}};
	printf("Test Case 193\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 193 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -193;
	} else {
		printf("Test Case 193 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAE618E63B6E2ADF7ULL,
		0x7DC4D7AE03CD3FCEULL,
		0x6FC33171B5FA0E35ULL,
		0x301D15D812F49659ULL,
		0x4E28AB0856B3D1DFULL,
		0x68CAFDEC461E4ACAULL,
		0xC584BF16DF51FF6AULL,
		0x01294B53BAA64F73ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5CC31CC76DC55BEEULL,
		0xFB89AF5C079A7F9DULL,
		0xDF8662E36BF41C6AULL,
		0x603A2BB025E92CB2ULL,
		0x9C515610AD67A3BEULL,
		0xD195FBD88C3C9594ULL,
		0x8B097E2DBEA3FED4ULL,
		0x025296A7754C9EE7ULL
	}};
	printf("Test Case 194\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 194 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -194;
	} else {
		printf("Test Case 194 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x49EDCCE1ACFEADBFULL,
		0x52F343A58A37C367ULL,
		0xC20780645BD484FEULL,
		0xEE63104A0C1AAA31ULL,
		0x058E70C7BFFAF01BULL,
		0x6DF46193BB8535C6ULL,
		0x783F9EA2003722D7ULL,
		0x08CA8BB5F7453FADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x93DB99C359FD5B7EULL,
		0xA5E6874B146F86CEULL,
		0x840F00C8B7A909FCULL,
		0xDCC6209418355463ULL,
		0x0B1CE18F7FF5E037ULL,
		0xDBE8C327770A6B8CULL,
		0xF07F3D44006E45AEULL,
		0x1195176BEE8A7F5AULL
	}};
	printf("Test Case 195\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 195 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -195;
	} else {
		printf("Test Case 195 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBC4F3E948BF9FA39ULL,
		0x0A98BAA115CDF10DULL,
		0x999DE304ED0889A1ULL,
		0xCEBC529E4A3CB72CULL,
		0x5C086834B34777ABULL,
		0x73C5631D1FCBBEB5ULL,
		0x6893147CA844471CULL,
		0x3251879B24F9BC9BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x789E7D2917F3F472ULL,
		0x153175422B9BE21BULL,
		0x333BC609DA111342ULL,
		0x9D78A53C94796E59ULL,
		0xB810D069668EEF57ULL,
		0xE78AC63A3F977D6AULL,
		0xD12628F950888E38ULL,
		0x64A30F3649F37936ULL
	}};
	printf("Test Case 196\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 196 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -196;
	} else {
		printf("Test Case 196 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0C6DF202E5003B1AULL,
		0x640FFE42E19F371AULL,
		0xEB0512C3D0145729ULL,
		0x1F6FF254F0328B63ULL,
		0x851E95B11B5D4B46ULL,
		0x5E73B970D3A89717ULL,
		0x7527357F5E969770ULL,
		0x3640AD50BAC69E2AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x18DBE405CA007634ULL,
		0xC81FFC85C33E6E34ULL,
		0xD60A2587A028AE52ULL,
		0x3EDFE4A9E06516C7ULL,
		0x0A3D2B6236BA968CULL,
		0xBCE772E1A7512E2FULL,
		0xEA4E6AFEBD2D2EE0ULL,
		0x6C815AA1758D3C54ULL
	}};
	printf("Test Case 197\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 197 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -197;
	} else {
		printf("Test Case 197 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8387C41CA8557690ULL,
		0x07B3513A69CC2205ULL,
		0xDADBFE916CE553E4ULL,
		0xE1F5FF83A3B97AE4ULL,
		0x89DCCDC7DF12D032ULL,
		0x6D470E163469FCA6ULL,
		0x35A271D83183FE2AULL,
		0x181C3F3CEE10FCF6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x070F883950AAED20ULL,
		0x0F66A274D398440BULL,
		0xB5B7FD22D9CAA7C8ULL,
		0xC3EBFF074772F5C9ULL,
		0x13B99B8FBE25A065ULL,
		0xDA8E1C2C68D3F94DULL,
		0x6B44E3B06307FC54ULL,
		0x30387E79DC21F9ECULL
	}};
	printf("Test Case 198\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 198 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -198;
	} else {
		printf("Test Case 198 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3667E286F0DC44FDULL,
		0x94D3D8CF0B1E1CECULL,
		0x8583A4EC63A51551ULL,
		0xE73838D2339A8FB2ULL,
		0x13EB0EECAEDAB499ULL,
		0xA451AF2F99BE6FCEULL,
		0x27352F7AF27721B1ULL,
		0x268F2D9F2F205969ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6CCFC50DE1B889FAULL,
		0x29A7B19E163C39D8ULL,
		0x0B0749D8C74A2AA3ULL,
		0xCE7071A467351F65ULL,
		0x27D61DD95DB56933ULL,
		0x48A35E5F337CDF9CULL,
		0x4E6A5EF5E4EE4363ULL,
		0x4D1E5B3E5E40B2D2ULL
	}};
	printf("Test Case 199\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 199 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -199;
	} else {
		printf("Test Case 199 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDDCF2A03AD677EBAULL,
		0xA587FA9DBBD4CA87ULL,
		0xB08A923147075DE2ULL,
		0x597EBA0813069210ULL,
		0xAB3A84110E1DA844ULL,
		0x0F4BBB2A656573C9ULL,
		0x9024A6EA13C97E40ULL,
		0x07E93B2C9976BA31ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB9E54075ACEFD74ULL,
		0x4B0FF53B77A9950FULL,
		0x611524628E0EBBC5ULL,
		0xB2FD7410260D2421ULL,
		0x567508221C3B5088ULL,
		0x1E977654CACAE793ULL,
		0x20494DD42792FC80ULL,
		0x0FD2765932ED7463ULL
	}};
	printf("Test Case 200\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
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