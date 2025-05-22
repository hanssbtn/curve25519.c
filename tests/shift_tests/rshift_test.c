#include "../tests.h"

int32_t curve25519_key_rshift_test(void) {
	printf("Key Right Shift Test\n");
	curve25519_key_t k1 = {.key64 = {
		0xBCD402AD876CB55BULL,
		0xE5B60F68CBF8C0C7ULL,
		0xF4F1B216EE7B3A48ULL,
		0x8800F83F38215225ULL,
		0xD2C784245A71FFD7ULL,
		0x6A8EDF625878A82AULL,
		0x35D77B057A258BFDULL,
		0x0000000000000000ULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0xB6C1ED197F1818F7ULL,
		0x9E3642DDCF67491CULL,
		0x001F07E7042A44BEULL,
		0x58F0848B4E3FFAF1ULL,
		0x51DBEC4B0F15055AULL,
		0xBAEF60AF44B17FADULL,
		0x0000000000000006ULL,
		0x0000000000000000ULL
	}};
	int shift = 59;
	curve25519_key_t r = {};
	printf("Test Case 1\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xC9D086DFEF92338CULL,
		0x0903B3794BB2B428ULL,
		0xAF4EBB7566E53BDAULL,
		0xDFC9B947F0DF2426ULL,
		0x30A2C1A60FE2F451ULL,
		0x4BA55C469AFD1179ULL,
		0xE5D0FE24B456C3E8ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE52ECAD0A327421BULL,
		0xD59B94EF68240ECDULL,
		0x1FC37C909ABD3AEDULL,
		0x983F8BD1477F26E5ULL,
		0x1A6BF445E4C28B06ULL,
		0x92D15B0FA12E9571ULL,
		0x00000000039743F8ULL,
		0x0000000000000000ULL
	}};
	shift = 38;
	printf("Test Case 2\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x63272BD4D980A28DULL,
		0x676CDD32D6E4C9B7ULL,
		0xA1499EE8FFE68C87ULL,
		0xD7C42A8A13989605ULL,
		0x5D9F65412F992D58ULL,
		0x6A023841EC793CCDULL,
		0xA4F19798C3867C3DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB5B9326DD8C9CAF5ULL,
		0x3FF9A321D9DB374CULL,
		0x84E62581685267BAULL,
		0x4BE64B5635F10AA2ULL,
		0x7B1E4F335767D950ULL,
		0x30E19F0F5A808E10ULL,
		0x00000000293C65E6ULL,
		0x0000000000000000ULL
	}};
	shift = 34;
	printf("Test Case 3\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xC0138874039FE1AFULL,
		0x60393EA702463944ULL,
		0x4539FCD8CB10D276ULL,
		0xD6B128F09A479A5AULL,
		0x57EB84B624BE6A01ULL,
		0x07A0BA149B4E33B7ULL,
		0x45C06A97F09DFD2DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF5381231CA26009CULL,
		0xE6C6588693B301C9ULL,
		0x4784D23CD2D229CFULL,
		0x25B125F3500EB589ULL,
		0xD0A4DA719DBABF5CULL,
		0x54BF84EFE9683D05ULL,
		0x0000000000022E03ULL,
		0x0000000000000000ULL
	}};
	shift = 45;
	printf("Test Case 4\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x3711D45048AF70B6ULL,
		0xE6EC993263A58360ULL,
		0xDE9BE90FA63201F7ULL,
		0x058DFC7AAACB0713ULL,
		0x3998938CECC193A6ULL,
		0x09F5C711A771BDDBULL,
		0xEBC75280AF30D65EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x80DC47514122BDC2ULL,
		0xDF9BB264C98E960DULL,
		0x4F7A6FA43E98C807ULL,
		0x981637F1EAAB2C1CULL,
		0x6CE6624E33B3064EULL,
		0x7827D71C469DC6F7ULL,
		0x03AF1D4A02BCC359ULL,
		0x0000000000000000ULL
	}};
	shift = 6;
	printf("Test Case 5\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xFA38C386695A99BDULL,
		0x2CA0CACF484FC138ULL,
		0x4B80A185946C1EE2ULL,
		0xF2E68BDAA40313BAULL,
		0xBA1AB74C8097B2DEULL,
		0xB69272C43DD43CB3ULL,
		0x6E841B005E7B8357ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x13F04E3E8E30E19AULL,
		0x1B07B88B2832B3D2ULL,
		0x00C4EE92E0286165ULL,
		0x25ECB7BCB9A2F6A9ULL,
		0x750F2CEE86ADD320ULL,
		0x9EE0D5EDA49CB10FULL,
		0x0000001BA106C017ULL,
		0x0000000000000000ULL
	}};
	shift = 26;
	printf("Test Case 6\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x83BA3357344238A4ULL,
		0x573F026C4C15D19CULL,
		0x8F684D03D1D0313FULL,
		0x097A12CCD8A37234ULL,
		0x8396FE68884BB16AULL,
		0xBB9BD349114597FBULL,
		0x2E30BF30F745175DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9B1305746720EE8CULL,
		0x40F4740C4FD5CFC0ULL,
		0xB33628DC8D23DA13ULL,
		0x9A2212EC5A825E84ULL,
		0xD2445165FEE0E5BFULL,
		0xCC3DD145D76EE6F4ULL,
		0x00000000000B8C2FULL,
		0x0000000000000000ULL
	}};
	shift = 42;
	printf("Test Case 7\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x635A5C7499915388ULL,
		0xB6ECBAFD89A4554EULL,
		0xE3750DA26B76400FULL,
		0xD50C8295F74E4B61ULL,
		0xC985FE8B2B7FDB83ULL,
		0x6AB70A05C95C8970ULL,
		0x746DDB2AE3CB3228ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x398D6971D266454EULL,
		0x3EDBB2EBF6269155ULL,
		0x878DD43689ADD900ULL,
		0x0F54320A57DD392DULL,
		0xC32617FA2CADFF6EULL,
		0xA1AADC2817257225ULL,
		0x01D1B76CAB8F2CC8ULL,
		0x0000000000000000ULL
	}};
	shift = 6;
	printf("Test Case 8\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xCB8B5A3115780227ULL,
		0x26733922712D6DD5ULL,
		0x14234ED2E694D465ULL,
		0xEC316233127DF6D8ULL,
		0xE2660B718F11195CULL,
		0x5154A7D64ADF53B5ULL,
		0x775F774498E55CDEULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB7572E2D68C455E0ULL,
		0x519499CCE489C4B5ULL,
		0xDB60508D3B4B9A53ULL,
		0x6573B0C588CC49F7ULL,
		0x4ED789982DC63C44ULL,
		0x737945529F592B7DULL,
		0x0001DD7DDD126395ULL,
		0x0000000000000000ULL
	}};
	shift = 14;
	printf("Test Case 9\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x2ED809027DD4268CULL,
		0x60DC2E0BB5D1FB62ULL,
		0x1AFADCD4771C14C0ULL,
		0x9BD3DE07807662EFULL,
		0x499BEC1ABAB66BF0ULL,
		0x690EF08F6C5F0D7AULL,
		0xDCDA774945DB7433ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x70B82ED747ED88BBULL,
		0xEB7351DC70530183ULL,
		0x4F781E01D98BBC6BULL,
		0x6FB06AEAD9AFC26FULL,
		0x3BC23DB17C35E926ULL,
		0x69DD25176DD0CDA4ULL,
		0x0000000000000373ULL,
		0x0000000000000000ULL
	}};
	shift = 54;
	printf("Test Case 10\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xCD6CDCB18469AAADULL,
		0x409B3597B742E1AAULL,
		0x3E7868E79FC3C890ULL,
		0xCFA1D011637D8341ULL,
		0xB39576B2F289C82AULL,
		0x3BE639FFE4966B31ULL,
		0x923C27B4631C9A8DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB2F6E85C3559AD9BULL,
		0x1CF3F87912081366ULL,
		0x022C6FB06827CF0DULL,
		0xD65E51390559F43AULL,
		0x3FFC92CD663672AEULL,
		0xF68C639351A77CC7ULL,
		0x0000000000124784ULL,
		0x0000000000000000ULL
	}};
	shift = 43;
	printf("Test Case 11\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x6CD9822B5DA81CBAULL,
		0x606202C85ADADDD9ULL,
		0x3DA0210D80321029ULL,
		0x862197782E62ECBEULL,
		0x8952699B27C86C9DULL,
		0xE0C2C8D64DD013CDULL,
		0x91491278A82EBEFBULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0B5B5BBB2D9B3045ULL,
		0xB00642052C0C4059ULL,
		0x05CC5D97C7B40421ULL,
		0x64F90D93B0C432EFULL,
		0xC9BA0279B12A4D33ULL,
		0x1505D7DF7C18591AULL,
		0x000000001229224FULL,
		0x0000000000000000ULL
	}};
	shift = 35;
	printf("Test Case 12\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x38525434993B8936ULL,
		0x5825EEE40C200FA8ULL,
		0x220D0577B1DE8AB1ULL,
		0xD77E58CED033EDAFULL,
		0x1C840441EA9A5173ULL,
		0xD3BCB89D10D060A0ULL,
		0x59D4300A032923BEULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDC818401F5070A4AULL,
		0xAEF63BD1562B04BDULL,
		0x19DA067DB5E441A0ULL,
		0x883D534A2E7AEFCBULL,
		0x13A21A0C14039080ULL,
		0x0140652477DA7797ULL,
		0x00000000000B3A86ULL,
		0x0000000000000000ULL
	}};
	shift = 43;
	printf("Test Case 13\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x25FB06330E9B98C5ULL,
		0x3F79A9DDC07FE9BEULL,
		0xB5C6A22C58524D28ULL,
		0xF135E197282922A1ULL,
		0xBDF87973E1AA5A9AULL,
		0x00CDF11BF76E513CULL,
		0x23A3CBC91B610AC6ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF12FD8319874DCC6ULL,
		0x41FBCD4EEE03FF4DULL,
		0x0DAE351162C29269ULL,
		0xD789AF0CB9414915ULL,
		0xE5EFC3CB9F0D52D4ULL,
		0x30066F88DFBB7289ULL,
		0x011D1E5E48DB0856ULL,
		0x0000000000000000ULL
	}};
	shift = 5;
	printf("Test Case 14\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xA4E1E8E3813FE3CFULL,
		0x6F4D94A2B393D8C5ULL,
		0x639729C856937E6CULL,
		0x24C2062528879CCAULL,
		0xEA376EB2A1EC6588ULL,
		0x378C1DE15796D286ULL,
		0x508A6D28054454DBULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD36528ACE4F63169ULL,
		0xE5CA7215A4DF9B1BULL,
		0x3081894A21E73298ULL,
		0x8DDBACA87B196209ULL,
		0xE3077855E5B4A1BAULL,
		0x229B4A01511536CDULL,
		0x0000000000000014ULL,
		0x0000000000000000ULL
	}};
	shift = 58;
	printf("Test Case 15\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x51291CD656B3D516ULL,
		0x97B3541FF4AA23D8ULL,
		0xC5F9BD8677F9DFBCULL,
		0x5957D9522D2EF727ULL,
		0x82DC4C971FA8D403ULL,
		0x24FC99AEAFAD1B0DULL,
		0xFAF600EAB29ED9C8ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA0FFA5511EC28948ULL,
		0xEC33BFCEFDE4BD9AULL,
		0xCA916977B93E2FCDULL,
		0x64B8FD46A01ACABEULL,
		0xCD757D68D86C16E2ULL,
		0x075594F6CE4127E4ULL,
		0x000000000007D7B0ULL,
		0x0000000000000000ULL
	}};
	shift = 45;
	printf("Test Case 16\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x668979F412405E85ULL,
		0x160E43197021C345ULL,
		0x17CA72374072F502ULL,
		0xE188B31DE3013DEDULL,
		0xA6A1157AD8A28170ULL,
		0x32F9FE82D0458C8BULL,
		0xDF5624815DF694BCULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC65C0870D159A25EULL,
		0x8DD01CBD40858390ULL,
		0xC778C04F7B45F29CULL,
		0x5EB628A05C38622CULL,
		0xA0B4116322E9A845ULL,
		0x20577DA52F0CBE7FULL,
		0x000000000037D589ULL,
		0x0000000000000000ULL
	}};
	shift = 42;
	printf("Test Case 17\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xC5AC8918CF4AA302ULL,
		0xBF3BBB682F1AB27EULL,
		0x14F330E1C71CF677ULL,
		0x8210F2D3354910EFULL,
		0xD68DBAB4343385EDULL,
		0x2DEBAF18549E3C16ULL,
		0xA6D66DCF079AD1F7ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB682F1AB27EC5AC8ULL,
		0x0E1C71CF677BF3BBULL,
		0x2D3354910EF14F33ULL,
		0xAB4343385ED8210FULL,
		0xF18549E3C16D68DBULL,
		0xDCF079AD1F72DEBAULL,
		0x00000000000A6D66ULL,
		0x0000000000000000ULL
	}};
	shift = 44;
	printf("Test Case 18\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x500B0A38FF52578CULL,
		0x9E251613D14021C8ULL,
		0xCFBE9AC4F62D4B77ULL,
		0xAAD37B59AC83CF67ULL,
		0x6A2EB15A8242CDA4ULL,
		0xEC4CE4CC38E6477EULL,
		0xEF26ABE7208243F1ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2805851C7FA92BC6ULL,
		0xCF128B09E8A010E4ULL,
		0xE7DF4D627B16A5BBULL,
		0x5569BDACD641E7B3ULL,
		0x351758AD412166D2ULL,
		0xF62672661C7323BFULL,
		0x779355F3904121F8ULL,
		0x0000000000000000ULL
	}};
	shift = 1;
	printf("Test Case 19\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xC4C547BA01281888ULL,
		0xAE9CF35A9D3CDB03ULL,
		0xAC7FDEEB0465133CULL,
		0xAB0E0BB5565BB461ULL,
		0x77C2029580EF2BFDULL,
		0x3D61364AB3D0F03FULL,
		0xB00ECE535795D64DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7898A8F740250311ULL,
		0x95D39E6B53A79B60ULL,
		0x358FFBDD608CA267ULL,
		0xB561C176AACB768CULL,
		0xEEF84052B01DE57FULL,
		0xA7AC26C9567A1E07ULL,
		0x1601D9CA6AF2BAC9ULL,
		0x0000000000000000ULL
	}};
	shift = 3;
	printf("Test Case 20\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xF0C22CBE788506C1ULL,
		0x1A967969A6457FF5ULL,
		0xF72AD295FC958643ULL,
		0xB56415F9088A28EEULL,
		0x72A0F0DD187274B2ULL,
		0xAFF85F5594961D37ULL,
		0x8F08947FE7195CB1ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3CB4D322BFFAF861ULL,
		0x694AFE4AC3218D4BULL,
		0x0AFC844514777B95ULL,
		0x786E8C393A595AB2ULL,
		0x2FAACA4B0E9BB950ULL,
		0x4A3FF38CAE58D7FCULL,
		0x0000000000004784ULL,
		0x0000000000000000ULL
	}};
	shift = 49;
	printf("Test Case 21\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xFA589F0B8514EB0CULL,
		0x2E9D9C04FB4D9F66ULL,
		0x3D75CF3DED61365BULL,
		0x6351B4A2BDA044E4ULL,
		0xD52C8399199EA35FULL,
		0x53F8BB406E4C8354ULL,
		0xC1CBD7C0DCFA0644ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDA6CFB37D2C4F85CULL,
		0x6B09B2D974ECE027ULL,
		0xED022721EBAE79EFULL,
		0xCCF51AFB1A8DA515ULL,
		0x72641AA6A9641CC8ULL,
		0xE7D032229FC5DA03ULL,
		0x000000060E5EBE06ULL,
		0x0000000000000000ULL
	}};
	shift = 29;
	printf("Test Case 22\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x688E5672CB58BD3DULL,
		0x1B368318B952704BULL,
		0xC7CEC84552BDD12CULL,
		0x6B883F10BE8E5913ULL,
		0xD87A8F9F83610534ULL,
		0x0375780447DF5F52ULL,
		0x9AEFEB2375B9DD1EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x72A4E096D11CACE5ULL,
		0xA57BA258366D0631ULL,
		0x7D1CB2278F9D908AULL,
		0x06C20A68D7107E21ULL,
		0x8FBEBEA5B0F51F3FULL,
		0xEB73BA3C06EAF008ULL,
		0x0000000135DFD646ULL,
		0x0000000000000000ULL
	}};
	shift = 31;
	printf("Test Case 23\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xE1938C299DFBA2BFULL,
		0x2EA66002F4426645ULL,
		0x2451163740B59DA4ULL,
		0x38117D827A8D0A58ULL,
		0xC659DDE46C8CDE43ULL,
		0xE7DECBC818571EF3ULL,
		0xA4970B1B7F995B02ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x800BD1099917864EULL,
		0x58DD02D67690BA99ULL,
		0xF609EA3429609144ULL,
		0x7791B233790CE045ULL,
		0x2F20615C7BCF1967ULL,
		0x2C6DFE656C0B9F7BULL,
		0x000000000002925CULL,
		0x0000000000000000ULL
	}};
	shift = 46;
	printf("Test Case 24\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xB82C5EEE5196C282ULL,
		0x46F6C369F74239D1ULL,
		0x92633FAAE0F88EF7ULL,
		0x99C6124F8F475276ULL,
		0x8E6C0B6DAAB6BBACULL,
		0xF3876BB4C8F93DE8ULL,
		0x0A714864BCC51191ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC369F74239D1B82CULL,
		0x3FAAE0F88EF746F6ULL,
		0x124F8F4752769263ULL,
		0x0B6DAAB6BBAC99C6ULL,
		0x6BB4C8F93DE88E6CULL,
		0x4864BCC51191F387ULL,
		0x0000000000000A71ULL,
		0x0000000000000000ULL
	}};
	shift = 48;
	printf("Test Case 25\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xB3DC7F1EF71CF14FULL,
		0xF43D0DD3496CF617ULL,
		0x93472E25F168AFF7ULL,
		0xD519C64D9E90806EULL,
		0xF965429A84D03B68ULL,
		0x1D5A2E00A3F4CEA5ULL,
		0xE90D463A5FAE3323ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD85ECF71FC7BDC73ULL,
		0xBFDFD0F4374D25B3ULL,
		0x01BA4D1CB897C5A2ULL,
		0xEDA3546719367A42ULL,
		0x3A97E5950A6A1340ULL,
		0xCC8C7568B8028FD3ULL,
		0x0003A43518E97EB8ULL,
		0x0000000000000000ULL
	}};
	shift = 14;
	printf("Test Case 26\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x9039E0F77BF71D47ULL,
		0x12C2894279913FB2ULL,
		0x97241A4F65F7BCF4ULL,
		0x62034A44554DC56CULL,
		0xC1D184E7880B6193ULL,
		0x1B881DB6947F8153ULL,
		0xC2D9782CB6989163ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4B0A2509E644FECAULL,
		0x5C90693D97DEF3D0ULL,
		0x880D2911553715B2ULL,
		0x0746139E202D864DULL,
		0x6E2076DA51FE054FULL,
		0x0B65E0B2DA62458CULL,
		0x0000000000000003ULL,
		0x0000000000000000ULL
	}};
	shift = 62;
	printf("Test Case 27\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x302E48795E9EE964ULL,
		0x7750528496CB1711ULL,
		0xA7DDE47FB6F5D803ULL,
		0x46793DC1C8E65271ULL,
		0x414B382868FBAD79ULL,
		0x336AE2B13D698C24ULL,
		0xC2E6AC0EE0E8E516ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5092D962E22605C9ULL,
		0x8FF6DEBB006EEA0AULL,
		0xB8391CCA4E34FBBCULL,
		0x050D1F75AF28CF27ULL,
		0x5627AD3184882967ULL,
		0x81DC1D1CA2C66D5CULL,
		0x0000000000185CD5ULL,
		0x0000000000000000ULL
	}};
	shift = 43;
	printf("Test Case 28\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x41978520C41D4CA4ULL,
		0x91B7B81320D1D14CULL,
		0xC11F58F000128A10ULL,
		0xA75BAD836BBE0A9BULL,
		0xF0B045FE7596D45CULL,
		0xFFFF932FDFB92CF0ULL,
		0x715FD494375581C8ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x99068E8A620CBC29ULL,
		0x80009450848DBDC0ULL,
		0x1B5DF054DE08FAC7ULL,
		0xF3ACB6A2E53ADD6CULL,
		0x7EFDC9678785822FULL,
		0xA1BAAC0E47FFFC99ULL,
		0x00000000038AFEA4ULL,
		0x0000000000000000ULL
	}};
	shift = 37;
	printf("Test Case 29\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x1872D5EB0C037EBFULL,
		0xECB1174030A8BD76ULL,
		0x02EC41AF8582C01EULL,
		0xC59F6FD64FD86172ULL,
		0xF44F9F7FE6CF2625ULL,
		0x5440F82BAA26E4A9ULL,
		0xA4A0D4E7CA9DE2CDULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8061517AEC30E5ABULL,
		0x5F0B05803DD9622EULL,
		0xAC9FB0C2E405D883ULL,
		0xFFCD9E4C4B8B3EDFULL,
		0x57544DC953E89F3EULL,
		0xCF953BC59AA881F0ULL,
		0x00000000014941A9ULL,
		0x0000000000000000ULL
	}};
	shift = 39;
	printf("Test Case 30\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x6CFBA67C0F4B0172ULL,
		0x0EF18116C4CDEA2AULL,
		0xF89E5F52D87C2E48ULL,
		0xA4995AED695D68E5ULL,
		0xA35C034F0CFD962FULL,
		0x262735BC69D2B63FULL,
		0x2FAE48250ED4106CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF18116C4CDEA2A6CULL,
		0x9E5F52D87C2E480EULL,
		0x995AED695D68E5F8ULL,
		0x5C034F0CFD962FA4ULL,
		0x2735BC69D2B63FA3ULL,
		0xAE48250ED4106C26ULL,
		0x000000000000002FULL,
		0x0000000000000000ULL
	}};
	shift = 56;
	printf("Test Case 31\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x2D6C79FF89C46BC9ULL,
		0x4489A8E11F97665FULL,
		0xFF5A8CC441A0A8B5ULL,
		0xB13F8CF08D21EB7CULL,
		0x3E24459A3DB1F9E7ULL,
		0x104226865EF02346ULL,
		0x1C2C172FBDB5173EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x997CB5B1E7FE2711ULL,
		0xA2D51226A3847E5DULL,
		0xADF3FD6A33110682ULL,
		0xE79EC4FE33C23487ULL,
		0x8D18F8911668F6C7ULL,
		0x5CF841089A197BC0ULL,
		0x000070B05CBEF6D4ULL,
		0x0000000000000000ULL
	}};
	shift = 14;
	printf("Test Case 32\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0C28403A1FBE4ED2ULL,
		0xBBB2C8D79C014481ULL,
		0x0898074BD9C529BAULL,
		0x71D771B9B9C2D01AULL,
		0x48F4187E76AFDB6DULL,
		0x6287C39711533A50ULL,
		0xB9184CCEC808DBF1ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8028902185080743ULL,
		0x38A5375776591AF3ULL,
		0x385A03411300E97BULL,
		0xD5FB6DAE3AEE3737ULL,
		0x2A674A091E830FCEULL,
		0x011B7E2C50F872E2ULL,
		0x00000017230999D9ULL,
		0x0000000000000000ULL
	}};
	shift = 27;
	printf("Test Case 33\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x1E260ABA09368E7AULL,
		0x5116653A55100486ULL,
		0xF3BAEA1AEC53E4EFULL,
		0x24E354AAB405FE92ULL,
		0xCA1739C3158E4D1BULL,
		0xFF3C96300EB215BAULL,
		0x69252EB83ED28B47ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA8802430F13055D0ULL,
		0x629F277A88B329D2ULL,
		0xA02FF4979DD750D7ULL,
		0xAC7268D9271AA555ULL,
		0x7590ADD650B9CE18ULL,
		0xF6945A3FF9E4B180ULL,
		0x00000003492975C1ULL,
		0x0000000000000000ULL
	}};
	shift = 29;
	printf("Test Case 34\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x8BF3C2DDB53E950CULL,
		0x60DD43463075055BULL,
		0x85698692A88D7509ULL,
		0xC61D08D9FFC188B5ULL,
		0xB1EF0F13C35B9D4BULL,
		0x7F2C1DF34AC19468ULL,
		0x43BC97A5139EE004ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x750D18C1D4156E2FULL,
		0xA61A4AA235D42583ULL,
		0x742367FF0622D615ULL,
		0xBC3C4F0D6E752F18ULL,
		0xB077CD2B0651A2C7ULL,
		0xF25E944E7B8011FCULL,
		0x000000000000010EULL,
		0x0000000000000000ULL
	}};
	shift = 54;
	printf("Test Case 35\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xFECAC6C130C61564ULL,
		0xA5F9230525CF4B92ULL,
		0xAA009AB075298D49ULL,
		0x9751FA43D3A18E39ULL,
		0x4B446A585B29BE31ULL,
		0x346B525C2422B13BULL,
		0xE11780B3186AFDA6ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5FD958D82618C2ACULL,
		0x34BF2460A4B9E972ULL,
		0x354013560EA531A9ULL,
		0x32EA3F487A7431C7ULL,
		0x69688D4B0B6537C6ULL,
		0xC68D6A4B84845627ULL,
		0x1C22F016630D5FB4ULL,
		0x0000000000000000ULL
	}};
	shift = 3;
	printf("Test Case 36\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xE6DBB26579C21188ULL,
		0x1756C5EF236C531FULL,
		0xF7724B020D1DC4E4ULL,
		0xC46A8B4956A5E45FULL,
		0xE239685FE54ED700ULL,
		0x71092E7C5AAA6A8EULL,
		0xFAC486D566A04E14ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8FF36DD932BCE108ULL,
		0x720BAB62F791B629ULL,
		0x2FFBB92581068EE2ULL,
		0x80623545A4AB52F2ULL,
		0x47711CB42FF2A76BULL,
		0x0A3884973E2D5535ULL,
		0x007D62436AB35027ULL,
		0x0000000000000000ULL
	}};
	shift = 9;
	printf("Test Case 37\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x9D79394A33EB1339ULL,
		0xDFF543C1EDE76CFDULL,
		0x2A165A385092CB0AULL,
		0xF5146C14362A019DULL,
		0xA0389F3D76D5A7A3ULL,
		0x73E40F22A870E916ULL,
		0x023AE2B376127641ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCEBC9CA519F5899CULL,
		0x6FFAA1E0F6F3B67EULL,
		0x950B2D1C28496585ULL,
		0xFA8A360A1B1500CEULL,
		0x501C4F9EBB6AD3D1ULL,
		0xB9F207915438748BULL,
		0x011D7159BB093B20ULL,
		0x0000000000000000ULL
	}};
	shift = 1;
	printf("Test Case 38\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x79FDEF7C0CC63602ULL,
		0x3B5E4F29BFB721D9ULL,
		0xCAD7744CF680A836ULL,
		0xD7FCF33DECB6F403ULL,
		0xCB4D07279CF6C72AULL,
		0xC0B063FFA25978EBULL,
		0xD4456B1A35FF4839ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0ECBCFEF7BE06631ULL,
		0x41B1DAF2794DFDB9ULL,
		0xA01E56BBA267B405ULL,
		0x3956BFE799EF65B7ULL,
		0xC75E5A68393CE7B6ULL,
		0x41CE05831FFD12CBULL,
		0x0006A22B58D1AFFAULL,
		0x0000000000000000ULL
	}};
	shift = 13;
	printf("Test Case 39\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x91B19BFFBB10FF6FULL,
		0xFB07751FA9C33350ULL,
		0x3AA9BBCA25B31A5AULL,
		0xC07BF1A9AE4C130CULL,
		0x08AF325B09983A32ULL,
		0x2C723D1076F99CC4ULL,
		0xB0CB4DB67EB9AA10ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3F538666A1236337ULL,
		0x944B6634B5F60EEAULL,
		0x535C982618755377ULL,
		0xB61330746580F7E3ULL,
		0x20EDF33988115E64ULL,
		0x6CFD73542058E47AULL,
		0x000000000161969BULL,
		0x0000000000000000ULL
	}};
	shift = 39;
	printf("Test Case 40\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x2CA9B367492FC7C3ULL,
		0xB575EE71DF7D9FA4ULL,
		0x6CA3D8967F09FAA5ULL,
		0x0EF4F5919596EED0ULL,
		0xF567E03EEA43F527ULL,
		0x46E523256942522CULL,
		0xA648B486BDC23FD7ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x75EE71DF7D9FA42CULL,
		0xA3D8967F09FAA5B5ULL,
		0xF4F5919596EED06CULL,
		0x67E03EEA43F5270EULL,
		0xE523256942522CF5ULL,
		0x48B486BDC23FD746ULL,
		0x00000000000000A6ULL,
		0x0000000000000000ULL
	}};
	shift = 56;
	printf("Test Case 41\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x81114DF7CEB18785ULL,
		0xEADC9C975B29A98DULL,
		0x42003F64B0B574DAULL,
		0x179F48D7E3D5BAC5ULL,
		0x8DB9FD88D754C14BULL,
		0xAC31B1FA69125917ULL,
		0x51005231A8E74A68ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1B02229BEF9D630FULL,
		0xB5D5B9392EB65353ULL,
		0x8A84007EC9616AE9ULL,
		0x962F3E91AFC7AB75ULL,
		0x2F1B73FB11AEA982ULL,
		0xD1586363F4D224B2ULL,
		0x00A200A46351CE94ULL,
		0x0000000000000000ULL
	}};
	shift = 7;
	printf("Test Case 42\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x056C95DD6A5AE18CULL,
		0x0088DA452FD20C57ULL,
		0xCF7E683F8BC6CC19ULL,
		0xFF31DBA55D19C0D9ULL,
		0x0DAEED2768D9DCCDULL,
		0xA96D0E0B5A792614ULL,
		0xEE91EB45E605948BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x297E9062B82B64AEULL,
		0xFC5E3660C80446D2ULL,
		0x2AE8CE06CE7BF341ULL,
		0x3B46CEE66FF98EDDULL,
		0x5AD3C930A06D7769ULL,
		0x2F302CA45D4B6870ULL,
		0x0000000007748F5AULL,
		0x0000000000000000ULL
	}};
	shift = 37;
	printf("Test Case 43\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x196ACBA276B65023ULL,
		0xE4B5344A1B4B4930ULL,
		0xEB11322A8D4808C2ULL,
		0x872D8B1C671CCECCULL,
		0xBF416B28DF8C2B98ULL,
		0xCDB380F2693558EAULL,
		0xEFF13D0A8DDC212BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA1B4B4930196ACBAULL,
		0xA8D4808C2E4B5344ULL,
		0xC671CCECCEB11322ULL,
		0x8DF8C2B98872D8B1ULL,
		0x2693558EABF416B2ULL,
		0xA8DDC212BCDB380FULL,
		0x000000000EFF13D0ULL,
		0x0000000000000000ULL
	}};
	shift = 36;
	printf("Test Case 44\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xC4274E395CA1D3D4ULL,
		0xC65F958947B2AE16ULL,
		0xF67C556087C80023ULL,
		0xB76AC713E112DF38ULL,
		0xA4BC4737C0308AA2ULL,
		0x33530DB8C93F48EDULL,
		0x97254BCDB861CCD2ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5B109D38E572874FULL,
		0x8F197E56251ECAB8ULL,
		0xE3D9F155821F2000ULL,
		0x8ADDAB1C4F844B7CULL,
		0xB692F11CDF00C22AULL,
		0x48CD4C36E324FD23ULL,
		0x025C952F36E18733ULL,
		0x0000000000000000ULL
	}};
	shift = 6;
	printf("Test Case 45\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x9F6C4667FA58C1B2ULL,
		0xCBEDD3E03C2C6FE9ULL,
		0x2A7A38CF0F8D6692ULL,
		0x687B0288E750E321ULL,
		0x3354DEC88C21F98BULL,
		0x7289E368BBB344CFULL,
		0x9B696618EECFDB87ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x03C2C6FE99F6C466ULL,
		0xF0F8D6692CBEDD3EULL,
		0x8E750E3212A7A38CULL,
		0x88C21F98B687B028ULL,
		0x8BBB344CF3354DECULL,
		0x8EECFDB877289E36ULL,
		0x0000000009B69661ULL,
		0x0000000000000000ULL
	}};
	shift = 36;
	printf("Test Case 46\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x9FC3D0AB2E7FFF6CULL,
		0xF8F28C23BB9F8E38ULL,
		0x7389A1960DB528BAULL,
		0x46B97B789BF821DFULL,
		0x00D831048B14430CULL,
		0x47CE20A81520977CULL,
		0xF63301BF62AA8999ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x11DDCFC71C4FE1E8ULL,
		0xCB06DA945D7C7946ULL,
		0xBC4DFC10EFB9C4D0ULL,
		0x82458A2186235CBDULL,
		0x540A904BBE006C18ULL,
		0xDFB15544CCA3E710ULL,
		0x00000000007B1980ULL,
		0x0000000000000000ULL
	}};
	shift = 41;
	printf("Test Case 47\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x036534BD917C4ED1ULL,
		0x9738308ADF7EB464ULL,
		0x9E79EBF20161448CULL,
		0x409500AECEAE9B25ULL,
		0x0ECF190F1073EEAFULL,
		0x47B2FDF76C0C6C23ULL,
		0xE541134EDDB4A5C0ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5BEFD68C806CA697ULL,
		0x402C289192E70611ULL,
		0xD9D5D364B3CF3D7EULL,
		0xE20E7DD5E812A015ULL,
		0xED818D8461D9E321ULL,
		0xDBB694B808F65FBEULL,
		0x000000001CA82269ULL,
		0x0000000000000000ULL
	}};
	shift = 35;
	printf("Test Case 48\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x6B83B249E2F0D1FFULL,
		0xAC9C0A95C9273D7AULL,
		0x887CB78BACE3F638ULL,
		0x7EE2A470A9A23ED7ULL,
		0xCB8CA25C75CCC0FEULL,
		0xF111417C537711EEULL,
		0x944F1B84033F6EB0ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x64E054AE4939EBD3ULL,
		0x43E5BC5D671FB1C5ULL,
		0xF71523854D11F6BCULL,
		0x5C6512E3AE6607F3ULL,
		0x888A0BE29BB88F76ULL,
		0xA278DC2019FB7587ULL,
		0x0000000000000004ULL,
		0x0000000000000000ULL
	}};
	shift = 61;
	printf("Test Case 49\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xA359441C94EBD8CDULL,
		0x48F6449480148CE9ULL,
		0xE703D69D16BC81DAULL,
		0x30AC04C32B220FBEULL,
		0x0B0C3758CDD6AF4FULL,
		0x0AF412522CBF851DULL,
		0xAB230C0B97EA93ECULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA400A4674D1ACA20ULL,
		0xE8B5E40ED247B224ULL,
		0x1959107DF7381EB4ULL,
		0xC66EB57A79856026ULL,
		0x9165FC28E85861BAULL,
		0x5CBF549F6057A092ULL,
		0x0000000005591860ULL,
		0x0000000000000000ULL
	}};
	shift = 37;
	printf("Test Case 50\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xB5DA9C16DBDBF287ULL,
		0x268BCA8088DEF01DULL,
		0xFE9DDF055EF5BF0DULL,
		0xD1C924C10D40BAB2ULL,
		0x90463AE72F04BFDCULL,
		0xE5B96BA993DA13DBULL,
		0xAC734481ED11C7CBULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x345E540446F780EDULL,
		0xF4EEF82AF7ADF869ULL,
		0x8E4926086A05D597ULL,
		0x8231D7397825FEE6ULL,
		0x2DCB5D4C9ED09EDCULL,
		0x639A240F688E3E5FULL,
		0x0000000000000005ULL,
		0x0000000000000000ULL
	}};
	shift = 61;
	printf("Test Case 51\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xA5AD45A0B3DBEA63ULL,
		0x6BE68CCDBB135C68ULL,
		0x8DBC50E08872A203ULL,
		0xAA2D45C798D2C20DULL,
		0xF198FDB9D041E415ULL,
		0x785359E375D89BE8ULL,
		0x928DB948AB0DA924ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6DD89AE3452D6A2DULL,
		0x044395101B5F3466ULL,
		0x3CC696106C6DE287ULL,
		0xCE820F20AD516A2EULL,
		0x1BAEC4DF478CC7EDULL,
		0x45586D4923C29ACFULL,
		0x0000000004946DCAULL,
		0x0000000000000000ULL
	}};
	shift = 37;
	printf("Test Case 52\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xC4C7474A3EF13F96ULL,
		0xE0BFF77A251D3933ULL,
		0xE44045BB07FE1003ULL,
		0xFA2F42641CC4A409ULL,
		0xB351FAD1E8215166ULL,
		0xD9CC8C5624A34290ULL,
		0x734150715E1634A1ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9E263A3A51F789FCULL,
		0x1F05FFBBD128E9C9ULL,
		0x4F22022DD83FF080ULL,
		0x37D17A1320E62520ULL,
		0x859A8FD68F410A8BULL,
		0x0ECE6462B1251A14ULL,
		0x039A0A838AF0B1A5ULL,
		0x0000000000000000ULL
	}};
	shift = 5;
	printf("Test Case 53\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x35B687A6F28275FAULL,
		0x130B3675BBD92A02ULL,
		0x674A29680E0941DDULL,
		0xE0FFB4F38729A698ULL,
		0xA4714F3457DCC44BULL,
		0x348A46947B39DB64ULL,
		0xFF35247A95B3A08AULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x235B687A6F28275FULL,
		0xD130B3675BBD92A0ULL,
		0x8674A29680E0941DULL,
		0xBE0FFB4F38729A69ULL,
		0x4A4714F3457DCC44ULL,
		0xA348A46947B39DB6ULL,
		0x0FF35247A95B3A08ULL,
		0x0000000000000000ULL
	}};
	shift = 4;
	printf("Test Case 54\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xF404AC3F999207A4ULL,
		0x055FD362115AB6D5ULL,
		0xE2B6761C75AA8C3CULL,
		0x3CD31963E936164FULL,
		0x25D58F28ADE3CF44ULL,
		0x5A984CCB254DD592ULL,
		0xFB9802FAAA3019D5ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x362115AB6D5F404AULL,
		0x61C75AA8C3C055FDULL,
		0x963E936164FE2B67ULL,
		0xF28ADE3CF443CD31ULL,
		0xCCB254DD59225D58ULL,
		0x2FAAA3019D55A984ULL,
		0x00000000000FB980ULL,
		0x0000000000000000ULL
	}};
	shift = 44;
	printf("Test Case 55\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x2F79DD44967E5D53ULL,
		0xC891C0C57799FDFEULL,
		0x5878F34A63833A1FULL,
		0x88E4402650029856ULL,
		0x753796E95D0F02EDULL,
		0x7BECF5F61E6B7E3AULL,
		0xA2AFE356CB6C3908ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBBCCFEFF17BCEEA2ULL,
		0x31C19D0FE448E062ULL,
		0x28014C2B2C3C79A5ULL,
		0xAE878176C4722013ULL,
		0x0F35BF1D3A9BCB74ULL,
		0x65B61C843DF67AFBULL,
		0x000000005157F1ABULL,
		0x0000000000000000ULL
	}};
	shift = 33;
	printf("Test Case 56\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0BB22146E0889AACULL,
		0x1B34500687228BE2ULL,
		0x5B5D2FEAEB1DA627ULL,
		0xA296358154D92DB2ULL,
		0xCBB94AC250D61AEFULL,
		0x33F448E50B1F94F7ULL,
		0x9E19281BF6EF7325ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x803439145F105D91ULL,
		0x7F5758ED3138D9A2ULL,
		0xAC0AA6C96D92DAE9ULL,
		0x561286B0D77D14B1ULL,
		0x472858FCA7BE5DCAULL,
		0x40DFB77B99299FA2ULL,
		0x000000000004F0C9ULL,
		0x0000000000000000ULL
	}};
	shift = 45;
	printf("Test Case 57\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x6346087711D44A38ULL,
		0x2B99C9207B396C4AULL,
		0xF6F7C19AE768C03FULL,
		0x3725CFB38F553A9AULL,
		0x31FCFA1D60F9714FULL,
		0x2E9286E9A44DB210ULL,
		0xEA799691843130B3ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD894C68C10EE23A8ULL,
		0x807E57339240F672ULL,
		0x7535EDEF8335CED1ULL,
		0xE29E6E4B9F671EAAULL,
		0x642063F9F43AC1F2ULL,
		0x61665D250DD3489BULL,
		0x0001D4F32D230862ULL,
		0x0000000000000000ULL
	}};
	shift = 15;
	printf("Test Case 58\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x495E58330A319FF0ULL,
		0xD43A0BB3473737FEULL,
		0xE968D10AA97C4265ULL,
		0x170CDAA1FC675F92ULL,
		0xF120C024E0080002ULL,
		0x6667504C718A7088ULL,
		0xB4D0B9585DFF53B8ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x495E58330A319FF0ULL,
		0xD43A0BB3473737FEULL,
		0xE968D10AA97C4265ULL,
		0x170CDAA1FC675F92ULL,
		0xF120C024E0080002ULL,
		0x6667504C718A7088ULL,
		0xB4D0B9585DFF53B8ULL,
		0x0000000000000000ULL
	}};
	shift = 0;
	printf("Test Case 59\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xD6A2A31DE7FF6A16ULL,
		0x765C7D17F35DE6A3ULL,
		0xB584023B9EF4BFE2ULL,
		0x8097C351589A26BEULL,
		0x866DF2D35973574BULL,
		0x840472EDF288F680ULL,
		0xC5470490B43B3A4DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6BBCD47AD45463BCULL,
		0xDE97FC4ECB8FA2FEULL,
		0x1344D7D6B0804773ULL,
		0x2E6AE97012F86A2BULL,
		0x511ED010CDBE5A6BULL,
		0x876749B0808E5DBEULL,
		0x00000018A8E09216ULL,
		0x0000000000000000ULL
	}};
	shift = 27;
	printf("Test Case 60\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x4E71647EE4F69C12ULL,
		0x508A9984A2BEECFCULL,
		0xED7ADB324E09F55BULL,
		0xD8AD8BAA15E2A690ULL,
		0xB220A25739DC3902ULL,
		0x4F011EAD21F6A83BULL,
		0x6A7C29E6D2968B65ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9457DD9F89CE2C8FULL,
		0x49C13EAB6A115330ULL,
		0x42BC54D21DAF5B66ULL,
		0xE73B87205B15B175ULL,
		0xA43ED5077644144AULL,
		0xDA52D16CA9E023D5ULL,
		0x000000000D4F853CULL,
		0x0000000000000000ULL
	}};
	shift = 35;
	printf("Test Case 61\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xD892439F3BE91E43ULL,
		0xFD87635C6FA43DE5ULL,
		0x0B6FE40EE1263AA7ULL,
		0xA6DA4329BBCE268DULL,
		0xB2F22DF9FDBA94D5ULL,
		0x1F58DEE48B7824E2ULL,
		0xB95C40C2D33E70F8ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEC3B1AE37D21EF2EULL,
		0x5B7F20770931D53FULL,
		0x36D2194DDE713468ULL,
		0x97916FCFEDD4A6ADULL,
		0xFAC6F7245BC12715ULL,
		0xCAE2061699F387C0ULL,
		0x0000000000000005ULL,
		0x0000000000000000ULL
	}};
	shift = 61;
	printf("Test Case 62\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x626C8E1D3C12A1AEULL,
		0x6AA29346601E9A97ULL,
		0xD59992EA8724AF04ULL,
		0x3614BB47CC88B120ULL,
		0xAFDE51F1BAB2C991ULL,
		0x0E132A63E9305FC5ULL,
		0x8AC980BA4E4533D5ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x01E9A97626C8E1D3ULL,
		0x724AF046AA293466ULL,
		0xC88B120D59992EA8ULL,
		0xAB2C9913614BB47CULL,
		0x9305FC5AFDE51F1BULL,
		0xE4533D50E132A63EULL,
		0x00000008AC980BA4ULL,
		0x0000000000000000ULL
	}};
	shift = 28;
	printf("Test Case 63\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x1AD2CBBC16EB367EULL,
		0x387643E531F18338ULL,
		0xB20826412F2D8567ULL,
		0x99F408391D571D4DULL,
		0x181DCC392BE72BD5ULL,
		0xF4D2F41D05AA60D9ULL,
		0xB42536459F238ED8ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3B21F298F8C19C0DULL,
		0x0413209796C2B39CULL,
		0xFA041C8EAB8EA6D9ULL,
		0x0EE61C95F395EACCULL,
		0x697A0E82D5306C8CULL,
		0x129B22CF91C76C7AULL,
		0x000000000000005AULL,
		0x0000000000000000ULL
	}};
	shift = 57;
	printf("Test Case 64\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x29CA0D7D869A412AULL,
		0x03A116159A628C95ULL,
		0x3E1A19086576DCDEULL,
		0x4FAE1B76A033DDE2ULL,
		0x3D17A3D681CC3ACFULL,
		0xE2499D78ECB84D28ULL,
		0x7B442D4A08917CD7ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8B0ACD31464A94E5ULL,
		0x0C8432BB6E6F01D0ULL,
		0x0DBB5019EEF11F0DULL,
		0xD1EB40E61D67A7D7ULL,
		0xCEBC765C26941E8BULL,
		0x16A50448BE6BF124ULL,
		0x0000000000003DA2ULL,
		0x0000000000000000ULL
	}};
	shift = 49;
	printf("Test Case 65\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x7C1B9396B8AAAFBCULL,
		0x92524BBB5FCCB1E5ULL,
		0x6D33813669582E14ULL,
		0x917EB97140E6BAAAULL,
		0x67E394A61529211DULL,
		0x775113D01A5A570EULL,
		0x45F7D010A2552F15ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6BF9963CAF837272ULL,
		0xCD2B05C2924A4977ULL,
		0x281CD7554DA67026ULL,
		0xC2A52423B22FD72EULL,
		0x034B4AE1CCFC7294ULL,
		0x144AA5E2AEEA227AULL,
		0x0000000008BEFA02ULL,
		0x0000000000000000ULL
	}};
	shift = 35;
	printf("Test Case 66\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x26D6077895C5E9E2ULL,
		0x174067841FAD8C66ULL,
		0xC2BFC01A057FEAABULL,
		0xE5D524BDE45BB094ULL,
		0xD6C0F6B577D56193ULL,
		0x39D6B7ED8282D3F3ULL,
		0x29AED3AB210E6374ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0FD6C633136B03BCULL,
		0x02BFF5558BA033C2ULL,
		0xF22DD84A615FE00DULL,
		0xBBEAB0C9F2EA925EULL,
		0xC14169F9EB607B5AULL,
		0x908731BA1CEB5BF6ULL,
		0x0000000014D769D5ULL,
		0x0000000000000000ULL
	}};
	shift = 33;
	printf("Test Case 67\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x695D985C8E3449D2ULL,
		0xDA73936577A25941ULL,
		0x18A59FDF57CEFE73ULL,
		0x6F1475315CC431E7ULL,
		0xC786671166079442ULL,
		0xCD371EFDD04D86D4ULL,
		0xE6A0EEF068161181ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCA0B4AECC2E471A2ULL,
		0xF39ED39C9B2BBD12ULL,
		0x8F38C52CFEFABE77ULL,
		0xA21378A3A98AE621ULL,
		0x36A63C33388B303CULL,
		0x8C0E69B8F7EE826CULL,
		0x00073507778340B0ULL,
		0x0000000000000000ULL
	}};
	shift = 13;
	printf("Test Case 68\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0F7D9F4F15E9C5C8ULL,
		0x766BE290DF9EDF1BULL,
		0x9D7371AFAF560A40ULL,
		0xD3D41DA031D85625ULL,
		0x18E33A3C7DFAE63DULL,
		0xA1A682B1199C15B2ULL,
		0xB7B8AFB464ACD01CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9AF8A437E7B7C6C3ULL,
		0x5CDC6BEBD582901DULL,
		0xF507680C76158967ULL,
		0x38CE8F1F7EB98F74ULL,
		0x69A0AC4667056C86ULL,
		0xEE2BED192B340728ULL,
		0x000000000000002DULL,
		0x0000000000000000ULL
	}};
	shift = 58;
	printf("Test Case 69\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x1BEEBD1FFE4FB5F2ULL,
		0x94A6AF36D1E9C297ULL,
		0x806F3E58F3B93523ULL,
		0x71BA6CE392DE9EFBULL,
		0xC329091463367DBEULL,
		0xEBBB02E65B08A7E9ULL,
		0x6A35796547EFDB01ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF4E14B8DF75E8FFFULL,
		0xDC9A91CA53579B68ULL,
		0x6F4F7DC0379F2C79ULL,
		0x9B3EDF38DD3671C9ULL,
		0x8453F4E194848A31ULL,
		0xF7ED80F5DD81732DULL,
		0x000000351ABCB2A3ULL,
		0x0000000000000000ULL
	}};
	shift = 25;
	printf("Test Case 70\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x6D1FA99BC92E46A4ULL,
		0x6ABBE9ECD6021F3EULL,
		0x10CB50921174CEF1ULL,
		0x1683E0BB766D18F5ULL,
		0x9D8228733716EB64ULL,
		0x0DCBA189A7B5773CULL,
		0x3FF840722D70E7ADULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCF9B47EA66F24B91ULL,
		0xBC5AAEFA7B358087ULL,
		0x3D4432D424845D33ULL,
		0xD905A0F82EDD9B46ULL,
		0xCF27608A1CCDC5BAULL,
		0xEB4372E86269ED5DULL,
		0x000FFE101C8B5C39ULL,
		0x0000000000000000ULL
	}};
	shift = 10;
	printf("Test Case 71\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x61D43BA0A2ECC412ULL,
		0x4193E874457EF079ULL,
		0x34AA5A70EC1927E5ULL,
		0xB88225C0AAE4B12BULL,
		0xA64EA04AB924EB99ULL,
		0xD966D808A2DE40D7ULL,
		0x2D02DEF2D75745E8ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x74457EF07961D43BULL,
		0x70EC1927E54193E8ULL,
		0xC0AAE4B12B34AA5AULL,
		0x4AB924EB99B88225ULL,
		0x08A2DE40D7A64EA0ULL,
		0xF2D75745E8D966D8ULL,
		0x00000000002D02DEULL,
		0x0000000000000000ULL
	}};
	shift = 40;
	printf("Test Case 72\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x3A44E03B401A65BEULL,
		0xE1F4CF58DE64CFC0ULL,
		0xE7E68FFCE731DE80ULL,
		0x66BBF2A7D8CDBBB3ULL,
		0x256F76D0D23E72D6ULL,
		0xD75F0CBD7CCA2D25ULL,
		0xC7CC816FB6BCDF48ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC6F3267E01D22701ULL,
		0xE7398EF4070FA67AULL,
		0x3EC66DDD9F3F347FULL,
		0x8691F396B335DF95ULL,
		0xEBE65169292B7BB6ULL,
		0x7DB5E6FA46BAF865ULL,
		0x00000000063E640BULL,
		0x0000000000000000ULL
	}};
	shift = 37;
	printf("Test Case 73\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x416E394CFA49FC6DULL,
		0x9CB0CDF939A3002EULL,
		0x45004618E0FDF296ULL,
		0x56F96C2ECF299723ULL,
		0x60229C31BF8DE581ULL,
		0x0A722EF9BCA693FDULL,
		0xE0E17433AAEB3EA2ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x720B71CA67D24FE3ULL,
		0xB4E5866FC9CD1801ULL,
		0x1A280230C707EF94ULL,
		0x0AB7CB6176794CB9ULL,
		0xEB0114E18DFC6F2CULL,
		0x10539177CDE5349FULL,
		0x07070BA19D5759F5ULL,
		0x0000000000000000ULL
	}};
	shift = 5;
	printf("Test Case 74\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x9CB8396BF936E74AULL,
		0x1B249FAB42020624ULL,
		0xF9C0BB5D64F9BC1FULL,
		0x00BA28004DFFB2C8ULL,
		0xA6B790E3A8660D26ULL,
		0xE3FBE159B086F1C8ULL,
		0x93E6B2F9EA1A8B24ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFD5A10103124E5C1ULL,
		0xDAEB27CDE0F8D924ULL,
		0x40026FFD9647CE05ULL,
		0x871D4330693005D1ULL,
		0x0ACD84378E4535BCULL,
		0x97CF50D459271FDFULL,
		0x0000000000049F35ULL,
		0x0000000000000000ULL
	}};
	shift = 45;
	printf("Test Case 75\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xFEF963C4DFC7518EULL,
		0xD28E50F0986EB8C1ULL,
		0x2DD1A0B15B371C1EULL,
		0x74DFBF677C560E60ULL,
		0xF346AAAE6A0CE762ULL,
		0xB2C657E5DC3F8CA7ULL,
		0xB6D3CD2999245077ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE50F0986EB8C1FEFULL,
		0x1A0B15B371C1ED28ULL,
		0xFBF677C560E602DDULL,
		0x6AAAE6A0CE76274DULL,
		0x657E5DC3F8CA7F34ULL,
		0x3CD2999245077B2CULL,
		0x0000000000000B6DULL,
		0x0000000000000000ULL
	}};
	shift = 52;
	printf("Test Case 76\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x7797F7C0F04766ECULL,
		0x97581DFA5313EAC4ULL,
		0xED31A8099BBB6299ULL,
		0x232993DCBB98A662ULL,
		0x6275AFC4E0EFDCA4ULL,
		0x5A374B7964C26F97ULL,
		0x7ADCBFECB5DA9EEEULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8EF2FEF81E08ECDDULL,
		0x32EB03BF4A627D58ULL,
		0x5DA6350133776C53ULL,
		0x8465327B977314CCULL,
		0xEC4EB5F89C1DFB94ULL,
		0xCB46E96F2C984DF2ULL,
		0x0F5B97FD96BB53DDULL,
		0x0000000000000000ULL
	}};
	shift = 3;
	printf("Test Case 77\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xDA9F6071591528E3ULL,
		0x544F86898FF9D0EFULL,
		0x73F24AE1096D8C33ULL,
		0x9CD446959B571C9CULL,
		0x2B583DDCB1A942D1ULL,
		0x4749A77436B9E89FULL,
		0xF79E62EF1B9BDBABULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF0D131FF3A1DFB53ULL,
		0x495C212DB1866A89ULL,
		0x88D2B36AE3938E7EULL,
		0x07BB9635285A339AULL,
		0x34EE86D73D13E56BULL,
		0xCC5DE3737B7568E9ULL,
		0x0000000000001EF3ULL,
		0x0000000000000000ULL
	}};
	shift = 51;
	printf("Test Case 78\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x16553EAA17A4E9BDULL,
		0x9B4CEF2AA05AEDE4ULL,
		0x07F5F5E7AD16914DULL,
		0x004769C1C7A3155EULL,
		0xF68E9934A5683525ULL,
		0xC223830A12B68112ULL,
		0x1C221EE8ABDE4458ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6D33BCAA816BB790ULL,
		0x1FD7D79EB45A4536ULL,
		0x011DA7071E8C5578ULL,
		0xDA3A64D295A0D494ULL,
		0x088E0C284ADA044BULL,
		0x70887BA2AF791163ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 62;
	printf("Test Case 79\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x5FDB6AA7F95246FEULL,
		0x87D506B80AC986CAULL,
		0xE923E4B5F2111DFAULL,
		0x21542F4DA21F8BDCULL,
		0x9510F0C2CDD0ECD8ULL,
		0xA38EE0938B0F7906ULL,
		0x05F4D93D2DA69530ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAC986CA5FDB6AA7FULL,
		0x2111DFA87D506B80ULL,
		0x21F8BDCE923E4B5FULL,
		0xDD0ECD821542F4DAULL,
		0xB0F79069510F0C2CULL,
		0xDA69530A38EE0938ULL,
		0x000000005F4D93D2ULL,
		0x0000000000000000ULL
	}};
	shift = 28;
	printf("Test Case 80\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xB5B6DDE0BA310FECULL,
		0x9BB74A50C7E0B72CULL,
		0xB53C059FE3A611F0ULL,
		0x900370B2CD105C4AULL,
		0xF4E55D06B977863CULL,
		0x108659A405F492A1ULL,
		0xCB20148EF698899DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x74A50C7E0B72CB5BULL,
		0xC059FE3A611F09BBULL,
		0x370B2CD105C4AB53ULL,
		0x55D06B977863C900ULL,
		0x659A405F492A1F4EULL,
		0x0148EF698899D108ULL,
		0x0000000000000CB2ULL,
		0x0000000000000000ULL
	}};
	shift = 52;
	printf("Test Case 81\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xD8DB3F02A422D106ULL,
		0x260589144BE6518EULL,
		0x62385F1622E9084EULL,
		0x2FA3384640222CD3ULL,
		0x2484252569BEF089ULL,
		0x8BD4ADF8E58D62F7ULL,
		0xF8E91F093C3557E2ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCA31DB1B67E05484ULL,
		0x2109C4C0B122897CULL,
		0x459A6C470BE2C45DULL,
		0xDE1125F46708C804ULL,
		0xAC5EE49084A4AD37ULL,
		0xAAFC517A95BF1CB1ULL,
		0x00001F1D23E12786ULL,
		0x0000000000000000ULL
	}};
	shift = 19;
	printf("Test Case 82\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x9D5F5AA48FE30E40ULL,
		0xD322054B018DC51BULL,
		0x72AE50689EAD813AULL,
		0x15E8E2F82A04126CULL,
		0x9E701F8D4DE82CBBULL,
		0x8B1203C2F06D6910ULL,
		0xFBEB5AF4061035F3ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6440A96031B8A373ULL,
		0x55CA0D13D5B0275AULL,
		0xBD1C5F0540824D8EULL,
		0xCE03F1A9BD059762ULL,
		0x6240785E0DAD2213ULL,
		0x7D6B5E80C206BE71ULL,
		0x000000000000001FULL,
		0x0000000000000000ULL
	}};
	shift = 59;
	printf("Test Case 83\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xDC69A75F643798CBULL,
		0xE61994A8789FE344ULL,
		0xF96EFD5BE446D696ULL,
		0xE560646715A2A1E3ULL,
		0x46B13BA93F128763ULL,
		0x159AA1C7FDA8E038ULL,
		0x3824649DBE9E434EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF13FC689B8D34EBEULL,
		0xC88DAD2DCC332950ULL,
		0x2B4543C7F2DDFAB7ULL,
		0x7E250EC7CAC0C8CEULL,
		0xFB51C0708D627752ULL,
		0x7D3C869C2B35438FULL,
		0x000000007048C93BULL,
		0x0000000000000000ULL
	}};
	shift = 31;
	printf("Test Case 84\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x3616DFE58A59DAADULL,
		0xD1F0C814FD818742ULL,
		0x6D24480C1BAE38DDULL,
		0x037B6F80FBB7325EULL,
		0xFABD642B6ABE851BULL,
		0xEAA1C8CCE7EEB63BULL,
		0x747E85A049440ABFULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x11B0B6FF2C52CED5ULL,
		0xEE8F8640A7EC0C3AULL,
		0xF369224060DD71C6ULL,
		0xD81BDB7C07DDB992ULL,
		0xDFD5EB215B55F428ULL,
		0xFF550E46673F75B1ULL,
		0x03A3F42D024A2055ULL,
		0x0000000000000000ULL
	}};
	shift = 5;
	printf("Test Case 85\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x4E5E8C65315BC2A4ULL,
		0x25BE7523CC534C35ULL,
		0xD5FDF59E1104DB40ULL,
		0xC360A0BE980F237BULL,
		0x630AAF176BF62C4AULL,
		0xCE2AAF82387F9DDFULL,
		0x685300D6D51002BAULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x534C354E5E8C6531ULL,
		0x04DB4025BE7523CCULL,
		0x0F237BD5FDF59E11ULL,
		0xF62C4AC360A0BE98ULL,
		0x7F9DDF630AAF176BULL,
		0x1002BACE2AAF8238ULL,
		0x000000685300D6D5ULL,
		0x0000000000000000ULL
	}};
	shift = 24;
	printf("Test Case 86\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x49706A95EC1792B8ULL,
		0x9AB6FF501619DF3FULL,
		0x4040042CFE732568ULL,
		0xF3FE91137EC969DBULL,
		0xC4F15E0F9DD1927CULL,
		0x1BBD946462FB10ADULL,
		0x4D2A6753D5CC0BF3ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBE7E92E0D52BD82FULL,
		0x4AD1356DFEA02C33ULL,
		0xD3B680800859FCE6ULL,
		0x24F9E7FD2226FD92ULL,
		0x215B89E2BC1F3BA3ULL,
		0x17E6377B28C8C5F6ULL,
		0x00009A54CEA7AB98ULL,
		0x0000000000000000ULL
	}};
	shift = 15;
	printf("Test Case 87\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xD8501B525F282203ULL,
		0x3BB8A70BC6114385ULL,
		0xAD414AE4E06BC7F4ULL,
		0xFA0C17259E81ECD8ULL,
		0x0C60A3DED6CBB5B5ULL,
		0x63C9D5C4FF93FAFBULL,
		0xC4DCBA58A67C866AULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5385E308A1C2EC28ULL,
		0xA5727035E3FA1DDCULL,
		0x0B92CF40F66C56A0ULL,
		0x51EF6B65DADAFD06ULL,
		0xEAE27FC9FD7D8630ULL,
		0x5D2C533E433531E4ULL,
		0x000000000000626EULL,
		0x0000000000000000ULL
	}};
	shift = 49;
	printf("Test Case 88\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x1823A5E423E22CC3ULL,
		0x8ABA9440AAF61C96ULL,
		0x67AF6D780082B470ULL,
		0x42946A99F0630F4EULL,
		0x111B7D9425E14491ULL,
		0x1A0D0991D5785A61ULL,
		0x70A3E2A4FCE638FAULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAAF61C961823A5E4ULL,
		0x0082B4708ABA9440ULL,
		0xF0630F4E67AF6D78ULL,
		0x25E1449142946A99ULL,
		0xD5785A61111B7D94ULL,
		0xFCE638FA1A0D0991ULL,
		0x0000000070A3E2A4ULL,
		0x0000000000000000ULL
	}};
	shift = 32;
	printf("Test Case 89\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xD95DD1149D6342FAULL,
		0x547708445EA8D493ULL,
		0x169F100645952B05ULL,
		0x0BBFE1F3FD36C00FULL,
		0xCEB4788E59B8946CULL,
		0x7C82BCE2EE86EB2EULL,
		0x34CF11DE70229ADCULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6A49ECAEE88A4EB1ULL,
		0x9582AA3B84222F54ULL,
		0x60078B4F880322CAULL,
		0x4A3605DFF0F9FE9BULL,
		0x7597675A3C472CDCULL,
		0x4D6E3E415E717743ULL,
		0x00001A6788EF3811ULL,
		0x0000000000000000ULL
	}};
	shift = 17;
	printf("Test Case 90\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x817E469F709FD674ULL,
		0x8470F87A5C25ED1DULL,
		0xFDE7424A782093E4ULL,
		0xFEF5C937477AC6FAULL,
		0x22ECCDF15137E4CEULL,
		0x8C7C5D04F875E96DULL,
		0x218E3358B55B6EDEULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA3B02FC8D3EE13FAULL,
		0x7C908E1F0F4B84BDULL,
		0xDF5FBCE8494F0412ULL,
		0x99DFDEB926E8EF58ULL,
		0x2DA45D99BE2A26FCULL,
		0xDBD18F8BA09F0EBDULL,
		0x000431C66B16AB6DULL,
		0x0000000000000000ULL
	}};
	shift = 11;
	printf("Test Case 91\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xB003FD3B5B2055FBULL,
		0x27F0F84FAFC12BB0ULL,
		0x5267D0A58A9E993BULL,
		0xBA158B8A60B39EC3ULL,
		0xB381080385B467D0ULL,
		0x4355BB37A78B2AD5ULL,
		0x231A9ED7075EA6B0ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC3E13EBF04AEC2C0ULL,
		0x9F42962A7A64EC9FULL,
		0x562E2982CE7B0D49ULL,
		0x04200E16D19F42E8ULL,
		0x56ECDE9E2CAB56CEULL,
		0x6A7B5C1D7A9AC10DULL,
		0x000000000000008CULL,
		0x0000000000000000ULL
	}};
	shift = 54;
	printf("Test Case 92\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0A9EF8CB1664A139ULL,
		0x560411C1E042451EULL,
		0xF772902EB6A3E536ULL,
		0xCBAA60316C0414E3ULL,
		0xB2FD93699E37CC5BULL,
		0x25E072D2204A9255ULL,
		0xEFF749B839ED2FF0ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0A9EF8CB1664A139ULL,
		0x560411C1E042451EULL,
		0xF772902EB6A3E536ULL,
		0xCBAA60316C0414E3ULL,
		0xB2FD93699E37CC5BULL,
		0x25E072D2204A9255ULL,
		0xEFF749B839ED2FF0ULL,
		0x0000000000000000ULL
	}};
	shift = 0;
	printf("Test Case 93\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x55D26F96E6BFFF8BULL,
		0x5ACCBAFAE9EE1D6BULL,
		0xE44E094127AE9E42ULL,
		0xA9624FD97B831D68ULL,
		0x880F65B354A19628ULL,
		0xD3C23FD9056198FEULL,
		0x68AB4751E5F411EEULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB5AAE937CB735FFFULL,
		0x212D665D7D74F70EULL,
		0xB4722704A093D74FULL,
		0x1454B127ECBDC18EULL,
		0x7F4407B2D9AA50CBULL,
		0xF769E11FEC82B0CCULL,
		0x003455A3A8F2FA08ULL,
		0x0000000000000000ULL
	}};
	shift = 9;
	printf("Test Case 94\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xD84C2DD2874346D9ULL,
		0xA514CC5C45352D7DULL,
		0x65FF1910456E2B58ULL,
		0x1CC9D25E3C28536AULL,
		0x63CC1298D1EE25C6ULL,
		0xFADF914C29219416ULL,
		0xAFF972EE3F0B33DDULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8A662E229A96BEECULL,
		0xFF8C8822B715AC52ULL,
		0x64E92F1E1429B532ULL,
		0xE6094C68F712E30EULL,
		0x6FC8A61490CA0B31ULL,
		0xFCB9771F8599EEFDULL,
		0x0000000000000057ULL,
		0x0000000000000000ULL
	}};
	shift = 57;
	printf("Test Case 95\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xC824F0FC18A7A799ULL,
		0x72DC00B150D12446ULL,
		0x5037B1B3DEAAB462ULL,
		0xA3C8EB59DF765232ULL,
		0xA5C04E90B74FD297ULL,
		0xEDBEA9407FCDF76DULL,
		0xC5726DD8FB3A9FF2ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1B2093C3F0629E9EULL,
		0x89CB7002C5434491ULL,
		0xC940DEC6CF7AAAD1ULL,
		0x5E8F23AD677DD948ULL,
		0xB697013A42DD3F4AULL,
		0xCBB6FAA501FF37DDULL,
		0x0315C9B763ECEA7FULL,
		0x0000000000000000ULL
	}};
	shift = 6;
	printf("Test Case 96\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0EF96B2CE8C3028CULL,
		0xCC82F4C29DF87F3FULL,
		0x5D434C7C514C0DFEULL,
		0x0F1DADD29B4B77A0ULL,
		0x361A05A18D23BCC2ULL,
		0xA1BD5FEA6F05E6CFULL,
		0x1BF7483C67B856A6ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0FE7E1DF2D659D18ULL,
		0x81BFD9905E9853BFULL,
		0x6EF40BA8698F8A29ULL,
		0x779841E3B5BA5369ULL,
		0xBCD9E6C340B431A4ULL,
		0x0AD4D437ABFD4DE0ULL,
		0x0000037EE9078CF7ULL,
		0x0000000000000000ULL
	}};
	shift = 19;
	printf("Test Case 97\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xCCB9C9FB4C0BAEF6ULL,
		0xFDF9AACD30BA361AULL,
		0xA1328E80F5C4F35EULL,
		0x26F19DCA9AC96041ULL,
		0x3E962B55AD2E1193ULL,
		0x5A0BD4C9302422F1ULL,
		0x4CA594674740FB46ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAB34C2E8D86B32E7ULL,
		0x3A03D713CD7BF7E6ULL,
		0x772A6B25810684CAULL,
		0xAD56B4B8464C9BC6ULL,
		0x5324C0908BC4FA58ULL,
		0x519D1D03ED19682FULL,
		0x0000000000013296ULL,
		0x0000000000000000ULL
	}};
	shift = 46;
	printf("Test Case 98\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xCC597E676CF79124ULL,
		0x478733BBF38582C0ULL,
		0x396A5E94198FAE01ULL,
		0x6442A35058BDBE7DULL,
		0x090FA856CE419399ULL,
		0xEC14D9597B27ED90ULL,
		0x22F3D4F0B35226ABULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCE160B033165F99DULL,
		0x663EB8051E1CCEEFULL,
		0x62F6F9F4E5A97A50ULL,
		0x39064E65910A8D41ULL,
		0xEC9FB640243EA15BULL,
		0xCD489AAFB0536565ULL,
		0x000000008BCF53C2ULL,
		0x0000000000000000ULL
	}};
	shift = 30;
	printf("Test Case 99\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x55C7088B622D8616ULL,
		0x3F3320BE6A4B6633ULL,
		0x065C1DE7AD346C56ULL,
		0x05992B4DA3D16BB5ULL,
		0xA665A351A5785E14ULL,
		0x56BCCDA6CA6BACBBULL,
		0xE8D08A2CE3D1C206ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x496CC66AB8E1116CULL,
		0xA68D8AC7E66417CDULL,
		0x7A2D76A0CB83BCF5ULL,
		0xAF0BC280B32569B4ULL,
		0x4D759774CCB46A34ULL,
		0x7A3840CAD799B4D9ULL,
		0x0000001D1A11459CULL,
		0x0000000000000000ULL
	}};
	shift = 27;
	printf("Test Case 100\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x5842E60C88523F21ULL,
		0xD8347DACBC807C81ULL,
		0xC51A552943F572DCULL,
		0x0D245BFF5ABA381CULL,
		0xA4D338982E4C57C3ULL,
		0xAB48D806902F860FULL,
		0x36D248FDE8CA3FC9ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF6B2F201F205610BULL,
		0x54A50FD5CB7360D1ULL,
		0x6FFD6AE8E0731469ULL,
		0xE260B9315F0C3491ULL,
		0x601A40BE183E934CULL,
		0x23F7A328FF26AD23ULL,
		0x000000000000DB49ULL,
		0x0000000000000000ULL
	}};
	shift = 46;
	printf("Test Case 101\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x1F468170C28070ABULL,
		0xAD923505BD9133BBULL,
		0xA500B0E72EE6AA02ULL,
		0x686639B05D49AA22ULL,
		0x03E58C4E54D9B7A6ULL,
		0x5EB7575554B10471ULL,
		0xFA4A682DF84E3E9FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDD8FA340B8614038ULL,
		0x0156C91A82DEC899ULL,
		0x1152805873977355ULL,
		0xD334331CD82EA4D5ULL,
		0x3881F2C6272A6CDBULL,
		0x4FAF5BABAAAA5882ULL,
		0x007D253416FC271FULL,
		0x0000000000000000ULL
	}};
	shift = 9;
	printf("Test Case 102\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xAE69993966427BD0ULL,
		0x8C63BF69F27CDE3FULL,
		0x6747F54F59B003BEULL,
		0x9796B261FEE3FDE4ULL,
		0xC520B756A98985B5ULL,
		0x654EEB00E01739E4ULL,
		0x754204EB60303180ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFB4F93E6F1FD734CULL,
		0xAA7ACD801DF4631DULL,
		0x930FF71FEF233A3FULL,
		0xBAB54C4C2DACBCB5ULL,
		0x580700B9CF262905ULL,
		0x275B01818C032A77ULL,
		0x000000000003AA10ULL,
		0x0000000000000000ULL
	}};
	shift = 45;
	printf("Test Case 103\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x3721109274F539D3ULL,
		0xD89062799319086DULL,
		0x2D8822066FCB5DFFULL,
		0xA2771D61859B50E6ULL,
		0xC0ACD3488DDE52EBULL,
		0xF4F4454BE2F53DEBULL,
		0x1AA65D73E928F325ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8C84369B9088493AULL,
		0xE5AEFFEC48313CC9ULL,
		0xCDA87316C4110337ULL,
		0xEF2975D13B8EB0C2ULL,
		0x7A9EF5E05669A446ULL,
		0x947992FA7A22A5F1ULL,
		0x0000000D532EB9F4ULL,
		0x0000000000000000ULL
	}};
	shift = 25;
	printf("Test Case 104\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xEA27D40D4D3EAFECULL,
		0xECA7DEEC444EBDB0ULL,
		0xD674AAE6EA374763ULL,
		0x638865760B6E563DULL,
		0x600CD9BD0F4C2CB8ULL,
		0x332075C452C8924BULL,
		0x2C90A330050D3069ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9D7B61D44FA81A9AULL,
		0x6E8EC7D94FBDD888ULL,
		0xDCAC7BACE955CDD4ULL,
		0x985970C710CAEC16ULL,
		0x912496C019B37A1EULL,
		0x1A60D26640EB88A5ULL,
		0x000000592146600AULL,
		0x0000000000000000ULL
	}};
	shift = 23;
	printf("Test Case 105\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x907A51EBB85166D9ULL,
		0xD05699AFFB4C2DE9ULL,
		0x93915368942DB0F8ULL,
		0x2D7EB8F870B2E490ULL,
		0xC0C418AB98E173D3ULL,
		0x4C1FB4A2FCE43368ULL,
		0xBDD97F50AC206539ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFDA616F4C83D28F5ULL,
		0x4A16D87C682B4CD7ULL,
		0x3859724849C8A9B4ULL,
		0xCC70B9E996BF5C7CULL,
		0x7E7219B460620C55ULL,
		0x5610329CA60FDA51ULL,
		0x000000005EECBFA8ULL,
		0x0000000000000000ULL
	}};
	shift = 33;
	printf("Test Case 106\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x209D9B16AA3192CCULL,
		0x465915396DAAF66DULL,
		0x0F1B8420907D0D44ULL,
		0x64508B465E2E439CULL,
		0x9FE2BEC5283A50A3ULL,
		0x54BE2DED97E7B5C4ULL,
		0xF80F51AC6B1DF97DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA9CB6D57B36904ECULL,
		0x210483E86A2232C8ULL,
		0x5A32F1721CE078DCULL,
		0xF62941D2851B2284ULL,
		0x6F6CBF3DAE24FF15ULL,
		0x8D6358EFCBEAA5F1ULL,
		0x000000000007C07AULL,
		0x0000000000000000ULL
	}};
	shift = 45;
	printf("Test Case 107\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x1BBE43A1E60F9B65ULL,
		0x4274700DCE340EC0ULL,
		0x4C0E6A2F9C918F8CULL,
		0xAFFBCEBCAC44979CULL,
		0x213A835EFE73DE6CULL,
		0xF64AEF93E40B1407ULL,
		0x9F4026013606BA10ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0377C8743CC1F36CULL,
		0x884E8E01B9C681D8ULL,
		0x8981CD45F39231F1ULL,
		0x95FF79D7958892F3ULL,
		0xE427506BDFCE7BCDULL,
		0x1EC95DF27C816280ULL,
		0x13E804C026C0D742ULL,
		0x0000000000000000ULL
	}};
	shift = 3;
	printf("Test Case 108\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x7FD88C670AF44CD1ULL,
		0x1095CF9D7C1ED227ULL,
		0x718420CEE08D0F33ULL,
		0x779C66F2A1A1FDEBULL,
		0x1C4DA04BFB08788FULL,
		0x6CE0CE48C41705CEULL,
		0x1FCBB6DFD79A89EAULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x07B489DFF62319C2ULL,
		0x2343CCC42573E75FULL,
		0x687F7ADC610833B8ULL,
		0xC21E23DDE719BCA8ULL,
		0x05C17387136812FEULL,
		0xE6A27A9B38339231ULL,
		0x00000007F2EDB7F5ULL,
		0x0000000000000000ULL
	}};
	shift = 26;
	printf("Test Case 109\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x1694C428A341301BULL,
		0x4027AAE6D0B20B9DULL,
		0x9EDBEB78A3C1B591ULL,
		0xAD82567482E67A0DULL,
		0x71F7B7E79C204E96ULL,
		0x9225E6FC7DA5F656ULL,
		0xD036D84F60092AE7ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3A2D298851468260ULL,
		0x22804F55CDA16417ULL,
		0x1B3DB7D6F147836BULL,
		0x2D5B04ACE905CCF4ULL,
		0xACE3EF6FCF38409DULL,
		0xCF244BCDF8FB4BECULL,
		0x01A06DB09EC01255ULL,
		0x0000000000000000ULL
	}};
	shift = 7;
	printf("Test Case 110\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x23EAB102E3CBD0FFULL,
		0xAE1B21A5B500266BULL,
		0xAF233E35BD6AC3E0ULL,
		0xBC7908725D083C28ULL,
		0xF6B759F087311A2EULL,
		0xA1EA69A4504A8C9FULL,
		0x5DA91EC11AE8849FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0133591F5588171EULL,
		0x561F0570D90D2DA8ULL,
		0x41E1457919F1ADEBULL,
		0x88D175E3C84392E8ULL,
		0x5464FFB5BACF8439ULL,
		0x4424FD0F534D2282ULL,
		0x000002ED48F608D7ULL,
		0x0000000000000000ULL
	}};
	shift = 21;
	printf("Test Case 111\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xA708ED9FD48EF9FEULL,
		0x7F2F8FC1EAA33F8BULL,
		0xA4F3A9AB8AA23DFAULL,
		0xB0062C76445158A9ULL,
		0x8E777A54FAC832B8ULL,
		0x3E9C5FE4BA7954A6ULL,
		0x576D4C65B5217723ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE2E9C23B67F523BEULL,
		0x7E9FCBE3F07AA8CFULL,
		0x2A693CEA6AE2A88FULL,
		0xAE2C018B1D911456ULL,
		0x29A39DDE953EB20CULL,
		0xC8CFA717F92E9E55ULL,
		0x0015DB53196D485DULL,
		0x0000000000000000ULL
	}};
	shift = 10;
	printf("Test Case 112\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xA5B767F9C6EDDA06ULL,
		0x6F9BBFC72720CD6CULL,
		0x13C5362C499B756BULL,
		0x2942258B85115551ULL,
		0xF650D64F60A498B3ULL,
		0xCC7F73649671E6A4ULL,
		0x43A2E971F22FC7C7ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7F8E4E419AD94B6EULL,
		0x6C589336EAD6DF37ULL,
		0x4B170A22AAA2278AULL,
		0xAC9EC14931665284ULL,
		0xE6C92CE3CD49ECA1ULL,
		0xD2E3E45F8F8F98FEULL,
		0x0000000000008745ULL,
		0x0000000000000000ULL
	}};
	shift = 47;
	printf("Test Case 113\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xB0151818A664C686ULL,
		0xE9BFFC10A9D40122ULL,
		0x29FCBF34B34492F6ULL,
		0x984A926DA66A7C32ULL,
		0xA31337B197DD74DAULL,
		0x61F7FE2FCD1ACCCBULL,
		0xC1BCD96CB4D3E207ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB0151818A664C686ULL,
		0xE9BFFC10A9D40122ULL,
		0x29FCBF34B34492F6ULL,
		0x984A926DA66A7C32ULL,
		0xA31337B197DD74DAULL,
		0x61F7FE2FCD1ACCCBULL,
		0xC1BCD96CB4D3E207ULL,
		0x0000000000000000ULL
	}};
	shift = 0;
	printf("Test Case 114\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x259663D1A145388FULL,
		0xEAC459091EAF53FDULL,
		0x4E4F273D5E3CDD47ULL,
		0x990E2B173678FE39ULL,
		0x9FDE02A9F1C13F95ULL,
		0xFA0934094DB9ED1BULL,
		0x64D917C3D7D56705ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x247ABD4FF496598FULL,
		0xF578F3751FAB1164ULL,
		0x5CD9E3F8E5393C9CULL,
		0xA7C704FE566438ACULL,
		0x2536E7B46E7F780AULL,
		0x0F5F559C17E824D0ULL,
		0x000000000193645FULL,
		0x0000000000000000ULL
	}};
	shift = 38;
	printf("Test Case 115\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xD883BE6D01B3CD92ULL,
		0x05454E18BAE7C97BULL,
		0xBF255F5B54EC3DD9ULL,
		0xD4BD57E294F98FA8ULL,
		0xE996C1605E403EDDULL,
		0xDB9FAA90AE2EE610ULL,
		0x67DAC0282812B7CEULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2EB9F25EF620EF9BULL,
		0xD53B0F7641515386ULL,
		0xA53E63EA2FC957D6ULL,
		0x17900FB7752F55F8ULL,
		0x2B8BB9843A65B058ULL,
		0x0A04ADF3B6E7EAA4ULL,
		0x0000000019F6B00AULL,
		0x0000000000000000ULL
	}};
	shift = 34;
	printf("Test Case 116\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xB808DD5B4FCFF6ADULL,
		0xC2823BFA6048BF9CULL,
		0x36B1F65E51968921ULL,
		0x1A366A838BCA4650ULL,
		0x833E9ABF0AC7C83FULL,
		0x8BC3B96EE056CAB0ULL,
		0x5716254AF8A89925ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x97011BAB69F9FED5ULL,
		0x3850477F4C0917F3ULL,
		0x06D63ECBCA32D124ULL,
		0xE346CD50717948CAULL,
		0x1067D357E158F907ULL,
		0xB178772DDC0AD956ULL,
		0x0AE2C4A95F151324ULL,
		0x0000000000000000ULL
	}};
	shift = 3;
	printf("Test Case 117\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xD1E014DFFBA80247ULL,
		0x384792EA76B0A3E8ULL,
		0xB2925B6CC1E43F53ULL,
		0x2CECB9D0DB0B0FC8ULL,
		0x541E337C0D4112D6ULL,
		0xAE6B20F120C515B9ULL,
		0xF91939FE7E7D1AF3ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x792EA76B0A3E8D1EULL,
		0x25B6CC1E43F53384ULL,
		0xCB9D0DB0B0FC8B29ULL,
		0xE337C0D4112D62CEULL,
		0xB20F120C515B9541ULL,
		0x939FE7E7D1AF3AE6ULL,
		0x0000000000000F91ULL,
		0x0000000000000000ULL
	}};
	shift = 52;
	printf("Test Case 118\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x800EA60D0A683AEEULL,
		0xAABEE35C517B65C2ULL,
		0xB8964925CB2AEE4DULL,
		0x04224079064BAFE3ULL,
		0x9666F57C5CC56A3CULL,
		0x28C4B7AF5029400DULL,
		0xC83083B0513E4769ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x70A003A983429A0EULL,
		0x936AAFB8D7145ED9ULL,
		0xF8EE25924972CABBULL,
		0x8F0108901E4192EBULL,
		0x036599BD5F17315AULL,
		0xDA4A312DEBD40A50ULL,
		0x00320C20EC144F91ULL,
		0x0000000000000000ULL
	}};
	shift = 10;
	printf("Test Case 119\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x4FE3A9898575FF23ULL,
		0x619A98FDE2FDF719ULL,
		0x24002F655815FD86ULL,
		0x226138FD8BD208F7ULL,
		0x83FEEDB87EC2B6ADULL,
		0xCCAF822FBC1D742FULL,
		0xCD6B0199C5D388CEULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEF17EFB8CA7F1D4CULL,
		0x2AC0AFEC330CD4C7ULL,
		0xEC5E9047B920017BULL,
		0xC3F615B5691309C7ULL,
		0x7DE0EBA17C1FF76DULL,
		0xCE2E9C4676657C11ULL,
		0x00000000066B580CULL,
		0x0000000000000000ULL
	}};
	shift = 37;
	printf("Test Case 120\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x24161B4F53FD7AC0ULL,
		0x1CDAFAA1FDDEAA5BULL,
		0xAEF5676840963AE0ULL,
		0x324544CD3915C65CULL,
		0x9FFA68D270ABF73AULL,
		0x49AEE0C75068B382ULL,
		0x8AF499D26A12BC70ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBD54B6482C369EA7ULL,
		0x2C75C039B5F543FBULL,
		0x2B8CB95DEACED081ULL,
		0x57EE74648A899A72ULL,
		0xD167053FF4D1A4E1ULL,
		0x2578E0935DC18EA0ULL,
		0x00000115E933A4D4ULL,
		0x0000000000000000ULL
	}};
	shift = 23;
	printf("Test Case 121\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xEF7E0C7195EF787DULL,
		0xEB3D7BC14D9B8F73ULL,
		0x3A8020ACAD08AE73ULL,
		0xF02879A3C5AA1E5AULL,
		0x0104EDCFD0708775ULL,
		0x36C88A8CD03123FCULL,
		0x555E5C78D8F9F6F9ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4D9B8F73EF7E0C71ULL,
		0xAD08AE73EB3D7BC1ULL,
		0xC5AA1E5A3A8020ACULL,
		0xD0708775F02879A3ULL,
		0xD03123FC0104EDCFULL,
		0xD8F9F6F936C88A8CULL,
		0x00000000555E5C78ULL,
		0x0000000000000000ULL
	}};
	shift = 32;
	printf("Test Case 122\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xBAB8652138AB3FCAULL,
		0x66EA83211BAE62EAULL,
		0x91B021EB19ED1A92ULL,
		0x3AD6714F4AC3474AULL,
		0x23C96E4DDBB8EF9EULL,
		0xE1A15337C5C31F8EULL,
		0xCF84E65EBC82E729ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC5D57570CA427156ULL,
		0x3524CDD50642375CULL,
		0x8E95236043D633DAULL,
		0xDF3C75ACE29E9586ULL,
		0x3F1C4792DC9BB771ULL,
		0xCE53C342A66F8B86ULL,
		0x00019F09CCBD7905ULL,
		0x0000000000000000ULL
	}};
	shift = 15;
	printf("Test Case 123\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x96FE954AD121F974ULL,
		0xCA8D487C191BC53EULL,
		0x45368F10D44DA073ULL,
		0x01EF984EB5D8F0E8ULL,
		0xF929102D9AB4378EULL,
		0xFAC4A31BE38F8265ULL,
		0xDFFDE193A3D800F7ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1A90F832378A7D2DULL,
		0x6D1E21A89B40E795ULL,
		0xDF309D6BB1E1D08AULL,
		0x52205B35686F1C03ULL,
		0x894637C71F04CBF2ULL,
		0xFBC32747B001EFF5ULL,
		0x00000000000001BFULL,
		0x0000000000000000ULL
	}};
	shift = 55;
	printf("Test Case 124\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x364682400169671EULL,
		0xBE62CD882E92C255ULL,
		0x4020A02F5E84BBBCULL,
		0x827573D75F1B839CULL,
		0xA151FC0EC14E8F73ULL,
		0x6F6DADAB93604922ULL,
		0x992DDE0105FAEC22ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8B3620BA4B0954D9ULL,
		0x8280BD7A12EEF2F9ULL,
		0xD5CF5D7C6E0E7100ULL,
		0x47F03B053A3DCE09ULL,
		0xB6B6AE4D81248A85ULL,
		0xB7780417EBB089BDULL,
		0x0000000000000264ULL,
		0x0000000000000000ULL
	}};
	shift = 54;
	printf("Test Case 125\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x367D3BFD167CB0AEULL,
		0x9B022DF3A857A185ULL,
		0x5334C21AA51BCCCCULL,
		0xC3D7B24DB8B844B0ULL,
		0xE07C7EB12E1B417EULL,
		0xB9E61848D71C2B2DULL,
		0x89402B05ACD4A38DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8614D9F4EFF459F2ULL,
		0x33326C08B7CEA15EULL,
		0x12C14CD3086A946FULL,
		0x05FB0F5EC936E2E1ULL,
		0xACB781F1FAC4B86DULL,
		0x8E36E79861235C70ULL,
		0x00022500AC16B352ULL,
		0x0000000000000000ULL
	}};
	shift = 14;
	printf("Test Case 126\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x5C23B85F8398B608ULL,
		0x9D20D16FA5418C17ULL,
		0xE6F401DADF08FBD4ULL,
		0xBCB7EA78A49BB40DULL,
		0x734F8AB7A8819467ULL,
		0x6464EEDC1BDAF61BULL,
		0xFB8979F2F6CA88D6ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC60BAE11DC2FC1CCULL,
		0x7DEA4E9068B7D2A0ULL,
		0xDA06F37A00ED6F84ULL,
		0xCA33DE5BF53C524DULL,
		0x7B0DB9A7C55BD440ULL,
		0x446B3232776E0DEDULL,
		0x00007DC4BCF97B65ULL,
		0x0000000000000000ULL
	}};
	shift = 17;
	printf("Test Case 127\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x46BFF2915CD7DD9CULL,
		0x2093A04357D35C9DULL,
		0x10B88FC0C4F0021FULL,
		0xE784B29D5EF26827ULL,
		0xAFF50CE56CD58721ULL,
		0x288C956988C5EBC6ULL,
		0xF28A72E5795B35C5ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x04357D35C9D46BFFULL,
		0xFC0C4F0021F2093AULL,
		0x29D5EF2682710B88ULL,
		0xCE56CD58721E784BULL,
		0x56988C5EBC6AFF50ULL,
		0x2E5795B35C5288C9ULL,
		0x00000000000F28A7ULL,
		0x0000000000000000ULL
	}};
	shift = 44;
	printf("Test Case 128\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x8FB73AEA4F2238FDULL,
		0x6A3A246E5B5E1CE8ULL,
		0xA3BC4C7E16549218ULL,
		0xA67AD023744B61F2ULL,
		0xD8D9E2CE676B3EB8ULL,
		0xF8915B930DAE6DA1ULL,
		0x8B35F7F58078FF02ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5B5E1CE88FB73AEAULL,
		0x165492186A3A246EULL,
		0x744B61F2A3BC4C7EULL,
		0x676B3EB8A67AD023ULL,
		0x0DAE6DA1D8D9E2CEULL,
		0x8078FF02F8915B93ULL,
		0x000000008B35F7F5ULL,
		0x0000000000000000ULL
	}};
	shift = 32;
	printf("Test Case 129\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xDE888019EAF0C271ULL,
		0xFEDE87255045F4C3ULL,
		0x1C668F0A35D6FE52ULL,
		0xFD2C3F77156048A2ULL,
		0x04933BE569AFFDA2ULL,
		0x620170025337A80BULL,
		0x009941E8FD0E9374ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x255045F4C3DE8880ULL,
		0x0A35D6FE52FEDE87ULL,
		0x77156048A21C668FULL,
		0xE569AFFDA2FD2C3FULL,
		0x025337A80B04933BULL,
		0xE8FD0E9374620170ULL,
		0x0000000000009941ULL,
		0x0000000000000000ULL
	}};
	shift = 40;
	printf("Test Case 130\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xAB3B38C73EB8AF99ULL,
		0x559B246B9A90B9E4ULL,
		0x395D93ABFA067972ULL,
		0x5196F2DAC92D78F7ULL,
		0xBE51EDDC4548E2CEULL,
		0xE26519069208FC54ULL,
		0x9C976338A2ECCCECULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x46B9A90B9E4AB3B3ULL,
		0x3ABFA067972559B2ULL,
		0x2DAC92D78F7395D9ULL,
		0xDDC4548E2CE5196FULL,
		0x9069208FC54BE51EULL,
		0x338A2ECCCECE2651ULL,
		0x000000000009C976ULL,
		0x0000000000000000ULL
	}};
	shift = 44;
	printf("Test Case 131\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x322D651CD999B4BAULL,
		0x33D84F2A63B27833ULL,
		0x9F6C19F4BBC933F8ULL,
		0x32ADAA2B79F9FDA7ULL,
		0x530228862697FE71ULL,
		0x502DD966D89E0CAEULL,
		0x2151C56436F8C1D7ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x833322D651CD999BULL,
		0x3F833D84F2A63B27ULL,
		0xDA79F6C19F4BBC93ULL,
		0xE7132ADAA2B79F9FULL,
		0xCAE530228862697FULL,
		0x1D7502DD966D89E0ULL,
		0x0002151C56436F8CULL,
		0x0000000000000000ULL
	}};
	shift = 12;
	printf("Test Case 132\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x5846123DBEB699ECULL,
		0x2A8D0478AF858D9AULL,
		0x662ADC716562B662ULL,
		0x9D72D148975C0732ULL,
		0x922AFDF0F497F424ULL,
		0x5652B2A383B92E14ULL,
		0x442E0DDAE86A47AFULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF15F0B1B34B08C24ULL,
		0xE2CAC56CC4551A08ULL,
		0x912EB80E64CC55B8ULL,
		0xE1E92FE8493AE5A2ULL,
		0x4707725C292455FBULL,
		0xB5D0D48F5EACA565ULL,
		0x0000000000885C1BULL,
		0x0000000000000000ULL
	}};
	shift = 39;
	printf("Test Case 133\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x10DBB8B9C0572375ULL,
		0x2EAFBBF402E204D1ULL,
		0xE78AE11957F2C2BFULL,
		0xED838EF7D7560317ULL,
		0x34C03664385C4A8CULL,
		0x632C0FD7A8F72936ULL,
		0x693143B869604DEEULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x01710268886DDC5CULL,
		0xABF9615F9757DDFAULL,
		0xEBAB018BF3C5708CULL,
		0x1C2E254676C1C77BULL,
		0xD47B949B1A601B32ULL,
		0x34B026F7319607EBULL,
		0x000000003498A1DCULL,
		0x0000000000000000ULL
	}};
	shift = 33;
	printf("Test Case 134\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x66FD4C16553041E7ULL,
		0x6EB69710AF82F84CULL,
		0x6CE9DBA714B25DEFULL,
		0x25E098D284D6788FULL,
		0x96AE12F092636C91ULL,
		0x7803548BE178AE80ULL,
		0xE7080F9390C0A87DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE215F05F098CDFA9ULL,
		0x74E2964BBDEDD6D2ULL,
		0x1A509ACF11ED9D3BULL,
		0x5E124C6D9224BC13ULL,
		0x917C2F15D012D5C2ULL,
		0xF27218150FAF006AULL,
		0x00000000001CE101ULL,
		0x0000000000000000ULL
	}};
	shift = 43;
	printf("Test Case 135\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x9F0EBDC6449BE1E1ULL,
		0x0EBDDCD70A60C955ULL,
		0x938E3731E2BAC286ULL,
		0x24F37B0467F18AC2ULL,
		0x30D36C4A03A1786BULL,
		0x4ACB93FB62B96FD5ULL,
		0xC64E1E741F7C053CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x67C3AF719126F878ULL,
		0x83AF7735C2983255ULL,
		0xA4E38DCC78AEB0A1ULL,
		0xC93CDEC119FC62B0ULL,
		0x4C34DB1280E85E1AULL,
		0x12B2E4FED8AE5BF5ULL,
		0x3193879D07DF014FULL,
		0x0000000000000000ULL
	}};
	shift = 2;
	printf("Test Case 136\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x459FA4CCF42822FEULL,
		0x1F9311E4C6C4DB64ULL,
		0xDE972F7AD7E6C14AULL,
		0x1D752AE99CB0D8B3ULL,
		0xE6323EF9F46A4B03ULL,
		0x4ABE9664CFEA4F6CULL,
		0xEBBB58FD1694F7A9ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x63626DB222CFD266ULL,
		0x6BF360A50FC988F2ULL,
		0xCE586C59EF4B97BDULL,
		0xFA3525818EBA9574ULL,
		0x67F527B673191F7CULL,
		0x8B4A7BD4A55F4B32ULL,
		0x0000000075DDAC7EULL,
		0x0000000000000000ULL
	}};
	shift = 33;
	printf("Test Case 137\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xD0F8F15FEF92C29CULL,
		0x8049CEAED0D6D58FULL,
		0xB02E649A6AC53D05ULL,
		0x5C4FCD8CA44C801EULL,
		0x31CED433182A6935ULL,
		0xFDE812AEBB2E40D2ULL,
		0x3A8B7BAFF64FFD03ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6B6AC7E87C78AFF7ULL,
		0x629E82C024E75768ULL,
		0x26400F5817324D35ULL,
		0x15349AAE27E6C652ULL,
		0x97206918E76A198CULL,
		0x27FE81FEF409575DULL,
		0x0000001D45BDD7FBULL,
		0x0000000000000000ULL
	}};
	shift = 25;
	printf("Test Case 138\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xC773F8F7E5350EF7ULL,
		0x49DC80223FDBCF4DULL,
		0xF7ACB9C2D1FD1A73ULL,
		0x97523140AAE944D9ULL,
		0x3B353F704BF7C86CULL,
		0xF67AED974A25FB55ULL,
		0x5811B293E4F8D967ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4EE40111FEDE7A6EULL,
		0xBD65CE168FE8D39AULL,
		0xBA918A05574A26CFULL,
		0xD9A9FB825FBE4364ULL,
		0xB3D76CBA512FDAA9ULL,
		0xC08D949F27C6CB3FULL,
		0x0000000000000002ULL,
		0x0000000000000000ULL
	}};
	shift = 61;
	printf("Test Case 139\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xE40F9B3751B9F248ULL,
		0xF06E222CDA41EDF9ULL,
		0x6D925BF73F8A832EULL,
		0x1BA76D66869744BCULL,
		0x28A2806384DE2C8CULL,
		0xD2C330EC86321097ULL,
		0xFB191832148203F5ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3DBF3C81F366EA37ULL,
		0x5065DE0DC4459B48ULL,
		0xE8978DB24B7EE7F1ULL,
		0xC5918374EDACD0D2ULL,
		0x4212E514500C709BULL,
		0x407EBA58661D90C6ULL,
		0x00001F6323064290ULL,
		0x0000000000000000ULL
	}};
	shift = 19;
	printf("Test Case 140\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xB23514CB98FA3E22ULL,
		0xB771CE6126CC4CFAULL,
		0x75705AEF9A603079ULL,
		0xDC6A7411E2B38BB8ULL,
		0xC3A11D079ACC6007ULL,
		0xFF503CBBC14D19C9ULL,
		0x9F2637091EB50020ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6CC4CFAB23514CB9ULL,
		0xA603079B771CE612ULL,
		0x2B38BB875705AEF9ULL,
		0xACC6007DC6A7411EULL,
		0x14D19C9C3A11D079ULL,
		0xEB50020FF503CBBCULL,
		0x00000009F2637091ULL,
		0x0000000000000000ULL
	}};
	shift = 28;
	printf("Test Case 141\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x3ACE43228629C599ULL,
		0x92FC203B2A2071EEULL,
		0x16F4E9894787E2FCULL,
		0x82CC611458917605ULL,
		0x528CFF6DF05D30D9ULL,
		0x8CCF3D38C0722CA9ULL,
		0x0F53E847456EFFB3ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5440E3DC759C8645ULL,
		0x8F0FC5F925F84076ULL,
		0xB122EC0A2DE9D312ULL,
		0xE0BA61B30598C228ULL,
		0x80E45952A519FEDBULL,
		0x8ADDFF67199E7A71ULL,
		0x000000001EA7D08EULL,
		0x0000000000000000ULL
	}};
	shift = 31;
	printf("Test Case 142\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xAA7EA7B2A5221FB3ULL,
		0x1087309C674077FCULL,
		0x5DF312E7F41A19F1ULL,
		0x3F4EA6A0D7FD5B88ULL,
		0x4FAC145D86E7A045ULL,
		0x2A16C0C61DBCDE71ULL,
		0x44EB6FB84815AAACULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6138CE80EFF954FDULL,
		0x25CFE83433E2210EULL,
		0x4D41AFFAB710BBE6ULL,
		0x28BB0DCF408A7E9DULL,
		0x818C3B79BCE29F58ULL,
		0xDF70902B5558542DULL,
		0x00000000000089D6ULL,
		0x0000000000000000ULL
	}};
	shift = 47;
	printf("Test Case 143\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xB864A38CEB9400F0ULL,
		0xB547C292ADFE693CULL,
		0xF2A53FD346BA4D6AULL,
		0x793245232F8F945FULL,
		0xBA9E28418E785352ULL,
		0xEB359220E0809341ULL,
		0x79BC8B83D00D062CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF0A4AB7F9A4F2E19ULL,
		0x4FF4D1AE935AAD51ULL,
		0x9148CBE3E517FCA9ULL,
		0x8A10639E14D49E4CULL,
		0x6488382024D06EA7ULL,
		0x22E0F403418B3ACDULL,
		0x0000000000001E6FULL,
		0x0000000000000000ULL
	}};
	shift = 50;
	printf("Test Case 144\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x685DF0C3F0BB7328ULL,
		0x0EFC08AE34CF35B6ULL,
		0x03CC0D84FFA341A3ULL,
		0x3CAF1DEF91425968ULL,
		0x25FA792A9C4EA54EULL,
		0xE27870E2A2C98F86ULL,
		0x0ECC8C554B83DE42ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x115C699E6B6CD0BBULL,
		0x1B09FF4683461DF8ULL,
		0x3BDF2284B2D00798ULL,
		0xF255389D4A9C795EULL,
		0xE1C545931F0C4BF4ULL,
		0x18AA9707BC85C4F0ULL,
		0x0000000000001D99ULL,
		0x0000000000000000ULL
	}};
	shift = 47;
	printf("Test Case 145\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xA4A20C4194CB332AULL,
		0x6173329B0D864125ULL,
		0x70EBE11184C6B1BCULL,
		0x3EC5DB45CE7758C6ULL,
		0x854BFD50D0D30956ULL,
		0xE2713779B5DA71C5ULL,
		0x6B1A8F2CB595B43BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC32092D2510620CAULL,
		0x6358DE30B9994D86ULL,
		0x3BAC633875F088C2ULL,
		0x6984AB1F62EDA2E7ULL,
		0xED38E2C2A5FEA868ULL,
		0xCADA1DF1389BBCDAULL,
		0x000000358D47965AULL,
		0x0000000000000000ULL
	}};
	shift = 25;
	printf("Test Case 146\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xEBE379267A2009C6ULL,
		0x365779C7DC32EC39ULL,
		0xA555F1BFB7F53C2AULL,
		0x565FAB802AB9FB7DULL,
		0x04A0A321D986D02DULL,
		0x488E14870814FA7DULL,
		0x6EF0C3EE37A45C34ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2EC39EBE379267A2ULL,
		0x53C2A365779C7DC3ULL,
		0x9FB7DA555F1BFB7FULL,
		0x6D02D565FAB802ABULL,
		0x4FA7D04A0A321D98ULL,
		0x45C34488E1487081ULL,
		0x000006EF0C3EE37AULL,
		0x0000000000000000ULL
	}};
	shift = 20;
	printf("Test Case 147\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x00E401EF98F0D018ULL,
		0x74ADDBD9CB1AB287ULL,
		0x03BA5B11D8AAB931ULL,
		0x8A4F00746E01459CULL,
		0x3075E4A42DB9E9F3ULL,
		0xDDA0EC89399F3B34ULL,
		0xA17A551CB1995EE7ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x672C6ACA1C039007ULL,
		0x4762AAE4C5D2B76FULL,
		0xD1B80516700EE96CULL,
		0x90B6E7A7CE293C01ULL,
		0x24E67CECD0C1D792ULL,
		0x72C6657B9F7683B2ULL,
		0x000000000285E954ULL,
		0x0000000000000000ULL
	}};
	shift = 38;
	printf("Test Case 148\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x75069405161BDD23ULL,
		0xDE3636D493708216ULL,
		0x480F5B81DD035172ULL,
		0xFC50ED6E2816B734ULL,
		0x39CFBE66A9BA6E39ULL,
		0x7DF192AC8187AE72ULL,
		0x20A900DF3D206116ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x675069405161BDD2ULL,
		0x2DE3636D49370821ULL,
		0x4480F5B81DD03517ULL,
		0x9FC50ED6E2816B73ULL,
		0x239CFBE66A9BA6E3ULL,
		0x67DF192AC8187AE7ULL,
		0x020A900DF3D20611ULL,
		0x0000000000000000ULL
	}};
	shift = 4;
	printf("Test Case 149\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x7806206955D6C423ULL,
		0xFA7DC7FC035D163BULL,
		0xA2D11EEA9493812DULL,
		0x7C418282D9541E25ULL,
		0xF084787889D915A2ULL,
		0x52EB76EE26890164ULL,
		0x9113520B062C0DA6ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE8B1DBC031034AAEULL,
		0x9C096FD3EE3FE01AULL,
		0xA0F12D1688F754A4ULL,
		0xC8AD13E20C1416CAULL,
		0x480B278423C3C44EULL,
		0x606D32975BB77134ULL,
		0x000004889A905831ULL,
		0x0000000000000000ULL
	}};
	shift = 21;
	printf("Test Case 150\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x7BFC01D619C33361ULL,
		0x1BD036EBEEEAA3AFULL,
		0x821596452D6EB633ULL,
		0x314E2EA4EB1AD3C2ULL,
		0x7AE86394993E06A3ULL,
		0xF5B03BAED4C45184ULL,
		0x31DEFC1A01F91D53ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA3AF7BFC01D619C3ULL,
		0xB6331BD036EBEEEAULL,
		0xD3C2821596452D6EULL,
		0x06A3314E2EA4EB1AULL,
		0x51847AE86394993EULL,
		0x1D53F5B03BAED4C4ULL,
		0x000031DEFC1A01F9ULL,
		0x0000000000000000ULL
	}};
	shift = 16;
	printf("Test Case 151\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xDAA3FC756548DE57ULL,
		0xEEF0AB618938CB2DULL,
		0xF3DAE67BED9AC7F6ULL,
		0x8494464693C70DC7ULL,
		0xB105CA74D112DE3CULL,
		0xCED75E027319AB1DULL,
		0x3CD517BC82692B26ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB76A8FF1D5952379ULL,
		0xDBBBC2AD8624E32CULL,
		0x1FCF6B99EFB66B1FULL,
		0xF21251191A4F1C37ULL,
		0x76C41729D3444B78ULL,
		0x9B3B5D7809CC66ACULL,
		0x00F3545EF209A4ACULL,
		0x0000000000000000ULL
	}};
	shift = 6;
	printf("Test Case 152\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xCD1524B3993562F0ULL,
		0xFE18DFA44E38D39FULL,
		0x2C40A2C67849AC19ULL,
		0x2754FD8AE46FC999ULL,
		0x67FDFAB19E7BB3BEULL,
		0xD40CC0A9DF46B5BEULL,
		0x89B254BFF81AD1DCULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBF489C71A73F9A2AULL,
		0x458CF0935833FC31ULL,
		0xFB15C8DF93325881ULL,
		0xF5633CF7677C4EA9ULL,
		0x8153BE8D6B7CCFFBULL,
		0xA97FF035A3B9A819ULL,
		0x0000000000011364ULL,
		0x0000000000000000ULL
	}};
	shift = 47;
	printf("Test Case 153\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x21812D9CCAEFB63AULL,
		0x6AA5774F506A8E11ULL,
		0x089B191AFA9CC6A4ULL,
		0xDA207FB2458651A2ULL,
		0x7BF5599378674BE8ULL,
		0xDC3024C080D67DBFULL,
		0x1E618571BA373027ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDD3D41AA38448604ULL,
		0x646BEA731A91AA95ULL,
		0xFEC916194688226CULL,
		0x664DE19D2FA36881ULL,
		0x93020359F6FDEFD5ULL,
		0x15C6E8DCC09F70C0ULL,
		0x0000000000007986ULL,
		0x0000000000000000ULL
	}};
	shift = 46;
	printf("Test Case 154\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x3EDD9094E2A96606ULL,
		0x17A2A07D7070EFAFULL,
		0x0C69E2BE37FE069EULL,
		0x5F7077179E545653ULL,
		0x7FC4B9BF5F16545EULL,
		0xEEED7FEB3B1055B5ULL,
		0xFC1F57D6B95A9EA6ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAE0E1DF5E7DBB212ULL,
		0xC6FFC0D3C2F4540FULL,
		0xF3CA8ACA618D3C57ULL,
		0xEBE2CA8BCBEE0EE2ULL,
		0x67620AB6AFF89737ULL,
		0xD72B53D4DDDDAFFDULL,
		0x000000001F83EAFAULL,
		0x0000000000000000ULL
	}};
	shift = 35;
	printf("Test Case 155\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x845B0391CF0AECEAULL,
		0xBAD6004DC8EB6240ULL,
		0xB7254C7E82D0EC5CULL,
		0x6DB0F9FF3CA3E962ULL,
		0x8BB4E797ED524311ULL,
		0x1DEFECBB996D1AFAULL,
		0x2C4C0B17A3EEDAB2ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6004DC8EB6240845ULL,
		0x54C7E82D0EC5CBADULL,
		0x0F9FF3CA3E962B72ULL,
		0x4E797ED5243116DBULL,
		0xFECBB996D1AFA8BBULL,
		0xC0B17A3EEDAB21DEULL,
		0x00000000000002C4ULL,
		0x0000000000000000ULL
	}};
	shift = 52;
	printf("Test Case 156\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x7198D7C237380035ULL,
		0xBBB732872E1FD8E5ULL,
		0xBD2CD56A66AB1094ULL,
		0x34A5B1B8A8923C62ULL,
		0xF06C8641833F5B67ULL,
		0x3D5CF5DCA223245FULL,
		0x10AB7F629B9F66D7ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE5C3FB1CAE331AF8ULL,
		0x4CD562129776E650ULL,
		0x1512478C57A59AADULL,
		0x3067EB6CE694B637ULL,
		0x9444648BFE0D90C8ULL,
		0x5373ECDAE7AB9EBBULL,
		0x0000000002156FECULL,
		0x0000000000000000ULL
	}};
	shift = 35;
	printf("Test Case 157\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x17BEC153CCC4C213ULL,
		0xA2E5AD367D3A9D72ULL,
		0x3A002C2C41AD40C6ULL,
		0xFDC57C088581B208ULL,
		0x15AA846073A9B1AEULL,
		0xF55E182137BBE3E4ULL,
		0xE47477E058E93ED5ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3AE42F7D82A79989ULL,
		0x818D45CB5A6CFA75ULL,
		0x641074005858835AULL,
		0x635DFB8AF8110B03ULL,
		0xC7C82B5508C0E753ULL,
		0x7DABEABC30426F77ULL,
		0x0001C8E8EFC0B1D2ULL,
		0x0000000000000000ULL
	}};
	shift = 15;
	printf("Test Case 158\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x12C7681487082D54ULL,
		0x3E9DE5FDBE1E546DULL,
		0x27694E1895298ADBULL,
		0xC42C0E2B7D0AD578ULL,
		0xA2C5614BC4091453ULL,
		0xD621D8772B851791ULL,
		0x60D3C9127EEA7D6FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC3CA8DA258ED0290ULL,
		0xA5315B67D3BCBFB7ULL,
		0xA15AAF04ED29C312ULL,
		0x81228A788581C56FULL,
		0x70A2F23458AC2978ULL,
		0xDD4FADFAC43B0EE5ULL,
		0x0000000C1A79224FULL,
		0x0000000000000000ULL
	}};
	shift = 27;
	printf("Test Case 159\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x053A172AD800CA7FULL,
		0x880968F26CA1BFFFULL,
		0x15A008BA1CABF5CCULL,
		0xF21F7AD5F9B80D0CULL,
		0x0408BB32C559F776ULL,
		0xDB77CBF3B3884B3CULL,
		0x8EAE1BD9D77E58F3ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x025A3C9B286FFFC1ULL,
		0x68022E872AFD7322ULL,
		0x87DEB57E6E034305ULL,
		0x022ECCB1567DDDBCULL,
		0xDDF2FCECE212CF01ULL,
		0xAB86F675DF963CF6ULL,
		0x0000000000000023ULL,
		0x0000000000000000ULL
	}};
	shift = 58;
	printf("Test Case 160\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xE85E4E54FBDB2E03ULL,
		0x716AE850F4B6DB5DULL,
		0x9C73BC4D929B0E2EULL,
		0x042732A9EEB3582CULL,
		0x187843986D760B89ULL,
		0xF76C1103B25A0995ULL,
		0x118623319138B6A2ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB6BBD0BC9CA9F7B6ULL,
		0x1C5CE2D5D0A1E96DULL,
		0xB05938E7789B2536ULL,
		0x1712084E6553DD66ULL,
		0x132A30F08730DAECULL,
		0x6D45EED8220764B4ULL,
		0x0000230C46632271ULL,
		0x0000000000000000ULL
	}};
	shift = 15;
	printf("Test Case 161\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x3F099D974243EA73ULL,
		0xB11FB58F9442F7DEULL,
		0x24DFFA7CA1709025ULL,
		0x2F7A97281D1A3913ULL,
		0x499BA6B55FB2007DULL,
		0xAEF8157A1108A5DCULL,
		0xB3DD12E76D8DB804ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB58F9442F7DE3F09ULL,
		0xFA7CA1709025B11FULL,
		0x97281D1A391324DFULL,
		0xA6B55FB2007D2F7AULL,
		0x157A1108A5DC499BULL,
		0x12E76D8DB804AEF8ULL,
		0x000000000000B3DDULL,
		0x0000000000000000ULL
	}};
	shift = 48;
	printf("Test Case 162\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x6881DA4D01A7B5C0ULL,
		0xE813E69A1F60D820ULL,
		0xE71D0F7E933ED35CULL,
		0x45AD0ABF6907A6A4ULL,
		0x833AE791639E169CULL,
		0x4765619D2E6407E5ULL,
		0xB8480EF26B5A1FDBULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x206881DA4D01A7B5ULL,
		0x5CE813E69A1F60D8ULL,
		0xA4E71D0F7E933ED3ULL,
		0x9C45AD0ABF6907A6ULL,
		0xE5833AE791639E16ULL,
		0xDB4765619D2E6407ULL,
		0x00B8480EF26B5A1FULL,
		0x0000000000000000ULL
	}};
	shift = 8;
	printf("Test Case 163\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xB63C9B971302D611ULL,
		0xA9C6B9A31D329A46ULL,
		0xD0AECF86BC927411ULL,
		0x456E0EC0EF313228ULL,
		0x4999C843CDE4BD43ULL,
		0xC2F44B355B9EF2FFULL,
		0xA245FA114015D6CBULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6B63C9B971302D61ULL,
		0x1A9C6B9A31D329A4ULL,
		0x8D0AECF86BC92741ULL,
		0x3456E0EC0EF31322ULL,
		0xF4999C843CDE4BD4ULL,
		0xBC2F44B355B9EF2FULL,
		0x0A245FA114015D6CULL,
		0x0000000000000000ULL
	}};
	shift = 4;
	printf("Test Case 164\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xE3F935A69E828D85ULL,
		0xF8AB37D90CA8B891ULL,
		0xF01FBC1F64E5BF7CULL,
		0x3964582F59FBA982ULL,
		0xFD3A056CB16965EFULL,
		0x21831E6D7003061EULL,
		0x2875630C2486F950ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF6432A2E2478FE4DULL,
		0x07D9396FDF3E2ACDULL,
		0x0BD67EEA60BC07EFULL,
		0x5B2C5A597BCE5916ULL,
		0x9B5C00C187BF4E81ULL,
		0xC30921BE540860C7ULL,
		0x00000000000A1D58ULL,
		0x0000000000000000ULL
	}};
	shift = 42;
	printf("Test Case 165\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x33407B18222FF8D6ULL,
		0x70B2028A88186FC6ULL,
		0x93D059C741574963ULL,
		0xE64DFD935E299CD7ULL,
		0xF5696DAD3D7C62BDULL,
		0xBE60E47AEEA77CC8ULL,
		0x6BEEEC91DD087E5DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA88186FC633407B1ULL,
		0x74157496370B2028ULL,
		0x35E299CD793D059CULL,
		0xD3D7C62BDE64DFD9ULL,
		0xAEEA77CC8F5696DAULL,
		0x1DD087E5DBE60E47ULL,
		0x0000000006BEEEC9ULL,
		0x0000000000000000ULL
	}};
	shift = 36;
	printf("Test Case 166\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x2281B3F6285AA983ULL,
		0x47E036613A46CF9CULL,
		0xD8034466B6B0390DULL,
		0x7DC553ECD1B170AEULL,
		0x89C95BA198A0DBCAULL,
		0x6B49A4CA3DD59D6AULL,
		0x18682437438B9E45ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x84E91B3E708A06CFULL,
		0x9ADAC0E4351F80D9ULL,
		0xB346C5C2BB600D11ULL,
		0x8662836F29F7154FULL,
		0x28F75675AA27256EULL,
		0xDD0E2E7915AD2693ULL,
		0x000000000061A090ULL,
		0x0000000000000000ULL
	}};
	shift = 38;
	printf("Test Case 167\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xC95C7CBAA2F7B7F2ULL,
		0x72EC9053B0CAD8C7ULL,
		0x70929CFD071EAA09ULL,
		0x4561AC0DE99BCC19ULL,
		0x2FDB81C87887706BULL,
		0x13CE0A40631769A3ULL,
		0xC7D53127779A3FB4ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD920A76195B18F92ULL,
		0x2539FA0E3D5412E5ULL,
		0xC3581BD3379832E1ULL,
		0xB70390F10EE0D68AULL,
		0x9C1480C62ED3465FULL,
		0xAA624EEF347F6827ULL,
		0x000000000000018FULL,
		0x0000000000000000ULL
	}};
	shift = 55;
	printf("Test Case 168\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x5DB6E568A5B97E14ULL,
		0x68C47B4D6278FC30ULL,
		0x3B6BFF2DB8D088D5ULL,
		0x5731FA33F80EFA45ULL,
		0x6D831E8AA7856764ULL,
		0xD1A59FDA106C0703ULL,
		0x086F11114538357FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x69AC4F1F860BB6DCULL,
		0xE5B71A111AAD188FULL,
		0x467F01DF48A76D7FULL,
		0xD154F0ACEC8AE63FULL,
		0xFB420D80E06DB063ULL,
		0x2228A706AFFA34B3ULL,
		0x0000000000010DE2ULL,
		0x0000000000000000ULL
	}};
	shift = 43;
	printf("Test Case 169\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x2590AA41E96BE3C1ULL,
		0x752861BF18AEEE45ULL,
		0x4DFEB9202E295A4BULL,
		0xDCBDAFFA1494ECCCULL,
		0x85DD7D5FF011C259ULL,
		0x38AD32CCCDFFAFEEULL,
		0x81B78023C9FC9E54ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC57772292C85520FULL,
		0x714AD25BA9430DF8ULL,
		0xA4A766626FF5C901ULL,
		0x808E12CEE5ED7FD0ULL,
		0x6FFD7F742EEBEAFFULL,
		0x4FE4F2A1C5699666ULL,
		0x000000040DBC011EULL,
		0x0000000000000000ULL
	}};
	shift = 29;
	printf("Test Case 170\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0D9B3AA3E5E9CE5AULL,
		0x908A100606625C48ULL,
		0x83DAEC8282E0D560ULL,
		0x7C3DFEF67BEE435AULL,
		0x362E3F4D72F6CA80ULL,
		0xF962CE2D8AA2FD6EULL,
		0x31D95101B3FDBA5CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9897120366CEA8F9ULL,
		0xB835582422840181ULL,
		0xFB90D6A0F6BB20A0ULL,
		0xBDB2A01F0F7FBD9EULL,
		0xA8BF5B8D8B8FD35CULL,
		0xFF6E973E58B38B62ULL,
		0x0000000C7654406CULL,
		0x0000000000000000ULL
	}};
	shift = 26;
	printf("Test Case 171\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0FCCBCC87D074322ULL,
		0x305735A4F31A2A8FULL,
		0x49DD8C755940BB05ULL,
		0x9F43221A0F3205CBULL,
		0xAAF4B436B8C7254FULL,
		0x2DFE36184B350479ULL,
		0xE99A93A63CBA4F18ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x35A4F31A2A8F0FCCULL,
		0x8C755940BB053057ULL,
		0x221A0F3205CB49DDULL,
		0xB436B8C7254F9F43ULL,
		0x36184B350479AAF4ULL,
		0x93A63CBA4F182DFEULL,
		0x000000000000E99AULL,
		0x0000000000000000ULL
	}};
	shift = 48;
	printf("Test Case 172\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x5430A1FC55A0C794ULL,
		0x9151C58FA6EDCB8DULL,
		0xF2CCEA260E28A3A1ULL,
		0xCF2ECFFE09AA033AULL,
		0x3C3F2B8141BAB31FULL,
		0x530FD423FB6C3E07ULL,
		0x37E8D310D61A7C4BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC58FA6EDCB8D5430ULL,
		0xEA260E28A3A19151ULL,
		0xCFFE09AA033AF2CCULL,
		0x2B8141BAB31FCF2EULL,
		0xD423FB6C3E073C3FULL,
		0xD310D61A7C4B530FULL,
		0x00000000000037E8ULL,
		0x0000000000000000ULL
	}};
	shift = 48;
	printf("Test Case 173\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x679F02E9104AD0B5ULL,
		0xB2A28ADE485E2F82ULL,
		0x327D9BB2C1B7566AULL,
		0xCC692A2B131404D1ULL,
		0x7DB2D06FDD1BBAA4ULL,
		0xB7CBA66A45A9D339ULL,
		0x34EF718C562952BBULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA28ADE485E2F8267ULL,
		0x7D9BB2C1B7566AB2ULL,
		0x692A2B131404D132ULL,
		0xB2D06FDD1BBAA4CCULL,
		0xCBA66A45A9D3397DULL,
		0xEF718C562952BBB7ULL,
		0x0000000000000034ULL,
		0x0000000000000000ULL
	}};
	shift = 56;
	printf("Test Case 174\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x1A378425A4127D53ULL,
		0xC9C931A72679C399ULL,
		0xCA5D5AB57412476CULL,
		0xEC8FAEC4E6F76E0FULL,
		0x96F4F9628B25C2E9ULL,
		0x939A684434280326ULL,
		0x782AFEA500E39EB3ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9C3991A378425A41ULL,
		0x2476CC9C931A7267ULL,
		0x76E0FCA5D5AB5741ULL,
		0x5C2E9EC8FAEC4E6FULL,
		0x8032696F4F9628B2ULL,
		0x39EB3939A6844342ULL,
		0x00000782AFEA500EULL,
		0x0000000000000000ULL
	}};
	shift = 20;
	printf("Test Case 175\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x512966F96A6F4A00ULL,
		0x83A019EAF3E24F48ULL,
		0xB41B272B3822A597ULL,
		0xD61AC4446C75EB5BULL,
		0x16195C51E6A67FBFULL,
		0xDF3C8264C0166F06ULL,
		0xB82EF23BC5FB9E27ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF893D2144A59BE5AULL,
		0x08A965E0E8067ABCULL,
		0x1D7AD6ED06C9CACEULL,
		0xA99FEFF586B1111BULL,
		0x059BC18586571479ULL,
		0x7EE789F7CF209930ULL,
		0x0000002E0BBC8EF1ULL,
		0x0000000000000000ULL
	}};
	shift = 26;
	printf("Test Case 176\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xB097FA13B1002E92ULL,
		0xF37F7D5414F75157ULL,
		0x0723D5DBB7C35FABULL,
		0x6DC6AF7DCB308813ULL,
		0x99A3E669B10127C2ULL,
		0xB46117EE1BE7BD3AULL,
		0xA8CEA1FE66B9D246ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEC25FE84EC400BA4ULL,
		0xFCDFDF55053DD455ULL,
		0xC1C8F576EDF0D7EAULL,
		0x9B71ABDF72CC2204ULL,
		0xA668F99A6C4049F0ULL,
		0xAD1845FB86F9EF4EULL,
		0x2A33A87F99AE7491ULL,
		0x0000000000000000ULL
	}};
	shift = 2;
	printf("Test Case 177\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x9A332358E2E9D9DAULL,
		0x7A0FBF9639EBEA52ULL,
		0x3003FA93A0250EA7ULL,
		0x4B8C4928AA5B7132ULL,
		0xF5AC028F6103B41CULL,
		0x68E576BF72580DD3ULL,
		0xD91AFB5A8A2CB64EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0FBF9639EBEA529AULL,
		0x03FA93A0250EA77AULL,
		0x8C4928AA5B713230ULL,
		0xAC028F6103B41C4BULL,
		0xE576BF72580DD3F5ULL,
		0x1AFB5A8A2CB64E68ULL,
		0x00000000000000D9ULL,
		0x0000000000000000ULL
	}};
	shift = 56;
	printf("Test Case 178\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xF586C7ABE117D2DDULL,
		0x089E2F5D0DF6CFA0ULL,
		0xAAA08BFE67BDBC2FULL,
		0xA5C70AE2387AFBFFULL,
		0x71496417653BF9FFULL,
		0x74A57017E4EF350FULL,
		0x32876CBEE54AE98CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4F17AE86FB67D07AULL,
		0x5045FF33DEDE1784ULL,
		0xE385711C3D7DFFD5ULL,
		0xA4B20BB29DFCFFD2ULL,
		0x52B80BF2779A87B8ULL,
		0x43B65F72A574C63AULL,
		0x0000000000000019ULL,
		0x0000000000000000ULL
	}};
	shift = 57;
	printf("Test Case 179\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xBE15B60F286EBE1AULL,
		0xF843C98088CF9382ULL,
		0x8CA23B5BAD4EA97FULL,
		0x330D9DE04993610DULL,
		0x798D0BF6550AF446ULL,
		0x4413BB4C0E1A91F7ULL,
		0x78E754A6D9F3C758ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5F0ADB0794375F0DULL,
		0xFC21E4C04467C9C1ULL,
		0xC6511DADD6A754BFULL,
		0x1986CEF024C9B086ULL,
		0xBCC685FB2A857A23ULL,
		0x2209DDA6070D48FBULL,
		0x3C73AA536CF9E3ACULL,
		0x0000000000000000ULL
	}};
	shift = 1;
	printf("Test Case 180\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x8B37484DFD038557ULL,
		0x51C104B83838A6F5ULL,
		0xDE5378139FB46748ULL,
		0x446BF2F4758A9A0CULL,
		0x9B515A0F05AA227CULL,
		0x94B84FBAEC63D098ULL,
		0x97125832EA8280C4ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x097070714DEB166EULL,
		0xF0273F68CE90A382ULL,
		0xE5E8EB153419BCA6ULL,
		0xB41E0B5444F888D7ULL,
		0x9F75D8C7A13136A2ULL,
		0xB065D50501892970ULL,
		0x0000000000012E24ULL,
		0x0000000000000000ULL
	}};
	shift = 47;
	printf("Test Case 181\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x5C2AEC445FB2CE1FULL,
		0x5438E1728166BFF5ULL,
		0x067D4A1EE354453CULL,
		0x7FB18DE02F5D0D90ULL,
		0xE08848192232D753ULL,
		0xDA42F941D6C6718AULL,
		0xD13C6350BE08171AULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEAB855D888BF659CULL,
		0x78A871C2E502CD7FULL,
		0x200CFA943DC6A88AULL,
		0xA6FF631BC05EBA1BULL,
		0x15C11090324465AEULL,
		0x35B485F283AD8CE3ULL,
		0x01A278C6A17C102EULL,
		0x0000000000000000ULL
	}};
	shift = 7;
	printf("Test Case 182\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xF1609E35D5259384ULL,
		0x87E9D45EBFB3A12AULL,
		0x746DF0D319E4A00BULL,
		0xAFAAA0FB96EDAB7DULL,
		0xE0C699E9A76DC053ULL,
		0xB14D42FBAB69239AULL,
		0x4ADA048D5C922184ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7AFECE84ABC58278ULL,
		0x4C6792802E1FA751ULL,
		0xEE5BB6ADF5D1B7C3ULL,
		0xA69DB7014EBEAA83ULL,
		0xEEADA48E6B831A67ULL,
		0x3572488612C5350BULL,
		0x00000000012B6812ULL,
		0x0000000000000000ULL
	}};
	shift = 38;
	printf("Test Case 183\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xE48872F7A574B5B2ULL,
		0x1412B1B475C5FEB4ULL,
		0xF2512C993302DB8BULL,
		0x11026CBF20FE3F19ULL,
		0x053E039CABF54E73ULL,
		0x136FA0C31FE52F0DULL,
		0xD2AD98184E83F035ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD1D717FAD39221CBULL,
		0x64CC0B6E2C504AC6ULL,
		0xFC83F8FC67C944B2ULL,
		0x72AFD539CC4409B2ULL,
		0x0C7F94BC3414F80EULL,
		0x613A0FC0D44DBE83ULL,
		0x00000000034AB660ULL,
		0x0000000000000000ULL
	}};
	shift = 38;
	printf("Test Case 184\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x6DB7F83F77892D86ULL,
		0x09686E545104E0B1ULL,
		0x3D890B60A2EC8B68ULL,
		0x9788C295EEFAEE07ULL,
		0xE440EA080B581360ULL,
		0x51838233F37472BDULL,
		0x6583F843B5FAA4B0ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCA8A209C162DB6FFULL,
		0x6C145D916D012D0DULL,
		0x52BDDF5DC0E7B121ULL,
		0x41016B026C12F118ULL,
		0x467E6E8E57BC881DULL,
		0x0876BF54960A3070ULL,
		0x00000000000CB07FULL,
		0x0000000000000000ULL
	}};
	shift = 43;
	printf("Test Case 185\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x3FD5D18FBA26142DULL,
		0x78B2A70D4E624FC4ULL,
		0x8035FE9589AB1D3BULL,
		0x44A55109D4ACDC3DULL,
		0x8E59628E84F54ADAULL,
		0xF70B049BB9414744ULL,
		0x0EE9A359E4354A61ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9C3539893F10FF57ULL,
		0xFA5626AC74EDE2CAULL,
		0x442752B370F600D7ULL,
		0x8A3A13D52B691295ULL,
		0x126EE5051D123965ULL,
		0x8D6790D52987DC2CULL,
		0x0000000000003BA6ULL,
		0x0000000000000000ULL
	}};
	shift = 46;
	printf("Test Case 186\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x42E30D7430764E3DULL,
		0xA110D8377253415AULL,
		0xDDAA960D17ED8DF9ULL,
		0x615FC286415C7BABULL,
		0x3C791A3AA37C26B1ULL,
		0xFFF7D6BE4B539DC6ULL,
		0x639924383FAB3EE1ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA42E30D7430764E3ULL,
		0x9A110D8377253415ULL,
		0xBDDAA960D17ED8DFULL,
		0x1615FC286415C7BAULL,
		0x63C791A3AA37C26BULL,
		0x1FFF7D6BE4B539DCULL,
		0x0639924383FAB3EEULL,
		0x0000000000000000ULL
	}};
	shift = 4;
	printf("Test Case 187\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x8D399C0B832FA5E0ULL,
		0xE8A7413CD1E230D9ULL,
		0x8C6CC000BC2B5114ULL,
		0x567722F3272C85C9ULL,
		0xBE0EE5F008EE7E94ULL,
		0x78576B45C74EDBD6ULL,
		0x9002F669CBFC4DB0ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC69CCE05C197D2F0ULL,
		0x7453A09E68F1186CULL,
		0xC63660005E15A88AULL,
		0x2B3B9179939642E4ULL,
		0x5F0772F804773F4AULL,
		0x3C2BB5A2E3A76DEBULL,
		0x48017B34E5FE26D8ULL,
		0x0000000000000000ULL
	}};
	shift = 1;
	printf("Test Case 188\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xC4DCD939F8D8E2ECULL,
		0x8F6FA07B3F139671ULL,
		0x123E96D273C024C1ULL,
		0x7C762A7B8DA4A0A9ULL,
		0x983A8BF0B36D09EFULL,
		0xA55ACA0547A68440ULL,
		0xBA28B8601A388764ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F67E272CE389B9BULL,
		0xDA4E78049831EDF4ULL,
		0x4F71B494152247D2ULL,
		0x7E166DA13DEF8EC5ULL,
		0x40A8F4D088130751ULL,
		0x0C034710EC94AB59ULL,
		0x0000000000174517ULL,
		0x0000000000000000ULL
	}};
	shift = 43;
	printf("Test Case 189\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xDB98EB09B2D20550ULL,
		0x9CA5172CB7E9F791ULL,
		0xE13E7F36A73385A5ULL,
		0x1F6230149E9B3B36ULL,
		0x7006C9D04DA200D9ULL,
		0x0F6F301EA2174A81ULL,
		0x0EFDC37C4D408DA4ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5172CB7E9F791DB9ULL,
		0xE7F36A73385A59CAULL,
		0x230149E9B3B36E13ULL,
		0x6C9D04DA200D91F6ULL,
		0xF301EA2174A81700ULL,
		0xDC37C4D408DA40F6ULL,
		0x00000000000000EFULL,
		0x0000000000000000ULL
	}};
	shift = 52;
	printf("Test Case 190\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x198BFA55ED4A1418ULL,
		0xDFED2BA516F07C19ULL,
		0x753A9B56FF670A08ULL,
		0x875B32FAD0A11FBBULL,
		0xB51C7285071ED6E4ULL,
		0x289435602BD8D3A9ULL,
		0x172DC0F8E9D76047ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x95D28B783E0C8CC5ULL,
		0x4DAB7FB385046FF6ULL,
		0x997D68508FDDBA9DULL,
		0x3942838F6B7243ADULL,
		0x1AB015EC69D4DA8EULL,
		0xE07C74EBB023944AULL,
		0x0000000000000B96ULL,
		0x0000000000000000ULL
	}};
	shift = 49;
	printf("Test Case 191\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x43D6EE5645BBCDDFULL,
		0xD8301070B1C0DB4BULL,
		0x79C6D5F0C6F03705ULL,
		0x6352E509F22EB648ULL,
		0x71317D5F6863FBC2ULL,
		0xB23A4FA149D4F132ULL,
		0xA80D2E9154807605ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDB4B43D6EE5645BBULL,
		0x3705D8301070B1C0ULL,
		0xB64879C6D5F0C6F0ULL,
		0xFBC26352E509F22EULL,
		0xF13271317D5F6863ULL,
		0x7605B23A4FA149D4ULL,
		0x0000A80D2E915480ULL,
		0x0000000000000000ULL
	}};
	shift = 16;
	printf("Test Case 192\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x2C097A965CDAFA33ULL,
		0x81174B4D9A3071E9ULL,
		0xB33013EF36392C89ULL,
		0xB3BC528E6C4758FCULL,
		0x924C4274813855E7ULL,
		0x1814EA61E6C233EDULL,
		0x7CB0674B05F97BCAULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9B3460E3D25812F5ULL,
		0xDE6C725913022E96ULL,
		0x1CD88EB1F9666027ULL,
		0xE90270ABCF6778A5ULL,
		0xC3CD8467DB249884ULL,
		0x960BF2F7943029D4ULL,
		0x0000000000F960CEULL,
		0x0000000000000000ULL
	}};
	shift = 39;
	printf("Test Case 193\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xF36AC05D6C315AE1ULL,
		0x1EC5A1D999D3002BULL,
		0x109B782D2DBBEA23ULL,
		0x6B1BAB4109B50465ULL,
		0xB6E3E0E9326AB53CULL,
		0xF648D21025B269C0ULL,
		0x5EA5A3038EC5B361ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD0ECCCE98015F9B5ULL,
		0xBC1696DDF5118F62ULL,
		0xD5A084DA8232884DULL,
		0xF07499355A9E358DULL,
		0x690812D934E05B71ULL,
		0xD181C762D9B0FB24ULL,
		0x0000000000002F52ULL,
		0x0000000000000000ULL
	}};
	shift = 49;
	printf("Test Case 194\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xE9B4591FE19388CCULL,
		0x36B66F917BFC99A7ULL,
		0xFEAC0140B299781BULL,
		0x8EEB2A7B172345A9ULL,
		0x97D684B5A1EBB3B6ULL,
		0xD86519DDDF065B5BULL,
		0x86E589C5B3AEE101ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x45EFF2669FA6D164ULL,
		0x02CA65E06CDAD9BEULL,
		0xEC5C8D16A7FAB005ULL,
		0xD687AECEDA3BACA9ULL,
		0x777C196D6E5F5A12ULL,
		0x16CEBB8407619467ULL,
		0x00000000021B9627ULL,
		0x0000000000000000ULL
	}};
	shift = 38;
	printf("Test Case 195\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x71871046678FB7FBULL,
		0x3507D40F337ABE3DULL,
		0xB90FFFB253CC9D0AULL,
		0x682D7BD8042D7267ULL,
		0x91FF61B78E3454D9ULL,
		0xDD6A252F9DB81B4BULL,
		0x06AED42C7CA571EEULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x503CCDEAF8F5C61CULL,
		0xFEC94F327428D41FULL,
		0xEF6010B5C99EE43FULL,
		0x86DE38D15365A0B5ULL,
		0x94BE76E06D2E47FDULL,
		0x50B1F295C7BB75A8ULL,
		0x0000000000001ABBULL,
		0x0000000000000000ULL
	}};
	shift = 46;
	printf("Test Case 196\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x1C5DA57FF545C977ULL,
		0xF41C52D180038C0AULL,
		0x5F68C02CF1FB17BBULL,
		0x46C8B3D463D4A458ULL,
		0xF71E230D759ED724ULL,
		0xC5E26B34D38C78D6ULL,
		0x2706CC9B519F6406ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA0E2968C001C6050ULL,
		0xFB4601678FD8BDDFULL,
		0x36459EA31EA522C2ULL,
		0xB8F1186BACF6B922ULL,
		0x2F1359A69C63C6B7ULL,
		0x383664DA8CFB2036ULL,
		0x0000000000000001ULL,
		0x0000000000000000ULL
	}};
	shift = 61;
	printf("Test Case 197\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xF61B7B6799FB8930ULL,
		0x21C2C2B6F096D811ULL,
		0x185E6240225D2EBFULL,
		0x911C9C13684A402DULL,
		0x892232A9D5921215ULL,
		0x5C452A717BF8F1A1ULL,
		0x6703C71ABC80D90FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x023EC36F6CF33F71ULL,
		0xD7E4385856DE12DBULL,
		0x05A30BCC48044BA5ULL,
		0x42B22393826D0948ULL,
		0x34312446553AB242ULL,
		0x21EB88A54E2F7F1EULL,
		0x000CE078E357901BULL,
		0x0000000000000000ULL
	}};
	shift = 11;
	printf("Test Case 198\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x75BCC064D35AB31BULL,
		0x0B5EFDFFA4B1598DULL,
		0x7FA5647DE6A42D6DULL,
		0x9A5CD8D013F404B4ULL,
		0xEF97A88EE958D829ULL,
		0x7A6CE7F0829B6427ULL,
		0x367459FA3E282988ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFBFF4962B31AEB79ULL,
		0xC8FBCD485ADA16BDULL,
		0xB1A027E80968FF4AULL,
		0x511DD2B1B05334B9ULL,
		0xCFE10536C84FDF2FULL,
		0xB3F47C505310F4D9ULL,
		0x0000000000006CE8ULL,
		0x0000000000000000ULL
	}};
	shift = 47;
	printf("Test Case 199\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x3AE1F45B1B4038FDULL,
		0x06EFFBD9316C6D6DULL,
		0x442A38B76E565685ULL,
		0x6BE21D70BDB66344ULL,
		0xFEAA9B039FAFCBC1ULL,
		0xE6EB5804566F55ACULL,
		0xF6F828680528CEC2ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3AE1F45B1B4038FDULL,
		0x06EFFBD9316C6D6DULL,
		0x442A38B76E565685ULL,
		0x6BE21D70BDB66344ULL,
		0xFEAA9B039FAFCBC1ULL,
		0xE6EB5804566F55ACULL,
		0xF6F828680528CEC2ULL,
		0x0000000000000000ULL
	}};
	shift = 0;
	printf("Test Case 200\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000400000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000040000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 56;
	printf("Test Case 201\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 201 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -201;
	} else {
		printf("Test Case 201 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0004000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0040000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 60;
	printf("Test Case 202\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 202 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -202;
	} else {
		printf("Test Case 202 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000004000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000400000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 56;
	printf("Test Case 203\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 203 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -203;
	} else {
		printf("Test Case 203 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000001ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 12;
	printf("Test Case 204\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 204 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -204;
	} else {
		printf("Test Case 204 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000200000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0002000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 48;
	printf("Test Case 205\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 205 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -205;
	} else {
		printf("Test Case 205 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000080000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0080000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 52;
	printf("Test Case 206\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 206 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -206;
	} else {
		printf("Test Case 206 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000010000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000001000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 56;
	printf("Test Case 207\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 207 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -207;
	} else {
		printf("Test Case 207 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000001000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0010000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 48;
	printf("Test Case 208\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 208 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -208;
	} else {
		printf("Test Case 208 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000010000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000001000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 4;
	printf("Test Case 209\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 209 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -209;
	} else {
		printf("Test Case 209 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0004000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000040000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 32;
	printf("Test Case 210\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 210 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -210;
	} else {
		printf("Test Case 210 PASSED\n");
	}
	printf("---\n\n");
	return 0;
}