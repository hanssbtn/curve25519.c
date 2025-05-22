#include "../tests.h"

int32_t curve25519_key_rshift_inplace_test(void) {
	printf("Inplace Key Right Shift Test\n");
	curve25519_key_t k1 = {.key64 = {
		0xA07F0F5CC932E407ULL,
		0x9076CA2221446DE4ULL,
		0x40FE909C65C53F32ULL,
		0x79AB76E74E60739AULL,
		0xC436C537C611A35BULL,
		0xD5808774AC38891AULL,
		0x773B23A79F69115CULL,
		0x0000000000000000ULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0x110A236F2503F87AULL,
		0xE32E29F99483B651ULL,
		0x3A73039CD207F484ULL,
		0xBE308D1ADBCD5BB7ULL,
		0xA561C448D621B629ULL,
		0x3CFB488AE6AC043BULL,
		0x0000000003B9D91DULL,
		0x0000000000000000ULL
	}};
	int shift = 37;
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
		0x2A638C9E16DBCBEAULL,
		0x426B9DFA62C6673AULL,
		0xC19038C20D902C39ULL,
		0x81AB3C7BAEC30B0FULL,
		0x4B749B9202F908B6ULL,
		0x8B59B016A885A0E1ULL,
		0xBB28BCCB7785A6EAULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x339D1531C64F0B6DULL,
		0x161CA135CEFD3163ULL,
		0x8587E0C81C6106C8ULL,
		0x845B40D59E3DD761ULL,
		0xD070A5BA4DC9017CULL,
		0xD37545ACD80B5442ULL,
		0x00005D945E65BBC2ULL,
		0x0000000000000000ULL
	}};
	shift = 17;
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
		0x61D7B69513E5BF64ULL,
		0x84D41C5266652B0AULL,
		0xF29F1DD75DEBEC3AULL,
		0x7E4CB6DC336F6242ULL,
		0xABB6A9C21A777B57ULL,
		0xE7C351381A8A912AULL,
		0x0A966005C939B3F4ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9A838A4CCCA5614CULL,
		0x53E3BAEBBD7D8750ULL,
		0xC996DB866DEC485EULL,
		0x76D538434EEF6AEFULL,
		0xF86A270351522555ULL,
		0x52CC00B927367E9CULL,
		0x0000000000000001ULL,
		0x0000000000000000ULL
	}};
	shift = 59;
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
		0x2F5AFE3025C29D38ULL,
		0xA584965B282D3B98ULL,
		0x7D302FFBDE97BE64ULL,
		0xC3483C1015E07B88ULL,
		0x57F31360BB8C671CULL,
		0x9EC7603F48477C93ULL,
		0x4929EB0607D1B67FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD3B982F5AFE3025CULL,
		0x7BE64A584965B282ULL,
		0x07B887D302FFBDE9ULL,
		0xC671CC3483C1015EULL,
		0x77C9357F31360BB8ULL,
		0x1B67F9EC7603F484ULL,
		0x000004929EB0607DULL,
		0x0000000000000000ULL
	}};
	shift = 20;
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
		0x7CA9DA1E8ADFADB1ULL,
		0x7B78DB3C16445FB6ULL,
		0xE000143FB95F27EBULL,
		0x28ED94DC8BDCACCFULL,
		0xAB55084A06E3752AULL,
		0x43BA8A8AF466994AULL,
		0xC3F7D3D3067E16B3ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEDE36CF059117ED9ULL,
		0x800050FEE57C9FADULL,
		0xA3B653722F72B33FULL,
		0xAD5421281B8DD4A8ULL,
		0x0EEA2A2BD19A652AULL,
		0x0FDF4F4C19F85ACDULL,
		0x0000000000000003ULL,
		0x0000000000000000ULL
	}};
	shift = 62;
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
		0xF0DC6EC994E6F71CULL,
		0xD5954F4894085DB9ULL,
		0xE6F0DBA3C7A85A53ULL,
		0xFEB2D5DE5526B1F1ULL,
		0x039AB9FEFD383676ULL,
		0xFC908F4E1E667C68ULL,
		0x772E6762EC70D8F4ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF0DC6EC994E6F71CULL,
		0xD5954F4894085DB9ULL,
		0xE6F0DBA3C7A85A53ULL,
		0xFEB2D5DE5526B1F1ULL,
		0x039AB9FEFD383676ULL,
		0xFC908F4E1E667C68ULL,
		0x772E6762EC70D8F4ULL,
		0x0000000000000000ULL
	}};
	shift = 0;
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
		0x45849472E49E5318ULL,
		0x204990F8FF387949ULL,
		0x343F17108ED45815ULL,
		0xEB104851C1C19CA5ULL,
		0x14BC4150E2B82C7CULL,
		0x15DCB699B78A87B9ULL,
		0x8DD1B0E5FC3CC7F4ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F8FF38794945849ULL,
		0x7108ED4581520499ULL,
		0x851C1C19CA5343F1ULL,
		0x150E2B82C7CEB104ULL,
		0x699B78A87B914BC4ULL,
		0x0E5FC3CC7F415DCBULL,
		0x000000000008DD1BULL,
		0x0000000000000000ULL
	}};
	shift = 44;
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
		0x89187030946B217FULL,
		0x5A72666958C20CF1ULL,
		0x6CC7BF261E1ECC8CULL,
		0xFB4A4BAB05E37774ULL,
		0xFCF187760D7C66D0ULL,
		0xB4012C7B26901DBFULL,
		0xC10E34920516CF0EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC999A5630833C624ULL,
		0x1EFC98787B323169ULL,
		0x292EAC178DDDD1B3ULL,
		0xC61DD835F19B43EDULL,
		0x04B1EC9A4076FFF3ULL,
		0x38D248145B3C3AD0ULL,
		0x0000000000000304ULL,
		0x0000000000000000ULL
	}};
	shift = 54;
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
		0x97E05158CD468398ULL,
		0x8EE29C104056DA8CULL,
		0xE686380230FCA3ABULL,
		0xF664358B704E9DF5ULL,
		0x99BA67D6223AD824ULL,
		0x937D9E22F96094E3ULL,
		0xC681702F4C478777ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA8C97E05158CD468ULL,
		0x3AB8EE29C104056DULL,
		0xDF5E686380230FCAULL,
		0x824F664358B704E9ULL,
		0x4E399BA67D6223ADULL,
		0x777937D9E22F9609ULL,
		0x000C681702F4C478ULL,
		0x0000000000000000ULL
	}};
	shift = 12;
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
		0x1ACC23E70447786AULL,
		0x0DA2004E27C232DCULL,
		0x1F9B2D8D99B643BEULL,
		0x487513FE9F1A99B6ULL,
		0x84B4ECE7DEBC243DULL,
		0x9549B2105A9015A5ULL,
		0x43D4C1CCF1E34972ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x801389F08CB706B3ULL,
		0xCB63666D90EF8368ULL,
		0x44FFA7C6A66D87E6ULL,
		0x3B39F7AF090F521DULL,
		0x6C8416A40569612DULL,
		0x30733C78D25CA552ULL,
		0x00000000000010F5ULL,
		0x0000000000000000ULL
	}};
	shift = 50;
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
		0xE7B2D8064C64BE3BULL,
		0x91369D7E76383F33ULL,
		0x17CF43B1BA22435DULL,
		0x6D27B15C0DDB35E6ULL,
		0xAD73375750C2E117ULL,
		0xA68A07287B541488ULL,
		0x4D363B1C9DBBBA52ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1F99F3D96C032632ULL,
		0x21AEC89B4EBF3B1CULL,
		0x9AF30BE7A1D8DD11ULL,
		0x708BB693D8AE06EDULL,
		0x0A4456B99BABA861ULL,
		0xDD29534503943DAAULL,
		0x0000269B1D8E4EDDULL,
		0x0000000000000000ULL
	}};
	shift = 17;
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
		0x81C5DD525104B103ULL,
		0x9592C0ED5A2B0816ULL,
		0x2427566BFD5265DFULL,
		0xD1673B6B86227EEFULL,
		0x5E970DE8D4985495ULL,
		0x17AF4DFE71616DF1ULL,
		0xCAC99981FA1DFC94ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x64B03B568AC205A0ULL,
		0x09D59AFF549977E5ULL,
		0x59CEDAE1889FBBC9ULL,
		0xA5C37A3526152574ULL,
		0xEBD37F9C585B7C57ULL,
		0xB266607E877F2505ULL,
		0x0000000000000032ULL,
		0x0000000000000000ULL
	}};
	shift = 58;
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
		0x0601003FCEAD85A7ULL,
		0x1B4D321E499C0D75ULL,
		0xB8D6EAAD8CA21670ULL,
		0x788BBB9F6EF1ADE6ULL,
		0x6F9E63CAE75560C9ULL,
		0x7DC8267730D12318ULL,
		0x19404608B00CB92FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x93381AEA0C02007FULL,
		0x19442CE0369A643CULL,
		0xDDE35BCD71ADD55BULL,
		0xCEAAC192F117773EULL,
		0x61A24630DF3CC795ULL,
		0x6019725EFB904CEEULL,
		0x0000000032808C11ULL,
		0x0000000000000000ULL
	}};
	shift = 31;
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
		0xB02719CFFAC6DDD8ULL,
		0x22A9C468F3D3ED62ULL,
		0x538D0ACB377E3037ULL,
		0x0B8011A84C566D47ULL,
		0x2AF468CE49026CCEULL,
		0x4F9C9E40C51ED04DULL,
		0x78DA71D7A81751BEULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2B02719CFFAC6DDDULL,
		0x722A9C468F3D3ED6ULL,
		0x7538D0ACB377E303ULL,
		0xE0B8011A84C566D4ULL,
		0xD2AF468CE49026CCULL,
		0xE4F9C9E40C51ED04ULL,
		0x078DA71D7A81751BULL,
		0x0000000000000000ULL
	}};
	shift = 4;
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
		0x16853700187275FCULL,
		0xADC5EDDEED0FA27DULL,
		0xF71AC439CD5255CEULL,
		0x1E5264A9DBD12AA9ULL,
		0xAB71D1DD00C9DF95ULL,
		0xC56C4EF15FC033C0ULL,
		0x178F1A9B5696A25CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7BB43E89F45A14DCULL,
		0xE73549573AB717B7ULL,
		0xA76F44AAA7DC6B10ULL,
		0x7403277E54794992ULL,
		0xC57F00CF02ADC747ULL,
		0x6D5A5A897315B13BULL,
		0x00000000005E3C6AULL,
		0x0000000000000000ULL
	}};
	shift = 38;
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
		0x79A1260F2D6A8728ULL,
		0x0962A86274F48D29ULL,
		0xED339D719757D1CFULL,
		0xE25F1809A8F80BD6ULL,
		0x3AB36C511C65BCA8ULL,
		0x08C40C1097391E09ULL,
		0x433EEC313D4593F6ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0C4E9E91A52F3424ULL,
		0xAE32EAFA39E12C55ULL,
		0x01351F017ADDA673ULL,
		0x8A238CB7951C4BE3ULL,
		0x8212E723C127566DULL,
		0x8627A8B27EC11881ULL,
		0x00000000000867DDULL,
		0x0000000000000000ULL
	}};
	shift = 43;
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
		0xDEBC2E3876341BE4ULL,
		0x73F5FB63EFCEF481ULL,
		0xC3F5F4F50316C933ULL,
		0x9C515EA666ED5D11ULL,
		0xC4ECB8D38BDF8BB6ULL,
		0xA93B193D536B6B46ULL,
		0x15A1D753DC08BECEULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF6C7DF9DE903BD78ULL,
		0xE9EA062D9266E7EBULL,
		0xBD4CCDDABA2387EBULL,
		0x71A717BF176D38A2ULL,
		0x327AA6D6D68D89D9ULL,
		0xAEA7B8117D9D5276ULL,
		0x0000000000002B43ULL,
		0x0000000000000000ULL
	}};
	shift = 47;
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
		0x613902BA5954019DULL,
		0xBDAE47E8AB9D7C1AULL,
		0xDC29169105DE9C63ULL,
		0x2420903764E52E61ULL,
		0x9021DBFCC09CBDAFULL,
		0x7090AA68746A780BULL,
		0xDDC9C34AA7CFA36DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x47E8AB9D7C1A6139ULL,
		0x169105DE9C63BDAEULL,
		0x903764E52E61DC29ULL,
		0xDBFCC09CBDAF2420ULL,
		0xAA68746A780B9021ULL,
		0xC34AA7CFA36D7090ULL,
		0x000000000000DDC9ULL,
		0x0000000000000000ULL
	}};
	shift = 48;
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
		0x50B7278BA34C61B2ULL,
		0xFD10936B4CEBC067ULL,
		0xED33FC423D04C8DBULL,
		0x4CBD45889053EEE1ULL,
		0x83F29207A6E4F2C6ULL,
		0x31A51E966BD11CF3ULL,
		0x6AF9944FE81146D8ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEBC06750B7278BA3ULL,
		0x04C8DBFD10936B4CULL,
		0x53EEE1ED33FC423DULL,
		0xE4F2C64CBD458890ULL,
		0xD11CF383F29207A6ULL,
		0x1146D831A51E966BULL,
		0x0000006AF9944FE8ULL,
		0x0000000000000000ULL
	}};
	shift = 24;
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
		0xE7CCE1DBC4E460B8ULL,
		0x74813CAF79A50451ULL,
		0xD21FF773571BDBD9ULL,
		0x5E632FE8B0F9E623ULL,
		0x1AB71E94133C9D16ULL,
		0xFF7C9C7D8DC83000ULL,
		0x680F2431F1FF794DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x95EF34A08A3CF99CULL,
		0xEE6AE37B7B2E9027ULL,
		0xFD161F3CC47A43FEULL,
		0xD2826793A2CBCC65ULL,
		0x8FB1B906000356E3ULL,
		0x863E3FEF29BFEF93ULL,
		0x00000000000D01E4ULL,
		0x0000000000000000ULL
	}};
	shift = 43;
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
		0x3B6C3B074E6AD671ULL,
		0x76A3944B42BF998AULL,
		0x829A112E8B6E362FULL,
		0x92EEC7B2C5BB549DULL,
		0x2BC43ACA9F03FB3EULL,
		0xB8B98C4118955B24ULL,
		0x9B6E26DD39FCE5EBULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x25A15FCCC51DB61DULL,
		0x9745B71B17BB51CAULL,
		0xD962DDAA4EC14D08ULL,
		0x654F81FD9F497763ULL,
		0x208C4AAD9215E21DULL,
		0x6E9CFE72F5DC5CC6ULL,
		0x00000000004DB713ULL,
		0x0000000000000000ULL
	}};
	shift = 41;
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
		0x7BF477A96396C768ULL,
		0x79720156CABB558DULL,
		0x4EB35397A43FBAA9ULL,
		0x34B98FE6F70D4106ULL,
		0xAD1F89289A287F42ULL,
		0x92C6C988D3358987ULL,
		0x6DC80E7D761541A7ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5B2AED5635EFD1DEULL,
		0x5E90FEEAA5E5C805ULL,
		0x9BDC3504193ACD4EULL,
		0xA268A1FD08D2E63FULL,
		0x234CD6261EB47E24ULL,
		0xF5D855069E4B1B26ULL,
		0x0000000001B72039ULL,
		0x0000000000000000ULL
	}};
	shift = 38;
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
		0x4EB2E4095046D5AEULL,
		0xE5A53DD0286DEA28ULL,
		0x07A32110431D4367ULL,
		0x3EEA91B38D465B1BULL,
		0x38E6AAB5C3BD14BCULL,
		0x28818E32475E76ACULL,
		0x879A6707BE97588CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x51427597204A8236ULL,
		0x1B3F2D29EE81436FULL,
		0xD8D83D19088218EAULL,
		0xA5E1F7548D9C6A32ULL,
		0xB561C73555AE1DE8ULL,
		0xC461440C71923AF3ULL,
		0x00043CD3383DF4BAULL,
		0x0000000000000000ULL
	}};
	shift = 13;
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
		0xB79F1EACA5767905ULL,
		0xE635CB881A64452CULL,
		0xC557B5643FE23563ULL,
		0x65CE232AF5BAC276ULL,
		0x9628261C59AF833BULL,
		0x54D006E2842BCBB1ULL,
		0x05584F3D1D480F25ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x222965BCF8F5652BULL,
		0x11AB1F31AE5C40D3ULL,
		0xD613B62ABDAB21FFULL,
		0x7C19DB2E711957ADULL,
		0x5E5D8CB14130E2CDULL,
		0x40792AA680371421ULL,
		0x0000002AC279E8EAULL,
		0x0000000000000000ULL
	}};
	shift = 21;
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
		0xFD038B2D91A857FAULL,
		0xEAF384E3526F64DDULL,
		0x8774B51BDF7DC2DCULL,
		0x0CA9FEBCA0AA3E96ULL,
		0x478B94D02EEF9856ULL,
		0x8F8F8E1D84C983BAULL,
		0x446B7C7B1D10E791ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF384E3526F64DDFDULL,
		0x74B51BDF7DC2DCEAULL,
		0xA9FEBCA0AA3E9687ULL,
		0x8B94D02EEF98560CULL,
		0x8F8E1D84C983BA47ULL,
		0x6B7C7B1D10E7918FULL,
		0x0000000000000044ULL,
		0x0000000000000000ULL
	}};
	shift = 56;
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
		0xDFCF0FB69F22F9C4ULL,
		0x7DCDE89147D54731ULL,
		0x2A4765728A0D4145ULL,
		0xFD682F20ABAE09B4ULL,
		0x9AAC9DE26B384F4FULL,
		0x77D2680CB534F548ULL,
		0xF66D0E51FDF132BAULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x398EFE787DB4F917ULL,
		0x0A2BEE6F448A3EAAULL,
		0x4DA1523B2B94506AULL,
		0x7A7FEB4179055D70ULL,
		0xAA44D564EF1359C2ULL,
		0x95D3BE934065A9A7ULL,
		0x0007B368728FEF89ULL,
		0x0000000000000000ULL
	}};
	shift = 13;
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
		0x592BAD973BC5ABD0ULL,
		0xB6BCE84D4D93AF7EULL,
		0xED58EF616A7397AAULL,
		0x2A5DB152451DBBD5ULL,
		0xCF88A60B9E202495ULL,
		0x003BA275D4E6E9B8ULL,
		0x0AF469914837704FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF3A135364EBDF964ULL,
		0x63BD85A9CE5EAADAULL,
		0x76C5491476EF57B5ULL,
		0x22982E78809254A9ULL,
		0xEE89D7539BA6E33EULL,
		0xD1A64520DDC13C00ULL,
		0x000000000000002BULL,
		0x0000000000000000ULL
	}};
	shift = 54;
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
		0x3F15426DF38D8ABAULL,
		0x6F3D43E9A6E62C93ULL,
		0x644738D460E5A636ULL,
		0x01F0865B2E792D88ULL,
		0x9312DDC0DAB3ABFAULL,
		0x3DAD86DFFE0FD6F6ULL,
		0xDF4D1C4ACC81A5E1ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB98B24CFC5509B7CULL,
		0x39698D9BCF50FA69ULL,
		0x9E4B621911CE3518ULL,
		0xACEAFE807C2196CBULL,
		0x83F5BDA4C4B77036ULL,
		0x2069784F6B61B7FFULL,
		0x00000037D34712B3ULL,
		0x0000000000000000ULL
	}};
	shift = 26;
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
		0xDAB6EA53D7D8EAFEULL,
		0x41873C48686E5E67ULL,
		0x7322DF8D7C6D40F5ULL,
		0xA497AA57B57E66F2ULL,
		0xB5F2B382BD05A5BBULL,
		0x9003C20EA55D6EF1ULL,
		0xF6AD19E416906439ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x372F33ED5B7529EBULL,
		0x36A07AA0C39E2434ULL,
		0xBF337939916FC6BEULL,
		0x82D2DDD24BD52BDAULL,
		0xAEB778DAF959C15EULL,
		0x48321CC801E10752ULL,
		0x0000007B568CF20BULL,
		0x0000000000000000ULL
	}};
	shift = 25;
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
		0xB03FD3FA9117C600ULL,
		0x2A0C9A2144D501FBULL,
		0xF1828E4E101402ABULL,
		0x181EAA30C995C084ULL,
		0x498081EAEA6F8754ULL,
		0x8A05B5CAA6FFACE5ULL,
		0x701FCF74C24F5822ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x144D501FBB03FD3FULL,
		0xE101402AB2A0C9A2ULL,
		0x0C995C084F1828E4ULL,
		0xAEA6F8754181EAA3ULL,
		0xAA6FFACE5498081EULL,
		0x4C24F58228A05B5CULL,
		0x000000000701FCF7ULL,
		0x0000000000000000ULL
	}};
	shift = 36;
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
		0x36AF82997E70871BULL,
		0xE1E143822795D428ULL,
		0x633D62661F46C428ULL,
		0xC9F9B5456FE857C4ULL,
		0xADDFD3886F478530ULL,
		0x6036269415136C7DULL,
		0x39B7E423E5B5FBFCULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEA141B57C14CBF38ULL,
		0x621470F0A1C113CAULL,
		0x2BE2319EB1330FA3ULL,
		0xC29864FCDAA2B7F4ULL,
		0xB63ED6EFE9C437A3ULL,
		0xFDFE301B134A0A89ULL,
		0x00001CDBF211F2DAULL,
		0x0000000000000000ULL
	}};
	shift = 17;
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
		0x3262C8B8C24321AFULL,
		0x3BFB55A74222FA9DULL,
		0x8C72A470EAEE9415ULL,
		0xAF6F114B6A664032ULL,
		0xA6CC6E801227DCC5ULL,
		0x62D0E1CFA0E2BE95ULL,
		0x0C02AE134C401A34ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9D3262C8B8C24321ULL,
		0x153BFB55A74222FAULL,
		0x328C72A470EAEE94ULL,
		0xC5AF6F114B6A6640ULL,
		0x95A6CC6E801227DCULL,
		0x3462D0E1CFA0E2BEULL,
		0x000C02AE134C401AULL,
		0x0000000000000000ULL
	}};
	shift = 8;
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
		0x1017F6AC50E9E049ULL,
		0xED84D56852A1AD14ULL,
		0x4405EF675F6111ACULL,
		0x80FC828F33C6664BULL,
		0x753BB4D7582B8614ULL,
		0x7D95B1A5FFC7DDDAULL,
		0x719017CAD220659CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8202FED58A1D3C09ULL,
		0x9DB09AAD0A5435A2ULL,
		0x6880BDECEBEC2235ULL,
		0x901F9051E678CCC9ULL,
		0x4EA7769AEB0570C2ULL,
		0x8FB2B634BFF8FBBBULL,
		0x0E3202F95A440CB3ULL,
		0x0000000000000000ULL
	}};
	shift = 3;
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
		0x96CB352ADB20DA1AULL,
		0x728F58FDDBD7DEDAULL,
		0x222D5FA466C6ED36ULL,
		0x60CDC5B0BAC4E8A3ULL,
		0x130BBBC0852659B0ULL,
		0xF0DE10717AA82E52ULL,
		0xD4F3CE7A3C790486ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEBEF6D4B659A956DULL,
		0x63769B3947AC7EEDULL,
		0x6274519116AFD233ULL,
		0x932CD83066E2D85DULL,
		0x5417290985DDE042ULL,
		0x3C8243786F0838BDULL,
		0x0000006A79E73D1EULL,
		0x0000000000000000ULL
	}};
	shift = 25;
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
		0xFB736E5360EB0577ULL,
		0x45B02E7CA4C7AFECULL,
		0xC0C0644143DBE3F2ULL,
		0xD03E27279AA8DE9AULL,
		0x56C4F9B41AB44FBFULL,
		0x47BABB09DE4690FFULL,
		0x2E586B66323A60ADULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3E5263D7F67DB9B7ULL,
		0x20A1EDF1F922D817ULL,
		0x93CD546F4D606032ULL,
		0xDA0D5A27DFE81F13ULL,
		0x84EF23487FAB627CULL,
		0xB3191D3056A3DD5DULL,
		0x0000000000172C35ULL,
		0x0000000000000000ULL
	}};
	shift = 41;
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
		0xEB1A73CDDA4C85D0ULL,
		0xC9C1948D3FC3E1DDULL,
		0x3113AF6758384198ULL,
		0x86835A93E8642EFAULL,
		0x90DF694B3D877FC6ULL,
		0x3FA7584925096020ULL,
		0x1FF7EB90F5BE6404ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD3FC3E1DDEB1A73CULL,
		0x758384198C9C1948ULL,
		0x3E8642EFA3113AF6ULL,
		0xB3D877FC686835A9ULL,
		0x92509602090DF694ULL,
		0x0F5BE64043FA7584ULL,
		0x0000000001FF7EB9ULL,
		0x0000000000000000ULL
	}};
	shift = 36;
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
		0xAEF37009BDA0C7CEULL,
		0x4381C19BFBF4B63EULL,
		0x5E59599F6C4139C8ULL,
		0xE88B9CC38904915FULL,
		0xAD0296EFB8D6BF19ULL,
		0xD3284AE628A566C2ULL,
		0x7F9ECE9F13092382ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1F5779B804DED063ULL,
		0xE421C0E0CDFDFA5BULL,
		0xAFAF2CACCFB6209CULL,
		0x8CF445CE61C48248ULL,
		0x6156814B77DC6B5FULL,
		0xC1699425731452B3ULL,
		0x003FCF674F898491ULL,
		0x0000000000000000ULL
	}};
	shift = 9;
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
		0x242C82B99FACD4D3ULL,
		0xC551711C1C8561A7ULL,
		0x1542071A08F9DCFEULL,
		0x66E6B3763195CCC1ULL,
		0xA3546EDFF49FED8FULL,
		0x80A1CE3E4AA5750BULL,
		0x4D0863CE894F5169ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1711C1C8561A7242ULL,
		0x2071A08F9DCFEC55ULL,
		0x6B3763195CCC1154ULL,
		0x46EDFF49FED8F66EULL,
		0x1CE3E4AA5750BA35ULL,
		0x863CE894F516980AULL,
		0x00000000000004D0ULL,
		0x0000000000000000ULL
	}};
	shift = 52;
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
		0x519C9CCE06387C83ULL,
		0xF1732944473DA8C7ULL,
		0x051B8B404D3224FDULL,
		0x8410CD03392A6A05ULL,
		0xE7E6B2B5C4C261A6ULL,
		0xE874EB6CA87B6503ULL,
		0xE1A112EC462F163BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x88E7B518EA339399ULL,
		0x09A6449FBE2E6528ULL,
		0x67254D40A0A37168ULL,
		0xB8984C34D08219A0ULL,
		0x950F6CA07CFCD656ULL,
		0x88C5E2C77D0E9D6DULL,
		0x000000001C34225DULL,
		0x0000000000000000ULL
	}};
	shift = 35;
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
		0x8069783195EB9F91ULL,
		0xB52EB4C99DE26268ULL,
		0x251454B15FAB67D1ULL,
		0x4B725FCB9679E763ULL,
		0xF899BC0B30F19194ULL,
		0x5B382B61978C685CULL,
		0x495AE68CD1CDB597ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6A5D69933BC4C4D1ULL,
		0x4A28A962BF56CFA3ULL,
		0x96E4BF972CF3CEC6ULL,
		0xF133781661E32328ULL,
		0xB67056C32F18D0B9ULL,
		0x92B5CD19A39B6B2EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 63;
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
		0xB793356BA53C09D9ULL,
		0xDC9F7CCCC11C29D9ULL,
		0x863D4978DA6E2EAAULL,
		0x9DE7D42FD2AC16A7ULL,
		0xBA888997E160230EULL,
		0x40532920D593B365ULL,
		0x899CFB441A794845ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7DF3330470A766DEULL,
		0xF525E369B8BAAB72ULL,
		0x9F50BF4AB05A9E18ULL,
		0x22265F85808C3A77ULL,
		0x4CA483564ECD96EAULL,
		0x73ED1069E5211501ULL,
		0x0000000000000226ULL,
		0x0000000000000000ULL
	}};
	shift = 54;
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
		0x80BA147089BBDD88ULL,
		0xD5B150E34D30E36BULL,
		0xBB5E719D129D3587ULL,
		0x022F4B783C51A4E9ULL,
		0xB5757E2B1AB6DE20ULL,
		0xA45C701C9B3794C0ULL,
		0x9998B380D6DF46D3ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD34C38DAE02E851CULL,
		0x44A74D61F56C5438ULL,
		0x0F14693A6ED79C67ULL,
		0xC6ADB788008BD2DEULL,
		0x26CDE5302D5D5F8AULL,
		0x35B7D1B4E9171C07ULL,
		0x0000000026662CE0ULL,
		0x0000000000000000ULL
	}};
	shift = 34;
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
		0x0B75FA47B9E24D01ULL,
		0xBEA27A69A3BE285EULL,
		0x10AADB1222901C97ULL,
		0xC0EA574FC89A1369ULL,
		0x833069DDD9B1C02EULL,
		0xB222C54278C82E01ULL,
		0x0F0F535FC7577F28ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3477C50BC16EBF48ULL,
		0x44520392F7D44F4DULL,
		0xF913426D22155B62ULL,
		0xBB363805D81D4AE9ULL,
		0x4F1905C030660D3BULL,
		0xF8EAEFE5164458A8ULL,
		0x0000000001E1EA6BULL,
		0x0000000000000000ULL
	}};
	shift = 35;
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
		0x600BE0FAFAE8608EULL,
		0x99B8091466FF0F65ULL,
		0x5FF14D7204FA19B1ULL,
		0x4F37800BFBC237F9ULL,
		0x019A4F4FE532652EULL,
		0x53F094A46CCCD5C0ULL,
		0xDE70C8D24D866F53ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x19BFC3D95802F83EULL,
		0x813E866C666E0245ULL,
		0xFEF08DFE57FC535CULL,
		0xF94C994B93CDE002ULL,
		0x1B333570006693D3ULL,
		0x93619BD4D4FC2529ULL,
		0x00000000379C3234ULL,
		0x0000000000000000ULL
	}};
	shift = 34;
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
		0x3AF5DCDB1E9944C6ULL,
		0xF44C86220C078C15ULL,
		0x0753339DBEF05AFDULL,
		0xC8892CCC4A201A5CULL,
		0xE5C48BFE60626F7DULL,
		0x050C47BB5B72CB6DULL,
		0x47FAAB2972D502B2ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x182A75EBB9B63D32ULL,
		0xB5FBE8990C44180FULL,
		0x34B80EA6673B7DE0ULL,
		0xDEFB911259989440ULL,
		0x96DBCB8917FCC0C4ULL,
		0x05640A188F76B6E5ULL,
		0x00008FF55652E5AAULL,
		0x0000000000000000ULL
	}};
	shift = 15;
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
		0x459DBA082BD5EC01ULL,
		0xBDA3D27F9A0B8A6BULL,
		0x60F964D686FC43B4ULL,
		0xB00E4176E3A54B76ULL,
		0x62275A8F6B04D4A5ULL,
		0x786C7A0DB9B74F00ULL,
		0xBFBFE3F01F901C90ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9A0B8A6B459DBA08ULL,
		0x86FC43B4BDA3D27FULL,
		0xE3A54B7660F964D6ULL,
		0x6B04D4A5B00E4176ULL,
		0xB9B74F0062275A8FULL,
		0x1F901C90786C7A0DULL,
		0x00000000BFBFE3F0ULL,
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
		0x14B4BF95DA172575ULL,
		0x40F8FEBE4757911AULL,
		0x51EB7389F72BAE22ULL,
		0x8C4D419D433823E9ULL,
		0x770A555C1D7E91BBULL,
		0x22E7B34D2EE3B3FBULL,
		0x9AF2798494D4E6C2ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF223429697F2BB42ULL,
		0x75C4481F1FD7C8EAULL,
		0x047D2A3D6E713EE5ULL,
		0xD2377189A833A867ULL,
		0x767F6EE14AAB83AFULL,
		0x9CD8445CF669A5DCULL,
		0x0000135E4F30929AULL,
		0x0000000000000000ULL
	}};
	shift = 19;
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
		0x99D49B18F00FB6F8ULL,
		0xC34A79F4AF635586ULL,
		0x8D3D620540735C9BULL,
		0x289699CE890B50D9ULL,
		0x90CD9FED28985D93ULL,
		0x6B354FCF540FB7A2ULL,
		0x969CCE71940D0FE1ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8D561A67526C63C0ULL,
		0xCD726F0D29E7D2BDULL,
		0x2D436634F5881501ULL,
		0x61764CA25A673A24ULL,
		0x3EDE8A43367FB4A2ULL,
		0x343F85ACD53F3D50ULL,
		0x0000025A7339C650ULL,
		0x0000000000000000ULL
	}};
	shift = 22;
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
		0xBCBB2C72C8C3B7A2ULL,
		0xC4FEABFC15FD88CCULL,
		0xC3E2751FE7DD36BEULL,
		0xD6F972C6BA681C03ULL,
		0xDA346CCCA81AC964ULL,
		0x026442D0EC38AC87ULL,
		0x66D723418E05BEA3ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEC4665E5D9639646ULL,
		0xE9B5F627F55FE0AFULL,
		0x40E01E1F13A8FF3EULL,
		0xD64B26B7CB9635D3ULL,
		0xC5643ED1A3666540ULL,
		0x2DF5181322168761ULL,
		0x00000336B91A0C70ULL,
		0x0000000000000000ULL
	}};
	shift = 21;
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
		0x8853D24FDE207A4EULL,
		0x189ADA8FD0B0D769ULL,
		0xCC6646F72192831CULL,
		0xB019F3FC4BC9E7A2ULL,
		0x9D57EB94C2B33786ULL,
		0xFE59D7BE2BC06251ULL,
		0x9133113729524D74ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1AED310A7A49FBC4ULL,
		0x506383135B51FA16ULL,
		0x3CF4598CC8DEE432ULL,
		0x66F0D6033E7F8979ULL,
		0x0C4A33AAFD729856ULL,
		0x49AE9FCB3AF7C578ULL,
		0x000012266226E52AULL,
		0x0000000000000000ULL
	}};
	shift = 19;
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
		0x9E866C49CBA766F9ULL,
		0x451785ED9B6FCD83ULL,
		0xE4280792D51C4968ULL,
		0xDE7591977E5CF6E6ULL,
		0x63778AFAA01C35FEULL,
		0x7AF4D5EB84416FF5ULL,
		0xAF674651F21567DAULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xED9B6FCD839E866CULL,
		0x92D51C4968451785ULL,
		0x977E5CF6E6E42807ULL,
		0xFAA01C35FEDE7591ULL,
		0xEB84416FF563778AULL,
		0x51F21567DA7AF4D5ULL,
		0x0000000000AF6746ULL,
		0x0000000000000000ULL
	}};
	shift = 40;
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
		0x396CBC951FAE81F9ULL,
		0x2EEBE4E80CCA2D86ULL,
		0xF834BF112A7FCBB1ULL,
		0x878C483F9D5B2E76ULL,
		0x8AECF0ADFD51E7C5ULL,
		0x516F59EAB2EF54FAULL,
		0x3C50D704D08EDAE6ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x328B618E5B2F2547ULL,
		0x9FF2EC4BBAF93A03ULL,
		0x56CB9DBE0D2FC44AULL,
		0x5479F161E3120FE7ULL,
		0xBBD53EA2BB3C2B7FULL,
		0x23B6B9945BD67AACULL,
		0x0000000F1435C134ULL,
		0x0000000000000000ULL
	}};
	shift = 26;
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
		0x306D5A766F31DEB3ULL,
		0x9CCFD1811BC5010BULL,
		0x776B513E295EB017ULL,
		0xF546E6C634456A50ULL,
		0xCE916165F4E27E01ULL,
		0x1591C544310FD75DULL,
		0xD238A38A8E4E51CAULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x042CC1B569D9BCC7ULL,
		0xC05E733F46046F14ULL,
		0xA941DDAD44F8A57AULL,
		0xF807D51B9B18D115ULL,
		0x5D773A458597D389ULL,
		0x472856471510C43FULL,
		0x000348E28E2A3939ULL,
		0x0000000000000000ULL
	}};
	shift = 14;
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
		0xA7884164D5F7AD08ULL,
		0x1A65282689992849ULL,
		0x302B84E6BDB3F832ULL,
		0xE41238973FE7238DULL,
		0x28310528737751D0ULL,
		0x4506F86FE055F1A6ULL,
		0x734C96F135468DB9ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x133250934F1082C9ULL,
		0x7B67F06434CA504DULL,
		0x7FCE471A605709CDULL,
		0xE6EEA3A1C824712EULL,
		0xC0ABE34C50620A50ULL,
		0x6A8D1B728A0DF0DFULL,
		0x00000000E6992DE2ULL,
		0x0000000000000000ULL
	}};
	shift = 31;
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
		0x24A32BABF229BD88ULL,
		0x730470D1D02EDA34ULL,
		0xC229361C302ADDF7ULL,
		0xE01ED5A6127A1335ULL,
		0x822A8AC9A14768C4ULL,
		0x48DE7A007C4A028DULL,
		0x37E31A4E2964A80FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x125195D5F914DEC4ULL,
		0xB9823868E8176D1AULL,
		0xE1149B0E18156EFBULL,
		0x700F6AD3093D099AULL,
		0xC1154564D0A3B462ULL,
		0xA46F3D003E250146ULL,
		0x1BF18D2714B25407ULL,
		0x0000000000000000ULL
	}};
	shift = 1;
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
		0x41389E6E3ACCED71ULL,
		0x5309E92736192047ULL,
		0xC78AC907ADF8A230ULL,
		0x9C4EB2EBA3261022ULL,
		0xBC5301AF9ACB0D59ULL,
		0x06ED42F0FD5FEE2FULL,
		0xADEF22F9398ABDB8ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9B0C9023A09C4F37ULL,
		0xD6FC51182984F493ULL,
		0xD193081163C56483ULL,
		0xCD6586ACCE275975ULL,
		0x7EAFF717DE2980D7ULL,
		0x9CC55EDC0376A178ULL,
		0x0000000056F7917CULL,
		0x0000000000000000ULL
	}};
	shift = 33;
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
		0x03F1FB242E8875D7ULL,
		0xFC56E28F966BA09DULL,
		0x7DEA4904A367F86BULL,
		0x708855ADD4483C1AULL,
		0xCC1D699ABFBB9E93ULL,
		0x9F8DD0B1F208C409ULL,
		0xAC0064CCA012F901ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAE82740FC7EC90BAULL,
		0x9FE1AFF15B8A3E59ULL,
		0x20F069F7A924128DULL,
		0xEE7A4DC22156B751ULL,
		0x2310273075A66AFEULL,
		0x4BE4067E3742C7C8ULL,
		0x000002B001933280ULL,
		0x0000000000000000ULL
	}};
	shift = 22;
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
		0xA99E574B065DF25DULL,
		0xDEF6511ABD42BD79ULL,
		0x378B270B59FF427CULL,
		0x0D2E56118E442758ULL,
		0x3E5E605CD79B1453ULL,
		0x18B47EED982C6D38ULL,
		0x977DAAF92EF8D081ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7AF3533CAE960CBBULL,
		0x84F9BDECA2357A85ULL,
		0x4EB06F164E16B3FEULL,
		0x28A61A5CAC231C88ULL,
		0xDA707CBCC0B9AF36ULL,
		0xA1023168FDDB3058ULL,
		0x00012EFB55F25DF1ULL,
		0x0000000000000000ULL
	}};
	shift = 15;
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
		0xD9FDE845CD61E64EULL,
		0x265275307634A149ULL,
		0xBD8D443401C85457ULL,
		0x617AAD648866A6EDULL,
		0xFB114170E51A15C8ULL,
		0xFC4EB358F20BFAEEULL,
		0x4372CCAC7892C6E8ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x49D4C1D8D2852767ULL,
		0x3510D00721515C99ULL,
		0xEAB592219A9BB6F6ULL,
		0x4505C39468572185ULL,
		0x3ACD63C82FEBBBECULL,
		0xCB32B1E24B1BA3F1ULL,
		0x000000000000010DULL,
		0x0000000000000000ULL
	}};
	shift = 54;
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
		0xABDC694FC9CFFF62ULL,
		0x38C8EE3D5B8C6AACULL,
		0x563CDF425B6295A3ULL,
		0x5AFF14518D245997ULL,
		0x0CD7EBD90147469BULL,
		0x4152C9A74FEEF791ULL,
		0x83D6389575A1B9EBULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xADC6355655EE34A7ULL,
		0x2DB14AD19C64771EULL,
		0xC6922CCBAB1E6FA1ULL,
		0x80A3A34DAD7F8A28ULL,
		0xA7F77BC8866BF5ECULL,
		0xBAD0DCF5A0A964D3ULL,
		0x0000000041EB1C4AULL,
		0x0000000000000000ULL
	}};
	shift = 33;
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
		0xDB6BA3D258E746F2ULL,
		0x2C7019A97C75928EULL,
		0xF9D3A0083BD101A5ULL,
		0x4EAE8C5019D6323CULL,
		0xB2421834C14DFF7AULL,
		0xA802BDB53F6E9B8DULL,
		0x64B3C4D23252B3D9ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x66A5F1D64A3B6DAEULL,
		0x8020EF440694B1C0ULL,
		0x31406758C8F3E74EULL,
		0x60D30537FDE93ABAULL,
		0xF6D4FDBA6E36C908ULL,
		0x1348C94ACF66A00AULL,
		0x00000000000192CFULL,
		0x0000000000000000ULL
	}};
	shift = 46;
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
		0xE12EB65C9C15FE9CULL,
		0xAD9AABA277BFA331ULL,
		0xC9A257D7BBC2891CULL,
		0x358FBBB403E3BB5FULL,
		0x39C77D241B4C026DULL,
		0x7364BE06D05D64BCULL,
		0xD2EDBA0573C9B37DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7F4663C25D6CB938ULL,
		0x8512395B355744EFULL,
		0xC776BF9344AFAF77ULL,
		0x9804DA6B1F776807ULL,
		0xBAC978738EFA4836ULL,
		0x9366FAE6C97C0DA0ULL,
		0x000001A5DB740AE7ULL,
		0x0000000000000000ULL
	}};
	shift = 23;
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
		0xE699AEACAD6ECDECULL,
		0x0451B8A4D612EB4EULL,
		0x1519AB88E474D943ULL,
		0xF64E99C0000C4D8BULL,
		0x4B04FD2B1E28EB11ULL,
		0x1C991564600D57DBULL,
		0x959B1C6BA27211EAULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB8A4D612EB4EE699ULL,
		0xAB88E474D9430451ULL,
		0x99C0000C4D8B1519ULL,
		0xFD2B1E28EB11F64EULL,
		0x1564600D57DB4B04ULL,
		0x1C6BA27211EA1C99ULL,
		0x000000000000959BULL,
		0x0000000000000000ULL
	}};
	shift = 48;
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
		0x60F180BDD02FE932ULL,
		0x81232C8AE54B9004ULL,
		0x4F2C00F0050506F7ULL,
		0xFE4DD4746FABD05AULL,
		0x67084FBDE3E573F6ULL,
		0xC9672D4E7F4D27A2ULL,
		0x822710BE3CFEEF49ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x048CB22B952E4011ULL,
		0x3CB003C014141BDEULL,
		0xF93751D1BEAF4169ULL,
		0x9C213EF78F95CFDBULL,
		0x259CB539FD349E89ULL,
		0x089C42F8F3FBBD27ULL,
		0x0000000000000002ULL,
		0x0000000000000000ULL
	}};
	shift = 62;
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
		0x7A863D511E431590ULL,
		0x67363011205DD190ULL,
		0x795706CA38F6239DULL,
		0x03EA1216AAC05A75ULL,
		0x44291337379A6424ULL,
		0xCAF4B1B64D145032ULL,
		0x4CCA9DB8761DFD91ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x81774641EA18F544ULL,
		0xE3D88E759CD8C044ULL,
		0xAB0169D5E55C1B28ULL,
		0xDE6990900FA8485AULL,
		0x345140C910A44CDCULL,
		0xD877F6472BD2C6D9ULL,
		0x00000001332A76E1ULL,
		0x0000000000000000ULL
	}};
	shift = 30;
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
		0xE69BCD9377A97420ULL,
		0x22A55C32DE71A12DULL,
		0xD535B03C27EEAB4BULL,
		0x6AF9B7BDF438E86FULL,
		0xABFE29B62A8B0012ULL,
		0x160A84D050062801ULL,
		0x4DF733C01701FC5AULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x79C684B79A6F364DULL,
		0x9FBAAD2C8A9570CBULL,
		0xD0E3A1BF54D6C0F0ULL,
		0xAA2C0049ABE6DEF7ULL,
		0x4018A006AFF8A6D8ULL,
		0x5C07F168582A1341ULL,
		0x0000000137DCCF00ULL,
		0x0000000000000000ULL
	}};
	shift = 30;
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
		0xE9CBDD6FF2442053ULL,
		0x0510C40FCA3D0FE4ULL,
		0x4511B676D14DF8A8ULL,
		0xCE4C2B9C39B8A1C2ULL,
		0x55676A115760FAE9ULL,
		0xCB2BA50EC59722FFULL,
		0x419792CBB6C59B7CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3D0FE4E9CBDD6FF2ULL,
		0x4DF8A80510C40FCAULL,
		0xB8A1C24511B676D1ULL,
		0x60FAE9CE4C2B9C39ULL,
		0x9722FF55676A1157ULL,
		0xC59B7CCB2BA50EC5ULL,
		0x000000419792CBB6ULL,
		0x0000000000000000ULL
	}};
	shift = 24;
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
		0x718C6D047EC061C4ULL,
		0xBFF97365E99768CAULL,
		0x96234400A66A3850ULL,
		0xAE56EBE9C939FD7EULL,
		0xDDC695A18B9DFEDFULL,
		0x970B854C77B3E3AEULL,
		0x756827A407AF1553ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9C631B411FB01871ULL,
		0x2FFE5CD97A65DA32ULL,
		0xA588D100299A8E14ULL,
		0xEB95BAFA724E7F5FULL,
		0xB771A56862E77FB7ULL,
		0xE5C2E1531DECF8EBULL,
		0x1D5A09E901EBC554ULL,
		0x0000000000000000ULL
	}};
	shift = 2;
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
		0xBD05CEFD56967EB7ULL,
		0xCDA4EDE6A6D52790ULL,
		0xA2E12A84C12A9D11ULL,
		0xB95568F30FB36A09ULL,
		0xDA3A04DC1E0D8A2AULL,
		0xFE51D854A4E40EA9ULL,
		0x0E90017C3F6C4C14ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA4EDE6A6D52790BDULL,
		0xE12A84C12A9D11CDULL,
		0x5568F30FB36A09A2ULL,
		0x3A04DC1E0D8A2AB9ULL,
		0x51D854A4E40EA9DAULL,
		0x90017C3F6C4C14FEULL,
		0x000000000000000EULL,
		0x0000000000000000ULL
	}};
	shift = 56;
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
		0x3ED248BFE50E1C7AULL,
		0x14990C23B644307CULL,
		0xFF590A781D370B5AULL,
		0xFF0660829262327DULL,
		0xF53436C5AA2D6CA0ULL,
		0x2626570B7B1BF21BULL,
		0xCE15C4F8D4361B32ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x23B644307C3ED248ULL,
		0x781D370B5A14990CULL,
		0x829262327DFF590AULL,
		0xC5AA2D6CA0FF0660ULL,
		0x0B7B1BF21BF53436ULL,
		0xF8D4361B32262657ULL,
		0x0000000000CE15C4ULL,
		0x0000000000000000ULL
	}};
	shift = 40;
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
		0x83A6D5CEBB593CB3ULL,
		0xB87F0F78DA7C0CE0ULL,
		0xD4DC131500A206FEULL,
		0x6723ACD1A58CA6CAULL,
		0x45BC9A90F272F987ULL,
		0xA9B058F400188933ULL,
		0x027E2AF7151A4752ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBC6D3E067041D36AULL,
		0x8A8051037F5C3F87ULL,
		0x68D2C653656A6E09ULL,
		0x4879397CC3B391D6ULL,
		0x7A000C4499A2DE4DULL,
		0x7B8A8D23A954D82CULL,
		0x0000000000013F15ULL,
		0x0000000000000000ULL
	}};
	shift = 41;
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
		0x7CE14889E365A04EULL,
		0x71AA0CF5E5BCF029ULL,
		0x908EAC88E690C1C4ULL,
		0x92073016C52117F1ULL,
		0xB9A3E3A722F34AABULL,
		0xD1805F21881C16B4ULL,
		0x5F446C0D3FE48A0FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2DE7814BE70A444FULL,
		0x34860E238D5067AFULL,
		0x2908BF8C84756447ULL,
		0x179A555C903980B6ULL,
		0x40E0B5A5CD1F1D39ULL,
		0xFF24507E8C02F90CULL,
		0x00000002FA236069ULL,
		0x0000000000000000ULL
	}};
	shift = 29;
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
		0xDE994267E77D18C0ULL,
		0x218F1068CFD6816CULL,
		0x418B4DD5B69BFE31ULL,
		0x45416C248D9C8701ULL,
		0x3D286A94710BEA9DULL,
		0x9A95EBDCAFBEE599ULL,
		0xD6ACC3DC68470B95ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x63C41A33F5A05B37ULL,
		0x62D3756DA6FF8C48ULL,
		0x505B09236721C050ULL,
		0x4A1AA51C42FAA751ULL,
		0xA57AF72BEFB9664FULL,
		0xAB30F71A11C2E566ULL,
		0x0000000000000035ULL,
		0x0000000000000000ULL
	}};
	shift = 58;
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
		0x88B7EDB398A3AD71ULL,
		0xA212B1300329802FULL,
		0xCF31C97744566003ULL,
		0xE500BE52845AF49DULL,
		0x437C617B95C44322ULL,
		0xB73A761A41DC7B49ULL,
		0xC89324B504118F7BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x600BE22DFB6CE628ULL,
		0x9800E884AC4C00CAULL,
		0xBD2773CC725DD115ULL,
		0x10C8B9402F94A116ULL,
		0x1ED250DF185EE571ULL,
		0x63DEEDCE9D869077ULL,
		0x00003224C92D4104ULL,
		0x0000000000000000ULL
	}};
	shift = 18;
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
		0xC1547F70781CD6AEULL,
		0xA9564E104AEC9761ULL,
		0xB6A60F945804E050ULL,
		0x5ACD9B39BE7BEFBDULL,
		0xBED9750FFFC776BBULL,
		0x636FD28DDFA5CB2CULL,
		0x833E9FFDCF12AB8CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA55938412BB25D87ULL,
		0xDA983E5160138142ULL,
		0x6B366CE6F9EFBEF6ULL,
		0xFB65D43FFF1DDAEDULL,
		0x8DBF4A377E972CB2ULL,
		0x0CFA7FF73C4AAE31ULL,
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
		0x38123F1A1B0C41B5ULL,
		0x4093039F23D0F267ULL,
		0x95284A1088F5748EULL,
		0xA1315E4CB090B7BFULL,
		0xFB5ACB94631C7516ULL,
		0xC2EA15AD22F5E6A1ULL,
		0x52A38059A1EA8BCCULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x073E47A1E4CE7024ULL,
		0x942111EAE91C8126ULL,
		0xBC9961216F7F2A50ULL,
		0x9728C638EA2D4262ULL,
		0x2B5A45EBCD43F6B5ULL,
		0x00B343D5179985D4ULL,
		0x000000000000A547ULL,
		0x0000000000000000ULL
	}};
	shift = 47;
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
		0x32507FDAA5931134ULL,
		0x920EA989B7EE55EFULL,
		0x9E2BAD0DE79492F4ULL,
		0x7567CBF707EC440AULL,
		0x67236462C32E15A6ULL,
		0x7F423425232110EAULL,
		0x40F39EA89054B28CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEF32507FDAA59311ULL,
		0xF4920EA989B7EE55ULL,
		0x0A9E2BAD0DE79492ULL,
		0xA67567CBF707EC44ULL,
		0xEA67236462C32E15ULL,
		0x8C7F423425232110ULL,
		0x0040F39EA89054B2ULL,
		0x0000000000000000ULL
	}};
	shift = 8;
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
		0x86366C7BCC503AD6ULL,
		0x18F212F58F0C6AEBULL,
		0x0F667265E453F636ULL,
		0x20C3BFDE7ECD1B61ULL,
		0xBC46F47A7DDE3E8AULL,
		0x4B33438CA86112E9ULL,
		0x30AB385DD41333A2ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC79097AC7863575CULL,
		0x7B33932F229FB1B0ULL,
		0x061DFEF3F668DB08ULL,
		0xE237A3D3EEF1F451ULL,
		0x599A1C654308974DULL,
		0x8559C2EEA0999D12ULL,
		0x0000000000000001ULL,
		0x0000000000000000ULL
	}};
	shift = 61;
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
		0x911DBDA50D02100DULL,
		0x62F7ADCDE9EEEC58ULL,
		0xE160E25BFF037CB0ULL,
		0x819A2285AE6C05E7ULL,
		0xDCA3FE49B251FC65ULL,
		0xD716BC2DB02B3482ULL,
		0x2187DFFD7F37FC70ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x62C488EDED286810ULL,
		0xE58317BD6E6F4F77ULL,
		0x2F3F0B0712DFF81BULL,
		0xE32C0CD1142D7360ULL,
		0xA416E51FF24D928FULL,
		0xE386B8B5E16D8159ULL,
		0x00010C3EFFEBF9BFULL,
		0x0000000000000000ULL
	}};
	shift = 13;
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
		0x45D8296315C41F07ULL,
		0x8385AD4EA4494CE1ULL,
		0x53A93626B900EA0CULL,
		0xEFF87B0C6CC8ED6AULL,
		0xC290B05C75558C01ULL,
		0xBAD4B090C4004996ULL,
		0x23923BCA67B00EE4ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x851760A58C57107CULL,
		0x320E16B53A912533ULL,
		0xA94EA4D89AE403A8ULL,
		0x07BFE1EC31B323B5ULL,
		0x5B0A42C171D55630ULL,
		0x92EB52C243100126ULL,
		0x008E48EF299EC03BULL,
		0x0000000000000000ULL
	}};
	shift = 6;
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
		0x56D5D6E1E6067AB9ULL,
		0x7A19422D457F32F7ULL,
		0xA715B9D12C02C39FULL,
		0x14E13AD2AB48DD24ULL,
		0xB9B5B9D2FF7C1054ULL,
		0x32C7F9003C2AA0ABULL,
		0xBD38F81DDE6C035EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x45A8AFE65EEADABAULL,
		0x3A25805873EF4328ULL,
		0x5A55691BA494E2B7ULL,
		0x3A5FEF820A829C27ULL,
		0x20078554157736B7ULL,
		0x03BBCD806BC658FFULL,
		0x000000000017A71FULL,
		0x0000000000000000ULL
	}};
	shift = 43;
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
		0x0B4D3B367FA88DF2ULL,
		0x496D8099535D6085ULL,
		0xC52D8FC1236641A8ULL,
		0x3E741F40B733B99BULL,
		0xBF97C1210B74821DULL,
		0x2C7565D92FB155E0ULL,
		0xAEF562B54C5C991DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x142D34ECD9FEA237ULL,
		0xA125B602654D7582ULL,
		0x6F14B63F048D9906ULL,
		0x74F9D07D02DCCEE6ULL,
		0x82FE5F04842DD208ULL,
		0x74B1D59764BEC557ULL,
		0x02BBD58AD5317264ULL,
		0x0000000000000000ULL
	}};
	shift = 6;
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
		0xD9A176935B56A71DULL,
		0x21ED53C987BC8133ULL,
		0xDB881D6EF85FE67FULL,
		0xAE75561B8FD14DA5ULL,
		0xF21A5A234CD44F1CULL,
		0x87DB0D09BDEE8B64ULL,
		0x491F14B4D0256B81ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4099ECD0BB49ADABULL,
		0xF33F90F6A9E4C3DEULL,
		0xA6D2EDC40EB77C2FULL,
		0x278E573AAB0DC7E8ULL,
		0x45B2790D2D11A66AULL,
		0xB5C0C3ED8684DEF7ULL,
		0x0000248F8A5A6812ULL,
		0x0000000000000000ULL
	}};
	shift = 17;
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
		0x11CBAC7CA92341FEULL,
		0x65187C5C83613328ULL,
		0x00EDF1C7DF21239BULL,
		0x16AD816026F456A2ULL,
		0x8D6CDCC087180F49ULL,
		0x1B3C112783C44D9EULL,
		0x18E54601081750FEULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x87C5C8361332811CULL,
		0xDF1C7DF21239B651ULL,
		0xD816026F456A200EULL,
		0xCDCC087180F4916AULL,
		0xC112783C44D9E8D6ULL,
		0x54601081750FE1B3ULL,
		0x000000000000018EULL,
		0x0000000000000000ULL
	}};
	shift = 52;
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
		0xA79068BC9D6E1807ULL,
		0x34F47CB89A092FAAULL,
		0xA4688F4FAD59A14AULL,
		0x2E7066F744112B99ULL,
		0xFC4A39C6F97B0EB4ULL,
		0xAC308288E82A4A48ULL,
		0x44EF57C1B8FC2DFBULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4D0497D553C8345EULL,
		0xD6ACD0A51A7A3E5CULL,
		0xA20895CCD23447A7ULL,
		0x7CBD875A1738337BULL,
		0x741525247E251CE3ULL,
		0xDC7E16FDD6184144ULL,
		0x000000002277ABE0ULL,
		0x0000000000000000ULL
	}};
	shift = 33;
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
		0xB686428C0EFABE59ULL,
		0xE4A6FE5F163F3802ULL,
		0xCEC022E06492A210ULL,
		0x99F5DB651884C7E9ULL,
		0x79E869718881EDEBULL,
		0xA0F5E9062DB6D09BULL,
		0xC2E6F1574B52D4D8ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF97C58FCE00ADA19ULL,
		0x8B81924A8843929BULL,
		0x6D9462131FA73B00ULL,
		0xA5C62207B7AE67D7ULL,
		0xA418B6DB426DE7A1ULL,
		0xC55D2D4B536283D7ULL,
		0x0000000000030B9BULL,
		0x0000000000000000ULL
	}};
	shift = 46;
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
		0x0A0BC5480EEDC02BULL,
		0x2D1EA796F2D3608DULL,
		0x7BFBAB04CD146BDDULL,
		0xEFC3B751DD9AE49AULL,
		0x43F4CBC03E7801B9ULL,
		0x9598CAA146D333C5ULL,
		0x68F6F5E9010B9395ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD1EA796F2D3608D0ULL,
		0xBFBAB04CD146BDD2ULL,
		0xFC3B751DD9AE49A7ULL,
		0x3F4CBC03E7801B9EULL,
		0x598CAA146D333C54ULL,
		0x8F6F5E9010B93959ULL,
		0x0000000000000006ULL,
		0x0000000000000000ULL
	}};
	shift = 60;
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
		0x8435AA6C7BA7CC17ULL,
		0x9DA905242F28831AULL,
		0x71544D92C472BE94ULL,
		0x57BF24DF973849C7ULL,
		0x673AA75B82B19DE5ULL,
		0x06E943300372E855ULL,
		0xD9D133381A495374ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1794418D421AD536ULL,
		0x62395F4A4ED48292ULL,
		0xCB9C24E3B8AA26C9ULL,
		0xC158CEF2ABDF926FULL,
		0x01B9742AB39D53ADULL,
		0x0D24A9BA0374A198ULL,
		0x000000006CE8999CULL,
		0x0000000000000000ULL
	}};
	shift = 33;
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
		0x278451B41CD574CFULL,
		0x7E008364EF1A3183ULL,
		0xA29E7A2E6BA1E9FFULL,
		0x9A3021C10B80E5A2ULL,
		0xABE3D7B3F3AC6182ULL,
		0x6F1C9FB9BAD7A12AULL,
		0xF1CCE7A8B0748434ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3278451B41CD574CULL,
		0xF7E008364EF1A318ULL,
		0x2A29E7A2E6BA1E9FULL,
		0x29A3021C10B80E5AULL,
		0xAABE3D7B3F3AC618ULL,
		0x46F1C9FB9BAD7A12ULL,
		0x0F1CCE7A8B074843ULL,
		0x0000000000000000ULL
	}};
	shift = 4;
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
		0x3ACB4A139C58F6DBULL,
		0xC8B8BCF2579E3677ULL,
		0xC2AF348585A64DBEULL,
		0xC36AC3EE251D9A9AULL,
		0xFE1AB97D3569BF91ULL,
		0x17610547F5A7F76DULL,
		0x84CAEBB21DFAEFD1ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x79E4AF3C6CEE7596ULL,
		0x690B0B4C9B7D9171ULL,
		0x87DC4A3B3535855EULL,
		0x72FA6AD37F2386D5ULL,
		0x0A8FEB4FEEDBFC35ULL,
		0xD7643BF5DFA22EC2ULL,
		0x0000000000010995ULL,
		0x0000000000000000ULL
	}};
	shift = 47;
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
		0x9850B60814B1378CULL,
		0x00FEF2072A9A3E6EULL,
		0x17AFF371802A4015ULL,
		0x8CD9C8236A79A438ULL,
		0x351687115741224CULL,
		0x87F760BD5ED4C33DULL,
		0x4F4E757EC0FEF38BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2072A9A3E6E9850BULL,
		0x371802A401500FEFULL,
		0x8236A79A43817AFFULL,
		0x7115741224C8CD9CULL,
		0x0BD5ED4C33D35168ULL,
		0x57EC0FEF38B87F76ULL,
		0x000000000004F4E7ULL,
		0x0000000000000000ULL
	}};
	shift = 44;
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
		0xCD155ACA2274F895ULL,
		0x0EC57F61FCA3181AULL,
		0xB2A42201B7F023ACULL,
		0x3295F3FDF976C519ULL,
		0xCBACCF7CF0CE1101ULL,
		0x938FAEBB544E892AULL,
		0x027698EA3BCD3EFAULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1ACD155ACA2274F8ULL,
		0xAC0EC57F61FCA318ULL,
		0x19B2A42201B7F023ULL,
		0x013295F3FDF976C5ULL,
		0x2ACBACCF7CF0CE11ULL,
		0xFA938FAEBB544E89ULL,
		0x00027698EA3BCD3EULL,
		0x0000000000000000ULL
	}};
	shift = 8;
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
		0xEB7394774F41D77CULL,
		0x068733FCFF77D4B4ULL,
		0x2C5E44657E57499DULL,
		0x07D748950F4FF298ULL,
		0x24E6DA0E7E9A96AFULL,
		0x500FF621A6342D71ULL,
		0x4BCCABECC00535E8ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9FE7FBBEA5A75B9CULL,
		0x232BF2BA4CE83439ULL,
		0x44A87A7F94C162F2ULL,
		0xD073F4D4B5783EBAULL,
		0xB10D31A16B892736ULL,
		0x5F660029AF42807FULL,
		0x0000000000025E65ULL,
		0x0000000000000000ULL
	}};
	shift = 45;
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
		0x2EE9B8946D371393ULL,
		0xD676C8CC51CC0470ULL,
		0x2CBE8AB67363ABB0ULL,
		0x286D87D7DB21D407ULL,
		0xCF0D15CA17B8601DULL,
		0x25813BD0FDC72065ULL,
		0x8F89ADEF6AF497DAULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0BBA6E251B4DC4E4ULL,
		0x359DB2331473011CULL,
		0xCB2FA2AD9CD8EAECULL,
		0x4A1B61F5F6C87501ULL,
		0x73C3457285EE1807ULL,
		0x89604EF43F71C819ULL,
		0x23E26B7BDABD25F6ULL,
		0x0000000000000000ULL
	}};
	shift = 2;
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
		0x932FA90569F35821ULL,
		0xE98F9B7F79842EDAULL,
		0xD2A209382F80D83BULL,
		0x847915E2F4154E2BULL,
		0x74B02C44CD5043F1ULL,
		0xA116BB9293DBF3C5ULL,
		0xC80E7E2F9742B18FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1F36FEF3085DB526ULL,
		0x4412705F01B077D3ULL,
		0xF22BC5E82A9C57A5ULL,
		0x6058899AA087E308ULL,
		0x2D772527B7E78AE9ULL,
		0x1CFC5F2E85631F42ULL,
		0x0000000000000190ULL,
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
		0x756E7258A79F6774ULL,
		0xFE0324278ACA236FULL,
		0x4E3CCC5176A5F607ULL,
		0x57438FCC792665C4ULL,
		0x4A0A3B2BFE84E71CULL,
		0xFD1D8C1957FA35DFULL,
		0x94A52578A481C40FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBAB7392C53CFB3BAULL,
		0xFF019213C56511B7ULL,
		0x271E6628BB52FB03ULL,
		0x2BA1C7E63C9332E2ULL,
		0xA5051D95FF42738EULL,
		0xFE8EC60CABFD1AEFULL,
		0x4A5292BC5240E207ULL,
		0x0000000000000000ULL
	}};
	shift = 1;
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
		0x2274C67596DA4168ULL,
		0x0193BFF92A997BC5ULL,
		0x63DA4938E7F8CCFAULL,
		0x037C123B6659945AULL,
		0xF4FF58C8F8C9A000ULL,
		0x4E7D401A576F71AFULL,
		0xE169096E67EB8526ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEF1489D319D65B69ULL,
		0x33E8064EFFE4AA65ULL,
		0x51698F6924E39FE3ULL,
		0x80000DF048ED9966ULL,
		0xC6BFD3FD6323E326ULL,
		0x149939F500695DBDULL,
		0x000385A425B99FAEULL,
		0x0000000000000000ULL
	}};
	shift = 14;
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
		0x8136328EFE3399F1ULL,
		0x141D7A4FEE28B0A6ULL,
		0x1956CA55DD29F5ACULL,
		0xE999D06A9CC13837ULL,
		0x10833EB840A6C3F4ULL,
		0x68591F6DF8037309ULL,
		0x840F0A6F8BB39C5BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA4FEE28B0A681363ULL,
		0xA55DD29F5AC141D7ULL,
		0x06A9CC138371956CULL,
		0xEB840A6C3F4E999DULL,
		0xF6DF803730910833ULL,
		0xA6F8BB39C5B68591ULL,
		0x00000000000840F0ULL,
		0x0000000000000000ULL
	}};
	shift = 44;
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
		0x8FDBF62778E80253ULL,
		0x6E93F06A7C1C3B5BULL,
		0x5F3DF51BB211674EULL,
		0x8C2C953DE239143EULL,
		0xA96C1ACD9723D6D1ULL,
		0xA51B87BDFE2AF392ULL,
		0x2A18F6D4DFF771B5ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x749F8353E0E1DADCULL,
		0xF9EFA8DD908B3A73ULL,
		0x6164A9EF11C8A1F2ULL,
		0x4B60D66CB91EB68CULL,
		0x28DC3DEFF1579C95ULL,
		0x50C7B6A6FFBB8DADULL,
		0x0000000000000001ULL,
		0x0000000000000000ULL
	}};
	shift = 61;
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
		0x2F3652FE30842706ULL,
		0xB4CC2527B6F1C881ULL,
		0x29FF05EFC5847E84ULL,
		0xBB8023E48489C8F1ULL,
		0x6BE657407F5382EDULL,
		0x4D729F436F5CB4D1ULL,
		0x79FE72679FDAC74EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x91025E6CA5FC6108ULL,
		0xFD0969984A4F6DE3ULL,
		0x91E253FE0BDF8B08ULL,
		0x05DB770047C90913ULL,
		0x69A2D7CCAE80FEA7ULL,
		0x8E9C9AE53E86DEB9ULL,
		0x0000F3FCE4CF3FB5ULL,
		0x0000000000000000ULL
	}};
	shift = 15;
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
		0x854D144871231954ULL,
		0x94A34DE64CE7D95CULL,
		0x441B3C02BA295273ULL,
		0x47071BB74CB82F05ULL,
		0xAB8668D9CA089C6DULL,
		0xD6D9BBB5465F11B3ULL,
		0x78ED4DEE4B2C7CA3ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x673ECAE42A68A243ULL,
		0xD14A939CA51A6F32ULL,
		0x65C1782A20D9E015ULL,
		0x5044E36A3838DDBAULL,
		0x32F88D9D5C3346CEULL,
		0x5963E51EB6CDDDAAULL,
		0x00000003C76A6F72ULL,
		0x0000000000000000ULL
	}};
	shift = 29;
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
		0x47E9E37C3D167242ULL,
		0x4DC992E5D396FC9DULL,
		0x36B02FB4E4676962ULL,
		0xA31D83DB983B7103ULL,
		0xA0F3F0450DEC2363ULL,
		0xC7F9C4A8AEB5E0E6ULL,
		0xF2560BE86B367166ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x72E9CB7E4EA3F4F1ULL,
		0xDA7233B4B126E4C9ULL,
		0xEDCC1DB8819B5817ULL,
		0x2286F611B1D18EC1ULL,
		0x54575AF0735079F8ULL,
		0xF4359B38B363FCE2ULL,
		0x0000000000792B05ULL,
		0x0000000000000000ULL
	}};
	shift = 41;
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
		0x85C4F6455B50B836ULL,
		0xEC321F72A2176BA9ULL,
		0x6BD5B42F8EBB57D7ULL,
		0x6A5400300D6F72AEULL,
		0x3C0CDD184001DEE8ULL,
		0xABBC6C5D45E604D1ULL,
		0xD99E1636C43D00CEULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD7530B89EC8AB6A1ULL,
		0xAFAFD8643EE5442EULL,
		0xE55CD7AB685F1D76ULL,
		0xBDD0D4A800601ADEULL,
		0x09A27819BA308003ULL,
		0x019D5778D8BA8BCCULL,
		0x0001B33C2C6D887AULL,
		0x0000000000000000ULL
	}};
	shift = 15;
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
		0x379A167533FB9CC2ULL,
		0x2DB10A21957DD240ULL,
		0xBA3C5E6D74800996ULL,
		0xB75F5B05100B86D5ULL,
		0xB1D83579328E4EC3ULL,
		0x99BE4299E355E7B5ULL,
		0x56D82400C26EB6F1ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1BCD0B3A99FDCE61ULL,
		0x16D88510CABEE920ULL,
		0xDD1E2F36BA4004CBULL,
		0xDBAFAD828805C36AULL,
		0xD8EC1ABC99472761ULL,
		0xCCDF214CF1AAF3DAULL,
		0x2B6C120061375B78ULL,
		0x0000000000000000ULL
	}};
	shift = 1;
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
		0xB9FC5CA5378604ABULL,
		0xCEDE9D53A6DD33AEULL,
		0xA8D52333E85EC1A7ULL,
		0x4EA90FFDCCE1240EULL,
		0x9237199A57F1FB81ULL,
		0x44DC143FCA8BEE90ULL,
		0xC7CA9F357FDDF71DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x76F4EA9D36E99D75ULL,
		0x46A9199F42F60D3EULL,
		0x75487FEE67092075ULL,
		0x91B8CCD2BF8FDC0AULL,
		0x26E0A1FE545F7484ULL,
		0x3E54F9ABFEEFB8EAULL,
		0x0000000000000006ULL,
		0x0000000000000000ULL
	}};
	shift = 61;
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
		0x28B5B6D42D7901BFULL,
		0x4F1D22DD7804B0FFULL,
		0x2C77F6A1BBAACBE0ULL,
		0x72811F5754CE0036ULL,
		0x0357B909C35CDBE5ULL,
		0xA58C1BA43C393D75ULL,
		0x58DE4B9C2085F97BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBAF00961FE516B6DULL,
		0x43775597C09E3A45ULL,
		0xAEA99C006C58EFEDULL,
		0x1386B9B7CAE5023EULL,
		0x4878727AEA06AF72ULL,
		0x38410BF2F74B1837ULL,
		0x0000000000B1BC97ULL,
		0x0000000000000000ULL
	}};
	shift = 39;
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
		0x8F5FC1158FC6ACCBULL,
		0x01173FDB9817DA03ULL,
		0xC01F53C9AD8EA891ULL,
		0x6BACBF3D4FDCFB0CULL,
		0x22FB186B7194564EULL,
		0x4B6BB0CC8DF0B76EULL,
		0xB6158EBF8FA4FCE7ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x05F680E3D7F04563ULL,
		0x63AA244045CFF6E6ULL,
		0xF73EC33007D4F26BULL,
		0x6515939AEB2FCF53ULL,
		0x7C2DDB88BEC61ADCULL,
		0xE93F39D2DAEC3323ULL,
		0x0000002D8563AFE3ULL,
		0x0000000000000000ULL
	}};
	shift = 26;
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
		0xCCDEE4454BC65A53ULL,
		0x5F5C6A8DA6B80702ULL,
		0xECB22610FF15A077ULL,
		0x322C59F428E6D96BULL,
		0xBE71F3862E029CFBULL,
		0xDBA5167075661A16ULL,
		0xCEEDF36C22772F6DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8DA6B80702CCDEE4ULL,
		0x10FF15A0775F5C6AULL,
		0xF428E6D96BECB226ULL,
		0x862E029CFB322C59ULL,
		0x7075661A16BE71F3ULL,
		0x6C22772F6DDBA516ULL,
		0x0000000000CEEDF3ULL,
		0x0000000000000000ULL
	}};
	shift = 40;
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
		0xF7794A238CF8599AULL,
		0xC909CAF3C5B7B399ULL,
		0xB1E4EE7792F1B676ULL,
		0x9255624CC099B3C3ULL,
		0xA01317A929A9C3B2ULL,
		0x5A76F16E6210FE1EULL,
		0x62BE4B3857BCE4C5ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5B7B399F7794A238ULL,
		0x2F1B676C909CAF3CULL,
		0x099B3C3B1E4EE779ULL,
		0x9A9C3B29255624CCULL,
		0x210FE1EA01317A92ULL,
		0x7BCE4C55A76F16E6ULL,
		0x000000062BE4B385ULL,
		0x0000000000000000ULL
	}};
	shift = 28;
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
		0xE5F83B593CCA229CULL,
		0x6B19858B839B5415ULL,
		0x4566F14C5B10B4EFULL,
		0xF3FB5B042CE9A7BCULL,
		0x1157CE2A5859EC6BULL,
		0x0CE7F62E87C8ED9BULL,
		0xA0F8035752BE5500ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5415E5F83B593CCAULL,
		0xB4EF6B19858B839BULL,
		0xA7BC4566F14C5B10ULL,
		0xEC6BF3FB5B042CE9ULL,
		0xED9B1157CE2A5859ULL,
		0x55000CE7F62E87C8ULL,
		0x0000A0F8035752BEULL,
		0x0000000000000000ULL
	}};
	shift = 16;
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
		0x0109B9675884871AULL,
		0x347490ECB61B391FULL,
		0xF23A9B5C4D7B70EFULL,
		0xB0148129892E625AULL,
		0x983268F1704FE59EULL,
		0xB552A56B0D840AEEULL,
		0x14B1E9D6BDB24D82ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x68E921D96C36723EULL,
		0xE47536B89AF6E1DEULL,
		0x60290253125CC4B5ULL,
		0x3064D1E2E09FCB3DULL,
		0x6AA54AD61B0815DDULL,
		0x2963D3AD7B649B05ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 63;
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
		0xA638DB89F40C0E3DULL,
		0xEF525209A1EABAA0ULL,
		0x1F5FBE69A533D37BULL,
		0xE3B2C00D4DA13FEDULL,
		0x88D266B7D22BAEC0ULL,
		0x4CF9B86A81A40F47ULL,
		0x3192FEF30BFC0A6EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAA0A638DB89F40C0ULL,
		0x37BEF525209A1EABULL,
		0xFED1F5FBE69A533DULL,
		0xEC0E3B2C00D4DA13ULL,
		0xF4788D266B7D22BAULL,
		0xA6E4CF9B86A81A40ULL,
		0x0003192FEF30BFC0ULL,
		0x0000000000000000ULL
	}};
	shift = 12;
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
		0x843DF88ED0925D1CULL,
		0x55B8C899A1FF2CB6ULL,
		0xE54A641CCDCE811EULL,
		0x319E1617E8829C45ULL,
		0x6D46AE9A66A55635ULL,
		0x6051CA6CE2D9CD5DULL,
		0xC500645B002A9B0CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6687FCB2DA10F7E2ULL,
		0x73373A047956E322ULL,
		0x5FA20A7117952990ULL,
		0x699A9558D4C67858ULL,
		0xB38B673575B51ABAULL,
		0x6C00AA6C31814729ULL,
		0x0000000003140191ULL,
		0x0000000000000000ULL
	}};
	shift = 38;
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
		0xE910A147FA5AF41BULL,
		0xEDC27A0DBFDD9497ULL,
		0x847339FBA166DEE0ULL,
		0x059F13D16EB068DBULL,
		0x9ED7CCD220561346ULL,
		0xD6B0AEA27F083ACEULL,
		0x41AB981F18FB5E43ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB292FD221428FF4BULL,
		0xDBDC1DB84F41B7FBULL,
		0x0D1B708E673F742CULL,
		0xC268C0B3E27A2DD6ULL,
		0x0759D3DAF99A440AULL,
		0x6BC87AD615D44FE1ULL,
		0x000008357303E31FULL,
		0x0000000000000000ULL
	}};
	shift = 19;
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
		0xCEEDA461265A3558ULL,
		0x75990D36E975F2FCULL,
		0x28125BF870F58850ULL,
		0x3D95FB484CD7D58CULL,
		0x20DD533565947DB3ULL,
		0x5131273EF552F243ULL,
		0x322248A1FBDD63DCULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA6DD2EBE5F99DDB4ULL,
		0x7F0E1EB10A0EB321ULL,
		0x69099AFAB185024BULL,
		0x66ACB28FB667B2BFULL,
		0xE7DEAA5E48641BAAULL,
		0x143F7BAC7B8A2624ULL,
		0x0000000000064449ULL,
		0x0000000000000000ULL
	}};
	shift = 43;
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
		0x7BDB29886E808606ULL,
		0xD46D8FF455D7E779ULL,
		0xB40B0626956DB26AULL,
		0xE29C9F4456EDCD03ULL,
		0x2C20B068CCAA8AD3ULL,
		0x8082A32CB8B1E828ULL,
		0x6310E5D725FA3037ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAFCEF2F7B65310DDULL,
		0xDB64D5A8DB1FE8ABULL,
		0xDB9A0768160C4D2AULL,
		0x5515A7C5393E88ADULL,
		0x63D050584160D199ULL,
		0xF4606F0105465971ULL,
		0x000000C621CBAE4BULL,
		0x0000000000000000ULL
	}};
	shift = 23;
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
		0x569E786F2C0B2542ULL,
		0xD894DB20527E9B34ULL,
		0x1418F71AE2F38E5DULL,
		0x0B374CE2AF0A4547ULL,
		0x29245CE9098DC724ULL,
		0xDAA1CB240D3B33A4ULL,
		0x17A00BD2A1597CB9ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3F4D9A2B4F3C3796ULL,
		0x79C72EEC4A6D9029ULL,
		0x8522A38A0C7B8D71ULL,
		0xC6E392059BA67157ULL,
		0x9D99D214922E7484ULL,
		0xACBE5CED50E59206ULL,
		0x0000000BD005E950ULL,
		0x0000000000000000ULL
	}};
	shift = 25;
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
		0xDABA7BD4F7E85346ULL,
		0x4D904F31C0212DBCULL,
		0xFF6CA4C7B8F7F7EAULL,
		0x665E1073C499F4EFULL,
		0xF125CD5E0DD84A6EULL,
		0x2B8F1584EE2B2A93ULL,
		0x23412D28114F5879ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB79B574F7A9EFD0AULL,
		0xFD49B209E6380425ULL,
		0x9DFFED9498F71EFEULL,
		0x4DCCCBC20E78933EULL,
		0x527E24B9ABC1BB09ULL,
		0x0F2571E2B09DC565ULL,
		0x00046825A50229EBULL,
		0x0000000000000000ULL
	}};
	shift = 11;
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
		0x6F37B352F472EA0FULL,
		0xB8097001F8C3F7BCULL,
		0xD7A9E364E67EA8B6ULL,
		0xC2BFD3D34F999E4AULL,
		0x87B112AC94EC3329ULL,
		0x3DED33A0F7C74F96ULL,
		0x603FA352251385E0ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF78DE6F66A5E8E5DULL,
		0x16D7012E003F187EULL,
		0xC95AF53C6C9CCFD5ULL,
		0x653857FA7A69F333ULL,
		0xF2D0F62255929D86ULL,
		0xBC07BDA6741EF8E9ULL,
		0x000C07F46A44A270ULL,
		0x0000000000000000ULL
	}};
	shift = 11;
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
		0x7AC030B0FE7EA9CEULL,
		0xFD525DD5D3CF667EULL,
		0x8146B60AD6B5C089ULL,
		0x83B76197D18C52FAULL,
		0x172B8339A0E20B50ULL,
		0x07CD4781E8407C3EULL,
		0x4ABB1EDB713C13F9ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE7B33F3D6018587FULL,
		0x5AE044FEA92EEAE9ULL,
		0xC6297D40A35B056BULL,
		0x7105A841DBB0CBE8ULL,
		0x203E1F0B95C19CD0ULL,
		0x9E09FC83E6A3C0F4ULL,
		0x000000255D8F6DB8ULL,
		0x0000000000000000ULL
	}};
	shift = 25;
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
		0x8DD16209C020BE72ULL,
		0xFD6711B482D9690DULL,
		0x352EB9A8DC31CCF0ULL,
		0x18E0EABB8FD9D5FAULL,
		0x46150584983A9FEEULL,
		0xE09C52350ED660F1ULL,
		0x0DDF45124EF7C62FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x90D8DD16209C020BULL,
		0xCF0FD6711B482D96ULL,
		0x5FA352EB9A8DC31CULL,
		0xFEE18E0EABB8FD9DULL,
		0x0F146150584983A9ULL,
		0x62FE09C52350ED66ULL,
		0x0000DDF45124EF7CULL,
		0x0000000000000000ULL
	}};
	shift = 12;
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
		0x39CDDB44602032FEULL,
		0x85DFC1C56C67BEDFULL,
		0x99C023A7076CD67FULL,
		0xE6BC7FF885C0CC12ULL,
		0x6583A2E1E72B3C46ULL,
		0xC4DD1D1DE6115F6BULL,
		0xC8250A29840A7BA3ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDF6F9CE6EDA23010ULL,
		0x6B3FC2EFE0E2B633ULL,
		0x66094CE011D383B6ULL,
		0x9E23735E3FFC42E0ULL,
		0xAFB5B2C1D170F395ULL,
		0x3DD1E26E8E8EF308ULL,
		0x000064128514C205ULL,
		0x0000000000000000ULL
	}};
	shift = 17;
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
		0x0AF98CF0E584D7CEULL,
		0xB5703CCB0A73B836ULL,
		0x42E473348107EFF2ULL,
		0x0774F5B969B42852ULL,
		0x3D567C4E6454B251ULL,
		0x9C8087709AEE9F81ULL,
		0x3EC8EF7245611BB2ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB81E658539DC1B05ULL,
		0x72399A4083F7F95AULL,
		0xBA7ADCB4DA142921ULL,
		0xAB3E27322A592883ULL,
		0x4043B84D774FC09EULL,
		0x6477B922B08DD94EULL,
		0x000000000000001FULL,
		0x0000000000000000ULL
	}};
	shift = 57;
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
		0x03F9D4A9EA9563FDULL,
		0x1D39A301DF413BC0ULL,
		0x6257D6EA7B25D943ULL,
		0x8AA4DBC7399CF346ULL,
		0x58F736E67D7AEF30ULL,
		0xC3E3D3F22974DAE8ULL,
		0x8F64B45F319A7E62ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA734603BE8277800ULL,
		0x4AFADD4F64BB2863ULL,
		0x549B78E7339E68CCULL,
		0x1EE6DCCFAF5DE611ULL,
		0x7C7A7E452E9B5D0BULL,
		0xEC968BE6334FCC58ULL,
		0x0000000000000011ULL,
		0x0000000000000000ULL
	}};
	shift = 59;
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
		0x568ABB03ECCBB650ULL,
		0x19FCC05135AFFF51ULL,
		0x91B738B8BD970121ULL,
		0xF0A49E2FE85D019BULL,
		0xFDD684FE46517856ULL,
		0x47BA451B4C566BAEULL,
		0x73CC89570B3ABF59ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFFD455A2AEC0FB32ULL,
		0xC048467F30144D6BULL,
		0x4066E46DCE2E2F65ULL,
		0x5E15BC29278BFA17ULL,
		0x9AEBBF75A13F9194ULL,
		0xAFD651EE9146D315ULL,
		0x00001CF32255C2CEULL,
		0x0000000000000000ULL
	}};
	shift = 18;
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
		0x46FD5B633AF9A494ULL,
		0x76DC8149EFADDA7AULL,
		0x68BA9841D824B8C7ULL,
		0x536E8F8B2C771960ULL,
		0x0EC9AC489C777140ULL,
		0xC4D867330FFAFBE3ULL,
		0x91F114FB04AE1422ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x49EFADDA7A46FD5BULL,
		0x41D824B8C776DC81ULL,
		0x8B2C77196068BA98ULL,
		0x489C777140536E8FULL,
		0x330FFAFBE30EC9ACULL,
		0xFB04AE1422C4D867ULL,
		0x000000000091F114ULL,
		0x0000000000000000ULL
	}};
	shift = 40;
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
		0xA082265EBFBC57C8ULL,
		0x2D52694AF18D4357ULL,
		0x12CBA88C971DFA67ULL,
		0x662EB7786884477BULL,
		0x404FE4E056DD587CULL,
		0xBBDCD416BC7EBE53ULL,
		0x38124F58AA5EDA06ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0D5E8208997AFEF1ULL,
		0xE99CB549A52BC635ULL,
		0x1DEC4B2EA2325C77ULL,
		0x61F198BADDE1A211ULL,
		0xF94D013F93815B75ULL,
		0x681AEF73505AF1FAULL,
		0x0000E0493D62A97BULL,
		0x0000000000000000ULL
	}};
	shift = 14;
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
		0x1F465B2790A5CE5DULL,
		0x80AB5BAD23E1E3ADULL,
		0x7A7057A98CAA9ADEULL,
		0x955BCC3B12B66EA1ULL,
		0x8854E8FF856E6CD9ULL,
		0xF3E4C5CD49ED786CULL,
		0xE556745E8BDB4D6DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x878EB47D196C9E42ULL,
		0xAA6B7A02AD6EB48FULL,
		0xD9BA85E9C15EA632ULL,
		0xB9B366556F30EC4AULL,
		0xB5E1B22153A3FE15ULL,
		0x6D35B7CF93173527ULL,
		0x0000039559D17A2FULL,
		0x0000000000000000ULL
	}};
	shift = 22;
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
		0xF9C035772D2E53D0ULL,
		0xE95CD63B8C32E458ULL,
		0xBEBB6B01BE1544ADULL,
		0xC51DCD0F1189E906ULL,
		0xE98DD158B569B004ULL,
		0xB268463920455DC2ULL,
		0x71BD9092C6A9E535ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAE6B1DC619722C7CULL,
		0x5DB580DF0AA256F4ULL,
		0x8EE68788C4F4835FULL,
		0xC6E8AC5AB4D80262ULL,
		0x34231C9022AEE174ULL,
		0xDEC8496354F29AD9ULL,
		0x0000000000000038ULL,
		0x0000000000000000ULL
	}};
	shift = 57;
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
		0x0DC27C0BE5548D08ULL,
		0xBE6B2F6D820F5355ULL,
		0xF136AE6913BFED8BULL,
		0xC353F25304A783A7ULL,
		0x1FBFDAB73B252A9FULL,
		0x4786F835CE65A5D4ULL,
		0x23FB3E04B2A25D95ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x97B6C107A9AA86E1ULL,
		0x573489DFF6C5DF35ULL,
		0xF9298253C1D3F89BULL,
		0xED5B9D92954FE1A9ULL,
		0x7C1AE732D2EA0FDFULL,
		0x9F0259512ECAA3C3ULL,
		0x00000000000011FDULL,
		0x0000000000000000ULL
	}};
	shift = 49;
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
		0xADD62851325CB10BULL,
		0x3020B931D9EA54CCULL,
		0xD863149E955BD749ULL,
		0x5613B707245F7B26ULL,
		0x2A6F1C6A2B2F5AC6ULL,
		0xF5ED2CCE31390B80ULL,
		0x618EEE24BF0CBDE6ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x082E4C767A95332BULL,
		0x18C527A556F5D24CULL,
		0x84EDC1C917DEC9B6ULL,
		0x9BC71A8ACBD6B195ULL,
		0x7B4B338C4E42E00AULL,
		0x63BB892FC32F79BDULL,
		0x0000000000000018ULL,
		0x0000000000000000ULL
	}};
	shift = 58;
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
		0xD5C665172BD646D2ULL,
		0x5F2E453EEF87FE8BULL,
		0xA30C4D78656A32B8ULL,
		0x7F1E156FF12BFE5FULL,
		0xD3A54F521A24DBD2ULL,
		0x4FF674200123A72EULL,
		0x3F41344DDAD919A3ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x53EEF87FE8BD5C66ULL,
		0xD78656A32B85F2E4ULL,
		0x56FF12BFE5FA30C4ULL,
		0xF521A24DBD27F1E1ULL,
		0x4200123A72ED3A54ULL,
		0x44DDAD919A34FF67ULL,
		0x000000000003F413ULL,
		0x0000000000000000ULL
	}};
	shift = 44;
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
		0x94B89F421E11F2D9ULL,
		0xB74E3465156DC9CEULL,
		0x751BCFC78423ECF9ULL,
		0x95ABB0D8E818789BULL,
		0x7E5AB182682CA94FULL,
		0xD3AF063EA5771F0AULL,
		0x2BBE6ECA14C1C828ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x94B89F421E11F2D9ULL,
		0xB74E3465156DC9CEULL,
		0x751BCFC78423ECF9ULL,
		0x95ABB0D8E818789BULL,
		0x7E5AB182682CA94FULL,
		0xD3AF063EA5771F0AULL,
		0x2BBE6ECA14C1C828ULL,
		0x0000000000000000ULL
	}};
	shift = 0;
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
		0x3FE5CEE0F15080A1ULL,
		0x6897B4C25094007CULL,
		0xE94BC484A7BA6A39ULL,
		0x68F925AA1EE4E8F2ULL,
		0x017DF5722E82A537ULL,
		0x6446A7B243D2BA41ULL,
		0x2BE6D3DC30ABC62BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x03E1FF2E77078A84ULL,
		0x51CB44BDA61284A0ULL,
		0x47974A5E24253DD3ULL,
		0x29BB47C92D50F727ULL,
		0xD2080BEFAB917415ULL,
		0x315B22353D921E95ULL,
		0x00015F369EE1855EULL,
		0x0000000000000000ULL
	}};
	shift = 13;
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
		0x708F18642D821610ULL,
		0xC408377ED0426055ULL,
		0x143DA794D835F62BULL,
		0x855EE729568EC3EFULL,
		0xEF27B85BB1E20362ULL,
		0xA246761ED4A85B58ULL,
		0x7CD9CA7723614CEDULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD0426055708F1864ULL,
		0xD835F62BC408377EULL,
		0x568EC3EF143DA794ULL,
		0xB1E20362855EE729ULL,
		0xD4A85B58EF27B85BULL,
		0x23614CEDA246761EULL,
		0x000000007CD9CA77ULL,
		0x0000000000000000ULL
	}};
	shift = 32;
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
		0x7068C012D81FF802ULL,
		0xFEF67450C44BE69DULL,
		0xE627B902AF3A4842ULL,
		0x8C1B3382F2797B3EULL,
		0xC4A6CFCD14F5E6D0ULL,
		0x6AF95327624DAB80ULL,
		0x10D1081606547534ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7450C44BE69D7068ULL,
		0xB902AF3A4842FEF6ULL,
		0x3382F2797B3EE627ULL,
		0xCFCD14F5E6D08C1BULL,
		0x5327624DAB80C4A6ULL,
		0x0816065475346AF9ULL,
		0x00000000000010D1ULL,
		0x0000000000000000ULL
	}};
	shift = 48;
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
		0x099DD32C560878F1ULL,
		0x128D4F778F7B3567ULL,
		0xBDB80C72B7869B09ULL,
		0x6B27E71669565469ULL,
		0x452595B8F1FC07E1ULL,
		0xFBBD2AF189BC357AULL,
		0xCF9923FA67349F60ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA7BBC7BD9AB384CEULL,
		0x06395BC34D848946ULL,
		0xF38B34AB2A34DEDCULL,
		0xCADC78FE03F0B593ULL,
		0x9578C4DE1ABD2292ULL,
		0x91FD339A4FB07DDEULL,
		0x00000000000067CCULL,
		0x0000000000000000ULL
	}};
	shift = 49;
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
		0x6FD1E8DCF64C8869ULL,
		0x893499948F19FA84ULL,
		0xCBC1500F430A9EE4ULL,
		0x8F1C785244CDE957ULL,
		0xB4F988EBD22922D0ULL,
		0x4612141585BF50AEULL,
		0xFE5AF50B4B29EFD0ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8DFA3D1B9EC9910DULL,
		0x9126933291E33F50ULL,
		0xF9782A01E86153DCULL,
		0x11E38F0A4899BD2AULL,
		0xD69F311D7A45245AULL,
		0x08C24282B0B7EA15ULL,
		0x1FCB5EA169653DFAULL,
		0x0000000000000000ULL
	}};
	shift = 3;
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
		0x37A9B81344C6D107ULL,
		0xF1FFDE6ECE5F7C00ULL,
		0x0C565F5E7741E1D2ULL,
		0xB76C13B7941E45FEULL,
		0x74A34B16EBEB3534ULL,
		0x6617C1D3E734B28FULL,
		0x60C5A0F582E9E4D8ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCBEF8006F5370268ULL,
		0xE83C3A5E3FFBCDD9ULL,
		0x83C8BFC18ACBEBCEULL,
		0x7D66A696ED8276F2ULL,
		0xE69651EE946962DDULL,
		0x5D3C9B0CC2F83A7CULL,
		0x0000000C18B41EB0ULL,
		0x0000000000000000ULL
	}};
	shift = 27;
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
		0x65BE028380745849ULL,
		0x42A635EE4B00A7DDULL,
		0xF8FAA4A79FCE8CFDULL,
		0x2064DDBE977229A4ULL,
		0x304F2CCDAE81DB19ULL,
		0x7C985A6D0A3AF9FEULL,
		0x81E49B9E2D06AF3BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC6BDC96014FBACB7ULL,
		0x5494F3F9D19FA854ULL,
		0x9BB7D2EE45349F1FULL,
		0xE599B5D03B63240CULL,
		0x0B4DA1475F3FC609ULL,
		0x9373C5A0D5E76F93ULL,
		0x000000000000103CULL,
		0x0000000000000000ULL
	}};
	shift = 51;
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
		0x4D1A746D51E0AA09ULL,
		0x69D5CC293925448CULL,
		0x2D90C369887AD718ULL,
		0x942A6B41581617CBULL,
		0x584E0464673E7B50ULL,
		0x5454077C598AE94CULL,
		0x5930CCCBD422CE3FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4A89189A34E8DAA3ULL,
		0xF5AE30D3AB985272ULL,
		0x2C2F965B2186D310ULL,
		0x7CF6A12854D682B0ULL,
		0x15D298B09C08C8CEULL,
		0x459C7EA8A80EF8B3ULL,
		0x000000B2619997A8ULL,
		0x0000000000000000ULL
	}};
	shift = 23;
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
		0x7656FE96CDE30759ULL,
		0x9255B730CEE1E898ULL,
		0xC29728E90588A3CEULL,
		0x44FF7C93F3766D11ULL,
		0x8523C82B1BA75FCCULL,
		0xC585E225596FE580ULL,
		0xBE3F66BCB1F722CAULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x87656FE96CDE3075ULL,
		0xE9255B730CEE1E89ULL,
		0x1C29728E90588A3CULL,
		0xC44FF7C93F3766D1ULL,
		0x08523C82B1BA75FCULL,
		0xAC585E225596FE58ULL,
		0x0BE3F66BCB1F722CULL,
		0x0000000000000000ULL
	}};
	shift = 4;
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
		0x407958A3ED08E4EEULL,
		0xEC35E82BA983FF3CULL,
		0x642C2EDDA72BDAD5ULL,
		0xF278D49B82555221ULL,
		0xBD4AC187A89A9299ULL,
		0xCC33EA7E7EFEF470ULL,
		0x300266FF0F52F32CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x407958A3ED08E4EEULL,
		0xEC35E82BA983FF3CULL,
		0x642C2EDDA72BDAD5ULL,
		0xF278D49B82555221ULL,
		0xBD4AC187A89A9299ULL,
		0xCC33EA7E7EFEF470ULL,
		0x300266FF0F52F32CULL,
		0x0000000000000000ULL
	}};
	shift = 0;
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
		0xE76855F3417D6101ULL,
		0xAF2B340A6E0CD3BEULL,
		0xFB1A9B32727B0EB1ULL,
		0xD760EEE32E561ED6ULL,
		0x970A56811F036535ULL,
		0x2DD7DFC25397FE31ULL,
		0xE3120987FE386ACBULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x34EFB9DA157CD05FULL,
		0xC3AC6BCACD029B83ULL,
		0x87B5BEC6A6CC9C9EULL,
		0xD94D75D83BB8CB95ULL,
		0xFF8C65C295A047C0ULL,
		0x1AB2CB75F7F094E5ULL,
		0x000038C48261FF8EULL,
		0x0000000000000000ULL
	}};
	shift = 18;
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
		0xA4295CC9B648B386ULL,
		0x589938345D75C89BULL,
		0x737C28797A460E12ULL,
		0x6A0296B689EDEB3AULL,
		0x6B92618DE5BF1687ULL,
		0x3CA395AE503A750FULL,
		0xC127D2EE05B85B04ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC89BA4295CC9B648ULL,
		0x0E12589938345D75ULL,
		0xEB3A737C28797A46ULL,
		0x16876A0296B689EDULL,
		0x750F6B92618DE5BFULL,
		0x5B043CA395AE503AULL,
		0x0000C127D2EE05B8ULL,
		0x0000000000000000ULL
	}};
	shift = 16;
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
		0x18F9F84099455D16ULL,
		0xC64A89C4D6AA83C2ULL,
		0xAF9E11AF57FEC5BBULL,
		0x8C844B4F5B7ECF1FULL,
		0x531D85AFD06CBE6DULL,
		0xDD9BB7931DE3DBE1ULL,
		0xF180F047F24D06E8ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3C218F9F84099455ULL,
		0x5BBC64A89C4D6AA8ULL,
		0xF1FAF9E11AF57FECULL,
		0xE6D8C844B4F5B7ECULL,
		0xBE1531D85AFD06CBULL,
		0x6E8DD9BB7931DE3DULL,
		0x000F180F047F24D0ULL,
		0x0000000000000000ULL
	}};
	shift = 12;
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
		0x833B055FDD0FB822ULL,
		0xEA729A352AD75A02ULL,
		0xEA4EFBB0CAE54D86ULL,
		0x11F0DDD38DAC1973ULL,
		0x1AB76C8C131B16F1ULL,
		0x9E6AECB89E0DD3A4ULL,
		0x791DBF4CA1FB5726ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2833B055FDD0FB82ULL,
		0x6EA729A352AD75A0ULL,
		0x3EA4EFBB0CAE54D8ULL,
		0x111F0DDD38DAC197ULL,
		0x41AB76C8C131B16FULL,
		0x69E6AECB89E0DD3AULL,
		0x0791DBF4CA1FB572ULL,
		0x0000000000000000ULL
	}};
	shift = 4;
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
		0xD34C3DE882620DF7ULL,
		0xF9154879E3A86141ULL,
		0xB1876C69504D2A18ULL,
		0x3C9C1A1C6D986734ULL,
		0xFC28FD96F95731D4ULL,
		0xCE03785D22ED11A0ULL,
		0x9606C753284F1EAEULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F3C750C283A6987ULL,
		0x8D2A09A5431F22A9ULL,
		0x438DB30CE69630EDULL,
		0xB2DF2AE63A879383ULL,
		0x0BA45DA2341F851FULL,
		0xEA6509E3D5D9C06FULL,
		0x000000000012C0D8ULL,
		0x0000000000000000ULL
	}};
	shift = 43;
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
		0x0094481F470A1AB2ULL,
		0x1A5B9DAE973F0302ULL,
		0x23EEC56B929C37ECULL,
		0xBD186641A16401FFULL,
		0x6B138D634CF8BC57ULL,
		0x640186665C2F9E5BULL,
		0xABC8E0CB49F1F921ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2DCED74B9F818100ULL,
		0xF762B5C94E1BF60DULL,
		0x8C3320D0B200FF91ULL,
		0x89C6B1A67C5E2BDEULL,
		0x00C3332E17CF2DB5ULL,
		0xE47065A4F8FC90B2ULL,
		0x0000000000000055ULL,
		0x0000000000000000ULL
	}};
	shift = 57;
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
		0x81AA1076B83A85AEULL,
		0x28D678A608DA49FDULL,
		0x4A5D0FE593C72547ULL,
		0x30C1A84AB7A3367CULL,
		0x603A0BB1A2AF3684ULL,
		0xCBDCACF739F99370ULL,
		0x2F3B680641B08F26ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1ACF14C11B493FB0ULL,
		0x4BA1FCB278E4A8E5ULL,
		0x18350956F466CF89ULL,
		0x0741763455E6D086ULL,
		0x7B959EE73F326E0CULL,
		0xE76D00C83611E4D9ULL,
		0x0000000000000005ULL,
		0x0000000000000000ULL
	}};
	shift = 59;
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
		0x9A059BDA83301626ULL,
		0xBC06B5BABA1759E5ULL,
		0x5C20811BD8936C31ULL,
		0xE39AF285D7557E09ULL,
		0x3EE30CE358FAF845ULL,
		0xDFB4A1A6C005C274ULL,
		0x2D745B25D9BECB57ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCD02CDED41980B13ULL,
		0xDE035ADD5D0BACF2ULL,
		0xAE10408DEC49B618ULL,
		0xF1CD7942EBAABF04ULL,
		0x1F718671AC7D7C22ULL,
		0xEFDA50D36002E13AULL,
		0x16BA2D92ECDF65ABULL,
		0x0000000000000000ULL
	}};
	shift = 1;
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
		0x11E76B425362F203ULL,
		0x989A57AD2E7BA27AULL,
		0x21ED0E55FFA40E0FULL,
		0xC2819EF33197C0C0ULL,
		0x6D96780510A8BF9FULL,
		0x7D976D392C0C52A0ULL,
		0x2873FE6DA70BA156ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5EB4B9EE89E8479DULL,
		0x3957FE90383E6269ULL,
		0x7BCCC65F030087B4ULL,
		0xE01442A2FE7F0A06ULL,
		0xB4E4B0314A81B659ULL,
		0xF9B69C2E8559F65DULL,
		0x000000000000A1CFULL,
		0x0000000000000000ULL
	}};
	shift = 46;
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
		0xB180734EBB9171ABULL,
		0xAB4EA9BC1990ACB2ULL,
		0x24B6E5EE56A479BFULL,
		0x025B3BC91EDA1BA7ULL,
		0x273CACFE892C9A7EULL,
		0x06C157D432A7396EULL,
		0x99E28AE8269819F9ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x06642B2CAC601CD3ULL,
		0x95A91E6FEAD3AA6FULL,
		0x47B686E9C92DB97BULL,
		0xA24B269F8096CEF2ULL,
		0x0CA9CE5B89CF2B3FULL,
		0x09A6067E41B055F5ULL,
		0x000000002678A2BAULL,
		0x0000000000000000ULL
	}};
	shift = 34;
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
		0x048E4A91B62975C0ULL,
		0x08144004F3F34A3AULL,
		0xC03857B199CA3B81ULL,
		0xFC1F430B329AC4E0ULL,
		0x734903B6F62E622BULL,
		0x215E6C1210620EA2ULL,
		0x8C21FF2BC632AF10ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x34A3A048E4A91B62ULL,
		0xA3B8108144004F3FULL,
		0xAC4E0C03857B199CULL,
		0xE622BFC1F430B329ULL,
		0x20EA2734903B6F62ULL,
		0x2AF10215E6C12106ULL,
		0x000008C21FF2BC63ULL,
		0x0000000000000000ULL
	}};
	shift = 20;
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
		0xEBA5788B0335C0BDULL,
		0x0D146F5F1107AF25ULL,
		0xA0702EB955698A6AULL,
		0x0C70CB97801B3702ULL,
		0x98C4723304E6B95AULL,
		0x04F3C2D0B6F62E2DULL,
		0x9CB173A1F69A90E1ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBC97AE95E22C0CD7ULL,
		0x29A83451BD7C441EULL,
		0xDC0A81C0BAE555A6ULL,
		0xE56831C32E5E006CULL,
		0xB8B66311C8CC139AULL,
		0x438413CF0B42DBD8ULL,
		0x000272C5CE87DA6AULL,
		0x0000000000000000ULL
	}};
	shift = 14;
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
		0x252947D74D51DE11ULL,
		0x90F724755CD25F1BULL,
		0x5365C156DCB962D9ULL,
		0xE96D57AB2EA57F1CULL,
		0xB1BD273D742DD301ULL,
		0x49691B7DEAA6BD58ULL,
		0xA899561602233C44ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDC91D573497C6C94ULL,
		0x97055B72E58B6643ULL,
		0xB55EACBA95FC714DULL,
		0xF49CF5D0B74C07A5ULL,
		0xA46DF7AA9AF562C6ULL,
		0x655858088CF11125ULL,
		0x00000000000002A2ULL,
		0x0000000000000000ULL
	}};
	shift = 54;
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
		0x8925D850E199EF44ULL,
		0xCEC7801BC8884FC5ULL,
		0xCA323CDFDC4B8C0FULL,
		0xFD0D71D3B941AA97ULL,
		0x83C5FCC8980E7040ULL,
		0x51D42B0947BDB7A2ULL,
		0x66C9778B1187FBD0ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9D8F003791109F8BULL,
		0x946479BFB897181FULL,
		0xFA1AE3A77283552FULL,
		0x078BF991301CE081ULL,
		0xA3A856128F7B6F45ULL,
		0xCD92EF16230FF7A0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 63;
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
		0xE59987F73CF4BF2BULL,
		0xCF86EF02D8B74919ULL,
		0xC29BD8FE294A519AULL,
		0x0037423752108895ULL,
		0x1AB32C813DE5812BULL,
		0xA5FF1D398778079DULL,
		0x6423348E7C907D69ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEF02D8B74919E599ULL,
		0xD8FE294A519ACF86ULL,
		0x423752108895C29BULL,
		0x2C813DE5812B0037ULL,
		0x1D398778079D1AB3ULL,
		0x348E7C907D69A5FFULL,
		0x0000000000006423ULL,
		0x0000000000000000ULL
	}};
	shift = 48;
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
		0xE225D396272085B6ULL,
		0x9827C0CF4003269FULL,
		0x4158D045AB566F66ULL,
		0x6E420FE261C7A4B6ULL,
		0x363D0735EE55BC01ULL,
		0xE9B5AE7D7A3B5E2AULL,
		0x2CB3DA1D941A1CF0ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFC44BA72C4E410B6ULL,
		0xD304F819E80064D3ULL,
		0xC82B1A08B56ACDECULL,
		0x2DC841FC4C38F496ULL,
		0x46C7A0E6BDCAB780ULL,
		0x1D36B5CFAF476BC5ULL,
		0x05967B43B283439EULL,
		0x0000000000000000ULL
	}};
	shift = 3;
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
		0xCD7B9C137DCD83D5ULL,
		0xC9F10F7CB7FBA25DULL,
		0x1F0A17C65A3BF0A9ULL,
		0x12F2F2E436D08AB8ULL,
		0x8FC69ED13CFCA731ULL,
		0x6B3D8AA5666A76DEULL,
		0x315E1D4D4268F04DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFBA25DCD7B9C137DULL,
		0x3BF0A9C9F10F7CB7ULL,
		0xD08AB81F0A17C65AULL,
		0xFCA73112F2F2E436ULL,
		0x6A76DE8FC69ED13CULL,
		0x68F04D6B3D8AA566ULL,
		0x000000315E1D4D42ULL,
		0x0000000000000000ULL
	}};
	shift = 24;
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
		0xE60A60C188CC31D0ULL,
		0x774A92F4AEDBEC1EULL,
		0x955A75A6D5F3FB5EULL,
		0x5F10FC991862387EULL,
		0x7B8424617E41E724ULL,
		0x9DB1E693F9EC1FF8ULL,
		0x691EF1F9451A33C6ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x92F4AEDBEC1EE60AULL,
		0x75A6D5F3FB5E774AULL,
		0xFC991862387E955AULL,
		0x24617E41E7245F10ULL,
		0xE693F9EC1FF87B84ULL,
		0xF1F9451A33C69DB1ULL,
		0x000000000000691EULL,
		0x0000000000000000ULL
	}};
	shift = 48;
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
		0x24DC27214B7A39AFULL,
		0xBFCD3B1DB9E32A58ULL,
		0x9F6DD7EDF5F86825ULL,
		0xED7CFDAF8AEBCDC3ULL,
		0xDB3D14DCF2A5F57CULL,
		0x28847A0B7543A98EULL,
		0xCDBCC861F1B6FACCULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA763B73C654B049BULL,
		0xBAFDBEBF0D04B7F9ULL,
		0x9FB5F15D79B873EDULL,
		0xA29B9E54BEAF9DAFULL,
		0x8F416EA87531DB67ULL,
		0x990C3E36DF598510ULL,
		0x00000000000019B7ULL,
		0x0000000000000000ULL
	}};
	shift = 51;
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
		0x67B2EC7E200A7F05ULL,
		0xC714B30D05870284ULL,
		0x6743042E03773185ULL,
		0x9611053C9A045A4CULL,
		0x812BA4102D2EB37DULL,
		0x2E5A6BB5EB67D4AFULL,
		0x17F25338E0C9EAFAULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x67B2EC7E200A7F05ULL,
		0xC714B30D05870284ULL,
		0x6743042E03773185ULL,
		0x9611053C9A045A4CULL,
		0x812BA4102D2EB37DULL,
		0x2E5A6BB5EB67D4AFULL,
		0x17F25338E0C9EAFAULL,
		0x0000000000000000ULL
	}};
	shift = 0;
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
		0x4A61AAC5D2255C90ULL,
		0x8B4BE2350001EA13ULL,
		0xAE0B3B703765536AULL,
		0x157B6006AA019219ULL,
		0xC77A1BA0BEC21F00ULL,
		0xA985D7C756A99348ULL,
		0xF4FD87D2ADBB78D5ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3D42694C3558BA44ULL,
		0xAA6D51697C46A000ULL,
		0x324335C1676E06ECULL,
		0x43E002AF6C00D540ULL,
		0x326918EF437417D8ULL,
		0x6F1AB530BAF8EAD5ULL,
		0x00001E9FB0FA55B7ULL,
		0x0000000000000000ULL
	}};
	shift = 19;
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
		0x9896E6CCC408E773ULL,
		0xF14CB87959BD95AFULL,
		0xFF1130795DDCFAC7ULL,
		0x93870D0B536F9050ULL,
		0x82F04374E83F0320ULL,
		0xCDC5F2ED7960B805ULL,
		0xDA133C8F8F6309ECULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2B37B2B5F312DCD9ULL,
		0x2BBB9F58FE29970FULL,
		0x6A6DF20A1FE2260FULL,
		0x9D07E0641270E1A1ULL,
		0xAF2C1700B05E086EULL,
		0xF1EC613D99B8BE5DULL,
		0x000000001B426791ULL,
		0x0000000000000000ULL
	}};
	shift = 35;
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
		0x0AC1F940DA4C3C84ULL,
		0x1E5C450D8399B219ULL,
		0x53C087E38AA4E799ULL,
		0xA6B14ED5779ACDCDULL,
		0xA9BF30A2FC81EFF3ULL,
		0xA48370FBA2454625ULL,
		0x98690E4906B011CFULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x97114360E66C8642ULL,
		0xF021F8E2A939E647ULL,
		0xAC53B55DE6B37354ULL,
		0x6FCC28BF207BFCE9ULL,
		0x20DC3EE89151896AULL,
		0x1A439241AC0473E9ULL,
		0x0000000000000026ULL,
		0x0000000000000000ULL
	}};
	shift = 58;
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
		0x358083FF717F960AULL,
		0x6C20061212A1CEAFULL,
		0xA1F842DA1865FBEAULL,
		0x8AC58DB1D4C1A2CDULL,
		0xA5E05A520F17AEDEULL,
		0x17FA9CB7C4C84711ULL,
		0x3177884CD15A7820ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1003090950E7579AULL,
		0xFC216D0C32FDF536ULL,
		0x62C6D8EA60D166D0ULL,
		0xF02D29078BD76F45ULL,
		0xFD4E5BE2642388D2ULL,
		0xBBC42668AD3C100BULL,
		0x0000000000000018ULL,
		0x0000000000000000ULL
	}};
	shift = 57;
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
		0x62A7F2911405A229ULL,
		0x18065197AA536C16ULL,
		0x186C224C139176A5ULL,
		0x83CEC91A2E2FA099ULL,
		0xB93DC89F50F8C5A8ULL,
		0x8671E006919AA150ULL,
		0x810E2CDAF3EEFE0EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8CBD529B60B3153FULL,
		0x12609C8BB528C032ULL,
		0x48D1717D04C8C361ULL,
		0x44FA87C62D441E76ULL,
		0x00348CD50A85C9EEULL,
		0x66D79F77F074338FULL,
		0x0000000000040871ULL,
		0x0000000000000000ULL
	}};
	shift = 45;
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
		0x3F8D949D59CF67C4ULL,
		0x01C32B6EF203375FULL,
		0xF804DAC045A675C5ULL,
		0x37321FA129559C9DULL,
		0xBEBD39538913D30CULL,
		0x6C15C693C5A5E265ULL,
		0x036BD75FC309CB44ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x779019BAF9FC6CA4ULL,
		0x022D33AE280E195BULL,
		0x094AACE4EFC026D6ULL,
		0x9C489E9861B990FDULL,
		0x9E2D2F132DF5E9CAULL,
		0xFE184E5A2360AE34ULL,
		0x00000000001B5EBAULL,
		0x0000000000000000ULL
	}};
	shift = 37;
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
		0x55EB151C1AC7D54EULL,
		0x9D9A33F6EE3CC46CULL,
		0x239535212C10E4ACULL,
		0x6FF39F08EB4B07CFULL,
		0x747FE171D36B36F7ULL,
		0x1D1F2922EBCD45FEULL,
		0x6B556AFFD9A2C51EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x467EDDC7988D8ABDULL,
		0xA6A425821C9593B3ULL,
		0x73E11D6960F9E472ULL,
		0xFC2E3A6D66DEEDFEULL,
		0xE5245D79A8BFCE8FULL,
		0xAD5FFB3458A3C3A3ULL,
		0x0000000000000D6AULL,
		0x0000000000000000ULL
	}};
	shift = 51;
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
		0xABC44962E423AD21ULL,
		0xB9F3F01C3199AFF8ULL,
		0x82AF95E28BE5FD16ULL,
		0xD2A5FD15860A49A9ULL,
		0xA0B6F392EFC1ED8CULL,
		0x271AFD76A25735BCULL,
		0x2181EA76AAB9863BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0E18CCD7FC55E224ULL,
		0xF145F2FE8B5CF9F8ULL,
		0x8AC30524D4C157CAULL,
		0xC977E0F6C66952FEULL,
		0xBB512B9ADE505B79ULL,
		0x3B555CC31D938D7EULL,
		0x000000000010C0F5ULL,
		0x0000000000000000ULL
	}};
	shift = 41;
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
		0xB2035FF426F85FD6ULL,
		0x317BFDD424021AD4ULL,
		0x7F901EE403F5D629ULL,
		0x447AD016843B2B90ULL,
		0x1ADF46DA9B6F1B62ULL,
		0xB0A4D383216575B6ULL,
		0x4B9E7DEF19A223C5ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA8480435A96406BFULL,
		0xC807EBAC5262F7FBULL,
		0x2D08765720FF203DULL,
		0xB536DE36C488F5A0ULL,
		0x0642CAEB6C35BE8DULL,
		0xDE3344478B6149A7ULL,
		0x0000000000973CFBULL,
		0x0000000000000000ULL
	}};
	shift = 39;
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
		0xDCCC8BBDCF4EE7B7ULL,
		0x97E013A58FFCD020ULL,
		0xA8F740D83053FB2CULL,
		0x674B6B0AA61712B3ULL,
		0x5B3C024B0CF59FCBULL,
		0xFFEF7E66C1509963ULL,
		0x1E7E7D58A3E46B29ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x13A58FFCD020DCCCULL,
		0x40D83053FB2C97E0ULL,
		0x6B0AA61712B3A8F7ULL,
		0x024B0CF59FCB674BULL,
		0x7E66C15099635B3CULL,
		0x7D58A3E46B29FFEFULL,
		0x0000000000001E7EULL,
		0x0000000000000000ULL
	}};
	shift = 48;
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
		0xCAEE6306C315DC63ULL,
		0x184CB449B52B8C6EULL,
		0x67FC6CCACC774FDAULL,
		0x5258CAE72FC1E41CULL,
		0x32C8B301C9C6E321ULL,
		0xBBD8921EC545C960ULL,
		0xCD504C4AFCC419A4ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC6ECAEE6306C315DULL,
		0xFDA184CB449B52B8ULL,
		0x41C67FC6CCACC774ULL,
		0x3215258CAE72FC1EULL,
		0x96032C8B301C9C6EULL,
		0x9A4BBD8921EC545CULL,
		0x000CD504C4AFCC41ULL,
		0x0000000000000000ULL
	}};
	shift = 12;
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
		0xA0A1F4E44C0C7C56ULL,
		0x7A565A638D08246FULL,
		0x93A609E639D0BC5DULL,
		0x954A7346FAB246B8ULL,
		0xDF09EA1BBF0337F8ULL,
		0xEA32F0FC22CEA7A1ULL,
		0xEB279C5B1D586FAFULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x959698E342091BE8ULL,
		0xE982798E742F175EULL,
		0x529CD1BEAC91AE24ULL,
		0xC27A86EFC0CDFE25ULL,
		0x8CBC3F08B3A9E877ULL,
		0xC9E716C7561BEBFAULL,
		0x000000000000003AULL,
		0x0000000000000000ULL
	}};
	shift = 58;
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
		0xCB7211B35E6C82C5ULL,
		0xDB4AC6FC266C8FECULL,
		0x40568B7460BFA78CULL,
		0xBFAC52D3546B0A57ULL,
		0xF60EDD0E2384F937ULL,
		0x9B546DAE96E288B0ULL,
		0xB67DC66FFE4057ABULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDA5637E133647F66ULL,
		0x02B45BA305FD3C66ULL,
		0xFD62969AA35852BAULL,
		0xB076E8711C27C9BDULL,
		0xDAA36D74B7144587ULL,
		0xB3EE337FF202BD5CULL,
		0x0000000000000005ULL,
		0x0000000000000000ULL
	}};
	shift = 61;
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
		0x1861471F6DE90546ULL,
		0xA3855169A56FC1DFULL,
		0xF2178F9F8765BE7EULL,
		0x68AEF8EDE0F2549DULL,
		0x4F3C3F4685C574DBULL,
		0xF8C998364305D4DEULL,
		0x30785D0C7EFE4582ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFC1DF1861471F6DEULL,
		0x5BE7EA3855169A56ULL,
		0x2549DF2178F9F876ULL,
		0x574DB68AEF8EDE0FULL,
		0x5D4DE4F3C3F4685CULL,
		0xE4582F8C99836430ULL,
		0x0000030785D0C7EFULL,
		0x0000000000000000ULL
	}};
	shift = 20;
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
		0x6EE86AEB9B4F7621ULL,
		0x600826343AD634B0ULL,
		0xBDFAB8DB874E6528ULL,
		0x900BA39D0CEFD103ULL,
		0xA3674CDDF3484B4BULL,
		0xEB66E9ABD82B6414ULL,
		0x39816D120EC62706ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6B1A5837743575CDULL,
		0xA732943004131A1DULL,
		0x77E881DEFD5C6DC3ULL,
		0xA425A5C805D1CE86ULL,
		0x15B20A51B3A66EF9ULL,
		0x63138375B374D5ECULL,
		0x0000001CC0B68907ULL,
		0x0000000000000000ULL
	}};
	shift = 25;
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
		0xA82F350931EFABDCULL,
		0x5DDC58B672545F7DULL,
		0x3C2FCBD1D667AD55ULL,
		0x9DBF1F90F7D9B0ABULL,
		0x1ECB8613588D4DA2ULL,
		0x11CF06FE3D51EAB4ULL,
		0x4013368ABE64F8FCULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDC58B672545F7DA8ULL,
		0x2FCBD1D667AD555DULL,
		0xBF1F90F7D9B0AB3CULL,
		0xCB8613588D4DA29DULL,
		0xCF06FE3D51EAB41EULL,
		0x13368ABE64F8FC11ULL,
		0x0000000000000040ULL,
		0x0000000000000000ULL
	}};
	shift = 56;
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
		0xB2F6CF46EFE9050AULL,
		0xB99B789B8D34161CULL,
		0xAD5F617B124B8605ULL,
		0x915AA7E834A04488ULL,
		0x5C1087EFD816D10FULL,
		0x27CD91B7368233ACULL,
		0xD9CAEC3E25AB37F5ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x872CBDB3D1BBFA41ULL,
		0x816E66DE26E34D05ULL,
		0x222B57D85EC492E1ULL,
		0x43E456A9FA0D2811ULL,
		0xEB170421FBF605B4ULL,
		0xFD49F3646DCDA08CULL,
		0x003672BB0F896ACDULL,
		0x0000000000000000ULL
	}};
	shift = 10;
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
		0x847F00A0573EF70AULL,
		0x007DA2D7DB4B9E13ULL,
		0xBBAEB4269BBC42ACULL,
		0xC38B176325F085FFULL,
		0xEB4387D9FBDD4B5EULL,
		0x5E04C6070E8AB757ULL,
		0x46453E9A8AC62116ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xED16BEDA5CF09C23ULL,
		0x75A134DDE2156003ULL,
		0x58BB192F842FFDDDULL,
		0x1C3ECFDEEA5AF61CULL,
		0x2630387455BABF5AULL,
		0x29F4D4563108B2F0ULL,
		0x0000000000000232ULL,
		0x0000000000000000ULL
	}};
	shift = 53;
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
		0x7082E019086C501FULL,
		0xD7164C2285772957ULL,
		0x6871855238B30F9BULL,
		0x8E7A2C42E78618C4ULL,
		0xB975FCCBB62185FEULL,
		0x86DCF0C4EDEBE59EULL,
		0xDBC44B5DB08F11DEULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x57729577082E0190ULL,
		0x8B30F9BD7164C228ULL,
		0x78618C4687185523ULL,
		0x62185FE8E7A2C42EULL,
		0xDEBE59EB975FCCBBULL,
		0x08F11DE86DCF0C4EULL,
		0x0000000DBC44B5DBULL,
		0x0000000000000000ULL
	}};
	shift = 28;
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
		0xFDD0CC3C7ED65AE9ULL,
		0x68C0AB818A646EC7ULL,
		0xCE6D002E1C22CF64ULL,
		0x4467F0E7F78EEC97ULL,
		0x5E3335E0ABAD4ADFULL,
		0xDB9A93FD3C58361FULL,
		0x036A6F40A3797B1AULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8A646EC7FDD0CC3CULL,
		0x1C22CF6468C0AB81ULL,
		0xF78EEC97CE6D002EULL,
		0xABAD4ADF4467F0E7ULL,
		0x3C58361F5E3335E0ULL,
		0xA3797B1ADB9A93FDULL,
		0x00000000036A6F40ULL,
		0x0000000000000000ULL
	}};
	shift = 32;
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
		0xE1720F25CA8325E5ULL,
		0x8CD383559AA365E3ULL,
		0x0595182929703F1DULL,
		0x71674BFDE63F24D3ULL,
		0x3F4C9E7CDCDA9135ULL,
		0x84596C4B4791F494ULL,
		0xC626955CBCE5D5EAULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x383559AA365E3E17ULL,
		0x5182929703F1D8CDULL,
		0x74BFDE63F24D3059ULL,
		0xC9E7CDCDA9135716ULL,
		0x96C4B4791F4943F4ULL,
		0x6955CBCE5D5EA845ULL,
		0x0000000000000C62ULL,
		0x0000000000000000ULL
	}};
	shift = 52;
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
		0xE9EA14364770D5B5ULL,
		0x08F283EF39BA0AF0ULL,
		0x5F0EA412E3415329ULL,
		0x8A352CE1A78C4A88ULL,
		0xACD85899ABE9AD75ULL,
		0x6F9C04D3843FF6D4ULL,
		0x20985EC4D7C0935EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x37415E1D3D4286C8ULL,
		0x682A65211E507DE7ULL,
		0xF189510BE1D4825CULL,
		0x7D35AEB146A59C34ULL,
		0x87FEDA959B0B1335ULL,
		0xF8126BCDF3809A70ULL,
		0x00000004130BD89AULL,
		0x0000000000000000ULL
	}};
	shift = 27;
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
		0xD922F1495DFE77AFULL,
		0xC37BBF14B3BB06E5ULL,
		0x4C3F68763DA07978ULL,
		0xC86B44C28060B8C0ULL,
		0xCE805F4A1692DE5DULL,
		0xED0A80805BFFAAEBULL,
		0xD08C631622E57FAFULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x86F77E2967760DCBULL,
		0x987ED0EC7B40F2F1ULL,
		0x90D6898500C17180ULL,
		0x9D00BE942D25BCBBULL,
		0xDA150100B7FF55D7ULL,
		0xA118C62C45CAFF5FULL,
		0x0000000000000001ULL,
		0x0000000000000000ULL
	}};
	shift = 63;
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
		0x41A3F245B02160B6ULL,
		0x13BE78124A18EC89ULL,
		0xB2D9C26FBC6FDE98ULL,
		0x67B3203639A46D16ULL,
		0x5E6BF18E5352B794ULL,
		0x3E7DFF610994C487ULL,
		0x40BDA88771760137ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x249431D9128347E4ULL,
		0xDF78DFBD30277CF0ULL,
		0x6C7348DA2D65B384ULL,
		0x1CA6A56F28CF6640ULL,
		0xC21329890EBCD7E3ULL,
		0x0EE2EC026E7CFBFEULL,
		0x0000000000817B51ULL,
		0x0000000000000000ULL
	}};
	shift = 39;
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
		0x60F709CA32AF8CD1ULL,
		0x6F120903BF3B8689ULL,
		0x7111320BC963C6DBULL,
		0xE470FC798A823492ULL,
		0x0A872970BE500CC1ULL,
		0xD34FB6B08D632EB0ULL,
		0x0547C89C8A15C7BAULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE1A2583DC2728CABULL,
		0xF1B6DBC48240EFCEULL,
		0x8D249C444C82F258ULL,
		0x0330791C3F1E62A0ULL,
		0xCBAC02A1CA5C2F94ULL,
		0x71EEB4D3EDAC2358ULL,
		0x00000151F2272285ULL,
		0x0000000000000000ULL
	}};
	shift = 18;
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
		0xE262BF0700E74874ULL,
		0x9B8C87199732E2F4ULL,
		0x154F387D3FAE0F02ULL,
		0xCA9780DDE66A5B95ULL,
		0x41708A2A1FE84543ULL,
		0x0ABA07D131762738ULL,
		0x6E02E7AD02A12968ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x321C665CCB8BD389ULL,
		0x3CE1F4FEB83C0A6EULL,
		0x5E037799A96E5455ULL,
		0xC228A87FA1150F2AULL,
		0xE81F44C5D89CE105ULL,
		0x0B9EB40A84A5A02AULL,
		0x00000000000001B8ULL,
		0x0000000000000000ULL
	}};
	shift = 54;
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
		0xA1AF2EA8F7E0B70EULL,
		0x86C213EC3EC16F83ULL,
		0x74BC0AD4F959168DULL,
		0x543F6E58C6866F77ULL,
		0x600E6B2F5091B98DULL,
		0x17B39D642BBD8382ULL,
		0x657C0DFA66D60087ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB084FB0FB05BE0E8ULL,
		0x2F02B53E5645A361ULL,
		0x0FDB9631A19BDDDDULL,
		0x039ACBD4246E6355ULL,
		0xECE7590AEF60E098ULL,
		0x5F037E99B58021C5ULL,
		0x0000000000000019ULL,
		0x0000000000000000ULL
	}};
	shift = 58;
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
		0x928AD4FDE8B24DA0ULL,
		0x219790A7CF317766ULL,
		0x2BF0795891F87DA1ULL,
		0xFEA26E304779A318ULL,
		0xA66A3D641E5A32D7ULL,
		0x54DF00DB4C9F31FAULL,
		0x791572715C92B218ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x53E798BBB349456AULL,
		0xAC48FC3ED090CBC8ULL,
		0x1823BCD18C15F83CULL,
		0xB20F2D196BFF5137ULL,
		0x6DA64F98FD53351EULL,
		0x38AE49590C2A6F80ULL,
		0x00000000003C8AB9ULL,
		0x0000000000000000ULL
	}};
	shift = 41;
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
		0x02C835655B1956D8ULL,
		0xC866ABEEEAA90D23ULL,
		0xC749E97A832EBDCFULL,
		0xC423CF4124D8C66EULL,
		0xFB1B33BAA84EB172ULL,
		0xC26406A41CDDA4A7ULL,
		0xD3474749974A09D3ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA4605906ACAB632AULL,
		0xB9F90CD57DDD5521ULL,
		0xCDD8E93D2F5065D7ULL,
		0x2E588479E8249B18ULL,
		0x94FF6366775509D6ULL,
		0x3A784C80D4839BB4ULL,
		0x001A68E8E932E941ULL,
		0x0000000000000000ULL
	}};
	shift = 11;
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
		0x03394AA2A03C0CADULL,
		0xA6C18D754021E760ULL,
		0xA126AD70DFA942A6ULL,
		0xA4A6CD76F6D12162ULL,
		0x2B777BB863E6E2C2ULL,
		0xCC3A3174773D9C81ULL,
		0xA2C34EC83D886907ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCEC0067295454078ULL,
		0x854D4D831AEA8043ULL,
		0x42C5424D5AE1BF52ULL,
		0xC585494D9AEDEDA2ULL,
		0x390256EEF770C7CDULL,
		0xD20F987462E8EE7BULL,
		0x000145869D907B10ULL,
		0x0000000000000000ULL
	}};
	shift = 15;
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
		0xFF1B8C0D12714697ULL,
		0x08C67942E8BF139EULL,
		0xAE48EF0AD6199380ULL,
		0x40976100805DBE40ULL,
		0x45632C33A75FE9EBULL,
		0xBB3EE81CE29DA999ULL,
		0x3964E0FCDA3F26BEULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x273DFE37181A24E2ULL,
		0x2700118CF285D17EULL,
		0x7C815C91DE15AC33ULL,
		0xD3D6812EC20100BBULL,
		0x53328AC658674EBFULL,
		0x4D7D767DD039C53BULL,
		0x000072C9C1F9B47EULL,
		0x0000000000000000ULL
	}};
	shift = 15;
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
		0x57C5CBDD765011C7ULL,
		0x384ED4CC9838E6A9ULL,
		0xA886E5B197D5AB2CULL,
		0xB64C54BC6BAD629CULL,
		0xA74406436800CF80ULL,
		0x0675C64E9E37D940ULL,
		0xA08FF151A0F82462ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB533260E39AA55F1ULL,
		0xB96C65F56ACB0E13ULL,
		0x152F1AEB58A72A21ULL,
		0x0190DA0033E02D93ULL,
		0x7193A78DF65029D1ULL,
		0xFC54683E0918819DULL,
		0x0000000000002823ULL,
		0x0000000000000000ULL
	}};
	shift = 50;
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
		0x1252E3F1B8E5827AULL,
		0x531471EE928922B7ULL,
		0x59B578B66B6FA45CULL,
		0x87480FA554EB22C8ULL,
		0xEF4EA1C85E28A702ULL,
		0xCBA9125E16AD2D6EULL,
		0xC5B0C85BEA28E65DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xADC494B8FC6E3960ULL,
		0x1714C51C7BA4A248ULL,
		0xB2166D5E2D9ADBE9ULL,
		0xC0A1D203E9553AC8ULL,
		0x5BBBD3A872178A29ULL,
		0x9772EA449785AB4BULL,
		0x00316C3216FA8A39ULL,
		0x0000000000000000ULL
	}};
	shift = 10;
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
		0xAE11C34554D90586ULL,
		0x0DAEF36379443EB0ULL,
		0x61838EE67D2C8D1BULL,
		0x386C282CDBB3D076ULL,
		0x56A4B1782B97E78CULL,
		0x5D38A0B1868A9650ULL,
		0x5A95DBEE91E7112DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x510FAC2B8470D155ULL,
		0x4B2346C36BBCD8DEULL,
		0xECF41D9860E3B99FULL,
		0xE5F9E30E1B0A0B36ULL,
		0xA2A59415A92C5E0AULL,
		0x79C44B574E282C61ULL,
		0x00000016A576FBA4ULL,
		0x0000000000000000ULL
	}};
	shift = 26;
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
		0xE42EEB3AE3187A9EULL,
		0x99F9F2CBF637AA31ULL,
		0x56CBFF2471458DE2ULL,
		0x9C8EDC6A8FF0DF86ULL,
		0xBC5D63DA7A6766AEULL,
		0x1AF89227FBBB117EULL,
		0xBDA6450851D5F675ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x518F217759D718C3ULL,
		0x6F14CFCF965FB1BDULL,
		0xFC32B65FF9238A2CULL,
		0x3574E476E3547F86ULL,
		0x8BF5E2EB1ED3D33BULL,
		0xB3A8D7C4913FDDD8ULL,
		0x0005ED3228428EAFULL,
		0x0000000000000000ULL
	}};
	shift = 13;
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
		0x4D2ABE9D778EE8AAULL,
		0x3122724478BD2659ULL,
		0xC2F322B268F761F6ULL,
		0x5CB7AC61585CF166ULL,
		0xB778D7F194F8260DULL,
		0x7E781C69C0ACD513ULL,
		0x66D245BBA61F0649ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x724478BD26594D2AULL,
		0x22B268F761F63122ULL,
		0xAC61585CF166C2F3ULL,
		0xD7F194F8260D5CB7ULL,
		0x1C69C0ACD513B778ULL,
		0x45BBA61F06497E78ULL,
		0x00000000000066D2ULL,
		0x0000000000000000ULL
	}};
	shift = 48;
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
		0xF6917F3EBEC3668FULL,
		0x6A7AE6914F070F4DULL,
		0x7EDAE5F7874E4510ULL,
		0x20F63AC85AB2B9EFULL,
		0x137767FB7F0A8DDBULL,
		0xC8FD0AC369C435A4ULL,
		0x35231B9E3E4F2877ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x348A78387A6FB48BULL,
		0x2FBC3A72288353D7ULL,
		0xD642D595CF7BF6D7ULL,
		0x3FDBF8546ED907B1ULL,
		0x561B4E21AD209BBBULL,
		0xDCF1F27943BE47E8ULL,
		0x000000000001A918ULL,
		0x0000000000000000ULL
	}};
	shift = 45;
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
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000080000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000800000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 48;
	printf("Test Case 201\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000008ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000008000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 40;
	printf("Test Case 202\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000800000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000800000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 52;
	printf("Test Case 203\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000001000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 28;
	printf("Test Case 204\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0800000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0008000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 8;
	printf("Test Case 205\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000400000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0040000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 32;
	printf("Test Case 206\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000080000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000800000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 60;
	printf("Test Case 207\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0800000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 4;
	printf("Test Case 208\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000100ULL,
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
	shift = 60;
	printf("Test Case 209\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000040ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000400000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 48;
	printf("Test Case 210\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
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