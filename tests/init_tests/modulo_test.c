#include "../tests.h"

int32_t curve25519_key_modulo_test(void) {
	printf("Modulo Test\n");
	curve25519_key_t k1 = {.key64 = {
		0x291E5F84051FB15DULL,
		0x5116842C9111AE1CULL,
		0x2D02B74205ADA100ULL,
		0xF0DD4E65C27F72DDULL,
		0xA8AE47A36CBF70BCULL,
		0xB067AEF5DAF6CB19ULL,
		0xF7B27EC92D63D64FULL,
		0x7C48D5CB6D4DA7F1ULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0x32FD01C6298A7017ULL,
		0x807A7CAB11B3D3EBULL,
		0xF181891EC27F70D4ULL,
		0x63AD0A97FC0660C7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 1\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	int32_t res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 1 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -1;
	} else {
		printf("Test Case 1 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB32034130A9BDC0CULL,
		0x1A759D51AF135538ULL,
		0xCB156B1412F3A593ULL,
		0x2CCB3644C02A1509ULL,
		0x71ED368C5463A801ULL,
		0x2F72110532F75FB8ULL,
		0x378AF177452A8B5DULL,
		0x4A527894D806C151ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x32FD01C6298A7017ULL,
		0x807A7CAB11B3D3EBULL,
		0xF181891EC27F70D4ULL,
		0x63AD0A97FC0660C7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 2\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 2 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -2;
	} else {
		printf("Test Case 2 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x41E512528CBEA69DULL,
		0x14A71B0ED794F8A8ULL,
		0x9F59CEA1FD52CE90ULL,
		0x3537CA300E117794ULL,
		0x56C0BC72C04E04A6ULL,
		0x9EFDD967976F0B9BULL,
		0xFC747BF55FC740DAULL,
		0xF00915CC9D784DA8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x32FD01C6298A7017ULL,
		0x807A7CAB11B3D3EBULL,
		0xF181891EC27F70D4ULL,
		0x63AD0A97FC0660C7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 3\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 3 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -3;
	} else {
		printf("Test Case 3 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x271DDBD7C61A338AULL,
		0x030D5F0E7DA87A98ULL,
		0x9ED1C1BB70576609ULL,
		0x267330822BABC72AULL,
		0xB847BAFE00FB9BB7ULL,
		0x326786E11830507BULL,
		0xEF49F0B863A48ED5ULL,
		0xDB49D1BE525A5BD2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x32FD01C6298A7017ULL,
		0x807A7CAB11B3D3EBULL,
		0xF181891EC27F70D4ULL,
		0x63AD0A97FC0660C7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 4\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 4 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -4;
	} else {
		printf("Test Case 4 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x19052F91EF95F7A6ULL,
		0x842EACC0D56DD0F5ULL,
		0xE083739D3B6BCB20ULL,
		0x5493396E66C81F16ULL,
		0x654D4B3003F5DA10ULL,
		0xA807C7B1EC23F99AULL,
		0x2C91DA9FE3A9F6CDULL,
		0xBADBC70D1D75A305ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x32FD01C6298A7017ULL,
		0x807A7CAB11B3D3EBULL,
		0xF181891EC27F70D4ULL,
		0x63AD0A97FC0660C7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 5\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 5 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -5;
	} else {
		printf("Test Case 5 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x160C7FEBCADB08ACULL,
		0xD2CD46B69AD112D0ULL,
		0x8B15CA30EBB95DF4ULL,
		0x25D62BC4B5301465ULL,
		0x7DE6F1E69F085B1EULL,
		0x493BA8B8A0DB006DULL,
		0x06809DF66E71E56EULL,
		0x00BF1B3F396ACA59ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x32FD01C6298A7017ULL,
		0x807A7CAB11B3D3EBULL,
		0xF181891EC27F70D4ULL,
		0x63AD0A97FC0660C7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 6\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 6 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -6;
	} else {
		printf("Test Case 6 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD5B3D9F637EB3FFBULL,
		0x6DCE36D2CC973CD0ULL,
		0x704EC3941F3628BAULL,
		0x3377BE288230457BULL,
		0x7A4A6D13AF2A41D2ULL,
		0x74216A5509BB9C58ULL,
		0x7BA429800B58408BULL,
		0x2BAECBF5BB5B50C1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x32FD01C6298A7017ULL,
		0x807A7CAB11B3D3EBULL,
		0xF181891EC27F70D4ULL,
		0x63AD0A97FC0660C7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 7\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 7 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -7;
	} else {
		printf("Test Case 7 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC4ED9DD8314DF22BULL,
		0x13DFB24FDDA61733ULL,
		0xE1E3F6243866D091ULL,
		0xC6D0ABC8478A4829ULL,
		0x812654278726A964ULL,
		0xDE4B294D0BCF5601ULL,
		0x0C874D95604C1DEEULL,
		0xC6AB87F954108F14ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x32FD01C6298A7017ULL,
		0x807A7CAB11B3D3EBULL,
		0xF181891EC27F70D4ULL,
		0x63AD0A97FC0660C7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 8\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 8 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -8;
	} else {
		printf("Test Case 8 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0E8162DC2244B7C2ULL,
		0xBAAA88D5A852D9E1ULL,
		0xD02C40D1297FA100ULL,
		0x746B46FA482D7DD8ULL,
		0x53B0E54C482C99A6ULL,
		0xD96D833A5B8FFC13ULL,
		0x4CC5BD54EF24308CULL,
		0x55D789CE71BFF756ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x32FD01C6298A7017ULL,
		0x807A7CAB11B3D3EBULL,
		0xF181891EC27F70D4ULL,
		0x63AD0A97FC0660C7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 9\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 9 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -9;
	} else {
		printf("Test Case 9 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x07FF55F7F56764A7ULL,
		0x84838EE918FE968BULL,
		0x8EA9188E4735955BULL,
		0x306659D9D0FEC3A4ULL,
		0xFC1729290F1D12E9ULL,
		0x066E5BF20E50B3EBULL,
		0x214CEDA68205B9CEULL,
		0x39BDCABD4B130249ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x32FD01C6298A7017ULL,
		0x807A7CAB11B3D3EBULL,
		0xF181891EC27F70D4ULL,
		0x63AD0A97FC0660C7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 10\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 10 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -10;
	} else {
		printf("Test Case 10 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3BAFBC8F4664D14EULL,
		0x8C21AAF6116F271BULL,
		0x2C276E186F917521ULL,
		0x52557B9B39C0C020ULL,
		0x127EE687B4FA7CA3ULL,
		0x7F16DBE6F4C24B8FULL,
		0xA28CEA497F680691ULL,
		0x02B52E054BBCDDA7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x32FD01C6298A7017ULL,
		0x807A7CAB11B3D3EBULL,
		0xF181891EC27F70D4ULL,
		0x63AD0A97FC0660C7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 11\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 11 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -11;
	} else {
		printf("Test Case 11 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE3D9FF5256E4B898ULL,
		0x78FC3BC01EEA5988ULL,
		0xEDCD8E43B9135058ULL,
		0x74C2CAFDD2EB2C78ULL,
		0xA29138E7130E4E96ULL,
		0x4FDF8EE313250038ULL,
		0xAE38538F03304365ULL,
		0x4BAD8F9679E1C8F4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x32FD01C6298A7017ULL,
		0x807A7CAB11B3D3EBULL,
		0xF181891EC27F70D4ULL,
		0x63AD0A97FC0660C7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 12\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 12 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -12;
	} else {
		printf("Test Case 12 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x66B52700C41DAB6CULL,
		0xA17F3833FAA92AF8ULL,
		0xA20454368B1E948CULL,
		0x8313BAC713095983ULL,
		0x57630BAD873DCA9BULL,
		0xFC650AB20A1E8630ULL,
		0x9B35BC27FF1BEF14ULL,
		0x624ADDC5C7FD79A2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x32FD01C6298A7017ULL,
		0x807A7CAB11B3D3EBULL,
		0xF181891EC27F70D4ULL,
		0x63AD0A97FC0660C7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 13\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 13 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -13;
	} else {
		printf("Test Case 13 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE07D99BD5F635CECULL,
		0x4ECF05C43E051760ULL,
		0xCF5682157BF174CEULL,
		0x34E0EE13D22EEA9AULL,
		0xDF9990AB90C1D276ULL,
		0xDA1EA9D7A1CC4FBBULL,
		0x8F24061F28A97A7DULL,
		0x6D236AA7A1F3A90CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x32FD01C6298A7017ULL,
		0x807A7CAB11B3D3EBULL,
		0xF181891EC27F70D4ULL,
		0x63AD0A97FC0660C7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 14\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 14 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -14;
	} else {
		printf("Test Case 14 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8E564A44A30D0AF4ULL,
		0xA69D0C27C8C2158AULL,
		0xD4DCF1A3FBBD09B3ULL,
		0x5065DCD90539DC4CULL,
		0xE09D049D788ABE1DULL,
		0x90ECB36B75E122D4ULL,
		0x29A674290373AD7AULL,
		0xC8D585514C3D614AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x32FD01C6298A7017ULL,
		0x807A7CAB11B3D3EBULL,
		0xF181891EC27F70D4ULL,
		0x63AD0A97FC0660C7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 15\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 15 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -15;
	} else {
		printf("Test Case 15 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7C1771B7E47F440CULL,
		0x26799C522A2574B1ULL,
		0xD3695A0A202085FBULL,
		0xD553F70AE7A17E91ULL,
		0x0BDFE2D129D79574ULL,
		0xD728B8FF041E456BULL,
		0xCECC8C78C12198D5ULL,
		0x03275F46EBFD9259ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x32FD01C6298A7017ULL,
		0x807A7CAB11B3D3EBULL,
		0xF181891EC27F70D4ULL,
		0x63AD0A97FC0660C7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 16\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 16 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -16;
	} else {
		printf("Test Case 16 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC34830B2F3EBC4F4ULL,
		0x6FB22BE36097B477ULL,
		0xBF73D9CDC7AB6639ULL,
		0x062426EFD488F435ULL,
		0x2666588C1D8BD159ULL,
		0x8EC4B8A7CBDD0083ULL,
		0x1656B9735CDA801FULL,
		0xE6E168D1BADCA7BBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x32FD01C6298A7017ULL,
		0x807A7CAB11B3D3EBULL,
		0xF181891EC27F70D4ULL,
		0x63AD0A97FC0660C7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 17\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 17 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -17;
	} else {
		printf("Test Case 17 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCA5D67C361552F71ULL,
		0x5F5379322BF50ACEULL,
		0xEEE2CCBD910D73A7ULL,
		0xE6B67DE6B72EEBF3ULL,
		0x39DDEDA4A9599AA8ULL,
		0x67905A83E1E92AAEULL,
		0xA614EB1A9B4B3F81ULL,
		0xF75F37E0C880D568ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x32FD01C6298A7017ULL,
		0x807A7CAB11B3D3EBULL,
		0xF181891EC27F70D4ULL,
		0x63AD0A97FC0660C7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 18\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 18 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -18;
	} else {
		printf("Test Case 18 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x67DFD0C661664A0FULL,
		0x2D8EA7AC5CF43ED8ULL,
		0x1EE856F64684ABC2ULL,
		0xDE2083567A069CEBULL,
		0x5ADA2A5A23542D81ULL,
		0x08667FA1E8D57E03ULL,
		0x691CC6B6D39345BBULL,
		0x2B1207F3B18475CAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x32FD01C6298A7017ULL,
		0x807A7CAB11B3D3EBULL,
		0xF181891EC27F70D4ULL,
		0x63AD0A97FC0660C7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 19\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 19 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -19;
	} else {
		printf("Test Case 19 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x751DD383DCB2BD46ULL,
		0xC84DC9A3734DDA0FULL,
		0x2A371FB0D6B129A5ULL,
		0x7A6A5E92B4CA5561ULL,
		0xA1F350298F5BDF4CULL,
		0x48C796F4334BAD64ULL,
		0x3A9566D24F05CB1AULL,
		0xD61693CDFFE3DE2DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x32FD01C6298A7017ULL,
		0x807A7CAB11B3D3EBULL,
		0xF181891EC27F70D4ULL,
		0x63AD0A97FC0660C7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 20\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 20 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -20;
	} else {
		printf("Test Case 20 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1CD7710DDC17ABBAULL,
		0xF49672C0C57FB361ULL,
		0xDB41BAAF2F48BC14ULL,
		0xAFFD4C2524D286B9ULL,
		0x6331E8C8C9FD73AFULL,
		0x709FADA73FCA5C99ULL,
		0xCB64591763CC9640ULL,
		0x47C27DF1CA9B1FBAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x32FD01C6298A7017ULL,
		0x807A7CAB11B3D3EBULL,
		0xF181891EC27F70D4ULL,
		0x63AD0A97FC0660C7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 21\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 21 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -21;
	} else {
		printf("Test Case 21 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7D0AF6C811144FC5ULL,
		0xE9595E057393B9F4ULL,
		0x0E1FC19D04D95CC2ULL,
		0xB67CF08C251DFD9EULL,
		0x470D28335EE082EFULL,
		0x4E584CC0547D703EULL,
		0x06145099E43F7A1FULL,
		0x1F96589826AFCD89ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x32FD01C6298A7017ULL,
		0x807A7CAB11B3D3EBULL,
		0xF181891EC27F70D4ULL,
		0x63AD0A97FC0660C7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 22\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 22 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -22;
	} else {
		printf("Test Case 22 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBF2C5EB13D4E1EEDULL,
		0x179491FA9F9B1F1FULL,
		0x0C0AE5770EDE9B35ULL,
		0x2AB32264A680FBE4ULL,
		0x404DC89D292D71A3ULL,
		0x00245A79D98DE125ULL,
		0x751471B38ABC7D8CULL,
		0x76DC5A7CC0E6772EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x32FD01C6298A7017ULL,
		0x807A7CAB11B3D3EBULL,
		0xF181891EC27F70D4ULL,
		0x63AD0A97FC0660C7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 23\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 23 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -23;
	} else {
		printf("Test Case 23 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5566CF96FFA17ACDULL,
		0x9FCDC47D7074D2B4ULL,
		0xDDFAFF9430690B00ULL,
		0x624F271B0849F01EULL,
		0x8797EF131C2D0D93ULL,
		0xD7E36E0160BF47FBULL,
		0xA893F26901E36E6FULL,
		0x70728ABCB37F1185ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x32FD01C6298A7017ULL,
		0x807A7CAB11B3D3EBULL,
		0xF181891EC27F70D4ULL,
		0x63AD0A97FC0660C7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 24\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 24 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -24;
	} else {
		printf("Test Case 24 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBBBF9AC7E313BB6EULL,
		0xD8F29F4AD775A387ULL,
		0x256294E87367103FULL,
		0xC95CF3D05B3D424CULL,
		0x9A96FBAB1421979FULL,
		0xE9364B6B0298F64DULL,
		0xB400228AE5A156DBULL,
		0x5A62F22EC29DCC1EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x32FD01C6298A7017ULL,
		0x807A7CAB11B3D3EBULL,
		0xF181891EC27F70D4ULL,
		0x63AD0A97FC0660C7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 25\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 25 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -25;
	} else {
		printf("Test Case 25 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x68E17421EC1450D5ULL,
		0xB73B59D7B4CC673AULL,
		0x8FE55541591C85CCULL,
		0xD7B5E5923242A2C1ULL,
		0x8C18C9BA6DD89B5BULL,
		0x7B70C3151CF3083FULL,
		0x9564A0A2EF714296ULL,
		0x85227FBB93A19620ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x32FD01C6298A7017ULL,
		0x807A7CAB11B3D3EBULL,
		0xF181891EC27F70D4ULL,
		0x63AD0A97FC0660C7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 26\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 26 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -26;
	} else {
		printf("Test Case 26 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9CABE562ED4A0BABULL,
		0x018C6070C555AEDBULL,
		0x78BF3BCD441E40B3ULL,
		0x85837E074EA33A2DULL,
		0xF1AA0FCE7CFBC3EBULL,
		0xDB0A1D31082901CBULL,
		0x426D48AB60C5DC83ULL,
		0x4B21267C1F3ED474ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x32FD01C6298A7017ULL,
		0x807A7CAB11B3D3EBULL,
		0xF181891EC27F70D4ULL,
		0x63AD0A97FC0660C7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 27\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 27 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -27;
	} else {
		printf("Test Case 27 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBF5D69DB79BFF825ULL,
		0xAD8815F9CDC0D41EULL,
		0x48C736759C4B9C81ULL,
		0xE8E7F92651E4E518ULL,
		0xC261426758987742ULL,
		0x4EB84AD64BA97572ULL,
		0x07F8DE955250A068ULL,
		0x912B4A7EFBEEA50AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x32FD01C6298A7017ULL,
		0x807A7CAB11B3D3EBULL,
		0xF181891EC27F70D4ULL,
		0x63AD0A97FC0660C7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 28\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 28 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -28;
	} else {
		printf("Test Case 28 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0DE88F28804AC680ULL,
		0x045A4CAC57133BCFULL,
		0x440EAB8889DB5CB4ULL,
		0x16C539BCDEB3BB0AULL,
		0x288037FFD966702FULL,
		0x715A622ECE0D1E13ULL,
		0x5C4C0730D7E524B0ULL,
		0x98B7912A15ED32FEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x32FD01C6298A7017ULL,
		0x807A7CAB11B3D3EBULL,
		0xF181891EC27F70D4ULL,
		0x63AD0A97FC0660C7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 29\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 29 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -29;
	} else {
		printf("Test Case 29 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD39467CBE572E1EDULL,
		0x5F4508166D4DCF0CULL,
		0xCC910036DE779008ULL,
		0x803E6E9F4654ACA9ULL,
		0xF27E1F1871AC4619ULL,
		0x0F3465004FD649C7ULL,
		0x33BF09DF21AE83F5ULL,
		0x30EEA30AF2E807CFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x32FD01C6298A7017ULL,
		0x807A7CAB11B3D3EBULL,
		0xF181891EC27F70D4ULL,
		0x63AD0A97FC0660C7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 30\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 30 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -30;
	} else {
		printf("Test Case 30 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x33EB97862A2FE9C6ULL,
		0xDD3CDFCC8C066466ULL,
		0xA0D0F2A193894C86ULL,
		0xECCE97931E775861ULL,
		0x8CC160EC009869DEULL,
		0xB3E3AA528E7E917EULL,
		0x8FF3804E420B44BAULL,
		0xA6B1B88D2E638CA8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x32FD01C6298A7017ULL,
		0x807A7CAB11B3D3EBULL,
		0xF181891EC27F70D4ULL,
		0x63AD0A97FC0660C7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 31\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 31 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -31;
	} else {
		printf("Test Case 31 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCD1EF33F5DD8DA3FULL,
		0x950760548BFAFC50ULL,
		0x7733532555246FACULL,
		0xC86D62159830E810ULL,
		0xD0E17B6EDD9B688DULL,
		0x28AD6B6B574F134DULL,
		0x5DEC9004ADB86D8FULL,
		0xD920855B6108D0F0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x32FD01C6298A7017ULL,
		0x807A7CAB11B3D3EBULL,
		0xF181891EC27F70D4ULL,
		0x63AD0A97FC0660C7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 32\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 32 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -32;
	} else {
		printf("Test Case 32 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDACD7C5DCA3E483CULL,
		0xBE71B5999A893E7AULL,
		0x100CA46C04C36553ULL,
		0xF08415EA949C1137ULL,
		0xBA7D24A06ACAC863ULL,
		0x8F9A3E971CF8FE89ULL,
		0xEDC69159B311FFDEULL,
		0xD69F1BFF7C334CFFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x32FD01C6298A7017ULL,
		0x807A7CAB11B3D3EBULL,
		0xF181891EC27F70D4ULL,
		0x63AD0A97FC0660C7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 33\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 33 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -33;
	} else {
		printf("Test Case 33 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC124993F30FBD7BBULL,
		0xEBE8ADD89471E983ULL,
		0x73A128D664067546ULL,
		0x02AF7F4EFC300399ULL,
		0xCCB3703AA482CE9DULL,
		0x2BAFA16CBE0BC056ULL,
		0x6C49550E2B82D5C8ULL,
		0x6C92916553244CF4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x32FD01C6298A7017ULL,
		0x807A7CAB11B3D3EBULL,
		0xF181891EC27F70D4ULL,
		0x63AD0A97FC0660C7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 34\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 34 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -34;
	} else {
		printf("Test Case 34 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4AECA1790BDE700CULL,
		0xAD54DBB2A18128E6ULL,
		0xEA0E510DB6617733ULL,
		0x90FF6F931951685DULL,
		0x53F38DC48AE9109BULL,
		0xD6EB054D3A5D7E04ULL,
		0x21F17D1C3D08D8E2ULL,
		0x43676B9D896ED512ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x32FD01C6298A7017ULL,
		0x807A7CAB11B3D3EBULL,
		0xF181891EC27F70D4ULL,
		0x63AD0A97FC0660C7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 35\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 35 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -35;
	} else {
		printf("Test Case 35 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4C4138676CD9419FULL,
		0x983A8DF2C872568AULL,
		0x436B8062C2746303ULL,
		0x73F20FC710D745E4ULL,
		0xA4EC254665F72BB6ULL,
		0xD46BDE50426DB093ULL,
		0x0B3CB45BACE93A05ULL,
		0x3C59A1B9FDBE77A2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x32FD01C6298A7017ULL,
		0x807A7CAB11B3D3EBULL,
		0xF181891EC27F70D4ULL,
		0x63AD0A97FC0660C7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 36\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 36 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -36;
	} else {
		printf("Test Case 36 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA2413B7CD846FEC0ULL,
		0x8DAA23331A57D96EULL,
		0x964A087C5CBA588EULL,
		0xF4E8BE77D9C76591ULL,
		0xAE6BD481C96E94EBULL,
		0x38EA93B449556459ULL,
		0x9F2F5C7B32781B9FULL,
		0x3DD2F2DCFCD8408CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x32FD01C6298A7017ULL,
		0x807A7CAB11B3D3EBULL,
		0xF181891EC27F70D4ULL,
		0x63AD0A97FC0660C7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 37\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 37 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -37;
	} else {
		printf("Test Case 37 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9C64CBBAC56C42D2ULL,
		0xF1ACC76F63FBA8D8ULL,
		0x957724E21AFCD124ULL,
		0xCBEA9A8837D6ECD5ULL,
		0x6C7EC06A0DE9FF94ULL,
		0xC6A5955E7270C283ULL,
		0x2A066C802C932659ULL,
		0xFE2C698D891365B3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x32FD01C6298A7017ULL,
		0x807A7CAB11B3D3EBULL,
		0xF181891EC27F70D4ULL,
		0x63AD0A97FC0660C7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 38\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 38 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -38;
	} else {
		printf("Test Case 38 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6C68BFA86C54B1E7ULL,
		0x8E5F1255A9EAFD8AULL,
		0xE4EA224CA3909BA6ULL,
		0x14399135E24A1F4EULL,
		0xACA77EA50470D701ULL,
		0xDBF89CB1C3B78BF5ULL,
		0xDEEE51164D9C456CULL,
		0x29CAB94C1F84EEA8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x32FD01C6298A7017ULL,
		0x807A7CAB11B3D3EBULL,
		0xF181891EC27F70D4ULL,
		0x63AD0A97FC0660C7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 39\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 39 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -39;
	} else {
		printf("Test Case 39 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7EA4E775CD7746F6ULL,
		0x542D436700CE41B8ULL,
		0x20B426CC8B1DC716ULL,
		0x392AB9813696015CULL,
		0xD92D5A81F4101D78ULL,
		0x2011D62BC117184CULL,
		0x5E903B3FFBDF49D0ULL,
		0x6CFEA5A0594ABAB7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x32FD01C6298A7017ULL,
		0x807A7CAB11B3D3EBULL,
		0xF181891EC27F70D4ULL,
		0x63AD0A97FC0660C7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 40\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 40 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -40;
	} else {
		printf("Test Case 40 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC2870017AE0D639CULL,
		0x5BCA9F5C19943139ULL,
		0x750725C7EF80D449ULL,
		0xAC0E1532E62E9AA3ULL,
		0xB459CC5186268CD0ULL,
		0x1991B27A9E9461EEULL,
		0x5596390C1B6F9B3CULL,
		0xAFD91454B3B1321FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x32FD01C6298A7017ULL,
		0x807A7CAB11B3D3EBULL,
		0xF181891EC27F70D4ULL,
		0x63AD0A97FC0660C7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 41\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 41 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -41;
	} else {
		printf("Test Case 41 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCDD7F72830C7FDD4ULL,
		0x759FF2CFC1A9A20DULL,
		0x96DC7CD12909107CULL,
		0x8F565A15F5214864ULL,
		0x8CD155757862CB74ULL,
		0xD7B397DD0A00DFBAULL,
		0x68E5A01366737117ULL,
		0xB6D4994F80CF9C2CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x32FD01C6298A7017ULL,
		0x807A7CAB11B3D3EBULL,
		0xF181891EC27F70D4ULL,
		0x63AD0A97FC0660C7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 42\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 42 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -42;
	} else {
		printf("Test Case 42 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDDC137B1C34A02B1ULL,
		0xF1FE62E3C301751BULL,
		0xAD4C93B8CBE96C6FULL,
		0x2924F90FAFACBF5EULL,
		0x3279438A2E73B7E9ULL,
		0x2E910BCC5658F0A7ULL,
		0xC8BB691CB75EAD3DULL,
		0xF84DF9BB07500053ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x32FD01C6298A7017ULL,
		0x807A7CAB11B3D3EBULL,
		0xF181891EC27F70D4ULL,
		0x63AD0A97FC0660C7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 43\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 43 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -43;
	} else {
		printf("Test Case 43 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4312BC1666F8E975ULL,
		0x030B460E5FF56396ULL,
		0x9E10D98939F56084ULL,
		0x829E7304CB517EFFULL,
		0x081EAFBBB57F8FBCULL,
		0xD51BA1E7FCBBEB66ULL,
		0x29DF4320C362B742ULL,
		0x1A051492688FC4F3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x32FD01C6298A7017ULL,
		0x807A7CAB11B3D3EBULL,
		0xF181891EC27F70D4ULL,
		0x63AD0A97FC0660C7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 44\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 44 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -44;
	} else {
		printf("Test Case 44 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x951E4849553CE002ULL,
		0x66AF0DEB14893251ULL,
		0xBA841D128CE98435ULL,
		0x5E227482B8E40EEBULL,
		0x245B234E41F4B867ULL,
		0xDA7149D4DD8C7B38ULL,
		0xD423C528FC79F220ULL,
		0x456EFC23ABA5B082ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x32FD01C6298A7017ULL,
		0x807A7CAB11B3D3EBULL,
		0xF181891EC27F70D4ULL,
		0x63AD0A97FC0660C7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 45\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 45 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -45;
	} else {
		printf("Test Case 45 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0E108B47EFE44A86ULL,
		0x769CBA95F8F4F18CULL,
		0x6A97AB3041E2FE03ULL,
		0xE0B0A68CB1AE780DULL,
		0xA395F12B8C39C12EULL,
		0x91326FC93DE744D0ULL,
		0xFFBA76F273B4E506ULL,
		0x3020A9D58987662EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x32FD01C6298A7017ULL,
		0x807A7CAB11B3D3EBULL,
		0xF181891EC27F70D4ULL,
		0x63AD0A97FC0660C7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 46\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 46 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -46;
	} else {
		printf("Test Case 46 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC91FFE58FFD87638ULL,
		0x3B18EE78585B5259ULL,
		0x6F29AA7E208BB0E2ULL,
		0x2A4CF6AF8736EBF6ULL,
		0x4897B0CC8446A2C9ULL,
		0xCA5E6AB1D5468635ULL,
		0xCD4956A43C918F41ULL,
		0x68D2370ED4AC12FAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x32FD01C6298A7017ULL,
		0x807A7CAB11B3D3EBULL,
		0xF181891EC27F70D4ULL,
		0x63AD0A97FC0660C7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 47\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 47 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -47;
	} else {
		printf("Test Case 47 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA0108A04DB937172ULL,
		0xAF24856A32A09946ULL,
		0xEA86C05ED5C947A0ULL,
		0x4F8CA67BD4E0A2A3ULL,
		0xD371C1310CEEF29CULL,
		0xFF0BAC9DDD29EA5FULL,
		0x3D727954467569B0ULL,
		0xD041EF0E428A79B8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x32FD01C6298A7017ULL,
		0x807A7CAB11B3D3EBULL,
		0xF181891EC27F70D4ULL,
		0x63AD0A97FC0660C7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 48\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 48 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -48;
	} else {
		printf("Test Case 48 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1EC63AD611B1353DULL,
		0x018E401AE0CEE09FULL,
		0x49BDF8AD982C9412ULL,
		0x97AEBE57CEC799B6ULL,
		0x490419B75084FDB9ULL,
		0xE490B66226D58224ULL,
		0xCC75CA88CED7507EULL,
		0xFFF048BEFDE60C2EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x32FD01C6298A7017ULL,
		0x807A7CAB11B3D3EBULL,
		0xF181891EC27F70D4ULL,
		0x63AD0A97FC0660C7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 49\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 49 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -49;
	} else {
		printf("Test Case 49 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC8CED193BB8F9BB1ULL,
		0x20B521EFBD28ED71ULL,
		0x5FA40057DF491F24ULL,
		0x552BFE135C434AEBULL,
		0x4BDCB0F0F8770EE0ULL,
		0x188E9DC4250E85E0ULL,
		0xA2166A608375A01CULL,
		0x4736EB6B8A0B769CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x32FD01C6298A7017ULL,
		0x807A7CAB11B3D3EBULL,
		0xF181891EC27F70D4ULL,
		0x63AD0A97FC0660C7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 50\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 50 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -50;
	} else {
		printf("Test Case 50 PASSED\n");
	}
	printf("---\n\n");
	return 0;
}