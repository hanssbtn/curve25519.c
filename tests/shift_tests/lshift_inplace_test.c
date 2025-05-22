#include "../tests.h"

int32_t curve25519_key_lshift_inplace_test(void) {
	printf("Inplace Key Left Shift Test\n");
	curve25519_key_t k1 = {.key64 = {
		0x5ADD4CD158D28F16ULL,
		0xF3FB22EDB59D9BA3ULL,
		0xC82E4C3AED650C8FULL,
		0x67FEEB9CC9BFF459ULL,
		0xB2D046D4DDD5DB13ULL,
		0x55672A3F0200473DULL,
		0x315AA7BA730FC355ULL,
		0x0000000000000000ULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0x3C58000000000000ULL,
		0x6E8D6B753345634AULL,
		0x323FCFEC8BB6D676ULL,
		0xD16720B930EBB594ULL,
		0x6C4D9FFBAE7326FFULL,
		0x1CF6CB411B537757ULL,
		0x0D55559CA8FC0801ULL,
		0x0000C56A9EE9CC3FULL
	}};
	int shift = 50;
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
		0x8C67AC03E5B72441ULL,
		0xC450CEF8B71D2CE6ULL,
		0x40A2322034B74CB1ULL,
		0x754BF2546CDB84A9ULL,
		0xD1C63487F03900CBULL,
		0x8146393EF86BB295ULL,
		0x2AEF3F7CE7400AA5ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0400000000000000ULL,
		0x9A319EB00F96DC91ULL,
		0xC711433BE2DC74B3ULL,
		0xA50288C880D2DD32ULL,
		0x2DD52FC951B36E12ULL,
		0x574718D21FC0E403ULL,
		0x960518E4FBE1AECAULL,
		0x00ABBCFDF39D002AULL
	}};
	shift = 58;
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
		0x51FF22B9F63F70E7ULL,
		0x3BFBE039E6A9641AULL,
		0xE382AB1EC0460835ULL,
		0x216CEB813AC82311ULL,
		0x1DA803326F53D213ULL,
		0x9916ED8344149118ULL,
		0xFF549DACE92F8A1EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x573EC7EE1CE00000ULL,
		0x073CD52C834A3FE4ULL,
		0x63D808C106A77F7CULL,
		0x70275904623C7055ULL,
		0x664DEA7A42642D9DULL,
		0xB06882922303B500ULL,
		0xB59D25F143D322DDULL,
		0x00000000001FEA93ULL
	}};
	shift = 21;
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
		0x9E8FF7855D793F7AULL,
		0xF18437CA5EB58E2EULL,
		0x9B483ADE2B972145ULL,
		0x8495C8F91F96D5F4ULL,
		0xE45309F73811F564ULL,
		0x22A1A7BA1DB32C36ULL,
		0x0E0C1F5BD306DDFAULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1FEF0ABAF27EF400ULL,
		0x086F94BD6B1C5D3DULL,
		0x9075BC572E428BE3ULL,
		0x2B91F23F2DABE936ULL,
		0xA613EE7023EAC909ULL,
		0x434F743B66586DC8ULL,
		0x183EB7A60DBBF445ULL,
		0x000000000000001CULL
	}};
	shift = 9;
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
		0x50208EBB08CCDAA4ULL,
		0x9FE53E94E1B1C7F8ULL,
		0x11625F20CAE4123BULL,
		0x49CED679745010F5ULL,
		0x2927FE29334926DAULL,
		0x90072861FF314766ULL,
		0x6E961E10F685E412ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x50208EBB08CCDAA4ULL,
		0x9FE53E94E1B1C7F8ULL,
		0x11625F20CAE4123BULL,
		0x49CED679745010F5ULL,
		0x2927FE29334926DAULL,
		0x90072861FF314766ULL,
		0x6E961E10F685E412ULL,
		0x0000000000000000ULL
	}};
	shift = 0;
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
		0xD15C410B64745703ULL,
		0x65EE37AC1E9DBCBAULL,
		0x6F90F9C95D56E425ULL,
		0xCC122066A90E3FC3ULL,
		0x5BFB767B3C2C8613ULL,
		0x345C4192A1C6A81EULL,
		0x25EBBC0D2B3DF8E1ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6000000000000000ULL,
		0x5A2B88216C8E8AE0ULL,
		0xACBDC6F583D3B797ULL,
		0x6DF21F392BAADC84ULL,
		0x7982440CD521C7F8ULL,
		0xCB7F6ECF678590C2ULL,
		0x268B88325438D503ULL,
		0x04BD7781A567BF1CULL
	}};
	shift = 61;
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
		0xE741B0A275DC4FBFULL,
		0xD46433030FC9E6F3ULL,
		0x9286FE7A04832A0EULL,
		0x5B3BC94EE27F023CULL,
		0x9FDAF07868D2DCF2ULL,
		0xFD0A13ECD2729395ULL,
		0xD9FA909BB8E9115EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x41B0A275DC4FBF00ULL,
		0x6433030FC9E6F3E7ULL,
		0x86FE7A04832A0ED4ULL,
		0x3BC94EE27F023C92ULL,
		0xDAF07868D2DCF25BULL,
		0x0A13ECD27293959FULL,
		0xFA909BB8E9115EFDULL,
		0x00000000000000D9ULL
	}};
	shift = 8;
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
		0xD0093BA37A49E963ULL,
		0x5773E8C3A750E94AULL,
		0x5BB5D09B941F5A9AULL,
		0x0DFD8E4283A25822ULL,
		0x71F2C557E5EA6B61ULL,
		0x3BDA29CFB2FAD630ULL,
		0xA0ED3AC2AE1AA06FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3000000000000000ULL,
		0xAD0093BA37A49E96ULL,
		0xA5773E8C3A750E94ULL,
		0x25BB5D09B941F5A9ULL,
		0x10DFD8E4283A2582ULL,
		0x071F2C557E5EA6B6ULL,
		0xF3BDA29CFB2FAD63ULL,
		0x0A0ED3AC2AE1AA06ULL
	}};
	shift = 60;
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
		0x462A108A8C0368B2ULL,
		0xFC82FE0F825A5936ULL,
		0xC47AFAFB0C1F5DBFULL,
		0xE8ED584C5AF57A77ULL,
		0x74CBBF23F8E8821FULL,
		0xE72D5FFDEB84A6CBULL,
		0xDAFC1EF60F224C50ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x601B459000000000ULL,
		0x12D2C9B231508454ULL,
		0x60FAEDFFE417F07CULL,
		0xD7ABD3BE23D7D7D8ULL,
		0xC74410FF476AC262ULL,
		0x5C25365BA65DF91FULL,
		0x79126287396AFFEFULL,
		0x00000006D7E0F7B0ULL
	}};
	shift = 35;
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
		0x2B43BBF1A2A225EBULL,
		0xA613A5F4572C6DB2ULL,
		0x5D2195BC945FCB17ULL,
		0x99E452E4D6984E78ULL,
		0x91FC7BB1AC03A787ULL,
		0x232CD6F66F9989BAULL,
		0xE8B74DA44A9BC5C0ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x112F580000000000ULL,
		0x636D915A1DDF8D15ULL,
		0xFE58BD309D2FA2B9ULL,
		0xC273C2E90CADE4A2ULL,
		0x1D3C3CCF229726B4ULL,
		0xCC4DD48FE3DD8D60ULL,
		0xDE2E011966B7B37CULL,
		0x00000745BA6D2254ULL
	}};
	shift = 43;
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
		0xF2D8509836F2FF5DULL,
		0x343D4632FBB93596ULL,
		0xFCCBBFF0BCCAE4F3ULL,
		0xAD1F593499C05F0EULL,
		0x4E5FAF7E6E2AE7A3ULL,
		0x1AEABFEA52B85923ULL,
		0x53CA06CCFFA92E4DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x284C1B797FAE8000ULL,
		0xA3197DDC9ACB796CULL,
		0xDFF85E6572799A1EULL,
		0xAC9A4CE02F877E65ULL,
		0xD7BF371573D1D68FULL,
		0x5FF5295C2C91A72FULL,
		0x03667FD497268D75ULL,
		0x00000000000029E5ULL
	}};
	shift = 15;
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
		0xC50899ABE61FAD14ULL,
		0x979B1E797B0AE8A5ULL,
		0x5D0E04950CFB0F7CULL,
		0xFB99D678AF407D5CULL,
		0x5DAD09B09669FD2CULL,
		0xBEF3574C93657CEDULL,
		0x9FA8369EA5E0C34EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCD5F30FD68A00000ULL,
		0xF3CBD857452E2844ULL,
		0x24A867D87BE4BCD8ULL,
		0xB3C57A03EAE2E870ULL,
		0x4D84B34FE967DCCEULL,
		0xBA649B2BE76AED68ULL,
		0xB4F52F061A75F79AULL,
		0x000000000004FD41ULL
	}};
	shift = 19;
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
		0xAEB0EB8AAC915096ULL,
		0x6BD4496728D64F85ULL,
		0x3256B553607BE5B1ULL,
		0x2891064CB42E36AFULL,
		0x9585B0C4E5015398ULL,
		0x5C6387278DB56F72ULL,
		0xD9E55E8ABDB0037FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB000000000000000ULL,
		0x2D75875C55648A84ULL,
		0x8B5EA24B3946B27CULL,
		0x7992B5AA9B03DF2DULL,
		0xC144883265A171B5ULL,
		0x94AC2D8627280A9CULL,
		0xFAE31C393C6DAB7BULL,
		0x06CF2AF455ED801BULL
	}};
	shift = 59;
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
		0x407EB24259F5121DULL,
		0xC53CEFF1551F97F3ULL,
		0x9A9C5B17D69E2F6EULL,
		0x3A9B7D507113CE11ULL,
		0xC07FE8C44634E805ULL,
		0xC7D516AC8C8F3B7DULL,
		0x76D10D83930AA459ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4B3EA243A0000000ULL,
		0x2AA3F2FE680FD648ULL,
		0xFAD3C5EDD8A79DFEULL,
		0x0E2279C233538B62ULL,
		0x88C69D00A7536FAAULL,
		0x9191E76FB80FFD18ULL,
		0x7261548B38FAA2D5ULL,
		0x000000000EDA21B0ULL
	}};
	shift = 29;
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
		0x763B558437724DD0ULL,
		0x509481CA31F15630ULL,
		0x479FFD659699287BULL,
		0x98092CB87BCFDADEULL,
		0x7CEFDD966130245AULL,
		0x23D81E4FC41DC119ULL,
		0x215F17E82FD9CB11ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE49BA00000000000ULL,
		0xE2AC60EC76AB086EULL,
		0x3250F6A129039463ULL,
		0x9FB5BC8F3FFACB2DULL,
		0x6048B530125970F7ULL,
		0x3B8232F9DFBB2CC2ULL,
		0xB3962247B03C9F88ULL,
		0x00000042BE2FD05FULL
	}};
	shift = 41;
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
		0x51E9B18B7B78EA3EULL,
		0x795F7107F4AC2327ULL,
		0xDA3D74D827E5ED53ULL,
		0xE7E9D03E6AFD07FAULL,
		0x7A662070678703F1ULL,
		0x219FEC81B59CB1D5ULL,
		0x61CF90F582E4363DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x16F6F1D47C000000ULL,
		0x0FE958464EA3D363ULL,
		0xB04FCBDAA6F2BEE2ULL,
		0x7CD5FA0FF5B47AE9ULL,
		0xE0CF0E07E3CFD3A0ULL,
		0x036B3963AAF4CC40ULL,
		0xEB05C86C7A433FD9ULL,
		0x0000000000C39F21ULL
	}};
	shift = 25;
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
		0x81216DAAC02EC867ULL,
		0xF103AA419A7F99F3ULL,
		0xA7F2239C6A63A673ULL,
		0xA8ACB9B38CC5769EULL,
		0xFB99CCDE7300E3EEULL,
		0xAE8F87B41EE97D4EULL,
		0xAB4DD50BE8749AE9ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5601764338000000ULL,
		0x0CD3FCCF9C090B6DULL,
		0xE3531D339F881D52ULL,
		0x9C662BB4F53F911CULL,
		0xF398071F754565CDULL,
		0xA0F74BEA77DCCE66ULL,
		0x5F43A4D74D747C3DULL,
		0x00000000055A6EA8ULL
	}};
	shift = 27;
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
		0xBE7A45B5E3247D7EULL,
		0x5846313304F1EC67ULL,
		0x4CDF97043F4025D9ULL,
		0x8407CFCE8C605869ULL,
		0x95FFBC9B6753B041ULL,
		0x748C08255940F3A1ULL,
		0xC6F58D567DD270AEULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE7A45B5E3247D7E0ULL,
		0x846313304F1EC67BULL,
		0xCDF97043F4025D95ULL,
		0x407CFCE8C6058694ULL,
		0x5FFBC9B6753B0418ULL,
		0x48C08255940F3A19ULL,
		0x6F58D567DD270AE7ULL,
		0x000000000000000CULL
	}};
	shift = 4;
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
		0x08EC3914849ED0A6ULL,
		0x4F0001225F8448BDULL,
		0x118DCDE4BF907232ULL,
		0x9FF145BF283392B5ULL,
		0x4D8B6BD4D7DC6682ULL,
		0x035D880ADC68E43FULL,
		0x7485EB79E1F386C1ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1D87229093DA14C0ULL,
		0xE000244BF08917A1ULL,
		0x31B9BC97F20E4649ULL,
		0xFE28B7E5067256A2ULL,
		0xB16D7A9AFB8CD053ULL,
		0x6BB1015B8D1C87E9ULL,
		0x90BD6F3C3E70D820ULL,
		0x000000000000000EULL
	}};
	shift = 5;
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
		0xC585611760A2AC22ULL,
		0xEDD9D98C9DA5F682ULL,
		0x2D66848B56A9D887ULL,
		0x09EF60245DDEFC15ULL,
		0xC312B2DF95AB9C5DULL,
		0x9C138BD71FFD505AULL,
		0x20F82BBA3577F294ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB051561100000000ULL,
		0x4ED2FB4162C2B08BULL,
		0xAB54EC43F6ECECC6ULL,
		0x2EEF7E0A96B34245ULL,
		0xCAD5CE2E84F7B012ULL,
		0x8FFEA82D6189596FULL,
		0x1ABBF94A4E09C5EBULL,
		0x00000000107C15DDULL
	}};
	shift = 31;
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
		0xDCB73A4392513346ULL,
		0x24D4B1834DB0D311ULL,
		0x6C98952E85294E3FULL,
		0xB60912B9F15537B0ULL,
		0x2A0BE23C4EC4C1C9ULL,
		0xFA659C7E4F37D4A0ULL,
		0x888450B975FA1C40ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3460000000000000ULL,
		0x311DCB73A4392513ULL,
		0xE3F24D4B1834DB0DULL,
		0x7B06C98952E85294ULL,
		0x1C9B60912B9F1553ULL,
		0x4A02A0BE23C4EC4CULL,
		0xC40FA659C7E4F37DULL,
		0x000888450B975FA1ULL
	}};
	shift = 52;
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
		0x1DE9CE5B602B2B55ULL,
		0x20935CFE0B217615ULL,
		0x5842BC1DD81D2125ULL,
		0x42366E2A8A2ED309ULL,
		0xF2959A467E7816C8ULL,
		0x1F1A6D889E32DB46ULL,
		0x67D49A33F89A5C20ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCE5B602B2B550000ULL,
		0x5CFE0B2176151DE9ULL,
		0xBC1DD81D21252093ULL,
		0x6E2A8A2ED3095842ULL,
		0x9A467E7816C84236ULL,
		0x6D889E32DB46F295ULL,
		0x9A33F89A5C201F1AULL,
		0x00000000000067D4ULL
	}};
	shift = 16;
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
		0x877C7466AC8E769DULL,
		0x7179D9DFB9BD1F43ULL,
		0x03B6FEC1B6A2B442ULL,
		0xA509A76ED1E6BCE7ULL,
		0x082C4A933C6BBD59ULL,
		0x503AAB1C56EBE01FULL,
		0x41CB29C2A33472C8ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE800000000000000ULL,
		0x1C3BE3A3356473B4ULL,
		0x138BCECEFDCDE8FAULL,
		0x381DB7F60DB515A2ULL,
		0xCD284D3B768F35E7ULL,
		0xF841625499E35DEAULL,
		0x4281D558E2B75F00ULL,
		0x020E594E1519A396ULL
	}};
	shift = 59;
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
		0xFC2C19FA11CCE9E9ULL,
		0xE3711B2E41736658ULL,
		0xBB3CD7C4F772BAB0ULL,
		0x62AE0D7F0CE5DA3DULL,
		0xB735C23A7D4B3A93ULL,
		0x1E06C493C123DB2CULL,
		0x51A9FECC44413D5DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0B067E84733A7A40ULL,
		0xDC46CB905CD9963FULL,
		0xCF35F13DDCAEAC38ULL,
		0xAB835FC339768F6EULL,
		0xCD708E9F52CEA4D8ULL,
		0x81B124F048F6CB2DULL,
		0x6A7FB311104F5747ULL,
		0x0000000000000014ULL
	}};
	shift = 6;
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
		0xF7AC030492519F8FULL,
		0x7E8A6F1FB7DF63F9ULL,
		0xBDDD228010411C58ULL,
		0x661283A1E485EC93ULL,
		0x570ACB15B144D9A6ULL,
		0xC2BAA78712F7E7BFULL,
		0x65750F3CF330BBDBULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x58060924A33F1E00ULL,
		0x14DE3F6FBEC7F3EFULL,
		0xBA4500208238B0FDULL,
		0x250743C90BD9277BULL,
		0x15962B6289B34CCCULL,
		0x754F0E25EFCF7EAEULL,
		0xEA1E79E66177B785ULL,
		0x00000000000000CAULL
	}};
	shift = 9;
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
		0xF50F894B6B6F341CULL,
		0xF9E78F73D8C2F396ULL,
		0x6375FDCD50A4AF41ULL,
		0xF5ADDC1A8A9C70C3ULL,
		0xD190A17871F6738EULL,
		0x8D87AD43197BA465ULL,
		0xE4428111973C3D0FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x96D6DE6838000000ULL,
		0xE7B185E72DEA1F12ULL,
		0x9AA1495E83F3CF1EULL,
		0x351538E186C6EBFBULL,
		0xF0E3ECE71DEB5BB8ULL,
		0x8632F748CBA32142ULL,
		0x232E787A1F1B0F5AULL,
		0x0000000001C88502ULL
	}};
	shift = 25;
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
		0x89C37AC24DB7F173ULL,
		0xC7E3F43B44E880DFULL,
		0xD14A4D1A0BF77AFAULL,
		0xAD354ABA418F8F9FULL,
		0x0B623B6F2962665FULL,
		0x533B337674473ADCULL,
		0x5E291703246D0EA8ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0936DFC5CC000000ULL,
		0xED13A2037E270DEBULL,
		0x682FDDEBEB1F8FD0ULL,
		0xE9063E3E7F452934ULL,
		0xBCA589997EB4D52AULL,
		0xD9D11CEB702D88EDULL,
		0x0C91B43AA14CECCDULL,
		0x000000000178A45CULL
	}};
	shift = 26;
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
		0x2C35F4E734041C1AULL,
		0x1E301D895B958940ULL,
		0x66A1DB9D6705E6F2ULL,
		0x26EAE4E8E60FCF43ULL,
		0xE42D2F7FA9DF087CULL,
		0x792D2AE9B71CA557ULL,
		0x250F7960CBEA9D50ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4E734041C1A00000ULL,
		0xD895B9589402C35FULL,
		0xB9D6705E6F21E301ULL,
		0x4E8E60FCF4366A1DULL,
		0xF7FA9DF087C26EAEULL,
		0xAE9B71CA557E42D2ULL,
		0x960CBEA9D50792D2ULL,
		0x00000000000250F7ULL
	}};
	shift = 20;
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
		0x2F22737F4CC96664ULL,
		0xC067861D4AD400E8ULL,
		0x67FD48C32DC46633ULL,
		0x65F051824D40ECFDULL,
		0x1485FE3091726227ULL,
		0x39BCBBA52E7B6F96ULL,
		0x64EA80C442C68836ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF22737F4CC966640ULL,
		0x067861D4AD400E82ULL,
		0x7FD48C32DC46633CULL,
		0x5F051824D40ECFD6ULL,
		0x485FE30917262276ULL,
		0x9BCBBA52E7B6F961ULL,
		0x4EA80C442C688363ULL,
		0x0000000000000006ULL
	}};
	shift = 4;
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
		0xB9B5EF59D1593691ULL,
		0x11650DEF74D3F682ULL,
		0x6DF3981F6C198848ULL,
		0xF7EECBC603A01B13ULL,
		0x79AF133E039F4716ULL,
		0x39716FBC3D3D070AULL,
		0xC997111E6584BB6BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDA44000000000000ULL,
		0xDA0AE6D7BD674564ULL,
		0x2120459437BDD34FULL,
		0x6C4DB7CE607DB066ULL,
		0x1C5BDFBB2F180E80ULL,
		0x1C29E6BC4CF80E7DULL,
		0xEDACE5C5BEF0F4F4ULL,
		0x0003265C44799612ULL
	}};
	shift = 50;
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
		0x4A6A3E61C2CEB5CBULL,
		0xE6DDAE607090AF06ULL,
		0x0717CBAC5F97BC59ULL,
		0x19BFEC5B675C92C9ULL,
		0x5C7B1CE342D48B37ULL,
		0x32E7EF6FEF47ECDDULL,
		0xE649BDCB76D51E3EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x47CC3859D6B96000ULL,
		0xB5CC0E1215E0C94DULL,
		0xF9758BF2F78B3CDBULL,
		0xFD8B6CEB925920E2ULL,
		0x639C685A9166E337ULL,
		0xFDEDFDE8FD9BAB8FULL,
		0x37B96EDAA3C7C65CULL,
		0x0000000000001CC9ULL
	}};
	shift = 13;
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
		0xE76FDDFFCA1E62C9ULL,
		0x7FB9F2AAFC8893BEULL,
		0x74C554A9FFB5C430ULL,
		0x874628ED080E9033ULL,
		0xF1D045D90692DED2ULL,
		0x601BAD57E5E00DDEULL,
		0xCC83553B47A94121ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE76FDDFFCA1E62C9ULL,
		0x7FB9F2AAFC8893BEULL,
		0x74C554A9FFB5C430ULL,
		0x874628ED080E9033ULL,
		0xF1D045D90692DED2ULL,
		0x601BAD57E5E00DDEULL,
		0xCC83553B47A94121ULL,
		0x0000000000000000ULL
	}};
	shift = 0;
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
		0x976B61D5D9DF2949ULL,
		0x75CBFC03EA6D30FEULL,
		0x0352492BBB14DC06ULL,
		0xB293D8781E9B7047ULL,
		0xB13C94229D597ED7ULL,
		0xC1AFEB35AADDE211ULL,
		0xF14C73D4B5435D33ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAD8757677CA52400ULL,
		0x2FF00FA9B4C3FA5DULL,
		0x4924AEEC537019D7ULL,
		0x4F61E07A6DC11C0DULL,
		0xF2508A7565FB5ECAULL,
		0xBFACD6AB778846C4ULL,
		0x31CF52D50D74CF06ULL,
		0x00000000000003C5ULL
	}};
	shift = 10;
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
		0xB5D9E45DE6B0D4D6ULL,
		0xEA949027AE09B846ULL,
		0xBD047A63ACCB4390ULL,
		0x70160F7FB2F39535ULL,
		0x368918DDF483A8FDULL,
		0x4DBDFC44A4485C0AULL,
		0x82E74346581BDC31ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1779AC3535800000ULL,
		0x09EB826E11AD7679ULL,
		0x98EB32D0E43AA524ULL,
		0xDFECBCE54D6F411EULL,
		0x377D20EA3F5C0583ULL,
		0x11291217028DA246ULL,
		0xD19606F70C536F7FULL,
		0x000000000020B9D0ULL
	}};
	shift = 22;
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
		0x2C24F60D7CB69CDBULL,
		0xBB0BDFB86B2362ADULL,
		0xABB55C5BC8BD77C4ULL,
		0xEFEB17E405CA8E4DULL,
		0x875F642754392EB1ULL,
		0x301AEB45C20FA46FULL,
		0xA96F1C60F6EFBF86ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x093D835F2DA736C0ULL,
		0xC2F7EE1AC8D8AB4BULL,
		0xED5716F22F5DF12EULL,
		0xFAC5F90172A3936AULL,
		0xD7D909D50E4BAC7BULL,
		0x06BAD17083E91BE1ULL,
		0x5BC7183DBBEFE18CULL,
		0x000000000000002AULL
	}};
	shift = 6;
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
		0x42223E823167E713ULL,
		0xB8A2098BB313E710ULL,
		0x88002F9F53E92D01ULL,
		0x9E802DFC65384021ULL,
		0xE631C730C63CF9B3ULL,
		0x30E59D506543B257ULL,
		0xAA763EE3311575FCULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x59F9C4C000000000ULL,
		0xC4F9C410888FA08CULL,
		0xFA4B406E288262ECULL,
		0x4E100862000BE7D4ULL,
		0x8F3E6CE7A00B7F19ULL,
		0x50EC95F98C71CC31ULL,
		0x455D7F0C39675419ULL,
		0x0000002A9D8FB8CCULL
	}};
	shift = 38;
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
		0x32A5240619FB3EC3ULL,
		0xDDE7247ACDCE823EULL,
		0xB55A6B21B9A2CFBCULL,
		0x4320AC20F1C8FAE2ULL,
		0x68D8E4CBEF59102DULL,
		0x4C38E5F9B7BC7FE1ULL,
		0x15357E5416B81A19ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6180000000000000ULL,
		0x1F195292030CFD9FULL,
		0xDE6EF3923D66E741ULL,
		0x715AAD3590DCD167ULL,
		0x16A190561078E47DULL,
		0xF0B46C7265F7AC88ULL,
		0x0CA61C72FCDBDE3FULL,
		0x000A9ABF2A0B5C0DULL
	}};
	shift = 55;
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
		0x5A59CFF555C431FFULL,
		0xD1CD8C3516042228ULL,
		0x8577D8C2F416385EULL,
		0xB56E24B2265A5537ULL,
		0x614DC350800B8201ULL,
		0x1B42F22111982BC5ULL,
		0x090C4D50BA141E81ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7FAAAE218FF80000ULL,
		0x61A8B0211142D2CEULL,
		0xC617A0B1C2F68E6CULL,
		0x259132D2A9BC2BBEULL,
		0x1A84005C100DAB71ULL,
		0x91088CC15E2B0A6EULL,
		0x6A85D0A0F408DA17ULL,
		0x0000000000004862ULL
	}};
	shift = 19;
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
		0x9583E27F4276AE0DULL,
		0x741836D45156542AULL,
		0x7F226C19F81ED803ULL,
		0xB16C23F3912C54A0ULL,
		0xE363085602EC017FULL,
		0x68D8112669458487ULL,
		0xD49AA1650AFFE1D3ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4ED5C1A000000000ULL,
		0x2ACA8552B07C4FE8ULL,
		0x03DB006E8306DA8AULL,
		0x258A940FE44D833FULL,
		0x5D802FF62D847E72ULL,
		0x28B090FC6C610AC0ULL,
		0x5FFC3A6D1B0224CDULL,
		0x0000001A93542CA1ULL
	}};
	shift = 37;
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
		0xF33F8C862F36D30AULL,
		0xD9FA2B1CC8871710ULL,
		0x8552B325759963CEULL,
		0x236B46FADFAEFF75ULL,
		0x5DBB70D96F6E0885ULL,
		0x1436A5031EABD28BULL,
		0xB6237E9B840E1064ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB4C2800000000000ULL,
		0xC5C43CCFE3218BCDULL,
		0x58F3B67E8AC73221ULL,
		0xBFDD6154ACC95D66ULL,
		0x822148DAD1BEB7EBULL,
		0xF4A2D76EDC365BDBULL,
		0x8419050DA940C7AAULL,
		0x00002D88DFA6E103ULL
	}};
	shift = 46;
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
		0x8F008BB494B3F9A6ULL,
		0x1CC6C1F0127731BFULL,
		0xDAF34F3A038690A9ULL,
		0x4B51C4E18D8C9B00ULL,
		0x9BB9BC84E4B171D1ULL,
		0xBB4BFE030EC674F7ULL,
		0xA54C0E0A3B7497ECULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF9A6000000000000ULL,
		0x31BF8F008BB494B3ULL,
		0x90A91CC6C1F01277ULL,
		0x9B00DAF34F3A0386ULL,
		0x71D14B51C4E18D8CULL,
		0x74F79BB9BC84E4B1ULL,
		0x97ECBB4BFE030EC6ULL,
		0x0000A54C0E0A3B74ULL
	}};
	shift = 48;
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
		0xAABA5085634FCC07ULL,
		0x100F37AD15CA8CC2ULL,
		0xCFFB59319A86393AULL,
		0x014BCB5294180A43ULL,
		0x9F824518934291ACULL,
		0x39B74D20C72B4FFCULL,
		0x49D82D93D63252E3ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8000000000000000ULL,
		0x555D2842B1A7E603ULL,
		0x08079BD68AE54661ULL,
		0xE7FDAC98CD431C9DULL,
		0x00A5E5A94A0C0521ULL,
		0x4FC1228C49A148D6ULL,
		0x9CDBA6906395A7FEULL,
		0x24EC16C9EB192971ULL
	}};
	shift = 63;
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
		0x089AA1C3861254D7ULL,
		0xBB42F3B837806B6DULL,
		0x4F43FA3A2FA52B2FULL,
		0x70C5C6CC356A6524ULL,
		0xBD1B3E7A081DADACULL,
		0xD9B01AA2CB15B448ULL,
		0xCFFF5202E5BA7493ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x61254D7000000000ULL,
		0x7806B6D089AA1C38ULL,
		0xFA52B2FBB42F3B83ULL,
		0x56A65244F43FA3A2ULL,
		0x81DADAC70C5C6CC3ULL,
		0xB15B448BD1B3E7A0ULL,
		0x5BA7493D9B01AA2CULL,
		0x0000000CFFF5202EULL
	}};
	shift = 36;
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
		0x2F508DECD3235ADDULL,
		0xBAD0FD4A8A4E038CULL,
		0x0BF5C5250361EC76ULL,
		0xD2E10A8966D325BAULL,
		0xD3694680B4263322ULL,
		0xEBA104BEFD1A040EULL,
		0xC683E51233167FCCULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD6B7400000000000ULL,
		0x80E30BD4237B34C8ULL,
		0x7B1DAEB43F52A293ULL,
		0xC96E82FD714940D8ULL,
		0x8CC8B4B842A259B4ULL,
		0x8103B4DA51A02D09ULL,
		0x9FF33AE8412FBF46ULL,
		0x000031A0F9448CC5ULL
	}};
	shift = 46;
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
		0x4AF983AFCB2D3825ULL,
		0x5237887FF3F213E9ULL,
		0x47614165AE677FD5ULL,
		0x7E82D57543B9585EULL,
		0x50784F35EAC88A67ULL,
		0xFFB8D962E11F5555ULL,
		0x881A21BD7F79EC8EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9400000000000000ULL,
		0xA52BE60EBF2CB4E0ULL,
		0x5548DE21FFCFC84FULL,
		0x791D850596B99DFFULL,
		0x9DFA0B55D50EE561ULL,
		0x5541E13CD7AB2229ULL,
		0x3BFEE3658B847D55ULL,
		0x02206886F5FDE7B2ULL
	}};
	shift = 58;
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
		0xA0FAC2B6A9A62FA1ULL,
		0xDD9426AD8CDF8C58ULL,
		0xB261BE3F643BE7FBULL,
		0x37EEDA1BB4327705ULL,
		0x14C62EC71AFE95F4ULL,
		0xBBA046EBAD5E4FF1ULL,
		0xA0FF3BDABFA1CF29ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4D317D0800000000ULL,
		0x66FC62C507D615B5ULL,
		0x21DF3FDEECA1356CULL,
		0xA193B82D930DF1FBULL,
		0xD7F4AFA1BF76D0DDULL,
		0x6AF27F88A6317638ULL,
		0xFD0E794DDD02375DULL,
		0x0000000507F9DED5ULL
	}};
	shift = 35;
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
		0xFECF24D2081935ADULL,
		0x409A4C08D4BC7EC5ULL,
		0xF436C28503DD187BULL,
		0xE84AF793BB53E0F6ULL,
		0xE0D311B84C1466BCULL,
		0x8690FEEB59D1A4C2ULL,
		0xB70E999FFD7C81E7ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF24D2081935AD000ULL,
		0xA4C08D4BC7EC5FECULL,
		0x6C28503DD187B409ULL,
		0xAF793BB53E0F6F43ULL,
		0x311B84C1466BCE84ULL,
		0x0FEEB59D1A4C2E0DULL,
		0xE999FFD7C81E7869ULL,
		0x0000000000000B70ULL
	}};
	shift = 12;
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
		0xA97461A7420374F3ULL,
		0x33CC2F3C9A09C16EULL,
		0x58B0064F467FD2E3ULL,
		0x6C8F6585F34561D3ULL,
		0x4B3EC2C75D1A60F6ULL,
		0xECED5415EA676136ULL,
		0xDFE23EA105872222ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4E8406E9E6000000ULL,
		0x79341382DD52E8C3ULL,
		0x9E8CFFA5C667985EULL,
		0x0BE68AC3A6B1600CULL,
		0x8EBA34C1ECD91ECBULL,
		0x2BD4CEC26C967D85ULL,
		0x420B0E4445D9DAA8ULL,
		0x0000000001BFC47DULL
	}};
	shift = 25;
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
		0x4096B761A85A763DULL,
		0xFFBA4EDBF2431CE0ULL,
		0x005F5FCFE325C54CULL,
		0x7497D773AC9D947DULL,
		0x6C5F4C3BE5E83384ULL,
		0xB0B4176BB7CD75FDULL,
		0x797429175ADC053EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1E80000000000000ULL,
		0x70204B5BB0D42D3BULL,
		0xA67FDD276DF9218EULL,
		0x3E802FAFE7F192E2ULL,
		0xC23A4BEBB9D64ECAULL,
		0xFEB62FA61DF2F419ULL,
		0x9F585A0BB5DBE6BAULL,
		0x003CBA148BAD6E02ULL
	}};
	shift = 55;
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
		0x84AF368927F8A8B2ULL,
		0xD4BB53A51C50E416ULL,
		0x7F045D741FAEBADBULL,
		0x4FBCF00D7D390F38ULL,
		0xF1A4266B4F9FFCFEULL,
		0xEC241A8A32F24D62ULL,
		0x7BE1050359F5274DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4590000000000000ULL,
		0x20B42579B4493FC5ULL,
		0xD6DEA5DA9D28E287ULL,
		0x79C3F822EBA0FD75ULL,
		0xE7F27DE7806BE9C8ULL,
		0x6B178D21335A7CFFULL,
		0x3A6F6120D4519792ULL,
		0x0003DF08281ACFA9ULL
	}};
	shift = 51;
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
		0xB0B810936A207D49ULL,
		0x6CAAF4323F5093FBULL,
		0x1786C9374193AD38ULL,
		0xE88CB0FEFD229BE3ULL,
		0x390887F752DC62EEULL,
		0x06606A007F86FB9DULL,
		0x4CA8091E9E7B93F0ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x85C0849B5103EA48ULL,
		0x6557A191FA849FDDULL,
		0xBC3649BA0C9D69C3ULL,
		0x446587F7E914DF18ULL,
		0xC8443FBA96E31777ULL,
		0x33035003FC37DCE9ULL,
		0x654048F4F3DC9F80ULL,
		0x0000000000000002ULL
	}};
	shift = 3;
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
		0xA85E99A3CA9E5784ULL,
		0x4D571D887D52FA4DULL,
		0x35E03D1C3A1C75E2ULL,
		0xBC90CD3E92F42E52ULL,
		0x1381DB76FAC46B73ULL,
		0x26DD786D844A3755ULL,
		0x26DBCD7979B13A10ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA9E5784000000000ULL,
		0xD52FA4DA85E99A3CULL,
		0xA1C75E24D571D887ULL,
		0x2F42E5235E03D1C3ULL,
		0xAC46B73BC90CD3E9ULL,
		0x44A37551381DB76FULL,
		0x9B13A1026DD786D8ULL,
		0x000000026DBCD797ULL
	}};
	shift = 36;
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
		0xCF231548002D89D0ULL,
		0x32042041587DF3DCULL,
		0xD05DD110F6ED8A05ULL,
		0x89CAA1E013805D9CULL,
		0xEF595ADB7863FBBCULL,
		0xAC722901DCA12563ULL,
		0xA16F34C443C7DC3CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x16C4E80000000000ULL,
		0x3EF9EE67918AA400ULL,
		0x76C50299021020ACULL,
		0xC02ECE682EE8887BULL,
		0x31FDDE44E550F009ULL,
		0x5092B1F7ACAD6DBCULL,
		0xE3EE1E56391480EEULL,
		0x00000050B79A6221ULL
	}};
	shift = 39;
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
		0x540B40824A66F4D6ULL,
		0x89B70FC336A2AF65ULL,
		0xB6F0A5A540EBB926ULL,
		0x421D8C3481612ACAULL,
		0x7B69AD1D7DCFF85DULL,
		0xF77768558DA2824EULL,
		0x0CD70F652E59D983ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6810494CDE9AC000ULL,
		0xE1F866D455ECAA81ULL,
		0x14B4A81D7724D136ULL,
		0xB186902C255956DEULL,
		0x35A3AFB9FF0BA843ULL,
		0xED0AB1B45049CF6DULL,
		0xE1ECA5CB3B307EEEULL,
		0x000000000000019AULL
	}};
	shift = 13;
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
		0x0692372D9C719BE4ULL,
		0x0EC27375598C6CB8ULL,
		0xE354607185D958CEULL,
		0x3799A2A619618693ULL,
		0x3757D5AE9CEF70C0ULL,
		0x12584D9A85CD9B79ULL,
		0xDEA3595CA576CB58ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCDF2000000000000ULL,
		0x365C03491B96CE38ULL,
		0xAC67076139BAACC6ULL,
		0xC349F1AA3038C2ECULL,
		0xB8601BCCD1530CB0ULL,
		0xCDBC9BABEAD74E77ULL,
		0x65AC092C26CD42E6ULL,
		0x00006F51ACAE52BBULL
	}};
	shift = 47;
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
		0x7F1447C9E83328B4ULL,
		0xD4839340F4175752ULL,
		0xE84E10FD392020DCULL,
		0x902ED896CCBD398AULL,
		0xA5FCDC64D16C83E2ULL,
		0x47774D4C96FD2714ULL,
		0x7E2F37D508C5D5F1ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4F419945A0000000ULL,
		0x07A0BABA93F8A23EULL,
		0xE9C90106E6A41C9AULL,
		0xB665E9CC57427087ULL,
		0x268B641F148176C4ULL,
		0x64B7E938A52FE6E3ULL,
		0xA8462EAF8A3BBA6AULL,
		0x0000000003F179BEULL
	}};
	shift = 27;
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
		0xDC9BBADB3F46381AULL,
		0x4E0D2A4988900C13ULL,
		0x8473BA349EF49BDFULL,
		0xA5FA420752F50EF5ULL,
		0x123657BD69012BE9ULL,
		0x3ED808855688D569ULL,
		0x4982FB73EAC3C67FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x75B67E8C70340000ULL,
		0x549311201827B937ULL,
		0x74693DE937BE9C1AULL,
		0x840EA5EA1DEB08E7ULL,
		0xAF7AD20257D34BF4ULL,
		0x110AAD11AAD2246CULL,
		0xF6E7D5878CFE7DB0ULL,
		0x0000000000009305ULL
	}};
	shift = 17;
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
		0x82B74760ED3E4633ULL,
		0xEDC79C39572ACE13ULL,
		0x8776F041FBB72142ULL,
		0x33BAC37986F77272ULL,
		0xCFF4B3FCC08F8E9BULL,
		0x020E0895D69A49BFULL,
		0x32D140F0B952B2E7ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6000000000000000ULL,
		0x7056E8EC1DA7C8C6ULL,
		0x5DB8F3872AE559C2ULL,
		0x50EEDE083F76E428ULL,
		0x6677586F30DEEE4EULL,
		0xF9FE967F9811F1D3ULL,
		0xE041C112BAD34937ULL,
		0x065A281E172A565CULL
	}};
	shift = 61;
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
		0x96308F1FD58213C0ULL,
		0x3BBFACC867BC276BULL,
		0x19CD14497CFD1993ULL,
		0x42447DD94701C2F5ULL,
		0xCC4346808B3BF3A7ULL,
		0xC8EDD642EBA813A3ULL,
		0x9CCEE05562C985F2ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8F1FD58213C00000ULL,
		0xACC867BC276B9630ULL,
		0x14497CFD19933BBFULL,
		0x7DD94701C2F519CDULL,
		0x46808B3BF3A74244ULL,
		0xD642EBA813A3CC43ULL,
		0xE05562C985F2C8EDULL,
		0x0000000000009CCEULL
	}};
	shift = 16;
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
		0xC635EDC45442CAD4ULL,
		0x7921DAC3675A4FDEULL,
		0x589620BC2F421F8BULL,
		0x8320D82513E371F2ULL,
		0x0ED34920E26871A0ULL,
		0xC966AA80456710C5ULL,
		0x51446723F158EE68ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE22A21656A000000ULL,
		0x61B3AD27EF631AF6ULL,
		0x5E17A10FC5BC90EDULL,
		0x1289F1B8F92C4B10ULL,
		0x90713438D041906CULL,
		0x4022B388628769A4ULL,
		0x91F8AC773464B355ULL,
		0x000000000028A233ULL
	}};
	shift = 23;
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
		0x3BD7B6E11E3FBE34ULL,
		0xA8606AAC8CFAB860ULL,
		0xA1D2FD723B35C4F7ULL,
		0x0968816DC8FD186EULL,
		0x879EA702624D9B7CULL,
		0x1D61C1F6A06F9F4EULL,
		0x28EF68942E129C3FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x708F1FDF1A000000ULL,
		0x56467D5C301DEBDBULL,
		0xB91D9AE27BD43035ULL,
		0xB6E47E8C3750E97EULL,
		0x813126CDBE04B440ULL,
		0xFB5037CFA743CF53ULL,
		0x4A17094E1F8EB0E0ULL,
		0x00000000001477B4ULL
	}};
	shift = 23;
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
		0x10D01673D3DC274EULL,
		0xF175D92A2A0357E2ULL,
		0x8BD8086037431E79ULL,
		0xBC9DF848CAB588B9ULL,
		0xAD2C94022D7F18F3ULL,
		0x7E50F143AB1079F8ULL,
		0x69211A319E5888A6ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD380000000000000ULL,
		0xF88434059CF4F709ULL,
		0x9E7C5D764A8A80D5ULL,
		0x2E62F602180DD0C7ULL,
		0x3CEF277E1232AD62ULL,
		0x7E2B4B25008B5FC6ULL,
		0x299F943C50EAC41EULL,
		0x001A48468C679622ULL
	}};
	shift = 54;
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
		0x395ED5FF0890FAD4ULL,
		0x512FF4F3A9BF1273ULL,
		0x3BC8F285CFB620A7ULL,
		0xABC37A998B780EE1ULL,
		0x22576D6877529F01ULL,
		0xEC1A0187C9FB364DULL,
		0xBC22FF19ED6D6BBBULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDABFE1121F5A8000ULL,
		0xFE9E7537E24E672BULL,
		0x1E50B9F6C414EA25ULL,
		0x6F53316F01DC2779ULL,
		0xEDAD0EEA53E03578ULL,
		0x4030F93F66C9A44AULL,
		0x5FE33DADAD777D83ULL,
		0x0000000000001784ULL
	}};
	shift = 13;
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
		0x538CE16F8CA36841ULL,
		0xFC4E3B7344C180D5ULL,
		0x83FBD42B38264631ULL,
		0x0803678D1B0F8286ULL,
		0xCF1770E4F9CF01A2ULL,
		0x872030C996AF9ED8ULL,
		0x599E267B76F061CEULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x670B7C651B420800ULL,
		0x71DB9A260C06AA9CULL,
		0xDEA159C132318FE2ULL,
		0x1B3C68D87C14341FULL,
		0xBB8727CE780D1040ULL,
		0x01864CB57CF6C678ULL,
		0xF133DBB7830E7439ULL,
		0x00000000000002CCULL
	}};
	shift = 11;
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
		0x64D8C4CC435C3FCBULL,
		0x72647EB9D8A5CC91ULL,
		0x1DBD2757C9534DFDULL,
		0xF03C3F86FC3A9659ULL,
		0x1E2268A588C2E810ULL,
		0x0F12B6B187087DAAULL,
		0x8E7601956D76D85DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0D70FF2C00000000ULL,
		0x6297324593631331ULL,
		0x254D37F5C991FAE7ULL,
		0xF0EA596476F49D5FULL,
		0x230BA043C0F0FE1BULL,
		0x1C21F6A87889A296ULL,
		0xB5DB61743C4ADAC6ULL,
		0x0000000239D80655ULL
	}};
	shift = 34;
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
		0xE67931C788611699ULL,
		0xBFC56C74802CA457ULL,
		0x4FECC90EC0E34CC8ULL,
		0x12E0ADD45DD78F8BULL,
		0x1A5BA142AAF6F3C4ULL,
		0x09C6C69A29AC2AA3ULL,
		0xCA7A147FFB6C61A4ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x638F10C22D320000ULL,
		0xD8E9005948AFCCF2ULL,
		0x921D81C699917F8AULL,
		0x5BA8BBAF1F169FD9ULL,
		0x428555EDE78825C1ULL,
		0x8D345358554634B7ULL,
		0x28FFF6D8C348138DULL,
		0x00000000000194F4ULL
	}};
	shift = 17;
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
		0xBB8DEDC7087D78FCULL,
		0x413E160ACE5EFAD0ULL,
		0xD1E8BE64572D0EF2ULL,
		0xDD7A6638CD617C7FULL,
		0x64918086B045C67BULL,
		0xAB2D487D4FEA8C7EULL,
		0xFAE6A545155A7A4DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x78FC000000000000ULL,
		0xFAD0BB8DEDC7087DULL,
		0x0EF2413E160ACE5EULL,
		0x7C7FD1E8BE64572DULL,
		0xC67BDD7A6638CD61ULL,
		0x8C7E64918086B045ULL,
		0x7A4DAB2D487D4FEAULL,
		0x0000FAE6A545155AULL
	}};
	shift = 48;
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
		0x27EA6BAFE7BABD9FULL,
		0xD6D7C3365EBEBCFAULL,
		0xB993E96A78C05C8BULL,
		0x5453530BAAAD4549ULL,
		0x41EEB62CF0C02DF0ULL,
		0x681D20424048FE2AULL,
		0x69CF31EB18A6AC0CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8000000000000000ULL,
		0x13F535D7F3DD5ECFULL,
		0xEB6BE19B2F5F5E7DULL,
		0xDCC9F4B53C602E45ULL,
		0x2A29A985D556A2A4ULL,
		0x20F75B16786016F8ULL,
		0x340E902120247F15ULL,
		0x34E798F58C535606ULL
	}};
	shift = 63;
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
		0xD5450794FFCE071DULL,
		0xEB7F7B0C78403329ULL,
		0xA9819770FB3C9256ULL,
		0xF46BEA5B5AC865D1ULL,
		0x9383614AB7F3102BULL,
		0x95601CE27C39DF8DULL,
		0xAFBD2A4A76B8369AULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCE071D0000000000ULL,
		0x403329D5450794FFULL,
		0x3C9256EB7F7B0C78ULL,
		0xC865D1A9819770FBULL,
		0xF3102BF46BEA5B5AULL,
		0x39DF8D9383614AB7ULL,
		0xB8369A95601CE27CULL,
		0x000000AFBD2A4A76ULL
	}};
	shift = 40;
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
		0x8BEE080EC2DDCCD9ULL,
		0x65B47241E4090673ULL,
		0x1E409469CE6E8B94ULL,
		0x80A3975953C4741BULL,
		0x3E129DB45B947313ULL,
		0x96EFD929D49CE2F6ULL,
		0x98532B073D9B958CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB99B200000000000ULL,
		0x20CE717DC101D85BULL,
		0xD1728CB68E483C81ULL,
		0x8E8363C8128D39CDULL,
		0x8E62701472EB2A78ULL,
		0x9C5EC7C253B68B72ULL,
		0x72B192DDFB253A93ULL,
		0x0000130A6560E7B3ULL
	}};
	shift = 45;
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
		0x6ACEADEB5DAAA166ULL,
		0x31461BC1675DB041ULL,
		0xFCA7F0058E943434ULL,
		0xB2A74B06B20BC541ULL,
		0xACAA5F9B52296A76ULL,
		0x90A90393A41233AAULL,
		0x944AEA0EFA0B4C27ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xB56756F5AED550B3ULL,
		0x18A30DE0B3AED820ULL,
		0xFE53F802C74A1A1AULL,
		0x5953A5835905E2A0ULL,
		0x56552FCDA914B53BULL,
		0xC85481C9D20919D5ULL,
		0x4A2575077D05A613ULL
	}};
	shift = 63;
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
		0x468F71F4A0F21B3FULL,
		0x1B565ECB1F97A237ULL,
		0x23F69BAA3E7DC1ECULL,
		0x7BA9341A59A4AE54ULL,
		0x22D4AC2A9A4F0AB4ULL,
		0x093F1B20B4624199ULL,
		0x58EDE7EEFDB42FE1ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1B3F000000000000ULL,
		0xA237468F71F4A0F2ULL,
		0xC1EC1B565ECB1F97ULL,
		0xAE5423F69BAA3E7DULL,
		0x0AB47BA9341A59A4ULL,
		0x419922D4AC2A9A4FULL,
		0x2FE1093F1B20B462ULL,
		0x000058EDE7EEFDB4ULL
	}};
	shift = 48;
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
		0xA7A54E712F815E07ULL,
		0xD1ED4716EE35F401ULL,
		0xA8DB9B1228DD5195ULL,
		0x59FC922B35BFFCA3ULL,
		0xE32E33B40F87E9DFULL,
		0xF97D3C4A8B4A6D6EULL,
		0xB7693859A32C2776ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x12F815E070000000ULL,
		0x6EE35F401A7A54E7ULL,
		0x228DD5195D1ED471ULL,
		0xB35BFFCA3A8DB9B1ULL,
		0x40F87E9DF59FC922ULL,
		0xA8B4A6D6EE32E33BULL,
		0x9A32C2776F97D3C4ULL,
		0x000000000B769385ULL
	}};
	shift = 28;
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
		0x548B23A0E95B0CA0ULL,
		0x115864E0C348E3A8ULL,
		0x78BE6B24E76CD7B5ULL,
		0xE81251661D6E8D47ULL,
		0xB6D0B9D88A8C6ECFULL,
		0x1D1449B4C46616BAULL,
		0x592FD2E418923844ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3280000000000000ULL,
		0x8EA1522C8E83A56CULL,
		0x5ED4456193830D23ULL,
		0x351DE2F9AC939DB3ULL,
		0xBB3FA049459875BAULL,
		0x5AEADB42E7622A31ULL,
		0xE110745126D31198ULL,
		0x000164BF4B906248ULL
	}};
	shift = 50;
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
		0x75B32317C8208249ULL,
		0xC93B689EFF2CBDB3ULL,
		0x416FFA378763AFCFULL,
		0xEE92ED3CC1982517ULL,
		0x2ED900B478465D93ULL,
		0x9FD7D144E0762CEDULL,
		0x620D034B0CADD170ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2317C82082490000ULL,
		0x689EFF2CBDB375B3ULL,
		0xFA378763AFCFC93BULL,
		0xED3CC1982517416FULL,
		0x00B478465D93EE92ULL,
		0xD144E0762CED2ED9ULL,
		0x034B0CADD1709FD7ULL,
		0x000000000000620DULL
	}};
	shift = 16;
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
		0xB1275820ACDFDDFBULL,
		0x9D8624118FED788CULL,
		0x385E09DB139E57B2ULL,
		0x45CCE972BD1F2210ULL,
		0xEB9A1D0CDE9A02EEULL,
		0x62AE3055BE2BE284ULL,
		0x483C7DAD4EFC9179ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6FEEFD8000000000ULL,
		0xF6BC465893AC1056ULL,
		0xCF2BD94EC31208C7ULL,
		0x8F91081C2F04ED89ULL,
		0x4D017722E674B95EULL,
		0x15F14275CD0E866FULL,
		0x7E48BCB157182ADFULL,
		0x000000241E3ED6A7ULL
	}};
	shift = 39;
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
		0x4D262335DB540BC8ULL,
		0x676B9D801D33DE40ULL,
		0x93123595A9E33580ULL,
		0x9ED28FEA0278D9DFULL,
		0x9376A75327B3AEFBULL,
		0x4B379E6829F27C8CULL,
		0xB134B144953926E9ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAEDAA05E40000000ULL,
		0x00E99EF202693119ULL,
		0xAD4F19AC033B5CECULL,
		0x5013C6CEFC9891ACULL,
		0x993D9D77DCF6947FULL,
		0x414F93E4649BB53AULL,
		0x24A9C9374A59BCF3ULL,
		0x000000000589A58AULL
	}};
	shift = 27;
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
		0x488E550A52C29C57ULL,
		0xD4C96FE60C0D478BULL,
		0x2865726B1CBCD06CULL,
		0x2CA93A09B2BD7217ULL,
		0xCDC602C58D8AF5B9ULL,
		0x33D94D0831EBCA95ULL,
		0x853621F3ADEBDB23ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x715C000000000000ULL,
		0x1E2D223954294B0AULL,
		0x41B35325BF983035ULL,
		0xC85CA195C9AC72F3ULL,
		0xD6E4B2A4E826CAF5ULL,
		0x2A5737180B16362BULL,
		0x6C8CCF653420C7AFULL,
		0x000214D887CEB7AFULL
	}};
	shift = 50;
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
		0xAE4EE61B83FCA7B8ULL,
		0x3E62874A7C646AB2ULL,
		0x437C38C73F829B9AULL,
		0xAAC4D2C8DBFDAAEEULL,
		0xA102DCFA5F1D3ED7ULL,
		0xFD93940AB9514244ULL,
		0x8F1E09541A83A862ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1FE53DC000000000ULL,
		0xE3235595727730DCULL,
		0xFC14DCD1F3143A53ULL,
		0xDFED57721BE1C639ULL,
		0xF8E9F6BD56269646ULL,
		0xCA8A12250816E7D2ULL,
		0xD41D4317EC9CA055ULL,
		0x0000000478F04AA0ULL
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
		0x37331D9557209573ULL,
		0xF356B1952DE1AAE3ULL,
		0x0180DDCD7CDBFFB5ULL,
		0x1983F728B4B313BBULL,
		0x1AE7C59C82F3F1CFULL,
		0x0D36ABD1CA21D41AULL,
		0x145F9C9C824D7F10ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAB98000000000000ULL,
		0x5719B998ECAAB904ULL,
		0xFDAF9AB58CA96F0DULL,
		0x9DD80C06EE6BE6DFULL,
		0x8E78CC1FB945A598ULL,
		0xA0D0D73E2CE4179FULL,
		0xF88069B55E8E510EULL,
		0x0000A2FCE4E4126BULL
	}};
	shift = 51;
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
		0xEAC727BE73357E40ULL,
		0xE0742E308B3128E0ULL,
		0x40C1F6984EA10038ULL,
		0x8B5BF3B55981B960ULL,
		0x9D5AABDE6C74EEDCULL,
		0x8F716EAFC38E0CC1ULL,
		0x95873DA85FD7AD76ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF900000000000000ULL,
		0xA383AB1C9EF9CCD5ULL,
		0x00E381D0B8C22CC4ULL,
		0xE5810307DA613A84ULL,
		0xBB722D6FCED56606ULL,
		0x3306756AAF79B1D3ULL,
		0xB5DA3DC5BABF0E38ULL,
		0x0002561CF6A17F5EULL
	}};
	shift = 50;
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
		0xCDAD35B63FF6E69DULL,
		0x83B27C419949B68AULL,
		0x3543BB2755A2CD12ULL,
		0xA682F65FD6F9615FULL,
		0x24AA622E392BA1F5ULL,
		0xE9761FE31EE63089ULL,
		0x454BC2942B538955ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8FFDB9A740000000ULL,
		0x66526DA2B36B4D6DULL,
		0xD568B344A0EC9F10ULL,
		0xF5BE5857CD50EEC9ULL,
		0x8E4AE87D69A0BD97ULL,
		0xC7B98C22492A988BULL,
		0x0AD4E2557A5D87F8ULL,
		0x000000001152F0A5ULL
	}};
	shift = 30;
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
		0x43C0124266BD5960ULL,
		0x52E8F0CC61348469ULL,
		0xC9D898D29EAF6BC3ULL,
		0xC1B2681A295EA2C7ULL,
		0x9A508093895277F8ULL,
		0x736AF03E967F0F63ULL,
		0xE832200E3C92BE74ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x049099AF56580000ULL,
		0x3C33184D211A50F0ULL,
		0x2634A7ABDAF0D4BAULL,
		0x9A068A57A8B1F276ULL,
		0x2024E2549DFE306CULL,
		0xBC0FA59FC3D8E694ULL,
		0x88038F24AF9D1CDAULL,
		0x0000000000003A0CULL
	}};
	shift = 14;
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
		0xEB2C9D729B604080ULL,
		0x63955164F4AF2F1EULL,
		0xBE306F15EF31B968ULL,
		0x58F88ECC1CA68114ULL,
		0x6D5BCD36D671AC49ULL,
		0xF136D4FF905AC7B8ULL,
		0xD662C80DCEEA21A8ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEB94DB0204000000ULL,
		0x8B27A57978F75964ULL,
		0x78AF798DCB431CAAULL,
		0x7660E53408A5F183ULL,
		0x69B6B38D624AC7C4ULL,
		0xA7FC82D63DC36ADEULL,
		0x406E77510D4789B6ULL,
		0x000000000006B316ULL
	}};
	shift = 19;
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
		0x1A84E4AADCAD4CB6ULL,
		0x890F59886BBA5AE0ULL,
		0xD61BE6203A0E8A70ULL,
		0xF3CF275216B14280ULL,
		0xC4BB8D6263DB98DDULL,
		0x6AE31ED9BDD535A1ULL,
		0x66084D738D20D501ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8000000000000000ULL,
		0x06A1392AB72B532DULL,
		0x2243D6621AEE96B8ULL,
		0x3586F9880E83A29CULL,
		0x7CF3C9D485AC50A0ULL,
		0x712EE35898F6E637ULL,
		0x5AB8C7B66F754D68ULL,
		0x1982135CE3483540ULL
	}};
	shift = 62;
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
		0x776A894BD6B35F91ULL,
		0xB610CB21655B0603ULL,
		0x2B28E56F4567B0E9ULL,
		0x369E79FDA690E663ULL,
		0x171E7A541AB04DA0ULL,
		0x58E968A485CC6B30ULL,
		0x85B392B4B64B957DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8000000000000000ULL,
		0xBBB544A5EB59AFC8ULL,
		0xDB086590B2AD8301ULL,
		0x959472B7A2B3D874ULL,
		0x1B4F3CFED3487331ULL,
		0x0B8F3D2A0D5826D0ULL,
		0xAC74B45242E63598ULL,
		0x42D9C95A5B25CABEULL
	}};
	shift = 63;
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
		0x02654246F8F4BAB0ULL,
		0x0A7FACF52EF79705ULL,
		0xD72111582DA852B1ULL,
		0x3F4D569E480EF804ULL,
		0x5F1BF2CF9325E7FDULL,
		0x152592339F12804CULL,
		0xB557A85937F8A84BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA5D5800000000000ULL,
		0xBCB828132A1237C7ULL,
		0x42958853FD67A977ULL,
		0x77C026B9088AC16DULL,
		0x2F3FE9FA6AB4F240ULL,
		0x940262F8DF967C99ULL,
		0xC54258A92C919CF8ULL,
		0x000005AABD42C9BFULL
	}};
	shift = 43;
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
		0x673285EC54D687FCULL,
		0x70164AC97C971F92ULL,
		0x1D2C43F18EA6B6B9ULL,
		0x1F3C6F29684D2240ULL,
		0x534C99D3196BF0C2ULL,
		0x220BD00EC945EBE0ULL,
		0xDBCBC15D5DE0040EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x50BD8A9AD0FF8000ULL,
		0xC9592F92E3F24CE6ULL,
		0x887E31D4D6D72E02ULL,
		0x8DE52D09A44803A5ULL,
		0x933A632D7E1843E7ULL,
		0x7A01D928BD7C0A69ULL,
		0x782BABBC0081C441ULL,
		0x0000000000001B79ULL
	}};
	shift = 13;
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
		0xC45DEB3F96245D60ULL,
		0x8427C6927C82680AULL,
		0x7AF93B445B5C4176ULL,
		0x214D19E74DBAF12DULL,
		0x61F7C30509348055ULL,
		0x28F11E9C4A1DA8EAULL,
		0x8ACB4DDC390C09E6ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEB3F96245D600000ULL,
		0xC6927C82680AC45DULL,
		0x3B445B5C41768427ULL,
		0x19E74DBAF12D7AF9ULL,
		0xC30509348055214DULL,
		0x1E9C4A1DA8EA61F7ULL,
		0x4DDC390C09E628F1ULL,
		0x0000000000008ACBULL
	}};
	shift = 16;
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
		0x9271D99179E17EBDULL,
		0xA2407AC3E0054E8DULL,
		0xBF095C6941C0BB10ULL,
		0x9EF1A018DA454D94ULL,
		0x1417D2D5B2F040F2ULL,
		0xE0DBE032DA1527B7ULL,
		0x1C6971669380520CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE800000000000000ULL,
		0x6C938ECC8BCF0BF5ULL,
		0x851203D61F002A74ULL,
		0xA5F84AE34A0E05D8ULL,
		0x94F78D00C6D22A6CULL,
		0xB8A0BE96AD978207ULL,
		0x6706DF0196D0A93DULL,
		0x00E34B8B349C0290ULL
	}};
	shift = 59;
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
		0x2731229CA7F83916ULL,
		0xD94517FB3EACD9B4ULL,
		0x1F3984A30C1A46F7ULL,
		0x331729DECBE43CE8ULL,
		0x3BAD58947618C0BAULL,
		0xBED8253068F9948EULL,
		0x22FDA016278E18D5ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4580000000000000ULL,
		0x6D09CC48A729FE0EULL,
		0xBDF65145FECFAB36ULL,
		0x3A07CE6128C30691ULL,
		0x2E8CC5CA77B2F90FULL,
		0x238EEB56251D8630ULL,
		0x356FB6094C1A3E65ULL,
		0x0008BF680589E386ULL
	}};
	shift = 54;
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
		0x76F3C5D1355EA247ULL,
		0x57D72460C22497B1ULL,
		0x9FA5D69F1FF2A97BULL,
		0x5981E8434B42C51BULL,
		0xEED5D815B88DDC29ULL,
		0xB3367142AA10A5FAULL,
		0xB5B6EBFFCC2EC19EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1C00000000000000ULL,
		0xC5DBCF1744D57A89ULL,
		0xED5F5C918308925EULL,
		0x6E7E975A7C7FCAA5ULL,
		0xA56607A10D2D0B14ULL,
		0xEBBB576056E23770ULL,
		0x7ACCD9C50AA84297ULL,
		0x02D6DBAFFF30BB06ULL
	}};
	shift = 58;
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
		0x38DC7627EB6AE68EULL,
		0x4BBDD241B69471A3ULL,
		0xB055AFBFC73BCD9CULL,
		0x3C9FCE5C2FF54CBBULL,
		0x9606C65582FCC1D5ULL,
		0xA1B4D655F00304F0ULL,
		0x683A83F94EFBC00EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE3B13F5B57347000ULL,
		0xEE920DB4A38D19C6ULL,
		0xAD7DFE39DE6CE25DULL,
		0xFE72E17FAA65DD82ULL,
		0x3632AC17E60EA9E4ULL,
		0xA6B2AF80182784B0ULL,
		0xD41FCA77DE00750DULL,
		0x0000000000000341ULL
	}};
	shift = 11;
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
		0x3C6F73CB96514C0EULL,
		0xB6FF5C3FB36E3917ULL,
		0xFEA28DC20C398BA2ULL,
		0x1A613DBBC99CCDBEULL,
		0xADC49F8406072D4CULL,
		0xE0DF54DF41F5831AULL,
		0x9F77084BD4B4F03DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8DEE7972CA2981C0ULL,
		0xDFEB87F66DC722E7ULL,
		0xD451B84187317456ULL,
		0x4C27B7793399B7DFULL,
		0xB893F080C0E5A983ULL,
		0x1BEA9BE83EB06355ULL,
		0xEEE1097A969E07BCULL,
		0x0000000000000013ULL
	}};
	shift = 5;
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
		0xE960151D5BD4BF48ULL,
		0xEC9E74510072F38EULL,
		0x7AEC3AC637B6B03AULL,
		0xBEDAA209A51B980BULL,
		0x26301EE4DF796817ULL,
		0xCC34464EC7C95936ULL,
		0xFFD269CA180322EFULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF480000000000000ULL,
		0x38EE960151D5BD4BULL,
		0x03AEC9E74510072FULL,
		0x80B7AEC3AC637B6BULL,
		0x817BEDAA209A51B9ULL,
		0x93626301EE4DF796ULL,
		0x2EFCC34464EC7C95ULL,
		0x000FFD269CA18032ULL
	}};
	shift = 52;
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
		0x96BD65C3A98A2F67ULL,
		0x71CADDFB2BDA1FBAULL,
		0x7CEB79D91F46431EULL,
		0x0696AEFFE8760B64ULL,
		0x07188565141BC5E0ULL,
		0xAEF5B95381C9070BULL,
		0x38DC6B06FC4910D9ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA2F6700000000000ULL,
		0xA1FBA96BD65C3A98ULL,
		0x6431E71CADDFB2BDULL,
		0x60B647CEB79D91F4ULL,
		0xBC5E00696AEFFE87ULL,
		0x9070B07188565141ULL,
		0x910D9AEF5B95381CULL,
		0x0000038DC6B06FC4ULL
	}};
	shift = 44;
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
		0xBB1C7A98D9299A60ULL,
		0xE1D6D1CD9393AB9EULL,
		0x4B4D4F359DBA4668ULL,
		0x777825E854874EEDULL,
		0xE5074B84389141C4ULL,
		0xE719620089184A23ULL,
		0x6A233FEF5EE96A58ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4A66980000000000ULL,
		0xE4EAE7AEC71EA636ULL,
		0x6E919A3875B47364ULL,
		0x21D3BB52D353CD67ULL,
		0x2450711DDE097A15ULL,
		0x461288F941D2E10EULL,
		0xBA5A9639C6588022ULL,
		0x0000001A88CFFBD7ULL
	}};
	shift = 38;
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
		0x348D55397268C034ULL,
		0xCEE08BDB859DAB44ULL,
		0x000BD33585A0383DULL,
		0x980CE583BE0809BFULL,
		0x05B7FC5C027D46A5ULL,
		0xDC144A0B8F013BDCULL,
		0xD5F92C56E83F3DC7ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4601A00000000000ULL,
		0xED5A21A46AA9CB93ULL,
		0x01C1EE77045EDC2CULL,
		0x404DF8005E99AC2DULL,
		0xEA352CC0672C1DF0ULL,
		0x09DEE02DBFE2E013ULL,
		0xF9EE3EE0A2505C78ULL,
		0x000006AFC962B741ULL
	}};
	shift = 43;
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
		0x1A62286DA1CEE1F4ULL,
		0xA34C285D940FA0D3ULL,
		0xBDE84BBDE5CF4790ULL,
		0x6D07789822B8A311ULL,
		0x9D9E69C5C1D31F45ULL,
		0x6D86FF0123DD6D12ULL,
		0x9B8A92F3BA9385A6ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7D00000000000000ULL,
		0x34C6988A1B6873B8ULL,
		0xE428D30A176503E8ULL,
		0xC46F7A12EF7973D1ULL,
		0xD15B41DE2608AE28ULL,
		0x44A7679A717074C7ULL,
		0x699B61BFC048F75BULL,
		0x0026E2A4BCEEA4E1ULL
	}};
	shift = 54;
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
		0xB8AD8B5DEA4E2B36ULL,
		0xF77FA414EA294898ULL,
		0xBE97374A5728364BULL,
		0xD9E9F584CB98E777ULL,
		0x68D0345C456093E1ULL,
		0x0AE7B7FDB93ACBA8ULL,
		0xEEF028FC2501441EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x566C000000000000ULL,
		0x9131715B16BBD49CULL,
		0x6C97EEFF4829D452ULL,
		0xCEEF7D2E6E94AE50ULL,
		0x27C3B3D3EB099731ULL,
		0x9750D1A068B88AC1ULL,
		0x883C15CF6FFB7275ULL,
		0x0001DDE051F84A02ULL
	}};
	shift = 49;
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
		0x10BB085ACC44EF22ULL,
		0x22216C42813C8905ULL,
		0xF0619B4578628E48ULL,
		0x94C7CC65BD15BEBEULL,
		0x208D035759AEAF66ULL,
		0x933A1F282E9B853FULL,
		0xD808BA3EA327F065ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x10BB085ACC44EF22ULL,
		0x22216C42813C8905ULL,
		0xF0619B4578628E48ULL,
		0x94C7CC65BD15BEBEULL,
		0x208D035759AEAF66ULL,
		0x933A1F282E9B853FULL,
		0xD808BA3EA327F065ULL,
		0x0000000000000000ULL
	}};
	shift = 0;
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
		0x664A6CBA1663D29AULL,
		0x82CB7DCE5490DC6FULL,
		0x315D948DF261A9EAULL,
		0x7B5B128235AA7135ULL,
		0xEF1F57FC332C8D1FULL,
		0x48149EF6B88715E8ULL,
		0x2B16FB2241DBB855ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6800000000000000ULL,
		0xBD9929B2E8598F4AULL,
		0xAA0B2DF739524371ULL,
		0xD4C5765237C986A7ULL,
		0x7DED6C4A08D6A9C4ULL,
		0xA3BC7D5FF0CCB234ULL,
		0x5520527BDAE21C57ULL,
		0x00AC5BEC89076EE1ULL
	}};
	shift = 58;
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
		0x6D164CC85D530157ULL,
		0xCDFB1C2B06FB3968ULL,
		0xE68DECC459E3B760ULL,
		0xDA1427057F94948AULL,
		0xAF866D03921E4F34ULL,
		0x46DF16F4044BEB3AULL,
		0x8C73F3E76FF0E4B1ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4C055C0000000000ULL,
		0xECE5A1B459332175ULL,
		0x8EDD8337EC70AC1BULL,
		0x52522B9A37B31167ULL,
		0x793CD368509C15FEULL,
		0x2FACEABE19B40E48ULL,
		0xC392C51B7C5BD011ULL,
		0x00000231CFCF9DBFULL
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
		0x204CF0EA2D496063ULL,
		0x8E11D0F6211FF876ULL,
		0xBF60190CF9724F66ULL,
		0x087B3C0DA6E0744EULL,
		0x3BAE8AD43578132EULL,
		0xE0E457148BDC846DULL,
		0x172500C99BE8E97DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC600000000000000ULL,
		0xEC4099E1D45A92C0ULL,
		0xCD1C23A1EC423FF0ULL,
		0x9D7EC03219F2E49EULL,
		0x5C10F6781B4DC0E8ULL,
		0xDA775D15A86AF026ULL,
		0xFBC1C8AE2917B908ULL,
		0x002E4A019337D1D2ULL
	}};
	shift = 57;
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
		0x01AAB29FC677129AULL,
		0x7497F0EAD2267295ULL,
		0x67881FA45AC8376FULL,
		0xBCCADB50122188CCULL,
		0xCA488490F7E9C67DULL,
		0x9E005E63DB40E8ADULL,
		0x57108E4CB7238B54ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7129A00000000000ULL,
		0x6729501AAB29FC67ULL,
		0x8376F7497F0EAD22ULL,
		0x188CC67881FA45ACULL,
		0x9C67DBCCADB50122ULL,
		0x0E8ADCA488490F7EULL,
		0x38B549E005E63DB4ULL,
		0x0000057108E4CB72ULL
	}};
	shift = 44;
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
		0x255B89FCFE5A3F09ULL,
		0x08F694681AE77317ULL,
		0x7450F64E796877C1ULL,
		0x999195D7DB15677CULL,
		0x6E0E5926D6D32039ULL,
		0x7EDD430471E96046ULL,
		0x810600C2F7B345EBULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5B89FCFE5A3F0900ULL,
		0xF694681AE7731725ULL,
		0x50F64E796877C108ULL,
		0x9195D7DB15677C74ULL,
		0x0E5926D6D3203999ULL,
		0xDD430471E960466EULL,
		0x0600C2F7B345EB7EULL,
		0x0000000000000081ULL
	}};
	shift = 8;
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
		0xFCA6CF3EB371CB08ULL,
		0x462FC691C62325E7ULL,
		0x1B5EF028F4C0CB8EULL,
		0xAC9F488F3E5EE9EFULL,
		0x250919FB5B1511F7ULL,
		0x468E4B380038D048ULL,
		0x43962A082E840B51ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1000000000000000ULL,
		0xCFF94D9E7D66E396ULL,
		0x1C8C5F8D238C464BULL,
		0xDE36BDE051E98197ULL,
		0xEF593E911E7CBDD3ULL,
		0x904A1233F6B62A23ULL,
		0xA28D1C96700071A0ULL,
		0x00872C54105D0816ULL
	}};
	shift = 57;
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
		0x483371CFF2BDC357ULL,
		0xC47720C9F06C72B4ULL,
		0xCAA2A5CD85129FFBULL,
		0x94FC71CA1368DB82ULL,
		0xDCD347D26F4BCDE4ULL,
		0x4271A76780CCD249ULL,
		0xCEBBA2AFE7D03324ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCDC73FCAF70D5C00ULL,
		0xDC8327C1B1CAD120ULL,
		0x8A9736144A7FEF11ULL,
		0xF1C7284DA36E0B2AULL,
		0x4D1F49BD2F379253ULL,
		0xC69D9E0333492773ULL,
		0xEE8ABF9F40CC9109ULL,
		0x000000000000033AULL
	}};
	shift = 10;
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
		0xA1935066AB631C93ULL,
		0x4FD940B406EBF187ULL,
		0x77C592E182ADBBF6ULL,
		0x9F2CA0D3E7E25537ULL,
		0xF592AEB1D8E29709ULL,
		0x9F5092A387A6FAE5ULL,
		0x6DC46BAF19DFB0FDULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD419AAD8C724C000ULL,
		0x502D01BAFC61E864ULL,
		0x64B860AB6EFD93F6ULL,
		0x2834F9F8954DDDF1ULL,
		0xABAC7638A5C267CBULL,
		0x24A8E1E9BEB97D64ULL,
		0x1AEBC677EC3F67D4ULL,
		0x0000000000001B71ULL
	}};
	shift = 14;
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
		0x207B8E53FEFBEE36ULL,
		0x6052D6BBCBDDA24BULL,
		0x9D4980569E6A04AEULL,
		0x615FE65D6B483597ULL,
		0x102BCF4A5EBC2593ULL,
		0xA5C212C3DBEC7C76ULL,
		0x46602A06EF925FC0ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1CA7FDF7DC6C0000ULL,
		0xAD7797BB449640F7ULL,
		0x00AD3CD4095CC0A5ULL,
		0xCCBAD6906B2F3A93ULL,
		0x9E94BD784B26C2BFULL,
		0x2587B7D8F8EC2057ULL,
		0x540DDF24BF814B84ULL,
		0x0000000000008CC0ULL
	}};
	shift = 17;
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
		0xF5E64DBFEE8C2E0DULL,
		0xE9829C4DA7A7591DULL,
		0x7AB0BB497ED4885CULL,
		0x74C128A352E04232ULL,
		0x155580F01A2716BFULL,
		0x3B9DBDF650DB4ED9ULL,
		0x7358D4A8423B8868ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFFBA30B834000000ULL,
		0x369E9D6477D79936ULL,
		0x25FB522173A60A71ULL,
		0x8D4B8108C9EAC2EDULL,
		0xC0689C5AFDD304A2ULL,
		0xD9436D3B64555603ULL,
		0xA108EE21A0EE76F7ULL,
		0x0000000001CD6352ULL
	}};
	shift = 26;
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
		0x53DDAE6030FB0208ULL,
		0xECEC2BBDB373A216ULL,
		0x70B03EBD28C5EFA4ULL,
		0x1B695F2B6B9B20D7ULL,
		0xF7EC6764C9D91DEBULL,
		0x0417799053841804ULL,
		0x9458B2FA5D331E01ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x061F604100000000ULL,
		0xB66E7442CA7BB5CCULL,
		0xA518BDF49D9D8577ULL,
		0x6D73641AEE1607D7ULL,
		0x993B23BD636D2BE5ULL,
		0x0A7083009EFD8CECULL,
		0x4BA663C02082EF32ULL,
		0x00000000128B165FULL
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
		0x22DE635B53405533ULL,
		0x0294872EDBF7B3B3ULL,
		0xF411A51B71BFC52BULL,
		0x0B07B69754B2134CULL,
		0x924064ED519E7B1BULL,
		0x71850134A6484C36ULL,
		0x43E0FB3353020494ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3000000000000000ULL,
		0x322DE635B5340553ULL,
		0xB0294872EDBF7B3BULL,
		0xCF411A51B71BFC52ULL,
		0xB0B07B69754B2134ULL,
		0x6924064ED519E7B1ULL,
		0x471850134A6484C3ULL,
		0x043E0FB335302049ULL
	}};
	shift = 60;
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
		0xE319FD88144BDEB3ULL,
		0xD499DE9BE540F18DULL,
		0x4DC76A0A55A51F78ULL,
		0xE997795873CC4375ULL,
		0x641A01596249F82AULL,
		0x42C5D446D226E566ULL,
		0x544E3A7EF81384EDULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x319FD88144BDEB30ULL,
		0x499DE9BE540F18DEULL,
		0xDC76A0A55A51F78DULL,
		0x997795873CC43754ULL,
		0x41A01596249F82AEULL,
		0x2C5D446D226E5666ULL,
		0x44E3A7EF81384ED4ULL,
		0x0000000000000005ULL
	}};
	shift = 4;
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
		0x5D1437A2A11B476FULL,
		0x0FE96CF535688E66ULL,
		0x647B665B085D19F3ULL,
		0x3DDEBF9821466772ULL,
		0x43D273D8E4EA90F4ULL,
		0xE94CAF31D4A506DEULL,
		0xF1C8242A172EFF2EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBD1508DA3B780000ULL,
		0x67A9AB447332E8A1ULL,
		0x32D842E8CF987F4BULL,
		0xFCC10A333B9323DBULL,
		0x9EC7275487A1EEF5ULL,
		0x798EA52836F21E93ULL,
		0x2150B977F9774A65ULL,
		0x0000000000078E41ULL
	}};
	shift = 19;
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
		0xB4D6AF48EFF6719BULL,
		0xED98BEBCE456FD28ULL,
		0x7EA0BA6B3056A6F7ULL,
		0x9A1FAED42DD9C62AULL,
		0x7EB27860613DA01CULL,
		0x34D4E088E2D560F7ULL,
		0xF17A66B42193935AULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF48EFF6719B0000ULL,
		0xBEBCE456FD28B4D6ULL,
		0xBA6B3056A6F7ED98ULL,
		0xAED42DD9C62A7EA0ULL,
		0x7860613DA01C9A1FULL,
		0xE088E2D560F77EB2ULL,
		0x66B42193935A34D4ULL,
		0x000000000000F17AULL
	}};
	shift = 16;
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
		0x7F34470676913030ULL,
		0x038EAFB8A17E84EBULL,
		0x2CEACFE6E291D318ULL,
		0xB868F3CE46F330B8ULL,
		0x8FBC29D10AF52A80ULL,
		0xF3424488E8AB9C61ULL,
		0xAB2C3184123FE8B4ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0C00000000000000ULL,
		0x3ADFCD11C19DA44CULL,
		0xC600E3ABEE285FA1ULL,
		0x2E0B3AB3F9B8A474ULL,
		0xA02E1A3CF391BCCCULL,
		0x1863EF0A7442BD4AULL,
		0x2D3CD091223A2AE7ULL,
		0x002ACB0C61048FFAULL
	}};
	shift = 54;
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
		0x54855B8AC66CA347ULL,
		0x0D159CB7E69F00E8ULL,
		0x4979306C796436E4ULL,
		0x7D6437591D221BDFULL,
		0x97C67CA394EEBE87ULL,
		0x5DC2401D7A7E35EBULL,
		0x2D5F2CD060694EC8ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA90AB7158CD9468EULL,
		0x1A2B396FCD3E01D0ULL,
		0x92F260D8F2C86DC8ULL,
		0xFAC86EB23A4437BEULL,
		0x2F8CF94729DD7D0EULL,
		0xBB84803AF4FC6BD7ULL,
		0x5ABE59A0C0D29D90ULL,
		0x0000000000000000ULL
	}};
	shift = 1;
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
		0x24A0A20E67BF7B18ULL,
		0xDE7C3034486709A8ULL,
		0x025936C51C6A1388ULL,
		0xB2DBED76437B38B8ULL,
		0x38A361B297E61E17ULL,
		0x15050219ED30E09CULL,
		0x04E2052DF196C70AULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x41CCF7EF63000000ULL,
		0x06890CE135049414ULL,
		0xD8A38D42711BCF86ULL,
		0xAEC86F6717004B26ULL,
		0x3652FCC3C2F65B7DULL,
		0x433DA61C1387146CULL,
		0xA5BE32D8E142A0A0ULL,
		0x0000000000009C40ULL
	}};
	shift = 21;
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
		0xD87459E303B35C2AULL,
		0x4E83CF5D649227F4ULL,
		0x86776800C304386CULL,
		0xC574DEC0F8F529B0ULL,
		0x9D7C9DFBCBF18265ULL,
		0x6CDDAF34A3E30409ULL,
		0x8B3812C01493543EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5C2A000000000000ULL,
		0x27F4D87459E303B3ULL,
		0x386C4E83CF5D6492ULL,
		0x29B086776800C304ULL,
		0x8265C574DEC0F8F5ULL,
		0x04099D7C9DFBCBF1ULL,
		0x543E6CDDAF34A3E3ULL,
		0x00008B3812C01493ULL
	}};
	shift = 48;
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
		0xD69A9020AAB4792EULL,
		0xC831DD24AEF04252ULL,
		0xC98A43986D824EB4ULL,
		0x79D6F845FB1632BEULL,
		0x3C941F600C9F71C9ULL,
		0xFD5F3E59D48DA4A5ULL,
		0xCC4C95EAB45A01E8ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x10555A3C97000000ULL,
		0x92577821296B4D48ULL,
		0xCC36C1275A6418EEULL,
		0x22FD8B195F64C521ULL,
		0xB0064FB8E4BCEB7CULL,
		0x2CEA46D2529E4A0FULL,
		0xF55A2D00F47EAF9FULL,
		0x000000000066264AULL
	}};
	shift = 23;
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
		0xCD303D1E987E8906ULL,
		0x7E2C89BE70E884A9ULL,
		0xD6BA484798802C35ULL,
		0x1DA5DE5838936387ULL,
		0xD71F8D089C3E02DDULL,
		0x0B3B7159E7B42253ULL,
		0x05A5275FA260B416ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F47A61FA2418000ULL,
		0x226F9C3A212A734CULL,
		0x9211E6200B0D5F8BULL,
		0x77960E24D8E1F5AEULL,
		0xE342270F80B74769ULL,
		0xDC5679ED0894F5C7ULL,
		0x49D7E8982D0582CEULL,
		0x0000000000000169ULL
	}};
	shift = 14;
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
		0x7E29E1584E7AF943ULL,
		0x356148AF4B3D7DFCULL,
		0x665BC64BA423D8F7ULL,
		0x6A365DD55FFC37DAULL,
		0x9DFDEA59CAF47B76ULL,
		0xB6DC0DFD93F553B3ULL,
		0xA1D5DD10EC7011BCULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBE50C00000000000ULL,
		0x5F7F1F8A7856139EULL,
		0xF63DCD58522BD2CFULL,
		0x0DF69996F192E908ULL,
		0x1EDD9A8D977557FFULL,
		0x54ECE77F7A9672BDULL,
		0x046F2DB7037F64FDULL,
		0x0000287577443B1CULL
	}};
	shift = 46;
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
		0x45CFDA7FED068227ULL,
		0xCDFEBD820C8000ECULL,
		0xD8E6EFA655B0FEB9ULL,
		0x914E715763668749ULL,
		0x90378CDDC6779657ULL,
		0xED314D62A291B8B2ULL,
		0x740DF7D6210045D2ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB41A089C00000000ULL,
		0x320003B1173F69FFULL,
		0x56C3FAE737FAF608ULL,
		0x8D9A1D27639BBE99ULL,
		0x19DE595E4539C55DULL,
		0x8A46E2CA40DE3377ULL,
		0x8401174BB4C5358AULL,
		0x00000001D037DF58ULL
	}};
	shift = 34;
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
		0x3C69A97906D529E6ULL,
		0xCAE597277405EDFCULL,
		0x3883968094AA7736ULL,
		0x21A4C3D305AB5F85ULL,
		0x20F702E9DD290D47ULL,
		0xEF9A76102888C60EULL,
		0xB323A7807A586A15ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBC836A94F3000000ULL,
		0x93BA02F6FE1E34D4ULL,
		0x404A553B9B6572CBULL,
		0xE982D5AFC29C41CBULL,
		0x74EE9486A390D261ULL,
		0x0814446307107B81ULL,
		0xC03D2C350AF7CD3BULL,
		0x00000000005991D3ULL
	}};
	shift = 23;
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
		0xDDD9FD55AC14FB9BULL,
		0x3247C725C93DAD17ULL,
		0x4EF8C44BD4D83223ULL,
		0x765AFD047CF461D8ULL,
		0xF205E7F0B61FB5FEULL,
		0x3831D13FD9018F9FULL,
		0xBF8B6E72AAF0624DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x67F556B053EE6C00ULL,
		0x1F1C9724F6B45F77ULL,
		0xE3112F5360C88CC9ULL,
		0x6BF411F3D187613BULL,
		0x179FC2D87ED7F9D9ULL,
		0xC744FF64063E7FC8ULL,
		0x2DB9CAABC18934E0ULL,
		0x00000000000002FEULL
	}};
	shift = 10;
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
		0xF57EBE58D35B6588ULL,
		0x5F0AFDAA9D5E3A45ULL,
		0x525DD709E4E9D692ULL,
		0x9B6ACE3C84CDE010ULL,
		0x5374E005FF81F8A1ULL,
		0x4A38065CC1833943ULL,
		0xF82C693B1E195359ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8000000000000000ULL,
		0x5F57EBE58D35B658ULL,
		0x25F0AFDAA9D5E3A4ULL,
		0x0525DD709E4E9D69ULL,
		0x19B6ACE3C84CDE01ULL,
		0x35374E005FF81F8AULL,
		0x94A38065CC183394ULL,
		0x0F82C693B1E19535ULL
	}};
	shift = 60;
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
		0xDDBD7AE189713080ULL,
		0x6E090057F17186B4ULL,
		0xD266121441B6A0A1ULL,
		0xFCE883C557827F23ULL,
		0x9434DCADC4C6C836ULL,
		0x2112F328EBB2F9F7ULL,
		0x345D218468DB8659ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x312E261000000000ULL,
		0xFE2E30D69BB7AF5CULL,
		0x8836D4142DC1200AULL,
		0xAAF04FE47A4CC242ULL,
		0xB898D906DF9D1078ULL,
		0x1D765F3EF2869B95ULL,
		0x8D1B70CB24225E65ULL,
		0x00000000068BA430ULL
	}};
	shift = 29;
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
		0xF7561CF8D8847366ULL,
		0x8B03BC11BAA5D14CULL,
		0x7FE6DDE6CCA1EEF9ULL,
		0x80A5A13760954A0BULL,
		0x96C01C6D48CBFBF4ULL,
		0x1E0B680DB71A3673ULL,
		0xE1F2185039FF3BB5ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD980000000000000ULL,
		0x533DD5873E36211CULL,
		0xBE62C0EF046EA974ULL,
		0x82DFF9B779B3287BULL,
		0xFD2029684DD82552ULL,
		0x9CE5B0071B5232FEULL,
		0xED4782DA036DC68DULL,
		0x00387C86140E7FCEULL
	}};
	shift = 54;
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
		0x8E0DFEC100253FB9ULL,
		0xA81775AE68D848CFULL,
		0xC6A864E89E2880EEULL,
		0x1C87EA0255E0A232ULL,
		0x762CFE98149D262FULL,
		0x9016B8B7B115D16DULL,
		0x3860918156913671ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA7F7200000000000ULL,
		0x0919F1C1BFD82004ULL,
		0x101DD502EEB5CD1BULL,
		0x144658D50C9D13C5ULL,
		0xA4C5E390FD404ABCULL,
		0xBA2DAEC59FD30293ULL,
		0x26CE3202D716F622ULL,
		0x0000070C12302AD2ULL
	}};
	shift = 45;
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
		0x99B48F2C7B6C0D5EULL,
		0x9FFA54B1577CFC70ULL,
		0x4EEBC4EE22CCE634ULL,
		0xF15EFE1F0FBE22D4ULL,
		0x898E7EDE36242D77ULL,
		0x97ACB3DF90042771ULL,
		0xAF12C90EA395130FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB606AF0000000000ULL,
		0xBE7E384CDA47963DULL,
		0x66731A4FFD2A58ABULL,
		0xDF116A2775E27711ULL,
		0x1216BBF8AF7F0F87ULL,
		0x0213B8C4C73F6F1BULL,
		0xCA8987CBD659EFC8ULL,
		0x0000005789648751ULL
	}};
	shift = 39;
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
		0x38F4333CAFF50FBCULL,
		0xEEE4DB2F67BD53B4ULL,
		0x0DF0D2C281B64137ULL,
		0x2A956397C6C27A43ULL,
		0x47EC1049572D9B19ULL,
		0x7B394894798335A3ULL,
		0x35CBAAA15A76DC8FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCF2BFD43EF000000ULL,
		0xCBD9EF54ED0E3D0CULL,
		0xB0A06D904DFBB936ULL,
		0xE5F1B09E90C37C34ULL,
		0x1255CB66C64AA558ULL,
		0x251E60CD68D1FB04ULL,
		0xA8569DB723DECE52ULL,
		0x00000000000D72EAULL
	}};
	shift = 22;
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
		0xF03ED01B11A0B7E3ULL,
		0x983718E7AC5EE295ULL,
		0xDC36973B8AAD1210ULL,
		0x67910FDD73DAC36EULL,
		0x848B2B5E3A534B34ULL,
		0xAB84244861FDFBE1ULL,
		0xFD11B1E7770CE04EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDA03623416FC6000ULL,
		0xE31CF58BDC52BE07ULL,
		0xD2E77155A2421306ULL,
		0x21FBAE7B586DDB86ULL,
		0x656BC74A69668CF2ULL,
		0x84890C3FBF7C3091ULL,
		0x363CEEE19C09D570ULL,
		0x0000000000001FA2ULL
	}};
	shift = 13;
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
		0xAFFCFD9059AC78F4ULL,
		0x8F1C8AC0D9CD0937ULL,
		0x1B16377D6640109FULL,
		0xC518BE3E1AD21DC5ULL,
		0x29C365AF60530764ULL,
		0xBEE03A78CF7E1B02ULL,
		0xAA23C547A2BE8AB3ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6B1E3D0000000000ULL,
		0x73424DEBFF3F6416ULL,
		0x900427E3C722B036ULL,
		0xB4877146C58DDF59ULL,
		0x14C1D931462F8F86ULL,
		0xDF86C08A70D96BD8ULL,
		0xAFA2ACEFB80E9E33ULL,
		0x0000002A88F151E8ULL
	}};
	shift = 38;
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
		0xD8207E2D285B902EULL,
		0x9ACDEE7F6149FB0DULL,
		0x483C01F269ED98EFULL,
		0xE88E549EE152AC54ULL,
		0xA36DFFB11222F1F2ULL,
		0x9B80CA8808092246ULL,
		0xC3556F3B9C995AB2ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x81F8B4A16E40B800ULL,
		0x37B9FD8527EC3760ULL,
		0xF007C9A7B663BE6BULL,
		0x39527B854AB15120ULL,
		0xB7FEC4488BC7CBA2ULL,
		0x032A202024891A8DULL,
		0x55BCEE72656ACA6EULL,
		0x000000000000030DULL
	}};
	shift = 10;
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
		0x29A268568782E7ABULL,
		0xEFE68CB682E12171ULL,
		0x2E571F31632B3B1DULL,
		0xF6458764EC326FDDULL,
		0x2DC8697EE25CFFCFULL,
		0x749F9333510A573CULL,
		0x5495239B88D38447ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB9EAC00000000000ULL,
		0x485C4A689A15A1E0ULL,
		0xCEC77BF9A32DA0B8ULL,
		0x9BF74B95C7CC58CAULL,
		0x3FF3FD9161D93B0CULL,
		0x95CF0B721A5FB897ULL,
		0xE111DD27E4CCD442ULL,
		0x0000152548E6E234ULL
	}};
	shift = 46;
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
		0x2133386D22A3FE48ULL,
		0xF973A205538288D4ULL,
		0x558D45172345FC12ULL,
		0xA0B6D50BD9A851D7ULL,
		0xF5F7D0DC06C01298ULL,
		0xFA4663325476D245ULL,
		0xD470E6B97784D337ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x70DA4547FC900000ULL,
		0x440AA70511A84266ULL,
		0x8A2E468BF825F2E7ULL,
		0xAA17B350A3AEAB1AULL,
		0xA1B80D802531416DULL,
		0xC664A8EDA48BEBEFULL,
		0xCD72EF09A66FF48CULL,
		0x000000000001A8E1ULL
	}};
	shift = 17;
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
		0x390E9DC1371D5087ULL,
		0x3A28EB8E86E842B9ULL,
		0x63A65A8A5B0A3EE6ULL,
		0x09E35984B65DCBBCULL,
		0xB8BBE8E92593B3D2ULL,
		0xAAE3C9DE03B81775ULL,
		0x4C9578A837D15A6BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA7704DC75421C000ULL,
		0x3AE3A1BA10AE4E43ULL,
		0x96A296C28FB98E8AULL,
		0xD6612D9772EF18E9ULL,
		0xFA3A4964ECF48278ULL,
		0xF27780EE05DD6E2EULL,
		0x5E2A0DF4569AEAB8ULL,
		0x0000000000001325ULL
	}};
	shift = 14;
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
		0x3823DF812F50E970ULL,
		0x1549812EE773D50AULL,
		0xA36AEDE2D7FF0C80ULL,
		0xEA3E7C457A54E86DULL,
		0x3E69DFE8E40DBA02ULL,
		0x37B5946B8E03B305ULL,
		0xDCBD8011E59F96EEULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8F7E04BD43A5C000ULL,
		0x2604BB9DCF5428E0ULL,
		0xABB78B5FFC320055ULL,
		0xF9F115E953A1B68DULL,
		0xA77FA39036E80BA8ULL,
		0xD651AE380ECC14F9ULL,
		0xF60047967E5BB8DEULL,
		0x0000000000000372ULL
	}};
	shift = 10;
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
		0xFF5D73B4AB945FD2ULL,
		0x2D3D3E626C2B63BDULL,
		0x0DE2803D616E5E0AULL,
		0xB3BFBD0FF436C47AULL,
		0xD2EFE1FD7077785EULL,
		0x464295A1F69826FEULL,
		0x4D9111A8FE1BE6FAULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFA40000000000000ULL,
		0x77BFEBAE7695728BULL,
		0xC145A7A7CC4D856CULL,
		0x8F41BC5007AC2DCBULL,
		0x0BD677F7A1FE86D8ULL,
		0xDFDA5DFC3FAE0EEFULL,
		0xDF48C852B43ED304ULL,
		0x0009B222351FC37CULL
	}};
	shift = 53;
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
		0x106DC9F6C00D847FULL,
		0x3FB1EFDEA73339C9ULL,
		0x2DEF67C68EF918FAULL,
		0xE18D011F3B02F6C6ULL,
		0xEA17B7C94E7F4578ULL,
		0xC6F5F1E0C3B830ABULL,
		0xB9F69618A93BE4EAULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7F00000000000000ULL,
		0xC9106DC9F6C00D84ULL,
		0xFA3FB1EFDEA73339ULL,
		0xC62DEF67C68EF918ULL,
		0x78E18D011F3B02F6ULL,
		0xABEA17B7C94E7F45ULL,
		0xEAC6F5F1E0C3B830ULL,
		0x00B9F69618A93BE4ULL
	}};
	shift = 56;
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
		0xAD3BAB8D487633FBULL,
		0x4CD7B840A3E41271ULL,
		0xF3C0A218A2AD2DE8ULL,
		0xC9B1D50B902C24D2ULL,
		0x0B9CD3A73F298E3DULL,
		0x572946F53ED6AD96ULL,
		0x653951DC31D12853ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1D8CFEC000000000ULL,
		0xF9049C6B4EEAE352ULL,
		0xAB4B7A1335EE1028ULL,
		0x0B0934BCF0288628ULL,
		0xCA638F726C7542E4ULL,
		0xB5AB6582E734E9CFULL,
		0x744A14D5CA51BD4FULL,
		0x000000194E54770CULL
	}};
	shift = 38;
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
		0xBB772FD2E59AA4E1ULL,
		0x004F9AA9FA4D1861ULL,
		0x52CE3B52E908E089ULL,
		0x0789F91E4981A65AULL,
		0x50E7393851BAB312ULL,
		0x93915D41388818E1ULL,
		0x7476D8B8BF27FAC3ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2708000000000000ULL,
		0xC30DDBB97E972CD5ULL,
		0x0448027CD54FD268ULL,
		0x32D29671DA974847ULL,
		0x98903C4FC8F24C0DULL,
		0xC70A8739C9C28DD5ULL,
		0xD61C9C8AEA09C440ULL,
		0x0003A3B6C5C5F93FULL
	}};
	shift = 51;
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
		0x308B5332F297A855ULL,
		0xCD0628C436C67E51ULL,
		0xC2F38C2206749330ULL,
		0xCE40C6CE13F60FC3ULL,
		0x2BC79BCAA8BF97D6ULL,
		0x876F547AE4E7B94CULL,
		0xC1E2B8143FA66C61ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5E52F50AA0000000ULL,
		0x86D8CFCA26116A66ULL,
		0x40CE926619A0C518ULL,
		0xC27EC1F8785E7184ULL,
		0x5517F2FAD9C818D9ULL,
		0x5C9CF7298578F379ULL,
		0x87F4CD8C30EDEA8FULL,
		0x00000000183C5702ULL
	}};
	shift = 29;
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
		0x963698B0DA465640ULL,
		0xBCDCE32E50E55805ULL,
		0x0820BF08B8525D92ULL,
		0x31C5D8C9363B67C6ULL,
		0xB15F8E6D147FF7B8ULL,
		0x8D99946168F8EC8DULL,
		0xE333D3944B401D09ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1B48CAC800000000ULL,
		0xCA1CAB00B2C6D316ULL,
		0x170A4BB2579B9C65ULL,
		0x26C76CF8C10417E1ULL,
		0xA28FFEF70638BB19ULL,
		0x2D1F1D91B62BF1CDULL,
		0x896803A131B3328CULL,
		0x000000001C667A72ULL
	}};
	shift = 29;
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
		0x74CA0160FBD80D0EULL,
		0x47071100F557B53EULL,
		0x429E5D8D0EC3F91AULL,
		0xC30DD0500F750EF3ULL,
		0x74BFB69F14C60065ULL,
		0x86B461C53CAF42EFULL,
		0xF87C6FE70E9B8ACDULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE000000000000000ULL,
		0xE74CA0160FBD80D0ULL,
		0xA47071100F557B53ULL,
		0x3429E5D8D0EC3F91ULL,
		0x5C30DD0500F750EFULL,
		0xF74BFB69F14C6006ULL,
		0xD86B461C53CAF42EULL,
		0x0F87C6FE70E9B8ACULL
	}};
	shift = 60;
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
		0x62BA96B092D66CC4ULL,
		0x9E77638A324E6E5CULL,
		0xFE0C862F8AA080B9ULL,
		0x46EAB0235BC600CDULL,
		0x6154C3A210718E4AULL,
		0xD37802930627D06CULL,
		0x7D6816D89C15234DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8800000000000000ULL,
		0xB8C5752D6125ACD9ULL,
		0x733CEEC714649CDCULL,
		0x9BFC190C5F154101ULL,
		0x948DD56046B78C01ULL,
		0xD8C2A9874420E31CULL,
		0x9BA6F005260C4FA0ULL,
		0x00FAD02DB1382A46ULL
	}};
	shift = 57;
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
		0xDF89140C7B39F479ULL,
		0x9F95099181EB70B2ULL,
		0xBC5D39891B29CCB7ULL,
		0x2AA69D1DB5BA1BB4ULL,
		0xAE85E622A647B428ULL,
		0xA99901A91C127C53ULL,
		0xFD5140542431A108ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7900000000000000ULL,
		0xB2DF89140C7B39F4ULL,
		0xB79F95099181EB70ULL,
		0xB4BC5D39891B29CCULL,
		0x282AA69D1DB5BA1BULL,
		0x53AE85E622A647B4ULL,
		0x08A99901A91C127CULL,
		0x00FD5140542431A1ULL
	}};
	shift = 56;
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
		0xD1181C8A0B088CE4ULL,
		0x27C290251B84C1B8ULL,
		0xBDE4918240BDA9A9ULL,
		0xB47F771F55E7BB28ULL,
		0x8A77FC14298A4906ULL,
		0x9E6F64EC26E879CDULL,
		0x0804565D3164B730ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7200000000000000ULL,
		0xDC688C0E45058446ULL,
		0xD493E148128DC260ULL,
		0x945EF248C1205ED4ULL,
		0x835A3FBB8FAAF3DDULL,
		0xE6C53BFE0A14C524ULL,
		0x984F37B27613743CULL,
		0x0004022B2E98B25BULL
	}};
	shift = 55;
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
		0xA374CF78EB19F7CDULL,
		0xDD7034A451DD4B65ULL,
		0x9099C5716F465087ULL,
		0x42DFECFC9FE10A96ULL,
		0xA67AC109F3AE82FFULL,
		0x5F6BBB6232AB975FULL,
		0xC57D65227BDC9147ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF7CD000000000000ULL,
		0x4B65A374CF78EB19ULL,
		0x5087DD7034A451DDULL,
		0x0A969099C5716F46ULL,
		0x82FF42DFECFC9FE1ULL,
		0x975FA67AC109F3AEULL,
		0x91475F6BBB6232ABULL,
		0x0000C57D65227BDCULL
	}};
	shift = 48;
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
		0xFD55B5C3B9009FAFULL,
		0x9288BE01143E0280ULL,
		0x72B7B26F2331CD0BULL,
		0x4E0A4A3985E6F1A0ULL,
		0x32252D5A4FDEDA3CULL,
		0xFC3344CFD1BCCA4CULL,
		0x34A7D1410B80068EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xADAE1DC804FD7800ULL,
		0x45F008A1F01407EAULL,
		0xBD9379198E685C94ULL,
		0x5251CC2F378D0395ULL,
		0x296AD27EF6D1E270ULL,
		0x9A267E8DE6526191ULL,
		0x3E8A085C003477E1ULL,
		0x00000000000001A5ULL
	}};
	shift = 11;
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
		0x016FA7B8D055FACEULL,
		0x036E1D8A9644AAB8ULL,
		0xD8448780F78F46FCULL,
		0x081DD223C0B1063EULL,
		0x25C64C829697B18FULL,
		0xC9E7C1660F6AE0F1ULL,
		0xDF4294F13EF1CF4AULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xABF59C0000000000ULL,
		0x89557002DF4F71A0ULL,
		0x1E8DF806DC3B152CULL,
		0x620C7DB0890F01EFULL,
		0x2F631E103BA44781ULL,
		0xD5C1E24B8C99052DULL,
		0xE39E9593CF82CC1EULL,
		0x000001BE8529E27DULL
	}};
	shift = 41;
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
		0x2B29D89B7F6A31AEULL,
		0x5A816D5071796133ULL,
		0xBEEA4D4479EBEFEFULL,
		0xF155F1DD63AA1DCDULL,
		0x2A143A49394E55FBULL,
		0x2D74FEABF46421F6ULL,
		0x8D24BBE3FABC59DEULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x89B7F6A31AE00000ULL,
		0xD50717961332B29DULL,
		0xD4479EBEFEF5A816ULL,
		0x1DD63AA1DCDBEEA4ULL,
		0xA49394E55FBF155FULL,
		0xEABF46421F62A143ULL,
		0xBE3FABC59DE2D74FULL,
		0x000000000008D24BULL
	}};
	shift = 20;
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
		0xD170360A998C4FCBULL,
		0xD94CE03301827365ULL,
		0x9F2512078E9BEF42ULL,
		0x16B44C291E0C0D0AULL,
		0xDEAD0042BD8B1F7FULL,
		0x0108FEAB183AD007ULL,
		0x8EE5696002FA81DAULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCC627E5800000000ULL,
		0x0C139B2E8B81B054ULL,
		0x74DF7A16CA670198ULL,
		0xF0606854F928903CULL,
		0xEC58FBF8B5A26148ULL,
		0xC1D6803EF5680215ULL,
		0x17D40ED00847F558ULL,
		0x00000004772B4B00ULL
	}};
	shift = 35;
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
		0x49A8B59336804F49ULL,
		0x36A28182653FA6E0ULL,
		0xC6E0ECB35151D624ULL,
		0x94121B234FDC3EF5ULL,
		0x1B0E48E2E944C3B8ULL,
		0x34A0F94B2AC8129BULL,
		0xC0E20D8FB4F28254ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA013D24000000000ULL,
		0x4FE9B8126A2D64CDULL,
		0x5475890DA8A06099ULL,
		0xF70FBD71B83B2CD4ULL,
		0x5130EE250486C8D3ULL,
		0xB204A6C6C39238BAULL,
		0x3CA0950D283E52CAULL,
		0x00000030388363EDULL
	}};
	shift = 38;
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
		0x4FCFE5023DB6D2FEULL,
		0x2B0F687B940CC38BULL,
		0x1CB77514A5C7D037ULL,
		0xFA94C4BA215555DDULL,
		0xB003340C7170CBB3ULL,
		0x73AFCAD357380993ULL,
		0xAF09D8A5B1CDF268ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x408F6DB4BF800000ULL,
		0x1EE50330E2D3F3F9ULL,
		0x452971F40DCAC3DAULL,
		0x2E88555577472DDDULL,
		0x031C5C32ECFEA531ULL,
		0xB4D5CE0264EC00CDULL,
		0x296C737C9A1CEBF2ULL,
		0x00000000002BC276ULL
	}};
	shift = 22;
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
		0x904125D9F566D7C0ULL,
		0x62E05760DB818D2EULL,
		0x15B03450099D32BCULL,
		0x3CD0E85EBCD3E761ULL,
		0xE1C1CC72B18E2885ULL,
		0xBDF716F445B69165ULL,
		0x4125060B606C7007ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBE00000000000000ULL,
		0x697482092ECFAB36ULL,
		0x95E31702BB06DC0CULL,
		0x3B08AD81A2804CE9ULL,
		0x4429E68742F5E69FULL,
		0x8B2F0E0E63958C71ULL,
		0x803DEFB8B7A22DB4ULL,
		0x00020928305B0363ULL
	}};
	shift = 51;
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
		0x3317A2CC671616EEULL,
		0xA09ACAC9F207EDFCULL,
		0xAB71109ED6083B2EULL,
		0xD341F4F6FCA5343AULL,
		0x5E4F2A6151394CC6ULL,
		0x7677408D8E426962ULL,
		0xD7E5F229B33A383FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x17A2CC671616EE00ULL,
		0x9ACAC9F207EDFC33ULL,
		0x71109ED6083B2EA0ULL,
		0x41F4F6FCA5343AABULL,
		0x4F2A6151394CC6D3ULL,
		0x77408D8E4269625EULL,
		0xE5F229B33A383F76ULL,
		0x00000000000000D7ULL
	}};
	shift = 8;
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
		0x6C71947C30B80663ULL,
		0xC93FA3A48033AF89ULL,
		0x136483EE6A699758ULL,
		0xE01502DE8093BC5EULL,
		0x6C6C12CB1060E586ULL,
		0xCB69E6D87D3D4478ULL,
		0x98A1DF0D9C6181DCULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE185C03318000000ULL,
		0x24019D7C4B638CA3ULL,
		0x73534CBAC649FD1DULL,
		0xF4049DE2F09B241FULL,
		0x5883072C3700A816ULL,
		0xC3E9EA23C3636096ULL,
		0x6CE30C0EE65B4F36ULL,
		0x0000000004C50EF8ULL
	}};
	shift = 27;
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
		0xBE055168C666612CULL,
		0xDE9B79B7EE469C88ULL,
		0x7F60BC910D7889E7ULL,
		0xF9864F4C6905EB2EULL,
		0x70CEC94E0957BF35ULL,
		0x8A6DE2796783C352ULL,
		0x859CFB8703B3B33EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB000000000000000ULL,
		0x22F81545A3199984ULL,
		0x9F7A6DE6DFB91A72ULL,
		0xB9FD82F24435E227ULL,
		0xD7E6193D31A417ACULL,
		0x49C33B2538255EFCULL,
		0xFA29B789E59E0F0DULL,
		0x021673EE1C0ECECCULL
	}};
	shift = 58;
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
		0xBBF94EB5825106E2ULL,
		0x7464AE47D5B28318ULL,
		0x6DDCA7147C0A3299ULL,
		0xB7E3E29B27673A3CULL,
		0x217C2000B3F213B3ULL,
		0x6D96A2F35AE8534DULL,
		0xBB6429F746257FECULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6E20000000000000ULL,
		0x318BBF94EB582510ULL,
		0x2997464AE47D5B28ULL,
		0xA3C6DDCA7147C0A3ULL,
		0x3B3B7E3E29B27673ULL,
		0x34D217C2000B3F21ULL,
		0xFEC6D96A2F35AE85ULL,
		0x000BB6429F746257ULL
	}};
	shift = 52;
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
		0x8871DC6FC965E46CULL,
		0x171BEB4D4FD16710ULL,
		0x1F88EBB3E4C9DA93ULL,
		0x07EE955108AB885AULL,
		0x9AD5A1DD97C61F3CULL,
		0x32E578F38405D466ULL,
		0xE1F907EF2C793480ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFC965E46C0000000ULL,
		0xD4FD167108871DC6ULL,
		0x3E4C9DA93171BEB4ULL,
		0x108AB885A1F88EBBULL,
		0xD97C61F3C07EE955ULL,
		0x38405D4669AD5A1DULL,
		0xF2C79348032E578FULL,
		0x000000000E1F907EULL
	}};
	shift = 28;
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
		0x700831E965A427B5ULL,
		0x8258B9CE0D3FB593ULL,
		0xB9DF6414D7D7DFB8ULL,
		0x20A3F3AE61F4022FULL,
		0xE79B1B815F5CD4EAULL,
		0x1D7592D5ECE515A3ULL,
		0x635ED578743747A6ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF6A0000000000000ULL,
		0xB26E01063D2CB484ULL,
		0xF7104B1739C1A7F6ULL,
		0x45F73BEC829AFAFBULL,
		0x9D44147E75CC3E80ULL,
		0xB47CF363702BEB9AULL,
		0xF4C3AEB25ABD9CA2ULL,
		0x000C6BDAAF0E86E8ULL
	}};
	shift = 53;
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
		0xC24D289FDC00FD28ULL,
		0x83A8345BEAA76E08ULL,
		0x78DF9F5CCE4A268BULL,
		0xC4C476BBCBAC4DC8ULL,
		0x7C7509D8EC5F760AULL,
		0xBE17E1188EE8A427ULL,
		0xD447DFCC689EC05EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFDC00FD280000000ULL,
		0xBEAA76E08C24D289ULL,
		0xCCE4A268B83A8345ULL,
		0xBCBAC4DC878DF9F5ULL,
		0x8EC5F760AC4C476BULL,
		0x88EE8A4277C7509DULL,
		0xC689EC05EBE17E11ULL,
		0x000000000D447DFCULL
	}};
	shift = 28;
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
		0x493B7E0B90A228C1ULL,
		0x3AFBB05F7B22F7ABULL,
		0xF04EADBF59F74276ULL,
		0x91969B97813CE0D0ULL,
		0x3A5A4F1EE261E8A6ULL,
		0xE30F70A051B932FDULL,
		0x72609B3FF77D22CDULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3B7E0B90A228C100ULL,
		0xFBB05F7B22F7AB49ULL,
		0x4EADBF59F742763AULL,
		0x969B97813CE0D0F0ULL,
		0x5A4F1EE261E8A691ULL,
		0x0F70A051B932FD3AULL,
		0x609B3FF77D22CDE3ULL,
		0x0000000000000072ULL
	}};
	shift = 8;
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
		0x82824356384ACA7EULL,
		0x4BE812DA1C24B25CULL,
		0xD9E03FE49BCEEBBCULL,
		0x20F88AF4835AB708ULL,
		0x6C8AA7728FBB8290ULL,
		0xBE825A0D08E04341ULL,
		0xF087BCDBFA0A26ACULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB29F800000000000ULL,
		0x2C9720A090D58E12ULL,
		0xBAEF12FA04B68709ULL,
		0xADC236780FF926F3ULL,
		0xE0A4083E22BD20D6ULL,
		0x10D05B22A9DCA3EEULL,
		0x89AB2FA096834238ULL,
		0x00003C21EF36FE82ULL
	}};
	shift = 46;
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
		0xC0BD6454FE9B6243ULL,
		0x5D5F1F5CF44B39A9ULL,
		0xCB333FD35F73E828ULL,
		0x1146694EDEBC7647ULL,
		0xC32D502D9B79F879ULL,
		0x79C17E559B237389ULL,
		0xF52B4F8525DD4D48ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2180000000000000ULL,
		0xD4E05EB22A7F4DB1ULL,
		0x142EAF8FAE7A259CULL,
		0x23E5999FE9AFB9F4ULL,
		0x3C88A334A76F5E3BULL,
		0xC4E196A816CDBCFCULL,
		0xA43CE0BF2ACD91B9ULL,
		0x007A95A7C292EEA6ULL
	}};
	shift = 55;
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
		0x65713F4B6B9BDCD7ULL,
		0x891F043576CCAFF0ULL,
		0x0F78A45263683D62ULL,
		0xD56A0D8F4CE2C683ULL,
		0xE68F739FB9816D56ULL,
		0x6893527CFDAAD6EFULL,
		0x7A1F5FE3614E373EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x27E96D737B9AE000ULL,
		0xE086AED995FE0CAEULL,
		0x148A4C6D07AC5123ULL,
		0x41B1E99C58D061EFULL,
		0xEE73F7302DAADAADULL,
		0x6A4F9FB55ADDFCD1ULL,
		0xEBFC6C29C6E7CD12ULL,
		0x0000000000000F43ULL
	}};
	shift = 13;
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
		0x0EEA8BBECAB67BC8ULL,
		0xD00E363F3C3B2569ULL,
		0x3191E5376DEF9C7CULL,
		0x721ABF6A64793470ULL,
		0x0DEB704C81ACFD62ULL,
		0xFB95BC0580F47073ULL,
		0x1776917E07A5C562ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x77545DF655B3DE40ULL,
		0x8071B1F9E1D92B48ULL,
		0x8C8F29BB6F7CE3E6ULL,
		0x90D5FB5323C9A381ULL,
		0x6F5B82640D67EB13ULL,
		0xDCADE02C07A38398ULL,
		0xBBB48BF03D2E2B17ULL,
		0x0000000000000000ULL
	}};
	shift = 3;
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
		0x1AFFA62D6AC9B1FBULL,
		0x4D117EAECFBFB422ULL,
		0xE0F523E0229B221CULL,
		0x1764D49DBEAB63CEULL,
		0x5CA95BD5159C121BULL,
		0xAD325EDE754D690BULL,
		0xC2611133419972ECULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1AFFA62D6AC9B1FBULL,
		0x4D117EAECFBFB422ULL,
		0xE0F523E0229B221CULL,
		0x1764D49DBEAB63CEULL,
		0x5CA95BD5159C121BULL,
		0xAD325EDE754D690BULL,
		0xC2611133419972ECULL,
		0x0000000000000000ULL
	}};
	shift = 0;
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
		0x8C02B59E8ADE5A47ULL,
		0xCD1F6FC55120A879ULL,
		0xDE13407C620439D5ULL,
		0x35305BCA57159326ULL,
		0x762E848627043560ULL,
		0x7E1EA693E7C8A638ULL,
		0xBF62450918C4B786ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8ADE5A4700000000ULL,
		0x5120A8798C02B59EULL,
		0x620439D5CD1F6FC5ULL,
		0x57159326DE13407CULL,
		0x2704356035305BCAULL,
		0xE7C8A638762E8486ULL,
		0x18C4B7867E1EA693ULL,
		0x00000000BF624509ULL
	}};
	shift = 32;
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
		0x384CAD7B06EB7136ULL,
		0x60555BCE0F1B2BF9ULL,
		0x04DAD07827CAA7FFULL,
		0x466453C9FB431439ULL,
		0x6473B8F59CB3A93EULL,
		0x6EAD5DADED498184ULL,
		0xD321B5378F002AB2ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC1BADC4D80000000ULL,
		0x83C6CAFE4E132B5EULL,
		0x09F2A9FFD81556F3ULL,
		0x7ED0C50E4136B41EULL,
		0x672CEA4F919914F2ULL,
		0x7B526061191CEE3DULL,
		0xE3C00AAC9BAB576BULL,
		0x0000000034C86D4DULL
	}};
	shift = 30;
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
		0xDA82D1E59F35B53DULL,
		0x4BE207E6F88D8B05ULL,
		0x49686F10637AB348ULL,
		0x778DA91C9B640AC2ULL,
		0x36D035E4263E23D8ULL,
		0xB79D8163DFFC96B9ULL,
		0xAF085B8FBA39EBBBULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB47967CD6D4F4000ULL,
		0x81F9BE2362C176A0ULL,
		0x1BC418DEACD212F8ULL,
		0x6A4726D902B0925AULL,
		0x0D79098F88F61DE3ULL,
		0x6058F7FF25AE4DB4ULL,
		0x16E3EE8E7AEEEDE7ULL,
		0x0000000000002BC2ULL
	}};
	shift = 14;
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
		0x1290D2E7683C7CA5ULL,
		0xAAD36CFAFF482952ULL,
		0x935BFBDB0ABF8DE2ULL,
		0x0329E29774E4C989ULL,
		0xAF17A399A963E941ULL,
		0x9B87E99F09497136ULL,
		0x743F52D50ABE5B83ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0D2E7683C7CA5000ULL,
		0x36CFAFF482952129ULL,
		0xBFBDB0ABF8DE2AADULL,
		0x9E29774E4C989935ULL,
		0x7A399A963E941032ULL,
		0x7E99F09497136AF1ULL,
		0xF52D50ABE5B839B8ULL,
		0x0000000000000743ULL
	}};
	shift = 12;
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
		0x6301D61E2BFCE2F9ULL,
		0xC21DD15AE7644F97ULL,
		0xEAE7A1D3E623F984ULL,
		0xC98BF3CCDF20D57FULL,
		0xEC53627F58A4CA60ULL,
		0x51D162844F4AE73CULL,
		0x9ABC1F579F3189DCULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2000000000000000ULL,
		0xEC603AC3C57F9C5FULL,
		0x9843BA2B5CEC89F2ULL,
		0xFD5CF43A7CC47F30ULL,
		0x19317E799BE41AAFULL,
		0x9D8A6C4FEB14994CULL,
		0x8A3A2C5089E95CE7ULL,
		0x135783EAF3E6313BULL
	}};
	shift = 61;
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
		0x99F44B08BB343C96ULL,
		0xB8086148C147FA1BULL,
		0x4B4510F0583B95D0ULL,
		0x9034B938CADF6988ULL,
		0x3AE3B5B4D5905034ULL,
		0x7F6DCDD21AFA7F5FULL,
		0x481A0AEEB0271B37ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x96117668792C0000ULL,
		0xC291828FF43733E8ULL,
		0x21E0B0772BA17010ULL,
		0x727195BED310968AULL,
		0x6B69AB20A0692069ULL,
		0x9BA435F4FEBE75C7ULL,
		0x15DD604E366EFEDBULL,
		0x0000000000009034ULL
	}};
	shift = 17;
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
		0x8BF945D5E1F3E63DULL,
		0x6A49AA4702871507ULL,
		0xFEE3E15595E14D63ULL,
		0x95A1B71220129E3BULL,
		0x704E5E1079C4AEF9ULL,
		0xAEFD0A9068BE04E9ULL,
		0xA08A107D704966ACULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x17F28BABC3E7CC7AULL,
		0xD493548E050E2A0FULL,
		0xFDC7C2AB2BC29AC6ULL,
		0x2B436E2440253C77ULL,
		0xE09CBC20F3895DF3ULL,
		0x5DFA1520D17C09D2ULL,
		0x411420FAE092CD59ULL,
		0x0000000000000001ULL
	}};
	shift = 1;
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
		0x1F60494711A2335DULL,
		0x9F4CBF67D396573BULL,
		0xC4C9E555D27C485DULL,
		0xFBBDF50959EFB230ULL,
		0x1923E81F43EEA71EULL,
		0xFF86E5D2B6598F4DULL,
		0x897DA49B9FE7556DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x88D119AE80000000ULL,
		0xE9CB2B9D8FB024A3ULL,
		0xE93E242ECFA65FB3ULL,
		0xACF7D9186264F2AAULL,
		0xA1F7538F7DDEFA84ULL,
		0x5B2CC7A68C91F40FULL,
		0xCFF3AAB6FFC372E9ULL,
		0x0000000044BED24DULL
	}};
	shift = 31;
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
		0xEFA8731343A9D383ULL,
		0x44E060728CD2E7B2ULL,
		0xB05084B90B45E181ULL,
		0x58691548644DE625ULL,
		0x37B3C4B2B3AFF0ABULL,
		0xEDB93A83CC44CFA8ULL,
		0xFFBF00FB10A8B6A8ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD4E9C18000000000ULL,
		0x6973D977D43989A1ULL,
		0xA2F0C0A270303946ULL,
		0x26F312D828425C85ULL,
		0xD7F855AC348AA432ULL,
		0x2267D41BD9E25959ULL,
		0x545B5476DC9D41E6ULL,
		0x0000007FDF807D88ULL
	}};
	shift = 39;
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
		0xCEB5CD1209E2C4FCULL,
		0x97DD8534D9B2933EULL,
		0x065031556F1CCDBBULL,
		0x2661494849CA781CULL,
		0x60EC9AE5DA248E5BULL,
		0xB5F05924891ACA3BULL,
		0x0FD0F5B27A0A644FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x675AE68904F1627EULL,
		0xCBEEC29A6CD9499FULL,
		0x032818AAB78E66DDULL,
		0x9330A4A424E53C0EULL,
		0xB0764D72ED12472DULL,
		0xDAF82C92448D651DULL,
		0x07E87AD93D053227ULL
	}};
	shift = 63;
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
		0x9A271EB037CD384CULL,
		0xD9C05304B1005049ULL,
		0x24734F0FF4DFDD18ULL,
		0xCCBF96570458BB79ULL,
		0x1416A7A4CF71EEEAULL,
		0xACB4428AE9DA54ABULL,
		0xCADCD5BB9D604386ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x44E3D606F9A70980ULL,
		0x380A6096200A0933ULL,
		0x8E69E1FE9BFBA31BULL,
		0x97F2CAE08B176F24ULL,
		0x82D4F499EE3DDD59ULL,
		0x9688515D3B4A9562ULL,
		0x5B9AB773AC0870D5ULL,
		0x0000000000000019ULL
	}};
	shift = 5;
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
		0x95B2918B54E2FC0BULL,
		0x53A32E5DF3078AB9ULL,
		0xAF5B54733906021DULL,
		0x022C9A90BF014734ULL,
		0x5D877082A656F4CAULL,
		0x44F1C13DB2D6ECAEULL,
		0x4EF830E44B404719ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x52316A9C5F816000ULL,
		0x65CBBE60F15732B6ULL,
		0x6A8E6720C043AA74ULL,
		0x935217E028E695EBULL,
		0xEE1054CADE994045ULL,
		0x3827B65ADD95CBB0ULL,
		0x061C896808E3289EULL,
		0x00000000000009DFULL
	}};
	shift = 13;
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
		0xBFFE089E66E1130FULL,
		0xE8CBF614FBF6BEC2ULL,
		0x6264725DED2DD8E7ULL,
		0x5FED630A1DFC6DD7ULL,
		0x99B90C5D5F53DA9CULL,
		0x0F1E3F8B2F348B17ULL,
		0x9E126B807837E6DCULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDC2261E000000000ULL,
		0x7ED7D857FFC113CCULL,
		0xA5BB1CFD197EC29FULL,
		0xBF8DBAEC4C8E4BBDULL,
		0xEA7B538BFDAC6143ULL,
		0xE69162F337218BABULL,
		0x06FCDB81E3C7F165ULL,
		0x00000013C24D700FULL
	}};
	shift = 37;
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
		0x01D373E08277642DULL,
		0x17271A9AC5BE4919ULL,
		0x313C955ACCF53380ULL,
		0xA3C213F2DD413026ULL,
		0x7EF86058C568D5A2ULL,
		0xA60804406FE26394ULL,
		0x65C5B17AE1D94B50ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x42D0000000000000ULL,
		0x91901D373E082776ULL,
		0x38017271A9AC5BE4ULL,
		0x026313C955ACCF53ULL,
		0x5A2A3C213F2DD413ULL,
		0x3947EF86058C568DULL,
		0xB50A60804406FE26ULL,
		0x00065C5B17AE1D94ULL
	}};
	shift = 52;
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
		0xE3E169F91EDAC996ULL,
		0x08B382F8E87A54ACULL,
		0x1AECD25B723CD17EULL,
		0xD3E112898564557CULL,
		0x481EC77C8A2BBDB5ULL,
		0x385198AA7710CD49ULL,
		0x9033A612CAEAC9D2ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6B26580000000000ULL,
		0xE952B38F85A7E47BULL,
		0xF345F822CE0BE3A1ULL,
		0x9155F06BB3496DC8ULL,
		0xAEF6D74F844A2615ULL,
		0x433525207B1DF228ULL,
		0xAB2748E14662A9DCULL,
		0x00000240CE984B2BULL
	}};
	shift = 42;
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
		0x5AB90A98BAC94684ULL,
		0xAE8CC13C832A302BULL,
		0x2F223F84A6F14268ULL,
		0x9D43F80D4E7C0A04ULL,
		0xFC42BA0EAEAB580CULL,
		0x1EC9B67201B0BBB8ULL,
		0x3CF3FA6D78D2F345ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1A10000000000000ULL,
		0xC0AD6AE42A62EB25ULL,
		0x09A2BA3304F20CA8ULL,
		0x2810BC88FE129BC5ULL,
		0x6032750FE03539F0ULL,
		0xEEE3F10AE83ABAADULL,
		0xCD147B26D9C806C2ULL,
		0x0000F3CFE9B5E34BULL
	}};
	shift = 50;
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
		0x0F301B09FE99AD1DULL,
		0x759293A05F80F255ULL,
		0xC4118EEB99CDA883ULL,
		0xEB80335C250A3CF3ULL,
		0xF4023371BB8A4708ULL,
		0x9FC9F3C405510D12ULL,
		0xBC395AB86C903115ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE603613FD335A3A0ULL,
		0xB252740BF01E4AA1ULL,
		0x8231DD7339B5106EULL,
		0x70066B84A1479E78ULL,
		0x80466E377148E11DULL,
		0xF93E7880AA21A25EULL,
		0x872B570D920622B3ULL,
		0x0000000000000017ULL
	}};
	shift = 5;
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
		0xAD3DEB449D3F7C16ULL,
		0x5DEB237E1E836736ULL,
		0xDA55A4E33768A496ULL,
		0x12A443C2ABDDB9CCULL,
		0x526054A5175B6D1EULL,
		0x2A7200B5C05C18B0ULL,
		0x42003EA7A828DD3FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x569EF5A24E9FBE0BULL,
		0x2EF591BF0F41B39BULL,
		0x6D2AD2719BB4524BULL,
		0x095221E155EEDCE6ULL,
		0x29302A528BADB68FULL,
		0x9539005AE02E0C58ULL,
		0x21001F53D4146E9FULL
	}};
	shift = 63;
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
		0xCEC0FC590F7FECAFULL,
		0x3AE3AD62A50E6A8FULL,
		0x17262D80C2BA607AULL,
		0xED7B539576A118FEULL,
		0xB4664057E5C0506DULL,
		0xA76508F8A13C1888ULL,
		0x103D2640F84DA86BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF1643DFFB2BC0000ULL,
		0xB58A9439AA3F3B03ULL,
		0xB6030AE981E8EB8EULL,
		0x4E55DA8463F85C98ULL,
		0x015F970141B7B5EDULL,
		0x23E284F06222D199ULL,
		0x9903E136A1AE9D94ULL,
		0x00000000000040F4ULL
	}};
	shift = 18;
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
		0x3633346BFE5D8232ULL,
		0x9ABC5FEC67E808C8ULL,
		0x0AD781C50EF3AE3CULL,
		0x7D84E5B86F854F15ULL,
		0xD1598F22ADD4716BULL,
		0x9E7209F7EAE543C0ULL,
		0x6067E232400C94A4ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC6668D7FCBB04640ULL,
		0x578BFD8CFD011906ULL,
		0x5AF038A1DE75C793ULL,
		0xB09CB70DF0A9E2A1ULL,
		0x2B31E455BA8E2D6FULL,
		0xCE413EFD5CA8781AULL,
		0x0CFC464801929493ULL,
		0x000000000000000CULL
	}};
	shift = 5;
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
		0x5F66AF2D6EB50431ULL,
		0x7085033475C167D4ULL,
		0x1D3999CB98EDD8C7ULL,
		0x07711052965F2B05ULL,
		0x1759D8D67D2C9110ULL,
		0x817D1F7B03106DCDULL,
		0x103E594E316917CDULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x35796B75A8218800ULL,
		0x2819A3AE0B3EA2FBULL,
		0xCCCE5CC76EC63B84ULL,
		0x888294B2F95828E9ULL,
		0xCEC6B3E96488803BULL,
		0xE8FBD818836E68BAULL,
		0xF2CA718B48BE6C0BULL,
		0x0000000000000081ULL
	}};
	shift = 11;
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
		0x57296EF39DC0556EULL,
		0x25556EFDF8C1CBF8ULL,
		0x5D96DDB9725AB703ULL,
		0x38C5E2A8E6F82039ULL,
		0xB83F1289F17408E4ULL,
		0x4912F70741261FECULL,
		0x7FD06E39B53400F1ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0AADC00000000000ULL,
		0x397F0AE52DDE73B8ULL,
		0x56E064AAADDFBF18ULL,
		0x04072BB2DBB72E4BULL,
		0x811C8718BC551CDFULL,
		0xC3FD9707E2513E2EULL,
		0x801E29225EE0E824ULL,
		0x00000FFA0DC736A6ULL
	}};
	shift = 45;
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
		0x28617294732B2EDEULL,
		0xDBC812C86A5B9A4AULL,
		0x7075F68E05CD5420ULL,
		0x5149E7BB360BE068ULL,
		0x60073D3BD450C5E4ULL,
		0x8030E52AD7640579ULL,
		0xCAAB4878BBA8354CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCBB7800000000000ULL,
		0xE6928A185CA51CCAULL,
		0x550836F204B21A96ULL,
		0xF81A1C1D7DA38173ULL,
		0x3179145279EECD82ULL,
		0x015E5801CF4EF514ULL,
		0x0D53200C394AB5D9ULL,
		0x000032AAD21E2EEAULL
	}};
	shift = 46;
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
		0x118554109B31B47EULL,
		0x3DDAC83BA3EC502FULL,
		0x83338393482112CDULL,
		0x3264039A40C1CA21ULL,
		0xDB81774355ED396CULL,
		0x816E2E48E2B329F6ULL,
		0x548E80952A0B0889ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x366368FC00000000ULL,
		0x47D8A05E230AA821ULL,
		0x9042259A7BB59077ULL,
		0x8183944306670726ULL,
		0xABDA72D864C80734ULL,
		0xC56653EDB702EE86ULL,
		0x5416111302DC5C91ULL,
		0x00000000A91D012AULL
	}};
	shift = 33;
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
		0x2E9772417F0256F5ULL,
		0x411E76CD8253E987ULL,
		0xA18DC79236D9C708ULL,
		0x8CFE007567E6B8A2ULL,
		0xE9DD7B622BBF46F4ULL,
		0x6831A2564AC73B12ULL,
		0x03C2B05777FDCBFDULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x12B7A80000000000ULL,
		0x9F4C3974BB920BF8ULL,
		0xCE384208F3B66C12ULL,
		0x35C5150C6E3C91B6ULL,
		0xFA37A467F003AB3FULL,
		0x39D8974EEBDB115DULL,
		0xEE5FEB418D12B256ULL,
		0x0000001E1582BBBFULL
	}};
	shift = 43;
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
		0x9F3FC8855C9FB668ULL,
		0x8026FC596DD3B2F0ULL,
		0xD159834248388A20ULL,
		0x7A155DFA610AF557ULL,
		0x3762A0F3D7BFD15FULL,
		0xC222BDE3460E006CULL,
		0x500F53EA33E7DADAULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD9A0000000000000ULL,
		0xCBC27CFF2215727EULL,
		0x2882009BF165B74EULL,
		0xD55F45660D0920E2ULL,
		0x457DE85577E9842BULL,
		0x01B0DD8A83CF5EFFULL,
		0x6B6B088AF78D1838ULL,
		0x0001403D4FA8CF9FULL
	}};
	shift = 50;
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
		0x11EAC98D4C32BC02ULL,
		0xC20F06CF925C49A7ULL,
		0xFBCC561AAC904A9AULL,
		0xB06F93095360FEB0ULL,
		0x8D444E52053FDF61ULL,
		0xF418D0D235C58F26ULL,
		0x861B284D4CDA8DADULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD4C32BC020000000ULL,
		0xF925C49A711EAC98ULL,
		0xAAC904A9AC20F06CULL,
		0x95360FEB0FBCC561ULL,
		0x2053FDF61B06F930ULL,
		0x235C58F268D444E5ULL,
		0xD4CDA8DADF418D0DULL,
		0x000000000861B284ULL
	}};
	shift = 28;
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
		0x4B364B5F01693AD2ULL,
		0x762099AA2D534039ULL,
		0x0D8B13EA45350EE8ULL,
		0x1D1E3B4ED7C5CF2AULL,
		0x672634D5F16A3B9CULL,
		0xCA2B1A5E482C5562ULL,
		0x8509C4CFBF790730ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF80B49D69000000ULL,
		0xD516A9A01CA59B25ULL,
		0xF5229A87743B104CULL,
		0xA76BE2E79506C589ULL,
		0x6AF8B51DCE0E8F1DULL,
		0x2F24162AB133931AULL,
		0x67DFBC839865158DULL,
		0x00000000004284E2ULL
	}};
	shift = 23;
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
		0xF679E0941F95D1A0ULL,
		0x38B889E7403E8520ULL,
		0xBE1AAF058F594C18ULL,
		0xC43F977BBA7FA29CULL,
		0x667C564CFD076448ULL,
		0x66A6F9BF024AD72DULL,
		0xC9545A43F7AC79AFULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0F679E0941F95D1AULL,
		0x838B889E7403E852ULL,
		0xCBE1AAF058F594C1ULL,
		0x8C43F977BBA7FA29ULL,
		0xD667C564CFD07644ULL,
		0xF66A6F9BF024AD72ULL,
		0x0C9545A43F7AC79AULL
	}};
	shift = 60;
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
		0x0E2A07652E09B215ULL,
		0xF64E210304535F4AULL,
		0x2AB16D5E6FA393A2ULL,
		0x87806E41E2FF420EULL,
		0x6C7F47BF78FEBE8EULL,
		0x90DACF0F63984670ULL,
		0x5F37D0D2219950D9ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC540ECA5C13642A0ULL,
		0xC9C420608A6BE941ULL,
		0x562DABCDF472745EULL,
		0xF00DC83C5FE841C5ULL,
		0x8FE8F7EF1FD7D1D0ULL,
		0x1B59E1EC7308CE0DULL,
		0xE6FA1A44332A1B32ULL,
		0x000000000000000BULL
	}};
	shift = 5;
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
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000800ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000800000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 24;
	printf("Test Case 201\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x0000100000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 16;
	printf("Test Case 202\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x0000000000000040ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000400ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 4;
	printf("Test Case 203\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x0020000000000000ULL,
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
		0x0000000000020000ULL,
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
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x0000000080000000ULL,
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
		0x0000000000000800ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 44;
	printf("Test Case 205\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x0000000000080000ULL,
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
		0x0000000000000080ULL,
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
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x0000000000000004ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000004000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 12;
	printf("Test Case 207\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x0000080000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 20;
	printf("Test Case 208\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000020000000000ULL,
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
		0x0000000000000002ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 24;
	printf("Test Case 209\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x0000000000080000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000080000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 24;
	printf("Test Case 210\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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