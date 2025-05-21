#include "../tests.h"

int32_t curve25519_key_x2_inplace_test(void) {
	printf("Inplace Key Doubling Test\n");
	curve25519_key_t k1 = {.key64 = {
		0x49307B92C6B983F6ULL,
		0xAAB4034F3C548272ULL,
		0x6AB83D6435E63FEAULL,
		0x5D10AE70262A3EC1ULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0x9260F7258D7307FFULL,
		0x5568069E78A904E4ULL,
		0xD5707AC86BCC7FD5ULL,
		0x3A215CE04C547D82ULL
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
		curve25519_key_printf(&k1, STR);
		return -1;
	} else {
		printf("Test Case 1 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4EBEC7B2CD8EFB78ULL,
		0x6BA55BD4B9CD7822ULL,
		0xEC558BC4042911A9ULL,
		0x3BC90516EC4E3809ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9D7D8F659B1DF6F0ULL,
		0xD74AB7A9739AF044ULL,
		0xD8AB178808522352ULL,
		0x77920A2DD89C7013ULL
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
		curve25519_key_printf(&k1, STR);
		return -2;
	} else {
		printf("Test Case 2 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x97D7FE343EAC25D8ULL,
		0x96B2A28BE7E5BC80ULL,
		0xE1BEDF31DB94BDE0ULL,
		0x4AFB24AE99201387ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2FAFFC687D584BC3ULL,
		0x2D654517CFCB7901ULL,
		0xC37DBE63B7297BC1ULL,
		0x15F6495D3240270FULL
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
		curve25519_key_printf(&k1, STR);
		return -3;
	} else {
		printf("Test Case 3 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3E80482B36568EBAULL,
		0x14C00EEB338791B1ULL,
		0x527712F372B77B84ULL,
		0x6EEDE6CC5222D3ACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7D0090566CAD1D87ULL,
		0x29801DD6670F2362ULL,
		0xA4EE25E6E56EF708ULL,
		0x5DDBCD98A445A758ULL
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
		curve25519_key_printf(&k1, STR);
		return -4;
	} else {
		printf("Test Case 4 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBCD01AFEA2664225ULL,
		0x160D8102C24EA742ULL,
		0x04685B0760C321ADULL,
		0x0CA20AF6AD5C1A9AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x79A035FD44CC844AULL,
		0x2C1B0205849D4E85ULL,
		0x08D0B60EC186435AULL,
		0x194415ED5AB83534ULL
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
		curve25519_key_printf(&k1, STR);
		return -5;
	} else {
		printf("Test Case 5 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x10EF2C0A96D99807ULL,
		0x56424B85CAC32D79ULL,
		0xA4DF33D8166B1E42ULL,
		0x420AF3B59BD871D2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x21DE58152DB33021ULL,
		0xAC84970B95865AF2ULL,
		0x49BE67B02CD63C84ULL,
		0x0415E76B37B0E3A5ULL
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
		curve25519_key_printf(&k1, STR);
		return -6;
	} else {
		printf("Test Case 6 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCAB7BA607649998EULL,
		0x460414D5BAA704FEULL,
		0x89CB6261DCD34D77ULL,
		0x5EAA6EB8AB3FDDD6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x956F74C0EC93332FULL,
		0x8C0829AB754E09FDULL,
		0x1396C4C3B9A69AEEULL,
		0x3D54DD71567FBBADULL
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
		curve25519_key_printf(&k1, STR);
		return -7;
	} else {
		printf("Test Case 7 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5EFC84DE3ADF374AULL,
		0x4893A27A2C29F599ULL,
		0xB771CC9829F3CCDAULL,
		0x73EF73B3415A048DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBDF909BC75BE6EA7ULL,
		0x912744F45853EB32ULL,
		0x6EE3993053E799B4ULL,
		0x67DEE76682B4091BULL
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
		curve25519_key_printf(&k1, STR);
		return -8;
	} else {
		printf("Test Case 8 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x10F187BFF2824053ULL,
		0xE06F29C4D004507EULL,
		0xD96842AC39E1AB12ULL,
		0x6ECC9FDF30C282E3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x21E30F7FE50480B9ULL,
		0xC0DE5389A008A0FCULL,
		0xB2D0855873C35625ULL,
		0x5D993FBE618505C7ULL
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
		curve25519_key_printf(&k1, STR);
		return -9;
	} else {
		printf("Test Case 9 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x80F296E0D0300D06ULL,
		0x5E55440EB2F30827ULL,
		0x59EEA64B010CD214ULL,
		0x53A25843CF9528D6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x01E52DC1A0601A1FULL,
		0xBCAA881D65E6104FULL,
		0xB3DD4C960219A428ULL,
		0x2744B0879F2A51ACULL
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
		curve25519_key_printf(&k1, STR);
		return -10;
	} else {
		printf("Test Case 10 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8F9C0F8655541255ULL,
		0xCE44850C083363E0ULL,
		0xBFD3EDBBD44339BFULL,
		0x6CABD844BF5770D4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1F381F0CAAA824BDULL,
		0x9C890A181066C7C1ULL,
		0x7FA7DB77A886737FULL,
		0x5957B0897EAEE1A9ULL
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
		curve25519_key_printf(&k1, STR);
		return -11;
	} else {
		printf("Test Case 11 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x73FD72965D6280EBULL,
		0xF80803C0842364FAULL,
		0xDD9A650A4BEC4625ULL,
		0x305EF980901FC040ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE7FAE52CBAC501D6ULL,
		0xF01007810846C9F4ULL,
		0xBB34CA1497D88C4BULL,
		0x60BDF301203F8081ULL
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
		curve25519_key_printf(&k1, STR);
		return -12;
	} else {
		printf("Test Case 12 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x51EF8379D4AC67C3ULL,
		0x87223CBF3976A902ULL,
		0x33539BCDC792AC10ULL,
		0x2BE73CEE819AD81BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA3DF06F3A958CF86ULL,
		0x0E44797E72ED5204ULL,
		0x66A7379B8F255821ULL,
		0x57CE79DD0335B036ULL
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
		curve25519_key_printf(&k1, STR);
		return -13;
	} else {
		printf("Test Case 13 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB7267FA91BF2C980ULL,
		0x17A8787EB3D7127AULL,
		0x2F5E8F8286507F75ULL,
		0x1BF02E8CB048B8D9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6E4CFF5237E59300ULL,
		0x2F50F0FD67AE24F5ULL,
		0x5EBD1F050CA0FEEAULL,
		0x37E05D19609171B2ULL
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
		curve25519_key_printf(&k1, STR);
		return -14;
	} else {
		printf("Test Case 14 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3188300A63A292A2ULL,
		0xAD2DA477AA183090ULL,
		0xAFFF5607F680B247ULL,
		0x0648F6515AE8CAC5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x63106014C7452544ULL,
		0x5A5B48EF54306120ULL,
		0x5FFEAC0FED01648FULL,
		0x0C91ECA2B5D1958BULL
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
		curve25519_key_printf(&k1, STR);
		return -15;
	} else {
		printf("Test Case 15 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1DD374A8713A1406ULL,
		0x5A4AE3BA22C27AB0ULL,
		0x679926A33CE4FE72ULL,
		0x6B12CFE34475CE0BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3BA6E950E274281FULL,
		0xB495C7744584F560ULL,
		0xCF324D4679C9FCE4ULL,
		0x56259FC688EB9C16ULL
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
		curve25519_key_printf(&k1, STR);
		return -16;
	} else {
		printf("Test Case 16 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEE615795C5176C90ULL,
		0x4E00ABC0B8C0FB39ULL,
		0xA76FC6E27960658DULL,
		0x1E789888371BCA63ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDCC2AF2B8A2ED920ULL,
		0x9C0157817181F673ULL,
		0x4EDF8DC4F2C0CB1AULL,
		0x3CF131106E3794C7ULL
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
		curve25519_key_printf(&k1, STR);
		return -17;
	} else {
		printf("Test Case 17 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x32F4AC54E8326FA0ULL,
		0xBAE0ED8B372CCE89ULL,
		0x88DE5E18EB5CE5EEULL,
		0x2F530CE65B21CE00ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x65E958A9D064DF40ULL,
		0x75C1DB166E599D12ULL,
		0x11BCBC31D6B9CBDDULL,
		0x5EA619CCB6439C01ULL
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
		curve25519_key_printf(&k1, STR);
		return -18;
	} else {
		printf("Test Case 18 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x605F0A248A1F47DBULL,
		0x5DBA6A41310BD3F4ULL,
		0xA74D049DE9CD392CULL,
		0x08C88DCD5D227570ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC0BE1449143E8FB6ULL,
		0xBB74D4826217A7E8ULL,
		0x4E9A093BD39A7258ULL,
		0x11911B9ABA44EAE1ULL
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
		curve25519_key_printf(&k1, STR);
		return -19;
	} else {
		printf("Test Case 19 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB20AF8529C39A715ULL,
		0xA2635E34AE9E7E72ULL,
		0x95528C72119EE7C7ULL,
		0x22EFCFF00B6A6A3DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6415F0A538734E2AULL,
		0x44C6BC695D3CFCE5ULL,
		0x2AA518E4233DCF8FULL,
		0x45DF9FE016D4D47BULL
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
		curve25519_key_printf(&k1, STR);
		return -20;
	} else {
		printf("Test Case 20 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x961B22B60D12AC7BULL,
		0x0E9E50B52E112284ULL,
		0x6658E99906301D40ULL,
		0x32E666BB9A541E4BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2C36456C1A2558F6ULL,
		0x1D3CA16A5C224509ULL,
		0xCCB1D3320C603A80ULL,
		0x65CCCD7734A83C96ULL
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
		curve25519_key_printf(&k1, STR);
		return -21;
	} else {
		printf("Test Case 21 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8E005A8AB5C3989AULL,
		0xAD138E4ED4B995B6ULL,
		0xE5DB605F5ED50A41ULL,
		0x43DCF51D28FDA24AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1C00B5156B873147ULL,
		0x5A271C9DA9732B6DULL,
		0xCBB6C0BEBDAA1483ULL,
		0x07B9EA3A51FB4495ULL
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
		curve25519_key_printf(&k1, STR);
		return -22;
	} else {
		printf("Test Case 22 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE7360383FAB717F1ULL,
		0x5B24B55E516098E6ULL,
		0xF59430C394AD8D58ULL,
		0x0B5BF32360CD6BFBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCE6C0707F56E2FE2ULL,
		0xB6496ABCA2C131CDULL,
		0xEB286187295B1AB0ULL,
		0x16B7E646C19AD7F7ULL
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
		curve25519_key_printf(&k1, STR);
		return -23;
	} else {
		printf("Test Case 23 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF1E6C5446F92F47AULL,
		0x7260325AD77865BEULL,
		0x793926DF4A046547ULL,
		0x71A4C2AC9D80CAC3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE3CD8A88DF25E907ULL,
		0xE4C064B5AEF0CB7DULL,
		0xF2724DBE9408CA8EULL,
		0x634985593B019586ULL
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
		curve25519_key_printf(&k1, STR);
		return -24;
	} else {
		printf("Test Case 24 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xED8A22BABFFAFCB3ULL,
		0x850BCB0898F8F6E6ULL,
		0xA90F072F10EFE181ULL,
		0x73860D447B3A88E4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDB1445757FF5F979ULL,
		0x0A17961131F1EDCDULL,
		0x521E0E5E21DFC303ULL,
		0x670C1A88F67511C9ULL
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
		curve25519_key_printf(&k1, STR);
		return -25;
	} else {
		printf("Test Case 25 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE7B06FEB8168E40FULL,
		0x4B55B3B20D717126ULL,
		0x7420B591319DD4B8ULL,
		0x3327837F481AFF09ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCF60DFD702D1C81EULL,
		0x96AB67641AE2E24DULL,
		0xE8416B22633BA970ULL,
		0x664F06FE9035FE12ULL
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
		curve25519_key_printf(&k1, STR);
		return -26;
	} else {
		printf("Test Case 26 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5C726C17E3A644B1ULL,
		0x6503BC7E2BD56825ULL,
		0xC9152A22F9F0923BULL,
		0x32946F131F6026CCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB8E4D82FC74C8962ULL,
		0xCA0778FC57AAD04AULL,
		0x922A5445F3E12476ULL,
		0x6528DE263EC04D99ULL
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
		curve25519_key_printf(&k1, STR);
		return -27;
	} else {
		printf("Test Case 27 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3D44BC71103B1F11ULL,
		0x4484DADEE2C52029ULL,
		0x16AC06131B6BB4F2ULL,
		0x3D25E395B4C2ACF2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7A8978E220763E22ULL,
		0x8909B5BDC58A4052ULL,
		0x2D580C2636D769E4ULL,
		0x7A4BC72B698559E4ULL
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
		curve25519_key_printf(&k1, STR);
		return -28;
	} else {
		printf("Test Case 28 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4A6C1D5F3398695FULL,
		0xD2263427050BE564ULL,
		0x0426B55A01977B2AULL,
		0x5D515AE248F42AC7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x94D83ABE6730D2D1ULL,
		0xA44C684E0A17CAC8ULL,
		0x084D6AB4032EF655ULL,
		0x3AA2B5C491E8558EULL
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
		curve25519_key_printf(&k1, STR);
		return -29;
	} else {
		printf("Test Case 29 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDF645A2C7105FE24ULL,
		0x53E9F92E11A55AE2ULL,
		0x22DF453B77D2590FULL,
		0x65A1413AF624BD44ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBEC8B458E20BFC5BULL,
		0xA7D3F25C234AB5C5ULL,
		0x45BE8A76EFA4B21EULL,
		0x4B428275EC497A88ULL
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
		curve25519_key_printf(&k1, STR);
		return -30;
	} else {
		printf("Test Case 30 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBD904FFB8C57DAB1ULL,
		0x99C8A0905E042993ULL,
		0xE876AED3F09455B6ULL,
		0x29A270FBCBFA5BC3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7B209FF718AFB562ULL,
		0x33914120BC085327ULL,
		0xD0ED5DA7E128AB6DULL,
		0x5344E1F797F4B787ULL
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
		curve25519_key_printf(&k1, STR);
		return -31;
	} else {
		printf("Test Case 31 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDA0D9E9B2257CF43ULL,
		0xC00DC8C6F72DEEA5ULL,
		0x0F3AD96ED25A414FULL,
		0x1729D0AB6EE7E078ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB41B3D3644AF9E86ULL,
		0x801B918DEE5BDD4BULL,
		0x1E75B2DDA4B4829FULL,
		0x2E53A156DDCFC0F0ULL
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
		curve25519_key_printf(&k1, STR);
		return -32;
	} else {
		printf("Test Case 32 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x406FEC9E8D6F5484ULL,
		0x7C67F8BE05BC9226ULL,
		0xF03792376701D54BULL,
		0x19E119CFC634ABE0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x80DFD93D1ADEA908ULL,
		0xF8CFF17C0B79244CULL,
		0xE06F246ECE03AA96ULL,
		0x33C2339F8C6957C1ULL
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
		curve25519_key_printf(&k1, STR);
		return -33;
	} else {
		printf("Test Case 33 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x343ADA0BB0399706ULL,
		0xE625AA0C3AC138CBULL,
		0x72D30F00D6D956D4ULL,
		0x0FDA51B6B763C0F4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6875B41760732E0CULL,
		0xCC4B541875827196ULL,
		0xE5A61E01ADB2ADA9ULL,
		0x1FB4A36D6EC781E8ULL
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
		curve25519_key_printf(&k1, STR);
		return -34;
	} else {
		printf("Test Case 34 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4E00F0FC5BF0F352ULL,
		0x2C3E9BB436D07BB8ULL,
		0x06372017B51C7DB2ULL,
		0x553DB0C96C144B86ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9C01E1F8B7E1E6B7ULL,
		0x587D37686DA0F770ULL,
		0x0C6E402F6A38FB64ULL,
		0x2A7B6192D828970CULL
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
		curve25519_key_printf(&k1, STR);
		return -35;
	} else {
		printf("Test Case 35 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEF235FC1776A20F0ULL,
		0xD6ED3179C6618BB4ULL,
		0x8DA58E8D08ACA9A8ULL,
		0x0A427648ED2D0B36ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDE46BF82EED441E0ULL,
		0xADDA62F38CC31769ULL,
		0x1B4B1D1A11595351ULL,
		0x1484EC91DA5A166DULL
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
		curve25519_key_printf(&k1, STR);
		return -36;
	} else {
		printf("Test Case 36 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7098E75119129E36ULL,
		0x677DA07D033B0B3CULL,
		0xC42E3F8FD5FDCFB2ULL,
		0x20E57A63282C05BAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE131CEA232253C6CULL,
		0xCEFB40FA06761678ULL,
		0x885C7F1FABFB9F64ULL,
		0x41CAF4C650580B75ULL
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
		curve25519_key_printf(&k1, STR);
		return -37;
	} else {
		printf("Test Case 37 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE8B7F6C5D8BB867CULL,
		0xC7EDA03532D95933ULL,
		0xB294170846AD0427ULL,
		0x77D748A3F6FC051CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD16FED8BB1770D0BULL,
		0x8FDB406A65B2B267ULL,
		0x65282E108D5A084FULL,
		0x6FAE9147EDF80A39ULL
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
		curve25519_key_printf(&k1, STR);
		return -38;
	} else {
		printf("Test Case 38 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE08AEB9A88CFFC90ULL,
		0x612192D364A6C511ULL,
		0xC7F5DFE0BCC5C779ULL,
		0x061BEEFA6AFE6104ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC115D735119FF920ULL,
		0xC24325A6C94D8A23ULL,
		0x8FEBBFC1798B8EF2ULL,
		0x0C37DDF4D5FCC209ULL
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
		curve25519_key_printf(&k1, STR);
		return -39;
	} else {
		printf("Test Case 39 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5ABAB41E155FCCD3ULL,
		0x6239D381F94B5AE9ULL,
		0x938C72FD45D91AF0ULL,
		0x5A917A03C5EF2B14ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB575683C2ABF99B9ULL,
		0xC473A703F296B5D2ULL,
		0x2718E5FA8BB235E0ULL,
		0x3522F4078BDE5629ULL
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
		curve25519_key_printf(&k1, STR);
		return -40;
	} else {
		printf("Test Case 40 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5EA62691E1FFA6E4ULL,
		0x3788CDFBC25D4AD1ULL,
		0x24022834D5B206FDULL,
		0x32B9C2F68A261A34ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBD4C4D23C3FF4DC8ULL,
		0x6F119BF784BA95A2ULL,
		0x48045069AB640DFAULL,
		0x657385ED144C3468ULL
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
		curve25519_key_printf(&k1, STR);
		return -41;
	} else {
		printf("Test Case 41 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x82296F58EC571FE5ULL,
		0xC3E121F2535E82D4ULL,
		0xFF9FA61EC7012A71ULL,
		0x17E321911A438F02ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0452DEB1D8AE3FCAULL,
		0x87C243E4A6BD05A9ULL,
		0xFF3F4C3D8E0254E3ULL,
		0x2FC6432234871E05ULL
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
		curve25519_key_printf(&k1, STR);
		return -42;
	} else {
		printf("Test Case 42 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x719D811FF1710B0BULL,
		0x3593363D57EDD7A9ULL,
		0x88D066C10CC5EF83ULL,
		0x5D6B430B7948AC76ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE33B023FE2E21629ULL,
		0x6B266C7AAFDBAF52ULL,
		0x11A0CD82198BDF06ULL,
		0x3AD68616F29158EDULL
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
		curve25519_key_printf(&k1, STR);
		return -43;
	} else {
		printf("Test Case 43 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCCF7186B1830E756ULL,
		0x3A094CF47DE23F73ULL,
		0x8421657AE8BB87A9ULL,
		0x14AAD57F5A916938ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x99EE30D63061CEACULL,
		0x741299E8FBC47EE7ULL,
		0x0842CAF5D1770F52ULL,
		0x2955AAFEB522D271ULL
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
		curve25519_key_printf(&k1, STR);
		return -44;
	} else {
		printf("Test Case 44 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA3CB1E7656EBDD56ULL,
		0xB8C89DC4624FF1A8ULL,
		0xDF7970A3311BBDBEULL,
		0x635EA88A3E612211ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x47963CECADD7BABFULL,
		0x71913B88C49FE351ULL,
		0xBEF2E14662377B7DULL,
		0x46BD51147CC24423ULL
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
		curve25519_key_printf(&k1, STR);
		return -45;
	} else {
		printf("Test Case 45 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x32A551ED25401010ULL,
		0x9B3DC5DD14DE9DA1ULL,
		0x212E599C1FB797F3ULL,
		0x3B11559E6E1DD2A0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x654AA3DA4A802020ULL,
		0x367B8BBA29BD3B42ULL,
		0x425CB3383F6F2FE7ULL,
		0x7622AB3CDC3BA540ULL
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
		curve25519_key_printf(&k1, STR);
		return -46;
	} else {
		printf("Test Case 46 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x771D2D2B8F14CEF6ULL,
		0xF398CD41C0C2C189ULL,
		0xC1197222BD441A94ULL,
		0x57F7008F2C5D6E8BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEE3A5A571E299DFFULL,
		0xE7319A8381858312ULL,
		0x8232E4457A883529ULL,
		0x2FEE011E58BADD17ULL
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
		curve25519_key_printf(&k1, STR);
		return -47;
	} else {
		printf("Test Case 47 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE7B68A8779297243ULL,
		0xEDA5C9ABE62C7A26ULL,
		0xD1D9F196E9D24D32ULL,
		0x5EECA99C05600024ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCF6D150EF252E499ULL,
		0xDB4B9357CC58F44DULL,
		0xA3B3E32DD3A49A65ULL,
		0x3DD953380AC00049ULL
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
		curve25519_key_printf(&k1, STR);
		return -48;
	} else {
		printf("Test Case 48 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC7C8897EBC39E573ULL,
		0xB48E85C91E2AFB05ULL,
		0x85B99958FD00B5CCULL,
		0x5B6577E1836A5524ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8F9112FD7873CAF9ULL,
		0x691D0B923C55F60BULL,
		0x0B7332B1FA016B99ULL,
		0x36CAEFC306D4AA49ULL
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
		curve25519_key_printf(&k1, STR);
		return -49;
	} else {
		printf("Test Case 49 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x552F2D9322290E9CULL,
		0xA9443FA387AF726CULL,
		0x066F15F9E9FEC9FCULL,
		0x563C1BA636F154EFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAA5E5B2644521D4BULL,
		0x52887F470F5EE4D8ULL,
		0x0CDE2BF3D3FD93F9ULL,
		0x2C78374C6DE2A9DEULL
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
		curve25519_key_printf(&k1, STR);
		return -50;
	} else {
		printf("Test Case 50 PASSED\n");
	}
	printf("---\n\n");
	return 0;
}