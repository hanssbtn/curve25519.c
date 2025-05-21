#include "../tests.h"

int32_t curve25519_key_sub_inplace_test(void) {
	printf("Inplace Key Subtraction Test\n");
	curve25519_key_t k1 = {.key64 = {
		0xDB864381A71F033AULL,
		0x8DB387C97C9C2233ULL,
		0xAA406B6CC38275CDULL,
		0x77B1BC77F16E335CULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0x05696EA7DC38AAA2ULL,
		0x7CF3D7238834D77CULL,
		0xEAA00727AABAF0F4ULL,
		0x2FC767C90611DA39ULL
	}};
	curve25519_key_t k3 = {.key64 = {
		0xD61CD4D9CAE65898ULL,
		0x10BFB0A5F4674AB7ULL,
		0xBFA0644518C784D9ULL,
		0x47EA54AEEB5C5922ULL
	}};
	printf("Test Case 1\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	int32_t res = curve25519_key_cmp(&k1, &k3);
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
		0x15EE8642D3BE9AF0ULL,
		0x4E2ED2E4146FE748ULL,
		0xB5BAB9C83D5A6565ULL,
		0x1194DFACF5C15366ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0651DAF25ACE9CFBULL,
		0x3034CD1F71D417B1ULL,
		0x437BC480870E7C19ULL,
		0x39329E008B28CC8DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0F9CAB5078EFFDE2ULL,
		0x1DFA05C4A29BCF97ULL,
		0x723EF547B64BE94CULL,
		0x586241AC6A9886D9ULL
	}};
	printf("Test Case 2\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xB7C45298B41A4C0CULL,
		0x56264844541E1DF2ULL,
		0x60821AF2D9EF6F70ULL,
		0x1D6C2AC932C72787ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC4FAD054EC2BF573ULL,
		0x977DE4C91BAE5025ULL,
		0x1B676DC817241068ULL,
		0x590682F9C47A874EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF2C98243C7EE5686ULL,
		0xBEA8637B386FCDCCULL,
		0x451AAD2AC2CB5F07ULL,
		0x4465A7CF6E4CA039ULL
	}};
	printf("Test Case 3\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x9DEF0E9FD5A8FDB3ULL,
		0x2F7F2C4AA6E962AEULL,
		0x9A0D673F207DAC1EULL,
		0x17B7EA99533125CFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB428C3F0E26C69D5ULL,
		0x8120AB238B166F53ULL,
		0xA5E04E3E97C52676ULL,
		0x0F4048841BEBFC24ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE9C64AAEF33C93DEULL,
		0xAE5E81271BD2F35AULL,
		0xF42D190088B885A7ULL,
		0x0877A215374529AAULL
	}};
	printf("Test Case 4\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xA5BAF0F1F6F28EC6ULL,
		0x8BA83C5E7DA7C5ACULL,
		0xFF5CB67668343086ULL,
		0x0057314D28DD577CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8FF77462C27D0D29ULL,
		0xE34B724BD24F2B64ULL,
		0xBC0E904B84728C43ULL,
		0x70A94BFBE24154E3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x15C37C8F3475818AULL,
		0xA85CCA12AB589A48ULL,
		0x434E262AE3C1A442ULL,
		0x0FADE551469C0299ULL
	}};
	printf("Test Case 5\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xA35DD2312804F218ULL,
		0x433133352D2018FEULL,
		0x6F9DB42D91D52F0AULL,
		0x31F309C70B7AA104ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9111607F1C792780ULL,
		0x3DF5001225A1A9C5ULL,
		0x047208D439CBFF70ULL,
		0x68AEBEAA1BDBE599ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x124C71B20B8BCA85ULL,
		0x053C3323077E6F39ULL,
		0x6B2BAB5958092F9AULL,
		0x49444B1CEF9EBB6BULL
	}};
	printf("Test Case 6\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x5BF75D595578217DULL,
		0x684600A6F93E9604ULL,
		0x5C1817B5F2487C0BULL,
		0x2ECDD4EC7596218BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x60633B99DF5AD4D3ULL,
		0xB8A8E3CAC5AE0C55ULL,
		0xAF4B33E8F314BF7AULL,
		0x4304113FE4D148B6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFB9421BF761D4C97ULL,
		0xAF9D1CDC339089AEULL,
		0xACCCE3CCFF33BC90ULL,
		0x6BC9C3AC90C4D8D4ULL
	}};
	printf("Test Case 7\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xD2BF2D40F094A162ULL,
		0xE8DAE6B3B6566099ULL,
		0x1097F1D5A2E3E1F7ULL,
		0x6DCDE6AE7C96738DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF317BCB3EC485D49ULL,
		0x68478C9CC2E41344ULL,
		0xEFD306552C21257AULL,
		0x700EA7F4EBA9684EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDFA7708D044C4406ULL,
		0x80935A16F3724D54ULL,
		0x20C4EB8076C2BC7DULL,
		0x7DBF3EB990ED0B3EULL
	}};
	printf("Test Case 8\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x209507B69B8A83EFULL,
		0xFAC9E673F1FBC958ULL,
		0x616FAF2ACAA39C32ULL,
		0x7C41339538F9E19EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2B6A359EA0B0EB24ULL,
		0x84D965D2782912BDULL,
		0xF9DBD6FDF4457309ULL,
		0x57613F664BC2C857ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF52AD217FAD998CBULL,
		0x75F080A179D2B69AULL,
		0x6793D82CD65E2929ULL,
		0x24DFF42EED371946ULL
	}};
	printf("Test Case 9\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x1A2827F6A7A0BD1FULL,
		0xEC0D785FEEB5E681ULL,
		0x7A87553AEA23310BULL,
		0x2AC6BC73DA0FF407ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3DBF81F19AEC4677ULL,
		0x0274A0C6C014D341ULL,
		0xE5F84D1230B7846DULL,
		0x56FF97B815583F80ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDC68A6050CB47695ULL,
		0xE998D7992EA1133FULL,
		0x948F0828B96BAC9EULL,
		0x53C724BBC4B7B486ULL
	}};
	printf("Test Case 10\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xF7F11F60E743DD31ULL,
		0x1514025BF9B64ECEULL,
		0xB8C14BFA9B4031EDULL,
		0x239552F6B9EB5B21ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFC8B4391E38EA8FFULL,
		0xB1BD3DE5C7AD48A5ULL,
		0xDD587DB17297A329ULL,
		0x2AEEADC05AF1C54AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFB65DBCF03B5341FULL,
		0x6356C47632090628ULL,
		0xDB68CE4928A88EC3ULL,
		0x78A6A5365EF995D6ULL
	}};
	printf("Test Case 11\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x8D4C3D7CBA93D8E6ULL,
		0xF61FD3B1ABD80B73ULL,
		0xC6713D41F837DFFCULL,
		0x14E37B67B606775FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFF08F78DD4B2B320ULL,
		0x4F41016CA50260B4ULL,
		0x331E4101EA63026AULL,
		0x7D641C649AAE1914ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8E4345EEE5E125B3ULL,
		0xA6DED24506D5AABEULL,
		0x9352FC400DD4DD92ULL,
		0x177F5F031B585E4BULL
	}};
	printf("Test Case 12\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xD5DD35B025A05ECBULL,
		0x1B31B2D8C88BCF2FULL,
		0xE6E16A61FC4F2F1BULL,
		0x15E1ACEE76993CECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD028FEF2FEAD2DEAULL,
		0x8A5AE606679FC9FCULL,
		0x7056F13C3D1F5F42ULL,
		0x1D94F7C06FD9B1CEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x05B436BD26F330CEULL,
		0x90D6CCD260EC0533ULL,
		0x768A7925BF2FCFD8ULL,
		0x784CB52E06BF8B1EULL
	}};
	printf("Test Case 13\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xF18197F86CBBB135ULL,
		0x5A3D30889FABAB3DULL,
		0xC3F26A23F8E26D98ULL,
		0x6D7B560EC6D1BD5CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEEFF0E6D88774FA5ULL,
		0xD8C1FB8260ECFFF0ULL,
		0x6992DD72695C9D04ULL,
		0x641C4C581242A37DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0282898AE4446190ULL,
		0x817B35063EBEAB4DULL,
		0x5A5F8CB18F85D093ULL,
		0x095F09B6B48F19DFULL
	}};
	printf("Test Case 14\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xA8E52AE1A5246DB2ULL,
		0x8C7FA64B5DEA8A08ULL,
		0x9E9D9FB430F06279ULL,
		0x5BE56B0B4B384C21ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD80610880BF6A85AULL,
		0x6C8F276E64D19328ULL,
		0xCC55E91E4E6E35E4ULL,
		0x7226C27A4AA93FDCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD0DF1A59992DC545ULL,
		0x1FF07EDCF918F6DFULL,
		0xD247B695E2822C95ULL,
		0x69BEA891008F0C44ULL
	}};
	printf("Test Case 15\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x16295DA071972E9BULL,
		0x24E7A0454CB6EC1AULL,
		0x0D2D1C76BE3520CDULL,
		0x33241A46E8DE1809ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5806EE9BB33C0884ULL,
		0x04B9A07CC2092436ULL,
		0x4ADA74F2632B4D70ULL,
		0x6D4B89EEEE4DFFCDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBE226F04BE5B2604ULL,
		0x202DFFC88AADC7E3ULL,
		0xC252A7845B09D35DULL,
		0x45D89057FA90183BULL
	}};
	printf("Test Case 16\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x725F9D2EFD5A75C7ULL,
		0xD83B03254A08C1C0ULL,
		0x819EC03BAB5B2495ULL,
		0x3B32896684EF93B8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0C96970D65610083ULL,
		0xB27F1F03E487B271ULL,
		0x28BC75A3244F9C7FULL,
		0x68035DB842A15267ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x65C9062197F97531ULL,
		0x25BBE42165810F4FULL,
		0x58E24A98870B8816ULL,
		0x532F2BAE424E4151ULL
	}};
	printf("Test Case 17\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x8234FC24353BDCCBULL,
		0x0F02FCA8826BC3A1ULL,
		0x812A531FDA564B65ULL,
		0x525C02E02B22AFD5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE3AE878A8ED89478ULL,
		0x18DBAB5282BF08A0ULL,
		0x49A993EFEACFE285ULL,
		0x65C3001E33472FF4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9E867499A6634840ULL,
		0xF6275155FFACBB00ULL,
		0x3780BF2FEF8668DFULL,
		0x6C9902C1F7DB7FE1ULL
	}};
	printf("Test Case 18\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xE2CF5DD9A67D17F0ULL,
		0xE0425F9B07AA30B6ULL,
		0x0640207504959D41ULL,
		0x31486610324685EEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x85DD215E489A5F53ULL,
		0x7818E9344A8784E3ULL,
		0xB3ECA243784D8F27ULL,
		0x59E60463F30A7D4AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5CF23C7B5DE2B88AULL,
		0x68297666BD22ABD3ULL,
		0x52537E318C480E1AULL,
		0x576261AC3F3C08A3ULL
	}};
	printf("Test Case 19\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x97658E0A8E086818ULL,
		0x00F22696C96C8410ULL,
		0x751C772EA2FA517FULL,
		0x487408A0BAA9067BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x25BDC976EFF75733ULL,
		0xC2857DE9282BD313ULL,
		0x5D38469C656862E2ULL,
		0x4A468771A6F31A58ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x71A7C4939E1110D2ULL,
		0x3E6CA8ADA140B0FDULL,
		0x17E430923D91EE9CULL,
		0x7E2D812F13B5EC23ULL
	}};
	printf("Test Case 20\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xD4321A432487D9C6ULL,
		0x24C324D1245BD06FULL,
		0xE827D8D3B79A9E5BULL,
		0x774C2217A7BE2F02ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC11A64A2A16AEC5DULL,
		0x7FAB277149CFBC24ULL,
		0x2AF753E41CE333CFULL,
		0x0CD5FD428B507CBBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1317B5A0831CED69ULL,
		0xA517FD5FDA8C144BULL,
		0xBD3084EF9AB76A8BULL,
		0x6A7624D51C6DB247ULL
	}};
	printf("Test Case 21\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xEB07A3B66ACCBA15ULL,
		0x4962CBF5A3220A40ULL,
		0x6E25444ADB1F2797ULL,
		0x0E4EBC328F84CB47ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEA38E2D28CD1F85DULL,
		0x4ECCB4615A4F510CULL,
		0x3A969E25B2AB7B22ULL,
		0x74C3456A5495A5CEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x00CEC0E3DDFAC1A5ULL,
		0xFA96179448D2B934ULL,
		0x338EA6252873AC74ULL,
		0x198B76C83AEF2579ULL
	}};
	printf("Test Case 22\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x041834A58ABC0281ULL,
		0x9E7AFB40E193A2ABULL,
		0x97A24CFF22FB981BULL,
		0x4836389C28FEA907ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2457A844AF4E399BULL,
		0xC053A387FED44E88ULL,
		0xD30E129BD0C5D54EULL,
		0x2F19A26238D33DD8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDFC08C60DB6DC8E6ULL,
		0xDE2757B8E2BF5422ULL,
		0xC4943A635235C2CCULL,
		0x191C9639F02B6B2EULL
	}};
	printf("Test Case 23\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xC67CB33CB152EC65ULL,
		0x281AB8E011963CF5ULL,
		0x22F2981652AA56EDULL,
		0x62B04A53B993AFCAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x56E0CDC1E5137663ULL,
		0x77CA7E6436DD4779ULL,
		0x891E06E66EB24D59ULL,
		0x0177144499DAB66AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6F9BE57ACC3F7602ULL,
		0xB0503A7BDAB8F57CULL,
		0x99D4912FE3F80993ULL,
		0x6139360F1FB8F95FULL
	}};
	printf("Test Case 24\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x38EA4C5F1732B7B0ULL,
		0xA6E76797FB2C4C0CULL,
		0x80914780954EBC5FULL,
		0x59C697B3AEBF4899ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5FC4545F38A027B8ULL,
		0xA623AD35202BEE09ULL,
		0x0C89592997E944C5ULL,
		0x527A374EEA544934ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD925F7FFDE928FF8ULL,
		0x00C3BA62DB005E02ULL,
		0x7407EE56FD65779AULL,
		0x074C6064C46AFF65ULL
	}};
	printf("Test Case 25\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x31E631930DC7D30AULL,
		0xC5B070BA2F5E829BULL,
		0x96D6864DC8903B45ULL,
		0x1B8D8EFA64544441ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD39D03CCD102FD1FULL,
		0xD2512976061FBFBAULL,
		0xEB66B2658000ED3EULL,
		0x5A1166C1BCCDF5C6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5E492DC63CC4D5D8ULL,
		0xF35F4744293EC2E0ULL,
		0xAB6FD3E8488F4E06ULL,
		0x417C2838A7864E7AULL
	}};
	printf("Test Case 26\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x28654D0C984C7148ULL,
		0x25499EABF07326F5ULL,
		0x994EBBF9E69F8348ULL,
		0x36008CD19D34DB6DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4B97157C82B2C597ULL,
		0x67C24DBD9BCF9E0EULL,
		0x4F359FBF25DF3EE0ULL,
		0x0C2CCA9BDF2EF1AAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDCCE37901599ABB1ULL,
		0xBD8750EE54A388E6ULL,
		0x4A191C3AC0C04467ULL,
		0x29D3C235BE05E9C3ULL
	}};
	printf("Test Case 27\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xD0350128D0259B79ULL,
		0x89DD6F82AE5F535DULL,
		0x4F71A3D09D855A20ULL,
		0x4B76FC0F17D93469ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2E8A1B96F5F548C2ULL,
		0x44BE97E9D7F8B8CCULL,
		0x39271B411F650484ULL,
		0x411ADDF917326261ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA1AAE591DA3052B7ULL,
		0x451ED798D6669A91ULL,
		0x164A888F7E20559CULL,
		0x0A5C1E1600A6D208ULL
	}};
	printf("Test Case 28\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x58B9BA4FF8D678E6ULL,
		0x814955D882CE89F3ULL,
		0x1E92B7B0A3BE2EA2ULL,
		0x296EE2F4336248A5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA682726451694C86ULL,
		0x01E8F8B044BECD23ULL,
		0xD7FA7B3C3AADCDD1ULL,
		0x607502786CC756DCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB23747EBA76D2C4DULL,
		0x7F605D283E0FBCCFULL,
		0x46983C74691060D1ULL,
		0x48F9E07BC69AF1C8ULL
	}};
	printf("Test Case 29\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x1DBB0492D4059109ULL,
		0x92B50814938D8D62ULL,
		0x19FA11C6097BE58EULL,
		0x7B56B5AAF6984254ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEBE3E2AEAFB94640ULL,
		0x147F67E5BDE94886ULL,
		0xF4F0AF4C9CC5860BULL,
		0x663746EA7E6530AEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x31D721E4244C4AC9ULL,
		0x7E35A02ED5A444DBULL,
		0x250962796CB65F83ULL,
		0x151F6EC0783311A5ULL
	}};
	printf("Test Case 30\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x2C678BC6108704F9ULL,
		0xF699E6612AE2C534ULL,
		0x31A2495A2FC1773CULL,
		0x6625783A6038E6AEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0179596E80431316ULL,
		0x44471116AC8AE7EFULL,
		0x7F0653A4F16AAA0DULL,
		0x22AC94CB1B539BDFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2AEE32579043F1E3ULL,
		0xB252D54A7E57DD45ULL,
		0xB29BF5B53E56CD2FULL,
		0x4378E36F44E54ACEULL
	}};
	printf("Test Case 31\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x40148ABC80F2CE0EULL,
		0x117C8229B7FAD38BULL,
		0x11BCF208116CE20CULL,
		0x1CE0FD3BCB1D2548ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x975BAC65B7FD8EE2ULL,
		0xBF1E7AB8071B7319ULL,
		0x57227F04E21EC9CEULL,
		0x04DF31C09623C805ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA8B8DE56C8F53F2CULL,
		0x525E0771B0DF6071ULL,
		0xBA9A73032F4E183DULL,
		0x1801CB7B34F95D42ULL
	}};
	printf("Test Case 32\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x7987810C53A14AEDULL,
		0xB691644444FEA9C1ULL,
		0x3497463CC5F9B5BAULL,
		0x30ADF3DEE5067BDFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC0671C09D88E5F16ULL,
		0x71BD25CFC00C162FULL,
		0x134AC9150AAF3FAFULL,
		0x6D86CC894108123FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB92065027B12EBC4ULL,
		0x44D43E7484F29391ULL,
		0x214C7D27BB4A760BULL,
		0x43272755A3FE69A0ULL
	}};
	printf("Test Case 33\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x2501B5A16BA54919ULL,
		0x351F12255655914AULL,
		0xCACC43D26E79FD8EULL,
		0x7355BC4574D7083CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDE712CEBE98FD57AULL,
		0x2F4FD7472D6F5053ULL,
		0x2260791619D9E569ULL,
		0x25772B06184941E0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x469088B58215739FULL,
		0x05CF3ADE28E640F6ULL,
		0xA86BCABC54A01825ULL,
		0x4DDE913F5C8DC65CULL
	}};
	printf("Test Case 34\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xC1544C2F85A59CE4ULL,
		0xDAB75FD300FD7F64ULL,
		0x7540DFDF2CC7EA58ULL,
		0x2127AA891C51BB4AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCB3AF171036C0543ULL,
		0x5A06012C4562E90BULL,
		0x02B4C3A9F6DD6725ULL,
		0x352AEE4160D3C0F2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF6195ABE8239978EULL,
		0x80B15EA6BB9A9658ULL,
		0x728C1C3535EA8333ULL,
		0x6BFCBC47BB7DFA58ULL
	}};
	printf("Test Case 35\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x1F195D2EEE9E93F9ULL,
		0xA8705F5F535C8511ULL,
		0x670A36E3751D579DULL,
		0x3B8ECF368D71AA5CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x76754971A0C86CD7ULL,
		0xFBDFFACB1830D043ULL,
		0xF157617C379AAE05ULL,
		0x40EF490EEEE4B57FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA8A413BD4DD6270FULL,
		0xAC9064943B2BB4CDULL,
		0x75B2D5673D82A997ULL,
		0x7A9F86279E8CF4DCULL
	}};
	printf("Test Case 36\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x91E77D4EE64B2E97ULL,
		0x4F6F0BA7CD9B3A64ULL,
		0xBA0750877DD5041CULL,
		0x0CF574792581C945ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x26D37433449D129EULL,
		0x55F77AC60AA284D7ULL,
		0xA988539D42664BE9ULL,
		0x249C003878473D41ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6B14091BA1AE1BE6ULL,
		0xF97790E1C2F8B58DULL,
		0x107EFCEA3B6EB832ULL,
		0x68597440AD3A8C04ULL
	}};
	printf("Test Case 37\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x284F19B2CE9F56D4ULL,
		0x54CBE8A1A588DFA0ULL,
		0x7F5A3D80A1380731ULL,
		0x2B03779520A80DE3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0708B6A5D83EC426ULL,
		0xC22536676A705491ULL,
		0x4C06E7D2163DAD8CULL,
		0x4241D3730F46EE73ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2146630CF660929BULL,
		0x92A6B23A3B188B0FULL,
		0x335355AE8AFA59A4ULL,
		0x68C1A42211611F70ULL
	}};
	printf("Test Case 38\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xD3E8E25AE5856E27ULL,
		0x9B3B19FF10E44861ULL,
		0xEE587B4310DA3D3FULL,
		0x3A4E645D9DF82268ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7C2C19186CA3649AULL,
		0x39B8031BB95E4534ULL,
		0xEBE1FF4F8B0B280AULL,
		0x6956061DB151972CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x57BCC94278E2097AULL,
		0x618316E35786032DULL,
		0x02767BF385CF1535ULL,
		0x50F85E3FECA68B3CULL
	}};
	printf("Test Case 39\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x4082ED4290DA1CA0ULL,
		0xA11866A24A2ACA48ULL,
		0x5FA52DAF19E3666CULL,
		0x2D11F9EC412CC590ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2DFD859AA65560E6ULL,
		0x603E7DA7D984AAFEULL,
		0x999FED8DE63984EBULL,
		0x59A67587442CA6F5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x128567A7EA84BBA7ULL,
		0x40D9E8FA70A61F4AULL,
		0xC605402133A9E181ULL,
		0x536B8464FD001E9AULL
	}};
	printf("Test Case 40\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x371612D9532DB1BEULL,
		0xF3B0A75AFB78A2A5ULL,
		0x85C489131EF6F632ULL,
		0x1452CADFB00E4317ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB37A7155F31D1571ULL,
		0x2EDBB4F3D966B301ULL,
		0x0D30FD529B400BAFULL,
		0x7C27262174F21057ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x839BA18360109C3AULL,
		0xC4D4F2672211EFA3ULL,
		0x78938BC083B6EA83ULL,
		0x182BA4BE3B1C32C0ULL
	}};
	printf("Test Case 41\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x51191E548B423C32ULL,
		0xE3878E82721B5FF9ULL,
		0x4BF3B22D8417F480ULL,
		0x75369B70D98ACC97ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEC78C52F366340FBULL,
		0xCF4F04915F2AA95AULL,
		0x1DF6102EF328287FULL,
		0x433096F4C43604DEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x64A0592554DEFB37ULL,
		0x143889F112F0B69EULL,
		0x2DFDA1FE90EFCC01ULL,
		0x3206047C1554C7B9ULL
	}};
	printf("Test Case 42\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x21598F71A9F407CEULL,
		0x73D0A8674597FF19ULL,
		0xFB91BAAC8D0D97B5ULL,
		0x0046AA3204B20B55ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x140E023582C8DB6EULL,
		0x857D6C3C0384D53BULL,
		0x611BD9EC2EB4E703ULL,
		0x7E25C4B46D5F9337ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0D4B8D3C272B2C4DULL,
		0xEE533C2B421329DEULL,
		0x9A75E0C05E58B0B1ULL,
		0x0220E57D9752781EULL
	}};
	printf("Test Case 43\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xE2185C001967B4DDULL,
		0x03EA643E349E1518ULL,
		0x943E87A2C21F3FEBULL,
		0x7AADDF69D48D107FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB750801DD46B19F7ULL,
		0xA1E8B3F25A451CE2ULL,
		0x7318248A6AD9180DULL,
		0x68633369C61FACD5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2AC7DBE244FC9AE6ULL,
		0x6201B04BDA58F836ULL,
		0x21266318574627DDULL,
		0x124AAC000E6D63AAULL
	}};
	printf("Test Case 44\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x601786200D8280BDULL,
		0x5BAD3B05F283AE7BULL,
		0x4E83F94128F32D86ULL,
		0x6880F3233913DED7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEDE11CCE16F11B1AULL,
		0x8EC17DFEBD1365C9ULL,
		0x048E45991565FDC4ULL,
		0x058EA5E52B9858E1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x72366951F69165A3ULL,
		0xCCEBBD07357048B1ULL,
		0x49F5B3A8138D2FC1ULL,
		0x62F24D3E0D7B85F6ULL
	}};
	printf("Test Case 45\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xE436C0E31AC9534CULL,
		0x96753AEA506888E1ULL,
		0x1CC2DEB23C74993DULL,
		0x28AB0D3F53EADDAAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFE9AAE7F77B2EF55ULL,
		0xFE3A908CA9BECE9CULL,
		0x4F1BB958D4383C20ULL,
		0x49A1005D507EF956ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE59C1263A31663E4ULL,
		0x983AAA5DA6A9BA44ULL,
		0xCDA72559683C5D1CULL,
		0x5F0A0CE2036BE453ULL
	}};
	printf("Test Case 46\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xA893A02F3B016472ULL,
		0x10AC1A00E12167BDULL,
		0x7117BAEFE8D7F6E9ULL,
		0x72919F8DBF68DD94ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5ECECCDAC4F1A7B1ULL,
		0xF5470A947C90FF9EULL,
		0x4966616E1A24FC09ULL,
		0x164CFE18C3E2DC2AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x49C4D354760FBCC1ULL,
		0x1B650F6C6490681FULL,
		0x27B15981CEB2FADFULL,
		0x5C44A174FB86016AULL
	}};
	printf("Test Case 47\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x6D937F430FF1D87BULL,
		0x942A8537CDF818B6ULL,
		0x49B4DC2B600A031BULL,
		0x319B33E1421498E5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE1337397AAFA157DULL,
		0x50BB5826291031A6ULL,
		0x9D5D18CC7C4EF0E1ULL,
		0x288F4F07BA178F87ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8C600BAB64F7C2FEULL,
		0x436F2D11A4E7E70FULL,
		0xAC57C35EE3BB123AULL,
		0x090BE4D987FD095DULL
	}};
	printf("Test Case 48\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x64B72C0048792E41ULL,
		0x3FC1A2352F6CFD2EULL,
		0x50EC7E6B657E5161ULL,
		0x0B53335B0404139EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCD62AFA4BE400FE3ULL,
		0x2D020FB1F669FBB7ULL,
		0x72261978044034D0ULL,
		0x54B5AC58EA80DDCEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x97547C5B8A391E4BULL,
		0x12BF928339030176ULL,
		0xDEC664F3613E1C91ULL,
		0x369D8702198335CFULL
	}};
	printf("Test Case 49\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x91F0CC2B32717BD6ULL,
		0x1023CA975DE5B27DULL,
		0x2C6554B2F211A409ULL,
		0x3ABCF8FB61F4F4F7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6563A836EE2E738DULL,
		0xA610D3A729BFD6B6ULL,
		0x4F0551F5C5AA5935ULL,
		0x42A980FB105CFF56ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2C8D23F444430836ULL,
		0x6A12F6F03425DBC7ULL,
		0xDD6002BD2C674AD3ULL,
		0x781378005197F5A0ULL
	}};
	printf("Test Case 50\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x2BBE00E25A3DB84BULL,
		0x7FCCA45D9B885005ULL,
		0x1B77173038F8C427ULL,
		0x12257DE677464A0BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5EAF8E749BE80D1BULL,
		0xCCCD452FEC60C802ULL,
		0x8085210855BF3F8BULL,
		0x420DC152DB5835B3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCD0E726DBE55AB1DULL,
		0xB2FF5F2DAF278802ULL,
		0x9AF1F627E339849BULL,
		0x5017BC939BEE1457ULL
	}};
	printf("Test Case 51\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xA4A995BCB69010C4ULL,
		0x9EAF1F956521EF5DULL,
		0x3D8C39845C9C2C63ULL,
		0x2DE1682E07F3886DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB1C328A1D407C8DULL,
		0x69A7B44BFAA205B5ULL,
		0xC3B2A7FDEA16467FULL,
		0x6C9662EB05FE7683ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE98D6332994F9424ULL,
		0x35076B496A7FE9A7ULL,
		0x79D991867285E5E4ULL,
		0x414B054301F511E9ULL
	}};
	printf("Test Case 52\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xA3CBC3B24AD057BEULL,
		0x2D541DC31A91A2CDULL,
		0xC70156A52AE6E4B6ULL,
		0x57D8036AC018FD9FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA141DB2A7ADBB00AULL,
		0xE179709859F723A3ULL,
		0x6D69AFC6FA101E9CULL,
		0x51E5200C8F64A48AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0289E887CFF4A7B4ULL,
		0x4BDAAD2AC09A7F2AULL,
		0x5997A6DE30D6C619ULL,
		0x05F2E35E30B45915ULL
	}};
	printf("Test Case 53\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xA24281D1B5A75CC5ULL,
		0x773EF65FE85B44BDULL,
		0x1B5A3DEA85B224C7ULL,
		0x6B59F656401B49D2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE1632D8D2B0E2381ULL,
		0xD7BF52561ACD7B7DULL,
		0xA100AAADF622ABE1ULL,
		0x3698C175256CDA03ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC0DF54448A993944ULL,
		0x9F7FA409CD8DC93FULL,
		0x7A59933C8F8F78E5ULL,
		0x34C134E11AAE6FCEULL
	}};
	printf("Test Case 54\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x9C988283FA4E84A5ULL,
		0x9AA28121FE7AF5CEULL,
		0x2F4D5E7E109FF9E5ULL,
		0x278212F97C4B8E23ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFBA823ED6009E8ADULL,
		0x99FB1CF3B662467AULL,
		0x98A281962A19A066ULL,
		0x345B016111EB4F61ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA0F05E969A449BE5ULL,
		0x00A7642E4818AF53ULL,
		0x96AADCE7E686597FULL,
		0x732711986A603EC1ULL
	}};
	printf("Test Case 55\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xED8E0F29AC0C8CDBULL,
		0xFBAA428D01753E69ULL,
		0x47335E7B05636E64ULL,
		0x06AD30BAB35164ABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBBF090E84D10F181ULL,
		0x6472129302BC5A5CULL,
		0x330302F7950585B6ULL,
		0x7BE74A7E2C7D36C8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x319D7E415EFB9B47ULL,
		0x97382FF9FEB8E40DULL,
		0x14305B83705DE8AEULL,
		0x0AC5E63C86D42DE3ULL
	}};
	printf("Test Case 56\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xEEE79337E3619CD6ULL,
		0x88EE98398A947660ULL,
		0xC52C3DB0E9DE24F3ULL,
		0x6B38845F8FA3B180ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCE368C3328F4A985ULL,
		0x375017A6FD881AF3ULL,
		0xA5BE0467C6D3B700ULL,
		0x14469A018F57BB81ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x20B10704BA6CF351ULL,
		0x519E80928D0C5B6DULL,
		0x1F6E3949230A6DF3ULL,
		0x56F1EA5E004BF5FFULL
	}};
	printf("Test Case 57\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x8D07E68F4E3BED58ULL,
		0xED918B9B496B4F2BULL,
		0x2AD5FEBC3D8EF71EULL,
		0x59D542E318144760ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7A2EE076C6C83B5EULL,
		0xA7F755D0BADDD86CULL,
		0xFEF7A043532F0717ULL,
		0x09B3619AA3486B9EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x12D906188773B1FAULL,
		0x459A35CA8E8D76BFULL,
		0x2BDE5E78EA5FF007ULL,
		0x5021E14874CBDBC1ULL
	}};
	printf("Test Case 58\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x76D9EB019AE49FEFULL,
		0x2D45E43BA3EA1A5EULL,
		0xC06EF7A14F9380B5ULL,
		0x347C580BF8B013DCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDFA06FB7B6E6D65DULL,
		0xE6FCA38C4E47F97FULL,
		0x0AD3A8CB1386AA77ULL,
		0x7C7DFE0246727D22ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x97397B49E3FDC97FULL,
		0x464940AF55A220DEULL,
		0xB59B4ED63C0CD63DULL,
		0x37FE5A09B23D96BAULL
	}};
	printf("Test Case 59\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x2B841D538E4C0161ULL,
		0xB8816F4070457627ULL,
		0x5B1E900AA876C357ULL,
		0x2E20FE6BBF7F9B03ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5D6DE9A94C790CBAULL,
		0x01B9A032F3077610ULL,
		0xDEC210FD38F89242ULL,
		0x2C075BFC44A0A998ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCE1633AA41D2F4A7ULL,
		0xB6C7CF0D7D3E0016ULL,
		0x7C5C7F0D6F7E3115ULL,
		0x0219A26F7ADEF16AULL
	}};
	printf("Test Case 60\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xE2C831F6D46F2EFEULL,
		0x3902B85ADD8B20C1ULL,
		0xECA0390E0B64A2BAULL,
		0x78029261FD0936F9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1C2DC603E4A333E5ULL,
		0x869BA98970A3B868ULL,
		0x429230ABAA8A4CC2ULL,
		0x1333E7DB43F89F96ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC69A6BF2EFCBFB19ULL,
		0xB2670ED16CE76859ULL,
		0xAA0E086260DA55F7ULL,
		0x64CEAA86B9109763ULL
	}};
	printf("Test Case 61\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x577FF0E3F5021C79ULL,
		0x669AD67A79294B67ULL,
		0x99BCC5729985130DULL,
		0x11BAF31AD408517EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5373C962A82340B9ULL,
		0x62FDAA030FE1643FULL,
		0x50C0CF240C304FFBULL,
		0x5E896C9A3E24FE53ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x040C27814CDEDBADULL,
		0x039D2C776947E728ULL,
		0x48FBF64E8D54C312ULL,
		0x3331868095E3532BULL
	}};
	printf("Test Case 62\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x2A6293D2C5B49241ULL,
		0x457AE8C4D0C4C4AFULL,
		0xFAE3B453301E59FFULL,
		0x643CBF6249E49B03ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBE967C940B2DEDC1ULL,
		0x83A436934C5356D0ULL,
		0x53BE4A859445A3FDULL,
		0x4C7C42E17925B4F4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6BCC173EBA86A480ULL,
		0xC1D6B23184716DDEULL,
		0xA72569CD9BD8B601ULL,
		0x17C07C80D0BEE60FULL
	}};
	printf("Test Case 63\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x9267EB5466DA0448ULL,
		0x4D7D6993841D16E5ULL,
		0xB16F75440106E78DULL,
		0x2CF5337FD118CAB8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x959ECF6575E60A85ULL,
		0x8A97B70B38203742ULL,
		0x5F3A6FCE33653072ULL,
		0x4DADAFC9A391A72FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFCC91BEEF0F3F9B0ULL,
		0xC2E5B2884BFCDFA2ULL,
		0x52350575CDA1B71AULL,
		0x5F4783B62D872389ULL
	}};
	printf("Test Case 64\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xB858C0F1C893C33FULL,
		0x1167D61EF4830D53ULL,
		0xC1B53D20444936E3ULL,
		0x565D1F61F734662FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x39F6ABF9A2761F7FULL,
		0x5108C1F528E8706DULL,
		0x2E1108A4101C21CFULL,
		0x405FADA9415B2A61ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7E6214F8261DA3C0ULL,
		0xC05F1429CB9A9CE6ULL,
		0x93A4347C342D1513ULL,
		0x15FD71B8B5D93BCEULL
	}};
	printf("Test Case 65\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x6BCB8CA3B7B2EA22ULL,
		0xEC8317CB473282E8ULL,
		0x4D1E460B314B43D8ULL,
		0x2675284DDD0CFEDCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCB937A4BEAE3CBE6ULL,
		0x5AD566DDD5816D50ULL,
		0xB60298A46A7F0922ULL,
		0x6177EAD043B7AE07ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA0381257CCCF1E29ULL,
		0x91ADB0ED71B11597ULL,
		0x971BAD66C6CC3AB6ULL,
		0x44FD3D7D995550D4ULL
	}};
	printf("Test Case 66\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xFDAC113B7C2EAE94ULL,
		0xB210A77BD24796E5ULL,
		0xC4879D0E61CDFF7CULL,
		0x6578193828B69A1BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDC82F0A010C9664DULL,
		0x4B74488F94C9B404ULL,
		0x39DF413FDB5A0F28ULL,
		0x2710CB3C91BC82FFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2129209B6B654847ULL,
		0x669C5EEC3D7DE2E1ULL,
		0x8AA85BCE8673F054ULL,
		0x3E674DFB96FA171CULL
	}};
	printf("Test Case 67\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xF8A1BDDBC40F6BEFULL,
		0x107E92EBAC21C538ULL,
		0xF8675FCC61AEEC20ULL,
		0x519B40D03E529993ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0D60E0C3A3B84F30ULL,
		0x8C24B77601785572ULL,
		0xD715B7BDAFEBFC87ULL,
		0x1408416F890134C2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEB40DD1820571CBFULL,
		0x8459DB75AAA96FC6ULL,
		0x2151A80EB1C2EF98ULL,
		0x3D92FF60B55164D1ULL
	}};
	printf("Test Case 68\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x6837889C2AF7A1FAULL,
		0x8E7F1E41D873B59AULL,
		0xA450A03DB1D9EE0FULL,
		0x6B28185FEC6161A7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x55924AABD74399D6ULL,
		0xA89893DDBB51B830ULL,
		0x8F9067142163952EULL,
		0x0679CA5B922BC874ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x12A53DF053B40824ULL,
		0xE5E68A641D21FD6AULL,
		0x14C03929907658E0ULL,
		0x64AE4E045A359933ULL
	}};
	printf("Test Case 69\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x8A8EBA373ECBA8FDULL,
		0x9358D932DCDB522BULL,
		0xBA6B47FE85837B33ULL,
		0x411C523165C4990FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD518DF566691B69EULL,
		0xAF50B7FAB55F9D85ULL,
		0x43703123DAF097DAULL,
		0x1C8AFC4CC199B890ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB575DAE0D839F25FULL,
		0xE4082138277BB4A5ULL,
		0x76FB16DAAA92E358ULL,
		0x249155E4A42AE07FULL
	}};
	printf("Test Case 70\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x8CB889CABA98B4D7ULL,
		0xAABAC84BD2ABEBDFULL,
		0x1F7B991C4FC72CC5ULL,
		0x4A1D98CD33633E52ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4BDB2C31ED4FBFB1ULL,
		0xD7C44BE4F2ED201CULL,
		0x60955F7B650CA29BULL,
		0x780816F48A4D6813ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x40DD5D98CD48F513ULL,
		0xD2F67C66DFBECBC3ULL,
		0xBEE639A0EABA8A29ULL,
		0x521581D8A915D63EULL
	}};
	printf("Test Case 71\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x1268287870C687CFULL,
		0x26D60401E02C7BEBULL,
		0xC79ABD1160C21C32ULL,
		0x6F46BA762F4FCCDFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x741B46751068621BULL,
		0x518B14505B39B688ULL,
		0xABDB351A0858CBC8ULL,
		0x374E1EBE0323BA58ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9E4CE203605E25B4ULL,
		0xD54AEFB184F2C562ULL,
		0x1BBF87F758695069ULL,
		0x37F89BB82C2C1287ULL
	}};
	printf("Test Case 72\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xBCB06E8683E2AC7FULL,
		0x1B739DF803694154ULL,
		0xAF19F3A6F0BF8A68ULL,
		0x7F78EF44DFF32CDEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F95C3916E96F940ULL,
		0x53677B720FCB68E5ULL,
		0xF80F0B94F1F13D64ULL,
		0x50C0D0692A9B2578ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAD1AAAF5154BB33FULL,
		0xC80C2285F39DD86FULL,
		0xB70AE811FECE4D03ULL,
		0x2EB81EDBB5580765ULL
	}};
	printf("Test Case 73\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x5BD5646FAD27A39EULL,
		0x7E87B5885A6ECBF0ULL,
		0x6A0ABB1B7AEABCC6ULL,
		0x0DFCACF9871D548EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA6BF00D399568C87ULL,
		0x1BE645C0B38ABB97ULL,
		0x62325AF7290ED433ULL,
		0x4905EA5D1E5363C4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB516639C13D11704ULL,
		0x62A16FC7A6E41058ULL,
		0x07D8602451DBE893ULL,
		0x44F6C29C68C9F0CAULL
	}};
	printf("Test Case 74\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x005781C61B64B4F3ULL,
		0xE787B3E91E7F3D03ULL,
		0xEA11A9A73CD779A1ULL,
		0x79A67071C150A3E4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x14E7832C0BBB93BEULL,
		0x8BA62115F9C78847ULL,
		0x351D0AADFB9BEC73ULL,
		0x55FD685D7CFC8383ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEB6FFE9A0FA92135ULL,
		0x5BE192D324B7B4BBULL,
		0xB4F49EF9413B8D2EULL,
		0x23A9081444542061ULL
	}};
	printf("Test Case 75\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x3C68913A923110A4ULL,
		0x4C651282E9034869ULL,
		0x035F49E1AE30A57AULL,
		0x356525AAB16ECC6CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x623BD744B12E3055ULL,
		0xA78632F782B70CC4ULL,
		0x7ED9689019576F9DULL,
		0x262C5E4C9DE4E48AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDA2CB9F5E102E04FULL,
		0xA4DEDF8B664C3BA4ULL,
		0x8485E15194D935DCULL,
		0x0F38C75E1389E7E1ULL
	}};
	printf("Test Case 76\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x123F6BFD1DD0C8B9ULL,
		0xF377F5E1CB3AD3FFULL,
		0x7BB0BCD67B95564DULL,
		0x7836CFE821743A2DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x46404BE5E18945C6ULL,
		0xCE412834E5C8D0A1ULL,
		0x4FA59D35D9490BCAULL,
		0x59DE4AB8A2435292ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCBFF20173C4782F3ULL,
		0x2536CDACE572035DULL,
		0x2C0B1FA0A24C4A83ULL,
		0x1E58852F7F30E79BULL
	}};
	printf("Test Case 77\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xBE49B7032C4A1628ULL,
		0x68BAAE202877883BULL,
		0x403BB5AE07E12E56ULL,
		0x6133DCDE7D26B42BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD3E2523EF4B296C6ULL,
		0x2ED9A92E9F3E4477ULL,
		0x56A6AD5FEEA4ABF9ULL,
		0x73EE10CDA9BEB1E5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEA6764C437977F4FULL,
		0x39E104F1893943C3ULL,
		0xE995084E193C825DULL,
		0x6D45CC10D3680245ULL
	}};
	printf("Test Case 78\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xCF46E0FBB01EA77FULL,
		0x70688D51140AA7D2ULL,
		0x7A4910CC2B56BDD8ULL,
		0x3B38DC1CF870F846ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x302EC92FDF40E4AFULL,
		0x36519D97747DB874ULL,
		0x843CA86E98FB1ECFULL,
		0x18AAA952A9A572E0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9F1817CBD0DDC2D0ULL,
		0x3A16EFB99F8CEF5EULL,
		0xF60C685D925B9F09ULL,
		0x228E32CA4ECB8565ULL
	}};
	printf("Test Case 79\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x9E06BA02EA8AA645ULL,
		0xFC87148CCED08E51ULL,
		0x193D32A87F43C530ULL,
		0x4F7C5990D2783F50ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x758C1719A451125DULL,
		0xA983653D7A3C64F4ULL,
		0x6FBDE8E36BE3FD91ULL,
		0x253D04553FD36E41ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x287AA2E9463993E8ULL,
		0x5303AF4F5494295DULL,
		0xA97F49C5135FC79FULL,
		0x2A3F553B92A4D10EULL
	}};
	printf("Test Case 80\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x3FE0B824615FF9C6ULL,
		0xD9BC2C67EFD3DFC1ULL,
		0x458A066560462720ULL,
		0x5362296FBAA10E40ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x98B5CD5381020A7EULL,
		0xFD785A3B8D801D6EULL,
		0xC336EFD2ABAD9202ULL,
		0x27C66A1663C81DBCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA72AEAD0E05DEF48ULL,
		0xDC43D22C6253C252ULL,
		0x82531692B498951DULL,
		0x2B9BBF5956D8F083ULL
	}};
	printf("Test Case 81\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x9C57BEF25D02F26EULL,
		0x2D4B630CA8236330ULL,
		0x66E6CEF5884173C7ULL,
		0x56D0E44B70302260ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA943777351AD3BB8ULL,
		0x7BA926E301F05FF2ULL,
		0xAB75A3C166BAA729ULL,
		0x6CC9140D881126A5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF314477F0B55B6A3ULL,
		0xB1A23C29A633033DULL,
		0xBB712B342186CC9DULL,
		0x6A07D03DE81EFBBAULL
	}};
	printf("Test Case 82\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x969912FBD6EF715CULL,
		0xD8EC969E035C47D8ULL,
		0x963061A43AA9C42DULL,
		0x678C852CE6FE4149ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE3820EEF9FF2A871ULL,
		0x9FD4D3272151D24CULL,
		0x8827FB8D9282A300ULL,
		0x20E57163DFA8A3A0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB317040C36FCC8EBULL,
		0x3917C376E20A758BULL,
		0x0E086616A827212DULL,
		0x46A713C907559DA9ULL
	}};
	printf("Test Case 83\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xF2AE0DF83F20AD7DULL,
		0x074E59D6DADC1205ULL,
		0x408699B554C2B5DDULL,
		0x751F148ED67ACC3BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8161D169A0E6BF06ULL,
		0xB1347A6C0C2FDFDAULL,
		0x0E456EC96F2C2A4FULL,
		0x6EF96DA788D91892ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x714C3C8E9E39EE77ULL,
		0x5619DF6ACEAC322BULL,
		0x32412AEBE5968B8DULL,
		0x0625A6E74DA1B3A9ULL
	}};
	printf("Test Case 84\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x21E3D23350A830A2ULL,
		0xCB1D3EFC9770D980ULL,
		0x96E0CA658F8C500FULL,
		0x0740BB7AA0EDF95DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x246855291BB28495ULL,
		0xD98F2ADFE07D501DULL,
		0x47EFDEF1B081E228ULL,
		0x75E21F79839E3FE1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFD7B7D0A34F5ABFAULL,
		0xF18E141CB6F38962ULL,
		0x4EF0EB73DF0A6DE6ULL,
		0x115E9C011D4FB97CULL
	}};
	printf("Test Case 85\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x2F7566AEF0269EA5ULL,
		0x25B594B4B70C02E0ULL,
		0x0076FE138AAC20D5ULL,
		0x02E2C76B063970A7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE2DC762F7DC0533AULL,
		0x93781F9F48DBAC7AULL,
		0x139933003B6D01F3ULL,
		0x7CF37AE1AFF706CAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4C98F07F72664B58ULL,
		0x923D75156E305665ULL,
		0xECDDCB134F3F1EE1ULL,
		0x05EF4C89564269DCULL
	}};
	printf("Test Case 86\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xFD7A3563BD4C7E25ULL,
		0x5579F0158C719866ULL,
		0x16DECD407A86FCE1ULL,
		0x0428F86C00CA905CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBA0950D1CBE1CEFCULL,
		0x98E81A82FB20BD1FULL,
		0x7F20E4DEEA5521ECULL,
		0x48C38130F2B1B895ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4370E491F16AAF16ULL,
		0xBC91D5929150DB47ULL,
		0x97BDE8619031DAF4ULL,
		0x3B65773B0E18D7C6ULL
	}};
	printf("Test Case 87\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x16A79904985A351EULL,
		0xD84F974E6E2B7871ULL,
		0x8C01F2E433BD5F5DULL,
		0x4B5565C06250AEF3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7908A15D78B31995ULL,
		0x394ECE6187D9B048ULL,
		0x71B3A12E26007E44ULL,
		0x69F1DA609F8BD521ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9D9EF7A71FA71B76ULL,
		0x9F00C8ECE651C828ULL,
		0x1A4E51B60DBCE119ULL,
		0x61638B5FC2C4D9D2ULL
	}};
	printf("Test Case 88\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xF71F1F5C133AD22AULL,
		0x8AF088CA395CC18DULL,
		0x4D50AA44A71F4F01ULL,
		0x7BE1A51D2DECEF59ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6486A5F453DED3BDULL,
		0x39A19ED733CC173AULL,
		0x2B5C644866703393ULL,
		0x7255E1D2D2510E49ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x92987967BF5BFE6DULL,
		0x514EE9F30590AA53ULL,
		0x21F445FC40AF1B6EULL,
		0x098BC34A5B9BE110ULL
	}};
	printf("Test Case 89\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xF74183DFE7591A7AULL,
		0x30FCAC27BFDFB3CBULL,
		0x6E4C36D767ED8324ULL,
		0x46EED2FD7834CAE1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x14BD0D5C69581F19ULL,
		0xCB4282BC27896A56ULL,
		0x930A7059BEF6DDEAULL,
		0x6F0829C0699CBDD9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE28476837E00FB4EULL,
		0x65BA296B98564975ULL,
		0xDB41C67DA8F6A539ULL,
		0x57E6A93D0E980D07ULL
	}};
	printf("Test Case 90\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x4DC6DB8133DA801BULL,
		0x6D024D661A231599ULL,
		0xEB455B681F986A27ULL,
		0x1D673AE4B145C40FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF0B27692EB25A795ULL,
		0x536C6BF7FC98E41BULL,
		0x539ABBCB39BAAE9AULL,
		0x1F647D0ED7E1733BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5D1464EE48B4D873ULL,
		0x1995E16E1D8A317DULL,
		0x97AA9F9CE5DDBB8DULL,
		0x7E02BDD5D96450D4ULL
	}};
	printf("Test Case 91\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x56A450967DFA3415ULL,
		0x8E45BD258E017184ULL,
		0x16FA705DD557B27FULL,
		0x0A8422188C63A958ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB1206845C970E788ULL,
		0x46BEAE3C747B9926ULL,
		0xE3F86C2FEE4BA21AULL,
		0x5083685D113601AFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA583E850B4894C7AULL,
		0x47870EE91985D85DULL,
		0x3302042DE70C1065ULL,
		0x3A00B9BB7B2DA7A8ULL
	}};
	printf("Test Case 92\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xC3691CC588AA6B88ULL,
		0xC527F024E4F704C3ULL,
		0x5BA86DD03A6C8D2FULL,
		0x26840FC4A851A856ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBEE2F3CC58C2128DULL,
		0xD776409FFA5313DAULL,
		0xB2686114FBA7A3FBULL,
		0x39336626DADC0154ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x048628F92FE858E8ULL,
		0xEDB1AF84EAA3F0E9ULL,
		0xA9400CBB3EC4E933ULL,
		0x6D50A99DCD75A701ULL
	}};
	printf("Test Case 93\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x9B260F68B679BF80ULL,
		0xC6072307EC7387E0ULL,
		0x4049092F850E8A1FULL,
		0x44161A72CBD87097ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x403483FB81B27BDBULL,
		0x6447CF284F22C581ULL,
		0x6C9875593A97EFC9ULL,
		0x0BA5C6A596E60456ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5AF18B6D34C743A5ULL,
		0x61BF53DF9D50C25FULL,
		0xD3B093D64A769A56ULL,
		0x387053CD34F26C40ULL
	}};
	printf("Test Case 94\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x256EFAF45DBAEEDAULL,
		0x8B7939A40F230921ULL,
		0x00A3A8ABC719B948ULL,
		0x42DF6FA4C7691253ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCD16F75D85556C6BULL,
		0x1AC5E13481B879DEULL,
		0xBDD9DA53C0EB719FULL,
		0x3DE3915F6DED00D4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x58580396D865826FULL,
		0x70B3586F8D6A8F42ULL,
		0x42C9CE58062E47A9ULL,
		0x04FBDE45597C117EULL
	}};
	printf("Test Case 95\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xEDB30500C309CF66ULL,
		0x57C90BE2BF5311B2ULL,
		0xE65AA19A9B3870DDULL,
		0x342F4100B14EDA4CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF6D855523A2AEB99ULL,
		0x3259CD02523ED4C9ULL,
		0x9EFCA11B2E81D54EULL,
		0x026874F6052432C8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF6DAAFAE88DEE3CDULL,
		0x256F3EE06D143CE8ULL,
		0x475E007F6CB69B8FULL,
		0x31C6CC0AAC2AA784ULL
	}};
	printf("Test Case 96\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x7FB51CFDBFA8E0EBULL,
		0xD98F33EF4944F8D1ULL,
		0x0EC0C80489DBCF6FULL,
		0x53E3E743E5631636ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x175B47C45427E656ULL,
		0xF2479ABB076BFF0AULL,
		0xA17B57A90DB95257ULL,
		0x555C624C097FFFBFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6859D5396B80FA82ULL,
		0xE747993441D8F9C7ULL,
		0x6D45705B7C227D17ULL,
		0x7E8784F7DBE31676ULL
	}};
	printf("Test Case 97\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x00E4A4219589DF34ULL,
		0xCAC2F8B3913DF220ULL,
		0x13BA4AA4E055061BULL,
		0x05AD703D8CF2D1FAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9C0DC71873198CD0ULL,
		0xB3FAC90AAC80B679ULL,
		0xCD6E211CAE60E71FULL,
		0x12B8C44D6727DA26ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x64D6DD0922705251ULL,
		0x16C82FA8E4BD3BA6ULL,
		0x464C298831F41EFCULL,
		0x72F4ABF025CAF7D3ULL
	}};
	printf("Test Case 98\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x78AC9C14966CFAD3ULL,
		0xE56939F748A19C81ULL,
		0xCE5A20A416ED8DD6ULL,
		0x099EB217B05D121DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6D4FAE549687DCDFULL,
		0x5BE9C7AA86B15E28ULL,
		0xDD332F167E982173ULL,
		0x701D26BD89319BCEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0B5CEDBFFFE51DE1ULL,
		0x897F724CC1F03E59ULL,
		0xF126F18D98556C63ULL,
		0x19818B5A272B764EULL
	}};
	printf("Test Case 99\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xDFB3EBFB098098C8ULL,
		0x22ECC2D1A08F55AFULL,
		0x41792229DF645239ULL,
		0x5EC954A35606F628ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3AC8BDBB3C50519EULL,
		0xF815597F455C1B53ULL,
		0x5505B4B9F0D39622ULL,
		0x6B2D4CF09A935CE7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA4EB2E3FCD304717ULL,
		0x2AD769525B333A5CULL,
		0xEC736D6FEE90BC16ULL,
		0x739C07B2BB739940ULL
	}};
	printf("Test Case 100\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x1EFD3C17A80C7732ULL,
		0x918FB6A327397EFDULL,
		0xB168B81EB71EE67DULL,
		0x607C6688E519EAB7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x09D4A571F33FA22EULL,
		0x7E190D707D431268ULL,
		0xBAE9744977564B0CULL,
		0x5760FA89B9252624ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x152896A5B4CCD504ULL,
		0x1376A932A9F66C95ULL,
		0xF67F43D53FC89B71ULL,
		0x091B6BFF2BF4C492ULL
	}};
	printf("Test Case 101\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x0696D85310F3E322ULL,
		0x566E85262E27558DULL,
		0x73B7672B211C495FULL,
		0x0608FCC258F7185FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFCD85AB35E5156F4ULL,
		0x7888E3FA04C36198ULL,
		0xDCDBABDF359A5085ULL,
		0x308715E4AB1DAF8AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x09BE7D9FB2A28C1BULL,
		0xDDE5A12C2963F3F4ULL,
		0x96DBBB4BEB81F8D9ULL,
		0x5581E6DDADD968D4ULL
	}};
	printf("Test Case 102\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xD46AF1E141131BA0ULL,
		0x4DA7121FA4FB900DULL,
		0x5197994076F02321ULL,
		0x33591CEEC6C80765ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xED21460623F21137ULL,
		0x0706500974ECF0C0ULL,
		0xA4D17091AC167E99ULL,
		0x3D89BDE9C12D5625ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE749ABDB1D210A56ULL,
		0x46A0C216300E9F4CULL,
		0xACC628AECAD9A488ULL,
		0x75CF5F05059AB13FULL
	}};
	printf("Test Case 103\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x905B6F7B622B18A6ULL,
		0x99CE1F2EF10739E5ULL,
		0x2C2FC246BE88664BULL,
		0x2BE502D7E732E466ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x55901C2A9B2E384DULL,
		0x2DF9B9834A3FF6D2ULL,
		0xA0642E3FE5B5F88EULL,
		0x0BFFCB99B425EB73ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3ACB5350C6FCE059ULL,
		0x6BD465ABA6C74313ULL,
		0x8BCB9406D8D26DBDULL,
		0x1FE5373E330CF8F2ULL
	}};
	printf("Test Case 104\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xEEA49C857C5BB4E5ULL,
		0xE302A621753C54B1ULL,
		0x2B65ED8ED7D086A2ULL,
		0x4B09FF76D104968FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7204818EB6E834DDULL,
		0x8020AC834A825A60ULL,
		0x4C912FECC31269E8ULL,
		0x45EA5C82CFD17197ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7CA01AF6C5738008ULL,
		0x62E1F99E2AB9FA51ULL,
		0xDED4BDA214BE1CBAULL,
		0x051FA2F4013324F7ULL
	}};
	printf("Test Case 105\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x95F87ACE53D56DB9ULL,
		0x637DA1E484BC968EULL,
		0x9DBF30F0BB1C942FULL,
		0x5A7E1D4AD22F76C5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCCF5E92FA6AC8AD4ULL,
		0xBEB54E4F636021C8ULL,
		0x1F2621F0C65D823EULL,
		0x07E72C0762AD2F0DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC902919EAD28E2E5ULL,
		0xA4C85395215C74C5ULL,
		0x7E990EFFF4BF11F0ULL,
		0x5296F1436F8247B8ULL
	}};
	printf("Test Case 106\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x648F3290E3ECF113ULL,
		0x120AD27195292F4DULL,
		0xED276C7472700060ULL,
		0x744A0D809390B71BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x716B28C798D3BD5DULL,
		0x22929AE7507490CEULL,
		0xD234674B594C171BULL,
		0x5D322B733AECB5C6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF32409C94B1933B6ULL,
		0xEF78378A44B49E7EULL,
		0x1AF305291923E944ULL,
		0x1717E20D58A40155ULL
	}};
	printf("Test Case 107\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xD634A22D17F7858EULL,
		0xE1B177E3E76C6F97ULL,
		0x483C0E6C45A3C154ULL,
		0x734C400CEBBE3C63ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1E69B7897AECACE8ULL,
		0x2AECC2245A83E8A3ULL,
		0x00F81D88B54F7594ULL,
		0x6AC9A93B18606483ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB7CAEAA39D0AD8A6ULL,
		0xB6C4B5BF8CE886F4ULL,
		0x4743F0E390544BC0ULL,
		0x088296D1D35DD7E0ULL
	}};
	printf("Test Case 108\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x150EF362BB4829E7ULL,
		0xC6BD51EFCF9D0510ULL,
		0x5F3395D399C8386FULL,
		0x1E2231513CAA38EBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5A12D9E48D862FB6ULL,
		0x24DB9841451C09C3ULL,
		0x7E23BFC3375451BBULL,
		0x2C52EA49D4E433C2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBAFC197E2DC1FA1EULL,
		0xA1E1B9AE8A80FB4CULL,
		0xE10FD6106273E6B4ULL,
		0x71CF470767C60528ULL
	}};
	printf("Test Case 109\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x791F97122A969405ULL,
		0x9E6D0A90682FCC1EULL,
		0xED1ABCE591433094ULL,
		0x244785F34B321C30ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0E5B721A8654374DULL,
		0x3BB2C213AD5D885FULL,
		0x3BAD9EA4B8CFB0F8ULL,
		0x07A21A30D12ACC25ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6AC424F7A4425CB8ULL,
		0x62BA487CBAD243BFULL,
		0xB16D1E40D8737F9CULL,
		0x1CA56BC27A07500BULL
	}};
	printf("Test Case 110\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xE6858699282D7717ULL,
		0x6596019FCB23F837ULL,
		0xC6CDACFCF920B3AAULL,
		0x4BE7ECA0FF72F60AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCA96DC68890B388FULL,
		0x56DB22CF7DE2405AULL,
		0x5F641041D69A540BULL,
		0x0D8B15D85771C300ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1BEEAA309F223E88ULL,
		0x0EBADED04D41B7DDULL,
		0x67699CBB22865F9FULL,
		0x3E5CD6C8A801330AULL
	}};
	printf("Test Case 111\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x3BAA324D62DCFA5CULL,
		0xD2B8F152ED46C8D8ULL,
		0x8B0631BF76CD98D2ULL,
		0x6509A3412E329D42ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDC4FC0D74D4DA023ULL,
		0xC27AB12097ECABB8ULL,
		0xC9324D7A1FEF38EBULL,
		0x2429316C1CBEA4B7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5F5A7176158F5A39ULL,
		0x103E4032555A1D1FULL,
		0xC1D3E44556DE5FE7ULL,
		0x40E071D51173F88AULL
	}};
	printf("Test Case 112\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x5B65160A3CE080B2ULL,
		0x822366B7A2413527ULL,
		0x85B0B06834259BBAULL,
		0x660F254E7B5BED71ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7FB2C255C41D3ED5ULL,
		0x2021571460E9E596ULL,
		0xB5932181FB0D4370ULL,
		0x291E61CE5CCBEA25ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDBB253B478C341DDULL,
		0x62020FA341574F90ULL,
		0xD01D8EE63918584AULL,
		0x3CF0C3801E90034BULL
	}};
	printf("Test Case 113\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xB326F84CC84B6B3BULL,
		0x8A4E267178E314CFULL,
		0xE63361D8F454951AULL,
		0x3415D44DB73611E2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4B9FF29CDCB7E323ULL,
		0x870093401D30EDEAULL,
		0xC0A28C3B26A9949FULL,
		0x4A49F28378B98F45ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x678705AFEB938805ULL,
		0x034D93315BB226E5ULL,
		0x2590D59DCDAB007BULL,
		0x69CBE1CA3E7C829DULL
	}};
	printf("Test Case 114\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xCD0D0D1D9C13C1FFULL,
		0x62433F5A91EC6304ULL,
		0x306326F0BD8DFDD0ULL,
		0x16D130C8C3533AADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x63D865736EBF188EULL,
		0xB0A9A3666DEFF8AEULL,
		0xF072D954667699C3ULL,
		0x45A57116807648C8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6934A7AA2D54A95EULL,
		0xB1999BF423FC6A56ULL,
		0x3FF04D9C5717640CULL,
		0x512BBFB242DCF1E4ULL
	}};
	printf("Test Case 115\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x1C83C6DCFBBF5A6CULL,
		0xAE1340E3CB6C7414ULL,
		0xD706BBB4B622A9E3ULL,
		0x08797CE747E4B0F6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5B4D3898E50F87B6ULL,
		0x625476653A8CE278ULL,
		0x5E38CAA7441586EEULL,
		0x13711B22C59CE318ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC1368E4416AFD2A3ULL,
		0x4BBECA7E90DF919BULL,
		0x78CDF10D720D22F5ULL,
		0x750861C48247CDDEULL
	}};
	printf("Test Case 116\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x16509D0344F145F0ULL,
		0x520F34790D33610EULL,
		0xC61D50CC7678B6FCULL,
		0x4CF9C8E5816D32ADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5D64A91B6C8794FAULL,
		0x998C6393ED29DE3EULL,
		0xD1E1F4C614A5199CULL,
		0x6120A121203E425CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB8EBF3E7D869B0E3ULL,
		0xB882D0E5200982CFULL,
		0xF43B5C0661D39D5FULL,
		0x6BD927C4612EF050ULL
	}};
	printf("Test Case 117\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xA523FF071D1DAAD1ULL,
		0x4D3929A4BCCD85DDULL,
		0xFCD498757130C58EULL,
		0x3E4D7205F0818DDDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2D7C7C808189C2BDULL,
		0x12FD9A01A2BDC840ULL,
		0xA348B5C23BBC3B51ULL,
		0x35AC4E72BD9D436FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x77A782869B93E814ULL,
		0x3A3B8FA31A0FBD9DULL,
		0x598BE2B335748A3DULL,
		0x08A1239332E44A6EULL
	}};
	printf("Test Case 118\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x3646CC59A73AF4A0ULL,
		0xA4E782F3B088EC9BULL,
		0xC8E4DAE9B15B08C9ULL,
		0x097589A671684315ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7D5CBC64A47A02D0ULL,
		0x64B18BBFE147070BULL,
		0x574175C33DE32AF1ULL,
		0x0634F1538D6FB894ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB8EA0FF502C0F1D0ULL,
		0x4035F733CF41E58FULL,
		0x71A365267377DDD8ULL,
		0x03409852E3F88A81ULL
	}};
	printf("Test Case 119\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xF495A01CF6742FBBULL,
		0xE7F7E620D6A1A01DULL,
		0xB043E68CE97BDAE4ULL,
		0x4DCD644D6D2BE16AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2033818CDE055D68ULL,
		0xDAE784AE44C35117ULL,
		0x535AABA89C89F77FULL,
		0x2DA77BC4E438E596ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD4621E90186ED253ULL,
		0x0D10617291DE4F06ULL,
		0x5CE93AE44CF1E365ULL,
		0x2025E88888F2FBD4ULL
	}};
	printf("Test Case 120\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x78B5145E7DCEAC79ULL,
		0xE526D8C395958934ULL,
		0x13A5DD91C3DAF4AAULL,
		0x29DDF0ECF8A008ADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5B941E1462D35CA4ULL,
		0x48DA0282C58C9DB5ULL,
		0x825C2E5453FEA1ECULL,
		0x29D7B5C4943E985AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1D20F64A1AFB4FD5ULL,
		0x9C4CD640D008EB7FULL,
		0x9149AF3D6FDC52BEULL,
		0x00063B2864617052ULL
	}};
	printf("Test Case 121\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x9D0BDE7880FA485FULL,
		0xB36F9D97C6D2A1D0ULL,
		0xFE6BBD648A3C9F3BULL,
		0x2AD9DC0CFDABEA0BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFB20D148CCB3C0D4ULL,
		0x3FA24322A9E2184EULL,
		0x7C37BBAB3CF132EDULL,
		0x0E18D7D95FC83740ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA1EB0D2FB446878BULL,
		0x73CD5A751CF08981ULL,
		0x823401B94D4B6C4EULL,
		0x1CC104339DE3B2CBULL
	}};
	printf("Test Case 122\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x3E7A53DCE4E49DAFULL,
		0x2C3F9045577A7E5CULL,
		0x5F3314A907DAD61DULL,
		0x3F4E3791B5075CECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCAB42A0D35A71BAEULL,
		0x39B6AE246927FA89ULL,
		0x34D474AA3A262345ULL,
		0x7AAFA5C858AB1811ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x73C629CFAF3D81EEULL,
		0xF288E220EE5283D2ULL,
		0x2A5E9FFECDB4B2D7ULL,
		0x449E91C95C5C44DBULL
	}};
	printf("Test Case 123\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x5B6B7B0F5AA7BE4EULL,
		0xB1E620918E8A4822ULL,
		0x29BFB800C4789AE5ULL,
		0x137B48ADAB08A755ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3156B62884FF710CULL,
		0xF0B118CE593F19F3ULL,
		0x76CE25F18A56F41CULL,
		0x1E18CCC0DDD3CACBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2A14C4E6D5A84D2FULL,
		0xC13507C3354B2E2FULL,
		0xB2F1920F3A21A6C8ULL,
		0x75627BECCD34DC89ULL
	}};
	printf("Test Case 124\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xE2FEBF81F2C6B3CEULL,
		0x2736686ED6E14185ULL,
		0x89A0ED0A2D45CAEEULL,
		0x0F92B8A368ACF0B1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0BB4051D5C1A5C5FULL,
		0xA1BFFD3609DE4487ULL,
		0xEC594A268FBCFA18ULL,
		0x5BFEF72025880CFCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD74ABA6496AC575CULL,
		0x85766B38CD02FCFEULL,
		0x9D47A2E39D88D0D5ULL,
		0x3393C1834324E3B4ULL
	}};
	printf("Test Case 125\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x67274E28C9D9C90CULL,
		0x4E2790428057B4CAULL,
		0x0C557462AE126E98ULL,
		0x5C0E4D609D4812D4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6DEF999EC144A8C6ULL,
		0x39E699BC1FDC5AE1ULL,
		0x511FA1116437038BULL,
		0x1CD5A4E8EE24E6FEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF937B48A08952046ULL,
		0x1440F686607B59E8ULL,
		0xBB35D35149DB6B0DULL,
		0x3F38A877AF232BD5ULL
	}};
	printf("Test Case 126\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x0C574DB029756734ULL,
		0x3AC5912B3CBB92A6ULL,
		0x43186F820FF34794ULL,
		0x011AA9EB4E848B54ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x59EA408297438E9BULL,
		0x8BA3B28603CB85EFULL,
		0x6FF40FF0DE1EB156ULL,
		0x7D0C1DDC657B6605ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB26D0D2D9231D886ULL,
		0xAF21DEA538F00CB6ULL,
		0xD3245F9131D4963DULL,
		0x040E8C0EE909254EULL
	}};
	printf("Test Case 127\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x43BC2BDC96F0BCE7ULL,
		0x22B2063CBD012C72ULL,
		0x5DFAB251A8A8E627ULL,
		0x311692A49ABDB6FFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x07F26077BA68E8ADULL,
		0x4D4B26E17B882235ULL,
		0x303F6E87C346E225ULL,
		0x383C6BECAED6D31FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3BC9CB64DC87D427ULL,
		0xD566DF5B41790A3DULL,
		0x2DBB43C9E5620401ULL,
		0x78DA26B7EBE6E3E0ULL
	}};
	printf("Test Case 128\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x72F14EC99FEEB079ULL,
		0xE4A2076F70845D75ULL,
		0x1F60C6984C286AF6ULL,
		0x0FB272BE5452D7B4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x042502E3346B9F0BULL,
		0xF02973C0D84EB710ULL,
		0xD9EB3EB9EDA16860ULL,
		0x3318D3AE476D9716ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6ECC4BE66B83115BULL,
		0xF47893AE9835A665ULL,
		0x457587DE5E870295ULL,
		0x5C999F100CE5409DULL
	}};
	printf("Test Case 129\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x176C558FF088546EULL,
		0x2DD6DC1FA3FD6A13ULL,
		0x54B9B24E6B8AF2CBULL,
		0x1400EF8C4F0FAB3AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC98793B0EBB8BC44ULL,
		0x51D812B0CED43BDAULL,
		0xB79BA7D51A331611ULL,
		0x086FDD4E7991583FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4DE4C1DF04CF982AULL,
		0xDBFEC96ED5292E38ULL,
		0x9D1E0A795157DCB9ULL,
		0x0B91123DD57E52FAULL
	}};
	printf("Test Case 130\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xD4854F5C3BB049D3ULL,
		0xE22532342CD323D9ULL,
		0x96A892C815422ABFULL,
		0x2AC5BE39C7611D3EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x566B1C39711BAB02ULL,
		0xC1AFC620ABFF1F64ULL,
		0x24D54379CC33662FULL,
		0x683757D7634ADE5CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7E1A3322CA949EBEULL,
		0x20756C1380D40475ULL,
		0x71D34F4E490EC490ULL,
		0x428E666264163EE2ULL
	}};
	printf("Test Case 131\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x0B2D7EAE9295829DULL,
		0x633699EE478DC435ULL,
		0x0A1AAC80CA3E4094ULL,
		0x626B1B0F67F5DC2CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF96B4880E81AEE7CULL,
		0xE6238417CCB1D1D2ULL,
		0x562C631C78BCFBFEULL,
		0x525321DA2221EFCAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x11C2362DAA7A9421ULL,
		0x7D1315D67ADBF262ULL,
		0xB3EE496451814495ULL,
		0x1017F93545D3EC61ULL
	}};
	printf("Test Case 132\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xF7A467D62EE61F83ULL,
		0x3A8506283FC13163ULL,
		0x1D6CDE9258EAE365ULL,
		0x10294447E63BFA3FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x37C6DC93ED3432AFULL,
		0x0F8881F73DF243DBULL,
		0xB6428EB41957AF99ULL,
		0x4333D498F5524CE1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBFDD8B4241B1ECC1ULL,
		0x2AFC843101CEED88ULL,
		0x672A4FDE3F9333CCULL,
		0x4CF56FAEF0E9AD5DULL
	}};
	printf("Test Case 133\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x2ACBD90085B8A423ULL,
		0x87ABD60B7FCE1E10ULL,
		0xE0AAA952D399A817ULL,
		0x7445EF24DAC9F76FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0CD9B9CE80748C8DULL,
		0x305E5A254329003FULL,
		0x9556A16550F60E6FULL,
		0x2884B4BDE77AA853ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1DF21F3205441796ULL,
		0x574D7BE63CA51DD1ULL,
		0x4B5407ED82A399A8ULL,
		0x4BC13A66F34F4F1CULL
	}};
	printf("Test Case 134\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xAE5A71BD5F9FFBF9ULL,
		0xDC815EAA514DEFF6ULL,
		0x47DFE3699B3B61BBULL,
		0x58B43171E4FB4E71ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4A4E55B5877D20AFULL,
		0xBDD8BDA440F46F6CULL,
		0xB83EDB5991FB46DDULL,
		0x45CB7A313468EBD1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x640C1C07D822DB4AULL,
		0x1EA8A1061059808AULL,
		0x8FA1081009401ADEULL,
		0x12E8B740B092629FULL
	}};
	printf("Test Case 135\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x120939DE1E82CCEBULL,
		0x56263A6D8D3E8A71ULL,
		0x02A85EF951FB30D7ULL,
		0x6A5DFE0517D5C4EDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD307FF814B85E0DFULL,
		0x41FCF2073385D487ULL,
		0x214869DD1E620A23ULL,
		0x1FD507C6FB482D55ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3F013A5CD2FCEC0CULL,
		0x1429486659B8B5E9ULL,
		0xE15FF51C339926B4ULL,
		0x4A88F63E1C8D9797ULL
	}};
	printf("Test Case 136\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xF3A81BE65CF630DEULL,
		0xCB8D08F2140C61D4ULL,
		0x07C2229157EAAB54ULL,
		0x49BDE430D9BC400EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F79489FF7CE3F12ULL,
		0xB3C45DB5543622B5ULL,
		0xF46565EEF1DA1C35ULL,
		0x5C2A0562F4B2F5D4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE42ED3466527F1B9ULL,
		0x17C8AB3CBFD63F1FULL,
		0x135CBCA266108F1FULL,
		0x6D93DECDE5094A39ULL
	}};
	printf("Test Case 137\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x546E017D7060DC11ULL,
		0xF275BC4573ADFBD7ULL,
		0x0FEEF7FEB21DD102ULL,
		0x3A9020A9748D55F3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x437B438BE6E130A7ULL,
		0xD60BBAD22A2C2F19ULL,
		0x22F5BB40299EFDFEULL,
		0x5E8C847EDDC9B24DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x10F2BDF1897FAB57ULL,
		0x1C6A01734981CCBEULL,
		0xECF93CBE887ED304ULL,
		0x5C039C2A96C3A3A5ULL
	}};
	printf("Test Case 138\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x60373A740CF8F0B7ULL,
		0xAE54EE1A86149776ULL,
		0xD37A7977161F2642ULL,
		0x5B900DD7E8569E7EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9801C8986DFCEDD9ULL,
		0x7F9C842687C4758BULL,
		0x575DDEC6EFB545A8ULL,
		0x6FBC80C03AF28971ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC83571DB9EFC02CBULL,
		0x2EB869F3FE5021EAULL,
		0x7C1C9AB02669E09AULL,
		0x6BD38D17AD64150DULL
	}};
	printf("Test Case 139\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xB0C72BBFB6827C20ULL,
		0xB198DFB4B43EC0F9ULL,
		0x9AC707D69D2DFEC1ULL,
		0x33906B816466A059ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x976FDAC18F01937CULL,
		0xDCCC45C101E01BA9ULL,
		0x8855C275EDED0827ULL,
		0x04AA84F5CFEF729FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x195750FE2780E8A4ULL,
		0xD4CC99F3B25EA550ULL,
		0x12714560AF40F699ULL,
		0x2EE5E68B94772DBAULL
	}};
	printf("Test Case 140\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x5533B370B89B8A0BULL,
		0x0DE70A9C4DF020F6ULL,
		0x0E0201B99767A71FULL,
		0x08D69BA7BE645BEAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x934D2472B9DAF80CULL,
		0x5CEB1F099F508495ULL,
		0x46EBF2083D0D8F8FULL,
		0x052C5B681FDC8F72ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC1E68EFDFEC091FFULL,
		0xB0FBEB92AE9F9C60ULL,
		0xC7160FB15A5A178FULL,
		0x03AA403F9E87CC77ULL
	}};
	printf("Test Case 141\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x70670652E08A87DBULL,
		0x25A78A0F7212C320ULL,
		0xE697E1758DC4B790ULL,
		0x6F707A7454854AE4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1795BF88E7A6A6A8ULL,
		0xF659612666A22AE4ULL,
		0x4F4785B1A0A9AC33ULL,
		0x33DA571446C7ED87ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x58D146C9F8E3E133ULL,
		0x2F4E28E90B70983CULL,
		0x97505BC3ED1B0B5CULL,
		0x3B9623600DBD5D5DULL
	}};
	printf("Test Case 142\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xDF73F1EDEA0651B6ULL,
		0xD6070BE1BDDBF632ULL,
		0xA7DF6EF65F45D042ULL,
		0x114C536CE6138A54ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDB7FE658277448F3ULL,
		0x6DE9315AE6DC7992ULL,
		0x5E286934BDC1F340ULL,
		0x304AD6235D2DE5B2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x03F40B95C29208B0ULL,
		0x681DDA86D6FF7CA0ULL,
		0x49B705C1A183DD02ULL,
		0x61017D4988E5A4A2ULL
	}};
	printf("Test Case 143\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x969CFA1500901284ULL,
		0x159AB47D618C4572ULL,
		0xE5B1CE2EE1B3EE53ULL,
		0x7532755FE3557465ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x23ECA462CAC0BA97ULL,
		0xC43D077ABAC577F1ULL,
		0x6374894339FD01CAULL,
		0x54CAE809B31CA5B4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x72B055B235CF57EDULL,
		0x515DAD02A6C6CD81ULL,
		0x823D44EBA7B6EC88ULL,
		0x20678D563038CEB1ULL
	}};
	printf("Test Case 144\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x80CF75F8B6D6312AULL,
		0xB52C0F003A38B4CFULL,
		0xDB1DAE8D6CB7AF5FULL,
		0x66741F4727BD53F8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0FDF7799F4AC63D3ULL,
		0x46A2E2316868B3AAULL,
		0xDB4724506BF3F94AULL,
		0x7A58A208113CDC32ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x70EFFE5EC229CD44ULL,
		0x6E892CCED1D00125ULL,
		0xFFD68A3D00C3B615ULL,
		0x6C1B7D3F168077C5ULL
	}};
	printf("Test Case 145\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xEA8D58EE12E342B7ULL,
		0xDF0577CEA9EE1018ULL,
		0x7100DDA971A4739BULL,
		0x78B0DC08DFEF9A11ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3A1C48B6439DF4B9ULL,
		0x0423509F87458EECULL,
		0x5E6700D04587EA91ULL,
		0x329628B74E6D8DDBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB0711037CF454DFEULL,
		0xDAE2272F22A8812CULL,
		0x1299DCD92C1C890AULL,
		0x461AB35191820C36ULL
	}};
	printf("Test Case 146\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x671111E9B6B1ADB5ULL,
		0x1F8AF635F8673819ULL,
		0xE230F1105DE87BB4ULL,
		0x36E0B50ED05C1731ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x509008548824071CULL,
		0xEF608F99D40834C0ULL,
		0x94298969AC5A4C66ULL,
		0x32E6EBAF697BD486ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x168109952E8DA699ULL,
		0x302A669C245F0359ULL,
		0x4E0767A6B18E2F4DULL,
		0x03F9C95F66E042ABULL
	}};
	printf("Test Case 147\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x47F1E6F259F23354ULL,
		0x65DC633DF77D59ABULL,
		0x153B4F0D3C38ED3AULL,
		0x49A098781916FE88ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6874F682C88E49B5ULL,
		0x52858F861ED540FBULL,
		0x1BA8DCEB8CA7AC7DULL,
		0x2942096909DA41AAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDF7CF06F9163E99FULL,
		0x1356D3B7D8A818AFULL,
		0xF9927221AF9140BDULL,
		0x205E8F0F0F3CBCDDULL
	}};
	printf("Test Case 148\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xFE5FB519C16E0594ULL,
		0x99877102A27FB50FULL,
		0x6863DBC3E81F6B3DULL,
		0x22E7B81272E74E8BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x32E23F3AF95B150EULL,
		0x96D0FB523325A563ULL,
		0x3A823406E57652D5ULL,
		0x00654C7D8EB7D893ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCB7D75DEC812F086ULL,
		0x02B675B06F5A0FACULL,
		0x2DE1A7BD02A91868ULL,
		0x22826B94E42F75F8ULL
	}};
	printf("Test Case 149\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x67B1D2D11ECDB443ULL,
		0x9D40D26A68F66183ULL,
		0xB3DF41EB32835BD2ULL,
		0x734A51144CEC22FAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x08FEA436D8EFDB07ULL,
		0x8D71A8F4F4AC3E45ULL,
		0xC13836469A898A2EULL,
		0x41CBA135EC5AABFAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5EB32E9A45DDD93CULL,
		0x0FCF2975744A233EULL,
		0xF2A70BA497F9D1A4ULL,
		0x317EAFDE609176FFULL
	}};
	printf("Test Case 150\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xCDECCC319DE18440ULL,
		0x1EA89AB9671BD342ULL,
		0xA653E2ED18EE7508ULL,
		0x3AF7C0E2F073FBCCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x76AFC962986C8FABULL,
		0x46BFC8C68F55F8D5ULL,
		0x586AC1276EA0F7BBULL,
		0x3567FF16980C07BDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x573D02CF0574F495ULL,
		0xD7E8D1F2D7C5DA6DULL,
		0x4DE921C5AA4D7D4CULL,
		0x058FC1CC5867F40FULL
	}};
	printf("Test Case 151\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x06FD0A5CA82C331CULL,
		0xF93E39DFB6696464ULL,
		0x0E4E81F5F09F21C3ULL,
		0x50AFEA452E4ED124ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC4653B56683619F0ULL,
		0x098E2C1FA00839C8ULL,
		0x51317FDC3886170FULL,
		0x6D652CDDDBA90977ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4297CF063FF61919ULL,
		0xEFB00DC016612A9BULL,
		0xBD1D0219B8190AB4ULL,
		0x634ABD6752A5C7ACULL
	}};
	printf("Test Case 152\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xAC5F36937CFFC7C0ULL,
		0x513E4748565B9CBAULL,
		0x9054A531742E5311ULL,
		0x107635CF39F3B21EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2985F2D95AC642ACULL,
		0xDF9762997C9FA81DULL,
		0x2E773ADBB1AEB83AULL,
		0x58A37650DE94682CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x82D943BA22398501ULL,
		0x71A6E4AED9BBF49DULL,
		0x61DD6A55C27F9AD6ULL,
		0x37D2BF7E5B5F49F2ULL
	}};
	printf("Test Case 153\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x5849CFA0C80BA6F5ULL,
		0xA9189E72BB6D5691ULL,
		0x77969C2694D35A87ULL,
		0x7175F94EFB62CFFDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD993FEC756184B63ULL,
		0xD84806487B781A54ULL,
		0x176C3F20707914E9ULL,
		0x5FC2962D94C40F75ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7EB5D0D971F35B92ULL,
		0xD0D0982A3FF53C3CULL,
		0x602A5D06245A459DULL,
		0x11B36321669EC088ULL
	}};
	printf("Test Case 154\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xCAB79427110EACA7ULL,
		0x96E52E28E06071B4ULL,
		0x12730651760FC1C5ULL,
		0x0FF8B64BDDE59DA0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x18E3C5AF8A61520DULL,
		0x2398425CD74D7270ULL,
		0xDF6C152C8A7324E9ULL,
		0x39DAE9C345B33E69ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB1D3CE7786AD5A87ULL,
		0x734CEBCC0912FF44ULL,
		0x3306F124EB9C9CDCULL,
		0x561DCC8898325F36ULL
	}};
	printf("Test Case 155\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x8D950A410C84A918ULL,
		0x6AD4A87D04400287ULL,
		0xBBD945A91BBE0988ULL,
		0x075C23553185262AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x142CF5745A4F81F5ULL,
		0x4544D8433205E698ULL,
		0xEE7B193BEA204D3AULL,
		0x27BEF203EAFB52FAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x796814CCB2352710ULL,
		0x258FD039D23A1BEFULL,
		0xCD5E2C6D319DBC4EULL,
		0x5F9D31514689D32FULL
	}};
	printf("Test Case 156\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x636DDD5378A087F9ULL,
		0xB9DC59214734EFDAULL,
		0x769E415DEAAE2A73ULL,
		0x5EDC148B85D10116ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF31466A23D8BF305ULL,
		0x3C48EC2A63F27855ULL,
		0xD997150DF9FDE470ULL,
		0x6E3825C0FDA485CCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x705976B13B1494E1ULL,
		0x7D936CF6E3427784ULL,
		0x9D072C4FF0B04603ULL,
		0x70A3EECA882C7B49ULL
	}};
	printf("Test Case 157\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x027D9E7A7983703AULL,
		0x2B4F5A40797CB442ULL,
		0xCFECE5C41E774D0EULL,
		0x1E648CB73C66273FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA630AE11A06BE214ULL,
		0x47069E2BD326B153ULL,
		0xD5B1F00B860819D2ULL,
		0x6D19E12931F5B2AEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5C4CF068D9178E13ULL,
		0xE448BC14A65602EEULL,
		0xFA3AF5B8986F333BULL,
		0x314AAB8E0A707490ULL
	}};
	printf("Test Case 158\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x6A411479FA000DC2ULL,
		0x5DA7D7165AAE513EULL,
		0x6988807A30F64CF1ULL,
		0x7E10D38B0100015DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4715C2017E9E232DULL,
		0x9F5A711A52FACEAFULL,
		0xDC7AD4E2569563F4ULL,
		0x17632A2258C054BFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x232B52787B61EA95ULL,
		0xBE4D65FC07B3828FULL,
		0x8D0DAB97DA60E8FCULL,
		0x66ADA968A83FAC9DULL
	}};
	printf("Test Case 159\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xDDC00D65EF4390A8ULL,
		0x8024C472DE946E37ULL,
		0x8B9F0286E2FE3F07ULL,
		0x464CF533D0B58DAFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAD76E55C7E7B1306ULL,
		0xD19EEE6F9C60E066ULL,
		0x2BED8E2C31505DC4ULL,
		0x7AEF3C72364EDF9CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3049280970C87D8FULL,
		0xAE85D60342338DD1ULL,
		0x5FB1745AB1ADE142ULL,
		0x4B5DB8C19A66AE13ULL
	}};
	printf("Test Case 160\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x0B3A18F5528B66BFULL,
		0x4BB8A13AE51F61BAULL,
		0x028D411A93F9D02CULL,
		0x1A20CAF05FA221E2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x64F7FBC9B6AAF409ULL,
		0x737AF37665DB9725ULL,
		0x3590307F0FC5311BULL,
		0x157535E6C19E1E80ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA6421D2B9BE072B6ULL,
		0xD83DADC47F43CA94ULL,
		0xCCFD109B84349F10ULL,
		0x04AB95099E040361ULL
	}};
	printf("Test Case 161\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xC7BB7F3E06CE9384ULL,
		0x5B58D597F38CB399ULL,
		0xC147A5B3386ED4AEULL,
		0x790246D72EB97D45ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x529AF942E453571AULL,
		0xE426256EEF5C24EAULL,
		0x3456E186CF69A64AULL,
		0x49A8A5C449282C1CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x752085FB227B3C6AULL,
		0x7732B02904308EAFULL,
		0x8CF0C42C69052E63ULL,
		0x2F59A112E5915129ULL
	}};
	printf("Test Case 162\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x213D1E5303AA3941ULL,
		0x81141CA20094C821ULL,
		0xB82B65D856E6AA89ULL,
		0x6FA4CE0AE16B2089ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xADC7939DDDE84396ULL,
		0x947FB00AF658D285ULL,
		0xA3133271594F2970ULL,
		0x1F75836318303980ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x73758AB525C1F5ABULL,
		0xEC946C970A3BF59BULL,
		0x15183366FD978118ULL,
		0x502F4AA7C93AE709ULL
	}};
	printf("Test Case 163\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x6EC277D0C38FD113ULL,
		0x06A5CA7C780E2A76ULL,
		0x15EE2F08628439E4ULL,
		0x58CBE12C7D7AC607ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x53AF3A5275A6DAC4ULL,
		0x09F90B3023AE2E88ULL,
		0x298ABB0AE851BDCCULL,
		0x62364886E6CC527DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1B133D7E4DE8F63CULL,
		0xFCACBF4C545FFBEEULL,
		0xEC6373FD7A327C17ULL,
		0x769598A596AE7389ULL
	}};
	printf("Test Case 164\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xDA23AC825B13E38FULL,
		0xF97DFA841A1026E6ULL,
		0x01C6B1B6EC8B0213ULL,
		0x780B04BAE665A17BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x19C2AAAB63B2DEEEULL,
		0xF8843B61F3121D70ULL,
		0x0620C9F3BDCD7491ULL,
		0x278FFE4D50479C9FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC06101D6F76104A1ULL,
		0x00F9BF2226FE0976ULL,
		0xFBA5E7C32EBD8D82ULL,
		0x507B066D961E04DBULL
	}};
	printf("Test Case 165\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xF6C3B2CA88F25B13ULL,
		0x9ADA50DC37C4A1BAULL,
		0x31BBC1E328FDBA37ULL,
		0x3553609C7BAFD1A4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1A167BFC7F1F8AF0ULL,
		0x9EBD73579C9708FCULL,
		0x0EEC0C5525862868ULL,
		0x4FDC3E6DA365022AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDCAD36CE09D2D010ULL,
		0xFC1CDD849B2D98BEULL,
		0x22CFB58E037791CEULL,
		0x6577222ED84ACF7AULL
	}};
	printf("Test Case 166\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xA16DDADF98B93CFAULL,
		0x7A88811B6F8A2F2EULL,
		0xD429600E3B532807ULL,
		0x6B773A1CA3A8E994ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x69CF78F310CA205AULL,
		0xA4E0295FA0A01AAAULL,
		0xCCA1058E45A5ADDCULL,
		0x6643560666F126F1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x379E61EC87EF1CA0ULL,
		0xD5A857BBCEEA1484ULL,
		0x07885A7FF5AD7A2AULL,
		0x0533E4163CB7C2A3ULL
	}};
	printf("Test Case 167\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x1DC32D53190AA37EULL,
		0x4E38C687AD2165D3ULL,
		0x43CC21E9415E2C0CULL,
		0x1C5295EF921DEC9AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x64B5C849B16B81A5ULL,
		0x57D0A295A70B1BB4ULL,
		0x6C5818F33E8453A3ULL,
		0x5A3B16050161D2FFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB90D6509679F21C6ULL,
		0xF66823F206164A1EULL,
		0xD77408F602D9D868ULL,
		0x42177FEA90BC199AULL
	}};
	printf("Test Case 168\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xDD138576AD50F9DFULL,
		0x7C69EB99DB4E5172ULL,
		0x68F646E404C32C0AULL,
		0x681458DF5CE658EEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1B4B44B58134A63BULL,
		0x16DDF82CA96D8D0DULL,
		0x8E56269204D82B78ULL,
		0x5871AB7F779718FCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC1C840C12C1C53A4ULL,
		0x658BF36D31E0C465ULL,
		0xDAA02051FFEB0092ULL,
		0x0FA2AD5FE54F3FF1ULL
	}};
	printf("Test Case 169\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x1179A66D6629BB16ULL,
		0xA0CECC3DE770833EULL,
		0x1E1C7EAAA0A9023FULL,
		0x039AA52331A644E5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x30012D0FB1068B22ULL,
		0xB601ADE98DFC1F51ULL,
		0x5469BDC48F55678CULL,
		0x2B4E827D1AB91DD1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE178795DB5232FE1ULL,
		0xEACD1E54597463ECULL,
		0xC9B2C0E611539AB2ULL,
		0x584C22A616ED2713ULL
	}};
	printf("Test Case 170\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x9CEF055D7DE6BAC1ULL,
		0xBDEC7E310B4A2426ULL,
		0xB545B0A7D31C7285ULL,
		0x435756B096DB4323ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDC5B0EC21DCFD477ULL,
		0xA0C9F2FD6B95779FULL,
		0x029AC32E537F7033ULL,
		0x5AB923CC9C37DA5BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC093F69B6016E637ULL,
		0x1D228B339FB4AC86ULL,
		0xB2AAED797F9D0252ULL,
		0x689E32E3FAA368C8ULL
	}};
	printf("Test Case 171\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xAF220AE4B10A0FF5ULL,
		0xB2134DB11CCF6830ULL,
		0x68FD1DBA31D1AE35ULL,
		0x529722470ACD060FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB1642BEC0768329DULL,
		0x77C4A745A70213EDULL,
		0x29A52F20FD2F750DULL,
		0x557ACBA13C2A77CAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFDBDDEF8A9A1DD45ULL,
		0x3A4EA66B75CD5442ULL,
		0x3F57EE9934A23928ULL,
		0x7D1C56A5CEA28E45ULL
	}};
	printf("Test Case 172\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x996D15F0F4107D3AULL,
		0x305D38240C5C7AC8ULL,
		0xF4401A62B3B836BBULL,
		0x0445E6DCE8A82E0FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x78B98A0991658A87ULL,
		0xCE2316ABD9740882ULL,
		0x7A591848A2856034ULL,
		0x27F889EF92070803ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x20B38BE762AAF2A0ULL,
		0x623A217832E87246ULL,
		0x79E7021A1132D686ULL,
		0x5C4D5CED56A1260CULL
	}};
	printf("Test Case 173\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xCA75C48073022FA0ULL,
		0x62CCB8785149EFEDULL,
		0x4D2080BD20EAEEE0ULL,
		0x5A10E15DC67B834BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEE561CB635FE9244ULL,
		0x14E9657A12F49DF4ULL,
		0xAB9B5B744294F18FULL,
		0x42FB544BA62EF3ABULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDC1FA7CA3D039D5CULL,
		0x4DE352FE3E5551F8ULL,
		0xA1852548DE55FD51ULL,
		0x17158D12204C8F9FULL
	}};
	printf("Test Case 174\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xE1A926333E7195BFULL,
		0x89491F12634F54E8ULL,
		0xB65E04AF51281598ULL,
		0x2C4E2B5E23D26DE9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA4843FD1A9230B2BULL,
		0x1975921C867D5592ULL,
		0x868932BB75B55BD7ULL,
		0x78C192A2A9C46900ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3D24E661954E8A81ULL,
		0x6FD38CF5DCD1FF56ULL,
		0x2FD4D1F3DB72B9C1ULL,
		0x338C98BB7A0E04E9ULL
	}};
	printf("Test Case 175\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xCEED3AF7A74D4661ULL,
		0xDD7706013EA5A65AULL,
		0xF6CD64F0F6CA1A92ULL,
		0x70BE2AE39774FD3AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8081F45ED766A0A5ULL,
		0x0E664D6B3966CA25ULL,
		0x1D8B4023F6DF61E8ULL,
		0x7679E84A45B31C3FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4E6B4698CFE6A5A9ULL,
		0xCF10B896053EDC35ULL,
		0xD94224CCFFEAB8AAULL,
		0x7A44429951C1E0FBULL
	}};
	printf("Test Case 176\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x8EC3A3787F3735A4ULL,
		0x082051683A866D63ULL,
		0x32F454D16F635686ULL,
		0x179D7741504F1EB2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x779EA63433139C0FULL,
		0xE7B3728C539087E6ULL,
		0xEBC17ABC6427F012ULL,
		0x58BCE5C18D3CBAF4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1724FD444C239982ULL,
		0x206CDEDBE6F5E57DULL,
		0x4732DA150B3B6673ULL,
		0x3EE0917FC31263BDULL
	}};
	printf("Test Case 177\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x487E6A2AE90358C0ULL,
		0x3B292F9846996356ULL,
		0x1ED55935F7C53F05ULL,
		0x4F3B60588C3B8982ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCA53083993E0DDC7ULL,
		0x947F6CD021903793ULL,
		0xA9C1CBFC26B07394ULL,
		0x16A1E3E659543B4CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7E2B61F155227AF9ULL,
		0xA6A9C2C825092BC2ULL,
		0x75138D39D114CB70ULL,
		0x38997C7232E74E35ULL
	}};
	printf("Test Case 178\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x1A1C663291187769ULL,
		0x74C764CCE621B1A3ULL,
		0x9E810B6264916A5DULL,
		0x4A810B86E42B726AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8BBBE3A4E58733BEULL,
		0x5DD6C890C3010F81ULL,
		0xC3EB3DB5E04FA9B1ULL,
		0x12AE5156071C13A8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8E60828DAB9143ABULL,
		0x16F09C3C2320A221ULL,
		0xDA95CDAC8441C0ACULL,
		0x37D2BA30DD0F5EC1ULL
	}};
	printf("Test Case 179\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x19CFF7B8E51C2F22ULL,
		0x4A909B684FDF39EBULL,
		0x2BB2A05E0AC175DFULL,
		0x40CB8D3D80F0AB56ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x843FCFA007A2914FULL,
		0x4117A170766F0DC3ULL,
		0xD5725F8707AFE1CBULL,
		0x1FDAD00A866960B3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x95902818DD799DD3ULL,
		0x0978F9F7D9702C27ULL,
		0x564040D703119414ULL,
		0x20F0BD32FA874AA2ULL
	}};
	printf("Test Case 180\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xFFEF13DA539A73B7ULL,
		0xA9C4B7C1F2EEA912ULL,
		0x916C3B7CDEA81D46ULL,
		0x663A20BDB218EBEBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x377884069AD897D7ULL,
		0x3F3D18A23FE25828ULL,
		0xC934F3546D5B7FAFULL,
		0x0861C6F63C788F41ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC8768FD3B8C1DBE0ULL,
		0x6A879F1FB30C50EAULL,
		0xC8374828714C9D97ULL,
		0x5DD859C775A05CA9ULL
	}};
	printf("Test Case 181\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x51AF968423B4F126ULL,
		0xBF63F8A43355113AULL,
		0x542B2330ADACC288ULL,
		0x4E2AB38F66D38AE2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE07AF951453D1C9FULL,
		0x28BD45C873A41302ULL,
		0xC989E52883C6E34AULL,
		0x484EA73270CC3F43ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x71349D32DE77D487ULL,
		0x96A6B2DBBFB0FE37ULL,
		0x8AA13E0829E5DF3EULL,
		0x05DC0C5CF6074B9EULL
	}};
	printf("Test Case 182\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x87A9B9854350107BULL,
		0xB4FBEC304195F9EAULL,
		0x445D29A71DB31E7FULL,
		0x0C4FB6B39536D107ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEF9E8890740613D4ULL,
		0xFBED720471800D89ULL,
		0x1E95988A0AA46D81ULL,
		0x21DED1A1EAC9003DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x980B30F4CF49FC94ULL,
		0xB90E7A2BD015EC60ULL,
		0x25C7911D130EB0FDULL,
		0x6A70E511AA6DD0CAULL
	}};
	printf("Test Case 183\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xABB142950C5E298FULL,
		0x539670D57E287645ULL,
		0xE2E10A910F0AA81DULL,
		0x6B1AF22F9188E781ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD41B901BA1BD27BCULL,
		0x7C3A241B89579A1CULL,
		0x5C4D7A43E0954563ULL,
		0x3B2639D7F7ED0314ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD795B2796AA101D3ULL,
		0xD75C4CB9F4D0DC28ULL,
		0x8693904D2E7562B9ULL,
		0x2FF4B857999BE46DULL
	}};
	printf("Test Case 184\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x6603F247CDB1CE9DULL,
		0xE15AD6F82A1AF6A6ULL,
		0x7BF843368F77390FULL,
		0x1B6557B21B852FB9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD6D13CB645D05693ULL,
		0x9D8A758DE1B3B302ULL,
		0x5089A6780DF0C14CULL,
		0x0D4EA6383A46D2D7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8F32B59187E1780AULL,
		0x43D0616A486743A3ULL,
		0x2B6E9CBE818677C3ULL,
		0x0E16B179E13E5CE2ULL
	}};
	printf("Test Case 185\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x4B1BB9D937016331ULL,
		0x370AFCDB73A924A3ULL,
		0x7337FE94BC3D0FEDULL,
		0x18C3D6F114ABD08DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE026999D752CDDBFULL,
		0xCD46BAE733175047ULL,
		0x35AE31633A02E7C4ULL,
		0x68432F88B3D56503ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6AF5203BC1D4855FULL,
		0x69C441F44091D45BULL,
		0x3D89CD31823A2828ULL,
		0x3080A76860D66B8AULL
	}};
	printf("Test Case 186\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x3E1E0D345BBB5CFCULL,
		0x7431212866CEEAE9ULL,
		0xF9D3FFC44832B446ULL,
		0x01D292E8A134983FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB1041F0A9B257247ULL,
		0xC306D90F097441C3ULL,
		0xE43C533EA047F176ULL,
		0x24C60FC9671E4138ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8D19EE29C095EAA2ULL,
		0xB12A48195D5AA925ULL,
		0x1597AC85A7EAC2CFULL,
		0x5D0C831F3A165707ULL
	}};
	printf("Test Case 187\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xDF3964CD3832396FULL,
		0xF3D9EB8B686CBC32ULL,
		0xD571BE33BF0FB8BAULL,
		0x2CC90C4489E8976DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x20B306AC3AA1E41CULL,
		0x04701EAA36A479CAULL,
		0x54C7E92E6AE40949ULL,
		0x5A2DBBE91EC0D8C2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBE865E20FD905540ULL,
		0xEF69CCE131C84268ULL,
		0x80A9D505542BAF71ULL,
		0x529B505B6B27BEABULL
	}};
	printf("Test Case 188\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x57254AFFEC64C268ULL,
		0xDDEC5A7259B8B1CFULL,
		0xDE8EE671D1D9D9A1ULL,
		0x12E09EF47D90B00EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB1CD1159A899706DULL,
		0x7A74C88B767B654EULL,
		0xFFC13A8B47180432ULL,
		0x0D70C10C0D613E7AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA55839A643CB51FBULL,
		0x637791E6E33D4C80ULL,
		0xDECDABE68AC1D56FULL,
		0x056FDDE8702F7193ULL
	}};
	printf("Test Case 189\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x19CA814141052C90ULL,
		0x06F63B7990EBA2E1ULL,
		0x7C18211D4FF55604ULL,
		0x10B6170C797C38A5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x72EC69DC4102B327ULL,
		0xFB58F954AC43A928ULL,
		0x3182600A0D19D1E6ULL,
		0x409E25335E348198ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA6DE176500027956ULL,
		0x0B9D4224E4A7F9B8ULL,
		0x4A95C11342DB841DULL,
		0x5017F1D91B47B70DULL
	}};
	printf("Test Case 190\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xDA7F37FAF297A6D5ULL,
		0xB9CBF3E941CD7726ULL,
		0xF9763D04EE9A3694ULL,
		0x1E5BEA694D1373DAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x83A4876437023402ULL,
		0xF4043A672E4AA643ULL,
		0x3AFC927A30206613ULL,
		0x478F0947F2309D2EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x56DAB096BB9572C0ULL,
		0xC5C7B9821382D0E3ULL,
		0xBE79AA8ABE79D080ULL,
		0x56CCE1215AE2D6ACULL
	}};
	printf("Test Case 191\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x56BA0183A7C2534AULL,
		0x3C559B517B7D503BULL,
		0x0B82B6A109E2A696ULL,
		0x1E2B2A30D2EE7980ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDA900B3545199FADULL,
		0x3E145D9B5E6593B1ULL,
		0x9777A0E7903602CAULL,
		0x5E709A1F6DB2FE9FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7C29F64E62A8B38AULL,
		0xFE413DB61D17BC89ULL,
		0x740B15B979ACA3CBULL,
		0x3FBA9011653B7AE0ULL
	}};
	printf("Test Case 192\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xC5B8B0D20A3CB613ULL,
		0xA08788174E00A2D4ULL,
		0x7739843718177691ULL,
		0x3E399F8CA711C670ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDEEF5E1E8B0D37D9ULL,
		0x56D486C4CB7EF21DULL,
		0x5D602C3B0563C1AFULL,
		0x469014E4672506CBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE6C952B37F2F7E27ULL,
		0x49B301528281B0B6ULL,
		0x19D957FC12B3B4E2ULL,
		0x77A98AA83FECBFA5ULL
	}};
	printf("Test Case 193\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x7F98951684F70B11ULL,
		0x387F32907FF2AB89ULL,
		0x2223E3B863C8AC56ULL,
		0x695B257A13F65FE2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x20B1BD1EEF89E012ULL,
		0x5A06382FD761A10AULL,
		0xB925C8D3167B32C3ULL,
		0x08DB9B4A59F84C98ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5EE6D7F7956D2AFFULL,
		0xDE78FA60A8910A7FULL,
		0x68FE1AE54D4D7992ULL,
		0x607F8A2FB9FE1349ULL
	}};
	printf("Test Case 194\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xD8BBE645872C43CBULL,
		0x369E14962CA095B0ULL,
		0xEB760A9178D32733ULL,
		0x0A339F98651AB537ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x343C1B2EB180A404ULL,
		0x3B3B3DACE2E60183ULL,
		0x8D0CD1B13673C91FULL,
		0x2B58734887692241ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA47FCB16D5AB9FB4ULL,
		0xFB62D6E949BA942DULL,
		0x5E6938E0425F5E13ULL,
		0x5EDB2C4FDDB192F6ULL
	}};
	printf("Test Case 195\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x8385FA75CE8A707FULL,
		0xF2C02C6B0D4D5CDFULL,
		0xD962764FE30EA8D1ULL,
		0x208A263210975A8EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB605538A71E23EB1ULL,
		0x063715D305AD69BBULL,
		0x6BE294486A391275ULL,
		0x134EB18C617D8C56ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCD80A6EB5CA831CEULL,
		0xEC891698079FF323ULL,
		0x6D7FE20778D5965CULL,
		0x0D3B74A5AF19CE38ULL
	}};
	printf("Test Case 196\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x6BDA9C8102BC01D7ULL,
		0x5E9DB692B08AE0C3ULL,
		0x416DE4476032C6BCULL,
		0x33F7016A8CAAEE33ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB0E62B77E048063FULL,
		0x4A9BC112501EBED2ULL,
		0xAD3CF10F01B8FD23ULL,
		0x51E4127053028CC8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBAF471092273FB85ULL,
		0x1401F580606C21F0ULL,
		0x9430F3385E79C999ULL,
		0x6212EEFA39A8616AULL
	}};
	printf("Test Case 197\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xE223648D65971991ULL,
		0x0C84382CE977EB3DULL,
		0x232AD18263C4ECCDULL,
		0x69BFAF75F8F51DCAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x45C44E9310F57BD2ULL,
		0x61644DABF91EECC8ULL,
		0xCAD17F33CDAB9A89ULL,
		0x2792DD1E6DE21E59ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9C5F15FA54A19DBFULL,
		0xAB1FEA80F058FE75ULL,
		0x5859524E96195243ULL,
		0x422CD2578B12FF70ULL
	}};
	printf("Test Case 198\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x7CC96994512D942BULL,
		0x1A7A94B311CFA8D9ULL,
		0x781A5E679CCBB1CCULL,
		0x0E6B4E4DDF748323ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC25FF2B99376EB1CULL,
		0x6954117A1887EF07ULL,
		0x3A75CD34B4F526DDULL,
		0x45A79A5E5CC211B2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBA6976DABDB6A8FCULL,
		0xB1268338F947B9D1ULL,
		0x3DA49132E7D68AEEULL,
		0x48C3B3EF82B27171ULL
	}};
	printf("Test Case 199\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xFBE986CB55CA86F5ULL,
		0x2CB1AB1BA41875CEULL,
		0x97B00620EC697C99ULL,
		0x43489F579CB37940ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8127D34E14C12B13ULL,
		0xF6B65CACE76B0386ULL,
		0x39A4891112B0DF75ULL,
		0x74BD8D8A3F0FD7A1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7AC1B37D41095BCFULL,
		0x35FB4E6EBCAD7248ULL,
		0x5E0B7D0FD9B89D23ULL,
		0x4E8B11CD5DA3A19FULL
	}};
	printf("Test Case 200\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 200 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -200;
	} else {
		printf("Test Case 200 PASSED\n");
	}
	printf("---\n\n");
	return 0;
}