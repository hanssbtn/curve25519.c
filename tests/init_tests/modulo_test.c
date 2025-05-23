#include "../tests.h"

int32_t curve25519_key_modulo_test(void) {
	printf("Modulo Test\n");
	curve25519_key_t k1 = {.key64 = {
		0x03FC293AA7A2C018ULL,
		0x4FBE60C2BC82DB4DULL,
		0xA3703D22AF4E7306ULL,
		0x73540796E06F51CAULL,
		0x713523C00F36764DULL,
		0x1EC28B8A35DDC231ULL,
		0x49AA458A5C5CD259ULL,
		0x492E4DFA11321AD8ULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0xD1DF77BCE9B85128ULL,
		0xE09F1746BB6DAEA3ULL,
		0x92B68FAC6515AC40ULL,
		0x50339AB56DDF4DE5ULL,
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
		curve25519_key_printf(&k1, COMPLETE);
		return -1;
	} else {
		printf("Test Case 1 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBDD101B7233EA128ULL,
		0x1400D9D4E52B8BB1ULL,
		0x5FB4DCEF6A9FA095ULL,
		0x01691C1C915089E3ULL,
		0x907F4017F5F71DDCULL,
		0x96DB2B0FC0BCDA9BULL,
		0x00E84B62016ABB84ULL,
		0x369FF74FAA6187EAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x30B48545A5ED1100ULL,
		0x78893E2B8133FEC9ULL,
		0x82300D7BA0777643ULL,
		0x1D27D1EFDBCAB69FULL,
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
		curve25519_key_printf(&k1, COMPLETE);
		return -2;
	} else {
		printf("Test Case 2 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA016EC0D00C968D4ULL,
		0xE2C05553F6DD5B3EULL,
		0x54B01BD3F8BDCEFFULL,
		0x6C003CDF4282A357ULL,
		0x59405E4ACADB95E2ULL,
		0xABE3EDE405B0B8D6ULL,
		0x9D28E30E78BEAB51ULL,
		0x0EBA33A5F2A3ADDAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDFA4EB271D61A8BFULL,
		0x6695A52CCF18CB0FULL,
		0xA8C1CFF9E50B3D1FULL,
		0x1BA3E78146CE71CAULL,
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
		curve25519_key_printf(&k1, COMPLETE);
		return -3;
	} else {
		printf("Test Case 3 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA3123AA6A6DEEDFBULL,
		0xA406BA2FFEEED7C4ULL,
		0x86F2FFEBDE67A35DULL,
		0xA84BC86BD2992980ULL,
		0x233380BC158A6527ULL,
		0xC31AE7CAD2D5ED9EULL,
		0x8112B79AE389B52EULL,
		0x3EA66632F51392B2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDCB75691D969F32EULL,
		0x9A05224B4AB01D3DULL,
		0xAFBA40E9A4D8884EULL,
		0x74FEF3FC3380EFFFULL,
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
		curve25519_key_printf(&k1, COMPLETE);
		return -4;
	} else {
		printf("Test Case 4 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x28CAE0EF25CBF776ULL,
		0xAD9256AED59F638EULL,
		0x9CADA1A4FDBB07D8ULL,
		0xBDF480CCDED112D3ULL,
		0x630EA84BF6BF3414ULL,
		0xEFDA3631DC7A18F3ULL,
		0x8867F09BE8B02A96ULL,
		0x1896BFFE476873B3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDCF7DC35C62DB306ULL,
		0x47F662158FBF17AEULL,
		0xDC1B58C987E15A40ULL,
		0x6455008B78523F79ULL,
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
		curve25519_key_printf(&k1, COMPLETE);
		return -5;
	} else {
		printf("Test Case 5 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x34F89DF593E0CAA9ULL,
		0xEE0A572C46E47680ULL,
		0xD1122645A3710580ULL,
		0xF79361236F8A9111ULL,
		0xD2664FED81684BD9ULL,
		0xCDB240BB7D7C0550ULL,
		0xC25B4358861C1FDBULL,
		0xEB3B4D69BB9AD673ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x70287B36C95C1224ULL,
		0x767FF300E74D407FULL,
		0xAA9E25698B9DC021ULL,
		0x6260DED548866640ULL,
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
		curve25519_key_printf(&k1, COMPLETE);
		return -6;
	} else {
		printf("Test Case 6 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x66A46EBC5FB91146ULL,
		0x796E0BB177B22B2AULL,
		0xB9DFD1346DEFE8ECULL,
		0x031D5FAE12F1E483ULL,
		0x59B04EC2DAC60732ULL,
		0xFCCB12C030BCAAFCULL,
		0x760CD4F41F47FC31ULL,
		0x5AF7E856F2E5D103ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB6D01FA8D91E24B3ULL,
		0xFF92D438B3B38C9FULL,
		0x3FC76D71129F5857ULL,
		0x03E9DC96210EEB07ULL,
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
		curve25519_key_printf(&k1, COMPLETE);
		return -7;
	} else {
		printf("Test Case 7 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x865E6EF62C9D81DAULL,
		0xD079EA8C7E9DF4C0ULL,
		0xDF10F40BE0A07F30ULL,
		0x5EBFED7196B93565ULL,
		0x85813F3B6B8D17FEULL,
		0x44CD148576C2BBDBULL,
		0xD100B9C93BCFF541ULL,
		0xDCFB00C3677321A1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x578DD1C8238F1674ULL,
		0x06EAF65C1F85D756ULL,
		0xE52C87EAC17EE6E1ULL,
		0x2C020A72F1D0336AULL,
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
		curve25519_key_printf(&k1, COMPLETE);
		return -8;
	} else {
		printf("Test Case 8 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x78D901F505575876ULL,
		0x70ED1806C628D2E3ULL,
		0x47432A0E91018A0FULL,
		0xF079749E8114A68FULL,
		0x730704E9D0A00CA2ULL,
		0x71BC5236DDDF306BULL,
		0xF8DF861DA5015BFDULL,
		0xFD75FE9049794CC3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8BE3BCA9FD193E39ULL,
		0x52E14C2BB54A02D6ULL,
		0x387112750F3531AEULL,
		0x0FFD3E0969160BA6ULL,
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
		curve25519_key_printf(&k1, COMPLETE);
		return -9;
	} else {
		printf("Test Case 9 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC7E57F865A0400F9ULL,
		0x5EB552AE462A54C0ULL,
		0x41974810194C7FD4ULL,
		0xC7FBC59F01841A5EULL,
		0x1D29763A7983D02BULL,
		0x9D5671A3FED5DC3EULL,
		0xC512246B0B2D5832ULL,
		0x7A5C35780E215F5BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1C0D0C346394EA1AULL,
		0xB98A310619E905F9ULL,
		0x8248AFF3C2079757ULL,
		0x71ABB5711A7841FDULL,
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
		curve25519_key_printf(&k1, COMPLETE);
		return -10;
	} else {
		printf("Test Case 10 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2EF4B5320EF1252EULL,
		0x622376D50E185555ULL,
		0xC218EC889C5AF461ULL,
		0x8F515E29C1F46399ULL,
		0x1C166E1E3CB04962ULL,
		0x92044E38EA0EFE63ULL,
		0x9DA5F8F67C8666CEULL,
		0xDD9F4F4614C0C2CBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5A490DAF111C0EA0ULL,
		0x0EC71347CC52180BULL,
		0x28BBE11F184E370BULL,
		0x74F72290D6914DD3ULL,
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
		curve25519_key_printf(&k1, COMPLETE);
		return -11;
	} else {
		printf("Test Case 11 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAEBC1AF688AA5E09ULL,
		0x79DBB68EFBDA5C1DULL,
		0x60C7B5B9A4B640A9ULL,
		0x473AB7167B612124ULL,
		0x1E6F7E8719E9C319ULL,
		0xEAC89EDB73D2FD94ULL,
		0x4E6F7CA796F898E0ULL,
		0x833CC407DB8E0080ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3348E304615D56A4ULL,
		0x53A34B222D2C001AULL,
		0x0554369A0D9CF20CULL,
		0x423FD04112753430ULL,
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
		curve25519_key_printf(&k1, COMPLETE);
		return -12;
	} else {
		printf("Test Case 12 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE52E713B5F61395CULL,
		0x6ECBB59C88A115BFULL,
		0x0D759AB631CE6AABULL,
		0xEA27F7D69A7F901AULL,
		0xC638928AEAA80CC6ULL,
		0x9CEDE70A492FD5D3ULL,
		0xFA0B83197D370A6FULL,
		0xF32BFA6E7EBC9863ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x519431DA3453243EULL,
		0xBA1C012365BAD32FULL,
		0x2B2B107EC7F9F73CULL,
		0x02AF243D6A7E2EF1ULL,
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
		curve25519_key_printf(&k1, COMPLETE);
		return -13;
	} else {
		printf("Test Case 13 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB0282207723EE2EEULL,
		0x4FD06806B4462FA7ULL,
		0x18F89E1D421E346BULL,
		0x1F7DE0C8EC96ABA4ULL,
		0x4CD05A45C7196167ULL,
		0xCABE16AE5E9467F5ULL,
		0x7243FBCBC78EB340ULL,
		0x4646678CDCCA145FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x17158863000359C7ULL,
		0x6807C5E8BE4D9E11ULL,
		0x0F0FFE5CE14CD009ULL,
		0x0DF13FB1B295B1CFULL,
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
		curve25519_key_printf(&k1, COMPLETE);
		return -14;
	} else {
		printf("Test Case 14 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA0DE4E56A7FD2C78ULL,
		0x4A3C9A0D35998664ULL,
		0xB5B36F2B883E47F1ULL,
		0xABCD8C41FE176B8AULL,
		0x6FEEDA11E99D9833ULL,
		0xEE2B310ACA879F1AULL,
		0x0AC34ABAC5E33B20ULL,
		0x6F867F0C6FC3E4DBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3E52ACFF5561C690ULL,
		0xA4A5E1A745BB2451ULL,
		0x4EB086E4E7F90ED4ULL,
		0x39C4681A952B640EULL,
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
		curve25519_key_printf(&k1, COMPLETE);
		return -15;
	} else {
		printf("Test Case 15 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4EEE5B952F3A4B78ULL,
		0x4DD3656586B6474BULL,
		0xB787083987B60547ULL,
		0x8FD691F458B66BCCULL,
		0xD3F7B6586D056358ULL,
		0x24564F43152536B1ULL,
		0x069DCCCAC90526C1ULL,
		0x03A01AEBF431C3D6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC5B36CB55E070AAEULL,
		0xB2A3295AAA3C65B0ULL,
		0xB2F36E535E79C5F2ULL,
		0x199A90FA98197D91ULL,
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
		curve25519_key_printf(&k1, COMPLETE);
		return -16;
	} else {
		printf("Test Case 16 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1E9E35CCE35A7FFFULL,
		0x0F7B230260BCE436ULL,
		0x381BC8A9F49D4331ULL,
		0x4FB842A952D5DBD0ULL,
		0x6055D34FE82B433EULL,
		0x7028CE735AE95DC8ULL,
		0xCEFA9EBF78FD1BDAULL,
		0xB4AC600EB3252B71ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6B5B93A959C67F35ULL,
		0xB589C821DF60CFF4ULL,
		0xF14F5915EA2F659DULL,
		0x214E84D7EA5A4EB4ULL,
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
		curve25519_key_printf(&k1, COMPLETE);
		return -17;
	} else {
		printf("Test Case 17 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBD55782A2FAFBDC2ULL,
		0x09ECABA3299CDDC5ULL,
		0xB75458E63432509DULL,
		0x723DFAE6524BA742ULL,
		0xCB7A91D0D9D92D20ULL,
		0xAA9904D95911BF9DULL,
		0x628DA9DE065BB1FBULL,
		0x2DB6F16657345750ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF1871D2A85EC718CULL,
		0x5CA363E6623F4F31ULL,
		0x585B8FDB25CEBBF8ULL,
		0x3B65D01744109D31ULL,
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
		curve25519_key_printf(&k1, COMPLETE);
		return -18;
	} else {
		printf("Test Case 18 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x37676C55F8BF1C77ULL,
		0x64B12472F5593A93ULL,
		0x711E7CC0839883C2ULL,
		0x337E0573A38373EEULL,
		0x741B491BF9E52E4AULL,
		0x910972BFDA728754ULL,
		0x2816F5C9DE4942EEULL,
		0x67C3B5A15EBA092DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7374467D10C3FDC0ULL,
		0xEC182CED6259511CULL,
		0x6486F8B78278732BULL,
		0x1A8AFB67B320D0A2ULL,
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
		curve25519_key_printf(&k1, COMPLETE);
		return -19;
	} else {
		printf("Test Case 19 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x74A987C9328E77F2ULL,
		0x499C0E15FB15117DULL,
		0x17AA453B1FE86257ULL,
		0xB3B67CF050CD47AAULL,
		0x7F3C8C369F8C4548ULL,
		0x40EB7B099C140B3FULL,
		0x0964A387CFDBC9CBULL,
		0x0E9F37931C0A2A18ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x57A657E4E160C101ULL,
		0xEC905183260EBCEAULL,
		0x7C9A8B63FA885682ULL,
		0x5F58BCC67A4F873BULL,
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
		curve25519_key_printf(&k1, COMPLETE);
		return -20;
	} else {
		printf("Test Case 20 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2B837FE161136AE8ULL,
		0x5C1531C9DFE297B9ULL,
		0xA0CF9BBA663C01B9ULL,
		0x10EB3199487F1E75ULL,
		0x744AA12BFC458751ULL,
		0x8898D4340DFE2B53ULL,
		0x07E6207D022EE380ULL,
		0xD89D4CF3521B7E84ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6E976C68D36585AEULL,
		0xA2C4B183F39D061CULL,
		0xCCF86E48B931C6CDULL,
		0x38449DB77893E60EULL,
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
		curve25519_key_printf(&k1, COMPLETE);
		return -21;
	} else {
		printf("Test Case 21 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE5E31525B82F722AULL,
		0x1BA975B0EA3FD744ULL,
		0xE9C43D06E2804828ULL,
		0x9A66D60C4251BD1CULL,
		0x78DC6363045362A8ULL,
		0x28F5950D150E341CULL,
		0x52ED19884DFC68ADULL,
		0xC8D96FCE7B51CA41ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD699D5D85C901B8EULL,
		0x301D95A20A5B937EULL,
		0x38F6074275F7D1DCULL,
		0x6AAD6EB29075C2CFULL,
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
		curve25519_key_printf(&k1, COMPLETE);
		return -22;
	} else {
		printf("Test Case 22 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8FDD9632E95F4C64ULL,
		0x1FC26975BC7CA047ULL,
		0x88256AC1A3A897C2ULL,
		0xF73B4B1680FDF9B6ULL,
		0x0D98255F353493EAULL,
		0x042978ACE6FDC0F1ULL,
		0xC33DF69F3AB6D735ULL,
		0xD30A448A79AFACAFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x94732254CF2D45E0ULL,
		0xBDEA53200627440FULL,
		0x835806645ACC89A0ULL,
		0x4AC177A491119BCDULL,
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
		curve25519_key_printf(&k1, COMPLETE);
		return -23;
	} else {
		printf("Test Case 23 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4FFC4EB007920CF9ULL,
		0xE759DD1378CA519BULL,
		0xCA8903F3FC92AFDFULL,
		0xD4576559F86790F8ULL,
		0x25CF894F07B6E94BULL,
		0x3E05F190BDFE6D41ULL,
		0xDD9093F9EC6BE206ULL,
		0xE5079685A61FDB5BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xECCAB06B2CB8B33AULL,
		0x1C3BB88FAC8E8946ULL,
		0xADFEFB0D14963CCDULL,
		0x5377BD30A122209BULL,
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
		curve25519_key_printf(&k1, COMPLETE);
		return -24;
	} else {
		printf("Test Case 24 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5A03322B176700C0ULL,
		0x952FFFF1A47CF69BULL,
		0xCBC87A03C5405BE7ULL,
		0x56779D893FBC2008ULL,
		0x8C426F195AFBC2B5ULL,
		0x9919089FCBF808CBULL,
		0xDABA385241E89C96ULL,
		0x232114BBC7CFF463ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2BDFAFEE98C5E86FULL,
		0x4EE747A9EB4E44D2ULL,
		0x436CD6398DC79A42ULL,
		0x0D60B168E89A66DBULL,
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
		curve25519_key_printf(&k1, COMPLETE);
		return -25;
	} else {
		printf("Test Case 25 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA63C03CB16335619ULL,
		0xD8973D3B0AD14923ULL,
		0x0771D63E4C785692ULL,
		0x1A24555DC1B57558ULL,
		0x8F037CA84A5EDEBCULL,
		0xA9E46F4C1CFFAFE8ULL,
		0x01B47287487B164FULL,
		0xA5CA2677C66CA01CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE0C084C6204869A4ULL,
		0x107FC28758C565A8ULL,
		0x483AD6530EBDA666ULL,
		0x36260B2535D53980ULL,
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
		curve25519_key_printf(&k1, COMPLETE);
		return -26;
	} else {
		printf("Test Case 26 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x48B981DA3D37E770ULL,
		0xF5E403AC3EB1C354ULL,
		0x91E5F219B6AD72A5ULL,
		0x5DC875DA3466C64EULL,
		0xDB394A27A6964686ULL,
		0x70C8EE155F66D36DULL,
		0x0C15ED86A309F5C7ULL,
		0x6F917B8CF1A825F6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD33A83BCF78661C7ULL,
		0xB3B75AD867F525A2ULL,
		0x5D273415EA27EE40ULL,
		0x6D60CCC6135C68D4ULL,
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
		curve25519_key_printf(&k1, COMPLETE);
		return -27;
	} else {
		printf("Test Case 27 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE2912D137698E7B0ULL,
		0xB9EE98A8A050EEBDULL,
		0x53B3DC14A9087105ULL,
		0x782625689FF9D1ACULL,
		0xAC9846F5D830C17DULL,
		0x275D35F83C5BF90FULL,
		0x3F577C2D841BD5B4ULL,
		0xAC1620534961DD9BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x812BB5918DD5A41AULL,
		0x91C49B8195F7E711ULL,
		0xBAB04AD6452A29C3ULL,
		0x036EF1C58480B6B7ULL,
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
		curve25519_key_printf(&k1, COMPLETE);
		return -28;
	} else {
		printf("Test Case 28 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9709764258C0CDC8ULL,
		0xA57AF6DA1A5B402DULL,
		0xE5DC6AF5B735A9F4ULL,
		0x9CBBDA95F488F165ULL,
		0xE5602FEE2799BEB1ULL,
		0xE8C45B4010B7AA55ULL,
		0x668F673C0C06C386ULL,
		0xC9A7326DF48822E8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA350939C39932095ULL,
		0x32A0825C959E88EDULL,
		0x1F25BDDF8036AFFBULL,
		0x0B8D56E840BE1FE5ULL,
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
		curve25519_key_printf(&k1, COMPLETE);
		return -29;
	} else {
		printf("Test Case 29 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2B52E1603007CBC4ULL,
		0x6C24B1B725D35302ULL,
		0x84BFB6164F992908ULL,
		0x0680B4AB65B65ADDULL,
		0xBF95EE5C3D2B49CAULL,
		0xEB0E182B0A9D49D7ULL,
		0x80BD615EBE243351ULL,
		0xF5563132AE17C754ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9B9443114474C518ULL,
		0x503C481AB92C4908ULL,
		0xA0DC2A2688F8C731ULL,
		0x714C02313D3DF168ULL,
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
		curve25519_key_printf(&k1, COMPLETE);
		return -30;
	} else {
		printf("Test Case 30 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB4CAEC772DC51D06ULL,
		0x247DB87CFC84CE4BULL,
		0x5E1EA549C4E465CAULL,
		0xA031905454C5E561ULL,
		0xF0022E3D2600EAEBULL,
		0x168E4C3A9746DDB3ULL,
		0x38EB16B0907D61DDULL,
		0xFFE4594D546A3ACBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x551DC98AD1E8019FULL,
		0x7D9D092F7109B701ULL,
		0xD104037F3780EC9BULL,
		0x1C16D1CEDC8A9F8BULL,
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
		curve25519_key_printf(&k1, COMPLETE);
		return -31;
	} else {
		printf("Test Case 31 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x78A132F99FCFAA31ULL,
		0xA4E666283F7E1A9EULL,
		0xFC1CB5A820D08D56ULL,
		0xAFF8E504C72B2E51ULL,
		0x512BAA068D7FEAC5ULL,
		0xDCCC7619B01164BDULL,
		0x4B415A6F360705AFULL,
		0x8C285F46E5343F7AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x851C6FF2A0CC868DULL,
		0x6B3FEDF862130EB8ULL,
		0x27D0222A25DB6571ULL,
		0x7DF7098ACCEC9A79ULL,
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
		curve25519_key_printf(&k1, COMPLETE);
		return -32;
	} else {
		printf("Test Case 32 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x228D9B74179832CFULL,
		0x8FA3A0B1FDB8F3C7ULL,
		0xDEF08552E0CEEB44ULL,
		0x58BB514F71B692EBULL,
		0x9DE30E58BB40F28AULL,
		0x7C8E49BC9557099DULL,
		0xA33272A030D1B7CDULL,
		0xBAF21ACBA2F37A92ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9241BC9FE33C3773ULL,
		0x0CC292B028A4612CULL,
		0x186D891A1FF033C5ULL,
		0x18AB4B89A1DAC4B0ULL,
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
		curve25519_key_printf(&k1, COMPLETE);
		return -33;
	} else {
		printf("Test Case 33 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDE5C1890A9C4BDC6ULL,
		0x8B5E1663E63CAEEAULL,
		0x939E675B415132C3ULL,
		0x550FF57CA185F2EAULL,
		0x05F1FDD94C04BF62ULL,
		0x65E02FD65CC087E8ULL,
		0xDA6AF284FCCF217EULL,
		0x7629E298EA488B1CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC047C6D1F27928EBULL,
		0xAAA53035AAD0DB5BULL,
		0xFF7E6718C8102B86ULL,
		0x5F47982F684A9932ULL,
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
		curve25519_key_printf(&k1, COMPLETE);
		return -34;
	} else {
		printf("Test Case 34 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7EF90A844AED5737ULL,
		0xF6D898B1B2DFC385ULL,
		0xA8DB848C9ADF5BE3ULL,
		0x4476F2112AE61C1CULL,
		0xA1EB8C3BF347B634ULL,
		0xDD1853201B10B106ULL,
		0xF0446AE5A9E4ACCAULL,
		0xD53AF44F9E658E6BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x87EFDB6A6792679CULL,
		0xC874EF75B75A0A81ULL,
		0x530362A3D2D10200ULL,
		0x6B3735E2ADF94022ULL,
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
		curve25519_key_printf(&k1, COMPLETE);
		return -35;
	} else {
		printf("Test Case 35 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0CE0B8BA8B04D5E1ULL,
		0x20037E5ACDD1FF6AULL,
		0xA1DE9CB76E722BF4ULL,
		0x8B91C26935899AF1ULL,
		0xF2931504B80496F0ULL,
		0xF19EB1C5B8FD61D6ULL,
		0x7597EF845650CCEEULL,
		0x8E7CC7B7A9127B4EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0EB5D76DDBB340B2ULL,
		0xFD91E1B4436E8552ULL,
		0x166C2A5C3E70976BULL,
		0x321767AC4E47E897ULL,
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
		curve25519_key_printf(&k1, COMPLETE);
		return -36;
	} else {
		printf("Test Case 36 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1CE34079AABFABB1ULL,
		0x4706BF7B921C87FAULL,
		0x5F8EE3CD3F40DA2CULL,
		0x164FD829D2059BB4ULL,
		0xC29BED833EB980ADULL,
		0xF7DCF4BA42403DAFULL,
		0x6B7D537F36ADC7CEULL,
		0xC4E370003B5D407BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x000881F4FA48C9ADULL,
		0x11D3132167A5B011ULL,
		0x542948AF5D0C82E5ULL,
		0x50127832A1DD2E06ULL,
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
		curve25519_key_printf(&k1, COMPLETE);
		return -37;
	} else {
		printf("Test Case 37 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA79717DD6591FA24ULL,
		0x1CA9FF5574DC8939ULL,
		0xA377FB6ED286F55FULL,
		0x2BD1AE5EEFDB22E0ULL,
		0xC5FD63CE00CF0AACULL,
		0x21B355C533207C34ULL,
		0xF7D5501397A63EABULL,
		0x6F091250E41A35EFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0B33E871844D921FULL,
		0x1D48BA9B0BAEF90FULL,
		0x6D21DE57553442C6ULL,
		0x272A6660CBBF247FULL,
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
		curve25519_key_printf(&k1, COMPLETE);
		return -38;
	} else {
		printf("Test Case 38 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5B22CEB111A981FDULL,
		0x28C6B33F1A40CB87ULL,
		0xE67A65EB7957E506ULL,
		0x052FC0DC70A31343ULL,
		0xDF35A76777E206A0ULL,
		0x2160C6FBDCE38978ULL,
		0xCEB2B0E1F2227FF3ULL,
		0x73BF98FBC109B5D6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7D19A80CDD368043ULL,
		0x1D243CA1E4073378ULL,
		0x9500A7756A76E31DULL,
		0x33A0763B18141126ULL,
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
		curve25519_key_printf(&k1, COMPLETE);
		return -39;
	} else {
		printf("Test Case 39 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB6B87E01BD676407ULL,
		0x9B234C7700E899D6ULL,
		0x8A5889A91CF95A05ULL,
		0x1EDCCDB2E1F09B4AULL,
		0xB128DF5CBA57F2B8ULL,
		0xF096166085AB3823ULL,
		0xC1D9B2EB3BE1D729ULL,
		0x53B8C8C5535AE732ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x02C9A5C566756D32ULL,
		0x516A9ECAD852EF23ULL,
		0x50A91894007F4A3FULL,
		0x0C4A9AFD416EECD3ULL,
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
		curve25519_key_printf(&k1, COMPLETE);
		return -40;
	} else {
		printf("Test Case 40 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x253D5D759A3ED3C4ULL,
		0xFA01D26DE6CD6DDCULL,
		0x1F5ED0346D8E78DFULL,
		0xF9612C0FEC139A72ULL,
		0xDA37A58029DDBB5AULL,
		0x7A6B8C9FD40BDCB6ULL,
		0x7B305041F7533091ULL,
		0xCC99B69928053D52ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x897FEE7BD128A7BAULL,
		0x25F8B22760903100ULL,
		0x688AB9FF23E7AE78ULL,
		0x583246CBDCDAB4B0ULL,
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
		curve25519_key_printf(&k1, COMPLETE);
		return -41;
	} else {
		printf("Test Case 41 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6A6165490CAE8FACULL,
		0xB355CFE2298B043BULL,
		0x33D4CE672A39D0CFULL,
		0x06570931F88BCEDEULL,
		0xE37FFED03D45E724ULL,
		0x4082E06EB4FD6599ULL,
		0x2BEE68DBBC3531FCULL,
		0x23525A09974FF470ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2F613832250EDFC2ULL,
		0x46C3205107281913ULL,
		0xB9385F051A1F3C41ULL,
		0x4490669E6E6A1784ULL,
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
		curve25519_key_printf(&k1, COMPLETE);
		return -42;
	} else {
		printf("Test Case 42 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0B6651AC66167BCCULL,
		0x3C622F82DEFC3CFEULL,
		0x2ECB5F536300C4E2ULL,
		0x55E6456B32FB1E46ULL,
		0x821FBDDC07745F2EULL,
		0xA8462AA0888FF51EULL,
		0x9BE922F9A6A3D438ULL,
		0x97581B5326F6CD88ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5C1C8055815C9FF7ULL,
		0x36CC8357245A9F85ULL,
		0x536690621F52454BULL,
		0x4CFA53C2FB9DA08DULL,
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
		curve25519_key_printf(&k1, COMPLETE);
		return -43;
	} else {
		printf("Test Case 43 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD0F798C32275162CULL,
		0x132572D7BD846100ULL,
		0xF8EA8F3F334D25E0ULL,
		0xBDB708D79ED09692ULL,
		0xEF2036CE173F3FFBULL,
		0xE4988E321A8EE48BULL,
		0xAC21690C2C6E0363ULL,
		0x0A6D8862AC14D489ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4FBFBB5A95D895BAULL,
		0x01CA8E47AEBA4DC6ULL,
		0x85E0270DCBA1A6B4ULL,
		0x49F9477D29E82302ULL,
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
		curve25519_key_printf(&k1, COMPLETE);
		return -44;
	} else {
		printf("Test Case 44 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA5619A55291EC6DAULL,
		0x8A7AF7478EB8301EULL,
		0x2E18761CE044055DULL,
		0xBF2A0E38EAD0E13DULL,
		0x01B709B395BAF71AULL,
		0x18963A29E615EDF6ULL,
		0xBB8B7AC360C6C26BULL,
		0x100E3FDC4DEAA8F0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE68D0AFD62DF7528ULL,
		0x30C7997FB5F982A2ULL,
		0x04CCAF1D3DC4E143ULL,
		0x214788EC7BA5F4F9ULL,
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
		curve25519_key_printf(&k1, COMPLETE);
		return -45;
	} else {
		printf("Test Case 45 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x83DDF08C082B9103ULL,
		0x287AEE9EEDA32FA9ULL,
		0x3F63C746BA335875ULL,
		0x9CC42F1BDE62AF7DULL,
		0x4A314ABE54A79A51ULL,
		0x4CC98A1148F4E3F7ULL,
		0x4EB214015042B327ULL,
		0x41D9152F2065AE86ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x872F08CC990C7A85ULL,
		0x8E656D2FC1FD065EULL,
		0xEDD2BF78A419F04AULL,
		0x62FD541AAD7A976CULL,
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
		curve25519_key_printf(&k1, COMPLETE);
		return -46;
	} else {
		printf("Test Case 46 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEE11B1C05A7BD498ULL,
		0xD0D46490C9C550BDULL,
		0x2F845FED2454AAE5ULL,
		0x30173CBC6333537AULL,
		0xDD2FD238506E1D18ULL,
		0x24FE91751DA8AF50ULL,
		0x8EE67B46FBF6C410ULL,
		0x682FB0EA4DC15618ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC32AE61C4AD42875ULL,
		0x4E9DFBF330CF56BEULL,
		0x65BAAC768AF5C54BULL,
		0x272B7F83EDE61B1FULL,
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
		curve25519_key_printf(&k1, COMPLETE);
		return -47;
	} else {
		printf("Test Case 47 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCA58BC05323489C0ULL,
		0xE537481DD491AE0DULL,
		0xC07101D5A3953AC4ULL,
		0x7773038E5ADF730AULL,
		0xC570F810510806A3ULL,
		0x95B13D11F4D7CE66ULL,
		0x6E432146A67401ADULL,
		0xDBC13F815DDC4536ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x191D8E7139658AD8ULL,
		0x1D8658C82C9A514FULL,
		0x1E67F25258CD7A89ULL,
		0x162270C24991B91FULL,
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
		curve25519_key_printf(&k1, COMPLETE);
		return -48;
	} else {
		printf("Test Case 48 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x328DCF088A48A93AULL,
		0xBA38160196A4CDB3ULL,
		0x3142C3BD00B5846DULL,
		0xFEFC950E57857296ULL,
		0x174B773BD2537E96ULL,
		0x8570CFCC9538D0B9ULL,
		0xAFE9F3D89C2C3554ULL,
		0xE4E0084281550804ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA7C181E9C2AD789DULL,
		0x88F6EE5FBD13C92CULL,
		0x4DFCF5E42F456EF9ULL,
		0x783DCEED8A24A348ULL,
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
		curve25519_key_printf(&k1, COMPLETE);
		return -49;
	} else {
		printf("Test Case 49 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9715B39E6C75136EULL,
		0xA9CCC928F2AC7FC4ULL,
		0x500A88EE4308118EULL,
		0x697B1891D194A181ULL,
		0x3791154E1013E089ULL,
		0x5D2B1FC5F13A3096ULL,
		0xB15E89CA67894F04ULL,
		0x4DCFDCD845D30886ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD69EDD34CF686979ULL,
		0x7E33808AC14FB610ULL,
		0xA412FCF9A169CC34ULL,
		0x7655E0AC2EE7E57FULL,
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
		curve25519_key_printf(&k1, COMPLETE);
		return -50;
	} else {
		printf("Test Case 50 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3B98A3103A4A45D6ULL,
		0xD04FE0CF8E90FAB9ULL,
		0xB704B90BFF851B2DULL,
		0x9BDC697A0F981F79ULL,
		0x77CB4F3EBF2E226BULL,
		0xC3A2B4C4321BBB48ULL,
		0x16C8DE358A330537ULL,
		0x2EB1A2C20ADD5CD7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x03C666609B2362D5ULL,
		0xDA76B5EEFEAEC77BULL,
		0x18D5B4FE8317E174ULL,
		0x0A3A9247AC73E767ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 51\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x0368907D3DE3ABA9ULL,
		0x69D2FE58AF6DB474ULL,
		0xCAF5A9F888678814ULL,
		0x64D3DAFC16556E85ULL,
		0x11574FC6EA42F9A1ULL,
		0x5F9CDF6962837052ULL,
		0x0CF0946FBCA132DDULL,
		0x38135236A2306A3EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x965E680403D4BAD2ULL,
		0x9B1C27FD4EF060A2ULL,
		0xB6ABB28E885514F0ULL,
		0x37B20F18298533BBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 52\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xBFC40FC3E9DA71D6ULL,
		0xDA884D0A01189DE4ULL,
		0xBF8BAAF5BEBB464FULL,
		0x98E37D7BCE151CC0ULL,
		0xCEF510FE578BC426ULL,
		0x41E542B0557F33C1ULL,
		0x8317F67301F017BBULL,
		0xB8227B390EC6D35CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x78249584E899938FULL,
		0xA2903336B1FA4CA9ULL,
		0x351A4008085ECC1BULL,
		0x6E01C7F3FF987C7CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 53\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x0630D450DF5DBFEAULL,
		0xE50AE82A80FBC0EBULL,
		0x93B5E38F4E3F058AULL,
		0xED12A255C199A500ULL,
		0xC3E2DC9AC5678213ULL,
		0x46285C8B3E7360D9ULL,
		0xA0377358B0937BB7ULL,
		0x140E0440C5E4300AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x19DD934A2CBB0F41ULL,
		0x4F08A4D5C61C213EULL,
		0x5BF102B9842362BFULL,
		0x672743F32178C694ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 54\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xA97F06012775A6D7ULL,
		0xFD8225B73DDD4C14ULL,
		0x14B3E2BA76DD7A28ULL,
		0x0202FB70A25ABD3BULL,
		0x6A228B4B0FB3C954ULL,
		0x60F8D61ADE08C637ULL,
		0x2A5528CC605214EFULL,
		0x637E5E4EBCE190FCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6A9FB3257C258B76ULL,
		0x6271EDB4332AB84EULL,
		0x5D57F110C30C95B1ULL,
		0x46C4FB20ABD642A9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 55\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x83754DC28C30993DULL,
		0x9228C7CF0A992277ULL,
		0x145D40F5B3BDB9A9ULL,
		0x9D24D9DB16576A88ULL,
		0x3AA9076F6888699DULL,
		0xD685D32FD9F8BEEFULL,
		0x27CC7BC0812F05CDULL,
		0x9BCD1E1F6ED7A429ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x388C684C10704A08ULL,
		0x6A0620E9658579FAULL,
		0xFCB79F88E0B89637ULL,
		0x3D9752858A59C8A3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 56\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x9E5E202C5F09A39DULL,
		0xE32EE543FC259871ULL,
		0x914D82FA7B881BCEULL,
		0xB0A32821EBCB0455ULL,
		0xD6E272A50E08922DULL,
		0xD7E88A7F86F5DB50ULL,
		0xA528DA796DFBF692ULL,
		0x1E787F2265774429ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x83FB24AC744F5709ULL,
		0xEFB3743204A42671ULL,
		0x155DF100CEEEB59AULL,
		0x3686073CFB7F2284ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 57\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x8CE4E0E778F3CBF9ULL,
		0x0F9005C77FD03F17ULL,
		0xE4094E2DE789A49FULL,
		0x18EB8BD055B6DBECULL,
		0xD479ACDCAFF5C0FFULL,
		0x63911027FC0EAE87ULL,
		0x1EAE3F4B18A005C8ULL,
		0x43AF517BFE58BFA3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x16F489A9976E734FULL,
		0xD7186BB6E9FE2741ULL,
		0x71E6B3538F4A805DULL,
		0x24F1A43816E34E23ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 58\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xECA03F7837A04F14ULL,
		0x214C6A11587A5B17ULL,
		0x2A7D21EAA600AEA5ULL,
		0x67F21D25FDB332B2ULL,
		0x930B309FE98A5244ULL,
		0xC467E67ACE061E63ULL,
		0x3A415DA7A7580567ULL,
		0xA371B7991254AF83ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC0497734E22888CFULL,
		0x48B8A04BED62DDDFULL,
		0xD03108CD7D117C0CULL,
		0x2AD35DDEB645402CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 59\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x32A3D742EA55613DULL,
		0x81E567A2D0AA78DAULL,
		0x945EAF63C1ADACDDULL,
		0xD63B8F57B070CFC4ULL,
		0x8516A4B6E3675752ULL,
		0x91CF6F0746FC661CULL,
		0x84B4B02FE47310ECULL,
		0x1EDF26D0E6A028E1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF4004A68ABAC5827ULL,
		0x26AFE2B75A21A115ULL,
		0x4730D67FAAC22FFBULL,
		0x6B5B5259EC36E13EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 60\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x4837C7FE104B7598ULL,
		0x5E8418AAFF51D7A0ULL,
		0x7A681FDBA3AEDCD4ULL,
		0x1FD878D8FAEDC65DULL,
		0xF5FECEEF35FD32D9ULL,
		0xBA69BBB9964396B1ULL,
		0x4E8281D97890C447ULL,
		0x869D4C93462B8E75ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCC0A7F8013E104C6ULL,
		0x0A35F6374D5A360AULL,
		0x21C76623892BFF7AULL,
		0x1B31D6B56564EBC7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 61\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xEAD96C72D29E32B3ULL,
		0xF7557A457E75837EULL,
		0xA5FD1ED2C3602A2FULL,
		0x13DB850DE7991293ULL,
		0x0CD2CBAEF33EE713ULL,
		0x69DD005ADE04FC80ULL,
		0x6306D6B9F9D20010ULL,
		0xC72A7A34EDAC0B32ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD223A86AEDF483E6ULL,
		0xAE2387C27332FE80ULL,
		0x5900FE6DD88C2C9FULL,
		0x2429A8E92F22BC0EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 62\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x550B28975A61A660ULL,
		0x2BC5D5E4C4E30E22ULL,
		0xEC1D1C2D0B42F8DAULL,
		0x89ADFBF824155DE5ULL,
		0xB530B3EDCF9FE45DULL,
		0x86D1C238FDD84E8FULL,
		0xFA2DD25B26862C46ULL,
		0x6103ECD3036048AAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3A45DDE42C1D8E55ULL,
		0x2EE8AA5A72FEB777ULL,
		0x0EEA55B4C32D8B52ULL,
		0x7043234AA4602747ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 63\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x59F7E5A7190844F5ULL,
		0x97A215006BB1EA4BULL,
		0xA386F0F42DC7A512ULL,
		0xEB9DF16E10502645ULL,
		0x17E0750FA83E65EEULL,
		0xC2637E2A4B4E4679ULL,
		0x235982C6047B23CAULL,
		0x8C25996503EDBA8DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE54945FA124B697AULL,
		0x7266CF4799506044ULL,
		0xE2D05A58D80EF52BULL,
		0x3932B66CA599D738ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 64\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x73CCE50A5AD46243ULL,
		0x6F571357BCD4F5D8ULL,
		0x61D0DBFA04603F9FULL,
		0xA5D796250AEF5FC4ULL,
		0x0128DD7EF2808A97ULL,
		0x878F9A2BEA2B3ADDULL,
		0xCEFB583A8DEEA50BULL,
		0x8D0FDDA6984B11B5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9FDDC5E259E8F7DEULL,
		0x8EA7F5DC7F3FB2A6ULL,
		0x1B1FF4AB15CCBF55ULL,
		0x16327CDFA61400C1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 65\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x1983827C341EB733ULL,
		0x297195C35064B75DULL,
		0x652643C4383DB8D1ULL,
		0x21EEFD271E16FAFDULL,
		0x6C633F521FC4EFC9ULL,
		0x0AE54E4A96D6B6AEULL,
		0xEC683A262190613FULL,
		0x6205A8B6FB445E6BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x303EE8ACEB5A5130ULL,
		0xC77B34D5B443D541ULL,
		0x7C9EE56D33AC282CULL,
		0x2EC608506A3CFF02ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 66\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x9F97DB0ACFD563BDULL,
		0x441D06C4D9BFF0BDULL,
		0xF6079AC3DE93CFEAULL,
		0xDA188DD642010ED8ULL,
		0xDB94C6ECF2260EFEULL,
		0xA7DDFBA3EA81037DULL,
		0x8C95B29AE3FADE41ULL,
		0xE909E930C7B6E646ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x37AD6236C17BA2A3ULL,
		0x2F106119A8E6756CULL,
		0xD4401DC1B5D0CDA9ULL,
		0x71912B13E7273D51ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 67\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x2E80A199D22CFEB4ULL,
		0x3E64BCB1A58BA7D8ULL,
		0xE5D48E4345BE8DF2ULL,
		0x05116C637D16A979ULL,
		0x76F396AFA770C865ULL,
		0x86BDF366BC7CFAF6ULL,
		0xBC453F3145CD92D7ULL,
		0x0509E4732772C5DFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD6A8FFACACEABDC5ULL,
		0x3E96DDF1A018E86DULL,
		0xD81BEF93A24259F0ULL,
		0x4489557B582008AFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 68\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x9CD296FCF686AB67ULL,
		0x56C21E4DFB4B474EULL,
		0x503DCFFD3103528BULL,
		0xD47F04896F25EE12ULL,
		0xE39D81BBEB6571D3ULL,
		0x0D9FF3B3DDAA30A7ULL,
		0xF102FA94AFE7B38BULL,
		0x29E5B0797E1F3B19ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6633D8E1E79591C3ULL,
		0x5C804B00E28E803AULL,
		0x16AF020F4D67F92FULL,
		0x0C97369227C8B3ECULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 69\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xF6DBA2471E99341DULL,
		0x8FA17A294638F76EULL,
		0xDF502E648234F03CULL,
		0xED4A72287881E000ULL,
		0x1D060CED915690A0ULL,
		0xDFDE962909424907ULL,
		0xD263FFA118B97667ULL,
		0x9A8D600D745AE5C2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x45C18D8AB172AF5AULL,
		0xCAABC440A60FCE7DULL,
		0x1A28204E2DBC83A7ULL,
		0x5E46B427BDFFFAECULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 70\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x8CF0E640322D29D9ULL,
		0x4B9E69C051A7BA04ULL,
		0x93C19DCCCF8CAD86ULL,
		0x366E5DB35403463CULL,
		0x0D6A40A883EC9D3DULL,
		0x6C5FD266400AA957ULL,
		0x0BA50396E735D74FULL,
		0xB7B8669F3F704A36ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8AB67F43C74C84E9ULL,
		0x61D7A4EDD33CDCF0ULL,
		0x4E402633218AA350ULL,
		0x7BCD9956BEAE4A42ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 71\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x6526FF60CB235DD0ULL,
		0x2179C9E088823A39ULL,
		0x93D062D4A2CD8B9AULL,
		0xB657CA45A5D221EEULL,
		0xE03085A01572AEE3ULL,
		0x959B4FD8A0518B71ULL,
		0x9631C1D6A3EC5046ULL,
		0x9198F4D428352535ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAC5AD523FA2956C6ULL,
		0x5687A408549CED20ULL,
		0xDF3328B0F7E17614ULL,
		0x530C21C39DB5A7E2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 72\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xDCE050B6714487BBULL,
		0x23F20BC20FB57527ULL,
		0xB1755998B955B392ULL,
		0x0678E84AABB14038ULL,
		0x9ECF56017196C002ULL,
		0xB0E92F335C732112ULL,
		0x96733139015CA6CCULL,
		0x700FF3747A9AA785ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6FA714ED4DA50A7AULL,
		0x668F0D61C8CC5DEBULL,
		0x068EA80EED1675F4ULL,
		0x28D70B94DEA61E0DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 73\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xA1CD387C8AE662DAULL,
		0x85A5916B2264A49FULL,
		0x3AE795129687D0DFULL,
		0x72855C2535F0AF68ULL,
		0x713701BDD6135D90ULL,
		0xCC46C64AE8E6AB53ULL,
		0x170F0F50E211AB0DULL,
		0x9CC93D52F36DA226ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6FF77AAA51C649B7ULL,
		0xD8270089B4A21302ULL,
		0xA723DB14252734EBULL,
		0x386476755836C10FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 74\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xC637C34B17097CC8ULL,
		0x8C6D87EC5B0A9808ULL,
		0x57D172891940B9C3ULL,
		0x533D7581565DEB9AULL,
		0x5BA111BA7C9BE2B7ULL,
		0xF4AB32B153C5458EULL,
		0x3512D6600AAD100BULL,
		0xC9226D240FF83980ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x602064F9962D2866ULL,
		0xDDD70E3ECA52EB2AULL,
		0x389D44CAAEF11B89ULL,
		0x2E59A8DBB53674A2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 75\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xD78F53AB2C7B4A87ULL,
		0x36331C6678C008D9ULL,
		0xFF4019E9DFEF12A8ULL,
		0xBF4E9265F7232D4CULL,
		0x8079A57DF3138CBBULL,
		0xF44B3ABCBD816E34ULL,
		0xE81EAA1977D1CCF7ULL,
		0xFB22A10C54A736D1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE99DE45D416233EDULL,
		0x795DD46A99F664A4ULL,
		0x73CD59B1A9137F76ULL,
		0x06727A3A87F55075ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 76\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x7934B0DA01D48858ULL,
		0x2578719059199C47ULL,
		0x40C9E6238DF36EF9ULL,
		0x4AC26835357D289FULL,
		0xC43FB5D865404E2BULL,
		0x54114AD60759EB98ULL,
		0x2DE0B1FC8626A512ULL,
		0x5A1FB46B402313CDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9AA9AEF9096024BBULL,
		0xA0098D55707294F4ULL,
		0x1024519F77AFEFB1ULL,
		0x2B773020BAB21914ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 77\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x57B88B9E8D129FE8ULL,
		0x3BDA10610A83EB34ULL,
		0x7D32109E9DD2129DULL,
		0x2AB8FD61B0E8B9D9ULL,
		0x2983E711E6DBD43FULL,
		0x5674D2486C7FBF07ULL,
		0xE5481F7B23979DBDULL,
		0x711FCEBCBA19A73EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x814CD846D1B423B5ULL,
		0x11314721257A4644ULL,
		0x85E6BCE5E6537CB8ULL,
		0x7571AD6550B78D2FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 78\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x131D5E0E1B7CECD8ULL,
		0x4A71717EF7D4EA4FULL,
		0x8ADE3108F608296DULL,
		0xA27F04079C8DBEAAULL,
		0xE0A899B1C339CF4BULL,
		0x16660B069D07BC73ULL,
		0x31070CE41A5ECAE4ULL,
		0x8A867BFDBC39D213ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6C242E711611B518ULL,
		0x9D97147A46FAE382ULL,
		0xD1EA1AE4E01A4748ULL,
		0x32756BB18D22ED83ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 79\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x6164BC090831CF15ULL,
		0x96EB1619C883F6BAULL,
		0x46883FDD536376BCULL,
		0x92EA23B2C99C1113ULL,
		0x1F946347141B2204ULL,
		0xA761E34BCC6A2E04ULL,
		0xD9179F7E6F5FCCD2ULL,
		0x0F9BF8775FE4D415ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x116B78960438DC0CULL,
		0x6F72D35A2046CB57ULL,
		0x8009ECA1DB9BDE01ULL,
		0x6411056B05938C51ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 80\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xA717FA13A866C08DULL,
		0x47E39CD012CA28DEULL,
		0x5EE0C15D1539BC68ULL,
		0xBA89CADF7B1A711EULL,
		0x76835B62C15155D1ULL,
		0xC8854627ADA8F99DULL,
		0x2C69479F7D6C030BULL,
		0x3EEE3D29D1560F66ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3E978ABC5A797F0FULL,
		0x0BAC06B3D9DF363EULL,
		0xF6816309B3423028ULL,
		0x11E6DF148DE0BA48ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 81\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xAC4D5C1126A3CCEDULL,
		0x48496BF578CCF98CULL,
		0xF54A06945DCADA32ULL,
		0x5872B9382FDC411FULL,
		0x3363E9730B250F92ULL,
		0x59A76D182E09BFF4ULL,
		0xEEAAA11969573387ULL,
		0x12D10408043ACDC5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4D220324CE241D0BULL,
		0x97239D8C4E3F77CCULL,
		0x629DF05A00BC8049ULL,
		0x23795268D096CC81ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 82\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xA3BAFB9DAF76054BULL,
		0xEFE9802C90CE7F8DULL,
		0x72D5A1739C16AF0FULL,
		0x488409B9CE7A1277ULL,
		0x3AD2827B787957A6ULL,
		0x22D45B83C8161D19ULL,
		0xE4A320236194013BULL,
		0xC0601E2D83A70901ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5EFA59F191790C2AULL,
		0x1B6F15BC4416D14CULL,
		0x630C66B4180EDDD7ULL,
		0x56C8847B594568BFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 83\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x77E889F5588B6830ULL,
		0x1DB07B7169DB4B93ULL,
		0xC142FB34CBB9F752ULL,
		0xD45C919C5C57F7E4ULL,
		0xEA78C70EE074D0C2ULL,
		0x28C3C768941DA632ULL,
		0x7DF2BC2728D45680ULL,
		0x438B1C265AA12A10ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x45D6162AA9E2668BULL,
		0x2AC014F76641F722ULL,
		0x734AE904DB3ECE58ULL,
		0x5B02BF4DD0443657ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 84\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x5C2375FC5FE9083EULL,
		0xAC80A94E903030E2ULL,
		0xF71DC698BF11FE3EULL,
		0x36EEDD2B12BE731DULL,
		0x06395AD7DF18FB2AULL,
		0x573096519DE70649ULL,
		0xA4E293AB5D921E00ULL,
		0xF66EE6D3F1AF03F6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x48A6F2077D9E55E5ULL,
		0x9DB6F96C007B1FB9ULL,
		0x70BFB208A2C2724BULL,
		0x4B6520A0F2B909BAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 85\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xCFB3F6608B1922D2ULL,
		0xF81D7CE7B07C9335ULL,
		0x58F4C67FA4FDE410ULL,
		0xC2B7228CA3D67D57ULL,
		0x5FF792B37034011DULL,
		0xFD12F0CD7DCAA407ULL,
		0xD33EB85738B4823EULL,
		0xAC50B5068F995121ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0E73BD0332D150FCULL,
		0x88ED3B685C90EC4EULL,
		0xB44423720FC9396AULL,
		0x56B20185F498885CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 86\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x6247927DF6539A47ULL,
		0x5B09F931169739BFULL,
		0xA6F875A36167623AULL,
		0x8FF1AF0B8585B9F6ULL,
		0x343EEAB23FF64F9EULL,
		0xFAAAFAD5C2B76807ULL,
		0x7B9D3189D28E38B3ULL,
		0x1AF558BB9A800818ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x239E68F374E36C66ULL,
		0x906B34EBFDD0AAD1ULL,
		0x004DD018A283CCF1ULL,
		0x105CDAE47486ED99ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 87\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x102918ED6B65A769ULL,
		0x479483A6CFE71440ULL,
		0x027CB7AB43F73E44ULL,
		0xFE7C6F6034D5E42FULL,
		0x1F3982E1986DC9CDULL,
		0xECC7BA8355A4D3ECULL,
		0x04C5E57AE1B1C10DULL,
		0x36EAF38377ED79D4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB2B2866A0BB19D2DULL,
		0x6D3A3325865E894CULL,
		0xB7DCC7E8C459E655ULL,
		0x255C94E40215F9A7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 88\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x0CE510FAEE6E1BACULL,
		0x59843ECDE843251DULL,
		0xB44E456270A19998ULL,
		0x98D06AA14DA6F270ULL,
		0x727ED0FEDC63F4B0ULL,
		0x7FA9A5C195D414F5ULL,
		0x64456D5E1514C0D0ULL,
		0xB8134806E396986BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0BB816CFA54471E1ULL,
		0x4CB2D98A25BE418CULL,
		0x969C815991B6388BULL,
		0x6BAD1BA716019261ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 89\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x38973D95DB89C6BDULL,
		0x3D1738F33B808EE2ULL,
		0x13FCCCD028CAC3D6ULL,
		0x70C257B388EE5557ULL,
		0x256866F05D04A91EULL,
		0x0BE66D9B993ED0EFULL,
		0xF6FDCBDBBA4E87F3ULL,
		0xD133F62E7BEF412BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC6168543AA3AE5CBULL,
		0x014B7E0BFAD39261ULL,
		0xBDA90F6DD072F1EAULL,
		0x7E78E299EE7201DDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 90\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xA05A8DF955741199ULL,
		0xE2CB9190FEE50E22ULL,
		0xB82D55829CE2E004ULL,
		0xDC767740EA99D38CULL,
		0x41D2BD4DFE9C28BFULL,
		0xFEA86E22664F26D1ULL,
		0x28BA38F03A33B532ULL,
		0xF9FE227DE1591054ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x65A2A78D20A22384ULL,
		0xAFCBEAAC2EA4D132ULL,
		0xC3D1C92B408FC596ULL,
		0x782F95F05DD2400AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 91\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xF3F5196951D96722ULL,
		0x0D6A860F9D79D066ULL,
		0x899A2D10961FC9F5ULL,
		0xA001514222FE1E00ULL,
		0x12AA2786AF18C575ULL,
		0x72D57E56EEEDA019ULL,
		0x091A0221D552CBB7ULL,
		0xA5998029827674D9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB936F7674F86BA36ULL,
		0x191B46F714BF941FULL,
		0xE3767E16406A0730ULL,
		0x34CA576B80937637ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 92\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x5066ADC2B5CAC1FCULL,
		0xC76DA4D7F822DC47ULL,
		0xB9796AD765B7F895ULL,
		0x98C46EB2D9467D7BULL,
		0x58A09C0A6CD5663BULL,
		0xBB843E6DB26946C2ULL,
		0xC6A9D6E18C3C5A7EULL,
		0x308E57554D2EB8FCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x783DD74EDD77EFDBULL,
		0x9D0EE92073C35D20ULL,
		0x36AF505236AD6765ULL,
		0x4DE5655C4E35F301ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 93\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x8F970789B477AE17ULL,
		0x75B5F33213379073ULL,
		0x04B013693B6FE989ULL,
		0x103CAF37F46C0F40ULL,
		0x8E8D354D4D51250AULL,
		0x2CDC3688A7A540F3ULL,
		0x4F9675509CAAE6E4ULL,
		0x2271AEC1FDF507AFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB88CF1032E832E51ULL,
		0x1E660B7AF5BF349AULL,
		0xD5057D607CCE2F68ULL,
		0x2D1CA003A6CB3345ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 94\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x8E8C6467CD759C60ULL,
		0x1CD176838A310CB6ULL,
		0xC8F119D754511CB3ULL,
		0xC808FF3BC537E7ACULL,
		0x56E03A68C600E78EULL,
		0xC0A073A7A715CA36ULL,
		0x0DCBBE02AC217813ULL,
		0x6B0A3C347CCF1B0AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x73D50FF53197FDE7ULL,
		0xB4A2A166576D10C7ULL,
		0xD52F4E3CE148EFA1ULL,
		0x2B8DEF064BF5EB2AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 95\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x4B68A6553B35D81CULL,
		0xFA6EB048EEFB07E8ULL,
		0x02C2719C96745CC2ULL,
		0x2D8FC734EB17342FULL,
		0x79BDB0B1B9B65365ULL,
		0x37C45A15DA8D8705ULL,
		0xB62D6A47E7041C7AULL,
		0x11284373B02B936CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5D90E0B6CC463979ULL,
		0x41940F875FFD12B8ULL,
		0x0D803848E11096E7ULL,
		0x3989CA61118F1652ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 96\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x032D11F8129D8A7BULL,
		0x70858149A9D6D451ULL,
		0x4018F9F11060D075ULL,
		0x639625EE35D1DD9EULL,
		0x3B73D3BECF2CE725ULL,
		0xB086C9201AB15CDCULL,
		0xA5076B07633FB070ULL,
		0xC9F6E214983864B9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD65E804AD347DE6DULL,
		0xA4875C0DA02A9D01ULL,
		0xBF32DD09CBD5012FULL,
		0x5E3BB4FCCE30D12CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 97\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x338FB68618F7091EULL,
		0x172584406901C09DULL,
		0xEDF599F7AA5E832BULL,
		0x1C302A6A1F72B8A4ULL,
		0x89A6ACE979CDBF30ULL,
		0xFCF6CDFA9B8F1119ULL,
		0xE350ABEA95151C8EULL,
		0x564B59BA38D7A8C6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA24D612E2D816C19ULL,
		0xA3C81773803E4A67ULL,
		0xABEF1EC9CB80C064ULL,
		0x6B5F7C0E8F75C62AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 98\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x395A289648612436ULL,
		0x2B68F6C5479A3F46ULL,
		0xBB043FC348AB28E4ULL,
		0x73503A2B2B8494EAULL,
		0xB02FFDE18852C772ULL,
		0xF200CDDD14962D0FULL,
		0xBB30A25167034A98ULL,
		0xE857EB34ED86518FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6079D81084AAC441ULL,
		0x1787859655E4EF9AULL,
		0x843C57D893283B98ULL,
		0x705D24066D74B040ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 99\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x8B38F469EF2D3761ULL,
		0x3CBC8DADFC768310ULL,
		0x21DEA7E74897A749ULL,
		0x6AE7F48C19AA329DULL,
		0xD44FD161D987FBEBULL,
		0x55165DA4A9F39A0CULL,
		0xDC8FCB20CD9D161CULL,
		0x54769F04FADCDFEDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F1208F0395C9E1EULL,
		0xDE0E741F369F60F8ULL,
		0xDF36CEC5CDE8EF7DULL,
		0x74838F4956736FEBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 100\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xF8E99A4C3E731966ULL,
		0xD8848149A0D671EFULL,
		0x0244D471E40FB430ULL,
		0xB37F4E5283B7866AULL,
		0x5EAD8AFC8CC0EAA9ULL,
		0x929C62F6929BD94EULL,
		0x4CE2B2B7269C406FULL,
		0x78A2F64473D080F4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x06AC3BC92315F13BULL,
		0x9BBB31E363F8B392ULL,
		0x6BEB5BA19F4144C0ULL,
		0x1BAFDC7BB4AAAAADULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 101\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xC03FC5BA18283787ULL,
		0x6036D83811A705ECULL,
		0xAE5A4B168A6FE569ULL,
		0x3E6B73379F83C8E3ULL,
		0x859A7989337129B1ULL,
		0xBCC78BD4841DE13EULL,
		0xDD4AC96E62215FCFULL,
		0x2B40DF2AD49A4A1DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x952DD017BAF468C4ULL,
		0x65D599C3AE167534ULL,
		0x877431791B641E3FULL,
		0x2A0C93932E6AC952ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 102\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x0A6497259CFA4E18ULL,
		0x14E81FB596142E81ULL,
		0xF67F07FA8D8179E9ULL,
		0xB29303ED35C75510ULL,
		0xFEE1DC74135C9C54ULL,
		0x9EE3407A929036A1ULL,
		0x8445D02AB6FC20D6ULL,
		0xAB1BE8A84207BBD5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDFEB50607CB9866CULL,
		0xAAA3B1E7577C4A8CULL,
		0x98DBEE51B6EE59C4ULL,
		0x18B78CE702ED36C2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 103\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x20EFDC83A8BD7EDCULL,
		0x96DACB6A71DD0BFDULL,
		0xEDA7BD5DBD361CBAULL,
		0x2160622E1F52BBCAULL,
		0x8BB935209CC019CCULL,
		0xFEC80B9C0697E7C2ULL,
		0xC565C0A303216EE9ULL,
		0x567139AF71654040ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDE6DBF5AED4154FFULL,
		0x688C84936C6972DDULL,
		0x3AC25590342C9376ULL,
		0x762EF238F45A4568ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 104\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x1C638D237D912E0EULL,
		0xE1A80708A5CC611EULL,
		0xBCCFE95D2BE55659ULL,
		0x5E3EA8AFEE166840ULL,
		0xD50EF124654B3537ULL,
		0x9C1A7073C572CBB8ULL,
		0xC781127F7A7C2B71ULL,
		0x2D56DD867E406E8AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBC9B588A86BB1542ULL,
		0x0D94B837F4D69E8DULL,
		0x59F8A8495A53C937ULL,
		0x19238AA6ABA6D0DAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 105\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x3AD52417DC3D372FULL,
		0x52FC5F056698DE85ULL,
		0x0AE8BBE7291EACF2ULL,
		0xD64628517DDF46C3ULL,
		0x9D0E2D1BC0EFB240ULL,
		0x3FAF4A8E464D41B2ULL,
		0x2DEEB3CCA2A58E9AULL,
		0xEF2B8DF63A25D953ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8AEFD6367FD1B207ULL,
		0xC7017023D6109F08ULL,
		0xDC576C474DB1D7D7ULL,
		0x56BD3ADE1F7D891BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 106\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x86659E00D2644DA2ULL,
		0xBA055C48B8144397ULL,
		0x4804A650E77E4356ULL,
		0x718C144EBEA665F6ULL,
		0xC7FF9D280B693253ULL,
		0xEF2AEE16138AB545ULL,
		0xDEA5CE79ED15E43EULL,
		0x5239C255B9BB7573ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3656F1F28401C7CFULL,
		0x3A64B38F9EAB2BF3ULL,
		0x54A14C6A18BE24AEULL,
		0x261EED085079D529ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 107\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x70BBBB1E6B58D579ULL,
		0x5C9BFEC0F7483E1AULL,
		0x44F92BADCBCF87E6ULL,
		0xEF8F39B434771E09ULL,
		0x651079B9A8C66493ULL,
		0x0444E7F6EFE188E3ULL,
		0x7EC0142CC616A448ULL,
		0x2A821E732204E83EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x712DCCAD78CBC455ULL,
		0xFED66D6892C28FDBULL,
		0x157C2A53332BEA96ULL,
		0x3EDFBECB41319750ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 108\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x207EAEF4997DD352ULL,
		0x0B7BC9FB700493B5ULL,
		0x95DC2914BC8DDD76ULL,
		0x61E883AE80AA29A0ULL,
		0x14C656F2F1C17B4DULL,
		0x61CB9351473AF998ULL,
		0x702063D8A1E85B3FULL,
		0xD073A12EF71021D5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x35EF97047C36255AULL,
		0x8FB3A80C02C5A048ULL,
		0x3AAAFB3CC50B68DEULL,
		0x531270A72D0F2F4FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 109\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x97AFCFA49C197081ULL,
		0x92C08413B4065FA4ULL,
		0xB36FF4133CA72A38ULL,
		0x894EA1261D567CDBULL,
		0xACA50C29FA9312F1ULL,
		0xC2669A500B918302ULL,
		0xBA55C546EAA5BC41ULL,
		0x869C22D9D31E3ADBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x382F9DDFCDEE4352ULL,
		0x6DFB6BF56B9FD20AULL,
		0x5C2B3C9A11411BFBULL,
		0x047BCD7B73D33979ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 110\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x70F48B172481C0F1ULL,
		0xBFC318F8F2D9F6D0ULL,
		0x875E2A77B242C3FAULL,
		0x3616C1F7DC2A2D8AULL,
		0xD3C04CE84C1BCD27ULL,
		0xC7EDD40B27B4AC39ULL,
		0x1D3253E9271F3208ULL,
		0x88586A9542996437ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDF7FF59270A237B3ULL,
		0x6D1092A0D7AB8765ULL,
		0xDCD69F1380E43148ULL,
		0x7336941FBEEF0DB8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 111\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x631D04DCB6163D84ULL,
		0x6E1E8B87D7557CEAULL,
		0x3BFE5448A69BAD28ULL,
		0x4E76EDD29B8173CAULL,
		0x501DE4B1DF7E410CULL,
		0x4BB0316B735CD075ULL,
		0x8D3020E738A9D6F1ULL,
		0x9FA606D376166539ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x478CF743E2D3E8DCULL,
		0xAA45E17AF71C6E54ULL,
		0x3123369B0FD194F9ULL,
		0x011BF13622D47A55ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 112\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xB586DC1123E73200ULL,
		0x71D78D645FF18355ULL,
		0x79D8B19545E3B2ADULL,
		0x46AA4F27E9949271ULL,
		0x19885D15F921DDB2ULL,
		0x4E527F76759F35F5ULL,
		0xE42FC31F51D1915EULL,
		0x2E427184E3665CB4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7FC4AD541EEE1B76ULL,
		0x121678F9D59385B7ULL,
		0x58EFA83B6AFF46ADULL,
		0x248728E1AAC6554BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 113\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x1AD11BBFA17DB968ULL,
		0x0ECB141117BBCE3DULL,
		0xE4EC8E3945DD092EULL,
		0xA7DBF35B277B6A7BULL,
		0x1E0DE60B62426029ULL,
		0xF57684CE9ACBDEC3ULL,
		0xBE489F5D05E214D1ULL,
		0x908B309C7383F7FEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x90E14170375802C2ULL,
		0x7E62CABC11FEDF33ULL,
		0x23B43608256C2058ULL,
		0x1C852A944D123A4CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 114\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xF50B1A6521D85751ULL,
		0xE058C88588008D25ULL,
		0xF7611809DE5DACBDULL,
		0xE0E485BC51634522ULL,
		0x67624AF5BA004011ULL,
		0x1140458868A392F2ULL,
		0xF2E3F9E56C4FCBCBULL,
		0x0BDAF321D49E4D94ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4DA23ADEBDE1DA36ULL,
		0x6FE31AC510485D21ULL,
		0x05383017F235ECE2ULL,
		0x23649CC1E0E2C93FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 115\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x5C6E6E5B90A80267ULL,
		0xEB6AECD540EA20F8ULL,
		0xE821D96D6E7F3162ULL,
		0x5383846FDAE4CA8EULL,
		0xDE543C315580A24BULL,
		0xA2A64B49FD059885ULL,
		0x98A536B2E2EEC95FULL,
		0xF8330E1DBBC6B72BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5CEF5DAE41C01F07ULL,
		0x101A19D0CFBEC4D7ULL,
		0x90A7F7FB1DF11595ULL,
		0x2B179CD9BA63FB07ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 116\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x3E5CE16605277904ULL,
		0x4D24ED927142C321ULL,
		0x9EB7EBD14F0BF517ULL,
		0x407EFC12E4E50991ULL,
		0xE1CB6356D7108559ULL,
		0xEE3B3DA1DC2BFBA0ULL,
		0x3D82B5B9115DDCCFULL,
		0x4BB69E0E6AB888D1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC28DA049F19B45DCULL,
		0xA9F013991FCA1D02ULL,
		0xC01EE549E2FABBF4ULL,
		0x7D9A7236BC4958A0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 117\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x0FA9AFE3FA6EA7CDULL,
		0x0CD844723C43040FULL,
		0xF00E72447FF25A12ULL,
		0xCB266AF5B4C4A4E8ULL,
		0x49A0FA26A4BFBB16ULL,
		0xA19E992B69B47294ULL,
		0x66AC64028093BEF8ULL,
		0xB51FC1AAFC8BA7EBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFD8ED1A06EE47126ULL,
		0x0A6300E3ED0C0611ULL,
		0x2DA54AA395E0B2FAULL,
		0x2DDD2A57317F91DAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 118\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xA8776580D86C5480ULL,
		0x6826561889730A37ULL,
		0x260F0D54FD709F98ULL,
		0x0B208D69A1C281DFULL,
		0x3AE4167302FA0948ULL,
		0x374DAB74DAD0681DULL,
		0xD089D63050736826ULL,
		0x8A5792784AD62901ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6652BA934989B83BULL,
		0x9DADC97104627E8EULL,
		0x1A84D880EE921544ULL,
		0x14204B44BD8C9824ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 119\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x63AE66C7C3585A6BULL,
		0x875D61ADFC0D6744ULL,
		0xFFB3BB23332B8113ULL,
		0xCB10B2BA2602580DULL,
		0xA35605DA03D6FF00ULL,
		0x245F9144AD558D16ULL,
		0x2EAFFF9A9C018A5AULL,
		0x33CAEC6A2B247265ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA27345245542359BULL,
		0xED8CF1DFB6C058A0ULL,
		0xEDD3AC165B660A74ULL,
		0x7B2FCA7C8D6B5312ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 120\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x82811C2C6C078DFEULL,
		0xD7337A573C745C12ULL,
		0x884787BE67A41F5AULL,
		0xCDB2BB882D9F673CULL,
		0x29C7879554F2CE31ULL,
		0x27A30C41ABD1E321ULL,
		0xA5D23B3F5BFB2EF9ULL,
		0x0ACE3A4AE77F415DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB61F3C5708122990ULL,
		0xB9674C16BD9C12FEULL,
		0x257C53260EED1856ULL,
		0x684F62A68A831B23ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 121\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x7AACD0A049032BA0ULL,
		0x5E2E49E8FC0D94FAULL,
		0x0B4A9CE7551DC85DULL,
		0x3F42A7504DE79353ULL,
		0x4564858A155B6862ULL,
		0xCFDCF1332727BACCULL,
		0xDD80688FB19BA0DEULL,
		0x0F1AF8CBC3F43909ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC798A31F7494AA78ULL,
		0x38FA1780CBF34F4CULL,
		0xEC5A223BB237A970ULL,
		0x7D43958F64280AC9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 122\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x96CFE1F7904D4448ULL,
		0xA53386D63C550088ULL,
		0x312CBA8E2B649080ULL,
		0x5BE0850251825889ULL,
		0xD70E45DA6171DBBEULL,
		0xF79459C21F3F2EB7ULL,
		0x7454471FD9C340DEULL,
		0x99B87E805FB52BACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x82EE40620733E5E6ULL,
		0x6538D9A6DFB5EFD2ULL,
		0x75AF49487E603199ULL,
		0x2D434C108666D422ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 123\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x1CEEFD94E40B1FE1ULL,
		0xD24222234D5ADED3ULL,
		0xAA2ADA3F9F4E45F3ULL,
		0xDF284DAD9E3BCB65ULL,
		0x10BE76700E7D02BBULL,
		0x454EB5FD95DBA28DULL,
		0x727692BC771A634FULL,
		0xEB24392BD4EBA257ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x993492370A998CE8ULL,
		0x1BF125C78BF4FFC3ULL,
		0xA7C4A2394D3903B8ULL,
		0x4688CA2F3935E460ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 124\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x304215190692BCF8ULL,
		0xED0BA88D0D2D4C0CULL,
		0x52DA9C81ED61019AULL,
		0xD4C9459961975B74ULL,
		0x29E7E54A2ED3467AULL,
		0xD2378865D69A0B19ULL,
		0x200105776FC101A4ULL,
		0x006D69B404ABAF53ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x68AE1E1BF9EF3327ULL,
		0x2149E7AAE80AF1C8ULL,
		0x13016C3C84074012ULL,
		0x6506F652131361CBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 125\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x7E8B24F71D157ADFULL,
		0xF8F07E85381D38F4ULL,
		0xFB476B2C0CF1C120ULL,
		0xB6A0B1D7A4A16293ULL,
		0xBF38FE318B7446F4ULL,
		0xCC20929AD251406DULL,
		0x6222EF76760FF64BULL,
		0xD99A892C8091AD20ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE100E051D05807FDULL,
		0x45C64180702CC93EULL,
		0x8C76F6C193505061ULL,
		0x03910E72BA411562ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 126\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x47D6639C24D04865ULL,
		0xCFB292098D83AEF2ULL,
		0x2AED2E1FF7020F63ULL,
		0xC70DC534E8034BE7ULL,
		0x8257EA8369AACB97ULL,
		0xFCD3583ED51DC793ULL,
		0xC22083CD9B82BF72ULL,
		0xFD3387BD6316F232ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA0E3331DD42A8673ULL,
		0x5711AB5D2FEF4ED7ULL,
		0xFBC0BEA50C6A7A75ULL,
		0x5CB3EB519D6B3F6FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 127\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xDF4B683033A2FA94ULL,
		0x97A6CF4FD9B3712EULL,
		0x755317023CE7CF03ULL,
		0x9C6CB696119430CCULL,
		0x42A10BCDABEE16C0ULL,
		0x0FD55CC6527D3BE7ULL,
		0xCD4E6FAC6E6671F6ULL,
		0x85DC2C78B1A7267BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC33328B7B8FA5E0CULL,
		0xF15294C0184A5582ULL,
		0xEEF7AA9AA01CB989ULL,
		0x7B1B50807063E72CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 128\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xAE238017A720B996ULL,
		0xB2A1BB34CF6A0476ULL,
		0xD4792DC40701BE79ULL,
		0xF5A8CCAF69CB8FE0ULL,
		0xACE3FC5BE3209705ULL,
		0xD78557C047C5C345ULL,
		0x5165922265B27D3AULL,
		0x0BCCE149E32180A1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x57FAF5BB5DF724B3ULL,
		0xB06CC1BF76C500CEULL,
		0xE98CDEDF1F805535ULL,
		0x36123DA720C4A7D2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 129\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xB91F5FB0BD983445ULL,
		0x81F3FDE6435D7D11ULL,
		0x3343554ED3DD657AULL,
		0x373D68BECBDCF196ULL,
		0x1D0134560AE10E48ULL,
		0xF24E3BE7736011DAULL,
		0xD6E306FD236BFAD8ULL,
		0x9280ECA7CE9B5EC7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x074D24765B005626ULL,
		0x7990E24163A02372ULL,
		0x18F65EE215E4A1AEULL,
		0x766089A776ED0340ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 130\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xA6D1D2BB4A62F5C9ULL,
		0x66415E2D423B1775ULL,
		0xDA4F3A342BC16B73ULL,
		0xAD46635494E1E28BULL,
		0x8B5662657A6B8A70ULL,
		0xE863ED3414F395C9ULL,
		0x681638C41308B35CULL,
		0x6FE441EF5A84B5E9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x55A46DCB765984EFULL,
		0xE51693E85E635360ULL,
		0x4D9BA74EFF0C0B3DULL,
		0x49282CDC0494E331ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 131\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xFDDF38A6B0779EE9ULL,
		0xD6A6F54A66B6CB81ULL,
		0xF33A5AC47EB2C4E8ULL,
		0x66CBA35B14C066F5ULL,
		0x2DEE238E21A3DEF7ULL,
		0xD6AFE76A7A42BAA3ULL,
		0xCB739777A70B97A0ULL,
		0xD0D7FEA57F910BDAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCF387FBFAECABC2DULL,
		0xB4C34F188C9E7FBAULL,
		0x2662D6874A6B46C8ULL,
		0x66DB6FEC04482970ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 132\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x195AAC0923E6FE66ULL,
		0xDAB02657DCAA1928ULL,
		0xA1192DC0DEA9951CULL,
		0x300AF720B589ADA6ULL,
		0xB3D1A01F01AF6302ULL,
		0x99F9EBA67021C0B6ULL,
		0x5ECB34BB549A33F6ULL,
		0xB5613EF5B5486D9BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCA7870A363EFB4B4ULL,
		0xB5C9210C81ACB446ULL,
		0xB343018F6D8D4BB7ULL,
		0x1C7A4F999E49F2B6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 133\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xBD175A25C2795527ULL,
		0x0E13A42AC0DDA088ULL,
		0xD3069FB625B4BA74ULL,
		0xC35AD788557F5FF9ULL,
		0x94DCD983496A2034ULL,
		0xDA15D1744E39F3F7ULL,
		0x81AE2874901D8BB0ULL,
		0xCC876153F9B05D8DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD5DFA3A2A83A2179ULL,
		0x6D50BB6E5D77D748ULL,
		0x12E0A1038A1776B4ULL,
		0x1F7349FF65AD42FBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 134\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x4F96E0E238CD74CCULL,
		0xFCED35E2823393BDULL,
		0xD205D87BD0EEAC68ULL,
		0xBA7A83E05D1B8B36ULL,
		0x851F2906A1CE6F33ULL,
		0x1F1482D52B71D0CAULL,
		0xAEB0B103266783D2ULL,
		0x8FAAE98322AC9797ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1236F7DE3D71F9A2ULL,
		0x99F8A186F51891CDULL,
		0xC0401EF3844C3D99ULL,
		0x0DD92D5782BA0BBAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 135\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x7B271059FB8F1DB8ULL,
		0x0C1269926139634AULL,
		0xFFAD44E7436822A3ULL,
		0x06555A31C43F1129ULL,
		0x2536ED16BB0106C4ULL,
		0x059C6085E03E5706ULL,
		0xA946B5CF0E3627FDULL,
		0x75A5ABC927879B51ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x014E41B9BDB62156ULL,
		0xE148BD71AA7A4E34ULL,
		0x202C41A35F721231ULL,
		0x7CECDA0DA2601F49ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 136\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x85FC05EC42FCAB22ULL,
		0xD062B8D4F48846ABULL,
		0x814A2C73AC651E98ULL,
		0x20F2320432F7395DULL,
		0x52266A54256DD8DEULL,
		0xE20EE20DCCDD1D27ULL,
		0xBC071C896B5CBB98ULL,
		0x5A2527F95C2BDD39ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB7AFCE69D14ADE17ULL,
		0x5E9846E15D5A9A81ULL,
		0x6A5868D99C28F74AULL,
		0x02762107E17A0FEFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 137\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xA1C22B612A4173FAULL,
		0x90A5AE2DBCFCF957ULL,
		0x5BEAB4BAA22C9A25ULL,
		0x8309BC989418E843ULL,
		0xA52D0C7CE26A8D13ULL,
		0x4468ED926D9AB9A6ULL,
		0xE4F3B23065BEFD77ULL,
		0x55FEC523D4C5114FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x267205EAC61266BAULL,
		0xB838F1EA01F48814ULL,
		0x581727E9BC8639D9ULL,
		0x46DAFFEA29597A1FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 138\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x8BF41F9FB5B3C1DEULL,
		0x86701F7658BDA145ULL,
		0xD5157DB9B6A4D221ULL,
		0xA060949F2E48974EULL,
		0x195D5437C59E82A0ULL,
		0x14DE73CD8E67BA4BULL,
		0xF51FF29C1F4A3620ULL,
		0xBB048368D1253CA4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4FCE9FE70B3B29C6ULL,
		0x9F754FF97C23486BULL,
		0x37D380E65BA8DAE4ULL,
		0x630C162E39CF97CBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 139\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x17B926B3F48F2AA6ULL,
		0x4DECC4B88807481AULL,
		0x600FFC7326A1608DULL,
		0x3C8FEDB3C56114AEULL,
		0x4F6EDE947A6EF00DULL,
		0x33183C0B1C755943ULL,
		0xFC9305DD4E170634ULL,
		0xC73A83805C550EF8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE22E30BE2106D0F5ULL,
		0xE385AE5EC1728817ULL,
		0xDDE2DB4CBE0C4C4CULL,
		0x4F3F72C17A014DA3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 140\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xF9E372FEEBA87A8EULL,
		0xDE23E9A002B327F5ULL,
		0x7FA0053B4A5370BDULL,
		0x59A3CF3DCE3C257CULL,
		0x42BE785D9C4CE349ULL,
		0x5A64C04EE070D290ULL,
		0x839E816E604DA01BULL,
		0xF824DA88963754FAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE22950E41F123CE2ULL,
		0x491875555372695FULL,
		0x09273B9D95D934CDULL,
		0x2F1C3F841A72C2ACULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 141\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xF688469E21079CDAULL,
		0x89C7AC40332CB8BDULL,
		0xB1452A2AC8701CC5ULL,
		0xB103A0FB2A7D07DDULL,
		0xE052F1B67F229578ULL,
		0x771D8A4127FD5B13ULL,
		0x6F46614A6AE79581ULL,
		0xB74CF105C7A9966EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x42D827B50029D0BFULL,
		0x382A31EC22C83DB1ULL,
		0x35B79B36A6D04DFDULL,
		0x666F67D6CDA95C42ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 142\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x6D31FA1B89BDB8CCULL,
		0x8A5EF6F224A19300ULL,
		0xDC245B2A195D63D2ULL,
		0xB1C964FC674EA6F4ULL,
		0x87F6ABD596431264ULL,
		0xB9B21EF1AB121DDFULL,
		0x04EE8C8AB81D7D19ULL,
		0x7A3ABAED5B7C1B6EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9BCF7BCFD7B27663ULL,
		0x1ACF8ED18952022EULL,
		0x978D37C16DBDF5A4ULL,
		0x56812437FBBAB949ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 143\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xC25340C2713DA6A0ULL,
		0x46D7598F22C57973ULL,
		0x9BEF339F91167A4CULL,
		0xCA74192BFED120F7ULL,
		0x067153C67AB2C988ULL,
		0x95AE4AEC3F2AE908ULL,
		0x5F83B3A605ACE672ULL,
		0x0C7D790D07AEAC7FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB725B038A7C7912FULL,
		0x7EB678A0832410A4ULL,
		0xC97BDE4468C0AF4EULL,
		0x2514111B22BEBBDFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 144\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x3328BFB3FB646504ULL,
		0x85689811B20F7890ULL,
		0xB2EC3FD36B051D69ULL,
		0xD542A92E1947EA45ULL,
		0x74CF5AD0A3D9E034ULL,
		0xDCDA894C758F5BDDULL,
		0xDB3AEC1FD16E2570ULL,
		0x6FEB2970925B25A4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x89F03AAC4DBBAF42ULL,
		0x4DD8F96B25571B6FULL,
		0x3DAB4C8C815EAC2AULL,
		0x722ACFE3D2CF80BEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 145\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xACE0DA39422AA9C7ULL,
		0xDE7AB86EF0DECF05ULL,
		0xE222FA4BA676956DULL,
		0x4CB985276B73F769ULL,
		0xE3CC4A25940280A1ULL,
		0xE84F7FF1C044405FULL,
		0x141869FBE2B298B1ULL,
		0x22FC98CAB4E70055ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7D33DBCD3A89C26BULL,
		0x5A47B6517B005D41ULL,
		0xDDC2B5AF4CF93FD6ULL,
		0x7E38333E45BE040AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 146\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xAF054E1BDD820D53ULL,
		0x3DBC463ADB517137ULL,
		0x498325A134403EC6ULL,
		0x26B77183DA3547D4ULL,
		0x7B05234852A43C11ULL,
		0x1C2D7FC4DBE67221ULL,
		0x6976BB7C14193C6AULL,
		0x7405A017545CC666ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF1C88AD821E2FA5FULL,
		0x6C7D3D737F86622FULL,
		0xF122FA0C2FFF3686ULL,
		0x5F8D34FA5FFABB07ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 147\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xB95D4444B4AB90DFULL,
		0xB58D51F9AFE061CEULL,
		0x727AE864D53CAB97ULL,
		0x385173D36F6F51D6ULL,
		0x1D82F924D80A311DULL,
		0xF99744E9BCD2B072ULL,
		0x30AFC61A09EAB526ULL,
		0xBA686B2E7E57AB34ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1ACE3FBCC62EDF42ULL,
		0xC2018CABB72692BFULL,
		0xAC9250424E138F60ULL,
		0x63D15CBA3072BB95ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 148\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xEE0A68715992DA9CULL,
		0xF79D6499B130F3E6ULL,
		0x49E42846F134C667ULL,
		0xEA3001B5C3F706DEULL,
		0x9815D64F2957352FULL,
		0x741B747BDAC3DEEAULL,
		0xBDEE222A2A6BA3F2ULL,
		0xE1A6D7C3721FC5A8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x814838317C84C4A2ULL,
		0x33B0AEFC2A440AB9ULL,
		0x7B3D3A893D2F1C65ULL,
		0x68F408B8B4AE5DEAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 149\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x12BB67219C3D6BFCULL,
		0x04540D7B915CE0F3ULL,
		0xDA9660E1E6A58FA0ULL,
		0x72C7E9983578C838ULL,
		0x9A6FF41E1A5B4596ULL,
		0xE7F2089656A7C0F5ULL,
		0xCB4EE3D2EF1EFC8EULL,
		0xAC32F27552C251D3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFF59A39985C9C41CULL,
		0x724153CC6E438567ULL,
		0x084C3231653F0CD6ULL,
		0x0257E7027E50EDA9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 150\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x97FDAB59DB9E03B4ULL,
		0xB8FFA32C4702EF60ULL,
		0x8810BB980CF40735ULL,
		0xAAB9E5CF4A2505EBULL,
		0xE58497199A9E2A14ULL,
		0xCDF8CF1F7D43756BULL,
		0x3C71305223DE3F3FULL,
		0x79093E31C519B7D5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA9AC1926CF18456BULL,
		0x4BEE61D8DF065D64ULL,
		0x80DDE7C95FF16AAEULL,
		0x221921328BF64F92ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 151\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x8C4CFE7D1570126CULL,
		0xD4AA1DA39772B864ULL,
		0xF8866C0A7C6C133BULL,
		0x416FFAC10DD4723EULL,
		0x36297006EE61C9A3ULL,
		0x877DCB0A8D5D64B5ULL,
		0x1EA8AE1C371A05B2ULL,
		0xC47D705CDEDEF335ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x96739F8477F404ECULL,
		0xF1564134934FAB4AULL,
		0x8590443AAA48EBBBULL,
		0x6C0EA88A22EC8C21ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 152\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x0C51430A6156A855ULL,
		0x76D49C224EE4D5BDULL,
		0x4D2689F8FE7DCCB5ULL,
		0x9D33E8D80706DB3DULL,
		0xD814BFE88E8C2ED2ULL,
		0x5850320E7215B80BULL,
		0xB7C6D165F9A7F0E7ULL,
		0xD27A967673F11890ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1F65BF8F8A25A02EULL,
		0x92BC0A473E1E277FULL,
		0x94A99F1C0D6B8F0CULL,
		0x5B663E6D3CD080B8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 153\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xFE1609BA99DCC6B6ULL,
		0x6CC389A02FE30F91ULL,
		0xF1F57712F0B20C90ULL,
		0xCE08BCE6139DCCA6ULL,
		0x2BE6DFE2F63F9929ULL,
		0xD2C5064B0B03B4BCULL,
		0x4453AA9A1DBA5DCFULL,
		0xFBCDDC6D7EB7D702ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x825B456B274D8870ULL,
		0xB60278C3D26FE380ULL,
		0x1660C9F35A5BF969ULL,
		0x2E977526E2E7B6FDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 154\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xBCD81E3A323E5AD6ULL,
		0x5F30DF96B36ED452ULL,
		0x5F39B605C54D206EULL,
		0x337C88EA24231EA7ULL,
		0x3F306E948C268041ULL,
		0x5AB2D304D1CF719FULL,
		0x2EDA0C1E5A80F2DFULL,
		0x755D28391076BBCBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1E088846FFF56715ULL,
		0xD5BC324DD839B1F6ULL,
		0x5397828734712D95ULL,
		0x1F50816295C2FED0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 155\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x3FA7B82F8EA6E918ULL,
		0x42176234E5776338ULL,
		0x4D66177B1EFB52F5ULL,
		0xFEFD4C68DCC43B0FULL,
		0x44A2D2BFA23BCA67ULL,
		0x9E15B0307D58EC73ULL,
		0xA54BDA08948270E7ULL,
		0xE93FAC5C329310DAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6FD300A1A386F9A7ULL,
		0xB94F896780AA7C54ULL,
		0xD6A874C12A581556ULL,
		0x1E70E2185E98BB83ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 156\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x55C887F066A09577ULL,
		0x8DADE2BF65A66254ULL,
		0x11CD8EF78BFDD54BULL,
		0x312159D882C50083ULL,
		0xAC35695F9618F94BULL,
		0x4A95DF3FC5A77041ULL,
		0xB74A13A4210521B4ULL,
		0x36C8BE68D8313CEEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE5B62C20AE5597C9ULL,
		0x9FED0636BC810C13ULL,
		0x46CC795472C0D60EULL,
		0x52ED9D689A140BF2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 157\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x338078EDE76A56E5ULL,
		0x8F9CF86A58A7B002ULL,
		0x58E77AECC8B1D5D1ULL,
		0xC10BC2798AD2B057ULL,
		0xC78B09B5F378C016ULL,
		0x1C5562ACE20C1CEFULL,
		0x0A6941CB7241BB43ULL,
		0x3A3FD188EE93405CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD223E9F00B56DB7FULL,
		0xC4499E13E673FB99ULL,
		0xE4873F1FBE73A1C7ULL,
		0x6684DCCCF4AE3E00ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 158\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xE5E3090F8F5864CFULL,
		0xA4E035007F100C22ULL,
		0x46B72C3815306592ULL,
		0x1879230CA98DCE97ULL,
		0xDE953850640BA864ULL,
		0xB120B3EEE30C891DULL,
		0x6D3648A540A354DAULL,
		0x39A8C9FEDCB3DD1AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF00964FE691364EAULL,
		0xEFBAEA7632EC6691ULL,
		0x7CC5F4BFAD6EFE08ULL,
		0x27871EE16C40A083ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 159\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x6A2853FF04496485ULL,
		0x2094BEF15C1B13C8ULL,
		0xB3D75D2AB89D9178ULL,
		0x54337073A338DA4CULL,
		0x058C5D7CA2CD80CBULL,
		0xDABBFB85ACC077ADULL,
		0x55862CA76AF5518EULL,
		0x7389580FEC8E7EFDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3CFE347F2ECA852DULL,
		0x987C14C900ACD777ULL,
		0x65C1FE049907ACACULL,
		0x7A9682D0C05FB3E7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 160\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x437861477A2C35B3ULL,
		0xFAED7BCCD721B24CULL,
		0xD1DD6E484180C2A9ULL,
		0xD172FC109118CC1AULL,
		0x9C883BF018EABA1BULL,
		0x1CFFC5DB5E503FD8ULL,
		0x2CB4E3468721BF3FULL,
		0x5C73AA9DE7035DC9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7FB146EB2D03D7DCULL,
		0x48E4DA5CD70B2C73ULL,
		0x74B72AC050832608ULL,
		0x0A9E4F80DB98B7F7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 161\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x2D591AA9D737B287ULL,
		0x82B0317C5C42194BULL,
		0x330CAD88B4CA0D03ULL,
		0x9FCC205A3729442DULL,
		0xB9E97982FDE60286ULL,
		0x6D0A8E8A2245BBCCULL,
		0x951A146020F2DBFDULL,
		0x2B0F362E7F2070B3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC601241B875C1375ULL,
		0xB24159FD729BF9AEULL,
		0x54EBB3CD98D6B4A1ULL,
		0x040E2B4115F9FED5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 162\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xAB69B9F9250BB7E4ULL,
		0xE13218EDAB3ABDAAULL,
		0xC460D54E738A3A0BULL,
		0x7D9CF9968B4A7F5FULL,
		0x18497A45A9E9C9E3ULL,
		0x24F7DC0A044E41FDULL,
		0x0B0F586F8D036913ULL,
		0xB3125B4B406ED55EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4651E0505DBFB398ULL,
		0x5DFCC26A4ED8893CULL,
		0x68A7F5DD620BD2E3ULL,
		0x125686C21BBE2B55ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 163\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x4AC21DFCEDC28FACULL,
		0x17603183AEE25C35ULL,
		0xAC84FF0452B6CBB0ULL,
		0x73B0A8CB8FDF4A45ULL,
		0xFC4D3DA318141E51ULL,
		0x30B4D7078A4E31CEULL,
		0x16443BB1E7381030ULL,
		0x08FA1F3A5EB7DBD0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBE39443280BF0FEBULL,
		0x52381CA2367DC0EEULL,
		0xFAA5DB6CA50932D7ULL,
		0x48D14B759F29EB28ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 164\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x9BA0E43217943C0EULL,
		0xA0442C057FE13FD4ULL,
		0x8FB3E1186A7CB6CEULL,
		0x07461F8D69D0E498ULL,
		0x8EAE47BCBED18317ULL,
		0x8213A9D34C6A3D7BULL,
		0xA2BF105F4DCF6E3DULL,
		0x1BB265CC7B4038DDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC97F8A366AADB210ULL,
		0xEF2F6162D7A6602BULL,
		0xB8104F3DF74713EFULL,
		0x23C13BE7B559557EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 165\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xF40619DB1F1A39FCULL,
		0x32190A27E85913D7ULL,
		0xC78A4D695403733CULL,
		0x612421D73271C3AEULL,
		0x5AC07ED87B5AAC76ULL,
		0xD67EEFEDAC41E7C6ULL,
		0x8296DAB58B97A2C2ULL,
		0x3976601790FDDB9BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6C98EDFD6E8FD4C3ULL,
		0x08F0A76F7A217B49ULL,
		0x29EEC45C0C859C28ULL,
		0x68B66556B8205CC4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 166\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xCAD705163470A692ULL,
		0x014E898701651DC9ULL,
		0x9A06F2916937CAF8ULL,
		0x8CCB378C627C45C7ULL,
		0x1D3E160F41657E1AULL,
		0x80E3F4F70600D804ULL,
		0x529FE4E9274CB381ULL,
		0xA352BBF5D77AA3CAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x220E4B59E9816211ULL,
		0x2324E631E5852E66ULL,
		0xDDC2ED2D3E9A7031ULL,
		0x4B131E0A5EB095CFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 167\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x3BFD7845E48F80F1ULL,
		0x1ECDA1A780A0F947ULL,
		0x7DDAB55624C352ABULL,
		0xCBB6D1BEB60E96B1ULL,
		0x677A15C58B64FAC7ULL,
		0x52339781C455F268ULL,
		0xBEA97DA29F200D2EULL,
		0x202C37FB2D6724FEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x981CB398958CBB4CULL,
		0x52761EEAA562F4C6ULL,
		0xCB035B79C385478BULL,
		0x12472107735E1481ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 168\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x13E5DE7C7D2141FDULL,
		0x95764FCB316DB1C1ULL,
		0x3FA8EE93AB0907C8ULL,
		0x779463E9893DF1A4ULL,
		0x28D95B98FDFC42BFULL,
		0x2BFC857F8F412C16ULL,
		0x43089BDEE2D0B10EULL,
		0xDD1DD4D0069981CDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2429773230932F3DULL,
		0x1CF220BA751A3D0BULL,
		0x32F011A956034FE3ULL,
		0x4A01FACA8407361CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 169\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xCA87524AA94E64F5ULL,
		0xD9A1D9910DDF0DCEULL,
		0xE1CC184656632DCDULL,
		0xEC1E9CB9EEA89910ULL,
		0x26AF05E659611E22ULL,
		0xAE75227291EA2072ULL,
		0xF43ACF8FA509EBF5ULL,
		0x8B249374E9B08552ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8882327BEDB8E132ULL,
		0xBF04F692B69FDEC0ULL,
		0x2286E798D5DC3445ULL,
		0x138C80149EDC6361ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 170\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xD57949364C97E29EULL,
		0x18D5630189B4CCCFULL,
		0x2168C68CB3858DE6ULL,
		0x1AF91F85FC4A3BF2ULL,
		0x6318462D419593DBULL,
		0xB8E8E00F17EEA94BULL,
		0x3922C8FFDCDB3A38ULL,
		0xD6BCB79C0AE7DB22ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8B13B3EE08CBD9CDULL,
		0x8B66A53F1721EE00ULL,
		0x9C929C877C103251ULL,
		0x7AFC60AF9AB4C306ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 171\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x0731C9E6558F9EB3ULL,
		0x2CFC4D92C4F4965AULL,
		0x66E59BB9AFEA69FDULL,
		0xC279CBDED6F40E68ULL,
		0xB08D7D1F0B45B0B1ULL,
		0x7316122CCF6E8645ULL,
		0x5907D740977EEC4CULL,
		0x96DEA9B1195B7630ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3C325C8201E7DC63ULL,
		0x424300398F5C84B2ULL,
		0x9E0F8F502CC17D56ULL,
		0x2786FC289A879995ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 172\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xF0275727617AB9BFULL,
		0x4B29BD56F8708E05ULL,
		0xBFDB658A6C970329ULL,
		0x9CD392141A27E9D7ULL,
		0xA322D509AE419016ULL,
		0xA8D5D401106F8EB1ULL,
		0xFDE4E717DF9519DFULL,
		0x8DB2C7210CBF2930ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2752F6973F362034ULL,
		0x5AE7357F68FFBC64ULL,
		0x6FD5B3159CB8DA5CULL,
		0x255D20FBFE88071DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 173\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x4D8199C74B8B8C00ULL,
		0x0C57CB224AF04404ULL,
		0xC5AF32D406648211ULL,
		0x397517EB4B46AF3AULL,
		0xF7F727F47BCADB4DULL,
		0x569B9D727C957CD2ULL,
		0xA22EA3C1B800E3C1ULL,
		0xCD71484BC1CCA02CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1C318811ABA81DF5ULL,
		0xE7712A20C920CB55ULL,
		0xD89B8195568650C3ULL,
		0x3845D32A0FA675DAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 174\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xDB9E5AF2FEABA524ULL,
		0x8A8C2CE77A674ABFULL,
		0xFCFF2128FF2A679CULL,
		0xAF94B967777B4932ULL,
		0x9E8598392F3DC254ULL,
		0xDA7D848648434764ULL,
		0xA098307B976BC60EULL,
		0xC958B42F01AAE497ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6372F37001D68223ULL,
		0xF92DD8D63463E3AFULL,
		0xD39653817929CDD0ULL,
		0x12BF7861B6D937B4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 175\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x0BEACE3E59B13DC7ULL,
		0x90B2ACAF064E1E3DULL,
		0xE489D589C2F1DA5AULL,
		0xADF277860C4703DDULL,
		0x8949F8BDA5377761ULL,
		0xFA3122146B0051AEULL,
		0xDFBE4D6BA3C55384ULL,
		0x91881396E71468B5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6CE5BA64DFECF971ULL,
		0xB3FDBBB6E85A3E25ULL,
		0x1AC95384123C4017ULL,
		0x48255FEC594E8EDDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 176\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x11F9CD7873674837ULL,
		0xD0DB2F0E1DE92ADCULL,
		0xDE1DB7012AA30DE2ULL,
		0x51A8FD4E504F3B56ULL,
		0xD580DCC4473CDF8BULL,
		0x838AB5777D3D72B3ULL,
		0xC4F62B255E9BEF77ULL,
		0x9E1CB70DBA2A53DAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC31A929B06707A56ULL,
		0x57721ECAB508318DULL,
		0x1AA81E8D35C899A0ULL,
		0x49EC2957F297ADD0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 177\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x8A5864E63ABF1232ULL,
		0xDD9A9C7E4AC79782ULL,
		0xC94EEBF9AD6FBD69ULL,
		0x45B8C650481379DCULL,
		0x5EAD133951ADA437ULL,
		0x334D70FE293BB994ULL,
		0xC7606AFA558B71B6ULL,
		0x28D6E949ECAB2BDDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x98093F685A857340ULL,
		0x7B19623869A52388ULL,
		0x619ECD2260229E75ULL,
		0x559F6749697BFCC8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 178\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x817A7DEEC61A3E01ULL,
		0x7BCFFACA69CBE91EULL,
		0x392CC11CFC1B13E4ULL,
		0xF11317978D102751ULL,
		0x6EBD5FEC3D700F86ULL,
		0x6E7E71A44BEB0580ULL,
		0x8F63D80F98DE1655ULL,
		0x240A4D7E246FC8EBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF196BAFFE4BC8CC9ULL,
		0xE294D92DAEAEBA2EULL,
		0x81FED36DAD126492ULL,
		0x4A9A9850F5A7FA48ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 179\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x27121D6CF13A5634ULL,
		0x71B3BB025A8E47DEULL,
		0xD2230AF0E82FD231ULL,
		0x28CECFEB676F8690ULL,
		0x24D54708A03B5C7CULL,
		0x165E6B336FDC898BULL,
		0xEA08E6662187708DULL,
		0x8BD06C5E677CB1ADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9EBAA8B4BA0A13A7ULL,
		0xC3B7A4A4F54AB285ULL,
		0x8F753E19E24A8722ULL,
		0x69BEE5EEC3F1E661ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 180\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x480EAA1C3B5A5111ULL,
		0xD66E9D3993BC74B4ULL,
		0x6A11D1350E218BD6ULL,
		0x4738A823F796ABE5ULL,
		0x2FA3C6C6A77224D4ULL,
		0x85B8C4B1B8834594ULL,
		0x615AA65973633415ULL,
		0xCF4F9959BF957588ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5A5E2B99164BCD23ULL,
		0xAFDBCF9AF738C8B3ULL,
		0xDD86827C2EDB4708ULL,
		0x0D096B7667C61E23ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 181\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x3B9788AC6CF5BB51ULL,
		0x2D8F947AADD4EB26ULL,
		0x376337ADCBA55A82ULL,
		0x4D57AE342ADDFC2DULL,
		0xF4CC2C052D8BEC56ULL,
		0x653F2D5ECEC2CDEDULL,
		0x8FCDAA1647831763ULL,
		0xCA6A0982554129E5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x91E611712FBAD489ULL,
		0x34F0508D5EBF7C78ULL,
		0x8FEA76FC691AD343ULL,
		0x5915178CD28A3440ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 182\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xCB65D51FA1CA0298ULL,
		0x6628487B029997CBULL,
		0xCBC0A5429B0CFABDULL,
		0xE2E1372022A4CF2DULL,
		0xEEFF7EFC4F5B9A4BULL,
		0xFD998023692FC70DULL,
		0xB001100C47F183F1ULL,
		0xE655C88123943EECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4552AE936962EEECULL,
		0x0AF14DBC9FB123DDULL,
		0xEBE9071548E690A9ULL,
		0x139CFA4B6AA6264FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 183\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x36C5D65A01377BE4ULL,
		0x10637423554C0FE8ULL,
		0xCBC3CF43D76ED1CDULL,
		0x665220696DE7A73FULL,
		0xAC1DD22B18CC087EULL,
		0x870649EE969DC1A4ULL,
		0x149C187FBA3B8EA2ULL,
		0x24A7E67894709536ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC33308BFAF80BF69ULL,
		0x1B526D8DB0B6CE59ULL,
		0xDAEF72397C45FDEDULL,
		0x573E564F769DCD46ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 184\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xC2B46FC3CC6AD95BULL,
		0x63AD5E61B518724AULL,
		0x859A745EE8B037E5ULL,
		0x870C9A54012E5B72ULL,
		0xA0A6D02703E3C2C5ULL,
		0x45E632C05736D687ULL,
		0xBE1E4C81D1BC94F3ULL,
		0x39CC32A4B0AB9765ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9B77558E6039C3EFULL,
		0xC3D8E6EEA73C4A6CULL,
		0xBE19CFA40AAE5401ULL,
		0x1B5C1EC63AA6D48CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 185\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xE3A0CF0BB653F807ULL,
		0xEFD2DC4F7065CFC0ULL,
		0xE775871F515817DCULL,
		0x5F8E6DB818E3204BULL,
		0x65AB34D3DEDABE7BULL,
		0x19D5A4EAB78BAE4CULL,
		0xCC6C937D3B8E670FULL,
		0x8633BEEC9BE46652ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFB0AA67ECACC4141ULL,
		0xC5895726AF21AF17ULL,
		0x3F936BB6287B641AULL,
		0x4B3CC4D73CCA5096ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 186\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x0BFC5A02F370B95DULL,
		0x90F2FEB1437E0614ULL,
		0xB2D3CDA21CD62AE6ULL,
		0x1FD0ACFE607258A3ULL,
		0xBFADDE96DC36C61AULL,
		0xE78E5982EBB3138AULL,
		0x58539BE769DB2EEFULL,
		0xFFDA4BB003C4B11FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7FCB6467A39226DDULL,
		0xF01448204012ECACULL,
		0xCF3CF1FBD35F2282ULL,
		0x1A37E91EEFA4A34AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 187\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xF0651153E21D95D0ULL,
		0x94F41B0371B4DC56ULL,
		0xF6D3D8DD48BB7D1FULL,
		0x650159F5D3598D3DULL,
		0x20D155729BDDCDEDULL,
		0x5E5D5E9C35F7DD35ULL,
		0xF279DA3E2B09B76AULL,
		0x86FF838E0D8A94E3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCF77C057050A29F6ULL,
		0x96D02633747FB239ULL,
		0xF4EA3E17AC2CB6E9ULL,
		0x6EEEE10BD5EBA713ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 188\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xD86BED17408A6B6FULL,
		0x3956BAD6901840A6ULL,
		0xB23D96D3A94C7C64ULL,
		0x6A08761D5F478B41ULL,
		0x649DF2659ECE04EFULL,
		0x188D091517320232ULL,
		0x8FE22CFD9E8A90FAULL,
		0xE3E7600D36CAAF57ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC7DDE82CD31F2BF5ULL,
		0xDE4613F801849421ULL,
		0x0DD0447931DE0183ULL,
		0x3E60B813815D9241ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 189\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xEFA18845D1A217AFULL,
		0x7554E1B31B46F7A8ULL,
		0x4E1CDF18BFF5CAF7ULL,
		0xE3C70DC7FCC42842ULL,
		0x44B75D75A9FA58A0ULL,
		0x106831D2F2B3F36FULL,
		0xDDC0BB97A53A3D86ULL,
		0xE1EED1DF7E7E7AB7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x22D967BD0CCB447BULL,
		0xE4CC470321FD1A2DULL,
		0x38B8B79B469AECDDULL,
		0x6D3A34F4C38A5F8DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 190\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xB0A48ACCF6EB7009ULL,
		0xD9536CAA9BE8D043ULL,
		0x794B7B9143E50D63ULL,
		0xD6F7E72A933D3B73ULL,
		0xAB81DED4692A450AULL,
		0x6DA1195F0601088EULL,
		0x859A0E5BA58BF99DULL,
		0x0B0F775BCAF47749ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x25EB9E549331AFD1ULL,
		0x1F3D30C580101571ULL,
		0x4E299D2BD6AC1AC2ULL,
		0x7B439ECAB386F05DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 191\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xE2FEF2A4FF1C5519ULL,
		0x556E6D9A7CAC5FE3ULL,
		0x82CBF5FF84DAF317ULL,
		0x8037CCC7308425F3ULL,
		0x57D758A3E0D82963ULL,
		0xACBD5DB40C4B17E8ULL,
		0x355DF0F2A356A244ULL,
		0xF0E2ED855FE802A3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xECF61AF85F327F23ULL,
		0xF98A56544FD1EC60ULL,
		0x6EBDBA03C3B70948ULL,
		0x41E70E936CF48A2DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 192\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x20C2A2B30821BABCULL,
		0x5F69F84A9E2329BCULL,
		0xFE2F1887E8546E9BULL,
		0x20420A680B772D1FULL,
		0xCB34F0E68C3BE214ULL,
		0x0A88F2215E0D99ADULL,
		0x49FC3DDB9CD00A79ULL,
		0xA1DAD2314BD5AC01ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4A9E64EBD9054D44ULL,
		0xEFBDE93E9427F988ULL,
		0xF9A047212F35FC92ULL,
		0x26BD3DB94D2EB550ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 193\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x204AB5E6D69142BCULL,
		0x638197442F73EA44ULL,
		0xBD7EBC35FBC6AA7CULL,
		0x4A9CFB39FF38F7FAULL,
		0xF32978773EA7557DULL,
		0xA681C7641C801D65ULL,
		0x3DA76237D2001169ULL,
		0x9CD5E388E42E41D1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3872979A2367F6C7ULL,
		0x1AC530206A784766ULL,
		0xE457507F27C9402BULL,
		0x125CC18BDE16BD09ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 194\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xA3DBC1BF3895ADEBULL,
		0x99EFA3D9E16FC3E9ULL,
		0xA89971E287EA463DULL,
		0x5AA477C364FA88FEULL,
		0x27138F166E9DF41DULL,
		0x03CA76D9FB3F01B8ULL,
		0x519A3924606DAD51ULL,
		0x64E3B7134C44CC4EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x70C2FF13A407EC73ULL,
		0x29FD48352CCA053FULL,
		0xC57DED48D8320044ULL,
		0x5471A4A0B730DC9EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 195\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xB2C926010FE6D437ULL,
		0x900E12B5DE0BDDABULL,
		0x8F6DAA584BFDA5BDULL,
		0xB62DEF8F2BAC8E73ULL,
		0xBA9630AB7E259055ULL,
		0x77B1E62B0F533CF8ULL,
		0xFDA87CC6BAA63D24ULL,
		0xE46EB08E9D073E3DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x65145F75C97A45F4ULL,
		0x54763D1A2466EA97ULL,
		0x36702FD800AAB927ULL,
		0x1E9C24BA7ABFCBA7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 196\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xCD752174B79B6A0CULL,
		0xE08FBC775628D75DULL,
		0xB5A73EFC31A14884ULL,
		0x0825455A25D65810ULL,
		0xD3A3F85A2FD235ADULL,
		0xAEA8F057EA681ED7ULL,
		0x38C8128803CF9058ULL,
		0x6551CC959065151FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x37CBFED7D0CF63F4ULL,
		0xCDA36984219D6B67ULL,
		0x2359FF2CC270B5AEULL,
		0x1249A38D94D77AB3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 197\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x9EFAB48D942DBCFCULL,
		0x325DA7982223FB80ULL,
		0xBC182F8E97AEF0C3ULL,
		0xC38255C51E8C74D8ULL,
		0x94A36148A231DACCULL,
		0x8AEE67460F991C48ULL,
		0x5BACDF3ACCB94EBFULL,
		0x7AFD9CD10540BAFCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF3B2555A7943A16ULL,
		0xD1C0FBFE72DE2E46ULL,
		0x57C15248FB30A131ULL,
		0x05279CCBE628364EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 198\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xDF1BE1421A874203ULL,
		0xB35B6CF89F6F73A9ULL,
		0x925BF712D13D5347ULL,
		0x6AF0DF4902EE5C07ULL,
		0x077971E9941B7BF1ULL,
		0x6840C43D5ABB236CULL,
		0x77035CACBC96BA48ULL,
		0xFD331305F113A4CBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFB22C9EE169BAD6DULL,
		0x2CF88E141736B5B2ULL,
		0x3CDBB8B6CF9CFA07ULL,
		0x0085B22ACBD8D23BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 199\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xD5BDF9AB9A09EC41ULL,
		0xD98B9AD5ABFFC953ULL,
		0x5641722EF4969F50ULL,
		0xB8088E918BD0B069ULL,
		0x67C03AA5324788BAULL,
		0xF892B01B4878B037ULL,
		0xA315EC6620936968ULL,
		0xFCFDC5F65C662B06ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3C46AE3110A83D81ULL,
		0xBF51BEE26DE9F18DULL,
		0x8B828957CA7844E5ULL,
		0x45B3F12342FB1365ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 200\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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