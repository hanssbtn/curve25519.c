#include "../tests.h"

int32_t curve25519_key_x2_inplace_test(void) {
	printf("Inplace Key Doubling Test\n");
	curve25519_key_t k1 = {.key64 = {
		0x38A95419E08F88A6ULL,
		0x66E70B1C9FCE061EULL,
		0x07B491203C006B77ULL,
		0xF3DBCACC993A970AULL,
		0xD09F04E74B6FF62CULL,
		0x0D951A0518C87446ULL,
		0xFD92043A8246137CULL,
		0x13749AB189EE85F8ULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0x7152A833C11F114CULL,
		0xCDCE16393F9C0C3CULL,
		0x0F6922407800D6EEULL,
		0xE7B7959932752E14ULL,
		0xA13E09CE96DFEC59ULL,
		0x1B2A340A3190E88DULL,
		0xFB240875048C26F8ULL,
		0x26E9356313DD0BF1ULL
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
		curve25519_key_printf(&k1, COMPLETE);
		return -1;
	} else {
		printf("Test Case 1 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x44B230A33EE13559ULL,
		0x004122C3A99B62A2ULL,
		0x1947C80300F4886AULL,
		0xDF370D8E5F86F172ULL,
		0xF1D60FA22B1B288CULL,
		0x01FADC7F66811A60ULL,
		0x0F81853473EC3559ULL,
		0x309F0D48DB47E9C7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x896461467DC26AB2ULL,
		0x008245875336C544ULL,
		0x328F900601E910D4ULL,
		0xBE6E1B1CBF0DE2E4ULL,
		0xE3AC1F4456365119ULL,
		0x03F5B8FECD0234C1ULL,
		0x1F030A68E7D86AB2ULL,
		0x613E1A91B68FD38EULL
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
		curve25519_key_printf(&k1, COMPLETE);
		return -2;
	} else {
		printf("Test Case 2 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4FA3D162949DA018ULL,
		0x9D6861E218EFD1F2ULL,
		0xE3374EB06AFCB9DAULL,
		0x2DA294B22ECD3AA3ULL,
		0x23457390B71B4AC3ULL,
		0x2DBD6C6E594A20AEULL,
		0x61BB21525B3DCC19ULL,
		0x1636CC61C54E07AFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9F47A2C5293B4030ULL,
		0x3AD0C3C431DFA3E4ULL,
		0xC66E9D60D5F973B5ULL,
		0x5B4529645D9A7547ULL,
		0x468AE7216E369586ULL,
		0x5B7AD8DCB294415CULL,
		0xC37642A4B67B9832ULL,
		0x2C6D98C38A9C0F5EULL
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
		curve25519_key_printf(&k1, COMPLETE);
		return -3;
	} else {
		printf("Test Case 3 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA77A7B1C83B16009ULL,
		0x9A2929A6A727E3B4ULL,
		0xEBD6FB988A55999AULL,
		0x79640596592779ABULL,
		0xF66FCD4DA552383AULL,
		0xC252A300319882B4ULL,
		0x52DDE0D870304C6BULL,
		0x1DD30656E8E6E34BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4EF4F6390762C012ULL,
		0x3452534D4E4FC769ULL,
		0xD7ADF73114AB3335ULL,
		0xF2C80B2CB24EF357ULL,
		0xECDF9A9B4AA47074ULL,
		0x84A5460063310569ULL,
		0xA5BBC1B0E06098D7ULL,
		0x3BA60CADD1CDC696ULL
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
		curve25519_key_printf(&k1, COMPLETE);
		return -4;
	} else {
		printf("Test Case 4 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x463CC19C1FE1953AULL,
		0x10E6A3822340321BULL,
		0xB958B93BF3F8F619ULL,
		0xBBB4972508F52F2AULL,
		0xC0A551DEAD28ECEFULL,
		0xFCB1A9D9BEC2753AULL,
		0xD255008D23936A10ULL,
		0x3C5B0D7CB4080647ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8C7983383FC32A74ULL,
		0x21CD470446806436ULL,
		0x72B17277E7F1EC32ULL,
		0x77692E4A11EA5E55ULL,
		0x814AA3BD5A51D9DFULL,
		0xF96353B37D84EA75ULL,
		0xA4AA011A4726D421ULL,
		0x78B61AF968100C8FULL
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
		curve25519_key_printf(&k1, COMPLETE);
		return -5;
	} else {
		printf("Test Case 5 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7FC94F28CFD8D0A8ULL,
		0x1B784BA301D7A4A1ULL,
		0x06243CD0FC774BF0ULL,
		0xD0E8BD30363C13DDULL,
		0x8BB6795AFFB5969FULL,
		0x3CB96667F31C0EF2ULL,
		0xD4783CBE82B57E2AULL,
		0x3C71DAD0384D2B6BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFF929E519FB1A150ULL,
		0x36F0974603AF4942ULL,
		0x0C4879A1F8EE97E0ULL,
		0xA1D17A606C7827BAULL,
		0x176CF2B5FF6B2D3FULL,
		0x7972CCCFE6381DE5ULL,
		0xA8F0797D056AFC54ULL,
		0x78E3B5A0709A56D7ULL
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
		curve25519_key_printf(&k1, COMPLETE);
		return -6;
	} else {
		printf("Test Case 6 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0C1838BCB946510BULL,
		0xE678FA7D7DDD26CDULL,
		0xD1D4FEEEFC74B6BBULL,
		0x5BCED68567C20F4FULL,
		0xA01573E03AF7B2D4ULL,
		0xFB8D2A2D4246F63EULL,
		0x49505610BA68191EULL,
		0x2D3C441C035C4677ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x18307179728CA216ULL,
		0xCCF1F4FAFBBA4D9AULL,
		0xA3A9FDDDF8E96D77ULL,
		0xB79DAD0ACF841E9FULL,
		0x402AE7C075EF65A8ULL,
		0xF71A545A848DEC7DULL,
		0x92A0AC2174D0323DULL,
		0x5A78883806B88CEEULL
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
		curve25519_key_printf(&k1, COMPLETE);
		return -7;
	} else {
		printf("Test Case 7 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1BEF2E3142B23D9FULL,
		0x547F43A890D4DA25ULL,
		0x88F769CCD43B6661ULL,
		0x335B611E622FE2FCULL,
		0x44AF438A994FDC54ULL,
		0xE69785AEBE29862FULL,
		0xF6D53DD16F424B02ULL,
		0x18663EF6DCCD08B4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x37DE5C6285647B3EULL,
		0xA8FE875121A9B44AULL,
		0x11EED399A876CCC2ULL,
		0x66B6C23CC45FC5F9ULL,
		0x895E8715329FB8A8ULL,
		0xCD2F0B5D7C530C5EULL,
		0xEDAA7BA2DE849605ULL,
		0x30CC7DEDB99A1169ULL
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
		curve25519_key_printf(&k1, COMPLETE);
		return -8;
	} else {
		printf("Test Case 8 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1DE1E342E2F453F1ULL,
		0x46CF7DA339B66ACCULL,
		0x97730626EF59262FULL,
		0x1215CE567985DC45ULL,
		0x2B67983D098F04BAULL,
		0x1E72A1A5B7834B53ULL,
		0xF55376FFB5376C9BULL,
		0x3A4E4BF72CFA895DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3BC3C685C5E8A7E2ULL,
		0x8D9EFB46736CD598ULL,
		0x2EE60C4DDEB24C5EULL,
		0x242B9CACF30BB88BULL,
		0x56CF307A131E0974ULL,
		0x3CE5434B6F0696A6ULL,
		0xEAA6EDFF6A6ED936ULL,
		0x749C97EE59F512BBULL
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
		curve25519_key_printf(&k1, COMPLETE);
		return -9;
	} else {
		printf("Test Case 9 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB75166FA4153B548ULL,
		0x3D34EF44900A871AULL,
		0x2C1AA4956DBCB3BFULL,
		0xED20EB7AAD0EF25EULL,
		0xF3BFEB17665827D7ULL,
		0xC65BE7348B22BECDULL,
		0x56FC64895B16A2CEULL,
		0x1E39CC1C529DAB1DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6EA2CDF482A76A90ULL,
		0x7A69DE8920150E35ULL,
		0x5835492ADB79677EULL,
		0xDA41D6F55A1DE4BCULL,
		0xE77FD62ECCB04FAFULL,
		0x8CB7CE6916457D9BULL,
		0xADF8C912B62D459DULL,
		0x3C739838A53B563AULL
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
		curve25519_key_printf(&k1, COMPLETE);
		return -10;
	} else {
		printf("Test Case 10 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x75233C7D0C36AB9CULL,
		0x1F092A88D4D7026FULL,
		0x5960D258A0338F6AULL,
		0xE8FE4AEBA662E379ULL,
		0xFEBA9A0284D19ECDULL,
		0x74BFF7E4D10F1A7DULL,
		0xE012A4B2CBF2F1FFULL,
		0x131AC02A42F0F371ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEA4678FA186D5738ULL,
		0x3E125511A9AE04DEULL,
		0xB2C1A4B140671ED4ULL,
		0xD1FC95D74CC5C6F2ULL,
		0xFD75340509A33D9BULL,
		0xE97FEFC9A21E34FBULL,
		0xC025496597E5E3FEULL,
		0x2635805485E1E6E3ULL
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
		curve25519_key_printf(&k1, COMPLETE);
		return -11;
	} else {
		printf("Test Case 11 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCFE1572930EDEE2DULL,
		0x0FF1B19728B1D002ULL,
		0x70BE5FC0176B2FEBULL,
		0x62550BC0D87C5B54ULL,
		0x8A990912E93A1CA6ULL,
		0x4492F3534E48752EULL,
		0x47C0C9EFFC2BA799ULL,
		0x203D8FCC22EFC736ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9FC2AE5261DBDC5AULL,
		0x1FE3632E5163A005ULL,
		0xE17CBF802ED65FD6ULL,
		0xC4AA1781B0F8B6A8ULL,
		0x15321225D274394CULL,
		0x8925E6A69C90EA5DULL,
		0x8F8193DFF8574F32ULL,
		0x407B1F9845DF8E6CULL
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
		curve25519_key_printf(&k1, COMPLETE);
		return -12;
	} else {
		printf("Test Case 12 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBC9472F9D3400B4FULL,
		0x7422014045EC74CFULL,
		0x58C0F315CC33C8DCULL,
		0x6623F5C7A9C7F588ULL,
		0xD52D6FB61859E06CULL,
		0xE7465F55947EFFD8ULL,
		0x1E623AA8F17C3C73ULL,
		0x0ED610283318CED1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7928E5F3A680169EULL,
		0xE84402808BD8E99FULL,
		0xB181E62B986791B8ULL,
		0xCC47EB8F538FEB10ULL,
		0xAA5ADF6C30B3C0D8ULL,
		0xCE8CBEAB28FDFFB1ULL,
		0x3CC47551E2F878E7ULL,
		0x1DAC205066319DA2ULL
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
		curve25519_key_printf(&k1, COMPLETE);
		return -13;
	} else {
		printf("Test Case 13 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1453D3BD8DD2F4CDULL,
		0xDAD8E49D519AD43EULL,
		0x84DB67FEBFABD1E6ULL,
		0xF46CA66C785A236DULL,
		0x5A42EE4316DE007CULL,
		0x08708B0A19BE9853ULL,
		0x7CD00D305542FB37ULL,
		0x3053D9D72FCE4B0AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x28A7A77B1BA5E99AULL,
		0xB5B1C93AA335A87CULL,
		0x09B6CFFD7F57A3CDULL,
		0xE8D94CD8F0B446DBULL,
		0xB485DC862DBC00F9ULL,
		0x10E11614337D30A6ULL,
		0xF9A01A60AA85F66EULL,
		0x60A7B3AE5F9C9614ULL
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
		curve25519_key_printf(&k1, COMPLETE);
		return -14;
	} else {
		printf("Test Case 14 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3E3D61267570085DULL,
		0x9FB51698F97F72C1ULL,
		0x88BEA3FA94B64CAEULL,
		0x29A254C197C5D99EULL,
		0x486AE2E0ABC23D81ULL,
		0x41E924A71D66EFD7ULL,
		0xEED8D6B032C9F246ULL,
		0x1DDBBFF2A6DB26C7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7C7AC24CEAE010BAULL,
		0x3F6A2D31F2FEE582ULL,
		0x117D47F5296C995DULL,
		0x5344A9832F8BB33DULL,
		0x90D5C5C157847B02ULL,
		0x83D2494E3ACDDFAEULL,
		0xDDB1AD606593E48CULL,
		0x3BB77FE54DB64D8FULL
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
		curve25519_key_printf(&k1, COMPLETE);
		return -15;
	} else {
		printf("Test Case 15 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4E0BC6FAE87A08CEULL,
		0xEA159BBA4EC3AC65ULL,
		0x6EB4BB943CB6752EULL,
		0xD30E311076E17872ULL,
		0x2C4F09568ACB55E5ULL,
		0xFF584C02F445D73CULL,
		0xFF933FCC193AA37CULL,
		0x09826FA27A94A4CEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9C178DF5D0F4119CULL,
		0xD42B37749D8758CAULL,
		0xDD697728796CEA5DULL,
		0xA61C6220EDC2F0E4ULL,
		0x589E12AD1596ABCBULL,
		0xFEB09805E88BAE78ULL,
		0xFF267F98327546F9ULL,
		0x1304DF44F529499DULL
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
		curve25519_key_printf(&k1, COMPLETE);
		return -16;
	} else {
		printf("Test Case 16 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x424E190F06EF5CB3ULL,
		0x23682F1FF13911A1ULL,
		0x1E59846BB880E2F6ULL,
		0xB5BC0A757163DE9EULL,
		0x0B14B406EBC85977ULL,
		0x6DEC2389C308FCEDULL,
		0x3F0A23B600B0C362ULL,
		0x0D98DBDD70882199ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x849C321E0DDEB966ULL,
		0x46D05E3FE2722342ULL,
		0x3CB308D77101C5ECULL,
		0x6B7814EAE2C7BD3CULL,
		0x1629680DD790B2EFULL,
		0xDBD847138611F9DAULL,
		0x7E14476C016186C4ULL,
		0x1B31B7BAE1104332ULL
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
		curve25519_key_printf(&k1, COMPLETE);
		return -17;
	} else {
		printf("Test Case 17 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFD30B984B240DF87ULL,
		0x8BD7942784F2DCFBULL,
		0x8D7AA4BA56BEF414ULL,
		0x1CA982A861DD7126ULL,
		0x29297E2577382DACULL,
		0xCE829A1E05A12331ULL,
		0xB74EA0B52ED42CEEULL,
		0x391672D72368BF67ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFA6173096481BF0EULL,
		0x17AF284F09E5B9F7ULL,
		0x1AF54974AD7DE829ULL,
		0x39530550C3BAE24DULL,
		0x5252FC4AEE705B58ULL,
		0x9D05343C0B424662ULL,
		0x6E9D416A5DA859DDULL,
		0x722CE5AE46D17ECFULL
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
		curve25519_key_printf(&k1, COMPLETE);
		return -18;
	} else {
		printf("Test Case 18 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCF028125F8B06654ULL,
		0x68C861CB56664EB6ULL,
		0xF34F52CE3A34F424ULL,
		0x91BE34F7E3B3BFFCULL,
		0x9991EBFD6E5C3A5EULL,
		0x206B8D0926AF0036ULL,
		0x429101BBD9920E38ULL,
		0x2EAA0920B3590F39ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9E05024BF160CCA8ULL,
		0xD190C396ACCC9D6DULL,
		0xE69EA59C7469E848ULL,
		0x237C69EFC7677FF9ULL,
		0x3323D7FADCB874BDULL,
		0x40D71A124D5E006DULL,
		0x85220377B3241C70ULL,
		0x5D54124166B21E72ULL
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
		curve25519_key_printf(&k1, COMPLETE);
		return -19;
	} else {
		printf("Test Case 19 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC8B7F39179656C4FULL,
		0x39E64DE145CC8B96ULL,
		0xA2CC2D0FCBABFCA5ULL,
		0x096A8EE517BE9F92ULL,
		0xF41D48218E0C4FEAULL,
		0xE942F897853786E0ULL,
		0x7BB9312B91A20EB5ULL,
		0x352ECE501FA4E12BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x916FE722F2CAD89EULL,
		0x73CC9BC28B99172DULL,
		0x45985A1F9757F94AULL,
		0x12D51DCA2F7D3F25ULL,
		0xE83A90431C189FD4ULL,
		0xD285F12F0A6F0DC1ULL,
		0xF772625723441D6BULL,
		0x6A5D9CA03F49C256ULL
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
		curve25519_key_printf(&k1, COMPLETE);
		return -20;
	} else {
		printf("Test Case 20 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4742BD4C38B2AE24ULL,
		0xC9456A5F9ED8D4E1ULL,
		0x236E43C164C2D93EULL,
		0x5DC883E2E4DA5A3CULL,
		0xA4316A991F47FEBFULL,
		0xD6037ABDCCE38C04ULL,
		0xB920018D43B4AA72ULL,
		0x0CE3C5602521DB50ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8E857A9871655C48ULL,
		0x928AD4BF3DB1A9C2ULL,
		0x46DC8782C985B27DULL,
		0xBB9107C5C9B4B478ULL,
		0x4862D5323E8FFD7EULL,
		0xAC06F57B99C71809ULL,
		0x7240031A876954E5ULL,
		0x19C78AC04A43B6A1ULL
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
		curve25519_key_printf(&k1, COMPLETE);
		return -21;
	} else {
		printf("Test Case 21 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE37AEC7F12FF0237ULL,
		0x43F35D0C0E06D805ULL,
		0x793D7D2F4D4D66EFULL,
		0xA3570FA404753E04ULL,
		0x2C7E3AA365C33A4FULL,
		0xC15F88FDE0814718ULL,
		0xA5E1E6FC729ED381ULL,
		0x2FA2EB6F8091A044ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC6F5D8FE25FE046EULL,
		0x87E6BA181C0DB00BULL,
		0xF27AFA5E9A9ACDDEULL,
		0x46AE1F4808EA7C08ULL,
		0x58FC7546CB86749FULL,
		0x82BF11FBC1028E30ULL,
		0x4BC3CDF8E53DA703ULL,
		0x5F45D6DF01234089ULL
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
		curve25519_key_printf(&k1, COMPLETE);
		return -22;
	} else {
		printf("Test Case 22 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x24C07A51261AD2B2ULL,
		0xD204B31921B7BEF8ULL,
		0xD5BA57C9BCE29909ULL,
		0xA819C7FBDDB817D5ULL,
		0x7E90F6235C8E1A68ULL,
		0x18FB09C084500B84ULL,
		0x6775D8495377E2CEULL,
		0x2EF817DF2DC5EE23ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4980F4A24C35A564ULL,
		0xA4096632436F7DF0ULL,
		0xAB74AF9379C53213ULL,
		0x50338FF7BB702FABULL,
		0xFD21EC46B91C34D1ULL,
		0x31F6138108A01708ULL,
		0xCEEBB092A6EFC59CULL,
		0x5DF02FBE5B8BDC46ULL
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
		curve25519_key_printf(&k1, COMPLETE);
		return -23;
	} else {
		printf("Test Case 23 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4D6E514508E07288ULL,
		0x9944E62B79EE66BFULL,
		0x44D2B16DD5819724ULL,
		0x9A3B8B156D64A98DULL,
		0xF1F610687DA1879EULL,
		0xE8078D8847E0692BULL,
		0xBB192425FEB06AA2ULL,
		0x2F68800054FA9593ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9ADCA28A11C0E510ULL,
		0x3289CC56F3DCCD7EULL,
		0x89A562DBAB032E49ULL,
		0x3477162ADAC9531AULL,
		0xE3EC20D0FB430F3DULL,
		0xD00F1B108FC0D257ULL,
		0x7632484BFD60D545ULL,
		0x5ED10000A9F52B27ULL
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
		curve25519_key_printf(&k1, COMPLETE);
		return -24;
	} else {
		printf("Test Case 24 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB78DC25F1CFDA41CULL,
		0xD64DAF5DD88967C9ULL,
		0xDBB4FD1E5CD1F84DULL,
		0xDFB3864488DEC43BULL,
		0x87D8ED14B86CC9D1ULL,
		0x3C38C8AD700018A2ULL,
		0xD7DF78749FB34F37ULL,
		0x18CE77205278D8A4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6F1B84BE39FB4838ULL,
		0xAC9B5EBBB112CF93ULL,
		0xB769FA3CB9A3F09BULL,
		0xBF670C8911BD8877ULL,
		0x0FB1DA2970D993A3ULL,
		0x7871915AE0003145ULL,
		0xAFBEF0E93F669E6EULL,
		0x319CEE40A4F1B149ULL
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
		curve25519_key_printf(&k1, COMPLETE);
		return -25;
	} else {
		printf("Test Case 25 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9FFAD1992BE66533ULL,
		0x61DC8E352D5C8E68ULL,
		0x9F7EC3CDF9E6EC3DULL,
		0x049BD75CADFC4267ULL,
		0xCAC55B0994FE68AAULL,
		0x54D3DC3ABA742E91ULL,
		0x98A02407496BDD6EULL,
		0x2F2927CEA8E622D5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3FF5A33257CCCA66ULL,
		0xC3B91C6A5AB91CD1ULL,
		0x3EFD879BF3CDD87AULL,
		0x0937AEB95BF884CFULL,
		0x958AB61329FCD154ULL,
		0xA9A7B87574E85D23ULL,
		0x3140480E92D7BADCULL,
		0x5E524F9D51CC45ABULL
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
		curve25519_key_printf(&k1, COMPLETE);
		return -26;
	} else {
		printf("Test Case 26 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB416979CA969A40CULL,
		0x93AC206203FCEC56ULL,
		0xD23FD1C23BB38DFEULL,
		0x4E3D31D8840B65AAULL,
		0xD6109A1F34B3BB1AULL,
		0xDF66A8E14EF4E03AULL,
		0x838FAB5DCC67FC17ULL,
		0x1A9FC6E5673356CAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x682D2F3952D34818ULL,
		0x275840C407F9D8ADULL,
		0xA47FA38477671BFDULL,
		0x9C7A63B10816CB55ULL,
		0xAC21343E69677634ULL,
		0xBECD51C29DE9C075ULL,
		0x071F56BB98CFF82FULL,
		0x353F8DCACE66AD95ULL
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
		curve25519_key_printf(&k1, COMPLETE);
		return -27;
	} else {
		printf("Test Case 27 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB553AFB93BE0F56EULL,
		0xB76B13AAF8E065BBULL,
		0x7D799B71B4DC63BAULL,
		0xDD8BE17CB49773F8ULL,
		0x918E1E7D6DA9E53CULL,
		0x43040550F8902D81ULL,
		0xB77A49DFD00B9910ULL,
		0x39120E32A81089BCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6AA75F7277C1EADCULL,
		0x6ED62755F1C0CB77ULL,
		0xFAF336E369B8C775ULL,
		0xBB17C2F9692EE7F0ULL,
		0x231C3CFADB53CA79ULL,
		0x86080AA1F1205B03ULL,
		0x6EF493BFA0173220ULL,
		0x72241C6550211379ULL
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
		curve25519_key_printf(&k1, COMPLETE);
		return -28;
	} else {
		printf("Test Case 28 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAE948386A23A50E1ULL,
		0x7D264887E6F9BD32ULL,
		0xA95743DB422C293CULL,
		0x3E93A7CFD5F302B2ULL,
		0x4FC996B6B095C85AULL,
		0x32C6C07C5383C83CULL,
		0xF1DBEA70B5A03057ULL,
		0x1A1F263657282BE9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5D29070D4474A1C2ULL,
		0xFA4C910FCDF37A65ULL,
		0x52AE87B684585278ULL,
		0x7D274F9FABE60565ULL,
		0x9F932D6D612B90B4ULL,
		0x658D80F8A7079078ULL,
		0xE3B7D4E16B4060AEULL,
		0x343E4C6CAE5057D3ULL
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
		curve25519_key_printf(&k1, COMPLETE);
		return -29;
	} else {
		printf("Test Case 29 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2E6FB8DCB54B55A7ULL,
		0x93B318A13B32C630ULL,
		0xE157617031341F61ULL,
		0x45653C5B6384A2FDULL,
		0x2E1CFEEC37E080EFULL,
		0xC2EA7F542AB1403CULL,
		0xF202C6FFABA82B89ULL,
		0x01FB1D63998D7A52ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5CDF71B96A96AB4EULL,
		0x2766314276658C60ULL,
		0xC2AEC2E062683EC3ULL,
		0x8ACA78B6C70945FBULL,
		0x5C39FDD86FC101DEULL,
		0x85D4FEA855628078ULL,
		0xE4058DFF57505713ULL,
		0x03F63AC7331AF4A5ULL
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
		curve25519_key_printf(&k1, COMPLETE);
		return -30;
	} else {
		printf("Test Case 30 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6BD0BDC8868CC29CULL,
		0xD9ED06546B4A6A17ULL,
		0xF64A7B84DF42C9EAULL,
		0xC567B0121FFBB283ULL,
		0x74FF14457A8F25E0ULL,
		0x50C70A74978BFBC5ULL,
		0x8B7D8BB11C0FE595ULL,
		0x220F86FF2B390D09ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD7A17B910D198538ULL,
		0xB3DA0CA8D694D42EULL,
		0xEC94F709BE8593D5ULL,
		0x8ACF60243FF76507ULL,
		0xE9FE288AF51E4BC1ULL,
		0xA18E14E92F17F78AULL,
		0x16FB1762381FCB2AULL,
		0x441F0DFE56721A13ULL
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
		curve25519_key_printf(&k1, COMPLETE);
		return -31;
	} else {
		printf("Test Case 31 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8FCD8E49C86FE4C3ULL,
		0x983C3EF47FCE5333ULL,
		0xD2C652C13C451F12ULL,
		0x2DC83606FAE4FCCAULL,
		0xF928170DACD3AF55ULL,
		0x25E8F7C28A9CABF0ULL,
		0x583C1B6689ED514FULL,
		0x219168D8B6A2B128ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1F9B1C9390DFC986ULL,
		0x30787DE8FF9CA667ULL,
		0xA58CA582788A3E25ULL,
		0x5B906C0DF5C9F995ULL,
		0xF2502E1B59A75EAAULL,
		0x4BD1EF85153957E1ULL,
		0xB07836CD13DAA29EULL,
		0x4322D1B16D456250ULL
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
		curve25519_key_printf(&k1, COMPLETE);
		return -32;
	} else {
		printf("Test Case 32 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA3D644E19772A96CULL,
		0x5C2204C633B5FD23ULL,
		0xD711B91078A21255ULL,
		0x02968C02A82B8B9CULL,
		0x1442924A25DADBEEULL,
		0x964229ADFF1F8371ULL,
		0x3E119400A806F2C6ULL,
		0x08022F7413C75C20ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x47AC89C32EE552D8ULL,
		0xB844098C676BFA47ULL,
		0xAE237220F14424AAULL,
		0x052D180550571739ULL,
		0x288524944BB5B7DCULL,
		0x2C84535BFE3F06E2ULL,
		0x7C232801500DE58DULL,
		0x10045EE8278EB840ULL
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
		curve25519_key_printf(&k1, COMPLETE);
		return -33;
	} else {
		printf("Test Case 33 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x28119266092298CDULL,
		0x8FE6ECA191EB83D0ULL,
		0x267A16BED458BECAULL,
		0xFBDB5C1069D18582ULL,
		0x2AEFBB0E6216432EULL,
		0xCBC871723965DAA6ULL,
		0x093DF1E7FD41141DULL,
		0x13B29477031AF7CCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x502324CC1245319AULL,
		0x1FCDD94323D707A0ULL,
		0x4CF42D7DA8B17D95ULL,
		0xF7B6B820D3A30B04ULL,
		0x55DF761CC42C865DULL,
		0x9790E2E472CBB54CULL,
		0x127BE3CFFA82283BULL,
		0x276528EE0635EF98ULL
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
		curve25519_key_printf(&k1, COMPLETE);
		return -34;
	} else {
		printf("Test Case 34 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCB8D7F94EF71A11EULL,
		0xA64DFD13205231FBULL,
		0x2AF7CC6A78E530DEULL,
		0xBD19F4D09EB7E1CBULL,
		0xE17313FAA651BA65ULL,
		0x55682656D81D5A81ULL,
		0x474A7740C4E0FD06ULL,
		0x1A0C0B069B823417ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x971AFF29DEE3423CULL,
		0x4C9BFA2640A463F7ULL,
		0x55EF98D4F1CA61BDULL,
		0x7A33E9A13D6FC396ULL,
		0xC2E627F54CA374CBULL,
		0xAAD04CADB03AB503ULL,
		0x8E94EE8189C1FA0CULL,
		0x3418160D3704682EULL
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
		curve25519_key_printf(&k1, COMPLETE);
		return -35;
	} else {
		printf("Test Case 35 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x87E058B2AA1335E7ULL,
		0xD84692DE537AAF8DULL,
		0x90BE70DB23B37A59ULL,
		0xA0AB23BB98CD8354ULL,
		0x8BC06D7B59DCAFC7ULL,
		0x40F1BB8EBB2B2B9BULL,
		0xC22C042A3C28BBB2ULL,
		0x11A65234A1BDF63EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0FC0B16554266BCEULL,
		0xB08D25BCA6F55F1BULL,
		0x217CE1B64766F4B3ULL,
		0x41564777319B06A9ULL,
		0x1780DAF6B3B95F8FULL,
		0x81E3771D76565737ULL,
		0x8458085478517764ULL,
		0x234CA469437BEC7DULL
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
		curve25519_key_printf(&k1, COMPLETE);
		return -36;
	} else {
		printf("Test Case 36 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAE7BF93B03BBE69EULL,
		0x8AA19B590D7388D1ULL,
		0xC3194A1B20F3F9E6ULL,
		0xA8E7B756B7CC732EULL,
		0xD0506AB3ED29D57EULL,
		0xFEC28879F6969452ULL,
		0x6D922FD17F9E36AAULL,
		0x3EF8865694A682A9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5CF7F2760777CD3CULL,
		0x154336B21AE711A3ULL,
		0x8632943641E7F3CDULL,
		0x51CF6EAD6F98E65DULL,
		0xA0A0D567DA53AAFDULL,
		0xFD8510F3ED2D28A5ULL,
		0xDB245FA2FF3C6D55ULL,
		0x7DF10CAD294D0552ULL
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
		curve25519_key_printf(&k1, COMPLETE);
		return -37;
	} else {
		printf("Test Case 37 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x17688C36005DE4F0ULL,
		0x1D0CD1572DB9AA64ULL,
		0x7CBE3499246DD431ULL,
		0x340C79201E47918EULL,
		0x38B31121B3089103ULL,
		0x427E23B063F2C15FULL,
		0x15F3D35DB4731E99ULL,
		0x111F698709D8974DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2ED1186C00BBC9E0ULL,
		0x3A19A2AE5B7354C8ULL,
		0xF97C693248DBA862ULL,
		0x6818F2403C8F231CULL,
		0x7166224366112206ULL,
		0x84FC4760C7E582BEULL,
		0x2BE7A6BB68E63D32ULL,
		0x223ED30E13B12E9AULL
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
		curve25519_key_printf(&k1, COMPLETE);
		return -38;
	} else {
		printf("Test Case 38 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8604A8445EF1F689ULL,
		0x6F8CA01DB5158132ULL,
		0xF8EECAF4B3132A4BULL,
		0x74AFDECE9D54802BULL,
		0x6F99BBDB259F943AULL,
		0xE2FF99557F8EF437ULL,
		0x3BE672B73A85A37FULL,
		0x2C9D675128CBE1FBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0C095088BDE3ED12ULL,
		0xDF19403B6A2B0265ULL,
		0xF1DD95E966265496ULL,
		0xE95FBD9D3AA90057ULL,
		0xDF3377B64B3F2874ULL,
		0xC5FF32AAFF1DE86EULL,
		0x77CCE56E750B46FFULL,
		0x593ACEA25197C3F6ULL
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
		curve25519_key_printf(&k1, COMPLETE);
		return -39;
	} else {
		printf("Test Case 39 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x07A1512D9ECDEBE9ULL,
		0xDB3483B56B7C8BCBULL,
		0x01688CC7C2299FCBULL,
		0x3113E4F26F52AF42ULL,
		0x9F1ABFAD9C16BE3EULL,
		0xCFE3EB9290C4F3B2ULL,
		0x2FD4CDB12E5CFF49ULL,
		0x24CC5BB2334340CEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F42A25B3D9BD7D2ULL,
		0xB669076AD6F91796ULL,
		0x02D1198F84533F97ULL,
		0x6227C9E4DEA55E84ULL,
		0x3E357F5B382D7C7CULL,
		0x9FC7D7252189E765ULL,
		0x5FA99B625CB9FE93ULL,
		0x4998B7646686819CULL
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
		curve25519_key_printf(&k1, COMPLETE);
		return -40;
	} else {
		printf("Test Case 40 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF380A16E831073ECULL,
		0xC9FB188A4477F1EEULL,
		0xA3EBB3DAB64B64A2ULL,
		0x29FE08C8BEED86D3ULL,
		0xF5E45D7831A67046ULL,
		0x5BA009C6B1F59523ULL,
		0x03A05964B15AA0EEULL,
		0x16B0E8EAA6AA2CC4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE70142DD0620E7D8ULL,
		0x93F6311488EFE3DDULL,
		0x47D767B56C96C945ULL,
		0x53FC11917DDB0DA7ULL,
		0xEBC8BAF0634CE08CULL,
		0xB740138D63EB2A47ULL,
		0x0740B2C962B541DCULL,
		0x2D61D1D54D545988ULL
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
		curve25519_key_printf(&k1, COMPLETE);
		return -41;
	} else {
		printf("Test Case 41 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE94B1BB95F0188F2ULL,
		0x7FAFCC8FB3EF22AFULL,
		0xEE1569C72CD2DAEEULL,
		0x6F4752D7D96C3346ULL,
		0x59876EC2744E8195ULL,
		0x4E783523CAC2E227ULL,
		0x5A82237B334B321BULL,
		0x36FA88B64195FAADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD2963772BE0311E4ULL,
		0xFF5F991F67DE455FULL,
		0xDC2AD38E59A5B5DCULL,
		0xDE8EA5AFB2D8668DULL,
		0xB30EDD84E89D032AULL,
		0x9CF06A479585C44EULL,
		0xB50446F666966436ULL,
		0x6DF5116C832BF55AULL
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
		curve25519_key_printf(&k1, COMPLETE);
		return -42;
	} else {
		printf("Test Case 42 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6624624FBC2752E9ULL,
		0x22FC19DEF3C826F6ULL,
		0xAC8060DD35DEBCA2ULL,
		0xD7DB883FEEFF3056ULL,
		0x5469513D41ADB40EULL,
		0xEE531B51BF2FAB6AULL,
		0xC906DEA4E4C67F82ULL,
		0x0C003A37F1DF27F7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCC48C49F784EA5D2ULL,
		0x45F833BDE7904DECULL,
		0x5900C1BA6BBD7944ULL,
		0xAFB7107FDDFE60ADULL,
		0xA8D2A27A835B681DULL,
		0xDCA636A37E5F56D4ULL,
		0x920DBD49C98CFF05ULL,
		0x1800746FE3BE4FEFULL
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
		curve25519_key_printf(&k1, COMPLETE);
		return -43;
	} else {
		printf("Test Case 43 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC4E202BEFB3E7149ULL,
		0x91E4203FB2546404ULL,
		0xBB80C01E0DF282CDULL,
		0x03B139523D731FF5ULL,
		0xD09056B42070BC02ULL,
		0x181BD2226130E374ULL,
		0x97A60B9BE5A58747ULL,
		0x14EBB93B9B7625A7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x89C4057DF67CE292ULL,
		0x23C8407F64A8C809ULL,
		0x7701803C1BE5059BULL,
		0x076272A47AE63FEBULL,
		0xA120AD6840E17804ULL,
		0x3037A444C261C6E9ULL,
		0x2F4C1737CB4B0E8EULL,
		0x29D7727736EC4B4FULL
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
		curve25519_key_printf(&k1, COMPLETE);
		return -44;
	} else {
		printf("Test Case 44 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5AFBADE516826332ULL,
		0x9299B1E65AC0EC73ULL,
		0x808D9E0649DCDFA7ULL,
		0xBA618DD283FB14D4ULL,
		0x91F77013EBF1C9B8ULL,
		0x03394047AD396EE1ULL,
		0xC336F51F816E90B8ULL,
		0x195EA439B12700DDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB5F75BCA2D04C664ULL,
		0x253363CCB581D8E6ULL,
		0x011B3C0C93B9BF4FULL,
		0x74C31BA507F629A9ULL,
		0x23EEE027D7E39371ULL,
		0x0672808F5A72DDC3ULL,
		0x866DEA3F02DD2170ULL,
		0x32BD4873624E01BBULL
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
		curve25519_key_printf(&k1, COMPLETE);
		return -45;
	} else {
		printf("Test Case 45 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC236125EB507F572ULL,
		0xAE910566F9C5EBFBULL,
		0xF155A343B079E029ULL,
		0x4E1B30B8C0B18025ULL,
		0x3F81624DD0687391ULL,
		0x1DD6F9D672E04F62ULL,
		0x9E12A5836F0ED4EFULL,
		0x115A860D4993237AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x846C24BD6A0FEAE4ULL,
		0x5D220ACDF38BD7F7ULL,
		0xE2AB468760F3C053ULL,
		0x9C3661718163004BULL,
		0x7F02C49BA0D0E722ULL,
		0x3BADF3ACE5C09EC4ULL,
		0x3C254B06DE1DA9DEULL,
		0x22B50C1A932646F5ULL
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
		curve25519_key_printf(&k1, COMPLETE);
		return -46;
	} else {
		printf("Test Case 46 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x72FEFB37A8A656ECULL,
		0x383187828718D0E5ULL,
		0xD64D04A61F139268ULL,
		0x8671246B4DBA130DULL,
		0x74A3F46536FE207BULL,
		0x4E97DDD4BA275CEBULL,
		0xFD1A5DF38AB6F98CULL,
		0x3E19E09EF35CF9FCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE5FDF66F514CADD8ULL,
		0x70630F050E31A1CAULL,
		0xAC9A094C3E2724D0ULL,
		0x0CE248D69B74261BULL,
		0xE947E8CA6DFC40F7ULL,
		0x9D2FBBA9744EB9D6ULL,
		0xFA34BBE7156DF318ULL,
		0x7C33C13DE6B9F3F9ULL
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
		curve25519_key_printf(&k1, COMPLETE);
		return -47;
	} else {
		printf("Test Case 47 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x00A462E84702A190ULL,
		0x56A05D91CBF13527ULL,
		0x3E10403C0654748AULL,
		0x883B3EFEB22DC733ULL,
		0xFEEC1FD4FA50D1C6ULL,
		0xE9F761F42D5616EFULL,
		0xF7E090F6A6B4750DULL,
		0x273693AF09388FC7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0148C5D08E054320ULL,
		0xAD40BB2397E26A4EULL,
		0x7C2080780CA8E914ULL,
		0x10767DFD645B8E66ULL,
		0xFDD83FA9F4A1A38DULL,
		0xD3EEC3E85AAC2DDFULL,
		0xEFC121ED4D68EA1BULL,
		0x4E6D275E12711F8FULL
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
		curve25519_key_printf(&k1, COMPLETE);
		return -48;
	} else {
		printf("Test Case 48 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE2B3DA2A70CE038CULL,
		0x89B1D8C6F6EFFAD9ULL,
		0x0572317D5ED19C83ULL,
		0xA04CFCDD86A991B3ULL,
		0xDC9D9E03413B942CULL,
		0xFFB5039048F40A7AULL,
		0xC805EDDA1DCF8C87ULL,
		0x39B89C313CD9BB9FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC567B454E19C0718ULL,
		0x1363B18DEDDFF5B3ULL,
		0x0AE462FABDA33907ULL,
		0x4099F9BB0D532366ULL,
		0xB93B3C0682772859ULL,
		0xFF6A072091E814F5ULL,
		0x900BDBB43B9F190FULL,
		0x7371386279B3773FULL
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
		curve25519_key_printf(&k1, COMPLETE);
		return -49;
	} else {
		printf("Test Case 49 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3FB2077FABD964F7ULL,
		0x58EB836AFB691BA3ULL,
		0x1FD9C19595F7EB7EULL,
		0x87D5D0FCBF948640ULL,
		0xC51ADBF72CEDB150ULL,
		0x18CDBEC2A3B11391ULL,
		0x11D5F4CB28162655ULL,
		0x14ED206586786FF4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7F640EFF57B2C9EEULL,
		0xB1D706D5F6D23746ULL,
		0x3FB3832B2BEFD6FCULL,
		0x0FABA1F97F290C80ULL,
		0x8A35B7EE59DB62A1ULL,
		0x319B7D8547622723ULL,
		0x23ABE996502C4CAAULL,
		0x29DA40CB0CF0DFE8ULL
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
		curve25519_key_printf(&k1, COMPLETE);
		return -50;
	} else {
		printf("Test Case 50 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDF01D84F0977459DULL,
		0xED0FB122D4198D84ULL,
		0x3C901785BEDD8525ULL,
		0xBB492135829E65BCULL,
		0x0FC54372B96AAC5DULL,
		0xBE6DDC6F64DC1DEAULL,
		0x94722A6D4948D073ULL,
		0x3F945335B3FD2038ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBE03B09E12EE8B3AULL,
		0xDA1F6245A8331B09ULL,
		0x79202F0B7DBB0A4BULL,
		0x7692426B053CCB78ULL,
		0x1F8A86E572D558BBULL,
		0x7CDBB8DEC9B83BD4ULL,
		0x28E454DA9291A0E7ULL,
		0x7F28A66B67FA4071ULL
	}};
	printf("Test Case 51\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x897DDA055AFF79E4ULL,
		0x83C24DFF31EEE0B7ULL,
		0x06CC130511299674ULL,
		0x55A2F2B63EF61E4EULL,
		0x48A3F894618056A1ULL,
		0xA12049D61A0E60E2ULL,
		0xD48C7D02C80C7F96ULL,
		0x0FE473AD90852DB5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x12FBB40AB5FEF3C8ULL,
		0x07849BFE63DDC16FULL,
		0x0D98260A22532CE9ULL,
		0xAB45E56C7DEC3C9CULL,
		0x9147F128C300AD42ULL,
		0x424093AC341CC1C4ULL,
		0xA918FA059018FF2DULL,
		0x1FC8E75B210A5B6BULL
	}};
	printf("Test Case 52\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xFCA9DE3DB0D5CC49ULL,
		0xE708F3B8EE71CD48ULL,
		0x47790A9DDFC92D53ULL,
		0xAC0BAAE1575A4B1AULL,
		0xAEB31B858411BD62ULL,
		0x324A0A75C7F8F310ULL,
		0x884A20B33D67722FULL,
		0x2D897AA5DC5EA932ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF953BC7B61AB9892ULL,
		0xCE11E771DCE39A91ULL,
		0x8EF2153BBF925AA7ULL,
		0x581755C2AEB49634ULL,
		0x5D66370B08237AC5ULL,
		0x649414EB8FF1E621ULL,
		0x109441667ACEE45EULL,
		0x5B12F54BB8BD5265ULL
	}};
	printf("Test Case 53\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x3F0CB28CD35D22C4ULL,
		0xC2FB5DAC602D9961ULL,
		0x1F6A84703E734AF3ULL,
		0x2D54D3EC31C84B57ULL,
		0xC6BD05B7B499E546ULL,
		0xEEEAB5B2EC5D89C6ULL,
		0x82A8D9984705BEA9ULL,
		0x36377BE007377967ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7E196519A6BA4588ULL,
		0x85F6BB58C05B32C2ULL,
		0x3ED508E07CE695E7ULL,
		0x5AA9A7D8639096AEULL,
		0x8D7A0B6F6933CA8CULL,
		0xDDD56B65D8BB138DULL,
		0x0551B3308E0B7D53ULL,
		0x6C6EF7C00E6EF2CFULL
	}};
	printf("Test Case 54\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x75ADDBDFB16D5CA3ULL,
		0x43895E0B30D92E24ULL,
		0x0A67200FB6711907ULL,
		0x91E3A32319987ABBULL,
		0xB5738D2BAA5501D7ULL,
		0x13D766C3247F4742ULL,
		0x0DCDDFD88DADCB7EULL,
		0x14EFDDB49B035763ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEB5BB7BF62DAB946ULL,
		0x8712BC1661B25C48ULL,
		0x14CE401F6CE2320EULL,
		0x23C746463330F576ULL,
		0x6AE71A5754AA03AFULL,
		0x27AECD8648FE8E85ULL,
		0x1B9BBFB11B5B96FCULL,
		0x29DFBB693606AEC6ULL
	}};
	printf("Test Case 55\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x14CA1A227DA7F262ULL,
		0x0C0ECFDA13C12603ULL,
		0x939FFA5073FD74E3ULL,
		0x999052758D3DA726ULL,
		0x688350EAF8D727D6ULL,
		0x896F8EFAE3588460ULL,
		0xF4776ADEBB128814ULL,
		0x018388C07C6744DBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x29943444FB4FE4C4ULL,
		0x181D9FB427824C06ULL,
		0x273FF4A0E7FAE9C6ULL,
		0x3320A4EB1A7B4E4DULL,
		0xD106A1D5F1AE4FADULL,
		0x12DF1DF5C6B108C0ULL,
		0xE8EED5BD76251029ULL,
		0x03071180F8CE89B7ULL
	}};
	printf("Test Case 56\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xB037E9E6439D8311ULL,
		0xF9A47F945FDDEC3EULL,
		0x19B709C88C086236ULL,
		0xC80A836624676F70ULL,
		0x11A47FA551CA0931ULL,
		0x249BCA2E0C458787ULL,
		0xF9097934372556DDULL,
		0x1E07EF7023D0145CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x606FD3CC873B0622ULL,
		0xF348FF28BFBBD87DULL,
		0x336E13911810C46DULL,
		0x901506CC48CEDEE0ULL,
		0x2348FF4AA3941263ULL,
		0x4937945C188B0F0EULL,
		0xF212F2686E4AADBAULL,
		0x3C0FDEE047A028B9ULL
	}};
	printf("Test Case 57\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xC1B8BAF03A0EA254ULL,
		0xD5A9DAB1705A9974ULL,
		0x6521D6510E557714ULL,
		0x226B1CC6B518D005ULL,
		0x61141C2BAFC1B2CBULL,
		0xF2A154D127789629ULL,
		0xE76ADF9C6E1A4110ULL,
		0x3BB77B16C515C8B4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x837175E0741D44A8ULL,
		0xAB53B562E0B532E9ULL,
		0xCA43ACA21CAAEE29ULL,
		0x44D6398D6A31A00AULL,
		0xC22838575F836596ULL,
		0xE542A9A24EF12C52ULL,
		0xCED5BF38DC348221ULL,
		0x776EF62D8A2B9169ULL
	}};
	printf("Test Case 58\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x339B5BAE29EF7C9EULL,
		0x2DBCBB1ABDF99AB7ULL,
		0xDCA8BD97EDA8EFEFULL,
		0x1BD0C55014E3DBE7ULL,
		0x3BE1A04485DA6C40ULL,
		0x4F1835E56C8E1D83ULL,
		0x5D34C44AE59F7EE2ULL,
		0x0425F9301B700C2AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6736B75C53DEF93CULL,
		0x5B7976357BF3356EULL,
		0xB9517B2FDB51DFDEULL,
		0x37A18AA029C7B7CFULL,
		0x77C340890BB4D880ULL,
		0x9E306BCAD91C3B06ULL,
		0xBA698895CB3EFDC4ULL,
		0x084BF26036E01854ULL
	}};
	printf("Test Case 59\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xDC2617F6549F76F2ULL,
		0x780072FDC683159CULL,
		0xDEE7467FF65F7E49ULL,
		0x1E296E8A42615012ULL,
		0x1C67258E01787BC2ULL,
		0x566ADFD7519DFD87ULL,
		0x354CB385A8A5D46FULL,
		0x393055562A8300F3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB84C2FECA93EEDE4ULL,
		0xF000E5FB8D062B39ULL,
		0xBDCE8CFFECBEFC92ULL,
		0x3C52DD1484C2A025ULL,
		0x38CE4B1C02F0F784ULL,
		0xACD5BFAEA33BFB0EULL,
		0x6A99670B514BA8DEULL,
		0x7260AAAC550601E6ULL
	}};
	printf("Test Case 60\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xAC1316D887A814B4ULL,
		0xB22D879027A20F34ULL,
		0xC6A3EE0E7B7810E6ULL,
		0x102F6DF8D80E5075ULL,
		0x797B38E8A8C76EDAULL,
		0xC1DDE6E9D39B108DULL,
		0xB0478643A9C790B7ULL,
		0x24A6C2956AB8E559ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x58262DB10F502968ULL,
		0x645B0F204F441E69ULL,
		0x8D47DC1CF6F021CDULL,
		0x205EDBF1B01CA0EBULL,
		0xF2F671D1518EDDB4ULL,
		0x83BBCDD3A736211AULL,
		0x608F0C87538F216FULL,
		0x494D852AD571CAB3ULL
	}};
	printf("Test Case 61\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x7A0A05A38B720199ULL,
		0x43C7D7F959EE589FULL,
		0xBE4934D4668043F2ULL,
		0x43C1138ADE2C0145ULL,
		0x01A40FD096948A57ULL,
		0x1A07361A942616CFULL,
		0x6257764FBA5B8B33ULL,
		0x3E381DB034E1FAFBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF4140B4716E40332ULL,
		0x878FAFF2B3DCB13EULL,
		0x7C9269A8CD0087E4ULL,
		0x87822715BC58028BULL,
		0x03481FA12D2914AEULL,
		0x340E6C35284C2D9EULL,
		0xC4AEEC9F74B71666ULL,
		0x7C703B6069C3F5F6ULL
	}};
	printf("Test Case 62\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xDFFB625C2F15570DULL,
		0x9E2FF8162693C9DAULL,
		0x0140AB5813668233ULL,
		0xFF564519C2F58D53ULL,
		0x302F94BB1D89D140ULL,
		0xCD32DC29AACF65F9ULL,
		0x999FA27FE2E4D965ULL,
		0x1BB24A453979A8DEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBFF6C4B85E2AAE1AULL,
		0x3C5FF02C4D2793B5ULL,
		0x028156B026CD0467ULL,
		0xFEAC8A3385EB1AA6ULL,
		0x605F29763B13A281ULL,
		0x9A65B853559ECBF2ULL,
		0x333F44FFC5C9B2CBULL,
		0x3764948A72F351BDULL
	}};
	printf("Test Case 63\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x3BE54A6538C44B34ULL,
		0x9F0837767A007E51ULL,
		0xCF20B1FE44A1F5CBULL,
		0x3B89C384F43DCDC2ULL,
		0xEF736DE1FFE07223ULL,
		0xDB55F95A3991D47CULL,
		0x8CFB72DE1C070BB1ULL,
		0x0CA62CB608AFBC74ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x77CA94CA71889668ULL,
		0x3E106EECF400FCA2ULL,
		0x9E4163FC8943EB97ULL,
		0x77138709E87B9B85ULL,
		0xDEE6DBC3FFC0E446ULL,
		0xB6ABF2B47323A8F9ULL,
		0x19F6E5BC380E1763ULL,
		0x194C596C115F78E9ULL
	}};
	printf("Test Case 64\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xE2AB599F58C1A47DULL,
		0xC4AADB8104AD1AB9ULL,
		0xAFF1E3F2E7D575BAULL,
		0x4415D81DB6BE5073ULL,
		0x71328D185E4302A4ULL,
		0x3A682607F5DB9796ULL,
		0xC18BDC803A53B389ULL,
		0x1126C06B17D45F81ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC556B33EB18348FAULL,
		0x8955B702095A3573ULL,
		0x5FE3C7E5CFAAEB75ULL,
		0x882BB03B6D7CA0E7ULL,
		0xE2651A30BC860548ULL,
		0x74D04C0FEBB72F2CULL,
		0x8317B90074A76712ULL,
		0x224D80D62FA8BF03ULL
	}};
	printf("Test Case 65\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xEF194915A960A96CULL,
		0x25C2E322A1AF592DULL,
		0x8CD490E42C5CA5E2ULL,
		0x819564C05B160A68ULL,
		0xDC42CBA9E91DEEB5ULL,
		0xA248C054CDB7D72FULL,
		0xA2DB7D9DFABB7C4DULL,
		0x058B21475C006353ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDE32922B52C152D8ULL,
		0x4B85C645435EB25BULL,
		0x19A921C858B94BC4ULL,
		0x032AC980B62C14D1ULL,
		0xB8859753D23BDD6BULL,
		0x449180A99B6FAE5FULL,
		0x45B6FB3BF576F89BULL,
		0x0B16428EB800C6A7ULL
	}};
	printf("Test Case 66\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x9F8743743B3B4B90ULL,
		0xF988F818F5A27F00ULL,
		0x831AB975D7643F19ULL,
		0x44F5347E5E303379ULL,
		0x9F333992BEEEF93EULL,
		0x7B6DC5FDFCADF040ULL,
		0x54733F677F863D88ULL,
		0x3EAC518BD395B366ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3F0E86E876769720ULL,
		0xF311F031EB44FE01ULL,
		0x063572EBAEC87E33ULL,
		0x89EA68FCBC6066F3ULL,
		0x3E6673257DDDF27CULL,
		0xF6DB8BFBF95BE081ULL,
		0xA8E67ECEFF0C7B10ULL,
		0x7D58A317A72B66CCULL
	}};
	printf("Test Case 67\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x6C33666F517A6A2EULL,
		0x34BB9F6F98C86E02ULL,
		0xED255044ECDB8677ULL,
		0x88CB7DEB9B48A735ULL,
		0x1486996A7C38DA4FULL,
		0x8C16883A2DA4A4F6ULL,
		0xC893B724843E2ADDULL,
		0x0305C355AF4220B3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD866CCDEA2F4D45CULL,
		0x69773EDF3190DC04ULL,
		0xDA4AA089D9B70CEEULL,
		0x1196FBD736914E6BULL,
		0x290D32D4F871B49FULL,
		0x182D10745B4949ECULL,
		0x91276E49087C55BBULL,
		0x060B86AB5E844167ULL
	}};
	printf("Test Case 68\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x9221055C206E594AULL,
		0x4DF62313D39F4237ULL,
		0xB6A382FD9F12F1EBULL,
		0xE061FA81DD79AFB6ULL,
		0xCFE6CE6CD596C0CFULL,
		0xED46BD2B72E210DDULL,
		0xF8B7F2281A9DE62FULL,
		0x12864CE12FA39BADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x24420AB840DCB294ULL,
		0x9BEC4627A73E846FULL,
		0x6D4705FB3E25E3D6ULL,
		0xC0C3F503BAF35F6DULL,
		0x9FCD9CD9AB2D819FULL,
		0xDA8D7A56E5C421BBULL,
		0xF16FE450353BCC5FULL,
		0x250C99C25F47375BULL
	}};
	printf("Test Case 69\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x8088ADEA3B9F199BULL,
		0xDCF8A9A8E518EAADULL,
		0x69819F6DD1ADD8B9ULL,
		0x2A688FE7D64D492FULL,
		0xD11B76FC122E0201ULL,
		0x418A080395F73A47ULL,
		0x0CA56DBC1856C1E8ULL,
		0x31685235398EC2BBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x01115BD4773E3336ULL,
		0xB9F15351CA31D55BULL,
		0xD3033EDBA35BB173ULL,
		0x54D11FCFAC9A925EULL,
		0xA236EDF8245C0402ULL,
		0x831410072BEE748FULL,
		0x194ADB7830AD83D0ULL,
		0x62D0A46A731D8576ULL
	}};
	printf("Test Case 70\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x63BD800466502143ULL,
		0x4EEF288CEDE9DC0CULL,
		0xABC38CC0A25F170DULL,
		0xC0D98B72DA4F34D4ULL,
		0x4D564457C6785B58ULL,
		0x42BE2C3FB8671968ULL,
		0x8486CBF7D4A03010ULL,
		0x01E779781022CF71ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC77B0008CCA04286ULL,
		0x9DDE5119DBD3B818ULL,
		0x5787198144BE2E1AULL,
		0x81B316E5B49E69A9ULL,
		0x9AAC88AF8CF0B6B1ULL,
		0x857C587F70CE32D0ULL,
		0x090D97EFA9406020ULL,
		0x03CEF2F020459EE3ULL
	}};
	printf("Test Case 71\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xA2DC6831A6755DE1ULL,
		0xCEC0A419D3683A32ULL,
		0xE205DDE1312775BDULL,
		0x8B341B003CB67A2CULL,
		0xD2403A08EC7B3E63ULL,
		0x0F863230834ACA99ULL,
		0x362D2A544D0FBBEFULL,
		0x21E7F88E14E16368ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x45B8D0634CEABBC2ULL,
		0x9D814833A6D07465ULL,
		0xC40BBBC2624EEB7BULL,
		0x16683600796CF459ULL,
		0xA4807411D8F67CC7ULL,
		0x1F0C646106959533ULL,
		0x6C5A54A89A1F77DEULL,
		0x43CFF11C29C2C6D0ULL
	}};
	printf("Test Case 72\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xE0387AAA449FF699ULL,
		0x514B87100690E5E4ULL,
		0x18D1D4CFD32C2413ULL,
		0x07C66528C4B809A8ULL,
		0xE893C60DDECDFDDDULL,
		0xF5F641E4CC14B161ULL,
		0x94FB189BEFE0D1D9ULL,
		0x28FA91F5A5BC17BBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC070F554893FED32ULL,
		0xA2970E200D21CBC9ULL,
		0x31A3A99FA6584826ULL,
		0x0F8CCA5189701350ULL,
		0xD1278C1BBD9BFBBAULL,
		0xEBEC83C9982962C3ULL,
		0x29F63137DFC1A3B3ULL,
		0x51F523EB4B782F77ULL
	}};
	printf("Test Case 73\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x2FB2442D86B529D1ULL,
		0x2A8EE7C552B13E0BULL,
		0x9221FA0728170918ULL,
		0xB5E42E56C5CBD5C4ULL,
		0x200CDF4A3B3A5612ULL,
		0x637708DE3303E80FULL,
		0x82B9DDF5A3261D97ULL,
		0x141F874AD0F01572ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5F64885B0D6A53A2ULL,
		0x551DCF8AA5627C16ULL,
		0x2443F40E502E1230ULL,
		0x6BC85CAD8B97AB89ULL,
		0x4019BE947674AC25ULL,
		0xC6EE11BC6607D01EULL,
		0x0573BBEB464C3B2EULL,
		0x283F0E95A1E02AE5ULL
	}};
	printf("Test Case 74\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xCA5FC4E494E6F7CAULL,
		0x18CC8777F6BCC729ULL,
		0x1EBDAA00977EDA30ULL,
		0x8117CBECE941858AULL,
		0x97906033B331946FULL,
		0xD558D2A8A39E2D04ULL,
		0x5D6BE859434D2475ULL,
		0x1FA992959FD62010ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x94BF89C929CDEF94ULL,
		0x31990EEFED798E53ULL,
		0x3D7B54012EFDB460ULL,
		0x022F97D9D2830B14ULL,
		0x2F20C067666328DFULL,
		0xAAB1A551473C5A09ULL,
		0xBAD7D0B2869A48EBULL,
		0x3F53252B3FAC4020ULL
	}};
	printf("Test Case 75\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x4C8268518B74BDD4ULL,
		0x6AC7B599DA5A4D95ULL,
		0x9D375387E3265E8FULL,
		0xF5B4486C54D0B002ULL,
		0xEF3FD173C3120D11ULL,
		0x4AC0D8A461BFC5F8ULL,
		0x197AD311E9C022D3ULL,
		0x046EE7CC33C1B2B2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9904D0A316E97BA8ULL,
		0xD58F6B33B4B49B2AULL,
		0x3A6EA70FC64CBD1EULL,
		0xEB6890D8A9A16005ULL,
		0xDE7FA2E786241A23ULL,
		0x9581B148C37F8BF1ULL,
		0x32F5A623D38045A6ULL,
		0x08DDCF9867836564ULL
	}};
	printf("Test Case 76\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x49557593BB67A8BCULL,
		0x9A51DC49E15B1EA4ULL,
		0x3D4D21E29F5B0A2FULL,
		0xC57F6C5CE5F62178ULL,
		0xC6DEA848FF8A7A2CULL,
		0xD38EEF0A64B813B5ULL,
		0x1F5F6EC03A7E557FULL,
		0x286C551A523C402AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x92AAEB2776CF5178ULL,
		0x34A3B893C2B63D48ULL,
		0x7A9A43C53EB6145FULL,
		0x8AFED8B9CBEC42F0ULL,
		0x8DBD5091FF14F459ULL,
		0xA71DDE14C970276BULL,
		0x3EBEDD8074FCAAFFULL,
		0x50D8AA34A4788054ULL
	}};
	printf("Test Case 77\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x678C54985C0953F1ULL,
		0x34A4CAAB685808CCULL,
		0xFA5885316DD4E107ULL,
		0xBDD9707BC8CE9A35ULL,
		0x2F7DFBF84D4EB972ULL,
		0x55F5FBC96A267F9AULL,
		0x9F6E5867F55344CEULL,
		0x1685FA2698FCB055ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCF18A930B812A7E2ULL,
		0x69499556D0B01198ULL,
		0xF4B10A62DBA9C20EULL,
		0x7BB2E0F7919D346BULL,
		0x5EFBF7F09A9D72E5ULL,
		0xABEBF792D44CFF34ULL,
		0x3EDCB0CFEAA6899CULL,
		0x2D0BF44D31F960ABULL
	}};
	printf("Test Case 78\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xB4AB4BB6C112D886ULL,
		0x1EE71214392EB68BULL,
		0x3FD16BADA6100BBFULL,
		0x4E287F98D5E40609ULL,
		0xB713AE50AA86965AULL,
		0xDF286D112F163668ULL,
		0xEAA533C6517E2260ULL,
		0x33B2FBCE987C7FC9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6956976D8225B10CULL,
		0x3DCE2428725D6D17ULL,
		0x7FA2D75B4C20177EULL,
		0x9C50FF31ABC80C12ULL,
		0x6E275CA1550D2CB4ULL,
		0xBE50DA225E2C6CD1ULL,
		0xD54A678CA2FC44C1ULL,
		0x6765F79D30F8FF93ULL
	}};
	printf("Test Case 79\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x5AAC752F0A18C123ULL,
		0xD1DB5FDAD94E5BEAULL,
		0x0FFBFE0CC94EC510ULL,
		0xAD4C9271C84F0193ULL,
		0xB283B922FB269D58ULL,
		0x49B1798BF299EB5DULL,
		0xF72B82BFBBB99F91ULL,
		0x123081A0CC1A9005ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB558EA5E14318246ULL,
		0xA3B6BFB5B29CB7D4ULL,
		0x1FF7FC19929D8A21ULL,
		0x5A9924E3909E0326ULL,
		0x65077245F64D3AB1ULL,
		0x9362F317E533D6BBULL,
		0xEE57057F77733F22ULL,
		0x246103419835200BULL
	}};
	printf("Test Case 80\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x1D70E125C9097A15ULL,
		0xD4966C16D24204B5ULL,
		0xA9010FE633DDD1C3ULL,
		0x9307948B6AF039C5ULL,
		0x5513897399BCDE04ULL,
		0x67E14059567BFB8AULL,
		0xDD6D3D5407965196ULL,
		0x114FFD757E8F13DCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3AE1C24B9212F42AULL,
		0xA92CD82DA484096AULL,
		0x52021FCC67BBA387ULL,
		0x260F2916D5E0738BULL,
		0xAA2712E73379BC09ULL,
		0xCFC280B2ACF7F714ULL,
		0xBADA7AA80F2CA32CULL,
		0x229FFAEAFD1E27B9ULL
	}};
	printf("Test Case 81\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xFB72B55D01026658ULL,
		0x9287823254DF1D46ULL,
		0x861DB40368D3CAA0ULL,
		0x73AB9F90FFDC2312ULL,
		0x515F5FA0C758D108ULL,
		0xA13017DD81DC2BC5ULL,
		0x0F6694CF0C012530ULL,
		0x36D09ED029CC33EAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF6E56ABA0204CCB0ULL,
		0x250F0464A9BE3A8DULL,
		0x0C3B6806D1A79541ULL,
		0xE7573F21FFB84625ULL,
		0xA2BEBF418EB1A210ULL,
		0x42602FBB03B8578AULL,
		0x1ECD299E18024A61ULL,
		0x6DA13DA0539867D4ULL
	}};
	printf("Test Case 82\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x2056237E8413DC47ULL,
		0x388C86A3A333E074ULL,
		0xF2191F0B0BAE69C0ULL,
		0x28D056DD7251DDA5ULL,
		0x2D48776F2E5864C2ULL,
		0x14B8F35A3ED52E3EULL,
		0xBD0AAB53FA641DFCULL,
		0x086BCA98A7A72398ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x40AC46FD0827B88EULL,
		0x71190D474667C0E8ULL,
		0xE4323E16175CD380ULL,
		0x51A0ADBAE4A3BB4BULL,
		0x5A90EEDE5CB0C984ULL,
		0x2971E6B47DAA5C7CULL,
		0x7A1556A7F4C83BF8ULL,
		0x10D795314F4E4731ULL
	}};
	printf("Test Case 83\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xD199C9825DABA74BULL,
		0x5DE8C7A76F7DA07CULL,
		0xC5BAA5598AFD5925ULL,
		0x38FB9F07CA3FF875ULL,
		0xE1A8AFC1133CE73CULL,
		0x6FCE8881E8C41F48ULL,
		0x17DBA986E5D3B8EEULL,
		0x350CCC8A91F93402ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA3339304BB574E96ULL,
		0xBBD18F4EDEFB40F9ULL,
		0x8B754AB315FAB24AULL,
		0x71F73E0F947FF0EBULL,
		0xC3515F822679CE78ULL,
		0xDF9D1103D1883E91ULL,
		0x2FB7530DCBA771DCULL,
		0x6A19991523F26804ULL
	}};
	printf("Test Case 84\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xB72C6B563A5A65AAULL,
		0x879C07A2C393EEB9ULL,
		0x3C16C57E6B70083CULL,
		0xC78CB835862FC6A3ULL,
		0x1A5B59BCA0A7A4C6ULL,
		0x7ED38EAD92E8E86FULL,
		0xF563D7263C39ED86ULL,
		0x3F37F019A607BDAEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6E58D6AC74B4CB54ULL,
		0x0F380F458727DD73ULL,
		0x782D8AFCD6E01079ULL,
		0x8F19706B0C5F8D46ULL,
		0x34B6B379414F498DULL,
		0xFDA71D5B25D1D0DEULL,
		0xEAC7AE4C7873DB0CULL,
		0x7E6FE0334C0F7B5DULL
	}};
	printf("Test Case 85\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x53511AB54379E9CCULL,
		0x22FA0A5DEBD67BB7ULL,
		0xC3FAD3AEF0EF8967ULL,
		0xB27CE7C0DB02AB1BULL,
		0x3075D8ADACF74BBBULL,
		0x9D8227CD74D1FF81ULL,
		0xDA8CD6BDA2701A1EULL,
		0x0A8ABB839D90258CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA6A2356A86F3D398ULL,
		0x45F414BBD7ACF76EULL,
		0x87F5A75DE1DF12CEULL,
		0x64F9CF81B6055637ULL,
		0x60EBB15B59EE9777ULL,
		0x3B044F9AE9A3FF02ULL,
		0xB519AD7B44E0343DULL,
		0x151577073B204B19ULL
	}};
	printf("Test Case 86\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xE0E25C0C334F0A2CULL,
		0xEBF0820D38C9C5B3ULL,
		0xB08851BE9B162FBDULL,
		0x897211AD48E03302ULL,
		0x0B728D4E33FEF7F3ULL,
		0x89B5EE53C487B87CULL,
		0xC41D60AE2B08E1ECULL,
		0x1D9A2D69FBEEC36EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC1C4B818669E1458ULL,
		0xD7E1041A71938B67ULL,
		0x6110A37D362C5F7BULL,
		0x12E4235A91C06605ULL,
		0x16E51A9C67FDEFE7ULL,
		0x136BDCA7890F70F8ULL,
		0x883AC15C5611C3D9ULL,
		0x3B345AD3F7DD86DDULL
	}};
	printf("Test Case 87\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xC9A462C5D3FC0CD0ULL,
		0x26357CE3EB788026ULL,
		0x644E1AB1F59B42F7ULL,
		0x4062C9B422E9BE3BULL,
		0xC5753D41EED3ADE0ULL,
		0xA1D51D1A0929A21BULL,
		0x5CF0F4AE53CFADDEULL,
		0x13D5DD2042568CA0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9348C58BA7F819A0ULL,
		0x4C6AF9C7D6F1004DULL,
		0xC89C3563EB3685EEULL,
		0x80C5936845D37C76ULL,
		0x8AEA7A83DDA75BC0ULL,
		0x43AA3A3412534437ULL,
		0xB9E1E95CA79F5BBDULL,
		0x27ABBA4084AD1940ULL
	}};
	printf("Test Case 88\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x9E50E8267011349FULL,
		0x2460C963BC306DDAULL,
		0x69EA2827C9D31FF6ULL,
		0x6CEDD468B10E35C3ULL,
		0x9A8E79874D3912B0ULL,
		0x1B23690A897F09CEULL,
		0xE8F8006801379045ULL,
		0x1E97BE74D6EEC478ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3CA1D04CE022693EULL,
		0x48C192C77860DBB5ULL,
		0xD3D4504F93A63FECULL,
		0xD9DBA8D1621C6B86ULL,
		0x351CF30E9A722560ULL,
		0x3646D21512FE139DULL,
		0xD1F000D0026F208AULL,
		0x3D2F7CE9ADDD88F1ULL
	}};
	printf("Test Case 89\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xA888D106602F8446ULL,
		0xE2D3833D809B88A8ULL,
		0x9546CD56FD779575ULL,
		0xAD622DDD9E085699ULL,
		0x94044250F13A3D4CULL,
		0xE3964C60DB87C71AULL,
		0xF62A77BE220F4C8EULL,
		0x26F98A1F6D2FED37ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5111A20CC05F088CULL,
		0xC5A7067B01371151ULL,
		0x2A8D9AADFAEF2AEBULL,
		0x5AC45BBB3C10AD33ULL,
		0x280884A1E2747A99ULL,
		0xC72C98C1B70F8E35ULL,
		0xEC54EF7C441E991DULL,
		0x4DF3143EDA5FDA6FULL
	}};
	printf("Test Case 90\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x062A2DE71EBA3A4CULL,
		0x76965F5F820E39D2ULL,
		0x2B5BAD544F4650CCULL,
		0xD83EF99FA9D2038FULL,
		0x83EEE6C75593E38BULL,
		0x4124E344841DFC02ULL,
		0xDECDDCE2FC92AA8BULL,
		0x072D992E727A73DFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0C545BCE3D747498ULL,
		0xED2CBEBF041C73A4ULL,
		0x56B75AA89E8CA198ULL,
		0xB07DF33F53A4071EULL,
		0x07DDCD8EAB27C717ULL,
		0x8249C689083BF805ULL,
		0xBD9BB9C5F9255516ULL,
		0x0E5B325CE4F4E7BFULL
	}};
	printf("Test Case 91\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xF101A68F67F130E9ULL,
		0xF0C7FDD2F6DCED45ULL,
		0xE1C9E18747FD74ACULL,
		0x9C28DF82DA696929ULL,
		0xB27BDC6F1E0ED939ULL,
		0xF12A755052828457ULL,
		0x6825CC0155673927ULL,
		0x23EA7D6EBC92679FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE2034D1ECFE261D2ULL,
		0xE18FFBA5EDB9DA8BULL,
		0xC393C30E8FFAE959ULL,
		0x3851BF05B4D2D253ULL,
		0x64F7B8DE3C1DB273ULL,
		0xE254EAA0A50508AFULL,
		0xD04B9802AACE724FULL,
		0x47D4FADD7924CF3EULL
	}};
	printf("Test Case 92\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xC0823E7F219358BFULL,
		0xF1EA0FCFD2B438B9ULL,
		0x45CBE360DECE787AULL,
		0x5BF11DBE5F5B6267ULL,
		0x5A593D875683EFF5ULL,
		0x50B9F228ABFF01E9ULL,
		0x2167A121B5AE4BAFULL,
		0x1779294EB99620ACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x81047CFE4326B17EULL,
		0xE3D41F9FA5687173ULL,
		0x8B97C6C1BD9CF0F5ULL,
		0xB7E23B7CBEB6C4CEULL,
		0xB4B27B0EAD07DFEAULL,
		0xA173E45157FE03D2ULL,
		0x42CF42436B5C975EULL,
		0x2EF2529D732C4158ULL
	}};
	printf("Test Case 93\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x26CB10A42DE91906ULL,
		0xE2D3B0D559A2A09CULL,
		0x292A99949462F257ULL,
		0x6C2E2969A6D6F574ULL,
		0xA9685EFD01BF1066ULL,
		0x61D76AAE93E5F409ULL,
		0x93E0031263376BDAULL,
		0x2F200206BAFBF947ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4D9621485BD2320CULL,
		0xC5A761AAB3454138ULL,
		0x5255332928C5E4AFULL,
		0xD85C52D34DADEAE8ULL,
		0x52D0BDFA037E20CCULL,
		0xC3AED55D27CBE813ULL,
		0x27C00624C66ED7B4ULL,
		0x5E40040D75F7F28FULL
	}};
	printf("Test Case 94\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xFB09C5318AC0D64DULL,
		0xF9E8C723F9C48DA7ULL,
		0xE2732784EAF7EB16ULL,
		0xE75C30D2FACDAC81ULL,
		0x68949FCE15A2B52BULL,
		0xE83E70459F324996ULL,
		0x6835FC31EA4F88CCULL,
		0x29668609C5818C49ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF6138A631581AC9AULL,
		0xF3D18E47F3891B4FULL,
		0xC4E64F09D5EFD62DULL,
		0xCEB861A5F59B5903ULL,
		0xD1293F9C2B456A57ULL,
		0xD07CE08B3E64932CULL,
		0xD06BF863D49F1199ULL,
		0x52CD0C138B031892ULL
	}};
	printf("Test Case 95\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xE07B99C5AFAE9BD1ULL,
		0xF51B36C495D8BC51ULL,
		0x4064931CFB95AEBFULL,
		0xC37B4B62D02B932BULL,
		0xFEA3C48629ECD319ULL,
		0x1642D88D965E0769ULL,
		0x2A91F20B1786B02DULL,
		0x3FD7A3C154795FA5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC0F7338B5F5D37A2ULL,
		0xEA366D892BB178A3ULL,
		0x80C92639F72B5D7FULL,
		0x86F696C5A0572656ULL,
		0xFD47890C53D9A633ULL,
		0x2C85B11B2CBC0ED3ULL,
		0x5523E4162F0D605AULL,
		0x7FAF4782A8F2BF4AULL
	}};
	printf("Test Case 96\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xD79EC306BFEDD822ULL,
		0x229E9AADAB571120ULL,
		0x4CDDD5EEA0E0809FULL,
		0x54AF0B1488A3E0CFULL,
		0xC8A2E12288DA1A0CULL,
		0x9EBA40318186F4F4ULL,
		0xC4D6654FA293E373ULL,
		0x30ED593C99DF42F5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF3D860D7FDBB044ULL,
		0x453D355B56AE2241ULL,
		0x99BBABDD41C1013EULL,
		0xA95E16291147C19EULL,
		0x9145C24511B43418ULL,
		0x3D748063030DE9E9ULL,
		0x89ACCA9F4527C6E7ULL,
		0x61DAB27933BE85EBULL
	}};
	printf("Test Case 97\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xA2CC7D2F195F79E2ULL,
		0x6F66C0FA08D3900FULL,
		0xF9D37F78D75D5564ULL,
		0x6BCF0A726209C08DULL,
		0x175F3134EAC28190ULL,
		0xC24231E1EDB844CFULL,
		0x569CDD6C86CC6B12ULL,
		0x3A8A57EE605C62D6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4598FA5E32BEF3C4ULL,
		0xDECD81F411A7201FULL,
		0xF3A6FEF1AEBAAAC8ULL,
		0xD79E14E4C413811BULL,
		0x2EBE6269D5850320ULL,
		0x848463C3DB70899EULL,
		0xAD39BAD90D98D625ULL,
		0x7514AFDCC0B8C5ACULL
	}};
	printf("Test Case 98\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xBB3DA1AD292DAB84ULL,
		0xB99091371693FCF7ULL,
		0x37CB536A2FBE8411ULL,
		0x6F7484BACD0534CDULL,
		0xCAEB5962C357BB6CULL,
		0x5C11A0019C852FD8ULL,
		0x8C7F5E23F83DDE87ULL,
		0x262A22E3CEA10C85ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x767B435A525B5708ULL,
		0x7321226E2D27F9EFULL,
		0x6F96A6D45F7D0823ULL,
		0xDEE909759A0A699AULL,
		0x95D6B2C586AF76D8ULL,
		0xB8234003390A5FB1ULL,
		0x18FEBC47F07BBD0EULL,
		0x4C5445C79D42190BULL
	}};
	printf("Test Case 99\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x50F4633557DD1467ULL,
		0x2CCBF93C08BF4C31ULL,
		0x14046AF811CB8C40ULL,
		0x40E3CA9832843332ULL,
		0x8D88C10571BA41E5ULL,
		0x40504938C4DF34A7ULL,
		0x1A451356FAB82BB7ULL,
		0x04D615AD4331BB98ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA1E8C66AAFBA28CEULL,
		0x5997F278117E9862ULL,
		0x2808D5F023971880ULL,
		0x81C7953065086664ULL,
		0x1B11820AE37483CAULL,
		0x80A0927189BE694FULL,
		0x348A26ADF570576EULL,
		0x09AC2B5A86637730ULL
	}};
	printf("Test Case 100\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xD353FD078413A4CAULL,
		0x63C6F2EE15EE9732ULL,
		0x7D392B61C28D88B4ULL,
		0xE00A1A0389C392F5ULL,
		0x8F9DBFF7FBEBDDB3ULL,
		0xBCCD9AE4DC9D985BULL,
		0x9630D2B91328DDFCULL,
		0x0CEA1E68537C15D4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA6A7FA0F08274994ULL,
		0xC78DE5DC2BDD2E65ULL,
		0xFA7256C3851B1168ULL,
		0xC0143407138725EAULL,
		0x1F3B7FEFF7D7BB67ULL,
		0x799B35C9B93B30B7ULL,
		0x2C61A5722651BBF9ULL,
		0x19D43CD0A6F82BA9ULL
	}};
	printf("Test Case 101\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x315A0C7C1D0094B8ULL,
		0x149F46FDA47FFEE6ULL,
		0xD5C6FDB7B5266861ULL,
		0x6D2F874B34A2A169ULL,
		0xDC5C76B3ECC7D8CBULL,
		0xA9A4B9D3D558E208ULL,
		0xDB8565F0891EE857ULL,
		0x0BAB3C51660F69B7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x62B418F83A012970ULL,
		0x293E8DFB48FFFDCCULL,
		0xAB8DFB6F6A4CD0C2ULL,
		0xDA5F0E96694542D3ULL,
		0xB8B8ED67D98FB196ULL,
		0x534973A7AAB1C411ULL,
		0xB70ACBE1123DD0AFULL,
		0x175678A2CC1ED36FULL
	}};
	printf("Test Case 102\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xB9629645D3275015ULL,
		0xD419F72CAE79BCDAULL,
		0x423FBB7FF9ADBD42ULL,
		0x885D7DB87A40B491ULL,
		0x076F241E19D6B276ULL,
		0x5384BF47F0145551ULL,
		0x0ADFC3C9665B9642ULL,
		0x3E9991BD78D7E680ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x72C52C8BA64EA02AULL,
		0xA833EE595CF379B5ULL,
		0x847F76FFF35B7A85ULL,
		0x10BAFB70F4816922ULL,
		0x0EDE483C33AD64EDULL,
		0xA7097E8FE028AAA2ULL,
		0x15BF8792CCB72C84ULL,
		0x7D33237AF1AFCD00ULL
	}};
	printf("Test Case 103\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xA6CE31399DBF15AAULL,
		0x2019D6E52E4E4409ULL,
		0xBC63CC78FF032163ULL,
		0x1A44BE6A0D78CD12ULL,
		0xDFE87ED8C57AC4F3ULL,
		0x2A3B650BF8792995ULL,
		0xDA72F75DB50384E0ULL,
		0x1F0360B7AAB423A4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4D9C62733B7E2B54ULL,
		0x4033ADCA5C9C8813ULL,
		0x78C798F1FE0642C6ULL,
		0x34897CD41AF19A25ULL,
		0xBFD0FDB18AF589E6ULL,
		0x5476CA17F0F2532BULL,
		0xB4E5EEBB6A0709C0ULL,
		0x3E06C16F55684749ULL
	}};
	printf("Test Case 104\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x08291D5503DAE76BULL,
		0x4A93657C4AF97D90ULL,
		0x40B9DB20DFDBC37AULL,
		0x4C1353A97565F4B1ULL,
		0xDEF1FCE65FECC265ULL,
		0x243E465124C6560BULL,
		0x80CE2696714B183BULL,
		0x3734956D5F7FA159ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x10523AAA07B5CED6ULL,
		0x9526CAF895F2FB20ULL,
		0x8173B641BFB786F4ULL,
		0x9826A752EACBE962ULL,
		0xBDE3F9CCBFD984CAULL,
		0x487C8CA2498CAC17ULL,
		0x019C4D2CE2963076ULL,
		0x6E692ADABEFF42B3ULL
	}};
	printf("Test Case 105\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x933372B99EBB7BF5ULL,
		0x7AE6D785BB0E32E9ULL,
		0x0DE9DCB27BDD5168ULL,
		0xF384E6F963E53B7BULL,
		0x1D55C79358008013ULL,
		0xDDCA15F583E57C62ULL,
		0x4E000076F20BB0C7ULL,
		0x1F130415F9DF1E24ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2666E5733D76F7EAULL,
		0xF5CDAF0B761C65D3ULL,
		0x1BD3B964F7BAA2D0ULL,
		0xE709CDF2C7CA76F6ULL,
		0x3AAB8F26B0010027ULL,
		0xBB942BEB07CAF8C4ULL,
		0x9C0000EDE417618FULL,
		0x3E26082BF3BE3C48ULL
	}};
	printf("Test Case 106\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xB3E84C596FFE0B86ULL,
		0xD8D31D46E3D3C28EULL,
		0x4DC6D31F4F1BC95FULL,
		0xA465A179CB31FAD5ULL,
		0xCC5181E340729CEBULL,
		0xE862B124340D3E1EULL,
		0x39138D6A5EB0BE3DULL,
		0x13874A6AE6EB995CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x67D098B2DFFC170CULL,
		0xB1A63A8DC7A7851DULL,
		0x9B8DA63E9E3792BFULL,
		0x48CB42F39663F5AAULL,
		0x98A303C680E539D7ULL,
		0xD0C56248681A7C3DULL,
		0x72271AD4BD617C7BULL,
		0x270E94D5CDD732B8ULL
	}};
	printf("Test Case 107\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xED626FB0E4DDA0ECULL,
		0x8916A7A7D14152EDULL,
		0x879BB62F1E25BC75ULL,
		0x2CF61B6E3F60B7FCULL,
		0x7EA32952724EB4C7ULL,
		0x3C661A1DB8FE96A9ULL,
		0xB012D0DF0198B383ULL,
		0x149F6C4D541C42D4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDAC4DF61C9BB41D8ULL,
		0x122D4F4FA282A5DBULL,
		0x0F376C5E3C4B78EBULL,
		0x59EC36DC7EC16FF9ULL,
		0xFD4652A4E49D698EULL,
		0x78CC343B71FD2D52ULL,
		0x6025A1BE03316706ULL,
		0x293ED89AA83885A9ULL
	}};
	printf("Test Case 108\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xE727DF0569B60B63ULL,
		0x22583E822F3C9377ULL,
		0xB15AD997106F8967ULL,
		0xCB8F15C413E9C25DULL,
		0xC7F060D3F7857A6DULL,
		0x5F834C540C033E75ULL,
		0xCE7B0FA89A6EC433ULL,
		0x3700233D24C192A4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCE4FBE0AD36C16C6ULL,
		0x44B07D045E7926EFULL,
		0x62B5B32E20DF12CEULL,
		0x971E2B8827D384BBULL,
		0x8FE0C1A7EF0AF4DBULL,
		0xBF0698A818067CEBULL,
		0x9CF61F5134DD8866ULL,
		0x6E00467A49832549ULL
	}};
	printf("Test Case 109\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x6F97DDBE3C36E8CDULL,
		0xABE8B4C4C4AD2578ULL,
		0x232E210FD3A99F60ULL,
		0x315D4DA760549F35ULL,
		0xFF8C7F3AFB8803AFULL,
		0xE6B8AE507C925ED0ULL,
		0x22E933B8BA27954CULL,
		0x1F0DB62D343AD618ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDF2FBB7C786DD19AULL,
		0x57D16989895A4AF0ULL,
		0x465C421FA7533EC1ULL,
		0x62BA9B4EC0A93E6AULL,
		0xFF18FE75F710075EULL,
		0xCD715CA0F924BDA1ULL,
		0x45D26771744F2A99ULL,
		0x3E1B6C5A6875AC30ULL
	}};
	printf("Test Case 110\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x8B60825E6C96E249ULL,
		0xC1D1065747A177E7ULL,
		0x741BA97A91A47838ULL,
		0x2D405C09AAB8204BULL,
		0x757B4F15995C168BULL,
		0xF3C6F99D62C04A27ULL,
		0xF3759A2927D11CD1ULL,
		0x2421A93875E0CE49ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x16C104BCD92DC492ULL,
		0x83A20CAE8F42EFCFULL,
		0xE83752F52348F071ULL,
		0x5A80B81355704096ULL,
		0xEAF69E2B32B82D16ULL,
		0xE78DF33AC580944EULL,
		0xE6EB34524FA239A3ULL,
		0x48435270EBC19C93ULL
	}};
	printf("Test Case 111\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xCEA7350B8A74ABFCULL,
		0x546A838AED67232FULL,
		0xB3F483050F6776B1ULL,
		0xB548B15600AE286DULL,
		0x8B22A2F59538B216ULL,
		0xEC8F081A088A28AFULL,
		0xED596E9DB681CED1ULL,
		0x1D8186D505A38B86ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9D4E6A1714E957F8ULL,
		0xA8D50715DACE465FULL,
		0x67E9060A1ECEED62ULL,
		0x6A9162AC015C50DBULL,
		0x164545EB2A71642DULL,
		0xD91E10341114515FULL,
		0xDAB2DD3B6D039DA3ULL,
		0x3B030DAA0B47170DULL
	}};
	printf("Test Case 112\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xA8F8192556607FBAULL,
		0xA124B801710A8308ULL,
		0xEEB31D248EE99716ULL,
		0xBC8CB9B3513BC34AULL,
		0xD155D07E217A986BULL,
		0xB601E916091735E3ULL,
		0xFB23A25FB9D9CFC3ULL,
		0x25C1596EBC6E240CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x51F0324AACC0FF74ULL,
		0x42497002E2150611ULL,
		0xDD663A491DD32E2DULL,
		0x79197366A2778695ULL,
		0xA2ABA0FC42F530D7ULL,
		0x6C03D22C122E6BC7ULL,
		0xF64744BF73B39F87ULL,
		0x4B82B2DD78DC4819ULL
	}};
	printf("Test Case 113\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xF9BC5D8128B4B0E8ULL,
		0x2BB92D4991784D12ULL,
		0x22D6388F187E3B49ULL,
		0x6B8E930939459482ULL,
		0xDEAB5208F5B925BCULL,
		0x9B6DC883190AD29DULL,
		0x1E0A8DE97048B47DULL,
		0x0DABF88FEB79E1C4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF378BB02516961D0ULL,
		0x57725A9322F09A25ULL,
		0x45AC711E30FC7692ULL,
		0xD71D2612728B2904ULL,
		0xBD56A411EB724B78ULL,
		0x36DB91063215A53BULL,
		0x3C151BD2E09168FBULL,
		0x1B57F11FD6F3C388ULL
	}};
	printf("Test Case 114\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xBD490C0ECF8267DFULL,
		0xE4599E7B9991EB90ULL,
		0xF974664625BF9F10ULL,
		0x2C3C2DFB588B73B4ULL,
		0xA55CE7908529CD3BULL,
		0xCA69D542C65D739CULL,
		0xD61755582EC98CC5ULL,
		0x054889839EE72A01ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7A92181D9F04CFBEULL,
		0xC8B33CF73323D721ULL,
		0xF2E8CC8C4B7F3E21ULL,
		0x58785BF6B116E769ULL,
		0x4AB9CF210A539A76ULL,
		0x94D3AA858CBAE739ULL,
		0xAC2EAAB05D93198BULL,
		0x0A9113073DCE5403ULL
	}};
	printf("Test Case 115\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x2125A6BBC3F305AAULL,
		0xF40364442A9797C1ULL,
		0x3E882050E5DAA244ULL,
		0x5F95D4E3A87572CFULL,
		0xA80F52865F66CE20ULL,
		0x31CD6F30D1E54884ULL,
		0x7F7FEB93C5AB74CCULL,
		0x1B599BFC58B8EF5EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x424B4D7787E60B54ULL,
		0xE806C888552F2F82ULL,
		0x7D1040A1CBB54489ULL,
		0xBF2BA9C750EAE59EULL,
		0x501EA50CBECD9C40ULL,
		0x639ADE61A3CA9109ULL,
		0xFEFFD7278B56E998ULL,
		0x36B337F8B171DEBCULL
	}};
	printf("Test Case 116\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x19574B8C97052CADULL,
		0xA7BB2C8B2B29262DULL,
		0xD0F5F6FAAF0D87CDULL,
		0xFD2714791461DCBDULL,
		0x4A083B835AE86C99ULL,
		0x2506B046443741B1ULL,
		0xD895D98DCFE891A8ULL,
		0x30C43EFC27207820ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x32AE97192E0A595AULL,
		0x4F76591656524C5AULL,
		0xA1EBEDF55E1B0F9BULL,
		0xFA4E28F228C3B97BULL,
		0x94107706B5D0D933ULL,
		0x4A0D608C886E8362ULL,
		0xB12BB31B9FD12350ULL,
		0x61887DF84E40F041ULL
	}};
	printf("Test Case 117\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xB0D2B8E167B09B95ULL,
		0xB974F40C6B2B747BULL,
		0xC92FED20FA2AA06CULL,
		0x8319A991A4CC1010ULL,
		0xDDC77BE2ABE8B819ULL,
		0x3510CE3601315453ULL,
		0xF4BFA68681E1942DULL,
		0x3405AD4DD9C4B7F0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x61A571C2CF61372AULL,
		0x72E9E818D656E8F7ULL,
		0x925FDA41F45540D9ULL,
		0x0633532349982021ULL,
		0xBB8EF7C557D17033ULL,
		0x6A219C6C0262A8A7ULL,
		0xE97F4D0D03C3285AULL,
		0x680B5A9BB3896FE1ULL
	}};
	printf("Test Case 118\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xBDA55CFC229A4CECULL,
		0x0695ED5992D4B0F4ULL,
		0xC36EA6350085484EULL,
		0xD9C4D775625F7B5EULL,
		0x617D468A51B7A06BULL,
		0xD9DA93DE352F749CULL,
		0x52ACAF9980DB4996ULL,
		0x322029E8B82CB285ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7B4AB9F8453499D8ULL,
		0x0D2BDAB325A961E9ULL,
		0x86DD4C6A010A909CULL,
		0xB389AEEAC4BEF6BDULL,
		0xC2FA8D14A36F40D7ULL,
		0xB3B527BC6A5EE938ULL,
		0xA5595F3301B6932DULL,
		0x644053D17059650AULL
	}};
	printf("Test Case 119\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xEECFBC670B5A4B0FULL,
		0x676AE61B045723CCULL,
		0x3F627E0E435568BAULL,
		0x6069137075851CF8ULL,
		0x0167D1D1E0970436ULL,
		0xBA987905354633D9ULL,
		0xB375CBB91A2FB7C3ULL,
		0x2A45A443F7C9E979ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDD9F78CE16B4961EULL,
		0xCED5CC3608AE4799ULL,
		0x7EC4FC1C86AAD174ULL,
		0xC0D226E0EB0A39F0ULL,
		0x02CFA3A3C12E086CULL,
		0x7530F20A6A8C67B2ULL,
		0x66EB9772345F6F87ULL,
		0x548B4887EF93D2F3ULL
	}};
	printf("Test Case 120\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xF3B1718E163313FAULL,
		0x0F1ADEF5AEC3F37FULL,
		0x121EE9CFFF6021F0ULL,
		0x79F2810ACAEA84F5ULL,
		0x533E60C65B9E2EB2ULL,
		0xCE762072B3442A70ULL,
		0x0FCD686204906891ULL,
		0x1BD4CF093675E429ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE762E31C2C6627F4ULL,
		0x1E35BDEB5D87E6FFULL,
		0x243DD39FFEC043E0ULL,
		0xF3E5021595D509EAULL,
		0xA67CC18CB73C5D64ULL,
		0x9CEC40E5668854E0ULL,
		0x1F9AD0C40920D123ULL,
		0x37A99E126CEBC852ULL
	}};
	printf("Test Case 121\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xB3F44447247D320DULL,
		0xD8C8F2BC40494E7EULL,
		0x0845E874EB4FBEBDULL,
		0xA816F3534544A287ULL,
		0x32FDB1D763A74937ULL,
		0x7C6DDFBD769F6BCEULL,
		0xA7BB2800DE05B27AULL,
		0x06DAA409A231AC8CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x67E8888E48FA641AULL,
		0xB191E57880929CFDULL,
		0x108BD0E9D69F7D7BULL,
		0x502DE6A68A89450EULL,
		0x65FB63AEC74E926FULL,
		0xF8DBBF7AED3ED79CULL,
		0x4F765001BC0B64F4ULL,
		0x0DB5481344635919ULL
	}};
	printf("Test Case 122\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x89E0E0BABBDD55DEULL,
		0x6D3906445D031A8EULL,
		0x45E5503CFB906ABAULL,
		0xBEAD8FEECB91A02CULL,
		0xD3979CBE32C6FA65ULL,
		0x62B0FB6D7F1BF891ULL,
		0x636565DB1FBB9CF9ULL,
		0x1A7720109713B4E2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x13C1C17577BAABBCULL,
		0xDA720C88BA06351DULL,
		0x8BCAA079F720D574ULL,
		0x7D5B1FDD97234058ULL,
		0xA72F397C658DF4CBULL,
		0xC561F6DAFE37F123ULL,
		0xC6CACBB63F7739F2ULL,
		0x34EE40212E2769C4ULL
	}};
	printf("Test Case 123\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x5DAF569111D01E4CULL,
		0x85BEF7DFA240644FULL,
		0x3B02A107EC7AA4B8ULL,
		0xA6A688DDB4718249ULL,
		0xB43FD905CCD9FDE7ULL,
		0x500B2D427F80F2DCULL,
		0xD5F7421781C28816ULL,
		0x1C3947FD44AED8F5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB5EAD2223A03C98ULL,
		0x0B7DEFBF4480C89EULL,
		0x7605420FD8F54971ULL,
		0x4D4D11BB68E30492ULL,
		0x687FB20B99B3FBCFULL,
		0xA0165A84FF01E5B9ULL,
		0xABEE842F0385102CULL,
		0x38728FFA895DB1EBULL
	}};
	printf("Test Case 124\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x96965BDBAECC7A88ULL,
		0x58DBB5BDDB343D8EULL,
		0x2879A37574B64D4AULL,
		0x9A3EEB1D4F1FE0C2ULL,
		0xF25A1F20BF2D5DEFULL,
		0x021C099A70284245ULL,
		0x89A79CC3404037D4ULL,
		0x22831F1456C556D6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2D2CB7B75D98F510ULL,
		0xB1B76B7BB6687B1DULL,
		0x50F346EAE96C9A94ULL,
		0x347DD63A9E3FC184ULL,
		0xE4B43E417E5ABBDFULL,
		0x04381334E050848BULL,
		0x134F398680806FA8ULL,
		0x45063E28AD8AADADULL
	}};
	printf("Test Case 125\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x5E9E6116F10E70E4ULL,
		0x50E610AD2270C865ULL,
		0x0ACC9391B8C4735DULL,
		0xBF23662608E8045BULL,
		0x0D529AFCEF046239ULL,
		0x46586F901A72A44EULL,
		0x0FE212FF8B14426CULL,
		0x0FACC310CDDC59D1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBD3CC22DE21CE1C8ULL,
		0xA1CC215A44E190CAULL,
		0x159927237188E6BAULL,
		0x7E46CC4C11D008B6ULL,
		0x1AA535F9DE08C473ULL,
		0x8CB0DF2034E5489CULL,
		0x1FC425FF162884D8ULL,
		0x1F5986219BB8B3A2ULL
	}};
	printf("Test Case 126\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x0A963C7EF33DBD1BULL,
		0xFD8C7B80D54DD0B2ULL,
		0xD6E1A4BB7B274483ULL,
		0x1BBAB9214B015217ULL,
		0xEB04DCE4DB069347ULL,
		0x09B1F2C6D83F43E8ULL,
		0x8414A0B0C169C138ULL,
		0x194A2F4EF66F3F66ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x152C78FDE67B7A36ULL,
		0xFB18F701AA9BA164ULL,
		0xADC34976F64E8907ULL,
		0x377572429602A42FULL,
		0xD609B9C9B60D268EULL,
		0x1363E58DB07E87D1ULL,
		0x0829416182D38270ULL,
		0x32945E9DECDE7ECDULL
	}};
	printf("Test Case 127\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xD28CFE167BD25C73ULL,
		0x9B30BF01CC592F93ULL,
		0x3D450ADDDED47835ULL,
		0x3B081BA24F36724AULL,
		0xD15C7F0CA39DAB06ULL,
		0x338ADC34C3FD7E74ULL,
		0xB93A07F93998636FULL,
		0x327B195C7F2406FBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA519FC2CF7A4B8E6ULL,
		0x36617E0398B25F27ULL,
		0x7A8A15BBBDA8F06BULL,
		0x761037449E6CE494ULL,
		0xA2B8FE19473B560CULL,
		0x6715B86987FAFCE9ULL,
		0x72740FF27330C6DEULL,
		0x64F632B8FE480DF7ULL
	}};
	printf("Test Case 128\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xF5E713A40BE26948ULL,
		0x2A9B838D6D4C6943ULL,
		0xD7467121059EA2B1ULL,
		0xFFE2E986CCDE4311ULL,
		0x1394C54EFAE5F403ULL,
		0x3C30B572164E1865ULL,
		0x207FAC2AB3411F44ULL,
		0x359BB5278779C085ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEBCE274817C4D290ULL,
		0x5537071ADA98D287ULL,
		0xAE8CE2420B3D4562ULL,
		0xFFC5D30D99BC8623ULL,
		0x27298A9DF5CBE807ULL,
		0x78616AE42C9C30CAULL,
		0x40FF585566823E88ULL,
		0x6B376A4F0EF3810AULL
	}};
	printf("Test Case 129\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xB576580D95916ACFULL,
		0x46D5602DDC1ADCF6ULL,
		0x9E98F2FFDE502A27ULL,
		0x4ACA6B37B89A74AAULL,
		0x9A58F186875DB572ULL,
		0x94EEFFD57BB91067ULL,
		0xF1CDD227D9D01A50ULL,
		0x0CF6DB7410631350ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6AECB01B2B22D59EULL,
		0x8DAAC05BB835B9EDULL,
		0x3D31E5FFBCA0544EULL,
		0x9594D66F7134E955ULL,
		0x34B1E30D0EBB6AE4ULL,
		0x29DDFFAAF77220CFULL,
		0xE39BA44FB3A034A1ULL,
		0x19EDB6E820C626A1ULL
	}};
	printf("Test Case 130\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xBE92822D232BF568ULL,
		0x91BFEB6A14421CC1ULL,
		0x7763D226D4A4C94AULL,
		0x61C4F7A2E1A56148ULL,
		0xE7EDB5E567CBEA44ULL,
		0xE19CC9FB8FFBBD8AULL,
		0x201FA56FAC2AE90FULL,
		0x04B746928621922FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7D25045A4657EAD0ULL,
		0x237FD6D428843983ULL,
		0xEEC7A44DA9499295ULL,
		0xC389EF45C34AC290ULL,
		0xCFDB6BCACF97D488ULL,
		0xC33993F71FF77B15ULL,
		0x403F4ADF5855D21FULL,
		0x096E8D250C43245EULL
	}};
	printf("Test Case 131\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x72EABB11360BD0C5ULL,
		0xB365D9042DD74193ULL,
		0x42A55DC9E2548480ULL,
		0x44CC47BF2DCE0403ULL,
		0x49FCFB57E38AC308ULL,
		0x8C0166C8F5344699ULL,
		0xBEC7B9C378DADA19ULL,
		0x2D21F600089AA8B5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE5D576226C17A18AULL,
		0x66CBB2085BAE8326ULL,
		0x854ABB93C4A90901ULL,
		0x89988F7E5B9C0806ULL,
		0x93F9F6AFC7158610ULL,
		0x1802CD91EA688D32ULL,
		0x7D8F7386F1B5B433ULL,
		0x5A43EC001135516BULL
	}};
	printf("Test Case 132\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xD91704F7101556A7ULL,
		0xC7426FFD4452B91FULL,
		0x1B2DECAA6C7281AFULL,
		0x3A553BF7B74AC09FULL,
		0xF4A98A9B77346DF9ULL,
		0x637EA5DB834CB933ULL,
		0x6F5900F40FF5365DULL,
		0x3B0C78366AD6E000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB22E09EE202AAD4EULL,
		0x8E84DFFA88A5723FULL,
		0x365BD954D8E5035FULL,
		0x74AA77EF6E95813EULL,
		0xE9531536EE68DBF2ULL,
		0xC6FD4BB706997267ULL,
		0xDEB201E81FEA6CBAULL,
		0x7618F06CD5ADC000ULL
	}};
	printf("Test Case 133\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x2593B98174E1D27AULL,
		0xB06E109E28CD4214ULL,
		0x16CA37BB6B785686ULL,
		0x71E3D9BFD840795AULL,
		0x1655F2E8B56846B9ULL,
		0x474DC12F353BE6C8ULL,
		0xBBBCA6B3294025C6ULL,
		0x10453D64B65AC79CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4B277302E9C3A4F4ULL,
		0x60DC213C519A8428ULL,
		0x2D946F76D6F0AD0DULL,
		0xE3C7B37FB080F2B4ULL,
		0x2CABE5D16AD08D72ULL,
		0x8E9B825E6A77CD90ULL,
		0x77794D6652804B8CULL,
		0x208A7AC96CB58F39ULL
	}};
	printf("Test Case 134\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xF4C119A1DC138104ULL,
		0xA39DE23C20695612ULL,
		0x14F9B36826BA640EULL,
		0xC1EC1A622C9FD383ULL,
		0x03309A7C6F2397DEULL,
		0x985BE0ECACE36AC9ULL,
		0xCF0E9CFFB0B278FBULL,
		0x34F949EAF60D4285ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE9823343B8270208ULL,
		0x473BC47840D2AC25ULL,
		0x29F366D04D74C81DULL,
		0x83D834C4593FA706ULL,
		0x066134F8DE472FBDULL,
		0x30B7C1D959C6D592ULL,
		0x9E1D39FF6164F1F7ULL,
		0x69F293D5EC1A850BULL
	}};
	printf("Test Case 135\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xC5711852A39A2047ULL,
		0xBB4648507EFC71CAULL,
		0x0EC1A56FB3196619ULL,
		0x73EC880873407A81ULL,
		0x801AFCDA9BECE59BULL,
		0x63A62C558EB68CF4ULL,
		0x2198ECCEA4DD77ABULL,
		0x0A875F798DE24C51ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8AE230A54734408EULL,
		0x768C90A0FDF8E395ULL,
		0x1D834ADF6632CC33ULL,
		0xE7D91010E680F502ULL,
		0x0035F9B537D9CB36ULL,
		0xC74C58AB1D6D19E9ULL,
		0x4331D99D49BAEF56ULL,
		0x150EBEF31BC498A2ULL
	}};
	printf("Test Case 136\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x75A47CB440F05E1CULL,
		0xF1982E9FB6AC6B4FULL,
		0x786CDE126A0FEC8EULL,
		0xB35B6D18E3E178BBULL,
		0xECE00B2937351B70ULL,
		0xA592F2A0E710E579ULL,
		0x5B07DCB68D1C2AF0ULL,
		0x3F5B095A6DB00635ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEB48F96881E0BC38ULL,
		0xE3305D3F6D58D69EULL,
		0xF0D9BC24D41FD91DULL,
		0x66B6DA31C7C2F176ULL,
		0xD9C016526E6A36E1ULL,
		0x4B25E541CE21CAF3ULL,
		0xB60FB96D1A3855E1ULL,
		0x7EB612B4DB600C6AULL
	}};
	printf("Test Case 137\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xEDB42222A8061D7BULL,
		0x7DD03F33D0628547ULL,
		0x0E6C78CB6A7B0561ULL,
		0xE8572C2FB0E019B2ULL,
		0x1982E440D4468E73ULL,
		0x0050CBC81808C8FDULL,
		0xB4CB36D85F9F1073ULL,
		0x12C6179A9F83D4FAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDB684445500C3AF6ULL,
		0xFBA07E67A0C50A8FULL,
		0x1CD8F196D4F60AC2ULL,
		0xD0AE585F61C03364ULL,
		0x3305C881A88D1CE7ULL,
		0x00A19790301191FAULL,
		0x69966DB0BF3E20E6ULL,
		0x258C2F353F07A9F5ULL
	}};
	printf("Test Case 138\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x2BB9B4F6AD0AF2E5ULL,
		0x75C784D3D1EE1A79ULL,
		0x448F9420873DE144ULL,
		0xD606DEAA13BFB77DULL,
		0x08CC17FE444325C1ULL,
		0x1FF2CE5D5E05BF85ULL,
		0xCC0838AEAE86067DULL,
		0x1143D42A7B37F3A9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x577369ED5A15E5CAULL,
		0xEB8F09A7A3DC34F2ULL,
		0x891F28410E7BC288ULL,
		0xAC0DBD54277F6EFAULL,
		0x11982FFC88864B83ULL,
		0x3FE59CBABC0B7F0AULL,
		0x9810715D5D0C0CFAULL,
		0x2287A854F66FE753ULL
	}};
	printf("Test Case 139\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xC08A0A21DBD83875ULL,
		0x9E3F92E38A9FF9F2ULL,
		0xD28FF81191CC345CULL,
		0xA699F52E54ECF5A6ULL,
		0xFB166753F1B3B20FULL,
		0x6978B7F438971DA9ULL,
		0xC19CF2F042F84A85ULL,
		0x0007E0062ED41F96ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x81141443B7B070EAULL,
		0x3C7F25C7153FF3E5ULL,
		0xA51FF023239868B9ULL,
		0x4D33EA5CA9D9EB4DULL,
		0xF62CCEA7E367641FULL,
		0xD2F16FE8712E3B53ULL,
		0x8339E5E085F0950AULL,
		0x000FC00C5DA83F2DULL
	}};
	printf("Test Case 140\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x5DE01F2B7C18D3DDULL,
		0x9F3ECC8F26870A6AULL,
		0xCAAEB12A82299EFBULL,
		0xFD80E857352E52E1ULL,
		0xB44F86A24DEECBAAULL,
		0xF5A02CAFC3A37F33ULL,
		0x32ADCC56C955CCF1ULL,
		0x14322DDDA323699CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBBC03E56F831A7BAULL,
		0x3E7D991E4D0E14D4ULL,
		0x955D625504533DF7ULL,
		0xFB01D0AE6A5CA5C3ULL,
		0x689F0D449BDD9755ULL,
		0xEB40595F8746FE67ULL,
		0x655B98AD92AB99E3ULL,
		0x28645BBB4646D338ULL
	}};
	printf("Test Case 141\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xE7E574EF3A852313ULL,
		0x99AB18701E5C4A73ULL,
		0xD6D489398105430CULL,
		0xC9C70730AC6554C3ULL,
		0x3BB4DB89A3CC3B94ULL,
		0x43B8F4AC28992315ULL,
		0xE10987D3C059133BULL,
		0x08B9BB64CB62C7B9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCFCAE9DE750A4626ULL,
		0x335630E03CB894E7ULL,
		0xADA91273020A8619ULL,
		0x938E0E6158CAA987ULL,
		0x7769B71347987729ULL,
		0x8771E9585132462AULL,
		0xC2130FA780B22676ULL,
		0x117376C996C58F73ULL
	}};
	printf("Test Case 142\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x277286EA5538C575ULL,
		0x1B1E3FAFE8254FF8ULL,
		0x65CB1D44B7F17FD8ULL,
		0x662D5C82E4FFF0A9ULL,
		0xEB1D54AD5DE03F99ULL,
		0x1FFE71953BDBFB43ULL,
		0xA60E50B1F8AA1A68ULL,
		0x1D69B34E3D690E4BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4EE50DD4AA718AEAULL,
		0x363C7F5FD04A9FF0ULL,
		0xCB963A896FE2FFB0ULL,
		0xCC5AB905C9FFE152ULL,
		0xD63AA95ABBC07F32ULL,
		0x3FFCE32A77B7F687ULL,
		0x4C1CA163F15434D0ULL,
		0x3AD3669C7AD21C97ULL
	}};
	printf("Test Case 143\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x0E5E1CDB4A344CD7ULL,
		0xA3F5BC10AC1CD0A4ULL,
		0x2B3DB882D9CE326DULL,
		0x07EB13062365D057ULL,
		0xC9270BD85F9E7393ULL,
		0xA268064B1B9DD804ULL,
		0x19D7F23FA501210BULL,
		0x1312E976622FD325ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1CBC39B6946899AEULL,
		0x47EB78215839A148ULL,
		0x567B7105B39C64DBULL,
		0x0FD6260C46CBA0AEULL,
		0x924E17B0BF3CE726ULL,
		0x44D00C96373BB009ULL,
		0x33AFE47F4A024217ULL,
		0x2625D2ECC45FA64AULL
	}};
	printf("Test Case 144\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x70B9D8BA1C4EAA74ULL,
		0xEFB22441EF17737EULL,
		0x8CC8CBA2BAFBC99AULL,
		0xC647777287DC52B7ULL,
		0xF121CFE4E088263FULL,
		0x51751089FB5F14CEULL,
		0x62C8222F000F2D2FULL,
		0x21D075EAE5F99EC1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE173B174389D54E8ULL,
		0xDF644883DE2EE6FCULL,
		0x1991974575F79335ULL,
		0x8C8EEEE50FB8A56FULL,
		0xE2439FC9C1104C7FULL,
		0xA2EA2113F6BE299DULL,
		0xC590445E001E5A5EULL,
		0x43A0EBD5CBF33D82ULL
	}};
	printf("Test Case 145\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xF53E6F555B045671ULL,
		0xAD87CA638F72F41AULL,
		0x9A69AC30A067234CULL,
		0x4FAAF444BB7D0732ULL,
		0x274A2F255C574B87ULL,
		0x894B1C7900525E06ULL,
		0x46908383369C6C98ULL,
		0x197E915F1E9B0331ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEA7CDEAAB608ACE2ULL,
		0x5B0F94C71EE5E835ULL,
		0x34D3586140CE4699ULL,
		0x9F55E88976FA0E65ULL,
		0x4E945E4AB8AE970EULL,
		0x129638F200A4BC0CULL,
		0x8D2107066D38D931ULL,
		0x32FD22BE3D360662ULL
	}};
	printf("Test Case 146\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xC390F12091DEA071ULL,
		0x2818F85A314B1648ULL,
		0x02C1FDA9635AB1C0ULL,
		0x81F2FBE54CE571FDULL,
		0x1F7D4610091F9A92ULL,
		0xC5F941F82D78A0F7ULL,
		0x063EE74656E11DEDULL,
		0x167BDAB798DFD4EEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8721E24123BD40E2ULL,
		0x5031F0B462962C91ULL,
		0x0583FB52C6B56380ULL,
		0x03E5F7CA99CAE3FAULL,
		0x3EFA8C20123F3525ULL,
		0x8BF283F05AF141EEULL,
		0x0C7DCE8CADC23BDBULL,
		0x2CF7B56F31BFA9DCULL
	}};
	printf("Test Case 147\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xEC56A1FCA6DC25BAULL,
		0x87797522DD8F27F7ULL,
		0x4FF76400B33163C0ULL,
		0x4A04495606E71226ULL,
		0x79DEB2C750736742ULL,
		0xE4D70B82F9853B7CULL,
		0x3CD3993128AF6ECDULL,
		0x2B13348B9E52D792ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD8AD43F94DB84B74ULL,
		0x0EF2EA45BB1E4FEFULL,
		0x9FEEC8016662C781ULL,
		0x940892AC0DCE244CULL,
		0xF3BD658EA0E6CE84ULL,
		0xC9AE1705F30A76F8ULL,
		0x79A73262515EDD9BULL,
		0x562669173CA5AF24ULL
	}};
	printf("Test Case 148\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xA1CFA9D9A804A0F9ULL,
		0x0F9D00A2C087976BULL,
		0x19F486AC53E5558AULL,
		0xBF6D2D9D801F3624ULL,
		0xC0E4602EE703BBBAULL,
		0x3E2CDA76B57AE471ULL,
		0x7F96A356AF066C70ULL,
		0x13756DD7C69CD840ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x439F53B3500941F2ULL,
		0x1F3A0145810F2ED7ULL,
		0x33E90D58A7CAAB14ULL,
		0x7EDA5B3B003E6C48ULL,
		0x81C8C05DCE077775ULL,
		0x7C59B4ED6AF5C8E3ULL,
		0xFF2D46AD5E0CD8E0ULL,
		0x26EADBAF8D39B080ULL
	}};
	printf("Test Case 149\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xB60B150AC6EFEF44ULL,
		0x334E1E1A2F55AB54ULL,
		0xC814950B3ED9E186ULL,
		0x398269D140EA2957ULL,
		0xACC2B4A3B9B41157ULL,
		0x781D3EB59A295C86ULL,
		0xD66A9F1B3CBD3D89ULL,
		0x3952A39DF2655805ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6C162A158DDFDE88ULL,
		0x669C3C345EAB56A9ULL,
		0x90292A167DB3C30CULL,
		0x7304D3A281D452AFULL,
		0x59856947736822AEULL,
		0xF03A7D6B3452B90DULL,
		0xACD53E36797A7B12ULL,
		0x72A5473BE4CAB00BULL
	}};
	printf("Test Case 150\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xE19EC6F56BA480D9ULL,
		0x59446F8C46B40984ULL,
		0x0EAF95A5F7D7A29DULL,
		0x8BB7CB4CFE17627EULL,
		0x079080E842D768ABULL,
		0x22C646BDD31F559CULL,
		0xFB121E8E9DAB3817ULL,
		0x1A5D8B9E3BF3369AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC33D8DEAD74901B2ULL,
		0xB288DF188D681309ULL,
		0x1D5F2B4BEFAF453AULL,
		0x176F9699FC2EC4FCULL,
		0x0F2101D085AED157ULL,
		0x458C8D7BA63EAB38ULL,
		0xF6243D1D3B56702EULL,
		0x34BB173C77E66D35ULL
	}};
	printf("Test Case 151\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x8748F6E7302FBB31ULL,
		0x6463DD34A3D66AE1ULL,
		0x0C4618CCB9CA5130ULL,
		0x6A7B603B4A1D88C1ULL,
		0xF7052F51A8AE8BAEULL,
		0x8C28F0BB8F852759ULL,
		0x8C7758E08F4BDF30ULL,
		0x18D4618AD3CE4313ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0E91EDCE605F7662ULL,
		0xC8C7BA6947ACD5C3ULL,
		0x188C31997394A260ULL,
		0xD4F6C076943B1182ULL,
		0xEE0A5EA3515D175CULL,
		0x1851E1771F0A4EB3ULL,
		0x18EEB1C11E97BE61ULL,
		0x31A8C315A79C8627ULL
	}};
	printf("Test Case 152\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x312C9AF7D2EBB26EULL,
		0x13FA9672E6A5AF14ULL,
		0xC50AC6E9DE81486CULL,
		0xE29F40C539DAABA1ULL,
		0xD4EFF90639A58472ULL,
		0x128388CFDE863FA6ULL,
		0x89CF237A4F337BF4ULL,
		0x180579D36C2A4061ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x625935EFA5D764DCULL,
		0x27F52CE5CD4B5E28ULL,
		0x8A158DD3BD0290D8ULL,
		0xC53E818A73B55743ULL,
		0xA9DFF20C734B08E5ULL,
		0x2507119FBD0C7F4DULL,
		0x139E46F49E66F7E8ULL,
		0x300AF3A6D85480C3ULL
	}};
	printf("Test Case 153\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x5EF06122D93E2C04ULL,
		0xFF6D12EE021AEB9AULL,
		0xB4A8F47D47E9F67DULL,
		0x407ECA482583473FULL,
		0xB18A4D3A9E7A9D8FULL,
		0x58A22630B2A177CCULL,
		0x28CD262A56A8E912ULL,
		0x3A54DE830768ECD2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBDE0C245B27C5808ULL,
		0xFEDA25DC0435D734ULL,
		0x6951E8FA8FD3ECFBULL,
		0x80FD94904B068E7FULL,
		0x63149A753CF53B1EULL,
		0xB1444C616542EF99ULL,
		0x519A4C54AD51D224ULL,
		0x74A9BD060ED1D9A4ULL
	}};
	printf("Test Case 154\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xE9AB6CB24550383AULL,
		0xFB13F306FB129633ULL,
		0xD0447A7A71D27F5EULL,
		0x920CAA4EC1857B22ULL,
		0x4AE3EE2C6885F1EBULL,
		0x354DCB98822636DFULL,
		0x2456B33F71D689ABULL,
		0x14D0F8A2213CFED5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD356D9648AA07074ULL,
		0xF627E60DF6252C67ULL,
		0xA088F4F4E3A4FEBDULL,
		0x2419549D830AF645ULL,
		0x95C7DC58D10BE3D7ULL,
		0x6A9B9731044C6DBEULL,
		0x48AD667EE3AD1356ULL,
		0x29A1F1444279FDAAULL
	}};
	printf("Test Case 155\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xDD4B2CFC41B8223FULL,
		0x5CF738419113A9BAULL,
		0xE17FD029E85952EAULL,
		0x9DAC84BEB1291E81ULL,
		0x3244235C1CC2CF7CULL,
		0xAAC3A937B1BF246DULL,
		0x20B6B4A3B8F4648DULL,
		0x2008AAC4131FE85FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBA9659F88370447EULL,
		0xB9EE708322275375ULL,
		0xC2FFA053D0B2A5D4ULL,
		0x3B59097D62523D03ULL,
		0x648846B839859EF9ULL,
		0x5587526F637E48DAULL,
		0x416D694771E8C91BULL,
		0x40115588263FD0BEULL
	}};
	printf("Test Case 156\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x8BD6B9C58B7A172CULL,
		0x33F6AA35CCE55A33ULL,
		0x7A8ECA4A780F0640ULL,
		0xD6DAE36A37ED85F8ULL,
		0x4FBD80FF5DD6B1CAULL,
		0x0D2DC4C004D97906ULL,
		0xC8AE1257D85708A2ULL,
		0x1D8FC2DA92115EF7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x17AD738B16F42E58ULL,
		0x67ED546B99CAB467ULL,
		0xF51D9494F01E0C80ULL,
		0xADB5C6D46FDB0BF0ULL,
		0x9F7B01FEBBAD6395ULL,
		0x1A5B898009B2F20CULL,
		0x915C24AFB0AE1144ULL,
		0x3B1F85B52422BDEFULL
	}};
	printf("Test Case 157\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x6F3360BD11E181C0ULL,
		0x9535E6E0F7EB26D7ULL,
		0x511CDB09253064F7ULL,
		0x7EF4C02098B95608ULL,
		0xA59ACD8A41B4180AULL,
		0x1CCE6ADE0296288DULL,
		0x52D0A590F288C163ULL,
		0x370493F8CEE7E260ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDE66C17A23C30380ULL,
		0x2A6BCDC1EFD64DAEULL,
		0xA239B6124A60C9EFULL,
		0xFDE980413172AC10ULL,
		0x4B359B1483683014ULL,
		0x399CD5BC052C511BULL,
		0xA5A14B21E51182C6ULL,
		0x6E0927F19DCFC4C0ULL
	}};
	printf("Test Case 158\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x1C3F9CC4432D526BULL,
		0xC638CC578E64BAF0ULL,
		0xE3F9B4C99FE5AE06ULL,
		0xC6666C74A3C4EA69ULL,
		0x285293593EFB6FEAULL,
		0x8D37B5F4B9730BAEULL,
		0x2F7C1E0AF53DB118ULL,
		0x1174EAB8A24C01A3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x387F3988865AA4D6ULL,
		0x8C7198AF1CC975E0ULL,
		0xC7F369933FCB5C0DULL,
		0x8CCCD8E94789D4D3ULL,
		0x50A526B27DF6DFD5ULL,
		0x1A6F6BE972E6175CULL,
		0x5EF83C15EA7B6231ULL,
		0x22E9D57144980346ULL
	}};
	printf("Test Case 159\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x6C434108DEDD2652ULL,
		0x74BE5A8B352AF96AULL,
		0xFFF682DCF11C9DB0ULL,
		0x0B3F20F02E99F89FULL,
		0x5F60E06C91E161DFULL,
		0x09BFF22E7EEF7D6BULL,
		0xDDF825FF9892F15BULL,
		0x17BB2BE35A5EC744ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD8868211BDBA4CA4ULL,
		0xE97CB5166A55F2D4ULL,
		0xFFED05B9E2393B60ULL,
		0x167E41E05D33F13FULL,
		0xBEC1C0D923C2C3BEULL,
		0x137FE45CFDDEFAD6ULL,
		0xBBF04BFF3125E2B6ULL,
		0x2F7657C6B4BD8E89ULL
	}};
	printf("Test Case 160\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x74A4AF883C935097ULL,
		0x02078A791ED71870ULL,
		0xF2B40ADCBF0EF73CULL,
		0x00F3A10CBA7330A2ULL,
		0x1FB53314689D618AULL,
		0x5A59107E2E8D19E9ULL,
		0x384867BB0BCE6F02ULL,
		0x16A4879BC5D9378EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE9495F107926A12EULL,
		0x040F14F23DAE30E0ULL,
		0xE56815B97E1DEE78ULL,
		0x01E7421974E66145ULL,
		0x3F6A6628D13AC314ULL,
		0xB4B220FC5D1A33D2ULL,
		0x7090CF76179CDE04ULL,
		0x2D490F378BB26F1CULL
	}};
	printf("Test Case 161\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x0AA507171E86B089ULL,
		0x0649323071A67B82ULL,
		0x99C81ACB67A552E2ULL,
		0xFBDF3F91218968B5ULL,
		0xB3186C7B61CA8F62ULL,
		0xFC59E4039B445CA6ULL,
		0x12E580B7663E4B3EULL,
		0x1C925E5A045E733BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x154A0E2E3D0D6112ULL,
		0x0C926460E34CF704ULL,
		0x33903596CF4AA5C4ULL,
		0xF7BE7F224312D16BULL,
		0x6630D8F6C3951EC5ULL,
		0xF8B3C8073688B94DULL,
		0x25CB016ECC7C967DULL,
		0x3924BCB408BCE676ULL
	}};
	printf("Test Case 162\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x510DD7EA067F9EAEULL,
		0xC77D483D55807E4EULL,
		0x5717C52C73124E04ULL,
		0xEC9F897CBD6B21A5ULL,
		0xB97FD6AB1B137C90ULL,
		0xF009F3CB887539B2ULL,
		0xFAE2E6F874587B7DULL,
		0x17090539EA671F82ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA21BAFD40CFF3D5CULL,
		0x8EFA907AAB00FC9CULL,
		0xAE2F8A58E6249C09ULL,
		0xD93F12F97AD6434AULL,
		0x72FFAD563626F921ULL,
		0xE013E79710EA7365ULL,
		0xF5C5CDF0E8B0F6FBULL,
		0x2E120A73D4CE3F05ULL
	}};
	printf("Test Case 163\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x475C8D51D99D7D22ULL,
		0x5BEA0CBF34E7ED5DULL,
		0x4FE4FEF32CD24A80ULL,
		0x7A5E40B5DA9F2627ULL,
		0x60BD3FA51BCCDDA6ULL,
		0xFDA562B11D93011BULL,
		0x9E0A85FDF1C35436ULL,
		0x1F97B5FACDF2FD2EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8EB91AA3B33AFA44ULL,
		0xB7D4197E69CFDABAULL,
		0x9FC9FDE659A49500ULL,
		0xF4BC816BB53E4C4EULL,
		0xC17A7F4A3799BB4CULL,
		0xFB4AC5623B260236ULL,
		0x3C150BFBE386A86DULL,
		0x3F2F6BF59BE5FA5DULL
	}};
	printf("Test Case 164\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x80DEEDDE749980BFULL,
		0x5AD5FB334E8C83CCULL,
		0xDAD815EFAD0F0089ULL,
		0x2B7BC54AE8369EA7ULL,
		0xF1F2046E52037313ULL,
		0xC965725321C0DF52ULL,
		0xD3059C00B6B8C5E1ULL,
		0x08EDDDCCC27EA6A4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x01BDDBBCE933017EULL,
		0xB5ABF6669D190799ULL,
		0xB5B02BDF5A1E0112ULL,
		0x56F78A95D06D3D4FULL,
		0xE3E408DCA406E626ULL,
		0x92CAE4A64381BEA5ULL,
		0xA60B38016D718BC3ULL,
		0x11DBBB9984FD4D49ULL
	}};
	printf("Test Case 165\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x1ED2402B9120DAE6ULL,
		0xA8F9F5E89EC82925ULL,
		0xC82BC5B55E4868E6ULL,
		0x53078D89E3EA27B8ULL,
		0x81FB590B587A82D8ULL,
		0x14FDD1C2DD7C4866ULL,
		0x80886DED04021E0AULL,
		0x26330BC686174905ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3DA480572241B5CCULL,
		0x51F3EBD13D90524AULL,
		0x90578B6ABC90D1CDULL,
		0xA60F1B13C7D44F71ULL,
		0x03F6B216B0F505B0ULL,
		0x29FBA385BAF890CDULL,
		0x0110DBDA08043C14ULL,
		0x4C66178D0C2E920BULL
	}};
	printf("Test Case 166\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xF4C1C5D259B9D0C0ULL,
		0x773C0992EA5D6C87ULL,
		0x28C7ED8F4BB76797ULL,
		0x7647FBED607ED823ULL,
		0x0F5E01853E7D7C10ULL,
		0xDF63EB078B00D200ULL,
		0xBDCDB2244D02532FULL,
		0x327EF5B5D675F236ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE9838BA4B373A180ULL,
		0xEE781325D4BAD90FULL,
		0x518FDB1E976ECF2EULL,
		0xEC8FF7DAC0FDB046ULL,
		0x1EBC030A7CFAF820ULL,
		0xBEC7D60F1601A400ULL,
		0x7B9B64489A04A65FULL,
		0x64FDEB6BACEBE46DULL
	}};
	printf("Test Case 167\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xAF0798EB349B8E01ULL,
		0x14BBEE4711AA5775ULL,
		0x953B2A88ECFF53D9ULL,
		0x114AFF4171FE92BCULL,
		0xB8CCC65E5B32E78EULL,
		0xEBEF7C20269E4606ULL,
		0x1071DB153E089180ULL,
		0x002371B166FBCDECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5E0F31D669371C02ULL,
		0x2977DC8E2354AEEBULL,
		0x2A765511D9FEA7B2ULL,
		0x2295FE82E3FD2579ULL,
		0x71998CBCB665CF1CULL,
		0xD7DEF8404D3C8C0DULL,
		0x20E3B62A7C112301ULL,
		0x0046E362CDF79BD8ULL
	}};
	printf("Test Case 168\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xCEEBD74AE975ADA5ULL,
		0x0D1E683072158010ULL,
		0xA3F48C4C635485A8ULL,
		0x4BEA678B67CDA9B3ULL,
		0x54E40C3701CBB4D8ULL,
		0x5F6EE3033D27003AULL,
		0x4F000B7B723A0230ULL,
		0x22E0485B84213E11ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9DD7AE95D2EB5B4AULL,
		0x1A3CD060E42B0021ULL,
		0x47E91898C6A90B50ULL,
		0x97D4CF16CF9B5367ULL,
		0xA9C8186E039769B0ULL,
		0xBEDDC6067A4E0074ULL,
		0x9E0016F6E4740460ULL,
		0x45C090B708427C22ULL
	}};
	printf("Test Case 169\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x86B38F9E390A77A5ULL,
		0xFB884A42ED374BD4ULL,
		0x95C36C5E24AA5DB2ULL,
		0x2379F4799A432AC5ULL,
		0xEB73DA2D47E63A00ULL,
		0xA2E975FDFDF0542EULL,
		0xCEE6ABA8B9765A6DULL,
		0x2684BCD56AC20B88ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0D671F3C7214EF4AULL,
		0xF7109485DA6E97A9ULL,
		0x2B86D8BC4954BB65ULL,
		0x46F3E8F33486558BULL,
		0xD6E7B45A8FCC7400ULL,
		0x45D2EBFBFBE0A85DULL,
		0x9DCD575172ECB4DBULL,
		0x4D0979AAD5841711ULL
	}};
	printf("Test Case 170\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xA1888D400E947177ULL,
		0xDCF8ACCFD312C53BULL,
		0xA4841B932E09BB4BULL,
		0x6F0006F645B9BDE0ULL,
		0xE950FABD7742F5ADULL,
		0xE45AD47EC76DE0AAULL,
		0x67CDE50371AD8D8BULL,
		0x0BE898716E9E6E3DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x43111A801D28E2EEULL,
		0xB9F1599FA6258A77ULL,
		0x490837265C137697ULL,
		0xDE000DEC8B737BC1ULL,
		0xD2A1F57AEE85EB5AULL,
		0xC8B5A8FD8EDBC155ULL,
		0xCF9BCA06E35B1B17ULL,
		0x17D130E2DD3CDC7AULL
	}};
	printf("Test Case 171\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x9655FE6AC14670BDULL,
		0xE416FD24EF8AFE1AULL,
		0x747AD49CB2879AA0ULL,
		0x45BF49CE07C8D527ULL,
		0x8D92B2FB934C7C05ULL,
		0x6F7EE16873E8DCE5ULL,
		0xE962626A617C39A2ULL,
		0x086290A0791E1EC8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2CABFCD5828CE17AULL,
		0xC82DFA49DF15FC35ULL,
		0xE8F5A939650F3541ULL,
		0x8B7E939C0F91AA4EULL,
		0x1B2565F72698F80AULL,
		0xDEFDC2D0E7D1B9CBULL,
		0xD2C4C4D4C2F87344ULL,
		0x10C52140F23C3D91ULL
	}};
	printf("Test Case 172\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xE055B15614907532ULL,
		0x3E877F2D488675C4ULL,
		0x0A16ECC94ACAB03DULL,
		0xB423C9C6F88FA590ULL,
		0x9292727F4EFE1976ULL,
		0xBFB3E8BAF9C5B6E2ULL,
		0xE8A46A5E823C3DA5ULL,
		0x24671CCCCAA883B9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC0AB62AC2920EA64ULL,
		0x7D0EFE5A910CEB89ULL,
		0x142DD9929595607AULL,
		0x6847938DF11F4B20ULL,
		0x2524E4FE9DFC32EDULL,
		0x7F67D175F38B6DC5ULL,
		0xD148D4BD04787B4BULL,
		0x48CE399995510773ULL
	}};
	printf("Test Case 173\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x726A9AAE21A75EFDULL,
		0x6422563D63DC8784ULL,
		0x25E6380B8AC5634BULL,
		0x3FF5B8C8F3C19F51ULL,
		0x3EC3D5786978C627ULL,
		0x05457B5D1CDEFAF5ULL,
		0x072D4851E9DF0214ULL,
		0x199885EF27DEF157ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE4D5355C434EBDFAULL,
		0xC844AC7AC7B90F08ULL,
		0x4BCC7017158AC696ULL,
		0x7FEB7191E7833EA2ULL,
		0x7D87AAF0D2F18C4EULL,
		0x0A8AF6BA39BDF5EAULL,
		0x0E5A90A3D3BE0428ULL,
		0x33310BDE4FBDE2AEULL
	}};
	printf("Test Case 174\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x1DB8098E4303D746ULL,
		0x97F71FA824605767ULL,
		0x617300F10E1EA2C0ULL,
		0xA15F1C51CC2A3A02ULL,
		0x5E962A77383E6310ULL,
		0x934B0078910A6765ULL,
		0xBC69B7CD78EEA5DFULL,
		0x2A2B1A32C6C821E3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3B70131C8607AE8CULL,
		0x2FEE3F5048C0AECEULL,
		0xC2E601E21C3D4581ULL,
		0x42BE38A398547404ULL,
		0xBD2C54EE707CC621ULL,
		0x269600F12214CECAULL,
		0x78D36F9AF1DD4BBFULL,
		0x545634658D9043C7ULL
	}};
	printf("Test Case 175\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xA931E38FE4AF352CULL,
		0xC9B78A4A3F7A122AULL,
		0x8C1ED40D34B348D6ULL,
		0xEE12F691A405CBC4ULL,
		0x2A81DC20B3AC2C1AULL,
		0x6FB410AF82953D21ULL,
		0x458A11F9027C98D9ULL,
		0x053C442C96E9FFB7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5263C71FC95E6A58ULL,
		0x936F14947EF42455ULL,
		0x183DA81A696691ADULL,
		0xDC25ED23480B9789ULL,
		0x5503B84167585835ULL,
		0xDF68215F052A7A42ULL,
		0x8B1423F204F931B2ULL,
		0x0A7888592DD3FF6EULL
	}};
	printf("Test Case 176\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x5D924827CF6CCAB2ULL,
		0x5FA55AE798F06225ULL,
		0xA68838C9F02D960AULL,
		0xE9D36D851F0D2CF5ULL,
		0x05A7A060856E88A2ULL,
		0xBFF6662AA8275DF5ULL,
		0xFA409832F777E515ULL,
		0x2EE66E3515EEC565ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB24904F9ED99564ULL,
		0xBF4AB5CF31E0C44AULL,
		0x4D107193E05B2C14ULL,
		0xD3A6DB0A3E1A59EBULL,
		0x0B4F40C10ADD1145ULL,
		0x7FECCC55504EBBEAULL,
		0xF4813065EEEFCA2BULL,
		0x5DCCDC6A2BDD8ACBULL
	}};
	printf("Test Case 177\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x9C52158E5F8FC1E6ULL,
		0x5853BDD4788A6CD6ULL,
		0xB873A678BC74C493ULL,
		0xF4C027E54B0B15D2ULL,
		0x07291101993C45AAULL,
		0x3B38B6754235623FULL,
		0xEC2C478FB28A67FEULL,
		0x27D35205C95D62B3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x38A42B1CBF1F83CCULL,
		0xB0A77BA8F114D9ADULL,
		0x70E74CF178E98926ULL,
		0xE9804FCA96162BA5ULL,
		0x0E52220332788B55ULL,
		0x76716CEA846AC47EULL,
		0xD8588F1F6514CFFCULL,
		0x4FA6A40B92BAC567ULL
	}};
	printf("Test Case 178\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x721A4A3E7795825BULL,
		0xEE2687C753E05F32ULL,
		0x427020B42F5F0CE7ULL,
		0xDE2CE3B04D9330A6ULL,
		0x785B873303BC6AFDULL,
		0x49AEA16C490236C8ULL,
		0x23FAFD0D14615981ULL,
		0x2E9F584D8DC7A675ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE434947CEF2B04B6ULL,
		0xDC4D0F8EA7C0BE64ULL,
		0x84E041685EBE19CFULL,
		0xBC59C7609B26614CULL,
		0xF0B70E660778D5FBULL,
		0x935D42D892046D90ULL,
		0x47F5FA1A28C2B302ULL,
		0x5D3EB09B1B8F4CEAULL
	}};
	printf("Test Case 179\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xE9DD7D691C3C4A6EULL,
		0xD1022996A40DA634ULL,
		0xE3BD712D4805541EULL,
		0xE2293FD61AC30A74ULL,
		0xD2520DB23C826107ULL,
		0x9E4CB04E93B6E486ULL,
		0x3270860F92B0A0E7ULL,
		0x184DBF47CAA8C6B5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD3BAFAD2387894DCULL,
		0xA204532D481B4C69ULL,
		0xC77AE25A900AA83DULL,
		0xC4527FAC358614E9ULL,
		0xA4A41B647904C20FULL,
		0x3C99609D276DC90DULL,
		0x64E10C1F256141CFULL,
		0x309B7E8F95518D6AULL
	}};
	printf("Test Case 180\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xCF85D1DA1525AB8DULL,
		0x17A5D6E860405FFCULL,
		0xF79E75D3EE2F6966ULL,
		0x65001C49644FE7AEULL,
		0x1F643FBC882CF607ULL,
		0xA740A28905E385A5ULL,
		0x0E11F1B43A434203ULL,
		0x331B78B820F8CEB4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9F0BA3B42A4B571AULL,
		0x2F4BADD0C080BFF9ULL,
		0xEF3CEBA7DC5ED2CCULL,
		0xCA003892C89FCF5DULL,
		0x3EC87F791059EC0EULL,
		0x4E8145120BC70B4AULL,
		0x1C23E36874868407ULL,
		0x6636F17041F19D68ULL
	}};
	printf("Test Case 181\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x055B2045DF9BA0AAULL,
		0x91EDD2071D69720EULL,
		0xAD852C7CF1B8D596ULL,
		0x8525459FAF32D728ULL,
		0xEE19D7964F7066E6ULL,
		0x21A7FB8A62F21553ULL,
		0x483EB9666982575DULL,
		0x3E36D3B4B64FE2E8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0AB6408BBF374154ULL,
		0x23DBA40E3AD2E41CULL,
		0x5B0A58F9E371AB2DULL,
		0x0A4A8B3F5E65AE51ULL,
		0xDC33AF2C9EE0CDCDULL,
		0x434FF714C5E42AA7ULL,
		0x907D72CCD304AEBAULL,
		0x7C6DA7696C9FC5D0ULL
	}};
	printf("Test Case 182\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xE4300D066EDD9A18ULL,
		0xABC06FCE23E1C863ULL,
		0xCA7BB68565DBC0A9ULL,
		0x1B06B486835EFFDEULL,
		0xDECEA50BC5569825ULL,
		0x5F11178B1FF871A7ULL,
		0xADFBA85AA4600FFAULL,
		0x1C9E7E06C25CDA22ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC8601A0CDDBB3430ULL,
		0x5780DF9C47C390C7ULL,
		0x94F76D0ACBB78153ULL,
		0x360D690D06BDFFBDULL,
		0xBD9D4A178AAD304AULL,
		0xBE222F163FF0E34FULL,
		0x5BF750B548C01FF4ULL,
		0x393CFC0D84B9B445ULL
	}};
	printf("Test Case 183\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x08CB60FFC9CE38CBULL,
		0xF6592BAA72648CC9ULL,
		0xF156F025274E22E0ULL,
		0x12F17A6ABDC43529ULL,
		0x40E57869FECD3302ULL,
		0x14FD241900F64BF0ULL,
		0x5ADE36B39430DDF3ULL,
		0x3AD3E5FCA26DB2A0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1196C1FF939C7196ULL,
		0xECB25754E4C91992ULL,
		0xE2ADE04A4E9C45C1ULL,
		0x25E2F4D57B886A53ULL,
		0x81CAF0D3FD9A6604ULL,
		0x29FA483201EC97E0ULL,
		0xB5BC6D672861BBE6ULL,
		0x75A7CBF944DB6540ULL
	}};
	printf("Test Case 184\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x53B21FB722A5BD35ULL,
		0x9EAF70DA3121699AULL,
		0xEF8F07AAD679A820ULL,
		0xAE53C4DD28735EF3ULL,
		0x444696164F5BFA96ULL,
		0xECD65B5ECFE04C52ULL,
		0x9CCD71C974F6684EULL,
		0x050D0089937DE736ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA7643F6E454B7A6AULL,
		0x3D5EE1B46242D334ULL,
		0xDF1E0F55ACF35041ULL,
		0x5CA789BA50E6BDE7ULL,
		0x888D2C2C9EB7F52DULL,
		0xD9ACB6BD9FC098A4ULL,
		0x399AE392E9ECD09DULL,
		0x0A1A011326FBCE6DULL
	}};
	printf("Test Case 185\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xE0F5C42A949B1D7DULL,
		0x4D0C42A4A8932C25ULL,
		0x58D153AE418C8419ULL,
		0x1218BEE41071E9B1ULL,
		0x7976D71CFB2AD326ULL,
		0x1DBC3B9ABF2AEEA8ULL,
		0x538CEC990C15F1BEULL,
		0x07E5B5059D726A78ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC1EB885529363AFAULL,
		0x9A1885495126584BULL,
		0xB1A2A75C83190832ULL,
		0x24317DC820E3D362ULL,
		0xF2EDAE39F655A64CULL,
		0x3B7877357E55DD50ULL,
		0xA719D932182BE37CULL,
		0x0FCB6A0B3AE4D4F0ULL
	}};
	printf("Test Case 186\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xBAFB563256C318B6ULL,
		0x07844238BB1BF358ULL,
		0x118F7AC00F84B955ULL,
		0xFDB9A487CD65EEB7ULL,
		0x58CFBF07C6F070E1ULL,
		0x21D75C06333AA9D2ULL,
		0x868A05FB1A42BA09ULL,
		0x22CA11A7BE652CD9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x75F6AC64AD86316CULL,
		0x0F0884717637E6B1ULL,
		0x231EF5801F0972AAULL,
		0xFB73490F9ACBDD6EULL,
		0xB19F7E0F8DE0E1C3ULL,
		0x43AEB80C667553A4ULL,
		0x0D140BF634857412ULL,
		0x4594234F7CCA59B3ULL
	}};
	printf("Test Case 187\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x8A0310B61C93FF06ULL,
		0xE511B3A903D47209ULL,
		0x9E9CCE4C8F0B2497ULL,
		0xB4A0B16FDA4A3C4DULL,
		0x3308777DC0D90C8FULL,
		0x9F47943088FEA2B4ULL,
		0xE55C3CEF6151454CULL,
		0x24DDFB8003107595ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1406216C3927FE0CULL,
		0xCA23675207A8E413ULL,
		0x3D399C991E16492FULL,
		0x694162DFB494789BULL,
		0x6610EEFB81B2191FULL,
		0x3E8F286111FD4568ULL,
		0xCAB879DEC2A28A99ULL,
		0x49BBF7000620EB2BULL
	}};
	printf("Test Case 188\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x43E3ED110492F4FAULL,
		0x575929488DFAE135ULL,
		0x8811CCC415D31993ULL,
		0x031D27D4A3826D2DULL,
		0x23BA68A916D41611ULL,
		0x478E196638B253BAULL,
		0x3215D8EC3E296758ULL,
		0x1C614CF55F5701ADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x87C7DA220925E9F4ULL,
		0xAEB252911BF5C26AULL,
		0x102399882BA63326ULL,
		0x063A4FA94704DA5BULL,
		0x4774D1522DA82C22ULL,
		0x8F1C32CC7164A774ULL,
		0x642BB1D87C52CEB0ULL,
		0x38C299EABEAE035AULL
	}};
	printf("Test Case 189\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x60802C258668E284ULL,
		0x26EE920835312603ULL,
		0x15183FC6AA8F29E7ULL,
		0xD80FCA761869D7E4ULL,
		0x03D1F315EAFFCC33ULL,
		0x15E6F776FAEAD5A9ULL,
		0x0EAF9B9C12C8D297ULL,
		0x0DA1C0BE3C59C28EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC100584B0CD1C508ULL,
		0x4DDD24106A624C06ULL,
		0x2A307F8D551E53CEULL,
		0xB01F94EC30D3AFC8ULL,
		0x07A3E62BD5FF9867ULL,
		0x2BCDEEEDF5D5AB52ULL,
		0x1D5F37382591A52EULL,
		0x1B43817C78B3851CULL
	}};
	printf("Test Case 190\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xFE0814CCA6032FC1ULL,
		0xB65BBBDE5FE63C2AULL,
		0x4B0A5F31761E1A6AULL,
		0xDBFB8D7DF12BC556ULL,
		0xB6647DBAF6A154C2ULL,
		0xAB9690A48FDB519FULL,
		0x72602894702B5DBDULL,
		0x24A7C28140198B6EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFC1029994C065F82ULL,
		0x6CB777BCBFCC7855ULL,
		0x9614BE62EC3C34D5ULL,
		0xB7F71AFBE2578AACULL,
		0x6CC8FB75ED42A985ULL,
		0x572D21491FB6A33FULL,
		0xE4C05128E056BB7BULL,
		0x494F8502803316DCULL
	}};
	printf("Test Case 191\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xB4B12B2C485407A0ULL,
		0x92E43C5A33F5F28AULL,
		0x3E35AF1B910F25CCULL,
		0xA3D022B78151FA6CULL,
		0xE0931AF7EF3CADBCULL,
		0x5CAC199BF372D9FEULL,
		0xCAE2157FB556DD5AULL,
		0x05F1DCD206DFC360ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6962565890A80F40ULL,
		0x25C878B467EBE515ULL,
		0x7C6B5E37221E4B99ULL,
		0x47A0456F02A3F4D8ULL,
		0xC12635EFDE795B79ULL,
		0xB9583337E6E5B3FDULL,
		0x95C42AFF6AADBAB4ULL,
		0x0BE3B9A40DBF86C1ULL
	}};
	printf("Test Case 192\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x8A7097BF5A3974C5ULL,
		0x50AFECDFE47B784AULL,
		0x9FEEFEDED3297B19ULL,
		0x854B8A637A692F76ULL,
		0x934F26EAAB297E4EULL,
		0x60EE20757FF9D7C9ULL,
		0x208C1A2F4FBCEDCFULL,
		0x20208C63F28B1BC9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x14E12F7EB472E98AULL,
		0xA15FD9BFC8F6F095ULL,
		0x3FDDFDBDA652F632ULL,
		0x0A9714C6F4D25EEDULL,
		0x269E4DD55652FC9DULL,
		0xC1DC40EAFFF3AF93ULL,
		0x4118345E9F79DB9EULL,
		0x404118C7E5163792ULL
	}};
	printf("Test Case 193\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x9F1E3E31A6149653ULL,
		0x7192FD596E36C247ULL,
		0xFC8D6575F422B0AAULL,
		0x5905D53BB998B0DFULL,
		0x561D07E865DC5EB6ULL,
		0xECBC6A67D84017A0ULL,
		0xF7F37713199B6AD5ULL,
		0x13B9DBF4760145B0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3E3C7C634C292CA6ULL,
		0xE325FAB2DC6D848FULL,
		0xF91ACAEBE8456154ULL,
		0xB20BAA77733161BFULL,
		0xAC3A0FD0CBB8BD6CULL,
		0xD978D4CFB0802F40ULL,
		0xEFE6EE263336D5ABULL,
		0x2773B7E8EC028B61ULL
	}};
	printf("Test Case 194\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x3AFE41DF84B19AA1ULL,
		0x0DB9F19DFECA105FULL,
		0x6DB4D524F9C535F1ULL,
		0xE8FD1DF4A87EFDB4ULL,
		0x40C5BF444F971D77ULL,
		0x3AEF06A66A3F4ACCULL,
		0xC1EA66EB94E4629BULL,
		0x36C0870ABB607144ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x75FC83BF09633542ULL,
		0x1B73E33BFD9420BEULL,
		0xDB69AA49F38A6BE2ULL,
		0xD1FA3BE950FDFB68ULL,
		0x818B7E889F2E3AEFULL,
		0x75DE0D4CD47E9598ULL,
		0x83D4CDD729C8C536ULL,
		0x6D810E1576C0E289ULL
	}};
	printf("Test Case 195\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x6FD0297B7954EDFDULL,
		0x6F46307C5106A6DEULL,
		0x6E725F40B2847F86ULL,
		0xAD09496CA1058053ULL,
		0xA04064EC6D7791C8ULL,
		0xEDB4DCCC21E3CFABULL,
		0xFCB4B33B8CC3C21EULL,
		0x2119B0BE01516104ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDFA052F6F2A9DBFAULL,
		0xDE8C60F8A20D4DBCULL,
		0xDCE4BE816508FF0CULL,
		0x5A1292D9420B00A6ULL,
		0x4080C9D8DAEF2391ULL,
		0xDB69B99843C79F57ULL,
		0xF96966771987843DULL,
		0x4233617C02A2C209ULL
	}};
	printf("Test Case 196\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x85BEDF8B0829689BULL,
		0x6EAC35501058DC66ULL,
		0xB1E45D71495AC532ULL,
		0xCB52D6F861A577D9ULL,
		0x77000B94A3A832CEULL,
		0x27975B7CE4D2E4C5ULL,
		0xFE88201E75184B25ULL,
		0x3F90515ACA74C228ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0B7DBF161052D136ULL,
		0xDD586AA020B1B8CDULL,
		0x63C8BAE292B58A64ULL,
		0x96A5ADF0C34AEFB3ULL,
		0xEE0017294750659DULL,
		0x4F2EB6F9C9A5C98AULL,
		0xFD10403CEA30964AULL,
		0x7F20A2B594E98451ULL
	}};
	printf("Test Case 197\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xC6CB3ABAE4B1F264ULL,
		0xEF73A85BCDEC281AULL,
		0xF58AE87E10D7586AULL,
		0x46394ADEA8D94BBCULL,
		0xC581C54165533D8BULL,
		0xC82CCD5146E6A873ULL,
		0xABD639A002E9E209ULL,
		0x1ABA39AF1FDBBEDBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8D967575C963E4C8ULL,
		0xDEE750B79BD85035ULL,
		0xEB15D0FC21AEB0D5ULL,
		0x8C7295BD51B29779ULL,
		0x8B038A82CAA67B16ULL,
		0x90599AA28DCD50E7ULL,
		0x57AC734005D3C413ULL,
		0x3574735E3FB77DB7ULL
	}};
	printf("Test Case 198\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xE248D0B9EC69B212ULL,
		0xED6683FE8E2E1131ULL,
		0x61DE3D306E64F35BULL,
		0x1267A77DAF72153BULL,
		0x06A8D02D7A3A341DULL,
		0x46683BECC5B3C30CULL,
		0x678C8F2990057F4FULL,
		0x2CF79BF59FCF1603ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC491A173D8D36424ULL,
		0xDACD07FD1C5C2263ULL,
		0xC3BC7A60DCC9E6B7ULL,
		0x24CF4EFB5EE42A76ULL,
		0x0D51A05AF474683AULL,
		0x8CD077D98B678618ULL,
		0xCF191E53200AFE9EULL,
		0x59EF37EB3F9E2C06ULL
	}};
	printf("Test Case 199\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xB2BD31E4FB97390FULL,
		0xBC54B3B84CA9ED7CULL,
		0xE765BD472024062FULL,
		0x6066ADBC0B461AE7ULL,
		0xCF7747D5452FD2EDULL,
		0x4873954872041D97ULL,
		0x52F26AA25968A38FULL,
		0x3AFDB6F42C4F0382ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x657A63C9F72E721EULL,
		0x78A967709953DAF9ULL,
		0xCECB7A8E40480C5FULL,
		0xC0CD5B78168C35CFULL,
		0x9EEE8FAA8A5FA5DAULL,
		0x90E72A90E4083B2FULL,
		0xA5E4D544B2D1471EULL,
		0x75FB6DE8589E0704ULL
	}};
	printf("Test Case 200\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x875107C55C3CD563ULL,
		0x905BEC55B6C20F13ULL,
		0x6FAA63DF7E39751EULL,
		0xB3524CA1793D51ECULL,
		0x7C1717594F364070ULL,
		0xF05B5853DE25F1E3ULL,
		0xC51371077F4BA028ULL,
		0x14D737B72F9F91E9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0EA20F8AB879AAC6ULL,
		0x20B7D8AB6D841E27ULL,
		0xDF54C7BEFC72EA3DULL,
		0x66A49942F27AA3D8ULL,
		0xF82E2EB29E6C80E1ULL,
		0xE0B6B0A7BC4BE3C6ULL,
		0x8A26E20EFE974051ULL,
		0x29AE6F6E5F3F23D3ULL
	}};
	printf("Test Case 201\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x94698F048A1CAF4AULL,
		0x912D1040E06B4D74ULL,
		0x978ECDA0AD18E944ULL,
		0xA9825056EF358984ULL,
		0x7F1BD10E683BE7D6ULL,
		0x3FBD38A39C29D9A0ULL,
		0x4319660041C317EFULL,
		0x2CE52947B5FB3320ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x28D31E0914395E94ULL,
		0x225A2081C0D69AE9ULL,
		0x2F1D9B415A31D289ULL,
		0x5304A0ADDE6B1309ULL,
		0xFE37A21CD077CFADULL,
		0x7F7A71473853B340ULL,
		0x8632CC0083862FDEULL,
		0x59CA528F6BF66640ULL
	}};
	printf("Test Case 202\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xA445603BFC3E803DULL,
		0x265EB1939D8E0494ULL,
		0x4F92ACA64963D9B4ULL,
		0xC88DE367A8AC3124ULL,
		0x9A0108FBF8A8F6E6ULL,
		0x2FEEBDFC94E9D8C5ULL,
		0x15BD2B5011DDDD86ULL,
		0x033F0D0AF7164C7EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x488AC077F87D007AULL,
		0x4CBD63273B1C0929ULL,
		0x9F25594C92C7B368ULL,
		0x911BC6CF51586248ULL,
		0x340211F7F151EDCDULL,
		0x5FDD7BF929D3B18BULL,
		0x2B7A56A023BBBB0CULL,
		0x067E1A15EE2C98FCULL
	}};
	printf("Test Case 203\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x8CFF91F94BE0F825ULL,
		0x671D3FBC1E3B6A31ULL,
		0xE165BC8AB8F87FD7ULL,
		0x2972FE11B84BE222ULL,
		0x1666223FF42F1F02ULL,
		0xA7C09A9B46729825ULL,
		0x0F218F0600C6E2B9ULL,
		0x1486E51D25D23114ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x19FF23F297C1F04AULL,
		0xCE3A7F783C76D463ULL,
		0xC2CB791571F0FFAEULL,
		0x52E5FC237097C445ULL,
		0x2CCC447FE85E3E04ULL,
		0x4F8135368CE5304AULL,
		0x1E431E0C018DC573ULL,
		0x290DCA3A4BA46228ULL
	}};
	printf("Test Case 204\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xF25AF385C8AC195AULL,
		0x2C386FF5E32378B1ULL,
		0x93D9500433C891A3ULL,
		0x96FA59B00EE5DC1CULL,
		0xCC0C4C8AD4E76C79ULL,
		0x28F5F91B370F9437ULL,
		0xC072D63562C4EAFCULL,
		0x28CA5DB8D2F2C269ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE4B5E70B915832B4ULL,
		0x5870DFEBC646F163ULL,
		0x27B2A00867912346ULL,
		0x2DF4B3601DCBB839ULL,
		0x98189915A9CED8F3ULL,
		0x51EBF2366E1F286FULL,
		0x80E5AC6AC589D5F8ULL,
		0x5194BB71A5E584D3ULL
	}};
	printf("Test Case 205\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xCCBCD206E3DD1D43ULL,
		0x9F5BD45E998BE2E7ULL,
		0xFBE878DA18179E5AULL,
		0x0CD72FF413ED276FULL,
		0xBC4668009EC947C4ULL,
		0x68EB40F7D0BEC5C3ULL,
		0x54878E5F3E9D4356ULL,
		0x0D5F60129F560638ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9979A40DC7BA3A86ULL,
		0x3EB7A8BD3317C5CFULL,
		0xF7D0F1B4302F3CB5ULL,
		0x19AE5FE827DA4EDFULL,
		0x788CD0013D928F88ULL,
		0xD1D681EFA17D8B87ULL,
		0xA90F1CBE7D3A86ACULL,
		0x1ABEC0253EAC0C70ULL
	}};
	printf("Test Case 206\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x87507A05B5819BB2ULL,
		0x82321A7DED38C003ULL,
		0xD24E22667B1E5D87ULL,
		0x884045E24D7327A8ULL,
		0x330387F5F8347F17ULL,
		0x0BD8CCBA92D7ED60ULL,
		0x78E7FDEEC3CA6846ULL,
		0x34469F66D73602B8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0EA0F40B6B033764ULL,
		0x046434FBDA718007ULL,
		0xA49C44CCF63CBB0FULL,
		0x10808BC49AE64F51ULL,
		0x66070FEBF068FE2FULL,
		0x17B1997525AFDAC0ULL,
		0xF1CFFBDD8794D08CULL,
		0x688D3ECDAE6C0570ULL
	}};
	printf("Test Case 207\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xA119116ED57DE92BULL,
		0xD61E6CE6B0C275E5ULL,
		0x726FD8387D7F8DF8ULL,
		0xBF1750B2F0EB9BFFULL,
		0x8FD5463525BC1E3EULL,
		0x4C3E7611E43EB419ULL,
		0x7A46D4ED596CD1E0ULL,
		0x271CBEF5D81DA748ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x423222DDAAFBD256ULL,
		0xAC3CD9CD6184EBCBULL,
		0xE4DFB070FAFF1BF1ULL,
		0x7E2EA165E1D737FEULL,
		0x1FAA8C6A4B783C7DULL,
		0x987CEC23C87D6833ULL,
		0xF48DA9DAB2D9A3C0ULL,
		0x4E397DEBB03B4E90ULL
	}};
	printf("Test Case 208\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x8826C63583DB64C9ULL,
		0x6FDF7B7F839C9B94ULL,
		0x12E34D7616CCA7C4ULL,
		0xBF986DDAC75634B5ULL,
		0xB1D09AF6B60EDABBULL,
		0xE227D54AAE5D0676ULL,
		0x9245E507CD9F2113ULL,
		0x3A176945DB3A00FAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x104D8C6B07B6C992ULL,
		0xDFBEF6FF07393729ULL,
		0x25C69AEC2D994F88ULL,
		0x7F30DBB58EAC696AULL,
		0x63A135ED6C1DB577ULL,
		0xC44FAA955CBA0CEDULL,
		0x248BCA0F9B3E4227ULL,
		0x742ED28BB67401F5ULL
	}};
	printf("Test Case 209\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x353477EE394E42D3ULL,
		0xBB501558D8780D4CULL,
		0x2D894E3AD871E403ULL,
		0xF715F2D5451EACB8ULL,
		0x6B9F260DFF55D674ULL,
		0xD426DA25FF96737FULL,
		0x46DF5D60393F5582ULL,
		0x2CB0753A20A6F35FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6A68EFDC729C85A6ULL,
		0x76A02AB1B0F01A98ULL,
		0x5B129C75B0E3C807ULL,
		0xEE2BE5AA8A3D5970ULL,
		0xD73E4C1BFEABACE9ULL,
		0xA84DB44BFF2CE6FEULL,
		0x8DBEBAC0727EAB05ULL,
		0x5960EA74414DE6BEULL
	}};
	printf("Test Case 210\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 210 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -210;
	} else {
		printf("Test Case 210 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x638FB20688C91E1BULL,
		0x24454D891B527A2CULL,
		0x33367EDEF6DE125BULL,
		0xE40C22C5705E43B5ULL,
		0x59343C32C2E04CBFULL,
		0xCBACB03860328CBBULL,
		0x8ABCFED9C06F06D6ULL,
		0x29C3508AFAF07155ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC71F640D11923C36ULL,
		0x488A9B1236A4F458ULL,
		0x666CFDBDEDBC24B6ULL,
		0xC818458AE0BC876AULL,
		0xB268786585C0997FULL,
		0x97596070C0651976ULL,
		0x1579FDB380DE0DADULL,
		0x5386A115F5E0E2ABULL
	}};
	printf("Test Case 211\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 211 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -211;
	} else {
		printf("Test Case 211 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4D8689660C4F7D87ULL,
		0xF48A73A4953C13BBULL,
		0xBFF260CD6CECA35CULL,
		0x3C0A4679CA3CB7A6ULL,
		0x967D849C713FF6FEULL,
		0xB99099E7671DF4BCULL,
		0x33515C1ED4090191ULL,
		0x0A402CFC41386436ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9B0D12CC189EFB0EULL,
		0xE914E7492A782776ULL,
		0x7FE4C19AD9D946B9ULL,
		0x78148CF394796F4DULL,
		0x2CFB0938E27FEDFCULL,
		0x732133CECE3BE979ULL,
		0x66A2B83DA8120323ULL,
		0x148059F88270C86CULL
	}};
	printf("Test Case 212\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 212 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -212;
	} else {
		printf("Test Case 212 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA8DC752A3AD186B2ULL,
		0x5167412CE9768C83ULL,
		0xA75157B7B9E05723ULL,
		0x2C6164EF0DA10D15ULL,
		0x2F40EE1F9AAA0BC0ULL,
		0x6698428D9FD63817ULL,
		0x36417EE9E45828DCULL,
		0x1BF485EC66923D41ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x51B8EA5475A30D64ULL,
		0xA2CE8259D2ED1907ULL,
		0x4EA2AF6F73C0AE46ULL,
		0x58C2C9DE1B421A2BULL,
		0x5E81DC3F35541780ULL,
		0xCD30851B3FAC702EULL,
		0x6C82FDD3C8B051B8ULL,
		0x37E90BD8CD247A82ULL
	}};
	printf("Test Case 213\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 213 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -213;
	} else {
		printf("Test Case 213 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7D2FE90DB06A85A0ULL,
		0xA1F6DBBD962D1B8BULL,
		0x36A96231C6A7A9F4ULL,
		0xC1FC6D168FADF18CULL,
		0x8995A7497CD8F1C1ULL,
		0xA55C1B4AE033377CULL,
		0x8B741FA35A04BB22ULL,
		0x2A7B0E1B151DBB23ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFA5FD21B60D50B40ULL,
		0x43EDB77B2C5A3716ULL,
		0x6D52C4638D4F53E9ULL,
		0x83F8DA2D1F5BE318ULL,
		0x132B4E92F9B1E383ULL,
		0x4AB83695C0666EF9ULL,
		0x16E83F46B4097645ULL,
		0x54F61C362A3B7647ULL
	}};
	printf("Test Case 214\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 214 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -214;
	} else {
		printf("Test Case 214 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA0D28616D5A72A1FULL,
		0x911EED1FC3D62409ULL,
		0x21D1CAF5BDAE327FULL,
		0xBCC3599890FDEFB6ULL,
		0x8E4C83F2C67D57A3ULL,
		0x52631A869655C588ULL,
		0x6BE5C59C8B3E2E1EULL,
		0x00501B859912A9C7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x41A50C2DAB4E543EULL,
		0x223DDA3F87AC4813ULL,
		0x43A395EB7B5C64FFULL,
		0x7986B33121FBDF6CULL,
		0x1C9907E58CFAAF47ULL,
		0xA4C6350D2CAB8B11ULL,
		0xD7CB8B39167C5C3CULL,
		0x00A0370B3225538EULL
	}};
	printf("Test Case 215\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 215 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -215;
	} else {
		printf("Test Case 215 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE0E3A47AD4102A26ULL,
		0xB8305681334AF494ULL,
		0x3B3D76F396EA2A98ULL,
		0x4821D8B621EF1E81ULL,
		0xA31C8939C372BD12ULL,
		0xF695C9504886193CULL,
		0x6CB455414C63A601ULL,
		0x314E8A76DCDA326BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC1C748F5A820544CULL,
		0x7060AD026695E929ULL,
		0x767AEDE72DD45531ULL,
		0x9043B16C43DE3D02ULL,
		0x4639127386E57A24ULL,
		0xED2B92A0910C3279ULL,
		0xD968AA8298C74C03ULL,
		0x629D14EDB9B464D6ULL
	}};
	printf("Test Case 216\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 216 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -216;
	} else {
		printf("Test Case 216 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3384C38C84CC6A38ULL,
		0xE5D8474AC0B0C97FULL,
		0x588FF25CA3D7BCEDULL,
		0xA4CC8A6D9111846AULL,
		0xB84D758C956602BEULL,
		0xE3E555D2B3C07860ULL,
		0x6F667754A43C1836ULL,
		0x2652177FD63B65AAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x670987190998D470ULL,
		0xCBB08E95816192FEULL,
		0xB11FE4B947AF79DBULL,
		0x499914DB222308D4ULL,
		0x709AEB192ACC057DULL,
		0xC7CAABA56780F0C1ULL,
		0xDECCEEA94878306DULL,
		0x4CA42EFFAC76CB54ULL
	}};
	printf("Test Case 217\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 217 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -217;
	} else {
		printf("Test Case 217 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9813D7935783E9CAULL,
		0x1154F459C29B9D5FULL,
		0x369D5430CE58440DULL,
		0x9BE793D0A6F09C53ULL,
		0x3FED24C65064E051ULL,
		0x2A21828DDACB2FF5ULL,
		0x4BAFCD9909D8D6A0ULL,
		0x3DB4A0738F8C7F9DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3027AF26AF07D394ULL,
		0x22A9E8B385373ABFULL,
		0x6D3AA8619CB0881AULL,
		0x37CF27A14DE138A6ULL,
		0x7FDA498CA0C9C0A3ULL,
		0x5443051BB5965FEAULL,
		0x975F9B3213B1AD40ULL,
		0x7B6940E71F18FF3AULL
	}};
	printf("Test Case 218\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 218 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -218;
	} else {
		printf("Test Case 218 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x15AB9751A10597C9ULL,
		0x447469EAC36DCB42ULL,
		0x1966240B69E6010BULL,
		0xB64AAE10B0219E5DULL,
		0xA7497BCB473B302FULL,
		0x6A58E47A8D4E94BAULL,
		0x33A91F9816723B9CULL,
		0x0E13468FD5151543ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2B572EA3420B2F92ULL,
		0x88E8D3D586DB9684ULL,
		0x32CC4816D3CC0216ULL,
		0x6C955C2160433CBAULL,
		0x4E92F7968E76605FULL,
		0xD4B1C8F51A9D2975ULL,
		0x67523F302CE47738ULL,
		0x1C268D1FAA2A2A86ULL
	}};
	printf("Test Case 219\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 219 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -219;
	} else {
		printf("Test Case 219 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDDF39B5FC54BDFEFULL,
		0x5A7B831CA1442AF1ULL,
		0x76332B17DB7B2BA4ULL,
		0x4838E157F6547990ULL,
		0x240E28F01ED6B1AEULL,
		0x1416C7FA5FDEDF93ULL,
		0x578AA7CB6572AB55ULL,
		0x1E3C721A881619BCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBBE736BF8A97BFDEULL,
		0xB4F70639428855E3ULL,
		0xEC66562FB6F65748ULL,
		0x9071C2AFECA8F320ULL,
		0x481C51E03DAD635CULL,
		0x282D8FF4BFBDBF26ULL,
		0xAF154F96CAE556AAULL,
		0x3C78E435102C3378ULL
	}};
	printf("Test Case 220\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 220 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -220;
	} else {
		printf("Test Case 220 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4D680854AAFE4588ULL,
		0xEF5B85F8C7218FAAULL,
		0xBB2292F709186A10ULL,
		0x8965C24D3D5A6705ULL,
		0x52E97F7906E3300CULL,
		0x7C7A15DA7D4BD991ULL,
		0x9881A1C1F6AE9B6AULL,
		0x1B9C87DD615C57E8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9AD010A955FC8B10ULL,
		0xDEB70BF18E431F54ULL,
		0x764525EE1230D421ULL,
		0x12CB849A7AB4CE0BULL,
		0xA5D2FEF20DC66019ULL,
		0xF8F42BB4FA97B322ULL,
		0x31034383ED5D36D4ULL,
		0x37390FBAC2B8AFD1ULL
	}};
	printf("Test Case 221\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 221 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -221;
	} else {
		printf("Test Case 221 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAF0D2D72C5BFC83DULL,
		0xD94F53089B30D546ULL,
		0xAA50A9CC51D8CB93ULL,
		0xEF72A1C3A6F3CD77ULL,
		0xB81386AD199CA798ULL,
		0xF5FC01DF2351130DULL,
		0xDF07C2CD131E3CDCULL,
		0x012A8EA1EB038C9CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5E1A5AE58B7F907AULL,
		0xB29EA6113661AA8DULL,
		0x54A15398A3B19727ULL,
		0xDEE543874DE79AEFULL,
		0x70270D5A33394F31ULL,
		0xEBF803BE46A2261BULL,
		0xBE0F859A263C79B9ULL,
		0x02551D43D6071939ULL
	}};
	printf("Test Case 222\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 222 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -222;
	} else {
		printf("Test Case 222 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x869C3989D30D8BD0ULL,
		0x543DFD208CCCACADULL,
		0xC4789341FC3BA10AULL,
		0x2B84228E095F3D7DULL,
		0xBE9E5E617487F4C7ULL,
		0xC4DE72F9F23072EAULL,
		0x90823D55F9A14CA1ULL,
		0x3691D39891A5A233ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0D387313A61B17A0ULL,
		0xA87BFA411999595BULL,
		0x88F12683F8774214ULL,
		0x5708451C12BE7AFBULL,
		0x7D3CBCC2E90FE98EULL,
		0x89BCE5F3E460E5D5ULL,
		0x21047AABF3429943ULL,
		0x6D23A731234B4467ULL
	}};
	printf("Test Case 223\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 223 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -223;
	} else {
		printf("Test Case 223 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9B5903C2954295ABULL,
		0x0CBA39B8E419A4B5ULL,
		0xEB2F67678761F51FULL,
		0x986E50A4F64C54B2ULL,
		0xE01307E7FE5B588DULL,
		0xE6EA966203BEC70AULL,
		0xB0A70C4EF99D9570ULL,
		0x2C6B37D27C74BB24ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x36B207852A852B56ULL,
		0x19747371C833496BULL,
		0xD65ECECF0EC3EA3EULL,
		0x30DCA149EC98A965ULL,
		0xC0260FCFFCB6B11BULL,
		0xCDD52CC4077D8E15ULL,
		0x614E189DF33B2AE1ULL,
		0x58D66FA4F8E97649ULL
	}};
	printf("Test Case 224\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 224 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -224;
	} else {
		printf("Test Case 224 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCEE0BEC7805D6242ULL,
		0x2063628C3B3687A6ULL,
		0x2979C930FC835388ULL,
		0xABC80AE850BCC04FULL,
		0x5733725F59B8A5D4ULL,
		0x8AB6AB374462DCADULL,
		0x8D10D8611F13984FULL,
		0x36B371DF113C46ACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9DC17D8F00BAC484ULL,
		0x40C6C518766D0F4DULL,
		0x52F39261F906A710ULL,
		0x579015D0A179809EULL,
		0xAE66E4BEB3714BA9ULL,
		0x156D566E88C5B95AULL,
		0x1A21B0C23E27309FULL,
		0x6D66E3BE22788D59ULL
	}};
	printf("Test Case 225\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 225 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -225;
	} else {
		printf("Test Case 225 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x81B2E4CAF5F5A904ULL,
		0x119A0AA84AF30CF8ULL,
		0x305A78DCB124D496ULL,
		0x6491F4AD4AC31CCBULL,
		0xBA0CBC24E932ECE7ULL,
		0xB4909D992325D74BULL,
		0x7BB0F77EAE3B79A8ULL,
		0x2F494E806C598B3EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0365C995EBEB5208ULL,
		0x2334155095E619F1ULL,
		0x60B4F1B96249A92CULL,
		0xC923E95A95863996ULL,
		0x74197849D265D9CEULL,
		0x69213B32464BAE97ULL,
		0xF761EEFD5C76F351ULL,
		0x5E929D00D8B3167CULL
	}};
	printf("Test Case 226\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 226 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -226;
	} else {
		printf("Test Case 226 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x16FF75B9FC95FB74ULL,
		0xEF5E90727B1CAE08ULL,
		0x08BCA45EF8579874ULL,
		0x55A2FE2F40443A87ULL,
		0x318197D16835C138ULL,
		0x0E1CC461BCD5143BULL,
		0x54CD9170BBDAA5E5ULL,
		0x2E52F96F0E3B5D82ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2DFEEB73F92BF6E8ULL,
		0xDEBD20E4F6395C10ULL,
		0x117948BDF0AF30E9ULL,
		0xAB45FC5E8088750EULL,
		0x63032FA2D06B8270ULL,
		0x1C3988C379AA2876ULL,
		0xA99B22E177B54BCAULL,
		0x5CA5F2DE1C76BB04ULL
	}};
	printf("Test Case 227\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 227 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -227;
	} else {
		printf("Test Case 227 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAF875EE1E722EC05ULL,
		0x336832D3749E7FE5ULL,
		0xEA557733BC251E2FULL,
		0xACF4D3B233BBDD2EULL,
		0x761B84AA4F22A8F9ULL,
		0xE2A256B68A07AFA3ULL,
		0xAB8367E572289E9BULL,
		0x20B69F141F263A07ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5F0EBDC3CE45D80AULL,
		0x66D065A6E93CFFCBULL,
		0xD4AAEE67784A3C5EULL,
		0x59E9A7646777BA5DULL,
		0xEC3709549E4551F3ULL,
		0xC544AD6D140F5F46ULL,
		0x5706CFCAE4513D37ULL,
		0x416D3E283E4C740FULL
	}};
	printf("Test Case 228\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 228 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -228;
	} else {
		printf("Test Case 228 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xABD670F60FBAD09BULL,
		0x2F69C40E9E5D3498ULL,
		0x32A78D2AF76CAEB9ULL,
		0xD450F24669B6104FULL,
		0x3AF101356AB6ACD5ULL,
		0x49383620F8D1105BULL,
		0xC6E8862249E453C3ULL,
		0x3A8C141DE2F6C5CEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x57ACE1EC1F75A136ULL,
		0x5ED3881D3CBA6931ULL,
		0x654F1A55EED95D72ULL,
		0xA8A1E48CD36C209EULL,
		0x75E2026AD56D59ABULL,
		0x92706C41F1A220B6ULL,
		0x8DD10C4493C8A786ULL,
		0x7518283BC5ED8B9DULL
	}};
	printf("Test Case 229\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 229 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -229;
	} else {
		printf("Test Case 229 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD40FFBA98C356D06ULL,
		0xD7B6707979527E7EULL,
		0x8BFFB67ED00F0731ULL,
		0xE17F0E01BC07CA8DULL,
		0x218A9FECA14750BCULL,
		0x999A46B31B58A108ULL,
		0xBC3764EDBFB2405DULL,
		0x2D7CC2AD232043ECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA81FF753186ADA0CULL,
		0xAF6CE0F2F2A4FCFDULL,
		0x17FF6CFDA01E0E63ULL,
		0xC2FE1C03780F951BULL,
		0x43153FD9428EA179ULL,
		0x33348D6636B14210ULL,
		0x786EC9DB7F6480BBULL,
		0x5AF9855A464087D9ULL
	}};
	printf("Test Case 230\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 230 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -230;
	} else {
		printf("Test Case 230 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB9D03C9BF6ECF0D7ULL,
		0xBEAAA5A644221D2DULL,
		0x862E39C4CD5CDCB8ULL,
		0x27AA3F4297FDBB6BULL,
		0xFCCF7045FE225E5EULL,
		0xC12C4E6B5CAC9F2DULL,
		0x97ED50894342DC25ULL,
		0x293FD32AC82D3D75ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x73A07937EDD9E1AEULL,
		0x7D554B4C88443A5BULL,
		0x0C5C73899AB9B971ULL,
		0x4F547E852FFB76D7ULL,
		0xF99EE08BFC44BCBCULL,
		0x82589CD6B9593E5BULL,
		0x2FDAA1128685B84BULL,
		0x527FA655905A7AEBULL
	}};
	printf("Test Case 231\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 231 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -231;
	} else {
		printf("Test Case 231 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x360C7D44522E4A57ULL,
		0xADFEF135F19886B2ULL,
		0x98966A2ACFD012F8ULL,
		0xA17201CC16D09929ULL,
		0x60FCB1426DA6EFA2ULL,
		0x971773D4FE53871AULL,
		0xF8C1194BAFAA08D1ULL,
		0x3AA37107E50E0558ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6C18FA88A45C94AEULL,
		0x5BFDE26BE3310D64ULL,
		0x312CD4559FA025F1ULL,
		0x42E403982DA13253ULL,
		0xC1F96284DB4DDF45ULL,
		0x2E2EE7A9FCA70E34ULL,
		0xF18232975F5411A3ULL,
		0x7546E20FCA1C0AB1ULL
	}};
	printf("Test Case 232\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 232 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -232;
	} else {
		printf("Test Case 232 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x975D65CCBCDF813EULL,
		0xE8CEABEA4D2167A7ULL,
		0xB13841820F2DFC12ULL,
		0x5AA7AB325482D0EAULL,
		0xF03DF28286A66645ULL,
		0xBA9F6096F804C527ULL,
		0x9BC7E449064BEF3CULL,
		0x042D9CF8CCF96B67ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2EBACB9979BF027CULL,
		0xD19D57D49A42CF4FULL,
		0x627083041E5BF825ULL,
		0xB54F5664A905A1D5ULL,
		0xE07BE5050D4CCC8AULL,
		0x753EC12DF0098A4FULL,
		0x378FC8920C97DE79ULL,
		0x085B39F199F2D6CFULL
	}};
	printf("Test Case 233\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 233 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -233;
	} else {
		printf("Test Case 233 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCEDB5D0682444C53ULL,
		0x2304D6F57EC5EE27ULL,
		0x7934EAB1720BE7C5ULL,
		0x6A4EA42032FA8F50ULL,
		0x201401A8D8F17F14ULL,
		0xE7CCC4B97E4798CFULL,
		0x0CDE54D4E8D8E184ULL,
		0x19742EAA2F6DE4D1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9DB6BA0D048898A6ULL,
		0x4609ADEAFD8BDC4FULL,
		0xF269D562E417CF8AULL,
		0xD49D484065F51EA0ULL,
		0x40280351B1E2FE28ULL,
		0xCF998972FC8F319EULL,
		0x19BCA9A9D1B1C309ULL,
		0x32E85D545EDBC9A2ULL
	}};
	printf("Test Case 234\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 234 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -234;
	} else {
		printf("Test Case 234 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFC50582291945B82ULL,
		0x7C62E535E0F9B2FFULL,
		0x6752A27625FC051FULL,
		0x3D24A71564861F98ULL,
		0xA9E820490DBA7166ULL,
		0xD5E4689314AFDEAFULL,
		0xE168CF789043D911ULL,
		0x0046F0B1334EFAEEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF8A0B0452328B704ULL,
		0xF8C5CA6BC1F365FFULL,
		0xCEA544EC4BF80A3EULL,
		0x7A494E2AC90C3F30ULL,
		0x53D040921B74E2CCULL,
		0xABC8D126295FBD5FULL,
		0xC2D19EF12087B223ULL,
		0x008DE162669DF5DDULL
	}};
	printf("Test Case 235\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 235 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -235;
	} else {
		printf("Test Case 235 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x204E379418DDC7A4ULL,
		0xF53C23E6B4D5F72BULL,
		0x43C438A36370B3A0ULL,
		0xB99820D849C0D974ULL,
		0xEF04EDB21DDD9A05ULL,
		0x43C777B6BC0D1810ULL,
		0xA3E993703768C7ADULL,
		0x39F8D84318AA9B37ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x409C6F2831BB8F48ULL,
		0xEA7847CD69ABEE56ULL,
		0x87887146C6E16741ULL,
		0x733041B09381B2E8ULL,
		0xDE09DB643BBB340BULL,
		0x878EEF6D781A3021ULL,
		0x47D326E06ED18F5AULL,
		0x73F1B0863155366FULL
	}};
	printf("Test Case 236\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 236 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -236;
	} else {
		printf("Test Case 236 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x097814BBCAE80232ULL,
		0xE83ECBBA6B4D7C37ULL,
		0xE3C867294BE42559ULL,
		0xF3E8F01872A0D866ULL,
		0xB761EBDEC00F9545ULL,
		0x5538D4780673D797ULL,
		0xB9F9008716E80896ULL,
		0x3E6FF2087C9923EAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x12F0297795D00464ULL,
		0xD07D9774D69AF86EULL,
		0xC790CE5297C84AB3ULL,
		0xE7D1E030E541B0CDULL,
		0x6EC3D7BD801F2A8BULL,
		0xAA71A8F00CE7AF2FULL,
		0x73F2010E2DD0112CULL,
		0x7CDFE410F93247D5ULL
	}};
	printf("Test Case 237\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 237 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -237;
	} else {
		printf("Test Case 237 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x34D96BF8D753A53DULL,
		0xCCAD1278A437046DULL,
		0xB64BB6921C67416EULL,
		0x5D050746A618BBE2ULL,
		0x402D981ACC2247A7ULL,
		0xF39D7292E81D4403ULL,
		0x69E5396435129C0BULL,
		0x300E6D49DAC5D038ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x69B2D7F1AEA74A7AULL,
		0x995A24F1486E08DAULL,
		0x6C976D2438CE82DDULL,
		0xBA0A0E8D4C3177C5ULL,
		0x805B303598448F4EULL,
		0xE73AE525D03A8806ULL,
		0xD3CA72C86A253817ULL,
		0x601CDA93B58BA070ULL
	}};
	printf("Test Case 238\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 238 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -238;
	} else {
		printf("Test Case 238 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF3C0A72B84A3FF2AULL,
		0x689B83A9EE8D8F95ULL,
		0xAC5AA3E63F076571ULL,
		0x414A21E00746AD9EULL,
		0x4EF382D77EC5B392ULL,
		0xA996433CCFCB500BULL,
		0xD6EB7807729D41BBULL,
		0x2B4F333C11A494A4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE7814E570947FE54ULL,
		0xD1370753DD1B1F2BULL,
		0x58B547CC7E0ECAE2ULL,
		0x829443C00E8D5B3DULL,
		0x9DE705AEFD8B6724ULL,
		0x532C86799F96A016ULL,
		0xADD6F00EE53A8377ULL,
		0x569E667823492949ULL
	}};
	printf("Test Case 239\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 239 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -239;
	} else {
		printf("Test Case 239 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFE2AB1B1D4A47944ULL,
		0x47CF14C2A795D983ULL,
		0x2C882F3E2FE0DE04ULL,
		0x300A9043C8B63199ULL,
		0x7BA1EB26BF491F7FULL,
		0xCCDE93A8DA3D5864ULL,
		0x0F96C5A9BED2F8BBULL,
		0x3BA86AD85A04C338ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFC556363A948F288ULL,
		0x8F9E29854F2BB307ULL,
		0x59105E7C5FC1BC08ULL,
		0x60152087916C6332ULL,
		0xF743D64D7E923EFEULL,
		0x99BD2751B47AB0C8ULL,
		0x1F2D8B537DA5F177ULL,
		0x7750D5B0B4098670ULL
	}};
	printf("Test Case 240\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 240 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -240;
	} else {
		printf("Test Case 240 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4522B71EA9EB1367ULL,
		0xB8698BCA87745B1AULL,
		0x342181EA4FD22713ULL,
		0xEACC163E1EDF49C0ULL,
		0x8412DC47FDB34E79ULL,
		0x51AEDC18EE7D1A7EULL,
		0x7CEFBE9A6AFBDEA5ULL,
		0x14ED166BAA80D53BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8A456E3D53D626CEULL,
		0x70D317950EE8B634ULL,
		0x684303D49FA44E27ULL,
		0xD5982C7C3DBE9380ULL,
		0x0825B88FFB669CF3ULL,
		0xA35DB831DCFA34FDULL,
		0xF9DF7D34D5F7BD4AULL,
		0x29DA2CD75501AA76ULL
	}};
	printf("Test Case 241\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 241 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -241;
	} else {
		printf("Test Case 241 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x33191EF165B5713BULL,
		0x478F8D9176C78B5FULL,
		0x819B2EE395338A24ULL,
		0x4E7A77DEAE1FAC2CULL,
		0x0D90719BA703CF9BULL,
		0x3BDA057FE6F2BBF0ULL,
		0x9B78DFE1339A2F15ULL,
		0x1073FC939B8936B7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x66323DE2CB6AE276ULL,
		0x8F1F1B22ED8F16BEULL,
		0x03365DC72A671448ULL,
		0x9CF4EFBD5C3F5859ULL,
		0x1B20E3374E079F36ULL,
		0x77B40AFFCDE577E0ULL,
		0x36F1BFC267345E2AULL,
		0x20E7F92737126D6FULL
	}};
	printf("Test Case 242\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 242 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -242;
	} else {
		printf("Test Case 242 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC053238CAC258EEFULL,
		0x92615210499F3436ULL,
		0x85CED864EEB7624EULL,
		0xBD7CD830F879BAACULL,
		0x2E09093C1265FF49ULL,
		0xB655CAA932C8EA95ULL,
		0x3BBA24B1E13AC020ULL,
		0x12EB0EAAC0763DC3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x80A64719584B1DDEULL,
		0x24C2A420933E686DULL,
		0x0B9DB0C9DD6EC49DULL,
		0x7AF9B061F0F37559ULL,
		0x5C12127824CBFE93ULL,
		0x6CAB95526591D52AULL,
		0x77744963C2758041ULL,
		0x25D61D5580EC7B86ULL
	}};
	printf("Test Case 243\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 243 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -243;
	} else {
		printf("Test Case 243 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x347CB959A4BC48B7ULL,
		0x5478B4B47B505A91ULL,
		0xCA33F434C98F7A30ULL,
		0x50EEDBA994105F17ULL,
		0x5B1742B3BE5C11DBULL,
		0xD604050AE2E36BBCULL,
		0x98233AB50A13CE5EULL,
		0x1858620CDE0CD002ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x68F972B34978916EULL,
		0xA8F16968F6A0B522ULL,
		0x9467E869931EF460ULL,
		0xA1DDB7532820BE2FULL,
		0xB62E85677CB823B6ULL,
		0xAC080A15C5C6D778ULL,
		0x3046756A14279CBDULL,
		0x30B0C419BC19A005ULL
	}};
	printf("Test Case 244\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 244 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -244;
	} else {
		printf("Test Case 244 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAD74837B5CDE914AULL,
		0xF310084783D69EFBULL,
		0x60E1E0D73EA3E31EULL,
		0x7EFA88A3F86B3236ULL,
		0x27BC43C4FB896165ULL,
		0x55C51BD60F648957ULL,
		0x0B39163703F40AFDULL,
		0x0CD07EA1513A1CEDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5AE906F6B9BD2294ULL,
		0xE620108F07AD3DF7ULL,
		0xC1C3C1AE7D47C63DULL,
		0xFDF51147F0D6646CULL,
		0x4F788789F712C2CAULL,
		0xAB8A37AC1EC912AEULL,
		0x16722C6E07E815FAULL,
		0x19A0FD42A27439DAULL
	}};
	printf("Test Case 245\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 245 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -245;
	} else {
		printf("Test Case 245 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0A92013C297B0684ULL,
		0x14312A7048D7A3D1ULL,
		0x119C19C9A81199B0ULL,
		0xC59674641DB2925FULL,
		0xA124057E24A0EDFDULL,
		0x637B38062AA5551FULL,
		0x08CA090FD1C5EC6EULL,
		0x3248F892D3353332ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1524027852F60D08ULL,
		0x286254E091AF47A2ULL,
		0x2338339350233360ULL,
		0x8B2CE8C83B6524BEULL,
		0x42480AFC4941DBFBULL,
		0xC6F6700C554AAA3FULL,
		0x1194121FA38BD8DCULL,
		0x6491F125A66A6664ULL
	}};
	printf("Test Case 246\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 246 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -246;
	} else {
		printf("Test Case 246 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x84D864877CD83990ULL,
		0x3F3EB41CBB08848FULL,
		0x6D423854C1254F8AULL,
		0x48704764C58262C2ULL,
		0x78ED0DB3C3F29FD0ULL,
		0xE2D3850C806DEA8FULL,
		0x82ECB7B344A1A79BULL,
		0x111ADC1AEA3C0A9AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x09B0C90EF9B07320ULL,
		0x7E7D68397611091FULL,
		0xDA8470A9824A9F14ULL,
		0x90E08EC98B04C584ULL,
		0xF1DA1B6787E53FA0ULL,
		0xC5A70A1900DBD51EULL,
		0x05D96F6689434F37ULL,
		0x2235B835D4781535ULL
	}};
	printf("Test Case 247\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 247 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -247;
	} else {
		printf("Test Case 247 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x294973724369AD7CULL,
		0xDA5736AC3DF1E8F7ULL,
		0x5C796971C5D65FEBULL,
		0xD1B8F8B56FD5E9DFULL,
		0x05F64C23AB84A5DCULL,
		0xF7B3E0FE4118DD9DULL,
		0x1F5796915E7B9B78ULL,
		0x171087EA63806AABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5292E6E486D35AF8ULL,
		0xB4AE6D587BE3D1EEULL,
		0xB8F2D2E38BACBFD7ULL,
		0xA371F16ADFABD3BEULL,
		0x0BEC984757094BB9ULL,
		0xEF67C1FC8231BB3AULL,
		0x3EAF2D22BCF736F1ULL,
		0x2E210FD4C700D556ULL
	}};
	printf("Test Case 248\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 248 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -248;
	} else {
		printf("Test Case 248 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x301FAA24E4A98E11ULL,
		0x7CC9AC1AACD42167ULL,
		0x8D267FFE1380957AULL,
		0xE04488E18F41AF3CULL,
		0x98AB225EC5672C0EULL,
		0x82097B6512134707ULL,
		0x8C940DD392709D04ULL,
		0x2D2AACCD48B2A7EAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x603F5449C9531C22ULL,
		0xF993583559A842CEULL,
		0x1A4CFFFC27012AF4ULL,
		0xC08911C31E835E79ULL,
		0x315644BD8ACE581DULL,
		0x0412F6CA24268E0FULL,
		0x19281BA724E13A09ULL,
		0x5A55599A91654FD5ULL
	}};
	printf("Test Case 249\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 249 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -249;
	} else {
		printf("Test Case 249 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x12D625BDFEBBD1F7ULL,
		0xBC965509C5157589ULL,
		0x00874827DA86C1A6ULL,
		0x73D47D037B417C1AULL,
		0xAB14A65AEE093B2FULL,
		0x43D4D2E801025B57ULL,
		0xBF476776CCB243ADULL,
		0x055DE00AB56B87E9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x25AC4B7BFD77A3EEULL,
		0x792CAA138A2AEB12ULL,
		0x010E904FB50D834DULL,
		0xE7A8FA06F682F834ULL,
		0x56294CB5DC12765EULL,
		0x87A9A5D00204B6AFULL,
		0x7E8ECEED9964875AULL,
		0x0ABBC0156AD70FD3ULL
	}};
	printf("Test Case 250\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 250 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -250;
	} else {
		printf("Test Case 250 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF99E504987D9F6BFULL,
		0x907AA42C5E4549A4ULL,
		0x90FCBD4609988A12ULL,
		0x077A1A2F08FDABF7ULL,
		0x36404323138EEB79ULL,
		0x746F26D45160C3BBULL,
		0xB7FBDDC975A94389ULL,
		0x07BAF3C53EA6FE47ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF33CA0930FB3ED7EULL,
		0x20F54858BC8A9349ULL,
		0x21F97A8C13311425ULL,
		0x0EF4345E11FB57EFULL,
		0x6C808646271DD6F2ULL,
		0xE8DE4DA8A2C18776ULL,
		0x6FF7BB92EB528712ULL,
		0x0F75E78A7D4DFC8FULL
	}};
	printf("Test Case 251\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 251 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -251;
	} else {
		printf("Test Case 251 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x88FF701C740FAC7DULL,
		0x157A08937A813F17ULL,
		0xEEF0ACA29CAC135DULL,
		0x0F67DED2ABEAE192ULL,
		0xFB960EB9EE2556E7ULL,
		0x977E2915DC036252ULL,
		0xCDFD4649F80973EFULL,
		0x0E599C80D9FF6F28ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x11FEE038E81F58FAULL,
		0x2AF41126F5027E2FULL,
		0xDDE15945395826BAULL,
		0x1ECFBDA557D5C325ULL,
		0xF72C1D73DC4AADCEULL,
		0x2EFC522BB806C4A5ULL,
		0x9BFA8C93F012E7DFULL,
		0x1CB33901B3FEDE51ULL
	}};
	printf("Test Case 252\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 252 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -252;
	} else {
		printf("Test Case 252 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x274EA5138283E91EULL,
		0x6E473CFD2742851BULL,
		0x4CA5A2A57E7DA200ULL,
		0x163405865DF80D4CULL,
		0xA44E8BADCEB130CAULL,
		0x931A43BDC9F93F82ULL,
		0x39F17EFEF80EEC57ULL,
		0x1207921AD0B284B7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4E9D4A270507D23CULL,
		0xDC8E79FA4E850A36ULL,
		0x994B454AFCFB4400ULL,
		0x2C680B0CBBF01A98ULL,
		0x489D175B9D626194ULL,
		0x2634877B93F27F05ULL,
		0x73E2FDFDF01DD8AFULL,
		0x240F2435A165096EULL
	}};
	printf("Test Case 253\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 253 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -253;
	} else {
		printf("Test Case 253 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7AF2B90FDD602574ULL,
		0xD26BE634E69A3BFEULL,
		0x9CF972DC444DAB61ULL,
		0x3C54B1BE400E8666ULL,
		0xC9B1E496BA9E62CBULL,
		0xD8EFC1F70FF41D33ULL,
		0x19E1BADB18EFB04EULL,
		0x22C1D9E537AA7EDFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF5E5721FBAC04AE8ULL,
		0xA4D7CC69CD3477FCULL,
		0x39F2E5B8889B56C3ULL,
		0x78A9637C801D0CCDULL,
		0x9363C92D753CC596ULL,
		0xB1DF83EE1FE83A67ULL,
		0x33C375B631DF609DULL,
		0x4583B3CA6F54FDBEULL
	}};
	printf("Test Case 254\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 254 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -254;
	} else {
		printf("Test Case 254 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x825A988C600D00EEULL,
		0x135472D9C21D4801ULL,
		0x9F7FEAE5BB34ECCCULL,
		0xFC27E9C05C367A02ULL,
		0x590B38FBE96D4E8FULL,
		0xE636F654569BDE11ULL,
		0x7D8D496C53CC02CFULL,
		0x2D521E51248CE81AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x04B53118C01A01DCULL,
		0x26A8E5B3843A9003ULL,
		0x3EFFD5CB7669D998ULL,
		0xF84FD380B86CF405ULL,
		0xB21671F7D2DA9D1FULL,
		0xCC6DECA8AD37BC22ULL,
		0xFB1A92D8A798059FULL,
		0x5AA43CA24919D034ULL
	}};
	printf("Test Case 255\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 255 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -255;
	} else {
		printf("Test Case 255 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFBB6C91FDE0688D6ULL,
		0x5A6D6588294F750EULL,
		0xF52E7232332C044AULL,
		0x86FE11AD1F1B4AD2ULL,
		0xA7DBA0152AC2EC3AULL,
		0x27964E2BEA5D55CBULL,
		0x5F76348363985D1FULL,
		0x0F8F83E877829777ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF76D923FBC0D11ACULL,
		0xB4DACB10529EEA1DULL,
		0xEA5CE46466580894ULL,
		0x0DFC235A3E3695A5ULL,
		0x4FB7402A5585D875ULL,
		0x4F2C9C57D4BAAB97ULL,
		0xBEEC6906C730BA3EULL,
		0x1F1F07D0EF052EEEULL
	}};
	printf("Test Case 256\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 256 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -256;
	} else {
		printf("Test Case 256 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB6D56215BBA46ADDULL,
		0x4EE21C1A79C35000ULL,
		0x0139F06147FD3E25ULL,
		0xBA2AC804632ADC96ULL,
		0xD258980E1BB0D26CULL,
		0x0CCCA708E95F287AULL,
		0x52C6146009BF66A1ULL,
		0x02A891405F9AB2E6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6DAAC42B7748D5BAULL,
		0x9DC43834F386A001ULL,
		0x0273E0C28FFA7C4AULL,
		0x74559008C655B92CULL,
		0xA4B1301C3761A4D9ULL,
		0x19994E11D2BE50F5ULL,
		0xA58C28C0137ECD42ULL,
		0x05512280BF3565CCULL
	}};
	printf("Test Case 257\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 257 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -257;
	} else {
		printf("Test Case 257 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1ADEB2E50A0C1848ULL,
		0x6E892B03FBE13701ULL,
		0x19E27B1E159461C3ULL,
		0xDEBAB74D69859A8AULL,
		0x4AA8BE445E9B5C52ULL,
		0x2EEF2AF70D5E5FFAULL,
		0x4528D3CDAA8FABECULL,
		0x3D8A42D39C73B440ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x35BD65CA14183090ULL,
		0xDD125607F7C26E02ULL,
		0x33C4F63C2B28C386ULL,
		0xBD756E9AD30B3514ULL,
		0x95517C88BD36B8A5ULL,
		0x5DDE55EE1ABCBFF4ULL,
		0x8A51A79B551F57D8ULL,
		0x7B1485A738E76880ULL
	}};
	printf("Test Case 258\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 258 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -258;
	} else {
		printf("Test Case 258 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCD96FDB417B732C8ULL,
		0x8DA57729E884000BULL,
		0x7DF5A2314B892549ULL,
		0xED3CA8341EBFEB89ULL,
		0x1B3777D3C1028496ULL,
		0x128822613824E5ABULL,
		0x0A560CCEBD56C163ULL,
		0x20B6E96961D8C83AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9B2DFB682F6E6590ULL,
		0x1B4AEE53D1080017ULL,
		0xFBEB446297124A93ULL,
		0xDA7950683D7FD712ULL,
		0x366EEFA78205092DULL,
		0x251044C27049CB56ULL,
		0x14AC199D7AAD82C6ULL,
		0x416DD2D2C3B19074ULL
	}};
	printf("Test Case 259\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 259 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -259;
	} else {
		printf("Test Case 259 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8D5F390C99C67E8FULL,
		0x423FE8B75A073643ULL,
		0x29236E0C19FC7638ULL,
		0x41D5561B25290675ULL,
		0x8750920F8F9ADB69ULL,
		0xCC7F94EA0A87A68BULL,
		0x6D7C2EF61364B25EULL,
		0x2EDEE2E89BB23CC1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1ABE7219338CFD1EULL,
		0x847FD16EB40E6C87ULL,
		0x5246DC1833F8EC70ULL,
		0x83AAAC364A520CEAULL,
		0x0EA1241F1F35B6D2ULL,
		0x98FF29D4150F4D17ULL,
		0xDAF85DEC26C964BDULL,
		0x5DBDC5D137647982ULL
	}};
	printf("Test Case 260\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 260 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -260;
	} else {
		printf("Test Case 260 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8F7AE82D4868963FULL,
		0x6F2F0BDFC140263CULL,
		0x8336BD6C904BA146ULL,
		0x3FAE7D1726E70FECULL,
		0x7C0C950D555E3F0EULL,
		0xC1A3A789462BA7EBULL,
		0xB04928A829DFA279ULL,
		0x10D4474BDA75FF72ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1EF5D05A90D12C7EULL,
		0xDE5E17BF82804C79ULL,
		0x066D7AD92097428CULL,
		0x7F5CFA2E4DCE1FD9ULL,
		0xF8192A1AAABC7E1CULL,
		0x83474F128C574FD6ULL,
		0x6092515053BF44F3ULL,
		0x21A88E97B4EBFEE5ULL
	}};
	printf("Test Case 261\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 261 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -261;
	} else {
		printf("Test Case 261 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3792CAF7787659CBULL,
		0x4648B77FF7168163ULL,
		0x029C3039DA082B4DULL,
		0x9D56C4B8C8CE1FFDULL,
		0x770904125C48F557ULL,
		0xD46C13028D3EBFF3ULL,
		0xC7A62B9F2628352EULL,
		0x1B60419C88665FB2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6F2595EEF0ECB396ULL,
		0x8C916EFFEE2D02C6ULL,
		0x05386073B410569AULL,
		0x3AAD8971919C3FFAULL,
		0xEE120824B891EAAFULL,
		0xA8D826051A7D7FE6ULL,
		0x8F4C573E4C506A5DULL,
		0x36C0833910CCBF65ULL
	}};
	printf("Test Case 262\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 262 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -262;
	} else {
		printf("Test Case 262 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5A5D338C5069879DULL,
		0x87D7B82445E8210AULL,
		0x856FA2906623787DULL,
		0xC561778F569C4559ULL,
		0xA30F9E9D3652435BULL,
		0x51D6B96989306419ULL,
		0xB01511DA7DBE67A1ULL,
		0x07D4CA89A1EF420CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB4BA6718A0D30F3AULL,
		0x0FAF70488BD04214ULL,
		0x0ADF4520CC46F0FBULL,
		0x8AC2EF1EAD388AB3ULL,
		0x461F3D3A6CA486B7ULL,
		0xA3AD72D31260C833ULL,
		0x602A23B4FB7CCF42ULL,
		0x0FA9951343DE8419ULL
	}};
	printf("Test Case 263\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 263 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -263;
	} else {
		printf("Test Case 263 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7ADB9705E904FA81ULL,
		0x8A58529B01A3DB77ULL,
		0x727B2A6251845817ULL,
		0x35911A77CEA98842ULL,
		0xECE77269C1E28F77ULL,
		0xEDD56194455950EDULL,
		0x04EC639D10B79C60ULL,
		0x1A1F27381AF34DC6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF5B72E0BD209F502ULL,
		0x14B0A5360347B6EEULL,
		0xE4F654C4A308B02FULL,
		0x6B2234EF9D531084ULL,
		0xD9CEE4D383C51EEEULL,
		0xDBAAC3288AB2A1DBULL,
		0x09D8C73A216F38C1ULL,
		0x343E4E7035E69B8CULL
	}};
	printf("Test Case 264\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 264 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -264;
	} else {
		printf("Test Case 264 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCB91067583C0F6CDULL,
		0xE48B528D87499241ULL,
		0x196536D8B05B48DDULL,
		0x7CD9F4D7F4BFDED0ULL,
		0x3B2D28429EB3FE46ULL,
		0xD64A7A9BC6377F62ULL,
		0x8EFBE100E0D666CFULL,
		0x0A9615D53E3A1B6DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x97220CEB0781ED9AULL,
		0xC916A51B0E932483ULL,
		0x32CA6DB160B691BBULL,
		0xF9B3E9AFE97FBDA0ULL,
		0x765A50853D67FC8CULL,
		0xAC94F5378C6EFEC4ULL,
		0x1DF7C201C1ACCD9FULL,
		0x152C2BAA7C7436DBULL
	}};
	printf("Test Case 265\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 265 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -265;
	} else {
		printf("Test Case 265 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5769AD938FC2BF0DULL,
		0x5B944CEB81C7F44CULL,
		0x6A43DEA5F102D452ULL,
		0x5A99A20A0E400A3EULL,
		0x0AC315DF3FA1CC27ULL,
		0x3CA996445BBF04DEULL,
		0x311222590E88C11FULL,
		0x3802539209CF4706ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAED35B271F857E1AULL,
		0xB72899D7038FE898ULL,
		0xD487BD4BE205A8A4ULL,
		0xB53344141C80147CULL,
		0x15862BBE7F43984EULL,
		0x79532C88B77E09BCULL,
		0x622444B21D11823EULL,
		0x7004A724139E8E0CULL
	}};
	printf("Test Case 266\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 266 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -266;
	} else {
		printf("Test Case 266 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9ECFAA4C21A687DFULL,
		0x75D005D9C65FA7C1ULL,
		0xE888FB405A90A07EULL,
		0x725A90D1A76E7330ULL,
		0x008E41492F9CEAB4ULL,
		0x8D0E90248725C604ULL,
		0xB5914FFF800C457FULL,
		0x3E7A4B67CDC46338ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3D9F5498434D0FBEULL,
		0xEBA00BB38CBF4F83ULL,
		0xD111F680B52140FCULL,
		0xE4B521A34EDCE661ULL,
		0x011C82925F39D568ULL,
		0x1A1D20490E4B8C08ULL,
		0x6B229FFF00188AFFULL,
		0x7CF496CF9B88C671ULL
	}};
	printf("Test Case 267\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 267 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -267;
	} else {
		printf("Test Case 267 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAFCD732FD04F9C19ULL,
		0xA329FE9E583A0BC3ULL,
		0xAE1CF10756693228ULL,
		0xF7BAC0A0E8A80AE4ULL,
		0xD4AAD8F1E1A3AA0EULL,
		0xAE002BB11D81B27CULL,
		0x66F6D04385D1C842ULL,
		0x32EFC0D769D9E4C6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5F9AE65FA09F3832ULL,
		0x4653FD3CB0741787ULL,
		0x5C39E20EACD26451ULL,
		0xEF758141D15015C9ULL,
		0xA955B1E3C347541DULL,
		0x5C0057623B0364F9ULL,
		0xCDEDA0870BA39085ULL,
		0x65DF81AED3B3C98CULL
	}};
	printf("Test Case 268\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 268 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -268;
	} else {
		printf("Test Case 268 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7A4C807A322C7FFDULL,
		0xA5C6E4857DEEC8AFULL,
		0xCA000C89B8B2897FULL,
		0xFA2459BE0FB12E06ULL,
		0xF4CF765384F41309ULL,
		0xA59DF362B45FDEF4ULL,
		0x8A8750CDA9B2D925ULL,
		0x2060427ADD371BF1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF49900F46458FFFAULL,
		0x4B8DC90AFBDD915EULL,
		0x94001913716512FFULL,
		0xF448B37C1F625C0DULL,
		0xE99EECA709E82613ULL,
		0x4B3BE6C568BFBDE9ULL,
		0x150EA19B5365B24BULL,
		0x40C084F5BA6E37E3ULL
	}};
	printf("Test Case 269\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 269 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -269;
	} else {
		printf("Test Case 269 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x810EEE2812939755ULL,
		0xCDF3A21CD629F0D2ULL,
		0x5E3157D2757AD74BULL,
		0x10479CB268978F2BULL,
		0x0DB9DEB0659EAC25ULL,
		0x56F4880D86E5F3F2ULL,
		0x1B9366CE77E6A76AULL,
		0x114813B732C369BDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x021DDC5025272EAAULL,
		0x9BE74439AC53E1A5ULL,
		0xBC62AFA4EAF5AE97ULL,
		0x208F3964D12F1E56ULL,
		0x1B73BD60CB3D584AULL,
		0xADE9101B0DCBE7E4ULL,
		0x3726CD9CEFCD4ED4ULL,
		0x2290276E6586D37AULL
	}};
	printf("Test Case 270\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 270 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -270;
	} else {
		printf("Test Case 270 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9859C4EB05090BBFULL,
		0x5FDAD70DA13355C6ULL,
		0xB2AC29D56B5D52B0ULL,
		0x37FE48804B72B8FFULL,
		0x2C47E7C37CE713A1ULL,
		0x99265ADD9ABA9A21ULL,
		0x90060CE11F6C443EULL,
		0x2CBF5A9F4E0A90EEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x30B389D60A12177EULL,
		0xBFB5AE1B4266AB8DULL,
		0x655853AAD6BAA560ULL,
		0x6FFC910096E571FFULL,
		0x588FCF86F9CE2742ULL,
		0x324CB5BB35753442ULL,
		0x200C19C23ED8887DULL,
		0x597EB53E9C1521DDULL
	}};
	printf("Test Case 271\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 271 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -271;
	} else {
		printf("Test Case 271 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7C7319AB9D24A355ULL,
		0x941B41282EDE85F8ULL,
		0x46F7DF686069EBAEULL,
		0xC6F1DAA5008B7FC7ULL,
		0x136365699C786937ULL,
		0xFFE27F92517B1FE5ULL,
		0xDBBB276617C76443ULL,
		0x015414EC80456B7AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF8E633573A4946AAULL,
		0x283682505DBD0BF0ULL,
		0x8DEFBED0C0D3D75DULL,
		0x8DE3B54A0116FF8EULL,
		0x26C6CAD338F0D26FULL,
		0xFFC4FF24A2F63FCAULL,
		0xB7764ECC2F8EC887ULL,
		0x02A829D9008AD6F5ULL
	}};
	printf("Test Case 272\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 272 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -272;
	} else {
		printf("Test Case 272 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDA5C388007748D4BULL,
		0x9B519D928B03A357ULL,
		0x5820145509965E83ULL,
		0x01E3DB4770441BC8ULL,
		0xE1E6973920432D83ULL,
		0x3EBF6F69FFA082B6ULL,
		0x40E04C9FDC3FE069ULL,
		0x0ADE15E43DFAF85AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB4B871000EE91A96ULL,
		0x36A33B25160746AFULL,
		0xB04028AA132CBD07ULL,
		0x03C7B68EE0883790ULL,
		0xC3CD2E7240865B06ULL,
		0x7D7EDED3FF41056DULL,
		0x81C0993FB87FC0D2ULL,
		0x15BC2BC87BF5F0B4ULL
	}};
	printf("Test Case 273\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 273 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -273;
	} else {
		printf("Test Case 273 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5AA613C5E2BC9DA6ULL,
		0x573A53000ED607B8ULL,
		0x38E821E42DBBF12DULL,
		0x82B169EF2115641AULL,
		0x0BF581009416BDD1ULL,
		0x168EB6A528D2CF66ULL,
		0x5B85E495A70B7C41ULL,
		0x253078BDF0E58FC5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB54C278BC5793B4CULL,
		0xAE74A6001DAC0F70ULL,
		0x71D043C85B77E25AULL,
		0x0562D3DE422AC834ULL,
		0x17EB0201282D7BA3ULL,
		0x2D1D6D4A51A59ECCULL,
		0xB70BC92B4E16F882ULL,
		0x4A60F17BE1CB1F8AULL
	}};
	printf("Test Case 274\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 274 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -274;
	} else {
		printf("Test Case 274 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x04A7F38B95B04EC6ULL,
		0x0DFF8FE4EC584C34ULL,
		0x049333CA7CD6D46FULL,
		0x62C30FDD219C32ACULL,
		0x6D2A371F514F0B42ULL,
		0xFF1A982D3F84BF7EULL,
		0xE8C9A79D3F3DEDCDULL,
		0x3164E84BD72AE699ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x094FE7172B609D8CULL,
		0x1BFF1FC9D8B09868ULL,
		0x09266794F9ADA8DEULL,
		0xC5861FBA43386558ULL,
		0xDA546E3EA29E1684ULL,
		0xFE35305A7F097EFCULL,
		0xD1934F3A7E7BDB9BULL,
		0x62C9D097AE55CD33ULL
	}};
	printf("Test Case 275\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 275 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -275;
	} else {
		printf("Test Case 275 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7EF25C210443C2D1ULL,
		0x34B4392B5EDB2FD6ULL,
		0xF990046C3808B23CULL,
		0x19E69895D8611B4DULL,
		0x4817F40E23C20FA4ULL,
		0xE737941E45B7DF9BULL,
		0xE3490B08E9D3A898ULL,
		0x2FA5859FC68D0895ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFDE4B842088785A2ULL,
		0x69687256BDB65FACULL,
		0xF32008D870116478ULL,
		0x33CD312BB0C2369BULL,
		0x902FE81C47841F48ULL,
		0xCE6F283C8B6FBF36ULL,
		0xC6921611D3A75131ULL,
		0x5F4B0B3F8D1A112BULL
	}};
	printf("Test Case 276\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 276 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -276;
	} else {
		printf("Test Case 276 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x426076CA8AABBA3BULL,
		0x939F299B90140837ULL,
		0x5CCD777130DAA4ADULL,
		0x8DCB7110D493D07FULL,
		0x80161BB0A54F4AD0ULL,
		0xB9BD8C8E26A0D505ULL,
		0x06D561AD29E848EAULL,
		0x34A29DA92E25D989ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x84C0ED9515577476ULL,
		0x273E53372028106EULL,
		0xB99AEEE261B5495BULL,
		0x1B96E221A927A0FEULL,
		0x002C37614A9E95A1ULL,
		0x737B191C4D41AA0BULL,
		0x0DAAC35A53D091D5ULL,
		0x69453B525C4BB312ULL
	}};
	printf("Test Case 277\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 277 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -277;
	} else {
		printf("Test Case 277 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1BC4BB1D25BB2D9CULL,
		0xFE216610E54A4CEEULL,
		0xE96453E81DF723FFULL,
		0xCA03556E420914D6ULL,
		0x646F9A066CFA9DB7ULL,
		0xB124AD81D2D4634AULL,
		0xD78A2D7FB1258E87ULL,
		0x0979A390D556512AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3789763A4B765B38ULL,
		0xFC42CC21CA9499DCULL,
		0xD2C8A7D03BEE47FFULL,
		0x9406AADC841229ADULL,
		0xC8DF340CD9F53B6FULL,
		0x62495B03A5A8C694ULL,
		0xAF145AFF624B1D0FULL,
		0x12F34721AAACA255ULL
	}};
	printf("Test Case 278\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 278 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -278;
	} else {
		printf("Test Case 278 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1848ACDBB907273AULL,
		0x6F3DDA0CB8074624ULL,
		0x2C38010ED0D017ABULL,
		0x5A493606F1342982ULL,
		0x224C91903D6361F7ULL,
		0xE633EA21ECEC501CULL,
		0xCD215B3B24575DBAULL,
		0x1D08DBDD3A1A99ABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x309159B7720E4E74ULL,
		0xDE7BB419700E8C48ULL,
		0x5870021DA1A02F56ULL,
		0xB4926C0DE2685304ULL,
		0x449923207AC6C3EEULL,
		0xCC67D443D9D8A038ULL,
		0x9A42B67648AEBB75ULL,
		0x3A11B7BA74353357ULL
	}};
	printf("Test Case 279\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 279 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -279;
	} else {
		printf("Test Case 279 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2FFB33BE6A8F9EB6ULL,
		0x565D5F90D670CEB6ULL,
		0x7AF08533D22B7232ULL,
		0x4DC9F3E3E5D9747EULL,
		0x22C11CE71FA8CDBEULL,
		0xCB3837CCECA8D77FULL,
		0x9836DA7827AB535CULL,
		0x1426A89E2939C541ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5FF6677CD51F3D6CULL,
		0xACBABF21ACE19D6CULL,
		0xF5E10A67A456E464ULL,
		0x9B93E7C7CBB2E8FCULL,
		0x458239CE3F519B7CULL,
		0x96706F99D951AEFEULL,
		0x306DB4F04F56A6B9ULL,
		0x284D513C52738A83ULL
	}};
	printf("Test Case 280\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 280 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -280;
	} else {
		printf("Test Case 280 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7E7DA81DD6546A1AULL,
		0xF302E98BF5B74CD6ULL,
		0x25901427F73EE37BULL,
		0x246AAD642AEAE57EULL,
		0xB729F24E293DEF92ULL,
		0x40BDBC45491DDB84ULL,
		0x7A6B91749FCAA28EULL,
		0x17F4032CE70C567BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFCFB503BACA8D434ULL,
		0xE605D317EB6E99ACULL,
		0x4B20284FEE7DC6F7ULL,
		0x48D55AC855D5CAFCULL,
		0x6E53E49C527BDF24ULL,
		0x817B788A923BB709ULL,
		0xF4D722E93F95451CULL,
		0x2FE80659CE18ACF6ULL
	}};
	printf("Test Case 281\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 281 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -281;
	} else {
		printf("Test Case 281 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x560037E830048356ULL,
		0x3571842EAFF9A35DULL,
		0xA252DB803D5A9B88ULL,
		0x51C26F639BFEF2DCULL,
		0x39AD647614F2A62AULL,
		0x39522CCCFE3AA917ULL,
		0x6CD2080E49A8DF5EULL,
		0x004D1A3FB70BFC1BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAC006FD0600906ACULL,
		0x6AE3085D5FF346BAULL,
		0x44A5B7007AB53710ULL,
		0xA384DEC737FDE5B9ULL,
		0x735AC8EC29E54C54ULL,
		0x72A45999FC75522EULL,
		0xD9A4101C9351BEBCULL,
		0x009A347F6E17F836ULL
	}};
	printf("Test Case 282\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 282 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -282;
	} else {
		printf("Test Case 282 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9878CBCCD33663D9ULL,
		0xCE2DD014CCDB3AD3ULL,
		0x6EA8D5B764469DEDULL,
		0x329FA5D243E00B0CULL,
		0x26CE1992FC56B6A7ULL,
		0x0F33E3150B4E7D61ULL,
		0xB041EC73D0EE290CULL,
		0x0758229BC85D18E7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x30F19799A66CC7B2ULL,
		0x9C5BA02999B675A7ULL,
		0xDD51AB6EC88D3BDBULL,
		0x653F4BA487C01618ULL,
		0x4D9C3325F8AD6D4EULL,
		0x1E67C62A169CFAC2ULL,
		0x6083D8E7A1DC5218ULL,
		0x0EB0453790BA31CFULL
	}};
	printf("Test Case 283\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 283 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -283;
	} else {
		printf("Test Case 283 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x873753F642563F6AULL,
		0x4405592BE6690A91ULL,
		0x3E9F45E9212D2397ULL,
		0x175AF489C5338EE2ULL,
		0x94E901BA9CA56AA2ULL,
		0xF4668D5B38CE1803ULL,
		0xC50D3AD055015EA2ULL,
		0x344CBA5E8F797004ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0E6EA7EC84AC7ED4ULL,
		0x880AB257CCD21523ULL,
		0x7D3E8BD2425A472EULL,
		0x2EB5E9138A671DC4ULL,
		0x29D20375394AD544ULL,
		0xE8CD1AB6719C3007ULL,
		0x8A1A75A0AA02BD45ULL,
		0x689974BD1EF2E009ULL
	}};
	printf("Test Case 284\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 284 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -284;
	} else {
		printf("Test Case 284 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7739D93197F1F553ULL,
		0x55837E0E95A06508ULL,
		0x77899378A7E4AC53ULL,
		0x3B102189B60E7AF1ULL,
		0xF8475669CE614DBDULL,
		0x2FFD1BE107FFE0ECULL,
		0x0F456161E42A684FULL,
		0x0B5E5C9AD58854FFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEE73B2632FE3EAA6ULL,
		0xAB06FC1D2B40CA10ULL,
		0xEF1326F14FC958A6ULL,
		0x762043136C1CF5E2ULL,
		0xF08EACD39CC29B7AULL,
		0x5FFA37C20FFFC1D9ULL,
		0x1E8AC2C3C854D09EULL,
		0x16BCB935AB10A9FEULL
	}};
	printf("Test Case 285\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 285 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -285;
	} else {
		printf("Test Case 285 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x15BDE265DEC1A481ULL,
		0xE5538720653383EFULL,
		0x56680FCD8CCCA04FULL,
		0x7B33F3EEE1A0FFB3ULL,
		0x2E2D616D5EB930BFULL,
		0x246C90ABE399B46AULL,
		0x91EFC7C3DCA28854ULL,
		0x08EDC2D13B5B8244ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2B7BC4CBBD834902ULL,
		0xCAA70E40CA6707DEULL,
		0xACD01F9B1999409FULL,
		0xF667E7DDC341FF66ULL,
		0x5C5AC2DABD72617EULL,
		0x48D92157C73368D4ULL,
		0x23DF8F87B94510A8ULL,
		0x11DB85A276B70489ULL
	}};
	printf("Test Case 286\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 286 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -286;
	} else {
		printf("Test Case 286 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9D7A0A79E40DDC1BULL,
		0x00E74B293CEFF180ULL,
		0xCE0696CA0CBC5E86ULL,
		0xB963586081443CF3ULL,
		0x4609F13FF5044C33ULL,
		0xB83221257153B82BULL,
		0xA3BF491DAF73C877ULL,
		0x2F60268490704C47ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3AF414F3C81BB836ULL,
		0x01CE965279DFE301ULL,
		0x9C0D2D941978BD0CULL,
		0x72C6B0C1028879E7ULL,
		0x8C13E27FEA089867ULL,
		0x7064424AE2A77056ULL,
		0x477E923B5EE790EFULL,
		0x5EC04D0920E0988FULL
	}};
	printf("Test Case 287\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 287 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -287;
	} else {
		printf("Test Case 287 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x75DEFBFAAB8058DFULL,
		0xA0B7742094A33CB9ULL,
		0x39F2204E605DEBA9ULL,
		0x4948C633640C3BB5ULL,
		0x4CE49E67BE309F68ULL,
		0xCFAF46BA56597DAFULL,
		0x04CD3A4B59C0BF76ULL,
		0x123E213470EB307BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEBBDF7F55700B1BEULL,
		0x416EE84129467972ULL,
		0x73E4409CC0BBD753ULL,
		0x92918C66C818776AULL,
		0x99C93CCF7C613ED0ULL,
		0x9F5E8D74ACB2FB5EULL,
		0x099A7496B3817EEDULL,
		0x247C4268E1D660F6ULL
	}};
	printf("Test Case 288\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 288 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -288;
	} else {
		printf("Test Case 288 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x20D1FDE790F95387ULL,
		0x7D8DBBC369863CF9ULL,
		0x4090E6E3AEA8A9C2ULL,
		0x1AFB44F24570D0BCULL,
		0x54D267B43CC9AB1AULL,
		0xB9A6097845044262ULL,
		0xAAFF43B9A072A9DAULL,
		0x157C5B26B29BC1BEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x41A3FBCF21F2A70EULL,
		0xFB1B7786D30C79F2ULL,
		0x8121CDC75D515384ULL,
		0x35F689E48AE1A178ULL,
		0xA9A4CF6879935634ULL,
		0x734C12F08A0884C4ULL,
		0x55FE877340E553B5ULL,
		0x2AF8B64D6537837DULL
	}};
	printf("Test Case 289\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 289 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -289;
	} else {
		printf("Test Case 289 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8098A466B3425AA1ULL,
		0x713F53FDE1D531EFULL,
		0x87286807B1258A61ULL,
		0xD80199735AAF7315ULL,
		0xF61EF6AAB7C63C60ULL,
		0x2CFB6E92423A4245ULL,
		0x44B20BE4DF070411ULL,
		0x3DCE4A8738994E62ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x013148CD6684B542ULL,
		0xE27EA7FBC3AA63DFULL,
		0x0E50D00F624B14C2ULL,
		0xB00332E6B55EE62BULL,
		0xEC3DED556F8C78C1ULL,
		0x59F6DD248474848BULL,
		0x896417C9BE0E0822ULL,
		0x7B9C950E71329CC4ULL
	}};
	printf("Test Case 290\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 290 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -290;
	} else {
		printf("Test Case 290 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x87A0C5C564FEAB34ULL,
		0xC5B8AE441A8068DFULL,
		0xED5B2AD03EE2B2ACULL,
		0x4E0481648D517524ULL,
		0x864E3AE1A583440CULL,
		0x4BEF5B87B3119D0AULL,
		0x9A07F60E712A05ADULL,
		0x331BBE351E5F7AD2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F418B8AC9FD5668ULL,
		0x8B715C883500D1BFULL,
		0xDAB655A07DC56559ULL,
		0x9C0902C91AA2EA49ULL,
		0x0C9C75C34B068818ULL,
		0x97DEB70F66233A15ULL,
		0x340FEC1CE2540B5AULL,
		0x66377C6A3CBEF5A5ULL
	}};
	printf("Test Case 291\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 291 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -291;
	} else {
		printf("Test Case 291 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB546A9F4697FC96EULL,
		0xF1CA838F6DB74694ULL,
		0xDEF043993918DF25ULL,
		0x54EEE98A8BFC8EEBULL,
		0xF6551776F59E2809ULL,
		0x4B48E8718AD5DF6FULL,
		0x634113A222FF1363ULL,
		0x2C02D6E470677C2FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6A8D53E8D2FF92DCULL,
		0xE395071EDB6E8D29ULL,
		0xBDE087327231BE4BULL,
		0xA9DDD31517F91DD7ULL,
		0xECAA2EEDEB3C5012ULL,
		0x9691D0E315ABBEDFULL,
		0xC682274445FE26C6ULL,
		0x5805ADC8E0CEF85EULL
	}};
	printf("Test Case 292\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 292 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -292;
	} else {
		printf("Test Case 292 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEB974BB6B8A8FCE7ULL,
		0x8B47EA139B126128ULL,
		0xED2EF455E85442ADULL,
		0x6E9BD246BC5DB941ULL,
		0x8722DFA97D3B17FAULL,
		0xA0A1A0FDC6B79BDFULL,
		0xB523C7FCE3F6776FULL,
		0x1C7B422A62EAC935ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD72E976D7151F9CEULL,
		0x168FD4273624C251ULL,
		0xDA5DE8ABD0A8855BULL,
		0xDD37A48D78BB7283ULL,
		0x0E45BF52FA762FF4ULL,
		0x414341FB8D6F37BFULL,
		0x6A478FF9C7ECEEDFULL,
		0x38F68454C5D5926BULL
	}};
	printf("Test Case 293\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 293 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -293;
	} else {
		printf("Test Case 293 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x57771F33D6E20546ULL,
		0x58A2063449078F73ULL,
		0x41A0BC0583BAB2B3ULL,
		0xB5B0E4BE22DEB994ULL,
		0xD7D405AFF64CE849ULL,
		0x1CDC1E342FDB0D82ULL,
		0x3E552A55F6D9766FULL,
		0x1B17DAF2D7D13F3DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAEEE3E67ADC40A8CULL,
		0xB1440C68920F1EE6ULL,
		0x8341780B07756566ULL,
		0x6B61C97C45BD7328ULL,
		0xAFA80B5FEC99D093ULL,
		0x39B83C685FB61B05ULL,
		0x7CAA54ABEDB2ECDEULL,
		0x362FB5E5AFA27E7AULL
	}};
	printf("Test Case 294\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 294 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -294;
	} else {
		printf("Test Case 294 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x248ED98BFCB61168ULL,
		0xA77FA719D2E85FACULL,
		0x753A5A363F64E3A7ULL,
		0x7B979394152619C2ULL,
		0xFEDB32DC5BBF979DULL,
		0x33CD9792E1D71B25ULL,
		0x1F8C5BE290C06AD2ULL,
		0x04C16BA925E4598DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x491DB317F96C22D0ULL,
		0x4EFF4E33A5D0BF58ULL,
		0xEA74B46C7EC9C74FULL,
		0xF72F27282A4C3384ULL,
		0xFDB665B8B77F2F3AULL,
		0x679B2F25C3AE364BULL,
		0x3F18B7C52180D5A4ULL,
		0x0982D7524BC8B31AULL
	}};
	printf("Test Case 295\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 295 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -295;
	} else {
		printf("Test Case 295 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD273E01CA9B4BF1AULL,
		0x881B9B7521C4A92FULL,
		0xC7D9CE7B37622B2EULL,
		0xC81D39D0993228B0ULL,
		0xBDC85B073DF75B6CULL,
		0x2C53FEACC9D837B8ULL,
		0x3F578BCCE1F59301ULL,
		0x0BD4C3836574A5D9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA4E7C03953697E34ULL,
		0x103736EA4389525FULL,
		0x8FB39CF66EC4565DULL,
		0x903A73A132645161ULL,
		0x7B90B60E7BEEB6D9ULL,
		0x58A7FD5993B06F71ULL,
		0x7EAF1799C3EB2602ULL,
		0x17A98706CAE94BB2ULL
	}};
	printf("Test Case 296\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 296 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -296;
	} else {
		printf("Test Case 296 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x26DD00D24CC69BEBULL,
		0x6C0A828CA858D2B5ULL,
		0xE251E9C4355A87B7ULL,
		0xA4AC752DFDB08442ULL,
		0x92FC185DDBAF9701ULL,
		0xB97FC3C369F6A7E7ULL,
		0xC24506C482035022ULL,
		0x130CCA685E818852ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4DBA01A4998D37D6ULL,
		0xD815051950B1A56AULL,
		0xC4A3D3886AB50F6EULL,
		0x4958EA5BFB610885ULL,
		0x25F830BBB75F2E03ULL,
		0x72FF8786D3ED4FCFULL,
		0x848A0D890406A045ULL,
		0x261994D0BD0310A5ULL
	}};
	printf("Test Case 297\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 297 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -297;
	} else {
		printf("Test Case 297 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0FC2E9DC26836FA2ULL,
		0x58FAEAD4C4AA063DULL,
		0x0B5A1B078AE6DF24ULL,
		0x2BEE9B85E0789000ULL,
		0xF3639E27CBD985B7ULL,
		0x4EF124AC4C76E1E3ULL,
		0x7F84A5BEB08BEE06ULL,
		0x3F26AC1CFF70DCDEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1F85D3B84D06DF44ULL,
		0xB1F5D5A989540C7AULL,
		0x16B4360F15CDBE48ULL,
		0x57DD370BC0F12000ULL,
		0xE6C73C4F97B30B6EULL,
		0x9DE2495898EDC3C7ULL,
		0xFF094B7D6117DC0CULL,
		0x7E4D5839FEE1B9BCULL
	}};
	printf("Test Case 298\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 298 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -298;
	} else {
		printf("Test Case 298 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x491D3435E2EB5F8DULL,
		0x1A46DFDD5304ECA3ULL,
		0xE1639267B3314B11ULL,
		0xD66518FDC5AF35FBULL,
		0x39AD838C2FF25D02ULL,
		0xF20DCD6C003D74B1ULL,
		0xCEB5F6E8DE46D834ULL,
		0x250BC7C705BDBE0EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x923A686BC5D6BF1AULL,
		0x348DBFBAA609D946ULL,
		0xC2C724CF66629622ULL,
		0xACCA31FB8B5E6BF7ULL,
		0x735B07185FE4BA05ULL,
		0xE41B9AD8007AE962ULL,
		0x9D6BEDD1BC8DB069ULL,
		0x4A178F8E0B7B7C1DULL
	}};
	printf("Test Case 299\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 299 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -299;
	} else {
		printf("Test Case 299 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x16BEA34D73264740ULL,
		0xD0D6E5E7D96BC266ULL,
		0x69DD36BE5A3B225DULL,
		0xCD62440180BE4F6CULL,
		0xFE92CE4651929FFDULL,
		0x55B5E7FB6762674AULL,
		0xB5F81CC5F17DF864ULL,
		0x17DD3FB2D32D824FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2D7D469AE64C8E80ULL,
		0xA1ADCBCFB2D784CCULL,
		0xD3BA6D7CB47644BBULL,
		0x9AC48803017C9ED8ULL,
		0xFD259C8CA3253FFBULL,
		0xAB6BCFF6CEC4CE95ULL,
		0x6BF0398BE2FBF0C8ULL,
		0x2FBA7F65A65B049FULL
	}};
	printf("Test Case 300\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 300 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -300;
	} else {
		printf("Test Case 300 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5803ED418655102DULL,
		0x8FFD4C897B0D8214ULL,
		0x05E44DEC7CD6DA94ULL,
		0xE4B924E58642977FULL,
		0x124C7B6F0EB45E0EULL,
		0x7D2359680B4943A6ULL,
		0x0C92D14E558A302DULL,
		0x2766666191233421ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB007DA830CAA205AULL,
		0x1FFA9912F61B0428ULL,
		0x0BC89BD8F9ADB529ULL,
		0xC97249CB0C852EFEULL,
		0x2498F6DE1D68BC1DULL,
		0xFA46B2D01692874CULL,
		0x1925A29CAB14605AULL,
		0x4ECCCCC322466842ULL
	}};
	printf("Test Case 301\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 301 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -301;
	} else {
		printf("Test Case 301 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x181FBF2DB6CDBA0CULL,
		0x7824818C92E50963ULL,
		0x0D1FDA60233EAA2EULL,
		0x2387CDF866E52656ULL,
		0x8406C0942E90EB39ULL,
		0xC1048D42DE04F06EULL,
		0xBAFE1B349B16B5FDULL,
		0x37B746E6DF677DB8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x303F7E5B6D9B7418ULL,
		0xF049031925CA12C6ULL,
		0x1A3FB4C0467D545CULL,
		0x470F9BF0CDCA4CACULL,
		0x080D81285D21D672ULL,
		0x82091A85BC09E0DDULL,
		0x75FC3669362D6BFBULL,
		0x6F6E8DCDBECEFB71ULL
	}};
	printf("Test Case 302\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 302 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -302;
	} else {
		printf("Test Case 302 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x04D5A53B5E66A4F8ULL,
		0x5AFB8FF500D58F9CULL,
		0xBCC0AC5C5C5144B9ULL,
		0x8A354BEB398690C1ULL,
		0xAA37D239DC753172ULL,
		0x7B2947847023EB74ULL,
		0x20A3A2368FC549A2ULL,
		0x09ADF38D3902A226ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x09AB4A76BCCD49F0ULL,
		0xB5F71FEA01AB1F38ULL,
		0x798158B8B8A28972ULL,
		0x146A97D6730D2183ULL,
		0x546FA473B8EA62E5ULL,
		0xF6528F08E047D6E9ULL,
		0x4147446D1F8A9344ULL,
		0x135BE71A7205444CULL
	}};
	printf("Test Case 303\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 303 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -303;
	} else {
		printf("Test Case 303 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE1EC9D23D313C3CAULL,
		0x4600101DF1D06CCCULL,
		0xB95F8BF27D9DD66EULL,
		0xD6B607F07E41FD92ULL,
		0x88D02C748096FAECULL,
		0x26DCDE92EF310632ULL,
		0x83C7608B66A61E5BULL,
		0x3598555DBA2AC00EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC3D93A47A6278794ULL,
		0x8C00203BE3A0D999ULL,
		0x72BF17E4FB3BACDCULL,
		0xAD6C0FE0FC83FB25ULL,
		0x11A058E9012DF5D9ULL,
		0x4DB9BD25DE620C65ULL,
		0x078EC116CD4C3CB6ULL,
		0x6B30AABB7455801DULL
	}};
	printf("Test Case 304\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 304 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -304;
	} else {
		printf("Test Case 304 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFAD7B9AF41AB338FULL,
		0x7916098E7737F3D0ULL,
		0x8544F730B62406FEULL,
		0x48631F2B8D729A69ULL,
		0x1B8D208295EBC68BULL,
		0xA5D2280640A4C2B2ULL,
		0x5873782814582C2AULL,
		0x244985FD503C03DFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF5AF735E8356671EULL,
		0xF22C131CEE6FE7A1ULL,
		0x0A89EE616C480DFCULL,
		0x90C63E571AE534D3ULL,
		0x371A41052BD78D16ULL,
		0x4BA4500C81498564ULL,
		0xB0E6F05028B05855ULL,
		0x48930BFAA07807BEULL
	}};
	printf("Test Case 305\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 305 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -305;
	} else {
		printf("Test Case 305 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9C0A51A5FAA77519ULL,
		0xAFF4426836ADC372ULL,
		0x25FA6132FD7283C8ULL,
		0x6525190A2D831637ULL,
		0x287704AF22670489ULL,
		0x878D5B33CB073B4AULL,
		0xA637CC33A7E1B696ULL,
		0x244CBAC56342E709ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3814A34BF54EEA32ULL,
		0x5FE884D06D5B86E5ULL,
		0x4BF4C265FAE50791ULL,
		0xCA4A32145B062C6EULL,
		0x50EE095E44CE0912ULL,
		0x0F1AB667960E7694ULL,
		0x4C6F98674FC36D2DULL,
		0x4899758AC685CE13ULL
	}};
	printf("Test Case 306\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 306 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -306;
	} else {
		printf("Test Case 306 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1A4EEC4A951F6212ULL,
		0xB9E803EE7FA29653ULL,
		0xC0A88B687C9B2335ULL,
		0x94648D127EF62D11ULL,
		0xDFB83E3619323E36ULL,
		0xD6A4840643182037ULL,
		0xD5CA9911F7090F95ULL,
		0x33EF4611425DB9D3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x349DD8952A3EC424ULL,
		0x73D007DCFF452CA6ULL,
		0x815116D0F936466BULL,
		0x28C91A24FDEC5A23ULL,
		0xBF707C6C32647C6DULL,
		0xAD49080C8630406FULL,
		0xAB953223EE121F2BULL,
		0x67DE8C2284BB73A7ULL
	}};
	printf("Test Case 307\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 307 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -307;
	} else {
		printf("Test Case 307 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA390E781830F9D43ULL,
		0x12D8C668211ED224ULL,
		0x38A57D6E3C653AB3ULL,
		0xA05A7B1822629396ULL,
		0x31BEC934D35D650AULL,
		0xEBA2339F73551945ULL,
		0x9CFF9A15020690EDULL,
		0x30453B892466E45FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4721CF03061F3A86ULL,
		0x25B18CD0423DA449ULL,
		0x714AFADC78CA7566ULL,
		0x40B4F63044C5272CULL,
		0x637D9269A6BACA15ULL,
		0xD744673EE6AA328AULL,
		0x39FF342A040D21DBULL,
		0x608A771248CDC8BFULL
	}};
	printf("Test Case 308\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 308 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -308;
	} else {
		printf("Test Case 308 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x85F19D19673863FBULL,
		0x393BB50848912700ULL,
		0x004AE00350C37137ULL,
		0x2C43ED4F2F9641B2ULL,
		0x9C34E2631DA9DB7DULL,
		0x6C8AC3D9CC6449F9ULL,
		0xD13FC4D9ECCA8ECDULL,
		0x3DBF0F8A8EBD078CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0BE33A32CE70C7F6ULL,
		0x72776A1091224E01ULL,
		0x0095C006A186E26EULL,
		0x5887DA9E5F2C8364ULL,
		0x3869C4C63B53B6FAULL,
		0xD91587B398C893F3ULL,
		0xA27F89B3D9951D9AULL,
		0x7B7E1F151D7A0F19ULL
	}};
	printf("Test Case 309\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 309 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -309;
	} else {
		printf("Test Case 309 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5F9799543A2A6BFCULL,
		0x2AC6D77CDDAB34F8ULL,
		0xE1183180216883E5ULL,
		0xF0386DFDFD21D944ULL,
		0x763B99BC7DA3F745ULL,
		0xF5EFC49108291297ULL,
		0x47740CA5677941DBULL,
		0x2B50B1C8D0CAA762ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBF2F32A87454D7F8ULL,
		0x558DAEF9BB5669F0ULL,
		0xC230630042D107CAULL,
		0xE070DBFBFA43B289ULL,
		0xEC773378FB47EE8BULL,
		0xEBDF89221052252EULL,
		0x8EE8194ACEF283B7ULL,
		0x56A16391A1954EC4ULL
	}};
	printf("Test Case 310\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 310 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -310;
	} else {
		printf("Test Case 310 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x93773BF77F14C00EULL,
		0x84F73D3DBC8F916CULL,
		0xB131E7141B39FD81ULL,
		0x05FB51825FC3CAFBULL,
		0x77E36FCB6DC3E3F1ULL,
		0xEDA046DB6E12AA7EULL,
		0xFC098AA4740E1C6CULL,
		0x2E5C7A1F99312E2AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x26EE77EEFE29801CULL,
		0x09EE7A7B791F22D9ULL,
		0x6263CE283673FB03ULL,
		0x0BF6A304BF8795F7ULL,
		0xEFC6DF96DB87C7E2ULL,
		0xDB408DB6DC2554FCULL,
		0xF8131548E81C38D9ULL,
		0x5CB8F43F32625C55ULL
	}};
	printf("Test Case 311\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 311 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -311;
	} else {
		printf("Test Case 311 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE9C5208885A3E0BFULL,
		0xEEAB4A5B72F0AA33ULL,
		0xAC339EFE12580F9DULL,
		0x4AB4EC70807B89E2ULL,
		0x8558572E0B031CB1ULL,
		0x5A3713FF49CFD7A7ULL,
		0x46AD048E8660A4F4ULL,
		0x145C8C7DF35E7461ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD38A41110B47C17EULL,
		0xDD5694B6E5E15467ULL,
		0x58673DFC24B01F3BULL,
		0x9569D8E100F713C5ULL,
		0x0AB0AE5C16063962ULL,
		0xB46E27FE939FAF4FULL,
		0x8D5A091D0CC149E8ULL,
		0x28B918FBE6BCE8C2ULL
	}};
	printf("Test Case 312\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 312 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -312;
	} else {
		printf("Test Case 312 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE88AFA66385EEFFEULL,
		0x25DCA3A122714066ULL,
		0x14C97EBF8B81B3B4ULL,
		0xA5A537DEA65424B8ULL,
		0x01ADE79B3203EF48ULL,
		0x988F9ADC34CB3855ULL,
		0xDE52E7D443527909ULL,
		0x3FBF23537EAB892FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD115F4CC70BDDFFCULL,
		0x4BB9474244E280CDULL,
		0x2992FD7F17036768ULL,
		0x4B4A6FBD4CA84970ULL,
		0x035BCF366407DE91ULL,
		0x311F35B8699670AAULL,
		0xBCA5CFA886A4F213ULL,
		0x7F7E46A6FD57125FULL
	}};
	printf("Test Case 313\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 313 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -313;
	} else {
		printf("Test Case 313 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x275610ECBFB9EE33ULL,
		0xA2B34208D71ECD5DULL,
		0x26582546BF99FCBAULL,
		0xFE9D35F59C26042DULL,
		0xC3390202DADF3914ULL,
		0x917C5E4747276DA5ULL,
		0xCC8C8591ECB54DD8ULL,
		0x3C54E721BC9C0514ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4EAC21D97F73DC66ULL,
		0x45668411AE3D9ABAULL,
		0x4CB04A8D7F33F975ULL,
		0xFD3A6BEB384C085AULL,
		0x86720405B5BE7229ULL,
		0x22F8BC8E8E4EDB4BULL,
		0x99190B23D96A9BB1ULL,
		0x78A9CE4379380A29ULL
	}};
	printf("Test Case 314\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 314 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -314;
	} else {
		printf("Test Case 314 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEFC2094487A3A194ULL,
		0x28A9BD444A6FE00FULL,
		0x9AB58CD9D0560719ULL,
		0xA9256C0BB402E149ULL,
		0x285E660383986AFFULL,
		0x77CCB0269F736D77ULL,
		0xBEDF6A91C094A2B4ULL,
		0x3E71819FE959E193ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDF8412890F474328ULL,
		0x51537A8894DFC01FULL,
		0x356B19B3A0AC0E32ULL,
		0x524AD8176805C293ULL,
		0x50BCCC070730D5FFULL,
		0xEF99604D3EE6DAEEULL,
		0x7DBED52381294568ULL,
		0x7CE3033FD2B3C327ULL
	}};
	printf("Test Case 315\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 315 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -315;
	} else {
		printf("Test Case 315 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xABF0F545916904D0ULL,
		0x666EDEA94546A147ULL,
		0x75D7638BCBB6FE2FULL,
		0x74F69B940E86F8DCULL,
		0x0B398F7E89247EBDULL,
		0x2A40EF452E5907BFULL,
		0x5E2E3964B7EFAD2BULL,
		0x096A38787A908324ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x57E1EA8B22D209A0ULL,
		0xCCDDBD528A8D428FULL,
		0xEBAEC717976DFC5EULL,
		0xE9ED37281D0DF1B8ULL,
		0x16731EFD1248FD7AULL,
		0x5481DE8A5CB20F7EULL,
		0xBC5C72C96FDF5A56ULL,
		0x12D470F0F5210648ULL
	}};
	printf("Test Case 316\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 316 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -316;
	} else {
		printf("Test Case 316 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x506F09A4A898ED12ULL,
		0x1D6D06FB01EBE499ULL,
		0xE9D422F64851CE82ULL,
		0xD333F12CE28CBED6ULL,
		0x540628D7FE421832ULL,
		0xEE210849102888C1ULL,
		0xDE45CF12A9CA0E81ULL,
		0x0EA627225926605AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA0DE13495131DA24ULL,
		0x3ADA0DF603D7C932ULL,
		0xD3A845EC90A39D04ULL,
		0xA667E259C5197DADULL,
		0xA80C51AFFC843065ULL,
		0xDC42109220511182ULL,
		0xBC8B9E2553941D03ULL,
		0x1D4C4E44B24CC0B5ULL
	}};
	printf("Test Case 317\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 317 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -317;
	} else {
		printf("Test Case 317 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3F823ED42A85E59BULL,
		0xAA895CEAFA794927ULL,
		0xB32B27554A656788ULL,
		0xB9DF59E96711AD13ULL,
		0x1EE36CA0A2947408ULL,
		0xF8DB9221403E82C4ULL,
		0x6B1AD0A7BB0EA87AULL,
		0x3A32C3F0F1DFBA65ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7F047DA8550BCB36ULL,
		0x5512B9D5F4F2924EULL,
		0x66564EAA94CACF11ULL,
		0x73BEB3D2CE235A27ULL,
		0x3DC6D9414528E811ULL,
		0xF1B72442807D0588ULL,
		0xD635A14F761D50F5ULL,
		0x746587E1E3BF74CAULL
	}};
	printf("Test Case 318\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 318 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -318;
	} else {
		printf("Test Case 318 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7960C5C985B0ED36ULL,
		0x15857C9145932000ULL,
		0xA3C12069E5ECB266ULL,
		0x5A589882BD7119D6ULL,
		0xAA09D0DD08796B94ULL,
		0x47D172DE4FBF5CDDULL,
		0x62534C48C1395555ULL,
		0x33005D0EF4FD87EBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF2C18B930B61DA6CULL,
		0x2B0AF9228B264000ULL,
		0x478240D3CBD964CCULL,
		0xB4B131057AE233ADULL,
		0x5413A1BA10F2D728ULL,
		0x8FA2E5BC9F7EB9BBULL,
		0xC4A698918272AAAAULL,
		0x6600BA1DE9FB0FD6ULL
	}};
	printf("Test Case 319\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 319 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -319;
	} else {
		printf("Test Case 319 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x841BC2CB4A1DC7F2ULL,
		0x85BF2885E9D8C6E6ULL,
		0xAEC436C3659011A2ULL,
		0x8DF9384490B3D74FULL,
		0xD9C04A4F9F6DC155ULL,
		0xA8B8ECC97A8E051CULL,
		0xD3A766BE8706444DULL,
		0x34672658D326123AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x08378596943B8FE4ULL,
		0x0B7E510BD3B18DCDULL,
		0x5D886D86CB202345ULL,
		0x1BF270892167AE9FULL,
		0xB380949F3EDB82ABULL,
		0x5171D992F51C0A39ULL,
		0xA74ECD7D0E0C889BULL,
		0x68CE4CB1A64C2475ULL
	}};
	printf("Test Case 320\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 320 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -320;
	} else {
		printf("Test Case 320 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF1FC0F370E37EF07ULL,
		0x046F39A1B2E47BD9ULL,
		0xF1B5F7071945054BULL,
		0xF298C1F786508000ULL,
		0xD667483941793B52ULL,
		0xB04EEABA43718D9BULL,
		0x3309809FA082B1ACULL,
		0x2BC1DDC720DF5448ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE3F81E6E1C6FDE0EULL,
		0x08DE734365C8F7B3ULL,
		0xE36BEE0E328A0A96ULL,
		0xE53183EF0CA10001ULL,
		0xACCE907282F276A5ULL,
		0x609DD57486E31B37ULL,
		0x6613013F41056359ULL,
		0x5783BB8E41BEA890ULL
	}};
	printf("Test Case 321\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 321 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -321;
	} else {
		printf("Test Case 321 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4D9B6790D62F4EC8ULL,
		0x3DB9CD9080F6BF9BULL,
		0xD5464A8104E38C13ULL,
		0x1C07CFBBAD28406EULL,
		0x25BC1471385A5D01ULL,
		0xF16ADB95A45F9E35ULL,
		0xEBDA435723F61557ULL,
		0x00B2B6B86AFAEDDBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9B36CF21AC5E9D90ULL,
		0x7B739B2101ED7F36ULL,
		0xAA8C950209C71826ULL,
		0x380F9F775A5080DDULL,
		0x4B7828E270B4BA02ULL,
		0xE2D5B72B48BF3C6AULL,
		0xD7B486AE47EC2AAFULL,
		0x01656D70D5F5DBB7ULL
	}};
	printf("Test Case 322\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 322 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -322;
	} else {
		printf("Test Case 322 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAE0A3F817F3FE271ULL,
		0xC299AA7D0AD3A509ULL,
		0x96D3A6C7BFFAF275ULL,
		0x057C571495739375ULL,
		0xD8E2AE3EC0066250ULL,
		0x5C4316767B0F6574ULL,
		0x30BCABA2744BCC3CULL,
		0x133D2487F3F4E75DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5C147F02FE7FC4E2ULL,
		0x853354FA15A74A13ULL,
		0x2DA74D8F7FF5E4EBULL,
		0x0AF8AE292AE726EBULL,
		0xB1C55C7D800CC4A0ULL,
		0xB8862CECF61ECAE9ULL,
		0x61795744E8979878ULL,
		0x267A490FE7E9CEBAULL
	}};
	printf("Test Case 323\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 323 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -323;
	} else {
		printf("Test Case 323 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDE752B8E21FE0756ULL,
		0x4B805DC350792EF5ULL,
		0x3B787A75300D617FULL,
		0x71CCD4D7D7558EFEULL,
		0xD73247891CADA6D1ULL,
		0xC9A056EE0B140BF0ULL,
		0xCBD057E7ECB52247ULL,
		0x3F8B70954E0C1B72ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBCEA571C43FC0EACULL,
		0x9700BB86A0F25DEBULL,
		0x76F0F4EA601AC2FEULL,
		0xE399A9AFAEAB1DFCULL,
		0xAE648F12395B4DA2ULL,
		0x9340ADDC162817E1ULL,
		0x97A0AFCFD96A448FULL,
		0x7F16E12A9C1836E5ULL
	}};
	printf("Test Case 324\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 324 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -324;
	} else {
		printf("Test Case 324 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8D0EA0CBF7D29389ULL,
		0x3DC8194E48443C59ULL,
		0x230381A2198BF4EAULL,
		0xE6E6E077F8034958ULL,
		0xF8140448E6447E3AULL,
		0x1BAA299CCD4C963EULL,
		0x0CFE85458590CE8BULL,
		0x2F8D261B30544D3BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1A1D4197EFA52712ULL,
		0x7B90329C908878B3ULL,
		0x460703443317E9D4ULL,
		0xCDCDC0EFF00692B0ULL,
		0xF0280891CC88FC75ULL,
		0x375453399A992C7DULL,
		0x19FD0A8B0B219D16ULL,
		0x5F1A4C3660A89A76ULL
	}};
	printf("Test Case 325\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 325 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -325;
	} else {
		printf("Test Case 325 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDE90CC5FB1F833C2ULL,
		0x9E50559E1B94214DULL,
		0x08B7473A90A9C9FFULL,
		0x5B8E79D147190262ULL,
		0x6D2F5D48C02A78E6ULL,
		0xDDF5455074378C04ULL,
		0xB9263E3949F47D35ULL,
		0x1C9E9619A6932AEFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBD2198BF63F06784ULL,
		0x3CA0AB3C3728429BULL,
		0x116E8E75215393FFULL,
		0xB71CF3A28E3204C4ULL,
		0xDA5EBA918054F1CCULL,
		0xBBEA8AA0E86F1808ULL,
		0x724C7C7293E8FA6BULL,
		0x393D2C334D2655DFULL
	}};
	printf("Test Case 326\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 326 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -326;
	} else {
		printf("Test Case 326 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF23669FA184CB479ULL,
		0xF03549BBD6A29F47ULL,
		0x3595AC0DA9BDF1B2ULL,
		0x3A1F2BE88B50DA72ULL,
		0xFDE17F400DD46BD7ULL,
		0xA788DF29CB6137CEULL,
		0xA1B36E2276C53BFDULL,
		0x1323560A4D252848ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE46CD3F4309968F2ULL,
		0xE06A9377AD453E8FULL,
		0x6B2B581B537BE365ULL,
		0x743E57D116A1B4E4ULL,
		0xFBC2FE801BA8D7AEULL,
		0x4F11BE5396C26F9DULL,
		0x4366DC44ED8A77FBULL,
		0x2646AC149A4A5091ULL
	}};
	printf("Test Case 327\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 327 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -327;
	} else {
		printf("Test Case 327 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEE434F1080F18B1CULL,
		0x25CD919AA7BDB406ULL,
		0xCFAED381054772CBULL,
		0x864AFD93DEC0387BULL,
		0x7573AA60D2910134ULL,
		0xE63F074F3745A502ULL,
		0x5C4B0CBB7895D9EAULL,
		0x0DE41F1AF078563CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDC869E2101E31638ULL,
		0x4B9B23354F7B680DULL,
		0x9F5DA7020A8EE596ULL,
		0x0C95FB27BD8070F7ULL,
		0xEAE754C1A5220269ULL,
		0xCC7E0E9E6E8B4A04ULL,
		0xB8961976F12BB3D5ULL,
		0x1BC83E35E0F0AC78ULL
	}};
	printf("Test Case 328\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 328 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -328;
	} else {
		printf("Test Case 328 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x51970B5242E8F428ULL,
		0x51194F2EEB225143ULL,
		0xB742D5523CFA9D65ULL,
		0x5486BFECA1D73462ULL,
		0x9CEFD2D75011B2A6ULL,
		0x63306A7446F98C2AULL,
		0x592EEDC2D4BD645FULL,
		0x1A84FC7436347F71ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA32E16A485D1E850ULL,
		0xA2329E5DD644A286ULL,
		0x6E85AAA479F53ACAULL,
		0xA90D7FD943AE68C5ULL,
		0x39DFA5AEA023654CULL,
		0xC660D4E88DF31855ULL,
		0xB25DDB85A97AC8BEULL,
		0x3509F8E86C68FEE2ULL
	}};
	printf("Test Case 329\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 329 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -329;
	} else {
		printf("Test Case 329 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x345EDC2DD8B9FD17ULL,
		0xF3BF07EF87E7CBABULL,
		0x3765DFBEF9A40893ULL,
		0xD573C3615C6D801BULL,
		0xDEC8B0E10A362D4AULL,
		0x74CDC1BDBE9650B2ULL,
		0xBB62385A80E3440FULL,
		0x19BD072D73ACCD19ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x68BDB85BB173FA2EULL,
		0xE77E0FDF0FCF9756ULL,
		0x6ECBBF7DF3481127ULL,
		0xAAE786C2B8DB0036ULL,
		0xBD9161C2146C5A95ULL,
		0xE99B837B7D2CA165ULL,
		0x76C470B501C6881EULL,
		0x337A0E5AE7599A33ULL
	}};
	printf("Test Case 330\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 330 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -330;
	} else {
		printf("Test Case 330 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD9628C2D3D9BBFD2ULL,
		0x34E30F34F9C2D446ULL,
		0x983291E5B7162328ULL,
		0x9857A9B46B846959ULL,
		0x2C37D25C109C9115ULL,
		0xFA1D348269CDAA02ULL,
		0xDB51D2CD9CE8C3D5ULL,
		0x0E21D4BDD890FA6DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB2C5185A7B377FA4ULL,
		0x69C61E69F385A88DULL,
		0x306523CB6E2C4650ULL,
		0x30AF5368D708D2B3ULL,
		0x586FA4B82139222BULL,
		0xF43A6904D39B5404ULL,
		0xB6A3A59B39D187ABULL,
		0x1C43A97BB121F4DBULL
	}};
	printf("Test Case 331\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 331 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -331;
	} else {
		printf("Test Case 331 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8191D9C820DDE994ULL,
		0xFB1E14E8DD66A4DFULL,
		0x05AD7D300675C7EFULL,
		0x234FD498F046D6A9ULL,
		0xFE3397AB251045ABULL,
		0x9B16EC68881751F8ULL,
		0x3E0D610649FDA13DULL,
		0x04E2A9E90B1910B9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0323B39041BBD328ULL,
		0xF63C29D1BACD49BFULL,
		0x0B5AFA600CEB8FDFULL,
		0x469FA931E08DAD52ULL,
		0xFC672F564A208B56ULL,
		0x362DD8D1102EA3F1ULL,
		0x7C1AC20C93FB427BULL,
		0x09C553D216322172ULL
	}};
	printf("Test Case 332\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 332 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -332;
	} else {
		printf("Test Case 332 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0D2DD20931C5AFAEULL,
		0xF547582C811718BAULL,
		0x6F0C1AF61B83B207ULL,
		0xE086AD516013719DULL,
		0x0E867E58A2F8F9C3ULL,
		0xCF2BABECDEFB00A2ULL,
		0xE87DE009941B3DB9ULL,
		0x0EFC5361D9DC2D3AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1A5BA412638B5F5CULL,
		0xEA8EB059022E3174ULL,
		0xDE1835EC3707640FULL,
		0xC10D5AA2C026E33AULL,
		0x1D0CFCB145F1F387ULL,
		0x9E5757D9BDF60144ULL,
		0xD0FBC01328367B73ULL,
		0x1DF8A6C3B3B85A75ULL
	}};
	printf("Test Case 333\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 333 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -333;
	} else {
		printf("Test Case 333 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB4D6E7EA0C0BC2C3ULL,
		0xD0D08AFE2FF26F6DULL,
		0x4A3635D1851ABD37ULL,
		0x67AB8D1550CAA720ULL,
		0xED43D8D22D6BC81DULL,
		0xB2F0008AD4BA4EADULL,
		0xB3512211C20C42FCULL,
		0x118DA58C19C6D96CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x69ADCFD418178586ULL,
		0xA1A115FC5FE4DEDBULL,
		0x946C6BA30A357A6FULL,
		0xCF571A2AA1954E40ULL,
		0xDA87B1A45AD7903AULL,
		0x65E00115A9749D5BULL,
		0x66A24423841885F9ULL,
		0x231B4B18338DB2D9ULL
	}};
	printf("Test Case 334\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 334 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -334;
	} else {
		printf("Test Case 334 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCB36C458681E8210ULL,
		0x5573D72D34670065ULL,
		0x62CA75AC2E03864EULL,
		0x42329DDE6299257EULL,
		0xC9CDE080AB5CE6C7ULL,
		0x80A4839BDF355C40ULL,
		0xC14F071F5B788D32ULL,
		0x2CE80430485B2253ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x966D88B0D03D0420ULL,
		0xAAE7AE5A68CE00CBULL,
		0xC594EB585C070C9CULL,
		0x84653BBCC5324AFCULL,
		0x939BC10156B9CD8EULL,
		0x01490737BE6AB881ULL,
		0x829E0E3EB6F11A65ULL,
		0x59D0086090B644A7ULL
	}};
	printf("Test Case 335\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 335 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -335;
	} else {
		printf("Test Case 335 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2FA12306E6EB9D5CULL,
		0x45083731EDD94AECULL,
		0xECD265CC2E181691ULL,
		0xA37BD8C9C12B087EULL,
		0x0A92868420DD845FULL,
		0xCB24244603A88ED7ULL,
		0xF4493949918B9716ULL,
		0x3B19E54C8BC8716BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5F42460DCDD73AB8ULL,
		0x8A106E63DBB295D8ULL,
		0xD9A4CB985C302D22ULL,
		0x46F7B193825610FDULL,
		0x15250D0841BB08BFULL,
		0x9648488C07511DAEULL,
		0xE892729323172E2DULL,
		0x7633CA991790E2D7ULL
	}};
	printf("Test Case 336\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 336 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -336;
	} else {
		printf("Test Case 336 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1CE55B5E26880C15ULL,
		0x03D3C6C4C2E27957ULL,
		0xA280DE92C4097DA9ULL,
		0xAE265DE291147EE8ULL,
		0xA18DDAB59438BF8BULL,
		0x88FA987DE09764AFULL,
		0x52588B69A65FD97EULL,
		0x0BFEC1227136DAC8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x39CAB6BC4D10182AULL,
		0x07A78D8985C4F2AEULL,
		0x4501BD258812FB52ULL,
		0x5C4CBBC52228FDD1ULL,
		0x431BB56B28717F17ULL,
		0x11F530FBC12EC95FULL,
		0xA4B116D34CBFB2FDULL,
		0x17FD8244E26DB590ULL
	}};
	printf("Test Case 337\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 337 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -337;
	} else {
		printf("Test Case 337 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF09B567E937E0CEBULL,
		0xDF53DE53AE6C971CULL,
		0xDD8D7E8908A433ACULL,
		0x7C19648592B1A43DULL,
		0x21B9F1D3A172168DULL,
		0x491D8D2F2A9B6335ULL,
		0xAFF08539F3D6081BULL,
		0x1200ECE9C968EE17ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE136ACFD26FC19D6ULL,
		0xBEA7BCA75CD92E39ULL,
		0xBB1AFD1211486759ULL,
		0xF832C90B2563487BULL,
		0x4373E3A742E42D1AULL,
		0x923B1A5E5536C66AULL,
		0x5FE10A73E7AC1036ULL,
		0x2401D9D392D1DC2FULL
	}};
	printf("Test Case 338\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 338 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -338;
	} else {
		printf("Test Case 338 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x559B3FC0EFC8E059ULL,
		0x082322DC2B8AEB56ULL,
		0x7ED9769F7ACA1B1EULL,
		0x795B381B7EFD466FULL,
		0xA8C393E8821D7CDDULL,
		0x1C968E53BFEEFFB7ULL,
		0xC75CBBB1751BA65FULL,
		0x1A218044A4E0C24CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAB367F81DF91C0B2ULL,
		0x104645B85715D6ACULL,
		0xFDB2ED3EF594363CULL,
		0xF2B67036FDFA8CDEULL,
		0x518727D1043AF9BAULL,
		0x392D1CA77FDDFF6FULL,
		0x8EB97762EA374CBEULL,
		0x3443008949C18499ULL
	}};
	printf("Test Case 339\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 339 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -339;
	} else {
		printf("Test Case 339 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6902558CD75D3E4DULL,
		0x0694E1C01F955A3DULL,
		0xE3EB88AC8A5DFA66ULL,
		0x4D164DC8AAF953D8ULL,
		0xD6370EDA4A29C02AULL,
		0xB3A9D2287787D9C3ULL,
		0x4FA1E7DCB29E1B11ULL,
		0x12100B83FAA45EFDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD204AB19AEBA7C9AULL,
		0x0D29C3803F2AB47AULL,
		0xC7D7115914BBF4CCULL,
		0x9A2C9B9155F2A7B1ULL,
		0xAC6E1DB494538054ULL,
		0x6753A450EF0FB387ULL,
		0x9F43CFB9653C3623ULL,
		0x24201707F548BDFAULL
	}};
	printf("Test Case 340\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 340 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -340;
	} else {
		printf("Test Case 340 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x320838EDA4547839ULL,
		0x1853FD4E82FCBF8EULL,
		0x04B36DF4C652E1B0ULL,
		0xF5E893A9ADC50D42ULL,
		0x4A03D0115C0B83E0ULL,
		0x26FB6480F4EF2615ULL,
		0x50CF591CB6E1E2CCULL,
		0x0A11836BEB2AA69FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x641071DB48A8F072ULL,
		0x30A7FA9D05F97F1CULL,
		0x0966DBE98CA5C360ULL,
		0xEBD127535B8A1A84ULL,
		0x9407A022B81707C1ULL,
		0x4DF6C901E9DE4C2AULL,
		0xA19EB2396DC3C598ULL,
		0x142306D7D6554D3EULL
	}};
	printf("Test Case 341\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 341 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -341;
	} else {
		printf("Test Case 341 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAA4D9E06052741C9ULL,
		0xA177B6A2E7951BC1ULL,
		0xEFECC142F195851AULL,
		0x3124C524E81B9A95ULL,
		0x116CAD2E143A343EULL,
		0xADA24A583912FA2BULL,
		0x56B02785D15A86ACULL,
		0x1BBB599CA9774618ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x549B3C0C0A4E8392ULL,
		0x42EF6D45CF2A3783ULL,
		0xDFD98285E32B0A35ULL,
		0x62498A49D037352BULL,
		0x22D95A5C2874687CULL,
		0x5B4494B07225F456ULL,
		0xAD604F0BA2B50D59ULL,
		0x3776B33952EE8C30ULL
	}};
	printf("Test Case 342\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 342 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -342;
	} else {
		printf("Test Case 342 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDFB459932206C0CDULL,
		0x4B0C729523BD3CECULL,
		0xA6E566FA5A2E4767ULL,
		0x4DBC29590448A35DULL,
		0x6030E7646E20F42AULL,
		0x2021049AE0C9902DULL,
		0x5067DFCF2F4F97CBULL,
		0x30306A7C1B61FD97ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBF68B326440D819AULL,
		0x9618E52A477A79D9ULL,
		0x4DCACDF4B45C8ECEULL,
		0x9B7852B2089146BBULL,
		0xC061CEC8DC41E854ULL,
		0x40420935C193205AULL,
		0xA0CFBF9E5E9F2F96ULL,
		0x6060D4F836C3FB2EULL
	}};
	printf("Test Case 343\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 343 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -343;
	} else {
		printf("Test Case 343 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5208B4302C3EA2C2ULL,
		0xA7F48ABF2C78BB6FULL,
		0x047E0FDEFBDCBCBDULL,
		0xFF5271DF5CCF1323ULL,
		0x3C6BF597C12C9C15ULL,
		0xFE1549DCC5C94E3FULL,
		0xD723E07E7B662390ULL,
		0x2747A2AAFC744204ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA4116860587D4584ULL,
		0x4FE9157E58F176DEULL,
		0x08FC1FBDF7B9797BULL,
		0xFEA4E3BEB99E2646ULL,
		0x78D7EB2F8259382BULL,
		0xFC2A93B98B929C7EULL,
		0xAE47C0FCF6CC4721ULL,
		0x4E8F4555F8E88409ULL
	}};
	printf("Test Case 344\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 344 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -344;
	} else {
		printf("Test Case 344 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDF7BC0493B9E2AF6ULL,
		0x302212BF4F39674CULL,
		0x42DC01EACD0CAC10ULL,
		0x74A391CDB1B64BC9ULL,
		0x857A43AA3260C5E1ULL,
		0xFB073DC459BF10A6ULL,
		0xECFAA0E3E97EA918ULL,
		0x245D70C48C2A3AE3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBEF78092773C55ECULL,
		0x6044257E9E72CE99ULL,
		0x85B803D59A195820ULL,
		0xE947239B636C9792ULL,
		0x0AF4875464C18BC2ULL,
		0xF60E7B88B37E214DULL,
		0xD9F541C7D2FD5231ULL,
		0x48BAE189185475C7ULL
	}};
	printf("Test Case 345\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 345 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -345;
	} else {
		printf("Test Case 345 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2D101A59C7E8B4CFULL,
		0x11465F3BF7D3C7A2ULL,
		0x6AACB97B7E383E4AULL,
		0x36BD1E2956C19E13ULL,
		0x41EEFEFB92472826ULL,
		0xA6561CD8705CD14BULL,
		0x9F1AD1997FBB0C71ULL,
		0x2C38086EBF75EDADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5A2034B38FD1699EULL,
		0x228CBE77EFA78F44ULL,
		0xD55972F6FC707C94ULL,
		0x6D7A3C52AD833C26ULL,
		0x83DDFDF7248E504CULL,
		0x4CAC39B0E0B9A296ULL,
		0x3E35A332FF7618E3ULL,
		0x587010DD7EEBDB5BULL
	}};
	printf("Test Case 346\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 346 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -346;
	} else {
		printf("Test Case 346 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x817C67D190E6544EULL,
		0xC787606B47ABE643ULL,
		0x62C52C495CA1DB40ULL,
		0xB68FB1A37E24C7BAULL,
		0x3A8D81F2B1A0EE79ULL,
		0x2F5A8B9D7880F22BULL,
		0x283B1A317B1BF52AULL,
		0x3EA20D91778BD2B4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x02F8CFA321CCA89CULL,
		0x8F0EC0D68F57CC87ULL,
		0xC58A5892B943B681ULL,
		0x6D1F6346FC498F74ULL,
		0x751B03E56341DCF3ULL,
		0x5EB5173AF101E456ULL,
		0x50763462F637EA54ULL,
		0x7D441B22EF17A568ULL
	}};
	printf("Test Case 347\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 347 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -347;
	} else {
		printf("Test Case 347 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x919DECB80521E965ULL,
		0x8CA331AABC183515ULL,
		0xE6F64DC77C5F8180ULL,
		0xDCA16092051C7962ULL,
		0x9C45443A3E5513FEULL,
		0x0054112427A738E2ULL,
		0x24231D133086E721ULL,
		0x2B730D8D5234A978ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x233BD9700A43D2CAULL,
		0x1946635578306A2BULL,
		0xCDEC9B8EF8BF0301ULL,
		0xB942C1240A38F2C5ULL,
		0x388A88747CAA27FDULL,
		0x00A822484F4E71C5ULL,
		0x48463A26610DCE42ULL,
		0x56E61B1AA46952F0ULL
	}};
	printf("Test Case 348\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 348 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -348;
	} else {
		printf("Test Case 348 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3D78E043B68B3D36ULL,
		0xDAE5A6B12CCEB32BULL,
		0x13CEFB8900C983C4ULL,
		0x0A715204011BB60EULL,
		0xB5A89DBC9F33844BULL,
		0x237C9CC47198C008ULL,
		0xF3639FB49571A513ULL,
		0x3D4FD333D3FBFDF5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7AF1C0876D167A6CULL,
		0xB5CB4D62599D6656ULL,
		0x279DF71201930789ULL,
		0x14E2A40802376C1CULL,
		0x6B513B793E670896ULL,
		0x46F93988E3318011ULL,
		0xE6C73F692AE34A26ULL,
		0x7A9FA667A7F7FBEBULL
	}};
	printf("Test Case 349\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 349 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -349;
	} else {
		printf("Test Case 349 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD7E7EB5B393EFE16ULL,
		0xDF141F44A3599AFEULL,
		0xDA451C07B39860EDULL,
		0xC76BD0CD5E58A49BULL,
		0x3B61C7D8DDE7FC58ULL,
		0xC89C1271804A7755ULL,
		0x7AECD87CB050CE2EULL,
		0x3F61CE4FEF3B1318ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAFCFD6B6727DFC2CULL,
		0xBE283E8946B335FDULL,
		0xB48A380F6730C1DBULL,
		0x8ED7A19ABCB14937ULL,
		0x76C38FB1BBCFF8B1ULL,
		0x913824E30094EEAAULL,
		0xF5D9B0F960A19C5DULL,
		0x7EC39C9FDE762630ULL
	}};
	printf("Test Case 350\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 350 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -350;
	} else {
		printf("Test Case 350 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC76EED8CCB85A786ULL,
		0x2361BD63BB866472ULL,
		0x1EDF32EFC2B71FFAULL,
		0x0E1EFC5459016F17ULL,
		0x087ECF58DFAF33ACULL,
		0xD6BE61D56EF9B3ECULL,
		0xB148AC4A9B5DE29AULL,
		0x3D1DCC02717C29C1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8EDDDB19970B4F0CULL,
		0x46C37AC7770CC8E5ULL,
		0x3DBE65DF856E3FF4ULL,
		0x1C3DF8A8B202DE2EULL,
		0x10FD9EB1BF5E6758ULL,
		0xAD7CC3AADDF367D8ULL,
		0x6291589536BBC535ULL,
		0x7A3B9804E2F85383ULL
	}};
	printf("Test Case 351\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 351 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -351;
	} else {
		printf("Test Case 351 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x02FF8B8E3CACE1F6ULL,
		0xBA939B3A03DDBA20ULL,
		0xB0CA2A2A06CC976DULL,
		0xCEBA56866179A60BULL,
		0x3E0D6C6184C0326BULL,
		0x366C52E41F0E6AB6ULL,
		0x454FB2C2BEBF7B7BULL,
		0x2147E801F37FC6CFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x05FF171C7959C3ECULL,
		0x7527367407BB7440ULL,
		0x619454540D992EDBULL,
		0x9D74AD0CC2F34C17ULL,
		0x7C1AD8C3098064D7ULL,
		0x6CD8A5C83E1CD56CULL,
		0x8A9F65857D7EF6F6ULL,
		0x428FD003E6FF8D9EULL
	}};
	printf("Test Case 352\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 352 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -352;
	} else {
		printf("Test Case 352 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xED21BFC8755A0606ULL,
		0xCB3155C9D6F10849ULL,
		0x0A10BBA2FD16E2C2ULL,
		0xF74FF76E05B46559ULL,
		0xB26A0735F4E3293EULL,
		0xB772D7BC7EF300FDULL,
		0xAFFEC26AED4E201BULL,
		0x2FD9D27FE6E35427ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDA437F90EAB40C0CULL,
		0x9662AB93ADE21093ULL,
		0x14217745FA2DC585ULL,
		0xEE9FEEDC0B68CAB2ULL,
		0x64D40E6BE9C6527DULL,
		0x6EE5AF78FDE601FBULL,
		0x5FFD84D5DA9C4037ULL,
		0x5FB3A4FFCDC6A84FULL
	}};
	printf("Test Case 353\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 353 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -353;
	} else {
		printf("Test Case 353 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1E5230AA3E00B1BCULL,
		0x7F60998D1FB39EE8ULL,
		0x1D360CF1DEE06507ULL,
		0x1F9FDE5ACB566111ULL,
		0xF7BAE91D3B538D88ULL,
		0x7B67817192F7799AULL,
		0xBE30570C521E118AULL,
		0x3D56AE89D089D767ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3CA461547C016378ULL,
		0xFEC1331A3F673DD0ULL,
		0x3A6C19E3BDC0CA0EULL,
		0x3F3FBCB596ACC222ULL,
		0xEF75D23A76A71B10ULL,
		0xF6CF02E325EEF335ULL,
		0x7C60AE18A43C2314ULL,
		0x7AAD5D13A113AECFULL
	}};
	printf("Test Case 354\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 354 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -354;
	} else {
		printf("Test Case 354 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7F7DF7492C4FDCBBULL,
		0x0D45049C661CDFC9ULL,
		0x7210834B619B7BBFULL,
		0xC8EFF1659E37428AULL,
		0x146458373231CA8CULL,
		0x4A607212EC426720ULL,
		0xBEBD1A418A603BF7ULL,
		0x352635323A2D37F1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFEFBEE92589FB976ULL,
		0x1A8A0938CC39BF92ULL,
		0xE4210696C336F77EULL,
		0x91DFE2CB3C6E8514ULL,
		0x28C8B06E64639519ULL,
		0x94C0E425D884CE40ULL,
		0x7D7A348314C077EEULL,
		0x6A4C6A64745A6FE3ULL
	}};
	printf("Test Case 355\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 355 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -355;
	} else {
		printf("Test Case 355 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0190A3C9DD1FB977ULL,
		0x8EDF7DB507C8EE9EULL,
		0xA379A1C99CC59F25ULL,
		0x6444DB3FDCF1E67AULL,
		0x84DA024931189D94ULL,
		0xB8A4C4E9F0143CC8ULL,
		0xF6D2035BA01C7DF3ULL,
		0x11FC7354F3871D46ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x03214793BA3F72EEULL,
		0x1DBEFB6A0F91DD3CULL,
		0x46F34393398B3E4BULL,
		0xC889B67FB9E3CCF5ULL,
		0x09B4049262313B28ULL,
		0x714989D3E0287991ULL,
		0xEDA406B74038FBE7ULL,
		0x23F8E6A9E70E3A8DULL
	}};
	printf("Test Case 356\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 356 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -356;
	} else {
		printf("Test Case 356 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x57E05B68E3F45F4EULL,
		0x2E381D0A6AB1CC40ULL,
		0xC470CAB48C59582EULL,
		0x30C0AF83E9068458ULL,
		0xF89FC5CDC7028F0FULL,
		0xE52399F656B9091AULL,
		0x3755B70A4C17B11DULL,
		0x035F8E28CE7F2CFCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAFC0B6D1C7E8BE9CULL,
		0x5C703A14D5639880ULL,
		0x88E1956918B2B05CULL,
		0x61815F07D20D08B1ULL,
		0xF13F8B9B8E051E1EULL,
		0xCA4733ECAD721235ULL,
		0x6EAB6E14982F623BULL,
		0x06BF1C519CFE59F8ULL
	}};
	printf("Test Case 357\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 357 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -357;
	} else {
		printf("Test Case 357 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5D212DB55DC1F52EULL,
		0x51684810AC2D7231ULL,
		0xBDB024D885C601CFULL,
		0x7F159C831BFFE7B7ULL,
		0x73512694071DC7E9ULL,
		0xA66B86C0C97D5008ULL,
		0x873763A314E760DAULL,
		0x06749E63D7CE59BEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBA425B6ABB83EA5CULL,
		0xA2D09021585AE462ULL,
		0x7B6049B10B8C039EULL,
		0xFE2B390637FFCF6FULL,
		0xE6A24D280E3B8FD2ULL,
		0x4CD70D8192FAA010ULL,
		0x0E6EC74629CEC1B5ULL,
		0x0CE93CC7AF9CB37DULL
	}};
	printf("Test Case 358\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 358 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -358;
	} else {
		printf("Test Case 358 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE909C85AB2BF59BFULL,
		0x902535FB62334916ULL,
		0x091722FFF257993BULL,
		0x1CFB4AAA4298CF0CULL,
		0x8781D312DEE4E072ULL,
		0xA3D567032CAEFD7DULL,
		0xE5C030008BFB09A8ULL,
		0x18E9D75AFDFA0BB9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD21390B5657EB37EULL,
		0x204A6BF6C466922DULL,
		0x122E45FFE4AF3277ULL,
		0x39F6955485319E18ULL,
		0x0F03A625BDC9C0E4ULL,
		0x47AACE06595DFAFBULL,
		0xCB80600117F61351ULL,
		0x31D3AEB5FBF41773ULL
	}};
	printf("Test Case 359\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 359 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -359;
	} else {
		printf("Test Case 359 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x02D7BFA51E930094ULL,
		0x43918595A02BAAD2ULL,
		0xDEE6F825D0274D68ULL,
		0xE087CD631F2C5649ULL,
		0x329DED2E47AAB1A3ULL,
		0xF0951D54849D8CFCULL,
		0x13638F32D05D29F9ULL,
		0x181BB1B946F54A97ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x05AF7F4A3D260128ULL,
		0x87230B2B405755A4ULL,
		0xBDCDF04BA04E9AD0ULL,
		0xC10F9AC63E58AC93ULL,
		0x653BDA5C8F556347ULL,
		0xE12A3AA9093B19F8ULL,
		0x26C71E65A0BA53F3ULL,
		0x303763728DEA952EULL
	}};
	printf("Test Case 360\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 360 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -360;
	} else {
		printf("Test Case 360 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE54A083883AD8406ULL,
		0x1AF20DD79FEE23CFULL,
		0x12B35ADE65E6C056ULL,
		0x664199B30C429A47ULL,
		0xED74A536E9C390CEULL,
		0xBF365EC0C77C5AB1ULL,
		0x2B54E42C34D2F6F5ULL,
		0x0A52DCB89F462B3AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCA941071075B080CULL,
		0x35E41BAF3FDC479FULL,
		0x2566B5BCCBCD80ACULL,
		0xCC8333661885348EULL,
		0xDAE94A6DD387219CULL,
		0x7E6CBD818EF8B563ULL,
		0x56A9C85869A5EDEBULL,
		0x14A5B9713E8C5674ULL
	}};
	printf("Test Case 361\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 361 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -361;
	} else {
		printf("Test Case 361 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE1F8BCFF4179FFE9ULL,
		0xEA0EFCABFB1D3AC6ULL,
		0xEF11D283A2085D24ULL,
		0x3F475967425519F2ULL,
		0x6AF347CB99641FA0ULL,
		0xDD165F7032D65775ULL,
		0x50C0F5A2FA1A4F2BULL,
		0x3BDD1A9055162CA4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC3F179FE82F3FFD2ULL,
		0xD41DF957F63A758DULL,
		0xDE23A5074410BA49ULL,
		0x7E8EB2CE84AA33E5ULL,
		0xD5E68F9732C83F40ULL,
		0xBA2CBEE065ACAEEAULL,
		0xA181EB45F4349E57ULL,
		0x77BA3520AA2C5948ULL
	}};
	printf("Test Case 362\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 362 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -362;
	} else {
		printf("Test Case 362 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3C623758E1D053EFULL,
		0x270527A2BF4E7DC6ULL,
		0x4081C824C5233989ULL,
		0x825CDA5588972A36ULL,
		0x648EC6B114492743ULL,
		0x7EB4BD56DC57A107ULL,
		0x362F1C94BA0CC81CULL,
		0x012C0F9505EAEB86ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x78C46EB1C3A0A7DEULL,
		0x4E0A4F457E9CFB8CULL,
		0x810390498A467312ULL,
		0x04B9B4AB112E546CULL,
		0xC91D8D6228924E87ULL,
		0xFD697AADB8AF420EULL,
		0x6C5E392974199038ULL,
		0x02581F2A0BD5D70CULL
	}};
	printf("Test Case 363\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 363 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -363;
	} else {
		printf("Test Case 363 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x62DBD699FDEB689BULL,
		0x46ECEDEF4049B2C5ULL,
		0xAACC7737531B831CULL,
		0x0C55F142AD3BCBE1ULL,
		0x0CC79BCA615C1EA7ULL,
		0x07E331A757EE6B9EULL,
		0xC4AEDA32DD6D74AFULL,
		0x1C83124BA6C60AD6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC5B7AD33FBD6D136ULL,
		0x8DD9DBDE8093658AULL,
		0x5598EE6EA6370638ULL,
		0x18ABE2855A7797C3ULL,
		0x198F3794C2B83D4EULL,
		0x0FC6634EAFDCD73CULL,
		0x895DB465BADAE95EULL,
		0x390624974D8C15ADULL
	}};
	printf("Test Case 364\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 364 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -364;
	} else {
		printf("Test Case 364 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x225E8EDC0D6D31E8ULL,
		0x5851F5908760CB4BULL,
		0x54A46A218E67EDCCULL,
		0xAE0119A14AE70952ULL,
		0x7F3D1B15C1175395ULL,
		0x1E476472E8E555BCULL,
		0xAEFFA7C19F61FEA7ULL,
		0x0FE117D4746F579CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x44BD1DB81ADA63D0ULL,
		0xB0A3EB210EC19696ULL,
		0xA948D4431CCFDB98ULL,
		0x5C02334295CE12A4ULL,
		0xFE7A362B822EA72BULL,
		0x3C8EC8E5D1CAAB78ULL,
		0x5DFF4F833EC3FD4EULL,
		0x1FC22FA8E8DEAF39ULL
	}};
	printf("Test Case 365\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 365 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -365;
	} else {
		printf("Test Case 365 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7679B1FE0901006AULL,
		0x7DF29C46599F1961ULL,
		0xE1A102253A150D00ULL,
		0xA0DB77707DD294D4ULL,
		0x0C13AF1375B96223ULL,
		0xD13C707BD82E3886ULL,
		0x578E8556B30DFD86ULL,
		0x31797E0FD9A759DBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xECF363FC120200D4ULL,
		0xFBE5388CB33E32C2ULL,
		0xC342044A742A1A00ULL,
		0x41B6EEE0FBA529A9ULL,
		0x18275E26EB72C447ULL,
		0xA278E0F7B05C710CULL,
		0xAF1D0AAD661BFB0DULL,
		0x62F2FC1FB34EB3B6ULL
	}};
	printf("Test Case 366\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 366 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -366;
	} else {
		printf("Test Case 366 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2134B1A0E8C603E0ULL,
		0x8F15E5D89CF37248ULL,
		0x95FB4FAEDA06DAB4ULL,
		0x52F5E2BBB721D1C4ULL,
		0x98508289359BF797ULL,
		0xA4F08F1D14EA60E7ULL,
		0x0F9D21373AEDE080ULL,
		0x351D9E278783A206ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x42696341D18C07C0ULL,
		0x1E2BCBB139E6E490ULL,
		0x2BF69F5DB40DB569ULL,
		0xA5EBC5776E43A389ULL,
		0x30A105126B37EF2EULL,
		0x49E11E3A29D4C1CFULL,
		0x1F3A426E75DBC101ULL,
		0x6A3B3C4F0F07440CULL
	}};
	printf("Test Case 367\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 367 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -367;
	} else {
		printf("Test Case 367 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4117DD9665EA12B4ULL,
		0xFF81FC3113664203ULL,
		0x6118FFC0E4A6879FULL,
		0x922F58ACFA3F29B5ULL,
		0xF5AA102DE5C8B138ULL,
		0x6C196CE25FBC0E47ULL,
		0x355F814788281E34ULL,
		0x031B23F24346FA9AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x822FBB2CCBD42568ULL,
		0xFF03F86226CC8406ULL,
		0xC231FF81C94D0F3FULL,
		0x245EB159F47E536AULL,
		0xEB54205BCB916271ULL,
		0xD832D9C4BF781C8FULL,
		0x6ABF028F10503C68ULL,
		0x063647E4868DF534ULL
	}};
	printf("Test Case 368\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 368 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -368;
	} else {
		printf("Test Case 368 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD184368DBE7CA64BULL,
		0x38762B011A98891CULL,
		0x479D89606DA6230CULL,
		0xAEF4DB0EE851EB87ULL,
		0xB9B311202108A0E4ULL,
		0xFE8D66785D5DCE87ULL,
		0x824FBD938B255426ULL,
		0x0DA9CD35F385CBA6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA3086D1B7CF94C96ULL,
		0x70EC560235311239ULL,
		0x8F3B12C0DB4C4618ULL,
		0x5DE9B61DD0A3D70EULL,
		0x73662240421141C9ULL,
		0xFD1ACCF0BABB9D0FULL,
		0x049F7B27164AA84DULL,
		0x1B539A6BE70B974DULL
	}};
	printf("Test Case 369\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 369 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -369;
	} else {
		printf("Test Case 369 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4B33532D7F2C9F16ULL,
		0x23A84DA525F7BDDCULL,
		0x26B966577801BE19ULL,
		0x31EFB276E476E88FULL,
		0xBD2B1A744DC4028EULL,
		0xD4A21A041B5960BAULL,
		0x047E57B6E656CCA6ULL,
		0x1CEF4910D2C7B012ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9666A65AFE593E2CULL,
		0x47509B4A4BEF7BB8ULL,
		0x4D72CCAEF0037C32ULL,
		0x63DF64EDC8EDD11EULL,
		0x7A5634E89B88051CULL,
		0xA944340836B2C175ULL,
		0x08FCAF6DCCAD994DULL,
		0x39DE9221A58F6024ULL
	}};
	printf("Test Case 370\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 370 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -370;
	} else {
		printf("Test Case 370 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFAED375F5E19BCBFULL,
		0x1725488AB7A5CD90ULL,
		0x358357998678E5E3ULL,
		0x2A3D9B4948EA0F12ULL,
		0x8FB8794934920B5FULL,
		0x2C03E9A7044F1BFFULL,
		0xA4FF543D9335BC6CULL,
		0x120BF85D4E0FB31EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF5DA6EBEBC33797EULL,
		0x2E4A91156F4B9B21ULL,
		0x6B06AF330CF1CBC6ULL,
		0x547B369291D41E24ULL,
		0x1F70F292692416BEULL,
		0x5807D34E089E37FFULL,
		0x49FEA87B266B78D8ULL,
		0x2417F0BA9C1F663DULL
	}};
	printf("Test Case 371\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 371 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -371;
	} else {
		printf("Test Case 371 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6384537448B310D2ULL,
		0x40C131DD9350D0D6ULL,
		0x880D5EFCB325AEA7ULL,
		0xB99F1B274E8F5951ULL,
		0xF198D6E9E7D285B5ULL,
		0xE368AA2221F49BE1ULL,
		0xA217E37D8518F38DULL,
		0x2F1EBE97529F6601ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC708A6E8916621A4ULL,
		0x818263BB26A1A1ACULL,
		0x101ABDF9664B5D4EULL,
		0x733E364E9D1EB2A3ULL,
		0xE331ADD3CFA50B6BULL,
		0xC6D1544443E937C3ULL,
		0x442FC6FB0A31E71BULL,
		0x5E3D7D2EA53ECC03ULL
	}};
	printf("Test Case 372\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 372 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -372;
	} else {
		printf("Test Case 372 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA41CA60B868B1363ULL,
		0xB98C290B4D77D60BULL,
		0x4A258B53AE9F9F11ULL,
		0x8A0B174FFE35F9C0ULL,
		0x7FA86808877E9024ULL,
		0x11300231DCC4613EULL,
		0x3B75270C170A6112ULL,
		0x3E42DF374E84A741ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x48394C170D1626C6ULL,
		0x731852169AEFAC17ULL,
		0x944B16A75D3F3E23ULL,
		0x14162E9FFC6BF380ULL,
		0xFF50D0110EFD2049ULL,
		0x22600463B988C27CULL,
		0x76EA4E182E14C224ULL,
		0x7C85BE6E9D094E82ULL
	}};
	printf("Test Case 373\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 373 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -373;
	} else {
		printf("Test Case 373 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5A4EF9EACDCE4409ULL,
		0x7549AD05C1B2A896ULL,
		0xE75151E05F65DBC6ULL,
		0x81B73B0477F94FEFULL,
		0xA312588959C3F91CULL,
		0xBE9A6E5067160497ULL,
		0xF42139B1582CE86DULL,
		0x29FC77F85FD0F5D8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB49DF3D59B9C8812ULL,
		0xEA935A0B8365512CULL,
		0xCEA2A3C0BECBB78CULL,
		0x036E7608EFF29FDFULL,
		0x4624B112B387F239ULL,
		0x7D34DCA0CE2C092FULL,
		0xE8427362B059D0DBULL,
		0x53F8EFF0BFA1EBB1ULL
	}};
	printf("Test Case 374\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 374 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -374;
	} else {
		printf("Test Case 374 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4B7595BA56C033ADULL,
		0x33FEC3597E293BC4ULL,
		0x4C63537F7312EB9BULL,
		0xE8AA3D3181A2F6C8ULL,
		0xCBA1C1E1D15A2034ULL,
		0x85AB0F6E95BAAFCAULL,
		0x8B33F1670E042B07ULL,
		0x257EE4696C604089ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x96EB2B74AD80675AULL,
		0x67FD86B2FC527788ULL,
		0x98C6A6FEE625D736ULL,
		0xD1547A630345ED90ULL,
		0x974383C3A2B44069ULL,
		0x0B561EDD2B755F95ULL,
		0x1667E2CE1C08560FULL,
		0x4AFDC8D2D8C08113ULL
	}};
	printf("Test Case 375\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 375 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -375;
	} else {
		printf("Test Case 375 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x04CC70EFD3FA98BDULL,
		0x5998820D56895740ULL,
		0x8833D752EEC4C8A9ULL,
		0x8780CD0D934A3446ULL,
		0x71FC9BDD820DD066ULL,
		0x624414151457EB0BULL,
		0x8BDC1B35AB9065ACULL,
		0x0A4898BF4FE3547EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0998E1DFA7F5317AULL,
		0xB331041AAD12AE80ULL,
		0x1067AEA5DD899152ULL,
		0x0F019A1B2694688DULL,
		0xE3F937BB041BA0CDULL,
		0xC488282A28AFD616ULL,
		0x17B8366B5720CB58ULL,
		0x1491317E9FC6A8FDULL
	}};
	printf("Test Case 376\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 376 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -376;
	} else {
		printf("Test Case 376 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCA6B54F846848456ULL,
		0x1EAB35B33D0EEBDDULL,
		0x201A9E1B3FC6EBC4ULL,
		0xD43436E48EE42592ULL,
		0x4EBB3EFD46DDAD64ULL,
		0x6D531AF2B36F94E4ULL,
		0x0A5F1EAAF27DA52FULL,
		0x1EEEB759647C22F7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x94D6A9F08D0908ACULL,
		0x3D566B667A1DD7BBULL,
		0x40353C367F8DD788ULL,
		0xA8686DC91DC84B24ULL,
		0x9D767DFA8DBB5AC9ULL,
		0xDAA635E566DF29C8ULL,
		0x14BE3D55E4FB4A5EULL,
		0x3DDD6EB2C8F845EEULL
	}};
	printf("Test Case 377\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 377 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -377;
	} else {
		printf("Test Case 377 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x003522620119AD8AULL,
		0xA137147AEC8B7479ULL,
		0x3B86A1974B22D57AULL,
		0xB3DCD4C9E9D86444ULL,
		0x80E26CF8A4AC090AULL,
		0xB16F9367D06E0A3EULL,
		0xE4A96FF5330AC88AULL,
		0x3A48936ED17E6559ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x006A44C402335B14ULL,
		0x426E28F5D916E8F2ULL,
		0x770D432E9645AAF5ULL,
		0x67B9A993D3B0C888ULL,
		0x01C4D9F149581215ULL,
		0x62DF26CFA0DC147DULL,
		0xC952DFEA66159115ULL,
		0x749126DDA2FCCAB3ULL
	}};
	printf("Test Case 378\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 378 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -378;
	} else {
		printf("Test Case 378 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC02AC981588CABDCULL,
		0x905DE69C9CF0EEAAULL,
		0xB54722F13BD9905FULL,
		0x93E4FEB547F60936ULL,
		0xE6D4C8CF9B68B1B9ULL,
		0x1B32C60EB297D165ULL,
		0x82A26A0782D8D376ULL,
		0x24F15254262071E4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x80559302B11957B8ULL,
		0x20BBCD3939E1DD55ULL,
		0x6A8E45E277B320BFULL,
		0x27C9FD6A8FEC126DULL,
		0xCDA9919F36D16373ULL,
		0x36658C1D652FA2CBULL,
		0x0544D40F05B1A6ECULL,
		0x49E2A4A84C40E3C9ULL
	}};
	printf("Test Case 379\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 379 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -379;
	} else {
		printf("Test Case 379 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFBB882F8CA3D484FULL,
		0x100EB272D75BCC4AULL,
		0x92219457728632ADULL,
		0xF05F182AC240F003ULL,
		0x706653AE823CFFCAULL,
		0xC7F6F40A9D798307ULL,
		0xA2045D663B28B8C3ULL,
		0x33AA6DF965A23382ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF77105F1947A909EULL,
		0x201D64E5AEB79895ULL,
		0x244328AEE50C655AULL,
		0xE0BE30558481E007ULL,
		0xE0CCA75D0479FF95ULL,
		0x8FEDE8153AF3060EULL,
		0x4408BACC76517187ULL,
		0x6754DBF2CB446705ULL
	}};
	printf("Test Case 380\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 380 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -380;
	} else {
		printf("Test Case 380 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE564CEF93732973AULL,
		0x377395725E910C5FULL,
		0x30328DF18FD4EB04ULL,
		0x789FA68A6CACC0C0ULL,
		0xC4DE5B8591EDB218ULL,
		0xDCE2A834B8B8A4B0ULL,
		0x7E4D2865C48F71A3ULL,
		0x023093195C3BAA82ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCAC99DF26E652E74ULL,
		0x6EE72AE4BD2218BFULL,
		0x60651BE31FA9D608ULL,
		0xF13F4D14D9598180ULL,
		0x89BCB70B23DB6430ULL,
		0xB9C5506971714961ULL,
		0xFC9A50CB891EE347ULL,
		0x04612632B8775504ULL
	}};
	printf("Test Case 381\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 381 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -381;
	} else {
		printf("Test Case 381 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2192E40A4B8FCFC5ULL,
		0x18CB8943E0AD5001ULL,
		0xC63317B1C0B8FFD5ULL,
		0xBCFC8ED8AF8F2DE0ULL,
		0xACB318905BAD0390ULL,
		0x61C95A341149DABCULL,
		0xCEF0733A1DC16F15ULL,
		0x14CAFE06D9BC28A3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4325C814971F9F8AULL,
		0x31971287C15AA002ULL,
		0x8C662F638171FFAAULL,
		0x79F91DB15F1E5BC1ULL,
		0x59663120B75A0721ULL,
		0xC392B4682293B579ULL,
		0x9DE0E6743B82DE2AULL,
		0x2995FC0DB3785147ULL
	}};
	printf("Test Case 382\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 382 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -382;
	} else {
		printf("Test Case 382 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x41469E627C903AA4ULL,
		0xA76524E154614DA1ULL,
		0x9BECFA009D113288ULL,
		0xB6C08333798AE9F2ULL,
		0x5021DE34453B75CFULL,
		0x15BE16647F65B54FULL,
		0x74FE4B6A0E786EC0ULL,
		0x38786B65FF56BC70ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x828D3CC4F9207548ULL,
		0x4ECA49C2A8C29B42ULL,
		0x37D9F4013A226511ULL,
		0x6D810666F315D3E5ULL,
		0xA043BC688A76EB9FULL,
		0x2B7C2CC8FECB6A9EULL,
		0xE9FC96D41CF0DD80ULL,
		0x70F0D6CBFEAD78E0ULL
	}};
	printf("Test Case 383\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 383 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -383;
	} else {
		printf("Test Case 383 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x62E6A07629B8FC2CULL,
		0xB3DC974343CEFE5DULL,
		0x2C12303E1048381DULL,
		0x7788704E78ED510FULL,
		0xD601773636A16E2BULL,
		0x448238BC136A8F5CULL,
		0x5D79F0CFE5D914E6ULL,
		0x0CE5F58346BE496CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC5CD40EC5371F858ULL,
		0x67B92E86879DFCBAULL,
		0x5824607C2090703BULL,
		0xEF10E09CF1DAA21EULL,
		0xAC02EE6C6D42DC56ULL,
		0x8904717826D51EB9ULL,
		0xBAF3E19FCBB229CCULL,
		0x19CBEB068D7C92D8ULL
	}};
	printf("Test Case 384\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 384 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -384;
	} else {
		printf("Test Case 384 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x28D1663C097CEC71ULL,
		0xEDAB24F8D2C47928ULL,
		0x3F8F628BC030C949ULL,
		0x8FB46C0B879551ACULL,
		0x19F328FAF561E5A8ULL,
		0xB8AAE45E4B8FE8C3ULL,
		0x6C5E298A2D4FCA52ULL,
		0x3722EA9E6F9E4A48ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x51A2CC7812F9D8E2ULL,
		0xDB5649F1A588F250ULL,
		0x7F1EC51780619293ULL,
		0x1F68D8170F2AA358ULL,
		0x33E651F5EAC3CB51ULL,
		0x7155C8BC971FD186ULL,
		0xD8BC53145A9F94A5ULL,
		0x6E45D53CDF3C9490ULL
	}};
	printf("Test Case 385\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 385 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -385;
	} else {
		printf("Test Case 385 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x82423399D2280BCFULL,
		0x424E3910F79BD394ULL,
		0x7E2CAB5054DAF8DFULL,
		0x074613BE61BB22CAULL,
		0xEAA5269EB975E14AULL,
		0x3ADC3E00B5C268D5ULL,
		0xDD51C3AA1EC79DA8ULL,
		0x176AC63D799044E7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x04846733A450179EULL,
		0x849C7221EF37A729ULL,
		0xFC5956A0A9B5F1BEULL,
		0x0E8C277CC3764594ULL,
		0xD54A4D3D72EBC294ULL,
		0x75B87C016B84D1ABULL,
		0xBAA387543D8F3B50ULL,
		0x2ED58C7AF32089CFULL
	}};
	printf("Test Case 386\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 386 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -386;
	} else {
		printf("Test Case 386 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4FC5489ED911D95AULL,
		0x7A63E6D2964C8C58ULL,
		0xD1F2E478EF2C4733ULL,
		0x5270C3968A2737F5ULL,
		0x39A9E52B6A4F5A1CULL,
		0xD9106776F93D6F5AULL,
		0xB94EAEAFD2FA38D8ULL,
		0x191941727FD5462AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9F8A913DB223B2B4ULL,
		0xF4C7CDA52C9918B0ULL,
		0xA3E5C8F1DE588E66ULL,
		0xA4E1872D144E6FEBULL,
		0x7353CA56D49EB438ULL,
		0xB220CEEDF27ADEB4ULL,
		0x729D5D5FA5F471B1ULL,
		0x323282E4FFAA8C55ULL
	}};
	printf("Test Case 387\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 387 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -387;
	} else {
		printf("Test Case 387 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x834DCC3FF779D388ULL,
		0x27F7C2FCBCC670E1ULL,
		0xC49F62F9B657E1D1ULL,
		0xEC3D6713A55D154CULL,
		0xEBD9CA199547F5C7ULL,
		0xCE022D0B86755439ULL,
		0xD29E78F9939D0955ULL,
		0x0A221B58933A68B1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x069B987FEEF3A710ULL,
		0x4FEF85F9798CE1C3ULL,
		0x893EC5F36CAFC3A2ULL,
		0xD87ACE274ABA2A99ULL,
		0xD7B394332A8FEB8FULL,
		0x9C045A170CEAA873ULL,
		0xA53CF1F3273A12ABULL,
		0x144436B12674D163ULL
	}};
	printf("Test Case 388\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 388 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -388;
	} else {
		printf("Test Case 388 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2BCBEC83F18F2A42ULL,
		0x5D4E378BEEC60CE5ULL,
		0x683C0687D2BFD64AULL,
		0x05D4AEB3FCAE65C6ULL,
		0x29468692F4E9D9DDULL,
		0x3A99B2104DA911DAULL,
		0x77D036BB93117027ULL,
		0x0E08102DCB227F6AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5797D907E31E5484ULL,
		0xBA9C6F17DD8C19CAULL,
		0xD0780D0FA57FAC94ULL,
		0x0BA95D67F95CCB8CULL,
		0x528D0D25E9D3B3BAULL,
		0x753364209B5223B4ULL,
		0xEFA06D772622E04EULL,
		0x1C10205B9644FED4ULL
	}};
	printf("Test Case 389\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 389 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -389;
	} else {
		printf("Test Case 389 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8DC28C215CF44A34ULL,
		0x94766B351590F2EAULL,
		0x8F4EA85A43B07AD5ULL,
		0x705D89A546D67BBEULL,
		0x7150CC699C701068ULL,
		0x458232E37403C750ULL,
		0x069490F486EB375DULL,
		0x1293BAAFAAF8E5B0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1B851842B9E89468ULL,
		0x28ECD66A2B21E5D5ULL,
		0x1E9D50B48760F5ABULL,
		0xE0BB134A8DACF77DULL,
		0xE2A198D338E020D0ULL,
		0x8B0465C6E8078EA0ULL,
		0x0D2921E90DD66EBAULL,
		0x2527755F55F1CB60ULL
	}};
	printf("Test Case 390\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 390 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -390;
	} else {
		printf("Test Case 390 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x484A9D3F068A44F1ULL,
		0xCFB7D8F5B3212E79ULL,
		0xE412E2B93915BA62ULL,
		0x04F29864846E6996ULL,
		0xB3E4612824E3831DULL,
		0xECB0CDDCD8DAB2E9ULL,
		0xC466702E7B077353ULL,
		0x1DD7B773C074A11BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x90953A7E0D1489E2ULL,
		0x9F6FB1EB66425CF2ULL,
		0xC825C572722B74C5ULL,
		0x09E530C908DCD32DULL,
		0x67C8C25049C7063AULL,
		0xD9619BB9B1B565D3ULL,
		0x88CCE05CF60EE6A7ULL,
		0x3BAF6EE780E94237ULL
	}};
	printf("Test Case 391\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 391 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -391;
	} else {
		printf("Test Case 391 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE82BC25852483FA6ULL,
		0x27DE5E7118BCC22EULL,
		0xB7445D90D2C9D687ULL,
		0x5D058E394D07C768ULL,
		0xD7AC41708E58D0F7ULL,
		0x2B897767E9D7A77BULL,
		0x99E0EB522F8276AAULL,
		0x172C950CE1151DAAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD05784B0A4907F4CULL,
		0x4FBCBCE23179845DULL,
		0x6E88BB21A593AD0EULL,
		0xBA0B1C729A0F8ED1ULL,
		0xAF5882E11CB1A1EEULL,
		0x5712EECFD3AF4EF7ULL,
		0x33C1D6A45F04ED54ULL,
		0x2E592A19C22A3B55ULL
	}};
	printf("Test Case 392\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 392 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -392;
	} else {
		printf("Test Case 392 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x879B282B2ED2DE3DULL,
		0xDE1E7BAE48AF13B1ULL,
		0x06F290C8BF0EBE96ULL,
		0x274AD69CC09A867AULL,
		0x90D12EE5424E698AULL,
		0x6E613A74B5528585ULL,
		0xD2659CF276EEF081ULL,
		0x399DD2621F6BF861ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F3650565DA5BC7AULL,
		0xBC3CF75C915E2763ULL,
		0x0DE521917E1D7D2DULL,
		0x4E95AD3981350CF4ULL,
		0x21A25DCA849CD314ULL,
		0xDCC274E96AA50B0BULL,
		0xA4CB39E4EDDDE102ULL,
		0x733BA4C43ED7F0C3ULL
	}};
	printf("Test Case 393\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 393 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -393;
	} else {
		printf("Test Case 393 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCB57381E5BC458DCULL,
		0x1B4C99BF03D16ABBULL,
		0x5F1EE851866456E1ULL,
		0x7FA6D2E5A613FE93ULL,
		0xB7FFCF74B948F99AULL,
		0x45C86E094C0727F9ULL,
		0xDBB687C063DE617EULL,
		0x2A67A08FF26C2552ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x96AE703CB788B1B8ULL,
		0x3699337E07A2D577ULL,
		0xBE3DD0A30CC8ADC2ULL,
		0xFF4DA5CB4C27FD26ULL,
		0x6FFF9EE97291F334ULL,
		0x8B90DC12980E4FF3ULL,
		0xB76D0F80C7BCC2FCULL,
		0x54CF411FE4D84AA5ULL
	}};
	printf("Test Case 394\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 394 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -394;
	} else {
		printf("Test Case 394 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x827D24C35DC57A00ULL,
		0xE5777AA14D1C388AULL,
		0x60076F903F308C6EULL,
		0x5793343539BF2B1FULL,
		0xCC87F9EC418AFDE0ULL,
		0x5251004464C7E4FCULL,
		0x7A9A4D2BFB5C52D2ULL,
		0x1DA7BDDD95CEA8E1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x04FA4986BB8AF400ULL,
		0xCAEEF5429A387115ULL,
		0xC00EDF207E6118DDULL,
		0xAF26686A737E563EULL,
		0x990FF3D88315FBC0ULL,
		0xA4A20088C98FC9F9ULL,
		0xF5349A57F6B8A5A4ULL,
		0x3B4F7BBB2B9D51C2ULL
	}};
	printf("Test Case 395\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 395 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -395;
	} else {
		printf("Test Case 395 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5EFDAD0CFC04DEF6ULL,
		0x25B525D73570BC03ULL,
		0xDD902402853F0DBCULL,
		0x4F6547CCD67872BFULL,
		0x51E4B12059BEB527ULL,
		0xF70AFDB5292F833AULL,
		0x3633F15AB25ED784ULL,
		0x03B2D68CBC5ED8E6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBDFB5A19F809BDECULL,
		0x4B6A4BAE6AE17806ULL,
		0xBB2048050A7E1B78ULL,
		0x9ECA8F99ACF0E57FULL,
		0xA3C96240B37D6A4EULL,
		0xEE15FB6A525F0674ULL,
		0x6C67E2B564BDAF09ULL,
		0x0765AD1978BDB1CCULL
	}};
	printf("Test Case 396\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 396 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -396;
	} else {
		printf("Test Case 396 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x446B3A82C8D827C7ULL,
		0x368615FEF7C5EF85ULL,
		0xC1B91D3AEAA9DC43ULL,
		0x4AEEEDE0B586B07AULL,
		0xDC79446575464C8AULL,
		0xC6276A70111329EAULL,
		0xA99E52DE8D6B51D1ULL,
		0x2B2EEE3ED526B076ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x88D6750591B04F8EULL,
		0x6D0C2BFDEF8BDF0AULL,
		0x83723A75D553B886ULL,
		0x95DDDBC16B0D60F5ULL,
		0xB8F288CAEA8C9914ULL,
		0x8C4ED4E0222653D5ULL,
		0x533CA5BD1AD6A3A3ULL,
		0x565DDC7DAA4D60EDULL
	}};
	printf("Test Case 397\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 397 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -397;
	} else {
		printf("Test Case 397 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x513C8EEE5F4EBC8AULL,
		0x7E4A52876810AEDAULL,
		0x04C0E8CB400EC158ULL,
		0xBFF5FD9EF2919193ULL,
		0xF94F1FCC17092E48ULL,
		0x869B820E24926BBAULL,
		0x53E94196D9E72C77ULL,
		0x13853C636E2E251FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA2791DDCBE9D7914ULL,
		0xFC94A50ED0215DB4ULL,
		0x0981D196801D82B0ULL,
		0x7FEBFB3DE5232326ULL,
		0xF29E3F982E125C91ULL,
		0x0D37041C4924D775ULL,
		0xA7D2832DB3CE58EFULL,
		0x270A78C6DC5C4A3EULL
	}};
	printf("Test Case 398\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 398 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -398;
	} else {
		printf("Test Case 398 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x35A0758EE4BC4536ULL,
		0xD1ED1EA582FC99E7ULL,
		0x86ADF13A8EBA9821ULL,
		0x5AC25AD8EE108E37ULL,
		0xCE0A14AFC8D1EFD8ULL,
		0x48A3E8E62C757D4AULL,
		0x8DA73C5CC40F77B9ULL,
		0x2F260944EFC57633ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6B40EB1DC9788A6CULL,
		0xA3DA3D4B05F933CEULL,
		0x0D5BE2751D753043ULL,
		0xB584B5B1DC211C6FULL,
		0x9C14295F91A3DFB0ULL,
		0x9147D1CC58EAFA95ULL,
		0x1B4E78B9881EEF72ULL,
		0x5E4C1289DF8AEC67ULL
	}};
	printf("Test Case 399\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 399 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -399;
	} else {
		printf("Test Case 399 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCD73B8A013ACA30AULL,
		0x3FA7E0B211B7310BULL,
		0x72D21EE4EA5A4F6FULL,
		0x967BE5E1A316E997ULL,
		0x23565E462F7B1DB9ULL,
		0x1086E6965CC389D0ULL,
		0x318B5772EA114D8FULL,
		0x014B0852B387ACCFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9AE7714027594614ULL,
		0x7F4FC164236E6217ULL,
		0xE5A43DC9D4B49EDEULL,
		0x2CF7CBC3462DD32EULL,
		0x46ACBC8C5EF63B73ULL,
		0x210DCD2CB98713A0ULL,
		0x6316AEE5D4229B1EULL,
		0x029610A5670F599EULL
	}};
	printf("Test Case 400\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 400 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -400;
	} else {
		printf("Test Case 400 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFD9112EE913A47F9ULL,
		0xDCE35E3CBC1C4B8EULL,
		0x37A28C190926DC45ULL,
		0x80B81C6A362D731AULL,
		0x1371990971D3CA42ULL,
		0xFCF30E256074D64DULL,
		0x998BE68E6F8DE4EBULL,
		0x261B16DC2400E0F5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFB2225DD22748FF2ULL,
		0xB9C6BC797838971DULL,
		0x6F451832124DB88BULL,
		0x017038D46C5AE634ULL,
		0x26E33212E3A79485ULL,
		0xF9E61C4AC0E9AC9AULL,
		0x3317CD1CDF1BC9D7ULL,
		0x4C362DB84801C1EBULL
	}};
	printf("Test Case 401\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 401 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -401;
	} else {
		printf("Test Case 401 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA3F77D6874F591E1ULL,
		0xB6D5828A71BDAF4DULL,
		0x7E53E08D8EA9F70DULL,
		0xEC6F52370C0C50AAULL,
		0x24052FDAD41E6D90ULL,
		0x401CB61E43230169ULL,
		0x2890E2B7AC8CE3CAULL,
		0x1B53C40690CBAC4CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x47EEFAD0E9EB23C2ULL,
		0x6DAB0514E37B5E9BULL,
		0xFCA7C11B1D53EE1BULL,
		0xD8DEA46E1818A154ULL,
		0x480A5FB5A83CDB21ULL,
		0x80396C3C864602D2ULL,
		0x5121C56F5919C794ULL,
		0x36A7880D21975898ULL
	}};
	printf("Test Case 402\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 402 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -402;
	} else {
		printf("Test Case 402 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x89CC7FEE1D8F50A3ULL,
		0x99495A57C9C13E19ULL,
		0xB18AE2A1701960FCULL,
		0x292DD7D6DA09DAB1ULL,
		0x2F458207A199E453ULL,
		0x21723041D7F837D7ULL,
		0xAD1B4185F2BFA1A0ULL,
		0x19970369A1A6F749ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1398FFDC3B1EA146ULL,
		0x3292B4AF93827C33ULL,
		0x6315C542E032C1F9ULL,
		0x525BAFADB413B563ULL,
		0x5E8B040F4333C8A6ULL,
		0x42E46083AFF06FAEULL,
		0x5A36830BE57F4340ULL,
		0x332E06D3434DEE93ULL
	}};
	printf("Test Case 403\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 403 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -403;
	} else {
		printf("Test Case 403 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x57C429DAB80776ABULL,
		0xAFF771D7AC01F57EULL,
		0x1D0125FBA21D2D1BULL,
		0x3E007518F1F9164FULL,
		0x0A9F9E2E523BFCA3ULL,
		0x4738628CF219954CULL,
		0x1CC779E239C805F0ULL,
		0x214AEF8ED97C31C4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF8853B5700EED56ULL,
		0x5FEEE3AF5803EAFCULL,
		0x3A024BF7443A5A37ULL,
		0x7C00EA31E3F22C9EULL,
		0x153F3C5CA477F946ULL,
		0x8E70C519E4332A98ULL,
		0x398EF3C473900BE0ULL,
		0x4295DF1DB2F86388ULL
	}};
	printf("Test Case 404\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 404 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -404;
	} else {
		printf("Test Case 404 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDA63EADC28825541ULL,
		0x2AA18F797FC43F8AULL,
		0x94CDDF1BFA811DEBULL,
		0x37CA7733760908B9ULL,
		0x8145BB932DEC230DULL,
		0xFEDBF9383F71B99EULL,
		0xD8E769BF09AE0AA0ULL,
		0x3BF287B262795BCCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB4C7D5B85104AA82ULL,
		0x55431EF2FF887F15ULL,
		0x299BBE37F5023BD6ULL,
		0x6F94EE66EC121173ULL,
		0x028B77265BD8461AULL,
		0xFDB7F2707EE3733DULL,
		0xB1CED37E135C1541ULL,
		0x77E50F64C4F2B799ULL
	}};
	printf("Test Case 405\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 405 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -405;
	} else {
		printf("Test Case 405 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDE0F84769F60B610ULL,
		0x23E47897586EC504ULL,
		0x6388F6AC8DEF8F08ULL,
		0xB705FB853F42779CULL,
		0x085864D84EF6E1BBULL,
		0x22D7F540D145D679ULL,
		0xAE58DBA2FBC13A4AULL,
		0x3244FB8831001745ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBC1F08ED3EC16C20ULL,
		0x47C8F12EB0DD8A09ULL,
		0xC711ED591BDF1E10ULL,
		0x6E0BF70A7E84EF38ULL,
		0x10B0C9B09DEDC377ULL,
		0x45AFEA81A28BACF2ULL,
		0x5CB1B745F7827494ULL,
		0x6489F71062002E8BULL
	}};
	printf("Test Case 406\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 406 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -406;
	} else {
		printf("Test Case 406 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x32423E922922A002ULL,
		0x825E87C5CD6EC5ECULL,
		0xD57CF3D867C1D737ULL,
		0x9788E01289C2F98AULL,
		0x5C7EC5979FFCD1E8ULL,
		0xF08A83EDC9F8FA8BULL,
		0x2B8C329EDED0FF6DULL,
		0x2FD40993A4595AD2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x64847D2452454004ULL,
		0x04BD0F8B9ADD8BD8ULL,
		0xAAF9E7B0CF83AE6FULL,
		0x2F11C0251385F315ULL,
		0xB8FD8B2F3FF9A3D1ULL,
		0xE11507DB93F1F516ULL,
		0x5718653DBDA1FEDBULL,
		0x5FA8132748B2B5A4ULL
	}};
	printf("Test Case 407\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 407 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -407;
	} else {
		printf("Test Case 407 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2079DCF89A0163D4ULL,
		0x6D84703EFA5ECC44ULL,
		0xFD322C43064D1392ULL,
		0x4FB3194769F524C1ULL,
		0x0C2C99BD5FDBF38FULL,
		0x7CAB6A555501F528ULL,
		0x383B65DC067A6D95ULL,
		0x00114B2D07836A6CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x40F3B9F13402C7A8ULL,
		0xDB08E07DF4BD9888ULL,
		0xFA6458860C9A2724ULL,
		0x9F66328ED3EA4983ULL,
		0x1859337ABFB7E71EULL,
		0xF956D4AAAA03EA50ULL,
		0x7076CBB80CF4DB2AULL,
		0x0022965A0F06D4D8ULL
	}};
	printf("Test Case 408\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 408 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -408;
	} else {
		printf("Test Case 408 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x13881A7294976CB8ULL,
		0xD066786DB9940013ULL,
		0xCEE3143C4D8029C9ULL,
		0x0D28009EDEA45F5AULL,
		0x4B9548EA9757855BULL,
		0xDD4DCC882DDEA179ULL,
		0x70FBFE2B269F3537ULL,
		0x1F99B29074B4BCABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x271034E5292ED970ULL,
		0xA0CCF0DB73280026ULL,
		0x9DC628789B005393ULL,
		0x1A50013DBD48BEB5ULL,
		0x972A91D52EAF0AB6ULL,
		0xBA9B99105BBD42F2ULL,
		0xE1F7FC564D3E6A6FULL,
		0x3F336520E9697956ULL
	}};
	printf("Test Case 409\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 409 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -409;
	} else {
		printf("Test Case 409 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE4A7AD8ED1404F66ULL,
		0x701DA28E41462CE0ULL,
		0x238FFF28741DC3C1ULL,
		0x6C35DD4AF3657C49ULL,
		0x657B3F4023A8EA56ULL,
		0x7EB9ADBF17BDA969ULL,
		0x96A579D66B414188ULL,
		0x0D5967FFE3E85CB2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC94F5B1DA2809ECCULL,
		0xE03B451C828C59C1ULL,
		0x471FFE50E83B8782ULL,
		0xD86BBA95E6CAF892ULL,
		0xCAF67E804751D4ACULL,
		0xFD735B7E2F7B52D2ULL,
		0x2D4AF3ACD6828310ULL,
		0x1AB2CFFFC7D0B965ULL
	}};
	printf("Test Case 410\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 410 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -410;
	} else {
		printf("Test Case 410 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0511597DDF597EC3ULL,
		0x9B23EB8E371548B9ULL,
		0xDE647C14BB85738FULL,
		0xB06571D90FC9D10DULL,
		0x0161B18DC9B1BEF6ULL,
		0x3E9A27D8B64EA7B4ULL,
		0x09226A7CE4FCD3B8ULL,
		0x37A1B302F0FA7DA6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0A22B2FBBEB2FD86ULL,
		0x3647D71C6E2A9172ULL,
		0xBCC8F829770AE71FULL,
		0x60CAE3B21F93A21BULL,
		0x02C3631B93637DEDULL,
		0x7D344FB16C9D4F68ULL,
		0x1244D4F9C9F9A770ULL,
		0x6F436605E1F4FB4CULL
	}};
	printf("Test Case 411\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 411 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -411;
	} else {
		printf("Test Case 411 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA2F7CFE0622CB3FDULL,
		0xAF43A21B1875CE7FULL,
		0x35B4BE9C89700090ULL,
		0x9DE227570AE6840AULL,
		0xDABA915EA7E3563BULL,
		0x26BFF10404EF386FULL,
		0xE85FEFB006DBE081ULL,
		0x0952E84AFBAB394CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x45EF9FC0C45967FAULL,
		0x5E87443630EB9CFFULL,
		0x6B697D3912E00121ULL,
		0x3BC44EAE15CD0814ULL,
		0xB57522BD4FC6AC77ULL,
		0x4D7FE20809DE70DFULL,
		0xD0BFDF600DB7C102ULL,
		0x12A5D095F7567299ULL
	}};
	printf("Test Case 412\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 412 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -412;
	} else {
		printf("Test Case 412 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD4297B6327F78224ULL,
		0xB6FE4720E6CD3650ULL,
		0x7F0C2BD30F1FC23BULL,
		0x04E014017CA4C003ULL,
		0x8BCA1821BE322332ULL,
		0x48237C1E11F5C027ULL,
		0xF63BE686213EA17EULL,
		0x0C1E9F3AD276101DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA852F6C64FEF0448ULL,
		0x6DFC8E41CD9A6CA1ULL,
		0xFE1857A61E3F8477ULL,
		0x09C02802F9498006ULL,
		0x179430437C644664ULL,
		0x9046F83C23EB804FULL,
		0xEC77CD0C427D42FCULL,
		0x183D3E75A4EC203BULL
	}};
	printf("Test Case 413\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 413 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -413;
	} else {
		printf("Test Case 413 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1398CA83576CB09DULL,
		0xE55F45906F33CAE1ULL,
		0xAF7988A1A18B3A6DULL,
		0x62A0AAA9D0B96971ULL,
		0xB850831416B54B70ULL,
		0x340A2EA6E5BABA5AULL,
		0x1BC5F199031FF741ULL,
		0x2AA27B801DAF0B31ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x27319506AED9613AULL,
		0xCABE8B20DE6795C2ULL,
		0x5EF31143431674DBULL,
		0xC5415553A172D2E3ULL,
		0x70A106282D6A96E0ULL,
		0x68145D4DCB7574B5ULL,
		0x378BE332063FEE82ULL,
		0x5544F7003B5E1662ULL
	}};
	printf("Test Case 414\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 414 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -414;
	} else {
		printf("Test Case 414 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEE3CF719C1C0268EULL,
		0xB4FBA64C5C0F90BDULL,
		0x370C4400087580B8ULL,
		0x0F393CF0A3A7FB92ULL,
		0xF7F9B1E0EE049121ULL,
		0xE29E4C7CCB36FC82ULL,
		0x336C00C80C7A27E3ULL,
		0x2CE2B1345B0ACB09ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDC79EE3383804D1CULL,
		0x69F74C98B81F217BULL,
		0x6E18880010EB0171ULL,
		0x1E7279E1474FF724ULL,
		0xEFF363C1DC092242ULL,
		0xC53C98F9966DF905ULL,
		0x66D8019018F44FC7ULL,
		0x59C56268B6159612ULL
	}};
	printf("Test Case 415\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 415 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -415;
	} else {
		printf("Test Case 415 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x48D57946C2F98EAAULL,
		0x26BBDA2862320DE2ULL,
		0x249791D28ED8CD24ULL,
		0xEB8124EEA2EFDE30ULL,
		0x32DB7B89FCD82246ULL,
		0xF7A110EEF83FBE70ULL,
		0xE8B09B308E227344ULL,
		0x2786D222E0964A30ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x91AAF28D85F31D54ULL,
		0x4D77B450C4641BC4ULL,
		0x492F23A51DB19A48ULL,
		0xD70249DD45DFBC60ULL,
		0x65B6F713F9B0448DULL,
		0xEF4221DDF07F7CE0ULL,
		0xD16136611C44E689ULL,
		0x4F0DA445C12C9461ULL
	}};
	printf("Test Case 416\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 416 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -416;
	} else {
		printf("Test Case 416 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9A407D835044813CULL,
		0x224D8543B7039550ULL,
		0x7C7330EC0A7F8070ULL,
		0xD1C0A593CDD83EECULL,
		0x92322BA412C6095BULL,
		0x23ACB6FACC357C0EULL,
		0x2001B663566422E0ULL,
		0x044A53CCCDD899DAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3480FB06A0890278ULL,
		0x449B0A876E072AA1ULL,
		0xF8E661D814FF00E0ULL,
		0xA3814B279BB07DD8ULL,
		0x24645748258C12B7ULL,
		0x47596DF5986AF81DULL,
		0x40036CC6ACC845C0ULL,
		0x0894A7999BB133B4ULL
	}};
	printf("Test Case 417\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 417 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -417;
	} else {
		printf("Test Case 417 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE20E33A19F4BA45DULL,
		0xA3E9B744C6BD1150ULL,
		0xC010F2DF954223E2ULL,
		0x95D11399AD360D41ULL,
		0x4A38B65F3680DE6FULL,
		0xE35FD91A81C6DF41ULL,
		0x0F8D5A5673AA79BDULL,
		0x273F28778E675B42ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC41C67433E9748BAULL,
		0x47D36E898D7A22A1ULL,
		0x8021E5BF2A8447C5ULL,
		0x2BA227335A6C1A83ULL,
		0x94716CBE6D01BCDFULL,
		0xC6BFB235038DBE82ULL,
		0x1F1AB4ACE754F37BULL,
		0x4E7E50EF1CCEB684ULL
	}};
	printf("Test Case 418\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 418 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -418;
	} else {
		printf("Test Case 418 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB6C966AE14E3F529ULL,
		0xE2D5A49B320F21C0ULL,
		0x72278D32C23E2164ULL,
		0x47B42C44881B1889ULL,
		0xE989C93558098631ULL,
		0xC7D7B78E937BB46DULL,
		0x9F52BC63353EF5BEULL,
		0x327A129252AE0103ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6D92CD5C29C7EA52ULL,
		0xC5AB4936641E4381ULL,
		0xE44F1A65847C42C9ULL,
		0x8F68588910363112ULL,
		0xD313926AB0130C62ULL,
		0x8FAF6F1D26F768DBULL,
		0x3EA578C66A7DEB7DULL,
		0x64F42524A55C0207ULL
	}};
	printf("Test Case 419\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 419 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -419;
	} else {
		printf("Test Case 419 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x09C8455453555883ULL,
		0x049CE8D7CE372629ULL,
		0xBBF51D9EFB9390AFULL,
		0x1E61581AFEB74F9CULL,
		0xF349245125962BBBULL,
		0x558EB26C6FDFC335ULL,
		0x47C34C1E9203A435ULL,
		0x049A9C9EED21F497ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x13908AA8A6AAB106ULL,
		0x0939D1AF9C6E4C52ULL,
		0x77EA3B3DF727215EULL,
		0x3CC2B035FD6E9F39ULL,
		0xE69248A24B2C5776ULL,
		0xAB1D64D8DFBF866BULL,
		0x8F86983D2407486AULL,
		0x0935393DDA43E92EULL
	}};
	printf("Test Case 420\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 420 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -420;
	} else {
		printf("Test Case 420 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE6934B7DD2F57E77ULL,
		0x1DB74353405FA2C2ULL,
		0xA7EEA9C4A6597083ULL,
		0xD8D4DBC683F65BD5ULL,
		0x65BAC12A4607F691ULL,
		0xAC88850E93AA84F0ULL,
		0xFC15C9962F6FD890ULL,
		0x388FD5F7E21EB029ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCD2696FBA5EAFCEEULL,
		0x3B6E86A680BF4585ULL,
		0x4FDD53894CB2E106ULL,
		0xB1A9B78D07ECB7ABULL,
		0xCB7582548C0FED23ULL,
		0x59110A1D275509E0ULL,
		0xF82B932C5EDFB121ULL,
		0x711FABEFC43D6053ULL
	}};
	printf("Test Case 421\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 421 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -421;
	} else {
		printf("Test Case 421 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x985FF5CFE546BFBCULL,
		0x55277EB299E4E57CULL,
		0x16883DF030D9AA6DULL,
		0x6A60BA993BA63237ULL,
		0xA687329FBF8201B8ULL,
		0xB8B8A9781F23B16FULL,
		0x73BC215CFDD6BBA9ULL,
		0x20B789C76502DF48ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x30BFEB9FCA8D7F78ULL,
		0xAA4EFD6533C9CAF9ULL,
		0x2D107BE061B354DAULL,
		0xD4C17532774C646EULL,
		0x4D0E653F7F040370ULL,
		0x717152F03E4762DFULL,
		0xE77842B9FBAD7753ULL,
		0x416F138ECA05BE90ULL
	}};
	printf("Test Case 422\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 422 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -422;
	} else {
		printf("Test Case 422 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC538D15C8A8304D5ULL,
		0x7E77BC8ECB23FBFCULL,
		0xE7FDFD1311D09EB0ULL,
		0xBEA8E40203811342ULL,
		0x8A55BB6C5F1169D2ULL,
		0xB61AAA8915D6776FULL,
		0xB8E46DDF23A23026ULL,
		0x0AD49234338BD744ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8A71A2B9150609AAULL,
		0xFCEF791D9647F7F9ULL,
		0xCFFBFA2623A13D60ULL,
		0x7D51C80407022685ULL,
		0x14AB76D8BE22D3A5ULL,
		0x6C3555122BACEEDFULL,
		0x71C8DBBE4744604DULL,
		0x15A924686717AE89ULL
	}};
	printf("Test Case 423\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 423 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -423;
	} else {
		printf("Test Case 423 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2EE0C8B2EC896F33ULL,
		0x067B774A7B452041ULL,
		0x2E136A18F4659243ULL,
		0xEB34E13A9DACC791ULL,
		0x32876C68581A8247ULL,
		0xD2A756D591404F64ULL,
		0xC683FC31E76ED682ULL,
		0x28D3875A848DDC56ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5DC19165D912DE66ULL,
		0x0CF6EE94F68A4082ULL,
		0x5C26D431E8CB2486ULL,
		0xD669C2753B598F22ULL,
		0x650ED8D0B035048FULL,
		0xA54EADAB22809EC8ULL,
		0x8D07F863CEDDAD05ULL,
		0x51A70EB5091BB8ADULL
	}};
	printf("Test Case 424\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 424 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -424;
	} else {
		printf("Test Case 424 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB14C76EBE4140CBEULL,
		0x81AE47CA7EA8D90EULL,
		0x5C7BE6306C430D84ULL,
		0x3FC7059D4059EDA7ULL,
		0x19066A656D61F30EULL,
		0x29F3BAE35AF98BACULL,
		0x77636F373C8C7909ULL,
		0x032723B91A773924ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6298EDD7C828197CULL,
		0x035C8F94FD51B21DULL,
		0xB8F7CC60D8861B09ULL,
		0x7F8E0B3A80B3DB4EULL,
		0x320CD4CADAC3E61CULL,
		0x53E775C6B5F31758ULL,
		0xEEC6DE6E7918F212ULL,
		0x064E477234EE7248ULL
	}};
	printf("Test Case 425\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 425 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -425;
	} else {
		printf("Test Case 425 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5C9E529AF91C574DULL,
		0x5094BD2FE5452E5FULL,
		0x73E303247628469CULL,
		0xD031620E5F946062ULL,
		0x7FE281C81A4A3083ULL,
		0x975545A5873E45F9ULL,
		0x467AD1E58C80F9AEULL,
		0x2F060B269CEB4538ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB93CA535F238AE9AULL,
		0xA1297A5FCA8A5CBEULL,
		0xE7C60648EC508D38ULL,
		0xA062C41CBF28C0C4ULL,
		0xFFC5039034946107ULL,
		0x2EAA8B4B0E7C8BF2ULL,
		0x8CF5A3CB1901F35DULL,
		0x5E0C164D39D68A70ULL
	}};
	printf("Test Case 426\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 426 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -426;
	} else {
		printf("Test Case 426 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x27F180FB866DEE03ULL,
		0x746F61E0EC8DC3D0ULL,
		0x91AA440D661C5EC8ULL,
		0x147909296D600F80ULL,
		0x86BF2D57A7262927ULL,
		0x8982D4870F94CC10ULL,
		0x42A7CF0C05C5DD44ULL,
		0x383FB9C514B0FD12ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4FE301F70CDBDC06ULL,
		0xE8DEC3C1D91B87A0ULL,
		0x2354881ACC38BD90ULL,
		0x28F21252DAC01F01ULL,
		0x0D7E5AAF4E4C524EULL,
		0x1305A90E1F299821ULL,
		0x854F9E180B8BBA89ULL,
		0x707F738A2961FA24ULL
	}};
	printf("Test Case 427\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 427 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -427;
	} else {
		printf("Test Case 427 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2A0FB5E0617A0C2EULL,
		0xBFA2629C9E617300ULL,
		0xA0401842F2BCDC8EULL,
		0x713130B93D7180B1ULL,
		0x5AC633FFF710C81AULL,
		0x5745E9BDE6BB7874ULL,
		0x27C9C4970D741F73ULL,
		0x1C3C1C0D683533F7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x541F6BC0C2F4185CULL,
		0x7F44C5393CC2E600ULL,
		0x40803085E579B91DULL,
		0xE26261727AE30163ULL,
		0xB58C67FFEE219034ULL,
		0xAE8BD37BCD76F0E8ULL,
		0x4F93892E1AE83EE6ULL,
		0x3878381AD06A67EEULL
	}};
	printf("Test Case 428\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 428 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -428;
	} else {
		printf("Test Case 428 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC6B1F2F8D00D35CAULL,
		0x381E01A5E720D27FULL,
		0x8839653CCA19FB94ULL,
		0x8ED732E36D893649ULL,
		0xBA8FD1B9CC893FBFULL,
		0x1D07EA1BD5105B7BULL,
		0x7831F644E7185C79ULL,
		0x13592D21F2CDC8F6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8D63E5F1A01A6B94ULL,
		0x703C034BCE41A4FFULL,
		0x1072CA799433F728ULL,
		0x1DAE65C6DB126C93ULL,
		0x751FA37399127F7FULL,
		0x3A0FD437AA20B6F7ULL,
		0xF063EC89CE30B8F2ULL,
		0x26B25A43E59B91ECULL
	}};
	printf("Test Case 429\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 429 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -429;
	} else {
		printf("Test Case 429 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD2B6647E1D6DF0D7ULL,
		0x2D9D93E9157089AAULL,
		0x77BE2D87E6D4A711ULL,
		0x7185CBE8DC64FC33ULL,
		0xFDD84B1B0753EB8BULL,
		0x2FBDC4D6E14AB46DULL,
		0xD1FB684B752D272FULL,
		0x26024B95322D90C8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA56CC8FC3ADBE1AEULL,
		0x5B3B27D22AE11355ULL,
		0xEF7C5B0FCDA94E22ULL,
		0xE30B97D1B8C9F866ULL,
		0xFBB096360EA7D716ULL,
		0x5F7B89ADC29568DBULL,
		0xA3F6D096EA5A4E5EULL,
		0x4C04972A645B2191ULL
	}};
	printf("Test Case 430\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 430 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -430;
	} else {
		printf("Test Case 430 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC577D441F5C4A18DULL,
		0x370D44B4BC150A49ULL,
		0x3FBFA06202EA53C9ULL,
		0xAB7BA9C1D976FE78ULL,
		0x0ED8812B5DD9060BULL,
		0x0D42B5D693A89FC2ULL,
		0x8AD6A68138B02F11ULL,
		0x1302B6EDC4AF1E3CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8AEFA883EB89431AULL,
		0x6E1A8969782A1493ULL,
		0x7F7F40C405D4A792ULL,
		0x56F75383B2EDFCF0ULL,
		0x1DB10256BBB20C17ULL,
		0x1A856BAD27513F84ULL,
		0x15AD4D0271605E22ULL,
		0x26056DDB895E3C79ULL
	}};
	printf("Test Case 431\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 431 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -431;
	} else {
		printf("Test Case 431 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA3E4B35167F8A772ULL,
		0xD5EE5E57ABA46FC4ULL,
		0x655D7786A145E380ULL,
		0x6574926A98BF87B6ULL,
		0x74117B20C35E6324ULL,
		0xA601C05281D0FF6FULL,
		0x72AD50860EEF9ED6ULL,
		0x08F52DAFE76EB055ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x47C966A2CFF14EE4ULL,
		0xABDCBCAF5748DF89ULL,
		0xCABAEF0D428BC701ULL,
		0xCAE924D5317F0F6CULL,
		0xE822F64186BCC648ULL,
		0x4C0380A503A1FEDEULL,
		0xE55AA10C1DDF3DADULL,
		0x11EA5B5FCEDD60AAULL
	}};
	printf("Test Case 432\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 432 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -432;
	} else {
		printf("Test Case 432 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x755B342323C4C4E1ULL,
		0x8B5260302A719AC8ULL,
		0xAB7C5C9EB3897DB5ULL,
		0x279A03E952227A69ULL,
		0x423B59348D979612ULL,
		0x505CF8A03F89A47FULL,
		0x0767CDCE967C3257ULL,
		0x11537D84EC212816ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEAB66846478989C2ULL,
		0x16A4C06054E33590ULL,
		0x56F8B93D6712FB6BULL,
		0x4F3407D2A444F4D3ULL,
		0x8476B2691B2F2C24ULL,
		0xA0B9F1407F1348FEULL,
		0x0ECF9B9D2CF864AEULL,
		0x22A6FB09D842502CULL
	}};
	printf("Test Case 433\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 433 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -433;
	} else {
		printf("Test Case 433 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x799C9A20BCF6F6EDULL,
		0x040AB14CC3FE9431ULL,
		0xF564E645547FADB1ULL,
		0xB494952F1DF92A26ULL,
		0x7F4FC0442EBA19A2ULL,
		0x2CA4EBFC3F7DEE35ULL,
		0xFB79111C2FB57BE8ULL,
		0x02572BF62A47ECF6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF339344179EDEDDAULL,
		0x0815629987FD2862ULL,
		0xEAC9CC8AA8FF5B62ULL,
		0x69292A5E3BF2544DULL,
		0xFE9F80885D743345ULL,
		0x5949D7F87EFBDC6AULL,
		0xF6F222385F6AF7D0ULL,
		0x04AE57EC548FD9EDULL
	}};
	printf("Test Case 434\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 434 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -434;
	} else {
		printf("Test Case 434 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x46E4F309A4F3A54BULL,
		0x78130B3EDDCEFB4EULL,
		0x4F63EADD641A3BECULL,
		0x682E42BAFF08F4B6ULL,
		0x39D7CDA57D20B99BULL,
		0x8F5908C6C72B548BULL,
		0x068E53487F6C0C74ULL,
		0x176E11F59E1765A8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8DC9E61349E74A96ULL,
		0xF026167DBB9DF69CULL,
		0x9EC7D5BAC83477D8ULL,
		0xD05C8575FE11E96CULL,
		0x73AF9B4AFA417336ULL,
		0x1EB2118D8E56A916ULL,
		0x0D1CA690FED818E9ULL,
		0x2EDC23EB3C2ECB50ULL
	}};
	printf("Test Case 435\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 435 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -435;
	} else {
		printf("Test Case 435 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x285EA3CA8809F014ULL,
		0x9102499934A35B97ULL,
		0xA6D9C0FE6313DDFFULL,
		0x4C191C396921AF97ULL,
		0x89DCE1FE59F0EB53ULL,
		0x9A506400D852B2E0ULL,
		0x2BDA46478161DE33ULL,
		0x175619CB2EAFE5DFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x50BD47951013E028ULL,
		0x220493326946B72EULL,
		0x4DB381FCC627BBFFULL,
		0x98323872D2435F2FULL,
		0x13B9C3FCB3E1D6A6ULL,
		0x34A0C801B0A565C1ULL,
		0x57B48C8F02C3BC67ULL,
		0x2EAC33965D5FCBBEULL
	}};
	printf("Test Case 436\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 436 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -436;
	} else {
		printf("Test Case 436 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBAC8521CF7BF9005ULL,
		0xEAFFD5EE26E39891ULL,
		0x1B1C74A8B70EE5ECULL,
		0xE4265688E8E548DBULL,
		0xA4B2FB080D20C7E2ULL,
		0x2021FA997AE2B98DULL,
		0x787E564FB62F928DULL,
		0x32BC840F4928E441ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7590A439EF7F200AULL,
		0xD5FFABDC4DC73123ULL,
		0x3638E9516E1DCBD9ULL,
		0xC84CAD11D1CA91B6ULL,
		0x4965F6101A418FC5ULL,
		0x4043F532F5C5731BULL,
		0xF0FCAC9F6C5F251AULL,
		0x6579081E9251C882ULL
	}};
	printf("Test Case 437\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 437 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -437;
	} else {
		printf("Test Case 437 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x85D3F27E63575EC0ULL,
		0xE980A73F7C4C28B2ULL,
		0x7609350BEEA214AAULL,
		0x1299E943E5887182ULL,
		0xCED35DA59E10E987ULL,
		0xC26EFE4EC9A62579ULL,
		0x245F610BD2C3B6A3ULL,
		0x27EE30C10BBC4848ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0BA7E4FCC6AEBD80ULL,
		0xD3014E7EF8985165ULL,
		0xEC126A17DD442955ULL,
		0x2533D287CB10E304ULL,
		0x9DA6BB4B3C21D30EULL,
		0x84DDFC9D934C4AF3ULL,
		0x48BEC217A5876D47ULL,
		0x4FDC618217789090ULL
	}};
	printf("Test Case 438\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 438 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -438;
	} else {
		printf("Test Case 438 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x699F2421723ABCA8ULL,
		0x9A12A0CA4F73A50BULL,
		0x50DFE6BA6C3681D4ULL,
		0x2127AC2E017EBA01ULL,
		0x9D3DF8C762B31342ULL,
		0x9DB6C1377A596861ULL,
		0x81D374F148CA42D7ULL,
		0x16BB0722602DB815ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD33E4842E4757950ULL,
		0x342541949EE74A16ULL,
		0xA1BFCD74D86D03A9ULL,
		0x424F585C02FD7402ULL,
		0x3A7BF18EC5662684ULL,
		0x3B6D826EF4B2D0C3ULL,
		0x03A6E9E2919485AFULL,
		0x2D760E44C05B702BULL
	}};
	printf("Test Case 439\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 439 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -439;
	} else {
		printf("Test Case 439 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCE413E2DF1D1B8DEULL,
		0x90ABF66F0F7E7B9CULL,
		0x4AFA6BF17BCB47F7ULL,
		0x72AB746EAF5458B4ULL,
		0xA5982DC9D35CB0A1ULL,
		0xEA21665457D4BF3BULL,
		0x8EB6BB688031B203ULL,
		0x11DCBB5D82BED3E3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9C827C5BE3A371BCULL,
		0x2157ECDE1EFCF739ULL,
		0x95F4D7E2F7968FEFULL,
		0xE556E8DD5EA8B168ULL,
		0x4B305B93A6B96142ULL,
		0xD442CCA8AFA97E77ULL,
		0x1D6D76D100636407ULL,
		0x23B976BB057DA7C7ULL
	}};
	printf("Test Case 440\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 440 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -440;
	} else {
		printf("Test Case 440 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8B5DD1C4DCABCD92ULL,
		0x43603CD3E09254AEULL,
		0x8CBBBA494EE1D43AULL,
		0xB47B96936BCB9B9FULL,
		0x3C59DB5E15CCE2B9ULL,
		0x02E5A92A02DCAE85ULL,
		0x5916000F2336A1F5ULL,
		0x270D7D64BA60F853ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x16BBA389B9579B24ULL,
		0x86C079A7C124A95DULL,
		0x197774929DC3A874ULL,
		0x68F72D26D797373FULL,
		0x78B3B6BC2B99C573ULL,
		0x05CB525405B95D0AULL,
		0xB22C001E466D43EAULL,
		0x4E1AFAC974C1F0A6ULL
	}};
	printf("Test Case 441\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 441 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -441;
	} else {
		printf("Test Case 441 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x50D58736717EA874ULL,
		0x9910B0C91FCE92D0ULL,
		0xEC0BB54383873D6AULL,
		0xF15F172C32BC3F1CULL,
		0xC39D965E272A5DBAULL,
		0xEBB46074C780F112ULL,
		0x7845AD12752E48EDULL,
		0x34276B37713FC6FAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA1AB0E6CE2FD50E8ULL,
		0x322161923F9D25A0ULL,
		0xD8176A87070E7AD5ULL,
		0xE2BE2E5865787E39ULL,
		0x873B2CBC4E54BB75ULL,
		0xD768C0E98F01E225ULL,
		0xF08B5A24EA5C91DBULL,
		0x684ED66EE27F8DF4ULL
	}};
	printf("Test Case 442\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 442 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -442;
	} else {
		printf("Test Case 442 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9ADD28BBAFE60500ULL,
		0x8FA110A626D1C02AULL,
		0x3A5D8931D55D6B9EULL,
		0x7FAF0BAFAB383C20ULL,
		0xA6DFA0F9E66B65E5ULL,
		0x0D88BFF71D137F33ULL,
		0xE75DC5ACE01A6CB5ULL,
		0x22B4C43ECCE39812ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x35BA51775FCC0A00ULL,
		0x1F42214C4DA38055ULL,
		0x74BB1263AABAD73DULL,
		0xFF5E175F56707840ULL,
		0x4DBF41F3CCD6CBCAULL,
		0x1B117FEE3A26FE67ULL,
		0xCEBB8B59C034D96AULL,
		0x4569887D99C73025ULL
	}};
	printf("Test Case 443\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 443 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -443;
	} else {
		printf("Test Case 443 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5D7BCFE61EB310C6ULL,
		0x7FE2DC58623029F9ULL,
		0xF5B7828FD7EA903DULL,
		0x22659F8667C2AC5EULL,
		0x6B2BCF08E3D960B6ULL,
		0x22F9230D5D290204ULL,
		0x82BD8CF0D9D75912ULL,
		0x256149F85D0B532FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBAF79FCC3D66218CULL,
		0xFFC5B8B0C46053F2ULL,
		0xEB6F051FAFD5207AULL,
		0x44CB3F0CCF8558BDULL,
		0xD6579E11C7B2C16CULL,
		0x45F2461ABA520408ULL,
		0x057B19E1B3AEB224ULL,
		0x4AC293F0BA16A65FULL
	}};
	printf("Test Case 444\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 444 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -444;
	} else {
		printf("Test Case 444 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7CFF8F330F79DB51ULL,
		0x5B5AB59A373DF167ULL,
		0x612F10219C5771E7ULL,
		0x10FFFA86B7BE9EBAULL,
		0x417BF4266CF2B656ULL,
		0x654DA6F3C8871284ULL,
		0x2C33DCE6AF56091BULL,
		0x04972D514AEF8646ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF9FF1E661EF3B6A2ULL,
		0xB6B56B346E7BE2CEULL,
		0xC25E204338AEE3CEULL,
		0x21FFF50D6F7D3D74ULL,
		0x82F7E84CD9E56CACULL,
		0xCA9B4DE7910E2508ULL,
		0x5867B9CD5EAC1236ULL,
		0x092E5AA295DF0C8CULL
	}};
	printf("Test Case 445\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 445 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -445;
	} else {
		printf("Test Case 445 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x855AAD9333A04414ULL,
		0xC9437A7F425E0A43ULL,
		0xEF14BADC649C3545ULL,
		0x25D69C6F0EB9A333ULL,
		0x275CD174DBE2116DULL,
		0x72283F5557654580ULL,
		0x63D50F0C20C04F6AULL,
		0x3F7C956E1B8FAFBDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0AB55B2667408828ULL,
		0x9286F4FE84BC1487ULL,
		0xDE2975B8C9386A8BULL,
		0x4BAD38DE1D734667ULL,
		0x4EB9A2E9B7C422DAULL,
		0xE4507EAAAECA8B00ULL,
		0xC7AA1E1841809ED4ULL,
		0x7EF92ADC371F5F7AULL
	}};
	printf("Test Case 446\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 446 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -446;
	} else {
		printf("Test Case 446 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x33023DAE78D881E8ULL,
		0xB5FA482EE659C7B1ULL,
		0xEB2BCD89928CB0D8ULL,
		0x5FC088DB04FE1B07ULL,
		0x2F9A8D337D3509D7ULL,
		0xBAF75846169D1D9EULL,
		0x94E35A63FFC8B721ULL,
		0x0045C8D25A1D65A3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x66047B5CF1B103D0ULL,
		0x6BF4905DCCB38F62ULL,
		0xD6579B13251961B1ULL,
		0xBF8111B609FC360FULL,
		0x5F351A66FA6A13AEULL,
		0x75EEB08C2D3A3B3CULL,
		0x29C6B4C7FF916E43ULL,
		0x008B91A4B43ACB47ULL
	}};
	printf("Test Case 447\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 447 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -447;
	} else {
		printf("Test Case 447 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0A33CE601D95E03AULL,
		0x3C8316ADE5E1E502ULL,
		0xD6456CAF325C7A12ULL,
		0xD70D7CAA043C10E2ULL,
		0x10FD7DE0C7E56622ULL,
		0xE74B9196E96C2B7CULL,
		0x46E114580F9F083AULL,
		0x3B108EC315940E55ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x14679CC03B2BC074ULL,
		0x79062D5BCBC3CA04ULL,
		0xAC8AD95E64B8F424ULL,
		0xAE1AF954087821C5ULL,
		0x21FAFBC18FCACC45ULL,
		0xCE97232DD2D856F8ULL,
		0x8DC228B01F3E1075ULL,
		0x76211D862B281CAAULL
	}};
	printf("Test Case 448\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 448 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -448;
	} else {
		printf("Test Case 448 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x044AF56D1CEBEB6BULL,
		0xD2B6663916CFA270ULL,
		0x335044A1F3F37569ULL,
		0xC4549AE8A9FF38EFULL,
		0x6E8D27141A84BC62ULL,
		0xA49E765827D17944ULL,
		0x4F5881FAADC27B5FULL,
		0x33D40D3EAE7D15D4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0895EADA39D7D6D6ULL,
		0xA56CCC722D9F44E0ULL,
		0x66A08943E7E6EAD3ULL,
		0x88A935D153FE71DEULL,
		0xDD1A4E28350978C5ULL,
		0x493CECB04FA2F288ULL,
		0x9EB103F55B84F6BFULL,
		0x67A81A7D5CFA2BA8ULL
	}};
	printf("Test Case 449\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 449 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -449;
	} else {
		printf("Test Case 449 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7D80A2F35200C637ULL,
		0xD207C4E9974D1703ULL,
		0xD48D426A3257C1CEULL,
		0x919503938D854511ULL,
		0x5C6A1B5FF8F38F97ULL,
		0xF5DDB4DB2B0CD90AULL,
		0x1583C5582E45244BULL,
		0x0B21CA0E6256BA5DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFB0145E6A4018C6EULL,
		0xA40F89D32E9A2E06ULL,
		0xA91A84D464AF839DULL,
		0x232A07271B0A8A23ULL,
		0xB8D436BFF1E71F2FULL,
		0xEBBB69B65619B214ULL,
		0x2B078AB05C8A4897ULL,
		0x1643941CC4AD74BAULL
	}};
	printf("Test Case 450\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 450 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -450;
	} else {
		printf("Test Case 450 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2CE719FC5C04DD5EULL,
		0x723E91036633FDD0ULL,
		0x58C31DC9971E5CD1ULL,
		0x530D33CDF3DFFA71ULL,
		0xD81D8D4F3E4A874CULL,
		0xE4A860DB023C4ED2ULL,
		0xCD51AB7BDDD3930AULL,
		0x2296830FE0620234ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x59CE33F8B809BABCULL,
		0xE47D2206CC67FBA0ULL,
		0xB1863B932E3CB9A2ULL,
		0xA61A679BE7BFF4E2ULL,
		0xB03B1A9E7C950E98ULL,
		0xC950C1B604789DA5ULL,
		0x9AA356F7BBA72615ULL,
		0x452D061FC0C40469ULL
	}};
	printf("Test Case 451\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 451 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -451;
	} else {
		printf("Test Case 451 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x562C3CB18A60F5BCULL,
		0x74CA13900C7A1113ULL,
		0x49FBD783B551E056ULL,
		0xE1443C8C18ECFDB8ULL,
		0xD9915D60340A2C22ULL,
		0x2031FED713C08ED7ULL,
		0x69253F197BEB0826ULL,
		0x2D22DE56CEFEF810ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAC58796314C1EB78ULL,
		0xE994272018F42226ULL,
		0x93F7AF076AA3C0ACULL,
		0xC288791831D9FB70ULL,
		0xB322BAC068145845ULL,
		0x4063FDAE27811DAFULL,
		0xD24A7E32F7D6104CULL,
		0x5A45BCAD9DFDF020ULL
	}};
	printf("Test Case 452\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 452 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -452;
	} else {
		printf("Test Case 452 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x731B02FEB4B81B40ULL,
		0x99B1FBC479E45533ULL,
		0x5D687AE20D56916CULL,
		0x12CCF90D9FED0DBCULL,
		0x5506A385B5DDC97AULL,
		0xB46269FCB90C27BFULL,
		0x83DF11E44A70BBE9ULL,
		0x19D7DFF388AA2EE1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE63605FD69703680ULL,
		0x3363F788F3C8AA66ULL,
		0xBAD0F5C41AAD22D9ULL,
		0x2599F21B3FDA1B78ULL,
		0xAA0D470B6BBB92F4ULL,
		0x68C4D3F972184F7EULL,
		0x07BE23C894E177D3ULL,
		0x33AFBFE711545DC3ULL
	}};
	printf("Test Case 453\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 453 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -453;
	} else {
		printf("Test Case 453 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4668CA92368A1AECULL,
		0xC875ABECBF77BCD5ULL,
		0xDEDE0FC0C1229C9DULL,
		0xD2D310E1C1E7E56AULL,
		0x9724004FA1619298ULL,
		0xAC5B75178510672DULL,
		0x681C5BA556E7E696ULL,
		0x0F9A91E7E8023E05ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8CD195246D1435D8ULL,
		0x90EB57D97EEF79AAULL,
		0xBDBC1F818245393BULL,
		0xA5A621C383CFCAD5ULL,
		0x2E48009F42C32531ULL,
		0x58B6EA2F0A20CE5BULL,
		0xD038B74AADCFCD2DULL,
		0x1F3523CFD0047C0AULL
	}};
	printf("Test Case 454\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 454 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -454;
	} else {
		printf("Test Case 454 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9E6687E2300588F4ULL,
		0x3C1E733F4A79B33DULL,
		0x93A266AE3D4EF8B2ULL,
		0x8D8BB6584E7C645AULL,
		0xE7B69036BC13603CULL,
		0x63E3331D98779FDAULL,
		0xD58D5252E724F80FULL,
		0x1FC96549732B631EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3CCD0FC4600B11E8ULL,
		0x783CE67E94F3667BULL,
		0x2744CD5C7A9DF164ULL,
		0x1B176CB09CF8C8B5ULL,
		0xCF6D206D7826C079ULL,
		0xC7C6663B30EF3FB5ULL,
		0xAB1AA4A5CE49F01EULL,
		0x3F92CA92E656C63DULL
	}};
	printf("Test Case 455\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 455 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -455;
	} else {
		printf("Test Case 455 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF87F109C4FEF99B1ULL,
		0x021FB9521F9AB2DBULL,
		0x23CB2AD5F1CD91C1ULL,
		0xDF89815563274B3CULL,
		0xA4E4DDCBFD072BDDULL,
		0x3E0C3C0FAEBF7B9CULL,
		0x93E04D1552EF55F3ULL,
		0x08F54207992EA52EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF0FE21389FDF3362ULL,
		0x043F72A43F3565B7ULL,
		0x479655ABE39B2382ULL,
		0xBF1302AAC64E9678ULL,
		0x49C9BB97FA0E57BBULL,
		0x7C18781F5D7EF739ULL,
		0x27C09A2AA5DEABE6ULL,
		0x11EA840F325D4A5DULL
	}};
	printf("Test Case 456\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 456 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -456;
	} else {
		printf("Test Case 456 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x440C4609971F0E9CULL,
		0xE5BB384E9BA9C907ULL,
		0xBCCBF4AAB18157C1ULL,
		0xA1444EBF7EF77B8CULL,
		0x8565042F0F4DC25DULL,
		0x51E4DA244606712AULL,
		0x0BDED22D7BB9A373ULL,
		0x08B1E012CAAEF5CFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x88188C132E3E1D38ULL,
		0xCB76709D3753920EULL,
		0x7997E9556302AF83ULL,
		0x42889D7EFDEEF719ULL,
		0x0ACA085E1E9B84BBULL,
		0xA3C9B4488C0CE255ULL,
		0x17BDA45AF77346E6ULL,
		0x1163C025955DEB9EULL
	}};
	printf("Test Case 457\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 457 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -457;
	} else {
		printf("Test Case 457 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x373E40849C2E3BFEULL,
		0x4544560E6AD2EF6CULL,
		0xC44949A912AC580EULL,
		0x010D9414DF85779CULL,
		0x902480778D89C5A2ULL,
		0xC747DCE0D9725EBEULL,
		0x7C59BDC5C74DE40AULL,
		0x0F88B4D14F1B086DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6E7C8109385C77FCULL,
		0x8A88AC1CD5A5DED8ULL,
		0x889293522558B01CULL,
		0x021B2829BF0AEF39ULL,
		0x204900EF1B138B44ULL,
		0x8E8FB9C1B2E4BD7DULL,
		0xF8B37B8B8E9BC815ULL,
		0x1F1169A29E3610DAULL
	}};
	printf("Test Case 458\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 458 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -458;
	} else {
		printf("Test Case 458 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB53E5FB91C9F1422ULL,
		0xF64202FAB1C52609ULL,
		0xAD7596E4D0554568ULL,
		0x62F6BFE99D979E21ULL,
		0x6604A37C9DE1A393ULL,
		0xB1764C2D2A5E1320ULL,
		0x6EDF5C74E0EEDE7DULL,
		0x297452C5BED89366ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6A7CBF72393E2844ULL,
		0xEC8405F5638A4C13ULL,
		0x5AEB2DC9A0AA8AD1ULL,
		0xC5ED7FD33B2F3C43ULL,
		0xCC0946F93BC34726ULL,
		0x62EC985A54BC2640ULL,
		0xDDBEB8E9C1DDBCFBULL,
		0x52E8A58B7DB126CCULL
	}};
	printf("Test Case 459\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 459 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -459;
	} else {
		printf("Test Case 459 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD7DAB8681ACE7C75ULL,
		0xB9147A3AC8522C5AULL,
		0x6E3F74CF4450F00EULL,
		0xFC23A4E2557F7749ULL,
		0x4E80E7B07AED37C9ULL,
		0xE0BD86DF812E3E0EULL,
		0xB3B91160D402122AULL,
		0x199F746E09361773ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAFB570D0359CF8EAULL,
		0x7228F47590A458B5ULL,
		0xDC7EE99E88A1E01DULL,
		0xF84749C4AAFEEE92ULL,
		0x9D01CF60F5DA6F93ULL,
		0xC17B0DBF025C7C1CULL,
		0x677222C1A8042455ULL,
		0x333EE8DC126C2EE7ULL
	}};
	printf("Test Case 460\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 460 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -460;
	} else {
		printf("Test Case 460 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB65C840BD176BE48ULL,
		0xB1C85441CC0865B1ULL,
		0xEE7DEE57459FFDE9ULL,
		0xF1547E4B5CFA022EULL,
		0x17A6CD42E530DB59ULL,
		0x8D4342A42BF983FEULL,
		0x75AC6656D0B535A8ULL,
		0x0020FCF05F680A74ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6CB90817A2ED7C90ULL,
		0x6390A8839810CB63ULL,
		0xDCFBDCAE8B3FFBD3ULL,
		0xE2A8FC96B9F4045DULL,
		0x2F4D9A85CA61B6B3ULL,
		0x1A86854857F307FCULL,
		0xEB58CCADA16A6B51ULL,
		0x0041F9E0BED014E8ULL
	}};
	printf("Test Case 461\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 461 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -461;
	} else {
		printf("Test Case 461 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x70A413DEEA0B3150ULL,
		0x20F9464A05D09732ULL,
		0xEACED2D1A1C43FEBULL,
		0x3A1C17C0C3DD24AEULL,
		0x7C94E60C3C69C698ULL,
		0x40C76A0D556EAB3CULL,
		0x576A80AEF3EE1D57ULL,
		0x05521563362BA50DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE14827BDD41662A0ULL,
		0x41F28C940BA12E64ULL,
		0xD59DA5A343887FD6ULL,
		0x74382F8187BA495DULL,
		0xF929CC1878D38D30ULL,
		0x818ED41AAADD5678ULL,
		0xAED5015DE7DC3AAEULL,
		0x0AA42AC66C574A1AULL
	}};
	printf("Test Case 462\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 462 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -462;
	} else {
		printf("Test Case 462 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDE9F52960A7EF333ULL,
		0xD1BF5B13F9DAB002ULL,
		0xA4CA17454679E566ULL,
		0x2DD1EDC837ECBA1DULL,
		0x0C40691A2EA3E3F9ULL,
		0x320260E63D9208A7ULL,
		0x11B8F72454C55E47ULL,
		0x1869079659C53F53ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBD3EA52C14FDE666ULL,
		0xA37EB627F3B56005ULL,
		0x49942E8A8CF3CACDULL,
		0x5BA3DB906FD9743BULL,
		0x1880D2345D47C7F2ULL,
		0x6404C1CC7B24114EULL,
		0x2371EE48A98ABC8EULL,
		0x30D20F2CB38A7EA6ULL
	}};
	printf("Test Case 463\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 463 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -463;
	} else {
		printf("Test Case 463 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAFB78ABDFC4F792AULL,
		0xA49455D8E23F4433ULL,
		0x0A7F82D7C6DBE87BULL,
		0x87980D16526778C7ULL,
		0x939FC89EF802A312ULL,
		0x7CE59D07763E32BFULL,
		0x899922330CB57A96ULL,
		0x35C1AED5F30E7686ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5F6F157BF89EF254ULL,
		0x4928ABB1C47E8867ULL,
		0x14FF05AF8DB7D0F7ULL,
		0x0F301A2CA4CEF18EULL,
		0x273F913DF0054625ULL,
		0xF9CB3A0EEC7C657FULL,
		0x13324466196AF52CULL,
		0x6B835DABE61CED0DULL
	}};
	printf("Test Case 464\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 464 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -464;
	} else {
		printf("Test Case 464 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD82A8B8C9D7988F8ULL,
		0xAAD05DA99738C79BULL,
		0xA280B6FF873E1CADULL,
		0x44AF5775C8761410ULL,
		0xAB95D3F8F49C75C6ULL,
		0xFA49FA8B672447B6ULL,
		0x7C0E3596B4C4CA84ULL,
		0x045D3DA9B10EC435ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB05517193AF311F0ULL,
		0x55A0BB532E718F37ULL,
		0x45016DFF0E7C395BULL,
		0x895EAEEB90EC2821ULL,
		0x572BA7F1E938EB8CULL,
		0xF493F516CE488F6DULL,
		0xF81C6B2D69899509ULL,
		0x08BA7B53621D886AULL
	}};
	printf("Test Case 465\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 465 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -465;
	} else {
		printf("Test Case 465 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x28E505E5114DEC76ULL,
		0xFDB86F64E593B573ULL,
		0xB7F6019CB4A7D8A9ULL,
		0xC6A41015933E54FFULL,
		0x0DA61719911A5BC7ULL,
		0xCE5804A5215C6E39ULL,
		0x7D7831AF26CE116CULL,
		0x3B537BBF77FCCCB0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x51CA0BCA229BD8ECULL,
		0xFB70DEC9CB276AE6ULL,
		0x6FEC0339694FB153ULL,
		0x8D48202B267CA9FFULL,
		0x1B4C2E332234B78FULL,
		0x9CB0094A42B8DC72ULL,
		0xFAF0635E4D9C22D9ULL,
		0x76A6F77EEFF99960ULL
	}};
	printf("Test Case 466\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 466 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -466;
	} else {
		printf("Test Case 466 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD4E270DB9ED0A595ULL,
		0xEA5181E3685AE09CULL,
		0x4D57C6A9CDE0F4A0ULL,
		0x2904425E0E99807DULL,
		0x3FCB2491FA5DC541ULL,
		0xE22CDB11BC55359DULL,
		0xB868CF9B515EE828ULL,
		0x06159FF1BECFA8DBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA9C4E1B73DA14B2AULL,
		0xD4A303C6D0B5C139ULL,
		0x9AAF8D539BC1E941ULL,
		0x520884BC1D3300FAULL,
		0x7F964923F4BB8A82ULL,
		0xC459B62378AA6B3AULL,
		0x70D19F36A2BDD051ULL,
		0x0C2B3FE37D9F51B7ULL
	}};
	printf("Test Case 467\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 467 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -467;
	} else {
		printf("Test Case 467 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x68F2FBA5DAB2B315ULL,
		0x1C6765174FA21AA3ULL,
		0x21E16525B028181BULL,
		0x4DDEE9E5C84CA380ULL,
		0xF720F20482F8768DULL,
		0x7D90DABB5531467DULL,
		0x3D5F825C4591058FULL,
		0x19141C3F1673887AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD1E5F74BB565662AULL,
		0x38CECA2E9F443546ULL,
		0x43C2CA4B60503036ULL,
		0x9BBDD3CB90994700ULL,
		0xEE41E40905F0ED1AULL,
		0xFB21B576AA628CFBULL,
		0x7ABF04B88B220B1EULL,
		0x3228387E2CE710F4ULL
	}};
	printf("Test Case 468\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 468 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -468;
	} else {
		printf("Test Case 468 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x117AAEE948B36F27ULL,
		0x39EB3994FDFF9ABDULL,
		0x43399C78E7399981ULL,
		0x429FF2E0E2C4EF0DULL,
		0x52B1DDFFEA477BA1ULL,
		0xFA1120C7E97B24B8ULL,
		0x89136562F053C3DCULL,
		0x1B119F381837690AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x22F55DD29166DE4EULL,
		0x73D67329FBFF357AULL,
		0x867338F1CE733302ULL,
		0x853FE5C1C589DE1AULL,
		0xA563BBFFD48EF742ULL,
		0xF422418FD2F64970ULL,
		0x1226CAC5E0A787B9ULL,
		0x36233E70306ED215ULL
	}};
	printf("Test Case 469\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 469 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -469;
	} else {
		printf("Test Case 469 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4D28AF38A31C2D31ULL,
		0x2656D6A65AE4452CULL,
		0x8F1D0EE166B474E1ULL,
		0x263C51C3E657240FULL,
		0x3E469CB99F3D94AFULL,
		0xB6DD91BC17F9C98AULL,
		0x2437AB750ABD6C0EULL,
		0x04E5FBA85B866C37ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9A515E7146385A62ULL,
		0x4CADAD4CB5C88A58ULL,
		0x1E3A1DC2CD68E9C2ULL,
		0x4C78A387CCAE481FULL,
		0x7C8D39733E7B295EULL,
		0x6DBB23782FF39314ULL,
		0x486F56EA157AD81DULL,
		0x09CBF750B70CD86EULL
	}};
	printf("Test Case 470\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 470 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -470;
	} else {
		printf("Test Case 470 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x846A3CE09997BF15ULL,
		0xB9A3B49B64B96550ULL,
		0x2F7A70BFA294DC87ULL,
		0x1745DE00DDE1CB4AULL,
		0x60EEA20EDCD256BEULL,
		0x8D1680741502E3C7ULL,
		0x28F59A982D38A16EULL,
		0x1B197123532495B0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x08D479C1332F7E2AULL,
		0x73476936C972CAA1ULL,
		0x5EF4E17F4529B90FULL,
		0x2E8BBC01BBC39694ULL,
		0xC1DD441DB9A4AD7CULL,
		0x1A2D00E82A05C78EULL,
		0x51EB35305A7142DDULL,
		0x3632E246A6492B60ULL
	}};
	printf("Test Case 471\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 471 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -471;
	} else {
		printf("Test Case 471 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7924D14EFC73D375ULL,
		0x4530059BBDC7BFF8ULL,
		0x7EE6101827804FCBULL,
		0x09052CD6D45A568EULL,
		0x46D9140CC7BA8108ULL,
		0xEA8FA7873374E311ULL,
		0x0E27A7642FE7B905ULL,
		0x36CBCBACFC46A4C9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF249A29DF8E7A6EAULL,
		0x8A600B377B8F7FF0ULL,
		0xFDCC20304F009F96ULL,
		0x120A59ADA8B4AD1CULL,
		0x8DB228198F750210ULL,
		0xD51F4F0E66E9C622ULL,
		0x1C4F4EC85FCF720BULL,
		0x6D979759F88D4992ULL
	}};
	printf("Test Case 472\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 472 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -472;
	} else {
		printf("Test Case 472 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6C3D6343B5712925ULL,
		0x83E413623DCE9A18ULL,
		0x4F37DB196AB340D4ULL,
		0x068978D91DFDB1D9ULL,
		0x32693DABA0053FB3ULL,
		0x6FA5D309F3B1FE92ULL,
		0x7894CD61825DA842ULL,
		0x347DFF2260149A7BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD87AC6876AE2524AULL,
		0x07C826C47B9D3430ULL,
		0x9E6FB632D56681A9ULL,
		0x0D12F1B23BFB63B2ULL,
		0x64D27B57400A7F66ULL,
		0xDF4BA613E763FD24ULL,
		0xF1299AC304BB5084ULL,
		0x68FBFE44C02934F6ULL
	}};
	printf("Test Case 473\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 473 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -473;
	} else {
		printf("Test Case 473 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAD070986D4A92FB1ULL,
		0x43AC9691FE1C9BF8ULL,
		0x3676FE20E557FC40ULL,
		0xAC848D92F32A9DE4ULL,
		0x7AF56B028950D8FCULL,
		0x99A59A4502814AC2ULL,
		0xA23B6BD4073FC46AULL,
		0x119EF68F75927200ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5A0E130DA9525F62ULL,
		0x87592D23FC3937F1ULL,
		0x6CEDFC41CAAFF880ULL,
		0x59091B25E6553BC8ULL,
		0xF5EAD60512A1B1F9ULL,
		0x334B348A05029584ULL,
		0x4476D7A80E7F88D5ULL,
		0x233DED1EEB24E401ULL
	}};
	printf("Test Case 474\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 474 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -474;
	} else {
		printf("Test Case 474 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD492868586191DA6ULL,
		0xAB8CFBE2B6DD5277ULL,
		0x8DDDFAEB03020DF8ULL,
		0xFF931174B193BE08ULL,
		0xBC46457B221C2982ULL,
		0x9B75D674AE596DC2ULL,
		0x9486935295FDC7CCULL,
		0x16AE2E57A2EB4D32ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA9250D0B0C323B4CULL,
		0x5719F7C56DBAA4EFULL,
		0x1BBBF5D606041BF1ULL,
		0xFF2622E963277C11ULL,
		0x788C8AF644385305ULL,
		0x36EBACE95CB2DB85ULL,
		0x290D26A52BFB8F99ULL,
		0x2D5C5CAF45D69A65ULL
	}};
	printf("Test Case 475\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 475 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -475;
	} else {
		printf("Test Case 475 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x39A9B3100834BBAEULL,
		0x646F5F1E2BC5AFB0ULL,
		0x24CA1E8591FCFE36ULL,
		0x9E83AFA684C7CD8CULL,
		0xC6191B05A82EA27BULL,
		0xB50AAF8A2618EDC9ULL,
		0x520D2468883DEB0EULL,
		0x307025E5694E51AEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x735366201069775CULL,
		0xC8DEBE3C578B5F60ULL,
		0x49943D0B23F9FC6CULL,
		0x3D075F4D098F9B18ULL,
		0x8C32360B505D44F7ULL,
		0x6A155F144C31DB93ULL,
		0xA41A48D1107BD61DULL,
		0x60E04BCAD29CA35CULL
	}};
	printf("Test Case 476\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 476 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -476;
	} else {
		printf("Test Case 476 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x19B2283208E4EB01ULL,
		0x2A72797849FF79CCULL,
		0x8234B28981260435ULL,
		0x5813A53DC37F2558ULL,
		0x32BBF4C0B6BA55D8ULL,
		0x553618D51471918AULL,
		0x82A8DEB353F8CFFAULL,
		0x384C4AAA7CCE1961ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3364506411C9D602ULL,
		0x54E4F2F093FEF398ULL,
		0x04696513024C086AULL,
		0xB0274A7B86FE4AB1ULL,
		0x6577E9816D74ABB0ULL,
		0xAA6C31AA28E32314ULL,
		0x0551BD66A7F19FF4ULL,
		0x70989554F99C32C3ULL
	}};
	printf("Test Case 477\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 477 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -477;
	} else {
		printf("Test Case 477 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x802612C91F23AF68ULL,
		0xAD45E10D21445CC4ULL,
		0xF16F084821D6846AULL,
		0x097127E68D69611DULL,
		0x41A90FC6E5E336F4ULL,
		0x3C417679DFB77CB0ULL,
		0xCA4DC82CBB58BCE4ULL,
		0x2CC36FEB3D1A7169ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x004C25923E475ED0ULL,
		0x5A8BC21A4288B989ULL,
		0xE2DE109043AD08D5ULL,
		0x12E24FCD1AD2C23BULL,
		0x83521F8DCBC66DE8ULL,
		0x7882ECF3BF6EF960ULL,
		0x949B905976B179C8ULL,
		0x5986DFD67A34E2D3ULL
	}};
	printf("Test Case 478\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 478 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -478;
	} else {
		printf("Test Case 478 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4EE480540A9EC96CULL,
		0xFB8089CD7D6D9CE6ULL,
		0x2192ABC1A30B0D6AULL,
		0x8F629448102EF674ULL,
		0x5C5080B7E52DAC83ULL,
		0x8D6A5635F998E356ULL,
		0x92CA526BCCD24242ULL,
		0x1587C8DB456AA357ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9DC900A8153D92D8ULL,
		0xF701139AFADB39CCULL,
		0x4325578346161AD5ULL,
		0x1EC52890205DECE8ULL,
		0xB8A1016FCA5B5907ULL,
		0x1AD4AC6BF331C6ACULL,
		0x2594A4D799A48485ULL,
		0x2B0F91B68AD546AFULL
	}};
	printf("Test Case 479\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 479 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -479;
	} else {
		printf("Test Case 479 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x89ADDCD892CC936FULL,
		0x02756BF9D20125F7ULL,
		0x2DC73E90414BAAFDULL,
		0x4801E4E58B06EE4DULL,
		0xCC3E18A69A752591ULL,
		0x17B0B7B86D98AAD3ULL,
		0x9DA3EFEA2FE5042CULL,
		0x00225A8AFED01180ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x135BB9B1259926DEULL,
		0x04EAD7F3A4024BEFULL,
		0x5B8E7D20829755FAULL,
		0x9003C9CB160DDC9AULL,
		0x987C314D34EA4B22ULL,
		0x2F616F70DB3155A7ULL,
		0x3B47DFD45FCA0858ULL,
		0x0044B515FDA02301ULL
	}};
	printf("Test Case 480\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 480 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -480;
	} else {
		printf("Test Case 480 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCFEBC0E426628E28ULL,
		0x9266BDF4F2C4A31AULL,
		0xC8609D8BA95598D6ULL,
		0x06E9F05A9BB7A1AEULL,
		0x5F8A1D8932950645ULL,
		0xD9BC5BA36777AD87ULL,
		0x3AC2216B3C999D04ULL,
		0x30C0F1E02DBBED00ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9FD781C84CC51C50ULL,
		0x24CD7BE9E5894635ULL,
		0x90C13B1752AB31ADULL,
		0x0DD3E0B5376F435DULL,
		0xBF143B12652A0C8AULL,
		0xB378B746CEEF5B0EULL,
		0x758442D679333A09ULL,
		0x6181E3C05B77DA00ULL
	}};
	printf("Test Case 481\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 481 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -481;
	} else {
		printf("Test Case 481 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2177DB3366057E06ULL,
		0x6D2621D478C7AFC7ULL,
		0x7FD0F10194856EEBULL,
		0x314D7EF46A31E3A0ULL,
		0x910A342AC96DCA21ULL,
		0xB6015D2AAE825F71ULL,
		0xC9A2FC4C7B7FC6A7ULL,
		0x39C23F87AF2846F2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x42EFB666CC0AFC0CULL,
		0xDA4C43A8F18F5F8EULL,
		0xFFA1E203290ADDD6ULL,
		0x629AFDE8D463C740ULL,
		0x2214685592DB9442ULL,
		0x6C02BA555D04BEE3ULL,
		0x9345F898F6FF8D4FULL,
		0x73847F0F5E508DE5ULL
	}};
	printf("Test Case 482\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 482 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -482;
	} else {
		printf("Test Case 482 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBFE112AD79F38662ULL,
		0xFB1095A52D216B71ULL,
		0xA3C7BE645B731B1AULL,
		0x5FC70B9E98ACBF8AULL,
		0xE51135DF20FBCBA0ULL,
		0xDEF06DB6F885057FULL,
		0xA0E078E196980F1AULL,
		0x28ED0EA85F747D97ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7FC2255AF3E70CC4ULL,
		0xF6212B4A5A42D6E3ULL,
		0x478F7CC8B6E63635ULL,
		0xBF8E173D31597F15ULL,
		0xCA226BBE41F79740ULL,
		0xBDE0DB6DF10A0AFFULL,
		0x41C0F1C32D301E35ULL,
		0x51DA1D50BEE8FB2FULL
	}};
	printf("Test Case 483\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 483 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -483;
	} else {
		printf("Test Case 483 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x08ABBB79595A4D3FULL,
		0xF2D3AEBB0CD5B12BULL,
		0x5C11BD324AE2E736ULL,
		0x26276AF033B720C2ULL,
		0xD9B5B2E5568B03F1ULL,
		0x486F819C001F3AD2ULL,
		0xC09CFE24FB08EBD6ULL,
		0x07D29C03A6604C72ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x115776F2B2B49A7EULL,
		0xE5A75D7619AB6256ULL,
		0xB8237A6495C5CE6DULL,
		0x4C4ED5E0676E4184ULL,
		0xB36B65CAAD1607E2ULL,
		0x90DF0338003E75A5ULL,
		0x8139FC49F611D7ACULL,
		0x0FA538074CC098E5ULL
	}};
	printf("Test Case 484\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 484 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -484;
	} else {
		printf("Test Case 484 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0A819555AD19DE1CULL,
		0x950C67CBCF628101ULL,
		0x3AE8A7CAEF43D7AFULL,
		0x5F576034653B58F9ULL,
		0x7A5F7EC9EA862551ULL,
		0x9D79E4B01F3C9831ULL,
		0x43B5A20C81B798ADULL,
		0x20671958A61CAE15ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x15032AAB5A33BC38ULL,
		0x2A18CF979EC50202ULL,
		0x75D14F95DE87AF5FULL,
		0xBEAEC068CA76B1F2ULL,
		0xF4BEFD93D50C4AA2ULL,
		0x3AF3C9603E793062ULL,
		0x876B4419036F315BULL,
		0x40CE32B14C395C2AULL
	}};
	printf("Test Case 485\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 485 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -485;
	} else {
		printf("Test Case 485 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x15FC879C90B5F5BFULL,
		0x47D65E28AC9B4752ULL,
		0x6E368A1802CE919CULL,
		0x33F13053A035CEC6ULL,
		0x1E0AC44635A654E2ULL,
		0x7118FC09781D4264ULL,
		0x656B0604D2F12F22ULL,
		0x3A77F6EB3C4AB738ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2BF90F39216BEB7EULL,
		0x8FACBC5159368EA4ULL,
		0xDC6D1430059D2338ULL,
		0x67E260A7406B9D8CULL,
		0x3C15888C6B4CA9C4ULL,
		0xE231F812F03A84C8ULL,
		0xCAD60C09A5E25E44ULL,
		0x74EFEDD678956E70ULL
	}};
	printf("Test Case 486\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 486 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -486;
	} else {
		printf("Test Case 486 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x40C0795541B56BF6ULL,
		0x8FF9C8CC095A02E1ULL,
		0xC1F1F4A124409043ULL,
		0x8BAA52F61560EA37ULL,
		0x9A12F171B4360CF6ULL,
		0xE0FA2A6BA68795F8ULL,
		0x67E247573F29C40BULL,
		0x1DC6608CB0DE3411ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8180F2AA836AD7ECULL,
		0x1FF3919812B405C2ULL,
		0x83E3E94248812087ULL,
		0x1754A5EC2AC1D46FULL,
		0x3425E2E3686C19EDULL,
		0xC1F454D74D0F2BF1ULL,
		0xCFC48EAE7E538817ULL,
		0x3B8CC11961BC6822ULL
	}};
	printf("Test Case 487\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 487 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -487;
	} else {
		printf("Test Case 487 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7224C89FFF5CAB6CULL,
		0x1AEFFDAAC3962112ULL,
		0x2D5F02600337EE39ULL,
		0xC4C86CCF8489AFE6ULL,
		0x3EEE3ACD67C0AC9FULL,
		0x9A70DDE3030CF40FULL,
		0xFA720E52B0E7CCD9ULL,
		0x0A1AAAC9B3930F17ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE449913FFEB956D8ULL,
		0x35DFFB55872C4224ULL,
		0x5ABE04C0066FDC72ULL,
		0x8990D99F09135FCCULL,
		0x7DDC759ACF81593FULL,
		0x34E1BBC60619E81EULL,
		0xF4E41CA561CF99B3ULL,
		0x1435559367261E2FULL
	}};
	printf("Test Case 488\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 488 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -488;
	} else {
		printf("Test Case 488 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF900FC4CDF2ABBD0ULL,
		0xCE4B48963FC82467ULL,
		0x210BD8BAF443901CULL,
		0x6C24536D2CA4E11AULL,
		0x0C05A8C982E41B0EULL,
		0xA8D73D14DEF961B1ULL,
		0xDBE211C8673B9FB8ULL,
		0x19242ADE9D35F761ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF201F899BE5577A0ULL,
		0x9C96912C7F9048CFULL,
		0x4217B175E8872039ULL,
		0xD848A6DA5949C234ULL,
		0x180B519305C8361CULL,
		0x51AE7A29BDF2C362ULL,
		0xB7C42390CE773F71ULL,
		0x324855BD3A6BEEC3ULL
	}};
	printf("Test Case 489\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 489 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -489;
	} else {
		printf("Test Case 489 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC647B33737C3F6E8ULL,
		0x47F3041D143C8D39ULL,
		0x05E366FAFD665B9FULL,
		0xF89940C9A7A0BDEAULL,
		0x58D6E8E693716B86ULL,
		0xEDBDA9E97B7E3328ULL,
		0x0AA2F2F18E5D398AULL,
		0x25EAC6CCC64259C4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8C8F666E6F87EDD0ULL,
		0x8FE6083A28791A73ULL,
		0x0BC6CDF5FACCB73EULL,
		0xF13281934F417BD4ULL,
		0xB1ADD1CD26E2D70DULL,
		0xDB7B53D2F6FC6650ULL,
		0x1545E5E31CBA7315ULL,
		0x4BD58D998C84B388ULL
	}};
	printf("Test Case 490\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 490 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -490;
	} else {
		printf("Test Case 490 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7AEA7D016CCAA68DULL,
		0xF73672F444C84C4CULL,
		0x79DB48C478455AB8ULL,
		0x77AB6106AE629A1BULL,
		0x637BB4C3E9708993ULL,
		0xC4F2F724CD5F6FC3ULL,
		0x86DD9936A12D168DULL,
		0x03BB7682E86874B7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF5D4FA02D9954D1AULL,
		0xEE6CE5E889909898ULL,
		0xF3B69188F08AB571ULL,
		0xEF56C20D5CC53436ULL,
		0xC6F76987D2E11326ULL,
		0x89E5EE499ABEDF86ULL,
		0x0DBB326D425A2D1BULL,
		0x0776ED05D0D0E96FULL
	}};
	printf("Test Case 491\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 491 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -491;
	} else {
		printf("Test Case 491 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x696E692CC53C9903ULL,
		0xCF3CFE330DE39749ULL,
		0xC27E15A0AE2B96DFULL,
		0x3519521FA7FB25B4ULL,
		0x2AD0310DB6E2A680ULL,
		0x4B73E1E3CDE10DB0ULL,
		0x3F9787547F92FC01ULL,
		0x23753AD839A515C4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD2DCD2598A793206ULL,
		0x9E79FC661BC72E92ULL,
		0x84FC2B415C572DBFULL,
		0x6A32A43F4FF64B69ULL,
		0x55A0621B6DC54D00ULL,
		0x96E7C3C79BC21B60ULL,
		0x7F2F0EA8FF25F802ULL,
		0x46EA75B0734A2B88ULL
	}};
	printf("Test Case 492\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 492 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -492;
	} else {
		printf("Test Case 492 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEE961947094BD569ULL,
		0x47174C6DBD392C98ULL,
		0x787213E80FCB64ADULL,
		0x0E361E0C8074305AULL,
		0x3331308E69E61FD6ULL,
		0x22B70D326252F50DULL,
		0xB79706DEB3A92651ULL,
		0x2275630EAB438FB4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDD2C328E1297AAD2ULL,
		0x8E2E98DB7A725931ULL,
		0xF0E427D01F96C95AULL,
		0x1C6C3C1900E860B4ULL,
		0x6662611CD3CC3FACULL,
		0x456E1A64C4A5EA1AULL,
		0x6F2E0DBD67524CA2ULL,
		0x44EAC61D56871F69ULL
	}};
	printf("Test Case 493\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 493 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -493;
	} else {
		printf("Test Case 493 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7681E2F589053865ULL,
		0x0564407CEB19EB7AULL,
		0xFE99913A58ADD83BULL,
		0xD543B12A6154F52CULL,
		0xA1FE69D0D74DD556ULL,
		0x3E31C8AA9A531CC3ULL,
		0x33AA77B5A36B09E2ULL,
		0x14FC33A33379427DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xED03C5EB120A70CAULL,
		0x0AC880F9D633D6F4ULL,
		0xFD332274B15BB076ULL,
		0xAA876254C2A9EA59ULL,
		0x43FCD3A1AE9BAAADULL,
		0x7C63915534A63987ULL,
		0x6754EF6B46D613C4ULL,
		0x29F8674666F284FAULL
	}};
	printf("Test Case 494\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 494 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -494;
	} else {
		printf("Test Case 494 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x263FC52CEB7665DEULL,
		0x4E4DFB334D9E258EULL,
		0x6CE2702942D75B78ULL,
		0xF9F4F6F921EF478DULL,
		0x67BBCF3D0D5EEA3DULL,
		0x8FE50CF49B497ABDULL,
		0xF8C667D064497ECFULL,
		0x14B019FF426EC523ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4C7F8A59D6ECCBBCULL,
		0x9C9BF6669B3C4B1CULL,
		0xD9C4E05285AEB6F0ULL,
		0xF3E9EDF243DE8F1AULL,
		0xCF779E7A1ABDD47BULL,
		0x1FCA19E93692F57AULL,
		0xF18CCFA0C892FD9FULL,
		0x296033FE84DD8A47ULL
	}};
	printf("Test Case 495\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 495 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -495;
	} else {
		printf("Test Case 495 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7AE38329E8947EFBULL,
		0xED687C0451562B86ULL,
		0x8A300D223303832BULL,
		0xE56AF3D76BED2A91ULL,
		0x43C2D149B2B0D82BULL,
		0xB0299AB7AC0FDE83ULL,
		0xB66463FACA297E0FULL,
		0x04D406B7EAA492BEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF5C70653D128FDF6ULL,
		0xDAD0F808A2AC570CULL,
		0x14601A4466070657ULL,
		0xCAD5E7AED7DA5523ULL,
		0x8785A2936561B057ULL,
		0x6053356F581FBD06ULL,
		0x6CC8C7F59452FC1FULL,
		0x09A80D6FD549257DULL
	}};
	printf("Test Case 496\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 496 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -496;
	} else {
		printf("Test Case 496 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2FC568252DF7933CULL,
		0x48017845AFEFBA4AULL,
		0xA071001285B3ACA4ULL,
		0x252012A74A7C935CULL,
		0xD9607641AFB8F2C4ULL,
		0x83D6888E2A55596BULL,
		0x577D3EDD21EE1400ULL,
		0x01F445B0CB6237B4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5F8AD04A5BEF2678ULL,
		0x9002F08B5FDF7494ULL,
		0x40E200250B675948ULL,
		0x4A40254E94F926B9ULL,
		0xB2C0EC835F71E588ULL,
		0x07AD111C54AAB2D7ULL,
		0xAEFA7DBA43DC2801ULL,
		0x03E88B6196C46F68ULL
	}};
	printf("Test Case 497\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 497 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -497;
	} else {
		printf("Test Case 497 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5E98E4D0450D9028ULL,
		0xD77DAB4828575F6FULL,
		0xDE22DD7DB11F0788ULL,
		0x35C5F7034E925248ULL,
		0x827F4DABC2830FE1ULL,
		0x5F9AB65F419F8A6FULL,
		0xA2FAAD4AEFB5990DULL,
		0x2706CAEEA640C6EFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBD31C9A08A1B2050ULL,
		0xAEFB569050AEBEDEULL,
		0xBC45BAFB623E0F11ULL,
		0x6B8BEE069D24A491ULL,
		0x04FE9B5785061FC2ULL,
		0xBF356CBE833F14DFULL,
		0x45F55A95DF6B321AULL,
		0x4E0D95DD4C818DDFULL
	}};
	printf("Test Case 498\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 498 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -498;
	} else {
		printf("Test Case 498 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x188A7D6F7139244BULL,
		0x1ED213AAE71A8CAFULL,
		0x1297D7BE359BA87AULL,
		0x20732C5A13C7F30CULL,
		0xE9374598419CC71FULL,
		0xAF4F6F36FB17AA5CULL,
		0xB96AF6BBDFF0A8E5ULL,
		0x1049076250FBCFCBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3114FADEE2724896ULL,
		0x3DA42755CE35195EULL,
		0x252FAF7C6B3750F4ULL,
		0x40E658B4278FE618ULL,
		0xD26E8B3083398E3EULL,
		0x5E9EDE6DF62F54B9ULL,
		0x72D5ED77BFE151CBULL,
		0x20920EC4A1F79F97ULL
	}};
	printf("Test Case 499\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 499 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -499;
	} else {
		printf("Test Case 499 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x046CA110CB1B64A0ULL,
		0x79B118396AA19A3EULL,
		0x4AFDE50A5AC20EB7ULL,
		0x54EC051747B6AFF6ULL,
		0x46EB73F19CA00F61ULL,
		0xACDDB33E45F5E028ULL,
		0x4B45FCACD9D3A56EULL,
		0x3682B71D6F4EAF25ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x08D942219636C940ULL,
		0xF3623072D543347CULL,
		0x95FBCA14B5841D6EULL,
		0xA9D80A2E8F6D5FECULL,
		0x8DD6E7E339401EC2ULL,
		0x59BB667C8BEBC050ULL,
		0x968BF959B3A74ADDULL,
		0x6D056E3ADE9D5E4AULL
	}};
	printf("Test Case 500\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 500 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -500;
	} else {
		printf("Test Case 500 PASSED\n");
	}
	printf("---\n\n");
	return 0;
}