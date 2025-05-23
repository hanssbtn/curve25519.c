#include "../tests.h"

int32_t curve25519_key_sub_modulo_test(void) {
	printf("Modular Key Subtraction Test\n");
	curve25519_key_t r = { };
	curve25519_key_t k1 = {.key64 = {
		0x3A761212DABE82A9ULL,
		0xECB936DD6F3EF78BULL,
		0x914C5C75DB7F015EULL,
		0xCA8465E1EF09E9A7ULL,
		0x47C185D479293397ULL,
		0xB1642C892CA8BF6CULL,
		0x92B2ECD6BB2B649DULL,
		0xC7199EA8E1B6D406ULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0x1A013DA3D15DDBD1ULL,
		0xE9BF7661A3135E1DULL,
		0x9590BA4188A5AEFFULL,
		0xB1C4C6B2F4280BB8ULL,
		0xEA1A3184966EA9A9ULL,
		0x341D89EF360DDE7EULL,
		0xC2D57E1C432F56C2ULL,
		0x852987283071F41BULL
	}};
	curve25519_key_t k3 = {.key64 = {
		0x074B584AB1112195ULL,
		0x9B75E3566728FCAAULL,
		0xD69A11E2224360F3ULL,
		0x62631C494B1B1AC9ULL,
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
		0xD52196E51BC1CD70ULL,
		0xBC2F5B252D8CC393ULL,
		0xA902E17913512561ULL,
		0x01F5F942C56778D9ULL,
		0x434E64836E94C9E1ULL,
		0x852C7C62A98A2614ULL,
		0x68F35D0427FE5C1DULL,
		0xC77595AA653B9EACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8A5CDD6E78873FA5ULL,
		0x6A6C27E4E859DF3FULL,
		0x1575A7EA29995A6AULL,
		0x9D2AF1EC315B100FULL,
		0xE55449EA902F2424ULL,
		0xB5D6AC26E95D61CFULL,
		0x3F5D94B2FA7932EFULL,
		0x111A07B7A7D5C3BEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3DE4AC27A6512BB5ULL,
		0x18801C1ECBD8067AULL,
		0xBFC8F59BAB7BE7C4ULL,
		0x7662195EB12AE824ULL,
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
		0xEE234774C4C71DC1ULL,
		0xD0BD2D952C31320FULL,
		0xE61E9D4F5A26040BULL,
		0x0AA57D67A44D79FEULL,
		0xFD8976932F0E442FULL,
		0xC5CDA1D5213F876CULL,
		0x99B133B016B88F2AULL,
		0xFBA8503FC9E9177FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x30A2FE51734320CAULL,
		0xE920251913AEBCF8ULL,
		0xA22072E7DFD00A87ULL,
		0x99B807D7F4F8E47BULL,
		0x1382F56A4EB17748ULL,
		0x9972A50C43EEBFFEULL,
		0xF40F30B31801864BULL,
		0xE2429D387E3DDDCDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7A7775349F4A67B3ULL,
		0x7D1E8E4CF2800F8EULL,
		0xDA0A9BF549814AA4ULL,
		0x360608A4EABF25E1ULL,
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
		0xA7B9983F3BE15337ULL,
		0x5E9604AC23D2614BULL,
		0x35AFE6CF673FD1CDULL,
		0x2F0F9ED248B9006CULL,
		0x4E8D5406B2F5BB12ULL,
		0x2BE5BE37A1882778ULL,
		0xEE7902FB4702F076ULL,
		0x30EA0D3AD47788EFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x981E5D2EB9C360C3ULL,
		0xAD3C7F4E99B9F79DULL,
		0x84E5830235C56860ULL,
		0xEE4668543929F29CULL,
		0x926F1F6C37898BFEULL,
		0x529134F50030518DULL,
		0x6816A618E49ACEF9ULL,
		0xCEDE11149C55BABFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFC1709FED42CEBC9ULL,
		0xF3E5E5417D222A85ULL,
		0xA3642D67CCEF61F4ULL,
		0x4E90A42A6493A903ULL,
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
		0xEA79AF76DA983991ULL,
		0x025A9E9AD50D00D2ULL,
		0xF13714D22C0321BEULL,
		0x60BF95397F4B9B43ULL,
		0xEF189191676C2588ULL,
		0x68FD3948F8CD627EULL,
		0x9C59022DAA8108B7ULL,
		0x391EC3AFCAAFBAB7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC947DBAFD07034DEULL,
		0xDBE7EA763D5A8234ULL,
		0xD37D9B9A4FE66B21ULL,
		0x5C6F50B485238696ULL,
		0xD950A2E4A90702F2ULL,
		0xA201C3E1F5196F36ULL,
		0x82CCC8A40995EE0BULL,
		0xCE3672D7BC8306CCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5CDF416B4D2B23A0ULL,
		0xAFC6216F24689B51ULL,
		0xE88A03A5BF02AC1BULL,
		0x62CC449714CAC992ULL,
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
		0x6F1194ACC51492A0ULL,
		0x97FD4CF332EFB94DULL,
		0x391985B732B1D163ULL,
		0xF6A3CC575BF97216ULL,
		0xFD4A1F35F89A2B8AULL,
		0xEE6E05BB7B9F3AB8ULL,
		0x68D363CA81E86CC9ULL,
		0x13EC8D35FD4F77B2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x703037DDC2EB973BULL,
		0x1B9642E8B0904B11ULL,
		0x2D9FAFCBB53B3E7CULL,
		0x7ADD28A43AB3A082ULL,
		0xABDC3CF7D1A94BD6ULL,
		0x1888077ADFFFA096ULL,
		0x31E8D3781DA2D5B6ULL,
		0xB73BEB1977F1EDADULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1530F208C9EA2C8DULL,
		0x3C8AC7A19C104F54ULL,
		0x324B42265FCAFFD9ULL,
		0x3DFEB3EEED284E5AULL,
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
		0x9488F26A40905C37ULL,
		0x4675BC57DAF40FE7ULL,
		0xC6AC32C5F6104157ULL,
		0x6B364D43C1222EEBULL,
		0x54EB8F42DC9BCA50ULL,
		0xC8128138B5F8D5EFULL,
		0x84B28B349EC214F6ULL,
		0xDE07FA9BC5467496ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x043865C3A1BD7DF0ULL,
		0x5C2ACD7942826A9FULL,
		0x3CC26B461B64AE81ULL,
		0x6CB4F9073C94F8BBULL,
		0xC571455E87BE2531ULL,
		0x22232A02C293C386ULL,
		0x9ED7446784AC826BULL,
		0x4D050AC8BD080DD4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDC77848B37B96412ULL,
		0x8BD1E0E0B97260CDULL,
		0xA87649F1B9DF5390ULL,
		0x04F0ED8FBDD076F8ULL,
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
		0x5ADA66F914FDBBECULL,
		0x5B9BA6CB1D7995F9ULL,
		0x18568099CB3B4897ULL,
		0x451BB4C83AA786F1ULL,
		0xDF3E2FB33F63ECD7ULL,
		0xF576450A36313648ULL,
		0xE8B6246A63271200ULL,
		0xF0A1CBF04412FB21ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8135D64468BAD75FULL,
		0x6BCF14F56C0C9DACULL,
		0x23B3345E4608AEFFULL,
		0x7F18F4CD30529E0CULL,
		0xEC312DC16D99BA36ULL,
		0x9154F162C376982CULL,
		0xC0BC99E2BEAEE1B2ULL,
		0xFAC2C263311CA9F1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xED92DA99D0466827ULL,
		0xCCBEFCB0B9207072ULL,
		0xE3ADDC5DEF09C53AULL,
		0x451E2AEBDAE4F60AULL,
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
		0x8B07CF8F247E8FE6ULL,
		0x1B901C21CE83D594ULL,
		0x4D8D7355EFC6B2CAULL,
		0x7D596E0EE6D08695ULL,
		0x2A95495B25E9681DULL,
		0xCCAEF2E4CD447419ULL,
		0xFE43D01D3F0F80F3ULL,
		0x6247BE3CB1B4B697ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x54084D3A671C5975ULL,
		0x336CBD159BF8CDDDULL,
		0xBC1B0B4974D66524ULL,
		0x53BE78C0BF88DE92ULL,
		0x66FA2D0F7DAB037BULL,
		0xD63099C2F63DA311ULL,
		0xAE5A296752FE05DCULL,
		0x682869005EC02753ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4005B58FB6A52657ULL,
		0x7EE49A121D8E0EDEULL,
		0x6E21270D8588930EULL,
		0x4A419C427794EC26ULL,
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
		0xF359FF3E003866D7ULL,
		0x10CB12906347CB15ULL,
		0x9F9311A884A3C0E5ULL,
		0xCE0CC41FD5FD07DAULL,
		0xD5BE7A05508F7F37ULL,
		0x87BA77A0305A267AULL,
		0x33C0A9D4553B864BULL,
		0x7E379B2629E84A0BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB96AF5F1A6779C79ULL,
		0x417D9EEFD434B628ULL,
		0x92ECF21C7C8FE00CULL,
		0x1520C4785F5F21F5ULL,
		0xE2A82302D67E7AB1ULL,
		0x4A5186627F288D7AULL,
		0xE52A6AF16641441FULL,
		0x3DDA2120096600DBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4F3FF3AA784777BEULL,
		0xECE142C8DC6FCAEBULL,
		0xB6F3753B8139B369ULL,
		0x46CC1C9049F4C2EAULL,
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
		0x365A54686399944EULL,
		0x6D2943EEF75FB0E1ULL,
		0x799714732D461F34ULL,
		0xD9315A2110AFB1E0ULL,
		0xCC399B222628CD9AULL,
		0xAAD7E46653134624ULL,
		0x3A8123F404F9C83DULL,
		0xA2C7B3AF137237A3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3127CA9AE631C993ULL,
		0x83F0D37AEB189EB9ULL,
		0x83B43FEF6EE851F8ULL,
		0xABDD1CB82A7A3598ULL,
		0x1E6AD1148F1E9C03ULL,
		0x1C7CA7CAE30CC150ULL,
		0xB815ACD622E2FD25ULL,
		0xDE446DB705045F27ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD1E487D1E8EB25CFULL,
		0x0AC36F86AD3EC9B9ULL,
		0x51D682F34DBFF2E1ULL,
		0x58D0A03B0A839E9DULL,
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
		0x13A904DB57418CE7ULL,
		0x94BE95BF868B0508ULL,
		0xC66E62E5E4DCD9B3ULL,
		0x8FC1C939F32D66A9ULL,
		0x00A7093FF08B9BF9ULL,
		0x0D86D48405606B24ULL,
		0x2F7DC2446D002DB6ULL,
		0x128D9324954AD914ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8F87498B4DC8595DULL,
		0x359703C086E2F1F1ULL,
		0x078133DE0D2E75FFULL,
		0x43AE486BF50A6383ULL,
		0xC6BF6FEC301EC059ULL,
		0xAD0D6FCB2C5ABF93ULL,
		0x58645EF35EDDD8BDULL,
		0xCB303DF3BAF9EC16ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1C827DBE99A1C935ULL,
		0xB12C856F367F8A7FULL,
		0xACB1ED0FF0C70092ULL,
		0x63EE260E662630D4ULL,
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
		0x46E944B180CD8EADULL,
		0x9E72920B0CCB587FULL,
		0x53B86D508A9DF0BEULL,
		0xBD84A841EE644D59ULL,
		0x459DBDE41638EF12ULL,
		0x5220382C0619CF4AULL,
		0xDDB7A98B72845D2CULL,
		0xFEA2A605E87A807BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA90209BC8B50162CULL,
		0xE1B0D49A3373764EULL,
		0xB4C3E996714A373FULL,
		0x9F9707418A8FB17FULL,
		0x363011418923037CULL,
		0x567EDC27B077233EULL,
		0xBB26E5A72BD3A5B2ULL,
		0x8AA6DBDB8B28440EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE82EDB15E6BE734BULL,
		0x16B566158F7D6BFAULL,
		0xC071979C978EF59AULL,
		0x554DA34A3E09940CULL,
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
		0xE7C766AD87E0DAE2ULL,
		0xA22262988D2E12FBULL,
		0x3954AB47257BF4D3ULL,
		0x210FDC3465349175ULL,
		0xB68B6146B10B6260ULL,
		0x7A33BBA4B7691859ULL,
		0x4B04B251C0DC0FA3ULL,
		0x6DE3CAC7B43B25D1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBC9C25E56851DFA8ULL,
		0x36498583BCFCE540ULL,
		0xE1FAC5D8650D872EULL,
		0xA1400CB9F288BB0BULL,
		0x7A349E3B7504B237ULL,
		0xE04FE089D2F70A4AULL,
		0x1432DBD6081A0728ULL,
		0xD59F100F2FE55392ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x200C3473088D1EF0ULL,
		0x43AB6312B91F43FEULL,
		0x7A7FBBCC2D3BAFD8ULL,
		0x1A0386DE17690BCBULL,
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
		0x0120EEBF0C105BA8ULL,
		0x1A5A69ED1D8D02F7ULL,
		0x0056574CC3B3202BULL,
		0xB42258CDAD288F53ULL,
		0xB8241ED6DB554BDAULL,
		0x76247DABD70E6A3CULL,
		0x54EDAF3436FDFBC3ULL,
		0xE0AD3051F53887E3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x98BA163BED3FFD36ULL,
		0x151C1B1BF07FF691ULL,
		0xEDCBF4A92E6C1EACULL,
		0x36148A99C486583FULL,
		0xD87740590AD528A8ULL,
		0x3F4BE30C2BD8A96BULL,
		0xF05D2EAAB3F862D6ULL,
		0xBEB6718D32667647ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9C0FDF3011D598AFULL,
		0x296542849707AB66ULL,
		0xFFFD770D081BB4B5ULL,
		0x08AE1F68D3D0D423ULL,
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
		0x259717981CBFD050ULL,
		0xDA926388DBF6C7D6ULL,
		0x11C789943A8A755EULL,
		0x896C1D26C303B47AULL,
		0x260BC90E584BD520ULL,
		0x4EEB4D397EB277CBULL,
		0x3CEB46B6E5FA5F5FULL,
		0x8231CC37E9A3FBBAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5D52D041ABBC41A2ULL,
		0x8AC6F6D76E36F73FULL,
		0xE7C08B0E72EA1E41ULL,
		0x18B8A3CFAE698F13ULL,
		0x9EB557F28ACDD2DAULL,
		0x626D3B8C2B72B99AULL,
		0xE335E07E262F5028ULL,
		0x4D85E7CF94741EBAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDF191176F1B7E642ULL,
		0x6A820C6BC9360BCAULL,
		0x7AF42AF23FC49944ULL,
		0x423760D3B9B4F34DULL,
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
		0x35CCAB2F9CFF1DF5ULL,
		0x62175215D165BC9CULL,
		0xF9BA0E537F301A3CULL,
		0x5258498688DF83A6ULL,
		0x200D6709518739D6ULL,
		0x1F79159A211855D1ULL,
		0x08EE695689F89254ULL,
		0xA88E46AF5FED80A0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4F3BD1C88D245CFDULL,
		0x36DA04CF43A4BF0CULL,
		0xBBAF74DD310204E9ULL,
		0x06D9E6F49E307623ULL,
		0xDB0D96022507EB59ULL,
		0xAF89D14D62BDA293ULL,
		0x013088814B632A40ULL,
		0xBB308F6A7286D67CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2489E077AAC06727ULL,
		0xC8C170AACF3798A8ULL,
		0x6439F91D985B8835ULL,
		0x076796CD27EC4EDCULL,
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
		0x3A8320C795DF925FULL,
		0x75FCBDFE48574B82ULL,
		0x1A80269150642265ULL,
		0x6E06A0FA787E65D7ULL,
		0xF64718D1C99DAF42ULL,
		0xA6C43DE555AED602ULL,
		0xA150C33E66A05983ULL,
		0x2F0438B2380C5889ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x715ECD46BE9C39F8ULL,
		0xEBA8C12ECECC6A1EULL,
		0x1A086D0542F0CFF5ULL,
		0x335D519C896692AEULL,
		0xC430787827FB25B5ULL,
		0x876E5815324111F8ULL,
		0x6247181D5247FCDBULL,
		0xE2B5DF1D3C69EED4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x388020CED563BF66ULL,
		0x311419B4BBD5FAE7ULL,
		0x5BE7207512911364ULL,
		0x0E4A9B7B49338410ULL,
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
		0x3558A12F13B549BDULL,
		0xD2ECE47745E72C98ULL,
		0x95CFB2A1EC222C1DULL,
		0x77209C0BF0B631A3ULL,
		0x93E0762BC27D87F1ULL,
		0x3EC0AD17A55793B7ULL,
		0x5DFBAE91EDDE87C0ULL,
		0x1477D0DD0497A94DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4FD2BFDF0C4014F0ULL,
		0xD6883A94BC941CABULL,
		0x461A8ABFF1EB02E7ULL,
		0x988157C4AA7DCEDAULL,
		0xA6EB8A8598AD5A85ULL,
		0x4E2036250A315AD4ULL,
		0xA85848286AF83D3DULL,
		0xA7755E607C7C8A5BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x11E0DBFA3C5BEF91ULL,
		0xB43651E590FF819CULL,
		0x45F65B8B686638A5ULL,
		0x0CFC42C37A3EFAAAULL,
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
		0xF8ED6D75C137C30FULL,
		0xAD6C4E9380582D21ULL,
		0x2DD8647434C345D6ULL,
		0x7582D4A07909ECE9ULL,
		0xC0E22462ADF9A2FEULL,
		0x862AB7C513902335ULL,
		0x8FEEC9050FB19959ULL,
		0x523A0E80353F2ADEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x37C105FE8767B0B8ULL,
		0xB5D817478D07B59CULL,
		0xE44146B96FFF0D90ULL,
		0xC76E0C51BBEAB9ACULL,
		0xDCB2EF53FD95ED98ULL,
		0x4D71A283C81926CAULL,
		0x934E6505DD08867BULL,
		0xC7A1DDA42F0E9905ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA02E47A5689CFCCFULL,
		0x630D5EFD26F9EF63ULL,
		0xC965F59C49DD0542ULL,
		0x40AC08F7A854D971ULL,
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
		0x5F15DE2D1F7439E2ULL,
		0x99E52E88D33DBF73ULL,
		0xD5D1E6548C345A83ULL,
		0xFCA2883CAE920415ULL,
		0x5227280FD504001BULL,
		0xF883260F5986ED2BULL,
		0xDEA50AA0C4DBD2C6ULL,
		0xC6A15EB5BCCF41AAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xECFB6B99DE9D0FA1ULL,
		0xF74BF0BDE9255861ULL,
		0x907AFFE858B31532ULL,
		0x0D7EE5102343C4D7ULL,
		0x971D6C9CBD562992ULL,
		0xD91BCB4114D46708ULL,
		0x26255946D1468E32ULL,
		0xB77F0C7A168832C3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x358C45A8C4A50309ULL,
		0x4BF0B8691C985039ULL,
		0xA84B39C65BA9734DULL,
		0x2E3BD80739DA75A3ULL,
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
		0xF6E1FF07600AE564ULL,
		0x89CDD3D9AF69B884ULL,
		0xA52943FB7C48F837ULL,
		0x35EA61232C99F3C7ULL,
		0x503FAC93561EA208ULL,
		0x03E012C6113545E1ULL,
		0xFB197195272E58AFULL,
		0xEEB7B2E0C4050C9BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8C7265F0615B2127ULL,
		0x2D4B31A3F98DD644ULL,
		0xC6F79F4CC7BAB6D6ULL,
		0x50405FD1B325FCF2ULL,
		0xF4E3FB7746A6F383ULL,
		0x129A4AF9D3A35227ULL,
		0x75354D12530D4820ULL,
		0x569FC1027D3704F0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFA0BE3414A73AF3FULL,
		0x2CDE4A86D9860FC3ULL,
		0xBE0F101A3176B699ULL,
		0x7937E84FFC091A4AULL,
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
		0x314F0E44C53FB3C7ULL,
		0xBE964FEA27382C06ULL,
		0xF236050D2CCC0139ULL,
		0x256C2C9CE96233E8ULL,
		0x26D86E87CD5973BFULL,
		0xE7A4DF77C1E6CFE5ULL,
		0xDED4AE732ABA20FAULL,
		0x0671989AD0525043ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x04B5B9E09D3BE26AULL,
		0x304E569635755D6BULL,
		0x4622649B6B0E4104ULL,
		0x354E58F6846A8EFDULL,
		0xA07C1AD221BF5003ULL,
		0xBB1616BE8F136DC2ULL,
		0xD900F236600558E5ULL,
		0x2F38F9F4760FAB5DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1E4DC15BA0E51E4EULL,
		0x2B79C4D17D235FBBULL,
		0x89819177D893735AULL,
		0x62856057CADC1F10ULL,
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
		0xB4FCA2A110B0894BULL,
		0x6D11F74670843786ULL,
		0xCEBE70816FCA4073ULL,
		0xA5D1EA8A541AF27DULL,
		0xEEFFF2AE106AF41CULL,
		0x841F229F43933CD5ULL,
		0x34F723B69DB9332AULL,
		0x43E3CA89CF61ED44ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8A4F6B4016CADC2BULL,
		0x83D2E79FF9001CCAULL,
		0x0212BC20D6D0B374ULL,
		0xAE7DDC9658F54906ULL,
		0x11CA1FF2C9540888ULL,
		0xC085B3BB85FA2A47ULL,
		0x78DAB04D2A7D5403ULL,
		0x6F2313B19E84C3FAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x00AA7F2D874CA421ULL,
		0xF20585749C3CDBF1ULL,
		0xB8E4D607B3DCACBFULL,
		0x0BEF320B3BF9CA69ULL,
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
		0x15C1D19CEECBEF49ULL,
		0x191D6C4AC1187E67ULL,
		0x03842A501B995B2AULL,
		0x669E620B51AD8BB4ULL,
		0x1EE6C949B03C6A66ULL,
		0x24BBAEF58C241582ULL,
		0x3D5421CA45D1B0B6ULL,
		0xF3237451BB0B4EBBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x04A6F0D80265A10EULL,
		0xB30050F10BE9C40FULL,
		0xF210EF5DE84BA7F2ULL,
		0x3393653237245332ULL,
		0x0AE3C0E9747C5F6BULL,
		0xF4713BCE9EE86DE1ULL,
		0x945C844F7C294248ULL,
		0x672DB7485B5C8F37ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x098E1F0DCAE7F288ULL,
		0x912A3320EC099C41ULL,
		0x26349B2C224E176CULL,
		0x79850C3D4E79A60CULL,
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
		0xA6BB43F393EEB096ULL,
		0xADECA332416821E5ULL,
		0xE8C20C0F45919302ULL,
		0xACD1EEFFB4DE4232ULL,
		0x61F9A6042FB64276ULL,
		0x3BFE30371668D0F5ULL,
		0x5E83612A2A66774BULL,
		0x5ED0A9CA6D884F6EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9CABC76FEE8FB9E8ULL,
		0x88A1CA28E8809CCCULL,
		0x3378ED8800C5F42DULL,
		0xD4CE7DDC3F659FE1ULL,
		0xEF97A7A8B4C16735ULL,
		0xDB92D720932541B3ULL,
		0x2BFCF4CDD483125AULL,
		0x5C5BDF9A684A48FBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x049B3E17E5B78254ULL,
		0x753A1260D4EEC8D0ULL,
		0x353D343C048C9A83ULL,
		0x355974443CAD976BULL,
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
		0x83F2A567AD756A45ULL,
		0x5BA3A586508E3267ULL,
		0x48C8D403D8CE9F8FULL,
		0x95768F1D81463C0CULL,
		0x60B05B963FA70F23ULL,
		0xC88FBA03C7F49CB1ULL,
		0x6BFEDCACBC65FE2AULL,
		0xC78160FC2D1D84C5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0355329E234AEBCBULL,
		0xF47C25124ED92DA7ULL,
		0x616D8BE3FB7B5496ULL,
		0x9DAFA143921B78B9ULL,
		0xD7C14E44FCC684EFULL,
		0x6B33885C4785F0C9ULL,
		0xF1B374F2623AFE12ULL,
		0x96F38E7D2ABAE1D4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD4196CD9777F033CULL,
		0x42D6DF511222891EULL,
		0x0E8CADC93FB54E96ULL,
		0x2CD42CB449CEF305ULL,
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
		0x0D49DB03F3637303ULL,
		0xDC472BD0A48D43ECULL,
		0xE02F2BF2953A5E7FULL,
		0xDAD4CB931C031AB4ULL,
		0x8FAF4462B8E8673CULL,
		0x1BF570EB936D9494ULL,
		0x80C231687BEDF292ULL,
		0x26F76038543C6789ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8733B14F50425B77ULL,
		0x621FDD956EDDBDC1ULL,
		0x5DE897CB5560F864ULL,
		0xAA06E0EC546CE191ULL,
		0x13666E3357C2C730ULL,
		0xFEE867AC41F8C716ULL,
		0x53580716D4AFCAF6ULL,
		0x9F33443F1C2EF553ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF8E5F4BD0EB6D6A8ULL,
		0xCA16ADA14D0606F0ULL,
		0x4008DC4613134721ULL,
		0x57EA11A519952D2EULL,
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
		0x4C81EC59A2A88D30ULL,
		0x28703A7BCA983A64ULL,
		0x0491B6C291AA907BULL,
		0x410B5D2FB9D1C009ULL,
		0x80D83218A46F80FBULL,
		0x44B9D6D0600EE6B4ULL,
		0x00A2947CF7214D25ULL,
		0xE60E4FCB0AA46992ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0A2FA7F37BBDC848ULL,
		0x469B8971E0221294ULL,
		0xE6C594CDC032FCC6ULL,
		0x2DFDA9841ED7F6C3ULL,
		0xBB8BF2EF2F6D0F56ULL,
		0xB21DB3260A4C73F5ULL,
		0xCD5B49E1E9B532F9ULL,
		0x25AFF67ABF49AB18ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8BA3A48D8547A7A1ULL,
		0xA501FC52A5533021ULL,
		0xBA6134F8CF83762CULL,
		0x210EF596CA720F42ULL,
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
		0x0A83E486DF52429EULL,
		0x409B04F90EA0E91CULL,
		0x6DC0786055F7A0B0ULL,
		0x66287D97843A6DD9ULL,
		0xBC7596BC75504100ULL,
		0x0C0AACECCE11E1B8ULL,
		0x40ADCE76B1B92E42ULL,
		0x4F64D7D92C8EEF16ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9912C90887893C12ULL,
		0x5609E3D4B7C631A5ULL,
		0x09E2D86BC42EDC04ULL,
		0x682E27C44ADDC744ULL,
		0x5BDCFD29568A68EEULL,
		0xBA3E27EBFAF398B0ULL,
		0x31772624E4AC1D05ULL,
		0xB4E7655B5F9AA792ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC817E754E92716EBULL,
		0x0EECDF43AD598EB4ULL,
		0xA5FA9C1901B953A0ULL,
		0x6C99547FA59F442FULL,
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
		0x3E6103F0CE4F004CULL,
		0xA89E92E15081FE59ULL,
		0x1C7272B829F31FAAULL,
		0x18DE7354E8A67CCCULL,
		0x755D176C904A2DFBULL,
		0x82193A47D07D6782ULL,
		0xE3D5F73EADB937D6ULL,
		0x7FF97FA8EF6E1CD0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEB438BD041A847F0ULL,
		0xBFADA73068BF695FULL,
		0xE0537A66FB3AD66BULL,
		0x9F59263B54283745ULL,
		0x9E5A50939A198E60ULL,
		0x1336CDA24127D5F2ULL,
		0x0EA46733B32A9747ULL,
		0x364D8A913C8A06BBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3D86FC5517DE6ADAULL,
		0x5E8D0C442E763053ULL,
		0xE17A59F25FE41E89ULL,
		0x690BAE9E22598CC3ULL,
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
		0xD25D88A89654F312ULL,
		0xDF6E203359D44557ULL,
		0x0CB8A766594C5620ULL,
		0x64F6E21738686857ULL,
		0x319E1DF3F8198B56ULL,
		0xB828CF6648A73E88ULL,
		0x4050EFCBD3213384ULL,
		0xF27FBADBE17CF5DBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6F72720A7B68FA00ULL,
		0x6B98A3742E488949ULL,
		0x2FF3C669451DB1E9ULL,
		0xAF50E67A0EEA741BULL,
		0xFA23B615F403ED11ULL,
		0x2D0F28B1C5B867EAULL,
		0x43F9EB9EBCE31B9AULL,
		0x3AB57593853CF742ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9F168192B6217B3FULL,
		0x19A43B8A9AFF9764ULL,
		0x51AF7FAE61663108ULL,
		0x7DAC445ADAFDBEF1ULL,
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
		0xA194FD054FFF0B10ULL,
		0x254F248156B2F0D4ULL,
		0x442549116A1BBB08ULL,
		0x6D8D449FC309D490ULL,
		0x60A84D37D76EC98BULL,
		0x0BB4CD554AF70AE3ULL,
		0x2B4A08967D0E4847ULL,
		0x85E065A7F6C4F609ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2C3CFE9240FF9C1BULL,
		0x40A12DE5E2C0728FULL,
		0x61AB23D3C1F21379ULL,
		0xB70DA307FF5CD565ULL,
		0xB626B2F921967641ULL,
		0x440FF4854277C2E6ULL,
		0x6B403B4CEF9E06ABULL,
		0x95AE8DCF6421889AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC494E3C20D1BCB7FULL,
		0x8726257CB6D72DC6ULL,
		0x63EE9E28A6D364AEULL,
		0x5DE5ABBD87EF3D9BULL,
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
		0x03CCDFAC2FC0C023ULL,
		0x94C8925C28DEF7BAULL,
		0x5CCA3AE2F2537B15ULL,
		0x3CBC79E132BC60BCULL,
		0xAED2B552DE104927ULL,
		0xDA637D45C80085C4ULL,
		0xE3D3D404626F00CCULL,
		0x3A46DAF486C86326ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEC79861FD0A64D88ULL,
		0xDC7A4DA4D6FDFA97ULL,
		0x2FE696ED6FF2765BULL,
		0x8705418748DC6198ULL,
		0x6EF4E0F4ED12A553ULL,
		0xD91ABEEF7DEDA1C2ULL,
		0x598D76149A5B74ACULL,
		0xF09ED08EEAB4E5C9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9240DF7E24C0BFFEULL,
		0xE91A858650AED577ULL,
		0xB355958D3547D179ULL,
		0x24A8C36F14C49B06ULL,
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
		0xFFD1C50049E4B2E4ULL,
		0x11002CC029ED6EDDULL,
		0x0386CE68037A6BA2ULL,
		0x31D0124221601217ULL,
		0x9E75FBEEB11A40D4ULL,
		0xA10E4E512F21E048ULL,
		0xE12E55A2C93B0490ULL,
		0x33C8A3AD2EAB8FE5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x152F6798B7317BE3ULL,
		0xA9A825F37E2F1598ULL,
		0x641F84E5255B0667ULL,
		0x652E8C27AD2159EDULL,
		0xB8F6D74433FB9840ULL,
		0x2DBFC2FF588973CEULL,
		0x25729F14852F5B2EULL,
		0xF27A87A54D39648CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFB81CEB6254038ABULL,
		0x8500B4F2865E735DULL,
		0x7D4462A0F7DA89D7ULL,
		0x7E39AF45EB31277BULL,
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
		0xA3F3807DDF5422DFULL,
		0x2EA666C72936CF44ULL,
		0x68331583783C8589ULL,
		0x52E460DC90241EDEULL,
		0xA41E1A10A119C706ULL,
		0x6B15827D0D68BA7CULL,
		0x865F8B338D8B049CULL,
		0x823B28CF90A5E549ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAE1D959EF0F63B0EULL,
		0xC6864CB791ABD36AULL,
		0xF75E568A81F06513ULL,
		0xEA89F83A08A9F075ULL,
		0xD3BB7BDAF30EB3F3ULL,
		0xCA6EB3CA84D7CEA5ULL,
		0x1FCEC9F860E85D88ULL,
		0x85007B0E6DF1939BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE47966D6C402BC6AULL,
		0x40E2C88FDD0DFDBCULL,
		0xAA516DC19670ED5FULL,
		0x7F10334DAE3E4E4BULL,
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
		0x96077AB03C3F953BULL,
		0xEBEE96ECBEC37D14ULL,
		0x24C982913D149CB1ULL,
		0x9DC867B3DF185571ULL,
		0x46DC5837974686E1ULL,
		0xA6C818E38120658BULL,
		0x865A56CD9E711E52ULL,
		0x7B695A2B915C67A3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7C5A12285E3F6721ULL,
		0x0329CE4DC0057148ULL,
		0xC4C4B5C8E6D93FEBULL,
		0x86D36B6946F4C696ULL,
		0x623D01C139D6C38FULL,
		0x0C0DA3D358D6E199ULL,
		0xD8024E806906DCAAULL,
		0x8B28ED42B07F954BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x09543E19BC972BE7ULL,
		0xE0722904F9A7A1B4ULL,
		0x4116083E44011BCDULL,
		0x408526DBF8EAC7DEULL,
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
		0x4FCFC611EE741D2CULL,
		0x3F8AF690A0386C8EULL,
		0xAD6851D1A2818582ULL,
		0x124B62E826E5BA53ULL,
		0x898CB23239E2D72FULL,
		0xF893D368101DE94AULL,
		0x7908CCB880C78B4CULL,
		0x64EA226324D05964ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE937DBF695D85588ULL,
		0x29BBE6770A863B91ULL,
		0xA1173C728E782DF7ULL,
		0x96F29A677C7D87E5ULL,
		0x3CCE1DC48B488840ULL,
		0x2039F37334EF810CULL,
		0x7A51C252D66CC7A9ULL,
		0x1D32CF31628D4B2CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCAE1F2634383809AULL,
		0x33264E721E95AA3BULL,
		0xDB7CA0765D8261DDULL,
		0x208F21E3805C4EBDULL,
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
		0x6226BC1E0D28CC4CULL,
		0x2006448804D91966ULL,
		0x8BCBB2B2D5E6A89AULL,
		0x5A71C13889902137ULL,
		0x5BF11DD4A030301BULL,
		0x599A257EBCCF8F8FULL,
		0xF12FDE011478FD5CULL,
		0x4042BE7DEB38F875ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x289079B22EE8D90BULL,
		0xC4759D7D56E1D118ULL,
		0x599C652996CC3B64ULL,
		0xCA6CE3BCBCD38246ULL,
		0x350E3D4AACD92D47ULL,
		0x5A4BD3D05B2374C8ULL,
		0xE283B9AC9084310AULL,
		0x86E8A5E87E4EE5AFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFF4396E5FD2A5D17ULL,
		0x4130C6ED2D8341DDULL,
		0x5FBCB214D570C161ULL,
		0x136483A9F77B6857ULL,
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
		0x1F320FEF0C527DF3ULL,
		0x66D1B3ACC7D8AED9ULL,
		0xCF351DD72F8E2917ULL,
		0xDAC46301119582BBULL,
		0x00A38A55349B04C1ULL,
		0x6E49065714EF02A1ULL,
		0x3A36BB79D0EA344CULL,
		0x1774B54F06C8FC65ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAC454877AFCAB542ULL,
		0xA986FB028534FDAAULL,
		0xB2B8E8409C73A658ULL,
		0x4B3C7FE7925507D2ULL,
		0xDEF22562164B81E8ULL,
		0xF577CE818B9709F6ULL,
		0x05AE601CF26E5D2FULL,
		0x720469079D50101CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7341C38DDC5532F9ULL,
		0xAC59025CA5B29A6FULL,
		0xE8B9C55F997C70F8ULL,
		0x1E3335B327338DC6ULL,
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
		0x0EAB2B2CB1537912ULL,
		0x245406C93877EC87ULL,
		0x860BCE85C8A12845ULL,
		0x9F86A78A109EF1AEULL,
		0xF0D34C79EE02C63DULL,
		0xD8D6F82EEDD2D2F9ULL,
		0x1FC3068DF7B11AADULL,
		0x5F0EFDEE92E263BEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x10860FD37361C9FEULL,
		0x86A342DB00E8440AULL,
		0x7D34E11C4F44C281ULL,
		0x783C69AF7C9EB2B8ULL,
		0x18F0690C1C666343ULL,
		0x0114EFE02F27BA59ULL,
		0xA6916D506E3633ADULL,
		0xA5F74EF607F23CB3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x09D2DDA65B285EA1ULL,
		0xA47DFF9E84F5505DULL,
		0x0633AC8BE19AAFE3ULL,
		0x20CE36BF33A60A84ULL,
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
		0x0A190031841D5B06ULL,
		0xCD9D9C6623956574ULL,
		0x1C847213182437C5ULL,
		0x7AD90C5F40124D24ULL,
		0x0D40BBB8F41E2169ULL,
		0x6C711476245205CDULL,
		0xD88AC8758635B558ULL,
		0x87A3233B8DD0A674ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB0981FC4E85CF335ULL,
		0xF2156F2F02DD7B46ULL,
		0x15B7B2EF52860AB2ULL,
		0xA4584B5A22E89149ULL,
		0x8ACA9F90197FC465ULL,
		0x5DB656B0662E0F61ULL,
		0xF6655F9E07501087ULL,
		0x7B0BCF3519EC42E8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB7090E7D0F4236A2ULL,
		0x0B4058915A0E7E22ULL,
		0x985A4F209BB4A41BULL,
		0x34F739FA5110829EULL,
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
		0x6A491D824EBC9D88ULL,
		0xF8BF824FBAEEB982ULL,
		0xCAC0F98AC2B1132DULL,
		0x8DEFD882792FC5FEULL,
		0x7CE1562502BBD24EULL,
		0xE4A59A524CB947B6ULL,
		0xDE2DB50B90E36894ULL,
		0xAEA83327E1F5D558ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAC13633E03E15D5AULL,
		0xF2A95619935E0F5EULL,
		0x72DD3183799BC868ULL,
		0x3BA3E74D2D23EA21ULL,
		0xA4FE61385A18285AULL,
		0xB5D33966A2ADDAB6ULL,
		0xCDF7C3EA8422F9B9ULL,
		0x5D137A7A1EA682C9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC9E6156553267C2EULL,
		0xF9508F316542D81DULL,
		0xBFE592EF2DA5BF4DULL,
		0x6E5F5B0049D21D19ULL,
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
		0xF69E51CC221F36A5ULL,
		0x1F47EE856F015AFBULL,
		0x8B68666A8A950AC6ULL,
		0xDC99ACFC90F013EFULL,
		0xD1ECEA5977012EEAULL,
		0xEFC8C7C535413D95ULL,
		0x6691CFC3D6D0C280ULL,
		0xCA5728AF9DCFAE5EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x64D2559091BB8043ULL,
		0xBFD880BEE8E4EA8EULL,
		0x6D03156F5B29D7A5ULL,
		0xD858FE769BC5BCA0ULL,
		0xDA8EFA0DA9A620A1ULL,
		0x3F6E6240E14AF5A2ULL,
		0xA840848973F0173DULL,
		0xFDEEB9D289BDF7FAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x49BDA77C0BE7D408ULL,
		0x8CDA7F6AFCAB1E7EULL,
		0x5E767BA5DCC49F2CULL,
		0x5BC12356EFCB6A1DULL,
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
		0xD101A66779C54249ULL,
		0x4F5C56DF8DA6FEB9ULL,
		0x4A4BB0E69BDBCEB8ULL,
		0xE93D7E1EC5AC0972ULL,
		0x1B48719CE6B5964EULL,
		0x4033E233E60FE810ULL,
		0x2D3607B90D1942F2ULL,
		0xD389ECE92FD8E472ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1396D4E3BED27D20ULL,
		0x7971B61197B9BF9AULL,
		0x44F5AB86428BC7C6ULL,
		0x44C2AA1D38148570ULL,
		0x9828AD87418DC7E9ULL,
		0x900211B2B42068FEULL,
		0x5732B2FD66F045C7ULL,
		0x554CC3CD993E9F8DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3421ECBA3EDB6AF9ULL,
		0xFD4F93FB5F7A1BB9ULL,
		0xC9D4993B03659B47ULL,
		0x618EEE19E87DBDF9ULL,
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
		0xBB4BC262D83AFEE3ULL,
		0xBBE0CBB9FAC7D785ULL,
		0x33D805F3A5707DA9ULL,
		0xB41AE1EE139A75D8ULL,
		0xB45EC079F3BB53C8ULL,
		0xEFBDECC56DAE1864ULL,
		0xE9CD7EB24271682DULL,
		0xDE41FE17DFAB14FDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x00F6C0A4ED850A6FULL,
		0x93871AC7C87A1C44ULL,
		0x754A37D5CAD00E7AULL,
		0x2B7071A75E64FED9ULL,
		0x6E02B154F237D7D7ULL,
		0x9187A649941EED79ULL,
		0xFFFFFABE8D1D44A7ULL,
		0xAC852BC64C963BE9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2BFF413C243A5B57ULL,
		0x246827547D8E1A2EULL,
		0x730F644AC51DB521ULL,
		0x6AB1A8628A4DAFF3ULL,
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
		0xB8A3BA15717134B5ULL,
		0x777DC61CD3524889ULL,
		0xDE1A2B760B90AF1BULL,
		0x8AADFD7928AE6B27ULL,
		0x88671C53616533D0ULL,
		0xF694B745415E7DE6ULL,
		0x8DD3D89A3A9D0515ULL,
		0x17A5F6B204BA994BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x29628661CD2B8B9FULL,
		0x5CD1D85C77FD334DULL,
		0x788A211F60F6AEE7ULL,
		0x2354EC926C9FFD57ULL,
		0x8F92E9445BDF219DULL,
		0x9000BB47710C1AA9ULL,
		0xD677D3049980BD5BULL,
		0xCB1BD8481ABF00F1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7EC0C7EE762C58B9ULL,
		0x54A3556D478FD049ULL,
		0x9D38DE8C94CCA5DFULL,
		0x43D9949F77670B21ULL,
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
		0x87CC0D4910FFADC9ULL,
		0xB7DC432FF6F7EE32ULL,
		0xCE018BDFDCC486E6ULL,
		0xFDC87C7FAEF47817ULL,
		0x25CD1A0726C53E0AULL,
		0xDD55B50FA3A58109ULL,
		0x717998FF354704FCULL,
		0x612EDC0EB7BB0ECCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x28D479D28BA5A068ULL,
		0xCF9F4DC09F6FEC05ULL,
		0xE6B862A9D8004AC8ULL,
		0x4376B8341EADBB2EULL,
		0x7ED115F9548E3EACULL,
		0x26C7CCDD8BB21E7AULL,
		0x9333CC019004141BULL,
		0xD0B1FE9FE28BFC23ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x28602D83B983F2F5ULL,
		0x014D6CDEE5A8A35AULL,
		0xE5A596DC8CB3FD9FULL,
		0x2CDAA2BF354381F9ULL,
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
		0x2D5C0656452ADB02ULL,
		0xE8CE16D7A7E24291ULL,
		0x75940086C85CBB1EULL,
		0x73247B4A23B8BF1BULL,
		0xDCFADE6411E2BE0CULL,
		0x56FBA89AAB426AE0ULL,
		0x74AEE317761215F7ULL,
		0xF0DB178F400084A2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x878FFCB9C73A350AULL,
		0x9AB1B1617803837CULL,
		0x73A881F952F3879FULL,
		0x25312C75E69BA80BULL,
		0x52D5695867873AF3ULL,
		0x84A26B04128E4898ULL,
		0x555B89AFB1BB4B22ULL,
		0x39A2EDC381ABD6FEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x275B6957C7861FC3ULL,
		0x875B89D0DA9BD5D9ULL,
		0xA84AC3F49A4B4F16ULL,
		0x004983127DAEDD6CULL,
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
		0x5E804819F4C0ACD8ULL,
		0x9740BCB0867A1EC2ULL,
		0x5C43E35951C98FE2ULL,
		0x27F89090C7DC17F9ULL,
		0xA368F4202CFE1523ULL,
		0x78ACD75C82E453BBULL,
		0xE3D129564F5326FCULL,
		0xEBBE6F25700403CBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD993123DDF1F2B73ULL,
		0xBBE58C30AE345EE3ULL,
		0x28BC1B941E831C48ULL,
		0x9914ACFFDD061F83ULL,
		0x4DB7CBC3E5BA68CEULL,
		0xD8F2AABC1912A788ULL,
		0x2FC28AA8A84ED531ULL,
		0xBD0D6DF630ED68CBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3D39338EA9AD16E7ULL,
		0x90FDD04F8D654F7DULL,
		0xEDB3558BFDEA97ADULL,
		0x7D2A10944830FA90ULL,
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
		0xDB6D56037C69A244ULL,
		0x28869C582514619FULL,
		0x38DBBAA3F4F439A6ULL,
		0xD6CAF022835DC57CULL,
		0xD0BFADE1E8C42443ULL,
		0x6888E0C72AE18C15ULL,
		0x613DBD4F664D0435ULL,
		0xB43465F33D11A53BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2EEA36CF2C57FBE4ULL,
		0xB65195404B507B1AULL,
		0xF7D9EF27A5AE27EBULL,
		0x85096E852059924BULL,
		0x5BA3C7E0BCE69995ULL,
		0x6D3FC3217175FD8BULL,
		0x196819218EF1C53DULL,
		0x1F084AEEE3675229ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0EA74360D2F43F78ULL,
		0xBF0F6DB15FBB0F13ULL,
		0xEAB82A4A46D16A89ULL,
		0x764D8442B24C87E6ULL,
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
		0xA94A7F2392811E1BULL,
		0x39857EC7337CB23FULL,
		0xCAFC49B6F1670DF4ULL,
		0xCFE9C2B514289A1CULL,
		0x19C6E1631F42B1E3ULL,
		0xB034313FF6D141D5ULL,
		0x4E2F5D179D8EF59DULL,
		0xA10DFC40D8A9E143ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB535EC7580CC1E77ULL,
		0xCE91053E1F47E8FAULL,
		0xA641554DDE059AC2ULL,
		0xEF8A86AE66986315ULL,
		0x84A833F0F9331E70ULL,
		0xCE9B8EAE2016B8F4ULL,
		0xC4D3A857E99B7480ULL,
		0xD22CA7E27318CB92ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x16A2519FB804E199ULL,
		0xE79C9B2EF3E51A9BULL,
		0x8857C8DDC9869D7AULL,
		0x15D1C209C1196F3BULL,
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
		0x128E60F72B319273ULL,
		0xC452893BBDA8E31BULL,
		0xA1B84DCACDAFDB0EULL,
		0x93BF93413A751DBEULL,
		0x3C45ABD27CF2D0C8ULL,
		0x5F60E211C343BA32ULL,
		0xD5754F52AAC3B210ULL,
		0xEEC77229BDF98506ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x36571104B9D3A593ULL,
		0x9E83206719D3188DULL,
		0x8D621FCBF5B24A54ULL,
		0x1635DB9B7327FD41ULL,
		0xB2E23A539167AD64ULL,
		0xA740AE28BCF6A4E8ULL,
		0x8357ECE130FAB9DBULL,
		0xF763FBE1C50DE019ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x40FA28C968052D92ULL,
		0x7A971D6B9346F378ULL,
		0x44B2CAD6EBD2688DULL,
		0x364D4654BA479BB7ULL,
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
		0x06D286ECCE6E9D53ULL,
		0x397359A6A0C1EC43ULL,
		0xF3DAE5F5DFF7A84AULL,
		0xB8E6E90D25A67309ULL,
		0x9B5694C5F4DDF96AULL,
		0x93037F9D8C356582ULL,
		0x76A093E2897344A4ULL,
		0x6AF5914879DE3FCAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0D2500FF1FABE937ULL,
		0x2E01DBEB461FD69CULL,
		0x4389D7FE53AC2A9FULL,
		0x3195A876137EC92CULL,
		0x960D56338349185FULL,
		0x522858466E07C84FULL,
		0x933F048B60206955ULL,
		0xE9CEF6D6870C49A2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC28CCFAA8ADC18FFULL,
		0xABF954A9D5676B39ULL,
		0x70CC54E7AE980B6EULL,
		0x330C2D811D5233C9ULL,
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
		0x6176BFCA59145575ULL,
		0xCF5BA4B1D17E4814ULL,
		0x28566988CB11A80FULL,
		0xC4E467316BEA6794ULL,
		0x190E4B568B434F3AULL,
		0x36D1BE7D0F99C023ULL,
		0xDBC68139D64BA88BULL,
		0x9232B26D66017FCEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6D17EFEA290A5AE3ULL,
		0x07E8AF38BF3151F7ULL,
		0xFD8D295F12B96407ULL,
		0x81292E6B23E475ACULL,
		0xA772804A21FDFA7AULL,
		0x5B210671A1EA60CFULL,
		0xB8D8AA104BFA31A8ULL,
		0xDDAB682968406B1CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD17EF3B7D0548D70ULL,
		0x63AE472B5A551C7FULL,
		0x5A173054406FE9B5ULL,
		0x0FD03EDDF2AF0458ULL,
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
		0xD2E64BB88F033041ULL,
		0x2A939B9B75BA799FULL,
		0xCE4C415C09EB9ADCULL,
		0xEDE26CA0A2191467ULL,
		0xA5CAD806D5491762ULL,
		0x97F2D1D16FA74882ULL,
		0x12F9993DAA60514EULL,
		0xD23D29AF74B749E7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8FC83702892B1FAEULL,
		0x9C3AC279674C94E8ULL,
		0x59F2B79BB4A17D63ULL,
		0x9A6B7D6870F26E98ULL,
		0x4E7BF0121C730B86ULL,
		0xB4533628804169C1ULL,
		0xE10D2882B2341E0DULL,
		0xAAD2096619B52730ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x38D48309759DD41FULL,
		0x5809F435978CF56AULL,
		0xDD7245812BD9B91AULL,
		0x2D5DBA1BB377CCDAULL,
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
		0x273EFAF699B9F188ULL,
		0x1EB9202805F2D11DULL,
		0xC1600C510A79D652ULL,
		0xCA7B663A0E9E2AE9ULL,
		0x53362015FA89C285ULL,
		0x56AD7002CE759BD2ULL,
		0xE874C0B540CBD088ULL,
		0xCFDACC8F5B32D87FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5CAFDFE83FFE8C2CULL,
		0x5FA240047B1ABE7CULL,
		0x1D16D35ED3552D09ULL,
		0x9502F28A8F83FBDDULL,
		0xA62386AC9DD19FEEULL,
		0x6AF936A9AB71D289ULL,
		0xFDF977D3C6E869A0ULL,
		0x33C7F62CA68E0986ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7B51E0B21D108B30ULL,
		0xBBD7635EBD67F36AULL,
		0x72960A6A4EE5EFB5ULL,
		0x604446564F90E7FFULL,
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
		0xE1BFD94EB38D11A6ULL,
		0xDDD86015B17EBCA6ULL,
		0xE8EB7754F6AC2FE1ULL,
		0xC69991BDC331AD98ULL,
		0xF14AE76B95CE5014ULL,
		0xF41183A672F959D0ULL,
		0x7FDE715DC843A174ULL,
		0xED3DD5A33AB6AD36ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x60732A4B0FEBF171ULL,
		0x6A66FC591B12BD77ULL,
		0x9F53EE3AC9300250ULL,
		0x70E93B712F6831DCULL,
		0x34AB6A29282B154FULL,
		0xF3A8E6E7064013DBULL,
		0x83BDACA4B5C41DDCULL,
		0xB3067A1165327A1DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x80F946DFE9DBDAB6ULL,
		0x82F8A826B9EC61A9ULL,
		0xB674BC92EC69B621ULL,
		0x79E7EDF245691171ULL,
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
		0x9A1F86271FD2918DULL,
		0x178825F2AF10A8D8ULL,
		0x18FB32E775DD2021ULL,
		0x3D1781907FDA6E03ULL,
		0x6121365EE27CAE9BULL,
		0x49CF135CF6ABAB8DULL,
		0x40411C6F8D2E45DFULL,
		0x4E5CE7DA15B39BBEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB3A1089F026C62D6ULL,
		0xFE21F8FF484B171DULL,
		0xB34FE05E27768E21ULL,
		0x073CA4F6D0DF4475ULL,
		0x08139FFAAEAFAF08ULL,
		0x351CE58975857F8FULL,
		0x9425BED314B1E545ULL,
		0xC177C8AA0C7DC2DEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1E82D067CDD41C03ULL,
		0x2BD8FA589270197CULL,
		0xF1BB37C330DCE8DEULL,
		0x1FDD7DBB0CF95AC0ULL,
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
		0x874E547DCB3F96D6ULL,
		0xE736E599C5986737ULL,
		0xC5DB1D647804F4EBULL,
		0xA3F1CB6D26491A60ULL,
		0x5168F63007345886ULL,
		0xFE60ADB69D811C20ULL,
		0xC0742412B7C81103ULL,
		0xE62C8F41739C6724ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3B0E717649DBDDBAULL,
		0x51902BF56D45F56EULL,
		0x79043A3C4AB1987EULL,
		0x52BB85412127A232ULL,
		0x7D55CB5BB28A9957ULL,
		0x7038A39AC327785BULL,
		0x6BC1266F4096FB30ULL,
		0x17A4C656156CDEF5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC7183E8C12961E9DULL,
		0xAF9839C6C1A0C100ULL,
		0xDF68896BDE9C99D4ULL,
		0x795E191C002FAF34ULL,
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
		0xBDFA057573EAA9B7ULL,
		0xBA6769B07E69C193ULL,
		0xD9D63440EC6EF72BULL,
		0x6D8F773050DAC555ULL,
		0xF53E2EAE12BCA634ULL,
		0x73DB11F228E026D7ULL,
		0x0380FC41FAACC688ULL,
		0x9377DF6547976CF4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB8B5285165C91BA3ULL,
		0x5B1F44B5A60115B5ULL,
		0xA91B5E84F8334BA3ULL,
		0x1CFFFBB566D28DA2ULL,
		0x4BF1CD23FFA449C8ULL,
		0x5D5EF0F0BDE7545FULL,
		0x26580D916DAF2230ULL,
		0x307C51530F15DAA0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x269B57A2E3BF4856ULL,
		0xB5B50B30B957E9C7ULL,
		0x04CE43F0E1E2109BULL,
		0x01E6922F4D43F026ULL,
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
		0x725C954E07949599ULL,
		0xB48945DBCE3BEB37ULL,
		0x6D4C7721EEE2F227ULL,
		0xBBC58CEEA4F14B34ULL,
		0x389A95F492D9513AULL,
		0x70BF0DACC4821286ULL,
		0x68842A242F7DD609ULL,
		0x7566EE93A3892E10ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCBCA73606071BD15ULL,
		0xB07AAD3F5650900CULL,
		0x1DAE0C83A809F7B0ULL,
		0xE3F35C6CB481225EULL,
		0x3C0329509B652462ULL,
		0x45B0B97669906C71ULL,
		0x45A41347A1EBB5E5ULL,
		0xC1FF0031A2C1E046ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x250C424462617ECCULL,
		0x682F18ADF7CA0248ULL,
		0x7CE1CF5B4A89BFD5ULL,
		0x793F930E0E05B4D7ULL,
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
		0x0E4D271B8098D9D4ULL,
		0x223FF189D11E07D4ULL,
		0x6E1C22CB518FB0F8ULL,
		0xB6D89F7E6246E175ULL,
		0x53FD2119246FAB5EULL,
		0xAE59BCF759581A4EULL,
		0x8F546A0E2073D1AAULL,
		0x8F3A1AC0FF3BE5B5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x48E45FE7F874AD6BULL,
		0x4A3B839B3F21B342ULL,
		0x31CF1B289C583DBEULL,
		0x226989C4CC286F10ULL,
		0x16EC2B74B776EBABULL,
		0x27B1E6A59E77FAFDULL,
		0x4582202E1FC5E3C7ULL,
		0x8DCF3FEC82B6BA0CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD5ED3D9BB510A10EULL,
		0xD4EE3E104F40FAA0ULL,
		0x3183FEE2CF08C2FFULL,
		0x4A4B914411E2ED86ULL,
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
		0x4405808EFE58F54CULL,
		0x77DB862E831C04B1ULL,
		0x6AB9E6EE976C7835ULL,
		0xC310D16C3BAF555DULL,
		0xBF2AC935EDEC48A5ULL,
		0x6A53B313283A2CA7ULL,
		0xA9BE2DAACD185492ULL,
		0xBB3F4C69924DDF67ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3567D902FE1AF0B4ULL,
		0xB0E84A4E74F35588ULL,
		0x52D28C4215B8D4DEULL,
		0x28D2499048A706E4ULL,
		0x9F5053E00F7C68AAULL,
		0x87E781F05069C246ULL,
		0xB901159E6C0F8F5DULL,
		0x0D2C571BD35FD405ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC90B124B04D947B6ULL,
		0x6302870C17187993ULL,
		0xD3F8EC82E900E930ULL,
		0x710EF1664A5DFF02ULL,
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
		0x5EE232EE63CB39DCULL,
		0xA871A5EB61D3D286ULL,
		0x0143A8538C8B139EULL,
		0x88BD6E69399DB89BULL,
		0x4FDB0490E86BA6BBULL,
		0x5667A74A0EF300B7ULL,
		0x8EBC4AA08CF01294ULL,
		0x565A2E8D8CF2D351ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEB6A20DB076A6061ULL,
		0xF9F92E86D0E5D835ULL,
		0xAB0AE46EF013BED8ULL,
		0x73A107AE38E1B68CULL,
		0x81F1AF74248FEFFAULL,
		0xD2259BD43147880FULL,
		0x7BD72DBC65EA1910ULL,
		0x2D47E2FBA9D3557AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x041AB4586EFDFB05ULL,
		0x50462AE37861E339ULL,
		0x243B0DC2675A5E4BULL,
		0x2DD39E62B768AFFBULL,
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
		0x11C1648CEBCD07FDULL,
		0x46567D424C91062EULL,
		0x2018AFBAAB519EF7ULL,
		0xC1AF79595AE9A29EULL,
		0xD4B5E82EB86D7AA8ULL,
		0xBB45A66CB3746B1CULL,
		0xC15B8317B57E91A9ULL,
		0xB7B4C74D84E4B9A5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC202707565322724ULL,
		0x0974BE6689B86B02ULL,
		0x66856D28011A1649ULL,
		0x3EEE5DC395397950ULL,
		0xCECE3969A0BE6B07ULL,
		0x45977C9FA264F0D0ULL,
		0x786B098684A6EDE9ULL,
		0xDF3CCBC5343DBDE5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3022E5590A9731EEULL,
		0xB4BBF34C4B24C274ULL,
		0x8D454E1FEA39D73FULL,
		0x249071D1BE7987D8ULL,
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
		0x83628F892EBD2F60ULL,
		0xFB98F5124525560AULL,
		0xE46B8073139C0397ULL,
		0x5DB4EBFB33FD9348ULL,
		0x7C28E244C5905026ULL,
		0x6D826376848AFCD0ULL,
		0xD81B9BE91A50C6BBULL,
		0x23F7483E112642A0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x40A916A77673E607ULL,
		0x7C6B08B4527B7471ULL,
		0x8A578DFF58798044ULL,
		0xC928BACCCC754C4AULL,
		0xC2E7363268703F92ULL,
		0xCF8A4B819CEAB631ULL,
		0xB03ABD8D7F7ED488ULL,
		0xD04C1E06659920D9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC279039B8B0BBB62ULL,
		0xF2017AB854745D28ULL,
		0x4574F40CB64C76D6ULL,
		0x7FF47571DE7B4A8EULL,
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
		0x1D8B99EA344584F4ULL,
		0xD9C88D5B6EA04EC4ULL,
		0x13ABD0A8FFE559B1ULL,
		0x075D4CA99C562C08ULL,
		0x08F4E895003A6314ULL,
		0x52F2AAAAEAC2381CULL,
		0x9B35E82282AB0324ULL,
		0xFC1C6749A04219C4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC873D7B019AB4942ULL,
		0xCC42C04CD93437CEULL,
		0x43D02A7B808AA526ULL,
		0xE76D0C4E0FFD228CULL,
		0x8D784E1927985D09ULL,
		0x897B6C8608296912ULL,
		0xB328E074528E6C2BULL,
		0xAA14F5F58B9D1CDCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA996B09C42A722F6ULL,
		0xF5390688381AD25DULL,
		0x41CACA08A3991D78ULL,
		0x4D0B12D69CD693E8ULL,
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
		0x272C965920FE635CULL,
		0x5E1522A8822DE761ULL,
		0x4EFF4A9028FEA9AFULL,
		0xB6ED312DB59A6E0AULL,
		0x3E78674BB11DA783ULL,
		0x799D894D15985E26ULL,
		0xB44505B45AB95F40ULL,
		0x780DF321C7BE1979ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD63379D0DF65B109ULL,
		0xD11CEDCFC3E4D783ULL,
		0x1160460EE24BB364ULL,
		0x29F9DDC29DE5B36FULL,
		0xE03C9B39AAC3A6ECULL,
		0xFFD33A9265CA6499ULL,
		0xAAE023C8A99BEC67ULL,
		0x9AD3187166183EB0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4DD9673532F4C7FFULL,
		0xA0FFE48ED6DC1AB3ULL,
		0xA2988D7D9112026CULL,
		0x63AFC99996533472ULL,
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
		0x0182ABA1906E5510ULL,
		0xF76331DEE2921C87ULL,
		0x6B6F0DA96A7F7A0AULL,
		0x7B652FDB7BE38E23ULL,
		0xA5C92439490CEED8ULL,
		0x1ABA93FA23AC012AULL,
		0x920AA6E2C527C54AULL,
		0x2820589137EA3681ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAEDFF12176C6D006ULL,
		0xBAF56E0F2F5290EFULL,
		0xFC40ECC620934FB9ULL,
		0x367C048E95D2B2A9ULL,
		0xE4C67A746043B22CULL,
		0x9CB4D3412BA93ACFULL,
		0x448024BFCD5A8F19ULL,
		0x20E5DD7EB0CCDA85ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF907EDBAA78686B8ULL,
		0xF1485F4483A8FD0FULL,
		0xF1BD721412623583ULL,
		0x5797700CF46C82ECULL,
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
		0x69E210F799FFA182ULL,
		0xBA35C3172D672BE5ULL,
		0xB39825B75B6AAF34ULL,
		0x418E3FDBA0BB909CULL,
		0xB058F2CB30D058F0ULL,
		0x4813479310E3C56EULL,
		0xB7B85776B5576D9EULL,
		0xE0A91B2A6B5B098EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x37764410D19F655AULL,
		0x1497CEC8900B023EULL,
		0xA317BF33038C5C35ULL,
		0x80ED8652F675D28EULL,
		0x8C5A64E2CB5A4860ULL,
		0xB3E9C6396C11CFF0ULL,
		0x79828E81BDE8D900ULL,
		0x3C629564F89681A4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8A34DD65D7E6B518ULL,
		0xA3C7279D14869A60ULL,
		0x4C7C3AE112486263ULL,
		0x231894D7B371EAD3ULL,
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
		0x898988AC97AFB2A9ULL,
		0x68BB9D6189871CB5ULL,
		0x6176367F99F5A805ULL,
		0xF99793C705805478ULL,
		0xBA12DC40A2FC6818ULL,
		0x554D1701F9CD39F8ULL,
		0xCD4A0EF36ADF6CE9ULL,
		0x35B028126BDE4C99ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0D00A955D26E7ABEULL,
		0x3516A18C9217BF00ULL,
		0x7C87127C69088ED8ULL,
		0x89726F3370686BFCULL,
		0xE805AA0DCAF7EBF9ULL,
		0xCAEBE57AD19ED0CCULL,
		0x3D9D4205DE97F123ULL,
		0x52C888EB6C7FA1C7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAA7E52E2D5EBA3EDULL,
		0xBE1255E4EE52FA36ULL,
		0x38958F460389787FULL,
		0x1E86C45D7D2543BDULL,
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
		0xEB9CD6D5A05A9157ULL,
		0xAA8060325EEF2C32ULL,
		0xA31D78401A967CD0ULL,
		0x68C2D28423AC5BFEULL,
		0x2A1DAE090A1E63C7ULL,
		0xBC06AD49FB13480AULL,
		0xAB86D10D95A11371ULL,
		0xAF44250A055046B5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x58E0505DC3094166ULL,
		0x2C0EB770D4E908E7ULL,
		0xB166954C209291D9ULL,
		0x7759DCB70A2D4563ULL,
		0xD352CA4DC81DCECFULL,
		0xF5A3F13CCFE8B96CULL,
		0x0EB15332436B98ECULL,
		0x757BE6F95CEAE27AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x74DA5443A9676E04ULL,
		0xF11992B5F2574EA6ULL,
		0x396791822DF41AACULL,
		0x05222C46188BF774ULL,
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
		0x1D49E5BC311322CAULL,
		0x3DF3FCC0ABCBD344ULL,
		0xF24C41E9179B0C39ULL,
		0x5A138CF2D6B9DDDAULL,
		0x54A0C7B1F8DE87CFULL,
		0xFA1AC763FA8BD552ULL,
		0x570EC441F63E41E3ULL,
		0x03CEAD44CDF62479ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC2CCADF6BDFA41D3ULL,
		0x772EEEBC3EA3FD18ULL,
		0x0155078D94A08262ULL,
		0x55A5980F6696F046ULL,
		0xE5A0F69D325FE037ULL,
		0x4B7C48D4CFDFE79CULL,
		0x7ABB2D0209942F0AULL,
		0xA943C1171A132DD7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD47640DAE9E5BDD1ULL,
		0xB24BD744C2AD1F19ULL,
		0xA55FADD8A4395626ULL,
		0x750D03AC23D3899BULL,
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
		0x244FA3714A68708EULL,
		0xF4290CFB2E759320ULL,
		0x65C2D2BF27481144ULL,
		0x2632B7861C4E136AULL,
		0x9B1404C2555A2516ULL,
		0x6B9DE89FFDE9F618ULL,
		0x8F648DBAFE6E4BE9ULL,
		0xB78AC7EC45E5700EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD82B29E6A65B6DF0ULL,
		0xE01247B6F43F1557ULL,
		0x258D5B9905B3192EULL,
		0x0AB5CFF8C3179C75ULL,
		0xBA790BD18B1FE8BBULL,
		0xF958F79BE13D5E8CULL,
		0xC20D1437A546CA17ULL,
		0xA5A8B61038F0533DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA3256D48A8B1F87FULL,
		0x0A528BE07BD4FC8BULL,
		0xBB3180A55D723D2DULL,
		0x430B8E374598BDF3ULL,
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
		0x75D2DC5BFCF0C5FAULL,
		0xDB711013AC732E5EULL,
		0xE6FDEE07D7837608ULL,
		0x9AA6F2BD9459140BULL,
		0xCE8C8067924BED7BULL,
		0x89A045A5DE4BEB9AULL,
		0x45C87A9553D6E400ULL,
		0x86B32F780E08F1C1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0DEF7B9D25E1E148ULL,
		0x47504C6277B7D7C5ULL,
		0x99F75169920E83D2ULL,
		0x046C5D3EA280727AULL,
		0x113BA0F612D8BDC5ULL,
		0x196A46DB2E97268DULL,
		0x371ACEFD379B2ECDULL,
		0x653F1F2EC60FE250ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x81E48B97C227FA87ULL,
		0x3C2495C7499096A3ULL,
		0x7ACE15327651D7D9ULL,
		0x0D75005FA0D0EC59ULL,
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
		0xBADEA015F4FA15A6ULL,
		0x2E6456356634A0F7ULL,
		0x37FCE882E17A081BULL,
		0xD65678846CBDD905ULL,
		0x95EBA982A94276F9ULL,
		0xEC26EF1F69D14DF4ULL,
		0x47EDF4210B0EA29EULL,
		0x78F205DD92C659CBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x594EAC5DA1EAE783ULL,
		0x81D8F464E88C3BCBULL,
		0x197AD3867679383FULL,
		0x8DBD2781AE524AA2ULL,
		0xBF6896799ED420F6ULL,
		0x8654CE52D526CB89ULL,
		0x48363725F854B7CCULL,
		0x29E89AF9EB2900D0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3904C70FDF6FF45DULL,
		0xC9BC402E8EF7C108ULL,
		0x13C822413299AB16ULL,
		0x03FF2ECD9FC6C3A5ULL,
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
		0x78142CE32464906DULL,
		0x306296EBC056A632ULL,
		0x639824D9261F4B36ULL,
		0xA6EC6EB7351103BBULL,
		0x78CB9F65299A053FULL,
		0x5C8487BA2C7168E2ULL,
		0x2E615A6FBAF40685ULL,
		0x21023FF762AB871CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1BFE112959B841EFULL,
		0xD93EAC5967692ED2ULL,
		0xE1C4AEBEC2382226ULL,
		0x1D04C4DC6E0CD70DULL,
		0x714EC4DA6257C8A1ULL,
		0xBEFF960A94D36A0AULL,
		0x3F1E20DA4AB23BEEULL,
		0xFADFC8AB10E6A59CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x789E8C535E814932ULL,
		0xB8DFCAA2DA614B71ULL,
		0x05CE02490DAB3B6AULL,
		0x33055F2EEA3DA5ABULL,
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
		0x2B6A561C5A98FCF5ULL,
		0xA881839C4588C02CULL,
		0xDEA77495C7B57C25ULL,
		0x1B624231FB8E5239ULL,
		0x43B4184BDBA8ABB7ULL,
		0x05135CDE6052F051ULL,
		0x3A746CFF895669FCULL,
		0x3D635A036329FB23ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2989962DF00452F7ULL,
		0xED2E389BA403A21DULL,
		0x6D4775AD322B3416ULL,
		0xD5D8FD892065C411ULL,
		0xE33557C2EBD48B54ULL,
		0x9035FF7159BCCEDEULL,
		0xB6BD716CDA6E8D50ULL,
		0xFA66BBB017326CA0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x54B1544204117462ULL,
		0x142F292F9BCE1509ULL,
		0xFE8956AE8BF50982ULL,
		0x3708C50621E7B587ULL,
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
		0xE9258F07B63AC73FULL,
		0x5E545F3D3DB91DF6ULL,
		0x8B82F0942D941D60ULL,
		0x775E60187814C5A0ULL,
		0x04D1D2E86151761DULL,
		0x14F274B66BC1E88EULL,
		0xF87199CC97921AE5ULL,
		0xDDED2A84D3819AB7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x84D17CD8953E3E2FULL,
		0xF388275E54F7D032ULL,
		0x126429356596735AULL,
		0xF180F0100A073C1BULL,
		0x1C3E4F507051F4B1ULL,
		0x6F29B3D3793F18ACULL,
		0x54AD4575611F4587ULL,
		0x873CE9983D018781ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEA399ABCE6E9C0E0ULL,
		0x0698D98EE82C294CULL,
		0xC8434C50DD0955ECULL,
		0x64071326C51063A1ULL,
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
		0x84FD67251AE6C819ULL,
		0xE0F3E5A541285E54ULL,
		0x76D07EC0B7BB90A8ULL,
		0xCFDEFC3194D1DD04ULL,
		0xA49135436BEBDDAFULL,
		0x29DF5BE237F278D0ULL,
		0xC1224E4A95DDD42DULL,
		0x3FD924A48B37A48EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x54E23769C726F0E7ULL,
		0x3C5440B7E52BE988ULL,
		0xDB54A0283234BB71ULL,
		0x24E575B570B11B94ULL,
		0x84B965D7E2C60600ULL,
		0x2539ABCC9C1A6261ULL,
		0x3AF0B067E46C1AE5ULL,
		0x8094BF8EC70F62ADULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEA23F9B1AF5DD9D6ULL,
		0x5537C8227E0FC94AULL,
		0x86D94E3EDC6855E8ULL,
		0x0F2087B7421A88E9ULL,
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
		0x562718162FBA7C0BULL,
		0xBB2ACE8705CEC2E4ULL,
		0xE2EDAF709322F35EULL,
		0x100944401F7CA066ULL,
		0x8E1CFCFD3D4743B6ULL,
		0xE7688295B01317CAULL,
		0x0F59C6067F873571ULL,
		0x9B6C52D0A53C87D9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x928E18DD827A3CB9ULL,
		0x9650B77FA4F1AB78ULL,
		0xCB08CA2170B99B2DULL,
		0x443DE92F7A66084FULL,
		0x3FBDA153EF028A49ULL,
		0x52768AF323A9764FULL,
		0x864E96AD42AD45C9ULL,
		0xDC861515EC917AA7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x65C09A5A4B73C404ULL,
		0x40C4D928388B0FB9ULL,
		0x6F8DEC8E2AC2EB37ULL,
		0x21F884C80E7A8D71ULL,
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
		0x3932AD88638FBA71ULL,
		0x4E711947989FC1DEULL,
		0xE2AEC22D17E13BBAULL,
		0x3B52E6CE09BF64C6ULL,
		0x73D89B5B2AE8DBA5ULL,
		0xEE43D8ABB9547DA5ULL,
		0x750551108F84D902ULL,
		0x4E2367D90CA0EF6AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8CC3DEC8958BC782ULL,
		0x6BAB70E46D577924ULL,
		0xCE8739D2D71E7648ULL,
		0x1695EE9B734F8CF8ULL,
		0xEF3D7A0185B738C6ULL,
		0xAEE60169DC86FE07ULL,
		0xE92142D3BA4DD889ULL,
		0x45FFCC04378B00F9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5B75C20E5362202FULL,
		0x4AB39C29F1C93A1BULL,
		0xD801A561E6ECD771ULL,
		0x5A0619CA37B13C82ULL,
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
		0x17468A11254D1485ULL,
		0x64B5E024C5C1CC62ULL,
		0x9CCE056FA6FF03AFULL,
		0x7E5CB2614CAC0655ULL,
		0xB12BC50708DE0519ULL,
		0x51A8976CC9158F10ULL,
		0x55BA860739146AD2ULL,
		0x7DBDB36C75ACF755ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x817E5195A4C65E89ULL,
		0x0485AECF018D81B9ULL,
		0x1AC0346F7A8A8524ULL,
		0x45CEF2C2254ABFAAULL,
		0x98FBA64DFEC1ED12ULL,
		0xF5944AF259D50A7BULL,
		0xD2FE8B09C775DD39ULL,
		0x3A8A2E2F2D38488DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2CECC7F300B24882ULL,
		0x0B338B8247C7F8CAULL,
		0xE9F5129F09FD8329ULL,
		0x323386B7E8B33848ULL,
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
		0x8E68EE869286F980ULL,
		0xF96F8608182022F7ULL,
		0xA9A6985D291276F4ULL,
		0x70CCB9AE9C66B480ULL,
		0x09C00E69D74A8E69ULL,
		0x7838DCAB6CC1FED2ULL,
		0xD243A96937B8655DULL,
		0x3251FBAB4F72CA5BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE7A36C5BF7A4E160ULL,
		0x1460A04854DE012BULL,
		0x6AA32BFB8E70DFDDULL,
		0xF5ED5C03F1A89B2CULL,
		0xB419476139FC16F1ULL,
		0x02A0662E01A90AE9ULL,
		0xAD29D873A553583DULL,
		0xC236CBB22F27EF2CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5D870D71F487D0ACULL,
		0x59B07C5DA8F65648ULL,
		0xC0D870D555A189E9ULL,
		0x1EE87CA575DAA253ULL,
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
		0x16BE0CF5D2AA268DULL,
		0x615B0D8BDF8C666BULL,
		0xA7DC867F5618F344ULL,
		0x67723D8045F558B4ULL,
		0xDF09D2354EA1B430ULL,
		0x9571EE611C478985ULL,
		0xD68BE85B9C34C165ULL,
		0x4C61DB168968D40CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4264F55876EC8978ULL,
		0xD6CE04FD6BA05749ULL,
		0x1DB20E6A1799E814ULL,
		0x20BB5093CBBB6AF5ULL,
		0x4BEECC8A99B7B2FFULL,
		0xA19DD0110059242BULL,
		0x5B97F560816C152AULL,
		0xD98934A466A9A73EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAA5BEEF43679C73DULL,
		0xBC098872994F1A93ULL,
		0xCA60895B38489BEFULL,
		0x52DFA1DDA29A9465ULL,
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
		0x556100CA85C8FFB7ULL,
		0xBFF5CFA867AA7E94ULL,
		0x855B2CEC1BE43C82ULL,
		0x70D57977ED9B160DULL,
		0xC791C204D08EB09BULL,
		0x4C96B84E435969E8ULL,
		0x5FFDE1D7AC0CF0DEULL,
		0x27BBAB5D1A5C921EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5DC8CA93A626611DULL,
		0x504B791F71A4E10BULL,
		0xD3D4447D51FCB332ULL,
		0x985F39251B79E65DULL,
		0xFCDF29FBF38B9953ULL,
		0x346AC0B1C51EA7BCULL,
		0x09A3696160607BB9ULL,
		0xE7CF5EEE72EB5C4DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0E1AC787AE180EFCULL,
		0x063117C3B2BE7009ULL,
		0x82F4C9FE0580ECD2ULL,
		0x558998BFACEF2CC2ULL,
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
		0x20FBC0FE8F1DE84FULL,
		0xBC0AE2207E372E3DULL,
		0xF5829F07EF7E6142ULL,
		0x2B068430C6FFE6E5ULL,
		0x5244C864A9B8DB30ULL,
		0x0B06D9D0695A93B5ULL,
		0x3B6AC82B7B424968ULL,
		0xDFFF5E9DFC748879ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1CFECF40E0E26D73ULL,
		0x7AC5EA5746551C58ULL,
		0x827788E96EC129FFULL,
		0x90A927345BC227D0ULL,
		0xF9F0912D95579282ULL,
		0xE7F1DA3AFA43C109ULL,
		0x63326C6054B8CCC5ULL,
		0xC4C2E5A61FDACE2CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x207D23EAB4AC4535ULL,
		0x7662E7F7B5455754ULL,
		0x8B68B6463925B754ULL,
		0x255751C72A0F667DULL,
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
		0x381EA71DB5E9F5C6ULL,
		0x0BD71822CD10A02BULL,
		0xE0C6E1646A55F6E8ULL,
		0xDCE43381DAD35027ULL,
		0x5F6BD656799695B5ULL,
		0xC5BD6B81ABBE64D7ULL,
		0x695A7F83666A9E58ULL,
		0x9B705409ADA21E05ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA0326902448D041AULL,
		0xD06F487FF516CECDULL,
		0x2A5B8136E0620616ULL,
		0x25FE21B8EA35A52EULL,
		0x6F058CFE9D29FC85ULL,
		0x68EEA43A27CDEE79ULL,
		0xB215E6143E10F808ULL,
		0x09117C3D0752B2B6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x471B2126297BB210ULL,
		0x021964406DAB634FULL,
		0xEA9A26AD8742A0BFULL,
		0x70FA1A29A06798A8ULL,
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
		0x7359A941B97984E2ULL,
		0x907360005090BAC9ULL,
		0x85640D47BB5F9178ULL,
		0x7B6FF8875FC6A8ABULL,
		0xA8ED2889F94C9437ULL,
		0x6229733B65399262ULL,
		0xFC7F3A346CFDC39DULL,
		0x936995CED1584C0EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x56AE44B741175893ULL,
		0xE47A2BC03877E801ULL,
		0xA4DCBB9F78119314ULL,
		0x95577DB834D21CE6ULL,
		0xAF5CDB9E8CBC5372ULL,
		0xFD73431B926920AFULL,
		0x2830CBCF7AC74633ULL,
		0x5890F0A9F0B2C77CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2816CF7C95CBCAD0ULL,
		0x9F0458F96309B359ULL,
		0x642BB4A437649C08ULL,
		0x2240FE4883863990ULL,
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
		0xB003BF050B290FF7ULL,
		0xAEEC2D869AB8922AULL,
		0x6E0AA090878FCD11ULL,
		0xA02AC788F0FB2E43ULL,
		0xCA3625C0604E64B5ULL,
		0x69C9AFA8B4F2656BULL,
		0x354B7ACE5562AC25ULL,
		0x9B23D97E113ED777ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE5D87922C3254747ULL,
		0x751AB1C25C86DC0CULL,
		0xF259D3C0AB07449AULL,
		0x80124758029C1118ULL,
		0x055BA1E27BD7B101ULL,
		0x33ECA5BFCCB3907DULL,
		0xD874CDED95FCF39CULL,
		0x145632EACA010A28ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x029AD8D231A27860ULL,
		0x38A0F456B785518FULL,
		0x438E762C45A1ECD5ULL,
		0x229F3A0D818B96CCULL,
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
		0x682700015B49D92EULL,
		0xCFC955578B149125ULL,
		0x527572111BBC381DULL,
		0xE6DAF8A4AD82190DULL,
		0xF871D7105B8D6DD1ULL,
		0x435FBCE6E9310431ULL,
		0x63FFC13851C33311ULL,
		0x68B88B34F1F551FDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0DA7076A076433F0ULL,
		0x6868C6E9E07FCEE9ULL,
		0x8C92AEBBF354C0E5ULL,
		0xBCEFB3DA8F191A85ULL,
		0x715FE4BF1F6B1007ULL,
		0x40AF62A06746298DULL,
		0x07AEA59100596E87ULL,
		0x506161EA1A6C73B0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6729F0A640FF91BFULL,
		0xCD8DF4E4F37136A8ULL,
		0x79ECDE2B3E1AA3B4ULL,
		0x46DB65E61CB9FE03ULL,
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
		0x637437968F58CA9DULL,
		0x46FBC76E90CFBDF5ULL,
		0x482D4D3EC825D7D0ULL,
		0xB31C0461B6D7A098ULL,
		0x9DC1DB3B16EBD13EULL,
		0xFCFB513D7C8B1D1DULL,
		0xE8154B7867A3A499ULL,
		0x1C4657BE90175B2BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9BDD94B3496E0755ULL,
		0x3F599F736D154795ULL,
		0xA9545B875A149179ULL,
		0x70FF04788EBF1713ULL,
		0xD578E4BD32FE68B5ULL,
		0x0BA4640440B2B86AULL,
		0x6FBCA019FB363DB4ULL,
		0x432A1BADCEB5D0C0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x826B39931B2846BAULL,
		0xDA895E7A05D968E9ULL,
		0x7C0261BB864E8C78ULL,
		0x7C4DEA65DC931578ULL,
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
		0xCDEB8DFF785D1739ULL,
		0x2EF0D65CED6CE8AFULL,
		0xCCACAD2DBBF7CC83ULL,
		0x64DE285545D3BB5BULL,
		0x0494FEBB640BFB4BULL,
		0xF31FD7082ABEB761ULL,
		0x29869236FBE2E887ULL,
		0x7FB225728343DA91ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0E69560D9D381CD7ULL,
		0x4862A60E69837C6BULL,
		0x671FD2D957FAFC38ULL,
		0x154E7F777327FB08ULL,
		0x4CF74F8F29909F66ULL,
		0xF3FF6ABE39ADF465ULL,
		0x42A14B281788A996ULL,
		0x85032C1B0BC36E95ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x00EA388289749E4DULL,
		0xC55E43484C665DA2ULL,
		0xAB95668A49622810ULL,
		0x0588ABD98FBBC7B7ULL,
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
		0x37ED1869DF0DAA3CULL,
		0xF891BC44B8281A4EULL,
		0xC72AFA22C0CEB847ULL,
		0xCBD1451E43774E15ULL,
		0x711168BF1FEF46FBULL,
		0x24750D29A9B1913BULL,
		0x6CBF094512E8B25CULL,
		0x68E6D42B4F2B0EAFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2C1ABB0A6662D63EULL,
		0x1A145F738DB91DE2ULL,
		0xF764CDDA1B844942ULL,
		0x5B76982626239264ULL,
		0xF455E2312ABF5F70ULL,
		0xD1BE33CBF1485DEAULL,
		0xD3B857DF2E6FC8F9ULL,
		0x4F7E322CFF1F6E6BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8FA85671DDC73338ULL,
		0x25A1A0BA8A0C9A5EULL,
		0x86C481688F3D139EULL,
		0x35E2B8B7FF0D85B9ULL,
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
		0x8D24D2CECDB91778ULL,
		0xE7CD13EEAE9A6922ULL,
		0x54369F8F67E79B20ULL,
		0x6CD8027BF57DF593ULL,
		0x988D4B6D4D58E116ULL,
		0xF1149B89BC76DEECULL,
		0xA765DAC8899D3BFFULL,
		0x2A3E6848442525DEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8349C0CB0A78DDD3ULL,
		0x20A13473C3FED0B5ULL,
		0x97383FD31DE14988ULL,
		0xE4792104A755C230ULL,
		0x28F55E5ED4A791BCULL,
		0xA6844249C21877CAULL,
		0x8970A7EB78B70F7FULL,
		0x1073C82CF935D5FCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9A684229AD920173ULL,
		0xD8991EFA149EE789ULL,
		0x2F63EC8CCC30ECA3ULL,
		0x5C72A5846DAE0EF3ULL,
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
		0xF5BB23B18759B7C0ULL,
		0x14F2A0593116C9FCULL,
		0x11FB02C10068AB61ULL,
		0x8D65EF97704336B2ULL,
		0x77DFEDCD359A3569ULL,
		0xAE609150CC16F37AULL,
		0x207CCFF7E27E60B9ULL,
		0x80E8E9228C02D579ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x648203ABEF93CB75ULL,
		0x11A4E1A7049EE18AULL,
		0x800F89E9AF35490EULL,
		0x044AFFEEAF828EF1ULL,
		0x9787F84CA04C0FD0ULL,
		0x08C06A71EF592FB6ULL,
		0xD6EB93D47C86CF1AULL,
		0xF62B0E88531F3E9BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDE47911BC15F7E7BULL,
		0x991383C6F0A2F785ULL,
		0x7D7A661873F30005ULL,
		0x2149628D32890C99ULL,
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
		0x4091E5B90E3ABC26ULL,
		0x079AF8C6C87F4950ULL,
		0x2AF5F9FE743701E6ULL,
		0xCF86EF40427B322DULL,
		0x1A4DFEF18337F7DBULL,
		0x9E42CA5E17D27BECULL,
		0x6D9F9FEBB82E4B88ULL,
		0xA940D2C4E484A7BCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCE83D9BF878A9CD4ULL,
		0xC9DD931D77745BB5ULL,
		0xA0AFE1EB7E1EB34DULL,
		0x28EC5F8E5D845498ULL,
		0xCD89B2F681F8E2FBULL,
		0x8CC6E151E675948CULL,
		0x583F1CEA65A64525ULL,
		0xE991E67C0499760FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD731533BB60D373CULL,
		0xD621FD78A4D545BFULL,
		0xB6998A453649414CULL,
		0x1A91A28321E03D45ULL,
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
		0xFAB7A6CBC4C33527ULL,
		0x9CEB518821EA9F24ULL,
		0x1A14536135BC4850ULL,
		0x39C1F55B3B7211C6ULL,
		0x3BDD89CB9EAC9760ULL,
		0x537862C9AB688E3FULL,
		0xAEACAD2911C28694ULL,
		0xBFDFA4C78CD4A5D0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x46820425710C4EA3ULL,
		0xE820F72A6A2F528CULL,
		0xC2F93793D6D3458DULL,
		0xBD6181456634AA59ULL,
		0x471B197337FF1C8EULL,
		0xFB3056D10976C6F9ULL,
		0xCDF9E1C9AB7375DCULL,
		0x5AD3F8DC4736B079ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x09124FC5917723C4ULL,
		0xCF7C2145C19EE0FBULL,
		0xB1A54BF68EA57DF9ULL,
		0x7C1BF9022AAFD251ULL,
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
		0x90F6D251837A861BULL,
		0xA05CD983199A134AULL,
		0x0C3221073FE28A2CULL,
		0x2F16130E59926FC5ULL,
		0xD7A823765FF55927ULL,
		0x4ACE18D74CB6CBC7ULL,
		0xC59E323129CA4B96ULL,
		0x46CD36DBE30A072AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1E438F78D0A03791ULL,
		0x8DCF6C171CA9FD09ULL,
		0x2843A6D83E37043AULL,
		0x474400C7D8EA65B5ULL,
		0x064893F1B64FEBB2ULL,
		0xA0F33552AD3A0BCAULL,
		0x7646937F54AC2E00ULL,
		0x2A5C20F9A5068E85ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x86E29089E1688E80ULL,
		0x490B331BA97495EEULL,
		0xAAF00894A423EA29ULL,
		0x209B51DBB52BF299ULL,
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
		0xCA77DC58D751AB4AULL,
		0x6DC5E1E811FD9500ULL,
		0xDE97DEC490D319C6ULL,
		0x0032F16A993EB1A0ULL,
		0x0D80277545CC3149ULL,
		0xB040A226928D3149ULL,
		0xB3E0610159A2A25BULL,
		0xCA86866CB88017B3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0AEE09B88BEDACEAULL,
		0x4EF3F3270F19AD77ULL,
		0xF2AE9075E9C82189ULL,
		0xD3A2629D1E3E0338ULL,
		0x1DDD0CD1A3F00596ULL,
		0x4CED3771AC1EA80DULL,
		0x336C841E335FC68DULL,
		0xFBF96010F6017104ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x51BFC6EA521279AFULL,
		0xDD33C59B374C466FULL,
		0xFD1C180654F798DFULL,
		0x5584406C59CD6C74ULL,
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
		0x7B0577CFF0BEB159ULL,
		0xFBB6D51AFDFCB6D8ULL,
		0x88E628966BA4BE83ULL,
		0x8CC7B3C13A22ADB1ULL,
		0x630F255043E3214EULL,
		0x01E9B34BFB011F9DULL,
		0xFF8964B4F4448ABCULL,
		0x8464B77F07BB19C0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x25F8BBA7BE28C84BULL,
		0x3AD04EB385B87ED1ULL,
		0xC5DEB4EFD18ED8ACULL,
		0x299D488B0D432A2BULL,
		0x45ADDF7FD51E1A9BULL,
		0x53B8F1C945B302CAULL,
		0x98F5F46D50D9597AULL,
		0x1ABDD9F4D8B46AA8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB17D1918A3D4EA00ULL,
		0x9C233FCE61DC7F5DULL,
		0xFCEA1E48DBFF3597ULL,
		0x11EF4DB927DD8124ULL,
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
		0x4830CED81DC033F4ULL,
		0x04C745205AEF5686ULL,
		0xC5C59320A2B960D0ULL,
		0x2A4199152F6F4C90ULL,
		0x17523542F75EB37BULL,
		0xA495F1A1C782DC8CULL,
		0x076512655AF41637ULL,
		0x4FDB244C009AE0DEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCFBBBD30BAC33F08ULL,
		0x05814F25234EF6D0ULL,
		0xCDE5840C633429B3ULL,
		0x13D8D5580747C3B8ULL,
		0xA7E869F5BD06B0BAULL,
		0x8758B2C86AC402A8ULL,
		0xD926DCD35707A51FULL,
		0x50705292162898A3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x02293F1E0C0D5D92ULL,
		0x565D4A3EFBF4B778ULL,
		0xD51C02C0D49E00B1ULL,
		0x0043E555F51E417AULL,
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
		0x3B38845B7927D39BULL,
		0x4BCFA8A661627A1FULL,
		0x2227AA4C4329D7F3ULL,
		0xAB484078371E4073ULL,
		0x4FEAB6DF8372DA9AULL,
		0x3EBC2D9BDADA8473ULL,
		0xF0FA8D608CE83412ULL,
		0x5F9F4911288CA1EDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9177DD9B877FC5B9ULL,
		0xF4B4DFE4D43EC1B7ULL,
		0x14BE3D477BF4506CULL,
		0xEC5648CBBF5808DFULL,
		0x2FAA248AEC6665F6ULL,
		0xCE71F98FF84FA8FDULL,
		0x3B3337AF10204B19ULL,
		0xFED954C0BE85D1BFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x73565F4E5D815AAAULL,
		0x021E82852DC04BF0ULL,
		0x0900255D4CE21C67ULL,
		0x1C543B9C34C91E83ULL,
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
		0x1562F54303CE4084ULL,
		0xF0B718ACB0A0CCCBULL,
		0xD2C24DDCAF83E75DULL,
		0x5325F0ACA1EFE8AEULL,
		0xEB5248AFE5B246DCULL,
		0x74160AE7FC202423ULL,
		0x47D884DC8F629B2FULL,
		0xE93DAA5600B6FDBCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD1FD376FB5992C8EULL,
		0x54513E8A8CDFD144ULL,
		0x68B4A8E148E01AAAULL,
		0x98CDE87C137677D0ULL,
		0x6FA76F1369767CA6ULL,
		0x5DD2BEC53CEC0719ULL,
		0x5A23007BF0C5DA50ULL,
		0xA907F9E56A853D46ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9EC20B0DBF151950ULL,
		0xEA63274A857D4B14ULL,
		0xB2FF4B52F1E86DD0ULL,
		0x425038E6D9DC025FULL,
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
		0xECE4F7C9B682D0ACULL,
		0xEC49B57CCCA8735CULL,
		0x12F91B2D2F3203E0ULL,
		0xD22C4A34329E0E42ULL,
		0x204BA85649DAC1A3ULL,
		0x2B06DCF203E7CF20ULL,
		0x03235E67FB87095FULL,
		0x4E3DEF491B5A156BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x88DCCAED646871D1ULL,
		0x1537A319E3087698ULL,
		0x3838A87CDC4E1D82ULL,
		0x529FDF8BCB8DC8A9ULL,
		0x2FCF4938FBAE6D7FULL,
		0x7071E08A78D89D5EULL,
		0xBEC77458984A08FAULL,
		0x3ECF51F9B621980CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x167E4B35ECAEDC92ULL,
		0x892F89C18DE15F8EULL,
		0x006530F90DF1F552ULL,
		0x49F7C4716D72E197ULL,
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
		0x75094F8E1C0FE304ULL,
		0xD9BDB24C26EAE55DULL,
		0x30E93CDE673CF7E7ULL,
		0xF8AB2566D8B504A0ULL,
		0x23D126E8FEE4A7D4ULL,
		0xEF6AD9D905F937A0ULL,
		0x51A9A4726FFBD8A6ULL,
		0xCD46F77155ACC9C1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5D3A0937F0F63E42ULL,
		0x70A0379F93ADF8DBULL,
		0x6FBD8BA89CEC1269ULL,
		0xD99610FDFE55FE80ULL,
		0x058D4EDDDF76E82FULL,
		0x7C4A9EEF76690544ULL,
		0x18BEF1503BFE36EDULL,
		0x4F1D7289AFDEDAA8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x95E157FCD56419FFULL,
		0x7FE63957E2A4662EULL,
		0x3402484981F6E705ULL,
		0x593ECECB76F083DEULL,
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
		0x6F0F6BA18949200AULL,
		0xB7601BA1C277D900ULL,
		0xFE032B265BEB3105ULL,
		0x852247D884D41FA3ULL,
		0x18892A41ABCE3533ULL,
		0xFB5DFF91478B60E7ULL,
		0x1F39D700CB2FD0C1ULL,
		0x2DCEAB5706ECC046ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x89E6FED4FC9EB79AULL,
		0xC177A07B03822C86ULL,
		0x4213DCF5E8B5FD8DULL,
		0x2F9521F6E0BDF6E8ULL,
		0x62E0E25A6A9237BCULL,
		0x7E1D018C3A17CC07ULL,
		0xA5C91CC76352A191ULL,
		0x0F92FA2BAFFFF6D6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDC2319203B9208C5ULL,
		0x8D8E2FE6BE1DC5AEULL,
		0xC2AAF2B5DE0A34AAULL,
		0x526972508B3C0F47ULL,
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
		0xDC9DB72E52A4FD6BULL,
		0x5A4485601555FC89ULL,
		0x0233DB73F1252DDEULL,
		0x33F4C1F9ABA2C4BCULL,
		0x5784259DE38E415AULL,
		0x0975FC641A953C5CULL,
		0x72D7E990428C1971ULL,
		0x9870BCA6936F1496ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8367A38892FF35ABULL,
		0xCC4C42C5B15FC876ULL,
		0x5BB5427F380DAF55ULL,
		0x3D0BAFBFF94D4D33ULL,
		0x616368FC92D40CF4ULL,
		0x4FBD2DAB09206C75ULL,
		0x2B0931484F423791ULL,
		0x3AB5D20ADEB69A49ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE2121397BB4990E5ULL,
		0x1F66F212FB4D105BULL,
		0x4F2DF3A2D60F05BEULL,
		0x60A7E55685B79F01ULL,
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
		0xF0A543EB0137BF93ULL,
		0x38716D592375EB69ULL,
		0xEC7A074A1846BB91ULL,
		0x8C75B34413DFF5D0ULL,
		0xF446D5005243FEA5ULL,
		0x2240DFB469A4D346ULL,
		0xB4FA3CB32B1A0A71ULL,
		0xBD7FC40BC5CC9BF1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2F404523C3425EE7ULL,
		0x3BC2D5B1CAB02B48ULL,
		0x42AE5AD62DC749EFULL,
		0x7767EE3D7E5E4693ULL,
		0xEC663DD23CF817E4ULL,
		0x5B977DA980685FD9ULL,
		0x96EF183E06E09F79ULL,
		0x6663A648A10E2906ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xECBB6F9E6739A340ULL,
		0x79D32545F7BEE250ULL,
		0x1F7315D74B055269ULL,
		0x033A2FFE09C6BE24ULL,
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
		0x4FC8820DDD483DABULL,
		0xFF6A71E5B1661D95ULL,
		0x50413348A7630166ULL,
		0xE0C280BABC53F3EFULL,
		0x0D6C3E4E2A1F5518ULL,
		0xEC4367AE80954F2DULL,
		0x23E00E69EF414A44ULL,
		0xE5D461EA68E5AB7BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x268956D5FDF4D66EULL,
		0xDAD7F12A1AD53718ULL,
		0x79F11FFB646C729BULL,
		0x50F37EFD5DB204E5ULL,
		0x8DDFA60080BDADC1ULL,
		0xF617889AADD077BBULL,
		0xC200A5E7E686ABE2ULL,
		0x8F8A5DA79D41E14EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x181DC6BF03D24015ULL,
		0xAF159DACDFC8E156ULL,
		0x5D79969A8EAA1155ULL,
		0x5ECBA3A798F1F1A0ULL,
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
		0x1B773E3886AF6F40ULL,
		0x345A3F7913B31D23ULL,
		0x1676091F5B733081ULL,
		0x7504DA1BE042CAA1ULL,
		0xBC5637A78370488DULL,
		0x78A8D292FB8A6302ULL,
		0xDF5E7EA96E69275CULL,
		0x903B4DD5AE42FA0BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9E95B21EB9AF096DULL,
		0x379FAAA314CC4A42ULL,
		0x5A989E4A85E4E0B3ULL,
		0x5314D71555AC0326ULL,
		0xD0793E851AA9AFCAULL,
		0xB911EA4713ED883CULL,
		0x77AB369613376080ULL,
		0x9E2C5FA4FD9F6208ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7FAE87355A7B1279ULL,
		0x6D21101A602F4C41ULL,
		0x207A1DB45EF1D46CULL,
		0x10275E40C2DF57FCULL,
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
		0xD0218987B8732584ULL,
		0x9D0231FB0A35C572ULL,
		0x69DD3816C922B2D1ULL,
		0x0202EF60767AFB5AULL,
		0xEDBBA961BC8AD5C9ULL,
		0xE24A43F255CF41FAULL,
		0xE80BA86427C289CFULL,
		0x32EAF613A7408390ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x90E9237DEC5DBBBAULL,
		0x43F941C39AD019CBULL,
		0x218D6FA75476660DULL,
		0x83741E612E0738ADULL,
		0xEF09EEEF5735A9F0ULL,
		0xCDB23607765CA7D5ULL,
		0x8444BA5073FB27DEULL,
		0x5667B7B4935FE08EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0D9A1304D6B9EB1CULL,
		0x679B01149A688D25ULL,
		0x17D71F5C2444D68DULL,
		0x3A0A131C3BCBF508ULL,
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
		0x25BFFA67F1195DEDULL,
		0x7EA62B847C84CBA9ULL,
		0xBAE961FD09E625F3ULL,
		0xD59CD14EDD818751ULL,
		0xE38F23A0FAEB59CEULL,
		0xC890343A0CDC831BULL,
		0xB90442A4E1A3DBB4ULL,
		0x43AD95C5873D31A1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x49B1C5E4292B541BULL,
		0x8E3678C8BB2633D9ULL,
		0x9723B3D516250604ULL,
		0x0A14021E2020E0CAULL,
		0x0FFA6A80D44103EAULL,
		0x505BA917243675C6ULL,
		0x7A67F1B5F91AE04DULL,
		0xC593D26C4ACFF0C7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4421AF498536C6EBULL,
		0xC83C59EA4A04928DULL,
		0x6EF9B19E7816714AULL,
		0x035BCE6FB59846ECULL,
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
		0xF53172554312BEBDULL,
		0x1866BE192C703B29ULL,
		0x2DF55616DFD51F56ULL,
		0x6441C1C013156901ULL,
		0x835C429DE4128B30ULL,
		0x6F9E685FE2D3E1BFULL,
		0x20326D9631CEA881ULL,
		0xA5BE5CEE41914852ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x299F1E91B6FAC473ULL,
		0x3F768705BDA8EA49ULL,
		0x1CA82B63332FB5A7ULL,
		0x74BE66E6B59715ECULL,
		0xF38503D7C791CFFBULL,
		0x1962C38CD991EBD8ULL,
		0x49685F73DC765037ULL,
		0x74D26FDEECF30594ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2585A52BC733C532ULL,
		0xA5CAAE66CE91D11AULL,
		0xF34B43CC57C284B7ULL,
		0x32888B1FECFC3B42ULL,
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
		0x326F645E6949FBABULL,
		0x3FE5A80A9F9C74C5ULL,
		0x74EC4855911E8C00ULL,
		0x00FBC6A37E3604F1ULL,
		0x71BF809DDF017ECEULL,
		0x3611A814C394B015ULL,
		0xF08E6A0B8DE6C957ULL,
		0x69DA086644FA051FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF70350D2872B0DFULL,
		0x5E2AFAAA24B0B864ULL,
		0xF813B2BDF2E8E43DULL,
		0x2E13971529227930ULL,
		0x7D34E49B923151CAULL,
		0x2130059E12BE1C7FULL,
		0xA61AD58E8D5D4807ULL,
		0x741FC54E2FFF1537ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCF9257A8A7BDF918ULL,
		0xFB38CAFEBAC5A4A2ULL,
		0x8A00A025B29ED9A5ULL,
		0x4C8E25217253283BULL,
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
		0xD060E0EA753DFE09ULL,
		0xD7D52B8AECB931A7ULL,
		0x209F08120170D3EBULL,
		0x11972F8D104CF061ULL,
		0xC4E4876778B550A6ULL,
		0x007B7BBF33804D90ULL,
		0x3F339384344DFAFCULL,
		0x929D13C435950340ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7AA7AD05FDAF9168ULL,
		0x5A2C3B403B970468ULL,
		0x5FFE46CBD952F1C6ULL,
		0x19A1EAFD26046199ULL,
		0xBD294D428DFA8DB2ULL,
		0x4F1F791CF61A1C4CULL,
		0x59B2F6E8F6AF0D6FULL,
		0x92557C0668AFFD64ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7B83D55F4F475CD9ULL,
		0xD151545FCE4D7D58ULL,
		0xD1B800514DB52507ULL,
		0x0295CABC54476D6BULL,
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
		0x2E3BE4B66F49F698ULL,
		0x319D607BCC7AD1B2ULL,
		0xF7987196F51D3858ULL,
		0x8F11BE3124B6F5C1ULL,
		0x0BC0B98A780749DAULL,
		0x3DC8BA82938E3010ULL,
		0x83464944C74F45BDULL,
		0x5BFDC0A0F2225F73ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3D62757C2CCF0D58ULL,
		0x2FF878FBB74DE295ULL,
		0xF7AA474A7C3DC6C3ULL,
		0xBB720DF914CA82B1ULL,
		0x3690805628A55079ULL,
		0xC2C5C52DB30258CAULL,
		0x5E24C43D774E2E2CULL,
		0x6BBF4C95DF5E0B50ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9601ECFE0B05ED34ULL,
		0x4415521969EEE37AULL,
		0x82E7E9625908F107ULL,
		0x7CE4E9DCD910F047ULL,
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
		0x7E9D5C7AD3E0EA1DULL,
		0xA24AF225B27FA982ULL,
		0xEF23DBA48B12F0F7ULL,
		0x7D18CDE38A4A37FAULL,
		0x7770A43F58C346E1ULL,
		0x355B8A871293D2B0ULL,
		0xDB1B83B5F068157AULL,
		0xD3CA9F5FD37B1752ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0106924CE903C441ULL,
		0x88C332DC7F106BD5ULL,
		0x6B28F462ABCB5BC5ULL,
		0x0BE78597C5615FF0ULL,
		0xFA3D7C3758E665D2ULL,
		0x72EDEC29AAF0F55EULL,
		0xD0DADF059B73786CULL,
		0x0E432A4110E8DEC4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x132EBB5DE5A69277ULL,
		0xF5CD4126959C17C6ULL,
		0x0993596E7B96E53CULL,
		0x434CAADCA69D3D20ULL,
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
		0xACA1A396C88F3062ULL,
		0xAD183D8C74589B8BULL,
		0xE92640F87A0D9021ULL,
		0x17A54E20717292A5ULL,
		0xC0C132FFF0816FB0ULL,
		0xBD8EA0DDEEB80379ULL,
		0x4842B13267DC2046ULL,
		0x36A2B211A6275E5EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x13CB1BCDDDAB432EULL,
		0x3D5DB8CA1D1604E0ULL,
		0x688E376B8908A9F5ULL,
		0x92439E5433117CCAULL,
		0xA7A63DF997CFA034ULL,
		0xCF872C4C8A3B56A9ULL,
		0xA9ED1D79CACF9D22ULL,
		0x9CA42A08BA7860D3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x52D6E6BA1548B73CULL,
		0xC4D5D25741C43D8FULL,
		0x014BF6F440E05D81ULL,
		0x6129E11F3A5AB86FULL,
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
		0x3142C6584D763814ULL,
		0xED930BF2905DA7FEULL,
		0x2076D30E4D3783AAULL,
		0x6A5C7328B36DDBC5ULL,
		0x6D66AA6DAEE35DE5ULL,
		0xEEBAAD779F359408ULL,
		0xF2F73BD3F03A726FULL,
		0xC98C1FCD959860C6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5D800A1D434A5C79ULL,
		0x5A910240643E6153ULL,
		0x751CE8C20E29D895ULL,
		0x9D21D19E43C9BFCFULL,
		0xC422E96DA6D5B0E8ULL,
		0x7CFDEE1A72D4A9F6ULL,
		0x5BB73AF8F5FE7963ULL,
		0x801EDDACB597179EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF3D1623C3C338AB8ULL,
		0x75067186C2820549ULL,
		0x1EDA0ACD63F4A2EEULL,
		0x3372726BAFD4F7FCULL,
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
		0x92F3719E95005209ULL,
		0x52910833DCB2D5E7ULL,
		0x60981527F3425505ULL,
		0x40ED5A767A16EBBAULL,
		0xBFA27736E58B534AULL,
		0xA66D6C094B6B0410ULL,
		0x76253EC93C8D4508ULL,
		0x351792F519A6EEBCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEA63EFF009253CB9ULL,
		0x036E85E0A051DBDDULL,
		0x40DF06711C49F68CULL,
		0xB3842E92B2C8F9A1ULL,
		0x1A72C4EADFFC267DULL,
		0x2E93D57EA0FF9EB4ULL,
		0xA4CF6DBA9602FE68ULL,
		0xA2ABAB5C977B1757ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2DA3F8F75F1BB938ULL,
		0x196EDAE8885205CAULL,
		0x327616E38F7EDA4BULL,
		0x496D8C8719CFEB10ULL,
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
		0x8F2197E8726AA35CULL,
		0x7E9EBB616B19FE4EULL,
		0x9697AFF367A8D7D5ULL,
		0x4ECC7D800148A6F6ULL,
		0x60DDFE4E60514CBDULL,
		0xDAC8471ACEA52C72ULL,
		0xEEB29D88D6E2F887ULL,
		0xDFBB4FA90F48A485ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x308A18E04282D3CBULL,
		0xC055D043641D3634ULL,
		0x1D90FDF62BE2D40BULL,
		0x30AAB80E69733FE0ULL,
		0x3E59E185A35F9FBCULL,
		0xDDD2D4EF3E408F1BULL,
		0xF1AB00DD8C3B00BEULL,
		0x758C48C946108EADULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7E33C4D43BC78004ULL,
		0x4AB7DD9575EC2309ULL,
		0x0827F36A50B4CB9FULL,
		0x611CCAA97628A526ULL,
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
		0xB3F3B12162FDBC9DULL,
		0x5AF1D6F24E5DAAFAULL,
		0x880D5B4EA72A2C45ULL,
		0xAAB0CFAC951B7756ULL,
		0xA2BA2E2B685F80DBULL,
		0x83A32DAB4B5E2DBFULL,
		0x4F227D7EFCA76D06ULL,
		0xBE67C58D58488588ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2F956D71F866FE9CULL,
		0x106E944FB36E89B8ULL,
		0xCC6219F6B75DFBCDULL,
		0x802DB4411A003570ULL,
		0x3C46025C6D9B4FAFULL,
		0x0D84EC16E0CD729EULL,
		0x6048D619533AA19AULL,
		0x2FC4168887227216ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB99CC468A3B60DA7ULL,
		0xD300FEAA6C6AE837ULL,
		0x2FFA1A6F15F26291ULL,
		0x56CF162286C224CFULL,
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
		0xAB2C087DBAD7DEF0ULL,
		0xF2D0247EA89D57B2ULL,
		0x6F48A1B876EF4FACULL,
		0x2FC5F41A880F4DB1ULL,
		0x6A8AEADFB83031C8ULL,
		0x8345BC7A0C768670ULL,
		0x11A5DAA9B83502CEULL,
		0x1C2A99ABF655DDFEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0E2B5DCA97A5C34DULL,
		0x474ACFE631BA0486ULL,
		0x37ABDA9E1370B5F1ULL,
		0xD8DA061935069992ULL,
		0xAAA71E864FB97D25ULL,
		0xD1044D07C38A8157ULL,
		0xA195CDB8896DDC77ULL,
		0x5700029A2590331BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x18D0FFF8A4D0EA6CULL,
		0x213BDF8F49EC14D9ULL,
		0xD9FEB2E7550E4A9AULL,
		0x1B3E5AA6506011BBULL,
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
		0x481BC865B19B6A76ULL,
		0x3569C2B7E289A8F2ULL,
		0xFC5C82E6A4ED255FULL,
		0xEFFF704F80218360ULL,
		0x7199C5F318AB82AAULL,
		0xAAC3805CA6F0F59BULL,
		0x0905BADE51A9583DULL,
		0x9B11092EA3EE108FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD5D5794A9221DCD4ULL,
		0x7D384B12C0FBA40BULL,
		0x8963CE4FDF4B04ADULL,
		0x3315DDCD268A10A1ULL,
		0x84E0E17FA0CF5495ULL,
		0xF8382D0036BADB01ULL,
		0x036C99EC99C5B8C5ULL,
		0xFBD55CBAED697491ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x95B8383EEA2862ACULL,
		0x38DFD75DC995F7BFULL,
		0x47B39878116BCC76ULL,
		0x5FC52BAF71469A74ULL,
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
		0xF39FD148F6D9E5F9ULL,
		0x8F2ABAEB31E3A8FBULL,
		0x685719426C99BF32ULL,
		0x15E74DEB21F0FCB3ULL,
		0xFEA6DDF68C8793CFULL,
		0xF7B076F5F892BD1AULL,
		0x1FB2325482ECF142ULL,
		0x80E359ECEC51558DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x388BC87B2C150896ULL,
		0x2924657B3E069744ULL,
		0xED9CD740C2A4590CULL,
		0xCACA13AC8FFF5663ULL,
		0x52C26835A598AADFULL,
		0xECA84F683A0BD02CULL,
		0x09CF9EA35FEC0F45ULL,
		0x5D9024A27A5E8D61ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3EFD8370123B71AEULL,
		0x093C347A3BE43D25ULL,
		0xBA5C2E4CDC16F1B6ULL,
		0x0977234B7BFB5CDAULL,
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
		0x46ED850C7C854F35ULL,
		0x20BB7DFE57690C21ULL,
		0x14C7A53289E53209ULL,
		0x6C670C3B340F8C5CULL,
		0x5131F7DA3ADB451DULL,
		0xD66EBB6D5008D278ULL,
		0x91FFC427A93099ABULL,
		0x3D2A454AB13742FAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x94A23C2F601E2A64ULL,
		0xCEB5B20DF53DD010ULL,
		0x98CFE90C4CD96B3DULL,
		0xE8CF44F9A7501AB2ULL,
		0x673AE2861CDBF78DULL,
		0x7BEDF7CFAC2ADBC9ULL,
		0xEBFA26DB94E86E8DULL,
		0xF19360BBCC0C76B2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6CF87359904CA41CULL,
		0xC122D556B51DDA07ULL,
		0x20CD15713FC22D4CULL,
		0x3BFDB4779119C44CULL,
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
		0xA498C98D25B89093ULL,
		0x686BE8781555B595ULL,
		0x799BC85400DA0E94ULL,
		0x90ADBCD71B99D74FULL,
		0x6681F6C148888E71ULL,
		0x52B25CE41DA7164FULL,
		0x12AB3D925654B00EULL,
		0xC9C1D234C5FB4636ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x31197849EC1DD726ULL,
		0x910BF13BCD2E6C19ULL,
		0x025F620D0FD1DDB6ULL,
		0x0650FD195D606E0FULL,
		0x3179D41A0EC590F6ULL,
		0x589C0A3EF802CBA8ULL,
		0x36D41BB69F397977ULL,
		0x40F30446149B7B56ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x52B47615CC8C5CBAULL,
		0xF6B03BBFDE8A5E4EULL,
		0x192B6CE41F124B46ULL,
		0x590F512C1271867BULL,
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
		0x8F1064BFEA1145B4ULL,
		0x766C26926E7750C2ULL,
		0xB0ADA52171F1B022ULL,
		0xC93D11D4B4AC091FULL,
		0xF40EF48652DB580CULL,
		0x28230181680345DCULL,
		0x0B24B9B947092839ULL,
		0xB660F99BF2F833B7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3542C3E15E8C71F1ULL,
		0x235BA72B1C56A0C4ULL,
		0x20EAD5B451391269ULL,
		0xA38DC956C07179C6ULL,
		0x6ABC1DDEDFAE63FAULL,
		0xECD251956AF3F80EULL,
		0x83C5FD12D31A0894ULL,
		0x2230EE3C3E4FC587ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBC197DB9A43111B3ULL,
		0x210A9C6EE2663CA6ULL,
		0xA7D2D0225637501AULL,
		0x24D0F8B2C53AEA67ULL,
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
		0x9DCCBC851BA0E824ULL,
		0xD47611B6D0AD12C7ULL,
		0x9324D420D1FDBDE8ULL,
		0x9A279C71E3325DA2ULL,
		0xD9805BD73117CA73ULL,
		0xAA731CF843D99FF0ULL,
		0xFC1433AB9554C5EAULL,
		0x889D1AF4D5ED365AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x55E58E8D8632CA08ULL,
		0xC642577BB79BE705ULL,
		0xA3442DE31ACB93AEULL,
		0xCB7C31E4D490925DULL,
		0x8C6F461BAA28F5F4ULL,
		0x654337337E77C18BULL,
		0x38AFBDC2BC3E5B7DULL,
		0xE02C5F5C1FF8DDEDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB87067CD9CE1A6F5ULL,
		0x534FD57065982ECBULL,
		0xF0CA26CDF085F672ULL,
		0x4F67433810E6EB8FULL,
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
		0xD9DDEB1819464E47ULL,
		0xC46DD13B17A29A33ULL,
		0x34CD9F899E7B785EULL,
		0x640E12EDCAC1EADBULL,
		0x0BBABAFF47122A23ULL,
		0x5BBD5F045DBAFF0DULL,
		0x8D7A71444D4FFED9ULL,
		0xB82D364DD710BCB8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5F1A4992B961BAD6ULL,
		0x24B8AB864147896DULL,
		0x580E5C892FDDFCC7ULL,
		0x71701D8DA5C9F8B6ULL,
		0xB5CEC6EDFA18D47CULL,
		0x89AD217F8E657606ULL,
		0x0100F4D59043C08CULL,
		0x81DDC20492E328EAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3BC9DC16CCE74B6BULL,
		0xCE1E476B9D0D67B7ULL,
		0xB6C7BB707E6EBAFEULL,
		0x0269384043BBE2CDULL,
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
		0x6438944797B83250ULL,
		0x88A3CCF953F9C67AULL,
		0x19034686C563FC90ULL,
		0x4440EE2A457B39A4ULL,
		0x2F6DE5128666CAF7ULL,
		0x1AD457A55861F294ULL,
		0x67FB13B5B71E1CFBULL,
		0x0055B4575F494568ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE13B9F37A76A28C1ULL,
		0xBA22A591564CDC66ULL,
		0x5A98A382997D694AULL,
		0x7E3C17037141C711ULL,
		0x0A5287C89076356BULL,
		0x490C3F425418C281ULL,
		0x3F6D48C364C6230DULL,
		0x92DE216B39879678ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x050CCE0A72043913ULL,
		0xF234C61AA08A0CEBULL,
		0xC376C2FC64F5AC92ULL,
		0x05C4A6346EF96A38ULL,
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
		0xEEEBEBB03E2BC830ULL,
		0x89E23AB102453E3CULL,
		0x20B9E84C0324D661ULL,
		0x85CD229A18449BBDULL,
		0x8E862C8289754835ULL,
		0xA0E8D711FEEF1CA0ULL,
		0xE4DF837AAC2E77C2ULL,
		0x67DBA37328C9F0AFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x607C43DC9324D2BDULL,
		0x8D95BC67567A304AULL,
		0xD3AF6BCC79ACDB0EULL,
		0xBA08133DFC955D36ULL,
		0x62E3342894F53DF6ULL,
		0xFEABD2EA6F3EBA44ULL,
		0x7303B6BC93A8DB6BULL,
		0xB60A109A97CF2B31ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x08A0852DF6087905ULL,
		0x115B1C28FFF9A7A1ULL,
		0x33AAE0B72D4D302FULL,
		0x30E0DB81A0E88F4BULL,
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
		0x2E7D47717A6AE0F8ULL,
		0x7C2E1FE0B72ABB29ULL,
		0x689F4A91CAA3807BULL,
		0x764AD72D45C9DC4FULL,
		0x3AC80C337DDDB826ULL,
		0x84AFC4DCDE5B375EULL,
		0x905480726F1063CFULL,
		0x141FCF1579EF9178ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x49A91DCC5E7B52E4ULL,
		0x2E625C18F9032E30ULL,
		0xDB365E657A1AA1FFULL,
		0xED9D7322A5C29B97ULL,
		0xA111B213F8CE03F5ULL,
		0x55D399587344019AULL,
		0xD8C7E4A209EDDA27ULL,
		0x471317D2631329B1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB5E58A52DC444C17ULL,
		0x427A396FA3998801ULL,
		0xCC480D1B53A94D73ULL,
		0x7890980004BEA836ULL,
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
		0xB9746348F16C3B56ULL,
		0x4997E61B99A3916EULL,
		0xF658E8EA3688F25CULL,
		0xFF93DA65147BE83DULL,
		0x4870FBDDA74EF78AULL,
		0x6A3067777B43F445ULL,
		0x3D7D745413A140C4ULL,
		0x9FB32254B11FB86BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1F1220C1A0D747F4ULL,
		0xE467246A83EBA708ULL,
		0xFAEBD218D8543A09ULL,
		0x0C6EAF956E7A2313ULL,
		0xB8B42BC2CADFCBCBULL,
		0xDC2DD332B9D72768ULL,
		0xE0D363CE5AD5C59CULL,
		0xAB1483BDCC151924ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF069268409157196ULL,
		0x7992C3E5CBDE5323ULL,
		0xBCAB8AAACC690031ULL,
		0x42B0B535A595699BULL,
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
		0x226C27A44D8160FCULL,
		0xF47C4566E410BE12ULL,
		0x5CF4B927FFE5C851ULL,
		0x4B000DB1CB3C2F85ULL,
		0x42CE81ABB1291444ULL,
		0x46A2213951DB4309ULL,
		0x14220DFA2AC1473EULL,
		0x12D79B6BF17F9F5FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8D44740E1818D3A3ULL,
		0xBEC87BE60D2EB10FULL,
		0x8B86C246EF0F1A03ULL,
		0x01C6F97B2543E05EULL,
		0x505A4B75D76CE968ULL,
		0x044723FE5975D110ULL,
		0x7216930A95A85391ULL,
		0x9DA5A0CE4F41A79EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9267BF948756E6F6ULL,
		0x0F356041B5F0F7F6ULL,
		0xDF223671328ADA06ULL,
		0x2EA4479CBB2B15BEULL,
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
		0xCB924ED3D4E7DCC8ULL,
		0x88B551075DC5A903ULL,
		0x069FF103A9B3A4CAULL,
		0x2726EC3F735E40AEULL,
		0x656346B3B53AE7DEULL,
		0x14C25270034825E4ULL,
		0x649D89A22F00B7E4ULL,
		0x21B79EE043789107ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF86F9AF4AF67D3D9ULL,
		0x6BC861E60C6F5B53ULL,
		0xB7A160F6B1C55EB3ULL,
		0x5481E95D7AD7184CULL,
		0xC9647B2A39BE0F6CULL,
		0xA31EBB0947C2502AULL,
		0xBC7301CCFF8129D0ULL,
		0x93158FF7E4250BFCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFAF4EA477A082742ULL,
		0xFB3568612734073CULL,
		0x454EB9B204DD5CF9ULL,
		0x7EB339601EECE7F6ULL,
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
		0xC2E321AA80022EE6ULL,
		0xE466A454EDF4ED5CULL,
		0x15AFD0ADA44BAB29ULL,
		0xBC6FC4A745E0BE26ULL,
		0x58640C4A3568C7F5ULL,
		0x239A6510823CF7A8ULL,
		0x7316711032AE78AAULL,
		0x5C0F9EA03F32868FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x56A60F924B75A918ULL,
		0x943D5E50CD4EC5B9ULL,
		0x7170DE5C1BA0BCEDULL,
		0xC92EDDFA78CF9C76ULL,
		0x7F6D12FD0B900D80ULL,
		0x25D8B314DC681C94ULL,
		0xF8838594959802A0ULL,
		0x6A07553F96EDE07AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA0E6138C6AB832CDULL,
		0xFAE9B15EBE3EAC95ULL,
		0xD60DE6AADA0073B7ULL,
		0x607BCB05C741C8B9ULL,
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
		0xEFC17F30C2A5F32AULL,
		0xDAECFC570BE9AB4EULL,
		0x51287F49896A3CFEULL,
		0x1BD28D56FC8EE8D9ULL,
		0xA430476CCB547C1BULL,
		0x4B8F6A05E8B7D6C8ULL,
		0x35C12AD33C44EF90ULL,
		0x9EA8A63BF2940365ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x85F03F3BBFE840B5ULL,
		0x9838F6A6D0F6E8FDULL,
		0x5F18B575AF7150A5ULL,
		0x8F81E29BF073CE1AULL,
		0x4DD24097ED114EB3ULL,
		0xF5E9337C92E57319ULL,
		0x406B5804F37FB6FDULL,
		0x959931CF54B94778ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3BC6438E00B66FF8ULL,
		0xF9601E12F82D8E58ULL,
		0x5CCD1472A73F5211ULL,
		0x649BF2DA7A92FFEBULL,
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
		0xE6905DDA3FBA3B08ULL,
		0x4F505C219D3044ABULL,
		0x230959F8B974C5D5ULL,
		0xD7EE8FF43DA00C03ULL,
		0x565EA25A5F0BA2D2ULL,
		0xCD88AB4D549A871DULL,
		0xC95545BAE9C28619ULL,
		0xEF39F9AA35A2111FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC748AAEAB7E1A0EDULL,
		0x193A9190256BED1DULL,
		0xAB0BCD00F32201CBULL,
		0x2964A7619C7FF932ULL,
		0x10D0DDC2009146ECULL,
		0xDFF1A2E2D85ACDE0ULL,
		0x9BED3313B8F9C30EULL,
		0x450C4DBAD6BE7B37ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7252E18D8E024208ULL,
		0x7A810A5FE939D6A6ULL,
		0x357051C9041FB7A9ULL,
		0x71516E1AB6E85347ULL,
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
		0x4A6860B51515C8C4ULL,
		0x8F0340ED45410215ULL,
		0x8822BAA229440955ULL,
		0x0025DA9B562FFDD0ULL,
		0xA7E1EA0913CCFDB7ULL,
		0x1A5EB432ADCD3A21ULL,
		0x22D94433C48844EEULL,
		0xC969B17BD5B8B9ABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBDF4A7739BEC508CULL,
		0xFFC03055C61E4D3FULL,
		0xB5BE474D369207E0ULL,
		0x2195C041B9DDB767ULL,
		0x0169BCD9697CBD8BULL,
		0x49CFF1A33FD11765ULL,
		0xC0950B05DCE9F77FULL,
		0xADD33F14EBC53B3EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x424A6E54C112FF45ULL,
		0x8473F1E1D28FDCD6ULL,
		0x6884F02554317FE7ULL,
		0x76E515A056770A7FULL,
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
		0xFB4BF4FE22ED3580ULL,
		0x3B4B7A665EDB2142ULL,
		0x40A758F1FAFA2A62ULL,
		0xD5D769FEDF6B90B6ULL,
		0x748C65CC1A85D55DULL,
		0xA178DE96943120C9ULL,
		0x3C79C25F57D5BAE6ULL,
		0xC1207BBC4801F8E7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5B95F2760C03E3A5ULL,
		0x80A30CEE052D201DULL,
		0x1BF22C06EE17D166ULL,
		0x1F7722EE89070DB2ULL,
		0xF857412CF917D0E5ULL,
		0x5AD2BA56A06572F6ULL,
		0xB2AF08FBD6C22A84ULL,
		0xC9E0551A49A1065BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0F9972270D3DFB85ULL,
		0x3751CEF689E9CE64ULL,
		0x98CCB1B035C9C792ULL,
		0x69E6031C18C883BAULL,
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
		0x6452194486AB3953ULL,
		0xEACC73EB0219219DULL,
		0xA5B31ECBFC31E98DULL,
		0x84906CA87802BCDCULL,
		0x2E69BAC641DB1CC3ULL,
		0xFA1909227DA50A63ULL,
		0x4538CF174E1F1013ULL,
		0xB00BA8EED0C1A314ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x759190A7E05ED977ULL,
		0xA4A270461F5A71A4ULL,
		0x67C770EC2C8A19C8ULL,
		0x88247D2BD878C57FULL,
		0x9DC9F58A91F154ECULL,
		0xA183A73B412E2FD4ULL,
		0xE03F37B79682A5A3ULL,
		0xABEC531BE3478867ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6677CF78C30009D9ULL,
		0x6C568BF7DC632122ULL,
		0x3AF8261510DF9C72ULL,
		0x1912ACCBDFA9ECF4ULL,
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
		0x8F26ABF31206E167ULL,
		0xE066E03EBBB7CB50ULL,
		0x1A8AE679A8FAE0B3ULL,
		0x7282E0EABF096D3FULL,
		0xEE167266E58AAF58ULL,
		0xBEB7132B47604C44ULL,
		0x93D7213C53BCECAAULL,
		0x635103F8520E1CEEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFC1062F5DF7272A8ULL,
		0xE51A5E74471039FFULL,
		0x2B57DB29224FAEC4ULL,
		0x559F50AC94064284ULL,
		0x565381F796E51464ULL,
		0x082D90E37DE4DA3BULL,
		0x86B2614CAA3E6F3AULL,
		0x5C313D5BD8EC4A80ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1A05F982DF296F1DULL,
		0x13B5D8725CFA7EBDULL,
		0xE2A788E3AF71D0AAULL,
		0x2B9B0B7826086710ULL,
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
		0x10EDD19469416A16ULL,
		0x5A7AFC07B69CB9BBULL,
		0x9F639DB8F7222A58ULL,
		0x9450E5B54BD4273CULL,
		0x5D64DA909FBEA3CAULL,
		0xC10ACDFE6132BBF7ULL,
		0x4EFA33BCD73ADB8FULL,
		0xFF3643625A31FB9DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD19CBAEC999521EEULL,
		0x711C70883C28A279ULL,
		0x3078441A1958E806ULL,
		0xF3A5B252B6B70372ULL,
		0x6163960222595B30ULL,
		0x0865EC8844F8BF43ULL,
		0x3476959F7597B3D6ULL,
		0xF0F6DEF2EE999D67ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA78143CE6CB50F3DULL,
		0x51D80307AB0F99F8ULL,
		0x5E74D1FB5C0127E3ULL,
		0x3E141BEC8DBB1FD2ULL,
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
		0xA9F267D647FDA86EULL,
		0x335B678E3C5CEEF9ULL,
		0x36BB7BD4C16C2B48ULL,
		0xECA22810F8D3749EULL,
		0xA74838FF27FA5DFFULL,
		0x5B4AAC8AB9D68F76ULL,
		0x384DD68D10DE4576ULL,
		0x971B684D69A9DFA6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3546E2AC2D653E28ULL,
		0x1E81299E12CE9E83ULL,
		0x589BAAC01263EA1EULL,
		0x86EEB7D7655CDFA7ULL,
		0x430B9D792752EA65ULL,
		0x4DC066B410FE6AF6ULL,
		0xB81616777B067C47ULL,
		0xFE3741178271DED3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x55AA9B0E337390E8ULL,
		0x17609BCD39A3BB85ULL,
		0xE6665448ED101E26ULL,
		0x17914239E5C6B435ULL,
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
		0x5B40C7E96DE13E25ULL,
		0xAB0357AABB4447E1ULL,
		0x004EF68EB3871789ULL,
		0x9452EF48D44A204BULL,
		0xEF655013DAB19F7BULL,
		0xA208F589802F239EULL,
		0xD1A0C8CBCEAF767DULL,
		0xFD8647FF8321D601ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3818FA11D2493BE8ULL,
		0x08E175B5E76BCF46ULL,
		0xCFB7773EAF71577DULL,
		0x181841ECC87354BCULL,
		0xF76D22E5EF6153EAULL,
		0xBB68AB56E23074D9ULL,
		0x61A0DD738B9CFEC4ULL,
		0x52DD27D781B78118ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF1FE82A889833D8CULL,
		0xDDECE57847A669D7ULL,
		0xD0946E69F8D3857EULL,
		0x5155734C419F6634ULL,
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
		0x7060FCE020B7534BULL,
		0x5D872541CEBA2CE2ULL,
		0x7021936F53ABF308ULL,
		0x1557BE32123818A5ULL,
		0xFD39108819AD63E3ULL,
		0xA6F1A6ADAF7DDB01ULL,
		0x4C897401ABD3C2C4ULL,
		0x74014E1DDF7CC68EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB3DBA515A682EF11ULL,
		0xB17B9986B1DA07DAULL,
		0xD34557737C5FC655ULL,
		0x378E5833A332F264ULL,
		0x21734BA257B58F04ULL,
		0x0409B3A23FB9D707ULL,
		0xCA2898965C427F62ULL,
		0xA2F3CF505497BC34ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5BE091E544FDFC37ULL,
		0xDA799F6DB3F8BC44ULL,
		0xF73CCDE9A6DC2D56ULL,
		0x65CA38810D04AF89ULL,
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
		0x7CFDCC118FA273D0ULL,
		0xF4BF7F8EDEF9A960ULL,
		0xFA120D54A56A3978ULL,
		0xBC36E0D04590D84AULL,
		0xF6DE4702E47ADB77ULL,
		0x0E510F883C046E9AULL,
		0x0FA9E625493CDC91ULL,
		0x9A0ECFF646F36D65ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCAF9A76624572166ULL,
		0xC4BA50801B6482F1ULL,
		0x036D4ABAD61FB120ULL,
		0x27610DA0DA2EFB31ULL,
		0x1F80AE10A4DAAD9EULL,
		0xD177722BA4585B5EULL,
		0xFF838CDF952675A7ULL,
		0x7C5014E2F265CD9BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA9E8D8A0DD12214BULL,
		0x38528ACD47200176ULL,
		0x5C5602F28A9DCEF7ULL,
		0x7F25980DF86794F2ULL,
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
		0xE521058388DD63D4ULL,
		0x46FC5381C3AEA975ULL,
		0x73FAC750FA2BA58AULL,
		0xEBC50B067D2E3B4EULL,
		0x43C658A6768B0DCCULL,
		0x4A18388A1F7C30EBULL,
		0x4BA09B62C0BE00C7ULL,
		0x006B220501DDA4F1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x99497F12BC2AB36DULL,
		0xE856D1DC659AB0D3ULL,
		0x08CF75FD2BA362F6ULL,
		0x0077838DAF5E0ECEULL,
		0x634FA74369A40B3CULL,
		0x36033E1CB61F5BD9ULL,
		0xBC1EDC6FA23F02B3ULL,
		0x8D6B489ECB41F561ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9D75DB24B6FD0EBCULL,
		0x59C2ADE301DB9949ULL,
		0xB86DA96A5561F98EULL,
		0x7D47CCA4E8EC3BCFULL,
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
		0xB4431C382AB2EA77ULL,
		0xD643B2A75E37C270ULL,
		0x5152680B64CB94CDULL,
		0x57B0969C08655BDFULL,
		0xF6D9450DC33D1512ULL,
		0x722E5DFFD7510D14ULL,
		0x91DFEB42E68B0F4BULL,
		0x13824FB3BD3DDE30ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2BF3CAD30BF931D3ULL,
		0x7BD6182CDA091BCFULL,
		0x59CC43FC46E708E2ULL,
		0xC28FBAC329445E7EULL,
		0xA5379D8E6BF32C24ULL,
		0x21E76C3A0776FDD7ULL,
		0x832C6054C1EBC4B5ULL,
		0xC85F13EF65F8947EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA64E2E4C13B247E3ULL,
		0x44F57DD75E8CE9BBULL,
		0x262CC3688D899E3BULL,
		0x3C5BBAFDD369EDCFULL,
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
		0x8DDD66766F042194ULL,
		0xBB6F491E2396037EULL,
		0x5B89CA57D388F2DFULL,
		0x7E4B88703657C24AULL,
		0x41890FA81B707E5BULL,
		0xF252A8AF1EC4B1D0ULL,
		0xFC4774E69C51D818ULL,
		0x917C900AA0D0A266ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD6384E8986E83C74ULL,
		0x2698983031656CD2ULL,
		0xAB8E750F91B04256ULL,
		0x5AF855DAA5454963ULL,
		0xB514F6D795E1022DULL,
		0xC36B8811B32C606CULL,
		0xCA8364D3F828897FULL,
		0xAF30E345B2031E13ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x90E0C6E0BB685349ULL,
		0x8B25884BEACCAB72ULL,
		0x1315B80C9FFA5B46ULL,
		0x3A8ED7D103941D40ULL,
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
		0xA111E96F3832EBAFULL,
		0xB89D590DEAC98235ULL,
		0xA3C5899FF6E6B640ULL,
		0x8074A7AB28AFE725ULL,
		0xF58467CE32E31DC3ULL,
		0xB9A390A0DAD25665ULL,
		0xC654F23EE4F13566ULL,
		0xAA110C74505E218AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xECFCAD420C879101ULL,
		0x1CF0FFE431E45947ULL,
		0xE89AFE81BE7390F3ULL,
		0x9DB16E02F3737A7DULL,
		0x41C166E4794876FDULL,
		0x8E98DCD2276C308CULL,
		0xA06C34DA1850E05CULL,
		0x017049AE6DA65A6DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x63075EDEB8A01FB5ULL,
		0xFF4309D85A0EC73EULL,
		0x5BB6A814983FC4CFULL,
		0x6AA02307DC83FAFBULL,
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
		0x7074766AE9B1EC4DULL,
		0xF4523BB55BA623B3ULL,
		0x13FBF8347D79D233ULL,
		0xD584B42303C6E8F9ULL,
		0x682DA47E99B1281AULL,
		0x117854A72C100E4EULL,
		0xA9AC194DA84D7919ULL,
		0x80000710C74C6A53ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2111648E15826F40ULL,
		0x6D4216550FB09CCDULL,
		0x7E2BA20E509602C5ULL,
		0xC9E7C0FDDFB0F2E1ULL,
		0x2A459C3BDA9556D6ULL,
		0x35A8CE4EB1E1DCE6ULL,
		0x7C1E90443E0E18B1ULL,
		0xEB4D0150FB9A80FFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7FD44BC532508AC5ULL,
		0x27DE16826ED0DC5FULL,
		0x58D2AD8BF24C1ED9ULL,
		0x1E2FCD9D607E9896ULL,
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
		0x6A9E04ABB8274C99ULL,
		0x5B924E8CA0AF3C7BULL,
		0x35240F036A40F1F0ULL,
		0x937B62822EFC9B11ULL,
		0x87DB095A521AC0D6ULL,
		0xD0E7D0655FF2A78EULL,
		0xC3657D57CD2118BAULL,
		0x9AA9C71DACCA79D6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCB19C59C1C77CF28ULL,
		0xA1707D39F5A6BB41ULL,
		0x0799A12602C7DADFULL,
		0x52178509BBEDE8DBULL,
		0x261A05513A19B4E1ULL,
		0x08298AED4C735AC4ULL,
		0x42398CAEB29C57A0ULL,
		0x72575775DE2AEA0CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x222AD8692BD744B3ULL,
		0x866021258FEDE744ULL,
		0x5A1026F7572DC10AULL,
		0x3DA070611EBE0A45ULL,
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
		0x53A9F5D9A0C7DC42ULL,
		0x350A68D3C9153FCAULL,
		0xA4A302F1F6E79704ULL,
		0x9A8A54195FA6694DULL,
		0x010B5B8A036AB132ULL,
		0x6FDADE22066B93B9ULL,
		0x765A62E34081B9DBULL,
		0xD7D1539237C28BFFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBA7791FD71A7EA7DULL,
		0xA355EE75A20C30E3ULL,
		0x15D24669FCA0AEEBULL,
		0x090CC7AC087BB982ULL,
		0x9B50613C4D2EAE1FULL,
		0xC0E636CAF90794D0ULL,
		0xD67F8632FCCF5FC1ULL,
		0x8C278FE7532D98BBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB2F38B653C08684CULL,
		0x8A05514A23E0E565ULL,
		0x494D7EB206C047E8ULL,
		0x4CB097CB4546CBD5ULL,
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
		0x3DC04256F9EA93BBULL,
		0x875FE9D566A36AD4ULL,
		0xC8FEE1D4F2313601ULL,
		0xBBB300E47E9B9EE6ULL,
		0x652B6922859977F8ULL,
		0x4B4785A7B804F2D8ULL,
		0xFA438D9EE0D60643ULL,
		0x5F4C19C8516B7206ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF207DB57E08AA8E8ULL,
		0x3DF37EC6377CC56FULL,
		0x710DB7D984C83658ULL,
		0xE5443DD83779AB80ULL,
		0xA7B6DBEE823CBBE1ULL,
		0x57ECCBA77655D57EULL,
		0xC47C7320C6EC38C8ULL,
		0xE58E9FFD12516E50ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6B055CB79923D332ULL,
		0x68E40718EF2500B6ULL,
		0x537F18B3461D7FE9ULL,
		0x688ED737A4FE8072ULL,
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
		0xFB2EBA8F909BF693ULL,
		0x2851968D743ABEA5ULL,
		0x39E12BE7365488F4ULL,
		0x349F0B2322DD6151ULL,
		0x32BDF467DAA785E5ULL,
		0x051F93B0163EC34EULL,
		0x1DA85843B10FE422ULL,
		0x22819F4822CA8399ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x694187BCBE1F72D2ULL,
		0x3668CDAC9D60E534ULL,
		0x3215E3FC7C258A67ULL,
		0x40B1CAD9EF7AC51FULL,
		0x251367102259A760ULL,
		0x925EB70621A307FBULL,
		0x480E81E9AB209053ULL,
		0xC6CB56539ABF4664ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x993E2DD82E0B87DCULL,
		0xFA898A1B25F7A7C5ULL,
		0xBCA119479BB56F31ULL,
		0x10FC1495650DB209ULL,
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
		0xA9962C4C6410B231ULL,
		0x242D27EB39DCBA92ULL,
		0xABC90CA33C1D179FULL,
		0xC77510DBFF5C1126ULL,
		0x0A050E8E3B0F760EULL,
		0x362DB89D57FC049EULL,
		0xAECD2179616BA61FULL,
		0x2BE2034E6FBE0DC0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0831E06D1E5A63DEULL,
		0x1DCFDA300FEBCD15ULL,
		0xFE72F32B76E082A2ULL,
		0x1499FD946E0B239AULL,
		0xB063FCBE1EBF87ACULL,
		0x0B2D96A3FE471922ULL,
		0x662A66D65B50FA38ULL,
		0xAA70EB6AE8C67AC8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEF4CF0C37993AE20ULL,
		0x686258BE7ACBE1CCULL,
		0x757DCDAAAD32194DULL,
		0x69A49F0D9A10BE66ULL,
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
		0x2657F8E5590941ADULL,
		0xAE71B07EE6EF1A14ULL,
		0x9DC28CE8E8CBAD31ULL,
		0x8511EC90510179F6ULL,
		0x8BD21AC8EE755EC1ULL,
		0xC1A19B8BA07EF5EFULL,
		0x302B6F97924A8CC9ULL,
		0xB4F652AEA884739CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x88EFEF44EC29E876ULL,
		0x53BB1305AC8E004CULL,
		0x4B1D87143837FCA5ULL,
		0x97AEB7265CA42638ULL,
		0x644E56D2F9E9922CULL,
		0xC0BAC62EA180E455ULL,
		0xEC2C8037839EF171ULL,
		0x90EBC4899A147021ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7AF72022B99FB813ULL,
		0x7CFA49471417B6A9ULL,
		0x6A7C8E16DE0CBF9CULL,
		0x46F44EEA18FDD7E4ULL,
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
		0x870F729B2BFD53B9ULL,
		0x81E4373399B3210CULL,
		0x3166B18B4CEE9194ULL,
		0x28DAE1B18C3C1DF5ULL,
		0xDD0857429E0D05C8ULL,
		0x79ECC16F00EF0491ULL,
		0xCB0C33E79AFA9812ULL,
		0x3EFA7BA0A5863EE1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAC9CD6DD14B2DA1CULL,
		0x27425C9EC1088008ULL,
		0xAB3BEA108EECDF1DULL,
		0xC94E6504145BA696ULL,
		0xED892DCD7D81521AULL,
		0x35960B160853BBF4ULL,
		0xEC2DF26F61CCCD70ULL,
		0x729EF287FC17A4DBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6752C320EC07242EULL,
		0x7F80EBC9BFB7684FULL,
		0x9B287F533ACDC68DULL,
		0x3522D6569E4B543DULL,
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
		0x1C497C205E806E6AULL,
		0x376157B07EEF83DBULL,
		0x6E5511B59906C4F9ULL,
		0x58412220E9F59C4CULL,
		0xE3BD1CF6DC1E33D8ULL,
		0x0AF49477C357CD31ULL,
		0x07E9C2185B08B846ULL,
		0x2C456596A8D07010ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFA0D4D63D55FB9B8ULL,
		0xA07F0B2A46D980ADULL,
		0x20A53F2661213D01ULL,
		0xE58D6817C7132367ULL,
		0x677F15FA9D17DF62ULL,
		0x12348F696FB5ADFAULL,
		0xEEA525AA9EA07013ULL,
		0xD99CB099332AAA12ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9371382DE4113A47ULL,
		0x83630CA6A226A569ULL,
		0x0DDF0AD92F603F88ULL,
		0x37BE97A8997DDC77ULL,
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
		0xAFC404877F24C081ULL,
		0x93ED3434E242D30EULL,
		0xC3013CBF7552F8E0ULL,
		0xA23B1E7B7BDDC93EULL,
		0x3A49FF70B34BD277ULL,
		0xB24428F1E4B5F8FBULL,
		0xFC1D58FF46A2A1BCULL,
		0x90DC53F6769949CBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x068438308EB0C10DULL,
		0x33419EC25D96E199ULL,
		0xB2BD88F1B2E6F774ULL,
		0x8F89F5BCB67950D2ULL,
		0x657B3C45F2BCD6CAULL,
		0x74DBED004CAC6907ULL,
		0x5D938083848C6126ULL,
		0x0174CA5C854DE336ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3FF0C4AF85AD5E40ULL,
		0x7E247B4F16174FA7ULL,
		0x98B9D62C91B997B9ULL,
		0x5C0F95989695B2A1ULL,
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
		0xBCFB9B93BDDE3B2BULL,
		0xB9306566C47EE2E8ULL,
		0xC51930B8D6EEED63ULL,
		0x27F91B94C3680AFDULL,
		0x138662C97B2F3FD1ULL,
		0xB33B15CA5B2A1CFFULL,
		0x0D04ED05D24D89C2ULL,
		0xA8B868B2E6000E1DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC8001B523EFBCAEEULL,
		0x95380F056AEF65ACULL,
		0x8E2974D7AC1409E3ULL,
		0x3439A47F9F5CEB34ULL,
		0xFA2C85C8E2A5A597ULL,
		0x3A0BD28C2D461C06ULL,
		0x6063423B609C2FECULL,
		0x3A46C4E7DF130B46ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB8524E58234F5739ULL,
		0x20FC519C2967A20FULL,
		0xD6EF15EE0B2E3956ULL,
		0x589DC7382B398BA6ULL,
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
		0xEF337B71856FF1A8ULL,
		0x1D09B6DF20EC5C4BULL,
		0x8219D4CB6409B844ULL,
		0x55115076FE5ABDDBULL,
		0xE809ECD317BEF3DDULL,
		0x4235AD11EAB3CFA0ULL,
		0x337A093F50CB5572ULL,
		0x78FF4ED6972202D1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC8ADB077C52CF57EULL,
		0x5660F4CD1FBA71AAULL,
		0xCD74A9ADE7C003A1ULL,
		0xAB50B5FAA3B5AD47ULL,
		0x0A69CC1A12A88A05ULL,
		0xC1B6CF7B3FBA9C37ULL,
		0x84E9680650ED66E9ULL,
		0x4A8E4EC0C1BE90B2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0C4AA6708196B331ULL,
		0xD97DA66F622F8C58ULL,
		0x9E1D1993773B1CE5ULL,
		0x0E869DBA07680121ULL,
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
		0x877E000CE7328098ULL,
		0x8E758B22FF5B17E1ULL,
		0xD07EDF825608F458ULL,
		0xE9B7CA24C76C9844ULL,
		0xA09121F1C21D4982ULL,
		0x71F2A13BD3BC5E0BULL,
		0x6A3810416E57C26AULL,
		0x208E5188C0D81EEDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9A0A483564491704ULL,
		0x988C5296342E37C1ULL,
		0x5A52A6972C1C4221ULL,
		0xD268FFE21D51AA39ULL,
		0x1BB1FA7E8235FC16ULL,
		0xEA92B88575FFEB88ULL,
		0xBCCFE2A4EB7E49A1ULL,
		0x083A35DF3C0182A7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA69392F2FF3EE821ULL,
		0x0E25C39EB525DFA5ULL,
		0x33A2FE2696349FFBULL,
		0x33CAE56C61F62063ULL,
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
		0xC4F6AF8ADEDCC269ULL,
		0x538BF51D2FA6E5D0ULL,
		0x9C7E9FE08E706445ULL,
		0x52253B13F58228BEULL,
		0xBF16511913336D4BULL,
		0xB9D10DF93FBCE1FDULL,
		0x7B8FBBA0F2F9D786ULL,
		0x00558934A558964CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x59CDC4211D1728A4ULL,
		0xDFA3BAAC57BDFB6CULL,
		0xE7C83448DB8445EDULL,
		0x6456EC30D774430CULL,
		0x5D5FEBA902F2730CULL,
		0xE5B66D230D7FE713ULL,
		0x2D12CB9940D551ECULL,
		0x544BAB9CF120D3CFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEC3BFA0C2B6ABD31ULL,
		0xEFDC1A3C4CF6292EULL,
		0x5B420CBC2457F32CULL,
		0x77453367DE54C44BULL,
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
		0x54DDEA0CDC0B100FULL,
		0xFD20DA2FAFC265AFULL,
		0x8CA8611E51C59E78ULL,
		0x40A992F8CF10AF2FULL,
		0xE76D265C1C3A66A3ULL,
		0x31FA068C8A51ED0AULL,
		0x841295664EA4F6EEULL,
		0xCABFA81F1B145327ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFA3206AAAD945F1FULL,
		0x6A58107EC115ED4BULL,
		0xEF2C73DF1FBE42B4ULL,
		0x3D71BA8E6C59A9BFULL,
		0x2025DF8448E3E2FCULL,
		0x54500A811C61D341ULL,
		0xBF9C3C2B4904A7C9ULL,
		0x1DA6AFDA8A362D04ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEF40676B8D4E3F83ULL,
		0x7A04336340504C56ULL,
		0xC70D2C0207D31B3DULL,
		0x34ECB297E3B0AE98ULL,
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
		0x1D1A03C5A2455F19ULL,
		0x6446AB48C3BD52D1ULL,
		0xB036BA302B6239D3ULL,
		0x8EFBAB52874230CDULL,
		0x405E4A4BD08316F8ULL,
		0x24FBC95F43B84F2CULL,
		0xEF8AAB4ECD16764AULL,
		0xDC81B4DC673C2237ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7ED86CDD1D8C9F6DULL,
		0x777FC9F9F7F9AAAFULL,
		0x094875428BA48017ULL,
		0x91AD9095486F215CULL,
		0xCB37A3BD3516FEE8ULL,
		0xD567384370158C3EULL,
		0x64025CD4F6F515DDULL,
		0x0B4E229B0FD43CDEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x01FE501396C456A6ULL,
		0xBCD46B7035EC9761ULL,
		0x5D29EB0368B209CFULL,
		0x0AF5D070383F1ABCULL,
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
		0x80FF4A34CB13D067ULL,
		0x0AB5B9231C2DA451ULL,
		0x49798F0C5B4AF3C3ULL,
		0x520A59953042B917ULL,
		0x360774E7E6AF5B55ULL,
		0x97449623FA1821F4ULL,
		0x0F9EB8E0D2FEE4E9ULL,
		0x542FC1B239CD1BB8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7717FE16A5234B6DULL,
		0x12127D1A8F08FA58ULL,
		0x1958F8801075E32AULL,
		0x635504B6B4BDA285ULL,
		0xA4742D7855AF01A8ULL,
		0x16516CC54D03B8A4ULL,
		0x58C83C2875A467E1ULL,
		0xBA619E4B42D4B1EAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA5C3E6ADABFDD25BULL,
		0x1CBB60163E2C4BC8ULL,
		0x53F719EA26439FDCULL,
		0x434E96272464CB1BULL,
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
		0x4E5A36158F8B7DD2ULL,
		0x5DE42E0108AC0A4FULL,
		0xD49DE5075EFB1D5DULL,
		0x22AB7F1E2A4249C3ULL,
		0x4B295668844AEA4DULL,
		0x349412D172CA8C39ULL,
		0x9AF42A085265573EULL,
		0xA5D0BC4F31A8D992ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7ABABD77A8EA06BEULL,
		0x7E8D41E47C296A7DULL,
		0x4E1BDEBEDA4C2992ULL,
		0xFEDF20D240C5890BULL,
		0xC5069ED25297BC9DULL,
		0x86B60215DEECF817ULL,
		0x62405E6EBCF06C44ULL,
		0x710481A42580BA04ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBCC6B8E9473A402BULL,
		0xAE4D67F47F669CCBULL,
		0xF1323F14B409D4DAULL,
		0x7A1D13AFB7716FD4ULL,
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
		0x2546501F763C1BEFULL,
		0x50EBFB54E1C00A04ULL,
		0xC1850DC19557331EULL,
		0x18EC4197A6FB35D8ULL,
		0xDD284FDDF8D5C331ULL,
		0xF50838C37066958EULL,
		0xAB5E4252A913BE25ULL,
		0x660262D12B28061BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAB0DD059EA05627CULL,
		0x93D9F97FDAE99546ULL,
		0x0A8916A815B9DB4CULL,
		0xC56DFF77330FC3CDULL,
		0x62F76C768C52483AULL,
		0xBE9E33A5E113480EULL,
		0x43AF09F561842ABDULL,
		0xD30E87017A1D9BA0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9D7A411FA7BAF797ULL,
		0xD0CEC4384D33F5CFULL,
		0x1AFE54F21EED3949ULL,
		0x23B0E2F4BB77405DULL,
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
		0x458603EAEEA204EAULL,
		0x766FD7F1AA6FEBDDULL,
		0xAEC57DDF77E257B8ULL,
		0xF6D7E1F8C461B1D9ULL,
		0x181213B9A8B35FFBULL,
		0xF19AF30EA15B2FECULL,
		0x94FE2E59788509D4ULL,
		0x3430C2EAF2BB0CD9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4DC7738728DADD4BULL,
		0x884166B9E698BE54ULL,
		0x787F50D1FDAA4A71ULL,
		0x971C23139B2E425FULL,
		0xE611C6CC6A7B48E7ULL,
		0x48D4F2E23D7F2552ULL,
		0x1CE46947E4269588ULL,
		0x84BABA090496D48CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x63C9FB9B021A92CFULL,
		0xFB9277CE9680C046ULL,
		0x0A196DA9803D50A7ULL,
		0x6B41106E8293CAFAULL,
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
		0x1EEBADCD2825417BULL,
		0x51B807897597983FULL,
		0x0FC83B44867000E9ULL,
		0x88E13C5168F92383ULL,
		0x343FC51ECD0C6869ULL,
		0xEDF815E0F8C8393AULL,
		0x88CFB76DABEB6347ULL,
		0xDBD19DCD641DE78BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBE8B0E90B5DC537BULL,
		0x8B0520908B914AB8ULL,
		0x429A9FF20F17C032ULL,
		0x6C3516292514E766ULL,
		0x54FEF21E96094027ULL,
		0x511C8E8E700FDB41ULL,
		0x05BBF5507319F236ULL,
		0xB4DE70FD82B7C9F8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x83FFF1449CC0E89DULL,
		0x0F48FD3935644077ULL,
		0x421C6BA8E66F0954ULL,
		0x64C4CD03B90CA002ULL,
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
		0xCD5397C73FEA600AULL,
		0x5493C69E6CFAF642ULL,
		0x099372627B9ED4F5ULL,
		0x4BB27C16DC25AEE1ULL,
		0xED18A2083CDD8BE1ULL,
		0x393733A3676993F2ULL,
		0xC487F1FC3FC4032FULL,
		0x592B35F4C8E43072ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB06A6BB6E935C73FULL,
		0x5F60BBBCF886D219ULL,
		0xE26DF3C7A05204D7ULL,
		0x7D9B7AC96EE924CFULL,
		0x3D945C1D070B9432ULL,
		0xA27A852E7219BEBEULL,
		0x5279A2008010603AULL,
		0xE86A7198437E70B0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2A8B8CFA53DF5994ULL,
		0x5534F03DDE4DC9FBULL,
		0x15455DF94FF7006CULL,
		0x0AB427093A5700EEULL,
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
		0xEFADF51B120590FDULL,
		0xA25D473E1F046422ULL,
		0x53881B5B707E5C52ULL,
		0x55C5F8994C919A4AULL,
		0xDFD822AAC2BEFD66ULL,
		0x7908B0631DFB4562ULL,
		0x9E9777163B7F115CULL,
		0xD6617637F53312DAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA3F0F7BA9231DB33ULL,
		0x8A20EBC99DDC400AULL,
		0xE61C3E761EE890ADULL,
		0x749AE45E58B38047ULL,
		0x63EC84D9AC45FC35ULL,
		0xD7BAC4F8757CEAD3ULL,
		0x27AAEAB6F760E1E6ULL,
		0xA1F7ADB15108EFDCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB0B66A69D5C9E42DULL,
		0x09CD4D4983E99564ULL,
		0x1488B3096E10D71BULL,
		0x28DED837521F4BC8ULL,
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
		0x3CFBAD04C45327E2ULL,
		0xCCA857F5AA5BDE83ULL,
		0x6C63ABA4C52FEA0DULL,
		0x8FA8078546A07D6BULL,
		0xD0327DBEFBD52F2FULL,
		0xC518FE88B2CB1B8BULL,
		0x1C8C497AD27C4126ULL,
		0xDE2603C583C93086ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBE1823587DA0F74DULL,
		0xC531699984093FB7ULL,
		0x5092D584FA15DF10ULL,
		0xDB875970CBDCC96BULL,
		0x703AE084810C12F1ULL,
		0xD582FDD33817C6DDULL,
		0x960376781CA24499ULL,
		0x102CA56984962EC9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBDA4E05A808C663DULL,
		0x97BB094C5CF130ADULL,
		0x14202886C97587E8ULL,
		0x4724AFBC5C55F5FCULL,
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
		0x79CA1252FAE4761CULL,
		0x99F0EB7B5DBF1F6EULL,
		0xAE8B4CE6227EA6E0ULL,
		0x161F705648340E06ULL,
		0xF3EA69E9AB1C8D84ULL,
		0xB7036A5BF29F93D2ULL,
		0x39653E776B61BA46ULL,
		0xCD52482959D63778ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD4D876B57638EF26ULL,
		0xE1DABCBE63FC22B4ULL,
		0x41A16E277B4A1A63ULL,
		0xF8E759579EE17DB5ULL,
		0xD023DDC28A4A486DULL,
		0x490681524AAC92C5ULL,
		0x557D2D6DA785E6DEULL,
		0x8ED297A1CC2FACA1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF46A696C63E1C990ULL,
		0x0BA0C62BE7D524ACULL,
		0x415C6631B9D5EDFDULL,
		0x642C4B1DB00B2C37ULL,
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
		0x7AAE53788AEF787CULL,
		0x3D2A0227A996FCA8ULL,
		0x26D476844FA8213FULL,
		0x63673B1A13E13B4FULL,
		0xAAA37C1E8D75DF2EULL,
		0xBDE14843535A814EULL,
		0x622E7869263DCEFFULL,
		0xEAE65CEFDC752FE7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0E290205215E1123ULL,
		0xEA98C91A22FF13D6ULL,
		0x9B0E5E64F1E52266ULL,
		0x3A01E245BE5E61F4ULL,
		0xE12130F7D5E7306DULL,
		0x6B1EC44D6C608D4CULL,
		0xACF1EFA1135F8492ULL,
		0xEEADBDC99813410FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x55DC7932A8BF57ECULL,
		0x9B70CF8DCFB22116ULL,
		0x72C265D22AC20B12ULL,
		0x19CCF8827C0C4D5FULL,
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
		0x4981FB3056A84282ULL,
		0xC4AE0A740733693BULL,
		0x53B67C2A5F449B73ULL,
		0x5E719E77E131AA00ULL,
		0xC58EFAF8A650085AULL,
		0xB02681DC8E3284C1ULL,
		0x97E7F55879B4CE07ULL,
		0x4528FB9C99A4C0D1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD0E2DFFFADEDDDB1ULL,
		0xB4FB679D30154D8FULL,
		0x75F8B971CF35AC1BULL,
		0x8E63222FA3FF5855ULL,
		0xDFA9F9AB08EB7CF4ULL,
		0xD302C5A68DD50F2BULL,
		0xA693BD20E29E8E7DULL,
		0x275E5387A2E322A9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x989D4CB605A7168DULL,
		0xE30092DAE4FD8FEBULL,
		0xB03E1AF8FD5C5DCEULL,
		0x3C236F64DDEFCB98ULL,
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
		0x61728550ABEC46F8ULL,
		0x0B87CB09465524DCULL,
		0xD52201D2382CA4DAULL,
		0xFE79319F9EDA6A3AULL,
		0x33D544F16A65A0B8ULL,
		0x1C8A56496561ED81ULL,
		0xFF1480A2408DB0C9ULL,
		0x26C10C68F292B863ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x85C809CEEBB55EAAULL,
		0x8F4CD5CA087B1C13ULL,
		0x62578F915FA3BBCAULL,
		0xF9FDEA2783B661EDULL,
		0xCEA38F3085CFCD22ULL,
		0x60960BC2231F7E06ULL,
		0xA174CB0DEB4A4482ULL,
		0xD475045A5F453B9BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE10B7623AE744CB6ULL,
		0x627E055313B694F3ULL,
		0x587F6645808AFB8FULL,
		0x3BC479A1F8A48E0BULL,
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
		0x12AF41B36102F8C7ULL,
		0x54FD4D629B7C87CFULL,
		0x5B937A094DC798ECULL,
		0x2DF614BCDF4811D2ULL,
		0xDC15856FD4203F15ULL,
		0x14F9E6F57CBB4D26ULL,
		0x51F72C709C10118BULL,
		0xC5F3D74FB133BA14ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBD9DE82A672A932CULL,
		0x6B19F86EE62B56DAULL,
		0x47E7932C19B5FA3EULL,
		0xA264F2485AD03CEAULL,
		0x09617D0F0D09486FULL,
		0xE8FFF2C5C52E9B9DULL,
		0x2CCBEF351F294E07ULL,
		0x09503B7AE5BB2A37ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9BCA97E687410654ULL,
		0x70FD9408F4338B69ULL,
		0x9816FDB1BE52A426ULL,
		0x0BDA440AB85D2FBBULL,
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
		0x15AFF63317823EBFULL,
		0xF4ED95E1DB31658EULL,
		0xA423A54D329605FAULL,
		0x1D0B0B7D3EEC9EBDULL,
		0x4F437BE158E9EFCEULL,
		0xE966239BD9CAFB48ULL,
		0x927CBEF109D88519ULL,
		0x4182C584C30F0EEBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x144ECBF7B1F47A91ULL,
		0x185F748D0634FA7EULL,
		0x5DA4918E809ED757ULL,
		0x0BB341F6BC03A2BDULL,
		0xB6B9939F314730B4ULL,
		0x4DC2BBF57E13EE37ULL,
		0xBF5186D68FCA0CBBULL,
		0xBA369152FC541F04ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA5D9A40D47B61F5EULL,
		0xF6CF840672285B86ULL,
		0x9EE967ACD01D0CAEULL,
		0x26A788EA02A89843ULL,
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
		0xB42FD997DA7B40A2ULL,
		0xFBB7D5A1AD398B67ULL,
		0xB9A7A4CD7A75B700ULL,
		0xAD8DA673B582E147ULL,
		0xE9D628DDB507B09CULL,
		0x3BF3540338C11091ULL,
		0x02B089549B563FFFULL,
		0xB78079A950C4A344ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA434DA08EAA8D9EDULL,
		0xE9C553772FA7A22BULL,
		0x649D77F494A237D9ULL,
		0x683E8C031BEDB037ULL,
		0xC1347057EE820528ULL,
		0xBD6E38000382D4BFULL,
		0x668D73FE3BB07D9FULL,
		0xD38EED41C9DA9FB8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x17FC636A67A9D955ULL,
		0xD9B4AAA464CECA6EULL,
		0x823F57AB186E5953ULL,
		0x1B29F1CEA051B7C9ULL,
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
		0x9BD2033A3E788848ULL,
		0xE68D8D271D39A3C6ULL,
		0x84A25635EFF193EDULL,
		0x41FE25DE7C33D41CULL,
		0x68651BBE062A74C7ULL,
		0x940E0FA930AC96B8ULL,
		0x86C5CBEA1381B86DULL,
		0x43C86C8F088E5349ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x07334C53E1A99924ULL,
		0x46EF3237C727932BULL,
		0x6D0D3007C5784253ULL,
		0x2647D0E2BD36B6A8ULL,
		0xF71C6BB814597FBAULL,
		0x02B6DB6D897ABF1AULL,
		0xEAAEB96845C33954ULL,
		0x84E66C8D042C2344ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6568D7C841D34D96ULL,
		0x32901BCA277811FAULL,
		0x4301E572B4C02F66ULL,
		0x7142554865903E23ULL,
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
		0x47C2A3BFED18ECA6ULL,
		0xD22DD6168FA9A0E5ULL,
		0x6F92B7960D7F364DULL,
		0xF173314DFE200B59ULL,
		0x065C0DD26242BD68ULL,
		0xA28065A5EE09A458ULL,
		0xC48EFEE1001BF5BBULL,
		0xBB1EE6D88B500A47ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x52005726C69213DDULL,
		0xE3C5836060F6D354ULL,
		0x1B54B79A01D14044ULL,
		0xEF100591B8F42ECCULL,
		0x0361E87B81225281ULL,
		0x42A5AC21355FE45DULL,
		0x84A2AC7181895FF5ULL,
		0xD1E1AEC4A3918FF7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x66E3D77E9156B68EULL,
		0x28DFDC6997E54CD3ULL,
		0xD1523C88D570317BULL,
		0x21797EB0AB720476ULL,
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
		0x4700540331FCE002ULL,
		0x057B2EF01648C11BULL,
		0xC72AA35CA2847EE5ULL,
		0x6091C15E1F242F44ULL,
		0xDBA092CB56416BE1ULL,
		0x0691018FF67B8FD2ULL,
		0x25664D5E98929891ULL,
		0x46B7E648AC4FAD48ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7E1D3E99EA78AC2BULL,
		0x6AAADC6DF346083DULL,
		0xB140EE2600A3C7F5ULL,
		0xEC91DD64326C6698ULL,
		0xEE0F1C2FA2254285ULL,
		0x2047A0F5E3F7D5FAULL,
		0x57A0BE8E9D40ABA0ULL,
		0x620888E5E6C3298EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0C7AB08603B256C1ULL,
		0xC9B4A960E2904EEBULL,
		0xA13CE815F009E2B1ULL,
		0x6607C0A33F935640ULL,
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
		0x4B8562BEECDE6F69ULL,
		0xA668C6BD64DFAB5AULL,
		0x85EE106FBC6C4654ULL,
		0x4ADC7104F5635AD9ULL,
		0x19CE9593E721A7D4ULL,
		0x0E605634B17E68D4ULL,
		0x2B476CC5AEB5CE06ULL,
		0x2F8F70CD3408D1B9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x89191A1EA771943AULL,
		0xC1D42D77C05658A1ULL,
		0xBA4F5D50A1F9B3D5ULL,
		0x5AC9CAB5BA35F0ABULL,
		0xCF002DA14DE7BC53ULL,
		0xED12411B272005E0ULL,
		0xA5BF3E5290602C9FULL,
		0x9A78C0004D546905ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDD0FB6A30405CDF5ULL,
		0xD62BBB102E8C02D5ULL,
		0x9DD598359B2887A7ULL,
		0x1170E4B979F4F4D3ULL,
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
		0x5A8585033D58AD73ULL,
		0x8E1A7AB756AC1236ULL,
		0xCE927AD74280FF79ULL,
		0x7BD5A5FEF6E15753ULL,
		0x5BA9017E11ACFC3EULL,
		0x39508879308BD1EEULL,
		0xB89CDE33BA261E40ULL,
		0xF349F3CCFD4109F6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDF4924A720DD70B6ULL,
		0xA62BB5A4BFFA758AULL,
		0x44F3452F624745F5ULL,
		0x1690A04173DBBD15ULL,
		0xF005902F16A8B705ULL,
		0x1114E78A0A92FD0CULL,
		0xCF3F9675E25D7B83ULL,
		0xADA62FBF867C0F79ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x757F32155F1D84C2ULL,
		0xE0C8A89239A13621ULL,
		0x2D77DBD5E801E197ULL,
		0x3B941FBD2442C8C9ULL,
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
		0x40790B0A749C5C09ULL,
		0x76DDB8B3A8B64A4CULL,
		0x743DE118B4DB41CCULL,
		0x45A98294238AC380ULL,
		0x6BFE270BED008C77ULL,
		0x2D19EFF64BBA0B70ULL,
		0x8ADDCAE27F616664ULL,
		0x2114F97B8E852383ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF5CDCB20A12E356DULL,
		0x936BEF87187E9347ULL,
		0x39D1A0EE2D3825BAULL,
		0x54CB27649B3057C5ULL,
		0x7E390FFFC2C7E9CEULL,
		0x959B24D96BC62B11ULL,
		0x315C3E517BECABD0ULL,
		0xEA9BF7E4AC56A5CDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x95ECABB817D6473EULL,
		0x6043EF75CE6B051BULL,
		0x83A71DB10AF6CDFAULL,
		0x06D497951B4114CCULL,
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
		0x489A2005F788914CULL,
		0x7DD0D3C1593B3772ULL,
		0xFE351FB99B03AD89ULL,
		0xA40F8DCB04DCC9C0ULL,
		0xD56822E25F7D5B3BULL,
		0x3CF43A152CFD2EBAULL,
		0x8A203C9B45931D33ULL,
		0xA940284A85EDB97FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4CB6752B7BC0EA2FULL,
		0xBEDB77147B0EE4BDULL,
		0x271137B538CC0BE6ULL,
		0xC6FB9CCDD19217B4ULL,
		0x4511A6837FE19DE9ULL,
		0x482C0BBAE09AECAAULL,
		0xF5AF2E554E206690ULL,
		0xBB1A39C2FBE96049ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x68BA20EFACE5C0D7ULL,
		0x14AC3E1434C2212AULL,
		0xDFEC06671D3EBDD3ULL,
		0x36B5591BAFEFF000ULL,
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
		0x83B321DCFC4D8C83ULL,
		0x5D41A25EAE785CB8ULL,
		0xC9DAE5B09FD688BEULL,
		0x830BF4C4C1086AD0ULL,
		0x9F62446D99B62E9CULL,
		0x5C4A9B7820E4E650ULL,
		0x1644E11810EA19DBULL,
		0x7D85398472C6CA33ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4CD7263576E6FE67ULL,
		0x93CAB09C31058D89ULL,
		0x5380B36B669F33C6ULL,
		0x31DC9051C8B01B8FULL,
		0xCE674521D6A15972ULL,
		0x5336B8DB98A715A7ULL,
		0x8A6DCF6D85A82B26ULL,
		0xF80300DA37EDC848ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3C1DE0E67A7E2FACULL,
		0x226A94FEB69FC83EULL,
		0x3846D195E500C3D7ULL,
		0x2283CDB7B48E9812ULL,
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
		0xF7A3F597DDA83952ULL,
		0x129E5843A96118B1ULL,
		0x75045C4D1A81F741ULL,
		0x71CEBC1DBE012E3EULL,
		0x059354BA9037F292ULL,
		0xF2441A20F8D383C7ULL,
		0xCCDA8E780D7125A6ULL,
		0x96C8FC7FC326599FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDF778963E293CAD4ULL,
		0xB5BF62EC6DA38344ULL,
		0xB8A534DEA60C8EB7ULL,
		0xAE92DBC8C138E9E2ULL,
		0xC907A47D95E5547EULL,
		0x666882CD2F04D212ULL,
		0x4A5225D8477CB31AULL,
		0x927C650E29ECDA66ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x14E895412357E576ULL,
		0x1F776BC7306BF62EULL,
		0x1C9EAF25D6BE6966ULL,
		0x669A5B31BB5126E5ULL,
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
		0x4ED9C0C2F1236D08ULL,
		0xDFAA67ACE1E0C2E5ULL,
		0xDEA0ACF0F17DBE7FULL,
		0x41B1BDBAABF51F88ULL,
		0x58DB8D9A84F5A87BULL,
		0x2CCBBE3BEB826BF7ULL,
		0x058F32C54088439EULL,
		0xCA561291DB8BBDE5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3C8DA2C6F39C7B20ULL,
		0x79D63C0071A5BB98ULL,
		0xA046A8096405819CULL,
		0x139034D2CF95FEDFULL,
		0x95FA8269D5303F54ULL,
		0xC827BEA341F91149ULL,
		0xDFD5EB1786D9F334ULL,
		0xE133C3CC89B0A39EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFFB3C73614D48D2DULL,
		0x562C1C559A9E7D17ULL,
		0xD7DAA8B11D582C88ULL,
		0x49393A3202E50712ULL,
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
		0x39A9B101BE3CCE3FULL,
		0xFD1D6DB8DA93E9F1ULL,
		0x5C2B92D41384C410ULL,
		0xB9E2248631541865ULL,
		0x0343BA4DE1387CE6ULL,
		0x727CAF1C0AE88E98ULL,
		0x5408587EFFA752C6ULL,
		0x2D9A39F33720C86CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9CF292B65297A9C9ULL,
		0xD1C798F14793955EULL,
		0xF6EA1D70686CBC96ULL,
		0xD5A34D2EE2AB7E15ULL,
		0x4BCABD93D439CC2AULL,
		0xB0BA4C05AF7F8888ULL,
		0xA24ED6F083B79A15ULL,
		0x89B04DBD4FC454F0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD8ACA1E959735E4AULL,
		0xEE308A1924973AE7ULL,
		0xC6CAB08A10AD71B6ULL,
		0x38F7E757A661BEABULL,
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
		0x65B72DC31F342ED3ULL,
		0xC451BD7A2242FAEEULL,
		0xCD9A124756AFD9B1ULL,
		0x8B0CBAC1BE7E835BULL,
		0xB4565D38ED0E34A1ULL,
		0xA863B1D2AEFDADBFULL,
		0xB648E811BDC91C48ULL,
		0x16FA838C813A1585ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE6C9D05EC79AC926ULL,
		0x842E30E0D460DDA9ULL,
		0x274FA04FA2EDCE90ULL,
		0xF7D99CFFDE39551EULL,
		0x972273F78D043F0BULL,
		0xF9352F371E5FB415ULL,
		0xEDEC84A02745B693ULL,
		0x07AE1FAD3886E6C8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD4A1FD189913DA2AULL,
		0x410AEFB0C5552C84ULL,
		0x640134D40B4323F3ULL,
		0x5889F0E6AADE1E43ULL,
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
		0x2FC8724748448444ULL,
		0x2683FD04B89E4692ULL,
		0x0CC8AED47027DA84ULL,
		0x17B689874B3F910AULL,
		0xB00F370D04EAA3E8ULL,
		0x03EDDA5410212A26ULL,
		0xF6425AF8F1CC0132ULL,
		0x542041A60067EC98ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x66C0BDD2A3BACEABULL,
		0x1979A4CEB2180FB2ULL,
		0xFB3E8552D01120F5ULL,
		0xE151E0887BD83B03ULL,
		0x84C0FAC3E2E0D86BULL,
		0xFC2A13BAECBEEE74ULL,
		0x3FB44FCB005554BAULL,
		0x716F2D6D2B2A9EC2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x36A4A74FB1FDE956ULL,
		0x3419D2F1471B1352ULL,
		0x2A9FD25377B4533AULL,
		0x5CADA96E7680E3E5ULL,
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
		0xF2654AED93DFA2B9ULL,
		0xF6164A7AD5EE8A5DULL,
		0xEADF42843A01B244ULL,
		0x4CD1B0C25DE5E4B2ULL,
		0x6DEB8A3A32E6A8E8ULL,
		0xF9D8F8CD9FEF7B33ULL,
		0x7D389D9EE790BEC5ULL,
		0xD81786F1272843A8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5BB7F4CFA1169136ULL,
		0x0E39FB7B5B466B3DULL,
		0xD9991E03CF45D346ULL,
		0x028712C4101748CFULL,
		0x1FA30AF4CA325F6FULL,
		0x13CB395B35477F7FULL,
		0x3B49BFEA8B7148A3ULL,
		0x66003D228015CA56ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x35703A6B7D8BFBFFULL,
		0x0DE6B9FB4F977BE4ULL,
		0xDABB0D461767682DULL,
		0x39BF92AB1A8C9E18ULL,
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
		0x6F9B65E8C5D2E34DULL,
		0x2B7FC6C91DCCD1E0ULL,
		0xC70A8C5CBA50CF7EULL,
		0xBC3F92873BC58994ULL,
		0x118AD59397B2AEFCULL,
		0x0FA0FA7B334E9710ULL,
		0xEFBAD38B209059D6ULL,
		0x4CAE6D5E22745F46ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4A37B8FDFB25AFA1ULL,
		0xA58971247C0D5189ULL,
		0x8ABC7B415B60D332ULL,
		0x10C64F3712B00CF7ULL,
		0x1087DA2D2E06584EULL,
		0xB60B31ED61DF52B2ULL,
		0xE2E681222A9B4947ULL,
		0x071EC06EB0EDC0C6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4BD4FE1E7A42130FULL,
		0xD2321AB1B843A64BULL,
		0x23D24CAFE150716CULL,
		0x7ECCEEDB0311039FULL,
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
		0xB518FDF993C7ED24ULL,
		0x066DB5C873848FAAULL,
		0xE6769BA1922E9F33ULL,
		0x3088A66D0FDD4741ULL,
		0xEBA4B8F801F29610ULL,
		0xC93B5E75ECB6BA70ULL,
		0x44A3D8DAFED45460ULL,
		0xA852CF66EF752444ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD214B7374AC8A07AULL,
		0x501C7216BC896A1BULL,
		0xEEFA311D528D4199ULL,
		0xF59BBA4B6706244BULL,
		0x980BC4CBE55486A0ULL,
		0x5F6C5B60E5884C32ULL,
		0x0A8488D116FEB5F0ULL,
		0x1970F2335E3C7A34ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4BB8854E88759A42ULL,
		0x6B0BB8D0C7DF82CFULL,
		0x98224BFCA956E249ULL,
		0x7073C1C93740615EULL,
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
		0x47DDBAE53C16D45EULL,
		0xAF8F717B9BFE3822ULL,
		0xD5A3AF75B6CCA10CULL,
		0x09AB976B97F75EDEULL,
		0x3FCA91A72567684DULL,
		0x76C6BFDF4813EFE1ULL,
		0xD162E3EA91C24F3DULL,
		0x38D02C0BF1A06002ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x918E6EA5B844FB3BULL,
		0xB2F0EBF5D5B8594DULL,
		0xBE964E1DED60ECC2ULL,
		0x8C029BD3058F7CB6ULL,
		0x60587C288A246324ULL,
		0xC4592189D02B7050ULL,
		0x14CCDB285C05D819ULL,
		0x6C97B554E6326AFFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE13E7D0A8FC49BF6ULL,
		0x78E4063592C8CE55ULL,
		0x1552AE2BC3656396ULL,
		0x4E0A9AC444BA40B6ULL,
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
		0xF1A48B7A41A58B24ULL,
		0x268022F9E328CF57ULL,
		0xA1BCF7952B40B4D8ULL,
		0xE1033467743936D9ULL,
		0x0714751EC743AB2CULL,
		0x3A086AC5ECCC3C79ULL,
		0x6D36BFCA9FCF4EADULL,
		0x54B9106E8E97C531ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE0E804BFAC63CBC8ULL,
		0xE00BF401A8252D38ULL,
		0x931B7C364750533CULL,
		0x4F80E1DE5D9D1038ULL,
		0xA8B8468C665A744DULL,
		0xADA4E83AF575EC33ULL,
		0xFFE5DEF31D97FCB3ULL,
		0xC3649857826D860BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x126B7074F7DFE216ULL,
		0x1D398F98F1D38C6BULL,
		0x48A2DB5C38268CA6ULL,
		0x240C25F4E4E1862FULL,
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
		0x5417A674CE7546C5ULL,
		0x6AC714171F73F5C0ULL,
		0x725BB03F14246B14ULL,
		0x8AA76981B25C45F4ULL,
		0xABA332359FF0F585ULL,
		0xE2EE85F4A06EE51BULL,
		0xCBCB80BA569CF18BULL,
		0x27F659903E284B26ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x200110D6DC4DF897ULL,
		0x91AF4D256005EFDCULL,
		0x5942B132AC892E9CULL,
		0xFF7E97138851643EULL,
		0x077BE45ED31CBC0FULL,
		0xF56D650430DF1D81ULL,
		0x010095386E64755AULL,
		0xDAE75CD10762DF8FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x91EC238059A7D19DULL,
		0x1A42AAA24EC5A6D8ULL,
		0x3337F454DFFDABBBULL,
		0x7B6256D04B58DA3EULL,
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
		0x1F8F4B6BFA484CC2ULL,
		0xD8B9B5439F1FCC82ULL,
		0x75719F8F6767168CULL,
		0x9DDCDEBE96359B2FULL,
		0xA98423027A0E97E8ULL,
		0x51E9269877DDEEF0ULL,
		0x2C88D722D64EAEF3ULL,
		0x02AD0B8108E0DCC6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2B74C151DA52329BULL,
		0xF1EBFF3E44E06B9DULL,
		0x852876BF67833605ULL,
		0x1C1A8D58ACB10E65ULL,
		0x8B579BE0D6FA9279ULL,
		0x8FBCC97336ACE8A2ULL,
		0x1629A0E4FA5BF1C1ULL,
		0xD3E8E172E35EC250ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6EB6991854EEE407ULL,
		0xB963898D0786507DULL,
		0x426B35FEA5EBF5E9ULL,
		0x72E08F7F7AD47A51ULL,
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
		0xA5FE81CFA04D5E73ULL,
		0x186AD892FCA9FEDAULL,
		0x09617D85D87F5180ULL,
		0x1499F8FD75442F9EULL,
		0xE0FBD457F78B8667ULL,
		0x4F8C2AA06708A7D4ULL,
		0xA53F8029677499BCULL,
		0xC18B71FAB593754CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB91211288928C87DULL,
		0x26FABB8DFD147BBFULL,
		0x70726FD8530F6911ULL,
		0x5FF0D997FF89F096ULL,
		0x1D45F0F6FE33F5C2ULL,
		0x23AAD297E6CC6C14ULL,
		0xFF895D4557260FB4ULL,
		0x573B87849FA35B8EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF9EC310C1A2410AEULL,
		0x74E32E48088661B7ULL,
		0x31F83B87F11865A5ULL,
		0x7C85ECECB75E112EULL,
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
		0xE15B1AB88EB70F8FULL,
		0x7FB9B486BFEC92D1ULL,
		0xF60D22615048437BULL,
		0x3979C690D9E0D004ULL,
		0xCE9800C619E04777ULL,
		0x429EB4F586776251ULL,
		0xB66DD4587D65FC44ULL,
		0x85DEEEB21BD8CA72ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x80DFC0A1E042A254ULL,
		0x3176A71758774376ULL,
		0xD02BBACF45E0028AULL,
		0x8DD1B0AF11283978ULL,
		0x02BB159A5783E396ULL,
		0x075FD54B6A492C08ULL,
		0x6B04A7E987FDFC30ULL,
		0x613DC8FDF0C982EFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA3464295882B415FULL,
		0x199840AF96515E4FULL,
		0x577E000A77D843F2ULL,
		0x1B93AEA02CFD3409ULL,
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
		0x8DF7ECF6F1AD50FFULL,
		0x3C0B70793C92BC2EULL,
		0x1A67555ADF5A4E9BULL,
		0x60B8C2D9A01D7F74ULL,
		0xE85A3CAA57579876ULL,
		0x38DB376BD8A7A45DULL,
		0xB28DFD281D805C0BULL,
		0xFCF9BE0D0CD1CBB5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCFABCC058FBBB2BAULL,
		0x4D2A31ACEC92154CULL,
		0x041F62F715F90E0FULL,
		0x1FAD4D967499D367ULL,
		0xD3DEFEB10D8D3830ULL,
		0xD85E33F7078AC519ULL,
		0xC145F2D53CAA8EA0ULL,
		0x5A82D4D54DEF7E9EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC89753F255FBEC39ULL,
		0x416FC2235A49CAFCULL,
		0xE6F97AB1291DBE56ULL,
		0x5EB21389811B1D74ULL,
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
		0xDC2F96A3B699FAB3ULL,
		0x4AA84CE4CFD0899AULL,
		0xAC000607D595A21FULL,
		0xEFD5285FBD1F6F55ULL,
		0x3CF2AF42FB3993A3ULL,
		0xE83C5E986FED8615ULL,
		0x6EA7CF643717A007ULL,
		0x535707CAE6BFCD0EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6AD30050B3EF8F51ULL,
		0x418533AE0A5B6071ULL,
		0x3CBACEB8CF09217DULL,
		0x33919214CAF79DF8ULL,
		0xF141DE639FE07DC3ULL,
		0xC19779ECC79BE363ULL,
		0xA6FADF37E72B20FEULL,
		0x5451660C5D8AA5F2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAD9B977A91E3AAB5ULL,
		0xC59D0AB1C1934F7AULL,
		0x12F0DDE2E3A75BFDULL,
		0x17199893500B9F7DULL,
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
		0x34586E5F077D2B3EULL,
		0x181D6AF883FE9C50ULL,
		0x4492BBC1D7110C1EULL,
		0x7B55F04ADBC1161BULL,
		0x99F21A7F2C4ADE36ULL,
		0x2DE7A0464DD83F76ULL,
		0x9116D8B520C017FFULL,
		0x15D8053F0DB18589ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB7DB165BFE0D538EULL,
		0x1A7FB9FB6A695911ULL,
		0x7E8DF0EAC491D66AULL,
		0xA13A89B485158C70ULL,
		0x8AB74CBD78C4F072ULL,
		0xDD5A5E1A2D9FF248ULL,
		0x717F45A0536E6C5AULL,
		0x55547CD90353F698ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBF37E2C3AF51214CULL,
		0xF2958389E1F0B814ULL,
		0x76849FED8C9EB017ULL,
		0x6DA1A5BBE08EC175ULL,
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
		0x4E697EEF066F2F78ULL,
		0xCBDE6DD598E9CB13ULL,
		0x137C7B4E3C369AF8ULL,
		0x24372326ECF86C7AULL,
		0xE60F30107BCCD36BULL,
		0xDC7ED733F387BAD6ULL,
		0x03446BF494D3F023ULL,
		0xB103B7BB92C6FA96ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7D38867CDBC16020ULL,
		0xBD76553D0C093875ULL,
		0xBC3CA16912168149ULL,
		0xE18377E56FA7458AULL,
		0x4F99530796C2E50EULL,
		0x3A0235A3A39B07F7ULL,
		0xE20AE436033DCE86ULL,
		0x7846CA3408168A9EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x26AFC7C42A273243ULL,
		0x2CE814046A031FCEULL,
		0x45CA002EC6691715ULL,
		0x2EBEED601381C59EULL,
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
		0x15856EC0BA8A8959ULL,
		0x719CECD468F721CDULL,
		0xBFF574190B19ED36ULL,
		0xCAA3D8B5F6A5C1F4ULL,
		0xDD6617F461B8109EULL,
		0x6402EEE7377361C4ULL,
		0x1F5F5749F796F099ULL,
		0xC374167568ED625BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4B1A6B620DDD13EFULL,
		0xDEDCC194E9F37F18ULL,
		0x27027AACB350FD3BULL,
		0x4969F0CEE09F10E0ULL,
		0x857E9E2B88B3DC0AULL,
		0xB12DDD3C6EDDCF5CULL,
		0x9C0F89CB22F216C4ULL,
		0x77EDD6C3E657593BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD6C7172EE34D4517ULL,
		0x1E60CA9945375E31ULL,
		0x16CB7A3FE841458DULL,
		0x37275C40784C0BC2ULL,
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
		0x7D5B807CF15596F2ULL,
		0xD390EFF43B7B5DA8ULL,
		0x1D044FE9F17E87EAULL,
		0xB141C92252EF8DA0ULL,
		0xF971219DF0FED4BEULL,
		0xC5C34B9A897A5947ULL,
		0xB135E90BE91D881CULL,
		0x3539537A23739A72ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5E941BF00209701BULL,
		0x64785399C6676773ULL,
		0x6DFE679377894308ULL,
		0xDBC1A5ADB46303D5ULL,
		0xA026654421C17192ULL,
		0x39FF6BCCD1613062ULL,
		0xCF1FD202CBC3CA70ULL,
		0x30D3F37110DDE3ECULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5FDF59E1B268DF5FULL,
		0x2E2BD4E3C8D00840ULL,
		0x3E4D53B0D5476C7FULL,
		0x7C8C64CD60C5A1AAULL,
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
		0x134668E8617A5D6FULL,
		0x729C2E1FD5899560ULL,
		0x3D7BB7A299F14160ULL,
		0xF5FBB354BD49E50CULL,
		0x9CAB2C36142BDCF6ULL,
		0xC3C8E4968BA50705ULL,
		0x54AC1BA966AFB524ULL,
		0xFB6C2566000B1591ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF73F894507AB99DAULL,
		0x734B9ACF32DAFAD0ULL,
		0xBA909C35F93E123CULL,
		0xFFF9B92F66F9119FULL,
		0x6ABBBF9E204AF748ULL,
		0x2C756CFCE20C119CULL,
		0xE077AAC4851A1168ULL,
		0x514ABBBE4162008FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8590FE318D30DF1FULL,
		0x75B4541FCF63082CULL,
		0xC2B3DD661CE97D22ULL,
		0x36F7A90BA369F1A3ULL,
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
		0x391F3F22FFDED824ULL,
		0xEC3F4BDC0C43FFD8ULL,
		0x94B1E972F1E762B7ULL,
		0x0D5BAE5E7F867501ULL,
		0x36B4B785E8675F91ULL,
		0xC47B757C537920FCULL,
		0x5AB46DE925650C5DULL,
		0x1305963BE7C09D6DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x183F5464082374F6ULL,
		0x4B6DFFB74E02260CULL,
		0xDDABCA53A6FCB476ULL,
		0x1ADAD2DAE3BBF7BEULL,
		0x208788F1C93989B0ULL,
		0x0D95E76175449B64ULL,
		0x00841A41795A7AE7ULL,
		0x8AD5F1C0D43E2CE5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6B94D4BB98891FE8ULL,
		0xC6E46421BA0DAE5FULL,
		0x1A328A02D47C45E0ULL,
		0x299345C881273180ULL,
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
		0x416D462AA0ECD0FAULL,
		0x76314DD68064C165ULL,
		0xBD783BAFE4A2B865ULL,
		0xBE25D8288D3505E9ULL,
		0x1F55E3AC82C8F70CULL,
		0xA974664C94D7FB03ULL,
		0x2D07D56F15A837ACULL,
		0xA95D03D3B545FF27ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8AFC67E87E12ADD7ULL,
		0xF3D1A89A6F1CD76FULL,
		0xA968FA961A19B1FBULL,
		0xC57C5C917EFEA5B8ULL,
		0x303EB5032E10DB44ULL,
		0x02DF5AD877EDEB27ULL,
		0xB6EEB51B22AA1DD1ULL,
		0xC164650DE691EAFDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x33E1CB64B62E423BULL,
		0x3C7F58785C06449BULL,
		0x9BCA0D8FDC40DD04ULL,
		0x67910CF3BCF15E58ULL,
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
		0x2AA4C0215F02B9F6ULL,
		0x5E6BE6AEACAE0806ULL,
		0x9E51DB3A74FF1AF1ULL,
		0xE04ECA2598C9FA09ULL,
		0xFD36A6E7A25951E5ULL,
		0x0D825965698B20C0ULL,
		0x68968F584C4A243CULL,
		0x1DD766D09C6C47CEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE5DE53C1BBCDA399ULL,
		0x42879EAAF4873B73ULL,
		0xF477EE346E7BDA09ULL,
		0x4638932924D93DAEULL,
		0x7DD9F99DFDD6C972ULL,
		0x0EAF5641B3976988ULL,
		0x313E0360EC91EBC9ULL,
		0xEE8DD40908B4BDFFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2C88254E0E9552E8ULL,
		0xEF36BF50BA53FEF5ULL,
		0xE0FEB3BE3BDBA1F9ULL,
		0x1F02009C612F311CULL,
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
		0x305AA6C0EEE8FDBDULL,
		0xB44B95C951F488B9ULL,
		0xB9B759B732E6AC0BULL,
		0x65853D74DDE6647CULL,
		0x1ED49BD56A425438ULL,
		0xD1008F06059C1114ULL,
		0x67B2D5DFEE841BA1ULL,
		0x394ADCAB6793F99AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x02D2C88003FC18A9ULL,
		0x15DABCC4E8FDC7FBULL,
		0xEE347C96FE06E323ULL,
		0xD8D9D5923F43D9CBULL,
		0x036D1595CCFEF0B0ULL,
		0x3DAD314CB0A4D978ULL,
		0xD3CAF31BD38ED423ULL,
		0xB140C260BF0324D0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3EE5CBB242EDA885ULL,
		0x7CD0C28705A901EAULL,
		0xBFEE863C354865B2ULL,
		0x3E2B4EF7A422209CULL,
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
		0xEA812084D421102DULL,
		0x38E2890180DAC060ULL,
		0x291EA752FC52F9C7ULL,
		0x776D495343D9857EULL,
		0x5A408F132C34462EULL,
		0x9ED872F06DEC27F2ULL,
		0x611FB5B6877140A4ULL,
		0x52DB9C96F3E52486ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4FC0D1508AD619E5ULL,
		0xA3B53000963CE0ACULL,
		0x0B20FD5E16484779ULL,
		0x21B00D42BD5167B3ULL,
		0xD5F2009A83536700ULL,
		0x0C007C1659701988ULL,
		0xBD0C51CC2708FBC4ULL,
		0xB340A21C43F5E3F0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3E69751D5AAC1508ULL,
		0x613BFD5FF508035EULL,
		0x78DE7EBF3584EBA3ULL,
		0x06BE6A46A40BB401ULL,
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
		0x5F3BF0A5432DA272ULL,
		0xE7AD893942EDB369ULL,
		0xB8754D86136ECE86ULL,
		0x0C8CC0B1FF2880D9ULL,
		0x3CBB22177C6B6CFDULL,
		0x8D0B3273A09F7AA2ULL,
		0xC21BA0A1A5C42EBDULL,
		0x1E610469A6D47BCBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0A5E7C156EECBB62ULL,
		0x76805CE5617BA883ULL,
		0x12E4DD884B9D97E5ULL,
		0x1446DC84BA4F00F3ULL,
		0x161ACBEC2187C48CULL,
		0x289C136FE59A30E6ULL,
		0x87FDEE492BB9DFDAULL,
		0x6BB78B09F7BDA32CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x10AA3EFF520BE60EULL,
		0x59ABC6E1A43AFCD4ULL,
		0x45F8E91FE558EC62ULL,
		0x7D6DE861423DA789ULL,
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
		0x070AFD8CE9DE23A2ULL,
		0x7C68BC367B4E2397ULL,
		0x19F8D83961D979DEULL,
		0x8D5446F3537759FAULL,
		0x3D91AB92F2E66561ULL,
		0xCBA582F2C93396FBULL,
		0x315A86EEEF50BCB9ULL,
		0xC14285B2CA19A515ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x46531E298B24BD42ULL,
		0xDF82E44FEF0DA932ULL,
		0xAF74DDA39D597B92ULL,
		0x3A8F0213A9B9D3FAULL,
		0x5DF46DA740550DA7ULL,
		0xB6B74358ECE42016ULL,
		0xB819E4E530C6AE58ULL,
		0xC7D7F687AD40706EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF20F105FE04C6BD6ULL,
		0xB84348BD400C205DULL,
		0x6A1C08080CFE20B4ULL,
		0x58968545F1FB56B5ULL,
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
		0xB2FC22B9A253AEAEULL,
		0x7C22F7966112A44CULL,
		0x12ACC680B06794E9ULL,
		0xD2C403E98567CC6AULL,
		0x4E47CFDC515F32DFULL,
		0x8FCC30BE5285E16FULL,
		0xE0338C1E452B35E6ULL,
		0xAA8C9341F68E92B9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3941944331859D25ULL,
		0x43A13912A653DA82ULL,
		0x3BE62E17A1AF697DULL,
		0xF15584ABFC3F7DB0ULL,
		0xD5027C7CDA55E501ULL,
		0x670143116F081904ULL,
		0x8715A4F3CFD5E0A6ULL,
		0xFDE79FA08DC915D6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7A04EEA21C2F9EA2ULL,
		0x46A1062D7F6A8998ULL,
		0x1136E8B67962D2F2ULL,
		0x01EAA9331678D879ULL,
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
		0xDFA714927DD31A16ULL,
		0x586CF7AEA9323FF8ULL,
		0x3868CC400546C758ULL,
		0x2771EABC4A843664ULL,
		0xE1617A82644E1333ULL,
		0xACCC74E6690C2DC2ULL,
		0x9CFD0E4176489CA7ULL,
		0xE81133273F0AE35DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCDD6C8441A2FA814ULL,
		0x6F0FBBDE60524A0AULL,
		0x28E75FA97F5B8495ULL,
		0x9ECDC5B23B8FA250ULL,
		0x08739E9BDA89AA09ULL,
		0xD9679D8F3F6F983BULL,
		0x534F3C10FAE49BD8ULL,
		0xC41077F4DDA57C70ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x451EF086D6CB0EE9ULL,
		0x4A5532C0761E2818ULL,
		0xFF4E9FC8D6C36176ULL,
		0x60BFEE848401DB4CULL,
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
		0xB28651567F993EADULL,
		0x80A4B40904FF6405ULL,
		0xD14169A18E7A376EULL,
		0xC663423258D0572FULL,
		0xA5531034636C76B5ULL,
		0x81197E94AB209458ULL,
		0xD942835012928BB2ULL,
		0x0DE5CC36676BEEEBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2540ED67A0FB3B07ULL,
		0x0876A8D4222D0491ULL,
		0xE3C7C9722BB560BBULL,
		0x7A86E343397BACF1ULL,
		0x765EB14C8AEF8DE3ULL,
		0xA853C9A32CBC2879ULL,
		0x5737D71640304DAEULL,
		0xD461C632142C48BDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x858B7A5901288E71ULL,
		0xA586E70DA5BA6295ULL,
		0x3B0F30C49D5A0B45ULL,
		0x557543937AC75525ULL,
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
		0xF3F7B73DAB10F464ULL,
		0x501DC9FB425E9AD6ULL,
		0x5823BD615AF3CAD0ULL,
		0x81CD57AB483E2F32ULL,
		0x46078509B83C3D46ULL,
		0xC417388F6B546E8EULL,
		0xA8E046C8B4A13A7FULL,
		0xC32566B08DFC92FDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8D5C8A9845447073ULL,
		0x2DA13078DB6A7E2EULL,
		0xAAA90A8032552E0FULL,
		0x86D7B4DC435FD601ULL,
		0x393F5796607C4439ULL,
		0x2074B3E21F458814ULL,
		0xC460B514CB8E7FD7ULL,
		0x4875AA06025B2F34ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4C51EBC46C4B7E8BULL,
		0x6C9C4B3BB12A52C6ULL,
		0x986A5395C16651C9ULL,
		0x310BA41FBED32902ULL,
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
		0xB772ED7891577043ULL,
		0x1B40E99CBEC1B459ULL,
		0xFEBEB00AA0117AC2ULL,
		0xE127DF74A3E7257CULL,
		0x39592D84E07AF251ULL,
		0x88305F51FA1F3A71ULL,
		0x89716C2F2DF52A6DULL,
		0xB47F07BFB8ADA2C8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD3793AB450431116ULL,
		0x4DF27BD873B2CC31ULL,
		0x056E7F0F4AB4277CULL,
		0xFFF13C509FD53FB6ULL,
		0x42C388B18A649CBFULL,
		0x13C4D7EBC11373C3ULL,
		0x3908939D3E9E9660ULL,
		0x4882BC04B07465A9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7E302A2308651526ULL,
		0x154486F0C2CE65FAULL,
		0xE8E056A4DC374D45ULL,
		0x68A9E0E73C90F86CULL,
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
		0x030E21BBE4AE926FULL,
		0x0BA1C5281E198C6FULL,
		0x59A032EA5632F18CULL,
		0x6A5A3670329EF411ULL,
		0xC57831809DAD836AULL,
		0x86C6ED715DA61BB5ULL,
		0x9EFCBF14DE8CD947ULL,
		0xD53DA1C906460130ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x577D5EA4B13A1B6CULL,
		0x5B552EA370A2DCA4ULL,
		0x32A6BE448602736AULL,
		0x82FC2BAC7114F8F2ULL,
		0xDDB1CD36E574CE32ULL,
		0x570D8C5BC423D43AULL,
		0xB6E8C03AEF0C5DACULL,
		0xC2C9782C249CBC36ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1303A6088BDF5DB2ULL,
		0xC5D0FFB976CD4C09ULL,
		0x99F148FF5D42D72AULL,
		0x249C380D40AA3837ULL,
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
		0x3DE14BC67C6CA3D3ULL,
		0x66AB2CCEE344548FULL,
		0xDE28DDAE5C3EF3F0ULL,
		0x014988932CB9307CULL,
		0x9B6E1541FAE4945DULL,
		0xA5FC85AB8CCB3C64ULL,
		0x5F775CD88C3247B8ULL,
		0xBCA6F3C780DE191FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBD92FC40194AE177ULL,
		0x4F8A1B5482D27EB8ULL,
		0x20563E6D790866BCULL,
		0x44FEE20D0C1831FCULL,
		0x8B83B94A5A777815ULL,
		0xAF0C901043E42BC2ULL,
		0x5023FD37603699F1ULL,
		0x05E91A462FC98948ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDD17F6483353F8FBULL,
		0xBEBF868732BE4DE4ULL,
		0x0432D12D6A9258BCULL,
		0x5C78EFB829AE586DULL,
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
		0x82030644FA5C954FULL,
		0xD4BA378B177C028AULL,
		0xCE4DFC3036FBD3BAULL,
		0x87464DB57AFC0559ULL,
		0x663B1CBF22681768ULL,
		0x7DD22D2FED2A3DDFULL,
		0x584B4BDD7A356C8DULL,
		0x86B7883176672611ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBCB2D7A19917D3B3ULL,
		0xEE7B42B71F6AC0CEULL,
		0xF24C9279B2142FEDULL,
		0xEFAC8C26E15CE322ULL,
		0x01D954C9D65AFEF0ULL,
		0xA45EA4A424CEDCDBULL,
		0x73D9C402DF0F3C87ULL,
		0x6BD85EE372F57608ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xABD3DD0CAB3663F1ULL,
		0x2D653993B5A1A862ULL,
		0xC4DB94298C92C4ABULL,
		0x14B9E3231C7F4388ULL,
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
		0xB51A2FAE365B5C36ULL,
		0x2EE2ACFD867307F7ULL,
		0xC7879F8F93CB806DULL,
		0x07D9555705B219EDULL,
		0x23A0B97A5D32B357ULL,
		0x554323702B478C17ULL,
		0xD1833C8EA4299AEFULL,
		0xB59D23E385D2FE2EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x21C3AF72E6590E5BULL,
		0xBBB197C96B2C74F9ULL,
		0x84A0DCDDFE56BF2CULL,
		0xCD2C7F8DF2CE217BULL,
		0xFD26A868D59175B4ULL,
		0x740D0EE346D45FEBULL,
		0x88702666DD45224DULL,
		0xCB2808C3C5BFDECDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x497508D571F17375ULL,
		0xE138221E045F2166ULL,
		0x1BBC0C991B5EA947ULL,
		0x080EDC7F95BAA0E3ULL,
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
		0x7EFEB4DDB22AD119ULL,
		0xB094EBC11A39654EULL,
		0xABE6D8325A64E094ULL,
		0x14D65C1AAF418C3BULL,
		0xA48B9BF17EB5FA6CULL,
		0x3DD8B67CB2B02A57ULL,
		0x827A0BCAD1D14E4EULL,
		0xBC13AF2F7C9302A4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0B39C14E032D9D12ULL,
		0x8279B85F7877A5CBULL,
		0x8850E560F80EDB8FULL,
		0x445F4339B7885765ULL,
		0xEC542BB67942238CULL,
		0x360C4C2CAC5EF4C6ULL,
		0x5AD891D0AB140BD1ULL,
		0x40E2E1D6C7D1E917ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCBFF9C527E2F1BF3ULL,
		0x5672FB4291CFB2FEULL,
		0x058E0DF3226DE394ULL,
		0x19B5940BCC62FFCAULL,
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
		0x70D37F79D919A14FULL,
		0x75762783B06F8CE0ULL,
		0xDE6DED3011E7EF0FULL,
		0x79CEE1C5ACA4229FULL,
		0x9F973D24AE33825FULL,
		0x37C30D85D6A91240ULL,
		0x8696CC291B9A750AULL,
		0x0240CB541CDFA721ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x860BB172A4A7C2CCULL,
		0x117475E5E54C93EBULL,
		0x3B743B2DC4FC94A4ULL,
		0xD4B863B42BE24A98ULL,
		0x13FB4EAD7D33E0C6ULL,
		0xAC114F868A43E745ULL,
		0xCF255CDB58D4FCCFULL,
		0x05BEF057D560F9F4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA3ED33B87A63DB13ULL,
		0x2063E58322275A4BULL,
		0xDDD0378D363B331CULL,
		0x205CFF841D8F8CAAULL,
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
		0xB9809237213DBF29ULL,
		0xE0F9FBDDE93AA6D6ULL,
		0x245B14D9A8B138B7ULL,
		0x7F045C3F0F955047ULL,
		0xE0846E705326CC8AULL,
		0x248ECA653CB3C341ULL,
		0xB8B258BEF947BC21ULL,
		0x3BCC613B8D6505AFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDC096B60F3CBBD94ULL,
		0x8931048DAF9AE153ULL,
		0xA169082833C436ACULL,
		0x6C26BF2663EDBFCAULL,
		0xD6A11354D52B5ED9ULL,
		0x5C6FABF3AABB8F79ULL,
		0xF7FAB070BAE79179ULL,
		0x8272AC0A0B559151ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5536ACEAE0C4484CULL,
		0x0C677C2BE4777534ULL,
		0x1E35084EB73356F3ULL,
		0x162E8271F9F2D667ULL,
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
		0x557FEB1160D0AA67ULL,
		0x9EEFA6066092504EULL,
		0x02E8F24AC2424CE0ULL,
		0x64E9D617C6C6F410ULL,
		0x2AC7834882519A8EULL,
		0x90E991AC75CF0F6CULL,
		0x8F6DE7E5C350386FULL,
		0xAE28370EB0671B66ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAC7A30921B7DAACFULL,
		0xE8B546A124D6311AULL,
		0x09CBCF8EFDCD52EEULL,
		0x8A99A2886752B726ULL,
		0xBC7F8C701A413420ULL,
		0x3850EFB0168E6148ULL,
		0x865146E1786F5DAAULL,
		0x966F10423E4CB6BFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x07B45E9EB7C2345EULL,
		0xDCE26ADB5F55F876ULL,
		0x535D095EE1D5733CULL,
		0x5FCBF5E84F5F2DB5ULL,
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
		0x82BB3B309EA88E96ULL,
		0x0610A3E8064CE6BBULL,
		0xD1B03ED32B92DC86ULL,
		0x88F566BDDEE8A4A1ULL,
		0x072654C1AF60E0DDULL,
		0x626A592F1EBA7C6DULL,
		0x5D2E7C686DB1E88FULL,
		0x88562A81CFB30BC2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9E4EE64CF2C5E0CCULL,
		0xBC3D2C855AE276FBULL,
		0x21EE396C95953530ULL,
		0x8D295DEB7D80A446ULL,
		0xC48CE1422FD8F3F2ULL,
		0x3A459DB368DD3E04ULL,
		0x28A410E0F66495EDULL,
		0xA1541109EB06A199ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC73379D09A0FD814ULL,
		0x3F474BBFAA41B339ULL,
		0x7C4DFB824B77EB67ULL,
		0x461BD09E52FFC279ULL,
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
		0x194DCABDFC188152ULL,
		0xE8F2E2535BFF0B3DULL,
		0x0E6FAD444FB66C4FULL,
		0x116C57767BF88E75ULL,
		0x9307F149016E0737ULL,
		0x6476A5DBB77D0005ULL,
		0xDDD97946C1418478ULL,
		0xE2C4C563CAE2AA00ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF636AB9AC8132A8FULL,
		0x0D9104F5BFA0E6A7ULL,
		0x6DF7CBFD954EDF40ULL,
		0xB8E138602D36D3B6ULL,
		0x4E6B7D3E7D0D95FCULL,
		0xB5296172FAEE8534ULL,
		0x455234DF21B8BE66ULL,
		0xBB83BB912B9BAB8EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x525058B2DA562643ULL,
		0xE0DA04E999845FA5ULL,
		0x448C08A868B4F3AFULL,
		0x2C329459F34B7FC1ULL,
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
		0x477AECC2E14E2D35ULL,
		0x4F24322B8F618008ULL,
		0x5B2B8EED2F8988DEULL,
		0x22C1F6EC5DB7F8BBULL,
		0xDC6F212592A4B43BULL,
		0xA2637DB554F146A1ULL,
		0x9B4B8B7DDAE4E97CULL,
		0x513CE5694F4FBAA6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1DA4721876E6A0F5ULL,
		0xB2F667A9697EDC76ULL,
		0x265E2F67E36385FEULL,
		0xE74A63767CF9C418ULL,
		0x07CBFD8A97E88E3FULL,
		0x6FD34B24FC58AABAULL,
		0xA0E08BD91F11DA3CULL,
		0x82F42C0A0FA3B07DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBA0DC3ABA2552E65ULL,
		0x1D954BEF4C89C7FBULL,
		0x60AF51F92D7A4667ULL,
		0x5A4317995447B6B8ULL,
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
		0x7B55ABDC0CAE6E4BULL,
		0x09EBB938D684EAB8ULL,
		0xC47C9D128537182BULL,
		0xB05D2F5460F1470AULL,
		0xB8A85260A88ED686ULL,
		0xAE655B710053EFE8ULL,
		0x34281F308A617EB6ULL,
		0x2B4F5E72E846F803ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x869C8CC548A66826ULL,
		0xDD4F086AD1DE9B80ULL,
		0x7C830E32F709CD88ULL,
		0x5856BDC8E9EF28FEULL,
		0x0C5C67940632CAF9ULL,
		0x65791D7759FDEA3BULL,
		0x7064A77E14C24A62ULL,
		0x9AF94E024AC39F0FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x87FDF976DDB1BAA0ULL,
		0xFFADE3DCB56B26FFULL,
		0x56FD535D03CF0F24ULL,
		0x44CCE242D881523BULL,
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
		0x03300737AF30E5FAULL,
		0xB5D25681B6849C30ULL,
		0x35BC10279C0C5E05ULL,
		0x6AEB272642EF6172ULL,
		0x51B4BA78506DADC3ULL,
		0xA1C6F921FC0E6FF7ULL,
		0x9D7A987232F5FDB2ULL,
		0xE2089E7258E7B563ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDCF53242E67C8A2FULL,
		0x9E2849481855F471ULL,
		0xB1A6BD981AD2B600ULL,
		0x36AF9D4A88E18380ULL,
		0x7E14F7E74BB7DDC1ULL,
		0x47E09C948C364406ULL,
		0x6DE33F5B0A907C6DULL,
		0x11397FD1F59A5115ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8FF1B67B7BB140B1ULL,
		0x6FDBCA3838452D7DULL,
		0x948C8BFF804AD850ULL,
		0x32FA15AA778AC18CULL,
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
		0x58C7C2FAAC778E87ULL,
		0x239B3D81FC604A8BULL,
		0x20971B8DE84353D6ULL,
		0x89761AB9DA4DDCFAULL,
		0x8AE215DA4D33A47FULL,
		0xB6C75268F8D7F426ULL,
		0xE5B0FFE9ABAA23A9ULL,
		0xE70FE2191253A369ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC04959465153D828ULL,
		0xBE0F7631024EA284ULL,
		0x5A7DC6302309DF0AULL,
		0x898E959BB4FA50ACULL,
		0xDBB94E4411631E98ULL,
		0x19BA570B3F1F826CULL,
		0xBDF305A2B205B668ULL,
		0x32A069241816989CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x988C0A013C179A98ULL,
		0xB579173A8B728996ULL,
		0xAC4C7BE6D3A1AC88ULL,
		0x4873797B4A6326C1ULL,
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
		0xE1D77EC9F47C7A0FULL,
		0x8DC0DB080C6AAF9BULL,
		0x9F41F6703A2F4333ULL,
		0xFE8174C0551E3EA2ULL,
		0xBF785B6187E30FACULL,
		0x4882C14E859A9138ULL,
		0x8130524C81068140ULL,
		0xBD023D2FA469F6FCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x30DBB0040058C2ABULL,
		0x3F4F96F29AF66BF6ULL,
		0xF0144B3A8FDBA4E6ULL,
		0x9FDAF92F0F4CE5BAULL,
		0x16C6F56D9FD4E026ULL,
		0x1BFA5A51B56ED593ULL,
		0x3AB0AC03C0824DC6ULL,
		0xCB8CE8F0DB4CF306ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBB50F0FA663EC4FCULL,
		0xEAB08D9C57F21E3CULL,
		0x26205A023DF3426FULL,
		0x3610FCE3201FEF76ULL,
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
		0x7B0FCEAD751046B1ULL,
		0xFBA272DF07C9DC56ULL,
		0x3EA6441E59B12405ULL,
		0x77BD4747437A8604ULL,
		0x098274D13131BA24ULL,
		0x25E65F15CCD41BD4ULL,
		0x526FDD0AE1C9E261ULL,
		0xD707C95A248A59F2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD700BF7DA8B6793AULL,
		0xB0C6B308E1E2D83FULL,
		0xAE8948C335996C5DULL,
		0x7738008BF72A42B9ULL,
		0xF02EDCAD4A3AB674ULL,
		0x62C9CD6CA5702D57ULL,
		0xC110B2B17DBD0631ULL,
		0x5C2BB8B82D177436ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6677A48415045C43ULL,
		0x41195EF1FEBC6A82ULL,
		0x243D449FFE0066BFULL,
		0x3D2FBEC6075E5D22ULL,
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
		0x20656A875E76C9C5ULL,
		0x44D0C748E4F12067ULL,
		0x62690A887C9A1D00ULL,
		0x8E2F4FF56CBC1200ULL,
		0xCFD7108ECD9D523BULL,
		0x0F2C2E57A1970E6AULL,
		0xAEA1C7BEB84A7F3BULL,
		0xE342B9D434CD7BC4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1CDEB4DB18FAFE7CULL,
		0x07922F1763BEA72DULL,
		0xF484B02325A86DC5ULL,
		0x25ABDDCE5348C216ULL,
		0x25B0AADFCEDC2787ULL,
		0xAD3C76B237038071ULL,
		0x61FF3428E6F598D0ULL,
		0xC45162C0242F061DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4539CDA6162822BFULL,
		0xC6D3DABF53198C49ULL,
		0xCE0642A2698BE305ULL,
		0x00565F2190F8C6BEULL,
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
		0x8154D6F95B9F6CB7ULL,
		0x585C76937A3ACEDBULL,
		0x248AA72CF3D6ACA1ULL,
		0x9F58274696AD0238ULL,
		0xAEAC8056E5C2E3FAULL,
		0x53D6C236B0AABB24ULL,
		0x7C8807E4BD20CCDBULL,
		0x8A6EBA0E5BBC279EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCE4D3ACF74B5D02BULL,
		0x13244EB3143567D5ULL,
		0xA4F69CCA970FFD46ULL,
		0x29FA1BF5403C94F7ULL,
		0x4D17C68E295A13ABULL,
		0x5F72973B74B3A3CDULL,
		0x97F688107C0A3C4BULL,
		0xE8744ABDEED22951ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2F1B2FF5DE788645ULL,
		0x8C16892B4CB2DDFEULL,
		0x6D2D03E4062024B9ULL,
		0x008A9141812C2CAAULL,
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
		0x072E7E6D4505B787ULL,
		0x9BF0FE5107B5019BULL,
		0xAAE6234BA349054EULL,
		0xF35A2223B630243AULL,
		0xC358F9428DC2A298ULL,
		0x45495324072802B6ULL,
		0x161BC062752EF74EULL,
		0xFD88198E6DB64601ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1F2C506DFD18642EULL,
		0x28503DB1C6D443B2ULL,
		0xA486415473D76A4CULL,
		0x33407D34ABEE5E55ULL,
		0x318A7455045BF56DULL,
		0x9553EFE06C41FB23ULL,
		0x677EEE633B3524FEULL,
		0x36BD54B74D6B7F6AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8CA9E941AD2B0C2FULL,
		0x920D7CA83F05DDD0ULL,
		0xF1A70DD9CA86D2D6ULL,
		0x4232DCDDD55B4042ULL,
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
		0xFE87CF30419234B6ULL,
		0xFF4EBF4D1D3CA7E8ULL,
		0x99A3FE5183180D17ULL,
		0x45553EC0AD1BB865ULL,
		0x0297916FFDF01B3DULL,
		0x097673EF3DEACAA2ULL,
		0xAE84E7C689E0420BULL,
		0x989606C1F0B36627ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x557EFEF8BA71DD0CULL,
		0x15DDC4C77547FD08ULL,
		0xC9DD91C8D6CAD745ULL,
		0x25A39ED550698062ULL,
		0x7D858DB75A6FB285ULL,
		0xE4F2B86217D1163CULL,
		0x3622B7DAB628817DULL,
		0x3CC522E986B0924AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x69B55D9FCC2FE4FBULL,
		0x54FED1794FC571F2ULL,
		0xAE59898A1993CAC6ULL,
		0x40B3720B191DAAE2ULL,
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
		0x76D5E5C953843CF6ULL,
		0x1C0166266ED4E191ULL,
		0x8DBF2967951DB1BAULL,
		0xFE9054156C249A6EULL,
		0x80A8745AA0A60765ULL,
		0x106B6C9715EE9553ULL,
		0xFB3A1F5C5003E0EBULL,
		0xAE1999E83D5B2409ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE0AEBC79AA2D63D1ULL,
		0xBD998CA5F2D324DCULL,
		0xCDC38D0708F9C231ULL,
		0xE2FF564CF5A9B0F8ULL,
		0x4D50B4ED393EA3ADULL,
		0x2540D98325F808A5ULL,
		0xC4F2E803AA1643A4ULL,
		0x560195BB8E22251AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x352D938D02AFA863ULL,
		0x46B9AE761A9A9E90ULL,
		0xCE8DD3892D69480FULL,
		0x2F219C6A78F0C0F7ULL,
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
		0x5FE4A76693832EACULL,
		0x089F44C8869A6DF1ULL,
		0xE585655419E792B0ULL,
		0x342102BDB8DC361FULL,
		0x712D93BAAE525F61ULL,
		0x31F2CA9FA1D6BF75ULL,
		0x152A58C9EF8ED603ULL,
		0xE3A16D4CFA792D6EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x56C2BCBC2A170FAEULL,
		0x5A963A1AC7F62B80ULL,
		0x3364E0A867A70ACAULL,
		0x490633613A77B88EULL,
		0xAD74CB3E9F026B6EULL,
		0x3DDE71A470EFEF0FULL,
		0x5B70C699C6183E7DULL,
		0xD15B1B82A736C4ACULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x168FAD14AF4A556FULL,
		0xE90E3FF700E7318CULL,
		0x43AC37D1D9DB05C7ULL,
		0x218AF364DA400A53ULL,
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
		0x4ED325A290E52ED9ULL,
		0x861223C568A4C1A7ULL,
		0x65D70162B9E444ABULL,
		0xDF6F39817C7D598EULL,
		0x2F9D8FC991A01D09ULL,
		0x0AA2B52B075C5166ULL,
		0xE991AA9F97F6577FULL,
		0x8C4439D2D4076427ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF06BC73F2BC52F5DULL,
		0x56094453F4C7E348ULL,
		0x8E0E1A8D09B7932EULL,
		0xEE6BF9251B8DEE83ULL,
		0xEB58B746FD9AB507ULL,
		0xAE270FC1BB8E75FFULL,
		0xCB670DFF82147DD4ULL,
		0x152703F82E3C7813ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x809F81C55DED7261ULL,
		0xEA636D12B46B6F8CULL,
		0x521C2698EFB300C6ULL,
		0x1F593ED0FD0E7607ULL,
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
		0xF848AFB1578ED15EULL,
		0x9B4E61DE2CC81152ULL,
		0x8AB3905AFBBDAA82ULL,
		0xA2E16BBF6C2DDA94ULL,
		0xC4810AA0C3D5D47EULL,
		0x6DAD60F0358E45A4ULL,
		0xAF8292BEAC34C382ULL,
		0xB01E926EE2A22870ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x256E6B05A534C86AULL,
		0xFBE99CFE2E96451AULL,
		0xEDC1DACEE5623658ULL,
		0x7FE2D9F7D6AD8B46ULL,
		0x5774DCA470055CAAULL,
		0xEC629EB50725C968ULL,
		0x7AF87DCF9502C659ULL,
		0x26FAE7368E5A43F7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x02A91820234BD564ULL,
		0xD07D99A8E1B43D31ULL,
		0x6970D10987C7082CULL,
		0x7E49FC24182C394BULL,
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
		0xC25442A17CFC67E1ULL,
		0x378EB13C0C6F8CEFULL,
		0xD21A0D1917DE18A8ULL,
		0x95570BA6C23525D7ULL,
		0xFA1422BEA9575183ULL,
		0x9B45A9D1E02F518CULL,
		0x4A187139853E45C8ULL,
		0x8E0BBE9C0266D72DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7FD837732568D17AULL,
		0x1CB162110BB567DEULL,
		0xF21837057629F143ULL,
		0x09478FB46D9B960EULL,
		0xA08792E54F08EE5CULL,
		0x7DA99328AA868650ULL,
		0x9DA6994A63DFDAFAULL,
		0xF25D6625DDCE763FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8D596571BF364C0AULL,
		0x8008AC48F7C85006ULL,
		0x78E7E39295B801FDULL,
		0x27F09D7BC337F310ULL,
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
		0x6DFDA58F76F09160ULL,
		0x71A079EA9EE203C4ULL,
		0xA64BC49D7DA80634ULL,
		0xF71A8F1FCC5F313EULL,
		0x37136691144A4840ULL,
		0x4E790EC2D3AD6D96ULL,
		0xC104A922240BE6D6ULL,
		0x02D96880BF225922ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0BBD35CF0FACADE4ULL,
		0xF824E8EC0F334958ULL,
		0x9AE940A5A5E2A1F9ULL,
		0x04AE2B7385209FDBULL,
		0x6F1CB01FF3579E81ULL,
		0x5BCBEAF85AF6577AULL,
		0x6F8E552B9BA8945DULL,
		0x04AE676201005859ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x10DF848B4B4915E9ULL,
		0x7F2EE10C7ADC028CULL,
		0x22F2FA901683A22EULL,
		0x2CCE8E3C804AAF45ULL,
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
		0x27AED8882CB79F69ULL,
		0xB3F0F509A605F3B9ULL,
		0x13F61B8206E8A8DBULL,
		0xBAEC272AFD3B114EULL,
		0xC88B262ADD51945AULL,
		0xFC8E61CBD26F2833ULL,
		0x5B517BCEE52E5A8FULL,
		0xE9F437E7F107FB71ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE0BF8BD805C023B0ULL,
		0x1CCED69BCBFB4ACDULL,
		0x5B2B094AC40E9FDCULL,
		0x4F8C2899B915B46AULL,
		0x3C5337A3F530064FULL,
		0xBBA98269078A2914ULL,
		0xFD37CAFA42D1B8B4ULL,
		0xE3B8461126DDA7ABULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x173CB4B69BF29181ULL,
		0x391B4717F808879AULL,
		0xB09B51C75C9A0F8BULL,
		0x5845E473466DCC2FULL,
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
		0x77974E9DFE3B3C53ULL,
		0x5055CF8C47BCA371ULL,
		0x223C4C1B7220AA43ULL,
		0x120925271C2CAFBAULL,
		0xA39B8334E3719AA3ULL,
		0xD5B222F11CB1754FULL,
		0x31EB89C42385926BULL,
		0xCBE70AC5476762B1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xACD2EEB60C98CAFBULL,
		0x271C332CEE30C1D4ULL,
		0x6ED32E91E68E6027ULL,
		0xC0FD21BB68C33BB3ULL,
		0x25993C9C7CC0CBC3ULL,
		0x6FB6173E9BE8F0DAULL,
		0x707D5D1A9F0DDD2BULL,
		0xE2C457A79D4B0382ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7F1ADA872FE125EDULL,
		0x4CA358DE774F8B0DULL,
		0x69C3BEB3355731ABULL,
		0x6C3299D2F39F94F7ULL,
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
		0xE39B3E95CD970A3CULL,
		0xEAC358DF84F89509ULL,
		0xABA6A7E470C6D1E5ULL,
		0x0730E8077BAE3A5DULL,
		0x13EEA20A227CD193ULL,
		0x814F1D9C66FC4252ULL,
		0x076C5A3E84C266ACULL,
		0x6C3A698D945FAA5AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x81E318A0FA5869ABULL,
		0xE1266A3365ACCC71ULL,
		0x81D5A7C454327EAFULL,
		0x610E849FB4214161ULL,
		0xBA28AFBD26F0BA40ULL,
		0x98156DF643798B54ULL,
		0xAD9F6D4600864B5AULL,
		0x8E6475AEC66D9068ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB51A1D622A0A1612ULL,
		0xA82D015564B2F233ULL,
		0x7E3C2D03BD80615EULL,
		0x13E4967A597CD2CFULL,
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
		0x848DD925DB015D07ULL,
		0xAA33ACEC65B7F131ULL,
		0x4B766CA7AFA0D5BEULL,
		0xEABA4DAAB9F9665AULL,
		0xE8C160A6E1DE6B7BULL,
		0x4C5C7172E9724B53ULL,
		0x7331C4C9DA4B35F0ULL,
		0xE607CD794348C4E0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x75A3E9A6E49B9253ULL,
		0x1F2CAEF9E6319E77ULL,
		0x3CDB53241A0D1875ULL,
		0x2F26230AC7568A2AULL,
		0x7E57CE32CA6B5842ULL,
		0x6EF3AF7FDED336DDULL,
		0xD00913ADCA36200AULL,
		0x8ACC704439C01B2BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDA95ACBA717AA73EULL,
		0x6893C80613235C4DULL,
		0x46A563ADF8B4FD68ULL,
		0x4664007F5CEC0D00ULL,
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
		0x5E232F4088268E9EULL,
		0x1FDC5459EAC35C8BULL,
		0xF1CF820028D3B4EFULL,
		0x974AB51D81DFB661ULL,
		0x3118EE0F49E042B2ULL,
		0xE6534FE3C9A4ED06ULL,
		0xCEDAE7FB0C6EE462ULL,
		0x64664A6FACB85B2EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF8C62525AC18289CULL,
		0x39FBFF2345012208ULL,
		0x7DB1B3C8A6F4E9ECULL,
		0xC1299D11D8976540ULL,
		0x9894C77FDF582D84ULL,
		0xB56ECA67BCF86945ULL,
		0x0E657BF80824CEEDULL,
		0xEA9AC57890E2F6CCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x08FAC364AC4187CBULL,
		0x27CC25A0875DC919ULL,
		0x058BD6AA24DDFA68ULL,
		0x6A56D4B9CAF537CAULL,
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
		0x407A7A44E34B80DBULL,
		0xD600A5FBCB54FAC8ULL,
		0x87AEF35458D9A80BULL,
		0xE9603FFD3C22B379ULL,
		0xAAF8D0C6F5D3E323ULL,
		0x88E02AC736F3891BULL,
		0xA581CBF888CACF33ULL,
		0xBD4EF4067681DEB7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA420E23476E4213BULL,
		0x29AA7A00E35DC573ULL,
		0xE0E560E7369BAECEULL,
		0x8396B189B9E465C3ULL,
		0xE0AE757090FD5DF6ULL,
		0x78137ADD0E8767A5ULL,
		0xCA8ECE361499A974ULL,
		0xFDFDC8AAE02E0E78ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA36326E3643F22E5ULL,
		0x2AB848BCE8042CD0ULL,
		0x26DB3D4A6189939AULL,
		0x4BD5FE0BD2AF370AULL,
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
		0xAA4A5EA5CB8173BCULL,
		0xF504C4C7BA2B73D9ULL,
		0xB386B441CEA299E0ULL,
		0xD55F57D63577B8EFULL,
		0x08138621B5A4799EULL,
		0xE9A78D562EC1A6DFULL,
		0xBEAE7C2F1F3AD64AULL,
		0x5CE44EA01605359BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC3F1ED560D28B5C5ULL,
		0xB4F19319CF526DD8ULL,
		0x59A844C315D906CBULL,
		0x1310EE5542BB3670ULL,
		0xC1329A5FD1CFC414ULL,
		0xC958E463EE73FA68ULL,
		0xC8C5280119DDCFADULL,
		0x3BBE476607826487ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6BBB70178FEBB144ULL,
		0x0BC045A376609F8FULL,
		0xDA80EE5384988E68ULL,
		0x2DF37C1F1A278B75ULL,
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
		0xD9DA1AA4AABD85CDULL,
		0xEAA4E0403F4FA9C3ULL,
		0x79014B78E65EDC2AULL,
		0x3B7CCF977D3C340FULL,
		0xA9E15F24F448B6B8ULL,
		0xA7C68A82362780A3ULL,
		0x31758EB02E126A2AULL,
		0xC49BE023B668F5FDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF8B0AF1CBF1FCC83ULL,
		0xFF71D7C0AD2246EEULL,
		0x6F40FA181F1734E2ULL,
		0xD07818EB2603F0D1ULL,
		0xFC3DE88F2375F58BULL,
		0xE29CE62D52341FC0ULL,
		0xD0625FD466D31803ULL,
		0x6F770A8A52665DA4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA76D05C4EAE667C0ULL,
		0x2F616D19684DC47AULL,
		0x729946005AADD909ULL,
		0x0E7C6B712F9AE05CULL,
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
		0x7CF3320CB8B40903ULL,
		0xB7E57CE57032136AULL,
		0x003AF9E4CF47E3BFULL,
		0xBC017BABC52E91FEULL,
		0x6D8E2AFFFDDA368CULL,
		0x26DBECBA49071473ULL,
		0x729D8C27E582CA25ULL,
		0x08AD3D52221256D0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x491F33B4969551ACULL,
		0x9FC79A11A7F91A19ULL,
		0x045984A3A9E152A8ULL,
		0x7B3E847F9BE09947ULL,
		0x08832F9324AE0B16ULL,
		0xF1D5F406E400CFFBULL,
		0xF99621647C388A7CULL,
		0x440472EB37742ECAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x337550805EAD2985ULL,
		0xF700CD74C7272330ULL,
		0xF2FB4E42C66C040EULL,
		0x71D10272FCC7E986ULL,
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
		0xAD534E67B16DF009ULL,
		0x128834EF378E9460ULL,
		0x4EABE4E4FA482458ULL,
		0x38987846784C039EULL,
		0xBC4E296020EF09ACULL,
		0x0D7AD634CD1145E0ULL,
		0x06B9993AEB6BC011ULL,
		0x66472521D48CB3B5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x64EEBB52C93BFD64ULL,
		0xC4DC6E99BFF0FE08ULL,
		0xF2A984E7D80C561BULL,
		0x82E1AEB50B712E50ULL,
		0xD6AC3E4CD6EA5F76ULL,
		0x9D55D47DDFA7D8FBULL,
		0xB2F5C4C58C9884D3ULL,
		0x89090598A38AB7DAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5E6D77F1E4E335D8ULL,
		0xF32A077CB543C052ULL,
		0xCB13E9693596995AULL,
		0x0CEF77EEB32637B5ULL,
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
		0x07688F48C569578DULL,
		0x80A47079A6D4A172ULL,
		0x9412973AE4321242ULL,
		0x675534D2C4F8A145ULL,
		0xAD613CAD21EA6B19ULL,
		0xE49DC3DD6F84CA12ULL,
		0xE5355F00B27E00ABULL,
		0x5B8D69E096519B1BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1A675A886F9291B7ULL,
		0xFE4A1C845508F0F8ULL,
		0xD40B45F0179272E4ULL,
		0x44B99754D4BCB855ULL,
		0x3AEABF42E61DB862ULL,
		0xBEA7707867829FCBULL,
		0xE8868AF99960CA1CULL,
		0x3A806E6DA943D799ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEA97D28536394DBEULL,
		0x24EAB4F4821DF714ULL,
		0x41FACA5886F5B89DULL,
		0x0A88F08D2046EE3BULL,
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
		0xCB6977A48A20D489ULL,
		0xB9ADBAB7E09F8624ULL,
		0xEE56F69B5502FFFAULL,
		0x14D1EA515456DBF7ULL,
		0x509B9049FD943B33ULL,
		0x6EE2FFDF88A53E1CULL,
		0x8CFB392A1D68EAA5ULL,
		0xC52AE199CB4954F5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE62FD430E3A6BAF7ULL,
		0xEF1C1EDA3D8D3903ULL,
		0x6B6E40C83FD4B9D1ULL,
		0x4F85EB4409F9E119ULL,
		0xB40622DAD38D4CC4ULL,
		0xFF6471C99747E178ULL,
		0x8927C6CD0587AE80ULL,
		0xF2255090240C1100ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2367E1F3E3817D02ULL,
		0x575AB31F76EE0D6AULL,
		0x144BAFA4A09D3391ULL,
		0x181F867C1D75113DULL,
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
		0xF8C1F4071805E97AULL,
		0xFA8BE4FE68046204ULL,
		0x8442FADA42BE738FULL,
		0x1F187F06FB89EF6BULL,
		0x066E613386ACE2CFULL,
		0x201F6F890CD11B82ULL,
		0x5BD0284BE1C2D4D6ULL,
		0x00601EB9DE3F02B5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA15EB2D3D7562B45ULL,
		0xB8D18557023CBE15ULL,
		0xE9BFB3D37E5714F5ULL,
		0x987BA7162527ABA9ULL,
		0x9E957AF365E92C88ULL,
		0x9041512038C1CB05ULL,
		0xE41CD0C6698F08CBULL,
		0xB1AD1DF1997EBEBDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC1956EB81DBCC8BDULL,
		0x9CB2E336E00D9666ULL,
		0x5F2244D69C17A82BULL,
		0x352EF5AB0AEC5A7DULL,
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
		0x1C29F51598E2E6BEULL,
		0x88AEDA85C41F4A0AULL,
		0xF1AC624D9A761BFCULL,
		0x05EFA9F550506B0CULL,
		0xD1A7783FEE8E8AA1ULL,
		0x8360EADD6254BA72ULL,
		0xE35F6082EC7B23DBULL,
		0x78AFFE64AA6CAA01ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2D544F5DC2FB8204ULL,
		0x5BA37759ACBD8BA5ULL,
		0xE8A6881FFC33B2EBULL,
		0x5A9686F79C1835F2ULL,
		0x6473AA9FC1E054E9ULL,
		0xF81E2CD545964EF2ULL,
		0x3E96FB773ECC04A0ULL,
		0x0B0AEE7CDD3521CFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x24862B7E77C36057ULL,
		0xD8F398605BA5B375ULL,
		0x7EC4D9E966410BC1ULL,
		0x71D97F662A766C9EULL,
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
		0x6661E8CBF17670C4ULL,
		0x6DA075CD1332CC64ULL,
		0xF0C53868D6532EF4ULL,
		0xCE1BF84A492D631BULL,
		0xBC3B852A0C329CE1ULL,
		0x9BC1F18A8F1F4B6FULL,
		0x1D5578FF57E0B4B2ULL,
		0x55CF35B2F725A72EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA8EAE1B6E85D303CULL,
		0x03F3ECD5482D79B9ULL,
		0xA2464123D87D2475ULL,
		0xA014E9512ED1FC7BULL,
		0xBFD7086D1747AAE8ULL,
		0xF038CFA82CCE893EULL,
		0x8734DF786DC577B9ULL,
		0x6B9F244C8DF2EB6DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x34618B2163F92AF9ULL,
		0xE0079092630225F0ULL,
		0x9755C14BBDE11768ULL,
		0x7129A42CB7E34536ULL,
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
		0x1495A92F43A86EA0ULL,
		0x1020173EE54CE6D2ULL,
		0xF4F5CD929BF094FDULL,
		0xC625EE3078E617B5ULL,
		0x6E73DAFA11E8B561ULL,
		0x5A2F9105B4185204ULL,
		0xE83E32CD4A177A7BULL,
		0x595D8D2B5556C7FAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB5037F53B7A6F6ABULL,
		0x269EA90EF9ABE53AULL,
		0xB6646C3F91BC791EULL,
		0xC0232C286DBE3522ULL,
		0xB3ED6215D3FE7ADDULL,
		0x34BD16D380AFA19AULL,
		0xFFDA281E6707E0CFULL,
		0x83EB4E5EFD95EAB7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0F881BBCBCC62696ULL,
		0x787F91A38D2B3149ULL,
		0xBD6AF748BE84EB6CULL,
		0x34F8145D11C8BA81ULL,
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
		0xF82E1B29109F5ABDULL,
		0xE0D1894E813CBF0DULL,
		0x54EDB5C1BD08C23FULL,
		0x0D3F64F508F70BA6ULL,
		0x2C83AB6AA48629EEULL,
		0x59E34D07AF03DF84ULL,
		0x0EB5FC8EA13EF82FULL,
		0xC231A559524D4EE1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9DEAB4DCA24A655EULL,
		0x804BC90709617C2EULL,
		0x2DBB7F954DF580A6ULL,
		0x5B21511CB5EDB296ULL,
		0xA5D2E512EBD37F79ULL,
		0xF334F6CF61DEBA3EULL,
		0x09D504429F15F044ULL,
		0x9FFC4C1086E8B5E6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5880D751D8DA4368ULL,
		0x9E668CA2EB5ECB31ULL,
		0xE0971174C12A6E64ULL,
		0x460954A683F80E52ULL,
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
		0x4BA972041A001F1EULL,
		0x825201C350433681ULL,
		0xA41EB2BFCCC520FCULL,
		0x9E48A449BEB43D3AULL,
		0xBBE787DBAC19548DULL,
		0x2A58A9700472E2C4ULL,
		0x2829D3893219568BULL,
		0xE5F0C9EE93FD5C08ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC46EE02775959A7BULL,
		0xE13D1C3AA91ACBA3ULL,
		0x585E2D803712DD93ULL,
		0xC9495870B40785AEULL,
		0x34CFA003EA5F68B8ULL,
		0x6F7BA9B839390FB4ULL,
		0x553C95BE309BC1C1ULL,
		0x88EEAA6F61DA19E1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x94C6FBE366038842ULL,
		0x5DE2DAD0D1BDBF51ULL,
		0x9AF7B161CE56595AULL,
		0x234FF8BA7BE8894FULL,
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
		0x2F42FD09984983C8ULL,
		0x09B1C700B742478AULL,
		0x406FE5E5FB98EBD0ULL,
		0xD8C9C7C717850E8FULL,
		0x6F044A52A8860B4DULL,
		0x0AD2C6A41FF0EB71ULL,
		0x7244A44B16BAF610ULL,
		0x12904F7C7935AEBAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6F22A798C08C1C06ULL,
		0xCDAA3D12EB056D1AULL,
		0xCF32ACF86176B7E8ULL,
		0x182FC206C71D59F6ULL,
		0x192034D1C368AA23ULL,
		0x2007F2CC92BE07A4ULL,
		0xF3A92EFFB8F61597ULL,
		0x8D22FA6EB157DBDEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7FFB8692DA19D165ULL,
		0x1622FBECC1CAAAEAULL,
		0x3C50A21D855B85DAULL,
		0x0ED4A5CBFB55012DULL,
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
		0xA032B045A3F11FE8ULL,
		0xCB7699A683263EE2ULL,
		0x0945F49478F042C4ULL,
		0x562F67C8C3CD3ECAULL,
		0x9194518602D2FA92ULL,
		0xD33DA330FE0FB9C6ULL,
		0x5C5707EFBE03584CULL,
		0x383039888A5F9334ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE094394ACD78C8D9ULL,
		0xDB87D1C8668F36B8ULL,
		0x8DB4DFBE69E527CBULL,
		0x17014BEE4581FA8BULL,
		0x7535CCB0CC7A30A6ULL,
		0xCA4092C9E99EAC1BULL,
		0x71FE76D29D6B8801ULL,
		0x6B57291DBD52ED60ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF5A62EA0E7A64EFAULL,
		0x457F372B255F0F8FULL,
		0x44B69F28E594061CULL,
		0x27668BB4EE2BE1B3ULL,
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
		0x4BD2CF86A586449BULL,
		0x91B5730D0D42321EULL,
		0x19EE99A1C00E2DDCULL,
		0x8FBC63CFB0B940F4ULL,
		0x846A77F9E06AF7A7ULL,
		0x56CC70B1FDE6943FULL,
		0xE8154AEC40E1EB75ULL,
		0x2ECBC7D98C5C1EE4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x69703340E208956BULL,
		0xECABC235659B50A5ULL,
		0x063A2C5503F896F5ULL,
		0x9CFE46272E8EB380ULL,
		0x7C975969C8B52172ULL,
		0x43709988C5E2EFA4ULL,
		0xFC2A5460DF5B2B0AULL,
		0x2E00E474066A8256ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0BB925A9487B7B0EULL,
		0x84ABA0F5F831507CULL,
		0x189505FD361626CBULL,
		0x10DBDEBA6407CA85ULL,
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
		0x84848BC65C37E19EULL,
		0x669A18FD7179201CULL,
		0x7524D0A96D9119E5ULL,
		0xCCF88BAEA8E7AD5EULL,
		0xB876E914E9E20D15ULL,
		0xC4BE6BB6D9B93A42ULL,
		0xC106FE8167047227ULL,
		0xD4BD7C8904F4A44CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAD2CC67718D3132EULL,
		0xD026F881A36F80EDULL,
		0x9098A5069C8ACB68ULL,
		0xA87015F01EA61AECULL,
		0x66949ADC92AAD769ULL,
		0xE28BD15545501F27ULL,
		0x63C5F953865A72BCULL,
		0xF1E4166F0AD5C892ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFEEF61AC3596C54DULL,
		0x29F60AF7D5A3A53CULL,
		0xBC32F0722A42385AULL,
		0x50CD9D99AAD6301BULL,
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
		0x0958E44AFDE4BCE9ULL,
		0x38DCD82581D02B62ULL,
		0x29565BA00FECF520ULL,
		0xEB9DAC18BF384796ULL,
		0x43976165310304FDULL,
		0xE865D27F18CEF5FAULL,
		0xCAFD14CDD7A3AA97ULL,
		0xB87B778ADE50B6C1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8EADC5638C94032DULL,
		0xCF9E574782E460F5ULL,
		0x644C6F51136E7575ULL,
		0x7B5DFE692B5AD0FDULL,
		0x72CE6BB9E9FC265BULL,
		0x7C8C5D7963040C93ULL,
		0x1BE8349BDD5EB4FBULL,
		0x72F54D497FA51720ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x787F9653FC55C757ULL,
		0x6B85DFB6FB0A6FAFULL,
		0xC22333BA22BAF4E2ULL,
		0x4229F363A1572898ULL,
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
		0xBFC9751DBC5D2651ULL,
		0x81EECC1A9C8484D5ULL,
		0x01509F29E19DB7CCULL,
		0x3604B4D95D3777DFULL,
		0x180EF76C6488CD82ULL,
		0x127C0CD3421168D6ULL,
		0x0EBF898679EE6426ULL,
		0x817576FFFF678554ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAAE0EF1737165E82ULL,
		0xB6EDABDAFFB6EA6FULL,
		0x60F47D894F64B6CFULL,
		0x766D96A5FCB85AD5ULL,
		0xAC5CA28D9C80C7F6ULL,
		0x8F4069A12ACDCB9CULL,
		0x2F9A91AF8F16B4C5ULL,
		0x02F2673950457F61ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x11611F1836779D56ULL,
		0x45DB59AF10D6F0ECULL,
		0xBFD8EB876E3D0950ULL,
		0x070B75B15F8BFF16ULL,
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
		0xC3686D2205314FF1ULL,
		0x86566C63A4A4CF28ULL,
		0xBF1E08ED6A6A8526ULL,
		0x382F046F02B88394ULL,
		0x6B84178BDA28891FULL,
		0xE608197BD0DD5C3BULL,
		0x568EA201C648C989ULL,
		0xA5915A643DDAA6FFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4FEFFF0B88CADA1CULL,
		0xBB518EDDFF136EE2ULL,
		0xF0B5BFB0036CB578ULL,
		0x7E83C0554D3BA9E0ULL,
		0x1320B2BDC91C68ECULL,
		0x3B079F67055672C8ULL,
		0x8A837258939489D0ULL,
		0xBB0C08ACE5EC46BEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x923964AD04333CE2ULL,
		0x2D16FC9BDB980765ULL,
		0x18115C5AEDBF453DULL,
		0x09756550C2DF2352ULL,
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
		0x14E0463409847F47ULL,
		0xE2A414C70BE3AA19ULL,
		0x2041FE5E78C0A44FULL,
		0x82DC1925E0D3ECEEULL,
		0x4D57AB3949FEB5ECULL,
		0x993B10C2E3746F04ULL,
		0x94AC3B16FE4BC042ULL,
		0x0C670509F9A6819AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDFE65D676FA4B4E8ULL,
		0x59E0AA30C259660DULL,
		0xDE62D61A2273D09CULL,
		0x34D1953A822A4ABBULL,
		0x9C993529B31D8DE8ULL,
		0x96EB63C83C96A83EULL,
		0x55F8AAF81D49A840ULL,
		0xA32349E57B4B8C93ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x713F6F1CFF4BB7A0ULL,
		0xE09717CB0E75C563ULL,
		0x90868CD9BC9C63FFULL,
		0x6E184B56202A0145ULL,
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
		0xD46DEC9618844728ULL,
		0xB0AF02E870FEE602ULL,
		0x0D116EC98BD69BA8ULL,
		0x13F699F6B77722E7ULL,
		0x087191DFE62ABE86ULL,
		0x89ED9D7976A629B0ULL,
		0x7590051BE7F8CD05ULL,
		0x35A820DE57CF33C1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF6CB8E50CFD3D4AEULL,
		0x3A551FC57EE78840ULL,
		0x848C9ED16F08FC31ULL,
		0xCD0CF6ED96962761ULL,
		0x47E7A14E06CEC787ULL,
		0x8A0DAD25311E6F10ULL,
		0x035E16115D19CBC4ULL,
		0x715D13AE663BE55CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x721C13EC70571AD8ULL,
		0x71978FA5443D1178ULL,
		0x7BEE4B88B9E7CF1DULL,
		0x6A0D9826FCBE9E94ULL,
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
		0x40208D6F6F8A75D7ULL,
		0xBD4B67B21ED0C572ULL,
		0x2BE5B35F8D7AFEC8ULL,
		0x35C3BB84BEA673F3ULL,
		0xF4B825127867DF4AULL,
		0xCD79E4B1BFB02009ULL,
		0x8FC51420266FCED7ULL,
		0x76FABCE498A2BE41ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE1198ECFEFEA918BULL,
		0xF3C5B5E6EFB3CF40ULL,
		0x1C8913FB8FA70E80ULL,
		0x697C216037DB567CULL,
		0x0BC1354AB4D7A869ULL,
		0x764AD3661EB5007AULL,
		0x73EB2D452A5E71D2ULL,
		0x708E4FF2E6305324ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF3AE9646870809C5ULL,
		0xBA8243051463A58DULL,
		0x31B4E3E56867BF12ULL,
		0x405FC60503C703C9ULL,
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
		0xCD68A5EC2B41AD83ULL,
		0xE376936F7FE683B4ULL,
		0xD2C61AEC5A32E6B8ULL,
		0xC7C4CA674B9B72E5ULL,
		0x1DBBE7B4B614EF35ULL,
		0x3F922EB042EBA59AULL,
		0xFD564732A62F8142ULL,
		0xF5C4AC3E7E43D935ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD1664860FF6B2F43ULL,
		0x171AF870267FBC16ULL,
		0xBA62C928FB8079FBULL,
		0x538FE8EB1A72E924ULL,
		0xCA9068FAD16B8A83ULL,
		0xF3CD22953BA2D678ULL,
		0x84DC9CC672D77686ULL,
		0x2CAA225CA589A784ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x54772D231CFB7520ULL,
		0x0B9B67026E358690ULL,
		0xFA729DD2FDC4048BULL,
		0x4E2559025CCBEA18ULL,
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
		0x2F20D4158102A896ULL,
		0x89FE95E35A7EAF97ULL,
		0xF2C455A830370777ULL,
		0x48A535DD5300F1DDULL,
		0xD4823B38C4FCE9B0ULL,
		0x054A07553390FEC6ULL,
		0x533A31D2DBDBAF4AULL,
		0x5FF5FB60E30AE280ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC579E5A872808C52ULL,
		0x24D9B850A5354CF1ULL,
		0xB9E41AC88B499085ULL,
		0xE753010BBAF86814ULL,
		0xF3CCD2E1A24E5D22ULL,
		0xAE4C2CAD4C5D3254ULL,
		0xE66FF34EAECA0B97ULL,
		0xA161DA1D2D089659ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC4946B5C346AF7C9ULL,
		0x4ED3527F06F9BB8CULL,
		0x5EE5827E558BC36BULL,
		0x2B4F24DE9C5FD77DULL,
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
		0x00F2C3E16CC27650ULL,
		0x090470874F82C356ULL,
		0xA72B454AEFB730B2ULL,
		0xAB9A3CFF28DE39EBULL,
		0x5791CBEA79B9A5EFULL,
		0x6D0BA8C07B7E8966ULL,
		0x242ADFFC064E49D9ULL,
		0xDC49C3460A0D2BE9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x87D264B83AC9AEEDULL,
		0x95512FCE392172CDULL,
		0x71C0434AFC38DDA6ULL,
		0x3AEBBC072131D596ULL,
		0xFEFDF91E3BDF45FDULL,
		0xA46BE2F303FDC032ULL,
		0x83207B34FDAE3EFBULL,
		0x7C20CC8767012F18ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9F11A97A60630776ULL,
		0x3B6A9D38D37F2E27ULL,
		0x1CF5F78B3B3FEFF7ULL,
		0x36C321443B73EB4DULL,
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
		0xC98BDA224DC4E66CULL,
		0x3965C7BF23F6CDFFULL,
		0x00396E7C4A8E93DBULL,
		0x59EF1C1417106869ULL,
		0x6514A5226464B857ULL,
		0x14FEE0530183290CULL,
		0x8681656D5C011C61ULL,
		0x3F247CAF841493B0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x97DB913D511EBE77ULL,
		0xD005B5BFFCF4615AULL,
		0x63C7E1530D9327B8ULL,
		0x7D0B925375F7B114ULL,
		0x36BBC392AF2AB003ULL,
		0x98A1F6197AF2C647ULL,
		0x86858421B4AF89C1ULL,
		0x821673B1FE15A933ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x12E1C439E34362DEULL,
		0xDF2AD689207115EAULL,
		0x9BD4FE6413172FCEULL,
		0x6CF8DF6284EF85E2ULL,
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
		0xBFAC2BE36020F1FBULL,
		0x082DA29D6E8945F5ULL,
		0x747789C517A8EF38ULL,
		0xEA406696E7A6404AULL,
		0xDC9E6C272DC3D35CULL,
		0x551EC6C99A773CDEULL,
		0xDF8EC182A7DC6072ULL,
		0xA2FB96AD45060EC9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE2225BBDFF42286BULL,
		0x6C9A079E47FB4239ULL,
		0x46673C8E0FF49AB9ULL,
		0x3CDCCF36AA53B652ULL,
		0x0ED6F47ED6F9B2DEULL,
		0xCC830F2DCAD53BB0ULL,
		0xE9F4F9AB9D2E7967ULL,
		0x35E057B746C2436CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6925932242DF9EB7ULL,
		0xE2B0DC1FF89A30AEULL,
		0xA2E3F7229D84A00EULL,
		0x5F6EEFE3FB62B9C4ULL,
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
		0x8DD294B939DD46BCULL,
		0x63C11383E646A424ULL,
		0x18581D18EFD3B6E2ULL,
		0x8B8578FDD400476AULL,
		0x8FD4938D2F7F2A1AULL,
		0xF78D0EEF4E92660FULL,
		0x31D346E52861027BULL,
		0x8CF5F5CA86AFC576ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1CDC6D51E6CCADA5ULL,
		0xDD7005B6F6DCFB58ULL,
		0x296D710A14BD00A1ULL,
		0x6B053ECDF3D3B942ULL,
		0x98BBB8BE69ADACC2ULL,
		0x66C90AEA510FB399ULL,
		0xE85858BB0AB0B007ULL,
		0x82F284A2DDD5EDBAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1EA6A218B0293460ULL,
		0x0369A68A90D0264FULL,
		0xD72A064F4342F38EULL,
		0x1D030612F08293F4ULL,
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
		0x2C432E9B9F37E084ULL,
		0xA3630211449115C0ULL,
		0x007EBDB7D77225ABULL,
		0x85F0927F527C69D5ULL,
		0xFA700280DABA78C4ULL,
		0x25309B321D0174AEULL,
		0xC070AAF887AA9E85ULL,
		0xE97607FD9DC3B243ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5A16A16CB67A1983ULL,
		0x7C22CC399CA7C268ULL,
		0x48EC5618B9ADBC3CULL,
		0xFC2F2E2F4D5EEC95ULL,
		0x2E12FA467BD66656ULL,
		0x503B18ADC82D7E3AULL,
		0xDE58859FE1243B12ULL,
		0xF5E8AE57A7C377BAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x27FBC5D8FE9882F6ULL,
		0xC3B1957C3F5FE8AEULL,
		0x4727F2C7D5B72C7AULL,
		0x30BCB2F289262D91ULL,
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
		0x9FC421B8433179F3ULL,
		0xDB91C34F3F490417ULL,
		0xCAA28883E13BE7ABULL,
		0xB317F3607C7AE7F5ULL,
		0xFC48D389ECCC5ED0ULL,
		0xC4F39BC260AD1343ULL,
		0x6FFAE5FE8DE6B057ULL,
		0xE98E1967D9535C1BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2C2007C5A8810856ULL,
		0xD3C82F95085FC22CULL,
		0x85EA54FEFD4CAF97ULL,
		0xF52A6BF681FED7DDULL,
		0x5B42124A29C32D65ULL,
		0x1E44C978AF2ED2F5ULL,
		0xDED25E9DF5A8F065ULL,
		0xE7C6D16D2ED88A7AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5AA4C9698E0DC77FULL,
		0xC5BCCAAA8FA6CD97ULL,
		0xD0BC4BDB7D19B618ULL,
		0x0182369F48B72DEDULL,
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
		0xA26E04C6ECF8A69CULL,
		0x3523CDFABBB74318ULL,
		0x6F8B345C3C017660ULL,
		0x8EF01E09F4D4890AULL,
		0xF55FB92E2BD61C5FULL,
		0xEC6E48145FDA80CAULL,
		0x55566D10853D818CULL,
		0xE2A4C85A3FCF65C3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBF10B5C78D105AE6ULL,
		0x045C9C0AAC01A2F6ULL,
		0xEB0A53F566E8EC90ULL,
		0x8FA0BBF338267F0BULL,
		0x0B4D41959EF58F1DULL,
		0xEF49C225D6262525ULL,
		0x55D4958D381D995DULL,
		0xF6659BB384F87AC9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA21B0FA4493D4310ULL,
		0xC4331358807B3AC2ULL,
		0x71C6DDE447D500C9ULL,
		0x10B002D67894EB1AULL,
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
		0x5914A2EC1A723C9EULL,
		0x1531E08E2875826BULL,
		0xB0D5F45D46328A5AULL,
		0x18518D9C60FAD769ULL,
		0xB5A1378087EAD7E2ULL,
		0x32B0DD57B0512FF7ULL,
		0xD5E13283220B8AB4ULL,
		0xAF3EC5E831DBEEDEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x577A1D1958887AB1ULL,
		0xF370BB98A3A86708ULL,
		0xE73F4C341328C6F9ULL,
		0x8EF288A2B7B75784ULL,
		0xF2DA966AA7361AFEULL,
		0x23D882EA47A91016ULL,
		0xEC223E7EFC1E4402ULL,
		0x95FB1BBC47058BC4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEB166F121CBDCC37ULL,
		0x55DE91330DC1D6BFULL,
		0x7BEEE0C6D44241CEULL,
		0x496A477E851635BDULL,
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
		0x3AF7C748CB88F67FULL,
		0xD1F0DBFBAAE43743ULL,
		0x9E767AC7332A3359ULL,
		0xA73CF98B5944C9B8ULL,
		0xCE08FA23518D671DULL,
		0x2F7A0A8CB0E81F3AULL,
		0xDD677079A042ED74ULL,
		0x4F6B13789D033276ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0055957558222EA1ULL,
		0x0DD76E70D1F6BB2FULL,
		0x74933D563EF7841DULL,
		0xC101600F5045C907ULL,
		0xFBDEB5B58A7DB90CULL,
		0x6D159F23E8D0211AULL,
		0xEA8AA701926C5E5AULL,
		0x2B48923B041F7EBDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6CE85A1EFFBA9F22ULL,
		0x9F015F188C7D34CDULL,
		0x36A92543020BED0FULL,
		0x435AC8A0BACBAE25ULL,
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
		0x20846DDAE609303CULL,
		0x0033CEEFEFEA2653ULL,
		0xD08C1208C7BF8A07ULL,
		0x9229A3846F61C090ULL,
		0x1FCC286EE0F81958ULL,
		0xED1F954F1C5C3F7DULL,
		0x7AF4BDADBDD24862ULL,
		0x94F926C646052BEBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8AF1A15A1199C03EULL,
		0x9E3DBE521339496DULL,
		0xDBC1E7DA7B9493F4ULL,
		0x8956918FFE540B3DULL,
		0xE44BA1F7A03DE3E0ULL,
		0xEE3DE540867D46D6ULL,
		0x6C9D501B3AEC5944ULL,
		0x62BF9D7EAD9B1CD7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6AA6C234701360D8ULL,
		0x377632C81BC9C592ULL,
		0x15C46DEDBA4C7486ULL,
		0x7D5D729510CBF24DULL,
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
		0x65626AEC234B9A8AULL,
		0x2951295A3D52CCD4ULL,
		0xBFFBC69AC4BE1186ULL,
		0xDD4B93627FBDB559ULL,
		0x94E9D877FE829688ULL,
		0xB0FA63DCD5127EF2ULL,
		0xA6366CC0BB8C26E7ULL,
		0x4BAEE501018A3994ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2B5160A81B4DD5B8ULL,
		0xC024251F6CF36CEFULL,
		0x5D5E6BCBC84C4685ULL,
		0xD5D5520D4E858C4AULL,
		0x2193D78D55F66DE8ULL,
		0x3C44F5CB3073D455ULL,
		0xE649B0B0F4B2F4DCULL,
		0xCD829A8FACFCF534ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x58D52D190CCBC9ADULL,
		0xBC1B5AD93FECB344ULL,
		0xDFC1452680AF38B3ULL,
		0x42094E27BE304F45ULL,
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
		0x528D17F73B6E82A1ULL,
		0x7D1F6BE2EF6BD980ULL,
		0x2559725004272C12ULL,
		0xBEFF16E969FF8309ULL,
		0x571D863D21975D78ULL,
		0x04D8FB00ADFDE40EULL,
		0xA497435170D2B879ULL,
		0x9E44BD36C385B214ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6A64CFA17376257EULL,
		0x194F88AA8CF3A45CULL,
		0xA9BA3A4A8B9735FFULL,
		0x4F14DDC591A121E6ULL,
		0x4B3E11E0F81077AEULL,
		0x7AF8D4620A6EFE0CULL,
		0x99385F95A6BF829DULL,
		0xEB6E2984C136206DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAB538E03F1FE776AULL,
		0xDB159EC4A9AE5971ULL,
		0x2BB505E57769F4A9ULL,
		0x7BC42590302DFFEEULL,
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
		0x143FBF2A2591AD40ULL,
		0xB46F1573A5107570ULL,
		0x9291BFFD922DDC2AULL,
		0x83C6F806F8721668ULL,
		0x40B4F66FE1822C07ULL,
		0xA6F26489D505DF49ULL,
		0x78CA543723ACC500ULL,
		0x6D835D6D82AC5FAFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDC9BA4DA6E6D512CULL,
		0xD7924DCE5344ACECULL,
		0x53BF9554E820D172ULL,
		0xB79F2A3AD37BF25CULL,
		0x8B37A88F4193B1DEULL,
		0xAC24D13BA7176A5FULL,
		0x1F1E22FF1DA7EEA7ULL,
		0xAB756AF8CB9E7FDFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x283DA9A7748A7CC1ULL,
		0x1760A54023312334ULL,
		0x8E6178F98EC4DBEDULL,
		0x1A39CB1F51055CF9ULL,
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
		0x485C4CD38264B7EEULL,
		0xCAB86D4EE1802B8CULL,
		0x62971B6DAB31594BULL,
		0x0A93EB66397246F1ULL,
		0xC1DB0D1EA26CF221ULL,
		0xCBF52FD7FEC9CE36ULL,
		0x57EE6B7FEE28C297ULL,
		0x790DC1D72F31DF08ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4A22FEB1B653D264ULL,
		0x222586BC27F7773CULL,
		0x0E318767485FD301ULL,
		0x0A6C3872EE57EFF3ULL,
		0x9B53E2D04F1DF18CULL,
		0x8928076E6B888EC5ULL,
		0x62411CB8254DAC0DULL,
		0x368BEF6F87992191ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB64995C229CAFD11ULL,
		0x9306E63E95381F1BULL,
		0xCC1F45AE3356DED0ULL,
		0x5F6CEE562BC676A6ULL,
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
		0x0FA0B90C1A3A9947ULL,
		0x8A1BDFDC72F54AD3ULL,
		0x543B69AFD74305F7ULL,
		0x9F514CDEFF78BDEFULL,
		0xE0735E8C81EF4B20ULL,
		0x2617C4470E94FC37ULL,
		0xF69450E441D34BA9ULL,
		0xE405196D55F83B3BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x77A8337280179231ULL,
		0x0C00DA25A3B81C37ULL,
		0x8A05B38EFEBC0886ULL,
		0xA08C2850E6F713F9ULL,
		0x44A6C1A5D03784C0ULL,
		0x950A48D0E149FC43ULL,
		0xF72BEA46F993B6E6ULL,
		0xA7FE653A8CF0FB61ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB857CFD7FB6A7A99ULL,
		0x061B5941885F2CEAULL,
		0xB3B4F17991F71253ULL,
		0x67C3E417EF952451ULL,
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
		0x8BCAC233A2A1E858ULL,
		0xDD0B1FDF6B216A2EULL,
		0xB07728BF2D0ED2F7ULL,
		0xB84A7D9F5DF3357CULL,
		0x93641934AFFC0B2BULL,
		0xA24FC8E49C0A9DB6ULL,
		0x91F5EE1D73383E65ULL,
		0x269F594E3BFD0332ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x164495B0024AEA34ULL,
		0x12E1C0B6BF497D98ULL,
		0x7F8B5BAD947992B1ULL,
		0x2E4382B60D419559ULL,
		0x19153056E47C5505ULL,
		0x524A3CF57995D12BULL,
		0xE26C69654F41A96DULL,
		0xACE6239C48FEED83ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9D3CBD6FD54C04E3ULL,
		0xAAFC24A7C92E494AULL,
		0x3F558066EF2F5D22ULL,
		0x1B84F3536268D811ULL,
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
		0x2F773692F33F001DULL,
		0xB3D90A7171F18D74ULL,
		0x8387D863969C6325ULL,
		0x7DFA1FC5F86B2EE7ULL,
		0xB8B46447862D0772ULL,
		0x0F36EC6A637C3182ULL,
		0xEC8FC9A01792109AULL,
		0xD19049283E9F7A13ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x15246FC0739F8884ULL,
		0x5A740CC7A969609BULL,
		0x2F23A98F09C7E18DULL,
		0xE84B236A46496E35ULL,
		0xA038975D9B0D23BEULL,
		0x6324B4C92A24DE2DULL,
		0x069E129A7C129D00ULL,
		0xA038C3C01E330827ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBCB3318B665B4548ULL,
		0xE4193F984B7E8B7AULL,
		0x764559A9A1BFAA67ULL,
		0x68ACC9D0823AA9DCULL,
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
		0x2D543AFB8519B17EULL,
		0xC3024C6C93B5D53EULL,
		0xECC2E0BCB40AC09AULL,
		0x9EEF45F55A2F9093ULL,
		0xCB824E7DD16F2A62ULL,
		0xF5B10DEF477E3ADCULL,
		0x68204CEAFA6EC380ULL,
		0xD858997B23093A88ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDF55A40CC0DF13A1ULL,
		0xA8E98C4BEC5420EFULL,
		0xE9690801EF3AA695ULL,
		0xA8D5C6B26116C051ULL,
		0x2BC7D2C368D0770CULL,
		0xABFC43076C9939F4ULL,
		0xA754CEC7A16C2708ULL,
		0x323C9C3AB8DFED8AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x03ACF49A4BC94044ULL,
		0x0AEEDE8B255FD6D6ULL,
		0xA18E91F9FB3353E0ULL,
		0x1E4116D2BB3A3DECULL,
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
		0xEDD4AAB33BEB40CDULL,
		0x8B7D3CA1EFC88146ULL,
		0xE44315DFB3303040ULL,
		0x2E1CEDB077FD4217ULL,
		0x31A0DD56A6D1BF54ULL,
		0xEAA523245D52B8B1ULL,
		0xA26A1918B17DBD1DULL,
		0x6B84CF478FDD45B3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9710BBB5E18FBDF0ULL,
		0x383C3BD87026B860ULL,
		0xA4C16CD7469F411AULL,
		0x7CB265B1B2BF99E5ULL,
		0x501960197BE2D899ULL,
		0xCBF50FC0DF60DB1BULL,
		0x9886725E0B2E566AULL,
		0xBB34244F8A151B57ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD0E08611B9D1C0C4ULL,
		0xE163E18E3188AD25ULL,
		0xB74C68BD1C5A2DBCULL,
		0x5D63E8CFA0F3F1DBULL,
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
		0x41160AF2E7C197D0ULL,
		0x7640555FF1FC7B5AULL,
		0xAD0C7CA23D7E762BULL,
		0x84297A7A4321A10FULL,
		0xED04F354A701C110ULL,
		0x2A7E27AA9C3264ADULL,
		0x21F7C838EB142CADULL,
		0x7257BFCE346B884DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9D3FC8D9FDB1948EULL,
		0xF669874254FF8E98ULL,
		0x619ECCB404A40495ULL,
		0x5769B669FB54BCFAULL,
		0xB0DF3860109BBE53ULL,
		0x4D6E8644C35D5B02ULL,
		0xF9CC6495AB70232CULL,
		0x15B6094C7EAADFFBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x917002673D346D51ULL,
		0x5028C33BCC9C5C2CULL,
		0x41DE7A29AB33DAB6ULL,
		0x6CC0DB514265E021ULL,
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
		0x66AA3ED9CBF1B12BULL,
		0x4FE70893593422ECULL,
		0x195E8FD6D6EA0863ULL,
		0xD50CA3C1E4D76782ULL,
		0xDC0A5BC0F2660108ULL,
		0xD7905EDFA03C7C79ULL,
		0x66EA921BAA64470FULL,
		0xE0E7DEEA12BC3182ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x61AD3BE75E06586CULL,
		0xFDB0DC2061638FF6ULL,
		0x7CD3CB2A27FF9B36ULL,
		0x7493085CA99ECDECULL,
		0x768AD13B7CC8FC2AULL,
		0x0E0F1C385A3DD299ULL,
		0xB68FED9E552A6268ULL,
		0x3DFB2671E3E37DEFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x15EB92C1E33A1556ULL,
		0x3B6611475B9DCA45ULL,
		0xC9FF2F4755825E14ULL,
		0x0F9CFD3C2F63415BULL,
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
		0x4F3FD00212FB1F7AULL,
		0x75D1F09A544B8FC9ULL,
		0xA123451BB816D5F9ULL,
		0x42CBE87895287AD8ULL,
		0xD8DFC4BBE7467A27ULL,
		0x35FF59987FBA65F5ULL,
		0x185CCA1720B60934ULL,
		0xAA0A8C2F90898D7AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBDF39BD2EB425595ULL,
		0x0A8DF17E83D1201AULL,
		0x460E84020507D1B5ULL,
		0xACEEF904FE7BC938ULL,
		0x0B81400CEE471257ULL,
		0xF5E2E8375455C868ULL,
		0xF47096C946565720ULL,
		0x9F413D06E5167A57ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0D53E6281DA232EBULL,
		0xEF7CD3884169D2BBULL,
		0xB0245EA81D43731FULL,
		0x2FBEAF7D09C188B1ULL,
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
		0xAD63DE6F84207F17ULL,
		0xDB70EB8EC5055FD8ULL,
		0x8F44799D28B9CCEDULL,
		0x80CDB77EC04558CCULL,
		0xF2152E0EBF5BD518ULL,
		0xCC67E0921098E8EDULL,
		0x22C6AE6B58D33FB2ULL,
		0x70AC8A2562CCC463ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6E5915C1CE0A260DULL,
		0x0644683C54BE69F6ULL,
		0x801153FBEE23E7AEULL,
		0xDAF095F8BCAB9663ULL,
		0x83F8C4E210DAD10CULL,
		0x118901C03D8C5EC3ULL,
		0x3A5F26F79642B28BULL,
		0x11D5240AF5F236E9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9742654F9D3CF4D3ULL,
		0x92419677C423782EULL,
		0x8E9140D01C0AD925ULL,
		0x39D649722C0AC281ULL,
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
		0x155E55156859675BULL,
		0x318F06BFC7261899ULL,
		0x6CCD2560A350093AULL,
		0x3C429A860E52B615ULL,
		0x5EA77570984435DBULL,
		0x1A3571E14B0D1A9DULL,
		0xD6C5E04BAF368CF8ULL,
		0x5E3E445CAB3547ACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBC71349329D9FFB9ULL,
		0x82FB81268483D948ULL,
		0xE5051DA5C01EB913ULL,
		0x06DF08B766FC3AA4ULL,
		0x53377E54CE1C8ACEULL,
		0xFE231C8271BE51A8ULL,
		0x16397773B3843289ULL,
		0x3CB2B26681BA2FF7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0B8BCEA24062CC4EULL,
		0xD94C31AD845413B0ULL,
		0x1C9F97CA3FAABC7EULL,
		0x301B3C58CF9C006BULL,
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
		0x9B577ED7DB15264CULL,
		0xA825939392121FDBULL,
		0x7F4F3428C86A0965ULL,
		0x951BFC4FDE9C8A99ULL,
		0xEC37374D239C0E43ULL,
		0x3136B2501D873EF7ULL,
		0x9A45B237399E0BBEULL,
		0xA3B10CA83C7C1F4AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1386E2093FD26A72ULL,
		0xA54E693E9CC03A48ULL,
		0x04B37E63F2F6DAB1ULL,
		0x96BB078D6F6ECE71ULL,
		0x86DDF15E0F134312ULL,
		0xE455817334ECDC0AULL,
		0xBA645DE5D5809252ULL,
		0x35698EB2B0BA1554ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9310FE4BA790E780ULL,
		0x6C446B1F7C3C94D0ULL,
		0xB60E39D9B1D334A1ULL,
		0x5CFDA7352DFB36A7ULL,
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
		0x3E1C00E753F83183ULL,
		0x88541540DA1C0708ULL,
		0xD0FF9DDA1380CEE4ULL,
		0x1D4CED15CED2FEDDULL,
		0x2302B37E0E1E0985ULL,
		0xEE66AA3E3A24978AULL,
		0x6527874A8ADC7A14ULL,
		0xDACC54E9F856A39FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x482E4ABC1C55C0B0ULL,
		0x3402B96A0B46CEE7ULL,
		0x1039D7B89E2A43A4ULL,
		0xD38C478B906B4257ULL,
		0x5660730584D29AAFULL,
		0x2E3C0D4F624C3A49ULL,
		0xCA11675FC6AE9D9FULL,
		0x64C419C179F347F8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5603480F98D4E70AULL,
		0xDAA4A74AD8F30FBFULL,
		0xC60E82FA942544BAULL,
		0x4EF96D8D01275741ULL,
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
		0x214288F9007439A3ULL,
		0x4152592834BAF92BULL,
		0x523F2BABCB5C713BULL,
		0x028950CFB5EE0D79ULL,
		0x061C445F3D6C7DD0ULL,
		0x516B63A782DADAFDULL,
		0x63392B54CFF28795ULL,
		0xB9EF2592F1B31F85ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB83E72E3957DB70EULL,
		0x63778B546610EDF7ULL,
		0x37FA517B8C6F38B9ULL,
		0x727AB36720CCC266ULL,
		0x778393B7277C6878ULL,
		0xC77B4730A56DBED5ULL,
		0x0638B30F89DC3C54ULL,
		0xB4D5C3054212DB48ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x93AE4F08AC99ADA5ULL,
		0x577F0778ACDC3912ULL,
		0xE856B478A63C6416ULL,
		0x51D33E70A6EB6C2EULL,
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
		0x021C9FA75D9A5823ULL,
		0xAA9631E22EB0C066ULL,
		0x136DB50EB1C9ED3CULL,
		0x143A98C7B67926FBULL,
		0x42A966AA5E3B2B28ULL,
		0xB0EA4D6994C7F3BDULL,
		0x8585995542D6234CULL,
		0x4EB5193566080811ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x962FB792C70603DAULL,
		0x06E2C015B54CFD83ULL,
		0xF0D39C2E83487973ULL,
		0xBF6C592DF317A6ABULL,
		0x337D679D045A2CD1ULL,
		0x38C703D2A57DBD47ULL,
		0xF2793F93813ED20FULL,
		0x5B06A0BE2D4ABC38ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAC74C40FEDFA14D4ULL,
		0x78F05E33FE67D868ULL,
		0xF66F6BA2EAF782E9ULL,
		0x00B4214C2F7AC274ULL,
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
		0xB5F67B43F512BA80ULL,
		0x918D473E2D0C20C7ULL,
		0x1C1E36D7F5B27218ULL,
		0x5B66642C7087BD61ULL,
		0x110B1FC7E22640FBULL,
		0x3A4260467B203DB1ULL,
		0x1453AC52A4CF08E7ULL,
		0x25C5E137EE593B45ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x05D6EEB9E86A9827ULL,
		0xFF07F5705B569A80ULL,
		0x5A5BABDCA37272EEULL,
		0x7FA55367A4F058E6ULL,
		0xA317DAD6E4CFFE3CULL,
		0xE4E4B3BD2B54DAA7ULL,
		0x08828FA133408EFDULL,
		0xD3A6847094A20D9BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x023BC84FA77606D7ULL,
		0x3E6CEE2FA9E639AEULL,
		0x82CCCD522D6617CCULL,
		0x0C68D65C1CC82BB8ULL,
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
		0x776F65919F593470ULL,
		0xDBDC4A2011C75240ULL,
		0xB6177148DB64B6B2ULL,
		0x2B63A5653B0FFEFCULL,
		0xA57B8267F2E2B3C6ULL,
		0xE0CF618BC41F8DA4ULL,
		0x3AF935EDC9D31D28ULL,
		0xEC451AF240B4550EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC8EDEF2B2EDAF9B6ULL,
		0x70FD11A427D29AB4ULL,
		0x7137984F901787E0ULL,
		0x015F15AC88DA40CAULL,
		0xF3C5CDE310D12D64ULL,
		0xB188291341F83902ULL,
		0x48B622F616F5670EULL,
		0x35840B0F2C01D89EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0F7A421FFF183148ULL,
		0x6F719A5F3BCB478CULL,
		0x3AD4A9BDD83636B5ULL,
		0x4AACEB6DC4B436D0ULL,
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
		0x49E8238F2FE08BA6ULL,
		0x57127742548A7A56ULL,
		0x27B962C25AC188F5ULL,
		0x951C3DA301EE3052ULL,
		0x225EB43BAA09762CULL,
		0x4B9319D6C9B13B5EULL,
		0x22869A7398E1C8F0ULL,
		0x2D67F6D1F4A89238ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x63EB457F928E25F3ULL,
		0x40141787EB00DA01ULL,
		0xCC9B5A754786F66DULL,
		0xDEC7A4226F4B7361ULL,
		0x24BB6484C84076C0ULL,
		0x67CCC3DC89CC5BE8ULL,
		0x4D7982A3EF7C2C35ULL,
		0xE2DD72CEB5424AC9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8C3AB33521284BA6ULL,
		0xE66F22DFE582CBD8ULL,
		0xFB0F9120384FD645ULL,
		0x46E431FBFBD15763ULL,
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
		0x07F4409DFBA8BFC2ULL,
		0x3A12D1007F937992ULL,
		0x15240818CD036A50ULL,
		0xD60842A8610A1391ULL,
		0xC174F6E8449E87C2ULL,
		0xA0BA62DA4EF74F93ULL,
		0xBC9416A33C42BE34ULL,
		0x257FD794FE54FDE7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC37CD6D99AE9464EULL,
		0x4241544F2E0CABF3ULL,
		0xF576291FF6F062B8ULL,
		0xB0712CAA7E722E4AULL,
		0xA649DC75B1993088ULL,
		0x8D0088EA5ADAAA06ULL,
		0x3336763707AC0009ULL,
		0xF4C13299BD82C009ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4CDD56C6338A6776ULL,
		0xE567D64F8DC76090ULL,
		0x8393AF08A47341FCULL,
		0x61E3934981CD144EULL,
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
		0x3CB89243572B0701ULL,
		0xE909E34BF8E55C0DULL,
		0x6161EA16650F9A3EULL,
		0x340AAE12AF36CA36ULL,
		0x012ADD272311A1C9ULL,
		0x61069724AFBF6579ULL,
		0x52E2326E8201C5A2ULL,
		0x309362FCF8D526C0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8B301AF9E3B56DC5ULL,
		0x67BC2649D0B20186ULL,
		0x414CF173BF4253CAULL,
		0xE4CDC98914893529ULL,
		0xD30ECB4C465E0495ULL,
		0xCDE1912DC33485B0ULL,
		0x454A3DA39BAB8B7CULL,
		0xD49ECFA234B58127ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x89B31DC6361EEB2BULL,
		0x58CC9FA944D0923DULL,
		0x24A34EC0D699E808ULL,
		0x758AC402B76029C5ULL,
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
		0xFCBAC98A77A6126EULL,
		0xFB397732B5E9C7D0ULL,
		0xF4FFEFC0391A545AULL,
		0x802D774BC7467D99ULL,
		0xBCC4B9A9A1B02103ULL,
		0xE13018A12E1C0078ULL,
		0x75DC8F8EDEAB2D2FULL,
		0x84FA5FBA89B7B5B6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBA0F6A9475FA4A96ULL,
		0x22052B03F08B48AFULL,
		0xCB90ABCF67062674ULL,
		0x97C92A74C08D56AFULL,
		0x0BC0D3EC1967CD94ULL,
		0x7B2A87C3CDBB0AF6ULL,
		0x221D6C223CC3C787ULL,
		0x867AEBA77370E304ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x893F79183C682A3FULL,
		0xFE07CD0B13C2F087ULL,
		0x97CE8610DA6D44E5ULL,
		0x2F4F87AC553C6D62ULL,
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
		0x40E2D5D861DA99BBULL,
		0xF643D44803FEEB1DULL,
		0x8D406CB89FF0C4D2ULL,
		0x8F532BBC0B13F033ULL,
		0x42F1DD91CD281E90ULL,
		0xF728E5AD7751D254ULL,
		0xE40F63A8E62A1005ULL,
		0x6115228DB9A67818ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA9666F7068671744ULL,
		0xB5061E8086086F5DULL,
		0xF9A2AAF189E41AB1ULL,
		0x918358ABD5E1491AULL,
		0xA485C3151C4AE0BEULL,
		0xA0AE1C7969A6A164ULL,
		0x57A8565475B58B1FULL,
		0xE74F42092130B59BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1B8854EA3A4AACABULL,
		0x17779381855FBF51ULL,
		0x6AE9BC4FC7586452ULL,
		0x112F26BED6AD85BBULL,
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
		0x0529DACC28636945ULL,
		0x6EF0DB266D909BD5ULL,
		0xFC94FFE52F651B49ULL,
		0x0ED27E4D314FE21DULL,
		0x8FA1E1C6675F4287ULL,
		0x8B898A8E190F8C0CULL,
		0x184FE2FD1C5849ECULL,
		0x0BA689D46A927960ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5B164BDB8EA4B0C1ULL,
		0x5ADB62030CDFACBBULL,
		0xD451F9364EDF20BAULL,
		0xF240E99EB8893D47ULL,
		0x5AC6D3CCE3CC6D45ULL,
		0xC4CBA102A8728DC8ULL,
		0xA329FA2B18800DB2ULL,
		0x7BE8BB6F40A02043ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8297A1FA218A5DA4ULL,
		0x944623D617FEAD39ULL,
		0x8BE395DB729EEB22ULL,
		0x72BE37B2B2BFDF0FULL,
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
		0xDB24AB5AB1B541A1ULL,
		0xAF37B49563D2B1C0ULL,
		0x8D9883441E904A44ULL,
		0x82688A46537FB8B4ULL,
		0x51837244057576F9ULL,
		0x8C4AEC6EAC4C07E7ULL,
		0x83738623BC3635A3ULL,
		0xCE7BD8DE12985979ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAC3AC204C4227B0CULL,
		0x1C51E7D8856717ECULL,
		0xCE6967D632980839ULL,
		0x53A1C11803C47884ULL,
		0x6B20D83CE6D653F0ULL,
		0x3C97E97121EF8501ULL,
		0xD1349494B12A1BE0ULL,
		0x1F6791211708FB0CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x618CC6647931FDC7ULL,
		0x67783E5F682707F4ULL,
		0x3486F6A98FC41509ULL,
		0x2BC96F3BA7034452ULL,
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
		0xCBCA45583587755FULL,
		0xF28B8691F3C4D5E7ULL,
		0x8E29F0BD6A08869AULL,
		0x86BFC5765B2383CDULL,
		0xDD4177D970A4979CULL,
		0xF876C493C95BB707ULL,
		0x1DDC7792A41F77EBULL,
		0x7C44AE4B07884FCAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x74CC1732FF3D947EULL,
		0x5925385FF1965352ULL,
		0x5543F72CD529EF68ULL,
		0x1CF613C172E890AAULL,
		0xE6695F9B27364581ULL,
		0x17090C7A622993D6ULL,
		0xB7A42319597E03B4ULL,
		0xAE7FBA7C4DD01F41ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFB11C7641CAA0FC6ULL,
		0x0FAFA1F7539FBBD9ULL,
		0x65428391A8D5D77EULL,
		0x7505E26479922762ULL,
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
		0x357ED5FB4DCFF1F6ULL,
		0x5C5233228DAE2639ULL,
		0xC624DDDAD5725A46ULL,
		0x3E520DF4B2631E5BULL,
		0x5FE07A8ADCFA70E9ULL,
		0xC6B9855BF27A6D23ULL,
		0xFF8B8BA5A96D2E58ULL,
		0x14806B14295A6563ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE3ABB04A746FF14FULL,
		0xE0C9397C0224EBE5ULL,
		0x3DD526263ACA9B04ULL,
		0x667E86F383D440DBULL,
		0x96DB7DF011D3517CULL,
		0x8C1B2CDC214EA676ULL,
		0xBC1224DFBB1B0A43ULL,
		0x0A26AE1A86D72F72ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2890A4AB012EAAFBULL,
		0x2F0A1C9F9808B7F9ULL,
		0x8C54F915FAD91A68ULL,
		0x6125940F4E08DF50ULL,
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
		0xF13E5735D566DDE8ULL,
		0xDFDB9FAAF7740E51ULL,
		0xD33E3E2C43ABF32EULL,
		0x6CF5783AD66EA4C2ULL,
		0xFAAF3FFAA2DB6513ULL,
		0x21000CFCE048B44DULL,
		0x72D1D3035D380B99ULL,
		0x3723A9882947AB64ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4D6F19BE7DF4839BULL,
		0x6A6E051F2EAAB047ULL,
		0x30269B38251D35F2ULL,
		0x6AD73C2762FD9991ULL,
		0x19C201C06CA3FCE9ULL,
		0x539C87E77743B437ULL,
		0x9EEC3459C5F9C361ULL,
		0x61841E0814D19581ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x07067A1B63ABCF92ULL,
		0xF2335BB95F876170ULL,
		0x172D302091CD7584ULL,
		0x37CCF1167CF84ADDULL,
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
		0xE5DD172A353A0430ULL,
		0xD24E37791F77DDFEULL,
		0xCFF6EA52F9B9F20CULL,
		0xD4DD8FEEAEF4B4FDULL,
		0x7F25B40AF1BB59D4ULL,
		0xF5FD470188536300ULL,
		0x7920D2FCCBB9BC61ULL,
		0xC0F203123F890F01ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x29544423BCDA0D69ULL,
		0x0A76558B76CE3909ULL,
		0x5D712898D950B02AULL,
		0xED48589CE9350063ULL,
		0xA59E5626FF767EB0ULL,
		0x51376E05E858536AULL,
		0x5B467AACC1D48769ULL,
		0xD2766F8173A6DFF6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x06A0C2DC6E987DADULL,
		0x3D36174767EDF534ULL,
		0xE0EEDD9B986F1ECBULL,
		0x4DED1ED00952B040ULL,
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
		0x79E15857B13DBB3DULL,
		0x9643A46EE5295FDDULL,
		0x220A31B3D66DFAFBULL,
		0xB6BFFEABA0D98531ULL,
		0xB089986239360C9AULL,
		0x0129D6C31E43149FULL,
		0xB20686089BC6EB76ULL,
		0xB47D0E5F4B60A71DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEA850A955C53DAE4ULL,
		0xB66BD36665DB1997ULL,
		0x711DF3B6A5D7507AULL,
		0xB8150F638959AB71ULL,
		0xE568F6D416C018ACULL,
		0xA347EF77BBF72E7AULL,
		0xBC511B3873329115ULL,
		0x6759C4A3989958F3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB63448DB726C174FULL,
		0xCF60263916926FBBULL,
		0x29DA18E3369C14CEULL,
		0x71E7E124A11573FAULL,
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
		0xB6466F23074425CDULL,
		0xF01E6D809B562099ULL,
		0x97770988E25C072EULL,
		0xBC6BCCDECD36263CULL,
		0xB63E5658CAC25037ULL,
		0xD982427D48F950DFULL,
		0x0459CBD3820C6E9DULL,
		0xF2E068ED173E005CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9110D26165A7106FULL,
		0xF875C4020AD639E6ULL,
		0x5BE176BD05B122D2ULL,
		0x688D504BA02773F7ULL,
		0x6ADF4D34BDB64663ULL,
		0x677DA7FA4B432568ULL,
		0xCFEA5ADE4BE841FAULL,
		0x87AA54168428CC13ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5550F81B91668D36ULL,
		0xE45798F0398A5A68ULL,
		0x04205731E609849EULL,
		0x3DE5946D023474FDULL,
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
		0x6CC41A271B7A1838ULL,
		0x0F8ABAED5309059BULL,
		0xECF8E7470400E2A8ULL,
		0x9CAC462F9AD27D6CULL,
		0x3BCC00F25522D12FULL,
		0xEB2A8F1390B95FF7ULL,
		0x26A8B39B5FA2D5F2ULL,
		0x039C924D4A660689ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB4E1B638802287EULL,
		0x2A5FF5A5A3377BC0ULL,
		0xF9D1CE97F4731D2BULL,
		0x4CF8E8BAE67E5597ULL,
		0x31F08D420E6714BCULL,
		0xC2BD0C46C2859F1FULL,
		0xE4C48921A75B08F1ULL,
		0x92224061A94E4F25ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x28092AEE1355E5AEULL,
		0xE56C2FAE4B8029ECULL,
		0xBB0566C06A3633A8ULL,
		0x27DB866E9DD96090ULL,
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
		0xE76E95A9E0E806DEULL,
		0xFAD2E1C545499EDCULL,
		0x72B3F7EF3B58B71BULL,
		0x59F3CAC64B99C44DULL,
		0x647188C1ADC0DD3AULL,
		0xB608B92E64F63857ULL,
		0xCF5723F058F9E740ULL,
		0x7EF62EAF8BDA618CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x56E70296D44FCF0FULL,
		0x59590CAC4D7BCCEEULL,
		0x86CA85387C3098BFULL,
		0x6A7B1074D1F07EC9ULL,
		0xCD889333FA1DECA4ULL,
		0xF42A55D7749BDD80ULL,
		0x83475081D200BD40ULL,
		0xDADA5C8644A4E875ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF71C061BB6C7EBFFULL,
		0x687C9400A5374DC8ULL,
		0x3642D51EC8245A53ULL,
		0x4B99EC720B993EF9ULL,
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
		0x488C758D2DDBF154ULL,
		0x1F03DED2F196EF33ULL,
		0x061286B067B0905AULL,
		0x3FD579E2838C6561ULL,
		0x073116E2CCB63C39ULL,
		0x4F95DA618CEBC773ULL,
		0x43B759DB579486BAULL,
		0xFCB79F38F9EFB6F6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5539F470D2351D97ULL,
		0x29E8BED81CB610A7ULL,
		0x798430C55AA89DD1ULL,
		0xC29349DE04134475ULL,
		0x78CCE6B1E86890ECULL,
		0xE3920F9805E1ADE3ULL,
		0xAE3F4C1EE2AC48E9ULL,
		0xAE99F24B3D4EDD3DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1631A85E3F2E42CDULL,
		0xFDAB39E4E060A9DBULL,
		0xBC605FE467811F78ULL,
		0x15A9DB4E7F597251ULL,
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
		0x192C9B3C2BA61644ULL,
		0xCB34EA64A78AD9BCULL,
		0xD5AA83C5FF787BA6ULL,
		0x93FB6B604068B3FAULL,
		0xE489023CA700D1C8ULL,
		0xCAF88D835CA9F6DAULL,
		0x29C292C921BB503FULL,
		0x8C7E692AB754D271ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD65D81C7AF6236B6ULL,
		0x70F6E4B5CCB3EB0FULL,
		0xF21AAED0DD4B6554ULL,
		0x15FB8E18A26EFCF2ULL,
		0xBE1764ED0D622F69ULL,
		0x95F3524896664762ULL,
		0xF623D8662BB8090DULL,
		0x10311E97A7F01BB0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF7AC734549CFFC67ULL,
		0x3904D06848E2FA81ULL,
		0x8D1F7FA5A6A9A7C6ULL,
		0x7178EF1BE6ECD78FULL,
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
		0x1573C98129D82191ULL,
		0x83AC4D052BF3F04AULL,
		0x5180CFBDFCC710A8ULL,
		0x587F9D5E58951334ULL,
		0xD0F9B03B301A3088ULL,
		0x609C14BDE2545C7DULL,
		0x5381838835084647ULL,
		0xB33E45EB641CD0CFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD33440EC5B992984ULL,
		0x8503ACEC86AE0322ULL,
		0xEB2D9ED12A70FD4BULL,
		0x000A738C4EEFB5DEULL,
		0xCB26B052DEC811BDULL,
		0xC8A496AE1919B22AULL,
		0xAD8F03FFDA54CCF7ULL,
		0xAE54E0D787A6BE02ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1F918510E06F8A55ULL,
		0x8D65567083FB357AULL,
		0x08521F2A48FA152DULL,
		0x131A2AC4C32C27B6ULL,
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
		0xBE254AB516B1BA7EULL,
		0xE35A8E3D17F462B0ULL,
		0xC2351A77A426E103ULL,
		0x46EB5C9D28F20C05ULL,
		0x84902DD3D4FA048FULL,
		0x77A77768BA494C9DULL,
		0x3363D2073BDD697EULL,
		0xB21B0152347E879AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x400F229E886B2436ULL,
		0xAB999FE30FE40B12ULL,
		0x5A2616FE44AA4B71ULL,
		0xE4495A22CB5D56B5ULL,
		0x4B0B983D67819A84ULL,
		0x84AEFE99C3430423ULL,
		0xD27AAB01F5DDCED9ULL,
		0x9270050C0C9AD9F8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x07C45C6ACE265482ULL,
		0x48A2DD12B2FF19C3ULL,
		0xCAAACE41C36D8A0EULL,
		0x160374E449607B44ULL,
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
		0x4B4FA0EF7A118020ULL,
		0x38C6A29FFE4120E8ULL,
		0xCC9E39158F3DA3FCULL,
		0xD93AC95F66CA4B41ULL,
		0x1FCD5B3CF97E7B4AULL,
		0xE25332C3F42C757EULL,
		0x012B1BAD068176DAULL,
		0x3406C3F98D014DEAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x707BA67E7A1744B3ULL,
		0x696B3877EB1FAB18ULL,
		0x94B92E294448CEE8ULL,
		0x96D681DC68C0D55DULL,
		0x1B264067FFCAFDA8ULL,
		0x9B535DF7921D72BFULL,
		0x26EEF843D8D7C916ULL,
		0x2F230C60F0DBC99EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8BA1F60E109EE18CULL,
		0x5955007EA15BDE2AULL,
		0x9CD24C891224A036ULL,
		0x7C31882A2B9B1926ULL,
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
		0x31B081558FACA54DULL,
		0xAAAFF3C2EC4FF8E7ULL,
		0x7B52B714BF4FEEACULL,
		0xBE0CDA43FBB2DFA3ULL,
		0xA54A0A87D64737BDULL,
		0x0CECB42952B6E437ULL,
		0x0B3BDBD24EE25D4EULL,
		0x835EEA59EFDDC21BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6172A2F770DD0BFFULL,
		0xE58A0EDD7D16832DULL,
		0x94C3F25D1FC240A8ULL,
		0x4DB561687A0B92A5ULL,
		0x80DEEBA876E15608ULL,
		0xD278E760170AE63CULL,
		0x8E4C24DD95C1D90DULL,
		0xF80A925F89D0E138ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3824738647EF17A6ULL,
		0x72564AC44AC12901ULL,
		0x7223ED0B1A614F8CULL,
		0x1EDC8806A790AE9CULL,
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
		0x39642717F49C2AFDULL,
		0x7C8B4F4496E023B7ULL,
		0x9E85C54478827DBAULL,
		0x39EF004122977A0FULL,
		0x55FD64C56D51866DULL,
		0xADF1700E2129E9A5ULL,
		0x08952CBB3A049EA1ULL,
		0x6E84737A6E4240A8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC02A1A23FB30191FULL,
		0x36EA9E113E58B240ULL,
		0x7A34ED001FB12D2DULL,
		0x018B3217AFF8248CULL,
		0xC2C0F8CE78FCAD43ULL,
		0x8565496BF44B090AULL,
		0xC6D66029E20CBE39ULL,
		0xD7CA5EA6EECDD002ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5432139C3E044BCDULL,
		0x4A6E6D46019CC868ULL,
		0xE6A335D7679CA003ULL,
		0x1802E58E5DE80E0AULL,
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
		0xEB9A64A6C9C0737AULL,
		0xFAA4FE06537708BEULL,
		0x0C1DBDDDFB85B496ULL,
		0x0FC0150E35210087ULL,
		0xBABC999AB8D9424CULL,
		0xF8BC82708B18B0BBULL,
		0xAD4CDCD66632049AULL,
		0xA2332899D7DE5538ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x41C690600DF4CD50ULL,
		0x22B8DCF3AF0C5228ULL,
		0xF6871C0FC90CF28BULL,
		0xA423DF0490EE6B39ULL,
		0xD2EDFCBCA3FA6916ULL,
		0xA809D9BF612A6806ULL,
		0x7DF62CCBF4B945D9ULL,
		0xE3F91B48C2DBCCC1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x127F1D3DD4DFE29FULL,
		0xD2712B5EDDC98171ULL,
		0x1C74C35B0A6512BDULL,
		0x283A3012C292D6FEULL,
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
		0xCCB25A445862230BULL,
		0xD81DAD79B874D3F8ULL,
		0x3372BB8D98969F07ULL,
		0xCA58C248D93CDDECULL,
		0x9C0B7C2E4BE05C90ULL,
		0xE8BE2BBC8EDC40EDULL,
		0xAB8815B77CB69F21ULL,
		0x8440BDAE35FC2E57ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3CF628A177339F85ULL,
		0x357CFD6F7B460141ULL,
		0x4FE72F6194401BFDULL,
		0x4BA122836DD57FC9ULL,
		0x125B8276CBD6FA3CULL,
		0x3A0BA2FD710CC2D6ULL,
		0x6BA6BA23F17D07EBULL,
		0x5A8B33E6F24BE6C2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFFDB42DFE2931CF5ULL,
		0x9120FC68A9FB8A35ULL,
		0x5EFF2412AEE2F528ULL,
		0x2FAA13597791FE4AULL,
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
		0x9214F12F84108E3EULL,
		0xD087E6EBFD126C7FULL,
		0x84597D113C2E8DDAULL,
		0x4B63279773080AC0ULL,
		0x47FD28282562FFD6ULL,
		0xC1ACDB5C4BE49711ULL,
		0x791CA4CD62DF05A4ULL,
		0x06BC8E44DA4A262CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x42D89566B056373EULL,
		0x8D1FB06D530A392BULL,
		0x1DF2C3521EE1F6B0ULL,
		0x374103AF74D4F225ULL,
		0x499B40E4BF84636CULL,
		0xB41DC5BCFB7A552FULL,
		0x326E2D5C53C85D9EULL,
		0x7126F79F2CC8876BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x11C4AFC9F2C58C5CULL,
		0x46A56C2499CDFAE0ULL,
		0xE44C74875AA98810ULL,
		0x4856807FBF70A94BULL,
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
		0xD0CDC8574B4C8409ULL,
		0x8D4F6447251BA057ULL,
		0x1B36443B537F9F72ULL,
		0x24AD867A879C6942ULL,
		0x9E56074687FB14FAULL,
		0xABCC7A0B4AB54EDBULL,
		0x61D68FC61F1CFA00ULL,
		0x422CB0E41CC9AF70ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBC30BC13D0203597ULL,
		0xEC0963DEF2B15F9DULL,
		0x093E31184AAB78A6ULL,
		0x7F3197451425052BULL,
		0x61DB8227A8769078ULL,
		0x6C69BCA94CDB4AB8ULL,
		0x9AE7BC2CF1E8AD73ULL,
		0x38C80CD784215B1AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0ECCCED8A8D7F9E4ULL,
		0x09EE1CF3E0C6DDF5ULL,
		0x996B7BDFBE9783C3ULL,
		0x0A6C49141C73E8D2ULL,
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
		0x3F139649800A5ED1ULL,
		0xF630A4A74D51F3A2ULL,
		0x4333DB871BFDDAACULL,
		0xC24A618A8185CF7EULL,
		0x49DBDAB80F9480E4ULL,
		0x2084EB2850C40D0AULL,
		0x7BEB1868255B11B5ULL,
		0xBD0A3CEE677CE4F4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9A9479049B266E7BULL,
		0xB3A2E99B04B53E0CULL,
		0x5AA8F9FEFD9DD415ULL,
		0x72821E89AEA0EFA9ULL,
		0x70D165B111B67A27ULL,
		0x266E5DB74FB13E0BULL,
		0x7B5CB2B2386EBCCEULL,
		0xE7D08A066B8AB8A5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDC0C7C4E93D8EF6DULL,
		0x61E6B9D271676F69ULL,
		0xFDADFA894974A0E0ULL,
		0x7658D17038D7738EULL,
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
		0x34DFA2C4F4053CF0ULL,
		0x0CDDB549F3617CB2ULL,
		0x8015A1F9A4339D42ULL,
		0x4FD830E62A61E48FULL,
		0x1C16A3AD426E2A1BULL,
		0x2A8F8FF307B61CF1ULL,
		0xDBD6387CA6A63104ULL,
		0x8D0B48FF8E8CD1C9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x80CE8FF6B9906763ULL,
		0x70BA78EB8B252295ULL,
		0x9C50E7945406ED43ULL,
		0x77DDF9CD1AB4FD6BULL,
		0x48142EF59A659BCDULL,
		0xF107D530FAE48B86ULL,
		0x16B769C04175E568ULL,
		0x6B4105873BB03241ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2C6E66112BB9F5CCULL,
		0x2648F52C4F57EFF8ULL,
		0x26576A5C5557E909ULL,
		0x5C003AF55C6C9571ULL,
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
		0x416E2AE8AE03C09EULL,
		0x892412C8C9B09A5FULL,
		0x63CCF222AB4736BFULL,
		0xAD6C770C30174AD5ULL,
		0x501CCDB61833594AULL,
		0x2E7D05A44714EC92ULL,
		0x2AA17DE44F85E63FULL,
		0xCC29DB328CBBFF9CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7FC13C0E3D4B9DB8ULL,
		0x86FB53C695CE8C86ULL,
		0x2FDB8ACC4FC8F123ULL,
		0x3F67CA8AEDD1789CULL,
		0x3D34A699D468E736ULL,
		0xB390517AFAA9F6C8ULL,
		0xD95DBF950AF760D8ULL,
		0x6A3A3E8E5A54BC87ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9022BD0C80C51405ULL,
		0x414B7D238BC289D7ULL,
		0x43FFA71A88A612D2ULL,
		0x7795ECE0BD99C73DULL,
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
		0xF184062FA8CAE79CULL,
		0x39F609247CD9CFE9ULL,
		0xE8FF7A026EA2B779ULL,
		0xED4C1284003B7768ULL,
		0xAD43ABAC6448C810ULL,
		0x5540A5E5872E3EB5ULL,
		0xB9E2AC565EB2D1E8ULL,
		0xA8F7BB5DB8F97C5CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x261879D1702A9CA8ULL,
		0x52CDF166A3EC519BULL,
		0x825446DE97E680FFULL,
		0x24A2C2F44FD00E85ULL,
		0x4CCD6CF2C3C04136ULL,
		0xEAF2689A5F8A4151ULL,
		0xA28EC05EAF72A881ULL,
		0xFB0962DA4B2E6428ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1CF8DBEC0CE44D9BULL,
		0xAEC530E5BB451B35ULL,
		0xDD2039E7DA425BADULL,
		0x1A0A7311FC91009EULL,
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
		0x3740CF7A6103114DULL,
		0xD3308A2979808694ULL,
		0xBB3A92F57FA64D2AULL,
		0x09ACE2BF19D8DD6FULL,
		0x4B0F90DE1137FCFCULL,
		0xADB0AEC3CFCEBB40ULL,
		0xBF759D814EB896B5ULL,
		0x894C356660126119ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4B1D8764D039818CULL,
		0x343F30F626BC286EULL,
		0xAEC6562B406D475FULL,
		0xD7361F8B9F927F56ULL,
		0x9125A8B2978BD35AULL,
		0xB2EEC3718E2DF8E4ULL,
		0x4C2A1374E84D3CBEULL,
		0x184D7216A9A292FEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x84DBBE89A057C01AULL,
		0xD7BA476910A137C3ULL,
		0x29AABAA173286074ULL,
		0x7847C1088EDEF62CULL,
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
		0xB291BB8D15E130A8ULL,
		0x43A7B7DDABA6189AULL,
		0xB65206B5F21397DFULL,
		0xC749F88D2FCC100AULL,
		0x558D57AB3E318085ULL,
		0x58EA27516909A55EULL,
		0xBE08D509FE434018ULL,
		0x41EFCF2FE5B894EAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x71F7CBAC73D3ABA7ULL,
		0xE85E72A05F42F138ULL,
		0xE492B77CE163CBABULL,
		0x19E612BBA1A33BA0ULL,
		0xF20FBFEA5A856FEDULL,
		0xD54A8E197C9ADB5EULL,
		0x05092CBAD0A49289ULL,
		0xFF4F66F50568F68BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x053E76826D97F77CULL,
		0xE4FA038A64D5234BULL,
		0x47B24AF9D63D8F5AULL,
		0x11335E8ED9FA569FULL,
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
		0xE7EA0983D85890CAULL,
		0x4A7EAD537AE4F8E9ULL,
		0x1AEF7FD5B93C5349ULL,
		0x8AE809595E8438C8ULL,
		0x0989BD1B253675F3ULL,
		0xFC88B6EF37BFA1A5ULL,
		0xF487739B1438584FULL,
		0xE3C5268C372BCF85ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x64C698D61E6E006AULL,
		0x43BFDDEDE91AA76EULL,
		0x79E9F1EEB8FD3A15ULL,
		0x0444E5A71D4E2E0DULL,
		0x84D81DF1BC55EE4BULL,
		0xD453EAFCB928A86FULL,
		0x46FB9371BFB1C4E5ULL,
		0x07B95D1141680375ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x358110D34B3EB836ULL,
		0xFE9515645C334F6DULL,
		0x63C8D4098C38FAF5ULL,
		0x30630BF2BC465534ULL,
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
		0xDDA450F42EF4E7F0ULL,
		0xA2E6EBB1C51180B8ULL,
		0xB1FCFA8DAD3C873AULL,
		0x695F24D697D07554ULL,
		0x5D98422610391713ULL,
		0xE4E843684AA910CFULL,
		0x5921B501DC02768FULL,
		0xE88BD1FAAE2DE2B6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9D14A9609EB26B87ULL,
		0xE2897DB6D55AE04BULL,
		0x2629D53ED62FEF4BULL,
		0xD692603A770ACF25ULL,
		0xD08C6D5E3B0AA971ULL,
		0x262007B44408A534ULL,
		0xDF17B25686E3F96FULL,
		0x19F64CA6DA46EBFDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x30513D3D3526C6E9ULL,
		0x12164AB3EB86995EULL,
		0xA94F8ABD79932ACBULL,
		0x3CFE8F0D950E4591ULL,
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
		0xC626C55F60F6560FULL,
		0x3E59017E7D95C823ULL,
		0x4EAE7BDBF86AE32CULL,
		0xF0CA9CE48F8DFD21ULL,
		0xAE72D9111C7237C1ULL,
		0x927C2AFFCBE5E58EULL,
		0x6E44FA6AE6B6E464ULL,
		0x3BB9E3D2487CAE57ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8BBAECAF2D6E8ACCULL,
		0xFB175E994DEB0587ULL,
		0x131C9393A36A8985ULL,
		0x2E4D6412A61DD389ULL,
		0x5B612F7A7A891C35ULL,
		0x274D5DA170147DFDULL,
		0x8198505F27870943ULL,
		0x7DB6EF1C3E7EC6EDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8F0B050C3C21E0A2ULL,
		0x2C341EE6D0C0222EULL,
		0x5D332606B61AE09CULL,
		0x76ED8BD765208351ULL,
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
		0xBD84ADC0C75EE0A5ULL,
		0x6D21C92BF5E550FFULL,
		0x0DA2A0EA23970C04ULL,
		0xA6BB8872242C0CFEULL,
		0xF8A9AA77FD7F5C06ULL,
		0xF83D49E8BF203521ULL,
		0xA9D572DCEAB71494ULL,
		0xF1621BD9ADBD45ABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0C83B23D4E4857A5ULL,
		0xF374454292367DE8ULL,
		0xD1E2B47DCED542DCULL,
		0x38E545A5457E7421ULL,
		0x5F160D9C09478E2DULL,
		0x5F335D8818B324E8ULL,
		0xA39F231EEB5BD31EULL,
		0x21853D334DBFB3E2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7CEA4429B95F1BD0ULL,
		0x31269A4217DF3BA4ULL,
		0x27CFC2A03C4D80C2ULL,
		0x489F4F7F1E513CB3ULL,
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
		0xADE745BA5FC88551ULL,
		0x7C21AF6C775CB0DAULL,
		0xE34EBA78426C767EULL,
		0xCF1270044AE089D2ULL,
		0xE56BB6C876F1757CULL,
		0xCDF4BB4EB3B726E9ULL,
		0x7948DC430F0CDD01ULL,
		0xEB3DB0B8F3A9D09BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x885075E42DC47A71ULL,
		0x61EF4B554C4ACD05ULL,
		0xD2257E685C508AA4ULL,
		0x53188E073AD78BC9ULL,
		0x28D21D31FC11BA0DULL,
		0x6E4F2E97C192D975ULL,
		0x028E42F4482DFE7EULL,
		0x1F6B96FFB161D6A5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x24639C2C6F39E1E1ULL,
		0x4CC5473F1C756329ULL,
		0xB0DBFDC16B30F35AULL,
		0x3D29B37CE6B8189EULL,
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
		0x56D972512C8324C4ULL,
		0x7EF9EDD14F1BE008ULL,
		0x4F4661574EB2078BULL,
		0x8B9B42E2004333FBULL,
		0x56750DB2C865CBAFULL,
		0xB867B31970BFAF78ULL,
		0xCB40781F007F334CULL,
		0x34BE235D12E8B434ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8BE1190358725BDEULL,
		0xAD4F2F1D85B6A0A4ULL,
		0x6359164BBB711282ULL,
		0x7C23C99D881605E6ULL,
		0xC9FFFA0A4F7EA0B7ULL,
		0x0AC2D2C55AC85CBDULL,
		0xD691AAC990435244ULL,
		0xC366692B9E542BB5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA459444FC6612685ULL,
		0x98240B2F0C1B8714ULL,
		0x3DDFC5BA3C245C52ULL,
		0x627D1C9BC63970EDULL,
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
		0x253AAD6D728880D2ULL,
		0xAD7207615F270D47ULL,
		0x31CF41F8ECC044ABULL,
		0xEBFA0917A108A7A7ULL,
		0x721E548EB78F0B34ULL,
		0xBA9631FBE5D0F372ULL,
		0x618BFF911A7F4E58ULL,
		0x56588C4CBBEE6B58ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE49E471FF995C5B9ULL,
		0x49A69CAA68C86FF8ULL,
		0xCA4C348B6FE910FBULL,
		0x7C59AB2FFF6D6CA4ULL,
		0x41BA1ADC360F3C7CULL,
		0x6A9184D509877301ULL,
		0xF07867B377E69FEAULL,
		0xC5EFE209C2CFD084ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6F7CF6CCB1EB67F6ULL,
		0x447D1E7BA947AE1BULL,
		0x306B98539F811810ULL,
		0x5F29A3D89C263665ULL,
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
		0x8A224876EE96D36DULL,
		0xF8AD5EC3D663D4E8ULL,
		0x9E300A634AEDC681ULL,
		0x71BAC18CD7ADE053ULL,
		0x07968990EF0A9D32ULL,
		0xDF28096C541C3EFCULL,
		0x305A32882A7AB11BULL,
		0x7828FCD1A6369EDDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3E8951174C61777EULL,
		0xAF2CB145C930B8C5ULL,
		0x9BBD6FE9C26A40D4ULL,
		0xFBC87787872E3360ULL,
		0x824E8049F576432AULL,
		0x385400F907C92F04ULL,
		0x075AD74CC96D725BULL,
		0x2BE71A14BCA0614EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x144A57E8AE3ABAAEULL,
		0x0CF9EE9B61877AE1ULL,
		0x185A2549F07AD646ULL,
		0x47B9F20FFCCCD033ULL,
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
		0xC8DEA265FE80E8FAULL,
		0x341643AD8C9929C6ULL,
		0xFDE761567A64EBF2ULL,
		0x9DFD979BE5AAB769ULL,
		0xC50FB8D58044D6ECULL,
		0xE6693CB0792E34B5ULL,
		0x5DEFF0F11A60D4B6ULL,
		0xE6A7D2025C5A0E2AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3004E7FBF4D8DB58ULL,
		0xB380E0CFC81F686CULL,
		0x72668D18D54F5344ULL,
		0xE826975CEDB0F5E5ULL,
		0x86CF5A6370BB14C7ULL,
		0xA328CF69EB349E6AULL,
		0x11B7D1C78BB1C95EULL,
		0x8D1FBCB96C8BE0FAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD667BF58581AE10EULL,
		0x7C259B56D7861085ULL,
		0xDBD57468D31147C7ULL,
		0x000A2912909476AFULL,
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
		0xD8A215663398B421ULL,
		0x449B0F7D9FDCB970ULL,
		0x51279836952DE91BULL,
		0xCAA63E68C4964EFEULL,
		0x14BB90A963B90921ULL,
		0x81BFAA26FE2627C6ULL,
		0x429D7E4839B4B12EULL,
		0x59997EE3580678CBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x478ACE123C8C04B1ULL,
		0x58D36F5844B29587ULL,
		0xD58721F21AE22314ULL,
		0x3D5004B633825A43ULL,
		0x143B5E3759E062BFULL,
		0x96C0B965116C0035ULL,
		0x379598F38A49F4FBULL,
		0xDCC1AC8D0A5626E4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA41EC4416D355F2AULL,
		0xCD9F5CEE7ECC036FULL,
		0x1ECC80D68423B595ULL,
		0x155F728219401D06ULL,
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
		0x7015640B76C709C0ULL,
		0x5347408E0D507902ULL,
		0xDB483C5586A98F15ULL,
		0x4FCA4FE7E4891147ULL,
		0x45203D9BD8208500ULL,
		0xF8C3299B1BAA13A8ULL,
		0x25350516ADA7CB6FULL,
		0xBE5A7FE6A3B4A351ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x859C68118389C1B6ULL,
		0x107E8170CE9C5150ULL,
		0x2C65BA24A18EB696ULL,
		0xE5377710811D1437ULL,
		0x58D3C32E53EBA520ULL,
		0x37BDC095BF5E2842ULL,
		0xC0D29E2DE9CD4AC0ULL,
		0x67E5D41CA5D3D5A6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFDD3283B93168512ULL,
		0xE99655E8F1F918D2ULL,
		0x957DC8BDF789F295ULL,
		0x3FE458D312CA845BULL,
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
		0x6E3D0583135179E3ULL,
		0x11C390E58890B627ULL,
		0x5D9B2535FD3D3E89ULL,
		0x7A1D0C462636CC55ULL,
		0xCEE6179066F36067ULL,
		0x1CE74A6AD4E89D05ULL,
		0xC124C3657AFF2481ULL,
		0x1BF5166B86306A1DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC07B4C7BAE9D3EAAULL,
		0xAA570EBDF729BB11ULL,
		0x3186D9F731A00112ULL,
		0xD528F23D3787B5A8ULL,
		0x7135A3C597BCA625ULL,
		0xC13F8A4689A9A0F0ULL,
		0x6D4AD79C0D066981ULL,
		0x5B434AB9EEC4C4C9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x95F2E92226D3DF89ULL,
		0x0253078ABCC06641ULL,
		0x9E6D4B251E88FF5EULL,
		0x3F58566568A9A131ULL,
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
		0xD2D955B64FFE6740ULL,
		0x765C5FBEFB0C2EF3ULL,
		0x9F4FE7956146C168ULL,
		0x2ADCECDF03919D3DULL,
		0x0A4058C311F42A73ULL,
		0xCD92B764205C45C7ULL,
		0x007A146C123C88CAULL,
		0x2F8D475DA23BB5E5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA9DB2A30A11585B8ULL,
		0x9046E545691307F5ULL,
		0x78D467A7B100DE09ULL,
		0x3A9A3C331327B36FULL,
		0x8D8C6272D501EA3DULL,
		0x1E3C4E8DF5E1FF91ULL,
		0x47C69F5F244F1336ULL,
		0x4F3E2094913A4885ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xABB4BB6EBADE68CEULL,
		0xECE90A43E01F92EEULL,
		0x911EDFD901855770ULL,
		0x3C02728476A02603ULL,
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
		0xE5973DD4936342B3ULL,
		0x37D9F0C97F45DF4DULL,
		0x167D9780FCEF223AULL,
		0x12D7CA15F877036DULL,
		0x0D1994AD240368AAULL,
		0xBE4B2181891D5BFEULL,
		0x0009A6C4BBE2AEFBULL,
		0xE31B8EE1904CF636ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4D039B18361EB2BBULL,
		0x0492F55889329FC3ULL,
		0x176DE25EBDE5C424ULL,
		0x3784F269F1880B64ULL,
		0x1ECEE1D84AF5140BULL,
		0xAB408F9EAEAC5B1FULL,
		0xEFCC898FF8B39357ULL,
		0x3E93856EFD3214A2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF7AA2E5495652322ULL,
		0x06D8A31D62D960A1ULL,
		0x68220AF738077871ULL,
		0x47843EADDCEC73DDULL,
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
		0x2C8F1CC4639FF193ULL,
		0x1CB993969A453ED3ULL,
		0x2B8C7C9AE8DEA72AULL,
		0xAB73040A7CE383CDULL,
		0xFD81F0A2196BD637ULL,
		0x0A2F3D18DE831C1DULL,
		0x1DB7993C149C3769ULL,
		0x29546D684E94087AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEE41E13C48F3A79BULL,
		0xD99999A794BCD402ULL,
		0xA9F8A77538093800ULL,
		0x15709D1B8A5338DBULL,
		0x1BE58A9571B1FA77ULL,
		0x89198C6E4323CF15ULL,
		0x96F76AFE6A0FBD5DULL,
		0x60EE1D78AEF90885ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBB8461690042E748ULL,
		0x6C58334215ADDA21ULL,
		0x821AB24D01AF8CDEULL,
		0x55324480A392493DULL,
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
		0xF337E785E1BEE857ULL,
		0xBCE6418B9103178FULL,
		0xE7803F6396F6F5AFULL,
		0x83715E1DBF134AB8ULL,
		0x66A5A0F50BDB7EA1ULL,
		0xCBDB53D151D02C68ULL,
		0x4242F831D9DF3097ULL,
		0x0D01B428D4091F0AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x31F46D98B1B6DA7EULL,
		0xB8B05FF5F91DCDECULL,
		0x612F0001D5F4BFAFULL,
		0x981A6B7B11E606F4ULL,
		0x7E55DA7780E9446AULL,
		0x4DAB41A556D9C677ULL,
		0xE8AF5C5520869957ULL,
		0x5AC40CF6619DD291ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3D1AF08FCFFCB03BULL,
		0xBF58941CD8786B66ULL,
		0xD23A62254428A992ULL,
		0x607DC41FA91A9DA1ULL,
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
		0x40E3E25A4B2A2B1FULL,
		0x7AF7161B3569E2D1ULL,
		0x921C63F442346A97ULL,
		0x86BF58A0B4C4A503ULL,
		0xDA2760AAB9AA83FFULL,
		0xE543A0ED7F09484CULL,
		0x09624B9EA8D8DE99ULL,
		0x27856CBC7E2A87C3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x43A856C6438BA7E3ULL,
		0x26C495427BFE0196ULL,
		0xB2764A0571784EF0ULL,
		0xB229F46ECA120AC3ULL,
		0xA345F9048ABBCB43ULL,
		0x6A001C6523628369ULL,
		0xFDD75FE3A1BCEE88ULL,
		0x981B4DF7C18CE94FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x22B0EE3EFF0DEC9EULL,
		0xA0382D16542D1AF5ULL,
		0x964517B1DEE1BE3FULL,
		0x1E55F565EA181F53ULL,
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
		0xF9B27EAD88436FA4ULL,
		0xBA4AFCA9FA2DD7D5ULL,
		0xEF31E62B717767B6ULL,
		0xD520D2942B914E55ULL,
		0x4BB01D10491CF760ULL,
		0x70249BEF44FDB8F0ULL,
		0xF9C508826D6F8BFFULL,
		0xB9BD2BAF29C6629FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0063FADEA9D56FFBULL,
		0xB3A2F41DFC5EFC1CULL,
		0x5AC9A8C054FF2E94ULL,
		0x9D149CE16B320F80ULL,
		0xE03C44E677C09DCAULL,
		0xEF5C790984AE6461ULL,
		0xF3D062AFEDDBF70BULL,
		0xC71E2E7C060EAA23ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEC809A03F2234BA1ULL,
		0x245D36A6899568DDULL,
		0x76B8DAAA0C605547ULL,
		0x3BA5CB4A0DA4A13EULL,
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
		0x05A5BD1B921C088FULL,
		0xA0E97AE6F6C3E7A0ULL,
		0x84B7B5F77A2F8F83ULL,
		0x85E322AB0404447EULL,
		0x1A4B573D36D83011ULL,
		0xAC6B0D9E2A3FCA62ULL,
		0xD9E6E78DE736005BULL,
		0x9033F0DA59C8C063ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2EA0B08947C39441ULL,
		0xB162983853839AECULL,
		0x09E1D51F1E57D369ULL,
		0x4E8AB91C1F0367CEULL,
		0xD3B3C362ABFFBB44ULL,
		0xE8A8B36D4A8DB5A1ULL,
		0x8466944118FC117BULL,
		0x801BE5AF4B7F127CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5184FF02E679CB1BULL,
		0xFE6045EFD7AF613EULL,
		0x2BE23E3EF8713150ULL,
		0x1AEA11F303F0AD07ULL,
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
		0x52E5A0B5D2B29283ULL,
		0x3704090E399B7B94ULL,
		0xAEFA172354A1F24DULL,
		0xC188D1B43557759DULL,
		0x2660EA7D346FA1E0ULL,
		0x5829961D0A1C1CC3ULL,
		0x6E63ACA9FEFA8F11ULL,
		0x7F0DF5E810EE6528ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x22E227B26613298AULL,
		0x3B47096695BE927EULL,
		0x214B7A170377E5ACULL,
		0x287CEB8974509171ULL,
		0x7585B92BD82EEC65ULL,
		0x661F981A0442F36AULL,
		0xCF0AF485F229F646ULL,
		0x3E439F444E5E3DA2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x708CCB171E3A5AB7ULL,
		0xE938B41A82190C40ULL,
		0x34D9F2663820BAC0ULL,
		0x3714C279A26CC202ULL,
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
		0x798AA174A4F36BE8ULL,
		0xE3C20947228448B2ULL,
		0x442590BA5EFB548CULL,
		0xB62750EE68B6B8C9ULL,
		0x1E4585FA517289E0ULL,
		0xC3F1C492BAEBA2A7ULL,
		0x1AF01F521B3294C9ULL,
		0x932436E5CF775B38ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB4E8C4140EEC073ULL,
		0x66BFCDE9284748FBULL,
		0x52F2A96388B9FD8FULL,
		0xAC73F9C678977559ULL,
		0x265A53ABC1B1AD49ULL,
		0x410D77F242A6C688ULL,
		0x8E9DDACDEDF1A9BAULL,
		0x6128BBE43B832A42ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8B258CDCBAA56AE9ULL,
		0xEAE59B2FD475AC4FULL,
		0xC56912F58DE43B4AULL,
		0x75079963E65E87E2ULL,
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
		0x743A392EE775E5F3ULL,
		0x44022514FBCA53B2ULL,
		0x2F116335FA9CEA1AULL,
		0x0B9780E1EC8A359CULL,
		0x5682DECEFAC51936ULL,
		0xC3CD193586FBD03FULL,
		0xDA1B2A8D21CE41B8ULL,
		0x643900D9DD223976ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4F27B235C5F6358EULL,
		0xD539A3F284DD2C37ULL,
		0x9F300900611F3F9AULL,
		0x8D02CD25E529F360ULL,
		0x44CC9D07DBCF16B7ULL,
		0x17EF080D44449666ULL,
		0xF637AC74660C6C9BULL,
		0xE3EA4F669065E4E6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC6204A87BA040C5AULL,
		0xF1BF0D1C5E1FBDB3ULL,
		0x63A611E178434CE6ULL,
		0x0A430AD96B54CF97ULL,
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
		0xBF364F814C800B03ULL,
		0x05FEF428CFF89393ULL,
		0x61E9027B5594D087ULL,
		0xFFDF6B6ED1FAAD4CULL,
		0x5DA2EBA19DD500EEULL,
		0xB5772C92231415F4ULL,
		0x64111921C1FA4837ULL,
		0x2D1BECD6D833C61AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2C0F23010B80A351ULL,
		0x3FDD63D49D6E948BULL,
		0x942E891A316A89B7ULL,
		0x0FCF4CCDE0EF3945ULL,
		0x2CC3C9C0A8D9185BULL,
		0x782CC10787758E93ULL,
		0x422C45283B856F17ULL,
		0x85EFBFD6E72DEDCDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD44633E49E63EBA9ULL,
		0xDF2D86E74C121775ULL,
		0xD5B1F06B19828198ULL,
		0x409ECC9EB7E98F79ULL,
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
		0x9405BA0539C40088ULL,
		0xCC40CA311A0165C8ULL,
		0x4B94471878A38D08ULL,
		0xDF3896EA2B3517ECULL,
		0x52BBE9B7B009521DULL,
		0x4412ED3C8A2A3AEEULL,
		0x4757975D4ED14962ULL,
		0xFFEB5F8D14CD52A7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x44206BCE4B63FCBFULL,
		0x09134A3EDDBC9300ULL,
		0xE6E433E58858F8E6ULL,
		0x61B51BEA93723C86ULL,
		0xA9D543795F820778ULL,
		0x857F97537E327AF8ULL,
		0x499053AD9FC5B36CULL,
		0x22D1639A51E9EA64ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6221FB76E2751D2DULL,
		0x0D0C408A030B513FULL,
		0x10441F46EC02D69DULL,
		0x4F5EE10885845557ULL,
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
		0x9ED1611A03D3379AULL,
		0xBBE294DD70AA4285ULL,
		0x2574AAF4E40D11BBULL,
		0x50D81850B05B7644ULL,
		0xF0F668444DC1A455ULL,
		0x7F2D31962519E051ULL,
		0xCA527B6529ADC435ULL,
		0x8C955D73CD28157EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x51152185DC4F3E9AULL,
		0x30C2BF2481A8E55DULL,
		0xE308EFB5BC29CD0FULL,
		0x301573BC2CF662CAULL,
		0xCE075FEF9E3FE963ULL,
		0xC4235C5BF78D08C7ULL,
		0x808B1CAF99E76E37ULL,
		0x029F4FF249528E7AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7D377C2634C5BBF7ULL,
		0x4E957C5BB1E95BA9ULL,
		0x3603CA327F540856ULL,
		0x1B48A5CE15171E1CULL,
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
		0xB85D951354468A77ULL,
		0x1BE3A15FB5EF742EULL,
		0xC128A16BF42E0377ULL,
		0x91A7619C1A65BA4FULL,
		0x91BCB09E50788CF7ULL,
		0x04FB47FA0E275520ULL,
		0x371FC33A9938C117ULL,
		0x69CBA4950DA9A0DEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA1A052BE39147029ULL,
		0xC9DDCCCBA08A12E3ULL,
		0xC49B74D141BD4D4BULL,
		0x547D47485DA037F5ULL,
		0xE8903EA92764DAFAULL,
		0x783B3A16849104FCULL,
		0x18151E5FC1A268DFULL,
		0xC131AFE6D34D50B0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x33562CB9341E83EEULL,
		0x3687E45A81B54696ULL,
		0x9821A516B2C1CE6AULL,
		0x44046C3066796932ULL,
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
		0x8A7B685815205645ULL,
		0xA8C3BC96469556E4ULL,
		0x6E60BA15DD58511FULL,
		0xFB4B1C889414D796ULL,
		0x840CB97B59D10330ULL,
		0x1860CF2AFFFE2D51ULL,
		0xA09EEBB8E86FBD68ULL,
		0x8C33D7C76DB5FB0AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA5FC319DEF9D8429ULL,
		0xFD8E3CB9BDEC986DULL,
		0x20F3ECB8210EBD37ULL,
		0x5CF9487E68500BD2ULL,
		0xD7A725F8AA3F21B0ULL,
		0x6090DEC8DC9BE063ULL,
		0xF6F5C06F59C05DBCULL,
		0x28DFBE011B57E2E5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7B931C20352A4D56ULL,
		0xF4132E6DC94029BEULL,
		0x7C893A48EA51C764ULL,
		0x5CCDA77A65BC6135ULL,
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
		0xC4538F6CEFE68BEDULL,
		0xFE80819A7C8EE330ULL,
		0x37F34C7ABC98A07AULL,
		0x5C1883860BBEBFEBULL,
		0x52BAC9F801D6E52BULL,
		0xCC4BDBE75BA980B2ULL,
		0x057F66B8CE2CFE2DULL,
		0x1D06AA69A03C981EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9001F1955BEC86F5ULL,
		0x59B4C450CA852FD9ULL,
		0x19602373BEE9DEB6ULL,
		0x641975D0AF581EE2ULL,
		0x17F7467E40A20CBCULL,
		0x376725221490C8A2ULL,
		0x580C81BC7265D5E1ULL,
		0x287B2726E3133729ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xED5721EA41D22526ULL,
		0xBEBEDE923FB505BFULL,
		0xDDA1267C9D3EBD22ULL,
		0x44B4899D708B055AULL,
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
		0x84469046F3D1CCE3ULL,
		0x40175AE0EA83D6D9ULL,
		0xF397E3E89416DCECULL,
		0xA4FCB4FF92AE3355ULL,
		0x425145B9A04F5C43ULL,
		0x565BAB48765BA483ULL,
		0x12307CE1C006AC73ULL,
		0xD7DEE4D67C9D849EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x528F541ED78369CCULL,
		0xA9C109E208AAA010ULL,
		0x7DF7AC19EE4B6191ULL,
		0x2DAAF590D2576140ULL,
		0x11E9F3B725ACACA4ULL,
		0x2167077C066F1A9AULL,
		0x2DA58BFB5A66E153ULL,
		0x083C165E0A876F1CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x610D68865074794BULL,
		0x72A6A1577EF5AF66ULL,
		0x623FFA01BB83A222ULL,
		0x497C654FAF9E035DULL,
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
		0xE5FCB31538748C1CULL,
		0x2A406965EB18A8ECULL,
		0x56C1964CC411DFC1ULL,
		0x958A1E6A8EBB7EC1ULL,
		0x7F9248289B7AFD03ULL,
		0xD3D9C0197DB810DDULL,
		0xF3A30FA1E70D4A01ULL,
		0x250DC77239188F17ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5BCCCE4E79D7769EULL,
		0x280CA46408757A62ULL,
		0x6E39052C02C82C33ULL,
		0x725A80FFA5289B6AULL,
		0x01F25B23DF4F4C22ULL,
		0xE3FBFB10A8D97354ULL,
		0xA3B8AF7EB1075C5CULL,
		0x4A7CD6C395021B3DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2FED137AAD195613ULL,
		0x9D1F04517BAE90F3ULL,
		0xC552D65AC62AFA09ULL,
		0x14B3575744E815BEULL,
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
		0x871ED97A042AF8DBULL,
		0x4F1B9A4C7529B890ULL,
		0xDB8BD392380224DAULL,
		0x368232ED6154731AULL,
		0xEFA0B50ABC96019CULL,
		0x230C170C010FCE13ULL,
		0x73921B20D6FB6EA2ULL,
		0x16A1596C8DFB60F4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2C62E3040FDDDE30ULL,
		0x701BD64B8D105970ULL,
		0x9EBC406556A617CFULL,
		0xCBDF002AA935FB17ULL,
		0xD9EE82B75F0F27CBULL,
		0xBF32AFCBFB973A42ULL,
		0x208BD997357E54C5ULL,
		0xD60D9F91CDF828B9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x932F6ED5D6516B63ULL,
		0xB1451781B7FF5029ULL,
		0x8FBD4D9AD9EDE3C1ULL,
		0x0090C93B3898D0D1ULL,
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
		0x3339257D14B916DCULL,
		0x09D2BA6E13ED2088ULL,
		0x68D3A8FF9940BAFCULL,
		0xAF1CE753158C7474ULL,
		0x5F447D07A6F435D0ULL,
		0x8BE890BFBDF5DE5FULL,
		0x714DD6F8E207EE56ULL,
		0xAC38078664917444ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x75AA3F46B3B940D6ULL,
		0xF1D5E06937B37AEEULL,
		0x42F99A6C6FDC0ADDULL,
		0xED98CFE4DB0B3BABULL,
		0x3E61E1CED1F92FA9ULL,
		0x5D12AECA12743924ULL,
		0x486291496C69B484ULL,
		0x46FD07065482F3ACULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9F31F0A5FE42C1F7ULL,
		0x0BBC647C51782C60ULL,
		0x38C6669E9EE14551ULL,
		0x48462A709CA84F5FULL,
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
		0xB4EAA6C534387569ULL,
		0xE1793B159F9E8851ULL,
		0x3B3A308106C637B5ULL,
		0xE08994A0DC038CADULL,
		0x8112B0EF4C7513BDULL,
		0xEA5BD364D27CC022ULL,
		0xFEDF9AF24B1B3DA9ULL,
		0x1741697CBF2FD12BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x64067FFB147845FBULL,
		0xC96677BC20DFF0C6ULL,
		0xAA3FD2F6B8EBB823ULL,
		0x06CB518AA8A3CE8DULL,
		0x8A8727E9395FD895ULL,
		0x2E6DB87920112CD3ULL,
		0x4B96776F045A3231ULL,
		0x0D9D9C07BDD02CF6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE99A7DB0F4E6F7AAULL,
		0xFD6AC255FAB67543ULL,
		0x2DD5A306CE82337DULL,
		0x480EC27467921E18ULL,
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
		0xD7809BCD4AA50F96ULL,
		0x1262023254C5EDA5ULL,
		0x561808C4C04B1D1FULL,
		0x395FC6C5980BAF60ULL,
		0x70F82EBEA1E7C201ULL,
		0x4176AF64A51DDD73ULL,
		0xF394423C1D580E59ULL,
		0x9580DEE01FFB3B29ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBAD55273493803E2ULL,
		0xD6D274FDADE4ECA7ULL,
		0x481276281EA9CD7DULL,
		0x621A7C841157702DULL,
		0x41210C59F7714E39ULL,
		0x64301A941D975665ULL,
		0x3C21552B91CACF0BULL,
		0x2FE7066F5C3F8F3DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x369A644B4F023D8BULL,
		0x1409A428C4D90D19ULL,
		0x4914C3115898B530ULL,
		0x6C1B6AFE948FC456ULL,
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
		0x51B734C22F49E71FULL,
		0x3BAA257F098EE4BCULL,
		0x59EB83C79C4A6A66ULL,
		0xA5B3A4B4D5D423E5ULL,
		0xFC2FEDE8A522B7F8ULL,
		0xBA9BB8DE2E219555ULL,
		0xB78146E54F94CC9BULL,
		0x2A47A32B87ECBB6FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9F5C5FE1F9C1317AULL,
		0xEBFC1331E5045AF9ULL,
		0xE091CAE2B7A9FBFEULL,
		0x065CAE394F3E6ED2ULL,
		0x1FBF2BD5B58A54AEULL,
		0x61FDBF9BA9359FC8ULL,
		0xCA09BF49694C25C0ULL,
		0xC9CD718B94CF8E7CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6B17A3AFC6276F24ULL,
		0x7721122CDF90FCD1ULL,
		0xB917DA09136932F6ULL,
		0x717A54399CEA6121ULL,
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
		0xB1C5928909582912ULL,
		0x6DEA4FCD111745D1ULL,
		0x584E2F25C384C85AULL,
		0xEEE1B130F6952CBEULL,
		0xFB4D45C4B7F56881ULL,
		0xDBE15793CFD01693ULL,
		0xCCDA52D8A4D3D2A6ULL,
		0xACA32BB99FFD708BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDC731BA0482E5E9EULL,
		0xD15084BC92C18D0BULL,
		0x02A6EA0ADE5AFD1BULL,
		0xB586B1A1175DFB02ULL,
		0xF22576527BB3FB10ULL,
		0x940626107D846005ULL,
		0x71C87B17D624426EULL,
		0x298493227E3F020DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x313B41DDB2E00C1FULL,
		0x4723248EB592D1DBULL,
		0xDA4D4BB993393399ULL,
		0x2FE5A5FEE17B987DULL,
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
		0x367DC29F9D688DDEULL,
		0x93A1A63E511052ACULL,
		0x0DCABCBB266B94BCULL,
		0x9F48B1E83C57B992ULL,
		0xBE847B56C0E1DB27ULL,
		0x86F580D37AA33F92ULL,
		0x54DAEA5A1E9CC5A0ULL,
		0xE81C575682F5E8A3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCBE6C7CE43C21399ULL,
		0xF09EB1F97DCC949FULL,
		0x5989C0057F90A523ULL,
		0xE5B8DBF5DF064A01ULL,
		0x20153F02F3DE58ABULL,
		0xAE69B1398B8E51B0ULL,
		0x514E958F04EB0895ULL,
		0x9184973BBA82CAE7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEF19EF41C82BDA88ULL,
		0xC7C3C51E505F0DAFULL,
		0x3B1592DB773CFF34ULL,
		0x141659EC1E67D979ULL,
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
		0x0DC53C490ED59D8FULL,
		0xC5B71DA966A57986ULL,
		0x6F39E5B2BB1C15C3ULL,
		0x6C19A808B9829338ULL,
		0x1DDB1E1CD2382283ULL,
		0xBE430F1E19492DF0ULL,
		0x7A9AED2660995860ULL,
		0x2E6093C94BF29B67ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF72C97490DB11358ULL,
		0x526A41D9DDF0F7D6ULL,
		0x0DC0F3728C72E0A4ULL,
		0xA2A17DDD2699C38BULL,
		0x30BB2442DAFF652BULL,
		0x90636D5B5753954BULL,
		0x55575EBACA989390ULL,
		0x0884006A8179AAFBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4957BB5AB390A605ULL,
		0x427EDEB853292A2AULL,
		0xE980163872C66C06ULL,
		0x68360A3DA0DC7FBAULL,
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
		0x1A0D0E0BDAE1D2DDULL,
		0x0517C5C96483244BULL,
		0xC5B5A4991FA0BC28ULL,
		0x52E4D941B440EDD5ULL,
		0x5BA2F4FED454C8D0ULL,
		0x6D1C88C1303BF5F9ULL,
		0x2735A537934C95E0ULL,
		0x7E3866C7AE75334CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE62F47DB7C81DBC4ULL,
		0x155F36D46BD325DBULL,
		0x40253E262878333CULL,
		0x762DC61CCFCB3FCCULL,
		0xA891EC2699475178ULL,
		0x9BD2B9FDFF6EFBDBULL,
		0xF3CF5503B7EC7475ULL,
		0xD4A90333FFFE5BA4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC8651649225FAC3BULL,
		0x00AD3FEE371D1ED7ULL,
		0x26C04E25876D7EC7ULL,
		0x07FFDB10CA19B0DBULL,
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
		0x8B762ED0A5D1FD20ULL,
		0x902FD294C4243CE2ULL,
		0x04120489A4C62AACULL,
		0x8FBDB4150C0A1502ULL,
		0xA749228BC190CC8EULL,
		0x7B6ACA1C270B20CEULL,
		0x555B0EF866E94E3BULL,
		0x43C7ABF47DEF0BE3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC3BE1F8FD36A5EDDULL,
		0xA74E516676DAF148ULL,
		0xBD8A6AA87350F637ULL,
		0xCC5A5398E2B6BA3BULL,
		0x1BF6D45F3F650E55ULL,
		0x48E079F11CDD61F1ULL,
		0x9111ADA15113B132ULL,
		0x56028BCA67F6AA09ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x75EFA9DC24E5DA47ULL,
		0x69696791D013A07CULL,
		0x696C0CCE6F2A83D2ULL,
		0x0EA626BB6C31E119ULL,
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
		0x731B86B11BE516BAULL,
		0x177C6A3927336D0FULL,
		0xE386FD829A3E838DULL,
		0x85A0ABB7DD9FEC20ULL,
		0x96673AE23B2DC69EULL,
		0x1D4E15C8F2ED0BB1ULL,
		0x9CBBBC823A534D68ULL,
		0xAF99C57E722C4EACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC1846A16C109548BULL,
		0xF0634AAA7B04FA4BULL,
		0x0D56EE5496F4240AULL,
		0x703DD19216B084E7ULL,
		0xD4252CB8273F849DULL,
		0x5C6410D99B1872EEULL,
		0x09568C83A8F698E9ULL,
		0x444A319B17D40A0FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x876536D9503990B5ULL,
		0xC9D5DB15B5BD1FACULL,
		0xB7352EF7970D2A52ULL,
		0x0332CDE53009969DULL,
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
		0xAC5375A655B037F8ULL,
		0xAF6B01B9AAF1143DULL,
		0x91FFFA7C8A1C244EULL,
		0xDCB32E33AE884E45ULL,
		0x8E8B0B492DAAD5CDULL,
		0xAC38CB323E24AC63ULL,
		0x44D1A71FBDB86931ULL,
		0x288EF18CF0C3F486ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB121DFAA38834403ULL,
		0xC2DCF085CB559404ULL,
		0x381F6DA6402D1034ULL,
		0xADB8FF3EBC387D85ULL,
		0x7CAA00EF324D4538ULL,
		0xAB6A8A3BCA919964ULL,
		0xDDD17F7A5139446FULL,
		0xD4881629E16BDD3FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA2991F576D10664AULL,
		0x0B2BB5C907705215ULL,
		0xA3E66F6464CE88E6ULL,
		0x27FEBFA939634533ULL,
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
		0x39E488DEAC5BE715ULL,
		0x46F3F40764FE115FULL,
		0xA13261AEF764F169ULL,
		0x44F949F309D2BCDCULL,
		0x4444862D96A3C1E6ULL,
		0x35C5503F595B6711ULL,
		0x2D37C5A9B923374EULL,
		0x3517EDEB1E95A0D8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x63E5AE295A6C2CBEULL,
		0xD0DFF9325D36D645ULL,
		0xE34977B913845FE3ULL,
		0xD8196644D6ED9CC1ULL,
		0x6754277BD155443AULL,
		0xBB2B869437A6367CULL,
		0x00CFB19D5516BCDAULL,
		0x0AE96EE72D3E85A5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA1ACE9189B9662B0ULL,
		0xA8E7EA3C08AC7132ULL,
		0x555BE3CCBDBABEA9ULL,
		0x2FC6BE4405D329B3ULL,
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
		0xAE0788BD94BB4EA8ULL,
		0x3EDD21024F4CE764ULL,
		0x006F5E5E1A00D9AEULL,
		0xE6895D8116124751ULL,
		0x37D3D4C9F03B7641ULL,
		0xF191CD3CBBC9B787ULL,
		0x5C20CCBDB774098EULL,
		0xD42BE073FDCE620AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC6CC0A73C8DB478DULL,
		0x6AF2A189D6C1F9FAULL,
		0xAE3719C809C33B9AULL,
		0x61411045C1B9A203ULL,
		0x30EDE0B06F76DBC6ULL,
		0x40E853805F39573BULL,
		0xA317458C388A419DULL,
		0xCD66FE7206EBE4FBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xED5DBA12E90EF596ULL,
		0x0D12916E35F938B2ULL,
		0xC9A255EEE6F14BF4ULL,
		0x0681D985F9F7357CULL,
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
		0x76AC23FE3063B26DULL,
		0x7077872C0FDF796EULL,
		0x4421181C7EB3E3A6ULL,
		0xFD88DA10CC143914ULL,
		0x6D4D7599A57EADDDULL,
		0xD718966C39CE7F14ULL,
		0xAD0B47777FAA4CCFULL,
		0xF2516AE18383D284ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC11DB57FDA9759A7ULL,
		0x08B6C56EF3CFEBF8ULL,
		0xEE0AC58A0F1F5CDCULL,
		0xEE44AC1DB3048638ULL,
		0xE1325175981A803CULL,
		0x9DD0A6453E75C88AULL,
		0x1505EC4DDA343196ULL,
		0x7D9E4D2E67459621ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8195CBD852AB2132ULL,
		0xE86E67866B3AA5E0ULL,
		0xE6E1DAC0FF1C9148ULL,
		0x61DA96894A4CA9A3ULL,
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
		0xFA096C4E80E0633CULL,
		0x32BBDA10CFF236A0ULL,
		0xD17E1C3A92BDD31CULL,
		0xED7A81CFE064607EULL,
		0xBBA3DD88E0DCAEC5ULL,
		0x0DE50A6E27755229ULL,
		0x1CD57433E47196EEULL,
		0xD04218ACFDDE0BA4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4EA00DD0477CFC8FULL,
		0x9125E3C9AA80B13AULL,
		0x2C8D49854681AB3FULL,
		0xC00607C883A9438DULL,
		0x36C52158F192973EULL,
		0xD284FCF11B63F556ULL,
		0xE442E1AA980BC40FULL,
		0x3179FBB79E135228ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x64794D9BBE62E834ULL,
		0x71D7F6D6F0054CCCULL,
		0x0AB29316A35974D9ULL,
		0x3F28C67394D2A53CULL,
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
		0x24F2A62555DC9D3FULL,
		0x14F3D6D2AC0DBD3EULL,
		0x1A7D72170386DFAEULL,
		0x5206FF4313490DEDULL,
		0x207951B5D4CA49BEULL,
		0xAFCC56B60A6B1A5FULL,
		0x1D83053D56E241C1ULL,
		0x7228C3480C7FD50BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5D4E590221DCD0E5ULL,
		0x1F9EAA07C8760FCCULL,
		0xA1310E796CAEF508ULL,
		0x2BD91273A3CDEF4FULL,
		0x804E7DA915BFAEC7ULL,
		0xBC3021D3F9E8B7CEULL,
		0xB968E19D162FE853ULL,
		0x92131D3CD35694C1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8DFFC7078F92CC46ULL,
		0x1E85065956F24EE9ULL,
		0x552DAD67315130F8ULL,
		0x69649279EB9AA982ULL,
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
		0x972D91CAFD0C192CULL,
		0xD33F484316620AC5ULL,
		0x3205EA9180F3C01EULL,
		0x2BD884BE2017E408ULL,
		0xF29CE0A3671AE8EDULL,
		0xAF295B239BFD249DULL,
		0x43502C21CA2C2BEFULL,
		0x4BD68CC277FDD5F8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD3C3ACABAB6D9C1CULL,
		0x900FB1377BBE990CULL,
		0xB0316BB08BECF64AULL,
		0x7BD86420B090B13FULL,
		0x2CBDE6E78D770D8AULL,
		0xF74D3771A350DAEFULL,
		0x6ACF1A4ECD3E2F88ULL,
		0x6933DAC754231218ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2282F7019FF10D04ULL,
		0x8DDCE376843661AAULL,
		0xA4FD2432805A4113ULL,
		0x54268BE4C2004602ULL,
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
		0xD865647EA6A40A61ULL,
		0xDDC04D6C3AD6DB75ULL,
		0x40F0045E1D9E0C2EULL,
		0xEE8B3E4CB97847C0ULL,
		0x27B254821685A44DULL,
		0xF659E85484040385ULL,
		0xAC47A62C359A140DULL,
		0xB4BA0A3199AD2D76ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x022F89A82B4DE14DULL,
		0xA5075009B30C6E9FULL,
		0xF6C34C16F35C73CBULL,
		0xF30F04529E046F7EULL,
		0xCB15FE1E96E8C9B4ULL,
		0x1E34520EAD9AC9C8ULL,
		0x40BE5A4EDC7C1477ULL,
		0xFA28C21E2FCA604BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x956AAD9B6C9E9A3BULL,
		0x4E4D4BC05B68FECCULL,
		0x408DFB2264B588C7ULL,
		0x2D0CECDBD31E4CB3ULL,
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
		0xDC8986F1A128015AULL,
		0xA615F386C4F57CC5ULL,
		0x7C4A4662598A3714ULL,
		0xEC7D16175FFB5178ULL,
		0x72EC56223393C820ULL,
		0x2C32A74588C5E28BULL,
		0x95457668DB1B537BULL,
		0xA63FCD682659F6BFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2BCADEAB19B86CDDULL,
		0x909B3FEE64405DFBULL,
		0x36485DB4B89C364FULL,
		0xAEF6BEEAA90589A2ULL,
		0x3443820B8BCB1268ULL,
		0x58BF8ECE8A63F9B4ULL,
		0xC6B3CB7CDCB3AE29ULL,
		0xAEA33D143F5038E8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFDCE23A36F3A8D94ULL,
		0x78905542233DAEBDULL,
		0xEFA147B564508AEAULL,
		0x7EC3C3A10267F5B8ULL,
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
		0x4A3E79365849D6B2ULL,
		0x34217E3D6847A22AULL,
		0x27AA417039AE3B7BULL,
		0x7907596B63006F12ULL,
		0x7830D74AE8090F21ULL,
		0xA7F5FEB6C37EE076ULL,
		0x705ED941470B6D65ULL,
		0x7BC31A93E866CF81ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA364DB594445C7F4ULL,
		0x3AF7C919482C9FFFULL,
		0xDDD5733D8FFA04D2ULL,
		0x3D35D498F973C623ULL,
		0x0CACF41E6965FDBEULL,
		0x13A83A5A30846C56ULL,
		0x24FC72331D190658ULL,
		0xC1DF109D8CCE56CDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9C6D5677E038A1E1ULL,
		0xFCB4DAE1F1483EFAULL,
		0x7A701A4CE3AF82ACULL,
		0x53AAFF64022E93B1ULL,
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
		0xE7EA27BAD043414FULL,
		0x4B5239FDB4BB0B0BULL,
		0xCEC8B7DF241913F3ULL,
		0xB9200A69306418A0ULL,
		0xAE08730FD86EDDA4ULL,
		0x4582F2E4EDD2E341ULL,
		0x6099EE4EB7C076D2ULL,
		0xF6F56B6B0ADDF348ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB69BE599DDB14366ULL,
		0x38E2AE71FDB5987DULL,
		0x5BDA802298538DCBULL,
		0x6A1DEDCCA7A0186AULL,
		0xBCB827803B43B04DULL,
		0x994C6E1E5638DF32ULL,
		0xE36038BFE9ECF0A0ULL,
		0xF2AED7CBF6CCF69DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0339797246FAB8E6ULL,
		0xA287410637E20CC6ULL,
		0x097F2AEF192B7187ULL,
		0x717C063983498185ULL,
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
		0xA3B44725997515E5ULL,
		0xCF219F80180BFAB0ULL,
		0x5132EA02BEB0BD1CULL,
		0xD7D219A68ADD855CULL,
		0xE609E64E38B5F4ECULL,
		0xD820D0A91D141CA5ULL,
		0x1DE53DCC8C1F576BULL,
		0x627C54325B9E5D09ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF1240499B92E231BULL,
		0x6355D70A5E8310C9ULL,
		0xB1F8FE9CB279B98EULL,
		0xD3CC6750E3DBEAF6ULL,
		0x8812B6795CC96CD4ULL,
		0xF7F226A8259CD83BULL,
		0x13797CFBF4AEEFA7ULL,
		0xB1397ADCF746E841ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA5415C2485632492ULL,
		0xB2B9049A753D11B0ULL,
		0x2B388A5C86E66AA1ULL,
		0x53F1F5028BFCF017ULL,
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
		0xF6AC5E68D1DCB667ULL,
		0xE94097FA3390ABE9ULL,
		0x18A5E361DB6AA2D5ULL,
		0xF290D610FF26DEA6ULL,
		0xEA1ADB39BFF3F13CULL,
		0xC01E903EEDBD6028ULL,
		0x1E050A946B2BC6B0ULL,
		0x9755968A245F4250ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x886592A22FB99024ULL,
		0x8466823128C55030ULL,
		0x67A00B712EA1172EULL,
		0x69A9971133D913FAULL,
		0x9645ED4A50F6C3B9ULL,
		0x779D5139BF38E077ULL,
		0x42962412A285A1D9ULL,
		0xDA8D1C7E3A5A6D5DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDFE21D511BB7E64CULL,
		0x2809708DF276500BULL,
		0x437C0F347573039CULL,
		0x0EA95CC4880566B8ULL,
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
		0x736F345ABE91D1F8ULL,
		0x74EDD55E3A018716ULL,
		0x0E7A570DDFB39E47ULL,
		0xBA9D8363C7D5A667ULL,
		0x0B8C756C088BABE6ULL,
		0xF9D294567E3F3B35ULL,
		0x18FE7573534D8BBBULL,
		0x798343A6B1E3816DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE244E0152633034CULL,
		0xBF6E3CC813496837ULL,
		0x5E37A96AC32BF98AULL,
		0xC69CCFE19DF28245ULL,
		0x6121EE201D474DEFULL,
		0xDC4F55C4F1608EFBULL,
		0xFF2CEE033B31AA73ULL,
		0xD301DE4473B89244ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDCFA698A8484BF55ULL,
		0x16FAE2310FC5AF6DULL,
		0x855CC846B0AB1571ULL,
		0x2B35C0176442A415ULL,
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
		0xB10DB34E76DE735DULL,
		0x1B1A41084483B1DFULL,
		0xE3670733297BF0E1ULL,
		0xFF556E2BD999321AULL,
		0x0D36D928480B6284ULL,
		0xD8EEF5E4F98B8B0DULL,
		0x0FE1CF3D7B5F094BULL,
		0x0AAABACACCE1DA9BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC092F504D54B1FEFULL,
		0x0F9B6F6B1DA001D5ULL,
		0xDC717A8A64409F97ULL,
		0x83DC2AED4558FACAULL,
		0xCE99A74466F45FA0ULL,
		0x305875927C837BCFULL,
		0xAF9728C443CBFA9FULL,
		0x820D7A1FDA3421E6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3BD0261D0AFDBEADULL,
		0x11D5DDDBB615F321ULL,
		0x520A42A7050F7EEBULL,
		0x42D0DC9E9A09A216ULL,
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
		0x46A093AE0EA85E90ULL,
		0x333CBC353BB0C117ULL,
		0x4DD4106D14B3B345ULL,
		0xDA67E588DD9598EBULL,
		0xD36FEA7DFD86491BULL,
		0x15050C923803E699ULL,
		0x3BFA58EE32DE73C0ULL,
		0xCF1F95E7449CB043ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF1DD8FC068A19A8DULL,
		0x96A2C6D050575790ULL,
		0xA2B0B3A236FEEE91ULL,
		0xAE06CCE60FFE8030ULL,
		0x764C96688667A58AULL,
		0x61D6994C3C262B99ULL,
		0x8D5CF876DF117456ULL,
		0x18661A06282E3FCBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x28017F1D54930F8BULL,
		0x357F11C84E432B94ULL,
		0x967FAE814E22AE64ULL,
		0x4BE97C0D05FBCA7EULL,
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
		0x42E06F51277F86CEULL,
		0xABF4E7812B5E460AULL,
		0x6F286FA7F831F87DULL,
		0xA774D00765E368FEULL,
		0x31F36B68C5EB219FULL,
		0xA72001F0626B5E98ULL,
		0x46C10D0B29603F29ULL,
		0xEC528CC1157036BBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFAF52D50EE6A5A88ULL,
		0xF88FC526475E03BBULL,
		0x348A24BD003C913CULL,
		0x97CB2D7CD0143C14ULL,
		0x7E2E93866AF92A7DULL,
		0x99B7F5D3047D27C0ULL,
		0xEF98C3B94A680F52ULL,
		0x93CF2BD69CBE557BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF7234D99B8FFDD40ULL,
		0xB0D6EEB6D55C6652ULL,
		0x2A992D1210CC812CULL,
		0x332A055880369C51ULL,
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
		0x3F6359383BE20B95ULL,
		0xFB351F8398070AA3ULL,
		0x85998CDC8CAB83BDULL,
		0x0432C82DAC847D4AULL,
		0x32F4AF4D4AF07550ULL,
		0x086471A8BCE4F195ULL,
		0x56E9CB625BDE53CBULL,
		0x578264A11A5D8F16ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6D3261CF8A2626EEULL,
		0x57E8F037743FB556ULL,
		0xFB3092DC05338AF5ULL,
		0x3CD1E21EBDFFED02ULL,
		0xA03919434EFFA1CEULL,
		0xC298B0F24B61BE70ULL,
		0x6A7B7E6E0A793B2EULL,
		0xF5053610FC831EE6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9A093CE4177B4663ULL,
		0xFF8ACA60FD40ECBAULL,
		0xA2C866449C799FFAULL,
		0x65F5CF735CF13764ULL,
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
		0x25F95CE6DCAAADB4ULL,
		0x378753E87DB6C517ULL,
		0x001A4D366C0EF3E7ULL,
		0x8133533AF6ED8034ULL,
		0x97DA00FE0909BDDDULL,
		0xB0D959CC83986910ULL,
		0x89721D46EF15ACF2ULL,
		0x5ABDDA2287544D98ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC8FFDB70ED97F12BULL,
		0x5BD109A5633ECF58ULL,
		0x4CA788238598D68EULL,
		0xF3C0788A05554B6CULL,
		0x587ACA52FF82CB36ULL,
		0xF84D990BE118B321ULL,
		0xB1542893F4D40D9EULL,
		0x131A746EA830E214ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC51B9ED9591AC2CFULL,
		0x4074E6DB396CF741ULL,
		0xC7E517A40C33C3C6ULL,
		0x2FB3F36410DA2A59ULL,
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
		0x38135C18E9F452A3ULL,
		0x01541A1793ECE5B0ULL,
		0x6F2F59EA263AA9C4ULL,
		0xDA8CE5CC4EDEC8DAULL,
		0xE5BAFA15FE0ECF1AULL,
		0xEE1D892D719A8532ULL,
		0x35B6F81E9AF160A1ULL,
		0x6559242F930C41B7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7E05CBC6E55562D0ULL,
		0x749F95C96BADD10CULL,
		0xDFF006CE3AE7A48AULL,
		0x4130BF10CAE878DDULL,
		0x2404EA31CE9078C1ULL,
		0xA9F83E5CA480D945ULL,
		0x2C09D8296955215BULL,
		0x29060EE8B69E8027ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7B13EC31115FC272ULL,
		0xAA3D9F4C9A0E99EEULL,
		0xFEF21181488469A7ULL,
		0x0DB14F403C410B5DULL,
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
		0xA26B593084D141BBULL,
		0xE24DBE598608B28FULL,
		0x6165B84A86D0F0A5ULL,
		0x37EF4845F805884CULL,
		0x53872693371BD2BEULL,
		0xCC88CFFF153735F0ULL,
		0xAE2B84C2E537EB45ULL,
		0xFC1DB3E742511EBAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5F1EA6E2BDDAC3E0ULL,
		0xF710A8151DB931FCULL,
		0xA5ADE793593792B8ULL,
		0x99830C870129AE7FULL,
		0xD196583FB4A74019ULL,
		0xDC8265D4B3252DA8ULL,
		0xA480E034F9391654ULL,
		0xF68B7806329262EDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8D0B52B324444259ULL,
		0x8C30D88EF6FCBB30ULL,
		0x2B0C3DC8356CF9B0ULL,
		0x72211F274D2BBA3CULL,
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
		0xA99B84488BCA1C52ULL,
		0x33D9DA54E75A81D9ULL,
		0x989B0EE4127C91AEULL,
		0xC5984A2E6F46E4BEULL,
		0xC07AB9A1A729F5BEULL,
		0xE7D88D36D8B07334ULL,
		0xB2C6E62B238863D0ULL,
		0x1EE1C467A70ABC3AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCC857850B44F7D48ULL,
		0xD6A7EC4ADFE31582ULL,
		0x98141492F6B1B3A7ULL,
		0x029612C5DA081597ULL,
		0xDB1CB9E89BA03FE9ULL,
		0x2A1A6A72CE20953EULL,
		0x957DC605B9094F73ULL,
		0xA4CDE00AD97E0C6EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE90A016F8DEB99C3ULL,
		0x876B172398D25ED6ULL,
		0x5961BFDEEAA7E3F0ULL,
		0x61F61D2F1820E773ULL,
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
		0xB926CF8796549E1DULL,
		0x5024780FF254839AULL,
		0x6ACAF0762CB5F400ULL,
		0x65E4EBDD6E1CDF7EULL,
		0xFC3C2DBB8AF0D721ULL,
		0xF9A3F7448D77BD11ULL,
		0xD9DE5C0E7766059BULL,
		0x47CF59B7EECBE97DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x18CD1E5B82B35CD6ULL,
		0x379DA68EFB0DEC72ULL,
		0x744B7FDFCE5D94E3ULL,
		0x239989091E1ACAC7ULL,
		0x74D0DF88F9EBF7D8ULL,
		0xB5AC3CE386452AEAULL,
		0xAD56EFF7BB4E3E72ULL,
		0xF4175CDF96FB32FDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBA474CAD9A5A6254ULL,
		0x2F4C7BE808C84906ULL,
		0x92997BF649DFEF3DULL,
		0x2F9AEAF158FD2BBDULL,
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
		0xB12992CF4FFE4642ULL,
		0xD33670919F42FDE7ULL,
		0x1945D6F917C0D054ULL,
		0xBBD0B7187EC7F80BULL,
		0xD9BCC1A2A33F047EULL,
		0x3432AFEDD9A0E36AULL,
		0x8348086138D509EEULL,
		0x37968D5FBFF8CBEBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF79B8CE6887B738AULL,
		0x8E60F5934E5DB7D4ULL,
		0x05B8D3B87C4EF4C5ULL,
		0xBD06C98B45BCB362ULL,
		0x07160C6759EB9E55ULL,
		0x03084E3199F11AF0ULL,
		0x87E9DCC5258AA825ULL,
		0x09E83D1A83BE1D46ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFE4CECB5A9E3FDC5ULL,
		0x911FFCEFC4FD084DULL,
		0x63877C6B787C5F6CULL,
		0x46A9D7D429C13126ULL,
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
		0x7DA044717859203CULL,
		0xBA72263784CA789EULL,
		0x530D255B52D31FCEULL,
		0xAC135FF7A99E408DULL,
		0x1AFCC893DDD914F8ULL,
		0xA3CB4A1109D16E34ULL,
		0x20D3D0072C8C3D47ULL,
		0x2A121B9C1D5F021BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB6F99728C4B10971ULL,
		0xB0063601203AE938ULL,
		0xB55BB9193C2CEFCCULL,
		0x4D6252EE1A29E626ULL,
		0x31695305DD7E7F5AULL,
		0xAA0A8E8F35AB7AEBULL,
		0x34749AF65BFA4694ULL,
		0xB64689A1D6C6AA84ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x728A205CC11A4934ULL,
		0x1D07C57BE231AC38ULL,
		0xB3D34CC10C50CE93ULL,
		0x0EE8B8300A115ACDULL,
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
		0xBC1E4469F2CD9E62ULL,
		0xF617F8CA4E503635ULL,
		0xDA55623183E31E73ULL,
		0xDF4362E02348DBD9ULL,
		0x979164F8CB4CE8F7ULL,
		0xA79814953BDBBA66ULL,
		0xCF09FA77B03D3F24ULL,
		0x6F55735CC366B5FFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0865C9F331431C43ULL,
		0x9D81C0F67A894D69ULL,
		0xAE962B74CEC92DF5ULL,
		0x776A2F2E10174C70ULL,
		0x2B7C0C1E1B4D2792ULL,
		0x4E0867AF2764ED97ULL,
		0x621A836BFEFDE0C9ULL,
		0xDAB419EC71CE0CF9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBEE3AAECE18134BDULL,
		0xA3E9E1FADD694F96ULL,
		0x574AE2790481F20DULL,
		0x77CC7A5E2FDAA65DULL,
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
		0x2C27D8207ADC37D5ULL,
		0x0781DA6FBAB0D99EULL,
		0x2FDAE0F0BBB96765ULL,
		0xA6660B789140E3B0ULL,
		0x901AAAB69E73E359ULL,
		0xBEE515CA9FC78C06ULL,
		0x790F409FE4E7B235ULL,
		0x8304D2715B5444FAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x31EF73EFD4C550B1ULL,
		0x44003F6187AE249CULL,
		0x35E1429978A20D97ULL,
		0xB92BF8C684B487FDULL,
		0xEF4494BD0A6591D5ULL,
		0x7A8F21B3465424A8ULL,
		0x4D4903F9390793E6ULL,
		0xFB2B40C2A0E79F1DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD9FFA73CA036FE10ULL,
		0xE843D6857A240CE7ULL,
		0x79669F14C65BD991ULL,
		0x1785B2A1B8ACFA87ULL,
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
		0xB70DB46D49EC6D01ULL,
		0x1C68051B368830E6ULL,
		0x7AEA614165E3B981ULL,
		0x07DFA7617FF3D477ULL,
		0x5D962CB6F526BABEULL,
		0xD3BA776B5F8D385CULL,
		0x38644738EF5A14D4ULL,
		0x223A5F473E9BA831ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x639A197DF2231FE9ULL,
		0xF7D29C59397D4F7EULL,
		0x20A5BC788CADE2B6ULL,
		0xF6E8BF647E2C5CDEULL,
		0x150767A909E5ED8DULL,
		0xB697BF0B8B286E49ULL,
		0x30B44FD1F93897C8ULL,
		0x040CC5C98A449BD6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x18A4DB004367C2E3ULL,
		0x77BCC6FB8400E045ULL,
		0x7E635E11622E6696ULL,
		0x0BBBB0A5C6B34D1CULL,
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
		0x615599E03AC199C8ULL,
		0x6219E75B0674B9DDULL,
		0xC09801180A79586AULL,
		0x186D2FE7195FEF9EULL,
		0xCEC468480AD35C72ULL,
		0xEAC34B068DDA5947ULL,
		0x828AE66DA2AD687CULL,
		0x1BACA58919ABC1BDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB2409CFC02F866F1ULL,
		0xC71C3F140063C254ULL,
		0x3098B47CDFB67C51ULL,
		0xD27A9D8D9CF415CBULL,
		0x53B082A4E7E0EB05ULL,
		0x094979893F0486C4ULL,
		0xC29F88DDB4514059ULL,
		0x78AD5861CD23E94DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF409131B67C606CBULL,
		0x1312C0E0B9CE370CULL,
		0x0CEF2FF88C70D16CULL,
		0x77D8062ED895FA6AULL,
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
		0x837F21147FC7E56BULL,
		0x56BF21F88A3F6164ULL,
		0x3695A61CE14BBEF1ULL,
		0x91C9A4251C3606E8ULL,
		0x198C1A28AF26029EULL,
		0x613128DE3506CCBDULL,
		0x3BF5D7CE03516EE6ULL,
		0xBE8AF88F59BC77B6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC2908D7073A969B3ULL,
		0xF30F05CAE26BD843ULL,
		0x9B8C2707E6905ABAULL,
		0xDDB5A8065B825290ULL,
		0xD1C36D229DEBBDF8ULL,
		0x4351BC67D74671B5ULL,
		0x09E17975D7AC1463ULL,
		0x4AC6B89557B39A8FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x68B8428A9AC4AECFULL,
		0xD2DA35BF92610C35ULL,
		0x0A0F802B7546D3ACULL,
		0x63357B3B0E048829ULL,
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
		0x430D900824F40440ULL,
		0x6118CDD47DD61ECBULL,
		0xC87D4520D259F479ULL,
		0x46E61E1368C70041ULL,
		0x53DCBB13D762C8A7ULL,
		0xCE9F6EBBC6EA6879ULL,
		0x87B5D8F8B65DE3A9ULL,
		0x1E5BF59187487BCAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBA3B1842B7B042BBULL,
		0xBBA8CF6FAAB3B97BULL,
		0xD5E4CF46B36E2635ULL,
		0x9891F59B7647C933ULL,
		0x7704CA3CDEBF7B9FULL,
		0x897D09461F0E9A19ULL,
		0x19DD668CC7CBAC4AULL,
		0xAF0C0D65A30D4926ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x50E037AE55812D71ULL,
		0xE88B0DDBBDC3078AULL,
		0x40B971DF88A00667ULL,
		0x34309EFBD348BB76ULL,
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
		0xB9F03D68EB4DEF84ULL,
		0xEDD65E9E871DAC88ULL,
		0x4B0077257F14152DULL,
		0x354B17129A739A6FULL,
		0x456D461F66268A26ULL,
		0x5D90A9E52A6526C0ULL,
		0xC3F65275A6D4A782ULL,
		0xEFD99DD3C3AC0888ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5731F70FFCF5862FULL,
		0xF8F56DA70A77F899ULL,
		0x13DF39FF4E9B0B94ULL,
		0x46C0FB5E80496248ULL,
		0x94B419E26F8BB2B2ULL,
		0xCE825C51594EFEF0ULL,
		0xB3D05A5F98749A88ULL,
		0xF474D012D5D53D17ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9E3AD76589546467ULL,
		0x310074E885EF9CC3ULL,
		0x9CC4106C52BAF6A4ULL,
		0x3F80A657680C6AEFULL,
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
		0x7E31D8B0C495A71AULL,
		0x72E611ABF04254FDULL,
		0xA7BFC2C81EEA61D8ULL,
		0x1C11334D2CB5741FULL,
		0xE05D15C94E29B783ULL,
		0x8DB7B4BC6DEADDA5ULL,
		0xEB993A1AA9377CCAULL,
		0x81DD0C3B2566614DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE9391E23B81C73B2ULL,
		0x9EC77EFE67977957ULL,
		0x7C3FE38D673329E6ULL,
		0xF91785E076DC5DC3ULL,
		0x4B6B313B43296A1CULL,
		0x49C1A485D4695A7FULL,
		0x7ABD9C62B90D956DULL,
		0xB05E4601DD229C06ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB0E0A7A2AE84AF82ULL,
		0xEAA4FAC851E4535FULL,
		0xEC1948885DEF8FC9ULL,
		0x3BCB19ED6FE85EF6ULL,
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
		0xA95995EEFBA43D0FULL,
		0xDE6C7F10B2DF6EBFULL,
		0x8DFDEA91A960EA8BULL,
		0x5E6A03870A2362EDULL,
		0x1B2F45F38A722AAEULL,
		0x1EA61CF3672B4AC9ULL,
		0xB249E8B0BD136C59ULL,
		0xF0FD6D8FDA66D8A8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6CD884A604B2F136ULL,
		0x98AFB3341FF77263ULL,
		0xA06FB2525B315B64ULL,
		0xEED1648105CFFA6DULL,
		0xA517F9AB6BD10167ULL,
		0x517769DF1716322FULL,
		0x5B769FF171A74427ULL,
		0x190503F882EF8ED2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC3F663FD82DD70FDULL,
		0xBAAB60E07609A323ULL,
		0xD0EB04A4803D868BULL,
		0x7E784B7D00085E50ULL,
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
		0xBF1A96FC5BB02CD7ULL,
		0x851AC9F60CC21F77ULL,
		0x12BCFC6C10CD8B9FULL,
		0x90948292CCC030BCULL,
		0x824340ACFD61671BULL,
		0xAEFFB577184F280EULL,
		0xE458B095935A239CULL,
		0x22CF90E5919BEFADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF18275831B550F77ULL,
		0x035515895567F324ULL,
		0x6AE4EDDFCDEBA224ULL,
		0xA4B2CF0CFF4D13B6ULL,
		0x56247399A1468F9AULL,
		0xCEDA4B70789B9998ULL,
		0x4C4F562234F99597ULL,
		0x5F61774C1CB04E92ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5A2A9258EC57191DULL,
		0xC75371686C0151DDULL,
		0x393B7BAC4536FE34ULL,
		0x6E39804D286D071EULL,
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
		0x694196DC1F88054CULL,
		0x33D076D23EE9E6CCULL,
		0x11D5795BECF963C5ULL,
		0xDEB68B90BC640FFEULL,
		0xA267225114F82D3DULL,
		0x39A840ACD83A332EULL,
		0x16E2C02014D78E55ULL,
		0xBF33199ACDB8BC5EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x55B3E19593C88589ULL,
		0x5C537B6AE361A004ULL,
		0x487B0911A8424C43ULL,
		0x497D1D989B7FF528ULL,
		0xD186705F7C6B8483ULL,
		0x4144A454F77B5998ULL,
		0x2F4217AF76B60978ULL,
		0x552FD9462572A964ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x14E81F2330A08DBFULL,
		0xB6463072B7DC9305ULL,
		0x2B337101BDB0D04EULL,
		0x51B4FA891B4AEBEEULL,
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
		0x8E9A3CDC6D53A6D1ULL,
		0xE03233863849D49AULL,
		0xA42B4AA95F42925DULL,
		0xAAC8F1F9213E4C96ULL,
		0xA4FA7B3D4E39DF71ULL,
		0x5CB795D74148C113ULL,
		0x6CCCF6E538275BADULL,
		0x25391C8AE2D233BDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F4DDCDBBCEC6578ULL,
		0x2D31AB9EA7513FDEULL,
		0xD2F612D83A0A090BULL,
		0x30C925DA42BC2576ULL,
		0xEE64ECF623E224E4ULL,
		0x28062A54582C29B1ULL,
		0x3C62CFFC1A2E51FCULL,
		0x27F1C6CEE087093BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x997F7E90F96CF247ULL,
		0x85567D562B370D3DULL,
		0x00F6FE6B982FF9A0ULL,
		0x1296860735AA7673ULL,
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
		0xE81A55090A159140ULL,
		0x2C7C5AB72CBC57E4ULL,
		0x2D8CD6A38B2C2541ULL,
		0xE09A1DB195024EC7ULL,
		0xB9F21F1187EF6A6BULL,
		0xC5FFE9916F8F4163ULL,
		0x76C57058F4451C8DULL,
		0x8ADF84469E0B8B76ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDCFAC9D2666D2E42ULL,
		0x853C036A921259C7ULL,
		0x388E02F3773F94D2ULL,
		0x3332496489E427C7ULL,
		0x18EC8BE29F1E5A35ULL,
		0xF4DF0215319919A4ULL,
		0x673056390F7B8F2EULL,
		0x5664A9CFDDAF2E3DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF1F3642D32B0CC32ULL,
		0xB222B3BDCD33E48EULL,
		0x4520B46C09D78C81ULL,
		0x77A441ED98D3FD78ULL,
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
		0xB14763BFA0DE18E2ULL,
		0xF01E3FED016D085CULL,
		0x7E26CED3C2D67BEDULL,
		0xBE8FBFE963FD96E0ULL,
		0x078C8163EF8E2120ULL,
		0xEEB36DDF0BDE5A72ULL,
		0x92DCBDAB14B6618AULL,
		0xFBDE6466E12A43D6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x603A3008CA62FC1EULL,
		0xE808C3B5F53186C8ULL,
		0x782425B28FB99D34ULL,
		0x3F086BFC554583F5ULL,
		0x69BC94D66071ED20ULL,
		0xE5FE16611101CA32ULL,
		0xE3DDBFEE4714FE3AULL,
		0x5CE5472EB2AF74EFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBDEA50BA14AAD854ULL,
		0x530078EA48F8EB05ULL,
		0xFFDC5327B9119C9AULL,
		0x1881AA43F4F2C928ULL,
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
		0x72C77DA9ED2C434AULL,
		0x3B8FB44C97E03500ULL,
		0x22EAA9ED551A532AULL,
		0x46A12B38CEC6E944ULL,
		0x1043EF19C881E49FULL,
		0x81C8587C603AFB9FULL,
		0xCC3FC3107FAE6629ULL,
		0x88B910678F94BE20ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB9C4BBEAC544E1F8ULL,
		0x5B5047A9BAABF103ULL,
		0xE73B6653C6FFE11BULL,
		0x7E9F4978F3D5AAE5ULL,
		0x22EADDD012307DB7ULL,
		0xA70ABA1023DB0D34ULL,
		0x270AE830044B701EULL,
		0xC0B80D82EFD57370ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF43B52B037FCA66CULL,
		0x5864F0B3D371A7DBULL,
		0xC187C0EBDECAF7ABULL,
		0x78284FAF91565496ULL,
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
		0xB715EC0B00146653ULL,
		0x0ABADE72F7DA4948ULL,
		0xFD74870F748979E6ULL,
		0x3532E24E7BD10F85ULL,
		0x42365D51087F3C15ULL,
		0x043F4CF9C411E42AULL,
		0xEEE86FDD00C7B7CAULL,
		0xC9DB9372BFD52A34ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8FA7655694F8EAC2ULL,
		0x7CB0C9EEBB59BCB7ULL,
		0xB7208B68B76716A8ULL,
		0x2F0D601870E631CBULL,
		0xDA83AB32A29DBBF1ULL,
		0x3BDCB934992D131EULL,
		0x0790D5BB552D5121ULL,
		0xE144FCF29BC53A15ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8BF4F7378A948064ULL,
		0x4CAC03C89A779442ULL,
		0x9D54DCA6360DA04BULL,
		0x0C7FD93B65488276ULL,
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
		0x4645E70C41324098ULL,
		0x609AC5D8E0135CC5ULL,
		0xB74C90176A7DBF2EULL,
		0xBE0FCCEFCDD9CAF6ULL,
		0x8D128B5A9A41F004ULL,
		0x6576488FB9AB50EEULL,
		0x56F9DFB2521E04DFULL,
		0xCDFDDCB82528CA17ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE9551A9026955408ULL,
		0x3024937DAC115198ULL,
		0x2875925CE9FBE2B6ULL,
		0xCB11495DA8A66F27ULL,
		0x665DEBD43B5008A1ULL,
		0xC43F8A65144F9BECULL,
		0x6CB0B17C03D2BAD1ULL,
		0x19E1E92563A6D50DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1BC07A6E32854931ULL,
		0x1E966CAFBF9EE97EULL,
		0x55B3D9CA1FAEDA7EULL,
		0x2F24AB5ADE7DBB48ULL,
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
		0xA02A84AC5F2BC6CFULL,
		0x75144418A59DE407ULL,
		0x8E4EDC05FE4AC671ULL,
		0x9F5126371F5DE4C6ULL,
		0xB88F22F0BEB81EDEULL,
		0xF460C0424ECF1203ULL,
		0x6F9FE5A6E30C78DAULL,
		0xB90A17F51BD05916ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFB692478E9EAF4A9ULL,
		0x2C29A9A3C8353375ULL,
		0x24C60EB00D1137E9ULL,
		0xDDEC1E79D33FB80EULL,
		0x05DFF88144BC2086ULL,
		0x74F284C1C5EC778CULL,
		0x64A22A245F4C4B74ULL,
		0x002ED914F4C430A0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2AC1ACBF90A89738ULL,
		0x33476F892F0B9E56ULL,
		0x0B32A2B57FC04BBFULL,
		0x31F05D0317EC2E3EULL,
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
		0x552C57927C279BF6ULL,
		0x99244EEE15778295ULL,
		0x2E397409B894B8FDULL,
		0xD9D38B6744E68C1FULL,
		0x996A088C115209A6ULL,
		0x849A19F35AAD2310ULL,
		0x05A253F4F1FE286AULL,
		0xDA41F4A1AB41EF9AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2C8B90B4621ABC9CULL,
		0xED4BA82C7AEA07EBULL,
		0x367416626668EF17ULL,
		0xBF9FD82979CC1818ULL,
		0x874EB22A1EB34FDFULL,
		0x76A533878F4B76C2ULL,
		0x52952DF0C77CF320ULL,
		0xB869D00318836AF9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD8AF99681D9C73A2ULL,
		0xBE32DAC1CB0D0E40ULL,
		0x8BB90245A159B2E3ULL,
		0x204922C7936223E1ULL,
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
		0xCE673F98D6DED8D1ULL,
		0xD75AC7B047EF0680ULL,
		0xD63E655B6B468E39ULL,
		0x1D8FD0E23A20127BULL,
		0xE76FA9DCA1E8FA9CULL,
		0x1F5DA9BB04B982B6ULL,
		0xC8C49F22F517CA54ULL,
		0xF6B00C51BDE77CC6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x699C394AE78EED74ULL,
		0xA97E820337A2ED37ULL,
		0x66DE6DB164F16482ULL,
		0x54AAF825B29E3D53ULL,
		0x5A9DED514053F94AULL,
		0x1BCF4F1D41A837BBULL,
		0xD95CFDCFE2E0C9B2ULL,
		0xC30610F81A4F8DB5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4BED02FE6B6E1E93ULL,
		0xB4FDB91804DD3AA0ULL,
		0xF8C1E9FEBA7F41C3ULL,
		0x7420280AD00F51ABULL,
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
		0x099BE215A6DF2E7EULL,
		0xE4766262C876CD49ULL,
		0x51E98507BDA874ACULL,
		0x3C68A4A20B1E2557ULL,
		0x0EA13B599E2F30B8ULL,
		0x788FB6DBFC1D6952ULL,
		0xF7C14DB0729D5DD8ULL,
		0x9D920FF2E3F3096FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x86066D048AF0EF3DULL,
		0xCF53CC1E64DA3AE9ULL,
		0x4799B19298243A0CULL,
		0x628E80124204354FULL,
		0xFA61200763B7480EULL,
		0x63A169520CBB13A0ULL,
		0x78EAD09FDE9C2370ULL,
		0xD056092AD5E79A76ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x85198345C9BAC74DULL,
		0x308218BDEC354AA8ULL,
		0xDE2663EB1DB2E613ULL,
		0x50C32641DECC6910ULL,
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
		0x2432FB7AFB1AB65CULL,
		0xA69815B8FDF7401AULL,
		0xBC398DD7D705AB69ULL,
		0xD0963FA6180CA3A3ULL,
		0x57F9B8D5E66B967BULL,
		0x9A5EA2722FFF3FAEULL,
		0x777FB9958F109D11ULL,
		0xBA0E347CDA5024D7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCF4434FFA0EA7D72ULL,
		0x8CAEEAF7D49D262EULL,
		0xF58047CC7447EBB7ULL,
		0x01A9CEF5156AA2ECULL,
		0x99E3BF3EC789F21FULL,
		0xDA5F18ADF1FB0A23ULL,
		0x445B82DFE64D7560ULL,
		0xA55564E01FA7EF9FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8C31D2E9EFAE9F17ULL,
		0x99D79DE25DFA0C83ULL,
		0x5E1965026FB5A3EEULL,
		0x625B41F4B799E70EULL,
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
		0x966BA5CF2723AC37ULL,
		0xE25FFB4FAA4FDBE0ULL,
		0x4B56E7C8D8ECCCD4ULL,
		0xBEEB14CD3C93A717ULL,
		0x83A0C251CFC8D79DULL,
		0xCFB838A70037DA91ULL,
		0x0DDF2E734CD6D75EULL,
		0x9C14D20B72EED6E1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6ACD5352C1D83CC2ULL,
		0x72749652E057E6F6ULL,
		0x406426DC46AE020BULL,
		0x177A75052D26E13CULL,
		0x0512E8A72F74DCC1ULL,
		0xFEB61950E48187A0ULL,
		0x79259D37941FCA32ULL,
		0xD718734BD76A8B28ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF4ACA1D031C2AADAULL,
		0x763C0BC4E70844C2ULL,
		0x1E7E4FC9FD6ABF4AULL,
		0x64E6B03925100341ULL,
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
		0x2CD232BFF50E7D63ULL,
		0x8B4E3AD920330A4FULL,
		0x6D1C5B7DE6F852C7ULL,
		0xB80F2AC5CAC60A4FULL,
		0xF268E0D895B4C38DULL,
		0x5EF5D386CCDD3976ULL,
		0x889190E25724A823ULL,
		0xCAA42E758370C2ABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4CC72959C331FFACULL,
		0xEC67786C5FE0829DULL,
		0x9DAB0444B58E4173ULL,
		0x5CB7AE8EE0B552B2ULL,
		0x203785B4A9E98CDEULL,
		0x73AEA107196A1443ULL,
		0x1CA5FD7A275EAE84ULL,
		0xB79D8C6756447964ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x135E90BB32069C23ULL,
		0x8B784161636A0D63ULL,
		0xD46938B048CD1EEAULL,
		0x2E538A519EA39836ULL,
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
		0xF990C2E5FCE7BE83ULL,
		0x5336B1C70DF410E4ULL,
		0x50C0E7682E4A0B8FULL,
		0xCBF2F397B6BCC387ULL,
		0xC5F83C140B710563ULL,
		0xD1C1A08DF3B7E797ULL,
		0x8AE49C78A8E32F64ULL,
		0x72F6F2134BA0B3A0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x05C633CCD0511AF0ULL,
		0x2300EAED9555C7E2ULL,
		0x26D899F6F712F139ULL,
		0xFED8DD2D12371C38ULL,
		0x8DB0D38C53ACE8D1ULL,
		0x98E5FD0F77A30A2DULL,
		0x40567FEE7E2A7FB6ULL,
		0xF7DB233AF73E7CF1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4E64133E73B2DE47ULL,
		0xA0D00B9FE3B726C7ULL,
		0x3B0089F38EA12E32ULL,
		0x133ACA872B19C554ULL,
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
		0x595887ECD2997885ULL,
		0x56F478FC77E3F565ULL,
		0xFB947BFC4A2ED5C4ULL,
		0xBBC2C7797239D036ULL,
		0xB4BF8A64FBAE77D2ULL,
		0x28B6704A5AE48F2FULL,
		0x2E12D78D3D6F5879ULL,
		0x2F3D80B1F0F2EB73ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x43BC62C257C8DEADULL,
		0x86AAB8C420CD757EULL,
		0xB415F6EDAF32DBE8ULL,
		0xE5B2CFF66A6414C7ULL,
		0xC57F4011C74C05C7ULL,
		0x6331EF2DB0C251B7ULL,
		0x28C77BD0FA15BC38ULL,
		0xC5606BAE9978F222ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x99272D84416D8423ULL,
		0x21F4EA79982B9FB4ULL,
		0x10AE23009A492B79ULL,
		0x0CE1160203F0BD76ULL,
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
		0x930BB419BD5DF7A3ULL,
		0x0ECABB04F07F0F4BULL,
		0xB0085B9D3A0ADC07ULL,
		0xC7B2F0E558EE7DE3ULL,
		0x8A5D42F57590975EULL,
		0xE1D5B19965EF700BULL,
		0x3011132D19607083ULL,
		0x6FBFDF68B69341C6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD37D4A5606E10235ULL,
		0xD6BC1FC03D057CB5ULL,
		0x2131CEC386A89ED4ULL,
		0xB64A77219EF1F0CDULL,
		0xA7219BDA89186066ULL,
		0xD33177112FFD7958ULL,
		0x5D8C01B8CEF3A07DULL,
		0x244E4ECA0C22CDC0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7A6937C2D0551FE0ULL,
		0x646F4B7CB5643123ULL,
		0xCE97241CBF891E18ULL,
		0x4443F15106ADC5F3ULL,
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
		0x9EF7E50B564EA034ULL,
		0xDC86A07D9D390F59ULL,
		0x069216833B463063ULL,
		0xDF53E4F91EE91D1EULL,
		0xBAB61286EE63B61CULL,
		0x975D73BAA01290CFULL,
		0x4CF0940729FEE2A8ULL,
		0x8EA9CFEF2C77936EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x469B5478F1E42AACULL,
		0x3E8B63C325DE0564ULL,
		0x4DDD6C93832C2470ULL,
		0x88DB36AAB7FBFD7AULL,
		0xFFC606373C9A42CEULL,
		0xF02C7D6FBA8C3A76ULL,
		0x57B98B7159A2372FULL,
		0x413178166AF3AFDEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x17FE6466C85194D1ULL,
		0x6F3FCBD8894BDB21ULL,
		0x1EDFF02CA5DB7FDCULL,
		0x5655B87B2080E702ULL,
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
		0xE6F949FE530724E5ULL,
		0xB0A06A66C0637721ULL,
		0x90E7E3511320DE93ULL,
		0x07835641CC681897ULL,
		0x19E815E65CE4B15EULL,
		0x3FF4C8F23C500F9FULL,
		0x41AD1E07C9E992C7ULL,
		0x2C96842D62F852C7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFD7DC7B6BE834EBEULL,
		0x7308321533054E66ULL,
		0x57C4663EFCDF81F1ULL,
		0xBF2290C6D9A9A12DULL,
		0x3E45CF2083A33213ULL,
		0x8B73674D21D3ECC6ULL,
		0xAD737D6D8C85BE66ULL,
		0xB70A582951DFE3E6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x839203A5D43CB818ULL,
		0x08CCB6D37BCB54EBULL,
		0x39B153F73312E2FDULL,
		0x3B2F4E157C5EECC0ULL,
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
		0xB1B90A6629F730CCULL,
		0xC4A4DCB0E26D7FC9ULL,
		0xBF65A491BCFF5810ULL,
		0x52183805EAB68265ULL,
		0x4D94C0407F50DDC1ULL,
		0xD3B61496F2F2DF61ULL,
		0xAE00B843860B0DE3ULL,
		0xE8F403C8FA25A08AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4EED70DAC7FB2EF5ULL,
		0xEFDA87FF8CAFE2B6ULL,
		0xC39332FD0B74BC2BULL,
		0xED17C96D5698EC37ULL,
		0x25BBA98BE6726F74ULL,
		0x9BBD6C4304C56709ULL,
		0xDBEC56AAFDE7D056ULL,
		0x2A87C9E9E5EA912CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4D04F85A1300655AULL,
		0x23B35126B07D7A29ULL,
		0x2AD8EE38E6C5BEDBULL,
		0x291105B594E1DE1BULL,
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
		0x145297C110686158ULL,
		0xA3E36F3139E6E34BULL,
		0x2ECE6882C2A3302DULL,
		0x3E43ED65C593FF4DULL,
		0x493D5C5B95024AE5ULL,
		0xB74AD418C79C4E63ULL,
		0xF957BD4101813A94ULL,
		0x8A0600E9A7C12A8DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x75C9E708D98502D3ULL,
		0x7386054E4E476A08ULL,
		0x47CBB2BBF622FEF1ULL,
		0xA2526A72AFF6A0A4ULL,
		0xA83158730B1E2828ULL,
		0xEECC8B8C10AF953CULL,
		0xA6068B1598897DB9ULL,
		0x89F54586A794BAA2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8651453CAEC08680ULL,
		0xF31C2EC612C2F4FEULL,
		0x45102838614639B5ULL,
		0x1E6D53A51C35FB97ULL,
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
		0xAC3319357E394A59ULL,
		0x5242D6AE0DCE9353ULL,
		0x1E865A94C772E72FULL,
		0x65340A5ED5F7A9CAULL,
		0x67D484808B93C3CBULL,
		0xC13CB4C266F328F4ULL,
		0x2F300CBB81407448ULL,
		0x96E8B844E74F0637ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2A1B4022402AF88CULL,
		0x1D289FA252E8BAC0ULL,
		0x08B841D3FB02129DULL,
		0x3AD4D6C9EBA08FCEULL,
		0x65528CA14BB0E35AULL,
		0xC3B33918797BFC7BULL,
		0x6B31E67381E83E2EULL,
		0xD1A74EB0A491E863ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE162A436B9BBA13DULL,
		0xD7829244FA967289ULL,
		0x2D87C770B388DC6DULL,
		0x7214DF96D269876BULL,
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
		0x4DFD1C200637FD49ULL,
		0x08B1EFC186CBD265ULL,
		0x1764821B59A1B5BAULL,
		0xE547BC675252E648ULL,
		0x6C12F8941AEC510EULL,
		0xC91A544EFF670141ULL,
		0xA063BDEC94872D99ULL,
		0x903AAB4FD3EB0536ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD88891E773CDCBC4ULL,
		0x1D35BDBE15552217ULL,
		0x7ADB547D045B4F16ULL,
		0x3A88366ED505748AULL,
		0xBF380C92DE5C5976ULL,
		0x42EE1F3CB6B09986ULL,
		0xAEF00EF5FF36470DULL,
		0x30701D2B0860DCF1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1DF392678FC8F43CULL,
		0xD60C12BA3C8A1603ULL,
		0x73B526387F489F7FULL,
		0x62D09F6EB3CF6BF9ULL,
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
		0x5CF37F82ED868A4AULL,
		0xE8DF092EE6A4870DULL,
		0xDBC4E7F76AE80E35ULL,
		0x9B9896B48E13A4ADULL,
		0x778758C9ED47D29BULL,
		0x4DD266380C829026ULL,
		0x5ABC17B48F8FE44DULL,
		0x37FC67640EE2079FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3257548B9D7919B2ULL,
		0xF5F504C6572CD092ULL,
		0x84F122F272F5475FULL,
		0xE5BD608E2CD29813ULL,
		0x4278F2673B2588CBULL,
		0xD22D3ACA3AFD698BULL,
		0x68ABA2662544B3C5ULL,
		0x42DE362B28E235C8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0ABF5D9DC124652CULL,
		0x4D6E76B5A93B7185ULL,
		0x45452EA8BF1BFAF2ULL,
		0x18568498853A3282ULL,
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
		0x0972BE491FBDCA70ULL,
		0xA2B05C5926E31B9FULL,
		0x0B60308E314AF123ULL,
		0x8C104DEBA93C03BCULL,
		0xA5F4C1B84288E0F9ULL,
		0x7F40BE9B4C9D282AULL,
		0xC7CB2C3B3560E843ULL,
		0x3AA9C0D6893A03F5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0A778D31C1ACF37EULL,
		0x771E5D3981739777ULL,
		0xE622C163684F1764ULL,
		0x9ED9BC88E777B7F4ULL,
		0xE48A4AB103692CD0ULL,
		0xE4A226B42423C6EFULL,
		0x36D91E8A02FB2A8BULL,
		0xD34EDA2310FF0190ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB4C8DC2ABCC5919EULL,
		0x1F1C8B6FA773F2E0ULL,
		0xA92B777844160300ULL,
		0x44B4D0069A86A6DAULL,
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
		0xA96F6E4950972425ULL,
		0x80BD24BA0FB6E51FULL,
		0x6279E0975DE6C920ULL,
		0x2D034D30F8CF4C19ULL,
		0x197C177148787F3FULL,
		0xAA22365AC5B2B8A5ULL,
		0x031662757DD2864EULL,
		0x1B4A6E4C66916173ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5249FCCB0405242AULL,
		0x1E2E2D44F414A172ULL,
		0xD2743FB3F8573C57ULL,
		0x65F269F0D8B6B04CULL,
		0x0CD70A30A535DE44ULL,
		0xA42027DF347DEE78ULL,
		0x34F52828170A2175ULL,
		0xC0639F809FD6C447ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x37A569168875E187ULL,
		0x46DD1DCCA978465DULL,
		0x28F44860A74E8500ULL,
		0x4553957F9FCBF04DULL,
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
		0x8FF84C21A6672BC3ULL,
		0x3B1F3D5B7FA8ADF2ULL,
		0x06EF25EE052E0E6AULL,
		0x394A4707B38DEDBFULL,
		0x2D566122092B40E3ULL,
		0x1D95646B697A66A1ULL,
		0xADA2D747827D67DBULL,
		0xA7A8590007F67621ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAA4EDF6927C6E5E1ULL,
		0xCF0408FB2F716BC7ULL,
		0x6E254FDC8D928F07ULL,
		0xF024C647B0859D50ULL,
		0x524301D939A54B90ULL,
		0xFD6FB8B67351C4D1ULL,
		0xCAD8D6B6C2DE5F32ULL,
		0xD0C4A8B74440DFEEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6A8991874C82AF2AULL,
		0x31B2B13CDA3F4705ULL,
		0x42C5EB8DE936C857ULL,
		0x2EF1AB8D0FFC9BFCULL,
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
		0xADF45F97DFBD2726ULL,
		0x4FC1E5A4619B023AULL,
		0x346CE3409D0E235FULL,
		0xDED567A4B75F3E1FULL,
		0x0687247AA6791E9DULL,
		0x2CD743032ABDF9E4ULL,
		0x1FD83AFA54ED03A9ULL,
		0xE75FDC9CC0B2C0A9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC5EA81E39FFD91C7ULL,
		0xE744A746F270F62EULL,
		0x9CDF59BD7131CD7CULL,
		0x2DEA6733D80640AEULL,
		0xBECC72F7301E58ECULL,
		0xE47C3CBA0D279DCCULL,
		0x96E0D3C355D2BE0CULL,
		0x6068150C47C86C95ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8DC03737D138F0B0ULL,
		0x26002D37D37BB780ULL,
		0xEC46DBAD09C2AB15ULL,
		0x39B29FE2D2217856ULL,
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
		0x5BE8281C879C2B38ULL,
		0x2A83F038782A3887ULL,
		0xAD78808B986E441DULL,
		0x95ED6B71D3D3A9E4ULL,
		0xCE5194E2CF32AE0CULL,
		0x0CE74BE06BB24221ULL,
		0xD69B738B2E817F3FULL,
		0xCED4489EEDB9B1E6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7C64D78066066DFFULL,
		0xBD11B5B6C123184CULL,
		0xEA01530A703E9E88ULL,
		0x75B761C3727F2FF7ULL,
		0x2277CD3EEEF69183ULL,
		0xF20887B5E0512E5EULL,
		0xABE2F98B45D96383ULL,
		0xB1FA5DA1CFC67FBBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x61D6F2EF6A81FA27ULL,
		0x6A8358D267700F46ULL,
		0x1AD9497DB123C35AULL,
		0x688EEB40D36DEC55ULL,
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
		0x7C9DBBCF0979537EULL,
		0xB4B7D7FF90BF1FD8ULL,
		0xD8AE654F89DCC3E2ULL,
		0x1F7F0522DC07CDABULL,
		0x86A294DC1E650020ULL,
		0x7A7BA467EBD4B7FDULL,
		0x42ABA221CF2D04DEULL,
		0xD7D73BA01E9A88BBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x13671FBF88DDAE73ULL,
		0xC47ABA4A735116A3ULL,
		0x17F1803F0941106BULL,
		0x5407691193887284ULL,
		0x0A91084C503A0BB4ULL,
		0x67C07F27D151E4E4ULL,
		0x553AA824BC5F7122ULL,
		0xCF546D9557D82BBAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD3D179681AFBED39ULL,
		0xB804A5390CD95EFDULL,
		0xFF8200A14B1FA161ULL,
		0x0EE231AAC959294AULL,
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
		0xA57766D213D7D3F7ULL,
		0xA78FB78A5B845DFAULL,
		0xC9483AD83D1AAAC2ULL,
		0x56C3B18E7389BAAAULL,
		0x2320F36F629B432FULL,
		0x596CE03AFFBB8EA8ULL,
		0x6515E94DDA691DA0ULL,
		0xE2D49FD620B9DB74ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6E4D0C8E1E586236ULL,
		0xE3E9E1425068B047ULL,
		0x5CAD3DEB794F8361ULL,
		0xE042EC4297C38C03ULL,
		0xECB906612DE063AAULL,
		0x173D1CAE5B84C17BULL,
		0xC98D6CB651B0E179ULL,
		0xE2362DF4AC5AE0A1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4A978A5FC93C9F6CULL,
		0x96BCDD286B3E2243ULL,
		0x82DD7B6B0F241534ULL,
		0x0E05ACC321DF69EAULL,
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
		0x9823257507DF26E5ULL,
		0xBC5F305B2D0E3C31ULL,
		0x828B0CDEBF9987A5ULL,
		0x79935FAB1CA4441AULL,
		0x065486083C72A069ULL,
		0x2FD841147EF1EACEULL,
		0x2D2E0CB494C68119ULL,
		0x533C7EEB19DD4CA6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFDF99ABC144BEDB1ULL,
		0x7E89B800370A5652ULL,
		0x16CC4A41477181BEULL,
		0x8AC26430672B6C06ULL,
		0xE2E37EDF2AEE8F4CULL,
		0x6BE26C07171FEB1DULL,
		0x14A2BB625CE6B328ULL,
		0xDFBFE3C9D0D110AFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDCF09AD18D2DC064ULL,
		0x545318585F2FDA03ULL,
		0x106CD4D1C36097A4ULL,
		0x1350026B8D49BEC2ULL,
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
		0x380EFC1DBF8DC06FULL,
		0xBAE7AA20E337829AULL,
		0x0D8AADEA74E38641ULL,
		0x10F621A3666BE4EBULL,
		0x159D880D7DB51E1CULL,
		0xB8D0D9CF42FD58F1ULL,
		0x954E1A2A8D83AE71ULL,
		0xD6CD8499029F3E73ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x00CF1C4CFF950150ULL,
		0x2BE8B3644F2F77D0ULL,
		0xE81F52C6769BD962ULL,
		0x8F1ABFBD634754B4ULL,
		0x1A5DE0DFA2325D03ULL,
		0xFBFDEF834EECADEAULL,
		0x31A8A3F660592CB9ULL,
		0xB7376383184533A8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x82B2B09F5561696DULL,
		0x964DBE02CE816DD3ULL,
		0xEFFAE6E2B296EE25ULL,
		0x32244B26CC822A66ULL,
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
		0x481FC247C31490E4ULL,
		0x1AA9E3B19FDD5495ULL,
		0x7A1AC958A8EC9DF3ULL,
		0x59CBE30117197702ULL,
		0x28A4E639D9ED4DFBULL,
		0xEB785F1E77067362ULL,
		0xD26F635E3762AE46ULL,
		0x18DAED2F43D41672ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDFBFD8F6A0EF7F5DULL,
		0xA176E10326DB6B59ULL,
		0x938AEEA4598D1B7CULL,
		0xD7D082C1C115130AULL,
		0x0C37D608F09B3646ULL,
		0x28C64D2F2D5EF36EULL,
		0xF3A1E449553B4F27ULL,
		0x1752116A65481521ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA0905093C4549652ULL,
		0x5FA1AC3367DEE777ULL,
		0xF910B7CDE137A12DULL,
		0x3C4BFF785ECC95F8ULL,
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
		0x6928FD6638012B57ULL,
		0x523CAA3160FA09A7ULL,
		0x44B85F21D82FCF88ULL,
		0x5339B706536E424BULL,
		0xF227F5E38C23586AULL,
		0x06F10BA170D8EC3CULL,
		0xA7F7B7A913524A32ULL,
		0x28E3927BA11E0B5EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x65D418FE12281DDBULL,
		0x7A946FB312B8724CULL,
		0x896222B670BB3F32ULL,
		0x3B609734823F8A9CULL,
		0x2FBC81425EE71F1FULL,
		0xF3E65E4A6D7A73E4ULL,
		0xDAB7B24F3F6F1CDBULL,
		0xACCE456D62125057ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDF483454DCC98BB9ULL,
		0xAB3DF568CE477487ULL,
		0x32D707C0DB2D4B1CULL,
		0x03028FEF2CEC7AB1ULL,
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
		0x8C3A44C617A0368CULL,
		0x48B469E03741C0B8ULL,
		0x925710B728E8A128ULL,
		0xDA5A9ED3EF014BDCULL,
		0x3049EE01518983D9ULL,
		0xE2356953806DCDA1ULL,
		0x90A4DE93D11DA6C8ULL,
		0x12BF74030BAF8F80ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5C94844E84DABBB6ULL,
		0xFF9A239AFEF1E005ULL,
		0xE66585380F1DB551ULL,
		0xF40F235055F75A02ULL,
		0xA21EF357D4E0214AULL,
		0x8DAD73B110D11025ULL,
		0xD65D5825DE6D15ECULL,
		0xDD17507FC20E6837ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4A06F5A013EA1789ULL,
		0xD548BC61C994010AULL,
		0x528F7FD120006C8AULL,
		0x5D40C10086F5C6A5ULL,
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
		0xC8FE6FC69F6E4BACULL,
		0x10D582639BF77BD5ULL,
		0xF5EB9175695C5C38ULL,
		0xD940FED5FA64E5D2ULL,
		0x6A1785F5475A9F3BULL,
		0xE903711059DAE025ULL,
		0xE547E33D3200A659ULL,
		0x3554FC1AAE7F3383ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9D5119829C1D5957ULL,
		0xE11F5293513104B7ULL,
		0x85815A0C8A688EE6ULL,
		0xA17448ED4A7A191CULL,
		0xEFDCF47D877092CAULL,
		0x141A7B1795A0CB0EULL,
		0xA303DDC0D99D13D2ULL,
		0x37179893B7B78C58ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x505EEE0A800ECB08ULL,
		0xCA4AB2BD6B659874ULL,
		0x468307DDFDBB8D7AULL,
		0x74E97BF1518D9D22ULL,
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
		0xEF7EF213E50D860FULL,
		0x0425D896059BD156ULL,
		0x94F0A7650B255EFDULL,
		0x0BFDF98F245F3830ULL,
		0xF5EA8418EECF8B13ULL,
		0x940CCAA0D3C4E97DULL,
		0xC0BDD6116024FC68ULL,
		0x3E63B5B0D53DB6CAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x650C05C568E69758ULL,
		0xCBA60EA4E7DDAC33ULL,
		0xD87FC6C4F6194466ULL,
		0x4044E7D040902A0CULL,
		0x321470BAF7647BD7ULL,
		0x7C867FA45BD1C0E1ULL,
		0x1E611C377FFB69CEULL,
		0xB52C2D519A4BED3EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9C39CC41360B2EF3ULL,
		0xB66EEB6AEBD62C68ULL,
		0xD63476F75B37DD75ULL,
		0x29F74FE1A3B2F903ULL,
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
		0xB6A14E8CA42193E9ULL,
		0x47FC0D47B042EE8BULL,
		0xD73C6D973F2FB1D8ULL,
		0xA1AC159537B2D9EEULL,
		0x108199CAF62A28A7ULL,
		0x544B050434017F0EULL,
		0x971DBA741669055FULL,
		0x0A9B379697AD0D3CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB204679FEFAAB45ULL,
		0xA4FD13CB64E794D8ULL,
		0x11CB33865F6127BEULL,
		0x7EF4CB95B27848F4ULL,
		0x575091FF3BB09485ULL,
		0xAC71009B5D5AA862ULL,
		0x6C771A060BAB5DACULL,
		0x75568348BDBF182AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x78C830505332E350ULL,
		0x8D5BA10C281F3730ULL,
		0x1A2D0A6677F56E9EULL,
		0x4AEA0D8DDE8CF1ADULL,
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
		0xB613AC9192D4530FULL,
		0x82FF78818A775DB6ULL,
		0xD9FA61E8E4C4BB2AULL,
		0x9A7AAE9354DC60BAULL,
		0x568282840FD6644FULL,
		0x16324FE35C03BEC8ULL,
		0x61E7119CB967A75BULL,
		0x9D701D25D12B7215ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x769A196B6D7DAD45ULL,
		0x4A6DAD2CC413A6C3ULL,
		0x3F4CA49C38244FAEULL,
		0x293E65505ACB965FULL,
		0xE8A2288F26091600ULL,
		0x31C5D9845EEA52EDULL,
		0x24114BABABC49D7AULL,
		0x2D705C63B876F655ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8EC6ED80D9D0480AULL,
		0x20AB5D6E5829B95FULL,
		0xC8691F14B2D3E2DEULL,
		0x1132E612A4DB28E4ULL,
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
		0x02D0CD810F324DEDULL,
		0x7B367659C188EE72ULL,
		0x4D0784865C4A66B6ULL,
		0xC61F5FB19561D8B0ULL,
		0x86242B4F47D8979EULL,
		0x4D40549436D88D1AULL,
		0xB12AAFC31AA54BBAULL,
		0xE20B6437E56966EEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2C0498DFF57D0A8FULL,
		0xA71DDC514E91416BULL,
		0xCEEF92CFE67B955DULL,
		0x5932574D08277357ULL,
		0x7F73217EA4C805C7ULL,
		0xCBB0C3C9E147CC62ULL,
		0xC2DDFB354D656D6EULL,
		0x7EE510137172BD74ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD513A9994E2AEB82ULL,
		0x0F68181126744857ULL,
		0xDD7ABEC2ED49D08EULL,
		0x249D85CDC3D78D71ULL,
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
		0x5E5A5058230F5C30ULL,
		0x431716FC47D4713FULL,
		0xFD4B3DD8C241AB02ULL,
		0x692523D80061CF98ULL,
		0x637A961C220B847EULL,
		0xD3D855BECF5769E7ULL,
		0x2466BD39F37FD363ULL,
		0x12C28534510B623AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAA3970F542C1A9C2ULL,
		0xB63B44FFF03FDEB3ULL,
		0xAE141109033E3225ULL,
		0x72678C5603452B95ULL,
		0x8EADE7BDEB70FAB3ULL,
		0x851A81BC407DBAF7ULL,
		0xA13EA91395101813ULL,
		0xA7E4BCA290497141ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4A82C15EFB3E2339ULL,
		0x3D094A5D8BE48A25ULL,
		0xC72A2A81C39946C8ULL,
		0x53A95D2499E668E6ULL,
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
		0x27675762C0F2B67CULL,
		0x161F91E34A8D680DULL,
		0x35B33021ABA5F884ULL,
		0x57F491DF05CB57D9ULL,
		0xFD391DC7ACC65BBDULL,
		0x2CB890F599CEC835ULL,
		0x584F8C9D5629957DULL,
		0xF5B14AFF0C583793ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE4E6C2005CA5A105ULL,
		0xCA5076DA9844AB71ULL,
		0xA4D78811EC905405ULL,
		0x36E3EA02703A4CDBULL,
		0x31574B292F3E5DFAULL,
		0x0D794832CFE89346ULL,
		0x01713F9ED1835EB4ULL,
		0x6C754A550F2D629CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8605D8E9067CC361ULL,
		0xEF33E7F2AA749833ULL,
		0x75DB15D76FC1C658ULL,
		0x7FF8C11829ECA7B4ULL,
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
		0x6F2B80DB4EA1D795ULL,
		0xE0E95475C8838507ULL,
		0xBD67522223F7A563ULL,
		0x75AE9885F2AE9B04ULL,
		0xB690DD3CFD5C2B2DULL,
		0x63703B32FA444174ULL,
		0xD08A74C0A07EAF00ULL,
		0x621EC418C4D94C28ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2DD7B3BAC6D645DAULL,
		0x5F81BE01A231FEF9ULL,
		0xC95EBFDC7233FBB8ULL,
		0x82DF156F1BF397D6ULL,
		0xC52FC60F03681E94ULL,
		0x76ACB8F06FAC5B3EULL,
		0x2AD9B8CD6093090AULL,
		0xF2F1C88A69EE4B1DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x15BD3DF3A2056D2DULL,
		0xA66CEC54B8DDB210ULL,
		0x8C4478612EBE4C2CULL,
		0x737CDA38559D2AE8ULL,
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
		0xCEFE215F3F3C8150ULL,
		0x916AB5243CEA52DAULL,
		0x1B0DECEE622A60BAULL,
		0x50DBDE873B265749ULL,
		0x6302429D0841FD40ULL,
		0xCEBAEE1D891BB3F8ULL,
		0x81CDE3A1611CB0F2ULL,
		0x83E75C9891BA55FCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xADB532586B498F2CULL,
		0xF1243F0D2F1836E4ULL,
		0xAFFDDAE7228D1D28ULL,
		0x81B8D21781B3A319ULL,
		0x2054F3D09C174380ULL,
		0x7F6B59C988ABEF02ULL,
		0x93798E29C4AC8505ULL,
		0x2D3652611353A0D7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0702A15EE24A867FULL,
		0x66167A8F1E695884ULL,
		0xCB94C1C87843C8CBULL,
		0x2D6A90AC7CB197AAULL,
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
		0xEA3E82D849FC1CF5ULL,
		0xFB55C0DCD34FE527ULL,
		0x2D3E67EDACD00407ULL,
		0x6D02EBDE2EAC0E55ULL,
		0x88E57E485B5B7E05ULL,
		0xA3422266164CFF8FULL,
		0x06266EDE35EE675BULL,
		0xA1096863E0734E8FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x23557D0E209EF5BBULL,
		0x98FFDD141736197AULL,
		0x411C2808A9CAE5A9ULL,
		0xDA4CAFE16B40A487ULL,
		0x16324259FD38D508ULL,
		0x2F08B640CC6F1734ULL,
		0x6E0CEA59DD6AE4A6ULL,
		0x92F609F3C65ACFADULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCD83EB2C22823D01ULL,
		0xA2DBF151B30A4940ULL,
		0x7FEBEB8A268A854DULL,
		0x299640A0A30E3F4AULL,
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
		0x614BBBDACD9C3401ULL,
		0xD3E72DB207051B88ULL,
		0x0B9E0C7DE29BF390ULL,
		0x502A68ADD309D512ULL,
		0xD4C858B40B4BAFA0ULL,
		0x14021438F2D3FB46ULL,
		0xD8FB1040834910BFULL,
		0x4A910382C294C040ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x51FE1F47A77D22CFULL,
		0xE37F89CBC0323116ULL,
		0xF70C53E0175D97BEULL,
		0x5748AF34E00B0BFDULL,
		0x416ACC9B8AEB4FD8ULL,
		0x8B03928B7F8AD966ULL,
		0x7022205D5F455AF0ULL,
		0x0681B47EA48A7EB2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEF306836346D4A5EULL,
		0x462EE3A563ADF1C7ULL,
		0xA4C5545523CB587AULL,
		0x1327741568848437ULL,
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
		0xAE976F7D77F7D617ULL,
		0x419EFADE9E953A11ULL,
		0x6172F4DBABC2AD49ULL,
		0x4EBD50BE91DE9FCEULL,
		0xBBEEC858BE7AC7FBULL,
		0xDD97B8B16B9FEA0AULL,
		0x4CE001AECE307EB7ULL,
		0xBA93A651483B16C1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x02D54D07E13A487DULL,
		0x480CC019FFC4BA08ULL,
		0x96DEFDF09BB7B599ULL,
		0x7E788DBD6EB949BDULL,
		0x4DD28A45A735D3CBULL,
		0x7AF58DC7C0FFC112ULL,
		0xC1812117FB205F75ULL,
		0x68BB43A6BF075EF8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x03F3594B0AF9CE6FULL,
		0x9DA49973F29694EAULL,
		0x7AA94D4E646F9B8AULL,
		0x7663685180D29DD5ULL,
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
		0xE2F7D9DEEFF99070ULL,
		0x0CD917467B33E09FULL,
		0xF2FC4888C738A245ULL,
		0x68D5D938F02FADE5ULL,
		0x11968509E537449FULL,
		0x6E45E61E3D5E069DULL,
		0x656E75CC586F8DA0ULL,
		0x6F44C1B44247C9BFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x932C47C134AF8636ULL,
		0x05AD58DA8C5F6B7AULL,
		0x13F63394FDF715B4ULL,
		0xD2B71C928DBE0369ULL,
		0x43853D218FE01ECEULL,
		0x996CCDB70FDC5204ULL,
		0x2F8783C7B630301FULL,
		0xCF55D9A04EF9D467ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE65C3E9A6639A506ULL,
		0x9F655DBCB01543D3ULL,
		0xDF4E01A3DEA96DB0ULL,
		0x53952F9C80041594ULL,
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
		0x4E292B6B144E507CULL,
		0x970E065EBC7EAAEEULL,
		0xDD187F5BFE402643ULL,
		0xB74E9CE39A15DDA0ULL,
		0x7F6F8D28EEC9BB8BULL,
		0xC8F915A148FE65FFULL,
		0x2621E9E84BD1E301ULL,
		0x06ADFF144100B4BBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x92DC517FBB075248ULL,
		0x4626412E2DCC8B94ULL,
		0xE6A077EC78AF149EULL,
		0x03F85712024B4E0AULL,
		0xEF0EE235268B49DCULL,
		0xF84CB13BD9759297ULL,
		0xA4C034A11DEDB803ULL,
		0xE28708A50B6B62C7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x29A63A1B128BD96EULL,
		0x4A7EAC3F1D0180B9ULL,
		0x2AF8F000556F7352ULL,
		0x111EDA538BF4B9BBULL,
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
		0x76241BB0C04AE11EULL,
		0x46E0579C17100119ULL,
		0xA6AC16B5574F2BA2ULL,
		0xDCF64F0326ABCE05ULL,
		0x45B76CC6AB60B8C4ULL,
		0x133EDA3690225516ULL,
		0x9FB6701322FE9744ULL,
		0xA4CAAC6D026880C1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB79217C34B917BB1ULL,
		0x5A608616C5B23355ULL,
		0x63B8568BD082D298ULL,
		0x232A104D4EB14B6AULL,
		0xB868CC40D2EE6AF7ULL,
		0xE934AB5EB2CED1D3ULL,
		0x3F7CFE226D5DB22CULL,
		0xF364D166FDBE736FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB83DD7CB95B0F039ULL,
		0x2A02C5902BC349A4ULL,
		0x8B7AA9E47CAE5A7AULL,
		0x0EEAC19A89387CD5ULL,
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
		0x11CD1CDDF2752C87ULL,
		0x3E7384FB0B7298F2ULL,
		0xD449765D01619C88ULL,
		0xE2078AC300A39216ULL,
		0xB56FB73660B568F3ULL,
		0x398687798C401A57ULL,
		0x9488F758D126F4F8ULL,
		0xD5D10B07B29C1287ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x24D6904CC7378E90ULL,
		0x1119F50DA68F4687ULL,
		0x431C7A54F1EA520BULL,
		0x8FD41FCF53A260E3ULL,
		0xEB9E0C35B6C697D5ULL,
		0xF960F815D41B350BULL,
		0xDB5B5194E1FA750EULL,
		0xDFD6C48854F21673ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE215EEAA64B0A832ULL,
		0xB2ECD8BABA5D5BAAULL,
		0x0DF3971D9012471CULL,
		0x5559E1DB943C9C21ULL,
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
		0x529FF320F05EF056ULL,
		0xC2AF380AA8029F2AULL,
		0x16F09E73A21CE1B9ULL,
		0xD63061B8742691FDULL,
		0xE17B8381D8B76CE2ULL,
		0xDA8918AF8656B1FCULL,
		0x4AD5EB7CAC2645B6ULL,
		0x65CBDE4B5B957FBDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF6527F7FFB99A991ULL,
		0xD0F8E2462FAE08CEULL,
		0xE60C781FCF028D3DULL,
		0x4789D6B0D4FE486DULL,
		0x24A65DA631E79377ULL,
		0x4D54CD5C99D0FDE6ULL,
		0xD273C779BC2B4734ULL,
		0xD853C29231547552ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x63F1123BB79F8A34ULL,
		0xE7798413942D51BBULL,
		0x0F757EC3725C1BDCULL,
		0x0E7AA883E4CFD55DULL,
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
		0xBA51AD51F87D5C09ULL,
		0x8405C528A9BA360FULL,
		0x794131374DEA1118ULL,
		0xE9C3B93F023A2F1FULL,
		0xF297586004BB513FULL,
		0xBB5C16D11C03C8E1ULL,
		0xE1B6102FD295687AULL,
		0x478B13AD585E20F0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEFDA52D6D55E29BFULL,
		0x992F4413BAD84D4FULL,
		0x7E2911D825E90485ULL,
		0x5E09B593876CE462ULL,
		0x6B8084D34B721583ULL,
		0x263EAF57FCB8F0CFULL,
		0x390E68420A360466ULL,
		0xFD470A98BA17B766ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD7DAC15EA3FE0C43ULL,
		0x0D33DD0F93FDFB7FULL,
		0x03FB0CAAE629E7A1ULL,
		0x11D35CBAF940F552ULL,
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
		0x1529846298378F14ULL,
		0x622F07EF4296D870ULL,
		0xD774D9A0A5D7545AULL,
		0xB8DDD1148EAA29ACULL,
		0x831256E9DD384296ULL,
		0x2EDAFF1A94258EC8ULL,
		0xEFF72EF0B3FAE5E5ULL,
		0xE5E134F10E27AEF2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x79A1A413D7C2B1CBULL,
		0xC8285330C36501C3ULL,
		0xD5510DA368A11042ULL,
		0x063715E40C056130ULL,
		0x6F5606D2829E2D29ULL,
		0x1FFA357FDD98AD63ULL,
		0x2CD2446C0EC6CB5DULL,
		0xC648E8260394D780ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x897BC3C633540C35ULL,
		0xCF64A1B5981B4BADULL,
		0xF99E9BADC2F23449ULL,
		0x634221541470C384ULL,
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
		0xB669FF3F7D2CEA00ULL,
		0xCDBDB363E16EA7A4ULL,
		0x4690E0C19DCF1000ULL,
		0x8993721F3800A199ULL,
		0x685325B289754F82ULL,
		0xD954E77C9AF0AC15ULL,
		0x9CF62FADBA41A0ECULL,
		0xEB887FEB7C121D96ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAA2E15317CA70102ULL,
		0x4C4082FAC6D4E832ULL,
		0xA090A865CDB572E9ULL,
		0x96D1514BBC1613B6ULL,
		0xE3BF570032C47D29ULL,
		0xBA7987CDA3372413ULL,
		0xCB64EA24789DC7D1ULL,
		0x90BF47DD21AFEAE0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBA2C9886DEC52422ULL,
		0x160D6461E023EFABULL,
		0xC1908ABB8E6BD71EULL,
		0x6CA072F4E67E14DFULL,
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
		0x7D0D4C27DEC7C035ULL,
		0x87553F84BF7545C2ULL,
		0x002E35F2426D1985ULL,
		0x3B02DE519A981963ULL,
		0x3D214F97232B92DBULL,
		0xBD2A70E9A6CD83CBULL,
		0xAAA0C0F294560D66ULL,
		0xE2E392A2FE9F8713ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9371643F108224EFULL,
		0x921D2E5D5F779524ULL,
		0x443260B8C7983142ULL,
		0x4050EAF1E7E6C8E6ULL,
		0x263D9D982BBF409AULL,
		0x7F26C08E1F3BBA7AULL,
		0x04E22570912D0322ULL,
		0xA9BB7EAFFBD764C9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4F6853C18859D21CULL,
		0x29C43EBD7FA192A7ULL,
		0x5646EA85F2EC6E64ULL,
		0x76A4E9721C666791ULL,
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
		0xD194EF9AC23D02DDULL,
		0x1C6C12E7C4CF2E51ULL,
		0x85C5E5F17258234BULL,
		0x5633DC336B4DA21EULL,
		0x8F6E2A3E24E125F9ULL,
		0xA696D9E8EB0C73FFULL,
		0xD7131D452AECB307ULL,
		0x9F7BA85C4DE4C90DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x73022C5FBEF780D1ULL,
		0xDAF0A4203C957D6FULL,
		0x4C9B7B9EF98DE921ULL,
		0x72914C837BC1ED01ULL,
		0xCFE8D3BBD7AACDFAULL,
		0x2964107EE55D7912ULL,
		0x17E0AC7A3937BA47ULL,
		0x217322D300F547B6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCC5D9A92795694A5ULL,
		0xD70554846032F006ULL,
		0x9AA7287259A726BBULL,
		0x18E662115B18E823ULL,
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
		0xA14FFAE3514508FDULL,
		0x73135824DBB2AE60ULL,
		0xA9814FB2BD95D131ULL,
		0x908BCD86BFA613D3ULL,
		0xD7A9B54EEC9912BCULL,
		0xE62C623F1D546114ULL,
		0x8D91258835887342ULL,
		0xE620AE646C0D2D1CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA4FA150293A38611ULL,
		0xE721E35811799BB2ULL,
		0x0A4FC378BEC6F883ULL,
		0x0AED339730004D44ULL,
		0xC931E2A30CFC6B3EULL,
		0x1E9F39C21E06274CULL,
		0xDBDC755CB5CEC613ULL,
		0xB3BF6B5B1B5934AEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x221F2B63EEE260D0ULL,
		0x2AE5775AAFD5A660ULL,
		0x0003B2AEF45E8DC5ULL,
		0x000E8D518A5CA6D8ULL,
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
		0x8832BB60BFBF5B8BULL,
		0x0B3DA79D56AF74CDULL,
		0xF67184C9C0D5269CULL,
		0xC06A16652BF75013ULL,
		0x7396C77A364096CCULL,
		0x598A82E14B582411ULL,
		0x55D7F93874020E48ULL,
		0x7C3D7EE0EF7C538DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x56F0C2A5500D3359ULL,
		0xAF1DED6292FFF2CCULL,
		0x6F834B782F18D30EULL,
		0x4B51225413BFBD45ULL,
		0x8A8336A4F9654B26ULL,
		0x0EF35EFB190893F2ULL,
		0x24DCC536CBBB67E5ULL,
		0x65A99EBC83798884ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCA297862783F635BULL,
		0x6E8F0E663B7EE697ULL,
		0xCC37F1908C39064AULL,
		0x4F0C397920A1B62BULL,
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
		0x5965D7F982B33A6FULL,
		0x0C82A7979A0F9807ULL,
		0xD97CC711D014EF33ULL,
		0x58A11F70A2835900ULL,
		0x7D75E6157595509AULL,
		0xD6D922350AAD457FULL,
		0x218D0A5FDB240204ULL,
		0x0AEEE8DD1DCB0568ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xABDC1CF5B57A577BULL,
		0xEFB75B05180B7E58ULL,
		0xF1750D2D528FDC46ULL,
		0x6E73ED1D2B046558ULL,
		0xA6114DA47AD1B24EULL,
		0xF3D5743D6E620C64ULL,
		0xC5A959B79E843ECBULL,
		0xD830B0DE8FCEA4E9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA6785BC906425DA2ULL,
		0xCF571F53B52E93AAULL,
		0x8BD3F2DD7D3C0D5DULL,
		0x7269821C8AF54669ULL,
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
		0x72128C70B054DBE9ULL,
		0x31C751D4D1D4C944ULL,
		0x773711BA5918AB28ULL,
		0xDF0E131B6B42095AULL,
		0x5111267F41571BA3ULL,
		0xB6EF3308D7137353ULL,
		0x76456839FF205C4BULL,
		0x71BC531D055CCB96ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x600221AC6FBAAD7EULL,
		0x20A6892DE14FE6E8ULL,
		0x68E75DFFC5EB64E7ULL,
		0x246B1A360E2DFD69ULL,
		0x86112516F4ED94C8ULL,
		0xB3C7FCC494BAFD23ULL,
		0x29025E0EFC351B84ULL,
		0x68B500D78956EFDDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3410A03F98443339ULL,
		0x88F2D6C8C9A66D74ULL,
		0x8643361D0218E3CBULL,
		0x11B92F35C5F2A972ULL,
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
		0xF194F5B00F98882BULL,
		0xF46E9780D0AE0B71ULL,
		0xD3C69624253C9731ULL,
		0x254AED322F081493ULL,
		0x50E9C6FD4831C89EULL,
		0xE21BD5332734A500ULL,
		0x52BC8E24710E19CDULL,
		0xF2ABA8C13BE9F23EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4E357605C8D5936DULL,
		0xBC1C572A27201E6FULL,
		0xC34AF3422DC423FFULL,
		0xD5C0B70030D973E2ULL,
		0x750F4742C84B3B56ULL,
		0xD6066256C0102C8CULL,
		0xEF0CCC12B98D8C34ULL,
		0x5B37CCCC323E1B1AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x45CE755942FBF09FULL,
		0x03814D0DF8F7CE35ULL,
		0xDC927183348D77EAULL,
		0x4ABCDC916DB08FF1ULL,
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
		0x1005E5B9DA4C23C9ULL,
		0x9B636FC6B6E217B3ULL,
		0x79FB213D7E684AFBULL,
		0x9B9A315F2486F99CULL,
		0xA47B23F19708BA99ULL,
		0x72AB47ACDEBF141AULL,
		0x47741FDFB9398B6CULL,
		0xA41896B3F4B8405FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x61DF237AC26FEBB1ULL,
		0xC696F43B6D2C7127ULL,
		0x6046D62887D4BD40ULL,
		0x668EB2AF69EEF9B9ULL,
		0x6C219A01ED345297ULL,
		0x7BA9D8CC784413A4ULL,
		0x479525515F9F1699ULL,
		0x4DD4836300C08C4EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0B713BD24D63AA52ULL,
		0x7F02F0DA7FF7B818ULL,
		0x14CD7C364380E50BULL,
		0x03265CB3F15CBA69ULL,
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
		0x398ED707B027E99BULL,
		0xA713D1937C201B6BULL,
		0x123C725E92C1968AULL,
		0xF1E2B0A7F303B909ULL,
		0xE135FB5D27F4E1DFULL,
		0x08DE7D61ED4A7524ULL,
		0x7A5DA56AC595F03BULL,
		0x37FF46CF3B094E50ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD9C679FF64FB5854ULL,
		0xEB563BA953649156ULL,
		0x6F29C3B669773413ULL,
		0xC5DE469C5B2B0CD0ULL,
		0x7BD895093C702095ULL,
		0x01C7C5711C58AAA3ULL,
		0x37072744BE348DA7ULL,
		0xC6FF9E7B977F62E1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6BA58D7D40E13F12ULL,
		0xC91CE3A92C9F9949ULL,
		0xA1E9684D41BF046FULL,
		0x71F76675DE519EBCULL,
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
		0xE716A89C88A1B0CEULL,
		0x7D7630DC7879748DULL,
		0x85F20652009AFF71ULL,
		0xAAED6505A2537C4DULL,
		0x014087BD8C253071ULL,
		0xBFA9128EBA5DF972ULL,
		0x4808F2D7F87C679FULL,
		0x7A0F3A909E9C3B34ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA095A35E56ACA283ULL,
		0xAF86F44A0E9EBD67ULL,
		0x6666D7D470C303C1ULL,
		0x48854F2AFA5006DEULL,
		0xF5ADE356A1DF6B96ULL,
		0x1E49CEE5A3605D68ULL,
		0x7E5D5E68C81EB91EULL,
		0x56763F755F96E893ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFE456C84F850479EULL,
		0xC21347ABD37FE07DULL,
		0x0F0336FEBDBFE2EDULL,
		0x2B1D5BE602CDB94DULL,
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
		0xDC8C415640AD1A1CULL,
		0x2A218F9883322FBBULL,
		0x5347B188EFFEBD42ULL,
		0x607AE086995532BDULL,
		0xE824F7EC8B5EE5A2ULL,
		0x8177A098788405F2ULL,
		0x81268C0FCA18C273ULL,
		0xCEAC68DF1108EAE7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x56019E0872A7B3C1ULL,
		0x5AF7EB326DFBD6C4ULL,
		0x7396DB0AFB9A9E7CULL,
		0x4F11533787D0F7D0ULL,
		0xE0E960A65533EB0CULL,
		0xEE3304AE9F0DA5A9ULL,
		0xE2FC3EA8688E22ECULL,
		0x9D75B3C674A24C1CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x996317B9D86699A9ULL,
		0xAB58C91C5CC8A3CEULL,
		0x59F853D66EF7CCBFULL,
		0x5F886EF648BFCD00ULL,
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
		0x2A00692FEF47E8C0ULL,
		0x24C5874857D3FFAFULL,
		0xC588D76620764117ULL,
		0x2762FB24A1C6ED17ULL,
		0xEC55DB63F2BC3870ULL,
		0x6130282D65285066ULL,
		0x9535630C097FDB25ULL,
		0x7C1C4AC40226DBCEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB5B4E49E371E878AULL,
		0x67A66AC92A19A391ULL,
		0xA05A34725BE73720ULL,
		0x44F213B03FF4EFD3ULL,
		0x24C6C784D3171C03ULL,
		0xB728002DA20A6104ULL,
		0xEAB288474C5944BDULL,
		0xA16C91FF76C3D443ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x138877B06AAB9880ULL,
		0xFA550C76242BE4C7ULL,
		0x749B1C27D8495D59ULL,
		0x588654A112851BD9ULL,
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
		0x7EFDD09A726F0543ULL,
		0x4B0D601B4047A312ULL,
		0x98CACA808F71D0DCULL,
		0xE5AFD71ED543D12AULL,
		0x2B47B82B62C7F226ULL,
		0x91B6B0DBDC2CCA6CULL,
		0x77EC39893AAE244AULL,
		0x1FCE37072FF5087DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8E7822AE7CE43BE8ULL,
		0xB9FCC0C6C69E2A5BULL,
		0xD4667F709E891F40ULL,
		0x61B3A1ADFC327FD9ULL,
		0x1BFAB3FCE4037E36ULL,
		0x5D87CE6197ED3591ULL,
		0x61768EED0339EC6CULL,
		0x90936BE0C359C735ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x35F44CD2C6B3FC88ULL,
		0x50063D7A9B19913BULL,
		0x19DB9E402C28FC97ULL,
		0x46B65D24F81D0204ULL,
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
		0xA86E6B69144C1BB9ULL,
		0x9BFFF061CE5708FCULL,
		0xBFBA46B1A14802ECULL,
		0xA9AC09AA0AB3FAC1ULL,
		0xC7E2CC4C0C8EB08DULL,
		0xB7E174D6E846D1E5ULL,
		0xAF041242A3AFB0A4ULL,
		0x8A05DBC018D17283ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEF4CD039D32D5455ULL,
		0xC97BE537A95D4167ULL,
		0x15ACB8DB0CB3E9E2ULL,
		0x93CE953A99B06FDEULL,
		0x4115129E76F4FD71ULL,
		0x30FA1647EF5E1FD2ULL,
		0x1C586F73AEAEF29CULL,
		0xAF4A486F799E7EDFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBBAB2AF375EF5CBBULL,
		0xD8DC14631784367AULL,
		0x6F87B88EF2B04E4DULL,
		0x0DB552671293B551ULL,
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
		0x2FECE47B391ECD45ULL,
		0x41168F0A715EAF91ULL,
		0x9ED1805CFCDAC0FCULL,
		0x1A846DE6E18AA9B6ULL,
		0x9B5BF0DB9A24A92EULL,
		0x284FE87C70E3F281ULL,
		0x086DD2E7714FE64BULL,
		0xEAD8C650B6464D88ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x21EA319C727E6203ULL,
		0xF55EC95CBA45F81EULL,
		0x2A98A455A0BAC344ULL,
		0x8974E64EB47D2120ULL,
		0x22025368DBD5D9F3ULL,
		0x443B14CC277C7716ULL,
		0x9197EB893F19FB72ULL,
		0x1DBBACFE7888AEB4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x115011E706533278ULL,
		0x26CF31D89C750967ULL,
		0x17F93402D020D9E9ULL,
		0x036149CD57331BFAULL,
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
		0xD18B93C710D7D534ULL,
		0x71CB07D18EAFEE91ULL,
		0x30AEC7C46EE9261EULL,
		0x1D09F14ABFB7C527ULL,
		0x6408E8C44A989ED7ULL,
		0x3C979DBFC473EFA5ULL,
		0xBEE211A990D7D14DULL,
		0x4D875116C1984BCEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x02E0523F38CB07CCULL,
		0xF81D833BB8953C4CULL,
		0xF5E0C38DF8FD6D96ULL,
		0xF4407AB0565B33F0ULL,
		0x44B07B4279534E07ULL,
		0x590BD61D2281C90DULL,
		0x78138654A9A00D33ULL,
		0x9512E45C54865FFDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x75CB82CCE856CA93ULL,
		0x406D26B9E00C6CDAULL,
		0xBD76B2D0C832D45FULL,
		0x0A119A469A059246ULL,
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
		0x9FA6DD4CAD49ED2BULL,
		0x4330155D9D202AF9ULL,
		0x70D81C8C4EAA1274ULL,
		0xAB8A5BB222CE901BULL,
		0x65629181515818FFULL,
		0x32787330B5FAF8CDULL,
		0xB2237367267FFB89ULL,
		0xF38804A04949F4F5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x81DB0A95C3B695D3ULL,
		0x16067E511CBA2C20ULL,
		0x48BA2A2F51F1A43DULL,
		0x5E8D5153E2965769ULL,
		0x615C4AE41E946ACAULL,
		0xFF7512DA0D6043D0ULL,
		0xB6318FC6FB2B311FULL,
		0x53947CC148CABEEBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB6BA4E0C729F36C6ULL,
		0xBFA9E3E9875CDC67ULL,
		0x8E05BC236B4E79D4ULL,
		0x0B233578531A3E2DULL,
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
		0x4F595455242A3465ULL,
		0x7C3ECE078E75AC59ULL,
		0x4807E6A310413485ULL,
		0xF192CCB6338EA9F2ULL,
		0xF48CC33261F1DEFCULL,
		0x10A5D8E91D6E4DE6ULL,
		0xA7DA735D15B40E81ULL,
		0x29B54A5467E386D0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x44435BD6AA9A0E74ULL,
		0x7718B0B06FAF4364ULL,
		0x53F2088C4603043FULL,
		0xCCB50812526CAB0CULL,
		0x435F961A950925B2ULL,
		0x96B70EE903FD135AULL,
		0x39E8266DE5838A3AULL,
		0x969B73B438E9F79CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x57CAAA06E41BA47AULL,
		0x1E98195AE59519D7ULL,
		0x460D4997F171D2BCULL,
		0x7AB3A06ADA2D40AEULL,
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
		0x13CB5C82D852D1FEULL,
		0x2FCA901FC63DD909ULL,
		0xF24A9ED8C7C7D3E5ULL,
		0x16C22BFD15D9EC32ULL,
		0x4A31BBA87E674397ULL,
		0xD0C3B8D0DAA8081FULL,
		0x235C8640D0AAA7F0ULL,
		0x7D1E1911CD8CD791ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9B5EEFAF628F6BB9ULL,
		0x482D7F3FDCEBA3FFULL,
		0x328063721C421A58ULL,
		0x2C22C9FE06343319ULL,
		0xB48E8019871F1EB9ULL,
		0x1210F67C4C781146ULL,
		0xF060851E569C2E13ULL,
		0x33D0FC8A4F7BA9B4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAEA7440C2A78E0C8ULL,
		0x3625E96D0470D92FULL,
		0x51326684C9ABD077ULL,
		0x4C119E1BC63287C9ULL,
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
		0x23F2EC0C025BC120ULL,
		0x4B031F93AA1CA356ULL,
		0xFA3D4A5C9C1A4D0AULL,
		0x6A37B5416D871B4FULL,
		0x9B27715C3279DB52ULL,
		0xB2CE575FB372B789ULL,
		0x422B1C6815EAC6BEULL,
		0x6A4CAAB08092ACA2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x819F6661F273E85CULL,
		0x2C95EEFBFEED616EULL,
		0xC46EB10CBECB683EULL,
		0xCCAAE280E0E1BA89ULL,
		0x787A97F7058BFEA4ULL,
		0x84619B9EE24B330BULL,
		0x743DFC3F62431976ULL,
		0x1A91EBA13618050BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC7FBCAAEBB369C3AULL,
		0x02910F36B70CECA0ULL,
		0xC7015F5A88329D83ULL,
		0x73452F059ADA4128ULL,
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
		0x1AF9F9284C21E840ULL,
		0x9D26C5F844E3EF11ULL,
		0x554933741E45C670ULL,
		0x6E18A9422ECCB91FULL,
		0x78B1559BD54E668EULL,
		0x1E978AB6ACDC1695ULL,
		0x56325E662E842178ULL,
		0x45F5049BEB8CD9EDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4474B29B9206F874ULL,
		0x0C262939AC0EA5BCULL,
		0x9DF0816A38A62783ULL,
		0x9FE94B14B8228537ULL,
		0x61BEED0AFAB0DEAEULL,
		0xF00A3859ACBB06C8ULL,
		0x439344DB89A961F8ULL,
		0x867E761E620270F1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3E80CC0D2D7D1990ULL,
		0x79FAD68C9DBDA1C6ULL,
		0x7AF67C9E5E180BCEULL,
		0x39C884CFE135C952ULL,
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
		0x7184D57CFC344AE7ULL,
		0xB8A0560B872F2E38ULL,
		0x403DD338C70F461FULL,
		0x362E5F009680EE75ULL,
		0x182506BF7F05F849ULL,
		0x8C57763760FA82E3ULL,
		0x3A76D668876616DCULL,
		0xA249A09574156BEDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4D041E1E8D4E36F7ULL,
		0x821C6178E76E8A04ULL,
		0x94CF346869D130B2ULL,
		0xEE882085D4985CFFULL,
		0x3BDF01A8ABCAB81AULL,
		0xE494347A9A4DA25AULL,
		0xE5B02C238164148EULL,
		0x2344315974ADFF56ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD6E578C1C9B19D96ULL,
		0x1D7FB6981D69F884ULL,
		0x40EBE50F418A6CF4ULL,
		0x2274C162AB42AFC6ULL,
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
		0xA4B8FA075F65CB2BULL,
		0x52DF37E6EF2D5913ULL,
		0x2AB6B63512E3CE61ULL,
		0x9C0ADBAFB02B3376ULL,
		0x201DE3EBD9670C01ULL,
		0xF4C59CF054DD454DULL,
		0xA244A65D07094C58ULL,
		0xDC99616CF872B715ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5F16855E28CFF4DDULL,
		0x261E56246D7DDF01ULL,
		0xCE1A6051F67013B8ULL,
		0xDBFA7DF90BFD913CULL,
		0x0901FBCC936B2769ULL,
		0xE8D233C38C4D2E32ULL,
		0x9561C45C51676C18ULL,
		0x61EAF80C836C09B3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB3C6E94D99F9C777ULL,
		0xF2E27E684712E817ULL,
		0x4649E1FE127B042AULL,
		0x75F40208032B5EC7ULL,
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
		0xD415A82076478A0DULL,
		0x72C786AC43853BEBULL,
		0xAB25932D5754B675ULL,
		0x1455C3B4E8A887FBULL,
		0x60C173093718867EULL,
		0x3FDA1C5379A76513ULL,
		0x60200D160BB9193EULL,
		0x82539A6AC2662C15ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x18DD1ED2E991ED5BULL,
		0xA75479B92D0C6C9AULL,
		0xDFC41966B38BFA6FULL,
		0xB8DBB001EEC74584ULL,
		0xF47A5171513280E9ULL,
		0xE12F5E02AB16727DULL,
		0x2CD61B79F397E248ULL,
		0x508ADAEC7AF15F08ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCDC785D9ACDA71C7ULL,
		0xD8CB4CF1BFFCD17FULL,
		0x685B56F238B6E471ULL,
		0x3F4680719537B26CULL,
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
	printf("Test Case 201\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 201 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -1;
	} else {
		printf("Test Case 201 PASSED\n");
	}
	printf("---\n\n");
	return 0;
}