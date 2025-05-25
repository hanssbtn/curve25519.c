#include "../tests.h"

int32_t curve25519_key_x2_test(void) {
	printf("Key Doubling Test\n");
	curve25519_key_t k1 = {.key64 = {
		0x540B85F1337B05DAULL,
		0x86ADBB537749E746ULL,
		0xF0B8C748A0EE368BULL,
		0x060466AD46A3F945ULL,
		0x3CD29F893DFECFF6ULL,
		0x10FF35A304EBC762ULL,
		0xC94FFD4AB9DBF51EULL,
		0x106919598D209BA6ULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0xA8170BE266F60BB4ULL,
		0x0D5B76A6EE93CE8CULL,
		0xE1718E9141DC6D17ULL,
		0x0C08CD5A8D47F28BULL,
		0x79A53F127BFD9FECULL,
		0x21FE6B4609D78EC4ULL,
		0x929FFA9573B7EA3CULL,
		0x20D232B31A41374DULL
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
		0x60DC2EBBC6FBBB4AULL,
		0xCA4B2A64B9350533ULL,
		0xC7D71BB882CECBFEULL,
		0xB30459F8428E87CBULL,
		0x94AE2746164C8F36ULL,
		0x7DAD036979EF4906ULL,
		0xC6CE7A5C18C54C3CULL,
		0x17BAC2C66F891CF6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC1B85D778DF77694ULL,
		0x949654C9726A0A66ULL,
		0x8FAE3771059D97FDULL,
		0x6608B3F0851D0F97ULL,
		0x295C4E8C2C991E6DULL,
		0xFB5A06D2F3DE920DULL,
		0x8D9CF4B8318A9878ULL,
		0x2F75858CDF1239EDULL
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
		0x741EB29A8D0B7B2AULL,
		0xA04C7E840C119C11ULL,
		0x9E2D2E94837F1EF8ULL,
		0xD3EEABF2DE7A8F1BULL,
		0x2310F953CB7D5169ULL,
		0xEA5F44C2C0482F58ULL,
		0x7F945E8123AC8A4DULL,
		0x0A8B0F0336DBEF19ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE83D65351A16F654ULL,
		0x4098FD0818233822ULL,
		0x3C5A5D2906FE3DF1ULL,
		0xA7DD57E5BCF51E37ULL,
		0x4621F2A796FAA2D3ULL,
		0xD4BE898580905EB0ULL,
		0xFF28BD024759149BULL,
		0x15161E066DB7DE32ULL
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
		0x491E6BDDB54DFA39ULL,
		0x06825643624386D9ULL,
		0x38E4CDCF8F518E1BULL,
		0xF8252B10A18312E2ULL,
		0x76441ECEF873C788ULL,
		0x383720F1689F80C0ULL,
		0x7513C78C987FB847ULL,
		0x26A902BD8058A9B1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x923CD7BB6A9BF472ULL,
		0x0D04AC86C4870DB2ULL,
		0x71C99B9F1EA31C36ULL,
		0xF04A5621430625C4ULL,
		0xEC883D9DF0E78F11ULL,
		0x706E41E2D13F0180ULL,
		0xEA278F1930FF708EULL,
		0x4D52057B00B15362ULL
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
		0xF123D66181C3F22EULL,
		0xFE78330B8D6352BFULL,
		0xCEB92893E784B6A6ULL,
		0x8A420B3DD937848CULL,
		0x62FA66F78E410F70ULL,
		0x6AB0F044129376B9ULL,
		0x4F62849F9FCC7084ULL,
		0x06522A53B0CD9260ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE247ACC30387E45CULL,
		0xFCF066171AC6A57FULL,
		0x9D725127CF096D4DULL,
		0x1484167BB26F0919ULL,
		0xC5F4CDEF1C821EE1ULL,
		0xD561E0882526ED72ULL,
		0x9EC5093F3F98E108ULL,
		0x0CA454A7619B24C0ULL
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
		0x950B9D1BF2323C82ULL,
		0xF0CEF4DF9FC2646CULL,
		0xC33818DDBA43F053ULL,
		0xC9824596ABF5221AULL,
		0x6CF6719C61CC3261ULL,
		0x615A0A8FDBFC8BEFULL,
		0x70A36EFD838B86B4ULL,
		0x1AC68268303DAB8AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2A173A37E4647904ULL,
		0xE19DE9BF3F84C8D9ULL,
		0x867031BB7487E0A7ULL,
		0x93048B2D57EA4435ULL,
		0xD9ECE338C39864C3ULL,
		0xC2B4151FB7F917DEULL,
		0xE146DDFB07170D68ULL,
		0x358D04D0607B5714ULL
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
		0x30361B75A7483FB8ULL,
		0x704DA4134BFCF5B5ULL,
		0xD3F7C2C851599B35ULL,
		0x631A924F1B2DA4C9ULL,
		0xF64F9947E7DF3AB4ULL,
		0xC1C0062FDEE7100FULL,
		0xFA4ACE33BF5D11A0ULL,
		0x19CA97693534BFC3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x606C36EB4E907F70ULL,
		0xE09B482697F9EB6AULL,
		0xA7EF8590A2B3366AULL,
		0xC635249E365B4993ULL,
		0xEC9F328FCFBE7568ULL,
		0x83800C5FBDCE201FULL,
		0xF4959C677EBA2341ULL,
		0x33952ED26A697F87ULL
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
		0x388FE8F90879BD13ULL,
		0xFD9F22A7436F8A93ULL,
		0xE5F0A513CAEDA9B9ULL,
		0xCDD2E768B63F667AULL,
		0xD44D33986121703CULL,
		0x69E5B8E0869BCF93ULL,
		0xCF9E35F58E7C5B62ULL,
		0x0E8505DD73C46E3AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x711FD1F210F37A26ULL,
		0xFB3E454E86DF1526ULL,
		0xCBE14A2795DB5373ULL,
		0x9BA5CED16C7ECCF5ULL,
		0xA89A6730C242E079ULL,
		0xD3CB71C10D379F27ULL,
		0x9F3C6BEB1CF8B6C4ULL,
		0x1D0A0BBAE788DC75ULL
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
		0x7D81296244724DE3ULL,
		0x03B718F73DB934FEULL,
		0x2FF1DB4496F0AD30ULL,
		0xCDB314BE1E14BCEDULL,
		0x210972B40FB801DFULL,
		0x17684E6DBBF81065ULL,
		0xEED78D0C0E2F22B7ULL,
		0x23ABB08C43E49E68ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFB0252C488E49BC6ULL,
		0x076E31EE7B7269FCULL,
		0x5FE3B6892DE15A60ULL,
		0x9B66297C3C2979DAULL,
		0x4212E5681F7003BFULL,
		0x2ED09CDB77F020CAULL,
		0xDDAF1A181C5E456EULL,
		0x4757611887C93CD1ULL
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
		0x939D0084C9A8896BULL,
		0xEDF3031E905BA2A7ULL,
		0x5B2BF13070C95E49ULL,
		0xC680DBCC448C1F92ULL,
		0x21DB68163C8324D6ULL,
		0x6B271650A4A7CBDBULL,
		0xC29D981F8F5C6476ULL,
		0x2D20A2B894C88714ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x273A0109935112D6ULL,
		0xDBE6063D20B7454FULL,
		0xB657E260E192BC93ULL,
		0x8D01B79889183F24ULL,
		0x43B6D02C790649ADULL,
		0xD64E2CA1494F97B6ULL,
		0x853B303F1EB8C8ECULL,
		0x5A41457129910E29ULL
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
		0x642BBE1B0C6DFE5CULL,
		0xDA649C303BC12723ULL,
		0xC9A480143074ACAAULL,
		0xEC77FFFB8B207E47ULL,
		0xA219FCCD40E9325DULL,
		0x88B79AA1DB60D59AULL,
		0xFE818C0C79594EE8ULL,
		0x217732AD5F4E8230ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC8577C3618DBFCB8ULL,
		0xB4C9386077824E46ULL,
		0x9349002860E95955ULL,
		0xD8EFFFF71640FC8FULL,
		0x4433F99A81D264BBULL,
		0x116F3543B6C1AB35ULL,
		0xFD031818F2B29DD1ULL,
		0x42EE655ABE9D0461ULL
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
		0xEB2C5479A2D27496ULL,
		0x251D4349B2CA0ED4ULL,
		0x34E35E69F50923C5ULL,
		0xF87CA37D1CD4B7C1ULL,
		0x434D7E01C710AC05ULL,
		0xFEFC2BE900EFED55ULL,
		0x2336BA725AFF0663ULL,
		0x14F3B6A9E0BCA1AAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD658A8F345A4E92CULL,
		0x4A3A869365941DA9ULL,
		0x69C6BCD3EA12478AULL,
		0xF0F946FA39A96F82ULL,
		0x869AFC038E21580BULL,
		0xFDF857D201DFDAAAULL,
		0x466D74E4B5FE0CC7ULL,
		0x29E76D53C1794354ULL
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
		0x53EA096BFF1CA923ULL,
		0x475785F99999CBFAULL,
		0x38FEBB37AC220AB9ULL,
		0x8DBDB1FD54B066F2ULL,
		0x33FCD2ACCABA1827ULL,
		0xEE7FB07CB752006BULL,
		0xED1B4E4296F8C6DBULL,
		0x3A0DD36D623BF69CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA7D412D7FE395246ULL,
		0x8EAF0BF3333397F4ULL,
		0x71FD766F58441572ULL,
		0x1B7B63FAA960CDE4ULL,
		0x67F9A5599574304FULL,
		0xDCFF60F96EA400D6ULL,
		0xDA369C852DF18DB7ULL,
		0x741BA6DAC477ED39ULL
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
		0x94BBF780D581C5DCULL,
		0xCB0960C65AF608C7ULL,
		0xD0FA69EF199D53DDULL,
		0x86E3E5D4A23A363FULL,
		0x13509B82DBFBB2D7ULL,
		0xF8D82E4FDFEAF786ULL,
		0x19CB5B19E634D02FULL,
		0x2836E97806AA82D6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2977EF01AB038BB8ULL,
		0x9612C18CB5EC118FULL,
		0xA1F4D3DE333AA7BBULL,
		0x0DC7CBA944746C7FULL,
		0x26A13705B7F765AFULL,
		0xF1B05C9FBFD5EF0CULL,
		0x3396B633CC69A05FULL,
		0x506DD2F00D5505ACULL
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
		0x992CD2F8FC90902DULL,
		0x64003A120ED0757CULL,
		0x5E10E45D10D1E78EULL,
		0xB44F920BE0E83B87ULL,
		0x3AB32164D0DEC9BFULL,
		0x9CA4E8C2053C3F6DULL,
		0x3D49C5BE4452DB75ULL,
		0x0A96FE6CF2800B88ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3259A5F1F921205AULL,
		0xC80074241DA0EAF9ULL,
		0xBC21C8BA21A3CF1CULL,
		0x689F2417C1D0770EULL,
		0x756642C9A1BD937FULL,
		0x3949D1840A787EDAULL,
		0x7A938B7C88A5B6EBULL,
		0x152DFCD9E5001710ULL
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
		0xADF1E2887B843368ULL,
		0x014B831E05345EF6ULL,
		0x3B3348F52A830D94ULL,
		0x4B9EEB13A17E0220ULL,
		0x85575F2DF4D68119ULL,
		0x94B084B57766F7A8ULL,
		0xDE2EADC57782852EULL,
		0x15AA477048B0CFEDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5BE3C510F70866D0ULL,
		0x0297063C0A68BDEDULL,
		0x766691EA55061B28ULL,
		0x973DD62742FC0440ULL,
		0x0AAEBE5BE9AD0232ULL,
		0x2961096AEECDEF51ULL,
		0xBC5D5B8AEF050A5DULL,
		0x2B548EE091619FDBULL
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
		0xA4B93B35123819E9ULL,
		0x03D14D0058958AC0ULL,
		0xFB34967AA26DC65CULL,
		0xE3B98CBF9CC18D52ULL,
		0x718BD741FE0632C2ULL,
		0xAAE8A39E9BA96265ULL,
		0x79BE12C13880CA4EULL,
		0x2614864FFCAF710EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4972766A247033D2ULL,
		0x07A29A00B12B1581ULL,
		0xF6692CF544DB8CB8ULL,
		0xC773197F39831AA5ULL,
		0xE317AE83FC0C6585ULL,
		0x55D1473D3752C4CAULL,
		0xF37C25827101949DULL,
		0x4C290C9FF95EE21CULL
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
		0x2B612EAB5EB8CD7DULL,
		0xB71B68BBF0C6C452ULL,
		0x63C7F24D5531B1D4ULL,
		0x01CEE88C6A3EAB4CULL,
		0x6E92C368CBD9FAF9ULL,
		0x3F3947E2B7D3E14AULL,
		0x5D5A4942B038AD8AULL,
		0x04DB6ED3AE38DDE0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x56C25D56BD719AFAULL,
		0x6E36D177E18D88A4ULL,
		0xC78FE49AAA6363A9ULL,
		0x039DD118D47D5698ULL,
		0xDD2586D197B3F5F2ULL,
		0x7E728FC56FA7C294ULL,
		0xBAB4928560715B14ULL,
		0x09B6DDA75C71BBC0ULL
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
		0xD840135412183156ULL,
		0x680BB78085649B82ULL,
		0x213321D59846880BULL,
		0x61B6890881ECE6A2ULL,
		0xD5D9C5CD88CC6794ULL,
		0x2D457B70852C7D47ULL,
		0x87E2CC3CEF6344B2ULL,
		0x31A47CE285404FD0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB08026A8243062ACULL,
		0xD0176F010AC93705ULL,
		0x426643AB308D1016ULL,
		0xC36D121103D9CD44ULL,
		0xABB38B9B1198CF28ULL,
		0x5A8AF6E10A58FA8FULL,
		0x0FC59879DEC68964ULL,
		0x6348F9C50A809FA1ULL
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
		0xE4DE5AEDE41CFA32ULL,
		0x34A86720F847C2ACULL,
		0x86281B8299B61594ULL,
		0xAF0C5D99601216CBULL,
		0x5DDA9B95D025AE23ULL,
		0x6574A69B9BC78BB5ULL,
		0x747D013AEB6120DAULL,
		0x284089EF9440B039ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC9BCB5DBC839F464ULL,
		0x6950CE41F08F8559ULL,
		0x0C503705336C2B28ULL,
		0x5E18BB32C0242D97ULL,
		0xBBB5372BA04B5C47ULL,
		0xCAE94D37378F176AULL,
		0xE8FA0275D6C241B4ULL,
		0x508113DF28816072ULL
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
		0x4E65A4E03AB22261ULL,
		0x546F3B3BDDD069D2ULL,
		0xD9138B75956D9684ULL,
		0xB53FBA532CD8E67CULL,
		0x20FD612B787D6704ULL,
		0x5724DC62A5791A3CULL,
		0xC0E2C697899271E6ULL,
		0x36FB38F99091F865ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9CCB49C0756444C2ULL,
		0xA8DE7677BBA0D3A4ULL,
		0xB22716EB2ADB2D08ULL,
		0x6A7F74A659B1CCF9ULL,
		0x41FAC256F0FACE09ULL,
		0xAE49B8C54AF23478ULL,
		0x81C58D2F1324E3CCULL,
		0x6DF671F32123F0CBULL
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
		0x540A4EEEA27E14E2ULL,
		0xB7B5BC354774BEDFULL,
		0x3D7D990AE0484295ULL,
		0x77338848714EAC01ULL,
		0x97E39C69687A9DADULL,
		0x92EBF0DF36A0F77CULL,
		0x1188FAB5F2FC59FDULL,
		0x3AC186DB7D4D96C5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA8149DDD44FC29C4ULL,
		0x6F6B786A8EE97DBEULL,
		0x7AFB3215C090852BULL,
		0xEE671090E29D5802ULL,
		0x2FC738D2D0F53B5AULL,
		0x25D7E1BE6D41EEF9ULL,
		0x2311F56BE5F8B3FBULL,
		0x75830DB6FA9B2D8AULL
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
		0x1B300013DC2F39C8ULL,
		0x4077E9FAA078B8D0ULL,
		0x829254DAA639F2E1ULL,
		0x4EC294010D2CBEC6ULL,
		0xE91DF6DAF96AAE02ULL,
		0xA9446388BB654187ULL,
		0x8ABEA5D15C4C10F0ULL,
		0x0E7DB732275A0D60ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x36600027B85E7390ULL,
		0x80EFD3F540F171A0ULL,
		0x0524A9B54C73E5C2ULL,
		0x9D8528021A597D8DULL,
		0xD23BEDB5F2D55C04ULL,
		0x5288C71176CA830FULL,
		0x157D4BA2B89821E1ULL,
		0x1CFB6E644EB41AC1ULL
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
		0x27BAA6025F5A0EF8ULL,
		0xE590A50513A0BD03ULL,
		0xEFA44DBF32B15B75ULL,
		0x2E05E6CA16EEF0D7ULL,
		0x41D536B0FFA8974CULL,
		0x0EAC0142F34D5D1EULL,
		0x7721FEBF9D8042D6ULL,
		0x1262B8AAD0A66108ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4F754C04BEB41DF0ULL,
		0xCB214A0A27417A06ULL,
		0xDF489B7E6562B6EBULL,
		0x5C0BCD942DDDE1AFULL,
		0x83AA6D61FF512E98ULL,
		0x1D580285E69ABA3CULL,
		0xEE43FD7F3B0085ACULL,
		0x24C57155A14CC210ULL
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
		0x72ABD1ADF56EFB9EULL,
		0x58AA9729FE8D6C92ULL,
		0x427B7FBBF49107B9ULL,
		0x97DE683544324901ULL,
		0x20526C03FE63061EULL,
		0xC7CF4CFEFB5DE660ULL,
		0x44F2E3C722186978ULL,
		0x09DD107018E5AE5AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE557A35BEADDF73CULL,
		0xB1552E53FD1AD924ULL,
		0x84F6FF77E9220F72ULL,
		0x2FBCD06A88649202ULL,
		0x40A4D807FCC60C3DULL,
		0x8F9E99FDF6BBCCC0ULL,
		0x89E5C78E4430D2F1ULL,
		0x13BA20E031CB5CB4ULL
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
		0x32C3A8F99F76E77AULL,
		0x98DDE292EEFD96D5ULL,
		0x88292BB39822961CULL,
		0x39E94E06EC1E3B74ULL,
		0x0E37A602C29AFB2AULL,
		0xD5858ABAF51C63EDULL,
		0xEAC8EFE88718107BULL,
		0x2B0549D13741880BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x658751F33EEDCEF4ULL,
		0x31BBC525DDFB2DAAULL,
		0x1052576730452C39ULL,
		0x73D29C0DD83C76E9ULL,
		0x1C6F4C058535F654ULL,
		0xAB0B1575EA38C7DAULL,
		0xD591DFD10E3020F7ULL,
		0x560A93A26E831017ULL
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
		0x86FEB09511AC1EA6ULL,
		0x3C071DCDF3B654E5ULL,
		0x0BE3D36E634C8F1EULL,
		0x601EB0F68620ABFEULL,
		0x730E3C46375DD80CULL,
		0xE1374093CF52E7EAULL,
		0x7C57B634A39E84DCULL,
		0x3443A2A49635FFD2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0DFD612A23583D4CULL,
		0x780E3B9BE76CA9CBULL,
		0x17C7A6DCC6991E3CULL,
		0xC03D61ED0C4157FCULL,
		0xE61C788C6EBBB018ULL,
		0xC26E81279EA5CFD4ULL,
		0xF8AF6C69473D09B9ULL,
		0x688745492C6BFFA4ULL
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
		0xBE2832430B8DC437ULL,
		0x1C450AADABE9AC2CULL,
		0x45703527B454E804ULL,
		0x40D041EF562AE424ULL,
		0x593DFD52009C0F67ULL,
		0xD9433DB857C452F3ULL,
		0x52A74C793A6A4E5EULL,
		0x2F42E9BD0721C3D2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7C506486171B886EULL,
		0x388A155B57D35859ULL,
		0x8AE06A4F68A9D008ULL,
		0x81A083DEAC55C848ULL,
		0xB27BFAA401381ECEULL,
		0xB2867B70AF88A5E6ULL,
		0xA54E98F274D49CBDULL,
		0x5E85D37A0E4387A4ULL
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
		0xBFEA63A6AC75C657ULL,
		0x4C5247A6F683B386ULL,
		0x1361143B16D533E1ULL,
		0xE3293642862D799AULL,
		0x3C392637F35FE909ULL,
		0xCDA98689510400CFULL,
		0x847B453C14AF017BULL,
		0x008070CBE2FF16C0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7FD4C74D58EB8CAEULL,
		0x98A48F4DED07670DULL,
		0x26C228762DAA67C2ULL,
		0xC6526C850C5AF334ULL,
		0x78724C6FE6BFD213ULL,
		0x9B530D12A208019EULL,
		0x08F68A78295E02F7ULL,
		0x0100E197C5FE2D81ULL
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
		0xD4612ECA75483D44ULL,
		0x0DEDED4243FA4623ULL,
		0x5435916D0994D3EBULL,
		0x61D92F483921017AULL,
		0xAEAA4369E5C3D64BULL,
		0x04A68C8475D75342ULL,
		0x58E5DF4F27CAEF5DULL,
		0x0BAFF13469BCF2B0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA8C25D94EA907A88ULL,
		0x1BDBDA8487F48C47ULL,
		0xA86B22DA1329A7D6ULL,
		0xC3B25E90724202F4ULL,
		0x5D5486D3CB87AC96ULL,
		0x094D1908EBAEA685ULL,
		0xB1CBBE9E4F95DEBAULL,
		0x175FE268D379E560ULL
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
		0xB11E96D2741328F1ULL,
		0x180B6ACFCA1657FCULL,
		0xDD093C757E72FA75ULL,
		0x3F604130FABC4B07ULL,
		0x6FDBE3B771173D25ULL,
		0xA3DF5431CDA1A789ULL,
		0x34804EBD3954A101ULL,
		0x1FBA5E26E899521FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x623D2DA4E82651E2ULL,
		0x3016D59F942CAFF9ULL,
		0xBA1278EAFCE5F4EAULL,
		0x7EC08261F578960FULL,
		0xDFB7C76EE22E7A4AULL,
		0x47BEA8639B434F12ULL,
		0x69009D7A72A94203ULL,
		0x3F74BC4DD132A43EULL
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
		0x91AC66CA955D0219ULL,
		0x043783D5BE8670D1ULL,
		0x7B8A07A3B42421FFULL,
		0x10961CB889E66213ULL,
		0xFE1F769668519AFBULL,
		0xB59CA5E1F2D2FB8CULL,
		0x40C70B21CB0D30A4ULL,
		0x1019C0D50ED13B06ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2358CD952ABA0432ULL,
		0x086F07AB7D0CE1A3ULL,
		0xF7140F47684843FEULL,
		0x212C397113CCC426ULL,
		0xFC3EED2CD0A335F6ULL,
		0x6B394BC3E5A5F719ULL,
		0x818E1643961A6149ULL,
		0x203381AA1DA2760CULL
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
		0x9702BDC05FC9A20FULL,
		0x13021444B1C9D829ULL,
		0x0417679E619FF169ULL,
		0x4509527CFA892BA4ULL,
		0xD95F039DDE16CCD1ULL,
		0xD8556C94CB4A603DULL,
		0x28D87DDB84664909ULL,
		0x3876BA7B0AAD737CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2E057B80BF93441EULL,
		0x260428896393B053ULL,
		0x082ECF3CC33FE2D2ULL,
		0x8A12A4F9F5125748ULL,
		0xB2BE073BBC2D99A2ULL,
		0xB0AAD9299694C07BULL,
		0x51B0FBB708CC9213ULL,
		0x70ED74F6155AE6F8ULL
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
		0x50E8F2FF416EECB4ULL,
		0x8309B13F1974028CULL,
		0x0EA95F78C5A850F2ULL,
		0x6F6EA35DFDEAA4CFULL,
		0xB967750632BA3211ULL,
		0xA88387E4B0717BF7ULL,
		0x2721E0F77B72ABD9ULL,
		0x1F763DC6212E9707ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA1D1E5FE82DDD968ULL,
		0x0613627E32E80518ULL,
		0x1D52BEF18B50A1E5ULL,
		0xDEDD46BBFBD5499EULL,
		0x72CEEA0C65746422ULL,
		0x51070FC960E2F7EFULL,
		0x4E43C1EEF6E557B3ULL,
		0x3EEC7B8C425D2E0EULL
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
		0x6D8F49D78468DEF3ULL,
		0x953D4E3A08DFEF7AULL,
		0x0DA6883300B7E664ULL,
		0xD4B7D5B4AC6C747EULL,
		0x68B6FA81D12B1BB6ULL,
		0x46413058F2AEABD5ULL,
		0x199B8C47C8EB944CULL,
		0x02E8667FF4CA0FAFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDB1E93AF08D1BDE6ULL,
		0x2A7A9C7411BFDEF4ULL,
		0x1B4D1066016FCCC9ULL,
		0xA96FAB6958D8E8FCULL,
		0xD16DF503A256376DULL,
		0x8C8260B1E55D57AAULL,
		0x3337188F91D72898ULL,
		0x05D0CCFFE9941F5EULL
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
		0xDB1939899D077492ULL,
		0x5E4EB71AED7F7A1FULL,
		0x767DE59E75C7B6DAULL,
		0xFAF35CF0FADDD67BULL,
		0x57EF1574340CADEEULL,
		0x9769401D0C5366A0ULL,
		0xE1E540A5FD94DCFEULL,
		0x1B9F1811FF85B0E2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB63273133A0EE924ULL,
		0xBC9D6E35DAFEF43FULL,
		0xECFBCB3CEB8F6DB4ULL,
		0xF5E6B9E1F5BBACF6ULL,
		0xAFDE2AE868195BDDULL,
		0x2ED2803A18A6CD40ULL,
		0xC3CA814BFB29B9FDULL,
		0x373E3023FF0B61C5ULL
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
		0x44B99B57AD6FB18FULL,
		0xBB3B53ADC5C4BB2BULL,
		0x1B49BE7572C77715ULL,
		0xCC003384650BB599ULL,
		0x1F33C708DD1EAB58ULL,
		0xA149B0893F1C968AULL,
		0x98E3E3625CA82D0AULL,
		0x0B3CA53CFEDD9D65ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x897336AF5ADF631EULL,
		0x7676A75B8B897656ULL,
		0x36937CEAE58EEE2BULL,
		0x98006708CA176B32ULL,
		0x3E678E11BA3D56B1ULL,
		0x429361127E392D14ULL,
		0x31C7C6C4B9505A15ULL,
		0x16794A79FDBB3ACBULL
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
		0x444CCBE6FF633F5BULL,
		0x3E01035B3CB48EB7ULL,
		0x2EB55434DAFFC08AULL,
		0x33D3D3324FAFC7EAULL,
		0x8F1F0C1CEDE35659ULL,
		0x65D361E99F7C7163ULL,
		0x62488FE871964189ULL,
		0x14539278A9185E53ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x889997CDFEC67EB6ULL,
		0x7C0206B679691D6EULL,
		0x5D6AA869B5FF8114ULL,
		0x67A7A6649F5F8FD4ULL,
		0x1E3E1839DBC6ACB2ULL,
		0xCBA6C3D33EF8E2C7ULL,
		0xC4911FD0E32C8312ULL,
		0x28A724F15230BCA6ULL
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
		0x94AB7B023FCED4A1ULL,
		0x047D628EA6B9A525ULL,
		0xB91A4B7D1D1EB35FULL,
		0x7D8DEE7218DEE4EEULL,
		0x2EA29F437A947FF5ULL,
		0x032E4989B41A635FULL,
		0x5D2A7F29ECB0EC10ULL,
		0x230BA1DD8890DB9DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2956F6047F9DA942ULL,
		0x08FAC51D4D734A4BULL,
		0x723496FA3A3D66BEULL,
		0xFB1BDCE431BDC9DDULL,
		0x5D453E86F528FFEAULL,
		0x065C93136834C6BEULL,
		0xBA54FE53D961D820ULL,
		0x461743BB1121B73AULL
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
		0x86D984D6B2330ACEULL,
		0x35203BFEFD3C862EULL,
		0xB5A0B87D037355EFULL,
		0xEADA3FEF61CEA640ULL,
		0x5D4035466F52823AULL,
		0x70C562091B2BBB78ULL,
		0x27D732A8F5A1CE62ULL,
		0x245B4E3575812CB5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0DB309AD6466159CULL,
		0x6A4077FDFA790C5DULL,
		0x6B4170FA06E6ABDEULL,
		0xD5B47FDEC39D4C81ULL,
		0xBA806A8CDEA50475ULL,
		0xE18AC412365776F0ULL,
		0x4FAE6551EB439CC4ULL,
		0x48B69C6AEB02596AULL
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
		0x340B95AF9697CAB9ULL,
		0x4DF7D81FFE585766ULL,
		0x7C5164A88A19C283ULL,
		0x6C69C0C5E51EA81EULL,
		0x525A481EF3B20045ULL,
		0x00A384FC2415FA3CULL,
		0x18931490A99276D6ULL,
		0x2147BB00F767361EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x68172B5F2D2F9572ULL,
		0x9BEFB03FFCB0AECCULL,
		0xF8A2C95114338506ULL,
		0xD8D3818BCA3D503CULL,
		0xA4B4903DE764008AULL,
		0x014709F8482BF478ULL,
		0x312629215324EDACULL,
		0x428F7601EECE6C3CULL
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
		0xB10A5CD705486FB4ULL,
		0xEE769ED36CCA5E22ULL,
		0x4D5FC883D461C99EULL,
		0xEA8F23E93E9FF896ULL,
		0xCE4C9D1838AD175BULL,
		0xBA8C9C79CDEF3D83ULL,
		0x6FE771251DEE95D4ULL,
		0x0C0ACAACABFBCE1DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6214B9AE0A90DF68ULL,
		0xDCED3DA6D994BC45ULL,
		0x9ABF9107A8C3933DULL,
		0xD51E47D27D3FF12CULL,
		0x9C993A30715A2EB7ULL,
		0x751938F39BDE7B07ULL,
		0xDFCEE24A3BDD2BA9ULL,
		0x1815955957F79C3AULL
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
		0x162DEDBCDDC637ECULL,
		0x4B96788856B2EF2BULL,
		0x39B03D8B1EDD5790ULL,
		0xADF451AA2ACB6585ULL,
		0x12365D6612166009ULL,
		0xA4C627C32A8DAE55ULL,
		0xF46B2487CC32C751ULL,
		0x28CB015FBD634CDCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2C5BDB79BB8C6FD8ULL,
		0x972CF110AD65DE56ULL,
		0x73607B163DBAAF20ULL,
		0x5BE8A3545596CB0AULL,
		0x246CBACC242CC013ULL,
		0x498C4F86551B5CAAULL,
		0xE8D6490F98658EA3ULL,
		0x519602BF7AC699B9ULL
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
		0x2E20118D6648A0E4ULL,
		0xEEF92DCBF812FEA2ULL,
		0xB8E1B1C5972ADEC6ULL,
		0xF3119673E6678A36ULL,
		0x177243E91B555898ULL,
		0x0368B99AD6834FEAULL,
		0x455061C3B3EA7E5AULL,
		0x37C4B43B702D8328ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5C40231ACC9141C8ULL,
		0xDDF25B97F025FD44ULL,
		0x71C3638B2E55BD8DULL,
		0xE6232CE7CCCF146DULL,
		0x2EE487D236AAB131ULL,
		0x06D17335AD069FD4ULL,
		0x8AA0C38767D4FCB4ULL,
		0x6F896876E05B0650ULL
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
		0xD1F0986DD4D6142FULL,
		0xF6E8F7EEB5CC6A31ULL,
		0x918FDCA919DC8C2BULL,
		0x12D2F0D460B8E7D1ULL,
		0xED6C547B75C82B55ULL,
		0x7437FAC67EF69930ULL,
		0xAABE2CCC173751A6ULL,
		0x33CBD6987CDB3342ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA3E130DBA9AC285EULL,
		0xEDD1EFDD6B98D463ULL,
		0x231FB95233B91857ULL,
		0x25A5E1A8C171CFA3ULL,
		0xDAD8A8F6EB9056AAULL,
		0xE86FF58CFDED3261ULL,
		0x557C59982E6EA34CULL,
		0x6797AD30F9B66685ULL
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
		0x11889A37461705A4ULL,
		0xFE1472F31AEDBD9BULL,
		0x7C7091EDB3F2B807ULL,
		0xBC1BD29199AF34FEULL,
		0xCF608DE94538EF65ULL,
		0x593FE11265232F3AULL,
		0x888E4895673DF587ULL,
		0x02675AE3251F4FFEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2311346E8C2E0B48ULL,
		0xFC28E5E635DB7B36ULL,
		0xF8E123DB67E5700FULL,
		0x7837A523335E69FCULL,
		0x9EC11BD28A71DECBULL,
		0xB27FC224CA465E75ULL,
		0x111C912ACE7BEB0EULL,
		0x04CEB5C64A3E9FFDULL
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
		0x32CCE925A2DB2102ULL,
		0x8ED51B49061AEC2BULL,
		0xFAF6E715071E3B79ULL,
		0x7E8F8ADE0EC1A973ULL,
		0xE66BF6C652C624E6ULL,
		0x881FF86D85606223ULL,
		0x9E4789927F542D96ULL,
		0x0E2A156185AEFE9AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6599D24B45B64204ULL,
		0x1DAA36920C35D856ULL,
		0xF5EDCE2A0E3C76F3ULL,
		0xFD1F15BC1D8352E7ULL,
		0xCCD7ED8CA58C49CCULL,
		0x103FF0DB0AC0C447ULL,
		0x3C8F1324FEA85B2DULL,
		0x1C542AC30B5DFD35ULL
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
		0x2F4F83CCD858DA7AULL,
		0xF09A70C61F508B89ULL,
		0x49CBC65E9014069CULL,
		0xFEFFA63669BBB9B3ULL,
		0xEE70BBA4DB42EAF9ULL,
		0x9B20C5E913ADD476ULL,
		0x93853002FA1F678DULL,
		0x1CA52518798F72A3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5E9F0799B0B1B4F4ULL,
		0xE134E18C3EA11712ULL,
		0x93978CBD20280D39ULL,
		0xFDFF4C6CD3777366ULL,
		0xDCE17749B685D5F3ULL,
		0x36418BD2275BA8EDULL,
		0x270A6005F43ECF1BULL,
		0x394A4A30F31EE547ULL
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
		0xD518B05BD520A3CFULL,
		0xF3485EC69EEB4B66ULL,
		0x4620229459411ED0ULL,
		0x2F0105F21ED1D5BEULL,
		0xC16C778E234CFEF0ULL,
		0x5D22866DC81D85DBULL,
		0x9E3C3D2BD2EE2C4BULL,
		0x050A7E552C88294AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAA3160B7AA41479EULL,
		0xE690BD8D3DD696CDULL,
		0x8C404528B2823DA1ULL,
		0x5E020BE43DA3AB7CULL,
		0x82D8EF1C4699FDE0ULL,
		0xBA450CDB903B0BB7ULL,
		0x3C787A57A5DC5896ULL,
		0x0A14FCAA59105295ULL
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
		0x4E4CE127B9ADC6CBULL,
		0xF2EFE7BAA999EC65ULL,
		0x90039F8EC3698EA2ULL,
		0x85E22220F3BC4795ULL,
		0x8D8A3FC6848ED68EULL,
		0xD9CD1341E13BA744ULL,
		0x72A3BE64AF294EDAULL,
		0x0B49F3905D52A2BBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9C99C24F735B8D96ULL,
		0xE5DFCF755333D8CAULL,
		0x20073F1D86D31D45ULL,
		0x0BC44441E7788F2BULL,
		0x1B147F8D091DAD1DULL,
		0xB39A2683C2774E89ULL,
		0xE5477CC95E529DB5ULL,
		0x1693E720BAA54576ULL
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
		0xC8B660D4DE155480ULL,
		0x3C17CE1B51361E5AULL,
		0x0CB3EC0CF64C6A02ULL,
		0xD0D294797967750BULL,
		0xC08733CD901ECA00ULL,
		0x3EDC2EC6D2A4FECFULL,
		0x41D651F3D46DA140ULL,
		0x00A8276C8059CA66ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x916CC1A9BC2AA900ULL,
		0x782F9C36A26C3CB5ULL,
		0x1967D819EC98D404ULL,
		0xA1A528F2F2CEEA16ULL,
		0x810E679B203D9401ULL,
		0x7DB85D8DA549FD9FULL,
		0x83ACA3E7A8DB4280ULL,
		0x01504ED900B394CCULL
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
		0x9A1E179B12B08B7EULL,
		0x55DE496CA56FA0CBULL,
		0x0D1E1BFB9A0433B9ULL,
		0x1F97319D951C111CULL,
		0x78E9912487B2F0D5ULL,
		0xC6BE547C682E58FCULL,
		0xC908423E010BD41BULL,
		0x1AB311D285BB5BE7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x343C2F36256116FCULL,
		0xABBC92D94ADF4197ULL,
		0x1A3C37F734086772ULL,
		0x3F2E633B2A382238ULL,
		0xF1D322490F65E1AAULL,
		0x8D7CA8F8D05CB1F8ULL,
		0x9210847C0217A837ULL,
		0x356623A50B76B7CFULL
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
		0x5FAD7043D54BB7B6ULL,
		0x6DFBD33820D3FD84ULL,
		0xD89D6CFD87600558ULL,
		0xE5536718F2227166ULL,
		0x02014A2E0DDD7C67ULL,
		0xA7C454F058FDD352ULL,
		0x58EA44DDF212AB53ULL,
		0x1EB0BF92404B3FF3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBF5AE087AA976F6CULL,
		0xDBF7A67041A7FB08ULL,
		0xB13AD9FB0EC00AB0ULL,
		0xCAA6CE31E444E2CDULL,
		0x0402945C1BBAF8CFULL,
		0x4F88A9E0B1FBA6A4ULL,
		0xB1D489BBE42556A7ULL,
		0x3D617F2480967FE6ULL
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
		0x98D8D4EBDCE029C2ULL,
		0x831F9BD8D462C46DULL,
		0xD4FA15880CC58BFDULL,
		0xEC01A5BE10A1A912ULL,
		0x5785690A5C4B65E3ULL,
		0x3C4E1EC4B54DC276ULL,
		0x0F63EDFE61703375ULL,
		0x02F59C8C75C60692ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x31B1A9D7B9C05384ULL,
		0x063F37B1A8C588DBULL,
		0xA9F42B10198B17FBULL,
		0xD8034B7C21435225ULL,
		0xAF0AD214B896CBC7ULL,
		0x789C3D896A9B84ECULL,
		0x1EC7DBFCC2E066EAULL,
		0x05EB3918EB8C0D24ULL
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
		0x2EFA8C3F76B76A43ULL,
		0xA35B095010F65D5CULL,
		0x03A795AF0281C218ULL,
		0x6DD9AC658CB7E9B5ULL,
		0x6494144D7964C6D9ULL,
		0x12A045E61D3DC81CULL,
		0x55C80DA24E31C6EAULL,
		0x13F74E0DE3AD00CAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5DF5187EED6ED486ULL,
		0x46B612A021ECBAB8ULL,
		0x074F2B5E05038431ULL,
		0xDBB358CB196FD36AULL,
		0xC928289AF2C98DB2ULL,
		0x25408BCC3A7B9038ULL,
		0xAB901B449C638DD4ULL,
		0x27EE9C1BC75A0194ULL
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
		0x3DB106D0F70C57F3ULL,
		0x822DA8CE834EE326ULL,
		0x75C095D16A40E6D7ULL,
		0x07B88B09230196AFULL,
		0xF03A68B88078769BULL,
		0x3F946D22CAD8266EULL,
		0x673B996427608884ULL,
		0x01DCCFE434A81D6DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7B620DA1EE18AFE6ULL,
		0x045B519D069DC64CULL,
		0xEB812BA2D481CDAFULL,
		0x0F71161246032D5EULL,
		0xE074D17100F0ED36ULL,
		0x7F28DA4595B04CDDULL,
		0xCE7732C84EC11108ULL,
		0x03B99FC869503ADAULL
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
		0xE9E54F226A03DEA5ULL,
		0x96DD062FAEBC07A0ULL,
		0x1265F63F00DEE517ULL,
		0xC3CD705A1CAE04F9ULL,
		0x9F7A567F847A4F9FULL,
		0x028490A658EC14B3ULL,
		0xAEE0EDF9BF0C5C22ULL,
		0x02655366037794A5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD3CA9E44D407BD4AULL,
		0x2DBA0C5F5D780F41ULL,
		0x24CBEC7E01BDCA2FULL,
		0x879AE0B4395C09F2ULL,
		0x3EF4ACFF08F49F3FULL,
		0x0509214CB1D82967ULL,
		0x5DC1DBF37E18B844ULL,
		0x04CAA6CC06EF294BULL
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
		0xBA97048C16D58AC3ULL,
		0x758DF798A8FBB1C9ULL,
		0xDE67555A7A800160ULL,
		0x1CA2427E4D04E18FULL,
		0x4B755B3D35CEB35AULL,
		0xCC368A75ECB301CBULL,
		0xB79695A69F97B37BULL,
		0x3317AE0933195D90ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x752E09182DAB1586ULL,
		0xEB1BEF3151F76393ULL,
		0xBCCEAAB4F50002C0ULL,
		0x394484FC9A09C31FULL,
		0x96EAB67A6B9D66B4ULL,
		0x986D14EBD9660396ULL,
		0x6F2D2B4D3F2F66F7ULL,
		0x662F5C126632BB21ULL
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
		0xD79959DB87D3140EULL,
		0x2AA96E0C25830E84ULL,
		0xE7B9BD42A4794D42ULL,
		0xCA3BA80EB332C935ULL,
		0x19F87E23F6A89BD1ULL,
		0xD7328E6ABCA42063ULL,
		0xC5EE95227FD602CEULL,
		0x2816AB846686719DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF32B3B70FA6281CULL,
		0x5552DC184B061D09ULL,
		0xCF737A8548F29A84ULL,
		0x9477501D6665926BULL,
		0x33F0FC47ED5137A3ULL,
		0xAE651CD5794840C6ULL,
		0x8BDD2A44FFAC059DULL,
		0x502D5708CD0CE33BULL
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
		0xB9C7D19FFBB09F73ULL,
		0x107B4959BD9AD9DEULL,
		0xAEFBB6BB16B72920ULL,
		0x1E1D9E78062EC273ULL,
		0x03CC061EC0194F7DULL,
		0x598E7440CA44365AULL,
		0xB649C5808C5F3AF8ULL,
		0x37428B4F2C230613ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x738FA33FF7613EE6ULL,
		0x20F692B37B35B3BDULL,
		0x5DF76D762D6E5240ULL,
		0x3C3B3CF00C5D84E7ULL,
		0x07980C3D80329EFAULL,
		0xB31CE88194886CB4ULL,
		0x6C938B0118BE75F0ULL,
		0x6E85169E58460C27ULL
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
		0x7AC74F09CC280D4AULL,
		0x4B8427D610CC047EULL,
		0x53C660BC334F172FULL,
		0xEB70DA32394A4825ULL,
		0x149EE78E98896702ULL,
		0xB27FABA0395B4859ULL,
		0xE5060E3853676467ULL,
		0x3D4D9379B9FA580AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF58E9E1398501A94ULL,
		0x97084FAC219808FCULL,
		0xA78CC178669E2E5EULL,
		0xD6E1B4647294904AULL,
		0x293DCF1D3112CE05ULL,
		0x64FF574072B690B2ULL,
		0xCA0C1C70A6CEC8CFULL,
		0x7A9B26F373F4B015ULL
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
		0x58CBB0240CB2BB80ULL,
		0xF12F44506840E48CULL,
		0x9A5260063DD3A0D4ULL,
		0xCD9A989A8DE8B54BULL,
		0x935E652586CDC3D8ULL,
		0xA29B7AF79563CC7DULL,
		0x02FDFFF981C2BE77ULL,
		0x19DE4170D456926EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB197604819657700ULL,
		0xE25E88A0D081C918ULL,
		0x34A4C00C7BA741A9ULL,
		0x9B3531351BD16A97ULL,
		0x26BCCA4B0D9B87B1ULL,
		0x4536F5EF2AC798FBULL,
		0x05FBFFF303857CEFULL,
		0x33BC82E1A8AD24DCULL
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
		0x3E8AB21EF0CB0627ULL,
		0xA54C40788966DCECULL,
		0x4DB2894F7397B753ULL,
		0x3BCE7BA09128C03BULL,
		0xABD9CC139D7C4328ULL,
		0xBF7653ECB07F3B19ULL,
		0x2B592A93340E13E4ULL,
		0x2255E773F83FC78FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7D15643DE1960C4EULL,
		0x4A9880F112CDB9D8ULL,
		0x9B65129EE72F6EA7ULL,
		0x779CF74122518076ULL,
		0x57B398273AF88650ULL,
		0x7EECA7D960FE7633ULL,
		0x56B25526681C27C9ULL,
		0x44ABCEE7F07F8F1EULL
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
		0x585D24EE948AB8C5ULL,
		0xE1559DB2241B0052ULL,
		0x9903ED05FC6DC634ULL,
		0xAD3CBD3DB97D7676ULL,
		0x9A45BC700AE7AEFCULL,
		0x0C786C8535110493ULL,
		0x41ACB6D982B08CFCULL,
		0x32753AEF73EFEDCEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB0BA49DD2915718AULL,
		0xC2AB3B64483600A4ULL,
		0x3207DA0BF8DB8C69ULL,
		0x5A797A7B72FAECEDULL,
		0x348B78E015CF5DF9ULL,
		0x18F0D90A6A220927ULL,
		0x83596DB3056119F8ULL,
		0x64EA75DEE7DFDB9CULL
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
		0x1F463C0BBA7A6E36ULL,
		0x9AA918A58EC7D8E0ULL,
		0x167AE639001B4F2AULL,
		0x318A5F351569AC33ULL,
		0x848B4DA5776961FDULL,
		0xAAB79134B1C1D259ULL,
		0x18DF8F356000F088ULL,
		0x2FC1DCBD1E036519ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3E8C781774F4DC6CULL,
		0x3552314B1D8FB1C0ULL,
		0x2CF5CC7200369E55ULL,
		0x6314BE6A2AD35866ULL,
		0x09169B4AEED2C3FAULL,
		0x556F22696383A4B3ULL,
		0x31BF1E6AC001E111ULL,
		0x5F83B97A3C06CA32ULL
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
		0x5A871D9CCED6A76FULL,
		0x71885C5FFC8DCF17ULL,
		0x518710032B22B69FULL,
		0x41616E044DC8D218ULL,
		0x0FDF857AAB382370ULL,
		0x5983BD846AEBA52DULL,
		0x3A53948C02E7E63EULL,
		0x0CD7F6EBFCE73103ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB50E3B399DAD4EDEULL,
		0xE310B8BFF91B9E2EULL,
		0xA30E200656456D3EULL,
		0x82C2DC089B91A430ULL,
		0x1FBF0AF5567046E0ULL,
		0xB3077B08D5D74A5AULL,
		0x74A7291805CFCC7CULL,
		0x19AFEDD7F9CE6206ULL
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
		0x181A8A6414A1FEB9ULL,
		0x684D9E3FBB464DBDULL,
		0x1E90360AA8496347ULL,
		0xD7B393858A7043BEULL,
		0x0607FA274924D85DULL,
		0xCE415DE2DDDF4186ULL,
		0x8C1103E463F4CA3BULL,
		0x105688698E96F7FFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x303514C82943FD72ULL,
		0xD09B3C7F768C9B7AULL,
		0x3D206C155092C68EULL,
		0xAF67270B14E0877CULL,
		0x0C0FF44E9249B0BBULL,
		0x9C82BBC5BBBE830CULL,
		0x182207C8C7E99477ULL,
		0x20AD10D31D2DEFFFULL
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
		0xC67605A64F88722BULL,
		0xB8106B9D0A0FE4A2ULL,
		0x05727861E7978EC0ULL,
		0x4BA7054AE0B92475ULL,
		0x90CD7787E4F8E154ULL,
		0x5B90F23D389512AAULL,
		0x6D7A8BCDE3FF2BCCULL,
		0x1E41BD6AE4D8757EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8CEC0B4C9F10E456ULL,
		0x7020D73A141FC945ULL,
		0x0AE4F0C3CF2F1D81ULL,
		0x974E0A95C17248EAULL,
		0x219AEF0FC9F1C2A8ULL,
		0xB721E47A712A2555ULL,
		0xDAF5179BC7FE5798ULL,
		0x3C837AD5C9B0EAFCULL
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
		0xF511CDC0B6BAEFA8ULL,
		0x6AA3B148389170F6ULL,
		0x57B752DCCFC86E43ULL,
		0xA611A528546537C9ULL,
		0x8804B70BAD974FCBULL,
		0x89CF552D62967569ULL,
		0x562B6E3FA4919D77ULL,
		0x21A74CDE7A58C526ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEA239B816D75DF50ULL,
		0xD54762907122E1EDULL,
		0xAF6EA5B99F90DC86ULL,
		0x4C234A50A8CA6F92ULL,
		0x10096E175B2E9F97ULL,
		0x139EAA5AC52CEAD3ULL,
		0xAC56DC7F49233AEFULL,
		0x434E99BCF4B18A4CULL
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
		0xC8B591B9E95FAFC4ULL,
		0xC13AA5837BFC4751ULL,
		0x2EAF4FC3B462CCFFULL,
		0xB14B18A539204C30ULL,
		0x99D16A2BBD10BECCULL,
		0xEEFD6F90F82BEE47ULL,
		0xA09AA4A20D473369ULL,
		0x29462FDD926F6885ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x916B2373D2BF5F88ULL,
		0x82754B06F7F88EA3ULL,
		0x5D5E9F8768C599FFULL,
		0x6296314A72409860ULL,
		0x33A2D4577A217D99ULL,
		0xDDFADF21F057DC8FULL,
		0x413549441A8E66D3ULL,
		0x528C5FBB24DED10BULL
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
		0x2BEABC4C2ADDA30DULL,
		0x286EF5C5616B0630ULL,
		0xDE00F673FDB236D7ULL,
		0x0520E89635AEF2B4ULL,
		0x3EE4F6BE59E42417ULL,
		0x523A17B50B5027BEULL,
		0x2E6D6C830F9FBBCEULL,
		0x23DE80B21C2E6FEAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x57D5789855BB461AULL,
		0x50DDEB8AC2D60C60ULL,
		0xBC01ECE7FB646DAEULL,
		0x0A41D12C6B5DE569ULL,
		0x7DC9ED7CB3C8482EULL,
		0xA4742F6A16A04F7CULL,
		0x5CDAD9061F3F779CULL,
		0x47BD0164385CDFD4ULL
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
		0x98FF7CAA1854591DULL,
		0xE77ED6E72C32B8FBULL,
		0x35FE5D8BF668A03EULL,
		0x1BA3E4CBE4543FF1ULL,
		0x0DCF14439230AC2AULL,
		0xF96BB07B22BAE0F8ULL,
		0x8A98F56A96B7DBB2ULL,
		0x1A3EFA45B5D06DC9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x31FEF95430A8B23AULL,
		0xCEFDADCE586571F7ULL,
		0x6BFCBB17ECD1407DULL,
		0x3747C997C8A87FE2ULL,
		0x1B9E288724615854ULL,
		0xF2D760F64575C1F0ULL,
		0x1531EAD52D6FB765ULL,
		0x347DF48B6BA0DB93ULL
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
		0x4E1881B1376402F1ULL,
		0x72BCA8D0F4D723B8ULL,
		0x7EF118C29FA3D13CULL,
		0x1F5CA45D2B52C6F8ULL,
		0xACE5E8BC2852839EULL,
		0xF5A0A0D16BE92798ULL,
		0xBF0FEB663607EC83ULL,
		0x32FE021C93620741ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9C3103626EC805E2ULL,
		0xE57951A1E9AE4770ULL,
		0xFDE231853F47A278ULL,
		0x3EB948BA56A58DF0ULL,
		0x59CBD17850A5073CULL,
		0xEB4141A2D7D24F31ULL,
		0x7E1FD6CC6C0FD907ULL,
		0x65FC043926C40E83ULL
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
		0x3FD535664C13E64EULL,
		0x15D4B2C71CCB49CCULL,
		0x3B387BCDAA651113ULL,
		0x8C95E556B0BC9564ULL,
		0x139CD1206ABE0BB5ULL,
		0x8C16478CD80D4F18ULL,
		0x051BCCCA8EBBC813ULL,
		0x1BC83FC33D29C522ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7FAA6ACC9827CC9CULL,
		0x2BA9658E39969398ULL,
		0x7670F79B54CA2226ULL,
		0x192BCAAD61792AC8ULL,
		0x2739A240D57C176BULL,
		0x182C8F19B01A9E30ULL,
		0x0A3799951D779027ULL,
		0x37907F867A538A44ULL
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
		0x4B933A1631961210ULL,
		0x5D09B417023A9FBCULL,
		0xC03E206D734C4462ULL,
		0xFD406D9A09F34224ULL,
		0xC7C6A85C004F2090ULL,
		0x88175628A822FC8CULL,
		0x66EBF8F44FDCAD79ULL,
		0x2D761C3A3277E20EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9726742C632C2420ULL,
		0xBA13682E04753F78ULL,
		0x807C40DAE69888C4ULL,
		0xFA80DB3413E68449ULL,
		0x8F8D50B8009E4121ULL,
		0x102EAC515045F919ULL,
		0xCDD7F1E89FB95AF3ULL,
		0x5AEC387464EFC41CULL
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
		0x847606C4896CEC5EULL,
		0x35EDBC4C5B69A000ULL,
		0xB49CC45F1E2C740EULL,
		0x90ABE045FD81B370ULL,
		0xBB558502A3DD6A4EULL,
		0x190424739370578DULL,
		0x2B5106184A4C3005ULL,
		0x110336B35E215BFEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x08EC0D8912D9D8BCULL,
		0x6BDB7898B6D34001ULL,
		0x693988BE3C58E81CULL,
		0x2157C08BFB0366E1ULL,
		0x76AB0A0547BAD49DULL,
		0x320848E726E0AF1BULL,
		0x56A20C309498600AULL,
		0x22066D66BC42B7FCULL
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
		0x06CF57CCBCCCA04FULL,
		0xD019D849D8806DD9ULL,
		0x858EC0DFF279BFE7ULL,
		0x9073843379F13C7DULL,
		0x4EBBF181414C9C14ULL,
		0x0C1C30865198D83BULL,
		0x0069DD1F190E22D2ULL,
		0x0145C9A219A8ED4BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0D9EAF997999409EULL,
		0xA033B093B100DBB2ULL,
		0x0B1D81BFE4F37FCFULL,
		0x20E70866F3E278FBULL,
		0x9D77E30282993829ULL,
		0x1838610CA331B076ULL,
		0x00D3BA3E321C45A4ULL,
		0x028B93443351DA96ULL
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
		0x47B6FBA1CD016158ULL,
		0x90A9E7C10CC29C6AULL,
		0x0277B9AC8183998DULL,
		0x723B81095A28FAECULL,
		0xFBF675B8179A9C16ULL,
		0x0F82893B2CE63C23ULL,
		0xE5D8D57465128F54ULL,
		0x07DA4A0ACCC21395ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8F6DF7439A02C2B0ULL,
		0x2153CF82198538D4ULL,
		0x04EF73590307331BULL,
		0xE4770212B451F5D8ULL,
		0xF7ECEB702F35382CULL,
		0x1F05127659CC7847ULL,
		0xCBB1AAE8CA251EA8ULL,
		0x0FB494159984272BULL
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
		0x6B4BCF17C87FCB54ULL,
		0x1D0781B037A637B1ULL,
		0x1C495AD39B34E794ULL,
		0x61FEB76D52585C75ULL,
		0xA52232781C002565ULL,
		0x36C1C89282FEC0F4ULL,
		0x3B2C3D489C607638ULL,
		0x3A9AED7559EDD76CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD6979E2F90FF96A8ULL,
		0x3A0F03606F4C6F62ULL,
		0x3892B5A73669CF28ULL,
		0xC3FD6EDAA4B0B8EAULL,
		0x4A4464F038004ACAULL,
		0x6D83912505FD81E9ULL,
		0x76587A9138C0EC70ULL,
		0x7535DAEAB3DBAED8ULL
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
		0x0896BD8DEACEA3EEULL,
		0x6B6C8A0A3306ECC4ULL,
		0xDA212F19241707AFULL,
		0x30C6733BFDEBC768ULL,
		0x9B71A723569FCAC8ULL,
		0xF8173562613A4431ULL,
		0xB9BB45DAEFBCCC71ULL,
		0x3BEDC1B41F684E54ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x112D7B1BD59D47DCULL,
		0xD6D91414660DD988ULL,
		0xB4425E32482E0F5EULL,
		0x618CE677FBD78ED1ULL,
		0x36E34E46AD3F9590ULL,
		0xF02E6AC4C2748863ULL,
		0x73768BB5DF7998E3ULL,
		0x77DB83683ED09CA9ULL
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
		0x1089B9D96C63BC0AULL,
		0xDB4DC7C88A1A2392ULL,
		0xE7321831FAA5FF68ULL,
		0x668E55078A5FAFD7ULL,
		0x19AE097C76F47B96ULL,
		0xBF85702BE2362640ULL,
		0xA665609018C4A8B0ULL,
		0x3D4B4FF2737718BAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x211373B2D8C77814ULL,
		0xB69B8F9114344724ULL,
		0xCE643063F54BFED1ULL,
		0xCD1CAA0F14BF5FAFULL,
		0x335C12F8EDE8F72CULL,
		0x7F0AE057C46C4C80ULL,
		0x4CCAC12031895161ULL,
		0x7A969FE4E6EE3175ULL
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
		0xD48B48B2D968CF61ULL,
		0x07A7E1F3B7121040ULL,
		0xCA3ADBBD6ACF6EBBULL,
		0x18A277023E956297ULL,
		0x983D00E6DB04EE80ULL,
		0xEDDB793BAFADD2F8ULL,
		0x5E8DDBEE8C57B92FULL,
		0x296D0ED9F071A39EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA9169165B2D19EC2ULL,
		0x0F4FC3E76E242081ULL,
		0x9475B77AD59EDD76ULL,
		0x3144EE047D2AC52FULL,
		0x307A01CDB609DD00ULL,
		0xDBB6F2775F5BA5F1ULL,
		0xBD1BB7DD18AF725FULL,
		0x52DA1DB3E0E3473CULL
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
		0x248FD9F13D71B38DULL,
		0xFF0B140BD6676808ULL,
		0x1DF43CF1C36E52E1ULL,
		0xB3FE3A61B0F38A0EULL,
		0xD3696EE6588B5F49ULL,
		0xE6CA5C4C128784ADULL,
		0xBCF2E5A1CC464ED9ULL,
		0x32A841EF19FE4AB5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x491FB3E27AE3671AULL,
		0xFE162817ACCED010ULL,
		0x3BE879E386DCA5C3ULL,
		0x67FC74C361E7141CULL,
		0xA6D2DDCCB116BE93ULL,
		0xCD94B898250F095BULL,
		0x79E5CB43988C9DB3ULL,
		0x655083DE33FC956BULL
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
		0x317171841B7ADA6AULL,
		0x3C96CA98F4DE5FC1ULL,
		0x91688A8245B07E1DULL,
		0xD0DFE703B6740F29ULL,
		0xB84DFB24F40306F8ULL,
		0xD4DCE303AB88BD30ULL,
		0x51C94F05BFC98D15ULL,
		0x0552D09CE0C8B0C9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x62E2E30836F5B4D4ULL,
		0x792D9531E9BCBF82ULL,
		0x22D115048B60FC3AULL,
		0xA1BFCE076CE81E53ULL,
		0x709BF649E8060DF1ULL,
		0xA9B9C60757117A61ULL,
		0xA3929E0B7F931A2BULL,
		0x0AA5A139C1916192ULL
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
		0x253BD0C0A761DF36ULL,
		0x467F3BD1D8D20E74ULL,
		0x7A118CE4D8D4DBBBULL,
		0x41444E3F232B9956ULL,
		0x05FB79181C1160E6ULL,
		0x83DF21F4218DBA1AULL,
		0x5F6B9DAC344CECCFULL,
		0x01F4A15333DEC338ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4A77A1814EC3BE6CULL,
		0x8CFE77A3B1A41CE8ULL,
		0xF42319C9B1A9B776ULL,
		0x82889C7E465732ACULL,
		0x0BF6F2303822C1CCULL,
		0x07BE43E8431B7434ULL,
		0xBED73B586899D99FULL,
		0x03E942A667BD8670ULL
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
		0x8927A0778A4E52C0ULL,
		0xC22C5F5C35B0584DULL,
		0xEA184CD06E9190ACULL,
		0x0ADEB2F84E139E0BULL,
		0x8BA079716A74F8C7ULL,
		0x3EC2AEF77AC1DC6FULL,
		0xF26C323C24813C98ULL,
		0x2FA82FA0BDDB1009ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x124F40EF149CA580ULL,
		0x8458BEB86B60B09BULL,
		0xD43099A0DD232159ULL,
		0x15BD65F09C273C17ULL,
		0x1740F2E2D4E9F18EULL,
		0x7D855DEEF583B8DFULL,
		0xE4D8647849027930ULL,
		0x5F505F417BB62013ULL
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
		0xDED8D12CB25FCFDDULL,
		0x254213745D14FA1CULL,
		0xB58FB74053DBB09EULL,
		0x883747C46C4123EBULL,
		0x20912906627A86B5ULL,
		0xDA18864012736B8FULL,
		0x5584AE63B8477F25ULL,
		0x12B7AE4D6A7E074DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBDB1A25964BF9FBAULL,
		0x4A8426E8BA29F439ULL,
		0x6B1F6E80A7B7613CULL,
		0x106E8F88D88247D7ULL,
		0x4122520CC4F50D6BULL,
		0xB4310C8024E6D71EULL,
		0xAB095CC7708EFE4BULL,
		0x256F5C9AD4FC0E9AULL
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
		0x762768374E2925A8ULL,
		0xDF16B38604D6DAF9ULL,
		0x2E4479A335C86B6FULL,
		0xF0A35473BD8DC601ULL,
		0x1838C4E2DC2CE1EBULL,
		0xF5E0C9537C2A2DE2ULL,
		0x8B4152FF0EB9F23BULL,
		0x369BC05D6EA24146ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEC4ED06E9C524B50ULL,
		0xBE2D670C09ADB5F2ULL,
		0x5C88F3466B90D6DFULL,
		0xE146A8E77B1B8C02ULL,
		0x307189C5B859C3D7ULL,
		0xEBC192A6F8545BC4ULL,
		0x1682A5FE1D73E477ULL,
		0x6D3780BADD44828DULL
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
		0x0512DDA47B388718ULL,
		0x440CCC4AC8628E57ULL,
		0x302D274D3D419BE5ULL,
		0xDF925DC35EE33408ULL,
		0xA31332D051482362ULL,
		0x2FC7DDFA907D7D85ULL,
		0xD9DD368D959189E6ULL,
		0x28D024F5AE74FDB5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0A25BB48F6710E30ULL,
		0x8819989590C51CAEULL,
		0x605A4E9A7A8337CAULL,
		0xBF24BB86BDC66810ULL,
		0x462665A0A29046C5ULL,
		0x5F8FBBF520FAFB0BULL,
		0xB3BA6D1B2B2313CCULL,
		0x51A049EB5CE9FB6BULL
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
		0x5C33D954C80CE671ULL,
		0x3BE17A3CDD2ECFD9ULL,
		0xC10C67B0070A4CC2ULL,
		0xC8C017760835D25CULL,
		0x743738E710F1C0FBULL,
		0x539FA8B37CD1B7A3ULL,
		0x9462BF71AE57C101ULL,
		0x1F1283BB7C2A1775ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB867B2A99019CCE2ULL,
		0x77C2F479BA5D9FB2ULL,
		0x8218CF600E149984ULL,
		0x91802EEC106BA4B9ULL,
		0xE86E71CE21E381F7ULL,
		0xA73F5166F9A36F46ULL,
		0x28C57EE35CAF8202ULL,
		0x3E250776F8542EEBULL
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
		0x169F3C50CCD36276ULL,
		0x93C2ED1093B230A7ULL,
		0xEACD9AEE55F7625CULL,
		0x3C9B5DCA195E6D24ULL,
		0x02131E3E899D41D4ULL,
		0xE0F2BF5E56D8D3B0ULL,
		0x2568AD4ABF22E8D9ULL,
		0x1FCEB0CB400451BDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2D3E78A199A6C4ECULL,
		0x2785DA212764614EULL,
		0xD59B35DCABEEC4B9ULL,
		0x7936BB9432BCDA49ULL,
		0x04263C7D133A83A8ULL,
		0xC1E57EBCADB1A760ULL,
		0x4AD15A957E45D1B3ULL,
		0x3F9D61968008A37AULL
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
		0x33457128B908FDDAULL,
		0xC68951FA7819CC6BULL,
		0x5B30D6E124967A84ULL,
		0x697B583B2C9B76EBULL,
		0x5E7F600F051434A3ULL,
		0x1656824EB5443B5FULL,
		0x2969F2F033EDA244ULL,
		0x1FE2DBD1676FDF7CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x668AE2517211FBB4ULL,
		0x8D12A3F4F03398D6ULL,
		0xB661ADC2492CF509ULL,
		0xD2F6B0765936EDD6ULL,
		0xBCFEC01E0A286946ULL,
		0x2CAD049D6A8876BEULL,
		0x52D3E5E067DB4488ULL,
		0x3FC5B7A2CEDFBEF8ULL
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
		0x805E054880367568ULL,
		0xF999E702B111BBFAULL,
		0x6D0F6E4F4BC3FAEEULL,
		0x9B3297E439586A78ULL,
		0xDE4A34EAC86E1C26ULL,
		0xEC35B1F5EEA31CD8ULL,
		0x54FFA045E960DFFBULL,
		0x1E5356131E443E59ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x00BC0A91006CEAD0ULL,
		0xF333CE05622377F5ULL,
		0xDA1EDC9E9787F5DDULL,
		0x36652FC872B0D4F0ULL,
		0xBC9469D590DC384DULL,
		0xD86B63EBDD4639B1ULL,
		0xA9FF408BD2C1BFF7ULL,
		0x3CA6AC263C887CB2ULL
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
		0x078B414C7046F95BULL,
		0x9415A44D513F6A43ULL,
		0xF6DB1CFF62A43C22ULL,
		0xB430BAAFA3F40765ULL,
		0x0F1B68BDFDF6AD11ULL,
		0xC9FE5E2340C71E1CULL,
		0xDEF6DF92403C7CD1ULL,
		0x3D2CC9B87DD3D1B3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F168298E08DF2B6ULL,
		0x282B489AA27ED486ULL,
		0xEDB639FEC5487845ULL,
		0x6861755F47E80ECBULL,
		0x1E36D17BFBED5A23ULL,
		0x93FCBC46818E3C38ULL,
		0xBDEDBF248078F9A3ULL,
		0x7A599370FBA7A367ULL
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
		0x1FCDA78E135486BFULL,
		0x64BF2497E492F17BULL,
		0x13E1F31B6D6BEAB1ULL,
		0x543F2B853F4D7732ULL,
		0xE4078A2DE55DCA38ULL,
		0xE4FE9FF3383D6208ULL,
		0xCEA4C1CE857C13D4ULL,
		0x317CE07950703078ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3F9B4F1C26A90D7EULL,
		0xC97E492FC925E2F6ULL,
		0x27C3E636DAD7D562ULL,
		0xA87E570A7E9AEE64ULL,
		0xC80F145BCABB9470ULL,
		0xC9FD3FE6707AC411ULL,
		0x9D49839D0AF827A9ULL,
		0x62F9C0F2A0E060F1ULL
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
		0xAB7A197E32DB8BD2ULL,
		0x4A2804681277F3D0ULL,
		0xBA2EB32FC0F09D7FULL,
		0x33484FDA08EE9F7CULL,
		0x50D3584245A85D80ULL,
		0x23BAB11FA406E4A1ULL,
		0x8A2DD8EDC3654550ULL,
		0x1FD487F5C03EA8BCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x56F432FC65B717A4ULL,
		0x945008D024EFE7A1ULL,
		0x745D665F81E13AFEULL,
		0x66909FB411DD3EF9ULL,
		0xA1A6B0848B50BB00ULL,
		0x4775623F480DC942ULL,
		0x145BB1DB86CA8AA0ULL,
		0x3FA90FEB807D5179ULL
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
		0x8DC32CC94854630CULL,
		0x7B03DDF166BB3752ULL,
		0x8833E233E0DB9C0CULL,
		0x3CACCF0C0F875F03ULL,
		0x29DEFDBF7CF32D09ULL,
		0xFD0A4CAF88D4E15EULL,
		0x315E71708A58144BULL,
		0x1B16E028C884ABCFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1B86599290A8C618ULL,
		0xF607BBE2CD766EA5ULL,
		0x1067C467C1B73818ULL,
		0x79599E181F0EBE07ULL,
		0x53BDFB7EF9E65A12ULL,
		0xFA14995F11A9C2BCULL,
		0x62BCE2E114B02897ULL,
		0x362DC0519109579EULL
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
		0x0F1160B54931438FULL,
		0xB2C48262A90351CDULL,
		0x4CD35F7E6D23588FULL,
		0x870FF4060C112BF9ULL,
		0xFFF39F24E10C4ABCULL,
		0xC6A1BD444295F7C2ULL,
		0xBFCB54778E0E90D8ULL,
		0x2F55262FA8C76B4EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1E22C16A9262871EULL,
		0x658904C55206A39AULL,
		0x99A6BEFCDA46B11FULL,
		0x0E1FE80C182257F2ULL,
		0xFFE73E49C2189579ULL,
		0x8D437A88852BEF85ULL,
		0x7F96A8EF1C1D21B1ULL,
		0x5EAA4C5F518ED69DULL
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
		0x0D1E09A9027E08D6ULL,
		0x4B06A6600C2A4601ULL,
		0x0BD6F200F96A9D5FULL,
		0x089E2CD4CAA15C90ULL,
		0xB0FE7A4F49414F4FULL,
		0x31D5BEA04EDC8141ULL,
		0x554A4566D7A1BD07ULL,
		0x0A734C71A585189DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1A3C135204FC11ACULL,
		0x960D4CC018548C02ULL,
		0x17ADE401F2D53ABEULL,
		0x113C59A99542B920ULL,
		0x61FCF49E92829E9EULL,
		0x63AB7D409DB90283ULL,
		0xAA948ACDAF437A0EULL,
		0x14E698E34B0A313AULL
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
		0xA5A1D7C114AC4B81ULL,
		0x84C174D437D22B5CULL,
		0xE3D8732CE24DB1CBULL,
		0x52CD772BE4D51F15ULL,
		0x95772A156CCF1471ULL,
		0xD92241CD25141755ULL,
		0x183E37A36128F166ULL,
		0x1E92D79FC8A1A3FAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4B43AF8229589702ULL,
		0x0982E9A86FA456B9ULL,
		0xC7B0E659C49B6397ULL,
		0xA59AEE57C9AA3E2BULL,
		0x2AEE542AD99E28E2ULL,
		0xB244839A4A282EABULL,
		0x307C6F46C251E2CDULL,
		0x3D25AF3F914347F4ULL
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
		0x6F63ABA0F8733379ULL,
		0x3DBB86BD5DF91E9AULL,
		0x8FD4A9F4451DF014ULL,
		0xD4D558A875102F9EULL,
		0xB7CC5D93C3C4F6ABULL,
		0x0BF7275C796133B0ULL,
		0x4CA453478194AF64ULL,
		0x194A895F8524EF88ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDEC75741F0E666F2ULL,
		0x7B770D7ABBF23D34ULL,
		0x1FA953E88A3BE028ULL,
		0xA9AAB150EA205F3DULL,
		0x6F98BB278789ED57ULL,
		0x17EE4EB8F2C26761ULL,
		0x9948A68F03295EC8ULL,
		0x329512BF0A49DF10ULL
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
		0xF45A52DE32568449ULL,
		0x8F35ADB4CFAD1176ULL,
		0x20F148C1950C352CULL,
		0x383367EA613DD265ULL,
		0xEAE4CC9151265900ULL,
		0xE65F2C8DDF01988AULL,
		0xE8BF94071F8D646DULL,
		0x016A0CA1D8855907ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE8B4A5BC64AD0892ULL,
		0x1E6B5B699F5A22EDULL,
		0x41E291832A186A59ULL,
		0x7066CFD4C27BA4CAULL,
		0xD5C99922A24CB200ULL,
		0xCCBE591BBE033115ULL,
		0xD17F280E3F1AC8DBULL,
		0x02D41943B10AB20FULL
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
		0xEFB765E059DC362DULL,
		0x50FACDF637136453ULL,
		0x6941F7023438450CULL,
		0xD61E93199FF6AD0DULL,
		0x019B27B4B10DD235ULL,
		0xEDA99B3B21D0115EULL,
		0x4427DD49A6069905ULL,
		0x274320E5CEF82C99ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDF6ECBC0B3B86C5AULL,
		0xA1F59BEC6E26C8A7ULL,
		0xD283EE0468708A18ULL,
		0xAC3D26333FED5A1AULL,
		0x03364F69621BA46BULL,
		0xDB53367643A022BCULL,
		0x884FBA934C0D320BULL,
		0x4E8641CB9DF05932ULL
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
		0x732696400D1FBF99ULL,
		0xC205DF2C664F1C51ULL,
		0x193F876011482750ULL,
		0x096A0DC0E776C43BULL,
		0x2268DAD6B22D19B2ULL,
		0x28FB9ABD5A827F23ULL,
		0x3C6412828ABA8345ULL,
		0x11782140841CAB80ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE64D2C801A3F7F32ULL,
		0x840BBE58CC9E38A2ULL,
		0x327F0EC022904EA1ULL,
		0x12D41B81CEED8876ULL,
		0x44D1B5AD645A3364ULL,
		0x51F7357AB504FE46ULL,
		0x78C825051575068AULL,
		0x22F0428108395700ULL
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
		0x9B59DBB35CB6659AULL,
		0xDCB50D846914D3ADULL,
		0x26B1F09B319CAF21ULL,
		0x721402FBB7654E17ULL,
		0x03ECF1831134B35FULL,
		0x6BA85E9363C9E6ECULL,
		0x796553C24B94C553ULL,
		0x08BEE8DBEB3EDFD9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x36B3B766B96CCB34ULL,
		0xB96A1B08D229A75BULL,
		0x4D63E13663395E43ULL,
		0xE42805F76ECA9C2EULL,
		0x07D9E306226966BEULL,
		0xD750BD26C793CDD8ULL,
		0xF2CAA78497298AA6ULL,
		0x117DD1B7D67DBFB2ULL
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
		0x45A9ED29DE18186EULL,
		0xBEB4F896A5A2EBD4ULL,
		0x6DEE644EBFE3F61FULL,
		0x2CA4CDCB947F7B7AULL,
		0xAD5724E9F0F06842ULL,
		0x6FAF76EE4B05FB1DULL,
		0x2AFB621DB4D0279DULL,
		0x2CC678B79207C723ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8B53DA53BC3030DCULL,
		0x7D69F12D4B45D7A8ULL,
		0xDBDCC89D7FC7EC3FULL,
		0x59499B9728FEF6F4ULL,
		0x5AAE49D3E1E0D084ULL,
		0xDF5EEDDC960BF63BULL,
		0x55F6C43B69A04F3AULL,
		0x598CF16F240F8E46ULL
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
		0x455FD9E9D086FA56ULL,
		0x64DB2BC880B73605ULL,
		0x0F132E9756F7B475ULL,
		0x73C5805A29AA101FULL,
		0x88E61CD9D44484C7ULL,
		0xCC45F875B1EEFB7FULL,
		0x52D505E1D0ACAE93ULL,
		0x09312304C9FB40FAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8ABFB3D3A10DF4ACULL,
		0xC9B65791016E6C0AULL,
		0x1E265D2EADEF68EAULL,
		0xE78B00B45354203EULL,
		0x11CC39B3A889098EULL,
		0x988BF0EB63DDF6FFULL,
		0xA5AA0BC3A1595D27ULL,
		0x1262460993F681F4ULL
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
		0xC36282F95AE9AFCBULL,
		0x269C8E753F8EE40DULL,
		0x3831D568274353EFULL,
		0x04116B1155067B5FULL,
		0xF71C55B910B92F62ULL,
		0xD1559D99AC9D87E2ULL,
		0x3272D62037264361ULL,
		0x3A70037B2A1A0FFDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x86C505F2B5D35F96ULL,
		0x4D391CEA7F1DC81BULL,
		0x7063AAD04E86A7DEULL,
		0x0822D622AA0CF6BEULL,
		0xEE38AB7221725EC4ULL,
		0xA2AB3B33593B0FC5ULL,
		0x64E5AC406E4C86C3ULL,
		0x74E006F654341FFAULL
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
		0x89D97CAFFF26B665ULL,
		0xC5234F586DAF1B02ULL,
		0xE516CC2690023E49ULL,
		0xFA6C32FD42687FD0ULL,
		0xA46E5DD5ABD99BB3ULL,
		0x83E592C3A108951FULL,
		0x34D5C2BD27D9DD98ULL,
		0x3076DBFA761EFCD2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x13B2F95FFE4D6CCAULL,
		0x8A469EB0DB5E3605ULL,
		0xCA2D984D20047C93ULL,
		0xF4D865FA84D0FFA1ULL,
		0x48DCBBAB57B33767ULL,
		0x07CB258742112A3FULL,
		0x69AB857A4FB3BB31ULL,
		0x60EDB7F4EC3DF9A4ULL
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
		0x3E07BC509384A05DULL,
		0x06731BAC98944999ULL,
		0x11E00C53682E1592ULL,
		0x82D45808EAF72D30ULL,
		0x8499231D31A059C6ULL,
		0x09D5BACB871EDADBULL,
		0xD43401D495664BEAULL,
		0x1A15400626553026ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7C0F78A1270940BAULL,
		0x0CE6375931289332ULL,
		0x23C018A6D05C2B24ULL,
		0x05A8B011D5EE5A60ULL,
		0x0932463A6340B38DULL,
		0x13AB75970E3DB5B7ULL,
		0xA86803A92ACC97D4ULL,
		0x342A800C4CAA604DULL
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
		0xA0EAB4B294E57755ULL,
		0x2AE4893BA75B124BULL,
		0x1BA012668E913967ULL,
		0xFE90F64D92A5EB00ULL,
		0x71B2F46C05C7D39FULL,
		0x6E47F36BAF34D1F3ULL,
		0xB99E155B3B0436A6ULL,
		0x38B8107C66DFFB8EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x41D5696529CAEEAAULL,
		0x55C912774EB62497ULL,
		0x374024CD1D2272CEULL,
		0xFD21EC9B254BD600ULL,
		0xE365E8D80B8FA73FULL,
		0xDC8FE6D75E69A3E6ULL,
		0x733C2AB676086D4CULL,
		0x717020F8CDBFF71DULL
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
		0x35441AB9ECB0F799ULL,
		0xBCF265DC6FEF32F8ULL,
		0xFA192A1D37B365EBULL,
		0x2347BA1A533A8B58ULL,
		0x4EAFFD67112F3DCAULL,
		0x83F7E203F54E3F43ULL,
		0xDA175127A1ED63B1ULL,
		0x36FFCBE0EB36AAA6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6A883573D961EF32ULL,
		0x79E4CBB8DFDE65F0ULL,
		0xF432543A6F66CBD7ULL,
		0x468F7434A67516B1ULL,
		0x9D5FFACE225E7B94ULL,
		0x07EFC407EA9C7E86ULL,
		0xB42EA24F43DAC763ULL,
		0x6DFF97C1D66D554DULL
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
		0xC2DA3E7F6C47F91DULL,
		0x06A921EF18E28689ULL,
		0x750E742D965DA071ULL,
		0xAEF1C4B42EBFB5BEULL,
		0x9DE9910FEF41F006ULL,
		0x5A1C264F062D1D7CULL,
		0xF6E5873214F8D488ULL,
		0x107F6ABA3C932B5BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x85B47CFED88FF23AULL,
		0x0D5243DE31C50D13ULL,
		0xEA1CE85B2CBB40E2ULL,
		0x5DE389685D7F6B7CULL,
		0x3BD3221FDE83E00DULL,
		0xB4384C9E0C5A3AF9ULL,
		0xEDCB0E6429F1A910ULL,
		0x20FED574792656B7ULL
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
		0xBBE1C9542175F090ULL,
		0xBD3441FF19E34C6EULL,
		0x022047454E76FD85ULL,
		0x931DE857E1017441ULL,
		0x8CD29A1F65B85722ULL,
		0x38E5AAF574D838B1ULL,
		0xA6F1C425FB6C45FDULL,
		0x3748935BB1F93075ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x77C392A842EBE120ULL,
		0x7A6883FE33C698DDULL,
		0x04408E8A9CEDFB0BULL,
		0x263BD0AFC202E882ULL,
		0x19A5343ECB70AE45ULL,
		0x71CB55EAE9B07163ULL,
		0x4DE3884BF6D88BFAULL,
		0x6E9126B763F260EBULL
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
		0xE64947ADC23693C4ULL,
		0x9A545372DDC0C2C5ULL,
		0x1E881907B88C63AEULL,
		0x7C508612529093C9ULL,
		0x9CA4581BF4393724ULL,
		0xEF9FC97691135440ULL,
		0x31B94F7490C8367DULL,
		0x29376F227C35DBC2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCC928F5B846D2788ULL,
		0x34A8A6E5BB81858BULL,
		0x3D10320F7118C75DULL,
		0xF8A10C24A5212792ULL,
		0x3948B037E8726E48ULL,
		0xDF3F92ED2226A881ULL,
		0x63729EE921906CFBULL,
		0x526EDE44F86BB784ULL
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
		0x79C57445470EC752ULL,
		0xB45E18371B45FD01ULL,
		0xAF45B80C628FBFFCULL,
		0x514EA6969CFD5091ULL,
		0x51D68D3124D24457ULL,
		0x00055B40031D30A1ULL,
		0xEEFF89257564B1FAULL,
		0x0B047161EEB21998ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF38AE88A8E1D8EA4ULL,
		0x68BC306E368BFA02ULL,
		0x5E8B7018C51F7FF9ULL,
		0xA29D4D2D39FAA123ULL,
		0xA3AD1A6249A488AEULL,
		0x000AB680063A6142ULL,
		0xDDFF124AEAC963F4ULL,
		0x1608E2C3DD643331ULL
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
		0xE6024D8BA4483655ULL,
		0x9301546564A493F3ULL,
		0x75E3CE152AAD3137ULL,
		0x466B6960A6B3AA2EULL,
		0x0BD6024106A66D50ULL,
		0xC32081B631862E1BULL,
		0xF387E990FC056E52ULL,
		0x375137BEC5335AA5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCC049B1748906CAAULL,
		0x2602A8CAC94927E7ULL,
		0xEBC79C2A555A626FULL,
		0x8CD6D2C14D67545CULL,
		0x17AC04820D4CDAA0ULL,
		0x8641036C630C5C36ULL,
		0xE70FD321F80ADCA5ULL,
		0x6EA26F7D8A66B54BULL
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
		0x2E3AC8CCB38C8E48ULL,
		0x44366C768A03596EULL,
		0x96191CF580385427ULL,
		0x23CED6CACE1CCF23ULL,
		0xE4E1843B52BF0151ULL,
		0x269A89468EE5537BULL,
		0x9319C80EC29EBBEAULL,
		0x2EBF58FCD9AAC5C7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5C75919967191C90ULL,
		0x886CD8ED1406B2DCULL,
		0x2C3239EB0070A84EULL,
		0x479DAD959C399E47ULL,
		0xC9C30876A57E02A2ULL,
		0x4D35128D1DCAA6F7ULL,
		0x2633901D853D77D4ULL,
		0x5D7EB1F9B3558B8FULL
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
		0xFEA9312641BD3A20ULL,
		0x594FCB3145C50C69ULL,
		0x9C1F1666FDF0DFD8ULL,
		0x65302C7DEF0C7E6FULL,
		0x1F3777FCB8DB9F77ULL,
		0x3638719A60CCFA3EULL,
		0xA0894632709E3585ULL,
		0x2E77AEE037E4BA5EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFD52624C837A7440ULL,
		0xB29F96628B8A18D3ULL,
		0x383E2CCDFBE1BFB0ULL,
		0xCA6058FBDE18FCDFULL,
		0x3E6EEFF971B73EEEULL,
		0x6C70E334C199F47CULL,
		0x41128C64E13C6B0AULL,
		0x5CEF5DC06FC974BDULL
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
		0x0EB6A3313BF81411ULL,
		0x4E528CDCA5311ED1ULL,
		0x5E274395C39D811AULL,
		0x8ED9E184CD58EB3FULL,
		0x4050851E85E63C07ULL,
		0x70901F5A58040F86ULL,
		0x2D6F5974E5F8274FULL,
		0x12A777460619ED83ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1D6D466277F02822ULL,
		0x9CA519B94A623DA2ULL,
		0xBC4E872B873B0234ULL,
		0x1DB3C3099AB1D67EULL,
		0x80A10A3D0BCC780FULL,
		0xE1203EB4B0081F0CULL,
		0x5ADEB2E9CBF04E9EULL,
		0x254EEE8C0C33DB06ULL
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
		0xF63DA1EF6F18A9ADULL,
		0x97E684C3EE3E0119ULL,
		0x193C3F375FACC70CULL,
		0xA55FD4FF955267BFULL,
		0x8412A338D32D92ACULL,
		0x058971294AA11E65ULL,
		0x901B890A7C83F6A6ULL,
		0x12C490959C9FE547ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEC7B43DEDE31535AULL,
		0x2FCD0987DC7C0233ULL,
		0x32787E6EBF598E19ULL,
		0x4ABFA9FF2AA4CF7EULL,
		0x08254671A65B2559ULL,
		0x0B12E25295423CCBULL,
		0x20371214F907ED4CULL,
		0x2589212B393FCA8FULL
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
		0x16769D9175C10584ULL,
		0xCF1D6262D77CA012ULL,
		0xC184D15F9C3C3CA1ULL,
		0xB3CCAAB9399EA77AULL,
		0xDCE49821519A6F1CULL,
		0xBFAF9F0A4099354CULL,
		0x45177E2CFBF2368CULL,
		0x2462FF36E6C7BA7FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2CED3B22EB820B08ULL,
		0x9E3AC4C5AEF94024ULL,
		0x8309A2BF38787943ULL,
		0x67995572733D4EF5ULL,
		0xB9C93042A334DE39ULL,
		0x7F5F3E1481326A99ULL,
		0x8A2EFC59F7E46D19ULL,
		0x48C5FE6DCD8F74FEULL
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
		0x07980866607BDD07ULL,
		0x68F0D868531E0CC7ULL,
		0x3BA832D9FBECD607ULL,
		0x18B5FD98366E0258ULL,
		0xD36FB1B1985D542FULL,
		0x4EE3BF076BA0A5DDULL,
		0x9B22C328DB524728ULL,
		0x394A0BF4A9C85398ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F3010CCC0F7BA0EULL,
		0xD1E1B0D0A63C198EULL,
		0x775065B3F7D9AC0EULL,
		0x316BFB306CDC04B0ULL,
		0xA6DF636330BAA85EULL,
		0x9DC77E0ED7414BBBULL,
		0x36458651B6A48E50ULL,
		0x729417E95390A731ULL
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
		0xC9FDDF0A0283426FULL,
		0x783258BE312FD773ULL,
		0x8403363BCF2F512AULL,
		0x3AD11F152F8A2765ULL,
		0x4492369C54C6B8A9ULL,
		0x9F8377A0B4E3B5C4ULL,
		0xE12AF57134CBD7B2ULL,
		0x24E351AE8FE8F599ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x93FBBE14050684DEULL,
		0xF064B17C625FAEE7ULL,
		0x08066C779E5EA254ULL,
		0x75A23E2A5F144ECBULL,
		0x89246D38A98D7152ULL,
		0x3F06EF4169C76B88ULL,
		0xC255EAE26997AF65ULL,
		0x49C6A35D1FD1EB33ULL
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
		0x7212B2AE9442DD56ULL,
		0xF9103CE557ABB885ULL,
		0x4E067A5203B3B2CFULL,
		0xC3489AF5FB7AD4BBULL,
		0x4A07FCCE00D1A87FULL,
		0x1224F5F21500EDCAULL,
		0xFF99F2EE8CE7C5AAULL,
		0x3E931CA62EB816C9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE425655D2885BAACULL,
		0xF22079CAAF57710AULL,
		0x9C0CF4A40767659FULL,
		0x869135EBF6F5A976ULL,
		0x940FF99C01A350FFULL,
		0x2449EBE42A01DB94ULL,
		0xFF33E5DD19CF8B54ULL,
		0x7D26394C5D702D93ULL
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
		0xFF73DF098FBE4F1EULL,
		0xEA6AE952A1CA5529ULL,
		0x5FA1BE56A971D865ULL,
		0x2AE3D02398518E50ULL,
		0x0F5A9A408011EC8EULL,
		0x940E2C51A48D2742ULL,
		0x90188936B0900AA0ULL,
		0x322C7A9DC81AE578ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFEE7BE131F7C9E3CULL,
		0xD4D5D2A54394AA53ULL,
		0xBF437CAD52E3B0CBULL,
		0x55C7A04730A31CA0ULL,
		0x1EB534810023D91CULL,
		0x281C58A3491A4E84ULL,
		0x2031126D61201541ULL,
		0x6458F53B9035CAF1ULL
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
		0x6C4942D6757678E9ULL,
		0x3FAEFBA9C3138E12ULL,
		0xCCC9CAFBE433D715ULL,
		0x8DD420AAAC368BA5ULL,
		0x7985544D0A84E6F0ULL,
		0x820056DC1969BB87ULL,
		0xB9972665D50012E2ULL,
		0x158EFF54AF150CF2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD89285ACEAECF1D2ULL,
		0x7F5DF75386271C24ULL,
		0x999395F7C867AE2AULL,
		0x1BA84155586D174BULL,
		0xF30AA89A1509CDE1ULL,
		0x0400ADB832D3770EULL,
		0x732E4CCBAA0025C5ULL,
		0x2B1DFEA95E2A19E5ULL
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
		0x70C682E0F9EED280ULL,
		0x834FCA4D9ED183C5ULL,
		0x1A2EB145FF2BC90CULL,
		0x604174D94D36612CULL,
		0x64CE48362CB911A0ULL,
		0xB2229405461E16D2ULL,
		0xDD4DA489AE482E44ULL,
		0x11858706ECE9767DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE18D05C1F3DDA500ULL,
		0x069F949B3DA3078AULL,
		0x345D628BFE579219ULL,
		0xC082E9B29A6CC258ULL,
		0xC99C906C59722340ULL,
		0x6445280A8C3C2DA4ULL,
		0xBA9B49135C905C89ULL,
		0x230B0E0DD9D2ECFBULL
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
		0x55A051AA6CC9D0CEULL,
		0xC8BE22AF52FBE5FBULL,
		0x3E69F30E6FB312EAULL,
		0x16326EEB34E2EEB5ULL,
		0xA7B77F0BACFC0AA6ULL,
		0xC3023FE9E9A7BD0CULL,
		0xE5D9708DB4B0F223ULL,
		0x29BB85A702C87255ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAB40A354D993A19CULL,
		0x917C455EA5F7CBF6ULL,
		0x7CD3E61CDF6625D5ULL,
		0x2C64DDD669C5DD6AULL,
		0x4F6EFE1759F8154CULL,
		0x86047FD3D34F7A19ULL,
		0xCBB2E11B6961E447ULL,
		0x53770B4E0590E4ABULL
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
		0x40AB3B49708E4B4BULL,
		0x4475145C2C29570CULL,
		0x0FB3640C1896897FULL,
		0x093D58095F2D67D4ULL,
		0x8F7FE3BB7CB22F2CULL,
		0x3378933CA54855EFULL,
		0x39ADA69A21D11271ULL,
		0x2C1ED60E0AD5FA0CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x81567692E11C9696ULL,
		0x88EA28B85852AE18ULL,
		0x1F66C818312D12FEULL,
		0x127AB012BE5ACFA8ULL,
		0x1EFFC776F9645E58ULL,
		0x66F126794A90ABDFULL,
		0x735B4D3443A224E2ULL,
		0x583DAC1C15ABF418ULL
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
		0xF7001ACBC46B613CULL,
		0x1BBB68399A414C3EULL,
		0x68CDAA06222CE09FULL,
		0xA7C1A456AB3DC218ULL,
		0x14CF597FA57825FBULL,
		0xD01F82611913BCDAULL,
		0xAD7F36FFBFBF2EC7ULL,
		0x2EC03E4A88D3D751ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEE00359788D6C278ULL,
		0x3776D0733482987DULL,
		0xD19B540C4459C13EULL,
		0x4F8348AD567B8430ULL,
		0x299EB2FF4AF04BF7ULL,
		0xA03F04C2322779B4ULL,
		0x5AFE6DFF7F7E5D8FULL,
		0x5D807C9511A7AEA3ULL
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
		0x14791DE10375B2C3ULL,
		0x5C924400A424A05AULL,
		0x65618C68E02400CDULL,
		0x810FBB7D600F75ECULL,
		0x59C9256E7C27AE8FULL,
		0x62C8E2144CCA3477ULL,
		0xDC6AFE7544E5FF4EULL,
		0x08369D05A4FEDA19ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x28F23BC206EB6586ULL,
		0xB9248801484940B4ULL,
		0xCAC318D1C048019AULL,
		0x021F76FAC01EEBD8ULL,
		0xB3924ADCF84F5D1FULL,
		0xC591C428999468EEULL,
		0xB8D5FCEA89CBFE9CULL,
		0x106D3A0B49FDB433ULL
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
		0xD231AC6EEFA28BBEULL,
		0x688722EB9CDFFADFULL,
		0xC1968BF8B254C2FDULL,
		0x25356C96B31FF2B4ULL,
		0xE66B0729A954D249ULL,
		0x9DA295C6C050260BULL,
		0xC7F625530130F8E3ULL,
		0x1772EC8BC815477FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA46358DDDF45177CULL,
		0xD10E45D739BFF5BFULL,
		0x832D17F164A985FAULL,
		0x4A6AD92D663FE569ULL,
		0xCCD60E5352A9A492ULL,
		0x3B452B8D80A04C17ULL,
		0x8FEC4AA60261F1C7ULL,
		0x2EE5D917902A8EFFULL
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
		0x5F4AF19AFD5ABC38ULL,
		0x000A6F91B2374BA7ULL,
		0x28A59984CD89E586ULL,
		0x575A245C39BF2EE2ULL,
		0xCF057C6B408DD4A9ULL,
		0x75AFCCD93E3FAFDBULL,
		0xD8A2F1D4CCFC338FULL,
		0x1FA8D398DFBDC85CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBE95E335FAB57870ULL,
		0x0014DF23646E974EULL,
		0x514B33099B13CB0CULL,
		0xAEB448B8737E5DC4ULL,
		0x9E0AF8D6811BA952ULL,
		0xEB5F99B27C7F5FB7ULL,
		0xB145E3A999F8671EULL,
		0x3F51A731BF7B90B9ULL
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
		0x6D8B7D81166A2665ULL,
		0x408D51608B660BDCULL,
		0xE825EAB59DB99CDCULL,
		0xF512F356D3C52106ULL,
		0xE5DB754DBC82ADE3ULL,
		0x723895247F9B37BFULL,
		0x00EF99266DE0A8BEULL,
		0x1C296A582AB05AA7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDB16FB022CD44CCAULL,
		0x811AA2C116CC17B8ULL,
		0xD04BD56B3B7339B8ULL,
		0xEA25E6ADA78A420DULL,
		0xCBB6EA9B79055BC7ULL,
		0xE4712A48FF366F7FULL,
		0x01DF324CDBC1517CULL,
		0x3852D4B05560B54EULL
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
		0xBD754743F6545B05ULL,
		0xE0DF2B17FCA03729ULL,
		0x18550529FD15BFDFULL,
		0xB8D081C0FABDF390ULL,
		0x579CA58FE1EBD2A0ULL,
		0x690CBA5EAEF8CD42ULL,
		0x9D80377DD4171807ULL,
		0x2D46B745EC050B7AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7AEA8E87ECA8B60AULL,
		0xC1BE562FF9406E53ULL,
		0x30AA0A53FA2B7FBFULL,
		0x71A10381F57BE720ULL,
		0xAF394B1FC3D7A541ULL,
		0xD21974BD5DF19A84ULL,
		0x3B006EFBA82E300EULL,
		0x5A8D6E8BD80A16F5ULL
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
		0x2262A2994C0C64DBULL,
		0x3A133BBE8AA7B9BBULL,
		0x7FAE5B9C2D2BB46FULL,
		0x0B1FCE8406EE784DULL,
		0x1AD2564D47CDC9ACULL,
		0x03318AD0A5F62DBEULL,
		0x1306668B713965A6ULL,
		0x1FDA23C2F059B35DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x44C545329818C9B6ULL,
		0x7426777D154F7376ULL,
		0xFF5CB7385A5768DEULL,
		0x163F9D080DDCF09AULL,
		0x35A4AC9A8F9B9358ULL,
		0x066315A14BEC5B7CULL,
		0x260CCD16E272CB4CULL,
		0x3FB44785E0B366BAULL
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
		0x6682F746C456E802ULL,
		0x0087722C192B42C3ULL,
		0xF6F688D0E51C6441ULL,
		0x715760B2D00CAC41ULL,
		0x41B948122F7FFE95ULL,
		0xDFC292961DA10FAAULL,
		0xEA8392EB903DF3E4ULL,
		0x2FFDFEAA674A9908ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCD05EE8D88ADD004ULL,
		0x010EE45832568586ULL,
		0xEDED11A1CA38C882ULL,
		0xE2AEC165A0195883ULL,
		0x837290245EFFFD2AULL,
		0xBF85252C3B421F54ULL,
		0xD50725D7207BE7C9ULL,
		0x5FFBFD54CE953211ULL
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
		0x1FB1EADB857FCE39ULL,
		0x184A6EF8ADCC9ADBULL,
		0x045EE22101072A4FULL,
		0x4B1E77C56C52CC79ULL,
		0xD36900FE7D3FA138ULL,
		0x36E14D2C4168C0FFULL,
		0xB793AC4E86366B5DULL,
		0x3D74BC57F6E85536ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3F63D5B70AFF9C72ULL,
		0x3094DDF15B9935B6ULL,
		0x08BDC442020E549EULL,
		0x963CEF8AD8A598F2ULL,
		0xA6D201FCFA7F4270ULL,
		0x6DC29A5882D181FFULL,
		0x6F27589D0C6CD6BAULL,
		0x7AE978AFEDD0AA6DULL
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
		0x53E02124651BC53BULL,
		0x66C32461A3C0219BULL,
		0x30A189D792347451ULL,
		0x3C705FC1BF370F8BULL,
		0xBC4CBCEA79C042B7ULL,
		0x60E9F3703A2FDBC9ULL,
		0x909A882EF7599DF7ULL,
		0x262CE9236B442058ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA7C04248CA378A76ULL,
		0xCD8648C347804336ULL,
		0x614313AF2468E8A2ULL,
		0x78E0BF837E6E1F16ULL,
		0x789979D4F380856EULL,
		0xC1D3E6E0745FB793ULL,
		0x2135105DEEB33BEEULL,
		0x4C59D246D68840B1ULL
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
		0xF7E17E886200271DULL,
		0x0B3E83C5C61512A2ULL,
		0x5C6091121B9B3755ULL,
		0xB12A94B7045C3826ULL,
		0x1D4BF5960B145D51ULL,
		0xD5B4D432B6A03533ULL,
		0xB5E7BBFEFEE77FC8ULL,
		0x15CD78E233B53A86ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEFC2FD10C4004E3AULL,
		0x167D078B8C2A2545ULL,
		0xB8C1222437366EAAULL,
		0x6255296E08B8704CULL,
		0x3A97EB2C1628BAA3ULL,
		0xAB69A8656D406A66ULL,
		0x6BCF77FDFDCEFF91ULL,
		0x2B9AF1C4676A750DULL
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
		0xA1F42B0899C7A037ULL,
		0x4A3F0FBC3C5B2E66ULL,
		0x632B108AA718153EULL,
		0x494DD3674E0A5A9AULL,
		0x6D942D11D080B1CEULL,
		0x1AB4B028A83E77E7ULL,
		0x2CAEBF64A4F05B50ULL,
		0x0FC4387F136E0EF4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x43E85611338F406EULL,
		0x947E1F7878B65CCDULL,
		0xC65621154E302A7CULL,
		0x929BA6CE9C14B534ULL,
		0xDB285A23A101639CULL,
		0x35696051507CEFCEULL,
		0x595D7EC949E0B6A0ULL,
		0x1F8870FE26DC1DE8ULL
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
		0x7036A32B0FC30067ULL,
		0xA0B2679876987BE6ULL,
		0xAB1C09B8C359080AULL,
		0xA026029A1662A31CULL,
		0xCAC67074D8FB67C5ULL,
		0x9C690EB6781068ABULL,
		0x8375367218E31AD3ULL,
		0x3545B7B43EC676E4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE06D46561F8600CEULL,
		0x4164CF30ED30F7CCULL,
		0x5638137186B21015ULL,
		0x404C05342CC54639ULL,
		0x958CE0E9B1F6CF8BULL,
		0x38D21D6CF020D157ULL,
		0x06EA6CE431C635A7ULL,
		0x6A8B6F687D8CEDC9ULL
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
		0x1D486941B5C13630ULL,
		0x8B2975816B0965B8ULL,
		0x43FA8C9F6894A01DULL,
		0xB960BE0B48A7D09EULL,
		0xE0BEB2BF50E6822CULL,
		0x40AAF338D972A72FULL,
		0xA92A61FC04B32345ULL,
		0x1FBBDA92B904C502ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3A90D2836B826C60ULL,
		0x1652EB02D612CB70ULL,
		0x87F5193ED129403BULL,
		0x72C17C16914FA13CULL,
		0xC17D657EA1CD0459ULL,
		0x8155E671B2E54E5FULL,
		0x5254C3F80966468AULL,
		0x3F77B52572098A05ULL
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
		0xE71E5869CA135494ULL,
		0x2241ED8523DAAEC4ULL,
		0xA462008DD7E79561ULL,
		0xAF9E21053C3EEF60ULL,
		0xE9B85357654696F3ULL,
		0xB9322FFDAE9571C1ULL,
		0x814FD6D55C48F7CFULL,
		0x02C6D64599F553D6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCE3CB0D39426A928ULL,
		0x4483DB0A47B55D89ULL,
		0x48C4011BAFCF2AC2ULL,
		0x5F3C420A787DDEC1ULL,
		0xD370A6AECA8D2DE7ULL,
		0x72645FFB5D2AE383ULL,
		0x029FADAAB891EF9FULL,
		0x058DAC8B33EAA7ADULL
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
		0xCC08457326800896ULL,
		0x489600DFCC904033ULL,
		0xF96E8772F426C79FULL,
		0x6B5B0F7920329DBDULL,
		0x67DE8BD39F3740C4ULL,
		0x4167C0830D1624C9ULL,
		0x309EB320F7310633ULL,
		0x198C2092391D2B38ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x98108AE64D00112CULL,
		0x912C01BF99208067ULL,
		0xF2DD0EE5E84D8F3EULL,
		0xD6B61EF240653B7BULL,
		0xCFBD17A73E6E8188ULL,
		0x82CF81061A2C4992ULL,
		0x613D6641EE620C66ULL,
		0x33184124723A5670ULL
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
		0x1EF2F8EDA56B9165ULL,
		0x8453C4D4F05FA216ULL,
		0x971C1FE98D8DDA7AULL,
		0xE694C622B58885E2ULL,
		0x49CDDE6B53D0539FULL,
		0x316DFB13561B00F2ULL,
		0xC41E8C2CD7429E74ULL,
		0x224C3DCDC437FDECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3DE5F1DB4AD722CAULL,
		0x08A789A9E0BF442CULL,
		0x2E383FD31B1BB4F5ULL,
		0xCD298C456B110BC5ULL,
		0x939BBCD6A7A0A73FULL,
		0x62DBF626AC3601E4ULL,
		0x883D1859AE853CE8ULL,
		0x44987B9B886FFBD9ULL
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
		0xC8CD2A74192CA9C9ULL,
		0x3FC9B1F89853ED0BULL,
		0xF1593C59E6BE08DFULL,
		0xA85C5511E577497DULL,
		0x4B0419A2AE73B3D6ULL,
		0x668FFBD7325B3DC8ULL,
		0x4A0A62759EF23A9BULL,
		0x2AED2412A7B51250ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x919A54E832595392ULL,
		0x7F9363F130A7DA17ULL,
		0xE2B278B3CD7C11BEULL,
		0x50B8AA23CAEE92FBULL,
		0x960833455CE767ADULL,
		0xCD1FF7AE64B67B90ULL,
		0x9414C4EB3DE47536ULL,
		0x55DA48254F6A24A0ULL
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
		0xBED88ADBF62D77DFULL,
		0xA9449F6B6A1CCA55ULL,
		0x622B2E4089B6BD12ULL,
		0x5E9F3A0B1AD076E9ULL,
		0xD562CD6857A2BDC0ULL,
		0xEEC782EB8030CA88ULL,
		0xC2DFC8F75BE554EEULL,
		0x044734BF2B96FA40ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7DB115B7EC5AEFBEULL,
		0x52893ED6D43994ABULL,
		0xC4565C81136D7A25ULL,
		0xBD3E741635A0EDD2ULL,
		0xAAC59AD0AF457B80ULL,
		0xDD8F05D700619511ULL,
		0x85BF91EEB7CAA9DDULL,
		0x088E697E572DF481ULL
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
		0xD3B2BC69EE9F19B7ULL,
		0x94E90B42C08FA428ULL,
		0x687F68C3994BB0C2ULL,
		0xE33768A0CF12C919ULL,
		0x0CCF6BDA03A9A29FULL,
		0xF832F12524AABB6AULL,
		0x933B1F6E9C4312AFULL,
		0x1771E10844E12888ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA76578D3DD3E336EULL,
		0x29D21685811F4851ULL,
		0xD0FED18732976185ULL,
		0xC66ED1419E259232ULL,
		0x199ED7B40753453FULL,
		0xF065E24A495576D4ULL,
		0x26763EDD3886255FULL,
		0x2EE3C21089C25111ULL
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
		0x5BB7079E2B12692DULL,
		0xCA16D09E8A561AFDULL,
		0x90ED95624C0A378EULL,
		0x2789BF0E97EF0C2DULL,
		0x535ABD615F7A95CFULL,
		0xD2CEECC0D6212534ULL,
		0x6602B8FF26A65748ULL,
		0x2D4F1C7A93097FE1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB76E0F3C5624D25AULL,
		0x942DA13D14AC35FAULL,
		0x21DB2AC498146F1DULL,
		0x4F137E1D2FDE185BULL,
		0xA6B57AC2BEF52B9EULL,
		0xA59DD981AC424A68ULL,
		0xCC0571FE4D4CAE91ULL,
		0x5A9E38F52612FFC2ULL
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
		0xC63B2794BCC15A5EULL,
		0x26216BEC84BAC5D4ULL,
		0x84CA9EF3D749634AULL,
		0x176C1DFF3FC5CA78ULL,
		0xB5E2F3C8EC3F6818ULL,
		0x954ED54232F68D77ULL,
		0x78A26C5CF181B999ULL,
		0x15E50BCA713B6122ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8C764F297982B4BCULL,
		0x4C42D7D909758BA9ULL,
		0x09953DE7AE92C694ULL,
		0x2ED83BFE7F8B94F1ULL,
		0x6BC5E791D87ED030ULL,
		0x2A9DAA8465ED1AEFULL,
		0xF144D8B9E3037333ULL,
		0x2BCA1794E276C244ULL
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
		0x686C3A4A487A2083ULL,
		0x6DF287166D03D5CCULL,
		0x484625F9B790B275ULL,
		0x975FECB611C2AED2ULL,
		0x86C870950452033EULL,
		0x6ED2D1D0537D92BBULL,
		0x7359B7FFBA0FA82BULL,
		0x0E40AC0F45BB4529ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD0D8749490F44106ULL,
		0xDBE50E2CDA07AB98ULL,
		0x908C4BF36F2164EAULL,
		0x2EBFD96C23855DA4ULL,
		0x0D90E12A08A4067DULL,
		0xDDA5A3A0A6FB2577ULL,
		0xE6B36FFF741F5056ULL,
		0x1C81581E8B768A52ULL
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
		0x1C8A8D7DF267FAA5ULL,
		0xA4F9478CF71E4795ULL,
		0xDB2ED01F3510EBC3ULL,
		0x52FD1CBFEF800B32ULL,
		0xE92FA30F3A322D23ULL,
		0xA8F54E1D0023ADDDULL,
		0x086C24FE95C45385ULL,
		0x05D2B2BEEC5D820BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x39151AFBE4CFF54AULL,
		0x49F28F19EE3C8F2AULL,
		0xB65DA03E6A21D787ULL,
		0xA5FA397FDF001665ULL,
		0xD25F461E74645A46ULL,
		0x51EA9C3A00475BBBULL,
		0x10D849FD2B88A70BULL,
		0x0BA5657DD8BB0416ULL
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
		0x6C777D35246F1D09ULL,
		0xCD2D7FF0078B0498ULL,
		0xF20ACDF272D91621ULL,
		0xDCAF8DA0DC872B40ULL,
		0x029BB8240E289822ULL,
		0xBBE42FFC8F2246D5ULL,
		0x0D7407DC24E00631ULL,
		0x0BC3F82602FE2621ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD8EEFA6A48DE3A12ULL,
		0x9A5AFFE00F160930ULL,
		0xE4159BE4E5B22C43ULL,
		0xB95F1B41B90E5681ULL,
		0x053770481C513045ULL,
		0x77C85FF91E448DAAULL,
		0x1AE80FB849C00C63ULL,
		0x1787F04C05FC4C42ULL
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
		0x1EB94028A7B170E7ULL,
		0xF3A64261568452F5ULL,
		0xE54D6C2BB6A4BE2AULL,
		0xDB6AF557C373785BULL,
		0x92056024A3750DC7ULL,
		0x2D5987980FB0C7E7ULL,
		0x968240B55564609CULL,
		0x095D88A9B1835378ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3D7280514F62E1CEULL,
		0xE74C84C2AD08A5EAULL,
		0xCA9AD8576D497C55ULL,
		0xB6D5EAAF86E6F0B7ULL,
		0x240AC04946EA1B8FULL,
		0x5AB30F301F618FCFULL,
		0x2D04816AAAC8C138ULL,
		0x12BB11536306A6F1ULL
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
		0xF68CF3FB454B943CULL,
		0x2E40CF1A6AC5B6F5ULL,
		0xDF9D06F5DA6C69C4ULL,
		0x286410F3CE6CEA3AULL,
		0xC2781EFBD8897E55ULL,
		0x160F609E556492F3ULL,
		0x3B5C48EE8548A5F3ULL,
		0x2FDBA5F52A04D48BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xED19E7F68A972878ULL,
		0x5C819E34D58B6DEBULL,
		0xBF3A0DEBB4D8D388ULL,
		0x50C821E79CD9D475ULL,
		0x84F03DF7B112FCAAULL,
		0x2C1EC13CAAC925E7ULL,
		0x76B891DD0A914BE6ULL,
		0x5FB74BEA5409A916ULL
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
		0xED2288916E12AB6DULL,
		0x5530575E934B7977ULL,
		0x4639F06B4A484938ULL,
		0xC44123C8A93ADE94ULL,
		0xB6E0BF49AD7AF62EULL,
		0x9453CF50C3FC4EEFULL,
		0xD15E627E9773C90DULL,
		0x04C90C85B598F90FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDA451122DC2556DAULL,
		0xAA60AEBD2696F2EFULL,
		0x8C73E0D694909270ULL,
		0x888247915275BD28ULL,
		0x6DC17E935AF5EC5DULL,
		0x28A79EA187F89DDFULL,
		0xA2BCC4FD2EE7921BULL,
		0x0992190B6B31F21FULL
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
		0xD6B900638E73C82DULL,
		0x9FD0C45AA76C438EULL,
		0xB1CB0B7D9C90E984ULL,
		0x2EDBF81119C6DBB4ULL,
		0x58C06E15C9BDC4B6ULL,
		0x383377BF7E9B497BULL,
		0x32BA8188F9CED79DULL,
		0x1588D07A81F45E1BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAD7200C71CE7905AULL,
		0x3FA188B54ED8871DULL,
		0x639616FB3921D309ULL,
		0x5DB7F022338DB769ULL,
		0xB180DC2B937B896CULL,
		0x7066EF7EFD3692F6ULL,
		0x65750311F39DAF3AULL,
		0x2B11A0F503E8BC36ULL
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
		0x341540650AE4F746ULL,
		0x420F6006C69BA321ULL,
		0xE356A73E1F07E445ULL,
		0xE256FDB9DB2467AEULL,
		0x23D6DF2BBACADB85ULL,
		0xCCB5C167C6407993ULL,
		0xDEE9E9063FE7DF12ULL,
		0x3E1E58749ADD2F6CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x682A80CA15C9EE8CULL,
		0x841EC00D8D374642ULL,
		0xC6AD4E7C3E0FC88AULL,
		0xC4ADFB73B648CF5DULL,
		0x47ADBE577595B70BULL,
		0x996B82CF8C80F326ULL,
		0xBDD3D20C7FCFBE25ULL,
		0x7C3CB0E935BA5ED9ULL
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
		0x403DFB9FEC0EC902ULL,
		0x180EDA6B628762F5ULL,
		0x852F8E84C24DF2DDULL,
		0xAF0966AF39426D7CULL,
		0x74847F9446483830ULL,
		0x77A742BAEAC30507ULL,
		0x89A1877B58C415DDULL,
		0x21B6C33747E1D364ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x807BF73FD81D9204ULL,
		0x301DB4D6C50EC5EAULL,
		0x0A5F1D09849BE5BAULL,
		0x5E12CD5E7284DAF9ULL,
		0xE908FF288C907061ULL,
		0xEF4E8575D5860A0EULL,
		0x13430EF6B1882BBAULL,
		0x436D866E8FC3A6C9ULL
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
		0x57A5004170E8C5D1ULL,
		0xC94A01E7C9EA4660ULL,
		0x6D8E875D98470C8FULL,
		0x181B57232713D21DULL,
		0x7B905C1E9E9168D7ULL,
		0x707FC1AB83E28461ULL,
		0xAA4A8AF01A82D27AULL,
		0x0492AA44C337DDB5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF4A0082E1D18BA2ULL,
		0x929403CF93D48CC0ULL,
		0xDB1D0EBB308E191FULL,
		0x3036AE464E27A43AULL,
		0xF720B83D3D22D1AEULL,
		0xE0FF835707C508C2ULL,
		0x549515E03505A4F4ULL,
		0x09255489866FBB6BULL
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
		0xB4036268F64C13D7ULL,
		0x900AC7666DDE7B40ULL,
		0x9CAD353361928F1DULL,
		0x36DC754DEE9B9B45ULL,
		0xB0A17842C741AD8FULL,
		0x66DAA9970BCE977FULL,
		0xC9A48B1C9311D6A9ULL,
		0x158DCE8E73550022ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6806C4D1EC9827AEULL,
		0x20158ECCDBBCF681ULL,
		0x395A6A66C3251E3BULL,
		0x6DB8EA9BDD37368BULL,
		0x6142F0858E835B1EULL,
		0xCDB5532E179D2EFFULL,
		0x934916392623AD52ULL,
		0x2B1B9D1CE6AA0045ULL
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
		0x64B846FCCFA34174ULL,
		0x192100C03FBCD046ULL,
		0xC60E3CB32CD036D1ULL,
		0x33C6ABCD12A98348ULL,
		0xC9D09C6C589FA21CULL,
		0xA091A891E6D6B8ECULL,
		0xDCA5F21ABBAE35CFULL,
		0x28ED788878C10295ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC9708DF99F4682E8ULL,
		0x324201807F79A08CULL,
		0x8C1C796659A06DA2ULL,
		0x678D579A25530691ULL,
		0x93A138D8B13F4438ULL,
		0x41235123CDAD71D9ULL,
		0xB94BE435775C6B9FULL,
		0x51DAF110F182052BULL
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
		0xC85D9483C0883BE1ULL,
		0x348EBB9611728EE9ULL,
		0x1755F89F0C30AB20ULL,
		0xC848D05BCFB1387AULL,
		0x09BB94C8CE087ED9ULL,
		0xA5944C7F3FD73C79ULL,
		0x0BD124774AEF74DDULL,
		0x296E0A15AEF02B22ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x90BB2907811077C2ULL,
		0x691D772C22E51DD3ULL,
		0x2EABF13E18615640ULL,
		0x9091A0B79F6270F4ULL,
		0x137729919C10FDB3ULL,
		0x4B2898FE7FAE78F2ULL,
		0x17A248EE95DEE9BBULL,
		0x52DC142B5DE05644ULL
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
		0xE35F891F139AAD32ULL,
		0xD476933F3B1338C2ULL,
		0xF2AE754C90459EAFULL,
		0x3FB0CA557439FE0CULL,
		0x55765B7A918CE2FDULL,
		0xC650CC9BC77107D6ULL,
		0x32BEA677D334BB34ULL,
		0x26AA327BC05BF460ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC6BF123E27355A64ULL,
		0xA8ED267E76267185ULL,
		0xE55CEA99208B3D5FULL,
		0x7F6194AAE873FC19ULL,
		0xAAECB6F52319C5FAULL,
		0x8CA199378EE20FACULL,
		0x657D4CEFA6697669ULL,
		0x4D5464F780B7E8C0ULL
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
		0x2A6F998F0C4F2A4FULL,
		0xC9B11F5B716B2311ULL,
		0x60870294AF3DF4B0ULL,
		0x31BF3F39CDE80934ULL,
		0xE1C731701FA879C0ULL,
		0xFF0B4A83AA526BBAULL,
		0xF4D5B97BC23ADCC4ULL,
		0x223CFA48C4A16D0AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x54DF331E189E549EULL,
		0x93623EB6E2D64622ULL,
		0xC10E05295E7BE961ULL,
		0x637E7E739BD01268ULL,
		0xC38E62E03F50F380ULL,
		0xFE16950754A4D775ULL,
		0xE9AB72F78475B989ULL,
		0x4479F4918942DA15ULL
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
		0xCC6FEEBE6F7E775EULL,
		0xDAEAE0CC36724EE8ULL,
		0x2E69940726268DD5ULL,
		0xB5D54A37582B34CBULL,
		0xCA756DF43F8BAE8CULL,
		0x16012868D5EE52AFULL,
		0xADA17347E5B55814ULL,
		0x24C4C8617BCED9C9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x98DFDD7CDEFCEEBCULL,
		0xB5D5C1986CE49DD1ULL,
		0x5CD3280E4C4D1BABULL,
		0x6BAA946EB0566996ULL,
		0x94EADBE87F175D19ULL,
		0x2C0250D1ABDCA55FULL,
		0x5B42E68FCB6AB028ULL,
		0x498990C2F79DB393ULL
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
		0x1185C7B7C9EBF9EEULL,
		0xB95DFC21C8680FD3ULL,
		0x88CF6FCF73916475ULL,
		0xC2002217AB7F0F8EULL,
		0x921C0BF88693FCAFULL,
		0x3344EE7250DE4C84ULL,
		0x515E8156B6D48846ULL,
		0x2FA4D51DD79F5238ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x230B8F6F93D7F3DCULL,
		0x72BBF84390D01FA6ULL,
		0x119EDF9EE722C8EBULL,
		0x8400442F56FE1F1DULL,
		0x243817F10D27F95FULL,
		0x6689DCE4A1BC9909ULL,
		0xA2BD02AD6DA9108CULL,
		0x5F49AA3BAF3EA470ULL
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
		0xEB2A55CAE5339BC1ULL,
		0x100FF94B99B2BAD5ULL,
		0xFDD24CC2B3EA9E26ULL,
		0xA533B5DDF9823AF2ULL,
		0xD725858166B9F3F0ULL,
		0x9C22CA86748C1C1DULL,
		0xEF707C251C9F701BULL,
		0x2D8B1462E74673A2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD654AB95CA673782ULL,
		0x201FF297336575ABULL,
		0xFBA4998567D53C4CULL,
		0x4A676BBBF30475E5ULL,
		0xAE4B0B02CD73E7E1ULL,
		0x3845950CE918383BULL,
		0xDEE0F84A393EE037ULL,
		0x5B1628C5CE8CE745ULL
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
		0x8DEF6C0A50D9E09CULL,
		0xA36A80D67FAE5480ULL,
		0x45A68753CC8FAEAAULL,
		0x65392A1BF1BFADB3ULL,
		0x5E98ACE5B2EB146FULL,
		0x440B46C7BCD4B445ULL,
		0xD27D566F7E39F9D5ULL,
		0x1D9F3525F3779AD9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1BDED814A1B3C138ULL,
		0x46D501ACFF5CA901ULL,
		0x8B4D0EA7991F5D55ULL,
		0xCA725437E37F5B66ULL,
		0xBD3159CB65D628DEULL,
		0x88168D8F79A9688AULL,
		0xA4FAACDEFC73F3AAULL,
		0x3B3E6A4BE6EF35B3ULL
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
		0xA176B5EACF16810DULL,
		0x7002C3DD1CDF13DEULL,
		0x16228BD40EF97DA0ULL,
		0xD3D51651E1DE9C48ULL,
		0x9C4FFD06FCEA4D46ULL,
		0x9B265B6769DEAD31ULL,
		0x11AA9C4791EA955CULL,
		0x1BA80E81B5CC9551ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x42ED6BD59E2D021AULL,
		0xE00587BA39BE27BDULL,
		0x2C4517A81DF2FB40ULL,
		0xA7AA2CA3C3BD3890ULL,
		0x389FFA0DF9D49A8DULL,
		0x364CB6CED3BD5A63ULL,
		0x2355388F23D52AB9ULL,
		0x37501D036B992AA2ULL
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
		0x16532AE8C3D4D0B1ULL,
		0x1C29EB80C448A18CULL,
		0xA512D21776EAA8E1ULL,
		0x8409F82E9D85BC8AULL,
		0xC37C2830B523C512ULL,
		0xA8F7F0BC4F5FB160ULL,
		0xC38C006E638BAB70ULL,
		0x2BE256DE9215501AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2CA655D187A9A162ULL,
		0x3853D70188914318ULL,
		0x4A25A42EEDD551C2ULL,
		0x0813F05D3B0B7915ULL,
		0x86F850616A478A25ULL,
		0x51EFE1789EBF62C1ULL,
		0x871800DCC71756E1ULL,
		0x57C4ADBD242AA035ULL
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
		0xC24BEE7F048F27B4ULL,
		0x3D6E4BFDF7BA6CA7ULL,
		0xBA83BE553C9D5250ULL,
		0x9D8E954695E7E33CULL,
		0xA07FD9142DE2CB07ULL,
		0x2A6BD7CE2B10E3BDULL,
		0xFAC7AB3EEE8190F9ULL,
		0x16FA745612877CCEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8497DCFE091E4F68ULL,
		0x7ADC97FBEF74D94FULL,
		0x75077CAA793AA4A0ULL,
		0x3B1D2A8D2BCFC679ULL,
		0x40FFB2285BC5960FULL,
		0x54D7AF9C5621C77BULL,
		0xF58F567DDD0321F2ULL,
		0x2DF4E8AC250EF99DULL
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
		0xA19705FE0B0C6DF0ULL,
		0x7A4FDD1685096A57ULL,
		0xE8BECB240685F3E6ULL,
		0x9CE1F1D29FEE0420ULL,
		0xF933131E68C9F5C9ULL,
		0xFE16156FA92DC721ULL,
		0x2002460345C68BC3ULL,
		0x189E60750519C734ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x432E0BFC1618DBE0ULL,
		0xF49FBA2D0A12D4AFULL,
		0xD17D96480D0BE7CCULL,
		0x39C3E3A53FDC0841ULL,
		0xF266263CD193EB93ULL,
		0xFC2C2ADF525B8E43ULL,
		0x40048C068B8D1787ULL,
		0x313CC0EA0A338E68ULL
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
		0xDCC3A9EC3BB50BF7ULL,
		0x8DCE4C4A741EE672ULL,
		0xC4EDD113C920ED52ULL,
		0x4E5135AC122FE1DFULL,
		0x829F3C96C1C44D3AULL,
		0xC027BB8EE13B7C2CULL,
		0xFF2BF97F66C37AEFULL,
		0x29B6485B7B584A03ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB98753D8776A17EEULL,
		0x1B9C9894E83DCCE5ULL,
		0x89DBA2279241DAA5ULL,
		0x9CA26B58245FC3BFULL,
		0x053E792D83889A74ULL,
		0x804F771DC276F859ULL,
		0xFE57F2FECD86F5DFULL,
		0x536C90B6F6B09407ULL
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
		0xCC127C78DEC0D921ULL,
		0x0E0E978DF21FDC08ULL,
		0xF32DD514FBC1526EULL,
		0x6C4AF30738524AC3ULL,
		0xFD312B4EDEF141D3ULL,
		0x2507262BD14392D0ULL,
		0x75B7FC0C851A91C9ULL,
		0x0C575402148C2AE8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9824F8F1BD81B242ULL,
		0x1C1D2F1BE43FB811ULL,
		0xE65BAA29F782A4DCULL,
		0xD895E60E70A49587ULL,
		0xFA62569DBDE283A6ULL,
		0x4A0E4C57A28725A1ULL,
		0xEB6FF8190A352392ULL,
		0x18AEA804291855D0ULL
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
		0x0FA32FCB3F1B2DE8ULL,
		0x387C3D4D3467FB11ULL,
		0xE434F452F7FD8B7FULL,
		0xD2B8EBB0C37E4456ULL,
		0x5A9B251F8B2C69A0ULL,
		0x552AB0197A933CD2ULL,
		0x391E4F111F56D4D1ULL,
		0x0463330E98C2C891ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1F465F967E365BD0ULL,
		0x70F87A9A68CFF622ULL,
		0xC869E8A5EFFB16FEULL,
		0xA571D76186FC88ADULL,
		0xB5364A3F1658D341ULL,
		0xAA556032F52679A4ULL,
		0x723C9E223EADA9A2ULL,
		0x08C6661D31859122ULL
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
		0x29E4BFE05468BFC7ULL,
		0x3F20CC2C717A1C38ULL,
		0xCB2839DCAD4812F9ULL,
		0x6FAB8C650D145D97ULL,
		0x2B56BB62DBE00B47ULL,
		0x2D94BE6E9A4661FDULL,
		0x815F0EDFB1C3399BULL,
		0x0F55F9BD7F0DB348ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x53C97FC0A8D17F8EULL,
		0x7E419858E2F43870ULL,
		0x965073B95A9025F2ULL,
		0xDF5718CA1A28BB2FULL,
		0x56AD76C5B7C0168EULL,
		0x5B297CDD348CC3FAULL,
		0x02BE1DBF63867336ULL,
		0x1EABF37AFE1B6691ULL
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
		0x1C342A8922A206DAULL,
		0x66B3646182C7218FULL,
		0xBFBCBC78E2981FA2ULL,
		0x31E0FC0C26FB3BEBULL,
		0x41982EA0EC82BAA5ULL,
		0xA37B7238199013FBULL,
		0x606C58AD36DB5C5BULL,
		0x3E286D8E7ABB0902ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3868551245440DB4ULL,
		0xCD66C8C3058E431EULL,
		0x7F7978F1C5303F44ULL,
		0x63C1F8184DF677D7ULL,
		0x83305D41D905754AULL,
		0x46F6E470332027F6ULL,
		0xC0D8B15A6DB6B8B7ULL,
		0x7C50DB1CF5761204ULL
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
		0xD66DE81C9F51F1F6ULL,
		0x0BFD09DF5B611BC5ULL,
		0xD86FBC95AAE7F8C4ULL,
		0x02B331EDB4B578C9ULL,
		0xB25D402D554809DDULL,
		0x725697C0A7EC40AFULL,
		0xC8A18A98CDF684D2ULL,
		0x37687298FCAD1136ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xACDBD0393EA3E3ECULL,
		0x17FA13BEB6C2378BULL,
		0xB0DF792B55CFF188ULL,
		0x056663DB696AF193ULL,
		0x64BA805AAA9013BAULL,
		0xE4AD2F814FD8815FULL,
		0x914315319BED09A4ULL,
		0x6ED0E531F95A226DULL
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
		0xADF5547FDEB270B8ULL,
		0xF27A2C3879059F84ULL,
		0x31D23D42012B64D9ULL,
		0x4938B766EE802916ULL,
		0x695A0A00282470FFULL,
		0x3B10391FAD45648CULL,
		0xD09DCF50F53135FBULL,
		0x3017E333120D39A1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5BEAA8FFBD64E170ULL,
		0xE4F45870F20B3F09ULL,
		0x63A47A840256C9B3ULL,
		0x92716ECDDD00522CULL,
		0xD2B414005048E1FEULL,
		0x7620723F5A8AC918ULL,
		0xA13B9EA1EA626BF6ULL,
		0x602FC666241A7343ULL
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
		0xC08BC16CD4DCAB98ULL,
		0x08104DC555581E3AULL,
		0xA9EEFB29155565BAULL,
		0xCE5F254CBD9981F9ULL,
		0x79320F64680636B5ULL,
		0xB9CD8F451EA12036ULL,
		0x3C3652DFE16E5F7FULL,
		0x1250402A4310C196ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x811782D9A9B95730ULL,
		0x10209B8AAAB03C75ULL,
		0x53DDF6522AAACB74ULL,
		0x9CBE4A997B3303F3ULL,
		0xF2641EC8D00C6D6BULL,
		0x739B1E8A3D42406CULL,
		0x786CA5BFC2DCBEFFULL,
		0x24A080548621832CULL
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
		0xA201C58F30AF1534ULL,
		0x845C77D60196EC7CULL,
		0x29DB0A71D6BC0B25ULL,
		0x5D045F851B32C675ULL,
		0x4C4C76FAB30807A8ULL,
		0x671743FC0906D248ULL,
		0x7E9139C64A43781BULL,
		0x0BE48C7048C6D3DFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x44038B1E615E2A68ULL,
		0x08B8EFAC032DD8F9ULL,
		0x53B614E3AD78164BULL,
		0xBA08BF0A36658CEAULL,
		0x9898EDF566100F50ULL,
		0xCE2E87F8120DA490ULL,
		0xFD22738C9486F036ULL,
		0x17C918E0918DA7BEULL
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
		0x83DCE386E7E7AC31ULL,
		0x6205B4E0B60CB134ULL,
		0x19334BBFF47D93F3ULL,
		0xC103AB444BB9ACBCULL,
		0xB11A1A155B7715BCULL,
		0x418B3DC19946C9E9ULL,
		0x7890BF62AE2CAE8BULL,
		0x32BB3C1D084869B4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x07B9C70DCFCF5862ULL,
		0xC40B69C16C196269ULL,
		0x3266977FE8FB27E6ULL,
		0x8207568897735978ULL,
		0x6234342AB6EE2B79ULL,
		0x83167B83328D93D3ULL,
		0xF1217EC55C595D16ULL,
		0x6576783A1090D368ULL
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
		0x657D8552C6358DDCULL,
		0xF2FE16BB00D54BDFULL,
		0x1D0167E91F2C5BA2ULL,
		0x4C59367D138C3074ULL,
		0xA25E5B12F3F250ACULL,
		0xC647AA7695CC793AULL,
		0xFFC8A3CDD5B2D92CULL,
		0x09C9A3EB9A05989AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCAFB0AA58C6B1BB8ULL,
		0xE5FC2D7601AA97BEULL,
		0x3A02CFD23E58B745ULL,
		0x98B26CFA271860E8ULL,
		0x44BCB625E7E4A158ULL,
		0x8C8F54ED2B98F275ULL,
		0xFF91479BAB65B259ULL,
		0x139347D7340B3135ULL
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
		0x6595F4411700F547ULL,
		0x910F80BF692EE461ULL,
		0xC5FCC4B8FDAEB1D0ULL,
		0x7B31773224549B9CULL,
		0x8DFAA0F36ACA9C90ULL,
		0x7516470524FB3C28ULL,
		0xD935912D268C34F7ULL,
		0x3F877A5D1BF95DA5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCB2BE8822E01EA8EULL,
		0x221F017ED25DC8C2ULL,
		0x8BF98971FB5D63A1ULL,
		0xF662EE6448A93739ULL,
		0x1BF541E6D5953920ULL,
		0xEA2C8E0A49F67851ULL,
		0xB26B225A4D1869EEULL,
		0x7F0EF4BA37F2BB4BULL
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
		0xD2C8C98D69D9010DULL,
		0xABAB3E02FBD08D38ULL,
		0xBBDF72D09C31874DULL,
		0xA379FCF42F9AB096ULL,
		0x5CF4853A1B84E60CULL,
		0x075D45639B031CC8ULL,
		0xF342A4BBC5A22C43ULL,
		0x24108690E2F982F6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA591931AD3B2021AULL,
		0x57567C05F7A11A71ULL,
		0x77BEE5A138630E9BULL,
		0x46F3F9E85F35612DULL,
		0xB9E90A743709CC19ULL,
		0x0EBA8AC736063990ULL,
		0xE68549778B445886ULL,
		0x48210D21C5F305EDULL
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
		0x88AF65C8BC0A2AC6ULL,
		0x053D8134C7937D7BULL,
		0xD880C052830D8136ULL,
		0xFBF3F58829C28DCAULL,
		0x0D1369BF3B6353E7ULL,
		0x339AE14B9252FDAAULL,
		0x5AF4DE468B1CFA45ULL,
		0x1CFFFBFE6D498C50ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x115ECB917814558CULL,
		0x0A7B02698F26FAF7ULL,
		0xB10180A5061B026CULL,
		0xF7E7EB1053851B95ULL,
		0x1A26D37E76C6A7CFULL,
		0x6735C29724A5FB54ULL,
		0xB5E9BC8D1639F48AULL,
		0x39FFF7FCDA9318A0ULL
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
		0x51B0D62ADC9A5815ULL,
		0x3C96EC30A701300DULL,
		0x6589D635A6891B92ULL,
		0xF22186DAF38C64E5ULL,
		0xD09DA164028FF990ULL,
		0xA0B2B71ED14F97DBULL,
		0x1FFD86CCEAF4DEBAULL,
		0x28DB5F7E265570C8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA361AC55B934B02AULL,
		0x792DD8614E02601AULL,
		0xCB13AC6B4D123724ULL,
		0xE4430DB5E718C9CAULL,
		0xA13B42C8051FF321ULL,
		0x41656E3DA29F2FB7ULL,
		0x3FFB0D99D5E9BD75ULL,
		0x51B6BEFC4CAAE190ULL
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
		0x805EEF765BFA5FC6ULL,
		0xE248594FE7D8991CULL,
		0x27729E9EEBF57A21ULL,
		0x448464BD13BB95F2ULL,
		0x0DF177CE44C56EFFULL,
		0x5B35FE1EAD419F0DULL,
		0xA5DABD0997FD15C7ULL,
		0x05075F33E779CFDBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x00BDDEECB7F4BF8CULL,
		0xC490B29FCFB13239ULL,
		0x4EE53D3DD7EAF443ULL,
		0x8908C97A27772BE4ULL,
		0x1BE2EF9C898ADDFEULL,
		0xB66BFC3D5A833E1AULL,
		0x4BB57A132FFA2B8EULL,
		0x0A0EBE67CEF39FB7ULL
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
		0xE686D02C1495C02CULL,
		0xEF4AC73D5F4E1D38ULL,
		0x49C34CE04B305D1BULL,
		0x9C834D7CE5EE4390ULL,
		0xC97649AFC111BC48ULL,
		0xF8244B7F6E6AB8B6ULL,
		0x3A10625865924240ULL,
		0x2613F390CF14F4E8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCD0DA058292B8058ULL,
		0xDE958E7ABE9C3A71ULL,
		0x938699C09660BA37ULL,
		0x39069AF9CBDC8720ULL,
		0x92EC935F82237891ULL,
		0xF04896FEDCD5716DULL,
		0x7420C4B0CB248481ULL,
		0x4C27E7219E29E9D0ULL
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
		0x0B0C10827FAC2E52ULL,
		0x06B9D9F026018F4AULL,
		0x6C59E2D0BB690860ULL,
		0x4FB87252C05477F1ULL,
		0x401D1836298B499FULL,
		0xC62F0A4E0E56FB43ULL,
		0x534FCA31D4DE5BFBULL,
		0x12ABD7203C046097ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x16182104FF585CA4ULL,
		0x0D73B3E04C031E94ULL,
		0xD8B3C5A176D210C0ULL,
		0x9F70E4A580A8EFE2ULL,
		0x803A306C5316933EULL,
		0x8C5E149C1CADF686ULL,
		0xA69F9463A9BCB7F7ULL,
		0x2557AE407808C12EULL
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
		0xD30C46750363400DULL,
		0x1AA9885362208EFDULL,
		0xE41E8E4955851C5DULL,
		0x579617352BB17FEDULL,
		0xE47089CEA323479EULL,
		0xF0770F15190B97F4ULL,
		0x501237547895F7AAULL,
		0x34D26A5E811AFBCDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA6188CEA06C6801AULL,
		0x355310A6C4411DFBULL,
		0xC83D1C92AB0A38BAULL,
		0xAF2C2E6A5762FFDBULL,
		0xC8E1139D46468F3CULL,
		0xE0EE1E2A32172FE9ULL,
		0xA0246EA8F12BEF55ULL,
		0x69A4D4BD0235F79AULL
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
		0xAEE44ABF33C65B4DULL,
		0x3743D2F34AD885E1ULL,
		0xEB2B9254F240C2E2ULL,
		0x7F86CED82B4EF43CULL,
		0x1C9AC54E565C340BULL,
		0xF65C9FF3E0DB2BD9ULL,
		0x792459D8790EF07AULL,
		0x2A0B74F68543E3B9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5DC8957E678CB69AULL,
		0x6E87A5E695B10BC3ULL,
		0xD65724A9E48185C4ULL,
		0xFF0D9DB0569DE879ULL,
		0x39358A9CACB86816ULL,
		0xECB93FE7C1B657B2ULL,
		0xF248B3B0F21DE0F5ULL,
		0x5416E9ED0A87C772ULL
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
		0x19E4EF4614461BC4ULL,
		0xA25CE0A5DBC1893DULL,
		0xA8218F5D2977A956ULL,
		0xB228D1E255ADE571ULL,
		0x266A30793B62C4D5ULL,
		0x141FE0A8C02D97A4ULL,
		0x51AAE17B72F003B6ULL,
		0x34EE1F1BF904549CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x33C9DE8C288C3788ULL,
		0x44B9C14BB783127AULL,
		0x50431EBA52EF52ADULL,
		0x6451A3C4AB5BCAE3ULL,
		0x4CD460F276C589ABULL,
		0x283FC151805B2F48ULL,
		0xA355C2F6E5E0076CULL,
		0x69DC3E37F208A938ULL
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
		0x6813C0B41388F239ULL,
		0xBD0521F2BC9BB676ULL,
		0xB896BEEDC386681DULL,
		0x6E5E49C02304FA6CULL,
		0x9271B10B860570A2ULL,
		0xF429F396C5CDC38AULL,
		0x65DAB9D5571D07BBULL,
		0x37F07A53DABD6C3FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD02781682711E472ULL,
		0x7A0A43E579376CECULL,
		0x712D7DDB870CD03BULL,
		0xDCBC93804609F4D9ULL,
		0x24E362170C0AE144ULL,
		0xE853E72D8B9B8715ULL,
		0xCBB573AAAE3A0F77ULL,
		0x6FE0F4A7B57AD87EULL
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
		0xEA363EFCE24BAEE6ULL,
		0xB9E5783679E014D4ULL,
		0xB3EEFF40413D0F07ULL,
		0x307EDDB9D7770646ULL,
		0x2BC27467722FDC97ULL,
		0x44B3E27850747989ULL,
		0x0DA7F5D38E659C2AULL,
		0x00FCE6006E110684ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD46C7DF9C4975DCCULL,
		0x73CAF06CF3C029A9ULL,
		0x67DDFE80827A1E0FULL,
		0x60FDBB73AEEE0C8DULL,
		0x5784E8CEE45FB92EULL,
		0x8967C4F0A0E8F312ULL,
		0x1B4FEBA71CCB3854ULL,
		0x01F9CC00DC220D08ULL
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
		0xFB4A37BF241E049CULL,
		0xBF7AFF9D872CA2EEULL,
		0x5C400F9D5BBDC2ABULL,
		0x85F598CACB08607CULL,
		0x13446B0B74154E99ULL,
		0xA6C30F2DF5214FE9ULL,
		0x7D4E20C6F0F61D79ULL,
		0x3EC70DF3FB0318CCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF6946F7E483C0938ULL,
		0x7EF5FF3B0E5945DDULL,
		0xB8801F3AB77B8557ULL,
		0x0BEB31959610C0F8ULL,
		0x2688D616E82A9D33ULL,
		0x4D861E5BEA429FD2ULL,
		0xFA9C418DE1EC3AF3ULL,
		0x7D8E1BE7F6063198ULL
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
		0x1703130574882DACULL,
		0x17FD9C4023C66941ULL,
		0xCD7AD56B6AB6D5CEULL,
		0x6FE5EE881979F3ACULL,
		0x4D0AF5CEAA7E762CULL,
		0x71A108CECB44CCD3ULL,
		0xA131B04BB66D3D1EULL,
		0x25E73F6435A85839ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2E06260AE9105B58ULL,
		0x2FFB3880478CD282ULL,
		0x9AF5AAD6D56DAB9CULL,
		0xDFCBDD1032F3E759ULL,
		0x9A15EB9D54FCEC58ULL,
		0xE342119D968999A6ULL,
		0x426360976CDA7A3CULL,
		0x4BCE7EC86B50B073ULL
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
	k1 = (curve25519_key_t){.key64 = {
		0x4FB346335EBDBC0DULL,
		0xEE4BAE9391B923DAULL,
		0xA8AEB8E4682261FAULL,
		0xCFA0662A111CB420ULL,
		0x54B604E1CFCF0E80ULL,
		0x50D819B0091E3D2AULL,
		0x0E49497136A813DFULL,
		0x33E842272D36B284ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9F668C66BD7B781AULL,
		0xDC975D27237247B4ULL,
		0x515D71C8D044C3F5ULL,
		0x9F40CC5422396841ULL,
		0xA96C09C39F9E1D01ULL,
		0xA1B03360123C7A54ULL,
		0x1C9292E26D5027BEULL,
		0x67D0844E5A6D6508ULL
	}};
	printf("Test Case 201\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x26D34F3407398C53ULL,
		0x8C3BDAC086A9DFE9ULL,
		0xD8554D68DE9A4795ULL,
		0x9971A8BB9F34E691ULL,
		0x0EE4930F7EDFF125ULL,
		0xF9B2CBBECEAC97D1ULL,
		0x2CCEA2809E19947BULL,
		0x3552585F14F1BB52ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4DA69E680E7318A6ULL,
		0x1877B5810D53BFD2ULL,
		0xB0AA9AD1BD348F2BULL,
		0x32E351773E69CD23ULL,
		0x1DC9261EFDBFE24BULL,
		0xF365977D9D592FA2ULL,
		0x599D45013C3328F7ULL,
		0x6AA4B0BE29E376A4ULL
	}};
	printf("Test Case 202\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x60AA50BF6E70D89EULL,
		0xCF4971A4B77D6583ULL,
		0x4C0031A7B7B1F5DEULL,
		0x1D29852BDEE47C15ULL,
		0x6415AA53624EBDEDULL,
		0x3EA0C34C3BB60883ULL,
		0xEB1164E86CBA2AC5ULL,
		0x0AA954906F0B2288ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC154A17EDCE1B13CULL,
		0x9E92E3496EFACB06ULL,
		0x9800634F6F63EBBDULL,
		0x3A530A57BDC8F82AULL,
		0xC82B54A6C49D7BDAULL,
		0x7D418698776C1106ULL,
		0xD622C9D0D974558AULL,
		0x1552A920DE164511ULL
	}};
	printf("Test Case 203\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x6077C70537C73340ULL,
		0xEA3EDDE3F03D9913ULL,
		0xF7A6C46F7D687339ULL,
		0xBDC34F2D5F92B595ULL,
		0x46DEB1770912FA89ULL,
		0x9CB6A1E41EBFCBF0ULL,
		0x814AA6156782CA6BULL,
		0x15ABB4116BAD3CCDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC0EF8E0A6F8E6680ULL,
		0xD47DBBC7E07B3226ULL,
		0xEF4D88DEFAD0E673ULL,
		0x7B869E5ABF256B2BULL,
		0x8DBD62EE1225F513ULL,
		0x396D43C83D7F97E0ULL,
		0x02954C2ACF0594D7ULL,
		0x2B576822D75A799BULL
	}};
	printf("Test Case 204\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x751DFE990AC22B67ULL,
		0x261865282829D1F3ULL,
		0xE3B42906EF655CC2ULL,
		0x59E9C520DC8C7862ULL,
		0x95DCFAA7759D51BFULL,
		0xAAC69B8A3350B346ULL,
		0xBD0EB1EC41380590ULL,
		0x281576601FC51CC9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEA3BFD32158456CEULL,
		0x4C30CA505053A3E6ULL,
		0xC768520DDECAB984ULL,
		0xB3D38A41B918F0C5ULL,
		0x2BB9F54EEB3AA37EULL,
		0x558D371466A1668DULL,
		0x7A1D63D882700B21ULL,
		0x502AECC03F8A3993ULL
	}};
	printf("Test Case 205\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x5181D849F9D7F3C9ULL,
		0xFA6469EF5D9A95F5ULL,
		0xE9F13C303AFDB261ULL,
		0xE0219503905014D0ULL,
		0xAD89EDD7772572D0ULL,
		0x8C611CF8E9114FB1ULL,
		0x23F7D80951E26964ULL,
		0x2327D38064253979ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA303B093F3AFE792ULL,
		0xF4C8D3DEBB352BEAULL,
		0xD3E2786075FB64C3ULL,
		0xC0432A0720A029A1ULL,
		0x5B13DBAEEE4AE5A1ULL,
		0x18C239F1D2229F63ULL,
		0x47EFB012A3C4D2C9ULL,
		0x464FA700C84A72F2ULL
	}};
	printf("Test Case 206\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x82274E57EAB4F1E3ULL,
		0x661A7F1103504B75ULL,
		0x98BC21C5FA37A642ULL,
		0x4145BFDC4794FFD3ULL,
		0x1B0E07CDDEFECCC4ULL,
		0xD1CA6E3A728293E8ULL,
		0x6FDA1974C686BC47ULL,
		0x1FCEC920632EF1AEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x044E9CAFD569E3C6ULL,
		0xCC34FE2206A096EBULL,
		0x3178438BF46F4C84ULL,
		0x828B7FB88F29FFA7ULL,
		0x361C0F9BBDFD9988ULL,
		0xA394DC74E50527D0ULL,
		0xDFB432E98D0D788FULL,
		0x3F9D9240C65DE35CULL
	}};
	printf("Test Case 207\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0xBC120E364E5F8C57ULL,
		0x490A3FD625E366A1ULL,
		0x8603511DD65B4997ULL,
		0xE42EBE722FC48983ULL,
		0xD72860520A4FDFA2ULL,
		0x679AADC06BF3B4F4ULL,
		0x52396317B967B44BULL,
		0x04E14F5A7057137DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x78241C6C9CBF18AEULL,
		0x92147FAC4BC6CD43ULL,
		0x0C06A23BACB6932EULL,
		0xC85D7CE45F891307ULL,
		0xAE50C0A4149FBF45ULL,
		0xCF355B80D7E769E9ULL,
		0xA472C62F72CF6896ULL,
		0x09C29EB4E0AE26FAULL
	}};
	printf("Test Case 208\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x61DA54A8208A89BBULL,
		0xADA610BB106BE25FULL,
		0xDA7A5249EEE00EE5ULL,
		0x6BFCD16BCEC3F3D2ULL,
		0xF74D8E234291701EULL,
		0xE086EF23995CE029ULL,
		0x6521C617EC8953BFULL,
		0x338A83D9F10880E7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC3B4A95041151376ULL,
		0x5B4C217620D7C4BEULL,
		0xB4F4A493DDC01DCBULL,
		0xD7F9A2D79D87E7A5ULL,
		0xEE9B1C468522E03CULL,
		0xC10DDE4732B9C053ULL,
		0xCA438C2FD912A77FULL,
		0x671507B3E21101CEULL
	}};
	printf("Test Case 209\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0xC756AE49AFC262D0ULL,
		0xB91C6B5F673BB519ULL,
		0x271CDEAD7DD3B1D6ULL,
		0xF3AD16CAC842C381ULL,
		0x31E9EDD8221F80B3ULL,
		0xAB85F248789C19EDULL,
		0x1AA0A64CDC708387ULL,
		0x2E5D235E8C53E2BEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8EAD5C935F84C5A0ULL,
		0x7238D6BECE776A33ULL,
		0x4E39BD5AFBA763ADULL,
		0xE75A2D9590858702ULL,
		0x63D3DBB0443F0167ULL,
		0x570BE490F13833DAULL,
		0x35414C99B8E1070FULL,
		0x5CBA46BD18A7C57CULL
	}};
	printf("Test Case 210\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 210 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -210;
	} else {
		printf("Test Case 210 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x475C3C77E7D6CFFFULL,
		0x9EAB6BFEB9B18908ULL,
		0x5681F32FD732681BULL,
		0x42F1B937DFDE8116ULL,
		0x1C9D2AE00E898E69ULL,
		0x4E8E86DA4E261689ULL,
		0x8549873A981FD6C6ULL,
		0x32566510F818A98DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8EB878EFCFAD9FFEULL,
		0x3D56D7FD73631210ULL,
		0xAD03E65FAE64D037ULL,
		0x85E3726FBFBD022CULL,
		0x393A55C01D131CD2ULL,
		0x9D1D0DB49C4C2D12ULL,
		0x0A930E75303FAD8CULL,
		0x64ACCA21F031531BULL
	}};
	printf("Test Case 211\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 211 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -211;
	} else {
		printf("Test Case 211 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7BCC29AC5E747D80ULL,
		0x2AC2B2A91F970F9CULL,
		0xF4F777ED0D590E4EULL,
		0x33CD265FB74D0B43ULL,
		0x81821A29993BE042ULL,
		0xC7A199F4B29F1001ULL,
		0xD103E65B16256218ULL,
		0x0471CB5226CCB3E2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF7985358BCE8FB00ULL,
		0x558565523F2E1F38ULL,
		0xE9EEEFDA1AB21C9CULL,
		0x679A4CBF6E9A1687ULL,
		0x030434533277C084ULL,
		0x8F4333E9653E2003ULL,
		0xA207CCB62C4AC431ULL,
		0x08E396A44D9967C5ULL
	}};
	printf("Test Case 212\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 212 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -212;
	} else {
		printf("Test Case 212 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD2DBA41B76191D0AULL,
		0x021FDE67C8A5A107ULL,
		0x447E4058388ED274ULL,
		0x00A98991449B647EULL,
		0x2AAE50E9E497B9EDULL,
		0xE16BCA2ABB772CC0ULL,
		0x2DA1FC3EF6790C0AULL,
		0x23CD967441F048B9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA5B74836EC323A14ULL,
		0x043FBCCF914B420FULL,
		0x88FC80B0711DA4E8ULL,
		0x015313228936C8FCULL,
		0x555CA1D3C92F73DAULL,
		0xC2D7945576EE5980ULL,
		0x5B43F87DECF21815ULL,
		0x479B2CE883E09172ULL
	}};
	printf("Test Case 213\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 213 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -213;
	} else {
		printf("Test Case 213 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0C88E5E4E8FC02EEULL,
		0xDE3C1AAB8F355F0FULL,
		0xF24ACD46212BD383ULL,
		0xEC845F7FC0C57A7BULL,
		0x020A8E0C6CBAEA7BULL,
		0xB0DCC4140714D941ULL,
		0x13B4055608C1E37DULL,
		0x237EFD7D06387C85ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1911CBC9D1F805DCULL,
		0xBC7835571E6ABE1EULL,
		0xE4959A8C4257A707ULL,
		0xD908BEFF818AF4F7ULL,
		0x04151C18D975D4F7ULL,
		0x61B988280E29B282ULL,
		0x27680AAC1183C6FBULL,
		0x46FDFAFA0C70F90AULL
	}};
	printf("Test Case 214\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 214 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -214;
	} else {
		printf("Test Case 214 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7B084B6BBD589876ULL,
		0x30C459D7046A57FAULL,
		0xED1B9B589B625E5AULL,
		0x151DE5992EF0D4E8ULL,
		0x39590480697F2AC8ULL,
		0x5B6BEFC665EF1DF3ULL,
		0x5010C10A2DB6F4BBULL,
		0x00B59B72751575E6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF61096D77AB130ECULL,
		0x6188B3AE08D4AFF4ULL,
		0xDA3736B136C4BCB4ULL,
		0x2A3BCB325DE1A9D1ULL,
		0x72B20900D2FE5590ULL,
		0xB6D7DF8CCBDE3BE6ULL,
		0xA02182145B6DE976ULL,
		0x016B36E4EA2AEBCCULL
	}};
	printf("Test Case 215\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 215 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -215;
	} else {
		printf("Test Case 215 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDEE07FF66A40FF84ULL,
		0x1E21CC93C84742E0ULL,
		0xFEE22319808D12C5ULL,
		0x34ABFFEE4D266E84ULL,
		0xBF0D1DDF2085F9DDULL,
		0x659BAE7356A78132ULL,
		0xC91704533908C34DULL,
		0x03174A1FEA4B74EFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBDC0FFECD481FF08ULL,
		0x3C439927908E85C1ULL,
		0xFDC44633011A258AULL,
		0x6957FFDC9A4CDD09ULL,
		0x7E1A3BBE410BF3BAULL,
		0xCB375CE6AD4F0265ULL,
		0x922E08A67211869AULL,
		0x062E943FD496E9DFULL
	}};
	printf("Test Case 216\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 216 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -216;
	} else {
		printf("Test Case 216 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFAEDAE98A4C53E53ULL,
		0x589E2E6544ACDD67ULL,
		0xF4E59A2869D7418FULL,
		0x4F65969EEAF5878DULL,
		0x6368DFCD5CE1E003ULL,
		0x30C35485E9D74B34ULL,
		0x684D636D4547D72CULL,
		0x20A2545991874D61ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF5DB5D31498A7CA6ULL,
		0xB13C5CCA8959BACFULL,
		0xE9CB3450D3AE831EULL,
		0x9ECB2D3DD5EB0F1BULL,
		0xC6D1BF9AB9C3C006ULL,
		0x6186A90BD3AE9668ULL,
		0xD09AC6DA8A8FAE58ULL,
		0x4144A8B3230E9AC2ULL
	}};
	printf("Test Case 217\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 217 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -217;
	} else {
		printf("Test Case 217 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF5E0C8C8AD70BEB5ULL,
		0x4B017864A5A3BC39ULL,
		0x7ED1A1419A336CD6ULL,
		0xBEF710C1A8224763ULL,
		0xC6BF3C21F3570501ULL,
		0xC68CCE12FBEEB1AAULL,
		0xC0ECFFA8F754FF18ULL,
		0x10628346788F247AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEBC191915AE17D6AULL,
		0x9602F0C94B477873ULL,
		0xFDA342833466D9ACULL,
		0x7DEE218350448EC6ULL,
		0x8D7E7843E6AE0A03ULL,
		0x8D199C25F7DD6355ULL,
		0x81D9FF51EEA9FE31ULL,
		0x20C5068CF11E48F5ULL
	}};
	printf("Test Case 218\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 218 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -218;
	} else {
		printf("Test Case 218 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x24943755B363DD5DULL,
		0xD1874F34FDD3C076ULL,
		0xE9C94DE11D8EE8B6ULL,
		0xEDAD5DF24642CD4DULL,
		0xA529290492031B88ULL,
		0x6BDE72D0692088A8ULL,
		0xC323B8C5728FCEA8ULL,
		0x3D1DC786D5E0648AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x49286EAB66C7BABAULL,
		0xA30E9E69FBA780ECULL,
		0xD3929BC23B1DD16DULL,
		0xDB5ABBE48C859A9BULL,
		0x4A52520924063711ULL,
		0xD7BCE5A0D2411151ULL,
		0x8647718AE51F9D50ULL,
		0x7A3B8F0DABC0C915ULL
	}};
	printf("Test Case 219\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 219 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -219;
	} else {
		printf("Test Case 219 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7EF5320262632934ULL,
		0x6201014211A9386CULL,
		0x9476A13580F2DD9BULL,
		0x103AB757233A6211ULL,
		0xA7B1788251265D91ULL,
		0x4380B8A7DD2A7FE2ULL,
		0x9E58E02D92CF125EULL,
		0x02098667A2147CA8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFDEA6404C4C65268ULL,
		0xC4020284235270D8ULL,
		0x28ED426B01E5BB36ULL,
		0x20756EAE4674C423ULL,
		0x4F62F104A24CBB22ULL,
		0x8701714FBA54FFC5ULL,
		0x3CB1C05B259E24BCULL,
		0x04130CCF4428F951ULL
	}};
	printf("Test Case 220\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 220 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -220;
	} else {
		printf("Test Case 220 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA5AE98B9DF571820ULL,
		0xE2DD457073535023ULL,
		0x9CF29D0F1A94E829ULL,
		0x2C429324AFAE57E8ULL,
		0x6A0106184C4BDC1AULL,
		0xCF96944C29A9EACAULL,
		0xEF51B7C4C72FB0BEULL,
		0x2AEAF866F26BACFEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4B5D3173BEAE3040ULL,
		0xC5BA8AE0E6A6A047ULL,
		0x39E53A1E3529D053ULL,
		0x588526495F5CAFD1ULL,
		0xD4020C309897B834ULL,
		0x9F2D28985353D594ULL,
		0xDEA36F898E5F617DULL,
		0x55D5F0CDE4D759FDULL
	}};
	printf("Test Case 221\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 221 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -221;
	} else {
		printf("Test Case 221 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF18989B17A6EB53EULL,
		0x2C1BE8386C968283ULL,
		0xDDF75F62BD86E733ULL,
		0x7EE758E21E5E60E7ULL,
		0x2176A9291F1A37CFULL,
		0x6DFE6995BD3AE065ULL,
		0xB20FBEA2A1D52784ULL,
		0x20B9D4F9B2C9D860ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE3131362F4DD6A7CULL,
		0x5837D070D92D0507ULL,
		0xBBEEBEC57B0DCE66ULL,
		0xFDCEB1C43CBCC1CFULL,
		0x42ED52523E346F9EULL,
		0xDBFCD32B7A75C0CAULL,
		0x641F7D4543AA4F08ULL,
		0x4173A9F36593B0C1ULL
	}};
	printf("Test Case 222\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 222 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -222;
	} else {
		printf("Test Case 222 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2F3A56EAFB52DE0AULL,
		0x12AEBAF7760CCA63ULL,
		0x18668C4027E6E4E4ULL,
		0xA9B1874D0B072C71ULL,
		0xA67774F2F2FBE794ULL,
		0x3B42DBEF0FF14934ULL,
		0x83FEFFF6CA450AD0ULL,
		0x0D7AB7C07A94FD74ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5E74ADD5F6A5BC14ULL,
		0x255D75EEEC1994C6ULL,
		0x30CD18804FCDC9C8ULL,
		0x53630E9A160E58E2ULL,
		0x4CEEE9E5E5F7CF29ULL,
		0x7685B7DE1FE29269ULL,
		0x07FDFFED948A15A0ULL,
		0x1AF56F80F529FAE9ULL
	}};
	printf("Test Case 223\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 223 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -223;
	} else {
		printf("Test Case 223 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC4D61B42CFE3F15FULL,
		0x6A786881BD1AFDDAULL,
		0xBF1E9DF05CA6A7C5ULL,
		0x2FF85CAC40A10CFBULL,
		0x07F83EFAC3DA1D3CULL,
		0x56299F3E541D347EULL,
		0x7B4C9003EDC8DBF3ULL,
		0x3ED718096E7D6659ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x89AC36859FC7E2BEULL,
		0xD4F0D1037A35FBB5ULL,
		0x7E3D3BE0B94D4F8AULL,
		0x5FF0B958814219F7ULL,
		0x0FF07DF587B43A78ULL,
		0xAC533E7CA83A68FCULL,
		0xF6992007DB91B7E6ULL,
		0x7DAE3012DCFACCB2ULL
	}};
	printf("Test Case 224\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 224 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -224;
	} else {
		printf("Test Case 224 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x49C4DBE783B2BA07ULL,
		0xF34ADCAC1A80B185ULL,
		0x2B1AB22942EC850FULL,
		0x2D5574AA49D7B454ULL,
		0xA2AD556744885A66ULL,
		0x8B7D1C7D89191FFEULL,
		0x4A5AEC5B09999937ULL,
		0x2671ABCCE87300DFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9389B7CF0765740EULL,
		0xE695B9583501630AULL,
		0x5635645285D90A1FULL,
		0x5AAAE95493AF68A8ULL,
		0x455AAACE8910B4CCULL,
		0x16FA38FB12323FFDULL,
		0x94B5D8B61333326FULL,
		0x4CE35799D0E601BEULL
	}};
	printf("Test Case 225\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 225 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -225;
	} else {
		printf("Test Case 225 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6DE22E2F3327C07AULL,
		0xCDFAC7B7A9D4B655ULL,
		0xB12AB87E92F4ED88ULL,
		0x1643965033357DABULL,
		0xE16A14882B1495DAULL,
		0x96E57D562D43C995ULL,
		0xAFBA1B6C0E38B277ULL,
		0x38021EE9F5BB624AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDBC45C5E664F80F4ULL,
		0x9BF58F6F53A96CAAULL,
		0x625570FD25E9DB11ULL,
		0x2C872CA0666AFB57ULL,
		0xC2D4291056292BB4ULL,
		0x2DCAFAAC5A87932BULL,
		0x5F7436D81C7164EFULL,
		0x70043DD3EB76C495ULL
	}};
	printf("Test Case 226\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 226 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -226;
	} else {
		printf("Test Case 226 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x383D9CB8EE972FA8ULL,
		0xC6AE040E25354748ULL,
		0x445156CB7368DEEDULL,
		0x775DA8B6EA44D3ADULL,
		0xF90F0356F97507D9ULL,
		0xA294CE38942223E9ULL,
		0x1A21C9B1B16AD7A4ULL,
		0x3B16AB0A46431DC1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x707B3971DD2E5F50ULL,
		0x8D5C081C4A6A8E90ULL,
		0x88A2AD96E6D1BDDBULL,
		0xEEBB516DD489A75AULL,
		0xF21E06ADF2EA0FB2ULL,
		0x45299C71284447D3ULL,
		0x3443936362D5AF49ULL,
		0x762D56148C863B82ULL
	}};
	printf("Test Case 227\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 227 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -227;
	} else {
		printf("Test Case 227 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDA511897000E0C64ULL,
		0x9E7792F679434DF9ULL,
		0xBA087D1DB6B4ACD2ULL,
		0xA4CAE4ED4A7A8700ULL,
		0x6B137191CEAABE8AULL,
		0xAD7E96CB67459750ULL,
		0x3B4F881FB226DABAULL,
		0x1650AB11DE4DB2FAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB4A2312E001C18C8ULL,
		0x3CEF25ECF2869BF3ULL,
		0x7410FA3B6D6959A5ULL,
		0x4995C9DA94F50E01ULL,
		0xD626E3239D557D15ULL,
		0x5AFD2D96CE8B2EA0ULL,
		0x769F103F644DB575ULL,
		0x2CA15623BC9B65F4ULL
	}};
	printf("Test Case 228\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 228 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -228;
	} else {
		printf("Test Case 228 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD50440A5E31D49DFULL,
		0x22102ABC528203ABULL,
		0xD7609BF274A3DAEAULL,
		0xA2C3C06B762D548DULL,
		0xE8C754A1D2B2FB9AULL,
		0x9164470D9C351183ULL,
		0xE95D2278C1D396FBULL,
		0x18B563FF29D531B9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAA08814BC63A93BEULL,
		0x44205578A5040757ULL,
		0xAEC137E4E947B5D4ULL,
		0x458780D6EC5AA91BULL,
		0xD18EA943A565F735ULL,
		0x22C88E1B386A2307ULL,
		0xD2BA44F183A72DF7ULL,
		0x316AC7FE53AA6373ULL
	}};
	printf("Test Case 229\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 229 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -229;
	} else {
		printf("Test Case 229 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x87A921BC86023E37ULL,
		0x059F711DFC58E28CULL,
		0x6637E4F28D26A56FULL,
		0x6F13320CEED17A28ULL,
		0x0ABB900D627E92E7ULL,
		0x0DE8B3D325F8CE5AULL,
		0xA93A6497741D58E4ULL,
		0x1F7D617F4EBF685EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F5243790C047C6EULL,
		0x0B3EE23BF8B1C519ULL,
		0xCC6FC9E51A4D4ADEULL,
		0xDE266419DDA2F450ULL,
		0x1577201AC4FD25CEULL,
		0x1BD167A64BF19CB4ULL,
		0x5274C92EE83AB1C8ULL,
		0x3EFAC2FE9D7ED0BDULL
	}};
	printf("Test Case 230\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 230 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -230;
	} else {
		printf("Test Case 230 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x880E71CBED58ED8FULL,
		0xD0B5842D692B5697ULL,
		0xE1A1D1913535C36FULL,
		0xB3E3654DFEDF7292ULL,
		0x9AF6565298271528ULL,
		0xA52C6FAB0022E274ULL,
		0xC2E39E66F847FA68ULL,
		0x21AF6CD306954CB0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x101CE397DAB1DB1EULL,
		0xA16B085AD256AD2FULL,
		0xC343A3226A6B86DFULL,
		0x67C6CA9BFDBEE525ULL,
		0x35ECACA5304E2A51ULL,
		0x4A58DF560045C4E9ULL,
		0x85C73CCDF08FF4D1ULL,
		0x435ED9A60D2A9961ULL
	}};
	printf("Test Case 231\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 231 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -231;
	} else {
		printf("Test Case 231 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x254046FC5E4482C6ULL,
		0xFFB815DA2535546EULL,
		0xBEA0E00BCC109E9EULL,
		0xE54B8FB6F96FDC68ULL,
		0x8559D09F58C9009FULL,
		0xF00CD6F897D40362ULL,
		0xCF83EEFACF4D3CE5ULL,
		0x25B3E1C732117CE0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4A808DF8BC89058CULL,
		0xFF702BB44A6AA8DCULL,
		0x7D41C01798213D3DULL,
		0xCA971F6DF2DFB8D1ULL,
		0x0AB3A13EB192013FULL,
		0xE019ADF12FA806C5ULL,
		0x9F07DDF59E9A79CBULL,
		0x4B67C38E6422F9C1ULL
	}};
	printf("Test Case 232\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 232 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -232;
	} else {
		printf("Test Case 232 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x393D97251A9008A5ULL,
		0x8639CCDCEC4F281DULL,
		0x6C94EBAEF27A08C9ULL,
		0xC55FE9E01B679DADULL,
		0x848D8DECDFA52C93ULL,
		0xB9857127D1895E36ULL,
		0x37E867562FAC4E0DULL,
		0x067064A9DEF72C07ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x727B2E4A3520114AULL,
		0x0C7399B9D89E503AULL,
		0xD929D75DE4F41193ULL,
		0x8ABFD3C036CF3B5AULL,
		0x091B1BD9BF4A5927ULL,
		0x730AE24FA312BC6DULL,
		0x6FD0CEAC5F589C1BULL,
		0x0CE0C953BDEE580EULL
	}};
	printf("Test Case 233\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 233 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -233;
	} else {
		printf("Test Case 233 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4AF97D27039F2CA0ULL,
		0x5C3D451AF4A34C36ULL,
		0x57DD4F4697B7F99DULL,
		0x87E9A99395F1ED2BULL,
		0x86294E2B4383EDFCULL,
		0x320F1E0780AA0E08ULL,
		0xFA845A747C1F29E1ULL,
		0x0510CA758F17F663ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x95F2FA4E073E5940ULL,
		0xB87A8A35E946986CULL,
		0xAFBA9E8D2F6FF33AULL,
		0x0FD353272BE3DA56ULL,
		0x0C529C568707DBF9ULL,
		0x641E3C0F01541C11ULL,
		0xF508B4E8F83E53C2ULL,
		0x0A2194EB1E2FECC7ULL
	}};
	printf("Test Case 234\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 234 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -234;
	} else {
		printf("Test Case 234 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x69F7C0F6855A2AFBULL,
		0x771C8377DF7E44D0ULL,
		0x47F1A186291CC936ULL,
		0x3D1970C5376C83E1ULL,
		0xB7F9CBEAAC25D50BULL,
		0x077181D1CE9C1084ULL,
		0x68830FE7C2E7E7A0ULL,
		0x336DF76D9BAF708AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD3EF81ED0AB455F6ULL,
		0xEE3906EFBEFC89A0ULL,
		0x8FE3430C5239926CULL,
		0x7A32E18A6ED907C2ULL,
		0x6FF397D5584BAA16ULL,
		0x0EE303A39D382109ULL,
		0xD1061FCF85CFCF40ULL,
		0x66DBEEDB375EE114ULL
	}};
	printf("Test Case 235\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 235 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -235;
	} else {
		printf("Test Case 235 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB917F3C018D64B7DULL,
		0xD40A8FD9DBD0A355ULL,
		0x7505F4F189C53A8FULL,
		0xF15BE11CD0F1CBE9ULL,
		0xD23B638BCE1501D8ULL,
		0x7891BA1304F48428ULL,
		0x564A53F161C434DDULL,
		0x1CB0840C2A8E6F5EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x722FE78031AC96FAULL,
		0xA8151FB3B7A146ABULL,
		0xEA0BE9E3138A751FULL,
		0xE2B7C239A1E397D2ULL,
		0xA476C7179C2A03B1ULL,
		0xF123742609E90851ULL,
		0xAC94A7E2C38869BAULL,
		0x39610818551CDEBCULL
	}};
	printf("Test Case 236\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 236 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -236;
	} else {
		printf("Test Case 236 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF2953168B01F5517ULL,
		0x8C59C9259454CCAFULL,
		0xCFC4EC55B8868351ULL,
		0xCA4C3A807958A159ULL,
		0xE38D90D05070A4CEULL,
		0x9F8F6FD0BF5D2E5CULL,
		0xA164795854F74AC6ULL,
		0x04CCEAF2B034280CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE52A62D1603EAA2EULL,
		0x18B3924B28A9995FULL,
		0x9F89D8AB710D06A3ULL,
		0x94987500F2B142B3ULL,
		0xC71B21A0A0E1499DULL,
		0x3F1EDFA17EBA5CB9ULL,
		0x42C8F2B0A9EE958DULL,
		0x0999D5E560685019ULL
	}};
	printf("Test Case 237\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 237 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -237;
	} else {
		printf("Test Case 237 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA2A436E3B85759A3ULL,
		0x7B0C274626BF8337ULL,
		0x27640AD328D52D44ULL,
		0x7C16B66E86CDC2B7ULL,
		0x3609A0413F4D2BC0ULL,
		0x74BFA40E8DAB377FULL,
		0x2015BB7AD7F85070ULL,
		0x2D1A8845C8B5DC5DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x45486DC770AEB346ULL,
		0xF6184E8C4D7F066FULL,
		0x4EC815A651AA5A88ULL,
		0xF82D6CDD0D9B856EULL,
		0x6C1340827E9A5780ULL,
		0xE97F481D1B566EFEULL,
		0x402B76F5AFF0A0E0ULL,
		0x5A35108B916BB8BAULL
	}};
	printf("Test Case 238\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 238 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -238;
	} else {
		printf("Test Case 238 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x063A20906A6C0E69ULL,
		0x4C03969A91EDFB97ULL,
		0xA67818C2E5DCAEBBULL,
		0xC32587E4A3944E63ULL,
		0x6207C121788121C0ULL,
		0xA0083F0DFF6336BDULL,
		0xD316825D354E9D5CULL,
		0x27A54069DC9458FDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0C744120D4D81CD2ULL,
		0x98072D3523DBF72EULL,
		0x4CF03185CBB95D76ULL,
		0x864B0FC947289CC7ULL,
		0xC40F8242F1024381ULL,
		0x40107E1BFEC66D7AULL,
		0xA62D04BA6A9D3AB9ULL,
		0x4F4A80D3B928B1FBULL
	}};
	printf("Test Case 239\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 239 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -239;
	} else {
		printf("Test Case 239 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6C051A51047600FFULL,
		0xE4D0B4FE1E532416ULL,
		0xD8B41EB7617475ADULL,
		0xBF5AD1D33EDD7456ULL,
		0x902133985F572F4EULL,
		0xF95F9332E7C3183AULL,
		0x76C506993B3C9FACULL,
		0x10CD3DFC2CE546A4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD80A34A208EC01FEULL,
		0xC9A169FC3CA6482CULL,
		0xB1683D6EC2E8EB5BULL,
		0x7EB5A3A67DBAE8ADULL,
		0x20426730BEAE5E9DULL,
		0xF2BF2665CF863075ULL,
		0xED8A0D3276793F59ULL,
		0x219A7BF859CA8D48ULL
	}};
	printf("Test Case 240\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 240 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -240;
	} else {
		printf("Test Case 240 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE785A9242C73B8DEULL,
		0x2381DD7DC2D6FE77ULL,
		0x14927E8F0D8F8463ULL,
		0x2A5ECE20C555DA43ULL,
		0x8B7E855E04762319ULL,
		0xC77C8CE5D5DF5B36ULL,
		0x8A31E2DA45AE3467ULL,
		0x372F4E2675BE8DADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCF0B524858E771BCULL,
		0x4703BAFB85ADFCEFULL,
		0x2924FD1E1B1F08C6ULL,
		0x54BD9C418AABB486ULL,
		0x16FD0ABC08EC4632ULL,
		0x8EF919CBABBEB66DULL,
		0x1463C5B48B5C68CFULL,
		0x6E5E9C4CEB7D1B5BULL
	}};
	printf("Test Case 241\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 241 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -241;
	} else {
		printf("Test Case 241 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x14EAB845915C1F2DULL,
		0x7237253A7F34E100ULL,
		0x9B8DECD526303F1CULL,
		0x0BE159F1624481C3ULL,
		0x1D6888736D67C4EDULL,
		0x0F1FCED230919E89ULL,
		0x8E9DB44A341F150DULL,
		0x08D8DB7C354E2432ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x29D5708B22B83E5AULL,
		0xE46E4A74FE69C200ULL,
		0x371BD9AA4C607E38ULL,
		0x17C2B3E2C4890387ULL,
		0x3AD110E6DACF89DAULL,
		0x1E3F9DA461233D12ULL,
		0x1D3B6894683E2A1AULL,
		0x11B1B6F86A9C4865ULL
	}};
	printf("Test Case 242\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 242 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -242;
	} else {
		printf("Test Case 242 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCE7E21786ECA36F2ULL,
		0xA27C823F1CEC9799ULL,
		0x83688FE0001468A2ULL,
		0xCC264CA43F7CA889ULL,
		0x609582CCB797E3AFULL,
		0x82A3C69BF41886F9ULL,
		0x20A2A435329310D7ULL,
		0x19D77F9C96A27D4AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9CFC42F0DD946DE4ULL,
		0x44F9047E39D92F33ULL,
		0x06D11FC00028D145ULL,
		0x984C99487EF95113ULL,
		0xC12B05996F2FC75FULL,
		0x05478D37E8310DF2ULL,
		0x4145486A652621AFULL,
		0x33AEFF392D44FA94ULL
	}};
	printf("Test Case 243\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 243 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -243;
	} else {
		printf("Test Case 243 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAF4074E9CD097A4BULL,
		0x9FF4EF07F9BAB6F3ULL,
		0x681C907D0A1352E7ULL,
		0x3AC61AFBB880363EULL,
		0x64B8B6B22C4038CEULL,
		0x8700019E448C0CB6ULL,
		0x9D1C21FF79601F25ULL,
		0x00F986E3A48F04C1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5E80E9D39A12F496ULL,
		0x3FE9DE0FF3756DE7ULL,
		0xD03920FA1426A5CFULL,
		0x758C35F771006C7CULL,
		0xC9716D645880719CULL,
		0x0E00033C8918196CULL,
		0x3A3843FEF2C03E4BULL,
		0x01F30DC7491E0983ULL
	}};
	printf("Test Case 244\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 244 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -244;
	} else {
		printf("Test Case 244 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF4BE035713D08479ULL,
		0x89E6CA0651052DB1ULL,
		0xA7324C731F68137DULL,
		0x71A1018608DF0472ULL,
		0xE8629087F1703BBFULL,
		0x58495EBDAA765191ULL,
		0x733472891080A1B5ULL,
		0x03BC49AAE5675562ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE97C06AE27A108F2ULL,
		0x13CD940CA20A5B63ULL,
		0x4E6498E63ED026FBULL,
		0xE342030C11BE08E5ULL,
		0xD0C5210FE2E0777EULL,
		0xB092BD7B54ECA323ULL,
		0xE668E5122101436AULL,
		0x07789355CACEAAC4ULL
	}};
	printf("Test Case 245\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 245 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -245;
	} else {
		printf("Test Case 245 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF4071D84C01F1C36ULL,
		0x02039D39B9458A3BULL,
		0x601FEAF66BF9FB6EULL,
		0x3C1E76A9F2198034ULL,
		0xD213145A51E69ADDULL,
		0x4151398A453C9A8FULL,
		0x52E83FDFF044EC19ULL,
		0x2F99D2816F4A1D4EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE80E3B09803E386CULL,
		0x04073A73728B1477ULL,
		0xC03FD5ECD7F3F6DCULL,
		0x783CED53E4330068ULL,
		0xA42628B4A3CD35BAULL,
		0x82A273148A79351FULL,
		0xA5D07FBFE089D832ULL,
		0x5F33A502DE943A9CULL
	}};
	printf("Test Case 246\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 246 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -246;
	} else {
		printf("Test Case 246 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x525E875F394E8F50ULL,
		0x46A054A00FFDD29BULL,
		0x985EBDE9B7890986ULL,
		0xA964499F60051FE6ULL,
		0xF63471FD9AB34DA2ULL,
		0x53F0C60FFC73B438ULL,
		0x9228916A82A573EAULL,
		0x229958FCF1F26AF7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA4BD0EBE729D1EA0ULL,
		0x8D40A9401FFBA536ULL,
		0x30BD7BD36F12130CULL,
		0x52C8933EC00A3FCDULL,
		0xEC68E3FB35669B45ULL,
		0xA7E18C1FF8E76871ULL,
		0x245122D5054AE7D4ULL,
		0x4532B1F9E3E4D5EFULL
	}};
	printf("Test Case 247\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 247 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -247;
	} else {
		printf("Test Case 247 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5063CDC02175A457ULL,
		0x85F262D5BFECD247ULL,
		0x23A5540F8DA6BE12ULL,
		0xC504A4A5E753BE42ULL,
		0x69BD79CECD6FCC12ULL,
		0x036F99808052837CULL,
		0x5DBABB1788D6D7FBULL,
		0x031B165B43A1251AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA0C79B8042EB48AEULL,
		0x0BE4C5AB7FD9A48EULL,
		0x474AA81F1B4D7C25ULL,
		0x8A09494BCEA77C84ULL,
		0xD37AF39D9ADF9825ULL,
		0x06DF330100A506F8ULL,
		0xBB75762F11ADAFF6ULL,
		0x06362CB687424A34ULL
	}};
	printf("Test Case 248\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 248 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -248;
	} else {
		printf("Test Case 248 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x57DAD6B2462F8AD9ULL,
		0x0AFE238AB8D9647DULL,
		0xBD54B59B4409F8BCULL,
		0x042BDE2882D00354ULL,
		0x4BCD3AE5674531FAULL,
		0xB5C658B7535E5A09ULL,
		0x7F75B4AB12275EA6ULL,
		0x2158D623E0BA8070ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAFB5AD648C5F15B2ULL,
		0x15FC471571B2C8FAULL,
		0x7AA96B368813F178ULL,
		0x0857BC5105A006A9ULL,
		0x979A75CACE8A63F4ULL,
		0x6B8CB16EA6BCB412ULL,
		0xFEEB6956244EBD4DULL,
		0x42B1AC47C17500E0ULL
	}};
	printf("Test Case 249\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 249 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -249;
	} else {
		printf("Test Case 249 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA15EF4849D88993CULL,
		0xE42FDA2121EA80C1ULL,
		0xC92831925F0638C3ULL,
		0x4A54490719302892ULL,
		0x526AA9CFB3BFD735ULL,
		0x4382CA9DC43F0FF0ULL,
		0x89B8AC7EBF2866B2ULL,
		0x3FDBB59C004852EEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x42BDE9093B113278ULL,
		0xC85FB44243D50183ULL,
		0x92506324BE0C7187ULL,
		0x94A8920E32605125ULL,
		0xA4D5539F677FAE6AULL,
		0x8705953B887E1FE0ULL,
		0x137158FD7E50CD64ULL,
		0x7FB76B380090A5DDULL
	}};
	printf("Test Case 250\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 250 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -250;
	} else {
		printf("Test Case 250 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x28D3D7B5DDF91F72ULL,
		0x02BDBB33C18A91E5ULL,
		0xC6CE6F41ECDF72DBULL,
		0x67AA569C26138AA8ULL,
		0x3EEC07674D9FE1A7ULL,
		0x305E4B4D5D241B1DULL,
		0x80929D8EE07788AAULL,
		0x219542982AE29A17ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x51A7AF6BBBF23EE4ULL,
		0x057B7667831523CAULL,
		0x8D9CDE83D9BEE5B6ULL,
		0xCF54AD384C271551ULL,
		0x7DD80ECE9B3FC34EULL,
		0x60BC969ABA48363AULL,
		0x01253B1DC0EF1154ULL,
		0x432A853055C5342FULL
	}};
	printf("Test Case 251\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 251 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -251;
	} else {
		printf("Test Case 251 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x70079817B11F6919ULL,
		0x7AFF32E2D8B64E58ULL,
		0x776E79EFA95A6D7FULL,
		0x7C991D7AF7815931ULL,
		0x49E35532907ECFFDULL,
		0x2E4CD24A728085BAULL,
		0x366024AF14AC06C3ULL,
		0x286A1173EEA39AC7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE00F302F623ED232ULL,
		0xF5FE65C5B16C9CB0ULL,
		0xEEDCF3DF52B4DAFEULL,
		0xF9323AF5EF02B262ULL,
		0x93C6AA6520FD9FFAULL,
		0x5C99A494E5010B74ULL,
		0x6CC0495E29580D86ULL,
		0x50D422E7DD47358EULL
	}};
	printf("Test Case 252\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 252 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -252;
	} else {
		printf("Test Case 252 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x894D42C29E870374ULL,
		0x6CFC67208DE0A5ACULL,
		0xB8DD447E899A0E92ULL,
		0x1FBB48812C14A930ULL,
		0xE6151241B1A67BF2ULL,
		0xD9C088762DBE35DAULL,
		0x803D772FDBB1A351ULL,
		0x0AD75700F37DE094ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x129A85853D0E06E8ULL,
		0xD9F8CE411BC14B59ULL,
		0x71BA88FD13341D24ULL,
		0x3F76910258295261ULL,
		0xCC2A2483634CF7E4ULL,
		0xB38110EC5B7C6BB5ULL,
		0x007AEE5FB76346A3ULL,
		0x15AEAE01E6FBC129ULL
	}};
	printf("Test Case 253\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 253 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -253;
	} else {
		printf("Test Case 253 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x84095DAA89A2F664ULL,
		0xACBAE344BF9E5A94ULL,
		0xE414202D5365C006ULL,
		0xA4B90C1CD48CA84FULL,
		0x4A92CB01F3F871C6ULL,
		0xE94308A03C58489DULL,
		0x29AC42798F501F43ULL,
		0x17AF9903232C3B19ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0812BB551345ECC8ULL,
		0x5975C6897F3CB529ULL,
		0xC828405AA6CB800DULL,
		0x49721839A919509FULL,
		0x95259603E7F0E38DULL,
		0xD286114078B0913AULL,
		0x535884F31EA03E87ULL,
		0x2F5F320646587632ULL
	}};
	printf("Test Case 254\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 254 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -254;
	} else {
		printf("Test Case 254 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x25E5359515EE2BF4ULL,
		0x05DBC70EFA4A58E1ULL,
		0xBD615B755D568180ULL,
		0x0557D6E2C3C2F846ULL,
		0x7ACA3B294511F6E1ULL,
		0x6E993EE508B1AD18ULL,
		0x54E2344E66382084ULL,
		0x1404CDDCF0104C0BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4BCA6B2A2BDC57E8ULL,
		0x0BB78E1DF494B1C2ULL,
		0x7AC2B6EABAAD0300ULL,
		0x0AAFADC58785F08DULL,
		0xF59476528A23EDC2ULL,
		0xDD327DCA11635A30ULL,
		0xA9C4689CCC704108ULL,
		0x28099BB9E0209816ULL
	}};
	printf("Test Case 255\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 255 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -255;
	} else {
		printf("Test Case 255 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB6441F3C243F2988ULL,
		0xE0CE077DCEAFE5F5ULL,
		0x7068704FD1AC3EDCULL,
		0xA3248904A8FCA0EBULL,
		0xF12F6DF90E54CFE8ULL,
		0xC3613112403FEA1CULL,
		0x3E5FBCF388194C10ULL,
		0x0D4E34AE6A6A3E2DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6C883E78487E5310ULL,
		0xC19C0EFB9D5FCBEBULL,
		0xE0D0E09FA3587DB9ULL,
		0x4649120951F941D6ULL,
		0xE25EDBF21CA99FD1ULL,
		0x86C26224807FD439ULL,
		0x7CBF79E710329821ULL,
		0x1A9C695CD4D47C5AULL
	}};
	printf("Test Case 256\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 256 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -256;
	} else {
		printf("Test Case 256 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB1BC6EAF0A6183ADULL,
		0xC792784049C8EB0BULL,
		0x7A3FC0583211DC59ULL,
		0x67974DE1CE805BBEULL,
		0x44AA50DD97CC6D8EULL,
		0x6ABB718B3DE99606ULL,
		0x0FC91161F0B585CDULL,
		0x0AC91E9CCAB8A6E0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6378DD5E14C3075AULL,
		0x8F24F0809391D617ULL,
		0xF47F80B06423B8B3ULL,
		0xCF2E9BC39D00B77CULL,
		0x8954A1BB2F98DB1CULL,
		0xD576E3167BD32C0CULL,
		0x1F9222C3E16B0B9AULL,
		0x15923D3995714DC0ULL
	}};
	printf("Test Case 257\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 257 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -257;
	} else {
		printf("Test Case 257 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x83B1C70F0A7178F0ULL,
		0x9DC6999B7B193188ULL,
		0xC20CC3309F4F52AAULL,
		0x170F5F6D611E67B1ULL,
		0x6E97A782B1C937AFULL,
		0xFB70118E797DC28FULL,
		0x14104CE8C59A7BBCULL,
		0x397A32743E6D2A8FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x07638E1E14E2F1E0ULL,
		0x3B8D3336F6326311ULL,
		0x841986613E9EA555ULL,
		0x2E1EBEDAC23CCF63ULL,
		0xDD2F4F0563926F5EULL,
		0xF6E0231CF2FB851EULL,
		0x282099D18B34F779ULL,
		0x72F464E87CDA551EULL
	}};
	printf("Test Case 258\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 258 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -258;
	} else {
		printf("Test Case 258 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1F8F60CB0B01DF67ULL,
		0xEE728C028994C570ULL,
		0x3EF0C3AA52BAB58BULL,
		0x9C5D635CDCD027EEULL,
		0xA6E023A9C9BBA6E6ULL,
		0x4421419415127D49ULL,
		0xD1EA99696A854A6AULL,
		0x07E31A3368A53ACDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3F1EC1961603BECEULL,
		0xDCE5180513298AE0ULL,
		0x7DE18754A5756B17ULL,
		0x38BAC6B9B9A04FDCULL,
		0x4DC0475393774DCDULL,
		0x884283282A24FA93ULL,
		0xA3D532D2D50A94D4ULL,
		0x0FC63466D14A759BULL
	}};
	printf("Test Case 259\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 259 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -259;
	} else {
		printf("Test Case 259 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC531E6CC28A09D4CULL,
		0x00567A62CBECF8CFULL,
		0x7658A73D9F1FA3D2ULL,
		0x2B664CCD478DCD40ULL,
		0x105AB5BD452949F7ULL,
		0x675BFFC1A55D4B6DULL,
		0x183789B6F69DDF71ULL,
		0x087E31392F2ABBECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8A63CD9851413A98ULL,
		0x00ACF4C597D9F19FULL,
		0xECB14E7B3E3F47A4ULL,
		0x56CC999A8F1B9A80ULL,
		0x20B56B7A8A5293EEULL,
		0xCEB7FF834ABA96DAULL,
		0x306F136DED3BBEE2ULL,
		0x10FC62725E5577D8ULL
	}};
	printf("Test Case 260\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 260 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -260;
	} else {
		printf("Test Case 260 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x29DA29B9D8609354ULL,
		0x47E4351AD797EC65ULL,
		0x1DD16CE189FDF531ULL,
		0x0B03CBA9971FB7A2ULL,
		0x0E720B2E47D752F8ULL,
		0x2277B82B0D7B616DULL,
		0xB75B681B56146DECULL,
		0x1A324327B606339CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x53B45373B0C126A8ULL,
		0x8FC86A35AF2FD8CAULL,
		0x3BA2D9C313FBEA62ULL,
		0x160797532E3F6F44ULL,
		0x1CE4165C8FAEA5F0ULL,
		0x44EF70561AF6C2DAULL,
		0x6EB6D036AC28DBD8ULL,
		0x3464864F6C0C6739ULL
	}};
	printf("Test Case 261\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 261 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -261;
	} else {
		printf("Test Case 261 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5B6386EA48B91515ULL,
		0xA7BE43623E0AD18FULL,
		0x66D15F507D7962A3ULL,
		0x96211DE67A18E3FFULL,
		0xC216F73EA3CA762AULL,
		0x80C8A652BF40BD6BULL,
		0x1A0C80433777B4F1ULL,
		0x30DA7E33D43EF928ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB6C70DD491722A2AULL,
		0x4F7C86C47C15A31EULL,
		0xCDA2BEA0FAF2C547ULL,
		0x2C423BCCF431C7FEULL,
		0x842DEE7D4794EC55ULL,
		0x01914CA57E817AD7ULL,
		0x341900866EEF69E3ULL,
		0x61B4FC67A87DF250ULL
	}};
	printf("Test Case 262\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 262 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -262;
	} else {
		printf("Test Case 262 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA43685F8959974ADULL,
		0x82720FF176155B3CULL,
		0xFF783A753F376D1BULL,
		0x3D8155F28DC9A827ULL,
		0x7055064047A3D5A4ULL,
		0xF126B12B38283972ULL,
		0x6A9C4E5380EAAE0DULL,
		0x2D68FDEE9016627AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x486D0BF12B32E95AULL,
		0x04E41FE2EC2AB679ULL,
		0xFEF074EA7E6EDA37ULL,
		0x7B02ABE51B93504FULL,
		0xE0AA0C808F47AB48ULL,
		0xE24D6256705072E4ULL,
		0xD5389CA701D55C1BULL,
		0x5AD1FBDD202CC4F4ULL
	}};
	printf("Test Case 263\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 263 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -263;
	} else {
		printf("Test Case 263 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBF54701017477AA5ULL,
		0x1DE39EFCC5ACF048ULL,
		0x1EB174479C8F6B0EULL,
		0x38C680D885FA206BULL,
		0xA182F4623D5DC369ULL,
		0xD84D7421BB0F17C9ULL,
		0x77E4AEA727DCDA84ULL,
		0x373E9065F38BF2BEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7EA8E0202E8EF54AULL,
		0x3BC73DF98B59E091ULL,
		0x3D62E88F391ED61CULL,
		0x718D01B10BF440D6ULL,
		0x4305E8C47ABB86D2ULL,
		0xB09AE843761E2F93ULL,
		0xEFC95D4E4FB9B509ULL,
		0x6E7D20CBE717E57CULL
	}};
	printf("Test Case 264\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 264 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -264;
	} else {
		printf("Test Case 264 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC48825CE4F94F29EULL,
		0x4A3BE61132945A63ULL,
		0xA9416AE4B4E3B7A3ULL,
		0x182265AB230C0ABFULL,
		0xD6B493EA4912BB16ULL,
		0xBB87D89D71ABE6ABULL,
		0x2AF53532CB56D781ULL,
		0x0BCCB15DA06307D0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x89104B9C9F29E53CULL,
		0x9477CC226528B4C7ULL,
		0x5282D5C969C76F46ULL,
		0x3044CB564618157FULL,
		0xAD6927D49225762CULL,
		0x770FB13AE357CD57ULL,
		0x55EA6A6596ADAF03ULL,
		0x179962BB40C60FA0ULL
	}};
	printf("Test Case 265\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 265 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -265;
	} else {
		printf("Test Case 265 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2C731DF14DC16A41ULL,
		0xCECE3A369EA35FCEULL,
		0x84A360C397CD8283ULL,
		0x814C4FF136698337ULL,
		0xA330572DA57EB6A1ULL,
		0x02933E70A7CE5DA1ULL,
		0x74A0E31374DDD1A1ULL,
		0x261E0681AD94D4E3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x58E63BE29B82D482ULL,
		0x9D9C746D3D46BF9CULL,
		0x0946C1872F9B0507ULL,
		0x02989FE26CD3066FULL,
		0x4660AE5B4AFD6D43ULL,
		0x05267CE14F9CBB43ULL,
		0xE941C626E9BBA342ULL,
		0x4C3C0D035B29A9C6ULL
	}};
	printf("Test Case 266\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 266 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -266;
	} else {
		printf("Test Case 266 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9D2DB2F9B88D659CULL,
		0x1337C82E5E63D84BULL,
		0xCF009A5BB3342053ULL,
		0xB1F2DB51C2467FA1ULL,
		0x1FB462D87AD3B417ULL,
		0xCDC6E67A1904A7ADULL,
		0x3AA08AE9F123E5EAULL,
		0x050ADB0EECCEDD3FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3A5B65F3711ACB38ULL,
		0x266F905CBCC7B097ULL,
		0x9E0134B7666840A6ULL,
		0x63E5B6A3848CFF43ULL,
		0x3F68C5B0F5A7682FULL,
		0x9B8DCCF432094F5AULL,
		0x754115D3E247CBD5ULL,
		0x0A15B61DD99DBA7EULL
	}};
	printf("Test Case 267\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 267 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -267;
	} else {
		printf("Test Case 267 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC373529B3101CDDBULL,
		0x65A48B4DB351671EULL,
		0x4C445628F1D31F49ULL,
		0xF55416D8EB0D1204ULL,
		0x7E78ED7C744E423AULL,
		0xE44F73E5F181A8B1ULL,
		0x351E736357F8BCC5ULL,
		0x11486EA35CDE6BABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x86E6A53662039BB6ULL,
		0xCB49169B66A2CE3DULL,
		0x9888AC51E3A63E92ULL,
		0xEAA82DB1D61A2408ULL,
		0xFCF1DAF8E89C8475ULL,
		0xC89EE7CBE3035162ULL,
		0x6A3CE6C6AFF1798BULL,
		0x2290DD46B9BCD756ULL
	}};
	printf("Test Case 268\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 268 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -268;
	} else {
		printf("Test Case 268 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x55D9F9A0623DC536ULL,
		0xD49C513BC8ADE536ULL,
		0xFE079C3C2111B7D7ULL,
		0x37C7C21802E82226ULL,
		0x4B98258BEAF48F01ULL,
		0xD26F290FB23C7E65ULL,
		0xB1CFB7B6DC7EF4E1ULL,
		0x1D45E38AACA636E2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xABB3F340C47B8A6CULL,
		0xA938A277915BCA6CULL,
		0xFC0F387842236FAFULL,
		0x6F8F843005D0444DULL,
		0x97304B17D5E91E02ULL,
		0xA4DE521F6478FCCAULL,
		0x639F6F6DB8FDE9C3ULL,
		0x3A8BC715594C6DC5ULL
	}};
	printf("Test Case 269\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 269 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -269;
	} else {
		printf("Test Case 269 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB6AD3BC346D2BC6FULL,
		0x12481ECD3361F7ACULL,
		0x2FDCC7325C1D585FULL,
		0x8AB80C800880D4F4ULL,
		0xFD50D9BE13759C76ULL,
		0x3ED31DB582054F75ULL,
		0xF57A04872C166D11ULL,
		0x179391BB1B37D637ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6D5A77868DA578DEULL,
		0x24903D9A66C3EF59ULL,
		0x5FB98E64B83AB0BEULL,
		0x157019001101A9E8ULL,
		0xFAA1B37C26EB38EDULL,
		0x7DA63B6B040A9EEBULL,
		0xEAF4090E582CDA22ULL,
		0x2F272376366FAC6FULL
	}};
	printf("Test Case 270\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 270 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -270;
	} else {
		printf("Test Case 270 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC8BAD0C8A44B01E9ULL,
		0x923F97F7FB7C2C7BULL,
		0xBE9B0B063321B450ULL,
		0xA3CBAF7077A6B63FULL,
		0xF49896FAB71C8EFDULL,
		0x422592EFA658C166ULL,
		0x70F82470290234F3ULL,
		0x2F3BEC66A90DB9B1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9175A191489603D2ULL,
		0x247F2FEFF6F858F7ULL,
		0x7D36160C664368A1ULL,
		0x47975EE0EF4D6C7FULL,
		0xE9312DF56E391DFBULL,
		0x844B25DF4CB182CDULL,
		0xE1F048E0520469E6ULL,
		0x5E77D8CD521B7362ULL
	}};
	printf("Test Case 271\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 271 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -271;
	} else {
		printf("Test Case 271 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x76C194B0C6AA6245ULL,
		0x25995CE1E3D93F2EULL,
		0x8C059CF5FBABA18CULL,
		0xE544485CABBE759EULL,
		0x26520301699EFB3AULL,
		0xB1E1B99FCF094206ULL,
		0x8B6FCA1F93D751CDULL,
		0x30A1B766450A3473ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xED8329618D54C48AULL,
		0x4B32B9C3C7B27E5CULL,
		0x180B39EBF7574318ULL,
		0xCA8890B9577CEB3DULL,
		0x4CA40602D33DF675ULL,
		0x63C3733F9E12840CULL,
		0x16DF943F27AEA39BULL,
		0x61436ECC8A1468E7ULL
	}};
	printf("Test Case 272\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 272 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -272;
	} else {
		printf("Test Case 272 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7DE1C7634952A834ULL,
		0x64F3E3EAE26C9133ULL,
		0xF294DF12E45FFF27ULL,
		0xB15BE3B4CB2BAC69ULL,
		0x6FD8C1F4AA41CC5FULL,
		0xDEDAD484EE7402DDULL,
		0x8DC70D66189F2B1CULL,
		0x0322C7DFCFEBE4C5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFBC38EC692A55068ULL,
		0xC9E7C7D5C4D92266ULL,
		0xE529BE25C8BFFE4EULL,
		0x62B7C769965758D3ULL,
		0xDFB183E9548398BFULL,
		0xBDB5A909DCE805BAULL,
		0x1B8E1ACC313E5639ULL,
		0x06458FBF9FD7C98BULL
	}};
	printf("Test Case 273\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 273 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -273;
	} else {
		printf("Test Case 273 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEBDB425572CB5C24ULL,
		0xFD9D60B2741C1170ULL,
		0xC73CB066CF32F5B8ULL,
		0xEDE095A50D3F5370ULL,
		0x77046D7A1B0E9F2BULL,
		0xC0F6E74C7DE7B82BULL,
		0xC99D1664DAF25C34ULL,
		0x24D92C2A420E35F8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD7B684AAE596B848ULL,
		0xFB3AC164E83822E1ULL,
		0x8E7960CD9E65EB71ULL,
		0xDBC12B4A1A7EA6E1ULL,
		0xEE08DAF4361D3E57ULL,
		0x81EDCE98FBCF7056ULL,
		0x933A2CC9B5E4B869ULL,
		0x49B25854841C6BF1ULL
	}};
	printf("Test Case 274\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 274 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -274;
	} else {
		printf("Test Case 274 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9C5D40E858B8E35EULL,
		0xA96AEBA063AC4895ULL,
		0x8EF050967F56A4C2ULL,
		0x107DAA7617BB9F28ULL,
		0xE6508C3BBED25BAAULL,
		0x869988B4C1A9D391ULL,
		0x3E81022DA9973926ULL,
		0x028495CB607B5B20ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x38BA81D0B171C6BCULL,
		0x52D5D740C758912BULL,
		0x1DE0A12CFEAD4985ULL,
		0x20FB54EC2F773E51ULL,
		0xCCA118777DA4B754ULL,
		0x0D3311698353A723ULL,
		0x7D02045B532E724DULL,
		0x05092B96C0F6B640ULL
	}};
	printf("Test Case 275\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 275 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -275;
	} else {
		printf("Test Case 275 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3FF5DCF4C9A5754BULL,
		0xCACBEA789F1C3DFBULL,
		0xC042051336154E2CULL,
		0x11151551AC59B41BULL,
		0x3941E6659D619965ULL,
		0xF24F91768B28927DULL,
		0xDCD55287B5ACA210ULL,
		0x252C5296A0EA1898ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7FEBB9E9934AEA96ULL,
		0x9597D4F13E387BF6ULL,
		0x80840A266C2A9C59ULL,
		0x222A2AA358B36837ULL,
		0x7283CCCB3AC332CAULL,
		0xE49F22ED165124FAULL,
		0xB9AAA50F6B594421ULL,
		0x4A58A52D41D43131ULL
	}};
	printf("Test Case 276\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 276 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -276;
	} else {
		printf("Test Case 276 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x92FF09D4BA83628CULL,
		0x74EFA3087C5B5FC9ULL,
		0xE0DD1B45F95306EDULL,
		0x3DC5DB6E1F8B04FAULL,
		0xF71ECC916DA94DA9ULL,
		0xD33EA3C4AD6CC519ULL,
		0x76DB14BF38B5654EULL,
		0x3F2821F9C7574E39ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x25FE13A97506C518ULL,
		0xE9DF4610F8B6BF93ULL,
		0xC1BA368BF2A60DDAULL,
		0x7B8BB6DC3F1609F5ULL,
		0xEE3D9922DB529B52ULL,
		0xA67D47895AD98A33ULL,
		0xEDB6297E716ACA9DULL,
		0x7E5043F38EAE9C72ULL
	}};
	printf("Test Case 277\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 277 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -277;
	} else {
		printf("Test Case 277 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1D7C029FC04C31E8ULL,
		0x0DB846FC5AE9BF6DULL,
		0xA3982E4F61F2DF5EULL,
		0x11FDAFA22AD7F4AEULL,
		0xBF47067F4B30E5F7ULL,
		0x770BB83BB7041C26ULL,
		0x366B777CAA0A5C85ULL,
		0x3285E6619A07F7B3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3AF8053F809863D0ULL,
		0x1B708DF8B5D37EDAULL,
		0x47305C9EC3E5BEBCULL,
		0x23FB5F4455AFE95DULL,
		0x7E8E0CFE9661CBEEULL,
		0xEE1770776E08384DULL,
		0x6CD6EEF95414B90AULL,
		0x650BCCC3340FEF66ULL
	}};
	printf("Test Case 278\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 278 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -278;
	} else {
		printf("Test Case 278 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD45A0A0B6AE27D4EULL,
		0x759763AFF857AB91ULL,
		0x9FC89484B3AC08CAULL,
		0x92A626BFA6A2563CULL,
		0x351DEF5EEFF241C9ULL,
		0x456B5D302AA913B2ULL,
		0x14EE1C745CDC74E4ULL,
		0x1FEDD4F62268C0F9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA8B41416D5C4FA9CULL,
		0xEB2EC75FF0AF5723ULL,
		0x3F91290967581194ULL,
		0x254C4D7F4D44AC79ULL,
		0x6A3BDEBDDFE48393ULL,
		0x8AD6BA6055522764ULL,
		0x29DC38E8B9B8E9C8ULL,
		0x3FDBA9EC44D181F2ULL
	}};
	printf("Test Case 279\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 279 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -279;
	} else {
		printf("Test Case 279 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE35595B5063EE722ULL,
		0x6CAEE19A9FE746CFULL,
		0x527EDCF27457ABA4ULL,
		0x76E07F8376ABAEFDULL,
		0xA493F5A0900BA320ULL,
		0x2928C632DB944B5AULL,
		0xBE5EF66DBC5DA55DULL,
		0x134D67B95ABAC221ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC6AB2B6A0C7DCE44ULL,
		0xD95DC3353FCE8D9FULL,
		0xA4FDB9E4E8AF5748ULL,
		0xEDC0FF06ED575DFAULL,
		0x4927EB4120174640ULL,
		0x52518C65B72896B5ULL,
		0x7CBDECDB78BB4ABAULL,
		0x269ACF72B5758443ULL
	}};
	printf("Test Case 280\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 280 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -280;
	} else {
		printf("Test Case 280 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEB8A7E0B70B51420ULL,
		0x0D3EA2F1E11B000FULL,
		0x932FF331780BB662ULL,
		0xCD9768680E5AD7F8ULL,
		0x0B078DE7CF1960C0ULL,
		0x5F89E48D82D25453ULL,
		0x49AE0A3EE6FBCE3DULL,
		0x0D73249C37B702B3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD714FC16E16A2840ULL,
		0x1A7D45E3C236001FULL,
		0x265FE662F0176CC4ULL,
		0x9B2ED0D01CB5AFF1ULL,
		0x160F1BCF9E32C181ULL,
		0xBF13C91B05A4A8A6ULL,
		0x935C147DCDF79C7AULL,
		0x1AE649386F6E0566ULL
	}};
	printf("Test Case 281\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 281 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -281;
	} else {
		printf("Test Case 281 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE5E8BFA728E14B83ULL,
		0x45EF383A7798DCCEULL,
		0xA315B06DBCA95670ULL,
		0xC975338C549324DFULL,
		0x9FD1DA459B9363A0ULL,
		0xA2D1C56492760580ULL,
		0xF732BDECE496B889ULL,
		0x01DD9B082AE8DA9EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCBD17F4E51C29706ULL,
		0x8BDE7074EF31B99DULL,
		0x462B60DB7952ACE0ULL,
		0x92EA6718A92649BFULL,
		0x3FA3B48B3726C741ULL,
		0x45A38AC924EC0B01ULL,
		0xEE657BD9C92D7113ULL,
		0x03BB361055D1B53DULL
	}};
	printf("Test Case 282\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 282 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -282;
	} else {
		printf("Test Case 282 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCA1BDA5DBA2FC63AULL,
		0xC563A959290A2C33ULL,
		0xEE353056942E4529ULL,
		0xD244E76DA9A08198ULL,
		0xE816865AF444AC62ULL,
		0x2F59C394770AD784ULL,
		0x948199BB29BDC717ULL,
		0x0A80174C2913476AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9437B4BB745F8C74ULL,
		0x8AC752B252145867ULL,
		0xDC6A60AD285C8A53ULL,
		0xA489CEDB53410331ULL,
		0xD02D0CB5E88958C5ULL,
		0x5EB38728EE15AF09ULL,
		0x29033376537B8E2EULL,
		0x15002E9852268ED5ULL
	}};
	printf("Test Case 283\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 283 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -283;
	} else {
		printf("Test Case 283 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB612D0B774815090ULL,
		0x319077658A9C2D7EULL,
		0xEC9F723188C94B45ULL,
		0x7452DC3452E3F990ULL,
		0xB62087DA552A8900ULL,
		0x2530866D72EF9F02ULL,
		0x47E73199EA462F10ULL,
		0x11A3F37BC3F6D5B7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6C25A16EE902A120ULL,
		0x6320EECB15385AFDULL,
		0xD93EE4631192968AULL,
		0xE8A5B868A5C7F321ULL,
		0x6C410FB4AA551200ULL,
		0x4A610CDAE5DF3E05ULL,
		0x8FCE6333D48C5E20ULL,
		0x2347E6F787EDAB6EULL
	}};
	printf("Test Case 284\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 284 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -284;
	} else {
		printf("Test Case 284 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2B62C5DED2D89C6DULL,
		0x69BBA65D1356027DULL,
		0xDB26D6B439210996ULL,
		0x63D61B76A3DBCED9ULL,
		0x6F2A85FCBAF87AB8ULL,
		0x339912919B839544ULL,
		0x9048EAAC526806FDULL,
		0x21954FD9D97C967FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x56C58BBDA5B138DAULL,
		0xD3774CBA26AC04FAULL,
		0xB64DAD687242132CULL,
		0xC7AC36ED47B79DB3ULL,
		0xDE550BF975F0F570ULL,
		0x6732252337072A88ULL,
		0x2091D558A4D00DFAULL,
		0x432A9FB3B2F92CFFULL
	}};
	printf("Test Case 285\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 285 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -285;
	} else {
		printf("Test Case 285 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3B5DF9DE71471DFBULL,
		0x1967DE84EAA7C68DULL,
		0xA8B2F7C7A9AE465DULL,
		0xF4B68305C44A24F6ULL,
		0xA224FB6A159E55E2ULL,
		0x6913F731E877EBE0ULL,
		0x5E9F98AFA7C9D4DEULL,
		0x1681ED4FA414919EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x76BBF3BCE28E3BF6ULL,
		0x32CFBD09D54F8D1AULL,
		0x5165EF8F535C8CBAULL,
		0xE96D060B889449EDULL,
		0x4449F6D42B3CABC5ULL,
		0xD227EE63D0EFD7C1ULL,
		0xBD3F315F4F93A9BCULL,
		0x2D03DA9F4829233CULL
	}};
	printf("Test Case 286\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 286 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -286;
	} else {
		printf("Test Case 286 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1D6CE4FDA54F8C32ULL,
		0x647F9102CD5062B0ULL,
		0xF7183225E05077FCULL,
		0x1DD59BE881FF3C12ULL,
		0xC23D72D1EB7220FBULL,
		0x5CE3FA90758DBFA5ULL,
		0x474F1BA303B3B092ULL,
		0x2AFC52E954BBC6A7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3AD9C9FB4A9F1864ULL,
		0xC8FF22059AA0C560ULL,
		0xEE30644BC0A0EFF8ULL,
		0x3BAB37D103FE7825ULL,
		0x847AE5A3D6E441F6ULL,
		0xB9C7F520EB1B7F4BULL,
		0x8E9E374607676124ULL,
		0x55F8A5D2A9778D4EULL
	}};
	printf("Test Case 287\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 287 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -287;
	} else {
		printf("Test Case 287 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x635A8F45B604E67DULL,
		0xBE80F669F2615D1FULL,
		0xD34C515480B5F120ULL,
		0x995589BD72E53134ULL,
		0x87E8B663BE9D3F85ULL,
		0xC7DE2CC844EAF484ULL,
		0xB5CA16C63CD1F7B4ULL,
		0x1B31BB97F3F80225ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC6B51E8B6C09CCFAULL,
		0x7D01ECD3E4C2BA3EULL,
		0xA698A2A9016BE241ULL,
		0x32AB137AE5CA6269ULL,
		0x0FD16CC77D3A7F0BULL,
		0x8FBC599089D5E909ULL,
		0x6B942D8C79A3EF69ULL,
		0x3663772FE7F0044BULL
	}};
	printf("Test Case 288\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 288 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -288;
	} else {
		printf("Test Case 288 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x903549EBC7EC6F51ULL,
		0x256E7E635D8B3A05ULL,
		0x3D4B7DC33F6AC880ULL,
		0x4547232B82B17D56ULL,
		0x1AD4CB852EE58630ULL,
		0xE1C7E19AEB13C4D3ULL,
		0x18A0F1AD993505A3ULL,
		0x065A200780FCB538ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x206A93D78FD8DEA2ULL,
		0x4ADCFCC6BB16740BULL,
		0x7A96FB867ED59100ULL,
		0x8A8E46570562FAACULL,
		0x35A9970A5DCB0C60ULL,
		0xC38FC335D62789A6ULL,
		0x3141E35B326A0B47ULL,
		0x0CB4400F01F96A70ULL
	}};
	printf("Test Case 289\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 289 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -289;
	} else {
		printf("Test Case 289 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7A774CA0597AB553ULL,
		0x38F641A0745BF070ULL,
		0x2FBC99457AEB0B03ULL,
		0x2FC55471385E79AFULL,
		0x325355FA2C9CDA03ULL,
		0x1C00B9EFDF7984AEULL,
		0xE50F1D2A05D2DF14ULL,
		0x147F9B0A6BCD8AA5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF4EE9940B2F56AA6ULL,
		0x71EC8340E8B7E0E0ULL,
		0x5F79328AF5D61606ULL,
		0x5F8AA8E270BCF35EULL,
		0x64A6ABF45939B406ULL,
		0x380173DFBEF3095CULL,
		0xCA1E3A540BA5BE28ULL,
		0x28FF3614D79B154BULL
	}};
	printf("Test Case 290\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 290 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -290;
	} else {
		printf("Test Case 290 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDA3E07576733BBF5ULL,
		0xCFA6341146C608E1ULL,
		0x45A7F79E5C4AD02AULL,
		0xFB31DE4DC3A61AF4ULL,
		0x783AC052176300C6ULL,
		0xA150D22A91F5C8CEULL,
		0xC75BA3AA6FE646BDULL,
		0x0814F917EA89F2FAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB47C0EAECE6777EAULL,
		0x9F4C68228D8C11C3ULL,
		0x8B4FEF3CB895A055ULL,
		0xF663BC9B874C35E8ULL,
		0xF07580A42EC6018DULL,
		0x42A1A45523EB919CULL,
		0x8EB74754DFCC8D7BULL,
		0x1029F22FD513E5F5ULL
	}};
	printf("Test Case 291\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 291 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -291;
	} else {
		printf("Test Case 291 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8FBA2A68D1DE5C3FULL,
		0x17362F4C3B0E788BULL,
		0x7B411E14B8877BCCULL,
		0x1DDDAF587AAE854EULL,
		0x5E302EC4E0A9DA61ULL,
		0x91ED54DE2676FCC3ULL,
		0x794F24184C41D92EULL,
		0x0F5A8496FDC80460ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1F7454D1A3BCB87EULL,
		0x2E6C5E98761CF117ULL,
		0xF6823C29710EF798ULL,
		0x3BBB5EB0F55D0A9CULL,
		0xBC605D89C153B4C2ULL,
		0x23DAA9BC4CEDF986ULL,
		0xF29E48309883B25DULL,
		0x1EB5092DFB9008C0ULL
	}};
	printf("Test Case 292\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 292 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -292;
	} else {
		printf("Test Case 292 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCA9B70A4FA45D223ULL,
		0x619A5576FA273C77ULL,
		0x47AD46907DC5B1B1ULL,
		0xAC4665AC898782B2ULL,
		0xF161F580E1857BCCULL,
		0x213569F320BBAF40ULL,
		0x32DCAD8F8F0A341BULL,
		0x37701089BB0BE631ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9536E149F48BA446ULL,
		0xC334AAEDF44E78EFULL,
		0x8F5A8D20FB8B6362ULL,
		0x588CCB59130F0564ULL,
		0xE2C3EB01C30AF799ULL,
		0x426AD3E641775E81ULL,
		0x65B95B1F1E146836ULL,
		0x6EE021137617CC62ULL
	}};
	printf("Test Case 293\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 293 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -293;
	} else {
		printf("Test Case 293 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD981F1FAB9B8451EULL,
		0x5F877A2F8871445CULL,
		0xD556C8F1B0EC120DULL,
		0x7CCE1310634F9130ULL,
		0xA14BD4D63C684433ULL,
		0xB1C2221E9D63724BULL,
		0x864290A144B855D8ULL,
		0x3C68C9E865AC19A9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB303E3F573708A3CULL,
		0xBF0EF45F10E288B9ULL,
		0xAAAD91E361D8241AULL,
		0xF99C2620C69F2261ULL,
		0x4297A9AC78D08866ULL,
		0x6384443D3AC6E497ULL,
		0x0C8521428970ABB1ULL,
		0x78D193D0CB583353ULL
	}};
	printf("Test Case 294\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 294 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -294;
	} else {
		printf("Test Case 294 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x671833E617C21955ULL,
		0x3093D9FB8891E1A8ULL,
		0xC3E5AD93282E98C1ULL,
		0x4C9135736CA5BB31ULL,
		0xF0A3318FF4C3FBDAULL,
		0x28D53EF14557BA3DULL,
		0x479DAFD21D16DD98ULL,
		0x34FD9BA992DD30AAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCE3067CC2F8432AAULL,
		0x6127B3F71123C350ULL,
		0x87CB5B26505D3182ULL,
		0x99226AE6D94B7663ULL,
		0xE146631FE987F7B4ULL,
		0x51AA7DE28AAF747BULL,
		0x8F3B5FA43A2DBB30ULL,
		0x69FB375325BA6154ULL
	}};
	printf("Test Case 295\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 295 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -295;
	} else {
		printf("Test Case 295 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x89EAF891A0CFF44FULL,
		0x78FCA2AAF5AEEFBBULL,
		0xB41008EA6CB7B212ULL,
		0x42D7A5D825B58B2EULL,
		0xB2488CD7EBBDDF7CULL,
		0xD7D3D44045ABCC69ULL,
		0x7A43642AA0CE8D42ULL,
		0x396D473DC3F01C39ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x13D5F123419FE89EULL,
		0xF1F94555EB5DDF77ULL,
		0x682011D4D96F6424ULL,
		0x85AF4BB04B6B165DULL,
		0x649119AFD77BBEF8ULL,
		0xAFA7A8808B5798D3ULL,
		0xF486C855419D1A85ULL,
		0x72DA8E7B87E03872ULL
	}};
	printf("Test Case 296\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 296 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -296;
	} else {
		printf("Test Case 296 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0BB8C1A4D4BA1E3FULL,
		0x51043A0CF2D8E3F5ULL,
		0xBD6A4B504641CC52ULL,
		0x26EDB1370D0F1F95ULL,
		0xF58799B0D585C969ULL,
		0x1A678607D8BAA6FBULL,
		0x2BAEC26E4835F3A4ULL,
		0x0CFC6CF7FC625286ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x17718349A9743C7EULL,
		0xA2087419E5B1C7EAULL,
		0x7AD496A08C8398A4ULL,
		0x4DDB626E1A1E3F2BULL,
		0xEB0F3361AB0B92D2ULL,
		0x34CF0C0FB1754DF7ULL,
		0x575D84DC906BE748ULL,
		0x19F8D9EFF8C4A50CULL
	}};
	printf("Test Case 297\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 297 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -297;
	} else {
		printf("Test Case 297 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE863B4B523D64FFAULL,
		0x0FF2A2D734E464C7ULL,
		0xED8008542E15953DULL,
		0x031356BEB1F6C599ULL,
		0x46E9E1D4926E998CULL,
		0xAE100F6B2DF89259ULL,
		0x2B1BF54419BC4B3DULL,
		0x258FC8AF93B5F59BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD0C7696A47AC9FF4ULL,
		0x1FE545AE69C8C98FULL,
		0xDB0010A85C2B2A7AULL,
		0x0626AD7D63ED8B33ULL,
		0x8DD3C3A924DD3318ULL,
		0x5C201ED65BF124B2ULL,
		0x5637EA883378967BULL,
		0x4B1F915F276BEB36ULL
	}};
	printf("Test Case 298\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 298 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -298;
	} else {
		printf("Test Case 298 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE037B55D79E86093ULL,
		0x22759245BAF42743ULL,
		0xCC5D0667DE04AD12ULL,
		0x251D7ACE810A6F32ULL,
		0x45B69F96C25415B4ULL,
		0x7A645B3D1C9ED26FULL,
		0x42FFF288EC68FB78ULL,
		0x3D7BBE7C0DB48A9EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC06F6ABAF3D0C126ULL,
		0x44EB248B75E84E87ULL,
		0x98BA0CCFBC095A24ULL,
		0x4A3AF59D0214DE65ULL,
		0x8B6D3F2D84A82B68ULL,
		0xF4C8B67A393DA4DEULL,
		0x85FFE511D8D1F6F0ULL,
		0x7AF77CF81B69153CULL
	}};
	printf("Test Case 299\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 299 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -299;
	} else {
		printf("Test Case 299 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x903508ED59DB4DA6ULL,
		0xA35F46135850D71EULL,
		0xD00EED1C8A822523ULL,
		0x2AC4A641664C5DBAULL,
		0x48339A3114EA2541ULL,
		0xEF966F142E584065ULL,
		0xB6EBD60938A7FB25ULL,
		0x3797BC2B1E4E48B0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x206A11DAB3B69B4CULL,
		0x46BE8C26B0A1AE3DULL,
		0xA01DDA3915044A47ULL,
		0x55894C82CC98BB75ULL,
		0x9067346229D44A82ULL,
		0xDF2CDE285CB080CAULL,
		0x6DD7AC12714FF64BULL,
		0x6F2F78563C9C9161ULL
	}};
	printf("Test Case 300\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 300 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -300;
	} else {
		printf("Test Case 300 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEBB2CC31DF55A90DULL,
		0xAFCC6D2C7CF45DCFULL,
		0x807A7306B02555DDULL,
		0xD18CB5AED1BBEC8DULL,
		0xA78CA55A76CF3D4DULL,
		0x0D628CE93B0E1C27ULL,
		0x8B71CFC92EB4EFDAULL,
		0x1901D456786812B8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD7659863BEAB521AULL,
		0x5F98DA58F9E8BB9FULL,
		0x00F4E60D604AABBBULL,
		0xA3196B5DA377D91BULL,
		0x4F194AB4ED9E7A9BULL,
		0x1AC519D2761C384FULL,
		0x16E39F925D69DFB4ULL,
		0x3203A8ACF0D02571ULL
	}};
	printf("Test Case 301\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 301 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -301;
	} else {
		printf("Test Case 301 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6F8D67767F4C8BD0ULL,
		0x90EDBE6562C4C255ULL,
		0xF72D39EFC3193809ULL,
		0xBEDD0D9CA1267849ULL,
		0x8BFD48CEC9EE3ADFULL,
		0x93808B5031B368FCULL,
		0x6ABB34A6C51C64EDULL,
		0x047B4790EE460A4EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDF1ACEECFE9917A0ULL,
		0x21DB7CCAC58984AAULL,
		0xEE5A73DF86327013ULL,
		0x7DBA1B39424CF093ULL,
		0x17FA919D93DC75BFULL,
		0x270116A06366D1F9ULL,
		0xD576694D8A38C9DBULL,
		0x08F68F21DC8C149CULL
	}};
	printf("Test Case 302\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 302 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -302;
	} else {
		printf("Test Case 302 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1AD9E575545B5000ULL,
		0x1C28D6F6FF33B229ULL,
		0x6FE353557A159256ULL,
		0x62BB346B368F25AFULL,
		0x4C6347AE80EFE962ULL,
		0xD467ADE9D4AA7F80ULL,
		0x30FED54FEBD42EA3ULL,
		0x2D0135F6D41AFFB9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x35B3CAEAA8B6A000ULL,
		0x3851ADEDFE676452ULL,
		0xDFC6A6AAF42B24ACULL,
		0xC57668D66D1E4B5EULL,
		0x98C68F5D01DFD2C4ULL,
		0xA8CF5BD3A954FF00ULL,
		0x61FDAA9FD7A85D47ULL,
		0x5A026BEDA835FF72ULL
	}};
	printf("Test Case 303\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 303 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -303;
	} else {
		printf("Test Case 303 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEC4061BD9F4A3668ULL,
		0xC7C55B7173A06522ULL,
		0x6FD0EAACBAF2F1DBULL,
		0x031BC01FDE170109ULL,
		0x7B8E51327F003AC0ULL,
		0xD41D16C064BBA090ULL,
		0x156D8486C84AB57BULL,
		0x3DA8F9968B17D776ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD880C37B3E946CD0ULL,
		0x8F8AB6E2E740CA45ULL,
		0xDFA1D55975E5E3B7ULL,
		0x0637803FBC2E0212ULL,
		0xF71CA264FE007580ULL,
		0xA83A2D80C9774120ULL,
		0x2ADB090D90956AF7ULL,
		0x7B51F32D162FAEECULL
	}};
	printf("Test Case 304\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 304 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -304;
	} else {
		printf("Test Case 304 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4FD0F358C0005316ULL,
		0xA166D091D03209DAULL,
		0xD9F1E13A3397C508ULL,
		0x5DB53763CDFDBE9FULL,
		0xED0AEABFCF9267EAULL,
		0x83DD336BEFCF7118ULL,
		0xE97CC8AFD80CBB82ULL,
		0x0B921AE0CDAD2691ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9FA1E6B18000A62CULL,
		0x42CDA123A06413B4ULL,
		0xB3E3C274672F8A11ULL,
		0xBB6A6EC79BFB7D3FULL,
		0xDA15D57F9F24CFD4ULL,
		0x07BA66D7DF9EE231ULL,
		0xD2F9915FB0197705ULL,
		0x172435C19B5A4D23ULL
	}};
	printf("Test Case 305\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 305 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -305;
	} else {
		printf("Test Case 305 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7E6E64EAC606D0EDULL,
		0x1B334D4B598DD1D2ULL,
		0xBAB3337CA8EBE6F8ULL,
		0x8A24AAF5E26600CEULL,
		0x3EA268F273099695ULL,
		0x79F278661DD6A51FULL,
		0x643F4B1EB5C7B310ULL,
		0x0DE558F56476B160ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFCDCC9D58C0DA1DAULL,
		0x36669A96B31BA3A4ULL,
		0x756666F951D7CDF0ULL,
		0x144955EBC4CC019DULL,
		0x7D44D1E4E6132D2BULL,
		0xF3E4F0CC3BAD4A3EULL,
		0xC87E963D6B8F6620ULL,
		0x1BCAB1EAC8ED62C0ULL
	}};
	printf("Test Case 306\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 306 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -306;
	} else {
		printf("Test Case 306 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE295039B983F9CA7ULL,
		0xFB392EA28E917EB7ULL,
		0x635D4AC348BD1EF1ULL,
		0x9EF71BE0F21B2510ULL,
		0x294374ABEAD12C3EULL,
		0xCA909C1D7E111C8BULL,
		0x6BEC7392CFEA1979ULL,
		0x08675A1A0C39335BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC52A0737307F394EULL,
		0xF6725D451D22FD6FULL,
		0xC6BA9586917A3DE3ULL,
		0x3DEE37C1E4364A20ULL,
		0x5286E957D5A2587DULL,
		0x9521383AFC223916ULL,
		0xD7D8E7259FD432F3ULL,
		0x10CEB434187266B6ULL
	}};
	printf("Test Case 307\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 307 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -307;
	} else {
		printf("Test Case 307 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x57E7868DF7E88A60ULL,
		0xAAE10F88EF9379BEULL,
		0xC43063025A0F4D87ULL,
		0x2B8B030ABBF6FC87ULL,
		0x4EAE5EF4AD1C615CULL,
		0x2C925C72C9D900D6ULL,
		0x4E45CDEED12F546DULL,
		0x2147D9E71D276C19ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAFCF0D1BEFD114C0ULL,
		0x55C21F11DF26F37CULL,
		0x8860C604B41E9B0FULL,
		0x5716061577EDF90FULL,
		0x9D5CBDE95A38C2B8ULL,
		0x5924B8E593B201ACULL,
		0x9C8B9BDDA25EA8DAULL,
		0x428FB3CE3A4ED832ULL
	}};
	printf("Test Case 308\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 308 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -308;
	} else {
		printf("Test Case 308 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5F2BB7B2931406C0ULL,
		0x3E4D35D31C47F17EULL,
		0x7A43563FEAE567BBULL,
		0xA0DE7E68431B0EC7ULL,
		0xCD8059826E0DCD1CULL,
		0x3955FEB505608E4FULL,
		0xB89F84FB28B04F27ULL,
		0x33755845EF7F5AE5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBE576F6526280D80ULL,
		0x7C9A6BA6388FE2FCULL,
		0xF486AC7FD5CACF76ULL,
		0x41BCFCD086361D8EULL,
		0x9B00B304DC1B9A39ULL,
		0x72ABFD6A0AC11C9FULL,
		0x713F09F651609E4EULL,
		0x66EAB08BDEFEB5CBULL
	}};
	printf("Test Case 309\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 309 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -309;
	} else {
		printf("Test Case 309 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA8521E5BDD9614EAULL,
		0x61413C60BE45F074ULL,
		0x38AAFC91B08099D2ULL,
		0x995592778FC13C24ULL,
		0x1F0018B27E431A90ULL,
		0x5E4534D26CA476F7ULL,
		0x96E6988A5A7FBB7DULL,
		0x0B1AB79771A1CFC5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x50A43CB7BB2C29D4ULL,
		0xC28278C17C8BE0E9ULL,
		0x7155F923610133A4ULL,
		0x32AB24EF1F827848ULL,
		0x3E003164FC863521ULL,
		0xBC8A69A4D948EDEEULL,
		0x2DCD3114B4FF76FAULL,
		0x16356F2EE3439F8BULL
	}};
	printf("Test Case 310\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 310 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -310;
	} else {
		printf("Test Case 310 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDF20ECE1B409D338ULL,
		0x3C13676F9300EA59ULL,
		0x5B819A5B7BA57F59ULL,
		0xFCB43248CDA744E2ULL,
		0xF03D3C726DE47F79ULL,
		0xCC65ECC4ACCBD5C4ULL,
		0x6E3C20CBD82482F3ULL,
		0x3F4FA6F5868ABBE0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBE41D9C36813A670ULL,
		0x7826CEDF2601D4B3ULL,
		0xB70334B6F74AFEB2ULL,
		0xF96864919B4E89C4ULL,
		0xE07A78E4DBC8FEF3ULL,
		0x98CBD9895997AB89ULL,
		0xDC784197B04905E7ULL,
		0x7E9F4DEB0D1577C0ULL
	}};
	printf("Test Case 311\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 311 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -311;
	} else {
		printf("Test Case 311 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9AD1A2B7EFA7EEE8ULL,
		0xA8DA5768EAD89836ULL,
		0x7824652FF87C8CA9ULL,
		0x50F3BD6AD40ADE11ULL,
		0x30CEA9775B1E4872ULL,
		0xB5F76A37BC15912FULL,
		0x6FE8048264428EFCULL,
		0x2C0F392566CA8633ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x35A3456FDF4FDDD0ULL,
		0x51B4AED1D5B1306DULL,
		0xF048CA5FF0F91953ULL,
		0xA1E77AD5A815BC22ULL,
		0x619D52EEB63C90E4ULL,
		0x6BEED46F782B225EULL,
		0xDFD00904C8851DF9ULL,
		0x581E724ACD950C66ULL
	}};
	printf("Test Case 312\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 312 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -312;
	} else {
		printf("Test Case 312 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA3E4C27405044A52ULL,
		0x02C400627C5137C4ULL,
		0x16395CE633A1892CULL,
		0xEC119563168ADD54ULL,
		0x768A00B27DAB1E87ULL,
		0x4910F7682ECA6FC3ULL,
		0x25D2670814B7EC5EULL,
		0x1D023EF6D62DF3DFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x47C984E80A0894A4ULL,
		0x058800C4F8A26F89ULL,
		0x2C72B9CC67431258ULL,
		0xD8232AC62D15BAA8ULL,
		0xED140164FB563D0FULL,
		0x9221EED05D94DF86ULL,
		0x4BA4CE10296FD8BCULL,
		0x3A047DEDAC5BE7BEULL
	}};
	printf("Test Case 313\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 313 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -313;
	} else {
		printf("Test Case 313 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2037B441C43BE84FULL,
		0x6410AFD65A97CE50ULL,
		0x8E561E7CC482B99CULL,
		0x66A9F4EFC4C465C8ULL,
		0x21C4E165F4F0227DULL,
		0x116E08083E71E62CULL,
		0x8727536C1DCF9D81ULL,
		0x2BCB4D75B5A0EE04ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x406F68838877D09EULL,
		0xC8215FACB52F9CA0ULL,
		0x1CAC3CF989057338ULL,
		0xCD53E9DF8988CB91ULL,
		0x4389C2CBE9E044FAULL,
		0x22DC10107CE3CC58ULL,
		0x0E4EA6D83B9F3B02ULL,
		0x57969AEB6B41DC09ULL
	}};
	printf("Test Case 314\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 314 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -314;
	} else {
		printf("Test Case 314 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAE58B1E24F3961B9ULL,
		0x66676ED55966D8CDULL,
		0xE47C0062F14BB0CEULL,
		0x5E3D494C424B9BC7ULL,
		0x8862AF60EF6264D3ULL,
		0xC7672A5AC8283C75ULL,
		0xA5830B5530825EC0ULL,
		0x26FC6E3572755957ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5CB163C49E72C372ULL,
		0xCCCEDDAAB2CDB19BULL,
		0xC8F800C5E297619CULL,
		0xBC7A92988497378FULL,
		0x10C55EC1DEC4C9A6ULL,
		0x8ECE54B5905078EBULL,
		0x4B0616AA6104BD81ULL,
		0x4DF8DC6AE4EAB2AFULL
	}};
	printf("Test Case 315\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 315 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -315;
	} else {
		printf("Test Case 315 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA127440D8D4BF57BULL,
		0xC943364FBC1941CDULL,
		0x488D0D4BD2305069ULL,
		0x7DBDAC01CA626709ULL,
		0x31E23BD93B5727DAULL,
		0xA3FEED2A8D2DFF6CULL,
		0x992451663C955499ULL,
		0x0C70742B3F8BCDB5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x424E881B1A97EAF6ULL,
		0x92866C9F7832839BULL,
		0x911A1A97A460A0D3ULL,
		0xFB7B580394C4CE12ULL,
		0x63C477B276AE4FB4ULL,
		0x47FDDA551A5BFED8ULL,
		0x3248A2CC792AA933ULL,
		0x18E0E8567F179B6BULL
	}};
	printf("Test Case 316\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 316 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -316;
	} else {
		printf("Test Case 316 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE67589698F357F25ULL,
		0xFCC5847F4DCA9A48ULL,
		0x9D21A4295E35FF5AULL,
		0x9E76695AB1D17D26ULL,
		0x58647F26652479FAULL,
		0x37BC0B3CEEB299D5ULL,
		0xAA55C4267E2A1A86ULL,
		0x3B90186F2319D07EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCCEB12D31E6AFE4AULL,
		0xF98B08FE9B953491ULL,
		0x3A434852BC6BFEB5ULL,
		0x3CECD2B563A2FA4DULL,
		0xB0C8FE4CCA48F3F5ULL,
		0x6F781679DD6533AAULL,
		0x54AB884CFC54350CULL,
		0x772030DE4633A0FDULL
	}};
	printf("Test Case 317\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 317 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -317;
	} else {
		printf("Test Case 317 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0BA063951AD37043ULL,
		0x7513E3E7CD254676ULL,
		0x495E3157295E8188ULL,
		0xF81B24724D537D5FULL,
		0x97D20EBD93E5D5A4ULL,
		0xDE85A2C12D7C7533ULL,
		0x067A3198F2B5DB52ULL,
		0x30F13363BF41874DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1740C72A35A6E086ULL,
		0xEA27C7CF9A4A8CECULL,
		0x92BC62AE52BD0310ULL,
		0xF03648E49AA6FABEULL,
		0x2FA41D7B27CBAB49ULL,
		0xBD0B45825AF8EA67ULL,
		0x0CF46331E56BB6A5ULL,
		0x61E266C77E830E9AULL
	}};
	printf("Test Case 318\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 318 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -318;
	} else {
		printf("Test Case 318 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD7AEE80A12ED0BD6ULL,
		0x4F387289F6F5421DULL,
		0xF70D793751D37CE7ULL,
		0x1B7A44221352E1C1ULL,
		0xB5D706C3083B1A0AULL,
		0xCADEB31C6980951BULL,
		0xC34311BC757C0996ULL,
		0x08514825AC9263E4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF5DD01425DA17ACULL,
		0x9E70E513EDEA843BULL,
		0xEE1AF26EA3A6F9CEULL,
		0x36F4884426A5C383ULL,
		0x6BAE0D8610763414ULL,
		0x95BD6638D3012A37ULL,
		0x86862378EAF8132DULL,
		0x10A2904B5924C7C9ULL
	}};
	printf("Test Case 319\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 319 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -319;
	} else {
		printf("Test Case 319 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x79B2A7F25501DD84ULL,
		0x8536D958EC95B321ULL,
		0xEBCE5BBC61A2212DULL,
		0xFB3E1A0E4E7B94DFULL,
		0x4961DCF567445F5BULL,
		0x463BF5916816C747ULL,
		0xD35D91DB14EA5B0AULL,
		0x0B972B28977E4CC4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF3654FE4AA03BB08ULL,
		0x0A6DB2B1D92B6642ULL,
		0xD79CB778C344425BULL,
		0xF67C341C9CF729BFULL,
		0x92C3B9EACE88BEB7ULL,
		0x8C77EB22D02D8E8EULL,
		0xA6BB23B629D4B614ULL,
		0x172E56512EFC9989ULL
	}};
	printf("Test Case 320\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 320 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -320;
	} else {
		printf("Test Case 320 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEE82BB49E551E822ULL,
		0x4EAA9466596F49C1ULL,
		0x173C9CE12205D7EBULL,
		0x7DE5E0054E380203ULL,
		0x01BD6C3753ABF466ULL,
		0x1494EF30460E7A7FULL,
		0xD3C383A4547A23F5ULL,
		0x08BD03DBBCD4EAB3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDD057693CAA3D044ULL,
		0x9D5528CCB2DE9383ULL,
		0x2E7939C2440BAFD6ULL,
		0xFBCBC00A9C700406ULL,
		0x037AD86EA757E8CCULL,
		0x2929DE608C1CF4FEULL,
		0xA7870748A8F447EAULL,
		0x117A07B779A9D567ULL
	}};
	printf("Test Case 321\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 321 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -321;
	} else {
		printf("Test Case 321 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA0B7E249B0A870A7ULL,
		0x602797026A014385ULL,
		0x8E5D483561048F51ULL,
		0x1F5968ABFDC60EBFULL,
		0xA11F5BD731C43590ULL,
		0xB8630BF6F755C09CULL,
		0xD5143DBB62375A16ULL,
		0x13926E5B1BAE3625ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x416FC4936150E14EULL,
		0xC04F2E04D402870BULL,
		0x1CBA906AC2091EA2ULL,
		0x3EB2D157FB8C1D7FULL,
		0x423EB7AE63886B20ULL,
		0x70C617EDEEAB8139ULL,
		0xAA287B76C46EB42DULL,
		0x2724DCB6375C6C4BULL
	}};
	printf("Test Case 322\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 322 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -322;
	} else {
		printf("Test Case 322 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDFD8DA43AEAAE78CULL,
		0x8AA01C9FA6DD32ACULL,
		0xDB8C7E18A32CBCF1ULL,
		0x720DCA6D584BD18BULL,
		0xE6777F491CAADB65ULL,
		0x061948D0517C6DD0ULL,
		0x3AF476C643642742ULL,
		0x30648D70FD36E5C2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBFB1B4875D55CF18ULL,
		0x1540393F4DBA6559ULL,
		0xB718FC31465979E3ULL,
		0xE41B94DAB097A317ULL,
		0xCCEEFE923955B6CAULL,
		0x0C3291A0A2F8DBA1ULL,
		0x75E8ED8C86C84E84ULL,
		0x60C91AE1FA6DCB84ULL
	}};
	printf("Test Case 323\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 323 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -323;
	} else {
		printf("Test Case 323 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x646C5375C8D5BEEAULL,
		0x00EC0092F4F69D84ULL,
		0xE2413DA2EFFB9786ULL,
		0x97326EF48BD5928DULL,
		0x800E5A4CF44F587AULL,
		0x492627BA4DCE15AAULL,
		0xE7ADD96CFBFCBE1BULL,
		0x310B1D2FE9867F92ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC8D8A6EB91AB7DD4ULL,
		0x01D80125E9ED3B08ULL,
		0xC4827B45DFF72F0CULL,
		0x2E64DDE917AB251BULL,
		0x001CB499E89EB0F5ULL,
		0x924C4F749B9C2B55ULL,
		0xCF5BB2D9F7F97C36ULL,
		0x62163A5FD30CFF25ULL
	}};
	printf("Test Case 324\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 324 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -324;
	} else {
		printf("Test Case 324 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA2D6D943A3600E2FULL,
		0xC09620CD794E323BULL,
		0x1B9CBB8C193C3E1AULL,
		0x30DB4484B575C76BULL,
		0x799E091BA3CB9578ULL,
		0x903BF7983D9289FBULL,
		0x19187574C64F6323ULL,
		0x2FCECC7159E3553BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x45ADB28746C01C5EULL,
		0x812C419AF29C6477ULL,
		0x3739771832787C35ULL,
		0x61B689096AEB8ED6ULL,
		0xF33C123747972AF0ULL,
		0x2077EF307B2513F6ULL,
		0x3230EAE98C9EC647ULL,
		0x5F9D98E2B3C6AA76ULL
	}};
	printf("Test Case 325\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 325 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -325;
	} else {
		printf("Test Case 325 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5C03DCB0D9CB1565ULL,
		0xDB32697020219896ULL,
		0x8B23E27766A017D3ULL,
		0xE6817A8CA7379F9DULL,
		0xC302EE794567DED0ULL,
		0x9D2ABC40FE9FDD6CULL,
		0x73D00B5A4DEF2F07ULL,
		0x0491E2E0034383F7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB807B961B3962ACAULL,
		0xB664D2E04043312CULL,
		0x1647C4EECD402FA7ULL,
		0xCD02F5194E6F3F3BULL,
		0x8605DCF28ACFBDA1ULL,
		0x3A557881FD3FBAD9ULL,
		0xE7A016B49BDE5E0FULL,
		0x0923C5C0068707EEULL
	}};
	printf("Test Case 326\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 326 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -326;
	} else {
		printf("Test Case 326 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x99149D8E4216D5BDULL,
		0x49E805E6BBF90F8AULL,
		0xE800C5568FAC6F2CULL,
		0xEBAF3FBE17E37F96ULL,
		0xCF3AF467CC56B0B8ULL,
		0xC256387104BE195EULL,
		0x55587A8AFF478752ULL,
		0x36AF035061150B17ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x32293B1C842DAB7AULL,
		0x93D00BCD77F21F15ULL,
		0xD0018AAD1F58DE58ULL,
		0xD75E7F7C2FC6FF2DULL,
		0x9E75E8CF98AD6171ULL,
		0x84AC70E2097C32BDULL,
		0xAAB0F515FE8F0EA5ULL,
		0x6D5E06A0C22A162EULL
	}};
	printf("Test Case 327\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 327 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -327;
	} else {
		printf("Test Case 327 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x593B3F690BA3A3E7ULL,
		0xCCED081EB0BC6820ULL,
		0x35A907E25EB1C3A1ULL,
		0xB6FA23866EE8FD9CULL,
		0xA8A2A41AE3022FB1ULL,
		0xF48C1F5CAB987396ULL,
		0x0F7EC12C4385C377ULL,
		0x13B0EE6103E37EC9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB2767ED2174747CEULL,
		0x99DA103D6178D040ULL,
		0x6B520FC4BD638743ULL,
		0x6DF4470CDDD1FB38ULL,
		0x51454835C6045F63ULL,
		0xE9183EB95730E72DULL,
		0x1EFD8258870B86EFULL,
		0x2761DCC207C6FD92ULL
	}};
	printf("Test Case 328\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 328 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -328;
	} else {
		printf("Test Case 328 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6E7E77C07C99E9DDULL,
		0x2D776AFF40E16CABULL,
		0x79E58731D1411AB8ULL,
		0x1034A903F938538BULL,
		0x2344D3755186D82BULL,
		0xE4311137BAE1E385ULL,
		0x5C34119044E2E37DULL,
		0x3D0E11FEAD0719E8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDCFCEF80F933D3BAULL,
		0x5AEED5FE81C2D956ULL,
		0xF3CB0E63A2823570ULL,
		0x20695207F270A716ULL,
		0x4689A6EAA30DB056ULL,
		0xC862226F75C3C70AULL,
		0xB868232089C5C6FBULL,
		0x7A1C23FD5A0E33D0ULL
	}};
	printf("Test Case 329\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 329 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -329;
	} else {
		printf("Test Case 329 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6D98060444B78ABDULL,
		0x7A4D326FBA091A1FULL,
		0x56554B1042219277ULL,
		0x10DB72957CC3EB2FULL,
		0x5EC6B8B914B8B521ULL,
		0x223F5E22AF62F809ULL,
		0x9EC8DEF075752B8BULL,
		0x24FA16D80DEAD582ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDB300C08896F157AULL,
		0xF49A64DF7412343EULL,
		0xACAA9620844324EEULL,
		0x21B6E52AF987D65EULL,
		0xBD8D717229716A42ULL,
		0x447EBC455EC5F012ULL,
		0x3D91BDE0EAEA5716ULL,
		0x49F42DB01BD5AB05ULL
	}};
	printf("Test Case 330\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 330 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -330;
	} else {
		printf("Test Case 330 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB69CC4D46902082CULL,
		0x3BCFA1AD9C673B8EULL,
		0x708954E397EC246DULL,
		0x839EDC9C91C7B7A1ULL,
		0x7C80B414AAAC3027ULL,
		0x837BA8F2B72E0757ULL,
		0xEF10C0B40F861272ULL,
		0x38744CBAA20495DBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6D3989A8D2041058ULL,
		0x779F435B38CE771DULL,
		0xE112A9C72FD848DAULL,
		0x073DB939238F6F42ULL,
		0xF90168295558604FULL,
		0x06F751E56E5C0EAEULL,
		0xDE2181681F0C24E5ULL,
		0x70E8997544092BB7ULL
	}};
	printf("Test Case 331\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 331 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -331;
	} else {
		printf("Test Case 331 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3860BF16DDC87840ULL,
		0x1EB443735584F88DULL,
		0x5E22A61EEAA559E0ULL,
		0xFBA55DA0F687E91CULL,
		0xFCEFDB07B57F4BFAULL,
		0x6BCCB402FE732DFEULL,
		0x81B873F2CE07D11DULL,
		0x19F810BD2AE7253AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x70C17E2DBB90F080ULL,
		0x3D6886E6AB09F11AULL,
		0xBC454C3DD54AB3C0ULL,
		0xF74ABB41ED0FD238ULL,
		0xF9DFB60F6AFE97F5ULL,
		0xD7996805FCE65BFDULL,
		0x0370E7E59C0FA23AULL,
		0x33F0217A55CE4A75ULL
	}};
	printf("Test Case 332\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 332 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -332;
	} else {
		printf("Test Case 332 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x81FEFE8B73617EDAULL,
		0x12DC1941C9E40861ULL,
		0xAF98C877FB1121BEULL,
		0xD572C552DB1AAC19ULL,
		0x392F251780B46ED2ULL,
		0x9A95F41399507A1FULL,
		0xBAB9447DCC422C7EULL,
		0x0ECF8745B63AA4C8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x03FDFD16E6C2FDB4ULL,
		0x25B8328393C810C3ULL,
		0x5F3190EFF622437CULL,
		0xAAE58AA5B6355833ULL,
		0x725E4A2F0168DDA5ULL,
		0x352BE82732A0F43EULL,
		0x757288FB988458FDULL,
		0x1D9F0E8B6C754991ULL
	}};
	printf("Test Case 333\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 333 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -333;
	} else {
		printf("Test Case 333 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB74C309CC75AD8E3ULL,
		0x63597CBED4D1A2DCULL,
		0xD0EB6832212A27E1ULL,
		0x400BF2B25FB49C5AULL,
		0x9B7A2C2BDAEB4DAFULL,
		0x9ECFCC5EAC6DA4B8ULL,
		0xB7655FD5A6901553ULL,
		0x324EA7D0DCD91F0CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6E9861398EB5B1C6ULL,
		0xC6B2F97DA9A345B9ULL,
		0xA1D6D06442544FC2ULL,
		0x8017E564BF6938B5ULL,
		0x36F45857B5D69B5EULL,
		0x3D9F98BD58DB4971ULL,
		0x6ECABFAB4D202AA7ULL,
		0x649D4FA1B9B23E19ULL
	}};
	printf("Test Case 334\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 334 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -334;
	} else {
		printf("Test Case 334 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD8BAD714497AC2E7ULL,
		0xFEF557941C25FB36ULL,
		0xF85A4524796C208CULL,
		0x3E8766C25B7832E4ULL,
		0x1907998D5829EE46ULL,
		0x3078C26AEA815806ULL,
		0xA6DD456998ED0EF7ULL,
		0x25EE58B362A5D1B8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB175AE2892F585CEULL,
		0xFDEAAF28384BF66DULL,
		0xF0B48A48F2D84119ULL,
		0x7D0ECD84B6F065C9ULL,
		0x320F331AB053DC8CULL,
		0x60F184D5D502B00CULL,
		0x4DBA8AD331DA1DEEULL,
		0x4BDCB166C54BA371ULL
	}};
	printf("Test Case 335\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 335 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -335;
	} else {
		printf("Test Case 335 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x524D1B3D29678C28ULL,
		0x565D02320F65226DULL,
		0xF279DE700B4D2F7BULL,
		0x6A63A6C5C4DD9633ULL,
		0xCF165F21A31A854CULL,
		0x3BC68F8490BFAE9DULL,
		0xCD1C480888CCE1E8ULL,
		0x05C541469CF195C3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA49A367A52CF1850ULL,
		0xACBA04641ECA44DAULL,
		0xE4F3BCE0169A5EF6ULL,
		0xD4C74D8B89BB2C67ULL,
		0x9E2CBE4346350A98ULL,
		0x778D1F09217F5D3BULL,
		0x9A3890111199C3D0ULL,
		0x0B8A828D39E32B87ULL
	}};
	printf("Test Case 336\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 336 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -336;
	} else {
		printf("Test Case 336 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0A24AE7123AECE03ULL,
		0xEEB614D732409E3BULL,
		0x763ADE2E4715A8EAULL,
		0x6A7B60A654FD9CB5ULL,
		0x07533657051E7D42ULL,
		0x52BD6F80F26CE1C2ULL,
		0x27D3C5405E38CE1BULL,
		0x3A6A8AB114457657ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x14495CE2475D9C06ULL,
		0xDD6C29AE64813C76ULL,
		0xEC75BC5C8E2B51D5ULL,
		0xD4F6C14CA9FB396AULL,
		0x0EA66CAE0A3CFA84ULL,
		0xA57ADF01E4D9C384ULL,
		0x4FA78A80BC719C36ULL,
		0x74D51562288AECAEULL
	}};
	printf("Test Case 337\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 337 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -337;
	} else {
		printf("Test Case 337 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x77A46B509AD6192FULL,
		0x8906325EE7291049ULL,
		0x3572031449D94BE9ULL,
		0xB1C9FADA7E52E6B9ULL,
		0xFD2AB59663CB9334ULL,
		0x709CD4B65D2117A2ULL,
		0x8DCDE8DA2A94AC31ULL,
		0x258A2A7321517FE3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEF48D6A135AC325EULL,
		0x120C64BDCE522092ULL,
		0x6AE4062893B297D3ULL,
		0x6393F5B4FCA5CD72ULL,
		0xFA556B2CC7972669ULL,
		0xE139A96CBA422F45ULL,
		0x1B9BD1B455295862ULL,
		0x4B1454E642A2FFC7ULL
	}};
	printf("Test Case 338\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 338 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -338;
	} else {
		printf("Test Case 338 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1A49B62D398D4094ULL,
		0x12C9614479BF08F3ULL,
		0x0A6024A4F936C6F4ULL,
		0x809D348F2F7DA406ULL,
		0x5D2F84443B325AF9ULL,
		0x05210744C8A44CA3ULL,
		0x68E006BF5B3DB0AAULL,
		0x069B1E83E33F118CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x34936C5A731A8128ULL,
		0x2592C288F37E11E6ULL,
		0x14C04949F26D8DE8ULL,
		0x013A691E5EFB480CULL,
		0xBA5F08887664B5F3ULL,
		0x0A420E8991489946ULL,
		0xD1C00D7EB67B6154ULL,
		0x0D363D07C67E2318ULL
	}};
	printf("Test Case 339\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 339 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -339;
	} else {
		printf("Test Case 339 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3AFD500529541749ULL,
		0x25FEE3828A37DF61ULL,
		0x7DB1AE0A413D633AULL,
		0xDB3A954A4DFD5D65ULL,
		0xDB96658E357C52B5ULL,
		0x79C74B4AC1BE78DBULL,
		0xB94E3700970ABDF8ULL,
		0x19CC53DC74EF16DCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x75FAA00A52A82E92ULL,
		0x4BFDC705146FBEC2ULL,
		0xFB635C14827AC674ULL,
		0xB6752A949BFABACAULL,
		0xB72CCB1C6AF8A56BULL,
		0xF38E9695837CF1B7ULL,
		0x729C6E012E157BF0ULL,
		0x3398A7B8E9DE2DB9ULL
	}};
	printf("Test Case 340\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 340 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -340;
	} else {
		printf("Test Case 340 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x94BD273330BE75C2ULL,
		0xC76EB40DC15667E8ULL,
		0x3CF2064867832939ULL,
		0x1577B181CADE9CFEULL,
		0xBF0916ADDD67841EULL,
		0xF22728389F711951ULL,
		0x2DE78B6ECA72B778ULL,
		0x22CA2A02DFE6BE80ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x297A4E66617CEB84ULL,
		0x8EDD681B82ACCFD1ULL,
		0x79E40C90CF065273ULL,
		0x2AEF630395BD39FCULL,
		0x7E122D5BBACF083CULL,
		0xE44E50713EE232A3ULL,
		0x5BCF16DD94E56EF1ULL,
		0x45945405BFCD7D00ULL
	}};
	printf("Test Case 341\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 341 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -341;
	} else {
		printf("Test Case 341 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDB906F4D10F31F88ULL,
		0xD2789271C73ACA96ULL,
		0x9AEF22FBFC71BB2DULL,
		0x09F793D5108C6D6DULL,
		0x805FCBE4857DAC0CULL,
		0xF13AE1DDECC8103BULL,
		0x3DDDEBD15C6BA990ULL,
		0x1B772B2FEFC05062ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB720DE9A21E63F10ULL,
		0xA4F124E38E75952DULL,
		0x35DE45F7F8E3765BULL,
		0x13EF27AA2118DADBULL,
		0x00BF97C90AFB5818ULL,
		0xE275C3BBD9902077ULL,
		0x7BBBD7A2B8D75321ULL,
		0x36EE565FDF80A0C4ULL
	}};
	printf("Test Case 342\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 342 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -342;
	} else {
		printf("Test Case 342 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD8590442ED6DDDBEULL,
		0xB29419640F94E9D8ULL,
		0x8BC4316D02359537ULL,
		0x86C95DDA256E9CD5ULL,
		0xF7BAE17452032B29ULL,
		0x4C1BE4B88D5B4E7BULL,
		0x14BE7E0B7F60849BULL,
		0x36ADEC384E615F52ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB0B20885DADBBB7CULL,
		0x652832C81F29D3B1ULL,
		0x178862DA046B2A6FULL,
		0x0D92BBB44ADD39ABULL,
		0xEF75C2E8A4065653ULL,
		0x9837C9711AB69CF7ULL,
		0x297CFC16FEC10936ULL,
		0x6D5BD8709CC2BEA4ULL
	}};
	printf("Test Case 343\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 343 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -343;
	} else {
		printf("Test Case 343 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x30E955F820DD57FCULL,
		0x0870F173C996D1BDULL,
		0xCE726CB8D18E466BULL,
		0x3231A5F4DCDE8A4CULL,
		0x12DE4D1D4D45786AULL,
		0x342B6ECC330096ADULL,
		0xCB57C2303F74E5ADULL,
		0x3931C99407D8B69BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x61D2ABF041BAAFF8ULL,
		0x10E1E2E7932DA37AULL,
		0x9CE4D971A31C8CD6ULL,
		0x64634BE9B9BD1499ULL,
		0x25BC9A3A9A8AF0D4ULL,
		0x6856DD9866012D5AULL,
		0x96AF84607EE9CB5AULL,
		0x726393280FB16D37ULL
	}};
	printf("Test Case 344\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 344 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -344;
	} else {
		printf("Test Case 344 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC23049EC3FEE6208ULL,
		0x982237CCC1157E97ULL,
		0x831CC0F212731707ULL,
		0xE71FC8BA89650170ULL,
		0xF35B33FADC0418EDULL,
		0x526A2C2F0A2C1C34ULL,
		0x2A359C26238CFBD6ULL,
		0x2602F0B1C0F723C8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x846093D87FDCC410ULL,
		0x30446F99822AFD2FULL,
		0x063981E424E62E0FULL,
		0xCE3F917512CA02E1ULL,
		0xE6B667F5B80831DBULL,
		0xA4D4585E14583869ULL,
		0x546B384C4719F7ACULL,
		0x4C05E16381EE4790ULL
	}};
	printf("Test Case 345\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 345 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -345;
	} else {
		printf("Test Case 345 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD40A42114F82EDC6ULL,
		0xA0E1D4E5934CBF79ULL,
		0x9F7E2378B44CE55EULL,
		0x98B5EEA1BEC71548ULL,
		0x5241F52358750436ULL,
		0x9960557C787CF303ULL,
		0x80ED4A7A968C5822ULL,
		0x27ABFE9EA51336B3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA81484229F05DB8CULL,
		0x41C3A9CB26997EF3ULL,
		0x3EFC46F16899CABDULL,
		0x316BDD437D8E2A91ULL,
		0xA483EA46B0EA086DULL,
		0x32C0AAF8F0F9E606ULL,
		0x01DA94F52D18B045ULL,
		0x4F57FD3D4A266D67ULL
	}};
	printf("Test Case 346\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 346 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -346;
	} else {
		printf("Test Case 346 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x06FA9B90EB7928B1ULL,
		0x50624FD1B4037DDFULL,
		0x607482F134BFFB5CULL,
		0xBCD931817FA3FEEAULL,
		0xB1CE07FCF5008DBEULL,
		0xB5FADA127FE691DCULL,
		0xDFC25F5A6FFD3715ULL,
		0x1D93B9FDD4E65022ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0DF53721D6F25162ULL,
		0xA0C49FA36806FBBEULL,
		0xC0E905E2697FF6B8ULL,
		0x79B26302FF47FDD4ULL,
		0x639C0FF9EA011B7DULL,
		0x6BF5B424FFCD23B9ULL,
		0xBF84BEB4DFFA6E2BULL,
		0x3B2773FBA9CCA045ULL
	}};
	printf("Test Case 347\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 347 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -347;
	} else {
		printf("Test Case 347 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x38F8458FD688934DULL,
		0x907A232AF412A3FFULL,
		0x70C624995896A6FDULL,
		0xD071F538F9F344FBULL,
		0xD0E4488CB1417DA9ULL,
		0x8164CC404DA131A8ULL,
		0x4F91B513D2A2DE33ULL,
		0x2D2E90770BA28D7CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x71F08B1FAD11269AULL,
		0x20F44655E82547FEULL,
		0xE18C4932B12D4DFBULL,
		0xA0E3EA71F3E689F6ULL,
		0xA1C891196282FB53ULL,
		0x02C998809B426351ULL,
		0x9F236A27A545BC67ULL,
		0x5A5D20EE17451AF8ULL
	}};
	printf("Test Case 348\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 348 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -348;
	} else {
		printf("Test Case 348 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7BE08070709545CEULL,
		0x1DF924F7DB01D09FULL,
		0x086DD1870D3B97E9ULL,
		0x0C522A0A91A04B99ULL,
		0x4A4D75C6260BF4C0ULL,
		0x6F5B98A2A4F5A13FULL,
		0x3740CFE0521D6C5BULL,
		0x290209C6702B3C14ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF7C100E0E12A8B9CULL,
		0x3BF249EFB603A13EULL,
		0x10DBA30E1A772FD2ULL,
		0x18A4541523409732ULL,
		0x949AEB8C4C17E980ULL,
		0xDEB7314549EB427EULL,
		0x6E819FC0A43AD8B6ULL,
		0x5204138CE0567828ULL
	}};
	printf("Test Case 349\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 349 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -349;
	} else {
		printf("Test Case 349 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD7A44ABD7D6F7651ULL,
		0x070E8E231B72CD0AULL,
		0x4746CB60D55C252DULL,
		0x4E38D96F021C68D0ULL,
		0xB9E09ECEBAE5A460ULL,
		0xE3CB26CC714E1AA0ULL,
		0x60871A7B629CEDA8ULL,
		0x3D8828765DD5C00CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF48957AFADEECA2ULL,
		0x0E1D1C4636E59A15ULL,
		0x8E8D96C1AAB84A5AULL,
		0x9C71B2DE0438D1A0ULL,
		0x73C13D9D75CB48C0ULL,
		0xC7964D98E29C3541ULL,
		0xC10E34F6C539DB51ULL,
		0x7B1050ECBBAB8018ULL
	}};
	printf("Test Case 350\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 350 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -350;
	} else {
		printf("Test Case 350 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2385CB5E9004BD8FULL,
		0xD2CD8680A5AF4298ULL,
		0xA5A3AA8A30F2019EULL,
		0xD4B27B50F5209319ULL,
		0x7D02941623631D93ULL,
		0xDAAE7858A6C775E5ULL,
		0x608BCAFB48A97615ULL,
		0x0ABD2498B12AE220ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x470B96BD20097B1EULL,
		0xA59B0D014B5E8530ULL,
		0x4B47551461E4033DULL,
		0xA964F6A1EA412633ULL,
		0xFA05282C46C63B27ULL,
		0xB55CF0B14D8EEBCAULL,
		0xC11795F69152EC2BULL,
		0x157A49316255C440ULL
	}};
	printf("Test Case 351\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 351 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -351;
	} else {
		printf("Test Case 351 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x93CC22942F3AB37CULL,
		0x81887953D933E703ULL,
		0x25A371103C3D584BULL,
		0x0AAD8282F875C0F1ULL,
		0xAFBBDCBB572E8442ULL,
		0x9D7E24E0EE70D6A2ULL,
		0xAF02DD006B5CBA35ULL,
		0x2C4AC58F314B5667ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x279845285E7566F8ULL,
		0x0310F2A7B267CE07ULL,
		0x4B46E220787AB097ULL,
		0x155B0505F0EB81E2ULL,
		0x5F77B976AE5D0884ULL,
		0x3AFC49C1DCE1AD45ULL,
		0x5E05BA00D6B9746BULL,
		0x58958B1E6296ACCFULL
	}};
	printf("Test Case 352\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 352 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -352;
	} else {
		printf("Test Case 352 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7C1A4CC2E0EAE9FCULL,
		0x4F5B347F8AEB145FULL,
		0x3F76FA34FCC0C93BULL,
		0x86CB73A296BEC7BBULL,
		0x37D4EFBDB0BD3B99ULL,
		0x079471602A63F990ULL,
		0x6D455D6D930507DCULL,
		0x249CF4D2D5A89928ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF8349985C1D5D3F8ULL,
		0x9EB668FF15D628BEULL,
		0x7EEDF469F9819276ULL,
		0x0D96E7452D7D8F76ULL,
		0x6FA9DF7B617A7733ULL,
		0x0F28E2C054C7F320ULL,
		0xDA8ABADB260A0FB8ULL,
		0x4939E9A5AB513250ULL
	}};
	printf("Test Case 353\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 353 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -353;
	} else {
		printf("Test Case 353 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE79487A566E35505ULL,
		0x2BF921E5B5516E2EULL,
		0xAC32B3430743EBDDULL,
		0x2AD9E3CFBC05AF14ULL,
		0x63B66C084526BA93ULL,
		0x1B029D13DA6B581FULL,
		0x84ECBBEA7B5D24AFULL,
		0x3481DBFB64158B2AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCF290F4ACDC6AA0AULL,
		0x57F243CB6AA2DC5DULL,
		0x586566860E87D7BAULL,
		0x55B3C79F780B5E29ULL,
		0xC76CD8108A4D7526ULL,
		0x36053A27B4D6B03EULL,
		0x09D977D4F6BA495EULL,
		0x6903B7F6C82B1655ULL
	}};
	printf("Test Case 354\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 354 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -354;
	} else {
		printf("Test Case 354 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x160E7C88C7D15ACCULL,
		0xDB97643AD045C563ULL,
		0xAA44C6EDA16E28BAULL,
		0x7D640F8E1FD90217ULL,
		0xDE235E12F234B320ULL,
		0x20027B99C38A66DDULL,
		0xA2CE179C354DB322ULL,
		0x303288E80C171912ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2C1CF9118FA2B598ULL,
		0xB72EC875A08B8AC6ULL,
		0x54898DDB42DC5175ULL,
		0xFAC81F1C3FB2042FULL,
		0xBC46BC25E4696640ULL,
		0x4004F7338714CDBBULL,
		0x459C2F386A9B6644ULL,
		0x606511D0182E3225ULL
	}};
	printf("Test Case 355\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 355 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -355;
	} else {
		printf("Test Case 355 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0BED839F19C0631DULL,
		0x83210F9E4621176EULL,
		0x4D19C17E45A72479ULL,
		0xC797894D81B8B022ULL,
		0x9CFEF644A505A117ULL,
		0x99E9E8AF4F4595D0ULL,
		0x7D4AF407CD232322ULL,
		0x2F583888388602ADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x17DB073E3380C63AULL,
		0x06421F3C8C422EDCULL,
		0x9A3382FC8B4E48F3ULL,
		0x8F2F129B03716044ULL,
		0x39FDEC894A0B422FULL,
		0x33D3D15E9E8B2BA1ULL,
		0xFA95E80F9A464645ULL,
		0x5EB07110710C055AULL
	}};
	printf("Test Case 356\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 356 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -356;
	} else {
		printf("Test Case 356 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x49887BE6F39740F4ULL,
		0xD005C2CBE418AC15ULL,
		0xDB689E6BBDE199E5ULL,
		0x2FE213AC39817ED2ULL,
		0x30C3BF884E20B0B9ULL,
		0x8F04B25780A3CEF0ULL,
		0xD8F48A1E92D934E6ULL,
		0x0D64AF6630092D8AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9310F7CDE72E81E8ULL,
		0xA00B8597C831582AULL,
		0xB6D13CD77BC333CBULL,
		0x5FC427587302FDA5ULL,
		0x61877F109C416172ULL,
		0x1E0964AF01479DE0ULL,
		0xB1E9143D25B269CDULL,
		0x1AC95ECC60125B15ULL
	}};
	printf("Test Case 357\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 357 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -357;
	} else {
		printf("Test Case 357 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB7A663BA2F6C9306ULL,
		0xD7C2DAB275FD0F1BULL,
		0xEE9ACFB47ED50C44ULL,
		0x6E8F31E0DE60D889ULL,
		0x4468971C02F97288ULL,
		0x0544A507CD094766ULL,
		0xE8E3B4357A614BCDULL,
		0x273DC60BE0EADE5FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6F4CC7745ED9260CULL,
		0xAF85B564EBFA1E37ULL,
		0xDD359F68FDAA1889ULL,
		0xDD1E63C1BCC1B113ULL,
		0x88D12E3805F2E510ULL,
		0x0A894A0F9A128ECCULL,
		0xD1C7686AF4C2979AULL,
		0x4E7B8C17C1D5BCBFULL
	}};
	printf("Test Case 358\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 358 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -358;
	} else {
		printf("Test Case 358 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4F26B4EF8F51EA7EULL,
		0x28AC0A3ABAFB6894ULL,
		0x1890FB1611163C42ULL,
		0x75B90D3076150E61ULL,
		0x7D03D701F1BF324CULL,
		0x97EF290F2378FB25ULL,
		0xD2C2AF0BDE4B7E71ULL,
		0x0071A4CDBE7129F3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9E4D69DF1EA3D4FCULL,
		0x5158147575F6D128ULL,
		0x3121F62C222C7884ULL,
		0xEB721A60EC2A1CC2ULL,
		0xFA07AE03E37E6498ULL,
		0x2FDE521E46F1F64AULL,
		0xA5855E17BC96FCE3ULL,
		0x00E3499B7CE253E7ULL
	}};
	printf("Test Case 359\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 359 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -359;
	} else {
		printf("Test Case 359 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x613115BD02F4CE22ULL,
		0x996DBA017E501CFCULL,
		0x8179F2720660A6D5ULL,
		0xA887E663BD24712AULL,
		0x3E677D9EB0295FC8ULL,
		0x8B37E61A4CD88BF0ULL,
		0x5757FB8AF59A8736ULL,
		0x0D1D22B4A7662D94ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC2622B7A05E99C44ULL,
		0x32DB7402FCA039F8ULL,
		0x02F3E4E40CC14DABULL,
		0x510FCCC77A48E255ULL,
		0x7CCEFB3D6052BF91ULL,
		0x166FCC3499B117E0ULL,
		0xAEAFF715EB350E6DULL,
		0x1A3A45694ECC5B28ULL
	}};
	printf("Test Case 360\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 360 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -360;
	} else {
		printf("Test Case 360 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA718FBF3349A4E1CULL,
		0x3ED71252CB464845ULL,
		0xEC1102BC072193FEULL,
		0x0C7FB1DC475655ABULL,
		0x99B49CC225C09B1DULL,
		0x82E735CA0319F506ULL,
		0x5C5F659C463303FCULL,
		0x34F328B06A16D05FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4E31F7E669349C38ULL,
		0x7DAE24A5968C908BULL,
		0xD82205780E4327FCULL,
		0x18FF63B88EACAB57ULL,
		0x336939844B81363AULL,
		0x05CE6B940633EA0DULL,
		0xB8BECB388C6607F9ULL,
		0x69E65160D42DA0BEULL
	}};
	printf("Test Case 361\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 361 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -361;
	} else {
		printf("Test Case 361 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8A497B8D0F3150FCULL,
		0x8772C1AEBC41E7AEULL,
		0x533CF8F164DFBF72ULL,
		0x8A28CDB5D9AA36E0ULL,
		0x2C3E0C8F1C50A9D6ULL,
		0x4608CA3F54BDF069ULL,
		0x8A76B993B4478410ULL,
		0x2E61C5D5ADC37973ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1492F71A1E62A1F8ULL,
		0x0EE5835D7883CF5DULL,
		0xA679F1E2C9BF7EE5ULL,
		0x14519B6BB3546DC0ULL,
		0x587C191E38A153ADULL,
		0x8C11947EA97BE0D2ULL,
		0x14ED7327688F0820ULL,
		0x5CC38BAB5B86F2E7ULL
	}};
	printf("Test Case 362\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 362 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -362;
	} else {
		printf("Test Case 362 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x43C21631B4FCB77FULL,
		0x91C6B7A64E7BA233ULL,
		0xF258CBBCC013B5DCULL,
		0x579C4BB49869B946ULL,
		0x457CBCCB5DA9C811ULL,
		0x12EC808B5B2579EEULL,
		0xB9CAD84976CA8B64ULL,
		0x0E55EB5E2E30E7E3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x87842C6369F96EFEULL,
		0x238D6F4C9CF74466ULL,
		0xE4B1977980276BB9ULL,
		0xAF38976930D3728DULL,
		0x8AF97996BB539022ULL,
		0x25D90116B64AF3DCULL,
		0x7395B092ED9516C8ULL,
		0x1CABD6BC5C61CFC7ULL
	}};
	printf("Test Case 363\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 363 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -363;
	} else {
		printf("Test Case 363 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1D0E296995EEE230ULL,
		0xF3EE7C9BE664D2BCULL,
		0x8DB71020F9186767ULL,
		0xD2F44FCB721ACEF6ULL,
		0x8F100D1CD70CB9CCULL,
		0x886E2D9ADE7FA47CULL,
		0xB57FFACD8930E7E3ULL,
		0x1CAB077BC60B7570ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3A1C52D32BDDC460ULL,
		0xE7DCF937CCC9A578ULL,
		0x1B6E2041F230CECFULL,
		0xA5E89F96E4359DEDULL,
		0x1E201A39AE197399ULL,
		0x10DC5B35BCFF48F9ULL,
		0x6AFFF59B1261CFC7ULL,
		0x39560EF78C16EAE1ULL
	}};
	printf("Test Case 364\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 364 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -364;
	} else {
		printf("Test Case 364 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x260FE67CAF08A040ULL,
		0xEF0299B3F916E0C9ULL,
		0x3798A93DA3C106D0ULL,
		0x63D3B2D2D2946E00ULL,
		0x88B76DD9FC230ABFULL,
		0xD01BA2738452B724ULL,
		0x1197F062E593D065ULL,
		0x27459B79616BD5A0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4C1FCCF95E114080ULL,
		0xDE053367F22DC192ULL,
		0x6F31527B47820DA1ULL,
		0xC7A765A5A528DC00ULL,
		0x116EDBB3F846157EULL,
		0xA03744E708A56E49ULL,
		0x232FE0C5CB27A0CBULL,
		0x4E8B36F2C2D7AB40ULL
	}};
	printf("Test Case 365\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 365 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -365;
	} else {
		printf("Test Case 365 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6044CE88E1DC32C2ULL,
		0x1C085D5A293DFC5DULL,
		0x5619607E2824F30CULL,
		0x8608AB19635D6345ULL,
		0x72B4D239A7AE7A07ULL,
		0x664F549B1BA26EFAULL,
		0xF7BE0DF84FA7731BULL,
		0x0F7AF2E539DC9CB6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC0899D11C3B86584ULL,
		0x3810BAB4527BF8BAULL,
		0xAC32C0FC5049E618ULL,
		0x0C115632C6BAC68AULL,
		0xE569A4734F5CF40FULL,
		0xCC9EA9363744DDF4ULL,
		0xEF7C1BF09F4EE636ULL,
		0x1EF5E5CA73B9396DULL
	}};
	printf("Test Case 366\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 366 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -366;
	} else {
		printf("Test Case 366 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC5C3BDCBEE443002ULL,
		0xE204F74897D13E1BULL,
		0x8B79BBE130F4FABDULL,
		0xD94A62E8C6A81D1FULL,
		0x84FB66DBD45E5E2EULL,
		0x4AA55C1DC04F9BB5ULL,
		0x5E83A2B9D5207FF0ULL,
		0x1A0577A9FD5A97C9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8B877B97DC886004ULL,
		0xC409EE912FA27C37ULL,
		0x16F377C261E9F57BULL,
		0xB294C5D18D503A3FULL,
		0x09F6CDB7A8BCBC5DULL,
		0x954AB83B809F376BULL,
		0xBD074573AA40FFE0ULL,
		0x340AEF53FAB52F92ULL
	}};
	printf("Test Case 367\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 367 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -367;
	} else {
		printf("Test Case 367 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x28AE1CE0A522B9D2ULL,
		0x32E63A393B20214EULL,
		0x5069E58BA0440AF5ULL,
		0x8CED6ADAB41FC452ULL,
		0xFBC5E073730C5517ULL,
		0x61F6FBC510975581ULL,
		0x1448FA831B81740BULL,
		0x3A642A751AB6680DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x515C39C14A4573A4ULL,
		0x65CC74727640429CULL,
		0xA0D3CB17408815EAULL,
		0x19DAD5B5683F88A4ULL,
		0xF78BC0E6E618AA2FULL,
		0xC3EDF78A212EAB03ULL,
		0x2891F5063702E816ULL,
		0x74C854EA356CD01AULL
	}};
	printf("Test Case 368\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 368 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -368;
	} else {
		printf("Test Case 368 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE23C35AEA3F53154ULL,
		0xBF8C9864928101F9ULL,
		0x67C9374FAF17FCCCULL,
		0x9CDC8B58339538E2ULL,
		0xCE6BDE9A7885E5D9ULL,
		0x89F3033A2ACAB873ULL,
		0x98FB277D743558B6ULL,
		0x12116F15AD4FD64FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC4786B5D47EA62A8ULL,
		0x7F1930C9250203F3ULL,
		0xCF926E9F5E2FF999ULL,
		0x39B916B0672A71C4ULL,
		0x9CD7BD34F10BCBB3ULL,
		0x13E60674559570E7ULL,
		0x31F64EFAE86AB16DULL,
		0x2422DE2B5A9FAC9FULL
	}};
	printf("Test Case 369\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 369 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -369;
	} else {
		printf("Test Case 369 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x86CBB02E0BE635AFULL,
		0x73431CF6A8CABB8DULL,
		0xE75682DBC60CD18EULL,
		0x01C219265700786BULL,
		0x0798A1E464E906D1ULL,
		0xD72AF1955289611CULL,
		0xC1BE690AE6D71C3FULL,
		0x01245E95D5A18EBAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0D97605C17CC6B5EULL,
		0xE68639ED5195771BULL,
		0xCEAD05B78C19A31CULL,
		0x0384324CAE00F0D7ULL,
		0x0F3143C8C9D20DA2ULL,
		0xAE55E32AA512C238ULL,
		0x837CD215CDAE387FULL,
		0x0248BD2BAB431D75ULL
	}};
	printf("Test Case 370\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 370 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -370;
	} else {
		printf("Test Case 370 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x71471F2B64843E3AULL,
		0x885A4AAAC2C03F6EULL,
		0x99CE547E64DB98B0ULL,
		0x8470F8DAE348DAB5ULL,
		0xA4EF1D71D535B7ABULL,
		0x5931B47A1C0A546EULL,
		0x7932279529A52056ULL,
		0x376990FCDEA7CA38ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE28E3E56C9087C74ULL,
		0x10B4955585807EDCULL,
		0x339CA8FCC9B73161ULL,
		0x08E1F1B5C691B56BULL,
		0x49DE3AE3AA6B6F57ULL,
		0xB26368F43814A8DDULL,
		0xF2644F2A534A40ACULL,
		0x6ED321F9BD4F9470ULL
	}};
	printf("Test Case 371\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 371 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -371;
	} else {
		printf("Test Case 371 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4DF52BF9FA1B0596ULL,
		0xC63DAF262E1C1D49ULL,
		0x7C20808A0C7E78C4ULL,
		0x8967DE5E4C1D508BULL,
		0xE2151C382D15EAB0ULL,
		0x981B0207DA170D54ULL,
		0xC360849662D5EA53ULL,
		0x133F22BE623FE1F4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9BEA57F3F4360B2CULL,
		0x8C7B5E4C5C383A92ULL,
		0xF841011418FCF189ULL,
		0x12CFBCBC983AA116ULL,
		0xC42A38705A2BD561ULL,
		0x3036040FB42E1AA9ULL,
		0x86C1092CC5ABD4A7ULL,
		0x267E457CC47FC3E9ULL
	}};
	printf("Test Case 372\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 372 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -372;
	} else {
		printf("Test Case 372 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x67924C75B0890801ULL,
		0x59B1559A52DC54D8ULL,
		0x1FF19C8467C110D2ULL,
		0x697B2FDA78B2162CULL,
		0xC461ADEDDA8AD3AAULL,
		0xCF07EB10CF458F39ULL,
		0x17526EB2D6379083ULL,
		0x247D7732E70EF779ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCF2498EB61121002ULL,
		0xB362AB34A5B8A9B0ULL,
		0x3FE33908CF8221A4ULL,
		0xD2F65FB4F1642C58ULL,
		0x88C35BDBB515A754ULL,
		0x9E0FD6219E8B1E73ULL,
		0x2EA4DD65AC6F2107ULL,
		0x48FAEE65CE1DEEF2ULL
	}};
	printf("Test Case 373\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 373 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -373;
	} else {
		printf("Test Case 373 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEF0CEE734163B7FEULL,
		0x3825CA3D0F21D992ULL,
		0xF237F431B0C250D8ULL,
		0x04D89E14B4EC7D10ULL,
		0x7C920CDD72617052ULL,
		0x85FB2293BF8C999BULL,
		0xCFAC2BE542F1341DULL,
		0x2F275A834E34C942ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDE19DCE682C76FFCULL,
		0x704B947A1E43B325ULL,
		0xE46FE8636184A1B0ULL,
		0x09B13C2969D8FA21ULL,
		0xF92419BAE4C2E0A4ULL,
		0x0BF645277F193336ULL,
		0x9F5857CA85E2683BULL,
		0x5E4EB5069C699285ULL
	}};
	printf("Test Case 374\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 374 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -374;
	} else {
		printf("Test Case 374 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8DE9DAED619DCD26ULL,
		0xE699510146EC81AEULL,
		0x6C96267ACB6D2819ULL,
		0xEC769F6EA1C60BB1ULL,
		0x99DF8BD089391484ULL,
		0xA36D5AD2A821A531ULL,
		0x34BBE9180E71F554ULL,
		0x197CE14C29C77F25ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1BD3B5DAC33B9A4CULL,
		0xCD32A2028DD9035DULL,
		0xD92C4CF596DA5033ULL,
		0xD8ED3EDD438C1762ULL,
		0x33BF17A112722909ULL,
		0x46DAB5A550434A63ULL,
		0x6977D2301CE3EAA9ULL,
		0x32F9C298538EFE4AULL
	}};
	printf("Test Case 375\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 375 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -375;
	} else {
		printf("Test Case 375 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0CE95D3C085B1AE1ULL,
		0x01C0E617FFCE37B7ULL,
		0x0FF2BA4E2F4B8E54ULL,
		0xBEDB96B1BED17EDAULL,
		0x3125C36600E2E24EULL,
		0xAECC79B29C3D1C67ULL,
		0x4759C9FAD0CF2DA0ULL,
		0x3A934F652134D267ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x19D2BA7810B635C2ULL,
		0x0381CC2FFF9C6F6EULL,
		0x1FE5749C5E971CA8ULL,
		0x7DB72D637DA2FDB4ULL,
		0x624B86CC01C5C49DULL,
		0x5D98F365387A38CEULL,
		0x8EB393F5A19E5B41ULL,
		0x75269ECA4269A4CEULL
	}};
	printf("Test Case 376\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 376 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -376;
	} else {
		printf("Test Case 376 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9FA274A3FB9092F6ULL,
		0x666F6AD4074EC061ULL,
		0x676668EB01F9119BULL,
		0xE0BADCDC5E22470BULL,
		0x5316E625945AA252ULL,
		0x2D6977229153CF46ULL,
		0xCB677EAC36880DA2ULL,
		0x36BB33E792CBD7E0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3F44E947F72125ECULL,
		0xCCDED5A80E9D80C3ULL,
		0xCECCD1D603F22336ULL,
		0xC175B9B8BC448E16ULL,
		0xA62DCC4B28B544A5ULL,
		0x5AD2EE4522A79E8CULL,
		0x96CEFD586D101B44ULL,
		0x6D7667CF2597AFC1ULL
	}};
	printf("Test Case 377\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 377 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -377;
	} else {
		printf("Test Case 377 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3AC599D90734F720ULL,
		0xDC74550382564CC0ULL,
		0x94DC4DBE3FACEA96ULL,
		0x089B89149F0F10BEULL,
		0x992AEBFF7D465112ULL,
		0xC13C837B9165DD29ULL,
		0xC93245CEBC0B0E59ULL,
		0x3A256D011B6F3250ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x758B33B20E69EE40ULL,
		0xB8E8AA0704AC9980ULL,
		0x29B89B7C7F59D52DULL,
		0x113712293E1E217DULL,
		0x3255D7FEFA8CA224ULL,
		0x827906F722CBBA53ULL,
		0x92648B9D78161CB3ULL,
		0x744ADA0236DE64A1ULL
	}};
	printf("Test Case 378\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 378 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -378;
	} else {
		printf("Test Case 378 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA69BEAA203F081FAULL,
		0x840CBB3277CC7489ULL,
		0x5EBE6AAEF8B650E1ULL,
		0xBC82833CC691765CULL,
		0xF4EC6EC4D80416E6ULL,
		0x4DD7B3163DFC6304ULL,
		0x96CE6FB09051C6C0ULL,
		0x0938143124B63946ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4D37D54407E103F4ULL,
		0x08197664EF98E913ULL,
		0xBD7CD55DF16CA1C3ULL,
		0x790506798D22ECB8ULL,
		0xE9D8DD89B0082DCDULL,
		0x9BAF662C7BF8C609ULL,
		0x2D9CDF6120A38D80ULL,
		0x12702862496C728DULL
	}};
	printf("Test Case 379\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 379 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -379;
	} else {
		printf("Test Case 379 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0DEA7D57DBCC46FAULL,
		0x87B9A777D37C4917ULL,
		0x65775D6207B28ECFULL,
		0x756E4C3D922691BFULL,
		0xA2C6CD252FC69B7EULL,
		0xEC06531F28BF06ACULL,
		0xF378B97973BA37B1ULL,
		0x26BD9CF7464EDCF2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1BD4FAAFB7988DF4ULL,
		0x0F734EEFA6F8922EULL,
		0xCAEEBAC40F651D9FULL,
		0xEADC987B244D237EULL,
		0x458D9A4A5F8D36FCULL,
		0xD80CA63E517E0D59ULL,
		0xE6F172F2E7746F63ULL,
		0x4D7B39EE8C9DB9E5ULL
	}};
	printf("Test Case 380\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 380 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -380;
	} else {
		printf("Test Case 380 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD6685BBE80D3A1FEULL,
		0x4040F5DB6B0141D2ULL,
		0x925B8F17E9ABF1B8ULL,
		0x74AB8C8A426F7F86ULL,
		0x3441812839803E66ULL,
		0x0C2642BC389EA5DDULL,
		0xF2561333875CBDE1ULL,
		0x130419B1669C897FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xACD0B77D01A743FCULL,
		0x8081EBB6D60283A5ULL,
		0x24B71E2FD357E370ULL,
		0xE957191484DEFF0DULL,
		0x6883025073007CCCULL,
		0x184C8578713D4BBAULL,
		0xE4AC26670EB97BC2ULL,
		0x26083362CD3912FFULL
	}};
	printf("Test Case 381\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 381 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -381;
	} else {
		printf("Test Case 381 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE3B7C82C1A3DEAF5ULL,
		0x6CFBF8B002778E9DULL,
		0x8D4E279249716859ULL,
		0x8F7003E533909C50ULL,
		0xE0AEDBE1A9729100ULL,
		0x0959A3AAFDB2359BULL,
		0xD152265C359E723EULL,
		0x2DA5681A444C200CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC76F9058347BD5EAULL,
		0xD9F7F16004EF1D3BULL,
		0x1A9C4F2492E2D0B2ULL,
		0x1EE007CA672138A1ULL,
		0xC15DB7C352E52201ULL,
		0x12B34755FB646B37ULL,
		0xA2A44CB86B3CE47CULL,
		0x5B4AD03488984019ULL
	}};
	printf("Test Case 382\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 382 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -382;
	} else {
		printf("Test Case 382 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x266EB79E8FC1D549ULL,
		0x13AA244748C181F7ULL,
		0x7787CF8CE0965396ULL,
		0x5A6CCD86B825C47BULL,
		0x662659F8E5D38ED5ULL,
		0xE301AA005EBFAEEAULL,
		0xDE1FA7B0C4C6E84AULL,
		0x374F0633831AD630ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4CDD6F3D1F83AA92ULL,
		0x2754488E918303EEULL,
		0xEF0F9F19C12CA72CULL,
		0xB4D99B0D704B88F6ULL,
		0xCC4CB3F1CBA71DAAULL,
		0xC6035400BD7F5DD4ULL,
		0xBC3F4F61898DD095ULL,
		0x6E9E0C670635AC61ULL
	}};
	printf("Test Case 383\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 383 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -383;
	} else {
		printf("Test Case 383 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x03AB6E1FF6668D23ULL,
		0xDDAC1879847A23F2ULL,
		0x96684DF126FF1030ULL,
		0x9F35A9364EFE432EULL,
		0x39E6B404EE704E04ULL,
		0xB29DF2DFA558211AULL,
		0xE7C84DBF02CA6325ULL,
		0x089EA3B35DFE3083ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0756DC3FECCD1A46ULL,
		0xBB5830F308F447E4ULL,
		0x2CD09BE24DFE2061ULL,
		0x3E6B526C9DFC865DULL,
		0x73CD6809DCE09C09ULL,
		0x653BE5BF4AB04234ULL,
		0xCF909B7E0594C64BULL,
		0x113D4766BBFC6107ULL
	}};
	printf("Test Case 384\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 384 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -384;
	} else {
		printf("Test Case 384 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC5C27ABE2BE8D99FULL,
		0x4F1EB4F304FE9162ULL,
		0x9A0DA861858EFCC3ULL,
		0x58B9367D410BBDB8ULL,
		0xB649FC7BB62D36D6ULL,
		0x0CD62A1A9E465B8CULL,
		0x4BFB46E058047262ULL,
		0x00D22686466FDC4CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8B84F57C57D1B33EULL,
		0x9E3D69E609FD22C5ULL,
		0x341B50C30B1DF986ULL,
		0xB1726CFA82177B71ULL,
		0x6C93F8F76C5A6DACULL,
		0x19AC54353C8CB719ULL,
		0x97F68DC0B008E4C4ULL,
		0x01A44D0C8CDFB898ULL
	}};
	printf("Test Case 385\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 385 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -385;
	} else {
		printf("Test Case 385 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC95B7268ACAC5665ULL,
		0x4F373A6D4F251AF5ULL,
		0x6D3DBD804A438B2BULL,
		0x5B3CDDA2D93E2A7DULL,
		0xDFC2CF670F2CC84EULL,
		0xE50EA30ACEBC3857ULL,
		0x9EA04A342981E741ULL,
		0x273627D9DF0882F8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x92B6E4D15958ACCAULL,
		0x9E6E74DA9E4A35EBULL,
		0xDA7B7B0094871656ULL,
		0xB679BB45B27C54FAULL,
		0xBF859ECE1E59909CULL,
		0xCA1D46159D7870AFULL,
		0x3D4094685303CE83ULL,
		0x4E6C4FB3BE1105F1ULL
	}};
	printf("Test Case 386\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 386 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -386;
	} else {
		printf("Test Case 386 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF8674196A82AF7DCULL,
		0xF6C1A0B648DB1023ULL,
		0x71D6E0996CDCAFBBULL,
		0xBEC207676D272464ULL,
		0xF4C541186DB4B30FULL,
		0x039A412A5878A49FULL,
		0xF903A06273EC4EB5ULL,
		0x1E642685D2F4E614ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF0CE832D5055EFB8ULL,
		0xED83416C91B62047ULL,
		0xE3ADC132D9B95F77ULL,
		0x7D840ECEDA4E48C8ULL,
		0xE98A8230DB69661FULL,
		0x07348254B0F1493FULL,
		0xF20740C4E7D89D6AULL,
		0x3CC84D0BA5E9CC29ULL
	}};
	printf("Test Case 387\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 387 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -387;
	} else {
		printf("Test Case 387 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE37CE5C3922FF5E0ULL,
		0xD53751784AB6EED6ULL,
		0x1C5863BD1D375E33ULL,
		0xACAA2CAA40CB8509ULL,
		0xB2FCB815321402D3ULL,
		0x5C48F2B6374FDB02ULL,
		0xCA5C11601D91ACCCULL,
		0x24E53D10AD66FEF1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC6F9CB87245FEBC0ULL,
		0xAA6EA2F0956DDDADULL,
		0x38B0C77A3A6EBC67ULL,
		0x5954595481970A12ULL,
		0x65F9702A642805A7ULL,
		0xB891E56C6E9FB605ULL,
		0x94B822C03B235998ULL,
		0x49CA7A215ACDFDE3ULL
	}};
	printf("Test Case 388\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 388 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -388;
	} else {
		printf("Test Case 388 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x06DD1E5AEEFE9C52ULL,
		0xEDE82FCF07807B38ULL,
		0x17AD9415BCD4B7BAULL,
		0x5D19DCA8F200FC5EULL,
		0x2812E334BE3B670AULL,
		0xFA81C664CD5C15BBULL,
		0x28EF12FE235830DCULL,
		0x3C4A39F12F8CF60AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0DBA3CB5DDFD38A4ULL,
		0xDBD05F9E0F00F670ULL,
		0x2F5B282B79A96F75ULL,
		0xBA33B951E401F8BCULL,
		0x5025C6697C76CE14ULL,
		0xF5038CC99AB82B76ULL,
		0x51DE25FC46B061B9ULL,
		0x789473E25F19EC14ULL
	}};
	printf("Test Case 389\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 389 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -389;
	} else {
		printf("Test Case 389 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x277140F8412C5862ULL,
		0x894781BED1E95DEEULL,
		0x06606AB45E7F25A1ULL,
		0xC1224FAB0D910A74ULL,
		0xE525D30DA00B54D2ULL,
		0xC16498B9E7E56E0EULL,
		0x22C59925CEFC01BCULL,
		0x27A113BA483EEC29ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4EE281F08258B0C4ULL,
		0x128F037DA3D2BBDCULL,
		0x0CC0D568BCFE4B43ULL,
		0x82449F561B2214E8ULL,
		0xCA4BA61B4016A9A5ULL,
		0x82C93173CFCADC1DULL,
		0x458B324B9DF80379ULL,
		0x4F422774907DD852ULL
	}};
	printf("Test Case 390\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 390 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -390;
	} else {
		printf("Test Case 390 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8CD3B530D3EED624ULL,
		0x989770959B87613CULL,
		0xD4E0E7B5E57A1F60ULL,
		0x5EE60ED85D965937ULL,
		0xC5655AC5FC8115B1ULL,
		0x64ACF69E327F713BULL,
		0x36EEB3BA7C8073E9ULL,
		0x0E8D05FBCAEC1BB0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x19A76A61A7DDAC48ULL,
		0x312EE12B370EC279ULL,
		0xA9C1CF6BCAF43EC1ULL,
		0xBDCC1DB0BB2CB26FULL,
		0x8ACAB58BF9022B62ULL,
		0xC959ED3C64FEE277ULL,
		0x6DDD6774F900E7D2ULL,
		0x1D1A0BF795D83760ULL
	}};
	printf("Test Case 391\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 391 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -391;
	} else {
		printf("Test Case 391 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6F80BFC9635CD909ULL,
		0xB23C81A7AA76DD64ULL,
		0x10B41C726F717B49ULL,
		0xAC10FD6B6312029BULL,
		0x1B195D76F199E082ULL,
		0xE44656D54460A328ULL,
		0xC64C5B0B5102A2A2ULL,
		0x26F36B2D4247D8C7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDF017F92C6B9B212ULL,
		0x6479034F54EDBAC8ULL,
		0x216838E4DEE2F693ULL,
		0x5821FAD6C6240536ULL,
		0x3632BAEDE333C105ULL,
		0xC88CADAA88C14650ULL,
		0x8C98B616A2054545ULL,
		0x4DE6D65A848FB18FULL
	}};
	printf("Test Case 392\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 392 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -392;
	} else {
		printf("Test Case 392 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD60C297C4645FC7AULL,
		0x766D9D92FFA895CFULL,
		0x146C5C62FA71807FULL,
		0x29FB45DFC9D9F5F2ULL,
		0xF01FCDFD2ADC5484ULL,
		0x70A4BDF236526DE8ULL,
		0x311855A3B89424F2ULL,
		0x06EBC768279088F9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAC1852F88C8BF8F4ULL,
		0xECDB3B25FF512B9FULL,
		0x28D8B8C5F4E300FEULL,
		0x53F68BBF93B3EBE4ULL,
		0xE03F9BFA55B8A908ULL,
		0xE1497BE46CA4DBD1ULL,
		0x6230AB47712849E4ULL,
		0x0DD78ED04F2111F2ULL
	}};
	printf("Test Case 393\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 393 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -393;
	} else {
		printf("Test Case 393 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD1777546A00B3E44ULL,
		0xBC449261C1DED526ULL,
		0x4E2761B8D9FF236CULL,
		0x73344831CEF97DC5ULL,
		0x18B1608C60888C50ULL,
		0x1BC1A04E88DB0EDCULL,
		0x6E63BFD036E54B33ULL,
		0x0716D9EF6ADF1F61ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA2EEEA8D40167C88ULL,
		0x788924C383BDAA4DULL,
		0x9C4EC371B3FE46D9ULL,
		0xE66890639DF2FB8AULL,
		0x3162C118C11118A0ULL,
		0x3783409D11B61DB8ULL,
		0xDCC77FA06DCA9666ULL,
		0x0E2DB3DED5BE3EC2ULL
	}};
	printf("Test Case 394\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 394 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -394;
	} else {
		printf("Test Case 394 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x05B8A3B57130D510ULL,
		0x8B8C7DA1C6BE73ACULL,
		0xA2FC2A8BE5D0B24CULL,
		0xCFD9FCC67A190F19ULL,
		0x30F5806030C0B3CCULL,
		0x96D9850561487BD8ULL,
		0xB56EA1E7D5DC6CECULL,
		0x198647FEBEA054A1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0B71476AE261AA20ULL,
		0x1718FB438D7CE758ULL,
		0x45F85517CBA16499ULL,
		0x9FB3F98CF4321E33ULL,
		0x61EB00C061816799ULL,
		0x2DB30A0AC290F7B0ULL,
		0x6ADD43CFABB8D9D9ULL,
		0x330C8FFD7D40A943ULL
	}};
	printf("Test Case 395\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 395 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -395;
	} else {
		printf("Test Case 395 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0C7B68C67DB9650AULL,
		0xF357DBE818CD6D5CULL,
		0xAE4CE4030505A998ULL,
		0x7CCA8DA6E685C305ULL,
		0x35475E893AB3BFB1ULL,
		0xC085C21C4338C8F5ULL,
		0x2019277CAA316ADEULL,
		0x1B49CF4FBA9A3F6DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x18F6D18CFB72CA14ULL,
		0xE6AFB7D0319ADAB8ULL,
		0x5C99C8060A0B5331ULL,
		0xF9951B4DCD0B860BULL,
		0x6A8EBD1275677F62ULL,
		0x810B8438867191EAULL,
		0x40324EF95462D5BDULL,
		0x36939E9F75347EDAULL
	}};
	printf("Test Case 396\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 396 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -396;
	} else {
		printf("Test Case 396 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5F2463AD504715F0ULL,
		0xA118DE0E3C8EA5CCULL,
		0xB24879D48BDFE27BULL,
		0x13200EA9623F9DC3ULL,
		0xC0B8694EFD4D7AF4ULL,
		0x30E66472B53464B2ULL,
		0xAE6BD8AD787B6D60ULL,
		0x33ECECE295B46CA4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBE48C75AA08E2BE0ULL,
		0x4231BC1C791D4B98ULL,
		0x6490F3A917BFC4F7ULL,
		0x26401D52C47F3B87ULL,
		0x8170D29DFA9AF5E8ULL,
		0x61CCC8E56A68C965ULL,
		0x5CD7B15AF0F6DAC0ULL,
		0x67D9D9C52B68D949ULL
	}};
	printf("Test Case 397\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 397 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -397;
	} else {
		printf("Test Case 397 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA520A162926DAEBFULL,
		0xF03EB17636E9D339ULL,
		0x38DE29600A028B25ULL,
		0x1AF2B0E26C35A9B0ULL,
		0x5081B4C5314BB059ULL,
		0xFCA7B68020EAE8F2ULL,
		0x2139BAF57641A6F0ULL,
		0x2439C948898FC478ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4A4142C524DB5D7EULL,
		0xE07D62EC6DD3A673ULL,
		0x71BC52C01405164BULL,
		0x35E561C4D86B5360ULL,
		0xA103698A629760B2ULL,
		0xF94F6D0041D5D1E4ULL,
		0x427375EAEC834DE1ULL,
		0x48739291131F88F0ULL
	}};
	printf("Test Case 398\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 398 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -398;
	} else {
		printf("Test Case 398 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2749A2D3D4E14E84ULL,
		0xDDE9C6F9B5AA7197ULL,
		0xC62EB627F8D040A5ULL,
		0x4365D151BD38AB92ULL,
		0x14AB007A0AFF149EULL,
		0xB5D1AA4856F7C245ULL,
		0xD16C7B202492CF6BULL,
		0x3D674D063EBD14E7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4E9345A7A9C29D08ULL,
		0xBBD38DF36B54E32EULL,
		0x8C5D6C4FF1A0814BULL,
		0x86CBA2A37A715725ULL,
		0x295600F415FE293CULL,
		0x6BA35490ADEF848AULL,
		0xA2D8F64049259ED7ULL,
		0x7ACE9A0C7D7A29CFULL
	}};
	printf("Test Case 399\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 399 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -399;
	} else {
		printf("Test Case 399 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x01FC00ABB2C5E9BCULL,
		0xAD51928130C041CBULL,
		0x9AC4C57B816D90B9ULL,
		0x8592C8A9365738DDULL,
		0x462D52104633369DULL,
		0x22B15611A1931570ULL,
		0xB479770B9782B1BBULL,
		0x26034BAE235300CCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x03F80157658BD378ULL,
		0x5AA3250261808396ULL,
		0x35898AF702DB2173ULL,
		0x0B2591526CAE71BBULL,
		0x8C5AA4208C666D3BULL,
		0x4562AC2343262AE0ULL,
		0x68F2EE172F056376ULL,
		0x4C06975C46A60199ULL
	}};
	printf("Test Case 400\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 400 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -400;
	} else {
		printf("Test Case 400 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xABF883524754604FULL,
		0x0DF43CC9250A08E3ULL,
		0x0D61F4C1B011FD5DULL,
		0x5D39116A0DBA8437ULL,
		0x3400910EEEE671DCULL,
		0x75B2D4874746CCD1ULL,
		0x88511954061571ABULL,
		0x0D6E0080CF4176CFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x57F106A48EA8C09EULL,
		0x1BE879924A1411C7ULL,
		0x1AC3E9836023FABAULL,
		0xBA7222D41B75086EULL,
		0x6801221DDDCCE3B8ULL,
		0xEB65A90E8E8D99A2ULL,
		0x10A232A80C2AE356ULL,
		0x1ADC01019E82ED9FULL
	}};
	printf("Test Case 401\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 401 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -401;
	} else {
		printf("Test Case 401 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA4D7BF43AADD72FCULL,
		0x7725AF07E6217498ULL,
		0x3CA569FC4FB728ADULL,
		0xCB8DF8E0E4BF46F3ULL,
		0x93126FACAC66A931ULL,
		0x07AC71564C6F8FCAULL,
		0xB234B5ABE7FDFA88ULL,
		0x1E63A9AB809D88DDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x49AF7E8755BAE5F8ULL,
		0xEE4B5E0FCC42E931ULL,
		0x794AD3F89F6E515AULL,
		0x971BF1C1C97E8DE6ULL,
		0x2624DF5958CD5263ULL,
		0x0F58E2AC98DF1F95ULL,
		0x64696B57CFFBF510ULL,
		0x3CC75357013B11BBULL
	}};
	printf("Test Case 402\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 402 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -402;
	} else {
		printf("Test Case 402 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0EE81F89338EE5C8ULL,
		0xA178CB6319643B84ULL,
		0x2239076E9C080540ULL,
		0x5421EA40E6C54D3FULL,
		0x086086BE421BA214ULL,
		0xDDF254EF7F84938FULL,
		0x9E2A4AD601696623ULL,
		0x31E38B2AA8D68353ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1DD03F12671DCB90ULL,
		0x42F196C632C87708ULL,
		0x44720EDD38100A81ULL,
		0xA843D481CD8A9A7EULL,
		0x10C10D7C84374428ULL,
		0xBBE4A9DEFF09271EULL,
		0x3C5495AC02D2CC47ULL,
		0x63C7165551AD06A7ULL
	}};
	printf("Test Case 403\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 403 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -403;
	} else {
		printf("Test Case 403 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x948C968CE6A85E19ULL,
		0x0FC6D4C878CA7D0DULL,
		0x4207884E29F905F7ULL,
		0xDA8BD387274576ADULL,
		0xA78BB2A3EA948B73ULL,
		0x2F60E3C89B0D7A13ULL,
		0x53090C01C890D6EAULL,
		0x1E0D4905F3826CD8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x29192D19CD50BC32ULL,
		0x1F8DA990F194FA1BULL,
		0x840F109C53F20BEEULL,
		0xB517A70E4E8AED5AULL,
		0x4F176547D52916E7ULL,
		0x5EC1C791361AF427ULL,
		0xA61218039121ADD4ULL,
		0x3C1A920BE704D9B0ULL
	}};
	printf("Test Case 404\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 404 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -404;
	} else {
		printf("Test Case 404 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC7DC3058786C35CAULL,
		0x3DD7F0683401882FULL,
		0xEED070697C649AA8ULL,
		0xA2938B25B14AEE26ULL,
		0xB50E86D12BB59A2AULL,
		0x64216A298E53DC71ULL,
		0xD906C78CCFF8B0E0ULL,
		0x3A7105ECA7D81D35ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8FB860B0F0D86B94ULL,
		0x7BAFE0D06803105FULL,
		0xDDA0E0D2F8C93550ULL,
		0x4527164B6295DC4DULL,
		0x6A1D0DA2576B3455ULL,
		0xC842D4531CA7B8E3ULL,
		0xB20D8F199FF161C0ULL,
		0x74E20BD94FB03A6BULL
	}};
	printf("Test Case 405\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 405 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -405;
	} else {
		printf("Test Case 405 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA96FD76750C960AEULL,
		0xE426A39798BBDDA0ULL,
		0xE89A038CA4D4F90AULL,
		0x5447F9118F758828ULL,
		0x9179571B50EF239FULL,
		0x9F2FF2730D655F6CULL,
		0x7202FF3F677B29EBULL,
		0x1B340514EDD34BA9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x52DFAECEA192C15CULL,
		0xC84D472F3177BB41ULL,
		0xD134071949A9F215ULL,
		0xA88FF2231EEB1051ULL,
		0x22F2AE36A1DE473EULL,
		0x3E5FE4E61ACABED9ULL,
		0xE405FE7ECEF653D7ULL,
		0x36680A29DBA69752ULL
	}};
	printf("Test Case 406\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 406 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -406;
	} else {
		printf("Test Case 406 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE2A486BC8EF35281ULL,
		0xD556F0CC4D0EA246ULL,
		0xD1001F8F3AB37B92ULL,
		0xEBD0D5FD0C297FB3ULL,
		0x5EACC4B4855B62A7ULL,
		0xA264D71FE58C6B1EULL,
		0xF1AB43460125CA3BULL,
		0x0313335488E77373ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC5490D791DE6A502ULL,
		0xAAADE1989A1D448DULL,
		0xA2003F1E7566F725ULL,
		0xD7A1ABFA1852FF67ULL,
		0xBD5989690AB6C54FULL,
		0x44C9AE3FCB18D63CULL,
		0xE356868C024B9477ULL,
		0x062666A911CEE6E7ULL
	}};
	printf("Test Case 407\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 407 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -407;
	} else {
		printf("Test Case 407 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF7538F6C64142E30ULL,
		0xBFBF6724BD202E03ULL,
		0xE9D2B1AF68B4C128ULL,
		0x82B3B4431DCE00BDULL,
		0x618BCA7086A0E519ULL,
		0xFEE645D6FD9B7FF0ULL,
		0x35C39A14AE1CBD46ULL,
		0x2E113CFED10FA157ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEEA71ED8C8285C60ULL,
		0x7F7ECE497A405C07ULL,
		0xD3A5635ED1698251ULL,
		0x056768863B9C017BULL,
		0xC31794E10D41CA33ULL,
		0xFDCC8BADFB36FFE0ULL,
		0x6B8734295C397A8DULL,
		0x5C2279FDA21F42AEULL
	}};
	printf("Test Case 408\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 408 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -408;
	} else {
		printf("Test Case 408 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA1E0FDF88E932A22ULL,
		0xB68860F149A42E1AULL,
		0x7DD3F62B89F09CA0ULL,
		0x7DCE437EF2AA3AC3ULL,
		0x04AF12A22F505961ULL,
		0xEF5B766F033E4D59ULL,
		0x3AC6C4526AA1C307ULL,
		0x2DD77592E3DF593DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x43C1FBF11D265444ULL,
		0x6D10C1E293485C35ULL,
		0xFBA7EC5713E13941ULL,
		0xFB9C86FDE5547586ULL,
		0x095E25445EA0B2C2ULL,
		0xDEB6ECDE067C9AB2ULL,
		0x758D88A4D543860FULL,
		0x5BAEEB25C7BEB27AULL
	}};
	printf("Test Case 409\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 409 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -409;
	} else {
		printf("Test Case 409 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCF28EFE5CB96B62DULL,
		0x6D05C066C20CFAEAULL,
		0x690839DE4815619BULL,
		0x0A5187F7B4BB0239ULL,
		0x9711AFD6526484E5ULL,
		0xE33E310DD8377802ULL,
		0x7E6AA86047E7DFC4ULL,
		0x118B5746586D2F23ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9E51DFCB972D6C5AULL,
		0xDA0B80CD8419F5D5ULL,
		0xD21073BC902AC336ULL,
		0x14A30FEF69760472ULL,
		0x2E235FACA4C909CAULL,
		0xC67C621BB06EF005ULL,
		0xFCD550C08FCFBF89ULL,
		0x2316AE8CB0DA5E46ULL
	}};
	printf("Test Case 410\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 410 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -410;
	} else {
		printf("Test Case 410 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8F7ADDBB36474AE0ULL,
		0xA18E40AFE3A40CC3ULL,
		0x4636AEEDD66E6EBEULL,
		0x38486324D1D7C8B7ULL,
		0x8505B8EC1F6FCD83ULL,
		0xD96EB30FAF2A46A2ULL,
		0xB5CDE4F1CCF6F4B3ULL,
		0x05BE065644549174ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1EF5BB766C8E95C0ULL,
		0x431C815FC7481987ULL,
		0x8C6D5DDBACDCDD7DULL,
		0x7090C649A3AF916EULL,
		0x0A0B71D83EDF9B06ULL,
		0xB2DD661F5E548D45ULL,
		0x6B9BC9E399EDE967ULL,
		0x0B7C0CAC88A922E9ULL
	}};
	printf("Test Case 411\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 411 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -411;
	} else {
		printf("Test Case 411 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB4937D1A3D1692FAULL,
		0x56CF5386B591A431ULL,
		0x35A502A350F60DABULL,
		0x9CFF9C1E68326CB7ULL,
		0xB01AAD8651E1E015ULL,
		0x72B933A2CF78A8E1ULL,
		0x94AB8E3FFCF3F3EAULL,
		0x2F084B8ED485B81AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6926FA347A2D25F4ULL,
		0xAD9EA70D6B234863ULL,
		0x6B4A0546A1EC1B56ULL,
		0x39FF383CD064D96EULL,
		0x60355B0CA3C3C02BULL,
		0xE57267459EF151C3ULL,
		0x29571C7FF9E7E7D4ULL,
		0x5E10971DA90B7035ULL
	}};
	printf("Test Case 412\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 412 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -412;
	} else {
		printf("Test Case 412 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xACF6E1C289244363ULL,
		0x26BDA12E9DC8C970ULL,
		0xAD94774DDBD554AAULL,
		0x2F1D26FA28E7FCABULL,
		0xA2DAEB5603CBD2E2ULL,
		0x9F307EB496A6E9DEULL,
		0xC0214E1E8CA9FEB4ULL,
		0x04FAE3475F8F7A4BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x59EDC385124886C6ULL,
		0x4D7B425D3B9192E1ULL,
		0x5B28EE9BB7AAA954ULL,
		0x5E3A4DF451CFF957ULL,
		0x45B5D6AC0797A5C4ULL,
		0x3E60FD692D4DD3BDULL,
		0x80429C3D1953FD69ULL,
		0x09F5C68EBF1EF497ULL
	}};
	printf("Test Case 413\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 413 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -413;
	} else {
		printf("Test Case 413 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0AF674BF2CC7FD41ULL,
		0xE59E94C2353D6CEBULL,
		0x819B0C7D96684E21ULL,
		0xAA1EE4C98E96F489ULL,
		0x8671BF087EE86363ULL,
		0x1203E8F518247680ULL,
		0xEE723C6B86859DA1ULL,
		0x36900CDC346C7989ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x15ECE97E598FFA82ULL,
		0xCB3D29846A7AD9D6ULL,
		0x033618FB2CD09C43ULL,
		0x543DC9931D2DE913ULL,
		0x0CE37E10FDD0C6C7ULL,
		0x2407D1EA3048ED01ULL,
		0xDCE478D70D0B3B42ULL,
		0x6D2019B868D8F313ULL
	}};
	printf("Test Case 414\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 414 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -414;
	} else {
		printf("Test Case 414 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC23F2DB5B35ED841ULL,
		0x7628CF539A8C64E9ULL,
		0xADAC0EB47D4853EEULL,
		0x4E027B2B51FD43C1ULL,
		0x9E31B02826987068ULL,
		0x206F8A778F572CB1ULL,
		0xF83153D0119F7D7FULL,
		0x33893119B38507C8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x847E5B6B66BDB082ULL,
		0xEC519EA73518C9D3ULL,
		0x5B581D68FA90A7DCULL,
		0x9C04F656A3FA8783ULL,
		0x3C6360504D30E0D0ULL,
		0x40DF14EF1EAE5963ULL,
		0xF062A7A0233EFAFEULL,
		0x67126233670A0F91ULL
	}};
	printf("Test Case 415\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 415 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -415;
	} else {
		printf("Test Case 415 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFB22778E42D7A7D9ULL,
		0xBE9F7317E646FE98ULL,
		0xCFC85663022737AFULL,
		0x01ACFCC0FB2B17B4ULL,
		0x47E8DF2FEA39C862ULL,
		0x35228F605D2F7F74ULL,
		0x9D69C3EB00B90575ULL,
		0x191DAE1704E14417ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF644EF1C85AF4FB2ULL,
		0x7D3EE62FCC8DFD31ULL,
		0x9F90ACC6044E6F5FULL,
		0x0359F981F6562F69ULL,
		0x8FD1BE5FD47390C4ULL,
		0x6A451EC0BA5EFEE8ULL,
		0x3AD387D601720AEAULL,
		0x323B5C2E09C2882FULL
	}};
	printf("Test Case 416\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 416 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -416;
	} else {
		printf("Test Case 416 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x79A660B069E9C5A1ULL,
		0x20EA3BA6637E41D4ULL,
		0xC8E13C521BB42EDAULL,
		0x14FEE5D5B84C917EULL,
		0x8C41F72633A4FDDAULL,
		0x475D92619D9ACCB4ULL,
		0x4044D3B3BC8E258DULL,
		0x229BE42A6F8A9721ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF34CC160D3D38B42ULL,
		0x41D4774CC6FC83A8ULL,
		0x91C278A437685DB4ULL,
		0x29FDCBAB709922FDULL,
		0x1883EE4C6749FBB4ULL,
		0x8EBB24C33B359969ULL,
		0x8089A767791C4B1AULL,
		0x4537C854DF152E42ULL
	}};
	printf("Test Case 417\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 417 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -417;
	} else {
		printf("Test Case 417 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x746EDC407BDED329ULL,
		0x5B58770385B65D7EULL,
		0x88314B860751ECBBULL,
		0xD69A339C25BF5811ULL,
		0x0062A0D03E9B361FULL,
		0x74B968926B981732ULL,
		0xB31985AA54B15EE5ULL,
		0x0A5DBDB53DE0635EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE8DDB880F7BDA652ULL,
		0xB6B0EE070B6CBAFCULL,
		0x1062970C0EA3D976ULL,
		0xAD3467384B7EB023ULL,
		0x00C541A07D366C3FULL,
		0xE972D124D7302E64ULL,
		0x66330B54A962BDCAULL,
		0x14BB7B6A7BC0C6BDULL
	}};
	printf("Test Case 418\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 418 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -418;
	} else {
		printf("Test Case 418 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1581CEF525E0D2A4ULL,
		0xD84F32932AEDF7AEULL,
		0x16F7978975AA931AULL,
		0x57D10C8B96267EEEULL,
		0x4D6882E6843E7D18ULL,
		0xF6BFCD0775D05A33ULL,
		0xBF411B8CD26C4153ULL,
		0x08924EFA80D201E5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2B039DEA4BC1A548ULL,
		0xB09E652655DBEF5CULL,
		0x2DEF2F12EB552635ULL,
		0xAFA219172C4CFDDCULL,
		0x9AD105CD087CFA30ULL,
		0xED7F9A0EEBA0B466ULL,
		0x7E823719A4D882A7ULL,
		0x11249DF501A403CBULL
	}};
	printf("Test Case 419\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 419 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -419;
	} else {
		printf("Test Case 419 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDD993FE53F29C015ULL,
		0x89D2C781C223EA24ULL,
		0x2E94F7AC8FC04B4CULL,
		0x325DC52BD674DA9AULL,
		0x60EC9AB32294FB13ULL,
		0xC32E44F477E19C62ULL,
		0x5AA8E3BA3C36D752ULL,
		0x31E10F881B5FB94EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB327FCA7E53802AULL,
		0x13A58F038447D449ULL,
		0x5D29EF591F809699ULL,
		0x64BB8A57ACE9B534ULL,
		0xC1D935664529F626ULL,
		0x865C89E8EFC338C4ULL,
		0xB551C774786DAEA5ULL,
		0x63C21F1036BF729CULL
	}};
	printf("Test Case 420\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 420 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -420;
	} else {
		printf("Test Case 420 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3842B9CD44491A8DULL,
		0x9FD71FC3656C867AULL,
		0xF84C3F05153C7C33ULL,
		0x1AAD7B3B4FF2EA39ULL,
		0x9180952BFD08C0A1ULL,
		0xEC1A331B486150EFULL,
		0x79FF314D5F1A1894ULL,
		0x38D1B43D007D48FEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7085739A8892351AULL,
		0x3FAE3F86CAD90CF4ULL,
		0xF0987E0A2A78F867ULL,
		0x355AF6769FE5D473ULL,
		0x23012A57FA118142ULL,
		0xD834663690C2A1DFULL,
		0xF3FE629ABE343129ULL,
		0x71A3687A00FA91FCULL
	}};
	printf("Test Case 421\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 421 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -421;
	} else {
		printf("Test Case 421 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF851223400B8D409ULL,
		0x46368AE8D830E159ULL,
		0x4BDB2F4DAEA69C2EULL,
		0xCC4AAECE0B319780ULL,
		0x922A8EA679D25C9EULL,
		0xF5B23CE9D3BC8C29ULL,
		0x0244D3B575E6FFF9ULL,
		0x37FEF5782A0207AEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF0A244680171A812ULL,
		0x8C6D15D1B061C2B3ULL,
		0x97B65E9B5D4D385CULL,
		0x98955D9C16632F00ULL,
		0x24551D4CF3A4B93DULL,
		0xEB6479D3A7791853ULL,
		0x0489A76AEBCDFFF3ULL,
		0x6FFDEAF054040F5CULL
	}};
	printf("Test Case 422\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 422 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -422;
	} else {
		printf("Test Case 422 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9A8B8BC08936CA5AULL,
		0x3C0FCB82C4436AB8ULL,
		0xC3F8F5CC9009283EULL,
		0x83ECC0EB5ECB5415ULL,
		0x7E0D0CCCCC006F68ULL,
		0x285FF9E087215BB0ULL,
		0xCF7410B5F642257FULL,
		0x155F37009855E9CDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x35171781126D94B4ULL,
		0x781F97058886D571ULL,
		0x87F1EB992012507CULL,
		0x07D981D6BD96A82BULL,
		0xFC1A19999800DED1ULL,
		0x50BFF3C10E42B760ULL,
		0x9EE8216BEC844AFEULL,
		0x2ABE6E0130ABD39BULL
	}};
	printf("Test Case 423\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 423 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -423;
	} else {
		printf("Test Case 423 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBF1D33639E536C59ULL,
		0xEBDBB8EEBF7FCADAULL,
		0xD4575501DE7C1441ULL,
		0x7C1C9477BF928563ULL,
		0x4888F33273AB5A8BULL,
		0x17B94A2A897E0F22ULL,
		0x87DFDCD30FAEF33FULL,
		0x279F54F3D01795EAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7E3A66C73CA6D8B2ULL,
		0xD7B771DD7EFF95B5ULL,
		0xA8AEAA03BCF82883ULL,
		0xF83928EF7F250AC7ULL,
		0x9111E664E756B516ULL,
		0x2F72945512FC1E44ULL,
		0x0FBFB9A61F5DE67EULL,
		0x4F3EA9E7A02F2BD5ULL
	}};
	printf("Test Case 424\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 424 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -424;
	} else {
		printf("Test Case 424 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA46F0CF4E78DF6CFULL,
		0x31A8CB065F0CA780ULL,
		0x3162EFA2EBAD0629ULL,
		0x4D7CB9B1F1334876ULL,
		0x49BF9751B400EBEBULL,
		0xF48569A9837D308DULL,
		0xADC25005207AC27DULL,
		0x0CC9340B3EA337DDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x48DE19E9CF1BED9EULL,
		0x6351960CBE194F01ULL,
		0x62C5DF45D75A0C52ULL,
		0x9AF97363E26690ECULL,
		0x937F2EA36801D7D6ULL,
		0xE90AD35306FA611AULL,
		0x5B84A00A40F584FBULL,
		0x199268167D466FBBULL
	}};
	printf("Test Case 425\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 425 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -425;
	} else {
		printf("Test Case 425 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x74A4390232053B04ULL,
		0x4361F621DAF3A559ULL,
		0x2E997425A764EBD8ULL,
		0xDED1B7DA8A41650EULL,
		0xB699D754785252C3ULL,
		0xDED12E3788041D8FULL,
		0xC88D1D4177EE8EA3ULL,
		0x0D64E123C61D4032ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE9487204640A7608ULL,
		0x86C3EC43B5E74AB2ULL,
		0x5D32E84B4EC9D7B0ULL,
		0xBDA36FB51482CA1CULL,
		0x6D33AEA8F0A4A587ULL,
		0xBDA25C6F10083B1FULL,
		0x911A3A82EFDD1D47ULL,
		0x1AC9C2478C3A8065ULL
	}};
	printf("Test Case 426\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 426 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -426;
	} else {
		printf("Test Case 426 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2630C64A46229113ULL,
		0x42F755E1F5A07648ULL,
		0xC8597A49C135156EULL,
		0xF207993CF8C72039ULL,
		0x524BC861B6B21351ULL,
		0x33196302393838A1ULL,
		0xF495F3861E0E5D11ULL,
		0x097002C42D6CC638ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4C618C948C452226ULL,
		0x85EEABC3EB40EC90ULL,
		0x90B2F493826A2ADCULL,
		0xE40F3279F18E4073ULL,
		0xA49790C36D6426A3ULL,
		0x6632C60472707142ULL,
		0xE92BE70C3C1CBA22ULL,
		0x12E005885AD98C71ULL
	}};
	printf("Test Case 427\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 427 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -427;
	} else {
		printf("Test Case 427 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x986942DE2864A2B9ULL,
		0xF5E6868EDBA56D5CULL,
		0xBDE7CE7B87EA37CEULL,
		0x4AD6FC4C27513806ULL,
		0xE809C758D2B3F566ULL,
		0xB70E4D9FD05D373BULL,
		0x966FA6EF9AA5251FULL,
		0x2DC66764305B192DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x30D285BC50C94572ULL,
		0xEBCD0D1DB74ADAB9ULL,
		0x7BCF9CF70FD46F9DULL,
		0x95ADF8984EA2700DULL,
		0xD0138EB1A567EACCULL,
		0x6E1C9B3FA0BA6E77ULL,
		0x2CDF4DDF354A4A3FULL,
		0x5B8CCEC860B6325BULL
	}};
	printf("Test Case 428\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 428 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -428;
	} else {
		printf("Test Case 428 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5F2867DBDAD9DCD3ULL,
		0xBE3B9ACE46BD4931ULL,
		0x01D557FEEF145A69ULL,
		0x2AEBCC6E8DD443D4ULL,
		0x23ED7C37F19228D0ULL,
		0x98BE6620D235E51FULL,
		0xCF2C9F75EE4601FFULL,
		0x0588B35D20E03B38ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBE50CFB7B5B3B9A6ULL,
		0x7C77359C8D7A9262ULL,
		0x03AAAFFDDE28B4D3ULL,
		0x55D798DD1BA887A8ULL,
		0x47DAF86FE32451A0ULL,
		0x317CCC41A46BCA3EULL,
		0x9E593EEBDC8C03FFULL,
		0x0B1166BA41C07671ULL
	}};
	printf("Test Case 429\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 429 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -429;
	} else {
		printf("Test Case 429 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x90FBF9B9926E560CULL,
		0x153879F47B5CBB28ULL,
		0x6CCC3ADAFCD4CB3CULL,
		0xD9DE451013E9F9F3ULL,
		0x2228236FA8C24A26ULL,
		0xAAD42B34A77A3AA6ULL,
		0x399CC7543AB26A70ULL,
		0x02548498C062C641ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x21F7F37324DCAC18ULL,
		0x2A70F3E8F6B97651ULL,
		0xD99875B5F9A99678ULL,
		0xB3BC8A2027D3F3E6ULL,
		0x445046DF5184944DULL,
		0x55A856694EF4754CULL,
		0x73398EA87564D4E1ULL,
		0x04A9093180C58C82ULL
	}};
	printf("Test Case 430\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 430 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -430;
	} else {
		printf("Test Case 430 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x19D1B1AE5F0E5C6FULL,
		0xBAFB9126EED55129ULL,
		0x9E28466EB8AB691CULL,
		0x2873F559D11C8065ULL,
		0x3AC7318D2443C6A2ULL,
		0xF5627AD32CE9787BULL,
		0x724606E88CD63306ULL,
		0x2A3DA3A9AE1F891AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x33A3635CBE1CB8DEULL,
		0x75F7224DDDAAA252ULL,
		0x3C508CDD7156D239ULL,
		0x50E7EAB3A23900CBULL,
		0x758E631A48878D44ULL,
		0xEAC4F5A659D2F0F6ULL,
		0xE48C0DD119AC660DULL,
		0x547B47535C3F1234ULL
	}};
	printf("Test Case 431\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 431 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -431;
	} else {
		printf("Test Case 431 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5D65E7C84CBA167AULL,
		0x43AC1A8467614BAFULL,
		0xD753CB05E9C17E9EULL,
		0xECE600C67E1F91C2ULL,
		0x0194A96CEA650227ULL,
		0x4229ECD1DC843536ULL,
		0xA5F2D42F0D420363ULL,
		0x221F7CDDEE7B46CFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBACBCF9099742CF4ULL,
		0x87583508CEC2975EULL,
		0xAEA7960BD382FD3CULL,
		0xD9CC018CFC3F2385ULL,
		0x032952D9D4CA044FULL,
		0x8453D9A3B9086A6CULL,
		0x4BE5A85E1A8406C6ULL,
		0x443EF9BBDCF68D9FULL
	}};
	printf("Test Case 432\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 432 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -432;
	} else {
		printf("Test Case 432 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x38AB64E43D6E627AULL,
		0x3EC33A25C17ACE6CULL,
		0xFD408CF19781AE64ULL,
		0xC98AEAABD56FF3ECULL,
		0x2C2E2BD02A10D6A9ULL,
		0xCF2CEC19D364D379ULL,
		0x2D42BB7C55669388ULL,
		0x2B952EAE9FB5BA18ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7156C9C87ADCC4F4ULL,
		0x7D86744B82F59CD8ULL,
		0xFA8119E32F035CC8ULL,
		0x9315D557AADFE7D9ULL,
		0x585C57A05421AD53ULL,
		0x9E59D833A6C9A6F2ULL,
		0x5A8576F8AACD2711ULL,
		0x572A5D5D3F6B7430ULL
	}};
	printf("Test Case 433\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 433 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -433;
	} else {
		printf("Test Case 433 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4AD2E7EDACD15AC5ULL,
		0x79E7D83AA14AB141ULL,
		0xC84225B36575C88DULL,
		0x4F288CC1C9087C2FULL,
		0xDDB8892C934EFEFDULL,
		0x3B0C957809EAC216ULL,
		0xD2BBE8F0035B3C49ULL,
		0x1BDBACBF3B6FE45BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x95A5CFDB59A2B58AULL,
		0xF3CFB07542956282ULL,
		0x90844B66CAEB911AULL,
		0x9E5119839210F85FULL,
		0xBB711259269DFDFAULL,
		0x76192AF013D5842DULL,
		0xA577D1E006B67892ULL,
		0x37B7597E76DFC8B7ULL
	}};
	printf("Test Case 434\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 434 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -434;
	} else {
		printf("Test Case 434 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4CE5B59E56A4F41CULL,
		0xEB52242ED68AA4BDULL,
		0x1A254DFAE1F55921ULL,
		0x5F4F0628A72F7DB7ULL,
		0xFE0086985E43CB6AULL,
		0x324447DB5E5D6B10ULL,
		0x6CCC01E19955896AULL,
		0x0881828AE5CB4ADDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x99CB6B3CAD49E838ULL,
		0xD6A4485DAD15497AULL,
		0x344A9BF5C3EAB243ULL,
		0xBE9E0C514E5EFB6EULL,
		0xFC010D30BC8796D4ULL,
		0x64888FB6BCBAD621ULL,
		0xD99803C332AB12D4ULL,
		0x11030515CB9695BAULL
	}};
	printf("Test Case 435\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 435 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -435;
	} else {
		printf("Test Case 435 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF16EED44C3743CDDULL,
		0x97D6309422F28BBFULL,
		0x87866512F3BB8EA4ULL,
		0x1BE68F2484BC873AULL,
		0x024B39A8AE0AB7C0ULL,
		0x9AAD5537EB6476A9ULL,
		0x4ACB0B996DFA2509ULL,
		0x1B3ECD6BE60514BEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE2DDDA8986E879BAULL,
		0x2FAC612845E5177FULL,
		0x0F0CCA25E7771D49ULL,
		0x37CD1E4909790E75ULL,
		0x049673515C156F80ULL,
		0x355AAA6FD6C8ED52ULL,
		0x95961732DBF44A13ULL,
		0x367D9AD7CC0A297CULL
	}};
	printf("Test Case 436\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 436 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -436;
	} else {
		printf("Test Case 436 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6024FAA6E82170F0ULL,
		0xC5230184C852EAF4ULL,
		0x6C5494A33331C7C5ULL,
		0x6EC13C009E0C78E4ULL,
		0xD93E358C79B9126EULL,
		0x4602C858F4AA84E7ULL,
		0x659D619B37D5CB27ULL,
		0x26208ED66C3FF93DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC049F54DD042E1E0ULL,
		0x8A46030990A5D5E8ULL,
		0xD8A9294666638F8BULL,
		0xDD8278013C18F1C8ULL,
		0xB27C6B18F37224DCULL,
		0x8C0590B1E95509CFULL,
		0xCB3AC3366FAB964EULL,
		0x4C411DACD87FF27AULL
	}};
	printf("Test Case 437\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 437 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -437;
	} else {
		printf("Test Case 437 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB4A80485DD7574BCULL,
		0x7F0D6F06F94F9A46ULL,
		0x426957B8560CF6B8ULL,
		0x089B82A87E611D44ULL,
		0x6E6526E2F28E8A1FULL,
		0x4694D06AAD46FBF6ULL,
		0xC5BD14FF71EF735FULL,
		0x3CB953EA3CA74C9BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6950090BBAEAE978ULL,
		0xFE1ADE0DF29F348DULL,
		0x84D2AF70AC19ED70ULL,
		0x11370550FCC23A88ULL,
		0xDCCA4DC5E51D143EULL,
		0x8D29A0D55A8DF7ECULL,
		0x8B7A29FEE3DEE6BEULL,
		0x7972A7D4794E9937ULL
	}};
	printf("Test Case 438\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 438 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -438;
	} else {
		printf("Test Case 438 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7401C6D24A1CDAC9ULL,
		0xA46B06C769DAE78FULL,
		0x4838BDA05D4D33D9ULL,
		0xD8B7286EED6D0CD8ULL,
		0xF2EA4643B6082B75ULL,
		0x88A24F672484D498ULL,
		0xC45AA1482A1BD2BBULL,
		0x2FED2E70153A0C93ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE8038DA49439B592ULL,
		0x48D60D8ED3B5CF1EULL,
		0x90717B40BA9A67B3ULL,
		0xB16E50DDDADA19B0ULL,
		0xE5D48C876C1056EBULL,
		0x11449ECE4909A931ULL,
		0x88B542905437A577ULL,
		0x5FDA5CE02A741927ULL
	}};
	printf("Test Case 439\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 439 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -439;
	} else {
		printf("Test Case 439 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDC8E47C62AB29946ULL,
		0xE9B6444DE17E4329ULL,
		0x4B0D63837197528BULL,
		0xE003333A6DF47796ULL,
		0x4F587AC8CC65D654ULL,
		0x2701F480B44D4401ULL,
		0x08E9FAFBC5B3063EULL,
		0x045777A812D19649ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB91C8F8C5565328CULL,
		0xD36C889BC2FC8653ULL,
		0x961AC706E32EA517ULL,
		0xC0066674DBE8EF2CULL,
		0x9EB0F59198CBACA9ULL,
		0x4E03E901689A8802ULL,
		0x11D3F5F78B660C7CULL,
		0x08AEEF5025A32C92ULL
	}};
	printf("Test Case 440\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 440 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -440;
	} else {
		printf("Test Case 440 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3C844955FF9C1377ULL,
		0xFDE4A70BA2CF9CF7ULL,
		0x645098DA7F577639ULL,
		0xBB3997B0F15BBCCBULL,
		0x9476E13D45DDF1D5ULL,
		0xEE21990EFDECAFD8ULL,
		0x6E28C598D5AD39C2ULL,
		0x1F8AD653E4CACE99ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x790892ABFF3826EEULL,
		0xFBC94E17459F39EEULL,
		0xC8A131B4FEAEEC73ULL,
		0x76732F61E2B77996ULL,
		0x28EDC27A8BBBE3ABULL,
		0xDC43321DFBD95FB1ULL,
		0xDC518B31AB5A7385ULL,
		0x3F15ACA7C9959D32ULL
	}};
	printf("Test Case 441\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 441 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -441;
	} else {
		printf("Test Case 441 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x00F186F118203F3BULL,
		0x2428A00B9A51382BULL,
		0x36A6CDDBF447A625ULL,
		0x06A43F1D9753E4CEULL,
		0x2D6FB077FF86B530ULL,
		0x11034AF6204446A8ULL,
		0xB2DD22A8691451F8ULL,
		0x30E153137D1B017FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x01E30DE230407E76ULL,
		0x4851401734A27056ULL,
		0x6D4D9BB7E88F4C4AULL,
		0x0D487E3B2EA7C99CULL,
		0x5ADF60EFFF0D6A60ULL,
		0x220695EC40888D50ULL,
		0x65BA4550D228A3F0ULL,
		0x61C2A626FA3602FFULL
	}};
	printf("Test Case 442\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 442 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -442;
	} else {
		printf("Test Case 442 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x63F3519826689AF9ULL,
		0x6C0736E0565EA21FULL,
		0xF60887A21B7F7E20ULL,
		0x15949CEB1140FF8BULL,
		0x8A74D8547FAAF581ULL,
		0x6E0C9999F6658B45ULL,
		0xF868CB942D9C3643ULL,
		0x3D959194A9B2D32FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC7E6A3304CD135F2ULL,
		0xD80E6DC0ACBD443EULL,
		0xEC110F4436FEFC40ULL,
		0x2B2939D62281FF17ULL,
		0x14E9B0A8FF55EB02ULL,
		0xDC193333ECCB168BULL,
		0xF0D197285B386C86ULL,
		0x7B2B23295365A65FULL
	}};
	printf("Test Case 443\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 443 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -443;
	} else {
		printf("Test Case 443 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE70E74DD76342D6DULL,
		0xB3C785B71BF98187ULL,
		0xD3DB387A99AC8B42ULL,
		0xB647003B38F1E306ULL,
		0x655342EF8A9D3207ULL,
		0x40CCA1632D597CA8ULL,
		0x4A69DE0A2C32094FULL,
		0x127EFA7BC09B820EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCE1CE9BAEC685ADAULL,
		0x678F0B6E37F3030FULL,
		0xA7B670F533591685ULL,
		0x6C8E007671E3C60DULL,
		0xCAA685DF153A640FULL,
		0x819942C65AB2F950ULL,
		0x94D3BC145864129EULL,
		0x24FDF4F78137041CULL
	}};
	printf("Test Case 444\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 444 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -444;
	} else {
		printf("Test Case 444 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE4F45323C49C4B8AULL,
		0xCB013CB36E9E635CULL,
		0x8968C07C9366E756ULL,
		0x7F65AA3D9C6A6E82ULL,
		0x2F3EE9FE7295B5A3ULL,
		0xCB63483079FFB2AFULL,
		0xF52A366CAA1329A7ULL,
		0x1908B739B84137A8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC9E8A64789389714ULL,
		0x96027966DD3CC6B9ULL,
		0x12D180F926CDCEADULL,
		0xFECB547B38D4DD05ULL,
		0x5E7DD3FCE52B6B46ULL,
		0x96C69060F3FF655EULL,
		0xEA546CD95426534FULL,
		0x32116E7370826F51ULL
	}};
	printf("Test Case 445\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 445 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -445;
	} else {
		printf("Test Case 445 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1FB649FBCF2353FBULL,
		0x6E3EE9C40E5E54C9ULL,
		0x57D420D77F117E3BULL,
		0xAB4F46CCE0F9F0DCULL,
		0x2E4B44E070FF3BE8ULL,
		0x0816164BBD00DFB5ULL,
		0xC8B81D557D459587ULL,
		0x2AB2A24470FA62CDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3F6C93F79E46A7F6ULL,
		0xDC7DD3881CBCA992ULL,
		0xAFA841AEFE22FC76ULL,
		0x569E8D99C1F3E1B8ULL,
		0x5C9689C0E1FE77D1ULL,
		0x102C2C977A01BF6AULL,
		0x91703AAAFA8B2B0EULL,
		0x55654488E1F4C59BULL
	}};
	printf("Test Case 446\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 446 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -446;
	} else {
		printf("Test Case 446 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6324C0B4D5CF3D7CULL,
		0xBB174F2622C7B837ULL,
		0x656C950EA6845242ULL,
		0x94CDC0AF625BFEB4ULL,
		0x51D882435B7948F6ULL,
		0x241E8E0AC9AD3B1CULL,
		0x58467E3B30F16B1CULL,
		0x39F51699D09B2849ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC6498169AB9E7AF8ULL,
		0x762E9E4C458F706EULL,
		0xCAD92A1D4D08A485ULL,
		0x299B815EC4B7FD68ULL,
		0xA3B10486B6F291EDULL,
		0x483D1C15935A7638ULL,
		0xB08CFC7661E2D638ULL,
		0x73EA2D33A1365092ULL
	}};
	printf("Test Case 447\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 447 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -447;
	} else {
		printf("Test Case 447 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3931B1408FB29900ULL,
		0x12A9CA7CCC56F053ULL,
		0xEF104CEAE8439B6FULL,
		0xDA7F161C78140249ULL,
		0xA870273A7AB5C08AULL,
		0x3CDAA546CA3B4719ULL,
		0x4AED12B2DE09F471ULL,
		0x0025E6E55FF53449ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x726362811F653200ULL,
		0x255394F998ADE0A6ULL,
		0xDE2099D5D08736DEULL,
		0xB4FE2C38F0280493ULL,
		0x50E04E74F56B8115ULL,
		0x79B54A8D94768E33ULL,
		0x95DA2565BC13E8E2ULL,
		0x004BCDCABFEA6892ULL
	}};
	printf("Test Case 448\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 448 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -448;
	} else {
		printf("Test Case 448 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC3438724234C935AULL,
		0x605CF0A4AD8F0614ULL,
		0x65087A167FCB18D2ULL,
		0x6875FB36D00A9089ULL,
		0x5EFFC504685445A6ULL,
		0x8680E24D14226092ULL,
		0x0B6DAEC020E1965DULL,
		0x0BFC9ECEEFB30766ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x86870E48469926B4ULL,
		0xC0B9E1495B1E0C29ULL,
		0xCA10F42CFF9631A4ULL,
		0xD0EBF66DA0152112ULL,
		0xBDFF8A08D0A88B4CULL,
		0x0D01C49A2844C124ULL,
		0x16DB5D8041C32CBBULL,
		0x17F93D9DDF660ECCULL
	}};
	printf("Test Case 449\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 449 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -449;
	} else {
		printf("Test Case 449 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9C59462CD24DBD7AULL,
		0xB057B18E316A0B97ULL,
		0xA644B13A884821F4ULL,
		0xF1B27F0AA0A54653ULL,
		0xDD2C2AA38E903788ULL,
		0x38B09029346B4624ULL,
		0x9276109D90704C2EULL,
		0x1E887DAAE43DA829ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x38B28C59A49B7AF4ULL,
		0x60AF631C62D4172FULL,
		0x4C896275109043E9ULL,
		0xE364FE15414A8CA7ULL,
		0xBA5855471D206F11ULL,
		0x7161205268D68C49ULL,
		0x24EC213B20E0985CULL,
		0x3D10FB55C87B5053ULL
	}};
	printf("Test Case 450\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 450 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -450;
	} else {
		printf("Test Case 450 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x17FA992B435FAC63ULL,
		0x1E3AF1740019A0CEULL,
		0xB7BFC292878C3429ULL,
		0x5AE01EC7CB716289ULL,
		0x7350B6A57C56652AULL,
		0x26980304470935BDULL,
		0x7F960C75BEDC9CBEULL,
		0x0347EF60C2D1D07CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2FF5325686BF58C6ULL,
		0x3C75E2E80033419CULL,
		0x6F7F85250F186852ULL,
		0xB5C03D8F96E2C513ULL,
		0xE6A16D4AF8ACCA54ULL,
		0x4D3006088E126B7AULL,
		0xFF2C18EB7DB9397CULL,
		0x068FDEC185A3A0F8ULL
	}};
	printf("Test Case 451\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 451 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -451;
	} else {
		printf("Test Case 451 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEDA9AED96E311BCFULL,
		0xF2D2FBBAEF4127E1ULL,
		0xB0F857E28DEFF989ULL,
		0xAFC2F08AC79CBAFCULL,
		0x29D553526B8C4431ULL,
		0x92951956038A2599ULL,
		0x6B2314BBADB579D4ULL,
		0x36ABDAFF182DAFFEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDB535DB2DC62379EULL,
		0xE5A5F775DE824FC3ULL,
		0x61F0AFC51BDFF313ULL,
		0x5F85E1158F3975F9ULL,
		0x53AAA6A4D7188863ULL,
		0x252A32AC07144B32ULL,
		0xD64629775B6AF3A9ULL,
		0x6D57B5FE305B5FFCULL
	}};
	printf("Test Case 452\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 452 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -452;
	} else {
		printf("Test Case 452 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x318F434AF181F738ULL,
		0xFF568E86C63E8846ULL,
		0x5A20C9E73C12661BULL,
		0x700712A754009933ULL,
		0xEB47355674808D8DULL,
		0x45FF1CC18011F53DULL,
		0xA5DEEA0717A1F463ULL,
		0x1B1C673A8FBA3451ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x631E8695E303EE70ULL,
		0xFEAD1D0D8C7D108CULL,
		0xB44193CE7824CC37ULL,
		0xE00E254EA8013266ULL,
		0xD68E6AACE9011B1AULL,
		0x8BFE39830023EA7BULL,
		0x4BBDD40E2F43E8C6ULL,
		0x3638CE751F7468A3ULL
	}};
	printf("Test Case 453\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 453 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -453;
	} else {
		printf("Test Case 453 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC62409F1FA1CB98DULL,
		0xB8AE63D60BBCE9EDULL,
		0xF9ED8352FE3D0845ULL,
		0x02B003253AD29948ULL,
		0x14DCB76E0A9B047DULL,
		0xC5ABF9E2520212C5ULL,
		0x069D9561516FBEABULL,
		0x0ABB9A855EC53DCFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8C4813E3F439731AULL,
		0x715CC7AC1779D3DBULL,
		0xF3DB06A5FC7A108BULL,
		0x0560064A75A53291ULL,
		0x29B96EDC153608FAULL,
		0x8B57F3C4A404258AULL,
		0x0D3B2AC2A2DF7D57ULL,
		0x1577350ABD8A7B9EULL
	}};
	printf("Test Case 454\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 454 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -454;
	} else {
		printf("Test Case 454 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x855AB06F723C4424ULL,
		0xD74ECB508AB47A01ULL,
		0x830A88F0DDCBD2C7ULL,
		0xB7DD5124CCFF0891ULL,
		0xC40B2840DABBC54AULL,
		0x1242C7162200F8EAULL,
		0xDCD56CC1FA49D1E3ULL,
		0x16C3E85169AA980CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0AB560DEE4788848ULL,
		0xAE9D96A11568F403ULL,
		0x061511E1BB97A58FULL,
		0x6FBAA24999FE1123ULL,
		0x88165081B5778A95ULL,
		0x24858E2C4401F1D5ULL,
		0xB9AAD983F493A3C6ULL,
		0x2D87D0A2D3553019ULL
	}};
	printf("Test Case 455\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 455 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -455;
	} else {
		printf("Test Case 455 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4E287D2DEDD21B03ULL,
		0x5DAD178341EB2A73ULL,
		0x0FDBEEF6FECB26CAULL,
		0xEC6E613FFA9FDF53ULL,
		0x7C58DF65C864C0B9ULL,
		0xF4329B0A425F8278ULL,
		0x36DCC0E63E05BDFCULL,
		0x25E8EA1C49C8A91DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9C50FA5BDBA43606ULL,
		0xBB5A2F0683D654E6ULL,
		0x1FB7DDEDFD964D94ULL,
		0xD8DCC27FF53FBEA6ULL,
		0xF8B1BECB90C98173ULL,
		0xE865361484BF04F0ULL,
		0x6DB981CC7C0B7BF9ULL,
		0x4BD1D4389391523AULL
	}};
	printf("Test Case 456\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 456 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -456;
	} else {
		printf("Test Case 456 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x270E0D33600E0271ULL,
		0x3934C710648BD56EULL,
		0x38544CA24B898FC3ULL,
		0xC2034DAAC486135DULL,
		0xD9B3BE5D73A9C6AEULL,
		0xC357FA53BC72B405ULL,
		0xE7CEB0BC0944A067ULL,
		0x1F7D3BFF9FEA2E6CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4E1C1A66C01C04E2ULL,
		0x72698E20C917AADCULL,
		0x70A8994497131F86ULL,
		0x84069B55890C26BAULL,
		0xB3677CBAE7538D5DULL,
		0x86AFF4A778E5680BULL,
		0xCF9D6178128940CFULL,
		0x3EFA77FF3FD45CD9ULL
	}};
	printf("Test Case 457\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 457 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -457;
	} else {
		printf("Test Case 457 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA87C9DDFAB20AA85ULL,
		0xFDD081E59DC9FEF4ULL,
		0xAC29F800814F7C1EULL,
		0x4974B4BF1CE78A49ULL,
		0x2E50B4CD14722C4EULL,
		0xD3836EA47D0737F6ULL,
		0x710BFA5D11610584ULL,
		0x09599B1FA4B47D00ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x50F93BBF5641550AULL,
		0xFBA103CB3B93FDE9ULL,
		0x5853F001029EF83DULL,
		0x92E9697E39CF1493ULL,
		0x5CA1699A28E4589CULL,
		0xA706DD48FA0E6FECULL,
		0xE217F4BA22C20B09ULL,
		0x12B3363F4968FA00ULL
	}};
	printf("Test Case 458\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 458 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -458;
	} else {
		printf("Test Case 458 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x65096F3CCD58AE0EULL,
		0x25CCBFC9431011A5ULL,
		0x1750BE25AC9C1F7DULL,
		0x53F616601FB75509ULL,
		0x00C6EDE4BF06ACA3ULL,
		0x7569EDB3BCA85858ULL,
		0x9FDE10AB3856D2ACULL,
		0x0A14324E2A1CF286ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCA12DE799AB15C1CULL,
		0x4B997F928620234AULL,
		0x2EA17C4B59383EFAULL,
		0xA7EC2CC03F6EAA12ULL,
		0x018DDBC97E0D5946ULL,
		0xEAD3DB677950B0B0ULL,
		0x3FBC215670ADA558ULL,
		0x1428649C5439E50DULL
	}};
	printf("Test Case 459\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 459 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -459;
	} else {
		printf("Test Case 459 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x865ACAB7F611ED45ULL,
		0xCA3DE64BB10E7835ULL,
		0x9E345D716C42C544ULL,
		0x5858859149463AD2ULL,
		0xE2239998C6F3F9B2ULL,
		0x4823B3BFDDD57A24ULL,
		0xE504758428729E77ULL,
		0x2479CE0D0DC19FA4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0CB5956FEC23DA8AULL,
		0x947BCC97621CF06BULL,
		0x3C68BAE2D8858A89ULL,
		0xB0B10B22928C75A5ULL,
		0xC44733318DE7F364ULL,
		0x9047677FBBAAF449ULL,
		0xCA08EB0850E53CEEULL,
		0x48F39C1A1B833F49ULL
	}};
	printf("Test Case 460\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 460 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -460;
	} else {
		printf("Test Case 460 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9E5892C6659AB00DULL,
		0xBD5D3D5B65628E0AULL,
		0x8C7E083FAE2F21EBULL,
		0x458D73758932AD08ULL,
		0x5FD69C345A4D1399ULL,
		0xFC0A306ADABD92B1ULL,
		0x04F89217CF54503BULL,
		0x0BA14F523CC9A978ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3CB1258CCB35601AULL,
		0x7ABA7AB6CAC51C15ULL,
		0x18FC107F5C5E43D7ULL,
		0x8B1AE6EB12655A11ULL,
		0xBFAD3868B49A2732ULL,
		0xF81460D5B57B2562ULL,
		0x09F1242F9EA8A077ULL,
		0x17429EA4799352F0ULL
	}};
	printf("Test Case 461\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 461 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -461;
	} else {
		printf("Test Case 461 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBC8723D34A7621CFULL,
		0x3B2EEA70BA43AF02ULL,
		0xE955C44984266555ULL,
		0xA8CE683164F476AAULL,
		0x17056DF806D05BB4ULL,
		0xC97FF9CF451A40B7ULL,
		0x838013D28755B00EULL,
		0x0B66CF0C05DC6FA0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x790E47A694EC439EULL,
		0x765DD4E174875E05ULL,
		0xD2AB8893084CCAAAULL,
		0x519CD062C9E8ED55ULL,
		0x2E0ADBF00DA0B769ULL,
		0x92FFF39E8A34816EULL,
		0x070027A50EAB601DULL,
		0x16CD9E180BB8DF41ULL
	}};
	printf("Test Case 462\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 462 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -462;
	} else {
		printf("Test Case 462 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2FEBBB8CC758968DULL,
		0x6C0FE4E5DA49BD65ULL,
		0xD11298F9186AD1ADULL,
		0x20014119CEE317FAULL,
		0x9DBD3D5379704980ULL,
		0x1691C234888A15EBULL,
		0x0EE8EF1773AB79C3ULL,
		0x0722F8A6CAF27FB8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5FD777198EB12D1AULL,
		0xD81FC9CBB4937ACAULL,
		0xA22531F230D5A35AULL,
		0x400282339DC62FF5ULL,
		0x3B7A7AA6F2E09300ULL,
		0x2D23846911142BD7ULL,
		0x1DD1DE2EE756F386ULL,
		0x0E45F14D95E4FF70ULL
	}};
	printf("Test Case 463\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 463 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -463;
	} else {
		printf("Test Case 463 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBBD2AFD6472CA3AEULL,
		0xF7E11AF04A1758F4ULL,
		0x1227B5D97124700EULL,
		0x59106E17E92D1E6EULL,
		0x80C007AA647E0EABULL,
		0xEDD8A7E2B34F30B8ULL,
		0xACA5C16D16DD8DECULL,
		0x1D94EBC917AE3995ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x77A55FAC8E59475CULL,
		0xEFC235E0942EB1E9ULL,
		0x244F6BB2E248E01DULL,
		0xB220DC2FD25A3CDCULL,
		0x01800F54C8FC1D56ULL,
		0xDBB14FC5669E6171ULL,
		0x594B82DA2DBB1BD9ULL,
		0x3B29D7922F5C732BULL
	}};
	printf("Test Case 464\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 464 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -464;
	} else {
		printf("Test Case 464 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDF5AE30B9CE3FCA4ULL,
		0x91CDD987B01AFE52ULL,
		0xF65C5B10D3538249ULL,
		0x645A3F7794ACDF2FULL,
		0xB40803106DB535E9ULL,
		0x879A933CD2E2F0C6ULL,
		0x493AC3AB0DCBB37BULL,
		0x3382710182839677ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBEB5C61739C7F948ULL,
		0x239BB30F6035FCA5ULL,
		0xECB8B621A6A70493ULL,
		0xC8B47EEF2959BE5FULL,
		0x68100620DB6A6BD2ULL,
		0x0F352679A5C5E18DULL,
		0x927587561B9766F7ULL,
		0x6704E20305072CEEULL
	}};
	printf("Test Case 465\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 465 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -465;
	} else {
		printf("Test Case 465 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x358C557281C52582ULL,
		0x1F642882F866A239ULL,
		0xC4A8A21FBF55FEC0ULL,
		0x7E8E1226B75C7547ULL,
		0xC861BBB4440B9867ULL,
		0x666D4E80116D19C3ULL,
		0x07C9EFB12F52682BULL,
		0x1242BA78DA6D3218ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6B18AAE5038A4B04ULL,
		0x3EC85105F0CD4472ULL,
		0x8951443F7EABFD80ULL,
		0xFD1C244D6EB8EA8FULL,
		0x90C37768881730CEULL,
		0xCCDA9D0022DA3387ULL,
		0x0F93DF625EA4D056ULL,
		0x248574F1B4DA6430ULL
	}};
	printf("Test Case 466\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 466 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -466;
	} else {
		printf("Test Case 466 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xED5FA7713136815CULL,
		0x58660E1286937CCAULL,
		0x35EA58DA7C1B3567ULL,
		0x86140DB64FA3C987ULL,
		0x76B88C4226C5A9BAULL,
		0xF2309533FB1D154FULL,
		0xA9E0191CE54A7F26ULL,
		0x205C723B1C5EC783ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDABF4EE2626D02B8ULL,
		0xB0CC1C250D26F995ULL,
		0x6BD4B1B4F8366ACEULL,
		0x0C281B6C9F47930EULL,
		0xED7118844D8B5375ULL,
		0xE4612A67F63A2A9EULL,
		0x53C03239CA94FE4DULL,
		0x40B8E47638BD8F07ULL
	}};
	printf("Test Case 467\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 467 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -467;
	} else {
		printf("Test Case 467 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAB8BB492EAD930C7ULL,
		0x5D281CDF97CC28A5ULL,
		0xA8F12C678A2924BEULL,
		0xAED6EE6CF55EA6C0ULL,
		0x4813DCF83C3A3941ULL,
		0xEC7B3972E6B1EEABULL,
		0xC6EDBB37A81DE381ULL,
		0x0F4C931F067590EAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x57176925D5B2618EULL,
		0xBA5039BF2F98514BULL,
		0x51E258CF1452497CULL,
		0x5DADDCD9EABD4D81ULL,
		0x9027B9F078747283ULL,
		0xD8F672E5CD63DD56ULL,
		0x8DDB766F503BC703ULL,
		0x1E99263E0CEB21D5ULL
	}};
	printf("Test Case 468\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 468 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -468;
	} else {
		printf("Test Case 468 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3BB1FEE4FF330409ULL,
		0x867E2370A8145875ULL,
		0x15FD165E2D8B07A6ULL,
		0x7DE01A0FD86088E8ULL,
		0x1C51BC4F1DAA36A3ULL,
		0x7ED03E77F908D758ULL,
		0x439DAFE1EAAB2BB1ULL,
		0x0D196BAFBEF93C6BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7763FDC9FE660812ULL,
		0x0CFC46E15028B0EAULL,
		0x2BFA2CBC5B160F4DULL,
		0xFBC0341FB0C111D0ULL,
		0x38A3789E3B546D46ULL,
		0xFDA07CEFF211AEB0ULL,
		0x873B5FC3D5565762ULL,
		0x1A32D75F7DF278D6ULL
	}};
	printf("Test Case 469\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 469 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -469;
	} else {
		printf("Test Case 469 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBF70E8BD3569F9C3ULL,
		0x035ACEBA527BCD9FULL,
		0xE60D511BDF8AC5FEULL,
		0x63B35F8454A84E69ULL,
		0x8CE30B2C293F35D1ULL,
		0x59DBC00F19B8EA06ULL,
		0x89D56494A47A0D58ULL,
		0x2C377278501A31C4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7EE1D17A6AD3F386ULL,
		0x06B59D74A4F79B3FULL,
		0xCC1AA237BF158BFCULL,
		0xC766BF08A9509CD3ULL,
		0x19C61658527E6BA2ULL,
		0xB3B7801E3371D40DULL,
		0x13AAC92948F41AB0ULL,
		0x586EE4F0A0346389ULL
	}};
	printf("Test Case 470\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 470 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -470;
	} else {
		printf("Test Case 470 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x343D229BBFE5CBE9ULL,
		0x4F879264BF2E9EA7ULL,
		0x553F2F61D931D994ULL,
		0xCB5BCB6128A88348ULL,
		0xD706E63F51A4621AULL,
		0xA5D4DFE8F1798B99ULL,
		0xD656B12D103B531FULL,
		0x317B86351386AB1BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x687A45377FCB97D2ULL,
		0x9F0F24C97E5D3D4EULL,
		0xAA7E5EC3B263B328ULL,
		0x96B796C251510690ULL,
		0xAE0DCC7EA348C435ULL,
		0x4BA9BFD1E2F31733ULL,
		0xACAD625A2076A63FULL,
		0x62F70C6A270D5637ULL
	}};
	printf("Test Case 471\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 471 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -471;
	} else {
		printf("Test Case 471 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB2A956A5B97023F4ULL,
		0x91F300F3F0A7C669ULL,
		0xDA34D4D904437209ULL,
		0x40640B02AB183D3AULL,
		0x4A5D84376AD2CD13ULL,
		0x8BD289C704A4BCA2ULL,
		0x364563D59BCF1DF5ULL,
		0x23E884F1F0D84725ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6552AD4B72E047E8ULL,
		0x23E601E7E14F8CD3ULL,
		0xB469A9B20886E413ULL,
		0x80C8160556307A75ULL,
		0x94BB086ED5A59A26ULL,
		0x17A5138E09497944ULL,
		0x6C8AC7AB379E3BEBULL,
		0x47D109E3E1B08E4AULL
	}};
	printf("Test Case 472\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 472 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -472;
	} else {
		printf("Test Case 472 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB9708771F1C6D482ULL,
		0x86E62009147DB3DBULL,
		0x3F9F10F09F57C7F3ULL,
		0x26C0597D222A9175ULL,
		0xA864D48206712085ULL,
		0xF44425FC41A9C6A3ULL,
		0x0502763B8DFBE04DULL,
		0x1F867FA9FA7DD3E4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x72E10EE3E38DA904ULL,
		0x0DCC401228FB67B7ULL,
		0x7F3E21E13EAF8FE7ULL,
		0x4D80B2FA445522EAULL,
		0x50C9A9040CE2410AULL,
		0xE8884BF883538D47ULL,
		0x0A04EC771BF7C09BULL,
		0x3F0CFF53F4FBA7C8ULL
	}};
	printf("Test Case 473\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 473 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -473;
	} else {
		printf("Test Case 473 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1C3B070948722A9AULL,
		0xDA61D6BE29902FFCULL,
		0xFA04DDC9770E2F9BULL,
		0x273AD02E37E9D84AULL,
		0xFA1BA986F3858BD8ULL,
		0x09B1A574EC20DDAAULL,
		0x2A56629A60A45599ULL,
		0x0672A5064FC0BBD2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x38760E1290E45534ULL,
		0xB4C3AD7C53205FF8ULL,
		0xF409BB92EE1C5F37ULL,
		0x4E75A05C6FD3B095ULL,
		0xF437530DE70B17B0ULL,
		0x13634AE9D841BB55ULL,
		0x54ACC534C148AB32ULL,
		0x0CE54A0C9F8177A4ULL
	}};
	printf("Test Case 474\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 474 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -474;
	} else {
		printf("Test Case 474 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2C48B687FF567E5FULL,
		0x5DAF77A523946659ULL,
		0xD0960074506F9FF2ULL,
		0x8A57A31D5B291568ULL,
		0xB0969959F195C758ULL,
		0x07F8F346DC615C89ULL,
		0x00E85F7BF2F68660ULL,
		0x3DD8B1D23D1E66AFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x58916D0FFEACFCBEULL,
		0xBB5EEF4A4728CCB2ULL,
		0xA12C00E8A0DF3FE4ULL,
		0x14AF463AB6522AD1ULL,
		0x612D32B3E32B8EB1ULL,
		0x0FF1E68DB8C2B913ULL,
		0x01D0BEF7E5ED0CC0ULL,
		0x7BB163A47A3CCD5EULL
	}};
	printf("Test Case 475\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 475 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -475;
	} else {
		printf("Test Case 475 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7BF5398EFEBBD410ULL,
		0xE3CC8E65A5326388ULL,
		0x0F0ED4221465F6F9ULL,
		0x856F364E247A127DULL,
		0x94B592557E2AB0B7ULL,
		0x067E8C76E349623CULL,
		0xECF99756A0E4C17EULL,
		0x0A122DCC5127582CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF7EA731DFD77A820ULL,
		0xC7991CCB4A64C710ULL,
		0x1E1DA84428CBEDF3ULL,
		0x0ADE6C9C48F424FAULL,
		0x296B24AAFC55616FULL,
		0x0CFD18EDC692C479ULL,
		0xD9F32EAD41C982FCULL,
		0x14245B98A24EB059ULL
	}};
	printf("Test Case 476\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 476 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -476;
	} else {
		printf("Test Case 476 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE4CEA0AEDB288DA6ULL,
		0xECA5546613249ABEULL,
		0xAA441508D010BA2AULL,
		0x872F556B8504EA29ULL,
		0x770E8D5B6BE18171ULL,
		0xED1C92092F1273FAULL,
		0xCDAA1CB3F8C8078FULL,
		0x3CD07E457828F1DAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC99D415DB6511B4CULL,
		0xD94AA8CC2649357DULL,
		0x54882A11A0217455ULL,
		0x0E5EAAD70A09D453ULL,
		0xEE1D1AB6D7C302E3ULL,
		0xDA3924125E24E7F4ULL,
		0x9B543967F1900F1FULL,
		0x79A0FC8AF051E3B5ULL
	}};
	printf("Test Case 477\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 477 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -477;
	} else {
		printf("Test Case 477 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCA815D1819A673ADULL,
		0xE7FA395EEA191D92ULL,
		0x6B5E5EEEA3959790ULL,
		0xF04D4EEF9168BCB3ULL,
		0xE6E6EA497FEC8F97ULL,
		0xE5D4EF9FE9820554ULL,
		0x3FE29774079FAE9BULL,
		0x3030D715326BD299ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9502BA30334CE75AULL,
		0xCFF472BDD4323B25ULL,
		0xD6BCBDDD472B2F21ULL,
		0xE09A9DDF22D17966ULL,
		0xCDCDD492FFD91F2FULL,
		0xCBA9DF3FD3040AA9ULL,
		0x7FC52EE80F3F5D37ULL,
		0x6061AE2A64D7A532ULL
	}};
	printf("Test Case 478\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 478 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -478;
	} else {
		printf("Test Case 478 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x43CE4CB68153EB22ULL,
		0x6FC35E9BE48D69CAULL,
		0x1592F9854FCC2F8EULL,
		0x9140112BFF95DE45ULL,
		0xE6D433B8BDA738E1ULL,
		0x2BA8EB47FA776315ULL,
		0x2A18CF8FA166EA6BULL,
		0x0A8EE233E9AC8D82ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x879C996D02A7D644ULL,
		0xDF86BD37C91AD394ULL,
		0x2B25F30A9F985F1CULL,
		0x22802257FF2BBC8AULL,
		0xCDA867717B4E71C3ULL,
		0x5751D68FF4EEC62BULL,
		0x54319F1F42CDD4D6ULL,
		0x151DC467D3591B04ULL
	}};
	printf("Test Case 479\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 479 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -479;
	} else {
		printf("Test Case 479 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3CDAA78A4A6DFD44ULL,
		0xB7523098EE9D9C9AULL,
		0x3FD98391AAFD43C9ULL,
		0xC0F339F8DC084C2FULL,
		0x707DD15737B42181ULL,
		0x4160C260EF5013DBULL,
		0xA247D355529423C9ULL,
		0x030704285781F058ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x79B54F1494DBFA88ULL,
		0x6EA46131DD3B3934ULL,
		0x7FB3072355FA8793ULL,
		0x81E673F1B810985EULL,
		0xE0FBA2AE6F684303ULL,
		0x82C184C1DEA027B6ULL,
		0x448FA6AAA5284792ULL,
		0x060E0850AF03E0B1ULL
	}};
	printf("Test Case 480\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 480 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -480;
	} else {
		printf("Test Case 480 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x552A9356B42FC427ULL,
		0x79BA13E57024D369ULL,
		0x5451393EABF8CA61ULL,
		0xA7C987F2C50B1B13ULL,
		0x8AB7D3DE58FED709ULL,
		0x09EF1FA70B72A434ULL,
		0x8106A895041EE76DULL,
		0x13019901E01EF366ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAA5526AD685F884EULL,
		0xF37427CAE049A6D2ULL,
		0xA8A2727D57F194C2ULL,
		0x4F930FE58A163626ULL,
		0x156FA7BCB1FDAE13ULL,
		0x13DE3F4E16E54869ULL,
		0x020D512A083DCEDAULL,
		0x26033203C03DE6CDULL
	}};
	printf("Test Case 481\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 481 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -481;
	} else {
		printf("Test Case 481 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9FE9DCAA3382C236ULL,
		0x3299A7683F4FFC9AULL,
		0xAF320FB7E1322665ULL,
		0xA51E6286E4B11FFEULL,
		0x0E7176657AD975C9ULL,
		0xBE609B0C1DBC873BULL,
		0x458ACA044D6EC6E0ULL,
		0x3E2A00A5DF24AC8FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3FD3B9546705846CULL,
		0x65334ED07E9FF935ULL,
		0x5E641F6FC2644CCAULL,
		0x4A3CC50DC9623FFDULL,
		0x1CE2ECCAF5B2EB93ULL,
		0x7CC136183B790E76ULL,
		0x8B1594089ADD8DC1ULL,
		0x7C54014BBE49591EULL
	}};
	printf("Test Case 482\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 482 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -482;
	} else {
		printf("Test Case 482 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x70B532A63A2A3240ULL,
		0x1AD703A4943AE31FULL,
		0x1812CE69AA70A89BULL,
		0x456A6887CC301AFFULL,
		0xBBA15667D1A2C654ULL,
		0x7DF4CA1C903DF899ULL,
		0x52E52CB792FC88E5ULL,
		0x2F5077C55F747A1EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE16A654C74546480ULL,
		0x35AE07492875C63EULL,
		0x30259CD354E15136ULL,
		0x8AD4D10F986035FEULL,
		0x7742ACCFA3458CA8ULL,
		0xFBE99439207BF133ULL,
		0xA5CA596F25F911CAULL,
		0x5EA0EF8ABEE8F43CULL
	}};
	printf("Test Case 483\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 483 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -483;
	} else {
		printf("Test Case 483 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x32DFEA96BAB8A127ULL,
		0x76941C7218BB1E70ULL,
		0x127F481B8D2249F3ULL,
		0x3434BF5BDDF95AE0ULL,
		0x965E49F514A1E5A1ULL,
		0xE0793B98AC3F3C5AULL,
		0xD931EFB1692AAB04ULL,
		0x086C196EC45BDCD9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x65BFD52D7571424EULL,
		0xED2838E431763CE0ULL,
		0x24FE90371A4493E6ULL,
		0x68697EB7BBF2B5C0ULL,
		0x2CBC93EA2943CB42ULL,
		0xC0F27731587E78B5ULL,
		0xB263DF62D2555609ULL,
		0x10D832DD88B7B9B3ULL
	}};
	printf("Test Case 484\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 484 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -484;
	} else {
		printf("Test Case 484 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x877FAF7B6A4EABB0ULL,
		0xE11831692DB57216ULL,
		0x688FA2F79C088FCEULL,
		0xBA3CD235E970FD5FULL,
		0xF035D055A9C4EB66ULL,
		0x5BC645200199E276ULL,
		0xDCFAA3405504ADC2ULL,
		0x35E6049E9821E945ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0EFF5EF6D49D5760ULL,
		0xC23062D25B6AE42DULL,
		0xD11F45EF38111F9DULL,
		0x7479A46BD2E1FABEULL,
		0xE06BA0AB5389D6CDULL,
		0xB78C8A400333C4EDULL,
		0xB9F54680AA095B84ULL,
		0x6BCC093D3043D28BULL
	}};
	printf("Test Case 485\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 485 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -485;
	} else {
		printf("Test Case 485 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCD346574BCEBFAFCULL,
		0xF0DF81E7FB95FF7BULL,
		0xF7EDE96366BFC583ULL,
		0x2FEDDFF6A3989BA7ULL,
		0x2591E7E3A6EDADB5ULL,
		0x262DF0F50A45EE05ULL,
		0xA63223F0EDAC915EULL,
		0x12235354075CFFADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9A68CAE979D7F5F8ULL,
		0xE1BF03CFF72BFEF7ULL,
		0xEFDBD2C6CD7F8B07ULL,
		0x5FDBBFED4731374FULL,
		0x4B23CFC74DDB5B6AULL,
		0x4C5BE1EA148BDC0AULL,
		0x4C6447E1DB5922BCULL,
		0x2446A6A80EB9FF5BULL
	}};
	printf("Test Case 486\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 486 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -486;
	} else {
		printf("Test Case 486 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x01959E1CFA691B11ULL,
		0xF41278884BB9F028ULL,
		0xD9EB4AD133A1D7D2ULL,
		0x366E2B6E5EA653D1ULL,
		0x6DCA7D8658EC463FULL,
		0xC329ACEAAF033235ULL,
		0x47663BCA1F02591FULL,
		0x1E55F43806D1B800ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x032B3C39F4D23622ULL,
		0xE824F1109773E050ULL,
		0xB3D695A26743AFA5ULL,
		0x6CDC56DCBD4CA7A3ULL,
		0xDB94FB0CB1D88C7EULL,
		0x865359D55E06646AULL,
		0x8ECC77943E04B23FULL,
		0x3CABE8700DA37000ULL
	}};
	printf("Test Case 487\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 487 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -487;
	} else {
		printf("Test Case 487 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0E6D059B423EC10EULL,
		0x7D80393F14619CA2ULL,
		0x5E5560889AAA4207ULL,
		0xB5527C15843B597DULL,
		0xA8837C943F38DC52ULL,
		0x005194164B6BF38CULL,
		0x010358271C4CB797ULL,
		0x38223A49762E4679ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1CDA0B36847D821CULL,
		0xFB00727E28C33944ULL,
		0xBCAAC1113554840EULL,
		0x6AA4F82B0876B2FAULL,
		0x5106F9287E71B8A5ULL,
		0x00A3282C96D7E719ULL,
		0x0206B04E38996F2EULL,
		0x70447492EC5C8CF2ULL
	}};
	printf("Test Case 488\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 488 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -488;
	} else {
		printf("Test Case 488 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x02432F5DB5B16C37ULL,
		0x17033C39642F016DULL,
		0x580F064BFA28C78AULL,
		0x962EAD741BA71E14ULL,
		0x27CBE24F413252E9ULL,
		0xF0FBFF9A953CCA85ULL,
		0x0D16E9C798BA5C1BULL,
		0x09566566A5C20798ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x04865EBB6B62D86EULL,
		0x2E067872C85E02DAULL,
		0xB01E0C97F4518F14ULL,
		0x2C5D5AE8374E3C28ULL,
		0x4F97C49E8264A5D3ULL,
		0xE1F7FF352A79950AULL,
		0x1A2DD38F3174B837ULL,
		0x12ACCACD4B840F30ULL
	}};
	printf("Test Case 489\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 489 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -489;
	} else {
		printf("Test Case 489 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD09D68E2049A054DULL,
		0x3B9A4A74C72C59EDULL,
		0xC88FE58D1785A86CULL,
		0x9B1610B32874503DULL,
		0x3A3C6F5A19076D91ULL,
		0x9D74B1A443512A10ULL,
		0x57218F42605517ECULL,
		0x384EED282AA59CAAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA13AD1C409340A9AULL,
		0x773494E98E58B3DBULL,
		0x911FCB1A2F0B50D8ULL,
		0x362C216650E8A07BULL,
		0x7478DEB4320EDB23ULL,
		0x3AE9634886A25420ULL,
		0xAE431E84C0AA2FD9ULL,
		0x709DDA50554B3954ULL
	}};
	printf("Test Case 490\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 490 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -490;
	} else {
		printf("Test Case 490 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8F0618B56E6931EBULL,
		0xFB86813D8A4F68FFULL,
		0xD19C8B5DF00A3838ULL,
		0xEFB0AE2B91BA7A1CULL,
		0x9982563CA072079FULL,
		0x3B0F3056069C6277ULL,
		0x2B9C2E2A8F4908B3ULL,
		0x112A531CBACC5C17ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1E0C316ADCD263D6ULL,
		0xF70D027B149ED1FFULL,
		0xA33916BBE0147071ULL,
		0xDF615C572374F439ULL,
		0x3304AC7940E40F3FULL,
		0x761E60AC0D38C4EFULL,
		0x57385C551E921166ULL,
		0x2254A6397598B82EULL
	}};
	printf("Test Case 491\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 491 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -491;
	} else {
		printf("Test Case 491 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x942A1337A0EFC836ULL,
		0x79683AD1F91ED7E9ULL,
		0x456F5C965BF26F33ULL,
		0x08DCFC54090AAC31ULL,
		0x98D3ED487A169CBFULL,
		0x9F640FB0CBD27E1EULL,
		0xDFB24EC7A52A124BULL,
		0x173E6ED1FFB9577FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2854266F41DF906CULL,
		0xF2D075A3F23DAFD3ULL,
		0x8ADEB92CB7E4DE66ULL,
		0x11B9F8A812155862ULL,
		0x31A7DA90F42D397EULL,
		0x3EC81F6197A4FC3DULL,
		0xBF649D8F4A542497ULL,
		0x2E7CDDA3FF72AEFFULL
	}};
	printf("Test Case 492\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 492 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -492;
	} else {
		printf("Test Case 492 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3750339F616155A1ULL,
		0x70A2E97289BCE0FFULL,
		0x9671438B3E95307DULL,
		0xD3659F099FBB2301ULL,
		0x60921EAF4DC082FDULL,
		0xAD1900FF351FFC78ULL,
		0x8452F423C25C1430ULL,
		0x386742E218F90BCCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6EA0673EC2C2AB42ULL,
		0xE145D2E51379C1FEULL,
		0x2CE287167D2A60FAULL,
		0xA6CB3E133F764603ULL,
		0xC1243D5E9B8105FBULL,
		0x5A3201FE6A3FF8F0ULL,
		0x08A5E84784B82861ULL,
		0x70CE85C431F21799ULL
	}};
	printf("Test Case 493\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 493 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -493;
	} else {
		printf("Test Case 493 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xADDD99C89909C797ULL,
		0x608A9D2E9946DB91ULL,
		0x198E80408C260665ULL,
		0xDFBE0B22BEC29855ULL,
		0x1C781C864A8997ADULL,
		0xD32946177D1B16C1ULL,
		0xD76445651AAFCE50ULL,
		0x0D2A05EFEFE1864BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5BBB339132138F2EULL,
		0xC1153A5D328DB723ULL,
		0x331D0081184C0CCAULL,
		0xBF7C16457D8530AAULL,
		0x38F0390C95132F5BULL,
		0xA6528C2EFA362D82ULL,
		0xAEC88ACA355F9CA1ULL,
		0x1A540BDFDFC30C97ULL
	}};
	printf("Test Case 494\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 494 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -494;
	} else {
		printf("Test Case 494 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x517999EBF6BF2DB1ULL,
		0xF3C40561806D5E80ULL,
		0x107993CDF97D0EC3ULL,
		0x92C2957F491E3BDEULL,
		0xD4721AB3641969D5ULL,
		0xFB5ECED61539F9CDULL,
		0x63724F0A0360360AULL,
		0x11920CC24A675801ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA2F333D7ED7E5B62ULL,
		0xE7880AC300DABD00ULL,
		0x20F3279BF2FA1D87ULL,
		0x25852AFE923C77BCULL,
		0xA8E43566C832D3ABULL,
		0xF6BD9DAC2A73F39BULL,
		0xC6E49E1406C06C15ULL,
		0x2324198494CEB002ULL
	}};
	printf("Test Case 495\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 495 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -495;
	} else {
		printf("Test Case 495 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF277D593F3A25F0DULL,
		0x7174745BAFB34D07ULL,
		0x1981F917E821388AULL,
		0x3B4A399015DD8DE5ULL,
		0xB0A1F67F465DDDB4ULL,
		0x1989E4CFEEE961F1ULL,
		0x4D29271C3CFA9AE9ULL,
		0x3BD61290615D010BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE4EFAB27E744BE1AULL,
		0xE2E8E8B75F669A0FULL,
		0x3303F22FD0427114ULL,
		0x769473202BBB1BCAULL,
		0x6143ECFE8CBBBB68ULL,
		0x3313C99FDDD2C3E3ULL,
		0x9A524E3879F535D2ULL,
		0x77AC2520C2BA0216ULL
	}};
	printf("Test Case 496\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 496 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -496;
	} else {
		printf("Test Case 496 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDE14F4C9B4A4DDAFULL,
		0x4D9965834B467566ULL,
		0xA2E7741057D1927AULL,
		0x178FC7CDB93540ADULL,
		0x14C36011819316ACULL,
		0x362F0A5949AF02DDULL,
		0x2CF901B7E45E421EULL,
		0x129FA91AC4C6BF82ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBC29E9936949BB5EULL,
		0x9B32CB06968CEACDULL,
		0x45CEE820AFA324F4ULL,
		0x2F1F8F9B726A815BULL,
		0x2986C02303262D58ULL,
		0x6C5E14B2935E05BAULL,
		0x59F2036FC8BC843CULL,
		0x253F5235898D7F04ULL
	}};
	printf("Test Case 497\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 497 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -497;
	} else {
		printf("Test Case 497 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2A73CAE6353C93FEULL,
		0x2AB28B8867F39E65ULL,
		0x205E5572DA71D105ULL,
		0xBD415CDA6755C945ULL,
		0x77F1175BA083470EULL,
		0x1B148450A70FAEE8ULL,
		0x6513525115ABF2EFULL,
		0x260C9BD8ADF7D524ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x54E795CC6A7927FCULL,
		0x55651710CFE73CCAULL,
		0x40BCAAE5B4E3A20AULL,
		0x7A82B9B4CEAB928AULL,
		0xEFE22EB741068E1DULL,
		0x362908A14E1F5DD0ULL,
		0xCA26A4A22B57E5DEULL,
		0x4C1937B15BEFAA48ULL
	}};
	printf("Test Case 498\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 498 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -498;
	} else {
		printf("Test Case 498 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0501DB340D29122EULL,
		0x95D8EE7F37306E31ULL,
		0xC5F45C87CF4ABD08ULL,
		0x7F8252AB93E2F09DULL,
		0x930BE460373A2192ULL,
		0xE00D8BE1A2E04919ULL,
		0xF0F9F00D74131337ULL,
		0x21CEED4EC8B6FEDAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0A03B6681A52245CULL,
		0x2BB1DCFE6E60DC62ULL,
		0x8BE8B90F9E957A11ULL,
		0xFF04A55727C5E13BULL,
		0x2617C8C06E744324ULL,
		0xC01B17C345C09233ULL,
		0xE1F3E01AE826266FULL,
		0x439DDA9D916DFDB5ULL
	}};
	printf("Test Case 499\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 499 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -499;
	} else {
		printf("Test Case 499 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2CE30E151B654946ULL,
		0x5DE18AC7A7A05338ULL,
		0xE838387B7389174BULL,
		0xC346FBB14F4C1A88ULL,
		0x06AB6564B084ED19ULL,
		0xF326F0B083FD7E0FULL,
		0x7DD6E50D14D5CA66ULL,
		0x01F30CE96507638AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x59C61C2A36CA928CULL,
		0xBBC3158F4F40A670ULL,
		0xD07070F6E7122E96ULL,
		0x868DF7629E983511ULL,
		0x0D56CAC96109DA33ULL,
		0xE64DE16107FAFC1EULL,
		0xFBADCA1A29AB94CDULL,
		0x03E619D2CA0EC714ULL
	}};
	printf("Test Case 500\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
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