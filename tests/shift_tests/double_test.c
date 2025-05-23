#include "../tests.h"

int32_t curve25519_key_x2_test(void) {
	printf("Key Doubling Test\n");
	curve25519_key_t k1 = {.key64 = {
		0x8FB5AA5712C29465ULL,
		0x7E16C1178C046E9EULL,
		0xAFDDD8749B37114EULL,
		0x1BEC161911F6684DULL,
		0x826AE0186550074FULL,
		0x389DD7390B2F5109ULL,
		0x47CAE5D60B4E6016ULL,
		0x31D65FB97AEBAB80ULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0x1F6B54AE258528CAULL,
		0xFC2D822F1808DD3DULL,
		0x5FBBB0E9366E229CULL,
		0x37D82C3223ECD09BULL,
		0x04D5C030CAA00E9EULL,
		0x713BAE72165EA213ULL,
		0x8F95CBAC169CC02CULL,
		0x63ACBF72F5D75700ULL
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
		0xFF4D66BE4AD1CDB0ULL,
		0x6228D4994082367BULL,
		0x72347441F35B11B2ULL,
		0x8507D5301109AF6CULL,
		0x22C03FF541E8115AULL,
		0xE5FBAB40E395E5C8ULL,
		0xD876CAD713C0F766ULL,
		0x10F4499355B46C9AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFE9ACD7C95A39B60ULL,
		0xC451A93281046CF7ULL,
		0xE468E883E6B62364ULL,
		0x0A0FAA6022135ED8ULL,
		0x45807FEA83D022B5ULL,
		0xCBF75681C72BCB90ULL,
		0xB0ED95AE2781EECDULL,
		0x21E89326AB68D935ULL
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
		0x1F0CC09CE89BA87DULL,
		0xB3B7D6F378E1E727ULL,
		0x13FD6EADDFEF59DDULL,
		0xE5DAEDCE8A369BF7ULL,
		0x85E1FDA8EB4BFB49ULL,
		0x901D13106808A7C0ULL,
		0xF2F74BEDA6E3FEC3ULL,
		0x0266F3FAEFFD7049ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3E198139D13750FAULL,
		0x676FADE6F1C3CE4EULL,
		0x27FADD5BBFDEB3BBULL,
		0xCBB5DB9D146D37EEULL,
		0x0BC3FB51D697F693ULL,
		0x203A2620D0114F81ULL,
		0xE5EE97DB4DC7FD87ULL,
		0x04CDE7F5DFFAE093ULL
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
		0x12E42B1EDBE1F0ADULL,
		0x56E37F82BEB7694EULL,
		0x9D868B35D3C109C4ULL,
		0x70831066E43B155EULL,
		0x2FA03813109B569BULL,
		0xF14B976685D0A60AULL,
		0xAAD06EAD3C550E24ULL,
		0x090D5096CD1B03D8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x25C8563DB7C3E15AULL,
		0xADC6FF057D6ED29CULL,
		0x3B0D166BA7821388ULL,
		0xE10620CDC8762ABDULL,
		0x5F4070262136AD36ULL,
		0xE2972ECD0BA14C14ULL,
		0x55A0DD5A78AA1C49ULL,
		0x121AA12D9A3607B1ULL
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
		0x9B6BF10B13CDD6D1ULL,
		0xC885B1F53DEC7A6CULL,
		0x77B8E8DD34D986F4ULL,
		0xE0D30272422EC595ULL,
		0xD978A349386EA704ULL,
		0x8A00584AE96AF595ULL,
		0x1FBB08814CB737ECULL,
		0x33AD71D2F02556E6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x36D7E216279BADA2ULL,
		0x910B63EA7BD8F4D9ULL,
		0xEF71D1BA69B30DE9ULL,
		0xC1A604E4845D8B2AULL,
		0xB2F1469270DD4E09ULL,
		0x1400B095D2D5EB2BULL,
		0x3F761102996E6FD9ULL,
		0x675AE3A5E04AADCCULL
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
		0xC906E37A8748E5C6ULL,
		0x3B2B597AC7081197ULL,
		0xF55178F6A7682F01ULL,
		0x30A36EEC4E937EA6ULL,
		0x226996EA396F173DULL,
		0x9370C92070B6CDA7ULL,
		0x052E5AE13852385EULL,
		0x278B5757F2491749ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x920DC6F50E91CB8CULL,
		0x7656B2F58E10232FULL,
		0xEAA2F1ED4ED05E02ULL,
		0x6146DDD89D26FD4DULL,
		0x44D32DD472DE2E7AULL,
		0x26E19240E16D9B4EULL,
		0x0A5CB5C270A470BDULL,
		0x4F16AEAFE4922E92ULL
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
		0x659F6432AD64E0D9ULL,
		0x98D66B0C9D68F90CULL,
		0x71573427483CFB4FULL,
		0x341BA196C8657C9CULL,
		0x1BA4942B2E1C414CULL,
		0x256F19B94DC659A3ULL,
		0x98078D882751C29FULL,
		0x37E7D64539E91CB1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCB3EC8655AC9C1B2ULL,
		0x31ACD6193AD1F218ULL,
		0xE2AE684E9079F69FULL,
		0x6837432D90CAF938ULL,
		0x374928565C388298ULL,
		0x4ADE33729B8CB346ULL,
		0x300F1B104EA3853EULL,
		0x6FCFAC8A73D23963ULL
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
		0x46EE3480BCEDD67FULL,
		0xA4303D7C7EE650D7ULL,
		0x6B98D92E1BFBD6FEULL,
		0xCB8E9458EF5E50F5ULL,
		0xCB833CEE306C119DULL,
		0xC83AFF8F3F099486ULL,
		0x733F251932A2BE1BULL,
		0x22BE73C238A5075FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8DDC690179DBACFEULL,
		0x48607AF8FDCCA1AEULL,
		0xD731B25C37F7ADFDULL,
		0x971D28B1DEBCA1EAULL,
		0x970679DC60D8233BULL,
		0x9075FF1E7E13290DULL,
		0xE67E4A3265457C37ULL,
		0x457CE784714A0EBEULL
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
		0x366E9E861D74E678ULL,
		0x0A9ABA103DBC14FEULL,
		0x3663DC1050D93FD7ULL,
		0xB31F2D58D32B93BEULL,
		0xE0002DBB235F0262ULL,
		0x42FC3873943DD12CULL,
		0x9D5BB90C0261F8CEULL,
		0x2AE8A3F9BC4BCAFFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6CDD3D0C3AE9CCF0ULL,
		0x153574207B7829FCULL,
		0x6CC7B820A1B27FAEULL,
		0x663E5AB1A657277CULL,
		0xC0005B7646BE04C5ULL,
		0x85F870E7287BA259ULL,
		0x3AB7721804C3F19CULL,
		0x55D147F3789795FFULL
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
		0x24C8D0D2288F6915ULL,
		0x81B430C0593D7AABULL,
		0xF06097FFB04EB15BULL,
		0x2DDB6BDF0649092CULL,
		0x9AC8231919ACBEE6ULL,
		0x02438EAF9A34B7E1ULL,
		0x178D5F7F1BB998E8ULL,
		0x1EAC228AC06E9E47ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4991A1A4511ED22AULL,
		0x03686180B27AF556ULL,
		0xE0C12FFF609D62B7ULL,
		0x5BB6D7BE0C921259ULL,
		0x3590463233597DCCULL,
		0x04871D5F34696FC3ULL,
		0x2F1ABEFE377331D0ULL,
		0x3D58451580DD3C8EULL
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
		0x2375B73CA0AA8012ULL,
		0xA9F83EDD8F87A507ULL,
		0x9067D31A30D8D912ULL,
		0x18463A054C89BC6DULL,
		0xE82C8B4050D08FB0ULL,
		0xD6B95B02928F6EE6ULL,
		0x7DE520C565C6A255ULL,
		0x213C595C2B470DC5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x46EB6E7941550024ULL,
		0x53F07DBB1F0F4A0EULL,
		0x20CFA63461B1B225ULL,
		0x308C740A991378DBULL,
		0xD0591680A1A11F60ULL,
		0xAD72B605251EDDCDULL,
		0xFBCA418ACB8D44ABULL,
		0x4278B2B8568E1B8AULL
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
		0x459D5C7F8EB65A14ULL,
		0x1422E00F65A5359CULL,
		0x6583A5110B5AAF7AULL,
		0x96DC3E575A45149EULL,
		0x96F458D32846A8E3ULL,
		0xC576B55F92232125ULL,
		0xBD60C94C2B87E8F0ULL,
		0x0E49E6B75F181ADFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8B3AB8FF1D6CB428ULL,
		0x2845C01ECB4A6B38ULL,
		0xCB074A2216B55EF4ULL,
		0x2DB87CAEB48A293CULL,
		0x2DE8B1A6508D51C7ULL,
		0x8AED6ABF2446424BULL,
		0x7AC19298570FD1E1ULL,
		0x1C93CD6EBE3035BFULL
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
		0x3791ACA4FCFC76CEULL,
		0x29134855CB16CCB8ULL,
		0xFBA58121AB7C1BA8ULL,
		0xA13D8345A240D6B2ULL,
		0xF11EFB48C86EA93AULL,
		0x4E17CEFFA823233DULL,
		0x3028F81AA4E828DDULL,
		0x28564184206CEE5AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6F235949F9F8ED9CULL,
		0x522690AB962D9970ULL,
		0xF74B024356F83750ULL,
		0x427B068B4481AD65ULL,
		0xE23DF69190DD5275ULL,
		0x9C2F9DFF5046467BULL,
		0x6051F03549D051BAULL,
		0x50AC830840D9DCB4ULL
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
		0x061BFE53DAFAB501ULL,
		0x4B9CA2B4A9B5D651ULL,
		0xF814402CAD6C985BULL,
		0x2EA9F633AD594FDBULL,
		0x045E444A52C69839ULL,
		0xA92B1CBD28155DBBULL,
		0xFFB73514AD0FA477ULL,
		0x39D8226EE257CA85ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0C37FCA7B5F56A02ULL,
		0x97394569536BACA2ULL,
		0xF02880595AD930B6ULL,
		0x5D53EC675AB29FB7ULL,
		0x08BC8894A58D3072ULL,
		0x5256397A502ABB76ULL,
		0xFF6E6A295A1F48EFULL,
		0x73B044DDC4AF950BULL
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
		0x1E7C1D456E0BD936ULL,
		0x1DAF1E9E83BD4075ULL,
		0xA798D732D8B82B17ULL,
		0xF31094666DEA3D1EULL,
		0x640125EB080B3EF7ULL,
		0xC0E046298981EE1BULL,
		0x9C24DC44E79AE7DEULL,
		0x124B1AC898DBAD92ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3CF83A8ADC17B26CULL,
		0x3B5E3D3D077A80EAULL,
		0x4F31AE65B170562EULL,
		0xE62128CCDBD47A3DULL,
		0xC8024BD610167DEFULL,
		0x81C08C531303DC36ULL,
		0x3849B889CF35CFBDULL,
		0x2496359131B75B25ULL
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
		0xC4BB12FE8ECBFB9AULL,
		0x076BB7B60DB6782AULL,
		0x66ACE60B3B7CBD65ULL,
		0x99D84E1B86B617F0ULL,
		0x2B3901E03C3CEE45ULL,
		0x947997679D6852A3ULL,
		0x226923A44B71FBFDULL,
		0x1B24798A2F9804FAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x897625FD1D97F734ULL,
		0x0ED76F6C1B6CF055ULL,
		0xCD59CC1676F97ACAULL,
		0x33B09C370D6C2FE0ULL,
		0x567203C07879DC8BULL,
		0x28F32ECF3AD0A546ULL,
		0x44D2474896E3F7FBULL,
		0x3648F3145F3009F4ULL
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
		0x3E0B10DE48A17804ULL,
		0x4AEF7A8CD8A33864ULL,
		0x72BF298F3123ACC7ULL,
		0x14634A3BD3468E13ULL,
		0xC9E313C26DF2287DULL,
		0xE9B23D79829F4375ULL,
		0xB9CDD69CAEA3D218ULL,
		0x2032893557B7F7C9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7C1621BC9142F008ULL,
		0x95DEF519B14670C8ULL,
		0xE57E531E6247598EULL,
		0x28C69477A68D1C26ULL,
		0x93C62784DBE450FAULL,
		0xD3647AF3053E86EBULL,
		0x739BAD395D47A431ULL,
		0x4065126AAF6FEF93ULL
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
		0x0BF100236D38CE8FULL,
		0xAC97439A3F8B77CEULL,
		0x026B5934078996ADULL,
		0x23D7247B5842BABFULL,
		0xB725D1C64CDD07AAULL,
		0x4B4FF3C52300253FULL,
		0x486BC7EC54D8C8D8ULL,
		0x095A8A904C6A99CDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x17E20046DA719D1EULL,
		0x592E87347F16EF9CULL,
		0x04D6B2680F132D5BULL,
		0x47AE48F6B085757EULL,
		0x6E4BA38C99BA0F54ULL,
		0x969FE78A46004A7FULL,
		0x90D78FD8A9B191B0ULL,
		0x12B5152098D5339AULL
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
		0x80A57E99B08A6E84ULL,
		0x61EC0604CAC65A6DULL,
		0x185B5A70798912A1ULL,
		0x92EF55CBF5B25E5EULL,
		0x6D6D77DE4CDD0CEEULL,
		0x3B178800746CDF72ULL,
		0x461ADB9C0BAF4C25ULL,
		0x050C88DF1966A4A3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x014AFD336114DD08ULL,
		0xC3D80C09958CB4DBULL,
		0x30B6B4E0F3122542ULL,
		0x25DEAB97EB64BCBCULL,
		0xDADAEFBC99BA19DDULL,
		0x762F1000E8D9BEE4ULL,
		0x8C35B738175E984AULL,
		0x0A1911BE32CD4946ULL
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
		0xE4B2F40312CB905BULL,
		0x8EBBB04870A148DBULL,
		0x86F267E18DF084BEULL,
		0x7223F1B1D7F138F9ULL,
		0x3CA6101A9009B262ULL,
		0xEAA00EBEDEF083CEULL,
		0x8B44720A5EE811F0ULL,
		0x05B1ACCFE9571A4DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC965E806259720B6ULL,
		0x1D776090E14291B7ULL,
		0x0DE4CFC31BE1097DULL,
		0xE447E363AFE271F3ULL,
		0x794C2035201364C4ULL,
		0xD5401D7DBDE1079CULL,
		0x1688E414BDD023E1ULL,
		0x0B63599FD2AE349BULL
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
		0x87D4F24D274F52B5ULL,
		0xFD0978E3D4E5D8A5ULL,
		0x52BAC96EBA23CD10ULL,
		0x426C256AA0E86AE2ULL,
		0xAFDAB2120EDC5255ULL,
		0x3A11F2165619948FULL,
		0x3A4A851FBC0485DEULL,
		0x02C8C6EEC30C7845ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0FA9E49A4E9EA56AULL,
		0xFA12F1C7A9CBB14BULL,
		0xA57592DD74479A21ULL,
		0x84D84AD541D0D5C4ULL,
		0x5FB564241DB8A4AAULL,
		0x7423E42CAC33291FULL,
		0x74950A3F78090BBCULL,
		0x05918DDD8618F08AULL
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
		0x6D74815AB676BEC6ULL,
		0xAABE95649A7D7076ULL,
		0x138EDC1B7F0AD59FULL,
		0xA39731D625400A54ULL,
		0x16AD007314C62582ULL,
		0xC58B8B85E59E2748ULL,
		0xF8542EDCC78CC687ULL,
		0x107F8619F5EADC83ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDAE902B56CED7D8CULL,
		0x557D2AC934FAE0ECULL,
		0x271DB836FE15AB3FULL,
		0x472E63AC4A8014A8ULL,
		0x2D5A00E6298C4B05ULL,
		0x8B17170BCB3C4E90ULL,
		0xF0A85DB98F198D0FULL,
		0x20FF0C33EBD5B907ULL
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
		0xDD676C53D6233866ULL,
		0xC2BBF7FE70D67612ULL,
		0x85688805F6086868ULL,
		0xEDB17D6A42C33FEFULL,
		0x6D2E2158606831A5ULL,
		0xE00B43C4274CE5B3ULL,
		0xD5BA331ED4B7A7BBULL,
		0x2887AFAF08E4E08CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBACED8A7AC4670CCULL,
		0x8577EFFCE1ACEC25ULL,
		0x0AD1100BEC10D0D1ULL,
		0xDB62FAD485867FDFULL,
		0xDA5C42B0C0D0634BULL,
		0xC01687884E99CB66ULL,
		0xAB74663DA96F4F77ULL,
		0x510F5F5E11C9C119ULL
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
		0x2138DEE4E9F8DBBEULL,
		0x611903332996A2BBULL,
		0xAC9A37A6EB6CA3A6ULL,
		0xC39418761C2F20DCULL,
		0x45C020B38EA82409ULL,
		0xC803DEB6329134D0ULL,
		0x8EFE40C60718FF30ULL,
		0x3B70AD26AD287823ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4271BDC9D3F1B77CULL,
		0xC2320666532D4576ULL,
		0x59346F4DD6D9474CULL,
		0x872830EC385E41B9ULL,
		0x8B8041671D504813ULL,
		0x9007BD6C652269A0ULL,
		0x1DFC818C0E31FE61ULL,
		0x76E15A4D5A50F047ULL
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
		0x60794784F5986ACEULL,
		0xAF6C8333690D8D63ULL,
		0xE6940C76619BA230ULL,
		0x20B92D65ED8FB4DEULL,
		0x186E9D448B6BAE91ULL,
		0x7AE2E12D62A73F14ULL,
		0x9A7ACA32A85A7B1FULL,
		0x07775D5BCC6F1429ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC0F28F09EB30D59CULL,
		0x5ED90666D21B1AC6ULL,
		0xCD2818ECC3374461ULL,
		0x41725ACBDB1F69BDULL,
		0x30DD3A8916D75D22ULL,
		0xF5C5C25AC54E7E28ULL,
		0x34F5946550B4F63EULL,
		0x0EEEBAB798DE2853ULL
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
		0x02E58ADB8CA0DEEFULL,
		0x72D8C82D81157C2DULL,
		0x75146F2DAD04DC0AULL,
		0x81F95F3FCA2D038CULL,
		0xFD8A689BF86C8D16ULL,
		0xCFA3DB08B5A1ACC8ULL,
		0xE7E0A98994EDE1E8ULL,
		0x38B48AD8A16F896AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x05CB15B71941BDDEULL,
		0xE5B1905B022AF85AULL,
		0xEA28DE5B5A09B814ULL,
		0x03F2BE7F945A0718ULL,
		0xFB14D137F0D91A2DULL,
		0x9F47B6116B435991ULL,
		0xCFC1531329DBC3D1ULL,
		0x716915B142DF12D5ULL
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
		0x2F74F1D4D9A45A8EULL,
		0x410D164DBE59AD12ULL,
		0x627034B9A570EE47ULL,
		0x05B7229C4E11424BULL,
		0xD6A4414684C5CBA8ULL,
		0x15C2D525589C49E3ULL,
		0xB64660BB7C4C83E4ULL,
		0x028F3413ECE11264ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5EE9E3A9B348B51CULL,
		0x821A2C9B7CB35A24ULL,
		0xC4E069734AE1DC8EULL,
		0x0B6E45389C228496ULL,
		0xAD48828D098B9750ULL,
		0x2B85AA4AB13893C7ULL,
		0x6C8CC176F89907C8ULL,
		0x051E6827D9C224C9ULL
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
		0x1CE3B0BEE1007713ULL,
		0x1C49BC6F3B4F2AF4ULL,
		0xE0DC8FC87A2904F6ULL,
		0x7BC4E2B802B92C0FULL,
		0xF55475D82B26FFAEULL,
		0xF62F7F6EE88A979CULL,
		0xC19FA958287C4A42ULL,
		0x167ABCE4BD83A6D5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x39C7617DC200EE26ULL,
		0x389378DE769E55E8ULL,
		0xC1B91F90F45209ECULL,
		0xF789C5700572581FULL,
		0xEAA8EBB0564DFF5CULL,
		0xEC5EFEDDD1152F39ULL,
		0x833F52B050F89485ULL,
		0x2CF579C97B074DABULL
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
		0x3DC1EE42A9ED3E81ULL,
		0xF235F673F602F7C8ULL,
		0xE07E315FF7E7D220ULL,
		0x0E4B1837440AFEBAULL,
		0xBB7DC35441B7E6A1ULL,
		0x39C06F3702D5B669ULL,
		0x63BA3AB5A3723409ULL,
		0x1756CFCE1B8AAD3DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7B83DC8553DA7D02ULL,
		0xE46BECE7EC05EF90ULL,
		0xC0FC62BFEFCFA441ULL,
		0x1C96306E8815FD75ULL,
		0x76FB86A8836FCD42ULL,
		0x7380DE6E05AB6CD3ULL,
		0xC774756B46E46812ULL,
		0x2EAD9F9C37155A7AULL
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
		0x0AE414AE62F2D54CULL,
		0x9D1C0E1D17912B09ULL,
		0x92AE401E558F8447ULL,
		0xF17AA5430F0F81DDULL,
		0x30BA8979EEECFCFBULL,
		0x718C5BED9FAECF3DULL,
		0xDBC8B3217B58F11EULL,
		0x249AC04480FB16ECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x15C8295CC5E5AA98ULL,
		0x3A381C3A2F225612ULL,
		0x255C803CAB1F088FULL,
		0xE2F54A861E1F03BBULL,
		0x617512F3DDD9F9F7ULL,
		0xE318B7DB3F5D9E7AULL,
		0xB7916642F6B1E23CULL,
		0x4935808901F62DD9ULL
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
		0xEFFD58731245FC8CULL,
		0x298AFFD01BD6678DULL,
		0x00A739911370ED43ULL,
		0xD8121079AAC4B2B5ULL,
		0x1EBF34F45003F562ULL,
		0x213FB116F7196C98ULL,
		0xB5D175C0BD023E5EULL,
		0x1D230B95468C49C1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDFFAB0E6248BF918ULL,
		0x5315FFA037ACCF1BULL,
		0x014E732226E1DA86ULL,
		0xB02420F35589656AULL,
		0x3D7E69E8A007EAC5ULL,
		0x427F622DEE32D930ULL,
		0x6BA2EB817A047CBCULL,
		0x3A46172A8D189383ULL
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
		0x29623207B03D95CBULL,
		0x772BCE888FA60672ULL,
		0xEDF8529C3C6F5801ULL,
		0xDC5E40BDA2F4F887ULL,
		0x59DC4B083E0101A1ULL,
		0x12B04420AE28C2D0ULL,
		0x0AC65E1B553A313AULL,
		0x321289EC141DA95BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x52C4640F607B2B96ULL,
		0xEE579D111F4C0CE4ULL,
		0xDBF0A53878DEB002ULL,
		0xB8BC817B45E9F10FULL,
		0xB3B896107C020343ULL,
		0x256088415C5185A0ULL,
		0x158CBC36AA746274ULL,
		0x642513D8283B52B6ULL
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
		0xCDD07CE24E17732CULL,
		0x873099A1429695F5ULL,
		0x37EB804479F24141ULL,
		0xCF152EAADD6EF40CULL,
		0x54A9EB0733884531ULL,
		0x8A795043595F63B5ULL,
		0x41CECCF44AC850C9ULL,
		0x3B9EFC20ADCB15C1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9BA0F9C49C2EE658ULL,
		0x0E613342852D2BEBULL,
		0x6FD70088F3E48283ULL,
		0x9E2A5D55BADDE818ULL,
		0xA953D60E67108A63ULL,
		0x14F2A086B2BEC76AULL,
		0x839D99E89590A193ULL,
		0x773DF8415B962B82ULL
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
		0x522FC451809EE77EULL,
		0xA94A77B232D0F960ULL,
		0x9AE33D49C2D009FAULL,
		0xB1C8A88F85D91540ULL,
		0x0D8821D06EF1C4B9ULL,
		0x4A574D8216337BEBULL,
		0x6745394D3D8696B0ULL,
		0x1CB88BC5CD1EE96FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA45F88A3013DCEFCULL,
		0x5294EF6465A1F2C0ULL,
		0x35C67A9385A013F5ULL,
		0x6391511F0BB22A81ULL,
		0x1B1043A0DDE38973ULL,
		0x94AE9B042C66F7D6ULL,
		0xCE8A729A7B0D2D60ULL,
		0x3971178B9A3DD2DEULL
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
		0x6EA9322DD6B78A8CULL,
		0x4A26C751C02C49C5ULL,
		0xF012D3373078D205ULL,
		0x38AAB5C95EF0C95BULL,
		0x258F67F93B8D0A4DULL,
		0x292E33BD5C26F491ULL,
		0x0271C0A3E0C37B56ULL,
		0x2199B37BFC59A679ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDD52645BAD6F1518ULL,
		0x944D8EA38058938AULL,
		0xE025A66E60F1A40AULL,
		0x71556B92BDE192B7ULL,
		0x4B1ECFF2771A149AULL,
		0x525C677AB84DE922ULL,
		0x04E38147C186F6ACULL,
		0x433366F7F8B34CF2ULL
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
		0x075958EFAEEFE664ULL,
		0x85EA8EE42231E81AULL,
		0xFCEDD36B8FC6B8F1ULL,
		0x28CFC53C525E676CULL,
		0xEB2FE8A97EC96DBBULL,
		0xDE6C1CFC15E61FAAULL,
		0x9D07A7CD210BE5EEULL,
		0x2D479758D588C0E3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0EB2B1DF5DDFCCC8ULL,
		0x0BD51DC84463D034ULL,
		0xF9DBA6D71F8D71E3ULL,
		0x519F8A78A4BCCED9ULL,
		0xD65FD152FD92DB76ULL,
		0xBCD839F82BCC3F55ULL,
		0x3A0F4F9A4217CBDDULL,
		0x5A8F2EB1AB1181C7ULL
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
		0x5A2AAFB7D089BD8EULL,
		0x945E1997FD614FCEULL,
		0x8E1DDE33F8194B4FULL,
		0xCBA1A022383D1564ULL,
		0x65DFD16EADCB2417ULL,
		0xA39715DF60B74F68ULL,
		0x75E29ED74AEF459DULL,
		0x240ECC1B6BF9B881ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB4555F6FA1137B1CULL,
		0x28BC332FFAC29F9CULL,
		0x1C3BBC67F032969FULL,
		0x97434044707A2AC9ULL,
		0xCBBFA2DD5B96482FULL,
		0x472E2BBEC16E9ED0ULL,
		0xEBC53DAE95DE8B3BULL,
		0x481D9836D7F37102ULL
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
		0xC6F02F031E093EDBULL,
		0x8A4D53B7C93EAFA7ULL,
		0x81F73BE4B0CA5653ULL,
		0x7D17E48C01EF0FB9ULL,
		0xF5AE94F0E56BFE62ULL,
		0x9A037BF0E7ED762CULL,
		0x81BA26C8D4686D2FULL,
		0x1DA6CAB867CFB847ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8DE05E063C127DB6ULL,
		0x149AA76F927D5F4FULL,
		0x03EE77C96194ACA7ULL,
		0xFA2FC91803DE1F73ULL,
		0xEB5D29E1CAD7FCC4ULL,
		0x3406F7E1CFDAEC59ULL,
		0x03744D91A8D0DA5FULL,
		0x3B4D9570CF9F708FULL
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
		0xA1AFBBB29DCFF1E6ULL,
		0x14939C6E2E3858F2ULL,
		0x5D3F70B95BC8DE69ULL,
		0x87EFEB49A840CF34ULL,
		0x368D9E2FC97D02D7ULL,
		0x80138607AF1B2E15ULL,
		0xCE34403C5B7D5A21ULL,
		0x24C87F68B0512AE7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x435F77653B9FE3CCULL,
		0x292738DC5C70B1E5ULL,
		0xBA7EE172B791BCD2ULL,
		0x0FDFD69350819E68ULL,
		0x6D1B3C5F92FA05AFULL,
		0x00270C0F5E365C2AULL,
		0x9C688078B6FAB443ULL,
		0x4990FED160A255CFULL
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
		0x538585956CFE5FCEULL,
		0x7EDB3970A2101157ULL,
		0x8570472C56CCF399ULL,
		0xB5652496F456D97FULL,
		0x58CD2B1C66E12B11ULL,
		0x90E5625F90572712ULL,
		0xCFA7F11D2A49FB30ULL,
		0x15AF9FFF759EEB16ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA70B0B2AD9FCBF9CULL,
		0xFDB672E1442022AEULL,
		0x0AE08E58AD99E732ULL,
		0x6ACA492DE8ADB2FFULL,
		0xB19A5638CDC25623ULL,
		0x21CAC4BF20AE4E24ULL,
		0x9F4FE23A5493F661ULL,
		0x2B5F3FFEEB3DD62DULL
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
		0x7C654C8C0DDA93B8ULL,
		0x918A8737C2A061B7ULL,
		0xE029F3D05745EABEULL,
		0x4B1B4804EAB52F92ULL,
		0x8AF8F4A785016787ULL,
		0xB160DA8A9C381529ULL,
		0x2AAEE11D53CAFBB1ULL,
		0x0E5AAE827F5E785FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF8CA99181BB52770ULL,
		0x23150E6F8540C36EULL,
		0xC053E7A0AE8BD57DULL,
		0x96369009D56A5F25ULL,
		0x15F1E94F0A02CF0EULL,
		0x62C1B51538702A53ULL,
		0x555DC23AA795F763ULL,
		0x1CB55D04FEBCF0BEULL
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
		0x826145C2FB3AB0C2ULL,
		0x822CD14B348FF225ULL,
		0xA325D99AD14B227DULL,
		0x84C74A093F28F2EBULL,
		0xC3EF323BC1B588B3ULL,
		0xD7B357F6E600EECBULL,
		0x538CA44FD32446A5ULL,
		0x32E869375429D0A8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x04C28B85F6756184ULL,
		0x0459A296691FE44BULL,
		0x464BB335A29644FBULL,
		0x098E94127E51E5D7ULL,
		0x87DE6477836B1167ULL,
		0xAF66AFEDCC01DD97ULL,
		0xA719489FA6488D4BULL,
		0x65D0D26EA853A150ULL
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
		0x6D28294E228ECF8FULL,
		0x3B0AC9A23A4D52E4ULL,
		0x7F0E82EA4F3A649FULL,
		0xFE177442BD20A75CULL,
		0x8510058A40C25C4DULL,
		0x2E8111B44941916FULL,
		0xC132EE16ED11D083ULL,
		0x34DCC73491DD95DAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDA50529C451D9F1EULL,
		0x76159344749AA5C8ULL,
		0xFE1D05D49E74C93EULL,
		0xFC2EE8857A414EB8ULL,
		0x0A200B148184B89BULL,
		0x5D022368928322DFULL,
		0x8265DC2DDA23A106ULL,
		0x69B98E6923BB2BB5ULL
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
		0x6A39EE1A2A0C4239ULL,
		0xED5B968E7C9B56E9ULL,
		0x407B11FCF7CBE8F5ULL,
		0xCAD84794FAB69B54ULL,
		0xC1698463886F69E5ULL,
		0x991F63273218987EULL,
		0xDA58A7BE57BC6ECFULL,
		0x1197930769404BE5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD473DC3454188472ULL,
		0xDAB72D1CF936ADD2ULL,
		0x80F623F9EF97D1EBULL,
		0x95B08F29F56D36A8ULL,
		0x82D308C710DED3CBULL,
		0x323EC64E643130FDULL,
		0xB4B14F7CAF78DD9FULL,
		0x232F260ED28097CBULL
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
		0x1DF5C18CF7386909ULL,
		0xF20A067BD1C5036AULL,
		0x7FDA5DC66335B110ULL,
		0x710420ED8FE58360ULL,
		0xCAC077B84CB5F9ADULL,
		0xE57D06D1DB32CE06ULL,
		0x6E538BE7BFC259FEULL,
		0x184B7677280E3B30ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3BEB8319EE70D212ULL,
		0xE4140CF7A38A06D4ULL,
		0xFFB4BB8CC66B6221ULL,
		0xE20841DB1FCB06C0ULL,
		0x9580EF70996BF35AULL,
		0xCAFA0DA3B6659C0DULL,
		0xDCA717CF7F84B3FDULL,
		0x3096ECEE501C7660ULL
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
		0x434F321A31999F38ULL,
		0x588E5E0EA3F6841EULL,
		0xBFAFAC72C10F80A5ULL,
		0x5A8CA15534B82C24ULL,
		0xE46E2D81C1E5F533ULL,
		0x7B5C50DA4119D71DULL,
		0x0123A5FE16CA1800ULL,
		0x3ADDECC245562FA8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x869E643463333E70ULL,
		0xB11CBC1D47ED083CULL,
		0x7F5F58E5821F014AULL,
		0xB51942AA69705849ULL,
		0xC8DC5B0383CBEA66ULL,
		0xF6B8A1B48233AE3BULL,
		0x02474BFC2D943000ULL,
		0x75BBD9848AAC5F50ULL
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
		0x44BDC344D76D172CULL,
		0xBDCD72931456068EULL,
		0x59E3EE39E983B15BULL,
		0xBB28CBFD3C3BE8FEULL,
		0x555E9FEBE876E46DULL,
		0x3415114F360DE325ULL,
		0x57DD6C679FC930B4ULL,
		0x2BD4DC1F8AD51E7AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x897B8689AEDA2E58ULL,
		0x7B9AE52628AC0D1CULL,
		0xB3C7DC73D30762B7ULL,
		0x765197FA7877D1FCULL,
		0xAABD3FD7D0EDC8DBULL,
		0x682A229E6C1BC64AULL,
		0xAFBAD8CF3F926168ULL,
		0x57A9B83F15AA3CF4ULL
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
		0x3BACAC99EC44CB58ULL,
		0xCDD8399F76E9A77DULL,
		0x7DE864143A9E56B9ULL,
		0x55D8A422442889E5ULL,
		0xEA3009225D874A8DULL,
		0x6AB62C0369126E96ULL,
		0x4710115C5DCBEE6DULL,
		0x15871C1388A89BB2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x77595933D88996B0ULL,
		0x9BB0733EEDD34EFAULL,
		0xFBD0C828753CAD73ULL,
		0xABB14844885113CAULL,
		0xD4601244BB0E951AULL,
		0xD56C5806D224DD2DULL,
		0x8E2022B8BB97DCDAULL,
		0x2B0E382711513764ULL
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
		0xA1A37D32B4B4CC08ULL,
		0xB33A8D4BA6191B3DULL,
		0x3FE00AA0F5DA18C2ULL,
		0x1F3A519A7BECA67EULL,
		0x3BC3C1A1228978CDULL,
		0x09A51D0D93EBA08FULL,
		0xEDBE9AD96D6EFD8FULL,
		0x3129FFC6823F52FAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4346FA6569699810ULL,
		0x66751A974C32367BULL,
		0x7FC01541EBB43185ULL,
		0x3E74A334F7D94CFCULL,
		0x778783424512F19AULL,
		0x134A3A1B27D7411EULL,
		0xDB7D35B2DADDFB1EULL,
		0x6253FF8D047EA5F5ULL
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
		0x1ED4B16073C95B7DULL,
		0x6A2D218FEA6D0135ULL,
		0x62065E70208ACA5AULL,
		0xFA2A5C01554EA1C7ULL,
		0xC19AD7FF121C15FBULL,
		0x70817ABB8BB073B5ULL,
		0x895F2B474475E4E8ULL,
		0x2CDC59292B9247ECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3DA962C0E792B6FAULL,
		0xD45A431FD4DA026AULL,
		0xC40CBCE0411594B4ULL,
		0xF454B802AA9D438EULL,
		0x8335AFFE24382BF7ULL,
		0xE102F5771760E76BULL,
		0x12BE568E88EBC9D0ULL,
		0x59B8B25257248FD9ULL
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
		0x49EAB988B0489B5BULL,
		0x032063FBBD799970ULL,
		0xC012E0556F554090ULL,
		0x69E602C98B9DBEDEULL,
		0x468DC15E203C928CULL,
		0x593B192A0265059BULL,
		0x6B252F408FC548ABULL,
		0x13ABCF0D2AC9F803ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x93D57311609136B6ULL,
		0x0640C7F77AF332E0ULL,
		0x8025C0AADEAA8120ULL,
		0xD3CC0593173B7DBDULL,
		0x8D1B82BC40792518ULL,
		0xB276325404CA0B36ULL,
		0xD64A5E811F8A9156ULL,
		0x27579E1A5593F006ULL
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
		0x5DD5F774CA0A318DULL,
		0x3AE2529AECA97F48ULL,
		0xD564DF20CC308257ULL,
		0xD8D0BCCC0F2E32A3ULL,
		0x3461EB00B50EE1D4ULL,
		0xA5E962385B7D8A62ULL,
		0x70FB10897786CA72ULL,
		0x3913EE1C99E4FDAAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBBABEEE99414631AULL,
		0x75C4A535D952FE90ULL,
		0xAAC9BE41986104AEULL,
		0xB1A179981E5C6547ULL,
		0x68C3D6016A1DC3A9ULL,
		0x4BD2C470B6FB14C4ULL,
		0xE1F62112EF0D94E5ULL,
		0x7227DC3933C9FB54ULL
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
		0xD2BDB34C1FBF7EAAULL,
		0x0CC6196D2AB68448ULL,
		0x9D3A127D44A795A4ULL,
		0x4DAE68FD9346D25EULL,
		0x20B0FE1EB39D1CFFULL,
		0xC7CA5EA9039F4CEEULL,
		0x6D1336D6AE6FF462ULL,
		0x151A903D27DBCF04ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA57B66983F7EFD54ULL,
		0x198C32DA556D0891ULL,
		0x3A7424FA894F2B48ULL,
		0x9B5CD1FB268DA4BDULL,
		0x4161FC3D673A39FEULL,
		0x8F94BD52073E99DCULL,
		0xDA266DAD5CDFE8C5ULL,
		0x2A35207A4FB79E08ULL
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
		0xC77476AAB0E3B32DULL,
		0xE0BC1E025BCECB6AULL,
		0xFEFBD916874EFACDULL,
		0x7DF9AF27D8096C15ULL,
		0x6CF025ABDD8D02EFULL,
		0x3F0D8B3F591100C3ULL,
		0x473E6B53E1FC09B6ULL,
		0x0AE787D4C379324CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8EE8ED5561C7665AULL,
		0xC1783C04B79D96D5ULL,
		0xFDF7B22D0E9DF59BULL,
		0xFBF35E4FB012D82BULL,
		0xD9E04B57BB1A05DEULL,
		0x7E1B167EB2220186ULL,
		0x8E7CD6A7C3F8136CULL,
		0x15CF0FA986F26498ULL
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
		0x418EAA71A7D9DBA3ULL,
		0xF8309B9FF83D4321ULL,
		0x7BF9B4C665315D09ULL,
		0x3F2BD080E3F24396ULL,
		0xAFAA8D206F61C95CULL,
		0xF50C321D1013BBBAULL,
		0x956480B9E18B3664ULL,
		0x14C7A4B6B94B47C7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x831D54E34FB3B746ULL,
		0xF061373FF07A8642ULL,
		0xF7F3698CCA62BA13ULL,
		0x7E57A101C7E4872CULL,
		0x5F551A40DEC392B8ULL,
		0xEA18643A20277775ULL,
		0x2AC90173C3166CC9ULL,
		0x298F496D72968F8FULL
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
		0x61133CA3E5B3DD3DULL,
		0xFE6A60116C45E3D0ULL,
		0xE1617FF654B6A2E7ULL,
		0x1D2A68A51540EE88ULL,
		0xA11CC5462E200686ULL,
		0xF96A165CE814E2BEULL,
		0x166A2AC34C5AF461ULL,
		0x036A12E9E5E09519ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC2267947CB67BA7AULL,
		0xFCD4C022D88BC7A0ULL,
		0xC2C2FFECA96D45CFULL,
		0x3A54D14A2A81DD11ULL,
		0x42398A8C5C400D0CULL,
		0xF2D42CB9D029C57DULL,
		0x2CD4558698B5E8C3ULL,
		0x06D425D3CBC12A32ULL
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
		0x6BE0BF05A78ED8A9ULL,
		0x36ACA5A96E82E141ULL,
		0xDCAF34CB60613A02ULL,
		0xD5E6186F9D8D828DULL,
		0xE6582FF4BFF76D13ULL,
		0xAE72A5DFCCDA18B3ULL,
		0x26B3DA381DE0B4CDULL,
		0x12CA89253B2F941AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD7C17E0B4F1DB152ULL,
		0x6D594B52DD05C282ULL,
		0xB95E6996C0C27404ULL,
		0xABCC30DF3B1B051BULL,
		0xCCB05FE97FEEDA27ULL,
		0x5CE54BBF99B43167ULL,
		0x4D67B4703BC1699BULL,
		0x2595124A765F2834ULL
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
		0x998643EB034E5DD1ULL,
		0x7735169F4045DFAAULL,
		0xBE961B73ADCF6854ULL,
		0x7E8B11097B2F82E2ULL,
		0x8CA0DFA528FEBCDFULL,
		0x865BFC8FCED294B4ULL,
		0xBE7FD69A480D12FEULL,
		0x1BF399EB2D05B410ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x330C87D6069CBBA2ULL,
		0xEE6A2D3E808BBF55ULL,
		0x7D2C36E75B9ED0A8ULL,
		0xFD162212F65F05C5ULL,
		0x1941BF4A51FD79BEULL,
		0x0CB7F91F9DA52969ULL,
		0x7CFFAD34901A25FDULL,
		0x37E733D65A0B6821ULL
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
		0xDF64D0D55AEA88C5ULL,
		0x119873C0014538E0ULL,
		0xF5B938FE5101C4DFULL,
		0xA11952AB37B5ADC8ULL,
		0x4C6E2072035721BCULL,
		0x821E0CEB88110123ULL,
		0xCB828B6FED89978EULL,
		0x00ADA0A4E0CF7D7AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBEC9A1AAB5D5118AULL,
		0x2330E780028A71C1ULL,
		0xEB7271FCA20389BEULL,
		0x4232A5566F6B5B91ULL,
		0x98DC40E406AE4379ULL,
		0x043C19D710220246ULL,
		0x970516DFDB132F1DULL,
		0x015B4149C19EFAF5ULL
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
		0xC7E4464D9BBDB340ULL,
		0xB993FDBFFF9115E3ULL,
		0xEEAE8224C7980DCFULL,
		0x7901FED7A203F35CULL,
		0x061B5501F9465D73ULL,
		0xF23F6C234ECA7E8DULL,
		0x22FCCA271BC816EEULL,
		0x1D414F67AF9C609AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8FC88C9B377B6680ULL,
		0x7327FB7FFF222BC7ULL,
		0xDD5D04498F301B9FULL,
		0xF203FDAF4407E6B9ULL,
		0x0C36AA03F28CBAE6ULL,
		0xE47ED8469D94FD1AULL,
		0x45F9944E37902DDDULL,
		0x3A829ECF5F38C134ULL
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
		0xA8CF72B31B7D1AE3ULL,
		0x34477F88F1756FE7ULL,
		0x4C68854A40FC9228ULL,
		0x949367CF8ED89E0FULL,
		0xC927F36E9416FEE1ULL,
		0x7C89E3E074B9E9E3ULL,
		0x05F3162F99CB61A3ULL,
		0x328AF6AEC1642C1FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x519EE56636FA35C6ULL,
		0x688EFF11E2EADFCFULL,
		0x98D10A9481F92450ULL,
		0x2926CF9F1DB13C1EULL,
		0x924FE6DD282DFDC3ULL,
		0xF913C7C0E973D3C7ULL,
		0x0BE62C5F3396C346ULL,
		0x6515ED5D82C8583EULL
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
		0x02E2F5ED9EB4B338ULL,
		0x02BF77DA32B2E0ADULL,
		0x9FC8AA1337F05BA8ULL,
		0xE4C53830AF5983BCULL,
		0x13B4F23281A162CFULL,
		0x989E424944366C3AULL,
		0x0EEADE3B8A610E0EULL,
		0x07CDFF8CFB554FE6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x05C5EBDB3D696670ULL,
		0x057EEFB46565C15AULL,
		0x3F9154266FE0B750ULL,
		0xC98A70615EB30779ULL,
		0x2769E4650342C59FULL,
		0x313C8492886CD874ULL,
		0x1DD5BC7714C21C1DULL,
		0x0F9BFF19F6AA9FCCULL
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
		0x8BB4FA9A2E5B9D92ULL,
		0x46AA1438CF8FA6D3ULL,
		0x59E3E2E8E254438FULL,
		0xC6EE5F1EF60959C7ULL,
		0x9F34CB3BC5F7A94DULL,
		0xA0421A84F6F4B032ULL,
		0x04E801F25A309421ULL,
		0x02875CB355CE15A3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1769F5345CB73B24ULL,
		0x8D5428719F1F4DA7ULL,
		0xB3C7C5D1C4A8871EULL,
		0x8DDCBE3DEC12B38EULL,
		0x3E6996778BEF529BULL,
		0x40843509EDE96065ULL,
		0x09D003E4B4612843ULL,
		0x050EB966AB9C2B46ULL
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
		0x5591E481957B9AECULL,
		0xFA7464F0EC944C2BULL,
		0x91B240155CF2EFC0ULL,
		0x4552F08063B614C5ULL,
		0x5CB87D24AF598001ULL,
		0xE3B96156FACC66B2ULL,
		0x68D4413C2AB3672AULL,
		0x36F84E59CEAC3DF4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAB23C9032AF735D8ULL,
		0xF4E8C9E1D9289856ULL,
		0x2364802AB9E5DF81ULL,
		0x8AA5E100C76C298BULL,
		0xB970FA495EB30002ULL,
		0xC772C2ADF598CD64ULL,
		0xD1A882785566CE55ULL,
		0x6DF09CB39D587BE8ULL
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
		0x0C952D50564FC132ULL,
		0xEE3D52EA23D6FB48ULL,
		0x0BA998CE2370821AULL,
		0xEF52585758496F88ULL,
		0x1DC2E6D0976B8237ULL,
		0x0D89BA014DB5C7ADULL,
		0xED6E8281EB499E57ULL,
		0x17FCE197C0A74326ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x192A5AA0AC9F8264ULL,
		0xDC7AA5D447ADF690ULL,
		0x1753319C46E10435ULL,
		0xDEA4B0AEB092DF10ULL,
		0x3B85CDA12ED7046FULL,
		0x1B1374029B6B8F5AULL,
		0xDADD0503D6933CAEULL,
		0x2FF9C32F814E864DULL
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
		0x77F40F0E4D2AAECEULL,
		0x7FDE1BB52C68A603ULL,
		0xE4D884734D611942ULL,
		0x91446406CD95A2FFULL,
		0x0B436D5A3E47C65FULL,
		0xC76FAEF7DE9CE035ULL,
		0x9B0A7BD1CC98BB2BULL,
		0x2F102AFA9760E2B3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEFE81E1C9A555D9CULL,
		0xFFBC376A58D14C06ULL,
		0xC9B108E69AC23284ULL,
		0x2288C80D9B2B45FFULL,
		0x1686DAB47C8F8CBFULL,
		0x8EDF5DEFBD39C06AULL,
		0x3614F7A399317657ULL,
		0x5E2055F52EC1C567ULL
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
		0xD99A5666D05B82E2ULL,
		0xD03B083CE4CBCDE6ULL,
		0xC857F7A978094A97ULL,
		0xDA4A64258C99A257ULL,
		0x59DCDBA776A30D9DULL,
		0x6FA63E9FFB08FD66ULL,
		0xD64E254925885E0FULL,
		0x1CB95D6F9AFF4391ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB334ACCDA0B705C4ULL,
		0xA0761079C9979BCDULL,
		0x90AFEF52F012952FULL,
		0xB494C84B193344AFULL,
		0xB3B9B74EED461B3BULL,
		0xDF4C7D3FF611FACCULL,
		0xAC9C4A924B10BC1EULL,
		0x3972BADF35FE8723ULL
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
		0xFEF75922A5106D86ULL,
		0x7C862398643F941DULL,
		0x5745D39409C111A7ULL,
		0x9F83E3D1003AE2B1ULL,
		0x597EA226D81F66AAULL,
		0xC5931FC28558D06CULL,
		0x5E84D440A66EE7A8ULL,
		0x25E736E7452B1880ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFDEEB2454A20DB0CULL,
		0xF90C4730C87F283BULL,
		0xAE8BA7281382234EULL,
		0x3F07C7A20075C562ULL,
		0xB2FD444DB03ECD55ULL,
		0x8B263F850AB1A0D8ULL,
		0xBD09A8814CDDCF51ULL,
		0x4BCE6DCE8A563100ULL
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
		0xE00D61EE97117193ULL,
		0xEABF4968FAC9BE60ULL,
		0x7F5FA676436C95D3ULL,
		0x87E0835448A54B3DULL,
		0x6CEA21BB35C6456BULL,
		0xDA5836BFDF137F80ULL,
		0x529204F3549D708DULL,
		0x06C6413113C9F9E9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC01AC3DD2E22E326ULL,
		0xD57E92D1F5937CC1ULL,
		0xFEBF4CEC86D92BA7ULL,
		0x0FC106A8914A967AULL,
		0xD9D443766B8C8AD7ULL,
		0xB4B06D7FBE26FF00ULL,
		0xA52409E6A93AE11BULL,
		0x0D8C82622793F3D2ULL
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
		0x2AA3DAC8DCBB4208ULL,
		0xD654E0CB9580606CULL,
		0x6B04AF029EFEF384ULL,
		0x8A4F3D68A9698EE6ULL,
		0x11911293767D6215ULL,
		0x556C555AEA03FD83ULL,
		0xAB9713A692449D83ULL,
		0x2815D8A0666175A5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5547B591B9768410ULL,
		0xACA9C1972B00C0D8ULL,
		0xD6095E053DFDE709ULL,
		0x149E7AD152D31DCCULL,
		0x23222526ECFAC42BULL,
		0xAAD8AAB5D407FB06ULL,
		0x572E274D24893B06ULL,
		0x502BB140CCC2EB4BULL
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
		0x18DFFC5BAC93F8DBULL,
		0x21F2C3720AC5F35CULL,
		0x03134BF1D2E9087FULL,
		0x7C7B9254666BE2CDULL,
		0xC078609423918D32ULL,
		0x53E7592D6308E1DBULL,
		0x3D6432BBC84EF7EDULL,
		0x1D14C5AD52200D93ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x31BFF8B75927F1B6ULL,
		0x43E586E4158BE6B8ULL,
		0x062697E3A5D210FEULL,
		0xF8F724A8CCD7C59AULL,
		0x80F0C12847231A64ULL,
		0xA7CEB25AC611C3B7ULL,
		0x7AC86577909DEFDAULL,
		0x3A298B5AA4401B26ULL
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
		0xB5C8A10BCDAB77FCULL,
		0x23AFC27E0C895009ULL,
		0x431FCB171A331D10ULL,
		0xE7E2DFBFF9E4C25CULL,
		0x606846428AE9C03AULL,
		0x86D68AA892155349ULL,
		0xD5D901EF7C948C2BULL,
		0x339C7C7111D179E3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6B9142179B56EFF8ULL,
		0x475F84FC1912A013ULL,
		0x863F962E34663A20ULL,
		0xCFC5BF7FF3C984B8ULL,
		0xC0D08C8515D38075ULL,
		0x0DAD1551242AA692ULL,
		0xABB203DEF9291857ULL,
		0x6738F8E223A2F3C7ULL
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
		0x806890A16733E96DULL,
		0x0DC1D028FA5EC173ULL,
		0xA173523FBDB319D8ULL,
		0x3BCD85E7FCE6C2E8ULL,
		0x69673C8F579EF8E7ULL,
		0x5B85FA691A626377ULL,
		0x83B3B39631F98A59ULL,
		0x1B980029EC5992A5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x00D12142CE67D2DAULL,
		0x1B83A051F4BD82E7ULL,
		0x42E6A47F7B6633B0ULL,
		0x779B0BCFF9CD85D1ULL,
		0xD2CE791EAF3DF1CEULL,
		0xB70BF4D234C4C6EEULL,
		0x0767672C63F314B2ULL,
		0x37300053D8B3254BULL
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
		0x61B21042792AA78FULL,
		0xBF7024F775BE54F7ULL,
		0x09B25ED882034C6DULL,
		0xF4B07F9BEC9B3885ULL,
		0xD80B2D5BF18F1621ULL,
		0x196148005D6196B4ULL,
		0x740A1003064E98CBULL,
		0x0C582BDAB5F3166BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC3642084F2554F1EULL,
		0x7EE049EEEB7CA9EEULL,
		0x1364BDB1040698DBULL,
		0xE960FF37D936710AULL,
		0xB0165AB7E31E2C43ULL,
		0x32C29000BAC32D69ULL,
		0xE81420060C9D3196ULL,
		0x18B057B56BE62CD6ULL
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
		0x0A5E49683BC1D9FDULL,
		0x6A340B3125B0CEB5ULL,
		0x1231E7425687AF09ULL,
		0xB69036F73D542EC2ULL,
		0x4CCDB72322076F60ULL,
		0x2C104F363169F78BULL,
		0xB26DE2D66DAAEE42ULL,
		0x10653E98799FD3B7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x14BC92D07783B3FAULL,
		0xD46816624B619D6AULL,
		0x2463CE84AD0F5E12ULL,
		0x6D206DEE7AA85D84ULL,
		0x999B6E46440EDEC1ULL,
		0x58209E6C62D3EF16ULL,
		0x64DBC5ACDB55DC84ULL,
		0x20CA7D30F33FA76FULL
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
		0x27B98863C0511699ULL,
		0xAD27A07136290EB2ULL,
		0x05F61809EDEB5DF5ULL,
		0x2211756B02A85B73ULL,
		0xDE1C9046961EBD63ULL,
		0x3D907A99E4573F40ULL,
		0x26B79865F0131785ULL,
		0x09DEF36924CC0AE5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4F7310C780A22D32ULL,
		0x5A4F40E26C521D64ULL,
		0x0BEC3013DBD6BBEBULL,
		0x4422EAD60550B6E6ULL,
		0xBC39208D2C3D7AC6ULL,
		0x7B20F533C8AE7E81ULL,
		0x4D6F30CBE0262F0AULL,
		0x13BDE6D2499815CAULL
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
		0xA0586FD1EBF5E5E3ULL,
		0x0F2345F5CB9FEFC3ULL,
		0x1F15B0DD2AE91B41ULL,
		0x4DCA12BD652C6434ULL,
		0x7D88890C646D28CFULL,
		0xD05B78358AEE6BEFULL,
		0x6E862BF4F1872F0DULL,
		0x1E7569E605010C7FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x40B0DFA3D7EBCBC6ULL,
		0x1E468BEB973FDF87ULL,
		0x3E2B61BA55D23682ULL,
		0x9B94257ACA58C868ULL,
		0xFB111218C8DA519EULL,
		0xA0B6F06B15DCD7DEULL,
		0xDD0C57E9E30E5E1BULL,
		0x3CEAD3CC0A0218FEULL
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
		0x3BCF7A9DEAB3A7C8ULL,
		0x2CC1D40F14213C2DULL,
		0x6C1282D12274E24AULL,
		0x70745CA555DA538BULL,
		0xC8D7E834447208EAULL,
		0xA71FCCA6F334FB91ULL,
		0xD41F27F690963BB7ULL,
		0x2F7BEA63A8CC12F7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x779EF53BD5674F90ULL,
		0x5983A81E2842785AULL,
		0xD82505A244E9C494ULL,
		0xE0E8B94AABB4A716ULL,
		0x91AFD06888E411D4ULL,
		0x4E3F994DE669F723ULL,
		0xA83E4FED212C776FULL,
		0x5EF7D4C7519825EFULL
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
		0xD05DA7286E33D53FULL,
		0x8BCE588EE27D95E3ULL,
		0xA59A652734A6D92DULL,
		0x23BFC6741DECBB39ULL,
		0x25BB90B7A60391BAULL,
		0x780F29BF12EE08C2ULL,
		0x984960E34D0BFBD1ULL,
		0x381F795F7250A49FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA0BB4E50DC67AA7EULL,
		0x179CB11DC4FB2BC7ULL,
		0x4B34CA4E694DB25BULL,
		0x477F8CE83BD97673ULL,
		0x4B77216F4C072374ULL,
		0xF01E537E25DC1184ULL,
		0x3092C1C69A17F7A2ULL,
		0x703EF2BEE4A1493FULL
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
		0x6A2DF1829CFEA726ULL,
		0x397CE0E58D144346ULL,
		0x41F08F732BAE8975ULL,
		0x0398B85F57B98C4DULL,
		0xB74F59D3A688DBABULL,
		0x0ADF195159B819D0ULL,
		0x1B9B82B0F0DB4BE7ULL,
		0x024E46438D2ED28EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD45BE30539FD4E4CULL,
		0x72F9C1CB1A28868CULL,
		0x83E11EE6575D12EAULL,
		0x073170BEAF73189AULL,
		0x6E9EB3A74D11B756ULL,
		0x15BE32A2B37033A1ULL,
		0x37370561E1B697CEULL,
		0x049C8C871A5DA51CULL
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
		0x8B4B8EF343F97E89ULL,
		0x6B270EEAE6C160E3ULL,
		0x8475C319C3FB09DEULL,
		0x898C9F197BCEDB5DULL,
		0x3E6640C4A6185D5AULL,
		0x0F2033CBAE47CCABULL,
		0xCFC3AF4C90944DEAULL,
		0x101F9B7932941A41ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x16971DE687F2FD12ULL,
		0xD64E1DD5CD82C1C7ULL,
		0x08EB863387F613BCULL,
		0x13193E32F79DB6BBULL,
		0x7CCC81894C30BAB5ULL,
		0x1E4067975C8F9956ULL,
		0x9F875E9921289BD4ULL,
		0x203F36F265283483ULL
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
		0xF1011FDC28D302ECULL,
		0x8E96FDC6D7D86742ULL,
		0x0317199422CA48F9ULL,
		0x1FB8DA0E15E918A9ULL,
		0x95E76B99BE2B1F61ULL,
		0xB15B0D91335B95A4ULL,
		0x9D2892AFDB8E2C7EULL,
		0x1C01B6BBCE2E7D22ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE2023FB851A605D8ULL,
		0x1D2DFB8DAFB0CE85ULL,
		0x062E3328459491F3ULL,
		0x3F71B41C2BD23152ULL,
		0x2BCED7337C563EC2ULL,
		0x62B61B2266B72B49ULL,
		0x3A51255FB71C58FDULL,
		0x38036D779C5CFA45ULL
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
		0xEB0A13665F02DE22ULL,
		0xC81DED137B309711ULL,
		0x731E92A968C8BBAEULL,
		0x862BA9B41B14D25AULL,
		0xF622C7A9C2D77F48ULL,
		0x5E95FF66F6FF65A3ULL,
		0xE719C1510C79EC42ULL,
		0x29DC1DF54C8D7D0FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD61426CCBE05BC44ULL,
		0x903BDA26F6612E23ULL,
		0xE63D2552D191775DULL,
		0x0C5753683629A4B4ULL,
		0xEC458F5385AEFE91ULL,
		0xBD2BFECDEDFECB47ULL,
		0xCE3382A218F3D884ULL,
		0x53B83BEA991AFA1FULL
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
		0x877F23893FEB35DCULL,
		0x20B929EFCC2DE57FULL,
		0xE6E97DF3AD4D0362ULL,
		0xF0AE3D50B7E5CFF1ULL,
		0xC63AD9D795EB2774ULL,
		0xDCD2A7706F1D2F32ULL,
		0xA9474C423C44ED1FULL,
		0x09794B11C4AFD421ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0EFE47127FD66BB8ULL,
		0x417253DF985BCAFFULL,
		0xCDD2FBE75A9A06C4ULL,
		0xE15C7AA16FCB9FE3ULL,
		0x8C75B3AF2BD64EE9ULL,
		0xB9A54EE0DE3A5E65ULL,
		0x528E98847889DA3FULL,
		0x12F29623895FA843ULL
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
		0xF5581FDA360F60ADULL,
		0x2152EF11DD9B70A5ULL,
		0x7FD9BE1E378C7203ULL,
		0xE0F46394477E29E3ULL,
		0x451CA83477D8780EULL,
		0x33953E237C414155ULL,
		0xC60CCAA486AB1B32ULL,
		0x0680A6A376143473ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEAB03FB46C1EC15AULL,
		0x42A5DE23BB36E14BULL,
		0xFFB37C3C6F18E406ULL,
		0xC1E8C7288EFC53C6ULL,
		0x8A395068EFB0F01DULL,
		0x672A7C46F88282AAULL,
		0x8C1995490D563664ULL,
		0x0D014D46EC2868E7ULL
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
		0x04788841FBC507AFULL,
		0x5D9CFAAC6E08139AULL,
		0xCA8F3B39E404AC51ULL,
		0x60BE708B3EC10F37ULL,
		0x2AA1285ED4B853E9ULL,
		0xC3DBDD1C883D8FA4ULL,
		0x501CEC6C0B375114ULL,
		0x0227B653A5CD67FAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x08F11083F78A0F5EULL,
		0xBB39F558DC102734ULL,
		0x951E7673C80958A2ULL,
		0xC17CE1167D821E6FULL,
		0x554250BDA970A7D2ULL,
		0x87B7BA39107B1F48ULL,
		0xA039D8D8166EA229ULL,
		0x044F6CA74B9ACFF4ULL
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
		0x6FE6AACD0B6B7BFAULL,
		0x533418AAA4BFF643ULL,
		0xF89E413D1CCFD3BFULL,
		0x7ED3FEF62F9F005CULL,
		0x721C3AF6538DCB9EULL,
		0xA90B8B44E8F056B6ULL,
		0x642844292344DF02ULL,
		0x1A87540EE87C41BBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDFCD559A16D6F7F4ULL,
		0xA6683155497FEC86ULL,
		0xF13C827A399FA77EULL,
		0xFDA7FDEC5F3E00B9ULL,
		0xE43875ECA71B973CULL,
		0x52171689D1E0AD6CULL,
		0xC85088524689BE05ULL,
		0x350EA81DD0F88376ULL
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
		0x263135A2EAB657FAULL,
		0xED7AFD41897C28E1ULL,
		0x044B1588BFD9A43DULL,
		0x3A9936F5AA781F9FULL,
		0xBFD3D32D01621A4DULL,
		0x56B5798526FE48F3ULL,
		0x736CCC042F9EF8ACULL,
		0x0C9328A12BDC8F76ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4C626B45D56CAFF4ULL,
		0xDAF5FA8312F851C2ULL,
		0x08962B117FB3487BULL,
		0x75326DEB54F03F3EULL,
		0x7FA7A65A02C4349AULL,
		0xAD6AF30A4DFC91E7ULL,
		0xE6D998085F3DF158ULL,
		0x1926514257B91EECULL
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
		0x11291E4304FA975CULL,
		0xF038963F96E28F40ULL,
		0x808298B3B6E9597DULL,
		0x338CE3F51CD9270FULL,
		0x7F1FB7F55F68C398ULL,
		0x89B7377F45ACBDB5ULL,
		0x6AA552B5B8E44AA1ULL,
		0x202FBFB8033109CBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x22523C8609F52EB8ULL,
		0xE0712C7F2DC51E80ULL,
		0x010531676DD2B2FBULL,
		0x6719C7EA39B24E1FULL,
		0xFE3F6FEABED18730ULL,
		0x136E6EFE8B597B6AULL,
		0xD54AA56B71C89543ULL,
		0x405F7F7006621396ULL
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
		0x86DDEBB9CBD9008BULL,
		0x636F37FD46D773A2ULL,
		0x72D9FDD2618310CCULL,
		0x1728FB8DA5FD5756ULL,
		0x88456E802EADE7E1ULL,
		0x36AA74635D986172ULL,
		0xD3B812EA91A6592CULL,
		0x22142F2663389F7CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0DBBD77397B20116ULL,
		0xC6DE6FFA8DAEE745ULL,
		0xE5B3FBA4C3062198ULL,
		0x2E51F71B4BFAAEACULL,
		0x108ADD005D5BCFC2ULL,
		0x6D54E8C6BB30C2E5ULL,
		0xA77025D5234CB258ULL,
		0x44285E4CC6713EF9ULL
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
		0xCEC88AD5417551D5ULL,
		0x520632BBBBD0CC1FULL,
		0xAE88B6323153D7A6ULL,
		0x4E2EB4B2D1CADE7AULL,
		0x899D9C06308E997EULL,
		0xFA7220417064E8F7ULL,
		0xFE4A4FEFC2122D71ULL,
		0x12B6F30E5F8CE3B1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9D9115AA82EAA3AAULL,
		0xA40C657777A1983FULL,
		0x5D116C6462A7AF4CULL,
		0x9C5D6965A395BCF5ULL,
		0x133B380C611D32FCULL,
		0xF4E44082E0C9D1EFULL,
		0xFC949FDF84245AE3ULL,
		0x256DE61CBF19C763ULL
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
		0xB04EAA573E90A4C0ULL,
		0x5861487A2631A84CULL,
		0xB9CCB898A719FEB8ULL,
		0xF5BE4BB464F19E48ULL,
		0xC797F15CA236C6C1ULL,
		0xAED381FE49C0C4ECULL,
		0x7A15062081A80822ULL,
		0x20F3D038CC0C709DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x609D54AE7D214980ULL,
		0xB0C290F44C635099ULL,
		0x739971314E33FD70ULL,
		0xEB7C9768C9E33C91ULL,
		0x8F2FE2B9446D8D83ULL,
		0x5DA703FC938189D9ULL,
		0xF42A0C4103501045ULL,
		0x41E7A0719818E13AULL
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
		0x36BD1FE71EE84B30ULL,
		0x8E63C5247B377725ULL,
		0x1D3E22F876A055C3ULL,
		0x9CCEDDB8E60EAF92ULL,
		0x63052E009A8D7069ULL,
		0x0C4A26C518B3E280ULL,
		0xF32695798D8BA2F5ULL,
		0x17328CF2A2AAAD04ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6D7A3FCE3DD09660ULL,
		0x1CC78A48F66EEE4AULL,
		0x3A7C45F0ED40AB87ULL,
		0x399DBB71CC1D5F24ULL,
		0xC60A5C01351AE0D3ULL,
		0x18944D8A3167C500ULL,
		0xE64D2AF31B1745EAULL,
		0x2E6519E545555A09ULL
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
		0x8F82B9B58CF7E90CULL,
		0x48F0D40E2629C2E1ULL,
		0xDC3F3239C9FF006AULL,
		0x4E1F585B208C8CF5ULL,
		0xA16F03A73B6A2779ULL,
		0xAB198B05EECE046CULL,
		0x38AAF01E1AE55849ULL,
		0x1B8E5FDF67FD4417ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1F05736B19EFD218ULL,
		0x91E1A81C4C5385C3ULL,
		0xB87E647393FE00D4ULL,
		0x9C3EB0B6411919EBULL,
		0x42DE074E76D44EF2ULL,
		0x5633160BDD9C08D9ULL,
		0x7155E03C35CAB093ULL,
		0x371CBFBECFFA882EULL
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
		0xED1E26A2FDFB309BULL,
		0xE1E5A822C6FE45F8ULL,
		0x64F094CAC8925452ULL,
		0x8E3788E33FDEA0AAULL,
		0xB20D5CF96AD9EE72ULL,
		0x22D07213EAFA9247ULL,
		0xF51A61453F52F62CULL,
		0x2DE8DB0083D70590ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDA3C4D45FBF66136ULL,
		0xC3CB50458DFC8BF1ULL,
		0xC9E129959124A8A5ULL,
		0x1C6F11C67FBD4154ULL,
		0x641AB9F2D5B3DCE5ULL,
		0x45A0E427D5F5248FULL,
		0xEA34C28A7EA5EC58ULL,
		0x5BD1B60107AE0B21ULL
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
		0xFED8992BE5A17F23ULL,
		0xBD3867522FD5F7C6ULL,
		0x53D0387EDC713839ULL,
		0xE3D0E0481EAA8AC2ULL,
		0x182F4F5AD0ECEB92ULL,
		0xA041D9286BEC65B3ULL,
		0x8ADDB7A4DCA4204AULL,
		0x1EBEDA8869C4C091ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFDB13257CB42FE46ULL,
		0x7A70CEA45FABEF8DULL,
		0xA7A070FDB8E27073ULL,
		0xC7A1C0903D551584ULL,
		0x305E9EB5A1D9D725ULL,
		0x4083B250D7D8CB66ULL,
		0x15BB6F49B9484095ULL,
		0x3D7DB510D3898123ULL
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
		0x5F52F260439C220EULL,
		0x682C1BBA5B45D45FULL,
		0xC1155FCC1F23D4CEULL,
		0x3F27CD259D2DA283ULL,
		0x7E4A0DC481C20451ULL,
		0x7CFCCDFCD937E1F6ULL,
		0x044BF2E6FF218D62ULL,
		0x20DB1A0CD46A03FEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBEA5E4C08738441CULL,
		0xD0583774B68BA8BEULL,
		0x822ABF983E47A99CULL,
		0x7E4F9A4B3A5B4507ULL,
		0xFC941B89038408A2ULL,
		0xF9F99BF9B26FC3ECULL,
		0x0897E5CDFE431AC4ULL,
		0x41B63419A8D407FCULL
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
		0x0201FEB4DA0D29DBULL,
		0x963EF2267B4AC7C1ULL,
		0x2659F3F9F3000D17ULL,
		0x9A7EE65A48994298ULL,
		0xA323E7DA324E292EULL,
		0xB33CC1B70EB5D8A9ULL,
		0x31F2EA6DA7A709FEULL,
		0x20F4D07BE7AB10B9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0403FD69B41A53B6ULL,
		0x2C7DE44CF6958F82ULL,
		0x4CB3E7F3E6001A2FULL,
		0x34FDCCB491328530ULL,
		0x4647CFB4649C525DULL,
		0x6679836E1D6BB153ULL,
		0x63E5D4DB4F4E13FDULL,
		0x41E9A0F7CF562172ULL
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
		0xB6347C4435983DAFULL,
		0x5FD14C8E90F8BC2EULL,
		0x641DC62A815BCA94ULL,
		0x1E68D422978F372DULL,
		0xF44B8B38382D0460ULL,
		0x97AE9854E1DD37C1ULL,
		0x1080029BC06ECC24ULL,
		0x0784AF80DF7280B5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6C68F8886B307B5EULL,
		0xBFA2991D21F1785DULL,
		0xC83B8C5502B79528ULL,
		0x3CD1A8452F1E6E5AULL,
		0xE8971670705A08C0ULL,
		0x2F5D30A9C3BA6F83ULL,
		0x2100053780DD9849ULL,
		0x0F095F01BEE5016AULL
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
		0x7CC2F39BBC5E8D39ULL,
		0x0EC65E242202FCC9ULL,
		0x056A1BDE42F71383ULL,
		0xC28CB101DC2D6375ULL,
		0x018CEBC263624D58ULL,
		0x1E7E43B99BB880ABULL,
		0xB6C49FB91484D8BEULL,
		0x34580A22F9600BEAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF985E73778BD1A72ULL,
		0x1D8CBC484405F992ULL,
		0x0AD437BC85EE2706ULL,
		0x85196203B85AC6EAULL,
		0x0319D784C6C49AB1ULL,
		0x3CFC877337710156ULL,
		0x6D893F722909B17CULL,
		0x68B01445F2C017D5ULL
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
		0x2136108471C0EBF1ULL,
		0x62198AC5C6D3F96DULL,
		0x63710B050908ADC6ULL,
		0xDE664B86544EF9B4ULL,
		0xF743653031191DF3ULL,
		0x2355B12AE24DF266ULL,
		0x7A16A65684FB29CFULL,
		0x2697FB83FBD0EB84ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x426C2108E381D7E2ULL,
		0xC433158B8DA7F2DAULL,
		0xC6E2160A12115B8CULL,
		0xBCCC970CA89DF368ULL,
		0xEE86CA6062323BE7ULL,
		0x46AB6255C49BE4CDULL,
		0xF42D4CAD09F6539EULL,
		0x4D2FF707F7A1D708ULL
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
		0x6E17E6B97B9D123FULL,
		0x36CA19E80323F974ULL,
		0xDEE66B2C5644F7F7ULL,
		0x4B84593296BEDDA2ULL,
		0x74492F148B967D84ULL,
		0x3B7B5CDD22050C98ULL,
		0x85AD544FB697E118ULL,
		0x3D9AAA30792C2F4EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDC2FCD72F73A247EULL,
		0x6D9433D00647F2E8ULL,
		0xBDCCD658AC89EFEEULL,
		0x9708B2652D7DBB45ULL,
		0xE8925E29172CFB08ULL,
		0x76F6B9BA440A1930ULL,
		0x0B5AA89F6D2FC230ULL,
		0x7B355460F2585E9DULL
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
		0x67CFE675FDBD4E02ULL,
		0x869323F1BCE24011ULL,
		0x9A24572CF6E3FC84ULL,
		0x800AD4EEE41496DEULL,
		0x1F2AFEFA0A135ADBULL,
		0x63DA1BF7A6760657ULL,
		0xABADB4DAD6E00507ULL,
		0x3FB31B1C0620D695ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCF9FCCEBFB7A9C04ULL,
		0x0D2647E379C48022ULL,
		0x3448AE59EDC7F909ULL,
		0x0015A9DDC8292DBDULL,
		0x3E55FDF41426B5B7ULL,
		0xC7B437EF4CEC0CAEULL,
		0x575B69B5ADC00A0EULL,
		0x7F6636380C41AD2BULL
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
		0x16D8ED662CF8E958ULL,
		0x6DA588BEC7A322D6ULL,
		0xEA0255937EB5C4F8ULL,
		0xF1286B19D6A1BEC6ULL,
		0xB6B05CACC2B0C918ULL,
		0x2F97E1E476964793ULL,
		0xB995557FE7B38859ULL,
		0x13AA144B3DC3D669ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2DB1DACC59F1D2B0ULL,
		0xDB4B117D8F4645ACULL,
		0xD404AB26FD6B89F0ULL,
		0xE250D633AD437D8DULL,
		0x6D60B95985619231ULL,
		0x5F2FC3C8ED2C8F27ULL,
		0x732AAAFFCF6710B2ULL,
		0x275428967B87ACD3ULL
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
		0x33A56CDEDDB9D19AULL,
		0x318BCC67D2E86DDDULL,
		0x17D19E1B77005E0CULL,
		0x6924819591E117A9ULL,
		0x235738DDE95CA5CBULL,
		0x94F1D5271A3A2721ULL,
		0x14B4EAB633D6F8DDULL,
		0x1BA8B80929066A61ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x674AD9BDBB73A334ULL,
		0x631798CFA5D0DBBAULL,
		0x2FA33C36EE00BC18ULL,
		0xD249032B23C22F52ULL,
		0x46AE71BBD2B94B96ULL,
		0x29E3AA4E34744E42ULL,
		0x2969D56C67ADF1BBULL,
		0x37517012520CD4C2ULL
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
		0xFB6C05E3081F427AULL,
		0x04A90544D597AC3BULL,
		0xB0DEE44660E011A2ULL,
		0xA0428F7D1F26A879ULL,
		0xC7EB6B1593B375A6ULL,
		0x316465AAE3A8010AULL,
		0xD6F1CD7EA24CD4C7ULL,
		0x3975F5A5FFBA6026ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF6D80BC6103E84F4ULL,
		0x09520A89AB2F5877ULL,
		0x61BDC88CC1C02344ULL,
		0x40851EFA3E4D50F3ULL,
		0x8FD6D62B2766EB4DULL,
		0x62C8CB55C7500215ULL,
		0xADE39AFD4499A98EULL,
		0x72EBEB4BFF74C04DULL
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
		0x246A1DC4E50C4220ULL,
		0x48F257D458BDB16BULL,
		0x70FF0948D43EF525ULL,
		0x1C1EEE7AEF99C64BULL,
		0x37497A97253D4A84ULL,
		0xF5C3F52A61FC5C27ULL,
		0x80D430FCA35727A4ULL,
		0x39367C80AC2DB8A9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x48D43B89CA188440ULL,
		0x91E4AFA8B17B62D6ULL,
		0xE1FE1291A87DEA4AULL,
		0x383DDCF5DF338C96ULL,
		0x6E92F52E4A7A9508ULL,
		0xEB87EA54C3F8B84EULL,
		0x01A861F946AE4F49ULL,
		0x726CF901585B7153ULL
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
		0x139275A3D68CBCECULL,
		0x21F615818C64EFC3ULL,
		0x48F3E5949EA7296CULL,
		0x50CA06AA4419AF62ULL,
		0x2C09EFBF63E000CEULL,
		0x43DB3649B6234E00ULL,
		0x73D36C2FBA6CEDC5ULL,
		0x239A639E9E1AF24CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2724EB47AD1979D8ULL,
		0x43EC2B0318C9DF86ULL,
		0x91E7CB293D4E52D8ULL,
		0xA1940D5488335EC4ULL,
		0x5813DF7EC7C0019CULL,
		0x87B66C936C469C00ULL,
		0xE7A6D85F74D9DB8AULL,
		0x4734C73D3C35E498ULL
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
		0x58242867714B1256ULL,
		0x766054A057F99B68ULL,
		0xD95FBD4EEFDC2C33ULL,
		0x7451716E0924412FULL,
		0x04A8F87F325D17DAULL,
		0x9B95CA28A38983CCULL,
		0xEB52DC3A8114BC5EULL,
		0x01B3931D6444C3BCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB04850CEE29624ACULL,
		0xECC0A940AFF336D0ULL,
		0xB2BF7A9DDFB85866ULL,
		0xE8A2E2DC1248825FULL,
		0x0951F0FE64BA2FB4ULL,
		0x372B945147130798ULL,
		0xD6A5B875022978BDULL,
		0x0367263AC8898779ULL
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
		0x0C3B5294FAC68684ULL,
		0x09F6CB1487A94407ULL,
		0x4590B0754AD67CF2ULL,
		0xCD735E5BF9E7E040ULL,
		0xD500A0E4228C2CECULL,
		0x4E06D3570A1BDC99ULL,
		0xA6A23EAD1C70FD75ULL,
		0x2100D93879C222D8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1876A529F58D0D08ULL,
		0x13ED96290F52880EULL,
		0x8B2160EA95ACF9E4ULL,
		0x9AE6BCB7F3CFC080ULL,
		0xAA0141C8451859D9ULL,
		0x9C0DA6AE1437B933ULL,
		0x4D447D5A38E1FAEAULL,
		0x4201B270F38445B1ULL
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
		0xE657F769B4901702ULL,
		0xFA3AE4A951245596ULL,
		0x910364D5145B794AULL,
		0x805F22511B34459FULL,
		0xCC91A9433B375A68ULL,
		0x1DE92B5C79643932ULL,
		0xE8A0169865154056ULL,
		0x30081CAC2E67F93FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCCAFEED369202E04ULL,
		0xF475C952A248AB2DULL,
		0x2206C9AA28B6F295ULL,
		0x00BE44A236688B3FULL,
		0x99235286766EB4D1ULL,
		0x3BD256B8F2C87265ULL,
		0xD1402D30CA2A80ACULL,
		0x601039585CCFF27FULL
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
		0x6551FC0BB7A45FC9ULL,
		0xA0F6547616272586ULL,
		0x31AFFFD02DEDA5F7ULL,
		0x9CE2F526FBFF69DCULL,
		0xC8CEDCF3D51F69C3ULL,
		0x7EC3D0DEFEB6292CULL,
		0x13DF47EAC916686AULL,
		0x1409BB3DB20B8164ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCAA3F8176F48BF92ULL,
		0x41ECA8EC2C4E4B0CULL,
		0x635FFFA05BDB4BEFULL,
		0x39C5EA4DF7FED3B8ULL,
		0x919DB9E7AA3ED387ULL,
		0xFD87A1BDFD6C5259ULL,
		0x27BE8FD5922CD0D4ULL,
		0x2813767B641702C8ULL
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
		0x38DA67A9B97F1090ULL,
		0xC8BD7899D0A6ED2CULL,
		0x165D549631425EC3ULL,
		0xC5C18B5AE5F44E9CULL,
		0x5226BFB1E6861F60ULL,
		0x40AC02EC98CE46A7ULL,
		0x38642CADADDCFB9DULL,
		0x0FABDE54B362AC3EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x71B4CF5372FE2120ULL,
		0x917AF133A14DDA58ULL,
		0x2CBAA92C6284BD87ULL,
		0x8B8316B5CBE89D38ULL,
		0xA44D7F63CD0C3EC1ULL,
		0x815805D9319C8D4EULL,
		0x70C8595B5BB9F73AULL,
		0x1F57BCA966C5587CULL
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
		0x22B68868AE505510ULL,
		0x8A8775DBE7A230F9ULL,
		0x2D5A7F5DAA049304ULL,
		0xB044C49FBCD80BCAULL,
		0xF787C03744B708E8ULL,
		0x6A0F7D9704D8AE0DULL,
		0xCBF906532D0EE3CDULL,
		0x31C6AAC5E6DF2952ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x456D10D15CA0AA20ULL,
		0x150EEBB7CF4461F2ULL,
		0x5AB4FEBB54092609ULL,
		0x6089893F79B01794ULL,
		0xEF0F806E896E11D1ULL,
		0xD41EFB2E09B15C1BULL,
		0x97F20CA65A1DC79AULL,
		0x638D558BCDBE52A5ULL
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
		0x4178E870D211070AULL,
		0x265399DBD8CA7634ULL,
		0xD32650F519424F23ULL,
		0x989CFCD12DF5AB40ULL,
		0xB9F874B33B7F1EA6ULL,
		0x0E2D12F7A39B3347ULL,
		0x595EA8C9601F2D4AULL,
		0x041DA9B80583936BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x82F1D0E1A4220E14ULL,
		0x4CA733B7B194EC68ULL,
		0xA64CA1EA32849E46ULL,
		0x3139F9A25BEB5681ULL,
		0x73F0E96676FE3D4DULL,
		0x1C5A25EF4736668FULL,
		0xB2BD5192C03E5A94ULL,
		0x083B53700B0726D6ULL
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
		0x163BA225EEDC240EULL,
		0x3D1A02EA76DC8E38ULL,
		0x40F2AAFF49B170DCULL,
		0xC3473F5DC151A060ULL,
		0x7B5E9770EB4B34F0ULL,
		0x9BDCA92098FC3674ULL,
		0x40DAFF703C00C525ULL,
		0x153CA6DE5C5D352AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2C77444BDDB8481CULL,
		0x7A3405D4EDB91C70ULL,
		0x81E555FE9362E1B8ULL,
		0x868E7EBB82A340C0ULL,
		0xF6BD2EE1D69669E1ULL,
		0x37B9524131F86CE8ULL,
		0x81B5FEE078018A4BULL,
		0x2A794DBCB8BA6A54ULL
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
		0x9E27E35E20040BDBULL,
		0xBAD03F727CF2DD71ULL,
		0xF72DB99596D616D0ULL,
		0x05BA6460AA8D24AAULL,
		0x67BB809B827A4932ULL,
		0x36A63EBF98BA8D7BULL,
		0xCCBCE4CEAC89472AULL,
		0x37AC0E704C7F1BECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3C4FC6BC400817B6ULL,
		0x75A07EE4F9E5BAE3ULL,
		0xEE5B732B2DAC2DA1ULL,
		0x0B74C8C1551A4955ULL,
		0xCF77013704F49264ULL,
		0x6D4C7D7F31751AF6ULL,
		0x9979C99D59128E54ULL,
		0x6F581CE098FE37D9ULL
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
		0xC4396DAD33FE3691ULL,
		0xE112B120C033B6FAULL,
		0x193F5BD01B9FF857ULL,
		0xD9C5E8F00733A4DFULL,
		0xFED75BEEBCCE0DC5ULL,
		0xD774E9A98B0D5607ULL,
		0x6F5BE86CDA372DFCULL,
		0x1E5E32E9F1DB6046ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8872DB5A67FC6D22ULL,
		0xC225624180676DF5ULL,
		0x327EB7A0373FF0AFULL,
		0xB38BD1E00E6749BEULL,
		0xFDAEB7DD799C1B8BULL,
		0xAEE9D353161AAC0FULL,
		0xDEB7D0D9B46E5BF9ULL,
		0x3CBC65D3E3B6C08CULL
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
		0xDC962BB477A9F334ULL,
		0x862C367933CFC0E0ULL,
		0xB4E92505DBB1ADD5ULL,
		0x47F3DE3D56D650E5ULL,
		0x8F427A5E3B79FA78ULL,
		0x5D1AB23B3827B4EFULL,
		0x3D340740667FFE3CULL,
		0x1BFEAC1903B0F89FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB92C5768EF53E668ULL,
		0x0C586CF2679F81C1ULL,
		0x69D24A0BB7635BABULL,
		0x8FE7BC7AADACA1CBULL,
		0x1E84F4BC76F3F4F0ULL,
		0xBA356476704F69DFULL,
		0x7A680E80CCFFFC78ULL,
		0x37FD58320761F13EULL
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
		0x0DB76E6D323CC80DULL,
		0x12609075647E9508ULL,
		0xD8B9A427CEF82DCDULL,
		0x0E56D0281F9ED4FDULL,
		0x5E66D27D7EF5506BULL,
		0x801DC123D7157F20ULL,
		0xDD4CE9885C027BF8ULL,
		0x31832A3C20AD03E5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1B6EDCDA6479901AULL,
		0x24C120EAC8FD2A10ULL,
		0xB173484F9DF05B9AULL,
		0x1CADA0503F3DA9FBULL,
		0xBCCDA4FAFDEAA0D6ULL,
		0x003B8247AE2AFE40ULL,
		0xBA99D310B804F7F1ULL,
		0x63065478415A07CBULL
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
		0x847B7A8CEFD3E2B1ULL,
		0xBFA9446C7A76A68CULL,
		0xFD2742240D77EF6BULL,
		0xDCC377AF6C244811ULL,
		0xCBD25F609A3979C0ULL,
		0x25CA97FED8CDCB24ULL,
		0x7DCEA1764FD46702ULL,
		0x39C70AB1FD967881ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x08F6F519DFA7C562ULL,
		0x7F5288D8F4ED4D19ULL,
		0xFA4E84481AEFDED7ULL,
		0xB986EF5ED8489023ULL,
		0x97A4BEC13472F381ULL,
		0x4B952FFDB19B9649ULL,
		0xFB9D42EC9FA8CE04ULL,
		0x738E1563FB2CF102ULL
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
		0x5525420C08EA6F21ULL,
		0x4FFDAF7E4C77A7EBULL,
		0x01BBA33B9D61DDE1ULL,
		0xC673C5E71A93078EULL,
		0xF8F929542E48A96AULL,
		0x45E3ABE045453221ULL,
		0x37E1052FEE45F3EEULL,
		0x0E949656ECF6C78FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAA4A841811D4DE42ULL,
		0x9FFB5EFC98EF4FD6ULL,
		0x037746773AC3BBC2ULL,
		0x8CE78BCE35260F1CULL,
		0xF1F252A85C9152D5ULL,
		0x8BC757C08A8A6443ULL,
		0x6FC20A5FDC8BE7DCULL,
		0x1D292CADD9ED8F1EULL
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
		0xE5391ABE133635F4ULL,
		0x876442CCE8155746ULL,
		0x7AA4B4726458B51CULL,
		0x487F50151E74E791ULL,
		0xEF8FFFBFEAECF1CEULL,
		0x1E99B925FE0EDF92ULL,
		0xBB2637E25FCF796FULL,
		0x1657E804B57A3E4DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCA72357C266C6BE8ULL,
		0x0EC88599D02AAE8DULL,
		0xF54968E4C8B16A39ULL,
		0x90FEA02A3CE9CF22ULL,
		0xDF1FFF7FD5D9E39CULL,
		0x3D33724BFC1DBF25ULL,
		0x764C6FC4BF9EF2DEULL,
		0x2CAFD0096AF47C9BULL
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
		0x247120901ECFD11BULL,
		0xC72ACE0FF2C67394ULL,
		0x3D917B97D6CFCCDDULL,
		0x421E303C48B6BED0ULL,
		0x32539986036081B0ULL,
		0x7B6783DA3D5F1FFAULL,
		0x456EA63FCC65B2EEULL,
		0x143749DCFB3B6457ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x48E241203D9FA236ULL,
		0x8E559C1FE58CE728ULL,
		0x7B22F72FAD9F99BBULL,
		0x843C6078916D7DA0ULL,
		0x64A7330C06C10360ULL,
		0xF6CF07B47ABE3FF4ULL,
		0x8ADD4C7F98CB65DCULL,
		0x286E93B9F676C8AEULL
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
		0x745FF4FAE676CABEULL,
		0x6FB63F63F3088A4FULL,
		0xB4BA383BF2E61208ULL,
		0x387650E2C6CEF6C6ULL,
		0x58FF1E316EB92289ULL,
		0x5618BC8FABEF7381ULL,
		0xB8B0AE43F3F5E26FULL,
		0x02CCABD358C3DA6AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE8BFE9F5CCED957CULL,
		0xDF6C7EC7E611149EULL,
		0x69747077E5CC2410ULL,
		0x70ECA1C58D9DED8DULL,
		0xB1FE3C62DD724512ULL,
		0xAC31791F57DEE702ULL,
		0x71615C87E7EBC4DEULL,
		0x059957A6B187B4D5ULL
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
		0x7D1C8E1EDE69DBF9ULL,
		0x6D4AA23423E175B1ULL,
		0xCC910F7FDC577C0EULL,
		0xF90C023101F0095FULL,
		0xE97AAEF1F52234C2ULL,
		0x4776A739A28E6BBEULL,
		0x8E3CB4954D98BBF7ULL,
		0x23A08EB94CEA540AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFA391C3DBCD3B7F2ULL,
		0xDA95446847C2EB62ULL,
		0x99221EFFB8AEF81CULL,
		0xF218046203E012BFULL,
		0xD2F55DE3EA446985ULL,
		0x8EED4E73451CD77DULL,
		0x1C79692A9B3177EEULL,
		0x47411D7299D4A815ULL
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
		0xCF5563A576131C47ULL,
		0x08D9A9DCE37686EEULL,
		0xF98A9DA7790BD910ULL,
		0x9AFB892E56AFF7F4ULL,
		0xA28DFBADD92A8D67ULL,
		0x7F36E5204B1EC3B0ULL,
		0x54BFA272CB5A3108ULL,
		0x13F5917985ED6137ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9EAAC74AEC26388EULL,
		0x11B353B9C6ED0DDDULL,
		0xF3153B4EF217B220ULL,
		0x35F7125CAD5FEFE9ULL,
		0x451BF75BB2551ACFULL,
		0xFE6DCA40963D8761ULL,
		0xA97F44E596B46210ULL,
		0x27EB22F30BDAC26EULL
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
		0x021A3C5574EA92CAULL,
		0x9FC2279E4D851CC0ULL,
		0xB2DA99FB01A60D6CULL,
		0x33571AB895A99552ULL,
		0xCB5975C5E2AC4170ULL,
		0xC6E13E31D55B13D1ULL,
		0x601B527E2B5D8346ULL,
		0x167DD6A3A7DB1084ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x043478AAE9D52594ULL,
		0x3F844F3C9B0A3980ULL,
		0x65B533F6034C1AD9ULL,
		0x66AE35712B532AA5ULL,
		0x96B2EB8BC55882E0ULL,
		0x8DC27C63AAB627A3ULL,
		0xC036A4FC56BB068DULL,
		0x2CFBAD474FB62108ULL
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
		0x0E7987B0CFECE3D1ULL,
		0xF06BA2C28E6E6758ULL,
		0xFBA93CF1E2BABC7BULL,
		0xE3F94261B8A4F085ULL,
		0x1D2C997C413AD67AULL,
		0xC52F6ED01DE46462ULL,
		0x5AC4F7001A2D4E44ULL,
		0x1D237A2A0C4E5CE8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1CF30F619FD9C7A2ULL,
		0xE0D745851CDCCEB0ULL,
		0xF75279E3C57578F7ULL,
		0xC7F284C37149E10BULL,
		0x3A5932F88275ACF5ULL,
		0x8A5EDDA03BC8C8C4ULL,
		0xB589EE00345A9C89ULL,
		0x3A46F454189CB9D0ULL
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
		0x75AC339CB7D66351ULL,
		0xF7246640F1B1810FULL,
		0x908BC2A9366180FBULL,
		0x05D489624A26F5B0ULL,
		0xE922E98B82067D32ULL,
		0x0F7A8B0FB2D13916ULL,
		0xE44647F381F6ACA4ULL,
		0x3EBD0B5854ED8162ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEB5867396FACC6A2ULL,
		0xEE48CC81E363021EULL,
		0x211785526CC301F7ULL,
		0x0BA912C4944DEB61ULL,
		0xD245D317040CFA64ULL,
		0x1EF5161F65A2722DULL,
		0xC88C8FE703ED5948ULL,
		0x7D7A16B0A9DB02C5ULL
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
		0x45C246E43DCB675FULL,
		0xCAF58758F1980591ULL,
		0x8C38AAB0B2166EAEULL,
		0x68E19A32C6FB0FD5ULL,
		0x9B60669F90724C5EULL,
		0x7E33A74D0631A127ULL,
		0xE4460342F005F52FULL,
		0x13C22B113AC5A9EFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8B848DC87B96CEBEULL,
		0x95EB0EB1E3300B22ULL,
		0x18715561642CDD5DULL,
		0xD1C334658DF61FABULL,
		0x36C0CD3F20E498BCULL,
		0xFC674E9A0C63424FULL,
		0xC88C0685E00BEA5EULL,
		0x27845622758B53DFULL
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
		0x1246C0961FE2493DULL,
		0xD2E41222C40CE132ULL,
		0xCE170F7271431FE8ULL,
		0xE02E881736AFF94AULL,
		0x7A74B5913B95D85AULL,
		0xCEC6944CC5927D87ULL,
		0x111E8E9DBBDA7275ULL,
		0x289D4BFF402A170BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x248D812C3FC4927AULL,
		0xA5C824458819C264ULL,
		0x9C2E1EE4E2863FD1ULL,
		0xC05D102E6D5FF295ULL,
		0xF4E96B22772BB0B5ULL,
		0x9D8D28998B24FB0EULL,
		0x223D1D3B77B4E4EBULL,
		0x513A97FE80542E16ULL
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
		0x5AA5D7ECE525B299ULL,
		0x4CC341A423EB67D3ULL,
		0xC0435EA1154CD6D9ULL,
		0xEBEEFDD30C8CC43FULL,
		0x425E1FE83D763AD5ULL,
		0xD2B2863BA43F66EFULL,
		0xCE648AC2F437C3D0ULL,
		0x3C4A4156D6B5CBE1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB54BAFD9CA4B6532ULL,
		0x9986834847D6CFA6ULL,
		0x8086BD422A99ADB2ULL,
		0xD7DDFBA61919887FULL,
		0x84BC3FD07AEC75ABULL,
		0xA5650C77487ECDDEULL,
		0x9CC91585E86F87A1ULL,
		0x789482ADAD6B97C3ULL
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
		0x250EFAD34B8F9815ULL,
		0xC6A0DB91477C46A8ULL,
		0xF0B1479CE807B933ULL,
		0x6F95CEF4080FCF90ULL,
		0x2C6D903D15E333CCULL,
		0xA945B0320245E7BFULL,
		0xE167994E7121D76DULL,
		0x12414E054EB3FFB4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4A1DF5A6971F302AULL,
		0x8D41B7228EF88D50ULL,
		0xE1628F39D00F7267ULL,
		0xDF2B9DE8101F9F21ULL,
		0x58DB207A2BC66798ULL,
		0x528B6064048BCF7EULL,
		0xC2CF329CE243AEDBULL,
		0x24829C0A9D67FF69ULL
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
		0xC3B63CB391B279F0ULL,
		0x0C67E1C7B21841B0ULL,
		0x67166A295F76AFC3ULL,
		0xD61BFE2426D1F625ULL,
		0x78C8228E09B6AFE8ULL,
		0xE7ACC09D5D483618ULL,
		0x0EBA7E80BDC8ECAFULL,
		0x2F0E96B347121006ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x876C79672364F3E0ULL,
		0x18CFC38F64308361ULL,
		0xCE2CD452BEED5F86ULL,
		0xAC37FC484DA3EC4AULL,
		0xF190451C136D5FD1ULL,
		0xCF59813ABA906C30ULL,
		0x1D74FD017B91D95FULL,
		0x5E1D2D668E24200CULL
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
		0xC47DB63C6AE2BB67ULL,
		0xF182F978E42E6693ULL,
		0x426EC3C0260A7C0AULL,
		0xC318F02F2078B9A0ULL,
		0x10DCA2001ACC6C04ULL,
		0x761F9BE35FCA4F61ULL,
		0xE9C93B708E51B004ULL,
		0x14B6B48B27A07ACCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x88FB6C78D5C576CEULL,
		0xE305F2F1C85CCD27ULL,
		0x84DD87804C14F815ULL,
		0x8631E05E40F17340ULL,
		0x21B944003598D809ULL,
		0xEC3F37C6BF949EC2ULL,
		0xD39276E11CA36008ULL,
		0x296D69164F40F599ULL
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
		0x482A33B857493A56ULL,
		0x5ADB6AA493D550ACULL,
		0xB3A3113D0EE931F4ULL,
		0xE94D1C8EEB55FDABULL,
		0xD58AACA5625CC40CULL,
		0xC87D99E8DC408AEFULL,
		0xE80D3A7BBDDABC62ULL,
		0x1408DCAC74FC7770ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x90546770AE9274ACULL,
		0xB5B6D54927AAA158ULL,
		0x6746227A1DD263E8ULL,
		0xD29A391DD6ABFB57ULL,
		0xAB15594AC4B98819ULL,
		0x90FB33D1B88115DFULL,
		0xD01A74F77BB578C5ULL,
		0x2811B958E9F8EEE1ULL
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
		0xEE2060934A0C730CULL,
		0x733FDACFD8E17140ULL,
		0x9B6F0450215CA70DULL,
		0xC383747B7912E45DULL,
		0xE4B0AAC3A6CB5B9DULL,
		0x542712F7CE99D54BULL,
		0xE3560B8CEF77A152ULL,
		0x0C0D0009CFB593ADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDC40C1269418E618ULL,
		0xE67FB59FB1C2E281ULL,
		0x36DE08A042B94E1AULL,
		0x8706E8F6F225C8BBULL,
		0xC96155874D96B73BULL,
		0xA84E25EF9D33AA97ULL,
		0xC6AC1719DEEF42A4ULL,
		0x181A00139F6B275BULL
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
		0xC705F47561DDD186ULL,
		0xCD5FD9222301500CULL,
		0x8543206289CE3295ULL,
		0x35FF690E4537C8DBULL,
		0xB7BC5DB166F1E470ULL,
		0xBF33E8ADCC0F9326ULL,
		0x3923216B632A9C89ULL,
		0x23E684EFF7CE8E53ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8E0BE8EAC3BBA30CULL,
		0x9ABFB2444602A019ULL,
		0x0A8640C5139C652BULL,
		0x6BFED21C8A6F91B7ULL,
		0x6F78BB62CDE3C8E0ULL,
		0x7E67D15B981F264DULL,
		0x724642D6C6553913ULL,
		0x47CD09DFEF9D1CA6ULL
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
		0x2534353BCD1E7A45ULL,
		0xE5FEE3DE48D1931FULL,
		0xD115369F1B179F79ULL,
		0x70FE92BEB1295BAAULL,
		0x6EC1EAA9100D7961ULL,
		0x78F98F8C8BE19FB5ULL,
		0x0BCDA21F7A2817C5ULL,
		0x1B5A0069E1409BB1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4A686A779A3CF48AULL,
		0xCBFDC7BC91A3263EULL,
		0xA22A6D3E362F3EF3ULL,
		0xE1FD257D6252B755ULL,
		0xDD83D552201AF2C2ULL,
		0xF1F31F1917C33F6AULL,
		0x179B443EF4502F8AULL,
		0x36B400D3C2813762ULL
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
		0xE7FCEF113C17FEC8ULL,
		0xE0D7840CF4BCEF8FULL,
		0x3182EF15F499465CULL,
		0xC042A0B23DF200F6ULL,
		0xBB2EBF91E178D651ULL,
		0x79619B22838E06B2ULL,
		0x200675FDDF42174CULL,
		0x3F468A09FFF7FB7DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCFF9DE22782FFD90ULL,
		0xC1AF0819E979DF1FULL,
		0x6305DE2BE9328CB9ULL,
		0x808541647BE401ECULL,
		0x765D7F23C2F1ACA3ULL,
		0xF2C33645071C0D65ULL,
		0x400CEBFBBE842E98ULL,
		0x7E8D1413FFEFF6FAULL
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
		0x0B81C831E50CC514ULL,
		0x10B1F30B389D3916ULL,
		0x3256D550223145CDULL,
		0x9C68B3F0E2D1AEE5ULL,
		0xDDF735693A6E5E07ULL,
		0x7C2EA606702A6BA7ULL,
		0x99F9DB7E9AB982E5ULL,
		0x11F3C966BE208CE8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x17039063CA198A28ULL,
		0x2163E616713A722CULL,
		0x64ADAAA044628B9AULL,
		0x38D167E1C5A35DCAULL,
		0xBBEE6AD274DCBC0FULL,
		0xF85D4C0CE054D74FULL,
		0x33F3B6FD357305CAULL,
		0x23E792CD7C4119D1ULL
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
		0x63CFE59E04EEDE62ULL,
		0x8C996BE69660F543ULL,
		0x71C211CDC0B6E74AULL,
		0xA8E5BF36882436F1ULL,
		0xABAF01955EE16D23ULL,
		0x886671B7E89095FBULL,
		0x193C38D1C22782FAULL,
		0x2218DC79A4025618ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC79FCB3C09DDBCC4ULL,
		0x1932D7CD2CC1EA86ULL,
		0xE384239B816DCE95ULL,
		0x51CB7E6D10486DE2ULL,
		0x575E032ABDC2DA47ULL,
		0x10CCE36FD1212BF7ULL,
		0x327871A3844F05F5ULL,
		0x4431B8F34804AC30ULL
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
		0xB0E6F3F8A0CC8110ULL,
		0x5FE8DCF1C07ED19DULL,
		0x67FABC7C560FAF43ULL,
		0x9B4754357EA97CCDULL,
		0xBEDA91982137A38BULL,
		0xE9C2C09E46C0456AULL,
		0x7DC232C2B2B91929ULL,
		0x197AF765686F7B84ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x61CDE7F141990220ULL,
		0xBFD1B9E380FDA33BULL,
		0xCFF578F8AC1F5E86ULL,
		0x368EA86AFD52F99AULL,
		0x7DB52330426F4717ULL,
		0xD385813C8D808AD5ULL,
		0xFB84658565723253ULL,
		0x32F5EECAD0DEF708ULL
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
		0xA956F26A24FE2641ULL,
		0xD15AE97FF1E9B413ULL,
		0x469D13882D9CD1C2ULL,
		0xC01F8A092965954AULL,
		0x40154A9E713E2146ULL,
		0x476312B04025F83AULL,
		0x914EDB1C9DC57E9EULL,
		0x2D32685BC0CDD24BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x52ADE4D449FC4C82ULL,
		0xA2B5D2FFE3D36827ULL,
		0x8D3A27105B39A385ULL,
		0x803F141252CB2A94ULL,
		0x802A953CE27C428DULL,
		0x8EC62560804BF074ULL,
		0x229DB6393B8AFD3CULL,
		0x5A64D0B7819BA497ULL
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
		0x71BA3992398E0BDFULL,
		0xE5051F1114D1E044ULL,
		0xA7449B3FD3E40785ULL,
		0x0DA5F1F4EB4415B4ULL,
		0x74DA0AB271B2EA79ULL,
		0x2C37F303543155BDULL,
		0x1A433E6BCEA955CBULL,
		0x2EFBD1C7A112D22AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE3747324731C17BEULL,
		0xCA0A3E2229A3C088ULL,
		0x4E89367FA7C80F0BULL,
		0x1B4BE3E9D6882B69ULL,
		0xE9B41564E365D4F2ULL,
		0x586FE606A862AB7AULL,
		0x34867CD79D52AB96ULL,
		0x5DF7A38F4225A454ULL
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
		0x63C99857508102D0ULL,
		0x0C42CBABA3AE893CULL,
		0xF85B424443544244ULL,
		0x33FBDEEFA31A571EULL,
		0x80A2E3B9995AB7F9ULL,
		0xB6A2F9467F719322ULL,
		0xB86DAED794DC53ACULL,
		0x06C65F86B0CC1095ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC79330AEA10205A0ULL,
		0x18859757475D1278ULL,
		0xF0B6848886A88488ULL,
		0x67F7BDDF4634AE3DULL,
		0x0145C77332B56FF2ULL,
		0x6D45F28CFEE32645ULL,
		0x70DB5DAF29B8A759ULL,
		0x0D8CBF0D6198212BULL
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
		0xC289F96C5DA27DCDULL,
		0xD550C5406E0F4A0EULL,
		0xBCBF006B028887B7ULL,
		0x36ADA73678D65EB1ULL,
		0xCB37B60001CA7228ULL,
		0x941F797E19DBE108ULL,
		0xE17CBB670A05D350ULL,
		0x0A18994B90D1C974ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8513F2D8BB44FB9AULL,
		0xAAA18A80DC1E941DULL,
		0x797E00D605110F6FULL,
		0x6D5B4E6CF1ACBD63ULL,
		0x966F6C000394E450ULL,
		0x283EF2FC33B7C211ULL,
		0xC2F976CE140BA6A1ULL,
		0x1431329721A392E9ULL
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
		0xA85E2DB9BE019793ULL,
		0x4E8D9D951CCBE4DBULL,
		0x77DA66D575D5F0AAULL,
		0x72FE520F7D82FFB4ULL,
		0x35333812C710B4B3ULL,
		0xF93B03F6844A6A12ULL,
		0x9384E6B6F397BFD2ULL,
		0x251709C48F152003ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x50BC5B737C032F26ULL,
		0x9D1B3B2A3997C9B7ULL,
		0xEFB4CDAAEBABE154ULL,
		0xE5FCA41EFB05FF68ULL,
		0x6A6670258E216966ULL,
		0xF27607ED0894D424ULL,
		0x2709CD6DE72F7FA5ULL,
		0x4A2E13891E2A4007ULL
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
		0x81FD5492DE8145B9ULL,
		0xA658236716C434A1ULL,
		0x16E82F0BCE4911BBULL,
		0x3A28D81050F394CEULL,
		0xAA92F06FA9550DFDULL,
		0x1C08A5FC94AF7A51ULL,
		0xD138BC0EBDBAB301ULL,
		0x0324E869ADFC758FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x03FAA925BD028B72ULL,
		0x4CB046CE2D886943ULL,
		0x2DD05E179C922377ULL,
		0x7451B020A1E7299CULL,
		0x5525E0DF52AA1BFAULL,
		0x38114BF9295EF4A3ULL,
		0xA271781D7B756602ULL,
		0x0649D0D35BF8EB1FULL
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
		0x5AFD0115F80CB86EULL,
		0xF4333187FBF423CBULL,
		0x4DE2A470BC21BBA7ULL,
		0xE0CD853FEFC0FE24ULL,
		0x07AECD953BD9A10AULL,
		0x571CCD8BFCD7A7DFULL,
		0xF4962FA97CE04231ULL,
		0x18238164E7E1D371ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB5FA022BF01970DCULL,
		0xE866630FF7E84796ULL,
		0x9BC548E17843774FULL,
		0xC19B0A7FDF81FC48ULL,
		0x0F5D9B2A77B34215ULL,
		0xAE399B17F9AF4FBEULL,
		0xE92C5F52F9C08462ULL,
		0x304702C9CFC3A6E3ULL
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
		0x6A047D0CCC9F4250ULL,
		0x38C6977EF612D3E7ULL,
		0xE1B4C9EC440E82D8ULL,
		0x87BF8D9549BD01FAULL,
		0x68D0F567254DE70DULL,
		0xAE6509433EBC5397ULL,
		0x59F9896075BFB2DAULL,
		0x3778D9BF8BC48233ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD408FA19993E84A0ULL,
		0x718D2EFDEC25A7CEULL,
		0xC36993D8881D05B0ULL,
		0x0F7F1B2A937A03F5ULL,
		0xD1A1EACE4A9BCE1BULL,
		0x5CCA12867D78A72EULL,
		0xB3F312C0EB7F65B5ULL,
		0x6EF1B37F17890466ULL
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
		0xDBFAF6762F84699AULL,
		0xB0432D2A8FABD8FEULL,
		0x3A507926D860E969ULL,
		0x2BA912E7B2A14653ULL,
		0x47B2266E9E4FADCAULL,
		0x7FB5B7E63D6D9DA0ULL,
		0xCE56D7CBE7F60FFCULL,
		0x33F326AF87289FC3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB7F5ECEC5F08D334ULL,
		0x60865A551F57B1FDULL,
		0x74A0F24DB0C1D2D3ULL,
		0x575225CF65428CA6ULL,
		0x8F644CDD3C9F5B94ULL,
		0xFF6B6FCC7ADB3B40ULL,
		0x9CADAF97CFEC1FF8ULL,
		0x67E64D5F0E513F87ULL
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
		0x23E54F9397E47F4DULL,
		0xD6E6F18B0742C86CULL,
		0x861E5DF2103A0766ULL,
		0x1A3C2B4F25F78327ULL,
		0x2DD96C4F11D23A88ULL,
		0x3A044D4C5FE54CC6ULL,
		0xB447ACD0732E4254ULL,
		0x0B1A10727017E148ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x47CA9F272FC8FE9AULL,
		0xADCDE3160E8590D8ULL,
		0x0C3CBBE420740ECDULL,
		0x3478569E4BEF064FULL,
		0x5BB2D89E23A47510ULL,
		0x74089A98BFCA998CULL,
		0x688F59A0E65C84A8ULL,
		0x163420E4E02FC291ULL
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
		0x40F06E93F91005BDULL,
		0xEA748341C35E45FCULL,
		0xFCA6FDDA00479B5EULL,
		0x10F6F0D65E509822ULL,
		0x69DC2D18E8EED45DULL,
		0x685BB84B21E38AF1ULL,
		0x33BD96E03CB0B855ULL,
		0x12E8E4948AFBF167ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x81E0DD27F2200B7AULL,
		0xD4E9068386BC8BF8ULL,
		0xF94DFBB4008F36BDULL,
		0x21EDE1ACBCA13045ULL,
		0xD3B85A31D1DDA8BAULL,
		0xD0B7709643C715E2ULL,
		0x677B2DC0796170AAULL,
		0x25D1C92915F7E2CEULL
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
		0xCC27A7EF20C88265ULL,
		0x5BFE8A5A8E0B4D80ULL,
		0x6AC18AC5F8722362ULL,
		0x2130CD92E9B5BE4DULL,
		0xCF338577A8344232ULL,
		0x4CAF20FA2AFEC25EULL,
		0x98F3C92854B9248AULL,
		0x14216D37D92DB1B1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x984F4FDE419104CAULL,
		0xB7FD14B51C169B01ULL,
		0xD583158BF0E446C4ULL,
		0x42619B25D36B7C9AULL,
		0x9E670AEF50688464ULL,
		0x995E41F455FD84BDULL,
		0x31E79250A9724914ULL,
		0x2842DA6FB25B6363ULL
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
		0xB873A6CE8200AE58ULL,
		0xC5AF3D6AE27AC40EULL,
		0x859A92BD7230DFA7ULL,
		0xD92CCDD73661AA58ULL,
		0xF6147756886DA94BULL,
		0x59649D3A0960E46DULL,
		0x95EB28BDE1CE8650ULL,
		0x1F6D1BFCF3518C8FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x70E74D9D04015CB0ULL,
		0x8B5E7AD5C4F5881DULL,
		0x0B35257AE461BF4FULL,
		0xB2599BAE6CC354B1ULL,
		0xEC28EEAD10DB5297ULL,
		0xB2C93A7412C1C8DBULL,
		0x2BD6517BC39D0CA0ULL,
		0x3EDA37F9E6A3191FULL
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
		0x879C497FD946D78EULL,
		0x6B2212370C9EF2EBULL,
		0xFE167DE6865A82C1ULL,
		0x91F24D6FC18B4CC9ULL,
		0x36618A0C68272785ULL,
		0x5147D1CFE8E8B269ULL,
		0xD47E213C655B823EULL,
		0x049E29A448760CF7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F3892FFB28DAF1CULL,
		0xD644246E193DE5D7ULL,
		0xFC2CFBCD0CB50582ULL,
		0x23E49ADF83169993ULL,
		0x6CC31418D04E4F0BULL,
		0xA28FA39FD1D164D2ULL,
		0xA8FC4278CAB7047CULL,
		0x093C534890EC19EFULL
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
		0x7038CB13F91C303CULL,
		0xA44BE0DC1B454440ULL,
		0x8CD286503EA5EB9BULL,
		0x5616C802DE731B62ULL,
		0xB643DBF812271D54ULL,
		0x1B9131917D281CD6ULL,
		0xEB002694B5E50C4FULL,
		0x3FC60BA088531184ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE0719627F2386078ULL,
		0x4897C1B8368A8880ULL,
		0x19A50CA07D4BD737ULL,
		0xAC2D9005BCE636C5ULL,
		0x6C87B7F0244E3AA8ULL,
		0x37226322FA5039ADULL,
		0xD6004D296BCA189EULL,
		0x7F8C174110A62309ULL
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
		0x1FD7488CDA0AD5CDULL,
		0xB7C2D3D780767801ULL,
		0x52D79C49BEAACDA0ULL,
		0xD83C2E1D220E5E15ULL,
		0x57D2749347952588ULL,
		0x3FB20B0B254C40C1ULL,
		0x3FC4C0FB2C11B78BULL,
		0x17217D91FEB98E20ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3FAE9119B415AB9AULL,
		0x6F85A7AF00ECF002ULL,
		0xA5AF38937D559B41ULL,
		0xB0785C3A441CBC2AULL,
		0xAFA4E9268F2A4B11ULL,
		0x7F6416164A988182ULL,
		0x7F8981F658236F16ULL,
		0x2E42FB23FD731C40ULL
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
		0x44FC0CAAF14F0B03ULL,
		0x002FE7E7901393E0ULL,
		0x8D2F4A89F936CF4BULL,
		0x936C1B36EC9F3561ULL,
		0x4A2375A185F05B52ULL,
		0x19809B79630BE6D6ULL,
		0xED5B303890357637ULL,
		0x025135576AA561A8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x89F81955E29E1606ULL,
		0x005FCFCF202727C0ULL,
		0x1A5E9513F26D9E96ULL,
		0x26D8366DD93E6AC3ULL,
		0x9446EB430BE0B6A5ULL,
		0x330136F2C617CDACULL,
		0xDAB66071206AEC6EULL,
		0x04A26AAED54AC351ULL
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
		0x748CE7E4025AB8EBULL,
		0xF5E4015933A620FCULL,
		0xD79BC024960A78A8ULL,
		0xA74E63758D28A792ULL,
		0xE4E2F8BD93CDFC99ULL,
		0x8D1D161A9E3C87DAULL,
		0xF5BAB759B376CC45ULL,
		0x24F88D9F6D01AD5BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE919CFC804B571D6ULL,
		0xEBC802B2674C41F8ULL,
		0xAF3780492C14F151ULL,
		0x4E9CC6EB1A514F25ULL,
		0xC9C5F17B279BF933ULL,
		0x1A3A2C353C790FB5ULL,
		0xEB756EB366ED988BULL,
		0x49F11B3EDA035AB7ULL
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
		0x71A66AB2A1E08BCFULL,
		0x36951081D0F3A0E1ULL,
		0x5388697C70EABD2DULL,
		0x75D23D5675668FF2ULL,
		0xDB1B824D24882941ULL,
		0xB2F0E1B947202470ULL,
		0x01FE373A1AB2E409ULL,
		0x2B512E4D9E8B0770ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE34CD56543C1179EULL,
		0x6D2A2103A1E741C2ULL,
		0xA710D2F8E1D57A5AULL,
		0xEBA47AACEACD1FE4ULL,
		0xB637049A49105282ULL,
		0x65E1C3728E4048E1ULL,
		0x03FC6E743565C813ULL,
		0x56A25C9B3D160EE0ULL
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
		0x6B9043249C3048EDULL,
		0x2B5C63D641E1F4F1ULL,
		0x5E0E386987A2EF86ULL,
		0xD246E3EB219C3029ULL,
		0x6CDA6BF96D5CB461ULL,
		0x3E7E36B7BB1ECC99ULL,
		0xF2389159C72C47BEULL,
		0x0A5CE3625ECC7605ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD7208649386091DAULL,
		0x56B8C7AC83C3E9E2ULL,
		0xBC1C70D30F45DF0CULL,
		0xA48DC7D643386052ULL,
		0xD9B4D7F2DAB968C3ULL,
		0x7CFC6D6F763D9932ULL,
		0xE47122B38E588F7CULL,
		0x14B9C6C4BD98EC0BULL
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
		0x64995C7B3F1D6E22ULL,
		0x8F7EB1B609D5A5C6ULL,
		0x36C1A99EBCEB927DULL,
		0x324AFC78F664E6E2ULL,
		0xB0957876440130D6ULL,
		0xFE84151CC6EFEEC5ULL,
		0x02A1229366DCDAC4ULL,
		0x1EC064FA014150F7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC932B8F67E3ADC44ULL,
		0x1EFD636C13AB4B8CULL,
		0x6D83533D79D724FBULL,
		0x6495F8F1ECC9CDC4ULL,
		0x612AF0EC880261ACULL,
		0xFD082A398DDFDD8BULL,
		0x05424526CDB9B589ULL,
		0x3D80C9F40282A1EEULL
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
		0xF23B7097E6B74A50ULL,
		0x88EEE465FE2F5A04ULL,
		0xB737D20860407F3FULL,
		0x4228B78722B2F762ULL,
		0x2B48D975C48B68A4ULL,
		0xAD1DB17687203CCDULL,
		0x08CC3A641AAD925FULL,
		0x36B0DDEDF2C5E4ABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE476E12FCD6E94A0ULL,
		0x11DDC8CBFC5EB409ULL,
		0x6E6FA410C080FE7FULL,
		0x84516F0E4565EEC5ULL,
		0x5691B2EB8916D148ULL,
		0x5A3B62ED0E40799AULL,
		0x119874C8355B24BFULL,
		0x6D61BBDBE58BC956ULL
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
		0xE5B3837731854C9FULL,
		0x8BCC274AF75CA0ADULL,
		0x88530D1CB32EC7A5ULL,
		0xF4DF5F22B5799E12ULL,
		0xAC72062D3BB0BE17ULL,
		0x2FEF012A6CF3C4B5ULL,
		0x1F46551353B64F1AULL,
		0x3F3BEF39F577DA67ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCB6706EE630A993EULL,
		0x17984E95EEB9415BULL,
		0x10A61A39665D8F4BULL,
		0xE9BEBE456AF33C25ULL,
		0x58E40C5A77617C2FULL,
		0x5FDE0254D9E7896BULL,
		0x3E8CAA26A76C9E34ULL,
		0x7E77DE73EAEFB4CEULL
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
		0xE57860BFE29CC227ULL,
		0xBA34231343F89796ULL,
		0x1A1B896C65FA2E90ULL,
		0xE21A55F4FD6543E4ULL,
		0x4541CE4788F73C93ULL,
		0xED286558A1C23BF4ULL,
		0x6434310F43309E24ULL,
		0x303C6D6EEC52C25DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCAF0C17FC539844EULL,
		0x7468462687F12F2DULL,
		0x343712D8CBF45D21ULL,
		0xC434ABE9FACA87C8ULL,
		0x8A839C8F11EE7927ULL,
		0xDA50CAB1438477E8ULL,
		0xC868621E86613C49ULL,
		0x6078DADDD8A584BAULL
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
		0xEDB56051266957A9ULL,
		0x23C558300A5FF089ULL,
		0xA47696A347659CF3ULL,
		0x59253A56847E2C41ULL,
		0x2348653562E7E36BULL,
		0xE79B85AC1ECDA370ULL,
		0x91A1588DF182D9B7ULL,
		0x3510729D3D54D167ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDB6AC0A24CD2AF52ULL,
		0x478AB06014BFE113ULL,
		0x48ED2D468ECB39E6ULL,
		0xB24A74AD08FC5883ULL,
		0x4690CA6AC5CFC6D6ULL,
		0xCF370B583D9B46E0ULL,
		0x2342B11BE305B36FULL,
		0x6A20E53A7AA9A2CFULL
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
		0xFDC778DAA1F9FCBBULL,
		0x919472AE3547DB12ULL,
		0x853B3DF03864B3A0ULL,
		0x359934B9C471B875ULL,
		0x75E541CC6B389B58ULL,
		0x9DDA3717F73CE178ULL,
		0x7B66855ED3597ECDULL,
		0x01BCC18E9230299FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFB8EF1B543F3F976ULL,
		0x2328E55C6A8FB625ULL,
		0x0A767BE070C96741ULL,
		0x6B32697388E370EBULL,
		0xEBCA8398D67136B0ULL,
		0x3BB46E2FEE79C2F0ULL,
		0xF6CD0ABDA6B2FD9BULL,
		0x0379831D2460533EULL
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
		0x149013CF903188DBULL,
		0x5F1574C1C9045079ULL,
		0x3EB5110D3700D3E0ULL,
		0xEDA71EDDFB1D6FC8ULL,
		0xE1C57449818B873FULL,
		0x007AA5CF605D387CULL,
		0xB17A7CE2274D32EDULL,
		0x3B508D26CDC1B6EAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2920279F206311B6ULL,
		0xBE2AE9839208A0F2ULL,
		0x7D6A221A6E01A7C0ULL,
		0xDB4E3DBBF63ADF90ULL,
		0xC38AE89303170E7FULL,
		0x00F54B9EC0BA70F9ULL,
		0x62F4F9C44E9A65DAULL,
		0x76A11A4D9B836DD5ULL
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
		0xF0B986E83F0F46AFULL,
		0xE3A0D0720B70FE0AULL,
		0x3AEDD9F9FA03ED00ULL,
		0xB259F50504F2F71EULL,
		0xFB3E9D941A71EBC9ULL,
		0x693C18A420663D81ULL,
		0xAA1699B91EBA7D1EULL,
		0x3792D50006C53CE7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE1730DD07E1E8D5EULL,
		0xC741A0E416E1FC15ULL,
		0x75DBB3F3F407DA01ULL,
		0x64B3EA0A09E5EE3CULL,
		0xF67D3B2834E3D793ULL,
		0xD278314840CC7B03ULL,
		0x542D33723D74FA3CULL,
		0x6F25AA000D8A79CFULL
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
		0x868D6932D3E2E85AULL,
		0x28FB895CE90EC110ULL,
		0xC50B049323460E14ULL,
		0xFEE16DD01C329543ULL,
		0x8FBF604F2C872A56ULL,
		0xDD94A26AA459D429ULL,
		0x3A502A4DF9057D62ULL,
		0x0766DB67038B62F4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0D1AD265A7C5D0B4ULL,
		0x51F712B9D21D8221ULL,
		0x8A160926468C1C28ULL,
		0xFDC2DBA038652A87ULL,
		0x1F7EC09E590E54ADULL,
		0xBB2944D548B3A853ULL,
		0x74A0549BF20AFAC5ULL,
		0x0ECDB6CE0716C5E8ULL
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
		0xD097A9E73F8BD550ULL,
		0x6856A0D5ABE6FF52ULL,
		0xEA00D914326AD65CULL,
		0xF8651ED8F90D4D35ULL,
		0x8175E3A7DC1B59EDULL,
		0x5AFBC3346102F420ULL,
		0xC0A2DC9290C3E709ULL,
		0x110E9F7901576E93ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA12F53CE7F17AAA0ULL,
		0xD0AD41AB57CDFEA5ULL,
		0xD401B22864D5ACB8ULL,
		0xF0CA3DB1F21A9A6BULL,
		0x02EBC74FB836B3DBULL,
		0xB5F78668C205E841ULL,
		0x8145B9252187CE12ULL,
		0x221D3EF202AEDD27ULL
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
		0xAF08D180EC825F7BULL,
		0xF575858017F0C215ULL,
		0x297A88E50B270231ULL,
		0xEA2FF316E8BBA5F6ULL,
		0xD08C12EC9A3C3196ULL,
		0x66C4CE57E5C2DCAFULL,
		0x0CC28DB6B2105EE5ULL,
		0x2B8F568FE521E39CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5E11A301D904BEF6ULL,
		0xEAEB0B002FE1842BULL,
		0x52F511CA164E0463ULL,
		0xD45FE62DD1774BECULL,
		0xA11825D93478632DULL,
		0xCD899CAFCB85B95FULL,
		0x19851B6D6420BDCAULL,
		0x571EAD1FCA43C738ULL
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
		0x6343EDBD8D2D8135ULL,
		0xAEF8CE2DABFF4778ULL,
		0x54EE5258A265CCBDULL,
		0xF07A0BB93FF860B9ULL,
		0x8547A6B63A0A332AULL,
		0x451A10EF653FDBD2ULL,
		0xD99E479CDAE86B03ULL,
		0x3F026BA7123F7BC7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC687DB7B1A5B026AULL,
		0x5DF19C5B57FE8EF0ULL,
		0xA9DCA4B144CB997BULL,
		0xE0F417727FF0C172ULL,
		0x0A8F4D6C74146655ULL,
		0x8A3421DECA7FB7A5ULL,
		0xB33C8F39B5D0D606ULL,
		0x7E04D74E247EF78FULL
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
		0x56FA895036E4CEC3ULL,
		0x0020A0923DC5FEF4ULL,
		0x34D4C0A4CC66010EULL,
		0xA84E1BD390A89F83ULL,
		0xD33B4C539C914A8DULL,
		0xD0F0D8D85DA31C7CULL,
		0xA5DADCEEDA2CEFECULL,
		0x151293C369F0F92DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xADF512A06DC99D86ULL,
		0x004141247B8BFDE8ULL,
		0x69A9814998CC021CULL,
		0x509C37A721513F06ULL,
		0xA67698A73922951BULL,
		0xA1E1B1B0BB4638F9ULL,
		0x4BB5B9DDB459DFD9ULL,
		0x2A252786D3E1F25BULL
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
		0xC1208DFC39EE63ADULL,
		0x97267BDB77DB92A3ULL,
		0x03BD6D2D63625848ULL,
		0xFC4EABD27227FBF0ULL,
		0xF0BD287A538516A4ULL,
		0x6CA613B7C9E0ABBBULL,
		0xAF61F8561F91887AULL,
		0x3B79BF11C0F0F0B0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x82411BF873DCC75AULL,
		0x2E4CF7B6EFB72547ULL,
		0x077ADA5AC6C4B091ULL,
		0xF89D57A4E44FF7E0ULL,
		0xE17A50F4A70A2D49ULL,
		0xD94C276F93C15777ULL,
		0x5EC3F0AC3F2310F4ULL,
		0x76F37E2381E1E161ULL
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
		0x09DCCB945C726C39ULL,
		0xC501F17BC916D082ULL,
		0x09FEB375E8F01FC5ULL,
		0xB828A035B583F809ULL,
		0xBB308F18A88D12C1ULL,
		0x134650606E6A4F29ULL,
		0x6ED01833B16A917FULL,
		0x16939F1104173B86ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x13B99728B8E4D872ULL,
		0x8A03E2F7922DA104ULL,
		0x13FD66EBD1E03F8BULL,
		0x7051406B6B07F012ULL,
		0x76611E31511A2583ULL,
		0x268CA0C0DCD49E53ULL,
		0xDDA0306762D522FEULL,
		0x2D273E22082E770CULL
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
		0xC288F41CEB164A09ULL,
		0x16324205EE4B91AFULL,
		0x3ABBD92D64C88C98ULL,
		0xA400CDA16817BC8AULL,
		0x18760BF2844CC2FBULL,
		0x609774ED7D6BF323ULL,
		0x695BC5139CE4B760ULL,
		0x0F93342343972C6DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8511E839D62C9412ULL,
		0x2C64840BDC97235FULL,
		0x7577B25AC9911930ULL,
		0x48019B42D02F7914ULL,
		0x30EC17E5089985F7ULL,
		0xC12EE9DAFAD7E646ULL,
		0xD2B78A2739C96EC0ULL,
		0x1F266846872E58DAULL
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
		0xB908D4C9788D0215ULL,
		0x199F9079546D1305ULL,
		0x9A08449002038739ULL,
		0x78B4F80D4AA865E6ULL,
		0x26DDC86D0BBA7CA5ULL,
		0x8B03A597A77B760DULL,
		0x91C3F2494DBC80DEULL,
		0x303E295BDED89F92ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7211A992F11A042AULL,
		0x333F20F2A8DA260BULL,
		0x3410892004070E72ULL,
		0xF169F01A9550CBCDULL,
		0x4DBB90DA1774F94AULL,
		0x16074B2F4EF6EC1AULL,
		0x2387E4929B7901BDULL,
		0x607C52B7BDB13F25ULL
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
		0x9D8C69BDB79D2D9AULL,
		0x81B11DD6F5892ADFULL,
		0x67497D8F7D360D32ULL,
		0xD6FCBBDC9C3781D4ULL,
		0x01FDABA416949739ULL,
		0x108F2A3D96C00895ULL,
		0x35CAB03356A8F072ULL,
		0x346ED4E7D6BCBF43ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3B18D37B6F3A5B34ULL,
		0x03623BADEB1255BFULL,
		0xCE92FB1EFA6C1A65ULL,
		0xADF977B9386F03A8ULL,
		0x03FB57482D292E73ULL,
		0x211E547B2D80112AULL,
		0x6B956066AD51E0E4ULL,
		0x68DDA9CFAD797E86ULL
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
		0x33ADE5E306D51617ULL,
		0x59FCA52CB3F07974ULL,
		0xBBDDC1D33098655BULL,
		0x232D2182BFC7FF42ULL,
		0xBE7A3C2DE1F8D157ULL,
		0xC3D2102583909D45ULL,
		0xA898AEA38AC8E045ULL,
		0x140EAEF94CA77494ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x675BCBC60DAA2C2EULL,
		0xB3F94A5967E0F2E8ULL,
		0x77BB83A66130CAB6ULL,
		0x465A43057F8FFE85ULL,
		0x7CF4785BC3F1A2AEULL,
		0x87A4204B07213A8BULL,
		0x51315D471591C08BULL,
		0x281D5DF2994EE929ULL
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
		0xA30DDFCC3872E66FULL,
		0x8FB3467264D935CDULL,
		0x6F14B386244F3326ULL,
		0x6D69D82746E74EBCULL,
		0xBC057EB11AD066CEULL,
		0x98A9528BD33701EFULL,
		0x2FF1EF3E26368E16ULL,
		0x31EF3058615E2E90ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x461BBF9870E5CCDEULL,
		0x1F668CE4C9B26B9BULL,
		0xDE29670C489E664DULL,
		0xDAD3B04E8DCE9D78ULL,
		0x780AFD6235A0CD9CULL,
		0x3152A517A66E03DFULL,
		0x5FE3DE7C4C6D1C2DULL,
		0x63DE60B0C2BC5D20ULL
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
		0xC2F3465E4A913394ULL,
		0x71592176B375AC73ULL,
		0xB42AF489036B76C6ULL,
		0x69E34F5B91DABB7CULL,
		0xD531C85BA0615C7AULL,
		0x4C40EA741ED00ACEULL,
		0x9EB0B639EE02F705ULL,
		0x1AE990F957B1A886ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x85E68CBC95226728ULL,
		0xE2B242ED66EB58E7ULL,
		0x6855E91206D6ED8CULL,
		0xD3C69EB723B576F9ULL,
		0xAA6390B740C2B8F4ULL,
		0x9881D4E83DA0159DULL,
		0x3D616C73DC05EE0AULL,
		0x35D321F2AF63510DULL
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
		0x29D38AC53E004367ULL,
		0x350EBC6E7BBD79B9ULL,
		0xFC5B882C8B4232BFULL,
		0x2FF80C20B8F90BECULL,
		0x498ACAF69C20D5C2ULL,
		0x30FC0BAE1A5E59BAULL,
		0x8CE4F43B29115879ULL,
		0x2153ECAEDC504919ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x53A7158A7C0086CEULL,
		0x6A1D78DCF77AF372ULL,
		0xF8B710591684657EULL,
		0x5FF0184171F217D9ULL,
		0x931595ED3841AB84ULL,
		0x61F8175C34BCB374ULL,
		0x19C9E8765222B0F2ULL,
		0x42A7D95DB8A09233ULL
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
		0x9173F08CE5191F1DULL,
		0xC80C1D22C249FB42ULL,
		0x80CCDA2280C67B4BULL,
		0x1EE8F99B903DA22AULL,
		0x49B5FB54F811D8F3ULL,
		0x8091BDFBE968FA4EULL,
		0x090359DF37B29699ULL,
		0x1ADCE84D6072F708ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x22E7E119CA323E3AULL,
		0x90183A458493F685ULL,
		0x0199B445018CF697ULL,
		0x3DD1F337207B4455ULL,
		0x936BF6A9F023B1E6ULL,
		0x01237BF7D2D1F49CULL,
		0x1206B3BE6F652D33ULL,
		0x35B9D09AC0E5EE10ULL
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
		0x02E91E518A8E6C2DULL,
		0x363E7412422D65A1ULL,
		0x293D4FC77A270353ULL,
		0x470821367D107B95ULL,
		0x5CB201DA555C39ECULL,
		0xFEB22855FC4EED0EULL,
		0xE566F0136D455909ULL,
		0x36062F4E8384D5A8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x05D23CA3151CD85AULL,
		0x6C7CE824845ACB42ULL,
		0x527A9F8EF44E06A6ULL,
		0x8E10426CFA20F72AULL,
		0xB96403B4AAB873D8ULL,
		0xFD6450ABF89DDA1CULL,
		0xCACDE026DA8AB213ULL,
		0x6C0C5E9D0709AB51ULL
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
		0x4DAEF46C2CFA91FBULL,
		0x12B6D9A2D83043DDULL,
		0xB75516C56B52F98EULL,
		0xB5BDD64311BA2637ULL,
		0x25A5B0C5CC7E1948ULL,
		0x0A12626A8DE15353ULL,
		0x9585068F0DA5A4CFULL,
		0x0F2C349C0682F24FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9B5DE8D859F523F6ULL,
		0x256DB345B06087BAULL,
		0x6EAA2D8AD6A5F31CULL,
		0x6B7BAC8623744C6FULL,
		0x4B4B618B98FC3291ULL,
		0x1424C4D51BC2A6A6ULL,
		0x2B0A0D1E1B4B499EULL,
		0x1E5869380D05E49FULL
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
		0x6A94836A03C46D22ULL,
		0x867C40767A513CE9ULL,
		0x661A63EBC08D0B83ULL,
		0xE309A351A7B553F8ULL,
		0x72D6524EB251C501ULL,
		0x58EFB01E785881DEULL,
		0x8ED5142C532A6E22ULL,
		0x0CFD505DBB24B830ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD52906D40788DA44ULL,
		0x0CF880ECF4A279D2ULL,
		0xCC34C7D7811A1707ULL,
		0xC61346A34F6AA7F0ULL,
		0xE5ACA49D64A38A03ULL,
		0xB1DF603CF0B103BCULL,
		0x1DAA2858A654DC44ULL,
		0x19FAA0BB76497061ULL
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
		0xBAD41E0C44A51254ULL,
		0xAE27F5DE610661F0ULL,
		0xEA3E07804D38B720ULL,
		0x9FBFF7573A86B1CFULL,
		0x207F44E3594D0DE2ULL,
		0xE6561BEF79088A6FULL,
		0xD9195DB3C9A8C0F8ULL,
		0x38CF4E4788A8070CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x75A83C18894A24A8ULL,
		0x5C4FEBBCC20CC3E1ULL,
		0xD47C0F009A716E41ULL,
		0x3F7FEEAE750D639FULL,
		0x40FE89C6B29A1BC5ULL,
		0xCCAC37DEF21114DEULL,
		0xB232BB67935181F1ULL,
		0x719E9C8F11500E19ULL
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
		0x2F0585539FAF9237ULL,
		0x0067AB7E43305385ULL,
		0x1462F6B9E66CD376ULL,
		0x8F6C476E82E1D3ECULL,
		0x9E42C01D6003DBCAULL,
		0xFBE607FC4EE673BDULL,
		0x824EC6142FF4AD4EULL,
		0x2E36DD2EC6ECC98AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5E0B0AA73F5F246EULL,
		0x00CF56FC8660A70AULL,
		0x28C5ED73CCD9A6ECULL,
		0x1ED88EDD05C3A7D8ULL,
		0x3C85803AC007B795ULL,
		0xF7CC0FF89DCCE77BULL,
		0x049D8C285FE95A9DULL,
		0x5C6DBA5D8DD99315ULL
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
		0xC9412E4B2A5CF765ULL,
		0xF9EF1CEAF9FE4292ULL,
		0x4403226A1A54CC0CULL,
		0x9831F4C2FA259852ULL,
		0x47A9D195F41653D3ULL,
		0x6C7ADC3A8D1BDDDFULL,
		0xE5CAE227B20CC8BEULL,
		0x0156CA215C047219ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x92825C9654B9EECAULL,
		0xF3DE39D5F3FC8525ULL,
		0x880644D434A99819ULL,
		0x3063E985F44B30A4ULL,
		0x8F53A32BE82CA7A7ULL,
		0xD8F5B8751A37BBBEULL,
		0xCB95C44F6419917CULL,
		0x02AD9442B808E433ULL
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
		0x8F784B0816DB30A6ULL,
		0x6E510276F4F4AB4FULL,
		0xDEAB62857507A446ULL,
		0x904CDF0AF00ECC76ULL,
		0x03F9B23C3C04BAF5ULL,
		0xC7B720B0C19030ABULL,
		0xFD15BBD904D3E01CULL,
		0x2BDA0788EA4D6F4EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1EF096102DB6614CULL,
		0xDCA204EDE9E9569FULL,
		0xBD56C50AEA0F488CULL,
		0x2099BE15E01D98EDULL,
		0x07F36478780975EBULL,
		0x8F6E416183206156ULL,
		0xFA2B77B209A7C039ULL,
		0x57B40F11D49ADE9DULL
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
		0x61DF46376C0EE2FCULL,
		0xBA73619511389C43ULL,
		0xA39FE4E996552A64ULL,
		0x8B56BCB398DD720FULL,
		0x03450BAD6655AC1AULL,
		0x65404380ED4F10DBULL,
		0xCF26062EC5134214ULL,
		0x15AABD5D89CB9D12ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC3BE8C6ED81DC5F8ULL,
		0x74E6C32A22713886ULL,
		0x473FC9D32CAA54C9ULL,
		0x16AD796731BAE41FULL,
		0x068A175ACCAB5835ULL,
		0xCA808701DA9E21B6ULL,
		0x9E4C0C5D8A268428ULL,
		0x2B557ABB13973A25ULL
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
		0xCEF41498BCB3DCB5ULL,
		0xC37AECBFA0BD1B3DULL,
		0x8EA197F5688559D2ULL,
		0x052E829C062824FEULL,
		0x90A2DCAB6CAA9B97ULL,
		0xC61E01837EA379F3ULL,
		0x3E14CE4DE4E345C0ULL,
		0x2D904E0B1CE7E120ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9DE829317967B96AULL,
		0x86F5D97F417A367BULL,
		0x1D432FEAD10AB3A5ULL,
		0x0A5D05380C5049FDULL,
		0x2145B956D955372EULL,
		0x8C3C0306FD46F3E7ULL,
		0x7C299C9BC9C68B81ULL,
		0x5B209C1639CFC240ULL
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
		0x0EED55F8BF2A82C7ULL,
		0xF10D0F8A82528B92ULL,
		0x67502F80E9F91FCEULL,
		0xBF30B97700543646ULL,
		0x2C527E0702F84950ULL,
		0x2DF777E0BD438156ULL,
		0x54CE4A2E83951187ULL,
		0x0F463D93D1976473ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1DDAABF17E55058EULL,
		0xE21A1F1504A51724ULL,
		0xCEA05F01D3F23F9DULL,
		0x7E6172EE00A86C8CULL,
		0x58A4FC0E05F092A1ULL,
		0x5BEEEFC17A8702ACULL,
		0xA99C945D072A230EULL,
		0x1E8C7B27A32EC8E6ULL
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
		0x68AE0DD7193E594DULL,
		0x7E54097F8243CF56ULL,
		0xB5807F2DAD5A02A2ULL,
		0x2E643D4B78FC81EBULL,
		0x33D9E2740B129CFAULL,
		0x03F868D63C23FFC6ULL,
		0x7BAAD600FA1DA154ULL,
		0x009154898B2C0FC8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD15C1BAE327CB29AULL,
		0xFCA812FF04879EACULL,
		0x6B00FE5B5AB40544ULL,
		0x5CC87A96F1F903D7ULL,
		0x67B3C4E8162539F4ULL,
		0x07F0D1AC7847FF8CULL,
		0xF755AC01F43B42A8ULL,
		0x0122A91316581F90ULL
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
		0x64FA06F7330BE6B5ULL,
		0x0E3C533A6F2168DEULL,
		0x1F005CEC98987CF3ULL,
		0x5A2F16A8E196D885ULL,
		0x0D8D0969790A8EB2ULL,
		0x56BD6B0328DB44A6ULL,
		0xA24A49E6EBA1E0FAULL,
		0x17EDB0622FB4AE32ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC9F40DEE6617CD6AULL,
		0x1C78A674DE42D1BCULL,
		0x3E00B9D93130F9E6ULL,
		0xB45E2D51C32DB10AULL,
		0x1B1A12D2F2151D64ULL,
		0xAD7AD60651B6894CULL,
		0x449493CDD743C1F4ULL,
		0x2FDB60C45F695C65ULL
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
		0x15B6CFBCDEE9EDA5ULL,
		0x39627BBC35A70BD9ULL,
		0x7DAE3BD7CDAE77BBULL,
		0x05E12580DF9BC07DULL,
		0x6C541184DC5D8EB0ULL,
		0x826E77CCC30E1DD1ULL,
		0xD506B7AC47EC1558ULL,
		0x018739E3ECB0C3F3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2B6D9F79BDD3DB4AULL,
		0x72C4F7786B4E17B2ULL,
		0xFB5C77AF9B5CEF76ULL,
		0x0BC24B01BF3780FAULL,
		0xD8A82309B8BB1D60ULL,
		0x04DCEF99861C3BA2ULL,
		0xAA0D6F588FD82AB1ULL,
		0x030E73C7D96187E7ULL
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
	return 0;
}