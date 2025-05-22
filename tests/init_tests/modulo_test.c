#include "../tests.h"

int32_t curve25519_key_modulo_test(void) {
	printf("Modulo Test\n");
	curve25519_key_t k1 = {.key64 = {
		0x411AFE0136FBE33FULL,
		0xCA79837AD51132AFULL,
		0x60253E03BB7DAD70ULL,
		0x7AB02EF301E28B6EULL,
		0xF43331DF24D59F14ULL,
		0xA07A93AC090FA988ULL,
		0xD7E73B987A9C4873ULL,
		0x973401FFF801DA32ULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0x80B46520AEB1838EULL,
		0x9CAB6F042D645D03ULL,
		0x6C7816A5EEB06E9AULL,
		0x6C687AF1D228EEFAULL,
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
		0x60EC08FF734C48FFULL,
		0xEA9FD9C3F1E0671AULL,
		0xC4082725CB9154AEULL,
		0xBEA3C139E45AC31DULL,
		0x2E9EC34625ADB8D4ULL,
		0xC0AA6B7ABFADD0D0ULL,
		0x868BF5C3915A674FULL,
		0x26A1374FF06A9716ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4C7D05690B15B95BULL,
		0x83EBCDFC65AD6601ULL,
		0xBCCEA22D5EFCAA85ULL,
		0x7A91F717942D3075ULL,
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
		0xB68EF57514A2D0BAULL,
		0x5459607449BA161FULL,
		0x4270ADB27DFF9F06ULL,
		0xDD41A352A005B85CULL,
		0x525FE8167765E8DBULL,
		0x21BE313C848A0DD2ULL,
		0x8DBC327A088B0483ULL,
		0xB4C27C1806958774ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF0CB68CACDC36551ULL,
		0x5694AF6FF6382357ULL,
		0x4C602BCFC2A24A7DULL,
		0x32200EE39A37D3A9ULL,
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
		0x83517EBAB925A333ULL,
		0xF130939BB465C292ULL,
		0xE65B3E9A4385AA46ULL,
		0xDF5D7A7366A95043ULL,
		0x48E0BB25FE6793DBULL,
		0xC4C26240FA38987DULL,
		0x7304611865BA3F55ULL,
		0x5D66741459DF496DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x54AD465E7C8597DCULL,
		0x260B2940D8CC652BULL,
		0xF901A8395D2B1102ULL,
		0x3C92B578BDCE3682ULL,
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
		0x1FF58D40AEA88E74ULL,
		0x428D7D614DB9C6A4ULL,
		0xE4533049C87F8C3DULL,
		0x899374D254B6C6B2ULL,
		0xA45DB2191650D09AULL,
		0xBBB159F9E9203FE1ULL,
		0x9823879BEF3644EFULL,
		0xC92471ED0314C86FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x85DDFCF9FEA789C4ULL,
		0x1EE0D879E8834222ULL,
		0x7999516F4A8DC7D3ULL,
		0x64FC5E00C9CC8743ULL,
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
		0xDDB9EBA58EF07E3CULL,
		0x1FB3F8B3656EB608ULL,
		0x64101902615DC09BULL,
		0x264B7FA7C961A9DEULL,
		0xDDD14228BE901FFEULL,
		0xF5657013EAE6FB12ULL,
		0xDBDA22527800F371ULL,
		0x296CDD6201DAA6FBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCAC9BDB1D8553ED4ULL,
		0x8CC29BA843B7FAD5ULL,
		0x067131403181E385ULL,
		0x4C745C340FD67341ULL,
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
		0x9FBC37584910CA6CULL,
		0x5FB8E83EF285371BULL,
		0x34D39583A8A256A2ULL,
		0x6AE42319062CE41DULL,
		0xFBED3301742D5135ULL,
		0x660D82D2832CCB0EULL,
		0xF303C6D6B149668FULL,
		0x32D9EAF1F6C69579ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x04F1C98F87CAD967ULL,
		0x85BA537E6B2B5B55ULL,
		0x47631961F9878FEBULL,
		0x773D0303A7A71437ULL,
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
		0x06195A5FB6E92312ULL,
		0x401DB596558BF947ULL,
		0xEC47729E7DC69440ULL,
		0xE3AE87450B9DF1EDULL,
		0x42E0585CF7FC790BULL,
		0x34A482B13B6CC8A7ULL,
		0x51DFFCEBD14D1D3BULL,
		0x581B63D7AD3E6DA0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF366782C86631CB5ULL,
		0x10891BE527B1C21AULL,
		0x1386FD9F8F38EB0AULL,
		0x77BF5948C2E237BAULL,
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
		0x14537CD8866E9BAEULL,
		0xF0F06FF1CE98442EULL,
		0xA56AE5AAFAE79B91ULL,
		0x43E1BF6A9CA8BA81ULL,
		0xA6C2BB3B053AA38EULL,
		0xA68BFA2C36638769ULL,
		0xEE9F9E47192CDC0FULL,
		0xFFB0811D9AFB98CEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD53B479B4D22E866ULL,
		0xA9B79281E15E5DDCULL,
		0x111C6438B79045E4ULL,
		0x3814E9CF9E016939ULL,
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
		0x10DA9CF666A48C97ULL,
		0x9CD5DE457D5FDAC6ULL,
		0x37AB60792FADFE3FULL,
		0x304A54E4CB61CA98ULL,
		0x170BF7AF9DBC35B6ULL,
		0x9CA9BBE0A5200885ULL,
		0x3CF9E1A63A1D6B7BULL,
		0xAB52E7AEDAD3EEADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7CA16107D0948964ULL,
		0xDE07C19E00211E87ULL,
		0x44C2DF25D00BF298ULL,
		0x1E98B8D946D7384FULL,
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
		0x8A27544869491B5AULL,
		0xFACCE58375AFA487ULL,
		0x5008BC24AEF4F4B2ULL,
		0x612D0D529B6DEAAAULL,
		0xDDA0858E37637B2AULL,
		0x44C063FFABA823E6ULL,
		0x1A23E35722999B7BULL,
		0x23BD9FB6BDA67345ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6FFB2764A20D6467ULL,
		0x2F5BBD76F0A4F8CCULL,
		0x315C7B13D1C208FFULL,
		0x2F52C272C22306ECULL,
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
		0x8FFCE0397D264BB2ULL,
		0xC1815C31A2494EE5ULL,
		0x9CCC7BD1F94FD92FULL,
		0x36FABAB330B86A75ULL,
		0x60815CEFA8DC1A0CULL,
		0x6FA9809EE28EC5D1ULL,
		0xE2C2C814094EBC52ULL,
		0x5558106B362A585DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE330ABCC8DD22B55ULL,
		0x54AA73C7437AABF9ULL,
		0x45B62ECB5AFFCD6CULL,
		0x620D2A9D3B018865ULL,
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
		0x52923E37DEA140D3ULL,
		0x5C0BF1D5CDA74796ULL,
		0x1726BBADCC188576ULL,
		0x095208EB78582CE8ULL,
		0x201997FD664EC5D3ULL,
		0x2AFB4BB60081C2E6ULL,
		0x9372E63DFC218722ULL,
		0xEFA7F722B30E1996ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x165ECDD50E52A36AULL,
		0xBD592ED9E0EA35BFULL,
		0xFA34E8E139129488ULL,
		0x1C40B8120C6FF941ULL,
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
		0xD1FB2B08328639EAULL,
		0xE6F07CF36D6D4A12ULL,
		0x83FFB5C5A608EEF3ULL,
		0xF327371B8960FDA1ULL,
		0xA4D86796B134E5BAULL,
		0x88C0508F0C820CB4ULL,
		0x06C7E8E886F8D242ULL,
		0x049E6B9384949749ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4A1A8B66806053BFULL,
		0x337C722F48BB2CE3ULL,
		0x85AC4849AEF824D4ULL,
		0x22AB2F01376F7278ULL,
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
		0xE51434AA979D41FFULL,
		0xF9A6BA081BDCFAA9ULL,
		0xB2D41B87F5C63B37ULL,
		0x812E94E884ED9CFBULL,
		0x08F86FC9DDF6AD38ULL,
		0x222DDF41FBE6F03CULL,
		0xEC910D927150851FULL,
		0xC002A776B19BF3F1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x39F4CCA18A3AFC9DULL,
		0x0C75DDD38024A393ULL,
		0xD05C1F44C7B9FDD7ULL,
		0x01937086E213D2E4ULL,
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
		0xDFDE6999890CB897ULL,
		0x5DEAE7B94F91B34DULL,
		0x4826978416281016ULL,
		0xD017B46D0A57624FULL,
		0xF1EE0A5EC8BCED6BULL,
		0xF8ECCA3E6794A966ULL,
		0x74FDA16CF9404512ULL,
		0x5528ABCFEC74735CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC933F3AB5517F867ULL,
		0x5110ECFCAFA2D895ULL,
		0xA5CC8DB115B250E7ULL,
		0x7421354A23A08208ULL,
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
		0x670A685946C3B81BULL,
		0x2E649DADC4AD975BULL,
		0xC560A657904C9316ULL,
		0x2821D8F1896B849DULL,
		0x36ED403BF59020ADULL,
		0xA219B8F9B8394B76ULL,
		0xD57D390D8B1A9D42ULL,
		0x19DFF6A7BB0C79F9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8E41F13FBA28924EULL,
		0x3E3612BF1D2ECAE7ULL,
		0x75F71E5A363FEAFAULL,
		0x7F6075D74D459FB3ULL,
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
		0x1BD786283000E8B4ULL,
		0xAFFE4FF90138B407ULL,
		0xB5114FF6704D8DC1ULL,
		0xBE44443A565E8FBCULL,
		0x5025CD2553BA8467ULL,
		0x5841572F23930F23ULL,
		0xF9977E165493CB8AULL,
		0x5AD97C01F5DA53EAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0173F9B29DB09212ULL,
		0xC9B140F8490CF345ULL,
		0xC18E0746FE3DC44AULL,
		0x3A8CAC84D4C7049DULL,
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
		0x2028FFB336619969ULL,
		0x2DEA2922BAD11145ULL,
		0xB750EF3AF494E98DULL,
		0x956932CB1F07AFE7ULL,
		0xFDACBD66EFF129C5ULL,
		0xA7CD38FCBBB185B0ULL,
		0x760D6C32FCF9C41EULL,
		0xBE938C5F56ABE68AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC7CD1CFAD42DD0E2ULL,
		0x16609EA6972AE98AULL,
		0x3D4EFECC81A8061AULL,
		0x5F5008F1FC8BE875ULL,
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
		0xA784E5D65629A8C1ULL,
		0xF5954E1F8B388356ULL,
		0x1A3ACB31014ABE6BULL,
		0x48B9B0D7E679A5ECULL,
		0xC79A9481DFD475B2ULL,
		0x095B62FCADDEACB0ULL,
		0x526B289EF608D043ULL,
		0xF955BB69A23D3FAFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4876F11D8FB326ABULL,
		0x5925FFA15A462594ULL,
		0x5622D2C98699A85FULL,
		0x4B738285FB9119F2ULL,
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
		0x900AAD06B86C9943ULL,
		0x974549050938086BULL,
		0xA68F0803D2D7BA3CULL,
		0x1B158EBA61608D39ULL,
		0xFCB29881798666D3ULL,
		0x19CAD14EACFF3145ULL,
		0x21A5D7C9A42B2422ULL,
		0x3D96BF4C7B04AA7DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x128D503EC25FDDEBULL,
		0x6B605AB2B71958CFULL,
		0xA52D0FF2313F174CULL,
		0x3F75F414A411DBCCULL,
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
		0xA9F7038BD0084F34ULL,
		0x274BBE6FDAE47BBDULL,
		0x1F0FE168E1D4AFEBULL,
		0x3B6EC61C3FD2F4FEULL,
		0x9AD9AC0D6EB62ED9ULL,
		0x72C28308D67294C5ULL,
		0x4E717FEBCFABD3DCULL,
		0x226631ADBCF643A6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA6468D8A3F134428ULL,
		0x302B31BFAFE69112ULL,
		0xC3E8DE69B55622A4ULL,
		0x569A25E64C60FFADULL,
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
		0xD2BD1E3093D0D44AULL,
		0x4D7F08010D862B6FULL,
		0x8E9DF26E96EEA50DULL,
		0xEC7B27CB88C9D7F9ULL,
		0x067FC16F61A975B5ULL,
		0x5784520765D4988FULL,
		0xEBC5909BECEDE182ULL,
		0x2A599436A15729B9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC9B3D4B912F84E32ULL,
		0x4B23351A2B14D0AAULL,
		0x8DF16993C23E1E66ULL,
		0x35C727E77BBA0992ULL,
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
		0x9D1394BBFC8CC39DULL,
		0x58DE8BF81A11353BULL,
		0xFEF7C1367A4ADC4FULL,
		0x76E310CB07F2FFB6ULL,
		0xBA79D2BF5EEDD9D3ULL,
		0x19FFBF6AFB02ED89ULL,
		0x8463FD1B626BF9AEULL,
		0x23E07326CD61F5B8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4B28DD2413DB19C0ULL,
		0x34D4F5D95C8077ADULL,
		0xA5CF53471651EC27ULL,
		0x4A34288D847D791AULL,
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
		0x90168FE7C3579E8FULL,
		0x8220647A76E3169EULL,
		0xF30EB29F3A68F371ULL,
		0x143A068DD6640658ULL,
		0x3EE58D03879176A8ULL,
		0x3543E03AC55D7697ULL,
		0x46D11DC5B0821793ULL,
		0xF502362FFFC2AFE0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE6297E6DE2EF40D7ULL,
		0x6A33AD33C2C2B111ULL,
		0x76191DF76DB8734BULL,
		0x728E11ADCD4A21A3ULL,
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
		0x8F96E3D628DEE4F7ULL,
		0xB6CD72677F3E3BA4ULL,
		0xE63EBDF26B128FCFULL,
		0x1905089B10D56C14ULL,
		0x256AC5C765F40161ULL,
		0xD2A2F2510DC2F62AULL,
		0x077A1F4B3D0A3F3FULL,
		0x0A8B5650AB51F480ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1D703F6F4B171996ULL,
		0xFAFD6A6F8A2EC5E6ULL,
		0x025F631D7A97F348ULL,
		0x29B3D8947EFFB716ULL,
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
		0xEB72BDC0513A42FAULL,
		0x33293A2ED8EAA550ULL,
		0x7562DD4A4ADE0DB4ULL,
		0x1D7982DC764C816EULL,
		0x8B1D6A18015AF52BULL,
		0xCC4CAAB6C00AA7B1ULL,
		0xDECC144186B212B9ULL,
		0x0C58015598510492ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x91D07D5084BAA795ULL,
		0x868A914F5A7F89ABULL,
		0x87ADDF04494CD548ULL,
		0x7289B59112532F3BULL,
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
		0x7B003505AB460989ULL,
		0xADBC84CBEEDE80A2ULL,
		0x115812B881187274ULL,
		0xC213AC351B0619ADULL,
		0x76EA3FB73CD58682ULL,
		0x6E7C7AD35003E251ULL,
		0x41B43EA8BE6D673DULL,
		0xF1BDE28A4B2CC25BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x21C5AA38B2F80640ULL,
		0x1436C029CF7218BAULL,
		0xD2195FC4C555C593ULL,
		0x24434CBC43AAF338ULL,
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
		0x015F01389FBE5D30ULL,
		0x1DC32D58D6C92A27ULL,
		0x2747AFDCE8B586A9ULL,
		0x93C0D0F9B18130A7ULL,
		0x4E52F48004D9631EULL,
		0x8BE3215B9EEB3F72ULL,
		0xC887C8E9B3E31CF2ULL,
		0x98E3594F5512E037ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA1AF4C395803170EULL,
		0xE17A20F26DB4951EULL,
		0xEB6F828D9C6BD2A9ULL,
		0x458012C0524E78EEULL,
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
		0x75D2F7C4E22C384BULL,
		0x570145D1CC1B9C33ULL,
		0xB8FCFB89ABEF5129ULL,
		0x3616E778A9FD75B2ULL,
		0xADA7A3750352BCB0ULL,
		0x99E6A47B49ACB074ULL,
		0x7751505CFEAEBCB3ULL,
		0xD418EFF7016C83F9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3CB53B2360743F18ULL,
		0x2F3DB01EBBBDCD85ULL,
		0x6F0EE95779DF53D2ULL,
		0x31CA8622E0190CBAULL,
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
		0x64ABB707BBC200D3ULL,
		0x8143E1F7611290A9ULL,
		0xAA156E38A3F6B2E5ULL,
		0x5187AFD75FA6B1D4ULL,
		0xCD2898554C6B4667ULL,
		0x5F646178B8FA7533ULL,
		0xB0C38500B5D91F9DULL,
		0x8656A3094ADBA92CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD8B253B113AE7715ULL,
		0xAA2A59E2D63FF659ULL,
		0xE71B2C53A2316441ULL,
		0x4263E3387C41CE76ULL,
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
		0x08E6F43BA7491B80ULL,
		0xCD4C75AC5C6A1217ULL,
		0x7EDFE74FBE0CE31AULL,
		0x72F2101FC640B839ULL,
		0x4E5618C01E8C3CF1ULL,
		0x6413AE2F955A1BCBULL,
		0xBA2A4962E3790028ULL,
		0xF194D697A14141F5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA9AEA0C0301A2C9EULL,
		0xA83850BC87CA3244ULL,
		0x2126CBFD8202E919ULL,
		0x4F09EAA1B5F082B3ULL,
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
		0xA37E0D3E04EE851CULL,
		0xC530F3811DA25584ULL,
		0x2CAF0BD8975A702AULL,
		0xB1A59B27EB7165CDULL,
		0x274BEA4D7B1794FAULL,
		0x7715FC304153ECBEULL,
		0xE403431AE244EBD3ULL,
		0x42C3BE6CB6057027ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x78C2D4BE4A6EA3C7ULL,
		0x727462AAD01779BEULL,
		0x052B01D62D95718EULL,
		0x1AB3DF4AF0400BB9ULL,
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
		0x8B038EF9378CEB64ULL,
		0xE603AA1A713BDB0FULL,
		0xC0F306AB008CE7CDULL,
		0xBE988AA7FA7A8CC5ULL,
		0xFF5CD3AAA8D1B295ULL,
		0xD144AEC06D846ECAULL,
		0x0CF0D4B2B9AFA383ULL,
		0xA2CA7A4F777DD3C3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x72CAFA4E46AD7125ULL,
		0xF6359AAAB2E44D31ULL,
		0xACB29932909F2D5EULL,
		0x68A6B273B727FBB9ULL,
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
		0x48968038C8CA814EULL,
		0x34CEE34694DF9A1AULL,
		0x6E19BF67FE0D961BULL,
		0x96BFA8F43FCB45E1ULL,
		0xE2B4470DAE7AFAEEULL,
		0xFE5BD5EE0ED1EC05ULL,
		0xEC90F87BB51CDFFBULL,
		0x76687E3FD0155F8AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEF590C40AF0BC34EULL,
		0xF670A49CC808A2F9ULL,
		0x8B9EA1C4E056D582ULL,
		0x2A42666D22F77480ULL,
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
		0x79DE26486A60D190ULL,
		0x3A1FD89809BA54B2ULL,
		0x5146102D1E408390ULL,
		0x3D4C430AB6B0627FULL,
		0xC4419DC29DCFEB72ULL,
		0xFA0B99A4BB5F52ACULL,
		0x830AF32250FB57EBULL,
		0x932E80DD89EEF440ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9B9B912BD73DC7C0ULL,
		0x57D8A70BD9E09A57ULL,
		0xC4E62745238F9097ULL,
		0x163363ED3028A412ULL,
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
		0xED53D2F2A716EFE9ULL,
		0x2C94E03DCD129F1AULL,
		0xC44B50293F5F62C5ULL,
		0xDA99FA22754C0F24ULL,
		0x239325EB1C550554ULL,
		0xB6C118D4032A1AFAULL,
		0xE53747FB126E24B3ULL,
		0x114AE98A6D208F99ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x352B73D8DBB5BAD3ULL,
		0x4D3E8FB64552A03CULL,
		0xCA7FFF6DFBB8D572ULL,
		0x6BB8A4AEA8215FFCULL,
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
		0x2FF905A4749D1A30ULL,
		0x7704B20EBDB160D1ULL,
		0x4EF12C8674F302B1ULL,
		0xE66249622EEF3AD1ULL,
		0x31046646442156AEULL,
		0x106A238D5D91A704ULL,
		0x813ADD944552052DULL,
		0x45F7840A26B40701ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x76A03412918FF9A6ULL,
		0xE6C5F90AA1502B70ULL,
		0x7DAE1088BF1FC761ULL,
		0x491FE2E3EDA8450AULL,
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
		0x690CAF6645DB1CFCULL,
		0x44EF1EB0C1A451A5ULL,
		0xFC6148CDBCE1F22AULL,
		0xB8E2C9C837BD3710ULL,
		0xD3516072AD376EB6ULL,
		0x005677F6B216EAA1ULL,
		0x9DFE1F75348CB2ECULL,
		0x746DD1A875B10797ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC721006BFC158EACULL,
		0x51C4ED4F310B25AAULL,
		0x7019F43389C48132ULL,
		0x012FE8C9B0045792ULL,
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
		0x2A2A41AFB1BF66FDULL,
		0xEFB68873B22F8616ULL,
		0x4C28376A33C45F47ULL,
		0xE8404C4B7057BB67ULL,
		0x5D072F0C7D5EDCCAULL,
		0x6900C97F5E79FD54ULL,
		0xA9B621AE2A94AC01ULL,
		0x7C2AD928D474ED7DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF93B3D8A4DD42FCBULL,
		0x85D4715BB84B209BULL,
		0x7D31374485D5E77DULL,
		0x569C885AF9B2FC0EULL,
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
		0xFEF394D9BA35097AULL,
		0x61A2ED798A7DDEDFULL,
		0xDCBA2CC835B87DE8ULL,
		0xA04DA20F5D7907FBULL,
		0x50FC1B9FD0285D61ULL,
		0xEC7B8BAF7C25366AULL,
		0x869CA292AC6764FFULL,
		0x12B0ECB9F0E8F665ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x045FAE92A032E652ULL,
		0x7BF9A985F803F2A8ULL,
		0xD7FA4E8DCD117BE5ULL,
		0x6690C5A9200D9B0DULL,
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
		0x0887CB960F4C79CAULL,
		0x0B0DDDE73AB33B97ULL,
		0x887EB12DA6531546ULL,
		0x6B4D27A9EFEB8B96ULL,
		0x0EFD36ABE0EDD0D5ULL,
		0x683818A97012E8DCULL,
		0x4C4532686DB681E3ULL,
		0xB5062A932F1ADF57ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x421DE91972997D6AULL,
		0x8361870DDD81CC41ULL,
		0xDAC42CADEF6A5D07ULL,
		0x4A377982EDE8B28BULL,
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
		0xE8445D84CC4FAB61ULL,
		0x1CA07C2D40F519BAULL,
		0xB7381BA6BB6C387BULL,
		0x03647AFC7CD12F87ULL,
		0xDED964C8079F436DULL,
		0x874FA96FE5AA6D92ULL,
		0x95DAD6B3E87962EFULL,
		0xEB7DF8F385D96233ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFC895335EDF3B2AEULL,
		0x3273A2C958415D87ULL,
		0xF5B3FA5B3D70E809ULL,
		0x78176F225B15C32FULL,
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
		0x6419A359827A1248ULL,
		0xDCF1E06DDFC78EE7ULL,
		0xC29DB39DC3FBFEE9ULL,
		0xF929BBD62FB2086FULL,
		0x2A4D1FCA1FB95E5FULL,
		0x328C129F295CEB29ULL,
		0x8F64CD135F720BC9ULL,
		0x306B148BA0CA37ABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAB8C5B5A37FE1592ULL,
		0x5DBCA40E03927703ULL,
		0x0B94247DEEE9BEC7ULL,
		0x290EC8900DB64BE7ULL,
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
		0xBDB25AEE2F486DB6ULL,
		0xECF81D32EB2E6A55ULL,
		0x1866F7FE96E28A16ULL,
		0x39FA98CB9AE37145ULL,
		0xA29273C55F7F6985ULL,
		0x814D7FD6866F6C08ULL,
		0xCD09EF00E674B1D0ULL,
		0x7FFC9C49EFF64A80ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDF6F8A3A5C321A46ULL,
		0x1E79170ADFB8739DULL,
		0x87E07220CC34EF0AULL,
		0x3979CBC539728063ULL,
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
		0xC6EF637CEA789635ULL,
		0xB9F202EBCE8CBAD7ULL,
		0x48A6D526514023C9ULL,
		0x2DDAB939EE9BDCC0ULL,
		0x5F526F96D6C0E27CULL,
		0xDA17BDF9ABC29FBBULL,
		0x51349BFD14B723BAULL,
		0x02A84241BB1E5B0FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xED2BF3E0CB1A34B0ULL,
		0x197835FB4D7070A7ULL,
		0x5675FCB7646F7186ULL,
		0x12D48EFBB51D6106ULL,
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
		0x562FA37CE98F716EULL,
		0x302C74BD2C9E775DULL,
		0xE41CD2EEA0A6E8CFULL,
		0x738156668B3CD655ULL,
		0xC665C5FFAC6BE3D2ULL,
		0x66BB5F2558E182BAULL,
		0xDF35F190ECB4DCB5ULL,
		0x835B56877DAC1036ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC94B07708193457FULL,
		0x6FFC94485E17DF16ULL,
		0x061EAE71C37FABBCULL,
		0x73102E8332C73E7BULL,
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
		0x02FED394661E7B32ULL,
		0x4AC0BBEA3B150DF6ULL,
		0x77BA09F338A72D21ULL,
		0x2E1E5840123AF114ULL,
		0xECCD50506EC5B1EAULL,
		0x82E31172F28BC4ADULL,
		0xF15F8AC4831CB303ULL,
		0x6C9891D1030D0C23ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2978BF84D776E64EULL,
		0xB87552FA3BD43FC7ULL,
		0x4BE8A31EAEE9BFA6ULL,
		0x4CC3FD46862ABE6AULL,
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
		0x86D19C6933987241ULL,
		0xC68ED87C8E96D1E0ULL,
		0x32555F98042AB457ULL,
		0xEEFF8F0B8B930823ULL,
		0xDC723CA90CA2B2F6ULL,
		0xABCEE13404B17292ULL,
		0x9981D4D4DA514F31ULL,
		0x4827F5780704D184ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3FC69D8113BF047AULL,
		0x4744463540EDD3ADULL,
		0xFB9AF7306C3C75B7ULL,
		0x24EDFEDC964A21D1ULL,
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
		0x9D59E92F2A3B62F1ULL,
		0x24E6193FEF3879F3ULL,
		0xF4BD64C26226A86CULL,
		0xD31D373E5202F91AULL,
		0x7BF8C1E21558B490ULL,
		0xF38E6C4C36CABC05ULL,
		0x8A80AC84EA8D315EULL,
		0x24947C4D7B7ED35CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0446B0BE55663135ULL,
		0x4C0A2C90115062C4ULL,
		0x83D7007D331BFC84ULL,
		0x4127AABEA6D658D7ULL,
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
		0x5E874F61BFB5EC6EULL,
		0xC7938C3F64E83F44ULL,
		0xFA95405F87C80BECULL,
		0x776D44144E50C24AULL,
		0x0E62E69FF972ECC0ULL,
		0xFAD796FD7EFD96C8ULL,
		0x76C278ABCE7B4FC3ULL,
		0xB0ED1E27AB787064ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x81358B20C6C514DDULL,
		0x0393F5E03E8CA0F6ULL,
		0x9B7329E02E15E304ULL,
		0x3A9FBDF7C2317134ULL,
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
		0x8906112F6D0FA135ULL,
		0xD6BD7580BB9A2595ULL,
		0x04E06A7ADE56AAB4ULL,
		0xCB6E5376774ABA82ULL,
		0x1C7133DC18247F47ULL,
		0xC8CC74492A104FB3ULL,
		0x991C2C84D8BAF050ULL,
		0x0456AA4010FC0044ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC1D3C3DB027A85E5ULL,
		0xA516B85CFA05FA2BULL,
		0xBF0F06330A1656B2ULL,
		0x704B98F8FCB2C4B0ULL,
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
		0x7802C84810082BE3ULL,
		0x966CE2A0DFCEF1E3ULL,
		0x7F0A4DB26280FED1ULL,
		0xB6BB1CCE478AEF00ULL,
		0x864379A5C1B09DA0ULL,
		0xDB4677D49D68217CULL,
		0xB07DA80D09030343ULL,
		0x275E00144CB67C94ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6606D6E2D03F929AULL,
		0x22E2AC303D43EA5FULL,
		0xB1B13FA1B8F37AE4ULL,
		0x0EAF1FD1AAA16D12ULL,
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
		0xBF285E9E2E80B9D4ULL,
		0xAC0AA67ABD914CEEULL,
		0xAED4FA81B693E4D1ULL,
		0xB91BD4DBF4E1DC37ULL,
		0x1537D41D3F2B4091ULL,
		0x851B0BF72B893295ULL,
		0x5BF483758FAD7834ULL,
		0xB405F3CFE7E4FCFDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE571DAF58EEC535CULL,
		0x6E0E6D2B33EECF0FULL,
		0x55207DF50A53BC9DULL,
		0x71FE05B860DF69D3ULL,
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
		0x68BC1A5B8D821E14ULL,
		0xF88BA3523C9074EEULL,
		0xDDBA4FC32E69A379ULL,
		0x9742BEBD83010DE5ULL,
		0xB5FB655A3BD42741ULL,
		0xCBDA36BCD11AE518ULL,
		0xFC8AD768066B319AULL,
		0xA5C4FA82617323A6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6C0D25C06EFFF570ULL,
		0x3AEFC359468E7699ULL,
		0x5A56493422530074ULL,
		0x327FEE17FA1858AFULL,
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
		0x119A01019EE5D881ULL,
		0x3A5B4E4D28387148ULL,
		0x025822475D4EF4A3ULL,
		0xD82E813450093E1AULL,
		0x40E34EE81BB58656ULL,
		0x9CFBF112CDAB2EA6ULL,
		0x19C095B5BC0588BCULL,
		0xC72C2156F75BF319ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB357B775BBD7CDB9ULL,
		0x87C11717AFA15DF5ULL,
		0xD4EE5B41462140A2ULL,
		0x68BB741D07AF53D3ULL,
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
		0x54217EB431B42D73ULL,
		0x9B3502D613BFE5F7ULL,
		0x82BF99B4043F2E0AULL,
		0x83317E68BCF8292EULL,
		0x11F1E6EC948E6394ULL,
		0xE915BE188E0994F8ULL,
		0xBD77BCA2C1412A9EULL,
		0x03DA5B76B55C1D70ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFE09C5D23ED6F591ULL,
		0x346F3A7B292C02C9ULL,
		0xA28599DCB3EB81A1ULL,
		0x159B1207A8A487EAULL,
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
		0xBF9FAF1A68D2DE6DULL,
		0x82A78562D29326EDULL,
		0xE03889C224F8EB96ULL,
		0x2317638ECAF6FF2DULL,
		0xAADA7CD280ED160EULL,
		0x4AF7FE9CDE965B7EULL,
		0x3CB15FC2BC77CEDCULL,
		0x1014B6751C019401ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1C0E36598C0424E0ULL,
		0xA37750ABDCE4BBBBULL,
		0xE28CC0AA1EC1A049ULL,
		0x062A78F0F332F75CULL,
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
		0xA6D5D7A948C1B721ULL,
		0xC9CCF2027CFDE293ULL,
		0x8574A37A2CE780EDULL,
		0xB049935F9FA8CCDAULL,
		0xDD52A7C3E1C537ACULL,
		0xF9F6B3CEA0BF264FULL,
		0xB071A21F922CE0E8ULL,
		0xB6F97F16735D1985ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x811ABEBCCC07FEBEULL,
		0xE46BA2AE595D926EULL,
		0xB652B429DF90E382ULL,
		0x595270B4BF7A96B2ULL,
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
		0x2E7956B11C300B85ULL,
		0x02916B0B1CEED2AEULL,
		0x020CBB07528F6BFDULL,
		0xA7650E99B90FFB2BULL,
		0x25227F93C976EFC4ULL,
		0x5AC8DAA37A1D5F1FULL,
		0xB2C23BECEB82C572ULL,
		0x7B739D19B6F303DDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB19846A103D7A55CULL,
		0x7C61DF4F3D4AF14DULL,
		0x8AE1A03247F8BAF6ULL,
		0x7A8E606AE1228E13ULL,
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
		0x72770ED79FA7946BULL,
		0xBD384A0C861F20BBULL,
		0x1D85461E9570683EULL,
		0xF478BA42F74830C7ULL,
		0xD7B1E59A2B3E28BBULL,
		0x514B210112E1B8ABULL,
		0x5D64B1569E8D8D77ULL,
		0xFE198DC1C9072550ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x76DF23BA0AE1A5E4ULL,
		0xCE5F303553A08A3DULL,
		0xFA7798FA1E7367F4ULL,
		0x2C43C506CE57BAB4ULL,
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
		0x883BED9D159B86FDULL,
		0xAABC25C19E2389F6ULL,
		0x30BE7070A9A841E5ULL,
		0x929331CAB75A1FA6ULL,
		0x088CCBC46F09D3A7ULL,
		0x4DA5582E142AD9F7ULL,
		0x889923DF4A4DB445ULL,
		0xB015EC1E6A421943ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCD222CC59110F5B6ULL,
		0x31473C989C7FE4A1ULL,
		0x7779C395B131042FULL,
		0x35D43E4E7D29DFACULL,
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
		0x7560C5A7881B10AAULL,
		0x6DB7C4ADAD3CBE9FULL,
		0x0B9D9F0726784BC6ULL,
		0x666E53F2BAB6E842ULL,
		0x7325FAA39ED477A1ULL,
		0x29B5D3606628C1BDULL,
		0xB80986CC233618F0ULL,
		0x6814A00D70CE4AD2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8D03F9F11BA4D4DDULL,
		0x9EB524FCD74980BEULL,
		0x5D07A154607FFF6CULL,
		0x597E15F179560389ULL,
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
		0x8FBE3FB96750C611ULL,
		0x455D5F1DBFCC0332ULL,
		0xDDBDE9BB57E65CE7ULL,
		0x9EF76DFE9C1B7601ULL,
		0x8B8C1C996B93AED4ULL,
		0x0C60368EAB4E871FULL,
		0xA7180130BB119EE9ULL,
		0x56F78C69A7DC052FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x468A7E7F5F3CBB8AULL,
		0x1BA5784B2D7411E1ULL,
		0xAB4E16F71C83F37FULL,
		0x07B645AD86C43B14ULL,
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
		0x7AA62C9662300F38ULL,
		0xD75B09593B42741BULL,
		0x9C1F486099B2D49BULL,
		0x603D3B1F50671A2FULL,
		0xD3D21E4E7CBF02DBULL,
		0x5CFD3594D7A0131BULL,
		0xA66A5AC74A70FD91ULL,
		0x9CD4887B89E9C982ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEBD6AC3CE68A7F37ULL,
		0xA4F0FD713D054A3CULL,
		0x4FE8C1F5A678782FULL,
		0x27C97D75C91B0394ULL,
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
		0x867ABF588A41944CULL,
		0x062501F7C5DF7450ULL,
		0x09B35A21CFD4B15BULL,
		0x7F5E85087E59FDF8ULL,
		0x6783B9A9F2863305ULL,
		0x4D77C3900F4367EFULL,
		0xEE41CE64946B7CA3ULL,
		0x450A47D9D0B843B5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE4084E928A2D2899ULL,
		0x85EC095A09E0E1D9ULL,
		0x6777FD0FD7C93198ULL,
		0x3EE52F5D79B40AF9ULL,
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
		0x27B3E0146F2880E2ULL,
		0x00D80A4E2E939E23ULL,
		0x455154BB3FDFEB48ULL,
		0xDCA558439A7CF6F5ULL,
		0x81B0C4AFDBEE54CDULL,
		0x3472F84A1D0B82CDULL,
		0x856DBE7C08258957ULL,
		0x3BB4F208131C66B9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x67F1122F148918B9ULL,
		0xC9E8E54E7E4908A4ULL,
		0x139B9B2475724E39ULL,
		0x3981457670B4367FULL,
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
		0x84F5840E880B5F67ULL,
		0x44C95C04F735A91AULL,
		0x44AD384BB432AE1EULL,
		0x0770A4F4AEC2FC8CULL,
		0x0DB18B4E59DF2480ULL,
		0xC78D3374649DFFE2ULL,
		0xC97BD919F2FE208BULL,
		0x9B1C9831943A188DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8D5031AFDF2ACDD1ULL,
		0xE3BEFF4BE6A9A4A8ULL,
		0x2D0F7225C5EB82DDULL,
		0x0DAF3C50AF62A198ULL,
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
		0x6E56644B42040918ULL,
		0x10042555F51EBA88ULL,
		0x55559039058F064CULL,
		0x7A6BF14BD8881625ULL,
		0x913DA8EC3659617CULL,
		0x202F2433B0CE2396ULL,
		0xF4FCC53044EE4A92ULL,
		0x7AC7C4291257A4AEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFD7D775B5348843FULL,
		0xD703850233B802E1ULL,
		0xB2DAD56340EE17FCULL,
		0x34130F64918A881DULL,
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
		0xB5E69EFC02641685ULL,
		0xDAB080986D23B4E1ULL,
		0xB1C9FC23C4AD9B52ULL,
		0xD6FE01B1684FEA93ULL,
		0x9260970FC8BB20B0ULL,
		0xB8A6FA6E1433546AULL,
		0x3C8F7EEBA124EE01ULL,
		0x837ADF83594DA431ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x703D0B53CE2AF39DULL,
		0x4379ACEF6CC23CB3ULL,
		0xAF16D31DB028EF94ULL,
		0x5B3B2F30A9D649E2ULL,
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
		0x6AFFB7B6E8DC073AULL,
		0xD53BA3150168FB31ULL,
		0x9295C929845F5F9EULL,
		0x17A0B68D65AE33E1ULL,
		0x7CFA0320A19434DDULL,
		0x5AD224B16257202DULL,
		0x259A438E53D368D9ULL,
		0x12CF75AED199F9C2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF81C2E8EE4DBE067ULL,
		0x506D15699A57C1F1ULL,
		0x277BD049F5C0EFE2ULL,
		0x626C2E80828946B3ULL,
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
		0x0CB3F634F3FF30F9ULL,
		0x5EDA8411A85301B2ULL,
		0x78BA12E6762C01CFULL,
		0x9C842D56FC1410E9ULL,
		0x0002DE2CB4D7FDBFULL,
		0xA020F2553D80C991ULL,
		0x25FFA2F7BE921504ULL,
		0x28E0997A9396FFE3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0D20F0D7CC0EDC4AULL,
		0x23BE7CB8C970ED38ULL,
		0x1CAC43ACBFDB207FULL,
		0x2DDAF588E47E0CA1ULL,
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
		0xA0ABFD82B18686D3ULL,
		0x92595EB9AC56E161ULL,
		0x123C94CEB4DE98E9ULL,
		0x398541A5422F3773ULL,
		0x45128861C76A2DCAULL,
		0xC488800BD8EDC07EULL,
		0x5A36FAE3E86BA0CAULL,
		0x7D730AC88BB14E28ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE16C3C064B49558EULL,
		0xBE9C607BDFA1741FULL,
		0x7665D2A334D87702ULL,
		0x5898DB69FE80D170ULL,
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
		0x381E68CA6E102C80ULL,
		0x9E209BCD94A6E8B2ULL,
		0xF852BF0149758542ULL,
		0xD399AA49E430E0CEULL,
		0xC3795E2E1F7CEB8BULL,
		0xA16274D6DEF6F9C1ULL,
		0x01F360AA5290A359ULL,
		0x7A88C4B4A352491EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3C2263A31A9B25F4ULL,
		0x92BDF3B2AD4FFB75ULL,
		0x427318498AEDC490ULL,
		0x03E6DD1A2267BB43ULL,
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
		0x8314C5832D65F893ULL,
		0x7E303B47CA0EAAC0ULL,
		0x0CAEA4773CCED70EULL,
		0x63AA4681D0079666ULL,
		0xD1BE6ECE026C7644ULL,
		0xC16933CDA19C3528ULL,
		0x12F2FF7206231547ULL,
		0x9FBFE72D51317694ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA5593817897F8A3BULL,
		0x33CDEBCDC73E8ECFULL,
		0xDCC08F642603FFB5ULL,
		0x1A26973BDD5F3060ULL,
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
		0xD7FEB408AA91C4B1ULL,
		0xA2EA592829F25CFEULL,
		0x79D084F105D212BAULL,
		0xBA9AF44904F3C910ULL,
		0x49D6F45449AC9973ULL,
		0xC4213430C36D334EULL,
		0xBEB6AD78B0F07700ULL,
		0xEBC9AF26CF11AF26ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCDE6F88B9A309108ULL,
		0xBFD818652C27FA9DULL,
		0xC8EE44DB4983BCD7ULL,
		0x3A8AF40BC193C8D0ULL,
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
		0xAE3A178A8723B39CULL,
		0x14C9F918844B3267ULL,
		0x32148C292C5600F7ULL,
		0x98967B67496AC967ULL,
		0x945E23C8CB54BBF6ULL,
		0xE7E15F903C29C621ULL,
		0xA649DFF3557EF958ULL,
		0x99B6055CF4BB5358ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB4336758B5B79D8AULL,
		0x803E2881727E9B63ULL,
		0xE10BCA47DD2F0429ULL,
		0x699B47339D39288FULL,
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
		0x0AAAC0E41929481FULL,
		0xDC5E42DB6981676DULL,
		0x0FEA7ACD3F24287CULL,
		0x6981AD4369A85BD8ULL,
		0x92A11FBD2074551AULL,
		0xBE0940DC55B3E957ULL,
		0x7167F56118B124D3ULL,
		0x2328392EA000F70FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCE9576F6EA6DEACCULL,
		0x11BDE39022360A6CULL,
		0xE558E736E96F9FEBULL,
		0x217A2A2F29CD0822ULL,
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
		0xD9D31FEB478E75C7ULL,
		0x0CB750C26766690BULL,
		0x8C1A03BD9CB21F23ULL,
		0x691F1977263F3AEDULL,
		0x53860A7BF107FE40ULL,
		0x4C73A1F31947F457ULL,
		0xF5A06FAB817C8A8DULL,
		0xA20709B7321045BEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3FB8AE510EBE36D7ULL,
		0x65E15AD82814AE02ULL,
		0x01EA9732D52EB01CULL,
		0x762A8AA894A99546ULL,
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
		0x88E527E194372FEBULL,
		0xE66343CE6A3E7E40ULL,
		0xD7DD248B97D4CF40ULL,
		0xD782FB3B832CE0BBULL,
		0x6611179B3B68EC0EULL,
		0xA4C12DAE3B789550ULL,
		0x01C7E1E8FD6F6681ULL,
		0xA25CBD2B1F008647ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF6EA8EC65CA3DA2ULL,
		0x5B100BAB3E24A82FULL,
		0x1B88AD21365E067FULL,
		0x71470FA21D40CF46ULL,
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
		0x98A272A7744A94B4ULL,
		0x4760F5504828374AULL,
		0x70589DEE28FF3397ULL,
		0x207DF41E0438C94BULL,
		0x59665D1603BD4FC3ULL,
		0xFEE6314838D069CDULL,
		0xCC1AD881D7863DDEULL,
		0xF6EC665CEB926D92ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDDD443EC02647111ULL,
		0x1D8C4608B717EBC5ULL,
		0xBC54C13426EC62B1ULL,
		0x479525E8FBF50D15ULL,
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
		0x970D82BE34E531DDULL,
		0x96857B948EEF839CULL,
		0x39A6DB6ED861901FULL,
		0x4F82C47EF7E7B1D4ULL,
		0x6B2C0EC2F8033616ULL,
		0x74DD9FF87DD7864AULL,
		0xCC70053BCD5A469FULL,
		0x35363D9208953DEDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7F97B3AF055F3A51ULL,
		0xEF6B3A773CED72A8ULL,
		0x9247A24F53C80BCAULL,
		0x358FE82C3E0EE320ULL,
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
		0x0336A4453D000CE8ULL,
		0x9881283B1D40264EULL,
		0x9227E247AD74D99EULL,
		0x11F23682E71A6A15ULL,
		0xD0C4EC403E6F741BULL,
		0xF2E8AE5318BD3EA9ULL,
		0xC20D74AA3952105BULL,
		0x2DCCAFA1BFB48BDDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0071B5CE818B49E1ULL,
		0xA70B0890C9577383ULL,
		0x6027338C2FA34744ULL,
		0x5E5448855BE72D00ULL,
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
		0x1FBA7F537E5A6891ULL,
		0x9D51DA56AD2D369CULL,
		0xE578B500729B5B59ULL,
		0x28CC0BE7F8571B72ULL,
		0xDB8E246A990AA3E3ULL,
		0x582DA4BAE66BE316ULL,
		0xC14D24CB9709BDBDULL,
		0xD852AEC9A405D11DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB6D3E72635EEC103ULL,
		0xB4184E14E130EC00ULL,
		0x96EC2B38DE0D8574ULL,
		0x4511FDD6513425DDULL,
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
		0xEAB3443D789E0205ULL,
		0x97C79239146CE9CDULL,
		0x02DC51EF04D27B33ULL,
		0x103660629627DB35ULL,
		0xC7BF3100FAEEFF96ULL,
		0x342A8739699BE4F4ULL,
		0x25EFAE6EE0760FDBULL,
		0x509FACCC96F62E0DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x91148A62B817F411ULL,
		0x5617A4BEC190E623ULL,
		0xA47036645658D5BDULL,
		0x07EA06C0FEB2B128ULL,
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
		0x289730755B409A83ULL,
		0x52FA9402C6B6516BULL,
		0x5916B667A13825ABULL,
		0x40040D6826791EFAULL,
		0x5234D1A02066322BULL,
		0x921E36882C29A2F8ULL,
		0x6A41AE8F0F22DEC3ULL,
		0x4220163223015DF5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5C6E4E3A2A6C0E61ULL,
		0x0376AC3954E48247ULL,
		0x1ED69FA3E06536B3ULL,
		0x10C758D958AD1168ULL,
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
		0x91D7C7634668BB47ULL,
		0x41556B63FBE6AD96ULL,
		0xB0102D7426742632ULL,
		0xEA5DBBED6CA71925ULL,
		0xE789C3DDBA8FA6DAULL,
		0x456AE0E15F04B060ULL,
		0xC1517861CCEEA0DEULL,
		0x8443581A9314181EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF04ADA4CF7BB82AEULL,
		0x8F32CCD81698DBF8ULL,
		0x62280BF891E00730ULL,
		0x0C5CCFDF41A2ADB6ULL,
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
		0xA5CCD89CF9515994ULL,
		0x7527D0EA0574E0AFULL,
		0xFA1BA2F7473DBFC4ULL,
		0x806E4F22E4C2722FULL,
		0xF39AE432F3CCF57CULL,
		0x0F6F1A1D3CADA5A7ULL,
		0x7CCA5D65BF23402BULL,
		0xD1420A520A4204AFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCECAB82D29BDCEA9ULL,
		0xBFA5B141073B779DULL,
		0x80258011A6794628ULL,
		0x103BD7506A8F243CULL,
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
		0x7D5CA78A7BE6701AULL,
		0x89FF908785AD27B7ULL,
		0x09C1887EACE6EE80ULL,
		0x963BD4D0ED92C213ULL,
		0xDD305579976DA809ULL,
		0xB69A568EDC9C48DBULL,
		0x6AF921F0A942EBAAULL,
		0xF8A98BE4673B78EDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x52895796F62D66EEULL,
		0xA4E869BC44DFF85AULL,
		0xEABC9237CCD5E9D7ULL,
		0x7F6698B84066B550ULL,
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
		0x8A9F9B8977137A6AULL,
		0xB13AD2D4B22FB32DULL,
		0x779F560AA9D2287EULL,
		0x68EE45BBA02FA4BEULL,
		0xBB6D8AC512008D46ULL,
		0x9681F09FD2532A5FULL,
		0xFC20E809DD738730ULL,
		0x380740CFBCC5634EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5CE234CA23287411ULL,
		0x08848A8DEA87FD63ULL,
		0xE481C78188F839B5ULL,
		0x3A01E491A57C6277ULL,
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
		0xB902CBDBDEFCF55DULL,
		0xA62548446E49D2D8ULL,
		0xB1D5EDE189187B63ULL,
		0x6980A9EC37585D23ULL,
		0x56B05483BE140549ULL,
		0x78FCE9A3883B95B8ULL,
		0xEE0BCC54782DD83CULL,
		0x56C7634F2DEA98B1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x972F576A15F5C021ULL,
		0x9BAFF68AA7220C35ULL,
		0x0796426B5FE6945DULL,
		0x4B1967AD082B078DULL,
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
		0xA47FF528C5F0BC39ULL,
		0xC6DAE5D2B4E40155ULL,
		0x8D8E199F69BBED18ULL,
		0x6FE71BAAE18B8D1EULL,
		0x8DCABD1A71D33150ULL,
		0x3EBA67A1E5A3CF89ULL,
		0xA0C17ADEE164108CULL,
		0x09DC64B287441AAEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB0980715AB4A0E52ULL,
		0x168647DACB34CFC0ULL,
		0x6A4656B4DE9661EAULL,
		0x669E0E2AF5A7830AULL,
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
		0x6D3FC04C58E692ABULL,
		0xA160D586E51CC756ULL,
		0xB077CD88171BDC8AULL,
		0x7BE1F59AE03A46A6ULL,
		0x36A49F307B3D82DCULL,
		0x2331E7AB0AAB4DCBULL,
		0x351309891C6C3345ULL,
		0xDEA50B88593A7A46ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x89AF617EA408044CULL,
		0xDAC938EA7A8A5380ULL,
		0x914B37E24F2B78CDULL,
		0x0861ABD81EE86D12ULL,
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
		0x4E3217D34AF35D45ULL,
		0x0649C7C54D73759BULL,
		0x84A5BA34121CE100ULL,
		0x1C9E4101ABEEB112ULL,
		0xD45CC8488CBB9F40ULL,
		0xDA4A990F93302DFBULL,
		0x13A8AB503439B2FDULL,
		0xDD23DD0E73E8F814ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD3F7D2982ECD0598ULL,
		0x6D5C8015269A48FCULL,
		0x6FAF281BD2AD72AEULL,
		0x6FF11126E083840DULL,
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
		0x00D838DB1B4C4970ULL,
		0xE969BE041812F25CULL,
		0x92BD45AAA735AD23ULL,
		0xF161C96D391D09D9ULL,
		0x9A5E1134F310F31DULL,
		0x25BAD8DC5726DE97ULL,
		0x1DA69637051887E2ULL,
		0x21195576CB5D3128ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEACEC6B72FD0608FULL,
		0x8325EEB907D7FCDCULL,
		0xF97791D568D9D8B5ULL,
		0x5B24790F68F255CDULL,
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
		0xDAF1D5460E2D30D2ULL,
		0x9869EC3C0FBD3B8CULL,
		0xBA085CE4F9A42159ULL,
		0x11DB8CEA5636CDEAULL,
		0xD58F3E736F5A1B99ULL,
		0xE84F5BAB8BA2D751ULL,
		0xFC2897E6A1CD7D0CULL,
		0xB2970F00FA0524C7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8E351A68958D4D77ULL,
		0x143187B2C9E931B2ULL,
		0x280EE920FE24B144ULL,
		0x1447C70F72FA439AULL,
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
		0xD0D367D14D3AF857ULL,
		0x72744661C0A582D3ULL,
		0x742AEB9538AC560CULL,
		0xF01F789EF8C0F54EULL,
		0xB5388979774C3C66ULL,
		0x2B5304BD04B438CAULL,
		0x8A1A6689B962B297ULL,
		0xA70E8104F9C6E9A0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB737CFD9028BF344ULL,
		0xE0C6FA707365F0EAULL,
		0xF4162406BD52D87CULL,
		0x3C469F5C0C47A322ULL,
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
		0x0056E6BA5C50A933ULL,
		0xFC292DAE060EF929ULL,
		0xE758C8D08A7132F2ULL,
		0x2D569E044FD19559ULL,
		0x5A1D7999718B08FEULL,
		0x33EB06E334F906F3ULL,
		0x1C1EDEEBAC530B15ULL,
		0xB3AC67D9907917FBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x60B6F38136F402D6ULL,
		0xB10C3367E3060148ULL,
		0x13EDDFCC1EC4D818ULL,
		0x58EE084FC1CB24A0ULL,
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
		0xE7703B03CEA5352FULL,
		0x989905624DFEA2FCULL,
		0x765B43F4D3AE76B8ULL,
		0x15F755F60BEAA3DBULL,
		0xF59AD25F51B16A99ULL,
		0x66E1C3DC86EBD2D4ULL,
		0x5BEF925019CC8D7BULL,
		0x2AEA51741B8DC93BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5C6B7529EEFB08C9ULL,
		0xDE1C181E54FFEE99ULL,
		0x1BEAFBD8A80B7709ULL,
		0x74BF6D3222F682ABULL,
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
		0x3774CBF3F883D5D9ULL,
		0xFEAACDC8FC5BE5DCULL,
		0xF292EAE1208F3A45ULL,
		0x77221C17EF747886ULL,
		0x8CE81BDE2CBB5EB7ULL,
		0x3B37D4955A7DE59FULL,
		0xD7A9A69960F7AFD7ULL,
		0xF42B650C57F43A58ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x21E8EEEE9C53EA6EULL,
		0xC8F45BF46B0BFB8BULL,
		0xF5C1A5A585535438ULL,
		0x35931BECFDB521B6ULL,
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
		0x92606E5BF11DFE18ULL,
		0x42581B0544AA9CEEULL,
		0x0A50418A1A47EE68ULL,
		0x48DBE0EB25DDA176ULL,
		0x50BAB055A692C0AEULL,
		0x5AFC782D34CC582AULL,
		0xBE560854D8E910B9ULL,
		0x6DC5ED8BF193DC5BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8E169B12AAE69A5FULL,
		0xC3D1F1BB1AFFB336ULL,
		0x4B157E224CE069EBULL,
		0x143D23B101D05714ULL,
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
		0xC009E77821BE31E5ULL,
		0x99E6A1DCD81AD0ECULL,
		0x16FE9EFA9A186199ULL,
		0xB7D57BBDB50528DFULL,
		0x82B12A6891F953BAULL,
		0xDA550F0D2797EB1AULL,
		0xA1E5648C7DC52242ULL,
		0x77984CA7CAD0A33FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x265632FDCCC0A22DULL,
		0x0286DDD0B8A7B6DCULL,
		0x1F0B8BD5455B7786ULL,
		0x7870DCA5CFFD6451ULL,
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
		0x178E05FCCB4DBE66ULL,
		0xB3C2231C3CB6868AULL,
		0x41FE0AA9598574D6ULL,
		0x538B074330D1FE64ULL,
		0x61311394B7DE710DULL,
		0x7D43B69DBC7EA10AULL,
		0x74D395EDDDCB7CBCULL,
		0x94F057558FE93471ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x84D6EE1016528998ULL,
		0x4BCF3E8637826E14ULL,
		0x99664BF845B9F8D1ULL,
		0x6F37FDF68D6FC73BULL,
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
		0x2860469E23E8D222ULL,
		0x3D170C50DBEF1CB2ULL,
		0x0AD31789305B7B4BULL,
		0x6F32EA3CE8281118ULL,
		0x9B9BA5EAE8179D7CULL,
		0x61845228B0673F45ULL,
		0x5E3E55F10BD5EA05ULL,
		0x5D464953AD88F87AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x417AE77C976A349EULL,
		0xB6BB3E5B0B428107ULL,
		0x0813D950F21C3817ULL,
		0x47A1CCA8AA7CF342ULL,
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
		0x7FE398D408597EBDULL,
		0xFF4795E43358DFA7ULL,
		0xEE83CF14E758412BULL,
		0x86E8164D56452CF3ULL,
		0x393CC1653933FAF5ULL,
		0x449FDB77EB3DA52CULL,
		0x4F13DB7FD79DF332ULL,
		0x5304022B5D85CF70ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFEE84DDA8610C0F6ULL,
		0x2F0229B11E7F6437ULL,
		0xAB76640EE8CA5AA2ULL,
		0x598068BD3821F79FULL,
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
		0x08621AD09D54587FULL,
		0x3E5DA80408AD6DE9ULL,
		0x893DABDF0339F287ULL,
		0x750603E5A145C649ULL,
		0x1CCF314849064A1CULL,
		0x6439714C2BB4F0DCULL,
		0xBA70F4C24798FC94ULL,
		0x12EAEB9D1DE4DD0DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4F236B8B74435919ULL,
		0x1EE4795285892E95ULL,
		0x360200B5A3EF708EULL,
		0x43E4FD38113E9653ULL,
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
		0x659BFDB25FC7FB46ULL,
		0xE413B89F4CEF9EE5ULL,
		0x6F57161395F4E787ULL,
		0xC08EB89D676F2BD8ULL,
		0x9565B9D34B52EA99ULL,
		0x16C59AB849427DB9ULL,
		0xC7CBF5DBCB6DF168ULL,
		0x72DFB52CBAE0A324ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x92B5930F8E16D095ULL,
		0x4568AFFA2CCE4871ULL,
		0x179D94B3C846BCFBULL,
		0x4DC39D4124C7634EULL,
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
		0x99745872C948A9B9ULL,
		0x1272747B35AA74E1ULL,
		0x51F19631A42E63ABULL,
		0xE3CD86C8CEEA5645ULL,
		0x5322C1B3E6EEB97EULL,
		0x197EDFA5BD902617ULL,
		0xC6E7C45399DE53A6ULL,
		0x1F9163504C30A094ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF09D192710B8333EULL,
		0xDB47A71559101C57ULL,
		0xD858BA9A7B2ECE52ULL,
		0x136244B41E222C5AULL,
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
		0x816C8E68D84D5462ULL,
		0x3E24A9567A5EA2CBULL,
		0xB1B500751218E003ULL,
		0x6E0AE6EA20404280ULL,
		0x0FD5F5580D57AB12ULL,
		0x3BB2B211C844498EULL,
		0xD677EA3BDE2E1D85ULL,
		0xB2F20097B83F201AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDB2EF97AD350BCFDULL,
		0x1AAB17FA34818DE1ULL,
		0x8781C5580CF141CAULL,
		0x7DF6FD6F799F067CULL,
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
		0x1314D7062DF4F9AEULL,
		0x11B08831BAEF592FULL,
		0xE69034023EB87B92ULL,
		0x3A5033F809173DD8ULL,
		0xD63488FF16B27C45ULL,
		0xB0A76E79A2239856ULL,
		0x82655AF24FE8059EULL,
		0x8AF1F0400FADBF9DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDEE12CE38C736EF7ULL,
		0x4A8AEE3FCC37F612ULL,
		0x419BB3FA1B295120ULL,
		0x5A39DD7A5CE1AF3AULL,
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
		0x7B482D8EC7C52791ULL,
		0x40B8315C85ACD794ULL,
		0x8994FE69B63C480EULL,
		0xB007BCE3B0614E1FULL,
		0x2E1CBFC15E0F5243ULL,
		0x35BF198A7C2003FFULL,
		0x4513D1E9F6C2F90AULL,
		0x7977FB4BBBD4ECF4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x538CA442BE0B6042ULL,
		0x3B15FBEAF26D6F75ULL,
		0xCA862724572D3F92ULL,
		0x37D70A2191FC7A61ULL,
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
		0xA752863F07501246ULL,
		0xE0EAA9721EFEEEE6ULL,
		0x2B3AC8D13AE7453FULL,
		0x3E4A15F4CCC0F776ULL,
		0x6686556EA062FCCCULL,
		0x34B73590DAB54661ULL,
		0xF00AB0AD9E6AF27AULL,
		0x315276D7EDE7DEAAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDF4334AAD60199ABULL,
		0xB41C9CF295E7615BULL,
		0xCCD10296BEC74363ULL,
		0x1087BA021D2C04D5ULL,
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
		0x0363C47986A0DA62ULL,
		0x9A6A8E533F872BB1ULL,
		0x14A4A8CBEDE41C6CULL,
		0x18272770D98106FAULL,
		0x2926D156FE5E3FC4ULL,
		0xCFF44BB669329049ULL,
		0xA2A29BA3A78E4331ULL,
		0x793E1C22F24D5B35ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1F26D763489E5426ULL,
		0x78ADCB66DD08968DULL,
		0x38C7C316CD0215D1ULL,
		0x175F54A0D0FC90F0ULL,
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
		0x7270AFA5AB1C8D4FULL,
		0x1DD4789B049A584DULL,
		0x2D36EC3D9586E5E1ULL,
		0x095BCBD611BDE1F8ULL,
		0xD2E10884A2680E86ULL,
		0x344BC32C096412C4ULL,
		0x8F5E80F289CDC3B9ULL,
		0xAE904E04C5B7EE9DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBFD7F355C68EB8FCULL,
		0xE113712469752184ULL,
		0x753E103E0A11F35EULL,
		0x72C7608B6B0B4D5BULL,
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
		0x55E5311DAD047040ULL,
		0xD8058C399BBA22A1ULL,
		0x406070CA29830CA1ULL,
		0xE12004746B59B0BBULL,
		0xDBD98F34251B1108ULL,
		0x1CF58EA9CBC70EB0ULL,
		0x4A1EB16F906CD44AULL,
		0x13DDFE5EC105E139ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF83072DB2F08F7F5ULL,
		0x2478B96DDB4650E1ULL,
		0x40EEC75999AA8FA2ULL,
		0x5413C68512391F3CULL,
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
		0xCF23270D5A5FFB1DULL,
		0x23F8994CE9DB3A19ULL,
		0x62972BD8358D6606ULL,
		0xF75783D251E838B7ULL,
		0xDB7BBF156AA3420BULL,
		0xCB32C78279A2365DULL,
		0x7482802D97BDEC5BULL,
		0x2856A54CC18DA16AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6381843B2E9BC9B6ULL,
		0x4D8236AAF7EF4C08ULL,
		0xADF6329CBBBE7BA6ULL,
		0x74340D370CEE2E84ULL,
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
		0xC41B7F4B3B493280ULL,
		0x29F2D853A91E30E0ULL,
		0x90913493032384C5ULL,
		0xD56BCDE7D5ED5C8FULL,
		0x40EE30B665B9FB72ULL,
		0x6AE3CAFD064F2554ULL,
		0xDE1DB7D5F43C8E4BULL,
		0xE79D493BE071256AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6776BA5E54E48A9EULL,
		0x07C2F9E298DDBB62ULL,
		0x88FA7E554420A3F7ULL,
		0x36C4ACCB26B8EA6CULL,
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
		0xE9BE210D72D54563ULL,
		0x2362EFC7FE5ABDC8ULL,
		0xAB30C1B4F5896D79ULL,
		0x23E76BADAA14E408ULL,
		0x11E502A1F2E60249ULL,
		0x12681743B65DC999ULL,
		0xA7A687E1EB3B8063ULL,
		0x5B3542CE9D4AB000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x91BC851780F99E3AULL,
		0xDED663D51046AA81ULL,
		0x8DE8ED3DE05E7C2DULL,
		0x2DCF5659032B0421ULL,
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
		0x9A6ED624F470898EULL,
		0x5BA41258ABA0DC41ULL,
		0xADFA8437D69FB27CULL,
		0xEEE9072DA0C724E0ULL,
		0xD53DF5235FDC418CULL,
		0x46FDE82297FDB5C7ULL,
		0x90F4BADD39DCA098ULL,
		0x36FC3370F1A4D1E7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x41A139652F2245ACULL,
		0xE554877B3B49D7EBULL,
		0x324E410E6D5F8916ULL,
		0x1858A9F17F3E4D40ULL,
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
		0x9F91BD55C4BBD212ULL,
		0xDC0E69B46DB45FC3ULL,
		0x959A1FC61F5A23E2ULL,
		0x4D6BDACC58DEBAADULL,
		0xF28E684E72DA1408ULL,
		0xA31A594486D32428ULL,
		0x24A08522EF8EECD2ULL,
		0xA34EB79A213C143EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA0B538FAD11ACEE5ULL,
		0x11F7A9E0710BBDD7ULL,
		0x056DE2F5AE914B27ULL,
		0x0B1B1BAD47C9BBE7ULL,
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
		0x8362037FAD548ABCULL,
		0x2B8E1497CFAF5E96ULL,
		0x9E38904F303636D3ULL,
		0x14A5931158884CBFULL,
		0x94EC632EA04EDAD8ULL,
		0xE2D07F14CA3EBFDFULL,
		0xFA3ABE83EF049598ULL,
		0x5842693E18BB9488ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9E78BC6B790908BAULL,
		0xD680F1ADD4FFD9C6ULL,
		0xC2F0D7E4AAE46B84ULL,
		0x2E81324904605914ULL,
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
		0xF19A31BCA05F4B33ULL,
		0x723D3B8CB8C12466ULL,
		0x68DB1E946631600DULL,
		0x392C4C621D765345ULL,
		0x5EC7CF8DC9223534ULL,
		0x96035ECBAB2E108DULL,
		0xAF667CB2D8B3BC4AULL,
		0xCE3A1C1C8ACC9DA0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x034300C87B733572ULL,
		0xB6BD4DC821979963ULL,
		0x7211A12090DF531FULL,
		0x55CC789EB7D5B91FULL,
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
		0x9A5E9B6DFB122F79ULL,
		0xCAFDAEF1FE4BE527ULL,
		0xF5A46A46AFBFD673ULL,
		0x6A1DF492877FF2EAULL,
		0x39695DC5C8DA172AULL,
		0x4AA44B115B183EB6ULL,
		0xBDEE78A3E94F62B2ULL,
		0x5A34EF5B5F1CF214ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x200286C9CB71A1B6ULL,
		0xDF60D38583E53434ULL,
		0x270A529B51887CEAULL,
		0x4DF97C22A5CBE1FFULL,
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
		0x58D98E81900F95E4ULL,
		0x9AC11DE91B89812DULL,
		0xFA7B9B5402F17A9AULL,
		0xA366553335FD5F9CULL,
		0x321CE8D359AE827AULL,
		0x857032D6A7B37D59ULL,
		0x33790091397605E5ULL,
		0x83A1912CF5BD6EC3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC9241DE0DFF6F6F8ULL,
		0x6968A9C6002E1C6AULL,
		0x9E71B0E28A765AACULL,
		0x2D61E1DFB01BD096ULL,
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
		0x13886C3EE8371C07ULL,
		0x10E598A26011A7A6ULL,
		0x920ED5879C234CC5ULL,
		0x38C17A2889A075EEULL,
		0x912BEE34EC30399FULL,
		0xEB7C715A83464DBDULL,
		0x613A162AC2417B19ULL,
		0x91F1A0E8BF4CC1A2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA00DC819F75FACD2ULL,
		0x055E6C11DC8131C9ULL,
		0x00AE1FE071DB929EULL,
		0x629F5CB4EF053409ULL,
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
		0x3EDEFDC1D89297CBULL,
		0xBB016345F38A29EFULL,
		0x2C2462569756D686ULL,
		0x6C1EA8FDD537ED71ULL,
		0x9842F9C6049113E4ULL,
		0x570304EF5FB4ECDFULL,
		0x3CC6A0197DBE0FB3ULL,
		0x16E213B8D844F2A9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD8D01126861B8C28ULL,
		0xA5741ECE2865531FULL,
		0x31A0261F418D2B25ULL,
		0x51AD966DEF73F290ULL,
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
		0x9A11CF2EAE2A535BULL,
		0xAE44279ED384353AULL,
		0x95BE9439B3D81A2FULL,
		0xA7512BC64F4C358FULL,
		0x18C4C2EDE2E6CC31ULL,
		0xFCAA05014DFC1A2CULL,
		0x39C6AAAB5F86D815ULL,
		0x088F4740B89749EFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4746BE7E5C6CA2DAULL,
		0x2F80E5D066F017C6ULL,
		0x293BE9A9E1DC2D73ULL,
		0x6C95BF61B5C12F12ULL,
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
		0x5231100D5B0BECE7ULL,
		0x33645084F95DD946ULL,
		0x05BC597FA6F35E02ULL,
		0x0CF9A49EE534EB8CULL,
		0x1ED4A0DC253C272CULL,
		0x4B0D28A2921B4DDBULL,
		0xF8A623ACD7D6C5EEULL,
		0x633AF61AC7D181E4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE5C0F0BAE1F9BF96ULL,
		0x575858A6A96B67CCULL,
		0xEE65A527B0D4BF61ULL,
		0x47BA2C988E4E3388ULL,
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
		0xAE7B523DDF65D4A2ULL,
		0xD6BABA63F8CB005FULL,
		0xE7B523F1790613DAULL,
		0x1DD834D422472820ULL,
		0x889217EC3F246DDDULL,
		0xE09C3416E79A57CCULL,
		0x627D6A68ED765C16ULL,
		0x2252A1348D1D3C34ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF42ADF4F3ECE242EULL,
		0x2DEA75CA59B408BBULL,
		0x8652EF84B897BF40ULL,
		0x361C22A1149E17E7ULL,
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
		0x5C537249794B8BB7ULL,
		0xA9D0822C20F61332ULL,
		0x10D5E42960C4893EULL,
		0x7BBC51EC56BE6992ULL,
		0x17BF4A30C0199F65ULL,
		0xFB4F7DE2B52C8D82ULL,
		0x7800FA593024DEE0ULL,
		0x76E936A5F2B44F1CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE2B87585FD193761ULL,
		0xF79D31D305931481ULL,
		0xE0FB0D66863D9EA3ULL,
		0x225A6E8E5D8227CBULL,
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
		0xCCF4AD0218C58DAEULL,
		0xBB69B4B3FF1536E7ULL,
		0x3C76920497634BEBULL,
		0x80497B8D05D567B3ULL,
		0xA7ACA32F88D665B6ULL,
		0xD32CD7FD14F5E847ULL,
		0xCC25A2F8C9E78203ULL,
		0x9B9BF36B87AB06C4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB094E6106898AA2FULL,
		0x1411C4451B95B18AULL,
		0x8A0CC2F28FC0987DULL,
		0x196F9D83293868E9ULL,
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
		0x4CD955085C681A09ULL,
		0x3B743FE479F5B087ULL,
		0xC4E5A433748F6682ULL,
		0xCE698948B9E86454ULL,
		0x12C315CD246EAF6FULL,
		0x1402E116811CCD60ULL,
		0x7ECD18F096C5B04FULL,
		0x36FC4CAE7120B9C1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x15CE917BC4D625C6ULL,
		0x33E1A93BA43C2CCAULL,
		0x975757E9D5E7923FULL,
		0x77DCEB2D84C3F70DULL,
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
		0x9195C4DD31F540D3ULL,
		0x16278218D074B6F5ULL,
		0x91D5C7683D035731ULL,
		0xACB6BE08C4321F2EULL,
		0x8800478A5A2C67E4ULL,
		0x4E19138DAF4B05CBULL,
		0x3B40D51FE2B7C39CULL,
		0x0008C1FCC700F9B7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC1A06366948CACBEULL,
		0xADE06920D597932BULL,
		0x5D756A23E44A6064ULL,
		0x2E03898E4E573061ULL,
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
		0xAC11A8A612BB9F78ULL,
		0xF7E7F07BE1B20445ULL,
		0xBBD0595C17599BECULL,
		0xF65BFF478A93EBC9ULL,
		0x7225557589CA9E8AULL,
		0x9ED8901305E519FFULL,
		0x738F100994B86CECULL,
		0xF413D290FC1F7954ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9D9C581886CF2D72ULL,
		0x8C0D534EC1B3E030ULL,
		0xE30CBAC82AB9C70CULL,
		0x314D40CCF73FEE52ULL,
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
		0xA4B091ACF89C3F50ULL,
		0xCD1F047F6A096958ULL,
		0x3C5F3799C83F311BULL,
		0x98422D299D630D2BULL,
		0xB2C540B0EAEE99BBULL,
		0x98E5038D9E2E6D6FULL,
		0x43E8D4403EE324DBULL,
		0x3137B3D8003A9F3CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2DF82BEFD807122FULL,
		0x7F1D8B84E4EDA7EDULL,
		0x50EEB9231DF6A9B4ULL,
		0x6686DF39A616B01DULL,
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
		0xD022961A1075A1EBULL,
		0x2E426D67C4C08B29ULL,
		0x68D6285C00527341ULL,
		0xC825C35B4A8693AEULL,
		0x15D0C11686A58F99ULL,
		0x5F504F0F48883A36ULL,
		0x14C6D596B2942217ULL,
		0x15772CA1E9D8D1D7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0D1F3F720D08F326ULL,
		0x542E29AC88F92F31ULL,
		0x7E59DCBA824F82B9ULL,
		0x77D6636400B5B99BULL,
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
		0xC601DA46CB0BCA77ULL,
		0x59F4433E9C807DA9ULL,
		0xA43DECE53F1C5E77ULL,
		0xBA58A90DE5E29BDEULL,
		0x37200A5BDB6A46B3ULL,
		0x026395C499E1BC68ULL,
		0x4B9A2F6D5CED5152ULL,
		0xA5F306171FBBE206ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF4C363E95CD24CBFULL,
		0xB4BC7E6D74027521ULL,
		0xDD20F7210A5670A3ULL,
		0x5C6B907C9BC628CDULL,
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
		0x2EBC23347BA488D7ULL,
		0x5E8B66E5B4711468ULL,
		0x66CCA6ACA82E050DULL,
		0xD78938B7B8556880ULL,
		0x2BEE2D66FE188190ULL,
		0x2262990D9D25AE91ULL,
		0x8373E78521B4F3E5ULL,
		0x5B3661809671BF38ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB416E07E3347C64BULL,
		0x792E1EEB0808FDF4ULL,
		0xEA01046FA90A3910ULL,
		0x619BB1CE0D37CAE3ULL,
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
		0xA9CD7173542DA69AULL,
		0xFBB19855AE04FBF4ULL,
		0xF9E7D4B6CEF7D44AULL,
		0xADC2AE31D091FD90ULL,
		0xB3311783EDD63A4AULL,
		0xBC9B8EC0827B78E3ULL,
		0x029F3359EC14914BULL,
		0xD8357C223A253DC6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4316EF08A1FA5269ULL,
		0xFAC8C8E90C58EDC1ULL,
		0x5D89740FDA056588ULL,
		0x45B31B46721928F5ULL,
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
		0x268AD031B5701699ULL,
		0xC42778DA15B3C0F1ULL,
		0x45C92576E6347ABDULL,
		0x427202833266787BULL,
		0x295D9CA7F91AECADULL,
		0x5C1A430EA3915D9EULL,
		0x8407D2A598566F2AULL,
		0x909348BDF7ADEB39ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4A701120AF6F3B78ULL,
		0x700D6D065D47A66BULL,
		0xDEF26A0B8308FB07ULL,
		0x384ECEB5F6376304ULL,
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
		0x4F1649C1E5BE217AULL,
		0xACF4C0EA0307C91AULL,
		0x01EC33A6974A25D3ULL,
		0xCF05CFFA01296228ULL,
		0x9C52EDF789DD2743ULL,
		0xDCCDE4ABD9DA19E1ULL,
		0x314BD84D54016AE6ULL,
		0xF82F3AE5C1F187FEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x83659C805C91FAFDULL,
		0x7384B26C5967A097ULL,
		0x532E4F210F800418ULL,
		0x26088E14CB0391E3ULL,
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
		0x2A90B534484B464EULL,
		0xFEBC7911C542DF8CULL,
		0x5F9EC89786AEC888ULL,
		0xDA6586936C0186CDULL,
		0xD123518A0F12AA38ULL,
		0x8FAD0CA652D336B2ULL,
		0x0A187597EE3B4CCBULL,
		0xA2B35492447D2A0AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x35CECFB285108E54ULL,
		0x526C59C2109CFE17ULL,
		0xDF403D24E37C2EC0ULL,
		0x010414499695C44AULL,
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
		0x072BC1F7076ACED5ULL,
		0x60CD35A6A0B3F77BULL,
		0x5F0EADEED88FA85EULL,
		0xD72642E739385032ULL,
		0xB86E074D09D998ECULL,
		0x10577B3070103AC2ULL,
		0x826A633C3D500623ULL,
		0x7720CC168CED008BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6780D7667DB7849CULL,
		0xCDC97ED7431CB062ULL,
		0xBAD968DFF2709192ULL,
		0x06048E40246664E7ULL,
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
		0x7C9D15AC94BA0806ULL,
		0x5AD0A26F3FD98B45ULL,
		0xFB96E1DB9F00408EULL,
		0x73C17BE3B05E173DULL,
		0xE3F506B803A61AA9ULL,
		0x62C241F97BDA7594ULL,
		0x8FC04B71CA774096ULL,
		0x97DC800B302AA987ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x52FC14FD1F620073ULL,
		0x03A66D77A246FF5FULL,
		0x522214BFACB3D6E1ULL,
		0x7E7C7D8CD6B3415DULL,
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
		0x5080A0F048141F71ULL,
		0x32EE9B09FE1C56D8ULL,
		0x6081E20EF87C00E8ULL,
		0xAE6F5CC61559B96DULL,
		0xCA29051426CD3357ULL,
		0x22F3B04F1B902C93ULL,
		0xD430A84CF2E3CED3ULL,
		0xFED3745549253A65ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x529761EE0A89C412ULL,
		0x631AC6C81582F4C8ULL,
		0xDFBADD7B064CB43FULL,
		0x01D2A16EF0E0648AULL,
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
		0xB2946DADC0F2B3EEULL,
		0x0AD6525B1A565715ULL,
		0x139A13DDA91E4E53ULL,
		0x6D1AF8C808EC5ADDULL,
		0xEBF31F66B3928262ULL,
		0x081BDC220CA6C376ULL,
		0xC0EC2B9BF486E608ULL,
		0x982BA6C144A36533ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB8AB16EC68B211E4ULL,
		0x3EF8FF68FB175ABCULL,
		0xB6A88D03F5247384ULL,
		0x0395B978392D608BULL,
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
		0x3D9803A3C5A3F5B5ULL,
		0xA348692C55ABA081ULL,
		0x3A633606245419CBULL,
		0x7F6AC3C0C020910DULL,
		0xF7AC6BB0BD3F0F66ULL,
		0x9FE0ED76E35868C7ULL,
		0x0ED8C52A1FBBE011ULL,
		0xC99D442E336B46C2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x012FFFDFDD00434DULL,
		0x5EABA8D214CB2E30ULL,
		0x6E907A46DA375C69ULL,
		0x6CC2E29C620D11DBULL,
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
		0xAD88A83B1B1F7398ULL,
		0x95A6CDBD8D57A404ULL,
		0x5C23FF20C152F4B3ULL,
		0xFB969075C8CF0C4CULL,
		0x13C6B5939EB4775AULL,
		0x978958D4439A4440ULL,
		0x996D9C97D7422F36ULL,
		0x6D89EA40A3E474C0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9D079C24A9E92D7AULL,
		0x1409FD3F963DC587ULL,
		0x22693DAAB525F6CEULL,
		0x3E0F560E1CB860E3ULL,
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
		0x9ECDBF2AD155019EULL,
		0x7ED529DCB2F4B047ULL,
		0x6DB267716483CEF3ULL,
		0x594BA4BB243C7981ULL,
		0xE7302B198FBCCC11ULL,
		0xA9844E1A5B85A8F0ULL,
		0xE30064D6C82A0EB7ULL,
		0xBE9642BF8690D06EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEFF424F6275B505FULL,
		0xA878C1C648CBC409ULL,
		0x1FC15F531AC1FE36ULL,
		0x23998D291DBB69F7ULL,
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
		0x42B9E923B7DE70AAULL,
		0x245BDE603727FE65ULL,
		0x50B13EF6794C060EULL,
		0x7E6A6B66110E470CULL,
		0xD56672A4FAB94764ULL,
		0x2800EAED49537034ULL,
		0xD04A5D4670C83146ULL,
		0x114867A93289363BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEFEEEDA0EF5F09F4ULL,
		0x147EBD99198AA63CULL,
		0x3BBB176B37035678ULL,
		0x0F29CE83916C53EDULL,
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
		0x3D963161A1A5F7FBULL,
		0xD80CDFBC263DED9EULL,
		0x4C06EF62BCEE557BULL,
		0xF7A83330DD1A76B6ULL,
		0x700EE28A24122E00ULL,
		0x2ED7692C413BD382ULL,
		0x6651F0E461798513ULL,
		0xB9FF657385388993ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDFCBD1E2FC58D036ULL,
		0xCC067C4DD51F52FAULL,
		0x7C30B14934F81654ULL,
		0x13914256A37EE297ULL,
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
		0x83F4433D66241B5BULL,
		0x764BFD66EE4450DEULL,
		0x3B525E2492B42247ULL,
		0x8ED5385A0C9B4BD4ULL,
		0x8D7F018843B8A7BEULL,
		0xED3184B38DAEF792ULL,
		0x1D6254D3EBD8F167ULL,
		0xF4BD202AECFB4794ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x84CE7D77738D06FAULL,
		0xABA5B00DF63D109FULL,
		0x97EAF59994E7F7B4ULL,
		0x62E7FEB939E7EBD0ULL,
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
		0x6AFED46E4577E3D8ULL,
		0x61F93EE6DE20D3FBULL,
		0x8F87449FCAEA4602ULL,
		0xF8591AA6B209DBB2ULL,
		0xEE992A554E986A77ULL,
		0x9F70A6867110739AULL,
		0x8E26E80C492711D4ULL,
		0x8894C5AB3B6C20A4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD5BB1D17F017B4A0ULL,
		0x0CB1F6DBA691FCFAULL,
		0xA94DB672A6B6EB92ULL,
		0x3E6E72118416B41FULL,
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
		0x86B6F44CC1F35DF9ULL,
		0xBD1987A341865E1BULL,
		0x8AB3DE0E14D6D84FULL,
		0x06E50A6700278F8DULL,
		0x7F80102B73E051D4ULL,
		0xF608A301508872BEULL,
		0xF92FFF8D82554AD8ULL,
		0xF42C3738CAEE93A7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x73B95ABFF53F88C9ULL,
		0x4261B9D535C76662ULL,
		0x87D3CD0F6D7FF484ULL,
		0x45753CD51F917A7CULL,
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
		0xDE915881FD3F57C9ULL,
		0x4F7BC739653B518EULL,
		0x29D8C48B66577226ULL,
		0x197E77863333CC91ULL,
		0x346F56234693B65CULL,
		0xE404B5EF9D6DF047ULL,
		0x63B34AF604A0E40DULL,
		0x1AEBF3F541C7354CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA71821BE772C6A09ULL,
		0x282EC8CAC38CFC20ULL,
		0xF675E51016394C36ULL,
		0x1884ADEDF6C5B5E7ULL,
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
		0x7D0A791ACDCD710AULL,
		0xF6FC5FECAD3F6F76ULL,
		0xA304DAAEF0B50626ULL,
		0x2947177C8C9E9487ULL,
		0xD650FEB38BD739CAULL,
		0xD425945765B57005ULL,
		0x19A4F7547341ADBBULL,
		0x51A16F0F44D1665EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4D1047C18FC006CEULL,
		0x749064E5C62E1054ULL,
		0x718191380C74D008ULL,
		0x473D93C0C3B3C67FULL,
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
		0x1C22BDFB6E92ECCDULL,
		0x9475B39698EF4C4AULL,
		0x8A3D4E97181A3ACEULL,
		0xD9D55E392C34177BULL,
		0x56F86D0CDDC83A33ULL,
		0x58508DD1CBA1CD23ULL,
		0xBAC6C217DC809C3BULL,
		0x8B3C5571901A04ABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0502EDE45A4B9390ULL,
		0xB06AC0BAD2F3BF89ULL,
		0x43BE1E21D3316B9DULL,
		0x04CA0D149010C8F9ULL,
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
		0xD42565ADAD17C835ULL,
		0x0339BACB0FD6DC33ULL,
		0x61140EDEA64DD1B5ULL,
		0xF8A24E9BE6CB16E2ULL,
		0x951B0F390D392546ULL,
		0x1E0B53756FA8C577ULL,
		0x6E4B67B7DD02AB3CULL,
		0x939FEA72BCDF78D9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF629A825A39353F0ULL,
		0x78E81E39A2E42BF3ULL,
		0xC045742974B33CA1ULL,
		0x625F1BA3EFF70728ULL,
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
		0xFE064492ED9147B4ULL,
		0xA3ABEFCDC3BB62C0ULL,
		0x2132C69781FFA1FFULL,
		0xB971EC3DDF03F470ULL,
		0x318D5796537FDDC7ULL,
		0x1E31EFF96D95E130ULL,
		0x831038CBA68C8DF1ULL,
		0x3CD620A330795E40ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x590144E3528C34A7ULL,
		0x1F158ED407FACFE8ULL,
		0x959B34D23ADCB3CAULL,
		0x413AC4771107F203ULL,
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
		0x597DF58D81F73067ULL,
		0xCD1E987A5D0C9BD1ULL,
		0x4AB2BE6BC98878CAULL,
		0xD37EEC27C6A0A65AULL,
		0x3FCA90F558E9074BULL,
		0x8326ED236A52B2CAULL,
		0xECB5CEE8EBC8AB67ULL,
		0x37A7FB1B8CE98B09ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD18F79F8B48E46DFULL,
		0x44E5CBBC255325D6ULL,
		0x6DAF74FEC951EA28ULL,
		0x166E323EB14B49D3ULL,
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
		0xC78CD55380D749F8ULL,
		0xE71ED4D334FAABFDULL,
		0xA51367EA090DA457ULL,
		0xA9486432554988B1ULL,
		0xEBEB421592B7FD2DULL,
		0x241A20D542A901D5ULL,
		0x22D7B6A408D7071BULL,
		0xD19F9606050BB885ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCC78A4874826E353ULL,
		0x42FFB47B1A10F1BEULL,
		0xD118844358F8B25FULL,
		0x46F8A9171506EC74ULL,
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
		0xDDD19D7658BE2787ULL,
		0x274FE7427580B48EULL,
		0x6B4D195819841226ULL,
		0xE2257EA97C8F25BDULL,
		0x98D2C53A097DD331ULL,
		0x74A1F9EF3DEAE136ULL,
		0x494060DF3795E36BULL,
		0xEC84A0F4DADC42EAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8D1AE413C16B8612ULL,
		0x775B00C5A65E22A9ULL,
		0x4ADB7A7A59C3D419ULL,
		0x7DD56301F9411484ULL,
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
		0x5561DB4670466746ULL,
		0xDD76B6056A68D71DULL,
		0x49EDEA7900283AF6ULL,
		0xF17F508D641BBC53ULL,
		0x3150DBC0E1892355ULL,
		0x882671623883D58CULL,
		0x39EDA5F59A4856E9ULL,
		0xB4F9820660D200E4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA76279E7EAA1A9F9ULL,
		0x132B8A99CDFA89ECULL,
		0xE3348CEDE6E521A1ULL,
		0x4E889D7FC347DE33ULL,
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
		0x4BC2546BEAEB67C2ULL,
		0x67E3754A73AABB7DULL,
		0xAB094664B207EC8EULL,
		0x19381B9A0BB8BEDDULL,
		0x37362134F844393DULL,
		0x2FA397A679E70E07ULL,
		0xAA44D6C0D2E7B83FULL,
		0x6F403F9326E50E1EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7DCB4248C50BE943ULL,
		0x7A2BF8008BF6D08FULL,
		0xF1412704006D45EFULL,
		0x1CC18B71D1B8D76AULL,
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
		0x9042A006F44FE5B5ULL,
		0x8BE2F003136C55EBULL,
		0xE586E9279CC3585BULL,
		0x1A0110E9E040219BULL,
		0xB229892A0777329CULL,
		0xFAE7F19AC76F0B1FULL,
		0xFD15B2D515CFE46EULL,
		0x8B4542FD0DB9BFBEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x026CFC4410016BE8ULL,
		0xCA50CCFCADE7FCA0ULL,
		0x76BF74C8D99F40D4ULL,
		0x46490279E9D297F5ULL,
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
		0x169EF95785135461ULL,
		0x867BF929C11989C4ULL,
		0xA37090F4EECE5558ULL,
		0x394F52FD0D38B37AULL,
		0xACA4C6FB293D0DD1ULL,
		0x04F4AC977E5A31ACULL,
		0x0F9AC133934060EAULL,
		0x1DFE18BC6A21AA4FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB714829FA4236212ULL,
		0x42CD97A6827CE965ULL,
		0xF4693E9CCA5CB815ULL,
		0x2D06FEF4CE37FB36ULL,
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
		0x7D71F43E245AD89DULL,
		0x2DEB2FA09A9FF585ULL,
		0xA7AAB4B9C4A102B8ULL,
		0x5C2E4C42CF95AEADULL,
		0x0F83353EB2DD603DULL,
		0x2D9F2E7B1FCD8633ULL,
		0x34436B8FDEFEBC87ULL,
		0x82F9AE5EEB6AF9EAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCAEBDB8CB1372490ULL,
		0xF38C15E75321E119ULL,
		0x69ACAC14DE70FEC8ULL,
		0x4D3E2E59C176C771ULL,
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
		0x6F054681E2E9072EULL,
		0x3001F6C123D52C94ULL,
		0xA7962ECE0EF48B1BULL,
		0x1451EC649D8DFED7ULL,
		0x51A7713107DD42F8ULL,
		0x219B062FB4B50CABULL,
		0xFE58AA73E15C466EULL,
		0xEAEE160D32247B93ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8DE013C90DC0FD1DULL,
		0x2D04E1D5F6B50E02ULL,
		0x68BF7C0182A6FF74ULL,
		0x73A9325A0EF856CFULL,
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
		0x57D10DE630830A08ULL,
		0x7B245F08B6E267A7ULL,
		0x53EB4F64A65966F4ULL,
		0xA729ED0840E7839FULL,
		0x7FA59F90F567D4C2ULL,
		0x1291D2684755ADD4ULL,
		0x0B0BA04621DCC06AULL,
		0xAB854FCB5DB0BE84ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4A66BD6A9DECA2B0ULL,
		0x3CC99A834D9A3532ULL,
		0xF7A519CDAD1DF6B3ULL,
		0x1CF3C5382923CB38ULL,
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
		0x269835C3EC29DE86ULL,
		0xF12D30A263F2CD8EULL,
		0xBAB4E877EC10A2D9ULL,
		0x3FB183AF04AF8B77ULL,
		0x67920479EEC9BDBFULL,
		0x875F2B1C7BA43FDFULL,
		0x0BA9B1958F467C4EULL,
		0x56BC13C4BC7125C4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8644DFDD5E1C0ACEULL,
		0x094D96DCBE5448B7ULL,
		0x75E544AB30871682ULL,
		0x1F9C72E2FD7B2691ULL,
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
		0x03E249268202AA6BULL,
		0x04F8D68EB207233AULL,
		0x004846F476AFF814ULL,
		0x2317AF7E8A80888BULL,
		0x50D117113CC996D4ULL,
		0x3CF7B5030D211C8FULL,
		0x4E31FEC356C69E62ULL,
		0x6986EBE4A622F685ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x02EBB5B587EF1030ULL,
		0x11BDB502A4F16080ULL,
		0x9BB417F3582B7AA9ULL,
		0x4D1EB36F33B12054ULL,
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
		0xF23865574097F596ULL,
		0x2C10780C77A3EDDEULL,
		0x9C92323A76E2D9D2ULL,
		0x03856CF90E444F0FULL,
		0x97676C8C72EB8D2DULL,
		0x06C4B661A2692DA5ULL,
		0x114F8335B6E03BE0ULL,
		0x6B803EF70FDD9F36ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6B9282304F8EEC91ULL,
		0x2D438A8A9340B473ULL,
		0x2E5FAC339C2BBD13ULL,
		0x788EC5A56929F116ULL,
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
		0xC09C519DF48C3D1EULL,
		0xB65392D9E231A511ULL,
		0x7C59D0CE9EC60F76ULL,
		0x7B1B28733E85E8E7ULL,
		0xE51D827D310F1B66ULL,
		0x324191E9A6832C1AULL,
		0xB0C194C595B8C06EULL,
		0x8F082FA2CBBF4850ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC2FDB0333CCA5173ULL,
		0x2C0F3B8899AA310FULL,
		0xB915E622D8329FD2ULL,
		0x36523A9D7CEAA4E1ULL,
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
		0x5C8E5D598E5A47D9ULL,
		0x846DF58B72DDE4BDULL,
		0x38F4FE1FB03EA753ULL,
		0x79C09011CB3E2567ULL,
		0x45149AC5A145C79FULL,
		0x8ED50AFCB6390AACULL,
		0xF5364343497AC384ULL,
		0xC2A70E4799ADA442ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9D9D56AF7EB5EDC1ULL,
		0xB80D970E7F557A4FULL,
		0x9F02FA1C9877AD00ULL,
		0x5E8CAEB29B048757ULL,
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
		0x0C28073C4A40B2DCULL,
		0xE0731D3BCEE43EB9ULL,
		0x4FDF413A2377CD19ULL,
		0xBCEE877EB2706DA1ULL,
		0x469548059F1CC691ULL,
		0xDB83C4B95E966168ULL,
		0x4F573F3A0ACECE86ULL,
		0x1A5227E9F1812904ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8650B811E8862D0DULL,
		0x760250BFD936B433ULL,
		0x16D2A3D7BE2A751EULL,
		0x252074388B9C8445ULL,
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
		0xF7EE7C7124943357ULL,
		0x5C83B719522DEC8BULL,
		0x4DA0C2559910C37AULL,
		0x37B119DFA1B814BBULL,
		0x2159FBC006B1452EULL,
		0xAF0361DA602E14CCULL,
		0x2D20BAB9FB62569AULL,
		0xCC229B19AE15F57EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEB49DAF222E47CB2ULL,
		0x57043D83990502D8ULL,
		0x007C79F0E9A99E70ULL,
		0x04D41FAF78FA8576ULL,
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
		0x33E3B91F7DEFA830ULL,
		0x7405E51C8D9FA498ULL,
		0xDBE0883C23EF29E3ULL,
		0x4ED4A68B1FA5755BULL,
		0x159710DCCE28484FULL,
		0xDA593065FA548A84ULL,
		0xCC37D9BADF4577A9ULL,
		0xCB52DF2769A3D6ACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x685039E617EA685EULL,
		0xDD43143FB62C3433ULL,
		0x2C2AD9F9483EED19ULL,
		0x7D21C664CDF75302ULL,
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
		0x9662BD7B4D195548ULL,
		0x42D236BED42D452FULL,
		0xBAED00F662E2BA84ULL,
		0xF431905C09B25C3EULL,
		0x7C9DE723D4C2B5F1ULL,
		0xB5BABBAC8D3B42A0ULL,
		0xFC33125C781B03C9ULL,
		0x6B74DAF990F234A5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x15D30CCCE2005981ULL,
		0x3C8A125BCAF92902ULL,
		0x2A81BAB036E54A75ULL,
		0x678A11678DA62CE2ULL,
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
		0x8BA182C160481903ULL,
		0x3649B8AC5D3A166DULL,
		0xDFB7642C1030CE51ULL,
		0x6B96143B7B0EE0F7ULL,
		0xC6D4CE0338342933ULL,
		0x900C8B54659C250AULL,
		0x0D62333C6334F8F6ULL,
		0x618FD034428FB8C5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F38173BB80638BCULL,
		0x9826673372679607ULL,
		0xDC4AFF22CA0DC2EAULL,
		0x66EEFBFD5C644E37ULL,
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
		0x9D73FEE8B69A597DULL,
		0xDC26626C6F605BDFULL,
		0xD5D525460AD267A3ULL,
		0x27BA7DD6BE9725CFULL,
		0xC83AD0313683C839ULL,
		0x2656C878252DD829ULL,
		0xB4FAB84533EC2EE6ULL,
		0x866F0FC61A85C5B5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x562EE636CE2A14EBULL,
		0x8D082441F42E7213ULL,
		0xB30C7F8BBFE15DCDULL,
		0x1C36D53EAE727EC8ULL,
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
		0x64983EC663CCE1EEULL,
		0x5FEFDA211A52C2C1ULL,
		0x6C0382CD149708B6ULL,
		0x73BF06812426201FULL,
		0xC0A2E8AA554C9F28ULL,
		0x4BDE41D6BCEB9295ULL,
		0x797BB21D8E149FDAULL,
		0x013F5879D88675EBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFCC6C80F0D2C81F1ULL,
		0xA2EDA001254A84FBULL,
		0x745FF3302BA6C31DULL,
		0x23262897481BA113ULL,
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
		0x06DC58EC1EE47931ULL,
		0x0711CC2E9EB87AC4ULL,
		0xD9C1F5668B310BDAULL,
		0xF6D98994674B9104ULL,
		0x0F632DC6CB6E74DBULL,
		0x5AB5F9900E66E972ULL,
		0xD9F7EA23E4731417ULL,
		0x391CFBA389D1E41BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4F95246E5149D309ULL,
		0x7E14D790C1FF21B2ULL,
		0x348EB6BA74460751ULL,
		0x7126E3DADC736D27ULL,
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
		0x951B498C6DE3DE51ULL,
		0x8E5A4799385DB945ULL,
		0x51070B4BA772C698ULL,
		0x139F83EC68888CAAULL,
		0x18D0F8A30E9D2312ULL,
		0xDE9C47F9025D4DF8ULL,
		0xE4C996B5E17F8C26ULL,
		0x9746633FBB6AD7E8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x442031C099371654ULL,
		0x998CF68F92374C19ULL,
		0x46F36A4B2061945DULL,
		0x08123F623A64993CULL,
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
		0x53F1FC7B09C81BD7ULL,
		0xD070D32B172647BAULL,
		0x0FBFF109743400B6ULL,
		0x07DAE910809FE220ULL,
		0x0830A0ABDE42DA4CULL,
		0x9250636C2D0E47B9ULL,
		0x2EAA62C31C37D179ULL,
		0x01E36A8E838CD798ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8B29D5FE07B4831FULL,
		0x885F9539C744ED31ULL,
		0xFD0A99FFA47D18C2ULL,
		0x4F9CBA380787E2B6ULL,
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
		0xC2FA72A6E2F3EB47ULL,
		0x0F10BE258B3E3553ULL,
		0x9685EAA05564EE93ULL,
		0x72B58FD1A3233A76ULL,
		0x68A130A59A45963AULL,
		0xB720B1FA0E3E976FULL,
		0x882B7649EC0A88BEULL,
		0xFF82431DEF2A5151ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4AE7AB3BC9483D87ULL,
		0x3DEB2943A888AFDDULL,
		0xCCF979995EF53AE2ULL,
		0x600B8643236B4C90ULL,
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
		0xFF3762F5F1411374ULL,
		0x9AC8FEEE0747AD2BULL,
		0x451505F899611307ULL,
		0x5A72BFEB91533DD1ULL,
		0xF9E47EAF479FCE5DULL,
		0x1EE33810E2A1C53EULL,
		0xFB4A9AE145061E5AULL,
		0x373501B30C95EAD8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x172230FA92F9B685ULL,
		0x3083516FAB4AF485ULL,
		0x92280368D8499468ULL,
		0x0C51007F6F941A06ULL,
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
		0x32C22799D42052CBULL,
		0xB46383DF27D46C88ULL,
		0xE916D06ECEA07B4FULL,
		0x9EE93AC6550ED946ULL,
		0xE3360911BEC53511ULL,
		0x6DC2EDEF371F1D20ULL,
		0x0AE8D0159627A79CULL,
		0xA5E5D3157AFD33D7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xECC7803C25663707ULL,
		0xFF52D5615672BF69ULL,
		0x87A5B3A318835C87ULL,
		0x3F068FF696A48B32ULL,
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
		0x270CD4C838A97ED3ULL,
		0xD0C7EF57A0728708ULL,
		0x563D210BB2D87D82ULL,
		0x10AF8508D5DFF59AULL,
		0xAACAC6521349E8DAULL,
		0xE360114143D14521ULL,
		0xA8AED0255B546397ULL,
		0x87857E9C90DFAA3AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x812644F715A21227ULL,
		0x910A7F07B182CA07ULL,
		0x60300697415F460EULL,
		0x2E80504657133A4FULL,
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
		0x9428E2BC42E60678ULL,
		0x136648B286E07C24ULL,
		0x023588A3760EB858ULL,
		0xFE413631CAEB10E3ULL,
		0xEADE07F32346F1EBULL,
		0xD0779EF12BFFCB8CULL,
		0x276333500F2F3BC1ULL,
		0xFA5A79EA1ACC4C9EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x711E10D37F6DF4FEULL,
		0x0527E07F0ED8B30FULL,
		0xDAEF2685B711971DULL,
		0x27AF4EF1C53E705CULL,
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
		0x412C062E2580EEC4ULL,
		0xBE7138CE2394C5CEULL,
		0x6C936A958507263AULL,
		0x6390AF583F219C1CULL,
		0x103B7D74C6A24AD8ULL,
		0xF0A91207C4F1454AULL,
		0x4C2A8BAAB74F76FDULL,
		0xA99BA28494678B85ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAA00A583A1980E9DULL,
		0x7789E5F55F650ECCULL,
		0xBAE425ECBAD2CFECULL,
		0x10AACF06468051E5ULL,
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
		0x06EB4E6FDDF2C76DULL,
		0xD05A6DE1618A7D09ULL,
		0x44340E0B30EEADA4ULL,
		0x201F26B71E0C2BA9ULL,
		0x11EE00F56225F7AFULL,
		0x0AD258F9B094CE6DULL,
		0x2C54FC981641AC65ULL,
		0x18F06B0FC014D934ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB03F72DC6F958BECULL,
		0x6B93A2F197A12139ULL,
		0xD8D18C9E7EAE44A4ULL,
		0x53CF0B0DA1246967ULL,
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
		0xA8407D6425D690EAULL,
		0xB1C87C207292461BULL,
		0xB51DEAFBE57C4F83ULL,
		0x180719DCF4CAA560ULL,
		0x175D19EA71C5E605ULL,
		0x86FC65F0FA7252A8ULL,
		0xFD4DA10B618211AFULL,
		0xE159D21B272E5807ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x201256310936BAA1ULL,
		0xBB3F9DE59F8A8B0FULL,
		0x4EA3D2AC5ECAEF91ULL,
		0x0B5C49E4C5ABB690ULL,
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
		0x5778EBB316F01A5CULL,
		0x41DD235B1A6CDEC4ULL,
		0xE9B29D8D03327634ULL,
		0xCBDB973DA4D3B92CULL,
		0xA4F0140F2682D80DULL,
		0x868257B1BF47BBC7ULL,
		0x46D1ED1E6B1DA15BULL,
		0x1348712AE844BC9FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD31BE5F2CE5C2CCFULL,
		0x393627BD7F12BE66ULL,
		0x6CDBD010E99869CAULL,
		0x289C639C1F07B8D1ULL,
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
		0xBFB813E89929C8FCULL,
		0xFD47B293A27CC632ULL,
		0x17C345D0D7889668ULL,
		0x269816049CB2CBACULL,
		0x6C836A8D6A74EB32ULL,
		0xF065371B4EE31877ULL,
		0xF95310E8EC3F74BDULL,
		0x1F06B8A04EC2593AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDB39E4E66684B313ULL,
		0xAC4DE0A1583267ECULL,
		0x1A17C863E8F3EA9AULL,
		0x41977DD04D8C0A6DULL,
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
		0xE001A0019FEB95ADULL,
		0x14C441E93C5D24A3ULL,
		0xD91A148ADBEC84A5ULL,
		0x183C3E8A0440FE55ULL,
		0xDB7926359AD76662ULL,
		0xDD9C1D69BFC8B0B3ULL,
		0x854CAA808CCA3B27ULL,
		0xF262567A9645B2C3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x73FD4BF69BE4CD91ULL,
		0xF9F09F9BB4275F56ULL,
		0xA27B639FC1F14C8FULL,
		0x12D514BC5299875BULL,
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
		0xECE824C11E333F3FULL,
		0x4253407833DA4A0CULL,
		0x7C7A8486E043060EULL,
		0xE050B2ABAEE84376ULL,
		0xDE56C52F914422D7ULL,
		0xCF50449971F2B4FCULL,
		0x5BC2E50DF6549911ULL,
		0x034C806049D97E5DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEDC969D0AE506B4FULL,
		0x083D6F3F1DE12795ULL,
		0x1B68849970D1BEB3ULL,
		0x5DABC0F6A5310552ULL,
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
		0x0E660EDC8853AA51ULL,
		0x34B63D9771BB15C8ULL,
		0xFAB64A5771FD7F38ULL,
		0x6EEE67FB3CF75FABULL,
		0x27D4203A595DA1A2ULL,
		0x1424A3CB106F34ABULL,
		0xA2D3B7AC9AE19A34ULL,
		0x12913AB52D5B4C4BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF7E2D785CC39A8CFULL,
		0x32268DBBE23CE72FULL,
		0x26238DF66F7A62F3ULL,
		0x307D1EDFF884B2E6ULL,
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
		0x096E5BFEA304DE0FULL,
		0xEAA783CC0CE51ACDULL,
		0xE2B4224FB32162ABULL,
		0x3835B33AC6E00FFFULL,
		0x667A13F341D1C761ULL,
		0xC860996D5DED36E7ULL,
		0x40F035204BEB9D9AULL,
		0x769792159853C6EEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3F8D521A6828790EULL,
		0xA8FE4A07FE1B4126ULL,
		0x865C051AF81AC7A5ULL,
		0x52B5626F634F975DULL,
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
		0x7D5C8AE57750F1D4ULL,
		0x8215FE2A48D3401CULL,
		0x68ADEF874CF7C3CFULL,
		0x45041E73C1B608B9ULL,
		0x04E55228020C3488ULL,
		0x333364A4D8ECBB32ULL,
		0xEDAB821A7DE29E57ULL,
		0x9DDA716C95A8ABE8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3766BCD5C520C181ULL,
		0x1BB6EEA27BF70989ULL,
		0xB0233F75FC9B44C1ULL,
		0x3370F491F8BF8D4CULL,
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
		0x0908FE315A76C9CFULL,
		0xBCEAD6140A2598B7ULL,
		0xC2A10A632B5DD938ULL,
		0xB2B895310776E6B1ULL,
		0x67CD2040E61B888CULL,
		0x0BA2C30C030E3CD4ULL,
		0x2B70AF208EA64D7EULL,
		0x6976B0DB090B01D3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x717BC7D3828D10F7ULL,
		0x7713C9DC7E42A03EULL,
		0x355B0938580D59EEULL,
		0x5A56D5B45F192C0AULL,
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