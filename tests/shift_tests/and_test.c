#include "../tests.h"

int32_t curve25519_key_and_test(void) {
	printf("Key and Test\n");
	curve25519_key_t k1 = {.key64 = {
		0xBDAF9E4D5EA3ADECULL,
		0xC23CB35FFD51DC19ULL,
		0x48ECC0E4E96A2074ULL,
		0xC0B49FCA81274163ULL,
		0x626298B1E6FACEF0ULL,
		0x8F7F0EB9D30C655CULL,
		0xE88075390FC2CB46ULL,
		0xE62EC607E7CB54D9ULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0xEA013CD6629A88FBULL,
		0x27D21A88A422A63AULL,
		0x93F59DD0E27C8C01ULL,
		0x1125B874134689C3ULL,
		0xE11B161B954380B8ULL,
		0x67B0B86234B78D46ULL,
		0x20BA18796B632103ULL,
		0xB989A14CCB1B40B7ULL
	}};
	curve25519_key_t k3 = {.key64 = {
		0xA8011C44428288E8ULL,
		0x02101208A4008418ULL,
		0x00E480C0E0680000ULL,
		0x0024984001060143ULL,
		0x60021011844280B0ULL,
		0x0730082010040544ULL,
		0x208010390B420102ULL,
		0xA0088004C30B4091ULL
	}};
	curve25519_key_t r = {};
	printf("Test Case 1\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	int32_t res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 1 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -1;
	} else {
		printf("Test Case 1 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2862143A2C445274ULL,
		0x65D4725278EEDFF1ULL,
		0x5309DD967FD7CB49ULL,
		0xF592CEC060C6416FULL,
		0xA17FA5527F90CC7AULL,
		0x383D11ABA4D0F4DCULL,
		0x1E5B6E5B5785E55AULL,
		0x25B3EAF5C4873384ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x70FB893F73A2C4FAULL,
		0xEE84168FA8A5DF00ULL,
		0x4876FEB5F5016CDAULL,
		0x456DC50EFF7E8AC7ULL,
		0x585473EF50D891B7ULL,
		0x671C4F2224EF25C5ULL,
		0x7BCD62626974CA89ULL,
		0x7B18DCBB3BBB2E79ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2062003A20004070ULL,
		0x6484120228A4DF00ULL,
		0x4000DC9475014848ULL,
		0x4500C40060460047ULL,
		0x0054214250908032ULL,
		0x201C012224C024C4ULL,
		0x1A4962424104C008ULL,
		0x2110C8B100832200ULL
	}};
	printf("Test Case 2\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 2 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -2;
	} else {
		printf("Test Case 2 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA997D9C5614A9FF9ULL,
		0x085B3FAC9BFFC4CEULL,
		0x5676F14341CB9613ULL,
		0x784E25FE0BBF4E37ULL,
		0x4F03A59837B90425ULL,
		0xB93DE528CEB0B002ULL,
		0x98AD67FF6584E495ULL,
		0x70B68660C01E6656ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4F92BF4A7A3CEACCULL,
		0x08C3BDC478036B39ULL,
		0x09BEE1DD571B59CCULL,
		0xE9990B1253CD5D7EULL,
		0x837A8175801BE9D4ULL,
		0x5385A897949BE039ULL,
		0xA5EF2449BAB773F6ULL,
		0x957BF4FD407A23BFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0992994060088AC8ULL,
		0x08433D8418034008ULL,
		0x0036E141410B1000ULL,
		0x68080112038D4C36ULL,
		0x0302811000190004ULL,
		0x1105A0008490A000ULL,
		0x80AD244920846094ULL,
		0x10328460401A2216ULL
	}};
	printf("Test Case 3\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 3 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -3;
	} else {
		printf("Test Case 3 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7D9DB26CB8E7B53AULL,
		0x394EC3F4DDA8BF1BULL,
		0x5D08BE36171595C9ULL,
		0xE0C03C735E92ACF7ULL,
		0x24AE60DCAC0880C0ULL,
		0xCCAFAA2883F21FEEULL,
		0x74463DF76537C225ULL,
		0x02CD0EDDE6E3A335ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3B40421F6C38E83CULL,
		0x4A5BADE613997D70ULL,
		0x657B8CAAC8D453C5ULL,
		0x65E6A7556B6B2DAEULL,
		0xA880DA5303553C6EULL,
		0x280B36765A7F2DB9ULL,
		0xCA251333991385DBULL,
		0xA2CE45A30E0404AFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3900020C2820A038ULL,
		0x084A81E411883D10ULL,
		0x45088C22001411C1ULL,
		0x60C024514A022CA6ULL,
		0x2080405000000040ULL,
		0x080B222002720DA8ULL,
		0x4004113301138001ULL,
		0x02CC048106000025ULL
	}};
	printf("Test Case 4\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 4 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -4;
	} else {
		printf("Test Case 4 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x052351CFCDC0856CULL,
		0x337D316A9246BB24ULL,
		0xA9B10D8A68A96152ULL,
		0x4C1806770D16A1DCULL,
		0x759C074B8A82B073ULL,
		0x2D60EAE19F6DAB62ULL,
		0x67CE282DDCF52417ULL,
		0x12AF32BA12D21F6FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x64FB7F145EC84F96ULL,
		0xB7615ECD7C78E61CULL,
		0xCB8EE02DEDDD5EE4ULL,
		0x50B41B99AFFF5B49ULL,
		0xA1A2336DAE4A3FFEULL,
		0xEF644147FFC6D6FDULL,
		0x2BB26E673D5A3AF0ULL,
		0xEEFA36F6E8ACEC1BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x042351044CC00504ULL,
		0x336110481040A204ULL,
		0x8980000868894040ULL,
		0x401002110D160148ULL,
		0x218003498A023072ULL,
		0x2D6040419F448260ULL,
		0x238228251C502010ULL,
		0x02AA32B200800C0BULL
	}};
	printf("Test Case 5\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 5 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -5;
	} else {
		printf("Test Case 5 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x73BD9028E3835D97ULL,
		0x736CB50CC897DA7BULL,
		0x5381F536DE0DDA2DULL,
		0xF51E904DE4A9AE19ULL,
		0xD1E533D63C186F6EULL,
		0xA339EF678D8994F2ULL,
		0x87D32548D1BE2544ULL,
		0x175601F4925C935EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x05648E8ED9F76330ULL,
		0x90AA0263B652D1A9ULL,
		0x17F7F251A25454A7ULL,
		0x41B4633E3487DC93ULL,
		0x6BD5A8D472BD0EE5ULL,
		0x7B28E59133335C37ULL,
		0x7EE14B6F741528CFULL,
		0xEB17E706A3D6ACC0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x01248008C1834110ULL,
		0x102800008012D029ULL,
		0x1381F01082045025ULL,
		0x4114000C24818C11ULL,
		0x41C520D430180E64ULL,
		0x2328E50101011432ULL,
		0x06C1014850142044ULL,
		0x0316010482548040ULL
	}};
	printf("Test Case 6\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 6 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -6;
	} else {
		printf("Test Case 6 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x91643828DFEEDF4AULL,
		0x447B2A39C0760FA2ULL,
		0xFCD0626808D85E12ULL,
		0xAF928DAEAF5B9BF5ULL,
		0xAE093390932D0B1FULL,
		0x665D49721052A461ULL,
		0xC06E6D9F2D91B368ULL,
		0x8426F291CE72323DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDE3852F9286EB411ULL,
		0x8923E92748238CE5ULL,
		0xD53503C312092B59ULL,
		0x174085E64CECFE70ULL,
		0xEDFFA1AFCA1E7083ULL,
		0x423A16EDC967A851ULL,
		0x68E336EB258DE744ULL,
		0x3CD549A428B4209CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x90201028086E9400ULL,
		0x0023282140220CA0ULL,
		0xD410024000080A10ULL,
		0x070085A60C489A70ULL,
		0xAC092180820C0003ULL,
		0x421800600042A041ULL,
		0x4062248B2581A340ULL,
		0x040440800830201CULL
	}};
	printf("Test Case 7\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 7 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -7;
	} else {
		printf("Test Case 7 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB430BD8447F01BEAULL,
		0x320B69002FB28228ULL,
		0x0E6605E65174D47DULL,
		0x37E16950A73E7724ULL,
		0x1609985113763459ULL,
		0x1F8F52F016DCF44CULL,
		0xB739253CC5D40D24ULL,
		0xC79E414111E2C57AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB088883E0CD9A231ULL,
		0x665F0C7C202CC45CULL,
		0x7C0853781F913212ULL,
		0x769E74A53350AE75ULL,
		0x773CAEA3F7EAE28EULL,
		0x677C1322E9ECABA7ULL,
		0x1B55EDE1BA5E4E24ULL,
		0xADD5668345481F6AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB000880404D00220ULL,
		0x220B080020208008ULL,
		0x0C00016011101010ULL,
		0x3680600023102624ULL,
		0x1608880113622008ULL,
		0x070C122000CCA004ULL,
		0x1311252080540C24ULL,
		0x859440010140056AULL
	}};
	printf("Test Case 8\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 8 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -8;
	} else {
		printf("Test Case 8 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x49D56B9B3E7D10EEULL,
		0x7EBAA4BC63794050ULL,
		0x4EFA072C36FD3CD5ULL,
		0xD1028BF346FEA884ULL,
		0x334D282DA27FBC28ULL,
		0xA1405ED34B6D7BA7ULL,
		0xB21E148E147EAE0BULL,
		0x44A38388BF39C682ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA455C3C8A72C2949ULL,
		0x9CE08A4E9C983F38ULL,
		0xA3ADC65A81E8BB4AULL,
		0x6F6C746F9C231AADULL,
		0xEDACF45B7036A95DULL,
		0x26BE7604B3B760F3ULL,
		0x0E82923D1BFD7F25ULL,
		0x3A1C1F7A0ADD370AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x00554388262C0048ULL,
		0x1CA0800C00180010ULL,
		0x02A8060800E83840ULL,
		0x4100006304220884ULL,
		0x210C20092036A808ULL,
		0x20005600032560A3ULL,
		0x0202100C107C2E01ULL,
		0x000003080A190602ULL
	}};
	printf("Test Case 9\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 9 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -9;
	} else {
		printf("Test Case 9 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2E42142F9FD2CBE6ULL,
		0x611497FF642FC476ULL,
		0x6AA76EC1DB540ADCULL,
		0xEBDC652D1448920CULL,
		0xC1D13EE223EF0073ULL,
		0xA340D099831CB589ULL,
		0xDDFF9EC352AEF383ULL,
		0x10E6FED73B808C95ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8E382AD02D3E9A6CULL,
		0xA0D67553AD141FD4ULL,
		0xF82C9B053AC12F8EULL,
		0x72268C97EF48C93BULL,
		0xE5F002E6CC75DFA3ULL,
		0x81617D21BC916DFFULL,
		0xE4A02D314F164728ULL,
		0x2AE76BA3BBB40841ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0E0000000D128A64ULL,
		0x2014155324040454ULL,
		0x68240A011A400A8CULL,
		0x6204040504488008ULL,
		0xC1D002E200650023ULL,
		0x8140500180102589ULL,
		0xC4A00C0142064300ULL,
		0x00E66A833B800801ULL
	}};
	printf("Test Case 10\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 10 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -10;
	} else {
		printf("Test Case 10 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB4401EBB8EEE3C79ULL,
		0x619F7DE5F7475F88ULL,
		0xFDF5BFE1FF495EAFULL,
		0xD948BD8A577F4BC7ULL,
		0xE77246FC64A9D992ULL,
		0x3C3038AFFF2A1C6EULL,
		0x154C1FF082EA2694ULL,
		0xE987448F35103B08ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x45DFE6F346E355F3ULL,
		0x7C69ACCEFD019E6AULL,
		0x11D8D88D20145C36ULL,
		0x8668F917FD12C73DULL,
		0xA98D9D324F4C3F7AULL,
		0xF22034E663BB7DAEULL,
		0x472EBF522B7C9137ULL,
		0x47241F6F415301BBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x044006B306E21471ULL,
		0x60092CC4F5011E08ULL,
		0x11D0988120005C26ULL,
		0x8048B90255124305ULL,
		0xA100043044081912ULL,
		0x302030A6632A1C2EULL,
		0x050C1F5002680014ULL,
		0x4104040F01100108ULL
	}};
	printf("Test Case 11\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 11 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -11;
	} else {
		printf("Test Case 11 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x95B9B00B6DFB7CDAULL,
		0x06EB18A68F7DDAFCULL,
		0xDA9CED5D84288496ULL,
		0x67C6250D5E57D4C6ULL,
		0xD056152C69BD69B9ULL,
		0x934F376E85FA96B0ULL,
		0xCDA40ECDBB9A3C40ULL,
		0x79E0AE217BFA2581ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x497DCE8DE1DB4CA9ULL,
		0x54E69D517A8CF4D5ULL,
		0x6DF27745E0607D43ULL,
		0x6014FBD2D9C62E5AULL,
		0x0B5722076B1F256AULL,
		0xA04069D9649BFD41ULL,
		0x4A0EFD7980667E06ULL,
		0x8B948912E62A971CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0139800961DB4C88ULL,
		0x04E218000A0CD0D4ULL,
		0x4890654580200402ULL,
		0x6004210058460442ULL,
		0x00560004691D2128ULL,
		0x80402148049A9400ULL,
		0x48040C4980023C00ULL,
		0x09808800622A0500ULL
	}};
	printf("Test Case 12\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 12 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -12;
	} else {
		printf("Test Case 12 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBF755FC81829FE30ULL,
		0x4911B3D77393A7F6ULL,
		0x1995F144913EBDE5ULL,
		0x6120E2D61E515563ULL,
		0xEAB1347036D16A76ULL,
		0xC72AF12ACAD63FA1ULL,
		0xD7E15AE236AD6953ULL,
		0x40E92000993A9506ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x613A19BC9EF62903ULL,
		0xFF652EB7D6AF8F7CULL,
		0x26FAA80555E4345CULL,
		0xD77827BCBD4D327CULL,
		0xBBDC5CDC3EF97B83ULL,
		0xBD1D0165AC67636FULL,
		0xFF46DA9B2D8E8F63ULL,
		0x1000EFC161C2F823ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2130198818202800ULL,
		0x4901229752838774ULL,
		0x0090A00411243444ULL,
		0x412022941C411060ULL,
		0xAA90145036D16A02ULL,
		0x8508012088462321ULL,
		0xD7405A82248C0943ULL,
		0x0000200001029002ULL
	}};
	printf("Test Case 13\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 13 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -13;
	} else {
		printf("Test Case 13 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD5149B7103FD08F4ULL,
		0x8765695C3094DB3BULL,
		0x176267BC8EE7D7BDULL,
		0x453A07309EE1B58EULL,
		0x359131631445E819ULL,
		0x219646D507CE956EULL,
		0x0CA3FD5D0EE1C750ULL,
		0x2E7F5E77C08A388CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA324A2E5A8A9CCAEULL,
		0x381956ED04D4AEBAULL,
		0x105073A813888B94ULL,
		0x3AD8B5F0E16E23D0ULL,
		0x2C5D1054DB2099D4ULL,
		0xE1E91AD0DEE052A5ULL,
		0xDA0A88FE4492DAD9ULL,
		0xEA2D05B9ED335254ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8104826100A908A4ULL,
		0x0001404C00948A3AULL,
		0x104063A802808394ULL,
		0x0018053080602180ULL,
		0x2411104010008810ULL,
		0x218002D006C01024ULL,
		0x0802885C0480C250ULL,
		0x2A2D0431C0021004ULL
	}};
	printf("Test Case 14\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 14 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -14;
	} else {
		printf("Test Case 14 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x88FF22BA7DDDEF41ULL,
		0xFD0B57911DA1ECACULL,
		0x2D46342447C92CDEULL,
		0xD633FA5E483EA424ULL,
		0x268BDD64CA18BCC5ULL,
		0xE2CDB4461F87C045ULL,
		0x4CC0960FCA5E2965ULL,
		0x4BE0CD5F6A1FD9E4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7D2ED9812D5B3CB6ULL,
		0xD2505EF3F5656A40ULL,
		0xD424F78F12557478ULL,
		0x6674D7E7B66EC76AULL,
		0x059A3CC982C01633ULL,
		0x7E19808F72F6A10CULL,
		0x5FBFA16D2843D658ULL,
		0xCB1C16070E7C4FE9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x082E00802D592C00ULL,
		0xD000569115216800ULL,
		0x0404340402412458ULL,
		0x4630D246002E8420ULL,
		0x048A1C4082001401ULL,
		0x6209800612868004ULL,
		0x4C80800D08420040ULL,
		0x4B0004070A1C49E0ULL
	}};
	printf("Test Case 15\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 15 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -15;
	} else {
		printf("Test Case 15 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCF33901C3F84C0C7ULL,
		0x43784DAA3C7F16FFULL,
		0x608B2C8F6D336733ULL,
		0x18C1E1E6931D6390ULL,
		0x306933D83416AB00ULL,
		0x56C92E82F3A186D1ULL,
		0xA25DE5910B73617BULL,
		0x41913CC16AF4FBB9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x87BD1FE13AC42915ULL,
		0xED2CC517B28DDA97ULL,
		0x8C018D00D0E031D1ULL,
		0xCEAED7D7EC8581B1ULL,
		0xA4011499CA08B75EULL,
		0x1882D371AD6DAEA7ULL,
		0x52CAC6AB32E59BD7ULL,
		0x695AEC39D021F29DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x873110003A840005ULL,
		0x41284502300D1297ULL,
		0x00010C0040202111ULL,
		0x0880C1C680050190ULL,
		0x200110980000A300ULL,
		0x10800200A1218681ULL,
		0x0248C48102610153ULL,
		0x41102C014020F299ULL
	}};
	printf("Test Case 16\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 16 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -16;
	} else {
		printf("Test Case 16 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDA0668EA5FD98B67ULL,
		0x9167503D0B436592ULL,
		0x06EC754716220A3AULL,
		0xB65E71612AE5117CULL,
		0xA0227B37FEAED680ULL,
		0xCF1B034DB5AF1890ULL,
		0xB03D71F7DFD103CFULL,
		0x08D375F24E3FC481ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9F7EE7B9BEB9C4F2ULL,
		0xE8D27807AC17A9D1ULL,
		0x9389EC796979503CULL,
		0x2C9C0CCA75E81FCBULL,
		0xFB2C82DBDD209244ULL,
		0x2952FFA9D0EE3928ULL,
		0x63CEAF3D612F5419ULL,
		0xA5FAFB3FD89BFFFBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9A0660A81E998062ULL,
		0x8042500508032190ULL,
		0x0288644100200038ULL,
		0x241C004020E01148ULL,
		0xA0200213DC209200ULL,
		0x0912030990AE1800ULL,
		0x200C213541010009ULL,
		0x00D27132481BC481ULL
	}};
	printf("Test Case 17\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 17 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -17;
	} else {
		printf("Test Case 17 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF6C4124CB0C506F2ULL,
		0x0FDCC441C704326DULL,
		0x5E3DAB99AFF9C29EULL,
		0x9830A6AF07D83EB3ULL,
		0x96156F044C22DCC7ULL,
		0xE3BB588CEA15F834ULL,
		0x7C50C4E5DF7ECBA1ULL,
		0x3D27996BB0CC1D87ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3B1FB8B003ADAC10ULL,
		0xE9648815E35AD0FBULL,
		0x44087737FF30FBFAULL,
		0x74285D1492B6CC92ULL,
		0x02BE19F22C2EC03DULL,
		0xB5EEC3C064464E4EULL,
		0xD47DCB7B127CF57FULL,
		0x5BC712580B627052ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3204100000850410ULL,
		0x09448001C3001069ULL,
		0x44082311AF30C29AULL,
		0x1020040402900C92ULL,
		0x021409000C22C005ULL,
		0xA1AA408060044804ULL,
		0x5450C061127CC121ULL,
		0x1907104800401002ULL
	}};
	printf("Test Case 18\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 18 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -18;
	} else {
		printf("Test Case 18 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD991D595A52FE753ULL,
		0x92C4B24BABD06FFFULL,
		0xCE83CC08416E7BE6ULL,
		0xC3F4C382DE7FC76DULL,
		0x1FAE6EAD636EBDFDULL,
		0x83C82D4C3B780950ULL,
		0x8BF4133A0BB4D2B3ULL,
		0x12CA2954340CA868ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBE5D7D18E34BB1E6ULL,
		0x051D26D293E1A46FULL,
		0x0F05079FDAD38537ULL,
		0x6D15CACD68448FF1ULL,
		0x9C1B1DB096C87929ULL,
		0x2D793ACE4CB6BA01ULL,
		0x4D71BE306549204AULL,
		0x209A6F324894E17EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x98115510A10BA142ULL,
		0x0004224283C0246FULL,
		0x0E01040840420126ULL,
		0x4114C28048448761ULL,
		0x1C0A0CA002483929ULL,
		0x0148284C08300800ULL,
		0x0970123001000002ULL,
		0x008A29100004A068ULL
	}};
	printf("Test Case 19\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 19 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -19;
	} else {
		printf("Test Case 19 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA349DB20F88C2B37ULL,
		0x6D320A05611FDB76ULL,
		0x0FF269A6B2A04CACULL,
		0xFA48856D7F16FF69ULL,
		0x23ABC673E754D7B0ULL,
		0x09ABC5F5BD84C462ULL,
		0x01C0F4675664E348ULL,
		0x60C865A1E42F3AB2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x06BB3200A2D7D6BCULL,
		0xB888240B627CC804ULL,
		0x28E448FB6586B175ULL,
		0xFDFFE13413EBCEEEULL,
		0xF6BE4D8F0473C8F3ULL,
		0x1248EC3DE40CE452ULL,
		0x8DDF601D79922F83ULL,
		0x69E1365FA7811904ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x02091200A0840234ULL,
		0x28000001601CC804ULL,
		0x08E048A220800024ULL,
		0xF84881241302CE68ULL,
		0x22AA44030450C0B0ULL,
		0x0008C435A404C442ULL,
		0x01C0600550002300ULL,
		0x60C02401A4011800ULL
	}};
	printf("Test Case 20\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 20 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -20;
	} else {
		printf("Test Case 20 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xACAA1529000373E1ULL,
		0xB89E59E306F36B8AULL,
		0x8BD1F7E35F42D97BULL,
		0xA7D67705C4C08AEBULL,
		0xB4DD92BDE770F9D6ULL,
		0x411A3463B12CDE3BULL,
		0x8C50E7B8D18EE0C6ULL,
		0x0A5746C6E7A62C07ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x423508464958EBB2ULL,
		0x85CF00A90C49DFE0ULL,
		0x5968C0FA0908EC8DULL,
		0xB3927A94D4C6A841ULL,
		0xF193E4524DCB1641ULL,
		0x7AB6452C10F559A9ULL,
		0xEB02D7CFD5C3CB95ULL,
		0x922252B55CA4800FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x00200000000063A0ULL,
		0x808E00A104414B80ULL,
		0x0940C0E20900C809ULL,
		0xA3927204C4C08841ULL,
		0xB091801045401040ULL,
		0x4012042010245829ULL,
		0x8800C788D182C084ULL,
		0x0202428444A40007ULL
	}};
	printf("Test Case 21\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 21 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -21;
	} else {
		printf("Test Case 21 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFBDE107292C7300DULL,
		0xDCA6DE1B8CB39640ULL,
		0x262529880DD988EEULL,
		0x773AF72BD498829FULL,
		0x6729D157B5005C48ULL,
		0x23AFDBC22A8CF743ULL,
		0xDAB7648241537E9AULL,
		0x61ACDDC53AFB0B7CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x684C04280B14C363ULL,
		0x510ED8D399ACDED8ULL,
		0x3D14CA3044D89013ULL,
		0x497463DC89DC0CA6ULL,
		0x5CF800D132090128ULL,
		0xD20501F8C68963ABULL,
		0xF7EA4A6A1A763B91ULL,
		0xBEAA6C4A0DF1E013ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x684C002002040001ULL,
		0x5006D81388A09640ULL,
		0x2404080004D88002ULL,
		0x4130630880980086ULL,
		0x4428005130000008ULL,
		0x020501C002886303ULL,
		0xD2A2400200523A90ULL,
		0x20A84C4008F10010ULL
	}};
	printf("Test Case 22\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 22 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -22;
	} else {
		printf("Test Case 22 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF76E723862A5D1FCULL,
		0x3C44B3FBD67566EEULL,
		0x26AAF5CCDAB75D6DULL,
		0x80F0CC2AD7B1AD22ULL,
		0xD22A21DBF269C56BULL,
		0x908B584A0DF3F258ULL,
		0x83A31E081050F1CFULL,
		0x1B651D7654335B64ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4B168BB977E966B9ULL,
		0x336FE279EDED38CDULL,
		0xBC3AF053B489CFDFULL,
		0xB1B60CE54114DCF8ULL,
		0x54B2F4B5463E03FDULL,
		0xBFBECACE0C034B3DULL,
		0x58975FDF99DB321CULL,
		0x7885BC5684A76ACFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4306023862A140B8ULL,
		0x3044A279C46520CCULL,
		0x242AF04090814D4DULL,
		0x80B00C2041108C20ULL,
		0x5022209142280169ULL,
		0x908A484A0C034218ULL,
		0x00831E081050300CULL,
		0x18051C5604234A44ULL
	}};
	printf("Test Case 23\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 23 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -23;
	} else {
		printf("Test Case 23 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB68A327C9311C17AULL,
		0x0E9FD3CEF9D94BA1ULL,
		0xB0E458884026F998ULL,
		0x58E68B167A373CFFULL,
		0xBD19E090FE5FDADBULL,
		0xCDE24E5C9D4B2DD7ULL,
		0x14EC7AD787DB5BDDULL,
		0x1E8BB8DE76E25FBBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x619BCDF2F05DC86CULL,
		0x446CCEB2F94A9A0EULL,
		0x7010CBDC0740FE8CULL,
		0x70F40BF6D855D797ULL,
		0x7D58D7FB90D33DF0ULL,
		0x398DBF33B9A7C051ULL,
		0xB56979642A36DBF2ULL,
		0x09586B1611069BBDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x208A00709011C068ULL,
		0x040CC282F9480A00ULL,
		0x300048880000F888ULL,
		0x50E40B1658151497ULL,
		0x3D18C090905318D0ULL,
		0x09800E1099030051ULL,
		0x1468784402125BD0ULL,
		0x0808281610021BB9ULL
	}};
	printf("Test Case 24\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 24 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -24;
	} else {
		printf("Test Case 24 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8BD5D729A2FCF1ADULL,
		0xC1C039F3D24F3A18ULL,
		0x4D168532E5559B06ULL,
		0x5DC2386F57B9B882ULL,
		0xD5883FA12D7FDB8BULL,
		0xF87E8283487A5F3BULL,
		0x4B77B7744E3C6B8BULL,
		0x60EDFE776E442D57ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7DE71A2B215AD14DULL,
		0xC5E802D624DE9E3EULL,
		0x8BEDB8C6CE05D5D4ULL,
		0xB02CC009469660A5ULL,
		0xD4F1B782F004456AULL,
		0x58BE680500A4EBA3ULL,
		0xF7FFB44D04E2B73BULL,
		0xD00E1E0529D5CE9EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x09C512292058D10DULL,
		0xC1C000D2004E1A18ULL,
		0x09048002C4059104ULL,
		0x1000000946902080ULL,
		0xD48037802004410AULL,
		0x583E000100204B23ULL,
		0x4377B4440420230BULL,
		0x400C1E0528440C16ULL
	}};
	printf("Test Case 25\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 25 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -25;
	} else {
		printf("Test Case 25 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA073DC81BC88C36DULL,
		0xFA5BC217EE9DC923ULL,
		0xECC82F29EEE34A9FULL,
		0xB070DE047DC511ABULL,
		0xC812764B2259066EULL,
		0x51838E6A0806F813ULL,
		0x3F26671D42341329ULL,
		0x3ED5A7F3A2064E57ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBBD8D982A7CFFF05ULL,
		0xE43C9729B1BB2092ULL,
		0xDAB446EBEC2A122BULL,
		0x277258B5933C40FFULL,
		0x74D0E5AE61D841E8ULL,
		0xB0B478F9FF9D8A14ULL,
		0xF7B00919B2188CBBULL,
		0x2C9C6DBA7571F449ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA050D880A488C305ULL,
		0xE0188201A0990002ULL,
		0xC8800629EC22020BULL,
		0x20705804110400ABULL,
		0x4010640A20580068ULL,
		0x1080086808048810ULL,
		0x3720011902100029ULL,
		0x2C9425B220004441ULL
	}};
	printf("Test Case 26\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 26 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -26;
	} else {
		printf("Test Case 26 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4E91E3802AB73DF3ULL,
		0x7F711CAC5AE8EDD9ULL,
		0x5E9C07BA29359631ULL,
		0x043E41098C60AA83ULL,
		0xC8071FA90904443AULL,
		0xA9F91AC8ED1A6E01ULL,
		0x4F6F34895434593DULL,
		0x62D3EEEE7E6AAA44ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0A6534C2B65F648DULL,
		0x77C25EA029BA70F5ULL,
		0x448E23445D5D1A06ULL,
		0xE38CA9B5FC50AF69ULL,
		0x16463EF1E631342EULL,
		0x0C1835C8FB63FB93ULL,
		0xF69215BD365CC54EULL,
		0x8587A1C540F93C0BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0A01208022172481ULL,
		0x77401CA008A860D1ULL,
		0x448C030009151200ULL,
		0x000C01018C40AA01ULL,
		0x00061EA10000042AULL,
		0x081810C8E9026A01ULL,
		0x460214891414410CULL,
		0x0083A0C440682800ULL
	}};
	printf("Test Case 27\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 27 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -27;
	} else {
		printf("Test Case 27 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xABF849F19CB63349ULL,
		0x032941190EB128F7ULL,
		0x6FC4FD9EB667FC6EULL,
		0x0900FE514394C669ULL,
		0x1A2380BDD666E038ULL,
		0x5F3C3E15DB4F701DULL,
		0x058EF80FD5483242ULL,
		0x4C31E118D5001F57ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x38EE435BA74EFD41ULL,
		0x5EF1FB24A47BA10DULL,
		0xAC5F12F1A7BC1FEDULL,
		0xA365D4C4281FED8DULL,
		0xD66F415582BB59F1ULL,
		0x3F5B1A6F87DD994FULL,
		0x83C50D8AA50ECD31ULL,
		0xEFBA308376E87222ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x28E8415184063141ULL,
		0x0221410004312005ULL,
		0x2C441090A6241C6CULL,
		0x0100D4400014C409ULL,
		0x1223001582224030ULL,
		0x1F181A05834D100DULL,
		0x0184080A85080000ULL,
		0x4C30200054001202ULL
	}};
	printf("Test Case 28\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 28 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -28;
	} else {
		printf("Test Case 28 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2E38406E2A3707ACULL,
		0xA31D3DE3A93D5749ULL,
		0x819E97D01E890776ULL,
		0x546E902BAFA04D49ULL,
		0x2003C97F1852D8C4ULL,
		0xB507416D710054F9ULL,
		0x3D58F061D1EDF168ULL,
		0x85443D16068C8734ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB54BBB6EAB713AECULL,
		0xC3331A67A078C6EDULL,
		0x5E7A346B89879E6EULL,
		0xA80ADA2AA5196BF2ULL,
		0x60332DFAE01C8AF0ULL,
		0xA7E61FC76061F0B4ULL,
		0x69EBE140E70742B9ULL,
		0x1186CC75712AB88DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2408006E2A3102ACULL,
		0x83111863A0384649ULL,
		0x001A144008810666ULL,
		0x000A902AA5004940ULL,
		0x2003097A001088C0ULL,
		0xA5060145600050B0ULL,
		0x2948E040C1054028ULL,
		0x01040C1400088004ULL
	}};
	printf("Test Case 29\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 29 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -29;
	} else {
		printf("Test Case 29 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8257DDF22626FA7FULL,
		0xB817EF06061A3555ULL,
		0x8C56C41BE11164A0ULL,
		0x5B5D7381C1BAC10BULL,
		0xC28D1DC082BB70CCULL,
		0x9953EC93D0D1DF97ULL,
		0x348F1318DFF9D9AAULL,
		0x454A4EA111B35940ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2914C1410E74B921ULL,
		0x6B48AC6FFED52312ULL,
		0x05C4A9CBB7F951CCULL,
		0x7F4EE43BCD423957ULL,
		0x38A76F0F6611B149ULL,
		0xE815F7A953C66768ULL,
		0x118A46795876F215ULL,
		0x736A9A550A9E6171ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0014C1400624B821ULL,
		0x2800AC0606102110ULL,
		0x0444800BA1114080ULL,
		0x5B4C6001C1020103ULL,
		0x00850D0002113048ULL,
		0x8811E48150C04700ULL,
		0x108A02185870D000ULL,
		0x414A0A0100924140ULL
	}};
	printf("Test Case 30\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 30 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -30;
	} else {
		printf("Test Case 30 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x954FF6A087F9F2C6ULL,
		0xAEC01D9EE4AC37B6ULL,
		0x11FE31D4263864EDULL,
		0x6EA2EC2D59B0AB03ULL,
		0xBD7AEF8CFD813170ULL,
		0xBA642B68D52A609BULL,
		0x6A9C145CFD9F76F4ULL,
		0x0D8FA39A7C0B4CF5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x65A91A71CA9E2BF0ULL,
		0x71CB0A8EAF795D2CULL,
		0xB98D1F56E193FC8DULL,
		0x6A6CFCE5CEA71A37ULL,
		0x7F79D43BE4A7922DULL,
		0xE170D40227690FC6ULL,
		0x8A1A798827B1B693ULL,
		0x77B1B6751049D92EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x05091220829822C0ULL,
		0x20C0088EA4281524ULL,
		0x118C11542010648DULL,
		0x6A20EC2548A00A03ULL,
		0x3D78C408E4811020ULL,
		0xA060000005280082ULL,
		0x0A18100825913690ULL,
		0x0581A21010094824ULL
	}};
	printf("Test Case 31\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 31 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -31;
	} else {
		printf("Test Case 31 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC4A81324F10E67DDULL,
		0x7988911DB8811B54ULL,
		0x91E1DB6F0B3D3806ULL,
		0x55EEB4F7169F280FULL,
		0x0F8AB0344B41204EULL,
		0x16140AD7CA45B863ULL,
		0x62B027425741146EULL,
		0xE4C964E2376C6C35ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC0F44ABB59C82E91ULL,
		0x9A1FDBC93E297DCFULL,
		0xCB14C43E32924F6FULL,
		0xE10D1D773D37642EULL,
		0x557227D664823173ULL,
		0x13E926A421AE6950ULL,
		0xAD91C94AD15745E6ULL,
		0xB4F164A9DF190838ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC0A0022051082691ULL,
		0x1808910938011944ULL,
		0x8100C02E02100806ULL,
		0x410C14771417200EULL,
		0x0502201440002042ULL,
		0x1200028400042840ULL,
		0x2090014251410466ULL,
		0xA4C164A017080830ULL
	}};
	printf("Test Case 32\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 32 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -32;
	} else {
		printf("Test Case 32 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2AD2D3BD87010142ULL,
		0x29639FC529622420ULL,
		0x3DF7CFE7665D245EULL,
		0x789AF85FB5381537ULL,
		0x6329AFAB7B661B17ULL,
		0x373E41379C239FC8ULL,
		0xFE03817BADD69856ULL,
		0x2A0778A982064A62ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8A396A57E714DE42ULL,
		0x1592FDD96D541611ULL,
		0x163918A0C8673816ULL,
		0x0B3A9D6B4B64AA40ULL,
		0x2CC9F545CB27FD4CULL,
		0x79A89D80731F46F6ULL,
		0xCF23ABECE12602A9ULL,
		0x12D2A3821D238168ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0A10421587000042ULL,
		0x01029DC129400400ULL,
		0x143108A040452016ULL,
		0x081A984B01200000ULL,
		0x2009A5014B261904ULL,
		0x31280100100306C0ULL,
		0xCE038168A1060000ULL,
		0x0202208000020060ULL
	}};
	printf("Test Case 33\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 33 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -33;
	} else {
		printf("Test Case 33 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5E50E8861F96AA4FULL,
		0x3283F48C847D267EULL,
		0xCBBD84893D9CA99DULL,
		0x501D4FBC53761B8EULL,
		0x081DDC52CE770BA8ULL,
		0xFD4594DD79B2E7BFULL,
		0xDF8A47605B32AC13ULL,
		0x19306AAE0A3E3469ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x91B11550B22E5F92ULL,
		0x6FB88562633F9B75ULL,
		0xFDCAE37510C685D9ULL,
		0x73236678B71DFDFEULL,
		0x2A85C547E59505A8ULL,
		0x517FBDCD5CED5D57ULL,
		0x0D1B8A354553056BULL,
		0x02412BB9DCBB27F3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1010000012060A02ULL,
		0x22808400003D0274ULL,
		0xC988800110848199ULL,
		0x500146381314198EULL,
		0x0805C442C41501A8ULL,
		0x514594CD58A04517ULL,
		0x0D0A022041120403ULL,
		0x00002AA8083A2461ULL
	}};
	printf("Test Case 34\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 34 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -34;
	} else {
		printf("Test Case 34 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDE47D468385AA0A3ULL,
		0x7B3A7ED5517B4D40ULL,
		0x431852A5FA34C808ULL,
		0x07F01EC37D652537ULL,
		0x9461E10C297D6E6EULL,
		0x88F509B812365758ULL,
		0x562E68FE12B3AC11ULL,
		0x8666DDD3D315EA36ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9F122C6AEE1CB24AULL,
		0x471846ABC09AB188ULL,
		0xEA27B1B8D30AEAB4ULL,
		0x8A99B3AF60DC72C4ULL,
		0xDFF1212AEF8E382DULL,
		0x836474DC750F30C6ULL,
		0x250955316532CA81ULL,
		0x535D8A77FE2F6069ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9E0204682818A002ULL,
		0x43184681401A0100ULL,
		0x420010A0D200C800ULL,
		0x0290128360442004ULL,
		0x94612108290C282CULL,
		0x8064009810061040ULL,
		0x0408403000328801ULL,
		0x02448853D2056020ULL
	}};
	printf("Test Case 35\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 35 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -35;
	} else {
		printf("Test Case 35 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF69BA424B3CF4A46ULL,
		0x57F897223484B92BULL,
		0x8761A5965F855E48ULL,
		0x3807EC72D2F74EA7ULL,
		0xD703EC9F95279D3BULL,
		0x43D6895B9A146814ULL,
		0x1B05A8724ECA9F81ULL,
		0xBD07205A06432F4BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x596AA6A58991CAA6ULL,
		0x519E6F0EB2F14680ULL,
		0x9F29159B261898C4ULL,
		0xCF3293967A6CF282ULL,
		0xCB22B6418739932DULL,
		0x94A02102D66F5D36ULL,
		0x378F4F48D103D34AULL,
		0x76F313235166E804ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x500AA42481814A06ULL,
		0x5198070230800000ULL,
		0x8721059206001840ULL,
		0x0802801252644282ULL,
		0xC302A40185219129ULL,
		0x0080010292044814ULL,
		0x1305084040029300ULL,
		0x3403000200422800ULL
	}};
	printf("Test Case 36\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 36 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -36;
	} else {
		printf("Test Case 36 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC62BB46E1532528CULL,
		0x1FC849B5E12BFD87ULL,
		0x8055CC97F552F5F7ULL,
		0xE2A077CA9278BF2BULL,
		0x278C4F8601716813ULL,
		0x546D229902F6971CULL,
		0x6A9C95E397BB22EAULL,
		0x83F94B0B030E9364ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBE9FCF14EAC26E35ULL,
		0xBCB23920F1E96DD2ULL,
		0xB6BD8AA376FAD878ULL,
		0x87ACBEB73110F268ULL,
		0x7D5CF848706BC4E9ULL,
		0x4C51D8665E4344C9ULL,
		0xA2952EE63D915FFAULL,
		0xF079C7E2B36622E4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x860B840400024204ULL,
		0x1C800920E1296D82ULL,
		0x801588837452D070ULL,
		0x82A036821010B228ULL,
		0x250C480000614001ULL,
		0x4441000002420408ULL,
		0x229404E2159102EAULL,
		0x8079430203060264ULL
	}};
	printf("Test Case 37\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 37 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -37;
	} else {
		printf("Test Case 37 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0D07E888B3675D70ULL,
		0x281CB6A42B661139ULL,
		0x74104A4613D91C16ULL,
		0xB84FBE22458102C1ULL,
		0xC75ED2D7FF3E738AULL,
		0x43B71E0D2F8387F8ULL,
		0xCF7B7FCAD17F12BFULL,
		0x00297FDCEFB06140ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x48A3039A6640BAD3ULL,
		0xD59654AC0AB9D5AAULL,
		0xD182866BAE62BF57ULL,
		0x17520F6732541E16ULL,
		0x306A47C3BA16AFDAULL,
		0xBD00F9EB736844B2ULL,
		0x2388F1C2A3757F52ULL,
		0xE5BB0F8B33795ABAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0803008822401850ULL,
		0x001414A40A201128ULL,
		0x5000024202401C16ULL,
		0x10420E2200000200ULL,
		0x004A42C3BA16238AULL,
		0x01001809230004B0ULL,
		0x030871C281751212ULL,
		0x00290F8823304000ULL
	}};
	printf("Test Case 38\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 38 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -38;
	} else {
		printf("Test Case 38 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA56BE4A47FDA3936ULL,
		0x483805D80C127E17ULL,
		0x65BB1EEA0D67B6F8ULL,
		0x162715CDD395E617ULL,
		0xA5F0CC0B82136F48ULL,
		0x03EBEAE8296E571FULL,
		0x60F44AEB5B112AA4ULL,
		0x0C0A4D36FEC44669ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0ED03ACB87589B41ULL,
		0x58811FC18757D1A8ULL,
		0x31BCF235C1DB6B5DULL,
		0x3D8CD793C374CDACULL,
		0x1F9779C7E4C0F98EULL,
		0xE03BAA3C440D9238ULL,
		0xE51D95E019F76B3CULL,
		0xF50146FE98F37E6BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0440208007581900ULL,
		0x480005C004125000ULL,
		0x21B8122001432258ULL,
		0x14041581C314C404ULL,
		0x0590480380006908ULL,
		0x002BAA28000C1218ULL,
		0x601400E019112A24ULL,
		0x0400443698C04669ULL
	}};
	printf("Test Case 39\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 39 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -39;
	} else {
		printf("Test Case 39 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x82E4A683AFA2ECD8ULL,
		0x45F2B5BDACA74FE8ULL,
		0xA120E63A67C0D118ULL,
		0x5AB79653E0E9A70BULL,
		0x39102CD55D38E7C4ULL,
		0x3346482C2DE59097ULL,
		0x6145D4AA378196FDULL,
		0x096F50C8A60A0FE0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x08A8D052A18CA959ULL,
		0x5A6F9E896976F7DEULL,
		0x6F7A1FB72BBCCD7DULL,
		0x84389ECD6648271EULL,
		0x06CEDC121F9270C6ULL,
		0x2079A48919B977D0ULL,
		0x82AADCA53DE0BA59ULL,
		0x8C16C95EB74738D2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x00A08002A180A858ULL,
		0x40629489282647C8ULL,
		0x212006322380C118ULL,
		0x003096416048270AULL,
		0x00000C101D1060C4ULL,
		0x2040000809A11090ULL,
		0x0000D4A035809259ULL,
		0x08064048A60208C0ULL
	}};
	printf("Test Case 40\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 40 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -40;
	} else {
		printf("Test Case 40 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x78D69FA5CFC4E239ULL,
		0xE3D626B1B4C16E6BULL,
		0x90B831F7A0EC9479ULL,
		0x69A552CAB5DEE263ULL,
		0x91B435BD1A148431ULL,
		0x310DD244B163CF2AULL,
		0x7281E7600577C84FULL,
		0x14E418B8154E6DC8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xADC69E21ECC65DB1ULL,
		0x2E4B0C0E750A9CF0ULL,
		0xB077B83BF52C697EULL,
		0x315EF53B2F292C3DULL,
		0xC059E6DF74D6F575ULL,
		0xEF4854B1EAC3149DULL,
		0xEF6883D76D88811AULL,
		0x990FEE66BB7F5953ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x28C69E21CCC44031ULL,
		0x2242040034000C60ULL,
		0x90303033A02C0078ULL,
		0x2104500A25082021ULL,
		0x8010249D10148431ULL,
		0x21085000A0430408ULL,
		0x620083400500800AULL,
		0x10040820114E4940ULL
	}};
	printf("Test Case 41\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 41 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -41;
	} else {
		printf("Test Case 41 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x66ACACA656F46A5AULL,
		0xAA0FADE42A4063F1ULL,
		0xD1B36E5A47773897ULL,
		0xD7422D00DA2FFB59ULL,
		0x75BE7B0CF89AFB3BULL,
		0x1FCD3C44F2711016ULL,
		0xF3A7E74B15389E92ULL,
		0x1DCE3E24419FB75BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x13630F52D16B361EULL,
		0xA3ED64D6A7816616ULL,
		0xB111500D652BA01EULL,
		0x1F2079064C1F37E1ULL,
		0xF40B332A9731055CULL,
		0xEC65C3B32ED9E9C2ULL,
		0xBF13683C0F92B242ULL,
		0x4513DAA1AFBDBBFDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x02200C025060221AULL,
		0xA20D24C422006210ULL,
		0x9111400845232016ULL,
		0x17002900480F3341ULL,
		0x740A330890100118ULL,
		0x0C45000022510002ULL,
		0xB303600805109202ULL,
		0x05021A20019DB359ULL
	}};
	printf("Test Case 42\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 42 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -42;
	} else {
		printf("Test Case 42 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6FACA85211B29CE8ULL,
		0x6E96912E2CBF9F17ULL,
		0xEF8E31BE522197E4ULL,
		0x355651452D046C90ULL,
		0xC071C35802ACB069ULL,
		0x7C95E0AB24E724D3ULL,
		0xF2ACAE4916AE0489ULL,
		0x1090C201047EA103ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB64539283AB7DA71ULL,
		0xF98333631A7F0CB9ULL,
		0x8A26C50C60B34B82ULL,
		0x8519C6EB728195D7ULL,
		0x736274C3ECEA9B00ULL,
		0x3081FE5F4458C6DEULL,
		0xEDDE521B4CE0040EULL,
		0x2D412AA701DD53AAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2604280010B29860ULL,
		0x68821122083F0C11ULL,
		0x8A06010C40210380ULL,
		0x0510404120000490ULL,
		0x4060404000A89000ULL,
		0x3081E00B044004D2ULL,
		0xE08C020904A00408ULL,
		0x00000201005C0102ULL
	}};
	printf("Test Case 43\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 43 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -43;
	} else {
		printf("Test Case 43 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x02F96E841B501EFCULL,
		0xF6AD40C5E7DF10FCULL,
		0xF041699CE9B0752DULL,
		0x2C17EB0D774DDDF8ULL,
		0x298ABF822AEA8B2EULL,
		0x5418BD7FD942F59AULL,
		0xB5E2882786FA150DULL,
		0x64B3362177D34ED6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE9CB2E50DB733676ULL,
		0x8B1493A9827B0F6AULL,
		0xC4813A77E976795CULL,
		0x3BC0165C9213958EULL,
		0x0A31663B7D847885ULL,
		0xF1F90CC6CA9303FFULL,
		0xAE10523E08F8AAFCULL,
		0x354580CBC481CD3DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x00C92E001B501674ULL,
		0x82040081825B0068ULL,
		0xC0012814E930710CULL,
		0x2800020C12019588ULL,
		0x0800260228800804ULL,
		0x50180C46C802019AULL,
		0xA400002600F8000CULL,
		0x2401000144814C14ULL
	}};
	printf("Test Case 44\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 44 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -44;
	} else {
		printf("Test Case 44 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD5B110951D3D026CULL,
		0xB9DF4CFD7DB49447ULL,
		0x73B57F8DA759F708ULL,
		0x5E914B3114E71A52ULL,
		0x68911CC0DF358C50ULL,
		0xE7B70E6931557EB8ULL,
		0x1BAEA50F64E08728ULL,
		0xDD5056539FECE8D1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6F604C7FF8485841ULL,
		0xF9F04C6CE096B9F3ULL,
		0x41BAA1CEE99B0519ULL,
		0x0FEFF9017E0DD60FULL,
		0x1436BB4E96D55110ULL,
		0x52AA286E03E61286ULL,
		0xDB19BD0CA95E60E4ULL,
		0xED57BA21F2012F88ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4520001518080040ULL,
		0xB9D04C6C60949043ULL,
		0x41B0218CA1190508ULL,
		0x0E81490114051202ULL,
		0x0010184096150010ULL,
		0x42A2086801441280ULL,
		0x1B08A50C20400020ULL,
		0xCD50120192002880ULL
	}};
	printf("Test Case 45\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 45 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -45;
	} else {
		printf("Test Case 45 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF11BD15C64CE13E0ULL,
		0xA05D72076559A469ULL,
		0x1A9045AF9B68C287ULL,
		0x717B35F976015AA2ULL,
		0x9D1F738CB90AA442ULL,
		0x6AB5FD76BDC7F516ULL,
		0x466E085C0C0DE14EULL,
		0x2E87F9EE5990CA78ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8E458A711B85A525ULL,
		0x6272A47C71215A8DULL,
		0xE321C8B89D1CE63FULL,
		0xA78AB87D0D472B33ULL,
		0xF7A74EB26E0D1B0DULL,
		0xA45B16F9E50D5468ULL,
		0x58E5BA6D377B619CULL,
		0x230E858FEA31925AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8001805000840120ULL,
		0x2050200461010009ULL,
		0x020040A89908C207ULL,
		0x210A307904010A22ULL,
		0x9507428028080000ULL,
		0x20111470A5055400ULL,
		0x4064084C0409610CULL,
		0x2206818E48108258ULL
	}};
	printf("Test Case 46\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 46 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -46;
	} else {
		printf("Test Case 46 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFC4F8B80F47B3E54ULL,
		0xC385D0705AE3CDE7ULL,
		0x49B203D35DE564F9ULL,
		0x67A23F515B59AF3CULL,
		0x34B8007A9E89AC60ULL,
		0xDF00B766B3555385ULL,
		0xAC11DEF908C710ECULL,
		0xF45BB5399C8B5FC4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x430CD7CC1BF89A42ULL,
		0xBBFDCFB7E08F9E99ULL,
		0x742A6F86BD2BB7C5ULL,
		0x0F8033AB87C1F3AAULL,
		0x110EA828D8490968ULL,
		0x3BA5EB0A1ED0D81AULL,
		0xFC6E7E6E8D250E17ULL,
		0xFD83C488DA546608ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x400C838010781A40ULL,
		0x8385C03040838C81ULL,
		0x402203821D2124C1ULL,
		0x078033010341A328ULL,
		0x1008002898090860ULL,
		0x1B00A30212505000ULL,
		0xAC005E6808050004ULL,
		0xF403840898004600ULL
	}};
	printf("Test Case 47\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 47 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -47;
	} else {
		printf("Test Case 47 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCA1B1205F24FBE2CULL,
		0x9552EF1D47F7FCA3ULL,
		0x30990971B29D9D0DULL,
		0x537E61F281D43036ULL,
		0x81B1CA6DEB66A4E7ULL,
		0x5F6FFBD62D3B5038ULL,
		0x0CAE66DC5B9F3803ULL,
		0xB2F60B7FEA439861ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC3147214CCB7951DULL,
		0x452017EBE26BE689ULL,
		0x2CE2B19A14CCA678ULL,
		0x5A1CCC938D4FFF1EULL,
		0xAD08F1E0270CD5D3ULL,
		0xFD4451584AD18187ULL,
		0x3CC867944D0D0298ULL,
		0x10A3CF010D268680ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC2101204C007940CULL,
		0x050007094263E481ULL,
		0x20800110108C8408ULL,
		0x521C409281443016ULL,
		0x8100C060230484C3ULL,
		0x5D44515008110000ULL,
		0x0C886694490D0000ULL,
		0x10A20B0108028000ULL
	}};
	printf("Test Case 48\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 48 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -48;
	} else {
		printf("Test Case 48 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3C1D13329AF78DE7ULL,
		0xD9CCB6531CE387C1ULL,
		0x407E206D51AB3894ULL,
		0xE63C547E65BAEE1DULL,
		0x8E8BE66FA9C04274ULL,
		0x0210F16C20E3D33EULL,
		0x5C257820E9BDED11ULL,
		0x1F714D32BB2EA13FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD4769C882CF882A6ULL,
		0xE8C8AF044EB27FF3ULL,
		0x4F6288954326FC0DULL,
		0x7AA6174C95815B2FULL,
		0x1F259E3EB005BE39ULL,
		0x7DFADDC40E5289F9ULL,
		0x680CCAA8EB9A9713ULL,
		0xBD283BFBF73EB65CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1414100008F080A6ULL,
		0xC8C8A6000CA207C1ULL,
		0x4062000541223804ULL,
		0x6224144C05804A0DULL,
		0x0E01862EA0000230ULL,
		0x0010D14400428138ULL,
		0x48044820E9988511ULL,
		0x1D200932B32EA01CULL
	}};
	printf("Test Case 49\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 49 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -49;
	} else {
		printf("Test Case 49 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x14B412ACE1358E7EULL,
		0x07102BD9432D5879ULL,
		0xA55A4CE4DE87298CULL,
		0x8BBDB1ECD82C6C3DULL,
		0x82CCEFA7880CD14DULL,
		0x98B831A1265FDA51ULL,
		0x3ED2B37CE7E71A39ULL,
		0x0EF1724BFC7E575FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9998513DFF40CD42ULL,
		0x58E98C97242E08F0ULL,
		0x12DC29E66EC58854ULL,
		0x27EA0C15E0430F91ULL,
		0x32A0FB770857B179ULL,
		0x884CB7690B986EBAULL,
		0x52A0375BA3D58E1AULL,
		0x83784E83E4C20773ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1090102CE1008C42ULL,
		0x00000891002C0870ULL,
		0x005808E44E850804ULL,
		0x03A80004C0000C11ULL,
		0x0280EB2708049149ULL,
		0x8808312102184A10ULL,
		0x12803358A3C50A18ULL,
		0x02704203E4420753ULL
	}};
	printf("Test Case 50\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 50 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -50;
	} else {
		printf("Test Case 50 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0605D5A500C9595AULL,
		0x2001EA1CDC19A08FULL,
		0x3B73D6980DB54DC4ULL,
		0x49D71CFFBB71E844ULL,
		0x4B6B81B6F6E6D487ULL,
		0x9B45053A1AD88511ULL,
		0xB5514D0062C3141EULL,
		0xDD9A4B9A6F51F768ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4D9E87FF5CFFA2E7ULL,
		0xB1507493360018F2ULL,
		0x3086DD0136C35690ULL,
		0xC1A3CFA68F72A376ULL,
		0x81F8BDC48F0ED1B6ULL,
		0x7351966FA41BB7CAULL,
		0xE54C417FCB1A3006ULL,
		0x277EA5ACC62C0E92ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x040485A500C90042ULL,
		0x2000601014000082ULL,
		0x3002D40004814480ULL,
		0x41830CA68B70A044ULL,
		0x016881848606D086ULL,
		0x1341042A00188500ULL,
		0xA540410042021006ULL,
		0x051A018846000600ULL
	}};
	printf("Test Case 51\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 51 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -51;
	} else {
		printf("Test Case 51 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x350BAC74AA969A95ULL,
		0x2D847F67F32ECB3FULL,
		0xD1ED7220F26F7EDFULL,
		0x12CEFA84E6548485ULL,
		0x0063966792F47E18ULL,
		0xF6F5A770F8BF335CULL,
		0xAAA6BA3BA528D739ULL,
		0x018FFBFB4EF8C5B0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDFD3F3E292F25ED5ULL,
		0xAE44836692FB1F7EULL,
		0xBA1C8F2DE35FABBDULL,
		0xF8D1722C2C86E304ULL,
		0xE3861D0DA881ED39ULL,
		0x3DC64A85DFDED771ULL,
		0xFE80D527036EA86CULL,
		0x778565515B319B1CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1503A06082921A95ULL,
		0x2C040366922A0B3EULL,
		0x900C0220E24F2A9DULL,
		0x10C0720424048004ULL,
		0x0002140580806C18ULL,
		0x34C40200D89E1350ULL,
		0xAA80902301288028ULL,
		0x018561514A308110ULL
	}};
	printf("Test Case 52\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 52 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -52;
	} else {
		printf("Test Case 52 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFCA87B80E8A4D486ULL,
		0xAFB950B3139E21C4ULL,
		0xCDEDD648A6DBD6F2ULL,
		0x20FF9FA928DC83FCULL,
		0x5F00D1BAB3047878ULL,
		0x1D23A8388E68E601ULL,
		0xB1FE3D0885B265FCULL,
		0xF814E21DA5AE05E2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE6BE1E43443033C2ULL,
		0x2988131255EAC76AULL,
		0x5CDBF7D368FA716DULL,
		0x9A2F83E09595ADD1ULL,
		0x2ADFDFB5B900045AULL,
		0x69C487198AACD2BBULL,
		0x497C88CE2A15B456ULL,
		0xAA77CE5A6FA92AF4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE4A81A0040201082ULL,
		0x29881012118A0140ULL,
		0x4CC9D64020DA5060ULL,
		0x002F83A0009481D0ULL,
		0x0A00D1B0B1000058ULL,
		0x090080188A28C201ULL,
		0x017C080800102454ULL,
		0xA814C21825A800E0ULL
	}};
	printf("Test Case 53\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 53 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -53;
	} else {
		printf("Test Case 53 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x53EDC439FB384704ULL,
		0x12883F1C80C9C338ULL,
		0x6FD6D1BFF9D6106CULL,
		0xC293194BF1B24DA5ULL,
		0xF83C3BD3B6BBA262ULL,
		0x2FFD27E2195445ECULL,
		0x82A5C2D7D9CB835FULL,
		0x9F6D6F1CDEAD9F90ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD6E1A4514D319E44ULL,
		0xA9F3CCC22E9D420CULL,
		0x0B7620D0445F1AA0ULL,
		0x22910E73F4CD6B6DULL,
		0x676FB72BC6B07163ULL,
		0xF7000EEDA7D9CD3FULL,
		0x879BD8B84A9EFD36ULL,
		0x7FBFF25EBB6CA59DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x52E1841149300604ULL,
		0x00800C0000894208ULL,
		0x0B56009040561020ULL,
		0x02910843F0804925ULL,
		0x602C330386B02062ULL,
		0x270006E00150452CULL,
		0x8281C090488A8116ULL,
		0x1F2D621C9A2C8590ULL
	}};
	printf("Test Case 54\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 54 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -54;
	} else {
		printf("Test Case 54 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x715FB0D4411C3D65ULL,
		0x78AA3B67DF994BB1ULL,
		0x65EFDD9CDFB6BEB6ULL,
		0xC53425C9CBB18528ULL,
		0xFB672C5197149E79ULL,
		0xB6668B01D5C54B1EULL,
		0xFCCEB3344E736B64ULL,
		0xA75A6C61CA4CEC87ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3E61F7EC4239D938ULL,
		0xBED8B05B941776A9ULL,
		0x82CE472DE7527DEBULL,
		0x622EAE3076500387ULL,
		0x38EC2437FB8C1D2EULL,
		0x290869C224BB2324ULL,
		0xCB1E22594253C4E6ULL,
		0x488FC719C011BD40ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3041B0C440181920ULL,
		0x38883043941142A1ULL,
		0x00CE450CC7123CA2ULL,
		0x4024240042100100ULL,
		0x3864241193041C28ULL,
		0x2000090004810304ULL,
		0xC80E221042534064ULL,
		0x000A4401C000AC00ULL
	}};
	printf("Test Case 55\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 55 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -55;
	} else {
		printf("Test Case 55 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1C493AC5AB27D299ULL,
		0x6593AA1F8BEEAC26ULL,
		0xD66C32670F0267D4ULL,
		0xC077DD52F9B1FAE1ULL,
		0xD73E7FAAF0674E6FULL,
		0xB8B9F52F6F247CADULL,
		0x736059F995B44935ULL,
		0x331B55113F867C86ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6422255AB93E2FDDULL,
		0xC183D56925418014ULL,
		0x66817565B68987BFULL,
		0x794AA2385C55285BULL,
		0x8BE58A6F7F324BBAULL,
		0xD95966ECB9E8DCDEULL,
		0xB814A47B7EDF45ABULL,
		0x72DD4F090F3129CCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x04002040A9260299ULL,
		0x4183800901408004ULL,
		0x4600306506000794ULL,
		0x4042801058112841ULL,
		0x83240A2A70224A2AULL,
		0x9819642C29205C8CULL,
		0x3000007914944121ULL,
		0x321945010F002884ULL
	}};
	printf("Test Case 56\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 56 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -56;
	} else {
		printf("Test Case 56 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF8EA757D789F3215ULL,
		0xE0899D7264F80789ULL,
		0xBD01C4ADE5C3BC77ULL,
		0x3B64E04D157EE0A5ULL,
		0xDE89B078B7915E19ULL,
		0xAD3E808784EB0B00ULL,
		0x94EC09EA6441B0ACULL,
		0x7C7B1903EE1479BDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3FE0C701275CC5F2ULL,
		0xC709A2693E2AFDA5ULL,
		0x32CECCD81DC80B08ULL,
		0x0FD18773D17A4AABULL,
		0xCFBB132AE45CF08FULL,
		0x6158004A9C8B9DBDULL,
		0x7C6B7710148A51F7ULL,
		0x608D9FADEF3F64DEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x38E04501201C0010ULL,
		0xC009806024280581ULL,
		0x3000C48805C00800ULL,
		0x0B408041117A40A1ULL,
		0xCE891028A4105009ULL,
		0x21180002848B0900ULL,
		0x14680100040010A4ULL,
		0x60091901EE14609CULL
	}};
	printf("Test Case 57\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 57 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -57;
	} else {
		printf("Test Case 57 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x15A791A83A9A1C45ULL,
		0xA2AEFF2D490B1CBBULL,
		0xBCCC64721FA37F40ULL,
		0x04DCAFB86E4EF016ULL,
		0x08DFF09BDFF89E16ULL,
		0xABBAFC9E9207499EULL,
		0x77EAF9265B026475ULL,
		0xDB9E19297F31BE15ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1096B2D0E7B4178FULL,
		0xCD5BC157796CC985ULL,
		0x6A110F463365AFCAULL,
		0x1F698A1C75CADC97ULL,
		0x7356E3DD4613CFDFULL,
		0x191BA74ACDA03D2FULL,
		0xD0C8375B28E78B68ULL,
		0x87F17BB75C5462FDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1086908022901405ULL,
		0x800AC10549080881ULL,
		0x2800044213212F40ULL,
		0x04488A18644AD016ULL,
		0x0056E09946108E16ULL,
		0x091AA40A8000090EULL,
		0x50C8310208020060ULL,
		0x839019215C102215ULL
	}};
	printf("Test Case 58\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 58 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -58;
	} else {
		printf("Test Case 58 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x432AEAAD2EE4C7A3ULL,
		0xD22E94A7CA8B9728ULL,
		0x0A2D22CE04341EDFULL,
		0x11420BCB3B4C2AADULL,
		0x5CB1D228FC6B1B99ULL,
		0x041A480AE6370223ULL,
		0x43965134D439A9ABULL,
		0x4245C17A26124316ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1D1B736841271A0FULL,
		0xC58FC23799614AA9ULL,
		0xE92E771AECA251CEULL,
		0x7A1C0061E15DB816ULL,
		0x29B08377F8B08A8EULL,
		0x977E4A080758A7B9ULL,
		0x4C1BF8310E72DCCDULL,
		0x35CCA9D9501A2932ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x010A622800240203ULL,
		0xC00E802788010228ULL,
		0x082C220A042010CEULL,
		0x10000041214C2804ULL,
		0x08B08220F8200A88ULL,
		0x041A480806100221ULL,
		0x4012503004308889ULL,
		0x0044815800120112ULL
	}};
	printf("Test Case 59\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 59 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -59;
	} else {
		printf("Test Case 59 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1358BF07E3E8A741ULL,
		0x22A934050A54BAACULL,
		0x5616DBA956856B7FULL,
		0x11C28825E27899ABULL,
		0x77FA94233818CDA5ULL,
		0x15C463183D844B7CULL,
		0x2213275E06BE9812ULL,
		0x5C584B628CCECDAEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x948ADCC62A093F3DULL,
		0x842C4D64937CE6E5ULL,
		0xAFB2DB7615C67C31ULL,
		0x8E72F1DCE1B758C5ULL,
		0x9347D41593A26DACULL,
		0x5D459D4296C24E18ULL,
		0x19F5C6E0B49D75C5ULL,
		0x01D6ADE6C194E38DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x10089C0622082701ULL,
		0x002804040254A2A4ULL,
		0x0612DB2014846831ULL,
		0x00428004E0301881ULL,
		0x1342940110004DA4ULL,
		0x1544010014804A18ULL,
		0x00110640049C1000ULL,
		0x005009628084C18CULL
	}};
	printf("Test Case 60\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 60 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -60;
	} else {
		printf("Test Case 60 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5967DE57D0A47559ULL,
		0x2E34A054DCE73530ULL,
		0x6130357D24A8CF32ULL,
		0x03074AF82994146DULL,
		0x24DF13E1287DEE38ULL,
		0x36C606086EEAA86DULL,
		0x384A976D2D2CA698ULL,
		0x02C2D3AE73D1FDBBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD6180404E3553424ULL,
		0x5F405EFD1D0420BCULL,
		0xEF44E0131370E0E7ULL,
		0x7720C4F8357306C3ULL,
		0x3F103A169AF6DA08ULL,
		0x723364AD4118C68AULL,
		0x29BB70397A7E353EULL,
		0x82358A7775AF9264ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x50000404C0043400ULL,
		0x0E0000541C042030ULL,
		0x610020110020C022ULL,
		0x030040F821100441ULL,
		0x241012000874CA08ULL,
		0x3202040840088008ULL,
		0x280A1029282C2418ULL,
		0x0200822671819020ULL
	}};
	printf("Test Case 61\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 61 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -61;
	} else {
		printf("Test Case 61 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x41C3414D104FCD41ULL,
		0xEEB14A6D11D5B3DBULL,
		0x92F82653BFD50D12ULL,
		0xB085C47BB55106FEULL,
		0x607F96A8A1F7B6C7ULL,
		0xD69B6A0014D3102CULL,
		0x417FA2B9B7DD35CAULL,
		0x153910F445EBDE19ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x98B73E25331C955CULL,
		0x000051007F44CAAAULL,
		0x65A12D6CC031F816ULL,
		0x89CBDBE5A4E59CDCULL,
		0xFD4E1A7CBE5835E3ULL,
		0x951B4E9A33272435ULL,
		0xC0BE9A62247587A9ULL,
		0xED12E511C9F6CEE6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x00830005100C8540ULL,
		0x000040001144828AULL,
		0x00A0244080110812ULL,
		0x8081C061A44104DCULL,
		0x604E1228A05034C3ULL,
		0x941B4A0010030024ULL,
		0x403E822024550588ULL,
		0x0510001041E2CE00ULL
	}};
	printf("Test Case 62\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 62 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -62;
	} else {
		printf("Test Case 62 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x19ED07AC2C8748EAULL,
		0x0008ED4C159C361CULL,
		0xDFD9005030C30365ULL,
		0x1C04EAC10E0E0A6EULL,
		0x6695C6CC1B84C499ULL,
		0x5ACDF797B1CDD08AULL,
		0x6B685459C44A16C1ULL,
		0x4C1E7B4BB0EBEF49ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x89247022784AE0AEULL,
		0x74E44B4B05896ACBULL,
		0x9E8F66326F23EC5CULL,
		0x03698F0D0F3016C1ULL,
		0xC9341C66BA4BB5EEULL,
		0x0E34942B5578C148ULL,
		0x1846C0ED22E98743ULL,
		0x1496F7EC039BA69AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x09240020280240AAULL,
		0x0000494805882208ULL,
		0x9E89001020030044ULL,
		0x00008A010E000240ULL,
		0x401404441A008488ULL,
		0x0A0494031148C008ULL,
		0x0840404900480641ULL,
		0x04167348008BA608ULL
	}};
	printf("Test Case 63\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 63 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -63;
	} else {
		printf("Test Case 63 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x932C317824A6D48FULL,
		0xA9AC4799137E56D7ULL,
		0x0211863631FDB753ULL,
		0x06B71B1143C545BEULL,
		0xAB74F603306C586DULL,
		0x0A28C0DF0EA45961ULL,
		0xBE84DED563E7CF7EULL,
		0x71188AE2EE55E759ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4D3389284F10F1A9ULL,
		0x5020D78BBE74B845ULL,
		0xF71CEDD4B1220D01ULL,
		0xB1C26DCD93E9C912ULL,
		0xA7762257E62096D8ULL,
		0x43029250B9248545ULL,
		0xB207B90BCD6AEE25ULL,
		0xECEA6806A7B960B1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x012001280400D089ULL,
		0x0020478912741045ULL,
		0x0210841431200501ULL,
		0x0082090103C14112ULL,
		0xA374220320201048ULL,
		0x0200805008240141ULL,
		0xB20498014162CE24ULL,
		0x60080802A6116011ULL
	}};
	printf("Test Case 64\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 64 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -64;
	} else {
		printf("Test Case 64 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5A36A9BE0535DE1DULL,
		0xAE80DB3CEAFE5570ULL,
		0x150E8E7C75756C05ULL,
		0x336F12280E00C0B2ULL,
		0xF168E320F02518A9ULL,
		0x5DA197193C328EE1ULL,
		0x4C0FB798DF017009ULL,
		0xA58B4A7E5E23890BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCB7DF510C90EB1DBULL,
		0x2B2D63C7C9A6B4AFULL,
		0x703420C21209267BULL,
		0x52D527EF980D0911ULL,
		0xD95DF6082C6EA47CULL,
		0x68A3D15C486F38F0ULL,
		0x0FC8B3F2BC8A8D09ULL,
		0xAAABDE502226B42BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4A34A11001049019ULL,
		0x2A004304C8A61420ULL,
		0x1004004010012401ULL,
		0x1245022808000010ULL,
		0xD148E20020240028ULL,
		0x48A19118082208E0ULL,
		0x0C08B3909C000009ULL,
		0xA08B4A500222800BULL
	}};
	printf("Test Case 65\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 65 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -65;
	} else {
		printf("Test Case 65 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2CF5CCF7CF674909ULL,
		0x5A56E633C9CDDB01ULL,
		0x5AE23F83A08E367CULL,
		0x9FD44CA93626A0AAULL,
		0xB480D70BBBAD168AULL,
		0x640C9B21A584E0CDULL,
		0x8478FB5B66E41F97ULL,
		0xAF5BB31F80A9ABC9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x591B11F2CCE27929ULL,
		0x54FDC6B9AC930EC7ULL,
		0xE80827CF4E2722B8ULL,
		0x58B4C9AA6FFAF7B6ULL,
		0xDCE15CD164E2D28AULL,
		0x0EE9FE7FB9528C28ULL,
		0x0AFE21235CAD398EULL,
		0x790E770507375684ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x081100F2CC624909ULL,
		0x5054C63188810A01ULL,
		0x4800278300062238ULL,
		0x189448A82622A0A2ULL,
		0x9480540120A0128AULL,
		0x04089A21A1008008ULL,
		0x0078210344A41986ULL,
		0x290A330500210280ULL
	}};
	printf("Test Case 66\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 66 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -66;
	} else {
		printf("Test Case 66 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x841E36A725633561ULL,
		0x132983BF3095DD62ULL,
		0x7A5F8E4A9E735142ULL,
		0xCEEF8E585CAED628ULL,
		0xA7C45BDA1F63A701ULL,
		0xA352FD116B483CB6ULL,
		0xBA0492DB6240CCB7ULL,
		0x47CB9199CB87D17CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x88C26F821DF6B826ULL,
		0x33885C4120C4D468ULL,
		0x88C6D8EA1A04DD47ULL,
		0x7792263B87121E7DULL,
		0x706259C2B2480948ULL,
		0xEEDEDC8150F1C473ULL,
		0x19F875A776E58246ULL,
		0x9B62A122E1CED101ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8002268205623020ULL,
		0x130800012084D460ULL,
		0x0846884A1A005142ULL,
		0x4682061804021628ULL,
		0x204059C212400100ULL,
		0xA252DC0140400432ULL,
		0x1800108362408006ULL,
		0x03428100C186D100ULL
	}};
	printf("Test Case 67\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 67 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -67;
	} else {
		printf("Test Case 67 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x89D8EF1EB743D865ULL,
		0xECB25B39B5268B4BULL,
		0xE97C327978537682ULL,
		0xDF874EB8AB923C7EULL,
		0xBE8094F130F664DDULL,
		0x3097342F4E309BB8ULL,
		0x14F1A44F5D4FC51FULL,
		0x17B12912CC3DB562ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4EB3FB96625322B1ULL,
		0x1D7FA051C5937F23ULL,
		0xA5A2DCA59974C62FULL,
		0xCE8BE29BF4F7CBE1ULL,
		0x46F1B620C7985982ULL,
		0xD6557F1F2DB707E0ULL,
		0x6610F5B2AA00C086ULL,
		0xB283F284997717C2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0890EB1622430021ULL,
		0x0C32001185020B03ULL,
		0xA120102118504602ULL,
		0xCE834298A0920860ULL,
		0x0680942000904080ULL,
		0x1015340F0C3003A0ULL,
		0x0410A4020800C006ULL,
		0x1281200088351542ULL
	}};
	printf("Test Case 68\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 68 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -68;
	} else {
		printf("Test Case 68 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x04318DEC2D07609CULL,
		0x355F83677CA36780ULL,
		0x4D562A1C665EA105ULL,
		0xE5FBDE85D7DECCCDULL,
		0x925CA6025DBA51F1ULL,
		0x192A460359BCB3E8ULL,
		0xE11DF91F5229FAA8ULL,
		0xB6AC17065C2B4EB4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE6137E3EFC0DC665ULL,
		0x19CC39BE18A623DDULL,
		0x79923ECDF4F67B6CULL,
		0x7046FC2C5E313A84ULL,
		0x0A032F0684F037B2ULL,
		0xAC13D091B0FE9FAFULL,
		0xCB8A3E3EDE2AA988ULL,
		0x8791F2991A895D0CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x04110C2C2C054004ULL,
		0x114C012618A22380ULL,
		0x49122A0C64562104ULL,
		0x6042DC0456100884ULL,
		0x0200260204B011B0ULL,
		0x0802400110BC93A8ULL,
		0xC108381E5228A888ULL,
		0x8680120018094C04ULL
	}};
	printf("Test Case 69\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 69 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -69;
	} else {
		printf("Test Case 69 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2505A9E7C1A90003ULL,
		0xC873342C47650B9AULL,
		0xB18211D29A0290F6ULL,
		0xFADE641DC4835210ULL,
		0x654AE6D867D4007CULL,
		0x72B0C12A5ED93902ULL,
		0x2EE10DE9BBA9BCBAULL,
		0xAE34F8EA61E12E7BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6BEF520CF95393C5ULL,
		0x0735852CC723AD8AULL,
		0x4B35BE281B26A980ULL,
		0xFDA7F1E2EF6A1F24ULL,
		0x9C82EF77FA0C3AEDULL,
		0x3746EC3316349626ULL,
		0x4440CB11AB1E748FULL,
		0x6E0A3A97E05EACCFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x21050004C1010001ULL,
		0x0031042C4721098AULL,
		0x010010001A028080ULL,
		0xF8866000C4021200ULL,
		0x0402E6506204006CULL,
		0x3200C02216101002ULL,
		0x04400901AB08348AULL,
		0x2E00388260402C4BULL
	}};
	printf("Test Case 70\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 70 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -70;
	} else {
		printf("Test Case 70 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x36DFFDF2D28A495BULL,
		0x1A553EA39345EBBBULL,
		0x53172E187EDF2A94ULL,
		0x59483C4D2FBEE87AULL,
		0x8D53887D1C2476AFULL,
		0xB5CE9D2CBB59FDF7ULL,
		0x42A431AD12C1ED78ULL,
		0x79009DDF71FE619AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x08D00D4BCAEC5ED4ULL,
		0x472996CC388BA305ULL,
		0xB178A10EE98937EBULL,
		0xEC6B3E41EB3F7EDEULL,
		0xC56826CB6CD03DD8ULL,
		0x65D2F5DD85B3BCF7ULL,
		0xE1BE2CAD196EB451ULL,
		0x3A0603C3A84B314EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x00D00D42C2884850ULL,
		0x020116801001A301ULL,
		0x1110200868892280ULL,
		0x48483C412B3E685AULL,
		0x854000490C003488ULL,
		0x25C2950C8111BCF7ULL,
		0x40A420AD1040A450ULL,
		0x380001C3204A210AULL
	}};
	printf("Test Case 71\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 71 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -71;
	} else {
		printf("Test Case 71 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x75E16C8E618CBF2BULL,
		0xB0E5B715FF872566ULL,
		0xA61E1B1A45F74352ULL,
		0x688E39FE50FE46AFULL,
		0xBA26BC78A8EB1FBAULL,
		0x3F5D72EC94216401ULL,
		0x2EB438A879E460C9ULL,
		0x1E97EBB2A84D3A3AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x40AB21B149AC696CULL,
		0xFBD813CCC4509AE6ULL,
		0xB282BE4342E7492FULL,
		0x0DBF078AD887F166ULL,
		0x54F2C96A42C053C2ULL,
		0xD68C49C583754D76ULL,
		0xBB8DC745B87F9B3BULL,
		0xB5747AD87B086AF3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x40A12080418C2928ULL,
		0xB0C01304C4000066ULL,
		0xA2021A0240E74102ULL,
		0x088E018A50864026ULL,
		0x1022886800C01382ULL,
		0x160C40C480214400ULL,
		0x2A84000038640009ULL,
		0x14146A9028082A32ULL
	}};
	printf("Test Case 72\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 72 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -72;
	} else {
		printf("Test Case 72 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x70F818DDF6B93211ULL,
		0xE04BD6E22DFE7A74ULL,
		0x531814EEAC9ED096ULL,
		0x08D7D8AE49269DD3ULL,
		0xAC44FA3A14E2534BULL,
		0x4476379C5614686DULL,
		0xFD152BE6923897ADULL,
		0xFB12748F9A719254ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x112AEBE574CE1F97ULL,
		0x1500A954DE68DF0CULL,
		0x77F250BB630A6AD3ULL,
		0x2BE18D2F39C0C588ULL,
		0xA9F37EE156BCAAC5ULL,
		0xF7BE458B6CCAA2B2ULL,
		0x597A4CFFCDC6B427ULL,
		0x648064485B2C5EADULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x102808C574881211ULL,
		0x000080400C685A04ULL,
		0x531010AA200A4092ULL,
		0x08C1882E09008580ULL,
		0xA8407A2014A00241ULL,
		0x4436058844002020ULL,
		0x591008E680009425ULL,
		0x600064081A201204ULL
	}};
	printf("Test Case 73\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 73 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -73;
	} else {
		printf("Test Case 73 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0F946DF032196AE7ULL,
		0x61ABEC48F4328A95ULL,
		0xBE31952D193C21A9ULL,
		0xF0527B6DDC0C26DDULL,
		0xE6C5CFDF71E1B294ULL,
		0x6C255D1162E900C6ULL,
		0x08953062AC692557ULL,
		0x50134B7B888C9837ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x730C74B5886148C3ULL,
		0x1DD3884226903F60ULL,
		0x0D9AA094DD7B5416ULL,
		0x6A99F1BEBCB48185ULL,
		0x562C798CF3CD6F6CULL,
		0x79406EBFA63D651CULL,
		0xB7E097BD2669FECAULL,
		0x30BE1A8B71194122ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x030464B0000148C3ULL,
		0x0183884024100A00ULL,
		0x0C10800419380000ULL,
		0x6010712C9C040085ULL,
		0x4604498C71C12204ULL,
		0x68004C1122290004ULL,
		0x0080102024692442ULL,
		0x10120A0B00080022ULL
	}};
	printf("Test Case 74\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 74 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -74;
	} else {
		printf("Test Case 74 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x75FBE19341F7829EULL,
		0xC527CB236A0D8BCFULL,
		0x65C741F3B052B733ULL,
		0x77BC35DF056136D0ULL,
		0x899A74306E0107A0ULL,
		0x21BC437F5BB4EB3DULL,
		0xFD84F5BEF76D7E0CULL,
		0xE6F5D690242C971CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC445E55279BA7436ULL,
		0x7B4713FE781B42CCULL,
		0xFC5292558BB0B428ULL,
		0x1C0596812238FDAEULL,
		0x347C917152BEFD10ULL,
		0xE4C3A631E3F56404ULL,
		0x3D2296FF5D49FA1EULL,
		0xFDF4647BDAB85046ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4441E11241B20016ULL,
		0x41070322680902CCULL,
		0x644200518010B420ULL,
		0x1404148100203480ULL,
		0x0018103042000500ULL,
		0x2080023143B46004ULL,
		0x3D0094BE55497A0CULL,
		0xE4F4441000281004ULL
	}};
	printf("Test Case 75\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 75 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -75;
	} else {
		printf("Test Case 75 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x32F4A880EB580900ULL,
		0x7E7C840C51758DF4ULL,
		0x25CABFFD08DDFCBCULL,
		0x431A9FEF5B18DE43ULL,
		0x5523BC20B86433D2ULL,
		0xE54AD7C3983B4528ULL,
		0x29B9EFA0F9AE3108ULL,
		0x9A37877F1421811EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6B3041E9083C427DULL,
		0x3A1554A066C4A5B4ULL,
		0x60DD33BEA01F1642ULL,
		0xC80390EF64EEA1F5ULL,
		0xC6828535911566C8ULL,
		0xA458530FD543F089ULL,
		0x57E88B7684530EBAULL,
		0xB73029D543BB4D35ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2230008008180000ULL,
		0x3A140400404485B4ULL,
		0x20C833BC001D1400ULL,
		0x400290EF40088041ULL,
		0x44028420900422C0ULL,
		0xA448530390034008ULL,
		0x01A88B2080020008ULL,
		0x9230015500210114ULL
	}};
	printf("Test Case 76\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 76 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -76;
	} else {
		printf("Test Case 76 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x24E2D7084C6467F9ULL,
		0x55033F94175D57BFULL,
		0xBA6716E07082E473ULL,
		0x27BD6A1CB14D3CA9ULL,
		0x2E9E6551FA717705ULL,
		0xE7241F6A1C7D54BBULL,
		0x9FC8C28E91A56F66ULL,
		0xFC0CBCE28E308904ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA15D50217BBAC29FULL,
		0xBE20164D60351460ULL,
		0x4E97BB65E514F11BULL,
		0x6E574D614A18C0E0ULL,
		0x9DA6D0D811D378C7ULL,
		0x5930263874CEA480ULL,
		0x9EA830ADB2F2A385ULL,
		0x20198CB62D7A8CDBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2040500048204299ULL,
		0x1400160400151420ULL,
		0x0A0712606000E013ULL,
		0x26154800000800A0ULL,
		0x0C86405010517005ULL,
		0x41200628144C0480ULL,
		0x9E88008C90A02304ULL,
		0x20088CA20C308800ULL
	}};
	printf("Test Case 77\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 77 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -77;
	} else {
		printf("Test Case 77 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA6ADA31C9B86BADAULL,
		0x7044D4A1C00FC856ULL,
		0x2BA62978C730EEA1ULL,
		0xC530DF8240254A15ULL,
		0x4435C47B81062518ULL,
		0xF3E3F9B63E6CB402ULL,
		0x215B99839827F4D4ULL,
		0x06C58AF482E3D84BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x55FC0F96F4DA58C1ULL,
		0x30801B269CBEFDA6ULL,
		0x4DF764ACF4404644ULL,
		0x23C342B16966DE52ULL,
		0x21D7B833AB190414ULL,
		0xEB500E63666AAC0EULL,
		0x955CB9058B1F41FEULL,
		0xCFA9C00A423F995AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x04AC0314908218C0ULL,
		0x30001020800EC806ULL,
		0x09A62028C4004600ULL,
		0x0100428040244A10ULL,
		0x0015803381000410ULL,
		0xE34008222668A402ULL,
		0x01589901880740D4ULL,
		0x068180000223984AULL
	}};
	printf("Test Case 78\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 78 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -78;
	} else {
		printf("Test Case 78 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x75CDAC1774E2BA6DULL,
		0x5036BFB62F74AA35ULL,
		0xD419DFE17DF83C60ULL,
		0x1F68F26D5790B83BULL,
		0x862B19EDD0B026FCULL,
		0xBCEBD41B13CE4505ULL,
		0xEF34FC17E3C4325BULL,
		0x2C5676B8ADEB2C94ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCCCE860FC01E0AAAULL,
		0xA789D80A2F3FA506ULL,
		0x8F59B5FEC284BA65ULL,
		0x3ABB7E299211AF9DULL,
		0x6EDF0EF761F89B33ULL,
		0x0A8F950681552FC4ULL,
		0x58850984B30D13F8ULL,
		0x141E673CF1BF7333ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x44CC840740020A28ULL,
		0x000098022F34A004ULL,
		0x841995E040803860ULL,
		0x1A2872291210A819ULL,
		0x060B08E540B00230ULL,
		0x088B940201440504ULL,
		0x48040804A3041258ULL,
		0x04166638A1AB2010ULL
	}};
	printf("Test Case 79\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 79 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -79;
	} else {
		printf("Test Case 79 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4A55DE70924BC8C6ULL,
		0x5EC074AFE62161FAULL,
		0x691226529472A87BULL,
		0xA64372CA175D474EULL,
		0xC27A37998D3AEA04ULL,
		0x04C6C3B3CA94DCBEULL,
		0xE44980478834C361ULL,
		0x8376EF462A5B3E1EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x64920CA8D45DC433ULL,
		0xB7AE4843A599B7C8ULL,
		0xF33F0E14CCACA65CULL,
		0x3A5DA75541053509ULL,
		0x56E70723D1FD149AULL,
		0x0AFB6AB4512CDA00ULL,
		0x304334F733BEBC44ULL,
		0xF04A217CE9BDBB4DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x40100C209049C002ULL,
		0x16804003A40121C8ULL,
		0x611206108420A058ULL,
		0x2241224001050508ULL,
		0x4262070181380000ULL,
		0x00C242B04004D800ULL,
		0x2041004700348040ULL,
		0x8042214428193A0CULL
	}};
	printf("Test Case 80\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 80 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -80;
	} else {
		printf("Test Case 80 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x21830EB87499EA8FULL,
		0x32C5340DD7BCD018ULL,
		0xCC6C448D3CE3A905ULL,
		0x4AD8464A539A1515ULL,
		0x4B168C342F520A55ULL,
		0x6074EB61D0C9E71BULL,
		0xFBCD80C8A5DF57F2ULL,
		0x08B0BC48F86191FDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEC3F334C4FF1E465ULL,
		0x2A7D3DBE85739683ULL,
		0xE8DD24EFC9C69778ULL,
		0x70C949EEA87890CCULL,
		0x39CEBB1EBF6A46B3ULL,
		0x07AB2662223F25C4ULL,
		0x53B51246354281A4ULL,
		0x763E379B783F5DF4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x200302084491E005ULL,
		0x2245340C85309000ULL,
		0xC84C048D08C28100ULL,
		0x40C8404A00181004ULL,
		0x090688142F420211ULL,
		0x0020226000092500ULL,
		0x53850040254201A0ULL,
		0x00303408782111F4ULL
	}};
	printf("Test Case 81\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 81 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -81;
	} else {
		printf("Test Case 81 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x20DF432EC6AED2A3ULL,
		0xCD0E946446A66F8DULL,
		0xA3E1EF4F092A65A5ULL,
		0x0CFE7D2BFA1D7DE6ULL,
		0xC94DACA5A3B10B39ULL,
		0xC2B3139F1D9EEFB9ULL,
		0x62999FFBEE7609ADULL,
		0x49DEA085CE9222DEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB021022BA680E31DULL,
		0x20D345CF2E1516C6ULL,
		0x7820CA3D01D82666ULL,
		0x1A46ED69D54F3E9CULL,
		0xEBC82DEEB23A163BULL,
		0xAAE85165E6C5C4EAULL,
		0x1564C4D956B2AE43ULL,
		0x077C6B842FC0649EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2001022A8680C201ULL,
		0x0002044406040684ULL,
		0x2020CA0D01082424ULL,
		0x08466D29D00D3C84ULL,
		0xC9482CA4A2300239ULL,
		0x82A011050484C4A8ULL,
		0x000084D946320801ULL,
		0x015C20840E80209EULL
	}};
	printf("Test Case 82\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 82 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -82;
	} else {
		printf("Test Case 82 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0AD14C819B677BD2ULL,
		0x0AD37AE1F6458467ULL,
		0x4F6334FE1C0747B4ULL,
		0xED575560968F2C1BULL,
		0xC94E4014CE0ABAD8ULL,
		0xC716B7B20FC67BC2ULL,
		0x9E5B8A8EC18DC775ULL,
		0x4F3E1BFF29918DD1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE79141BF154BA685ULL,
		0xEFE9EF1E6C87F0AAULL,
		0xA96F4D39C0FB518BULL,
		0x4FE3CF4FAAF1D0C7ULL,
		0xA89E8F8D52B7B182ULL,
		0x29A837AD6FAD3827ULL,
		0xC3F5FF0BAAF5BB92ULL,
		0x0A65B0083452C016ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0291408111432280ULL,
		0x0AC16A0064058022ULL,
		0x0963043800034180ULL,
		0x4D43454082810003ULL,
		0x880E00044202B080ULL,
		0x010037A00F843802ULL,
		0x82518A0A80858310ULL,
		0x0A24100820108010ULL
	}};
	printf("Test Case 83\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 83 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -83;
	} else {
		printf("Test Case 83 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x309D6E108245BF66ULL,
		0x4BFAD3B3BB780BC6ULL,
		0x903C2DDA36974A15ULL,
		0x9E2B0938C2C8A2B1ULL,
		0xFA63EFAD76B995DBULL,
		0xCABCBD00EE37E87FULL,
		0x33EE8E303FD21E0EULL,
		0x9196018B0A5395E0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x88B4EE825825C02CULL,
		0xDF8BD2761CD60CD3ULL,
		0xD74914A68C2D7322ULL,
		0xFCA9986D2F79A1A2ULL,
		0x2F88C032DE5DAC6AULL,
		0x57639ACFF224434CULL,
		0x7282BFDBE36D19E7ULL,
		0xD87649A17660D962ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x00946E0000058024ULL,
		0x4B8AD232185008C2ULL,
		0x9008048204054200ULL,
		0x9C2908280248A0A0ULL,
		0x2A00C0205619844AULL,
		0x42209800E224404CULL,
		0x32828E1023401806ULL,
		0x9016018102409160ULL
	}};
	printf("Test Case 84\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 84 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -84;
	} else {
		printf("Test Case 84 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2EEF2B94BBD85E9FULL,
		0x01A6116EF003987FULL,
		0x9AD0D8A177434D89ULL,
		0x9F63038F13FDD42BULL,
		0xA5F0FED58B65D4A7ULL,
		0xE82493CC36498EAFULL,
		0xF3A5F1A1656E4164ULL,
		0x51AD9A979DEDF181ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC47361D68B69206AULL,
		0x6F4A44CAF22FE61DULL,
		0x6957FE8DBECC984EULL,
		0x2B84D5C5587D61B7ULL,
		0xD8AFFFF60FD521F1ULL,
		0xB4B5DC2154A516F9ULL,
		0xA5EBD49650572D78ULL,
		0xD4778225F077D48EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x046321948B48000AULL,
		0x0102004AF003801DULL,
		0x0850D88136400808ULL,
		0x0B000185107D4023ULL,
		0x80A0FED40B4500A1ULL,
		0xA0249000140106A9ULL,
		0xA1A1D08040460160ULL,
		0x502582059065D080ULL
	}};
	printf("Test Case 85\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 85 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -85;
	} else {
		printf("Test Case 85 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x629E5B43F1F39BBDULL,
		0x86F2A77854966E86ULL,
		0x9A33E140877D1A54ULL,
		0x04D8FE38A0A878DBULL,
		0xE0030CA8885B2545ULL,
		0x58524F9FAD0F7156ULL,
		0x504A5B496BE95653ULL,
		0x117C69E048285941ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF45F76D3641C6844ULL,
		0x9AC292F235601B46ULL,
		0x0C1F78C685F39C27ULL,
		0x302E97AA26347E54ULL,
		0x8D2B772850F393C1ULL,
		0xD0B1F4B2AB1CB4ABULL,
		0x0A03B99FCC24B9ADULL,
		0x329FCDB870927374ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x601E524360100804ULL,
		0x82C2827014000A06ULL,
		0x0813604085711804ULL,
		0x0008962820207850ULL,
		0x8003042800530141ULL,
		0x50104492A90C3002ULL,
		0x0002190948201001ULL,
		0x101C49A040005140ULL
	}};
	printf("Test Case 86\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 86 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -86;
	} else {
		printf("Test Case 86 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x966CE5E2D39DB452ULL,
		0xF102CC778FA26142ULL,
		0xE199E6C1DBE093B0ULL,
		0xA822C1022B71F4A5ULL,
		0xB04CB76D2AC760CAULL,
		0x5D074C344046A019ULL,
		0x5885D0034725AE2BULL,
		0x1797865AE0ABC5D5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x39206941089F85C6ULL,
		0x0D0CB6E5553D1AD7ULL,
		0x9B3B42E4846F3904ULL,
		0xB8E26276E9E3973CULL,
		0x99A59F7209491961ULL,
		0x4D741ED75343F4DEULL,
		0x819CC11368E3A4DBULL,
		0x6593C8D4D154F7A0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x10206140009D8442ULL,
		0x0100846505200042ULL,
		0x811942C080601100ULL,
		0xA822400229619424ULL,
		0x9004976008410040ULL,
		0x4D040C144042A018ULL,
		0x0084C0034021A40BULL,
		0x05938050C000C580ULL
	}};
	printf("Test Case 87\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 87 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -87;
	} else {
		printf("Test Case 87 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x12B7136CB573386FULL,
		0xC7C07FA9FE836580ULL,
		0x394225C990CB094CULL,
		0xB4A3736EDEB35E85ULL,
		0x2E7D58234409D05AULL,
		0x9DBE87244A0F16F3ULL,
		0x0A08D9ED5BF626DEULL,
		0x6E7450FF9211E4A3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4E92281566C759FAULL,
		0x8C9F793E44B96452ULL,
		0x876AA618C391810AULL,
		0x22E68B3FD1CB7927ULL,
		0xFBE797281A698901ULL,
		0x35934ED5194B96A3ULL,
		0x28CDE627757C1C9EULL,
		0x43A8EC64BD41C987ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x029200042443186AULL,
		0x8480792844816400ULL,
		0x0142240880810108ULL,
		0x20A2032ED0835805ULL,
		0x2A65102000098000ULL,
		0x15920604080B16A3ULL,
		0x0808C0255174049EULL,
		0x422040649001C083ULL
	}};
	printf("Test Case 88\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 88 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -88;
	} else {
		printf("Test Case 88 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3F46F6993FC7134EULL,
		0xB751D9B45FFB734CULL,
		0xFB2B4323C7B662E0ULL,
		0x0C2B4E22BD88D51BULL,
		0x09FE7CD69F1B1732ULL,
		0xB3D195E9CDFF20A8ULL,
		0x72B13025B0378195ULL,
		0x372D4AC600C962B6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x89E55BAB11D5AFB2ULL,
		0xAD6CA75D83FCC85CULL,
		0xB4C0CDEB931678BFULL,
		0xD1105ED0F0C1A157ULL,
		0x8B8B463ECCD82D0FULL,
		0x21C2EFEDC05DD4ACULL,
		0x08654483A6AC89DFULL,
		0x459D38003E04B164ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0944528911C50302ULL,
		0xA540811403F8404CULL,
		0xB0004123831660A0ULL,
		0x00004E00B0808113ULL,
		0x098A44168C180502ULL,
		0x21C085E9C05D00A8ULL,
		0x00210001A0248195ULL,
		0x050D080000002024ULL
	}};
	printf("Test Case 89\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 89 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -89;
	} else {
		printf("Test Case 89 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x39246ACFFE6447A2ULL,
		0x3346763E5BE6A692ULL,
		0x8205B68847D745BBULL,
		0xE94861508F4D694AULL,
		0x69D512D85ECD617EULL,
		0xBC804C1785344709ULL,
		0x71751A0212D3EEFAULL,
		0xB2E16C5BA6190F72ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0B493A524095745FULL,
		0xD5FC64F91C5B9EBDULL,
		0x96CDFAB2E52A1C76ULL,
		0xDD17D2EAA18D1901ULL,
		0x15757EF6EFEB3405ULL,
		0x5142E0D247F9A0A6ULL,
		0xA1E96C04E0C5CC19ULL,
		0xB0576784E66D0053ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x09002A4240044402ULL,
		0x1144643818428690ULL,
		0x8205B28045020432ULL,
		0xC9004040810D0900ULL,
		0x015512D04EC92004ULL,
		0x1000401205300000ULL,
		0x2161080000C1CC18ULL,
		0xB0416400A6090052ULL
	}};
	printf("Test Case 90\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 90 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -90;
	} else {
		printf("Test Case 90 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC1E44228055D6197ULL,
		0xBE3CA3B58F981374ULL,
		0xA1F45E64D50F45DCULL,
		0x43CE7D3500133724ULL,
		0x0A48CFD5EA33A998ULL,
		0x187902A7B2587C30ULL,
		0xC0953B796DDB25EBULL,
		0xE9342813C1EA3CBDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5DECD9C5FB7B796EULL,
		0x3A1758777CC7BE49ULL,
		0xA70D2F6D451EC1E6ULL,
		0xB0E086D1DF6996E0ULL,
		0xEEF6844C95DE513BULL,
		0x82167D6970DEBC64ULL,
		0xB012F395ED5C5D0CULL,
		0x3FF0728306CF5D6FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x41E4400001596106ULL,
		0x3A1400350C801240ULL,
		0xA1040E64450E41C4ULL,
		0x00C0041100011620ULL,
		0x0A40844480120118ULL,
		0x0010002130583C20ULL,
		0x801033116D580508ULL,
		0x2930200300CA1C2DULL
	}};
	printf("Test Case 91\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 91 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -91;
	} else {
		printf("Test Case 91 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8F811B2AED33443AULL,
		0x90D3485FDBD41354ULL,
		0x9B36C5986B6E6B45ULL,
		0x00E8F8139ED0AD81ULL,
		0x6935348C7D569AEBULL,
		0x9664953C98E1F095ULL,
		0xED5E7B7BD47D7FE5ULL,
		0x56C252D97B3008C2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x23DA8649B92E2CFBULL,
		0xCB27D4A8C891A2E9ULL,
		0xA56AD08128FF52E1ULL,
		0xFE719F98FAF78828ULL,
		0x125535C95F1DF34AULL,
		0x5626D395FE8026CDULL,
		0x5E8DFE17374D469FULL,
		0x6B890BDD91FEC096ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x03800208A922043AULL,
		0x80034008C8900240ULL,
		0x8122C080286E4241ULL,
		0x006098109AD08800ULL,
		0x001534885D14924AULL,
		0x1624911498802085ULL,
		0x4C0C7A13144D4685ULL,
		0x428002D911300082ULL
	}};
	printf("Test Case 92\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 92 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -92;
	} else {
		printf("Test Case 92 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x389B6237BB3A387CULL,
		0x206567D92B4F3BA8ULL,
		0xCEEF84ADCE33F242ULL,
		0x71D6F58287D0E452ULL,
		0x81C09908E1E885F1ULL,
		0xEFC2FFC113030BB5ULL,
		0x2655BB7A1B0C177BULL,
		0xD87A248E209FE251ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0BBD5628C9876F70ULL,
		0xE36CF6A23F5190FAULL,
		0x1B8CB8DB88DA69ABULL,
		0x418796058B67C967ULL,
		0x4B47F43605934D5BULL,
		0xE243DC42D42809A7ULL,
		0x9BE235D7B0A705E1ULL,
		0x9E620C914277027CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0899422089022870ULL,
		0x206466802B4110A8ULL,
		0x0A8C808988126002ULL,
		0x418694008340C042ULL,
		0x0140900001800551ULL,
		0xE242DC40100009A5ULL,
		0x0240315210040561ULL,
		0x9862048000170250ULL
	}};
	printf("Test Case 93\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 93 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -93;
	} else {
		printf("Test Case 93 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0F7493A69F45603CULL,
		0xA02F9C53CD997862ULL,
		0x4AEA2F4498EA1E73ULL,
		0x6AEC86B5C2E7A44BULL,
		0xC286B91810C4CD55ULL,
		0xA55839CCFF6C202FULL,
		0xFD46ADA2461033D1ULL,
		0x1081BF3A6C7EB771ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBD8C4B3AB4E30C2CULL,
		0x9FDA510D1A61B5DBULL,
		0xFCB5CB7123BE366EULL,
		0x48FA5978064B7965ULL,
		0xA4378EA145234BC9ULL,
		0xB115161422B5F022ULL,
		0x43229A0D96AF3956ULL,
		0x3E3F45096FB25DF9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0D0403229441002CULL,
		0x800A100108013042ULL,
		0x48A00B4000AA1662ULL,
		0x48E8003002432041ULL,
		0x8006880000004941ULL,
		0xA110100422242022ULL,
		0x4102880006003150ULL,
		0x100105086C321571ULL
	}};
	printf("Test Case 94\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 94 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -94;
	} else {
		printf("Test Case 94 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA5BB747E2CD630A0ULL,
		0xD42D8F13D174DFF3ULL,
		0xD1A75CD9E3B3DC84ULL,
		0xACD4EA1D404D23C3ULL,
		0xF07FE70A3817722BULL,
		0x0C9E65D94FEF3734ULL,
		0xD8E4EC74B9BCA981ULL,
		0x4C274F410117CC0DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9BA1625B8B4786E0ULL,
		0xFFFB8030F7047FAAULL,
		0x94B1E01B2B29BEB5ULL,
		0x34C1E2FB0DA876A7ULL,
		0xE10F8D05F5C6E34EULL,
		0x0A6CF2714DD5E3FBULL,
		0x1536523776EDE244ULL,
		0x2A3E37F7B7CB1773ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x81A1605A084600A0ULL,
		0xD4298010D1045FA2ULL,
		0x90A1401923219C84ULL,
		0x24C0E21900082283ULL,
		0xE00F85003006620AULL,
		0x080C60514DC52330ULL,
		0x1024403430ACA000ULL,
		0x0826074101030401ULL
	}};
	printf("Test Case 95\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 95 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -95;
	} else {
		printf("Test Case 95 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAA8F667F2C5EA3D1ULL,
		0xAF5399094AA16A74ULL,
		0x92C0F8AC200A24CEULL,
		0x4F0DE0C8C0910CF3ULL,
		0x56228C1480E702DAULL,
		0x895639BFEA9EBB8AULL,
		0xB84312A31C8EC285ULL,
		0x032DAF2311C24E68ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3FE809036776564CULL,
		0xF87ADD300E13E4E3ULL,
		0x972E79957DDF1390ULL,
		0x1810BAF219CE674CULL,
		0x49DE4FC2A168C27AULL,
		0x7549C72CBDEA5E7FULL,
		0x1B57972A9DC5B95AULL,
		0x06D7F3B922C4F69CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2A88000324560240ULL,
		0xA85299000A016060ULL,
		0x92007884200A0080ULL,
		0x0800A0C000800440ULL,
		0x40020C008060025AULL,
		0x0140012CA88A1A0AULL,
		0x184312221C848000ULL,
		0x0205A32100C04608ULL
	}};
	printf("Test Case 96\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 96 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -96;
	} else {
		printf("Test Case 96 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x410D11D0DC94D004ULL,
		0xAD06F79C97319440ULL,
		0x609BD8FE0AFD8259ULL,
		0x14C8E3E55BC8FA67ULL,
		0x1DEC5DFBE7429841ULL,
		0x099D8A3F07D55FCDULL,
		0x8B97936A7847A9B6ULL,
		0xD8E6BEAA80077827ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD4B1DAB28EFB3833ULL,
		0xDF2E45476052C5E6ULL,
		0x53C9F01E213E6547ULL,
		0x35A28BF1B3273BA8ULL,
		0x11BD2C818FAA4BD0ULL,
		0xEB6DC90A33808F21ULL,
		0x155E54B6D5C20638ULL,
		0xD2C27AEA9484B008ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x400110908C901000ULL,
		0x8D06450400108440ULL,
		0x4089D01E003C0041ULL,
		0x148083E113003A20ULL,
		0x11AC0C8187020840ULL,
		0x090D880A03800F01ULL,
		0x0116102250420030ULL,
		0xD0C23AAA80043000ULL
	}};
	printf("Test Case 97\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 97 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -97;
	} else {
		printf("Test Case 97 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x933FA54AC03D6145ULL,
		0x9A6A2EF0CE5E3205ULL,
		0xBBCB5CA52C3C43BFULL,
		0x91FDF70918C8CA21ULL,
		0x19BB0E841C616DEBULL,
		0x2FA790680294AFB1ULL,
		0x915F3012DE88A04CULL,
		0xE11F2030633A48CEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x30482821B3CD7354ULL,
		0x8655E763C67EEF95ULL,
		0x1BD771EB0824F54DULL,
		0x8BE51A797769A97AULL,
		0x6D63E71963C3BBADULL,
		0xD9D1BAA4FBA0D498ULL,
		0xCFD269D04DBF6EBAULL,
		0x2C6FAC1F2986201BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x10082000800D6144ULL,
		0x82402660C65E2205ULL,
		0x1BC350A10824410DULL,
		0x81E5120910488820ULL,
		0x09230600004129A9ULL,
		0x0981902002808490ULL,
		0x815220104C882008ULL,
		0x200F20102102000AULL
	}};
	printf("Test Case 98\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 98 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -98;
	} else {
		printf("Test Case 98 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x784550A0D0472957ULL,
		0x94622E0C31A324AAULL,
		0x34E28955659237F3ULL,
		0xA0A369500577D4B5ULL,
		0x7C5C56AAEF46D76DULL,
		0x098E7480722E6630ULL,
		0xE336C987CBCB0FE8ULL,
		0x9CE78EE9FC30473DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x69E169861667BA87ULL,
		0xF67BD51452EF079DULL,
		0xAD9CCBEF200B487FULL,
		0x6E0FA231F4D8227AULL,
		0xC4D3D46CF28EA73BULL,
		0xED3EF6746DD2FAB1ULL,
		0x661DBAAE29D1478BULL,
		0x08C52DA6E44BDC03ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6841408010472807ULL,
		0x9462040410A30488ULL,
		0x2480894520020073ULL,
		0x2003201004500030ULL,
		0x44505428E2068729ULL,
		0x090E740060026230ULL,
		0x6214888609C10788ULL,
		0x08C50CA0E4004401ULL
	}};
	printf("Test Case 99\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 99 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -99;
	} else {
		printf("Test Case 99 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD169366465EA4E41ULL,
		0x0A86F6216261863AULL,
		0xAFCDD82C57E0F444ULL,
		0x997BBBEB258E178BULL,
		0x702C8E48A1603283ULL,
		0xE6FFD4A13E7152EEULL,
		0x02BD87CBD8020ACBULL,
		0x8A5080B82924994FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA814EF4893B7F427ULL,
		0x0A4BA1DD34B87BA9ULL,
		0x6C70D80B12EE0E37ULL,
		0x054CDF075F2DCECCULL,
		0x84234B625A1E2ECEULL,
		0xCFC7C1CC6D1F6CD4ULL,
		0x8F1391DBD548F521ULL,
		0x14DC463A1DA770C0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8000264001A24401ULL,
		0x0A02A00120200228ULL,
		0x2C40D80812E00404ULL,
		0x01489B03050C0688ULL,
		0x00200A4000002282ULL,
		0xC6C7C0802C1140C4ULL,
		0x021181CBD0000001ULL,
		0x0050003809241040ULL
	}};
	printf("Test Case 100\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 100 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -100;
	} else {
		printf("Test Case 100 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1B9C4F60272FAE05ULL,
		0x871654ECF444E5C8ULL,
		0x6064EFBD4EBBEDF0ULL,
		0x594AB7A6E36E536DULL,
		0x742A6F9DA0B43625ULL,
		0x7D6D780C6C16A186ULL,
		0x6D87F9A8FD3C3D63ULL,
		0x1FFF142EA85FFFCEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xED21747DB238AAF8ULL,
		0x51875F4225685D5AULL,
		0x64F8A6C4A2B637A6ULL,
		0x004BFA39533A583FULL,
		0x494B2B4A2AD3D95AULL,
		0x970BBF12BFE04CAEULL,
		0x6E30B73EC2D9F4BDULL,
		0x3F6FAE71142E5AA3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x090044602228AA00ULL,
		0x0106544024404548ULL,
		0x6060A68402B225A0ULL,
		0x004AB220432A502DULL,
		0x400A2B0820901000ULL,
		0x150938002C000086ULL,
		0x6C00B128C0183421ULL,
		0x1F6F0420000E5A82ULL
	}};
	printf("Test Case 101\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 101 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -101;
	} else {
		printf("Test Case 101 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x52EAACCED468000EULL,
		0x4AA1EB7C16A8B511ULL,
		0xD4380A877511D247ULL,
		0x9996075E12176228ULL,
		0xECD657C1A9D1D903ULL,
		0x1912AB148FD78AF2ULL,
		0xBE54656D8BCDF926ULL,
		0xA95AB6B434F1BF66ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE2FD80C5E214BDDBULL,
		0x80F1291736560DFEULL,
		0xCBF5984A7C4E54FAULL,
		0xDA5D478CBF40DF0DULL,
		0xBE1A9FDBB5D7E0A1ULL,
		0xEE7D5BABE0207C71ULL,
		0x69106450568C3269ULL,
		0xE61A971BD5E218C3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x42E880C4C000000AULL,
		0x00A1291416000510ULL,
		0xC030080274005042ULL,
		0x9814070C12004208ULL,
		0xAC1217C1A1D1C001ULL,
		0x08100B0080000870ULL,
		0x28106440028C3020ULL,
		0xA01A961014E01842ULL
	}};
	printf("Test Case 102\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 102 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -102;
	} else {
		printf("Test Case 102 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD6C56F7CB6B0F23BULL,
		0x8C09A31787C3CFFAULL,
		0x272065A0217F7AFBULL,
		0x9D37659F9B7D7799ULL,
		0x7BE9178200C83332ULL,
		0xE5E4BACD94254C68ULL,
		0x9145837D3508DBECULL,
		0xF3EB6B67FFF72C56ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8FEDEA2685DF5456ULL,
		0x270E5CC389799C50ULL,
		0xBF07A167354E8F49ULL,
		0x09B4F7F0289152D3ULL,
		0xBF860EEE4CBACAAAULL,
		0xD57DAB0272927B0CULL,
		0x7CF92DC8A076F144ULL,
		0x1E698EAA35EC693BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x86C56A2484905012ULL,
		0x0408000381418C50ULL,
		0x27002120214E0A49ULL,
		0x0934659008115291ULL,
		0x3B80068200880222ULL,
		0xC564AA0010004808ULL,
		0x104101482000D144ULL,
		0x12690A2235E42812ULL
	}};
	printf("Test Case 103\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 103 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -103;
	} else {
		printf("Test Case 103 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF8C36927A2C10391ULL,
		0x361DBFBBFF088F4DULL,
		0xD6A24C1AE23321ECULL,
		0x48D4026D0FBCA818ULL,
		0x3A7E59E1DE59E6A6ULL,
		0x1266ADDFF219AD53ULL,
		0x21A108ADFFC69D45ULL,
		0xE2A38F7B649E16E8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC764534944311954ULL,
		0xBCDEA8D6017B34C7ULL,
		0x72A91C32EE615B05ULL,
		0x5C6649E7C242E5F7ULL,
		0x9F369C724AB6009CULL,
		0x4245AC3D0B2454BBULL,
		0xA53A7D72EFCA70F1ULL,
		0x16429B809CAC2E84ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC040410100010110ULL,
		0x341CA89201080445ULL,
		0x52A00C12E2210104ULL,
		0x484400650200A010ULL,
		0x1A3618604A100084ULL,
		0x0244AC1D02000413ULL,
		0x21200820EFC21041ULL,
		0x02028B00048C0680ULL
	}};
	printf("Test Case 104\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 104 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -104;
	} else {
		printf("Test Case 104 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2F545637E88FF327ULL,
		0xC5C1B3CD07F1242AULL,
		0x5840C456B5186AAFULL,
		0xC8403FEBC104CBF0ULL,
		0xB739C17C009C1697ULL,
		0xFF46659D75967795ULL,
		0xA071778143524A81ULL,
		0x7C66DE1EC1AFE93FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5F14E79DB326B537ULL,
		0x591994E4EAF750A8ULL,
		0x9A1ECCB5AE4F480FULL,
		0x74DD1D1AE84AC2E3ULL,
		0x776121328CF1333FULL,
		0x460D1CCA113650C8ULL,
		0xE1FE876A93175EA0ULL,
		0xB06ECCE6AA18DD49ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0F144615A006B127ULL,
		0x410190C402F10028ULL,
		0x1800C414A408480FULL,
		0x40401D0AC000C2E0ULL,
		0x3721013000901217ULL,
		0x4604048811165080ULL,
		0xA070070003124A80ULL,
		0x3066CC068008C909ULL
	}};
	printf("Test Case 105\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 105 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -105;
	} else {
		printf("Test Case 105 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9CE4D68575C146FFULL,
		0x5CD7755709793AB2ULL,
		0x428557CF646F6F43ULL,
		0x5EF972DE8068FBD7ULL,
		0x614D4EC46CA72DF5ULL,
		0x1F47873FB1217DB6ULL,
		0x876EED81D5AAC498ULL,
		0xF108CC421ABB204BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x469EB50A622CB5BDULL,
		0xF42855F9441C3845ULL,
		0xBFEE2AE8E4E1791CULL,
		0xCE312F45E40731C7ULL,
		0xF0C4AE3048DDE280ULL,
		0xE54605B87E0B76CAULL,
		0x47CF86407BE91033ULL,
		0x101ED248163844AAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x04849400600004BDULL,
		0x5400555100183800ULL,
		0x028402C864616900ULL,
		0x4E312244800031C7ULL,
		0x60440E0048852080ULL,
		0x0546053830017482ULL,
		0x074E840051A80010ULL,
		0x1008C0401238000AULL
	}};
	printf("Test Case 106\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 106 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -106;
	} else {
		printf("Test Case 106 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3BEB0827791A3BE2ULL,
		0xCA9D191A8B85EB6CULL,
		0xA33331CC012CB8E0ULL,
		0x9885F38DDE24F4AEULL,
		0x7F4925F48A61690AULL,
		0x90DBF95CE42C17B2ULL,
		0x1151B0D587DF9E0EULL,
		0xF067E68BC82D8E84ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF968DD05F44E61D7ULL,
		0x291511B059297243ULL,
		0x256BA3091A139245ULL,
		0x09DEBC57755ED5F2ULL,
		0xF1A67B564F6B1413ULL,
		0x2E35031573F47705ULL,
		0xC8E95933BF4451CCULL,
		0xEAE36A2E16AF8AA7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x39680805700A21C2ULL,
		0x0815111009016240ULL,
		0x2123210800009040ULL,
		0x0884B0055404D4A2ULL,
		0x710021540A610002ULL,
		0x0011011460241700ULL,
		0x004110118744100CULL,
		0xE063620A002D8A84ULL
	}};
	printf("Test Case 107\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 107 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -107;
	} else {
		printf("Test Case 107 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4AE682AE69632C96ULL,
		0x8D29F0BAC115FA04ULL,
		0xCFB9ED94B2F95658ULL,
		0x67C164A377B44887ULL,
		0xD9D05CB33F1978CAULL,
		0x4BB5890CE33F74A3ULL,
		0xDA74BFFC6C7B9A83ULL,
		0xA538A8FD90FA1CAEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5D465C51519EDA0AULL,
		0x9DF53C84FEF81B16ULL,
		0x2B8A1F9E8C915FECULL,
		0x83194FFE999F5699ULL,
		0xA4BF6CBC3FBD8701ULL,
		0x4D5E72759F0BB16EULL,
		0x25ADFA7F96AE5FFEULL,
		0x2A784AB6C403BC5FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4846000041020802ULL,
		0x8D213080C0101A04ULL,
		0x0B880D9480915648ULL,
		0x030144A211944081ULL,
		0x80904CB03F190000ULL,
		0x49140004830B3022ULL,
		0x0024BA7C042A1A82ULL,
		0x203808B480021C0EULL
	}};
	printf("Test Case 108\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 108 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -108;
	} else {
		printf("Test Case 108 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCD821059E033899EULL,
		0xFCA2EDC83FB2E9C5ULL,
		0xED2CE9CAE54130C0ULL,
		0x39FC3769AD0EC2DDULL,
		0x56FA58C76ACF771DULL,
		0xBDAA9127CC7DF1E3ULL,
		0xFA4904EE3A80E599ULL,
		0x85263F08DB8F76C0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0DFAD1D11130883EULL,
		0x75B9F6DE2502B115ULL,
		0xA4CE88545B5090A3ULL,
		0x3D863BE7910F4069ULL,
		0xE8CBE8CD783C39AEULL,
		0x384D276082CFD8BAULL,
		0xDB8609ABDCF5318FULL,
		0xA692A0D3D7EA3836ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0D8210510030881EULL,
		0x74A0E4C82502A105ULL,
		0xA40C884041401080ULL,
		0x39843361810E4049ULL,
		0x40CA48C5680C310CULL,
		0x38080120804DD0A2ULL,
		0xDA0000AA18802189ULL,
		0x84022000D38A3000ULL
	}};
	printf("Test Case 109\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 109 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -109;
	} else {
		printf("Test Case 109 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3D0DA6ED1F1110D9ULL,
		0x6FA09BE1798DF9BDULL,
		0xB04D0228471E1183ULL,
		0x3C65A7820C5B3814ULL,
		0xF13234EF54E88C47ULL,
		0x020514DCAF5E33C4ULL,
		0xB8BE7EE3DADF5539ULL,
		0x648E4FED0F7961E2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD8D8CC1DB4B38768ULL,
		0xA5A5E1C7110CCC0AULL,
		0xA5F844E0571BC357ULL,
		0xA0F226AC8A95E58FULL,
		0x63D441D1AFD76779ULL,
		0xF0F87FB43833A0C4ULL,
		0xD984466ACE54177DULL,
		0x6F670D5869A2989AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1808840D14110048ULL,
		0x25A081C1110CC808ULL,
		0xA0480020471A0103ULL,
		0x2060268008112004ULL,
		0x611000C104C00441ULL,
		0x00001494281220C4ULL,
		0x98844662CA541539ULL,
		0x64060D4809200082ULL
	}};
	printf("Test Case 110\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 110 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -110;
	} else {
		printf("Test Case 110 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x45BC2CDAFBDF9397ULL,
		0x43D65BC43619C606ULL,
		0x9147DD8AC5AB19E3ULL,
		0x96D2C2BB6C6FE413ULL,
		0xE62FF695435F6ADDULL,
		0x28BBDCF3247C4EB1ULL,
		0x144EDAE1BD7686E2ULL,
		0xC017A5C3114E3B23ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDCC3B726F0139024ULL,
		0x8B6B77CD569FF9C8ULL,
		0xA5B3A0E6C7C582C2ULL,
		0x701753C7081F04FBULL,
		0x21BCEA57288E58D2ULL,
		0xC5716FD9A4CAF397ULL,
		0xB1F5708817974205ULL,
		0x9A7E958D82ACC7F3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x44802402F0139004ULL,
		0x034253C41619C000ULL,
		0x81038082C58100C2ULL,
		0x10124283080F0413ULL,
		0x202CE215000E48D0ULL,
		0x00314CD124484291ULL,
		0x1044508015160200ULL,
		0x80168581000C0323ULL
	}};
	printf("Test Case 111\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 111 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -111;
	} else {
		printf("Test Case 111 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x67EDC972B2103227ULL,
		0x198083C25AEE9692ULL,
		0xCD901DF1CF3F4600ULL,
		0x108FB0CC1C4781E7ULL,
		0xD257BAD29BF8EC5FULL,
		0x3421EF1EF5EE568EULL,
		0x936EF156F67048F4ULL,
		0x70A4B4EC11406E0AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA4DC141EE5B2F4B9ULL,
		0x8369FD0A26E1DA16ULL,
		0x1F5E6691F911855EULL,
		0x72F96127152DAED2ULL,
		0x8854201EACD0C1BAULL,
		0x8BD4836387986F93ULL,
		0xED1952319E950EB1ULL,
		0x835A907BEC8C1B22ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x24CC0012A0103021ULL,
		0x0100810202E09212ULL,
		0x0D100491C9110400ULL,
		0x10892004140580C2ULL,
		0x8054201288D0C01AULL,
		0x0000830285884682ULL,
		0x81085010961008B0ULL,
		0x0000906800000A02ULL
	}};
	printf("Test Case 112\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 112 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -112;
	} else {
		printf("Test Case 112 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x05DB70AE29590EE0ULL,
		0x05133A45746173D0ULL,
		0x0F92761E629B6F4FULL,
		0xF669C01DB7BD95BFULL,
		0x0EC81A20CA604A0CULL,
		0xC54EE36BB91C8DCEULL,
		0x632D0D4C996D109BULL,
		0x9AAEF8A6967B05FDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x71F30B525EA0AF0FULL,
		0x445C450CE3B306C0ULL,
		0xAEB3F417B9833CFBULL,
		0x02B07D3A103D237BULL,
		0x89118D3111B4DCABULL,
		0x975F2443DFE907FEULL,
		0xDDDF1188BF343D3CULL,
		0xE582376A7BFF6E52ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x01D3000208000E00ULL,
		0x04100004602102C0ULL,
		0x0E92741620832C4BULL,
		0x02204018103D013BULL,
		0x0800082000204808ULL,
		0x854E2043990805CEULL,
		0x410D010899241018ULL,
		0x80823022127B0450ULL
	}};
	printf("Test Case 113\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 113 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -113;
	} else {
		printf("Test Case 113 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE970D21937924972ULL,
		0x0AF0ED517498399DULL,
		0x1D5F6F61158CEC90ULL,
		0x5A90D64685337ED2ULL,
		0x3EBAE447B52E5BD4ULL,
		0x22060564C0114CC0ULL,
		0x3FE7F24339CCB53EULL,
		0xBD13C8374D274AE0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA14B5DC3CA85B9E1ULL,
		0x5627A3796BC0CC27ULL,
		0x1A338F6D1D157C42ULL,
		0x6554EF4AE3D0DEDCULL,
		0xAADFB4FCC164C789ULL,
		0xD57BDDA973E3796EULL,
		0x945A6D83AC68E50AULL,
		0x675B9993E92B59BFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA140500102800960ULL,
		0x0220A15160800805ULL,
		0x18130F6115046C00ULL,
		0x4010C64281105ED0ULL,
		0x2A9AA44481244380ULL,
		0x0002052040014840ULL,
		0x144260032848A50AULL,
		0x25138813492348A0ULL
	}};
	printf("Test Case 114\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 114 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -114;
	} else {
		printf("Test Case 114 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0DFA40CE8545E4C1ULL,
		0x431514BD0F5A286EULL,
		0xA2F0895B8A4CE896ULL,
		0xF562D02867136D11ULL,
		0xCB17BE685ED742ECULL,
		0xF538E87DB0B7118BULL,
		0xF170ED30AD9F369DULL,
		0xC21001B345B31D78ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF5858C9F86943BAAULL,
		0xD320DDC38D8BBBB6ULL,
		0x7540671AD411150AULL,
		0xF1951C55FC8C68D6ULL,
		0xF2FEB0DEB00C10B1ULL,
		0x6AAC4C5F90DFEB33ULL,
		0x557CA2FFF378EBD4ULL,
		0x57A30C3579D2D0A2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0580008E84042080ULL,
		0x430014810D0A2826ULL,
		0x2040011A80000002ULL,
		0xF100100064006810ULL,
		0xC216B048100400A0ULL,
		0x6028485D90970103ULL,
		0x5170A030A1182294ULL,
		0x4200003141921020ULL
	}};
	printf("Test Case 115\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 115 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -115;
	} else {
		printf("Test Case 115 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4B74C0B88FE21A99ULL,
		0x123F2AAEC52B9C3CULL,
		0x1990BD122355C50AULL,
		0xB8CF5AB3A7F598E6ULL,
		0xDF7A87823D74BE46ULL,
		0x4FC84CC0CF2FFA62ULL,
		0xAEA36A4B4B031FCFULL,
		0x557530FD8AEFB1B9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x559939CAABABD49FULL,
		0x591F63C6E4A5890FULL,
		0x91F9EF210AA4D123ULL,
		0xB8E2698E91177C17ULL,
		0xD1FBF3480085794FULL,
		0x5741752BCAF1035FULL,
		0x6C8093F313C14F08ULL,
		0x3F23C5FC96F84C44ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x411000888BA21099ULL,
		0x101F2286C421880CULL,
		0x1190AD000204C102ULL,
		0xB8C2488281151806ULL,
		0xD17A830000043846ULL,
		0x47404400CA210242ULL,
		0x2C80024303010F08ULL,
		0x152100FC82E80000ULL
	}};
	printf("Test Case 116\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 116 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -116;
	} else {
		printf("Test Case 116 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x229AC25ADF999AE3ULL,
		0x8E8B9772BF3B6BB6ULL,
		0x3319CDA1C5E853A2ULL,
		0xE082D5B026F5CEB8ULL,
		0xE99310C62DE888B6ULL,
		0x331609550458D16CULL,
		0xFBB3D162BABA83F4ULL,
		0xC699AA0DE1B21F9CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4DAA151F46A8C0E4ULL,
		0xA48B8B3E75795725ULL,
		0x6299476F07F0773CULL,
		0x485D6D3FBAB18770ULL,
		0x9B6F263271DFCD1CULL,
		0xC55D9AE53B345894ULL,
		0x5D369185F2EADEFCULL,
		0x61C1DA8B88A8D05BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x008A001A468880E0ULL,
		0x848B833235394324ULL,
		0x2219452105E05320ULL,
		0x4000453022B18630ULL,
		0x8903000221C88814ULL,
		0x0114084500105004ULL,
		0x59329100B2AA82F4ULL,
		0x40818A0980A01018ULL
	}};
	printf("Test Case 117\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 117 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -117;
	} else {
		printf("Test Case 117 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCF67DEAE1BF4482FULL,
		0xCCF4B4FFF500F53AULL,
		0x07BD383FDA152076ULL,
		0x47F79D9A76813F98ULL,
		0x7A165DFC5ACBF440ULL,
		0x3DA04B81CFBBF3C0ULL,
		0x0BE699A3405DFB1BULL,
		0x6F966D797FBA8EF8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDC6DAC8AFC5A4BFCULL,
		0xA7A2420ABDA9FA26ULL,
		0x2CAC75B05903ED20ULL,
		0x577628F926AEA000ULL,
		0x8669C3B228A2EA3CULL,
		0xB3ADA417772071BBULL,
		0xC5DCFB8A26D7C3A8ULL,
		0x2143D5BF970B0EE6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCC658C8A1850482CULL,
		0x84A0000AB500F022ULL,
		0x04AC303058012020ULL,
		0x4776089826802000ULL,
		0x020041B00882E000ULL,
		0x31A0000147207180ULL,
		0x01C499820055C308ULL,
		0x21024539170A0EE0ULL
	}};
	printf("Test Case 118\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 118 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -118;
	} else {
		printf("Test Case 118 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA28DDAA172688410ULL,
		0x430746550116B2DBULL,
		0x5C89C9ADC1B465E9ULL,
		0xC1E66C7A1651306FULL,
		0xA4A05B3532D251C4ULL,
		0xB3671D4751F6AACFULL,
		0xAB6FD7E6B7FECF25ULL,
		0xA1411A651A2C3696ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDFBD6F2DD208B8D9ULL,
		0xB747FDDA04F026F0ULL,
		0x6B94FE3F3BF84AB1ULL,
		0xA1C78AC62A5354DEULL,
		0x254350F090AFE9C5ULL,
		0x6CAC2A496C71D58AULL,
		0x706B5A6C602380B1ULL,
		0x67113D7C2F422719ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x828D4A2152088010ULL,
		0x03074450001022D0ULL,
		0x4880C82D01B040A1ULL,
		0x81C608420251104EULL,
		0x24005030108241C4ULL,
		0x202408414070808AULL,
		0x206B526420228021ULL,
		0x210118640A002610ULL
	}};
	printf("Test Case 119\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 119 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -119;
	} else {
		printf("Test Case 119 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFEA925283FA5A031ULL,
		0x5902E3F975860DABULL,
		0x2F9CE86CD58E40F0ULL,
		0x0E0E580E4D82524BULL,
		0xEACE7DEA61C61577ULL,
		0xEEA01FC51F272E10ULL,
		0xDB7766C03E2B3F9EULL,
		0x02BC41416D2189B6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB147741EF60F984EULL,
		0x919DA3269B3A7F5EULL,
		0x967496A37CC81ACEULL,
		0x9044ECC70E647A78ULL,
		0x0663AE249A53C5A4ULL,
		0xAB2BFA1A5D4BACAFULL,
		0x4BCD49127F4A5183ULL,
		0x2C45475B499B1B13ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB001240836058000ULL,
		0x1100A32011020D0AULL,
		0x06148020548800C0ULL,
		0x000448060C005248ULL,
		0x02422C2000420524ULL,
		0xAA201A001D032C00ULL,
		0x4B4540003E0A1182ULL,
		0x0004414149010912ULL
	}};
	printf("Test Case 120\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 120 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -120;
	} else {
		printf("Test Case 120 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x57CC9A17DE48DBB7ULL,
		0x81130B977F8BDCB9ULL,
		0x682CD1C1C1C52E00ULL,
		0xB92C57CF3EA0E0D9ULL,
		0x0201EE7CC77C8165ULL,
		0x932A90900E8B3A28ULL,
		0xEDA4007914FC940FULL,
		0x936A15545561A0E8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDB3F3BFB833D9C4FULL,
		0x05670D58F94C50CAULL,
		0x2C7267DD89E2DD24ULL,
		0xAF90D4980CAF1CCFULL,
		0xA257AEB70660564AULL,
		0xBA9D61DDF0EC1DC5ULL,
		0xC6604CEA924C76EDULL,
		0x730FC5FC349B4669ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x530C1A1382089807ULL,
		0x0103091079085088ULL,
		0x282041C181C00C00ULL,
		0xA90054880CA000C9ULL,
		0x0201AE3406600040ULL,
		0x9208009000881800ULL,
		0xC4200068104C140DULL,
		0x130A055414010068ULL
	}};
	printf("Test Case 121\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 121 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -121;
	} else {
		printf("Test Case 121 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE8D86136704A943AULL,
		0x06D0B990ABEE93A2ULL,
		0xBF70BC036047833AULL,
		0x90BFA889C07FE82AULL,
		0x7490A2C480D739F5ULL,
		0xF97EDD2A33D689D6ULL,
		0xF6A85A11581775EBULL,
		0xED0FD9FB64254B7DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8AA0D939C5295C00ULL,
		0x8982A83DBAB62F99ULL,
		0x53FBA0404E985925ULL,
		0x52EAB87DECC0929BULL,
		0x8094BB20F2BA9E58ULL,
		0x5756BEF966721576ULL,
		0x7553C60C3AE2CD06ULL,
		0x9E1F225D9A734BAFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8880413040081400ULL,
		0x0080A810AAA60380ULL,
		0x1370A00040000120ULL,
		0x10AAA809C040800AULL,
		0x0090A20080921850ULL,
		0x51569C2822520156ULL,
		0x7400420018024502ULL,
		0x8C0F005900214B2DULL
	}};
	printf("Test Case 122\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 122 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -122;
	} else {
		printf("Test Case 122 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x210D18122B9D0CE9ULL,
		0xFF3E966AB1BC5F32ULL,
		0xE083F1A4462C2D3DULL,
		0x248BC93F3EF81E11ULL,
		0xCF830C66501D0B7FULL,
		0x3E76732333D95751ULL,
		0xE85604D521731CFBULL,
		0x1BEE236DF7DAEA5CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEC22F18D32078329ULL,
		0x49A7EDE54256E12BULL,
		0x2FAB66BE152E79BEULL,
		0x3F2BAD91DFEE8B1FULL,
		0x921EE17F5A8C7E8AULL,
		0xB6F32888453253D9ULL,
		0xFDCA8DFF590A4056ULL,
		0x81402ECDD2D4DB67ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2000100022050029ULL,
		0x4926846000144122ULL,
		0x208360A4042C293CULL,
		0x240B89111EE80A11ULL,
		0x82020066500C0A0AULL,
		0x3672200001105351ULL,
		0xE84204D501020052ULL,
		0x0140224DD2D0CA44ULL
	}};
	printf("Test Case 123\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 123 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -123;
	} else {
		printf("Test Case 123 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x637E3A60941EB89CULL,
		0x0D03CE02B25B285BULL,
		0xF2FB6BB5746DA6E2ULL,
		0x5DB885A781C85314ULL,
		0x783BEEB279D21A45ULL,
		0xC7582212F22CF304ULL,
		0x41FA585A6E9B161AULL,
		0x02D9DD27A99164FCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4037D0962AE4660FULL,
		0xB11486BF9FEBA506ULL,
		0x817A8EF45164BFC6ULL,
		0x2C1D8FD66CCDE312ULL,
		0x44D4B191764B9882ULL,
		0x636E0493BC6D6C15ULL,
		0x9BCB1C48FB60D4BFULL,
		0x54AEC6129E878D50ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x403610000004200CULL,
		0x01008602924B2002ULL,
		0x807A0AB45064A6C2ULL,
		0x0C18858600C84310ULL,
		0x4010A09070421800ULL,
		0x43480012B02C6004ULL,
		0x01CA18486A00141AULL,
		0x0088C40288810450ULL
	}};
	printf("Test Case 124\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 124 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -124;
	} else {
		printf("Test Case 124 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC9CB8500E688D346ULL,
		0xB47EB703A78AD781ULL,
		0x10B3AC6E62015927ULL,
		0x8E3D9DBD228B2636ULL,
		0xF9A3375286E06BD4ULL,
		0xC3C356704FE3697BULL,
		0x3BEEE4F20AC9AE48ULL,
		0xCCC6343A8D9DDFF9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x47A2F0C1BB99A062ULL,
		0x3266021638B20448ULL,
		0x458EF889437E7179ULL,
		0x0572811B5251408FULL,
		0x2FCCA26EB1E82923ULL,
		0x5C24262D9604E152ULL,
		0x6ADCFCF64C28838FULL,
		0x433114839311D438ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x41828000A2888042ULL,
		0x3066020220820400ULL,
		0x0082A80842005121ULL,
		0x0430811902010006ULL,
		0x2980224280E02900ULL,
		0x4000062006006152ULL,
		0x2ACCE4F208088208ULL,
		0x400014028111D438ULL
	}};
	printf("Test Case 125\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 125 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -125;
	} else {
		printf("Test Case 125 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x69D8A03ABE12BE6FULL,
		0x389EEAF6E6B619B2ULL,
		0x2FEE0C864CAE8760ULL,
		0xC61044D2C0AA2DD3ULL,
		0xA5592D4077DBAA39ULL,
		0x0504CB15F2E7668EULL,
		0x6AF3CD9CD81C164AULL,
		0x895D6E169D1E9977ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC46271CA41A8AE30ULL,
		0x374B005505B73E8FULL,
		0xE61CC351173944C5ULL,
		0x73394C8161939EF0ULL,
		0x79FC8E604F736395ULL,
		0x36CE43E1C3502456ULL,
		0xEBB3FEB45D7C41B6ULL,
		0x38385C9C3EC62253ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4040200A0000AE20ULL,
		0x300A005404B61882ULL,
		0x260C000004280440ULL,
		0x4210448040820CD0ULL,
		0x21580C4047532211ULL,
		0x04044301C2402406ULL,
		0x6AB3CC94581C0002ULL,
		0x08184C141C060053ULL
	}};
	printf("Test Case 126\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 126 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -126;
	} else {
		printf("Test Case 126 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x26496256A9BA6877ULL,
		0xE82C4FF3732B3D81ULL,
		0x5FB26A34C3751EFFULL,
		0xA3045BBF0347A278ULL,
		0x7BC9C36C59156ED8ULL,
		0x4DF4D17CCE2AC84BULL,
		0xCD4C49455E2F505FULL,
		0xCD6BA9A90B34AB6BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x158942FC2BF93728ULL,
		0x468FE5D496BB24F1ULL,
		0x98B80D8B347A73A5ULL,
		0x9A5DD9ED79AC860AULL,
		0x98F735A32BE79D64ULL,
		0x737CAF28F70BB5EDULL,
		0x64174FF92BFC4CFAULL,
		0xCA2622AE8FF3FF35ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0409425429B82020ULL,
		0x400C45D0122B2481ULL,
		0x18B00800007012A5ULL,
		0x820459AD01048208ULL,
		0x18C1012009050C40ULL,
		0x41748128C60A8049ULL,
		0x440449410A2C405AULL,
		0xC82220A80B30AB21ULL
	}};
	printf("Test Case 127\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 127 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -127;
	} else {
		printf("Test Case 127 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3BDF3DD6C1F40E1CULL,
		0x1A2A64CB09919F92ULL,
		0x893EB1A26B84C2BBULL,
		0x8740C256441E1401ULL,
		0xDC2BEF645B873B22ULL,
		0x5EA4AF79CCCCE7EFULL,
		0xC67DBB7AEBEA688CULL,
		0x26A6F199FD917663ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2F8F304EDC66A49CULL,
		0x6C3C920E9F2C927CULL,
		0x820C5F55ACB94F1AULL,
		0x3BF1FBBEA3D67DFFULL,
		0xB09CEFBD171EE6B3ULL,
		0xE70E77CD35F69C67ULL,
		0x767C61F98F7425C1ULL,
		0xED2DE6C5B29C5CBDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2B8F3046C064041CULL,
		0x0828000A09009210ULL,
		0x800C11002880421AULL,
		0x0340C21600161401ULL,
		0x9008EF2413062222ULL,
		0x4604274904C48467ULL,
		0x467C21788B602080ULL,
		0x2424E081B0905421ULL
	}};
	printf("Test Case 128\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 128 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -128;
	} else {
		printf("Test Case 128 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x23AD2ACE6DD3D3D8ULL,
		0x8197D6B666DD5950ULL,
		0xBBB92D228F4651A2ULL,
		0xA171E8E7797548F3ULL,
		0x3625DCB16857A83CULL,
		0x2BD9BCEF4450A082ULL,
		0xCC07148D4006358DULL,
		0x0C155B6C43C8CAFCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x823121DE117DDEB3ULL,
		0x2D277721A1707FE9ULL,
		0x0551DD61F34FA9D6ULL,
		0x664CB7A79CFE7DEFULL,
		0x572E41E042177DE3ULL,
		0x21347AFC2162CEB8ULL,
		0x944C40AE2AFD5D95ULL,
		0xDF87E534176F6159ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x022120CE0151D290ULL,
		0x0107562020505940ULL,
		0x01110D2083460182ULL,
		0x2040A0A7187448E3ULL,
		0x162440A040172820ULL,
		0x211038EC00408080ULL,
		0x8404008C00041585ULL,
		0x0C05412403484058ULL
	}};
	printf("Test Case 129\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 129 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -129;
	} else {
		printf("Test Case 129 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8DDF1A20EDCA60B6ULL,
		0xC284D9A70F86CBECULL,
		0x8286F8E9F101AA17ULL,
		0xBEF3410552664B3DULL,
		0x7673EB57B172804AULL,
		0x7507284D6B9F9BBFULL,
		0x6143EB474396E2EFULL,
		0xE836A01A70FA3EC9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0FD4519F0830BA1FULL,
		0x70E7D2DCE41C8000ULL,
		0x19D3484E155F67FFULL,
		0x7D5BDE262F2FE600ULL,
		0xBDB9D9DD97D43FE7ULL,
		0x69F86B48E0E3644DULL,
		0x7D131E695A681552ULL,
		0xD4366840D7B65EF3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0DD4100008002016ULL,
		0x4084D08404048000ULL,
		0x0082484811012217ULL,
		0x3C53400402264200ULL,
		0x3431C95591500042ULL,
		0x610028486083000DULL,
		0x61030A4142000042ULL,
		0xC036200050B21EC1ULL
	}};
	printf("Test Case 130\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 130 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -130;
	} else {
		printf("Test Case 130 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA8780A3B3BD1ACBBULL,
		0x0C882BE0A630E85AULL,
		0x96764A678175A6A7ULL,
		0xA996A4A459E20C5BULL,
		0x843E367BFC191511ULL,
		0x27260341283B36C5ULL,
		0xC346D8F23EF64C3BULL,
		0xD86EE97F0B14D941ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x945E03DB5C8B624BULL,
		0x2D828CF106DE233EULL,
		0x5C1D6B00C74F360BULL,
		0x898AE4ED6B9273A9ULL,
		0x208598BA4E359E8DULL,
		0xD6FC0752AC705B46ULL,
		0xB6934F07C76D6FB0ULL,
		0xD8B13AA831A88049ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8058021B1881200BULL,
		0x0C8008E00610201AULL,
		0x14144A0081452603ULL,
		0x8982A4A449820009ULL,
		0x0004103A4C111401ULL,
		0x0624034028301244ULL,
		0x8202480206644C30ULL,
		0xD820282801008041ULL
	}};
	printf("Test Case 131\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 131 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -131;
	} else {
		printf("Test Case 131 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB8B6048BCC20AA2FULL,
		0x08F1A49C908BB8BAULL,
		0x6A85A0079F2224D0ULL,
		0x52B5D484B73C4D5FULL,
		0xBE401B7E40C199B7ULL,
		0x5D3259E3A482A259ULL,
		0x8822BD827C68DF5BULL,
		0x5C181427F778DF01ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDD1899F58AAF044EULL,
		0x6964776925D5F3BEULL,
		0x1BDD11F25D18655BULL,
		0xC5FE9CDAB0099D8EULL,
		0x70DF59A81F0B5328ULL,
		0x7C66B12019FE366DULL,
		0x89E14E5AEB335852ULL,
		0x84AC317404D87E54ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x981000818820000EULL,
		0x086024080081B0BAULL,
		0x0A8500021D002450ULL,
		0x40B49480B0080D0EULL,
		0x3040192800011120ULL,
		0x5C22112000822249ULL,
		0x88200C0268205852ULL,
		0x0408102404585E00ULL
	}};
	printf("Test Case 132\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 132 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -132;
	} else {
		printf("Test Case 132 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x54DCA6941973F743ULL,
		0x773F01A9E35B3254ULL,
		0x8DADCDCE22C8C4AAULL,
		0x8A3FEB27D0A98BB0ULL,
		0x0DC852C04A51BF13ULL,
		0xB7658F2E28029A9CULL,
		0xEF3605A5F7C46211ULL,
		0x3BAFFC24C9902AFCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7C36BFA061F75F76ULL,
		0x97AF66C13A3E6C78ULL,
		0xE7C9CC5FC01AC94FULL,
		0x835B5F526AD49A8AULL,
		0x06B8085867441BFAULL,
		0x18318FEAE606E335ULL,
		0xBEE60AE62756DEDEULL,
		0x2E8B1DA2E23C2CEDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5414A68001735742ULL,
		0x172F0081221A2050ULL,
		0x8589CC4E0008C00AULL,
		0x821B4B0240808A80ULL,
		0x0488004042401B12ULL,
		0x10218F2A20028214ULL,
		0xAE2600A427444210ULL,
		0x2A8B1C20C01028ECULL
	}};
	printf("Test Case 133\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 133 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -133;
	} else {
		printf("Test Case 133 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x69EC9C7B3B35E154ULL,
		0x197398067A207E2BULL,
		0xB764A2CFAA4508ACULL,
		0x12CB257892EB0F8DULL,
		0x405B65F429B05D18ULL,
		0x8A1F3912DA6EAC5EULL,
		0xD80A2179645BE582ULL,
		0xAB81EBFCA4E81A59ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9CB0221F3D15388BULL,
		0xD6639945E4ED3DF4ULL,
		0xE58F97169827BDEDULL,
		0xB79D8DB05D88C9ADULL,
		0xD9045973102F35F1ULL,
		0x40DE75D7EA3216E6ULL,
		0xACCAF55EF7E1CA99ULL,
		0x2FED613982BE334AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x08A0001B39152000ULL,
		0x1063980460203C20ULL,
		0xA5048206880508ACULL,
		0x128905301088098DULL,
		0x4000417000201510ULL,
		0x001E3112CA220446ULL,
		0x880A21586441C080ULL,
		0x2B81613880A81248ULL
	}};
	printf("Test Case 134\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 134 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -134;
	} else {
		printf("Test Case 134 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD6A910091217224FULL,
		0x26BDA6491FD40397ULL,
		0x1EEAECF6472D0F4FULL,
		0xAFFCC17C2FECF5A2ULL,
		0xAACA8936966C1D4FULL,
		0xB9D4FDFA85AC01DEULL,
		0x957576231D85ECDFULL,
		0x231EEB087345A8E6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x867C36EAAEE6F12EULL,
		0x769B3D0CA3236FA8ULL,
		0x34AA04D03ABFE070ULL,
		0xCA7F6AE669F3093DULL,
		0x1F442B068483C691ULL,
		0x524C10A03943980BULL,
		0xFBFEF3ADCD3508E6ULL,
		0xCF0EF7A5228CBC7DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x862810080206200EULL,
		0x2699240803000380ULL,
		0x14AA04D0022D0040ULL,
		0x8A7C406429E00120ULL,
		0x0A40090684000401ULL,
		0x104410A00100000AULL,
		0x917472210D0508C6ULL,
		0x030EE3002204A864ULL
	}};
	printf("Test Case 135\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 135 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -135;
	} else {
		printf("Test Case 135 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0DA7A2E00483C210ULL,
		0x745609B5E81A1D08ULL,
		0x0C1F2E007DA1786BULL,
		0x84C8633F2903B2C8ULL,
		0x46F2526A8B265A57ULL,
		0x670EA75FA13A9101ULL,
		0x03DD2C55A1BC7CB7ULL,
		0xC0F9A2705F689C90ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC7C955C057C56A03ULL,
		0x62A5C72923536B9CULL,
		0x132BD1BD594B5B3AULL,
		0x4AA2B74B72E07218ULL,
		0x2939F16AAE624A7CULL,
		0x0133BA4E32E4110CULL,
		0xDB904AB5023CC2E3ULL,
		0x70D8723B0EA52144ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x058100C004814200ULL,
		0x6004012120120908ULL,
		0x000B00005901582AULL,
		0x0080230B20003208ULL,
		0x0030506A8A224A54ULL,
		0x0102A24E20201100ULL,
		0x03900815003C40A3ULL,
		0x40D822300E200000ULL
	}};
	printf("Test Case 136\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 136 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -136;
	} else {
		printf("Test Case 136 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x990A0E748693AF2AULL,
		0xB8127EA0C46F37C0ULL,
		0x64C970D12A361937ULL,
		0x23060EE34DB80DFCULL,
		0xA96FBFDA790E8B76ULL,
		0xF46924E60C94018CULL,
		0xC1782137BAE77E5FULL,
		0xEE950F0FE22C2573ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEC93B427D8809B05ULL,
		0x7E56303F671CB0B1ULL,
		0x1250208FBA3C940DULL,
		0x6AFEB5EEF378D881ULL,
		0xD90B321EA2C3EE3FULL,
		0x1CC1A9A4ACBBD06AULL,
		0x3DDB5E08C1ACDFF5ULL,
		0x73AD1DD6EC018131ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8802042480808B00ULL,
		0x38123020440C3080ULL,
		0x004020812A341005ULL,
		0x220604E241380880ULL,
		0x890B321A20028A36ULL,
		0x144120A40C900008ULL,
		0x0158000080A45E55ULL,
		0x62850D06E0000131ULL
	}};
	printf("Test Case 137\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 137 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -137;
	} else {
		printf("Test Case 137 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF45BEDAE352B85EFULL,
		0x1C7DD5A9E00D283FULL,
		0x363A0504CFCFFD12ULL,
		0xCB91C1145BB869BEULL,
		0x373C1D15A2E56B1EULL,
		0xD2420B80AB5F5D68ULL,
		0x30A2393839C7613BULL,
		0x7907E44BCB548F6AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA9DD58750F70127EULL,
		0xE1E7D39B42D794D2ULL,
		0xD40D04FE44DE0C35ULL,
		0x31B0790CB1247050ULL,
		0xF320F31569D7AF75ULL,
		0x010EC8AE38C435F1ULL,
		0x15EC9D26A202FE8CULL,
		0xA61F0501584190A7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA05948240520006EULL,
		0x0065D18940050012ULL,
		0x1408040444CE0C10ULL,
		0x0190410411206010ULL,
		0x3320111520C52B14ULL,
		0x0002088028441560ULL,
		0x10A0192020026008ULL,
		0x2007040148408022ULL
	}};
	printf("Test Case 138\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 138 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -138;
	} else {
		printf("Test Case 138 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x56E1FB7D112FFA09ULL,
		0x5A9D9C6781F2E43DULL,
		0x0F7020E175AFA469ULL,
		0x7AB682C2EF4094A2ULL,
		0x6CD46C277719B6F9ULL,
		0x58C18AE207A381F0ULL,
		0x338981BFB6377291ULL,
		0x14AC6686CD1116FEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEDD4340626043BCAULL,
		0x8F9C7B0B5F05227CULL,
		0x4A43754724869697ULL,
		0x9D381250354FD9ACULL,
		0x72A3B8C1C63E7166ULL,
		0xCE9BFA46CF286050ULL,
		0x4AA4030DDDE1FFA9ULL,
		0xE6B5D895ABC608F6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x44C0300400043A08ULL,
		0x0A9C18030100203CULL,
		0x0A40204124868401ULL,
		0x18300240254090A0ULL,
		0x6080280146183060ULL,
		0x48818A4207200050ULL,
		0x0280010D94217281ULL,
		0x04A44084890000F6ULL
	}};
	printf("Test Case 139\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 139 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -139;
	} else {
		printf("Test Case 139 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6AE32D12201E2C8BULL,
		0x0C2A8DEBDDCD4185ULL,
		0x145B6B24DF1C4532ULL,
		0xBDCA8BBB1BCD9E37ULL,
		0x9E8B18861C948617ULL,
		0x06ED6A1D6FB1DB65ULL,
		0x275060B2961C8185ULL,
		0xEF54EE2E6C1D0F55ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x352E55F7925CF144ULL,
		0x259C285D3257EA3AULL,
		0x50407D1F676AAC12ULL,
		0x2BF087686312062CULL,
		0x5163682226CE3660ULL,
		0xE281EB5A0D2A3263ULL,
		0x66A275C4E2FBBD89ULL,
		0x7ADA37FDB87DDEBEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x20220512001C2000ULL,
		0x0408084910454000ULL,
		0x1040690447080412ULL,
		0x29C0832803000624ULL,
		0x1003080204840600ULL,
		0x02816A180D201261ULL,
		0x2600608082188181ULL,
		0x6A50262C281D0E14ULL
	}};
	printf("Test Case 140\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 140 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -140;
	} else {
		printf("Test Case 140 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x07A426874B692956ULL,
		0xDF7BF2E9C23D5586ULL,
		0xC6CCA7E22E6FABBBULL,
		0x9519581246137829ULL,
		0x0CE04570CB30A302ULL,
		0x925492178A4C2D2DULL,
		0xFEE87118043516D6ULL,
		0xCCD483B5467F8B55ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x783ED0C9897C58A4ULL,
		0x46535646F5C2A97EULL,
		0x7EE20F6410D2C861ULL,
		0x886190550AEF41B5ULL,
		0xB79BD9782ADD8332ULL,
		0xE05214D0A887868CULL,
		0x033D989FCD2C2364ULL,
		0x99B8E26306426C65ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0024008109680804ULL,
		0x46535240C0000106ULL,
		0x46C0076000428821ULL,
		0x8001101002034021ULL,
		0x048041700A108302ULL,
		0x805010108804040CULL,
		0x0228101804240244ULL,
		0x8890822106420845ULL
	}};
	printf("Test Case 141\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 141 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -141;
	} else {
		printf("Test Case 141 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3E6851E5BA1B1C2BULL,
		0x08BED42D619B02CAULL,
		0x03F6188AF681EFDCULL,
		0x163AA2B8480BFA47ULL,
		0x2CB01EC9B89BE9A8ULL,
		0x3AD03A3F7FF4E9E8ULL,
		0x9FC408543CDD151FULL,
		0x8E024AB9F0B8CC85ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2701245030703643ULL,
		0x1587EC2D5E9D3CB3ULL,
		0x61A1CB5693B6B65AULL,
		0x4528F9608BEC1256ULL,
		0x076CF6896890ED9DULL,
		0xAE4C9AF8343C93E0ULL,
		0xF166A957D34AE22CULL,
		0x63A48C96724E6FEBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2600004030101403ULL,
		0x0086C42D40990082ULL,
		0x01A008029280A658ULL,
		0x0428A02008081246ULL,
		0x042016892890E988ULL,
		0x2A401A38343481E0ULL,
		0x914408541048000CULL,
		0x0200089070084C81ULL
	}};
	printf("Test Case 142\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 142 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -142;
	} else {
		printf("Test Case 142 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBD6A8EDB76E361A1ULL,
		0x343C384C045E5BB7ULL,
		0x3FE19ACDD172A336ULL,
		0xCDED482CD4A8112EULL,
		0x092F9EC95503F3F2ULL,
		0x35365BD915A35DB6ULL,
		0x00816F4F8B01EC59ULL,
		0x66E292246589A5F0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF373F1F94218F5F2ULL,
		0x4CF5ED734515E063ULL,
		0x7B79C8EC1F74A8AAULL,
		0x71367F7D557993FAULL,
		0x563288629824F369ULL,
		0xEB90B0DE0537DC4CULL,
		0xA002B6F94C57C523ULL,
		0x35B6019377410D5AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB16280D9420061A0ULL,
		0x0434284004144023ULL,
		0x3B6188CC1170A022ULL,
		0x4124482C5428112AULL,
		0x002288401000F360ULL,
		0x211010D805235C04ULL,
		0x000026490801C401ULL,
		0x24A2000065010550ULL
	}};
	printf("Test Case 143\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 143 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -143;
	} else {
		printf("Test Case 143 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCEC5ED227D578789ULL,
		0x456E8FDA790419B1ULL,
		0x46BC166D2FF28956ULL,
		0x5B2856B137188B4AULL,
		0x0B40290CCDB223DDULL,
		0xBD4223DF8B333ACAULL,
		0xEDC625A912EBF5AFULL,
		0x88A03EBC940DEC6AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x220B528B2FE648E0ULL,
		0x8FF167CAE70D4567ULL,
		0x2FE610C5DBB7A806ULL,
		0xF75FBB63CFB91A94ULL,
		0x8F737A0270D82579ULL,
		0x5F6EEEE097BF19FEULL,
		0xA53209C771C19821ULL,
		0x4F731A000E7ACE4FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x020140022D460080ULL,
		0x056007CA61040121ULL,
		0x06A410450BB28806ULL,
		0x5308122107180A00ULL,
		0x0B40280040902159ULL,
		0x1D4222C0833318CAULL,
		0xA502018110C19021ULL,
		0x08201A000408CC4AULL
	}};
	printf("Test Case 144\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 144 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -144;
	} else {
		printf("Test Case 144 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0544721B9B3DBA2CULL,
		0xE97DEBA92B7D0D65ULL,
		0x8C69BDEB375ED11AULL,
		0x2A27B2844635B2D8ULL,
		0x5FE61E0008D31B30ULL,
		0x54F01F99088AA040ULL,
		0x5F457059417A43E4ULL,
		0x5F0668BEC01469BBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCC456E28906D5D2DULL,
		0x9F4099DE24D49517ULL,
		0xA0B32BBEC4B73DD1ULL,
		0xE4657B7572B29865ULL,
		0xB40F24882C7B6821ULL,
		0x7D5F5E781792D5E7ULL,
		0x807A9D8FD8768F19ULL,
		0xBA276661353D868BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x04446208902D182CULL,
		0x8940898820540505ULL,
		0x802129AA04161110ULL,
		0x2025320442309040ULL,
		0x1406040008530820ULL,
		0x54501E1800828040ULL,
		0x0040100940720300ULL,
		0x1A0660200014008BULL
	}};
	printf("Test Case 145\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 145 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -145;
	} else {
		printf("Test Case 145 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2E606A5EAD39A7FAULL,
		0x1764EE97DE59DC13ULL,
		0xDD39C00C63A8BEC4ULL,
		0x519E250184D7E75BULL,
		0xCC98B695E5F3778EULL,
		0x39004302E9079587ULL,
		0x44A52A0982B9A190ULL,
		0x89F1AD65F82E7A59ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x29CB1AE4A919B6B0ULL,
		0x1DFCAAA53A01FE98ULL,
		0xEEB9024E62A35D37ULL,
		0x3BACFD1AA84316C3ULL,
		0x8D570F433B77370CULL,
		0x7E1B5CCCFEEA4BE4ULL,
		0xF4E953F3DE5AAB74ULL,
		0x95F5D38E21E01021ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x28400A44A919A6B0ULL,
		0x1564AA851A01DC10ULL,
		0xCC39000C62A01C04ULL,
		0x118C250080430643ULL,
		0x8C1006012173370CULL,
		0x38004000E8020184ULL,
		0x44A102018218A110ULL,
		0x81F1810420201001ULL
	}};
	printf("Test Case 146\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 146 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -146;
	} else {
		printf("Test Case 146 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB7D92FD79B9A2444ULL,
		0x62D50FA46A80E92AULL,
		0xAF29294C210BB633ULL,
		0x14FD2C0D247A24C2ULL,
		0xA4BB5C3D38D58C48ULL,
		0xCA6BB1EA1FAE7250ULL,
		0xB2DA121BD8BA4A3DULL,
		0x9C6B71215CB08810ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x138AA3CB012F98FDULL,
		0xC477492A4A561347ULL,
		0xF79198484F305BC6ULL,
		0x40DCB6971E7536E4ULL,
		0x5F71565A9A396F7FULL,
		0x6571C77D94BCC0D3ULL,
		0xC2A1C4C27A56BEDDULL,
		0x55D64D8915F373D7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x138823C3010A0044ULL,
		0x405509204A000102ULL,
		0xA701084801001202ULL,
		0x00DC2405047024C0ULL,
		0x0431541818110C48ULL,
		0x4061816814AC4050ULL,
		0x8280000258120A1DULL,
		0x1442410114B00010ULL
	}};
	printf("Test Case 147\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 147 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -147;
	} else {
		printf("Test Case 147 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4AA6F513745170A7ULL,
		0x0720855E2AFE0734ULL,
		0xCF91E9A1E4CD5436ULL,
		0x925DA80D1A64BCC6ULL,
		0x129BB44F00514641ULL,
		0xE4107B8D4FD29D6EULL,
		0x495E2164B58D4C98ULL,
		0x9AC82976818919A7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD6F7C38D5CB03495ULL,
		0xCD1B4C4489CB7D5BULL,
		0xD911209DE44CD27AULL,
		0xB8411311F920404EULL,
		0xC09A4E63D3C480B1ULL,
		0x08F82D3486B16CADULL,
		0xC910F26E93BEF7FEULL,
		0xA00E3913FB5A8666ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x42A6C10154103085ULL,
		0x0500044408CA0510ULL,
		0xC9112081E44C5032ULL,
		0x9041000118200046ULL,
		0x009A044300400001ULL,
		0x0010290406900C2CULL,
		0x49102064918C4498ULL,
		0x8008291281080026ULL
	}};
	printf("Test Case 148\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 148 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -148;
	} else {
		printf("Test Case 148 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDE58E9B0E8617661ULL,
		0xB20DB5EC202EBF7BULL,
		0x4BD5C478C5707930ULL,
		0x5BCEFEF5E1BFB477ULL,
		0x4232A3B9043ECEE4ULL,
		0x3522FC9A4D94814BULL,
		0xABA34E3CE63C86BDULL,
		0xC904A1C2988EEE82ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x26D8BC5B556306DFULL,
		0xBA1A3F7B2DA4821AULL,
		0xB99296EB876FA526ULL,
		0x10E0C504924876C2ULL,
		0x968781A073DFF125ULL,
		0x57AB9BD6D12A07E6ULL,
		0xB43B6A131F206CD1ULL,
		0xDE2C99BCDEA8EE0AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0658A81040610641ULL,
		0xB20835682024821AULL,
		0x0990846885602120ULL,
		0x10C0C40480083442ULL,
		0x020281A0001EC024ULL,
		0x1522989241000142ULL,
		0xA0234A1006200491ULL,
		0xC80481809888EE02ULL
	}};
	printf("Test Case 149\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 149 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -149;
	} else {
		printf("Test Case 149 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE83B7435844B50E0ULL,
		0xA0E4CD7485444B1CULL,
		0x0A8C2B6FF5553749ULL,
		0x0ADE9C545AB24A1EULL,
		0xD5C95745A96948F6ULL,
		0xD70FA295ABDBF1F3ULL,
		0x7F38E256EAA89AB7ULL,
		0x83980E98E4AE3059ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA243542088A47414ULL,
		0x8EF6393473DCB38AULL,
		0x42A11116B7397EDFULL,
		0xE82725B5FA2342AFULL,
		0xEF19E68ED4E3B5B0ULL,
		0x76BE888C771F5BB3ULL,
		0x62BEC96CC7EC258DULL,
		0xEB0DFB482D1CB7CFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA003542080005000ULL,
		0x80E4093401440308ULL,
		0x02800106B5113649ULL,
		0x080604145A22420EULL,
		0xC5094604806100B0ULL,
		0x560E8084231B51B3ULL,
		0x6238C044C2A80085ULL,
		0x83080A08240C3049ULL
	}};
	printf("Test Case 150\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 150 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -150;
	} else {
		printf("Test Case 150 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8011F4C32894B6BAULL,
		0xF64452A115FB0E08ULL,
		0xF84E7C05FC887E72ULL,
		0xD65DE4F4827ADC98ULL,
		0x9EEB58D246BADAE1ULL,
		0x1BD954FBC8E8A73EULL,
		0x129D72705EF185F1ULL,
		0xD580E12680298BC7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCAD61190EF6619D2ULL,
		0x03F3066906C8E676ULL,
		0xCF208E6D4F1ABD1CULL,
		0x5E9C0C4F8A147BAEULL,
		0x75460DD7B5BF15A4ULL,
		0x44CC781CE5AA4400ULL,
		0x07C18C07BDB859F5ULL,
		0x613F162CAFED6E59ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8010108028041092ULL,
		0x0240022104C80600ULL,
		0xC8000C054C083C10ULL,
		0x561C044482105888ULL,
		0x144208D204BA10A0ULL,
		0x00C85018C0A80400ULL,
		0x028100001CB001F1ULL,
		0x4100002480290A41ULL
	}};
	printf("Test Case 151\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 151 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -151;
	} else {
		printf("Test Case 151 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0FCA2386AA6784C2ULL,
		0x902B71EE97DF56B3ULL,
		0x30FF670ABDB3B6E4ULL,
		0x0DA498182301C6A4ULL,
		0x6B997073FA64922EULL,
		0x08305A8EF73D2BD7ULL,
		0xEDBCFE3C90449379ULL,
		0x242EC7FE666CFB98ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0CDC2A01A0FC8BEFULL,
		0x813F3B7590C519B4ULL,
		0xB6DE0AD87C176967ULL,
		0x4CDC88C8BFDD1D2DULL,
		0xCDB90FA0963B6245ULL,
		0x952CC4CD40054B9FULL,
		0x236CF094BC81F4D6ULL,
		0xCC454950A459809EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0CC82200A06480C2ULL,
		0x802B316490C510B0ULL,
		0x30DE02083C132064ULL,
		0x0C84880823010424ULL,
		0x4999002092200204ULL,
		0x0020408C40050B97ULL,
		0x212CF01490009050ULL,
		0x0404415024488098ULL
	}};
	printf("Test Case 152\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 152 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -152;
	} else {
		printf("Test Case 152 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xABD78D8AA0E8CCBDULL,
		0x79969E35852080B5ULL,
		0xFB4EB8891C0A001BULL,
		0xC65ABE6DD5FDD5BAULL,
		0x755B9B62E51AB77FULL,
		0x50B0519BA2D5A4A0ULL,
		0x975998A1A136CA91ULL,
		0x4AAAF551AEC5EDF3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4B466E1259ECBB12ULL,
		0xE02618A1DDAE63DFULL,
		0x3634D087801E329AULL,
		0x4C66203C33694165ULL,
		0x0DF7638CFC74C48CULL,
		0x6C422CC2369BE394ULL,
		0x9ECE329C321182A6ULL,
		0x4C3EB0C318EEE0FFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0B460C0200E88810ULL,
		0x6006182185200095ULL,
		0x32049081000A001AULL,
		0x4442202C11694120ULL,
		0x05530300E410840CULL,
		0x400000822291A080ULL,
		0x9648108020108280ULL,
		0x482AB04108C4E0F3ULL
	}};
	printf("Test Case 153\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 153 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -153;
	} else {
		printf("Test Case 153 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE760676FA47AFCC7ULL,
		0xEF128D94B8431BCDULL,
		0xB68875C607A9E9B1ULL,
		0x2377879882F9070DULL,
		0x2D36FD6DC56A9D8CULL,
		0x2305094C0532628EULL,
		0xA1500D5D3C6D0C3EULL,
		0xBFDE2548F568EE82ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB6857D65A1EECCC7ULL,
		0xB6821B543B6EF693ULL,
		0xE411A6F3BA4CAD1CULL,
		0xFCA68B004DDB1EC0ULL,
		0x87860D82486D8775ULL,
		0x79B4CFC354F84ED0ULL,
		0x32631EBF410170B0ULL,
		0xFDF2F7BF922FDA8DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA6006565A06ACCC7ULL,
		0xA602091438421281ULL,
		0xA40024C20208A910ULL,
		0x2026830000D90600ULL,
		0x05060D0040688504ULL,
		0x2104094004304280ULL,
		0x20400C1D00010030ULL,
		0xBDD225089028CA80ULL
	}};
	printf("Test Case 154\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 154 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -154;
	} else {
		printf("Test Case 154 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBAF2A3A778829CB0ULL,
		0xD6466FC489FC171FULL,
		0xA09FDC4CEA0DA544ULL,
		0xCE18E11B9506E4E2ULL,
		0x5F31527E425CC979ULL,
		0xA5366F44AC2F8948ULL,
		0x725E28AB839AA226ULL,
		0x4770DDBF9A6E1FA1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5A457D53F7059E76ULL,
		0x24BF2C9EA15B05C2ULL,
		0x07D0A2997A231FFBULL,
		0x2C38F9A80C7E7C5BULL,
		0x8D4E703244855393ULL,
		0xB7A9528F90596359ULL,
		0x13675CFD7399093BULL,
		0x34ADC80A0F722138ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1A40210370009C30ULL,
		0x04062C8481580502ULL,
		0x009080086A010540ULL,
		0x0C18E10804066442ULL,
		0x0D00503240044111ULL,
		0xA520420480090148ULL,
		0x124608A903980022ULL,
		0x0420C80A0A620120ULL
	}};
	printf("Test Case 155\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 155 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -155;
	} else {
		printf("Test Case 155 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x31F480201A3FAD75ULL,
		0xAC5E99DAF35EA207ULL,
		0xFCEB425311B79879ULL,
		0x24E808A461948B3BULL,
		0x5AE2D93A1AEDB1EDULL,
		0x1911B1992A22EA46ULL,
		0x18E71C217EF4A6E0ULL,
		0xB1AE759EBDDA1DABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0CCA89771276AC9BULL,
		0xCC1390972B334D54ULL,
		0xDC0695BB65CE40AFULL,
		0xA0CA5E5C28511078ULL,
		0x862A7ACE763AFAC8ULL,
		0xF74541F07874FB96ULL,
		0xD9027710892BF6BFULL,
		0x1C5B53DD8606C821ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x00C080201236AC11ULL,
		0x8C12909223120004ULL,
		0xDC02001301860029ULL,
		0x20C8080420100038ULL,
		0x0222580A1228B0C8ULL,
		0x110101902820EA06ULL,
		0x180214000820A6A0ULL,
		0x100A519C84020821ULL
	}};
	printf("Test Case 156\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 156 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -156;
	} else {
		printf("Test Case 156 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x35DE08A5E380D8BCULL,
		0x010F0C70B06A2831ULL,
		0x399D23C5FA4F4665ULL,
		0x4F7A2E0C9FBA3402ULL,
		0x83C305A9AF8C9501ULL,
		0xE4F849DDF13685ADULL,
		0xD6ED1FE658665458ULL,
		0x1F21BF8E365BA257ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x50AD984794991CE2ULL,
		0x33D1A5F918E3EC9DULL,
		0xD781247CEBAC629EULL,
		0x2FAD65A0B3A566D1ULL,
		0x29EE550A39D4E66FULL,
		0xEDD25CD97C805B14ULL,
		0xBDFA7A15DBCCB533ULL,
		0x602C6C2C2B58B739ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x108C0805808018A0ULL,
		0x0101047010622811ULL,
		0x11812044EA0C4204ULL,
		0x0F28240093A02400ULL,
		0x01C2050829848401ULL,
		0xE4D048D970000104ULL,
		0x94E81A0458441410ULL,
		0x00202C0C2258A211ULL
	}};
	printf("Test Case 157\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 157 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -157;
	} else {
		printf("Test Case 157 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x578E529885979C6EULL,
		0x7A39EC1093A3BD5BULL,
		0xD86737231E3A16F7ULL,
		0x0D5C0DCE5E8C1A23ULL,
		0x46BD5500D15691A4ULL,
		0x0002A14965DE606BULL,
		0x5A129852F1BDEF20ULL,
		0xF80B96A71625E047ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC870CBB1ECFEABCAULL,
		0xC7C45AB266D43893ULL,
		0x4406FDFCB07373E7ULL,
		0x1AE9103F77536CB6ULL,
		0x8A61BFBFAA893D47ULL,
		0x61A41F65053D3507ULL,
		0x80C9764CC4B59245ULL,
		0xD67DBFA8A6AB3813ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x400042908496884AULL,
		0x4200481002803813ULL,
		0x40063520103212E7ULL,
		0x0848000E56000822ULL,
		0x0221150080001104ULL,
		0x00000141051C2003ULL,
		0x00001040C0B58200ULL,
		0xD00996A006212003ULL
	}};
	printf("Test Case 158\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 158 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -158;
	} else {
		printf("Test Case 158 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3E429DAC33EA2F3DULL,
		0x4EF39FBC29D21161ULL,
		0xAF3A7A7CE2892BB4ULL,
		0xD6149439B1F22697ULL,
		0x5D6E413B30815828ULL,
		0xCF826F7F076B065BULL,
		0x3B07281AC56DEF55ULL,
		0xE465687E835EC4C9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5DE77381313D3A49ULL,
		0x8A4FA579852665C5ULL,
		0x6BA70F474D2781E6ULL,
		0x13317EB722C584E6ULL,
		0x0D1DD1992C8F2F97ULL,
		0xD65D20DDC95EA0B2ULL,
		0xB947EB66BD427EADULL,
		0x74642D8F264D0B61ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1C42118031282A09ULL,
		0x0A43853801020141ULL,
		0x2B220A44400101A4ULL,
		0x1210143120C00486ULL,
		0x0D0C411920810800ULL,
		0xC600205D014A0012ULL,
		0x3907280285406E05ULL,
		0x6464280E024C0041ULL
	}};
	printf("Test Case 159\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 159 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -159;
	} else {
		printf("Test Case 159 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5934901B7C5CE606ULL,
		0x76CDD3D0F4CF1B6FULL,
		0x681B8C8FD1231339ULL,
		0xAD83675075E66BAAULL,
		0xC66F74C3912900ADULL,
		0xE69A18C4E2C1F77FULL,
		0x1F64AE95AE0657CAULL,
		0x5626DEDAA598DDFDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4F4CD21C36CAFAF2ULL,
		0xA9EC8A4B07FA695EULL,
		0xEA8346CB73141F6EULL,
		0x6448E7A1232A1681ULL,
		0x2FAFF94207C33A97ULL,
		0x060A253E0A1C4A63ULL,
		0xA6E9EF24D9768C34ULL,
		0x63D1B76B01304FDEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x490490183448E202ULL,
		0x20CC824004CA094EULL,
		0x6803048B51001328ULL,
		0x2400670021220280ULL,
		0x062F704201010085ULL,
		0x060A000402004263ULL,
		0x0660AE0488060400ULL,
		0x4200964A01104DDCULL
	}};
	printf("Test Case 160\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 160 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -160;
	} else {
		printf("Test Case 160 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0B717AD6681259C8ULL,
		0x9D2B74B091FB50DBULL,
		0xA17228CF51A477B0ULL,
		0x70C471E8381B5030ULL,
		0xF3AE11071C1755E7ULL,
		0xDB3A6E86687A6770ULL,
		0x33AC04935C11EC45ULL,
		0xBEC9BC81C667A61BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x971E524988BCC090ULL,
		0xC59B21E4EE795AA0ULL,
		0x0CC03E1AD33680BBULL,
		0xFB57EA54D3721C33ULL,
		0xBB0C7D3F8E68EFDFULL,
		0x0101103A50396FEBULL,
		0x67F43286264F7B62ULL,
		0x37F190AA063388FEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0310524008104080ULL,
		0x850B20A080795080ULL,
		0x0040280A512400B0ULL,
		0x7044604010121030ULL,
		0xB30C11070C0045C7ULL,
		0x0100000240386760ULL,
		0x23A4008204016840ULL,
		0x36C190800623801AULL
	}};
	printf("Test Case 161\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 161 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -161;
	} else {
		printf("Test Case 161 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2FF1F0395ADDF658ULL,
		0xE294FEAE3C15B729ULL,
		0x78BCEF10395F2753ULL,
		0x3159A40D563FE606ULL,
		0x6ECC59EE3ACA00B9ULL,
		0x363C829E6B4EE83BULL,
		0x4F0301766FFC8003ULL,
		0x8EF2EE79E406DDBEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB47CC43C3CFCFECAULL,
		0x1CCB62F902A173E3ULL,
		0xC50E0FD5B788E1FAULL,
		0xA6F1225F1A993E35ULL,
		0x0A40E43B579D584BULL,
		0xFD844B9649913BC1ULL,
		0x3DCBB2F4FF4DA2C5ULL,
		0xA4A8134DDCD0BDD6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2470C03818DCF648ULL,
		0x008062A800013321ULL,
		0x400C0F1031082152ULL,
		0x2051200D12192604ULL,
		0x0A40402A12880009ULL,
		0x3404029649002801ULL,
		0x0D0300746F4C8001ULL,
		0x84A00249C4009D96ULL
	}};
	printf("Test Case 162\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 162 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -162;
	} else {
		printf("Test Case 162 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9081B7D7F3EA3E45ULL,
		0x1F6D531311AC2FEDULL,
		0xD9FB42FCF6AB8327ULL,
		0xE09596812D51C401ULL,
		0x15A518F7AF2961D4ULL,
		0x41AC94EF2BD197BEULL,
		0x96FA6DB5AEFA6249ULL,
		0xB357B9AF9A35AAAFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x86F3B9D06BDBEB67ULL,
		0x425FD14497933311ULL,
		0x1D39F7D9AA7306F1ULL,
		0x95B378A8C0545A32ULL,
		0x509C5681450E065EULL,
		0x91EA5EF67A806F49ULL,
		0x0F507AAB03E0B599ULL,
		0xB854BF2CE2226FE3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8081B1D063CA2A45ULL,
		0x024D510011802301ULL,
		0x193942D8A2230221ULL,
		0x8091108000504000ULL,
		0x1084108105080054ULL,
		0x01A814E62A800708ULL,
		0x065068A102E02009ULL,
		0xB054B92C82202AA3ULL
	}};
	printf("Test Case 163\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 163 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -163;
	} else {
		printf("Test Case 163 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3FA3711AD885FA35ULL,
		0xE906D8E121612641ULL,
		0x8B673B86D1A27124ULL,
		0x88E7E2E1393DEC26ULL,
		0x1AF3AF1878543F91ULL,
		0x4D585BDCB3B4D42BULL,
		0x0F9D88AF0CBA36F2ULL,
		0xF1257DF09369709EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x419950FA4C888513ULL,
		0x92AD624992D20989ULL,
		0xE653A292DB9F69B3ULL,
		0xDC46A2E6AD797F15ULL,
		0x33080F4B91DC6D57ULL,
		0xA885876682F642E4ULL,
		0xBFE52A923E64832CULL,
		0x3BAD7C30F59E18B5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0181501A48808011ULL,
		0x8004404100400001ULL,
		0x82432282D1826120ULL,
		0x8846A2E029396C04ULL,
		0x12000F0810542D11ULL,
		0x0800034482B44020ULL,
		0x0F8508820C200220ULL,
		0x31257C3091081094ULL
	}};
	printf("Test Case 164\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 164 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -164;
	} else {
		printf("Test Case 164 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAD50D02AC641736EULL,
		0x7A7B18EBF5E717D9ULL,
		0x3772C64B4BB46596ULL,
		0x67CAD4D43C8590C0ULL,
		0xFD3AAF46CB1D22B1ULL,
		0xC3CE88805732D202ULL,
		0x8553ECAA29065466ULL,
		0xF43E051A56BB2893ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x061A50CA7943D1E5ULL,
		0x1043CE72D6CAB930ULL,
		0x50D11AEC529C462BULL,
		0x61FB093588C20840ULL,
		0xF703EAC1940EC7E7ULL,
		0x8CB0B9D645A4A484ULL,
		0x20FE0ADE7EA68257ULL,
		0x8D6E73C869FD6BF6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0410500A40415164ULL,
		0x10430862D4C21110ULL,
		0x1050024842944402ULL,
		0x61CA001408800040ULL,
		0xF502AA40800C02A1ULL,
		0x8080888045208000ULL,
		0x0052088A28060046ULL,
		0x842E010840B92892ULL
	}};
	printf("Test Case 165\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 165 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -165;
	} else {
		printf("Test Case 165 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x669FF412D6D9CE03ULL,
		0x214ECC9BC74A4CC1ULL,
		0x78158FB9BA2C5847ULL,
		0x9B94FD5BB2318534ULL,
		0x33CDFCFE335ECEEEULL,
		0x2AE1FD08D2C9642BULL,
		0xB11AC6E2B128DD0EULL,
		0x22C72A27A8BB4441ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE7C911E0F4FBB2B5ULL,
		0x6406CC7FE01386ABULL,
		0x8D3BD165E29D29D5ULL,
		0xCD785D8FFA77616EULL,
		0xC5E6CB33BDA131C6ULL,
		0x1B1C38BAB6371F07ULL,
		0x3FB64ADF1ADBC27EULL,
		0xE9028A669DACB5FCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x66891000D4D98201ULL,
		0x2006CC1BC0020481ULL,
		0x08118121A20C0845ULL,
		0x89105D0BB2310124ULL,
		0x01C4C832310000C6ULL,
		0x0A00380892010403ULL,
		0x311242C21008C00EULL,
		0x20020A2688A80440ULL
	}};
	printf("Test Case 166\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 166 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -166;
	} else {
		printf("Test Case 166 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x68926CBFE7A51243ULL,
		0x3109049FA20F5C87ULL,
		0x09E1C0D8277AE117ULL,
		0x899628E59BBB93DDULL,
		0xE32A94AE33CA5B38ULL,
		0x023DB105A0867608ULL,
		0x4B57BBC6F64F9A7EULL,
		0x29508C062949EF07ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x170DB75D2C646841ULL,
		0x9438D0C57D7C668EULL,
		0xA128FD4C73A70144ULL,
		0x3D319A8D1F039074ULL,
		0x7C8AB7EDF04E804CULL,
		0x7F71C8861378DB69ULL,
		0x416C4054F6DCBA47ULL,
		0x8A02C5755AC291A7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0000241D24240041ULL,
		0x10080085200C4486ULL,
		0x0120C04823220104ULL,
		0x091008851B039054ULL,
		0x600A94AC304A0008ULL,
		0x0231800400005208ULL,
		0x41440044F64C9A46ULL,
		0x0800840408408107ULL
	}};
	printf("Test Case 167\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 167 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -167;
	} else {
		printf("Test Case 167 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x99C87B7DF8B1DAE3ULL,
		0xC581AA118211A553ULL,
		0x48A78D46FEDDD891ULL,
		0x95F9D9CE84865952ULL,
		0x4A418A6610B40ADCULL,
		0x9CF3AD5FCAFA0862ULL,
		0xA2D6F0CAC056756CULL,
		0x5AB0A2D82CB11FECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB7D4BDCF9FFB4915ULL,
		0x6417C68CCCB41569ULL,
		0x61976E1EDA7A7E5FULL,
		0x46644F93668F7CA2ULL,
		0x31D9640E79FBC2C7ULL,
		0x6F8F11F6FB953344ULL,
		0x6273DA2016EF0464ULL,
		0xD0885B9912CB1DC9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x91C0394D98B14801ULL,
		0x4401820080100541ULL,
		0x40870C06DA585811ULL,
		0x0460498204865802ULL,
		0x0041000610B002C4ULL,
		0x0C830156CA900040ULL,
		0x2252D00000460464ULL,
		0x5080029800811DC8ULL
	}};
	printf("Test Case 168\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 168 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -168;
	} else {
		printf("Test Case 168 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7C97AE2E6D06E6C5ULL,
		0xA978C0C6D759FD3EULL,
		0x41B24021936C57D0ULL,
		0x4EE96D9EB54E138FULL,
		0xFF8469F704D0D702ULL,
		0xCB5C6D10E2BC8FA3ULL,
		0xA318DEFE7FCB4E28ULL,
		0xD93569C8D755C01FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x993813DE69D0831FULL,
		0xD15945ADBEA9E189ULL,
		0xE81E4B95C201BC45ULL,
		0x7A1D4AC9D36E06A1ULL,
		0x5448740A61A7BA24ULL,
		0x9563C8F3E693AC6CULL,
		0x6F9FBF321BDAFA91ULL,
		0x17854BE084908A25ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1810020E69008205ULL,
		0x815840849609E108ULL,
		0x4012400182001440ULL,
		0x4A094888914E0281ULL,
		0x5400600200809200ULL,
		0x81404810E2908C20ULL,
		0x23189E321BCA4A00ULL,
		0x110549C084108005ULL
	}};
	printf("Test Case 169\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 169 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -169;
	} else {
		printf("Test Case 169 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEC964E704DD3E9E3ULL,
		0xA0ED3205E0710F7FULL,
		0x7176A0083A33A56DULL,
		0x5D4A499BD8C18026ULL,
		0x094B733D28D2155BULL,
		0xAF0DA32FC2AD6917ULL,
		0xE445DA1F4D2A36F5ULL,
		0x1D68C06BD67A111FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF0F7FDA9CA39480ULL,
		0x69839F59E063D6FAULL,
		0x9B5D4FA1019E69C9ULL,
		0x37C535FBC2196124ULL,
		0x2A96BE49B0DE3B14ULL,
		0x354FE228D95EE3D5ULL,
		0x32002C86DAAFDAA6ULL,
		0x68839E84A553287BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAC064E500C838080ULL,
		0x20811201E061067AULL,
		0x1154000000122149ULL,
		0x1540019BC0010024ULL,
		0x0802320920D21110ULL,
		0x250DA228C00C6115ULL,
		0x20000806482A12A4ULL,
		0x080080008452001BULL
	}};
	printf("Test Case 170\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 170 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -170;
	} else {
		printf("Test Case 170 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x534F415A95A224C5ULL,
		0x2FD6A40C0197C21FULL,
		0xD1295E061BAFBAC2ULL,
		0xA00834A2397A990AULL,
		0x83A571FCB63D1D13ULL,
		0xADF43574B95D6691ULL,
		0x912216DFB4541F8AULL,
		0x34E00E40751DEA3CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC380594F646A4A21ULL,
		0xA0C312C5E9067D43ULL,
		0xA2F62EFBC9FE7F70ULL,
		0x6AE21E77BA495988ULL,
		0xD4E3EE7F6437E748ULL,
		0xD341AB0DDB3CAFF9ULL,
		0x3EA03C304225D020ULL,
		0x4B0EBB9E8A922090ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4300414A04220001ULL,
		0x20C2000401064003ULL,
		0x80200E0209AE3A40ULL,
		0x2000142238481908ULL,
		0x80A1607C24350500ULL,
		0x81402104991C2691ULL,
		0x1020141000041000ULL,
		0x00000A0000102010ULL
	}};
	printf("Test Case 171\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 171 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -171;
	} else {
		printf("Test Case 171 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD7D7CFA503CC5C83ULL,
		0xED92DA2B60637E97ULL,
		0x28758D50C6EEA0B2ULL,
		0xAB59AE88F1522A1EULL,
		0xF9E869D441D57405ULL,
		0x7E129F897882170CULL,
		0xD193922713700C7AULL,
		0x99B4DE805D79F704ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE52E09C8E4455A90ULL,
		0xA845572107596DEBULL,
		0xD1BA8C875DCEC4DBULL,
		0x22AF317B99A0F737ULL,
		0xF50821314646041AULL,
		0x388F7DE02DD67525ULL,
		0xE129AB4FB34F8DE0ULL,
		0x1DF5613E4A31A74BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC506098000445880ULL,
		0xA800522100416C83ULL,
		0x00308C0044CE8092ULL,
		0x2209200891002216ULL,
		0xF108211040440400ULL,
		0x38021D8028821504ULL,
		0xC101820713400C60ULL,
		0x19B440004831A700ULL
	}};
	printf("Test Case 172\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 172 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -172;
	} else {
		printf("Test Case 172 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3C18AC9CD3AF18ABULL,
		0xC473C6A7DD528ADAULL,
		0x2C819D2CB0603AE1ULL,
		0xF80071447AE4AAA3ULL,
		0xC815B56D51CDFCBEULL,
		0x93A3FC09C9418687ULL,
		0x0D3711B60E7390C6ULL,
		0x221E122680F02223ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xABA05E6015DDCD48ULL,
		0x274146B695E248C6ULL,
		0x759CA9981D09CF2BULL,
		0xFB68990AB3999A33ULL,
		0xE691F27F8210A1BFULL,
		0x1686F3DDECDB9461ULL,
		0xB38F0385285E8299ULL,
		0xD0A9AFBCC3140627ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x28000C00118D0808ULL,
		0x044146A6954208C2ULL,
		0x2480890810000A21ULL,
		0xF800110032808A23ULL,
		0xC011B06D0000A0BEULL,
		0x1282F009C8418401ULL,
		0x0107018408528080ULL,
		0x0008022480100223ULL
	}};
	printf("Test Case 173\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 173 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -173;
	} else {
		printf("Test Case 173 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC5A9CFD9954A2C4BULL,
		0x225DF6731A69458FULL,
		0x9D826D769F421639ULL,
		0x83BA8E59FD75909DULL,
		0xB53B194388F0CE6DULL,
		0xA9F12487EF9AE578ULL,
		0x0BF5771E2ECA0705ULL,
		0xE2052F6DE516FC6EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x64286BA61A4F5884ULL,
		0x1FB62FDF74635669ULL,
		0x902F75CBAB358FEFULL,
		0xD35DE944F021A5CDULL,
		0x347BAE02504BDA04ULL,
		0x15841D17C1BD73A3ULL,
		0x2381874AA7BF4377ULL,
		0xF01327EFA93476AFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x44284B80104A0800ULL,
		0x0214265310614409ULL,
		0x900265428B000629ULL,
		0x83188840F021808DULL,
		0x343B08020040CA04ULL,
		0x01800407C1986120ULL,
		0x0381070A268A0305ULL,
		0xE001276DA114742EULL
	}};
	printf("Test Case 174\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 174 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -174;
	} else {
		printf("Test Case 174 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x594FB7C726BB4989ULL,
		0x57E3D807A3F91193ULL,
		0x64B5F258A9115FBDULL,
		0x676CA66DE74B2739ULL,
		0xE7EB93EEE180F6FFULL,
		0x925DF5C87D2E2509ULL,
		0x4BFA0050C3690D3EULL,
		0xFA97D2A1891AF7BCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x611FA2A61B8478B9ULL,
		0xA9105AECB28105BBULL,
		0x141B3F6D15B486EAULL,
		0x9AF6351E97169F03ULL,
		0x0CC0F29F47BBB59DULL,
		0x8D2103563BE1DE5CULL,
		0x5842C2D6AC2CCA7FULL,
		0x873F7593E17096BAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x410FA28602804889ULL,
		0x01005804A2810193ULL,
		0x04113248011006A8ULL,
		0x0264240C87020701ULL,
		0x04C0928E4180B49DULL,
		0x8001014039200408ULL,
		0x484200508028083EULL,
		0x82175081811096B8ULL
	}};
	printf("Test Case 175\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 175 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -175;
	} else {
		printf("Test Case 175 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5E691C64853A42D9ULL,
		0x9ED956950C4DF9A1ULL,
		0x5F724B0270DF05A8ULL,
		0x9E807688845B3C70ULL,
		0xCFBBEA7E41ABE9CCULL,
		0x8CD00238C3DE0DCAULL,
		0x8B3D8913299128DAULL,
		0x593E22BB621628AEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDAB0E9B3D40BB553ULL,
		0x3A87C3789B6CD387ULL,
		0xF45A568A798CD5A2ULL,
		0xC795DAD1EF85F53AULL,
		0x5B6700535E6B80E4ULL,
		0x801C932AE08E9995ULL,
		0x1A3C14E7D0B62012ULL,
		0xA0AD39AE670FEC82ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5A200820840A0051ULL,
		0x1A814210084CD181ULL,
		0x54524202708C05A0ULL,
		0x8680528084013430ULL,
		0x4B230052402B80C4ULL,
		0x80100228C08E0980ULL,
		0x0A3C000300902012ULL,
		0x002C20AA62062882ULL
	}};
	printf("Test Case 176\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 176 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -176;
	} else {
		printf("Test Case 176 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD77A62CDB07582B7ULL,
		0x2402E2ED8CC90DBCULL,
		0xD2227FBE0CFC4EEDULL,
		0x6DA7C005E079A5C5ULL,
		0xB294B5A9F7900700ULL,
		0xEE2415066A8DEBB5ULL,
		0x354253DB78763D07ULL,
		0x601383FE7ACD50C5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x12F2756D8BD94BCCULL,
		0x00BD123291A6EADEULL,
		0xB91FA665C96F7F16ULL,
		0xF6268FD6EE0BBDB7ULL,
		0xDF611FF4387ACCFFULL,
		0xCEF669B028EBC79DULL,
		0x889AA18A5C48D115ULL,
		0x1BCA6A8CAA56CDB5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1272604D80510284ULL,
		0x000002208080089CULL,
		0x90022624086C4E04ULL,
		0x64268004E009A585ULL,
		0x920015A030100400ULL,
		0xCE2401002889C395ULL,
		0x0002018A58401105ULL,
		0x0002028C2A444085ULL
	}};
	printf("Test Case 177\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 177 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -177;
	} else {
		printf("Test Case 177 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x53EF998EEE2B2E1AULL,
		0xB765DF4955BC01E3ULL,
		0xA479DE1C0A44E96FULL,
		0xB4C243AB5C14E7B7ULL,
		0xBFE43289DBF52EABULL,
		0xB24F95BBB4D37312ULL,
		0xDBA4BAB3740B2FE1ULL,
		0xF1DF9B826A223913ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEAFC7047E3399B0EULL,
		0x376B92EAC23BF5F6ULL,
		0x3B1554720A66FA26ULL,
		0x06A6E6A24943C032ULL,
		0xE1C359A33D46EF6EULL,
		0x03FA103CB343D6D9ULL,
		0x2CF930CE5F844B0BULL,
		0x57FA4FD4083A4CA0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x42EC1006E2290A0AULL,
		0x37619248403801E2ULL,
		0x201154100A44E826ULL,
		0x048242A24800C032ULL,
		0xA1C0108119442E2AULL,
		0x024A1038B0435210ULL,
		0x08A0308254000B01ULL,
		0x51DA0B8008220800ULL
	}};
	printf("Test Case 178\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 178 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -178;
	} else {
		printf("Test Case 178 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB23FF8B440F7ADD9ULL,
		0x75968182A2F93A96ULL,
		0x55E155552C6AC754ULL,
		0xB183D77A364C6D21ULL,
		0x20E39B095E219963ULL,
		0x9E56E31242A89B98ULL,
		0xE0D88CE304A6D9DCULL,
		0xBDEFEA5CC9558F93ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0904B17CF264CC71ULL,
		0x52D74D85542FE75EULL,
		0x92C1B26DC0A3CBAFULL,
		0x01335857518D1602ULL,
		0x149B625EE086A32DULL,
		0xC28F2BCD352A7CABULL,
		0xB4462DCCCB912B31ULL,
		0xF605625B297A68F4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0004B03440648C51ULL,
		0x5096018000292216ULL,
		0x10C110450022C304ULL,
		0x01035052100C0400ULL,
		0x0083020840008121ULL,
		0x8206230000281888ULL,
		0xA0400CC000800910ULL,
		0xB405625809500890ULL
	}};
	printf("Test Case 179\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 179 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -179;
	} else {
		printf("Test Case 179 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAAF15662024977F9ULL,
		0x5C457244E8B8D53CULL,
		0x0415836ED99B1309ULL,
		0xF8CD19F02B098EE0ULL,
		0x77C1B49831C66B69ULL,
		0x165B5D665E27B2DAULL,
		0x6ABFED310A24432EULL,
		0xE9442CA4480458EFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAC2B4F4E86DD8FC9ULL,
		0x5B3BBB5D7FF8056BULL,
		0xE6A723C5C3629590ULL,
		0x247D85CEAC1D06CDULL,
		0x217FD9BD3DF8D477ULL,
		0x9B3A2A1534F84383ULL,
		0x68301E1A8ADE2419ULL,
		0xE25DCC86F99E6D42ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA8214642024907C9ULL,
		0x5801324468B80528ULL,
		0x04050344C1021100ULL,
		0x204D01C0280906C0ULL,
		0x2141909831C04061ULL,
		0x121A080414200282ULL,
		0x68300C100A040008ULL,
		0xE0440C8448044842ULL
	}};
	printf("Test Case 180\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 180 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -180;
	} else {
		printf("Test Case 180 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x25E217CC2E7EABF7ULL,
		0xBB3C606D980BC01CULL,
		0xB53B63EC7F83B746ULL,
		0xEDC288B232F1CD11ULL,
		0xC8CDAC0852B6DF0CULL,
		0x34F4911D88761817ULL,
		0x7FF28C128900AA79ULL,
		0xED620B114F668609ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC8A0F75C6F16C284ULL,
		0x7C6B948F3DB88E0EULL,
		0x77E4EF0C1E84B51BULL,
		0xDA15612BEDFB26E8ULL,
		0xD706ED70AF4C6E7DULL,
		0xF43516ACA875D446ULL,
		0x3F63338B7B98CC68ULL,
		0xB24BB6F96B6E350FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x00A0174C2E168284ULL,
		0x3828000D1808800CULL,
		0x3520630C1E80B502ULL,
		0xC800002220F10400ULL,
		0xC004AC0002044E0CULL,
		0x3434100C88741006ULL,
		0x3F62000209008868ULL,
		0xA04202114B660409ULL
	}};
	printf("Test Case 181\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 181 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -181;
	} else {
		printf("Test Case 181 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE1B378A2AB426C62ULL,
		0xD3DEC39573193041ULL,
		0xCB4C467EE53FA210ULL,
		0x27FCB3D0EBF92A30ULL,
		0x823F36BFC05A75BFULL,
		0x68495F861ED39FB9ULL,
		0xA283BA5AEE42FB8EULL,
		0xC3EED4C9035AF57AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3FBFAE56F9F7B8E8ULL,
		0x82C555A6E9094C22ULL,
		0x319962DE51023460ULL,
		0xA8E8DC7BC741BF2AULL,
		0xBC940BC62FBEDACBULL,
		0xEB39E78657A6B041ULL,
		0x8E0EE8FFBFE00FDBULL,
		0x19C28EC594F94654ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x21B32802A9422860ULL,
		0x82C4418461090000ULL,
		0x0108425E41022000ULL,
		0x20E89050C3412A20ULL,
		0x80140286001A508BULL,
		0x6809478616829001ULL,
		0x8202A85AAE400B8AULL,
		0x01C284C100584450ULL
	}};
	printf("Test Case 182\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 182 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -182;
	} else {
		printf("Test Case 182 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB41C15DBC3903114ULL,
		0x380F17AB21533D68ULL,
		0x1CBB34069EA0D1DDULL,
		0x4A52B08C3FA3A129ULL,
		0x1C237ADA0CCA8276ULL,
		0x3463D64E74418537ULL,
		0xB590966554C35896ULL,
		0xE9732EA1E6CE3C63ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x522742A7170A2DE7ULL,
		0x454BE2A558AAAEC7ULL,
		0x6D4DF232DC4BC42BULL,
		0xAC9F9124A47030A9ULL,
		0xB414AE3DA82F290CULL,
		0x5114399C4DCC29CBULL,
		0x9BB4E9304D144522ULL,
		0xCC51953AD8B2699DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1004008303002104ULL,
		0x000B02A100022C40ULL,
		0x0C0930029C00C009ULL,
		0x0812900424202029ULL,
		0x14002A18080A0004ULL,
		0x1000100C44400103ULL,
		0x9190802044004002ULL,
		0xC8510420C0822801ULL
	}};
	printf("Test Case 183\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 183 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -183;
	} else {
		printf("Test Case 183 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEC6E60CD4542533FULL,
		0x5DB296255A0C49BEULL,
		0x1335B0A613B8DFFEULL,
		0x640838401B732F43ULL,
		0xE786A15678861493ULL,
		0x2CA57AD7599E6A68ULL,
		0xDF2975FC933647B4ULL,
		0x423BAF6B718E9F41ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x741B3B6985955FD1ULL,
		0x66D8E2B847B3346CULL,
		0x8D71AF12BA9C7F7DULL,
		0xE5ACE19D12A339A6ULL,
		0x56CC54A8022AC0ACULL,
		0xFC32FB3E39A00987ULL,
		0x2F2935B3DB9050FEULL,
		0xD57E59C2BE764CDAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x640A204905005311ULL,
		0x449082204200002CULL,
		0x0131A00212985F7CULL,
		0x6408200012232902ULL,
		0x4684000000020080ULL,
		0x2C207A1619800800ULL,
		0x0F2935B0931040B4ULL,
		0x403A094230060C40ULL
	}};
	printf("Test Case 184\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 184 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -184;
	} else {
		printf("Test Case 184 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFC766BB5760EE789ULL,
		0x7DDBD7E9D811A7CBULL,
		0xC05B2DA24F26F899ULL,
		0xBF5559103E480567ULL,
		0x0EC7F0B597C78C7AULL,
		0xDB711DF5ACCC3455ULL,
		0x0682724BDCACE622ULL,
		0x66709BE5DD93778CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5CDEBBAC7CEBFDB3ULL,
		0x84995DC9BFF0DA6DULL,
		0x273D746B9A7C1CF0ULL,
		0x1165B1BA1DE69816ULL,
		0x098CA9442ADA8947ULL,
		0x91E3EDE56DDA6BA5ULL,
		0x33D5780BB4C510B0ULL,
		0x073BDA219D6C8352ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5C562BA4740AE581ULL,
		0x049955C998108249ULL,
		0x001924220A241890ULL,
		0x114511101C400006ULL,
		0x0884A00402C28842ULL,
		0x91610DE52CC82005ULL,
		0x0280700B94840020ULL,
		0x06309A219D000300ULL
	}};
	printf("Test Case 185\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 185 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -185;
	} else {
		printf("Test Case 185 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5A6F5BEBC25B9BEFULL,
		0x9CFD4EE29F044AD4ULL,
		0x253CE85E91D5F4D2ULL,
		0x26C9632BC61C8E48ULL,
		0x89382E70B0E001B0ULL,
		0xCCC46FBE3D1AD622ULL,
		0xDF3BF0778AECDF93ULL,
		0xC80E17A3A63EBC9BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x81CB26B6DD6DBC03ULL,
		0xB74BB91E87D3A0B4ULL,
		0x0F9192A15FFC6D92ULL,
		0x64AEB9C9C6AE4DDBULL,
		0x504411241C600BBEULL,
		0x01BFC49C46E224AFULL,
		0x01A3F663F5593F2EULL,
		0x0520A878F6DCA439ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x004B02A2C0499803ULL,
		0x9449080287000094ULL,
		0x0510800011D46492ULL,
		0x24882109C60C0C48ULL,
		0x00000020106001B0ULL,
		0x0084449C04020422ULL,
		0x0123F06380481F02ULL,
		0x00000020A61CA419ULL
	}};
	printf("Test Case 186\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 186 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -186;
	} else {
		printf("Test Case 186 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x21F2027E5F023E9BULL,
		0xF4A6589D1D4172AFULL,
		0x2F3B974F8E1C745AULL,
		0x88DCB9FEFCD5C0C0ULL,
		0x93EA82C392043604ULL,
		0x61B4408D10964982ULL,
		0x45BB9276D7369562ULL,
		0x732DBECB73CF6AB9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF349E117F88F53B3ULL,
		0xAA5DEBB3E0BA9F23ULL,
		0xEB7520B1658BCB51ULL,
		0xE989515B7656B717ULL,
		0xF548EDBF364F334DULL,
		0x315789A00B61A6B1ULL,
		0x46073015456C440FULL,
		0x11D9AD6D704F57F2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2140001658021293ULL,
		0xA004489100001223ULL,
		0x2B31000104084050ULL,
		0x8888115A74548000ULL,
		0x9148808312043204ULL,
		0x2114008000000080ULL,
		0x4403101445240402ULL,
		0x1109AC49704F42B0ULL
	}};
	printf("Test Case 187\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 187 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -187;
	} else {
		printf("Test Case 187 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDAC567B65F21820AULL,
		0x5CF983760D538D88ULL,
		0xAE53CA03BD72635CULL,
		0x57E85F409F5446F2ULL,
		0x8386FA95AFC1CD6EULL,
		0x0FB3C82B5A92052CULL,
		0x03521FEA6879487BULL,
		0x110093BB4C592162ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x42578C7811DEFA95ULL,
		0x8EE8A3BE5F47A39DULL,
		0x1A3778CA4D6F1A00ULL,
		0xA0062969D4040886ULL,
		0x70841B31D973EA22ULL,
		0xEF45A21203C0297DULL,
		0xB197585B9BB68940ULL,
		0xCD9500D7040B1168ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4245043011008200ULL,
		0x0CE883360D438188ULL,
		0x0A1348020D620200ULL,
		0x0000094094040082ULL,
		0x00841A118941C822ULL,
		0x0F0180020280012CULL,
		0x0112184A08300840ULL,
		0x0100009304090160ULL
	}};
	printf("Test Case 188\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 188 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -188;
	} else {
		printf("Test Case 188 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2550E951335C9B05ULL,
		0xEDD67FAC510CBF5CULL,
		0xB0F5D04EC4CFF8FDULL,
		0x6FCAB58236814165ULL,
		0xD9BF490C72EBC9D2ULL,
		0x30C3DB23179F01DDULL,
		0x35A1A0A5A075F907ULL,
		0xD1740CC83781CF34ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x873A37139BD22EADULL,
		0x69FBC41242D77418ULL,
		0x279B7444292C15D1ULL,
		0x472F92D5B0DA6605ULL,
		0x87386EEA16FDAA70ULL,
		0xB2CEA288A67522AAULL,
		0x08A460C8DC5076B9ULL,
		0xB2BE681143A9C27AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0510211113500A05ULL,
		0x69D2440040043418ULL,
		0x20915044000C10D1ULL,
		0x470A908030804005ULL,
		0x8138480812E98850ULL,
		0x30C2820006150088ULL,
		0x00A0208080507001ULL,
		0x903408000381C230ULL
	}};
	printf("Test Case 189\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 189 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -189;
	} else {
		printf("Test Case 189 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0D957AB7B59ABD1FULL,
		0xAEB4770AB228DFAAULL,
		0x18A8260E9BE5F71EULL,
		0xB517B861F8A7BB04ULL,
		0x26C4AD31A7F6ACEAULL,
		0x7A36488F8D84DF4DULL,
		0x5139653E09626E09ULL,
		0x2DBB0F5E6824FF44ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7EF9E7D39618A14AULL,
		0x9567FB285F1E0886ULL,
		0x442D6205163F22CEULL,
		0x23FF93C1C675E43AULL,
		0x9C2A7E15A705D823ULL,
		0x84FFEBFED3E874F4ULL,
		0x3DB967E2E468A6A9ULL,
		0x9EED3481C8F79711ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0C9162939418A10AULL,
		0x8424730812080882ULL,
		0x002822041225220EULL,
		0x21179041C025A000ULL,
		0x04002C11A7048822ULL,
		0x0036488E81805444ULL,
		0x1139652200602609ULL,
		0x0CA9040048249700ULL
	}};
	printf("Test Case 190\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 190 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -190;
	} else {
		printf("Test Case 190 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x99E91ACA6E907C27ULL,
		0x78E1CE599F9701F1ULL,
		0xD6EB40C31A439AACULL,
		0xF30829B0DBBD7148ULL,
		0xAC1DD6CAA838D74FULL,
		0xDF84D547E5AF8287ULL,
		0x9C5A5703FF7D0FEDULL,
		0xDEC666F0AC957B35ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x22D9EC5AF47C9601ULL,
		0x965273E4BB8C4528ULL,
		0xDE45DCFD1C18938FULL,
		0xA1FD02D45486ECC9ULL,
		0xF6F6986C86E4EFA0ULL,
		0xF2760421A5834599ULL,
		0xECFF0D34C46246ABULL,
		0x2E1D49548F6C5796ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x00C9084A64101401ULL,
		0x104042409B840120ULL,
		0xD64140C11800928CULL,
		0xA108009050846048ULL,
		0xA41490488020C700ULL,
		0xD2040401A5830081ULL,
		0x8C5A0500C46006A9ULL,
		0x0E0440508C045314ULL
	}};
	printf("Test Case 191\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 191 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -191;
	} else {
		printf("Test Case 191 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCD421E00C45617EDULL,
		0xEA61C1466B4A84D7ULL,
		0xD3336D25FCB6FAF8ULL,
		0x347A79025A3A36F9ULL,
		0x2C352AD0338123ADULL,
		0xB59438B702EA9F5EULL,
		0x3F959BA024FD87B0ULL,
		0x8D6EA13B10CBACFAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE37E9239DB4DA53CULL,
		0x156825A6C502D16DULL,
		0x207176490DB765F0ULL,
		0x2181D7297B15C1C1ULL,
		0xC394B568AD17CD55ULL,
		0xAE98E033ABB1BE76ULL,
		0xFAFF6AA395FB1BE4ULL,
		0x83D301E32CD112F0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC1421200C044052CULL,
		0x0060010641028045ULL,
		0x003164010CB660F0ULL,
		0x200051005A1000C1ULL,
		0x0014204021010105ULL,
		0xA490203302A09E56ULL,
		0x3A950AA004F903A0ULL,
		0x8142012300C100F0ULL
	}};
	printf("Test Case 192\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 192 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -192;
	} else {
		printf("Test Case 192 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD5E51F6697B29E1FULL,
		0x90FD5332FBC81B2EULL,
		0x50CDB70C74EC17F4ULL,
		0x8B3E0B7CC1557E60ULL,
		0xBF19E72B42B595D8ULL,
		0x1D839A667B37126AULL,
		0xF37713010AA315ECULL,
		0xCA407A3D53CFE037ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCF07621F8A2EC3E2ULL,
		0x49F30CD9B1BC1AF4ULL,
		0xE3ECCB12224AFB94ULL,
		0x663DF4C353C60FEFULL,
		0xB3A41A566202E7CAULL,
		0x0CE20405F8380551ULL,
		0xB816C40EDE5105D9ULL,
		0x442E4CF17613FEC8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC505020682228202ULL,
		0x00F10010B1881A24ULL,
		0x40CC830020481394ULL,
		0x023C004041440E60ULL,
		0xB3000202420085C8ULL,
		0x0C82000478300040ULL,
		0xB01600000A0105C8ULL,
		0x400048315203E000ULL
	}};
	printf("Test Case 193\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 193 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -193;
	} else {
		printf("Test Case 193 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDBF4A3C242092396ULL,
		0x21F8BB34BCAA4BCAULL,
		0x60C525257ED2181FULL,
		0x23C6BDA7EF5EF46AULL,
		0xCCB5C977B23CF1C9ULL,
		0xCC7DB0D6B6C6728AULL,
		0xCC66684FB4782472ULL,
		0xEA35C6B85BC84E6EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEABF7C5A448927F0ULL,
		0x0F3388E0240B103DULL,
		0x5DFD27C7753C4870ULL,
		0xED835E958B2304FEULL,
		0x32947ECF012FCA2DULL,
		0x4A5F1EF2CAC2C4E6ULL,
		0xD8B751705744E5EBULL,
		0xA72782F8EE389C30ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCAB4204240092390ULL,
		0x01308820240A0008ULL,
		0x40C5250574100810ULL,
		0x21821C858B02046AULL,
		0x00944847002CC009ULL,
		0x485D10D282C24082ULL,
		0xC826404014402462ULL,
		0xA22582B84A080C20ULL
	}};
	printf("Test Case 194\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 194 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -194;
	} else {
		printf("Test Case 194 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x83519B785E952648ULL,
		0xE0B2ADEDF6EE51BDULL,
		0xD403D73F5612E176ULL,
		0xE6C44E01CAF532ADULL,
		0x96A585DCABFD2F36ULL,
		0x0EEAC89EDE3DE8BAULL,
		0x93E68CCB35668CCEULL,
		0x021926E852B16045ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xACAE1DCFFC860D29ULL,
		0x4E5E247AF0247BA3ULL,
		0xE6A15AD7CB9E60ACULL,
		0x46798D9630B0ECBCULL,
		0x36E396A85E6CE114ULL,
		0xEE518E7CE1F0BDDBULL,
		0x8084EC30000DA7FDULL,
		0xC790BF68E8F051CCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x800019485C840408ULL,
		0x40122468F02451A1ULL,
		0xC401521742126024ULL,
		0x46400C0000B020ACULL,
		0x16A184880A6C2114ULL,
		0x0E40881CC030A89AULL,
		0x80848C00000484CCULL,
		0x0210266840B04044ULL
	}};
	printf("Test Case 195\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 195 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -195;
	} else {
		printf("Test Case 195 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1517EFC86CA8655BULL,
		0xDB1F41FC81DF7420ULL,
		0xD30FB938D94553D3ULL,
		0x2C80819848BC3B25ULL,
		0xC38494365FB6405BULL,
		0x62F23F427F6A5435ULL,
		0x6B27415A1AA168FFULL,
		0xC982C9E691B43AFCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x85098018F8D0DCB0ULL,
		0x9F55A8AC1F71C6B6ULL,
		0x98ADD8ABE56B92D5ULL,
		0x43D72B1DD8048992ULL,
		0xFEE1C880E3659DB4ULL,
		0x2A95252E13C94422ULL,
		0x1544B4DD8B634279ULL,
		0x77E2A4483C113042ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0501800868804410ULL,
		0x9B1500AC01514420ULL,
		0x900D9828C14112D1ULL,
		0x0080011848040900ULL,
		0xC280800043240010ULL,
		0x2290250213484420ULL,
		0x010400580A214079ULL,
		0x4182804010103040ULL
	}};
	printf("Test Case 196\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 196 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -196;
	} else {
		printf("Test Case 196 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x713A710C8FF6F8FDULL,
		0xC439A3D8CE620E21ULL,
		0x3907C6726F677BD3ULL,
		0xE5DF44E9AFC5CEF0ULL,
		0x1D092D7C6913A776ULL,
		0x8BB3E538AB7066F7ULL,
		0xCD882197E98F637CULL,
		0x72544B45310C71FEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAC5C3055BCE630FAULL,
		0x58E24FC2EF05E2B9ULL,
		0xC4C7AFE07E2289ADULL,
		0x278AB70891F0C980ULL,
		0x1DC7744565D938C0ULL,
		0x0BE872A905720EF6ULL,
		0xDD1522460001DEFBULL,
		0xD97BDD44A50AB870ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x201830048CE630F8ULL,
		0x402003C0CE000221ULL,
		0x000786606E220981ULL,
		0x258A040881C0C880ULL,
		0x1D01244461112040ULL,
		0x0BA06028017006F6ULL,
		0xCD00200600014278ULL,
		0x5050494421083070ULL
	}};
	printf("Test Case 197\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 197 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -197;
	} else {
		printf("Test Case 197 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x12561F056976BEE4ULL,
		0xF47C2B0334F69D9FULL,
		0x895120B83C834642ULL,
		0x0C05C2E23DCD191EULL,
		0x72295320AE696F83ULL,
		0x8E90C810BE0D0210ULL,
		0x6159AD6D65C0D00CULL,
		0x850A63CBB2ABEB99ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD47E3152EF36584CULL,
		0x2CB2D795C659E22DULL,
		0x7BCE69E1CB205F72ULL,
		0xD7D5AB808CF21908ULL,
		0x6C233EB03C884196ULL,
		0x30BF664501909C05ULL,
		0x1DE511AA3A003132ULL,
		0x29583D910D68B0B5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1056110069361844ULL,
		0x243003010450800DULL,
		0x094020A008004642ULL,
		0x040582800CC01908ULL,
		0x602112202C084182ULL,
		0x0090400000000000ULL,
		0x0141012820001000ULL,
		0x010821810028A091ULL
	}};
	printf("Test Case 198\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 198 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -198;
	} else {
		printf("Test Case 198 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4C497E7CF8D7E9A9ULL,
		0x754352E261E0BA33ULL,
		0xF403CF3CB7B80BD9ULL,
		0x55C909687A3E6D9CULL,
		0xA21F6840AAEA9CEFULL,
		0xD5F116D20061757AULL,
		0xCBBFB4DEC62CD031ULL,
		0x06994C5CA7F0E743ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x27764755001DCAE4ULL,
		0xE8C697E0C041759AULL,
		0x94E60F85159B833CULL,
		0x815FE40F30F93AAAULL,
		0x496DBE7FA9B3D88DULL,
		0x8B7CADDC899DB81FULL,
		0x00D088592699C72DULL,
		0x41FAE45B6B881204ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x044046540015C8A0ULL,
		0x604212E040403012ULL,
		0x94020F0415980318ULL,
		0x0149000830382888ULL,
		0x000D2840A8A2988DULL,
		0x817004D00001301AULL,
		0x009080580608C021ULL,
		0x0098445823800200ULL
	}};
	printf("Test Case 199\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 199 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -199;
	} else {
		printf("Test Case 199 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x140214CE3E73F8A2ULL,
		0xB93C4251E9175C12ULL,
		0x5AB4D51495A24E08ULL,
		0xF0ADEE694ECDB696ULL,
		0x8916466EBBBA1DA0ULL,
		0x0723AE6AE4DAD761ULL,
		0xCEEEAA878D4CEC35ULL,
		0xF3ABB6D323894BACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x823F22C4DCAEEFE4ULL,
		0x2E3C173593BC6393ULL,
		0x654A53169470FB13ULL,
		0xD3143F1ADDCA00B6ULL,
		0x8C372596E863FF65ULL,
		0x62B48FBBAC6D8047ULL,
		0x761F1830218C0EABULL,
		0x97700B71ADC30429ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x000200C41C22E8A0ULL,
		0x283C021181144012ULL,
		0x4000511494204A00ULL,
		0xD0042E084CC80096ULL,
		0x88160406A8221D20ULL,
		0x02208E2AA4488041ULL,
		0x460E0800010C0C21ULL,
		0x9320025121810028ULL
	}};
	printf("Test Case 200\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 200 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -200;
	} else {
		printf("Test Case 200 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x40E7EBC5A073FDADULL,
		0x298899E25F94CA95ULL,
		0xD7376F2F498C362FULL,
		0xD91D7ABB520CB0D7ULL,
		0x849DF03EF347B494ULL,
		0x30264CC1D9618BD7ULL,
		0x1951EECCBC4DAAE9ULL,
		0x353D0BFA753DBE3AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x07B81BB84FC10C08ULL,
		0x1DE189C5DEBD3DE2ULL,
		0x1C8EA7FBABBF8A45ULL,
		0xDA3EDC6DF92914F8ULL,
		0xAC663520996691F9ULL,
		0x4F646979ED8A995DULL,
		0xF0EED9BBC69E6379ULL,
		0x12A5E7D05AC3B105ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x00A00B8000410C08ULL,
		0x098089C05E940880ULL,
		0x1406272B098C0205ULL,
		0xD81C5829500810D0ULL,
		0x8404302091469090ULL,
		0x00244841C9008955ULL,
		0x1040C888840C2269ULL,
		0x102503D05001B000ULL
	}};
	printf("Test Case 201\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 201 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -201;
	} else {
		printf("Test Case 201 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x48AC16A5BDECD4BAULL,
		0xBC9406D84B0066BAULL,
		0x23874A5351BB349EULL,
		0xF274E9FD74EEC39AULL,
		0xE521D6C51D21EFC6ULL,
		0x6E5D268F51F50820ULL,
		0x4B86F1A8D08279A2ULL,
		0x12052CA7478C93DDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x430266FE1AD787E9ULL,
		0x9F6486E2E9ACF8D1ULL,
		0x84E074FB0D7BE42EULL,
		0x09CD94D38E4C943BULL,
		0x2174D857895E8B41ULL,
		0x7971F2C935BF294CULL,
		0x3F2BFC854711B714ULL,
		0xC613AB28EFD2CC6BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x400006A418C484A8ULL,
		0x9C0406C049006090ULL,
		0x00804053013B240EULL,
		0x004480D1044C801AULL,
		0x2120D04509008B40ULL,
		0x6851228911B50800ULL,
		0x0B02F08040003100ULL,
		0x0201282047808049ULL
	}};
	printf("Test Case 202\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 202 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -202;
	} else {
		printf("Test Case 202 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2CB9F0A1B94E40D5ULL,
		0xEB29D1676B77E523ULL,
		0x34C018FDB90C9D77ULL,
		0x541C458F05AA8B90ULL,
		0x9DF3EA63A929AA2DULL,
		0xDAEAA6B64DBB0E33ULL,
		0x8E1ADEB8DFD674C5ULL,
		0x37C17B50A12C006BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x09B55E229960F0E9ULL,
		0xBCAD316EB07C3234ULL,
		0xF8272E6C367C9B79ULL,
		0x4DDE91218F19EC9EULL,
		0x6908BA16C33E5A9DULL,
		0x20E535E109772983ULL,
		0xCEEE7A7A83287B69ULL,
		0xC38EC218C69C4DD7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x08B15020994040C1ULL,
		0xA829116620742020ULL,
		0x3000086C300C9971ULL,
		0x441C010105088890ULL,
		0x0900AA0281280A0DULL,
		0x00E024A009330803ULL,
		0x8E0A5A3883007041ULL,
		0x03804210800C0043ULL
	}};
	printf("Test Case 203\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 203 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -203;
	} else {
		printf("Test Case 203 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1DEF1FB4500FDA31ULL,
		0xC24362B428FD8F88ULL,
		0x5767222E6BE9A01FULL,
		0xBE8B263B3AA8CD87ULL,
		0x887C9D29B225A0F7ULL,
		0x5B8F9C5C8B3A31C9ULL,
		0x518A182A0E838AE2ULL,
		0x35E5FCAA38B3FAF6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE24DDC09E7132965ULL,
		0x5354FFF75866A046ULL,
		0xFF06FE83D3591907ULL,
		0x580314206EEE3D2AULL,
		0xBDDD94B8D68AC6B8ULL,
		0x8130DC774EB785DAULL,
		0x1A8C44347F760DDCULL,
		0x5B7BEC68A1EC2554ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x004D1C0040030821ULL,
		0x424062B408648000ULL,
		0x5706220243490007ULL,
		0x180304202AA80D02ULL,
		0x885C9428920080B0ULL,
		0x01009C540A3201C8ULL,
		0x108800200E0208C0ULL,
		0x1161EC2820A02054ULL
	}};
	printf("Test Case 204\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 204 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -204;
	} else {
		printf("Test Case 204 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x387174EFBAB46923ULL,
		0xCD84666667D38010ULL,
		0x3D697CC6AFE3E7BAULL,
		0xF9FDBFECE71178A0ULL,
		0x2343E75D25E437C6ULL,
		0x1A299C13726B7CF7ULL,
		0x6E8B4475B9A6E63CULL,
		0x88CC97FA9941AC9AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x032E9432A2F8673DULL,
		0x8812755F3A4BADB5ULL,
		0xEA8B32770553C498ULL,
		0x81F5EE4AA3E0454DULL,
		0x135BDE19C7829824ULL,
		0x12CC7C93A6CC9841ULL,
		0x712A8FA1E42AB32EULL,
		0x6D90B57A939FE114ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x00201422A2B06121ULL,
		0x8800644622438010ULL,
		0x280930460543C498ULL,
		0x81F5AE48A3004000ULL,
		0x0343C61905801004ULL,
		0x12081C1322481841ULL,
		0x600A0421A022A22CULL,
		0x0880957A9101A010ULL
	}};
	printf("Test Case 205\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 205 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -205;
	} else {
		printf("Test Case 205 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x88B6D42BD7B1915DULL,
		0x6EB51D0E7F64D378ULL,
		0x6CB64E179F27260CULL,
		0x006CDCB62853F81EULL,
		0x259A053EA934B7ABULL,
		0x75DDE3571ECAE511ULL,
		0xE4CBB45E07B14FA7ULL,
		0x8F7BA20900D0EE4BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x60BAE4E74E8C9013ULL,
		0xED268F042FF0CC95ULL,
		0xCC3CD43F5FFE423EULL,
		0x0BB08CB4C5AA811FULL,
		0x60D694FB46A74449ULL,
		0x58E9BD4CB9AFFE43ULL,
		0x8E35C7198A140B2DULL,
		0x327010DF7DCA4171ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x00B2C42346809011ULL,
		0x6C240D042F60C010ULL,
		0x4C3444171F26020CULL,
		0x00208CB40002801EULL,
		0x2092043A00240409ULL,
		0x50C9A144188AE401ULL,
		0x8401841802100B25ULL,
		0x0270000900C04041ULL
	}};
	printf("Test Case 206\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 206 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -206;
	} else {
		printf("Test Case 206 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0EFBECD7846F16D4ULL,
		0x62CDFF1DCB7ABA20ULL,
		0x6079DEC178B39BD4ULL,
		0x33ED183DF3F6893FULL,
		0x584D5942059E66A1ULL,
		0x4C8E8A8EFB14A674ULL,
		0x604F0BF4AB376E65ULL,
		0x261BA9C8CD2EF9EDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5120702184C5714EULL,
		0x8385DE2EBA60ABCCULL,
		0xB75733FAD554575CULL,
		0x5CD51FF52931CA62ULL,
		0x79AC952244A9FE1DULL,
		0x525E4198C7815B55ULL,
		0xA4D3D31BFF517B50ULL,
		0xC536A53D9178A475ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0020600184451044ULL,
		0x0285DE0C8A60AA00ULL,
		0x205112C050101354ULL,
		0x10C5183521308822ULL,
		0x580C110204886601ULL,
		0x400E0088C3000254ULL,
		0x20430310AB116A40ULL,
		0x0412A1088128A065ULL
	}};
	printf("Test Case 207\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 207 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -207;
	} else {
		printf("Test Case 207 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6A562BA35AB7C42CULL,
		0x858DD1F67CB2A5CAULL,
		0xB16A7B605B3F63D0ULL,
		0xAFCAFC01970BEEF6ULL,
		0x3FCFFE210C711E76ULL,
		0x7F805C7A00F5D0E0ULL,
		0x50AC3911028B6624ULL,
		0x8EB7993E97074519ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF0CCAF0983D0992EULL,
		0xACFA74E8A7F5CC2DULL,
		0xF25954B0273B0428ULL,
		0xC7E5F6AEB9A2EBEDULL,
		0x7422B9274293770DULL,
		0x53B7DA09E2BB5D05ULL,
		0x06D0A2A83C2243DEULL,
		0x6F76AC26EBF95954ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x60442B010290802CULL,
		0x848850E024B08408ULL,
		0xB0485020033B0000ULL,
		0x87C0F4009102EAE4ULL,
		0x3402B82100111604ULL,
		0x5380580800B15000ULL,
		0x0080200000024204ULL,
		0x0E36882683014110ULL
	}};
	printf("Test Case 208\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 208 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -208;
	} else {
		printf("Test Case 208 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9B86EF0BA8D6D19BULL,
		0x5E04870DA8EB3F75ULL,
		0x6A3CB265B083FEFFULL,
		0xF98E98B43FE6A20BULL,
		0xED14D8F62F97F28CULL,
		0x3EA75BF8867A4A6AULL,
		0x0CB20770E243FE2DULL,
		0xF96CD2ECCF70D452ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE0A08B86692A316AULL,
		0x94E3C01E7FBBC512ULL,
		0x89D19E51C7575EF9ULL,
		0x697DDA6464463BB8ULL,
		0x6F2A0E3D9E9A0025ULL,
		0x70F6620AE30E85E2ULL,
		0xCB1BC04A7DF42BCFULL,
		0x6D931B9B692878C7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x80808B022802110AULL,
		0x1400800C28AB0510ULL,
		0x0810924180035EF9ULL,
		0x690C982424462208ULL,
		0x6D0008340E920004ULL,
		0x30A64208820A0062ULL,
		0x0812004060402A0DULL,
		0x6900128849205042ULL
	}};
	printf("Test Case 209\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 209 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -209;
	} else {
		printf("Test Case 209 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6CC7934EB8EBCD4AULL,
		0xEF5E63F83C9193B9ULL,
		0x038B8946B6F62E35ULL,
		0xF151DA584F31787EULL,
		0x91985A5248124E86ULL,
		0x3E5B8CE8C8F99796ULL,
		0x2DF658FF4D0C4B1AULL,
		0x80E61008DB47B689ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA1629672F147A67EULL,
		0x82E635164399B636ULL,
		0x38D3FA0C874CBB60ULL,
		0x9742BDD6ED657325ULL,
		0x8E5D483931A566E3ULL,
		0xDB531D5693C22B3CULL,
		0x0A21855E2DA8B674ULL,
		0x04714AB024066C39ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x20429242B043844AULL,
		0x8246211000919230ULL,
		0x0083880486442A20ULL,
		0x914098504D217024ULL,
		0x8018481000004682ULL,
		0x1A530C4080C00314ULL,
		0x0820005E0D080210ULL,
		0x0060000000062409ULL
	}};
	printf("Test Case 210\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 210 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -210;
	} else {
		printf("Test Case 210 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x82BFECB34E839117ULL,
		0x8B0BA6F4F8A42EA3ULL,
		0xA33CA98C55F6A104ULL,
		0x952A09AADBDFF946ULL,
		0x924098C83107E857ULL,
		0x107F2A31F290D12AULL,
		0x088D1A42A2D32C47ULL,
		0x2C1CAD39C1FD0F69ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA63A665F04A54FC9ULL,
		0x76D53ABE8E0D8F76ULL,
		0x0D314DA11DF9C219ULL,
		0x2A82C1973C630E7DULL,
		0xBA97EB8F1B310220ULL,
		0x83BF15724122B948ULL,
		0x3ED7A8EFD7B1A008ULL,
		0xC60E66FCE4B0496EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x823A641304810101ULL,
		0x020122B488040E22ULL,
		0x0130098015F08000ULL,
		0x0002018218430844ULL,
		0x9200888811010000ULL,
		0x003F003040009108ULL,
		0x0885084282912000ULL,
		0x040C2438C0B00968ULL
	}};
	printf("Test Case 211\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 211 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -211;
	} else {
		printf("Test Case 211 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x265B88A6117FFF72ULL,
		0x72DAED36D6F2E274ULL,
		0x12F5E692D7D11024ULL,
		0xA2D413FF236EC238ULL,
		0x1D0A7DA2ECA24B32ULL,
		0xDB7066E77131681CULL,
		0x71A754AFE636AC47ULL,
		0x3F2E13EEE5155697ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4598FC4265B9233FULL,
		0x13ED5FDFACB34423ULL,
		0xE071C428D13D1CE9ULL,
		0x73A3B3970DF4D976ULL,
		0x360F3AEC4783314AULL,
		0xA85259729240B0EDULL,
		0xDEA24D38B7C8C09AULL,
		0x2B025D5921DF5D41ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0418880201392332ULL,
		0x12C84D1684B24020ULL,
		0x0071C400D1111020ULL,
		0x228013970164C030ULL,
		0x140A38A044820102ULL,
		0x885040621000200CULL,
		0x50A24428A6008002ULL,
		0x2B02114821155401ULL
	}};
	printf("Test Case 212\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 212 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -212;
	} else {
		printf("Test Case 212 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x512DCE3544D38AF9ULL,
		0xD0FA7DC5CCCA1B3EULL,
		0xA348AC7CB1CF2E88ULL,
		0xE24BC33B5007604DULL,
		0xB218B6E3EB097967ULL,
		0x910D11C3F3888E91ULL,
		0x90726619A4737081ULL,
		0x0CB891EF7E24B3D4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA0B2196A3F44A5E2ULL,
		0x289217C8507849A5ULL,
		0x2BC0E70728D72D76ULL,
		0x440CAEA873BF72C0ULL,
		0xC79817874187CBB5ULL,
		0xA4902172F919F4F3ULL,
		0x78FB12116E32EF69ULL,
		0xC0B36324B7D455D9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x00200820044080E0ULL,
		0x009215C040480924ULL,
		0x2340A40420C72C00ULL,
		0x4008822850076040ULL,
		0x8218168341014925ULL,
		0x80000142F1088491ULL,
		0x1072021124326001ULL,
		0x00B00124360411D0ULL
	}};
	printf("Test Case 213\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 213 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -213;
	} else {
		printf("Test Case 213 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4B18AD9AF0D7669BULL,
		0x302BA9D36DDD5EEBULL,
		0x822636EC6C39403BULL,
		0x9A408A92B4B9253AULL,
		0x6CF5151DAD6BCC30ULL,
		0x1ED7C1A7B0CE52CEULL,
		0xCDC240D7380C52F5ULL,
		0xB45CA80973A33C9DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBC82D205F7634FA0ULL,
		0xD39FF72868CAA0DCULL,
		0xF681E9B5985B4BE9ULL,
		0x501571E18FCB8AE5ULL,
		0xB6006F7447AF37F7ULL,
		0xC3480FA7FA1B1AD4ULL,
		0xEBE1F2792CB1D8FCULL,
		0x0B9A5F66D61BEA3EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x08008000F0434680ULL,
		0x100BA10068C800C8ULL,
		0x820020A408194029ULL,
		0x1000008084890020ULL,
		0x24000514052B0430ULL,
		0x024001A7B00A12C4ULL,
		0xC9C04051280050F4ULL,
		0x001808005203281CULL
	}};
	printf("Test Case 214\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 214 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -214;
	} else {
		printf("Test Case 214 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF19D22509FA22AFCULL,
		0xDD2729643E2F0C04ULL,
		0x90711FFBD2DC1CB7ULL,
		0x56CFCF62F29B0237ULL,
		0x3F251AA7DFB5E95FULL,
		0x80B54671B9F25B7BULL,
		0xBB3C62A3EDAB88F0ULL,
		0xA5D94C88CC5B16CAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1C2DF838AD2B273FULL,
		0x161A6E1DE16380DFULL,
		0x567671019C12FB4AULL,
		0x959ABB92AAA41C23ULL,
		0x7EECA60944DE3EBAULL,
		0xDC8CD261D7699CF2ULL,
		0x80D89BDC9BD8BE99ULL,
		0xD8432A841CBDD588ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x100D20108D22223CULL,
		0x1402280420230004ULL,
		0x1070110190101802ULL,
		0x148A8B02A2800023ULL,
		0x3E2402014494281AULL,
		0x8084426191601872ULL,
		0x8018028089888890ULL,
		0x804108800C191488ULL
	}};
	printf("Test Case 215\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 215 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -215;
	} else {
		printf("Test Case 215 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB1AE22BD25382E7FULL,
		0xF0A85383E37DE191ULL,
		0x8638FA815BD2005EULL,
		0x770864EBE4C29901ULL,
		0xAA2E1311C0EFFA04ULL,
		0x8A09B6B26B39BE55ULL,
		0x01A670F74DAFC91EULL,
		0xC70ADAFF905795D5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x46EFA4A9F962896CULL,
		0xECDE75DBFFB2FAF9ULL,
		0x4171586068C56146ULL,
		0x22A720D5E374D3FDULL,
		0x892BDB7FF385CD12ULL,
		0xDD92D9A8F8B6BDB5ULL,
		0x282011FE91C325BDULL,
		0x096569CA74F03CE3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x00AE20A92120086CULL,
		0xE0885183E330E091ULL,
		0x0030580048C00046ULL,
		0x220020C1E0409101ULL,
		0x882A1311C085C800ULL,
		0x880090A06830BC15ULL,
		0x002010F60183011CULL,
		0x010048CA105014C1ULL
	}};
	printf("Test Case 216\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 216 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -216;
	} else {
		printf("Test Case 216 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5B0311B8A17F87F2ULL,
		0x3DDC5B1C419395AFULL,
		0xFAF97C94422A43DDULL,
		0x2A67F44A2A41354AULL,
		0xD5EDE4D5DC629F6FULL,
		0x3CDB754036E9E75FULL,
		0x3E98AE17A6DD688BULL,
		0xCFA4E0E5BA181CF5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x40E4F0B0FAFCD1BCULL,
		0xAA4B99C5164AEEE4ULL,
		0x4766057F6EF31DE0ULL,
		0x957439A2EFBC9671ULL,
		0x749A521A65A52204ULL,
		0xEB7A69EAB90DAE9FULL,
		0x82E47565438DCD10ULL,
		0x338BC07C5A661C1FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x400010B0A07C81B0ULL,
		0x28481904000284A4ULL,
		0x42600414422201C0ULL,
		0x006430022A001440ULL,
		0x5488401044200204ULL,
		0x285A61403009A61FULL,
		0x02802405028D4800ULL,
		0x0380C0641A001C15ULL
	}};
	printf("Test Case 217\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 217 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -217;
	} else {
		printf("Test Case 217 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4CE90656BE879B11ULL,
		0x0375D837AA29D673ULL,
		0xA55A29C6EE1B5DDAULL,
		0x089DBC0484498217ULL,
		0x522DAD4A1606AF57ULL,
		0x53798391E6386D92ULL,
		0xEDFA038EEB41CC68ULL,
		0x2E3D81B29A2D97CFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE07566EE0EFAF4E8ULL,
		0x6FB3BE9E9DCC9F5DULL,
		0x32412865C78E8A2CULL,
		0x1A31AD818E778E1BULL,
		0x22943EB8D7CFCABDULL,
		0x28FCC7C7AF0318A0ULL,
		0x8285E33EE66BC6A1ULL,
		0x2172B540EA9DD547ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x406106460E829000ULL,
		0x0331981688089651ULL,
		0x20402844C60A0808ULL,
		0x0811AC0084418213ULL,
		0x02042C0816068A15ULL,
		0x00788381A6000880ULL,
		0x8080030EE241C420ULL,
		0x203081008A0D9547ULL
	}};
	printf("Test Case 218\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 218 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -218;
	} else {
		printf("Test Case 218 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x71F8AE79465164C3ULL,
		0x52563815D0E361EFULL,
		0x80BB49ACDF005BE7ULL,
		0x0398C406805EF2F2ULL,
		0xD019FA902A6837A7ULL,
		0x0723431E6F87D2A3ULL,
		0x1D8E4EC079CECCACULL,
		0x2C6DFD87712C1F22ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFCC40341BEC0CB58ULL,
		0x626D9A33C070CAFFULL,
		0x32E4D864C8DEF28FULL,
		0x2D296BCB76C3BF35ULL,
		0x04E94C9344A52281ULL,
		0x6D5605CC8FE833D4ULL,
		0xBCDD4B6DA0D71EC4ULL,
		0x2EDB4E30D339AEF4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x70C0024106404040ULL,
		0x42441811C06040EFULL,
		0x00A04824C8005287ULL,
		0x010840020042B230ULL,
		0x0009489000202281ULL,
		0x0502010C0F801280ULL,
		0x1C8C4A4020C60C84ULL,
		0x2C494C0051280E20ULL
	}};
	printf("Test Case 219\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 219 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -219;
	} else {
		printf("Test Case 219 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x96140E0D2FF215C0ULL,
		0xB6172DC6296A7F1EULL,
		0x469E53492C13E558ULL,
		0x685B87137888D2BFULL,
		0xB71ED925F7B73ECEULL,
		0x9F6882527274E93FULL,
		0x29608E8EFAFA6BC0ULL,
		0x3841245C50963FB3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x95476EFD7D1108F6ULL,
		0x198BAF7792F34AF4ULL,
		0xB8533485C3C39447ULL,
		0x33580BBE0F33855EULL,
		0x3544FC79E1358C3FULL,
		0xF5FD58D62E20710EULL,
		0xDA2D858D6FA9388EULL,
		0xDD7BE50EE92BBC06ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x94040E0D2D1000C0ULL,
		0x10032D4600624A14ULL,
		0x0012100100038440ULL,
		0x205803120800801EULL,
		0x3504D821E1350C0EULL,
		0x956800522220610EULL,
		0x0820848C6AA82880ULL,
		0x1841240C40023C02ULL
	}};
	printf("Test Case 220\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 220 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -220;
	} else {
		printf("Test Case 220 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9791E9AECEF7F270ULL,
		0x474766E38A44BB87ULL,
		0x4A3FEECA2F5C05AEULL,
		0x091A6AA31DF6EF55ULL,
		0x3316AD47791CFE37ULL,
		0xFA5610599B474ACAULL,
		0x0FB536C36F0A0722ULL,
		0x12E875EC1D3E99E8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x017F069745729475ULL,
		0xF39D37AEA5A63080ULL,
		0x442FCCF5523AB13BULL,
		0x1E80BF983D0A2B74ULL,
		0x40B1D71C129DB37DULL,
		0x0A0462DC5C35A865ULL,
		0x9FB84F2359F48024ULL,
		0x21E09B4F3E9E7808ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0111008644729070ULL,
		0x430526A280043080ULL,
		0x402FCCC00218012AULL,
		0x08002A801D022B54ULL,
		0x00108504101CB235ULL,
		0x0A04005818050840ULL,
		0x0FB0060349000020ULL,
		0x00E0114C1C1E1808ULL
	}};
	printf("Test Case 221\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 221 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -221;
	} else {
		printf("Test Case 221 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1E1640A991B5DA73ULL,
		0x013477A8FC5C5ECAULL,
		0x5319249DB3029D9FULL,
		0xAA9413AE1AD9FBCBULL,
		0x1B0B57CB78249822ULL,
		0x10B6E8BE71683581ULL,
		0x09519C156FCE53B3ULL,
		0xD570454C372F8FC1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x30B87EC4FBAC1BC9ULL,
		0x58880ECD42C11C91ULL,
		0x3D60CE22D7F34420ULL,
		0xBA60DE6C86AB973CULL,
		0x22E6C5DD40F722A7ULL,
		0xF43EAA53D3D1364FULL,
		0x716A7C2BBF817004ULL,
		0xBFEB05C49F4C51C1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1010408091A41A41ULL,
		0x0000068840401C80ULL,
		0x1100040093020400ULL,
		0xAA00122C02899308ULL,
		0x020245C940240022ULL,
		0x1036A81251403401ULL,
		0x01401C012F805000ULL,
		0x95600544170C01C1ULL
	}};
	printf("Test Case 222\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 222 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -222;
	} else {
		printf("Test Case 222 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x294E2A689F4103DDULL,
		0xB15779978E068177ULL,
		0x6250A73F3EBB6543ULL,
		0x9404C74B3135E206ULL,
		0x79198B5132919281ULL,
		0xD89E4C4038D348B8ULL,
		0xA6F67A57F3E371C2ULL,
		0xC9C1D6D5EB1ACB4BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1DFBECEC02BAED97ULL,
		0xCF9540E3D825A86FULL,
		0x6D5803DCF02E9A6BULL,
		0x0227750879A24541ULL,
		0xF8AF68013920546FULL,
		0x27B9B97566302C26ULL,
		0x5BB48ED155FB2F26ULL,
		0xF6EABC6748AB8586ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x094A286802000195ULL,
		0x8115408388048067ULL,
		0x6050031C302A0043ULL,
		0x0004450831204000ULL,
		0x7809080130001001ULL,
		0x0098084020100820ULL,
		0x02B40A5151E32102ULL,
		0xC0C09445480A8102ULL
	}};
	printf("Test Case 223\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 223 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -223;
	} else {
		printf("Test Case 223 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCC367C3D414ADD69ULL,
		0xEDF55678CABD642DULL,
		0x45D756FF1D703005ULL,
		0x12936AFED355E9AEULL,
		0xF8702274455CDF5AULL,
		0xF441BC27B491812AULL,
		0xE9D36A8F9DD6D250ULL,
		0xA571FF6E723E636BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9AF5747531D60C7DULL,
		0x60F7019F20B84528ULL,
		0x5BD30430A57D1518ULL,
		0x336E18180D6EE14CULL,
		0x530030286E5CB9B7ULL,
		0x63D172F3F0F93C84ULL,
		0x0368A0AAD6BF55F1ULL,
		0x258BB390B58BA1BBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8834743501420C69ULL,
		0x60F5001800B84428ULL,
		0x41D3043005701000ULL,
		0x120208180144E10CULL,
		0x50002020445C9912ULL,
		0x60413023B0910000ULL,
		0x0140208A94965050ULL,
		0x2501B300300A212BULL
	}};
	printf("Test Case 224\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 224 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -224;
	} else {
		printf("Test Case 224 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBBBA9C3B1FF7041DULL,
		0x01A7273FF4D97B8CULL,
		0x02EE87D85E9C46A8ULL,
		0x38494DACF97FF927ULL,
		0x72739BE0702CE03CULL,
		0xDF270444CBE9B8C9ULL,
		0x442BFB2FD1709CA8ULL,
		0xDC951F85954135D9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB785F2B536504FE7ULL,
		0xFCC019C40A0F032FULL,
		0xFC8AABC0A0FA10D0ULL,
		0xAF47A76D3896CC41ULL,
		0x635D19899295C735ULL,
		0xCC555BBEEAED66A6ULL,
		0x5593B9B2A85A83BDULL,
		0xC8AE35813D1B82DCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB380903116500405ULL,
		0x008001040009030CULL,
		0x008A83C000980080ULL,
		0x2841052C3816C801ULL,
		0x625119801004C034ULL,
		0xCC050004CAE92080ULL,
		0x4403B922805080A8ULL,
		0xC8841581150100D8ULL
	}};
	printf("Test Case 225\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 225 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -225;
	} else {
		printf("Test Case 225 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x964DD1870CD57BC7ULL,
		0x2E89D11C6BCF19C0ULL,
		0x081CE7E3E8DAB7A9ULL,
		0xEF645047A33F822AULL,
		0x4A39207FC794FAC9ULL,
		0xD05875FFDC8B7BF9ULL,
		0xEE372847A299E433ULL,
		0x618FD5D2BFD6868BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x60D9B7E940CE032DULL,
		0x45929E39E54A5599ULL,
		0x1A53D6166F32045AULL,
		0xD367634BF2EA05F1ULL,
		0x23D83F220853D068ULL,
		0x690976F7C27A80C0ULL,
		0xA9B47690A5B861BDULL,
		0x2CF0A832FDB2E052ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0049918100C40305ULL,
		0x04809018614A1180ULL,
		0x0810C60268120408ULL,
		0xC3644043A22A0020ULL,
		0x021820220010D048ULL,
		0x400874F7C00A00C0ULL,
		0xA8342000A0986031ULL,
		0x20808012BD928002ULL
	}};
	printf("Test Case 226\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 226 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -226;
	} else {
		printf("Test Case 226 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCEB36B75BDD29413ULL,
		0x4D501C2C16DD7BDFULL,
		0xEE8BA77162F340AAULL,
		0x3128784D6ED87ADCULL,
		0xECE89AF415727256ULL,
		0x183E866E25BDDF2DULL,
		0x2BB0979B1303F1BCULL,
		0xD4318972B65FDE27ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7F1C50A2191902C2ULL,
		0xD4D42881B592FA22ULL,
		0x9056378E56B1EC54ULL,
		0x3DB17DEE4C2D586EULL,
		0x6DC3B5859478B3E6ULL,
		0x540EE6FB516B8336ULL,
		0x99980DC54CCB6D4EULL,
		0x3088D26254FF7C56ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4E10402019100002ULL,
		0x4450080014907A02ULL,
		0x8002270042B14000ULL,
		0x3120784C4C08584CULL,
		0x6CC0908414703246ULL,
		0x100E866A01298324ULL,
		0x099005810003610CULL,
		0x10008062145F5C06ULL
	}};
	printf("Test Case 227\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 227 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -227;
	} else {
		printf("Test Case 227 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8DD523D128B8697CULL,
		0xA0991698CA7E6FEDULL,
		0x720CA617E7EE4822ULL,
		0xA1ADDD868BD8C3AFULL,
		0xC55B236B45484389ULL,
		0xA8E2D9A32E42BD07ULL,
		0x53D3A1BAF5C45D34ULL,
		0xFC35E2F391BED8D7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB49248E429BC2334ULL,
		0x54E66CBFD564F800ULL,
		0xE01CDEDEE5335371ULL,
		0x705B3D575A9F5B45ULL,
		0x3307B5441FF9E719ULL,
		0x8CB6AFA026C0FAA9ULL,
		0xC2C49D9E8965F247ULL,
		0x7E7C011F2CE510FFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x849000C028B82134ULL,
		0x00800498C0646800ULL,
		0x600C8616E5224020ULL,
		0x20091D060A984305ULL,
		0x0103214005484309ULL,
		0x88A289A02640B801ULL,
		0x42C0819A81445004ULL,
		0x7C34001300A410D7ULL
	}};
	printf("Test Case 228\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 228 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -228;
	} else {
		printf("Test Case 228 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8DC484A0AC26A6DAULL,
		0xDD8537E97FF7E290ULL,
		0xBE408210B9524B63ULL,
		0x02AFE2F573EEA7C3ULL,
		0xC5E4FAD41869617AULL,
		0x89A2929AA2B7D634ULL,
		0xCACD2B6E4D904F62ULL,
		0x6B902A553F927EC8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC3FFACB2985A94E1ULL,
		0xC46F75FD9B8B866CULL,
		0x8C3FF67780E6FF01ULL,
		0xB018531B978E1A43ULL,
		0x4FCF1FB1922C02A2ULL,
		0x797F34A9A43F908DULL,
		0x1E49044CC7FDB5DAULL,
		0x2C46656B6BD1B9F0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x81C484A0880284C0ULL,
		0xC40535E91B838200ULL,
		0x8C00821080424B01ULL,
		0x00084211138E0243ULL,
		0x45C41A9010280022ULL,
		0x09221088A0379004ULL,
		0x0A49004C45900542ULL,
		0x280020412B9038C0ULL
	}};
	printf("Test Case 229\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 229 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -229;
	} else {
		printf("Test Case 229 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x140341337D3128A8ULL,
		0x58A173BC24EEB55BULL,
		0x75A306A0C004336FULL,
		0x6B0BE5EA29151204ULL,
		0xEAF8775AA28A9E17ULL,
		0xB4B57D4E6EC0D9F2ULL,
		0x564C2D837CC3E905ULL,
		0x446F90BA9212477CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3FA703E80889678FULL,
		0x7AF595F8CAA11996ULL,
		0x0754342B598218DAULL,
		0x77584C3D90BA7958ULL,
		0xACA96744705E4EB1ULL,
		0x1E32165BD7D3DEE2ULL,
		0x7C81F081F2FBDEE4ULL,
		0x998B834A7BD2F0F0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1403012008012088ULL,
		0x58A111B800A01112ULL,
		0x050004204000104AULL,
		0x6308442800101000ULL,
		0xA8A86740200A0E11ULL,
		0x1430144A46C0D8E2ULL,
		0x5400208170C3C804ULL,
		0x000B800A12124070ULL
	}};
	printf("Test Case 230\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 230 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -230;
	} else {
		printf("Test Case 230 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x273580121B80383DULL,
		0x27DF5FBFF1D04EECULL,
		0xAE1584F53E022BCFULL,
		0x714E45350D53660AULL,
		0xE0F1248EEE6CD604ULL,
		0x280AA2B46DE9AAAEULL,
		0xD491B18BEF6875D6ULL,
		0x005DB4AD511C1646ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE6CF5DB336C5049BULL,
		0x3802E8E0E494F7D7ULL,
		0x6DDD2BC09DE6AD66ULL,
		0x0AF0027686DF7530ULL,
		0xA1E26447D6F42209ULL,
		0x19004B4C9992367AULL,
		0x201DCBD42330B9C7ULL,
		0xE77DF0E97EDD52E2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2605001212800019ULL,
		0x200248A0E09046C4ULL,
		0x2C1500C01C022946ULL,
		0x0040003404536400ULL,
		0xA0E02406C6640200ULL,
		0x080002040980222AULL,
		0x00118180232031C6ULL,
		0x005DB0A9501C1242ULL
	}};
	printf("Test Case 231\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 231 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -231;
	} else {
		printf("Test Case 231 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5F114D5AA600632BULL,
		0xEB1284F70E665DF9ULL,
		0x4BDECCC1C0B571E2ULL,
		0x9C321B9F58819B09ULL,
		0x6F6AABDCC5AF8136ULL,
		0x4FF2C17FF62ECB4FULL,
		0x844C997250848A15ULL,
		0xDD9203366F1A47C7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xADA72EE64F5DDC04ULL,
		0x1ACC0C340E165318ULL,
		0xB09586AF6370AC5FULL,
		0xF547ED2DF777AEBDULL,
		0x3BB97C3AAAB5CA3DULL,
		0xB413271AE06E9B2EULL,
		0x52C82BC16BE51BE5ULL,
		0x9119217D92091509ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0D010C4206004000ULL,
		0x0A0004340E065118ULL,
		0x0094848140302042ULL,
		0x9402090D50018A09ULL,
		0x2B28281880A58034ULL,
		0x0412011AE02E8B0EULL,
		0x0048094040840A05ULL,
		0x9110013402080501ULL
	}};
	printf("Test Case 232\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 232 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -232;
	} else {
		printf("Test Case 232 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE559D6D1630BFD37ULL,
		0x6D6E80C860546849ULL,
		0x0BD39F1072FAC391ULL,
		0xE09E2D520D521BB6ULL,
		0xE633AE3A915F3F8AULL,
		0xF414951BCCF49C41ULL,
		0x8A7A5B5358085E6DULL,
		0x358E90684799B98BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB91D40F7D703F9EDULL,
		0x87DDF2334C1E581AULL,
		0xC48E09ABD6C47D55ULL,
		0xA2E8495011D8DDAAULL,
		0x7F3204B9BE23701AULL,
		0x5832D78BE5675C0BULL,
		0x85A9E9078757B35BULL,
		0x230A3064BDD59186ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA11940D14303F925ULL,
		0x054C800040144808ULL,
		0x0082090052C04111ULL,
		0xA0880950015019A2ULL,
		0x663204389003300AULL,
		0x5010950BC4641C01ULL,
		0x8028490300001249ULL,
		0x210A106005919182ULL
	}};
	printf("Test Case 233\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 233 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -233;
	} else {
		printf("Test Case 233 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x719B72E64A5E59B8ULL,
		0x47004198ABE639D0ULL,
		0x56500FFEDF497508ULL,
		0x0DA1CD70B8EC3FF8ULL,
		0xD319D3054739442EULL,
		0x95B91AC51F0CC477ULL,
		0xAE3E7E110C0246CEULL,
		0xC1C253CFBC51E1B5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1FA1345F53212B64ULL,
		0xAE753B193F3115E4ULL,
		0xA9E6B37ED647BEC7ULL,
		0x7B2524E8A12DCCD7ULL,
		0xBE153FA3678DD94FULL,
		0xA3EED6076FF6CF51ULL,
		0xD2F3443E53D9507CULL,
		0x91C1E176318F30E4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1181304642000920ULL,
		0x060001182B2011C0ULL,
		0x0040037ED6413400ULL,
		0x09210460A02C0CD0ULL,
		0x921113014709400EULL,
		0x81A812050F04C451ULL,
		0x823244100000404CULL,
		0x81C04146300120A4ULL
	}};
	printf("Test Case 234\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 234 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -234;
	} else {
		printf("Test Case 234 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2B8DBE092FE8B300ULL,
		0x46DDD80BA9E4507DULL,
		0x3BC3BD0EF84B29F8ULL,
		0x2E2A2CD533CB4036ULL,
		0x584E6BDE5BBB496AULL,
		0xE840C8757C93C8E8ULL,
		0xE3456ED559F2F47DULL,
		0xB7D3E720FFEBB262ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8D7B62C1D7FBB25BULL,
		0x85AD2BE596CC5290ULL,
		0x3FB1BEEDC7ED587CULL,
		0x3C3478A6D560180AULL,
		0x364F96FC8AFDBC2BULL,
		0x618128FD317BEB07ULL,
		0x8D7378A585AE5068ULL,
		0xB5EE3EB6519C8034ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0909220107E8B200ULL,
		0x048D080180C45010ULL,
		0x3B81BC0CC0490878ULL,
		0x2C20288411400002ULL,
		0x104E02DC0AB9082AULL,
		0x600008753013C800ULL,
		0x8141688501A25068ULL,
		0xB5C2262051888020ULL
	}};
	printf("Test Case 235\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 235 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -235;
	} else {
		printf("Test Case 235 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDF0EFE86A0C0CE5FULL,
		0x8494B9C42B27DF76ULL,
		0xA077E8E0296B0495ULL,
		0x27CCC8FDB7CE710CULL,
		0x43B65B50877A1D84ULL,
		0xC7BE5260ECED9F03ULL,
		0xC13D5EB02A8BB174ULL,
		0xF4ACFFBBB76E6C20ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6293FBAD0AC8C4D3ULL,
		0xBD1D1492BB3E0C8BULL,
		0x544A8BB88544C1C0ULL,
		0x05BF62E5058AAE2DULL,
		0xDDE9E4E81480510FULL,
		0x1DC8198CAFA2F44EULL,
		0xC3F879CCAA873A7BULL,
		0x2E7E4DB26C9C1957ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4202FA8400C0C453ULL,
		0x841410802B260C02ULL,
		0x004288A001400080ULL,
		0x058C40E5058A200CULL,
		0x41A0404004001104ULL,
		0x05881000ACA09402ULL,
		0xC13858802A833070ULL,
		0x242C4DB2240C0800ULL
	}};
	printf("Test Case 236\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 236 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -236;
	} else {
		printf("Test Case 236 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC303BBFFD8B490BEULL,
		0xAB525E578B9EE0F6ULL,
		0xEA6FB5B436496A72ULL,
		0x53C5F3691D7C7174ULL,
		0x57192DA003E6A4E6ULL,
		0x5585C4A400BC4ED4ULL,
		0x399F3DAF53AF06E1ULL,
		0x4683C484A9BFB9C3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3D8F5BEEB5A61386ULL,
		0x6A11D9076600999DULL,
		0x76B48651EDBE1326ULL,
		0xC4565F44B0C150A4ULL,
		0x74BB6F5660DF7420ULL,
		0x1AF28346A795C269ULL,
		0xFBEC5C4FE5758002ULL,
		0x69EC03430E1BFA0FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x01031BEE90A41086ULL,
		0x2A10580702008094ULL,
		0x6224841024080222ULL,
		0x4044534010405024ULL,
		0x54192D0000C62420ULL,
		0x1080800400944240ULL,
		0x398C1C0F41250000ULL,
		0x40800000081BB803ULL
	}};
	printf("Test Case 237\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 237 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -237;
	} else {
		printf("Test Case 237 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAA5F9104D2CD68ABULL,
		0x371BEA750ABE29BEULL,
		0x60A708BB40A7C385ULL,
		0x3016866D46F4F333ULL,
		0x7A52BA7AC9D57602ULL,
		0xCF20984360A98EF9ULL,
		0x38A5300D83E69844ULL,
		0x68059B66C01C833FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3B0726A2701CE06BULL,
		0xC60E277A5B534167ULL,
		0x41B57BE44D78A31FULL,
		0x8A5A0E1ECF515A0DULL,
		0x33713933409EE25BULL,
		0x4A59ACC47D135E2CULL,
		0x7383A043F540C837ULL,
		0x6B58E1A95133870EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2A070000500C602BULL,
		0x060A22700A120126ULL,
		0x40A508A040208305ULL,
		0x0012060C46505201ULL,
		0x3250383240946202ULL,
		0x4A00884060010E28ULL,
		0x3081200181408804ULL,
		0x680081204010830EULL
	}};
	printf("Test Case 238\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 238 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -238;
	} else {
		printf("Test Case 238 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0FB72B09C871F3F7ULL,
		0x14EB03CD125B24F4ULL,
		0x47114AEF24E9F9C3ULL,
		0x60487D40B7BE23DCULL,
		0xF6A3645FB9901EC6ULL,
		0x28F7E811EB3F0D50ULL,
		0xE543DB404FCFD011ULL,
		0x15F299562E761A5DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x21A9EA80367CC03AULL,
		0x3174F4E931DE5D8DULL,
		0x8CD2C5EEF896F614ULL,
		0x81ECA8E061C5687DULL,
		0xB70DACF2924519A3ULL,
		0x408252C6D1EBD6C2ULL,
		0xF6D2EECA61541D6AULL,
		0x1D8E346F38388036ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x01A12A000070C032ULL,
		0x106000C9105A0484ULL,
		0x041040EE2080F000ULL,
		0x004828402184205CULL,
		0xB601245290001882ULL,
		0x00824000C12B0440ULL,
		0xE442CA4041441000ULL,
		0x1582104628300014ULL
	}};
	printf("Test Case 239\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 239 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -239;
	} else {
		printf("Test Case 239 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5BEA8055955703B9ULL,
		0xF4B8D209F46389E9ULL,
		0x4B8E503F7CDE79B8ULL,
		0x810439D7B75538BBULL,
		0x5521116983DE58CEULL,
		0x868AF2CDDCC70D99ULL,
		0x33C071AAA24C2726ULL,
		0x3D7D23DFEA82BADFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x36D4ACD3235F52F6ULL,
		0x212C2A530766BE82ULL,
		0x8957155CC8A193FAULL,
		0xBD760B817C7434A2ULL,
		0x292294105E42CA10ULL,
		0x16146C6760EF8AFEULL,
		0xC7A4C76190A9EC48ULL,
		0xD6568DCF89845B84ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x12C08051015702B0ULL,
		0x2028020104628880ULL,
		0x0906101C488011B8ULL,
		0x81040981345430A2ULL,
		0x0120100002424800ULL,
		0x0600604540C70898ULL,
		0x0380412080082400ULL,
		0x145401CF88801A84ULL
	}};
	printf("Test Case 240\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 240 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -240;
	} else {
		printf("Test Case 240 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE83B0500CFA648E0ULL,
		0x5DCE43C6B5DEE035ULL,
		0x7BAE1259BA43D36FULL,
		0x5ACC2E4D7CF1CA31ULL,
		0x8D4B606C823C957DULL,
		0xB7FF0773E0312633ULL,
		0x6EBAAA0D24611EB4ULL,
		0xE33052C4733C073FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x88DD5C71D7A40AE1ULL,
		0x51C2D3FAE0693917ULL,
		0x28E546A60BE648EAULL,
		0xD2B20166146D69DAULL,
		0xF9F79ACC6B749E57ULL,
		0x1EF0F330C737AC2CULL,
		0x7289098B9B101CCBULL,
		0x43470E4A7FDD084AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x88190400C7A408E0ULL,
		0x51C243C2A0482015ULL,
		0x28A402000A42406AULL,
		0x5280004414614810ULL,
		0x8943004C02349455ULL,
		0x16F00330C0312420ULL,
		0x6288080900001C80ULL,
		0x43000240731C000AULL
	}};
	printf("Test Case 241\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 241 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -241;
	} else {
		printf("Test Case 241 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF96A79C43758A9E8ULL,
		0xB5BC587B9D7122A4ULL,
		0x4EFB4238A6DE7429ULL,
		0x14C4AF1609E88EBCULL,
		0x21D01C64400B9C4EULL,
		0xAD50A222BE901655ULL,
		0x82F61DB1A27F592AULL,
		0x8F4B72956D7271A6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x93A210C2693E7096ULL,
		0xF28AC278D4982593ULL,
		0x1F3CB7099411738EULL,
		0x1F9E8832DBDF5DDCULL,
		0x5CA0B83CDFDFFCF4ULL,
		0x57DA617F06B072F4ULL,
		0xE967E4861DDCCD6DULL,
		0x3E55644AE5EF27BDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x912210C021182080ULL,
		0xB088407894102080ULL,
		0x0E38020884107008ULL,
		0x1484881209C80C9CULL,
		0x00801824400B9C44ULL,
		0x0550202206901254ULL,
		0x80660480005C4928ULL,
		0x0E416000656221A4ULL
	}};
	printf("Test Case 242\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 242 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -242;
	} else {
		printf("Test Case 242 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCF7AA477C0DF2FCEULL,
		0xDD7F9A00ED75D093ULL,
		0xE374A8B657472518ULL,
		0xA4B023302A3768ECULL,
		0x4739EA2D8EF840D6ULL,
		0x7F09AAB4EF5C2654ULL,
		0xC1BEE3C897DCFA1DULL,
		0x96574157AFD1889CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6DC70402292FDA65ULL,
		0xB56C84D610C2C42BULL,
		0x076D64AB30982C6AULL,
		0x1A5E7509D81D7B36ULL,
		0xE93E97CEB470A582ULL,
		0xF3CA7B0F8BEAEC2BULL,
		0xB41EB453C863807EULL,
		0xDC7BF289739B30C8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4D420402000F0A44ULL,
		0x956C80000040C003ULL,
		0x036420A210002408ULL,
		0x0010210008156824ULL,
		0x4138820C84700082ULL,
		0x73082A048B482400ULL,
		0x801EA0408040801CULL,
		0x9453400123910088ULL
	}};
	printf("Test Case 243\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 243 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -243;
	} else {
		printf("Test Case 243 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF1048C7B10AAD47CULL,
		0x64C6C5084068672FULL,
		0xC0CCA6E920533B49ULL,
		0x66D0F20DC5928A0FULL,
		0x267CD3696A406A82ULL,
		0xF8643FA9D5F1936EULL,
		0xF86077863A1EAF90ULL,
		0x33E4E703929E149BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x04B71D5CB2C75353ULL,
		0x143EA7EEE59D2A68ULL,
		0xCE94D94DC5005EBCULL,
		0x89C759E3C1503F88ULL,
		0xBCD46F3188B7F226ULL,
		0x37E7DDDD116CB28CULL,
		0x148AB3E34F0DBDE9ULL,
		0x7611B9222E8A3208ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x00040C5810825050ULL,
		0x0406850840082228ULL,
		0xC084804900001A08ULL,
		0x00C05001C1100A08ULL,
		0x2454432108006202ULL,
		0x30641D891160920CULL,
		0x100033820A0CAD80ULL,
		0x3200A102028A1008ULL
	}};
	printf("Test Case 244\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 244 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -244;
	} else {
		printf("Test Case 244 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x413AD558A68E24F4ULL,
		0x7ADCB21113B133AEULL,
		0x0D4C50703055103EULL,
		0x1C769430DBB8EF4AULL,
		0x0E12BF0D97DB3502ULL,
		0x7132442E0D4E35AEULL,
		0x0AFA3620834467D4ULL,
		0x6D75F65061100DD3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC6276FE8462905EDULL,
		0xA4B6D64E3F0E4E7BULL,
		0x24D847FEA497DFFDULL,
		0xA716605B34449EEEULL,
		0x537D1AE2B085C290ULL,
		0x2E52CFAB21D18901ULL,
		0xD7177D92C40528C2ULL,
		0x59757A7CE697F826ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x40224548060804E4ULL,
		0x209492001300022AULL,
		0x044840702015103CULL,
		0x0416001010008E4AULL,
		0x02101A0090810000ULL,
		0x2012442A01400100ULL,
		0x02123400800420C0ULL,
		0x4975725060100802ULL
	}};
	printf("Test Case 245\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 245 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -245;
	} else {
		printf("Test Case 245 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x316CB9BC63A02664ULL,
		0xCE1F9827A72EE05AULL,
		0xE563A016505EF432ULL,
		0xD5EAE4F4C8B4FB93ULL,
		0xBBF9B82BF0C809F3ULL,
		0x18A5D36BA5642258ULL,
		0xDD86F7A817D1BA74ULL,
		0x9E4215483D79283CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x260ABF76343B827BULL,
		0xC2DA54988F5CE441ULL,
		0x1975EADB73BDF1E5ULL,
		0x23686EA7CF3E05F1ULL,
		0xAE63A0355DF7D0C0ULL,
		0xA871B090BED40A17ULL,
		0xB7485AB20DA2B122ULL,
		0x817E536BD66A618AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2008B93420200260ULL,
		0xC21A1000870CE040ULL,
		0x0161A012501CF020ULL,
		0x016864A4C8340191ULL,
		0xAA61A02150C000C0ULL,
		0x08219000A4440210ULL,
		0x950052A00580B020ULL,
		0x8042114814682008ULL
	}};
	printf("Test Case 246\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 246 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -246;
	} else {
		printf("Test Case 246 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD800821B355F80DBULL,
		0x5C09B112AB4CAF4CULL,
		0x6E76739E4DB21D87ULL,
		0xBFFE3E0C1E9FA408ULL,
		0xDED66524BCE8A7DCULL,
		0x6124C24EB510E467ULL,
		0xA9AD097E9E18ABFFULL,
		0xC64C5B0FFD63465EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x636BEA9CB613F98CULL,
		0xD88BD5E6714E820CULL,
		0xA3A6935E51C5CD5DULL,
		0x0FE64ACF57E39456ULL,
		0x9907863CFE6FACCCULL,
		0xA5A9F588AE4CE70BULL,
		0x61B6D8F4C9BDF259ULL,
		0xE52991450749FB4FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4000821834138088ULL,
		0x58099102214C820CULL,
		0x2226131E41800D05ULL,
		0x0FE60A0C16838400ULL,
		0x98060424BC68A4CCULL,
		0x2120C008A400E403ULL,
		0x21A408748818A259ULL,
		0xC40811050541424EULL
	}};
	printf("Test Case 247\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 247 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -247;
	} else {
		printf("Test Case 247 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF68783E147DA70D7ULL,
		0xA1B0CB3B38593E46ULL,
		0x74730E2F58294E28ULL,
		0x1B79C7DB977B918BULL,
		0xC2B5F86C22394CF7ULL,
		0xFC64B22D7383B651ULL,
		0xE6AF0EBEEDC59251ULL,
		0xB22BFC463664DD1CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x93F36DB331CB6F30ULL,
		0x23C868A1675D06D2ULL,
		0xA430399D44788CD1ULL,
		0x1D5D73BDC460123DULL,
		0x323F4E0BBD044F48ULL,
		0xE470475CBA20AAF2ULL,
		0x2567E52EB3BE51F0ULL,
		0x296FA1A6F514DDD1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x928301A101CA6010ULL,
		0x2180482120590642ULL,
		0x2430080D40280C00ULL,
		0x1959439984601009ULL,
		0x0235480820004C40ULL,
		0xE460020C3200A250ULL,
		0x2427042EA1841050ULL,
		0x202BA0063404DD10ULL
	}};
	printf("Test Case 248\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 248 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -248;
	} else {
		printf("Test Case 248 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x175636E6F05A0310ULL,
		0x14958287F899BB4EULL,
		0x6C046929C3C1C1D2ULL,
		0x194FB5D093B70B37ULL,
		0xA32D184CB7D6EAD2ULL,
		0xF2CC5BADD013E391ULL,
		0x49CE6E494389F09DULL,
		0x1649439CBEAD8D60ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6DA737A322A46E35ULL,
		0xE3750A3373A94F2EULL,
		0x8A008E5517C9CC3CULL,
		0x99D926E6C722ADCFULL,
		0x9E50E85769F42000ULL,
		0x2F13169DE21BF2EBULL,
		0xD08ADFCFED888C7EULL,
		0x74A12CA42AF223ECULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x050636A220000210ULL,
		0x0015020370890B0EULL,
		0x0800080103C1C010ULL,
		0x194924C083220907ULL,
		0x8200084421D42000ULL,
		0x2200128DC013E281ULL,
		0x408A4E494188801CULL,
		0x140100842AA00160ULL
	}};
	printf("Test Case 249\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 249 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -249;
	} else {
		printf("Test Case 249 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x166F160B322E7414ULL,
		0xB8E81A1E81832A14ULL,
		0xA26065242EA5FB7FULL,
		0x38893E38E73431EEULL,
		0xAE29F9E017E4FF6CULL,
		0x08EE51B7134C53E4ULL,
		0xDB0E5D4268F48B07ULL,
		0xF0AC3CA61E64287BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCE158DA117F4923CULL,
		0xC96014D8F7B73742ULL,
		0x4F29E1B7E47C789DULL,
		0xFAF92DFDA710F57AULL,
		0x08FCE2E40EF4115DULL,
		0x01D7AEED558C1F26ULL,
		0x1AEB3C62903F4219ULL,
		0x644367633BB0BFCCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0605040112241014ULL,
		0x8860101881832200ULL,
		0x022061242424781DULL,
		0x38892C38A710316AULL,
		0x0828E0E006E4114CULL,
		0x00C600A5110C1324ULL,
		0x1A0A1C4200340201ULL,
		0x600024221A202848ULL
	}};
	printf("Test Case 250\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 250 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -250;
	} else {
		printf("Test Case 250 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x899F55B0F276C280ULL,
		0xF731581C386555B7ULL,
		0xA86923E5B410DDECULL,
		0xA8147F82E8CED6EFULL,
		0xC89E84C3EE6573D5ULL,
		0x2A3F9791A4D47043ULL,
		0xFC0F9FB21B2E6914ULL,
		0x51FB4DB5ADAD83C0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x193F0143978FE4B2ULL,
		0x7EE4917C8993BA47ULL,
		0x2BE7B72261A76683ULL,
		0x5FF54026B9564374ULL,
		0x415180A3DF5F51F5ULL,
		0x1C4D404B4671D6C6ULL,
		0xF36B844D5257E5A8ULL,
		0x50F5093E1DEAD9F7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x091F01009206C080ULL,
		0x7620101C08011007ULL,
		0x2861232020004480ULL,
		0x08144002A8464264ULL,
		0x40108083CE4551D5ULL,
		0x080D000104505042ULL,
		0xF00B840012066100ULL,
		0x50F109340DA881C0ULL
	}};
	printf("Test Case 251\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 251 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -251;
	} else {
		printf("Test Case 251 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xED3C2FEBB2B85968ULL,
		0x67E19B677914BE60ULL,
		0xEB3D4974402A20D9ULL,
		0x549C080DB05DA0C6ULL,
		0xD432D072AC2A210AULL,
		0x6EBB1B9DBE27E962ULL,
		0xB92AC0B2ACBF2196ULL,
		0x9054CCAA64757A6BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6FB0F61C4705935CULL,
		0xE720FEB1B904CA45ULL,
		0x4AC2B2B014C239EAULL,
		0x83970E93C3F36D2CULL,
		0x671180859B8B1B38ULL,
		0x04CAF274ACECE663ULL,
		0x06266D8AA6FB4A25ULL,
		0xBD2FF9DE516FFE21ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6D30260802001148ULL,
		0x67209A2139048A40ULL,
		0x4A000030000220C8ULL,
		0x0094080180512004ULL,
		0x44108000880A0108ULL,
		0x048A1214AC24E062ULL,
		0x00224082A4BB0004ULL,
		0x9004C88A40657A21ULL
	}};
	printf("Test Case 252\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 252 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -252;
	} else {
		printf("Test Case 252 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF517BC0841BFC360ULL,
		0xEC7ECDA8639AEC25ULL,
		0xEB523FE28A91AB07ULL,
		0xEAA111C46E0BF857ULL,
		0x674CE30D756DF4EFULL,
		0x31B2D16AD922C6C5ULL,
		0x7DC0D7C8650E52E0ULL,
		0x29AA2CF492D3C425ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1C1A41B0EAE96D33ULL,
		0x86F33B2420DE06C3ULL,
		0x04DD4BC99568861BULL,
		0x849ECB94A8AB7841ULL,
		0x1D22E8E552A15B0FULL,
		0x0C8042B36D417F71ULL,
		0x37EEC749610609EAULL,
		0x9C01639C0BFA3124ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1412000040A94120ULL,
		0x84720920209A0401ULL,
		0x00500BC080008203ULL,
		0x80800184280B7841ULL,
		0x0500E0055021500FULL,
		0x0080402249004641ULL,
		0x35C0C748610600E0ULL,
		0x0800209402D20024ULL
	}};
	printf("Test Case 253\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 253 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -253;
	} else {
		printf("Test Case 253 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF76F3996C6F592C6ULL,
		0xA49B34819575FF2BULL,
		0x0D4084C8449F5D36ULL,
		0x84E233CCA9893922ULL,
		0x7DE5FF80743DF49FULL,
		0x826C2AB805118780ULL,
		0xCFA3B001A94FE003ULL,
		0xF72D0406F7229185ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x638A5DE650AC0082ULL,
		0xE5C61E0C6CB22D27ULL,
		0x8997FE119D5F716EULL,
		0x5DBB008014DC55D5ULL,
		0x7CBCD12E7A32CA9DULL,
		0x1A3EC498BBE727BDULL,
		0xCBB089F1D523EA7EULL,
		0x785681F89B50FF15ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x630A198640A40082ULL,
		0xA482140004302D23ULL,
		0x09008400041F5126ULL,
		0x04A2008000881100ULL,
		0x7CA4D1007030C09DULL,
		0x022C009801010780ULL,
		0xCBA080018103E002ULL,
		0x7004000093009105ULL
	}};
	printf("Test Case 254\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 254 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -254;
	} else {
		printf("Test Case 254 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x676FB017EC61CBC7ULL,
		0x5A5F82B5308400E9ULL,
		0xA1A75A10FDF0ECB5ULL,
		0x25DF6E5617DA95B4ULL,
		0xEE6A08236E306981ULL,
		0x27B1C09DF69C61ACULL,
		0x6EAE1ABA7ABA27D3ULL,
		0xBACCCD6470A51CF2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x452266D237832F17ULL,
		0xAF9DDE0256FC440AULL,
		0x614D34E965C27848ULL,
		0xD103A322ECC8AF2FULL,
		0xD2AD1CDB9AC38BF6ULL,
		0x1F96CF87907320F1ULL,
		0x21F42573AF4116A2ULL,
		0xBEF209D365BDF72EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4522201224010B07ULL,
		0x0A1D820010840008ULL,
		0x2105100065C06800ULL,
		0x0103220204C88524ULL,
		0xC22808030A000980ULL,
		0x0790C085901020A0ULL,
		0x20A400322A000682ULL,
		0xBAC0094060A51422ULL
	}};
	printf("Test Case 255\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 255 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -255;
	} else {
		printf("Test Case 255 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2B02EA76D3119C3EULL,
		0x537B8A997B59A8C8ULL,
		0x58A7B526C536B0E2ULL,
		0x265F2E2B02358323ULL,
		0xA5AD00E274BCE24EULL,
		0x44F6BFBEA54B7D67ULL,
		0xED51F1F9618F40FDULL,
		0xB0979BD3A1724514ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x545127DE8CB8F74BULL,
		0x09A0AF046387B127ULL,
		0xB7576DC4D7FC622BULL,
		0x4CC7AD30B4938806ULL,
		0xF69D4F545850EA3BULL,
		0x44EBA2C2180ABF30ULL,
		0x7EC2A0428CB0D042ULL,
		0xDC2753EB7CEBA1F1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x000022568010940AULL,
		0x01208A006301A000ULL,
		0x10072504C5342022ULL,
		0x04472C2000118002ULL,
		0xA48D00405010E20AULL,
		0x44E2A282000A3D20ULL,
		0x6C40A04000804040ULL,
		0x900713C320620110ULL
	}};
	printf("Test Case 256\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 256 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -256;
	} else {
		printf("Test Case 256 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE058A1414AF45256ULL,
		0x83637C23E5F1A9F1ULL,
		0x3A534AE3562A36E4ULL,
		0x6892AC7026DAEBB3ULL,
		0xDDF5AB980DA1EBE8ULL,
		0x6EBE9D1CD824386EULL,
		0x824C1E698CF2ED0CULL,
		0x468C2A950D161055ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x33A552C3A4EFDBB3ULL,
		0xADB1E93205FDBEEBULL,
		0xCC846949D125F3EDULL,
		0x8DD3FD0DA05E86EAULL,
		0x4D00105775D984FCULL,
		0xC48072DE9FBCF4E0ULL,
		0x1DA618B0A23A8B0EULL,
		0x4595C50C2433CBAEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2000004100E45212ULL,
		0x8121682205F1A8E1ULL,
		0x08004841502032E4ULL,
		0x0892AC00205A82A2ULL,
		0x4D000010058180E8ULL,
		0x4480101C98243060ULL,
		0x000418208032890CULL,
		0x4484000404120004ULL
	}};
	printf("Test Case 257\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 257 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -257;
	} else {
		printf("Test Case 257 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5A7295EC01B29645ULL,
		0x84F2B741DFE85EB5ULL,
		0xADF3907E7EE848A0ULL,
		0x84EAB5ECC239B653ULL,
		0x69D70E1DEA2F250AULL,
		0xF4A476169A5EB8B9ULL,
		0x22A5C8FE920291BCULL,
		0xFAD93C15C1637870ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0EDFF6E42D6F0698ULL,
		0x2A78FABA6BFC08C6ULL,
		0x5092A7DE8EF5E1E4ULL,
		0x9F80BC92100B39A7ULL,
		0xF6248EA701D699DCULL,
		0x8578DE0DFBA0446CULL,
		0x3AFAB10443D3A042ULL,
		0xF972E0F3465E105AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0A5294E401220600ULL,
		0x0070B2004BE80884ULL,
		0x0092805E0EE040A0ULL,
		0x8480B48000093003ULL,
		0x60040E0500060108ULL,
		0x842056049A000028ULL,
		0x22A0800402028000ULL,
		0xF850201140421050ULL
	}};
	printf("Test Case 258\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 258 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -258;
	} else {
		printf("Test Case 258 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFDE9B58A1860A233ULL,
		0x1A553B0B28D79325ULL,
		0x3D78C334FC916C6DULL,
		0x3746EF1B2259CA84ULL,
		0x07245044ED10316EULL,
		0xECDD5E68C4ABE1BAULL,
		0xDE826F1EBE392B86ULL,
		0x60ADB8E40CFD5B8AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE25748926D896244ULL,
		0x5D047212D763C334ULL,
		0xA078CA64784D32C4ULL,
		0xA634D04253DDBAC5ULL,
		0xDEBD0A621CDDD82EULL,
		0x28827D60C1A4DB21ULL,
		0xAACF4F5D1EAFF4C7ULL,
		0x0F4130526AD18AFBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE041008208002200ULL,
		0x1804320200438324ULL,
		0x2078C22478012044ULL,
		0x2604C00202598A84ULL,
		0x062400400C10102EULL,
		0x28805C60C0A0C120ULL,
		0x8A824F1C1E292086ULL,
		0x0001304008D10A8AULL
	}};
	printf("Test Case 259\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 259 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -259;
	} else {
		printf("Test Case 259 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5DB50333D0BA8457ULL,
		0xE9249866E1BDFBF6ULL,
		0xB4C781ED8F2C5942ULL,
		0xECAD69017078CDC7ULL,
		0xAD62C5E649F2992FULL,
		0xDEDCF7FB47C176EDULL,
		0xC74C71A5B40959D1ULL,
		0x795708324F7F8674ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE2CEEE035B89D514ULL,
		0xC51FC5F12C6FDFD6ULL,
		0x7D879A53B73B41A1ULL,
		0x1FBD579E5475FB33ULL,
		0xDEE4C70DDF324464ULL,
		0x21A8A51BAA4DA12FULL,
		0xACE13EE154B7EA91ULL,
		0xDF49ACB45F9DB639ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4084020350888414ULL,
		0xC1048060202DDBD6ULL,
		0x3487804187284100ULL,
		0x0CAD41005070C903ULL,
		0x8C60C50449320024ULL,
		0x0088A51B0241202DULL,
		0x844030A114014891ULL,
		0x594108304F1D8630ULL
	}};
	printf("Test Case 260\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 260 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -260;
	} else {
		printf("Test Case 260 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCCD7E12937D369E5ULL,
		0x7F57682EC5207691ULL,
		0x49716E0AF4629ADAULL,
		0x757D338B84A583A2ULL,
		0x880772B8C6A8BD63ULL,
		0x37E6D8AE149B4C94ULL,
		0x64458C02D92EE12FULL,
		0xD319744062299924ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x54AE479A46FBD418ULL,
		0xCEB3B90396EE63FCULL,
		0xD98AA2C3F416B142ULL,
		0x8D66770F8F48AD35ULL,
		0x022DC598B7EC2ACEULL,
		0x2C2FFFC9B6742348ULL,
		0xA727FC3942448116ULL,
		0xDE951CF6B55A3622ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4486410806D34000ULL,
		0x4E13280284206290ULL,
		0x49002202F4029042ULL,
		0x0564330B84008120ULL,
		0x0005409886A82842ULL,
		0x2426D88814100000ULL,
		0x24058C0040048106ULL,
		0xD211144020081020ULL
	}};
	printf("Test Case 261\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 261 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -261;
	} else {
		printf("Test Case 261 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6131C4970FA9AA62ULL,
		0x9B9E88B4C7D5E5F5ULL,
		0x8A3E265BC33725ABULL,
		0x4A629159D7886623ULL,
		0xA196D58B1E47B22BULL,
		0x61A80BEA2D158329ULL,
		0xF20F0B22030EC9D5ULL,
		0x737BF61F4FEC3AA5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4DCB42871004D3CDULL,
		0xE01F479DDB1BA337ULL,
		0xEEF03630ACE02C57ULL,
		0x7D39C28B815500F7ULL,
		0xBF0CF5DF5F144B07ULL,
		0x10F86B440EE213E1ULL,
		0xCA2C6A9B95A32D0BULL,
		0xA92FF6AEC15D7AD4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4101408700008240ULL,
		0x801E0094C311A135ULL,
		0x8A30261080202403ULL,
		0x4820800981000023ULL,
		0xA104D58B1E040203ULL,
		0x00A80B400C000321ULL,
		0xC20C0A0201020901ULL,
		0x212BF60E414C3A84ULL
	}};
	printf("Test Case 262\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 262 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -262;
	} else {
		printf("Test Case 262 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEA30900097562EEBULL,
		0x0854ABC94F4F203AULL,
		0xA1515492F537E60AULL,
		0xE7C60CD8E0B1FA24ULL,
		0xDA5EC611AC2D4BCDULL,
		0xBAF3C427DA90BAEFULL,
		0x6AD2045F2B92EF8EULL,
		0x732F39FE6489C5E3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAD4B10C0DBBFA8DFULL,
		0xA90412CA7FCD3F10ULL,
		0xE5B4B5DEFE6372BFULL,
		0xD01F8A1382DEB447ULL,
		0xBA90894646B9D40DULL,
		0x563D09A251C9C6ABULL,
		0x99C08A5C865DC762ULL,
		0x9FAEC6BD52C87B7EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA8001000931628CBULL,
		0x080402C84F4D2010ULL,
		0xA1101492F423620AULL,
		0xC00608108090B004ULL,
		0x9A1080000429400DULL,
		0x12310022508082ABULL,
		0x08C0005C0210C702ULL,
		0x132E00BC40884162ULL
	}};
	printf("Test Case 263\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 263 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -263;
	} else {
		printf("Test Case 263 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x54EB96FF320F0109ULL,
		0x4C5B190307B82C3CULL,
		0x11F933544018C425ULL,
		0x3E06316385F17187ULL,
		0xD7BE4C081FB7B7D1ULL,
		0x9DD2C5280C4F811CULL,
		0xF59347568330F709ULL,
		0xB36A91813170A475ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2686D19052240D78ULL,
		0xD700B4D4492E83E7ULL,
		0x0B2AB88C564B0AE9ULL,
		0x567D6741D73BD746ULL,
		0x98CB5BB8EF90EAC1ULL,
		0xD57AEE16D60F0A02ULL,
		0x9F51BBD043802C38ULL,
		0xF5E0F842618E1912ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0482909012040108ULL,
		0x4400100001280024ULL,
		0x0128300440080021ULL,
		0x1604214185315106ULL,
		0x908A48080F90A2C1ULL,
		0x9552C400040F0000ULL,
		0x9511035003002408ULL,
		0xB160900021000010ULL
	}};
	printf("Test Case 264\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 264 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -264;
	} else {
		printf("Test Case 264 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE38763D6E237B024ULL,
		0xE9EAB676672CCAD3ULL,
		0xD1109C7D28A34B75ULL,
		0x502B6D41349EDA15ULL,
		0x2AEC319CE9C5FE64ULL,
		0x4CD805DFD22EEF82ULL,
		0x88C51C1E9C93A2A7ULL,
		0x3DE18402AC8B2B04ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x08FDBFD6A7C53FDCULL,
		0x08E956ABE5448622ULL,
		0xAEE930DC428578D5ULL,
		0xEC2666B9314CF530ULL,
		0x8C3CAE2339FCB6E6ULL,
		0xDFB3C4CC28A22B7BULL,
		0xAFC34F0C1077C717ULL,
		0xF27136D0CBE5E0C6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x008523D6A2053004ULL,
		0x08E8162265048202ULL,
		0x8000105C00814855ULL,
		0x40226401300CD010ULL,
		0x082C200029C4B664ULL,
		0x4C9004CC00222B02ULL,
		0x88C10C0C10138207ULL,
		0x3061040088812004ULL
	}};
	printf("Test Case 265\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 265 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -265;
	} else {
		printf("Test Case 265 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB4BD2AA9C7FD3D76ULL,
		0xE05BFF712F593BA7ULL,
		0x43859F6E53879C9BULL,
		0x98680E84CCEC00DBULL,
		0x524BACD18CCA63CEULL,
		0x6C2158875BF2CD39ULL,
		0xD7951E34840FC677ULL,
		0xFD9A49E13B60CA54ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x07898B118161D362ULL,
		0xAF2D9811C28D4764ULL,
		0x60ED76C06331A943ULL,
		0x51F590109580C143ULL,
		0x3A3FACEC64380335ULL,
		0x5DE7B21C00CDB53FULL,
		0xD4CE23789DE13B36ULL,
		0x96163CEDAC1C9940ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x04890A0181611162ULL,
		0xA009981102090324ULL,
		0x4085164043018803ULL,
		0x1060000084800043ULL,
		0x120BACC004080304ULL,
		0x4C21100400C08539ULL,
		0xD484023084010236ULL,
		0x941208E128008840ULL
	}};
	printf("Test Case 266\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 266 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -266;
	} else {
		printf("Test Case 266 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x731E232EE5146141ULL,
		0x5D6B02B5BB1248EDULL,
		0x699570AB4C3EC203ULL,
		0x0BEEC4194E08D8B6ULL,
		0xC8CF74EF426E8470ULL,
		0xFE51595C713B9895ULL,
		0x1E7A988D1F2D8D79ULL,
		0xBB6C02D826333C07ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFBC0F23AC0326A13ULL,
		0xDA5084BA617DDF1AULL,
		0x356F36FC6E232861ULL,
		0x47B436B7EA824FD4ULL,
		0xCEADD1D42E50AFCFULL,
		0x93F2CBC415A85E81ULL,
		0x1CF930C938B9D519ULL,
		0x501DDFD34BA3B3B6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7300222AC0106001ULL,
		0x584000B021104808ULL,
		0x210530A84C220001ULL,
		0x03A404114A004894ULL,
		0xC88D50C402408440ULL,
		0x9250494411281881ULL,
		0x1C78108918298519ULL,
		0x100C02D002233006ULL
	}};
	printf("Test Case 267\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 267 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -267;
	} else {
		printf("Test Case 267 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x26BF93FAB7443826ULL,
		0x7DAC645D4AE98D35ULL,
		0x190939498EEBFDAEULL,
		0x0C7F61D0E399CDE8ULL,
		0x90D9D8006D58320BULL,
		0xE4B8EEA8805721E1ULL,
		0x5F83DE51A0CC6638ULL,
		0x1CC08E5704DE5CDEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF74D26C9543AF544ULL,
		0x71FCBC81D0940ABBULL,
		0x2CCBAE183EB46C08ULL,
		0xCC14B5119143E2B7ULL,
		0x43DC309AD57D387DULL,
		0x7FD20077A2CADFA2ULL,
		0x7F62D0A86F1CEC49ULL,
		0x63A44A695ACD95BFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x260D02C814003004ULL,
		0x71AC240140800831ULL,
		0x080928080EA06C08ULL,
		0x0C1421108101C0A0ULL,
		0x00D8100045583009ULL,
		0x64900020804201A0ULL,
		0x5F02D000200C6408ULL,
		0x00800A4100CC149EULL
	}};
	printf("Test Case 268\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 268 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -268;
	} else {
		printf("Test Case 268 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5E300153C4064214ULL,
		0xC099D980AF5EA073ULL,
		0xE7B7822E4DA159D0ULL,
		0xDE45D7C0D34E3EC8ULL,
		0x3E2E803CF84C0DE6ULL,
		0x47A6BADDF57D4472ULL,
		0x0FEACB3E53DF10E6ULL,
		0x6F713E0C1A5E3998ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB8354A209E84FDC8ULL,
		0xB88CE14D8F910F7EULL,
		0x6ED3A294164BCAF0ULL,
		0xFF0D40A6B31FCFD0ULL,
		0x6DB67D946694E59CULL,
		0xE795B47309EF9778ULL,
		0xDD359D2C46A66B7CULL,
		0x4BCED479FE8751DDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1830000084044000ULL,
		0x8088C1008F100072ULL,
		0x66938204040148D0ULL,
		0xDE054080930E0EC0ULL,
		0x2C26001460040584ULL,
		0x4784B051016D0470ULL,
		0x0D20892C42860064ULL,
		0x4B4014081A061198ULL
	}};
	printf("Test Case 269\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 269 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -269;
	} else {
		printf("Test Case 269 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD3F227A1DF9A6CADULL,
		0xD6087EFD01AFEFCEULL,
		0xDE8847942216B33EULL,
		0x3F7DE5E88D7873E3ULL,
		0x446CE7710FECCED9ULL,
		0x79E7C834162C16A7ULL,
		0x2B6096032B028663ULL,
		0xA199420B718BA049ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7747D00E8DE0D3B8ULL,
		0x7A281587940C1397ULL,
		0x64B2AFE81718E76BULL,
		0x844AD913DA776515ULL,
		0x3EE3EA73ECFD00B7ULL,
		0xD04E46D65C78F74CULL,
		0xA4C2F2355F136C3EULL,
		0x4EA1B4FCC632D184ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x534200008D8040A8ULL,
		0x52081485000C0386ULL,
		0x448007800210A32AULL,
		0x0448C10088706101ULL,
		0x0460E2710CEC0091ULL,
		0x5046401414281604ULL,
		0x204092010B020422ULL,
		0x0081000840028000ULL
	}};
	printf("Test Case 270\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 270 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -270;
	} else {
		printf("Test Case 270 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD7FBBEE373D6725FULL,
		0x47369BB228DFBD43ULL,
		0x8B0E8488A4DE20DFULL,
		0x1CF8BDC5A5420921ULL,
		0x77222F57418327B8ULL,
		0xDC3912EC26A315AFULL,
		0xD621D98165C4B91DULL,
		0x809A69C9BD65F60DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x385C0A252EA38781ULL,
		0xE4D52C6D3D48A3CFULL,
		0x990665C5BB6C03F7ULL,
		0x3943C162A49B3B6EULL,
		0x42F00981D4CEA04AULL,
		0xD0FEB94FD9633D16ULL,
		0xFBF7380E82D01642ULL,
		0x3207F4570407A3D6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x10580A2122820201ULL,
		0x441408202848A143ULL,
		0x89060480A04C00D7ULL,
		0x18408140A4020920ULL,
		0x4220090140822008ULL,
		0xD038104C00231506ULL,
		0xD221180000C01000ULL,
		0x000260410405A204ULL
	}};
	printf("Test Case 271\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 271 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -271;
	} else {
		printf("Test Case 271 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x24357B7E898FB49FULL,
		0x563F628245C31EFFULL,
		0x05ECDDC260D9C648ULL,
		0xD7989ED65279C760ULL,
		0x8FD6C66B09AA16B3ULL,
		0x39DBEA27CC20B729ULL,
		0x796F2CEFB53D00A9ULL,
		0x3632D50191DADC95ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x59967CE26468439AULL,
		0xAB5865A36894328DULL,
		0x32DC176EF7061A7AULL,
		0x7CA33BCFA5256427ULL,
		0x524C94F630978AE5ULL,
		0x111E0486BD93889EULL,
		0xC5C03162184D162AULL,
		0xAEACD66CE8042AA7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x001478620008009AULL,
		0x021860824080128DULL,
		0x00CC154260000248ULL,
		0x54801AC600214420ULL,
		0x02448462008202A1ULL,
		0x111A00068C008008ULL,
		0x41402062100D0028ULL,
		0x2620D40080000885ULL
	}};
	printf("Test Case 272\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 272 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -272;
	} else {
		printf("Test Case 272 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEBAA07E699BC9901ULL,
		0xFB7913B70B217481ULL,
		0x5E536359D7237FF8ULL,
		0x2333BBEC96554E22ULL,
		0x3444A4A159107214ULL,
		0x08A902C3BC5C6380ULL,
		0x3DF3B9D4A5E50DAAULL,
		0x13094ECB9F93366CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBFAD1BDCF6B3A51BULL,
		0xF3A84D98A2AB4C77ULL,
		0xBE4981F5A23D85B0ULL,
		0x35292C0DA3E9AF5AULL,
		0x318ECF6BB09C7BA9ULL,
		0xBC21C41B3A067274ULL,
		0x7FEFCD91226E334CULL,
		0x239716BFE9CD87F9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xABA803C490B08101ULL,
		0xF328019002214401ULL,
		0x1E410151822105B0ULL,
		0x2121280C82410E02ULL,
		0x3004842110107200ULL,
		0x0821000338046200ULL,
		0x3DE3899020640108ULL,
		0x0301068B89810668ULL
	}};
	printf("Test Case 273\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 273 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -273;
	} else {
		printf("Test Case 273 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2B02560BD392412DULL,
		0xEF3FE4971460728EULL,
		0xEA144C5D17F51C67ULL,
		0x5F145DC876D82F67ULL,
		0xEB78244885E90CF4ULL,
		0x2597EADC29835D00ULL,
		0xC781899BC5284F58ULL,
		0x46D7A3E16BF16A82ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA7432A3F74C9F28EULL,
		0x3F45B923BF341416ULL,
		0xC8EF78968308BC3DULL,
		0xBCA5D1CFA53740B3ULL,
		0x808E5B92D5698E28ULL,
		0xB792E841ED4284F2ULL,
		0x379EC2A122F15B42ULL,
		0xB7957A69015E1E0DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2302020B5080400CULL,
		0x2F05A00314201006ULL,
		0xC804481403001C25ULL,
		0x1C0451C824100023ULL,
		0x8008000085690C20ULL,
		0x2592E84029020400ULL,
		0x0780808100204B40ULL,
		0x0695226101500A00ULL
	}};
	printf("Test Case 274\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 274 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -274;
	} else {
		printf("Test Case 274 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEB7F2B52A91397B7ULL,
		0xD6AE8989E4C25156ULL,
		0x6FB8EB2F27F0FC3DULL,
		0xB66974AD3DC5E776ULL,
		0xDA968DD408C6604BULL,
		0x09BEE90BE3D1F3C3ULL,
		0x64ABDFBEFD609469ULL,
		0x5912B0B2A810D775ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5880400F78585F35ULL,
		0x0468E84796118749ULL,
		0x5D4054D04D706D48ULL,
		0xB6C849E748664C39ULL,
		0x07634065FBA09A0FULL,
		0xA65DAD7AA2ADF93EULL,
		0xD2E9A50EA76FE5A0ULL,
		0xCDFE42CA2ED36705ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4800000228101735ULL,
		0x0428880184000140ULL,
		0x4D00400005706C08ULL,
		0xB64840A508444430ULL,
		0x020200440880000BULL,
		0x001CA90AA281F102ULL,
		0x40A9850EA5608420ULL,
		0x4912008228104705ULL
	}};
	printf("Test Case 275\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 275 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -275;
	} else {
		printf("Test Case 275 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9BD5009A16326319ULL,
		0x54DD38C8BFC8A78DULL,
		0xDFF72648061F9310ULL,
		0xD375FCFB02D7C31AULL,
		0xCC32FC475985081BULL,
		0x0B6D111959AC53C6ULL,
		0x8FCA957A1C0E7E84ULL,
		0x524AFD7F90CAD0BEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1530260C7A263A6FULL,
		0x1450974AB036BB60ULL,
		0x5655694DA9D9D1A0ULL,
		0x1D991C444C68925EULL,
		0x9556F8B10C2A6D18ULL,
		0x61538F751B9E361BULL,
		0xAAE8F231D371A491ULL,
		0x8C59808752031C44ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1110000812222209ULL,
		0x14501048B000A300ULL,
		0x5655204800199100ULL,
		0x11111C400040821AULL,
		0x8412F80108000818ULL,
		0x01410111198C1202ULL,
		0x8AC8903010002480ULL,
		0x0048800710021004ULL
	}};
	printf("Test Case 276\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 276 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -276;
	} else {
		printf("Test Case 276 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2CF90AC16B2AC277ULL,
		0x2E9E0F77826B12BFULL,
		0x960F8018523DE7AFULL,
		0xC237F23A64D8547CULL,
		0x08588FA5A0C2E904ULL,
		0x9AFE0F144AC771B0ULL,
		0x7C6210ACCD8E4BECULL,
		0xD4F40F833D92DE14ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x86AB0DAF80627432ULL,
		0x6B5F5053785D0204ULL,
		0x281DEABDDA54664BULL,
		0x6832E268F6804946ULL,
		0x84B33433F646CC28ULL,
		0x8A510E820F57B38BULL,
		0xBA5B62D0CE4BD6FBULL,
		0x6346B50AD3DD1AEAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x04A9088100224032ULL,
		0x2A1E005300490204ULL,
		0x000D80185214660BULL,
		0x4032E22864804044ULL,
		0x00100421A042C800ULL,
		0x8A500E000A473180ULL,
		0x38420080CC0A42E8ULL,
		0x4044050211901A00ULL
	}};
	printf("Test Case 277\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 277 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -277;
	} else {
		printf("Test Case 277 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x67D8DCA20449547EULL,
		0xFE888464AF3B28C1ULL,
		0x25EEBCD4F2F14795ULL,
		0x45BF1C135907584EULL,
		0xD7B109DF987D9043ULL,
		0xEABFF8AC47B57536ULL,
		0x51BA8C863816DA8EULL,
		0xB284F618705B5F63ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x59A847B65954D66DULL,
		0x9174A4D99A58417FULL,
		0x568F89FEEA924023ULL,
		0x3531F8BCEBB66E50ULL,
		0xBED524FCFCAD1529ULL,
		0xCCDA244B2F600385ULL,
		0x4F22B99CEF5E2335ULL,
		0xB1D03AD832E1406FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x418844A20040546CULL,
		0x900084408A180041ULL,
		0x048E88D4E2904001ULL,
		0x0531181049064840ULL,
		0x969100DC982D1001ULL,
		0xC89A200807200104ULL,
		0x4122888428160204ULL,
		0xB080321830414063ULL
	}};
	printf("Test Case 278\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 278 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -278;
	} else {
		printf("Test Case 278 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7A3F7E2E451D8E77ULL,
		0xB1CE392455567EA3ULL,
		0x364BD984CDE2F9FFULL,
		0x73069C3ADCE1B85BULL,
		0xFD061C522106CE17ULL,
		0xF044887EB549EDC2ULL,
		0xA2395548EE58157FULL,
		0xA243B443D00B2912ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x85187C291BF8ABE5ULL,
		0x105BB6DB724E6980ULL,
		0x952BE4073AF5521DULL,
		0xD69EF63CCF56DD35ULL,
		0x29C091D0063595C2ULL,
		0xE8EF1252A76BA952ULL,
		0xC27BC0388420499FULL,
		0xE153615FB0649E2BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x00187C2801188A65ULL,
		0x104A300050466880ULL,
		0x140BC00408E0501DULL,
		0x52069438CC409811ULL,
		0x2900105000048402ULL,
		0xE0440052A549A942ULL,
		0x823940088400011FULL,
		0xA043204390000802ULL
	}};
	printf("Test Case 279\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 279 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -279;
	} else {
		printf("Test Case 279 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x983518C4652B5E00ULL,
		0x96EA1523FF79C08BULL,
		0x2E608346F08D8F36ULL,
		0x2B85C44C933C4897ULL,
		0x1AF3109C6E2C3A1CULL,
		0xD8CCC0BD90D1BDECULL,
		0x19503AE53587AF34ULL,
		0x3480BFBB186E92C1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x563773A9E5BAB681ULL,
		0xE85281C260C1604DULL,
		0xB8B19B749A4AB90EULL,
		0x61F4362F33B60ABCULL,
		0x0A4A4D6B3CFE0544ULL,
		0x63BA7DD203373EE1ULL,
		0xC4DC31DCB2D841F7ULL,
		0x71DAACF2295BB5CFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x10351080652A1600ULL,
		0x8042010260414009ULL,
		0x2820834490088906ULL,
		0x2184040C13340894ULL,
		0x0A4200082C2C0004ULL,
		0x4088409000113CE0ULL,
		0x005030C430800134ULL,
		0x3080ACB2084A90C1ULL
	}};
	printf("Test Case 280\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 280 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -280;
	} else {
		printf("Test Case 280 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE97B95379404D273ULL,
		0x216A0A7028920DA0ULL,
		0xDA8F1F8651470A8AULL,
		0xBB1659859ECE1209ULL,
		0xA7C5090A60F93DE6ULL,
		0x7D15EE81B2547930ULL,
		0x0AA10572ADF0765BULL,
		0x7CEED5EDA88328F0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF1B4735AC1D8A7E9ULL,
		0x3C9B33A98FEEF246ULL,
		0x7CC05D4B057EE093ULL,
		0x62F7321F886B5001ULL,
		0x860140017DEF52A1ULL,
		0x9E86689106DE43D8ULL,
		0xFBFBC0730229A8ABULL,
		0xFE65A3C8DDB517E8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE130111280008261ULL,
		0x200A022008820000ULL,
		0x58801D0201460082ULL,
		0x22161005884A1001ULL,
		0x8601000060E910A0ULL,
		0x1C04688102544110ULL,
		0x0AA100720020200BULL,
		0x7C6481C8888100E0ULL
	}};
	printf("Test Case 281\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 281 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -281;
	} else {
		printf("Test Case 281 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD057BCF79359CB63ULL,
		0x843AE68AEC74B7DCULL,
		0xAF18FB71C6AB92A8ULL,
		0x4218FBA63FB6D924ULL,
		0x2728DDA1D9967BE3ULL,
		0x89CDFCF8584B2418ULL,
		0xD5055BF7970963F2ULL,
		0x030CE3ED2925C356ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5380FD6C09A8B0B8ULL,
		0x7C28C24A04B8537FULL,
		0xF3717F15E5D435F0ULL,
		0x26982318CB13A94DULL,
		0x2D5C2392A9A6302AULL,
		0x599198B6B567B881ULL,
		0xA364D225BEE879B2ULL,
		0xB489F7084AC8BCCCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5000BC6401088020ULL,
		0x0428C20A0430135CULL,
		0xA3107B11C48010A0ULL,
		0x021823000B128904ULL,
		0x2508018089863022ULL,
		0x098198B010432000ULL,
		0x81045225960861B2ULL,
		0x0008E30808008044ULL
	}};
	printf("Test Case 282\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 282 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -282;
	} else {
		printf("Test Case 282 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6EC22AF9912599FDULL,
		0xB057509A3C81B759ULL,
		0x3333F2CBC3DE8948ULL,
		0x011338C24CE23184ULL,
		0x8BB8C9244E78FC13ULL,
		0x732139C17B7071ACULL,
		0x787CC81DDAF1A6E1ULL,
		0xF6FBA27CB5471BB8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA660BF7D31A9FF09ULL,
		0x32DDBFC99F6FBB35ULL,
		0x532DE252181B231AULL,
		0x68AF34E3DBA18347ULL,
		0x18BE67AC25E6C5DBULL,
		0xE3AB6C5AEA5290D1ULL,
		0xA38BB1038ADE9B83ULL,
		0xFEDA2A0A748F7526ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x26402A7911219909ULL,
		0x305510881C01B311ULL,
		0x1321E242001A0108ULL,
		0x000330C248A00104ULL,
		0x08B841240460C413ULL,
		0x632128406A501080ULL,
		0x200880018AD08281ULL,
		0xF6DA220834071120ULL
	}};
	printf("Test Case 283\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 283 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -283;
	} else {
		printf("Test Case 283 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFE92C3FFAB05B212ULL,
		0x024EFE1AC5FC9764ULL,
		0x18E1301012189C93ULL,
		0xEF431C6B17CD8DCCULL,
		0x0DEA44F95C17B992ULL,
		0x9534CE154038EF1DULL,
		0x2B03C07090DB6687ULL,
		0x518875B0FBEDEC04ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBC30D3F0FF6EF034ULL,
		0x152951C772A26110ULL,
		0x57E62EF3E6156DDCULL,
		0xAD93BCF0B380AA01ULL,
		0xEA3D43ADFDA77EC9ULL,
		0xC8CF418B7FE921E3ULL,
		0x5DD32EB967156F44ULL,
		0x49B85551ECCF8E18ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBC10C3F0AB04B010ULL,
		0x0008500240A00100ULL,
		0x10E0201002100C90ULL,
		0xAD031C6013808800ULL,
		0x082840A95C073880ULL,
		0x8004400140282101ULL,
		0x0903003000116604ULL,
		0x41885510E8CD8C00ULL
	}};
	printf("Test Case 284\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 284 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -284;
	} else {
		printf("Test Case 284 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE996E248192FCCB9ULL,
		0xCB8B1BFD0B91D47EULL,
		0x6B68C8ED0FEF129CULL,
		0xE1091B67AA35D393ULL,
		0x1515FA6ABC4C4063ULL,
		0xCE21F19856DEA95BULL,
		0x6422B90CD5FD8632ULL,
		0x5CC245BFCF8C65C6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB3EBCBF7820A8F60ULL,
		0x83E6ED356A405A5AULL,
		0x9B1620DC33B60E7FULL,
		0xF75A5A2FEBA85EE8ULL,
		0x7DDC776894CF80C6ULL,
		0x491796FDE6582C61ULL,
		0xA3D163EFDDAE28C3ULL,
		0x3A0D76357EE63247ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA182C240000A8C20ULL,
		0x838209350A00505AULL,
		0x0B0000CC03A6021CULL,
		0xE1081A27AA205280ULL,
		0x15147268944C0042ULL,
		0x4801909846582841ULL,
		0x2000210CD5AC0002ULL,
		0x180044354E842046ULL
	}};
	printf("Test Case 285\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 285 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -285;
	} else {
		printf("Test Case 285 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB6D68B41693FBCEBULL,
		0x0BC404C6AA8D442BULL,
		0x3F69EBB4D93FFD53ULL,
		0xBBA8C5B0C30DDEE2ULL,
		0x1E31C620D03BDCA0ULL,
		0x75B5449CAA4C019AULL,
		0x9CA95A10CBB92A18ULL,
		0xB45EFBB56C522E86ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE895E928928BCB99ULL,
		0x0D5687C89D80BDCDULL,
		0x9CEAAFFA70B9C5A6ULL,
		0x2B95D1B98C64CA25ULL,
		0xEE0F03CE29E95D59ULL,
		0x9FF55A6BF89E7ED8ULL,
		0x4F9A496B2F946E45ULL,
		0xB4FE4D671194CF84ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA0948900000B8889ULL,
		0x094404C088800409ULL,
		0x1C68ABB05039C502ULL,
		0x2B80C1B08004CA20ULL,
		0x0E01020000295C00ULL,
		0x15B54008A80C0098ULL,
		0x0C8848000B902A00ULL,
		0xB45E492500100E84ULL
	}};
	printf("Test Case 286\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 286 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -286;
	} else {
		printf("Test Case 286 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEBFB1A2E194E7559ULL,
		0x67929F1A2B8DD636ULL,
		0xBCA5B7C6AC69C1C0ULL,
		0xF4D9E8CED3744369ULL,
		0x490DDE67A1CCB91BULL,
		0x831F810B8EC2D681ULL,
		0x12E5184ECE7536CFULL,
		0x3FD72FD21CCD6157ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD9512C8984B0E5F7ULL,
		0xE1785DBB089E15EEULL,
		0xEC7CF865F2E9A5DBULL,
		0xE26E13A04203DEB8ULL,
		0x1A20FD23F9AA78A9ULL,
		0x1545DDA68976D305ULL,
		0x7EEA5722BA821C88ULL,
		0x4B3D1F2B6C3E9609ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC951080800006551ULL,
		0x61101D1A088C1426ULL,
		0xAC24B044A06981C0ULL,
		0xE048008042004228ULL,
		0x0800DC23A1883809ULL,
		0x010581028842D201ULL,
		0x12E010028A001488ULL,
		0x0B150F020C0C0001ULL
	}};
	printf("Test Case 287\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 287 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -287;
	} else {
		printf("Test Case 287 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1C66824F4834DBEBULL,
		0xA467A6F98B71FFA7ULL,
		0x007528637C61FF2DULL,
		0xCFBBE324004D4433ULL,
		0xDF88E899AB702A8FULL,
		0x41A9FABC671D2186ULL,
		0x5384148B75C20633ULL,
		0x48E9C69E75783093ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE120C303BCDC3642ULL,
		0xE32E2608F1E96BFFULL,
		0x0D0026790E3214D3ULL,
		0x66EA6985D095CCC2ULL,
		0xE7414B54EB87A7C8ULL,
		0x819CCBF5131CE3B6ULL,
		0x8CBDCA4EA4E0C892ULL,
		0x9049D9478F0A8A1AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0020820308141242ULL,
		0xA026260881616BA7ULL,
		0x000020610C201401ULL,
		0x46AA610400054402ULL,
		0xC7004810AB002288ULL,
		0x0188CAB4031C2186ULL,
		0x0084000A24C00012ULL,
		0x0049C00605080012ULL
	}};
	printf("Test Case 288\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 288 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -288;
	} else {
		printf("Test Case 288 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC003A2484377A04FULL,
		0x358E5DE761C76F5EULL,
		0xF281F163DE9C2BD5ULL,
		0xAEC7DAEF49BF1319ULL,
		0x0AB17E249977D9D6ULL,
		0x80E590DCC78D7988ULL,
		0xC8087F7F0B803BFBULL,
		0xC40E2A567EEA82F4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7BFEBC3B41610200ULL,
		0x9DF251FA564FAEC2ULL,
		0x6DAEB96D6099C431ULL,
		0xC25812029766F50BULL,
		0xA20CF39CE9A8CF5FULL,
		0x917AA5C5D4C2C5E8ULL,
		0x835843DB34A27F40ULL,
		0xEE1825EEDD5635F1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4002A00841610000ULL,
		0x158251E240472E42ULL,
		0x6080B16140980011ULL,
		0x8240120201261109ULL,
		0x020072048920C956ULL,
		0x806080C4C4804188ULL,
		0x8008435B00803B40ULL,
		0xC40820465C4200F0ULL
	}};
	printf("Test Case 289\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 289 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -289;
	} else {
		printf("Test Case 289 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA16C6D26E3107117ULL,
		0x93B8E14CEF86850DULL,
		0x2712787970959247ULL,
		0x660588B3C54FC4D5ULL,
		0x9C35B451670590AAULL,
		0x071F2F37C61AF46BULL,
		0x41D10F0044ED237AULL,
		0xC2676A58B2548F36ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAA124F9E19A9A5EFULL,
		0x70E346E65897F118ULL,
		0x1D5AB7C0DF8817ABULL,
		0xF3F9234778EFECF8ULL,
		0x8F2B39A6F151D642ULL,
		0x7FBA4F33085413E5ULL,
		0x1CD714DA6B84AD26ULL,
		0x1F3550AD358AF1ACULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA0004D0601002107ULL,
		0x10A0404448868108ULL,
		0x0512304050801203ULL,
		0x62010003404FC4D0ULL,
		0x8C21300061019002ULL,
		0x071A0F3300101061ULL,
		0x00D1040040842122ULL,
		0x0225400830008124ULL
	}};
	printf("Test Case 290\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 290 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -290;
	} else {
		printf("Test Case 290 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x62242382D67677ACULL,
		0x0FB0C4A9CA232CD1ULL,
		0x5A3929B16D277299ULL,
		0x04CBAFDB7B194B56ULL,
		0x07B75DF5F511BFFBULL,
		0xDF0ABFAEF99A0365ULL,
		0x55FE2EC743621DABULL,
		0xF2165D0348F0308FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3DE71B8190C2BE30ULL,
		0x877D1C8FB881407DULL,
		0x66DBF0716BD08414ULL,
		0xBD6C652E2F5C938BULL,
		0xE93F03B76AC036F5ULL,
		0xD74A9B01B1D27D88ULL,
		0xA0DE729F9F3FEAB7ULL,
		0xBE9C812FEBDAF101ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2024038090423620ULL,
		0x0730048988010051ULL,
		0x4219203169000010ULL,
		0x0448250A2B180302ULL,
		0x013701B5600036F1ULL,
		0xD70A9B00B1920100ULL,
		0x00DE2287032208A3ULL,
		0xB214010348D03001ULL
	}};
	printf("Test Case 291\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 291 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -291;
	} else {
		printf("Test Case 291 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC7BFB890C37CE8D8ULL,
		0x9E40B27F0D84CBEDULL,
		0xDCCFCBD75FD69674ULL,
		0xF0A30B66273BAB62ULL,
		0x7FB79CC71F7FAC9AULL,
		0xE076F331362E3E8EULL,
		0x093A4A389F2E0924ULL,
		0x00DF600487BB1994ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x638B10EA87EB0B31ULL,
		0x429AC315ABF343CEULL,
		0x591DAE9671EC8519ULL,
		0x892A06F0FED763E9ULL,
		0xE5F17EF517B5EE65ULL,
		0xFBC6C8E4AA26D544ULL,
		0x64B631576AB581E6ULL,
		0x8BAF29919699245AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x438B108083680810ULL,
		0x02008215098043CCULL,
		0x580D8A9651C48410ULL,
		0x8022026026132360ULL,
		0x65B11CC51735AC00ULL,
		0xE046C02022261404ULL,
		0x003200100A240124ULL,
		0x008F200086990010ULL
	}};
	printf("Test Case 292\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 292 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -292;
	} else {
		printf("Test Case 292 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2E0E81538FCD0A7AULL,
		0x9356392EB785316EULL,
		0xDF69F282C616ACCBULL,
		0x5F8743F309963078ULL,
		0x622E00D9D51EF0ADULL,
		0x23E3A87DDADE4CA4ULL,
		0x8D6F635ED5A9D03AULL,
		0x45C06322172712DCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5E0F7C5AB945B887ULL,
		0xC298E29982E898FDULL,
		0xDE5F755B232401E1ULL,
		0xA2A9D32C73DF9C2CULL,
		0xE4352381D4B6426FULL,
		0x6ABCA34CD5C253B0ULL,
		0x34AC3D224BB1CA5CULL,
		0x91600E6FD7AC511EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0E0E005289450802ULL,
		0x821020088280106CULL,
		0xDE497002020400C1ULL,
		0x0281432001961028ULL,
		0x60240081D416402DULL,
		0x22A0A04CD0C240A0ULL,
		0x042C210241A1C018ULL,
		0x014002221724101CULL
	}};
	printf("Test Case 293\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 293 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -293;
	} else {
		printf("Test Case 293 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x45FF46FA094555A2ULL,
		0x3A1AFB7AAC00ACA1ULL,
		0x1CF91294DA3FBA49ULL,
		0xF3B3570F79835E6DULL,
		0x72908908EAC3068EULL,
		0xCBD977E1C981CC0AULL,
		0x91A3CAF4D2AE1BE5ULL,
		0x17AD57C9C4638F5BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6977518A3D640F61ULL,
		0x5FCF2CC120F5ABC2ULL,
		0x60800F632E957958ULL,
		0xC8C953A7219C7990ULL,
		0xA81BB92CE381DA62ULL,
		0x00BBAA7C6895C8E5ULL,
		0x2E58F836526FFC33ULL,
		0xA2EE52C2178E66A6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4177408A09440520ULL,
		0x1A0A28402000A880ULL,
		0x008002000A153848ULL,
		0xC081530721805800ULL,
		0x20108908E2810202ULL,
		0x009922604881C800ULL,
		0x0000C834522E1821ULL,
		0x02AC52C004020602ULL
	}};
	printf("Test Case 294\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 294 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -294;
	} else {
		printf("Test Case 294 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x363F40AFB97CB159ULL,
		0x2793FA0813B9DDADULL,
		0xABD0D09F46EED52DULL,
		0xD3F09F7A3F0E8749ULL,
		0x7606F42B4CEE0392ULL,
		0xCDBE3C88AE03F535ULL,
		0xE9C2B82996E15F19ULL,
		0x706E3152A47C631AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCA7CB3E4C8379890ULL,
		0x6C16CEFB41E00FE3ULL,
		0xBCCC05E8D3E1DF60ULL,
		0x172954618CE7D069ULL,
		0x9C7AB46F53FB26A2ULL,
		0x77E4289A8E24AAD7ULL,
		0x86F89D89693C138FULL,
		0x709D0337582AD02EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x023C00A488349010ULL,
		0x2412CA0801A00DA1ULL,
		0xA8C0008842E0D520ULL,
		0x132014600C068049ULL,
		0x1402B42B40EA0282ULL,
		0x45A428888E00A015ULL,
		0x80C0980900201309ULL,
		0x700C01120028400AULL
	}};
	printf("Test Case 295\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 295 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -295;
	} else {
		printf("Test Case 295 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC5377F2AA62D814AULL,
		0x5E4BFA22FD934BD7ULL,
		0x4345A3150490CC49ULL,
		0x7BC8E440E2977879ULL,
		0x2A52FBD5BA3E21F7ULL,
		0xEBFE3C12AED6793BULL,
		0x773FE0C68B9F32EAULL,
		0x04158C495052E430ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA54E044F8B8E67E8ULL,
		0xD34F971BF462C56CULL,
		0x8A79EFEA8C3D17C6ULL,
		0xEADA1E727D348550ULL,
		0xDF8536F38ACC8AACULL,
		0x380313FBA6C55730ULL,
		0x30B7C84DC3155449ULL,
		0x8BDCA743CEE057B5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8506040A820C0148ULL,
		0x524B9202F4024144ULL,
		0x0241A30004100440ULL,
		0x6AC8044060140050ULL,
		0x0A0032D18A0C00A4ULL,
		0x28021012A6C45130ULL,
		0x3037C04483151048ULL,
		0x0014844140404430ULL
	}};
	printf("Test Case 296\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 296 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -296;
	} else {
		printf("Test Case 296 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC9B14F48CB96E6AAULL,
		0x925770A9B7836283ULL,
		0xEA3052DA01B14C85ULL,
		0x8BBD4D584C8D66FAULL,
		0xEC9ED6473A094539ULL,
		0xE5883AFDBC6A2DA3ULL,
		0xCC7491F78EC3074FULL,
		0xD74F216DD17A1883ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB88FB88E249FF4B0ULL,
		0x724CBF8BC87044BEULL,
		0xE5D7588FA8BB896AULL,
		0x7F0C24ED072455E0ULL,
		0x5D41433E7DD41D3AULL,
		0xEB82BA736BD111C5ULL,
		0x5EFCDAB57D6C7143ULL,
		0xB98520F31F79E356ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x888108080096E4A0ULL,
		0x1244308980004082ULL,
		0xE010508A00B10800ULL,
		0x0B0C0448040444E0ULL,
		0x4C00420638000538ULL,
		0xE1803A7128400181ULL,
		0x4C7490B50C400143ULL,
		0x9105206111780002ULL
	}};
	printf("Test Case 297\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 297 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -297;
	} else {
		printf("Test Case 297 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF3097EF121B99326ULL,
		0xD25B9F6D92961287ULL,
		0xBD45161606DCC1D2ULL,
		0xE3A411F10DB39798ULL,
		0xCC2182BF02D61F27ULL,
		0x36D36EB39F33FFDBULL,
		0x3B9D804F1916CF3EULL,
		0x7F554477C2D39A8EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA823958961519BFCULL,
		0xA3E8D67951240AA4ULL,
		0xD71431A0DAA01892ULL,
		0xE0A6D062E6325861ULL,
		0x61F444690D134A83ULL,
		0x59C63500D53F1CCDULL,
		0x44C65F0C1D40F1CBULL,
		0x142A2F764FAD6791ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA001148121119324ULL,
		0x8248966910040284ULL,
		0x9504100002800092ULL,
		0xE0A4106004321000ULL,
		0x4020002900120A03ULL,
		0x10C2240095331CC9ULL,
		0x0084000C1900C10AULL,
		0x1400047642810280ULL
	}};
	printf("Test Case 298\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 298 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -298;
	} else {
		printf("Test Case 298 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x39319BF2DC113ADBULL,
		0x70BB97304DA7A08EULL,
		0x063A533B081CCFD7ULL,
		0x2C22A42791D39496ULL,
		0x771E5F2F13AA0897ULL,
		0x2C8F44A4EBD17487ULL,
		0xCFE7802C804372E9ULL,
		0xD66BE850CC8AE102ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE5BF5EB62C95193EULL,
		0xAA0769C9BA9987D0ULL,
		0x09EC9C2C84738DB2ULL,
		0x7B9FD28E6EDCF35BULL,
		0x243638F43E73E114ULL,
		0xF05CE6BCB90D503EULL,
		0xECC5BA1126775C0CULL,
		0x5A3C46BAB8CA85AAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x21311AB20C11181AULL,
		0x2003010008818080ULL,
		0x0028102800108D92ULL,
		0x2802800600D09012ULL,
		0x2416182412220014ULL,
		0x200C44A4A9015006ULL,
		0xCCC5800000435008ULL,
		0x52284010888A8102ULL
	}};
	printf("Test Case 299\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 299 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -299;
	} else {
		printf("Test Case 299 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9E617253543C8767ULL,
		0x5EE8C1B460CEEE6BULL,
		0xDF55C97BD37A30A2ULL,
		0xB9285FB075EA0328ULL,
		0xBF195E8464FAA7DAULL,
		0x51EF423811C72FFDULL,
		0xE0F5D9A2F2B7E903ULL,
		0x2CDFC95E179FDC20ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0D48A3CC37F73745ULL,
		0x9C082A797E22B106ULL,
		0x2173C6469FD3B1FFULL,
		0xF66CD25F6C8BA2BDULL,
		0x655B2F56B74636E9ULL,
		0x599AF33E85B58640ULL,
		0xE5A03F89208E308BULL,
		0xF2873F57B69311E5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0C40224014340745ULL,
		0x1C0800306002A002ULL,
		0x0151C042935230A2ULL,
		0xB0285210648A0228ULL,
		0x25190E04244226C8ULL,
		0x518A423801850640ULL,
		0xE0A0198020862003ULL,
		0x2087095616931020ULL
	}};
	printf("Test Case 300\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 300 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -300;
	} else {
		printf("Test Case 300 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9A59B2B43831745EULL,
		0x79734849AD594BAFULL,
		0x27F1139036DB47CEULL,
		0x23B9830CBF04B2A5ULL,
		0xF2256473B3C9C9D8ULL,
		0x66EDD9D5F6F1E88EULL,
		0x3E7260F453FE7F55ULL,
		0x20159DD1524A7EA4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3A5BE6F5C9CDF557ULL,
		0x74D98C0F0DAE86C2ULL,
		0xF5BEE5B47EA631E5ULL,
		0xE6B50C137D6ECCB0ULL,
		0x6AE6278296EBB545ULL,
		0xBE11621E5975984DULL,
		0xCF606057CAFE3B4EULL,
		0xFE786F967D448D14ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1A59A2B408017456ULL,
		0x705108090D080282ULL,
		0x25B00190368201C4ULL,
		0x22B100003D0480A0ULL,
		0x6224240292C98140ULL,
		0x260140145071880CULL,
		0x0E60605442FE3B44ULL,
		0x20100D9050400C04ULL
	}};
	printf("Test Case 301\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 301 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -301;
	} else {
		printf("Test Case 301 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF54996362F93ED82ULL,
		0x8FBDBBEB9F57B645ULL,
		0xBE2DAE054C287AC7ULL,
		0xD8EFCF4C6EA8D099ULL,
		0x4D29252C3F55F09CULL,
		0xE815D4E120665076ULL,
		0x1D0893488E2C5F16ULL,
		0xA464E0627B1721FEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBC028579E933D0F1ULL,
		0x4417AA87F7B6AF23ULL,
		0x2A2C294E8C067CB9ULL,
		0x4EC6CEAF736C74E6ULL,
		0xD049ACFA1F52286AULL,
		0x23BEC7DDB936586BULL,
		0x6EB8C48D9FA30A51ULL,
		0xFD1F62BF1FD458BEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB40084302913C080ULL,
		0x0415AA839716A601ULL,
		0x2A2C28040C007881ULL,
		0x48C6CE0C62285080ULL,
		0x400924281F502008ULL,
		0x2014C4C120265062ULL,
		0x0C0880088E200A10ULL,
		0xA40460221B1400BEULL
	}};
	printf("Test Case 302\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 302 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -302;
	} else {
		printf("Test Case 302 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA6D9CD2CA75E129BULL,
		0x03AD7FA4A30966A4ULL,
		0x6902FDE4E6BD88C4ULL,
		0xBA3E787A3DAE45BFULL,
		0xFC9ACED1E0EAFBFFULL,
		0x07F61F1F702EB5A8ULL,
		0xCA12F548FE8A8F1AULL,
		0xF8CC23DEB1264D7AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEED8BC5F9C9090C0ULL,
		0x85BD0D2ED8A0C460ULL,
		0x526CD079CEA958EBULL,
		0xC2660392B7958479ULL,
		0xA646A8C544E36A04ULL,
		0xEE8AEBEC6DE9CB5BULL,
		0x3DF950098F82EBAAULL,
		0x81717AE78E3CAF54ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA6D88C0C84101080ULL,
		0x01AD0D2480004420ULL,
		0x4000D060C6A908C0ULL,
		0x8226001235840439ULL,
		0xA40288C140E26A04ULL,
		0x06820B0C60288108ULL,
		0x081050088E828B0AULL,
		0x804022C680240D50ULL
	}};
	printf("Test Case 303\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 303 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -303;
	} else {
		printf("Test Case 303 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5D1721946CA89C34ULL,
		0x1A0799EB80790EACULL,
		0xF0432843DD801741ULL,
		0x265558E5CE941C1AULL,
		0xD3F82F22DFE37EF6ULL,
		0x46B3E117177EBFB4ULL,
		0xF0FD8CD3E4D419F3ULL,
		0x089AFF2048868AA8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6F692D83ED1CDCFBULL,
		0x98B12AC85A55F364ULL,
		0x1A821C448D56F123ULL,
		0x548BDDDE10468A92ULL,
		0xD547D3479236D320ULL,
		0xE713936D8E20FDAEULL,
		0x2581D54A23F10D90ULL,
		0x89B363052C8D767EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4D0121806C089C30ULL,
		0x180108C800510224ULL,
		0x100208408D001101ULL,
		0x040158C400040812ULL,
		0xD140030292225220ULL,
		0x461381050620BDA4ULL,
		0x2081844220D00990ULL,
		0x0892630008840228ULL
	}};
	printf("Test Case 304\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 304 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -304;
	} else {
		printf("Test Case 304 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB339D8A368A845E6ULL,
		0xD1095F8A7F62D3E5ULL,
		0xBD1A2BE5C6898194ULL,
		0x15A19FFEA0DD3939ULL,
		0x6C6D0D9DF473C0DDULL,
		0x5FBB6FA869240844ULL,
		0x7B2878EBC11895F5ULL,
		0x0A8FE4C367BAEB32ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x98B71B536163F88AULL,
		0x86E6D7D6AFE25E81ULL,
		0x6880DB9D8871A363ULL,
		0xFA7ECD72F4DD37D0ULL,
		0xB699ECC6419A489CULL,
		0x75B8E5524ADDDF0DULL,
		0xCFE264336D69601AULL,
		0xAEE3467E142965AAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9031180360204082ULL,
		0x800057822F625281ULL,
		0x28000B8580018100ULL,
		0x10208D72A0DD3110ULL,
		0x24090C844012409CULL,
		0x55B8650048040804ULL,
		0x4B20602341080010ULL,
		0x0A83444204286122ULL
	}};
	printf("Test Case 305\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 305 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -305;
	} else {
		printf("Test Case 305 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2BF9EFDB7C3A0CBCULL,
		0xC44FB0086A9BA29DULL,
		0xE6AAB3D306493505ULL,
		0xFEA03129E2D1DE4DULL,
		0xA761A485B4AED2F8ULL,
		0xD1D7B7916128B967ULL,
		0x339EAA6D6AFFA118ULL,
		0xDEA3C91D48FBACDCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE9C4C632FEAE2816ULL,
		0x907022A342E866C6ULL,
		0x6806E5AD98394129ULL,
		0x54227C5B6D6FCEEFULL,
		0x8319DEF283C684FDULL,
		0xD892DBCC7216A443ULL,
		0x08ED033DE3239A8AULL,
		0xAB7309E074667E61ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x29C0C6127C2A0814ULL,
		0x8040200042882284ULL,
		0x6002A18100090101ULL,
		0x542030096041CE4DULL,
		0x83018480808680F8ULL,
		0xD09293806000A043ULL,
		0x008C022D62238008ULL,
		0x8A23090040622C40ULL
	}};
	printf("Test Case 306\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 306 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -306;
	} else {
		printf("Test Case 306 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC02DC037484A0B1CULL,
		0x28E5F9E8A426C7C7ULL,
		0x6FE6D3F478BCA390ULL,
		0xA1571F88EE9641BFULL,
		0x6F7AFC6984803FD2ULL,
		0x3433A2FC2DDD8B36ULL,
		0x3FA4F62F2E5DAFD0ULL,
		0x38EEC6E68C4A8AA3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x86DEBF44EFBC1812ULL,
		0xC5EAD698EAE19268ULL,
		0x418BC1B5D83D1F2EULL,
		0x103FA6ED488A12F5ULL,
		0xDB17233A36D9D0D1ULL,
		0xCCEA802A17F72AD2ULL,
		0xD92AD6C182D90E03ULL,
		0x7C6083032BEF2CF1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x800C800448080810ULL,
		0x00E0D088A0208240ULL,
		0x4182C1B4583C0300ULL,
		0x00170688488200B5ULL,
		0x4B122028048010D0ULL,
		0x0422802805D50A12ULL,
		0x1920D60102590E00ULL,
		0x38608202084A08A1ULL
	}};
	printf("Test Case 307\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 307 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -307;
	} else {
		printf("Test Case 307 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x40C113BAE3523350ULL,
		0xEC62EA6CE16DF145ULL,
		0xFFDF6FF48F521C63ULL,
		0xE6AAD50683C3633AULL,
		0x3B39491B4A7090B2ULL,
		0xDEF1CAC30F319967ULL,
		0xC5E2C4A6C459E51CULL,
		0x7B998985B371B211ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8A689AFB91DB923AULL,
		0x545215C085E468A6ULL,
		0x46B4493FD0D6BF3EULL,
		0x0DCF923A7DD0F62BULL,
		0xC3EA7FE4FACC782CULL,
		0x7B75F66F9D590693ULL,
		0x5EE3868F34ED6BFEULL,
		0x49D553E1B68118D0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x004012BA81521210ULL,
		0x4442004081646004ULL,
		0x4694493480521C22ULL,
		0x048A900201C0622AULL,
		0x032849004A401020ULL,
		0x5A71C2430D110003ULL,
		0x44E284860449611CULL,
		0x49910181B2011010ULL
	}};
	printf("Test Case 308\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 308 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -308;
	} else {
		printf("Test Case 308 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDE42D974350E3EAEULL,
		0x08B02F812A684051ULL,
		0x8928EF33C877C9FAULL,
		0xFA4695CFE6AC95E5ULL,
		0x914DA30CDC4CBED2ULL,
		0xF494E3588B090AF1ULL,
		0x0D747360678C7F43ULL,
		0xEA45E36C6B843678ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x194F5F1E27B3C218ULL,
		0xE18CD82633671ABAULL,
		0x6CD812BB043EDEE8ULL,
		0x14FEE6F2D0710B87ULL,
		0x79F84DF5CC138C6FULL,
		0x6C3C9DD1DFFF4199ULL,
		0xF1C3860E8FA669BBULL,
		0x697EA764583F641DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1842591425020208ULL,
		0x0080080022600010ULL,
		0x080802330036C8E8ULL,
		0x104684C2C0200185ULL,
		0x11480104CC008C42ULL,
		0x641481508B090091ULL,
		0x0140020007846903ULL,
		0x6844A36448042418ULL
	}};
	printf("Test Case 309\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 309 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -309;
	} else {
		printf("Test Case 309 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x31A518B5C06D9935ULL,
		0xF515F324631E0899ULL,
		0xF0314E82A6A1B0F9ULL,
		0x116245B81A7FBA4CULL,
		0x16B03B801A8BA079ULL,
		0x2661C07E0A5E694CULL,
		0xEE28DDCE248FFDAAULL,
		0x903599ED357CE00DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x18A9DC75105ABE9FULL,
		0x08AD7527BDAAF52CULL,
		0x3D97E6AC6F9B6E50ULL,
		0x6164BF87C75AD2A3ULL,
		0xE282EF7D3EB6B40AULL,
		0x2613DD88DBDF8D83ULL,
		0xFB6A262BDB981327ULL,
		0x5441905AC0FF647BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x10A1183500489815ULL,
		0x00057124210A0008ULL,
		0x3011468026812050ULL,
		0x01600580025A9200ULL,
		0x02802B001A82A008ULL,
		0x2601C0080A5E0900ULL,
		0xEA28040A00881122ULL,
		0x10019048007C6009ULL
	}};
	printf("Test Case 310\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 310 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -310;
	} else {
		printf("Test Case 310 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x847B2FAB2DBEE264ULL,
		0xEECD1E94F4C9AD21ULL,
		0xC8F845A299A9B598ULL,
		0x8364F2D374214F51ULL,
		0xE9D84037756AE9F5ULL,
		0xD15D12AC8C3E31D6ULL,
		0xDD44B501AEAAE06BULL,
		0x3F96B7A906EF8644ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8B4FFF1C7CD516A6ULL,
		0x1DE0350D546C2E63ULL,
		0x6ECED35D69123E26ULL,
		0xCEC5906C0329C609ULL,
		0x5857351D07B1921DULL,
		0x72D530E6070BE5A8ULL,
		0x73AC9739709A16C2ULL,
		0x66E6997028B03C5CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x804B2F082C940224ULL,
		0x0CC0140454482C21ULL,
		0x48C8410009003400ULL,
		0x8244904000214601ULL,
		0x4850001505208015ULL,
		0x505510A4040A2180ULL,
		0x51049501208A0042ULL,
		0x2686912000A00444ULL
	}};
	printf("Test Case 311\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 311 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -311;
	} else {
		printf("Test Case 311 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x10A2816CE851B773ULL,
		0x6A3451708C2A477AULL,
		0x099E75747726F4C5ULL,
		0x64593CE430FF8C63ULL,
		0x68C2F0D1C44D037DULL,
		0x6E535B3025E7CDA5ULL,
		0xA3CA12482167C32BULL,
		0x6DD46A428B3D56FDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x518CBC7130B11B65ULL,
		0xD71C1F7BA8CA9E6FULL,
		0x192B9A3460A046B3ULL,
		0x30A942697CF947D8ULL,
		0x6DEBDD1DEDC6372CULL,
		0x9F7AD98C9999D1C0ULL,
		0x9E4CD1AAB3AF6CC9ULL,
		0x3C968A8EED9B3BBAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1080806020111361ULL,
		0x42141170880A066AULL,
		0x090A103460204481ULL,
		0x2009006030F90440ULL,
		0x68C2D011C444032CULL,
		0x0E5259000181C180ULL,
		0x8248100821274009ULL,
		0x2C940A02891912B8ULL
	}};
	printf("Test Case 312\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 312 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -312;
	} else {
		printf("Test Case 312 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBEB9F7A43FCC6CDDULL,
		0x743D97606055E445ULL,
		0xA52790969E7752DEULL,
		0x1BC25946F858234EULL,
		0xD898D3BF438B36DDULL,
		0x56702A178323FF31ULL,
		0xC9CBBC654BB872BEULL,
		0x6BB6833AFEA751DFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xACF39E4E5E478ED0ULL,
		0x8962C20618B42A2FULL,
		0x9537073E04C01F26ULL,
		0xB79FD95F34CC33F4ULL,
		0x274AEE9A1EC00E83ULL,
		0x77CD2A91918B8A7AULL,
		0xFD4ABD3C41473C2BULL,
		0x57026ED7001C4C7EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xACB196041E440CD0ULL,
		0x0020820000142005ULL,
		0x8527001604401206ULL,
		0x1382594630482344ULL,
		0x0008C29A02800681ULL,
		0x56402A1181038A30ULL,
		0xC94ABC244100302AULL,
		0x430202120004405EULL
	}};
	printf("Test Case 313\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 313 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -313;
	} else {
		printf("Test Case 313 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3EC635BF06A1F085ULL,
		0x1D35BA7DBC52DD31ULL,
		0x559D9E92E4AA673EULL,
		0x3BABB7DD0E23D09AULL,
		0x6F4B6DE19C0B6E1AULL,
		0x4AA205479A7B05A3ULL,
		0x2F0C1E29C256C6F2ULL,
		0x4688BBE6DA554D50ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7CF42AED2EBEC9B0ULL,
		0x990642773431906EULL,
		0xA2BCE4BAEDC3353FULL,
		0x8275DCE13BDE081FULL,
		0xA68B1E261542C8D2ULL,
		0xA0934053349424BDULL,
		0x7D55E171304A6C81ULL,
		0x43DA3B0479D01EC9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3CC420AD06A0C080ULL,
		0x1904027534109020ULL,
		0x009C8492E482253EULL,
		0x022194C10A02001AULL,
		0x260B0C2014024812ULL,
		0x00820043101004A1ULL,
		0x2D04002100424480ULL,
		0x42883B0458500C40ULL
	}};
	printf("Test Case 314\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 314 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -314;
	} else {
		printf("Test Case 314 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEF7156DB0260DC6EULL,
		0xCE3B7C8F1A3958A3ULL,
		0xF8358FF25FC915D5ULL,
		0x8FBD453F00863140ULL,
		0x152982E60D5666AEULL,
		0x04DCF7F9EC08B5DFULL,
		0xB39DDC5E1FA5E6AEULL,
		0xFBD2FB97BE26CC37ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC344188539BA6543ULL,
		0xA9B883D455A5CD9BULL,
		0x809D29DF8CDB33B5ULL,
		0x98D023CA0A6F86DFULL,
		0xBC52CE8C31355C3FULL,
		0x81051AD1CE0E6DB5ULL,
		0x0356854B41DFC1ADULL,
		0x7975EF94EECB91EFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC340108100204442ULL,
		0x8838008410214883ULL,
		0x801509D20CC91195ULL,
		0x8890010A00060040ULL,
		0x140082840114442EULL,
		0x000412D1CC082595ULL,
		0x0314844A0185C0ACULL,
		0x7950EB94AE028027ULL
	}};
	printf("Test Case 315\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 315 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -315;
	} else {
		printf("Test Case 315 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8F07778BB1C3EEC9ULL,
		0xA730900542EAF0CAULL,
		0xD5C517F43041594EULL,
		0x6EF144DD7F641116ULL,
		0xEFF428B341A61919ULL,
		0xCB78FD10223EA4A5ULL,
		0x25703229D6A648C6ULL,
		0xE239D0805267E53EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8B8FD10BAA20786EULL,
		0x17CEA57A1F64AC73ULL,
		0xF315C40AC19F9DC8ULL,
		0x45D3F2C7B4BAE239ULL,
		0xB37FCB1190BAD65AULL,
		0x7008F99FD3579317ULL,
		0x77ED68B3599A2C18ULL,
		0xC9A11678076620D8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8B07510BA0006848ULL,
		0x070080000260A042ULL,
		0xD105040000011948ULL,
		0x44D140C534200010ULL,
		0xA374081100A21018ULL,
		0x4008F91002168005ULL,
		0x2560202150820800ULL,
		0xC021100002662018ULL
	}};
	printf("Test Case 316\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 316 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -316;
	} else {
		printf("Test Case 316 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA46748DA7B0566A9ULL,
		0xF699142A12EB7944ULL,
		0x8E13E4C7B3AAF44BULL,
		0x401AB9B05B4F59ECULL,
		0x641699472D571F25ULL,
		0xE92BAF9D766718F0ULL,
		0x5EEAAE251ABC1E86ULL,
		0xA6EE95DFE8D5501AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB5F7D3BEBB779009ULL,
		0x1A1DE57C9BDE122AULL,
		0x9B71DEA94ECFF1C6ULL,
		0x3091C7926CE6E9F0ULL,
		0x59243CF7E1C244A2ULL,
		0x8FDB802CD6CC422EULL,
		0xE2505A7DAE56131CULL,
		0xCC20BF1D1744C1C5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA467409A3B050009ULL,
		0x1219042812CA1000ULL,
		0x8A11C481028AF042ULL,
		0x00108190484649E0ULL,
		0x4004184721420420ULL,
		0x890B800C56440020ULL,
		0x42400A250A141204ULL,
		0x8420951D00444000ULL
	}};
	printf("Test Case 317\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 317 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -317;
	} else {
		printf("Test Case 317 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0FD194CF2E6E59A3ULL,
		0xB63F0A501CEFFDF0ULL,
		0x2069F1BFDA7FD611ULL,
		0x0844B1890B7C631DULL,
		0xA4448F09F8156293ULL,
		0x580948691E13B876ULL,
		0xBBBC9A8BB4A3887EULL,
		0x4452DCB32758F25AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x15F502B1081EF241ULL,
		0xD0DD2F4CDDB3DA66ULL,
		0xDC55EC9C08EFFBEEULL,
		0x2E501488A1022462ULL,
		0xC118B835E7763D0EULL,
		0x26B3FA28C4E6A1AEULL,
		0xB3F6A98760BE62C4ULL,
		0x9C1B55661FB56092ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x05D10081080E5001ULL,
		0x901D0A401CA3D860ULL,
		0x0041E09C086FD200ULL,
		0x0840108801002000ULL,
		0x80008801E0142002ULL,
		0x000148280402A026ULL,
		0xB3B4888320A20044ULL,
		0x0412542207106012ULL
	}};
	printf("Test Case 318\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 318 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -318;
	} else {
		printf("Test Case 318 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEC04510325C7650FULL,
		0xDA2491704F7D62B2ULL,
		0x10D8F879F4BC17C9ULL,
		0x0E02E881CA59A71FULL,
		0x39760C7FED2908E5ULL,
		0xD8553FBA0F2D43ACULL,
		0x6B833AB9D71782FDULL,
		0x45598B10E8DFAA80ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4771DF8B6D150E93ULL,
		0xF81EE3393D46C1A8ULL,
		0xC9F99D8A59F2BDF0ULL,
		0x2FD9E656547BAE96ULL,
		0xA33651A4B6FF59E0ULL,
		0x4ECB49F11596D0C7ULL,
		0xC01AAFCA5D53B175ULL,
		0x5D75336A41BD3749ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4400510325050403ULL,
		0xD80481300D4440A0ULL,
		0x00D8980850B015C0ULL,
		0x0E00E0004059A616ULL,
		0x21360024A42908E0ULL,
		0x484109B005044084ULL,
		0x40022A8855138075ULL,
		0x45510300409D2200ULL
	}};
	printf("Test Case 319\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 319 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -319;
	} else {
		printf("Test Case 319 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCE59458D11B5879BULL,
		0xA3D5A01EDCC4C8E7ULL,
		0xD6408586A8FE11B8ULL,
		0xF65A094943974921ULL,
		0x6E24694E3195FBF3ULL,
		0xC87E207442BB69B4ULL,
		0x1BF077653468F3B3ULL,
		0xBC6133A82C511DADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x45A806696C1082CBULL,
		0x4BBC3292D78A227FULL,
		0x518AFA9BA7000884ULL,
		0xCECB42F825EC5454ULL,
		0x97576842274BBB5CULL,
		0xF04ABD3D360FD5C5ULL,
		0x33799A5DDAE1BE44ULL,
		0xFA0F6D22A44D74D2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x440804090010828BULL,
		0x03942012D4800067ULL,
		0x50008082A0000080ULL,
		0xC64A004801844000ULL,
		0x060468422101BB50ULL,
		0xC04A2034020B4184ULL,
		0x137012451060B200ULL,
		0xB801212024411480ULL
	}};
	printf("Test Case 320\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 320 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -320;
	} else {
		printf("Test Case 320 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x324B4A7F1F129C12ULL,
		0x86EE03F91C52D8DFULL,
		0x82A236F131589BBCULL,
		0x988578C36E858487ULL,
		0xB0BF3C3525AF258AULL,
		0x97D2345402CD7BC9ULL,
		0x3BE055A7851DEA3AULL,
		0xC3662C0D4A19F824ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF062EB15A083B178ULL,
		0x500E66F3FFE28DF7ULL,
		0xF403A93BAF246A17ULL,
		0x6BDC4E156B012AC4ULL,
		0xD8B9F07886696F3CULL,
		0x67FC3A3AF0740E13ULL,
		0xA2C9F2772D677658ULL,
		0xF2D371706558BC15ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x30424A1500029010ULL,
		0x000E02F11C4288D7ULL,
		0x8002203121000A14ULL,
		0x088448016A010084ULL,
		0x90B9303004292508ULL,
		0x07D0301000440A01ULL,
		0x22C0502705056218ULL,
		0xC24220004018B804ULL
	}};
	printf("Test Case 321\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 321 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -321;
	} else {
		printf("Test Case 321 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x664DB480E3E2AFA0ULL,
		0x63C587DBDB0BA071ULL,
		0xD217A6BF8D460EF4ULL,
		0x82088DB3C8AF5625ULL,
		0x85CC2281609488E7ULL,
		0x44B67B039603BD00ULL,
		0x723F187E111F84BAULL,
		0xB989838357F531CFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x886EAA5FBDB50919ULL,
		0x120B1A934F4718D5ULL,
		0x43D5D86DA7DBCE39ULL,
		0x78A8EB42B912B1C4ULL,
		0x302541159E050B42ULL,
		0xA973DB3BA94ECD15ULL,
		0x91CEF3554E4D35A4ULL,
		0x81110625D64858B4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x004CA000A1A00900ULL,
		0x020102934B030051ULL,
		0x4215802D85420E30ULL,
		0x0008890288021004ULL,
		0x0004000100040842ULL,
		0x00325B0380028D00ULL,
		0x100E1054000D04A0ULL,
		0x8101020156401084ULL
	}};
	printf("Test Case 322\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 322 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -322;
	} else {
		printf("Test Case 322 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD1A3F711A3A5638AULL,
		0x259D0E3EBDB978C7ULL,
		0x223F5931FF793165ULL,
		0x38A7ABE9B8D3EEB8ULL,
		0x4BB8DC7187DCC391ULL,
		0xE002909CC44D17D5ULL,
		0xC6F91A7026D01DC8ULL,
		0xC1974B05D9BE583CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x67BA86D95A57A2C8ULL,
		0x3067B3E6BC4F8561ULL,
		0x3BD62A09EF7276DDULL,
		0x4EBD5B0755679421ULL,
		0x52606B334A4147F8ULL,
		0x23A9DB7D6D5E0C79ULL,
		0xDA01080F491014FCULL,
		0xBF8EDE0A7721121FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x41A2861102052288ULL,
		0x20050226BC090041ULL,
		0x22160801EF703045ULL,
		0x08A50B0110438420ULL,
		0x4220483102404390ULL,
		0x2000901C444C0451ULL,
		0xC2010800001014C8ULL,
		0x81864A005120101CULL
	}};
	printf("Test Case 323\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 323 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -323;
	} else {
		printf("Test Case 323 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE1C76281174DDFF7ULL,
		0xCCCCEAA9DACAADD0ULL,
		0x5E022DFF74954894ULL,
		0xD220DEBF9653D566ULL,
		0x33B3F00991DAC0F7ULL,
		0x7D3905C1938E8508ULL,
		0x132ECA4C183BB590ULL,
		0x06CB477DECE5A353ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x295CFE6F6EC8B412ULL,
		0xD0565F5AA8485392ULL,
		0xC56619CAFF9ACBB4ULL,
		0x03644C0C85922A54ULL,
		0x64F216FAAC3679BBULL,
		0x7F027D0B7408AE5EULL,
		0x980BC8B8862FC52CULL,
		0x0C2BFF6A5B2C5E21ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2144620106489412ULL,
		0xC0444A0888480190ULL,
		0x440209CA74904894ULL,
		0x02204C0C84120044ULL,
		0x20B21008801240B3ULL,
		0x7D00050110088408ULL,
		0x100AC808002B8500ULL,
		0x040B476848240201ULL
	}};
	printf("Test Case 324\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 324 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -324;
	} else {
		printf("Test Case 324 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA331AA24B35B5849ULL,
		0xD32BDB8D8FB2ED0EULL,
		0xAEEA4DC2DE848D04ULL,
		0x7654EDE6C30EE2E3ULL,
		0xA3CB1624C71570D0ULL,
		0xABB39BDA143812C1ULL,
		0xA2B0DA4782DA28C2ULL,
		0xC0DD2571840C6D42ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1AE30DE946613E2EULL,
		0x7BC8A47692894D48ULL,
		0x0750D6AB2C1E75B7ULL,
		0xCAF9350B4430D83EULL,
		0xC238D0338F4D9EFDULL,
		0x3CC29FF0692ABDA4ULL,
		0x19D6A45AB89000DBULL,
		0x2F4437A4F8EAEAEDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0221082002411808ULL,
		0x5308800482804D08ULL,
		0x064044820C040504ULL,
		0x425025024000C022ULL,
		0x82081020870510D0ULL,
		0x28829BD000281080ULL,
		0x00908042809000C2ULL,
		0x0044252080086840ULL
	}};
	printf("Test Case 325\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 325 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -325;
	} else {
		printf("Test Case 325 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x454B855AFBE92028ULL,
		0xEF0D58A76BD9B340ULL,
		0xC847C4A6718460B5ULL,
		0x5769B97347F3F66CULL,
		0x2581F10A36F4D6A1ULL,
		0x9858D41804C1E4C5ULL,
		0x6F15E35774DE0B5FULL,
		0xC3F1CAC3CEF633C5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3F0FD99393A0F1AFULL,
		0x969BF626DEA0D50FULL,
		0xAD44096C4FB64DB5ULL,
		0xC4C4A944B287EA78ULL,
		0x19A54D813E0E4B25ULL,
		0x36A09A144456574DULL,
		0xBC3DE2359EAF53A1ULL,
		0x5CA0FDB74B2B39A7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x050B811293A02028ULL,
		0x860950264A809100ULL,
		0x88440024418440B5ULL,
		0x4440A9400283E268ULL,
		0x0181410036044221ULL,
		0x1000901004404445ULL,
		0x2C15E215148E0301ULL,
		0x40A0C8834A223185ULL
	}};
	printf("Test Case 326\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 326 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -326;
	} else {
		printf("Test Case 326 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0D4C11544BBBDE9BULL,
		0x51B16B4A4B483D94ULL,
		0xE064D2648449EA22ULL,
		0xE66E4026848D9570ULL,
		0x8920509281264760ULL,
		0xBBDE437BD414C91BULL,
		0x371B3210CD61311AULL,
		0x5EED589998AF8BC4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFD9088D21EE89766ULL,
		0x0456CAC15E7AEBDDULL,
		0xAB83EC187F8F8021ULL,
		0x2FC6B76B34627233ULL,
		0x0CA94ED9A423315BULL,
		0x7E8892E0B94B092EULL,
		0xE1BC3E0F046B43E2ULL,
		0xB93AB9DD1D61E04FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0D0000500AA89602ULL,
		0x00104A404A482994ULL,
		0xA000C00004098020ULL,
		0x2646002204001030ULL,
		0x0820409080220140ULL,
		0x3A8802609000090AULL,
		0x2118320004610102ULL,
		0x1828189918218044ULL
	}};
	printf("Test Case 327\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 327 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -327;
	} else {
		printf("Test Case 327 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5DC83B9C5BE83140ULL,
		0x7C1474DF9E9B416DULL,
		0x7E42147DD57F7B7BULL,
		0x22DC6C9B7CB1858AULL,
		0x389F85EAC38044B6ULL,
		0x967F7E1587E6728BULL,
		0x3B89B320293BBF0FULL,
		0xED3BB0854415C56FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC157EF52FDDDFF13ULL,
		0xB0631173478287EBULL,
		0xB1480CB30ED8CE47ULL,
		0xAF087EBCDEC2456FULL,
		0xE1DBB0ABC4D01360ULL,
		0x021880390EB10530ULL,
		0x2407FC4A500EC70BULL,
		0x9339C1356DC98909ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x41402B1059C83100ULL,
		0x3000105306820169ULL,
		0x3040043104584A43ULL,
		0x22086C985C80050AULL,
		0x209B80AAC0800020ULL,
		0x0218001106A00000ULL,
		0x2001B000000A870BULL,
		0x8139800544018109ULL
	}};
	printf("Test Case 328\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 328 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -328;
	} else {
		printf("Test Case 328 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA13B3EFC7D72CD36ULL,
		0xF1B9484CABA3F307ULL,
		0x5B5D5B69B202C415ULL,
		0x8BBDA83FE5B453A8ULL,
		0x5E1E0473210C2635ULL,
		0x830654E352D41A22ULL,
		0x65C83C7BEBC2F9BDULL,
		0xC84A2FF8F768B0E0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xACBF12B28C4F4DC5ULL,
		0x47D38F68192974DBULL,
		0x80B6E1808588E4A8ULL,
		0x7F5A3FB4A41A6FE7ULL,
		0x8DC3DDDD7E191441ULL,
		0xC4DAE7F1EA4C87C1ULL,
		0x538ED18C91000B7EULL,
		0xCEEA4889117B53C9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA03B12B00C424D04ULL,
		0x4191084809217003ULL,
		0x001441008000C400ULL,
		0x0B182834A41043A0ULL,
		0x0C02045120080401ULL,
		0x800244E142440200ULL,
		0x418810088100093CULL,
		0xC84A0888116810C0ULL
	}};
	printf("Test Case 329\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 329 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -329;
	} else {
		printf("Test Case 329 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6FF9DF3243F51F34ULL,
		0x421A59F7BD5EF3B0ULL,
		0x78B9457DD46D878FULL,
		0xE27EF77E77723CEAULL,
		0x619358527EE370A8ULL,
		0xDC3097CA7C1751C3ULL,
		0x973C6D627FA3C14FULL,
		0xCFED33C2C9DDDD87ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF5A6BFF3076BA00EULL,
		0x9048F07F0FA083DBULL,
		0x65C4FB267CE3DEC1ULL,
		0xF489D6FD493A117DULL,
		0x89DCBE23B0A7D0FCULL,
		0x8C1996871AE014E4ULL,
		0xBA7372C4D971C996ULL,
		0x551CD3F645565AADULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x65A09F3203610004ULL,
		0x000850770D008390ULL,
		0x6080412454618681ULL,
		0xE008D67C41321068ULL,
		0x0190180230A350A8ULL,
		0x8C109682180010C0ULL,
		0x923060405921C106ULL,
		0x450C13C241545885ULL
	}};
	printf("Test Case 330\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 330 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -330;
	} else {
		printf("Test Case 330 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2819446DE675B835ULL,
		0x6104C8D46763CC4BULL,
		0x95064D82B5F4FF33ULL,
		0x8D41E359333C84B2ULL,
		0x002E1A4C343633BFULL,
		0xF424E5FA07839C77ULL,
		0x05D2A7A7F63BF002ULL,
		0xEDF7E2D9F85DA1F5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFC6C8949F7D6E0D0ULL,
		0x167F4AF0E071D324ULL,
		0x56056C66A8C8540AULL,
		0xB16A8DF644069437ULL,
		0x4DE4CF27669D5C04ULL,
		0x147BEE91E6E4FC3EULL,
		0x28C20FF5877ECA8DULL,
		0x8BF0E8F6A2AD1F3BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x28080049E654A010ULL,
		0x000448D06061C000ULL,
		0x14044C02A0C05402ULL,
		0x8140815000048432ULL,
		0x00240A0424141004ULL,
		0x1420E49006809C36ULL,
		0x00C207A5863AC000ULL,
		0x89F0E0D0A00D0131ULL
	}};
	printf("Test Case 331\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 331 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -331;
	} else {
		printf("Test Case 331 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9CF400B9423C7BF5ULL,
		0xF9E2B4237C92DB1AULL,
		0x903AAA56D9DCB269ULL,
		0x8D677FDB103D7CA9ULL,
		0x1F1C92FD50F6A8B6ULL,
		0x8B12CB40BE1FB45DULL,
		0x81DF579FA0C141BAULL,
		0x0FF2A6D6C3388BEDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7010BA6DD701FEE7ULL,
		0xEA92DF7377B0F45DULL,
		0x54A3266EC72866FDULL,
		0xB8993B00FB511342ULL,
		0x15A0AAAFC200D173ULL,
		0x7A8D87A58BAB7A5AULL,
		0xF839E6128DB5F452ULL,
		0x579E52B10F495F70ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1010002942007AE5ULL,
		0xE88294237490D018ULL,
		0x10222246C1082269ULL,
		0x88013B0010111000ULL,
		0x150082AD40008032ULL,
		0x0A0083008A0B3058ULL,
		0x8019461280814012ULL,
		0x0792029003080B60ULL
	}};
	printf("Test Case 332\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 332 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -332;
	} else {
		printf("Test Case 332 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC665268683DCD1A8ULL,
		0xE8CE2E6AD69FB934ULL,
		0x35DCAA627093F09CULL,
		0x3525CC8DC6D951C7ULL,
		0xB90FCF9682C520EBULL,
		0x03995147A5509385ULL,
		0xDFC1C879B8525B80ULL,
		0xF4306FFB0A16A8C0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x987E7635EFB5DFF8ULL,
		0xCCF51939DDD28A9AULL,
		0xAD4D64FD15519EF7ULL,
		0x4BBA797322B96A75ULL,
		0x442F2B0C1225B16DULL,
		0x5EC411E49C74ED5FULL,
		0x5F4FBD29CACCDE67ULL,
		0xE38ADD6EE8583CC1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x806426048394D1A8ULL,
		0xC8C40828D4928810ULL,
		0x254C206010119094ULL,
		0x0120480102994045ULL,
		0x000F0B0402052069ULL,
		0x0280114484508105ULL,
		0x5F41882988405A00ULL,
		0xE0004D6A081028C0ULL
	}};
	printf("Test Case 333\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 333 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -333;
	} else {
		printf("Test Case 333 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x46CE79A66773BA0EULL,
		0x5B1EB91C89F6F779ULL,
		0xDE1F23B58C357240ULL,
		0x05B51955D7B4A9F5ULL,
		0xE1F1FCE37107D9B7ULL,
		0xFB60B831A3E8D8BCULL,
		0x934E009ABFB9AB26ULL,
		0xED81BF904752C068ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x47B83A5753772901ULL,
		0x655D2158CE7ABB7CULL,
		0x453658B733CF3E7AULL,
		0xB34F0865F83BA7FBULL,
		0xE0FEC0732A91B3C3ULL,
		0x2007447879E9E807ULL,
		0xB00AC268997B9FB1ULL,
		0x60350623E989AD51ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4688380643732800ULL,
		0x411C21188872B378ULL,
		0x441600B500053240ULL,
		0x01050845D030A1F1ULL,
		0xE0F0C06320019183ULL,
		0x2000003021E8C804ULL,
		0x900A000899398B20ULL,
		0x6001060041008040ULL
	}};
	printf("Test Case 334\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 334 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -334;
	} else {
		printf("Test Case 334 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3DFD3891D61932CCULL,
		0x67FA638C93B88B20ULL,
		0x3A926E0466B8CDBCULL,
		0x92B1DE31190112E5ULL,
		0xB1F64109DBE729D8ULL,
		0x1DA3EF537A60C3FCULL,
		0xDEAB51FF5BE1BA7AULL,
		0x1ED18AA062423EF7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x99434B4BA2D22FD3ULL,
		0x723FF68DF6366FABULL,
		0xB153ACF8D803AC4CULL,
		0x7C1A5F0650862BF3ULL,
		0xB8A8D7294264BD16ULL,
		0xDE4052B38A68B4CAULL,
		0x64CC7BF5FAEB03D4ULL,
		0xF7E82B48D7E8958BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x19410801821022C0ULL,
		0x623A628C92300B20ULL,
		0x30122C0040008C0CULL,
		0x10105E00100002E1ULL,
		0xB0A0410942642910ULL,
		0x1C0042130A6080C8ULL,
		0x448851F55AE10250ULL,
		0x16C00A0042401483ULL
	}};
	printf("Test Case 335\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 335 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -335;
	} else {
		printf("Test Case 335 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x77BE6788F9DF9F81ULL,
		0x5AE98E8E6CC17B86ULL,
		0x0019DBA261753601ULL,
		0xAEE2A717D11B2834ULL,
		0x29CFC3D7302BC3D3ULL,
		0xB391D764DAA48BF7ULL,
		0x68FF6468FB6712C0ULL,
		0xB9C59C4169D2F85EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x346596157C9C0F46ULL,
		0x2C9FD4A8C93DDA63ULL,
		0xA9D647F2E9C945C7ULL,
		0x36388B351C09A0C5ULL,
		0x25B1B5797B5D8FDBULL,
		0xB05D0384B5029209ULL,
		0xEFFACF320879E5BCULL,
		0x76BB0DB3C50EA0B6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x34240600789C0F00ULL,
		0x0889848848015A02ULL,
		0x001043A261410401ULL,
		0x2620831510092004ULL,
		0x21818151300983D3ULL,
		0xB011030490008201ULL,
		0x68FA442008610080ULL,
		0x30810C014102A016ULL
	}};
	printf("Test Case 336\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 336 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -336;
	} else {
		printf("Test Case 336 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA4A6A4D91FA72D27ULL,
		0xA33FEB7C25B8DF60ULL,
		0xE7225942DBF9E601ULL,
		0x4BF57FC9BB1DEFEDULL,
		0x58BE9CDE895441D9ULL,
		0x266A7A8EC44F5B9FULL,
		0x0A17FE003914B20EULL,
		0x92970A57F917FDC9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x567017C9E3A8D71AULL,
		0xB4955D36E41FFF11ULL,
		0xBD7EEF0D1A8931AAULL,
		0x408E5A11FC76D6BCULL,
		0xB5E58D33575575C7ULL,
		0x481B69F842C76C9BULL,
		0x8FD0F8271723DAAEULL,
		0xCC87A5485DEB8DE8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x042004C903A00502ULL,
		0xA01549342418DF00ULL,
		0xA52249001A892000ULL,
		0x40845A01B814C6ACULL,
		0x10A48C12015441C1ULL,
		0x000A68884047489BULL,
		0x0A10F8001100920EULL,
		0x8087004059038DC8ULL
	}};
	printf("Test Case 337\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 337 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -337;
	} else {
		printf("Test Case 337 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEDE213CCD8B89890ULL,
		0xD09D1C25FABBDC2BULL,
		0xCEB73DE63521EEA7ULL,
		0xF7342C638223BA93ULL,
		0xEA152A3AFEF42F87ULL,
		0x7D04D10FCE0EBE01ULL,
		0x468B97035FAEC6D8ULL,
		0x21076E722CB172EFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBDE2716CD51D735CULL,
		0x5DFBE6A8B0E1FA20ULL,
		0x1EC2B3454AFC3E43ULL,
		0x653DB76028D4509AULL,
		0xA046E19D63E9BDC5ULL,
		0xE3BAEAD13A236233ULL,
		0x2DD1DE21852E8C30ULL,
		0x321ECDF7EFB40CC1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xADE2114CD0181010ULL,
		0x50990420B0A1D820ULL,
		0x0E82314400202E03ULL,
		0x6534246000001092ULL,
		0xA004201862E02D85ULL,
		0x6100C0010A022201ULL,
		0x04819601052E8410ULL,
		0x20064C722CB000C1ULL
	}};
	printf("Test Case 338\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 338 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -338;
	} else {
		printf("Test Case 338 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA59065C87A821CC7ULL,
		0xFCC1B5C5BC9F137BULL,
		0x00A2AC9B25885155ULL,
		0x806E2BEA299BCBA4ULL,
		0x85A98ED4B023E6A4ULL,
		0x64EF5EE0195F127DULL,
		0xF3887D2B87828A3CULL,
		0xEFD13B4CFCFD6960ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x63827CE1E9B7D248ULL,
		0xAF9DBCC3915A5DC9ULL,
		0xBCD81B65BDCA01D9ULL,
		0x0C301F3928CD3502ULL,
		0x5E45174360C803D7ULL,
		0x062E976C067E254CULL,
		0xE03832EB1FF301FEULL,
		0xFB6121895D1CF950ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x218064C068821040ULL,
		0xAC81B4C1901A1149ULL,
		0x0080080125880151ULL,
		0x00200B2828890100ULL,
		0x0401064020000284ULL,
		0x042E1660005E004CULL,
		0xE008302B0782003CULL,
		0xEB4121085C1C6940ULL
	}};
	printf("Test Case 339\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 339 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -339;
	} else {
		printf("Test Case 339 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x132116E4C022561CULL,
		0xB45D9DEACEC28CD1ULL,
		0x59B508E056A9BCC0ULL,
		0xEAEF2EC454EC3C0EULL,
		0xBBBA66750C80473EULL,
		0x5D353B2078F1F6AFULL,
		0x0B4C46A25E64E884ULL,
		0x0E0C4E7C592EA67AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3EED9ADB65C28986ULL,
		0x1C41D0701E10819BULL,
		0xB064C2ADEA248086ULL,
		0xEDBBFBB44CD5AEC0ULL,
		0x8289A34437D6CED6ULL,
		0xAF8C06F960EB1377ULL,
		0x303A1B9DCF0F84E2ULL,
		0xC8B4931C8957CA23ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x122112C040020004ULL,
		0x144190600E008091ULL,
		0x102400A042208080ULL,
		0xE8AB2A8444C42C00ULL,
		0x8288224404804616ULL,
		0x0D04022060E11227ULL,
		0x000802804E048080ULL,
		0x0804021C09068222ULL
	}};
	printf("Test Case 340\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 340 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -340;
	} else {
		printf("Test Case 340 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x48586C0680D78009ULL,
		0xA01B0BF2F4BE0892ULL,
		0xB67F619985AC7AEAULL,
		0xE0FD32E83190B14EULL,
		0x8F587200AA36C814ULL,
		0xB3A9E295ABF5A72EULL,
		0x2734DBEAED8E03DEULL,
		0xC97B7C730135840FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFE1329A122894BEBULL,
		0xBF774D93E90139A5ULL,
		0x30F437582857E431ULL,
		0xA24AB7B34F6F110CULL,
		0xE0A84D9F6CAC2FA8ULL,
		0x38936A7D3058C17EULL,
		0xF1C881DF064567E5ULL,
		0x82AC177E33561B55ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4810280000810009ULL,
		0xA0130992E0000880ULL,
		0x3074211800046020ULL,
		0xA04832A00100110CULL,
		0x8008400028240800ULL,
		0x308162152050812EULL,
		0x210081CA040403C4ULL,
		0x8028147201140005ULL
	}};
	printf("Test Case 341\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 341 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -341;
	} else {
		printf("Test Case 341 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7EA94C1BEE9E80EFULL,
		0x0CB27308EAA68FCFULL,
		0xBCA3AF2631862E8AULL,
		0xC747B62BEC9663E3ULL,
		0x54C0F6FFAF007DA7ULL,
		0x639CB91DA2E15356ULL,
		0xB8178C72A077B233ULL,
		0xB4715CEF25A49F6BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDFA6F21AF14112B0ULL,
		0x9F00AB3A1E94A814ULL,
		0xFFD6AC9596265884ULL,
		0x20032FB6E163A5F3ULL,
		0x75D18045EE470CFBULL,
		0x709E73DF528C25EDULL,
		0xB679B8274330D8E1ULL,
		0xC77DE3DFF08E69F9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5EA0401AE00000A0ULL,
		0x0C0023080A848804ULL,
		0xBC82AC0410060880ULL,
		0x00032622E00221E3ULL,
		0x54C08045AE000CA3ULL,
		0x609C311D02800144ULL,
		0xB011882200309021ULL,
		0x847140CF20840969ULL
	}};
	printf("Test Case 342\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 342 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -342;
	} else {
		printf("Test Case 342 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1F216E0036EE4D26ULL,
		0x957B172108149688ULL,
		0x044128532EE85EA3ULL,
		0x97D22C55F8952A45ULL,
		0xEBEAB1D65553B9E5ULL,
		0x7F002A0CDD6317FCULL,
		0xE4C4830D20338A66ULL,
		0xF2FAF4B58EC6F885ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3B55F9CE7C25256FULL,
		0xE1E2CE8112726BA8ULL,
		0xD4D819E3DDBB8C9DULL,
		0x452BC9B658E0916CULL,
		0x250EA6B14F0B4C3EULL,
		0xF20AC4886258C7E3ULL,
		0xDE125C78D0623BC7ULL,
		0xE898371D165E4DEAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1B01680034240526ULL,
		0x8162060100100288ULL,
		0x044008430CA80C81ULL,
		0x0502081458800044ULL,
		0x210AA09045030824ULL,
		0x72000008404007E0ULL,
		0xC400000800220A46ULL,
		0xE098341506464880ULL
	}};
	printf("Test Case 343\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 343 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -343;
	} else {
		printf("Test Case 343 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x56970DD9C9FF65E6ULL,
		0xB69E69C0C5C4B042ULL,
		0x386844C54CFB8E47ULL,
		0x34900C4938BAFEB7ULL,
		0x663CD40B8637E22DULL,
		0x8392B8FB718450F0ULL,
		0x60B36E551A7557B1ULL,
		0x81DBF6FBCD5A733BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x710C803E7E00CF38ULL,
		0x2A7E6434C8E99AABULL,
		0x9620828E780EE623ULL,
		0xB4910AAF08D336DEULL,
		0xCF0B804411F3BB8CULL,
		0x89BF5B47BFB2F0C5ULL,
		0xDECB5DF865EDD884ULL,
		0x67FBE98AAFA35E7CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5004001848004520ULL,
		0x221E6000C0C09002ULL,
		0x10200084480A8603ULL,
		0x3490080908923696ULL,
		0x460880000033A20CULL,
		0x81921843318050C0ULL,
		0x40834C5000655080ULL,
		0x01DBE08A8D025238ULL
	}};
	printf("Test Case 344\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 344 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -344;
	} else {
		printf("Test Case 344 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF4CD6BD447A0EE9AULL,
		0x86119C6202E73FDBULL,
		0x574A0A0745272F82ULL,
		0xCDEC4783ED530885ULL,
		0xFDF85A5BE0B64B78ULL,
		0x4844DDDD67CD703DULL,
		0x923103ECBC0F476BULL,
		0xD7BB8A7D462629F4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC89527F4CF11AA28ULL,
		0xA9F8670F23988667ULL,
		0x2D9C4AB7BC8352E6ULL,
		0x70B1185E3A452153ULL,
		0xA03E0853A6EFACB2ULL,
		0xFD995C241AF7055CULL,
		0xFF4B9A1C5F8206A5ULL,
		0x8808415376B2CA05ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC08523D44700AA08ULL,
		0x8010040202800643ULL,
		0x05080A0704030282ULL,
		0x40A0000228410001ULL,
		0xA0380853A0A60830ULL,
		0x48005C0402C5001CULL,
		0x9201020C1C020621ULL,
		0x8008005146220804ULL
	}};
	printf("Test Case 345\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 345 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -345;
	} else {
		printf("Test Case 345 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCAB57D12ADEA0107ULL,
		0x3E50E396E34CA52AULL,
		0x6F48D0A26B276A3BULL,
		0xC1F9B6D3BE030146ULL,
		0xBBBB0D49675A6891ULL,
		0x63A468C0D2BCCCC9ULL,
		0xDC59CFCAD65EE57DULL,
		0xFDF84FD87A7FFC82ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2A121AF860777117ULL,
		0x88AD639600CD23D1ULL,
		0xEAFF78806808E334ULL,
		0x394EAE65251DEFFDULL,
		0xA127B9BE43BBFC19ULL,
		0xE0AF6726D4E3AB82ULL,
		0x457D6FF2323FE636ULL,
		0x1F9A7C8A4D0A6AB4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0A10181020620107ULL,
		0x08006396004C2100ULL,
		0x6A48508068006230ULL,
		0x0148A64124010144ULL,
		0xA1230908431A6811ULL,
		0x60A46000D0A08880ULL,
		0x44594FC2121EE434ULL,
		0x1D984C88480A6880ULL
	}};
	printf("Test Case 346\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 346 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -346;
	} else {
		printf("Test Case 346 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x095477EA5A32FF7BULL,
		0x433FC9BA7D5AC5A4ULL,
		0x42A62DD431FB1467ULL,
		0x896633DAD4F72A44ULL,
		0x055B33940E00327DULL,
		0xD519EC24005ED700ULL,
		0x582468D146644232ULL,
		0x5CEC977B736C3FBFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x959B36F2DF44891EULL,
		0xCFE60D1D1760094AULL,
		0xB51B4F8AAB67E30FULL,
		0x1BB9934A3FA136D7ULL,
		0x9E653A1C6D37B416ULL,
		0xB96C92D169F1C2AAULL,
		0x9A99DF5EAA1F0700ULL,
		0x864FBAC9DD445A27ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x011036E25A00891AULL,
		0x4326091815400100ULL,
		0x00020D8021630007ULL,
		0x0920134A14A12244ULL,
		0x044132140C003014ULL,
		0x910880000050C200ULL,
		0x1800485002040200ULL,
		0x044C924951441A27ULL
	}};
	printf("Test Case 347\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 347 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -347;
	} else {
		printf("Test Case 347 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD3F962040CE54FA0ULL,
		0xFCA5A5AD1AC894BFULL,
		0xB4B5E176AA4389F9ULL,
		0x8B5EA8350EC2577BULL,
		0x5B6AD8F78E15BEADULL,
		0x7689D6BFB6B46AE5ULL,
		0xC46D493511240AB3ULL,
		0xE050A4559D694718ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x46A0F594DDCA97C5ULL,
		0x0E80E4AA6FFFE743ULL,
		0xE17FCAD19A4D2EA0ULL,
		0xC40100D662BF8B89ULL,
		0xA06A28461CD99DE0ULL,
		0xB0EC085E3A19A336ULL,
		0x7982D91529540D24ULL,
		0x2A123B52CCD3F451ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x42A060040CC00780ULL,
		0x0C80A4A80AC88403ULL,
		0xA035C0508A4108A0ULL,
		0x8000001402820309ULL,
		0x006A08460C119CA0ULL,
		0x3088001E32102224ULL,
		0x4000491501040820ULL,
		0x201020508C414410ULL
	}};
	printf("Test Case 348\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 348 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -348;
	} else {
		printf("Test Case 348 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x71F6B6F526A7B8C3ULL,
		0xFD8543055F451F03ULL,
		0xB41BA3505C6B6D3DULL,
		0x8F76005C9D488A8EULL,
		0xEFD6691A22D17EACULL,
		0x7558C467C76419C9ULL,
		0xE63E7923BB79032FULL,
		0xA8AF67A1D7B01006ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE1D0D9C514EA742BULL,
		0x5462C7B2AEF202B7ULL,
		0x637F3F3C98BC3AB5ULL,
		0x02C98E3752ADA7E1ULL,
		0x178B0EAADFC2090BULL,
		0x6EDA1F0660D58B29ULL,
		0x3AF36143C5EB5414ULL,
		0xE41054C38574E2F9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x61D090C504A23003ULL,
		0x540043000E400203ULL,
		0x201B231018282835ULL,
		0x0240001410088280ULL,
		0x0782080A02C00808ULL,
		0x6458040640440909ULL,
		0x2232610381690004ULL,
		0xA000448185300000ULL
	}};
	printf("Test Case 349\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 349 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -349;
	} else {
		printf("Test Case 349 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x89B5CE27E0E91D07ULL,
		0x0B9C2B8F8470A06AULL,
		0x34CA21AFAAA6078AULL,
		0x08B36956F5FF7A66ULL,
		0x567FC8981E8075C9ULL,
		0x7536EBD069D68954ULL,
		0xFCF9932F3A4D3F93ULL,
		0xF51917F896927F70ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB73C8DBB2C8A2EEBULL,
		0x123993060765A4D8ULL,
		0x40D3067E4BB3141FULL,
		0x9D56AF7FA26A1E27ULL,
		0x9079FD08D8142633ULL,
		0x529DCC9D8BF05FF0ULL,
		0x0EB3BEE1DFB40AFFULL,
		0x75B5C0290EE5AB28ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x81348C2320880C03ULL,
		0x021803060460A048ULL,
		0x00C2002E0AA2040AULL,
		0x08122956A06A1A26ULL,
		0x1079C80818002401ULL,
		0x5014C89009D00950ULL,
		0x0CB192211A040A93ULL,
		0x7511002806802B20ULL
	}};
	printf("Test Case 350\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 350 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -350;
	} else {
		printf("Test Case 350 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4E50E2758DDFD26BULL,
		0x518570E434FB0B3BULL,
		0x42229EA0E77911D8ULL,
		0x1ECD70DB83B25D5DULL,
		0x440E17D053E52589ULL,
		0xA576CBD44476A477ULL,
		0xE1715E4C246B4275ULL,
		0x32A2E1F04618EC1CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x22EE274907F00547ULL,
		0xB8146C7BD94B447BULL,
		0x4A942FE7CF2029D0ULL,
		0x5FB7B14880B8150DULL,
		0x28028787FDCA9E69ULL,
		0x876E9F271893346DULL,
		0x7154F62DBD445F23ULL,
		0x3D0642ED8B3194B8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0240224105D00043ULL,
		0x10046060104B003BULL,
		0x42000EA0C72001D0ULL,
		0x1E85304880B0150DULL,
		0x0002078051C00409ULL,
		0x85668B0400122465ULL,
		0x6150560C24404221ULL,
		0x300240E002108418ULL
	}};
	printf("Test Case 351\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 351 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -351;
	} else {
		printf("Test Case 351 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x87F2B9B9DF6CE3ACULL,
		0x6AEE76DB306FDB44ULL,
		0x2AA713C9BC55B1D1ULL,
		0x807B32ECF81440F0ULL,
		0xE92889C3D246F82EULL,
		0x6A963AE66E5E3725ULL,
		0x8D941933AD447233ULL,
		0x9B8443E65A5EAF70ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x47303E71055EC878ULL,
		0xBBD66D45BD40AEAFULL,
		0x82F02245EF4E18C8ULL,
		0xDD3A0B6CA0F421E7ULL,
		0x69E37C92548EF159ULL,
		0x0663DB5BD345D033ULL,
		0x9B4F4150B1CCB3ABULL,
		0x09EA113C09F45584ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x07303831054CC028ULL,
		0x2AC6644130408A04ULL,
		0x02A00241AC4410C0ULL,
		0x803A026CA01400E0ULL,
		0x692008825006F008ULL,
		0x02021A4242441021ULL,
		0x89040110A1443223ULL,
		0x0980012408540500ULL
	}};
	printf("Test Case 352\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 352 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -352;
	} else {
		printf("Test Case 352 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x021725128B3372DEULL,
		0xC6089EEE7679EACDULL,
		0x7764258D17E75158ULL,
		0x69BB1C274DA55AACULL,
		0xB84B7575058476D2ULL,
		0x2CA4EC4D758EADA4ULL,
		0x146A3E9E2D551446ULL,
		0x873B544DC377867BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x23A2143E89261E96ULL,
		0x22FB6D1B9B26800BULL,
		0x90AE988C80D9B6D3ULL,
		0x43D9A3F233E61811ULL,
		0xCE0F69D377C56D08ULL,
		0xB9E0E5A2B5690311ULL,
		0x00CF9B577A18AD15ULL,
		0xC0A4E437B4EC5907ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0202041289221296ULL,
		0x02080C0A12208009ULL,
		0x1024008C00C11050ULL,
		0x4199002201A41800ULL,
		0x880B615105846400ULL,
		0x28A0E40035080100ULL,
		0x004A1A1628100404ULL,
		0x8020440580640003ULL
	}};
	printf("Test Case 353\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 353 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -353;
	} else {
		printf("Test Case 353 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9972F6122618FBFEULL,
		0xB1E289C20EF0105EULL,
		0xC257AE9486290C48ULL,
		0x05C0BC1A116D62F5ULL,
		0xE926E34E776A4D81ULL,
		0x607EACD5C4E3BAC7ULL,
		0x6A71BF9BB733A5F2ULL,
		0x462891045ADF9C0BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC8EB373964AB8585ULL,
		0xBA64FEDF6EC7BA48ULL,
		0x0FC18C707CE5C1B4ULL,
		0x8899D969343E1EACULL,
		0xABAA24674D771A2BULL,
		0xB302A01389866F18ULL,
		0x0E09F1A71B22486EULL,
		0x85A7769D012B3F4AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8862361024088184ULL,
		0xB06088C20EC01048ULL,
		0x02418C1004210000ULL,
		0x00809808102C02A4ULL,
		0xA922204645620801ULL,
		0x2002A01180822A00ULL,
		0x0A01B18313220062ULL,
		0x04201004000B1C0AULL
	}};
	printf("Test Case 354\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 354 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -354;
	} else {
		printf("Test Case 354 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x738E51060261FE64ULL,
		0xD4D070C21F35BC5FULL,
		0x467DE8FBCCC18C9CULL,
		0x623AACE05430AF88ULL,
		0xAB4DF479D18BE478ULL,
		0x81A37A778E3EF33CULL,
		0x0B7C29EFFA65F057ULL,
		0x0A16A1044D01FF84ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7764E0402D717781ULL,
		0xBE7F0D0698037B5BULL,
		0xB02B9746A5A74987ULL,
		0x54597BC01B3AAE53ULL,
		0x101549453B84A4F4ULL,
		0x0463FCCB36C3A1A6ULL,
		0x7B971F89A84D75EDULL,
		0xE69DDBEF49BD365BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7304400000617600ULL,
		0x945000021801385BULL,
		0x0029804284810884ULL,
		0x401828C01030AE00ULL,
		0x000540411180A470ULL,
		0x002378430602A124ULL,
		0x0B140989A8457045ULL,
		0x0214810449013600ULL
	}};
	printf("Test Case 355\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 355 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -355;
	} else {
		printf("Test Case 355 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8FE9CCC0949B6ED5ULL,
		0x6B74592D2319425EULL,
		0x2700833199EEFBF0ULL,
		0xAF730D34B1DD1F8EULL,
		0xE17BBA66AFFC5EE3ULL,
		0x9EADCAE27B3EEE47ULL,
		0xD8660BB3C9A22BE1ULL,
		0x25518042770FBCF5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD0157B688CF35968ULL,
		0xDEDC66509EE4C72AULL,
		0x070C80DD21362C70ULL,
		0x60375451DD871E51ULL,
		0xD1BEC62A2F31A05EULL,
		0x0032501205F6263BULL,
		0x8640E703E68C18A0ULL,
		0xD7395B58B36F8392ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8001484084934840ULL,
		0x4A5440000200420AULL,
		0x0700801101262870ULL,
		0x2033041091851E00ULL,
		0xC13A82222F300042ULL,
		0x0020400201362603ULL,
		0x80400303C08008A0ULL,
		0x05110040330F8090ULL
	}};
	printf("Test Case 356\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 356 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -356;
	} else {
		printf("Test Case 356 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x62863D8E4FD64860ULL,
		0x84A5DF901D892325ULL,
		0x40D9ADD0E46174B2ULL,
		0xB4C761D2439AC55EULL,
		0x5D4EE6DF84CF1842ULL,
		0x927D358C4851B911ULL,
		0x3E6AA03BA8C1CE1EULL,
		0x0C4648CEE152E8F4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x655EB3817D285F48ULL,
		0xD143B9AE2D826016ULL,
		0x46825D6C59B501FCULL,
		0x5C1AC021E74D1A45ULL,
		0x73B70C1163BC8B3AULL,
		0x78B8DF0840383BCAULL,
		0x4045547563B40AEBULL,
		0xDBE9596CA54DBBF9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x600631804D004840ULL,
		0x800199800D802004ULL,
		0x40800D40402100B0ULL,
		0x1402400043080044ULL,
		0x51060411008C0802ULL,
		0x1038150840103900ULL,
		0x0040003120800A0AULL,
		0x0840484CA140A8F0ULL
	}};
	printf("Test Case 357\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 357 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -357;
	} else {
		printf("Test Case 357 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6936889995DDB230ULL,
		0xD5013A6B6D8D4B4CULL,
		0xB5E20FEAFD235CDAULL,
		0x2DF89C272E6091CAULL,
		0xE8C22855DD1569E2ULL,
		0x368C16AE406AF6E4ULL,
		0x9BADC1177AC38789ULL,
		0x296CAC8E87C5FFC0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2147ABACB59A4420ULL,
		0x8073257CC1C50513ULL,
		0x99D11175C5EE9159ULL,
		0xD1B2E22256850E67ULL,
		0x64407BEF761F9A9AULL,
		0x0C9482D0ABA3AE29ULL,
		0x6CA8B78CFEFEC29CULL,
		0x973488ED71BA0ECEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2106888895980020ULL,
		0x8001206841850100ULL,
		0x91C00160C5221058ULL,
		0x01B0802206000042ULL,
		0x6040284554150882ULL,
		0x048402800022A620ULL,
		0x08A881047AC28288ULL,
		0x0124888C01800EC0ULL
	}};
	printf("Test Case 358\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 358 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -358;
	} else {
		printf("Test Case 358 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB963E123628235D1ULL,
		0x896BE9B8C9E1FD46ULL,
		0x6288E96C0FCAB55EULL,
		0x671AD3B06FE954C0ULL,
		0xC4509C01CAF99F37ULL,
		0xB7E0B78FDCAD776AULL,
		0x18BF7856BE885550ULL,
		0x17C86A9A94AF2BC9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x321A47D8C1058A01ULL,
		0x74F78D6EFB304BBCULL,
		0xD3B6198182565467ULL,
		0xFE533B00967CD1D0ULL,
		0x87D2D8A7214CFF6EULL,
		0x680C31FEF4BBAE7AULL,
		0xC8F177CF67496140ULL,
		0xCDF8D95D548D6196ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3002410040000001ULL,
		0x00638928C9204904ULL,
		0x4280090002421446ULL,
		0x66121300066850C0ULL,
		0x8450980100489F26ULL,
		0x2000318ED4A9266AULL,
		0x08B1704626084140ULL,
		0x05C84818148D2180ULL
	}};
	printf("Test Case 359\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 359 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -359;
	} else {
		printf("Test Case 359 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3F16EBBA458E3119ULL,
		0xB1520081156D70E4ULL,
		0x7214686CB8BD84ABULL,
		0x2FE45609C7869F29ULL,
		0xF9D4561FB0EE7955ULL,
		0x37241CE3A9A4AB64ULL,
		0x31D25508D6BA21C0ULL,
		0xCB0C25879B552820ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0585E059BF502F58ULL,
		0x155581435F1C5BF7ULL,
		0xD51B50D83E46B4C4ULL,
		0x9B56C53C9EEAD2B4ULL,
		0x0C5A85D7ED67DA95ULL,
		0xE6328D22C46A58E1ULL,
		0x389BF2CC326BC350ULL,
		0x6ECBAC8CA749B917ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0504E01805002118ULL,
		0x11500001150C50E4ULL,
		0x5010404838048480ULL,
		0x0B44440886829220ULL,
		0x08500417A0665815ULL,
		0x26200C2280200860ULL,
		0x30925008122A0140ULL,
		0x4A08248483412800ULL
	}};
	printf("Test Case 360\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 360 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -360;
	} else {
		printf("Test Case 360 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3E4DA31D81C8CC0DULL,
		0xFC883348A55988A6ULL,
		0x1A3D548FCB845314ULL,
		0x6D1F2C04A9E27D5BULL,
		0xA5737146DE3EDE14ULL,
		0x4BCA39DAB492C36BULL,
		0x3EF8EF81BFC9E163ULL,
		0x1F4157039205DEE1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4E6D9A14F5197DD9ULL,
		0xEE88AEB818E0B7A4ULL,
		0x5667A983D353F050ULL,
		0x4DBB0A593513627FULL,
		0xAFB229716A6F6075ULL,
		0x48AFDFCAF5943F1EULL,
		0x5C3C11F74CCB240DULL,
		0x1A2F321421D1B5D7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0E4D821481084C09ULL,
		0xEC882208004080A4ULL,
		0x12250083C3005010ULL,
		0x4D1B08002102605BULL,
		0xA53221404A2E4014ULL,
		0x488A19CAB490030AULL,
		0x1C3801810CC92001ULL,
		0x1A011200000194C1ULL
	}};
	printf("Test Case 361\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 361 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -361;
	} else {
		printf("Test Case 361 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8CF8D2EF8806EE1DULL,
		0x36F1AC86D2791997ULL,
		0x4B462F56CB5ABBCAULL,
		0xF1BD95BFC6BB5F4AULL,
		0x5937E5EE753493B8ULL,
		0xE630A4C039D3F1E6ULL,
		0x620A43152BE28787ULL,
		0x8F301D459DBA4138ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5F02B002E4C6D6E5ULL,
		0x19013451117E0321ULL,
		0x2D41C43BFE81F311ULL,
		0x82809A56963C4B86ULL,
		0x3B321F03717DAB85ULL,
		0xE0754BBD627FC8E6ULL,
		0xD31FB84BFD582208ULL,
		0xA88B2426C16B5C05ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0C0090028006C605ULL,
		0x1001240010780101ULL,
		0x09400412CA00B300ULL,
		0x8080901686384B02ULL,
		0x1932050271348380ULL,
		0xE03000802053C0E6ULL,
		0x420A000129400200ULL,
		0x88000404812A4000ULL
	}};
	printf("Test Case 362\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 362 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -362;
	} else {
		printf("Test Case 362 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2D1B55E84E518DB5ULL,
		0xB51732C67B6F4EE6ULL,
		0xCBDBBB8DE0A2D438ULL,
		0xD6C43AC4056693D7ULL,
		0x9749D1984359B15EULL,
		0x2D2A2C79701B9322ULL,
		0x01013CFF6ADDD071ULL,
		0x217E2B1308BF853BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2491844B823D5952ULL,
		0x6CA706C8D94071FCULL,
		0x0D2D9FD454566AD7ULL,
		0xFF324768D512C81CULL,
		0xD9E4E8089219A25AULL,
		0xB88DB16EA5010CD3ULL,
		0x6AD224844CF4B34DULL,
		0xA01F98112FD964A7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2411044802110910ULL,
		0x240702C0594040E4ULL,
		0x09099B8440024010ULL,
		0xD600024005028014ULL,
		0x9140C0080219A05AULL,
		0x2808206820010002ULL,
		0x0000248448D49041ULL,
		0x201E081108990423ULL
	}};
	printf("Test Case 363\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 363 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -363;
	} else {
		printf("Test Case 363 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDE1548C4B3F19911ULL,
		0x17F4FF315FFC46FCULL,
		0x181080B681FF1753ULL,
		0x3199377D638D355FULL,
		0xE8E1E8546112C8A8ULL,
		0xB2F37DBBB115417BULL,
		0xCDB292EA74F94917ULL,
		0x42F802E0DFA21688ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x10E313A9A5EAE121ULL,
		0xB6CE375DBA15C229ULL,
		0x011873D1655CE92BULL,
		0xA6F4A78F27918266ULL,
		0x195735ED507F0301ULL,
		0x52BEFE07FBA42A61ULL,
		0xA0BC22955CA7CC65ULL,
		0x7C27B8F952349BEBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x10010080A1E08101ULL,
		0x16C437111A144228ULL,
		0x00100090015C0103ULL,
		0x2090270D23810046ULL,
		0x0841204440120000ULL,
		0x12B27C03B1040061ULL,
		0x80B0028054A14805ULL,
		0x402000E052201288ULL
	}};
	printf("Test Case 364\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 364 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -364;
	} else {
		printf("Test Case 364 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x591416A69D2BBD86ULL,
		0x687742399E84C786ULL,
		0xAA4A4895AC433865ULL,
		0x5CE4D66F251598D7ULL,
		0xF22CAA20E5701EE0ULL,
		0xA2DADABA25647F21ULL,
		0x9AABE3C0F4BE8C2DULL,
		0x80364403FC13B4A8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9B65EA54E11FE0EDULL,
		0x3D7A37A83F3EDF9BULL,
		0x8B37B14CFDDDA532ULL,
		0x168AECE35B190CF9ULL,
		0x97378EF13CEDE029ULL,
		0x07F8D61686F732EEULL,
		0x1A39560162FC6667ULL,
		0x631711E3A809BA24ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x19040204810BA084ULL,
		0x287202281E04C782ULL,
		0x8A020004AC412020ULL,
		0x1480C463011108D1ULL,
		0x92248A2024600020ULL,
		0x02D8D21204643220ULL,
		0x1A29420060BC0425ULL,
		0x00160003A801B020ULL
	}};
	printf("Test Case 365\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 365 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -365;
	} else {
		printf("Test Case 365 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x14A4FEF8F6248411ULL,
		0x556EDC78715F5CE9ULL,
		0xABB4EF470AD94112ULL,
		0xD357BC8B34B64E1DULL,
		0xB9D157DA09D66680ULL,
		0x22EF8967A2C62C01ULL,
		0xDBCF37C9FDDD2474ULL,
		0xC8D9B4B6B4290682ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCD5BB904DCFFEB10ULL,
		0xF1F1FB398EF8DD2CULL,
		0x504A47D770DE3497ULL,
		0xF27B0DD2293B0755ULL,
		0x31BEF66B55EB91F7ULL,
		0x08994147153A60A2ULL,
		0x46931F0B6AEEE884ULL,
		0xCBA004DDE7C59765ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0400B800D4248010ULL,
		0x5160D83800585C28ULL,
		0x0000474700D80012ULL,
		0xD2530C8220320615ULL,
		0x3190564A01C20080ULL,
		0x0089014700022000ULL,
		0x4283170968CC2004ULL,
		0xC8800494A4010600ULL
	}};
	printf("Test Case 366\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 366 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -366;
	} else {
		printf("Test Case 366 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA6D4AA804E1E6FF7ULL,
		0x146D614350270D11ULL,
		0x60EA9CDADCAD867BULL,
		0xA9D0239DF408674CULL,
		0x94AE87419B0D9DA8ULL,
		0x219D5F430097F659ULL,
		0xA751C3E21096ECB3ULL,
		0x07F6B79F0BED8AFCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x870047730142CED1ULL,
		0xDDC99E0A274DF2D5ULL,
		0x3912AD98C4B902FBULL,
		0xA2F9C036A6B70503ULL,
		0xBDA0A9C2029AFE27ULL,
		0x3C8BD513D43D5628ULL,
		0x36111197E53F0A19ULL,
		0xA8DC6D2FF3BF2368ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8600020000024ED1ULL,
		0x1449000200050011ULL,
		0x20028C98C4A9027BULL,
		0xA0D00014A4000500ULL,
		0x94A0814002089C20ULL,
		0x2089550300155608ULL,
		0x2611018200160811ULL,
		0x00D4250F03AD0268ULL
	}};
	printf("Test Case 367\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 367 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -367;
	} else {
		printf("Test Case 367 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x77A68B3B82FEA34BULL,
		0xE027A9E654FB9105ULL,
		0x73E73D1A563B61C7ULL,
		0xB028605DD46A0152ULL,
		0x8BF0CF07AD1AB921ULL,
		0x77808B832478152FULL,
		0x78526AA9DB80A549ULL,
		0xC8727CB854A18622ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCD4EAC9375065D73ULL,
		0x6A701B998B0F006BULL,
		0x88CC6508671897ABULL,
		0x75B0B3AD7A040F52ULL,
		0xC8A74D1A07E2581CULL,
		0x50FDA469A8AEE68DULL,
		0x53ABA9ADA69BF724ULL,
		0xAC3240FB3B120560ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4506881300060143ULL,
		0x60200980000B0001ULL,
		0x00C4250846180183ULL,
		0x3020200D50000152ULL,
		0x88A04D0205021800ULL,
		0x508080012028040DULL,
		0x500228A98280A500ULL,
		0x883240B810000420ULL
	}};
	printf("Test Case 368\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 368 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -368;
	} else {
		printf("Test Case 368 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF0E52096EA57D5BCULL,
		0x1326E218A5DE5C3DULL,
		0x1B47A2FDE230D725ULL,
		0x265D8336F09E5B1FULL,
		0xFC6B0839D496084FULL,
		0x0C8FB3A800648791ULL,
		0x8C68D45A74B904B2ULL,
		0x60836A810BD42DD3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9978887A093D6A34ULL,
		0x1B479754D56B922EULL,
		0x4F0DD371CDC887BEULL,
		0xDA5E2E1B57111BA1ULL,
		0x57675A00D80AA363ULL,
		0x6FCCA1E0748ED9DBULL,
		0xE091F03766EF2F75ULL,
		0x98B579D7008ECB5CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9060001208154034ULL,
		0x13068210854A102CULL,
		0x0B058271C0008724ULL,
		0x025C021250101B01ULL,
		0x54630800D0020043ULL,
		0x0C8CA1A000048191ULL,
		0x8000D01264A90430ULL,
		0x0081688100840950ULL
	}};
	printf("Test Case 369\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 369 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -369;
	} else {
		printf("Test Case 369 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFFE9E1658FACE25DULL,
		0xB76C2C432E107B0DULL,
		0xDD68A430AC2D3B49ULL,
		0x0FE5EA7228565903ULL,
		0xEA85D7A924982956ULL,
		0xFE52115C946B1FBBULL,
		0xFD676075F6A36604ULL,
		0xB8188C07D354790DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC053154228AEC36DULL,
		0xAEC2C7EE448D816DULL,
		0x8DB8C3137DB5085FULL,
		0x743F733CBF4604CDULL,
		0x395E247336CE8685ULL,
		0x12788B7CCF8EEF0AULL,
		0xAC4314CEDDD78B45ULL,
		0xF4FF469BE9FD52D7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC041014008ACC24DULL,
		0xA64004420400010DULL,
		0x8D2880102C250849ULL,
		0x0425623028460001ULL,
		0x2804042124880004ULL,
		0x1250015C840A0F0AULL,
		0xAC430044D4830204ULL,
		0xB0180403C1545005ULL
	}};
	printf("Test Case 370\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 370 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -370;
	} else {
		printf("Test Case 370 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC8FCCC3A67C499F1ULL,
		0xAAF04314604094B9ULL,
		0x0B67F4C2638AFCCBULL,
		0x46E612D827A62937ULL,
		0x56C34421074D552BULL,
		0xC27311808926AE65ULL,
		0x76A8B6AED5758E0DULL,
		0x962A26584BD30C25ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2D70B453EF673274ULL,
		0x4B4CF1A3F71D01A9ULL,
		0x7ABF057097A53381ULL,
		0x5DA08C8B3E0FA094ULL,
		0x20D76C274C847932ULL,
		0x2E87688E2CF070A6ULL,
		0x70400DAB6145F60BULL,
		0xC57C320D1CAA6B88ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0870841267441070ULL,
		0x0A404100600000A9ULL,
		0x0A27044003803081ULL,
		0x44A0008826062014ULL,
		0x00C3442104045122ULL,
		0x0203008008202024ULL,
		0x700004AA41458609ULL,
		0x8428220808820800ULL
	}};
	printf("Test Case 371\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 371 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -371;
	} else {
		printf("Test Case 371 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5F4650C1819CA50AULL,
		0x9250CB151060EE30ULL,
		0x5F1752C62BDFC261ULL,
		0xD0F849F6F7B7A611ULL,
		0x5FF74C9E8D5BCAA4ULL,
		0xE817F31C44072DF6ULL,
		0x2535DDC0BAE49E5AULL,
		0xA1F335F760796778ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE14B3C97E4452B70ULL,
		0x81CB8F81FD868090ULL,
		0x0B40F26FF4D0F893ULL,
		0x5063F944F8A860F1ULL,
		0x30175F99024E9228ULL,
		0x208ED93173E9DF09ULL,
		0xAE9DCA270A2E003CULL,
		0x0917A27BEC9D16CEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4142108180042100ULL,
		0x80408B0110008010ULL,
		0x0B00524620D0C001ULL,
		0x50604944F0A02011ULL,
		0x10174C98004A8220ULL,
		0x2006D11040010D00ULL,
		0x2415C8000A240018ULL,
		0x0113207360190648ULL
	}};
	printf("Test Case 372\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 372 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -372;
	} else {
		printf("Test Case 372 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8EDD053916176EE1ULL,
		0x02D6BE56F44C1AEEULL,
		0xA0145ACF78A76722ULL,
		0x199034B5F23CB867ULL,
		0x02CF312F28B2A3E7ULL,
		0xCE964A590F7E4FA5ULL,
		0x4A3AF469831DCDDBULL,
		0x7FE561C612C8EAE1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1B295C336618B452ULL,
		0xE8990068BDF497A0ULL,
		0xDA2752CCC055804EULL,
		0x04A735644373D1ACULL,
		0x63858DC5563A4B08ULL,
		0x3402955B829C7B0EULL,
		0x015558AEB8F7677AULL,
		0x30EFECDAC243C77FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0A09043106102440ULL,
		0x00900040B44412A0ULL,
		0x800452CC40050002ULL,
		0x0080342442309024ULL,
		0x0285010500320300ULL,
		0x04020059021C4B04ULL,
		0x001050288015455AULL,
		0x30E560C20240C261ULL
	}};
	printf("Test Case 373\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 373 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -373;
	} else {
		printf("Test Case 373 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0EB5F4CC5036F8E3ULL,
		0x27779BAB23749202ULL,
		0xB9D0767D7EB1EE10ULL,
		0x86D149DFE04AD02DULL,
		0x8D4D23E19D0370EFULL,
		0xD57780E59500AB49ULL,
		0xD317C870371CAAB6ULL,
		0x3D36F0EC327C5808ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBC291E440CB243E1ULL,
		0xB5AE807555F3FC65ULL,
		0x964EA2D7C205F380ULL,
		0x3F88D0BAEB3DD000ULL,
		0xA47C612885619018ULL,
		0x187CFB30F2EF5CFCULL,
		0xB7BE89AA0610DEB6ULL,
		0xA7B0B1944400DAB1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0C211444003240E1ULL,
		0x2526802101709000ULL,
		0x904022554201E200ULL,
		0x0680409AE008D000ULL,
		0x844C212085011008ULL,
		0x1074802090000848ULL,
		0x9316882006108AB6ULL,
		0x2530B08400005800ULL
	}};
	printf("Test Case 374\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 374 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -374;
	} else {
		printf("Test Case 374 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC778F43474BD3BB0ULL,
		0x2C5BD45C45D01629ULL,
		0x7F7E1FA3B18FE35EULL,
		0x01C6047225F3CF31ULL,
		0xD4E4D2FA3D680D50ULL,
		0x3ACC9BE287CFC78DULL,
		0x4BA391C358BA2263ULL,
		0x84A49EF0D6F642FAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8103320611D8CBD6ULL,
		0x4C2B7D3D04E41265ULL,
		0x095A300BF9572DE4ULL,
		0x646C3DB1BE7985EFULL,
		0xF58CA1BDD1426B3EULL,
		0x6B0EDAEA09CC2A56ULL,
		0x7CC44E8C73F1C0D3ULL,
		0xA17D5EF7B53A1C13ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8100300410980B90ULL,
		0x0C0B541C04C01221ULL,
		0x095A1003B1072144ULL,
		0x0044043024718521ULL,
		0xD48480B811400910ULL,
		0x2A0C9AE201CC0204ULL,
		0x4880008050B00043ULL,
		0x80241EF094320012ULL
	}};
	printf("Test Case 375\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 375 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -375;
	} else {
		printf("Test Case 375 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x55A3BF0C40AA739BULL,
		0x8CCE260D06B2CE21ULL,
		0x99045EDA970E3C63ULL,
		0x4EF64D5D0235803BULL,
		0xF933CE1E9CA61E2EULL,
		0xB617B5E73791AACAULL,
		0x10F6F11857809003ULL,
		0xA7ED58EDAE7C09DFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBDD676F96D654207ULL,
		0x77F06E9B13585022ULL,
		0xAFB55F0C20D8D428ULL,
		0x85A6A0145BDE39C3ULL,
		0x349562CB1923DF3CULL,
		0x798CA5DC643CEDCAULL,
		0xD4AFB183A1D0783DULL,
		0x0A2B14C51218CEBAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1582360840204203ULL,
		0x04C0260902104020ULL,
		0x89045E0800081420ULL,
		0x04A6001402140003ULL,
		0x3011420A18221E2CULL,
		0x3004A5C42410A8CAULL,
		0x10A6B10001801001ULL,
		0x022910C50218089AULL
	}};
	printf("Test Case 376\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 376 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -376;
	} else {
		printf("Test Case 376 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDD07414C687E67AEULL,
		0x12520AAAA65C185BULL,
		0x70C398F29003EDF9ULL,
		0xE6F635559117F2C7ULL,
		0xBB7119288099D37BULL,
		0x56033D7383C0E068ULL,
		0xC09DEB533F298CB9ULL,
		0xC53CD080D0561DDFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC94C2B156AF6ECB2ULL,
		0x064CC8D530C24164ULL,
		0xCED3FA531456158AULL,
		0xEDD35F9C4702C272ULL,
		0x0CB666CEE140E85FULL,
		0x838EDE400A62006DULL,
		0x30D5C6CD281A7B95ULL,
		0x4E5E1FCDFD5C23D6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC9040104687664A2ULL,
		0x0240088020400040ULL,
		0x40C3985210020588ULL,
		0xE4D215140102C242ULL,
		0x083000088000C05BULL,
		0x02021C4002400068ULL,
		0x0095C24128080891ULL,
		0x441C1080D05401D6ULL
	}};
	printf("Test Case 377\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 377 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -377;
	} else {
		printf("Test Case 377 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x82C05F6022F26E95ULL,
		0x664C144B34D17969ULL,
		0x35797D947A041B44ULL,
		0x82AFB70559D80579ULL,
		0xEAF7C84352AD1B46ULL,
		0x2C479CF1F9A120B3ULL,
		0x99DC5E4279C43033ULL,
		0x45A2C0C05D5CFD92ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4B54A61BB868CB2AULL,
		0xA313533FD1CA7F98ULL,
		0xE6BFEEDCC7E252D9ULL,
		0xD8D3B6D85DA959E8ULL,
		0xB5CEC74D9D3FDA13ULL,
		0xD6AE5E41A7B017BDULL,
		0x3E5DCBFC7D0EF82DULL,
		0xFD7AC96D01790CC5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0240060020604A00ULL,
		0x2200100B10C07908ULL,
		0x24396C9442001240ULL,
		0x8083B60059880168ULL,
		0xA0C6C041102D1A02ULL,
		0x04061C41A1A000B1ULL,
		0x185C4A4079043021ULL,
		0x4522C04001580C80ULL
	}};
	printf("Test Case 378\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 378 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -378;
	} else {
		printf("Test Case 378 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x53261ED32B05BE1CULL,
		0x175B864226F3F607ULL,
		0x9B378702AF81F60FULL,
		0x135CDA9FEFCC7338ULL,
		0xE74F3E85C387A8C2ULL,
		0x9B0682B3E94EDA6CULL,
		0x237C8332796C6E48ULL,
		0x5AE7AAE7391E4FC6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA8257739D4CC7B08ULL,
		0x2200EEA37EFD011EULL,
		0x4FDFCB62DC7911EFULL,
		0xFCE15CE152803CE2ULL,
		0xB6D487E174F8C134ULL,
		0x66D298B8AFB186A5ULL,
		0xF2646550466933B8ULL,
		0x10BF27DEE801B1B0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0024161100043A08ULL,
		0x0200860226F10006ULL,
		0x0B1783028C01100FULL,
		0x1040588142803020ULL,
		0xA644068140808000ULL,
		0x020280B0A9008224ULL,
		0x2264011040682208ULL,
		0x10A722C628000180ULL
	}};
	printf("Test Case 379\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 379 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -379;
	} else {
		printf("Test Case 379 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2F9AD95E946B7806ULL,
		0x071C9700EE4F896FULL,
		0x6C57D2A6F32A1842ULL,
		0x3A95F648837A62C0ULL,
		0x66F7F5681626F12AULL,
		0x75D2F693CDCFA73CULL,
		0xAA4C6A821C40F079ULL,
		0x7F096C687A892408ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x62705A3724D8CD5FULL,
		0x26E7C9D77374A91EULL,
		0x8DC5D8FD832FD332ULL,
		0x38035B1F41591430ULL,
		0xC9D1B5E30848CEDAULL,
		0x5CC0AABE19C06FA9ULL,
		0xE133539C779CD51CULL,
		0x430EFC0B5949E7E9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2210581604484806ULL,
		0x060481006244890EULL,
		0x0C45D0A4832A1002ULL,
		0x3801520801580000ULL,
		0x40D1B5600000C00AULL,
		0x54C0A29209C02728ULL,
		0xA00042801400D018ULL,
		0x43086C0858092408ULL
	}};
	printf("Test Case 380\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 380 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -380;
	} else {
		printf("Test Case 380 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6326D2E84520CCB4ULL,
		0x691E35EB64CFF7DFULL,
		0x453350CEB86003F4ULL,
		0x62FAB8BC647D6A32ULL,
		0x68431A9B39A4526EULL,
		0x46BBB05E748B1EB0ULL,
		0x2CAA1332C7F8DB79ULL,
		0x1E3F16B986850B96ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDBC541EB59E0132CULL,
		0xDDB0762F21BDBE9AULL,
		0x73057BAAB7694397ULL,
		0x5A0F5AF1BD6E22ADULL,
		0x708DB8EC13053294ULL,
		0x56F84AC8582403BEULL,
		0x2CEF4DD78819D773ULL,
		0x3C630789BB5919B4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x430440E841200024ULL,
		0x4910342B208DB69AULL,
		0x4101508AB0600394ULL,
		0x420A18B0246C2220ULL,
		0x6001188811041204ULL,
		0x46B80048500002B0ULL,
		0x2CAA01128018D371ULL,
		0x1C23068982010994ULL
	}};
	printf("Test Case 381\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 381 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -381;
	} else {
		printf("Test Case 381 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x48E552FED27866F3ULL,
		0xB47434D319B3F615ULL,
		0x11CC146AC525BE9FULL,
		0x2B6D6A8B3E4CB022ULL,
		0x1C60152999067F1AULL,
		0x7983474548DCC7E4ULL,
		0xD9228690EEF83B3BULL,
		0x903F225B539DD2FDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6BCCE8EA9FC5220DULL,
		0x80A848CB1652A005ULL,
		0x04867ABA248F7651ULL,
		0x77EBBE8F21C1C9F4ULL,
		0xD948C7F8B91923F7ULL,
		0x00F85EFAA6BAA714ULL,
		0xA83E84A015F4DF75ULL,
		0xEB4FDA1BB7AF782DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x48C440EA92402201ULL,
		0x802000C31012A005ULL,
		0x0084102A04053611ULL,
		0x23692A8B20408020ULL,
		0x1840052899002312ULL,
		0x0080464000988704ULL,
		0x8822848004F01B31ULL,
		0x800F021B138D502DULL
	}};
	printf("Test Case 382\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 382 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -382;
	} else {
		printf("Test Case 382 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAEBB502544F7FFF7ULL,
		0xA6FCD026151B7017ULL,
		0xA21218ECFAED8A19ULL,
		0xB98014E77AF40ED1ULL,
		0xAAD97C09C14FCEF9ULL,
		0x5167B42F7F8BFFE4ULL,
		0xBBEC9F7453D4F7BFULL,
		0x55E6C665A9FD6F96ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x60C2723149FE28BAULL,
		0x298C54E2018BE85BULL,
		0x9DA18842DF15D4D9ULL,
		0xA34770F045629B72ULL,
		0xC09C3145EC6B6A84ULL,
		0xE05763357E1E57B9ULL,
		0x696DA62E900AAFE6ULL,
		0xC15CE5BAF92A4C13ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2082502140F628B2ULL,
		0x208C5022010B6013ULL,
		0x80000840DA058019ULL,
		0xA10010E040600A50ULL,
		0x80983001C04B4A80ULL,
		0x404720257E0A57A0ULL,
		0x296C86241000A7A6ULL,
		0x4144C420A9284C12ULL
	}};
	printf("Test Case 383\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 383 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -383;
	} else {
		printf("Test Case 383 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8019356C02ED9ED2ULL,
		0x207AC5D82420FEF9ULL,
		0x04C695BC73FE16F9ULL,
		0xB46EFFA4514651F6ULL,
		0x4062399792D455ABULL,
		0x2BEE9049C2236134ULL,
		0xFA2E3569BC59313FULL,
		0x2D27745CE7136B86ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7AE2BBE8F77FFE1AULL,
		0x42421265B19C68BAULL,
		0xAD8B1F3612A80D2FULL,
		0x4FDB7DB779D43751ULL,
		0x2D3B2A89E185B213ULL,
		0x72F7D4B38B90EB43ULL,
		0x02F8AE9DF81BE1D0ULL,
		0x9B5F93915B4CDBF7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x00003168026D9E12ULL,
		0x00420040200068B8ULL,
		0x0482153412A80429ULL,
		0x044A7DA451441150ULL,
		0x0022288180841003ULL,
		0x22E6900182006100ULL,
		0x02282409B8192110ULL,
		0x0907101043004B86ULL
	}};
	printf("Test Case 384\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 384 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -384;
	} else {
		printf("Test Case 384 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7D7E7EF4EC7416E3ULL,
		0x7AB851ACEB8BC20AULL,
		0x1902D2C2B4DBDB66ULL,
		0xC80484CD5AAB1F92ULL,
		0x2377E6BB2DDA366BULL,
		0x8A62F350BE53ABCEULL,
		0x2FCCD4BBE29263DDULL,
		0xFFC0297E41909FDEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x771E7ADD0D078795ULL,
		0xCD2D1EA9356005E8ULL,
		0x7E0539F3C2515B46ULL,
		0xE823A35A5557BF01ULL,
		0xC97E5285BCA3F845ULL,
		0x691CDF1325393C4CULL,
		0xC396FB70107AF774ULL,
		0x2E0DFE7370D2949EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x751E7AD40C040681ULL,
		0x482810A821000008ULL,
		0x180010C280515B46ULL,
		0xC800804850031F00ULL,
		0x017642812C823041ULL,
		0x0800D3102411284CULL,
		0x0384D03000126354ULL,
		0x2E0028724090949EULL
	}};
	printf("Test Case 385\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 385 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -385;
	} else {
		printf("Test Case 385 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA7D4ABEEC51E2485ULL,
		0x21475595A9AB4EBBULL,
		0x12B81958FD2598B8ULL,
		0xB862E5B865708627ULL,
		0xBA67F8ED65C411F5ULL,
		0x7E15D379D18FE692ULL,
		0xEA2CFDB7287A5696ULL,
		0x30628B7A8A5465F4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4A144EC14523B67FULL,
		0xDDBEF5FC6A52D5AFULL,
		0x623DEFC090C80372ULL,
		0x36858E255CC2ADA7ULL,
		0xC07EFE63C568A07AULL,
		0x767C905E9B3EA784ULL,
		0x46A38C6BEC0B69CDULL,
		0x175A40F44E560461ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x02140AC045022405ULL,
		0x01065594280244ABULL,
		0x0238094090000030ULL,
		0x3000842044408427ULL,
		0x8066F86145400070ULL,
		0x76149058910EA680ULL,
		0x42208C23280A4084ULL,
		0x104200700A540460ULL
	}};
	printf("Test Case 386\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 386 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -386;
	} else {
		printf("Test Case 386 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD7D40246BD984936ULL,
		0x001291B24C7DB852ULL,
		0xA2EF2590FE191C99ULL,
		0x856AAF9B32FD9B75ULL,
		0xEEB274A81F4870FDULL,
		0x037C3857F57E04EAULL,
		0x3E6C809E38A14834ULL,
		0xB2AAE7393F3F56EDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4308C4B5F2D4D604ULL,
		0x20DA937233DBEE6BULL,
		0xF256563BC6F46E6EULL,
		0x61CC4E3027B4DA68ULL,
		0x38E4FD4EF86BEFABULL,
		0x9480E87CF124CFEEULL,
		0x50F0F4E0D0DA51F6ULL,
		0xD8CBD25011CD62E6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x43000004B0904004ULL,
		0x001291320059A842ULL,
		0xA2460410C6100C08ULL,
		0x01480E1022B49A60ULL,
		0x28A07408184860A9ULL,
		0x00002854F12404EAULL,
		0x1060808010804034ULL,
		0x908AC210110D42E4ULL
	}};
	printf("Test Case 387\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 387 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -387;
	} else {
		printf("Test Case 387 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFAE9A31C1191851DULL,
		0xBA9F8D2D06278C83ULL,
		0xE0A98AEF850CA43FULL,
		0xFCAD927C3C5BB2D3ULL,
		0xF0E100C65BA68432ULL,
		0xEB2BA90C2376B03DULL,
		0xDEB158EC206DA7F3ULL,
		0xE3EE98E18BCA3E70ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0A2597D255B38AE3ULL,
		0xFC7DD096D4304312ULL,
		0x2366C1B0765864D3ULL,
		0x467FECAE4E949FF6ULL,
		0x1944286333E898C0ULL,
		0xDB6EE940C088A4D5ULL,
		0xE78D724728165023ULL,
		0x9FC15A78EA01D4E6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0A21831011918001ULL,
		0xB81D800404200002ULL,
		0x202080A004082413ULL,
		0x442D802C0C1092D2ULL,
		0x1040004213A08000ULL,
		0xCB2AA9000000A015ULL,
		0xC681504420040023ULL,
		0x83C018608A001460ULL
	}};
	printf("Test Case 388\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 388 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -388;
	} else {
		printf("Test Case 388 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x99D64AE43D7817A0ULL,
		0xF18D05682CD65F6FULL,
		0xFD28714112B85DF9ULL,
		0x7D0F772CE277D95CULL,
		0xF0100880C1C9D3C7ULL,
		0xEA88C91E3C6AC3CAULL,
		0x7374D1717F4ECD2BULL,
		0x70FCC4A8DABFBCF7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8BA5DCF774814777ULL,
		0xC093AD792BBD6877ULL,
		0x9D3B3B9D80871644ULL,
		0x30CF7F793A08D266ULL,
		0xE45E6D83B66935CCULL,
		0x26EBC0DD32E75DE1ULL,
		0x4AA11BB7466006A4ULL,
		0xC5C70B13E85BC0DBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x898448E434000720ULL,
		0xC081056828944867ULL,
		0x9D28310100801440ULL,
		0x300F77282200D044ULL,
		0xE0100880804911C4ULL,
		0x2288C01C306241C0ULL,
		0x4220113146400420ULL,
		0x40C40000C81B80D3ULL
	}};
	printf("Test Case 389\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 389 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -389;
	} else {
		printf("Test Case 389 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5D889B03844D9DDEULL,
		0xDD691E89FAD9BDD1ULL,
		0xF137199281DDC3CBULL,
		0x176DB962822D42CBULL,
		0x283EB91EE63E15F5ULL,
		0xF50211F22379D861ULL,
		0xA8C88329A698403FULL,
		0x4F8165E3AB248B24ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5BD71D08292E30CFULL,
		0x5F0CA21B042B5B8BULL,
		0x7A3A0611AD9D9EABULL,
		0x8097554571673B28ULL,
		0x38C51E4438E398D3ULL,
		0xB6FFF5898764793FULL,
		0x9251F7822E74CB34ULL,
		0x001A46742929F14AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x59801900000C10CEULL,
		0x5D08020900091981ULL,
		0x70320010819D828BULL,
		0x0005114000250208ULL,
		0x28041804202210D1ULL,
		0xB402118003605821ULL,
		0x8040830026104034ULL,
		0x0000446029208100ULL
	}};
	printf("Test Case 390\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 390 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -390;
	} else {
		printf("Test Case 390 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBF700F7BFB3969B5ULL,
		0x453F1C12BD510248ULL,
		0x53D8514CB8363601ULL,
		0x4BFA0931CD7F3EE1ULL,
		0x85CFE8D0E5EECE36ULL,
		0x65008BF3E77BE67FULL,
		0xC5947E08E5B981B5ULL,
		0x2E31FB1A8E833972ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA1190710C88E8B00ULL,
		0xCCC0E477591D5ED2ULL,
		0x31D8F8555E36A5D5ULL,
		0x595442E0208B917AULL,
		0x77A7623F10253065ULL,
		0xC7282E40C876DC90ULL,
		0x9CF708A93DB0C5ADULL,
		0x93214A6E44E41732ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA1100710C8080900ULL,
		0x4400041219110240ULL,
		0x11D8504418362401ULL,
		0x49500020000B1060ULL,
		0x0587601000240024ULL,
		0x45000A40C072C410ULL,
		0x8494080825B081A5ULL,
		0x02214A0A04801132ULL
	}};
	printf("Test Case 391\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 391 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -391;
	} else {
		printf("Test Case 391 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE99E21B2466BF9D2ULL,
		0x5AD2C510F87C0060ULL,
		0xA33E3EC39914E738ULL,
		0x0BA7646DB43EC1A3ULL,
		0x679478AD9F3BEACBULL,
		0xFF280E4C2BB79028ULL,
		0x83A0BF4F65AEB284ULL,
		0xE1955AE7C2043CD6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA7043D8CE2DB5539ULL,
		0xCA9E6A363E695EA5ULL,
		0xEAF19D319BEB9D4CULL,
		0x9C5D9DA995C105BAULL,
		0x9936B6A4D5DFEECBULL,
		0xFE8D8E096CCFC39FULL,
		0x93A4874BECB23145ULL,
		0x9661F518233E8A0DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA1042180424B5110ULL,
		0x4A92401038680020ULL,
		0xA2301C0199008508ULL,
		0x08050429940001A2ULL,
		0x011430A4951BEACBULL,
		0xFE080E0828878008ULL,
		0x83A0874B64A23004ULL,
		0x8001500002040804ULL
	}};
	printf("Test Case 392\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 392 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -392;
	} else {
		printf("Test Case 392 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAF27EA4DBCA380C8ULL,
		0xB548D47D6095B43BULL,
		0x1E390AAE25D9DD46ULL,
		0x97DB8CC45F1A342DULL,
		0x799331C2865BBFF2ULL,
		0xABE322562E9DB8EAULL,
		0x7FE8BA75E5BB5FA7ULL,
		0x87AA32950965F3DCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x96A13A6666C98837ULL,
		0xAFE9CC5A42AB963AULL,
		0xAE07682CAA69AFD3ULL,
		0x7BB8DBB9A203B3AFULL,
		0x9670F84F27E7526FULL,
		0x074D6A4236AA38F2ULL,
		0xAFE250715DF5FF52ULL,
		0xA7EB4A13FAEA51A2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x86212A4424818000ULL,
		0xA548C4584081943AULL,
		0x0E01082C20498D42ULL,
		0x139888800202302DULL,
		0x1010304206431262ULL,
		0x03412242268838E2ULL,
		0x2FE0107145B15F02ULL,
		0x87AA021108605180ULL
	}};
	printf("Test Case 393\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 393 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -393;
	} else {
		printf("Test Case 393 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x30965E54BDF67B99ULL,
		0x972517101EFD84DBULL,
		0xC027AAAA5DCDE72BULL,
		0x741E63F19F7F588CULL,
		0xC84324398C09F2BBULL,
		0x95A1A4175CA05BF7ULL,
		0x08F7C7594C4BEA3DULL,
		0x5E9AC735241DB4FAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x22CA277E64988C56ULL,
		0x59BC76008C7557ABULL,
		0xA8831ADB18AD1A2BULL,
		0x3597867A75E1A4FDULL,
		0x9C39CF7D97EBB93CULL,
		0xAB380550479E794CULL,
		0xF99687A18452AE7FULL,
		0x93A39BB1D94B25EBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2082065424900810ULL,
		0x112416000C75048BULL,
		0x80030A8A188D022BULL,
		0x341602701561008CULL,
		0x880104398409B038ULL,
		0x8120041044805944ULL,
		0x089687010442AA3DULL,
		0x12828331000924EAULL
	}};
	printf("Test Case 394\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 394 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -394;
	} else {
		printf("Test Case 394 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x552DFA391AB07ED3ULL,
		0x30019DA8211176FDULL,
		0x34BABC15A9D19BBCULL,
		0x0576F21640D98969ULL,
		0x1E3952508138E964ULL,
		0x5CA2976D231D388DULL,
		0xA0E9287DC621BDA1ULL,
		0xAE84F9D125BD09FDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1697EAE84954646EULL,
		0x2886F17EEDDB013AULL,
		0x7EE85136B54655CEULL,
		0x56D811B0B93303FCULL,
		0xBA3538C98B0B0702ULL,
		0x66689791EB09C60BULL,
		0xBA296E14F89E03C7ULL,
		0xF3FB9FF75D52E08DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1405EA2808106442ULL,
		0x2000912821110038ULL,
		0x34A81014A140118CULL,
		0x0450101000110168ULL,
		0x1A31104081080100ULL,
		0x4420970123090009ULL,
		0xA0292814C0000181ULL,
		0xA28099D10510008DULL
	}};
	printf("Test Case 395\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 395 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -395;
	} else {
		printf("Test Case 395 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7F88E6FE705ACF3DULL,
		0x6F6368A984781CE5ULL,
		0x7BBE102F8B34EC6CULL,
		0x9F091A66217CD9E3ULL,
		0x9170AEBF8401A17CULL,
		0x9E29DC5B4211BDBDULL,
		0x99CE57F47448168BULL,
		0x73C7BC9158DB8A24ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE9A8D9D43DE18DDBULL,
		0x2E813C02691AC84EULL,
		0x9A695A8ABF1C2338ULL,
		0x8D714C9EC6C547D1ULL,
		0xECE4A39162B6E284ULL,
		0xBD165F23B0B70297ULL,
		0x45A1F11C82B811C9ULL,
		0x39F24387A224C0C9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6988C0D430408D19ULL,
		0x2E01280000180844ULL,
		0x1A28100A8B142028ULL,
		0x8D010806004441C1ULL,
		0x8060A2910000A004ULL,
		0x9C005C0300110095ULL,
		0x0180511400081089ULL,
		0x31C2008100008000ULL
	}};
	printf("Test Case 396\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 396 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -396;
	} else {
		printf("Test Case 396 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1FA58E8E964471ADULL,
		0x341C690CE89A3567ULL,
		0x050352378532101EULL,
		0x3614A7FEF8209DAFULL,
		0xB52E867890946BCBULL,
		0x5CC7474222EF16DAULL,
		0x9DF5F9C2D7CD8AD7ULL,
		0x7C616DD54FE32DE7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF041129366112E3EULL,
		0xA9054367AB06FB67ULL,
		0x9D9E15A1540B961AULL,
		0xC77F8FEC961DE741ULL,
		0x2F4E6246D98CEA03ULL,
		0xD043A55AFF2CF95BULL,
		0x7BD1223042BBC4C8ULL,
		0x66E332C08B312F67ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x100102820600202CULL,
		0x20044104A8023167ULL,
		0x050210210402101AULL,
		0x061487EC90008501ULL,
		0x250E024090846A03ULL,
		0x50430542222C105AULL,
		0x19D12000428980C0ULL,
		0x646120C00B212D67ULL
	}};
	printf("Test Case 397\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 397 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -397;
	} else {
		printf("Test Case 397 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x43B963D271AAA49BULL,
		0xB24822398DF2517AULL,
		0x54EFBFE68F5C4140ULL,
		0xBF89490962CFEC98ULL,
		0x9FB9013806C03C95ULL,
		0x2B98D79C054757EBULL,
		0x63A945C6D28927F4ULL,
		0x243E7EFA5751D0BEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2324A10651568FFCULL,
		0x8982F93D8509751EULL,
		0xB18150505843B861ULL,
		0x3B075848CC5C9B74ULL,
		0x1AC1C237852DD60AULL,
		0x67DF3152D5332F40ULL,
		0x334182DD0B1A61A6ULL,
		0x2A0F1ED6BFBCFBCAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0320210251028498ULL,
		0x800020398500511AULL,
		0x1081104008400040ULL,
		0x3B014808404C8810ULL,
		0x1A81003004001400ULL,
		0x2398111005030740ULL,
		0x230100C4020821A4ULL,
		0x200E1ED21710D08AULL
	}};
	printf("Test Case 398\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 398 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -398;
	} else {
		printf("Test Case 398 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3DB88E758064385CULL,
		0x10ECB60266D6F98BULL,
		0xAEE1C42F58EEE4E4ULL,
		0x6712B63CED01D801ULL,
		0x83DC6ABFAE737DBAULL,
		0x9ED0A66933F0BEB7ULL,
		0x2AA139B5E19C258BULL,
		0xC904722040DBEC08ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x71BEF4466B76156FULL,
		0xFE61B51A3B5A36F7ULL,
		0x449EB1DE21F1B428ULL,
		0x1928CF6D285062FAULL,
		0x2BD7D1D8CB157662ULL,
		0x7ADFC6FFD567A3D4ULL,
		0xCBF95F874D1487E4ULL,
		0x37F65DE0D4FE8089ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x31B884440064104CULL,
		0x1060B40222523083ULL,
		0x0480800E00E0A420ULL,
		0x0100862C28004000ULL,
		0x03D440988A117422ULL,
		0x1AD086691160A294ULL,
		0x0AA1198541140580ULL,
		0x0104502040DA8008ULL
	}};
	printf("Test Case 399\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 399 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -399;
	} else {
		printf("Test Case 399 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x875B7C7CCF736CA2ULL,
		0x99A82C36F574C123ULL,
		0xA2EFCA5FEC59B31DULL,
		0x01605745E61BDAAFULL,
		0x21C44B36A20B76E0ULL,
		0x8C5410852D774861ULL,
		0xC5FAE367EAA4D4E7ULL,
		0xE92C4F7C09EE4CB1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5416FFBF5CD1FFEBULL,
		0xA25503AF0E9E6E0EULL,
		0xDE9C61E1AE472157ULL,
		0xE0F0B2B63AEB6CD2ULL,
		0x922D8FA4A5513F35ULL,
		0x1F4028C594E699DFULL,
		0x3DBF82ECF83C3E99ULL,
		0xF19F56ABE99F94EDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x04127C3C4C516CA2ULL,
		0x8000002604144002ULL,
		0x828C4041AC412115ULL,
		0x00601204220B4882ULL,
		0x00040B24A0013620ULL,
		0x0C40008504660841ULL,
		0x05BA8264E8241481ULL,
		0xE10C4628098E04A1ULL
	}};
	printf("Test Case 400\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 400 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -400;
	} else {
		printf("Test Case 400 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBF3986EC14CB54FFULL,
		0x9ED6207E4FE4F538ULL,
		0x1422285EC1CB7C3FULL,
		0x6BC5918A9A637BB1ULL,
		0x80001848AA28738EULL,
		0x06B782A7B63D2142ULL,
		0xC9D368D3469D9DF8ULL,
		0x6E7EF2C64836137AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x05F7ADB54F6BB254ULL,
		0x3855290E554C6DEEULL,
		0xFF5D58F978381D8EULL,
		0xA9E06E1537891CECULL,
		0x504446F4F0A7298AULL,
		0x5C215F857CD551F8ULL,
		0x7E2490AFDBAB67BCULL,
		0x238D78762AA2B31CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x053184A4044B1054ULL,
		0x1854200E45446528ULL,
		0x1400085840081C0EULL,
		0x29C00000120118A0ULL,
		0x00000040A020218AULL,
		0x0421028534150140ULL,
		0x48000083428905B8ULL,
		0x220C704608221318ULL
	}};
	printf("Test Case 401\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 401 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -401;
	} else {
		printf("Test Case 401 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8271F0E4465CF51FULL,
		0xC2BE7EA0285A4C36ULL,
		0xC5F8CE05440F5235ULL,
		0xFCEC9122BD491200ULL,
		0xC15AC2D4635EB9B9ULL,
		0x88F08612A6B611CDULL,
		0xABB4148D697AC45EULL,
		0x4F0F8D467F855FC0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA72332FB65D1317FULL,
		0x7F729B3646E4FB45ULL,
		0x363FF3BC0216EFFCULL,
		0x30B4762E15B237F9ULL,
		0x5C0FCB30046E3C41ULL,
		0xFC0EEEAFD51129B0ULL,
		0xBD50FC607515C74FULL,
		0xDCCA06F0D6B14260ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x822130E04450311FULL,
		0x42321A2000404804ULL,
		0x0438C20400064234ULL,
		0x30A4102215001200ULL,
		0x400AC210004E3801ULL,
		0x8800860284100180ULL,
		0xA91014006110C44EULL,
		0x4C0A044056814240ULL
	}};
	printf("Test Case 402\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 402 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -402;
	} else {
		printf("Test Case 402 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x87310E49FD55BFC2ULL,
		0x21E56FDCDD906E24ULL,
		0x34237D6625ADBA2BULL,
		0xCEE4305780DD025FULL,
		0x333B21A472B84A5FULL,
		0xB19790EB4BB0CAD8ULL,
		0x579760F90B66BE09ULL,
		0x90930D807A0903ACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE8DF819D7682BE12ULL,
		0x96DDA39762A67AE3ULL,
		0x0CD76F6797DD5806ULL,
		0x60BCBC969AFCA0CBULL,
		0xFEE6594E92B30DBBULL,
		0x141F8D3366CFC2E1ULL,
		0x99EEB160AD01CE99ULL,
		0xF8096A8E130AAE6EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x801100097400BE02ULL,
		0x00C5239440806A20ULL,
		0x04036D66058D1802ULL,
		0x40A4301680DC004BULL,
		0x3222010412B0081BULL,
		0x101780234280C2C0ULL,
		0x1186206009008E09ULL,
		0x900108801208022CULL
	}};
	printf("Test Case 403\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 403 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -403;
	} else {
		printf("Test Case 403 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF2DFE3D930E33FADULL,
		0x12A4C05E2AE18E30ULL,
		0x2E73594F8BED24B6ULL,
		0x07013C622EEC3D99ULL,
		0x202453F461778A09ULL,
		0x075ED4528E9C6C5BULL,
		0xEF720A2F17BF0444ULL,
		0x7E171E97DA1E389EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3CACF540E1254BAAULL,
		0x845F2CCC88F0E2B9ULL,
		0x1E42CBE30097B12EULL,
		0x46EE3C246581CF69ULL,
		0xEC47FA338ADEFEC2ULL,
		0xD24BB90EBDC689A6ULL,
		0x6BB2F72155924355ULL,
		0x613AEE0B6CD2A0B9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x308CE14020210BA8ULL,
		0x0004004C08E08230ULL,
		0x0E42494300852026ULL,
		0x06003C2024800D09ULL,
		0x2004523000568A00ULL,
		0x024A90028C840802ULL,
		0x6B32022115920044ULL,
		0x60120E0348122098ULL
	}};
	printf("Test Case 404\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 404 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -404;
	} else {
		printf("Test Case 404 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2A20FA32FC8A74EBULL,
		0x1D7BAB8FF40FF80AULL,
		0xF1FE8E537DFFE3FAULL,
		0xD23B11A6D1287781ULL,
		0xDC13192EA0BC861FULL,
		0x5792DCBDB2327DCDULL,
		0x056BEE7CE67AEA8BULL,
		0x7761A1A6E705B70AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4730728EA237106CULL,
		0x9AC832A330A97174ULL,
		0xB3589EBE9307FE75ULL,
		0x500D4A79D8AE35EFULL,
		0x690F471819985925ULL,
		0x7B2D32878D02AEB7ULL,
		0xBB116F38D9E2DC61ULL,
		0x3FE90788BF99C93BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x02207202A0021068ULL,
		0x1848228330097000ULL,
		0xB1588E121107E270ULL,
		0x50090020D0283581ULL,
		0x4803010800980005ULL,
		0x5300108580022C85ULL,
		0x01016E38C062C801ULL,
		0x37610180A701810AULL
	}};
	printf("Test Case 405\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 405 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -405;
	} else {
		printf("Test Case 405 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x94EC2F0A32CF68D5ULL,
		0xC49FBF8B8504509DULL,
		0x0178B8EB0650DFA1ULL,
		0xF6E51ABFC428F6B8ULL,
		0x30F10A51016995F3ULL,
		0xD58FDBE23226B5D1ULL,
		0x3F66CB68E1D03954ULL,
		0x6B4420158B321C49ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2B49874390B09561ULL,
		0xC3B01E584547A122ULL,
		0x0E7C80DB6F84C8D4ULL,
		0x8514CF46F756E077ULL,
		0x3E4036E4F8CB2D00ULL,
		0xC450D3BD6B333AE6ULL,
		0x46B5B6783C4D27B5ULL,
		0xAC68C6A3FCCB133AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0048070210800041ULL,
		0xC0901E0805040000ULL,
		0x007880CB0600C880ULL,
		0x84040A06C400E030ULL,
		0x3040024000490500ULL,
		0xC400D3A0222230C0ULL,
		0x0624826820402114ULL,
		0x2840000188021008ULL
	}};
	printf("Test Case 406\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 406 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -406;
	} else {
		printf("Test Case 406 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEE11AF75888FCDE8ULL,
		0x9077004A5E385B31ULL,
		0xC1B7E491DF0CA3F7ULL,
		0xDE67CE43640608BCULL,
		0x73D0CFCE5DF8F1E1ULL,
		0xB8CE32B1CF80821AULL,
		0xC63311F39EB92187ULL,
		0x35C78A8A1E560BFDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x518009E6E5429953ULL,
		0x747AEA7F702C0D30ULL,
		0xF530DF47F0431E88ULL,
		0xDB5061BFBC7CA74EULL,
		0x9555F6041E042771ULL,
		0xAEEA4766D323D368ULL,
		0xAE666CF736F0947AULL,
		0x9EB17C7488CC8CE2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4000096480028940ULL,
		0x1072004A50280930ULL,
		0xC130C401D0000280ULL,
		0xDA4040032404000CULL,
		0x1150C6041C002161ULL,
		0xA8CA0220C3008208ULL,
		0x862200F316B00002ULL,
		0x14810800084408E0ULL
	}};
	printf("Test Case 407\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 407 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -407;
	} else {
		printf("Test Case 407 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9ADAB6B3EE4EDD34ULL,
		0xB07BE57874BBC066ULL,
		0x62D88C9E3BB76E72ULL,
		0x37C4D268AFD06BAEULL,
		0xA662230AC0C606FEULL,
		0x506FBCC5F5A49D1FULL,
		0xEED90C8197E5D163ULL,
		0x6EC9735B89E2AAFFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE81ED094DB8E5E4CULL,
		0x3D70F7B97FE20AE4ULL,
		0xAB78278AE9219145ULL,
		0x5C5E7D441711AF28ULL,
		0xCAA5A48667F390D9ULL,
		0x9384643E0F3E8635ULL,
		0xE6BB730664629162ULL,
		0x78ACD796F2001D86ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x881A9090CA0E5C04ULL,
		0x3070E53874A20064ULL,
		0x2258048A29210040ULL,
		0x1444504007102B28ULL,
		0x8220200240C200D8ULL,
		0x1004240405248415ULL,
		0xE699000004609162ULL,
		0x6888531280000886ULL
	}};
	printf("Test Case 408\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 408 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -408;
	} else {
		printf("Test Case 408 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x49C7EBC01C1EA7E7ULL,
		0x79198DF5AF7BE0A5ULL,
		0xBE553EC76D9584FDULL,
		0x447CCB8284965346ULL,
		0x7631093B2472F92DULL,
		0x4DF421C4F8E5D81AULL,
		0xC608E5C4865D325AULL,
		0x6A570BB33ED92E29ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7A90E6F648425200ULL,
		0xDB32821904DD5F9BULL,
		0xD4EA7EE62D55D749ULL,
		0x485022997DC24986ULL,
		0xABC428B2770B0B70ULL,
		0x018B98FD57CB5528ULL,
		0xB68A38E0CE820A97ULL,
		0x3D31E9043F1190E0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4880E2C008020200ULL,
		0x5910801104594081ULL,
		0x94403EC62D158449ULL,
		0x4050028004824106ULL,
		0x2200083224020920ULL,
		0x018000C450C15008ULL,
		0x860820C086000212ULL,
		0x281109003E110020ULL
	}};
	printf("Test Case 409\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 409 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -409;
	} else {
		printf("Test Case 409 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAB812565791415CFULL,
		0x211DF67F7FC7D596ULL,
		0x90BF9297D65CC6D4ULL,
		0xCA8B871E503E911AULL,
		0x6593FBB6B35CE9C3ULL,
		0x0D05E8ED5564F72CULL,
		0xDC8187DDA4F17D14ULL,
		0xB52993AEEB46B9E6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5AA6D809BCD996F0ULL,
		0x93855F1C5B9BCCACULL,
		0x1D795B02B657D862ULL,
		0x018B77755FCBCDF5ULL,
		0x5ADB3752BEEAEFF9ULL,
		0x08BE36DC0070E13CULL,
		0x38786CA5A72711C8ULL,
		0x27BCD867B5DDADC1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0A800001381014C0ULL,
		0x0105561C5B83C484ULL,
		0x103912029654C040ULL,
		0x008B0714500A8110ULL,
		0x40933312B248E9C1ULL,
		0x080420CC0060E12CULL,
		0x18000485A4211100ULL,
		0x25289026A144A9C0ULL
	}};
	printf("Test Case 410\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 410 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -410;
	} else {
		printf("Test Case 410 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4124CEA612B284D5ULL,
		0x5B5C686EB40863EDULL,
		0x6A9DD3CA605395ABULL,
		0xC7F6B486D7AC034FULL,
		0xD74475F5714784E9ULL,
		0xCC22013510EF56DCULL,
		0x7CBE73163E7F73E1ULL,
		0x3238E90181A56B3FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4DE8EAD51B85BAF1ULL,
		0xEF1D8093A7FF283FULL,
		0x5F64880A6DB2EB01ULL,
		0x3CA939E376B2577CULL,
		0x144EDA71DD909BB3ULL,
		0x375D08DCFF94BE70ULL,
		0x16939098A6433BE8ULL,
		0x1E04A6B7557EDC4BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4120CA84128080D1ULL,
		0x4B1C0002A408202DULL,
		0x4A04800A60128101ULL,
		0x04A0308256A0034CULL,
		0x14445071510080A1ULL,
		0x0400001410841650ULL,
		0x14921010264333E0ULL,
		0x1200A0010124480BULL
	}};
	printf("Test Case 411\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 411 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -411;
	} else {
		printf("Test Case 411 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x52AB6A7808BE01CDULL,
		0xE2371656B8542511ULL,
		0xBB9F4B0B08C6B544ULL,
		0xDC009E1264959062ULL,
		0x0E5B504265EDFB63ULL,
		0x1C7F945BA9BA6A5AULL,
		0x06EAF453D40EF731ULL,
		0x8FB15F09CAAA33B3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x26BF81A209E6B9D4ULL,
		0xCE70382C3931722CULL,
		0x6ACC2ED8D7B14D77ULL,
		0xCB813E66AAC3A6B8ULL,
		0x114E7A38306A4021ULL,
		0x28FDF6583D982982ULL,
		0x8836C331472D8ADEULL,
		0x3018BAD46BBA9794ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x02AB002008A601C4ULL,
		0xC230100438102000ULL,
		0x2A8C0A0800800544ULL,
		0xC8001E0220818020ULL,
		0x004A500020684021ULL,
		0x087D945829982802ULL,
		0x0022C011440C8210ULL,
		0x00101A004AAA1390ULL
	}};
	printf("Test Case 412\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 412 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -412;
	} else {
		printf("Test Case 412 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB4C7F9ED4A32AD17ULL,
		0x5CCBC1B0101D97A5ULL,
		0x30F6D9B66156FAF2ULL,
		0x1FDBC4C1FBB97260ULL,
		0x3CF1862273169E59ULL,
		0x5E6F8AAC4D7DC5D1ULL,
		0xA3C5E22559B26D85ULL,
		0x26821BF20D55D129ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x03F27382463E150FULL,
		0x02FD8897F4F28AD4ULL,
		0x52A9BAF9210F950AULL,
		0x489C658E3D50231BULL,
		0x29EE313F7FCD3FE3ULL,
		0x4A9A418AD82EB03EULL,
		0xB6AD5B766B1D4D48ULL,
		0xE62D0795EDC1B550ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x00C2718042320507ULL,
		0x00C9809010108284ULL,
		0x10A098B021069002ULL,
		0x0898448039102200ULL,
		0x28E0002273041E41ULL,
		0x4A0A0088482C8010ULL,
		0xA285422449104D00ULL,
		0x260003900D419100ULL
	}};
	printf("Test Case 413\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 413 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -413;
	} else {
		printf("Test Case 413 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE59C82B48FF43787ULL,
		0xBE449B13AE601A9FULL,
		0xCFC3E2CD6DBC0B23ULL,
		0x23BDB671A94BAE4AULL,
		0xB4A4D548DCCD2B36ULL,
		0x9BBC2A4C73849774ULL,
		0xFC1E9E283988F0BAULL,
		0xC5AE36BD11A1B306ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7E7775A0A44C771CULL,
		0xD2B23C4BE640CBF6ULL,
		0x10A8793758B6EABFULL,
		0x7E32C448D021CA0CULL,
		0x6DBA1B9AEFDED3DAULL,
		0x7B26D06D0327F389ULL,
		0x2A169CA55B78746CULL,
		0x9C16A91E269C1043ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x641400A084443704ULL,
		0x92001803A6400A96ULL,
		0x0080600548B40A23ULL,
		0x2230844080018A08ULL,
		0x24A01108CCCC0312ULL,
		0x1B24004C03049300ULL,
		0x28169C2019087028ULL,
		0x8406201C00801002ULL
	}};
	printf("Test Case 414\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 414 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -414;
	} else {
		printf("Test Case 414 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEEAA195DD486F4A9ULL,
		0xA91AF56EBF157C72ULL,
		0x159C22F7C91A714CULL,
		0x76154AB3F3C9235EULL,
		0x20D17303B4C3233AULL,
		0x8E3B73B1A8154710ULL,
		0x54064F92008C5A37ULL,
		0x4C20E6C7522A0D90ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2BB8C05415B5DE9DULL,
		0x2299DA507BFCB3EEULL,
		0x9F5137160F73DE2FULL,
		0x220C7EB0CDCF3C44ULL,
		0x1A2716B9EC826BC5ULL,
		0x3DF1C7D50EC31502ULL,
		0x70B5535E45242B2CULL,
		0x8245B43307505C72ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2AA800541484D489ULL,
		0x2018D0403B143062ULL,
		0x151022160912500CULL,
		0x22044AB0C1C92044ULL,
		0x00011201A4822300ULL,
		0x0C31439108010500ULL,
		0x5004431200040A24ULL,
		0x0000A40302000C10ULL
	}};
	printf("Test Case 415\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 415 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -415;
	} else {
		printf("Test Case 415 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x53355CCFC7BDB251ULL,
		0x6668778CA90BC5E7ULL,
		0x339EB1E54BE55140ULL,
		0x4164DA9534548C8EULL,
		0x853BE8F077AABDA5ULL,
		0xFDE07B734F2EE8E5ULL,
		0xC75A669C84D4D8B8ULL,
		0xF5FDDCE529F342F8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x61064E3EA3A141DDULL,
		0xEE1F37BE508EC289ULL,
		0xC684771EB843D770ULL,
		0x4A7C90F40546DC79ULL,
		0x48B826E1248B7BA7ULL,
		0xA6CEA993EDFF9F0BULL,
		0x96720AC0B269CC46ULL,
		0x386915395215F175ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x41044C0E83A10051ULL,
		0x6608378C000AC081ULL,
		0x0284310408415140ULL,
		0x4064909404448C08ULL,
		0x003820E0248A39A5ULL,
		0xA4C029134D2E8801ULL,
		0x865202808040C800ULL,
		0x3069142100114070ULL
	}};
	printf("Test Case 416\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 416 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -416;
	} else {
		printf("Test Case 416 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x35CC464D43C89231ULL,
		0xB6BDA3A9297FC44DULL,
		0x8517EE880A20F0A7ULL,
		0xDE3767B724C3D198ULL,
		0xD03B231A3BAFC9D9ULL,
		0x8CF0159BA7DDD127ULL,
		0x9809DF2B25D7918CULL,
		0xB335ED940AFA20AEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1DF9698380406473ULL,
		0x5C9D4F23EC678A68ULL,
		0xA414219A315E02D9ULL,
		0xF2B36BC0C939E206ULL,
		0x4F844E3B7C4F30EDULL,
		0xB9E33210D2AEA4C8ULL,
		0xFE37B1D167830ADBULL,
		0x6A0E2716BB147C8CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x15C8400100400031ULL,
		0x149D032128678048ULL,
		0x8414208800000081ULL,
		0xD23363800001C000ULL,
		0x4000021A380F00C9ULL,
		0x88E01010828C8000ULL,
		0x9801910125830088ULL,
		0x220425140A10208CULL
	}};
	printf("Test Case 417\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 417 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -417;
	} else {
		printf("Test Case 417 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEC4C048BA23E9A5AULL,
		0xD5BA8B261FD2CE92ULL,
		0x38CBF965386DB7A5ULL,
		0x6D7AC848C067E5A4ULL,
		0x41217FA3493BEDE9ULL,
		0x445AE01E38B21645ULL,
		0x628FDC5FA4485A39ULL,
		0x1EC193E52C275317ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x84ACC2ABB989B35FULL,
		0x9BB82318227A984DULL,
		0x1FC05299E5CF72D7ULL,
		0x80CDA7846C028BA8ULL,
		0xB83A0D3B95988F91ULL,
		0xD665EEB8E653CFBAULL,
		0x530666CBD694C340ULL,
		0xCD919F0CB640E5A2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x840C008BA008925AULL,
		0x91B8030002528800ULL,
		0x18C05001204D3285ULL,
		0x00488000400281A0ULL,
		0x00200D2301188D81ULL,
		0x4440E01820120600ULL,
		0x4206444B84004200ULL,
		0x0C81930424004102ULL
	}};
	printf("Test Case 418\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 418 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -418;
	} else {
		printf("Test Case 418 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA9DE027AF7EEF493ULL,
		0x0969CA921AF99700ULL,
		0x8480F29AA6681B74ULL,
		0xEA3D26691FC8247AULL,
		0x36389B86B1481821ULL,
		0xD26F9493A8DD7F01ULL,
		0x6E186CE9F33E70AEULL,
		0xD9680657C701AFCAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF3675E7F0D32E5B9ULL,
		0x932FAEEAB1FD95FDULL,
		0xCD0B03BFE64979EDULL,
		0xA3F9329DEBCD7F8DULL,
		0x667AAC41D76751D1ULL,
		0x6EDCE462A09F5969ULL,
		0xD812D24CF41F0E20ULL,
		0xFF12457E9FB15999ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA146027A0522E491ULL,
		0x01298A8210F99500ULL,
		0x8400029AA6481964ULL,
		0xA23922090BC82408ULL,
		0x2638880091401001ULL,
		0x424C8402A09D5901ULL,
		0x48104048F01E0020ULL,
		0xD900045687010988ULL
	}};
	printf("Test Case 419\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 419 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -419;
	} else {
		printf("Test Case 419 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3BD028532FF3B31DULL,
		0x2B75D4EC9C7C48D0ULL,
		0xF667D24642D8FEC9ULL,
		0xAFEE7A2CD67E5391ULL,
		0x8F8EDDD7549B7CFAULL,
		0x64E26B2615F361C8ULL,
		0x626839D1AA73F0CAULL,
		0xD0F9633861030111ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8120445DEFA4B865ULL,
		0x12CF421C7B968ADBULL,
		0xE7DE9D8210B3E130ULL,
		0xBF970A6774FEF923ULL,
		0x43FA7EDEAA3C5DB1ULL,
		0xD1FCE7806B27EC65ULL,
		0x2F7725DA58F489EAULL,
		0xE379DE16A694AF2CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x010000512FA0B005ULL,
		0x0245400C181408D0ULL,
		0xE64690020090E000ULL,
		0xAF860A24547E5101ULL,
		0x038A5CD600185CB0ULL,
		0x40E0630001236040ULL,
		0x226021D0087080CAULL,
		0xC079421020000100ULL
	}};
	printf("Test Case 420\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 420 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -420;
	} else {
		printf("Test Case 420 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1E50B8AA0F534624ULL,
		0x7B47BE22005BC945ULL,
		0x94E5DD3988FCB6B2ULL,
		0x600FCA5EE5B59699ULL,
		0xCA1A00B8C04F0455ULL,
		0x0FC5E2DF7701D311ULL,
		0xD94A8C1D974A06E9ULL,
		0x44A6BDB5C54F80FAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFF8B76D5CC85B37BULL,
		0xF19E8E73F7323CDDULL,
		0x4BAA2AA5027ABC97ULL,
		0x276F2937CF659D3BULL,
		0x39672124ECC51FEDULL,
		0xDED9B09B9BB473F7ULL,
		0x517ABA07C2FDE232ULL,
		0x8B5521EBF6BDE840ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1E0030800C010220ULL,
		0x71068E2200120845ULL,
		0x00A008210078B492ULL,
		0x200F0816C5259419ULL,
		0x08020020C0450445ULL,
		0x0EC1A09B13005311ULL,
		0x514A880582480220ULL,
		0x000421A1C40D8040ULL
	}};
	printf("Test Case 421\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 421 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -421;
	} else {
		printf("Test Case 421 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAA7EAE4C5A5961EFULL,
		0x6023D27C2C7FFFF1ULL,
		0xE96975E72D53FA7AULL,
		0xB8E3271FAF02E929ULL,
		0x86768D4B2B75EF94ULL,
		0x63AC2E2D940CA6AAULL,
		0x9EF3550622D38250ULL,
		0x03F44A2B00A63877ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFD6F8FA8542A4C52ULL,
		0x62434AC0DD7CED4BULL,
		0x910DD52F24706211ULL,
		0x7A1BF44D6B9AB067ULL,
		0x45BFAA0BDC913C9AULL,
		0xD330DB08E514B0B1ULL,
		0x2B130E284971FDE2ULL,
		0xBC2EFD7E4A0327FBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA86E8E0850084042ULL,
		0x600342400C7CED41ULL,
		0x8109552724506210ULL,
		0x3803240D2B02A021ULL,
		0x0436880B08112C90ULL,
		0x43200A088404A0A0ULL,
		0x0A13040000518040ULL,
		0x0024482A00022073ULL
	}};
	printf("Test Case 422\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 422 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -422;
	} else {
		printf("Test Case 422 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x26DB75B555973A0AULL,
		0xF86D5F1D2694835EULL,
		0xC1CF54A55388FE49ULL,
		0xA96398AA8C321306ULL,
		0x69CD22C1E7877F11ULL,
		0xC236366EB35BFA49ULL,
		0xDA30B1F4FF30D93FULL,
		0x4E97E3EB7A5A0492ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3D93A5A495CEC40EULL,
		0x3C46D44231FA925FULL,
		0xE62729FB905C1A88ULL,
		0x2BC2FAF3D4EDCF53ULL,
		0xA927AD9FC33ED387ULL,
		0x1BB4BC7DC6D54D15ULL,
		0x01668761E77A9C61ULL,
		0xE783380DBE096BABULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x249325A41586000AULL,
		0x384454002090825EULL,
		0xC00700A110081A08ULL,
		0x294298A284200302ULL,
		0x29052081C3065301ULL,
		0x0234346C82514801ULL,
		0x00208160E7309821ULL,
		0x468320093A080082ULL
	}};
	printf("Test Case 423\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 423 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -423;
	} else {
		printf("Test Case 423 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7CE34E839B464C78ULL,
		0x13E4EB3657A8DCE4ULL,
		0x7608CD9D4D94D7EBULL,
		0xF9774A41F82DE302ULL,
		0x077A4A94EA538801ULL,
		0xFD7D2A7C2D1A2DFBULL,
		0xFB3FDA997BEEFB00ULL,
		0x4BBF2AFB965B8C1AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB8C25BADB8CA568FULL,
		0x222CB3EABC062C70ULL,
		0xAF83EBB4C130DBEEULL,
		0x15B185B3D808B492ULL,
		0x143758EC3A404CD3ULL,
		0xEDD71841E3DC7F77ULL,
		0x02F19233A4C2CAF9ULL,
		0x9CA5656B5034CBDAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x38C24A8198424408ULL,
		0x0224A32214000C60ULL,
		0x2600C9944110D3EAULL,
		0x11310001D808A002ULL,
		0x043248842A400801ULL,
		0xED55084021182D73ULL,
		0x0231921120C2CA00ULL,
		0x08A5206B1010881AULL
	}};
	printf("Test Case 424\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 424 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -424;
	} else {
		printf("Test Case 424 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2F8867CD29FFE502ULL,
		0x293278C371760F80ULL,
		0xB2AB406798578DF0ULL,
		0x8DE3C5A7DE7DEF23ULL,
		0xC1BE2BA0738231DAULL,
		0x55FB6EDC69789B27ULL,
		0xE26BC6DDCF1B549AULL,
		0x02690D4BC0E05989ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7417DDBCC47009F1ULL,
		0x87192BE8A91D5044ULL,
		0x58BD5CEC091FB0DDULL,
		0xFCEC2342A7142B79ULL,
		0xEA2877C75CA1F837ULL,
		0x29EF3D555E07B27FULL,
		0x02FE3DDACC8AAB46ULL,
		0xC76A3B905F6B35D0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2400458C00700100ULL,
		0x011028C021140000ULL,
		0x10A94064081780D0ULL,
		0x8CE0010286142B21ULL,
		0xC028238050803012ULL,
		0x01EB2C5448009227ULL,
		0x026A04D8CC0A0002ULL,
		0x0268090040601180ULL
	}};
	printf("Test Case 425\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 425 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -425;
	} else {
		printf("Test Case 425 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x47173D0E27A4F96BULL,
		0x0D961B9E357E9B6DULL,
		0x6F0F59652F5EE631ULL,
		0xD45617ABD389ABEBULL,
		0x2599B27BA8A7B829ULL,
		0x9D827B896D92ABDFULL,
		0x8C32E03EE267283BULL,
		0x2E3C35823A459405ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x94F545E10714A092ULL,
		0xA399890946868647ULL,
		0xF153C048A3AE487AULL,
		0x6F7FF866374DDAD6ULL,
		0x85C6953BE908FAEBULL,
		0x67B403F841FBF195ULL,
		0x343E62753A21C3E1ULL,
		0x5A4E5575A2649D38ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x041505000704A002ULL,
		0x0190090804068245ULL,
		0x61034040230E4030ULL,
		0x4456102213098AC2ULL,
		0x0580903BA800B829ULL,
		0x058003884192A195ULL,
		0x0432603422210021ULL,
		0x0A0C150022449400ULL
	}};
	printf("Test Case 426\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 426 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -426;
	} else {
		printf("Test Case 426 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7D64D03887A9AAE1ULL,
		0xDC6E3AB6E38741ABULL,
		0x24E3C3D6E2BF9A84ULL,
		0x62790FD06B9D97A3ULL,
		0xEBF8126995E9574DULL,
		0xDA27B77F16A38258ULL,
		0x919B03FA0CF35276ULL,
		0x3A127B0887948A17ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x997354E0FBBC76E6ULL,
		0x38823823A537C378ULL,
		0x19BD73B559FBE536ULL,
		0x4CAE29D9383B632DULL,
		0x8B418B770D865394ULL,
		0xB982879368E80B1EULL,
		0x6E15A8AACCC3AB4BULL,
		0x4257679C36AA7261ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1960502083A822E0ULL,
		0x18023822A1074128ULL,
		0x00A1439440BB8004ULL,
		0x402809D028190321ULL,
		0x8B40026105805304ULL,
		0x9802871300A00218ULL,
		0x001100AA0CC30242ULL,
		0x0212630806800201ULL
	}};
	printf("Test Case 427\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 427 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -427;
	} else {
		printf("Test Case 427 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x167719D369399089ULL,
		0xD7F0C4CA2CD288CEULL,
		0x19C02355F2EBD02EULL,
		0xB221C09E2B317E9FULL,
		0xA2696C5A8B51ED4AULL,
		0x2E98675D67B0FE1EULL,
		0x66488640F9ED8111ULL,
		0xB24AB2906E1B067FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0283FD3D43371A1AULL,
		0x4B5939404C6E3A9EULL,
		0x9A2EF322A37A6889ULL,
		0x9AE7CEE804BFDB35ULL,
		0x38777B2EE2DF8763ULL,
		0x795D3764B526CDF0ULL,
		0x132251948212745AULL,
		0xDADF157BE4ACAA5CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0203191141311008ULL,
		0x435000400C42088EULL,
		0x18002300A26A4008ULL,
		0x9221C08800315A15ULL,
		0x2061680A82518542ULL,
		0x281827442520CC10ULL,
		0x0200000080000010ULL,
		0x924A10106408025CULL
	}};
	printf("Test Case 428\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 428 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -428;
	} else {
		printf("Test Case 428 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x596F90AB47D3024DULL,
		0x09CC9E04F2497086ULL,
		0x8C7BC10B023301F8ULL,
		0x78BD9D9135BD0B54ULL,
		0x9D03714461D36628ULL,
		0xA7E3BDEA507E01FEULL,
		0x9030F47E71FBEA89ULL,
		0x6B23F569A804FFE3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4F312228808F4152ULL,
		0x9A6476A070D370B7ULL,
		0xAA410207573B8728ULL,
		0x66748053C40C01C4ULL,
		0xC00DD6F8DB97D729ULL,
		0xF56E41B8D79A43FBULL,
		0x2542ACFFB8FA5064ULL,
		0x08D195A0DEBF3E19ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4921002800830040ULL,
		0x0844160070417086ULL,
		0x8841000302330128ULL,
		0x60348011040C0144ULL,
		0x8001504041934628ULL,
		0xA56201A8501A01FAULL,
		0x0000A47E30FA4000ULL,
		0x0801952088043E01ULL
	}};
	printf("Test Case 429\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 429 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -429;
	} else {
		printf("Test Case 429 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC1AB2DFDC4CA7A8EULL,
		0x83FE7DE2284CED91ULL,
		0x76058EF06678DEB3ULL,
		0x0215BACFBCF24538ULL,
		0x18ADDBF80C138E20ULL,
		0xFA86C411BCD89B7DULL,
		0x2AE831FE9012F462ULL,
		0x454A5E948B77F9B3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD2BAC554496636DFULL,
		0x45287B283A0FCDD1ULL,
		0x7B8267DA31F63B4BULL,
		0xD1FE3FF5A741CCFEULL,
		0x39F491EF7403F129ULL,
		0x9DD66782FCD92E22ULL,
		0x82C77973C8F6AFB7ULL,
		0x1809ACFCE9F1B3EBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC0AA05544042328EULL,
		0x01287920280CCD91ULL,
		0x720006D020701A03ULL,
		0x00143AC5A4404438ULL,
		0x18A491E804038020ULL,
		0x98864400BCD80A20ULL,
		0x02C031728012A422ULL,
		0x00080C948971B1A3ULL
	}};
	printf("Test Case 430\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 430 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -430;
	} else {
		printf("Test Case 430 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC646855899C9945DULL,
		0x06A1FF3E48BD4E21ULL,
		0x6757C1B33F1F4555ULL,
		0x8A8C70CFDC9853CDULL,
		0xF0EAE4B916D5E29BULL,
		0x5861E4F8D481A379ULL,
		0x67121EF36F9ED733ULL,
		0x78DE57F49F122FFCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7A72F392158C6ADCULL,
		0x0F1C5D8013D56A05ULL,
		0x2237BE9F7F3374EEULL,
		0x056DCABCDDDD4956ULL,
		0xDA40991A1603193EULL,
		0x83BB0F349CB8EA1AULL,
		0x5D82E1651E4DAD8FULL,
		0x8DBAD431D1A36527ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x424281101188005CULL,
		0x06005D0000954A01ULL,
		0x221780933F134444ULL,
		0x000C408CDC984144ULL,
		0xD04080181601001AULL,
		0x002104309480A218ULL,
		0x450200610E0C8503ULL,
		0x089A543091022524ULL
	}};
	printf("Test Case 431\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 431 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -431;
	} else {
		printf("Test Case 431 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2329A464D615424CULL,
		0x30C68E88E03CC6DCULL,
		0xB0BDF9F648BE5CF5ULL,
		0x7C3B6B7F9989F32EULL,
		0x6A1F3D000351BEA5ULL,
		0x322389786569ED3FULL,
		0x48DC5C3AFD101915ULL,
		0xE853930C2534C84FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x41290DE3208D290AULL,
		0x519D815078C4D821ULL,
		0x12AAF96EA42316FDULL,
		0x189E05BA6A199CF3ULL,
		0xD1EBFC01B4A2E6E4ULL,
		0x6A5545775DB37D07ULL,
		0x2C078F881F5A4FB8ULL,
		0x86BA4EC3326A261DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0129046000050008ULL,
		0x108480006004C000ULL,
		0x10A8F966002214F5ULL,
		0x181A013A08099022ULL,
		0x400B3C000000A6A4ULL,
		0x2201017045216D07ULL,
		0x08040C081D100910ULL,
		0x801202002020000DULL
	}};
	printf("Test Case 432\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 432 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -432;
	} else {
		printf("Test Case 432 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x448210DE1E458B82ULL,
		0x1E9149C25336D293ULL,
		0xC51A55DA6B35D5EFULL,
		0x732BB06D83E84B95ULL,
		0x86BC05B54B731CD8ULL,
		0x3950765342825288ULL,
		0x8C505CBFFCF22A0FULL,
		0x054ED2059B4C35FCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5324F71E762D02D9ULL,
		0xFDC387013E4E4B5FULL,
		0xB918AAE550B9F12CULL,
		0x2744134B69184166ULL,
		0x821F2241BF2B97A6ULL,
		0x77C29635CC5C0B76ULL,
		0x684A79CE6DAF433FULL,
		0x97D333130609B8B5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4000101E16050280ULL,
		0x1C81010012064213ULL,
		0x811800C04031D12CULL,
		0x2300104901084104ULL,
		0x821C00010B231480ULL,
		0x3140161140000200ULL,
		0x0840588E6CA2020FULL,
		0x05421201020830B4ULL
	}};
	printf("Test Case 433\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 433 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -433;
	} else {
		printf("Test Case 433 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6FA21BB37C153D68ULL,
		0xE33CE90D52639F84ULL,
		0x2A33588D0F3F9760ULL,
		0xE26412AD4CFC0270ULL,
		0x5DBE338BF6141F58ULL,
		0x2639666059694F46ULL,
		0x3FD6FDF77B537553ULL,
		0x3CAF8BEC97DAC7CDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFB6371313023272FULL,
		0x6CE13234A2B2AFFDULL,
		0x807FF9B5D416E538ULL,
		0x57506119B4DDFD2FULL,
		0x163EBB661C0577C9ULL,
		0x6140B5E624E9635EULL,
		0x99A4AA09DF2362AFULL,
		0xE81F3384FCCBBDE6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6B22113130012528ULL,
		0x6020200402228F84ULL,
		0x0033588504168520ULL,
		0x4240000904DC0020ULL,
		0x143E330214041748ULL,
		0x2000246000694346ULL,
		0x1984A8015B036003ULL,
		0x280F038494CA85C4ULL
	}};
	printf("Test Case 434\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 434 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -434;
	} else {
		printf("Test Case 434 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC9F5AA37B987D493ULL,
		0xD1560CABA1C95EC9ULL,
		0x467DAD7793AF8044ULL,
		0x881BFFA021253BEFULL,
		0xEEACE821175FA4EAULL,
		0x29D0E198BEC32FB2ULL,
		0x2FEC7E13227D9726ULL,
		0x56F9D3C26AEA9490ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x69926C46251FE75DULL,
		0x686E28190821AE81ULL,
		0x8A97DA640939349BULL,
		0xA5C1DD890877A8A4ULL,
		0x264C32D7BE74736BULL,
		0x5BAE94B92557E3C1ULL,
		0x0EEBB3084C9DC878ULL,
		0xAAC5A7B53FE7B287ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x499028062107C411ULL,
		0x4046080900010E81ULL,
		0x0215886401290000ULL,
		0x8001DD80002528A4ULL,
		0x260C20011654206AULL,
		0x0980809824432380ULL,
		0x0EE83200001D8020ULL,
		0x02C183802AE29080ULL
	}};
	printf("Test Case 435\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 435 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -435;
	} else {
		printf("Test Case 435 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x34BC08C443F38616ULL,
		0xFE48889B2E4E8203ULL,
		0x91504ED4BE5887F9ULL,
		0x1CC7BE47B48AC8A0ULL,
		0x6A7806D6BD46C6E3ULL,
		0x2DE2B04AC4E52FDEULL,
		0xE6E777E9E0BD2C85ULL,
		0x24C87B2D761AB98CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB845187A2989B20FULL,
		0x6661FD774C89EF49ULL,
		0x48A76FB75ABE44A4ULL,
		0xF91003BBE7A3CD4CULL,
		0xBB7B033864D1FF29ULL,
		0x46FA204ED2F26AA8ULL,
		0x34FCBB63F62B4FA5ULL,
		0x769A790DEC4F0655ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3004084001818206ULL,
		0x664088130C088201ULL,
		0x00004E941A1804A0ULL,
		0x18000203A482C800ULL,
		0x2A7802102440C621ULL,
		0x04E2204AC0E02A88ULL,
		0x24E43361E0290C85ULL,
		0x2488790D640A0004ULL
	}};
	printf("Test Case 436\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 436 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -436;
	} else {
		printf("Test Case 436 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1B38AB80398901F3ULL,
		0xA10190724C13FCDBULL,
		0x51E80BDCBE51E6C5ULL,
		0x053FF95487368E66ULL,
		0x20CAC78E7CA9D636ULL,
		0xA691949442663CE7ULL,
		0x85C55917968EFF17ULL,
		0x128098EC4FB1679FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2F65ED8449678798ULL,
		0x46985136D5A2E0C3ULL,
		0x123EB50A2C32749DULL,
		0x002F5467AFF7B8DDULL,
		0x778ACCB803FF43B9ULL,
		0x0D67BE25E4FCDF78ULL,
		0x058A6CB0BCA9BA8FULL,
		0xB00512550E8BBC3FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0B20A98009010190ULL,
		0x000010324402E0C3ULL,
		0x102801082C106485ULL,
		0x002F504487368844ULL,
		0x208AC48800A94230ULL,
		0x0401940440641C60ULL,
		0x058048109488BA07ULL,
		0x100010440E81241FULL
	}};
	printf("Test Case 437\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 437 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -437;
	} else {
		printf("Test Case 437 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x08970252550E8808ULL,
		0x6512B2F015370581ULL,
		0x55BBFC7DE0AEDE16ULL,
		0x5C0BC062DB1D9303ULL,
		0x58D75500AB405B25ULL,
		0xF886BB3DFB0B3C37ULL,
		0x0AD7FC7583B1C1EAULL,
		0x39DBFE160614E818ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF73B90A9D2F9D386ULL,
		0x05C94E3AD8FF7ED1ULL,
		0xB70932F6E5E90460ULL,
		0xB7C3602BE079D1AAULL,
		0x127148EF3C03F216ULL,
		0xF31E3E09C865FCB3ULL,
		0x03CDD70BE09A0092ULL,
		0xD841F236321E1A1BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0013000050088000ULL,
		0x0500023010370481ULL,
		0x15093074E0A80400ULL,
		0x14034022C0199102ULL,
		0x1051400028005204ULL,
		0xF0063A09C8013C33ULL,
		0x02C5D40180900082ULL,
		0x1841F21602140818ULL
	}};
	printf("Test Case 438\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 438 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -438;
	} else {
		printf("Test Case 438 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5B982EA1BBD84020ULL,
		0xEA74D0AB809F3A28ULL,
		0x8110F4E110012D90ULL,
		0x55023CD700FFE23EULL,
		0xF91F022C5EDA1809ULL,
		0xAC18B06DF94A6089ULL,
		0xB9B6587213A6414AULL,
		0xAB6BC8BB474C85FEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5871B13965CA98A5ULL,
		0x3D11B1DB0558BE5FULL,
		0xE3BD19310DCDBCF5ULL,
		0xEAC9C4A903083D97ULL,
		0xF845273EB7457746ULL,
		0x286C397CD9ADDC30ULL,
		0x80ACB2A8178FADFDULL,
		0xE60E846298E74691ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5810202121C80020ULL,
		0x2810908B00183A08ULL,
		0x8110102100012C90ULL,
		0x4000048100082016ULL,
		0xF805022C16401000ULL,
		0x2808306CD9084000ULL,
		0x80A4102013860148ULL,
		0xA20A802200440490ULL
	}};
	printf("Test Case 439\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 439 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -439;
	} else {
		printf("Test Case 439 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x49447F49CC05758BULL,
		0xE9A901F761B308DFULL,
		0x1F6363C124D867B2ULL,
		0xC67E88A2063568E3ULL,
		0x44657D69297D51D3ULL,
		0x4F4E07FC5D1F5A96ULL,
		0x05C0005C33434B40ULL,
		0x03F7CB365BE4AD9AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8C10750B791F73F3ULL,
		0xC8CDB32E87BEEB49ULL,
		0x7C83F116136C1B0CULL,
		0x5FC0AC182DFEBA29ULL,
		0xE311458511D8944AULL,
		0xCF5AF6E7F0484AD6ULL,
		0xBAEC530744DEAA5FULL,
		0x01898C9BCE0ECB08ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0800750948057183ULL,
		0xC889012601B20849ULL,
		0x1C03610000480300ULL,
		0x4640880004342821ULL,
		0x4001450101581042ULL,
		0x4F4A06E450084A96ULL,
		0x00C0000400420A40ULL,
		0x018188124A048908ULL
	}};
	printf("Test Case 440\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 440 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -440;
	} else {
		printf("Test Case 440 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA19320D2A4408397ULL,
		0x5B059FA1E4B173C1ULL,
		0x891493E18AAC0F17ULL,
		0x7F682C1B343275B8ULL,
		0x357A721C7D8872D4ULL,
		0x79EC01E938398EECULL,
		0xCC66D9329F22B509ULL,
		0x777BB1A5E9414CE8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x532435055DBA668CULL,
		0xB5E46200EB969351ULL,
		0xFEABC1CFBDE88A0DULL,
		0xA1847AB8F9D42F63ULL,
		0xCED3EA387B0471C9ULL,
		0x786047EB0D60883FULL,
		0xDBE2807A46AB3A9EULL,
		0xF137C4CF80424804ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0100200004000284ULL,
		0x11040200E0901341ULL,
		0x880081C188A80A05ULL,
		0x2100281830102520ULL,
		0x04526218790070C0ULL,
		0x786001E90820882CULL,
		0xC862803206223008ULL,
		0x7133808580404800ULL
	}};
	printf("Test Case 441\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 441 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -441;
	} else {
		printf("Test Case 441 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5042FECED840AB80ULL,
		0xB92B55376B357B2FULL,
		0x7511EBB6374A342EULL,
		0x0D984F9610160C17ULL,
		0xEFB831B2F896D336ULL,
		0xB13FC2644480CA64ULL,
		0x828913945A03AB35ULL,
		0xEB654B17D4F55FE2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1E7905404FD42D95ULL,
		0x3A1E48413F01EDF6ULL,
		0xC1F884729C90D6EDULL,
		0x49C96E96BE0BF879ULL,
		0xBC98BE5948908F75ULL,
		0xC5B002231F32E884ULL,
		0x8DF1C5EA62783C66ULL,
		0x24DFDF96EE1C5072ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1040044048402980ULL,
		0x380A40012B016926ULL,
		0x411080321400142CULL,
		0x09884E9610020811ULL,
		0xAC98301048908334ULL,
		0x813002200400C804ULL,
		0x8081018042002824ULL,
		0x20454B16C4145062ULL
	}};
	printf("Test Case 442\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 442 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -442;
	} else {
		printf("Test Case 442 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCA373DEAC1B865BCULL,
		0x44BA9D4BA69F6883ULL,
		0x03026C64086B9348ULL,
		0xAD7FA294A549C69AULL,
		0x355DABCC80812982ULL,
		0x5FA1340C8903E27EULL,
		0x347E4CE5A4F0EFA1ULL,
		0xB6AC0415E58A5BE6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x912A700ED1F54B79ULL,
		0xB59D038498697222ULL,
		0xC5B543C26ABBB443ULL,
		0x198D5D2B68D8949EULL,
		0x2A8BE01821C800C9ULL,
		0x5565083034F6D293ULL,
		0x89DB1CEDD311FE89ULL,
		0xF2F97F8F573D687CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8022300AC1B04138ULL,
		0x0498010080096002ULL,
		0x01004040082B9040ULL,
		0x090D00002048849AULL,
		0x2009A00800800080ULL,
		0x552100000002C212ULL,
		0x005A0CE58010EE81ULL,
		0xB2A8040545084864ULL
	}};
	printf("Test Case 443\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 443 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -443;
	} else {
		printf("Test Case 443 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE14FADA42FB71776ULL,
		0x765B0F5681B66136ULL,
		0xCA9C6D79964C7DF7ULL,
		0x6B31C27C749470B8ULL,
		0x81F0CC178DDE1F28ULL,
		0x25CF3482F4C6CCF9ULL,
		0xF8B4FD31DC64E56BULL,
		0xDB49B3D1F59B31F7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA138D5DA4A427521ULL,
		0x27CF10800DE0A7B3ULL,
		0x5504D4FDCE14A7B7ULL,
		0x47AAE12F292B793CULL,
		0xE47F96C3F19D048CULL,
		0x55EFB0936FA74F9DULL,
		0xB9B2B0B3FDCBF582ULL,
		0x5EB2873F25756689ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA10885800A021520ULL,
		0x264B000001A02132ULL,
		0x40044479860425B7ULL,
		0x4320C02C20007038ULL,
		0x80708403819C0408ULL,
		0x05CF308264864C99ULL,
		0xB8B0B031DC40E502ULL,
		0x5A00831125112081ULL
	}};
	printf("Test Case 444\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 444 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -444;
	} else {
		printf("Test Case 444 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x424F32CFFB15BF0BULL,
		0x31C2B9BF0D5564DFULL,
		0xEC1FC2DC902C4494ULL,
		0xF49149563CED43BAULL,
		0x7A5CC1659EA4995CULL,
		0x3C31FE8208A2D216ULL,
		0x71E15A41D5ACC4E5ULL,
		0xE1B454E3C1F1A0C5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB7D856BB4621BCA4ULL,
		0x0B023FC21A69330EULL,
		0xD501D26ABBCADE0FULL,
		0x321AF89C231F7B50ULL,
		0x497CAF764FFAB404ULL,
		0x08C05FF74F2FBD6DULL,
		0x2BC7F958E09C594DULL,
		0x3EFAC728291336CCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0248128B4201BC00ULL,
		0x010239820841200EULL,
		0xC401C24890084404ULL,
		0x30104814200D4310ULL,
		0x485C81640EA09004ULL,
		0x08005E8208229004ULL,
		0x21C15840C08C4045ULL,
		0x20B04420011120C4ULL
	}};
	printf("Test Case 445\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 445 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -445;
	} else {
		printf("Test Case 445 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x921BD520DF926572ULL,
		0xA7BB7330F8CC7322ULL,
		0x3E109F49EB8EF9AAULL,
		0x219549E15DC09593ULL,
		0x6B4D85AE6B8451A8ULL,
		0x7DE88E3126CF086EULL,
		0x3FEF96F96E41998FULL,
		0xB608CD647CDEDC2FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFBC293B1D7B1894AULL,
		0xA2F285F724F7A4CAULL,
		0x202AF5E8EA54940EULL,
		0x8B7409804BFBA30FULL,
		0x4A5A45729F2E179EULL,
		0xA47B5EE58090B60DULL,
		0x6A31D9AEF7A20740ULL,
		0xB953820EA45394FCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x92029120D7900142ULL,
		0xA2B2013020C42002ULL,
		0x20009548EA04900AULL,
		0x0114098049C08103ULL,
		0x4A4805220B041188ULL,
		0x24680E210080000CULL,
		0x2A2190A866000100ULL,
		0xB00080042452942CULL
	}};
	printf("Test Case 446\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 446 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -446;
	} else {
		printf("Test Case 446 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD6D38D46D3B83233ULL,
		0xFFD705920E0050E9ULL,
		0x0064CEFB59616064ULL,
		0x29A651D75B000CA4ULL,
		0x7EDFE2023180F56AULL,
		0x6F7D65E7D1E65034ULL,
		0x5C2FE0B6A181210EULL,
		0x66035FFA80E5EFD2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA451AF0A51308AC7ULL,
		0xA37A4369FCED14A2ULL,
		0x3CFD9E39BEE90267ULL,
		0x5A145E54F03D9BD0ULL,
		0xC4FD5A59739F60B1ULL,
		0xDA442198B0656805ULL,
		0x817C516E01FC931EULL,
		0x0135FEC743959A55ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x84518D0251300203ULL,
		0xA35201000C0010A0ULL,
		0x00648E3918610064ULL,
		0x0804505450000880ULL,
		0x44DD420031806020ULL,
		0x4A44218090644004ULL,
		0x002C40260180010EULL,
		0x00015EC200858A50ULL
	}};
	printf("Test Case 447\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 447 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -447;
	} else {
		printf("Test Case 447 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x869A8CAF6DA50812ULL,
		0x3D38B022B3CD8508ULL,
		0xCF8745C80A1428A7ULL,
		0x67CB4BEDAA4FB6D2ULL,
		0xA6352D25BEEB4847ULL,
		0x8FFB84EE87073F10ULL,
		0x198D67B3457E11B3ULL,
		0x61F09A68F63AC2FAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x157AD0ECAF453E82ULL,
		0xB42E8153D5753F94ULL,
		0x898BF1425DB4E2EBULL,
		0x0D9E0C3EC1780631ULL,
		0x04D497DA66B34DCBULL,
		0x6DBB4794D80E7F1AULL,
		0x0AB54EF298BF8B1AULL,
		0x4BFF207A18F43517ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x041A80AC2D050802ULL,
		0x3428800291450500ULL,
		0x89834140081420A3ULL,
		0x058A082C80480610ULL,
		0x0414050026A34843ULL,
		0x0DBB048480063F10ULL,
		0x088546B2003E0112ULL,
		0x41F0006810300012ULL
	}};
	printf("Test Case 448\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 448 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -448;
	} else {
		printf("Test Case 448 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA5D9F7E336D48F8CULL,
		0x939B9CCC7E09E35CULL,
		0x9C524F554E0D68D6ULL,
		0x449F7C745BDD85A4ULL,
		0x9EC1E4A5D34B2D9DULL,
		0xA635EF3361D57234ULL,
		0xD9200457EC47FF13ULL,
		0xF45E1D35D14A74B3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3B9B7778AB2407BDULL,
		0xD9C902C47382F3A9ULL,
		0x28E3DC0C34D86F59ULL,
		0x87A58AFB06E95F90ULL,
		0x711FA159996FFD37ULL,
		0x1C68EBF83A04233DULL,
		0xF77A66A1DCEFEAE6ULL,
		0xCB3A25F5A26198FDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x219977602204078CULL,
		0x918900C47200E308ULL,
		0x08424C0404086850ULL,
		0x0485087002C90580ULL,
		0x1001A001914B2D15ULL,
		0x0420EB3020042234ULL,
		0xD1200401CC47EA02ULL,
		0xC01A0535804010B1ULL
	}};
	printf("Test Case 449\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 449 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -449;
	} else {
		printf("Test Case 449 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8EE7FD653BFF395DULL,
		0x9819F086A98E043AULL,
		0xA4D1064E37BFA7DCULL,
		0x6CC0543631203021ULL,
		0x93BFD3E4413982EAULL,
		0x79BFECC104FE6006ULL,
		0x1AB44798B44382A3ULL,
		0x376D3B9181F2EB67ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6E1003CE2F4AD545ULL,
		0xCA94CC6878BBED5BULL,
		0x375573586E72BA6BULL,
		0x313FCDFCEECA2567ULL,
		0x7133B8C1281A1428ULL,
		0x1A885D7325BD9357ULL,
		0xC56633A28748707AULL,
		0x483F771493F84DB6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0E0001442B4A1145ULL,
		0x8810C000288A041AULL,
		0x245102482632A248ULL,
		0x2000443420002021ULL,
		0x113390C000180028ULL,
		0x18884C4104BC0006ULL,
		0x0024038084400022ULL,
		0x002D331081F04926ULL
	}};
	printf("Test Case 450\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 450 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -450;
	} else {
		printf("Test Case 450 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF0661F9BD8113F98ULL,
		0xD56B01992D34569FULL,
		0xDBCD35B13DB04512ULL,
		0xCFB2C85788BE8CDCULL,
		0xB368BF947579A08CULL,
		0x9BD7CAA49E1A1C5BULL,
		0x5D49EAB48F0740A1ULL,
		0xD5560C832E68ED4DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFD448D20757B2195ULL,
		0x67FB6DA2B9393318ULL,
		0x78150168537257E4ULL,
		0x621DBA84B3C966B0ULL,
		0x59BEA66B5FEA0445ULL,
		0xB796E72F18B09D58ULL,
		0x48456664798D62B0ULL,
		0x3F02E8ADDB6803BEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF0440D0050112190ULL,
		0x456B018029301218ULL,
		0x5805012011304500ULL,
		0x4210880480880490ULL,
		0x1128A60055680004ULL,
		0x9396C22418101C58ULL,
		0x48416224090540A0ULL,
		0x150208810A68010CULL
	}};
	printf("Test Case 451\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 451 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -451;
	} else {
		printf("Test Case 451 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x60BCC5BAD59BB864ULL,
		0xA03CBE32AD9EC9E6ULL,
		0x0CF34F852E992618ULL,
		0xE6F64DC44D28E20BULL,
		0xC4FEF04BF49BC949ULL,
		0x19D28536434E6699ULL,
		0x9E74E32078D703C3ULL,
		0x7267DA974FEFAC83ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF29FDAB1D4CADB3DULL,
		0xBB5EF9A3CB3035B8ULL,
		0xC1419CFAA66790D3ULL,
		0xCBF8440191CB13AAULL,
		0x51C64EF29E13D623ULL,
		0x4757D0765B6E2A4BULL,
		0x74D8D3C7F32EF6F7ULL,
		0x4F5B7CDCDF058364ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x609CC0B0D48A9824ULL,
		0xA01CB822891001A0ULL,
		0x00410C8026010010ULL,
		0xC2F044000108020AULL,
		0x40C640429413C001ULL,
		0x01528036434E2209ULL,
		0x1450C300700602C3ULL,
		0x424358944F058000ULL
	}};
	printf("Test Case 452\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 452 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -452;
	} else {
		printf("Test Case 452 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x689D35C92500DEC2ULL,
		0x09BEE2F82932F7EBULL,
		0x05C5FCB95EDFAC80ULL,
		0xC82FE13DCBF894A4ULL,
		0xD36347025A79E3F9ULL,
		0xF953197EF7FF68D9ULL,
		0x0CBCB3A96ACDC120ULL,
		0x6CCDE413C477E7ACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA7486A44B97556FBULL,
		0x86EF5E8AD04119DEULL,
		0xFAD8EA2646C4E0F9ULL,
		0x83738A69CFCF86A2ULL,
		0xC558692925DB0AAFULL,
		0x1B7CC2893C03EA2AULL,
		0xC099FBD2E0DEC31BULL,
		0xC460F7E365E5BD21ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x20082040210056C2ULL,
		0x00AE4288000011CAULL,
		0x00C0E82046C4A080ULL,
		0x80238029CBC884A0ULL,
		0xC1404100005902A9ULL,
		0x1950000834036808ULL,
		0x0098B38060CCC100ULL,
		0x4440E4034465A520ULL
	}};
	printf("Test Case 453\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 453 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -453;
	} else {
		printf("Test Case 453 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA1297703AD3A17D8ULL,
		0x158993A833207514ULL,
		0xECC5511D9FB9CE00ULL,
		0xEFD410E4B9D1EA7CULL,
		0x8867944F266E5504ULL,
		0x984FD9238EC6961DULL,
		0xA31EB8E046B06760ULL,
		0x3B8CC67417076AB1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF7E290C763B733F5ULL,
		0x00264515B7C09F3CULL,
		0xAB9924657EE2AA9BULL,
		0x4BFB82FD40B4FCC9ULL,
		0x4503E357557C5855ULL,
		0x43AFEF21466080F6ULL,
		0x55FA1EF7E12B11D8ULL,
		0xF01289A1C4920D5AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA1201003213213D0ULL,
		0x0000010033001514ULL,
		0xA88100051EA08A00ULL,
		0x4BD000E40090E848ULL,
		0x00038047046C5004ULL,
		0x000FC92106408014ULL,
		0x011A18E040200140ULL,
		0x3000802004020810ULL
	}};
	printf("Test Case 454\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 454 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -454;
	} else {
		printf("Test Case 454 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x211881BBAD6569F9ULL,
		0x3B149394165537D7ULL,
		0x3A787E793BD49A95ULL,
		0x31D6E0E546539D8DULL,
		0x18F49F7FECAA01A1ULL,
		0x23C2F76203F80748ULL,
		0xEF1BA628A994DA14ULL,
		0xED5FC84E6EB23B3EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3B140430BFB31409ULL,
		0x5A85BB4C23E4B129ULL,
		0x5F67DA18FE672A22ULL,
		0x414E28C5C8AA1F49ULL,
		0xAF698B06E0BDF52BULL,
		0x3A022D7BA0893662ULL,
		0x6CE300A4FD311A8BULL,
		0x4E485BD1B09A6C13ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x21100030AD210009ULL,
		0x1A04930402443101ULL,
		0x1A605A183A440A00ULL,
		0x014620C540021D09ULL,
		0x08608B06E0A80121ULL,
		0x2202256200880640ULL,
		0x6C030020A9101A00ULL,
		0x4C48484020922812ULL
	}};
	printf("Test Case 455\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 455 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -455;
	} else {
		printf("Test Case 455 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA8DADFE982CFCF19ULL,
		0xF5DC63C215090939ULL,
		0xBFC6D5346C6D1EC1ULL,
		0x7748B0C927EB27A6ULL,
		0x373BB4975A8344DBULL,
		0x89007E914756187EULL,
		0xA7398CAC2C0D5371ULL,
		0xBF32FD0F1488F909ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEB0B0D45CC48D363ULL,
		0xE5B551B8512F31B9ULL,
		0x754C3846CE83F924ULL,
		0x402406A104B0ED57ULL,
		0x761D4812749E1484ULL,
		0x16AF9E9D0554ED96ULL,
		0xB507534DB7A63544ULL,
		0x2D4B996665947FE8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA80A0D418048C301ULL,
		0xE594418011090139ULL,
		0x354410044C011800ULL,
		0x4000008104A02506ULL,
		0x3619001250820480ULL,
		0x00001E9105540816ULL,
		0xA501000C24041140ULL,
		0x2D02990604807908ULL
	}};
	printf("Test Case 456\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 456 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -456;
	} else {
		printf("Test Case 456 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA968B82A66ED84AAULL,
		0xFACFA7D0D2CDF289ULL,
		0x314A76D23E71C8C2ULL,
		0x63069798069F6411ULL,
		0x043F7F85E0E82B6DULL,
		0x2D641A6FD9D4FACDULL,
		0x87A30F16F49C8845ULL,
		0xB736BC1BDF259A04ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6947B565A9B503EAULL,
		0x7F274A49387B008EULL,
		0x1CB382F2B92BA649ULL,
		0xF3782DDA9E296AF7ULL,
		0x0DEA81953AB3BCFBULL,
		0x15B3AA41ABD1ECC9ULL,
		0xB33F52305C4DA9B7ULL,
		0x7F9F249A7E4A713AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2940B02020A500AAULL,
		0x7A07024010490088ULL,
		0x100202D238218040ULL,
		0x6300059806096011ULL,
		0x042A018520A02869ULL,
		0x05200A4189D0E8C9ULL,
		0x83230210540C8805ULL,
		0x3716241A5E001000ULL
	}};
	printf("Test Case 457\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 457 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -457;
	} else {
		printf("Test Case 457 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x58FB37C8DB009B48ULL,
		0x50ABC7BBA4C1BB8FULL,
		0x5C900665B072184DULL,
		0x20D12C087074DAF3ULL,
		0xC5598539212444BBULL,
		0x188B8AAAD25B2A83ULL,
		0x2B37CA178E8A2710ULL,
		0xB91B9A844F11C14FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6BFC50EF71DECC72ULL,
		0x4645DD92AC136A49ULL,
		0x32EEC0ADB9DDFF14ULL,
		0x1AF80F99C802C21EULL,
		0x959A54894748A84AULL,
		0xF1C945DC5A6381EEULL,
		0xE92FC2692737724FULL,
		0xDD3A8BFFE2833B1AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x48F810C851008840ULL,
		0x4001C592A4012A09ULL,
		0x10800025B0501804ULL,
		0x00D00C084000C212ULL,
		0x851804090100000AULL,
		0x1089008852430082ULL,
		0x2927C20106022200ULL,
		0x991A8A844201010AULL
	}};
	printf("Test Case 458\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 458 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -458;
	} else {
		printf("Test Case 458 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDB61E9315A44D836ULL,
		0x45B1F7648752C97FULL,
		0x0F058AAADF88DA51ULL,
		0x254C8C6625A991D3ULL,
		0x74982D8A7B156262ULL,
		0xC824C2A04599056CULL,
		0x959DCB79D5E8BD8FULL,
		0x642A527026C0590BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE9D2019551C8A243ULL,
		0x671234C0020BCB4BULL,
		0x05EE3E7132AA7CF0ULL,
		0xF9659E9CDF410433ULL,
		0x69650A6023650E4BULL,
		0x311E3A28BA8E7B8BULL,
		0x3C71C3B41AB0C0F0ULL,
		0x210E19A53F7E7B59ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC940011150408002ULL,
		0x451034400202C94BULL,
		0x05040A2012885850ULL,
		0x21448C0405010013ULL,
		0x6000080023050242ULL,
		0x0004022000880108ULL,
		0x1411C33010A08080ULL,
		0x200A102026405909ULL
	}};
	printf("Test Case 459\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 459 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -459;
	} else {
		printf("Test Case 459 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1819FE709B0E37BCULL,
		0xC6D1BC1DDB08FC06ULL,
		0xF6BF186A31BC0C53ULL,
		0x3D81240038DB1E1CULL,
		0xA3F584C5434F23FBULL,
		0x8BB4D23E0926DFA7ULL,
		0x27B5F5078DADD626ULL,
		0xF5AEB27BD9061E1EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x82839F6E09821B3DULL,
		0x031C03BF51FAA2A7ULL,
		0x81FF1CEBE4449E1CULL,
		0x576FBFC8E7E4DA21ULL,
		0x311494ACC5B78ADCULL,
		0x30CA56CBA76C3D6EULL,
		0x93875697961EF564ULL,
		0xD2745A890CA0F8CAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x00019E600902133CULL,
		0x0210001D5108A006ULL,
		0x80BF186A20040C10ULL,
		0x1501240020C01A00ULL,
		0x21148484410702D8ULL,
		0x0080520A01241D26ULL,
		0x03855407840CD424ULL,
		0xD02412090800180AULL
	}};
	printf("Test Case 460\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 460 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -460;
	} else {
		printf("Test Case 460 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xECB1A6AE27A576B2ULL,
		0xC5B32281890B6A0CULL,
		0x0018E19889D7BB4EULL,
		0x21BE434C4D7FB8B9ULL,
		0xFA8D1391C7B8034DULL,
		0x14235444A89A710EULL,
		0x8170A4FA2F4EC644ULL,
		0x3119850B2E162874ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7F6A6D9227670C58ULL,
		0x2632962353961C8CULL,
		0x839A47EAB5B192E3ULL,
		0x3C4FA879C9CC6D17ULL,
		0x27500CDB6AD5D151ULL,
		0xB96525800A864D77ULL,
		0xBF651E186C023D0CULL,
		0xD2CB1A10047437B0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6C20248227250410ULL,
		0x043202010102080CULL,
		0x0018418881919242ULL,
		0x200E0048494C2811ULL,
		0x2200009142900141ULL,
		0x1021040008824106ULL,
		0x816004182C020404ULL,
		0x1009000004142030ULL
	}};
	printf("Test Case 461\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 461 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -461;
	} else {
		printf("Test Case 461 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC367F03C17BBBA88ULL,
		0xC0355A091C637517ULL,
		0xA08CAD5CA65A2E24ULL,
		0xF2A29220B244E3FBULL,
		0x03EF7E0F77D68D24ULL,
		0xDAAA225D0AC8530CULL,
		0xAC5E915240495F9BULL,
		0x99B35D3DD8AAFFE1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCC64FA19A0DB4BABULL,
		0xBFF55D7842B19CC7ULL,
		0x79D5F508313619EAULL,
		0x8955DBBFA7F81036ULL,
		0xD9DEF68B771AD2C3ULL,
		0x1B4F7890A2382DA3ULL,
		0x2672D2D74BB2EE4DULL,
		0xBBD8F5B35A234C2CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC064F018009B0A88ULL,
		0x8035580800211407ULL,
		0x2084A50820120820ULL,
		0x80009220A2400032ULL,
		0x01CE760B77128000ULL,
		0x1A0A201002080100ULL,
		0x2452905240004E09ULL,
		0x9990553158224C20ULL
	}};
	printf("Test Case 462\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 462 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -462;
	} else {
		printf("Test Case 462 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x872D12ABB8EF0E85ULL,
		0x1D8EF3B67E7B0D25ULL,
		0x1BE0B09E427155D4ULL,
		0x3AEF03FC3E9F79FFULL,
		0x36C4F0F3A44D0A0BULL,
		0x2F208DD51A77883BULL,
		0xBA29007139382C9AULL,
		0x54A7129F52708595ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1000790FC4CCD623ULL,
		0x8D75F61E8CAF4888ULL,
		0xFECDBC86612A75A2ULL,
		0xA5241D6B5323BC45ULL,
		0x8C5BC7890D49BDFBULL,
		0xEF4792823265D889ULL,
		0xD4A08EAAFC7A4E05ULL,
		0x94A497554D732A2BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0000100B80CC0601ULL,
		0x0D04F2160C2B0800ULL,
		0x1AC0B08640205580ULL,
		0x2024016812033845ULL,
		0x0440C0810449080BULL,
		0x2F00808012658809ULL,
		0x9020002038380C00ULL,
		0x14A4121540700001ULL
	}};
	printf("Test Case 463\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 463 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -463;
	} else {
		printf("Test Case 463 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5CBBE64F8A9C4761ULL,
		0x0683DA28FCED883FULL,
		0xB68D0FA29D706DBBULL,
		0xEF42AD721983F621ULL,
		0x2AD1D8385C7D1A38ULL,
		0xBF1C30A129612FF5ULL,
		0x03DEDBEC3EB6FEC1ULL,
		0x0BD8D3BA16F15803ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x25EF77F3889E5DBEULL,
		0x6DD6077DB289631AULL,
		0xB43F859F4609C3D2ULL,
		0xDAE929CAD73BC6F7ULL,
		0xC9851A83A34C6B3DULL,
		0x42B36EF5F8BE6325ULL,
		0x72BACBC6B01E21B4ULL,
		0x2BE9FE816C02A3EAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x04AB6643889C4520ULL,
		0x04820228B089001AULL,
		0xB40D058204004192ULL,
		0xCA4029421103C621ULL,
		0x08811800004C0A38ULL,
		0x021020A128202325ULL,
		0x029ACBC430162080ULL,
		0x0BC8D28004000002ULL
	}};
	printf("Test Case 464\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 464 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -464;
	} else {
		printf("Test Case 464 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9943B732764FFAC3ULL,
		0xADEF36842F43BBE5ULL,
		0x5ABB781A8D03B9A3ULL,
		0x70530738925A898AULL,
		0x4B382AF37983ECBCULL,
		0x65323D8B5FC24CEFULL,
		0x9860864916BDD51DULL,
		0xDB39EBFE2CAE1321ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x29EE4F71766C995BULL,
		0x802E34A324292527ULL,
		0x362CC03E6BFD09C9ULL,
		0x711598C24D31CBC4ULL,
		0xC95FC2AE04E8AA9BULL,
		0x631D45905D7C261DULL,
		0x7E27783ABA8FD34DULL,
		0xD1B4B83C1013E110ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x09420730764C9843ULL,
		0x802E348024012125ULL,
		0x1228401A09010981ULL,
		0x7011000000108980ULL,
		0x491802A20080A898ULL,
		0x611005805D40040DULL,
		0x18200008128DD10DULL,
		0xD130A83C00020100ULL
	}};
	printf("Test Case 465\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 465 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -465;
	} else {
		printf("Test Case 465 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x54379D8C9FEB2C71ULL,
		0x64208422C6267E14ULL,
		0x78B4A777E8B6E3B5ULL,
		0xAD153ED5C98B61CDULL,
		0x1A4E28371081DFB9ULL,
		0x5C7E5EECBC1A9847ULL,
		0xC9B555DAB7F0B441ULL,
		0x6511879FC26B029EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2257DC9303B5DB43ULL,
		0xCCF2E65A358537A1ULL,
		0x9C1F2DB58D3D9216ULL,
		0xEA8FA3B5102E6950ULL,
		0x33333C49061E8D17ULL,
		0x6779173287CD322AULL,
		0x41A6FA74ABEF8C5CULL,
		0x1AF55A2D9FCBAE20ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x00179C8003A10841ULL,
		0x4420840204043600ULL,
		0x1814253588348214ULL,
		0xA8052295000A6140ULL,
		0x1202280100008D11ULL,
		0x4478162084081002ULL,
		0x41A45050A3E08440ULL,
		0x0011020D824B0200ULL
	}};
	printf("Test Case 466\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 466 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -466;
	} else {
		printf("Test Case 466 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6C2EBE0183ABFF84ULL,
		0x2455DBC4CF4C5A2EULL,
		0x935B683D4D99B75AULL,
		0xA43B57D09F7A4F16ULL,
		0x98634475309AC5D0ULL,
		0x7C811DF866BB590AULL,
		0xF8F20A8A8E47DB71ULL,
		0x6BBCCF9600642F0FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x23A6A88BCA4AF8BCULL,
		0x3C55DE90738E400CULL,
		0x22F8954EC75FC804ULL,
		0x321B907CB33CA378ULL,
		0xC65E9C2E7E4A5C1BULL,
		0xABB9A82916A9ED78ULL,
		0x5759F690E661B0D0ULL,
		0xB8E800B06888D198ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2026A801820AF884ULL,
		0x2455DA80430C400CULL,
		0x0258000C45198000ULL,
		0x201B105093380310ULL,
		0x80420424300A4410ULL,
		0x2881082806A94908ULL,
		0x5050028086419050ULL,
		0x28A8009000000108ULL
	}};
	printf("Test Case 467\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 467 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -467;
	} else {
		printf("Test Case 467 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6F387508E9F64E52ULL,
		0xDCA18679375AF4A7ULL,
		0xFAE654001ACC3AA1ULL,
		0x58D8C9B7EEE25BB9ULL,
		0xD0FEDF15B4AC4B4BULL,
		0x6150912D5F8DCE3DULL,
		0x6237C7F92490B7F9ULL,
		0xE01098CF46E20DBFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9755CDCB808B4E8EULL,
		0x7666D0F288A9AABBULL,
		0x810495414A56B1F4ULL,
		0x9E58B03730BB51E8ULL,
		0x43B31FA1AAD7C973ULL,
		0xE799C5CA518FA89FULL,
		0x440CB3AC3802E289ULL,
		0x2700B13FA41DEF06ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0710450880824E02ULL,
		0x542080700008A0A3ULL,
		0x800414000A4430A0ULL,
		0x1858803720A251A8ULL,
		0x40B21F01A0844943ULL,
		0x61108108518D881DULL,
		0x400483A82000A289ULL,
		0x2000900F04000D06ULL
	}};
	printf("Test Case 468\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 468 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -468;
	} else {
		printf("Test Case 468 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8917130C0C4FEB9DULL,
		0x889E95B6F65AA4EFULL,
		0x5945C3CBEF34C87BULL,
		0xC55E8253D71E1B83ULL,
		0x1671B1288D7BE867ULL,
		0xA23603F2D34301E0ULL,
		0x0FC1B33C6E0AE040ULL,
		0xB24E904BE07C9EFCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x89FBC8D90835B76FULL,
		0xB1F2B638AF204E90ULL,
		0x9E3B8D912E4A09AFULL,
		0x392C2EF7ECCE2FB5ULL,
		0x4B0B77D6727DB9EEULL,
		0x44FD452345D4ED01ULL,
		0xBAB8FF871B1E5EA8ULL,
		0x0BC894D8AA2E0A24ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x891300080805A30DULL,
		0x80929430A6000480ULL,
		0x180181812E00082BULL,
		0x010C0253C40E0B81ULL,
		0x020131000079A866ULL,
		0x0034012241400100ULL,
		0x0A80B3040A0A4000ULL,
		0x02489048A02C0A24ULL
	}};
	printf("Test Case 469\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 469 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -469;
	} else {
		printf("Test Case 469 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEC44300665AF0BCCULL,
		0x9184DCADE71659EFULL,
		0x42B9183F47BC9C89ULL,
		0x6E288D1CE6CD617FULL,
		0x93F846F3BEF84ADEULL,
		0x54C176FC220AA924ULL,
		0xB191C66666042C37ULL,
		0xE30FFBD98D64A640ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAC8CE0436BE24542ULL,
		0xBCDC25D184657947ULL,
		0x64A1EC7B7C396669ULL,
		0x465F035F3EED3EACULL,
		0x1016316F208F4678ULL,
		0x795A494F94F6063EULL,
		0x0F9364166B23AC6DULL,
		0x8225DF371B841390ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAC04200261A20140ULL,
		0x9084048184045947ULL,
		0x40A1083B44380409ULL,
		0x4608011C26CD202CULL,
		0x1010006320884258ULL,
		0x5040404C00020024ULL,
		0x0191440662002C25ULL,
		0x8205DB1109040200ULL
	}};
	printf("Test Case 470\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 470 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -470;
	} else {
		printf("Test Case 470 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x80371718BD3EF1B5ULL,
		0x7C2EC2181A53CE8FULL,
		0x6A5318314DA214FFULL,
		0xE9F7E1CC0262FF98ULL,
		0x006335AA97F35EFFULL,
		0x5C5265D3FD4BFC15ULL,
		0x4843A14649FE4789ULL,
		0x890E80672DABCBB3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCFAE1F54EB081F1AULL,
		0x25A58DAFE56C5B00ULL,
		0x5EAA85BB7720C95CULL,
		0x553AD1A09C293D7EULL,
		0xC8D33FE1436A50B9ULL,
		0xCF47560DD077EF05ULL,
		0x2AE7D40FE835A8B8ULL,
		0xEE07B5BCC5E678EEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x80261710A9081110ULL,
		0x2424800800404A00ULL,
		0x4A0200314520005CULL,
		0x4132C18000203D18ULL,
		0x004335A0036250B9ULL,
		0x4C424401D043EC05ULL,
		0x0843800648340088ULL,
		0x8806802405A248A2ULL
	}};
	printf("Test Case 471\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 471 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -471;
	} else {
		printf("Test Case 471 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA197CE3516002463ULL,
		0x56967ED0E16C2FD3ULL,
		0x041A5EDFC92E88B5ULL,
		0x6ED33044A7F1C7F5ULL,
		0x8FCC61EEE4A27A1DULL,
		0x693455C6DEB751D9ULL,
		0xE941B25DAE426895ULL,
		0x58EA1880A845F9D3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2B7BF08EDD5D7971ULL,
		0x1F63E60A963B8D35ULL,
		0xEA26844026911703ULL,
		0xE4A0A96D91CC94C0ULL,
		0xAF88C5306A791A46ULL,
		0x87D0235C8CE3A9E3ULL,
		0x924C2780ACC77742ULL,
		0x84C99C46BB41C417ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2113C00414002061ULL,
		0x1602660080280D11ULL,
		0x0002044000000001ULL,
		0x6480204481C084C0ULL,
		0x8F88412060201A04ULL,
		0x011001448CA301C1ULL,
		0x80402200AC426000ULL,
		0x00C81800A841C013ULL
	}};
	printf("Test Case 472\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 472 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -472;
	} else {
		printf("Test Case 472 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA2D7FF8F5DE63481ULL,
		0xE026CE6F84D2ABF4ULL,
		0x5675F4E87F57D91CULL,
		0xED68E227A8166F35ULL,
		0xEC7AD2A42CC076DCULL,
		0x0F55ECDAD74982A0ULL,
		0xA2538CB0D505831FULL,
		0x3A92ACD21D8DE464ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFBD4451F2123B01BULL,
		0x2C2A5DD34C1AA371ULL,
		0x12C2093DDB2E5EDBULL,
		0xC9F5A8ABFF914E03ULL,
		0x7BD44078B35E3D87ULL,
		0x58F84581CE1E1909ULL,
		0x86470CB95BDA92E9ULL,
		0x0F2DA1A9847F9B31ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA2D4450F01223001ULL,
		0x20224C430412A370ULL,
		0x124000285B065818ULL,
		0xC960A023A8104E01ULL,
		0x6850402020403484ULL,
		0x08504480C6080000ULL,
		0x82430CB051008209ULL,
		0x0A00A080040D8020ULL
	}};
	printf("Test Case 473\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 473 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -473;
	} else {
		printf("Test Case 473 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8732C078B83F2A04ULL,
		0x042AEC35A8731102ULL,
		0xED151DCA901FD3C5ULL,
		0x8475E32411583E46ULL,
		0x3FBCA35957A05081ULL,
		0xF9F107C3202EF9B0ULL,
		0x7CAA8978143422E4ULL,
		0x8BDD5347B8013F4AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x26917A5AA8EED27AULL,
		0x741750525A08F913ULL,
		0x388E65C996747105ULL,
		0x937F15C0C0A766ADULL,
		0x10BDE5C350E895EBULL,
		0xC733E37424A35BD2ULL,
		0x859B28348B08380CULL,
		0xB68CB51037BA12E5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x06104058A82E0200ULL,
		0x0402401008001102ULL,
		0x280405C890145105ULL,
		0x8075010000002604ULL,
		0x10BCA14150A01081ULL,
		0xC131034020225990ULL,
		0x048A083000002004ULL,
		0x828C110030001240ULL
	}};
	printf("Test Case 474\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 474 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -474;
	} else {
		printf("Test Case 474 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x67F32FE7AC6B052FULL,
		0xCABE55D4D83E427AULL,
		0x72DD8BB7F819E660ULL,
		0xE63677540C665ECAULL,
		0xCD3B1926E847B5C6ULL,
		0xFA5D9BD4343D9FB3ULL,
		0xABDA2B3B78AFC886ULL,
		0x26AAFD6B77A9553BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC63897743F182AD4ULL,
		0x5AC18E71CEC9B163ULL,
		0x8BD3284B5A2D92B7ULL,
		0x8644C244CB2B18A5ULL,
		0x70FA0DEDB82733E5ULL,
		0x1A1880B0ED79439EULL,
		0x81A9CA437447986DULL,
		0x1C02A7F1F2D0B939ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x463007642C080004ULL,
		0x4A800450C8080062ULL,
		0x02D1080358098220ULL,
		0x8604424408221880ULL,
		0x403A0924A80731C4ULL,
		0x1A18809024390392ULL,
		0x81880A0370078804ULL,
		0x0402A56172801139ULL
	}};
	printf("Test Case 475\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 475 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -475;
	} else {
		printf("Test Case 475 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x01E9FD4B4D686BF6ULL,
		0xEE85176D6D7AD7C2ULL,
		0x606CCB9FCEA4752AULL,
		0xDF0E5D2DC6237004ULL,
		0x41E6589CC5760B4DULL,
		0xFD9C24019071C24AULL,
		0xEDB83C5829FED584ULL,
		0x91DDA0345EA12D84ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x31F99049B9C61ECCULL,
		0x42EFC6BF4F4CCE33ULL,
		0x7D15700FB6630F36ULL,
		0xE46B474C6BC7B359ULL,
		0xEFBDB07C95CE10A9ULL,
		0xEB539D94664CA97DULL,
		0x65DAB7ED582DD9E0ULL,
		0x09385A6B1824BA37ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x01E9904909400AC4ULL,
		0x4285062D4D48C602ULL,
		0x6004400F86200522ULL,
		0xC40A450C42033000ULL,
		0x41A4101C85460009ULL,
		0xE910040000408048ULL,
		0x65983448082CD180ULL,
		0x0118002018202804ULL
	}};
	printf("Test Case 476\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 476 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -476;
	} else {
		printf("Test Case 476 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x493244E276BC561CULL,
		0xFEC0C9D6696C93F8ULL,
		0x5605AE55E35751E4ULL,
		0x2087BCE526AE6DACULL,
		0x32089A10B71AA8A9ULL,
		0x60525E6FCA4A1AD2ULL,
		0x7F12747F750708BAULL,
		0x37960E978A99A194ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE2DEAC78FF1938BFULL,
		0x274F78012DC665E3ULL,
		0xA21E2A2E56437359ULL,
		0xE4C55AAF0F2E437AULL,
		0xBEC861A6557C03FBULL,
		0x4FA9A6215C80E3ACULL,
		0x302EC68DB5D619BBULL,
		0x5665EA7E8F904B55ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x401204607618101CULL,
		0x26404800294401E0ULL,
		0x02042A0442435140ULL,
		0x208518A5062E4128ULL,
		0x32080000151800A9ULL,
		0x4000062148000280ULL,
		0x3002440D350608BAULL,
		0x16040A168A900114ULL
	}};
	printf("Test Case 477\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 477 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -477;
	} else {
		printf("Test Case 477 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8A9B3378FE737966ULL,
		0x8EB06D271BFAEAC8ULL,
		0x23A7BD7DDDBF63F1ULL,
		0x7A8FF4B1FA965BACULL,
		0xAF2197BA036F6349ULL,
		0xEE829DE2D1EFEFD4ULL,
		0x4769EA891499114CULL,
		0xB68716C495DED0E1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x34D0B17819E1029AULL,
		0x510DDECB32EE5D9BULL,
		0x5D296044275E991DULL,
		0x7C4EA95D0036AB11ULL,
		0x3BAD9E1A4548675CULL,
		0xA69930FF7938AAB4ULL,
		0xEEFC117325F5236EULL,
		0x5CEDF2D6BD13E6ECULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0090317818610002ULL,
		0x00004C0312EA4888ULL,
		0x01212044051E0111ULL,
		0x780EA01100160B00ULL,
		0x2B21961A01486348ULL,
		0xA68010E25128AA94ULL,
		0x466800010491014CULL,
		0x148512C49512C0E0ULL
	}};
	printf("Test Case 478\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 478 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -478;
	} else {
		printf("Test Case 478 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x54EE3C41BBA4B5EFULL,
		0x5C891A6C4A921E52ULL,
		0x903B27FEDAAA8FFFULL,
		0x9FE03ACF55BA6A70ULL,
		0x0C268F9422B4F328ULL,
		0x72CF29A80E12DFCAULL,
		0x98E15B8FBD69765AULL,
		0xB58FCE50F8D5D584ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8EC2A410CEA58F56ULL,
		0x438653D91D80874EULL,
		0xA301D5A7638D2111ULL,
		0xC3212AB29C36DE26ULL,
		0x789CB9E3A2FA4C6BULL,
		0xE21166F3242EF5E7ULL,
		0xA3BF83DBF9181661ULL,
		0x849904BB6336CCA4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x04C224008AA48546ULL,
		0x4080124808800642ULL,
		0x800105A642880111ULL,
		0x83202A8214324A20ULL,
		0x0804898022B04028ULL,
		0x620120A00402D5C2ULL,
		0x80A1038BB9081640ULL,
		0x848904106014C484ULL
	}};
	printf("Test Case 479\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 479 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -479;
	} else {
		printf("Test Case 479 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2EA77B0BA1D68501ULL,
		0x53F505C36F4BFB1AULL,
		0x452C9E67D6008CB9ULL,
		0x599D947F29F0D89AULL,
		0x8012B767ED6A5B52ULL,
		0x281F075A2DB3E32DULL,
		0xF05B8E1532644198ULL,
		0xF79940D5EC70E619ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB944ADB8235102B1ULL,
		0x2CA9C66D21E27AB8ULL,
		0xB0E9E577A80A91EEULL,
		0x269A7027C8372985ULL,
		0xA7D1E8CEFB553C08ULL,
		0xD42E0750F8755D6DULL,
		0xA8B14D1A3D3D3A11ULL,
		0x175E9601AE4FCDCAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2804290821500001ULL,
		0x00A1044121427A18ULL,
		0x00288467800080A8ULL,
		0x0098102708300880ULL,
		0x8010A046E9401800ULL,
		0x000E07502831412DULL,
		0xA0110C1030240010ULL,
		0x17180001AC40C408ULL
	}};
	printf("Test Case 480\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 480 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -480;
	} else {
		printf("Test Case 480 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE62EBFD106FDD0FAULL,
		0x663B56CBD26845A6ULL,
		0xE68E740FFD66AC6BULL,
		0x65E1A701947A965DULL,
		0x3AF466C60BE44731ULL,
		0xEC206C67B7E93E6FULL,
		0x94A213CC7DB1AE33ULL,
		0x829D5434E3F96BD9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB9F1A7F13C1FB52EULL,
		0x193F91578D4B33A9ULL,
		0x6C58CBB2A23DB147ULL,
		0x1E84DA58D1D40E66ULL,
		0xB0A63FF29749190BULL,
		0xC6F657E8E2CF1E17ULL,
		0x5CB3A4BAE8BE62E8ULL,
		0x5C4F2C1A3E6C14CBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA020A7D1041D902AULL,
		0x003B1043804801A0ULL,
		0x64084002A024A043ULL,
		0x0480820090500644ULL,
		0x30A426C203400101ULL,
		0xC4204460A2C91E07ULL,
		0x14A2008868B02220ULL,
		0x000D0410226800C9ULL
	}};
	printf("Test Case 481\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 481 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -481;
	} else {
		printf("Test Case 481 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1890E7DAC39B1D34ULL,
		0x41117D624CD8E6CEULL,
		0x956FE88304A96A86ULL,
		0xB43FF3AB41C12637ULL,
		0x46FCF2F340B7DA53ULL,
		0xBE93032AD5CC2102ULL,
		0xDC8F21CD0A77E0D9ULL,
		0x2A2561FB300560E9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF7EF25FE4F44D3ACULL,
		0xC9A73096EBF0A117ULL,
		0x431A3D3BE136094DULL,
		0x8E90A75D83F29A17ULL,
		0x7E540E60F6C3192EULL,
		0x8A11CE4BE87E6ACDULL,
		0x33795CDA85176E62ULL,
		0x018A67DF3B29B3EEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x108025DA43001124ULL,
		0x4101300248D0A006ULL,
		0x010A280300200804ULL,
		0x8410A30901C00217ULL,
		0x4654026040831802ULL,
		0x8A11020AC04C2000ULL,
		0x100900C800176040ULL,
		0x000061DB300120E8ULL
	}};
	printf("Test Case 482\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 482 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -482;
	} else {
		printf("Test Case 482 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA2E2856DB7EA9894ULL,
		0x1D5F310FF5D007E4ULL,
		0x62F7D46E49BA4385ULL,
		0x02029117715F220AULL,
		0x64BA63E30503F002ULL,
		0x5087727C20CC17FDULL,
		0x3F80DD8450EC619FULL,
		0x3546448075EB4222ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE7694C3DCBDA6079ULL,
		0x6C05170FF4163482ULL,
		0x2FB2CB251B38FEF0ULL,
		0x12991C12B59698B0ULL,
		0xAEC98CC53F74A8D1ULL,
		0x3E2C1BE7EF39C6E2ULL,
		0xDF4B6423372B5A5DULL,
		0x8D43427E391945E9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA260042D83CA0010ULL,
		0x0C05110FF4100480ULL,
		0x22B2C02409384280ULL,
		0x0200101231160000ULL,
		0x248800C10500A000ULL,
		0x10041264200806E0ULL,
		0x1F0044001028401DULL,
		0x0542400031094020ULL
	}};
	printf("Test Case 483\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 483 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -483;
	} else {
		printf("Test Case 483 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x634E6F319418C190ULL,
		0x8F8C957868594C37ULL,
		0x81CAE9448FBB8508ULL,
		0x8A9813E0EEB21E72ULL,
		0x91BCFB2420B51F08ULL,
		0x236C12E4D5580AFEULL,
		0x6C995793B4E5881FULL,
		0x5503725A74C29DB6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4385668935CC23B0ULL,
		0x9ACD2132C88EE26EULL,
		0x184C7B0FC4243F9CULL,
		0xD1904B8A2FEDBEBFULL,
		0x7E9FC210CF950012ULL,
		0x25F10E4842BD7092ULL,
		0x75823020E0C4124DULL,
		0xC1F876D0A994E87FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4304660114080190ULL,
		0x8A8C013048084026ULL,
		0x0048690484200508ULL,
		0x809003802EA01E32ULL,
		0x109CC20000950000ULL,
		0x2160024040180092ULL,
		0x64801000A0C4000DULL,
		0x4100725020808836ULL
	}};
	printf("Test Case 484\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 484 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -484;
	} else {
		printf("Test Case 484 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD19FE380F89E43EDULL,
		0x405F47BFBE55276FULL,
		0x3B682EA8CD05DC4CULL,
		0xB2C165BEE373B5D4ULL,
		0x1FFFFF9E690B9EA3ULL,
		0x3DEBEB9FF1460D28ULL,
		0x635B74F379C65D1AULL,
		0x7D86CE0E0866D633ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6BED58AA076FEBC1ULL,
		0x8C3C2F21DE62DFA1ULL,
		0x71DAAD41D77354F4ULL,
		0xF597D16A4C2CE202ULL,
		0x801475B0A62AB59FULL,
		0x38B779BDAC87E556ULL,
		0x3E13F635320A6268ULL,
		0x0564AF1DF2C02B0DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x418D4080000E43C1ULL,
		0x001C07219E400721ULL,
		0x31482C00C5015444ULL,
		0xB081412A4020A000ULL,
		0x00147590200A9483ULL,
		0x38A3699DA0060500ULL,
		0x2213743130024008ULL,
		0x05048E0C00400201ULL
	}};
	printf("Test Case 485\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 485 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -485;
	} else {
		printf("Test Case 485 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB5EB49B246B905A8ULL,
		0x6191FAC768F219ABULL,
		0x7743534BC81FB2A4ULL,
		0x4D3BC85331B65D61ULL,
		0x42EF674017039F32ULL,
		0x841DD5589EF851B6ULL,
		0x96B69CC3375AD105ULL,
		0x78D0244AD50C5F59ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA84CA81C80164FB7ULL,
		0xA34C4B32442EDA59ULL,
		0xFA086F811F953EF0ULL,
		0x100F248AD374FD0AULL,
		0xD55D9067ECB14E3DULL,
		0x0BCC771F1CCA7D6DULL,
		0x5A5BB8718A18B299ULL,
		0x1CC643811174999FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA0480810001005A0ULL,
		0x21004A0240221809ULL,
		0x72004301081532A0ULL,
		0x000B000211345D00ULL,
		0x404D004004010E30ULL,
		0x000C55181CC85124ULL,
		0x1212984102189001ULL,
		0x18C0000011041919ULL
	}};
	printf("Test Case 486\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 486 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -486;
	} else {
		printf("Test Case 486 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAF9D1D70B584CEE4ULL,
		0xF0A73974D33D6D99ULL,
		0x3E05301BEC5AAC05ULL,
		0x240204F4962EC648ULL,
		0xE7E22BF7C98DA7D3ULL,
		0x6270EC305600473BULL,
		0x3BB9EFF23750EFDDULL,
		0x8A567C43048EEEF2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x68EC128F40A4A4C9ULL,
		0x34791DF24762154AULL,
		0x5A1374049D819D95ULL,
		0x634C880FB5DFCFB0ULL,
		0xCCB6B1CA3164F801ULL,
		0x438D8D599493B110ULL,
		0x3640946A16EAA373ULL,
		0xB1D3877CF1664EA7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x288C1000008484C0ULL,
		0x3021197043200508ULL,
		0x1A0130008C008C05ULL,
		0x20000004940EC600ULL,
		0xC4A221C20104A001ULL,
		0x42008C1014000110ULL,
		0x320084621640A351ULL,
		0x8052044000064EA2ULL
	}};
	printf("Test Case 487\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 487 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -487;
	} else {
		printf("Test Case 487 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x058AF27AAC6CBDA2ULL,
		0x5066ECAC791046AEULL,
		0x27DEA7A84D848FBBULL,
		0x1DCC1422F588A4FEULL,
		0x2D2A5B77EFC480BBULL,
		0xE5E0DFFD76818186ULL,
		0x8C58268AC0B300C0ULL,
		0xDAC287615370D745ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1AF5B02FC82E3942ULL,
		0x9E575CAEB956454EULL,
		0x5ED0D42465171E85ULL,
		0xFCB1FA71BCAE75F8ULL,
		0xF86E07D9ED751CA3ULL,
		0x818611D9AA409F16ULL,
		0xED268315F057C6A8ULL,
		0x0DC4D987A2D8F1C6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0080B02A882C3902ULL,
		0x10464CAC3910440EULL,
		0x06D0842045040E81ULL,
		0x1C801020B48824F8ULL,
		0x282A0351ED4400A3ULL,
		0x818011D922008106ULL,
		0x8C000200C0130080ULL,
		0x08C081010250D144ULL
	}};
	printf("Test Case 488\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 488 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -488;
	} else {
		printf("Test Case 488 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1AE07B44419D5F62ULL,
		0x032B01465B1D71ECULL,
		0xBB4EF0E89F7236EDULL,
		0x4EA3D6FC79259B78ULL,
		0x65144C388C7F194DULL,
		0xD6F3EA352AC3AE53ULL,
		0x1C320AEA52172254ULL,
		0x6B4978051688BFF0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5D564328E66D9A77ULL,
		0x7A66149EE1EC1E6FULL,
		0x3F22DC0CFD0A7206ULL,
		0x20CD86CAD6798CE3ULL,
		0xD0B962DF05E73CC2ULL,
		0xC42BB78651D1506BULL,
		0x5CF8612085791063ULL,
		0xB897F716CF6A7A18ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x18404300400D1A62ULL,
		0x02220006410C106CULL,
		0x3B02D0089D023204ULL,
		0x008186C850218860ULL,
		0x4010401804671840ULL,
		0xC423A20400C10043ULL,
		0x1C30002000110040ULL,
		0x2801700406083A10ULL
	}};
	printf("Test Case 489\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 489 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -489;
	} else {
		printf("Test Case 489 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF444399AA3929019ULL,
		0x3AB57EB02D008547ULL,
		0xD5F3F2A79A41D065ULL,
		0x403BD20872C8938EULL,
		0x82FC6FA30E348D6BULL,
		0x2C1B28565D2BC911ULL,
		0xF885825E3D006FBDULL,
		0x43B536B4FAD2CAB6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x80BB6AF22C99F2C1ULL,
		0x1BE6127D3DBF4CF7ULL,
		0x5E9D21A0EA761221ULL,
		0xC59CC151AA60870EULL,
		0xE1D21DC2057737CDULL,
		0xE66EC9ECD4D6D06BULL,
		0x3470041C409AEE33ULL,
		0x890CC671770251BEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8000289220909001ULL,
		0x1AA412302D000447ULL,
		0x549120A08A401021ULL,
		0x4018C0002240830EULL,
		0x80D00D8204340549ULL,
		0x240A08445402C001ULL,
		0x3000001C00006E31ULL,
		0x01040630720240B6ULL
	}};
	printf("Test Case 490\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 490 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -490;
	} else {
		printf("Test Case 490 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0FEB4DB819E49B5EULL,
		0x95125BD178575991ULL,
		0x55DD0625B038E3EDULL,
		0xE6C687A6D24F0CB6ULL,
		0x273F859D4E04091DULL,
		0x87A2F2D7DB9EC04FULL,
		0xC55C6FF42C9FC3FEULL,
		0x4D85FE7655D0E515ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA444C2532BE6A164ULL,
		0x44845F1D8AC70D51ULL,
		0x6DCBC932D1A1ECE5ULL,
		0x786F891D32853791ULL,
		0x51230F361FAF7EB9ULL,
		0x78356D38FEE7F21BULL,
		0x29D7F329649BF49EULL,
		0x8E31A763B5EDD4DBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0440401009E48144ULL,
		0x04005B1108470911ULL,
		0x45C900209020E0E5ULL,
		0x6046810412050490ULL,
		0x012305140E040819ULL,
		0x00206010DA86C00BULL,
		0x01546320249BC09EULL,
		0x0C01A66215C0C411ULL
	}};
	printf("Test Case 491\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 491 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -491;
	} else {
		printf("Test Case 491 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x06D8CE786789DD8AULL,
		0x80220E18FC85FDE6ULL,
		0x01608972C9917FEEULL,
		0x3505562006A9FA29ULL,
		0x6BCC46566DE278E3ULL,
		0x8F39E09F32116CDEULL,
		0xB9B5FBB7E385A5C9ULL,
		0xB38902750AA065F7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x79026A432E5B15E7ULL,
		0x1EC3CBC79C6494C5ULL,
		0xFFFDB95E25FAC6D5ULL,
		0x4BAFE17CEC30F395ULL,
		0xED73982543B66CCEULL,
		0xC8CD6089E5C19671ULL,
		0xA7BFA292750B46ACULL,
		0xA365AEDAA51B126DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x00004A4026091582ULL,
		0x00020A009C0494C4ULL,
		0x01608952019046C4ULL,
		0x010540200420F201ULL,
		0x6940000441A268C2ULL,
		0x8809608920010450ULL,
		0xA1B5A29261010488ULL,
		0xA301025000000065ULL
	}};
	printf("Test Case 492\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 492 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -492;
	} else {
		printf("Test Case 492 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6AAFBDA408046B8CULL,
		0x892FD30C18C59759ULL,
		0x3343EE74D8211546ULL,
		0x54A31C6A77A3D2E9ULL,
		0xC94A5799999A46FBULL,
		0x2F13F6F92AA560E2ULL,
		0x832C8254FE4696FEULL,
		0xD7029E9F06E33C56ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBDF29D69833D5132ULL,
		0x1746344B80220129ULL,
		0x1384D6BBC2A72021ULL,
		0xB5D29BDCE15A96EBULL,
		0x6BB7E7273F812538ULL,
		0x548B2B878690D032ULL,
		0x6B8AB898A5E4D3E0ULL,
		0xA45A2020F7069CF5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x28A29D2000044100ULL,
		0x0106100800000109ULL,
		0x1300C630C0210000ULL,
		0x14821848610292E9ULL,
		0x4902470119800438ULL,
		0x0403228102804022ULL,
		0x03088010A44492E0ULL,
		0x8402000006021C54ULL
	}};
	printf("Test Case 493\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 493 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -493;
	} else {
		printf("Test Case 493 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xABF951FDD4E18AE9ULL,
		0xEE9AD66F9C0AB0D9ULL,
		0xCA5034C952386F6CULL,
		0x56B5435F43C5E8E3ULL,
		0xB1048F362CC56814ULL,
		0x90728D4BFE882243ULL,
		0xE90707BFF27E2BF0ULL,
		0x406D9D0153E77585ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x47832C0295947BB4ULL,
		0x1D4C9349A752ED36ULL,
		0x7DAF61D09A3D70F2ULL,
		0x036528073243FA19ULL,
		0xC543E28006933B59ULL,
		0xCBA224A6691228F9ULL,
		0x98E6D76C8C6D2513ULL,
		0x612AE88AD448C288ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0381000094800AA0ULL,
		0x0C0892498402A010ULL,
		0x480020C012386060ULL,
		0x022500070241E801ULL,
		0x8100820004812810ULL,
		0x8022040268002041ULL,
		0x8806072C806C2110ULL,
		0x4028880050404080ULL
	}};
	printf("Test Case 494\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 494 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -494;
	} else {
		printf("Test Case 494 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE4994BB9B89F0D69ULL,
		0x0357597217B172C4ULL,
		0x985ED20AC4844AA6ULL,
		0xE82C51279AC62FE7ULL,
		0x2C89CB974FD834C9ULL,
		0xD3DDC54AD2AD6961ULL,
		0x107F4EF635DC801EULL,
		0xC2B3C05F7B65B464ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0FD5566B9F1565C8ULL,
		0xAA0402497CBB0999ULL,
		0x85715EC89BC298A0ULL,
		0x9B2A380230337BC0ULL,
		0x4C747A2C6498E784ULL,
		0xC05424D692AB608DULL,
		0x3384F838ACFF5CE6ULL,
		0x58862CCB1218C7DFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0491422998150548ULL,
		0x0204004014B10080ULL,
		0x80505208808008A0ULL,
		0x8828100210022BC0ULL,
		0x0C004A0444982480ULL,
		0xC054044292A96001ULL,
		0x1004483024DC0006ULL,
		0x4082004B12008444ULL
	}};
	printf("Test Case 495\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 495 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -495;
	} else {
		printf("Test Case 495 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x05EB1BB35A329842ULL,
		0x915DD385D79DD05AULL,
		0xBFF3214A6BA75579ULL,
		0xF7694286B2C18797ULL,
		0x4852F6D2C649BBE9ULL,
		0xF7A46DC735359EF0ULL,
		0x972907FF5B3F103FULL,
		0x35A087E90164DA82ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0274B6DE07D5DB8DULL,
		0x01D7AE086EC7CE9CULL,
		0x53EDF4650243FC07ULL,
		0x71E9BF00432324E4ULL,
		0xA4DE946ACEED5AFFULL,
		0x4588FAE41D20964CULL,
		0xF2F9F5B87D59E5F3ULL,
		0x6F7E0057B224F73CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0060129202109800ULL,
		0x015582004685C018ULL,
		0x13E1204002035401ULL,
		0x7169020002010484ULL,
		0x00529442C6491AE9ULL,
		0x458068C415209640ULL,
		0x922905B859190033ULL,
		0x252000410024D200ULL
	}};
	printf("Test Case 496\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 496 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -496;
	} else {
		printf("Test Case 496 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7DF0903E9FC9DF02ULL,
		0xE79CF77798DC336DULL,
		0x692BB855B1EB21E5ULL,
		0xB3C6F856F2BA98FCULL,
		0xE9163B760B80E731ULL,
		0x9626808852AF5C88ULL,
		0x6D42285A9C202CD7ULL,
		0x9BD5D9F5F77AB8BDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFCD8B0AFF8AAAA73ULL,
		0x3A3CADEEFE00EB15ULL,
		0x46EBD5AF526A34C5ULL,
		0xD625C87C84C01174ULL,
		0xB14C25D2F4FC1CC8ULL,
		0x807B843B763DAE18ULL,
		0x21FCF26A9F9F5E71ULL,
		0xC61275601DBE13EAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7CD0902E98888A02ULL,
		0x221CA56698002305ULL,
		0x402B9005106A20C5ULL,
		0x9204C85480801074ULL,
		0xA104215200800400ULL,
		0x80228008522D0C08ULL,
		0x2140204A9C000C51ULL,
		0x82105160153A10A8ULL
	}};
	printf("Test Case 497\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 497 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -497;
	} else {
		printf("Test Case 497 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF772C47B383B4828ULL,
		0x4693F466A28809D4ULL,
		0xA97CA81C5826A24CULL,
		0x25522979854BC029ULL,
		0x8110ABD5D107F32BULL,
		0xFC3F41135B94501EULL,
		0x679D639BADED5606ULL,
		0xEDB92AFD235AA516ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2966C1C35CED01A5ULL,
		0xA104AA36F715D2BCULL,
		0xE452B9B2E872F9EFULL,
		0x507F255906BCF981ULL,
		0xD1E8A5A406C845B5ULL,
		0x64018CD2BBD447BEULL,
		0xFE934B9E622CF0EEULL,
		0x2A11F1CA238933C7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2162C04318290020ULL,
		0x0000A026A2000094ULL,
		0xA050A8104822A04CULL,
		0x005221590408C001ULL,
		0x8100A18400004121ULL,
		0x640100121B94401EULL,
		0x6691439A202C5006ULL,
		0x281120C823082106ULL
	}};
	printf("Test Case 498\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 498 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -498;
	} else {
		printf("Test Case 498 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7844AE26C826E085ULL,
		0xE6391D9F9F6ECEA8ULL,
		0x4F74C54FE2337031ULL,
		0x32CEB35A91634EBCULL,
		0x93359838B4A853ABULL,
		0xD83D6847DB4AFF48ULL,
		0x61BDFF082E231AFEULL,
		0x03C99660F05028CBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6A85BD9A1D999724ULL,
		0xEB65147452A12A69ULL,
		0x54DDF618C0209FD4ULL,
		0x26402376322905F1ULL,
		0x6B4316296D937BFDULL,
		0xC019DFACF6373DF4ULL,
		0x0E4D76190DA659D1ULL,
		0x812F129E8A47A272ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6804AC0208008004ULL,
		0xE221141412200A28ULL,
		0x4454C408C0201010ULL,
		0x22402352102104B0ULL,
		0x03011028248053A9ULL,
		0xC0194804D2023D40ULL,
		0x000D76080C2218D0ULL,
		0x0109120080402042ULL
	}};
	printf("Test Case 499\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 499 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -499;
	} else {
		printf("Test Case 499 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x67422B9B6F825C60ULL,
		0x2A9A47DD8A5A33F6ULL,
		0x8B645E756267FF39ULL,
		0x1139666749474ADFULL,
		0x9012D3F47B488522ULL,
		0xA54986E042FFE159ULL,
		0xFD2E926CE547A281ULL,
		0x9419158B8F69E28CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB855B32C3CD7FA07ULL,
		0xF4FD9C929F9C5A5AULL,
		0x7AE716F9AF1ED604ULL,
		0xBF756DB14D1F14E8ULL,
		0x6214AFFB312F03A5ULL,
		0x5EB3455200143193ULL,
		0xD525048C4FC01901ULL,
		0x705913DB5AB19680ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x204023082C825800ULL,
		0x209804908A181252ULL,
		0x0A6416712206D600ULL,
		0x11316421490700C8ULL,
		0x001083F031080120ULL,
		0x0401044000142111ULL,
		0xD524000C45400001ULL,
		0x1019118B0A218280ULL
	}};
	printf("Test Case 500\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 500 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -500;
	} else {
		printf("Test Case 500 PASSED\n");
	}
	printf("---\n\n");
	return 0;
}