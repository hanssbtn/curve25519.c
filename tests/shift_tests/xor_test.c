#include "../tests.h"

int32_t curve25519_key_xor_test(void) {
	printf("Key XOR Test\n");
	curve25519_key_t k1 = {.key64 = {
		0xE83CB122D2593897ULL,
		0x46EDE17B2E1FF24FULL,
		0xDA69A4D9A07C4CA3ULL,
		0x3CEE8D1861757082ULL,
		0x76F6A5E8E485CCDCULL,
		0x484D627169454163ULL,
		0xECDB2CDBE4AC5ECFULL,
		0x83B87E75D5EF7618ULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0xA9C0E09608E84262ULL,
		0xF90952880EBE3315ULL,
		0xCE55B0F921AF996DULL,
		0xCF0BFA04778CE13BULL,
		0xB21C2C90C3276DA7ULL,
		0x0D6315B608BD9015ULL,
		0x7C747CC83E15E7C2ULL,
		0x0605C1904F5676B1ULL
	}};
	curve25519_key_t k3 = {.key64 = {
		0x41FC51B4DAB17AF5ULL,
		0xBFE4B3F320A1C15AULL,
		0x143C142081D3D5CEULL,
		0xF3E5771C16F991B9ULL,
		0xC4EA897827A2A17BULL,
		0x452E77C761F8D176ULL,
		0x90AF5013DAB9B90DULL,
		0x85BDBFE59AB900A9ULL
	}};
	curve25519_key_t r = {};
	printf("Test Case 1\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x3141CCEB6BAF2BC4ULL,
		0x4115E6C2364B75F9ULL,
		0xBD2FD6C606E66715ULL,
		0x7D66CAC3A5AE206FULL,
		0xAEB897D2869F5ED1ULL,
		0x59545AE07CA02F75ULL,
		0xEED0555CE1C6635BULL,
		0x1086A15F2414C44CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD7C06B3D908513ECULL,
		0x636353B75FDEBFECULL,
		0x11ADCF7D18219122ULL,
		0x48EF1ED7D290DB21ULL,
		0x73016B4F1357DD10ULL,
		0x7DC50F75C3A09D2FULL,
		0x70DE96CC118E165EULL,
		0xCD0102A0FEA74A53ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE681A7D6FB2A3828ULL,
		0x2276B5756995CA15ULL,
		0xAC8219BB1EC7F637ULL,
		0x3589D414773EFB4EULL,
		0xDDB9FC9D95C883C1ULL,
		0x24915595BF00B25AULL,
		0x9E0EC390F0487505ULL,
		0xDD87A3FFDAB38E1FULL
	}};
	printf("Test Case 2\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x699925B4B14C3DF3ULL,
		0xBA5E53D0197681AFULL,
		0x760C3EFFB7AA7ECDULL,
		0x5C8035A992767D41ULL,
		0x2AA6609418F957A4ULL,
		0x415C04A5898CD06CULL,
		0x907D2EB763EC2463ULL,
		0x4037B6EB103AB7ECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x237A97D3BBB36147ULL,
		0x0ADD68A16670317EULL,
		0x6C30C3CE0C68DD64ULL,
		0x96B5036AD77A23BEULL,
		0xF6FB81B85F905F77ULL,
		0x6190470367449BB1ULL,
		0xF7C9BC7B81295982ULL,
		0x21F99173836CA172ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4AE3B2670AFF5CB4ULL,
		0xB0833B717F06B0D1ULL,
		0x1A3CFD31BBC2A3A9ULL,
		0xCA3536C3450C5EFFULL,
		0xDC5DE12C476908D3ULL,
		0x20CC43A6EEC84BDDULL,
		0x67B492CCE2C57DE1ULL,
		0x61CE27989356169EULL
	}};
	printf("Test Case 3\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x608ECC5180FA781DULL,
		0x1C16080A2A1DC779ULL,
		0xE9B4C9C5D4D73947ULL,
		0x3632EF978071F546ULL,
		0x24118F6EF195A156ULL,
		0x59F6EFC506B015FAULL,
		0xD7E3B841DF21DE03ULL,
		0x741EB85DB01DC3E0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA72A81279740FCB5ULL,
		0x3EBC6B582877C23CULL,
		0x1B3B4289A13F7B24ULL,
		0x33F06F7B2EFFD8D9ULL,
		0x29DD67FBA3E8491EULL,
		0x180AE3A1CF4515DFULL,
		0x76D4322ABA48FEEDULL,
		0x0EF1482E272FE82BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC7A44D7617BA84A8ULL,
		0x22AA6352026A0545ULL,
		0xF28F8B4C75E84263ULL,
		0x05C280ECAE8E2D9FULL,
		0x0DCCE895527DE848ULL,
		0x41FC0C64C9F50025ULL,
		0xA1378A6B656920EEULL,
		0x7AEFF07397322BCBULL
	}};
	printf("Test Case 4\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x6AF2238A65132DAFULL,
		0x262B358327F46735ULL,
		0x9DC1FE88400ECB20ULL,
		0xCA7B160ED8E18ADCULL,
		0xD043A335A015F58CULL,
		0xE2C0D018264D0939ULL,
		0xA964E03D07D3C842ULL,
		0x2DB7DA9F353DC0FCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2D59AEAE7D060CC6ULL,
		0x8F4B96FD6303BAA0ULL,
		0xAF19107330E0A3EAULL,
		0x482B09B204774FD9ULL,
		0x7A121798A591B7EEULL,
		0xB17A6044C861A2C7ULL,
		0x8C00E6D6422EC9D6ULL,
		0x2F4EBBE8B11FC264ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x47AB8D2418152169ULL,
		0xA960A37E44F7DD95ULL,
		0x32D8EEFB70EE68CAULL,
		0x82501FBCDC96C505ULL,
		0xAA51B4AD05844262ULL,
		0x53BAB05CEE2CABFEULL,
		0x256406EB45FD0194ULL,
		0x02F9617784220298ULL
	}};
	printf("Test Case 5\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x169A584F61D312BEULL,
		0x7A162B6ED8FCAB66ULL,
		0x3C4C5E8ED7903BCFULL,
		0x4194B2AA8512A511ULL,
		0x9FE422A782E1387CULL,
		0x436208ECFF85AA50ULL,
		0x42D31139AEDD1414ULL,
		0x17C9F11BD18B5145ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x74EC52BDD66E6B0BULL,
		0xF400393201BAF819ULL,
		0x982B0F86C203B414ULL,
		0x42EDB4F72E246D0DULL,
		0xE634EF012A47932AULL,
		0xC9DB6C0C234CDAA0ULL,
		0xAA23250AF6CBA099ULL,
		0x73480A8978957513ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x62760AF2B7BD79B5ULL,
		0x8E16125CD946537FULL,
		0xA467510815938FDBULL,
		0x0379065DAB36C81CULL,
		0x79D0CDA6A8A6AB56ULL,
		0x8AB964E0DCC970F0ULL,
		0xE8F034335816B48DULL,
		0x6481FB92A91E2456ULL
	}};
	printf("Test Case 6\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x3BD9A97C6D184F09ULL,
		0xB422992BA0535FDAULL,
		0xEC34A171FEE40964ULL,
		0x3D12320C6E94CADFULL,
		0xD7B4285114E04888ULL,
		0xD333D03BC2B5F24FULL,
		0xE5F580B435BADE47ULL,
		0x0D0748D48F462F81ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x26BD59A6AABA4C8CULL,
		0x0D3FC12A88962274ULL,
		0x152392956C83869BULL,
		0x4A91C5965D46C9D5ULL,
		0xBEEDA7B8C7309E7AULL,
		0xB4E8ABB2C7F4FCCDULL,
		0xC240069973C6F058ULL,
		0xC7748D42DA0794B8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1D64F0DAC7A20385ULL,
		0xB91D580128C57DAEULL,
		0xF91733E492678FFFULL,
		0x7783F79A33D2030AULL,
		0x69598FE9D3D0D6F2ULL,
		0x67DB7B8905410E82ULL,
		0x27B5862D467C2E1FULL,
		0xCA73C5965541BB39ULL
	}};
	printf("Test Case 7\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x78E67E2FC188BC1DULL,
		0x89E948868118A877ULL,
		0x4E4BCFC09D9ABF72ULL,
		0x2CBCF9A6E4B163FBULL,
		0x13063BB7B11230C2ULL,
		0xB2DCC3CB6D5A9D9AULL,
		0x55757B25E3065449ULL,
		0x23C8DEC78859FD29ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9DAEE6170A5EBEBDULL,
		0x14F79E6CAF3E8B55ULL,
		0xEAD0EF76A37CD663ULL,
		0x32434E5C68CBE7A5ULL,
		0x2810259764C4F2F1ULL,
		0xB8B8F25A97292FDDULL,
		0x15F8269E1EE0DD8CULL,
		0xDEBAFEFE186C09C3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE5489838CBD602A0ULL,
		0x9D1ED6EA2E262322ULL,
		0xA49B20B63EE66911ULL,
		0x1EFFB7FA8C7A845EULL,
		0x3B161E20D5D6C233ULL,
		0x0A643191FA73B247ULL,
		0x408D5DBBFDE689C5ULL,
		0xFD7220399035F4EAULL
	}};
	printf("Test Case 8\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x9FF0D0CA4A460FC6ULL,
		0xFC5090B2894EDDA3ULL,
		0xE6815657DBB22F15ULL,
		0xB54A584D72631984ULL,
		0xB15BE0A0D47B7E68ULL,
		0xFF562446CB7DF24FULL,
		0x78F494511A28B65FULL,
		0x2EF9B8E7758EE9A1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x074297F77C155755ULL,
		0x813C1E4508CB2450ULL,
		0xA6348D7DC3C820E1ULL,
		0x0B376DF5899CE1D1ULL,
		0x52B5CE50FD3874B4ULL,
		0x25CB45C2511E56DCULL,
		0x9AD34DDF6E299A7DULL,
		0x2355710BF15C94F0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x98B2473D36535893ULL,
		0x7D6C8EF78185F9F3ULL,
		0x40B5DB2A187A0FF4ULL,
		0xBE7D35B8FBFFF855ULL,
		0xE3EE2EF029430ADCULL,
		0xDA9D61849A63A493ULL,
		0xE227D98E74012C22ULL,
		0x0DACC9EC84D27D51ULL
	}};
	printf("Test Case 9\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x29EB72093D7CE91EULL,
		0xBCC818A7C598B542ULL,
		0x01155A087806B234ULL,
		0x37D61791A1343060ULL,
		0xAA76DBB584003F9AULL,
		0xB0AD37C7FA304CA4ULL,
		0x6ECCEDDC9E60C773ULL,
		0x4EFE310DCC7FCFEEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x36C9FA503B8E7EC7ULL,
		0x13C712F5E0BBEE7EULL,
		0xE6DFD1A38C2B0176ULL,
		0xF3F0A54EFD3D427EULL,
		0x699BE6C49BF98101ULL,
		0xA3DC5EF2ECFBD13CULL,
		0x82EEBEB72A681B72ULL,
		0x03B7E78DF3263F82ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1F22885906F297D9ULL,
		0xAF0F0A5225235B3CULL,
		0xE7CA8BABF42DB342ULL,
		0xC426B2DF5C09721EULL,
		0xC3ED3D711FF9BE9BULL,
		0x1371693516CB9D98ULL,
		0xEC22536BB408DC01ULL,
		0x4D49D6803F59F06CULL
	}};
	printf("Test Case 10\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xECC2C24B58BD02F1ULL,
		0x2FCA24F81847EEFFULL,
		0xF182190C489E8141ULL,
		0x2AF497CD5A510CC6ULL,
		0x4ED817616137F478ULL,
		0x5E9262EED80D205AULL,
		0xECE23DDF47E4A633ULL,
		0xE5E310432D568B2BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE74E17F1AAAB41B9ULL,
		0x1EC7C86BDCF4D978ULL,
		0xBDE9CFE705532545ULL,
		0x50E913DA827958F0ULL,
		0x8860CEC7C11080D1ULL,
		0xD355CE69E5C5D3B1ULL,
		0x8F5B8EE39C83A2E4ULL,
		0xC292E2B025E8906CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0B8CD5BAF2164348ULL,
		0x310DEC93C4B33787ULL,
		0x4C6BD6EB4DCDA404ULL,
		0x7A1D8417D8285436ULL,
		0xC6B8D9A6A02774A9ULL,
		0x8DC7AC873DC8F3EBULL,
		0x63B9B33CDB6704D7ULL,
		0x2771F2F308BE1B47ULL
	}};
	printf("Test Case 11\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xA9A111E64736260AULL,
		0xED879D9713DE2D7CULL,
		0x6741D2A2FC0AA002ULL,
		0xA39B009FB109FC6DULL,
		0x370A90A39B19F5C0ULL,
		0x0A309A2A4A9B2304ULL,
		0x3FDD2C116A2CBF18ULL,
		0x9900137F79C23AD1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7FAB4560EA1BCC15ULL,
		0xEB6186B4CEF303CDULL,
		0xF3456EFFFEEDFEBCULL,
		0x1FBD2F9CE934F062ULL,
		0x4DBB6E9D59B0C0D1ULL,
		0x61374BD8BDAF870FULL,
		0xD895A60A519FDB3FULL,
		0x22B9D43374A40F78ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD60A5486AD2DEA1FULL,
		0x06E61B23DD2D2EB1ULL,
		0x9404BC5D02E75EBEULL,
		0xBC262F03583D0C0FULL,
		0x7AB1FE3EC2A93511ULL,
		0x6B07D1F2F734A40BULL,
		0xE7488A1B3BB36427ULL,
		0xBBB9C74C0D6635A9ULL
	}};
	printf("Test Case 12\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xBFD1645A8C5CCFA2ULL,
		0x542252A5250E1A8EULL,
		0x4AA3FB0EC269C339ULL,
		0xA7CFBED7ACFE3235ULL,
		0x9F0A56DF3CD243E2ULL,
		0x503E084A5F8A4625ULL,
		0xDE5A0B6E23CEC5B1ULL,
		0xAB108CB0771ADE46ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x10022664C3374157ULL,
		0x305358DF1CA48CBFULL,
		0xE8E691A7D7DADD17ULL,
		0x572481912A16B8A4ULL,
		0xD4BCE60F8EBA0D6FULL,
		0xC4870AA86AF7DF97ULL,
		0xBE522B717DC9E196ULL,
		0xCBAEA699AE970107ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAFD3423E4F6B8EF5ULL,
		0x64710A7A39AA9631ULL,
		0xA2456AA915B31E2EULL,
		0xF0EB3F4686E88A91ULL,
		0x4BB6B0D0B2684E8DULL,
		0x94B902E2357D99B2ULL,
		0x6008201F5E072427ULL,
		0x60BE2A29D98DDF41ULL
	}};
	printf("Test Case 13\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x348D8C86E822441DULL,
		0xD3087E6BEF55E7ABULL,
		0xDF26DEBA797CDB56ULL,
		0xD80CE14E26AD9FAAULL,
		0xE1648381A21D79E6ULL,
		0x8E64D83CD83710EFULL,
		0x278050AF193D97E8ULL,
		0xBB14ACF51CA3D7C4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x51B41283017866CDULL,
		0x222E5A6BE153A280ULL,
		0x54C8A32732F7096FULL,
		0x6A3B33EEC2548F50ULL,
		0xCCAD30A311A23C71ULL,
		0x3332F7640DB9B964ULL,
		0xC18B536748073133ULL,
		0xBB73E428EBB61F0DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x65399E05E95A22D0ULL,
		0xF12624000E06452BULL,
		0x8BEE7D9D4B8BD239ULL,
		0xB237D2A0E4F910FAULL,
		0x2DC9B322B3BF4597ULL,
		0xBD562F58D58EA98BULL,
		0xE60B03C8513AA6DBULL,
		0x006748DDF715C8C9ULL
	}};
	printf("Test Case 14\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xEDD4EC8D02585741ULL,
		0x4C99A9A3AE18D4F7ULL,
		0xD3E19E9D51A2DC8FULL,
		0xEA37DAE94DBA08BEULL,
		0x43E0EACD4DC6ECA7ULL,
		0x761D23B59F7DB668ULL,
		0x8F3E7BBBD19DA037ULL,
		0xAFB02F6BA18DD946ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x82A9C2EBD48DCD07ULL,
		0xAFACDE15CCA1C0FDULL,
		0x6DB9AE6A0BB4E6A2ULL,
		0x628D2D8BE04D8574ULL,
		0x0881D7DBAC8D477FULL,
		0x01F6314A1886546AULL,
		0x717F0AAD9F9D41A6ULL,
		0xE009DDBE7A8132A1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6F7D2E66D6D59A46ULL,
		0xE33577B662B9140AULL,
		0xBE5830F75A163A2DULL,
		0x88BAF762ADF78DCAULL,
		0x4B613D16E14BABD8ULL,
		0x77EB12FF87FBE202ULL,
		0xFE4171164E00E191ULL,
		0x4FB9F2D5DB0CEBE7ULL
	}};
	printf("Test Case 15\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x4CE55B778E40BAE7ULL,
		0x8640391B7EA9CAD1ULL,
		0x270EE2BAD6D02F7DULL,
		0x59C8DDD1806F5E04ULL,
		0xDC40CAFCC592613EULL,
		0x1C073FC0A6674FF0ULL,
		0xD49BDC1C73570D25ULL,
		0x8BD9C0C84C470C91ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5DA010C204DC9876ULL,
		0xCE78A1EE7798D470ULL,
		0xDF8AD7D4AD2F1A8DULL,
		0xC11A2B502C5EDF37ULL,
		0x66481D3903773372ULL,
		0x0802C2D4EAC65698ULL,
		0x9F0FAEC4F0626608ULL,
		0xB9DB05FAF25D4C65ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x11454BB58A9C2291ULL,
		0x483898F509311EA1ULL,
		0xF884356E7BFF35F0ULL,
		0x98D2F681AC318133ULL,
		0xBA08D7C5C6E5524CULL,
		0x1405FD144CA11968ULL,
		0x4B9472D883356B2DULL,
		0x3202C532BE1A40F4ULL
	}};
	printf("Test Case 16\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xD14DFC47A9411ED9ULL,
		0xCF159C64FE6AC419ULL,
		0xC207E9B0DE56EA54ULL,
		0x9FBB65324452BF6BULL,
		0x34BD46DB9AE9ED73ULL,
		0xFE0332C505305F7CULL,
		0x50151325F8BBAF6CULL,
		0xE5EEEBCEB7D2F5B6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5FBB7F45F2C54CDEULL,
		0x1D31E69E6EE66C99ULL,
		0x576693AB307938C0ULL,
		0x055B7C359B94303EULL,
		0x55FE34F054A6D706ULL,
		0x5404A09B5DC37CA2ULL,
		0xA5EEA1FD58723E35ULL,
		0xFA67A977664350A0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8EF683025B845207ULL,
		0xD2247AFA908CA880ULL,
		0x95617A1BEE2FD294ULL,
		0x9AE01907DFC68F55ULL,
		0x6143722BCE4F3A75ULL,
		0xAA07925E58F323DEULL,
		0xF5FBB2D8A0C99159ULL,
		0x1F8942B9D191A516ULL
	}};
	printf("Test Case 17\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xB4F3557CD4B42097ULL,
		0xBE3B513138868FD0ULL,
		0x55866568EE39C1F2ULL,
		0x40204FB67C4324D6ULL,
		0xC2C14B67F72363B2ULL,
		0xE47B29D007262ED3ULL,
		0xA9F831D12805C862ULL,
		0xA3D226061025FF5EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEA9F43C46E8A2F86ULL,
		0x7151EE8DA9F39284ULL,
		0x814F814D89D39128ULL,
		0x4AD66F8582C2235BULL,
		0x4C7053DA9F2ECF07ULL,
		0x7C946AE5A03585C4ULL,
		0xEA7BEA9CF4614364ULL,
		0x158A9705DB346503ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5E6C16B8BA3E0F11ULL,
		0xCF6ABFBC91751D54ULL,
		0xD4C9E42567EA50DAULL,
		0x0AF62033FE81078DULL,
		0x8EB118BD680DACB5ULL,
		0x98EF4335A713AB17ULL,
		0x4383DB4DDC648B06ULL,
		0xB658B103CB119A5DULL
	}};
	printf("Test Case 18\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x6089F26E7B5B5259ULL,
		0x4A0DDF5E37FCDA38ULL,
		0xB7EC1A1812BB2B55ULL,
		0xEDFA950254A5017CULL,
		0x4E9FA8F310A24C70ULL,
		0x4549C551594A78D9ULL,
		0x8474B0510A1F1C50ULL,
		0x62A5FF649823A65FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x90994B3AA0A74BE4ULL,
		0x4BAF2D0A17705605ULL,
		0xC4FBAA6FD0ABBC68ULL,
		0xEF181604965C8408ULL,
		0x271FCA0EB81CA953ULL,
		0x72599853EA78D6BBULL,
		0x95C4A84A061A759CULL,
		0x26951C0451BBB50DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF010B954DBFC19BDULL,
		0x01A2F254208C8C3DULL,
		0x7317B077C210973DULL,
		0x02E28306C2F98574ULL,
		0x698062FDA8BEE523ULL,
		0x37105D02B332AE62ULL,
		0x11B0181B0C0569CCULL,
		0x4430E360C9981352ULL
	}};
	printf("Test Case 19\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xFB4FD022F157381DULL,
		0x879EE30394A530AFULL,
		0x248064ADBD8E69E0ULL,
		0x89F643262EB301C1ULL,
		0x264D6542F5EBBB3DULL,
		0xB405D92F3DA63D8CULL,
		0x4950317B268D3640ULL,
		0xA76797920198986EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x45975E014B7F02F1ULL,
		0x892C4C8F5D66794DULL,
		0xBF6105E1E14EE3D6ULL,
		0x878D6EBCFFDC02EDULL,
		0x7CEA4C02F9BD29D2ULL,
		0x2752B8AE8ACDC313ULL,
		0xEDC0272BB3E7F826ULL,
		0xCA362D0C79BADB23ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBED88E23BA283AECULL,
		0x0EB2AF8CC9C349E2ULL,
		0x9BE1614C5CC08A36ULL,
		0x0E7B2D9AD16F032CULL,
		0x5AA729400C5692EFULL,
		0x93576181B76BFE9FULL,
		0xA4901650956ACE66ULL,
		0x6D51BA9E7822434DULL
	}};
	printf("Test Case 20\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x4FABD8DCCB66BF86ULL,
		0xDD1CC05175400FC7ULL,
		0xD395A2F79311E89EULL,
		0x9BABC19D5F4EC819ULL,
		0x66974A397DE20689ULL,
		0xA974BEDF1744606BULL,
		0x229A90BF92F42E86ULL,
		0x78ACAB92E0D5D291ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBFDBAEA694E345A3ULL,
		0x18AA7AEFD0C74C82ULL,
		0x6B9810F9982F482AULL,
		0xBFF81D5E2C5957BBULL,
		0x878666037D243F2BULL,
		0x84937C2816AE07D1ULL,
		0xA691854A1378DD6BULL,
		0x326CE50F9F9CD370ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF070767A5F85FA25ULL,
		0xC5B6BABEA5874345ULL,
		0xB80DB20E0B3EA0B4ULL,
		0x2453DCC373179FA2ULL,
		0xE1112C3A00C639A2ULL,
		0x2DE7C2F701EA67BAULL,
		0x840B15F5818CF3EDULL,
		0x4AC04E9D7F4901E1ULL
	}};
	printf("Test Case 21\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x233088A870584135ULL,
		0xAF20FF0A9E9EE46DULL,
		0xD4D4298FEBE29842ULL,
		0xE6924CE11BCAD648ULL,
		0x27BEC05501185024ULL,
		0xFB0B3003B943927FULL,
		0xBC5DAD94F4499E9AULL,
		0xAA03DE009A322D07ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC0E2FE644C84A03CULL,
		0xC70E5CFD2CC3959DULL,
		0x86A25EDADBAA9815ULL,
		0x34AC2529D8C4D2CBULL,
		0xC67D0176A5658403ULL,
		0x28D2896DCB5F3106ULL,
		0x1CDCA144FB1A9320ULL,
		0x9E297B9708A30CA5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE3D276CC3CDCE109ULL,
		0x682EA3F7B25D71F0ULL,
		0x5276775530480057ULL,
		0xD23E69C8C30E0483ULL,
		0xE1C3C123A47DD427ULL,
		0xD3D9B96E721CA379ULL,
		0xA0810CD00F530DBAULL,
		0x342AA597929121A2ULL
	}};
	printf("Test Case 22\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x3054D9ACEAEED7C6ULL,
		0xC00BDBCAA9307F7BULL,
		0x35031E4271BF08C0ULL,
		0x80F1CF355C738D34ULL,
		0xD27AC6F80190349EULL,
		0xE52CA5F5504B89C2ULL,
		0xB94E95E7BA3386ADULL,
		0x4E77D3F5065741DBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF206B87EFD20A0CBULL,
		0x32710F6420098C7BULL,
		0x244BABE0FBE5FDCEULL,
		0x779B8E79301A1EF2ULL,
		0xA34BE35946EA2A39ULL,
		0x36224F4BE8F0E4BFULL,
		0x68040D52ED37B57AULL,
		0x687680B616E9C343ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC25261D217CE770DULL,
		0xF27AD4AE8939F300ULL,
		0x1148B5A28A5AF50EULL,
		0xF76A414C6C6993C6ULL,
		0x713125A1477A1EA7ULL,
		0xD30EEABEB8BB6D7DULL,
		0xD14A98B5570433D7ULL,
		0x2601534310BE8298ULL
	}};
	printf("Test Case 23\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xDE535E7FA28E39DBULL,
		0xF9890ED725F00D4BULL,
		0xF873A0E53C8E819DULL,
		0xBB8BBAD1140B0FE9ULL,
		0x052EE8FA1355DF6BULL,
		0xCEA0AD9EFF664714ULL,
		0x89B021E5A4B830D5ULL,
		0x9BD23503B0823565ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4B95188A9EAB7191ULL,
		0x64206C363E616369ULL,
		0xB91A6B5DD5C2186EULL,
		0x79FE516CB0B07BB6ULL,
		0x0CC2BD3E8FFE075FULL,
		0x1817983814A6F157ULL,
		0x5F9C0365CF7F6E62ULL,
		0x1118646C5784E14BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x95C646F53C25484AULL,
		0x9DA962E11B916E22ULL,
		0x4169CBB8E94C99F3ULL,
		0xC275EBBDA4BB745FULL,
		0x09EC55C49CABD834ULL,
		0xD6B735A6EBC0B643ULL,
		0xD62C22806BC75EB7ULL,
		0x8ACA516FE706D42EULL
	}};
	printf("Test Case 24\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x116A845A545E336DULL,
		0xD10DD7D986330535ULL,
		0x5881D4FA60C765A2ULL,
		0x6AAB0F136A9085C7ULL,
		0x6BA929CA349FE9E9ULL,
		0x299B4DF2184B7B21ULL,
		0x474BE1191013BDF1ULL,
		0x2E89A96DAB284ED9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x39FA1A8CF69885F4ULL,
		0x03101B356A31564BULL,
		0x9B503C0FF81BFFA2ULL,
		0x7D07C436C5DA8308ULL,
		0x8A04A7F28A6F01E3ULL,
		0xA62A1657BCE05312ULL,
		0xCAAE9178322F5882ULL,
		0xB76F8DA69AF76400ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x28909ED6A2C6B699ULL,
		0xD21DCCECEC02537EULL,
		0xC3D1E8F598DC9A00ULL,
		0x17ACCB25AF4A06CFULL,
		0xE1AD8E38BEF0E80AULL,
		0x8FB15BA5A4AB2833ULL,
		0x8DE57061223CE573ULL,
		0x99E624CB31DF2AD9ULL
	}};
	printf("Test Case 25\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xCA0E20B658F15534ULL,
		0xB2505218EBCEA60DULL,
		0x5750051816271A03ULL,
		0x605EB7F147C5CA43ULL,
		0x8C6F62B7FC6897F6ULL,
		0x63A223AC81C93DB3ULL,
		0x63C05B29EE746788ULL,
		0xDB45E6A823B1E302ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3BE344C8F6C81FBBULL,
		0xE56781F3CED373E1ULL,
		0xDA4651759733CFA7ULL,
		0x916A3389893B8642ULL,
		0xC6D19C935C1EEF88ULL,
		0xABF67934C25CF2EEULL,
		0x375DF3DA36EF42D6ULL,
		0xCF9F7C6CA8FA9B38ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF1ED647EAE394A8FULL,
		0x5737D3EB251DD5ECULL,
		0x8D16546D8114D5A4ULL,
		0xF1348478CEFE4C01ULL,
		0x4ABEFE24A076787EULL,
		0xC8545A984395CF5DULL,
		0x549DA8F3D89B255EULL,
		0x14DA9AC48B4B783AULL
	}};
	printf("Test Case 26\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x64FB597CE80DEA35ULL,
		0x0B4F51CF87343957ULL,
		0x921AAA0B0C53734BULL,
		0x2349740AD4A250D5ULL,
		0x297F2AAA171359C1ULL,
		0x5392ECB71092063BULL,
		0xA28E32531C755088ULL,
		0x483E56131AF8A91FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0622F1D8C461F2F5ULL,
		0xFC8AB34F8F23C0B4ULL,
		0x58DE15C1A9449F9CULL,
		0x2E3CFFC993623318ULL,
		0x42E05FC46EBAA6E5ULL,
		0x0194019C3DD46A94ULL,
		0x5019A2B0D34ECCD7ULL,
		0x69229802B69BDA86ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x62D9A8A42C6C18C0ULL,
		0xF7C5E2800817F9E3ULL,
		0xCAC4BFCAA517ECD7ULL,
		0x0D758BC347C063CDULL,
		0x6B9F756E79A9FF24ULL,
		0x5206ED2B2D466CAFULL,
		0xF29790E3CF3B9C5FULL,
		0x211CCE11AC637399ULL
	}};
	printf("Test Case 27\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x8C6647D099AA078FULL,
		0xFD48351A866C52BBULL,
		0xFAFA9722448BC075ULL,
		0x6BE6060A59947115ULL,
		0x558D6A62C26420CBULL,
		0x75A56482205F4913ULL,
		0x48DBD12948532878ULL,
		0x7197B87C05007023ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2E6B378F7D886429ULL,
		0x390BEB2C93407A73ULL,
		0x60EC724FD37B8AFCULL,
		0xD9CDA069EDCA18F8ULL,
		0x98E3BEDD12650034ULL,
		0x663574C5E4BD4286ULL,
		0xD336A91F60D703E1ULL,
		0x8DFB9FAA60D3E8D4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA20D705FE42263A6ULL,
		0xC443DE36152C28C8ULL,
		0x9A16E56D97F04A89ULL,
		0xB22BA663B45E69EDULL,
		0xCD6ED4BFD00120FFULL,
		0x13901047C4E20B95ULL,
		0x9BED783628842B99ULL,
		0xFC6C27D665D398F7ULL
	}};
	printf("Test Case 28\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x35AEA704F5C9F34FULL,
		0x87E05012052F2213ULL,
		0x878A3B3ADFA90CBFULL,
		0xFF10C403A9B2D07BULL,
		0xF3B1C9DB0C0E3ACEULL,
		0x0C41CE491D462D05ULL,
		0x09AEE3D7B28AFD24ULL,
		0x2DD7EB9D25591BB1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFCDF7FAE97F9F2CDULL,
		0xB830E64B20DD7774ULL,
		0xBD4294AB1B6B54E0ULL,
		0x49DC9745046E7817ULL,
		0x78C4CBDF41B68AC2ULL,
		0xC7922142D3C9E806ULL,
		0xBDF6CE94337A7EC0ULL,
		0x7D4C83A74459AF96ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC971D8AA62300182ULL,
		0x3FD0B65925F25567ULL,
		0x3AC8AF91C4C2585FULL,
		0xB6CC5346ADDCA86CULL,
		0x8B7502044DB8B00CULL,
		0xCBD3EF0BCE8FC503ULL,
		0xB4582D4381F083E4ULL,
		0x509B683A6100B427ULL
	}};
	printf("Test Case 29\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x624AE93735F8287CULL,
		0xEB765B9E3ED40CE3ULL,
		0x6FA89C058F8C0750ULL,
		0x619157BDE43A27D6ULL,
		0xE5FC56D60E04C652ULL,
		0xBB946AEB1816F34EULL,
		0xBF9F161BC2AE8CCBULL,
		0x328FCE24134F33DDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA7207138D7565B55ULL,
		0xB68EA213A358BFBBULL,
		0xD46728C92946C518ULL,
		0x17D11D99192D170BULL,
		0x689F62F671DD7C67ULL,
		0x03481034AB0AD378ULL,
		0x1821507DE54C3D22ULL,
		0x81AC7F1542927F73ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC56A980FE2AE7329ULL,
		0x5DF8F98D9D8CB358ULL,
		0xBBCFB4CCA6CAC248ULL,
		0x76404A24FD1730DDULL,
		0x8D6334207FD9BA35ULL,
		0xB8DC7ADFB31C2036ULL,
		0xA7BE466627E2B1E9ULL,
		0xB323B13151DD4CAEULL
	}};
	printf("Test Case 30\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xC227655BC7693918ULL,
		0xBABB899E2244D41EULL,
		0x669FB827A3256165ULL,
		0x8003F3B479C5D534ULL,
		0x887438DFAA14D7D3ULL,
		0x5F1AAAD337B19CC8ULL,
		0x1AFD777987A3A6CAULL,
		0xB4CA7EEA7F5CEDEBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD68F78E36313E70AULL,
		0x7B939216865B09D3ULL,
		0x4B1B6AA9D5438606ULL,
		0xAC37AE103373D19EULL,
		0x159277E6492561A2ULL,
		0xC7AC03426DBD31AFULL,
		0xD8780D3976554BE8ULL,
		0x74A6BF1DC1550C7EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x14A81DB8A47ADE12ULL,
		0xC1281B88A41FDDCDULL,
		0x2D84D28E7666E763ULL,
		0x2C345DA44AB604AAULL,
		0x9DE64F39E331B671ULL,
		0x98B6A9915A0CAD67ULL,
		0xC2857A40F1F6ED22ULL,
		0xC06CC1F7BE09E195ULL
	}};
	printf("Test Case 31\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x2269584820AB916DULL,
		0x0C41A429B48B8A3EULL,
		0x61C2701ED20EC15DULL,
		0x4F02084D188D4D40ULL,
		0x8E7BA486A535DCE7ULL,
		0xDF79B5F57B85E7D2ULL,
		0x959AB074790D19FDULL,
		0x0822C0E7404F69C0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC5060DF4D45FDCC2ULL,
		0x9763F9D2A721E191ULL,
		0x898422A3B360A579ULL,
		0x830227C699C16A5AULL,
		0x46E6DAE4D1CFA62FULL,
		0x317A19079983C275ULL,
		0x5F72BF7FDF004586ULL,
		0x85CF7C7E73876D06ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE76F55BCF4F44DAFULL,
		0x9B225DFB13AA6BAFULL,
		0xE84652BD616E6424ULL,
		0xCC002F8B814C271AULL,
		0xC89D7E6274FA7AC8ULL,
		0xEE03ACF2E20625A7ULL,
		0xCAE80F0BA60D5C7BULL,
		0x8DEDBC9933C804C6ULL
	}};
	printf("Test Case 32\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x62FA7A48C02E9BEAULL,
		0x628E379B0A21CD19ULL,
		0x0DEA3B9D6F3DECFCULL,
		0x3C47C2F295EE05DBULL,
		0x6AD9BE580E3632D1ULL,
		0x6B10A1134720B6E3ULL,
		0x8C70830C67789609ULL,
		0x07E247A7CF995E1BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDB6C2E8A8C87E96AULL,
		0x28562AD88C6C0B3FULL,
		0x262A77D6609E5A6EULL,
		0xC3A2DF3A0BDF75F2ULL,
		0x4847C8A53175971CULL,
		0xE7C1406CAE4B08D3ULL,
		0x7B13D882AB5ADA96ULL,
		0x14B0A88173580207ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB99654C24CA97280ULL,
		0x4AD81D43864DC626ULL,
		0x2BC04C4B0FA3B692ULL,
		0xFFE51DC89E317029ULL,
		0x229E76FD3F43A5CDULL,
		0x8CD1E17FE96BBE30ULL,
		0xF7635B8ECC224C9FULL,
		0x1352EF26BCC15C1CULL
	}};
	printf("Test Case 33\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x6B5B86F3FB692F69ULL,
		0x1A8220FF2FBF805DULL,
		0x001D163F54A22B20ULL,
		0x8C1C6B14E14772B4ULL,
		0x248364113CE3B538ULL,
		0x9EDCA6AB565A7C9AULL,
		0x686EA7BDC9AC1715ULL,
		0x59BBEA992933FF2CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7CD2B36D2E680696ULL,
		0x5DF47C6A4DE65E2EULL,
		0x52488E06C67EF8F4ULL,
		0xC1FF5A905A2073D7ULL,
		0x430657538C9EA5C2ULL,
		0x89584135A7EB9B6CULL,
		0x2CAC2A516377B3D2ULL,
		0x99A4FE36822522F3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1789359ED50129FFULL,
		0x47765C956259DE73ULL,
		0x5255983992DCD3D4ULL,
		0x4DE33184BB670163ULL,
		0x67853342B07D10FAULL,
		0x1784E79EF1B1E7F6ULL,
		0x44C28DECAADBA4C7ULL,
		0xC01F14AFAB16DDDFULL
	}};
	printf("Test Case 34\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x34DE56BD3DF2ADE3ULL,
		0xB6869AEA20265875ULL,
		0x7EA61EB3D69BCAEDULL,
		0xBD458861E206E05DULL,
		0x7588B6BE51EE0BDAULL,
		0x243D4F7450C87D9AULL,
		0x500DE34720C6C0C9ULL,
		0xCA9BECF8943B1672ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBDAF1D3CA7FA5F46ULL,
		0x98CA405DB0D584A9ULL,
		0xE62F28AE0E4A367BULL,
		0x6C6E999464B5D152ULL,
		0x3871A6E2C05888DDULL,
		0x4072E049FBF3F18FULL,
		0x1EBB468EF2C7C900ULL,
		0xE014CA7892336012ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x89714B819A08F2A5ULL,
		0x2E4CDAB790F3DCDCULL,
		0x9889361DD8D1FC96ULL,
		0xD12B11F586B3310FULL,
		0x4DF9105C91B68307ULL,
		0x644FAF3DAB3B8C15ULL,
		0x4EB6A5C9D20109C9ULL,
		0x2A8F268006087660ULL
	}};
	printf("Test Case 35\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x7A58EF3DB4010ECEULL,
		0x6838E819C8740EB8ULL,
		0xEE2FAF8AC09EE7D3ULL,
		0x8C6C1D103A3DE227ULL,
		0xEDCC0A790B51C7D0ULL,
		0xB1A13CAD0F037824ULL,
		0xB50C83EE5EC547C5ULL,
		0x979DBB2C8480CDF6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x27BE2609A53729FBULL,
		0x0240E903CEC89983ULL,
		0x289CCAD2AF72EB9DULL,
		0xE805DD9FC4D7B855ULL,
		0x2B7F8582093B614FULL,
		0x910326CE1F4E7503ULL,
		0xC7DA91A3F3C6228FULL,
		0x0E51F07D5E67B66CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5DE6C93411362735ULL,
		0x6A78011A06BC973BULL,
		0xC6B365586FEC0C4EULL,
		0x6469C08FFEEA5A72ULL,
		0xC6B38FFB026AA69FULL,
		0x20A21A63104D0D27ULL,
		0x72D6124DAD03654AULL,
		0x99CC4B51DAE77B9AULL
	}};
	printf("Test Case 36\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x642D015260469024ULL,
		0x6EB99143EF0FF617ULL,
		0x6B7A06252E8270F5ULL,
		0x0DA9BA4730867E5AULL,
		0x83AA2A12D12937EBULL,
		0x46383D400D58A78BULL,
		0x4EA10E7B4F47CCF2ULL,
		0xE0173771EE7ECDE6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF2881714267C9C43ULL,
		0x0EEA584DDFFA92AFULL,
		0x0015AE42E9FCAF82ULL,
		0x369EA41AB0F9E1D1ULL,
		0x4BEF85FFC070C5E7ULL,
		0xC4285DA22815AB8FULL,
		0x577F640EDA000A46ULL,
		0xDC80204325C8F724ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x96A51646463A0C67ULL,
		0x6053C90E30F564B8ULL,
		0x6B6FA867C77EDF77ULL,
		0x3B371E5D807F9F8BULL,
		0xC845AFED1159F20CULL,
		0x821060E2254D0C04ULL,
		0x19DE6A759547C6B4ULL,
		0x3C971732CBB63AC2ULL
	}};
	printf("Test Case 37\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x2A6A50785FAC85EFULL,
		0x08B25309128763BAULL,
		0xB2527C6740F205A8ULL,
		0x6B311606714EC9FBULL,
		0x224A903ADCCE8750ULL,
		0xD63B6AE6E3F674E0ULL,
		0x8AD53EBF072626C3ULL,
		0xE8FD1A9AA5B931C1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6364058F021D402EULL,
		0x663FF835C24405AEULL,
		0x5F8355865486CE19ULL,
		0xF9136877DFC9F13EULL,
		0x0124EA8E34642895ULL,
		0xE85A061F0AFB4D62ULL,
		0xD5CE3F11531EAAAAULL,
		0x46BFA77412EF94B4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x490E55F75DB1C5C1ULL,
		0x6E8DAB3CD0C36614ULL,
		0xEDD129E11474CBB1ULL,
		0x92227E71AE8738C5ULL,
		0x236E7AB4E8AAAFC5ULL,
		0x3E616CF9E90D3982ULL,
		0x5F1B01AE54388C69ULL,
		0xAE42BDEEB756A575ULL
	}};
	printf("Test Case 38\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x8D4EB79D12B4184DULL,
		0x398396CF594CA69EULL,
		0x697F7D05413D2C3CULL,
		0xE32DDBBF08B7C375ULL,
		0x5E0DD6FB5CD5CEFFULL,
		0x39ECC55C42B80D48ULL,
		0x4D3F97448B705AD0ULL,
		0xA3B9683DF9137EFFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x87FB66277AAB6080ULL,
		0x8D60E90C38FB41EAULL,
		0x3AE37A9705E29F02ULL,
		0x176C7E99355C9530ULL,
		0xD6B379B4CE94914FULL,
		0x0E7C83BBC171C4CDULL,
		0x27FA74A6D91F854DULL,
		0x96E103204FA43C1CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0AB5D1BA681F78CDULL,
		0xB4E37FC361B7E774ULL,
		0x539C079244DFB33EULL,
		0xF441A5263DEB5645ULL,
		0x88BEAF4F92415FB0ULL,
		0x379046E783C9C985ULL,
		0x6AC5E3E2526FDF9DULL,
		0x35586B1DB6B742E3ULL
	}};
	printf("Test Case 39\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x93A3670579B59D35ULL,
		0xC412B66783727BB3ULL,
		0x0E81963C1BCB0811ULL,
		0x67C6285C9C07DA56ULL,
		0x6D80A3102C948317ULL,
		0xB58F36D9E6952532ULL,
		0x3AC36F347EF054F6ULL,
		0xC3A35919423E3191ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCBCB86CDA6CDF4F1ULL,
		0x25E6E4D656196DD2ULL,
		0xE096DA2DF7CAEA2AULL,
		0xF1C92E83E9F14183ULL,
		0x3819275E0B53650FULL,
		0x53CE732610408103ULL,
		0xFAB514F75FB4A515ULL,
		0x8048B196679B76E6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5868E1C8DF7869C4ULL,
		0xE1F452B1D56B1661ULL,
		0xEE174C11EC01E23BULL,
		0x960F06DF75F69BD5ULL,
		0x5599844E27C7E618ULL,
		0xE64145FFF6D5A431ULL,
		0xC0767BC32144F1E3ULL,
		0x43EBE88F25A54777ULL
	}};
	printf("Test Case 40\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x81CD8E3BA6C5AE16ULL,
		0xABF4A41E23C15F36ULL,
		0x2BA8264E5AC8AA58ULL,
		0x2D783DE78F4E34DCULL,
		0xE4D46E6D16A19DA8ULL,
		0x00489B8882515248ULL,
		0x92C93235E598BBA0ULL,
		0xEC5D8D71017245C3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF6230CC477D7F961ULL,
		0x16457540FEF44CE2ULL,
		0x11CF0DF92B515119ULL,
		0x98A2DFF2A6ABDC16ULL,
		0x60E55FF822599A5FULL,
		0x9DA21049994F0ED5ULL,
		0x24872BFBA0FF7B65ULL,
		0x5797576DE846567BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x77EE82FFD1125777ULL,
		0xBDB1D15EDD3513D4ULL,
		0x3A672BB77199FB41ULL,
		0xB5DAE21529E5E8CAULL,
		0x8431319534F807F7ULL,
		0x9DEA8BC11B1E5C9DULL,
		0xB64E19CE4567C0C5ULL,
		0xBBCADA1CE93413B8ULL
	}};
	printf("Test Case 41\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x50C7D05D866A72CEULL,
		0xFC7702747B6B68D3ULL,
		0xD80828833EC6E24BULL,
		0x334F71B51C057182ULL,
		0x5492CD19212F5C2CULL,
		0x59B826BC56908778ULL,
		0x3EA5354EE892FE01ULL,
		0x8C89356DFD26F27CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4C79B27044AC15BAULL,
		0x49C4E75E4C1C48BDULL,
		0x4E467E1945EEEA2DULL,
		0x2769CF87CE0F1761ULL,
		0xD99191BAF3749802ULL,
		0xD2FB70254FA7F2B9ULL,
		0x8E9E883AB6DE60DAULL,
		0x858A0E9B9366F9F1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1CBE622DC2C66774ULL,
		0xB5B3E52A3777206EULL,
		0x964E569A7B280866ULL,
		0x1426BE32D20A66E3ULL,
		0x8D035CA3D25BC42EULL,
		0x8B435699193775C1ULL,
		0xB03BBD745E4C9EDBULL,
		0x09033BF66E400B8DULL
	}};
	printf("Test Case 42\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xF394534E7B7D0040ULL,
		0xE89E95B250101B85ULL,
		0x725BC100EEA127FAULL,
		0x8E09A977E0304614ULL,
		0xD91FB56E89501350ULL,
		0xF93D11909F8D2849ULL,
		0xE1FC69EE8A05B9ABULL,
		0x63061C0900585546ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC625F284E8D778ADULL,
		0x28AF60427774160CULL,
		0xE2B0DA611109F898ULL,
		0x2F089E9561EEC278ULL,
		0x68DFBE717A0233A4ULL,
		0x9996C010B2AD5CE7ULL,
		0x6C9C14155E87D978ULL,
		0x93C868188C98A0DAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x35B1A1CA93AA78EDULL,
		0xC031F5F027640D89ULL,
		0x90EB1B61FFA8DF62ULL,
		0xA10137E281DE846CULL,
		0xB1C00B1FF35220F4ULL,
		0x60ABD1802D2074AEULL,
		0x8D607DFBD48260D3ULL,
		0xF0CE74118CC0F59CULL
	}};
	printf("Test Case 43\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x10610FD5AD4337F2ULL,
		0xB460F622431C9431ULL,
		0xECAC6CFBB3FBA7A3ULL,
		0xE4C57834881F3EEAULL,
		0xE8202FCCB7F06F80ULL,
		0x8729C1F5C6156AF6ULL,
		0x944506500383F590ULL,
		0xC93B379913EC10A0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x34C365552A238212ULL,
		0x6EE1746D1A4249E0ULL,
		0xC3C8A2D26B1B31D4ULL,
		0xCBE5B1AA8A13BFEFULL,
		0x6B8DD01C9BC95925ULL,
		0x0161A1503869B424ULL,
		0x9F5245DE87058B29ULL,
		0xDCB5960B842D8D04ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x24A26A808760B5E0ULL,
		0xDA81824F595EDDD1ULL,
		0x2F64CE29D8E09677ULL,
		0x2F20C99E020C8105ULL,
		0x83ADFFD02C3936A5ULL,
		0x864860A5FE7CDED2ULL,
		0x0B17438E84867EB9ULL,
		0x158EA19297C19DA4ULL
	}};
	printf("Test Case 44\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x27349571037E47F7ULL,
		0xF9B7F0F29CB9B4BCULL,
		0x9B10D029ABAC69A4ULL,
		0x89D62F1408D6C36BULL,
		0xA364CBE460BBA3EDULL,
		0xEBCED59DF014AF28ULL,
		0x84AF146132D99137ULL,
		0xF0D12FF35B31A4DAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x631EA6DED4D0D82DULL,
		0xBAFC81539161CFF2ULL,
		0xED7F5A7007F525CDULL,
		0x5436760A4C5C0997ULL,
		0x320714ED2D1580F5ULL,
		0x7DCEE4FCD1D6FBADULL,
		0x7D68DCF17567577BULL,
		0xB76AA2F30FD4EB80ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x442A33AFD7AE9FDAULL,
		0x434B71A10DD87B4EULL,
		0x766F8A59AC594C69ULL,
		0xDDE0591E448ACAFCULL,
		0x9163DF094DAE2318ULL,
		0x9600316121C25485ULL,
		0xF9C7C89047BEC64CULL,
		0x47BB8D0054E54F5AULL
	}};
	printf("Test Case 45\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xFF033AA58DA98010ULL,
		0x4BCFC3E647418697ULL,
		0x92704757D3CCEACFULL,
		0x987EB2A2A14D3A9CULL,
		0xE3B5A4C94FF31EBCULL,
		0xD4B6E75832F14325ULL,
		0x94B3F480721FD6F0ULL,
		0x2A0397174346E9BAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6BFF72890F0DE220ULL,
		0x7D4FEC96BE145691ULL,
		0xB31F0CAD26EADD2CULL,
		0x5DE806427475886CULL,
		0xC45F58F697660985ULL,
		0x4B048BE86B43297BULL,
		0xA107C3409B425BB0ULL,
		0xFAA9E05FFEFE9895ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x94FC482C82A46230ULL,
		0x36802F70F955D006ULL,
		0x216F4BFAF52637E3ULL,
		0xC596B4E0D538B2F0ULL,
		0x27EAFC3FD8951739ULL,
		0x9FB26CB059B26A5EULL,
		0x35B437C0E95D8D40ULL,
		0xD0AA7748BDB8712FULL
	}};
	printf("Test Case 46\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xF980BD2B305F1D67ULL,
		0xF18961D5201F51E9ULL,
		0x647B3991D0390B98ULL,
		0xCC6C139D467DFD5FULL,
		0xCF4A717CC7EEDED9ULL,
		0xC980C7501B286BDBULL,
		0x4768BEDDE34EA331ULL,
		0x028402590CF64922ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x108781E6D2DFA25EULL,
		0x40FA855EE30D4416ULL,
		0x8BC7351DE0BE6897ULL,
		0xB52333709EF3D8AAULL,
		0x24D84602725A215EULL,
		0x7BF1FD1114FE26B2ULL,
		0xDC17272E7D91B273ULL,
		0x1532FAD19F2E631BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE9073CCDE280BF39ULL,
		0xB173E48BC31215FFULL,
		0xEFBC0C8C3087630FULL,
		0x794F20EDD88E25F5ULL,
		0xEB92377EB5B4FF87ULL,
		0xB2713A410FD64D69ULL,
		0x9B7F99F39EDF1142ULL,
		0x17B6F88893D82A39ULL
	}};
	printf("Test Case 47\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x3B4946434C805779ULL,
		0x549A45102D3C31FCULL,
		0xBEDC093473AC9A99ULL,
		0x6B4CF866ABE1BEDFULL,
		0x28B53DFF6A5AE300ULL,
		0xF4E2889BD1EF312FULL,
		0x22B8BA0271917155ULL,
		0x27CC94223FB5AA54ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE369B8E9C9ED480BULL,
		0x3F1403BB5AC5E0A2ULL,
		0xF7CA1666AB5822F6ULL,
		0xE26AFBB8B009A5B9ULL,
		0xBA87DB3728ED41A3ULL,
		0x254A47918E3B9DF1ULL,
		0xFF1D52BBF428B25CULL,
		0x8B6FF6D859C9E927ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD820FEAA856D1F72ULL,
		0x6B8E46AB77F9D15EULL,
		0x49161F52D8F4B86FULL,
		0x892603DE1BE81B66ULL,
		0x9232E6C842B7A2A3ULL,
		0xD1A8CF0A5FD4ACDEULL,
		0xDDA5E8B985B9C309ULL,
		0xACA362FA667C4373ULL
	}};
	printf("Test Case 48\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xA2FD5EFD30C35FAFULL,
		0x309C2FA7D2EC23D0ULL,
		0x50C71FBEE8A8FF7BULL,
		0xB14150749562C361ULL,
		0x5279642EDC233AFEULL,
		0x4DD8AED77AE09744ULL,
		0x0739B91B066E245BULL,
		0xB2B96FC3959EB386ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x279E45B00B86DCDDULL,
		0x180E1C0B9CF27112ULL,
		0x24B769FBC2E48BE0ULL,
		0x2DB0C6132DADD8A1ULL,
		0x4E7BE850C58A237EULL,
		0xEE160C23EAF2DF66ULL,
		0x805ECE0937E94BDAULL,
		0xFB48B1B64C65B701ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x85631B4D3B458372ULL,
		0x289233AC4E1E52C2ULL,
		0x747076452A4C749BULL,
		0x9CF19667B8CF1BC0ULL,
		0x1C028C7E19A91980ULL,
		0xA3CEA2F490124822ULL,
		0x8767771231876F81ULL,
		0x49F1DE75D9FB0487ULL
	}};
	printf("Test Case 49\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x3DFBE0A01228BF6FULL,
		0xF8EBE2082C530F35ULL,
		0x718ECB420F8643EBULL,
		0x25CC746045FADED4ULL,
		0xDD7359197A3DBE78ULL,
		0x24E20644C5D48A73ULL,
		0x23ACB0237195DC7FULL,
		0x985CDC957E239721ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC2290A5D979C7F56ULL,
		0x9E66A8D7D4FFAE6FULL,
		0x5D225D327065BA9DULL,
		0x0EE30100B4B416D7ULL,
		0x1A1F5D16126F0EFEULL,
		0xDF3391F96B3AB453ULL,
		0x7BA1CFF350C07915ULL,
		0x4DC553CF7857A58CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFFD2EAFD85B4C039ULL,
		0x668D4ADFF8ACA15AULL,
		0x2CAC96707FE3F976ULL,
		0x2B2F7560F14EC803ULL,
		0xC76C040F6852B086ULL,
		0xFBD197BDAEEE3E20ULL,
		0x580D7FD02155A56AULL,
		0xD5998F5A067432ADULL
	}};
	printf("Test Case 50\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xE6B1CA7B03DE2C2CULL,
		0x4D9056A477DFABE4ULL,
		0xB55F1780E327B6F3ULL,
		0xF71957AEFA519729ULL,
		0xACFB92B3D21AAFDEULL,
		0x02DFD4B5193B565FULL,
		0x857219B3C5D085AAULL,
		0x3A25469AF0D78010ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA004AAD41F15B86DULL,
		0xDB766461762FA780ULL,
		0x2E4E999242F9556CULL,
		0x6F5677DB0554F74FULL,
		0x49BF1F5D8FCEE316ULL,
		0x2FAD4F2A312966CCULL,
		0xAEB879B947ACD51DULL,
		0x99BD2D2D0EA9DA15ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x46B560AF1CCB9441ULL,
		0x96E632C501F00C64ULL,
		0x9B118E12A1DEE39FULL,
		0x984F2075FF056066ULL,
		0xE5448DEE5DD44CC8ULL,
		0x2D729B9F28123093ULL,
		0x2BCA600A827C50B7ULL,
		0xA3986BB7FE7E5A05ULL
	}};
	printf("Test Case 51\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x49936E07DDE99323ULL,
		0xBDCC64CB51FE5BDCULL,
		0x52032987C4114810ULL,
		0x637152F498F7AAA1ULL,
		0x602DDB56E95B091CULL,
		0x5D628438EEF74830ULL,
		0x2C2E791583179F69ULL,
		0x18D3434CF235C96CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x87A8E53D633F217EULL,
		0x64BDB626908FB931ULL,
		0x562EC6712200B32AULL,
		0xA06341869E05365CULL,
		0xBE23DB141D4A8D8AULL,
		0xF7EEA460AA6E94FEULL,
		0xAABADB819084BD0CULL,
		0xAAC6B57675FAF01EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCE3B8B3ABED6B25DULL,
		0xD971D2EDC171E2EDULL,
		0x042DEFF6E611FB3AULL,
		0xC312137206F29CFDULL,
		0xDE0E0042F4118496ULL,
		0xAA8C20584499DCCEULL,
		0x8694A29413932265ULL,
		0xB215F63A87CF3972ULL
	}};
	printf("Test Case 52\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x95E9D01D345F239DULL,
		0xD9F1512B5D7F4C19ULL,
		0x6B27574C0416FB07ULL,
		0x4BDBA4638DD8F10AULL,
		0xC4F0C2135A4B604AULL,
		0xA07998372D269373ULL,
		0x447345ADC6CD5F34ULL,
		0x1558DE711A7A1E34ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x224F58A14C32F0BBULL,
		0x95490EFCDE0059B1ULL,
		0xD004F127AFF5C497ULL,
		0xA331215A6F0FE8CFULL,
		0xF5C3DD8798D8DC84ULL,
		0x91F5471E9C34E6F2ULL,
		0x0F6A92C1E42CB2F0ULL,
		0x3A7D34791899A9FDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB7A688BC786DD326ULL,
		0x4CB85FD7837F15A8ULL,
		0xBB23A66BABE33F90ULL,
		0xE8EA8539E2D719C5ULL,
		0x31331F94C293BCCEULL,
		0x318CDF29B1127581ULL,
		0x4B19D76C22E1EDC4ULL,
		0x2F25EA0802E3B7C9ULL
	}};
	printf("Test Case 53\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xCC5D121F334750F5ULL,
		0x841DF94BC08B6BD5ULL,
		0x44DDDAFF2D243501ULL,
		0x4BF77759C085C121ULL,
		0xDB5D26DC1C83B5AFULL,
		0xB139A262E88053D7ULL,
		0xD276C431BB582045ULL,
		0x4CE5091D1C35ABD2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x02707FBD12723397ULL,
		0x4D700AD041A0ECBCULL,
		0x1B8923590918C38CULL,
		0xEAE32D9019EBD9CBULL,
		0x30227A83411C2745ULL,
		0x0520B1B587EE7577ULL,
		0x3B6EE9E83DE7EAEFULL,
		0xB7C897B9BADCE2BCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCE2D6DA221356362ULL,
		0xC96DF39B812B8769ULL,
		0x5F54F9A6243CF68DULL,
		0xA1145AC9D96E18EAULL,
		0xEB7F5C5F5D9F92EAULL,
		0xB41913D76F6E26A0ULL,
		0xE9182DD986BFCAAAULL,
		0xFB2D9EA4A6E9496EULL
	}};
	printf("Test Case 54\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xB6C44D667F8A766BULL,
		0x1692D600D896C34FULL,
		0xC201D3CC5550695EULL,
		0x13CACE259AF3E344ULL,
		0x8161FA4FDC242D3CULL,
		0x563A8FC90FD0AC2BULL,
		0x65844EB31770DA9EULL,
		0x20775002A85A0E82ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x17A4B7425E5B4066ULL,
		0xBAB0976F772A0999ULL,
		0x4AD13AF3EF5184EEULL,
		0xB45E53FC1AE7E04BULL,
		0x562B58C343FBB626ULL,
		0xB60D066864934324ULL,
		0x8F34DE59439D6E2EULL,
		0x49D9E5B28951667BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA160FA2421D1360DULL,
		0xAC22416FAFBCCAD6ULL,
		0x88D0E93FBA01EDB0ULL,
		0xA7949DD98014030FULL,
		0xD74AA28C9FDF9B1AULL,
		0xE03789A16B43EF0FULL,
		0xEAB090EA54EDB4B0ULL,
		0x69AEB5B0210B68F9ULL
	}};
	printf("Test Case 55\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x1F0454859C312403ULL,
		0x2BD2090B3111E84EULL,
		0x4E25985279A61511ULL,
		0xE82AFBD2D44C5595ULL,
		0xC969D90BC6505DBCULL,
		0xFE0F20CA52AE1D01ULL,
		0x4AC1C3BFA5213C92ULL,
		0xDC6DAEC80577C801ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8A9E27AC7A311E35ULL,
		0xED48AD84677153CEULL,
		0xECEABDA0DACD6859ULL,
		0xDA58445FF4E992E4ULL,
		0xD49B748B3BD4575FULL,
		0xBC546F1198DFCCAFULL,
		0x1961A4FEEAD2CE1AULL,
		0xCEC24A7E8C0D1B56ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x959A7329E6003A36ULL,
		0xC69AA48F5660BB80ULL,
		0xA2CF25F2A36B7D48ULL,
		0x3272BF8D20A5C771ULL,
		0x1DF2AD80FD840AE3ULL,
		0x425B4FDBCA71D1AEULL,
		0x53A067414FF3F288ULL,
		0x12AFE4B6897AD357ULL
	}};
	printf("Test Case 56\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x9324A639C665A7DCULL,
		0xB444540301CAFF2DULL,
		0x087CB9093D8A065FULL,
		0x627DABE1E6B42948ULL,
		0x973F8F699B4FAE39ULL,
		0x804EAF07CBF251BBULL,
		0x944FF4BE7FEF485FULL,
		0x5B6A9EC21C6DAE5FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7733976193E45C89ULL,
		0x175030AF121B6A9FULL,
		0xDAD8AF323B63D5FFULL,
		0xC9FAF40BF38C0548ULL,
		0x3C57E2E8B00AD765ULL,
		0xBD3C762F25FB293BULL,
		0x5112EA07083FD71BULL,
		0xD5FEF04EDCFBDD50ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE41731585581FB55ULL,
		0xA31464AC13D195B2ULL,
		0xD2A4163B06E9D3A0ULL,
		0xAB875FEA15382C00ULL,
		0xAB686D812B45795CULL,
		0x3D72D928EE097880ULL,
		0xC55D1EB977D09F44ULL,
		0x8E946E8CC096730FULL
	}};
	printf("Test Case 57\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xE728F50CB65CA7A7ULL,
		0x60BCC021EE81320AULL,
		0xC33A54BB13A94F8EULL,
		0x912CD9B7994A3102ULL,
		0x3D14A15F8B01A9FDULL,
		0xFC2EC2252539882BULL,
		0xC4B588FB1ADEA28BULL,
		0x94B0A782B34C377CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA2EF08F10B0441C9ULL,
		0xFBD523A48CB07BE1ULL,
		0x88C02C970AF0B20DULL,
		0xA94626AF99D5D873ULL,
		0xDB7BB7B7BF7C0162ULL,
		0xC06DCDF86954AF41ULL,
		0x8C5CE50C93471E6FULL,
		0x1AB4A087F20DCCEBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x45C7FDFDBD58E66EULL,
		0x9B69E385623149EBULL,
		0x4BFA782C1959FD83ULL,
		0x386AFF18009FE971ULL,
		0xE66F16E8347DA89FULL,
		0x3C430FDD4C6D276AULL,
		0x48E96DF78999BCE4ULL,
		0x8E0407054141FB97ULL
	}};
	printf("Test Case 58\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x51ECCA67EA664A6BULL,
		0xC5F6C699143A7E66ULL,
		0x6FBCF4F6592BF9FEULL,
		0x8B94E74D16202311ULL,
		0xDEC4906C51535E16ULL,
		0x6D3CB100CFF9E58DULL,
		0x8795CD9B95468CA0ULL,
		0x95E90F7A5D2E3367ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA5D05DAB8E46A939ULL,
		0xE7309FCCAABD81EFULL,
		0x6E630DE18F6A9D8AULL,
		0x8AB304D601682B8CULL,
		0xC3BF7FF09D5F61DCULL,
		0xCA60CD650F528B17ULL,
		0x67B4F2871BEB23A4ULL,
		0xEB901DE84D16B72FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF43C97CC6420E352ULL,
		0x22C65955BE87FF89ULL,
		0x01DFF917D6416474ULL,
		0x0127E39B1748089DULL,
		0x1D7BEF9CCC0C3FCAULL,
		0xA75C7C65C0AB6E9AULL,
		0xE0213F1C8EADAF04ULL,
		0x7E79129210388448ULL
	}};
	printf("Test Case 59\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xB776BCDED6AA335AULL,
		0xF0360D6B03E6A029ULL,
		0xDFF88C8739128A27ULL,
		0x0CD4CB5317AE22CDULL,
		0x7384E8D4EDBA630EULL,
		0x1D1AC1ABAD162E33ULL,
		0x5FEEAD08C07B97D5ULL,
		0xCC7902C3004C99F8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF1FBFEB797BFB67AULL,
		0xDD93676F0AE8862CULL,
		0xED7E3F29AAA045C8ULL,
		0x9D18D165B446C4EAULL,
		0x3F0A70A0F0E553FAULL,
		0x8ADA7DAE7BDCEB65ULL,
		0xD5E746C0C2518FA9ULL,
		0x844A7DA34A2D6612ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x468D426941158520ULL,
		0x2DA56A04090E2605ULL,
		0x3286B3AE93B2CFEFULL,
		0x91CC1A36A3E8E627ULL,
		0x4C8E98741D5F30F4ULL,
		0x97C0BC05D6CAC556ULL,
		0x8A09EBC8022A187CULL,
		0x48337F604A61FFEAULL
	}};
	printf("Test Case 60\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x03A6E35DD7F26D41ULL,
		0x18D4A6B75EF4543AULL,
		0x04CC1853DDD72771ULL,
		0x0B9F30C22882DA01ULL,
		0x7C468E9B7308F1E3ULL,
		0x18BF9CC4D321F7F5ULL,
		0x9F71609EE17D58F0ULL,
		0xEC6F9C6B24C5D310ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAC001C9BCE3BED5DULL,
		0x0648E9ADFDDB16EFULL,
		0x84DA666305C9A41AULL,
		0x38D98946320CF23CULL,
		0xD52143DE27676D3CULL,
		0x5D63BE412EDCE53FULL,
		0x49D24D22C58C1612ULL,
		0x8E95C03BB4A2F27BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAFA6FFC619C9801CULL,
		0x1E9C4F1AA32F42D5ULL,
		0x80167E30D81E836BULL,
		0x3346B9841A8E283DULL,
		0xA967CD45546F9CDFULL,
		0x45DC2285FDFD12CAULL,
		0xD6A32DBC24F14EE2ULL,
		0x62FA5C509067216BULL
	}};
	printf("Test Case 61\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xBDBCA23916ACBEE6ULL,
		0x7F825E42FB4B97CEULL,
		0x94FEAFEDD2D2D7EEULL,
		0x1438EBE2880B27C8ULL,
		0x8E9C42F7230398AAULL,
		0x545F859D55D4AC66ULL,
		0xA7D9A0BD853E3E9FULL,
		0xE9A96FA7D8CE3281ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8FE795A489ABDFE4ULL,
		0xDEDA2FA616289A56ULL,
		0x65B3E37AA7D1C55DULL,
		0xAB6F192A1C24B3B9ULL,
		0x245B00B13C795BC4ULL,
		0x1D0CF1C703306941ULL,
		0x303CFDEEEF7ECF57ULL,
		0xA552D2D1E1A9F4ACULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x325B379D9F076102ULL,
		0xA15871E4ED630D98ULL,
		0xF14D4C97750312B3ULL,
		0xBF57F2C8942F9471ULL,
		0xAAC742461F7AC36EULL,
		0x4953745A56E4C527ULL,
		0x97E55D536A40F1C8ULL,
		0x4CFBBD763967C62DULL
	}};
	printf("Test Case 62\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x18CD13B42290A0BFULL,
		0x12F3CD5E8C0C59B3ULL,
		0x3F9373662B4D39B1ULL,
		0x95BBA4CD2CBCE2F2ULL,
		0xDD03FEE0533C89FEULL,
		0x9C126D49CFDB691DULL,
		0x5560F545E7F64CFCULL,
		0x08E5647B5116C0B0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x013363A2AEDA2E1FULL,
		0x65EC7C65E02B80C4ULL,
		0x424A18FFE97BB5F4ULL,
		0x76BFAA323A23599CULL,
		0x2DAD75CC1C5C2F26ULL,
		0xC8A1CD3A3C3E7550ULL,
		0xCB7DE6AAEFA19BA5ULL,
		0xE91D2E24202C9F24ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x19FE70168C4A8EA0ULL,
		0x771FB13B6C27D977ULL,
		0x7DD96B99C2368C45ULL,
		0xE3040EFF169FBB6EULL,
		0xF0AE8B2C4F60A6D8ULL,
		0x54B3A073F3E51C4DULL,
		0x9E1D13EF0857D759ULL,
		0xE1F84A5F713A5F94ULL
	}};
	printf("Test Case 63\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x68B259C1BE14D518ULL,
		0x20B99A2B0E8598C5ULL,
		0xA8316326DE7F2136ULL,
		0xC719D2D02ECAC7C9ULL,
		0x22E7C8C3C872A4FCULL,
		0x4FD7766BA17ADEEDULL,
		0x8697B5256FD9559CULL,
		0x6457F06C017D1658ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9AFAF7FA54CAA7C1ULL,
		0x42E4EDE71EF9B860ULL,
		0xC212BEFBFFA2D773ULL,
		0x44639257D7B6AB2FULL,
		0x9528E97EA34FAD89ULL,
		0x886457FE99E6CE3BULL,
		0x0406FDCF1EC8206AULL,
		0x72E60E2891A27062ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF248AE3BEADE72D9ULL,
		0x625D77CC107C20A5ULL,
		0x6A23DDDD21DDF645ULL,
		0x837A4087F97C6CE6ULL,
		0xB7CF21BD6B3D0975ULL,
		0xC7B32195389C10D6ULL,
		0x829148EA711175F6ULL,
		0x16B1FE4490DF663AULL
	}};
	printf("Test Case 64\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x109EA655AB23AFC7ULL,
		0x5235D5EC97041B4FULL,
		0x760AEC21B9563BC4ULL,
		0x3135EEF1CDF96E7AULL,
		0x30B8DDDBA92D0E41ULL,
		0x77603B749610E47FULL,
		0xD86B2B4CC867605FULL,
		0x7B6637D8ADBE2CDCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2E95AA696F3A8CA3ULL,
		0xA7D508E352F21BD8ULL,
		0xAEE83E99E438AD28ULL,
		0x948B4333CDF8BC78ULL,
		0xF29B212CC7A62D15ULL,
		0x5894E063622F9546ULL,
		0x938A40CA4A34C77BULL,
		0x35919FEB5E34B42CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3E0B0C3CC4192364ULL,
		0xF5E0DD0FC5F60097ULL,
		0xD8E2D2B85D6E96ECULL,
		0xA5BEADC20001D202ULL,
		0xC223FCF76E8B2354ULL,
		0x2FF4DB17F43F7139ULL,
		0x4BE16B868253A724ULL,
		0x4EF7A833F38A98F0ULL
	}};
	printf("Test Case 65\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x2B8F56487F7C707FULL,
		0xAFDE14CEAF15F004ULL,
		0xD53CF8DF0CAB5583ULL,
		0x051FEDDD60917E15ULL,
		0xF4F61FF8BD212CE1ULL,
		0xB96802A80F2CE2B7ULL,
		0xF2F9249176ED2FA6ULL,
		0x8E7A8B9E27E084C4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x62C2E9EB68BA127CULL,
		0xDD2547AA72C500E3ULL,
		0x651EA12E269B39B7ULL,
		0x006781580E77945EULL,
		0x75F26462D82F28A5ULL,
		0x7CBDB99C544705F3ULL,
		0xB479705BA1EF846EULL,
		0x469B3285E9812DA8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x494DBFA317C66203ULL,
		0x72FB5364DDD0F0E7ULL,
		0xB02259F12A306C34ULL,
		0x05786C856EE6EA4BULL,
		0x81047B9A650E0444ULL,
		0xC5D5BB345B6BE744ULL,
		0x468054CAD702ABC8ULL,
		0xC8E1B91BCE61A96CULL
	}};
	printf("Test Case 66\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x0430DB05923E5CC6ULL,
		0xD8CEE1D60FD2E301ULL,
		0x61680281DE24547CULL,
		0x1E12384A12B6639EULL,
		0xCDE79190AE8BFA41ULL,
		0xBC05C42AFCAA8AB3ULL,
		0x95B2E33B27C8885BULL,
		0x83A844040583284AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF42B6031937C3E24ULL,
		0xA10DE46FF2E128FEULL,
		0xCB69559F1B6A02DBULL,
		0x9EDD84D50DB7FA35ULL,
		0x9FABCCF2F6CF03E5ULL,
		0x3523B853313E3D34ULL,
		0x180A6D0CCFD8E98BULL,
		0xE6B127A9B732687CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF01BBB34014262E2ULL,
		0x79C305B9FD33CBFFULL,
		0xAA01571EC54E56A7ULL,
		0x80CFBC9F1F0199ABULL,
		0x524C5D625844F9A4ULL,
		0x89267C79CD94B787ULL,
		0x8DB88E37E81061D0ULL,
		0x651963ADB2B14036ULL
	}};
	printf("Test Case 67\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x6A2BB1DA362F92EBULL,
		0x575C417AE810A843ULL,
		0x8A293C596B635CEFULL,
		0x02180407F78E6139ULL,
		0x6F6829048ED570D7ULL,
		0xDEEC1DF842C81536ULL,
		0x627D84010E48ACEFULL,
		0x767E4476DCE86710ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x77EBB4AE35C834D8ULL,
		0xFCDC224535860E98ULL,
		0xFAC64874A188DBFEULL,
		0xD62F6B9853F34BD1ULL,
		0x9DFC357775C2CE7DULL,
		0xC7E837FFF13FADAFULL,
		0x7F9BA25E3B25643CULL,
		0x296F9A7DC7A9954CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1DC0057403E7A633ULL,
		0xAB80633FDD96A6DBULL,
		0x70EF742DCAEB8711ULL,
		0xD4376F9FA47D2AE8ULL,
		0xF2941C73FB17BEAAULL,
		0x19042A07B3F7B899ULL,
		0x1DE6265F356DC8D3ULL,
		0x5F11DE0B1B41F25CULL
	}};
	printf("Test Case 68\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x859509E846D25D09ULL,
		0x787759F5FD8704B2ULL,
		0x3B4AEBE21695D851ULL,
		0xF79AD2B211355E90ULL,
		0x0EBE0008F997ED99ULL,
		0x8678CFADE05D71E1ULL,
		0x5355AE834344030EULL,
		0x45B6DF4690D0AA0CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDC7F99FDB374F2B0ULL,
		0xDAB0EBA79422925CULL,
		0xBE806A607A1F7E43ULL,
		0x898A0370D8E5A129ULL,
		0x84A5899A7416B438ULL,
		0x12CFB4E40191692BULL,
		0xD03C44DFA09F4DE4ULL,
		0x9A19265FF7FF43F3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x59EA9015F5A6AFB9ULL,
		0xA2C7B25269A596EEULL,
		0x85CA81826C8AA612ULL,
		0x7E10D1C2C9D0FFB9ULL,
		0x8A1B89928D8159A1ULL,
		0x94B77B49E1CC18CAULL,
		0x8369EA5CE3DB4EEAULL,
		0xDFAFF919672FE9FFULL
	}};
	printf("Test Case 69\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x31705932F8D89235ULL,
		0x57B34FB59382C942ULL,
		0xE5202285141DFC74ULL,
		0x44764B44543E71B1ULL,
		0xBB314056AAB56AEEULL,
		0xAEC83C180808A8B2ULL,
		0x1E76C4FAAB28BA6EULL,
		0x23FF7F532E95CC37ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB105077D06654DAFULL,
		0xE43822737C92FECFULL,
		0xB5040C111D7BEC1BULL,
		0x104F475C30E5115AULL,
		0x1EA509BC78B48BC6ULL,
		0x3BE149260CBF8B7AULL,
		0x267951DA6FF760EDULL,
		0xDD3120D503FD7F24ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x80755E4FFEBDDF9AULL,
		0xB38B6DC6EF10378DULL,
		0x50242E940966106FULL,
		0x54390C1864DB60EBULL,
		0xA59449EAD201E128ULL,
		0x9529753E04B723C8ULL,
		0x380F9520C4DFDA83ULL,
		0xFECE5F862D68B313ULL
	}};
	printf("Test Case 70\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x12C16E5A007A8041ULL,
		0xA70C0537120314BDULL,
		0x7AC42F112A2D2026ULL,
		0xFE9685771AC1A332ULL,
		0xB93D76F710B75257ULL,
		0x9A763ACF9BFF77C9ULL,
		0x78E69CDCDD612EA0ULL,
		0x94198D00D7DC5001ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5D706E4AB7943F94ULL,
		0x314A9262F300492CULL,
		0x6B8A933B9820080FULL,
		0x8450D5E3B1467C1BULL,
		0xA4E39A35B4B6E2F5ULL,
		0x9B57155968E55D8FULL,
		0x81EC6A899DEAD7C1ULL,
		0xA9660850170E5BD1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4FB10010B7EEBFD5ULL,
		0x96469755E1035D91ULL,
		0x114EBC2AB20D2829ULL,
		0x7AC65094AB87DF29ULL,
		0x1DDEECC2A401B0A2ULL,
		0x01212F96F31A2A46ULL,
		0xF90AF655408BF961ULL,
		0x3D7F8550C0D20BD0ULL
	}};
	printf("Test Case 71\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x45941A2FCF87B884ULL,
		0x0271B0C6EF8A9EB7ULL,
		0xE42BDA2AADD24932ULL,
		0xC5FA80CA8274E5FAULL,
		0x30E2E2079A09DD26ULL,
		0x405411C92D0CE1F2ULL,
		0xCD5FDC1C60930DCFULL,
		0x632D280148C02ABFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEFDAC066F0FEA21AULL,
		0x4D542CF075D3F21EULL,
		0x27BCA7FC8522B24FULL,
		0x5AB10DE6322A26DFULL,
		0xE612235661F91D0AULL,
		0x3EBBA5D1DB8FA0A6ULL,
		0x937F588E788170FBULL,
		0x00F0E9D14BCC35AFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAA4EDA493F791A9EULL,
		0x4F259C369A596CA9ULL,
		0xC3977DD628F0FB7DULL,
		0x9F4B8D2CB05EC325ULL,
		0xD6F0C151FBF0C02CULL,
		0x7EEFB418F6834154ULL,
		0x5E20849218127D34ULL,
		0x63DDC1D0030C1F10ULL
	}};
	printf("Test Case 72\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x6C3AA3F77DE60A81ULL,
		0x4BF4D26829D1B1E5ULL,
		0x64237A4F34FC7A87ULL,
		0xE31EEAFE8939FC3CULL,
		0x86D67ABB419FE505ULL,
		0x4EE6DC646AAD3F40ULL,
		0x0DB9B476C0B73EA5ULL,
		0x6FD58EFA18B25B64ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x90CD8C7D504809F0ULL,
		0x47BDC3D0EBD0BA9BULL,
		0x29BFAEBDC53980B8ULL,
		0x7313F45287778AECULL,
		0x25D722C49CE83796ULL,
		0x84E53C1EA647B38FULL,
		0xB38D2AE780400858ULL,
		0x5706C2918AC40010ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFCF72F8A2DAE0371ULL,
		0x0C4911B8C2010B7EULL,
		0x4D9CD4F2F1C5FA3FULL,
		0x900D1EAC0E4E76D0ULL,
		0xA301587FDD77D293ULL,
		0xCA03E07ACCEA8CCFULL,
		0xBE349E9140F736FDULL,
		0x38D34C6B92765B74ULL
	}};
	printf("Test Case 73\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x8C567FB762D4C769ULL,
		0x476DACBE3C87948DULL,
		0x76B15EC1329008B0ULL,
		0x57E22D0CE6A8F892ULL,
		0x01E06C0D72813DFEULL,
		0x4BB554458B8F5813ULL,
		0x5C3131197BB4A35DULL,
		0x8828026E890C71C4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1D300C53633A2E7BULL,
		0x738E389DD6FF84CAULL,
		0x06148B3FE01AC59BULL,
		0xB76709827537A1CAULL,
		0xE810C173B42957CDULL,
		0x920D25F47C33C08DULL,
		0xA9A62C58FA9A5F9EULL,
		0x5C511A91DA48DF0FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x916673E401EEE912ULL,
		0x34E39423EA781047ULL,
		0x70A5D5FED28ACD2BULL,
		0xE085248E939F5958ULL,
		0xE9F0AD7EC6A86A33ULL,
		0xD9B871B1F7BC989EULL,
		0xF5971D41812EFCC3ULL,
		0xD47918FF5344AECBULL
	}};
	printf("Test Case 74\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xF8E49029CB98087DULL,
		0x3BE10285B23CEBE2ULL,
		0x34A75097E08FE3D9ULL,
		0xCF0A92991A8975BAULL,
		0xECCA1FA15BBEDED8ULL,
		0x50B63D2252E30845ULL,
		0x45299F1980FD092BULL,
		0x1F969D968A098223ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5910B4EB52E6F085ULL,
		0x5E02A2DF30E5DCA6ULL,
		0x84C933081120E978ULL,
		0x88B2EFA49FDAFB21ULL,
		0x4B5E21AF05C32314ULL,
		0x64B9E10744B2B0DBULL,
		0x983306429FF5BCB2ULL,
		0xD711D32D8398BECAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA1F424C2997EF8F8ULL,
		0x65E3A05A82D93744ULL,
		0xB06E639FF1AF0AA1ULL,
		0x47B87D3D85538E9BULL,
		0xA7943E0E5E7DFDCCULL,
		0x340FDC251651B89EULL,
		0xDD1A995B1F08B599ULL,
		0xC8874EBB09913CE9ULL
	}};
	printf("Test Case 75\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x334F09FC629B1212ULL,
		0xCE493D935196FAA8ULL,
		0x1D334BB9F23473CDULL,
		0x44825DC83AF4B538ULL,
		0x3A43504830BE0089ULL,
		0xD53FB56496363E92ULL,
		0x204CE88F885FD963ULL,
		0xFF4FD66EAD655D44ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8845730F3D4C1D34ULL,
		0xCB26857A73C2AAD2ULL,
		0xBA5988F02626BF60ULL,
		0x80F56945657C9522ULL,
		0x59DDC10469C4A362ULL,
		0x384865FD7D023CD8ULL,
		0xFD8CD38E428CCCCFULL,
		0x2F734E272FDCFBACULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBB0A7AF35FD70F26ULL,
		0x056FB8E92254507AULL,
		0xA76AC349D412CCADULL,
		0xC477348D5F88201AULL,
		0x639E914C597AA3EBULL,
		0xED77D099EB34024AULL,
		0xDDC03B01CAD315ACULL,
		0xD03C984982B9A6E8ULL
	}};
	printf("Test Case 76\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x667CF4DFC7B95861ULL,
		0xBE1DD29EE6ED5F1FULL,
		0xEBB9561087908C01ULL,
		0x7FFBE2FEF9E33A5BULL,
		0x5052D1C80A9CB2D4ULL,
		0x5917F98C9A6DDD3BULL,
		0x228E4EA4C052116FULL,
		0x6228C136E3932196ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xABAF012CA2A9BC2EULL,
		0xC83D57C2784DD171ULL,
		0xB42446037882EF2FULL,
		0x3CCC4CA8CDA92BE9ULL,
		0x34D77CED9A7F810BULL,
		0xD1E92BC62F34AADCULL,
		0x7672D1DEC8A89554ULL,
		0x9E6D3D0F5C77ED5DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCDD3F5F36510E44FULL,
		0x7620855C9EA08E6EULL,
		0x5F9D1013FF12632EULL,
		0x4337AE56344A11B2ULL,
		0x6485AD2590E333DFULL,
		0x88FED24AB55977E7ULL,
		0x54FC9F7A08FA843BULL,
		0xFC45FC39BFE4CCCBULL
	}};
	printf("Test Case 77\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x35099AF69F592A7EULL,
		0x31910D6A625220ACULL,
		0x1492EB9A15CA610BULL,
		0xBABC1E1C84C7E373ULL,
		0xE9D155352AC983E6ULL,
		0x287C39F328FA16DDULL,
		0x74C1AC323F7710A8ULL,
		0xBBB633EC9D4C6094ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD1C4E17A572FFD20ULL,
		0x348E85880763AB2CULL,
		0xE7345B2D17886F38ULL,
		0x795B85F0A81F6BAAULL,
		0x9ED6A0061C7A5D20ULL,
		0x5A9BD1C635BD9D7FULL,
		0xCEF36F1CC8C9BFC9ULL,
		0x67C451578EA18524ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE4CD7B8CC876D75EULL,
		0x051F88E265318B80ULL,
		0xF3A6B0B702420E33ULL,
		0xC3E79BEC2CD888D9ULL,
		0x7707F53336B3DEC6ULL,
		0x72E7E8351D478BA2ULL,
		0xBA32C32EF7BEAF61ULL,
		0xDC7262BB13EDE5B0ULL
	}};
	printf("Test Case 78\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x5EED19403CEEBF2FULL,
		0x1F94C7A8D2D645BCULL,
		0xF0D62C42A9399678ULL,
		0x0B12164E86EC1E5CULL,
		0x8C1FB2C1F03B1D61ULL,
		0x5CAEFEE952DD87BDULL,
		0x0D6FA35F4AD504F6ULL,
		0x2FEDF421DC95647FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0EA75F4EA514EE4FULL,
		0x5818279B7AF76F44ULL,
		0x17C5B0888E872C84ULL,
		0x92FA56C0C1457247ULL,
		0x896457373BCC22F3ULL,
		0xDC9B643ED9AD5717ULL,
		0xB0E3AE48C9236923ULL,
		0xC4D3D3650135B2D5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x504A460E99FA5160ULL,
		0x478CE033A8212AF8ULL,
		0xE7139CCA27BEBAFCULL,
		0x99E8408E47A96C1BULL,
		0x057BE5F6CBF73F92ULL,
		0x80359AD78B70D0AAULL,
		0xBD8C0D1783F66DD5ULL,
		0xEB3E2744DDA0D6AAULL
	}};
	printf("Test Case 79\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x8EED632C8A8D7A9FULL,
		0xA13B874F4766A5B8ULL,
		0x862CB2273BD77CFEULL,
		0xBCF4BFA4218F4E6EULL,
		0xCF9BF3DD72EBCD85ULL,
		0x24179BF004E5B88CULL,
		0x45878A86A80651DAULL,
		0x7DF930E81D7DEA9AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF82ED6095F706957ULL,
		0xD7BD74466AE7FF77ULL,
		0x91AE311DE8A1C6D6ULL,
		0x81978F43337CBBFBULL,
		0x6555EBF3F54CB1C4ULL,
		0xCAB04EDE1E19EFECULL,
		0x0E9089A3BCA822F3ULL,
		0x921C222F3BE9492CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x76C3B525D5FD13C8ULL,
		0x7686F3092D815ACFULL,
		0x1782833AD376BA28ULL,
		0x3D6330E712F3F595ULL,
		0xAACE182E87A77C41ULL,
		0xEEA7D52E1AFC5760ULL,
		0x4B17032514AE7329ULL,
		0xEFE512C72694A3B6ULL
	}};
	printf("Test Case 80\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x5C87E50C1CE15E31ULL,
		0x2F878BC0A0D273F2ULL,
		0x564929E826BE03E7ULL,
		0x880D586C5BB2E178ULL,
		0x545B5623EED3335BULL,
		0x49CC899C3D7A522FULL,
		0xAC304A95C8D6246BULL,
		0x51D985209C2D20A5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0C06C1089017C472ULL,
		0x9330E21D2B96B799ULL,
		0x179D93BE210EA7FCULL,
		0xB87303343991646CULL,
		0xD93467CAF046D203ULL,
		0x8C00222F1990CAFAULL,
		0x13A8F5B2FB11A49FULL,
		0x128CFADCCFE8C92BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x508124048CF69A43ULL,
		0xBCB769DD8B44C46BULL,
		0x41D4BA5607B0A41BULL,
		0x307E5B5862238514ULL,
		0x8D6F31E91E95E158ULL,
		0xC5CCABB324EA98D5ULL,
		0xBF98BF2733C780F4ULL,
		0x43557FFC53C5E98EULL
	}};
	printf("Test Case 81\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x6B4BC9A1BAE0C6E7ULL,
		0x8262E41760BA1DA3ULL,
		0x99AD42172D558887ULL,
		0x65D75C62B16530D5ULL,
		0x89B5F1BA03699077ULL,
		0xB489BF51321A22D6ULL,
		0x2974C14397C421D2ULL,
		0x5FC34E297D8C0AEEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x802191F1D6B9A5B7ULL,
		0x4A97E2E197BAF6A5ULL,
		0x39332A34CD330F22ULL,
		0x1880C9C8E417044BULL,
		0xE2CD51D109C29C9AULL,
		0x99B85ECADA30EF62ULL,
		0xE7A4EF24AECB4D84ULL,
		0xD3AF30791B0C8802ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEB6A58506C596350ULL,
		0xC8F506F6F700EB06ULL,
		0xA09E6823E06687A5ULL,
		0x7D5795AA5572349EULL,
		0x6B78A06B0AAB0CEDULL,
		0x2D31E19BE82ACDB4ULL,
		0xCED02E67390F6C56ULL,
		0x8C6C7E50668082ECULL
	}};
	printf("Test Case 82\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xA75E5A1C05DC3C07ULL,
		0xC86B42B2332D4864ULL,
		0x3C120F433466E009ULL,
		0x1C93A5758F9BB369ULL,
		0x332CBFA1BB0901EDULL,
		0xFCC807BB273B2B66ULL,
		0x5EC6FBB0D2D8BD14ULL,
		0x20DD5E04D47ED28CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x789329C27BA486C3ULL,
		0x6E4C5FA991B5F0DBULL,
		0x10DE3DA114986D64ULL,
		0x4E8FD63AD0D7378DULL,
		0x978A0B4F5D4198C2ULL,
		0x1672033ADDF3A94BULL,
		0x68E593623791E59EULL,
		0x12B24830115A320CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDFCD73DE7E78BAC4ULL,
		0xA6271D1BA298B8BFULL,
		0x2CCC32E220FE8D6DULL,
		0x521C734F5F4C84E4ULL,
		0xA4A6B4EEE648992FULL,
		0xEABA0481FAC8822DULL,
		0x362368D2E549588AULL,
		0x326F1634C524E080ULL
	}};
	printf("Test Case 83\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x7C689067A2DF28B1ULL,
		0x4C21DF43EF7E550BULL,
		0x57E40CBC0F8A945DULL,
		0x9044CA90E5DD7409ULL,
		0x35EA6DF80C85D18CULL,
		0x20CCDFACF42F7671ULL,
		0x8564F07C9592AF5FULL,
		0x4EAD44DEDB5F015FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x736A3B6FE92531F7ULL,
		0x213107094E8D87A6ULL,
		0x7BAA3E0AFE72244AULL,
		0xA2544B1FE23D5455ULL,
		0x2BF52E43406D4EABULL,
		0x4B0AD8BCC8454BDCULL,
		0x0E0FED8BA72D8338ULL,
		0x2E134B452A57B4A0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0F02AB084BFA1946ULL,
		0x6D10D84AA1F3D2ADULL,
		0x2C4E32B6F1F8B017ULL,
		0x3210818F07E0205CULL,
		0x1E1F43BB4CE89F27ULL,
		0x6BC607103C6A3DADULL,
		0x8B6B1DF732BF2C67ULL,
		0x60BE0F9BF108B5FFULL
	}};
	printf("Test Case 84\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x4E85B753EFB68300ULL,
		0xAB2464F24C5509C3ULL,
		0x33C532CA1025F1ECULL,
		0x29AE5D6C9DCF647CULL,
		0x70C49C9CD92536B2ULL,
		0x5A095DE4C1876A71ULL,
		0xF8E83B493D8C5A36ULL,
		0xC274A571A5FDD214ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDA4B19BC5C6BD5C4ULL,
		0x12C24F4FEF508040ULL,
		0x15B0E5891F54D016ULL,
		0x3A30ADC27BC74497ULL,
		0x99B44A7E2271BF17ULL,
		0x7919F8361C066317ULL,
		0xD662AE164F6EE4F6ULL,
		0x8FCD6BE8460C82E3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x94CEAEEFB3DD56C4ULL,
		0xB9E62BBDA3058983ULL,
		0x2675D7430F7121FAULL,
		0x139EF0AEE60820EBULL,
		0xE970D6E2FB5489A5ULL,
		0x2310A5D2DD810966ULL,
		0x2E8A955F72E2BEC0ULL,
		0x4DB9CE99E3F150F7ULL
	}};
	printf("Test Case 85\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xAF8517C49E7E7752ULL,
		0xDFA0EEFD4C2EFB1CULL,
		0xC4B20E4DEBD85079ULL,
		0x56D50F54A21F582AULL,
		0x2537865BA2F041C4ULL,
		0xC2EC37D7EA00F193ULL,
		0x27B2B44B41B78B00ULL,
		0x16481FB5E9A4FFB3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF176D774195DEB17ULL,
		0xAB33817C06841980ULL,
		0x30F7F7D4707D5955ULL,
		0xB71292D061E24782ULL,
		0x80947CBF4929BB4EULL,
		0x33BFFD32F79AD2CDULL,
		0x8B314AECA7CFDF3FULL,
		0x0DFB49A8E6B1B40AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5EF3C0B087239C45ULL,
		0x74936F814AAAE29CULL,
		0xF445F9999BA5092CULL,
		0xE1C79D84C3FD1FA8ULL,
		0xA5A3FAE4EBD9FA8AULL,
		0xF153CAE51D9A235EULL,
		0xAC83FEA7E678543FULL,
		0x1BB3561D0F154BB9ULL
	}};
	printf("Test Case 86\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x5C93EB56BE306FA1ULL,
		0x15A87F163BF9D6F0ULL,
		0x0E94CA214D589123ULL,
		0x127FFC3FE5AACA13ULL,
		0x2753FEED4FD0E49DULL,
		0xE3BF6CE73506F6DCULL,
		0x054F237703DA6183ULL,
		0xA72C10E9905418A2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1D93470BAFABE4ECULL,
		0x2A0CFAD37AF9C777ULL,
		0x9AC6D99218CBA0D0ULL,
		0xF804E6878099638FULL,
		0xF029E8ECE56700C0ULL,
		0xBAC05D9086247E07ULL,
		0xCDA22EDE69ABD64AULL,
		0x36A1A16D8E3D2B49ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4100AC5D119B8B4DULL,
		0x3FA485C541001187ULL,
		0x945213B3559331F3ULL,
		0xEA7B1AB86533A99CULL,
		0xD77A1601AAB7E45DULL,
		0x597F3177B32288DBULL,
		0xC8ED0DA96A71B7C9ULL,
		0x918DB1841E6933EBULL
	}};
	printf("Test Case 87\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x99863C0B80C22B9DULL,
		0x1DB797E35034409CULL,
		0x17374D948CCA2E74ULL,
		0x3FFE0D71925E2F7FULL,
		0x26229BA5B228CCBDULL,
		0x49E967E639E85657ULL,
		0x78686DF19300D529ULL,
		0xFF080282F40DB236ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA89F31E989460387ULL,
		0x31527FD953425E72ULL,
		0x14ACD530418839BAULL,
		0xC9DFDC7F63DD29C5ULL,
		0x494F7469A12BF600ULL,
		0x031E67B30EBEA017ULL,
		0x85DEA6F5E4F9A012ULL,
		0xD5172C21BD3161B6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x31190DE20984281AULL,
		0x2CE5E83A03761EEEULL,
		0x039B98A4CD4217CEULL,
		0xF621D10EF18306BAULL,
		0x6F6DEFCC13033ABDULL,
		0x4AF700553756F640ULL,
		0xFDB6CB0477F9753BULL,
		0x2A1F2EA3493CD380ULL
	}};
	printf("Test Case 88\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x6554ED2E87DAEA16ULL,
		0xFAD182C009BEF255ULL,
		0x037B5F92E2BC6C75ULL,
		0x7EE9A5B66E6B8B1CULL,
		0x45EEC890392667E5ULL,
		0x30DE7EBBFF4D972FULL,
		0x0476914B1C100DF2ULL,
		0xCA4D953860A11E77ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDF8F3C3FA60244E0ULL,
		0xACD13B546894DA90ULL,
		0xCDDF2AAAB20D1495ULL,
		0xFFBE46291FBD3B8EULL,
		0xFB057AD76EC5AC04ULL,
		0xF0D816C76C9CB79AULL,
		0x14A18EC602177194ULL,
		0x2DA6C6C4F2E696CBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBADBD11121D8AEF6ULL,
		0x5600B994612A28C5ULL,
		0xCEA4753850B178E0ULL,
		0x8157E39F71D6B092ULL,
		0xBEEBB24757E3CBE1ULL,
		0xC006687C93D120B5ULL,
		0x10D71F8D1E077C66ULL,
		0xE7EB53FC924788BCULL
	}};
	printf("Test Case 89\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xC29D9653E8B6E137ULL,
		0xD65D594C0DA47705ULL,
		0x2D926CF3DAD801D5ULL,
		0xB47CD23AEE859B6EULL,
		0x817341B9F55F9F5AULL,
		0xE46CEFBCBE0E5BBDULL,
		0x51B3DDE969031408ULL,
		0xCB10CE89677CEEDAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE075AF997F5BAB6BULL,
		0x8D0EF236E5644410ULL,
		0xF0855AD6ACC16C06ULL,
		0x0217DF7A01D92DA5ULL,
		0x866A12700966BB93ULL,
		0xE75893F19F7AF8EEULL,
		0x0170D1101AEFA56DULL,
		0x1DD80F3D69821C0CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x22E839CA97ED4A5CULL,
		0x5B53AB7AE8C03315ULL,
		0xDD17362576196DD3ULL,
		0xB66B0D40EF5CB6CBULL,
		0x071953C9FC3924C9ULL,
		0x03347C4D2174A353ULL,
		0x50C30CF973ECB165ULL,
		0xD6C8C1B40EFEF2D6ULL
	}};
	printf("Test Case 90\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x776CBD3EAB0ADA92ULL,
		0xE7940F205FB11868ULL,
		0x8792A2DCCBB47875ULL,
		0x3A5F8AC4E2CB460BULL,
		0xE4CABA177E2CBE08ULL,
		0x65336A35335E1A90ULL,
		0xD3E9814095ED8949ULL,
		0x5CE221F1E8EFDCE0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x32B0C987707B4D57ULL,
		0x4182EE3464665788ULL,
		0xE0D6B743F9CFA056ULL,
		0x9C7DA81B2F51314BULL,
		0x403AD08515ABAA1CULL,
		0x49CC9EF62C431D74ULL,
		0x264E6DD9942F5399ULL,
		0xF7762435107BB3CCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x45DC74B9DB7197C5ULL,
		0xA616E1143BD74FE0ULL,
		0x6744159F327BD823ULL,
		0xA62222DFCD9A7740ULL,
		0xA4F06A926B871414ULL,
		0x2CFFF4C31F1D07E4ULL,
		0xF5A7EC9901C2DAD0ULL,
		0xAB9405C4F8946F2CULL
	}};
	printf("Test Case 91\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x76440C91FCFB1DB7ULL,
		0x714159B7209A1E75ULL,
		0xD0D70E89112DD370ULL,
		0xA443D606D6A173FFULL,
		0x43267CED593A119CULL,
		0xD98C407CF00C83FBULL,
		0xAEF3E24B4562CED4ULL,
		0x69C339D9AC6A4DCAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x981B44E5A0E4B83FULL,
		0xFE31AA8E4E04362EULL,
		0xC82DAF6F220C3287ULL,
		0x4C6B66E8C97EE9B5ULL,
		0x3EF19FEFF100B0A2ULL,
		0x1790152B66D48855ULL,
		0x945AEAED704CEF8CULL,
		0x72A748BCFC827217ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEE5F48745C1FA588ULL,
		0x8F70F3396E9E285BULL,
		0x18FAA1E63321E1F7ULL,
		0xE828B0EE1FDF9A4AULL,
		0x7DD7E302A83AA13EULL,
		0xCE1C555796D80BAEULL,
		0x3AA908A6352E2158ULL,
		0x1B64716550E83FDDULL
	}};
	printf("Test Case 92\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x2C95E1B209675C70ULL,
		0xB6280D7542E94937ULL,
		0x8DBCA7E910190B83ULL,
		0x629D537E69EE12A5ULL,
		0x64D3A1163AF7E844ULL,
		0xF2DA51EA9E630F63ULL,
		0xDAD531FFBFF022E8ULL,
		0x7345481B54D32DF0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x82744191CBEC5CC4ULL,
		0xC210DACE395A66CAULL,
		0xC2E404040BB8E478ULL,
		0x6E789BFBB9EA71F9ULL,
		0x2483D7A2CB9F173DULL,
		0x0AED99676A7FFB96ULL,
		0x166582B15A062918ULL,
		0x8AFFC269B3A2D407ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAEE1A023C28B00B4ULL,
		0x7438D7BB7BB32FFDULL,
		0x4F58A3ED1BA1EFFBULL,
		0x0CE5C885D004635CULL,
		0x405076B4F168FF79ULL,
		0xF837C88DF41CF4F5ULL,
		0xCCB0B34EE5F60BF0ULL,
		0xF9BA8A72E771F9F7ULL
	}};
	printf("Test Case 93\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x7C7B374223F60092ULL,
		0x9A35886736F948D7ULL,
		0x6136CA898ACFB71CULL,
		0x68A0E1B7DCC7EBA0ULL,
		0x06B6881D89FBEB81ULL,
		0x090989B7CABBE23CULL,
		0x203DC21CC8833F08ULL,
		0x46E7BC08ACB4B8A7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCFF4C0F5E71B48EAULL,
		0x362253F3D85C6102ULL,
		0xC8A9166FE42FBA3BULL,
		0xE3F3D7C5D6EA34CEULL,
		0xE347E8461ED03B57ULL,
		0x191EEE54BD8C82A2ULL,
		0x1B2081565BCB31FDULL,
		0xF6FA5BC9BFF52D24ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB38FF7B7C4ED4878ULL,
		0xAC17DB94EEA529D5ULL,
		0xA99FDCE66EE00D27ULL,
		0x8B5336720A2DDF6EULL,
		0xE5F1605B972BD0D6ULL,
		0x101767E37737609EULL,
		0x3B1D434A93480EF5ULL,
		0xB01DE7C113419583ULL
	}};
	printf("Test Case 94\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xFC850F217A6B5BBBULL,
		0xCFF3D780C6CA6751ULL,
		0x00062F3B703156B2ULL,
		0x223D58B2396C9811ULL,
		0xC0C236E3B883F68CULL,
		0x783697145780C33AULL,
		0x4090DB562FFA1874ULL,
		0x75FA44CD257997F6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA3CA14A8151E9DFBULL,
		0x32D18F8B71A15321ULL,
		0x64334F2C952650F4ULL,
		0x892C244019B96B97ULL,
		0x8D197A3B2BB494D3ULL,
		0xC5B34F9CD927E5DDULL,
		0x100139F68164132DULL,
		0x250EA09C8326FE23ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5F4F1B896F75C640ULL,
		0xFD22580BB76B3470ULL,
		0x64356017E5170646ULL,
		0xAB117CF220D5F386ULL,
		0x4DDB4CD89337625FULL,
		0xBD85D8888EA726E7ULL,
		0x5091E2A0AE9E0B59ULL,
		0x50F4E451A65F69D5ULL
	}};
	printf("Test Case 95\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xA6AFE189DF3E880BULL,
		0x004188C40B400CADULL,
		0xDAA068A55286FF20ULL,
		0x14BFBCF597BD6127ULL,
		0x55C1257382F1E889ULL,
		0x7DCCD4A092BEF294ULL,
		0x2ACFEEA2C0A453BDULL,
		0xEF281172640440F9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8EFEBFB21572B3AAULL,
		0xE85E8D8CAE6D16FCULL,
		0x02B56AC968349A2EULL,
		0x88A0AB8E7E9EB147ULL,
		0x161E797F5E7319AFULL,
		0xFB30E50408300927ULL,
		0x880C8BCE031C935BULL,
		0x7DC5506BE1C3135FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x28515E3BCA4C3BA1ULL,
		0xE81F0548A52D1A51ULL,
		0xD815026C3AB2650EULL,
		0x9C1F177BE923D060ULL,
		0x43DF5C0CDC82F126ULL,
		0x86FC31A49A8EFBB3ULL,
		0xA2C3656CC3B8C0E6ULL,
		0x92ED411985C753A6ULL
	}};
	printf("Test Case 96\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x22B21DEF490288C4ULL,
		0x558102746F8935E9ULL,
		0x808D0D871F420168ULL,
		0xFE7ABE3746D8CD29ULL,
		0xA8BC6B61835D8BACULL,
		0xB66681AB4628D938ULL,
		0x128F9DBD73B80BAAULL,
		0xF8020BD513F2AF58ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4CD3F42D85BD9B79ULL,
		0x363AB74F729921ECULL,
		0x94687CBB62FBD5E5ULL,
		0x848AF7BE0934C7A1ULL,
		0x1E4E3CF1DBF042A2ULL,
		0x92D5BACCF418820FULL,
		0x10327C5678F5609FULL,
		0xCA35A8A75C19D3E1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6E61E9C2CCBF13BDULL,
		0x63BBB53B1D101405ULL,
		0x14E5713C7DB9D48DULL,
		0x7AF049894FEC0A88ULL,
		0xB6F2579058ADC90EULL,
		0x24B33B67B2305B37ULL,
		0x02BDE1EB0B4D6B35ULL,
		0x3237A3724FEB7CB9ULL
	}};
	printf("Test Case 97\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x55332E13CFFAE8F7ULL,
		0x64A8E8972CCA9AA5ULL,
		0x6B07FCD33941728CULL,
		0x815E4A5046755642ULL,
		0xFF398D7F93AA7D82ULL,
		0xF00607BFEFAA0409ULL,
		0x578824AAEC8EEB1FULL,
		0x6EA03FD9BE25846AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEB0C84DCB3F902F9ULL,
		0xD71F625CB59E9F81ULL,
		0x817B28FC1106F491ULL,
		0x5A9CB4BC6D641A81ULL,
		0x08C864E1619FFB3BULL,
		0x2F991F7114E88E5FULL,
		0x7E55F4DCE3B3FC2CULL,
		0x76D5482293E3F659ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBE3FAACF7C03EA0EULL,
		0xB3B78ACB99540524ULL,
		0xEA7CD42F2847861DULL,
		0xDBC2FEEC2B114CC3ULL,
		0xF7F1E99EF23586B9ULL,
		0xDF9F18CEFB428A56ULL,
		0x29DDD0760F3D1733ULL,
		0x187577FB2DC67233ULL
	}};
	printf("Test Case 98\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xE123BE6FD379326EULL,
		0xDD2BFB11645F5D71ULL,
		0x39F269ED4F92A418ULL,
		0x12C9C589477EA5CEULL,
		0x4862B9F14EAB9F68ULL,
		0x8561F3FF799A0CFCULL,
		0x521583783D6C6B0EULL,
		0xEFAC90307D41AC27ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5E69133A4667A8ACULL,
		0xB3CF253016EC91D2ULL,
		0x32D57E155783829CULL,
		0xBE9C90FC5ED81BF1ULL,
		0x25034330029B8456ULL,
		0xBE621F1E01E5A1B1ULL,
		0x5A7120DEDE66E6B0ULL,
		0x458EDD79FA8C096EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBF4AAD55951E9AC2ULL,
		0x6EE4DE2172B3CCA3ULL,
		0x0B2717F818112684ULL,
		0xAC55557519A6BE3FULL,
		0x6D61FAC14C301B3EULL,
		0x3B03ECE1787FAD4DULL,
		0x0864A3A6E30A8DBEULL,
		0xAA224D4987CDA549ULL
	}};
	printf("Test Case 99\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xBD30E11CCC205D3BULL,
		0x3B789308FD4983D3ULL,
		0x1EE199EECD8F8ECFULL,
		0x2EF047B2E2975300ULL,
		0x4807232326575DC0ULL,
		0x22126998EE0C87AAULL,
		0x7BF2E06C26E0D559ULL,
		0x291D1EDE1173971DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x81CE919D12A006FDULL,
		0x69AEB439D9A95FB9ULL,
		0x869182BBF916DDF4ULL,
		0xF23247AD115D6AEAULL,
		0x7446C5238E4CDBF4ULL,
		0xCDAEDD57E1D5AC27ULL,
		0xAA87F4B61DAFAD65ULL,
		0xBD7F087422FBDB00ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3CFE7081DE805BC6ULL,
		0x52D6273124E0DC6AULL,
		0x98701B553499533BULL,
		0xDCC2001FF3CA39EAULL,
		0x3C41E600A81B8634ULL,
		0xEFBCB4CF0FD92B8DULL,
		0xD17514DA3B4F783CULL,
		0x946216AA33884C1DULL
	}};
	printf("Test Case 100\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x7B5930CE7E510CB1ULL,
		0x3621CAB1C973A5A2ULL,
		0xCCBC160BC71E33BEULL,
		0xF812D822B8865E5FULL,
		0x9640BACEAEDD9070ULL,
		0x7C052F1337664A58ULL,
		0x3E51B62EB8568B09ULL,
		0x290B93CCD128FD40ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2F48DBDE797C4135ULL,
		0xDAE5F2FCAC983059ULL,
		0x7D4A3248D137687BULL,
		0x5805816EE70CA0F3ULL,
		0xF4F6EA2865268127ULL,
		0x466A07A84F5CDC5EULL,
		0xF763DB9F5082E4B8ULL,
		0x093C1C454A41022FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5411EB10072D4D84ULL,
		0xECC4384D65EB95FBULL,
		0xB1F6244316295BC5ULL,
		0xA017594C5F8AFEACULL,
		0x62B650E6CBFB1157ULL,
		0x3A6F28BB783A9606ULL,
		0xC9326DB1E8D46FB1ULL,
		0x20378F899B69FF6FULL
	}};
	printf("Test Case 101\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x735FD2226C3C182DULL,
		0x26AE1E7404008E55ULL,
		0xAD9567E8E5908758ULL,
		0xC695D9A769B9E1E6ULL,
		0x38378D309132E747ULL,
		0x5FACA495A5C26C1FULL,
		0xBE937B173D0973B7ULL,
		0x9D1276767E82E539ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFC960A1AD9584148ULL,
		0x6593B350CE67FA7EULL,
		0xA3A5AE270F8DDB13ULL,
		0x24F982D440B3A332ULL,
		0xA90B2BA69FC570E4ULL,
		0x191D6161BB6A34D5ULL,
		0x74532CC09447FF65ULL,
		0xC34B927A5491EC0DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8FC9D838B5645965ULL,
		0x433DAD24CA67742BULL,
		0x0E30C9CFEA1D5C4BULL,
		0xE26C5B73290A42D4ULL,
		0x913CA6960EF797A3ULL,
		0x46B1C5F41EA858CAULL,
		0xCAC057D7A94E8CD2ULL,
		0x5E59E40C2A130934ULL
	}};
	printf("Test Case 102\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x322EC0F3622E1247ULL,
		0x38BF4003EAEB68B1ULL,
		0xC79FD2467AA87A8AULL,
		0x65EF84FAC7921FBCULL,
		0xD42C465173598984ULL,
		0xF7D8C8371D7F9456ULL,
		0x3748010DE05A6D31ULL,
		0xFC9D0879323AC413ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB98BA0B9D45B3EB0ULL,
		0x637AA837515AE80BULL,
		0xF3D4FAAD61882CC4ULL,
		0xAE6F4BAE7866DE82ULL,
		0x45C893E6C6A04B0DULL,
		0xD04C53FD540467E1ULL,
		0x8D27D3A6B585504BULL,
		0x82F95B7D9FF4FF86ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8BA5604AB6752CF7ULL,
		0x5BC5E834BBB180BAULL,
		0x344B28EB1B20564EULL,
		0xCB80CF54BFF4C13EULL,
		0x91E4D5B7B5F9C289ULL,
		0x27949BCA497BF3B7ULL,
		0xBA6FD2AB55DF3D7AULL,
		0x7E645304ADCE3B95ULL
	}};
	printf("Test Case 103\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xF9232B6C258B2B7CULL,
		0x215B3FF0044EB8EBULL,
		0x1FF9AB18F548D528ULL,
		0x15C555D8FCC37961ULL,
		0xD1C105495D02853BULL,
		0xB812998FFF9713BAULL,
		0xB723C2698E9E40A4ULL,
		0x2F7F8CE4E9DF2665ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4338D6C89A0E842DULL,
		0xACBE328BB8D6103DULL,
		0x5AB7EBA0F0F0BDB1ULL,
		0x160554676DBB3EA5ULL,
		0x47F6A850949CE0D9ULL,
		0x44ACEFD66A4AE574ULL,
		0x3B13E1F198666302ULL,
		0x0F05A98C1FFEAA70ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBA1BFDA4BF85AF51ULL,
		0x8DE50D7BBC98A8D6ULL,
		0x454E40B805B86899ULL,
		0x03C001BF917847C4ULL,
		0x9637AD19C99E65E2ULL,
		0xFCBE765995DDF6CEULL,
		0x8C30239816F823A6ULL,
		0x207A2568F6218C15ULL
	}};
	printf("Test Case 104\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xF831176845D4B738ULL,
		0x419F25067BABFCFFULL,
		0xD9F21358D9F26411ULL,
		0xBDA61DF91CD1F6AEULL,
		0xD3AB44BEFD93CBBFULL,
		0xDEBC7C116FE69EC6ULL,
		0x678437B2884C69ACULL,
		0xC5970D3688314C36ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x80DDDA1FC859B40CULL,
		0xD8662C99745F30ACULL,
		0x2E200878E8C7E3DEULL,
		0xA068B0763057CEBEULL,
		0xAF0A2B53CF906C04ULL,
		0x6CF74C973D7422B9ULL,
		0x30E14479984D829AULL,
		0x0D276129CD79D653ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x78ECCD778D8D0334ULL,
		0x99F9099F0FF4CC53ULL,
		0xF7D21B20313587CFULL,
		0x1DCEAD8F2C863810ULL,
		0x7CA16FED3203A7BBULL,
		0xB24B30865292BC7FULL,
		0x576573CB1001EB36ULL,
		0xC8B06C1F45489A65ULL
	}};
	printf("Test Case 105\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x14B3F3DD17D32620ULL,
		0xBF800E3C1ADAEAF9ULL,
		0xD4DFF7654CC230A3ULL,
		0x3EBAF899519A17FEULL,
		0x84518A50F8DE536BULL,
		0x0DC545D5E98B56F7ULL,
		0xFD9182AD687FD8AFULL,
		0x8FEA9BB064EC8E3EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x24C657C1D5359540ULL,
		0xBEFEEAF0CFF06D50ULL,
		0x2B0A4E1E39200F2AULL,
		0x554381D81AED0E61ULL,
		0x9353C554CED0D6C8ULL,
		0xA1F3E1765FD302ABULL,
		0x43A8A2B9C4BA3605ULL,
		0x44D7B356FD298E94ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3075A41CC2E6B360ULL,
		0x017EE4CCD52A87A9ULL,
		0xFFD5B97B75E23F89ULL,
		0x6BF979414B77199FULL,
		0x17024F04360E85A3ULL,
		0xAC36A4A3B658545CULL,
		0xBE392014ACC5EEAAULL,
		0xCB3D28E699C500AAULL
	}};
	printf("Test Case 106\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x3BEA8593F5EE4787ULL,
		0x8095A5E787BC81DDULL,
		0xD8356318A22E24C3ULL,
		0x16926084C131E059ULL,
		0x02E6255B922BBC66ULL,
		0xBDAF40672517E192ULL,
		0xB76924109D297533ULL,
		0x0022907F52D667C2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB85D935E04643F75ULL,
		0xAB0E7FB58B800AF7ULL,
		0x43A3D18691D305F6ULL,
		0x00F86B1DB0A8A2BFULL,
		0x3135B2EFEAAE2CABULL,
		0x66DCC164A9E38E97ULL,
		0xF9EC00F385954D2BULL,
		0x3AF1C1D92DB77EB8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x83B716CDF18A78F2ULL,
		0x2B9BDA520C3C8B2AULL,
		0x9B96B29E33FD2135ULL,
		0x166A0B99719942E6ULL,
		0x33D397B4788590CDULL,
		0xDB7381038CF46F05ULL,
		0x4E8524E318BC3818ULL,
		0x3AD351A67F61197AULL
	}};
	printf("Test Case 107\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xA22F23ADC33312BCULL,
		0x6AA3696124F083D8ULL,
		0xFB46A87FD9F481E1ULL,
		0x31EE24EE5D7C2762ULL,
		0x7FD2871F1C5848E6ULL,
		0x6E8A25F3CE00BB1CULL,
		0xE598E51AF37780C2ULL,
		0x3CA6628CC09200CDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0D03BED78E9FDCE0ULL,
		0xFCD1ABFAC7446B65ULL,
		0x1B7CF46306662F33ULL,
		0xA20F2963FDBA272DULL,
		0x6122BD4FA4673036ULL,
		0xB2518C015CCB981BULL,
		0xCEC69F9E11BF5B98ULL,
		0x4E8658C0B193740AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAF2C9D7A4DACCE5CULL,
		0x9672C29BE3B4E8BDULL,
		0xE03A5C1CDF92AED2ULL,
		0x93E10D8DA0C6004FULL,
		0x1EF03A50B83F78D0ULL,
		0xDCDBA9F292CB2307ULL,
		0x2B5E7A84E2C8DB5AULL,
		0x72203A4C710174C7ULL
	}};
	printf("Test Case 108\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xFF16426021131EEDULL,
		0xC5EA7E9AF9CB6501ULL,
		0x09CC2B567E1708DEULL,
		0xC760CC37B99A74DAULL,
		0xBA675B46074AEAD4ULL,
		0x1722CF42BDDFCE4DULL,
		0xC85F3EC1C83C0D45ULL,
		0x0633813D507B5DBFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6C49C2BDF25F5317ULL,
		0xC26C24F4E742CA4FULL,
		0xAD64231940A2531CULL,
		0x2B932252EF11526BULL,
		0x0369845B2F3AB1FBULL,
		0x5959032EBF0913F2ULL,
		0x25F509B01ED6769AULL,
		0x5CF8CF1DEEBE13EFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x935F80DDD34C4DFAULL,
		0x07865A6E1E89AF4EULL,
		0xA4A8084F3EB55BC2ULL,
		0xECF3EE65568B26B1ULL,
		0xB90EDF1D28705B2FULL,
		0x4E7BCC6C02D6DDBFULL,
		0xEDAA3771D6EA7BDFULL,
		0x5ACB4E20BEC54E50ULL
	}};
	printf("Test Case 109\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x3BBE6C6B277892C8ULL,
		0xEE8C0A3D06FE63A4ULL,
		0x0B6992F84F117107ULL,
		0x235695D9A8F40367ULL,
		0x299107A4E75ABB02ULL,
		0x9FF316C5B5AF1970ULL,
		0xA63FA0B08132BFF9ULL,
		0xA76310D719F91213ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xECD1156BB368BC7EULL,
		0x76AF17415C7E2A63ULL,
		0xBC816061DBEEB5BCULL,
		0xE5D61DD2A7A16FE8ULL,
		0x7818E47EF500D3CAULL,
		0x1630A5B095ED55FBULL,
		0x8A30628841602491ULL,
		0x6438BCC00302B943ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD76F790094102EB6ULL,
		0x98231D7C5A8049C7ULL,
		0xB7E8F29994FFC4BBULL,
		0xC680880B0F556C8FULL,
		0x5189E3DA125A68C8ULL,
		0x89C3B37520424C8BULL,
		0x2C0FC238C0529B68ULL,
		0xC35BAC171AFBAB50ULL
	}};
	printf("Test Case 110\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xBF71D4AF5D883891ULL,
		0x31481D57CD10F7E4ULL,
		0x5B89379575AF1274ULL,
		0xE2ED8FB35D46A675ULL,
		0x8CFC2215FC34F36EULL,
		0xE26EE06033201B63ULL,
		0xD576B66BBAA1E87DULL,
		0xC1D4173B108C1215ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0DD1F5C6C196420DULL,
		0xD86BC6A093318D8DULL,
		0xF35C417D9A7B858FULL,
		0x5A0E352E5368B775ULL,
		0xA4AB2F1DDB28219CULL,
		0xFA3920FFDE19ADE6ULL,
		0x68DBE2B8AD582BC0ULL,
		0xE5E2E0A9257AFB7EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB2A021699C1E7A9CULL,
		0xE923DBF75E217A69ULL,
		0xA8D576E8EFD497FBULL,
		0xB8E3BA9D0E2E1100ULL,
		0x28570D08271CD2F2ULL,
		0x1857C09FED39B685ULL,
		0xBDAD54D317F9C3BDULL,
		0x2436F79235F6E96BULL
	}};
	printf("Test Case 111\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x829DD63FF3E67A7DULL,
		0xA24E4795167525D1ULL,
		0x5A4934BB489B79B9ULL,
		0x7E2033141346F7C9ULL,
		0xC6A3F0C21AF6DF70ULL,
		0x817F3DC2AD0F0074ULL,
		0xA460E77CE35873BFULL,
		0x73E2055A08FD1382ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9D7EA4E3410E1BD2ULL,
		0x49E987ABC9EE0397ULL,
		0xF7C8F4EF2BC54653ULL,
		0xDBBFD575BA8110C5ULL,
		0x7F8055F685ABF60BULL,
		0x236F14B1F99AC5A4ULL,
		0xEA316F4344B717D0ULL,
		0xCC6358074B3DDF80ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1FE372DCB2E861AFULL,
		0xEBA7C03EDF9B2646ULL,
		0xAD81C054635E3FEAULL,
		0xA59FE661A9C7E70CULL,
		0xB923A5349F5D297BULL,
		0xA21029735495C5D0ULL,
		0x4E51883FA7EF646FULL,
		0xBF815D5D43C0CC02ULL
	}};
	printf("Test Case 112\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x33E42DF3E755D55BULL,
		0x60DDB86106CAD33EULL,
		0x37DD8EB9017334FAULL,
		0x236E186C90857C8FULL,
		0x4A0581DD81542DC6ULL,
		0xD6ECD622AA44B001ULL,
		0x8A16FEEE07D4F46CULL,
		0x1CC82D3CD977B512ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x52905955D323082FULL,
		0x0C0CF55095AA72D5ULL,
		0xB50D99E7E14BEB89ULL,
		0x4702A99D986E0E12ULL,
		0xC3E321A25CC77B35ULL,
		0x768CE302145FDC6CULL,
		0x854EC80097230581ULL,
		0x0CA6F5946E0E4811ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x617474A63476DD74ULL,
		0x6CD14D319360A1EBULL,
		0x82D0175EE038DF73ULL,
		0x646CB1F108EB729DULL,
		0x89E6A07FDD9356F3ULL,
		0xA0603520BE1B6C6DULL,
		0x0F5836EE90F7F1EDULL,
		0x106ED8A8B779FD03ULL
	}};
	printf("Test Case 113\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xB202D39470FD42A1ULL,
		0x205DFF73850890DCULL,
		0xACDB03F7A738D48CULL,
		0xEC2431F0E355F382ULL,
		0xD7623624C2DC5D60ULL,
		0xC01F5AAC82F31555ULL,
		0x4A56BA2702B4D649ULL,
		0x449C898E801F41F0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x15DC90F8C223A142ULL,
		0xB81B98B5DCF19D3CULL,
		0xF1C19A8B2F0F38DEULL,
		0xC911D69010820141ULL,
		0x28B30E1D93B92760ULL,
		0x9CA3586D9B5D6D38ULL,
		0xC3DAA604929C7675ULL,
		0x9E852AB1ADDF93BDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA7DE436CB2DEE3E3ULL,
		0x984667C659F90DE0ULL,
		0x5D1A997C8837EC52ULL,
		0x2535E760F3D7F2C3ULL,
		0xFFD1383951657A00ULL,
		0x5CBC02C119AE786DULL,
		0x898C1C239028A03CULL,
		0xDA19A33F2DC0D24DULL
	}};
	printf("Test Case 114\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xAD6589683AC73A94ULL,
		0x23155D2B16EC6681ULL,
		0x748DA832C0AE981DULL,
		0xF5DE1D3D16FA80FBULL,
		0xEEFD520145C55621ULL,
		0x1178DA5D5091BFC9ULL,
		0x4251CFFD00AD7BBBULL,
		0xAC73B9E1B75DC7E0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE7B2E6321CAAE28EULL,
		0x71D103FA4D0E5AC5ULL,
		0x382D1392B6589E47ULL,
		0xB8A61C9041582CF5ULL,
		0x9A9EAC702FCC418EULL,
		0xD587ADCDE0B708E4ULL,
		0x41EFCFAEF9E14D37ULL,
		0xD9D30F781FF39E35ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4AD76F5A266DD81AULL,
		0x52C45ED15BE23C44ULL,
		0x4CA0BBA076F6065AULL,
		0x4D7801AD57A2AC0EULL,
		0x7463FE716A0917AFULL,
		0xC4FF7790B026B72DULL,
		0x03BE0053F94C368CULL,
		0x75A0B699A8AE59D5ULL
	}};
	printf("Test Case 115\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xEE6951CE22951E85ULL,
		0xA8E68108EEF2BA99ULL,
		0x1616318652C8106CULL,
		0x7E67765276E97F09ULL,
		0xDBD0011DC76D1A82ULL,
		0x8A46301010FAE435ULL,
		0x0D72CB78B7F588CDULL,
		0xBB267DC1CE9E1A20ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6DE5E51D894981ACULL,
		0x7C425FCC08FE4C04ULL,
		0x16799D8E50343270ULL,
		0x48E52D39624ED121ULL,
		0x4B4333A6036B79BDULL,
		0xBAEFCE2CAC4E593CULL,
		0xA3F4FD56575ECD10ULL,
		0x68F066D1D1FD6EADULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x838CB4D3ABDC9F29ULL,
		0xD4A4DEC4E60CF69DULL,
		0x006FAC0802FC221CULL,
		0x36825B6B14A7AE28ULL,
		0x909332BBC406633FULL,
		0x30A9FE3CBCB4BD09ULL,
		0xAE86362EE0AB45DDULL,
		0xD3D61B101F63748DULL
	}};
	printf("Test Case 116\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x092F316728309D0DULL,
		0x0074DC2FECF07B76ULL,
		0x96FA891A02B006B8ULL,
		0x192B9E6F91DB8EEFULL,
		0x3AC2182E768CC8B0ULL,
		0xBDD5EF398F9598DCULL,
		0x93FAEB564BC9E2D6ULL,
		0x3CF24804851400A0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x97C6E9DEE8715B4CULL,
		0x4170DEDF3C220399ULL,
		0x7FAE01F146A6C87FULL,
		0x523E3635C25CFBF7ULL,
		0xD909E23A1B199C9FULL,
		0xD3FABF6AE22A6C72ULL,
		0xC2221870B2D49E69ULL,
		0x795849159FE37CF5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9EE9D8B9C041C641ULL,
		0x410402F0D0D278EFULL,
		0xE95488EB4416CEC7ULL,
		0x4B15A85A53877518ULL,
		0xE3CBFA146D95542FULL,
		0x6E2F50536DBFF4AEULL,
		0x51D8F326F91D7CBFULL,
		0x45AA01111AF77C55ULL
	}};
	printf("Test Case 117\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xF48B311B70C126FBULL,
		0x6E18AD54ED437193ULL,
		0xD59E852B84A9A3C1ULL,
		0x75DDB6C62AEDBB3AULL,
		0x509E4CB87106CFD6ULL,
		0xBFF2E4B6234C3050ULL,
		0x94DE06C5AC6B7A9DULL,
		0xD5295CC792EEC602ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x15ED7DB7DD818BCCULL,
		0x2F558A0AF3AFC948ULL,
		0x6F3ACCC7D10B6031ULL,
		0x22F45D4D3263707FULL,
		0x06CE5A9871E76C67ULL,
		0x809B301A32781AE9ULL,
		0x52CC2AA877AC8D62ULL,
		0xCE435795863EEB9AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE1664CACAD40AD37ULL,
		0x414D275E1EECB8DBULL,
		0xBAA449EC55A2C3F0ULL,
		0x5729EB8B188ECB45ULL,
		0x5650162000E1A3B1ULL,
		0x3F69D4AC11342AB9ULL,
		0xC6122C6DDBC7F7FFULL,
		0x1B6A0B5214D02D98ULL
	}};
	printf("Test Case 118\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x74349D5943DF4229ULL,
		0xB38AFCD896E72849ULL,
		0x58D5D4D302D7677DULL,
		0x69D55ADBDA7672F6ULL,
		0x73AC4F176BC954AAULL,
		0x556DCC42EFE02EA7ULL,
		0x2468688B47448E53ULL,
		0x580646B108D1A86DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBF53E069DB515ED1ULL,
		0x9C5A9B517F96E865ULL,
		0xA88932150B695BCDULL,
		0x316BDF929EC295E6ULL,
		0x86B5699C7A0B078EULL,
		0x8BC983A335239B5CULL,
		0x4F9B51C42168CC4DULL,
		0xB965C987E5C5AB17ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCB677D30988E1CF8ULL,
		0x2FD06789E971C02CULL,
		0xF05CE6C609BE3CB0ULL,
		0x58BE854944B4E710ULL,
		0xF519268B11C25324ULL,
		0xDEA44FE1DAC3B5FBULL,
		0x6BF3394F662C421EULL,
		0xE1638F36ED14037AULL
	}};
	printf("Test Case 119\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xFC08C72DCC0F47BBULL,
		0x324ADD8446CDEC4CULL,
		0x515B7CC4A546695DULL,
		0xBAA18AB46046ED97ULL,
		0xC79C62A98F00C017ULL,
		0x7AFF12E22491B6C4ULL,
		0x0AF41C724FA14A7FULL,
		0x0CED1670B08334ECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x561320B4AFB4648AULL,
		0x00AFD4F98C6B5381ULL,
		0x9B3C54CF59C70012ULL,
		0x966E7A63EAF4B67DULL,
		0x8CFABDFE0242AE1BULL,
		0x44D6BFF6704C38C7ULL,
		0xB426053E8C02574EULL,
		0x04CF564F12DA5750ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAA1BE79963BB2331ULL,
		0x32E5097DCAA6BFCDULL,
		0xCA67280BFC81694FULL,
		0x2CCFF0D78AB25BEAULL,
		0x4B66DF578D426E0CULL,
		0x3E29AD1454DD8E03ULL,
		0xBED2194CC3A31D31ULL,
		0x0822403FA25963BCULL
	}};
	printf("Test Case 120\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xD01D17EA6D4C4E4FULL,
		0x30262445A8F50FE2ULL,
		0xEC3F5F40F0619101ULL,
		0x26DF740B9AB1B6F6ULL,
		0xF7E9D129730D3AC8ULL,
		0x998EC2B1A542F179ULL,
		0x1E2162B7E832FB13ULL,
		0x15E29A8DBB549EB2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xED2068556D6E49D3ULL,
		0x445B078B6926DCCFULL,
		0x842F16CFBCB2C8ECULL,
		0x68E1FD29F9B4A916ULL,
		0xADA2757E77F8C292ULL,
		0x76956858C6A2D143ULL,
		0x161DE22DB10E8EEBULL,
		0x2FF2F26820F61361ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3D3D7FBF0022079CULL,
		0x747D23CEC1D3D32DULL,
		0x6810498F4CD359EDULL,
		0x4E3E892263051FE0ULL,
		0x5A4BA45704F5F85AULL,
		0xEF1BAAE963E0203AULL,
		0x083C809A593C75F8ULL,
		0x3A1068E59BA28DD3ULL
	}};
	printf("Test Case 121\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x303709F4A9D31E90ULL,
		0xB50FC91E1B7C069CULL,
		0x1B50F9E19E79A201ULL,
		0x2A416C6CA3AC1539ULL,
		0x250B7589A22EB121ULL,
		0x0559B63CC001EA59ULL,
		0x46F32E85F469B94EULL,
		0xEA0975743D452806ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x87E0420A7A676E85ULL,
		0x3DE6D0CD9B28CF68ULL,
		0x56D68A56ADED4D35ULL,
		0x4F0FEB7227AC98E5ULL,
		0xBF57BAB2206778ADULL,
		0xBD2826644DC5DE21ULL,
		0x87AAA5644D558A2DULL,
		0x4CA0597D898474E2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB7D74BFED3B47015ULL,
		0x88E919D38054C9F4ULL,
		0x4D8673B73394EF34ULL,
		0x654E871E84008DDCULL,
		0x9A5CCF3B8249C98CULL,
		0xB87190588DC43478ULL,
		0xC1598BE1B93C3363ULL,
		0xA6A92C09B4C15CE4ULL
	}};
	printf("Test Case 122\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x0B660537BB7BF7EFULL,
		0xF2BFCC155579B92FULL,
		0xFE820F412728C1FBULL,
		0x863CC40A34543B7EULL,
		0xE7548F5FF4E76D70ULL,
		0x9E622F9D22282B36ULL,
		0x2AF96F01D99AE038ULL,
		0xACFD1A807E48E032ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD7B0E9DE95622EEEULL,
		0xF19BF7250572A007ULL,
		0x3813D7575DDDD3A9ULL,
		0x0BDE843EDC070280ULL,
		0x5E5A7DCB01856CADULL,
		0x817BDD312F242FCCULL,
		0x8E6FDB3D01DF4BD8ULL,
		0x38177B5C5BA45923ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDCD6ECE92E19D901ULL,
		0x03243B30500B1928ULL,
		0xC691D8167AF51252ULL,
		0x8DE24034E85339FEULL,
		0xB90EF294F56201DDULL,
		0x1F19F2AC0D0C04FAULL,
		0xA496B43CD845ABE0ULL,
		0x94EA61DC25ECB911ULL
	}};
	printf("Test Case 123\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x961C60511411B22CULL,
		0x0BD6413B081C1B38ULL,
		0xE9C5B81E5BD7BA1FULL,
		0xD82CFA29DC88EF2AULL,
		0x2DA272CB1C82BE12ULL,
		0x587B854084FD0E6DULL,
		0xEBA196D65EEC9BFFULL,
		0x7D128D06BF640BF3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDEFB1758F67EEACCULL,
		0x89095364C53241CDULL,
		0x4F0E831FBF296D3EULL,
		0x39B339177C8039A2ULL,
		0x815AC46980EE930BULL,
		0xE848C8541A076C64ULL,
		0xC0F30A10AC9DDCB6ULL,
		0xBD038F58F5E71C04ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x48E77709E26F58E0ULL,
		0x82DF125FCD2E5AF5ULL,
		0xA6CB3B01E4FED721ULL,
		0xE19FC33EA008D688ULL,
		0xACF8B6A29C6C2D19ULL,
		0xB0334D149EFA6209ULL,
		0x2B529CC6F2714749ULL,
		0xC011025E4A8317F7ULL
	}};
	printf("Test Case 124\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x8E2AA29ACD76EEB1ULL,
		0x7D7990A22D46A41BULL,
		0x9D2F5154A5308DC4ULL,
		0x8A4BF789A407CAE5ULL,
		0xA8F3210692BF90EBULL,
		0x0DB7D7B7334E6437ULL,
		0x2AD1A1F1FB73276AULL,
		0x4137A5206EF979C4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x27F779EA981BE2CCULL,
		0xEB930608034BD9F8ULL,
		0x9049613408E15A14ULL,
		0x0CFB34E3B2726E51ULL,
		0x358617C5D83165A7ULL,
		0x965498D3373FD26DULL,
		0x753721F8749B1DE0ULL,
		0x2F90BF62938C787AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA9DDDB70556D0C7DULL,
		0x96EA96AA2E0D7DE3ULL,
		0x0D663060ADD1D7D0ULL,
		0x86B0C36A1675A4B4ULL,
		0x9D7536C34A8EF54CULL,
		0x9BE34F640471B65AULL,
		0x5FE680098FE83A8AULL,
		0x6EA71A42FD7501BEULL
	}};
	printf("Test Case 125\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xCB722BD6A09ED00DULL,
		0x310F06ACFFD54897ULL,
		0xEC705348D68377D3ULL,
		0x3A1D93B89ABB1CD0ULL,
		0x8C4A981629F4585BULL,
		0x96DBD5F299DEC2DCULL,
		0xDCBE5A566A9BF1FAULL,
		0xD68B7F17A4F619D5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC06BC6DABBB8A7C2ULL,
		0xBF5384BC5F8B207AULL,
		0x35B4E2EE18D3D30AULL,
		0x98E78A582D83CDB7ULL,
		0x74099BB60A0A70C4ULL,
		0xD70C6CFA2AB0FAABULL,
		0xFB85EC8E8DEC4A66ULL,
		0x3651CFB53FB20E0FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0B19ED0C1B2677CFULL,
		0x8E5C8210A05E68EDULL,
		0xD9C4B1A6CE50A4D9ULL,
		0xA2FA19E0B738D167ULL,
		0xF84303A023FE289FULL,
		0x41D7B908B36E3877ULL,
		0x273BB6D8E777BB9CULL,
		0xE0DAB0A29B4417DAULL
	}};
	printf("Test Case 126\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xEF5298795C182E89ULL,
		0x2C1E8FFED53FA5AAULL,
		0xB50147FC22284992ULL,
		0x51915F68A1EB7174ULL,
		0x0DE9E802D59BAA25ULL,
		0x220699B85791C951ULL,
		0x97FF75B588CF9B70ULL,
		0x6AB4CE02723B5B68ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9777942A41B717F8ULL,
		0xEF5B4A7F5E0CEB6CULL,
		0x7AC05B756B694D3DULL,
		0x565A8D4414FFC0E7ULL,
		0xDFE3DA76EC1F1DB2ULL,
		0x9899A62B22B57C3DULL,
		0x81A504891C963F92ULL,
		0xFFAEC5C60AA906B2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x78250C531DAF3971ULL,
		0xC345C5818B334EC6ULL,
		0xCFC11C89494104AFULL,
		0x07CBD22CB514B193ULL,
		0xD20A32743984B797ULL,
		0xBA9F3F937524B56CULL,
		0x165A713C9459A4E2ULL,
		0x951A0BC478925DDAULL
	}};
	printf("Test Case 127\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xD9C8B087F1F75A08ULL,
		0x5B1AA94675FEB1E4ULL,
		0x5FFA0EC0C5A646DAULL,
		0x2D1E9640E2063D74ULL,
		0x7EF1F57B8EC8A1F7ULL,
		0x29B20B15CB6D4F24ULL,
		0x5FCFAF2471E65A34ULL,
		0xAD1B694DC4478833ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x90E8906DF386FB05ULL,
		0x402E68A7B02A3946ULL,
		0x7544DB89EF42C056ULL,
		0x50E4C7FA93B01546ULL,
		0xF730C3E31776087FULL,
		0x4833570C67BABB3AULL,
		0x1B2D0AB0BFED174FULL,
		0x8C1C83262108B1A7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x492020EA0271A10DULL,
		0x1B34C1E1C5D488A2ULL,
		0x2ABED5492AE4868CULL,
		0x7DFA51BA71B62832ULL,
		0x89C1369899BEA988ULL,
		0x61815C19ACD7F41EULL,
		0x44E2A594CE0B4D7BULL,
		0x2107EA6BE54F3994ULL
	}};
	printf("Test Case 128\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x5015E61FD66A7727ULL,
		0xB91F7639D49DFF44ULL,
		0xBC18071B7A8F0F7AULL,
		0x045BF4D37D3942C8ULL,
		0x0BB9786DA673C1E0ULL,
		0x018CC89E41767554ULL,
		0x4F4B18E2054F39F7ULL,
		0xD0BAB871D2D01246ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x36F63F276A1AE0B4ULL,
		0x999FF7DA19A5E199ULL,
		0xB814878AEEAB4D80ULL,
		0x56D507915FEEC7C9ULL,
		0x8930D8C6FF2456CAULL,
		0x6DE6BC1E3F6A03B7ULL,
		0x1A2078AE0FB73FD5ULL,
		0x12F0FC96EAD51B95ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x66E3D938BC709793ULL,
		0x208081E3CD381EDDULL,
		0x040C8091942442FAULL,
		0x528EF34222D78501ULL,
		0x8289A0AB5957972AULL,
		0x6C6A74807E1C76E3ULL,
		0x556B604C0AF80622ULL,
		0xC24A44E7380509D3ULL
	}};
	printf("Test Case 129\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x123411B05902E568ULL,
		0x6D7DF20D2E0DFC23ULL,
		0x52B11BDDAC24FB07ULL,
		0x91EABB8EB12A122AULL,
		0x278AA7C968279E9DULL,
		0xE9E8B55EC0098899ULL,
		0xE6F4D349B655BA1DULL,
		0xFAAF768565B8E745ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x205768AC2CB83AA1ULL,
		0x4A6AFB630448596FULL,
		0xA8EF4FBB22BEECAFULL,
		0xBDA5B5460652841AULL,
		0xB4FF5BABB4BA6921ULL,
		0xD6C0AF56273FFFBBULL,
		0x662F3B15BB9B9DE9ULL,
		0xB58C47F86F4F71D2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3263791C75BADFC9ULL,
		0x2717096E2A45A54CULL,
		0xFA5E54668E9A17A8ULL,
		0x2C4F0EC8B7789630ULL,
		0x9375FC62DC9DF7BCULL,
		0x3F281A08E7367722ULL,
		0x80DBE85C0DCE27F4ULL,
		0x4F23317D0AF79697ULL
	}};
	printf("Test Case 130\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xF306D7EB52C33BCFULL,
		0x25980B8689EE83FFULL,
		0xF67EE9FE6E4FDD59ULL,
		0x980ED4C2DA782DC6ULL,
		0x8231F8FDC7DAC80BULL,
		0xCA5BAE6FE8264553ULL,
		0xA66FA290FF934EC9ULL,
		0x36BE83A9931C8F31ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5EC867F71E74A1A6ULL,
		0x445BE30346EEF5FAULL,
		0x1EB29FE82EC79203ULL,
		0x4DC96C206C265961ULL,
		0x40D0CEED17A72D00ULL,
		0xA3D71378DEA3CB5DULL,
		0x40C36A02DC59AD1BULL,
		0xC62352D80ADC41E9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xADCEB01C4CB79A69ULL,
		0x61C3E885CF007605ULL,
		0xE8CC761640884F5AULL,
		0xD5C7B8E2B65E74A7ULL,
		0xC2E13610D07DE50BULL,
		0x698CBD1736858E0EULL,
		0xE6ACC89223CAE3D2ULL,
		0xF09DD17199C0CED8ULL
	}};
	printf("Test Case 131\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xB3A16C63A8D93CC4ULL,
		0x70619A6C8D64C8A0ULL,
		0xB115257D6F764E4AULL,
		0x67D2FBC5C2F5FF45ULL,
		0x7D08F1C70F2F8016ULL,
		0x28492068403653A3ULL,
		0xADB3D4EF7292ECB9ULL,
		0xAB0D31FBFFDEEE2BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBC1D053B71F43274ULL,
		0x545B620F1AABA325ULL,
		0xCA626E65B8EF1B42ULL,
		0xEE2521ACC156DC6BULL,
		0x9DD9D9BAD966EFD1ULL,
		0x1958BE386106CF59ULL,
		0x63757718E9677608ULL,
		0xF27E6EA3027BA95FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0FBC6958D92D0EB0ULL,
		0x243AF86397CF6B85ULL,
		0x7B774B18D7995508ULL,
		0x89F7DA6903A3232EULL,
		0xE0D1287DD6496FC7ULL,
		0x31119E5021309CFAULL,
		0xCEC6A3F79BF59AB1ULL,
		0x59735F58FDA54774ULL
	}};
	printf("Test Case 132\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x38A434AFCBD6A1B1ULL,
		0xD578A510046D2F3DULL,
		0x96EFB3D43472320DULL,
		0x707BE96F9639460FULL,
		0x83E55FB30EDA6286ULL,
		0xD9621153F5DE0211ULL,
		0x37A27143D49C5B03ULL,
		0xBF159B1F1A1D80DDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE7B0E102469F931DULL,
		0x23C17AB41F0B3A8CULL,
		0xBAD15C0E11A47689ULL,
		0x89C294652EF86CA3ULL,
		0x77C5CCDBB7B8BE93ULL,
		0x78C6EB4CCF8DF75EULL,
		0x094A1F6EA76302FCULL,
		0x2DB20F5D1CD7CF51ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDF14D5AD8D4932ACULL,
		0xF6B9DFA41B6615B1ULL,
		0x2C3EEFDA25D64484ULL,
		0xF9B97D0AB8C12AACULL,
		0xF4209368B962DC15ULL,
		0xA1A4FA1F3A53F54FULL,
		0x3EE86E2D73FF59FFULL,
		0x92A7944206CA4F8CULL
	}};
	printf("Test Case 133\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x4CE8C7D96BB516CCULL,
		0x5B9D06EF3298191EULL,
		0x09713D00A8619341ULL,
		0xA21A5C90F004AADBULL,
		0xD53E90765F530679ULL,
		0xED2E6CA8EC4BBEFCULL,
		0x7E33FA95A0D0B4B5ULL,
		0xCC3D391EB1D5AA8DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2D8EE4D198798B0CULL,
		0xD198BF2129C8D8E3ULL,
		0x2BC8C5FFF89AE450ULL,
		0x1C087204BDE38B3DULL,
		0x742B812D8C466AC2ULL,
		0x8667DEE4651B1B1CULL,
		0x8DEB5A786C7EB42CULL,
		0x04D5F7197FB29E96ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x61662308F3CC9DC0ULL,
		0x8A05B9CE1B50C1FDULL,
		0x22B9F8FF50FB7711ULL,
		0xBE122E944DE721E6ULL,
		0xA115115BD3156CBBULL,
		0x6B49B24C8950A5E0ULL,
		0xF3D8A0EDCCAE0099ULL,
		0xC8E8CE07CE67341BULL
	}};
	printf("Test Case 134\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x4ECD52E89EB31923ULL,
		0xB64093041FAAC6C9ULL,
		0x9A389C84CC67AA29ULL,
		0x63D0A27099E58CE5ULL,
		0x04FD8CEE70ED80E7ULL,
		0x11714E7E124E7CC2ULL,
		0xEE16DADEE4916949ULL,
		0x61A4DD343FD0D30BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4187809129E41284ULL,
		0x1397F4EEBB41804AULL,
		0xEFBD4673AEAC7074ULL,
		0xC37DFFFC0EE79F30ULL,
		0x50257566871B71E3ULL,
		0xCF3775BEE8F035B6ULL,
		0x448933BCB63ABEB3ULL,
		0x581C82CC2338244AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0F4AD279B7570BA7ULL,
		0xA5D767EAA4EB4683ULL,
		0x7585DAF762CBDA5DULL,
		0xA0AD5D8C970213D5ULL,
		0x54D8F988F7F6F104ULL,
		0xDE463BC0FABE4974ULL,
		0xAA9FE96252ABD7FAULL,
		0x39B85FF81CE8F741ULL
	}};
	printf("Test Case 135\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xDC2650782DECE132ULL,
		0x04FAB8B4A9989F29ULL,
		0x6DEB0C098C071913ULL,
		0x6266197A236F8F25ULL,
		0x65D7542493E31497ULL,
		0x1107919E3E66DA9EULL,
		0xCD791AF7948CA8FCULL,
		0x0DF0C55125C7E6BAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x536FD7C56555C2F3ULL,
		0xE947C66912FEEA79ULL,
		0x99C6108DCA8FAA22ULL,
		0x181EAB2D96B11143ULL,
		0xF3125D2AA088AF62ULL,
		0x6E6656C17E9929EDULL,
		0x8EC1666F8ED003A3ULL,
		0xA7042418EC942697ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8F4987BD48B923C1ULL,
		0xEDBD7EDDBB667550ULL,
		0xF42D1C844688B331ULL,
		0x7A78B257B5DE9E66ULL,
		0x96C5090E336BBBF5ULL,
		0x7F61C75F40FFF373ULL,
		0x43B87C981A5CAB5FULL,
		0xAAF4E149C953C02DULL
	}};
	printf("Test Case 136\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x1DFDF11EE8B7DE95ULL,
		0xD296DEE6E712A66FULL,
		0xE719F3D654BADED7ULL,
		0x6F963287A40928C4ULL,
		0xB704D094E301C18DULL,
		0x3150E4AEE31F52B0ULL,
		0xD3EC95EF562D93DCULL,
		0xCC5F293A7D04CB04ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCAEB79309E2F6723ULL,
		0x33ACE4D16168EAD4ULL,
		0x02A9151E4E393A11ULL,
		0x7FE0D7F35E8A67C3ULL,
		0x9B96BFEA7DC08636ULL,
		0x2CE9737FCEA69CA3ULL,
		0x8E437DB11D641CB4ULL,
		0xC9407609ACF09115ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD716882E7698B9B6ULL,
		0xE13A3A37867A4CBBULL,
		0xE5B0E6C81A83E4C6ULL,
		0x1076E574FA834F07ULL,
		0x2C926F7E9EC147BBULL,
		0x1DB997D12DB9CE13ULL,
		0x5DAFE85E4B498F68ULL,
		0x051F5F33D1F45A11ULL
	}};
	printf("Test Case 137\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xFD48E742476D6B6AULL,
		0x9C1D4BC832FC2642ULL,
		0x8524277E8FA4164EULL,
		0xE0F696314FCE47EBULL,
		0x5F113A672C4C4F6EULL,
		0x6804ABF8DDC640AEULL,
		0x3F9630F50E9E3552ULL,
		0x0091EDE6A5F326C7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCA4EB6D45750CBF5ULL,
		0xAFB74E327A8FF438ULL,
		0xA11DD6F3EDE393CEULL,
		0x13352E53A2D85374ULL,
		0xA28315A7B5D63486ULL,
		0xE8C0E8D1BEC60D66ULL,
		0x7662D548944F5A0BULL,
		0x0265DA9FF2EFD627ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x37065196103DA09FULL,
		0x33AA05FA4873D27AULL,
		0x2439F18D62478580ULL,
		0xF3C3B862ED16149FULL,
		0xFD922FC0999A7BE8ULL,
		0x80C4432963004DC8ULL,
		0x49F4E5BD9AD16F59ULL,
		0x02F43779571CF0E0ULL
	}};
	printf("Test Case 138\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x640094D72BFDDA53ULL,
		0x70BD16DFE762E022ULL,
		0xA877580622B2E9FCULL,
		0x486F5F4391543BC5ULL,
		0x1CC906C0224189F0ULL,
		0x5BF6D2EBD20A725BULL,
		0x552A531E0E154491ULL,
		0xA6AE9AA306B6ADB8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x29E7789A49D4B821ULL,
		0x9D51FD12EE4AD8E8ULL,
		0xD5498B9EB7C1424CULL,
		0xD93A271C862E819CULL,
		0x2604424FD1FD10A5ULL,
		0x2156ED9F70526016ULL,
		0x23F4628357C8F599ULL,
		0x04F6131FE3767AD6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4DE7EC4D62296272ULL,
		0xEDECEBCD092838CAULL,
		0x7D3ED3989573ABB0ULL,
		0x9155785F177ABA59ULL,
		0x3ACD448FF3BC9955ULL,
		0x7AA03F74A258124DULL,
		0x76DE319D59DDB108ULL,
		0xA25889BCE5C0D76EULL
	}};
	printf("Test Case 139\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x252DC94EA6F090E1ULL,
		0xBAE50E0C03725940ULL,
		0x8792ACEBA82A298CULL,
		0xF99156F0DD7E21A4ULL,
		0xEF227F23639F24A1ULL,
		0x9F0A6D5516D2B764ULL,
		0x02526F81D52973DBULL,
		0x3EB8DB4D8D0F27BFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9695B199EB858EFCULL,
		0x7A06FBBE1C1263B1ULL,
		0xDB37D72EFDF1B13CULL,
		0xDCED2357B79E5934ULL,
		0x066CF79B907BB40DULL,
		0x0ED340CF3A5E2B22ULL,
		0xC356959B3F07D4FDULL,
		0x057C233F99B8C1A9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB3B878D74D751E1DULL,
		0xC0E3F5B21F603AF1ULL,
		0x5CA57BC555DB98B0ULL,
		0x257C75A76AE07890ULL,
		0xE94E88B8F3E490ACULL,
		0x91D92D9A2C8C9C46ULL,
		0xC104FA1AEA2EA726ULL,
		0x3BC4F87214B7E616ULL
	}};
	printf("Test Case 140\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x57124A2A344089ABULL,
		0xAFFBF17632AD53DDULL,
		0x1EA1F02401D1EB3CULL,
		0x39A68186C1C9B7B2ULL,
		0x9085DA4E30E0CCA6ULL,
		0x25DBB4C67F6D8C73ULL,
		0xC1BFED2F4CEFF81EULL,
		0x308033D3FDCFA413ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2333BED55E842C04ULL,
		0xC897CD71B8803616ULL,
		0x4E68AB62319E2446ULL,
		0x9A57D8B6159D005EULL,
		0x85C55C588328942BULL,
		0x50C05F80575B36ACULL,
		0x4CECF70A175BBF64ULL,
		0x634FDFA75C043207ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7421F4FF6AC4A5AFULL,
		0x676C3C078A2D65CBULL,
		0x50C95B46304FCF7AULL,
		0xA3F15930D454B7ECULL,
		0x15408616B3C8588DULL,
		0x751BEB462836BADFULL,
		0x8D531A255BB4477AULL,
		0x53CFEC74A1CB9614ULL
	}};
	printf("Test Case 141\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x9B64BBF27A772AE6ULL,
		0x3083454152363532ULL,
		0x2C1DC3238D6C7531ULL,
		0xC3F93C9427C69234ULL,
		0x11391C7AB8622761ULL,
		0x6D69173A23982A3CULL,
		0x91F477ADEA6E01C4ULL,
		0x621D1D7BE82E6043ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3CC5ECFFC554AA79ULL,
		0xED566BF0EEA8FF63ULL,
		0x313B81212E669B59ULL,
		0x5A57D52EFF98FC6FULL,
		0x9A51138A964F23CAULL,
		0x70233282A74016F8ULL,
		0x1241C98300BB4B17ULL,
		0x27EB27D58BB364C9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA7A1570DBF23809FULL,
		0xDDD52EB1BC9ECA51ULL,
		0x1D264202A30AEE68ULL,
		0x99AEE9BAD85E6E5BULL,
		0x8B680FF02E2D04ABULL,
		0x1D4A25B884D83CC4ULL,
		0x83B5BE2EEAD54AD3ULL,
		0x45F63AAE639D048AULL
	}};
	printf("Test Case 142\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x927D2C76C2B8A5E0ULL,
		0x1B473B779F3B2664ULL,
		0xF83B51C17DC1E068ULL,
		0x8DEE9E0F350232A7ULL,
		0x077B602B7CDEDD63ULL,
		0xA6FFF5C77EAF4C76ULL,
		0x3AD68CD706B44C66ULL,
		0x73AC02A08317AEBFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8096AEB191858FEAULL,
		0x75FBFD64F4F2AB76ULL,
		0x921F730CF9FC0596ULL,
		0xD5B768BCEFB47C0DULL,
		0x6089EFE49872B1B8ULL,
		0x11D5D417F559D91AULL,
		0x81F4D9EAB0324334ULL,
		0x5E0B28FCDE072378ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x12EB82C7533D2A0AULL,
		0x6EBCC6136BC98D12ULL,
		0x6A2422CD843DE5FEULL,
		0x5859F6B3DAB64EAAULL,
		0x67F28FCFE4AC6CDBULL,
		0xB72A21D08BF6956CULL,
		0xBB22553DB6860F52ULL,
		0x2DA72A5C5D108DC7ULL
	}};
	printf("Test Case 143\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x40BD359D214DE47FULL,
		0x4399BD6D19D1FABEULL,
		0xFFBD46CC1E7859D8ULL,
		0x13FE0FD7130CDCB4ULL,
		0x91265CF42C519EDBULL,
		0x5E53515121549CDDULL,
		0xED71BCD58BF64BBEULL,
		0x33824808A07514EBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5E45C4F1F45D988BULL,
		0xEB38DD6B266B7C00ULL,
		0xEE7D94AAE0263805ULL,
		0x42C7F20C956D432CULL,
		0x2919A21CE216E42CULL,
		0x1919AB128F68E075ULL,
		0x8419F6F84152F8F0ULL,
		0xA036344C165C0B6DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1EF8F16CD5107CF4ULL,
		0xA8A160063FBA86BEULL,
		0x11C0D266FE5E61DDULL,
		0x5139FDDB86619F98ULL,
		0xB83FFEE8CE477AF7ULL,
		0x474AFA43AE3C7CA8ULL,
		0x69684A2DCAA4B34EULL,
		0x93B47C44B6291F86ULL
	}};
	printf("Test Case 144\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xCFAF2DD7107DC7F5ULL,
		0xC306EF66E832D923ULL,
		0x08EBCDA86BA2FCA2ULL,
		0xC2C4E403875A56FEULL,
		0xB293FFEDCF5C11B2ULL,
		0xB66F0D4C59B7B742ULL,
		0x29A182F201BA6B9EULL,
		0x7FBC88C61B0219B3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x45DE28B42CE5782CULL,
		0x9A4AB003BF6A8BE6ULL,
		0x4982AD0D7F69BAB7ULL,
		0x86D77CD913C6C271ULL,
		0x4870C602DA9BD490ULL,
		0x8EB34FB8627E0E6AULL,
		0x280508A2BB52592FULL,
		0x1327A30EFEAD9019ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8A7105633C98BFD9ULL,
		0x594C5F65575852C5ULL,
		0x416960A514CB4615ULL,
		0x441398DA949C948FULL,
		0xFAE339EF15C7C522ULL,
		0x38DC42F43BC9B928ULL,
		0x01A48A50BAE832B1ULL,
		0x6C9B2BC8E5AF89AAULL
	}};
	printf("Test Case 145\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xD801F61942D71305ULL,
		0x7EF6BD476F6E4C69ULL,
		0x3F7E208E6C1F7498ULL,
		0xF76EF42894E314F1ULL,
		0x20F29B267AF157B4ULL,
		0x7727182E92E7293DULL,
		0xB73B3326C3FD34B3ULL,
		0x62EDD7E186FE2CF9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x33A871CD739D976CULL,
		0xADDCE5AFEE25D6BDULL,
		0xDE6C39E6FB40D46DULL,
		0xF0F6ECE0FF15D44CULL,
		0xD466A35DF5832A10ULL,
		0x9BF77B0F501AF4C1ULL,
		0xDB3945F6DFB411CFULL,
		0xC4B617CC9455A348ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEBA987D4314A8469ULL,
		0xD32A58E8814B9AD4ULL,
		0xE1121968975FA0F5ULL,
		0x079818C86BF6C0BDULL,
		0xF494387B8F727DA4ULL,
		0xECD06321C2FDDDFCULL,
		0x6C0276D01C49257CULL,
		0xA65BC02D12AB8FB1ULL
	}};
	printf("Test Case 146\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xF5BCCD9A71152649ULL,
		0x93A2BACFF67C0A60ULL,
		0x3581C2105AE37056ULL,
		0x01889DFE60819535ULL,
		0x3B9F531D6E3FD48EULL,
		0xC9A4CAFD887B7E85ULL,
		0x1282307CC2570B47ULL,
		0x6C57D3FE7F76011CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBE3E79FEDE24D3EFULL,
		0xA2A2EBACAEA7C08AULL,
		0x50B42F2209A7D74AULL,
		0xA0A4D60B8C7AE962ULL,
		0x235F9F3BF5143805ULL,
		0x20098A779B379B14ULL,
		0xE09F8983EB44057AULL,
		0x97D2317375090AB5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4B82B464AF31F5A6ULL,
		0x3100516358DBCAEAULL,
		0x6535ED325344A71CULL,
		0xA12C4BF5ECFB7C57ULL,
		0x18C0CC269B2BEC8BULL,
		0xE9AD408A134CE591ULL,
		0xF21DB9FF29130E3DULL,
		0xFB85E28D0A7F0BA9ULL
	}};
	printf("Test Case 147\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x2C24B7689D57EDF0ULL,
		0x42B55D1C6EC82C84ULL,
		0x789AE44CB3BC246DULL,
		0x160755D146462771ULL,
		0x9C1E11E4B9528F0FULL,
		0x9DBE83E26D2F7624ULL,
		0x26754ACED2457003ULL,
		0x4AF000CED47225B5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8FEB656BB1C90CBFULL,
		0x5D6FF052CF4F68D6ULL,
		0xE377EFA8B520AA1FULL,
		0xA210E99B84B4A092ULL,
		0x59A641947851CE24ULL,
		0x31A3D892EB116890ULL,
		0x7A4F1210D5E681C8ULL,
		0x85373F2FF4620547ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA3CFD2032C9EE14FULL,
		0x1FDAAD4EA1874452ULL,
		0x9BED0BE4069C8E72ULL,
		0xB417BC4AC2F287E3ULL,
		0xC5B85070C103412BULL,
		0xAC1D5B70863E1EB4ULL,
		0x5C3A58DE07A3F1CBULL,
		0xCFC73FE1201020F2ULL
	}};
	printf("Test Case 148\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x4F456C665F6BCE26ULL,
		0xD6F2B2524B15702FULL,
		0x86A2B1C7C0B26D49ULL,
		0x4EBC1184B4773127ULL,
		0x9A77576726C79C50ULL,
		0x8AA86C8606FB27A7ULL,
		0x176D2AD83BEDF515ULL,
		0x7F5F151CE86B42EFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2ABF167E806CC15CULL,
		0x4137E2E634DDA8E2ULL,
		0x0F201578788B0614ULL,
		0x7777BF1EB2AB9BBCULL,
		0x3F4DC19EEE04C93BULL,
		0xEB7D97425B80DBC9ULL,
		0x4FFE7B0203B3A8C1ULL,
		0xAB8638DF66304FD8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x65FA7A18DF070F7AULL,
		0x97C550B47FC8D8CDULL,
		0x8982A4BFB8396B5DULL,
		0x39CBAE9A06DCAA9BULL,
		0xA53A96F9C8C3556BULL,
		0x61D5FBC45D7BFC6EULL,
		0x589351DA385E5DD4ULL,
		0xD4D92DC38E5B0D37ULL
	}};
	printf("Test Case 149\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xFF0FBDD16449BD54ULL,
		0x085FE55974401B83ULL,
		0xF9CB1C9FBDA2F541ULL,
		0x4ACA3B24C4EEE84AULL,
		0x3320D51579E9EFFFULL,
		0x3275A3C7154A199CULL,
		0xFD152C91120604F2ULL,
		0xE1954A984FD82B4AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAC7994A6C2385AB0ULL,
		0x786A667483C7D283ULL,
		0x63C8D7147001C0E4ULL,
		0x2A8610F6FC6CB621ULL,
		0x10E6FDBD4C2194FBULL,
		0xE4A5AA127C1C90EAULL,
		0xCA88FE95BAD3A97EULL,
		0xE3742838F2F67F15ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x53762977A671E7E4ULL,
		0x7035832DF787C900ULL,
		0x9A03CB8BCDA335A5ULL,
		0x604C2BD238825E6BULL,
		0x23C628A835C87B04ULL,
		0xD6D009D569568976ULL,
		0x379DD204A8D5AD8CULL,
		0x02E162A0BD2E545FULL
	}};
	printf("Test Case 150\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x3ED8592FEE99CB53ULL,
		0xAE6FB2A77283FF94ULL,
		0xB152E9AA3AD0A36DULL,
		0xFC96381E822B6628ULL,
		0xC15DDE5307C303FFULL,
		0x2CD9A7F6E9BEEDC1ULL,
		0xB6F018527A91D780ULL,
		0x57E6CB430FDEA09AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD3D921BC75D13A78ULL,
		0x4C840CFFE90075DBULL,
		0xC4800A0F9D5EE9E2ULL,
		0x5F34836F947D9FE2ULL,
		0x2D00F02965751523ULL,
		0xBC657BB744A57A29ULL,
		0x4E0ACDC3AE85E9B3ULL,
		0x1E250D20170EBC42ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xED0178939B48F12BULL,
		0xE2EBBE589B838A4FULL,
		0x75D2E3A5A78E4A8FULL,
		0xA3A2BB711656F9CAULL,
		0xEC5D2E7A62B616DCULL,
		0x90BCDC41AD1B97E8ULL,
		0xF8FAD591D4143E33ULL,
		0x49C3C66318D01CD8ULL
	}};
	printf("Test Case 151\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x64C884CFAB8FB04AULL,
		0x38962B33A197EBE8ULL,
		0x016E98EBB4290008ULL,
		0x0E0C3C44B00757F4ULL,
		0xC76D697FE89BEE9BULL,
		0x4FFE76BB1C0B9607ULL,
		0x3B002B4F7312292FULL,
		0x656FBF40F552ECD4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x417791BDEB808EB9ULL,
		0xB5DDF0E372F6077AULL,
		0x1E4E522F1450CE20ULL,
		0xAC0727BD82D330DDULL,
		0x9BEAA6496F224B80ULL,
		0x16510CF9D7B61BC4ULL,
		0x2714C89D65C42EB3ULL,
		0x705E53783BFA594EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x25BF1572400F3EF3ULL,
		0x8D4BDBD0D361EC92ULL,
		0x1F20CAC4A079CE28ULL,
		0xA20B1BF932D46729ULL,
		0x5C87CF3687B9A51BULL,
		0x59AF7A42CBBD8DC3ULL,
		0x1C14E3D216D6079CULL,
		0x1531EC38CEA8B59AULL
	}};
	printf("Test Case 152\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x2B7CBF03579E42B3ULL,
		0xB1BAFBE7BE49F53EULL,
		0x951724391E0D5247ULL,
		0xE069B632E6A2E518ULL,
		0x7530C39B1E7B5D93ULL,
		0x96CBB0286DA0D565ULL,
		0x923FD43994D8F5B2ULL,
		0xB0358611DFF5C90BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5411ABD7F1888572ULL,
		0xE904CC6F8F236496ULL,
		0xB0E46BA9471FA64EULL,
		0x8BD7DC97A204D9D2ULL,
		0x60E948C420D0EDDCULL,
		0x62E141C8E9919988ULL,
		0x84E43E82AA4CFF52ULL,
		0x6EEEAF90F9F7C2C7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7F6D14D4A616C7C1ULL,
		0x58BE3788316A91A8ULL,
		0x25F34F905912F409ULL,
		0x6BBE6AA544A63CCAULL,
		0x15D98B5F3EABB04FULL,
		0xF42AF1E084314CEDULL,
		0x16DBEABB3E940AE0ULL,
		0xDEDB298126020BCCULL
	}};
	printf("Test Case 153\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x283A3412E73851AFULL,
		0xAE38B47047090340ULL,
		0x7834CA90B8E40D43ULL,
		0xA23E3E48E5FFDC5BULL,
		0xDFC02F48CC6F1BB8ULL,
		0xDC6116099F8BEDC9ULL,
		0x9A466637D4B094D7ULL,
		0x29727A407D68C091ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFEDCFC6E9DA0C7D9ULL,
		0x4EB1775204F766D5ULL,
		0x93D5EAD181D7FEC8ULL,
		0xC059CB1226C663BEULL,
		0x3944190CBEC48616ULL,
		0xA4CA684DAF4E7860ULL,
		0x1A88C8C49C2761C1ULL,
		0x709132B1D46975C8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD6E6C87C7A989676ULL,
		0xE089C32243FE6595ULL,
		0xEBE120413933F38BULL,
		0x6267F55AC339BFE5ULL,
		0xE684364472AB9DAEULL,
		0x78AB7E4430C595A9ULL,
		0x80CEAEF34897F516ULL,
		0x59E348F1A901B559ULL
	}};
	printf("Test Case 154\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x98681769E557A9C0ULL,
		0x1FE1603B3E6E1690ULL,
		0xAA39D3BCB4DD4A98ULL,
		0x9C2F7B92F9FE29D6ULL,
		0x2CDB8FDA1C5EE143ULL,
		0xBD657F9516C71F51ULL,
		0xA38072CD9DB8700BULL,
		0x390EDAFC29F0F454ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5F50F953C775E83FULL,
		0xC59B5D6B5EC0ECCEULL,
		0xB425C873C5CA809AULL,
		0x29082CE2FD2B553BULL,
		0xFC6EB5E7058DD1B7ULL,
		0xB5C73B2752564AA5ULL,
		0xCC20C67917388EA7ULL,
		0xA990CFCF347293B0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC738EE3A222241FFULL,
		0xDA7A3D5060AEFA5EULL,
		0x1E1C1BCF7117CA02ULL,
		0xB527577004D57CEDULL,
		0xD0B53A3D19D330F4ULL,
		0x08A244B2449155F4ULL,
		0x6FA0B4B48A80FEACULL,
		0x909E15331D8267E4ULL
	}};
	printf("Test Case 155\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x5141BFA549926FA1ULL,
		0xD031F4B9BA22C2F6ULL,
		0xD524D414851B788FULL,
		0x3EDE417249805ED2ULL,
		0x34F46FABE65535C4ULL,
		0x7FFABFD4D6114503ULL,
		0xC6C775F19CFD74A3ULL,
		0xB9A5DE921893CFEDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD5BF9FC69EBBCBDDULL,
		0xBE38223C42F65F97ULL,
		0x2637887236922534ULL,
		0x3B209B18EAA95179ULL,
		0x11E33B95A085357BULL,
		0xB2F0FDA4810E1F34ULL,
		0xC4BC722D91012ACEULL,
		0xF693C894605EC495ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x84FE2063D729A47CULL,
		0x6E09D685F8D49D61ULL,
		0xF3135C66B3895DBBULL,
		0x05FEDA6AA3290FABULL,
		0x2517543E46D000BFULL,
		0xCD0A4270571F5A37ULL,
		0x027B07DC0DFC5E6DULL,
		0x4F36160678CD0B78ULL
	}};
	printf("Test Case 156\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xCBC53C62A2F6504CULL,
		0x81A5806993B99B04ULL,
		0xB712FE6EF4F98DBFULL,
		0x7C29D800095A7494ULL,
		0xB0C8370F57F31A56ULL,
		0xDE7092AF272A7877ULL,
		0xE19F84B44B1C9903ULL,
		0xE9868B0A9DD19E42ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x518924E0848F5AFFULL,
		0x3883370D567F158CULL,
		0xD8233F3F11214062ULL,
		0x6C2AD890D1BA1A06ULL,
		0x98ED146789B5E6D3ULL,
		0x5ACB977B6C8005CBULL,
		0x4A03567019347108ULL,
		0x2EC61E6245A70433ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9A4C188226790AB3ULL,
		0xB926B764C5C68E88ULL,
		0x6F31C151E5D8CDDDULL,
		0x10030090D8E06E92ULL,
		0x28252368DE46FC85ULL,
		0x84BB05D44BAA7DBCULL,
		0xAB9CD2C45228E80BULL,
		0xC7409568D8769A71ULL
	}};
	printf("Test Case 157\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x38F86952F05683C1ULL,
		0x2B20D6AFD652C25EULL,
		0x681A611A22598C55ULL,
		0x8AD5DF55FC8A16D1ULL,
		0xE032AF4C8FC0194DULL,
		0x667AE01D2A71A9DEULL,
		0xB7D1FF5D1B756DF8ULL,
		0x796E16292F984BA5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBC3E49560120F3C4ULL,
		0x523C172B75867AA3ULL,
		0xBB03DFDA4B269A4EULL,
		0x88C1A17C452DFC39ULL,
		0x74CC90E2E490FE72ULL,
		0xD16ADEAECFAD158BULL,
		0x4D410B1ADB08FB81ULL,
		0x5840942883926DCEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x84C62004F1767005ULL,
		0x791CC184A3D4B8FDULL,
		0xD319BEC0697F161BULL,
		0x02147E29B9A7EAE8ULL,
		0x94FE3FAE6B50E73FULL,
		0xB7103EB3E5DCBC55ULL,
		0xFA90F447C07D9679ULL,
		0x212E8201AC0A266BULL
	}};
	printf("Test Case 158\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xFD487EA7359EA7DEULL,
		0xF2D7A98B9BFED0F5ULL,
		0x95EA4675B0E08AEAULL,
		0x1CAB8CC5FECF468CULL,
		0x87FC648B7F07D316ULL,
		0x421F8CCF6A67273BULL,
		0x69788A9E93C854E9ULL,
		0xAEC2E2FC26D2B828ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFADB73B10028318EULL,
		0x77FB1CAD8BA7CCA1ULL,
		0xAE3AF2BD624DBE34ULL,
		0x9BC3B72E423A5C50ULL,
		0xCD2E4E4AA2274780ULL,
		0xC18AC722D8EACF44ULL,
		0xB113685A4BD315C4ULL,
		0x66AC046E43556B09ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x07930D1635B69650ULL,
		0x852CB52610591C54ULL,
		0x3BD0B4C8D2AD34DEULL,
		0x87683BEBBCF51ADCULL,
		0x4AD22AC1DD209496ULL,
		0x83954BEDB28DE87FULL,
		0xD86BE2C4D81B412DULL,
		0xC86EE6926587D321ULL
	}};
	printf("Test Case 159\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xFD4657FBEE733DDAULL,
		0xB044AC658F27A6B0ULL,
		0x2272FC99613F05A2ULL,
		0x84C4983C7F5A8E20ULL,
		0x6EBF4DCC218EA756ULL,
		0x48D83DEC8ECC70E6ULL,
		0x4325FCE7DEED3F02ULL,
		0xF52B761A7FEA5619ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC06BE99E95558394ULL,
		0xD15A28E249DDA066ULL,
		0x01DFF4C90EDFF2EBULL,
		0xC822C04EB4831070ULL,
		0x7FAA4F6DA9C5AB16ULL,
		0xD09398574A338B7FULL,
		0x2DDC3D2BC6130A93ULL,
		0x03BA54F47358D3D6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3D2DBE657B26BE4EULL,
		0x611E8487C6FA06D6ULL,
		0x23AD08506FE0F749ULL,
		0x4CE65872CBD99E50ULL,
		0x111502A1884B0C40ULL,
		0x984BA5BBC4FFFB99ULL,
		0x6EF9C1CC18FE3591ULL,
		0xF69122EE0CB285CFULL
	}};
	printf("Test Case 160\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x9C670F71A2561D2BULL,
		0x376559E84085DBE9ULL,
		0x55443C4675879648ULL,
		0xAF784A94916EB93DULL,
		0x0301FD906D43CC50ULL,
		0x3083001345E79B2FULL,
		0x9CC8BE1A769A5B46ULL,
		0x7B5F19D13CE445DBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE89EB8F35C11A4BEULL,
		0xEFD93DBBCEB19F40ULL,
		0xBD97542F867EDA1DULL,
		0x9BEF55F33707F78AULL,
		0x1CE99D91A4D1B343ULL,
		0xC6BB252F2BEF6FCFULL,
		0xBC5C94C90C924991ULL,
		0x0BAE40B5D16E5F93ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x74F9B782FE47B995ULL,
		0xD8BC64538E3444A9ULL,
		0xE8D36869F3F94C55ULL,
		0x34971F67A6694EB7ULL,
		0x1FE86001C9927F13ULL,
		0xF638253C6E08F4E0ULL,
		0x20942AD37A0812D7ULL,
		0x70F15964ED8A1A48ULL
	}};
	printf("Test Case 161\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xA82D18FDF0AB722BULL,
		0xFDFCD78AE914E08BULL,
		0xA6BA1121280E8407ULL,
		0x2366D81AF88921B5ULL,
		0x965465A8A4C3DA44ULL,
		0xAA850529BCC4C46DULL,
		0xFF007A3BF80AEDEEULL,
		0x518D582108D43967ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAD0AE876679CDFFEULL,
		0x15A36706A6C1DF15ULL,
		0x4B357AC93F21D221ULL,
		0x088F12A877C37247ULL,
		0x28C99CEDFBBAE367ULL,
		0x953A56F6F3C9E86EULL,
		0x64A449ED00720618ULL,
		0x9827ED2CC14B19E1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0527F08B9737ADD5ULL,
		0xE85FB08C4FD53F9EULL,
		0xED8F6BE8172F5626ULL,
		0x2BE9CAB28F4A53F2ULL,
		0xBE9DF9455F793923ULL,
		0x3FBF53DF4F0D2C03ULL,
		0x9BA433D6F878EBF6ULL,
		0xC9AAB50DC99F2086ULL
	}};
	printf("Test Case 162\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xEF742B9D5EFC8084ULL,
		0x12463CE0E406FD6EULL,
		0x584774D6FCB67FDDULL,
		0x2DB3707728C3E564ULL,
		0x8A8A587F7FB6A19AULL,
		0x384DAC9785D34A49ULL,
		0x67B6FF56CC516889ULL,
		0xC5689DD08EAF94F7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7CAECD4EA772468CULL,
		0x18D4D4E51CB4B49AULL,
		0x131F1A1610237AF0ULL,
		0xF1645AA7864D61B5ULL,
		0x7C1B1E91DF8C524BULL,
		0x7F2B93B8F627CF32ULL,
		0x2DD442B07CC47611ULL,
		0xC73A888E9E0E39A6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x93DAE6D3F98EC608ULL,
		0x0A92E805F8B249F4ULL,
		0x4B586EC0EC95052DULL,
		0xDCD72AD0AE8E84D1ULL,
		0xF69146EEA03AF3D1ULL,
		0x47663F2F73F4857BULL,
		0x4A62BDE6B0951E98ULL,
		0x0252155E10A1AD51ULL
	}};
	printf("Test Case 163\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x888720EEBC3108F7ULL,
		0x966C5C6C6F16D467ULL,
		0xDA4A0783B85B4F16ULL,
		0xBEF72C61C6C4B8E6ULL,
		0xC528BAD61D67C117ULL,
		0xD646B220EB15AB2CULL,
		0xD9EDA972651E414CULL,
		0x3F621D6980F1BB6FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x68B66E057D58F4D2ULL,
		0x60A60050164947A3ULL,
		0x40D5B6FB9AAD4029ULL,
		0x679E75BF0AAD7D5FULL,
		0x6D0F5935445D548DULL,
		0x2ACE87F548678161ULL,
		0xCADF5F259A63F409ULL,
		0xE243931FF9BA493AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE0314EEBC169FC25ULL,
		0xF6CA5C3C795F93C4ULL,
		0x9A9FB17822F60F3FULL,
		0xD96959DECC69C5B9ULL,
		0xA827E3E3593A959AULL,
		0xFC8835D5A3722A4DULL,
		0x1332F657FF7DB545ULL,
		0xDD218E76794BF255ULL
	}};
	printf("Test Case 164\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xBB28B1C78C0E2BD2ULL,
		0x7ADB0A945BF8996CULL,
		0x4A39A604FC8A7EB8ULL,
		0xD5E14D2001D02BA5ULL,
		0x7E87F521F3C0FD2AULL,
		0xDB02BE096C8C8080ULL,
		0x6F7103C7A3503605ULL,
		0x1FAA81175E206C28ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA9C32D6A726ADF36ULL,
		0x2047DCDB06C1643FULL,
		0x22C8729DE980EA98ULL,
		0xD64C5990175D3E4AULL,
		0xD27AEB67A001015EULL,
		0xE1F8B947CCB36B53ULL,
		0xB6115CC7B5EB17DFULL,
		0xEB1BA7C9CD626A81ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x12EB9CADFE64F4E4ULL,
		0x5A9CD64F5D39FD53ULL,
		0x68F1D499150A9420ULL,
		0x03AD14B0168D15EFULL,
		0xACFD1E4653C1FC74ULL,
		0x3AFA074EA03FEBD3ULL,
		0xD9605F0016BB21DAULL,
		0xF4B126DE934206A9ULL
	}};
	printf("Test Case 165\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xB2200F71AFD664ECULL,
		0x5029C6AD693F1E52ULL,
		0xF7F1AB3BB7F6833FULL,
		0xA4A5584328A63770ULL,
		0xD41B2D9A9EE7CBDDULL,
		0x5B9DC1A111218897ULL,
		0x3A78C5521374B435ULL,
		0xDAD60FE173E48B81ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0716232FD2B3C156ULL,
		0x3EB8B4DDE2E09727ULL,
		0x9CD86AB4E7B21A1AULL,
		0xA3F8099945283BD7ULL,
		0x54F1F36F1E130CCAULL,
		0x596D4572771ED553ULL,
		0x69FBFC202B458DF7ULL,
		0xF3B8506D6C7B10EBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB5362C5E7D65A5BAULL,
		0x6E9172708BDF8975ULL,
		0x6B29C18F50449925ULL,
		0x075D51DA6D8E0CA7ULL,
		0x80EADEF580F4C717ULL,
		0x02F084D3663F5DC4ULL,
		0x53833972383139C2ULL,
		0x296E5F8C1F9F9B6AULL
	}};
	printf("Test Case 166\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x6EE4FD34C917B46AULL,
		0x65DF4829C74C0C94ULL,
		0x87ADDCAC3A4F1A7EULL,
		0xF2B573E0C2FB1212ULL,
		0x39D0C067594450A2ULL,
		0x7946E671A06AB824ULL,
		0xC82DB7659BF61405ULL,
		0x86D5C51EBF47DEC1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0A54C824D10DBE1DULL,
		0x5AF194BC4AD86637ULL,
		0xEF46AAB0944B4C6AULL,
		0xA582FC5183CD806FULL,
		0x33D7FED25838E101ULL,
		0xD383334E5C74B65DULL,
		0x1B3D4A6187D4A41BULL,
		0xA74146A8913048CFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x64B03510181A0A77ULL,
		0x3F2EDC958D946AA3ULL,
		0x68EB761CAE045614ULL,
		0x57378FB14136927DULL,
		0x0A073EB5017CB1A3ULL,
		0xAAC5D53FFC1E0E79ULL,
		0xD310FD041C22B01EULL,
		0x219483B62E77960EULL
	}};
	printf("Test Case 167\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x0EE3D5330002441DULL,
		0x6C24CD9547A5D637ULL,
		0xF69AFB71C2798E0CULL,
		0xF5048739EB9FBED0ULL,
		0xF8FB1F72932A7B63ULL,
		0xF6AB69FB46FA7340ULL,
		0x95965395B8CC55E2ULL,
		0x1F37059AC04D7ED8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x25991F3845157A76ULL,
		0xC5C3D5383BFF338EULL,
		0xC34C1EA2D8A91040ULL,
		0xC2028CFBF240C641ULL,
		0xADE6667EC2488FA5ULL,
		0x74F3D675B43FA558ULL,
		0x0E6DC795979A9D45ULL,
		0xAFCD6025B2F6AD99ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2B7ACA0B45173E6BULL,
		0xA9E718AD7C5AE5B9ULL,
		0x35D6E5D31AD09E4CULL,
		0x37060BC219DF7891ULL,
		0x551D790C5162F4C6ULL,
		0x8258BF8EF2C5D618ULL,
		0x9BFB94002F56C8A7ULL,
		0xB0FA65BF72BBD341ULL
	}};
	printf("Test Case 168\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x549A2C0D8D32D7F3ULL,
		0x73B6063EE7ED8A30ULL,
		0x9EA4636C0316C022ULL,
		0x6FD715653D10F359ULL,
		0xE763289B8CA8188AULL,
		0x6BA114CABBDF6DBAULL,
		0x53C1C186221C6184ULL,
		0x22D8CDB03D8B2475ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0E07EA13856BA128ULL,
		0xEDEFB8360DC4385DULL,
		0xD68706B52AD194FFULL,
		0x0153B17667AEDF87ULL,
		0x0F0A86DBC02DB4E8ULL,
		0x05F2354526D39A12ULL,
		0x6285282A51E1AB04ULL,
		0x81A6CBBB67C5CE77ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5A9DC61E085976DBULL,
		0x9E59BE08EA29B26DULL,
		0x482365D929C754DDULL,
		0x6E84A4135ABE2CDEULL,
		0xE869AE404C85AC62ULL,
		0x6E53218F9D0CF7A8ULL,
		0x3144E9AC73FDCA80ULL,
		0xA37E060B5A4EEA02ULL
	}};
	printf("Test Case 169\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x39C3173320113E55ULL,
		0x2BFF4AB6E6C1D722ULL,
		0xAD56E727994CFD29ULL,
		0x62EAC773CFD2336EULL,
		0xD55911FD94288F46ULL,
		0xCF073ED3830A2BCDULL,
		0x8E00016938A93F2CULL,
		0xFF008167BA41486FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F5B0810D57929A0ULL,
		0x98144BF927F824EAULL,
		0x27D6E4DAD9C2FB6AULL,
		0x8213FEBBF8D456F1ULL,
		0xAAC4BD89398AE6B1ULL,
		0x2F6816A99A857376ULL,
		0x4571CB11C21A5266ULL,
		0x85BA4F8139811486ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x36981F23F56817F5ULL,
		0xB3EB014FC139F3C8ULL,
		0x8A8003FD408E0643ULL,
		0xE0F939C83706659FULL,
		0x7F9DAC74ADA269F7ULL,
		0xE06F287A198F58BBULL,
		0xCB71CA78FAB36D4AULL,
		0x7ABACEE683C05CE9ULL
	}};
	printf("Test Case 170\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xB66F85FA87E76750ULL,
		0x200145E19C07E42EULL,
		0xE42F3697469C673FULL,
		0x97A6DF565639DBE1ULL,
		0x621BB118BCE81BDFULL,
		0x99510593F0ACBC20ULL,
		0x268F51833F87DB1DULL,
		0xDDC47F27F0E1E3D4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB4A316FD878EAD54ULL,
		0x7291F46888E46783ULL,
		0x926A53581200C5B9ULL,
		0x6B759B416D549846ULL,
		0x9E8624DECBD7C420ULL,
		0x8C3424A2DD6FEDE8ULL,
		0xC446AAA9C9E62308ULL,
		0x50087DB6048D7BA8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x02CC93070069CA04ULL,
		0x5290B18914E383ADULL,
		0x764565CF549CA286ULL,
		0xFCD344173B6D43A7ULL,
		0xFC9D95C6773FDFFFULL,
		0x156521312DC351C8ULL,
		0xE2C9FB2AF661F815ULL,
		0x8DCC0291F46C987CULL
	}};
	printf("Test Case 171\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x2A2221FF01FCD51DULL,
		0x2311288F3035F901ULL,
		0x03093F2480AAF8F9ULL,
		0xD08B4D9CFD678025ULL,
		0xE1992CE3BB9703BFULL,
		0x625AB22D5E4D4774ULL,
		0x85D5FD0ED331EAE0ULL,
		0xF7025DBBF0793FE9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE99050DBD8D201C1ULL,
		0x6ADAD7B126E7A4C0ULL,
		0xF61E1A50CBC5E855ULL,
		0x9CA1AEDFC0592BC8ULL,
		0x71AE61B0EB98EF2BULL,
		0x7E647F857EFDDDF1ULL,
		0xCF997C2BE83FE564ULL,
		0x5896E1418852A66AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC3B27124D92ED4DCULL,
		0x49CBFF3E16D25DC1ULL,
		0xF51725744B6F10ACULL,
		0x4C2AE3433D3EABEDULL,
		0x90374D53500FEC94ULL,
		0x1C3ECDA820B09A85ULL,
		0x4A4C81253B0E0F84ULL,
		0xAF94BCFA782B9983ULL
	}};
	printf("Test Case 172\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xB12683BFB3C04353ULL,
		0x74D1C9A9C3E0DF60ULL,
		0x33CED1CE1976626CULL,
		0x549EB111D1380158ULL,
		0x11E8449C1AE00580ULL,
		0x0C46009C3AC38F62ULL,
		0x8C83A86B350756C0ULL,
		0xF1EA80E2F61A9815ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3E87E4515E751316ULL,
		0x40127D8A319D074CULL,
		0x8331E1883F114220ULL,
		0x0967BD3E724EBD43ULL,
		0x1A07E1C98F919B73ULL,
		0x050F0630B3DCF958ULL,
		0xB5F0DACD8E33CC0CULL,
		0x6D81E05EBED694DBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8FA167EEEDB55045ULL,
		0x34C3B423F27DD82CULL,
		0xB0FF30462667204CULL,
		0x5DF90C2FA376BC1BULL,
		0x0BEFA55595719EF3ULL,
		0x094906AC891F763AULL,
		0x397372A6BB349ACCULL,
		0x9C6B60BC48CC0CCEULL
	}};
	printf("Test Case 173\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x1CA0C729101602BEULL,
		0x1E6B63ABAB121CF1ULL,
		0xE373C415A53521D2ULL,
		0x0B660B27E8C0D7ECULL,
		0x5A378471A712AA6DULL,
		0xA5682984CB1D20F5ULL,
		0xD23A305957707035ULL,
		0x564F3F28E0BE874CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2F3543D1B045CD06ULL,
		0x0D85A66147CAC331ULL,
		0xAE10C9D81CA1A8C9ULL,
		0xA54EF348EDCFC636ULL,
		0x7A8BDE0774BA7739ULL,
		0x9672552825194511ULL,
		0xC4B6E7793614FBF4ULL,
		0xE6BBFD784FD973C7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x339584F8A053CFB8ULL,
		0x13EEC5CAECD8DFC0ULL,
		0x4D630DCDB994891BULL,
		0xAE28F86F050F11DAULL,
		0x20BC5A76D3A8DD54ULL,
		0x331A7CACEE0465E4ULL,
		0x168CD72061648BC1ULL,
		0xB0F4C250AF67F48BULL
	}};
	printf("Test Case 174\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xDC277BB5EDCE015EULL,
		0xC57F55B65B0FEEFDULL,
		0xAAB6640BA4855197ULL,
		0xF1258AF85E072F04ULL,
		0x4422B6277DA57489ULL,
		0x34846F7CC8B5C3B7ULL,
		0x66C7C8509258D66BULL,
		0xC521F07209336C08ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x333CFCF21C31F946ULL,
		0x15B547B3B33AC383ULL,
		0xDA59013E47B9D717ULL,
		0x0B0A4389801FF26DULL,
		0x9739669C425B2A2CULL,
		0x3E137C7D5A882705ULL,
		0xEA7BD324BD8A050CULL,
		0x0F2971902A752569ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEF1B8747F1FFF818ULL,
		0xD0CA1205E8352D7EULL,
		0x70EF6535E33C8680ULL,
		0xFA2FC971DE18DD69ULL,
		0xD31BD0BB3FFE5EA5ULL,
		0x0A971301923DE4B2ULL,
		0x8CBC1B742FD2D367ULL,
		0xCA0881E223464961ULL
	}};
	printf("Test Case 175\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x7057F22447AFDDB8ULL,
		0xCDC5F78683AF0164ULL,
		0x8D50A4FFFB449AC5ULL,
		0x408DDFA0E8A5CB5BULL,
		0xD948A83476F69FCEULL,
		0x945BB871690CED16ULL,
		0x61ADC0AEB2655CDBULL,
		0x61D1514FEE54832FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x420D9CE134455BEEULL,
		0x4D809E5B6F2A0ECCULL,
		0x1D8937AFCED90E38ULL,
		0x194DA20464833968ULL,
		0x99869593806BA699ULL,
		0x9FB097ED52179BFEULL,
		0xD7543768D794AF1CULL,
		0x70096B906F56DAD0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x325A6EC573EA8656ULL,
		0x804569DDEC850FA8ULL,
		0x90D99350359D94FDULL,
		0x59C07DA48C26F233ULL,
		0x40CE3DA7F69D3957ULL,
		0x0BEB2F9C3B1B76E8ULL,
		0xB6F9F7C665F1F3C7ULL,
		0x11D83ADF810259FFULL
	}};
	printf("Test Case 176\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x1D2E7404A8A6772AULL,
		0xBBD9B232F5742359ULL,
		0x340139EF7005EC19ULL,
		0x2744C83D42B980E3ULL,
		0x9F6FE5BD8DBAB67BULL,
		0x512421AE9E90BD80ULL,
		0xCD15E66786634E02ULL,
		0x1A82C805CF17B5B7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x26A8643049F28F6AULL,
		0x748A063433FBE5AAULL,
		0x14CCB557BF5E89D6ULL,
		0xD00DE90717E33BBDULL,
		0xA71B156A3967F8D6ULL,
		0xE0A4D9618CFCC101ULL,
		0xED96AB1A9AAB85CFULL,
		0x931C8BA8C911378EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3B861034E154F840ULL,
		0xCF53B406C68FC6F3ULL,
		0x20CD8CB8CF5B65CFULL,
		0xF749213A555ABB5EULL,
		0x3874F0D7B4DD4EADULL,
		0xB180F8CF126C7C81ULL,
		0x20834D7D1CC8CBCDULL,
		0x899E43AD06068239ULL
	}};
	printf("Test Case 177\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x9C3DABC1F5753535ULL,
		0xC828E469230ADBB6ULL,
		0xB67891C1961A31EAULL,
		0x4AA9521923D700FBULL,
		0x34E74866324711A5ULL,
		0xEE0619055203730CULL,
		0xBD28141D1EF93285ULL,
		0x045159BD1EC2BC22ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCF7942FE1889F6F1ULL,
		0x1DA2EC366CDD0137ULL,
		0xE0D3799891974FF7ULL,
		0x99C3C1ABFE909E16ULL,
		0x0E02A38BC41EEC36ULL,
		0x497FF8477D4F95A2ULL,
		0x2393EF99A6225297ULL,
		0xCF5C8E2D37EE3FF2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5344E93FEDFCC3C4ULL,
		0xD58A085F4FD7DA81ULL,
		0x56ABE859078D7E1DULL,
		0xD36A93B2DD479EEDULL,
		0x3AE5EBEDF659FD93ULL,
		0xA779E1422F4CE6AEULL,
		0x9EBBFB84B8DB6012ULL,
		0xCB0DD790292C83D0ULL
	}};
	printf("Test Case 178\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x2A7B4278207781AFULL,
		0x4304CA7953218915ULL,
		0x19CFE0904CD1381AULL,
		0x2C3B0419C32DADEFULL,
		0xB5EDB338191C6761ULL,
		0x946D129084FE7321ULL,
		0xB45760552ECDB8B9ULL,
		0x025E995113B024BCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA1C140329A0B3365ULL,
		0xE9790F548C92CB2CULL,
		0xB197B467F2000D7DULL,
		0x75BDFD11691C3FCFULL,
		0xAC3A6C3AE41E5868ULL,
		0x47C04C21A624165AULL,
		0x38F2B04375D84A73ULL,
		0x9902EF4247F85503ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8BBA024ABA7CB2CAULL,
		0xAA7DC52DDFB34239ULL,
		0xA85854F7BED13567ULL,
		0x5986F908AA319220ULL,
		0x19D7DF02FD023F09ULL,
		0xD3AD5EB122DA657BULL,
		0x8CA5D0165B15F2CAULL,
		0x9B5C7613544871BFULL
	}};
	printf("Test Case 179\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xF38845D460B80F68ULL,
		0xAC8D3C674F1312B3ULL,
		0x42B0E0D5290C726AULL,
		0xF2E5E1FB0631BDB2ULL,
		0x31787C3888E2D686ULL,
		0x9036DF7E3D214187ULL,
		0x6455BF47AB9CB166ULL,
		0x0ED92F689E4F0A93ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFB520EA3153A0231ULL,
		0x8304899EAD5C1197ULL,
		0x87C93DEA50ED5BC9ULL,
		0x959716480A61DA7AULL,
		0x0E5272EF0D18BDE3ULL,
		0xC6EB471410F81180ULL,
		0x0D5B1E412649EA4EULL,
		0x65F896EAF5F62D44ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x08DA4B7775820D59ULL,
		0x2F89B5F9E24F0324ULL,
		0xC579DD3F79E129A3ULL,
		0x6772F7B30C5067C8ULL,
		0x3F2A0ED785FA6B65ULL,
		0x56DD986A2DD95007ULL,
		0x690EA1068DD55B28ULL,
		0x6B21B9826BB927D7ULL
	}};
	printf("Test Case 180\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x4B9D46FF66BD4F3DULL,
		0x9574EBEEC17C7907ULL,
		0xA773D20C4F26EBA4ULL,
		0xD2B51980819B689AULL,
		0x6C3DDC00AB45138DULL,
		0x1A7B7864FC93BCDAULL,
		0xEA9FB83859D179AEULL,
		0x3CA7ED80386A3A6BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5F77F459EDC64E14ULL,
		0x98765441FAA67D28ULL,
		0xB276E11C1A148657ULL,
		0x92E2FAAAF97136B4ULL,
		0x549AC8CDE537D64FULL,
		0xDDA198C089360F92ULL,
		0x15350033687FA487ULL,
		0xEB695EAEDE7924C2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x14EAB2A68B7B0129ULL,
		0x0D02BFAF3BDA042FULL,
		0x1505331055326DF3ULL,
		0x4057E32A78EA5E2EULL,
		0x38A714CD4E72C5C2ULL,
		0xC7DAE0A475A5B348ULL,
		0xFFAAB80B31AEDD29ULL,
		0xD7CEB32EE6131EA9ULL
	}};
	printf("Test Case 181\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x3A3F49E5E08EC2EDULL,
		0x24D350E4BFBB438FULL,
		0x5D1115615B393A39ULL,
		0xC355B3AE55D0F918ULL,
		0xF0EECBF04B005780ULL,
		0x1782B94BA8831C04ULL,
		0x43F6397E43C67BF5ULL,
		0xC952E7F44A3CFC00ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5F4EF72970E200B0ULL,
		0x1551322F640B2D09ULL,
		0x44E45CDEB071A9CBULL,
		0x7E9DBBA5FBA2A57BULL,
		0x10EEDBC6A334E202ULL,
		0xD04CE627D83D8706ULL,
		0x7F72A0D52C3637C2ULL,
		0x0DAD4AAD2C62DB6DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6571BECC906CC25DULL,
		0x318262CBDBB06E86ULL,
		0x19F549BFEB4893F2ULL,
		0xBDC8080BAE725C63ULL,
		0xE0001036E834B582ULL,
		0xC7CE5F6C70BE9B02ULL,
		0x3C8499AB6FF04C37ULL,
		0xC4FFAD59665E276DULL
	}};
	printf("Test Case 182\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xDF6A0C35311260C5ULL,
		0x49105D6B1E4F28A1ULL,
		0x3F47528419E1A628ULL,
		0x063D2A06A512E34CULL,
		0xD96232B7C7B0734CULL,
		0x2286F6424A61D2EBULL,
		0x6098C9217791F620ULL,
		0x1911B93B6CF35FB2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3F1DB82C7D0F5721ULL,
		0x386F7D2D1A902EA4ULL,
		0x88A8D30E11BCF4C5ULL,
		0xB60C37E3BC4656C4ULL,
		0xA9019ABCCB0222C3ULL,
		0x672E938D297D74D9ULL,
		0xD186D73ABAD5E7CAULL,
		0xECA4605B38326E5CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE077B4194C1D37E4ULL,
		0x717F204604DF0605ULL,
		0xB7EF818A085D52EDULL,
		0xB0311DE51954B588ULL,
		0x7063A80B0CB2518FULL,
		0x45A865CF631CA632ULL,
		0xB11E1E1BCD4411EAULL,
		0xF5B5D96054C131EEULL
	}};
	printf("Test Case 183\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xE67E75C2BF971F4CULL,
		0x500F0F88CBC4751FULL,
		0x540DC9FD3D1D9EEFULL,
		0xA6471FC4A3174364ULL,
		0x26B9D9161D538F00ULL,
		0x2E88A6F64CC8C5FDULL,
		0x50D0E0BAB871EB7AULL,
		0xA25D826CC8CE93D3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3D2A7F3870B2E7C8ULL,
		0x28C406230FB89A93ULL,
		0x5435BDF1A0736A0AULL,
		0x79F2AC101A6CB5A1ULL,
		0xA970C441670D7CE7ULL,
		0x61E9F5DD5B994A8FULL,
		0x0ACEB55DFA6A7FB2ULL,
		0x1217AF36B4FC9249ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDB540AFACF25F884ULL,
		0x78CB09ABC47CEF8CULL,
		0x0038740C9D6EF4E5ULL,
		0xDFB5B3D4B97BF6C5ULL,
		0x8FC91D577A5EF3E7ULL,
		0x4F61532B17518F72ULL,
		0x5A1E55E7421B94C8ULL,
		0xB04A2D5A7C32019AULL
	}};
	printf("Test Case 184\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x899701E134248F32ULL,
		0x30268554D9FF43F5ULL,
		0x438B1B187D855231ULL,
		0xDAC236BA13DB111DULL,
		0x1F419E2163D39717ULL,
		0x671990E04D617F37ULL,
		0xC80C2D23233050BBULL,
		0x100BA7BCFB78B31DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x145FCC82111472AEULL,
		0x39374C36EE1C83BDULL,
		0x191076A8C45F4FDDULL,
		0xD85FB2B73FA00483ULL,
		0x56D8B2E29869CEF8ULL,
		0x4DB4AE2809745FA5ULL,
		0x840E690793A2454CULL,
		0xD6201DA3D0939796ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9DC8CD632530FD9CULL,
		0x0911C96237E3C048ULL,
		0x5A9B6DB0B9DA1DECULL,
		0x029D840D2C7B159EULL,
		0x49992CC3FBBA59EFULL,
		0x2AAD3EC844152092ULL,
		0x4C024424B09215F7ULL,
		0xC62BBA1F2BEB248BULL
	}};
	printf("Test Case 185\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xECD11B32887739DCULL,
		0x19C436F1357E91DCULL,
		0x570D4D5929E2D196ULL,
		0x11842E2126A1BA63ULL,
		0x7C2DC365F1DB1D7CULL,
		0x41402E2C268DC760ULL,
		0x996CACFFBA728339ULL,
		0x3220801C585CC254ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7AD284CEE5ABD365ULL,
		0x33125F5CE0FB899EULL,
		0x645E49491674E2BCULL,
		0xBD41F45D6D28F8A6ULL,
		0x965390CAD08E3AA1ULL,
		0xEF597FC581ACB405ULL,
		0x6AA44CBBE045E412ULL,
		0x6EA6494AE4654B14ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x96039FFC6DDCEAB9ULL,
		0x2AD669ADD5851842ULL,
		0x335304103F96332AULL,
		0xACC5DA7C4B8942C5ULL,
		0xEA7E53AF215527DDULL,
		0xAE1951E9A7217365ULL,
		0xF3C8E0445A37672BULL,
		0x5C86C956BC398940ULL
	}};
	printf("Test Case 186\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xC0339BB8E9CEED14ULL,
		0x880BDDF89ACDFBF8ULL,
		0x42E0E481B99B67A0ULL,
		0x86E6969E7277D848ULL,
		0xA3BC413892BA0404ULL,
		0x2151C79D5242F6CCULL,
		0x065CAC90B985D1D0ULL,
		0xC68F7825E788292DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xED4755774A6B8A04ULL,
		0x85C7088EC659864FULL,
		0x25F9092C8CC265ECULL,
		0x4555EC7A003F3D25ULL,
		0xBAF9FAA336AA055DULL,
		0x6748CEDFCAD14AB8ULL,
		0xEFA499F2FDA29C22ULL,
		0x388D34A6BC323800ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2D74CECFA3A56710ULL,
		0x0DCCD5765C947DB7ULL,
		0x6719EDAD3559024CULL,
		0xC3B37AE47248E56DULL,
		0x1945BB9BA4100159ULL,
		0x461909429893BC74ULL,
		0xE9F8356244274DF2ULL,
		0xFE024C835BBA112DULL
	}};
	printf("Test Case 187\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xE6081E0A10DA878EULL,
		0x8BA9FFCDBC3E97F6ULL,
		0x2D4A2B22C2B29A85ULL,
		0x29E21507328BA0ECULL,
		0xD3738DCBABDC432DULL,
		0x01D5B8F1FAF1533CULL,
		0xA8D6751013E5F538ULL,
		0x949D3D62CB6D4903ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x514B7C4F6A00EC4AULL,
		0x239C0431E7051788ULL,
		0xFC0127CF9D1CF7E1ULL,
		0x237AFDDC93BC20B2ULL,
		0x0E1FDB89FB170B25ULL,
		0x0A7BB9DD1AEF8271ULL,
		0xBE2CF21F6990A5FDULL,
		0x0EB1B4C4D02B6DE8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB74362457ADA6BC4ULL,
		0xA835FBFC5B3B807EULL,
		0xD14B0CED5FAE6D64ULL,
		0x0A98E8DBA137805EULL,
		0xDD6C564250CB4808ULL,
		0x0BAE012CE01ED14DULL,
		0x16FA870F7A7550C5ULL,
		0x9A2C89A61B4624EBULL
	}};
	printf("Test Case 188\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x61985FAC78F88B09ULL,
		0x5103C422E327EC5BULL,
		0xD4D52362FCF9A4DEULL,
		0xE267CEDF220D140BULL,
		0xA26864A505B7F0CDULL,
		0x15DFC289DE3082ABULL,
		0x2C28B76D1FCC68BDULL,
		0x6D450A74B59F90A5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9C85CF2E5E5A173DULL,
		0x113229F9D62D704FULL,
		0x001610C305139B07ULL,
		0xC2D1240CD8BE3EF0ULL,
		0x18F4F9E91DB70556ULL,
		0x572906060147B313ULL,
		0xEEF7F14280C6F6F8ULL,
		0xB46A77638C1072EAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFD1D908226A29C34ULL,
		0x4031EDDB350A9C14ULL,
		0xD4C333A1F9EA3FD9ULL,
		0x20B6EAD3FAB32AFBULL,
		0xBA9C9D4C1800F59BULL,
		0x42F6C48FDF7731B8ULL,
		0xC2DF462F9F0A9E45ULL,
		0xD92F7D17398FE24FULL
	}};
	printf("Test Case 189\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xC299B35969B3844FULL,
		0x3B0D404F24880B1AULL,
		0x0891FD3D5DFDE68EULL,
		0x3E651A291AF68B4DULL,
		0x452D2468E296B725ULL,
		0x5C8289B99248A82BULL,
		0x8BD256748B662F19ULL,
		0x1C4592885E3F1292ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAA8633319182CC5EULL,
		0xEAFAB8D958B482ABULL,
		0xADEFDD8CBCBD7A0AULL,
		0xB37E0A0E02F4D65DULL,
		0x38F7C26445725137ULL,
		0x20DB1A02E45A361CULL,
		0x939919DF1243C535ULL,
		0x154A52FFC7938A09ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x681F8068F8314811ULL,
		0xD1F7F8967C3C89B1ULL,
		0xA57E20B1E1409C84ULL,
		0x8D1B102718025D10ULL,
		0x7DDAE60CA7E4E612ULL,
		0x7C5993BB76129E37ULL,
		0x184B4FAB9925EA2CULL,
		0x090FC07799AC989BULL
	}};
	printf("Test Case 190\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xC8241C0440E7EE81ULL,
		0xFD24D675D1EFAA6FULL,
		0x8A1240235BAB11D6ULL,
		0xF3F4963603A8BEAFULL,
		0x5D7E9D67090C778BULL,
		0xC634CD21D63C49CDULL,
		0xBD6B91591D9B234BULL,
		0xA9680844ADABDFE4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEEE521DFA01EB4F2ULL,
		0x05A6576D8C1AFC51ULL,
		0xC6A42A6ACBD5A4F4ULL,
		0xA0E17D4A6C6EC656ULL,
		0x94ACF2EB34D82EC8ULL,
		0x60394E754611FA75ULL,
		0x375F58CCDA6BDF33ULL,
		0xCA31E057B53B195DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x26C13DDBE0F95A73ULL,
		0xF88281185DF5563EULL,
		0x4CB66A49907EB522ULL,
		0x5315EB7C6FC678F9ULL,
		0xC9D26F8C3DD45943ULL,
		0xA60D8354902DB3B8ULL,
		0x8A34C995C7F0FC78ULL,
		0x6359E8131890C6B9ULL
	}};
	printf("Test Case 191\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xACA6EBEA4CEE4903ULL,
		0xBF5ABCF6FA0E473AULL,
		0xED3363E0C77D5470ULL,
		0xA1585EA039AECB44ULL,
		0x9C4B1717E23D8C11ULL,
		0x6C26039F517AF413ULL,
		0x6A3AFC172821B016ULL,
		0x45AA360CBEEB842EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5E115CC224403C4BULL,
		0x10236CBBC1E9A983ULL,
		0xACCDCC02D2802BA2ULL,
		0x86B4C7B2D89D2BC7ULL,
		0x4815AD07C98D5B7CULL,
		0xDAC7E69A0442107FULL,
		0x8AB5695CB86B3C2BULL,
		0x426F26F385403310ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF2B7B72868AE7548ULL,
		0xAF79D04D3BE7EEB9ULL,
		0x41FEAFE215FD7FD2ULL,
		0x27EC9912E133E083ULL,
		0xD45EBA102BB0D76DULL,
		0xB6E1E5055538E46CULL,
		0xE08F954B904A8C3DULL,
		0x07C510FF3BABB73EULL
	}};
	printf("Test Case 192\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xED0F75A4BFC3EE0CULL,
		0x7CD4DB061ACA79DEULL,
		0x29CDB218D170A5F8ULL,
		0xCDFAE452571B567CULL,
		0x37894877AEBED091ULL,
		0x1F48B118C64831E2ULL,
		0xC805F8F52256362AULL,
		0xA69D8B9F776846F0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB9D71925798B01CFULL,
		0xDAC18879B7913F28ULL,
		0x1803610799F15222ULL,
		0x7675F32861C9E7DCULL,
		0x8DE2450D69476B38ULL,
		0x7299ADD92288E640ULL,
		0xD70986DDE7AB9B1FULL,
		0x530A5D8ACB90EF6AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x54D86C81C648EFC3ULL,
		0xA615537FAD5B46F6ULL,
		0x31CED31F4881F7DAULL,
		0xBB8F177A36D2B1A0ULL,
		0xBA6B0D7AC7F9BBA9ULL,
		0x6DD11CC1E4C0D7A2ULL,
		0x1F0C7E28C5FDAD35ULL,
		0xF597D615BCF8A99AULL
	}};
	printf("Test Case 193\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x61C7C69490BE067AULL,
		0xEE03B61EC544F132ULL,
		0xF216BB65C00EFF99ULL,
		0x9E017E8DA3D54B8BULL,
		0x79BC4951FB3423E6ULL,
		0x200BBA995372B6A1ULL,
		0xBBA250EC5C5A00EBULL,
		0x6A660437A45EE47CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE9670E40A9E00C21ULL,
		0x924E2DD64E1F257CULL,
		0xC96ECDC9BAF74E48ULL,
		0xD032BF202651F773ULL,
		0xF6B649831686EAEDULL,
		0xD0048D81338D20EBULL,
		0xE54C32344E95A241ULL,
		0x9B5FBF7170AC673BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x88A0C8D4395E0A5BULL,
		0x7C4D9BC88B5BD44EULL,
		0x3B7876AC7AF9B1D1ULL,
		0x4E33C1AD8584BCF8ULL,
		0x8F0A00D2EDB2C90BULL,
		0xF00F371860FF964AULL,
		0x5EEE62D812CFA2AAULL,
		0xF139BB46D4F28347ULL
	}};
	printf("Test Case 194\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x930C35291480272CULL,
		0x781A628242AD6B88ULL,
		0x26C940FEE41CED5BULL,
		0x55FEDBC24B7B4AD5ULL,
		0x25AEF4369A8AF3FBULL,
		0x0F45B3F51157FE96ULL,
		0xB5637F6B2617FD86ULL,
		0xA8D4091D951D306EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7053B6CB62C44985ULL,
		0x3610790D55B527DAULL,
		0xE023B2784E34A5CCULL,
		0xBB9383BB1F1F7959ULL,
		0x6E88C45CCFC67D8DULL,
		0xDFEA7FF26C3B8C36ULL,
		0x1C0C265D0C45F374ULL,
		0xD758E9B9E44A9F45ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE35F83E276446EA9ULL,
		0x4E0A1B8F17184C52ULL,
		0xC6EAF286AA284897ULL,
		0xEE6D58795464338CULL,
		0x4B26306A554C8E76ULL,
		0xD0AFCC077D6C72A0ULL,
		0xA96F59362A520EF2ULL,
		0x7F8CE0A47157AF2BULL
	}};
	printf("Test Case 195\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x877F333E6DDFCD1BULL,
		0x0978BD67CC07AE34ULL,
		0x54E6418FFE75F171ULL,
		0x04938C0C08D035BDULL,
		0xE2F89F4B915DC230ULL,
		0x4BE4672CDD186C09ULL,
		0x4C32A7E9377898B6ULL,
		0x395D2F587D28D2B4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9D269489ECE11A71ULL,
		0x3A6CF23C472D2AC5ULL,
		0x40D779DE97E44E41ULL,
		0x5FEC773B3C913B67ULL,
		0x284A93963CC7320DULL,
		0x1AFF02809B227143ULL,
		0xAB284631CF066E04ULL,
		0x55D8C8B4E36C904CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1A59A7B7813ED76AULL,
		0x33144F5B8B2A84F1ULL,
		0x143138516991BF30ULL,
		0x5B7FFB3734410EDAULL,
		0xCAB20CDDAD9AF03DULL,
		0x511B65AC463A1D4AULL,
		0xE71AE1D8F87EF6B2ULL,
		0x6C85E7EC9E4442F8ULL
	}};
	printf("Test Case 196\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x7452ED5091C5BCC3ULL,
		0xA9ACC7085777D2E6ULL,
		0xC275498EA5493ED6ULL,
		0x2500D77FDDAF032CULL,
		0x2C622F3E05A74926ULL,
		0xB5EDDF407E0F2A97ULL,
		0xB52F86DEC78CA476ULL,
		0xEAD6AB41B47F9DF1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB7071C669E9FA4C0ULL,
		0x9106DF4958A60508ULL,
		0x989C3726995A8160ULL,
		0x9319B2790DD22D8AULL,
		0xF8C3EF5F1D5926CEULL,
		0x335ABAE0E353FB0EULL,
		0x3C72EC16C134947FULL,
		0x1C5B2A1A72C9AA92ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC355F1360F5A1803ULL,
		0x38AA18410FD1D7EEULL,
		0x5AE97EA83C13BFB6ULL,
		0xB6196506D07D2EA6ULL,
		0xD4A1C06118FE6FE8ULL,
		0x86B765A09D5CD199ULL,
		0x895D6AC806B83009ULL,
		0xF68D815BC6B63763ULL
	}};
	printf("Test Case 197\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xE5F70F90E4AA21CAULL,
		0xA6CA0643D7F39737ULL,
		0xA8645D1DCBE4D522ULL,
		0x090A07A63C8E947BULL,
		0xB7814A9D7E74D8B6ULL,
		0xA2D205331EF55C7AULL,
		0x95536052C385E16EULL,
		0x17E15CC57E5B140EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC2AB8AC38F2AD573ULL,
		0x7C355FEF4BE471BBULL,
		0xB538A0C20D4527CFULL,
		0x7A02F192F26C88D4ULL,
		0x9253001FFAB70FC6ULL,
		0x614977E0B8207536ULL,
		0x8DC5CCA8E21D19E7ULL,
		0xA98F10F9735AA287ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x275C85536B80F4B9ULL,
		0xDAFF59AC9C17E68CULL,
		0x1D5CFDDFC6A1F2EDULL,
		0x7308F634CEE21CAFULL,
		0x25D24A8284C3D770ULL,
		0xC39B72D3A6D5294CULL,
		0x1896ACFA2198F889ULL,
		0xBE6E4C3C0D01B689ULL
	}};
	printf("Test Case 198\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x9157B10B62EDE901ULL,
		0x06CB1E34FD5AE2C1ULL,
		0x8E27FDBD8818FB0DULL,
		0x7F2CE65A13F97A61ULL,
		0xE445625E09B3345AULL,
		0xB8D0D068BF8623BFULL,
		0x572C1FF1A85AADA5ULL,
		0x7434FD302BCAE32CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCF28B06C943E67C4ULL,
		0x2BC42BFE3AEDF37FULL,
		0xF209A3AD52FACECDULL,
		0x4D345B904323C65AULL,
		0x70E9623488B731E6ULL,
		0xD2D685633C49E874ULL,
		0xF5E7FA9613CCA911ULL,
		0xE3B481EAA74B8F5FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5E7F0167F6D38EC5ULL,
		0x2D0F35CAC7B711BEULL,
		0x7C2E5E10DAE235C0ULL,
		0x3218BDCA50DABC3BULL,
		0x94AC006A810405BCULL,
		0x6A06550B83CFCBCBULL,
		0xA2CBE567BB9604B4ULL,
		0x97807CDA8C816C73ULL
	}};
	printf("Test Case 199\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x694BF03B21C1667AULL,
		0xD34CFB1F20921F23ULL,
		0x7C2F61DFB8E5EAD2ULL,
		0x32681E65A019C9AAULL,
		0x3A122A614928EE5CULL,
		0x8C975CF5F16679A2ULL,
		0x6E2F3FA7786C658CULL,
		0xE8F35E03B2346DC4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7EC03436BFDF4B0FULL,
		0x8BB378373C79C6BFULL,
		0xB9FBA5CC657772ACULL,
		0xB95493A55C80563FULL,
		0x9CC2B1A8A6E319B1ULL,
		0x095665181131BC4DULL,
		0x6A21D2122868A8E0ULL,
		0x30C9ED35E25270FFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x178BC40D9E1E2D75ULL,
		0x58FF83281CEBD99CULL,
		0xC5D4C413DD92987EULL,
		0x8B3C8DC0FC999F95ULL,
		0xA6D09BC9EFCBF7EDULL,
		0x85C139EDE057C5EFULL,
		0x040EEDB55004CD6CULL,
		0xD83AB33650661D3BULL
	}};
	printf("Test Case 200\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x977399D205332291ULL,
		0xF877BDE8E5338963ULL,
		0x4D51BA0AC86ECA7EULL,
		0x34F8A0EC2684EFB6ULL,
		0xAE3EDE97481E769BULL,
		0x7E0A2CAC4ECBF56BULL,
		0xBDD484EF5F639FD9ULL,
		0x6DD6406F2D35C3A5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2A01499B5E6592A8ULL,
		0xA98C52C87F3E0CC0ULL,
		0x62CC417EBB6167DAULL,
		0xA36F3A8E4F90A7DCULL,
		0xBE9943537F561E2BULL,
		0x9FFEBC31FDA63799ULL,
		0x635F9711FFA71FC6ULL,
		0xCAC17859C4258A59ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBD72D0495B56B039ULL,
		0x51FBEF209A0D85A3ULL,
		0x2F9DFB74730FADA4ULL,
		0x97979A626914486AULL,
		0x10A79DC4374868B0ULL,
		0xE1F4909DB36DC2F2ULL,
		0xDE8B13FEA0C4801FULL,
		0xA7173836E91049FCULL
	}};
	printf("Test Case 201\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xF5E629E5982F6191ULL,
		0xD86A567462A36673ULL,
		0xF4259A6ACF0D5D1AULL,
		0x464A64200834AC08ULL,
		0xB5C218F697215E3AULL,
		0xA5E526CE02727F72ULL,
		0x4DCBBCCB5A32015CULL,
		0x8DBB3424E7F85CB9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x24F4C70D38351809ULL,
		0x868761F4FA1F53F8ULL,
		0x291988BCF9E09A04ULL,
		0x11536E0C30B37868ULL,
		0xF2439EF7F9EC7AF5ULL,
		0x9505EFDF94953A82ULL,
		0xCBA32617143A06FAULL,
		0x148F9CBEF115D632ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD112EEE8A01A7998ULL,
		0x5EED378098BC358BULL,
		0xDD3C12D636EDC71EULL,
		0x57190A2C3887D460ULL,
		0x478186016ECD24CFULL,
		0x30E0C91196E745F0ULL,
		0x86689ADC4E0807A6ULL,
		0x9934A89A16ED8A8BULL
	}};
	printf("Test Case 202\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xDA9751BB35CAAF19ULL,
		0x91D677855825EB34ULL,
		0xE693CD3B791A3D35ULL,
		0x23BB3B8A26E376F8ULL,
		0xBA9252A72DE46FF8ULL,
		0x1BCFACA243701C1EULL,
		0x57956A82C2484743ULL,
		0x741B187AF97FEFFAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA2A3BF218C1551C7ULL,
		0x3EE05B6C1A273FCAULL,
		0xC2832377FA675EA6ULL,
		0x86E29B2A38D25CF9ULL,
		0xB93BB5E36C1063FAULL,
		0xF0196F401318B2E5ULL,
		0x5ED568CE5B6BD499ULL,
		0x92D47D82C897FFA7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7834EE9AB9DFFEDEULL,
		0xAF362CE94202D4FEULL,
		0x2410EE4C837D6393ULL,
		0xA559A0A01E312A01ULL,
		0x03A9E74441F40C02ULL,
		0xEBD6C3E25068AEFBULL,
		0x0940024C992393DAULL,
		0xE6CF65F831E8105DULL
	}};
	printf("Test Case 203\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xC887AB4865695118ULL,
		0x39B6E71DD3FCEBB4ULL,
		0x1CB20043CF5F2AEDULL,
		0x6FDEF7E13A637684ULL,
		0xAE6189AB667DE78BULL,
		0xA79DDC756CA77A05ULL,
		0x101E33280BD404A4ULL,
		0x677D34DE7EBFA1C4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE06852B172C292AEULL,
		0xA4DC8DB1D9729646ULL,
		0x44340550E834F2D7ULL,
		0x477129DB17382B0AULL,
		0x97B651AD783A9FB7ULL,
		0x578E25807B61D03DULL,
		0xF5ADE890845062A2ULL,
		0x4DC694F6BA15F1A5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x28EFF9F917ABC3B6ULL,
		0x9D6A6AAC0A8E7DF2ULL,
		0x58860513276BD83AULL,
		0x28AFDE3A2D5B5D8EULL,
		0x39D7D8061E47783CULL,
		0xF013F9F517C6AA38ULL,
		0xE5B3DBB88F846606ULL,
		0x2ABBA028C4AA5061ULL
	}};
	printf("Test Case 204\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x763E2E7B42C25230ULL,
		0x69F85832669B7C1EULL,
		0x6671C62292C1C662ULL,
		0x2805F462CB7DF77EULL,
		0x7D8D038ECDB2978BULL,
		0x279B425649E3387EULL,
		0x70FF2FE85D8A8054ULL,
		0x6914166A039011B6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x202E4D1281ED21B7ULL,
		0x1D8730E614336471ULL,
		0xABFCC0982A4B3836ULL,
		0x30F72DEF8A6AB211ULL,
		0x55EF83DC2ACAA5C0ULL,
		0x88050CF848A5FF05ULL,
		0x1D6E0684A069B58AULL,
		0xCE2BC62DEF463729ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x56106369C32F7387ULL,
		0x747F68D472A8186FULL,
		0xCD8D06BAB88AFE54ULL,
		0x18F2D98D4117456FULL,
		0x28628052E778324BULL,
		0xAF9E4EAE0146C77BULL,
		0x6D91296CFDE335DEULL,
		0xA73FD047ECD6269FULL
	}};
	printf("Test Case 205\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xA9B724ECAE4A95F6ULL,
		0x06FFEBD52F35A9D2ULL,
		0x9458253E13327974ULL,
		0xF2ADC26144DF573EULL,
		0x19462B794E7C97CDULL,
		0x416C3DE548C46D69ULL,
		0x03B594F5C44B45D4ULL,
		0x375498158273EF71ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF5519FA64AAAA04AULL,
		0xE718AE6E14FF667FULL,
		0xA2DCF710A57CFCA5ULL,
		0xB8C819DD5146070DULL,
		0x5728723F39372500ULL,
		0xC0F44527E58EC61AULL,
		0x56ECEB7A332390CCULL,
		0x0EB192C8577A614BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5CE6BB4AE4E035BCULL,
		0xE1E745BB3BCACFADULL,
		0x3684D22EB64E85D1ULL,
		0x4A65DBBC15995033ULL,
		0x4E6E5946774BB2CDULL,
		0x819878C2AD4AAB73ULL,
		0x55597F8FF768D518ULL,
		0x39E50ADDD5098E3AULL
	}};
	printf("Test Case 206\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x1DF4FB1549976B19ULL,
		0xF80D4667C4B84116ULL,
		0xB1D0382FDD649CD0ULL,
		0x86C829AB66129456ULL,
		0x8F6A7F70A67E9805ULL,
		0x9219D9B5E0ED2002ULL,
		0x08F60D407D239B29ULL,
		0x939D72ACB2651A02ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC732E5F09884A480ULL,
		0x94343CA11A44E5FDULL,
		0x9D48FC1D4476E3EAULL,
		0x3F60F10D9B0ADB2FULL,
		0xA24D6A059322C378ULL,
		0xE6967445893AB7B5ULL,
		0x393EAAEBD2BD31ACULL,
		0xA0B7147BCF03E9EFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDAC61EE5D113CF99ULL,
		0x6C397AC6DEFCA4EBULL,
		0x2C98C43299127F3AULL,
		0xB9A8D8A6FD184F79ULL,
		0x2D271575355C5B7DULL,
		0x748FADF069D797B7ULL,
		0x31C8A7ABAF9EAA85ULL,
		0x332A66D77D66F3EDULL
	}};
	printf("Test Case 207\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x90CACB3DB094A0B8ULL,
		0x7663AADFB970FCB0ULL,
		0xDA6F6493CD87C781ULL,
		0xFECAF06EFBAD5256ULL,
		0xA52B3DB8613289DCULL,
		0x7E47B5C8BAA0FB52ULL,
		0x8D3411E5132FFA19ULL,
		0x5362BB825872A686ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x23F5DB959CE70A8FULL,
		0xB19CC9EF9DAF8CC0ULL,
		0x3B02B38B1D36FABDULL,
		0xEAA5363265D15E35ULL,
		0x32665EBB4F209493ULL,
		0x93EB4323534D98F9ULL,
		0xD3BB927FEFF630FBULL,
		0x6BFDE70C58456C0DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB33F10A82C73AA37ULL,
		0xC7FF633024DF7070ULL,
		0xE16DD718D0B13D3CULL,
		0x146FC65C9E7C0C63ULL,
		0x974D63032E121D4FULL,
		0xEDACF6EBE9ED63ABULL,
		0x5E8F839AFCD9CAE2ULL,
		0x389F5C8E0037CA8BULL
	}};
	printf("Test Case 208\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xBA85935AF476671CULL,
		0x155CBF2CC160F462ULL,
		0xAD84915C108BFC14ULL,
		0xFB9528A8FA3EF8BDULL,
		0x05E8F31736C77571ULL,
		0x774DC84CEA786283ULL,
		0x1384FF311F6ECAE2ULL,
		0x6F11EBC5C9C9F9F0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF6B055F713C23776ULL,
		0x9D4040A5171694C9ULL,
		0xA16DAA95D89263D8ULL,
		0x38398DB2BE81892DULL,
		0x3B9930BE5E48B270ULL,
		0xAE72CCBB950BD15FULL,
		0x658834422D02B367ULL,
		0xBA9B8184C5B4A036ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4C35C6ADE7B4506AULL,
		0x881CFF89D67660ABULL,
		0x0CE93BC9C8199FCCULL,
		0xC3ACA51A44BF7190ULL,
		0x3E71C3A9688FC701ULL,
		0xD93F04F77F73B3DCULL,
		0x760CCB73326C7985ULL,
		0xD58A6A410C7D59C6ULL
	}};
	printf("Test Case 209\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x348159DDEE5647A2ULL,
		0xA60A9D72F90BDF2CULL,
		0x4057BE58A3227C24ULL,
		0xD4630E9EB35AAD47ULL,
		0x220430C44FD9E04CULL,
		0x28CB1268DDCC5544ULL,
		0x2EAD56969F40A90FULL,
		0x472A600E584C0B9DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x47270A663A9C4786ULL,
		0x86459DCD0D29EAE1ULL,
		0x9EC070916D5BB44CULL,
		0xE05EC785C65020E5ULL,
		0xBD0186653B9A542DULL,
		0x51D302956CFBF6FAULL,
		0x7293A40904EBB01FULL,
		0x2D7C4F6FC77FA35FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x73A653BBD4CA0024ULL,
		0x204F00BFF42235CDULL,
		0xDE97CEC9CE79C868ULL,
		0x343DC91B750A8DA2ULL,
		0x9F05B6A17443B461ULL,
		0x791810FDB137A3BEULL,
		0x5C3EF29F9BAB1910ULL,
		0x6A562F619F33A8C2ULL
	}};
	printf("Test Case 210\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x757DCAB671ECF7B3ULL,
		0x13B3A7EE039673D0ULL,
		0xB2FF395BAF203AC9ULL,
		0x724E69D63905C441ULL,
		0x02E204554173D99AULL,
		0x33DA4E767C11B1A6ULL,
		0x86792B32170A69BCULL,
		0xEC3D1C424FD91BC9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x90913F9A8F9D6469ULL,
		0x5392B4A4B0E7D5E1ULL,
		0xCFD34DF0965ACA6BULL,
		0xF9E8DC26E4159B78ULL,
		0x382461AB5680B8BFULL,
		0x5EDA9BC9259D18ABULL,
		0x7714B6A36F3F1883ULL,
		0x272C2410959A5F36ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE5ECF52CFE7193DAULL,
		0x4021134AB371A631ULL,
		0x7D2C74AB397AF0A2ULL,
		0x8BA6B5F0DD105F39ULL,
		0x3AC665FE17F36125ULL,
		0x6D00D5BF598CA90DULL,
		0xF16D9D917835713FULL,
		0xCB113852DA4344FFULL
	}};
	printf("Test Case 211\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xB6E762255969E2CBULL,
		0xB657F55D32B6E6FAULL,
		0xF0EFAF738B7C8EF3ULL,
		0x0B40314D0A50C35EULL,
		0xF48D89F556868057ULL,
		0x411B11F9458E2FD5ULL,
		0xEFD4DD9A6E7E2B83ULL,
		0xFFEE35336EB30661ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2C667CFD30145428ULL,
		0x094C224D96126772ULL,
		0xA6CD50DAD92D42EEULL,
		0x3A74D96F6654D9CDULL,
		0x89DD7B8D540518ECULL,
		0x3006B1EC7A0354B7ULL,
		0xD543BD69F9E270A5ULL,
		0xD498BB69516FE7BEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9A811ED8697DB6E3ULL,
		0xBF1BD710A4A48188ULL,
		0x5622FFA95251CC1DULL,
		0x3134E8226C041A93ULL,
		0x7D50F278028398BBULL,
		0x711DA0153F8D7B62ULL,
		0x3A9760F3979C5B26ULL,
		0x2B768E5A3FDCE1DFULL
	}};
	printf("Test Case 212\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x1128659DCE9E2899ULL,
		0x5970D2DEE14102D3ULL,
		0x9F0DC6C2A3E82171ULL,
		0x83199D8AE5D22904ULL,
		0x10D10DCC56241BDBULL,
		0xAB2462A114038BFCULL,
		0x8F4F53CCA3206CE6ULL,
		0x331E8922E8E4B66AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEBB9ADF2EBCD58D9ULL,
		0x4F63A27572822A2FULL,
		0xDFDF6DC1CD5D7F1CULL,
		0xF9BC8DC0DA1B6CE8ULL,
		0xA94A5570AE5F922FULL,
		0x0428A9B07709F7A0ULL,
		0x60DC2C72EFF5B743ULL,
		0xF4CF865B0AAB842EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFA91C86F25537040ULL,
		0x161370AB93C328FCULL,
		0x40D2AB036EB55E6DULL,
		0x7AA5104A3FC945ECULL,
		0xB99B58BCF87B89F4ULL,
		0xAF0CCB11630A7C5CULL,
		0xEF937FBE4CD5DBA5ULL,
		0xC7D10F79E24F3244ULL
	}};
	printf("Test Case 213\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xA091DB0C7ECB5F3FULL,
		0x3BCE0FFC0392312BULL,
		0x06C3973BFD1A0D2EULL,
		0x1D035F264C28B2B1ULL,
		0x8E41ED0FD6521258ULL,
		0x4EB2D68D90D810EFULL,
		0x183AB2F6FF08CA52ULL,
		0xBA62BAFFC7F2BCD5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6D79F8944197BA24ULL,
		0xB0BFD1A0263B4087ULL,
		0x85A49B89BE450E0BULL,
		0x0C003A526D5468E7ULL,
		0x057311103838DEAFULL,
		0xE15ED06F9F74DD53ULL,
		0xDB3394AA7A30D9C3ULL,
		0x3E55BA45766BDCA7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCDE823983F5CE51BULL,
		0x8B71DE5C25A971ACULL,
		0x83670CB2435F0325ULL,
		0x11036574217CDA56ULL,
		0x8B32FC1FEE6ACCF7ULL,
		0xAFEC06E20FACCDBCULL,
		0xC309265C85381391ULL,
		0x843700BAB1996072ULL
	}};
	printf("Test Case 214\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x3AB4401907D065FFULL,
		0x6E29293EB0872A73ULL,
		0xF9187665D7E2D686ULL,
		0xA7F3E7224955067DULL,
		0xAC1CC0260564412EULL,
		0xE631696E93ADCF33ULL,
		0x5C70A40D0F685207ULL,
		0x55E6CCD4211720A2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDCCE24737FBC693EULL,
		0x8249061B15774C92ULL,
		0xC870177A9E63F32BULL,
		0x54F9223D6FE8A5AFULL,
		0xB71636E312E46201ULL,
		0x912364EE80FD9647ULL,
		0x439E87B2C4FE202FULL,
		0xEC96D0C771148ADBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE67A646A786C0CC1ULL,
		0xEC602F25A5F066E1ULL,
		0x3168611F498125ADULL,
		0xF30AC51F26BDA3D2ULL,
		0x1B0AF6C51780232FULL,
		0x77120D8013505974ULL,
		0x1FEE23BFCB967228ULL,
		0xB9701C135003AA79ULL
	}};
	printf("Test Case 215\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xEC0F485190277E31ULL,
		0xFC3DE99BEC98B146ULL,
		0xE7EF8269291C5B89ULL,
		0xB16707F1E982807BULL,
		0x545FB82022AD4A1DULL,
		0x8168F271A437909FULL,
		0xD7893C74E89537BCULL,
		0xEF4DC37A5A74082AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0696457A918B63D9ULL,
		0x655FC013CFADCD9BULL,
		0x0287EF07855B440DULL,
		0xC78AF1F9D9A71343ULL,
		0xEE034287D70279D4ULL,
		0xCA8398C82AAB5CCBULL,
		0xC9ED2791E31E435CULL,
		0x712BC9573084DEFCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEA990D2B01AC1DE8ULL,
		0x9962298823357CDDULL,
		0xE5686D6EAC471F84ULL,
		0x76EDF60830259338ULL,
		0xBA5CFAA7F5AF33C9ULL,
		0x4BEB6AB98E9CCC54ULL,
		0x1E641BE50B8B74E0ULL,
		0x9E660A2D6AF0D6D6ULL
	}};
	printf("Test Case 216\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xF6E81878C3E2CCCBULL,
		0xA6899EC7F7357A22ULL,
		0xC1822EB8A748C0A6ULL,
		0x80BA800E7ECB6DDDULL,
		0xFD3F2BB311D73B4FULL,
		0xE22F95A86BBCA2BBULL,
		0x4417756B6B52C6DDULL,
		0x76AFA704D865F9C5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC8E23B5A266803D8ULL,
		0x93A59FACB3E11684ULL,
		0x025725DBC69B85C2ULL,
		0x3401A94FC4EE23DCULL,
		0xF359D184CE9A7F30ULL,
		0x3C01FCCC98DC8EA6ULL,
		0x8DF7FA3CADE6B416ULL,
		0xCAEAF48382B322DAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3E0A2322E58ACF13ULL,
		0x352C016B44D46CA6ULL,
		0xC3D50B6361D34564ULL,
		0xB4BB2941BA254E01ULL,
		0x0E66FA37DF4D447FULL,
		0xDE2E6964F3602C1DULL,
		0xC9E08F57C6B472CBULL,
		0xBC4553875AD6DB1FULL
	}};
	printf("Test Case 217\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xBD4209B8157C5886ULL,
		0x7D33434BA699202EULL,
		0xEED123661DF2F753ULL,
		0x0C3C27326BDB5FB4ULL,
		0x2DD57423CCA96102ULL,
		0xD17D352903137B91ULL,
		0x2C9D1BA4F71E9A86ULL,
		0x9A30DEAFBCE3D475ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x86AB029EC8A072E2ULL,
		0xBFFB6435703C0048ULL,
		0x276C4A8C7FA23305ULL,
		0x1C4E7E753C8542A0ULL,
		0x0E86673AAC2D5C21ULL,
		0xDAFE41F0E1B7B01FULL,
		0x7A28DB602E6BB8ECULL,
		0xAFD0191D467A15F6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3BE90B26DDDC2A64ULL,
		0xC2C8277ED6A52066ULL,
		0xC9BD69EA6250C456ULL,
		0x10725947575E1D14ULL,
		0x2353131960843D23ULL,
		0x0B8374D9E2A4CB8EULL,
		0x56B5C0C4D975226AULL,
		0x35E0C7B2FA99C183ULL
	}};
	printf("Test Case 218\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x86700167DE4E61EFULL,
		0x836550F80A975E39ULL,
		0x2D74FB8A6990F3AFULL,
		0x75C76878E56D05F4ULL,
		0xCE9A8D1684C80CFDULL,
		0xC5AD5FA5C3F62E0BULL,
		0xE33501348A30F924ULL,
		0xF6C4BA285EB22B50ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x26B4AB6AA544D703ULL,
		0x0CA174F9D7D4FC92ULL,
		0x91882A0BD0DEC9B9ULL,
		0x1851DC73A782C808ULL,
		0x988C4D0FAD6D5900ULL,
		0xD24C417518991A3CULL,
		0x658ED6F9F64BFF7EULL,
		0x30A1CC898DBA015CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA0C4AA0D7B0AB6ECULL,
		0x8FC42401DD43A2ABULL,
		0xBCFCD181B94E3A16ULL,
		0x6D96B40B42EFCDFCULL,
		0x5616C01929A555FDULL,
		0x17E11ED0DB6F3437ULL,
		0x86BBD7CD7C7B065AULL,
		0xC66576A1D3082A0CULL
	}};
	printf("Test Case 219\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x3E4950E73DCF2640ULL,
		0x4C93E1A22720EB63ULL,
		0xC2D39A31109C19E0ULL,
		0xEF098A0D595B2565ULL,
		0xE278D4AED0F8BA73ULL,
		0x414473FE273BF664ULL,
		0x9177631DA787E0D4ULL,
		0xD61CB5075929CF61ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2913A2899E1D881FULL,
		0x77C6EFE0DC37FB1BULL,
		0x4032A5017F7E09ECULL,
		0x9F68A9960AD64438ULL,
		0xD67D5D94727C7825ULL,
		0x6ECB93032970E9E4ULL,
		0x6A992CB0226993BCULL,
		0xF5F31F1A971DE470ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x175AF26EA3D2AE5FULL,
		0x3B550E42FB171078ULL,
		0x82E13F306FE2100CULL,
		0x7061239B538D615DULL,
		0x3405893AA284C256ULL,
		0x2F8FE0FD0E4B1F80ULL,
		0xFBEE4FAD85EE7368ULL,
		0x23EFAA1DCE342B11ULL
	}};
	printf("Test Case 220\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x6B7221563C072B40ULL,
		0x8621850411E45ECDULL,
		0x6B767D0EE8C4B4BFULL,
		0x6A4C5584B5E4901CULL,
		0xAE4DB2506027F0F1ULL,
		0x99CF6D2105B8B026ULL,
		0x6C7373246BAAB75FULL,
		0x2964EDCDF5E0456DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCCC2C0FDA27CB329ULL,
		0x9DB0FB482D1963DFULL,
		0x6E1224CF4A8C8F51ULL,
		0x16B3E54F2B7EA109ULL,
		0xA219C80A35BCCCCCULL,
		0x170A7FC23A95FDECULL,
		0x0AC9BB5F4D189896ULL,
		0x652B5407CE43008DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA7B0E1AB9E7B9869ULL,
		0x1B917E4C3CFD3D12ULL,
		0x056459C1A2483BEEULL,
		0x7CFFB0CB9E9A3115ULL,
		0x0C547A5A559B3C3DULL,
		0x8EC512E33F2D4DCAULL,
		0x66BAC87B26B22FC9ULL,
		0x4C4FB9CA3BA345E0ULL
	}};
	printf("Test Case 221\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x78A3146A0D7FCA21ULL,
		0xD492CB581804F3F2ULL,
		0x3A47A3E1CFFB55FEULL,
		0xFD7DDFE6E016AB9DULL,
		0x8DE3240A56C0B560ULL,
		0x8F5BCA126A3E149EULL,
		0x3F482CF196285914ULL,
		0xC07508352166047CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3622B6B14BE657E7ULL,
		0x1F72C93DE2A9B4FFULL,
		0xE1949E0AE252D45BULL,
		0xAF3E1835351DEB7CULL,
		0xBDBD72920AFB3919ULL,
		0xFF6BE383B33F2FEDULL,
		0x314CCEF06897C770ULL,
		0x3F0B427A04AB9E32ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4E81A2DB46999DC6ULL,
		0xCBE00265FAAD470DULL,
		0xDBD33DEB2DA981A5ULL,
		0x5243C7D3D50B40E1ULL,
		0x305E56985C3B8C79ULL,
		0x70302991D9013B73ULL,
		0x0E04E201FEBF9E64ULL,
		0xFF7E4A4F25CD9A4EULL
	}};
	printf("Test Case 222\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x1EDD7D48E5472580ULL,
		0x25D1CE936FCBEF7AULL,
		0x55D7727A31A3A311ULL,
		0xD97B666F48056815ULL,
		0x10E118BB376EE796ULL,
		0x45F88229713ACFC5ULL,
		0xE4B606FEE2EC83B8ULL,
		0x91739D6414DA430FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE47FED841A70BBFEULL,
		0xC3E2B75EFDB73A35ULL,
		0x5A0351FE5D81FC81ULL,
		0x3C5A90471A4FAC5CULL,
		0xD16DE8E789CB300DULL,
		0x8DF45801019F8B7CULL,
		0x920E9517B24AF28BULL,
		0xCC900A3039B8878FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFAA290CCFF379E7EULL,
		0xE63379CD927CD54FULL,
		0x0FD423846C225F90ULL,
		0xE521F628524AC449ULL,
		0xC18CF05CBEA5D79BULL,
		0xC80CDA2870A544B9ULL,
		0x76B893E950A67133ULL,
		0x5DE397542D62C480ULL
	}};
	printf("Test Case 223\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x7D4E4C4AA1AB0015ULL,
		0xF8B692F32C14ADDBULL,
		0x2F926A696270D779ULL,
		0x6CD1FEDC60FDC7D0ULL,
		0xD860BA4519C13288ULL,
		0xA3925B8552324114ULL,
		0xBC13E5896BBDB82EULL,
		0x5A93CBEDDF924D8DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBE1BEBCF302AD9D7ULL,
		0xBD44E0FA33DD5337ULL,
		0x5DD852D3B30A72B6ULL,
		0x768BE27517C57945ULL,
		0xF9D4B811992D417AULL,
		0x44BA5BA304626C8FULL,
		0x3558F9EE565CE1A7ULL,
		0x47217F414BD0CEEFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC355A7859181D9C2ULL,
		0x45F272091FC9FEECULL,
		0x724A38BAD17AA5CFULL,
		0x1A5A1CA97738BE95ULL,
		0x21B4025480EC73F2ULL,
		0xE728002656502D9BULL,
		0x894B1C673DE15989ULL,
		0x1DB2B4AC94428362ULL
	}};
	printf("Test Case 224\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x43B00A2D57FB5F3AULL,
		0x8AE8CF317FC003CAULL,
		0x5CFB837A5240ABC2ULL,
		0xBF79D4C886B499C3ULL,
		0x8A2D0D16F9783156ULL,
		0x85140CEC278F73ABULL,
		0x07919584F118C376ULL,
		0xF790DC97DCB9854BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5B9BCC2D927B6654ULL,
		0x2B9F18F1D8BD23B9ULL,
		0x50D38B376318E6AFULL,
		0xFB6791D487E7A5D7ULL,
		0xBDF10951144518D2ULL,
		0x5EE1EB71A918FD36ULL,
		0x9A1510414F78B949ULL,
		0xA7392E81AA44673EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x182BC600C580396EULL,
		0xA177D7C0A77D2073ULL,
		0x0C28084D31584D6DULL,
		0x441E451C01533C14ULL,
		0x37DC0447ED3D2984ULL,
		0xDBF5E79D8E978E9DULL,
		0x9D8485C5BE607A3FULL,
		0x50A9F21676FDE275ULL
	}};
	printf("Test Case 225\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x550225C104DC2924ULL,
		0x34BC4D2E15DBC102ULL,
		0xA02EFD7025450FB9ULL,
		0x5490180942F7F7E2ULL,
		0xA60C16D0E0DDA65AULL,
		0x64652E9D077EDF92ULL,
		0x4C61E7ADF1FEEDEFULL,
		0x27F3E6A3EADCC5CBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x21F2009C6CFD44F2ULL,
		0xE2FCD369A24EDF71ULL,
		0x5B03EDCEE300A4EAULL,
		0xAD35EA8E21448A85ULL,
		0x787D8AE2FA40E365ULL,
		0x27D354966C335332ULL,
		0xF7506B0A9FF7E366ULL,
		0xED09B0BE395D351DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x74F0255D68216DD6ULL,
		0xD6409E47B7951E73ULL,
		0xFB2D10BEC645AB53ULL,
		0xF9A5F28763B37D67ULL,
		0xDE719C321A9D453FULL,
		0x43B67A0B6B4D8CA0ULL,
		0xBB318CA76E090E89ULL,
		0xCAFA561DD381F0D6ULL
	}};
	printf("Test Case 226\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x5836C9C051A2BCECULL,
		0xF2B6A46C8F888695ULL,
		0xF2A92CFE22119EDFULL,
		0x0F1ED491C634A921ULL,
		0x640A3C0C82900EEAULL,
		0x6461A05D36E8E285ULL,
		0x90511F6999E16453ULL,
		0x525D4BE56F47269CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD890BF79CD6EB715ULL,
		0x03C1B8519FD40D16ULL,
		0xD0499653BA23FA08ULL,
		0x01E4EFCB8EB3161AULL,
		0xC25DB52EF0C4EA8CULL,
		0xFD2D90184D62A931ULL,
		0xCC95AC5036408186ULL,
		0x7A7AABAAB594A6F9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x80A676B99CCC0BF9ULL,
		0xF1771C3D105C8B83ULL,
		0x22E0BAAD983264D7ULL,
		0x0EFA3B5A4887BF3BULL,
		0xA65789227254E466ULL,
		0x994C30457B8A4BB4ULL,
		0x5CC4B339AFA1E5D5ULL,
		0x2827E04FDAD38065ULL
	}};
	printf("Test Case 227\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xDA97BF4E6DCC4998ULL,
		0x141223BDFDAADA81ULL,
		0xCF04BA95D40920EDULL,
		0x1AB76A075A8AE5EAULL,
		0xC92041B88902B14BULL,
		0xA71F853C689A67D4ULL,
		0xA08521671F1C490CULL,
		0x298C7FDF9C67CE72ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAEB3E86DBCE01074ULL,
		0x0D59BC32C8236128ULL,
		0x83FA27FE113787DEULL,
		0xB9DAEAADD4FC8634ULL,
		0xA6DA5E67EFC744CCULL,
		0x273217FA25DF93D2ULL,
		0x93A487A80BD5EB91ULL,
		0xEE00C813043D7606ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x74245723D12C59ECULL,
		0x194B9F8F3589BBA9ULL,
		0x4CFE9D6BC53EA733ULL,
		0xA36D80AA8E7663DEULL,
		0x6FFA1FDF66C5F587ULL,
		0x802D92C64D45F406ULL,
		0x3321A6CF14C9A29DULL,
		0xC78CB7CC985AB874ULL
	}};
	printf("Test Case 228\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x27693341A7D790F5ULL,
		0x740C56CAE529CFF4ULL,
		0x9A450164E244C234ULL,
		0x808F6C52C504B6AAULL,
		0x8FA9BA759F1AD4D3ULL,
		0x49B2C76F80A5DAC3ULL,
		0xDA0FD1B6ACBAA785ULL,
		0x5553AF58816B83C6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6C12BE162E359F90ULL,
		0xA941A971FD73B445ULL,
		0x211F55D33925865FULL,
		0x78F267AEE02FDFE0ULL,
		0xD0BECECFB28DA7AEULL,
		0x8F1C4ACF619DB330ULL,
		0x44F5A8115FEC89D8ULL,
		0x85D3B0F1C2C07042ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4B7B8D5789E20F65ULL,
		0xDD4DFFBB185A7BB1ULL,
		0xBB5A54B7DB61446BULL,
		0xF87D0BFC252B694AULL,
		0x5F1774BA2D97737DULL,
		0xC6AE8DA0E13869F3ULL,
		0x9EFA79A7F3562E5DULL,
		0xD0801FA943ABF384ULL
	}};
	printf("Test Case 229\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xD4FAC37A1DA3D495ULL,
		0xEF0CB41FE90EBCD5ULL,
		0xF6FFBDCF35BD3440ULL,
		0x9A0B611791A72D8EULL,
		0x776C3564E064E2C4ULL,
		0x4FAA487507AD17A3ULL,
		0x53152E0E4BB40E31ULL,
		0x538F7F4D6AC572B7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1003C3AADA876F8FULL,
		0x516714B2F0421429ULL,
		0x4B9827F792B103C5ULL,
		0xFA6C95509F44EB95ULL,
		0xFB1D6BD9AA44A390ULL,
		0x2A06E608331F92D6ULL,
		0x8ABBD5232CFDAE9CULL,
		0xAD7AE249636C5408ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC4F900D0C724BB1AULL,
		0xBE6BA0AD194CA8FCULL,
		0xBD679A38A70C3785ULL,
		0x6067F4470EE3C61BULL,
		0x8C715EBD4A204154ULL,
		0x65ACAE7D34B28575ULL,
		0xD9AEFB2D6749A0ADULL,
		0xFEF59D0409A926BFULL
	}};
	printf("Test Case 230\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x2ADADEF228395BC5ULL,
		0x9C1925C7A1F9514AULL,
		0x24B496C4113CE954ULL,
		0xE747C57BBBE83343ULL,
		0x3495FE65DDEA09A6ULL,
		0xC0D7D46BE7D472ABULL,
		0x71FEB5867B164BE2ULL,
		0x278A80627BF5FAF8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x14263F8B2E58D69CULL,
		0xE8BFB0E4A4ADFD4FULL,
		0x8FB56C48C453B9B0ULL,
		0x1D03BB066B565CB9ULL,
		0xEDF57512CE5C4C90ULL,
		0xCA089DF421E33AB0ULL,
		0xB3074BB94857DE86ULL,
		0xDF5DC6B1CA609838ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3EFCE17906618D59ULL,
		0x74A695230554AC05ULL,
		0xAB01FA8CD56F50E4ULL,
		0xFA447E7DD0BE6FFAULL,
		0xD9608B7713B64536ULL,
		0x0ADF499FC637481BULL,
		0xC2F9FE3F33419564ULL,
		0xF8D746D3B19562C0ULL
	}};
	printf("Test Case 231\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x76A30801D6C283FAULL,
		0x3454F4C3255DA718ULL,
		0x3849B34D494B192EULL,
		0xBDFE9AD2AC9ED1D5ULL,
		0x2A7A3A2BDFECA68BULL,
		0x5B362BEBEC6612F0ULL,
		0x823E2F3CCEA52121ULL,
		0xC90F5825E52B6204ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA7730638AF78DA95ULL,
		0x65E51FB64F60B06AULL,
		0xCA47E67655AA8A28ULL,
		0xB8D316BD70A754D0ULL,
		0x15797B0E8A1A9030ULL,
		0x968C13F78F7065ACULL,
		0xB98B5EB2309BB7C4ULL,
		0x0C59C55D3AEFE9C0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD1D00E3979BA596FULL,
		0x51B1EB756A3D1772ULL,
		0xF20E553B1CE19306ULL,
		0x052D8C6FDC398505ULL,
		0x3F03412555F636BBULL,
		0xCDBA381C6316775CULL,
		0x3BB5718EFE3E96E5ULL,
		0xC5569D78DFC48BC4ULL
	}};
	printf("Test Case 232\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xC8EC651348E4AA73ULL,
		0x13AF6F54D79E7677ULL,
		0x1C9AA2ACFA32AE96ULL,
		0xA56B4A27F2236C9EULL,
		0x5696CA02DF5995BCULL,
		0xECE79BC20CD276C4ULL,
		0xEA25D3CF837334EDULL,
		0xE7B59C32A9A8985AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x18FCB06461115D65ULL,
		0x91F07A85C8C5BC29ULL,
		0xFF1ED4381BCC10DFULL,
		0xE990C4A84F3998E2ULL,
		0x509B4D978E743A1CULL,
		0x55570321825B3ECCULL,
		0x47EFA2589B630110ULL,
		0x3B8E2F1866133715ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD010D57729F5F716ULL,
		0x825F15D11F5BCA5EULL,
		0xE3847694E1FEBE49ULL,
		0x4CFB8E8FBD1AF47CULL,
		0x060D8795512DAFA0ULL,
		0xB9B098E38E894808ULL,
		0xADCA7197181035FDULL,
		0xDC3BB32ACFBBAF4FULL
	}};
	printf("Test Case 233\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x1CCAF8BCB6ACFA10ULL,
		0xA4FC75F6E21AD934ULL,
		0xC246C0BF4AF6A800ULL,
		0x381DF84C2B6F0F7AULL,
		0x2C521A365506497AULL,
		0xBC76C67DB407824BULL,
		0xEE70597D8F7ACE63ULL,
		0xD341643E5A570138ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3CC0A5D44D24226EULL,
		0xFDF54245C3EB0E9BULL,
		0x91E959C4B556A8D9ULL,
		0x35D4C40EB468921DULL,
		0x666BADC0FA6D810AULL,
		0x32D272EE000BAA08ULL,
		0xB19DCEF4D0518C65ULL,
		0x4EAAB094E645B354ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x200A5D68FB88D87EULL,
		0x590937B321F1D7AFULL,
		0x53AF997BFFA000D9ULL,
		0x0DC93C429F079D67ULL,
		0x4A39B7F6AF6BC870ULL,
		0x8EA4B493B40C2843ULL,
		0x5FED97895F2B4206ULL,
		0x9DEBD4AABC12B26CULL
	}};
	printf("Test Case 234\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x82D45E0EA1ED3BE7ULL,
		0x0ABE6394CAE9C1C3ULL,
		0xA3FE723772790B0FULL,
		0xC55F3BE4823EFD77ULL,
		0x304FED2ECEDB2BB8ULL,
		0xA2662253EA500AA4ULL,
		0xBADAE8C23DCD9720ULL,
		0x7A06241F779EBC6DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x599E7775655EFD38ULL,
		0xFE988CC4AA00443FULL,
		0x301426E80D05AC80ULL,
		0xF993E46500CF97CAULL,
		0x7E3914CCE9BD537DULL,
		0x92344C75FE0EBA8DULL,
		0x8E82BB9EFC69A980ULL,
		0x24E40F40CB86D8C3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDB4A297BC4B3C6DFULL,
		0xF426EF5060E985FCULL,
		0x93EA54DF7F7CA78FULL,
		0x3CCCDF8182F16ABDULL,
		0x4E76F9E2276678C5ULL,
		0x30526E26145EB029ULL,
		0x3458535CC1A43EA0ULL,
		0x5EE22B5FBC1864AEULL
	}};
	printf("Test Case 235\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x89426328DE12A36AULL,
		0xC4B64E40B41C6336ULL,
		0xA732056748E1B6F0ULL,
		0x60CD14D5BCB2F561ULL,
		0xF44EFCC1568FEF15ULL,
		0x7BFC41AE59FB4272ULL,
		0x54FA93FA41277BA3ULL,
		0xF83A35357C159081ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x14805C8B8303A594ULL,
		0x1EA6BA0E1AB1CB1BULL,
		0x05DF0A99106D9A65ULL,
		0x4E00488B25B4D25CULL,
		0x6D4160D839AA31C9ULL,
		0xBF193FC6A117EF86ULL,
		0x8C37CFFD2064594EULL,
		0xD392BF6695174D93ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9DC23FA35D1106FEULL,
		0xDA10F44EAEADA82DULL,
		0xA2ED0FFE588C2C95ULL,
		0x2ECD5C5E9906273DULL,
		0x990F9C196F25DEDCULL,
		0xC4E57E68F8ECADF4ULL,
		0xD8CD5C07614322EDULL,
		0x2BA88A53E902DD12ULL
	}};
	printf("Test Case 236\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x8937E2819B4EC3CEULL,
		0x3C4F1FDCAE3A16E9ULL,
		0x7E075CED5F87F7CBULL,
		0x171F3F234AE2ABCAULL,
		0xD5C76C9EEE2D19D2ULL,
		0xF5F3049FD9952C5FULL,
		0xCE39B97D21AA697CULL,
		0xBA3C48FFAD7B3F9DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8BBBAE2C0E04123EULL,
		0xDD9F3F9EBED5CBD8ULL,
		0xD5E03A295482BF2AULL,
		0xA3F5AE80E7F3D300ULL,
		0x6B4A1E7C7925C173ULL,
		0xCCE44C919708867BULL,
		0xF152FBEAB83BF391ULL,
		0xBF5A4FD9FA7486C5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x028C4CAD954AD1F0ULL,
		0xE1D0204210EFDD31ULL,
		0xABE766C40B0548E1ULL,
		0xB4EA91A3AD1178CAULL,
		0xBE8D72E29708D8A1ULL,
		0x3917480E4E9DAA24ULL,
		0x3F6B429799919AEDULL,
		0x05660726570FB958ULL
	}};
	printf("Test Case 237\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x132177F8276322CFULL,
		0xBFD4A44188751E2FULL,
		0xE11E72BA50299425ULL,
		0xFD7A2150F0ED5BC9ULL,
		0xFD4A2F1BE90B9326ULL,
		0xC0A55F87EAF18C71ULL,
		0xA3F6ACDEDA560AE9ULL,
		0xE23B8EDEEC800B03ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7F19708D0D357340ULL,
		0x845D0D71AB30331CULL,
		0xD97075AF295E8837ULL,
		0xA054E796BCDC7F38ULL,
		0xFACD9F6D316E30A6ULL,
		0x2B4E70003CBE358EULL,
		0x5C0D06B5D1DE6FEDULL,
		0xDE83909A2DF976CDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6C3807752A56518FULL,
		0x3B89A93023452D33ULL,
		0x386E071579771C12ULL,
		0x5D2EC6C64C3124F1ULL,
		0x0787B076D865A380ULL,
		0xEBEB2F87D64FB9FFULL,
		0xFFFBAA6B0B886504ULL,
		0x3CB81E44C1797DCEULL
	}};
	printf("Test Case 238\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x35766FC7F51C1A9CULL,
		0xBDF9533A7D390180ULL,
		0xAF835812B2750640ULL,
		0x59B990FF4B88EA8EULL,
		0xDC039236738B0862ULL,
		0x3D40465667B9EF30ULL,
		0x207F3C6F797B2DA6ULL,
		0x900B1B9A017ED569ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3DEB2DA1CE8A3BA2ULL,
		0x65CA62535B18712AULL,
		0xDB19602D0F91F802ULL,
		0x9D7A1B3323288722ULL,
		0xC9F8EDD2B44583EEULL,
		0x2D7E3033DC97A2F2ULL,
		0x918EE646CAC56A08ULL,
		0x068B098CD40DB65EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x089D42663B96213EULL,
		0xD8333169262170AAULL,
		0x749A383FBDE4FE42ULL,
		0xC4C38BCC68A06DACULL,
		0x15FB7FE4C7CE8B8CULL,
		0x103E7665BB2E4DC2ULL,
		0xB1F1DA29B3BE47AEULL,
		0x96801216D5736337ULL
	}};
	printf("Test Case 239\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x3894DF9C4716717AULL,
		0xA28FB7303A1E9584ULL,
		0x38DBBAE9F9D387D3ULL,
		0xDD60B99FC2300D15ULL,
		0xDB977B2F0279E498ULL,
		0xBD060938D5889E07ULL,
		0x2401D1EBE9977B49ULL,
		0x227F6B877E40E291ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x89EA45590FF942B4ULL,
		0xEAB7CC02832BA31AULL,
		0x589B6A85202C0C30ULL,
		0xEE51E5C4BE0EE678ULL,
		0x68C599B9007A77C0ULL,
		0x3AB9D9FC4DA11C8DULL,
		0xCB3BE097EE34DA20ULL,
		0x109DD6FD3AE80E04ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB17E9AC548EF33CEULL,
		0x48387B32B935369EULL,
		0x6040D06CD9FF8BE3ULL,
		0x33315C5B7C3EEB6DULL,
		0xB352E29602039358ULL,
		0x87BFD0C49829828AULL,
		0xEF3A317C07A3A169ULL,
		0x32E2BD7A44A8EC95ULL
	}};
	printf("Test Case 240\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xC6367A59E888746EULL,
		0xEBB4DF2FDAFAA51EULL,
		0xA9ED3EEB8919B2ADULL,
		0x71708EF0E97D8E27ULL,
		0x7E9246A826D4FD94ULL,
		0x0E946E76D09D2A25ULL,
		0x6EB348284F3D875BULL,
		0xE6326D0E3068329CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB5011CD4E17C1A56ULL,
		0x5ADE41D99120C3D1ULL,
		0xB9EBE89E9145040DULL,
		0x5822F7EC23C05C9DULL,
		0x45E98D351143739EULL,
		0x3F1EAB993B6D970BULL,
		0x7CB44F3CC597FC6EULL,
		0x2DE8014D0BEAE8B4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7337668D09F46E38ULL,
		0xB16A9EF64BDA66CFULL,
		0x1006D675185CB6A0ULL,
		0x2952791CCABDD2BAULL,
		0x3B7BCB9D37978E0AULL,
		0x318AC5EFEBF0BD2EULL,
		0x120707148AAA7B35ULL,
		0xCBDA6C433B82DA28ULL
	}};
	printf("Test Case 241\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x1A2E7F24C03AE341ULL,
		0xC01F443C9E81FBAEULL,
		0xF494C4C80EF8C2BBULL,
		0x98EFE5B99342F5DFULL,
		0xFA692A732E80779FULL,
		0x063F826B8AD32722ULL,
		0x703C72FA87267C2CULL,
		0x03C0028B1B45C6C7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD9F34DB2E4C35FFBULL,
		0x193149DFAC207EECULL,
		0xE88A39DE9FB494B8ULL,
		0x6B8E240D52A92390ULL,
		0xD982889CFF0E9BAFULL,
		0xDA2EB791211AEE2CULL,
		0xB7EFA7A98613B4A6ULL,
		0xC43BA1A56423E16CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC3DD329624F9BCBAULL,
		0xD92E0DE332A18542ULL,
		0x1C1EFD16914C5603ULL,
		0xF361C1B4C1EBD64FULL,
		0x23EBA2EFD18EEC30ULL,
		0xDC1135FAABC9C90EULL,
		0xC7D3D5530135C88AULL,
		0xC7FBA32E7F6627ABULL
	}};
	printf("Test Case 242\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xDBD10A7A14F6A6C7ULL,
		0x295FE64027CC25D9ULL,
		0x7AF0942A9D9E9820ULL,
		0x11D114431FBA9622ULL,
		0x5D8B6C62241433B9ULL,
		0x37936957C1285C12ULL,
		0xC6B2AC59F8431741ULL,
		0x1325C6DC4E24C01BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC2DD0C9588D9E93EULL,
		0x4920A9AE53B67C39ULL,
		0x159C7EE7AEF80393ULL,
		0x9FB91FEC9FC610A2ULL,
		0x57965551CD4F9E9AULL,
		0xDB74C85ED1DEFBC5ULL,
		0xDE5CF5208D4C6994ULL,
		0x93E44A0068F294D8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x190C06EF9C2F4FF9ULL,
		0x607F4FEE747A59E0ULL,
		0x6F6CEACD33669BB3ULL,
		0x8E680BAF807C8680ULL,
		0x0A1D3933E95BAD23ULL,
		0xECE7A10910F6A7D7ULL,
		0x18EE5979750F7ED5ULL,
		0x80C18CDC26D654C3ULL
	}};
	printf("Test Case 243\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x4A4C70ECB205C75CULL,
		0x21CB0A1C3A62AA0FULL,
		0x81685B2E2975744AULL,
		0x528AFE19DE4A583FULL,
		0xF32CF6B2A35BE4C1ULL,
		0x72A09DA0CD6EF8F0ULL,
		0x428C951D566F1A28ULL,
		0x6F633BE520CE539DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x80D5366BCE5C710DULL,
		0x564A0F04C5126131ULL,
		0x027B740DC3F0B255ULL,
		0x9A3CCB01AD549BA7ULL,
		0x5B39845F93462C47ULL,
		0x06083869E0C23590ULL,
		0x81FAB6FC60AACEB4ULL,
		0xEAE676C3BDD789EDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCA9946877C59B651ULL,
		0x77810518FF70CB3EULL,
		0x83132F23EA85C61FULL,
		0xC8B63518731EC398ULL,
		0xA81572ED301DC886ULL,
		0x74A8A5C92DACCD60ULL,
		0xC37623E136C5D49CULL,
		0x85854D269D19DA70ULL
	}};
	printf("Test Case 244\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x5FC095AA6ADAF5E4ULL,
		0x44CD7D502950E6D0ULL,
		0x63F03A10B22525B1ULL,
		0xB46173164143F86BULL,
		0x1855565FE0FFC894ULL,
		0x87F8D811C010C02EULL,
		0x48A0CBF299E6491BULL,
		0x7AF9C742C2F7783DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD64F2FC313DF98D4ULL,
		0xD5AFFE1215F26625ULL,
		0xE8A6A596E9759622ULL,
		0xFC9C9E788C0E60B3ULL,
		0x4857C935E8281290ULL,
		0xFA150EB0FD570A14ULL,
		0xA8E73226387F8D92ULL,
		0xDE939298E4CF14C6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x898FBA6979056D30ULL,
		0x916283423CA280F5ULL,
		0x8B569F865B50B393ULL,
		0x48FDED6ECD4D98D8ULL,
		0x50029F6A08D7DA04ULL,
		0x7DEDD6A13D47CA3AULL,
		0xE047F9D4A199C489ULL,
		0xA46A55DA26386CFBULL
	}};
	printf("Test Case 245\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x8F1E5D0579D9E6F9ULL,
		0x7A61AA9F61256A51ULL,
		0xA68E430718930DF0ULL,
		0x744A04758233ECE9ULL,
		0xD3D9B04C212F79CEULL,
		0x143B224AE7824940ULL,
		0x0E55386E7ECEA46AULL,
		0x083144B6B5D3DC8CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1E5028901960D9C7ULL,
		0x686138BC094DB4A2ULL,
		0x291908FC4AB2AD5DULL,
		0x740D350B59B05366ULL,
		0x68A45AD706DD045BULL,
		0xFFF518D7A2E66C7FULL,
		0x6638B6F6C958D84DULL,
		0x8804FC566806D254ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x914E759560B93F3EULL,
		0x120092236868DEF3ULL,
		0x8F974BFB5221A0ADULL,
		0x0047317EDB83BF8FULL,
		0xBB7DEA9B27F27D95ULL,
		0xEBCE3A9D4564253FULL,
		0x686D8E98B7967C27ULL,
		0x8035B8E0DDD50ED8ULL
	}};
	printf("Test Case 246\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x5985988D17F1F637ULL,
		0x621867308E69FFA4ULL,
		0xF92587580288307BULL,
		0x2D3B01BEE0A469AAULL,
		0x8AA4AF0DC56EDE51ULL,
		0x8E36840047803C4EULL,
		0x7C5594BED7E2CAC8ULL,
		0x3F96AA354201F42AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x254DDE678C17B292ULL,
		0x5E9485D871D26070ULL,
		0xDBDE9C833AD8AD76ULL,
		0x79CAE6452806627BULL,
		0xEFADB069A0B8C43CULL,
		0xFA11ABB6908FE587ULL,
		0x1AEF50626A5B9974ULL,
		0xC6479E9AB8CD7BF6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7CC846EA9BE644A5ULL,
		0x3C8CE2E8FFBB9FD4ULL,
		0x22FB1BDB38509D0DULL,
		0x54F1E7FBC8A20BD1ULL,
		0x65091F6465D61A6DULL,
		0x74272FB6D70FD9C9ULL,
		0x66BAC4DCBDB953BCULL,
		0xF9D134AFFACC8FDCULL
	}};
	printf("Test Case 247\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xEA69DBB4F0FA5FC7ULL,
		0x13D7CFB0611A4C2EULL,
		0xC8FC98DA8BDCFFEAULL,
		0x6BEA8D8614124322ULL,
		0xFD114F2EF2A392D9ULL,
		0x410D49D0DFB17292ULL,
		0x9014348A68EFB79EULL,
		0x267C018B91C874A8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF1260159B361E6D1ULL,
		0x8C45750A4991E60BULL,
		0x09EAFED6E7911383ULL,
		0x9AF2CF63441FDC11ULL,
		0x62D0892C76E7871BULL,
		0xED4BD740F48403CDULL,
		0x164D288DEDDCECABULL,
		0xA827DD054B146A9DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1B4FDAED439BB916ULL,
		0x9F92BABA288BAA25ULL,
		0xC116660C6C4DEC69ULL,
		0xF11842E5500D9F33ULL,
		0x9FC1C602844415C2ULL,
		0xAC469E902B35715FULL,
		0x86591C0785335B35ULL,
		0x8E5BDC8EDADC1E35ULL
	}};
	printf("Test Case 248\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x7972809764595F0EULL,
		0xE450FE990B70A13BULL,
		0xCA4E45A8AC0E9966ULL,
		0x308569E2BF17D6FEULL,
		0x07FB709A5E49AB0FULL,
		0xE993F4C3DAEC54F4ULL,
		0x33DF159825388831ULL,
		0xA662C0C3D8C0E91FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x448862B66067C987ULL,
		0x154E96CFC95902C3ULL,
		0x648744BF03BF7250ULL,
		0x7691D6DF3481A439ULL,
		0x1D77AB43985B3C75ULL,
		0x43E38FFA543396A4ULL,
		0x182B55E3D9FDD06FULL,
		0xE41C9C7B1A0A5BCFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3DFAE221043E9689ULL,
		0xF11E6856C229A3F8ULL,
		0xAEC90117AFB1EB36ULL,
		0x4614BF3D8B9672C7ULL,
		0x1A8CDBD9C612977AULL,
		0xAA707B398EDFC250ULL,
		0x2BF4407BFCC5585EULL,
		0x427E5CB8C2CAB2D0ULL
	}};
	printf("Test Case 249\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x7A030BF122B1DCE2ULL,
		0xC421AC4FD8F7EB6AULL,
		0xE05D631F6A968DAAULL,
		0xC2117E4AF32BD5F8ULL,
		0xC4834BA4F12359D1ULL,
		0x61B56D8977D7AE8FULL,
		0xA8E874CB714FDDD5ULL,
		0x8127F13DBA569E24ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB3C70EF961F12BE2ULL,
		0x7929C70F430143F5ULL,
		0x2E6C21D3D312CA1BULL,
		0xF82DE90159DEAE0DULL,
		0x877B66A238E6DC19ULL,
		0x3F9A343583B82A0AULL,
		0x210514B18CEF6B33ULL,
		0xBA124A46BF2BF589ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC9C405084340F700ULL,
		0xBD086B409BF6A89FULL,
		0xCE3142CCB98447B1ULL,
		0x3A3C974BAAF57BF5ULL,
		0x43F82D06C9C585C8ULL,
		0x5E2F59BCF46F8485ULL,
		0x89ED607AFDA0B6E6ULL,
		0x3B35BB7B057D6BADULL
	}};
	printf("Test Case 250\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x219D75B14EB5ECDBULL,
		0x2928D98CC6E65FACULL,
		0xBBC76519513A4DEAULL,
		0x5C8FE23E12361C09ULL,
		0x490BD48B4646215BULL,
		0x91AE0AF52A7E3F56ULL,
		0xDDDB54C41A3B234BULL,
		0x14799441C4E0C44AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9F8C4FE3C8757537ULL,
		0xD47EAF3B3F99F3F9ULL,
		0x539B056A54117D7CULL,
		0xAFB568B55CA3CB61ULL,
		0x3CCDF375657CAD9FULL,
		0xD8B342B761F377A8ULL,
		0x101B20C852571854ULL,
		0xD67EEB6488C36221ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBE113A5286C099ECULL,
		0xFD5676B7F97FAC55ULL,
		0xE85C6073052B3096ULL,
		0xF33A8A8B4E95D768ULL,
		0x75C627FE233A8CC4ULL,
		0x491D48424B8D48FEULL,
		0xCDC0740C486C3B1FULL,
		0xC2077F254C23A66BULL
	}};
	printf("Test Case 251\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x363B964F0B6FAFE2ULL,
		0x937201E66EE2102CULL,
		0x222289799DAD83CBULL,
		0x916A8CF09606D5E6ULL,
		0xF4783F54AE5AA252ULL,
		0x4F6846007C2A4F2EULL,
		0x3F8370B77CA31643ULL,
		0xAEFE08780EBC29A5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x360BD58334516213ULL,
		0x6B2ACA64664EED39ULL,
		0xB83EE0DD1945FB0DULL,
		0xED268BCAA0972FA2ULL,
		0xFCCB3A7A1DA16B8DULL,
		0x7B0D9001B0B49486ULL,
		0xA5AF4932F7A196A2ULL,
		0x00609C0C7F8AA8F8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x003043CC3F3ECDF1ULL,
		0xF858CB8208ACFD15ULL,
		0x9A1C69A484E878C6ULL,
		0x7C4C073A3691FA44ULL,
		0x08B3052EB3FBC9DFULL,
		0x3465D601CC9EDBA8ULL,
		0x9A2C39858B0280E1ULL,
		0xAE9E94747136815DULL
	}};
	printf("Test Case 252\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x538BFA1B32ED7B49ULL,
		0x5CA938FA085D9417ULL,
		0x98050DC6A9D9A9C2ULL,
		0xB98369344CA2E949ULL,
		0x59D841BED1EA6B0FULL,
		0x8D26B1287BFB44EAULL,
		0xF5BA0B8F2579C9BCULL,
		0x41CC8CB77B1875BFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x108D3CCB4264E06CULL,
		0xF394B36487755943ULL,
		0x47CDB8DB0D1D889DULL,
		0x77F7A0D11E983BAEULL,
		0x98C63157716F8BB9ULL,
		0x3FFF318DCC8C379BULL,
		0x15FB56673733B14BULL,
		0xBC0461008B349410ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4306C6D070899B25ULL,
		0xAF3D8B9E8F28CD54ULL,
		0xDFC8B51DA4C4215FULL,
		0xCE74C9E5523AD2E7ULL,
		0xC11E70E9A085E0B6ULL,
		0xB2D980A5B7777371ULL,
		0xE0415DE8124A78F7ULL,
		0xFDC8EDB7F02CE1AFULL
	}};
	printf("Test Case 253\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x64F6A35101D41636ULL,
		0xE9C3EA7D19E02AB3ULL,
		0x57B922DAD389BC18ULL,
		0x15B0AE3DEB038842ULL,
		0xD0D4657AA3638A2DULL,
		0x44EFCB00F0841D7CULL,
		0x3CA1F6A4DB364EE0ULL,
		0x65210AB60286BB33ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x865140C22649B1A4ULL,
		0x6D909032BA920260ULL,
		0xDD4B59AAD3872BF8ULL,
		0x897E0C18BED53451ULL,
		0x3DB5A646A95C1DFDULL,
		0x5EB7D61FDF9C2F7CULL,
		0x6F0F3F6B02E22049ULL,
		0x9C1DEF125AE5BB44ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE2A7E393279DA792ULL,
		0x84537A4FA37228D3ULL,
		0x8AF27B70000E97E0ULL,
		0x9CCEA22555D6BC13ULL,
		0xED61C33C0A3F97D0ULL,
		0x1A581D1F2F183200ULL,
		0x53AEC9CFD9D46EA9ULL,
		0xF93CE5A458630077ULL
	}};
	printf("Test Case 254\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xDB2D8CD8CBF4102DULL,
		0xFCED0E2B1B6BA8E0ULL,
		0xF7662B44DFD70FA4ULL,
		0x79CBE62FBCBC292AULL,
		0x0DFC465EA63D8302ULL,
		0x4FC3524CA7DEB6F7ULL,
		0x5E17FA23C220D434ULL,
		0xE4A03233CB635437ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x59C84DF087B69897ULL,
		0x52013CEDB1AC6289ULL,
		0x0963AA51C2C2C67CULL,
		0x0019FABA0EC73F10ULL,
		0x57E4A6A08A09CA47ULL,
		0xB19E7BB0739D7B99ULL,
		0xFA9DA689C634D277ULL,
		0xC6F871C8378088AFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x82E5C1284C4288BAULL,
		0xAEEC32C6AAC7CA69ULL,
		0xFE0581151D15C9D8ULL,
		0x79D21C95B27B163AULL,
		0x5A18E0FE2C344945ULL,
		0xFE5D29FCD443CD6EULL,
		0xA48A5CAA04140643ULL,
		0x225843FBFCE3DC98ULL
	}};
	printf("Test Case 255\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x5D8C116982E0BCFAULL,
		0x350099E765282C1CULL,
		0x6B84B8DEA8F99DCBULL,
		0x31A63C54751A978EULL,
		0x864C6B89385371A2ULL,
		0xA73EC839AF09C601ULL,
		0xD288D706056EBA47ULL,
		0x003296BDB580C686ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA806925D855A3C16ULL,
		0x515C3D5C4E33B639ULL,
		0xDFCE075FC112BB66ULL,
		0x4A221012887A15F0ULL,
		0xE592C4A97397B44CULL,
		0xB45B427EA982252AULL,
		0xB0F1E07C5BBAB600ULL,
		0xEC92982B49E1A242ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF58A833407BA80ECULL,
		0x645CA4BB2B1B9A25ULL,
		0xB44ABF8169EB26ADULL,
		0x7B842C46FD60827EULL,
		0x63DEAF204BC4C5EEULL,
		0x13658A47068BE32BULL,
		0x6279377A5ED40C47ULL,
		0xECA00E96FC6164C4ULL
	}};
	printf("Test Case 256\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xC741A7EB822C8583ULL,
		0x7E8D4B21AFEAC3F3ULL,
		0x851EE127117AB78EULL,
		0x1FE5E6A20DE66040ULL,
		0x07A3F546900954DDULL,
		0xF17E2780E3D6F4A6ULL,
		0x9BC3DDA64DE767A2ULL,
		0x63BEFC6BB1D94855ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x242A2B221F64ACB0ULL,
		0x72031380444D3DF4ULL,
		0xCC1BAF4A7660D2E7ULL,
		0x3CABA90E9757F217ULL,
		0x1530A259C959207AULL,
		0x064AD08CB7142498ULL,
		0x0737EEB141703DF1ULL,
		0xAAE32EBF8823D6F3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE36B8CC99D482933ULL,
		0x0C8E58A1EBA7FE07ULL,
		0x49054E6D671A6569ULL,
		0x234E4FAC9AB19257ULL,
		0x1293571F595074A7ULL,
		0xF734F70C54C2D03EULL,
		0x9CF433170C975A53ULL,
		0xC95DD2D439FA9EA6ULL
	}};
	printf("Test Case 257\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x578DB7482CC3D0A5ULL,
		0x792D6D44E87FD16EULL,
		0x1CC160E28FC6F657ULL,
		0xC82A68908950D693ULL,
		0x285CD2CAA6FCC738ULL,
		0x67D0B53A5FDECB43ULL,
		0xC1FCF7AF6CEFEDE0ULL,
		0x94D147DC5303A543ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE60772141D8C711CULL,
		0x9260E39C4B9E2C9AULL,
		0xB6F961DE143E7D3FULL,
		0x03F3178D2CAE5607ULL,
		0x52A5D346D57FBBC8ULL,
		0xBC7D7E231046224AULL,
		0x3E26920F87E98ECDULL,
		0x8807FF89EE00B4D7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB18AC55C314FA1B9ULL,
		0xEB4D8ED8A3E1FDF4ULL,
		0xAA38013C9BF88B68ULL,
		0xCBD97F1DA5FE8094ULL,
		0x7AF9018C73837CF0ULL,
		0xDBADCB194F98E909ULL,
		0xFFDA65A0EB06632DULL,
		0x1CD6B855BD031194ULL
	}};
	printf("Test Case 258\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xFAF9E1103195784FULL,
		0x2DE42233F5866303ULL,
		0x436424B954C73D45ULL,
		0xC2C05EAFF5C3EA75ULL,
		0x41887F2ECE4A61FCULL,
		0x5C0E3EDBB05EC00BULL,
		0x048630A213819BB1ULL,
		0x93D5100172711198ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x33410B9B41D54BBEULL,
		0x617BE24AB3E8517DULL,
		0xC1EF4B14573CD728ULL,
		0x2C97D0B308D18439ULL,
		0x2F6820AF7C1707B2ULL,
		0x5BF3938F09AE48DDULL,
		0x1E2174AA1C0E23B7ULL,
		0xA192A642F831900BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC9B8EA8B704033F1ULL,
		0x4C9FC079466E327EULL,
		0x828B6FAD03FBEA6DULL,
		0xEE578E1CFD126E4CULL,
		0x6EE05F81B25D664EULL,
		0x07FDAD54B9F088D6ULL,
		0x1AA744080F8FB806ULL,
		0x3247B6438A408193ULL
	}};
	printf("Test Case 259\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xFC14E8BE8D92186CULL,
		0x1E308BEA39E260FBULL,
		0xC61B4AF2CEABBE8BULL,
		0x5A09DB5926BFDD57ULL,
		0xEBC6CB6B887FA81CULL,
		0xC8E954D9DEABCFD7ULL,
		0x21FA7FB5DD7E68B2ULL,
		0xF1B11FE175B387A9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x74FD5796380E6808ULL,
		0x1DA02728EFC1701CULL,
		0xD9705DB7874FB773ULL,
		0x5757CC5F0E3DEC58ULL,
		0x0C0B65C234801CC7ULL,
		0x7F7BB23FE85C305BULL,
		0x2354E7E7F7A13705ULL,
		0x199D8BA47091FDDEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x88E9BF28B59C7064ULL,
		0x0390ACC2D62310E7ULL,
		0x1F6B174549E409F8ULL,
		0x0D5E17062882310FULL,
		0xE7CDAEA9BCFFB4DBULL,
		0xB792E6E636F7FF8CULL,
		0x02AE98522ADF5FB7ULL,
		0xE82C944505227A77ULL
	}};
	printf("Test Case 260\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x2CB08A7D4DD968ECULL,
		0x61E45E5D012DE934ULL,
		0x85011EFDA482493EULL,
		0x2CC949AF1DCC0BC5ULL,
		0xA63CF6AC93A93970ULL,
		0xB44209A00EDAEF48ULL,
		0x778A5818011D8809ULL,
		0x7855AB163FD3285DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x252A881660DA41E4ULL,
		0x4314A931A77579B7ULL,
		0x10D221B7A39FB94EULL,
		0x5E801B6692272E9EULL,
		0xD949CAFD15C02CF5ULL,
		0x78EB8B6B896761A5ULL,
		0x6BD432ACFD036918ULL,
		0x9FEC71E6860BDDCDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x099A026B2D032908ULL,
		0x22F0F76CA6589083ULL,
		0x95D33F4A071DF070ULL,
		0x724952C98FEB255BULL,
		0x7F753C5186691585ULL,
		0xCCA982CB87BD8EEDULL,
		0x1C5E6AB4FC1EE111ULL,
		0xE7B9DAF0B9D8F590ULL
	}};
	printf("Test Case 261\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x9E430CD6CF8A0E64ULL,
		0x5F8CCC90896CDC0EULL,
		0x5F736EFB2E4A1836ULL,
		0xE4F94A59DED12053ULL,
		0xF9C953C2493066AFULL,
		0x45DC39EB3030F05CULL,
		0x7EE3B0C30EED9733ULL,
		0x288FC3E2FA1EBFAEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC1C7480B471396ECULL,
		0x2D8A9C7B827F2D06ULL,
		0xFD7F9D12DD78D95EULL,
		0x0BFFC46DCCBCBE99ULL,
		0x40DADBF220AB88EAULL,
		0xFB21E3ACD32470ECULL,
		0x4B5CADA9F5AD48C1ULL,
		0xA4626F6651B652B9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5F8444DD88999888ULL,
		0x720650EB0B13F108ULL,
		0xA20CF3E9F332C168ULL,
		0xEF068E34126D9ECAULL,
		0xB9138830699BEE45ULL,
		0xBEFDDA47E31480B0ULL,
		0x35BF1D6AFB40DFF2ULL,
		0x8CEDAC84ABA8ED17ULL
	}};
	printf("Test Case 262\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x98FCA21AC1B13ED3ULL,
		0x3318789B173361C9ULL,
		0xDB176CFA7F684410ULL,
		0xA9DC1B260909DF2DULL,
		0xD1AC60B33F7575F1ULL,
		0xE08E7336024E4F2FULL,
		0xAA746C6544A8E2E2ULL,
		0xC5ECFF80FBF2F436ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5CEB7E1EF1E3D323ULL,
		0x63304A0EB789F6ADULL,
		0x5DADCC480DADDB8DULL,
		0x6BC787518850A7CBULL,
		0x5F170D3E397E678FULL,
		0xBA4E4D23D252368AULL,
		0x30919270CC1634DEULL,
		0xECF09E1F1A7FD4A9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC417DC043052EDF0ULL,
		0x50283295A0BA9764ULL,
		0x86BAA0B272C59F9DULL,
		0xC21B9C77815978E6ULL,
		0x8EBB6D8D060B127EULL,
		0x5AC03E15D01C79A5ULL,
		0x9AE5FE1588BED63CULL,
		0x291C619FE18D209FULL
	}};
	printf("Test Case 263\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x8B7A52D716498234ULL,
		0x9A431FC5BEDF713AULL,
		0xBE1CA377A61FD47CULL,
		0x64B95E7CD8D875F3ULL,
		0xA0AAF08A7E8E12CBULL,
		0xD906DD18541C6520ULL,
		0xB3A917F543868F8EULL,
		0xD97461AF0DD32216ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x42EDF693D1D04FC6ULL,
		0x59EFA0C77F0DA0FFULL,
		0x169524D616E30FE6ULL,
		0x6258F2356E68BA1DULL,
		0xEA279DDE34F6FC9DULL,
		0xA77854C3490C9150ULL,
		0x3C5257401926B931ULL,
		0x64F20709FDAEAAC2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC997A444C799CDF2ULL,
		0xC3ACBF02C1D2D1C5ULL,
		0xA88987A1B0FCDB9AULL,
		0x06E1AC49B6B0CFEEULL,
		0x4A8D6D544A78EE56ULL,
		0x7E7E89DB1D10F470ULL,
		0x8FFB40B55AA036BFULL,
		0xBD8666A6F07D88D4ULL
	}};
	printf("Test Case 264\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x255EB840329E7AF3ULL,
		0xF799D8C53F92921FULL,
		0xB3435F302A8E7F5EULL,
		0xA7A4CC825D819449ULL,
		0x806B3E3D9C58E554ULL,
		0x62DDA3FF40A22AA1ULL,
		0x8B1635CB936F8080ULL,
		0x8C50284825343A1DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3F85036E0291C895ULL,
		0x6A729C09379094CFULL,
		0x1524E44679EB49BDULL,
		0x6D109AF669017D7EULL,
		0xAD50B361DC4995AFULL,
		0xC996B55EAF6FFE08ULL,
		0xFD239DEFB2E12A6AULL,
		0xBF06AAF983962B4DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1ADBBB2E300FB266ULL,
		0x9DEB44CC080206D0ULL,
		0xA667BB76536536E3ULL,
		0xCAB456743480E937ULL,
		0x2D3B8D5C401170FBULL,
		0xAB4B16A1EFCDD4A9ULL,
		0x7635A824218EAAEAULL,
		0x335682B1A6A21150ULL
	}};
	printf("Test Case 265\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xD535A86BCC0DF807ULL,
		0x19DDA4AC320E6959ULL,
		0x280E3664439EB7DDULL,
		0xFF90EC66E27F5098ULL,
		0xBD51EBB201CCFCA5ULL,
		0x1817D0EF39ED6E38ULL,
		0xDAF28BCAEA2D8B32ULL,
		0x55B6F6504463622BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB53AC3D5335FC322ULL,
		0xD3BD63084BBE7440ULL,
		0xE0CA2DB463E5A77AULL,
		0x5E71E27EEC58787AULL,
		0x956ADC0072AE4816ULL,
		0xF85815391305CDD1ULL,
		0x9D7962747600BBE0ULL,
		0x6BC0B34F4D3B659CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x600F6BBEFF523B25ULL,
		0xCA60C7A479B01D19ULL,
		0xC8C41BD0207B10A7ULL,
		0xA1E10E180E2728E2ULL,
		0x283B37B27362B4B3ULL,
		0xE04FC5D62AE8A3E9ULL,
		0x478BE9BE9C2D30D2ULL,
		0x3E76451F095807B7ULL
	}};
	printf("Test Case 266\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x4F4B82D797252538ULL,
		0x36EE17533A72218DULL,
		0x06A892DD07549E54ULL,
		0xF91E14A691AD2C9FULL,
		0xB5EEA5184797CFD0ULL,
		0xD58A061001654B9BULL,
		0x056BD7CC8292BB5BULL,
		0xA820CD10A8AF2EC4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1EA6AF58C7202A5DULL,
		0x2050B098EA6658BFULL,
		0x33196DB9948823B9ULL,
		0x7BA06330AF6FC86CULL,
		0x98B836C6B6A8E6F4ULL,
		0xE874B468EB30DE06ULL,
		0xFBDC2856D2685BDDULL,
		0x94AC3FCB784AB2F9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x51ED2D8F50050F65ULL,
		0x16BEA7CBD0147932ULL,
		0x35B1FF6493DCBDEDULL,
		0x82BE77963EC2E4F3ULL,
		0x2D5693DEF13F2924ULL,
		0x3DFEB278EA55959DULL,
		0xFEB7FF9A50FAE086ULL,
		0x3C8CF2DBD0E59C3DULL
	}};
	printf("Test Case 267\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xBFA7D8ADC9D65286ULL,
		0x794AC93B9FFB25F0ULL,
		0x6D42846D08590158ULL,
		0x65B449EB9E42409BULL,
		0x36BD276F5175072CULL,
		0x9F4224A4179AB5F2ULL,
		0x40D101AF54551939ULL,
		0x48BAE8251AE8988CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA2B5D27E45F90B21ULL,
		0xCBFBDE17C5FB73B2ULL,
		0x8318E0F1A8C9FC33ULL,
		0x02BC4A08BE26745CULL,
		0xB91024B40B2113B0ULL,
		0x56BED41C170532DDULL,
		0x7BFB8E1CC1E2ECE9ULL,
		0xB9FDF568F3AB7C9FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1D120AD38C2F59A7ULL,
		0xB2B1172C5A005642ULL,
		0xEE5A649CA090FD6BULL,
		0x670803E3206434C7ULL,
		0x8FAD03DB5A54149CULL,
		0xC9FCF0B8009F872FULL,
		0x3B2A8FB395B7F5D0ULL,
		0xF1471D4DE943E413ULL
	}};
	printf("Test Case 268\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x961D918B5922B792ULL,
		0x06A088B1B7DE5724ULL,
		0xB91260DD0DE7E370ULL,
		0x032273D4DCAA7524ULL,
		0xF9C7550B8A278821ULL,
		0x5265423B72E2E0DEULL,
		0x41BEB3D91E649B9DULL,
		0xC4C45E1E51FF335DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC015FF0E53E19832ULL,
		0xEE3E43A965E46FDBULL,
		0x7E8B7F6BD0FBA1C0ULL,
		0x8E553B19C4E130C6ULL,
		0x3B24D30B909D1A28ULL,
		0x2FC50A72A493F90DULL,
		0x3F14CAB1C998CA9AULL,
		0x682093ED800F48DDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x56086E850AC32FA0ULL,
		0xE89ECB18D23A38FFULL,
		0xC7991FB6DD1C42B0ULL,
		0x8D7748CD184B45E2ULL,
		0xC2E386001ABA9209ULL,
		0x7DA04849D67119D3ULL,
		0x7EAA7968D7FC5107ULL,
		0xACE4CDF3D1F07B80ULL
	}};
	printf("Test Case 269\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xBCAC786CF0A8C719ULL,
		0x5670A4C565DDC2EBULL,
		0xEA3A1E365CC09631ULL,
		0x5C34F89EFB76E185ULL,
		0x15E6E46449A863A2ULL,
		0xBA90F08C7F60B2E9ULL,
		0x403182515B10F064ULL,
		0x6F129F7EC7F0AD41ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x689117ED98D5ABA6ULL,
		0xBEDD853E83A62338ULL,
		0x6829EC07803D4196ULL,
		0x6C76EB1E4D450B14ULL,
		0xC7582BE476B035ABULL,
		0x06CAABC0BAEF81D4ULL,
		0xE8C9CB5CCF16F467ULL,
		0xF4E304BF0F0FDD1CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD43D6F81687D6CBFULL,
		0xE8AD21FBE67BE1D3ULL,
		0x8213F231DCFDD7A7ULL,
		0x30421380B633EA91ULL,
		0xD2BECF803F185609ULL,
		0xBC5A5B4CC58F333DULL,
		0xA8F8490D94060403ULL,
		0x9BF19BC1C8FF705DULL
	}};
	printf("Test Case 270\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xDBD43F0C1FD278E9ULL,
		0x92C0DE639464C428ULL,
		0xCA2CB262E99976E0ULL,
		0x11B193F7778DD11AULL,
		0xE1116C22A4094A51ULL,
		0xDB0FAD8B411CE998ULL,
		0xD2F9C0D181C18E7EULL,
		0x0718F13C2FEF931FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x27829D016FA1681EULL,
		0xBC897B89D396E843ULL,
		0x5F703C5A2F78F14EULL,
		0x14CAEFC7631707E5ULL,
		0x46EC912E8D76C6C2ULL,
		0xA07D25CA7A80AA6EULL,
		0x7B8F5D3C80214D34ULL,
		0x90DA9844A971C22BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFC56A20D707310F7ULL,
		0x2E49A5EA47F22C6BULL,
		0x955C8E38C6E187AEULL,
		0x057B7C30149AD6FFULL,
		0xA7FDFD0C297F8C93ULL,
		0x7B7288413B9C43F6ULL,
		0xA9769DED01E0C34AULL,
		0x97C26978869E5134ULL
	}};
	printf("Test Case 271\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x5449D26E32FD98ABULL,
		0x1F03DA3A683190A7ULL,
		0x9E3878767187FE9FULL,
		0xDDF238FA1AC2BB12ULL,
		0xE6063B7448316601ULL,
		0xFD7DAD7180703296ULL,
		0xD08311A4BCA7602BULL,
		0xBB7D4DFD33CAFCB0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0EAD2EB29ADA0FCDULL,
		0xF46059F3533AFC7AULL,
		0x846BFD41797303B9ULL,
		0x0606D1F58C265336ULL,
		0x9363EBECC4E08BD3ULL,
		0x92B55EE15CAC32A0ULL,
		0x24ED95148125BB4CULL,
		0x7E51A9351FF42AEDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5AE4FCDCA8279766ULL,
		0xEB6383C93B0B6CDDULL,
		0x1A53853708F4FD26ULL,
		0xDBF4E90F96E4E824ULL,
		0x7565D0988CD1EDD2ULL,
		0x6FC8F390DCDC0036ULL,
		0xF46E84B03D82DB67ULL,
		0xC52CE4C82C3ED65DULL
	}};
	printf("Test Case 272\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x63DC5FD9E25F3E44ULL,
		0xF3D5469C4C5144E5ULL,
		0xCBDF9C604FF1124EULL,
		0x14F911755F8D22AEULL,
		0xA892B936673BA2D3ULL,
		0xBF09D9DE70A94C11ULL,
		0xAC7A057354281C20ULL,
		0x7197963D9617F42FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x88F957A8F92AC70AULL,
		0x84CD163B62F632C6ULL,
		0xDE787DB936E335B9ULL,
		0x484EB4E3BE53599BULL,
		0x8890D1EF62E15459ULL,
		0x86B66046437FF1A9ULL,
		0x2A98FAFF61317CD0ULL,
		0x384B79E9CB2A38D3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEB2508711B75F94EULL,
		0x771850A72EA77623ULL,
		0x15A7E1D9791227F7ULL,
		0x5CB7A596E1DE7B35ULL,
		0x200268D905DAF68AULL,
		0x39BFB99833D6BDB8ULL,
		0x86E2FF8C351960F0ULL,
		0x49DCEFD45D3DCCFCULL
	}};
	printf("Test Case 273\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x01C951C2069374ECULL,
		0x1F70ECE148F87EE3ULL,
		0xF3B4324789D7ED45ULL,
		0xFD82D3B45A15FFC7ULL,
		0xD392E1D4330023E2ULL,
		0xB8D529714D1660B4ULL,
		0x8D10E338E046DF6FULL,
		0x6454A7820FABF1D2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7BF4C18FA68B06FDULL,
		0x46C2770413CDEA2AULL,
		0x49BE8742DF2F447DULL,
		0x220A0F56E4859D8AULL,
		0x482AFE3D94EF0E94ULL,
		0xE4227841A9E49A7FULL,
		0x23E793CDDD70B8E7ULL,
		0x0CC2B903F872D124ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7A3D904DA0187211ULL,
		0x59B29BE55B3594C9ULL,
		0xBA0AB50556F8A938ULL,
		0xDF88DCE2BE90624DULL,
		0x9BB81FE9A7EF2D76ULL,
		0x5CF75130E4F2FACBULL,
		0xAEF770F53D366788ULL,
		0x68961E81F7D920F6ULL
	}};
	printf("Test Case 274\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xE8F689275CC59998ULL,
		0xFB3E145ABFBF9879ULL,
		0x103A90109933F005ULL,
		0xF0D10F11B1412B67ULL,
		0x51D19D40B2849E70ULL,
		0x6CBCD06AD2861A0CULL,
		0x1FB451D7B60F179DULL,
		0x4A4F401E4CFCF8B9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0A31D391A85F3809ULL,
		0xCB1F7B6B467BA806ULL,
		0x25E43ED161954B20ULL,
		0xF190ED7763221436ULL,
		0x306724A40168E1E0ULL,
		0x323905780C719189ULL,
		0xEE8600CE46C2D6DBULL,
		0xFEC5BD80402396A3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE2C75AB6F49AA191ULL,
		0x30216F31F9C4307FULL,
		0x35DEAEC1F8A6BB25ULL,
		0x0141E266D2633F51ULL,
		0x61B6B9E4B3EC7F90ULL,
		0x5E85D512DEF78B85ULL,
		0xF1325119F0CDC146ULL,
		0xB48AFD9E0CDF6E1AULL
	}};
	printf("Test Case 275\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xE83FE5E0D0C038B5ULL,
		0x64D660B7149E7F3CULL,
		0x141A1DA23743888AULL,
		0x9139CD1ACED24A29ULL,
		0x1E3EC7ED93DF9081ULL,
		0xC8BC24397D9583CDULL,
		0xF7E9C0486C85867BULL,
		0x315282D4B3429F7CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB63F8BA071625833ULL,
		0xB9C08F52047531BAULL,
		0x8F9B08981F2AB0F1ULL,
		0x1F8A3FB347A8EDA1ULL,
		0x8573A7028A0C44D4ULL,
		0x580553EADD0D77E0ULL,
		0x743F57F793325125ULL,
		0xCB8F32A2AB04AD49ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5E006E40A1A26086ULL,
		0xDD16EFE510EB4E86ULL,
		0x9B81153A2869387BULL,
		0x8EB3F2A9897AA788ULL,
		0x9B4D60EF19D3D455ULL,
		0x90B977D3A098F42DULL,
		0x83D697BFFFB7D75EULL,
		0xFADDB07618463235ULL
	}};
	printf("Test Case 276\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xE642DEFDA089F442ULL,
		0xDD60035D4A3C89A3ULL,
		0x91BE6492AC95760DULL,
		0x55F2C122C0845B6AULL,
		0x8BEB8C4C7408DA39ULL,
		0x473B3F90467B064BULL,
		0x7CAD54A7995DB8BDULL,
		0x3CE64113BB385325ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAFFEEBF3B3B76725ULL,
		0xAAF7A47D555A9CE2ULL,
		0x6FC8A6C9949DEF87ULL,
		0x4918055C582EB54FULL,
		0xC8BABC78A710A6E7ULL,
		0xE88428C2655A5BFBULL,
		0xA9A61D071EA20A72ULL,
		0x6B0A0ED61B8A25E4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x49BC350E133E9367ULL,
		0x7797A7201F661541ULL,
		0xFE76C25B3808998AULL,
		0x1CEAC47E98AAEE25ULL,
		0x43513034D3187CDEULL,
		0xAFBF175223215DB0ULL,
		0xD50B49A087FFB2CFULL,
		0x57EC4FC5A0B276C1ULL
	}};
	printf("Test Case 277\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x6B57E67487EAE557ULL,
		0x37C497BDA77DE793ULL,
		0xCB376123C9B285A5ULL,
		0x03E18EF56DAD1640ULL,
		0x297AE14A09273897ULL,
		0xE61535C41105A30DULL,
		0xD963FDEC88D95913ULL,
		0x015B1CCDFC8E2AAFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF76947C6E7519EA5ULL,
		0x514DEE9F24A8BDF5ULL,
		0x4FDE4593ADAF68F3ULL,
		0x3D13102AED39A863ULL,
		0xB287408FB730B5A5ULL,
		0xAD807517CB73B8C5ULL,
		0xF6B34EE0BF47F745ULL,
		0xDFB1A7F56EAAB105ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9C3EA1B260BB7BF2ULL,
		0x6689792283D55A66ULL,
		0x84E924B0641DED56ULL,
		0x3EF29EDF8094BE23ULL,
		0x9BFDA1C5BE178D32ULL,
		0x4B9540D3DA761BC8ULL,
		0x2FD0B30C379EAE56ULL,
		0xDEEABB3892249BAAULL
	}};
	printf("Test Case 278\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x49FE850B5B7FA665ULL,
		0x5432F9ABABD86E8EULL,
		0x396066B5A9EAFC38ULL,
		0xE3F48ED12D875ED0ULL,
		0x5CFAA2470004E24AULL,
		0x631486DB08F7B3C2ULL,
		0xF513D90D154EF6B7ULL,
		0xAA7BED5190C82DC6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x32C9CB7148DD10AEULL,
		0x183D81A48591C8BCULL,
		0x367EE61E66A80140ULL,
		0x152128254BAD1164ULL,
		0x33D4BDB48D4CE345ULL,
		0x15ECC9260C95ADA9ULL,
		0x83610C380CF17264ULL,
		0x3D7552D41344AE1BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7B374E7A13A2B6CBULL,
		0x4C0F780F2E49A632ULL,
		0x0F1E80ABCF42FD78ULL,
		0xF6D5A6F4662A4FB4ULL,
		0x6F2E1FF38D48010FULL,
		0x76F84FFD04621E6BULL,
		0x7672D53519BF84D3ULL,
		0x970EBF85838C83DDULL
	}};
	printf("Test Case 279\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xACA80F854BA123D3ULL,
		0x6668FC193089BAA3ULL,
		0x158725F2391E245CULL,
		0xA9D07AF5152B262FULL,
		0xB0A00D4331E5F4C7ULL,
		0xBC5FDD758ECEB948ULL,
		0xD7323CC3D14E9C58ULL,
		0xF23539A3F31A89B2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x65E641AC2A89C56EULL,
		0xB0B6E0E2F8E34B3BULL,
		0xD0F8E0D74AC160F1ULL,
		0x0D41D11CB903680FULL,
		0x5166FCE0BF0C62B5ULL,
		0x539358EB5ED38F1CULL,
		0x4DA9FCC1A62E5174ULL,
		0x542DFCB745ECEAD1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC94E4E296128E6BDULL,
		0xD6DE1CFBC86AF198ULL,
		0xC57FC52573DF44ADULL,
		0xA491ABE9AC284E20ULL,
		0xE1C6F1A38EE99672ULL,
		0xEFCC859ED01D3654ULL,
		0x9A9BC0027760CD2CULL,
		0xA618C514B6F66363ULL
	}};
	printf("Test Case 280\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xAA57457051A8F19DULL,
		0x61DCEDAB6BD64CF4ULL,
		0xC33CFCD9DBD7E00DULL,
		0x6E148137E943E68EULL,
		0x22033D3C814BD96FULL,
		0x501D8409BB437CECULL,
		0x5AF0AAAACBF112E9ULL,
		0xFE78A7A335260443ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB3AD41F077F219A3ULL,
		0x13174B48F7F49213ULL,
		0x2E53E2370319DFAEULL,
		0x7BC74FF692F7827AULL,
		0xD73C2E0534E39784ULL,
		0xD781F40B774CFE00ULL,
		0x0AC44F2A3D329D4FULL,
		0x19590279E46019B8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x19FA0480265AE83EULL,
		0x72CBA6E39C22DEE7ULL,
		0xED6F1EEED8CE3FA3ULL,
		0x15D3CEC17BB464F4ULL,
		0xF53F1339B5A84EEBULL,
		0x879C7002CC0F82ECULL,
		0x5034E580F6C38FA6ULL,
		0xE721A5DAD1461DFBULL
	}};
	printf("Test Case 281\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x1CE32A8CC4DA0ABFULL,
		0xB943D7F98724617FULL,
		0xAFB6B720C0F86342ULL,
		0xAD61D8382F05E69DULL,
		0xB145F57DF14B69E7ULL,
		0x9CA592E48AED7365ULL,
		0xCB67DF578110AB4FULL,
		0x382F6BC30DCF23C0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE17B95D342F32DD4ULL,
		0xD11EAE753E59873CULL,
		0x389420CAF07D6DDDULL,
		0x3334EB9EA8E50F7DULL,
		0xAF3DB8A67981E2EDULL,
		0xF8AB033DB558BC8FULL,
		0xD7DD27CE7D71289DULL,
		0xA24AB9DD8B9150AFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFD98BF5F8629276BULL,
		0x685D798CB97DE643ULL,
		0x972297EA30850E9FULL,
		0x9E5533A687E0E9E0ULL,
		0x1E784DDB88CA8B0AULL,
		0x640E91D93FB5CFEAULL,
		0x1CBAF899FC6183D2ULL,
		0x9A65D21E865E736FULL
	}};
	printf("Test Case 282\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x6384022DED68FDA7ULL,
		0x1C5DDE61FFA27171ULL,
		0x816C9826F08B669CULL,
		0x21CD18884F3819D5ULL,
		0x8AA98AF19AE07AE8ULL,
		0xCF30D097B7BA9962ULL,
		0x0FC0AE8AF1C6F370ULL,
		0xC3F007F544B43D6AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBD9E32CDBBDCCB01ULL,
		0x7D2C2C547773AFFFULL,
		0x2CBF9E63F727E19EULL,
		0x7770211A37C05BFBULL,
		0x08703ACD5C44783FULL,
		0x863C71AFC4AF0896ULL,
		0x93BB7935F2F042ADULL,
		0x3A23FF718BDB3064ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDE1A30E056B436A6ULL,
		0x6171F23588D1DE8EULL,
		0xADD3064507AC8702ULL,
		0x56BD399278F8422EULL,
		0x82D9B03CC6A402D7ULL,
		0x490CA138731591F4ULL,
		0x9C7BD7BF0336B1DDULL,
		0xF9D3F884CF6F0D0EULL
	}};
	printf("Test Case 283\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x873AE191A3EE4C5EULL,
		0x353741822FEDFDE4ULL,
		0xE9D66513F2CBE2EFULL,
		0x4B665F21311645D1ULL,
		0x7FE984B179C72DAEULL,
		0xE1A229A616DE5F6EULL,
		0x4A2407C8D85DA18BULL,
		0xD38F84235C42CE5DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA0A892B515FF73B8ULL,
		0xC6451DE781DD2145ULL,
		0xA23DDDA6C6FF3043ULL,
		0x6E5675DD35D25C88ULL,
		0x584A7D1B42B1DE0DULL,
		0x7E5B7658895CB8E9ULL,
		0x12C40BB4EBF8FEAFULL,
		0x8ACCE73150A35665ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x27927324B6113FE6ULL,
		0xF3725C65AE30DCA1ULL,
		0x4BEBB8B53434D2ACULL,
		0x25302AFC04C41959ULL,
		0x27A3F9AA3B76F3A3ULL,
		0x9FF95FFE9F82E787ULL,
		0x58E00C7C33A55F24ULL,
		0x594363120CE19838ULL
	}};
	printf("Test Case 284\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xE4303E5FD99053C4ULL,
		0xFD79D499E221BFDFULL,
		0xEEA00BFB63332063ULL,
		0x92049A1FCF8750BDULL,
		0x3B51689FB037CBF0ULL,
		0x5E2B9ABDFD494B4BULL,
		0x277CC3470D2A30CDULL,
		0xE6733372593A1493ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBFFAA956690D83ADULL,
		0x2872B270F36E30A4ULL,
		0x21CBFC2721BD5580ULL,
		0x0599DC5C365A2B52ULL,
		0xB2873F6D0F378E5AULL,
		0x3A22027D87473803ULL,
		0x478E4EA3AC194413ULL,
		0xDC775533016997BAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5BCA9709B09DD069ULL,
		0xD50B66E9114F8F7BULL,
		0xCF6BF7DC428E75E3ULL,
		0x979D4643F9DD7BEFULL,
		0x89D657F2BF0045AAULL,
		0x640998C07A0E7348ULL,
		0x60F28DE4A13374DEULL,
		0x3A04664158538329ULL
	}};
	printf("Test Case 285\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x478C81DB5E6FC213ULL,
		0x40C73F8A1D16656FULL,
		0x8E72CA1B996ADA6DULL,
		0xD000C55C4F427D06ULL,
		0x6CAC3B5B95236588ULL,
		0x7D2CB630991C3975ULL,
		0xD619DED909818845ULL,
		0xC7F05E207ABB99AFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC8F89D4B660F5408ULL,
		0x69751744402937F8ULL,
		0x5370447EE37F1E2EULL,
		0x17CCDF434E8F4C71ULL,
		0x8DEA20DD0EEC4182ULL,
		0xCC553675DF205F9CULL,
		0x802B1531E7AC4661ULL,
		0xE0D1D4AFBAC0D561ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8F741C903860961BULL,
		0x29B228CE5D3F5297ULL,
		0xDD028E657A15C443ULL,
		0xC7CC1A1F01CD3177ULL,
		0xE1461B869BCF240AULL,
		0xB1798045463C66E9ULL,
		0x5632CBE8EE2DCE24ULL,
		0x27218A8FC07B4CCEULL
	}};
	printf("Test Case 286\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x133143DC6223A919ULL,
		0x948913945DD9E2F0ULL,
		0x627CC74C38F632A4ULL,
		0xA4AAE6577F9EB088ULL,
		0x9B649210B87CEBB1ULL,
		0x050D6AD77B42E162ULL,
		0xF621E9C634F9FA0CULL,
		0x9AC6774AEC33FC1EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD1B1D4D6FF509C79ULL,
		0x6B73D07EE5382F94ULL,
		0x5A0230C65F6FB899ULL,
		0x196781E0BB923EA1ULL,
		0x3C6B145F5D9466ECULL,
		0x862DE3EB00F25B83ULL,
		0x82C8FA81EAF5CB40ULL,
		0xA0123D5DEF242A03ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC280970A9D733560ULL,
		0xFFFAC3EAB8E1CD64ULL,
		0x387EF78A67998A3DULL,
		0xBDCD67B7C40C8E29ULL,
		0xA70F864FE5E88D5DULL,
		0x8320893C7BB0BAE1ULL,
		0x74E91347DE0C314CULL,
		0x3AD44A170317D61DULL
	}};
	printf("Test Case 287\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x78B875E26632CAC7ULL,
		0x81E40ECEA54A2EDAULL,
		0x66EDE2590329F7BDULL,
		0x31430E149A662A9FULL,
		0x4EC411E1C68AC4CCULL,
		0xF02CAF3E6697AF0EULL,
		0xE28422AE112EC106ULL,
		0xEE23EAB91013C908ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x783F3EAC9DDF4067ULL,
		0xBDA1FB735F1EAF36ULL,
		0xCA70BDF5170D9E9DULL,
		0x59903458AB1B19C5ULL,
		0xEA75FBE9F3663C47ULL,
		0xADFAFEC00795D333ULL,
		0xDCECDAB072A1EE70ULL,
		0xE60F882C203742F8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x00874B4EFBED8AA0ULL,
		0x3C45F5BDFA5481ECULL,
		0xAC9D5FAC14246920ULL,
		0x68D33A4C317D335AULL,
		0xA4B1EA0835ECF88BULL,
		0x5DD651FE61027C3DULL,
		0x3E68F81E638F2F76ULL,
		0x082C629530248BF0ULL
	}};
	printf("Test Case 288\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x0FF2308DDFA4FD37ULL,
		0x457A9DA84A02F675ULL,
		0x4C29AEC3601E9597ULL,
		0xC5E5DCC243CD9155ULL,
		0x567BEDDF9C6EA5B7ULL,
		0x558001ABE17CDE77ULL,
		0xCB05E2F057F2F36AULL,
		0xC022AA5AED29467CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x76B9609A16EF671FULL,
		0x5CA30A80A22B61AEULL,
		0xAA549993B54D6BCBULL,
		0x4B16DEAAAFC55783ULL,
		0x14FCCFEA58CA2D13ULL,
		0xA4965BB180D1753AULL,
		0x50A7C6EEBC8F956DULL,
		0x935D911FE069BE99ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x794B5017C94B9A28ULL,
		0x19D99728E82997DBULL,
		0xE67D3750D553FE5CULL,
		0x8EF30268EC08C6D6ULL,
		0x42872235C4A488A4ULL,
		0xF1165A1A61ADAB4DULL,
		0x9BA2241EEB7D6607ULL,
		0x537F3B450D40F8E5ULL
	}};
	printf("Test Case 289\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xF5EE1A98E128299EULL,
		0xC1420221722658C2ULL,
		0xBD8409D3F42628CAULL,
		0x82884FDFE18EB9D4ULL,
		0x9923576D7786A405ULL,
		0xE43CBB47714E4511ULL,
		0x457D8A35A32BF4EFULL,
		0x28374A8BDAA208F0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x67A229778F0CD605ULL,
		0xCC7351291FC65951ULL,
		0xB93CB319008045BEULL,
		0x2BF8C68980B89C3CULL,
		0x4A86B8CC046E27E4ULL,
		0x44CFA89AC9CA4659ULL,
		0xA7543053A665D2BFULL,
		0x19D26957FA63FF0CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x924C33EF6E24FF9BULL,
		0x0D3153086DE00193ULL,
		0x04B8BACAF4A66D74ULL,
		0xA9708956613625E8ULL,
		0xD3A5EFA173E883E1ULL,
		0xA0F313DDB8840348ULL,
		0xE229BA66054E2650ULL,
		0x31E523DC20C1F7FCULL
	}};
	printf("Test Case 290\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xA6D37CF51CFA08D5ULL,
		0xD1CBDCD6E3176BA9ULL,
		0x407BF4D87B667F8CULL,
		0xF43201172CC52FC4ULL,
		0x2198FF5C313AC36BULL,
		0xBB5F33DF737F828DULL,
		0x7D96590EEADB55D2ULL,
		0xEC91B6FBFC216C7FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8487E0B0F5AA43DCULL,
		0xD7665AA836C02F0DULL,
		0xDBF9D4D4C79AD885ULL,
		0x03714F2FF7D8A28AULL,
		0x369A759F0C9BEA35ULL,
		0x96AFD9427C166493ULL,
		0x6ED63CE37625500BULL,
		0x2EDC72D2702A599CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x22549C45E9504B09ULL,
		0x06AD867ED5D744A4ULL,
		0x9B82200CBCFCA709ULL,
		0xF7434E38DB1D8D4EULL,
		0x17028AC33DA1295EULL,
		0x2DF0EA9D0F69E61EULL,
		0x134065ED9CFE05D9ULL,
		0xC24DC4298C0B35E3ULL
	}};
	printf("Test Case 291\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xB6B136BB7884E3E8ULL,
		0x4C82A13299131C3AULL,
		0x446856DB567C1D68ULL,
		0x45096C5825C7978CULL,
		0x5BB927B782A6BA60ULL,
		0x569E5E9836D2CA45ULL,
		0xCCB515BCC4CB65E7ULL,
		0x0B7673BA9794AE8BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3BB92EC2485C67D1ULL,
		0xAA815F17E40463D2ULL,
		0xC62E035BD2DA6095ULL,
		0xB89FCB06BB5E2C5EULL,
		0xE5DD4E27D566CC05ULL,
		0xBBFE3A348120037CULL,
		0x1213484ACEB6DB5EULL,
		0xDBA9A01673D01464ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8D08187930D88439ULL,
		0xE603FE257D177FE8ULL,
		0x8246558084A67DFDULL,
		0xFD96A75E9E99BBD2ULL,
		0xBE64699057C07665ULL,
		0xED6064ACB7F2C939ULL,
		0xDEA65DF60A7DBEB9ULL,
		0xD0DFD3ACE444BAEFULL
	}};
	printf("Test Case 292\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x9F534C80799F9E6CULL,
		0xA41B9587DC865BC2ULL,
		0x09F6FA90976C6C79ULL,
		0xF3207ECF2774491EULL,
		0x77970B41ED6AFBF8ULL,
		0x140907C5FDABB603ULL,
		0xBC1F11795053AD41ULL,
		0xBD584FD7EE6AA095ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4AF0B693A2D90731ULL,
		0x4652F7875AF0B4F7ULL,
		0x23CE5E69A650A934ULL,
		0x2B22A66190336A7FULL,
		0x8FB81984C805443BULL,
		0x64A5A066C838EF55ULL,
		0xC141AD18125F7A0EULL,
		0x903EB9EAF6306267ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD5A3FA13DB46995DULL,
		0xE24962008676EF35ULL,
		0x2A38A4F9313CC54DULL,
		0xD802D8AEB7472361ULL,
		0xF82F12C5256FBFC3ULL,
		0x70ACA7A335935956ULL,
		0x7D5EBC61420CD74FULL,
		0x2D66F63D185AC2F2ULL
	}};
	printf("Test Case 293\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xE6302171D7AF33E9ULL,
		0x1AC6B6329F1DD506ULL,
		0xF5DB12656BC0AB7FULL,
		0x1F6AE75447A684FCULL,
		0x0A9A21039D8EA36BULL,
		0x368AC31195A46FB9ULL,
		0x2BC5CEDF3C303B5FULL,
		0xDD990F40260DC687ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x32AEA0BB80293C00ULL,
		0x16FEA83FC569A5E2ULL,
		0x8DC5DBF01E41A8A5ULL,
		0xD721D7A2EB0A00B2ULL,
		0x37E5D6E383C58F2DULL,
		0x77C321BF951AB61DULL,
		0x6250822161ED24A3ULL,
		0x5680BD9B8D2C9C64ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD49E81CA57860FE9ULL,
		0x0C381E0D5A7470E4ULL,
		0x781EC995758103DAULL,
		0xC84B30F6ACAC844EULL,
		0x3D7FF7E01E4B2C46ULL,
		0x4149E2AE00BED9A4ULL,
		0x49954CFE5DDD1FFCULL,
		0x8B19B2DBAB215AE3ULL
	}};
	printf("Test Case 294\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x58106A4B4C6A91AEULL,
		0x1766DB396436C182ULL,
		0x8C241F7EC6722984ULL,
		0x38D9E51C33D7FB42ULL,
		0xE2CC2DF673717E20ULL,
		0x4A0BFC991320FFF7ULL,
		0x154E786DDC5C5130ULL,
		0x7C65DD565A7A68F3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC59AE5A7C3D74984ULL,
		0xC30D14B79C3D7F36ULL,
		0xC4C0F04F21890D93ULL,
		0xB190A5C8FE9D9F5FULL,
		0x04CBD465989FD1FFULL,
		0x92D56B4F7A833217ULL,
		0xF3ADDEEB125882F2ULL,
		0x01D8E85B0A566522ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9D8A8FEC8FBDD82AULL,
		0xD46BCF8EF80BBEB4ULL,
		0x48E4EF31E7FB2417ULL,
		0x894940D4CD4A641DULL,
		0xE607F993EBEEAFDFULL,
		0xD8DE97D669A3CDE0ULL,
		0xE6E3A686CE04D3C2ULL,
		0x7DBD350D502C0DD1ULL
	}};
	printf("Test Case 295\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x55FB1B517195DE70ULL,
		0x8752091E3A107273ULL,
		0x7DB4B57D546F3B1CULL,
		0x0ECA5D800D29A7D4ULL,
		0x2C33223B2FEAB5D5ULL,
		0x704FFC0B4797066BULL,
		0x7A790E3BE3C259CDULL,
		0x6613DC6B814851B0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1183A889DF8DED24ULL,
		0x4F2842B3F0839D30ULL,
		0xB323208970D35C3EULL,
		0x86BABD220530B602ULL,
		0x18CA71A35AE18A2CULL,
		0x21A911F7D2DBAF3FULL,
		0x01A8E618CD813D73ULL,
		0xC8FE5D95BD37724CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4478B3D8AE183354ULL,
		0xC87A4BADCA93EF43ULL,
		0xCE9795F424BC6722ULL,
		0x8870E0A2081911D6ULL,
		0x34F95398750B3FF9ULL,
		0x51E6EDFC954CA954ULL,
		0x7BD1E8232E4364BEULL,
		0xAEED81FE3C7F23FCULL
	}};
	printf("Test Case 296\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x17CC7FE37F767955ULL,
		0xAB6CF65FF42BAAEBULL,
		0x3D984B8F40E3D0CFULL,
		0xC4D40BA702827DDCULL,
		0x380572E9AAA18BF8ULL,
		0xC629FA03ABAA5426ULL,
		0x924A2DD36939295CULL,
		0x0FD0618ED734B88FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x422FD8F5A844476BULL,
		0xDC55C97768F6069DULL,
		0xCC4283E5504F21B2ULL,
		0x51E4F908E32769F3ULL,
		0xE81304B0C0369DD1ULL,
		0x119E230350E06E2FULL,
		0xBDA3E5CCED27CCB7ULL,
		0xA5F97DA046842285ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x55E3A716D7323E3EULL,
		0x77393F289CDDAC76ULL,
		0xF1DAC86A10ACF17DULL,
		0x9530F2AFE1A5142FULL,
		0xD01676596A971629ULL,
		0xD7B7D900FB4A3A09ULL,
		0x2FE9C81F841EE5EBULL,
		0xAA291C2E91B09A0AULL
	}};
	printf("Test Case 297\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xBB7AA0E5D2F79535ULL,
		0x10161B6B5AE060B4ULL,
		0xC82514FA3432BF36ULL,
		0xA8C43F109D16CC9FULL,
		0xA15538A5F874B005ULL,
		0x0481D206B9BD008FULL,
		0x66760E11A95835CAULL,
		0xCBB8A957EB241EC4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x184EBE115E53920CULL,
		0x1738D590B7C40AF4ULL,
		0x43BFD4CA0E0CEF24ULL,
		0x2D6F7694C02AD824ULL,
		0x2BF9C5F48038E4D8ULL,
		0x75BDF48E0D0BD377ULL,
		0x25D2DE51A32C47DFULL,
		0xA8F037FB02DC9B30ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA3341EF48CA40739ULL,
		0x072ECEFBED246A40ULL,
		0x8B9AC0303A3E5012ULL,
		0x85AB49845D3C14BBULL,
		0x8AACFD51784C54DDULL,
		0x713C2688B4B6D3F8ULL,
		0x43A4D0400A747215ULL,
		0x63489EACE9F885F4ULL
	}};
	printf("Test Case 298\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x14E4C043F3757DE3ULL,
		0xD5A2FC54928AD6D2ULL,
		0xCEA4C9D097140B52ULL,
		0x6F38A3FB240154E4ULL,
		0x3A96661EAEBA448FULL,
		0x1F5DA4FBFC47C42CULL,
		0x04B57670A3A46289ULL,
		0xF0D049F5BB168B7EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x57D84598C7880CE4ULL,
		0xD905724AFC8DA90CULL,
		0x349F6A4FAA969E00ULL,
		0xEFF86B4B16C68D4FULL,
		0xF1FF6F4B47B19E00ULL,
		0x9CA47FF9DBD7E72CULL,
		0x9C00038E2A9F18B0ULL,
		0x71F1626960ADC7F7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x433C85DB34FD7107ULL,
		0x0CA78E1E6E077FDEULL,
		0xFA3BA39F3D829552ULL,
		0x80C0C8B032C7D9ABULL,
		0xCB690955E90BDA8FULL,
		0x83F9DB0227902300ULL,
		0x98B575FE893B7A39ULL,
		0x81212B9CDBBB4C89ULL
	}};
	printf("Test Case 299\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x6569CB8B78576BF1ULL,
		0xDAFF3FD4F4B6093FULL,
		0xA359039BD2A0F881ULL,
		0xCC22D4D8971DB429ULL,
		0xB2185D58F8D3BEC5ULL,
		0x811D14138A2AE74AULL,
		0x5A885FD7038E7C1BULL,
		0x5EDA81D8D110AF5DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1801964FDB87E62DULL,
		0x55BEED94FBB35183ULL,
		0x0801AEED458E038EULL,
		0x74CDD904A70EAE09ULL,
		0xF0980302F3E548F4ULL,
		0xB7E0EE88C34D55FDULL,
		0xC9F67E6A3FA76E08ULL,
		0x367B44E8B1392116ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7D685DC4A3D08DDCULL,
		0x8F41D2400F0558BCULL,
		0xAB58AD76972EFB0FULL,
		0xB8EF0DDC30131A20ULL,
		0x42805E5A0B36F631ULL,
		0x36FDFA9B4967B2B7ULL,
		0x937E21BD3C291213ULL,
		0x68A1C53060298E4BULL
	}};
	printf("Test Case 300\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xD00E90D6E1D97773ULL,
		0x1686615E0299AE8CULL,
		0x2D30EE67CACB965EULL,
		0xC9B1B6F480EC59FBULL,
		0x77C37885633F4AB9ULL,
		0xBF70175CDFF26F47ULL,
		0xADA459E978865F89ULL,
		0xF6F7546A2F776EB9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9E6D300D769CF71AULL,
		0xF7DF800A79AA92D8ULL,
		0xDB4BD48D84690765ULL,
		0x28CE97D5DEE9EEC3ULL,
		0x9011C31B345C5000ULL,
		0xE33FB256EB7A5312ULL,
		0xE286E22AD50AAC56ULL,
		0xB41ED76BB3E3071AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4E63A0DB97458069ULL,
		0xE159E1547B333C54ULL,
		0xF67B3AEA4EA2913BULL,
		0xE17F21215E05B738ULL,
		0xE7D2BB9E57631AB9ULL,
		0x5C4FA50A34883C55ULL,
		0x4F22BBC3AD8CF3DFULL,
		0x42E983019C9469A3ULL
	}};
	printf("Test Case 301\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xE8C5BC82BC6E2228ULL,
		0x0D34599840762CF6ULL,
		0xFBD2F090ADA68CD8ULL,
		0x4A3620DA870F2D03ULL,
		0xFCE80168CF156B0FULL,
		0x557E694AEF532BB5ULL,
		0x3B37A95E593EA656ULL,
		0x4F62DE88E6D7EEC9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5D829F483BB74FB5ULL,
		0xBB7DD7719E3C54FBULL,
		0x7FFF660BEE845B57ULL,
		0x21E737A061187DC6ULL,
		0x024E0E6445E230EAULL,
		0x3A412BC1DFFB6E76ULL,
		0x18820D74334DD3B9ULL,
		0xF8FBB721C8350633ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB54723CA87D96D9DULL,
		0xB6498EE9DE4A780DULL,
		0x842D969B4322D78FULL,
		0x6BD1177AE61750C5ULL,
		0xFEA60F0C8AF75BE5ULL,
		0x6F3F428B30A845C3ULL,
		0x23B5A42A6A7375EFULL,
		0xB79969A92EE2E8FAULL
	}};
	printf("Test Case 302\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x291F9C219A90A2F1ULL,
		0x52E10D466F8C5AC8ULL,
		0x66B86E9CEB05AF48ULL,
		0x55164555C106E221ULL,
		0xAC468B5878A2BC10ULL,
		0xA503596E9ECC5991ULL,
		0x0486BB66318F0A30ULL,
		0x111B8B204ECA5716ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5CD3B8191E9697A6ULL,
		0x56D0C0544BECB5FAULL,
		0x8AAFC271C9BBE8B4ULL,
		0xD6426CFC6DA2C5A4ULL,
		0x51E19A1ACA3256E1ULL,
		0x14DA376C730D2C61ULL,
		0x28CE5915E85FE22FULL,
		0xEC184AFFA7610D6CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x75CC243884063557ULL,
		0x0431CD122460EF32ULL,
		0xEC17ACED22BE47FCULL,
		0x835429A9ACA42785ULL,
		0xFDA71142B290EAF1ULL,
		0xB1D96E02EDC175F0ULL,
		0x2C48E273D9D0E81FULL,
		0xFD03C1DFE9AB5A7AULL
	}};
	printf("Test Case 303\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x740A5953352466FDULL,
		0xF6B4A6DB7F93FBF5ULL,
		0xD56FF744866D1C16ULL,
		0xD83ECCA159D5EDD5ULL,
		0x7DECD79145A0D50CULL,
		0xD371C3E4F38D165FULL,
		0x24ED32D87FE3D09BULL,
		0x5146A8DAF407F4C9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF2C6D2D1F4919645ULL,
		0xFFA9124EC63FF7D6ULL,
		0xF9A0C6660FBC3231ULL,
		0xECC9A02D480096ADULL,
		0x568FDAD5D0A20738ULL,
		0xBA42DB4F5906506BULL,
		0x65D8774F943C8FBEULL,
		0x66F25B3516CB4B68ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x86CC8B82C1B5F0B8ULL,
		0x091DB495B9AC0C23ULL,
		0x2CCF312289D12E27ULL,
		0x34F76C8C11D57B78ULL,
		0x2B630D449502D234ULL,
		0x693318ABAA8B4634ULL,
		0x41354597EBDF5F25ULL,
		0x37B4F3EFE2CCBFA1ULL
	}};
	printf("Test Case 304\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x9E73FA0E63C6B901ULL,
		0x57C59607A56B38B2ULL,
		0x477C45B12D3A4A1FULL,
		0xBFF9CB865C337F36ULL,
		0x4CDCD5CDD1483F0EULL,
		0x9777790F56E5CEEBULL,
		0x171998D6C09F8A3EULL,
		0x32E799E1DAF48845ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3B771345C59C62F7ULL,
		0x65961A6FC6357129ULL,
		0x3915FEE2A2A4A5A8ULL,
		0x32AAA5248E05DE71ULL,
		0x927D5AE172E5D4A4ULL,
		0x07C3297474874893ULL,
		0x2879ACA2709A5343ULL,
		0x8D4E7F0B5EF569FBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA504E94BA65ADBF6ULL,
		0x32538C68635E499BULL,
		0x7E69BB538F9EEFB7ULL,
		0x8D536EA2D236A147ULL,
		0xDEA18F2CA3ADEBAAULL,
		0x90B4507B22628678ULL,
		0x3F603474B005D97DULL,
		0xBFA9E6EA8401E1BEULL
	}};
	printf("Test Case 305\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x6E2BBA3DCC0E1B95ULL,
		0xFFF924B191CB0E30ULL,
		0x1F2B2ED3E93CFFE4ULL,
		0x126E2750F0DD611AULL,
		0xA6198001522773AAULL,
		0xB00E1C670C8DB4EFULL,
		0x1431D799E9C871DDULL,
		0xEA39EC66F56B6CFBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xADB315947B318E19ULL,
		0xD655129F1C76114EULL,
		0xA2B190F41CB06C6BULL,
		0x82E99F4875F74388ULL,
		0x6E365563C5B2C969ULL,
		0x4F26FE7541599029ULL,
		0xDB32401C1596ADF6ULL,
		0xC4A9EEE251A4EDCDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC398AFA9B73F958CULL,
		0x29AC362E8DBD1F7EULL,
		0xBD9ABE27F58C938FULL,
		0x9087B818852A2292ULL,
		0xC82FD5629795BAC3ULL,
		0xFF28E2124DD424C6ULL,
		0xCF039785FC5EDC2BULL,
		0x2E900284A4CF8136ULL
	}};
	printf("Test Case 306\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x77D2288C030B2DD8ULL,
		0xA50ADB87A9154CC8ULL,
		0xD971EE654CA9C358ULL,
		0xD25A803B4C5F40A9ULL,
		0xA59BD8977E601D7EULL,
		0x0523F14E52040A61ULL,
		0xF95F56BB8C85C66FULL,
		0xF5E08DAC46178E74ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE005C0DCC4FF3CACULL,
		0xD0E9B7C452479864ULL,
		0xE24B507E23AAC89DULL,
		0x11323596AB099752ULL,
		0x088D567C0AF06E30ULL,
		0xFF448D735779207AULL,
		0x856036B982893341ULL,
		0xE6437AB048C280D1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x97D7E850C7F41174ULL,
		0x75E36C43FB52D4ACULL,
		0x3B3ABE1B6F030BC5ULL,
		0xC368B5ADE756D7FBULL,
		0xAD168EEB7490734EULL,
		0xFA677C3D057D2A1BULL,
		0x7C3F60020E0CF52EULL,
		0x13A3F71C0ED50EA5ULL
	}};
	printf("Test Case 307\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x74AF85026C09CF84ULL,
		0x3BA70C8A03505226ULL,
		0x8553A3763593430CULL,
		0x35858C42F7434531ULL,
		0x70FC6C5D8FA0AE30ULL,
		0x65F4532E6A899965ULL,
		0x39C13BB8E6E76AC9ULL,
		0x5C13064372BEB538ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4AE318E698C9314AULL,
		0x3605C5F4A102EF25ULL,
		0x7D1D3AA6F6E471C2ULL,
		0xCAC77C9868731DFCULL,
		0x98F051184F4BE8A4ULL,
		0x41601B84D96EB118ULL,
		0x1A2E49159828D004ULL,
		0x47DC10B1B0572A6CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3E4C9DE4F4C0FECEULL,
		0x0DA2C97EA252BD03ULL,
		0xF84E99D0C37732CEULL,
		0xFF42F0DA9F3058CDULL,
		0xE80C3D45C0EB4694ULL,
		0x249448AAB3E7287DULL,
		0x23EF72AD7ECFBACDULL,
		0x1BCF16F2C2E99F54ULL
	}};
	printf("Test Case 308\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xA9F23945DA52CACCULL,
		0x76EC97C4EEFD2707ULL,
		0x51CA8A203C1944FFULL,
		0x84C62619775C18F5ULL,
		0x1EA9352469BBA420ULL,
		0x6A265BADEB4FC187ULL,
		0xE7B83F47DB62F029ULL,
		0x6D0803F87CC8C9C3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBD9B3FB69EB71E46ULL,
		0x3A4415E8BD57C77DULL,
		0xDD36492224A36B90ULL,
		0x21DC4D73083EB15FULL,
		0xB56534F8B1705133ULL,
		0x07DCE73719D9688BULL,
		0xCCB3B4C11F929C26ULL,
		0x2B150B85D12C4590ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x146906F344E5D48AULL,
		0x4CA8822C53AAE07AULL,
		0x8CFCC30218BA2F6FULL,
		0xA51A6B6A7F62A9AAULL,
		0xABCC01DCD8CBF513ULL,
		0x6DFABC9AF296A90CULL,
		0x2B0B8B86C4F06C0FULL,
		0x461D087DADE48C53ULL
	}};
	printf("Test Case 309\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xEDE3DD5FF2BE2A74ULL,
		0x0722179BD24F21D6ULL,
		0x5A29D861A1717058ULL,
		0x95406B2F72E58BF5ULL,
		0xAA2BEA3F84403A54ULL,
		0x07EB17D1DCF3F3B8ULL,
		0x1570FEB467000183ULL,
		0x57184CA07CBFE519ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC7D885E4F9675EFEULL,
		0xC0A8E5C39EEAA0C7ULL,
		0xA23CD5FDEE275747ULL,
		0x6485CD296417F628ULL,
		0x8EFB26DB271FDE00ULL,
		0x9ECCAD6C3A6F9973ULL,
		0x09C733E1CF7D7301ULL,
		0x1F65CD3AA24A5CAEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2A3B58BB0BD9748AULL,
		0xC78AF2584CA58111ULL,
		0xF8150D9C4F56271FULL,
		0xF1C5A60616F27DDDULL,
		0x24D0CCE4A35FE454ULL,
		0x9927BABDE69C6ACBULL,
		0x1CB7CD55A87D7282ULL,
		0x487D819ADEF5B9B7ULL
	}};
	printf("Test Case 310\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x0BB3EF0F8919D5E8ULL,
		0x270B6E079DB2C824ULL,
		0xF858C8B92E116309ULL,
		0x3DC6A2B58E7243D3ULL,
		0x0F31A027D6A4E7EAULL,
		0x5ED01591AA64E34AULL,
		0xD1E28CC6C7DD6A7FULL,
		0x5A242207188B61A1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x40D68C0B5EE2C410ULL,
		0xD5C087AAFFEBDEF8ULL,
		0x5B5B02B1D4557D9CULL,
		0xEFF2824F9DEC259BULL,
		0x116A6A068DFFE2D4ULL,
		0x92ED7DC87449CE52ULL,
		0xC730BE98AFF17382ULL,
		0xC17BD18C1E38B322ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4B656304D7FB11F8ULL,
		0xF2CBE9AD625916DCULL,
		0xA303CA08FA441E95ULL,
		0xD23420FA139E6648ULL,
		0x1E5BCA215B5B053EULL,
		0xCC3D6859DE2D2D18ULL,
		0x16D2325E682C19FDULL,
		0x9B5FF38B06B3D283ULL
	}};
	printf("Test Case 311\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x962087B2750DEA6CULL,
		0x8863813999C793E3ULL,
		0x00FBC59B544730A2ULL,
		0x623E7070CCBDFF40ULL,
		0xF0AE088B68197489ULL,
		0x4852A4B8D0791F8AULL,
		0x52AC3AF8093E5352ULL,
		0x8037AF98D92149ADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0CDA4636BF275273ULL,
		0xC0D7FABD83FFBEEEULL,
		0xF26899D62E1F7329ULL,
		0x04D9C4E6F6D8EB36ULL,
		0x186A471EE9F8BDC2ULL,
		0x95E491C7E6C7009CULL,
		0x49DEBECBF72A1442ULL,
		0x8A9DBBC1FDC0F2BDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9AFAC184CA2AB81FULL,
		0x48B47B841A382D0DULL,
		0xF2935C4D7A58438BULL,
		0x66E7B4963A651476ULL,
		0xE8C44F9581E1C94BULL,
		0xDDB6357F36BE1F16ULL,
		0x1B728433FE144710ULL,
		0x0AAA145924E1BB10ULL
	}};
	printf("Test Case 312\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xA2F5371E9670F8F7ULL,
		0x5D3E5789608313B1ULL,
		0x801C91BCAD288530ULL,
		0x176A77EC8A75B28FULL,
		0x2EA74CE9202AF1EFULL,
		0x84BEFD00874FAF7FULL,
		0xA1783DEE3C9B3805ULL,
		0x41DFD859FC0DCD9CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3BFDB67E83913606ULL,
		0xDF076B5A160D5EA3ULL,
		0xA087C4F1141F1DFFULL,
		0x50D73D7602297647ULL,
		0x350342DD5B55F61FULL,
		0xA5612AFDA4E5281BULL,
		0x1EFBF40A473A61FEULL,
		0x2B57F98A143EA869ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9908816015E1CEF1ULL,
		0x82393CD3768E4D12ULL,
		0x209B554DB93798CFULL,
		0x47BD4A9A885CC4C8ULL,
		0x1BA40E347B7F07F0ULL,
		0x21DFD7FD23AA8764ULL,
		0xBF83C9E47BA159FBULL,
		0x6A8821D3E83365F5ULL
	}};
	printf("Test Case 313\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xF6042279B054DD84ULL,
		0x4F835169DBDB0AB7ULL,
		0x2381BA1C6B2AD3B2ULL,
		0x54CBB2E759E20D08ULL,
		0x57B9AE7463F569C9ULL,
		0x733F610C45F7DF7EULL,
		0x7BE9364D93B49506ULL,
		0xA82DA31FA21DA05CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCD40146F871C46CCULL,
		0xB348294D984E14FEULL,
		0xCEEEDC1CE048E334ULL,
		0x4F3F5FC6E4F707D6ULL,
		0x98FE8BF06A3C0981ULL,
		0x69976C3AACD9C921ULL,
		0xC258D60DEFF51CBDULL,
		0x7F73198E49177000ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3B44361637489B48ULL,
		0xFCCB782443951E49ULL,
		0xED6F66008B623086ULL,
		0x1BF4ED21BD150ADEULL,
		0xCF47258409C96048ULL,
		0x1AA80D36E92E165FULL,
		0xB9B1E0407C4189BBULL,
		0xD75EBA91EB0AD05CULL
	}};
	printf("Test Case 314\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x57D20749AB35470CULL,
		0x82E92A8400C8CC28ULL,
		0x14956EE2FBAABBBCULL,
		0xE1CF2CBE91740BE8ULL,
		0x297A3C6D69DB073FULL,
		0xA0322AAFFF1EB0D0ULL,
		0xA8C002A59212A5E6ULL,
		0xF39F7E9453ACD6A7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x565E4AF23D70410AULL,
		0xD2BA405CE1D7D89EULL,
		0x0454E4F68080AE3FULL,
		0x017DEFBAF0BED7C3ULL,
		0x87DE191902D3DC0EULL,
		0xD327926180C34F5CULL,
		0xEFA2FCDA1D7A2421ULL,
		0x412ACFAE19B0B687ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x018C4DBB96450606ULL,
		0x50536AD8E11F14B6ULL,
		0x10C18A147B2A1583ULL,
		0xE0B2C30461CADC2BULL,
		0xAEA425746B08DB31ULL,
		0x7315B8CE7FDDFF8CULL,
		0x4762FE7F8F6881C7ULL,
		0xB2B5B13A4A1C6020ULL
	}};
	printf("Test Case 315\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x22BA9A5FFAF26A5FULL,
		0x9974AFC963DB9805ULL,
		0xCB04245E79F1BB25ULL,
		0x6AE16F422522EC71ULL,
		0x3EB3870A998412F2ULL,
		0xC8252F8E9CAA3CC5ULL,
		0x8756144188017F37ULL,
		0x3C71DAA9892CE973ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x385D4B5622483733ULL,
		0x5C84063812228639ULL,
		0x301652DA6E67317DULL,
		0xD3DFD2E7EEC7CC48ULL,
		0x5D40AA660016F81EULL,
		0xAFA08B8E5E4D225AULL,
		0xE4B694B83D4DB75BULL,
		0xAAE6DB467BFF00CBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1AE7D109D8BA5D6CULL,
		0xC5F0A9F171F91E3CULL,
		0xFB12768417968A58ULL,
		0xB93EBDA5CBE52039ULL,
		0x63F32D6C9992EAECULL,
		0x6785A400C2E71E9FULL,
		0x63E080F9B54CC86CULL,
		0x969701EFF2D3E9B8ULL
	}};
	printf("Test Case 316\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x5F72951E8CC4882AULL,
		0x0FAE12E98145C6A0ULL,
		0xD100C51837D07BA0ULL,
		0x72F567577161D5BAULL,
		0x6945409FF19F40D6ULL,
		0xAA8962D038060ACCULL,
		0xD2B8A0B8F3793039ULL,
		0x22EBA03D4E729A58ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x24411C6924A44C55ULL,
		0x289A3F1C084FD80BULL,
		0x77A79BF932AE3700ULL,
		0x05332E8E65D2AE4DULL,
		0xE8FB7A63F9AA7760ULL,
		0xAB1B428696BC51B4ULL,
		0x39737FBB9B79497DULL,
		0x47C8F7E0B181726AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7B338977A860C47FULL,
		0x27342DF5890A1EABULL,
		0xA6A75EE1057E4CA0ULL,
		0x77C649D914B37BF7ULL,
		0x81BE3AFC083537B6ULL,
		0x01922056AEBA5B78ULL,
		0xEBCBDF0368007944ULL,
		0x652357DDFFF3E832ULL
	}};
	printf("Test Case 317\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x44B917D099024B51ULL,
		0xF8DB63420F8CB4AFULL,
		0x5BC35166C552C2ACULL,
		0xD8DFDC18844FA9F1ULL,
		0x66CD69EF8BDE735DULL,
		0x81BA55EE9D95F358ULL,
		0x8B49E702B9798F67ULL,
		0x64A57AF761CB4574ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x017A02E589737196ULL,
		0x3190180EFEDDF7EEULL,
		0x80C816C2F0AAE168ULL,
		0x7A8A09FBEF63F858ULL,
		0x72F75BCAF579C4EDULL,
		0xF8A017FA26EAFDD6ULL,
		0x950EE81EDDAA4291ULL,
		0x9BE9F4CEA62ACF10ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x45C3153510713AC7ULL,
		0xC94B7B4CF1514341ULL,
		0xDB0B47A435F823C4ULL,
		0xA255D5E36B2C51A9ULL,
		0x143A32257EA7B7B0ULL,
		0x791A4214BB7F0E8EULL,
		0x1E470F1C64D3CDF6ULL,
		0xFF4C8E39C7E18A64ULL
	}};
	printf("Test Case 318\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x9898A51459127DEEULL,
		0x3DCFAB4EC7268797ULL,
		0xA5EC305FB8F767B3ULL,
		0xCD84A8245135473FULL,
		0x6755BC5FA306DCB7ULL,
		0x041C160A60426887ULL,
		0x8F2092B21940D47EULL,
		0xC4B4A3C2833AD961ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAEBE4AC3849B2714ULL,
		0xC05503FB2A05AC28ULL,
		0x4CBFE900D1FA40D1ULL,
		0x606569C63ED5179CULL,
		0xA7DA38DF729621CFULL,
		0x6D919EA4475A5B2CULL,
		0xAE793B7F0E211B76ULL,
		0xAEFF0E181BFF35BFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3626EFD7DD895AFAULL,
		0xFD9AA8B5ED232BBFULL,
		0xE953D95F690D2762ULL,
		0xADE1C1E26FE050A3ULL,
		0xC08F8480D190FD78ULL,
		0x698D88AE271833ABULL,
		0x2159A9CD1761CF08ULL,
		0x6A4BADDA98C5ECDEULL
	}};
	printf("Test Case 319\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xB6D22E0E34308D1EULL,
		0xAA16E7D8DB0B1A50ULL,
		0x3743E06D0E690646ULL,
		0x5ED32288203D8712ULL,
		0xFD1581096DC42911ULL,
		0x184117455A318C4BULL,
		0x8D4AAA1B32049D43ULL,
		0xD1E310D030542901ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0BB4FAAE58F244A6ULL,
		0xE36DC54F4E61F409ULL,
		0x98C6E4B868926DB9ULL,
		0xB8558256965C4A09ULL,
		0x3F2E599BBBE30DD2ULL,
		0x3B29739D7ECADFF8ULL,
		0x6E58244F966EA60FULL,
		0x8DFCFE186CE5F9B7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBD66D4A06CC2C9B8ULL,
		0x497B2297956AEE59ULL,
		0xAF8504D566FB6BFFULL,
		0xE686A0DEB661CD1BULL,
		0xC23BD892D62724C3ULL,
		0x236864D824FB53B3ULL,
		0xE3128E54A46A3B4CULL,
		0x5C1FEEC85CB1D0B6ULL
	}};
	printf("Test Case 320\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x3F3DC870F2B82151ULL,
		0xA1357723713F6CAEULL,
		0xE61E40731A4CDD84ULL,
		0xA9DC7D0D0BA0A25BULL,
		0x206383C7EA7BCB64ULL,
		0xD04899E5CE4D8003ULL,
		0x856BD7619FB724BBULL,
		0x45C21F8BC414FDB9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC7CCBF9D70502E73ULL,
		0xE84B428198174272ULL,
		0x057385D1FB1267C9ULL,
		0x4CA054EBED11C779ULL,
		0x8FCEAD6827DCEDF9ULL,
		0x7680A7AB1590876EULL,
		0x0B9883067EA9256CULL,
		0x8CB2F0C0A1986C91ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF8F177ED82E80F22ULL,
		0x497E35A2E9282EDCULL,
		0xE36DC5A2E15EBA4DULL,
		0xE57C29E6E6B16522ULL,
		0xAFAD2EAFCDA7269DULL,
		0xA6C83E4EDBDD076DULL,
		0x8EF35467E11E01D7ULL,
		0xC970EF4B658C9128ULL
	}};
	printf("Test Case 321\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x771C1B38D0A44BEFULL,
		0x678DAC90A7196F8AULL,
		0x60F353AF62151E8BULL,
		0x73A7EDF6B7BCEC7DULL,
		0x74B42B151F5D76ABULL,
		0x5F0FBDBF8AFBD09BULL,
		0xD5492DDAB02B9FDAULL,
		0xEBF819BF5627632CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6EBD44FF77A6E7CFULL,
		0x7EFADB6C0E0765C4ULL,
		0x18EC97E0195E2E2BULL,
		0x317DDF5C69A54293ULL,
		0xF182E01D82CFA534ULL,
		0xE95F844D4A2D4CF9ULL,
		0xF70F59FD836E74D6ULL,
		0xAF56B522CCD6DEE7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x19A15FC7A702AC20ULL,
		0x197777FCA91E0A4EULL,
		0x781FC44F7B4B30A0ULL,
		0x42DA32AADE19AEEEULL,
		0x8536CB089D92D39FULL,
		0xB65039F2C0D69C62ULL,
		0x224674273345EB0CULL,
		0x44AEAC9D9AF1BDCBULL
	}};
	printf("Test Case 322\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x077E82F485EF8DD6ULL,
		0x10E189365642D884ULL,
		0x9B81F875D9B6B538ULL,
		0xF5F6461B1ACEFA91ULL,
		0x79439EF17C96D60BULL,
		0x6C15CF8A0DD7AE6BULL,
		0x072FA57EB3921118ULL,
		0x7EBC1A42DF1D4EFCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD2DEFC8E1B40F065ULL,
		0x8855C23297DB3531ULL,
		0xB85DEC3F1607840FULL,
		0x528645773B584B18ULL,
		0xC83E7DA8E93DED2CULL,
		0x2E92B9872FC48F34ULL,
		0x89C4835C295C7250ULL,
		0x64370CF5C8C1CCD3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD5A07E7A9EAF7DB3ULL,
		0x98B44B04C199EDB5ULL,
		0x23DC144ACFB13137ULL,
		0xA770036C2196B189ULL,
		0xB17DE35995AB3B27ULL,
		0x4287760D2213215FULL,
		0x8EEB26229ACE6348ULL,
		0x1A8B16B717DC822FULL
	}};
	printf("Test Case 323\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x3ADB12A71B6FC47EULL,
		0x47F002C16809142FULL,
		0xF244917603462ADDULL,
		0xB305071D7122704CULL,
		0x4F3AF1B93E2F91A1ULL,
		0x5F10E724E09EB9ABULL,
		0x111A462F2B309E17ULL,
		0xE70619DE32DFB088ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF77F44EFD6D8FEA0ULL,
		0x742AD9D7645C0DEBULL,
		0x041FB6CB7739EE49ULL,
		0xE60552848AC52CFEULL,
		0xE2DE36A7CB85EB0CULL,
		0x125BB4D028F96A5CULL,
		0x424FD2BD7EC6002DULL,
		0x600CEF21B45B0EB3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCDA45648CDB73ADEULL,
		0x33DADB160C5519C4ULL,
		0xF65B27BD747FC494ULL,
		0x55005599FBE75CB2ULL,
		0xADE4C71EF5AA7AADULL,
		0x4D4B53F4C867D3F7ULL,
		0x5355949255F69E3AULL,
		0x870AF6FF8684BE3BULL
	}};
	printf("Test Case 324\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x6B2D18DA7BE95098ULL,
		0xE86271C995C38267ULL,
		0x2A883F16D56AC237ULL,
		0x4190F79B5B557EE6ULL,
		0x277F922D97A2C0C1ULL,
		0x0A180DDEEC12B120ULL,
		0x30B476B37DEC9179ULL,
		0xC781A112CC8B7C8EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFAE4E61E0291586FULL,
		0x5DB56EB29D9D6D97ULL,
		0x1F27DD0F6279EAE9ULL,
		0xDCEEE461A0D0A832ULL,
		0x27ABB5C55618633CULL,
		0x31E699DD25041F2AULL,
		0x5070D5A9BCF28441ULL,
		0xF83796DC782331E7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x91C9FEC4797808F7ULL,
		0xB5D71F7B085EEFF0ULL,
		0x35AFE219B71328DEULL,
		0x9D7E13FAFB85D6D4ULL,
		0x00D427E8C1BAA3FDULL,
		0x3BFE9403C916AE0AULL,
		0x60C4A31AC11E1538ULL,
		0x3FB637CEB4A84D69ULL
	}};
	printf("Test Case 325\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xF5CDE40095694B7BULL,
		0xA209074B3214D8FDULL,
		0x27620DBCB779B389ULL,
		0xC58D25AFE772EBD1ULL,
		0xEEEC9536991C2194ULL,
		0x899C53D18798A17DULL,
		0xE49B5C6334F77296ULL,
		0x4E9CC6CDCA42BA79ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDB817D49B9DA0CF9ULL,
		0xBEBBDD2596A8DF67ULL,
		0x3CC76DC77AB76AD4ULL,
		0xA4B365701C6EB2AAULL,
		0x0FED2CA2BAEE702CULL,
		0x00A59E647C05975DULL,
		0x2440051B70495504ULL,
		0x0CB8D9D9977CCD75ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2E4C99492CB34782ULL,
		0x1CB2DA6EA4BC079AULL,
		0x1BA5607BCDCED95DULL,
		0x613E40DFFB1C597BULL,
		0xE101B99423F251B8ULL,
		0x8939CDB5FB9D3620ULL,
		0xC0DB597844BE2792ULL,
		0x42241F145D3E770CULL
	}};
	printf("Test Case 326\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x3E5BE7ECE1F314FAULL,
		0x419F18C72DD692ADULL,
		0xB199BA3CE9C361F5ULL,
		0x69A5DDBAA9EC5E02ULL,
		0xE1B044A3D3DF93ECULL,
		0xD2E0D7E9AC296FE7ULL,
		0x484F0CADED1203F1ULL,
		0xBAD6A1FDB3670155ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF981B0B70AF7136ULL,
		0xE23E00687D77574DULL,
		0x64725ABD2562EDC3ULL,
		0x555450246048989EULL,
		0xDD51C8E95977212CULL,
		0x199305BF3A76667EULL,
		0x01CD047BC0F68C89ULL,
		0xD999B707856E7026ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x91C3FCE7915C65CCULL,
		0xA3A118AF50A1C5E0ULL,
		0xD5EBE081CCA18C36ULL,
		0x3CF18D9EC9A4C69CULL,
		0x3CE18C4A8AA8B2C0ULL,
		0xCB73D256965F0999ULL,
		0x498208D62DE48F78ULL,
		0x634F16FA36097173ULL
	}};
	printf("Test Case 327\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x385A2323D5E69A0FULL,
		0x3E13DDCF8ED127A9ULL,
		0x2FBE80FEB093212BULL,
		0xDC1E4C2BF94B3B21ULL,
		0x58EF85E978E8C015ULL,
		0xBF16A4B8D9C4C4ACULL,
		0xCEFA3F524C93DAB4ULL,
		0x322065F236702401ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x48CBA99B26069A66ULL,
		0xFEFD212D9F548498ULL,
		0x286EF134F0C7E9F6ULL,
		0xB1B36E8F623FFEC1ULL,
		0x7E014B17EDC9D271ULL,
		0x686E5464CE221DD9ULL,
		0x09772226AD3AAEC1ULL,
		0xBA8F051914729FCAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x70918AB8F3E00069ULL,
		0xC0EEFCE21185A331ULL,
		0x07D071CA4054C8DDULL,
		0x6DAD22A49B74C5E0ULL,
		0x26EECEFE95211264ULL,
		0xD778F0DC17E6D975ULL,
		0xC78D1D74E1A97475ULL,
		0x88AF60EB2202BBCBULL
	}};
	printf("Test Case 328\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x7089A4C1757EF59EULL,
		0xB1CE1BA0D419425FULL,
		0x44A25ACC8C4C231BULL,
		0xA479BD2EAAE52901ULL,
		0xA96741F55E63989BULL,
		0x2F4E47CE6341AAAFULL,
		0xC419AF0EED6C97D5ULL,
		0x1798A99BA385523DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x06918CE36959D80DULL,
		0xE0056F259A22EF69ULL,
		0x37CB2458F16C49F7ULL,
		0xA4755DC3C2823BC4ULL,
		0x975DBE6F8F645F18ULL,
		0x3E15B6E3E5584980ULL,
		0xD61A4E2675AF11ABULL,
		0x1ABB3E7903171EA5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x761828221C272D93ULL,
		0x51CB74854E3BAD36ULL,
		0x73697E947D206AECULL,
		0x000CE0ED686712C5ULL,
		0x3E3AFF9AD107C783ULL,
		0x115BF12D8619E32FULL,
		0x1203E12898C3867EULL,
		0x0D2397E2A0924C98ULL
	}};
	printf("Test Case 329\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xFC16EC297410F2FAULL,
		0xB71F068D241AA545ULL,
		0xDFEA6438D881427BULL,
		0xE3E8018CF49B5A2CULL,
		0xED61748EA4650C7EULL,
		0x47454D10B3D7073CULL,
		0xAFF864B79014586CULL,
		0x66C06352FDF51643ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5BE19D2E5BBBC923ULL,
		0xFEECA9410B88E5ADULL,
		0x512B056A0B346D2AULL,
		0x1CAA0A0C88BA30A2ULL,
		0xD43C40E84C85583CULL,
		0xC566FEB72FF77279ULL,
		0x4D7164981087EF10ULL,
		0x77A5643A276E5576ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA7F771072FAB3BD9ULL,
		0x49F3AFCC2F9240E8ULL,
		0x8EC16152D3B52F51ULL,
		0xFF420B807C216A8EULL,
		0x395D3466E8E05442ULL,
		0x8223B3A79C207545ULL,
		0xE289002F8093B77CULL,
		0x11650768DA9B4335ULL
	}};
	printf("Test Case 330\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x635B837D3E48ED20ULL,
		0x247F6FBE4B836AF5ULL,
		0x6FC72CAC49A7BD8BULL,
		0x4BF645AD1FC704D5ULL,
		0xDDA137857A6E9152ULL,
		0x67803675A8A204C4ULL,
		0x8A04051239122BD0ULL,
		0x9148F797CB694653ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x57E0178E97663A2DULL,
		0x6F80DBA61D8F9EACULL,
		0x5F61DCD3F90C39A8ULL,
		0xF3D1ACBD7855263EULL,
		0xB5510698996F768EULL,
		0x430851A84BBD0BBCULL,
		0xDFC564688BD60F0CULL,
		0xCAB3FF6D5E50F011ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x34BB94F3A92ED70DULL,
		0x4BFFB418560CF459ULL,
		0x30A6F07FB0AB8423ULL,
		0xB827E910679222EBULL,
		0x68F0311DE301E7DCULL,
		0x248867DDE31F0F78ULL,
		0x55C1617AB2C424DCULL,
		0x5BFB08FA9539B642ULL
	}};
	printf("Test Case 331\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xD9852BC59C2D52ECULL,
		0xA705F2742B7AEDF1ULL,
		0xBEAFC3FC5BAFC215ULL,
		0x828BF9111602D8B9ULL,
		0x6B3A5262FABBBFD1ULL,
		0xD68DA44E4137806DULL,
		0xAAE1973A32983943ULL,
		0xE4217436DFA278CAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB1FB771305ACBCE4ULL,
		0x2CFCCD005C684342ULL,
		0xF35C6FE786A6ED13ULL,
		0xAB602854244A911FULL,
		0x5C7BAC07F5EC141DULL,
		0x981A76A44D5A87DBULL,
		0xD15FDEB3D72BEF3DULL,
		0x1FDDCA3254FA6D0DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x687E5CD69981EE08ULL,
		0x8BF93F747712AEB3ULL,
		0x4DF3AC1BDD092F06ULL,
		0x29EBD145324849A6ULL,
		0x3741FE650F57ABCCULL,
		0x4E97D2EA0C6D07B6ULL,
		0x7BBE4989E5B3D67EULL,
		0xFBFCBE048B5815C7ULL
	}};
	printf("Test Case 332\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x7BA001DE85843CD4ULL,
		0x42D0CEE9E8D5ED20ULL,
		0xB23952D0A30833D9ULL,
		0x4A9B4C14C0272EE8ULL,
		0x38DFC16225CB3AD1ULL,
		0xE2150B4ECB833BF7ULL,
		0xD7FB6F1F1D1C3D10ULL,
		0xAB56BCBF78D2E3EDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC8A2C1E8A4A73F90ULL,
		0x4C6EDC6128ED7E55ULL,
		0x01D7AB0063CB626CULL,
		0xDECF6319CECC92DBULL,
		0xC4E89603AD45F0EAULL,
		0x43744E7F874956E6ULL,
		0x0ED28E0C797EA89DULL,
		0xF718F2DC0E0BC90CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB302C03621230344ULL,
		0x0EBE1288C0389375ULL,
		0xB3EEF9D0C0C351B5ULL,
		0x94542F0D0EEBBC33ULL,
		0xFC375761888ECA3BULL,
		0xA16145314CCA6D11ULL,
		0xD929E1136462958DULL,
		0x5C4E4E6376D92AE1ULL
	}};
	printf("Test Case 333\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x6365250C7BB56CB9ULL,
		0x36A4053C4EE65B08ULL,
		0x5A4708FC61FFCE16ULL,
		0xB8943DA7B18AA286ULL,
		0x33E5AC4B1A2597F4ULL,
		0x2FB2BA1E773C81BAULL,
		0x23B4192B2757D7DEULL,
		0x622D13D78D0282F1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x337543DC5E9CD84EULL,
		0x659F6351EDE53CAEULL,
		0x1DEA15F0BF362E4AULL,
		0xD78AFAD4E0E74EB1ULL,
		0x3F30AD0B2C137F7CULL,
		0x3A9621E593AD680BULL,
		0x0D991BA3421EFE30ULL,
		0x9519AB59C10F7B28ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x501066D02529B4F7ULL,
		0x533B666DA30367A6ULL,
		0x47AD1D0CDEC9E05CULL,
		0x6F1EC773516DEC37ULL,
		0x0CD501403636E888ULL,
		0x15249BFBE491E9B1ULL,
		0x2E2D0288654929EEULL,
		0xF734B88E4C0DF9D9ULL
	}};
	printf("Test Case 334\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xD9C25AF1BAF6A90EULL,
		0xD3D9F94F8ABF707EULL,
		0x93052C2A37B7DFA0ULL,
		0x99AB3CF14AB66E54ULL,
		0x1BB9ED2B553D6EE0ULL,
		0x0580B33095827051ULL,
		0xC45C837FDBCA8A39ULL,
		0x138D2A8B7408808DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB3C60C9CC323691CULL,
		0xADCA1E79221A957FULL,
		0x4EFE7B67FD2C8A6DULL,
		0x2161C316B8E9F6D5ULL,
		0xE8165D35E4EC2FC7ULL,
		0xDE8E1DFB1D5D5FFEULL,
		0x071DD343101F2F5AULL,
		0x973CF7D0BADC121BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6A04566D79D5C012ULL,
		0x7E13E736A8A5E501ULL,
		0xDDFB574DCA9B55CDULL,
		0xB8CAFFE7F25F9881ULL,
		0xF3AFB01EB1D14127ULL,
		0xDB0EAECB88DF2FAFULL,
		0xC341503CCBD5A563ULL,
		0x84B1DD5BCED49296ULL
	}};
	printf("Test Case 335\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x4DEFC4B5BE59DD0DULL,
		0x7A618F624A4E80ACULL,
		0xAF792E721BEA51FFULL,
		0x55A94DAFAB023F52ULL,
		0x1F741B8811655CA6ULL,
		0x5DE7447EF5C0E0F3ULL,
		0x4A3922EBDB2C9BA4ULL,
		0x6AEF52313277B0F6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCCA47384E778D637ULL,
		0x08333B34318FE81FULL,
		0x234788085B25B722ULL,
		0x7B8A0C1FD28273B8ULL,
		0x462009CA269D69A3ULL,
		0x7BBBFD9C90F03D12ULL,
		0x9565B5243C64DB2AULL,
		0x1BE87584E0A354CDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x814BB73159210B3AULL,
		0x7252B4567BC168B3ULL,
		0x8C3EA67A40CFE6DDULL,
		0x2E2341B079804CEAULL,
		0x5954124237F83505ULL,
		0x265CB9E26530DDE1ULL,
		0xDF5C97CFE748408EULL,
		0x710727B5D2D4E43BULL
	}};
	printf("Test Case 336\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x8486D64D7B2E9397ULL,
		0xE83255AE633A7604ULL,
		0x2D4790CE0461153CULL,
		0xAC19EE118074EC36ULL,
		0x1F16AB4BE61AFF2AULL,
		0xD4A3EF5E1F604FC7ULL,
		0x87D270F17BB66541ULL,
		0xA3130665924ADA93ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1A1A251E6C463FEEULL,
		0xCE9EE996F332B594ULL,
		0x7BEAD00D00ED4DA6ULL,
		0x783B31BC21FF971BULL,
		0x2EC20B2B9ACF4FF4ULL,
		0x6F05EC00CE40B13FULL,
		0xBAC9B835E99CD968ULL,
		0xAFDE19A3EFC6E539ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9E9CF3531768AC79ULL,
		0x26ACBC389008C390ULL,
		0x56AD40C3048C589AULL,
		0xD422DFADA18B7B2DULL,
		0x31D4A0607CD5B0DEULL,
		0xBBA6035ED120FEF8ULL,
		0x3D1BC8C4922ABC29ULL,
		0x0CCD1FC67D8C3FAAULL
	}};
	printf("Test Case 337\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x6BB9436674BFB23FULL,
		0x85702886E62552EFULL,
		0x08BAFBFBE7038513ULL,
		0x0A4D1D680831CE08ULL,
		0xF59C883C7F71F6FAULL,
		0x3147E5A540D0270DULL,
		0xC8E49E512A8919A1ULL,
		0xFB71461D90D63AF3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEC1F0121E4241383ULL,
		0x04690EE0151A29DDULL,
		0x0A416E66F71D7A23ULL,
		0xFF725F8CA779D57AULL,
		0xAE1EFB6E0493786AULL,
		0xEA21DF832F592410ULL,
		0x1A6CFF9651A53B98ULL,
		0x8B5780B5F91B2F9BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x87A64247909BA1BCULL,
		0x81192666F33F7B32ULL,
		0x02FB959D101EFF30ULL,
		0xF53F42E4AF481B72ULL,
		0x5B8273527BE28E90ULL,
		0xDB663A266F89031DULL,
		0xD28861C77B2C2239ULL,
		0x7026C6A869CD1568ULL
	}};
	printf("Test Case 338\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x515228C5780B242DULL,
		0xD5BEA6560EE02E0EULL,
		0x1B9D90D5A031E17FULL,
		0x3DB148EEDDD5D4A6ULL,
		0x95DE34FADAD2BA37ULL,
		0xA3DC1877F6CC83A9ULL,
		0xC3D7BC3C4CB11EF9ULL,
		0x2AE47BD5528C8B14ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6FD1E61F9074F4C2ULL,
		0xAFA56188CE856D71ULL,
		0x2949FCC4D6C5D542ULL,
		0x1FD31F37C28FF44BULL,
		0xEC86AAC674625547ULL,
		0xA929EE041B5DF9B1ULL,
		0xD0EA22741AF35C08ULL,
		0x6AB6CD97BB5BC420ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3E83CEDAE87FD0EFULL,
		0x7A1BC7DEC065437FULL,
		0x32D46C1176F4343DULL,
		0x226257D91F5A20EDULL,
		0x79589E3CAEB0EF70ULL,
		0x0AF5F673ED917A18ULL,
		0x133D9E48564242F1ULL,
		0x4052B642E9D74F34ULL
	}};
	printf("Test Case 339\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xB349362042E7B6BCULL,
		0x1C7864252AF389FAULL,
		0xE403691359C4BD0AULL,
		0x3BAE19AC341FE0F2ULL,
		0x4A25A984763A5CF8ULL,
		0xCB6125B1E440ACC9ULL,
		0x65B8C0BE29D58E8CULL,
		0x22B8B48F741FECF6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x83FD7D162E30FF72ULL,
		0x3179C7E57808AB16ULL,
		0xF17114AB5B0AA4F8ULL,
		0x633AE62D4A437F9EULL,
		0x06FE1D1F3F293490ULL,
		0x495B1DC695AC7AFAULL,
		0xE44C05798FB9530AULL,
		0x9107B270697B5F41ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x30B44B366CD749CEULL,
		0x2D01A3C052FB22ECULL,
		0x15727DB802CE19F2ULL,
		0x5894FF817E5C9F6CULL,
		0x4CDBB49B49136868ULL,
		0x823A387771ECD633ULL,
		0x81F4C5C7A66CDD86ULL,
		0xB3BF06FF1D64B3B7ULL
	}};
	printf("Test Case 340\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x295A9A6AB057FF1AULL,
		0xB0B713BF1CCB70A1ULL,
		0x2641927F5ECA3C28ULL,
		0x42F7601ABC8C5497ULL,
		0xBA22E1E9DC666AF9ULL,
		0x340A309C0DA66D2EULL,
		0x2985A9AF34AE4020ULL,
		0x29669A31BEF55BF0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x059F12F0C65F3EEEULL,
		0xABDF67998E085BEEULL,
		0xEDE0EDAFB0FA8236ULL,
		0x2E1A3AF65A3624BDULL,
		0x6B33BC16E9BC3FF9ULL,
		0x7C0513D88135F20CULL,
		0xB10FD2B1AF39F004ULL,
		0x5FA95887B97A60FEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2CC5889A7608C1F4ULL,
		0x1B68742692C32B4FULL,
		0xCBA17FD0EE30BE1EULL,
		0x6CED5AECE6BA702AULL,
		0xD1115DFF35DA5500ULL,
		0x480F23448C939F22ULL,
		0x988A7B1E9B97B024ULL,
		0x76CFC2B6078F3B0EULL
	}};
	printf("Test Case 341\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x69120604BE4619B5ULL,
		0xE1D6B6F836A8D55CULL,
		0xF10BFE6E456FB4BEULL,
		0xEF8EBFE4AE0F6F7BULL,
		0xCD612951356356CDULL,
		0x100374E9F2E2FDAEULL,
		0x3BB88CFF7AEB4AE0ULL,
		0x54B676F018E4E6D2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3896B020B313B7F9ULL,
		0x3ED2B7C36B9EB388ULL,
		0xE187D309C1862F4FULL,
		0x4E0B5EFAF3EA6DC2ULL,
		0x01E54B994E406611ULL,
		0xCB9A47E4553A3587ULL,
		0xCB95BA11B40C9529ULL,
		0x3D3587431DF17692ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5184B6240D55AE4CULL,
		0xDF04013B5D3666D4ULL,
		0x108C2D6784E99BF1ULL,
		0xA185E11E5DE502B9ULL,
		0xCC8462C87B2330DCULL,
		0xDB99330DA7D8C829ULL,
		0xF02D36EECEE7DFC9ULL,
		0x6983F1B305159040ULL
	}};
	printf("Test Case 342\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x834F5095934B6B43ULL,
		0xFB1CB8521C7F0CD3ULL,
		0xA88BEB7AAB66C14AULL,
		0x2E831A9D045018CCULL,
		0xCB76A124D1028AB6ULL,
		0x73178CB0B08FD07EULL,
		0x44FA2B0CA1A70DEAULL,
		0xF995AE51ABD75A47ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x466803A73E5D40F3ULL,
		0x3B58F5393E0223D4ULL,
		0x6A1A1CB153CD5B6DULL,
		0x3D47BC66228ED175ULL,
		0x2AC3B92728A81341ULL,
		0x6A4124396E9D9C63ULL,
		0x6AF725056DBACF11ULL,
		0x3277F8A5787A1DEAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC5275332AD162BB0ULL,
		0xC0444D6B227D2F07ULL,
		0xC291F7CBF8AB9A27ULL,
		0x13C4A6FB26DEC9B9ULL,
		0xE1B51803F9AA99F7ULL,
		0x1956A889DE124C1DULL,
		0x2E0D0E09CC1DC2FBULL,
		0xCBE256F4D3AD47ADULL
	}};
	printf("Test Case 343\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xDAB06D37864C4176ULL,
		0x28EB3F65EC603F48ULL,
		0x419C1D038887AAE2ULL,
		0xB2275852A33B93AEULL,
		0x6EC7AA6288A6BABEULL,
		0x465968BDCB4AEB2FULL,
		0x937B611A405F8147ULL,
		0x4B10D6D91BDDEF90ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x265E41DDCDC71275ULL,
		0xA15A0E5F289C552EULL,
		0xA849EEDA0DF48276ULL,
		0x0A038080CF03C7CEULL,
		0xEEC23D8FBE1C8540ULL,
		0x72533252AFAE82BCULL,
		0x08AE4E52BFF737A9ULL,
		0x9C31ADEF2C06DD70ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFCEE2CEA4B8B5303ULL,
		0x89B1313AC4FC6A66ULL,
		0xE9D5F3D985732894ULL,
		0xB824D8D26C385460ULL,
		0x800597ED36BA3FFEULL,
		0x340A5AEF64E46993ULL,
		0x9BD52F48FFA8B6EEULL,
		0xD7217B3637DB32E0ULL
	}};
	printf("Test Case 344\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xAF2E6C7BD7E0C6ECULL,
		0x41EE7B909AE4288BULL,
		0xDCB3C880EEE9BED1ULL,
		0x7FF461BAFB6CDF65ULL,
		0x687430A5119C0A65ULL,
		0xEF282F5BB32710E0ULL,
		0x30B5206A932E6943ULL,
		0x57A84CF0254DF5C6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD3E05C0264FBF066ULL,
		0x9A7823B662C0729CULL,
		0xE5025D9D5FB8E3B3ULL,
		0x46FF0172C40150D5ULL,
		0x71F9A457F63C077FULL,
		0x2312869FAC4ECB51ULL,
		0x04FA72CCD445F353ULL,
		0xBC3EC530F31FEBF9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7CCE3079B31B368AULL,
		0xDB965826F8245A17ULL,
		0x39B1951DB1515D62ULL,
		0x390B60C83F6D8FB0ULL,
		0x198D94F2E7A00D1AULL,
		0xCC3AA9C41F69DBB1ULL,
		0x344F52A6476B9A10ULL,
		0xEB9689C0D6521E3FULL
	}};
	printf("Test Case 345\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x08CBAA806B01DB10ULL,
		0x6D4B724899DA7D93ULL,
		0xD7C4DB961ADCB6DDULL,
		0xAFB1C814A7EFDCA5ULL,
		0x926FC32F97EA856DULL,
		0x47A97C6272D8A552ULL,
		0x9EAF102DE93BD84FULL,
		0x4F2C7C94D640A0E2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x136676CBDE0C53F7ULL,
		0x932E1896DA91EB98ULL,
		0x5E7F4F33BC790D58ULL,
		0x47D6464B742BE042ULL,
		0xD9AA49B4A57D2527ULL,
		0xA3D3A4F8D087290AULL,
		0x91CAF99BF3C1DA81ULL,
		0x9B2BAFB04DE0C092ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1BADDC4BB50D88E7ULL,
		0xFE656ADE434B960BULL,
		0x89BB94A5A6A5BB85ULL,
		0xE8678E5FD3C43CE7ULL,
		0x4BC58A9B3297A04AULL,
		0xE47AD89AA25F8C58ULL,
		0x0F65E9B61AFA02CEULL,
		0xD407D3249BA06070ULL
	}};
	printf("Test Case 346\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x07764B23900F337BULL,
		0xF115398473D51B35ULL,
		0x9DCEC573C957947EULL,
		0x46EB5D39DBD60B36ULL,
		0x7FDEDEB3B0BCCEA2ULL,
		0x2241EFF5888BE048ULL,
		0xCA72F2BB225CE4D7ULL,
		0xF7C9B33071026690ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA46A7FA57C956866ULL,
		0x92A23711D8C686BCULL,
		0x7E7154F1B09C5006ULL,
		0x9F8A0646DE7A5DFAULL,
		0x4C23C76132DA9928ULL,
		0xBEEE9429D50EF35EULL,
		0xE4BB3731D7AFC374ULL,
		0x2573698B5E8AA546ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA31C3486EC9A5B1DULL,
		0x63B70E95AB139D89ULL,
		0xE3BF918279CBC478ULL,
		0xD9615B7F05AC56CCULL,
		0x33FD19D28266578AULL,
		0x9CAF7BDC5D851316ULL,
		0x2EC9C58AF5F327A3ULL,
		0xD2BADABB2F88C3D6ULL
	}};
	printf("Test Case 347\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x12E061416EA3B256ULL,
		0xC97A8F3B1690ED15ULL,
		0x3B259BFDE8196B24ULL,
		0xBDD345E662969E86ULL,
		0x1C0B5FDE9D3C132BULL,
		0x3D3251AB4790AEF5ULL,
		0xB0DFEFD26E4D780FULL,
		0x9C8B0E0912BBC06DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD96258B0BC149D33ULL,
		0x28E6D00DA8F22034ULL,
		0x3F4E9A63486D5D7EULL,
		0x94A6F929D7586BE9ULL,
		0x3CEBD9F53C67D051ULL,
		0x6AC6BDA9C2A5D7DEULL,
		0x91D87E59378AB175ULL,
		0xD6F93B99B5FE4AD8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCB8239F1D2B72F65ULL,
		0xE19C5F36BE62CD21ULL,
		0x046B019EA074365AULL,
		0x2975BCCFB5CEF56FULL,
		0x20E0862BA15BC37AULL,
		0x57F4EC028535792BULL,
		0x2107918B59C7C97AULL,
		0x4A723590A7458AB5ULL
	}};
	printf("Test Case 348\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x656EBE021F3C4E5EULL,
		0xBCD14AC61ABAAB51ULL,
		0x02F551B0A09A1D7AULL,
		0x14EF8EFEA7892880ULL,
		0x0AC64BA2E1248EF0ULL,
		0x510EF9B62E70DFE1ULL,
		0x8574A23289C66DA8ULL,
		0x20A4560C342E2100ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0D1B854C3102AEC7ULL,
		0xF480FDB992645728ULL,
		0x2A0B50E82F83EC84ULL,
		0xE4EDCD663E61F6D4ULL,
		0xCBABA67612C7E8FBULL,
		0xD74846277393EFBCULL,
		0xD287CD77828CE9EEULL,
		0x4FD5C030970F8079ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x68753B4E2E3EE099ULL,
		0x4851B77F88DEFC79ULL,
		0x28FE01588F19F1FEULL,
		0xF002439899E8DE54ULL,
		0xC16DEDD4F3E3660BULL,
		0x8646BF915DE3305DULL,
		0x57F36F450B4A8446ULL,
		0x6F71963CA321A179ULL
	}};
	printf("Test Case 349\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x51C3B2B037ADE03DULL,
		0xCA35C6664A1FED74ULL,
		0xB30CDA000D5AB380ULL,
		0x7A2B35D7AE1D3748ULL,
		0x179714B6E1E49A12ULL,
		0x65EF3E55496CC858ULL,
		0xB083F76BDBEF6FE0ULL,
		0x24C7716B1224A99CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5799FC1E579DAAC0ULL,
		0x285CEA024C8DED4EULL,
		0x78F72FB2051EFD94ULL,
		0x8170786609A05366ULL,
		0xA064DFB99BEBB9FBULL,
		0x300BB7EA4F372739ULL,
		0xE88ED2AA50A5F0B7ULL,
		0xB2215F44606BCB58ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x065A4EAE60304AFDULL,
		0xE2692C640692003AULL,
		0xCBFBF5B208444E14ULL,
		0xFB5B4DB1A7BD642EULL,
		0xB7F3CB0F7A0F23E9ULL,
		0x55E489BF065BEF61ULL,
		0x580D25C18B4A9F57ULL,
		0x96E62E2F724F62C4ULL
	}};
	printf("Test Case 350\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xB5E166E2E3D5CEBFULL,
		0x02A23B781DC682EAULL,
		0x3387692DABF5216AULL,
		0x6112F8E48A33EFB7ULL,
		0x28BB492705983DADULL,
		0x68E3C8132AFB0650ULL,
		0xA2EC168D0B8E8BF5ULL,
		0x6930682F700D06C1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2389FBD28F8281F6ULL,
		0x164A2620C41A80C8ULL,
		0x9133799969E691D8ULL,
		0x65C3F04D7B5E4D8EULL,
		0x6A382E901D7FCEC1ULL,
		0x5179FD2B1F441467ULL,
		0xC93A21412A7767AAULL,
		0x3EF5DDA7CE8B2332ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x96689D306C574F49ULL,
		0x14E81D58D9DC0222ULL,
		0xA2B410B4C213B0B2ULL,
		0x04D108A9F16DA239ULL,
		0x428367B718E7F36CULL,
		0x399A353835BF1237ULL,
		0x6BD637CC21F9EC5FULL,
		0x57C5B588BE8625F3ULL
	}};
	printf("Test Case 351\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x77B120F880476DD7ULL,
		0x5175AD948C2AE736ULL,
		0x22EDBE86C90BC523ULL,
		0x645CD14F556F5EF6ULL,
		0xE2D74744B6A7BE80ULL,
		0x094929A24F86B83EULL,
		0xEE0BC23BEAC70932ULL,
		0x195CDD0C5AD5B586ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x340A7F5D14B5BE38ULL,
		0xD321B4DD0070D621ULL,
		0xE0E6106CA23C3F93ULL,
		0x192AF64F7EDB9947ULL,
		0x061F8119EF5D18A9ULL,
		0x3AED1CA0C59DE88FULL,
		0xE0B9F2C045B61C74ULL,
		0x90B2657210C60C96ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x43BB5FA594F2D3EFULL,
		0x825419498C5A3117ULL,
		0xC20BAEEA6B37FAB0ULL,
		0x7D7627002BB4C7B1ULL,
		0xE4C8C65D59FAA629ULL,
		0x33A435028A1B50B1ULL,
		0x0EB230FBAF711546ULL,
		0x89EEB87E4A13B910ULL
	}};
	printf("Test Case 352\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x1BAFA72B78BCB174ULL,
		0x7A9492F3B5FFFC7DULL,
		0xB403AB18C208E583ULL,
		0x3F201EBFD4CCDEFCULL,
		0xB2C9FA3F4A8CC318ULL,
		0xAE85E0D720F6395DULL,
		0xF31641E68F073BE0ULL,
		0xC1F47E56B6CCB67FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA585940B4B3AEEE2ULL,
		0xE45B8E16F8CE852FULL,
		0x5BCFB5BD9D41367DULL,
		0x21C94A83068B81F7ULL,
		0xC382BED28AD186C1ULL,
		0x8BA3341C9844809FULL,
		0x6E821A130D96D091ULL,
		0x4F0A1F4E455598BEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBE2A332033865F96ULL,
		0x9ECF1CE54D317952ULL,
		0xEFCC1EA55F49D3FEULL,
		0x1EE9543CD2475F0BULL,
		0x714B44EDC05D45D9ULL,
		0x2526D4CBB8B2B9C2ULL,
		0x9D945BF58291EB71ULL,
		0x8EFE6118F3992EC1ULL
	}};
	printf("Test Case 353\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xAEE0FB3056E5DAD9ULL,
		0x7A7D48E44BACFE43ULL,
		0x5D068BC58C7B4025ULL,
		0xCCCA332517B8FF7DULL,
		0xDE22943B96178726ULL,
		0x65F3542341B5CE07ULL,
		0x15CE1A6C1EA68E86ULL,
		0x24743F0D28BA0F84ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7BE1D900BF29D9EDULL,
		0x03787AB2AC3B0F50ULL,
		0xC4B476D5CC1D2C44ULL,
		0xCFE66E86F20673FCULL,
		0x18A0FFDDEE21010EULL,
		0x9BFDFDC4D96E5AD7ULL,
		0x25D61526C2BA70BAULL,
		0x5F9938934CB5F2C2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD5012230E9CC0334ULL,
		0x79053256E797F113ULL,
		0x99B2FD1040666C61ULL,
		0x032C5DA3E5BE8C81ULL,
		0xC6826BE678368628ULL,
		0xFE0EA9E798DB94D0ULL,
		0x30180F4ADC1CFE3CULL,
		0x7BED079E640FFD46ULL
	}};
	printf("Test Case 354\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x099E77762FC92C9BULL,
		0x3F5CB53A4A4E0801ULL,
		0x94B7382B9AA69675ULL,
		0xD25253C875B1142EULL,
		0x7F023DF772B2F600ULL,
		0xB0A4F8A36985A496ULL,
		0x2B5257DAA0136DD3ULL,
		0x50A25F70DA5EF1F6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE36998C62EE95238ULL,
		0xD568CDAE0EEF9EEDULL,
		0xF7188CCE2BEF8FC5ULL,
		0xDFA8C9307596AF3AULL,
		0x5EEA6784127C7F0CULL,
		0xF48ACD1DDD9C2324ULL,
		0xF0F3E8F7E5719BA8ULL,
		0x34249E2AF2C4CA25ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEAF7EFB001207EA3ULL,
		0xEA34789444A196ECULL,
		0x63AFB4E5B14919B0ULL,
		0x0DFA9AF80027BB14ULL,
		0x21E85A7360CE890CULL,
		0x442E35BEB41987B2ULL,
		0xDBA1BF2D4562F67BULL,
		0x6486C15A289A3BD3ULL
	}};
	printf("Test Case 355\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x7B84967875B36E55ULL,
		0xC4E6F09DC2F93B4CULL,
		0xC06FFA68C4D69709ULL,
		0xE8CDBE6D58B967E2ULL,
		0x1BB2429954308DE9ULL,
		0x7872EE7C5FCE310FULL,
		0x270DA7C5DE418BFDULL,
		0x236181E683387C4DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x83510B3A7786BC38ULL,
		0xDDACC3B77B571FA1ULL,
		0xABABC2C77E771198ULL,
		0xA390509F2C7E9984ULL,
		0x89090F88385323B9ULL,
		0xC6BF89336BD4CB5AULL,
		0x09837B316AC3C7EEULL,
		0x8ADD310CA7FC1053ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF8D59D420235D26DULL,
		0x194A332AB9AE24EDULL,
		0x6BC438AFBAA18691ULL,
		0x4B5DEEF274C7FE66ULL,
		0x92BB4D116C63AE50ULL,
		0xBECD674F341AFA55ULL,
		0x2E8EDCF4B4824C13ULL,
		0xA9BCB0EA24C46C1EULL
	}};
	printf("Test Case 356\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x7EAF7FF418A15F7BULL,
		0x02E40EE13C3C9D92ULL,
		0xA04B415373E1C083ULL,
		0x5869B6E6C9D63DC7ULL,
		0x30EB8D2B5D163042ULL,
		0xD5DC52126EB19B51ULL,
		0x1B9A56C834250390ULL,
		0x378912381B12F889ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA9FABE1121751FD2ULL,
		0x4B45B216F29EE1D9ULL,
		0xE731F5EA8ECC36A8ULL,
		0x51D555B5401C232FULL,
		0x92DC02655ADADC1DULL,
		0x9068871357C31179ULL,
		0x7730C2921734BC59ULL,
		0x3FC5DEAADA812168ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD755C1E539D440A9ULL,
		0x49A1BCF7CEA27C4BULL,
		0x477AB4B9FD2DF62BULL,
		0x09BCE35389CA1EE8ULL,
		0xA2378F4E07CCEC5FULL,
		0x45B4D50139728A28ULL,
		0x6CAA945A2311BFC9ULL,
		0x084CCC92C193D9E1ULL
	}};
	printf("Test Case 357\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xC89726A36AD5B3E6ULL,
		0xCFE5CA08A0F475C5ULL,
		0x2FE68C79DF3122E4ULL,
		0x65F02A85C518FBF7ULL,
		0x8073DE0D6E100E7CULL,
		0x23FB2AC4D3FD9353ULL,
		0x2DD3DA34B231A70AULL,
		0x3D5832978477EF4FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x209DBCF783EB04C4ULL,
		0xE2FC02D05DC49587ULL,
		0x2333C9626F2B2F63ULL,
		0x8145ED71126D3121ULL,
		0x5B561E0145EAD060ULL,
		0xBE97E0D8FD15EE38ULL,
		0x7CD2DBD08251C2AEULL,
		0x0087C5F09A8D7B29ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE80A9A54E93EB722ULL,
		0x2D19C8D8FD30E042ULL,
		0x0CD5451BB01A0D87ULL,
		0xE4B5C7F4D775CAD6ULL,
		0xDB25C00C2BFADE1CULL,
		0x9D6CCA1C2EE87D6BULL,
		0x510101E4306065A4ULL,
		0x3DDFF7671EFA9466ULL
	}};
	printf("Test Case 358\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xA5E7A2818A889798ULL,
		0x80EE540DB32D63A1ULL,
		0x9B72EDDD3958ED89ULL,
		0x4362231F557E3037ULL,
		0xFAB2D3322D67AC57ULL,
		0x92EEE2812BB93111ULL,
		0x7B73A8B1ADF49B62ULL,
		0x920DE5428AE62E54ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x49DAF42FC44EAC1AULL,
		0xB7B66ACC3C24890FULL,
		0x4277B8532C5020CBULL,
		0x27F463DA5DB83851ULL,
		0x5B685BCEAAC7BE22ULL,
		0xC9241A4205820291ULL,
		0x5E066AD11BCD9E85ULL,
		0x2F7C9470248B6D69ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEC3D56AE4EC63B82ULL,
		0x37583EC18F09EAAEULL,
		0xD905558E1508CD42ULL,
		0x649640C508C60866ULL,
		0xA1DA88FC87A01275ULL,
		0x5BCAF8C32E3B3380ULL,
		0x2575C260B63905E7ULL,
		0xBD717132AE6D433DULL
	}};
	printf("Test Case 359\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x46EF0696DE750BC7ULL,
		0x18D5FCF3BE58C7D5ULL,
		0xFC0D1906A27000E7ULL,
		0x8145E9347244223FULL,
		0xC2BB65A08F5956D7ULL,
		0xF5EEB8FBC0A417DFULL,
		0xB186DA4E13ADD4D3ULL,
		0xB5CDBD151B2DFFACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7CC2AEBC4C89FE56ULL,
		0xB23674A5E5598C34ULL,
		0x0AA7E96FDEEE1EE6ULL,
		0x354F9FC7A64EFA49ULL,
		0xD49BB390FD7483E3ULL,
		0xA74CCBE3813319F2ULL,
		0x413F3DA79D86DC7DULL,
		0x2FB8F6AFB92FBDC2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3A2DA82A92FCF591ULL,
		0xAAE388565B014BE1ULL,
		0xF6AAF0697C9E1E01ULL,
		0xB40A76F3D40AD876ULL,
		0x1620D630722DD534ULL,
		0x52A2731841970E2DULL,
		0xF0B9E7E98E2B08AEULL,
		0x9A754BBAA202426EULL
	}};
	printf("Test Case 360\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xEED542211BA0CB50ULL,
		0x14329D68333EFF74ULL,
		0x693BE3FE3ADA75DCULL,
		0x3747DCE84DF401BEULL,
		0xB295DA1F01DCAE57ULL,
		0x2DC134B6D37173AEULL,
		0xF23538FE866341D2ULL,
		0xE29B76D2B624BE20ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3AA15AF9D452E162ULL,
		0xC288987ED51C4551ULL,
		0x8F074CAA16D52A5BULL,
		0xA313DF0D8DD1EF92ULL,
		0x931D9BF80A893D57ULL,
		0xE61768E74657ECDEULL,
		0x3DD3DE047BDF5703ULL,
		0x798CFEA997139A51ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD47418D8CFF22A32ULL,
		0xD6BA0516E622BA25ULL,
		0xE63CAF542C0F5F87ULL,
		0x945403E5C025EE2CULL,
		0x218841E70B559300ULL,
		0xCBD65C5195269F70ULL,
		0xCFE6E6FAFDBC16D1ULL,
		0x9B17887B21372471ULL
	}};
	printf("Test Case 361\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x9C81EBB8B72E4FDAULL,
		0x5056A0226D9080A3ULL,
		0xE8B89169707011F0ULL,
		0x7929015F5C50820CULL,
		0x888C2B4510F81181ULL,
		0xD9495D224B4F0F8EULL,
		0x961C5A0742D7CBF8ULL,
		0x1800A05FD1CAF036ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x054DE79D55BB348AULL,
		0x018468EAFC293258ULL,
		0x9E6E17680A901614ULL,
		0xD4B1D2E9DF23FFABULL,
		0xBE7E56AE46B86053ULL,
		0x7B47B743D701EB29ULL,
		0x979BA57CE15959F1ULL,
		0x124458D70F6536FCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x99CC0C25E2957B50ULL,
		0x51D2C8C891B9B2FBULL,
		0x76D686017AE007E4ULL,
		0xAD98D3B683737DA7ULL,
		0x36F27DEB564071D2ULL,
		0xA20EEA619C4EE4A7ULL,
		0x0187FF7BA38E9209ULL,
		0x0A44F888DEAFC6CAULL
	}};
	printf("Test Case 362\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x10DD24C082DAD023ULL,
		0x17AD61D41BDBB1E2ULL,
		0x3D711DC5B2C35FBBULL,
		0xBAD8FCFFA1B05D93ULL,
		0x6E790DF9C354B3E4ULL,
		0x05971B36D5CF2639ULL,
		0x0D4659577FE07D18ULL,
		0x36C94DA4156AD66FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD593AA8654B4076FULL,
		0x1590A55584C94763ULL,
		0xF7FF6C723503AC55ULL,
		0xD474A7DA44434B61ULL,
		0xB54C8E76479BA0ABULL,
		0x5947721D94695C7DULL,
		0xBCC6A6A4FE1DC1AFULL,
		0xCF36EA58CA8D1838ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC54E8E46D66ED74CULL,
		0x023DC4819F12F681ULL,
		0xCA8E71B787C0F3EEULL,
		0x6EAC5B25E5F316F2ULL,
		0xDB35838F84CF134FULL,
		0x5CD0692B41A67A44ULL,
		0xB180FFF381FDBCB7ULL,
		0xF9FFA7FCDFE7CE57ULL
	}};
	printf("Test Case 363\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x42B066C4517E59ABULL,
		0x2A23739EC5E01187ULL,
		0x444C7809F5838F5BULL,
		0xC0337D9D0745CE89ULL,
		0x7EFE3166C6F77623ULL,
		0x9E6299B5DE2CE4DDULL,
		0xDD8935AE6B3A81A3ULL,
		0x8D77C4077E19701BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0226F55D553EDFF0ULL,
		0x2F79A624A68C5B4CULL,
		0xB165EC786F201971ULL,
		0xBEDFE86448636975ULL,
		0xD01DB17B24AA2919ULL,
		0xF4E7B156746552D1ULL,
		0x1B72F95F8ED5A284ULL,
		0x81FF3947B77D3392ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x409693990440865BULL,
		0x055AD5BA636C4ACBULL,
		0xF52994719AA3962AULL,
		0x7EEC95F94F26A7FCULL,
		0xAEE3801DE25D5F3AULL,
		0x6A8528E3AA49B60CULL,
		0xC6FBCCF1E5EF2327ULL,
		0x0C88FD40C9644389ULL
	}};
	printf("Test Case 364\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xE5FA12A034390FE4ULL,
		0x6CBB285AFD6671DFULL,
		0x64C1A16279AB2DC2ULL,
		0x341939569AAC9335ULL,
		0xAE5054CDB7B78B70ULL,
		0x33D53FE5FA877EB5ULL,
		0x9E87261272EAA7D2ULL,
		0x9322EEEF220B7267ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB321962818FFFAEFULL,
		0xA272995EA323E504ULL,
		0xD651CD047383338AULL,
		0x1284B0CAAAB74877ULL,
		0xB28DE9A251814B14ULL,
		0x5140D1438CB338C8ULL,
		0x56C607BC936F0305ULL,
		0x7E42D290684E9701ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x56DB84882CC6F50BULL,
		0xCEC9B1045E4594DBULL,
		0xB2906C660A281E48ULL,
		0x269D899C301BDB42ULL,
		0x1CDDBD6FE636C064ULL,
		0x6295EEA67634467DULL,
		0xC84121AEE185A4D7ULL,
		0xED603C7F4A45E566ULL
	}};
	printf("Test Case 365\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xFF65148486220DACULL,
		0xB86ACECA4E87FD1EULL,
		0x431D2440A7E4F21EULL,
		0xF0E845D995E01711ULL,
		0x58EFD5065548943CULL,
		0x14A36D5E4228E44BULL,
		0x7401378AC8CDE919ULL,
		0xC97755FE0F0A888CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDE34C8801BB87D35ULL,
		0xFE1D595B13A71788ULL,
		0xB72DE5EC761A5F96ULL,
		0xBA1F755E0339E16EULL,
		0xC005E68B68BE560AULL,
		0xFDDBCDC5D4F5D5E8ULL,
		0xFCAD35B2FCB83BE9ULL,
		0x28588C48030D0A60ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2151DC049D9A7099ULL,
		0x467797915D20EA96ULL,
		0xF430C1ACD1FEAD88ULL,
		0x4AF7308796D9F67FULL,
		0x98EA338D3DF6C236ULL,
		0xE978A09B96DD31A3ULL,
		0x88AC02383475D2F0ULL,
		0xE12FD9B60C0782ECULL
	}};
	printf("Test Case 366\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xF8FED63B27518752ULL,
		0x18312C065189CE51ULL,
		0x50F6D04CA94334C2ULL,
		0x98C82106553E4312ULL,
		0x32F9A117792B3F72ULL,
		0xAA5BA1180A7B27FBULL,
		0xC7EFA3363439FACFULL,
		0xD42B4C4D0F35F6AFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x63EC4CCD3755400FULL,
		0x0ED50ED0D85C54CAULL,
		0xE97D31A5827D1689ULL,
		0x97790FB18DAE3FC3ULL,
		0xE8B0D23E0E057129ULL,
		0xB67745ED58B26742ULL,
		0x06B6CAB20FF2E8B1ULL,
		0x4CE1BCBF41DB0E13ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9B129AF61004C75DULL,
		0x16E422D689D59A9BULL,
		0xB98BE1E92B3E224BULL,
		0x0FB12EB7D8907CD1ULL,
		0xDA497329772E4E5BULL,
		0x1C2CE4F552C940B9ULL,
		0xC15969843BCB127EULL,
		0x98CAF0F24EEEF8BCULL
	}};
	printf("Test Case 367\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x39DC98FAC1BBC7BBULL,
		0xED02FD437D7C8204ULL,
		0x62423CBD10EE5B77ULL,
		0x4B53D61AF2441FBCULL,
		0x675C50261400D35EULL,
		0xFB491E30461F027BULL,
		0x8EE8CB9286A5068DULL,
		0xD354E15E69715E00ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x37294015B03E0F90ULL,
		0x639A833E089F822AULL,
		0x2E90A3831DD29AE3ULL,
		0xBC4357E2E67405E3ULL,
		0x55CC8EEB1635FFE6ULL,
		0x71D4502C939C2DDDULL,
		0x5392DF6A2FD68CBDULL,
		0x7B970792A64E7EA3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0EF5D8EF7185C82BULL,
		0x8E987E7D75E3002EULL,
		0x4CD29F3E0D3CC194ULL,
		0xF71081F814301A5FULL,
		0x3290DECD02352CB8ULL,
		0x8A9D4E1CD5832FA6ULL,
		0xDD7A14F8A9738A30ULL,
		0xA8C3E6CCCF3F20A3ULL
	}};
	printf("Test Case 368\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xDF8A28A678BE0CDAULL,
		0x9656ED3644D095F2ULL,
		0x5493234569C1B614ULL,
		0xFCE1D47124057258ULL,
		0x502D2CBF64678859ULL,
		0x2A9D0AFE982788EFULL,
		0x408366694100904DULL,
		0xBD4677777B251852ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEA848895BA6DB27BULL,
		0x55C3597F3D4A4BB8ULL,
		0x8CD364885D939A0BULL,
		0x281277419806AE64ULL,
		0x416840B142E6096AULL,
		0xB216407CE010D09FULL,
		0x7024F12A5CDDF363ULL,
		0x24ECDECFECF23A03ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x350EA033C2D3BEA1ULL,
		0xC395B449799ADE4AULL,
		0xD84047CD34522C1FULL,
		0xD4F3A330BC03DC3CULL,
		0x11456C0E26818133ULL,
		0x988B4A8278375870ULL,
		0x30A797431DDD632EULL,
		0x99AAA9B897D72251ULL
	}};
	printf("Test Case 369\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x7A00EDD35A591EF0ULL,
		0x38144170CF473ADDULL,
		0xE852E407BCD0038DULL,
		0xB41B2484114340F2ULL,
		0x2F010C0CD4433459ULL,
		0x1BD48742504F63AEULL,
		0xF79542C72F33BCE6ULL,
		0xF2E560B5C53136B0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC7DA31879B4768D3ULL,
		0x2721DB8106262877ULL,
		0x713EF04316668CD4ULL,
		0x5D3A6DB7110E296BULL,
		0xA35A1819AEB56EADULL,
		0x5C2C720465E54A6BULL,
		0xB015E8837875AFA3ULL,
		0x7739B76D87009134ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBDDADC54C11E7623ULL,
		0x1F359AF1C96112AAULL,
		0x996C1444AAB68F59ULL,
		0xE9214933004D6999ULL,
		0x8C5B14157AF65AF4ULL,
		0x47F8F54635AA29C5ULL,
		0x4780AA4457461345ULL,
		0x85DCD7D84231A784ULL
	}};
	printf("Test Case 370\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x67CECF46113E3842ULL,
		0xC70771A5AEE78F75ULL,
		0x92CB59A11D095FC9ULL,
		0x746CFB26CEF2063DULL,
		0x6F92B0E7FE154910ULL,
		0x019449E9B1373D6FULL,
		0x154AAF05C525A29EULL,
		0x6D6D821CFBF3B815ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAFB92B6DF5C1317FULL,
		0xFD8CA36582CF4B4DULL,
		0xB988B01B8F6D2051ULL,
		0xEE544DB15069C9CCULL,
		0x22F8A6B576B03E35ULL,
		0xC0BE1C5427DAF294ULL,
		0xE07BCA8F7119FCEFULL,
		0x68B823D52DB84B25ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC877E42BE4FF093DULL,
		0x3A8BD2C02C28C438ULL,
		0x2B43E9BA92647F98ULL,
		0x9A38B6979E9BCFF1ULL,
		0x4D6A165288A57725ULL,
		0xC12A55BD96EDCFFBULL,
		0xF531658AB43C5E71ULL,
		0x05D5A1C9D64BF330ULL
	}};
	printf("Test Case 371\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xF4686509AC2D0D2EULL,
		0x832A6CAE14CD2C08ULL,
		0xB21868717981C19DULL,
		0x86DF0B69C6108EFBULL,
		0x976004B2098C8AB7ULL,
		0xB6FAE9EFBF33B651ULL,
		0xF4077086524FB73DULL,
		0xAFCAB3F70451472BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x639B1F4B5E5F638DULL,
		0xB74C0E8ADE907B61ULL,
		0x3E16E66EAE8C564FULL,
		0xF29137D329281BBAULL,
		0xF5DBCA55E0B3FFF3ULL,
		0x1290FF80C32EE9D2ULL,
		0x0051F25F33C49FA1ULL,
		0x16DE8036486F0D94ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x97F37A42F2726EA3ULL,
		0x34666224CA5D5769ULL,
		0x8C0E8E1FD70D97D2ULL,
		0x744E3CBAEF389541ULL,
		0x62BBCEE7E93F7544ULL,
		0xA46A166F7C1D5F83ULL,
		0xF45682D9618B289CULL,
		0xB91433C14C3E4ABFULL
	}};
	printf("Test Case 372\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x2B8E9F7F1FF9468FULL,
		0x7D93D296CA50B15DULL,
		0x3BE0C064DAF4488EULL,
		0x36B13931482D9AAAULL,
		0x959365CA5DA5BD3EULL,
		0x8291607911131E94ULL,
		0x4BC87A065F4298F4ULL,
		0xC98556FB259D4657ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x67D6CCEFF4795FD0ULL,
		0xF2499A14FC05CF5FULL,
		0x29BAB5CF662C89C4ULL,
		0x66D18235CCA5703EULL,
		0x4006D35DA0F8FD00ULL,
		0xC01E5175D8BE6BD0ULL,
		0x0FC75C3887A24864ULL,
		0x83D223A9C87A0AECULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4C585390EB80195FULL,
		0x8FDA488236557E02ULL,
		0x125A75ABBCD8C14AULL,
		0x5060BB048488EA94ULL,
		0xD595B697FD5D403EULL,
		0x428F310CC9AD7544ULL,
		0x440F263ED8E0D090ULL,
		0x4A577552EDE74CBBULL
	}};
	printf("Test Case 373\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x90D5A939FC59AA73ULL,
		0xA90D5BA42BF7A895ULL,
		0x550D958ECC1F51B6ULL,
		0xC528931BEE929798ULL,
		0x58BD827D012630CBULL,
		0xCCEB37088EC77091ULL,
		0xCA78BECC825B629FULL,
		0x52CD0886628879D6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD6733C7E423309C0ULL,
		0x140CF0FEC8860F50ULL,
		0x75517EE131EB4206ULL,
		0x31A76629FAF6803FULL,
		0x11B40F37E0BEDA47ULL,
		0xB0F1A9BFF7F4881EULL,
		0x983D4C91DBC2B1E5ULL,
		0x137BF69B9E2FEB1EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x46A69547BE6AA3B3ULL,
		0xBD01AB5AE371A7C5ULL,
		0x205CEB6FFDF413B0ULL,
		0xF48FF532146417A7ULL,
		0x49098D4AE198EA8CULL,
		0x7C1A9EB77933F88FULL,
		0x5245F25D5999D37AULL,
		0x41B6FE1DFCA792C8ULL
	}};
	printf("Test Case 374\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x38438B5ED4B0FE74ULL,
		0x1836AB8E4DCD28C7ULL,
		0xB9DD0A8AAB78A4D7ULL,
		0xE3AE1EAEC490BCCAULL,
		0xAB4DE6567A75DA66ULL,
		0xA2A5128D966461C1ULL,
		0xA670642ABA624885ULL,
		0xF96F19EA7ABCCA55ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x19EC6E17DAB34BC1ULL,
		0xB46785D186A6FDF0ULL,
		0x3B7D927D276F48B4ULL,
		0x145E18FBF506A47FULL,
		0x8B2630C9815B4242ULL,
		0x53B9DCBAFE5DF21CULL,
		0x6DE5E98B36BE95FDULL,
		0x62919B40100BC144ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x21AFE5490E03B5B5ULL,
		0xAC512E5FCB6BD537ULL,
		0x82A098F78C17EC63ULL,
		0xF7F00655319618B5ULL,
		0x206BD69FFB2E9824ULL,
		0xF11CCE37683993DDULL,
		0xCB958DA18CDCDD78ULL,
		0x9BFE82AA6AB70B11ULL
	}};
	printf("Test Case 375\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xDCFF68FCCEDEC107ULL,
		0xAD894A9CADD3A824ULL,
		0x6AB406AF12FCC6ADULL,
		0x9F4B542011D0CC2AULL,
		0x9F21A8CFE26DE89FULL,
		0x3DF925110421130FULL,
		0x1A7508E4E562C904ULL,
		0x7416456175000D4DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB3366658118E228CULL,
		0x7764868DA33A63C4ULL,
		0x87C8DB08E3B49B70ULL,
		0x24562370BEEA8ECBULL,
		0xF25B69CD6412FA70ULL,
		0x754552C727F53E4AULL,
		0xBB3A8833DF7C46A3ULL,
		0x9499DE3CD7ACA27FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6FC90EA4DF50E38BULL,
		0xDAEDCC110EE9CBE0ULL,
		0xED7CDDA7F1485DDDULL,
		0xBB1D7750AF3A42E1ULL,
		0x6D7AC102867F12EFULL,
		0x48BC77D623D42D45ULL,
		0xA14F80D73A1E8FA7ULL,
		0xE08F9B5DA2ACAF32ULL
	}};
	printf("Test Case 376\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x12D5E3FCFB28A01EULL,
		0x2F6B6DF1FE90FCBAULL,
		0xC54969CA2474C094ULL,
		0x856F60772DD694E0ULL,
		0x019D1388E040C1EAULL,
		0xE7C60172C31F0881ULL,
		0xB8A8773A5671FD36ULL,
		0x12B8C6A4A85A37CCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x90F2A475BAB02F04ULL,
		0x91DFA8E16309E476ULL,
		0x9D2BB2E531B92FDFULL,
		0xE0CD12CB886A60A6ULL,
		0xD0E1A3C6C63ED382ULL,
		0xC6FED0FCA9941848ULL,
		0x6920BAF3A59C7441ULL,
		0x98DADD5EE7A21247ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8227478941988F1AULL,
		0xBEB4C5109D9918CCULL,
		0x5862DB2F15CDEF4BULL,
		0x65A272BCA5BCF446ULL,
		0xD17CB04E267E1268ULL,
		0x2138D18E6A8B10C9ULL,
		0xD188CDC9F3ED8977ULL,
		0x8A621BFA4FF8258BULL
	}};
	printf("Test Case 377\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x64B7D522CDD0CCD3ULL,
		0xB9038059EF8B60FFULL,
		0xCFA561782B098069ULL,
		0x2497A0EA6197F691ULL,
		0xB4C25806CF48AAE2ULL,
		0x8CD67D7412887861ULL,
		0xDD13E8238B72D2ADULL,
		0xE905BF8B6A43E5B4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x25A8A5FF54B8D3CCULL,
		0xE6A7C4C01A587D03ULL,
		0x626FEC98393DDE45ULL,
		0x9BA8622E8043217CULL,
		0x8B45EA71EE1EB6B1ULL,
		0xB837705B9B48EA22ULL,
		0x6D0AFF160AF84EC3ULL,
		0x9C1B3C2266A08573ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x411F70DD99681F1FULL,
		0x5FA44499F5D31DFCULL,
		0xADCA8DE012345E2CULL,
		0xBF3FC2C4E1D4D7EDULL,
		0x3F87B27721561C53ULL,
		0x34E10D2F89C09243ULL,
		0xB0191735818A9C6EULL,
		0x751E83A90CE360C7ULL
	}};
	printf("Test Case 378\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x76C31F78C13285B1ULL,
		0x186A60103A74A9FFULL,
		0x544E4677EE175338ULL,
		0x13B1C0D1200C8DFDULL,
		0x7C7DFDD87AB339D1ULL,
		0x5C054E6EEF1F25DCULL,
		0x4421DF39B66AB311ULL,
		0x6833330F020FC2C5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6288CF35A1E18729ULL,
		0x65AE90C5CF7CB270ULL,
		0x945E8A4CAC1B4BA0ULL,
		0xC5209664A75A4234ULL,
		0xC6989B642A920848ULL,
		0x79593D95ABF6034AULL,
		0xF8D3625E8B6E5266ULL,
		0x9C28CAA96D88E4BCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x144BD04D60D30298ULL,
		0x7DC4F0D5F5081B8FULL,
		0xC010CC3B420C1898ULL,
		0xD69156B58756CFC9ULL,
		0xBAE566BC50213199ULL,
		0x255C73FB44E92696ULL,
		0xBCF2BD673D04E177ULL,
		0xF41BF9A66F872679ULL
	}};
	printf("Test Case 379\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x7634557A15A9CEE7ULL,
		0x7B8EEB35A0C85CEEULL,
		0xE7BBA74A8A1E3378ULL,
		0x5586CDC464A13890ULL,
		0x764B646C79EFEB75ULL,
		0xD44E728314BC99E3ULL,
		0xBD04BC1580B68E77ULL,
		0x3694885DE4677724ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x50DE6E1ABA1A4AF1ULL,
		0xCFCE340874A0F9C9ULL,
		0x6B002676BACD6B71ULL,
		0xBEE0E0E78B46008BULL,
		0x33D6659284239C3DULL,
		0x188EA6F1EDDD9BDCULL,
		0x77AC41808ED78B59ULL,
		0x9DE9EC04545B1B17ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x26EA3B60AFB38416ULL,
		0xB440DF3DD468A527ULL,
		0x8CBB813C30D35809ULL,
		0xEB662D23EFE7381BULL,
		0x459D01FEFDCC7748ULL,
		0xCCC0D472F961023FULL,
		0xCAA8FD950E61052EULL,
		0xAB7D6459B03C6C33ULL
	}};
	printf("Test Case 380\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x39A90B13F40429E9ULL,
		0xEAD794EEF6815F93ULL,
		0xC8C39AE2209C4A5EULL,
		0x82E355FA5F14CD86ULL,
		0x94CCD223F1FC0EEDULL,
		0x78F1220D8FFB719EULL,
		0x465E0D74527FE13CULL,
		0x3ADF8CBF08FA93A0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x159CAD79063E4F91ULL,
		0xAEA7985AA11343AAULL,
		0xED15DDF101542DD4ULL,
		0xE66DE5B14B8F0DD4ULL,
		0x5A5186B167CBF23DULL,
		0xD4E19EFF7A1D9D7FULL,
		0xAB3739453290583EULL,
		0x7B31A562411B2663ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2C35A66AF23A6678ULL,
		0x44700CB457921C39ULL,
		0x25D6471321C8678AULL,
		0x648EB04B149BC052ULL,
		0xCE9D54929637FCD0ULL,
		0xAC10BCF2F5E6ECE1ULL,
		0xED69343160EFB902ULL,
		0x41EE29DD49E1B5C3ULL
	}};
	printf("Test Case 381\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xB7EAE60FC8D29A4DULL,
		0x7D53271DE05C2B9EULL,
		0x3DBEE82ACC0F67BDULL,
		0xA911C1F352771BBCULL,
		0x5D95B8F630F3AD50ULL,
		0x0C3FEBAE4E4C50D6ULL,
		0x68C7ADBB0FC3FEF1ULL,
		0x9F05E99F61D41DF2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF763A2E1D3EC21BFULL,
		0xEC129F2C926349BFULL,
		0xF1038726BCEF1F12ULL,
		0xB7F941496423E8A4ULL,
		0x99B6B33F92100AD5ULL,
		0x288361449A4B8297ULL,
		0xD04DFD428F561D56ULL,
		0x13AC8518F61F8511ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x408944EE1B3EBBF2ULL,
		0x9141B831723F6221ULL,
		0xCCBD6F0C70E078AFULL,
		0x1EE880BA3654F318ULL,
		0xC4230BC9A2E3A785ULL,
		0x24BC8AEAD407D241ULL,
		0xB88A50F98095E3A7ULL,
		0x8CA96C8797CB98E3ULL
	}};
	printf("Test Case 382\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x926366B67AFE5B3CULL,
		0x047D932CDAF21C49ULL,
		0xFEE3F8D9ED2E5847ULL,
		0x6A17A438B265C08DULL,
		0x0630D9E8CD2B179AULL,
		0x78C6EC68C9EE37E6ULL,
		0x469E4764E3C5B67CULL,
		0x89E55C96006AD6B6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6C0AD3F96E3536C0ULL,
		0x5A2410F2264F7DB5ULL,
		0xCFA6CB4FFC460589ULL,
		0xF22A59588A5C8E02ULL,
		0xAE81B6FA7D11E692ULL,
		0xFF3CE84D8D43AA2AULL,
		0x4E5103E4FD310F38ULL,
		0x48ABDE80AF951617ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFE69B54F14CB6DFCULL,
		0x5E5983DEFCBD61FCULL,
		0x3145339611685DCEULL,
		0x983DFD6038394E8FULL,
		0xA8B16F12B03AF108ULL,
		0x87FA042544AD9DCCULL,
		0x08CF44801EF4B944ULL,
		0xC14E8216AFFFC0A1ULL
	}};
	printf("Test Case 383\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xC69B868565336512ULL,
		0x599C85AF5FE493D7ULL,
		0x04B5D38C494F3D4AULL,
		0x426230813747099AULL,
		0x5459882EC362F7FEULL,
		0x121E51A59E784C0CULL,
		0xBF257CA0B3F60013ULL,
		0xEF8ABFF456B7EDB2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB89DE0775035F83BULL,
		0x874A04E7046007A8ULL,
		0x6E9D0D15F7F4751DULL,
		0x34E7F8864DD711CBULL,
		0x66BCFE19549A1E2CULL,
		0x8DE9C4C3FAB41C94ULL,
		0xC5B5723BAE4E7074ULL,
		0x41F2527B5C84BAB1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7E0666F235069D29ULL,
		0xDED681485B84947FULL,
		0x6A28DE99BEBB4857ULL,
		0x7685C8077A901851ULL,
		0x32E5763797F8E9D2ULL,
		0x9FF7956664CC5098ULL,
		0x7A900E9B1DB87067ULL,
		0xAE78ED8F0A335703ULL
	}};
	printf("Test Case 384\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x9AB89AE7A5AA6CA1ULL,
		0xEC4CDEC8EF33E8C5ULL,
		0x46AB1A136806DB0FULL,
		0x82498DCA4AAE0B0EULL,
		0x1E751D9B5B5413CDULL,
		0xE20A47DDEE539412ULL,
		0x56496B5809385F3EULL,
		0x397F347552456C50ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBA40FE622F29E10AULL,
		0x7B19EC1765BCD8CDULL,
		0x45B04B8DD9470147ULL,
		0x1467196DA9A9B332ULL,
		0xA14F431F28BD72F2ULL,
		0xED0A13613EB93798ULL,
		0xC8B93FB0AD375628ULL,
		0x1FC5F7E819EB7674ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x20F864858A838DABULL,
		0x975532DF8A8F3008ULL,
		0x031B519EB141DA48ULL,
		0x962E94A7E307B83CULL,
		0xBF3A5E8473E9613FULL,
		0x0F0054BCD0EAA38AULL,
		0x9EF054E8A40F0916ULL,
		0x26BAC39D4BAE1A24ULL
	}};
	printf("Test Case 385\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xB87C967DFD33C5DEULL,
		0xEAABAA5F9DAF6F68ULL,
		0x2977E0A63936C156ULL,
		0x4ECB745D90446EFEULL,
		0x67FCAC624C935ECCULL,
		0x1A86327F4F17F728ULL,
		0x846C67D8E9928CE6ULL,
		0x9A068B80EBD3E07DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3FAD0C7476EDA688ULL,
		0x0E29D25B96FE4C70ULL,
		0xC5F97BF60757883AULL,
		0x3F02B3FAA5503B29ULL,
		0x96FEA5AFA1281985ULL,
		0x949E8C6B8C49F530ULL,
		0xD914BDC3D3799373ULL,
		0x153572D42287E601ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x87D19A098BDE6356ULL,
		0xE48278040B512318ULL,
		0xEC8E9B503E61496CULL,
		0x71C9C7A7351455D7ULL,
		0xF10209CDEDBB4749ULL,
		0x8E18BE14C35E0218ULL,
		0x5D78DA1B3AEB1F95ULL,
		0x8F33F954C954067CULL
	}};
	printf("Test Case 386\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x2B040478B2E78201ULL,
		0x314D8C1CDFCEF0EBULL,
		0xB5A57FE1D36B5019ULL,
		0xFBAB6B089AFEAAD7ULL,
		0x39294EC5320237E4ULL,
		0x64223DA90E2B7317ULL,
		0x5555EAA2C2FF490EULL,
		0x06FE014FDB75E74EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDF3896D75B741AC6ULL,
		0x1FF61D2CAA6A39EAULL,
		0x779381D33A6E4FE0ULL,
		0xA9B81103F7AEE9F7ULL,
		0xEE633875E2907CAAULL,
		0x2C706CBB43347763ULL,
		0x2CE7C9F5BC903A57ULL,
		0xAE25D76AB9EB71E4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF43C92AFE99398C7ULL,
		0x2EBB913075A4C901ULL,
		0xC236FE32E9051FF9ULL,
		0x52137A0B6D504320ULL,
		0xD74A76B0D0924B4EULL,
		0x485251124D1F0474ULL,
		0x79B223577E6F7359ULL,
		0xA8DBD625629E96AAULL
	}};
	printf("Test Case 387\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xAC3211027ED065B9ULL,
		0x1B2A1929D6B2C73EULL,
		0x16FC6433619A60CCULL,
		0xBAE4A935D987CD8AULL,
		0x0F0B44D53FA45BBEULL,
		0xE020CC77CB908083ULL,
		0xC3D7D04459CEE524ULL,
		0x778DFC7AEFE5F6B3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x62C3FACDFE8FA8ABULL,
		0x61FD9953632EF652ULL,
		0x86178387C5DAEF51ULL,
		0x72587CFE0A62E1C6ULL,
		0x954FD497193C51A1ULL,
		0x7CE540F985A09C67ULL,
		0x55EB110FD307FAC9ULL,
		0x9F23506B8A99ACF2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCEF1EBCF805FCD12ULL,
		0x7AD7807AB59C316CULL,
		0x90EBE7B4A4408F9DULL,
		0xC8BCD5CBD3E52C4CULL,
		0x9A44904226980A1FULL,
		0x9CC58C8E4E301CE4ULL,
		0x963CC14B8AC91FEDULL,
		0xE8AEAC11657C5A41ULL
	}};
	printf("Test Case 388\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x06562D45955062C6ULL,
		0x08E815346F84F2C1ULL,
		0xA2EC4640402E1520ULL,
		0xC1923CF39ED9501DULL,
		0xD6B69F48BCED2D82ULL,
		0xA137BB428F3B370CULL,
		0x49E83C60DBED8739ULL,
		0x7FAC7F596744E78AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF7F4FDFC1F346867ULL,
		0x45A21E30FB00AA64ULL,
		0x8C22C4FE7C3B1EB7ULL,
		0x2F5ECB1A45ED5112ULL,
		0x4E2EC1F0A52DB582ULL,
		0x6861A75C61C1AC95ULL,
		0x3F79806C20B1BF26ULL,
		0x0227998B92E2E0DAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF1A2D0B98A640AA1ULL,
		0x4D4A0B04948458A5ULL,
		0x2ECE82BE3C150B97ULL,
		0xEECCF7E9DB34010FULL,
		0x98985EB819C09800ULL,
		0xC9561C1EEEFA9B99ULL,
		0x7691BC0CFB5C381FULL,
		0x7D8BE6D2F5A60750ULL
	}};
	printf("Test Case 389\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x04FBD0D7AD34DE64ULL,
		0x72E1B994218385BEULL,
		0x4560B070CBD8D297ULL,
		0xCF6CB25754C17376ULL,
		0x1B5CD28390303F83ULL,
		0x5B44875EC0DF0884ULL,
		0x62E4AD17A5E4E797ULL,
		0x22C1B97B2087F2A0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5780202ADA73D30CULL,
		0x9A5C721671FFDBA2ULL,
		0x1101FFAF743EDAF4ULL,
		0x0A71860E6E3F43AAULL,
		0x330F6047D59DF880ULL,
		0xA2CE4D4E53C334E4ULL,
		0x85A5A66E0F442B29ULL,
		0x2D1D49BD8F6E9C73ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x537BF0FD77470D68ULL,
		0xE8BDCB82507C5E1CULL,
		0x54614FDFBFE60863ULL,
		0xC51D34593AFE30DCULL,
		0x2853B2C445ADC703ULL,
		0xF98ACA10931C3C60ULL,
		0xE7410B79AAA0CCBEULL,
		0x0FDCF0C6AFE96ED3ULL
	}};
	printf("Test Case 390\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xE78A19268FE5B308ULL,
		0xC4FDAC24C8996446ULL,
		0xB608E78E5261D0C7ULL,
		0x893B58DB193072DFULL,
		0x435031AEB1245C64ULL,
		0xB6F6128F21EB029EULL,
		0x697BB460406FA562ULL,
		0x166E466EA8B3EA7AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9D18F24D7CC891DBULL,
		0xFC75B4DC49137C29ULL,
		0x851F05882FE4FA12ULL,
		0x2F2D3241FB4D6E40ULL,
		0x5856486C2CF280F2ULL,
		0x91649704E3369B1AULL,
		0xB9D1829242DBC54AULL,
		0xB52A1D69B12073FAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7A92EB6BF32D22D3ULL,
		0x388818F8818A186FULL,
		0x3317E2067D852AD5ULL,
		0xA6166A9AE27D1C9FULL,
		0x1B0679C29DD6DC96ULL,
		0x2792858BC2DD9984ULL,
		0xD0AA36F202B46028ULL,
		0xA3445B0719939980ULL
	}};
	printf("Test Case 391\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x40605FE385D1A8B4ULL,
		0x51CF164EEE401C7BULL,
		0x79046CF958F65308ULL,
		0xB7825AC1FC5B22B6ULL,
		0x189F174E52AE8C43ULL,
		0x0505CCB80CA54FAAULL,
		0x2B876B605D35C4AEULL,
		0xACC8AABAB07A8488ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x64F2A5108B84A6ACULL,
		0xB68201F06E78BBCDULL,
		0xAB3FF234CF28743FULL,
		0x35EADA87FD645286ULL,
		0x3C9E2F17F2073AFEULL,
		0x74B76B625A12BFDEULL,
		0x20FE0ED86D13AC3BULL,
		0x006AFD98BD3344EBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2492FAF30E550E18ULL,
		0xE74D17BE8038A7B6ULL,
		0xD23B9ECD97DE2737ULL,
		0x82688046013F7030ULL,
		0x24013859A0A9B6BDULL,
		0x71B2A7DA56B7F074ULL,
		0x0B7965B830266895ULL,
		0xACA257220D49C063ULL
	}};
	printf("Test Case 392\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xF39CA146A531DF96ULL,
		0x3CCB590EA8B028F6ULL,
		0xF22765882DBC71D4ULL,
		0xF2A801E73AC113C5ULL,
		0xAF7BC74737C9D3A7ULL,
		0xE7E921D49D102C92ULL,
		0x1043154D9BAD6CD2ULL,
		0xE98F3F13A4F2690CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x121FC273BD25EE0CULL,
		0x9F5E21FC69F9564CULL,
		0x138FE37BCB22E071ULL,
		0x26A36DCF92164575ULL,
		0x7D3C39EB26CB9D93ULL,
		0xA78D9968B52CCAA1ULL,
		0xCB10895CAEACF912ULL,
		0xE27C97DDD370EB83ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE18363351814319AULL,
		0xA39578F2C1497EBAULL,
		0xE1A886F3E69E91A5ULL,
		0xD40B6C28A8D756B0ULL,
		0xD247FEAC11024E34ULL,
		0x4064B8BC283CE633ULL,
		0xDB539C11350195C0ULL,
		0x0BF3A8CE7782828FULL
	}};
	printf("Test Case 393\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x6452954C2348AA6CULL,
		0x24851DA73F265FEEULL,
		0x92F0492C570E32A9ULL,
		0x73841116439BE0C0ULL,
		0x7ADB45A62CA6DDC5ULL,
		0x295E17F9FD043DEBULL,
		0xBF3C6911B850FE54ULL,
		0x680E8757A93EC68CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAB33DECC4A0AAB1BULL,
		0xE26D868DC8B0F194ULL,
		0xB671019B3F64F4B7ULL,
		0xE59753EAD727D833ULL,
		0x0C17347CF42E463EULL,
		0xF42C6F4B4E7E69A9ULL,
		0x8CB9C734B6ABB055ULL,
		0xA14AFAD785F44C0BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCF614B8069420177ULL,
		0xC6E89B2AF796AE7AULL,
		0x248148B7686AC61EULL,
		0x961342FC94BC38F3ULL,
		0x76CC71DAD8889BFBULL,
		0xDD7278B2B37A5442ULL,
		0x3385AE250EFB4E01ULL,
		0xC9447D802CCA8A87ULL
	}};
	printf("Test Case 394\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x231E0D35A50AC6B8ULL,
		0xC5AE92118F13EE0AULL,
		0x35412B9409490BC4ULL,
		0xD73D2C264021AD54ULL,
		0x95FB789010EF6CB7ULL,
		0x908AFD953090AFCBULL,
		0x79641F1D2EB58943ULL,
		0x232DAEC411EE9DBFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF937B3E6D1522BC4ULL,
		0x8C1A04CE3CBBF681ULL,
		0xE1B1A75AEF440264ULL,
		0x0B4AE0BE1EBC43FAULL,
		0x74B483F928F40E7CULL,
		0xD4A7DAA00260194EULL,
		0xC2A671A93BF4910CULL,
		0x4F29D775A4EA9681ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDA29BED37458ED7CULL,
		0x49B496DFB3A8188BULL,
		0xD4F08CCEE60D09A0ULL,
		0xDC77CC985E9DEEAEULL,
		0xE14FFB69381B62CBULL,
		0x442D273532F0B685ULL,
		0xBBC26EB41541184FULL,
		0x6C0479B1B5040B3EULL
	}};
	printf("Test Case 395\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x13493ACA3458FC20ULL,
		0xDA8F65BF98BE4926ULL,
		0x0245C5496B63A2BCULL,
		0x069A2837F6C7D384ULL,
		0xD8D142CD3005BC97ULL,
		0x4DD1A13A77C00665ULL,
		0xAD67C4189CA6C3F2ULL,
		0x3966C5F12B9AF5ADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6F71C18820AAA5D4ULL,
		0x3C1C4429E1D9C311ULL,
		0x09649C777DE9827EULL,
		0xC4C2E5BDD91B05C1ULL,
		0x5E360F0E36853A60ULL,
		0xEEC8AEE75657C9D9ULL,
		0xE58522A0DFFB5844ULL,
		0x344E0784F645E150ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7C38FB4214F259F4ULL,
		0xE693219679678A37ULL,
		0x0B21593E168A20C2ULL,
		0xC258CD8A2FDCD645ULL,
		0x86E74DC3068086F7ULL,
		0xA3190FDD2197CFBCULL,
		0x48E2E6B8435D9BB6ULL,
		0x0D28C275DDDF14FDULL
	}};
	printf("Test Case 396\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x6A610DA0EAB8C578ULL,
		0x8BC40A407488B2A2ULL,
		0x761B9C06BDAF7D95ULL,
		0xC8F15752FF26E6D0ULL,
		0x32858FF8024517C6ULL,
		0x4E32BA59CFFBB213ULL,
		0xF3728D3172809469ULL,
		0xFA5FC66AB193985FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA1CD1A3C8554533CULL,
		0xA522D40470F65EBAULL,
		0x81B32DCBF56EA599ULL,
		0xA2B4EFCE474B153DULL,
		0xDC9E94EA5F224E75ULL,
		0x9688AC3DFC0771BAULL,
		0x0B599450A46DD3ECULL,
		0x17CFA3B3948327F1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCBAC179C6FEC9644ULL,
		0x2EE6DE44047EEC18ULL,
		0xF7A8B1CD48C1D80CULL,
		0x6A45B89CB86DF3EDULL,
		0xEE1B1B125D6759B3ULL,
		0xD8BA166433FCC3A9ULL,
		0xF82B1961D6ED4785ULL,
		0xED9065D92510BFAEULL
	}};
	printf("Test Case 397\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xB97DE97D34E10C7CULL,
		0x870359B4EFECFFF5ULL,
		0x49AE48F41F55FDD0ULL,
		0xFD1E254AB9977555ULL,
		0xB10DD7E1DB3FE5DAULL,
		0x84C89F28B76838ADULL,
		0xB062A918A5686F0AULL,
		0x9373961B25E72790ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3C7611331FA218B2ULL,
		0x78EBFC84AB1C8FFEULL,
		0xD9D7B22E6231687CULL,
		0xCDBFF9339E1FB651ULL,
		0x4F14E89B92E7359CULL,
		0xB30DE888B864C2E4ULL,
		0x39C05D04EB68AFFBULL,
		0x5F82B4BD4CA75435ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x850BF84E2B4314CEULL,
		0xFFE8A53044F0700BULL,
		0x9079FADA7D6495ACULL,
		0x30A1DC792788C304ULL,
		0xFE193F7A49D8D046ULL,
		0x37C577A00F0CFA49ULL,
		0x89A2F41C4E00C0F1ULL,
		0xCCF122A6694073A5ULL
	}};
	printf("Test Case 398\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x484091FC2AC0885DULL,
		0x65AADC30F22E21FFULL,
		0x7298A375812E9994ULL,
		0x2891A22E5C760FB6ULL,
		0x454F55E88D1A341FULL,
		0x713B64F113D967BFULL,
		0x582E50E76C2CBCD7ULL,
		0x0F6DA1F718DC2096ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF73B9A36E675B4EEULL,
		0x726ECDE9485D49BDULL,
		0xDB8BBF2444B44B53ULL,
		0xA1B901D52645959AULL,
		0xAE2939339E6AEB57ULL,
		0x4F2583526E698BAFULL,
		0x5739E383CF310F56ULL,
		0x9C4C4ADEE976A7A7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBF7B0BCACCB53CB3ULL,
		0x17C411D9BA736842ULL,
		0xA9131C51C59AD2C7ULL,
		0x8928A3FB7A339A2CULL,
		0xEB666CDB1370DF48ULL,
		0x3E1EE7A37DB0EC10ULL,
		0x0F17B364A31DB381ULL,
		0x9321EB29F1AA8731ULL
	}};
	printf("Test Case 399\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x457310CBB98DE99BULL,
		0xC337147677FE6A09ULL,
		0x4148C26C5963B822ULL,
		0x841AE86773438DCAULL,
		0xFEF02F15B798ECDDULL,
		0x4DA6F503D1A4B884ULL,
		0x5A386F518FE7D995ULL,
		0x83088DC6476AB1CBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB96126F8591C2CAFULL,
		0x49F01B0CB5851EB5ULL,
		0x981937D54B37E199ULL,
		0xB8A0C158866818D9ULL,
		0x21E40DF0084A0F4BULL,
		0x4AB3E1D57B521DA2ULL,
		0xD68CFF06D4F9052BULL,
		0x02F325C312DDA071ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFC123633E091C534ULL,
		0x8AC70F7AC27B74BCULL,
		0xD951F5B9125459BBULL,
		0x3CBA293FF52B9513ULL,
		0xDF1422E5BFD2E396ULL,
		0x071514D6AAF6A526ULL,
		0x8CB490575B1EDCBEULL,
		0x81FBA80555B711BAULL
	}};
	printf("Test Case 400\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xA5123A6CF22E03D5ULL,
		0x8FC0D7CE82E30AC3ULL,
		0x3E36BDF1A142AF1BULL,
		0x9238A7C314C9F721ULL,
		0x7E168716AFE1A73AULL,
		0xCA1D3FEFB8BFA7FBULL,
		0xAD874ED0E76F5E46ULL,
		0xF61050F12C95A2DCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x03AF70E51F5679B1ULL,
		0x1277EF927EA2FBD1ULL,
		0xED86C240F8D21D9FULL,
		0xEE239C19A52DFA0FULL,
		0x9F089ADADC625D5FULL,
		0xE2FA0802D18577B7ULL,
		0xE56AD52612AC8897ULL,
		0x98CB3526DA464337ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA6BD4A89ED787A64ULL,
		0x9DB7385CFC41F112ULL,
		0xD3B07FB15990B284ULL,
		0x7C1B3BDAB1E40D2EULL,
		0xE11E1DCC7383FA65ULL,
		0x28E737ED693AD04CULL,
		0x48ED9BF6F5C3D6D1ULL,
		0x6EDB65D7F6D3E1EBULL
	}};
	printf("Test Case 401\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x59917108FF29AD45ULL,
		0x61ED47D598EBAEABULL,
		0x2A1483D4C4EB65B2ULL,
		0x035F2A29452509A8ULL,
		0x53B55AF314763DF0ULL,
		0x9DAE50664A70328EULL,
		0xD1406E742B6C1294ULL,
		0x1EAD320D2210CD0AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFD30AEB209137EDEULL,
		0xD954594374675ECFULL,
		0xEBBE304A6CEE0D60ULL,
		0x67FA536A5C01379FULL,
		0x2071DE8E05053E0CULL,
		0xDC1DF540B78582E1ULL,
		0x91DC7FF79A0383F5ULL,
		0xA9FD5268C52E7875ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA4A1DFBAF63AD39BULL,
		0xB8B91E96EC8CF064ULL,
		0xC1AAB39EA80568D2ULL,
		0x64A5794319243E37ULL,
		0x73C4847D117303FCULL,
		0x41B3A526FDF5B06FULL,
		0x409C1183B16F9161ULL,
		0xB7506065E73EB57FULL
	}};
	printf("Test Case 402\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x4683C8C180EACCCEULL,
		0x3D521267D0F81A35ULL,
		0x159F3964FC5954DDULL,
		0xB0AC1D24BDE1EF44ULL,
		0x0C807528C7FCBB43ULL,
		0x8C98168AE2DBCF2FULL,
		0x5674EC71DB620350ULL,
		0x8077BA20694E66C8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6C9E7AB29E45AEC8ULL,
		0x8304ABBAD32F13CEULL,
		0x26A2402A283B314AULL,
		0xC43E535146B16ECEULL,
		0xD5D682F2976E3969ULL,
		0x921AE9F97E15A919ULL,
		0xA0EB2DB943330CF2ULL,
		0x5509542A9DE0F5A6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2A1DB2731EAF6206ULL,
		0xBE56B9DD03D709FBULL,
		0x333D794ED4626597ULL,
		0x74924E75FB50818AULL,
		0xD956F7DA5092822AULL,
		0x1E82FF739CCE6636ULL,
		0xF69FC1C898510FA2ULL,
		0xD57EEE0AF4AE936EULL
	}};
	printf("Test Case 403\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x3041FF89DB620B78ULL,
		0xB1F71A924D7E6612ULL,
		0x129E07F8F6CC581BULL,
		0x8FBFE15DD1FD7E98ULL,
		0xB0F71D31149F4FB5ULL,
		0xAB914980CF8E3C58ULL,
		0x1FAFB4CEEF024CB2ULL,
		0x4FADE9076E0AB294ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4B3DFA79BE14F00CULL,
		0xC5AE6205C2B23B35ULL,
		0x599DC43B0EA12D32ULL,
		0x105F0F10D4284AEAULL,
		0xA72E4E2E9CCAA616ULL,
		0x1C37F941E576B451ULL,
		0x0317E25E1D4FFE32ULL,
		0x74FB22A911F51877ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7B7C05F06576FB74ULL,
		0x745978978FCC5D27ULL,
		0x4B03C3C3F86D7529ULL,
		0x9FE0EE4D05D53472ULL,
		0x17D9531F8855E9A3ULL,
		0xB7A6B0C12AF88809ULL,
		0x1CB85690F24DB280ULL,
		0x3B56CBAE7FFFAAE3ULL
	}};
	printf("Test Case 404\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x3D8AD0ABC83DF070ULL,
		0x5B101CC2A85F617FULL,
		0x6B81930B68003D5BULL,
		0x72AB9AC813B7EFA3ULL,
		0x15131AA63A92B09DULL,
		0x792F0AAC4249364EULL,
		0x48DB6B8FA52631A4ULL,
		0x56378A1443067297ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBDFA8556FA36FF3CULL,
		0x34D711227AA37955ULL,
		0x3845979FB91BD9D5ULL,
		0x2ADAA4B290E8F9FAULL,
		0xFF0D4523BEB36130ULL,
		0x4261AF352E963B5FULL,
		0xDB17373C28C51787ULL,
		0xD2F7C58C52BCE624ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x807055FD320B0F4CULL,
		0x6FC70DE0D2FC182AULL,
		0x53C40494D11BE48EULL,
		0x58713E7A835F1659ULL,
		0xEA1E5F858421D1ADULL,
		0x3B4EA5996CDF0D11ULL,
		0x93CC5CB38DE32623ULL,
		0x84C04F9811BA94B3ULL
	}};
	printf("Test Case 405\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xF02B1E31567382E7ULL,
		0x82A03F72F2822355ULL,
		0x7F9336EEC609E263ULL,
		0x24DBF9CE0A52401AULL,
		0x66BD37DCD2DC1A25ULL,
		0xF7386548BFE2571DULL,
		0xC8188E1F9D9E479FULL,
		0x025E895ED39DB3D4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6918CE22A61DB13EULL,
		0xA7A7D372C9B261A7ULL,
		0xD88033BE515EEFA2ULL,
		0x02A1CB2D5FCCC1B9ULL,
		0xAAED0BBE446E395AULL,
		0x83AB1CBFCD0000EBULL,
		0x4818FB73B6D49D37ULL,
		0x4F4AD8CC03EEAC18ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9933D013F06E33D9ULL,
		0x2507EC003B3042F2ULL,
		0xA713055097570DC1ULL,
		0x267A32E3559E81A3ULL,
		0xCC503C6296B2237FULL,
		0x749379F772E257F6ULL,
		0x8000756C2B4ADAA8ULL,
		0x4D145192D0731FCCULL
	}};
	printf("Test Case 406\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x3A58139D6B060D09ULL,
		0xCA7EA91ADB114221ULL,
		0x5E9C0F5F7D45FD1DULL,
		0xF97AB3A371F05C31ULL,
		0x42270E8D6347C710ULL,
		0xFD1B5D4D16C4638AULL,
		0xC121A3A3F40AFDCDULL,
		0x44132267E079ED8CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9E600F09B87D9E0EULL,
		0xA33306F18FE80C86ULL,
		0xC20B732A8C3E7A69ULL,
		0x773F2439B4930692ULL,
		0x1D468BA815C607A0ULL,
		0x074000E2614A6594ULL,
		0x21DABD25A3040419ULL,
		0x0B1EB956DD6170ADULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA4381C94D37B9307ULL,
		0x694DAFEB54F94EA7ULL,
		0x9C977C75F17B8774ULL,
		0x8E45979AC5635AA3ULL,
		0x5F6185257681C0B0ULL,
		0xFA5B5DAF778E061EULL,
		0xE0FB1E86570EF9D4ULL,
		0x4F0D9B313D189D21ULL
	}};
	printf("Test Case 407\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x504B169122400E4BULL,
		0xE9B796A978BB678EULL,
		0xDEB0ECB1ABF9E857ULL,
		0x79221E3D896B2B19ULL,
		0x7C62D24C05183AD8ULL,
		0xAD4F95DCECF7B2D9ULL,
		0x8A43AC27CE7E1476ULL,
		0x1FA3273C2D7CF526ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1BFA46DE9285B631ULL,
		0xE10EF93B79BAEC55ULL,
		0xF429FF2F41AF4BD8ULL,
		0x5A1F6D791BC63B3CULL,
		0x84D79DD9EAC95AE8ULL,
		0x14C4C71762DEC228ULL,
		0x1DDEDA0567BAB77BULL,
		0x7654CEFCA8DFD31BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4BB1504FB0C5B87AULL,
		0x08B96F9201018BDBULL,
		0x2A99139EEA56A38FULL,
		0x233D734492AD1025ULL,
		0xF8B54F95EFD16030ULL,
		0xB98B52CB8E2970F1ULL,
		0x979D7622A9C4A30DULL,
		0x69F7E9C085A3263DULL
	}};
	printf("Test Case 408\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x8948E1EF5FB0BBD0ULL,
		0x729842B52E0B9E73ULL,
		0xF61D2D6205DABD28ULL,
		0xB1E8739F164CFE52ULL,
		0xCB533C4EAB78233BULL,
		0xEF469839004CA54FULL,
		0x776E9231D1C0047EULL,
		0x7F49C00000C82E77ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC80644E0D23A0B57ULL,
		0xA8D71EDF266372E1ULL,
		0xA0C91C0E1A375AAEULL,
		0x680295159CF369ECULL,
		0xB4889D24D7BA9528ULL,
		0xF623897BD286A27BULL,
		0xD3CBB3BBB952CB91ULL,
		0x0DB630D090A2BB03ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x414EA50F8D8AB087ULL,
		0xDA4F5C6A0868EC92ULL,
		0x56D4316C1FEDE786ULL,
		0xD9EAE68A8ABF97BEULL,
		0x7FDBA16A7CC2B613ULL,
		0x19651142D2CA0734ULL,
		0xA4A5218A6892CFEFULL,
		0x72FFF0D0906A9574ULL
	}};
	printf("Test Case 409\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xBBD3042D37F3E950ULL,
		0xD029E7C30B748583ULL,
		0x356CA60254CFBD2CULL,
		0x005B01A73A3EF575ULL,
		0xB01AAC7946B3BAEDULL,
		0xFBF749746DE99082ULL,
		0xF069291ED1B4356FULL,
		0xAD031FB92EED76A3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x971AEA6D4D971EA2ULL,
		0x7C1041B2EBE0DFC1ULL,
		0x17CB1C7E9F36F717ULL,
		0x563FEAD476B9FB96ULL,
		0xA5603F010CD1D3C2ULL,
		0x87ED9BB5218B3925ULL,
		0x74B15E1B3B8C63FBULL,
		0xB1556F5FDC07538DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2CC9EE407A64F7F2ULL,
		0xAC39A671E0945A42ULL,
		0x22A7BA7CCBF94A3BULL,
		0x5664EB734C870EE3ULL,
		0x157A93784A62692FULL,
		0x7C1AD2C14C62A9A7ULL,
		0x84D87705EA385694ULL,
		0x1C5670E6F2EA252EULL
	}};
	printf("Test Case 410\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x6BEA4652A598F3E9ULL,
		0xC65FF94B4331C404ULL,
		0x1D3B0BC3A0275837ULL,
		0x32F988381B13CC6EULL,
		0x57A35B248BACE781ULL,
		0x4C7FCE737338F292ULL,
		0x747051FE51DB1FC0ULL,
		0x3A6F1840814BA6AEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC4DD065DC3E9F8E2ULL,
		0x73E28CAB35D75BC7ULL,
		0x61B2206C87040962ULL,
		0x3C6C55F5D878E3E9ULL,
		0xE897360D01DDF796ULL,
		0xDB0806D7455475A7ULL,
		0x4A033B0E9B55B1B0ULL,
		0x2E2B54C46943C4D8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAF37400F66710B0BULL,
		0xB5BD75E076E69FC3ULL,
		0x7C892BAF27235155ULL,
		0x0E95DDCDC36B2F87ULL,
		0xBF346D298A711017ULL,
		0x9777C8A4366C8735ULL,
		0x3E736AF0CA8EAE70ULL,
		0x14444C84E8086276ULL
	}};
	printf("Test Case 411\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xB6B5554EE9CD8FFEULL,
		0x419CACA212A3EC5EULL,
		0xA19A00219B54DCE8ULL,
		0xE749753F46EFF84AULL,
		0xA2C7169BBA42BB63ULL,
		0x1179C95120A6D1E5ULL,
		0x89B42DEB361ADD9EULL,
		0xCC6D3152BA4FF17CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB2BDAE5DB9808400ULL,
		0x1F0122A57350F01AULL,
		0x224B49DCF2635A70ULL,
		0x974FDD63AD985897ULL,
		0x2517A4EEF766565BULL,
		0x6463DED84F6D3848ULL,
		0x02E4C9128AB1A5A2ULL,
		0x31E155651922675DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0408FB13504D0BFEULL,
		0x5E9D8E0761F31C44ULL,
		0x83D149FD69378698ULL,
		0x7006A85CEB77A0DDULL,
		0x87D0B2754D24ED38ULL,
		0x751A17896FCBE9ADULL,
		0x8B50E4F9BCAB783CULL,
		0xFD8C6437A36D9621ULL
	}};
	printf("Test Case 412\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xA1167057630A1208ULL,
		0x7476EF7A4988C886ULL,
		0x20B28E68EFF75B43ULL,
		0x47D420443DA74E09ULL,
		0x0A1B9E34A6ABEFBBULL,
		0x05964AEBAF5503A8ULL,
		0x84A296EBFF232877ULL,
		0x876F3DFCF46C62BCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE7586A7FA097C610ULL,
		0x2D5AD8DAF9F2C93FULL,
		0x728EBEFBE5D96A93ULL,
		0x3113708EDC9543CCULL,
		0xC9A918BCC67BDD88ULL,
		0xECE1BE100F6A7A41ULL,
		0x21DA88358789C341ULL,
		0x53C069B7A794DB53ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x464E1A28C39DD418ULL,
		0x592C37A0B07A01B9ULL,
		0x523C30930A2E31D0ULL,
		0x76C750CAE1320DC5ULL,
		0xC3B2868860D03233ULL,
		0xE977F4FBA03F79E9ULL,
		0xA5781EDE78AAEB36ULL,
		0xD4AF544B53F8B9EFULL
	}};
	printf("Test Case 413\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xFC254B7FC33123B9ULL,
		0x55C7268EA4133891ULL,
		0x5144EAC946AC6E2AULL,
		0x7BDDAC614FD9E9BDULL,
		0x9A105652C4941B68ULL,
		0xFA42A7279E749340ULL,
		0x3469001A9D07CFC8ULL,
		0x8449EAA043B8CFAEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8B3B603B91CD1CA8ULL,
		0xA731ADDF84201F56ULL,
		0x31407DCB80F1AACFULL,
		0x617501348D100C84ULL,
		0x5F9A3467888263B6ULL,
		0xE25A17F9A032E5A8ULL,
		0xBBB1BB81226A0088ULL,
		0x548C877A66303F30ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x771E2B4452FC3F11ULL,
		0xF2F68B51203327C7ULL,
		0x60049702C65DC4E5ULL,
		0x1AA8AD55C2C9E539ULL,
		0xC58A62354C1678DEULL,
		0x1818B0DE3E4676E8ULL,
		0x8FD8BB9BBF6DCF40ULL,
		0xD0C56DDA2588F09EULL
	}};
	printf("Test Case 414\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x577832759414CB0AULL,
		0x7BCD49B2803C2D33ULL,
		0x5077AF9EB9637B89ULL,
		0x2693F96DD3342576ULL,
		0x5BB3B38DFCFD9E48ULL,
		0x36E4259F807442A5ULL,
		0xD644AF686CA1B6FCULL,
		0xC6B8F6150D8E5273ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5AA9BF1799E933C1ULL,
		0x36975A078071EC46ULL,
		0xB0E1D11064D4CFF9ULL,
		0x3A6F7DAA657A5DE7ULL,
		0x05097405F1EA8D2AULL,
		0xE6463F6615016350ULL,
		0x87F9F4040851EC51ULL,
		0x8538A4A401621AE3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0DD18D620DFDF8CBULL,
		0x4D5A13B5004DC175ULL,
		0xE0967E8EDDB7B470ULL,
		0x1CFC84C7B64E7891ULL,
		0x5EBAC7880D171362ULL,
		0xD0A21AF9957521F5ULL,
		0x51BD5B6C64F05AADULL,
		0x438052B10CEC4890ULL
	}};
	printf("Test Case 415\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x85C7896763513D8CULL,
		0x146F26A5679673D2ULL,
		0x3E67426BD899B30CULL,
		0x29B87D9039F7EE21ULL,
		0x36D40952317BC573ULL,
		0x80F427CC78B17E23ULL,
		0x617C4323392C0838ULL,
		0x07D33B91F18E9F00ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x859E38E28FC5BECEULL,
		0x7E9F61C8B28DEB69ULL,
		0x2C5E78A27F0C1CABULL,
		0xA2408AD855611FCCULL,
		0xAC10292BE9206ED1ULL,
		0x886F03B0460B4A74ULL,
		0x7B24AB87D62F5172ULL,
		0xBBF8CA4F1E935269ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0059B185EC948342ULL,
		0x6AF0476DD51B98BBULL,
		0x12393AC9A795AFA7ULL,
		0x8BF8F7486C96F1EDULL,
		0x9AC42079D85BABA2ULL,
		0x089B247C3EBA3457ULL,
		0x1A58E8A4EF03594AULL,
		0xBC2BF1DEEF1DCD69ULL
	}};
	printf("Test Case 416\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x07BF6B0E53743B73ULL,
		0x7F0952C61703CC92ULL,
		0xDFAFFE4BF27E0C1CULL,
		0x2776151500841DD0ULL,
		0xBF5CAAF96DA2B097ULL,
		0x80DA6BCCC5CFE484ULL,
		0xBD0C319375E777C5ULL,
		0xCD5236BDDD2F56ABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x61F5D3ABF7305690ULL,
		0xB289286EC78A7168ULL,
		0xFB22EF204EAD21C6ULL,
		0xFB93B7BD030C7233ULL,
		0xD550A4176107949CULL,
		0x6CEE29AC8A3D8659ULL,
		0x74D2A347376ECC4BULL,
		0x6604FAFDB20A8B26ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x664AB8A5A4446DE3ULL,
		0xCD807AA8D089BDFAULL,
		0x248D116BBCD32DDAULL,
		0xDCE5A2A803886FE3ULL,
		0x6A0C0EEE0CA5240BULL,
		0xEC3442604FF262DDULL,
		0xC9DE92D44289BB8EULL,
		0xAB56CC406F25DD8DULL
	}};
	printf("Test Case 417\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x5D2A9853BF496A72ULL,
		0xA833A1B2D2EDAB6EULL,
		0x497CAEB559FDBC3AULL,
		0x5CC586DD47A0FC53ULL,
		0x5636B419F151CDBFULL,
		0xCC20D4B28B80A1CAULL,
		0xE3F6302F1FC9E8CDULL,
		0xB52DAB823E94236EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6E441B9EFF414BC4ULL,
		0x0E2617F775463DA7ULL,
		0xDE0E65A43440E41AULL,
		0x108286269157B5CAULL,
		0x729C08B4EF7E780BULL,
		0xF9413A16F291029CULL,
		0x7A85B40AB2BEEFB8ULL,
		0x2A8EF2F63A0833C8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x336E83CD400821B6ULL,
		0xA615B645A7AB96C9ULL,
		0x9772CB116DBD5820ULL,
		0x4C4700FBD6F74999ULL,
		0x24AABCAD1E2FB5B4ULL,
		0x3561EEA47911A356ULL,
		0x99738425AD770775ULL,
		0x9FA35974049C10A6ULL
	}};
	printf("Test Case 418\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x8090EEB07C9D4C1CULL,
		0xEE5F6BECC0778E23ULL,
		0xEC64E86364ABD4AAULL,
		0xCEF2BEA791B995FFULL,
		0x61E614D223AAA5B1ULL,
		0xC1AC1F55109F8447ULL,
		0xC1540EADE2ED19BEULL,
		0x3A4F943E686CB0B2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB45DB483377F121BULL,
		0xC1DF51AA311A9092ULL,
		0x858294EAEDF30858ULL,
		0xA05C97EBE4A600BCULL,
		0x24DEF0B9628C8CB0ULL,
		0x712693FDE764AADCULL,
		0x306C53C0D0EB25F7ULL,
		0xF50D9F393453081FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x34CD5A334BE25E07ULL,
		0x2F803A46F16D1EB1ULL,
		0x69E67C898958DCF2ULL,
		0x6EAE294C751F9543ULL,
		0x4538E46B41262901ULL,
		0xB08A8CA8F7FB2E9BULL,
		0xF1385D6D32063C49ULL,
		0xCF420B075C3FB8ADULL
	}};
	printf("Test Case 419\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x4C4A4BA4A3F9984CULL,
		0xF72C9BAB681F1BA2ULL,
		0x017963929376A0E6ULL,
		0x29DBCD6D67871577ULL,
		0x0654C9872EF71A34ULL,
		0x16CA7EE9EFBE5AEBULL,
		0x216AC3C49BD9031FULL,
		0x5F649F00753AB9BFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5F5434C633ABFABDULL,
		0xCDCEEE23F56D83AAULL,
		0xFDF215F67AE6092EULL,
		0x05EC7136F5E80B59ULL,
		0xFC55FA16E3D4076DULL,
		0x73E6D328878856D5ULL,
		0x96B101C2B2D6F8FBULL,
		0x8CB9E7BF26EEC769ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x131E7F62905262F1ULL,
		0x3AE275889D729808ULL,
		0xFC8B7664E990A9C8ULL,
		0x2C37BC5B926F1E2EULL,
		0xFA013391CD231D59ULL,
		0x652CADC168360C3EULL,
		0xB7DBC206290FFBE4ULL,
		0xD3DD78BF53D47ED6ULL
	}};
	printf("Test Case 420\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xF7F6547EF8D407F1ULL,
		0xAA2FB5A2098F3E2AULL,
		0x0FB4AADA364C6D35ULL,
		0x97C18BDBDC529363ULL,
		0x76E1E6D18A7913C3ULL,
		0xF4728906871DA60FULL,
		0x8AB6C5236A12016CULL,
		0xB3D20CFA3A358EF9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8A433DD82BB0ED5AULL,
		0xE6108B1B7943C6FCULL,
		0x04077E26700F6E1EULL,
		0xCB69BD1F9BFEDF5AULL,
		0xCCF3DD3C355A0B0BULL,
		0x3EF8A6862DB49D8BULL,
		0xEAE42113F2293B19ULL,
		0x6A05885EA8EA234FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7DB569A6D364EAABULL,
		0x4C3F3EB970CCF8D6ULL,
		0x0BB3D4FC4643032BULL,
		0x5CA836C447AC4C39ULL,
		0xBA123BEDBF2318C8ULL,
		0xCA8A2F80AAA93B84ULL,
		0x6052E430983B3A75ULL,
		0xD9D784A492DFADB6ULL
	}};
	printf("Test Case 421\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x63EEEA2C84EB5461ULL,
		0xB8B7FFCF5279F4CCULL,
		0x315994E50C9BFDD6ULL,
		0xD8FA8D0927008B82ULL,
		0x5E4B44E0900B5048ULL,
		0x6BD6C1312D6BFE39ULL,
		0x2FABD50499E01B90ULL,
		0x01C4339616C26114ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x413FA3D3CCAF3D22ULL,
		0xD1B7C4F3115074FFULL,
		0xE12BCC4758BC0153ULL,
		0xBEAA4471780FE5AFULL,
		0x15142B3929B1CC40ULL,
		0x73EBD76EFD8DEACDULL,
		0x7E504309A5AF8C93ULL,
		0x46DA9A564B552135ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x22D149FF48446943ULL,
		0x69003B3C43298033ULL,
		0xD07258A25427FC85ULL,
		0x6650C9785F0F6E2DULL,
		0x4B5F6FD9B9BA9C08ULL,
		0x183D165FD0E614F4ULL,
		0x51FB960D3C4F9703ULL,
		0x471EA9C05D974021ULL
	}};
	printf("Test Case 422\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xBDFB124E980B8672ULL,
		0xAC5817A52DC4B7E6ULL,
		0x8B0B7A8DB37CC088ULL,
		0xAD4759EB26AD0EBAULL,
		0x6077D34601D282CCULL,
		0xECBAA4D55E527B15ULL,
		0xAB0C1623BEDE3C18ULL,
		0x43B8B504D760CA9DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x73B0F469BADF1D0EULL,
		0x8C83E4CB615E75CCULL,
		0x06007AF99A939E07ULL,
		0xF5A5BFC8801346FBULL,
		0x3BD79A35F4334276ULL,
		0x2C7538BDC5997B9CULL,
		0x627E872BB6E14A0CULL,
		0x14A09B1CE8B2DFF1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCE4BE62722D49B7CULL,
		0x20DBF36E4C9AC22AULL,
		0x8D0B007429EF5E8FULL,
		0x58E2E623A6BE4841ULL,
		0x5BA04973F5E1C0BAULL,
		0xC0CF9C689BCB0089ULL,
		0xC9729108083F7614ULL,
		0x57182E183FD2156CULL
	}};
	printf("Test Case 423\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xB3FBEDF614FD69AAULL,
		0x4A528EF7E7FEAD79ULL,
		0x9A3DA82DF144AA9EULL,
		0x3225E0D1FB6242D6ULL,
		0xC7942B92A9818972ULL,
		0x7F30E58A044126B7ULL,
		0x1E775CEFB0035CA3ULL,
		0x710B7F48514885A3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x609A847271C4E84CULL,
		0xDEFBEEC61B06D2E2ULL,
		0xC53500A910E88690ULL,
		0x99526765073CDEB2ULL,
		0xE71DED598C59058FULL,
		0x90A0688A5CED0DD1ULL,
		0x38638E650D8362BFULL,
		0x6BE9F7F24CEC7F69ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD3616984653981E6ULL,
		0x94A96031FCF87F9BULL,
		0x5F08A884E1AC2C0EULL,
		0xAB7787B4FC5E9C64ULL,
		0x2089C6CB25D88CFDULL,
		0xEF908D0058AC2B66ULL,
		0x2614D28ABD803E1CULL,
		0x1AE288BA1DA4FACAULL
	}};
	printf("Test Case 424\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xEAE673A3F685DEC6ULL,
		0x8918D8EF56278877ULL,
		0x9904723D18C4F126ULL,
		0x4403390BE6F5E401ULL,
		0xBC88332DF4D804ACULL,
		0x39DBC98FD1FE3305ULL,
		0x2E8EF10C07197CEEULL,
		0x8B047A83CAF741DFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC6E59A81AEA04BEEULL,
		0x365DC8338C0BDEA6ULL,
		0xA18E085287D020B7ULL,
		0xEBC7357B8DCFF371ULL,
		0x1B1DB26AAB0ED31DULL,
		0xD98AAC832E758458ULL,
		0x06B445859CAE4974ULL,
		0xCE29E5C8D7E4251BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2C03E92258259528ULL,
		0xBF4510DCDA2C56D1ULL,
		0x388A7A6F9F14D191ULL,
		0xAFC40C706B3A1770ULL,
		0xA79581475FD6D7B1ULL,
		0xE051650CFF8BB75DULL,
		0x283AB4899BB7359AULL,
		0x452D9F4B1D1364C4ULL
	}};
	printf("Test Case 425\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xB52169275038CD97ULL,
		0x24A57AA88A1CF616ULL,
		0x1976168F613264DEULL,
		0x6A91260D74833C90ULL,
		0xCA51D210C20B123AULL,
		0xF398E97CCCB8155FULL,
		0xD1AAFABBB2C529E0ULL,
		0x9741AA7846FE1E8EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x81DD29EC56B59059ULL,
		0x37732777BFF3B9D3ULL,
		0x80E3AD8A0625A861ULL,
		0x26C2853453E56E9AULL,
		0xE7801FA81885E8E0ULL,
		0x1358E162FB8EC593ULL,
		0x251C140B3D0667FAULL,
		0xD3E1D97D4D68A8D6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x34FC40CB068D5DCEULL,
		0x13D65DDF35EF4FC5ULL,
		0x9995BB056717CCBFULL,
		0x4C53A3392766520AULL,
		0x2DD1CDB8DA8EFADAULL,
		0xE0C0081E3736D0CCULL,
		0xF4B6EEB08FC34E1AULL,
		0x44A073050B96B658ULL
	}};
	printf("Test Case 426\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xC1A07FDDB07A63CDULL,
		0x61AA08A2A80B3226ULL,
		0x0BA1FB16B27068B7ULL,
		0xE8AE7E717C44580AULL,
		0x1C5691A946542865ULL,
		0x684329F520A85661ULL,
		0x47A45B1E2445EF6AULL,
		0x3F0AE8CF975C924DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE2C5489075388218ULL,
		0x49D8D87CBF2C4070ULL,
		0xB095B3FC44233AD5ULL,
		0x82154F5D075534B6ULL,
		0x53974A7D2C7C123FULL,
		0x9ADC87D2DA80986AULL,
		0xAE87CAA3FCB330B4ULL,
		0x901FC848501DABF5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2365374DC542E1D5ULL,
		0x2872D0DE17277256ULL,
		0xBB3448EAF6535262ULL,
		0x6ABB312C7B116CBCULL,
		0x4FC1DBD46A283A5AULL,
		0xF29FAE27FA28CE0BULL,
		0xE92391BDD8F6DFDEULL,
		0xAF152087C74139B8ULL
	}};
	printf("Test Case 427\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x7D4051162543D067ULL,
		0x866A2C0E428AE88FULL,
		0x23CF7B1CE7544D4DULL,
		0x3CE31E7A26C756E7ULL,
		0x7AE2D24036D396BCULL,
		0x5EBCA1B1A04D3BE2ULL,
		0xFCC90D6C54F8DC6EULL,
		0x737A89616770BC32ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD1B422A1C7902FBDULL,
		0xFBB292F59DD00CB3ULL,
		0x827FD593AE6CA5E1ULL,
		0x4C983C8985DFE55AULL,
		0x15622E1A5DCF1ED0ULL,
		0x7C6CD5889E5A81A7ULL,
		0x845444D8E4013D3CULL,
		0xD70DACB58085C739ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xACF473B7E2D3FFDAULL,
		0x7DD8BEFBDF5AE43CULL,
		0xA1B0AE8F4938E8ACULL,
		0x707B22F3A318B3BDULL,
		0x6F80FC5A6B1C886CULL,
		0x22D074393E17BA45ULL,
		0x789D49B4B0F9E152ULL,
		0xA47725D4E7F57B0BULL
	}};
	printf("Test Case 428\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x63C205308B5F1A4DULL,
		0x193AF5C47A962E8FULL,
		0xBD39893DD4188586ULL,
		0x0F00499A2B09F9EAULL,
		0x6C0833E4A374E9EDULL,
		0x86A4A308752760C7ULL,
		0x41C8C2448816C293ULL,
		0xDD90D1DA17A88AB0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x178AA22074E442FBULL,
		0x01A02AE700C08A73ULL,
		0x29817BB6D0287333ULL,
		0x1E57B509C9A9DB25ULL,
		0x9E7AB08748444EAAULL,
		0x64239F25C77E74C9ULL,
		0xC1E51F5BA7BE1958ULL,
		0x851086D676CE501BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7448A710FFBB58B6ULL,
		0x189ADF237A56A4FCULL,
		0x94B8F28B0430F6B5ULL,
		0x1157FC93E2A022CFULL,
		0xF2728363EB30A747ULL,
		0xE2873C2DB259140EULL,
		0x802DDD1F2FA8DBCBULL,
		0x5880570C6166DAABULL
	}};
	printf("Test Case 429\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x538939DE2F98AD27ULL,
		0x65CB30A67FB596D6ULL,
		0x49A451E2EC323EB3ULL,
		0x2F59327A70A1ABF6ULL,
		0xEC2E003004A7660AULL,
		0x9B9D039AFBD280E9ULL,
		0x02672A1710FDD676ULL,
		0xD2D69ED46AD7B102ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x436FE0B3F6CCD24EULL,
		0xF411BB224787B02CULL,
		0x2A15AACB5119AE8CULL,
		0xA335AA5B57AE31C3ULL,
		0x9727F451617AF541ULL,
		0x05BE43077C292A1DULL,
		0x0AA9B62E2412567CULL,
		0x172382700139790AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x10E6D96DD9547F69ULL,
		0x91DA8B84383226FAULL,
		0x63B1FB29BD2B903FULL,
		0x8C6C9821270F9A35ULL,
		0x7B09F46165DD934BULL,
		0x9E23409D87FBAAF4ULL,
		0x08CE9C3934EF800AULL,
		0xC5F51CA46BEEC808ULL
	}};
	printf("Test Case 430\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xE1B55A6908CF8BFBULL,
		0x7782B8AD35A5EFB4ULL,
		0x090074B4F63F35CEULL,
		0xFC2DDF3D359050B9ULL,
		0x0CA471DE5763C027ULL,
		0x191A17A6AB2B2E91ULL,
		0xD8FD0B955A6EF9ABULL,
		0x127B3AF2EE61EAB0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x99DE7E7D3FC0257AULL,
		0x8DD6525FFB51C7B5ULL,
		0x4EEF6F20738CA554ULL,
		0x5D9A56BC316C6A15ULL,
		0x3CECCDA0099CA416ULL,
		0xC4E07BAD0912117BULL,
		0x3A11A25997BC9732ULL,
		0xA8FED399AC86D6E7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x786B2414370FAE81ULL,
		0xFA54EAF2CEF42801ULL,
		0x47EF1B9485B3909AULL,
		0xA1B7898104FC3AACULL,
		0x3048BC7E5EFF6431ULL,
		0xDDFA6C0BA2393FEAULL,
		0xE2ECA9CCCDD26E99ULL,
		0xBA85E96B42E73C57ULL
	}};
	printf("Test Case 431\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x5F90E91840FEB8F2ULL,
		0x5C147F1678EFCD88ULL,
		0x24D7F173EA8D57D7ULL,
		0xE50A4E5D64AEE693ULL,
		0x692D16FE0EDA1C96ULL,
		0x54E9AEA74EB2A847ULL,
		0x1D7D80A60AA832B0ULL,
		0x6C6E53D67FBBC490ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x21302F5C1044037EULL,
		0x05B6FCF4F4D62584ULL,
		0x2D480E461E1DFE9DULL,
		0xFEBE2CED040C4576ULL,
		0x31EDA04E7155DEBDULL,
		0xE37A071FC8EF79F6ULL,
		0x6230F15A2F8CB46FULL,
		0x104AB0173279E4E5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7EA0C64450BABB8CULL,
		0x59A283E28C39E80CULL,
		0x099FFF35F490A94AULL,
		0x1BB462B060A2A3E5ULL,
		0x58C0B6B07F8FC22BULL,
		0xB793A9B8865DD1B1ULL,
		0x7F4D71FC252486DFULL,
		0x7C24E3C14DC22075ULL
	}};
	printf("Test Case 432\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x8DFD38FC3CBFFFDAULL,
		0x667AE5FCE905E4C5ULL,
		0x606E6EBEC8C23373ULL,
		0x4FF89CE77ACEE3D7ULL,
		0x0DC05ACDE8D58A0CULL,
		0x0D97D84C55567621ULL,
		0x2EA8AC49404C8076ULL,
		0x07D7251787A46E59ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x605ADAADF8E55753ULL,
		0xE34E17EE21D096AAULL,
		0xA2EAA6398AEEA525ULL,
		0xA17CA5D105C8D712ULL,
		0x2245E895371958D6ULL,
		0x6503D6CCB82CA394ULL,
		0x59FF07E60ABEE267ULL,
		0x368EEDB59CA59E8DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEDA7E251C45AA889ULL,
		0x8534F212C8D5726FULL,
		0xC284C887422C9656ULL,
		0xEE8439367F0634C5ULL,
		0x2F85B258DFCCD2DAULL,
		0x68940E80ED7AD5B5ULL,
		0x7757ABAF4AF26211ULL,
		0x3159C8A21B01F0D4ULL
	}};
	printf("Test Case 433\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xB5A84900AA3C8BF9ULL,
		0xBD44B93B3C9AD123ULL,
		0x5FB9682A5EEBF14BULL,
		0x6E4BCFBB969D14D2ULL,
		0x8BDE6A3E5EC4BFCFULL,
		0x42AF29D257C7EA95ULL,
		0x701AA95A5620E58BULL,
		0x7724AD75B2AEB76BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4ED23AF9FBEFFA50ULL,
		0xABA29E5F6FE42714ULL,
		0x64DA3290243CE42FULL,
		0x8928A4EC1909246CULL,
		0x5F4B3FEDC563D138ULL,
		0x2D3BB18483245282ULL,
		0x6FD3D9B6F7B33248ULL,
		0xEFBC27239ED4A9CDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFB7A73F951D371A9ULL,
		0x16E62764537EF637ULL,
		0x3B635ABA7AD71564ULL,
		0xE7636B578F9430BEULL,
		0xD49555D39BA76EF7ULL,
		0x6F949856D4E3B817ULL,
		0x1FC970ECA193D7C3ULL,
		0x98988A562C7A1EA6ULL
	}};
	printf("Test Case 434\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x9A536BCB4743BC05ULL,
		0x49209119942BDF5DULL,
		0x9914253D890ADA90ULL,
		0xD39A999FF2D9E4FAULL,
		0xB65BC5C8EF955620ULL,
		0x894FAA70B8BAF49EULL,
		0x661A0BEA445A4B93ULL,
		0xE8CBE0875BEF4FD9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8C7C9E2AA0CDCBE6ULL,
		0x0EBC97E317B06C0CULL,
		0x3D0114E0CCF62AC1ULL,
		0x68EDCCDE309C3308ULL,
		0xDA51B637ECEB00CCULL,
		0x309AEF351F51A28AULL,
		0xB9FA74778CC378CCULL,
		0xAE0B59A85081AF88ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x162FF5E1E78E77E3ULL,
		0x479C06FA839BB351ULL,
		0xA41531DD45FCF051ULL,
		0xBB775541C245D7F2ULL,
		0x6C0A73FF037E56ECULL,
		0xB9D54545A7EB5614ULL,
		0xDFE07F9DC899335FULL,
		0x46C0B92F0B6EE051ULL
	}};
	printf("Test Case 435\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x091CA37348AFEF2DULL,
		0x18D96718FB812161ULL,
		0x298E4F4AB2CF90A0ULL,
		0x61BC86E367A57E0EULL,
		0xA1E30B2BD6FF6E52ULL,
		0x0EDF6CBB1D404056ULL,
		0x15D7835DB7FB0E3FULL,
		0xF448769A3FDB2606ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9D40CD6ABC328543ULL,
		0xFEACADA1AF90FF91ULL,
		0x40331DBE5CDF3C25ULL,
		0x2CA19167673ED86DULL,
		0xA80CA13E78D1B1BCULL,
		0x918F35CF1E4B393AULL,
		0xB6DE75185ACABAC3ULL,
		0x14A6807997B52C3DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x945C6E19F49D6A6EULL,
		0xE675CAB95411DEF0ULL,
		0x69BD52F4EE10AC85ULL,
		0x4D1D1784009BA663ULL,
		0x09EFAA15AE2EDFEEULL,
		0x9F505974030B796CULL,
		0xA309F645ED31B4FCULL,
		0xE0EEF6E3A86E0A3BULL
	}};
	printf("Test Case 436\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xAC74B339F5CF5773ULL,
		0xF040EFEEF9F2FFC1ULL,
		0x4180496AFD0FD7C2ULL,
		0xF9A13DB032B49595ULL,
		0x5E7D92E3597C6DB5ULL,
		0x6A9C794CAC54DB7BULL,
		0x20D959B03F2E8240ULL,
		0x7F7107459CA22EEBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEDAE0A764C441A53ULL,
		0xB296F273B6102FBAULL,
		0xF69E733E1A144551ULL,
		0xE676F62B726A2B4AULL,
		0xF106117C000C40CEULL,
		0x7E66BD9092F66C3FULL,
		0xC896D4DE56B52195ULL,
		0x2D383E75C528A006ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x41DAB94FB98B4D20ULL,
		0x42D61D9D4FE2D07BULL,
		0xB71E3A54E71B9293ULL,
		0x1FD7CB9B40DEBEDFULL,
		0xAF7B839F59702D7BULL,
		0x14FAC4DC3EA2B744ULL,
		0xE84F8D6E699BA3D5ULL,
		0x52493930598A8EEDULL
	}};
	printf("Test Case 437\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x7E674B2629D29F37ULL,
		0x3A95B3685AFD86B8ULL,
		0xA754934EA7E49E67ULL,
		0x382552A23F22EA06ULL,
		0xB849359A8985AF15ULL,
		0x014E04AE2253AE48ULL,
		0x68F2850B103B7E25ULL,
		0xEEF3C4989EF27F36ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x51B517DADFBA480EULL,
		0x2A1FA6CD2990A0F5ULL,
		0x8D89468B7F0FA7BDULL,
		0xC2A7AB73A2C6AE9FULL,
		0xF483835E79FE6C71ULL,
		0x47FB464DAC94E5A9ULL,
		0x702E522025EF3DD5ULL,
		0x1E2F9EFD5A4C9810ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2FD25CFCF668D739ULL,
		0x108A15A5736D264DULL,
		0x2ADDD5C5D8EB39DAULL,
		0xFA82F9D19DE44499ULL,
		0x4CCAB6C4F07BC364ULL,
		0x46B542E38EC74BE1ULL,
		0x18DCD72B35D443F0ULL,
		0xF0DC5A65C4BEE726ULL
	}};
	printf("Test Case 438\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x6F9C9D4B7CBFCF71ULL,
		0xB0118112463BD8CFULL,
		0xCC846C519C1636F5ULL,
		0x6220CE7CD7B2AA48ULL,
		0x642DCE71F1E40C31ULL,
		0xB1993FA9690E4786ULL,
		0x614341FECE654401ULL,
		0xD300F00328037C20ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3A1D1C6B94207663ULL,
		0xCD0B5AF012D00749ULL,
		0x95E29E0296ADC25DULL,
		0x9551C18370BF66FBULL,
		0x884A17E5AC144E98ULL,
		0xE30EE5D629828506ULL,
		0xE4FE3CCAAB0053F3ULL,
		0xDA2392A643C67F1CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x55818120E89FB912ULL,
		0x7D1ADBE254EBDF86ULL,
		0x5966F2530ABBF4A8ULL,
		0xF7710FFFA70DCCB3ULL,
		0xEC67D9945DF042A9ULL,
		0x5297DA7F408CC280ULL,
		0x85BD7D34656517F2ULL,
		0x092362A56BC5033CULL
	}};
	printf("Test Case 439\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xCCC11873B2CEB02CULL,
		0x9EBE4C18181388A9ULL,
		0x49A1FF3D8161DB57ULL,
		0x2A89A564A08DDD27ULL,
		0x3BD07082FB2CCA2FULL,
		0x45D80FA1C8958E94ULL,
		0x6478FCCA81D1F27EULL,
		0x208A20ECCBDF0FD6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x82F9C16A29A1D98AULL,
		0xFAA24E11B17AAF68ULL,
		0x9F0CD6E60FF7F81DULL,
		0xF8C754410C4B06B3ULL,
		0x82C1907DC72FEFF5ULL,
		0x3EA22F4C7C3E1945ULL,
		0xE8136AA1F1401B5AULL,
		0x49B439B71BB40DAFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4E38D9199B6F69A6ULL,
		0x641C0209A96927C1ULL,
		0xD6AD29DB8E96234AULL,
		0xD24EF125ACC6DB94ULL,
		0xB911E0FF3C0325DAULL,
		0x7B7A20EDB4AB97D1ULL,
		0x8C6B966B7091E924ULL,
		0x693E195BD06B0279ULL
	}};
	printf("Test Case 440\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x0A10AB3FE254F6A8ULL,
		0x7229F4FB18C3BAA9ULL,
		0x8FFEC8684B60A0E1ULL,
		0x99DBF6E977FB1D36ULL,
		0x67898F2D307A84DAULL,
		0x13BC6B988B11EE71ULL,
		0x86BA7279A141D085ULL,
		0x779923886FE8FE2CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA171827C68AF1695ULL,
		0xF82C39D83828FB8EULL,
		0xF404504D5730FC18ULL,
		0x79E959FF44B74088ULL,
		0x2954AA0A99BC2DB9ULL,
		0x933E7712BCDF603AULL,
		0xD2E45DA00255FE5DULL,
		0xD67E9D7F722F333BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAB6129438AFBE03DULL,
		0x8A05CD2320EB4127ULL,
		0x7BFA98251C505CF9ULL,
		0xE032AF16334C5DBEULL,
		0x4EDD2527A9C6A963ULL,
		0x80821C8A37CE8E4BULL,
		0x545E2FD9A3142ED8ULL,
		0xA1E7BEF71DC7CD17ULL
	}};
	printf("Test Case 441\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x359366C0CF4E9816ULL,
		0x0310FBAF313D1805ULL,
		0x83AF4E6A89F0612CULL,
		0x8EEB317E8C141430ULL,
		0x10C18A626C0EC70CULL,
		0x31411A20E177C0A7ULL,
		0x3828354A1D4CC403ULL,
		0x8AFBB4033D2F6FD1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x454213F94161D0ACULL,
		0x878B54957781D5CCULL,
		0xDF6D6CBA113A249CULL,
		0x098B76C2C2FB312FULL,
		0xC60F38AC584B4996ULL,
		0xEFFA9556DCE127A9ULL,
		0x695D64A2D9ED90A8ULL,
		0x479F4ACEDE812B8FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x70D175398E2F48BAULL,
		0x849BAF3A46BCCDC9ULL,
		0x5CC222D098CA45B0ULL,
		0x876047BC4EEF251FULL,
		0xD6CEB2CE34458E9AULL,
		0xDEBB8F763D96E70EULL,
		0x517551E8C4A154ABULL,
		0xCD64FECDE3AE445EULL
	}};
	printf("Test Case 442\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x59D0DFD177AEE7A9ULL,
		0xE2B3C472C79AF8F9ULL,
		0x7E75AEA3FC12DFCCULL,
		0x009F8A403103A47EULL,
		0x4F07EDDBFBFD81B6ULL,
		0x31A2895F1ABE69F3ULL,
		0xCA8452094ED4C775ULL,
		0xE5BAA9A5B937D612ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0DF5414E910DD7A6ULL,
		0x344E28B2B60CC5B3ULL,
		0xDCF2DCCEC00435EAULL,
		0x667BA7854E1FB6E8ULL,
		0xF1E8F2826DAE2622ULL,
		0xEC282413BED50C10ULL,
		0xA47CD64689E1587CULL,
		0x6C05E02E16DAE51FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x54259E9FE6A3300FULL,
		0xD6FDECC071963D4AULL,
		0xA287726D3C16EA26ULL,
		0x66E42DC57F1C1296ULL,
		0xBEEF1F599653A794ULL,
		0xDD8AAD4CA46B65E3ULL,
		0x6EF8844FC7359F09ULL,
		0x89BF498BAFED330DULL
	}};
	printf("Test Case 443\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xF141A218F3A3EA24ULL,
		0xB8EB2DEF53652135ULL,
		0x4343C393C1489CCDULL,
		0x8C9889E2186D993DULL,
		0xAD27D2CD0AD44139ULL,
		0x784880D7729B11AFULL,
		0x4E74C15A1BF17EFEULL,
		0x8D92F3D53552D83BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCC6E89A7367C3C14ULL,
		0x2D431C59CB708A18ULL,
		0xCCFA6797FB3138EFULL,
		0xF099D2F61C456D02ULL,
		0x9AC69B15AC814A7EULL,
		0x830D43D37B98BBA5ULL,
		0x68CA66C89305A822ULL,
		0x51BC01F41F214C29ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3D2F2BBFC5DFD630ULL,
		0x95A831B69815AB2DULL,
		0x8FB9A4043A79A422ULL,
		0x7C015B140428F43FULL,
		0x37E149D8A6550B47ULL,
		0xFB45C3040903AA0AULL,
		0x26BEA79288F4D6DCULL,
		0xDC2EF2212A739412ULL
	}};
	printf("Test Case 444\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x68AE1CB512C27BD7ULL,
		0x926AC1B8C3178E2CULL,
		0x2775A4121BA3BB46ULL,
		0x55A4AB98141B8AC7ULL,
		0x801B536A70DB75BBULL,
		0x161D8A1C31FDD0ADULL,
		0x84D1B719AD031ADCULL,
		0xA0AEAFC57A22E1D4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9CE011BAD3B4E564ULL,
		0xE6CD5C9AD3913240ULL,
		0x11FA877ED4FA0A60ULL,
		0xBB29FEA1B9E2C16FULL,
		0xB8195219F4A08983ULL,
		0x1B88820426B84970ULL,
		0xC7EA41E72B5712CAULL,
		0x0D375D50D4DE1819ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF44E0D0FC1769EB3ULL,
		0x74A79D221086BC6CULL,
		0x368F236CCF59B126ULL,
		0xEE8D5539ADF94BA8ULL,
		0x38020173847BFC38ULL,
		0x0D950818174599DDULL,
		0x433BF6FE86540816ULL,
		0xAD99F295AEFCF9CDULL
	}};
	printf("Test Case 445\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x544C794715AE8B4DULL,
		0x8CBF5F854B7C163CULL,
		0x15149CBCB4ACD497ULL,
		0xAED9082F187C1902ULL,
		0x64547240FA4462C5ULL,
		0x9C0EFA9FD581FC4EULL,
		0x1D3EB305A13775D8ULL,
		0xEBA63E58257AAD13ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8512073FDE3BD1F3ULL,
		0x8E507A2A84F208D2ULL,
		0xCEB6771D198295F3ULL,
		0xED2E690CA580767FULL,
		0xB8A94B1B1954DB71ULL,
		0x7A5AB4F67F46EEFDULL,
		0x4870A2375D70CF59ULL,
		0x4064A6487DBD05F5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD15E7E78CB955ABEULL,
		0x02EF25AFCF8E1EEEULL,
		0xDBA2EBA1AD2E4164ULL,
		0x43F76123BDFC6F7DULL,
		0xDCFD395BE310B9B4ULL,
		0xE6544E69AAC712B3ULL,
		0x554E1132FC47BA81ULL,
		0xABC2981058C7A8E6ULL
	}};
	printf("Test Case 446\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x89B1E3D55C9C8282ULL,
		0x1CE78E41B8B5EF86ULL,
		0x2AE96666D7125062ULL,
		0xE55586CAF892967FULL,
		0x9D97B584A1CC4E6AULL,
		0xB7C33AD812DE8283ULL,
		0x50CD0BFB5163DA2FULL,
		0x0A0084989E3CFEBFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x303964795783C697ULL,
		0x462FDC25F897A068ULL,
		0x8EC65AAC9F78F374ULL,
		0x62346EE9E08445F0ULL,
		0xCFDE36A7806C5E0BULL,
		0xC465DF8F19FC3280ULL,
		0xE8DF170A917FCD74ULL,
		0x9A9E3AC1D845C4A3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB98887AC0B1F4415ULL,
		0x5AC8526440224FEEULL,
		0xA42F3CCA486AA316ULL,
		0x8761E8231816D38FULL,
		0x5249832321A01061ULL,
		0x73A6E5570B22B003ULL,
		0xB8121CF1C01C175BULL,
		0x909EBE5946793A1CULL
	}};
	printf("Test Case 447\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xB437626C6067A793ULL,
		0xAE0CBE03FADB6720ULL,
		0xDA85416E9D01E034ULL,
		0x856D5F73D291578BULL,
		0xA66A560A7485B397ULL,
		0x077F0605F7BB8CF8ULL,
		0x75676660EF051BE1ULL,
		0x11879130EEC210B5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5A63E3DBE27EC0E1ULL,
		0xE42C98BC6C5BE974ULL,
		0xD69C71B7C30EA053ULL,
		0x1D29174FDF65D4EEULL,
		0xD1C7BA9353735463ULL,
		0x6CE5906DEDBB35FBULL,
		0x25F2801533521D59ULL,
		0x78DA6AD64E2CCBC0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEE5481B782196772ULL,
		0x4A2026BF96808E54ULL,
		0x0C1930D95E0F4067ULL,
		0x9844483C0DF48365ULL,
		0x77ADEC9927F6E7F4ULL,
		0x6B9A96681A00B903ULL,
		0x5095E675DC5706B8ULL,
		0x695DFBE6A0EEDB75ULL
	}};
	printf("Test Case 448\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xD5AABA72D56EAA6AULL,
		0xEAC10BE0F052553AULL,
		0xA38AB9CF3BA17D6EULL,
		0x3AA46F64C4A6360CULL,
		0x34E1884F3B2E4F86ULL,
		0xE23CF11B85DC0CACULL,
		0x952D462CCE7962DDULL,
		0x5C8097503702F9B0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA38BE025057C34C8ULL,
		0xC695BE4E2736ABD3ULL,
		0xC413820E05E862D6ULL,
		0xD2361A47408B45CAULL,
		0x593AB8D804A42B15ULL,
		0x181580E558C75826ULL,
		0x054589DBF05054B5ULL,
		0x159489082AB41C3CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x76215A57D0129EA2ULL,
		0x2C54B5AED764FEE9ULL,
		0x67993BC13E491FB8ULL,
		0xE8927523842D73C6ULL,
		0x6DDB30973F8A6493ULL,
		0xFA2971FEDD1B548AULL,
		0x9068CFF73E293668ULL,
		0x49141E581DB6E58CULL
	}};
	printf("Test Case 449\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x49C38FF9B0C567B9ULL,
		0x0B70157B3BF69F47ULL,
		0x60C5CB3A48BB1A2CULL,
		0xDAD7107B5AE3DBE4ULL,
		0x9BDDA4CBAFFDC344ULL,
		0x6DFD02C39AD895E5ULL,
		0x11A653DE6CDDCB26ULL,
		0x5FB6A2807538E2ECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x25F0150D274FD979ULL,
		0xA0806FA5055D6733ULL,
		0x3E6C494CB1CFBD73ULL,
		0x2EFF6C22D12DEC71ULL,
		0x6CC9DDF95DDDD83EULL,
		0xEE273D582AD11116ULL,
		0x924272E8CC7BDEFAULL,
		0xE0ECA2B3B39EB5C8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6C339AF4978ABEC0ULL,
		0xABF07ADE3EABF874ULL,
		0x5EA98276F974A75FULL,
		0xF4287C598BCE3795ULL,
		0xF7147932F2201B7AULL,
		0x83DA3F9BB00984F3ULL,
		0x83E42136A0A615DCULL,
		0xBF5A0033C6A65724ULL
	}};
	printf("Test Case 450\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x70CFAD232D49D88EULL,
		0x4CB501B378A1405BULL,
		0xB315EEC70DC827B7ULL,
		0xBC2D39A5855DA3A6ULL,
		0x81AE0E5BB7FE4E78ULL,
		0x570F1A6139D784BBULL,
		0xC21B32EC9CB7C8CEULL,
		0x7C0D2227EC6B65C5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4266B5A6E3BBA857ULL,
		0x0FBA0C96FDDEFF0FULL,
		0x90A18F30DCFE6020ULL,
		0x0FD642465E948BAAULL,
		0xB549973D54D41FCFULL,
		0x6691647734EA7B64ULL,
		0x0625C1BC80E3D769ULL,
		0xA576DFC9EA816C96ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x32A91885CEF270D9ULL,
		0x430F0D25857FBF54ULL,
		0x23B461F7D1364797ULL,
		0xB3FB7BE3DBC9280CULL,
		0x34E79966E32A51B7ULL,
		0x319E7E160D3DFFDFULL,
		0xC43EF3501C541FA7ULL,
		0xD97BFDEE06EA0953ULL
	}};
	printf("Test Case 451\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xA3EC6302D25E1FE5ULL,
		0x1C2D1528846EDB45ULL,
		0x248B7DF8F490A979ULL,
		0x3D096B98C4F58D3EULL,
		0x0BDF7990DF2BB416ULL,
		0xDA0E61C881BBD13FULL,
		0x5038D568D24C4694ULL,
		0xF2C9E814C289C47BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x08AB3334A64572BDULL,
		0x0B0DA32B5469F445ULL,
		0x8C450207C9F1E3A5ULL,
		0xBEACE4A90F909048ULL,
		0x484344F4A12DCAD5ULL,
		0x4FBFD636484047AFULL,
		0x414C1B55DB0541EFULL,
		0x3477F9379F9B09F1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAB475036741B6D58ULL,
		0x1720B603D0072F00ULL,
		0xA8CE7FFF3D614ADCULL,
		0x83A58F31CB651D76ULL,
		0x439C3D647E067EC3ULL,
		0x95B1B7FEC9FB9690ULL,
		0x1174CE3D0949077BULL,
		0xC6BE11235D12CD8AULL
	}};
	printf("Test Case 452\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x36FE8F379E84EF68ULL,
		0x7404B568BD98DEECULL,
		0x7D37BDD7C2F31B69ULL,
		0x993C317B45CD9FD7ULL,
		0xCBBAFBB5B3989154ULL,
		0x4304D9B878D3BB6BULL,
		0x67C8650E149877B6ULL,
		0x9344747F5ABCBEB8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAE9CC1A892B2BA53ULL,
		0x9945FA5DD7F3B7B1ULL,
		0x103E1D520FEDEB62ULL,
		0x2787D3CD3ADD955DULL,
		0xAAD8D31B90EB54AEULL,
		0x56BB4502EDEF89C0ULL,
		0x5A8BDA6E2309625DULL,
		0x4AC0F569E54A3325ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x98624E9F0C36553BULL,
		0xED414F356A6B695DULL,
		0x6D09A085CD1EF00BULL,
		0xBEBBE2B67F100A8AULL,
		0x616228AE2373C5FAULL,
		0x15BF9CBA953C32ABULL,
		0x3D43BF60379115EBULL,
		0xD9848116BFF68D9DULL
	}};
	printf("Test Case 453\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xCF642E75211508C1ULL,
		0x0C2F7D774B78F314ULL,
		0x3D7056606CB8738DULL,
		0xCD8C6BBCF2B50A4FULL,
		0x91D750822504090BULL,
		0xEDA6B3A2671A4BBCULL,
		0x0092DD2C1C19B10FULL,
		0x5545588C1D262F07ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC3CE2128C9B42B83ULL,
		0xD4C0AEAEBE3B4937ULL,
		0xC9C8511950B721E6ULL,
		0xF216DAC4895CC505ULL,
		0x7D5723DC55148DF7ULL,
		0xB7FA7FEC08FE4DC3ULL,
		0x12D9D458335219B2ULL,
		0xCA9BAA6EE59737E9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0CAA0F5DE8A12342ULL,
		0xD8EFD3D9F543BA23ULL,
		0xF4B807793C0F526BULL,
		0x3F9AB1787BE9CF4AULL,
		0xEC80735E701084FCULL,
		0x5A5CCC4E6FE4067FULL,
		0x124B09742F4BA8BDULL,
		0x9FDEF2E2F8B118EEULL
	}};
	printf("Test Case 454\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x70BFA26D2C49C0BCULL,
		0xD73C2EF255E15238ULL,
		0x89C60DB09F858D50ULL,
		0x701CEE413FF4BD06ULL,
		0xD4CB047B8B7248CBULL,
		0xF6DC96B69F5399FCULL,
		0xA3E12C3A808A87BFULL,
		0xC93678274FA2A5A7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5EB726619ACC4010ULL,
		0xDB78E1200E25BA86ULL,
		0xB8F0366DC0BB5AF0ULL,
		0x57C271D6C1E9FF8BULL,
		0x4F0347BD74B1BC55ULL,
		0xD0B9607835D5EBF6ULL,
		0x6F7728F937139D7BULL,
		0x2DB07E06DE7C2C46ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2E08840CB68580ACULL,
		0x0C44CFD25BC4E8BEULL,
		0x31363BDD5F3ED7A0ULL,
		0x27DE9F97FE1D428DULL,
		0x9BC843C6FFC3F49EULL,
		0x2665F6CEAA86720AULL,
		0xCC9604C3B7991AC4ULL,
		0xE486062191DE89E1ULL
	}};
	printf("Test Case 455\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x7956442D2324F83DULL,
		0x07C74FC983E41D9CULL,
		0x189AB210C44D5452ULL,
		0x554C045832EAC10DULL,
		0xBBAE4BD314B3BCDFULL,
		0x3F62F1A4FA456BC3ULL,
		0x3430D03FF87D9EFFULL,
		0x7E04FBC283CBFFCEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC0F93C99533C32BAULL,
		0x4BFE0621DFEDA3F4ULL,
		0x23D57F3E4B86636AULL,
		0xE0ABCBBA7FE6B0B7ULL,
		0x2C4FEA05EB9FC31AULL,
		0x126EFDEB4708563DULL,
		0x11E3CB07B9374998ULL,
		0xEE30070CE78B370EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB9AF78B47018CA87ULL,
		0x4C3949E85C09BE68ULL,
		0x3B4FCD2E8FCB3738ULL,
		0xB5E7CFE24D0C71BAULL,
		0x97E1A1D6FF2C7FC5ULL,
		0x2D0C0C4FBD4D3DFEULL,
		0x25D31B38414AD767ULL,
		0x9034FCCE6440C8C0ULL
	}};
	printf("Test Case 456\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x30F11632E79819EBULL,
		0x687DD0344010C682ULL,
		0xE477C74F09A569A5ULL,
		0xC6840885F21BF433ULL,
		0xBDED33AFB1D184A1ULL,
		0xCEA34D0FFD5C68DDULL,
		0x516DBEAEFB4AD353ULL,
		0x06CCEBC368AAA082ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4D3F052E82FF05DEULL,
		0x9CE0C9DD4F60FC5AULL,
		0x8592912EBB1C6B3BULL,
		0x63B5C71EC7770584ULL,
		0xC7910FB0B8E55063ULL,
		0xCB0A685E5A62BB72ULL,
		0x8DD5E15B51D025ADULL,
		0x0004AA15B0ED9C78ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7DCE131C65671C35ULL,
		0xF49D19E90F703AD8ULL,
		0x61E55661B2B9029EULL,
		0xA531CF9B356CF1B7ULL,
		0x7A7C3C1F0934D4C2ULL,
		0x05A92551A73ED3AFULL,
		0xDCB85FF5AA9AF6FEULL,
		0x06C841D6D8473CFAULL
	}};
	printf("Test Case 457\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x42CF0DDD4FFD899CULL,
		0x29B6CD47C89EBB43ULL,
		0xC5BCF0C2973B7E6AULL,
		0xC779F8D51430AEFFULL,
		0xD214F032B524F8BDULL,
		0x6BF0CAACD1BB1090ULL,
		0x12BBC9E1AC7B0AFBULL,
		0xB81D3C4B0A68494AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF0DCF608DF538AA1ULL,
		0xE89B0B2EF5F5461BULL,
		0xE79CDF4D24A50AE7ULL,
		0x089388560A308EC7ULL,
		0x383F38EB5EC30B95ULL,
		0x4BCAC7C4AE7BB20AULL,
		0x787BDB504B94B894ULL,
		0x4924612403490FA0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB213FBD590AE033DULL,
		0xC12DC6693D6BFD58ULL,
		0x22202F8FB39E748DULL,
		0xCFEA70831E002038ULL,
		0xEA2BC8D9EBE7F328ULL,
		0x203A0D687FC0A29AULL,
		0x6AC012B1E7EFB26FULL,
		0xF1395D6F092146EAULL
	}};
	printf("Test Case 458\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x7453C2D5BF858AEBULL,
		0xC0D240746C1D35CAULL,
		0xFE9E4D931FF34D38ULL,
		0xC8A7D1FABA4F0E52ULL,
		0xC548462B7EDCF91FULL,
		0x75E5CEFC3E29609AULL,
		0xD3EBAB1D6C9AEAB2ULL,
		0xCCE40AB1B8F6A2E1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA29CC721B995DF2BULL,
		0xB6013FA2ADFE528BULL,
		0x7D1645981F54B521ULL,
		0xCDF9749CAD122CCFULL,
		0x4F4B872F56F21611ULL,
		0x582AC858932FF562ULL,
		0x29AA7C4C4E7A4290ULL,
		0x590A25544D01F37EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD6CF05F4061055C0ULL,
		0x76D37FD6C1E36741ULL,
		0x8388080B00A7F819ULL,
		0x055EA566175D229DULL,
		0x8A03C104282EEF0EULL,
		0x2DCF06A4AD0695F8ULL,
		0xFA41D75122E0A822ULL,
		0x95EE2FE5F5F7519FULL
	}};
	printf("Test Case 459\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x0F54F490703D92E3ULL,
		0x13629CA84292D092ULL,
		0x6582F733FCCE7920ULL,
		0x4A040E828CF9226FULL,
		0x351A9047C5C18F85ULL,
		0xC8EF09C5EE43D09FULL,
		0x23DC2DC0FF0A578BULL,
		0x5A0AFB0554A0BD3CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1E53758F6411A8ACULL,
		0x6C36F0AE7976868BULL,
		0xE7BE0BC615B4DF69ULL,
		0xA6DC610578EAFAF0ULL,
		0x04D5A48CFABBFD54ULL,
		0x155C9CE99C1EB750ULL,
		0x6A56AF450370855AULL,
		0xC4A1F06855AB1638ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1107811F142C3A4FULL,
		0x7F546C063BE45619ULL,
		0x823CFCF5E97AA649ULL,
		0xECD86F87F413D89FULL,
		0x31CF34CB3F7A72D1ULL,
		0xDDB3952C725D67CFULL,
		0x498A8285FC7AD2D1ULL,
		0x9EAB0B6D010BAB04ULL
	}};
	printf("Test Case 460\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x2BC8CE0E51110598ULL,
		0x29820B0E8BBA921EULL,
		0x089A027E3AEAA1F9ULL,
		0xD8112ECCF87577AAULL,
		0xF5C6181CBBA7123AULL,
		0xCDBB29092EA62FD8ULL,
		0xE0B3918EE934CB3FULL,
		0x9D3D95E4789C2FD5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x89F0909735F00CA6ULL,
		0x1DC7BE7EE0A77081ULL,
		0x29BBCF44B6345E1FULL,
		0xB35B56DA5B04353DULL,
		0x90BED6C91ACEB671ULL,
		0xC8194A55CE2D97BBULL,
		0x6012167CBAD68AD5ULL,
		0x8FE7EBE549955320ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA2385E9964E1093EULL,
		0x3445B5706B1DE29FULL,
		0x2121CD3A8CDEFFE6ULL,
		0x6B4A7816A3714297ULL,
		0x6578CED5A169A44BULL,
		0x05A2635CE08BB863ULL,
		0x80A187F253E241EAULL,
		0x12DA7E0131097CF5ULL
	}};
	printf("Test Case 461\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x36F33B6F094F0EE0ULL,
		0x0EB739A303048A3BULL,
		0xEEA76D284F9CAD1CULL,
		0xF89C8F1D23C654D5ULL,
		0xAF37C0774F12D152ULL,
		0x985F5EE035EC5520ULL,
		0x704805EDB45ABE65ULL,
		0x51380B3BE6995773ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDC8880227C123654ULL,
		0xDBDAC578B8A0AFADULL,
		0xA4DC9CEEE17749C7ULL,
		0x72E80CC997C40EFCULL,
		0x07B679FBB81A1893ULL,
		0x0CD3F82D55718B68ULL,
		0x38A121441EF69EDDULL,
		0x988C162E3BA4021AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEA7BBB4D755D38B4ULL,
		0xD56DFCDBBBA42596ULL,
		0x4A7BF1C6AEEBE4DBULL,
		0x8A7483D4B4025A29ULL,
		0xA881B98CF708C9C1ULL,
		0x948CA6CD609DDE48ULL,
		0x48E924A9AAAC20B8ULL,
		0xC9B41D15DD3D5569ULL
	}};
	printf("Test Case 462\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xE5D38FFC6CC9A5CFULL,
		0xFD469590A4A8D399ULL,
		0x7E855CFA5C769155ULL,
		0x97082E6750937498ULL,
		0xF836FE6144F72B3EULL,
		0xDF503225C14E4A94ULL,
		0x162FFD84B0219795ULL,
		0x30B2A3E3B40B4729ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4A482E58D6B237BBULL,
		0x3BD77B0FB443C8B0ULL,
		0xA1B03A70CFB0A62AULL,
		0x3AC53FFC9EA95716ULL,
		0xE03171865BC5FCF8ULL,
		0x2D3D4E33D58C98D1ULL,
		0xF448699AEEB37750ULL,
		0xB0FEC6A6D233A9E4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAF9BA1A4BA7B9274ULL,
		0xC691EE9F10EB1B29ULL,
		0xDF35668A93C6377FULL,
		0xADCD119BCE3A238EULL,
		0x18078FE71F32D7C6ULL,
		0xF26D7C1614C2D245ULL,
		0xE267941E5E92E0C5ULL,
		0x804C65456638EECDULL
	}};
	printf("Test Case 463\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x3BB7B82AC4DC5B5FULL,
		0x62C74624CF09E486ULL,
		0xFAEBACBCFFABD2B9ULL,
		0xACB8A5CD95372C0EULL,
		0x53382B537B18020FULL,
		0x1C8EA40E7A16D229ULL,
		0xA36957A923F1C39CULL,
		0x697764E6141935ACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x223CA05A4B584BA5ULL,
		0xF3F5AECB199E034FULL,
		0x80788D75BBC6BFB7ULL,
		0xFDC28F0A9AA35E3CULL,
		0xBF50142DB2067C7DULL,
		0x2D465D8CE76AB06DULL,
		0xAD537959D4C0E932ULL,
		0xDA1A2FDBDD1382E6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x198B18708F8410FAULL,
		0x9132E8EFD697E7C9ULL,
		0x7A9321C9446D6D0EULL,
		0x517A2AC70F947232ULL,
		0xEC683F7EC91E7E72ULL,
		0x31C8F9829D7C6244ULL,
		0x0E3A2EF0F7312AAEULL,
		0xB36D4B3DC90AB74AULL
	}};
	printf("Test Case 464\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xB58BE23A09DDFB98ULL,
		0xD74FE59F1B627618ULL,
		0xC1177E23020DC924ULL,
		0x7023153955D5D7E3ULL,
		0xB09E4772C3FF6A9DULL,
		0x8FCF8A81EC735CADULL,
		0x42176B6C7A6CC762ULL,
		0x98D09C0BFCEC6525ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9C21A3203C8AE147ULL,
		0x2C02A7ABB1A8A8F3ULL,
		0x7043D8F13FCF0039ULL,
		0xD5980D82EC440ADCULL,
		0x2814FE10892E5142ULL,
		0x107826F8A11BA9FAULL,
		0x2B77F02F724060D1ULL,
		0x8DB3922AABBDF1C1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x29AA411A35571ADFULL,
		0xFB4D4234AACADEEBULL,
		0xB154A6D23DC2C91DULL,
		0xA5BB18BBB991DD3FULL,
		0x988AB9624AD13BDFULL,
		0x9FB7AC794D68F557ULL,
		0x69609B43082CA7B3ULL,
		0x15630E21575194E4ULL
	}};
	printf("Test Case 465\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xDD548019C5B10E96ULL,
		0x0788A9E1C2F4D7C6ULL,
		0x4E9A77246C331FDCULL,
		0x7362718E151BB8ACULL,
		0xD3CAF0ECE2514131ULL,
		0x2DD075D7A42887E9ULL,
		0x5789D33FFC0838AEULL,
		0x35D5FF7384EB9DD7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x86F40574F2270FF2ULL,
		0x42626FCC3F31AEF8ULL,
		0x13491DCB99509FF5ULL,
		0xC7BE9457E9ECB256ULL,
		0x0D4F9F8BEE5DB07AULL,
		0x0D330F539D0F767CULL,
		0xD29810DE3480B370ULL,
		0x25C9194E1E0E9EDDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5BA0856D37960164ULL,
		0x45EAC62DFDC5793EULL,
		0x5DD36AEFF5638029ULL,
		0xB4DCE5D9FCF70AFAULL,
		0xDE856F670C0CF14BULL,
		0x20E37A843927F195ULL,
		0x8511C3E1C8888BDEULL,
		0x101CE63D9AE5030AULL
	}};
	printf("Test Case 466\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xBEF131E4A2F1D761ULL,
		0x2CC9C70B5FDEABB6ULL,
		0x6C7964C95B276D0BULL,
		0x76E660A2F3698698ULL,
		0x3EF5DC1A01766DEFULL,
		0xDE03C069CCEE28BAULL,
		0x9925189F007DB389ULL,
		0x1A7404D875F4E479ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x64BDAD39034DFA14ULL,
		0x56A41ABB868333AEULL,
		0xD1E0A1B09560BD64ULL,
		0x77A13D37A19A74D1ULL,
		0xE9DA43B7F1B280C4ULL,
		0x06395A64099FBDB8ULL,
		0xEC730AC06B77BBF1ULL,
		0xF7B0D9D58EB4D1B2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDA4C9CDDA1BC2D75ULL,
		0x7A6DDDB0D95D9818ULL,
		0xBD99C579CE47D06FULL,
		0x01475D9552F3F249ULL,
		0xD72F9FADF0C4ED2BULL,
		0xD83A9A0DC5719502ULL,
		0x7556125F6B0A0878ULL,
		0xEDC4DD0DFB4035CBULL
	}};
	printf("Test Case 467\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x5FE12052E18707D0ULL,
		0x999D8EBA0DF2DF27ULL,
		0x89650EF25192F690ULL,
		0x7C39C89B59906B01ULL,
		0xA590379094340FEDULL,
		0xBF388FD2104C8C71ULL,
		0x90D25CA0E312F414ULL,
		0x4DAA1489E37620CAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6A66567C14577A72ULL,
		0xBCDE23E7E2CE93F9ULL,
		0x9BF2D1CFC1137630ULL,
		0xAFB5DCD024A4D180ULL,
		0xF8845FF00BB678BCULL,
		0xD5B25DCFA2425356ULL,
		0x0718C3CE95FECAA3ULL,
		0x6D923546EA7D1EF4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3587762EF5D07DA2ULL,
		0x2543AD5DEF3C4CDEULL,
		0x1297DF3D908180A0ULL,
		0xD38C144B7D34BA81ULL,
		0x5D1468609F827751ULL,
		0x6A8AD21DB20EDF27ULL,
		0x97CA9F6E76EC3EB7ULL,
		0x203821CF090B3E3EULL
	}};
	printf("Test Case 468\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x94EB30F0409B3EB4ULL,
		0xF69269C12970883CULL,
		0xB276A1DABB1A8110ULL,
		0x7A5E6D3BB25E317CULL,
		0x33F5075B5BE532B3ULL,
		0x6C08E584D511AA47ULL,
		0x359A5A355658CFA0ULL,
		0x27858A1FD9AE31EAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x99BE6CE7762B8AF1ULL,
		0x211270DC0A7E8AB0ULL,
		0xFB6E0CF08E8A1DE7ULL,
		0x69D79372F6486CFBULL,
		0x6CDC1D534180BCEEULL,
		0x8D50D9895BBE320BULL,
		0xC0A7B94CEC98252BULL,
		0x1B915F51FD2E32EDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0D555C1736B0B445ULL,
		0xD780191D230E028CULL,
		0x4918AD2A35909CF7ULL,
		0x1389FE4944165D87ULL,
		0x5F291A081A658E5DULL,
		0xE1583C0D8EAF984CULL,
		0xF53DE379BAC0EA8BULL,
		0x3C14D54E24800307ULL
	}};
	printf("Test Case 469\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xC68C422B0BD8CAABULL,
		0x3F11ECF0ACF579B2ULL,
		0x23D7C7929D07722BULL,
		0x6325DC2C281B8300ULL,
		0x5E1E4723292E6FFCULL,
		0x69D67ACD7BBF8262ULL,
		0x3B7A514E841C031EULL,
		0x5D80301310A3B9D4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x571DEC152B73BB12ULL,
		0x68E0CE443C02D949ULL,
		0x077EEC0E82B2FDE7ULL,
		0x952915C68D27212DULL,
		0x310E5D511576D910ULL,
		0xCDD3A305A1B8F672ULL,
		0x3D46184C8CFCF300ULL,
		0x8AEAAA5AC7AF764CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9191AE3E20AB71B9ULL,
		0x57F122B490F7A0FBULL,
		0x24A92B9C1FB58FCCULL,
		0xF60CC9EAA53CA22DULL,
		0x6F101A723C58B6ECULL,
		0xA405D9C8DA077410ULL,
		0x063C490208E0F01EULL,
		0xD76A9A49D70CCF98ULL
	}};
	printf("Test Case 470\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x98F71220E98651B6ULL,
		0x0C6E273CA7324DA0ULL,
		0x2330B04FA356DAD7ULL,
		0x2228096DEA47DD54ULL,
		0xB208DE2788A38190ULL,
		0x5FCD84D24019A185ULL,
		0x99034C77FB981968ULL,
		0x7C109D5D93B0D98BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x51D94C734DA915A5ULL,
		0x86B2D2F8DEA63D8AULL,
		0x1F0929628D02D031ULL,
		0x9351D435D28AF530ULL,
		0xD24D15A699C39A21ULL,
		0xD2697CA5929A1AF0ULL,
		0xC13A57D56B3D1805ULL,
		0xE6F9012AC66BA494ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC92E5E53A42F4413ULL,
		0x8ADCF5C47994702AULL,
		0x3C39992D2E540AE6ULL,
		0xB179DD5838CD2864ULL,
		0x6045CB8111601BB1ULL,
		0x8DA4F877D283BB75ULL,
		0x58391BA290A5016DULL,
		0x9AE99C7755DB7D1FULL
	}};
	printf("Test Case 471\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x5242245DC6C3BEB2ULL,
		0xAEAEBBA1D51351A4ULL,
		0x972CA094F673F286ULL,
		0x2049C033C0F41039ULL,
		0xBC1F5FC77D9FC373ULL,
		0x5224BCFCFF688047ULL,
		0xEE69EEE0627B37C8ULL,
		0x06A3793C279B8748ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x35FF9A6D1FF01D51ULL,
		0xFA54105AA5E8FF31ULL,
		0x29CAB5F0C2F99412ULL,
		0x1B5D3B440599EB57ULL,
		0x63D08E566970CED0ULL,
		0x37D9B6FE093C2257ULL,
		0x8032D07B35402F72ULL,
		0xDF41CC674DBB305FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x67BDBE30D933A3E3ULL,
		0x54FAABFB70FBAE95ULL,
		0xBEE61564348A6694ULL,
		0x3B14FB77C56DFB6EULL,
		0xDFCFD19114EF0DA3ULL,
		0x65FD0A02F654A210ULL,
		0x6E5B3E9B573B18BAULL,
		0xD9E2B55B6A20B717ULL
	}};
	printf("Test Case 472\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x1DFD2C37235AA6E3ULL,
		0x1B59C920C2226EC8ULL,
		0xCE5FB4D0FEDCF115ULL,
		0x7AE387223B679785ULL,
		0x15BFB85165ED486FULL,
		0x01351C2E2109310BULL,
		0x37CD4EA2B0043F79ULL,
		0x8324536E853BAD08ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x521FA80F6B9F6EA5ULL,
		0x3796D7465CC29241ULL,
		0xA98CFDEF3E5B4AC1ULL,
		0xC39299E0514487E3ULL,
		0x87B59C7D72C87759ULL,
		0x93F6811DD63811DAULL,
		0x2CC08AE1C52B565FULL,
		0xED29F06D1CA6F898ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4FE2843848C5C846ULL,
		0x2CCF1E669EE0FC89ULL,
		0x67D3493FC087BBD4ULL,
		0xB9711EC26A231066ULL,
		0x920A242C17253F36ULL,
		0x92C39D33F73120D1ULL,
		0x1B0DC443752F6926ULL,
		0x6E0DA303999D5590ULL
	}};
	printf("Test Case 473\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x8AA704EB670CB4DFULL,
		0xBC4A1AEA5561F862ULL,
		0x449B5F07BB5579F8ULL,
		0x27FB12E53AFD54AFULL,
		0xF626087C5978F78DULL,
		0xDE81DC68D550B08FULL,
		0x2F96B6222CD00964ULL,
		0x5C8DFDABA7D42278ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0983DD8D5F0733FFULL,
		0x2E16FD1350F576A6ULL,
		0xE1A2BA9240F4E38BULL,
		0xE18965DCFFD35845ULL,
		0x329987054A1D6FABULL,
		0x487AB8384C6AD34CULL,
		0x972825BBB452E634ULL,
		0x85FE6E8B43E7A3EFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8324D966380B8720ULL,
		0x925CE7F905948EC4ULL,
		0xA539E595FBA19A73ULL,
		0xC6727739C52E0CEAULL,
		0xC4BF8F7913659826ULL,
		0x96FB6450993A63C3ULL,
		0xB8BE93999882EF50ULL,
		0xD9739320E4338197ULL
	}};
	printf("Test Case 474\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xA6D566EDCB0E3FB0ULL,
		0x853D9E116749EB94ULL,
		0x96184265E418E38DULL,
		0xB061B759463A5789ULL,
		0x60BD43824BFE7C63ULL,
		0x1C70E8634E307BB2ULL,
		0xD05CE5D9953D3E60ULL,
		0x4F124F2718B0C405ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE80890AE27E74051ULL,
		0xD57988D9CFD79F0AULL,
		0xCC6CB34AEAC621CFULL,
		0x861B3282A2204C1DULL,
		0xCA4DC15A3CB18683ULL,
		0x72908E85B6BBB8ADULL,
		0xC710E89C55FA76F6ULL,
		0xC1E22497054FFE58ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4EDDF643ECE97FE1ULL,
		0x504416C8A89E749EULL,
		0x5A74F12F0EDEC242ULL,
		0x367A85DBE41A1B94ULL,
		0xAAF082D8774FFAE0ULL,
		0x6EE066E6F88BC31FULL,
		0x174C0D45C0C74896ULL,
		0x8EF06BB01DFF3A5DULL
	}};
	printf("Test Case 475\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x51F2DBD02207451AULL,
		0x0BA8547D46900069ULL,
		0x63609C9F0DE628DFULL,
		0x91D5FF54D2DC2853ULL,
		0x7EAF7C7F733BF1CBULL,
		0xE0CBFAD217D756E1ULL,
		0xFE6F1EEE2D7C4FCFULL,
		0xD01A0A3F4422D1CEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x41788855BFA1F43CULL,
		0x93D27769A84EB171ULL,
		0x0A73B6E0EB7B9BFFULL,
		0x556DEA34D0CCCC70ULL,
		0x7C8E050F51384846ULL,
		0x87BFBBE1BDEAC5A7ULL,
		0xF1716DECC66DFFC5ULL,
		0x587FE2E20C0090E5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x108A53859DA6B126ULL,
		0x987A2314EEDEB118ULL,
		0x69132A7FE69DB320ULL,
		0xC4B815600210E423ULL,
		0x022179702203B98DULL,
		0x67744133AA3D9346ULL,
		0x0F1E7302EB11B00AULL,
		0x8865E8DD4822412BULL
	}};
	printf("Test Case 476\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x1D43C8FE1337EB91ULL,
		0x06E4435306F2363BULL,
		0x1BDAFA1507AD3AC6ULL,
		0x002BFECD9A02A3C4ULL,
		0x1D6775637F878FE5ULL,
		0x9E7DDBCD8407EDAAULL,
		0x76B969C22012657EULL,
		0x870F23621D6CE2A0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA6D85CB125DE81D0ULL,
		0x834555CD3FAB038CULL,
		0xBDC32549D5DAE532ULL,
		0x09B21D9417A9809AULL,
		0x88985AF4EF29B980ULL,
		0xDD7DF7E99672BC71ULL,
		0xA33D727246B8D7DBULL,
		0x2E75AD115DD41F22ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBB9B944F36E96A41ULL,
		0x85A1169E395935B7ULL,
		0xA619DF5CD277DFF4ULL,
		0x0999E3598DAB235EULL,
		0x95FF2F9790AE3665ULL,
		0x43002C24127551DBULL,
		0xD5841BB066AAB2A5ULL,
		0xA97A8E7340B8FD82ULL
	}};
	printf("Test Case 477\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x590EB5D73CD885BDULL,
		0xBD3261B5172F55AFULL,
		0xEE50291D19E6BCF8ULL,
		0x673399D53F5E2700ULL,
		0xE07AA3585209DB3AULL,
		0x6D5FD197D9A7C5DCULL,
		0x7EFB75049F5BB31DULL,
		0xCC32868771C11AEEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4802BC0898B8F3B9ULL,
		0x616C5FBF647E662FULL,
		0x7AB641E7B70341DFULL,
		0xAA6C82BE05355730ULL,
		0x0E1FE4D4D8A15F74ULL,
		0x7B946A37A425A423ULL,
		0xFFE9A78B947B9218ULL,
		0xC1869B8C61B6F9DFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x110C09DFA4607604ULL,
		0xDC5E3E0A73513380ULL,
		0x94E668FAAEE5FD27ULL,
		0xCD5F1B6B3A6B7030ULL,
		0xEE65478C8AA8844EULL,
		0x16CBBBA07D8261FFULL,
		0x8112D28F0B202105ULL,
		0x0DB41D0B1077E331ULL
	}};
	printf("Test Case 478\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x5EA416147E376E55ULL,
		0x8E74C8E53DB1B669ULL,
		0xF27A1B7BDFE1EA52ULL,
		0x803472C874325677ULL,
		0xAFF3AB6C479396CCULL,
		0x05E46123E93D5C8EULL,
		0x009D422536134FD7ULL,
		0x037ED1FF1064F067ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD62FD6BE0AEADD22ULL,
		0x245B147210B42C81ULL,
		0x9F88054154D0C1CFULL,
		0xA31E4E51DD04374FULL,
		0x20CCA30C56FD84FDULL,
		0x047FD1F7E44231B5ULL,
		0x52DCB0EC896BCBA3ULL,
		0x80CF678C8B987BA4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x888BC0AA74DDB377ULL,
		0xAA2FDC972D059AE8ULL,
		0x6DF21E3A8B312B9DULL,
		0x232A3C99A9366138ULL,
		0x8F3F0860116E1231ULL,
		0x019BB0D40D7F6D3BULL,
		0x5241F2C9BF788474ULL,
		0x83B1B6739BFC8BC3ULL
	}};
	printf("Test Case 479\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xC740BE4386D74C0FULL,
		0x412C0735FD1F2CA8ULL,
		0xE99726C09A25E9DCULL,
		0x16DA832020C61A57ULL,
		0x800A11FCDAA6FA3BULL,
		0xC40443566F85766DULL,
		0xA710C5A48500B296ULL,
		0x9B261D165B55BA16ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6EE526CEF9242266ULL,
		0x7F8F9989F8241499ULL,
		0xD48F5949DBDE9E53ULL,
		0x0DF119CB05A467AEULL,
		0x391466C625F6B507ULL,
		0x712E5399EE942652ULL,
		0x65958C014C3E12CEULL,
		0xF0AF2F53C32044BDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA9A5988D7FF36E69ULL,
		0x3EA39EBC053B3831ULL,
		0x3D187F8941FB778FULL,
		0x1B2B9AEB25627DF9ULL,
		0xB91E773AFF504F3CULL,
		0xB52A10CF8111503FULL,
		0xC28549A5C93EA058ULL,
		0x6B8932459875FEABULL
	}};
	printf("Test Case 480\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xAB57593093E731D4ULL,
		0x2BED2FE722AEAB82ULL,
		0xF249681FEF82B7B7ULL,
		0xB3E21334297483A3ULL,
		0x52C790B9F192E7FFULL,
		0x2D2C75E150B987DCULL,
		0xF204BDF1343EF68FULL,
		0x2E91836D5AC51C77ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7F086DB24A94F582ULL,
		0x9310960E6E8AB8E4ULL,
		0x418D55EAFD604BB5ULL,
		0x5F2775FD7E34FD06ULL,
		0x50F4BE289FFF3C58ULL,
		0xE8CC7266FD51C351ULL,
		0x0486B614E6DAE32AULL,
		0x97427B1149F9CAA2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD45F3482D973C456ULL,
		0xB8FDB9E94C241366ULL,
		0xB3C43DF512E2FC02ULL,
		0xECC566C957407EA5ULL,
		0x02332E916E6DDBA7ULL,
		0xC5E00787ADE8448DULL,
		0xF6820BE5D2E415A5ULL,
		0xB9D3F87C133CD6D5ULL
	}};
	printf("Test Case 481\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xEFB68979554C0EA2ULL,
		0x4751C0EA15D252C7ULL,
		0xEF2F6802EC28AFB7ULL,
		0x62B8DC2F201D83A0ULL,
		0x7FAD9BF6F783B6C1ULL,
		0x38277425A439FECAULL,
		0xF1139B8AA471694EULL,
		0xE35EE1C622B00BDCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBD2549B0E92D10C1ULL,
		0xEFEBF43FF13B258DULL,
		0x50ACF0C3D3999E6EULL,
		0xE8F849C85141300CULL,
		0xD27C7CA9AEC6D2D6ULL,
		0x2239CCE63F089737ULL,
		0x347C05C91CB92920ULL,
		0x46E983B0209D4968ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5293C0C9BC611E63ULL,
		0xA8BA34D5E4E9774AULL,
		0xBF8398C13FB131D9ULL,
		0x8A4095E7715CB3ACULL,
		0xADD1E75F59456417ULL,
		0x1A1EB8C39B3169FDULL,
		0xC56F9E43B8C8406EULL,
		0xA5B76276022D42B4ULL
	}};
	printf("Test Case 482\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x65EE7CA01CD925C2ULL,
		0x0119A3F76AE5C82BULL,
		0xFE766E478427E2ABULL,
		0x13B12F4720DBB747ULL,
		0x4644372C77125DC6ULL,
		0x4CCD6548FD561BCAULL,
		0x6CFB0BD7D1A35DF8ULL,
		0x4E007A24212ABBA6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDB974C81B475C6CBULL,
		0x719A45DBF5C6A942ULL,
		0x0E0F6C805673905DULL,
		0x344A675EE65BE0F3ULL,
		0xAE4C9C862757326EULL,
		0xEFF2DA448D0C31B3ULL,
		0x12018BC1B2EB20A6ULL,
		0xB4186668A8F203AFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBE793021A8ACE309ULL,
		0x7083E62C9F236169ULL,
		0xF07902C7D25472F6ULL,
		0x27FB4819C68057B4ULL,
		0xE808ABAA50456FA8ULL,
		0xA33FBF0C705A2A79ULL,
		0x7EFA801663487D5EULL,
		0xFA181C4C89D8B809ULL
	}};
	printf("Test Case 483\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x6047C1604EF7D66EULL,
		0x0FAA20DCCC7FD630ULL,
		0x86048F4C539A2074ULL,
		0x2E9CF0BD5576C643ULL,
		0x4A789EC1E25C85C8ULL,
		0xD29DCA2270AA098AULL,
		0x28C1A1830C47F96DULL,
		0x93A7ECA41DEF82C7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x467DFC04AA5D381EULL,
		0xFA14CE789E86096FULL,
		0xC604F92CA6173778ULL,
		0xBEFF4A4A5EC28A74ULL,
		0xA3BB874FD10B7E91ULL,
		0x6F09A93478BB89EFULL,
		0x6B53ABB636B64582ULL,
		0x8D56AB52F1FD595FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x263A3D64E4AAEE70ULL,
		0xF5BEEEA452F9DF5FULL,
		0x40007660F58D170CULL,
		0x9063BAF70BB44C37ULL,
		0xE9C3198E3357FB59ULL,
		0xBD94631608118065ULL,
		0x43920A353AF1BCEFULL,
		0x1EF147F6EC12DB98ULL
	}};
	printf("Test Case 484\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xD4047B5A2E059B28ULL,
		0x7252B433DC211A58ULL,
		0x7DB3D3E7C128BCA7ULL,
		0x1F6631D504CD6AB8ULL,
		0xE6D169F419E89EF0ULL,
		0x96B4313CAF7E8335ULL,
		0x4195928E5D989890ULL,
		0x0FF5744B496F51B8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x74D714D69CEF926EULL,
		0x4E8AA5144084D16BULL,
		0x5829CF4F1F386E4EULL,
		0xBB10B7493B022A0FULL,
		0x7CFCD3BAE839D782ULL,
		0x290BDC8121FE97CBULL,
		0x60DB522AA8C63B4CULL,
		0x35238A7A54904C3CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA0D36F8CB2EA0946ULL,
		0x3CD811279CA5CB33ULL,
		0x259A1CA8DE10D2E9ULL,
		0xA476869C3FCF40B7ULL,
		0x9A2DBA4EF1D14972ULL,
		0xBFBFEDBD8E8014FEULL,
		0x214EC0A4F55EA3DCULL,
		0x3AD6FE311DFF1D84ULL
	}};
	printf("Test Case 485\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x520368A806244E95ULL,
		0x1B9D63AF8128E10DULL,
		0x66EB18A05B812AD8ULL,
		0xC1C4716DADA02B85ULL,
		0xB0E7775445D419B5ULL,
		0x266210D10072F116ULL,
		0xF7429777C1B3BEC0ULL,
		0x937CCC22389A3E2BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x15AE4A3C43EBC9D4ULL,
		0x019B129F29A3C45DULL,
		0xBC62CA1597642CC7ULL,
		0xD21A6F6D4C79817EULL,
		0x1BD14B7A0F3C5436ULL,
		0xB996036C2D8FCE41ULL,
		0x308B39053C210EDCULL,
		0xD896337F1054E49FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x47AD229445CF8741ULL,
		0x1A067130A88B2550ULL,
		0xDA89D2B5CCE5061FULL,
		0x13DE1E00E1D9AAFBULL,
		0xAB363C2E4AE84D83ULL,
		0x9FF413BD2DFD3F57ULL,
		0xC7C9AE72FD92B01CULL,
		0x4BEAFF5D28CEDAB4ULL
	}};
	printf("Test Case 486\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x4F10C2012BEF712BULL,
		0x5A403A34374CDC2CULL,
		0x96B2C09100A8B55DULL,
		0xFE6686982D9999B7ULL,
		0x695157542CC07B35ULL,
		0xEF23BB85BFAC7C08ULL,
		0x8A2DC681D78EE9F3ULL,
		0x31F2997B586FEF59ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEFD51892A5983653ULL,
		0x2BF78FE1B87001A4ULL,
		0xA5EF4419A1358BAFULL,
		0x83F6A529278E2103ULL,
		0x11E03E0ED970684CULL,
		0xDFF9D9EC1F48486BULL,
		0xF567DC2C96458111ULL,
		0x184114EB6F130F27ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA0C5DA938E774778ULL,
		0x71B7B5D58F3CDD88ULL,
		0x335D8488A19D3EF2ULL,
		0x7D9023B10A17B8B4ULL,
		0x78B1695AF5B01379ULL,
		0x30DA6269A0E43463ULL,
		0x7F4A1AAD41CB68E2ULL,
		0x29B38D90377CE07EULL
	}};
	printf("Test Case 487\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xC5A540394E15B9D3ULL,
		0x6FFBB0E95CE9E363ULL,
		0xCB7920AA084266ACULL,
		0xBAD7AB8A388568AAULL,
		0x31211C9CAD371B68ULL,
		0xF4753121EC5EED03ULL,
		0x31DF35708673C490ULL,
		0x0D8D4B2AEEB08FDEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEAC2BC0FD1814F75ULL,
		0x26C6CCFDF3C67203ULL,
		0x9C4FD260E057A84FULL,
		0x3A452D90149EE73BULL,
		0xB7CE6039C0934CB7ULL,
		0xB1A45755606824EDULL,
		0xA62E960E8A6202ADULL,
		0xCAA48A0179CC3F10ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2F67FC369F94F6A6ULL,
		0x493D7C14AF2F9160ULL,
		0x5736F2CAE815CEE3ULL,
		0x8092861A2C1B8F91ULL,
		0x86EF7CA56DA457DFULL,
		0x45D166748C36C9EEULL,
		0x97F1A37E0C11C63DULL,
		0xC729C12B977CB0CEULL
	}};
	printf("Test Case 488\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x27A269AACFF3818DULL,
		0x539221770F654554ULL,
		0x85FE2638CCD9B077ULL,
		0xD4B3D656B9D68F41ULL,
		0xE2E44D253AD79207ULL,
		0xC5D49412B00780AEULL,
		0x2E5DB300754524BEULL,
		0x1325C0BCA84764EEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x182C78B584EA0A79ULL,
		0x9B7EFE6080EB45B1ULL,
		0x3842479938B223EFULL,
		0x28F3DFAF516820ADULL,
		0xC38A0EF1429D2054ULL,
		0x5A430FF240BF7F85ULL,
		0x81C61B7A86F8F709ULL,
		0xEAD9BDDF123A7AD6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3F8E111F4B198BF4ULL,
		0xC8ECDF178F8E00E5ULL,
		0xBDBC61A1F46B9398ULL,
		0xFC4009F9E8BEAFECULL,
		0x216E43D4784AB253ULL,
		0x9F979BE0F0B8FF2BULL,
		0xAF9BA87AF3BDD3B7ULL,
		0xF9FC7D63BA7D1E38ULL
	}};
	printf("Test Case 489\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xDBABF988FDBCBFD0ULL,
		0xE36A044B873311B1ULL,
		0x23F7425DD6CF72C0ULL,
		0xFFA076652C23C4B6ULL,
		0xDCA7371F112D3998ULL,
		0xF509389FEBECE528ULL,
		0xBB70E050E872726FULL,
		0x3D00D3B2BABDF1EDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x252A9190FC1590A2ULL,
		0x50B15332D5EE670CULL,
		0x0FEBE022ABDAD95AULL,
		0x1521E81C1CEF07B5ULL,
		0xFE1F7EE31D1A1857ULL,
		0x1B7D9A6AAC9CE0BBULL,
		0x35B718EEFF02100EULL,
		0x8B56BC6E6459588BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFE81681801A92F72ULL,
		0xB3DB577952DD76BDULL,
		0x2C1CA27F7D15AB9AULL,
		0xEA819E7930CCC303ULL,
		0x22B849FC0C3721CFULL,
		0xEE74A2F547700593ULL,
		0x8EC7F8BE17706261ULL,
		0xB6566FDCDEE4A966ULL
	}};
	printf("Test Case 490\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xC173341E0171D716ULL,
		0x004D157143F47739ULL,
		0x7F612BF736F16B9DULL,
		0xB45A26A528851C6EULL,
		0xE56B35A6D437661AULL,
		0xB325F53ABB708950ULL,
		0xDCE97CD40711FA96ULL,
		0x9ACC5BCE50418696ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8F59F9537CDE68EBULL,
		0x7392AD608410A1CCULL,
		0x9D6ACDDF1F01087DULL,
		0xF0F01C82558DFC87ULL,
		0x8F71A496E33CAD4BULL,
		0xD5F1BD8497DA2979ULL,
		0x3BAD77FD076CCD0EULL,
		0x7D6D5362E5F712C1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4E2ACD4D7DAFBFFDULL,
		0x73DFB811C7E4D6F5ULL,
		0xE20BE62829F063E0ULL,
		0x44AA3A277D08E0E9ULL,
		0x6A1A9130370BCB51ULL,
		0x66D448BE2CAAA029ULL,
		0xE7440B29007D3798ULL,
		0xE7A108ACB5B69457ULL
	}};
	printf("Test Case 491\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x6E61255DB8D7C517ULL,
		0x82604B67711792E5ULL,
		0xC1C3C47857ACB1B8ULL,
		0xE691FE0F519A66C8ULL,
		0x0C577C92480BBD58ULL,
		0xA79F7DB5BCA084A0ULL,
		0xDDA0B7130ABAC25CULL,
		0xE9151AA0C243941AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4D7BBAD438694955ULL,
		0x49543D9847812964ULL,
		0xE09860C22C01B080ULL,
		0x34445C52EDBAF0DCULL,
		0x4B9CDACC05869E72ULL,
		0xDE3F8FBF77D8328AULL,
		0x561788DB8A163BE8ULL,
		0x48D9A9EA41E8B6AAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x231A9F8980BE8C42ULL,
		0xCB3476FF3696BB81ULL,
		0x215BA4BA7BAD0138ULL,
		0xD2D5A25DBC209614ULL,
		0x47CBA65E4D8D232AULL,
		0x79A0F20ACB78B62AULL,
		0x8BB73FC880ACF9B4ULL,
		0xA1CCB34A83AB22B0ULL
	}};
	printf("Test Case 492\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x424D7773D4468149ULL,
		0x31CC940494AD12C1ULL,
		0x8EDEC7A9DC5B94B1ULL,
		0xD29765A86D68BED9ULL,
		0x42B917695D2FAC99ULL,
		0x255302176BAF7107ULL,
		0xDE28205172148609ULL,
		0xE185700AE19DAD7DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFE54B58533D925F0ULL,
		0xBE48346AA8E5A438ULL,
		0xB2C34B8D2261C89FULL,
		0x711BE4389E270974ULL,
		0x770A4CC6F0DC9E80ULL,
		0xBDC7B8E91958D859ULL,
		0x5B4E97778046B7F5ULL,
		0x5F6F8990DCDACF7BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBC19C2F6E79FA4B9ULL,
		0x8F84A06E3C48B6F9ULL,
		0x3C1D8C24FE3A5C2EULL,
		0xA38C8190F34FB7ADULL,
		0x35B35BAFADF33219ULL,
		0x9894BAFE72F7A95EULL,
		0x8566B726F25231FCULL,
		0xBEEAF99A3D476206ULL
	}};
	printf("Test Case 493\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xD8CDB67D22465E49ULL,
		0xF0D053BF3CCF81EBULL,
		0x0E86F88F1C827E51ULL,
		0x242A9EA24AEBFD41ULL,
		0xFDCE0D40842B9C6FULL,
		0xD15B69C3C3B8D57CULL,
		0x9D2D3DEA564EB1A2ULL,
		0x1CDFA15EEDEC3485ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x912DE0E3B2513B32ULL,
		0x2D59ACAFAA9CE0C6ULL,
		0x7333E4FEC0A1787EULL,
		0x27FA6D1BF662D02DULL,
		0xA25EECA1881D7EBAULL,
		0x30B5B66A133E5E2DULL,
		0xFEAFEC0FC5871270ULL,
		0x088BBF3FCF1D3E2DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x49E0569E9017657BULL,
		0xDD89FF109653612DULL,
		0x7DB51C71DC23062FULL,
		0x03D0F3B9BC892D6CULL,
		0x5F90E1E10C36E2D5ULL,
		0xE1EEDFA9D0868B51ULL,
		0x6382D1E593C9A3D2ULL,
		0x14541E6122F10AA8ULL
	}};
	printf("Test Case 494\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x4D37CC111D789A7DULL,
		0xC4B1CB451FBE8A17ULL,
		0x83CCE3A0FEAF3A93ULL,
		0x5AC62A53887F418AULL,
		0x7DBF06ECE4D857AFULL,
		0x7C627EF9B9381F68ULL,
		0x798482791000F931ULL,
		0x8A11F0CCA7F2E33EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF2D1D1605132F6D4ULL,
		0x4316C2CACA2C5449ULL,
		0xAA0C864A4303E59CULL,
		0xA2612F00B499B8F3ULL,
		0x047FDAC0BC22CBD8ULL,
		0x43016A1B92A8DEDBULL,
		0xB42F95563B6CAEEBULL,
		0xBCB597F2913F6C2FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBFE61D714C4A6CA9ULL,
		0x87A7098FD592DE5EULL,
		0x29C065EABDACDF0FULL,
		0xF8A705533CE6F979ULL,
		0x79C0DC2C58FA9C77ULL,
		0x3F6314E22B90C1B3ULL,
		0xCDAB172F2B6C57DAULL,
		0x36A4673E36CD8F11ULL
	}};
	printf("Test Case 495\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x9309109028770C14ULL,
		0xC2FE3A1ECC6F3274ULL,
		0x99FEF95A8FA951DFULL,
		0x8EC85BBEA4D04F99ULL,
		0xF7BCFCF502ADD6B3ULL,
		0xD0965A38AC10D1B0ULL,
		0x4E0EAF9EA8709B58ULL,
		0xB1F66275C7E9A6EAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3F40CE6568A8F9A3ULL,
		0xAC2FF49ECE37EE0DULL,
		0xA1435E79821B3889ULL,
		0xC4D0D5F5E02FDB5EULL,
		0xEE2634A206BA28F3ULL,
		0x9CD5A8B221BB3754ULL,
		0x02CA946C6BC787D4ULL,
		0xD0D4AF114C64836BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAC49DEF540DFF5B7ULL,
		0x6ED1CE800258DC79ULL,
		0x38BDA7230DB26956ULL,
		0x4A188E4B44FF94C7ULL,
		0x199AC8570417FE40ULL,
		0x4C43F28A8DABE6E4ULL,
		0x4CC43BF2C3B71C8CULL,
		0x6122CD648B8D2581ULL
	}};
	printf("Test Case 496\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0xBEBB1B0C7EEB7FF2ULL,
		0x21772489FDF192D2ULL,
		0xA6CB8777EB4389A7ULL,
		0x6E338D5ADD0D782EULL,
		0xCB99E8EE20DD4A7EULL,
		0x52C3A250425394C2ULL,
		0xE5CE0202729169C5ULL,
		0xB45C20E12E22FC13ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6EBB75DE14F52A32ULL,
		0x7E64ED3ED1B806E9ULL,
		0x4EA640752BBD4E78ULL,
		0xA0D050449E0B5199ULL,
		0x5FA1A3FC0635FE76ULL,
		0x25E01985079BEC9BULL,
		0x93014993651314B4ULL,
		0xD10B348706AC871BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD0006ED26A1E55C0ULL,
		0x5F13C9B72C49943BULL,
		0xE86DC702C0FEC7DFULL,
		0xCEE3DD1E430629B7ULL,
		0x94384B1226E8B408ULL,
		0x7723BBD545C87859ULL,
		0x76CF4B9117827D71ULL,
		0x65571466288E7B08ULL
	}};
	printf("Test Case 497\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x7AF82CBBE78BAE2CULL,
		0x003F448A82C9E4FBULL,
		0xE1FC1C8CFD659177ULL,
		0x1221564EF7D7808CULL,
		0x676A54C937156BCAULL,
		0x98743A407263CC8BULL,
		0x9CF849A2B93E0782ULL,
		0xE239DA795EF217B0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE5A2162CC3963695ULL,
		0xDDF313BC7CC04BF1ULL,
		0x02CFD90628524F6AULL,
		0x9F60A3F1FCB1B68AULL,
		0xA22B624EC8073CCCULL,
		0x1C66D23D0AC1D3EAULL,
		0x630AA6BB986700D2ULL,
		0x4E0801D249616F79ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9F5A3A97241D98B9ULL,
		0xDDCC5736FE09AF0AULL,
		0xE333C58AD537DE1DULL,
		0x8D41F5BF0B663606ULL,
		0xC5413687FF125706ULL,
		0x8412E87D78A21F61ULL,
		0xFFF2EF1921590750ULL,
		0xAC31DBAB179378C9ULL
	}};
	printf("Test Case 498\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x32961A4F158835E7ULL,
		0xB774650BD0C3AFBBULL,
		0x9FD4A8D2F9C51925ULL,
		0x3B25E7F22495A158ULL,
		0x601067B8D4452C0FULL,
		0xBA20296E7E260856ULL,
		0xFEA93D4A3545143BULL,
		0x4AA8DD4CAB9245E0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC62545349D46A423ULL,
		0x8B54F770E1CE4EA9ULL,
		0xF4B4C053578CEE32ULL,
		0xC79CC8AE02EC49BDULL,
		0x735300A02FFFE32DULL,
		0x05CC7742399C8686ULL,
		0x1A38EF53B1B95F3CULL,
		0xF3D7024F98DC0361ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF4B35F7B88CE91C4ULL,
		0x3C20927B310DE112ULL,
		0x6B606881AE49F717ULL,
		0xFCB92F5C2679E8E5ULL,
		0x13436718FBBACF22ULL,
		0xBFEC5E2C47BA8ED0ULL,
		0xE491D21984FC4B07ULL,
		0xB97FDF03334E4681ULL
	}};
	printf("Test Case 499\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
		0x67C48E692DA5A005ULL,
		0x8BA53EAABBFE4E96ULL,
		0xD7062088C74F2DCFULL,
		0xD94ED749B45B35FAULL,
		0x5EDA344760B11DFAULL,
		0x8090CB56C6EE33DFULL,
		0x62A5A1765D528321ULL,
		0x0B7E7B85B588F39DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x22E5713E84A50309ULL,
		0x4BE74814F6E17714ULL,
		0xAB9748D2ECDECF68ULL,
		0x00E13C7B7F9DBFB0ULL,
		0x34B843E3B5975D15ULL,
		0x4249AFE5E8E7D592ULL,
		0xC2DE8F12E7247475ULL,
		0xA0FA70C0CC1AA5F3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4521FF57A900A30CULL,
		0xC04276BE4D1F3982ULL,
		0x7C91685A2B91E2A7ULL,
		0xD9AFEB32CBC68A4AULL,
		0x6A6277A4D52640EFULL,
		0xC2D964B32E09E64DULL,
		0xA07B2E64BA76F754ULL,
		0xAB840B457992566EULL
	}};
	printf("Test Case 500\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
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
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4D7EEB31F0D698A9ULL,
		0xB7588D717B283C2DULL,
		0x8F85DCBC5E337546ULL,
		0xB196910742DEC326ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC1FFD58F42544EB8ULL,
		0xDB5616B766DC4A3CULL,
		0x83D4C940AAAFFB0BULL,
		0x50CEE1BA054063E5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC1FFD58F42544EB8ULL,
		0xDB5616B766DC4A3CULL,
		0x83D4C940AAAFFB0BULL,
		0x50CEE1BA054063E5ULL,
		0x4D7EEB31F0D698A9ULL,
		0xB7588D717B283C2DULL,
		0x8F85DCBC5E337546ULL,
		0xB196910742DEC326ULL
	}};
	printf("Test Case 501\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 501 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -501;
	} else {
		printf("Test Case 501 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6F66A677C9F481DFULL,
		0xD54865EAE695EF9AULL,
		0xF046AF2ACA020F8CULL,
		0x98DAC3B05A1DD37EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x36E0AFA63247C6A4ULL,
		0x2EE636E498E52383ULL,
		0xAA6A2DC09599967EULL,
		0xEE63AD4C9D2B408CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x36E0AFA63247C6A4ULL,
		0x2EE636E498E52383ULL,
		0xAA6A2DC09599967EULL,
		0xEE63AD4C9D2B408CULL,
		0x6F66A677C9F481DFULL,
		0xD54865EAE695EF9AULL,
		0xF046AF2ACA020F8CULL,
		0x98DAC3B05A1DD37EULL
	}};
	printf("Test Case 502\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 502 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -502;
	} else {
		printf("Test Case 502 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF0F538BF24017598ULL,
		0xEEAE53CC44ED1A84ULL,
		0x9E8CF83C1FFE479EULL,
		0xF3B0E9EE04A0BF3AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x746BFAFCE8ADD0E3ULL,
		0x1E582AC112E2C26EULL,
		0xE9A80F625161E979ULL,
		0xDC59665D70E16115ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x746BFAFCE8ADD0E3ULL,
		0x1E582AC112E2C26EULL,
		0xE9A80F625161E979ULL,
		0xDC59665D70E16115ULL,
		0xF0F538BF24017598ULL,
		0xEEAE53CC44ED1A84ULL,
		0x9E8CF83C1FFE479EULL,
		0xF3B0E9EE04A0BF3AULL
	}};
	printf("Test Case 503\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 503 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -503;
	} else {
		printf("Test Case 503 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x43C417FAC1101F38ULL,
		0x0E7EBD1FF09973F6ULL,
		0x5560052BF50E8CFAULL,
		0x2C52DEC90A33D8DFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFE486881FB94597BULL,
		0x7F5D2BCF404B9077ULL,
		0x4B331D0203359E6FULL,
		0x6986EF734F2234C1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFE486881FB94597BULL,
		0x7F5D2BCF404B9077ULL,
		0x4B331D0203359E6FULL,
		0x6986EF734F2234C1ULL,
		0x43C417FAC1101F38ULL,
		0x0E7EBD1FF09973F6ULL,
		0x5560052BF50E8CFAULL,
		0x2C52DEC90A33D8DFULL
	}};
	printf("Test Case 504\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 504 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -504;
	} else {
		printf("Test Case 504 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB82000B1B3E8E5DCULL,
		0x515155B41E580B9EULL,
		0xAA7E6B4B6ACCF9A0ULL,
		0xB7E48ED1DE481915ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x01F586E131EDED94ULL,
		0x0F5756C3C4BD55FFULL,
		0x1387AE5C978E5319ULL,
		0xCE40E1B48C56E476ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x01F586E131EDED94ULL,
		0x0F5756C3C4BD55FFULL,
		0x1387AE5C978E5319ULL,
		0xCE40E1B48C56E476ULL,
		0xB82000B1B3E8E5DCULL,
		0x515155B41E580B9EULL,
		0xAA7E6B4B6ACCF9A0ULL,
		0xB7E48ED1DE481915ULL
	}};
	printf("Test Case 505\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 505 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -505;
	} else {
		printf("Test Case 505 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0D3F0F086E1CE22BULL,
		0x250E014A18EE1428ULL,
		0x7EE63B7F57D6472FULL,
		0xBAD5C89CFA800D71ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x505D40DBE697E92AULL,
		0x4726D8AA9F1AE84CULL,
		0xC9D9A2929708B3F0ULL,
		0x005EC17F48AD48CAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x505D40DBE697E92AULL,
		0x4726D8AA9F1AE84CULL,
		0xC9D9A2929708B3F0ULL,
		0x005EC17F48AD48CAULL,
		0x0D3F0F086E1CE22BULL,
		0x250E014A18EE1428ULL,
		0x7EE63B7F57D6472FULL,
		0xBAD5C89CFA800D71ULL
	}};
	printf("Test Case 506\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 506 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -506;
	} else {
		printf("Test Case 506 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x16D4B32018AA20F9ULL,
		0xC8D81509EBC3C4EAULL,
		0x079446E0203584F0ULL,
		0xF0AFEBBCB7223BEFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD9D0E2B9F40BD91EULL,
		0xAC45648FB7758AB9ULL,
		0x2922A1C770479361ULL,
		0xB59B9813FE0439EBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD9D0E2B9F40BD91EULL,
		0xAC45648FB7758AB9ULL,
		0x2922A1C770479361ULL,
		0xB59B9813FE0439EBULL,
		0x16D4B32018AA20F9ULL,
		0xC8D81509EBC3C4EAULL,
		0x079446E0203584F0ULL,
		0xF0AFEBBCB7223BEFULL
	}};
	printf("Test Case 507\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 507 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -507;
	} else {
		printf("Test Case 507 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1DABE71010822CBCULL,
		0xD2FD91CF02BE50CAULL,
		0xECACFCA9AE277635ULL,
		0xDD84CA7A95C9189AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x76F1D21B0D413DE5ULL,
		0x57AED06BFAAE48D3ULL,
		0x6443D815612B75EBULL,
		0x98D9842CDD77F1FBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x76F1D21B0D413DE5ULL,
		0x57AED06BFAAE48D3ULL,
		0x6443D815612B75EBULL,
		0x98D9842CDD77F1FBULL,
		0x1DABE71010822CBCULL,
		0xD2FD91CF02BE50CAULL,
		0xECACFCA9AE277635ULL,
		0xDD84CA7A95C9189AULL
	}};
	printf("Test Case 508\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 508 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -508;
	} else {
		printf("Test Case 508 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1E9EB1324788A080ULL,
		0x033DC3C1100CA754ULL,
		0x8AA9E544EBC79516ULL,
		0xE37201349123B802ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF92074A28D916095ULL,
		0x19EB158B4E74BAFAULL,
		0x96AA487C5398F9FBULL,
		0xF7ACA3E1E601AAC4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF92074A28D916095ULL,
		0x19EB158B4E74BAFAULL,
		0x96AA487C5398F9FBULL,
		0xF7ACA3E1E601AAC4ULL,
		0x1E9EB1324788A080ULL,
		0x033DC3C1100CA754ULL,
		0x8AA9E544EBC79516ULL,
		0xE37201349123B802ULL
	}};
	printf("Test Case 509\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 509 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -509;
	} else {
		printf("Test Case 509 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1E98C38097F4283CULL,
		0x5ECF5696D9E7362AULL,
		0xF13971B959842861ULL,
		0xBC1D8B50E193AC63ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE9E75E93C9A8EA60ULL,
		0x7A45FE0A08542F91ULL,
		0xA58A1437124912C5ULL,
		0x1B69850606CFBDA9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE9E75E93C9A8EA60ULL,
		0x7A45FE0A08542F91ULL,
		0xA58A1437124912C5ULL,
		0x1B69850606CFBDA9ULL,
		0x1E98C38097F4283CULL,
		0x5ECF5696D9E7362AULL,
		0xF13971B959842861ULL,
		0xBC1D8B50E193AC63ULL
	}};
	printf("Test Case 510\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 510 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -510;
	} else {
		printf("Test Case 510 PASSED\n");
	}
	printf("---\n\n");
	return 0;
}