#include "../tests.h"

int32_t curve25519_key_cmp_test(void) {
	printf("Key Comparison Test\n");
	curve25519_key_t k1 = {.key64 = {
		0x33FAD3740B38BDEFULL,
		0x266F0DB9F107937FULL,
		0x65FEF32A22489F1FULL,
		0xCC58A49E295FCBC3ULL,
		0x64E8A7EE6E851FEBULL,
		0xC413E2AA01AF5BE5ULL,
		0x56184BA04E7A900AULL,
		0xF298CD453684831FULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0x9BFCCB07988A7303ULL,
		0x2053DDD44EC111C4ULL,
		0xF09F2428789E9FF6ULL,
		0x83022545B0BEBEBCULL,
		0x217705CE9D958F3FULL,
		0x02B3D71AAA96B95EULL,
		0x00E78BCAA20B5AF9ULL,
		0x883A07E42C397874ULL
	}};
	int t = 1;
	printf("Test Case 1\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	int32_t res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 1 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -1;
	} else {
		printf("Test Case 1 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x64E7E6D52DA9510EULL,
		0xCC39FAD7218FA3FAULL,
		0x822780D461779460ULL,
		0x9CC608351D46D4FEULL,
		0x16C9FA4317E40C4EULL,
		0x60BC80C7AA2ECC31ULL,
		0x8A3773E425D5C009ULL,
		0x776B6B7EB906327AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7FD1E566044B3BECULL,
		0xB232AF14DA9C0B24ULL,
		0xB1C1C500EAD994CEULL,
		0x3D80FEEE2DE4E44AULL,
		0x53BD63C804CBA990ULL,
		0xA2E244228941D004ULL,
		0xA6CFFB84CEB561C3ULL,
		0xF44BD8229555C2DBULL
	}};
	t = -1;
	printf("Test Case 2\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 2 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -2;
	} else {
		printf("Test Case 2 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF4C0C41232E3BC1DULL,
		0x7418A790A37538CAULL,
		0x554AA518EC7AB13BULL,
		0x5DBB7F4EFED4B1C9ULL,
		0x85A0A17B324E9E6AULL,
		0x2D074F3DC10C2310ULL,
		0x7F7FE8307F229534ULL,
		0xD76A30E29889100CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x663DCB88A8A06CA1ULL,
		0x15268E8E611006FCULL,
		0x3692DE1F4223D35EULL,
		0xC03B8FC879C5A600ULL,
		0xDC67EDC4BFA1B613ULL,
		0xF4B975D7E4A9E738ULL,
		0x5C3F44BD7CDF33E4ULL,
		0xA1869629E0E2DDDBULL
	}};
	t = 1;
	printf("Test Case 3\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 3 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -3;
	} else {
		printf("Test Case 3 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x76900252128C9DA7ULL,
		0x72F45164956BB59AULL,
		0x659ECCDD39D06A92ULL,
		0x9EDA91F458575A7AULL,
		0x94AA0C6927F93F34ULL,
		0xD58C0D84035776BEULL,
		0x35A586B72176E489ULL,
		0x8B9C396EC27F8AC7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x88772871F0F72A55ULL,
		0xDA788FAB7B7F78EDULL,
		0xBCA54EE1E01A01BDULL,
		0xD1EACB6860691CF3ULL,
		0x1127D42763C8829EULL,
		0xE9201101467541DDULL,
		0x97BF9BA779EEF286ULL,
		0xCA84A12EDA1C02F9ULL
	}};
	t = -1;
	printf("Test Case 4\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 4 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -4;
	} else {
		printf("Test Case 4 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x337F904BA6CD9D8FULL,
		0x20DD8E395AAA7A3BULL,
		0x4AFB28DBA7D1A013ULL,
		0x0DE8599C850960D9ULL,
		0x4701E29CD2658692ULL,
		0x4ACDBBE578E9B9C3ULL,
		0x6D7329EFA1E8E2E7ULL,
		0x39EADD385DD830C7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x337F904BA6CD9D8FULL,
		0x20DD8E395AAA7A3BULL,
		0x4AFB28DBA7D1A013ULL,
		0x0DE8599C850960D9ULL,
		0x4701E29CD2658692ULL,
		0x4ACDBBE578E9B9C3ULL,
		0x6D7329EFA1E8E2E7ULL,
		0x39EADD385DD830C7ULL
	}};
	t = 0;
	printf("Test Case 5\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 5 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -5;
	} else {
		printf("Test Case 5 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x042651C92676EBCCULL,
		0x511E565AF2982182ULL,
		0x826670C1E9DBA742ULL,
		0xFB2AD86E4B430BCBULL,
		0x102B79CA92F83488ULL,
		0xB7070826147D4603ULL,
		0x79340F008B3F811FULL,
		0xBA0B9EE2832ABED3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB1EF3C32E0A1617EULL,
		0x79ABC227FD752544ULL,
		0x0EC206C0DE361103ULL,
		0xFFBB59B6BBEF1F6FULL,
		0x5243796E134D9656ULL,
		0xACAF26ADAB27DEE2ULL,
		0x622790C8411B6AFCULL,
		0x2FE8831F87271A23ULL
	}};
	t = 1;
	printf("Test Case 6\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 6 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -6;
	} else {
		printf("Test Case 6 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x904197AA24692CA5ULL,
		0xF238594BA8931197ULL,
		0xB9BE31F00C51294CULL,
		0x80298C7A831C7933ULL,
		0xAFA57B45EF36BF0CULL,
		0xD7C6BB3AB25AA95EULL,
		0x717668BE7E4FFE5CULL,
		0xA0906B8803D8A89AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xACB41A7DE89E4E37ULL,
		0x119A3BBF4E65406DULL,
		0x0C61F0F5558A8205ULL,
		0xAD1E52D405758D59ULL,
		0xC79CD2B586B85A53ULL,
		0x933EBF2D13D326C1ULL,
		0xC90A883674317C7EULL,
		0xEA69FBE64624F6ECULL
	}};
	t = -1;
	printf("Test Case 7\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 7 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -7;
	} else {
		printf("Test Case 7 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE98B7262EE04E52DULL,
		0x3AA1A0132BD126C5ULL,
		0x3E8100A425A71006ULL,
		0x418843EF490E7D18ULL,
		0x38831E19F08BBEE6ULL,
		0xEC3D2D4FFCDA4DB9ULL,
		0xB339CD30F59E7860ULL,
		0x3625E87A86995E35ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD5B9101CF6D2BA9AULL,
		0x9160A38C71AC9B87ULL,
		0xCEFDE3C410AEBA03ULL,
		0x1F2A4994EBFB448CULL,
		0xACC10DD5DD57FF17ULL,
		0x1CA4DF7D791EE832ULL,
		0x79399C371F20FF0DULL,
		0xC8265A60F22CBE80ULL
	}};
	t = -1;
	printf("Test Case 8\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 8 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -8;
	} else {
		printf("Test Case 8 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x37B9045B921DD1C2ULL,
		0x2FA9A0CE09B16A95ULL,
		0x6BF2766CE1B02C3DULL,
		0xC2C786199549DD38ULL,
		0xF9CF747965D909D4ULL,
		0x92F793862AA6D0E2ULL,
		0x66F80C194CAD89E2ULL,
		0x96E919E841AA069CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x37B9045B921DD1C2ULL,
		0x2FA9A0CE09B16A95ULL,
		0x6BF2766CE1B02C3DULL,
		0xC2C786199549DD38ULL,
		0xF9CF747965D909D4ULL,
		0x92F793862AA6D0E2ULL,
		0x66F80C194CAD89E2ULL,
		0x96E919E841AA069CULL
	}};
	t = 0;
	printf("Test Case 9\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 9 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -9;
	} else {
		printf("Test Case 9 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x279721B42AAA9802ULL,
		0x789702DF81D9A82BULL,
		0x5185E0298BADD3B9ULL,
		0x93E21B0B56A86166ULL,
		0xB4495B779107595DULL,
		0xAFAEB2E0B90A4CE0ULL,
		0xD95887758D527594ULL,
		0xD86252776CC08E69ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9D9EB6ACE02DACA3ULL,
		0xF58176176AB3E958ULL,
		0x60928C7977C18D5AULL,
		0x9EB3822AE70FB326ULL,
		0x43529D0B0ACBF112ULL,
		0x8D6162119F5B4C2FULL,
		0xFF583A362CDFCDA3ULL,
		0x4003F061AFEECD9AULL
	}};
	t = 1;
	printf("Test Case 10\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 10 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -10;
	} else {
		printf("Test Case 10 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x46D54453856C73F4ULL,
		0xF6529C3CB954A414ULL,
		0x4824A67F61D615E5ULL,
		0x32E744B9593468B0ULL,
		0x617FB694129DA2AAULL,
		0x4B58F785754D65BFULL,
		0x5547DBAC147AD7A8ULL,
		0x2F4E5F5891E5F84CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBD1EAB37E024EC85ULL,
		0x5D79B587611D4738ULL,
		0x64511C35C1A86B44ULL,
		0x786FA0EFCC6CF5CAULL,
		0x0CAEECD12313D9A3ULL,
		0x40E9081D74F2A514ULL,
		0xC50B7EDD2BA79659ULL,
		0xE2627B922EB136C1ULL
	}};
	t = -1;
	printf("Test Case 11\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 11 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -11;
	} else {
		printf("Test Case 11 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9590807E3F295D76ULL,
		0xE7E4811AE9D9B1B5ULL,
		0x71D27329BFF5C0FCULL,
		0x26D406E547F2205AULL,
		0x35FAB47CDCC228F3ULL,
		0xFE75DFB2F0321E81ULL,
		0x7CBFFA1C0016B946ULL,
		0xE4D27E0B3ABEACC4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCBFBED1227046C03ULL,
		0xCDF583C11E431F9EULL,
		0x1A469CD661157340ULL,
		0x4B289EB6EA278BC7ULL,
		0x1E88E15A494C92FAULL,
		0x8F5588AA867A11C5ULL,
		0x05A1083BEE7EAEE3ULL,
		0x75B22B7C09CF8B0DULL
	}};
	t = 1;
	printf("Test Case 12\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 12 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -12;
	} else {
		printf("Test Case 12 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x87F483F7CE2A0206ULL,
		0xF539E1D5A3C2F1ECULL,
		0x5BC6BBC81F3D3E8EULL,
		0x4201374621DB9080ULL,
		0x84F37A9A65188109ULL,
		0xA8DD53477768F5ECULL,
		0x5F2A0B7A5C7E95BAULL,
		0x9B1A2AB53AD5D1ABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x87F483F7CE2A0206ULL,
		0xF539E1D5A3C2F1ECULL,
		0x5BC6BBC81F3D3E8EULL,
		0x4201374621DB9080ULL,
		0x84F37A9A65188109ULL,
		0xA8DD53477768F5ECULL,
		0x5F2A0B7A5C7E95BAULL,
		0x9B1A2AB53AD5D1ABULL
	}};
	t = 0;
	printf("Test Case 13\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 13 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -13;
	} else {
		printf("Test Case 13 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x012E04BABF7C4027ULL,
		0x3B14B1DAC19F6D7AULL,
		0x644797E495359187ULL,
		0x5DA23C9063775969ULL,
		0x7E2277F4D8B02869ULL,
		0xA5F550C61F44FA1FULL,
		0x86B78346FF46F918ULL,
		0x370F5540D03D360EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDCAD1A7A1FD025BDULL,
		0x2B29E89A5949E164ULL,
		0x890952DAF47E9AD0ULL,
		0x9CA90075E8E03FAEULL,
		0x5EB9EA3C72087717ULL,
		0xE855CF7D7D408355ULL,
		0x073551678F2AF3FEULL,
		0x6EAB624021E3FA29ULL
	}};
	t = -1;
	printf("Test Case 14\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 14 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -14;
	} else {
		printf("Test Case 14 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x15C6E2C8CF554AB7ULL,
		0x5BD300929B696DBFULL,
		0xBC8ACED4AF767978ULL,
		0x5BDAD6F411C56E57ULL,
		0x964F3E51762C6FFEULL,
		0xCB714AB42D8661DCULL,
		0x01A248B989336DE0ULL,
		0x15E89F499A43EBEBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3B63DFA001AD269CULL,
		0xFCB99499D3C54E2DULL,
		0x62CC2B0D279B9991ULL,
		0x74D54ED30877D9EEULL,
		0x94E2BA995F73EF83ULL,
		0x00AA300B7C104006ULL,
		0x0D2F7317984F4007ULL,
		0x95BECF2ED89B853AULL
	}};
	t = -1;
	printf("Test Case 15\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 15 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -15;
	} else {
		printf("Test Case 15 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE3900ED3FED0C729ULL,
		0xC3E7677F60F92204ULL,
		0x6F9B5C5AF375DA04ULL,
		0x8E0AB1E5B21D74BAULL,
		0x4B3479ED647DFFF4ULL,
		0xE9C48BF25CE33E0CULL,
		0x038FD06A05CCCF7DULL,
		0x936777E1AD14EB6EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE4BB4F1AFCA05F67ULL,
		0xB7BEE869C1F475EDULL,
		0x98AA791893C5795AULL,
		0x824A2DE8CDC4A523ULL,
		0x5E0A42453AC3597AULL,
		0x6B91BC39367B4B39ULL,
		0x548B7C120EEF769FULL,
		0xD0B1611FA42E752AULL
	}};
	t = -1;
	printf("Test Case 16\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 16 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -16;
	} else {
		printf("Test Case 16 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7818C3FB66BF3D7CULL,
		0x13AFD1FC412CC9E5ULL,
		0x63391EC9308E3E73ULL,
		0xFD2AE4F38B53B111ULL,
		0x2E7639DBB60B2E4BULL,
		0xB90607B2EA428F42ULL,
		0xB16F1265F5DDF7B0ULL,
		0x40A1550DD59F2FDAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7818C3FB66BF3D7CULL,
		0x13AFD1FC412CC9E5ULL,
		0x63391EC9308E3E73ULL,
		0xFD2AE4F38B53B111ULL,
		0x2E7639DBB60B2E4BULL,
		0xB90607B2EA428F42ULL,
		0xB16F1265F5DDF7B0ULL,
		0x40A1550DD59F2FDAULL
	}};
	t = 0;
	printf("Test Case 17\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 17 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -17;
	} else {
		printf("Test Case 17 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF9B03BCE5135C1F7ULL,
		0xB66376EDF5DF5FDBULL,
		0x397C808EE868C1DEULL,
		0xA7AF7C4B3A10978BULL,
		0x02588529F4477BF5ULL,
		0x473297DEADB5F3B7ULL,
		0x23AEB1F992325582ULL,
		0x69F5B0A3B3F2651FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBF13C19F3B30B187ULL,
		0x0617FB53B35AB5CBULL,
		0xDD9F389DDC367388ULL,
		0xC33EF269F24E83EFULL,
		0xBF86DF9DF1F95112ULL,
		0x385F35EED7BC5DFDULL,
		0xB2FA91E7D87B8F8FULL,
		0x2916E8AF127B7564ULL
	}};
	t = 1;
	printf("Test Case 18\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 18 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -18;
	} else {
		printf("Test Case 18 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x59EF94EDFA6A37CEULL,
		0xCD4AC972742F7BF8ULL,
		0xF2C02342DC657284ULL,
		0x493CEE67AA441A14ULL,
		0x4AE06FE5125C7D77ULL,
		0x2A0D46785C54D777ULL,
		0x64C95A7FB6E55384ULL,
		0x29CA3C01A46DA04AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA39A131EAD029A43ULL,
		0xC00D2D251B548037ULL,
		0x2DFE67ADCF952EF4ULL,
		0x77B9203ABA091BEDULL,
		0xCB73BA2186C074E7ULL,
		0x86B9F5E1DE174ED5ULL,
		0x7379E7EC4016EFF4ULL,
		0x909CD7638977E39EULL
	}};
	t = -1;
	printf("Test Case 19\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 19 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -19;
	} else {
		printf("Test Case 19 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB172F71FA2B2B65CULL,
		0x9A63B720E3586EEDULL,
		0x869FF43076DED76BULL,
		0x7226831D98DFFD7CULL,
		0x773A4BDAD529E7F1ULL,
		0xD7A1C0DDBF0C57E3ULL,
		0x94A34AAC4C58C7CFULL,
		0x2E914C83AD1E6201ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x72D083B3EDF8BDE5ULL,
		0x8098CE65CA38E62CULL,
		0xC6E86D6C4B3325E5ULL,
		0x6437B2E97205EBDEULL,
		0x44E74588D0322616ULL,
		0xA2B09429BB5E5C0FULL,
		0xF97DBCB6823388F0ULL,
		0xDC24223533C155B1ULL
	}};
	t = -1;
	printf("Test Case 20\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 20 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -20;
	} else {
		printf("Test Case 20 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC7E3773CBFD8DEA2ULL,
		0x044B1D4C87921C82ULL,
		0x9DAC2503E1942513ULL,
		0xDBEBD82E9DC193A2ULL,
		0x89A4AD6BF773EEFCULL,
		0x89DDF05CF7ED6ED0ULL,
		0x2615B75D99B5DE42ULL,
		0x736FB959CD495468ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC7E3773CBFD8DEA2ULL,
		0x044B1D4C87921C82ULL,
		0x9DAC2503E1942513ULL,
		0xDBEBD82E9DC193A2ULL,
		0x89A4AD6BF773EEFCULL,
		0x89DDF05CF7ED6ED0ULL,
		0x2615B75D99B5DE42ULL,
		0x736FB959CD495468ULL
	}};
	t = 0;
	printf("Test Case 21\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 21 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -21;
	} else {
		printf("Test Case 21 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8A505B8D1B0C5AE9ULL,
		0xEC17895BFAB1B7C3ULL,
		0x9B6AA3AF28184507ULL,
		0x9E5E5CAA10CDDE5BULL,
		0x2FC758B4948AC3CEULL,
		0x0D27C18B6ADA1D30ULL,
		0x1F65FF2344C5CE28ULL,
		0xE25C7360217F1BE6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9EA4471956B8696EULL,
		0xDCB4A8C1B4BBCFD6ULL,
		0x75803D827EB9533AULL,
		0x88A7322BB169EEB4ULL,
		0xF93A4D9D9CFFA501ULL,
		0xFC75BF3CFACBD26AULL,
		0x7B15D350271BE119ULL,
		0x492757596604B275ULL
	}};
	t = 1;
	printf("Test Case 22\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 22 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -22;
	} else {
		printf("Test Case 22 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3A2D9ECB95CF48A5ULL,
		0xCB938B5B59793D75ULL,
		0xF4B23227DF0D24E9ULL,
		0xAC7488B01629FC6FULL,
		0xEDA85D97583FA99DULL,
		0x1AFC62FD40FFEF2DULL,
		0xE0D5EE797A5065A4ULL,
		0xD6362348043A2AE0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6F312387C3B8921CULL,
		0xF6215634912B05DEULL,
		0xD883390E0C27A629ULL,
		0x8141D61E96AC7EC5ULL,
		0x08A7178E752D2618ULL,
		0x0660C071C478EC9EULL,
		0x44EA9EB1FB87DB49ULL,
		0xD08B077B25E23768ULL
	}};
	t = 1;
	printf("Test Case 23\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 23 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -23;
	} else {
		printf("Test Case 23 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xECD20DC50B3BF7C8ULL,
		0x8BA392F83E25BE29ULL,
		0x40638F6C3D9594A4ULL,
		0xA275D41BB41C5323ULL,
		0x95B9589CFC5EC5EBULL,
		0xFD69F2C5A805952DULL,
		0x43EB908F51A6DF7AULL,
		0xCE5B7FC09A7D7903ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDC909683F89D6F84ULL,
		0x5D0D3FF412A10A52ULL,
		0x0CEE2B1BCD19E009ULL,
		0x0853B7039459BC26ULL,
		0x7D95599A70DBA6DEULL,
		0xA541100C4ED241F7ULL,
		0x88A7CDBFB6B153D7ULL,
		0xC009F8926981547DULL
	}};
	t = 1;
	printf("Test Case 24\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 24 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -24;
	} else {
		printf("Test Case 24 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9722FEF05082601BULL,
		0xFE72034DAF685003ULL,
		0x1CB2A3350C2B0434ULL,
		0x7B908AB3899C57AAULL,
		0xE2FAB605B420EC12ULL,
		0x3B6D1316EF543240ULL,
		0x549F167993927837ULL,
		0xAFEBBE0967FAE237ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9722FEF05082601BULL,
		0xFE72034DAF685003ULL,
		0x1CB2A3350C2B0434ULL,
		0x7B908AB3899C57AAULL,
		0xE2FAB605B420EC12ULL,
		0x3B6D1316EF543240ULL,
		0x549F167993927837ULL,
		0xAFEBBE0967FAE237ULL
	}};
	t = 0;
	printf("Test Case 25\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 25 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -25;
	} else {
		printf("Test Case 25 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x83402D2F36950898ULL,
		0x331FE21DCD600ED4ULL,
		0xC265ABA018950F42ULL,
		0x2E5D5341630B45CEULL,
		0xD9A00171559114A0ULL,
		0xFE3FD7B2AD98300DULL,
		0x2E352E9A334185EDULL,
		0x352B792174F20CF5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF555B05407BDF7FFULL,
		0xF9240E66B2EF796AULL,
		0x76FDCAA7F63D9931ULL,
		0x65865650BDA82D3DULL,
		0x08B405A6C49209E9ULL,
		0xB1A10D51D5985F17ULL,
		0xCBD006925CAF682EULL,
		0x2BCDCB0ACB4F7B03ULL
	}};
	t = 1;
	printf("Test Case 26\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 26 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -26;
	} else {
		printf("Test Case 26 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x916031614027A793ULL,
		0x9C195ECC146868BBULL,
		0xF1C1AD49B8C4808DULL,
		0xEF2A44E198851AD9ULL,
		0x0DAB647B542DE5B5ULL,
		0x9F65195B0163AABDULL,
		0x91A883F1E887F946ULL,
		0xBE59BD19773F800DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1B7F2088C96B2C97ULL,
		0x92F8575291186DB5ULL,
		0x9F71B013760C914FULL,
		0x977037DE416D969EULL,
		0xAB063050A7A2042BULL,
		0xE3A3BCF89F21170CULL,
		0x29F356E4C4A13DAFULL,
		0x34247A2B9CFE3583ULL
	}};
	t = 1;
	printf("Test Case 27\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 27 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -27;
	} else {
		printf("Test Case 27 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8991949A31E540A9ULL,
		0x622759D1BA890D74ULL,
		0x4190254E5035569DULL,
		0xDAE36B2F9362B86EULL,
		0x198969CCE0D277DBULL,
		0xE00ECC944EF41EF0ULL,
		0x8158EC3081CF5CCFULL,
		0xB0F6E212D17776D8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB3086BD11060173FULL,
		0xF70FB09CCB144A62ULL,
		0xE369A1D8E618F495ULL,
		0xE465A39BDFB71F17ULL,
		0x4C90D1AD2E7F4FB2ULL,
		0x969B58BA1DF008F0ULL,
		0xF36AC269DE984638ULL,
		0x9B0D8047A31B66CEULL
	}};
	t = 1;
	printf("Test Case 28\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 28 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -28;
	} else {
		printf("Test Case 28 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x433B27504A384A1CULL,
		0xA41AF9EF81E1D972ULL,
		0xE45905C120568281ULL,
		0x753A7F1D36A3D17DULL,
		0xDF9339926DA5B9F9ULL,
		0xC4FEA861BA8A12E5ULL,
		0x759FCF53EBEE7979ULL,
		0x7B82C12253859F37ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x433B27504A384A1CULL,
		0xA41AF9EF81E1D972ULL,
		0xE45905C120568281ULL,
		0x753A7F1D36A3D17DULL,
		0xDF9339926DA5B9F9ULL,
		0xC4FEA861BA8A12E5ULL,
		0x759FCF53EBEE7979ULL,
		0x7B82C12253859F37ULL
	}};
	t = 0;
	printf("Test Case 29\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 29 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -29;
	} else {
		printf("Test Case 29 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0F4FF994C912E7F4ULL,
		0x2F7786DE8AA8BFC1ULL,
		0x48EA306A7D462536ULL,
		0xA0E8AAC04284CF14ULL,
		0x2F3A1B97BFDC33D3ULL,
		0xDBDD4F2F83C453B8ULL,
		0xD2A080CAFE342380ULL,
		0x10008AEE12C27DCBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFA3DB5483EDE0A88ULL,
		0x2F721EAF868F0FB2ULL,
		0x0419D7E548466DE1ULL,
		0x35CF8F5CEBC8F54EULL,
		0x81BE2B3EEFFEF374ULL,
		0x2BD5757DC481C107ULL,
		0x3032C79FBF93C07DULL,
		0x370376677FA021CDULL
	}};
	t = -1;
	printf("Test Case 30\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 30 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -30;
	} else {
		printf("Test Case 30 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2C23E76751C9C5C1ULL,
		0x27234D9045A43255ULL,
		0x3B981D272CE2D719ULL,
		0x2E6AD4618D9CA444ULL,
		0x16C72F8161FA8C77ULL,
		0x3B131660EFCDB7EFULL,
		0x5B464E0BED5471E1ULL,
		0xB188B66617177C16ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC5D3FBC9E24FAEEBULL,
		0x71DA0F5C79E3169FULL,
		0x99A959C3B8611818ULL,
		0x889AAE4834617607ULL,
		0xB5E9A44CEBF10EDDULL,
		0x922AB2037D087382ULL,
		0xA9E2C48786B92C41ULL,
		0x7EC4F6E232ED7BB8ULL
	}};
	t = 1;
	printf("Test Case 31\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 31 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -31;
	} else {
		printf("Test Case 31 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB06BEF806946B678ULL,
		0x9859F2E96CE626F7ULL,
		0x2FCBD03EE6A46DFFULL,
		0x2FF8E23A3CB2C9D2ULL,
		0xC58A874024F815AAULL,
		0x9AC4C639D3684BEDULL,
		0x89A66FDD32713F0FULL,
		0xEA2EBEB842F9295CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0C698C6A1B7FF85BULL,
		0xFAB9661648258688ULL,
		0xBB9F20E6C8B9821DULL,
		0x5B99EA09E5169631ULL,
		0x522C3C3D759295C7ULL,
		0xD5CA51D3EF209681ULL,
		0xC3FE304B2AA9AF9AULL,
		0xF7A1CDB4F82F3AFBULL
	}};
	t = -1;
	printf("Test Case 32\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 32 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -32;
	} else {
		printf("Test Case 32 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA3B2F2EB750E266CULL,
		0x61E8D1C6C1DE7E53ULL,
		0x76F185B74FF944C5ULL,
		0x9176BE8167434003ULL,
		0xFFD6E78C67EC3294ULL,
		0xD93EA8EF0C0ABC2EULL,
		0x44090F7A5D27D977ULL,
		0x86577FF454434DE1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA3B2F2EB750E266CULL,
		0x61E8D1C6C1DE7E53ULL,
		0x76F185B74FF944C5ULL,
		0x9176BE8167434003ULL,
		0xFFD6E78C67EC3294ULL,
		0xD93EA8EF0C0ABC2EULL,
		0x44090F7A5D27D977ULL,
		0x86577FF454434DE1ULL
	}};
	t = 0;
	printf("Test Case 33\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 33 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -33;
	} else {
		printf("Test Case 33 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x750137C20598D7E8ULL,
		0x624E7867EA6D1E4AULL,
		0x46651B7324575529ULL,
		0x56681EE50D87498DULL,
		0x0F898511B1DB2706ULL,
		0xC70DA467C1AF38BDULL,
		0xD13E53C234C63FBCULL,
		0x2F7F2C89CEDAC941ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA91FBE3E19404B1EULL,
		0xF5F6D6EB71E6C90CULL,
		0x13A9F18A9D60D93DULL,
		0xA680745F4372D6F8ULL,
		0xA48642B30233BF6BULL,
		0x0190E37172DAAA80ULL,
		0x84795EEEDEF6C84DULL,
		0x931AA6FA46BE212FULL
	}};
	t = -1;
	printf("Test Case 34\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 34 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -34;
	} else {
		printf("Test Case 34 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5AA45932A1691537ULL,
		0x104A68704FA8299AULL,
		0x446C83F4948AE783ULL,
		0x05FC5F49E52CA860ULL,
		0xA0AF0ED56A6B2820ULL,
		0x9BFF0A53EAB98220ULL,
		0x0D1C9284098BC0E2ULL,
		0xA6B82C1C3C73BEEBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBD45FC49C05A1FE2ULL,
		0x85510016E2E43CD5ULL,
		0xC71DC83E19FF5AFBULL,
		0xFEE9CC55C46419FCULL,
		0x8841D370867E1044ULL,
		0x2BE228524150479EULL,
		0xA785BBF14DC739FCULL,
		0xCB1E97F703234D01ULL
	}};
	t = -1;
	printf("Test Case 35\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 35 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -35;
	} else {
		printf("Test Case 35 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x74CD15F319A24EC1ULL,
		0x8CE167265D8467EFULL,
		0xF6165B3CB0248016ULL,
		0x38196B7BA6BCC499ULL,
		0xF4BF03FFF19B2A9FULL,
		0xF2263AA2BA41076EULL,
		0x6D4CD1633530A710ULL,
		0x75B8C69A35C2F0E1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF3C13CDF2AF2B0BEULL,
		0x917B04944B0E6758ULL,
		0x1003F187187B44E5ULL,
		0x755E4CD353DF197AULL,
		0xE6340374A619F527ULL,
		0xD856FDFFBFE2F7EFULL,
		0x0682F503C7AC6F27ULL,
		0x4D55D67EAF461D13ULL
	}};
	t = 1;
	printf("Test Case 36\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 36 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -36;
	} else {
		printf("Test Case 36 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7484FC0CA69F22DDULL,
		0x0576DDC91E298CD7ULL,
		0xBDFC2C292A8DD24CULL,
		0xA9CCCFF1619A1A8CULL,
		0xF4542A441CE70B8CULL,
		0x1D3EB6C3D4B2F08AULL,
		0xE682B5B60018C617ULL,
		0x8071E0E066EF5395ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7484FC0CA69F22DDULL,
		0x0576DDC91E298CD7ULL,
		0xBDFC2C292A8DD24CULL,
		0xA9CCCFF1619A1A8CULL,
		0xF4542A441CE70B8CULL,
		0x1D3EB6C3D4B2F08AULL,
		0xE682B5B60018C617ULL,
		0x8071E0E066EF5395ULL
	}};
	t = 0;
	printf("Test Case 37\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 37 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -37;
	} else {
		printf("Test Case 37 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6E25D92BF95D3629ULL,
		0xFA6BCC2BF4C78E7DULL,
		0x0D2422CB3D1A1854ULL,
		0x340D3E9479E2C7BAULL,
		0xC08B52C1B2E65A46ULL,
		0xE6493513D3E32ABFULL,
		0x931C6CA6079BD473ULL,
		0x29E6116753CF90EBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2AFCDCD57664A188ULL,
		0x44D7B58A5C9FF833ULL,
		0x997FE2F3695A76DBULL,
		0xBDFA88C730E1BC4FULL,
		0xAFA4FD0EE649D89CULL,
		0x851352722875E987ULL,
		0xAD972204688443F1ULL,
		0x8457C1F2961B94F6ULL
	}};
	t = -1;
	printf("Test Case 38\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 38 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -38;
	} else {
		printf("Test Case 38 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x301700F7C899BD25ULL,
		0x6E9A5D47C21ECB8EULL,
		0x6C2410F90CE51703ULL,
		0x0989095F10BA3B3BULL,
		0xDDB0CC73C2FD324DULL,
		0x98F2CC594B52F5BEULL,
		0x949C3F781540026BULL,
		0xFCBE7FC427BBC1C4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x721922B98062A584ULL,
		0x07007A63C08B10CDULL,
		0x533FC86228FB2A45ULL,
		0xE3716D72F7354FBFULL,
		0x9A1D68AA929704AEULL,
		0x363D2E4970F3A240ULL,
		0x79E3135BB5DED303ULL,
		0x23863F15CE5C482CULL
	}};
	t = 1;
	printf("Test Case 39\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 39 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -39;
	} else {
		printf("Test Case 39 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x21EC9B13F37AC760ULL,
		0x470CB0CC208FBF9EULL,
		0x9E4ED682D42029EDULL,
		0x405FFFF09D91624BULL,
		0x17FAD162A195420AULL,
		0x74418B4492A6DA62ULL,
		0x5258A5519DE10F92ULL,
		0x4D0486C28CA7F828ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x70750150BC34B956ULL,
		0xFE23C8F5761036EDULL,
		0xD348D4B16D1E3943ULL,
		0x6A5356D1980EF6A8ULL,
		0x2379D5F81D2A600CULL,
		0x639D6F233EB7AE49ULL,
		0x7898438901211DC1ULL,
		0xDE6101453A767A2DULL
	}};
	t = -1;
	printf("Test Case 40\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 40 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -40;
	} else {
		printf("Test Case 40 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDDF170FCC28FDAABULL,
		0xFE4E351D1999ED9FULL,
		0x36B22DEDDE179C06ULL,
		0xEC3B5A54A9C14471ULL,
		0x14EEA15CEBC31772ULL,
		0x3FE0EE9AD34C6D84ULL,
		0x7856B8F682ED5E9DULL,
		0xB088DDB20AC1999EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDDF170FCC28FDAABULL,
		0xFE4E351D1999ED9FULL,
		0x36B22DEDDE179C06ULL,
		0xEC3B5A54A9C14471ULL,
		0x14EEA15CEBC31772ULL,
		0x3FE0EE9AD34C6D84ULL,
		0x7856B8F682ED5E9DULL,
		0xB088DDB20AC1999EULL
	}};
	t = 0;
	printf("Test Case 41\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 41 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -41;
	} else {
		printf("Test Case 41 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x21F020C9FC9889C7ULL,
		0x1B1AB8E1845B95DCULL,
		0xCA5DD0108C839103ULL,
		0x7287C7D697D9C115ULL,
		0xF258BA989E05D847ULL,
		0x47AE17B728FEBC59ULL,
		0xA9ACBA1F85AD7156ULL,
		0x4D14C7E7C8F0F818ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD202AD6B992A6FA9ULL,
		0x4D94FD84C329712EULL,
		0x3474798AA3C69CACULL,
		0x0F3EE402C7FDDD62ULL,
		0x8AEDB157B2FCFB78ULL,
		0x104044534A501693ULL,
		0x73BE27524885CC2EULL,
		0x00D8920B5F502F5CULL
	}};
	t = 1;
	printf("Test Case 42\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 42 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -42;
	} else {
		printf("Test Case 42 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x89944F2F164F3B66ULL,
		0x7019CE3FD8294BE4ULL,
		0xD716E43544D002AAULL,
		0xA8EC6F4D71AF679BULL,
		0x8B15147A47A4B443ULL,
		0xDC476E753EA68729ULL,
		0xB5361FBBF40804D7ULL,
		0x4854034A83601E56ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x695F825FA7163184ULL,
		0xB4A5DFC27CCD18CFULL,
		0xB584BBA1685F8882ULL,
		0x8944F59DE49D1367ULL,
		0x90696A48FBB90910ULL,
		0x3824D3E13BBDFC64ULL,
		0xBF6CE84B5D7CD0DCULL,
		0x9C9299F9B6AC55EAULL
	}};
	t = -1;
	printf("Test Case 43\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 43 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -43;
	} else {
		printf("Test Case 43 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFA60B3A79683C810ULL,
		0xFE61467547239831ULL,
		0xC42534514AA58038ULL,
		0x4275AD6DAA054D52ULL,
		0x664A79A5ADA04557ULL,
		0x7F9963A1FF4C1DBEULL,
		0xD0D5A9F13DED6CECULL,
		0x153BAAD67E633757ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6277CE6BCDD643DCULL,
		0xBFDC4FC8C19B8E32ULL,
		0x5C5B40ECEE1F11BAULL,
		0x2E3C7F9FD2E81C27ULL,
		0xDA195EE9CCC7AD1AULL,
		0x19D4C4FEFF7924E0ULL,
		0x38AF3779DE65290DULL,
		0x890227C5FD290D75ULL
	}};
	t = -1;
	printf("Test Case 44\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 44 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -44;
	} else {
		printf("Test Case 44 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE1D316E33AD31DEAULL,
		0x947D647DB5AFF598ULL,
		0xA716FC1E0667A366ULL,
		0x413C5869F709D5DFULL,
		0x487FD71DA22446A0ULL,
		0x714181C9194278B7ULL,
		0x43337EBBE97CCEBAULL,
		0x7066BAC176D9393CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE1D316E33AD31DEAULL,
		0x947D647DB5AFF598ULL,
		0xA716FC1E0667A366ULL,
		0x413C5869F709D5DFULL,
		0x487FD71DA22446A0ULL,
		0x714181C9194278B7ULL,
		0x43337EBBE97CCEBAULL,
		0x7066BAC176D9393CULL
	}};
	t = 0;
	printf("Test Case 45\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 45 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -45;
	} else {
		printf("Test Case 45 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCA4FA802D9984C8EULL,
		0x934D81468A0B26FBULL,
		0xAA083029D3C242C7ULL,
		0x8290ECF16CD7160CULL,
		0x6D782D33981E6EF2ULL,
		0x5029C83AC2D2121CULL,
		0xACCCC9F8968E0846ULL,
		0xB71040FB8D97A0F5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x90B592976F30674FULL,
		0x6B80306B92D8A838ULL,
		0x5FFF956C7DCD8590ULL,
		0x30372CE08E5F0F61ULL,
		0xB4079341D3F1EAD0ULL,
		0x23AA65DB1C26382FULL,
		0xF3BE3CF26B8543C1ULL,
		0x59C87620D2CF0ABBULL
	}};
	t = 1;
	printf("Test Case 46\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 46 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -46;
	} else {
		printf("Test Case 46 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5339C2052189A3AAULL,
		0x136F880319DB7174ULL,
		0xF1A78CBF7B82C2E6ULL,
		0xC88CBDAE246B74DDULL,
		0x3EAF36AF21F4252DULL,
		0x283932ABB32A0525ULL,
		0xDC64ED8CED32B0D5ULL,
		0xE5AA56A1D703D085ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5B01FCE3FB52BCA5ULL,
		0x299DCC3D0683608FULL,
		0xC2E9AD41F9FD7127ULL,
		0xE38464D2A2A534DFULL,
		0xFCF84D3AB3E712CDULL,
		0x7EF53EEC918917ACULL,
		0xFD22EBE76EA6B93CULL,
		0xBD40528A0292ECFEULL
	}};
	t = 1;
	printf("Test Case 47\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 47 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -47;
	} else {
		printf("Test Case 47 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAD10BF2EABC7E55EULL,
		0x393B801DCC11B6B6ULL,
		0x649074170C00458AULL,
		0x2469B1FA2F7D63ABULL,
		0x34F7C9650389ABDEULL,
		0xA6F479194A8C1481ULL,
		0x2D66B3BE3052F434ULL,
		0x6CD9876C0862FBB4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBD4FCADAA70B37A7ULL,
		0x197E6212C4D64B21ULL,
		0xA5AC77DECDB363C8ULL,
		0x6F881C19320205E6ULL,
		0x501F8436451EE6C9ULL,
		0xED8C91AE398D9839ULL,
		0xA480EC829176AA69ULL,
		0x609F6EC8A1AFE8C2ULL
	}};
	t = 1;
	printf("Test Case 48\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 48 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -48;
	} else {
		printf("Test Case 48 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA3D6D4A4D077BDC3ULL,
		0x09CDBA2A14CAA298ULL,
		0xBAEB988D986C6F91ULL,
		0x2E23B8C752B487B1ULL,
		0x601FBD7E92E2B90AULL,
		0x4AFDEA3E6F69E1B2ULL,
		0xDB68A7E9A3DDF9AAULL,
		0x613FA91F421B2E32ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA3D6D4A4D077BDC3ULL,
		0x09CDBA2A14CAA298ULL,
		0xBAEB988D986C6F91ULL,
		0x2E23B8C752B487B1ULL,
		0x601FBD7E92E2B90AULL,
		0x4AFDEA3E6F69E1B2ULL,
		0xDB68A7E9A3DDF9AAULL,
		0x613FA91F421B2E32ULL
	}};
	t = 0;
	printf("Test Case 49\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 49 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -49;
	} else {
		printf("Test Case 49 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9489AEE2CA74484AULL,
		0xFA5596D1A9B5CE29ULL,
		0xA55D8B2E45C88F89ULL,
		0x20FD7F243A07346FULL,
		0x7519622C3B57AECDULL,
		0x0C64C07678BB51D5ULL,
		0x88659CCB8A45E06EULL,
		0x12274C0C94AA5D14ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4DBF717F71C4E170ULL,
		0x0A5289CCC0519767ULL,
		0x25ECF09F88BBE386ULL,
		0x4912EA955B4ED705ULL,
		0x4654F8DBE6613640ULL,
		0xA7A3C305417E62C1ULL,
		0xAA57E57E5ABB9558ULL,
		0x4E68D66C1B5C4274ULL
	}};
	t = -1;
	printf("Test Case 50\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 50 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -50;
	} else {
		printf("Test Case 50 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC5BED49DC9121DCAULL,
		0xEE2C9872E92010C9ULL,
		0x4FC3970FA2118766ULL,
		0x63453810C858C105ULL,
		0x13A3655B6DBE972CULL,
		0xEC085F439AE0D04CULL,
		0xCB7ACBF2A6642311ULL,
		0xE863F2921C02AE67ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x157C97BE392416C0ULL,
		0x23D947F4BEDDA2D9ULL,
		0xEC900EC6778E82BAULL,
		0x05CBD54C21B4B8F9ULL,
		0xA88485AE347E0974ULL,
		0x870CB7A8BF5E0B83ULL,
		0xC3E01AFE7A6D3D2EULL,
		0x71CE09EC11A87D71ULL
	}};
	t = 1;
	printf("Test Case 51\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 51 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -51;
	} else {
		printf("Test Case 51 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0E33FBB385B58387ULL,
		0xF78D64B0347088C5ULL,
		0x525D01B01C3883CCULL,
		0x86CBD9CD4D8DE7FCULL,
		0xA6EB574DA351C9E5ULL,
		0xC1E7C4FEDCB4EB6BULL,
		0x19A48169CE2D8699ULL,
		0x348F49EFA2AB5C9BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFFC708DB7828A043ULL,
		0x99EE5C90525F8F72ULL,
		0x3E4A92D0A3F2C774ULL,
		0x4832086B79EC4559ULL,
		0x61E3E09BD808211BULL,
		0xA3EE697BADB4FD8DULL,
		0xD879109BC59075D4ULL,
		0xFC20BFBA4152E609ULL
	}};
	t = -1;
	printf("Test Case 52\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 52 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -52;
	} else {
		printf("Test Case 52 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4312C0358F3674C7ULL,
		0xBE84F03C119A6423ULL,
		0xDFB02714C66AEF9CULL,
		0x9EAE64F0C47CB6A2ULL,
		0xB67FB082467F4CB5ULL,
		0x39A41D0A5E3F41F9ULL,
		0xEA9C653A7621D14EULL,
		0x0B7E2CD8BF475182ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4312C0358F3674C7ULL,
		0xBE84F03C119A6423ULL,
		0xDFB02714C66AEF9CULL,
		0x9EAE64F0C47CB6A2ULL,
		0xB67FB082467F4CB5ULL,
		0x39A41D0A5E3F41F9ULL,
		0xEA9C653A7621D14EULL,
		0x0B7E2CD8BF475182ULL
	}};
	t = 0;
	printf("Test Case 53\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 53 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -53;
	} else {
		printf("Test Case 53 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x419139965512366CULL,
		0x908D1CD0E76B9C8AULL,
		0xC044F8482CD57F4EULL,
		0xF1C7B30D50CF3E9DULL,
		0xBF7CD1CA4D02F2DFULL,
		0x0696FA44CCFE7D31ULL,
		0x375AC930772A327FULL,
		0x3102B566E6114D3FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCF4602E528DF66E6ULL,
		0x3587E600EC5D7A6DULL,
		0xECF2AF0F4DE97CA7ULL,
		0xC134CAC82B3CEE0EULL,
		0x8FA2C259BAD4C8F8ULL,
		0xCF3D19F21D573179ULL,
		0x57EA7646C73E5BEAULL,
		0x53AB09CCE54AA313ULL
	}};
	t = -1;
	printf("Test Case 54\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 54 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -54;
	} else {
		printf("Test Case 54 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x537636F87D23B322ULL,
		0xCD04A6E5353F65FDULL,
		0x2C008380911FC5D8ULL,
		0xD344EB3F8F81D8CDULL,
		0xB4B51E3CFA1F264DULL,
		0x2CC1340A3A688FAFULL,
		0x59303383A21921D6ULL,
		0x00AE01566CD75509ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x165630B7A7ADF025ULL,
		0xF06E51B1D363DA44ULL,
		0xD368A09C0EF0D929ULL,
		0xACD2ECAC8CE85DC0ULL,
		0xB1C219208945D78CULL,
		0x633E7A266EDCE2D0ULL,
		0x1AF2AA6E2487F008ULL,
		0xDBEDE54E7E5FA5A0ULL
	}};
	t = -1;
	printf("Test Case 55\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 55 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -55;
	} else {
		printf("Test Case 55 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2ED4B511CA315EF9ULL,
		0xF1FFD96EABDAFCFCULL,
		0x67595FF48293BC8CULL,
		0xFE32AFCB1BBD4CCFULL,
		0x6F5DE9D232A94276ULL,
		0xFC318C1F36AC57B5ULL,
		0xFB4CD76A04DEB8A6ULL,
		0x464FF9261CD033E6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xED3145D8B44D6C1EULL,
		0x92E1EF8938C29099ULL,
		0x3E43B418134AE58AULL,
		0x68E9C0EDF6E620C1ULL,
		0xDF43CB8986561A4CULL,
		0x4B1EFF9638C848FEULL,
		0x5ABBFAEE28CF39C5ULL,
		0x65CBC45BF65AD392ULL
	}};
	t = -1;
	printf("Test Case 56\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 56 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -56;
	} else {
		printf("Test Case 56 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x26FF2C6E86A083E2ULL,
		0x4985A069C9115A90ULL,
		0xFDFD5124CCC2F428ULL,
		0x3DAA3D34EF316C9FULL,
		0xD7FB9F82C1516001ULL,
		0x8739819C39147094ULL,
		0x42A27173D3D8C1C8ULL,
		0x87200D3FC69F9345ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x26FF2C6E86A083E2ULL,
		0x4985A069C9115A90ULL,
		0xFDFD5124CCC2F428ULL,
		0x3DAA3D34EF316C9FULL,
		0xD7FB9F82C1516001ULL,
		0x8739819C39147094ULL,
		0x42A27173D3D8C1C8ULL,
		0x87200D3FC69F9345ULL
	}};
	t = 0;
	printf("Test Case 57\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 57 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -57;
	} else {
		printf("Test Case 57 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x77333EAC4BC67BE6ULL,
		0x270411495A51D9B4ULL,
		0x6325D7B35D8039C4ULL,
		0x00D3CB9821CA615EULL,
		0xA62E4FD59148D21EULL,
		0x71DAC8DD1F11D31EULL,
		0xF1494E1EEBFAA7BDULL,
		0x6552B49D03655862ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x00AFB488CB8F7136ULL,
		0x138D4FBE1796F65FULL,
		0x5D1FE0E35F58FCCFULL,
		0x9D8C05C38502869CULL,
		0x597A58B63E2F2226ULL,
		0x8B8A49D4B4866024ULL,
		0x46E60C312D959C05ULL,
		0xDDC1330B71ABB2B4ULL
	}};
	t = -1;
	printf("Test Case 58\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 58 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -58;
	} else {
		printf("Test Case 58 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x200CF8AF76B38575ULL,
		0x46141F9221A3BDAFULL,
		0xD8B6164D9EA8EDCAULL,
		0xA734C883335496D1ULL,
		0xA35B1E77CE58A8E7ULL,
		0x7D019C4B1433C859ULL,
		0x02ECADE0535F5138ULL,
		0xB1C05C74190E4177ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4E61F1378DED6086ULL,
		0xB18C5051C3E7903BULL,
		0xD541B0ABDB4C1D31ULL,
		0x607B7B614D1AC79EULL,
		0x4DF2F2B26632CB80ULL,
		0x2E15652094A0342CULL,
		0x1D4D5C73D611110DULL,
		0xE961D44C32244708ULL
	}};
	t = -1;
	printf("Test Case 59\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 59 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -59;
	} else {
		printf("Test Case 59 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD848ADBB65C7155BULL,
		0xBC0F1DB50A0BD187ULL,
		0xC6DD2B6D3F694DB3ULL,
		0x6596D85B191DF9D9ULL,
		0x7AA36AA1729B47E5ULL,
		0x28F78E6E0180D0C2ULL,
		0x3E02B2DD9A4E5A2BULL,
		0x562BA71FCD671F1DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1C97DF02A4F4DE28ULL,
		0x7F28BC9B8C6F5147ULL,
		0xE53AB720714425BCULL,
		0x87166E5B3D475DFEULL,
		0xE35227F51D3D4B62ULL,
		0xB75956BA3D402A98ULL,
		0x0CB4CAA0416FBC87ULL,
		0xF24BD019B4557FD7ULL
	}};
	t = -1;
	printf("Test Case 60\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 60 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -60;
	} else {
		printf("Test Case 60 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA1ECB625AA8DF75FULL,
		0x1CF14F75777CD22AULL,
		0x49766CDF4FA60717ULL,
		0xA0A0C996B62B5690ULL,
		0x163D76B4BC202CF5ULL,
		0x929092FEAE6EC730ULL,
		0xFE1C65B91259B01DULL,
		0xD8CEF56ED260893DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA1ECB625AA8DF75FULL,
		0x1CF14F75777CD22AULL,
		0x49766CDF4FA60717ULL,
		0xA0A0C996B62B5690ULL,
		0x163D76B4BC202CF5ULL,
		0x929092FEAE6EC730ULL,
		0xFE1C65B91259B01DULL,
		0xD8CEF56ED260893DULL
	}};
	t = 0;
	printf("Test Case 61\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 61 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -61;
	} else {
		printf("Test Case 61 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x56688360F8B69CEDULL,
		0x7C7DDC1B0DECA424ULL,
		0x8BD6B949AAAEE24CULL,
		0xCBAF3C1EE8028D02ULL,
		0x3EF0D752036F38ADULL,
		0x8936F440972CEAC4ULL,
		0x656571618A5A9450ULL,
		0xED91B00EFD906400ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x22A081E31237922EULL,
		0x24B0BCADD71924AEULL,
		0x4B123DA0E8C6CEA2ULL,
		0xE9E50FF035DACAAEULL,
		0xC3292A70488F10FAULL,
		0xFEF95680AA6A18B0ULL,
		0x5F88050B463BD56CULL,
		0x7D9EDA2EFB492154ULL
	}};
	t = 1;
	printf("Test Case 62\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 62 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -62;
	} else {
		printf("Test Case 62 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6E0C5F4ABFFF4F29ULL,
		0x070474F7C5E70379ULL,
		0x65099F21559905EBULL,
		0xB0AD83358B54DD22ULL,
		0x8E3B902BE63BCC05ULL,
		0x51D0ACE00B2A8479ULL,
		0xFDF0690245E7E4B4ULL,
		0xE6191ACFD8681A6EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB9585771C894258AULL,
		0x04138D014D441E52ULL,
		0x4AB46B2D2527A171ULL,
		0x5DDDECF06B52A654ULL,
		0xDD59025883AB86B9ULL,
		0xDB422C4B826675ADULL,
		0x8712E2AF67A58F1BULL,
		0x6803CCAB7D1541D8ULL
	}};
	t = 1;
	printf("Test Case 63\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 63 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -63;
	} else {
		printf("Test Case 63 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEBAFCB8C704D26A8ULL,
		0x1D0CE2B17060DCEEULL,
		0x28C7346C76F1449BULL,
		0x40A3281626FC6D9EULL,
		0x1A087C988358A5D9ULL,
		0x73F9BE6C2D31AA61ULL,
		0xA13AD24C4C0EEA97ULL,
		0xB4D83D76E5C048EBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8A3EB9BD02D9129BULL,
		0x09698C4A465D44EEULL,
		0x0E6436CD62A5698DULL,
		0x68424DC73963C01FULL,
		0x745B101D7660AFE7ULL,
		0x89D34D0EB6EDE3E3ULL,
		0xD259B1FFCAD5D9F8ULL,
		0x8DEBDF222DEA1C29ULL
	}};
	t = 1;
	printf("Test Case 64\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 64 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -64;
	} else {
		printf("Test Case 64 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x336B3F54D2E08FFCULL,
		0xE8AB6F243F66E0D3ULL,
		0xAAFCE69039566A2AULL,
		0xA77F2EB589E23A4FULL,
		0xEBD3A47C3CBADAFCULL,
		0xBF549883DE39227FULL,
		0xBB461355E7DBC3F2ULL,
		0xAFE057506C4D2B7AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x336B3F54D2E08FFCULL,
		0xE8AB6F243F66E0D3ULL,
		0xAAFCE69039566A2AULL,
		0xA77F2EB589E23A4FULL,
		0xEBD3A47C3CBADAFCULL,
		0xBF549883DE39227FULL,
		0xBB461355E7DBC3F2ULL,
		0xAFE057506C4D2B7AULL
	}};
	t = 0;
	printf("Test Case 65\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 65 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -65;
	} else {
		printf("Test Case 65 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x400B0C522E773481ULL,
		0x021F4DEF8EFCE708ULL,
		0x9EE4ECCCF4A8DD46ULL,
		0x336320AE0CAE840AULL,
		0x6B13039A3A8034A9ULL,
		0xF11F96EF4D67A8CFULL,
		0xE4DE6B66E486FF87ULL,
		0x7181FC6BAB265822ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC7A4589522205E76ULL,
		0x1D48FE658B7E75FEULL,
		0x602957EB99F8FC73ULL,
		0x39B86724185EA9EAULL,
		0x5AFB5A189C0AAA32ULL,
		0x1CBA01E755DB3652ULL,
		0x711F5BE8F7DFB433ULL,
		0xF70C643284A5FDE0ULL
	}};
	t = -1;
	printf("Test Case 66\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 66 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -66;
	} else {
		printf("Test Case 66 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x703B5B91EBAFBC1AULL,
		0xF427C28F65DB00CFULL,
		0x2F819E17957A2CCAULL,
		0x7815CE76DF83078FULL,
		0x5E37D53D8A27D518ULL,
		0x9E4528D8E9F01FAAULL,
		0x68A87D6C85EB36E4ULL,
		0xF87EECB03CA6145EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE1AC6F3FA5EAC692ULL,
		0xD90B17DB034041ACULL,
		0xD9C6ED17D799B798ULL,
		0xA4305D369491B74CULL,
		0x19495F6C4B62BFD3ULL,
		0x8CA61B14C5457F9DULL,
		0xBF65CA8EB12A76D8ULL,
		0x59710CF25F5BB617ULL
	}};
	t = 1;
	printf("Test Case 67\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 67 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -67;
	} else {
		printf("Test Case 67 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9EA14D60961C8BC7ULL,
		0xE8ABF26C7875F1F0ULL,
		0x456046AB8374D528ULL,
		0xD41E26D2F4E40164ULL,
		0x81EE23089332F284ULL,
		0xC7DED8475503D35CULL,
		0x669783B5A326515DULL,
		0xD1C01E663091F99FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF54173AB9408144EULL,
		0x8D316ABFD35C746AULL,
		0xEEE1C2CEFDFC317CULL,
		0x4E68F9D79B6BFA4BULL,
		0xBF18A1F06C63C01AULL,
		0xAC201CFFE9F15008ULL,
		0x27A3049D181DD77AULL,
		0xEB2AEA670205CB44ULL
	}};
	t = -1;
	printf("Test Case 68\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 68 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -68;
	} else {
		printf("Test Case 68 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFC7B87585433C8D4ULL,
		0xF89DFB3984986F6EULL,
		0x1FE1B26766327DBBULL,
		0x555EE081DE825D6CULL,
		0xD9E6DFD53953134CULL,
		0xEF6F10F405BE2C91ULL,
		0x0277D661FDDA1B6CULL,
		0x6A6415F289CE3B06ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFC7B87585433C8D4ULL,
		0xF89DFB3984986F6EULL,
		0x1FE1B26766327DBBULL,
		0x555EE081DE825D6CULL,
		0xD9E6DFD53953134CULL,
		0xEF6F10F405BE2C91ULL,
		0x0277D661FDDA1B6CULL,
		0x6A6415F289CE3B06ULL
	}};
	t = 0;
	printf("Test Case 69\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 69 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -69;
	} else {
		printf("Test Case 69 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2B15BA3AE4C39ED1ULL,
		0xA4BD14640619D563ULL,
		0x558D3208706E8869ULL,
		0xF6000BA8188CCE74ULL,
		0xF50EDE7B2758AA92ULL,
		0xCB24AE709B70B0BDULL,
		0xE96B433164C215A0ULL,
		0x9995A5EF88A185C7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4B45FEEC46749CD3ULL,
		0xAACE926D230B2637ULL,
		0x4304008B69E369A9ULL,
		0x190AD89B0A0EDBEFULL,
		0xB02FD6F12B918F7DULL,
		0xAB347C9347463D7FULL,
		0xAB9C52A0565F150FULL,
		0xD6827A1FC52E3A5CULL
	}};
	t = -1;
	printf("Test Case 70\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 70 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -70;
	} else {
		printf("Test Case 70 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9B10E76E3833491EULL,
		0xA03C29585ABD2705ULL,
		0x4338783BD708739DULL,
		0x74167ED7248BDE06ULL,
		0x924192D2BB59D3C5ULL,
		0x6FD49729B7CAB370ULL,
		0x1BA3FF8866BB7737ULL,
		0xA213EDAC576C2D0FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEE6389E67CC434ECULL,
		0x2C0ABE877150D47DULL,
		0x2ECEA14554416D71ULL,
		0x9B29CB36747C87B9ULL,
		0xB7D5495808EE95D4ULL,
		0x7E1233F269F76360ULL,
		0x81ABAD23D9A938E1ULL,
		0x36FB8997E7A210BDULL
	}};
	t = 1;
	printf("Test Case 71\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 71 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -71;
	} else {
		printf("Test Case 71 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAE4EA872AFE5A8CCULL,
		0xEE400A4D16E6DC54ULL,
		0x407574834CC68A02ULL,
		0xFDEB98B25F6D53C9ULL,
		0x4813746F9CD1DDEBULL,
		0xC60E52A031CF7D43ULL,
		0x79711112201200D0ULL,
		0xD252B12298ABDF8DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x79B3A14CB561EA0BULL,
		0xA7B4A667C9186CA2ULL,
		0x137C1645F17B65F8ULL,
		0x7177872445EA96F9ULL,
		0x1B9BAA1335DF4AE2ULL,
		0x96C3992746C5C58AULL,
		0xE908C0F7356D7E9BULL,
		0x529085A5F0753FF7ULL
	}};
	t = 1;
	printf("Test Case 72\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 72 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -72;
	} else {
		printf("Test Case 72 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x96A804A0F5608770ULL,
		0xF60EED80D33E8134ULL,
		0x547D2BA05237F8D4ULL,
		0x90ACCB29D80C558AULL,
		0xBDF2A6064F27D32BULL,
		0x66A71B4AE0FEA18CULL,
		0x6DA78ED0599F0132ULL,
		0xF706162DD34FF240ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x96A804A0F5608770ULL,
		0xF60EED80D33E8134ULL,
		0x547D2BA05237F8D4ULL,
		0x90ACCB29D80C558AULL,
		0xBDF2A6064F27D32BULL,
		0x66A71B4AE0FEA18CULL,
		0x6DA78ED0599F0132ULL,
		0xF706162DD34FF240ULL
	}};
	t = 0;
	printf("Test Case 73\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 73 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -73;
	} else {
		printf("Test Case 73 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2248FD2F17A6C295ULL,
		0xBD644B061B65D2D8ULL,
		0x7755664C50B6356BULL,
		0x0C3148FEE4396FC3ULL,
		0xB3365BFD44CCB85CULL,
		0x7533F68F50947C08ULL,
		0xBC70A2E38E67BDF7ULL,
		0x070F0DA12EC416A2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xECDFB8999A8279B4ULL,
		0x85B87B89557A316AULL,
		0x7CA3CA82A2B61BB9ULL,
		0xB76C1340F775DF7AULL,
		0xFF9080561417F6E2ULL,
		0x4DFFBB950816A522ULL,
		0x36B9E97C04B81B37ULL,
		0xCBBFF51A5CF387B6ULL
	}};
	t = -1;
	printf("Test Case 74\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 74 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -74;
	} else {
		printf("Test Case 74 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x96FA8378F3195EC9ULL,
		0x8073E656A23BB93CULL,
		0x50F02D65D5EBD158ULL,
		0x4D549C47C94EFDD9ULL,
		0x5B76FABA9792E9F6ULL,
		0x38D34CA8A13912AFULL,
		0x0C4CE09DF5D689A6ULL,
		0x1331F62265A2810BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5A1B5DF1477928D5ULL,
		0xAB7C08CE80939CFAULL,
		0xB40715E53C2A3F29ULL,
		0x6C8F874E864EC4CAULL,
		0x6DFD3A28D46E142FULL,
		0x8482E2AAE293BAE9ULL,
		0x67E55D6479A8A8C0ULL,
		0xA03A38B55590DB89ULL
	}};
	t = -1;
	printf("Test Case 75\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 75 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -75;
	} else {
		printf("Test Case 75 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5EEE9B6A1814913AULL,
		0x0740352AFDE3B344ULL,
		0xB17C809B3EF1E1C1ULL,
		0x356524D4D656FEF2ULL,
		0x7147B01D150BB1B6ULL,
		0x526810E86FBF26F0ULL,
		0x465D95601DF46622ULL,
		0xD2DD8FD69274D298ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDA990F6AEBFBC14FULL,
		0x2493792D13754AADULL,
		0x694D7D109ACE2689ULL,
		0xA491E79B843FB6A1ULL,
		0xD634A2C2C7731E70ULL,
		0xA8CD2BFF00BEC8B5ULL,
		0x449F42D80E5C428DULL,
		0x7FE27A473D388C88ULL
	}};
	t = 1;
	printf("Test Case 76\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 76 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -76;
	} else {
		printf("Test Case 76 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC2BB38D1F0728CC7ULL,
		0x378FBEFF1D2DA885ULL,
		0x5F7544BEB936AC04ULL,
		0x9EE9EB0466BBF8EFULL,
		0xB255FE5D40CE26D6ULL,
		0x5D0179F1C8A05B2DULL,
		0xD58AB951F705BA54ULL,
		0x9A2DD2B9B9177EBFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC2BB38D1F0728CC7ULL,
		0x378FBEFF1D2DA885ULL,
		0x5F7544BEB936AC04ULL,
		0x9EE9EB0466BBF8EFULL,
		0xB255FE5D40CE26D6ULL,
		0x5D0179F1C8A05B2DULL,
		0xD58AB951F705BA54ULL,
		0x9A2DD2B9B9177EBFULL
	}};
	t = 0;
	printf("Test Case 77\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 77 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -77;
	} else {
		printf("Test Case 77 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1AB6CDAEF40397D6ULL,
		0x412693DEE24BA7C3ULL,
		0x5536D740A089AE13ULL,
		0x0B234E480D55EE1BULL,
		0xCE4BA374CDB091A4ULL,
		0x00B36E8F709BD2A6ULL,
		0x1FC07B9DAC1726CAULL,
		0xBFFB4C02DC600539ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF17C8FA87F3362B3ULL,
		0x103587A9034EE730ULL,
		0x7ED19B9F45B0AB22ULL,
		0x74C481E14FE98758ULL,
		0xC5C2383C0B54EE7AULL,
		0xE72F805A7A4E8763ULL,
		0xD2E5233E794A8DDBULL,
		0x9FFD00831674C5A0ULL
	}};
	t = 1;
	printf("Test Case 78\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 78 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -78;
	} else {
		printf("Test Case 78 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC381F9544755B142ULL,
		0xDCA60C244CF470C4ULL,
		0x81707294D73DFD5AULL,
		0xE866CB2CB9B0D3CEULL,
		0xB334215D17456028ULL,
		0xAAF94265DE45FB02ULL,
		0x3678CC6724AF8AD0ULL,
		0x0533870DF981AF49ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x939880CA375F070DULL,
		0x27D557D26B37FEE9ULL,
		0xEAD1FE1F2F3CD84BULL,
		0xF1F4B8BAA5828BF5ULL,
		0xBBF53CE64F3A4E59ULL,
		0x5BC196707AF0732CULL,
		0xB4F57E2424258E12ULL,
		0x0A326F8623536849ULL
	}};
	t = -1;
	printf("Test Case 79\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 79 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -79;
	} else {
		printf("Test Case 79 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0A48781FF3A0038EULL,
		0x09D20E7E77A77C49ULL,
		0x5BE7E048C8775DA1ULL,
		0x15ED774828D519E5ULL,
		0x308BA38A4EFCBE46ULL,
		0x534C970649FAF0B1ULL,
		0xFD3C2EE023B2C9B9ULL,
		0xBA7726236B2C01A4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4BF3211315761DF1ULL,
		0xBAD96E33C62A1241ULL,
		0xD9440D0C189CF588ULL,
		0x5402C00CBD622822ULL,
		0x55EE9BB9A72B307AULL,
		0x371AE412812E25CFULL,
		0xC94DFF9958B18B53ULL,
		0xA5D6ADDE37A73808ULL
	}};
	t = 1;
	printf("Test Case 80\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 80 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -80;
	} else {
		printf("Test Case 80 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x584F2D6FDA10CC86ULL,
		0xBD91D88A6497608CULL,
		0x0B933DD1F0344A34ULL,
		0x77CEAF5C44570481ULL,
		0x0B88E60285077455ULL,
		0x55EB8C7EDBC99766ULL,
		0x755A1B8A803C27A1ULL,
		0xDC6BEE92EBC2DA66ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x584F2D6FDA10CC86ULL,
		0xBD91D88A6497608CULL,
		0x0B933DD1F0344A34ULL,
		0x77CEAF5C44570481ULL,
		0x0B88E60285077455ULL,
		0x55EB8C7EDBC99766ULL,
		0x755A1B8A803C27A1ULL,
		0xDC6BEE92EBC2DA66ULL
	}};
	t = 0;
	printf("Test Case 81\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 81 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -81;
	} else {
		printf("Test Case 81 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9C776723CB93E253ULL,
		0x2031C1C327E7D48CULL,
		0x855AA7086A6F27A6ULL,
		0x69086B4CE03EF188ULL,
		0x392C051DE11AA0C2ULL,
		0xC2D0F31E5C776110ULL,
		0x87712037EB92C7B7ULL,
		0x3FCC3ECB8623A4B9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6646CDBB7572CCF6ULL,
		0xB89C9E2AEBE6BF0CULL,
		0x776E833E1A786351ULL,
		0xE2E7B29F24D26C63ULL,
		0x551FBF870D93AB12ULL,
		0xFA93617F77E72D97ULL,
		0xD9A8BF1DA2C7EA10ULL,
		0x2983FEDDAE09DCA5ULL
	}};
	t = 1;
	printf("Test Case 82\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 82 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -82;
	} else {
		printf("Test Case 82 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7DF762986A95DE22ULL,
		0x79BE84052380FF19ULL,
		0xBD4708649596F574ULL,
		0x0547DD8CD1F5BC84ULL,
		0x0A6F7B2F5C06B58BULL,
		0x8312B6805C2A370AULL,
		0xEE9579FDF7B15D9CULL,
		0x2CB4FBEF27B1EE0BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7601B67E7EFCCF72ULL,
		0x0F5FE87CC5805131ULL,
		0x0D035760E1F27E97ULL,
		0x68133979B09218FBULL,
		0xC309CBF340809BA7ULL,
		0x8FF3159A15313E3AULL,
		0xF5B55CB3A1C417F6ULL,
		0x1821E744503ED8AAULL
	}};
	t = 1;
	printf("Test Case 83\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 83 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -83;
	} else {
		printf("Test Case 83 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x321259BEDBF1B153ULL,
		0x06703513EA709C2BULL,
		0x6B43CF1522C90A4EULL,
		0x067F833B6DC2E536ULL,
		0xEFEDF933013AED87ULL,
		0x5601AB7AB8F4CC18ULL,
		0x19D18B9C2EB3876EULL,
		0x9E458D2C1D1DAC79ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x71D64A7040183DD6ULL,
		0x11C41E052B962247ULL,
		0x54E90B14608106E8ULL,
		0x0C6E51CB50E01695ULL,
		0x970EF95B9BD5C2D0ULL,
		0x90E16DCF3A9CCFC2ULL,
		0x50C0205F810DB10DULL,
		0xAD5EA060FDF43017ULL
	}};
	t = -1;
	printf("Test Case 84\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 84 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -84;
	} else {
		printf("Test Case 84 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB2DCA4448AD411B9ULL,
		0xD05E205EBDF1677DULL,
		0x9A363FF728B67469ULL,
		0xD6E2B2B25C4B1F0DULL,
		0xFB1AC76619008E0DULL,
		0x04497227D1D155F0ULL,
		0x2F2DB38E78210A2CULL,
		0x19A856557810A219ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB2DCA4448AD411B9ULL,
		0xD05E205EBDF1677DULL,
		0x9A363FF728B67469ULL,
		0xD6E2B2B25C4B1F0DULL,
		0xFB1AC76619008E0DULL,
		0x04497227D1D155F0ULL,
		0x2F2DB38E78210A2CULL,
		0x19A856557810A219ULL
	}};
	t = 0;
	printf("Test Case 85\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 85 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -85;
	} else {
		printf("Test Case 85 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF043BFFD3EB7A4DDULL,
		0x351D34DFC2A1D3C6ULL,
		0xE35C5190E030DB41ULL,
		0x440106444CB7994CULL,
		0x5143E4290371088EULL,
		0x3CA60A7BB993CC75ULL,
		0xAD9ACC982F4AEC55ULL,
		0xCAF46E7EC3DEFDDDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2BC25B45AB980D10ULL,
		0xA6CA97EB95EB3D78ULL,
		0x3FB89F747E152C92ULL,
		0x87BB4DE2FA2C611CULL,
		0xF307F93F7AD1C20EULL,
		0xEA3289543953A83EULL,
		0x4E7C0E74BDF85F46ULL,
		0xFCCD6295CBB007B2ULL
	}};
	t = -1;
	printf("Test Case 86\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 86 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -86;
	} else {
		printf("Test Case 86 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF171F436BF36027EULL,
		0x9301C719DF1B8E40ULL,
		0x70CFACA74A585C28ULL,
		0xEFA3B758C4960BB2ULL,
		0xEDC36B8FB71C3A69ULL,
		0x918780515C215465ULL,
		0xFE4088B6CC541BD6ULL,
		0xD401663C0118F20DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x600DADDA364E9958ULL,
		0x594EFC0C6F4E3387ULL,
		0x13D0D9186DA88AF5ULL,
		0x8AB5AA26AB7336F3ULL,
		0x405EF16366675FBDULL,
		0x5A1F56FDF7F42560ULL,
		0x363ABE17DC9CA5A4ULL,
		0xF3BCE836C0BDC970ULL
	}};
	t = -1;
	printf("Test Case 87\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 87 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -87;
	} else {
		printf("Test Case 87 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF2A3F11E2F9B7D91ULL,
		0x3005319F70AFB5F0ULL,
		0x95C0A5B942E14DAAULL,
		0x73458EE54B9FA602ULL,
		0x0B0106B3E2455F06ULL,
		0x702C273197F61E3EULL,
		0x979B40521092D786ULL,
		0x8FFEA656083BC5BBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6590D03C45599191ULL,
		0x7BE0FCAA63B4DA4CULL,
		0x69E3E10D371B625BULL,
		0xE8651C644AA67235ULL,
		0x113020AB960C3E2DULL,
		0xE35FCB112F135AEEULL,
		0x4863C2D748C0BD3AULL,
		0xC2A3ADEA61DF7705ULL
	}};
	t = -1;
	printf("Test Case 88\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 88 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -88;
	} else {
		printf("Test Case 88 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0F3675CEC0BEF47BULL,
		0xAA3E78D5CCC8EC6FULL,
		0x3FC7DBEF164FEF85ULL,
		0xC162807CCA9C91BEULL,
		0x31521A73B75D8EAEULL,
		0xC6DB6EC16AEC07C8ULL,
		0x04FEBB663DFFB483ULL,
		0x3C96DAA3789E35F0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F3675CEC0BEF47BULL,
		0xAA3E78D5CCC8EC6FULL,
		0x3FC7DBEF164FEF85ULL,
		0xC162807CCA9C91BEULL,
		0x31521A73B75D8EAEULL,
		0xC6DB6EC16AEC07C8ULL,
		0x04FEBB663DFFB483ULL,
		0x3C96DAA3789E35F0ULL
	}};
	t = 0;
	printf("Test Case 89\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 89 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -89;
	} else {
		printf("Test Case 89 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x56B4BDF98FB2A48CULL,
		0x1447F97701AC4870ULL,
		0x23AB1FECD23D51CFULL,
		0xB7527B4985321543ULL,
		0x073263AB609EFEEFULL,
		0x379D0B21CC80D152ULL,
		0x1E6A47D10BE276AFULL,
		0x9D74A024363B249CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0E08C179FEC2A0F4ULL,
		0x32AA1FC12F605B38ULL,
		0x2174CA9EAE357C00ULL,
		0x6DAF1280682F6180ULL,
		0x903AAA59E8DC70FFULL,
		0x41FCFDBD2A798FC4ULL,
		0x8627E6DC05F58BB5ULL,
		0x788161096D4287A2ULL
	}};
	t = 1;
	printf("Test Case 90\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 90 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -90;
	} else {
		printf("Test Case 90 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD02361B0EFF64BD5ULL,
		0x4E44C507F2A5C667ULL,
		0xEC822C0D1D3DEFC7ULL,
		0x72E0D93AEDEB840BULL,
		0xCE21C149140FBE99ULL,
		0x011BBF43C22E6CDDULL,
		0x28BA89E1858A554EULL,
		0x487C320798CC729DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEFF5A5759DE16669ULL,
		0x2A12D24476DF2FEDULL,
		0xBBE3759A4F89D228ULL,
		0xFABEC8C848A1ABB8ULL,
		0x1B0C25BFDDB777FFULL,
		0xD463E057AC36F5C5ULL,
		0xA78588DED3F53E42ULL,
		0x35D10B53991540E9ULL
	}};
	t = 1;
	printf("Test Case 91\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 91 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -91;
	} else {
		printf("Test Case 91 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD65B2C8EFF24497FULL,
		0x940F416D8BDE8E85ULL,
		0xE10BF13F809C6A15ULL,
		0x21F16A2215FFC4E3ULL,
		0x35C84644EF274E79ULL,
		0x734C2D332C219D92ULL,
		0x09316CDB196198FDULL,
		0x85D9078C0601A2C3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF3097C42031E0C92ULL,
		0xD258D52141822A2EULL,
		0x7C5835F875F2C23FULL,
		0x4817CA387064B72CULL,
		0x7F9B425E0D786669ULL,
		0xEE61B1903AD6D283ULL,
		0xDDF13AE9D6217333ULL,
		0x5AB3579CACFF0E5AULL
	}};
	t = 1;
	printf("Test Case 92\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 92 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -92;
	} else {
		printf("Test Case 92 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC944353BFB3C3BE6ULL,
		0xE6025F55D2036FACULL,
		0xAACE8897ED5E936EULL,
		0x1397CFCCCDB4544DULL,
		0x49655098DDB7D06FULL,
		0x2409030FE66725FDULL,
		0xE0F021568570FF9DULL,
		0x3BB1C117DFE8CFDAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC944353BFB3C3BE6ULL,
		0xE6025F55D2036FACULL,
		0xAACE8897ED5E936EULL,
		0x1397CFCCCDB4544DULL,
		0x49655098DDB7D06FULL,
		0x2409030FE66725FDULL,
		0xE0F021568570FF9DULL,
		0x3BB1C117DFE8CFDAULL
	}};
	t = 0;
	printf("Test Case 93\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 93 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -93;
	} else {
		printf("Test Case 93 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC117CF4818CAB38EULL,
		0x07E070C1CBFD8EA3ULL,
		0x4167840554778A6BULL,
		0x6182F6EDC3D9C8A2ULL,
		0xD1F3E1F174519ED9ULL,
		0xF7560337B2119988ULL,
		0xF58096C80844414EULL,
		0x540E784EDBCD2C79ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9E4EA4C8B3ECF93EULL,
		0xAED490A627577C05ULL,
		0x86BCDBF786FC29C3ULL,
		0x0F08259DCD82DA36ULL,
		0x565A59C0861766D3ULL,
		0xA7DFF433C5793D9BULL,
		0x48D77E59B839DF3DULL,
		0xF9ED85F4E8596FD2ULL
	}};
	t = -1;
	printf("Test Case 94\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 94 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -94;
	} else {
		printf("Test Case 94 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x102B16BAE4F052DEULL,
		0x01C1939F7B16FF54ULL,
		0xD3249BFEF81356C0ULL,
		0xE9CCEFB2CDF9F996ULL,
		0x0DF092B61263613AULL,
		0xFB56FFDE6E535DACULL,
		0x0DBA93D210597222ULL,
		0xC47A11AAB1DD13D0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA26D243034623A84ULL,
		0x209997D6CB22919CULL,
		0x5CE31CA3C1A24B1BULL,
		0x539C49498C7114C8ULL,
		0x16A69E7A80EB1C69ULL,
		0x3ABB506F2182E5EDULL,
		0xA908212A03CC2EE6ULL,
		0x40A30EBA829CA3D8ULL
	}};
	t = 1;
	printf("Test Case 95\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 95 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -95;
	} else {
		printf("Test Case 95 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6473CD565514286CULL,
		0xFFB82D45B1FDFC30ULL,
		0xDE013E195EEDD621ULL,
		0x33C02D17B2580965ULL,
		0x7CC29959B7F11BC1ULL,
		0x3158F3D3F8173852ULL,
		0x47A9ACD01FAC512CULL,
		0xE8B1B583803FD119ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5412FB2C454CFF6BULL,
		0xDCD061C49E3567B5ULL,
		0x9FBCCC090B040AE0ULL,
		0x5C18AAB350D186E2ULL,
		0x34EF026B0B554050ULL,
		0x30AEDCD1908E2547ULL,
		0xF50631D79AE071B3ULL,
		0x7A9D3CBF17AE6F1CULL
	}};
	t = 1;
	printf("Test Case 96\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 96 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -96;
	} else {
		printf("Test Case 96 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x023F473C67DB5CFCULL,
		0xD22D91DE8E22A0FAULL,
		0x4CB9E4E98EAD745FULL,
		0x2762EA78B699B88DULL,
		0x17E8B9318C881012ULL,
		0xBDAB67CC9C9B4415ULL,
		0x1851B21EE5466539ULL,
		0x4CA35A9FA9AC0B57ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x023F473C67DB5CFCULL,
		0xD22D91DE8E22A0FAULL,
		0x4CB9E4E98EAD745FULL,
		0x2762EA78B699B88DULL,
		0x17E8B9318C881012ULL,
		0xBDAB67CC9C9B4415ULL,
		0x1851B21EE5466539ULL,
		0x4CA35A9FA9AC0B57ULL
	}};
	t = 0;
	printf("Test Case 97\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 97 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -97;
	} else {
		printf("Test Case 97 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x23A26A62E5432F77ULL,
		0xF1D2D5B2391D0CF5ULL,
		0xD7092DDDF83B8163ULL,
		0x87CCB6EC02A7791EULL,
		0x06C55B71F6E07F33ULL,
		0x73B57BBA8166A81AULL,
		0xC9392346BEADC220ULL,
		0x53FA6010467FB56DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7015F05E28750008ULL,
		0x08FF776D09BC5EB1ULL,
		0x834504DAF065BBF5ULL,
		0x8A88D89D3584C07BULL,
		0x35D5566C904F1DB9ULL,
		0x352CD0E43FBC5925ULL,
		0x0F59A88305BBCBE7ULL,
		0x7F3B71D524D5FA53ULL
	}};
	t = -1;
	printf("Test Case 98\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 98 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -98;
	} else {
		printf("Test Case 98 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB73FB0712768F3F3ULL,
		0x3324A7F41CEF5286ULL,
		0x879AD99E0EFC257BULL,
		0x3A61FAE81B23E44CULL,
		0xED3E7D5268AD7E9BULL,
		0xE1D63FC1CC01B11EULL,
		0x5CAAE1F74BBE9415ULL,
		0x3F65020634109FA8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA8E584E3142E579AULL,
		0x20150BC7D5FA1501ULL,
		0x3CDCC891BBF94C2FULL,
		0x318AD99D91EA5014ULL,
		0xFDDF21AC1C8F9219ULL,
		0x1893A3B0B22B3554ULL,
		0x6013B045B7643176ULL,
		0x23B6BE498C32D592ULL
	}};
	t = 1;
	printf("Test Case 99\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 99 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -99;
	} else {
		printf("Test Case 99 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFC025B40A3763036ULL,
		0x292ED21CAB791FA5ULL,
		0x543252CFC669361DULL,
		0xF539CCE45DB255F6ULL,
		0x701F715C5A2D26C9ULL,
		0x0764C3DCCCF6DC22ULL,
		0x82C16CF5B97DE70BULL,
		0xCE6BB23DD000882DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE0D9F4B2E73D6A03ULL,
		0x82EC5748DE48D987ULL,
		0xC451D9153E7FC597ULL,
		0x26BE08593969AA73ULL,
		0x7B7C1B590EAAA1A2ULL,
		0xC612AE75F3442C69ULL,
		0x082B5DF1105E6180ULL,
		0xCD95456C4B4FBC3DULL
	}};
	t = 1;
	printf("Test Case 100\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 100 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -100;
	} else {
		printf("Test Case 100 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x580E4A3A05F1D202ULL,
		0x01DBF32452D21997ULL,
		0x8B0CA759BB912E59ULL,
		0xA7E24CC66701DBD4ULL,
		0x6D38685EC8F24D06ULL,
		0x06384CB199200942ULL,
		0x9C4B50460415402FULL,
		0x7348EDB4BAA272B9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x580E4A3A05F1D202ULL,
		0x01DBF32452D21997ULL,
		0x8B0CA759BB912E59ULL,
		0xA7E24CC66701DBD4ULL,
		0x6D38685EC8F24D06ULL,
		0x06384CB199200942ULL,
		0x9C4B50460415402FULL,
		0x7348EDB4BAA272B9ULL
	}};
	t = 0;
	printf("Test Case 101\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 101 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -101;
	} else {
		printf("Test Case 101 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4AB08D9B059BDAD6ULL,
		0xA02AF586930D3343ULL,
		0xCBB2941661175CC7ULL,
		0x01AA745CE25967EAULL,
		0xDC54A9032B31409BULL,
		0xAA07737AC2E4CB1CULL,
		0x3DA10E4A8A5B8A27ULL,
		0xE442ACA7200A3E17ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x870139DBC7FA46F0ULL,
		0x119AAAFB8DD8833EULL,
		0xAAD651DD055BF327ULL,
		0x89EEFD84BFA54B37ULL,
		0x68EC3DEF5FE418F1ULL,
		0x2F2F9BA018B401A1ULL,
		0x900B63BCBBF80001ULL,
		0xDE3CB5F5D13EF726ULL
	}};
	t = 1;
	printf("Test Case 102\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 102 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -102;
	} else {
		printf("Test Case 102 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x08CF506DA6578A82ULL,
		0x848AF2F73AD6AD32ULL,
		0x7859C1F6326A7AC0ULL,
		0x31791C8E14B32E30ULL,
		0xA11818C702AB98EBULL,
		0x8D784B609E675184ULL,
		0xAA0C968F5AE280F7ULL,
		0x2F8A027BCC716D3FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x87DD5B33A974F17AULL,
		0x5B1D4481DE7776FCULL,
		0x2B2F2450A1BDA8ACULL,
		0xD794CE291A7EB83DULL,
		0xC78AFB66724A2610ULL,
		0xC5DE8513654E471BULL,
		0x8FF86FCC28826ECDULL,
		0x0BD2371772831444ULL
	}};
	t = 1;
	printf("Test Case 103\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 103 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -103;
	} else {
		printf("Test Case 103 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1C9F51014E6C154FULL,
		0x450EAD81E870083EULL,
		0xDC3AA3597D6C147CULL,
		0x5285B6D63C953100ULL,
		0xA913040F76CF4A4DULL,
		0x0C6E545E7E635498ULL,
		0x6FCB7C0B65505B6EULL,
		0x61E8E2B776D680E5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8D3031C90FBD1B5FULL,
		0x9FF40F79AA3204E4ULL,
		0xCB83AFA776383F1CULL,
		0x0D7228A871E07BE5ULL,
		0x33F82AA49963E4ADULL,
		0x24E6CB365DEC3E77ULL,
		0x9320A9ED1B913055ULL,
		0x20BAD98998CD203CULL
	}};
	t = 1;
	printf("Test Case 104\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 104 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -104;
	} else {
		printf("Test Case 104 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x545E19D2200E54F4ULL,
		0x53DBCB4C324A80B0ULL,
		0xA15589FBDD674B28ULL,
		0x6E930CE100FEAFCFULL,
		0x4D76DE466840FA67ULL,
		0x07ACDF0BFF1F93D1ULL,
		0xFBA146377E4A9FBDULL,
		0x1C95769E4A24F187ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x545E19D2200E54F4ULL,
		0x53DBCB4C324A80B0ULL,
		0xA15589FBDD674B28ULL,
		0x6E930CE100FEAFCFULL,
		0x4D76DE466840FA67ULL,
		0x07ACDF0BFF1F93D1ULL,
		0xFBA146377E4A9FBDULL,
		0x1C95769E4A24F187ULL
	}};
	t = 0;
	printf("Test Case 105\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 105 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -105;
	} else {
		printf("Test Case 105 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBBEA511D56920E22ULL,
		0xCFA8E0C1047FD121ULL,
		0x3D19E5B985200572ULL,
		0xDB450781D4F5FC4FULL,
		0xEAFDC6C76C4BA95CULL,
		0xC1D2B591C47B3DCBULL,
		0x4C9CDE16E5622970ULL,
		0x565C1C3D1744107FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA246077E6A6010F0ULL,
		0x59F29B7B91F18C0FULL,
		0x55C1F8CDDF176455ULL,
		0xE891EFEBC252D90EULL,
		0xFE6C464AAF578C85ULL,
		0x3EC79E2A30ED07DCULL,
		0x19508326C001E981ULL,
		0xDE1CA4C4C586706BULL
	}};
	t = -1;
	printf("Test Case 106\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 106 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -106;
	} else {
		printf("Test Case 106 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6B1AED72E2191E6BULL,
		0x26E71C5DB4610E1AULL,
		0x108C43C6B77E8B20ULL,
		0x4C5C6BCB47A9D871ULL,
		0x6367534DAD37947DULL,
		0x6523608BC2EA7DADULL,
		0x1BCF6083508E64F4ULL,
		0x00E29ADE70A6A000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE70ED08A9A5FE189ULL,
		0xA3139101AF16512DULL,
		0xAC0E062459A65F80ULL,
		0x0AB7EBE712FC621FULL,
		0x1078ED1673129F75ULL,
		0x18BC703FC979B7FCULL,
		0x55C4AB53E4833635ULL,
		0x462470F49FF267D0ULL
	}};
	t = -1;
	printf("Test Case 107\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 107 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -107;
	} else {
		printf("Test Case 107 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB98DE99DBE42958EULL,
		0x30F5F22E8C8EE5CAULL,
		0xAFCE73311347889FULL,
		0x97344C4D646CC0CCULL,
		0x6E000F72129A5C83ULL,
		0x663E05EF2707F15EULL,
		0x28ED820D035F61A7ULL,
		0x50CAEFAE8A8D5518ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x802979E6C0544D6FULL,
		0x5CD55D7729B85DB1ULL,
		0x98FEE14E4A62C6E8ULL,
		0xDD62558CE678281DULL,
		0xE86A5006CD840ECEULL,
		0xD19AB8813D35C29AULL,
		0x28D8F477D9A2D4EEULL,
		0xB9F7187D6E9A6FCCULL
	}};
	t = -1;
	printf("Test Case 108\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 108 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -108;
	} else {
		printf("Test Case 108 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x719A2ABEEE4BAED3ULL,
		0xD9F4A3D36A9A68A2ULL,
		0xBE076147F21DEE9FULL,
		0x8D03471CE1196D9CULL,
		0x8D992A01C1119696ULL,
		0x5ED01757B7C695A4ULL,
		0xD0F836F22C193C37ULL,
		0xFB320E9199A989FDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x719A2ABEEE4BAED3ULL,
		0xD9F4A3D36A9A68A2ULL,
		0xBE076147F21DEE9FULL,
		0x8D03471CE1196D9CULL,
		0x8D992A01C1119696ULL,
		0x5ED01757B7C695A4ULL,
		0xD0F836F22C193C37ULL,
		0xFB320E9199A989FDULL
	}};
	t = 0;
	printf("Test Case 109\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 109 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -109;
	} else {
		printf("Test Case 109 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1AAED5B21C533D17ULL,
		0x537C5D4E522632CFULL,
		0x1DA48CA2FFB2C95AULL,
		0xA7B99F99F128E6E3ULL,
		0x827448E5F9B39367ULL,
		0xF7D485991D5AC4AEULL,
		0x1D8FD6CE67396AECULL,
		0x9B1E55D54D32ACA6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF260AE5C5B2EB952ULL,
		0xECE0345B99ED6129ULL,
		0x67A32E38EA9AF7FDULL,
		0x546C2C951625558EULL,
		0x9F29778A8E27E432ULL,
		0xAB1E23537EA25AA6ULL,
		0x3B41534FEC1EE1A4ULL,
		0x407EB03A077B74FFULL
	}};
	t = 1;
	printf("Test Case 110\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 110 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -110;
	} else {
		printf("Test Case 110 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE1BF686F418F665CULL,
		0x38774DE555597CD5ULL,
		0xF53EB7A568B4B93AULL,
		0x6EC44116D5271E31ULL,
		0x610C7902F3B9E407ULL,
		0x1E5AD8F7D75D0CC7ULL,
		0xC65F35886C335D51ULL,
		0x2B388B6604DFFCA1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA5D7FE9C3268A3EFULL,
		0xE732DDACFB3E6FB5ULL,
		0x94408EB6C71ABABDULL,
		0x50903527B2C675D3ULL,
		0x0C3B5E177238E9D2ULL,
		0x94D821D197E46EFDULL,
		0x40034D248288613AULL,
		0x1681007BE17655AFULL
	}};
	t = 1;
	printf("Test Case 111\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 111 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -111;
	} else {
		printf("Test Case 111 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0058DFF7D613EDA8ULL,
		0x24FD2FA4C95C0BA2ULL,
		0x428E8EE348099B89ULL,
		0xD7198D63EEB817BCULL,
		0x8A407E816213AC6CULL,
		0xEF62988ADB9A39E9ULL,
		0x8E0B8BB59FB94C11ULL,
		0x595D909C933409CCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2104949B7A5A388BULL,
		0x4547199F99CE33CEULL,
		0xA217BD4F325A24EFULL,
		0xC0857D24B8B29BACULL,
		0x37B32D6F9C670AC2ULL,
		0x05F3C339A4E173C5ULL,
		0xEFF3CA3891C6C00BULL,
		0x995319E65A90C898ULL
	}};
	t = -1;
	printf("Test Case 112\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 112 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -112;
	} else {
		printf("Test Case 112 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE195E6E597BC7618ULL,
		0xFAB4A6FEFEA862DCULL,
		0xF3227D91A4C70CB9ULL,
		0xF6A12BD71F3F2987ULL,
		0x70736E00303E9F7DULL,
		0x0130F373ED5F1C20ULL,
		0x66E66AD2FEBE7BAAULL,
		0x9A7911F4A74BFFAFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE195E6E597BC7618ULL,
		0xFAB4A6FEFEA862DCULL,
		0xF3227D91A4C70CB9ULL,
		0xF6A12BD71F3F2987ULL,
		0x70736E00303E9F7DULL,
		0x0130F373ED5F1C20ULL,
		0x66E66AD2FEBE7BAAULL,
		0x9A7911F4A74BFFAFULL
	}};
	t = 0;
	printf("Test Case 113\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 113 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -113;
	} else {
		printf("Test Case 113 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x678196026E83ABBFULL,
		0xFE60004BCB974DA6ULL,
		0x5FC8C09205ED4AAAULL,
		0x8FA0733C5AA1F0EAULL,
		0x2E365534767E69D1ULL,
		0x77D8E3D6DDAF051CULL,
		0xCEE7A54C849FC585ULL,
		0xEF03D32FF09ED9E3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x22B9800F3DF1191DULL,
		0xE7FD7B8313D4DB6DULL,
		0x2B7F780A62E3CBAAULL,
		0xAE7FB827D0726230ULL,
		0x5ED60B4085AE3429ULL,
		0x89B4C28F57FCFCF0ULL,
		0xFFFC6C4EBDA77676ULL,
		0x170F7418743C5645ULL
	}};
	t = 1;
	printf("Test Case 114\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 114 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -114;
	} else {
		printf("Test Case 114 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1CC643B7459821D1ULL,
		0x295DF130EF76E958ULL,
		0xAE8303A371121AB7ULL,
		0xBA73DD72BE5896D2ULL,
		0x26A932B226C49D13ULL,
		0x35F4B25BFD4C3CBAULL,
		0xB6AB3C03E811A60BULL,
		0xC4CF26975799A24FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5A12B8D8EBBB9D34ULL,
		0x5F66EEEEFC7EC516ULL,
		0xEC67F7B6E79075CDULL,
		0x8A8F408DD9C3E048ULL,
		0xEB3948EFFD27834CULL,
		0x0B2305C4BCD57363ULL,
		0x46D761691D4F2A1BULL,
		0x743A84946D16CCFCULL
	}};
	t = 1;
	printf("Test Case 115\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 115 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -115;
	} else {
		printf("Test Case 115 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB594F513E2FC6CA3ULL,
		0x39179BC909BB2316ULL,
		0xD8B6060D67EB863FULL,
		0x0535D1F72FDFE61FULL,
		0x076301BD86110529ULL,
		0x2DF2C410A681416AULL,
		0xC620BF7EBD9AF4E1ULL,
		0xE5C173101B84AC0DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xECF2D849A97B3B08ULL,
		0x747408C7E9A73CC7ULL,
		0x27E3B684509095ECULL,
		0x83B8D80E6632F9FFULL,
		0xCA0C1F76DB914CCDULL,
		0xA0662714EB57FE28ULL,
		0x00D8758C3BF027F8ULL,
		0x42B310D10140B2A4ULL
	}};
	t = 1;
	printf("Test Case 116\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 116 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -116;
	} else {
		printf("Test Case 116 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB85FE96DFF292AEBULL,
		0x8580280F28A3A910ULL,
		0x8CDE4037DFBB0CE5ULL,
		0xBE0D1614197B2772ULL,
		0x74FBEC9140746FE4ULL,
		0x04BCA5D8246423B5ULL,
		0xDE499C65DEBDAF6BULL,
		0x94A48A8991022E23ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB85FE96DFF292AEBULL,
		0x8580280F28A3A910ULL,
		0x8CDE4037DFBB0CE5ULL,
		0xBE0D1614197B2772ULL,
		0x74FBEC9140746FE4ULL,
		0x04BCA5D8246423B5ULL,
		0xDE499C65DEBDAF6BULL,
		0x94A48A8991022E23ULL
	}};
	t = 0;
	printf("Test Case 117\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 117 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -117;
	} else {
		printf("Test Case 117 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4CCA7DFC9025BB7BULL,
		0x17ACC922D94AAD17ULL,
		0x427A8E59BC4DCDD6ULL,
		0x31FE8E74615C0B70ULL,
		0x7806FBD530459A7EULL,
		0xCD61DBFCAD96839CULL,
		0xDAD17ADEE9082EA0ULL,
		0x0F3AC58EBD0163ECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x408ADF63AC1F8C47ULL,
		0xF227B19E5F95AE93ULL,
		0x80B1745D483B7092ULL,
		0x82F7E0D702A9D7BBULL,
		0x13AB99078CCD5B92ULL,
		0x77A44201C1C67FA8ULL,
		0xA262D683E1F30B4BULL,
		0x4F237F586405CEC9ULL
	}};
	t = -1;
	printf("Test Case 118\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 118 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -118;
	} else {
		printf("Test Case 118 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x985E661A6DB070ECULL,
		0xE544911C816C01A8ULL,
		0xB8E7E1322B77DF6FULL,
		0x66A2163E95E534DDULL,
		0x4952C729338F090EULL,
		0xBCC29C4FDB52ECF2ULL,
		0xAAD9AE3F3FFBB78FULL,
		0x87E85EB01DB70324ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF7DCF68BE49AB331ULL,
		0x01903133172DDAEBULL,
		0xCE6CF6A223EDE700ULL,
		0x9E048759AE046653ULL,
		0xCBB1406AAFDE7C50ULL,
		0x2CE69748C61E3CC0ULL,
		0xC4D21C9F054F63FBULL,
		0x30E6E5EC3890903BULL
	}};
	t = 1;
	printf("Test Case 119\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 119 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -119;
	} else {
		printf("Test Case 119 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x420C49BC320BEF4DULL,
		0xC359237117C68833ULL,
		0xA8AD87EEF8BCEDF7ULL,
		0x854682E957210B69ULL,
		0x4A5F6834077AC933ULL,
		0xF5411184B01B7DCCULL,
		0xD1B19AC46D316378ULL,
		0xFBF35A12F3BCBF8CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3588EE980CFA9F0CULL,
		0x2D778B818594204EULL,
		0x504E7F9FB5413F9BULL,
		0xB3C2758ABE2D32A6ULL,
		0x2A1C748836590F80ULL,
		0xAF08C4C84408589DULL,
		0xA029450AFDB4ACD2ULL,
		0xEDA41E1AD28DA5FEULL
	}};
	t = 1;
	printf("Test Case 120\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 120 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -120;
	} else {
		printf("Test Case 120 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x76BFC6E24CC8A79CULL,
		0xF20D7D6A5B9DF1CEULL,
		0xCEEF1E9D2823381DULL,
		0x683459F47FFD6A18ULL,
		0x8D1B41F8113A3C10ULL,
		0x8F0DEE996A1DAC4BULL,
		0x37FB0FF2624ECC77ULL,
		0x0914F414A3C71A41ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x76BFC6E24CC8A79CULL,
		0xF20D7D6A5B9DF1CEULL,
		0xCEEF1E9D2823381DULL,
		0x683459F47FFD6A18ULL,
		0x8D1B41F8113A3C10ULL,
		0x8F0DEE996A1DAC4BULL,
		0x37FB0FF2624ECC77ULL,
		0x0914F414A3C71A41ULL
	}};
	t = 0;
	printf("Test Case 121\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 121 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -121;
	} else {
		printf("Test Case 121 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDB67E8FE7C2AE476ULL,
		0x8399D52979DAE8EAULL,
		0x8856A236283F2B3DULL,
		0x2BEA4B8D9475EC45ULL,
		0x7CA411E2BBC8601BULL,
		0xF95FA04A198BD030ULL,
		0xD3ECFBAF33D62CFBULL,
		0x04CF2977948EC7B8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x19A4748A428668EEULL,
		0x8FC57ECFA817010BULL,
		0x623FE74167ABF50FULL,
		0xAF779B940DEE4624ULL,
		0x9A756EEBE4C3ED9FULL,
		0x8BA7E40B426C4B2AULL,
		0xA5302782CD8BCB0CULL,
		0x5301E89296DFB77EULL
	}};
	t = -1;
	printf("Test Case 122\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 122 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -122;
	} else {
		printf("Test Case 122 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6DAD1422EF8D1214ULL,
		0xAD6AAFE744ED3002ULL,
		0x74C99ED2C372AE6EULL,
		0xA9A35D2531D6951FULL,
		0x54EAC7F67CF86B5CULL,
		0x15E90AE10AEC447AULL,
		0x447BC4A607C92B0EULL,
		0x1399E90B366C558FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCD635D6C1FBE2B8AULL,
		0xD9019E0CD79C1166ULL,
		0xFBF68E01F68D7474ULL,
		0x531A4371A6DC05DFULL,
		0x78911BD777B80577ULL,
		0x56F297416C0EB901ULL,
		0x6C92C571F4C22A30ULL,
		0xAC10A25840897309ULL
	}};
	t = -1;
	printf("Test Case 123\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 123 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -123;
	} else {
		printf("Test Case 123 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x684C729A946158A0ULL,
		0x6BE417ACFBE5DE8FULL,
		0x30D4ED0CFC6E32D6ULL,
		0xF6106DCDD526B14AULL,
		0xEFB03E2B62A29B16ULL,
		0x01F6520B8768C233ULL,
		0xE2B8A1CD5595E80EULL,
		0x9749B8FFB00E962FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x339BE5F149E41945ULL,
		0x139C1FB944633206ULL,
		0x53AC1DDF566D31B2ULL,
		0xDC44CEF4C9A27EC2ULL,
		0x6E231F4FEBC9E5C1ULL,
		0xC69C7D0F94F26D6EULL,
		0x3CB1AE20A1724135ULL,
		0xF8D24002D324C14AULL
	}};
	t = -1;
	printf("Test Case 124\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 124 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -124;
	} else {
		printf("Test Case 124 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x455C6D2DB0DF066EULL,
		0x67CBA02F21191A1AULL,
		0x1999072966CEEB04ULL,
		0x95685A28D416A1F3ULL,
		0xE9337E77F0F18A71ULL,
		0xD16399A4F2083213ULL,
		0x6E15370BC7CBA6C7ULL,
		0x4EC93DB1076FE72FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x455C6D2DB0DF066EULL,
		0x67CBA02F21191A1AULL,
		0x1999072966CEEB04ULL,
		0x95685A28D416A1F3ULL,
		0xE9337E77F0F18A71ULL,
		0xD16399A4F2083213ULL,
		0x6E15370BC7CBA6C7ULL,
		0x4EC93DB1076FE72FULL
	}};
	t = 0;
	printf("Test Case 125\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 125 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -125;
	} else {
		printf("Test Case 125 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC31CDABFD0A28404ULL,
		0x9D0854436CBE85B5ULL,
		0x2014ECF28EA1D83BULL,
		0x71E79B2ABE553CFFULL,
		0x21F0C5EB75EFBAD8ULL,
		0x8E0A5FA6A39A7E34ULL,
		0x0941B87303011ECDULL,
		0xDBDE04B080237F5FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x855021554D4E5449ULL,
		0x477F003EB92AA2F2ULL,
		0x2A38A0EA96A39466ULL,
		0xE54F90794E0EFEF3ULL,
		0x1021DFD8B3EFFC41ULL,
		0xC06C4A17F1F8A5CEULL,
		0xF7FF46ECFF5D3720ULL,
		0xD602246E9FD31A3FULL
	}};
	t = 1;
	printf("Test Case 126\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 126 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -126;
	} else {
		printf("Test Case 126 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6EB980C584FF0870ULL,
		0x0BF548CF287BBB20ULL,
		0x43908676FCD8195AULL,
		0xF1B9E22E0D676192ULL,
		0x93C59001CEA3AAE9ULL,
		0x96AC0F8C52048831ULL,
		0xC6E49C2CB8DF0305ULL,
		0xAEF70B0618C1B253ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB96BD60D59ADF3F5ULL,
		0x5CBA5CBB91784E30ULL,
		0x4DF52B7DC0121A56ULL,
		0x2B8F1D7ACACFE6AFULL,
		0x9AE6175287ADA9D7ULL,
		0xEEFD0058F4C0A733ULL,
		0x293AB4CCAC059C95ULL,
		0x3AC0FF3203752250ULL
	}};
	t = 1;
	printf("Test Case 127\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 127 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -127;
	} else {
		printf("Test Case 127 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAD24C43B0E1EBB71ULL,
		0x0A75D0DBCF94A337ULL,
		0xEF3CE98DE4BC4BB2ULL,
		0x09FAFCC65A722FF7ULL,
		0xB089DFC5D2809FE7ULL,
		0xC9C71D1304D3B302ULL,
		0x9A6E1FA52F35F5EAULL,
		0xD4C9F986BBC0FCE2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7A9E3711329610C1ULL,
		0x09543843E2B871C0ULL,
		0xB827E5422EE2CA37ULL,
		0xDA7E6EDEFBAF0374ULL,
		0x58A39B4DC1AB706AULL,
		0x9EFCF7710172F11CULL,
		0x4010B970448DD53EULL,
		0xEDDB55724EBB327DULL
	}};
	t = -1;
	printf("Test Case 128\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 128 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -128;
	} else {
		printf("Test Case 128 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB85CCE2F56800271ULL,
		0xCD05C89CDD477F9DULL,
		0x6C0E805094AB97A5ULL,
		0x77804740E6F35730ULL,
		0xFCC76792E213EF76ULL,
		0x69073FFFC1B6C512ULL,
		0x542769CDB62BC46AULL,
		0xA30D1668F9FC8594ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB85CCE2F56800271ULL,
		0xCD05C89CDD477F9DULL,
		0x6C0E805094AB97A5ULL,
		0x77804740E6F35730ULL,
		0xFCC76792E213EF76ULL,
		0x69073FFFC1B6C512ULL,
		0x542769CDB62BC46AULL,
		0xA30D1668F9FC8594ULL
	}};
	t = 0;
	printf("Test Case 129\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 129 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -129;
	} else {
		printf("Test Case 129 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC9E282D1D6114328ULL,
		0x6226231324B45F47ULL,
		0xE2294539505721FDULL,
		0x64BD2880D4B8199DULL,
		0x7B5EE4BAA7451211ULL,
		0x36BAC9140C9B15A1ULL,
		0xA7D9BDE7F93D078CULL,
		0x015C693D6C676DD0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x67BAB5FBE13C45F7ULL,
		0x3A06C3E6F70E0DD2ULL,
		0xE21E00F36A2E094AULL,
		0xFBDC565DBE18A359ULL,
		0x377CF93F46EF34EEULL,
		0x64B34292490A874CULL,
		0x6E31F78C0B6BA0E6ULL,
		0xE056D0A648E96D5AULL
	}};
	t = -1;
	printf("Test Case 130\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 130 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -130;
	} else {
		printf("Test Case 130 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x01C21766F87686B5ULL,
		0xDD1273814931F120ULL,
		0x8A5CB6D037A88C79ULL,
		0x72473EF295638D05ULL,
		0xFEC7DF3000472BE4ULL,
		0x385D1C2C0E8A9D11ULL,
		0x3DAA73B384B51631ULL,
		0x10B0C91831D2882FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x708FE7B5598EB8B0ULL,
		0xE53D633FF7C4E218ULL,
		0x80EEC4E520E16B46ULL,
		0x4C6B000EDD842C64ULL,
		0x86BC0B42AD15FD70ULL,
		0x78F5FC7863863164ULL,
		0xB57213CEE2D1C5A8ULL,
		0xC5C26E57DAED7CFFULL
	}};
	t = -1;
	printf("Test Case 131\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 131 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -131;
	} else {
		printf("Test Case 131 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC1F9572AF565E6B8ULL,
		0x8BE9631A6D1505DDULL,
		0x6F4E0DEE4C8138FEULL,
		0x9FE4324D52C61B30ULL,
		0x3CAC5C77020DF5F6ULL,
		0x4F30E1FB46586ECAULL,
		0x79C27C5C69D38673ULL,
		0x571F2A2D0359D97EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3DFBFC4FAC794EC8ULL,
		0x07182A88EC781C36ULL,
		0x078AA101B2D5EC98ULL,
		0xCD97A31913A5CF20ULL,
		0x1BC148442A25B4E6ULL,
		0xCCBEB54DA5E3E93DULL,
		0xA8FF9526C7C10DA0ULL,
		0xA568CA54DB40201EULL
	}};
	t = -1;
	printf("Test Case 132\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 132 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -132;
	} else {
		printf("Test Case 132 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x172295FE05D30426ULL,
		0x3386BA538188590CULL,
		0xC4025E193E1BE97EULL,
		0x17DA4AD6B215F547ULL,
		0xDB93AA2644024D31ULL,
		0x06F7DE9FD199EA5CULL,
		0xD4A97A31C640E933ULL,
		0x7DB5A4EA8FA1611AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x172295FE05D30426ULL,
		0x3386BA538188590CULL,
		0xC4025E193E1BE97EULL,
		0x17DA4AD6B215F547ULL,
		0xDB93AA2644024D31ULL,
		0x06F7DE9FD199EA5CULL,
		0xD4A97A31C640E933ULL,
		0x7DB5A4EA8FA1611AULL
	}};
	t = 0;
	printf("Test Case 133\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 133 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -133;
	} else {
		printf("Test Case 133 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1DA0E4268D364107ULL,
		0x6BED4BF451766CC4ULL,
		0x3F4C49B2162CE783ULL,
		0xD3C748BC785EF1F9ULL,
		0xF3659E1C26548C3DULL,
		0xA5BF79610CBC40D7ULL,
		0xEDDF07ABA7982DC7ULL,
		0x42762834BFD7E9FFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x467418B55966B80FULL,
		0x79C8E455E6AD482AULL,
		0xFB775911A7F0656AULL,
		0x92286C09B042E7F2ULL,
		0x22D650544A38264BULL,
		0xB1D64B8E4D1E12CDULL,
		0xE0043196B613DCFBULL,
		0xD693F0146B2BC3FFULL
	}};
	t = -1;
	printf("Test Case 134\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 134 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -134;
	} else {
		printf("Test Case 134 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0A77A81DB80B07E7ULL,
		0x6FDCAD55050B34D2ULL,
		0x5E5EB5104CC413D4ULL,
		0x509499FA93EB4E2BULL,
		0x084780D1BE37B9D6ULL,
		0xEFAD56082DEA3744ULL,
		0x54CC8099034F7E5AULL,
		0x26C10DD0010C076CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1891188AE44CA4DFULL,
		0x6CE899FC804C9228ULL,
		0xFA422C439F451E77ULL,
		0xF6CB672BF7151647ULL,
		0x2885B35B210F7A7AULL,
		0x042AB84062347E7AULL,
		0x5BAB8BDCA6E4DE27ULL,
		0xD06AF865A706443FULL
	}};
	t = -1;
	printf("Test Case 135\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 135 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -135;
	} else {
		printf("Test Case 135 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x520E4ACE16CCA03DULL,
		0x4DD20EF07F950F8CULL,
		0xD8DD7A812F4583DDULL,
		0x3D45D2C115CE5773ULL,
		0x852459DF711B7F0DULL,
		0x473A391C7B4BBECFULL,
		0xF6C0D5455CBE3409ULL,
		0x3DE04736ED143F0AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4971BDD0A5F0C8BBULL,
		0x7A982C23825398CAULL,
		0x2D69DBF6CA4A2E87ULL,
		0xE65BB02E448227A3ULL,
		0xA203B2DE7701E38FULL,
		0x45F8CD1F963E5F70ULL,
		0xAA3EC526F8FB6567ULL,
		0x5138CA37CF2C7784ULL
	}};
	t = -1;
	printf("Test Case 136\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 136 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -136;
	} else {
		printf("Test Case 136 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC7E6AE9BADC06CCFULL,
		0x969C6D74BF0FE5C4ULL,
		0x30F15C7E4B4CE065ULL,
		0x6E7DFAA9F00990A0ULL,
		0xC7C2205AC70FDB14ULL,
		0x128CC64EB8F84E8FULL,
		0x11A91E3254465F44ULL,
		0x3AC42F2DFD9617FBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC7E6AE9BADC06CCFULL,
		0x969C6D74BF0FE5C4ULL,
		0x30F15C7E4B4CE065ULL,
		0x6E7DFAA9F00990A0ULL,
		0xC7C2205AC70FDB14ULL,
		0x128CC64EB8F84E8FULL,
		0x11A91E3254465F44ULL,
		0x3AC42F2DFD9617FBULL
	}};
	t = 0;
	printf("Test Case 137\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 137 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -137;
	} else {
		printf("Test Case 137 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFBD315E675D6E695ULL,
		0x6B51E37BFFBA7416ULL,
		0xC4D688D821095C65ULL,
		0x2BFC3F7C68067338ULL,
		0x8E36F87C039DD65FULL,
		0x4E63CC3664B76CBAULL,
		0x6C17CB1B9D874964ULL,
		0xDF4F550FD06AB469ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAC97360E370C705CULL,
		0xFBF1167649B66F76ULL,
		0x1807383AB781847AULL,
		0x018FB8ABE193005FULL,
		0x35DE72E10FEAF0DAULL,
		0x1DC9E47621FF3F14ULL,
		0xDF52797C6A4F2733ULL,
		0x9563B88F1B5B8BB6ULL
	}};
	t = 1;
	printf("Test Case 138\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 138 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -138;
	} else {
		printf("Test Case 138 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5DD62FE8A1AB2E46ULL,
		0x97C5552DDFC8D0F7ULL,
		0x107148ED80EB49B2ULL,
		0xD208A806A860DADDULL,
		0x1B1A7E24BE68742DULL,
		0x980A4A2329B6B8E8ULL,
		0x5A67030A302F0142ULL,
		0x930F18E365DCCAEAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1AF73C3D698B3911ULL,
		0x00BCAD5CEA4D1023ULL,
		0x2C5D7E66A1398994ULL,
		0x29F3B767ED2F2DD9ULL,
		0x5CDFD1D23C5F1A65ULL,
		0x393DD4730E97E5FAULL,
		0xCBD21E89A90B9BA2ULL,
		0x945A5BDFE6AE343EULL
	}};
	t = -1;
	printf("Test Case 139\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 139 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -139;
	} else {
		printf("Test Case 139 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x014DAB812FE86CD7ULL,
		0x338AA3C0F9462831ULL,
		0x47E8A0C692E8E5B3ULL,
		0x8A6018879D4E1586ULL,
		0xEF769F2CD279E6AEULL,
		0x63B09143A83326EAULL,
		0x8D610DBA6ABEC477ULL,
		0xB2397537CEB7F935ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8A40AFCD623D8298ULL,
		0xBD45F8B912189984ULL,
		0x40F337992C89A6F0ULL,
		0x093E5C8A0A0B4C1FULL,
		0xAF8A3F2534B684FAULL,
		0x8F5A99CA7BB62B20ULL,
		0x2A89107CF5EB452EULL,
		0xAF7D80ABADD64F23ULL
	}};
	t = 1;
	printf("Test Case 140\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 140 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -140;
	} else {
		printf("Test Case 140 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x18B79E693E1020C2ULL,
		0xA2B55AE2A2E3BB36ULL,
		0x87A1E0C5D5AF5492ULL,
		0xE6264A2BC6F096E0ULL,
		0xA27B1CD5E2D09D94ULL,
		0x3185FC6A83A7576DULL,
		0xCB8D46E4E71F538CULL,
		0x4093ECBCA13ACA97ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x18B79E693E1020C2ULL,
		0xA2B55AE2A2E3BB36ULL,
		0x87A1E0C5D5AF5492ULL,
		0xE6264A2BC6F096E0ULL,
		0xA27B1CD5E2D09D94ULL,
		0x3185FC6A83A7576DULL,
		0xCB8D46E4E71F538CULL,
		0x4093ECBCA13ACA97ULL
	}};
	t = 0;
	printf("Test Case 141\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 141 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -141;
	} else {
		printf("Test Case 141 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEC74E366E9AE124DULL,
		0x30D21FAA722E3A24ULL,
		0xAF3149335AA3324FULL,
		0x55E323436ED74573ULL,
		0x46EB1AF31B3B1DF2ULL,
		0x709EBA8224108A63ULL,
		0x9092147746A4A58EULL,
		0xBC714DE769C44872ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1D66FCAA8D00410EULL,
		0xBCB404710D6E9D6CULL,
		0x2545AF5F4EE5B4E7ULL,
		0xD9F6F82375278020ULL,
		0x57C4D81ACDBE79DAULL,
		0xDE4B389C5C598E82ULL,
		0x7F1D503A7F3C2069ULL,
		0xEDA0E384576AD66FULL
	}};
	t = -1;
	printf("Test Case 142\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 142 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -142;
	} else {
		printf("Test Case 142 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x97E05A06F48D1A0FULL,
		0xBF62AE34C256EC85ULL,
		0x7DF90123AD60106BULL,
		0x7C204A4104A27AB7ULL,
		0xEC29388B58F184B3ULL,
		0xC76DCC5961264CAEULL,
		0x9CD88B376ACA384EULL,
		0x5637313E0582ED55ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6B0C267ED9DCEA86ULL,
		0x346CBB7A4C92FDC9ULL,
		0x53AF1B3D393FBD1FULL,
		0xF059D9156407E6A9ULL,
		0x4CB9D950E2D0BB3BULL,
		0xA8A1521253EA7CB0ULL,
		0x3B0DF5633825A026ULL,
		0x6D06088646F8BF40ULL
	}};
	t = -1;
	printf("Test Case 143\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 143 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -143;
	} else {
		printf("Test Case 143 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x68475F180E147D67ULL,
		0xAB4D8637892E7154ULL,
		0x69A55760B14796F5ULL,
		0x74975F550F27AD92ULL,
		0x3877096C84E7E82FULL,
		0x11BE843FA537714DULL,
		0x776C59CE4057443FULL,
		0x88509B6823BEFCD6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x907DCEAF584AA39DULL,
		0xD3C0DCC3F87B954CULL,
		0xBD11993B5ACA1363ULL,
		0xA0757BC34260971DULL,
		0x09636DCEFA01BD70ULL,
		0x60E127BF4D3B61A4ULL,
		0xADF9C9D3AC7C1E03ULL,
		0x632026B879783DEAULL
	}};
	t = 1;
	printf("Test Case 144\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 144 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -144;
	} else {
		printf("Test Case 144 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB1EBC7C464307567ULL,
		0x6795083A135CEA82ULL,
		0x144B7C75F9C04CE0ULL,
		0x1E29E048FCFEA0DCULL,
		0x842DD3903BA813DAULL,
		0x88717F7AE38E6270ULL,
		0x9829CB0A969B7AA8ULL,
		0xD2ABBB4EE1FFF398ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB1EBC7C464307567ULL,
		0x6795083A135CEA82ULL,
		0x144B7C75F9C04CE0ULL,
		0x1E29E048FCFEA0DCULL,
		0x842DD3903BA813DAULL,
		0x88717F7AE38E6270ULL,
		0x9829CB0A969B7AA8ULL,
		0xD2ABBB4EE1FFF398ULL
	}};
	t = 0;
	printf("Test Case 145\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 145 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -145;
	} else {
		printf("Test Case 145 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1550E26889E24C90ULL,
		0xE3BC42ED67EB81D4ULL,
		0xB4EE35CFB3768D3BULL,
		0xCDD89E231C80EBE9ULL,
		0x4B1D17937167C940ULL,
		0x8BA9E0E67F2DBF49ULL,
		0x80BD5C8FB0B458CFULL,
		0xFB1403A2F465F506ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF693AE6F83498034ULL,
		0xFC79C31212A39111ULL,
		0xC2916EF891F4A47DULL,
		0xE9D2274E1FC580EBULL,
		0x9633514622A39BA1ULL,
		0x1EFEC8D42AF68B75ULL,
		0xD287300F91AAF105ULL,
		0x5307E727DC3DA4E7ULL
	}};
	t = 1;
	printf("Test Case 146\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 146 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -146;
	} else {
		printf("Test Case 146 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2E412AB22A1F3A58ULL,
		0x32B8BF63612FD341ULL,
		0x6003342739B539BFULL,
		0x288ED77DD4E95594ULL,
		0x4ACB98EF90E40079ULL,
		0x43F1A94FDB75C8F1ULL,
		0x5B3F5F66E639E2BEULL,
		0xF96E8178C498A0C8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCAB65195D512E5D6ULL,
		0x9A5E808E06ED75E8ULL,
		0xB56C016564AEEDD7ULL,
		0x64B2909D1BA15715ULL,
		0xA8186549FAE6B92FULL,
		0xBB4F71D75F1F8633ULL,
		0x58B59B201B7A4306ULL,
		0x5ABCAC804CAEB724ULL
	}};
	t = 1;
	printf("Test Case 147\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 147 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -147;
	} else {
		printf("Test Case 147 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5E4EDBBBA93949CBULL,
		0x4E62342B3790BE1BULL,
		0x502C597EC129A940ULL,
		0xB459B14BB00FEE63ULL,
		0x2B5DDB8DA484D830ULL,
		0x40470DE1B5D64A7CULL,
		0x0019DF06186E0A29ULL,
		0x0FA22036B18C4CBBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1FA066C46414467CULL,
		0x14F8BF1A7629FB64ULL,
		0x20992A98FDE335E0ULL,
		0xC35DBB86B7F332FAULL,
		0xF9815EBB792D4C52ULL,
		0x070332F63E1FD619ULL,
		0x0E8E9EF3AA9C9264ULL,
		0xF07309FF7833EBC4ULL
	}};
	t = -1;
	printf("Test Case 148\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 148 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -148;
	} else {
		printf("Test Case 148 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA7CE4845C37485D3ULL,
		0xC193B0DEF0942793ULL,
		0x42C34157BF9BF345ULL,
		0x41EA8F8D348BF769ULL,
		0xA38B3F0861D62F44ULL,
		0x3FDD5C2ABFF07A36ULL,
		0x8645C668561C3624ULL,
		0xA68444DBBBBF4DD4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA7CE4845C37485D3ULL,
		0xC193B0DEF0942793ULL,
		0x42C34157BF9BF345ULL,
		0x41EA8F8D348BF769ULL,
		0xA38B3F0861D62F44ULL,
		0x3FDD5C2ABFF07A36ULL,
		0x8645C668561C3624ULL,
		0xA68444DBBBBF4DD4ULL
	}};
	t = 0;
	printf("Test Case 149\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 149 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -149;
	} else {
		printf("Test Case 149 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD9E61CCD41772CEAULL,
		0xF83A40828A48E50DULL,
		0xFF826516D8FF9DB2ULL,
		0xFB82E239E171702CULL,
		0xC1C640E9314F507EULL,
		0x787685C56C968E33ULL,
		0xE6408AC73C9C2FEFULL,
		0x25FC8A9E6B989FFDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD623710BD26B03D9ULL,
		0x7644C569F00F2B92ULL,
		0xEE03E14AB35B6B88ULL,
		0x19BB7D841A971935ULL,
		0x4C1B7A7ECFCB196DULL,
		0x88877F20B8236ED6ULL,
		0x50F70A9AAE451E8AULL,
		0xBABB16616F519D3DULL
	}};
	t = -1;
	printf("Test Case 150\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 150 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -150;
	} else {
		printf("Test Case 150 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4400884A2D8D6888ULL,
		0x01A647FDB91159F2ULL,
		0x41F72FA0B8FD2CD9ULL,
		0x0A77AB2A016AB57DULL,
		0x38D820A6C147A427ULL,
		0x1DB075F4C9C4B063ULL,
		0xC252DCB691AFCD9AULL,
		0x42FFF1256C03084AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x84027E75CD1244B2ULL,
		0xCC7566FD31846DEDULL,
		0x71BAF0BCF747F13FULL,
		0x147E527D7F0F902AULL,
		0xC353DDFF1952CC85ULL,
		0xA784909B631FCA8BULL,
		0x44023277C48CB3EAULL,
		0xCE25C1FEBC94F7D7ULL
	}};
	t = -1;
	printf("Test Case 151\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 151 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -151;
	} else {
		printf("Test Case 151 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0CDBAE5F1BA0719DULL,
		0xAD1ADAF5B8788100ULL,
		0xF1F1F4A33112F045ULL,
		0x32B0E567099D8D6BULL,
		0xDAE37D4C96AB93F3ULL,
		0x69F2722D65FFFC8FULL,
		0xBB9C5F346BEDCB06ULL,
		0x9C60CB49579F80CBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE9541486DB990CC8ULL,
		0x40DFC9BB5063B27FULL,
		0xC87CD9D1CA3977C2ULL,
		0x5ECDCFFB1C6D9C58ULL,
		0x032ED803D77ED670ULL,
		0x77C42B79BFC54DAEULL,
		0x26E0F20751E65AFDULL,
		0x5021486634044BE2ULL
	}};
	t = 1;
	printf("Test Case 152\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 152 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -152;
	} else {
		printf("Test Case 152 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0168F0493B1C5240ULL,
		0x5267C57BAAABDE8AULL,
		0x61D856F1A03DA0B4ULL,
		0xE0C692E52886AC02ULL,
		0x89282DE540B55B1AULL,
		0x8FE04FE8EBDC8E4AULL,
		0x4B7AA5DA99FC2C92ULL,
		0x6BFE8D3B726FC7E4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0168F0493B1C5240ULL,
		0x5267C57BAAABDE8AULL,
		0x61D856F1A03DA0B4ULL,
		0xE0C692E52886AC02ULL,
		0x89282DE540B55B1AULL,
		0x8FE04FE8EBDC8E4AULL,
		0x4B7AA5DA99FC2C92ULL,
		0x6BFE8D3B726FC7E4ULL
	}};
	t = 0;
	printf("Test Case 153\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 153 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -153;
	} else {
		printf("Test Case 153 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x06536AFC46BF5995ULL,
		0x1417E3581A1774F9ULL,
		0x3C530C26275BEA12ULL,
		0xCC800FD006494397ULL,
		0xFA09EB202DDA1361ULL,
		0x829754D3FA0E59A9ULL,
		0x1B47792736391391ULL,
		0x3508CE8976A3FF8AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0236BAE2EC0152A0ULL,
		0x86CE3D5A85D0ED86ULL,
		0x1EA6D2D2D0C7D2C3ULL,
		0x09DEDC2F37C46D8EULL,
		0xD19B76047CD7C26BULL,
		0x66F3212E898990ABULL,
		0x81570EBF242E6411ULL,
		0xBAD081C348B80253ULL
	}};
	t = -1;
	printf("Test Case 154\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 154 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -154;
	} else {
		printf("Test Case 154 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x14FCD4ED04862AFBULL,
		0x34774E82E699F36AULL,
		0xB0686AA49114208DULL,
		0xF3B5E5F227B18753ULL,
		0x4060FCC3D99F2E66ULL,
		0x4FBBFCB0EC397E3FULL,
		0x83BA0C98D9F0B174ULL,
		0xF95101211C0A9444ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF8C93BD7709DDD41ULL,
		0x629582DA7067854CULL,
		0x43C90A55DB3E0971ULL,
		0xC8312CB840C3F595ULL,
		0x17E3EFB0AE6C10EEULL,
		0x7EB315A6F13E97F7ULL,
		0xFA5B01A693F62D1CULL,
		0xF2A27001D5A833FBULL
	}};
	t = 1;
	printf("Test Case 155\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 155 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -155;
	} else {
		printf("Test Case 155 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA9F5161AF8B2C0F3ULL,
		0xAB250998D51618A4ULL,
		0x45388BB0E91859E6ULL,
		0x996E09AE55169871ULL,
		0xFE47DCA9C01A5840ULL,
		0x2DCCC1B82CB8EEC0ULL,
		0x604AC29100646634ULL,
		0xA6D60AC6911EE0F7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB1184998C162CDB8ULL,
		0x62B5BF93378C3626ULL,
		0x6B486E88AA613E7DULL,
		0x772A41963030E7D5ULL,
		0x68500F1CE54AB62AULL,
		0x091599DF33390DA1ULL,
		0x9E7B576191207B99ULL,
		0x8B1EBA3277C03D34ULL
	}};
	t = 1;
	printf("Test Case 156\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 156 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -156;
	} else {
		printf("Test Case 156 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3EEBD35DE0675A47ULL,
		0x2A396B5768072CF7ULL,
		0x3982412D91C36545ULL,
		0x4806474AF4456AA1ULL,
		0x8131C0D77919207DULL,
		0x1983BABDF0D614C1ULL,
		0x4AEA2E9D2EED8F4CULL,
		0xE02BA357778DC48CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3EEBD35DE0675A47ULL,
		0x2A396B5768072CF7ULL,
		0x3982412D91C36545ULL,
		0x4806474AF4456AA1ULL,
		0x8131C0D77919207DULL,
		0x1983BABDF0D614C1ULL,
		0x4AEA2E9D2EED8F4CULL,
		0xE02BA357778DC48CULL
	}};
	t = 0;
	printf("Test Case 157\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 157 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -157;
	} else {
		printf("Test Case 157 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x364CD1372766F12BULL,
		0x8C13F0A2B5A6742AULL,
		0x030EC7A847DD3B60ULL,
		0x2F27EDF6D4F39ECCULL,
		0x674D4F815B68A605ULL,
		0xE44D8EFC103DC873ULL,
		0x3DC313D27F44EB5CULL,
		0x00F363DBBEC6C602ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xADC62AF9E11ECD6BULL,
		0xCD52452F19306AB8ULL,
		0x0D32DEAB110CE10EULL,
		0xD90C9AB6746227BAULL,
		0x705DCBFC3FD5E7D6ULL,
		0x6AD7268005F1484EULL,
		0x197B2DD5F113CA2FULL,
		0xE80280F9DA16CCA6ULL
	}};
	t = -1;
	printf("Test Case 158\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 158 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -158;
	} else {
		printf("Test Case 158 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF91B8AA5F95C7529ULL,
		0x80FF266E2C0DD30DULL,
		0x638CCD7DBFF9446FULL,
		0xE866C5687F8A8155ULL,
		0xA2ACB401FC98D882ULL,
		0x8A21E168058EDDFFULL,
		0x9C9054171502B083ULL,
		0x9110AF6F33654BACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCC23605D65F31C8FULL,
		0x31CD3699D2D012BDULL,
		0xA7F656F94D12FD40ULL,
		0x99A65374E3270CC3ULL,
		0x938F0053C4DC4188ULL,
		0x69A7A2AAA7C129E6ULL,
		0xDB1895D53C73AD6CULL,
		0x2687AFEE74791E43ULL
	}};
	t = 1;
	printf("Test Case 159\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 159 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -159;
	} else {
		printf("Test Case 159 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE2FDA514236815C2ULL,
		0xB64F2761B283E33AULL,
		0x51064E729DB8532CULL,
		0x93D454679D4FB8E5ULL,
		0x42B14E98DF8F280FULL,
		0x3F9740DA1BF3FD4CULL,
		0x01F0F8DA119E6695ULL,
		0x3AA3A946E28C0191ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCBB1A1BABEAE2D27ULL,
		0xDB0D412ADE7B973DULL,
		0x3EA46110EC2DF4A9ULL,
		0x811CA78E3FF7ADA1ULL,
		0x8544E2A6F33CDF21ULL,
		0xB429A831DD7FC266ULL,
		0x3D74F73758D9CAC9ULL,
		0x9D20BECF3DE43B4BULL
	}};
	t = -1;
	printf("Test Case 160\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 160 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -160;
	} else {
		printf("Test Case 160 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x135DFC62D884CC63ULL,
		0xD7B9D7FD4C94BCA1ULL,
		0x52C793E910D312E4ULL,
		0xC342C3F5F3E397CCULL,
		0x3122810DF9D6CBA3ULL,
		0x6C6B60DEA810AE4EULL,
		0xBE2B9482E3918326ULL,
		0xF7FF7042D72875ACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x135DFC62D884CC63ULL,
		0xD7B9D7FD4C94BCA1ULL,
		0x52C793E910D312E4ULL,
		0xC342C3F5F3E397CCULL,
		0x3122810DF9D6CBA3ULL,
		0x6C6B60DEA810AE4EULL,
		0xBE2B9482E3918326ULL,
		0xF7FF7042D72875ACULL
	}};
	t = 0;
	printf("Test Case 161\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 161 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -161;
	} else {
		printf("Test Case 161 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6067BFF63D32009FULL,
		0x6F0E637FFD1A05D6ULL,
		0xB5B05154E4A8EF36ULL,
		0x0FEBFA61D37B05EEULL,
		0x5015E639E4D841BDULL,
		0x187A684CAA5B358EULL,
		0x8F8E9F012A46C9BDULL,
		0xCBB76F73F1608670ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBD97D62BC0B28B6CULL,
		0xA3EC4D8D497114DFULL,
		0xA0561C0626BD636DULL,
		0xCE9811D65D1A0294ULL,
		0xBDA1F97E47FDCAD8ULL,
		0x5CB400262D5A5EEAULL,
		0x2E50FB763C224649ULL,
		0x230E731ACC4CA780ULL
	}};
	t = 1;
	printf("Test Case 162\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 162 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -162;
	} else {
		printf("Test Case 162 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8FE59E17AC65D27EULL,
		0x438963953FAC2032ULL,
		0xCA9F8892FCDDF13BULL,
		0x03AEB6053D69BE4AULL,
		0x3A31A71D0384B7E9ULL,
		0x977BB34F2DF7415CULL,
		0x330456994DCB659AULL,
		0x070C601F20AE9AC3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5DD34AC270E1047FULL,
		0x6BCDC608CDF42A35ULL,
		0xF3E1E4D074C8BE28ULL,
		0x8EED965581623A5EULL,
		0x4AA680390EEF8819ULL,
		0x7F26E76DF65135E0ULL,
		0x40DD924DD2E326FAULL,
		0xEA5BAB09BB12B4E0ULL
	}};
	t = -1;
	printf("Test Case 163\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 163 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -163;
	} else {
		printf("Test Case 163 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFE1B9E6B32D4705BULL,
		0x660A6AABD1072124ULL,
		0xE48D667291B9B020ULL,
		0x0ED22C59D1C38073ULL,
		0x050443236AD724F9ULL,
		0x6B37AAA99A2366E4ULL,
		0x685CC2226CDC9749ULL,
		0x6588A0AD677556A2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8A87416759A291A0ULL,
		0x070CA9039F4D763BULL,
		0x798DC05EE06040DAULL,
		0x90FEFD3F80B4FBDDULL,
		0x1CF4B8173EE21600ULL,
		0xC5E5B4D9FFA31F5BULL,
		0x095C3DB0D0EF855FULL,
		0x8ABFA8ADC5F9A3A3ULL
	}};
	t = -1;
	printf("Test Case 164\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 164 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -164;
	} else {
		printf("Test Case 164 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1FD82BD2E0C9CF47ULL,
		0x1B74DA8253E89FD5ULL,
		0x2DF5D4E44199F5DDULL,
		0x091B69C7201E88DFULL,
		0x2A3315A681B92A23ULL,
		0x1C7038878BE16E0BULL,
		0x063B5C3AFA217F33ULL,
		0xF0E623A1B3067787ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1FD82BD2E0C9CF47ULL,
		0x1B74DA8253E89FD5ULL,
		0x2DF5D4E44199F5DDULL,
		0x091B69C7201E88DFULL,
		0x2A3315A681B92A23ULL,
		0x1C7038878BE16E0BULL,
		0x063B5C3AFA217F33ULL,
		0xF0E623A1B3067787ULL
	}};
	t = 0;
	printf("Test Case 165\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 165 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -165;
	} else {
		printf("Test Case 165 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x24C3758F59F2A4D2ULL,
		0x5A19C8B19A0D637CULL,
		0xAB14A08FFED3E430ULL,
		0x738F0BFFC2D074F8ULL,
		0x0261AECB15EA8F48ULL,
		0xB53B0CD4F0640954ULL,
		0xAF1F93E62389EAD6ULL,
		0x92E01CD4F8FCA8E5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4A9F259ECB6F4CB0ULL,
		0x72CA2361B945ADDCULL,
		0x65CDA6AD73F9F078ULL,
		0x2EF732D024E2DDB4ULL,
		0x07AEC3F7E0BB620DULL,
		0xF8693A741318E1C2ULL,
		0x8043C43865350420ULL,
		0x6CA120D8957D7F84ULL
	}};
	t = 1;
	printf("Test Case 166\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 166 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -166;
	} else {
		printf("Test Case 166 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x744390A482DFFE38ULL,
		0x2F2D84E4F314EDC6ULL,
		0x90661E3DE30CBEF7ULL,
		0xC71663CC8F07F4E2ULL,
		0xF5CAC2777B411284ULL,
		0x6B9653E5EEE0A5A8ULL,
		0x49CA4F4C0FD8FA04ULL,
		0xEB33A8BC1DB23C84ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8E091E8FEB65AC6BULL,
		0x04C75AF10BE12F46ULL,
		0x5FC44E629DA0EFC4ULL,
		0x79D41856618941ACULL,
		0x0D94F2FD7BE11925ULL,
		0xEDC5D206311EAC3FULL,
		0x3B022ADCCEE58A87ULL,
		0xD1DDBB74FE920BB9ULL
	}};
	t = 1;
	printf("Test Case 167\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 167 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -167;
	} else {
		printf("Test Case 167 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x392625C549B59391ULL,
		0xF1C5F71B4C7FDE8AULL,
		0xBE402BF9B16936F4ULL,
		0x183869FCADDBEB51ULL,
		0x08B3E9264F6116EEULL,
		0x872511F63BC0F6F6ULL,
		0x95B34BBDC5DAB319ULL,
		0x0A7C76D7EFD9B17CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA77EEFD336933610ULL,
		0xBFB661A6853B879BULL,
		0x0A6642B3984C0476ULL,
		0x297E663880A7B1D8ULL,
		0x84F5AD5F43F93897ULL,
		0x590F0940751201CEULL,
		0x6C4A5124419CCA8BULL,
		0x82DD553B7CDE516FULL
	}};
	t = -1;
	printf("Test Case 168\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 168 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -168;
	} else {
		printf("Test Case 168 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFB86778F555D44A6ULL,
		0x834E0F153B094D1AULL,
		0x74DFA38C4DB1FAD9ULL,
		0x4306281CA82CE018ULL,
		0x8EBC39761C112F5BULL,
		0xB51C034DA5A2E7BDULL,
		0x87758765BAF4D4C0ULL,
		0xE5CF9B53D9D5ED87ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFB86778F555D44A6ULL,
		0x834E0F153B094D1AULL,
		0x74DFA38C4DB1FAD9ULL,
		0x4306281CA82CE018ULL,
		0x8EBC39761C112F5BULL,
		0xB51C034DA5A2E7BDULL,
		0x87758765BAF4D4C0ULL,
		0xE5CF9B53D9D5ED87ULL
	}};
	t = 0;
	printf("Test Case 169\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 169 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -169;
	} else {
		printf("Test Case 169 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC3E76BE2C1B9620DULL,
		0x228AD2A379BDE083ULL,
		0xC659F587F2265C82ULL,
		0x13D75A76EDB68D6FULL,
		0x940AD4B4E49BBEE6ULL,
		0x28F2437971676477ULL,
		0xAFC06FACD6A91AA8ULL,
		0x3B7D9102E052F66BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA8D4BBCF81F9B34AULL,
		0xA1EE88CF1EE5F5E6ULL,
		0x33B826F5988FB13BULL,
		0x3519ACAEC239756EULL,
		0x087388DAD8240820ULL,
		0x1E31F1DF3386710AULL,
		0x2F98DAB7E475D51CULL,
		0xA818AB76629D744EULL
	}};
	t = -1;
	printf("Test Case 170\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 170 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -170;
	} else {
		printf("Test Case 170 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF56E23F0B953FED4ULL,
		0xAC2B5D5A31414F3FULL,
		0xED9564FD8300C3C4ULL,
		0x028EE5C5BD72FA0DULL,
		0x3CF5431891513019ULL,
		0x52917BCC00E1FAA1ULL,
		0xCA2F221EF947C501ULL,
		0x2D9E14AAA1D789A3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x472E4CBBA0148B8DULL,
		0x1E89DE2A9FD9AA20ULL,
		0x063703AA68288863ULL,
		0xD61E77604099498AULL,
		0x85C7747953C4C77FULL,
		0x8D9E5A289D162B64ULL,
		0xB2CD8F96E64EEA90ULL,
		0x0DFFF3C5B2643E18ULL
	}};
	t = 1;
	printf("Test Case 171\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 171 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -171;
	} else {
		printf("Test Case 171 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7F3967E0FF9803A8ULL,
		0x4C4A918521CCDAFEULL,
		0x275F278D2D71943EULL,
		0xCCC412F1A1F631E3ULL,
		0x027701FCA9063857ULL,
		0x4D83FA8DF042BA12ULL,
		0xD33E1E7270727B33ULL,
		0x491CF75150BDFD40ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5E82004E955CAC94ULL,
		0xC3BA21E38AD8F661ULL,
		0x11F1611A46C35B3AULL,
		0x8FC2100111596456ULL,
		0x2C311FF631841BB6ULL,
		0x470D098B4E1E158BULL,
		0x434A1D4B8F59912CULL,
		0xDD438C2160C2FCC8ULL
	}};
	t = -1;
	printf("Test Case 172\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 172 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -172;
	} else {
		printf("Test Case 172 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x67622B3CCEA4663CULL,
		0x2E43F519B4D1067FULL,
		0xB8602DD71EE528D0ULL,
		0xC854221183B43D46ULL,
		0xA13587D48416C9C3ULL,
		0x3DF8FF923C6991CCULL,
		0x36B11139C275E5B3ULL,
		0x3C1FCEBA8DB51626ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x67622B3CCEA4663CULL,
		0x2E43F519B4D1067FULL,
		0xB8602DD71EE528D0ULL,
		0xC854221183B43D46ULL,
		0xA13587D48416C9C3ULL,
		0x3DF8FF923C6991CCULL,
		0x36B11139C275E5B3ULL,
		0x3C1FCEBA8DB51626ULL
	}};
	t = 0;
	printf("Test Case 173\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 173 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -173;
	} else {
		printf("Test Case 173 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB04CF97800AB80F5ULL,
		0xFF702EAAE06415DDULL,
		0xA8B3F6D03F6B415AULL,
		0x7490203F247CFD1CULL,
		0x9EC339B7247B8A8BULL,
		0xAA17819543062F48ULL,
		0xF93E40680C0C86BAULL,
		0xFA6DA6047D16A977ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x64FDF6B178F05F6BULL,
		0x854850CD7D6ABC6CULL,
		0x76E12FD085501286ULL,
		0x71FD78934C7AC191ULL,
		0x5F06559EEDAA0054ULL,
		0x58AEC73BD469445FULL,
		0x13F2BCA7B119032CULL,
		0x4FD213F918E5D8FDULL
	}};
	t = 1;
	printf("Test Case 174\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 174 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -174;
	} else {
		printf("Test Case 174 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0081589E91D80E91ULL,
		0x19D5F5D6EFE04404ULL,
		0x6818B9481BA9A9F5ULL,
		0x68DFB52AC6E25888ULL,
		0x2ADAF34DB103CD0DULL,
		0x283853889D3C1871ULL,
		0x8538DE408C181B94ULL,
		0x87CB1C7B8259EBF4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0967132A2B85168AULL,
		0xD4A88207466D5572ULL,
		0xB580556659B5A09EULL,
		0x150DD7CC55AE119AULL,
		0x492D5D84E3661026ULL,
		0x4DC2214F60C201F2ULL,
		0x8086A7BA2502E8A3ULL,
		0xEA3033D93FB87D94ULL
	}};
	t = -1;
	printf("Test Case 175\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 175 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -175;
	} else {
		printf("Test Case 175 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE9A4EDDAEB3CE2DFULL,
		0x31AFAC431FEAEC69ULL,
		0x3CEC8FF7D572EE85ULL,
		0x0F639BF1842FF367ULL,
		0x28664CA00E0A6B3AULL,
		0xFA23CA6DDA0B3E0BULL,
		0xAF7EDAC1D3B42F4EULL,
		0x8316E0681129A1A3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB9BE1F84EB2E823BULL,
		0xD873440AF758951EULL,
		0x5E8B6A95B55DFC57ULL,
		0x5609BCEFE9AD635AULL,
		0x8B94F6084F2B40E8ULL,
		0x6EE0659005DF34ADULL,
		0xA5DAC06199E57A8CULL,
		0x768D9638338D6691ULL
	}};
	t = 1;
	printf("Test Case 176\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 176 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -176;
	} else {
		printf("Test Case 176 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0043920ED87AE059ULL,
		0xAE702823E722F30FULL,
		0x6B9D9409EF2C640DULL,
		0x0CE90CC4100FAF21ULL,
		0x2F8F6074B1D56C8EULL,
		0x8308B0A49FE1D16EULL,
		0x543350FEA9FFD321ULL,
		0x6A43C5079626EEA0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0043920ED87AE059ULL,
		0xAE702823E722F30FULL,
		0x6B9D9409EF2C640DULL,
		0x0CE90CC4100FAF21ULL,
		0x2F8F6074B1D56C8EULL,
		0x8308B0A49FE1D16EULL,
		0x543350FEA9FFD321ULL,
		0x6A43C5079626EEA0ULL
	}};
	t = 0;
	printf("Test Case 177\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 177 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -177;
	} else {
		printf("Test Case 177 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2F226C5B9DC396E5ULL,
		0x7D6B1975897DA4D2ULL,
		0x3C15ACF2A4BBD5FFULL,
		0xE81FD09B6C3DF32CULL,
		0xDADC0BFFD57C0CBBULL,
		0x42A7125893E5A78CULL,
		0x3508A20A9EAABE8AULL,
		0x2EB688C24E89E8BFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9835BF15A06AFA3EULL,
		0x46D643B57475B5B8ULL,
		0x4B4C08D72A3A8DF8ULL,
		0xC4FA6CCCF68B329BULL,
		0x81D93294403374FEULL,
		0x2F85D24E83992EB8ULL,
		0x69A1C8B34B54C7CDULL,
		0x06C4D9C2A76C7DC1ULL
	}};
	t = 1;
	printf("Test Case 178\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 178 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -178;
	} else {
		printf("Test Case 178 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC61C104252CEBE35ULL,
		0xFA35A188A8FCAA39ULL,
		0x9E9F6FAF42511638ULL,
		0x6DF564C9068309B0ULL,
		0x1EC44EED0FB346A7ULL,
		0xDD043D26D0420C38ULL,
		0x736B6E363910EF25ULL,
		0x57C83851A4A6F76AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAB3A40ECC10A9CEAULL,
		0x0BD8A194E25AB130ULL,
		0xDA379548E4CF2F04ULL,
		0x16B7B9D1533C190BULL,
		0xD9B112FD1D21157DULL,
		0x0030CF6BE1C6C1DFULL,
		0x2989893E0B1D96A7ULL,
		0xFC2878FF971A42B0ULL
	}};
	t = -1;
	printf("Test Case 179\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 179 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -179;
	} else {
		printf("Test Case 179 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBDA0C6480AFF930DULL,
		0xDEB7B981D2F56C78ULL,
		0x93DCBA7994106207ULL,
		0xA41CAE051AB3BA72ULL,
		0xD461C8D07A491C87ULL,
		0x5147F6FA2D316387ULL,
		0x0440E7D49E648537ULL,
		0x7D17D8AA97736B92ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAA964C68AC477BBFULL,
		0xBFD3BC5A61ACF448ULL,
		0xAC658030CDDF40D7ULL,
		0xC8EEC930E812F7C3ULL,
		0x5FE7CFEC745D599FULL,
		0x42AFA8B0964187EDULL,
		0x5127D10217732AC6ULL,
		0x02DA6D708F30A902ULL
	}};
	t = 1;
	printf("Test Case 180\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 180 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -180;
	} else {
		printf("Test Case 180 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD825B973955B040FULL,
		0x1991293D444D98D2ULL,
		0xD6CC97545AA41E72ULL,
		0xEF463486FC6BF688ULL,
		0xEFD922F5C0D6F643ULL,
		0xA4A7EFC87C1E5842ULL,
		0xB0F3086D8E1B0728ULL,
		0x8C7DD49C5C920D7BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD825B973955B040FULL,
		0x1991293D444D98D2ULL,
		0xD6CC97545AA41E72ULL,
		0xEF463486FC6BF688ULL,
		0xEFD922F5C0D6F643ULL,
		0xA4A7EFC87C1E5842ULL,
		0xB0F3086D8E1B0728ULL,
		0x8C7DD49C5C920D7BULL
	}};
	t = 0;
	printf("Test Case 181\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 181 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -181;
	} else {
		printf("Test Case 181 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x42AA98A6C055F020ULL,
		0x04E4AE3F47EEAB84ULL,
		0x050ED59F0976642AULL,
		0xA0A3D62DB895D0BEULL,
		0x25EA279422B54568ULL,
		0x5690A0095A420781ULL,
		0xC2C1944EEDB28266ULL,
		0xC0D6589DA496CC46ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5236490ADD0EBA73ULL,
		0x56D8EFDB2CD5278EULL,
		0x986A2B32E49FD80EULL,
		0x725FB1E03D310FDFULL,
		0x3F48533AA9091785ULL,
		0xD6239E0326ABC164ULL,
		0x1092B9DB372EAE61ULL,
		0x38B6876490FE86A7ULL
	}};
	t = 1;
	printf("Test Case 182\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 182 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -182;
	} else {
		printf("Test Case 182 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2240264EA71FB84EULL,
		0x12AB1CFE8280DB48ULL,
		0x4C98F436546626BEULL,
		0x0840A1D19080277FULL,
		0xE60872D4B2B41460ULL,
		0xC7241599FC7BF265ULL,
		0xB8BEB7FDA8FB6473ULL,
		0xA52AE05796548936ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2EA488FB21F270D4ULL,
		0xAA9349F335044971ULL,
		0xC149625B75F6F77EULL,
		0x97B57ACBFDB903CEULL,
		0x3B2DEECC43595450ULL,
		0x622A1017A63B41D1ULL,
		0x61BD2283850A61BCULL,
		0x763BA7D612F8A2F8ULL
	}};
	t = 1;
	printf("Test Case 183\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 183 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -183;
	} else {
		printf("Test Case 183 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x820B9A04FFE7C3C4ULL,
		0x1A1E8E24A711C63FULL,
		0x3BBB599AAD5D4149ULL,
		0xE0F580554510A27DULL,
		0xA5EBE0CE43A33EC9ULL,
		0x28DC6E50831E59C1ULL,
		0x2268411949381E4CULL,
		0x1294C3513F1D923DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1ECEC9A1518F9A55ULL,
		0xA9A73FE15DCD66D5ULL,
		0x2F93E2649787D90FULL,
		0x5062BA64754CC486ULL,
		0xBDBB18831EB0BB93ULL,
		0x3458C6A9A0DFA641ULL,
		0xE7372E952C593C2FULL,
		0xB9BE51CBB1FE8741ULL
	}};
	t = -1;
	printf("Test Case 184\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 184 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -184;
	} else {
		printf("Test Case 184 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEDFA3F5CFD9E23B0ULL,
		0xD217BF2A96DD6403ULL,
		0x6693576EBA4A3766ULL,
		0xF729F325199C9AE9ULL,
		0xFCA05BF7A39D0443ULL,
		0x0FCA9B1AD90C4AB5ULL,
		0x35B37CDFD8ECD089ULL,
		0x53B6934932FED026ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEDFA3F5CFD9E23B0ULL,
		0xD217BF2A96DD6403ULL,
		0x6693576EBA4A3766ULL,
		0xF729F325199C9AE9ULL,
		0xFCA05BF7A39D0443ULL,
		0x0FCA9B1AD90C4AB5ULL,
		0x35B37CDFD8ECD089ULL,
		0x53B6934932FED026ULL
	}};
	t = 0;
	printf("Test Case 185\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 185 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -185;
	} else {
		printf("Test Case 185 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE55838831EE5F7F7ULL,
		0x4AE6BAB5D847A54BULL,
		0x290CC1032D3A55ADULL,
		0xE1C6BB0CE24A9728ULL,
		0xB53616DF0DFD2F79ULL,
		0x103AB6B3F61F0CCDULL,
		0xC582B0E5EFCA5DF3ULL,
		0x6DA4148F9C6ACC85ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x94D3267F124A08EDULL,
		0x77A9FF58A52DAABFULL,
		0xEAA6E517BF8251D0ULL,
		0x06608485804C5F7CULL,
		0x31624A94F7EE55B5ULL,
		0x551CD242ED7936EBULL,
		0x1BA59AB3198341EEULL,
		0x3DF37CC53B0D149CULL
	}};
	t = 1;
	printf("Test Case 186\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 186 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -186;
	} else {
		printf("Test Case 186 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC0027960C29E4C3DULL,
		0xC22CEC6FBA7E61C3ULL,
		0x4A529736623499A4ULL,
		0xBC526BF03105A9BCULL,
		0xC098C0C4478546EAULL,
		0x265C9A9D8806F931ULL,
		0xA572AB90826DCA5DULL,
		0xBC34E51431449CF2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x45D3FCB065608B5AULL,
		0x881F03376E8F6179ULL,
		0x73A03918EAA66610ULL,
		0xA0BD41DD54A1CDFFULL,
		0xBA819EE4EE51F0F1ULL,
		0x4F492FAD7BB68570ULL,
		0xD960A4A9A8178471ULL,
		0xF385E321B91E6931ULL
	}};
	t = -1;
	printf("Test Case 187\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 187 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -187;
	} else {
		printf("Test Case 187 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x19284AAEBAB65CA9ULL,
		0xFA3FFB7284C35B13ULL,
		0x8EEF763E6A98E4F3ULL,
		0x9265CA2A6A9DFFAAULL,
		0x5E0B38E3BC2A44E5ULL,
		0xB65C92FFBA10802EULL,
		0xFA60290488E6AC04ULL,
		0xD60C71E91BA6F3DBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3061DEC26AC7749CULL,
		0x6C75EB8712E339A4ULL,
		0xA5B34167AE4DF75AULL,
		0xC529C0DA8FE3AD43ULL,
		0xA88D168F9429924EULL,
		0x6D955C7E147EAB4CULL,
		0x26803ABF5E281146ULL,
		0x631E1D98E05FDB6DULL
	}};
	t = 1;
	printf("Test Case 188\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 188 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -188;
	} else {
		printf("Test Case 188 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9B4B05C7786BA6E0ULL,
		0x0242482CC03115E4ULL,
		0x11E67343313E9780ULL,
		0x52D593358DC1769CULL,
		0x0C51B610443DDC35ULL,
		0x13883B6DB1320190ULL,
		0x20FA4F461D2AB9C5ULL,
		0x3968FC23209A3903ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9B4B05C7786BA6E0ULL,
		0x0242482CC03115E4ULL,
		0x11E67343313E9780ULL,
		0x52D593358DC1769CULL,
		0x0C51B610443DDC35ULL,
		0x13883B6DB1320190ULL,
		0x20FA4F461D2AB9C5ULL,
		0x3968FC23209A3903ULL
	}};
	t = 0;
	printf("Test Case 189\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 189 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -189;
	} else {
		printf("Test Case 189 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9FE1498F6AAC9329ULL,
		0xC9FC2C7A63D4ECE6ULL,
		0x312BF81BB3C233E3ULL,
		0xF56E39A883A84503ULL,
		0xD22E84A8FFE5F943ULL,
		0xB6331648A9A39309ULL,
		0x3698BBA0B17FAEA8ULL,
		0x22DA8EBBBD0C17ABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x61B56CB985EBBF3DULL,
		0x184B4E38E1A35E5DULL,
		0x07115B1CF94876CCULL,
		0x264F58F6DA257EEDULL,
		0xA5D7ECD967A711FBULL,
		0x9B4CCBFD36706847ULL,
		0xD105F97589974F68ULL,
		0x538FB09077D99E84ULL
	}};
	t = -1;
	printf("Test Case 190\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 190 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -190;
	} else {
		printf("Test Case 190 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0AD4C2D1002B9D17ULL,
		0x7A5446959D7511C1ULL,
		0x617E3272FC5EF80BULL,
		0xB2F64EE4BCE09F28ULL,
		0x49018F29E15750ECULL,
		0x556C323B93F9D1F1ULL,
		0xE79B9CA985BC5009ULL,
		0x4828C4E6F6E78D03ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x017D20EAFD381613ULL,
		0xFA5527928AE3748EULL,
		0x9256E93598A76B96ULL,
		0xC2C1C0D5AAF55FD5ULL,
		0xA71266D91530143CULL,
		0x8D48C53AAAA7FC2AULL,
		0x39E20D79B51CD7FDULL,
		0x0CB5203529ABF6DEULL
	}};
	t = 1;
	printf("Test Case 191\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 191 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -191;
	} else {
		printf("Test Case 191 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x945824CA0F18B3A0ULL,
		0x4FC8199EC765F2F2ULL,
		0xAC2A1F72A108240FULL,
		0xE969A86E8D89BC1BULL,
		0x4D4D37B3C88A763EULL,
		0xB1A9783C3A670F43ULL,
		0x2FACF406F5B82D78ULL,
		0x838E238F2E98AAEEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x966ED312A3B883DAULL,
		0xBB2312019265931AULL,
		0x367B3CA0C10DB812ULL,
		0xA36EA9EC970E270AULL,
		0x42B28EE10CBEDF61ULL,
		0x68C062587E931B49ULL,
		0xF6A890E038EA3B51ULL,
		0x1A838F98639B37FEULL
	}};
	t = 1;
	printf("Test Case 192\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 192 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -192;
	} else {
		printf("Test Case 192 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x36FC548B33C49F01ULL,
		0x64C2474696C6AA25ULL,
		0x3E7BD6AB4E0DC3B6ULL,
		0x33AD2318E5BFA190ULL,
		0xA4F2DC9E4C8BB716ULL,
		0x47EC7729C35AF10AULL,
		0x9C1E7D2B973E75D0ULL,
		0xCFBE210A6B6D1451ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x36FC548B33C49F01ULL,
		0x64C2474696C6AA25ULL,
		0x3E7BD6AB4E0DC3B6ULL,
		0x33AD2318E5BFA190ULL,
		0xA4F2DC9E4C8BB716ULL,
		0x47EC7729C35AF10AULL,
		0x9C1E7D2B973E75D0ULL,
		0xCFBE210A6B6D1451ULL
	}};
	t = 0;
	printf("Test Case 193\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 193 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -193;
	} else {
		printf("Test Case 193 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x81CAF37FEC07E455ULL,
		0xA04A39E17EB5C452ULL,
		0x770DEF5194E53824ULL,
		0xC6B935D1EEFB6C2CULL,
		0xFF3053D3458B5566ULL,
		0x01DC4D0063B17080ULL,
		0x24E8D92127084484ULL,
		0x4BE2F48DD0248645ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4E0C149763551BC6ULL,
		0xC4C3117D3719A387ULL,
		0x60601A5AD2B6D94EULL,
		0x79111652BB586861ULL,
		0xCDEF6CFA12130149ULL,
		0xB323DF6411CA20C3ULL,
		0x93E002543AF955B4ULL,
		0xF08724A0E00EDAF8ULL
	}};
	t = -1;
	printf("Test Case 194\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 194 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -194;
	} else {
		printf("Test Case 194 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x788F3628260F6F0BULL,
		0x0120B5F5487F2A40ULL,
		0xF5B859752624ADA7ULL,
		0xDEC4C05B30E82140ULL,
		0x0B914EC13F9D790CULL,
		0x087341C2EF51E1B8ULL,
		0x749896316884324DULL,
		0xD1D9070AA853E496ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6D8DDF586DEE2BFEULL,
		0xBCE078B942738CE2ULL,
		0x0E45CEBBA00E8BBFULL,
		0xE7E6FD6C81E1E1FFULL,
		0x0ADBDD401FAB95B4ULL,
		0xF30E1BDFF8A92C88ULL,
		0xE9E21E9FAF50FF3EULL,
		0x7B29787EEA8F14AEULL
	}};
	t = 1;
	printf("Test Case 195\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 195 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -195;
	} else {
		printf("Test Case 195 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE3766A8ACCB74007ULL,
		0x097DF3B9FD6553C4ULL,
		0x116680284027D9A8ULL,
		0x244EB393BE322E9CULL,
		0x6E44869D8A45AA11ULL,
		0x712CB7C8FA43CE1CULL,
		0xBAF76E841ED99A4CULL,
		0x4E6D0A6CF6E8B10CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD9120DF60C96C76DULL,
		0x6C05AD0CBE5151BAULL,
		0xE3D75ECB56023246ULL,
		0x335AFF1E5E75434AULL,
		0x0674984A18852D0AULL,
		0x4DAD1EC72BBBD23EULL,
		0xEBD5F275CA8D5002ULL,
		0xB9F6CA1114641E06ULL
	}};
	t = -1;
	printf("Test Case 196\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 196 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -196;
	} else {
		printf("Test Case 196 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x45243EEECBF5F3F2ULL,
		0x6ABFBB8989BE0EB5ULL,
		0xCBD78811CAF2CA53ULL,
		0xCB5ACAF325CB9116ULL,
		0xEEE2CF265B7502A1ULL,
		0xF5CFE4B81AB8CAF3ULL,
		0x6F13E6D1E3EE2FBAULL,
		0x258CD1359C71270CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x45243EEECBF5F3F2ULL,
		0x6ABFBB8989BE0EB5ULL,
		0xCBD78811CAF2CA53ULL,
		0xCB5ACAF325CB9116ULL,
		0xEEE2CF265B7502A1ULL,
		0xF5CFE4B81AB8CAF3ULL,
		0x6F13E6D1E3EE2FBAULL,
		0x258CD1359C71270CULL
	}};
	t = 0;
	printf("Test Case 197\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 197 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -197;
	} else {
		printf("Test Case 197 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x83E87E9A42AE805AULL,
		0x3FDB8CD08DE37B42ULL,
		0x04AEDC6B7F71D3BAULL,
		0x663C85239B58F9E6ULL,
		0x8FF4D40B2FE29024ULL,
		0x5A5E85EB7EF00DBBULL,
		0x388400EA74857DE5ULL,
		0xDC9FE7CB26FFAB6FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8F6F07ABB3B4C800ULL,
		0x1F2984C197015DEEULL,
		0x70BB1F59E3376935ULL,
		0x9C216D9B4C170D91ULL,
		0x5A5677E9F6238186ULL,
		0xC50FFD8A6210D412ULL,
		0xE216B1E7090ECD28ULL,
		0xC903B6AECBC68A88ULL
	}};
	t = 1;
	printf("Test Case 198\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 198 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -198;
	} else {
		printf("Test Case 198 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x47CA155C8B3AC917ULL,
		0xECA22D9507AEFE8BULL,
		0x10C0B0F908CA834CULL,
		0xD312499AF9A32273ULL,
		0x3A3E51E85ED6B5C5ULL,
		0x8224B6A5D612B9C3ULL,
		0x033F6F2EB0AC9C65ULL,
		0xD11B8009E188128EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x59D90A1CF0D12A00ULL,
		0xA36F15E755E10D4BULL,
		0xCBEB6E96E0447516ULL,
		0xA83406164E452C59ULL,
		0x3F7B7CFB54DE7FA4ULL,
		0x09DDA6EEAB82870BULL,
		0x3DF9BD341493D90BULL,
		0x3E20BB34BC92ED7BULL
	}};
	t = 1;
	printf("Test Case 199\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 199 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -199;
	} else {
		printf("Test Case 199 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCB2F4302E35AB7BAULL,
		0x5FF497ECA4B30043ULL,
		0xFD40A59A75CC995BULL,
		0x02980659EF183939ULL,
		0x5D478F6803AB1CEFULL,
		0x89707CD4415BF39BULL,
		0x77F8AB12E75AFEE2ULL,
		0xA29EAF38FE38F7FCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3D86C8D59B4BBC79ULL,
		0x9784491F7C82FE95ULL,
		0x8FC7C5B7A7087FD9ULL,
		0x4629A4F91B0F75C9ULL,
		0xC7D4C21BE33F4E60ULL,
		0x9E9E18767D794F9EULL,
		0x469C51BC31CCA305ULL,
		0x2807BEF21CA5E11EULL
	}};
	t = 1;
	printf("Test Case 200\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 200 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -200;
	} else {
		printf("Test Case 200 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x98BB21D43D814F34ULL,
		0xE223356071FBEC08ULL,
		0x5C9A97A33C918217ULL,
		0x9140EB584F39EDC1ULL,
		0xA2E502C608F9FBC2ULL,
		0x30B7C0ACAF503054ULL,
		0x8EF6D83469D2AA0AULL,
		0xC847B6CAF275062CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x98BB21D43D814F34ULL,
		0xE223356071FBEC08ULL,
		0x5C9A97A33C918217ULL,
		0x9140EB584F39EDC1ULL,
		0xA2E502C608F9FBC2ULL,
		0x30B7C0ACAF503054ULL,
		0x8EF6D83469D2AA0AULL,
		0xC847B6CAF275062CULL
	}};
	t = 0;
	printf("Test Case 201\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 201 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -201;
	} else {
		printf("Test Case 201 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3F0277A622979443ULL,
		0x12772F88675F9069ULL,
		0x0483BDF604306793ULL,
		0xF9548011B46FE694ULL,
		0xA97ED2C20EA1A48EULL,
		0xE24DA2643780BA46ULL,
		0x6BBAB5CE0F8899B1ULL,
		0x4F83B308FD9A485CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0D19C83019507AE5ULL,
		0xD4A380F7E994457AULL,
		0x5FF12AA4B3FDDF4CULL,
		0x10E07FEB265F8AFFULL,
		0x6FAD9558FE8957EAULL,
		0x3BCADF838370E261ULL,
		0xF9C17243E85ADD89ULL,
		0xDD9422929534039FULL
	}};
	t = -1;
	printf("Test Case 202\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 202 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -202;
	} else {
		printf("Test Case 202 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2519095351DC25B9ULL,
		0xC031C3AE223A7F18ULL,
		0x188BDCEFC6DAEAA5ULL,
		0xF3EA76984863D0A4ULL,
		0x39E88E85E90EBAB8ULL,
		0x79B25E5A7B6B701DULL,
		0x9FC1409689A11B12ULL,
		0xD012AFE9F2008B66ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3BA1FC2A2229B470ULL,
		0x9367501EAD3FAB60ULL,
		0x097A9CE5F85AF31EULL,
		0xB849B6840955706CULL,
		0x5DBEEBF27C3A25A3ULL,
		0x01CCF8902675F1A6ULL,
		0x496378F5E03AC5D8ULL,
		0xDE324AFF1775C3C2ULL
	}};
	t = -1;
	printf("Test Case 203\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 203 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -203;
	} else {
		printf("Test Case 203 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC1E3FA34204CA31AULL,
		0xC5A9A823650AC2A3ULL,
		0x711B4EC35E04138EULL,
		0xB65BCEC909C79FAEULL,
		0xD5E8DEF2D0DA4ACBULL,
		0x9BB40022A1B87696ULL,
		0xDD9B7A39CB02564EULL,
		0x2B9B71CC3A9137E3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1056844B5ACF4394ULL,
		0xD0E663B05A80EE19ULL,
		0x5B2690E071ACC818ULL,
		0xA68994114DFE9BC2ULL,
		0x7674CC38C8F1D05CULL,
		0xE31BA23A00C6CEA8ULL,
		0x7E6D10FC2724CD98ULL,
		0xB951F7F793460168ULL
	}};
	t = -1;
	printf("Test Case 204\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 204 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -204;
	} else {
		printf("Test Case 204 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x48A7F89D5892980CULL,
		0x5044120460479DFBULL,
		0xF265AAA31B44C248ULL,
		0xFF82F99B537FAB2AULL,
		0x13D8D24796D65F8BULL,
		0x0F46AC9FC9B12CE1ULL,
		0x54FAE9A7481672FBULL,
		0xA46308C5C9A680D3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x48A7F89D5892980CULL,
		0x5044120460479DFBULL,
		0xF265AAA31B44C248ULL,
		0xFF82F99B537FAB2AULL,
		0x13D8D24796D65F8BULL,
		0x0F46AC9FC9B12CE1ULL,
		0x54FAE9A7481672FBULL,
		0xA46308C5C9A680D3ULL
	}};
	t = 0;
	printf("Test Case 205\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 205 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -205;
	} else {
		printf("Test Case 205 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDCDAE6FC11AF7C6CULL,
		0xB1FA21F6820CACFDULL,
		0xDA5C5AC9555E13A6ULL,
		0xF4EE99E21CA7365AULL,
		0xA838FD8F91D082DBULL,
		0x0D61B6263022A6DDULL,
		0x80C31498C4156186ULL,
		0x1A0DAC009DF69184ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD5206D0A623BDE96ULL,
		0x996CCDF27E0EFCBEULL,
		0x796E89D6DE2801B1ULL,
		0x0F5150DF63E73EB7ULL,
		0x4267DB805378DD0AULL,
		0xBD3C5476B5EDDD2CULL,
		0x08F73A0E205B0B55ULL,
		0xCAD4725240E9F5EFULL
	}};
	t = -1;
	printf("Test Case 206\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 206 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -206;
	} else {
		printf("Test Case 206 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCC3378BE100CE4E2ULL,
		0xEB2042F195A34D4CULL,
		0xFD2B3AC73C5CC56FULL,
		0xD350F94729C44219ULL,
		0xD9DBE94EA6217A60ULL,
		0x6D9818100BFC72B6ULL,
		0xA201B576C1642811ULL,
		0x6198E7509EB8E6C6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCF04BB2B764FB40DULL,
		0x3D28DF8BF1140464ULL,
		0x4D72B466B5D7D40AULL,
		0x2779E6BBC6E0A6DFULL,
		0x5C551BCA415019E2ULL,
		0x8C6CEAA36A2DA84CULL,
		0x8B5E440E5FD98AD6ULL,
		0xF1BBD807ADC02E14ULL
	}};
	t = -1;
	printf("Test Case 207\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 207 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -207;
	} else {
		printf("Test Case 207 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x695327ED07E89C0CULL,
		0xADC9C10E067169A2ULL,
		0xA6571301A95A24B9ULL,
		0x7B4FDA8616A35699ULL,
		0xB3F72C8C40A42980ULL,
		0x45963DD0BDF58B96ULL,
		0xF736BAF611687D65ULL,
		0x3A0B7E6B022D8837ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4E461ABAF10FDD3DULL,
		0x1A257A1CCEDE5C58ULL,
		0x37503C5235BF1ACEULL,
		0xC9473F7EB92C7126ULL,
		0x4AEBE291328D0993ULL,
		0xEC97C6803622C730ULL,
		0x5778FAEDFFD9D759ULL,
		0x6FAE9E21CB216C10ULL
	}};
	t = -1;
	printf("Test Case 208\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 208 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -208;
	} else {
		printf("Test Case 208 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x851C08B45B9AE674ULL,
		0x4FF0D14DC1F16B9FULL,
		0x897037F7BDBFFF38ULL,
		0x9C431B7E1B6F78F4ULL,
		0xD73412558789B922ULL,
		0x136C6561FC4AA823ULL,
		0x8ACCC47AFC88EB12ULL,
		0x89C3EE453D1EBC70ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x851C08B45B9AE674ULL,
		0x4FF0D14DC1F16B9FULL,
		0x897037F7BDBFFF38ULL,
		0x9C431B7E1B6F78F4ULL,
		0xD73412558789B922ULL,
		0x136C6561FC4AA823ULL,
		0x8ACCC47AFC88EB12ULL,
		0x89C3EE453D1EBC70ULL
	}};
	t = 0;
	printf("Test Case 209\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 209 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -209;
	} else {
		printf("Test Case 209 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC3F75D3C72A90ABAULL,
		0x0780E4A81563BC3AULL,
		0xEFAC2406AEB7B2D4ULL,
		0x09588C857C973D75ULL,
		0xDAB84776BCE17E23ULL,
		0x544E422E573F60BAULL,
		0x447C37A8DFC2C9DCULL,
		0x2B039874291E71C1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF48734892B0DC1DEULL,
		0x42245FB42B22BD25ULL,
		0x51FC1D11E81221D9ULL,
		0x51476145C890438FULL,
		0xE9C0D30EC1C8183DULL,
		0xCDB568F3D9603037ULL,
		0x13DA0810B31DA674ULL,
		0x7AB1829490465BCDULL
	}};
	t = -1;
	printf("Test Case 210\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 210 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -210;
	} else {
		printf("Test Case 210 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEA468F5C38672CE7ULL,
		0x737789822FDC4E8EULL,
		0xEAFFD6A380DD31E2ULL,
		0x3A985E11A4E87101ULL,
		0x9B4C508D1015144EULL,
		0x871A0EE6CF586EF4ULL,
		0x3CEA82983989842AULL,
		0xCAE71784F7E2CEBBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFF438FC27E822711ULL,
		0x0058625714746201ULL,
		0xB072675947C79793ULL,
		0x847CD262CAE87460ULL,
		0x3A39725EFCB01375ULL,
		0x7460F2F3E4083B1AULL,
		0xF0AAF217782E3C51ULL,
		0xA34821504A55D0DFULL
	}};
	t = 1;
	printf("Test Case 211\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 211 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -211;
	} else {
		printf("Test Case 211 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4FAB781B175DA4FDULL,
		0xDB09E467CCF5B1F3ULL,
		0x10FC9413F85DF38BULL,
		0x59787535EAE923A3ULL,
		0x126B3774FB94777EULL,
		0x16269D1382FE77BFULL,
		0xB60816D610100BA3ULL,
		0x123CFFC00BA89B3AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1FA7FF5EBCA7AC38ULL,
		0x9D15E7F09E59D74CULL,
		0x2123864189491C2CULL,
		0x69538C06363F461AULL,
		0x6C1DB07E1212D6B2ULL,
		0x7D1ED698861F8B99ULL,
		0x7CBB66F2128519EAULL,
		0xFEE06ABEDFBAA8F7ULL
	}};
	t = -1;
	printf("Test Case 212\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 212 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -212;
	} else {
		printf("Test Case 212 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x736CCF54E187040FULL,
		0xE3C1C06F1C532CE7ULL,
		0xFF9F13939B7D761DULL,
		0x6A748FA48FFAA2E1ULL,
		0xBAB3709DD8B1B26EULL,
		0x05386AF09B67FBE0ULL,
		0x1BDEBE8653779309ULL,
		0xE6ADDFA1D8680359ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x736CCF54E187040FULL,
		0xE3C1C06F1C532CE7ULL,
		0xFF9F13939B7D761DULL,
		0x6A748FA48FFAA2E1ULL,
		0xBAB3709DD8B1B26EULL,
		0x05386AF09B67FBE0ULL,
		0x1BDEBE8653779309ULL,
		0xE6ADDFA1D8680359ULL
	}};
	t = 0;
	printf("Test Case 213\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 213 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -213;
	} else {
		printf("Test Case 213 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1C5705A0CAFC4C06ULL,
		0x611A03DFFD24DEC8ULL,
		0xA4E5BACF1EDC88EDULL,
		0x0CF41AE3EE701767ULL,
		0x9512A67DEB6ED0D6ULL,
		0x5B0FA82ED9DFBE7BULL,
		0xB92F33BF5F12F2AAULL,
		0xA65C77D239EE5444ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x13C7B93F11942D56ULL,
		0xEF3CC9C61A0DEE2BULL,
		0x5F2E65D7D60B7EECULL,
		0xE86960D02602DA34ULL,
		0xFD7B5C0FDFB91F86ULL,
		0x0886D3E81CAD3C21ULL,
		0xD151941B83660C4DULL,
		0xDE1066EFAB12F28BULL
	}};
	t = -1;
	printf("Test Case 214\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 214 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -214;
	} else {
		printf("Test Case 214 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD616E35ED1634915ULL,
		0xD7E54198E7646379ULL,
		0x4C4F0F670D0B90EEULL,
		0x6962C818733844F1ULL,
		0x8618062F646264BEULL,
		0x0E4468CD2A45984AULL,
		0xC7212365FF78E155ULL,
		0xCBEBBAD00CB0648AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x23A833584B408900ULL,
		0x8D11BBE3CDF4C2E7ULL,
		0xF34317B75B416183ULL,
		0x0E18252E7E0FCB1FULL,
		0x1B8C80C8B75913D6ULL,
		0xAB2848CE350CC024ULL,
		0x309E780D531468B2ULL,
		0xE52AA3C1A7C6056FULL
	}};
	t = -1;
	printf("Test Case 215\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 215 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -215;
	} else {
		printf("Test Case 215 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1852EE5B8007BE6BULL,
		0xDEA18FC1E90A9087ULL,
		0xAB8E18CD1C6B69C0ULL,
		0xC4A2164FD1716830ULL,
		0x445641A877E35E9BULL,
		0x6A6351953822F815ULL,
		0xB39EA4EB4536A825ULL,
		0xAFBBFB5946B5833AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9FCFA42F33B6133EULL,
		0xE53CA19DD6ABED41ULL,
		0x7611323EFC3D7819ULL,
		0x0E060AD6037BB595ULL,
		0xFAB2BA2311875192ULL,
		0xD04E40D38606EF65ULL,
		0x75F2C623073C714DULL,
		0xFD1B6A312D0AD7ABULL
	}};
	t = -1;
	printf("Test Case 216\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 216 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -216;
	} else {
		printf("Test Case 216 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAD31F0570A9A1321ULL,
		0x9BC6125F3A90C14AULL,
		0x43B8849B70F5FE7CULL,
		0xEDEBCD00A62901E1ULL,
		0xE5B96006E14B3747ULL,
		0x803C5C6B3A52BA77ULL,
		0xCB83D1E7967F0E0DULL,
		0x28D6EBB017E45A58ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAD31F0570A9A1321ULL,
		0x9BC6125F3A90C14AULL,
		0x43B8849B70F5FE7CULL,
		0xEDEBCD00A62901E1ULL,
		0xE5B96006E14B3747ULL,
		0x803C5C6B3A52BA77ULL,
		0xCB83D1E7967F0E0DULL,
		0x28D6EBB017E45A58ULL
	}};
	t = 0;
	printf("Test Case 217\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 217 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -217;
	} else {
		printf("Test Case 217 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x390A1140797E49C8ULL,
		0xDDC7143A6CCAF306ULL,
		0xD960D96B42598C69ULL,
		0x4BB809F5C48ED0BCULL,
		0x12AF1F5B9DDE739CULL,
		0x2D780460E912499EULL,
		0x079AE9F13E3AB0A8ULL,
		0xA6155728C2DD3129ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFC183EBC1EF6A1C8ULL,
		0xBB95DE222F1B28E5ULL,
		0x6873D7CD8ABC0DD0ULL,
		0x83973EF6E799E5C1ULL,
		0xA8121B3D97A638DFULL,
		0x20876DDF414FA138ULL,
		0x40F73E53218B4E4BULL,
		0xACDC5A3E678BC8A7ULL
	}};
	t = -1;
	printf("Test Case 218\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 218 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -218;
	} else {
		printf("Test Case 218 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC964858302045809ULL,
		0xBDA31C48CB78E8C2ULL,
		0x3272B4FF20C5D4F6ULL,
		0x0EC4FFA44045F079ULL,
		0xF775FFB8E5C0798EULL,
		0x213686012F056BEFULL,
		0x3DCDD9D5E36817D8ULL,
		0x5D1E06566CB421A0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7F2A6B6DB72FFE3BULL,
		0xACF63771AAFAB5B9ULL,
		0xF2B8D0CB95C2756BULL,
		0xC90FA37F033CDEC5ULL,
		0xDB9C089D22A9B3B6ULL,
		0xB99D0782415E5C08ULL,
		0x98E221D690F8ED31ULL,
		0x5DEACFA4189CC9F7ULL
	}};
	t = -1;
	printf("Test Case 219\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 219 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -219;
	} else {
		printf("Test Case 219 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCD6691DA7D62BD17ULL,
		0xD1CC73F4744543E8ULL,
		0x6882F043A6485B41ULL,
		0xE7B10E2264E4021DULL,
		0x06498A0A442099F7ULL,
		0xDE6C43AFBAC869B8ULL,
		0x6FD4B3578D1AD65FULL,
		0xFE52522FF1DA84E6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAC8396A81BBF1B23ULL,
		0x54CD13E6D45E2B2FULL,
		0x4383F43BB8C32700ULL,
		0x1FAD5664DCE55858ULL,
		0x3C3F553E56C27D98ULL,
		0xB0AFA5DBEC694AA7ULL,
		0xEBBBCEC139D4F8C5ULL,
		0x93AA161482968E15ULL
	}};
	t = 1;
	printf("Test Case 220\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 220 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -220;
	} else {
		printf("Test Case 220 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x570933EB8DE2CE76ULL,
		0x18F11980AB6F511DULL,
		0x33E94055C4516731ULL,
		0x3B3ADFB385B59D46ULL,
		0x7B042A6F14060E13ULL,
		0x530B4543D100BE31ULL,
		0x5BB45AFA9F938E6CULL,
		0x50F00AB08240CC64ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x570933EB8DE2CE76ULL,
		0x18F11980AB6F511DULL,
		0x33E94055C4516731ULL,
		0x3B3ADFB385B59D46ULL,
		0x7B042A6F14060E13ULL,
		0x530B4543D100BE31ULL,
		0x5BB45AFA9F938E6CULL,
		0x50F00AB08240CC64ULL
	}};
	t = 0;
	printf("Test Case 221\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 221 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -221;
	} else {
		printf("Test Case 221 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA697ABA59235E9B0ULL,
		0xCB562FC8058CDF27ULL,
		0x72740AC089E03E0FULL,
		0x5ACAF473AEEB36F2ULL,
		0xDD0AD62AD7403774ULL,
		0x17059B215823D0B0ULL,
		0x0D34633685215971ULL,
		0x33E7BB155FEB2B9DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x89D7CED1EF275967ULL,
		0xF55C7A87392CC279ULL,
		0xBC4012D4DDE125A5ULL,
		0xF50A16ACB9368B5BULL,
		0x1449772DDA6D950AULL,
		0x6B5031A0661412B6ULL,
		0x06C23BED4CA2AA79ULL,
		0x12569A1F053DA2B4ULL
	}};
	t = 1;
	printf("Test Case 222\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 222 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -222;
	} else {
		printf("Test Case 222 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4B3F02CF51917CE6ULL,
		0xDA908E4A01F7E41CULL,
		0xE3AC07721C21ACDAULL,
		0x824A8F17BF45AB3AULL,
		0xB3B27514B059B07FULL,
		0xA4316104921E6751ULL,
		0xB5F51DAF7E5CF33CULL,
		0x94B57CC8F2B435D9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x213D7A219FD45BDFULL,
		0x2272E1C1A55D4504ULL,
		0x7F875C25A7F30222ULL,
		0x04E764111BF41A40ULL,
		0xDF8191D79C70C82BULL,
		0xC378A3A3D7BD3E1FULL,
		0xBC1D0C8028B05DCCULL,
		0x4992A1B545CE45EFULL
	}};
	t = 1;
	printf("Test Case 223\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 223 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -223;
	} else {
		printf("Test Case 223 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x70C3658CDDA36CD1ULL,
		0x778FF3C01D47ECEBULL,
		0x700D003B7D8B30A5ULL,
		0x00C760B2579E2110ULL,
		0x04EC0764E899A2ADULL,
		0x7339DFCD4A8D39D3ULL,
		0x95FD9C5CD41E6F03ULL,
		0x9E6F4DAF1D7C89B5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0BBEACFD8B431081ULL,
		0x6320ACCDC58C11D6ULL,
		0x714F33D19B386E22ULL,
		0x9678F62199956651ULL,
		0x60E56ADAAEA19431ULL,
		0x4D51113FE1A68D51ULL,
		0xBE7BE187A7FFEC52ULL,
		0x060BB04D0F7D0C67ULL
	}};
	t = 1;
	printf("Test Case 224\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 224 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -224;
	} else {
		printf("Test Case 224 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB22BA3E29037D47FULL,
		0x856A4D5E66C5D491ULL,
		0x38031C131461270DULL,
		0x738ABC437FF97C5CULL,
		0x16984CE2DC7FD14EULL,
		0xB2D499024CDD5F52ULL,
		0xF3A71FF7E1C3BB1DULL,
		0xC52A906F095C6761ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB22BA3E29037D47FULL,
		0x856A4D5E66C5D491ULL,
		0x38031C131461270DULL,
		0x738ABC437FF97C5CULL,
		0x16984CE2DC7FD14EULL,
		0xB2D499024CDD5F52ULL,
		0xF3A71FF7E1C3BB1DULL,
		0xC52A906F095C6761ULL
	}};
	t = 0;
	printf("Test Case 225\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 225 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -225;
	} else {
		printf("Test Case 225 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1CBE1FFDCBAAF56CULL,
		0x9AD39CA8DD707BC1ULL,
		0x50DD99C5ABC542E4ULL,
		0x8AE13ADC194BFC37ULL,
		0xDDD61AF68A78CE78ULL,
		0x4F3DA250295CA79EULL,
		0x81FB32B3974F8226ULL,
		0xEE767CAFE5BA5BD8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC361620EFE322073ULL,
		0xA23F8243B2882DEFULL,
		0xF10A9F71F21E8BA6ULL,
		0x916D70FDF20002C5ULL,
		0xC6CAE7DCFAE37141ULL,
		0x5D11B07C1186C966ULL,
		0xB332582731C38171ULL,
		0xFC97922C0AB9CC19ULL
	}};
	t = -1;
	printf("Test Case 226\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 226 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -226;
	} else {
		printf("Test Case 226 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2C0CF083643A6215ULL,
		0xBEF1D9C54F66B327ULL,
		0xAB44465B68A472FEULL,
		0xDD00F9819DC43B4DULL,
		0x04B3D2AB0DCF7ABFULL,
		0x58E618566816F05EULL,
		0x68B6D3DC6DCD628EULL,
		0xDD2E246009866968ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFAB53FA231DB7648ULL,
		0xC3F133872A818F25ULL,
		0x171C0B6EC980E2EBULL,
		0x5B2C9E2664C7C88EULL,
		0xFEC84F2F07EC5958ULL,
		0x48A6FE171F5E980BULL,
		0xBA68B6795DC7B754ULL,
		0x73A64766EA121340ULL
	}};
	t = 1;
	printf("Test Case 227\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 227 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -227;
	} else {
		printf("Test Case 227 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD40AF58545DD5C44ULL,
		0xBF977E30A81076B9ULL,
		0x0E934DAC6B2E6639ULL,
		0x5AD19B9B582DF8F5ULL,
		0xD21741C42C46E482ULL,
		0x7DE80CAD7077A52BULL,
		0x8314913E5A304CEEULL,
		0x9459398341658D8EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFFE04ADEC834BDD6ULL,
		0x555A4C88DC046F58ULL,
		0x20F9779B1E47C9D5ULL,
		0x05ED5E5962F8DB27ULL,
		0x185835711368714CULL,
		0x391E346196AF0FEBULL,
		0x9FB8029AF378ECAEULL,
		0x4605318923B4D7ACULL
	}};
	t = 1;
	printf("Test Case 228\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 228 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -228;
	} else {
		printf("Test Case 228 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA4B89178DC75B1C6ULL,
		0xD7CAE7A0411F850FULL,
		0xC0E37922BBBD41B4ULL,
		0xA2D5F6253CBE1B56ULL,
		0x5DBBA0CBC8AF964AULL,
		0xB937FBCA7FA072D8ULL,
		0x5A7041EC8385990CULL,
		0x6C0B229D52DB0ED1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA4B89178DC75B1C6ULL,
		0xD7CAE7A0411F850FULL,
		0xC0E37922BBBD41B4ULL,
		0xA2D5F6253CBE1B56ULL,
		0x5DBBA0CBC8AF964AULL,
		0xB937FBCA7FA072D8ULL,
		0x5A7041EC8385990CULL,
		0x6C0B229D52DB0ED1ULL
	}};
	t = 0;
	printf("Test Case 229\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 229 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -229;
	} else {
		printf("Test Case 229 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x612DB906CF3BE547ULL,
		0xA3A8CD8F8643F5C4ULL,
		0x0CCF9747DE827A97ULL,
		0x54014E7CA131BA61ULL,
		0xC8AC8C3733331A6AULL,
		0xC50EB1FA41FF77B5ULL,
		0x910DF8324D33A00EULL,
		0x629A58F225D05629ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8B5E755F58C0F80DULL,
		0x8E00574991F3C2F6ULL,
		0x49F0ABBB19F5871DULL,
		0x5B3E50BD7B4BD214ULL,
		0x1B0A7C6E4AE3AA9AULL,
		0x3009E3585477FAECULL,
		0x8AAC203A5AB14B83ULL,
		0xF2C0AE019A964A06ULL
	}};
	t = -1;
	printf("Test Case 230\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 230 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -230;
	} else {
		printf("Test Case 230 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9B7ED18461CF3234ULL,
		0x9B3F738E4FBEA15EULL,
		0x2157F402BFEED7ECULL,
		0x81CD2DD8D594DFB8ULL,
		0x209639DE6E3F8DDFULL,
		0x104A993488A56D9FULL,
		0x594019CCAA1E6686ULL,
		0xDD4F200B3F787DD5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF35742D82B018F12ULL,
		0x78FD7AE9F1F2B65AULL,
		0xB871332C2B763090ULL,
		0xFB13C36C6AD4E7C5ULL,
		0xC3E5CE049F83E815ULL,
		0x2B552E16CCBD885DULL,
		0x1F648A09A271C79CULL,
		0xA48F9C0F312C0247ULL
	}};
	t = 1;
	printf("Test Case 231\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 231 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -231;
	} else {
		printf("Test Case 231 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD31DF79281E0CAB3ULL,
		0xF7BC840DCD946FB0ULL,
		0x16DEF7BB5D3C15DFULL,
		0x733F75820E8DED91ULL,
		0xF502917974C2DE42ULL,
		0x181FA5006F2253CEULL,
		0xF09B0AD654186638ULL,
		0xF473F2A120193A11ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE94320F3E2E0252AULL,
		0x86EC6725E3AF7E4DULL,
		0x7C9327F88B7849F2ULL,
		0xFDC756EAECFCB647ULL,
		0x1F78ACADE2E9BDA7ULL,
		0x168C905413863314ULL,
		0x90F3EBFFF81D7A66ULL,
		0xAA5CFB0432D22BFAULL
	}};
	t = 1;
	printf("Test Case 232\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 232 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -232;
	} else {
		printf("Test Case 232 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF2306EBA34E246A6ULL,
		0x883A2EDC96C2FE47ULL,
		0x85D62A857A4EF83EULL,
		0xF2950A8BB3A52A03ULL,
		0x8944D912E4A8628CULL,
		0xA2934C6A55F652A4ULL,
		0xB229341B66EA3C2EULL,
		0x5557E00D3CA3633BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF2306EBA34E246A6ULL,
		0x883A2EDC96C2FE47ULL,
		0x85D62A857A4EF83EULL,
		0xF2950A8BB3A52A03ULL,
		0x8944D912E4A8628CULL,
		0xA2934C6A55F652A4ULL,
		0xB229341B66EA3C2EULL,
		0x5557E00D3CA3633BULL
	}};
	t = 0;
	printf("Test Case 233\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 233 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -233;
	} else {
		printf("Test Case 233 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCEBD214C63951620ULL,
		0x0D7B513BEDB61A69ULL,
		0x007D7172DD0EF0CDULL,
		0x3DE53ED36C30A5D9ULL,
		0x404704613575A43FULL,
		0xBC5CB0D877DBEB93ULL,
		0xE77C8E63FD620D38ULL,
		0x1960650A3031875FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1081BF308B699486ULL,
		0xFE583037F3D4ADAEULL,
		0x4352948E40158230ULL,
		0xFCC56DA0876F8EC9ULL,
		0x4736C89629385F73ULL,
		0x2C0A3C247F11F787ULL,
		0x8DF033BAC879C295ULL,
		0x2FE6477D39B12EC7ULL
	}};
	t = -1;
	printf("Test Case 234\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 234 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -234;
	} else {
		printf("Test Case 234 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF4A408A016C2EC0AULL,
		0x0C3981545EFA5CEBULL,
		0x2F0D4D79A0EFD186ULL,
		0x6D80F8921B34B905ULL,
		0x7EC8EE3FF9B2CEF8ULL,
		0x9383C888555CA87AULL,
		0xD2F46B0DD08873F6ULL,
		0xE94662CF21288351ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9CF42B8171413D05ULL,
		0x6C70C2633B3BF62FULL,
		0xFCA7D04624EE6C8AULL,
		0x4B7605E82F45ED35ULL,
		0x1DDB4FE8EAF0B54EULL,
		0x6ACEBED86AC0541DULL,
		0xE0B8DEE57CA3BC00ULL,
		0xECD26524AA16F538ULL
	}};
	t = -1;
	printf("Test Case 235\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 235 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -235;
	} else {
		printf("Test Case 235 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBCACD1963CC29EAAULL,
		0xDE8800CE2AC55250ULL,
		0xE9C636C998BCC4B7ULL,
		0xDEEFD4DEC44C85E7ULL,
		0x1C3CC3D7D1F7EA20ULL,
		0xAD2C521B6EB1F1DBULL,
		0x4B900F054CFBE488ULL,
		0xD1D7C43005E767F7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBBA89843E19276EAULL,
		0x58178223110D0361ULL,
		0xA044AE79E423F63FULL,
		0xAD656C93C9659945ULL,
		0x38F9BEBC82D7C9F9ULL,
		0xA0812881D3EF369FULL,
		0x18C3432F2A7CA220ULL,
		0x7221EC66390BDE86ULL
	}};
	t = 1;
	printf("Test Case 236\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 236 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -236;
	} else {
		printf("Test Case 236 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5802304756D5538CULL,
		0xF1A301EAB8A98F1BULL,
		0xDB69E55FF01FA59FULL,
		0xF3755A414D820EE4ULL,
		0x54B141CE7C11573BULL,
		0xC4824A587FCD139EULL,
		0x556C1FE5C1281B2DULL,
		0x447F224A54A7992CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5802304756D5538CULL,
		0xF1A301EAB8A98F1BULL,
		0xDB69E55FF01FA59FULL,
		0xF3755A414D820EE4ULL,
		0x54B141CE7C11573BULL,
		0xC4824A587FCD139EULL,
		0x556C1FE5C1281B2DULL,
		0x447F224A54A7992CULL
	}};
	t = 0;
	printf("Test Case 237\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 237 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -237;
	} else {
		printf("Test Case 237 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5B5C566C3D43B4D5ULL,
		0xC7C671C9AC535006ULL,
		0xAB115FA690D961C5ULL,
		0x2865645C5E2AE902ULL,
		0x07C34B58645544D7ULL,
		0x91E5EC34CBF42560ULL,
		0xBD562C48D7268A85ULL,
		0x6C365B482A24CF6BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5CFB0D3BD9A61698ULL,
		0x2538733F2B1ECC0FULL,
		0x297FBD04050BCEF7ULL,
		0xC4F3168E4927F89CULL,
		0x630F5C248CEAE678ULL,
		0x9175BCA9D8B448EAULL,
		0x9F5B55EBCE4A0FBCULL,
		0x2EFDA40E58D98B74ULL
	}};
	t = 1;
	printf("Test Case 238\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 238 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -238;
	} else {
		printf("Test Case 238 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAF3DDEC96E08A5C1ULL,
		0x4AC5F4B72D7FA155ULL,
		0x23EFEEE23B6282FFULL,
		0x98D06963B3961099ULL,
		0x19722EC880C904CAULL,
		0x204A1B6E214579E7ULL,
		0xCF6268365682C3EEULL,
		0x3F581C0F92BA0B0FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC50DB068A1779A65ULL,
		0x9D2FC23911737CABULL,
		0x65DE1B434AE845E8ULL,
		0x8BB8C534BCD25684ULL,
		0x2C5F3023253E4516ULL,
		0x255747CDA17BA396ULL,
		0x1E629D6C185F04FCULL,
		0x8C71989BD153DBBEULL
	}};
	t = -1;
	printf("Test Case 239\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 239 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -239;
	} else {
		printf("Test Case 239 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4D7B370CF8204F0FULL,
		0xED302D8477888F12ULL,
		0x9E72658F00864A83ULL,
		0xBE92551134DBBB56ULL,
		0xEC438707A5E9C1F0ULL,
		0x5DEC4E89E93C3803ULL,
		0xFFCF04909D628C36ULL,
		0x0F5DE307AAE98100ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6B6F693EC17CEC26ULL,
		0x625EBF128B6EE442ULL,
		0xBC15CFBC8092BC31ULL,
		0xB3D32D79B4AEC006ULL,
		0xE18CFB4BF0173405ULL,
		0x1EDE8E0F3C9198B7ULL,
		0x136C288F49AE20A2ULL,
		0x8CE831A91C7B6FDEULL
	}};
	t = -1;
	printf("Test Case 240\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 240 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -240;
	} else {
		printf("Test Case 240 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD05B142EF19F4ADBULL,
		0x6A514A7AB7C3F025ULL,
		0x182B49F5F5A6B817ULL,
		0x6D84A1067B3AA506ULL,
		0x506DA11CDC679BF7ULL,
		0x35A6C808EB559F34ULL,
		0xBDA0B591EB773A32ULL,
		0x8B9C9FF25568808AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD05B142EF19F4ADBULL,
		0x6A514A7AB7C3F025ULL,
		0x182B49F5F5A6B817ULL,
		0x6D84A1067B3AA506ULL,
		0x506DA11CDC679BF7ULL,
		0x35A6C808EB559F34ULL,
		0xBDA0B591EB773A32ULL,
		0x8B9C9FF25568808AULL
	}};
	t = 0;
	printf("Test Case 241\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 241 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -241;
	} else {
		printf("Test Case 241 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0DC69C0AAD0F319EULL,
		0x4F80B33DEC6C2077ULL,
		0xE98C663D732093EAULL,
		0xDA428FEC064FEFBEULL,
		0xCC68E58BA864F87CULL,
		0x3E5DD7EB2D27A001ULL,
		0x618E287353A11842ULL,
		0xB12AFF5FA3E57E1DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x267B48F5B2E3FB08ULL,
		0x0C0F833F945D187EULL,
		0xD44EC20E6C93995DULL,
		0x1C67419502D6CF48ULL,
		0x35306A8ACFD08C67ULL,
		0xC884C346F7EB5B82ULL,
		0xC502F31E4255F4E2ULL,
		0x3A1B9B3B7638991EULL
	}};
	t = 1;
	printf("Test Case 242\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 242 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -242;
	} else {
		printf("Test Case 242 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8269A887267F4FE3ULL,
		0x3353A868E5DBB3C1ULL,
		0xE41062FB9051DF02ULL,
		0x41743DD74CF40B8CULL,
		0x55AC5867B4EC0A11ULL,
		0x93107C20C266E702ULL,
		0xDAFBD387BD533B8FULL,
		0x3A0BCDE179696AA2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4C15399FB3C93584ULL,
		0xD623686C36FA222AULL,
		0x6F2F1B52F83FDFF3ULL,
		0x7EBAC9553B13FF2AULL,
		0xF4BA8AC3BA679E1EULL,
		0x02D410B29C0634C3ULL,
		0xEA9C927FB6E2FC22ULL,
		0x3F410A076521A1F3ULL
	}};
	t = -1;
	printf("Test Case 243\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 243 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -243;
	} else {
		printf("Test Case 243 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC4E0FCE62B65C906ULL,
		0x3939CD0573174220ULL,
		0xB4CE8A610912245CULL,
		0xE39A755D729FFA18ULL,
		0x3049CD1F8E982FFFULL,
		0x6367D38F9CD7E474ULL,
		0x628C8F31E3432B00ULL,
		0xB3BCEA5E1CA9BCABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x185D050B47AE4312ULL,
		0x31D86C6D6501D7A9ULL,
		0x7D5837588C83C4E9ULL,
		0xED5D81B786FFD20DULL,
		0x6579474482154F21ULL,
		0x5F1612049B15B337ULL,
		0xC25AE7571B816A25ULL,
		0x5ECFD86D60306B46ULL
	}};
	t = 1;
	printf("Test Case 244\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 244 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -244;
	} else {
		printf("Test Case 244 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x56ABF34669FF218BULL,
		0x3CD46BC7F9F0A637ULL,
		0xDE87E052605C6D22ULL,
		0x2FE35EF73D4BE011ULL,
		0xBE83C3D12B76EB87ULL,
		0x5A5F8826D9208CF5ULL,
		0x1E1BB0D3D4C43CB9ULL,
		0x752BA612BD0D0DE7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x56ABF34669FF218BULL,
		0x3CD46BC7F9F0A637ULL,
		0xDE87E052605C6D22ULL,
		0x2FE35EF73D4BE011ULL,
		0xBE83C3D12B76EB87ULL,
		0x5A5F8826D9208CF5ULL,
		0x1E1BB0D3D4C43CB9ULL,
		0x752BA612BD0D0DE7ULL
	}};
	t = 0;
	printf("Test Case 245\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 245 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -245;
	} else {
		printf("Test Case 245 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD0130DE9E286D677ULL,
		0x46284950E87171CBULL,
		0x936CA0B383DB3DE0ULL,
		0xFAA54932511A7193ULL,
		0x0FBE38D0F1EC7D9CULL,
		0x570D42B21B74D616ULL,
		0x5DD95912C5133B65ULL,
		0x9A59A99537BBA856ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x71D45E2BF5667B77ULL,
		0xA9CD6CA9270CDD66ULL,
		0x0C9E78CE735A5E71ULL,
		0x873B6E33842A6611ULL,
		0x1B373E900556AB62ULL,
		0xA6E7845EC2873CC5ULL,
		0x5C32C9000A05D444ULL,
		0x4865A06D178FFF67ULL
	}};
	t = 1;
	printf("Test Case 246\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 246 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -246;
	} else {
		printf("Test Case 246 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x701A706EFDFE9185ULL,
		0xDFB02E6E50DD52CDULL,
		0xC9A1D0CEAD40D55FULL,
		0x910A4A71673A8779ULL,
		0xEE74625A00B4AA79ULL,
		0xD4B324F4F9A9EA09ULL,
		0x2D8E6CCD7A3DF629ULL,
		0xA75D9DA97D53FFE8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x02495D7FD3136E24ULL,
		0x340DD383FD2B2230ULL,
		0xA037246B462B1022ULL,
		0xAC6F840703DADD6DULL,
		0xB27A50A89C09D812ULL,
		0xFECAD74A99D5AE9AULL,
		0x706C10A31242C385ULL,
		0x6C6DEFB617D50747ULL
	}};
	t = 1;
	printf("Test Case 247\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 247 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -247;
	} else {
		printf("Test Case 247 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6B7F6A737A5A9498ULL,
		0x2DB28BC222359638ULL,
		0xFB780CD4082F81A0ULL,
		0xF0E3DE07E51052C2ULL,
		0xA49EEB9CD86381BAULL,
		0x140E338123879AF5ULL,
		0x5B20D002E057B002ULL,
		0xDBDAB03EE92CB7E9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB3C08E1EDF2D023FULL,
		0x2CEDF76074C28381ULL,
		0x884B9A121FA548F5ULL,
		0x5B187DD422BCD8C3ULL,
		0x31A5CDEF1F3FA431ULL,
		0x0493670880A65059ULL,
		0x0CE82F2B7476D34FULL,
		0xB19E2E6C40BE4296ULL
	}};
	t = 1;
	printf("Test Case 248\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 248 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -248;
	} else {
		printf("Test Case 248 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x52EE683C0DB647D2ULL,
		0xE865A6F2EE48363CULL,
		0xFF6337AE432E53D3ULL,
		0x9F6CD238668FBC68ULL,
		0x14C909AA45A06932ULL,
		0x4FA92558AC6C218BULL,
		0x7393F53BE5988CD8ULL,
		0x9C8D4C432554CD18ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x52EE683C0DB647D2ULL,
		0xE865A6F2EE48363CULL,
		0xFF6337AE432E53D3ULL,
		0x9F6CD238668FBC68ULL,
		0x14C909AA45A06932ULL,
		0x4FA92558AC6C218BULL,
		0x7393F53BE5988CD8ULL,
		0x9C8D4C432554CD18ULL
	}};
	t = 0;
	printf("Test Case 249\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 249 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -249;
	} else {
		printf("Test Case 249 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x23015F95700D9599ULL,
		0xEF3A304B7E23A011ULL,
		0x7D2A975705DA8448ULL,
		0xACC204B78510BA41ULL,
		0x1659B69F673E5666ULL,
		0x6DF7FB0013915F0AULL,
		0xBF401393C1DE7873ULL,
		0x25F06C0DD2E3FC0DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4732302C31A0E63CULL,
		0xD846A3E5748BD1E8ULL,
		0x61B8829D62C62C89ULL,
		0x44842FF537AF9E1AULL,
		0x1F2E3C7E898866C6ULL,
		0x3DEAB9BDC17CE1B7ULL,
		0x4EFA19B900B20046ULL,
		0x63A9AA50AC6831F8ULL
	}};
	t = -1;
	printf("Test Case 250\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 250 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -250;
	} else {
		printf("Test Case 250 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4E33E7A4662BFA5DULL,
		0x53D22E04165A87AAULL,
		0x6043644D2FDE04B1ULL,
		0x95D36C9FE83A6F91ULL,
		0x8E389141462B54E6ULL,
		0xF292877D0DC71922ULL,
		0x39D51E7BAB7A0C72ULL,
		0xF7E14B8DDB816E20ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8CC376D28CB0F51DULL,
		0x8693835C7A30FC4CULL,
		0x86A6C1906114B616ULL,
		0xE4813699FBCC9B0EULL,
		0x9E2A24F24F6F4189ULL,
		0x15441EEA3034D3E7ULL,
		0xBBDBD286F71F11ECULL,
		0xB510FE81D1B89B31ULL
	}};
	t = 1;
	printf("Test Case 251\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 251 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -251;
	} else {
		printf("Test Case 251 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAE99077673194E96ULL,
		0x77EB212FC9D4FB64ULL,
		0x40010EEB6F01903BULL,
		0xFD57A0A06873E5DEULL,
		0x98ED78A92D9A5515ULL,
		0x3A4094204D4186F0ULL,
		0xB2EA17C3FF733C4EULL,
		0xFE005A0F33E8108EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1272A49F012E4A43ULL,
		0xAAE46F1473CFF78FULL,
		0x839B938408E271F4ULL,
		0xFFA76509EDAA7A8BULL,
		0xC11D069085E2893AULL,
		0x812CA1C86C53621DULL,
		0xF9FD214FF9800C8CULL,
		0x06CD9D3DF7547150ULL
	}};
	t = 1;
	printf("Test Case 252\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 252 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -252;
	} else {
		printf("Test Case 252 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6CE1EF02A1EFF7AEULL,
		0xC7B7A0CDD66D2AEAULL,
		0xFE8C7465D3EBB752ULL,
		0x1F8AC974DB47805EULL,
		0xFD66BA308DAE1BF3ULL,
		0x15F07B32F0566DCFULL,
		0xB1E9917784942FA6ULL,
		0x2603C422769C0020ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6CE1EF02A1EFF7AEULL,
		0xC7B7A0CDD66D2AEAULL,
		0xFE8C7465D3EBB752ULL,
		0x1F8AC974DB47805EULL,
		0xFD66BA308DAE1BF3ULL,
		0x15F07B32F0566DCFULL,
		0xB1E9917784942FA6ULL,
		0x2603C422769C0020ULL
	}};
	t = 0;
	printf("Test Case 253\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 253 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -253;
	} else {
		printf("Test Case 253 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9611E36D87C3B33DULL,
		0xE05EA7FE526BE97EULL,
		0xAF8CFE1070C8F3BEULL,
		0x364661090E71625FULL,
		0x89D87820D3DCCE3CULL,
		0xC74FB64B2DCE3753ULL,
		0xFE11737266F57999ULL,
		0xF3051973297CC98CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x453E7450EDF40657ULL,
		0xBEFBC4C0AC2D4AD8ULL,
		0x87A31376A9342D34ULL,
		0x8CE8AA91D81630B5ULL,
		0xACD014305CD5F79CULL,
		0x66F7650E8D83B701ULL,
		0xA93783EF17B9EF49ULL,
		0xDCF715C225193D38ULL
	}};
	t = 1;
	printf("Test Case 254\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 254 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -254;
	} else {
		printf("Test Case 254 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB74D1E18C1BEC2C0ULL,
		0xE9061B9E4AA52232ULL,
		0xA6967D62E2C7C66AULL,
		0xEE96563E3F9CE993ULL,
		0x464354005BE57075ULL,
		0x499A3C5055749D97ULL,
		0xEF8C5E205392B5FAULL,
		0x1FE2A3A227F91474ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x607C218DF6FE5C22ULL,
		0x61E0AD891397C09BULL,
		0x17F1FC37780A43F9ULL,
		0x44665122E23B4C27ULL,
		0x448309B7F0C60714ULL,
		0xC58F04C6C50FE7B0ULL,
		0x1ABCE418D3D0768BULL,
		0x845CE9822FD1A4BAULL
	}};
	t = -1;
	printf("Test Case 255\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 255 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -255;
	} else {
		printf("Test Case 255 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xED78A2F64E346C88ULL,
		0x11FA883E1874C785ULL,
		0xCB87B79A2DD28A7DULL,
		0x2BB9D03E6B451004ULL,
		0xFE92CC03101C049FULL,
		0x67A18EBBEA380285ULL,
		0x8B933CB015B283DFULL,
		0xBA3318B2E4FCAF1BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0C3D9758797507EEULL,
		0x53C559383F2FEE98ULL,
		0x58C33416CAC52F6FULL,
		0xE6E96026B65D2126ULL,
		0x31391CC6697210C9ULL,
		0x774108C8C5277479ULL,
		0x9F1256A4631280F1ULL,
		0xCEFE095DC7540367ULL
	}};
	t = -1;
	printf("Test Case 256\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 256 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -256;
	} else {
		printf("Test Case 256 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x691C2BFBBA0DEB14ULL,
		0x7D27DE6DF818A222ULL,
		0x971CB64922EACB6BULL,
		0x14193A1676E0DB67ULL,
		0x4CE71B0F8E64E177ULL,
		0x7B2F81807BC2200BULL,
		0x41B10EBC731043BFULL,
		0xBDC52323ECE749D5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x691C2BFBBA0DEB14ULL,
		0x7D27DE6DF818A222ULL,
		0x971CB64922EACB6BULL,
		0x14193A1676E0DB67ULL,
		0x4CE71B0F8E64E177ULL,
		0x7B2F81807BC2200BULL,
		0x41B10EBC731043BFULL,
		0xBDC52323ECE749D5ULL
	}};
	t = 0;
	printf("Test Case 257\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 257 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -257;
	} else {
		printf("Test Case 257 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC9F8AEB18B8B51EEULL,
		0x79A6826D2033BBCEULL,
		0x8AC995ED6C78405BULL,
		0xFDCCD75D595FD3FEULL,
		0x3C84A1541C35C0E3ULL,
		0x7BCD4C08E9E157A0ULL,
		0xDCC1B34208102495ULL,
		0x990C6F0ECFEA13BBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x16D488F0933A8FC3ULL,
		0x386562B2E16569E6ULL,
		0x9AE3120F119086CAULL,
		0xE24438BE5B233312ULL,
		0x540365A67B3F1AF5ULL,
		0x3FDF270277B693A3ULL,
		0x3A545BA6BBEFACBDULL,
		0xC3971C9B1B53958AULL
	}};
	t = -1;
	printf("Test Case 258\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 258 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -258;
	} else {
		printf("Test Case 258 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCAF63C5943BA9182ULL,
		0x86A6D999CC7B4EE2ULL,
		0x96846921316CF9D8ULL,
		0x20109193A9E4C488ULL,
		0x68C3855F2AA1C4D9ULL,
		0x17CA177D06C5C841ULL,
		0xADB5E4F1A6DCD216ULL,
		0x87BDAE77933B227DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2EA7B7EC3E046718ULL,
		0xC3877738A937A1EFULL,
		0x819DDD621B87A32BULL,
		0xBAC35CF0808D80DDULL,
		0x5335450AD6DAA856ULL,
		0xFDB89B1B17A8DA3AULL,
		0x29EE1F6636B70B42ULL,
		0xAA8F9F7A1386410AULL
	}};
	t = -1;
	printf("Test Case 259\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 259 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -259;
	} else {
		printf("Test Case 259 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD8E8C8FAC16C1A90ULL,
		0xB0A8D4AEE6F462F8ULL,
		0xCB34A4AA5BADF868ULL,
		0x82CFE4A67F784A98ULL,
		0x192F430F15B20993ULL,
		0xFF4C6AB7C08294F0ULL,
		0x339A7CFA2273CC86ULL,
		0xDF389EBF10A3EAC5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC99FEE54005714CBULL,
		0x7F4616F75A6FC913ULL,
		0x56D3772CB076E78FULL,
		0x862F351ADA7CFFD8ULL,
		0xE55DABCD38D26F64ULL,
		0xE93090802A6EA35EULL,
		0xBAA9A859B00808C0ULL,
		0x8E616E0C86133BDCULL
	}};
	t = 1;
	printf("Test Case 260\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 260 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -260;
	} else {
		printf("Test Case 260 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE049AF773D9BA5A4ULL,
		0x0D91E41683C0406CULL,
		0x583E7CC39030AFF5ULL,
		0x70274B02217DE29FULL,
		0xD1B86233891CAA98ULL,
		0x237746A1DEF14F29ULL,
		0x45581745179B26EAULL,
		0xBC44426EF25099A4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE049AF773D9BA5A4ULL,
		0x0D91E41683C0406CULL,
		0x583E7CC39030AFF5ULL,
		0x70274B02217DE29FULL,
		0xD1B86233891CAA98ULL,
		0x237746A1DEF14F29ULL,
		0x45581745179B26EAULL,
		0xBC44426EF25099A4ULL
	}};
	t = 0;
	printf("Test Case 261\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 261 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -261;
	} else {
		printf("Test Case 261 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x26BA0E6DD7CA4425ULL,
		0x84D4FBAF985DC9F6ULL,
		0x725116B173CF31F6ULL,
		0xE869DFC8739CBF7EULL,
		0x7D62835922F0CB51ULL,
		0xBFA2869FC52288E9ULL,
		0xC4E30AF37B3F2FF0ULL,
		0xB4A7E740251AA0EEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x16DBD0A7441040C0ULL,
		0x17A9DC7C4BD649F1ULL,
		0x77C3D996069C9D43ULL,
		0x64ABCA8D12BF1252ULL,
		0x8943ACBDF0A3772CULL,
		0x1D14778400CD557AULL,
		0x689F4AA8825AA6DDULL,
		0xF37BAF9A5EF56E20ULL
	}};
	t = -1;
	printf("Test Case 262\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 262 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -262;
	} else {
		printf("Test Case 262 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE78C312E67C84A88ULL,
		0xEA311D3E86E63EDEULL,
		0x5AAB830C8E433E34ULL,
		0x05BF8CACA373D321ULL,
		0x2429AFF746539659ULL,
		0x7EA1137D7982ED73ULL,
		0x3C7932C15ECA8479ULL,
		0xC0CAD7E768FB8F0FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6B5BEF896D33C33EULL,
		0x3670032363586AC4ULL,
		0x0CB51CE19921607FULL,
		0x859F0ED53E61FD05ULL,
		0x51968934E7CE9A13ULL,
		0x7067EB6439A5E7DEULL,
		0x08E60FC08DBCC9E7ULL,
		0x0C71AE156D836160ULL
	}};
	t = 1;
	printf("Test Case 263\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 263 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -263;
	} else {
		printf("Test Case 263 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8551399BDDAE57CCULL,
		0x0605BC509F5E09F8ULL,
		0xA115283D4944AA0AULL,
		0x2F12FF8831BF1D00ULL,
		0x80E4DEC25FB36C3AULL,
		0x57E9A83479BE402EULL,
		0xC5CAC325FE582045ULL,
		0xC5656F274AC6764DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x60ACA35708BCFFC0ULL,
		0x6F54EE9F29A488C8ULL,
		0x5544D8282F07DB9CULL,
		0x1F85BBFDF9D96F96ULL,
		0xA66AC9C766A309F6ULL,
		0xA6412DEDF8AEBEA1ULL,
		0x8A903BB40B7BD086ULL,
		0xD9CF5CBB86BDCE0EULL
	}};
	t = -1;
	printf("Test Case 264\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 264 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -264;
	} else {
		printf("Test Case 264 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x00A5D0437EF48B30ULL,
		0xE5185940307E5DBFULL,
		0x6D5D2D42B9DD2C4FULL,
		0x2A8024742D4B98F4ULL,
		0x365685A374EB59D2ULL,
		0xDE249EE30A51000AULL,
		0x6968FF8173F4D269ULL,
		0xB91A53DEFF166538ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x00A5D0437EF48B30ULL,
		0xE5185940307E5DBFULL,
		0x6D5D2D42B9DD2C4FULL,
		0x2A8024742D4B98F4ULL,
		0x365685A374EB59D2ULL,
		0xDE249EE30A51000AULL,
		0x6968FF8173F4D269ULL,
		0xB91A53DEFF166538ULL
	}};
	t = 0;
	printf("Test Case 265\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 265 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -265;
	} else {
		printf("Test Case 265 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCBCCC2BF367CB94AULL,
		0x107178AA0F15B856ULL,
		0x0535EEB595949B7CULL,
		0xD1AF6C7A5113C383ULL,
		0x38B3AAA65A80F34EULL,
		0xE0BA0C7D55A803CEULL,
		0x858934D06AFE3E9FULL,
		0x25624C4D5A42156CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x213991007BBD2A0EULL,
		0xDC58D4011B17E51CULL,
		0x35F2110C3EA1BE77ULL,
		0x67652970D4CC6933ULL,
		0x98A6816F8CD4A313ULL,
		0xE38778D2D7B96E0BULL,
		0x748C1FAD178CDB3AULL,
		0x5694863AC4EC87B8ULL
	}};
	t = -1;
	printf("Test Case 266\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 266 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -266;
	} else {
		printf("Test Case 266 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBF426D4F92F1C617ULL,
		0x695E0D01708B66BBULL,
		0x55CF643BF8A78A13ULL,
		0x100084425B387CC4ULL,
		0xF8D9B6C79FD68209ULL,
		0x3A3E04BA55B34C4CULL,
		0x0A140B8C1CB0BD7DULL,
		0x89B5A2F02DFC7844ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2D21F2F69C84C66BULL,
		0xB080B1EB60A70DC6ULL,
		0x8584AAAAD3FC2400ULL,
		0xB49755E60ED2D64DULL,
		0x4A1A17CBC6403E95ULL,
		0xA4997CF42F4FF1CAULL,
		0xAAAAAD3E3F1A1BF0ULL,
		0x9434337C4F4DCA7BULL
	}};
	t = -1;
	printf("Test Case 267\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 267 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -267;
	} else {
		printf("Test Case 267 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBBF477BDA410C700ULL,
		0xFA8DFD3CA1E67A49ULL,
		0x452D3C288D6D5976ULL,
		0x89B9B2C73FB8265CULL,
		0xC120EF6A1C608312ULL,
		0xCE0E2E9AFE6F50BFULL,
		0x0D41856DC7B1E8D7ULL,
		0xC25C1C30B6916F1DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDA1ADD6E1B46DEA3ULL,
		0xF97876A75503B8DBULL,
		0xA3FD77449477FA14ULL,
		0x08480AC440C18B8FULL,
		0x203B03785707F7BAULL,
		0x2FF6F45BEA75DD12ULL,
		0x0F911DEC2DFD04DBULL,
		0x91BD28FC8F77A2BFULL
	}};
	t = 1;
	printf("Test Case 268\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 268 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -268;
	} else {
		printf("Test Case 268 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x181AE16B97F91596ULL,
		0x4F8F98718E0E7821ULL,
		0xAE655C5F68F9AE61ULL,
		0x6A2E3CB2A823A59DULL,
		0x7714DF4FC1DF4DD5ULL,
		0xD2DF5AB116FD1B66ULL,
		0xFC2B83597B2E6B8EULL,
		0xB7221EE0AFE815C3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x181AE16B97F91596ULL,
		0x4F8F98718E0E7821ULL,
		0xAE655C5F68F9AE61ULL,
		0x6A2E3CB2A823A59DULL,
		0x7714DF4FC1DF4DD5ULL,
		0xD2DF5AB116FD1B66ULL,
		0xFC2B83597B2E6B8EULL,
		0xB7221EE0AFE815C3ULL
	}};
	t = 0;
	printf("Test Case 269\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 269 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -269;
	} else {
		printf("Test Case 269 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2E72A4E4C721DCFEULL,
		0x76B08D8374C5B98FULL,
		0xE0B5B2F27089901FULL,
		0x7439DEB1D84C3BCBULL,
		0xBDCDC47A530C04B6ULL,
		0xCDC2AC0865140B6CULL,
		0xDA5B253D2E105CF3ULL,
		0xC90A05A268B6366CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0EEC0FDDC6D8FE7DULL,
		0x04178F54500A07E6ULL,
		0xB4B03031616AB322ULL,
		0xC3AD8D6A8663D312ULL,
		0x5ACB888F5AE041D3ULL,
		0xBFCAB64476C7EEE6ULL,
		0x9F47520621AAC9F5ULL,
		0xA75F514ECD9A4261ULL
	}};
	t = 1;
	printf("Test Case 270\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 270 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -270;
	} else {
		printf("Test Case 270 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6E04F5A8766FC213ULL,
		0x6F5A1898E03BAD32ULL,
		0xFE2ACB52643988D4ULL,
		0x9FB8F7557EF4BCB9ULL,
		0xC4E73723858C7CA7ULL,
		0xA9E6EF7A46DEA4E6ULL,
		0x711D606958B70AEEULL,
		0x19C8A489E770BCB0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB29D9DDAC7B061D3ULL,
		0x39E5BFE2BD3FFA1BULL,
		0x94C8FDBB2651F014ULL,
		0x2004CBA5FB70592CULL,
		0x7F61ECE835C39E89ULL,
		0x7BEEEBEC7F2C17C6ULL,
		0x38559DA5351659ADULL,
		0x62E13AAD30387B74ULL
	}};
	t = -1;
	printf("Test Case 271\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 271 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -271;
	} else {
		printf("Test Case 271 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x18E54126DB515F05ULL,
		0xA6226081C013E413ULL,
		0xECA6413213DF5E86ULL,
		0x9E7C48C8A1D199D2ULL,
		0x6BAA442490084B43ULL,
		0x13408CC8967E8FBFULL,
		0xBFFC23CB99A7A50FULL,
		0xF9D1D3C5D15878BBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4C071587A3F5A4B1ULL,
		0x9B2EF8A1C3F7B403ULL,
		0xB740A816DE5F8D88ULL,
		0xD9415F013CF6E790ULL,
		0xF50C06764C97DFE1ULL,
		0x7EBBF5F96914D38EULL,
		0xA7A4983DE564C5A7ULL,
		0x9994525B3C44525EULL
	}};
	t = 1;
	printf("Test Case 272\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 272 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -272;
	} else {
		printf("Test Case 272 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBA6B7FDDC599DFE0ULL,
		0xC34DC7BD7ACF4C12ULL,
		0x16C8D3031BABA99DULL,
		0xC615EDFFE2421C82ULL,
		0xDCA17D38FE411B4BULL,
		0x4A28FEF7A05EBF72ULL,
		0x40CCABB66EC1270DULL,
		0xD834BEC15DE67C5AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBA6B7FDDC599DFE0ULL,
		0xC34DC7BD7ACF4C12ULL,
		0x16C8D3031BABA99DULL,
		0xC615EDFFE2421C82ULL,
		0xDCA17D38FE411B4BULL,
		0x4A28FEF7A05EBF72ULL,
		0x40CCABB66EC1270DULL,
		0xD834BEC15DE67C5AULL
	}};
	t = 0;
	printf("Test Case 273\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 273 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -273;
	} else {
		printf("Test Case 273 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF78E6F4914418598ULL,
		0x94E86D24AB1E1167ULL,
		0xB3ABAC62DFF11CE5ULL,
		0x364294F70B681999ULL,
		0xABD667C638AC21E1ULL,
		0x27C685D7FD850DBAULL,
		0x067ADF0112983006ULL,
		0x72B6D66BEE3F684CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD4CADA844B4507B4ULL,
		0x7C3915E9CBD3F746ULL,
		0xA85451C03193CE79ULL,
		0x26278B3096AA1F25ULL,
		0xD7A541BC54015803ULL,
		0x406C0A11A50A9E53ULL,
		0xA256E9801AAC61C7ULL,
		0x4647A560C613F7B2ULL
	}};
	t = 1;
	printf("Test Case 274\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 274 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -274;
	} else {
		printf("Test Case 274 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1A73208B0A752809ULL,
		0x0A744BEDF857FB95ULL,
		0x5B4BF6F6065EF4F2ULL,
		0x330AD7741C7AC85CULL,
		0x10EBDA31CC1442A4ULL,
		0x7CC587C414D7460EULL,
		0x19ECEF78C3239371ULL,
		0x5AA091515C376B1EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x88AF645EE3784F7EULL,
		0xBC1FD7B1D1034EC7ULL,
		0x2A863710EDBABBB2ULL,
		0x36D223B823AA997BULL,
		0xF98F9919306D63B3ULL,
		0x091AAFA4ED7B59A8ULL,
		0x35B57DB9D6EA71AFULL,
		0x3329C3773D226671ULL
	}};
	t = 1;
	printf("Test Case 275\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 275 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -275;
	} else {
		printf("Test Case 275 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1B93D6A6BC6D1BB1ULL,
		0x065616238565DB6EULL,
		0x183C37DD57A7471DULL,
		0xF7DAA384790D169FULL,
		0x15AAC610AAE13A71ULL,
		0xB4A231520FEDC8DFULL,
		0x858893F9A4121E2CULL,
		0xAE8124F40CE4D27AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0B9564F25BE75FD0ULL,
		0xAD1FABE00CECD762ULL,
		0xEF8D2B2D84D61AB5ULL,
		0x86B3EE28B8F4EED6ULL,
		0x381745E0D7BFA37DULL,
		0x9C3C2D6BD82EF55FULL,
		0x6AB487FF9D28C7DFULL,
		0x8375F293DBE0133DULL
	}};
	t = 1;
	printf("Test Case 276\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 276 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -276;
	} else {
		printf("Test Case 276 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x34E05D51F2EC70B7ULL,
		0xE3787EBEC9ED9FD0ULL,
		0xF2AA5093F8F59C34ULL,
		0xBFA6CBAFF78ACE24ULL,
		0xBA22CBA7EAC54DD6ULL,
		0x84C461529CA8FA5FULL,
		0x47A2C2DF12509159ULL,
		0xC28CC5FA484FDE43ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x34E05D51F2EC70B7ULL,
		0xE3787EBEC9ED9FD0ULL,
		0xF2AA5093F8F59C34ULL,
		0xBFA6CBAFF78ACE24ULL,
		0xBA22CBA7EAC54DD6ULL,
		0x84C461529CA8FA5FULL,
		0x47A2C2DF12509159ULL,
		0xC28CC5FA484FDE43ULL
	}};
	t = 0;
	printf("Test Case 277\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 277 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -277;
	} else {
		printf("Test Case 277 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB1C26D219289B3DEULL,
		0x576177CE601FDE0BULL,
		0xC4C9972A9707893AULL,
		0x9B6A399D0C212991ULL,
		0xF6531D7E2655B9D7ULL,
		0xBD0D776D46F8483FULL,
		0x480DEE34FE897FE1ULL,
		0x94CB204773758728ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCB75A106E04AAF07ULL,
		0x9CC19847FAB23906ULL,
		0x7DD3A118F9FD8942ULL,
		0x2A2F2873263D6456ULL,
		0xFE8B15E3A2CD9304ULL,
		0x98B78044109F1A4DULL,
		0xE055BF810EB47253ULL,
		0x5FBDA6424D2E4590ULL
	}};
	t = 1;
	printf("Test Case 278\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 278 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -278;
	} else {
		printf("Test Case 278 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9271FEB769B566BFULL,
		0x98DD38CAE996EFDCULL,
		0xEC97D7842408D1DFULL,
		0x69B7A3A5434425B1ULL,
		0xC50B9B0CAA45A9A9ULL,
		0x91BAD1985C02C264ULL,
		0x7545CD44C9C00370ULL,
		0xFA7BB85DF0833A94ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x32BEC9E9B81DB81AULL,
		0x3EE6A13D2C86BBD2ULL,
		0xAA8D00375E73B6A0ULL,
		0xB2FE5856DBEC2FDBULL,
		0xF0BC67A3044E7777ULL,
		0x24C5F631B369E370ULL,
		0x1D41F5E473541AEEULL,
		0x29B2497DF619FF29ULL
	}};
	t = 1;
	printf("Test Case 279\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 279 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -279;
	} else {
		printf("Test Case 279 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1A6E0159938557ECULL,
		0x7E910DAB50F42D10ULL,
		0x06AB3C882664E099ULL,
		0x9E8B326CAAAAB9A3ULL,
		0xA9CF11ACE6126014ULL,
		0x35D52FD1A876C82EULL,
		0x2C1431D696C471A2ULL,
		0x46ABE4CA7CBF3E8AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE6484DB3D3D6C24DULL,
		0xFBF4E174463257F3ULL,
		0x5A42FD3CEE76D793ULL,
		0x43FBF198676648AEULL,
		0xA4B8E1A518A0C304ULL,
		0xB6E7CEB3DDB3C805ULL,
		0x4C701B9924AE725FULL,
		0xE7DEE0ABCFC06CA5ULL
	}};
	t = -1;
	printf("Test Case 280\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 280 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -280;
	} else {
		printf("Test Case 280 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1203F8F3AFC7A64FULL,
		0xF6AE0A45DB056083ULL,
		0x0E19D3B8406E86B6ULL,
		0xE16D17B9B841A29EULL,
		0xF32EC79D7BC0DE2CULL,
		0x7BD473E0D8019DC2ULL,
		0x0B1D8902173EBCBFULL,
		0x681AF1C1859DE619ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1203F8F3AFC7A64FULL,
		0xF6AE0A45DB056083ULL,
		0x0E19D3B8406E86B6ULL,
		0xE16D17B9B841A29EULL,
		0xF32EC79D7BC0DE2CULL,
		0x7BD473E0D8019DC2ULL,
		0x0B1D8902173EBCBFULL,
		0x681AF1C1859DE619ULL
	}};
	t = 0;
	printf("Test Case 281\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 281 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -281;
	} else {
		printf("Test Case 281 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x416BBAEE0F974C38ULL,
		0xD728682C2ADC370DULL,
		0xADAD78D5D5FC3D92ULL,
		0xB503E9EE5EF0FEDFULL,
		0xF01429A3D5610B4AULL,
		0x16C907F67EB8EC38ULL,
		0x069ABB1324557E99ULL,
		0xA3042B0C434EC5CDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD908E96BCB961B89ULL,
		0x3B754BE6E95B97BFULL,
		0x722DC6B229B43A02ULL,
		0x1D8DC0503E9DB479ULL,
		0x19105FD56B97E96AULL,
		0xC85F91D3683A7261ULL,
		0xADB2EF4285DC4D22ULL,
		0xC51A50A3677547DCULL
	}};
	t = -1;
	printf("Test Case 282\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 282 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -282;
	} else {
		printf("Test Case 282 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x78459FE827FDF644ULL,
		0x1E2768B1AC76EE3FULL,
		0x7DDFCC0726FA271AULL,
		0x05D07A703A67E276ULL,
		0x731F784918410D2AULL,
		0xA33D6D426D4C03DFULL,
		0x5829B5677C7F86D9ULL,
		0xC3343E76B03F53F8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE40F03DE4D433C6CULL,
		0xD0ACC0A6631A4873ULL,
		0xC07DC078171BFFEDULL,
		0x0AE0F153AD27C0C8ULL,
		0x98A1F9A33CA97C59ULL,
		0x87FDEC44F38B8948ULL,
		0xADE8E7501C17000BULL,
		0x00BA12C5F5D185AFULL
	}};
	t = 1;
	printf("Test Case 283\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 283 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -283;
	} else {
		printf("Test Case 283 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD8325AD9455259F1ULL,
		0xBBBE3A0C6C38362CULL,
		0xFCCC7579174B6605ULL,
		0x51AEDBB2682D199BULL,
		0x7D3D342DF8EF7C0DULL,
		0x26972284A7CF4247ULL,
		0x35871B627D928CC0ULL,
		0xDFACEBF415181663ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEF786AD3F40192FFULL,
		0x4A3F63B1B7F670AEULL,
		0x0E79201D14D5DD29ULL,
		0x2021FD52BC961415ULL,
		0x05FB2AA384E0D0FEULL,
		0x4F4A2E97EB9FDD50ULL,
		0xC05B6FEC60BDB8E8ULL,
		0x11BC0FED8B5E4C09ULL
	}};
	t = 1;
	printf("Test Case 284\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 284 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -284;
	} else {
		printf("Test Case 284 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3226DB3CD3457489ULL,
		0x67B6F5B479035DA7ULL,
		0x78EAA3B36CE1031FULL,
		0x896B4B5922983F99ULL,
		0xE047A2D382CDB953ULL,
		0xF0A548C7A231F1D4ULL,
		0xD00B5696B6AC34FAULL,
		0x204AFBDC6883FB83ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3226DB3CD3457489ULL,
		0x67B6F5B479035DA7ULL,
		0x78EAA3B36CE1031FULL,
		0x896B4B5922983F99ULL,
		0xE047A2D382CDB953ULL,
		0xF0A548C7A231F1D4ULL,
		0xD00B5696B6AC34FAULL,
		0x204AFBDC6883FB83ULL
	}};
	t = 0;
	printf("Test Case 285\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 285 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -285;
	} else {
		printf("Test Case 285 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6631EAFBE235F777ULL,
		0x43A0E115DDF4929BULL,
		0x47EAEA43970EEDD0ULL,
		0x4B9456E2DDD86CD6ULL,
		0xFD342BD6412DFEC9ULL,
		0x5402385DB72FCD93ULL,
		0x09AB59C693AB7B2AULL,
		0xE57F24838AB5DB54ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBCEF45CA47863032ULL,
		0xCEAA732ACF8E3E42ULL,
		0x21DF58484656E93EULL,
		0x750593833E86F184ULL,
		0xFE381777D9E7C4D5ULL,
		0x4B280DC6697646EEULL,
		0x89DBB88110AC3B63ULL,
		0x49663447F21A0688ULL
	}};
	t = 1;
	printf("Test Case 286\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 286 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -286;
	} else {
		printf("Test Case 286 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7AAB0F32A59E4A8CULL,
		0x0889B1D935278534ULL,
		0x569ECF7F9F79E070ULL,
		0x0AC0583B18B76DCAULL,
		0x08349D01B2A8B727ULL,
		0xF952605F983438E3ULL,
		0x8645923F3690C5F8ULL,
		0x6768EE824E4CD306ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x154FD4A7DFF4718EULL,
		0xE0F48F9A1BB85781ULL,
		0xE2980680648C8373ULL,
		0xCBB9492CE8282597ULL,
		0x74CAB2D7353F14BBULL,
		0xC91677348362AB72ULL,
		0x07C75384B3250A1CULL,
		0x27FB02335FAAEB73ULL
	}};
	t = 1;
	printf("Test Case 287\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 287 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -287;
	} else {
		printf("Test Case 287 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2118105741FF150EULL,
		0x99D7758F815CC137ULL,
		0xA8AF8DC127AB949AULL,
		0x19C24808A904829EULL,
		0x5358258AD6701367ULL,
		0xB6B75D99290866A7ULL,
		0xE8AA540BC672C998ULL,
		0xD5E9F201BACF863FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB7F4128857027F94ULL,
		0x3087D2A30D233167ULL,
		0xCE298BB955DA7BAEULL,
		0xC5A1041C4A468006ULL,
		0x099948803AA3C413ULL,
		0x8EC9FBD472EDAA2DULL,
		0xE4E03BBD2136C2F1ULL,
		0x3155E05885980D03ULL
	}};
	t = 1;
	printf("Test Case 288\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 288 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -288;
	} else {
		printf("Test Case 288 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3571279DA50D984AULL,
		0xF1EDFE4967B2AEBFULL,
		0x96D42FF9CC82E9EFULL,
		0xB7B8FDB2A63CC0ABULL,
		0xF6907267F976A4E9ULL,
		0x3C4D7FAE05CAD5FDULL,
		0x58F35833AD4A669FULL,
		0x9CE27C4860FD0D42ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3571279DA50D984AULL,
		0xF1EDFE4967B2AEBFULL,
		0x96D42FF9CC82E9EFULL,
		0xB7B8FDB2A63CC0ABULL,
		0xF6907267F976A4E9ULL,
		0x3C4D7FAE05CAD5FDULL,
		0x58F35833AD4A669FULL,
		0x9CE27C4860FD0D42ULL
	}};
	t = 0;
	printf("Test Case 289\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 289 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -289;
	} else {
		printf("Test Case 289 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCF56C86F328FD73EULL,
		0xE1E6CE7ECDA7A1E4ULL,
		0xF48F21C40602EBB7ULL,
		0x66CA6463BD640BA8ULL,
		0xE0E958BEBE92CBC3ULL,
		0x2D49256741759F4BULL,
		0xC9D7A6F3B3D67219ULL,
		0x4C55D05EEB2CC74AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x218FF00A3001F039ULL,
		0xFE9479BDB1CFA7A6ULL,
		0x9BDEB389E209997AULL,
		0x39F6ABB45A248699ULL,
		0x39FCCB160A55A036ULL,
		0xF08F04B87FF3EE56ULL,
		0xC1854B3405EBBC2FULL,
		0xD215E31D36CA58FDULL
	}};
	t = -1;
	printf("Test Case 290\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 290 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -290;
	} else {
		printf("Test Case 290 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x50FB134F6E0CA71EULL,
		0x57EF14D7CE9B6809ULL,
		0x25AC6BB182442040ULL,
		0x1CB9240CB622E4F0ULL,
		0x10A022FED7DF1F6CULL,
		0x545B901D43BCC07DULL,
		0x0E870F2806038F3AULL,
		0xE3044BCD0DFA9C15ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5F6B1E7D1BB0D6A0ULL,
		0x4FFFF831FC3FA7D4ULL,
		0x0F4FEFD344ED59FBULL,
		0xEBD3A5081FD1E1E8ULL,
		0xAF0B4DE2334F31B7ULL,
		0xA3DA4103FBA78BBFULL,
		0x9F00FF41880A02C5ULL,
		0xEC6C4CFACEBCB472ULL
	}};
	t = -1;
	printf("Test Case 291\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 291 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -291;
	} else {
		printf("Test Case 291 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE278A9BFC93E1A3FULL,
		0x55CF1B773946A72FULL,
		0x6FB1A2205421AAEBULL,
		0x72B934D7D7CDEF7BULL,
		0x7251BD84C6F22739ULL,
		0x94675C2C5A68E0FEULL,
		0x26734589D22C427EULL,
		0xFFB82EA761A808B4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBAA892CC6F8FDD7AULL,
		0x4148ABDDC43705EDULL,
		0xDE32035CCE638B43ULL,
		0xBCCB1C933EF1158FULL,
		0xB9E8DAD7EBC57F64ULL,
		0x288480CADDB98C7EULL,
		0xD16330812A91EF91ULL,
		0xDB23F95A3CFA9EB7ULL
	}};
	t = 1;
	printf("Test Case 292\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 292 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -292;
	} else {
		printf("Test Case 292 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA180A4498E13ACB4ULL,
		0x6CF71E6B6F5C2784ULL,
		0x8DFF86F6083D5DF3ULL,
		0xED72A49296EF8501ULL,
		0x142076802E65C4B6ULL,
		0x740C08B6740DDC52ULL,
		0x7391B976EBDA7880ULL,
		0x881FEEBDFEB87441ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA180A4498E13ACB4ULL,
		0x6CF71E6B6F5C2784ULL,
		0x8DFF86F6083D5DF3ULL,
		0xED72A49296EF8501ULL,
		0x142076802E65C4B6ULL,
		0x740C08B6740DDC52ULL,
		0x7391B976EBDA7880ULL,
		0x881FEEBDFEB87441ULL
	}};
	t = 0;
	printf("Test Case 293\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 293 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -293;
	} else {
		printf("Test Case 293 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2337BC9AA6EE7C5EULL,
		0x506566F550867BC5ULL,
		0x1C0646B29EBE5E9DULL,
		0x043B00E14B166C22ULL,
		0xDE19B6E016DE854CULL,
		0x4FEFE2C03FBC58E1ULL,
		0xAFC8DB87BEB2B56AULL,
		0x830A8D9DA76264A2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x07EF43AE95A9200FULL,
		0xFB727B5D8A4CAD73ULL,
		0x3E7769D30AC4FF1EULL,
		0x6BB6F02D5CB6A0D1ULL,
		0x4687C3611498218CULL,
		0x6D2A9F227FD4B50DULL,
		0xB1BF3D0CECC155DDULL,
		0xFCB14A29DD4A6D9FULL
	}};
	t = -1;
	printf("Test Case 294\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 294 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -294;
	} else {
		printf("Test Case 294 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x864FB4C0628201E6ULL,
		0x9020815E753BC758ULL,
		0xE605D469706A83DAULL,
		0x782889E79E3D6273ULL,
		0x8D5C0773F68C1574ULL,
		0xF9881FD328956A2CULL,
		0xCF1F07FE363864F1ULL,
		0x163C4F5EB7A3220BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC8859F3FBB9BB866ULL,
		0x0DE3281FB1378D6DULL,
		0xEC9AB86732098AD7ULL,
		0x751D3EF2D284B99AULL,
		0x6D8B25677F009ACEULL,
		0x012A99652FA1F968ULL,
		0x1BF7A80A5011036FULL,
		0x91D8F7578C19FC83ULL
	}};
	t = -1;
	printf("Test Case 295\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 295 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -295;
	} else {
		printf("Test Case 295 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x09CA707B80F86139ULL,
		0x1A68FA697613381AULL,
		0x83B6C79F3150E2D5ULL,
		0xE3AC62BC4A4C3463ULL,
		0xC39EB3BEFFF27C7EULL,
		0x2E79B9A60DECC1F5ULL,
		0xA5F9CDB8B90B936DULL,
		0xF4477D3C92B4A9FAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCD8E016EE9876153ULL,
		0x4C4596A3E2E9F24FULL,
		0x4A7B533A64593132ULL,
		0x8D83290DDCD4AFE2ULL,
		0xBBEF187B227969E9ULL,
		0xF974E1D086D64524ULL,
		0x0BDF84D04F8220CCULL,
		0x172F6F0013617FDDULL
	}};
	t = 1;
	printf("Test Case 296\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 296 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -296;
	} else {
		printf("Test Case 296 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4D9A0CE17FBADF80ULL,
		0x10DBE7FBD32F9642ULL,
		0x576EDA4B2058F23AULL,
		0x9CDC9B27306DE129ULL,
		0x8C62DF88A70F1448ULL,
		0x11C6E37A0EB4D6BAULL,
		0x284E6B03419506D7ULL,
		0x877BB241047FC67EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4D9A0CE17FBADF80ULL,
		0x10DBE7FBD32F9642ULL,
		0x576EDA4B2058F23AULL,
		0x9CDC9B27306DE129ULL,
		0x8C62DF88A70F1448ULL,
		0x11C6E37A0EB4D6BAULL,
		0x284E6B03419506D7ULL,
		0x877BB241047FC67EULL
	}};
	t = 0;
	printf("Test Case 297\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 297 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -297;
	} else {
		printf("Test Case 297 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x46FCFAECF2EC0F8AULL,
		0x2AC700F21195A4CFULL,
		0x022C6CC1FAB9FFE9ULL,
		0xBB65BE13AAD353ADULL,
		0x0B3089485973D1E6ULL,
		0x0C77B9B0ECC5262EULL,
		0x6BD7F5CA079781F9ULL,
		0xB6BF29FC458C05FEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5FA5AE1E39421245ULL,
		0x793C6264E645D8A3ULL,
		0x56021AA2992D04B5ULL,
		0x1B7C16CAC8BE7505ULL,
		0x8D61F6F6D5BEC881ULL,
		0xD3308461B954639BULL,
		0xA9C4E4345084BF4BULL,
		0x28A611E9EEB854B3ULL
	}};
	t = 1;
	printf("Test Case 298\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 298 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -298;
	} else {
		printf("Test Case 298 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4B3BD1AABDAEC4C9ULL,
		0xA53D49E84513C5AEULL,
		0xA2B2C542EB091BA9ULL,
		0x2B004258249FF05EULL,
		0x00A480BDB6CCD8B9ULL,
		0xEB0C039B8AE1B541ULL,
		0x243517FEA2FC5DF5ULL,
		0x1F707CA6C8A5DB9DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0E56B3D4C4BC0E5BULL,
		0x908FD63A3D36638AULL,
		0x0A4DCAFEA8A09516ULL,
		0xDCCCC7208D63B6F9ULL,
		0xA32E6F21A93AD6B1ULL,
		0xE5EB72262D1080B7ULL,
		0xDE4F5511011B280BULL,
		0x9DF69514B9610603ULL
	}};
	t = -1;
	printf("Test Case 299\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 299 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -299;
	} else {
		printf("Test Case 299 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBCB17513E8472C98ULL,
		0x1F37CBBD95CBC564ULL,
		0x8574F096D5F66918ULL,
		0xF8BF549FB784341AULL,
		0xDB386733621FCF6DULL,
		0x1C643D12DCC1C88BULL,
		0xC8DFB2EDD1555805ULL,
		0xF3F518D664325D3EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x60660E98BC9BC110ULL,
		0xD53C7550A363596BULL,
		0x8C5E30CD8BABAE0EULL,
		0x2038BBE51BF85CDEULL,
		0xB344E987CB4BA376ULL,
		0xC518F794C5358025ULL,
		0xA21BE4DF9242BE54ULL,
		0x277935BE125DE7C3ULL
	}};
	t = 1;
	printf("Test Case 300\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 300 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -300;
	} else {
		printf("Test Case 300 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x25EDE3157E75C2FBULL,
		0x727404CE03F5FAD1ULL,
		0xB8C178E84BCB41B1ULL,
		0xBD32496ADCAD6C34ULL,
		0xB7305332CD9BE332ULL,
		0x3C9BF14AC04C9FB8ULL,
		0xC211603A66D24E27ULL,
		0x9016D2170081D4EEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x25EDE3157E75C2FBULL,
		0x727404CE03F5FAD1ULL,
		0xB8C178E84BCB41B1ULL,
		0xBD32496ADCAD6C34ULL,
		0xB7305332CD9BE332ULL,
		0x3C9BF14AC04C9FB8ULL,
		0xC211603A66D24E27ULL,
		0x9016D2170081D4EEULL
	}};
	t = 0;
	printf("Test Case 301\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 301 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -301;
	} else {
		printf("Test Case 301 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC965E6202F111D73ULL,
		0x0C96EEDD854F9A0BULL,
		0x1D2275316A7F4E90ULL,
		0xEF781C19D715CA83ULL,
		0xFAE376B3752C4D62ULL,
		0x4AFAEC4A3B9639EAULL,
		0xA3B212EC487C5DACULL,
		0x5C90CD46BBB466EEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3CF7FF8621AE75A7ULL,
		0x1BCA7B691E2E638FULL,
		0xFFD77162A141E5BFULL,
		0x0E674CD1E4106EE1ULL,
		0x9B8653D5616BDD95ULL,
		0xD373D9F886B2E19FULL,
		0x6DD6DE871A314536ULL,
		0xCA3FFF7A8B41652BULL
	}};
	t = -1;
	printf("Test Case 302\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 302 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -302;
	} else {
		printf("Test Case 302 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7921E4D7C4C8C2A2ULL,
		0xD59FA1B5F59F9540ULL,
		0x368D48F4EA95895FULL,
		0xE1D7C6C414D70DBAULL,
		0x36CE4C5F972BB8F4ULL,
		0x553094C9930CD489ULL,
		0x734216F35118F98AULL,
		0x8819B23BF5CC9EFEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB37D2AD0B4C83F97ULL,
		0xAC48414272704E00ULL,
		0x595CEC23BCB22884ULL,
		0xA16C79ADB79B4EB1ULL,
		0x8B03B784AE387252ULL,
		0x92BEB043F45ACAABULL,
		0xD0D4E53F1C6B4F12ULL,
		0xBB52428E05C59533ULL
	}};
	t = -1;
	printf("Test Case 303\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 303 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -303;
	} else {
		printf("Test Case 303 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1ECBF397196AC9BBULL,
		0xC0D687408EEDBC6FULL,
		0x558324B8BE8AA082ULL,
		0xD8B4DEA8B7A1A91CULL,
		0xB5DE06C8CA6EBD92ULL,
		0x8BF731A73A889C4DULL,
		0x813F92C968432B2FULL,
		0xA46D3C85DC8878EBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8CDC004AC189FE55ULL,
		0x077B8FB4B9743C92ULL,
		0xC531AEFBC06EA973ULL,
		0x971FBDA35DCC3B70ULL,
		0x0C5CF4B1AE3BB6B5ULL,
		0xDF4FD756984CACAAULL,
		0x8C4C1ABC950BEF60ULL,
		0x1CB470FA917DF30DULL
	}};
	t = 1;
	printf("Test Case 304\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 304 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -304;
	} else {
		printf("Test Case 304 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0C2F3CE590359A00ULL,
		0x262B5556F47A1CF3ULL,
		0x411C61EC00CE8858ULL,
		0x77F9E8C17728B76BULL,
		0x839583E3BCF42E92ULL,
		0x31C12E7E93E25703ULL,
		0xE18F0058AF173ABDULL,
		0x04A3EE6BF0A7A223ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0C2F3CE590359A00ULL,
		0x262B5556F47A1CF3ULL,
		0x411C61EC00CE8858ULL,
		0x77F9E8C17728B76BULL,
		0x839583E3BCF42E92ULL,
		0x31C12E7E93E25703ULL,
		0xE18F0058AF173ABDULL,
		0x04A3EE6BF0A7A223ULL
	}};
	t = 0;
	printf("Test Case 305\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 305 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -305;
	} else {
		printf("Test Case 305 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8742D514610D7F3EULL,
		0x8757BEE2B7CCE33AULL,
		0x42F392045B19507DULL,
		0xDF7BC6E307ED96BDULL,
		0x42DACB56F11F0CDCULL,
		0xA10747A65408C655ULL,
		0xC5B06F5B0D86534EULL,
		0x14CB194DABE5D067ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9F81372A94430266ULL,
		0x3A49BBB16E78E5D9ULL,
		0xA9017FFD6A97F388ULL,
		0x3F6069290395DF79ULL,
		0x9802855697EB3658ULL,
		0x52DA4C2E58383C91ULL,
		0xE1BC03DF885DD5AAULL,
		0x27AD3E5F4FFCA246ULL
	}};
	t = -1;
	printf("Test Case 306\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 306 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -306;
	} else {
		printf("Test Case 306 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x756BB13FED65CC21ULL,
		0x6EB081447A5A6BA5ULL,
		0x2D6F748ABC21B6EDULL,
		0xB3DE81689F8926F3ULL,
		0x2A78EB791E92D8DDULL,
		0xE8A06BE81B2FE7CAULL,
		0xC315603B575ED050ULL,
		0xCE3EA127E132D6E1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFB3B87059B458E43ULL,
		0xFC7F96D805F2F02AULL,
		0xDE31D2D9BA764620ULL,
		0x1F6051C8954B5E71ULL,
		0xF4D09D6F68689127ULL,
		0x67C1F556E4FE3FCEULL,
		0xA956BB32DA9BECA0ULL,
		0xD4CB5A950088598DULL
	}};
	t = -1;
	printf("Test Case 307\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 307 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -307;
	} else {
		printf("Test Case 307 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA38AAE28F16947B0ULL,
		0x6DA2AA263DF8FCDFULL,
		0x255FEB1126080915ULL,
		0x965E488BFA123B84ULL,
		0xC815841A7BCDDF6AULL,
		0x3CE5FBB6B04CF5FCULL,
		0x6E96B3BB1E82096DULL,
		0x05C0F740286E5D1EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5BCC9265A042A9F6ULL,
		0xAE90D36995FEC4C7ULL,
		0x59AFEB7E459EA73CULL,
		0x2550A04766645970ULL,
		0xD1E42A79584B9D64ULL,
		0xB010A77EBF5DC0A4ULL,
		0x8804D0420B2D637DULL,
		0xE6F303A281F2277FULL
	}};
	t = -1;
	printf("Test Case 308\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 308 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -308;
	} else {
		printf("Test Case 308 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCFE6B3FC4540EF44ULL,
		0xFF401AC7E382B841ULL,
		0x7B27A1BC62CCAAF2ULL,
		0x167656C89F1930F5ULL,
		0xF2C5E95F558ACAB7ULL,
		0x9FBC211FB94B0E09ULL,
		0x21A123923CBC91D8ULL,
		0xD817A7E39D395B0FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCFE6B3FC4540EF44ULL,
		0xFF401AC7E382B841ULL,
		0x7B27A1BC62CCAAF2ULL,
		0x167656C89F1930F5ULL,
		0xF2C5E95F558ACAB7ULL,
		0x9FBC211FB94B0E09ULL,
		0x21A123923CBC91D8ULL,
		0xD817A7E39D395B0FULL
	}};
	t = 0;
	printf("Test Case 309\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 309 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -309;
	} else {
		printf("Test Case 309 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBF29F89BEABB3B28ULL,
		0xFC47B534E761D321ULL,
		0x59A9F245B6BC1546ULL,
		0xDE6088BA177B46E1ULL,
		0x16E69D63825B7F35ULL,
		0xDCFED4A2BCE99C4FULL,
		0xE5A09245E20BB184ULL,
		0x4386736AE6A1E2A8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8AE5B06A65ABECB1ULL,
		0xC451E2D0EDF0B79EULL,
		0xAB4095B91B58D07DULL,
		0xDABBA08BCE5C80D6ULL,
		0xEF9EC130F9EE37ADULL,
		0x7DE7AD78BCB9DC9DULL,
		0x36CA1833E77DFFD6ULL,
		0x0A82338EDD2DDB21ULL
	}};
	t = 1;
	printf("Test Case 310\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 310 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -310;
	} else {
		printf("Test Case 310 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1A839F061A821AB9ULL,
		0xDFA9B922D1F10908ULL,
		0xF0A780BA93D626D0ULL,
		0xD1A67CFB653FC98DULL,
		0xAB9F21389A96AC6DULL,
		0xD88AB8883AEE8F84ULL,
		0xA1DBAC3783D3B202ULL,
		0x30CDE07DB06689BAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB5C46B87463383DAULL,
		0xA44CB55C1C09949EULL,
		0xF90F3481CD17BDDEULL,
		0x5B2950E9FC31191AULL,
		0x4C5E886FFCAAE15CULL,
		0x0618BA870D349FBAULL,
		0x89724043E2759938ULL,
		0x625835B8B71460EDULL
	}};
	t = -1;
	printf("Test Case 311\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 311 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -311;
	} else {
		printf("Test Case 311 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1C41A77BE8E4916CULL,
		0x7137936AD45B5EC6ULL,
		0x55BFB00C1335C0BEULL,
		0x6E4BDC86E1027F32ULL,
		0xC442769AEE699E79ULL,
		0x55B01B1D1AC52EB3ULL,
		0x78A3059120E85FA3ULL,
		0xC33B7A7226643582ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAB19231D63E50B8AULL,
		0xAE9029F35074FDFCULL,
		0x9177CEF4B5B52810ULL,
		0x5C412487868EED44ULL,
		0x60E549647EED0E39ULL,
		0x6CD16F9E09FC79C7ULL,
		0x13ADF7CD0CD4D15AULL,
		0xF7277260E01BA4CAULL
	}};
	t = -1;
	printf("Test Case 312\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 312 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -312;
	} else {
		printf("Test Case 312 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2105BC2D2F496F47ULL,
		0x1D5D8571A8D0B63DULL,
		0xF59730D8307E70CCULL,
		0xD1AB54B341BD7C7BULL,
		0xEC1A8E9DAA6CE615ULL,
		0x57697A9B347BFFB2ULL,
		0xA75F79758FC3C5DCULL,
		0x100FDD0537A8761DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2105BC2D2F496F47ULL,
		0x1D5D8571A8D0B63DULL,
		0xF59730D8307E70CCULL,
		0xD1AB54B341BD7C7BULL,
		0xEC1A8E9DAA6CE615ULL,
		0x57697A9B347BFFB2ULL,
		0xA75F79758FC3C5DCULL,
		0x100FDD0537A8761DULL
	}};
	t = 0;
	printf("Test Case 313\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 313 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -313;
	} else {
		printf("Test Case 313 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDC576C152FC6A42BULL,
		0x155CC538503B9473ULL,
		0x180380849016FF8EULL,
		0x918A521B1BE1D970ULL,
		0x9FE29ADCBF335C34ULL,
		0x7EC96EFD88EBD591ULL,
		0x2931D76B23E0CC27ULL,
		0x7743503D12665BD2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x36CFDEDC3FCEE164ULL,
		0x74755F26A04BBD91ULL,
		0x1E56FC74AF331CF3ULL,
		0x6FC8A7ADBB6295A9ULL,
		0x679E27C93F0924CCULL,
		0x4133D20E59801CE8ULL,
		0xFA52321DA55CEA19ULL,
		0xA951CE5B5A7E1E58ULL
	}};
	t = -1;
	printf("Test Case 314\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 314 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -314;
	} else {
		printf("Test Case 314 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB3B3EDD358ECC11AULL,
		0x9ECF7F7A5F7E4142ULL,
		0x71CCC58F81E0421BULL,
		0xB8E92DAAEC0956D6ULL,
		0x995D2F5EDE096B86ULL,
		0x040AE6A7F0387445ULL,
		0x6DCCB95785295DEEULL,
		0xF8B771A31621F0D7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD60D4080E7F388A6ULL,
		0x21F0FE9A59A282E1ULL,
		0xB3ECE23BEFEB9055ULL,
		0x4A87E5BBC109D064ULL,
		0xF6DB3D98AE433620ULL,
		0xAE3D17AE55DFBC31ULL,
		0x1C70DB04D559E8B5ULL,
		0x33A7590FCCB23100ULL
	}};
	t = 1;
	printf("Test Case 315\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 315 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -315;
	} else {
		printf("Test Case 315 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAB99D5DF18CD197FULL,
		0x72AC5427218D9C24ULL,
		0xB72EBAA2F8A7D915ULL,
		0xA8752739B5462E7EULL,
		0x2A3F7918C0B2D8EFULL,
		0x3FCF8F74E16DF7C1ULL,
		0x4FD85DEDEAA891F1ULL,
		0x11C98C0A6FC04C93ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x99C113F81D7B5A1BULL,
		0x4ADCB099C27B83C6ULL,
		0x1371A7AF05103A1BULL,
		0xD73B27FA29C87F0EULL,
		0x7C6EA7F10C6F9262ULL,
		0xDAF6D423D8525005ULL,
		0xCA86D97BCB68942BULL,
		0xDE90D0E470023F10ULL
	}};
	t = -1;
	printf("Test Case 316\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 316 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -316;
	} else {
		printf("Test Case 316 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0AACF4379C2F5806ULL,
		0x9C0196F1F4A83E09ULL,
		0x6A889BC5223669B2ULL,
		0x062D587D53B33FCDULL,
		0x37FE80B89BC3BD5BULL,
		0x3880C2F8D5037773ULL,
		0xC852CEA94D05A680ULL,
		0xD4DC0D3D55F3C4DDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0AACF4379C2F5806ULL,
		0x9C0196F1F4A83E09ULL,
		0x6A889BC5223669B2ULL,
		0x062D587D53B33FCDULL,
		0x37FE80B89BC3BD5BULL,
		0x3880C2F8D5037773ULL,
		0xC852CEA94D05A680ULL,
		0xD4DC0D3D55F3C4DDULL
	}};
	t = 0;
	printf("Test Case 317\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 317 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -317;
	} else {
		printf("Test Case 317 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB9ECAB41D1C07583ULL,
		0x7EFE7A10AD5E0CACULL,
		0xC576673C2CDF08C9ULL,
		0x1EC202E2850A82C0ULL,
		0xBA697C7683561F11ULL,
		0x2B29587EA53730C9ULL,
		0xB1B5FF9C0DC18B84ULL,
		0x31CE83D43263FFD2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x61B8BA717CFF23CCULL,
		0x6C70B476AB227F15ULL,
		0xBFE03C98C2567914ULL,
		0x409E71F037E291FBULL,
		0x28D26ED7D4DF8FF6ULL,
		0x37136CDE773EC609ULL,
		0xC16135753ABDD327ULL,
		0x1EBB31F8EBF6E0C1ULL
	}};
	t = 1;
	printf("Test Case 318\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 318 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -318;
	} else {
		printf("Test Case 318 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x97E39A3ADDE13D07ULL,
		0x284466120A2C27A0ULL,
		0x48FD2E36EEDB93E2ULL,
		0x39E87CFF5035C7E3ULL,
		0x345B8614165F2EC8ULL,
		0xAC7F2B9A34293AB0ULL,
		0xAEB4760BB08DFA68ULL,
		0xA8FC23EB8BFB4DFBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9EE33B61B0BCB749ULL,
		0x7F02CE88AE814E6DULL,
		0x0A476E046D64FFEEULL,
		0x90E567785C618C17ULL,
		0x16B07A56D1DEAB60ULL,
		0xD45986BCF7BEE6F4ULL,
		0x6F314EEDCC5E96A7ULL,
		0x73F1E1414B73DCA3ULL
	}};
	t = 1;
	printf("Test Case 319\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 319 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -319;
	} else {
		printf("Test Case 319 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x71C1A1EC9AA10BC7ULL,
		0x6F3BB2D3B763B2F7ULL,
		0xB96CE66AC3132C03ULL,
		0xD29E267C6B68AE6CULL,
		0xA318DC6BFA2FEEFDULL,
		0xE5719E4201809F65ULL,
		0x46DCD6F337FB0975ULL,
		0xA9A2D9FDF40E625AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x71FEE58742EBD67DULL,
		0x8F4A1FA3F6700695ULL,
		0x3D6C8238B4E2EF61ULL,
		0xC7888719D1FF3577ULL,
		0xD4AB16C11065D0AEULL,
		0x447C3C972DD0D4E1ULL,
		0xB4273E84B53B000DULL,
		0x1882573F64E015E0ULL
	}};
	t = 1;
	printf("Test Case 320\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 320 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -320;
	} else {
		printf("Test Case 320 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA36FFE3CC7AF3AB0ULL,
		0x0A3067DC14864230ULL,
		0xC72DDF221145070BULL,
		0x793AFC6C5B3FC39EULL,
		0x36EF19C4DD729D31ULL,
		0xED417B47A5A50205ULL,
		0xD4183B4FC752C7B3ULL,
		0x542099A08896409FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA36FFE3CC7AF3AB0ULL,
		0x0A3067DC14864230ULL,
		0xC72DDF221145070BULL,
		0x793AFC6C5B3FC39EULL,
		0x36EF19C4DD729D31ULL,
		0xED417B47A5A50205ULL,
		0xD4183B4FC752C7B3ULL,
		0x542099A08896409FULL
	}};
	t = 0;
	printf("Test Case 321\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 321 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -321;
	} else {
		printf("Test Case 321 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4EF02879806A0D47ULL,
		0x361F65911E4A9990ULL,
		0x454F357CDEAF541FULL,
		0xF01B380B306EA376ULL,
		0x0523F50C4392BE82ULL,
		0x8CEA672AFAE382BAULL,
		0x767B7FA1927233ECULL,
		0x9D41463CB115A513ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x641D118B67949607ULL,
		0xDE7AF6F0333368E2ULL,
		0x162214868E915485ULL,
		0x3E0EF27A0F85061FULL,
		0x58F79EBE5022833EULL,
		0xA4C43367D01EC29FULL,
		0x7FAF73622237F03BULL,
		0xF78B355A959B2950ULL
	}};
	t = -1;
	printf("Test Case 322\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 322 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -322;
	} else {
		printf("Test Case 322 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA0A7264B979F5B38ULL,
		0xCBBB933F249D7DE9ULL,
		0x7012996143088FC1ULL,
		0x81949EB7DB772B2AULL,
		0x8869C2E2DC063BCAULL,
		0x481D5EC04524BA52ULL,
		0x8270E0EEDABAB875ULL,
		0x9B8FB208A4B08B06ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x383E36CF4E148ECCULL,
		0x5D0390DC861F8F05ULL,
		0xBF21B6A3FC2B3327ULL,
		0x690AD390100A0667ULL,
		0x6FC53E3A6671E2F0ULL,
		0x079365C2509B0E76ULL,
		0xA2B3EC509FB7B28DULL,
		0xFCCB5318AEBD267EULL
	}};
	t = -1;
	printf("Test Case 323\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 323 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -323;
	} else {
		printf("Test Case 323 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5C46F9EF3AF58999ULL,
		0x938580E501CF3886ULL,
		0x13570354456EEB4CULL,
		0x6D6CB8D60F17762EULL,
		0x232791F82C4649A2ULL,
		0xD96165AEE8EF2DD5ULL,
		0xA336EECAB69EE18DULL,
		0x09C6782FE4557A0DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDC46B9F3C42807EFULL,
		0x95F7F55B1E22470AULL,
		0xC6E5C7FF4803DD0BULL,
		0xB9FB55B02E71D792ULL,
		0xFFF13FAEBD809979ULL,
		0x0D00A9218D4D24C5ULL,
		0xA88D54BC4C225801ULL,
		0x0E24480EB460C179ULL
	}};
	t = -1;
	printf("Test Case 324\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 324 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -324;
	} else {
		printf("Test Case 324 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x369F89C9A09DB0B4ULL,
		0x120F97EDFE0DC736ULL,
		0xEB2A207D45555E16ULL,
		0x643DCC03AA68102EULL,
		0x591443645F98C43FULL,
		0x3C42614F487148B1ULL,
		0xC11CE60759457069ULL,
		0x7AC6D84B5F361061ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x369F89C9A09DB0B4ULL,
		0x120F97EDFE0DC736ULL,
		0xEB2A207D45555E16ULL,
		0x643DCC03AA68102EULL,
		0x591443645F98C43FULL,
		0x3C42614F487148B1ULL,
		0xC11CE60759457069ULL,
		0x7AC6D84B5F361061ULL
	}};
	t = 0;
	printf("Test Case 325\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 325 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -325;
	} else {
		printf("Test Case 325 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE73E7859AB464250ULL,
		0x5701826979EF9A7CULL,
		0xEAE1955DA05E704BULL,
		0x87D668F0DD5FA125ULL,
		0x1AD1109C221930A4ULL,
		0xD4F37DB4F8BC91AFULL,
		0x014CF63C3CB3F5F6ULL,
		0x9E94831BF80B1D14ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1E123ED8BF2D4856ULL,
		0xED38E0D343B66C4DULL,
		0xBBCE7ABFBEE2D8C9ULL,
		0xDC8BC0690B2AC08DULL,
		0x94C9FBB4D1BDA480ULL,
		0x773774903002C2E8ULL,
		0xB3235C8CC3C00FBCULL,
		0xB535AD7D5B411167ULL
	}};
	t = -1;
	printf("Test Case 326\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 326 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -326;
	} else {
		printf("Test Case 326 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x93E812E798F92A73ULL,
		0x1E2D13FA6B0D625DULL,
		0xEC9BA4111263EBA7ULL,
		0xBF87CEB1DA0065DCULL,
		0xE82444CE947089C0ULL,
		0xB806C7BD80A23869ULL,
		0x5D283811CE4AF64CULL,
		0xC3BA245972EF45B6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2A7DB11F325E6D7FULL,
		0x018AC32EB892D496ULL,
		0x2FF172759E3FEB9DULL,
		0xC38F837FA9F26583ULL,
		0x768A299DAF8C8D06ULL,
		0xFD18289E7D348778ULL,
		0x9C6EB24CD2909389ULL,
		0x8FC337C0723F9356ULL
	}};
	t = 1;
	printf("Test Case 327\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 327 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -327;
	} else {
		printf("Test Case 327 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD49B25225C9C6361ULL,
		0xAA7E2C2EB74EC4A3ULL,
		0x1C61DEC3E9192E6DULL,
		0x0AD15EE3B1AABFD1ULL,
		0x524BB05E77DA5AC4ULL,
		0x5198980F6697F370ULL,
		0x97C203B73B7852EBULL,
		0x7083AB942D875A56ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4E79CAB9F91769B7ULL,
		0x4CDF98CA3DB966C6ULL,
		0x5D60ADA262FAF211ULL,
		0x24B51376ADF0AEEBULL,
		0x65ED8BE204457A75ULL,
		0x8DBEC580AE4E9BB6ULL,
		0x819348E72C92362AULL,
		0xE8C5B65CEBDDFEDAULL
	}};
	t = -1;
	printf("Test Case 328\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 328 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -328;
	} else {
		printf("Test Case 328 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x56BB75C4ED5C13C9ULL,
		0x55774BC20F4E5BA4ULL,
		0x9F4B8FA3AB372CDFULL,
		0x784E8E238828F475ULL,
		0xA1C48975EE18872CULL,
		0x7C53D868D67B29A0ULL,
		0xEAE3B4E9C41C8552ULL,
		0x333E5A54EDFF502CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x56BB75C4ED5C13C9ULL,
		0x55774BC20F4E5BA4ULL,
		0x9F4B8FA3AB372CDFULL,
		0x784E8E238828F475ULL,
		0xA1C48975EE18872CULL,
		0x7C53D868D67B29A0ULL,
		0xEAE3B4E9C41C8552ULL,
		0x333E5A54EDFF502CULL
	}};
	t = 0;
	printf("Test Case 329\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 329 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -329;
	} else {
		printf("Test Case 329 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x96AE82250D0E672AULL,
		0x73F4D4FE2FA29BB2ULL,
		0xF683608E7BA2E237ULL,
		0xED9700445AC88078ULL,
		0xE97792B33F9D3760ULL,
		0xAD98E4E920D74FA7ULL,
		0x005F90F0C9334D7DULL,
		0x5365B04EA49D34F7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBF4F4E433AE26B99ULL,
		0xD4668002EE49581DULL,
		0xC3D793DFE6340E8DULL,
		0xA8F25375B736AA98ULL,
		0xBB8801D8E996A668ULL,
		0xED4534C65595B362ULL,
		0x99F7F3752598DECDULL,
		0x744B54D95C8E94A2ULL
	}};
	t = -1;
	printf("Test Case 330\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 330 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -330;
	} else {
		printf("Test Case 330 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA9335E1AA534F34AULL,
		0xB527BCA94D01D5C4ULL,
		0x3192A21AFA336593ULL,
		0x5C534AF110CEFEAFULL,
		0xE95DC94E88DE340AULL,
		0xCCE23D50C352AE99ULL,
		0x7EE8B3896C5396EAULL,
		0x8E441A18500E18E2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x854976EBBA6E0069ULL,
		0x2A4937C7D3A6E0E4ULL,
		0x567F2A2469FEEBA5ULL,
		0xE5E8A9093CF0ACD9ULL,
		0xBB596659D12C8148ULL,
		0xE45F35CB5A3D5639ULL,
		0x3DBEE77D8B913663ULL,
		0x868C9FD3EA3A18B1ULL
	}};
	t = 1;
	printf("Test Case 331\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 331 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -331;
	} else {
		printf("Test Case 331 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEE48FB43FBF04507ULL,
		0xF5EE0D06E9A6904CULL,
		0x7C6D168563D1A8BEULL,
		0x691C07298A18C38BULL,
		0x6B206CAD2D207904ULL,
		0x67DE8F62C1533D21ULL,
		0xC9628DA27737BE28ULL,
		0xF6874D67DCE7E69CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9EFDECBA8E9578B8ULL,
		0xDB6F42C56E8792E3ULL,
		0x49C321C068B2D701ULL,
		0x837B908EBA4B7A6EULL,
		0x129AB9C8B2C891FFULL,
		0x39FDEC9F2247C969ULL,
		0x5D6586A019C24605ULL,
		0x6C431F6B6224B8BCULL
	}};
	t = 1;
	printf("Test Case 332\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 332 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -332;
	} else {
		printf("Test Case 332 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x653C126E89FD3990ULL,
		0xEE6BA44B5C53EA5DULL,
		0xC6DB179B781D1050ULL,
		0x3C48E8D64AEE1B13ULL,
		0x8E10879FCD9C70B9ULL,
		0xA58F1B6A82A61E85ULL,
		0x286C4EDFF13A659BULL,
		0xC4F87CF932259A62ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x653C126E89FD3990ULL,
		0xEE6BA44B5C53EA5DULL,
		0xC6DB179B781D1050ULL,
		0x3C48E8D64AEE1B13ULL,
		0x8E10879FCD9C70B9ULL,
		0xA58F1B6A82A61E85ULL,
		0x286C4EDFF13A659BULL,
		0xC4F87CF932259A62ULL
	}};
	t = 0;
	printf("Test Case 333\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 333 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -333;
	} else {
		printf("Test Case 333 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD13B6CB146A5F19AULL,
		0x1E2A28D18F432E3DULL,
		0xBF95A3CAA85939BBULL,
		0x993BC83F4521BB9FULL,
		0xE6F24FA42E08576BULL,
		0xD2387D3C47EE010AULL,
		0x277E043D55AF6DA8ULL,
		0x4114D64BE5C7030AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF57A9F140F8374ADULL,
		0x74E6752091678CCAULL,
		0xEBB103B415037A77ULL,
		0xDEBF81F63DCA29F6ULL,
		0xCBAC69F1EEDA73B2ULL,
		0xA63B18392D13824AULL,
		0x3DD6CD6627DAB092ULL,
		0x2A1AF4CF24A8D8B5ULL
	}};
	t = 1;
	printf("Test Case 334\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 334 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -334;
	} else {
		printf("Test Case 334 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4D6ED68630B79672ULL,
		0xC3AAD8BB8F7A751DULL,
		0x0FBB130D2DF09951ULL,
		0xA7190A7C73C9A54EULL,
		0xE9AE2CF348529711ULL,
		0xA62CD88853D5FEF2ULL,
		0x474FF310984DE8D3ULL,
		0x4A159016DB3DBC9CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8EAF5C36BA289B11ULL,
		0x79F9F7120AF6B04FULL,
		0x15C3048F41C12FEAULL,
		0x79E6453E6EE65FD6ULL,
		0x9297F736A3826E11ULL,
		0x916F7E5206040F10ULL,
		0xB5EECE2FBCD06B29ULL,
		0x353B3AEBDB7C080CULL
	}};
	t = 1;
	printf("Test Case 335\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 335 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -335;
	} else {
		printf("Test Case 335 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x03D39C3C62438AD7ULL,
		0x808D27472F550A66ULL,
		0x1ABB4FBA161B8255ULL,
		0xAF5F06148F2CE3ECULL,
		0xF60C1E378C7F3EB1ULL,
		0x5D433A7916DCDD2FULL,
		0xCCEB888EFF923509ULL,
		0x83069CE9E464332DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA1395A2076D10834ULL,
		0x433419F280AC88D0ULL,
		0xB57361348A9007F7ULL,
		0xB7BB02A27366C79DULL,
		0x3C71E3D9B886F2C7ULL,
		0xE4BC28811AB6398DULL,
		0xFDA63FB320D4BC33ULL,
		0x3788677125B3D0B6ULL
	}};
	t = 1;
	printf("Test Case 336\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 336 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -336;
	} else {
		printf("Test Case 336 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6A499D36545A5EA5ULL,
		0x427889C0AE742154ULL,
		0xA883ADA7907456FDULL,
		0x7BB392479B5C10ACULL,
		0xD3165E52C5CA022EULL,
		0xD8FE860143DC38ADULL,
		0xD5C3EF1B884EB891ULL,
		0x5F0942D0156904DEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6A499D36545A5EA5ULL,
		0x427889C0AE742154ULL,
		0xA883ADA7907456FDULL,
		0x7BB392479B5C10ACULL,
		0xD3165E52C5CA022EULL,
		0xD8FE860143DC38ADULL,
		0xD5C3EF1B884EB891ULL,
		0x5F0942D0156904DEULL
	}};
	t = 0;
	printf("Test Case 337\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 337 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -337;
	} else {
		printf("Test Case 337 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x24A2F507DAC9423CULL,
		0xF0A582AEF0117AFAULL,
		0x7F9D62EBF05CCCB8ULL,
		0x10D6920AB495D9EEULL,
		0xC79AD719C99C63E1ULL,
		0xB482B5D9380EA7EBULL,
		0x7516E316FAF42672ULL,
		0x646BF952C57AB19DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC3DF930A2854DC0EULL,
		0x5CACF8F3ECBBC12FULL,
		0xA96ABB6982B21C18ULL,
		0x2991CE981013D41AULL,
		0x610799B0BBB89454ULL,
		0xEB95814A4EE1D780ULL,
		0xCADC718A4C681CC6ULL,
		0xC733E431A68181DFULL
	}};
	t = -1;
	printf("Test Case 338\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 338 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -338;
	} else {
		printf("Test Case 338 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5C43D689BA695CA4ULL,
		0x2E88DA8BC6B5B779ULL,
		0x8B72F1F7B5DC5EACULL,
		0x475E5E9FD49CD4BAULL,
		0xC629D9CA115B4EB5ULL,
		0x609B54B22860A623ULL,
		0x52921667D62F5477ULL,
		0xDC3C7B9DE0391D05ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x093AA0F5270AD8BFULL,
		0x0E60126F29A5CB61ULL,
		0xD76ECB423EF259A8ULL,
		0xCC580B80ECCC5280ULL,
		0xD9B84C50D35E7471ULL,
		0xD442DF917439EE18ULL,
		0x27CE93E7205A5293ULL,
		0xD8F951A145B1CF06ULL
	}};
	t = 1;
	printf("Test Case 339\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 339 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -339;
	} else {
		printf("Test Case 339 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1D910FDC2E834FECULL,
		0x0462410204E7F273ULL,
		0x7B76D0307BA84973ULL,
		0x733D715C970F2056ULL,
		0xD9972F6A60043370ULL,
		0x9E677010EB275396ULL,
		0x372EB142F451B3B6ULL,
		0x01DF388D13CD8B88ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFC1B3C1768369F4FULL,
		0x1EC9E76B220B66A8ULL,
		0x97DE98C02EE4FD48ULL,
		0x829F500D0F6B5252ULL,
		0x855D1EB58980E143ULL,
		0xE55260D3BF5A40CEULL,
		0xEBC6323EE616D515ULL,
		0xBF338774EF9CB9CCULL
	}};
	t = -1;
	printf("Test Case 340\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 340 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -340;
	} else {
		printf("Test Case 340 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7B006B3A67255889ULL,
		0x71EE62A5785BBCDAULL,
		0xC67462B14F0C0A5EULL,
		0xCDB6D7A035E5136FULL,
		0xDF59CFD33B99DC9CULL,
		0xA3F8E20B62C15DA8ULL,
		0x2169C5367B54D910ULL,
		0x2A428C85B115210DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7B006B3A67255889ULL,
		0x71EE62A5785BBCDAULL,
		0xC67462B14F0C0A5EULL,
		0xCDB6D7A035E5136FULL,
		0xDF59CFD33B99DC9CULL,
		0xA3F8E20B62C15DA8ULL,
		0x2169C5367B54D910ULL,
		0x2A428C85B115210DULL
	}};
	t = 0;
	printf("Test Case 341\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 341 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -341;
	} else {
		printf("Test Case 341 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x62E872B2DCEB506FULL,
		0xF560A19E524906A5ULL,
		0x8E525F61A1B6A4B7ULL,
		0xE304ACF7C7A42E4DULL,
		0xABD5194CA70AFDA0ULL,
		0xD786613F6D3C205EULL,
		0x2048BCC7A3545D00ULL,
		0x2EEABA9C8F577A8AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x778DC91EE74991E9ULL,
		0xBADEB46D1F4401EAULL,
		0x4DA272A1E680A886ULL,
		0xCCBFCF59A96DA8DEULL,
		0x670A6CE046FBDC3DULL,
		0xEC86FB34E90C03EEULL,
		0x5F3C40CBA14C5230ULL,
		0xB0E856C342689826ULL
	}};
	t = -1;
	printf("Test Case 342\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 342 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -342;
	} else {
		printf("Test Case 342 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x46A1D8BA3D43C064ULL,
		0xDCCD0A2212B0408EULL,
		0x9556C9DDF43915B3ULL,
		0x4510322159C6017CULL,
		0x9678A9D8F7AE6393ULL,
		0x6E04949FB647BBC1ULL,
		0x8733FEB554473C92ULL,
		0xAB5E7FE12BF49941ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE424B207C9901666ULL,
		0xA01EB00543ED7FD1ULL,
		0x67D7533BB7A5494EULL,
		0xB3D8F175611CD4B7ULL,
		0xE9E0134BC65EDD27ULL,
		0x8CA44413256EF26CULL,
		0xF41F32E2C6944AEAULL,
		0x10E1B20CA5881063ULL
	}};
	t = 1;
	printf("Test Case 343\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 343 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -343;
	} else {
		printf("Test Case 343 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x94D5296763C0B292ULL,
		0xCBC4B0E2C6156FCCULL,
		0x9E791A3A57F8FD5FULL,
		0x1867E7A8CCCEC662ULL,
		0x3B56F1E676C231DAULL,
		0xFF8BC522533B0074ULL,
		0x585CE463BBB48F71ULL,
		0xD6ECD3AE77E91E97ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x373D033E340A4C66ULL,
		0xEAA1B70560255EE6ULL,
		0x2BC3C541E4A3D494ULL,
		0xF37560C54858F9D1ULL,
		0x5F8F24D6EEA51D1CULL,
		0x2E566591A4A90C3DULL,
		0xC7042631AA1E91B4ULL,
		0x34D18A769B642F86ULL
	}};
	t = 1;
	printf("Test Case 344\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 344 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -344;
	} else {
		printf("Test Case 344 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2A7C699F5DF3792DULL,
		0x73ECF3CE3EE36C64ULL,
		0x656FE1AA55AC3824ULL,
		0xA66B54F6455B6E05ULL,
		0x9657C24B4B9DD589ULL,
		0x252F7A1C29D59F84ULL,
		0x5A2906B927C8CAF4ULL,
		0xBFCBD6A0C21D21BEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2A7C699F5DF3792DULL,
		0x73ECF3CE3EE36C64ULL,
		0x656FE1AA55AC3824ULL,
		0xA66B54F6455B6E05ULL,
		0x9657C24B4B9DD589ULL,
		0x252F7A1C29D59F84ULL,
		0x5A2906B927C8CAF4ULL,
		0xBFCBD6A0C21D21BEULL
	}};
	t = 0;
	printf("Test Case 345\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 345 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -345;
	} else {
		printf("Test Case 345 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0BF0BCD3DFC5E82BULL,
		0x07BC7429AD2F0371ULL,
		0xA7562AABF3AA131CULL,
		0x4343B2BC8FB2ACE9ULL,
		0xC21F8E6E2EC2C311ULL,
		0x82B024E98F4AAD74ULL,
		0x5B3AA1A709294328ULL,
		0x3ED70C663B2D8E47ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9AD89A7284731D91ULL,
		0xF84BA07920A92789ULL,
		0x7DB0A2CADE883742ULL,
		0xC842D2232617BCDAULL,
		0x23075D121B980395ULL,
		0x8DBE74A6F9DC1F3FULL,
		0x5652FE0D137A1D8DULL,
		0x09D51004A572C446ULL
	}};
	t = 1;
	printf("Test Case 346\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 346 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -346;
	} else {
		printf("Test Case 346 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD23EBB3C6075EA80ULL,
		0x0BF57171A7857ED8ULL,
		0xA8E1A34DB45BD92AULL,
		0xF96723F265A730F4ULL,
		0x2FA26F27B37900A5ULL,
		0x58E2D2D60C1AC430ULL,
		0x95290AF02C552D71ULL,
		0xCF4E96D2F59D39BFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2ADCAD7419EA33F1ULL,
		0x257DFB812DD3E9DFULL,
		0xCB1259F3CA7D89A3ULL,
		0x49425EF12C71A567ULL,
		0x442075E3BD627109ULL,
		0xABA43FD922690644ULL,
		0x64C3663A9A6D3B9AULL,
		0x4FE6FD59DD190D52ULL
	}};
	t = 1;
	printf("Test Case 347\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 347 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -347;
	} else {
		printf("Test Case 347 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9D6A79A511065C94ULL,
		0x753B02E7F6DB0DB0ULL,
		0x3DDEF65A6704A91FULL,
		0xEF19BDF6D1D86DCCULL,
		0x36D12A2C6D824569ULL,
		0xBE2A9E14ECCAFB17ULL,
		0xD81996EA39CBDC92ULL,
		0x0398C3969C8E1306ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x108E86F4975C952EULL,
		0x4223A5DEC11A2435ULL,
		0x9BA5F612EE7749A7ULL,
		0x0385C3996237C0F1ULL,
		0x776D79D32C41BDFCULL,
		0xAA451A378A03B787ULL,
		0x5DDECAFA4234BC70ULL,
		0x3E1A2CC5FB8FEC62ULL
	}};
	t = -1;
	printf("Test Case 348\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 348 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -348;
	} else {
		printf("Test Case 348 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x916221AAEF51680FULL,
		0x64D00FE96DED3BD5ULL,
		0x3F7872008280C603ULL,
		0x1FB2DE00208F6729ULL,
		0x8AE2677480557962ULL,
		0x19E4182242BF1F97ULL,
		0x457CD21A96735444ULL,
		0x52B5341EF4E6FFEEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x916221AAEF51680FULL,
		0x64D00FE96DED3BD5ULL,
		0x3F7872008280C603ULL,
		0x1FB2DE00208F6729ULL,
		0x8AE2677480557962ULL,
		0x19E4182242BF1F97ULL,
		0x457CD21A96735444ULL,
		0x52B5341EF4E6FFEEULL
	}};
	t = 0;
	printf("Test Case 349\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 349 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -349;
	} else {
		printf("Test Case 349 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF0A291DA7D3F9C83ULL,
		0x25519DE0A2276C3DULL,
		0x9C098083E33DBD81ULL,
		0x4341572BD0A19094ULL,
		0x80EA10BD5C4375CCULL,
		0x063A7CE315DDE419ULL,
		0x2B809D3006A4F222ULL,
		0xD4BE506FAED3508FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF7EAB94D477F610DULL,
		0x0046EC5CB2CA1C3DULL,
		0xAA9AC88BC29D245FULL,
		0x63575A2C33846351ULL,
		0xA0994FF93955D957ULL,
		0xA237AA0BCB2BF07DULL,
		0xEB540A9B73759A7EULL,
		0xE3CABD0D60AC2395ULL
	}};
	t = -1;
	printf("Test Case 350\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 350 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -350;
	} else {
		printf("Test Case 350 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x606DBF15B9101374ULL,
		0xE5F39F73084D8A84ULL,
		0xC4FBB28C560CCACCULL,
		0x28810D89E544CFBBULL,
		0x5822BBCBD1A6AC4AULL,
		0xA16B8FB31D6880CCULL,
		0x176CF8F743E04A0BULL,
		0x343ACDAF06746D2CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0D817C5F49FB416BULL,
		0x281D568FBC8EEC48ULL,
		0xA097AA4516EB3F4DULL,
		0x6522DCD20FFB0C2DULL,
		0x2BF1CF8834CD15B9ULL,
		0x26BFA7A87980D93BULL,
		0x01DC51BBE77FFCDEULL,
		0xDC5344E9286B38B4ULL
	}};
	t = -1;
	printf("Test Case 351\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 351 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -351;
	} else {
		printf("Test Case 351 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3A5246A354CE5348ULL,
		0x40971E2FA924C7CDULL,
		0xBC677D4212BAD4A1ULL,
		0x6D8FC83147387E09ULL,
		0x9B25AF3487BC507CULL,
		0x5CECE0D4397A0A2DULL,
		0xF41FD48DFEB72E85ULL,
		0xFF327528B848AB3CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x92CB136F27CCC994ULL,
		0x8204447975B298B7ULL,
		0x976DCBCC27998AC4ULL,
		0x2DB3D39E13FCBA23ULL,
		0x94944BE95714926FULL,
		0xF856AE4776991634ULL,
		0x087A6A47916DF27CULL,
		0xC85D2526E054F0BDULL
	}};
	t = 1;
	printf("Test Case 352\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 352 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -352;
	} else {
		printf("Test Case 352 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x122F5BB181C7F3EEULL,
		0x89E90B28D51455FBULL,
		0x2FE131B94261438BULL,
		0x7D21FCD5A7707CCFULL,
		0xB2DB58983DCA5891ULL,
		0x4F226F534230B8E6ULL,
		0xE67E6C6326D5F75EULL,
		0xD9A53095FD450A1FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x122F5BB181C7F3EEULL,
		0x89E90B28D51455FBULL,
		0x2FE131B94261438BULL,
		0x7D21FCD5A7707CCFULL,
		0xB2DB58983DCA5891ULL,
		0x4F226F534230B8E6ULL,
		0xE67E6C6326D5F75EULL,
		0xD9A53095FD450A1FULL
	}};
	t = 0;
	printf("Test Case 353\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 353 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -353;
	} else {
		printf("Test Case 353 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x670F245045986E13ULL,
		0xD53B158842B7C7D9ULL,
		0x77D1788FB97FBC09ULL,
		0x04ADD01518814F89ULL,
		0xA952538780F6150CULL,
		0x13372D041697CD15ULL,
		0xFD1BD57FF2AD1DADULL,
		0x7DF9C1F5994DADD9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD04FDE23F194F138ULL,
		0xDA236355FB3DDBA6ULL,
		0xC6BFB79333E13B8AULL,
		0x5EE58F477312C60EULL,
		0xB367832813E695CBULL,
		0xD5D1690C19A387C1ULL,
		0xC781CED78EC073B3ULL,
		0xB83D2D035DEAC7C3ULL
	}};
	t = -1;
	printf("Test Case 354\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 354 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -354;
	} else {
		printf("Test Case 354 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9BB67900B6BC7D62ULL,
		0x670F6F12932967DCULL,
		0xCF69182B40F146B5ULL,
		0xFA71B17A9D9CB1E4ULL,
		0x3A63816355414174ULL,
		0x34E7547E98BBF813ULL,
		0x831AEB4AF704EBBAULL,
		0x96130F871A1E658BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD4DF1842E9FDB1BEULL,
		0x609D3FF76EDF0275ULL,
		0x6D7A93B752D3A2A0ULL,
		0xF12C7C6FF36E4FACULL,
		0x40C0554965016028ULL,
		0x33BC737CA921C2ADULL,
		0x6C3686108210211FULL,
		0x5B6C50E698FB95C5ULL
	}};
	t = 1;
	printf("Test Case 355\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 355 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -355;
	} else {
		printf("Test Case 355 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x52005BF5DA1B4BBCULL,
		0xC66FE7627EDF55ABULL,
		0x020E10BBD0C943FCULL,
		0x14E405F3CD75C06EULL,
		0xBD32A002BA8C5800ULL,
		0x68922CD0B2586287ULL,
		0x74107AA8E6E64426ULL,
		0xFBDBFC45508B9EA3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC70BDE09AB4C1E87ULL,
		0x31F4177CDD9B8338ULL,
		0xF63618D6C7633726ULL,
		0x21B02504CFFEE947ULL,
		0xA7F75658101CDF3DULL,
		0xE82027CE59D7EA03ULL,
		0xDD91115951312D2CULL,
		0x0BA81A2BCCCFA341ULL
	}};
	t = 1;
	printf("Test Case 356\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 356 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -356;
	} else {
		printf("Test Case 356 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x252939C7E132F84BULL,
		0x1F9FD3EB48307C86ULL,
		0x2ED0D19ECBA09C90ULL,
		0xF9A5B69B9AD0AC26ULL,
		0xDA1975C2CE8ABF30ULL,
		0x0F4CC9765D0FD0CFULL,
		0xDDC1702F8EF40F8BULL,
		0xE333F1A2E9258DA2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x252939C7E132F84BULL,
		0x1F9FD3EB48307C86ULL,
		0x2ED0D19ECBA09C90ULL,
		0xF9A5B69B9AD0AC26ULL,
		0xDA1975C2CE8ABF30ULL,
		0x0F4CC9765D0FD0CFULL,
		0xDDC1702F8EF40F8BULL,
		0xE333F1A2E9258DA2ULL
	}};
	t = 0;
	printf("Test Case 357\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 357 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -357;
	} else {
		printf("Test Case 357 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8F5BC52896A94C13ULL,
		0xE7F63797689A9C35ULL,
		0x11B16174802CA35CULL,
		0x978E8B7102A9AC92ULL,
		0x3997C3DA49FC0D75ULL,
		0x653A26CADE977152ULL,
		0x0A576CFC5F41F6CDULL,
		0xA9161160AD673B0EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x00AC4FB9344E81FAULL,
		0x9BF6CD8C6AC90F8EULL,
		0x3EDDF95269D0641EULL,
		0x87BCA6A9A4280226ULL,
		0x7922BE0FAE2E9882ULL,
		0x43E810C790C062E0ULL,
		0x5C53F7431A58D243ULL,
		0xF7C838448CCF8FFDULL
	}};
	t = -1;
	printf("Test Case 358\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 358 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -358;
	} else {
		printf("Test Case 358 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0881900ADA8D3AF2ULL,
		0xF5B580550F99F069ULL,
		0xA534BCD0CE7300A7ULL,
		0xAEF4F261575BF75EULL,
		0x8351F318F2738B11ULL,
		0xC6226C199E3481DFULL,
		0x3D4F29DC5E6DD66CULL,
		0xB46F8F15B372F875ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA25CD1D5EAE97B6CULL,
		0x7D24B0A2C0408B30ULL,
		0x0B9840B7B0E365D3ULL,
		0x378DE739697B59E6ULL,
		0x95A05ADB9875254DULL,
		0x50F1A90E6AAFFC94ULL,
		0xFA965B03AC16CE84ULL,
		0xCC96F72383D0C512ULL
	}};
	t = -1;
	printf("Test Case 359\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 359 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -359;
	} else {
		printf("Test Case 359 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD71497B16C7C43C7ULL,
		0xB654E207A8B20C78ULL,
		0x1165AE67FD8693E7ULL,
		0xB933F62D5EA43F04ULL,
		0xD8AA32824D36B0D2ULL,
		0xE838C8BC82CCE360ULL,
		0x2AA2785585F57880ULL,
		0x1B1757518078BC00ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2D85C139907536F2ULL,
		0x73AC0BFC2B8B07FBULL,
		0x32D3F7EFB5DA1523ULL,
		0xEACC8048EC4EB6C1ULL,
		0xB0E2F53FACE155A4ULL,
		0xEA32C598AFCFC3E3ULL,
		0xDF4720811A04F294ULL,
		0xEC57355EE7C3EE10ULL
	}};
	t = -1;
	printf("Test Case 360\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 360 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -360;
	} else {
		printf("Test Case 360 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA43C065E0675DEA0ULL,
		0xBA999116F28D4882ULL,
		0x28D4898E80D9E93CULL,
		0xFE947A6668CC0875ULL,
		0x6F92B8E687E6A710ULL,
		0x49EE39AA8354728DULL,
		0x49589FD91FD93264ULL,
		0x99855BF6C6D2A996ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA43C065E0675DEA0ULL,
		0xBA999116F28D4882ULL,
		0x28D4898E80D9E93CULL,
		0xFE947A6668CC0875ULL,
		0x6F92B8E687E6A710ULL,
		0x49EE39AA8354728DULL,
		0x49589FD91FD93264ULL,
		0x99855BF6C6D2A996ULL
	}};
	t = 0;
	printf("Test Case 361\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 361 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -361;
	} else {
		printf("Test Case 361 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0214FFE17052141DULL,
		0xE59568BB541BBAAEULL,
		0xBE0179DD1CDF387EULL,
		0x905ED49F2F304BEFULL,
		0xECAE2D774234496DULL,
		0xFD3ABBD2610007A5ULL,
		0x010F6269E4ECDC42ULL,
		0x081A7EE77CA56752ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x411E59DAEDAB85A6ULL,
		0xF751FA42BCFC2ABDULL,
		0xB4A55E2D7969B022ULL,
		0x4E0D43E21E939DCFULL,
		0xCF7E4AC9FD25E003ULL,
		0xA7C8849B9BDEB195ULL,
		0xDACEFA88B9F7F8F8ULL,
		0x2E9018BEB959E397ULL
	}};
	t = -1;
	printf("Test Case 362\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 362 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -362;
	} else {
		printf("Test Case 362 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x945769FB05D84D25ULL,
		0x0EB0C505711EC3B2ULL,
		0x8057307142971E7EULL,
		0x93FFDC20AAD9D24EULL,
		0x0DBA354FF5378065ULL,
		0xAE851165AEEA546DULL,
		0xCD8E01B2C509B5F7ULL,
		0x04643137C45004B3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2C8B1EC7A43CDC0AULL,
		0x5DAA5F2E0D4DA429ULL,
		0x9C589DA0999BEB36ULL,
		0x6EC013FB3ECC7D63ULL,
		0x8D008A6CFBE4DDB2ULL,
		0x894C19EE1FFFE7F7ULL,
		0x1F32034CB47BE3C8ULL,
		0x33AD4C394E735810ULL
	}};
	t = -1;
	printf("Test Case 363\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 363 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -363;
	} else {
		printf("Test Case 363 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF2AC166E62B670E1ULL,
		0x0A97F0EC766C5F85ULL,
		0xDA912B1BCE814FCBULL,
		0xBE5D9E7C58813E90ULL,
		0xB443807AC310721EULL,
		0xF81B4D1C13722E77ULL,
		0x4536724682202628ULL,
		0xB571E8893EB69391ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC630293AC85920D8ULL,
		0x1DB60ED43280A376ULL,
		0x6B7ECBDC3A66B6A2ULL,
		0xB26C27A095BFF722ULL,
		0xE33356D2262AEE8EULL,
		0x92406664FC86ABB3ULL,
		0x26AC6CA5218E2895ULL,
		0x1D147D52F7D570F7ULL
	}};
	t = 1;
	printf("Test Case 364\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 364 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -364;
	} else {
		printf("Test Case 364 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCEA16E2B694BD7A5ULL,
		0x3E6CE909F5369842ULL,
		0x0CA330D61155C2B1ULL,
		0x29231832D369C2D4ULL,
		0x5CC1878672C7F829ULL,
		0xD6EA7E82B46A4C77ULL,
		0x61D06AAB0998549CULL,
		0x96C26E6389F02221ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCEA16E2B694BD7A5ULL,
		0x3E6CE909F5369842ULL,
		0x0CA330D61155C2B1ULL,
		0x29231832D369C2D4ULL,
		0x5CC1878672C7F829ULL,
		0xD6EA7E82B46A4C77ULL,
		0x61D06AAB0998549CULL,
		0x96C26E6389F02221ULL
	}};
	t = 0;
	printf("Test Case 365\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 365 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -365;
	} else {
		printf("Test Case 365 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9F66814F2EB351D0ULL,
		0x9366C5B16B883DE8ULL,
		0x86F0A8154F0AB6BBULL,
		0x17749DD61970E7BDULL,
		0xE3224FAD1D436CE4ULL,
		0x3E8F150E809B825EULL,
		0xA27BBCC192E6C6F9ULL,
		0x08DDEA87DDDCDF9EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6C2BDD361C01FFDFULL,
		0xC3EE537ACBBC4827ULL,
		0x33A3B30FB184B990ULL,
		0x059E3738247560E3ULL,
		0x99834BC35DB0769AULL,
		0x23C954D9C0358120ULL,
		0x72CA99A825428DBEULL,
		0x339466288CEEACC9ULL
	}};
	t = -1;
	printf("Test Case 366\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 366 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -366;
	} else {
		printf("Test Case 366 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF07EF525362FBE45ULL,
		0x346DC55D0C650BF0ULL,
		0xD06B2CFA4B5AE8F9ULL,
		0x142667AE8547C0D3ULL,
		0x7D785055B40DAD88ULL,
		0xCE85ABB7CFEDAD02ULL,
		0xD9D8B8E68419DAABULL,
		0x3B56BB4BEFD6435EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD943E684F8E07E7AULL,
		0x4D3DB906A9BF6926ULL,
		0x8D9EBB6AE65E3350ULL,
		0x959112750204D88EULL,
		0xDA82F220068F0D34ULL,
		0x2A8CA54FF0936ED9ULL,
		0x90862A2AB368C9E2ULL,
		0x6B317FAC11C2C6DCULL
	}};
	t = -1;
	printf("Test Case 367\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 367 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -367;
	} else {
		printf("Test Case 367 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x750D2913CACD7148ULL,
		0xC5759741EDABBA0AULL,
		0xDC11CA29017721C8ULL,
		0x8982485A12585A98ULL,
		0xEA1E076D873B1B7CULL,
		0xA14BDB55219CDE5FULL,
		0x72195C826F164E2FULL,
		0x508461A179987894ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x41D26D3A7DA41900ULL,
		0xE64FA172E5954EAEULL,
		0x61D02F5E4F6FB40AULL,
		0x3B2E4317EE1D0DB9ULL,
		0x51C67CDEFF9E0BC8ULL,
		0x108FB94FD04976B1ULL,
		0x5DF3590422C5D06BULL,
		0x2F92161235819E8CULL
	}};
	t = 1;
	printf("Test Case 368\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 368 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -368;
	} else {
		printf("Test Case 368 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD68417C948885A71ULL,
		0x725C317C58AF8D90ULL,
		0x7726325CB11AF65BULL,
		0x40ED3A2D1512E8A6ULL,
		0x4E93F5B146A6AE67ULL,
		0x5027F2463F931873ULL,
		0x1CEE944D583585BAULL,
		0xCDAC6907BE0FE04AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD68417C948885A71ULL,
		0x725C317C58AF8D90ULL,
		0x7726325CB11AF65BULL,
		0x40ED3A2D1512E8A6ULL,
		0x4E93F5B146A6AE67ULL,
		0x5027F2463F931873ULL,
		0x1CEE944D583585BAULL,
		0xCDAC6907BE0FE04AULL
	}};
	t = 0;
	printf("Test Case 369\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 369 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -369;
	} else {
		printf("Test Case 369 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD34A35DD5D6141B1ULL,
		0x86350EEB15878454ULL,
		0x44F29511E224F978ULL,
		0x47D261679D388992ULL,
		0x49990605B56EDB10ULL,
		0x355AAEA6A9AAE73FULL,
		0x67CB167A94CECFFCULL,
		0x881821624E32E33EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4439E5227D4E6ACCULL,
		0x3659E6F4EF64F930ULL,
		0xAFAFCF64E82282B4ULL,
		0x31B2A5EDFAC2BD60ULL,
		0x502D40903F14661BULL,
		0x016AD2A8A56A7FECULL,
		0x00FBDA2E298D94D9ULL,
		0xB2032E9C13C9575FULL
	}};
	t = -1;
	printf("Test Case 370\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 370 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -370;
	} else {
		printf("Test Case 370 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x164B822223B5DE32ULL,
		0xE824D2FEA681E736ULL,
		0x9877B72A2D47F8A4ULL,
		0x6F0A1E25E5551818ULL,
		0x65BAF3FA9DCB503EULL,
		0x130FC4D9E7F97ED6ULL,
		0x48BE88530C8CF7AFULL,
		0xE28B21FF5B105429ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x06278A77234FB74AULL,
		0xEA7AB4DE6A6F8D82ULL,
		0x48F80E8210C7816AULL,
		0x92C4E083948D91B3ULL,
		0x97D6C941E57CA4ABULL,
		0x79F939EE54D4E970ULL,
		0x6F5C511B72F6E6E6ULL,
		0x7B0167C52672571AULL
	}};
	t = 1;
	printf("Test Case 371\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 371 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -371;
	} else {
		printf("Test Case 371 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB2C0779FB6FB5357ULL,
		0x2ED46132E2A5998BULL,
		0xBA03975A3CBF7BA8ULL,
		0xCA3FCA554233CEABULL,
		0x1C6A0F8F9C0FB956ULL,
		0x2780284402CBB032ULL,
		0x95F40BD079FC2493ULL,
		0x32FB83E957C41869ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFBF9A4AE1831F124ULL,
		0x05422792DCB6C2CCULL,
		0x78EB49A71EC90E6BULL,
		0x9140DB00AD39AEB4ULL,
		0x3D0A263CDB0FB790ULL,
		0x109A23F215D760E7ULL,
		0x0A6483C76E87C15EULL,
		0xC3311F70DB406511ULL
	}};
	t = -1;
	printf("Test Case 372\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 372 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -372;
	} else {
		printf("Test Case 372 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC73A6F9DD585AE7EULL,
		0xE1C4C94C8A26BE93ULL,
		0x5B5155C1328F04E2ULL,
		0x8E63C0B171C5DAEFULL,
		0x2FB0AA4A92FCF371ULL,
		0x4FAFA31E8730067EULL,
		0x155EC47639A0BA97ULL,
		0x66AF8EABC96F81F5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC73A6F9DD585AE7EULL,
		0xE1C4C94C8A26BE93ULL,
		0x5B5155C1328F04E2ULL,
		0x8E63C0B171C5DAEFULL,
		0x2FB0AA4A92FCF371ULL,
		0x4FAFA31E8730067EULL,
		0x155EC47639A0BA97ULL,
		0x66AF8EABC96F81F5ULL
	}};
	t = 0;
	printf("Test Case 373\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 373 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -373;
	} else {
		printf("Test Case 373 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3FC7DFBED05B4814ULL,
		0xA30C897D333899ADULL,
		0x7F2E4AC7D5843245ULL,
		0x8BDA0989EED7D745ULL,
		0x3E166693295E990FULL,
		0x712D9401B0D8FCADULL,
		0xCE131C28E1D7E525ULL,
		0x9776E756309A54B6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD617A925032F2DA4ULL,
		0xF53F03408F65396FULL,
		0x3239044619D91F1AULL,
		0x7270600025C9C801ULL,
		0x9AFE3CEE3C690C2AULL,
		0x9DFEA95C5BB629D6ULL,
		0x070523BA398CCE25ULL,
		0xED944BFD2C571138ULL
	}};
	t = -1;
	printf("Test Case 374\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 374 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -374;
	} else {
		printf("Test Case 374 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB0C8C7B6B2E11C00ULL,
		0x459E59DF54D442F4ULL,
		0x75D9D86DCF325BA8ULL,
		0xFD722F3428F28532ULL,
		0x3F4469A45175B78CULL,
		0x315F72E844B5D557ULL,
		0x36BA8BE239BA184AULL,
		0x005272AA0EF0FEE5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8760E724A216327BULL,
		0x24A9C52451B04399ULL,
		0xE84BD88040596944ULL,
		0x5D518314E44D9117ULL,
		0x4CA8F3152D35FF09ULL,
		0xB51262646345A63EULL,
		0xD11166AEFE78D8AEULL,
		0x1AF90407C521B4F4ULL
	}};
	t = -1;
	printf("Test Case 375\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 375 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -375;
	} else {
		printf("Test Case 375 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x98A17A6B223B349AULL,
		0x07514CDDBFE58A86ULL,
		0xD4B917CB1B0D9412ULL,
		0xD2BFA1B93307E4A4ULL,
		0xECDB9CA5EE5140E2ULL,
		0x71D40837434654C9ULL,
		0xFA712140CE34066CULL,
		0x966ED22E1EC85BD7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF8D78AB7E8096675ULL,
		0xCDACE5C966E5A078ULL,
		0x9DE323770B66E155ULL,
		0x7F27D43554973EDAULL,
		0x5199F35257851975ULL,
		0xB24DA780D0553360ULL,
		0x365CDFFBD106FB02ULL,
		0xC2D23789C1F3A65CULL
	}};
	t = -1;
	printf("Test Case 376\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 376 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -376;
	} else {
		printf("Test Case 376 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x841C633537ABCC9DULL,
		0x2EB29F11242115D9ULL,
		0x5A81DB1CF3F53E5DULL,
		0x7D9EE8DEE148A0F9ULL,
		0x9C741A76A824B0D0ULL,
		0x7F91E3F4FE9CE8E4ULL,
		0xAA0CC1DE2C1B05A0ULL,
		0x7E28DF04797AB87EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x841C633537ABCC9DULL,
		0x2EB29F11242115D9ULL,
		0x5A81DB1CF3F53E5DULL,
		0x7D9EE8DEE148A0F9ULL,
		0x9C741A76A824B0D0ULL,
		0x7F91E3F4FE9CE8E4ULL,
		0xAA0CC1DE2C1B05A0ULL,
		0x7E28DF04797AB87EULL
	}};
	t = 0;
	printf("Test Case 377\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 377 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -377;
	} else {
		printf("Test Case 377 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x69375B37E0CBA16BULL,
		0x9307D5AB65C1C7DDULL,
		0xA6096ECB24A3B9E3ULL,
		0xE87725650493FBF0ULL,
		0x33193AE31A88233FULL,
		0xF06DE13459EB3EC3ULL,
		0x98DA53B0497E3D20ULL,
		0x2DD44D918A968DE4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3585F78B099E598EULL,
		0x3FA2452CCDE06DF0ULL,
		0x5E4251CD20B08C5CULL,
		0xB8E8E4AE3A904C43ULL,
		0xDCF3C405725198CEULL,
		0x4B88E764EEF4404EULL,
		0x666A5282B907853BULL,
		0x7FE730C987B003B2ULL
	}};
	t = -1;
	printf("Test Case 378\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 378 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -378;
	} else {
		printf("Test Case 378 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7F7054CA9E08416FULL,
		0x547097C00C4EA06AULL,
		0x21BC64919597BE6BULL,
		0xF5164923F054977FULL,
		0x9316F174A13A37C4ULL,
		0xE794953019216C8BULL,
		0xF56A86A9F457BB9AULL,
		0xEE7BCC57D03A7629ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC1103BF6BB534C43ULL,
		0xBE29AF61E5006017ULL,
		0x1650382A2E244946ULL,
		0x029F1D718071D2AEULL,
		0xEB9C5F7DBF998766ULL,
		0x26C2795D57876A21ULL,
		0x43843EFCABEE27BBULL,
		0x544B8A1302233FDFULL
	}};
	t = 1;
	printf("Test Case 379\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 379 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -379;
	} else {
		printf("Test Case 379 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6E13AA89BD0F8A78ULL,
		0xD4638DB0E725AD77ULL,
		0x07166D1F12989049ULL,
		0x11DB95CE1BE7D071ULL,
		0x5DBAB280DD718615ULL,
		0x046B646E67B1F52EULL,
		0xC9EDD644282578F5ULL,
		0x5F21317E8E15CD28ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF683A15ECC34F8C6ULL,
		0xECECA04B03A96840ULL,
		0x4BB25706B35FD4F2ULL,
		0x447DF3E61144CB10ULL,
		0xEC49E80E01F7675EULL,
		0x97372871ACC695F5ULL,
		0x7204097BFB538F9CULL,
		0x632AFBA2478C2BE0ULL
	}};
	t = -1;
	printf("Test Case 380\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 380 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -380;
	} else {
		printf("Test Case 380 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6205FFC5C1BDEC38ULL,
		0x86453653F746F77CULL,
		0xF422FA26AA8DFD24ULL,
		0x94E168A421906E2FULL,
		0xD2F576358EEB355CULL,
		0xAC3B26C267E7D762ULL,
		0x36A2B26E02A9A36EULL,
		0x9BCA08D220DE756DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6205FFC5C1BDEC38ULL,
		0x86453653F746F77CULL,
		0xF422FA26AA8DFD24ULL,
		0x94E168A421906E2FULL,
		0xD2F576358EEB355CULL,
		0xAC3B26C267E7D762ULL,
		0x36A2B26E02A9A36EULL,
		0x9BCA08D220DE756DULL
	}};
	t = 0;
	printf("Test Case 381\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 381 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -381;
	} else {
		printf("Test Case 381 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD1594C3AFCA2A994ULL,
		0x187BFD9A6479EFCDULL,
		0x1367A6ED158B1664ULL,
		0xB04D2E1B030F0D42ULL,
		0x646A506CF8B9823EULL,
		0x608884B8243BE2DBULL,
		0xA7035B1A6B52E335ULL,
		0x0C87D2A5C7530266ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x647F03B559EDDA89ULL,
		0xE62C6591041218AEULL,
		0x6E45595160559A92ULL,
		0xADF711F2FA811B01ULL,
		0x84CFE31C1A91022FULL,
		0x59B42D3318283E28ULL,
		0x93931C51F9C3D367ULL,
		0x6FD0324FD1F6BF83ULL
	}};
	t = -1;
	printf("Test Case 382\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 382 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -382;
	} else {
		printf("Test Case 382 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8B7CFD173DFD8E27ULL,
		0xEDDF60829128C698ULL,
		0x73AFB4FCE14DC182ULL,
		0x829FB31312FCA81AULL,
		0xC8D7FF1DC285DA9BULL,
		0xD73449193F3ECA47ULL,
		0x6A4B4F05C96D62C1ULL,
		0x9063E1965FF1421EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9F348A6E2B93C453ULL,
		0xDF0BED403B12E55CULL,
		0x579B147FD967948DULL,
		0x5B1535ED8E55A04BULL,
		0x13C4329BB128A670ULL,
		0xBE32DD01FCFE09CEULL,
		0x72368DAF31556F6DULL,
		0x3C5B78B22C77E2EDULL
	}};
	t = 1;
	printf("Test Case 383\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 383 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -383;
	} else {
		printf("Test Case 383 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6BECAEB00233F33BULL,
		0x2B09A5268738BB26ULL,
		0x7A33A2C9022AD0C7ULL,
		0x2DF45D65D6F74135ULL,
		0x33B960F1F0FF6E4CULL,
		0xAA42A6AD01B2BF2EULL,
		0x0FDFF97742AE9AFFULL,
		0xF8CDE874BC96DA3EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x35278DB0E789AF40ULL,
		0x8BE7D16D7FDAEA03ULL,
		0xA79DE19161C6EFD3ULL,
		0xE63FB7541D6E821FULL,
		0x8FF90C8D4977F845ULL,
		0xBDE8173D1C5B958FULL,
		0x870D7416FC2D6151ULL,
		0xE7698C4706011305ULL
	}};
	t = 1;
	printf("Test Case 384\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 384 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -384;
	} else {
		printf("Test Case 384 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD012C84098BC2562ULL,
		0x3338AC92F8408509ULL,
		0x49D7B10494F7D343ULL,
		0xED29B2A919FDF537ULL,
		0xB979A185E5CDE895ULL,
		0x800510328E9BB86DULL,
		0xD5002287D233385AULL,
		0xCDC7A4EDEB77C24AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD012C84098BC2562ULL,
		0x3338AC92F8408509ULL,
		0x49D7B10494F7D343ULL,
		0xED29B2A919FDF537ULL,
		0xB979A185E5CDE895ULL,
		0x800510328E9BB86DULL,
		0xD5002287D233385AULL,
		0xCDC7A4EDEB77C24AULL
	}};
	t = 0;
	printf("Test Case 385\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 385 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -385;
	} else {
		printf("Test Case 385 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x274C26E987CA84F4ULL,
		0x39CE7E26DF37BC34ULL,
		0x5184AB2EE9F52211ULL,
		0xE1B53B512AF573C7ULL,
		0xC6E8FE4FBC1068A2ULL,
		0x38426A6D182F21F1ULL,
		0x8F17A736A5002FB5ULL,
		0xA506D2E041F24DC6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9D22F95B6AA38946ULL,
		0xEE82D8A97A361CE7ULL,
		0x5A63DF8EDC085D89ULL,
		0x226A8AD0BFCB978AULL,
		0xEA811B2E7439B2BCULL,
		0xE911F31B9F2526DDULL,
		0x3D964430BCF9FCA5ULL,
		0x2159E0FE53B45B4FULL
	}};
	t = 1;
	printf("Test Case 386\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 386 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -386;
	} else {
		printf("Test Case 386 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x52EB2F4077A0EE9FULL,
		0x40CBA1AA71EF661EULL,
		0xF14CE52A696FC610ULL,
		0xBBA7ECC48C28B123ULL,
		0x681378B21048FFC1ULL,
		0x156E5FC7F58E822DULL,
		0x3CD9ABA250239623ULL,
		0x09A858E247EB9E3EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x54606305746F770CULL,
		0x1DBDCC67DD2912BBULL,
		0xCEDE759AA0A82302ULL,
		0xE93473B18A64553DULL,
		0x95BE8D328D4F00CCULL,
		0x640BF91D3C3175B6ULL,
		0xE8F15E48875453CBULL,
		0xB5067234EACAB887ULL
	}};
	t = -1;
	printf("Test Case 387\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 387 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -387;
	} else {
		printf("Test Case 387 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD336E5EBF43E47D2ULL,
		0x9FF2D7D41A8731F9ULL,
		0xF9B68C2A22817A4BULL,
		0x7EFFF13AC675BA74ULL,
		0x73FDB3B8179060FAULL,
		0x12B44D04B313F762ULL,
		0x56C51AD9FF99804FULL,
		0x51A12B4B24F01756ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA4B8685EA1C7A488ULL,
		0x77DA74C9F7FA4C6FULL,
		0xCE268679799246D2ULL,
		0x1016C8D6C709C77DULL,
		0xEF29DB973DED0FE7ULL,
		0x37916094AF9CEDFDULL,
		0xE376DB042692B5EFULL,
		0x3FABBCC7E854C232ULL
	}};
	t = 1;
	printf("Test Case 388\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 388 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -388;
	} else {
		printf("Test Case 388 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x56B25E8D797F0DC2ULL,
		0xC1E3C0321741CF2EULL,
		0x1A917D6095BF5493ULL,
		0x7A0AD7E023AEBD31ULL,
		0x57F323B77A4E3BEBULL,
		0x472571E515CE1204ULL,
		0xCB628B6AAB0FDA61ULL,
		0xC30E7792B1B94F82ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x56B25E8D797F0DC2ULL,
		0xC1E3C0321741CF2EULL,
		0x1A917D6095BF5493ULL,
		0x7A0AD7E023AEBD31ULL,
		0x57F323B77A4E3BEBULL,
		0x472571E515CE1204ULL,
		0xCB628B6AAB0FDA61ULL,
		0xC30E7792B1B94F82ULL
	}};
	t = 0;
	printf("Test Case 389\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 389 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -389;
	} else {
		printf("Test Case 389 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x82CB0731AABEE10CULL,
		0x137BF4D8D58EB1E9ULL,
		0xC6DDE68D967209D3ULL,
		0xDDA88FD4F613A7B8ULL,
		0xD4AC9F559DC521EBULL,
		0x431519225EEED1F6ULL,
		0xFB74CE8A4B1C36E7ULL,
		0x54EABB0F09B8FAB4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCBFEA5D683F2DAB3ULL,
		0xB0329348DEB94ED2ULL,
		0xF9A13416A0F220C4ULL,
		0x8C84BE1AD067B5A8ULL,
		0x262EB4886CC94AE1ULL,
		0x01F00449066EC63EULL,
		0x9E47295684AB9237ULL,
		0xCB7CCA6B21E80319ULL
	}};
	t = -1;
	printf("Test Case 390\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 390 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -390;
	} else {
		printf("Test Case 390 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEFFC7DC38CF20A61ULL,
		0x34AC48F1D2C41435ULL,
		0xECFD8AD6B1386E12ULL,
		0xA2141E7BDD802354ULL,
		0x0429EFA9D7C807A4ULL,
		0x72F5D26AB9348F9DULL,
		0xBFFF4B37E5AB945AULL,
		0xCB611FB8ACC97ACDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x26A464A3C8635986ULL,
		0x34272028F7DCDF33ULL,
		0x4F2820EC18F82EAAULL,
		0xE5763495E93E0136ULL,
		0x54936820EC07F27DULL,
		0x082D192C35512F14ULL,
		0xEE101E98CE2002EDULL,
		0x0D0DEE8D67FD469AULL
	}};
	t = 1;
	printf("Test Case 391\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 391 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -391;
	} else {
		printf("Test Case 391 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0DC2334561D79488ULL,
		0xB7FB2D47E138AE32ULL,
		0x6F0DE7B060D063DDULL,
		0x18E017541AF66E3EULL,
		0x3D5DBDC9BD464244ULL,
		0x0C378469C12BE56EULL,
		0x8C93F929FAEF4DFFULL,
		0x9D2CCA0DB41830F1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC58F71517803A23BULL,
		0xB07518861E75EB4FULL,
		0xA1DC401D02F16DD0ULL,
		0x7CEAB676A77F3D0AULL,
		0x9AC2BFDFB092161BULL,
		0x8AF9E7D5EBBD8005ULL,
		0x2C0C4C8598E17268ULL,
		0x5986B2F8405C09B0ULL
	}};
	t = 1;
	printf("Test Case 392\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 392 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -392;
	} else {
		printf("Test Case 392 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8C8199A21E1D5A93ULL,
		0x2368D1A6344A1EA5ULL,
		0x2744148A962C901EULL,
		0xCC94914BE32766F6ULL,
		0x4E6C122745287C1EULL,
		0x2C641E03EB01B966ULL,
		0x44CE186FB73BF296ULL,
		0xD8B50AC148E56FAAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8C8199A21E1D5A93ULL,
		0x2368D1A6344A1EA5ULL,
		0x2744148A962C901EULL,
		0xCC94914BE32766F6ULL,
		0x4E6C122745287C1EULL,
		0x2C641E03EB01B966ULL,
		0x44CE186FB73BF296ULL,
		0xD8B50AC148E56FAAULL
	}};
	t = 0;
	printf("Test Case 393\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 393 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -393;
	} else {
		printf("Test Case 393 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xACE61109C6079C84ULL,
		0x81470690961573EAULL,
		0x4967F445D1C5BBEFULL,
		0xBBC0EA6A1B43794FULL,
		0x4E2DF2FF1C3A3256ULL,
		0x97FFAF8F1B357E78ULL,
		0x0CA9CD7B55520F56ULL,
		0x866F17ECD51FA6DEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x68263B2465297C55ULL,
		0x3AFA9CD2E8C968E6ULL,
		0x7DBB3C988FE8D3AAULL,
		0x55894EAB00130E71ULL,
		0x344A840B14714D4BULL,
		0x531B354B6C64E07AULL,
		0xA1F88D61814ADA29ULL,
		0x4DA051897FC7EB31ULL
	}};
	t = 1;
	printf("Test Case 394\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 394 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -394;
	} else {
		printf("Test Case 394 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE82FCE847644279BULL,
		0xB344BE254FBE7E54ULL,
		0xF682DFFA7BD71A1AULL,
		0x632A8103D1E5CB38ULL,
		0x769450FBFE180557ULL,
		0xF807B1CEAD737F00ULL,
		0x1A01A7B1E882D1DBULL,
		0x5F94E60F267B1862ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCF7F82CAC5DFA0FEULL,
		0x734D4D02CC9C1F89ULL,
		0x38D2B2D71EC5CEF3ULL,
		0x29E5B2F43D60E96CULL,
		0x9AA923506E10EC34ULL,
		0x6FDF59DB49231173ULL,
		0xD564317880B9EFD4ULL,
		0x4BD93D46BBA4A04AULL
	}};
	t = 1;
	printf("Test Case 395\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 395 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -395;
	} else {
		printf("Test Case 395 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x792C6ACCD4C52C29ULL,
		0x62DABE8220AA2D9FULL,
		0x26BD74CCD8F8BCF7ULL,
		0xD30F6826249C4F2BULL,
		0xB175B9A85BC350C8ULL,
		0x8075964B56CC5CD2ULL,
		0x7CEE1CC483A3461DULL,
		0x9B4C37EF771A4B13ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC5C899EB463475B3ULL,
		0xE23B3DDE634AC600ULL,
		0x814044A1FD8423DAULL,
		0x7E2E00B923186510ULL,
		0x2F373017FA27CD24ULL,
		0xEE657EE7423A8E4DULL,
		0x765A8EA6CC5D3A6CULL,
		0xF4A085B89744E2F0ULL
	}};
	t = -1;
	printf("Test Case 396\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 396 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -396;
	} else {
		printf("Test Case 396 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2B43141C733B10A4ULL,
		0x426B227029910464ULL,
		0xD977874B596587DDULL,
		0x10935B52FB8F521BULL,
		0x3634142094AB484FULL,
		0x4536FFA86D46D474ULL,
		0xE39FD8A296A2C3E8ULL,
		0x914137B0483B0C49ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2B43141C733B10A4ULL,
		0x426B227029910464ULL,
		0xD977874B596587DDULL,
		0x10935B52FB8F521BULL,
		0x3634142094AB484FULL,
		0x4536FFA86D46D474ULL,
		0xE39FD8A296A2C3E8ULL,
		0x914137B0483B0C49ULL
	}};
	t = 0;
	printf("Test Case 397\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 397 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -397;
	} else {
		printf("Test Case 397 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2BADDB8581CFEB41ULL,
		0x108E73461906EA97ULL,
		0x85F5394ACF506386ULL,
		0x6DE35AC04340C009ULL,
		0x5C84622C69203E7DULL,
		0xD43A5B2CD10ECCB7ULL,
		0xB9A18B1753829BCFULL,
		0x6B9E9DE1B188392DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x585A6A15E3103C07ULL,
		0x5FDC25276A4C439DULL,
		0xF89CD1D631156AB0ULL,
		0x389749F49B75284FULL,
		0x1A434D01E53F2CF1ULL,
		0xA87AF4ACFA24A522ULL,
		0xF71AC21C8FE05FC5ULL,
		0xF7E36D5F301F69CDULL
	}};
	t = -1;
	printf("Test Case 398\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 398 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -398;
	} else {
		printf("Test Case 398 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAC3A2D00FFE673BCULL,
		0x7EB4A3F78B5117AFULL,
		0xFF4C7C76520A82A1ULL,
		0xE406B6A88C43D8C2ULL,
		0xD39F9384C8304D7BULL,
		0x163B3E3B60AFFD38ULL,
		0xE5ED0634D780B530ULL,
		0x300B1452AD3FD6A2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEB4015B1AABC9C2DULL,
		0xAE0EC40F8118EC1DULL,
		0xC10617D701E242A7ULL,
		0x1F71C25459048606ULL,
		0x91E5F64D844FB747ULL,
		0xDC3A5C0662DD8B08ULL,
		0xDD3BA6FBB4516BA4ULL,
		0x693EAE7387838F19ULL
	}};
	t = -1;
	printf("Test Case 399\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 399 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -399;
	} else {
		printf("Test Case 399 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8DE2A60A499AA61FULL,
		0x04C80D0753D6A1D4ULL,
		0x091742AEA1B3C003ULL,
		0x07D231551AA22FBBULL,
		0x3B385C649E161374ULL,
		0x3604033926E6E06CULL,
		0xFC7BC4D9166F75C5ULL,
		0xE25B6BDEB7A80447ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEDFB72EFF14FDC65ULL,
		0x09E7AAE94125B0B7ULL,
		0x0A083D3A266C4A54ULL,
		0xCA39D11414FD39E6ULL,
		0xFD8614BC3081C338ULL,
		0x2AC521E45CEE32D4ULL,
		0x562A4528643A077EULL,
		0x898A26D1D9955558ULL
	}};
	t = 1;
	printf("Test Case 400\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 400 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -400;
	} else {
		printf("Test Case 400 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCBE89B83E21E53E0ULL,
		0x0B25AFD50D4E7CAFULL,
		0xA57B684302AF28D5ULL,
		0xC205CF90CE4BF5B3ULL,
		0x8D0658D7605942DBULL,
		0x144269F7F79B0CE2ULL,
		0x613116769CB8F693ULL,
		0xC965C792884E5F15ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCBE89B83E21E53E0ULL,
		0x0B25AFD50D4E7CAFULL,
		0xA57B684302AF28D5ULL,
		0xC205CF90CE4BF5B3ULL,
		0x8D0658D7605942DBULL,
		0x144269F7F79B0CE2ULL,
		0x613116769CB8F693ULL,
		0xC965C792884E5F15ULL
	}};
	t = 0;
	printf("Test Case 401\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 401 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -401;
	} else {
		printf("Test Case 401 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x893CB2DAAEAAFE29ULL,
		0x39B821AED37789F8ULL,
		0x0CD6B41E42257566ULL,
		0x23F78E97EE5435E6ULL,
		0x68242490F004168CULL,
		0x97815933142001A7ULL,
		0x16C8BCD81E650E94ULL,
		0x34C7A72F2381DF32ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9034A551DC225C94ULL,
		0x836F19FA51C41521ULL,
		0x4DE160C47A5F5E49ULL,
		0x5C6EF28D39002E02ULL,
		0x3AE03F013B0B1CB5ULL,
		0x58C26D4D86589271ULL,
		0x5EB3C6E663EE2743ULL,
		0x2A38FAA6962FE4E0ULL
	}};
	t = 1;
	printf("Test Case 402\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 402 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -402;
	} else {
		printf("Test Case 402 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x88ABBD455E2BD8F3ULL,
		0xFFE3C28A659EFB16ULL,
		0x09DD93AD274DB9D8ULL,
		0x789D083AA55056F4ULL,
		0xE5D0AD0981888BFDULL,
		0xD5EA5B9703872402ULL,
		0x0EE61769ED8EAE87ULL,
		0x6C67C9F760F17CB8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAA9409045D687E40ULL,
		0x2017E0143FDBB038ULL,
		0xD2997030BF626823ULL,
		0x083F8B4DCE4ACC87ULL,
		0xBEBC981144DBE608ULL,
		0xED404D9EC12F916EULL,
		0x9A0A7345CACD0160ULL,
		0x575E2A349B62B945ULL
	}};
	t = 1;
	printf("Test Case 403\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 403 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -403;
	} else {
		printf("Test Case 403 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x22A33D7AB445621DULL,
		0xD71BB2BC4CD6376FULL,
		0xC853F4B077361DB2ULL,
		0xA48974730432651BULL,
		0x3216D35A6D5DE578ULL,
		0xDCF53DDF10C15CB0ULL,
		0x10E01BC5E6199238ULL,
		0xD063868B3C1DED89ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4303B7CA9E7AC61DULL,
		0x142C2047E3AC383BULL,
		0x05DEFD959AFD6D4BULL,
		0x1DB8366A0423D428ULL,
		0x12FBBF7DEF041BC6ULL,
		0x33EF03F686733077ULL,
		0xB6D0B512B347BB1EULL,
		0x8E7A6071B524B3E1ULL
	}};
	t = 1;
	printf("Test Case 404\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 404 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -404;
	} else {
		printf("Test Case 404 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x190A5FF89549DB30ULL,
		0x4EE1824D34F48751ULL,
		0xD8688F2957EB479EULL,
		0xB7EBD415CB03CC8EULL,
		0x5F09236424FFDC74ULL,
		0xEB9A3162E53371E3ULL,
		0x12AC0814C00CA52BULL,
		0xB9F7377EE8F40456ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x190A5FF89549DB30ULL,
		0x4EE1824D34F48751ULL,
		0xD8688F2957EB479EULL,
		0xB7EBD415CB03CC8EULL,
		0x5F09236424FFDC74ULL,
		0xEB9A3162E53371E3ULL,
		0x12AC0814C00CA52BULL,
		0xB9F7377EE8F40456ULL
	}};
	t = 0;
	printf("Test Case 405\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 405 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -405;
	} else {
		printf("Test Case 405 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x03C47C8EE86D8E08ULL,
		0x6107B4C8039594CFULL,
		0x8412D44366F4BEB8ULL,
		0x974808A88AF61A0BULL,
		0xA4DC176F49EA75D1ULL,
		0x5F8710D22AE9147CULL,
		0x6F17B187B3DBDB7FULL,
		0x20A259CAA40A1BAAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6DD4B7A316F10EC7ULL,
		0x2D76B673BFFA8B62ULL,
		0x7EAB67EC445FFBC3ULL,
		0x3E9064529BEBD469ULL,
		0x38B74504037D6EDBULL,
		0x91318E84BCFE37B0ULL,
		0xD024C41D839C0599ULL,
		0x383E0D3D9CC4417DULL
	}};
	t = -1;
	printf("Test Case 406\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 406 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -406;
	} else {
		printf("Test Case 406 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5B33768DFE06B07AULL,
		0xC7531D70AA45EE60ULL,
		0xEFC5DC02AE0CA4A7ULL,
		0x7566F470DD756296ULL,
		0x4AD4AA7B02772118ULL,
		0x2F7ED6E896A5158EULL,
		0xC13EB5C0B1C204A9ULL,
		0x9550A86D960879C0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5E6FF19A6011C2D0ULL,
		0x617F59DC5E8DE1B6ULL,
		0xCD1D0E0D2846FE2AULL,
		0x96F9117E280B5490ULL,
		0xE8B782A73F1A4354ULL,
		0x8FD0AE319AC67CF6ULL,
		0xD6DC07EDA9E6DE10ULL,
		0x7D57DB19AF4FF7D7ULL
	}};
	t = 1;
	printf("Test Case 407\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 407 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -407;
	} else {
		printf("Test Case 407 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6643D36C7E6A3380ULL,
		0xFBD394D1A23FA02AULL,
		0x1A36379F8EC5C185ULL,
		0xBFC59A98CA529272ULL,
		0x003D57C435249DADULL,
		0x658610DC0C08019EULL,
		0x11B8B78806D66D42ULL,
		0x6F0FB32D9F1B02AAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x074154B3152F42D4ULL,
		0xEDB0661C3407F7EDULL,
		0xEB37C43F24B7F485ULL,
		0x3D43CF3C483659E1ULL,
		0xFBB14ED78831371DULL,
		0x02459F5E36BF1B32ULL,
		0x93CD7245E2AF1EE8ULL,
		0x7C35D77778E40D59ULL
	}};
	t = -1;
	printf("Test Case 408\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 408 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -408;
	} else {
		printf("Test Case 408 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE109581C47DAAED4ULL,
		0x3D5F96654F1C9513ULL,
		0x12FD10B869B9E966ULL,
		0xF2C1DBA371E45487ULL,
		0x5CD665111A47E8DBULL,
		0x538D1C84BD10C2A8ULL,
		0xC0CACB3846376DDFULL,
		0x5E6BB18C539FC089ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE109581C47DAAED4ULL,
		0x3D5F96654F1C9513ULL,
		0x12FD10B869B9E966ULL,
		0xF2C1DBA371E45487ULL,
		0x5CD665111A47E8DBULL,
		0x538D1C84BD10C2A8ULL,
		0xC0CACB3846376DDFULL,
		0x5E6BB18C539FC089ULL
	}};
	t = 0;
	printf("Test Case 409\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 409 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -409;
	} else {
		printf("Test Case 409 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x37F3F86089F4D0E3ULL,
		0x3C732D502B152106ULL,
		0x16BEBE0F82A3F231ULL,
		0xD5CAAC191ED7D89AULL,
		0x2D618B23F2309317ULL,
		0x12FFC6A728783359ULL,
		0x94BEA9F4E2103A5AULL,
		0x67FF38BC16C4EF4FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x40AA45EC0592EEE3ULL,
		0xDCE16A0C20C259FAULL,
		0x1316BC1104757741ULL,
		0x3C54910C19F71DDAULL,
		0x1F5B0962E340569EULL,
		0xA33F9020EF1A402FULL,
		0xD0A1B57B73EB2920ULL,
		0x2A843C74FFFA8780ULL
	}};
	t = 1;
	printf("Test Case 410\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 410 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -410;
	} else {
		printf("Test Case 410 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB385F31E0A9DF42CULL,
		0xCB9999E923D7C9C6ULL,
		0x99DF63D16B7E7F1EULL,
		0x861D4D0F368D2974ULL,
		0xF0050C7FE31ED4A8ULL,
		0xD4CB7FA606CCB8B1ULL,
		0x33AB57D1AE13A3D5ULL,
		0x5F7D675FBD30A2C9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x45ACA5DB0C942982ULL,
		0x9E20A3BF72ADF76DULL,
		0xF22508D864E37CCBULL,
		0x944EE8641BCAA741ULL,
		0xD60F4331D12D3466ULL,
		0xC9752FB1B00A87B4ULL,
		0x1B87917806117601ULL,
		0x85B0447EF59DC000ULL
	}};
	t = -1;
	printf("Test Case 411\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 411 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -411;
	} else {
		printf("Test Case 411 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x12CF8DBB43C324CFULL,
		0x01D9B5EEE4B33107ULL,
		0x2B751670E30EE6B4ULL,
		0xA8646650FF00C2A2ULL,
		0x4343CB38C4524111ULL,
		0x4BFCF2842EE350ECULL,
		0x5E6F72A009A80DD5ULL,
		0x8E0F833A6989DBB0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF5A4AC243D331C13ULL,
		0x2AA0A87BF1D3A422ULL,
		0xA4C517DDCC0AD4EAULL,
		0x32B4D76AB5589D66ULL,
		0x5B9EDF63D15FBC51ULL,
		0xB7AD7272D2AEBC41ULL,
		0x8FED14A32DBF6816ULL,
		0xC3829B0BBF4EE56DULL
	}};
	t = -1;
	printf("Test Case 412\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 412 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -412;
	} else {
		printf("Test Case 412 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC9DE4761E3E283A2ULL,
		0xE3D344899B362146ULL,
		0x8AA47C3A3D4D80C2ULL,
		0x6DC6BF0967DAE215ULL,
		0x22D19E746A88CF5EULL,
		0xFA165D002BC9B83CULL,
		0x60FD8D3CA3CDB0B2ULL,
		0x76D23ACC87DB2DC5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC9DE4761E3E283A2ULL,
		0xE3D344899B362146ULL,
		0x8AA47C3A3D4D80C2ULL,
		0x6DC6BF0967DAE215ULL,
		0x22D19E746A88CF5EULL,
		0xFA165D002BC9B83CULL,
		0x60FD8D3CA3CDB0B2ULL,
		0x76D23ACC87DB2DC5ULL
	}};
	t = 0;
	printf("Test Case 413\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 413 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -413;
	} else {
		printf("Test Case 413 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7285E68770314087ULL,
		0xC15106CE407D9652ULL,
		0x23D3767FE98C6310ULL,
		0xD5ECFEFD7F3A1B87ULL,
		0x71BA999DBFC93D84ULL,
		0x78ABAB1BE34A007DULL,
		0x3ACEF4F4675D9656ULL,
		0x15A230344396F4E2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE0BECB3979F86076ULL,
		0xED8CAF4983E7D9BAULL,
		0x2ECAA70E72DA9F1AULL,
		0x7AF336E696FFADD1ULL,
		0x49B02699B79FB6CBULL,
		0x1112B4A2EDAE4CC5ULL,
		0x244EA6AAB71CFCDCULL,
		0xD1169DE1BAC57648ULL
	}};
	t = -1;
	printf("Test Case 414\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 414 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -414;
	} else {
		printf("Test Case 414 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD072D7CF0ED68C25ULL,
		0x9D72BF674152FDF9ULL,
		0x0E25207F3FE083B5ULL,
		0x29562AF0642A6E29ULL,
		0xF580A592D2892E84ULL,
		0x9B3E2D56B624E5BFULL,
		0xFD07A705F99743FEULL,
		0x19BAA21591C3035CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x31E3768E24578170ULL,
		0x77590F6DBA500D29ULL,
		0x7050C4FE665D8A85ULL,
		0x765D9A6A701B230DULL,
		0x31C5CE24621FA486ULL,
		0xCD5D887C9283FF2EULL,
		0x438F385411BCFD22ULL,
		0x1DE81EA6C1793F46ULL
	}};
	t = -1;
	printf("Test Case 415\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 415 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -415;
	} else {
		printf("Test Case 415 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x281897C6FD2F39F1ULL,
		0x2AD99E88E5AC27B9ULL,
		0x6418924A4B35990CULL,
		0x72DDF0565F0144A4ULL,
		0x85986D36E88E954FULL,
		0x5318253C56E1C1D4ULL,
		0x72FE2813A87882C7ULL,
		0x0E2F6F9E739A4BBBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2D21C4DDF5FEE620ULL,
		0xA72BF58610AE0D8EULL,
		0x545741C5D5D010E5ULL,
		0x72F1DC378E5CB779ULL,
		0xC0D23BBC273932C3ULL,
		0x7C1700079F6624AEULL,
		0x1EDE89E6B8FF7D11ULL,
		0x49F725D37F127221ULL
	}};
	t = -1;
	printf("Test Case 416\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 416 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -416;
	} else {
		printf("Test Case 416 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD8889F37BF19122AULL,
		0x10F1025B66A6AF51ULL,
		0x62E9E0156A903BF0ULL,
		0x8667BDD65FB48605ULL,
		0x71F746A0FDC2092BULL,
		0xA87A6A07F10C4882ULL,
		0x2410DCC39861529AULL,
		0x5A0331FBF11986AAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD8889F37BF19122AULL,
		0x10F1025B66A6AF51ULL,
		0x62E9E0156A903BF0ULL,
		0x8667BDD65FB48605ULL,
		0x71F746A0FDC2092BULL,
		0xA87A6A07F10C4882ULL,
		0x2410DCC39861529AULL,
		0x5A0331FBF11986AAULL
	}};
	t = 0;
	printf("Test Case 417\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 417 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -417;
	} else {
		printf("Test Case 417 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAB8FFF9A0FD9492DULL,
		0x572A4D7BC25E2B2AULL,
		0x928C9310D74214DEULL,
		0x13835337B86E72BCULL,
		0x0442F59BA7488DFCULL,
		0xD4761F657D79E546ULL,
		0x82BC8E812D4E3040ULL,
		0x23FC4285C1540E1BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCBCC590BA6777021ULL,
		0x5DF68B42DBD6D991ULL,
		0x7BD5A913B1AC2500ULL,
		0x37B42A65613E46A5ULL,
		0xE8EED88880856A48ULL,
		0x9E6E86979C6BEFBEULL,
		0xFF99E6AF6F3D5653ULL,
		0xF480E42DA0697897ULL
	}};
	t = -1;
	printf("Test Case 418\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 418 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -418;
	} else {
		printf("Test Case 418 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x297FA5D5E3A215C8ULL,
		0xA650FC4DB93C5D9BULL,
		0xF9DF9AF6732E36C1ULL,
		0xC013E5107F612884ULL,
		0x14BCA91B5A253B77ULL,
		0x4A5EEDCA8274CC19ULL,
		0x473B54EF595B4824ULL,
		0x9246981BB3CE9B96ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB9D2DD769EE589F2ULL,
		0x3B01D06861E346D2ULL,
		0x975CCDC87FDF360FULL,
		0x54ADF4FB9F7E4055ULL,
		0x14B494B7C0AEDA5BULL,
		0xA622D9683888FEB9ULL,
		0x4BC612C4547870B9ULL,
		0xA07A63B5558F6617ULL
	}};
	t = -1;
	printf("Test Case 419\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 419 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -419;
	} else {
		printf("Test Case 419 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB11EDE4F0CAED4FBULL,
		0xD8666209B378A234ULL,
		0x492CB0DA5591C981ULL,
		0x8346854F2AB1E131ULL,
		0xF52D470BD63AB69CULL,
		0x041D5FEF520230C5ULL,
		0xE5F186D5A0DAB802ULL,
		0xA68A3B62007F07C8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1093D3AEF939C64AULL,
		0x0C2F4CCB612E1A03ULL,
		0x1F3089E4259F2CD0ULL,
		0xB54F456E41775E9FULL,
		0x427F7A8B47F505E7ULL,
		0x0B3C557887D16C7CULL,
		0x6425B977FC3851CBULL,
		0x2609DDB0D421E747ULL
	}};
	t = 1;
	printf("Test Case 420\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 420 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -420;
	} else {
		printf("Test Case 420 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA801AC9CA95D9D1AULL,
		0xBE93BA9BFE4C6D2FULL,
		0x560C0270DA2DF6C8ULL,
		0x296C48B8DC00ADD6ULL,
		0xCB8EB11A3D616DA1ULL,
		0x7321B76B8EDA740CULL,
		0x6EB52623F4BE0DEFULL,
		0xB3A2AD3D1496654CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA801AC9CA95D9D1AULL,
		0xBE93BA9BFE4C6D2FULL,
		0x560C0270DA2DF6C8ULL,
		0x296C48B8DC00ADD6ULL,
		0xCB8EB11A3D616DA1ULL,
		0x7321B76B8EDA740CULL,
		0x6EB52623F4BE0DEFULL,
		0xB3A2AD3D1496654CULL
	}};
	t = 0;
	printf("Test Case 421\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 421 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -421;
	} else {
		printf("Test Case 421 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x53BCCDF786719B8BULL,
		0xEF1421BA14A48D14ULL,
		0x5992FB684DA72464ULL,
		0x142FE8F44E809CD0ULL,
		0xBBD08CAD06E6A39AULL,
		0xF05780A69D2F9259ULL,
		0x3B4C8BD9E521199FULL,
		0x2C2CED6C55126EC9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8A379D9057A13BDBULL,
		0xEF894B4285BD272DULL,
		0xEF4D9AF75F59D14DULL,
		0x64494F46B7954459ULL,
		0xE6308C365985B9F5ULL,
		0x51D64ECF88138BCFULL,
		0xBEDA677ABB0AD2FFULL,
		0x135E8D97A7AF4237ULL
	}};
	t = 1;
	printf("Test Case 422\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 422 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -422;
	} else {
		printf("Test Case 422 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x44D06502ADE55A5EULL,
		0xA1FD84B19345ED45ULL,
		0x53B9C5BF3BAEC1A9ULL,
		0x7A32F61B3AB3DBFAULL,
		0xACB814D13D84673BULL,
		0xD41B820A131CE2C1ULL,
		0x3BD7D017E06C0F68ULL,
		0x97416B8F9E5D515CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBDA2ABD16DC414FDULL,
		0xFC270CE08A46D1B9ULL,
		0x32E5C79E9F892225ULL,
		0x528232AF4E69153EULL,
		0x6B89D7059E149C33ULL,
		0x2E6288CAAC6E8328ULL,
		0xB1BE2A96E6856097ULL,
		0x738DAA8526751E5FULL
	}};
	t = 1;
	printf("Test Case 423\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 423 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -423;
	} else {
		printf("Test Case 423 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2967869DD6B728F9ULL,
		0xE889A7B465E06D70ULL,
		0x0E07A6F2D2702103ULL,
		0x18765F49A0822AFEULL,
		0xE534390FBDC303EEULL,
		0x0BE566E8A98E0487ULL,
		0x04D54471D4E48117ULL,
		0x2A896F2C6D827AA5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2DFE227040B40B21ULL,
		0x4310E3AA77FE2E13ULL,
		0x7149C5ADCFDB7E3EULL,
		0x4D666649562E9B3CULL,
		0xFC29B6F646C2A805ULL,
		0xA0B3C060A1558A75ULL,
		0xC0271DBE141B22A4ULL,
		0x11B7975E1F759A36ULL
	}};
	t = 1;
	printf("Test Case 424\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 424 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -424;
	} else {
		printf("Test Case 424 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x84FEDDE4FA864639ULL,
		0x683C7171B06A652DULL,
		0xEEC5304781B395BEULL,
		0x523EB3B82414DF07ULL,
		0x47A624A9BEBD9365ULL,
		0x9A6F023F473C0C57ULL,
		0xEB49166B2510FB1FULL,
		0x228C690B9C480326ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x84FEDDE4FA864639ULL,
		0x683C7171B06A652DULL,
		0xEEC5304781B395BEULL,
		0x523EB3B82414DF07ULL,
		0x47A624A9BEBD9365ULL,
		0x9A6F023F473C0C57ULL,
		0xEB49166B2510FB1FULL,
		0x228C690B9C480326ULL
	}};
	t = 0;
	printf("Test Case 425\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 425 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -425;
	} else {
		printf("Test Case 425 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB6090A4135BB6285ULL,
		0x2B9D32E45BD8D8ECULL,
		0x50824F343D6ED83BULL,
		0xB88BB22AD87FABBDULL,
		0x20FD32E4160E6CD6ULL,
		0xF9AE5CAADC990756ULL,
		0x7690064FE19BE958ULL,
		0x21019846B58D9F27ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x41678C4D84BD3127ULL,
		0x9357514504CBD7A3ULL,
		0x4FB6622B41F3990EULL,
		0x6DD2364714871214ULL,
		0x67E21AE80FFA534FULL,
		0x1AE1ECE4D962019AULL,
		0xD0412F63C2E2A225ULL,
		0xA97F9792A22327FDULL
	}};
	t = -1;
	printf("Test Case 426\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 426 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -426;
	} else {
		printf("Test Case 426 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1F737FABEF59E8A3ULL,
		0x56619495DDA2498BULL,
		0xA49B2C05C84DDB77ULL,
		0xCBFAECD2D72ACBBAULL,
		0x178E27D4A2A576FDULL,
		0x8661E0FE29A5B855ULL,
		0x011ECB00F6909F00ULL,
		0x0329827348986AA1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3B741151B0C89EACULL,
		0x4DF1C22BBA4F1548ULL,
		0x82DE4B0C304C8790ULL,
		0x188387AC27F5E4C9ULL,
		0x28D1B5F1F75E48DAULL,
		0x14693ABB48B4E6C7ULL,
		0xADD5AD4B06659EB7ULL,
		0x12528C5EAD68911AULL
	}};
	t = -1;
	printf("Test Case 427\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 427 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -427;
	} else {
		printf("Test Case 427 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8BA934D34FCD61FCULL,
		0x7271E2FE51506797ULL,
		0x2948371B3D19573BULL,
		0x5B2612A0E3B114EEULL,
		0x9187073DFFFB3377ULL,
		0x05AF5103AFFA508CULL,
		0xB3DB4C3A34F5562DULL,
		0x9CEAA568C97B2842ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x81DFF2B0281A8CBBULL,
		0x48A2E3D716D9DAE5ULL,
		0xCEA82E4A09F807A2ULL,
		0xB13E86A261F6A386ULL,
		0x4635C9E5F12517BEULL,
		0x02194FFBE58EDC03ULL,
		0xBEBD4EE5D1A9FF1BULL,
		0x28B92DFF3C3F2946ULL
	}};
	t = 1;
	printf("Test Case 428\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 428 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -428;
	} else {
		printf("Test Case 428 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4A6D797E59380C8AULL,
		0x1764C6E6D9038548ULL,
		0x11A25134BFF2A531ULL,
		0xE690397B8101B1DCULL,
		0xE86DEB8DA48974FBULL,
		0xCD6F7D69931542D4ULL,
		0x68A92E574F362193ULL,
		0xAA8735D615F9BFA5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4A6D797E59380C8AULL,
		0x1764C6E6D9038548ULL,
		0x11A25134BFF2A531ULL,
		0xE690397B8101B1DCULL,
		0xE86DEB8DA48974FBULL,
		0xCD6F7D69931542D4ULL,
		0x68A92E574F362193ULL,
		0xAA8735D615F9BFA5ULL
	}};
	t = 0;
	printf("Test Case 429\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 429 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -429;
	} else {
		printf("Test Case 429 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x082631B0C8F9F4D8ULL,
		0x51551E151A396C54ULL,
		0xBB5D23509DC43A2DULL,
		0xCE5DDA72907636D6ULL,
		0x911B41EDE13C960DULL,
		0xA78DAFD446F9E9D7ULL,
		0xB80E89BA54034BDFULL,
		0xAD7AE7A85074AD3BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAA52D00637DDB463ULL,
		0x515CAC3298F6DC25ULL,
		0x0465759A40A45FC3ULL,
		0xBBED64CBB40388ADULL,
		0xB16D36FEC8A27CB0ULL,
		0x82AB6B74D3DF47FBULL,
		0x796A64A242921C1EULL,
		0x8033B0E09CFC3C2DULL
	}};
	t = 1;
	printf("Test Case 430\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 430 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -430;
	} else {
		printf("Test Case 430 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3D689CFBF4EB98D2ULL,
		0x6EAD3D8F42771C69ULL,
		0xB85E934FAFFEDC1AULL,
		0x8468489AB6D67E11ULL,
		0x87581B53167BE27DULL,
		0x50FAC222AF685031ULL,
		0xE52B90DD5C7B98D0ULL,
		0xAAD82947B3613EC0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9D01EA507E10DE44ULL,
		0x69DC53808571FA1EULL,
		0xC79BF172BD678140ULL,
		0xA77B7D5424BF396CULL,
		0xA8C85C2F96F5BCFFULL,
		0xCAE6145AEAFC0352ULL,
		0x0342E3D079DA49D7ULL,
		0xDDC039F4FD300B1CULL
	}};
	t = -1;
	printf("Test Case 431\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 431 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -431;
	} else {
		printf("Test Case 431 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3E7B4BDEEE53FA8CULL,
		0x3169477DD6ABE330ULL,
		0x15F6E3A49986B384ULL,
		0x7A16EB6FDDBCF1A5ULL,
		0xCE81B2D3C0F715ACULL,
		0x872AE8566FA29E46ULL,
		0xA7028743F9FE00E3ULL,
		0xB1CE2311CCFA4DF8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2FD1019A7E29ACF2ULL,
		0x532A247645B1C53AULL,
		0x8889148A62A0A700ULL,
		0x6DAEB3FC23BD12E2ULL,
		0xEAA13A35C8A3A741ULL,
		0x2748FF6384DAD326ULL,
		0xA1FE54855616162BULL,
		0x6007E3774B92A6A5ULL
	}};
	t = 1;
	printf("Test Case 432\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 432 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -432;
	} else {
		printf("Test Case 432 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8F8263C2AD3E117EULL,
		0x8C3D637E8CDD0CFCULL,
		0x4E5122288A74010CULL,
		0xF8CDF6B3F57599C7ULL,
		0xABC928500DA76C96ULL,
		0x5A5EC1A6C3AC7E49ULL,
		0x5FD7A6BD44F98B84ULL,
		0x320CA11AF1BD999DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8F8263C2AD3E117EULL,
		0x8C3D637E8CDD0CFCULL,
		0x4E5122288A74010CULL,
		0xF8CDF6B3F57599C7ULL,
		0xABC928500DA76C96ULL,
		0x5A5EC1A6C3AC7E49ULL,
		0x5FD7A6BD44F98B84ULL,
		0x320CA11AF1BD999DULL
	}};
	t = 0;
	printf("Test Case 433\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 433 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -433;
	} else {
		printf("Test Case 433 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3FAD59B6DBE31180ULL,
		0x77ADE64819D9F92EULL,
		0x0B3EA19BBC16F965ULL,
		0xCAB68A1639D60FD5ULL,
		0xB58B540C966E2782ULL,
		0xB1D0AB24693D70D9ULL,
		0xEBF138FC2A273322ULL,
		0xADFA7F5B9071D8A8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x96AA62BB6164237EULL,
		0x8D9433D425F13E51ULL,
		0x0C0DBEC0B3840A5FULL,
		0xE4D4E36CAC6C3617ULL,
		0xD6076467A7483290ULL,
		0x5CFC4D76DA2D23C2ULL,
		0x0543FA65A66E9E35ULL,
		0xB0629B0DE1DFBC62ULL
	}};
	t = -1;
	printf("Test Case 434\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 434 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -434;
	} else {
		printf("Test Case 434 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x23FA3B695C5CC49BULL,
		0x35182709520DCC9DULL,
		0x058F8DE5515483D0ULL,
		0x80A4861419CDB3E6ULL,
		0x0C3BA34BFA8FD780ULL,
		0x460E10ECB86D4A6EULL,
		0x7F40A72E90384B80ULL,
		0xA60908065FFBEB31ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x65D338815ACD489FULL,
		0x0F1DC593E67CA91BULL,
		0x45483EB3A36F3BF3ULL,
		0x228BD68121DE17B8ULL,
		0x792083CCABE5D078ULL,
		0xA517429ED7512E0DULL,
		0x1951689335FBE640ULL,
		0x7E2619DE5989CA55ULL
	}};
	t = 1;
	printf("Test Case 435\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 435 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -435;
	} else {
		printf("Test Case 435 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFE5C810571A50AE0ULL,
		0xF13F27AF99002BFEULL,
		0x9094561E231D55E5ULL,
		0xF014B21899221017ULL,
		0x4A76E3D035E2F97EULL,
		0x00CE3D3A2320C228ULL,
		0xD317DE321B452076ULL,
		0x34597318C7BE1E7BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3EA3EBE820812456ULL,
		0xC3F60156932AA07CULL,
		0xCAEC1BE5520DB730ULL,
		0xBCA9CD986C17FB06ULL,
		0xE53CE8924DB3696AULL,
		0x106D07EA042EEB49ULL,
		0x8E9AA443E3B416E0ULL,
		0xE289ED0A80B73F75ULL
	}};
	t = -1;
	printf("Test Case 436\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 436 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -436;
	} else {
		printf("Test Case 436 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD4FCCC87EBF2DEF0ULL,
		0x5B222B127DCE26D4ULL,
		0x163AD8059E58CA1DULL,
		0x70FEDD0B70685A54ULL,
		0x80817C81A30BF38DULL,
		0xDA4CD40B4458521AULL,
		0xA43654A683CFB188ULL,
		0x58990E0B1C037563ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD4FCCC87EBF2DEF0ULL,
		0x5B222B127DCE26D4ULL,
		0x163AD8059E58CA1DULL,
		0x70FEDD0B70685A54ULL,
		0x80817C81A30BF38DULL,
		0xDA4CD40B4458521AULL,
		0xA43654A683CFB188ULL,
		0x58990E0B1C037563ULL
	}};
	t = 0;
	printf("Test Case 437\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 437 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -437;
	} else {
		printf("Test Case 437 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD7AC004B113DE202ULL,
		0x8567F8C487A80790ULL,
		0x79020541E5DB08A4ULL,
		0xF4B657BCF7D0BD5DULL,
		0x57FF5E40AD623ED0ULL,
		0x80C2041DCB699F95ULL,
		0xD0FA339A00B6A64CULL,
		0x38BF0A389C91FCFEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF245B72A20D1C3AFULL,
		0xF2DA3DBA7A7BF68AULL,
		0xB55BEDF350F9DE67ULL,
		0x650A5C24B960C825ULL,
		0x0711B38C3975409AULL,
		0xB386061A5B649DF4ULL,
		0x84A23A37854A48D6ULL,
		0xDD4D525EF280B1CFULL
	}};
	t = -1;
	printf("Test Case 438\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 438 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -438;
	} else {
		printf("Test Case 438 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x67B47F210FCC0CBBULL,
		0x0895FE88804AE9C2ULL,
		0x27F48C22822DE04DULL,
		0x91F80DEA80AC3AADULL,
		0xCAA488EE95673A84ULL,
		0x2C2D80C093184415ULL,
		0x70F87D2A3EF7A394ULL,
		0x6EB2EF9163E5BC70ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x238BDC982735DE4AULL,
		0xE36DA9D826F6FD9EULL,
		0xC069818B56434AF6ULL,
		0x6D51A1F53C5C08E4ULL,
		0xF4B2D10A589A58E7ULL,
		0x36F40887A08217C3ULL,
		0x9397D597705B8B1FULL,
		0x092E29AED6222F10ULL
	}};
	t = 1;
	printf("Test Case 439\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 439 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -439;
	} else {
		printf("Test Case 439 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB185890430E82ECCULL,
		0x33C655114CB23FBAULL,
		0x29BB7F59D61EC8EBULL,
		0xC093B2E324ACA95FULL,
		0x3A18BE7DB24777B0ULL,
		0xCC42600FBF5B5C1AULL,
		0x23DFE9D33EB5B757ULL,
		0x6E4492D0663DBF6AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3B4E5EB14F93A58FULL,
		0x7ED2C271517B569BULL,
		0x3481A0C2A0EAFE9FULL,
		0x018455D9A0CE3AE1ULL,
		0x92500A1D41BC1FF6ULL,
		0x6B2E242EBD2A5177ULL,
		0x3AFFC53A302C9136ULL,
		0x606E2847B82ECBFAULL
	}};
	t = 1;
	printf("Test Case 440\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 440 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -440;
	} else {
		printf("Test Case 440 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5F14822F8B86DD24ULL,
		0x57B10144D12F5091ULL,
		0x9100DD9CBC4F8ACDULL,
		0xEB0765AEDECB5975ULL,
		0x8D1FA04286D1F91BULL,
		0x03BD9E0696392D4EULL,
		0x6080A4A6035E867DULL,
		0xC4E83D4DA114EDB6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5F14822F8B86DD24ULL,
		0x57B10144D12F5091ULL,
		0x9100DD9CBC4F8ACDULL,
		0xEB0765AEDECB5975ULL,
		0x8D1FA04286D1F91BULL,
		0x03BD9E0696392D4EULL,
		0x6080A4A6035E867DULL,
		0xC4E83D4DA114EDB6ULL
	}};
	t = 0;
	printf("Test Case 441\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 441 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -441;
	} else {
		printf("Test Case 441 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6C490CA629E74B82ULL,
		0x9C33C644B311DEC8ULL,
		0x24E808FAD3EA4BB6ULL,
		0x438135AFB7B66CC1ULL,
		0x5399F01FF3545347ULL,
		0xBFAD9596813E52E6ULL,
		0x0E1DA71C736A7CB0ULL,
		0x6B83A43D7503088FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9EC18FFCA9EA7056ULL,
		0x0777BD990B3B11E4ULL,
		0x87D80E590CB46B79ULL,
		0x546CF3D703446247ULL,
		0xF3295186D9EC8EECULL,
		0x6A878759A12F6CEEULL,
		0x72987993469E8E9BULL,
		0x9CBD7F9EDA671AE4ULL
	}};
	t = -1;
	printf("Test Case 442\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 442 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -442;
	} else {
		printf("Test Case 442 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCE850B4B5204345AULL,
		0x8400E4AAF095FBC6ULL,
		0x3A05A96D7BD2F97CULL,
		0x524879EB6F30E7A2ULL,
		0xAB74B112F69425E4ULL,
		0x8A68E2CE235646A8ULL,
		0x5B6A275B0805EC70ULL,
		0xA60E01C7FE61C022ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x84C9E1EBF1A0F4B4ULL,
		0x1243B2A0334AD997ULL,
		0x66097C9222CB97C2ULL,
		0x7C8CDA16E75A71D7ULL,
		0xE863F469B53E14B0ULL,
		0x853FDD97B65F596DULL,
		0x165E8E7770D0EB02ULL,
		0x9E7A905C54DF10C8ULL
	}};
	t = 1;
	printf("Test Case 443\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 443 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -443;
	} else {
		printf("Test Case 443 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x59F969D0592131A3ULL,
		0x8A02249AF270C903ULL,
		0x7BE124AE8E5A9A47ULL,
		0xAFEFFC4F2A0C220EULL,
		0x46173D32B7671B40ULL,
		0x52738F2D0C8C01FDULL,
		0x391C75DB0BA33451ULL,
		0xCEAFC36E26DC4D24ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5A17794201025BB2ULL,
		0x784BDA6AFC32AFAEULL,
		0x8E8B05462D6A8342ULL,
		0x3007E15EE42574EFULL,
		0xA58393E45070B2A2ULL,
		0x98F908560E95BD4CULL,
		0xA4AFEAD6CBC6964BULL,
		0xF32AB5FD2B952B59ULL
	}};
	t = -1;
	printf("Test Case 444\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 444 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -444;
	} else {
		printf("Test Case 444 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF5038517BD9EEBE2ULL,
		0xEB4917B0E52B819CULL,
		0x8E01B88C55042339ULL,
		0xAF79A06D10AA1E6BULL,
		0xD320568DE64B709AULL,
		0x7845F5C9DA6552DFULL,
		0xC08B732D3EAC3D9FULL,
		0x831CC1472167EB21ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF5038517BD9EEBE2ULL,
		0xEB4917B0E52B819CULL,
		0x8E01B88C55042339ULL,
		0xAF79A06D10AA1E6BULL,
		0xD320568DE64B709AULL,
		0x7845F5C9DA6552DFULL,
		0xC08B732D3EAC3D9FULL,
		0x831CC1472167EB21ULL
	}};
	t = 0;
	printf("Test Case 445\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 445 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -445;
	} else {
		printf("Test Case 445 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x58EEA11574B6CD38ULL,
		0xD6DBA2C76942A195ULL,
		0xD703CF835D11EDA2ULL,
		0x6FF32A6BFD356CF0ULL,
		0xCAED435CDC1E2219ULL,
		0x8F0CA559DABFFF15ULL,
		0xAF9EB1CE674D87A4ULL,
		0x257E318C9919222BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB6597BE702113522ULL,
		0xE32042FD34B358D7ULL,
		0x22424AC2EB81D182ULL,
		0x25993963C42BC61FULL,
		0xE6A3EA45BAE476BAULL,
		0xC35CD30DFA8FE878ULL,
		0xF72AEAE38AD6DAF0ULL,
		0xA362C31EA064E03FULL
	}};
	t = -1;
	printf("Test Case 446\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 446 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -446;
	} else {
		printf("Test Case 446 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xECE3E88D93896E1FULL,
		0x4A8C3554C3BB8660ULL,
		0xF377ABD1CF14EFBDULL,
		0x813086E6F081114FULL,
		0x3E2138405AD0ED21ULL,
		0x401ECD31258D5C34ULL,
		0xF8C500DDC6009AADULL,
		0x15122579732EEE78ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x827A3A139D88B453ULL,
		0x8910055112066A71ULL,
		0x977E24D22167E396ULL,
		0x5DB547CC674E2B2BULL,
		0x92ED57505ECF7EFFULL,
		0x7FD8F9E7D9CBD3FEULL,
		0x8F18D5F55C1CB8E8ULL,
		0xF3A4EFCA0720BFCDULL
	}};
	t = -1;
	printf("Test Case 447\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 447 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -447;
	} else {
		printf("Test Case 447 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x26B3A27DD95ED038ULL,
		0x8F94D64463E20D9BULL,
		0x271AD774C2D8E7EAULL,
		0x5FAD0BFD6081A38FULL,
		0x838B1D09AE318D42ULL,
		0x478F36F3B20E5868ULL,
		0x14E383F66251BE4CULL,
		0x36BD3A9F276E3143ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x31C86F6E9ED8A138ULL,
		0xEBBF68877859CF36ULL,
		0x16D7BF3DBC3F9860ULL,
		0x7E7CDEE3E5866D9DULL,
		0x97876220A04FE545ULL,
		0xA4D56B345A1CA280ULL,
		0x0F8B28DA1A2A2F9DULL,
		0xB2F99676D87F47B3ULL
	}};
	t = -1;
	printf("Test Case 448\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 448 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -448;
	} else {
		printf("Test Case 448 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB871BA3EB4A2DC2FULL,
		0xDE0F36011F232C35ULL,
		0x737FC3192504660EULL,
		0x00D7FA89144214E6ULL,
		0x1C8D7488A6A5FC13ULL,
		0x8185F7103E48D2CCULL,
		0x757E4CE9D5AA47BAULL,
		0xCDF0C0C359620512ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB871BA3EB4A2DC2FULL,
		0xDE0F36011F232C35ULL,
		0x737FC3192504660EULL,
		0x00D7FA89144214E6ULL,
		0x1C8D7488A6A5FC13ULL,
		0x8185F7103E48D2CCULL,
		0x757E4CE9D5AA47BAULL,
		0xCDF0C0C359620512ULL
	}};
	t = 0;
	printf("Test Case 449\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 449 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -449;
	} else {
		printf("Test Case 449 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1FA25299C0E8D98FULL,
		0xD93C49E198B7CEA7ULL,
		0x51154830A9587D74ULL,
		0x592DF28F5FE07B4AULL,
		0x14D9D497A4900ADAULL,
		0x032B3256BFF292EAULL,
		0x5B6611ADBDF86084ULL,
		0x53E0507D2977EE36ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x69728BD5D941D308ULL,
		0x6F5124F31C51B542ULL,
		0x9D80B2F7EF40F1A5ULL,
		0x63B9F9E6D1C203C9ULL,
		0x429C3D9328867333ULL,
		0xCB4F680269D36406ULL,
		0xC4741DA259A69C5AULL,
		0x194F34CCC0E04411ULL
	}};
	t = 1;
	printf("Test Case 450\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 450 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -450;
	} else {
		printf("Test Case 450 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x791DA6991177F87CULL,
		0xE6B3384214E3CBC1ULL,
		0x9B68AEED04266EA4ULL,
		0x7F423A20485F9EC8ULL,
		0x7C51722F60803C38ULL,
		0x03AD80ABF7EB34B6ULL,
		0xF6103172D199FC18ULL,
		0xA5A16E1483374877ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x30DA5221562E097EULL,
		0xB0406450CDCFDAACULL,
		0xE63B2F80B8EFF399ULL,
		0xD82ABDD35F1F0483ULL,
		0x1EBAB456FF20701CULL,
		0x1DAF4ED2D71DD956ULL,
		0x479474A695571D19ULL,
		0x11FE2579BCDC5E6EULL
	}};
	t = 1;
	printf("Test Case 451\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 451 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -451;
	} else {
		printf("Test Case 451 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5530CB5BED04640BULL,
		0xF8DD1EE5F9955745ULL,
		0x7582147DBC85A74DULL,
		0x85585E794B280B65ULL,
		0x0B54981B24AFC1DEULL,
		0x9E3CCB305AF06BDAULL,
		0xEDDE559D58F62BECULL,
		0xD5D86E21E87AC240ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC673936AF35D515AULL,
		0x0AA5CA6D146957F6ULL,
		0x717FFDFB498DE228ULL,
		0x1CCFA93838FC7C76ULL,
		0x8CFCEFBB6AE9CA54ULL,
		0x736EB91ECF59D012ULL,
		0x12B411F1A2149530ULL,
		0xA4AD2A4774B34A44ULL
	}};
	t = 1;
	printf("Test Case 452\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 452 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -452;
	} else {
		printf("Test Case 452 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x73C3B331D0D2E53AULL,
		0x41AA56FC4E654B12ULL,
		0x8FE81ED156634743ULL,
		0xF42AF3242722F629ULL,
		0x7CD278EAF0CB4E1EULL,
		0x6882437F7DCAED96ULL,
		0x5727C501FDCCB8D7ULL,
		0xFCA066771728E542ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x73C3B331D0D2E53AULL,
		0x41AA56FC4E654B12ULL,
		0x8FE81ED156634743ULL,
		0xF42AF3242722F629ULL,
		0x7CD278EAF0CB4E1EULL,
		0x6882437F7DCAED96ULL,
		0x5727C501FDCCB8D7ULL,
		0xFCA066771728E542ULL
	}};
	t = 0;
	printf("Test Case 453\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 453 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -453;
	} else {
		printf("Test Case 453 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8B8D1813F26C7933ULL,
		0xE8A19B43B28CC37DULL,
		0xA086D129E030B0D1ULL,
		0x61FA99278F578807ULL,
		0x4B1010068F0AB0F4ULL,
		0x2336C10F5CD379B3ULL,
		0x84D79328A9B05837ULL,
		0x582FB5E0A49ACADAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF7C8F387BD4298FEULL,
		0x28B446D789CD26A9ULL,
		0x8F7207EF1666F8D7ULL,
		0x20CA7FAC3BE882F8ULL,
		0x7C75A29F6D4D2E75ULL,
		0x78B0212768FCE6A0ULL,
		0xA6ED2390118DC33EULL,
		0xF6693463EC7AF984ULL
	}};
	t = -1;
	printf("Test Case 454\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 454 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -454;
	} else {
		printf("Test Case 454 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x350FDA0463C3F630ULL,
		0x44F6E38F2D1F2E4EULL,
		0xDAEE7DFFE535DD2CULL,
		0x493838124D3B213EULL,
		0xA30F4AC02899FB56ULL,
		0x9A33385D54473D63ULL,
		0xCFA584D99A50BDDCULL,
		0xC8A31FF4CDDEF7C5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1B9155239B0C0E8DULL,
		0x439BA530B090EEE4ULL,
		0x0F8A2964D95995DEULL,
		0x92A03D0D90821406ULL,
		0x7B141749D54D863DULL,
		0xD81BB48ABD1E45B6ULL,
		0x4574D79084445B22ULL,
		0xF5BA4A8BB6A2D12EULL
	}};
	t = -1;
	printf("Test Case 455\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 455 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -455;
	} else {
		printf("Test Case 455 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x39A8C554C062F900ULL,
		0xE3CFF5DE45752EC9ULL,
		0xBA4B2B32320411D9ULL,
		0x5E981676541A084BULL,
		0x9E6C63942090BF01ULL,
		0x5F52AD194C8A4B7AULL,
		0xB0A2AC1B64630087ULL,
		0xB0DC20ABB8D91A96ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFB6C9056B4A72BDAULL,
		0x725307042EA8A195ULL,
		0x29C0DD33C72B4ED2ULL,
		0x3108F199F1C07DA3ULL,
		0x46AA3EC845FDCA0CULL,
		0x1A3D0938AE9A1ED2ULL,
		0xF6CECB6541F29D51ULL,
		0x177DD1402DA0A269ULL
	}};
	t = 1;
	printf("Test Case 456\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 456 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -456;
	} else {
		printf("Test Case 456 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x29E7E1AFB11F8CAAULL,
		0x4D581A6760C4F53AULL,
		0x1A262982F269C0D3ULL,
		0x9A418621252BD22CULL,
		0xBC926AB301887DEAULL,
		0x95FAE255F849E44CULL,
		0x0BD5E5EACE507472ULL,
		0x7F9034DAA8520247ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x29E7E1AFB11F8CAAULL,
		0x4D581A6760C4F53AULL,
		0x1A262982F269C0D3ULL,
		0x9A418621252BD22CULL,
		0xBC926AB301887DEAULL,
		0x95FAE255F849E44CULL,
		0x0BD5E5EACE507472ULL,
		0x7F9034DAA8520247ULL
	}};
	t = 0;
	printf("Test Case 457\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 457 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -457;
	} else {
		printf("Test Case 457 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7462983B1C18A2A4ULL,
		0xCBB2CAE82D34AD1DULL,
		0x497692DACDBEB7EAULL,
		0x04E7D8376CEF61E6ULL,
		0xEC494E525FC056E3ULL,
		0xA7198D55C9F0CB78ULL,
		0x60D82E0D5ED712C1ULL,
		0xED7DA48547024246ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x800B8D19BF7CF406ULL,
		0xE6E621E6126761BAULL,
		0x59E2D36433FA908FULL,
		0x1FF300F0AF14C706ULL,
		0x92E71354C51A4BABULL,
		0xC17654944BE9D94FULL,
		0x1478EEC274440E2AULL,
		0x659C8B28CBCCF95DULL
	}};
	t = 1;
	printf("Test Case 458\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 458 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -458;
	} else {
		printf("Test Case 458 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x624F3B1B8FADB015ULL,
		0xEFFE92869138AD09ULL,
		0xB240CFC0E19FAFB1ULL,
		0x21E5627CC37FC51DULL,
		0xD014BFD22ABFA968ULL,
		0x693A797F10F9E045ULL,
		0x655F4D7D316B32ADULL,
		0xC6FF2095149F7063ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x55DCDEE26CB20B7DULL,
		0x15769A2F0E0ED96DULL,
		0x851A3E9094FC85DBULL,
		0x8EB3C37E322D14ECULL,
		0xD6F88F11F93F9B56ULL,
		0xA6E519AA1B2BE48EULL,
		0x2D4622A7CA3592D2ULL,
		0xBEB2A4A546E155D4ULL
	}};
	t = 1;
	printf("Test Case 459\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 459 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -459;
	} else {
		printf("Test Case 459 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFC200D0BFE54CF31ULL,
		0xADE1F7BDE45F05D9ULL,
		0xBB0ABB9A6D719170ULL,
		0x3B9CDAD23C46CC50ULL,
		0x8432B52A9CAE7D27ULL,
		0x7BB66EA1DD0121ABULL,
		0x98FB3EC9776DE535ULL,
		0x266ED576988EDFCEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x72C826A3C0F76E28ULL,
		0x4727CC3CC40D45A0ULL,
		0x904303F6F7489D0AULL,
		0x47D471130D17B799ULL,
		0x9218EE9F2A615CC4ULL,
		0x3331C0FDF380141FULL,
		0x744F4F43A8BD0BADULL,
		0x6403654FFB69C5D1ULL
	}};
	t = -1;
	printf("Test Case 460\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 460 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -460;
	} else {
		printf("Test Case 460 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA62B327096C67176ULL,
		0xF42CE403E78E3AACULL,
		0x2487646D8B849C74ULL,
		0xAB35518312B27E78ULL,
		0xB5CF9065A5AAE365ULL,
		0xEBBFF2357E2B886AULL,
		0xED941CDD273F62C0ULL,
		0x43EBF3B1E76119B4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA62B327096C67176ULL,
		0xF42CE403E78E3AACULL,
		0x2487646D8B849C74ULL,
		0xAB35518312B27E78ULL,
		0xB5CF9065A5AAE365ULL,
		0xEBBFF2357E2B886AULL,
		0xED941CDD273F62C0ULL,
		0x43EBF3B1E76119B4ULL
	}};
	t = 0;
	printf("Test Case 461\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 461 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -461;
	} else {
		printf("Test Case 461 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCA2F3104B9A6E164ULL,
		0x0D1919E5A779EF05ULL,
		0x33D83D34DE80BEF0ULL,
		0x4784AC0B38C1BEE4ULL,
		0x9C15BE67ABFE5354ULL,
		0xD4EE139CC7E5A959ULL,
		0x967473D89AD9CE26ULL,
		0x213E97AA2ECC6033ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1ECC78303D9D1CA2ULL,
		0x5F6D2C51D374C61DULL,
		0xA9EC5A454E1D3FFFULL,
		0x6C0984EAB22606EAULL,
		0x7239E39F757B2BFFULL,
		0x0561794E6136A18BULL,
		0x06FF2D5A809EA462ULL,
		0x769336F9F7006F27ULL
	}};
	t = -1;
	printf("Test Case 462\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 462 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -462;
	} else {
		printf("Test Case 462 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x83AEC78FA49BCE8EULL,
		0x6CA141889CA0529CULL,
		0xCBCDDC6E32B0311AULL,
		0xA7EBA0D4543B02B0ULL,
		0x9FD1BC443D4B04C3ULL,
		0xC81266735B81DD5CULL,
		0x729F4E894746BD67ULL,
		0xFF9BED4CB0B7BD81ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC62BEF6C58AA9507ULL,
		0xD40C3B5832110795ULL,
		0xDA1A5CF697D303D2ULL,
		0xEEAB0EF754298840ULL,
		0xD56C952EE8B3A3BDULL,
		0xDB887A8D7BBF62ACULL,
		0x161FC333F5034AECULL,
		0xEA9DE6F3FCF3D9A9ULL
	}};
	t = 1;
	printf("Test Case 463\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 463 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -463;
	} else {
		printf("Test Case 463 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x79FE02E601A1C5D4ULL,
		0x1E82D38F9A7BD974ULL,
		0x08E64498A00D1161ULL,
		0x6B97CA075A7A4A41ULL,
		0x94B6B02D5817E523ULL,
		0x83CF71029C406361ULL,
		0x3B6797C61C8862E1ULL,
		0x2CA5B3D703E9BE22ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEB2B0B6D4B2A6555ULL,
		0xDAFEBE9B39BCE14CULL,
		0x21ACFDE7D67CA474ULL,
		0x426AD90AE2C36693ULL,
		0x336BEF9D962A93BAULL,
		0x98792ECE6EF5E1D3ULL,
		0xE2425A16DA7750CDULL,
		0x170621251046A874ULL
	}};
	t = 1;
	printf("Test Case 464\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 464 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -464;
	} else {
		printf("Test Case 464 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x14205A2C08D9F353ULL,
		0x54BF0A053AA4268BULL,
		0x8AC8A30FFC685FE0ULL,
		0xBB38FDB0836D30C6ULL,
		0xA58D4DFDB57ADC38ULL,
		0x9054794AB6B69825ULL,
		0xF4E398B2829A721FULL,
		0x77A228C951277829ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x14205A2C08D9F353ULL,
		0x54BF0A053AA4268BULL,
		0x8AC8A30FFC685FE0ULL,
		0xBB38FDB0836D30C6ULL,
		0xA58D4DFDB57ADC38ULL,
		0x9054794AB6B69825ULL,
		0xF4E398B2829A721FULL,
		0x77A228C951277829ULL
	}};
	t = 0;
	printf("Test Case 465\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 465 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -465;
	} else {
		printf("Test Case 465 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFA69030947586D72ULL,
		0xB380C7664B0390D5ULL,
		0xB31FEE03872DE2A3ULL,
		0xC0387E508BBCE79DULL,
		0x70E416562C8058C6ULL,
		0x13E83F16B40F426BULL,
		0x86B8A846E6BE64E5ULL,
		0xC80F618333DFBEECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD6046F4B9B2C0332ULL,
		0xAA999D8254D44A24ULL,
		0x541D209EE051AC4EULL,
		0xC483A94E34213CE6ULL,
		0xA1313A0917A52492ULL,
		0xF00CA5CCA0D43EB5ULL,
		0x2B689D07153ECCDFULL,
		0x5E52475A1F66DFDDULL
	}};
	t = 1;
	printf("Test Case 466\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 466 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -466;
	} else {
		printf("Test Case 466 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCB4C7DC7E8D01FC4ULL,
		0x9B34724E6EB03326ULL,
		0xD74C2C6101065384ULL,
		0xA58546EB82035C55ULL,
		0xAB2A7A4DFA939F80ULL,
		0x797C9F2D48549168ULL,
		0x15AA6DC3654D0FE5ULL,
		0x9F2B95D34993B630ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x51A79FF546BB5DB8ULL,
		0xB03199FE0CBCED52ULL,
		0xB6911859A48350E8ULL,
		0x8B96B5931421863FULL,
		0x92E8B2D399FB12E4ULL,
		0x5855A7258D9F9409ULL,
		0x151EC0BD51B82C90ULL,
		0x20884B6745630AF1ULL
	}};
	t = 1;
	printf("Test Case 467\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 467 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -467;
	} else {
		printf("Test Case 467 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1FE2892A7B21ED5FULL,
		0xBC1B6FCC4F4CDEA8ULL,
		0x7A26F2FC3BAA95CBULL,
		0x9BD2A6C1E70233F0ULL,
		0xFE09E6146869A0C7ULL,
		0x9FE5DA31A069C410ULL,
		0x972F7739C8A5214EULL,
		0x8DD8FB6D698CDAADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB19D83032E54C8D0ULL,
		0x7F892EE17A4B9A13ULL,
		0x7E507F68F27B37A8ULL,
		0x961888DF5C136E18ULL,
		0x3686D0D7155E5584ULL,
		0x015830BE222AFA53ULL,
		0x55FBF25483B95433ULL,
		0xFD189843C3962133ULL
	}};
	t = -1;
	printf("Test Case 468\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 468 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -468;
	} else {
		printf("Test Case 468 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEF558490D9B6E399ULL,
		0x75FEB8E266C3D002ULL,
		0x5F7D2A8F2841E6E9ULL,
		0x57BF80A18E650E38ULL,
		0xD03805666B071F26ULL,
		0x6B76A2484CBEE5C0ULL,
		0x376D7EE8D89042C6ULL,
		0xB59DDAC7063F8FD2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEF558490D9B6E399ULL,
		0x75FEB8E266C3D002ULL,
		0x5F7D2A8F2841E6E9ULL,
		0x57BF80A18E650E38ULL,
		0xD03805666B071F26ULL,
		0x6B76A2484CBEE5C0ULL,
		0x376D7EE8D89042C6ULL,
		0xB59DDAC7063F8FD2ULL
	}};
	t = 0;
	printf("Test Case 469\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 469 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -469;
	} else {
		printf("Test Case 469 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD3DA7FF32B59FBFEULL,
		0x608B72B906FF09F8ULL,
		0x2172FF3DB923C627ULL,
		0x64B289DAA645C3B5ULL,
		0x6304ACC6FA1B5EC8ULL,
		0xD56E5713DCF2073AULL,
		0xF2F1E554F48CBD0CULL,
		0xBDC080DF30CF1182ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA6504304DD4E8C92ULL,
		0x0F9D2B1589ACDCFFULL,
		0x9FF9FF40627F7AEBULL,
		0x2C9F3B0D0B196265ULL,
		0xD55F7DBBF2E359DCULL,
		0xE09F8D406055FD68ULL,
		0x37CAE96C7313874AULL,
		0x782CAFD4B0459EC0ULL
	}};
	t = 1;
	printf("Test Case 470\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 470 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -470;
	} else {
		printf("Test Case 470 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEBCB7D48772A04FCULL,
		0xD583A3C4BBAFC69FULL,
		0x1C7520554B2284D6ULL,
		0x70B277A434861DEBULL,
		0xC3754B43CCB08538ULL,
		0x41376E4D3C61E22FULL,
		0xE022309538A30C00ULL,
		0x2FCFC45C0E6ED620ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFFAEA8EA4098C3F2ULL,
		0x60D467D515BF1978ULL,
		0x90D45B48B37D7CB6ULL,
		0x7023A190088E0919ULL,
		0x2AE033A891C27852ULL,
		0x9EF7DB2578B4796BULL,
		0x5C3F84CEAAF11347ULL,
		0x18E297EEA34DAD21ULL
	}};
	t = 1;
	printf("Test Case 471\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 471 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -471;
	} else {
		printf("Test Case 471 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x85531D4701AE8E16ULL,
		0xFE9A2CFE1E5FF611ULL,
		0x6700F5ABCC2E6B61ULL,
		0xC1EB3D611F9487F7ULL,
		0x6AE5EB46461918BDULL,
		0xDFEAA4853CA8B9C0ULL,
		0xF69D43B8DF4C644AULL,
		0x417C205EF7C4B04EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x66D575FE12C4222EULL,
		0x9E004B9D6E97CEF1ULL,
		0x32987BB8137BE837ULL,
		0x005478EFEAFDF614ULL,
		0x45842B9B4408F2C0ULL,
		0xB53F9FE59E06D1F3ULL,
		0x3B29BB645717DDD7ULL,
		0x3795A3121BCC6C24ULL
	}};
	t = 1;
	printf("Test Case 472\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 472 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -472;
	} else {
		printf("Test Case 472 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8FDE938313482C42ULL,
		0xCFA4927721B826D2ULL,
		0xCB3E19FE836A93DDULL,
		0x4739818F67D89A3EULL,
		0xC3B3B781537AC5EFULL,
		0xE8AEC3F4FDDAB379ULL,
		0x2F8BC4D5BBE7C0F2ULL,
		0xE646C2562CDB1BCCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8FDE938313482C42ULL,
		0xCFA4927721B826D2ULL,
		0xCB3E19FE836A93DDULL,
		0x4739818F67D89A3EULL,
		0xC3B3B781537AC5EFULL,
		0xE8AEC3F4FDDAB379ULL,
		0x2F8BC4D5BBE7C0F2ULL,
		0xE646C2562CDB1BCCULL
	}};
	t = 0;
	printf("Test Case 473\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 473 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -473;
	} else {
		printf("Test Case 473 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD7FC5B16253411A3ULL,
		0xC0183AD183666AEAULL,
		0x20266602542164C5ULL,
		0xF67E680070BC16E3ULL,
		0xED223C12BDBB5DD4ULL,
		0x30EFEEB873870C2EULL,
		0xAFADED5B97910DFFULL,
		0x7BB11A73E86663D7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8B13A11D0C532497ULL,
		0x5996454A6694FE65ULL,
		0xEEAD50EE924BDBACULL,
		0x84F3FC4CEE3D5B1AULL,
		0xAEC4203F424961E7ULL,
		0x2EF12282A1BEF178ULL,
		0xB8BCD798DA163774ULL,
		0xA5EAC16ACAB36072ULL
	}};
	t = -1;
	printf("Test Case 474\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 474 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -474;
	} else {
		printf("Test Case 474 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xABBCB56F36AF3072ULL,
		0x3C954D768D0F1A24ULL,
		0x4FCCCF1B83DC9AE6ULL,
		0x1DFAC9213AF7DEACULL,
		0x81A4D62832978516ULL,
		0xDE9A49EB1ED1B28EULL,
		0xF0F38FF53E3D7176ULL,
		0x0E2A306143818F9AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9996C928C7139E60ULL,
		0xA4CF659323038A44ULL,
		0xBCDDD4504C0056B4ULL,
		0x309DE08A1666953BULL,
		0x1A5F92EEF3275FF2ULL,
		0x4380893C7F32FEB3ULL,
		0xF07E7C9610BC60C9ULL,
		0xC40EDA67E696FF4AULL
	}};
	t = -1;
	printf("Test Case 475\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 475 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -475;
	} else {
		printf("Test Case 475 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDABD5FA6E34689FDULL,
		0xF8CF20965F188C42ULL,
		0x5D8860411C4821E8ULL,
		0xC5CB3DE79A2A5084ULL,
		0x9BA27EE6FBA51731ULL,
		0x7B3B248610EFC12DULL,
		0x391FC5DCE538FC5EULL,
		0xE5E0D2D99A6CBDD7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x41416FC8E6383A2EULL,
		0x38EB74D91BFFD42DULL,
		0x03CE77BFDFF85609ULL,
		0xE73A8BA12F42BAAFULL,
		0xB8616E349D68DEBDULL,
		0x4165B18049BE0C20ULL,
		0xB250E11EF4A91115ULL,
		0x909E99F3B8A5AF96ULL
	}};
	t = 1;
	printf("Test Case 476\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 476 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -476;
	} else {
		printf("Test Case 476 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE17162C5FA38CD37ULL,
		0x6810E2C7FD3538A9ULL,
		0xA86C7CA179B5E037ULL,
		0xAFDB0DCB6A159F70ULL,
		0x80D27D15F35ADB81ULL,
		0x1E9A6831275FEF74ULL,
		0x5BAA6E9D386F712AULL,
		0xD3B396CEC3E0EBBBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE17162C5FA38CD37ULL,
		0x6810E2C7FD3538A9ULL,
		0xA86C7CA179B5E037ULL,
		0xAFDB0DCB6A159F70ULL,
		0x80D27D15F35ADB81ULL,
		0x1E9A6831275FEF74ULL,
		0x5BAA6E9D386F712AULL,
		0xD3B396CEC3E0EBBBULL
	}};
	t = 0;
	printf("Test Case 477\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 477 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -477;
	} else {
		printf("Test Case 477 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x12B66C2D1F31511FULL,
		0x49FEAC782817577CULL,
		0x16E05E249E1092F9ULL,
		0xD183530151649532ULL,
		0x226DB0CBCF380379ULL,
		0x80C6F378BA2EB26EULL,
		0xD25300BDC3D99ECFULL,
		0xFDB75C730117D3EBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xED81DBB8FBBDC7B6ULL,
		0x311DB4B19119165CULL,
		0xC5C8A704BA254969ULL,
		0x55EBC53046BA2F45ULL,
		0x879EE420F806841EULL,
		0x0C98DDBF44A52420ULL,
		0xC362BC3CE00876CEULL,
		0xAAABFA7075DFF4B3ULL
	}};
	t = 1;
	printf("Test Case 478\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 478 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -478;
	} else {
		printf("Test Case 478 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6B89CBE786C692FAULL,
		0xCAC1D5BF6CBF99C0ULL,
		0x0D12473138214870ULL,
		0x2292334B4190129CULL,
		0x80B8401E463FA973ULL,
		0xDBE10F654FCDA221ULL,
		0x6A56C200E62E7446ULL,
		0xB9672C92E4098FB9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFA87C9B03C429D87ULL,
		0xF25FD61E0C9FCC04ULL,
		0x9D1CE3F3D4FC47D8ULL,
		0xF228292CE87CC411ULL,
		0x5D15485BB0681897ULL,
		0x9662D6E4AB1E7B1BULL,
		0x4F45155C4016BB44ULL,
		0x4D74844CFD93FAF8ULL
	}};
	t = 1;
	printf("Test Case 479\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 479 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -479;
	} else {
		printf("Test Case 479 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB2BAF4E827C4505EULL,
		0xD23872C88406E905ULL,
		0x0184DCE54BBF3879ULL,
		0x5FE2E210FB812353ULL,
		0x70C9909CDAB5070DULL,
		0xEF2A9A6902F86CD1ULL,
		0xA3FF77C2ECF4D65CULL,
		0xB6E84C02D3B5C23EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB95ACB74E85C15ADULL,
		0xEF084F5DA8325D31ULL,
		0xC24E35E83058E59CULL,
		0x96A48566D868A4E8ULL,
		0xE12533133F6312F9ULL,
		0x7EFD104EF6594966ULL,
		0xED1FF8F0E9C3ED8BULL,
		0x51EA149B87719C54ULL
	}};
	t = 1;
	printf("Test Case 480\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 480 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -480;
	} else {
		printf("Test Case 480 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x18117D2E385B08A1ULL,
		0x36A2EFCAD0C06077ULL,
		0xFEE135127287F719ULL,
		0xF84EB5384B06679BULL,
		0xF3426D5C365A27ABULL,
		0x68BC6E5B99F234D6ULL,
		0xB26575072AF71B51ULL,
		0x3DF9D62D3A72E459ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x18117D2E385B08A1ULL,
		0x36A2EFCAD0C06077ULL,
		0xFEE135127287F719ULL,
		0xF84EB5384B06679BULL,
		0xF3426D5C365A27ABULL,
		0x68BC6E5B99F234D6ULL,
		0xB26575072AF71B51ULL,
		0x3DF9D62D3A72E459ULL
	}};
	t = 0;
	printf("Test Case 481\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 481 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -481;
	} else {
		printf("Test Case 481 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x300117BE8BA8A45CULL,
		0xE83858A2DDB1F770ULL,
		0xD2C620278D805C36ULL,
		0x095EFE1FB08BD985ULL,
		0x3CBFF25D0DFE445FULL,
		0x07FE2E6796155251ULL,
		0x6D289EC3867058EFULL,
		0xBF6F1FBF074C9F70ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD9632BB1C095A95EULL,
		0x653CC5B07D58A9EDULL,
		0x4674A00F256F1418ULL,
		0xF70BB9FE47D1D043ULL,
		0x5FA10F94AAB4A55BULL,
		0x62CCD51A70CE322CULL,
		0xED6FAEBBB1C9189CULL,
		0xA7CFB08AC112BD04ULL
	}};
	t = 1;
	printf("Test Case 482\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 482 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -482;
	} else {
		printf("Test Case 482 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x58803107DCA8A150ULL,
		0x48F1ECCA675EC15EULL,
		0x23F9D8161AB193D4ULL,
		0x230873F9169821A4ULL,
		0x373FF520A0033259ULL,
		0x96120BC3344C1E71ULL,
		0x0E94E5F029BF4972ULL,
		0x3E7A90192AD51E9EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9F0CEEB3424ED104ULL,
		0x6EE3096001D77D4AULL,
		0x2C35E270AC15AAC4ULL,
		0xCA02E364BA7F51C4ULL,
		0xA96E855C2A357741ULL,
		0x3154979321F69BE3ULL,
		0xF0CB1C58AAB21686ULL,
		0xFAC16C80C460713EULL
	}};
	t = -1;
	printf("Test Case 483\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 483 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -483;
	} else {
		printf("Test Case 483 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5C1989E87D2403D0ULL,
		0xD42FD6662D4AFB94ULL,
		0x548C0D8AA7E8AA24ULL,
		0xB0AA477202F43F39ULL,
		0x29398D332A5AE3C8ULL,
		0xCDFED174EA50E91EULL,
		0x2BA02B70BDD62D3DULL,
		0x6B6582EB81FFE479ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2D28F713788D0210ULL,
		0x2EC77A37644AD7A3ULL,
		0xCB9C68CD00AEDB2AULL,
		0xE9AC87E7C28F8D69ULL,
		0xB1F5A79DD6BEC8CEULL,
		0x6EBD081602093932ULL,
		0xA787BB4F95F9B1AEULL,
		0xDA2AC84937B25100ULL
	}};
	t = -1;
	printf("Test Case 484\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 484 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -484;
	} else {
		printf("Test Case 484 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1CBCE5828409CF22ULL,
		0x041B41EB89345510ULL,
		0xABB326CFC118D5B5ULL,
		0xBA9BCC7CF3C963E2ULL,
		0xD7B031FA9C7E58D7ULL,
		0xC814237680BB41DBULL,
		0x43BED82B3CD8F605ULL,
		0xDBB2369C37A8CFFAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1CBCE5828409CF22ULL,
		0x041B41EB89345510ULL,
		0xABB326CFC118D5B5ULL,
		0xBA9BCC7CF3C963E2ULL,
		0xD7B031FA9C7E58D7ULL,
		0xC814237680BB41DBULL,
		0x43BED82B3CD8F605ULL,
		0xDBB2369C37A8CFFAULL
	}};
	t = 0;
	printf("Test Case 485\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 485 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -485;
	} else {
		printf("Test Case 485 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x052C760E630289C1ULL,
		0x911D9CE815C64739ULL,
		0x3949B883BFA32061ULL,
		0x293875025AF4F14CULL,
		0x96C20C082D04221FULL,
		0xEC26833D5D40E4D1ULL,
		0x82CDFC63C4969AF2ULL,
		0x72723FA92B212AB2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4B2B90B4ABEF90E4ULL,
		0x1770EFE9B78D05A9ULL,
		0xB2B69DED8BC060F1ULL,
		0x071CEAB209F73FB1ULL,
		0x7063DEE80878EF29ULL,
		0x83B3B2BA0B6DDE0DULL,
		0x4D7A85A825EDBF38ULL,
		0x8C0BFE8128D4D14CULL
	}};
	t = -1;
	printf("Test Case 486\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 486 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -486;
	} else {
		printf("Test Case 486 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA8EAA5D85401B343ULL,
		0xD327A1825DA7F348ULL,
		0xD4F4842B1EDF184FULL,
		0x48B68676B8167E78ULL,
		0x1BA7996D17C0AA00ULL,
		0x221E18D8F67B89A7ULL,
		0xC4EB98C1AA156D1FULL,
		0xB9397F24BBF80AF6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x65E2209FDD47CECCULL,
		0x923B2EE4DD921370ULL,
		0x60A2B344D4EE9B63ULL,
		0xC26B113E76540450ULL,
		0x462E75FCDE0DBBB3ULL,
		0x4CFF2B2410C3FF52ULL,
		0xF241CCCE5DC95C98ULL,
		0xD7C8F2EB84E0B34DULL
	}};
	t = -1;
	printf("Test Case 487\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 487 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -487;
	} else {
		printf("Test Case 487 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC24B9A536B658295ULL,
		0xCE92C5F578E133D1ULL,
		0xBBF400302557B1FFULL,
		0xE57F8CB96954AF14ULL,
		0x0AC75C2490B38007ULL,
		0x06C75B9F178B109CULL,
		0xA8C60761B63C2FA6ULL,
		0x7CF5E78BBBC56F87ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x84404C5EB2A73A14ULL,
		0xF08217852E3CB967ULL,
		0x9DD5C4A1384C11A0ULL,
		0x3A3E45D53986C568ULL,
		0xD7811E9EFE75F943ULL,
		0x04C83C1A01096E65ULL,
		0x6593E13F616527FAULL,
		0x573EC6909D9D7B16ULL
	}};
	t = 1;
	printf("Test Case 488\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 488 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -488;
	} else {
		printf("Test Case 488 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6077E6141DD91374ULL,
		0xCAEF6637F9436AF0ULL,
		0x644953BBAD723545ULL,
		0xCBBB8E0AB7275184ULL,
		0x89FE2F0202181F9EULL,
		0xEA1409EDE5BB493FULL,
		0x0C0FEF84644C40D2ULL,
		0x3FE436B75267C727ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6077E6141DD91374ULL,
		0xCAEF6637F9436AF0ULL,
		0x644953BBAD723545ULL,
		0xCBBB8E0AB7275184ULL,
		0x89FE2F0202181F9EULL,
		0xEA1409EDE5BB493FULL,
		0x0C0FEF84644C40D2ULL,
		0x3FE436B75267C727ULL
	}};
	t = 0;
	printf("Test Case 489\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 489 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -489;
	} else {
		printf("Test Case 489 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCFCBE4F89BFE771EULL,
		0xD49DDA2E767F2C1FULL,
		0xAEAA4BB2FDAC0CDAULL,
		0xBBCE857090764A7EULL,
		0x0697AA59AE6AB34DULL,
		0x6F51ADCA0A290F8BULL,
		0xD3F53FFE7517B265ULL,
		0x097AD5115849357AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5F2A3F928C950A2DULL,
		0x663A96967AB5B631ULL,
		0x7BFB8E6D9FA9F877ULL,
		0x8668FE51BA18699AULL,
		0x73BF2DA6CA77D6E6ULL,
		0xF5ECC9A34E94A808ULL,
		0x2C826BEA354F7613ULL,
		0x9A64D31013603109ULL
	}};
	t = -1;
	printf("Test Case 490\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 490 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -490;
	} else {
		printf("Test Case 490 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0C68E8F7903BFAEDULL,
		0xEA9AB64B841EE18EULL,
		0x34546187CDEB3A23ULL,
		0xAED38EFB94A07C89ULL,
		0x0FF75E5ABCFA6F1FULL,
		0x9D440E329CC0436DULL,
		0xD4A258DBFAAE2076ULL,
		0x32B6749BAD52F434ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x731141818E406D88ULL,
		0x7BD7E33A3FACCA75ULL,
		0xA8E4A0010CCAB19EULL,
		0xC1FC0323C47B779CULL,
		0xB11C2731322C26D7ULL,
		0xF5BB78CA3BAC8718ULL,
		0x98A4148615FC1450ULL,
		0xAC697C0C171B2E3FULL
	}};
	t = -1;
	printf("Test Case 491\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 491 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -491;
	} else {
		printf("Test Case 491 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x394CED152F38CACCULL,
		0x4311355C0B2DEF46ULL,
		0x049D5FCC48767E89ULL,
		0x709B78599FBAA874ULL,
		0xF5E0D0F90A00D34AULL,
		0x7536319726136C1FULL,
		0x53E0DD14526A1C62ULL,
		0x0EC41031BAD324EDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x16CE8AF28901E9A7ULL,
		0xF8E69E9E6CC86D30ULL,
		0xAB4334E86141AEC2ULL,
		0x6F9D34815EC12986ULL,
		0x0A9DEF2654E8CED0ULL,
		0x6915E3E50BB711ADULL,
		0xCF2F36F684996942ULL,
		0x46DD0D85F42E977EULL
	}};
	t = -1;
	printf("Test Case 492\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 492 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -492;
	} else {
		printf("Test Case 492 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x94CBD9D8B801DDE4ULL,
		0x26CE5A0A3186EAB6ULL,
		0x14E0191442F28507ULL,
		0xE6663B0CE425697AULL,
		0xEAD59EDEEBEBDC97ULL,
		0x89EE7F813E2CC036ULL,
		0xFE226B709A2EFE6AULL,
		0xF5BB8D652D0E1E9AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x94CBD9D8B801DDE4ULL,
		0x26CE5A0A3186EAB6ULL,
		0x14E0191442F28507ULL,
		0xE6663B0CE425697AULL,
		0xEAD59EDEEBEBDC97ULL,
		0x89EE7F813E2CC036ULL,
		0xFE226B709A2EFE6AULL,
		0xF5BB8D652D0E1E9AULL
	}};
	t = 0;
	printf("Test Case 493\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 493 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -493;
	} else {
		printf("Test Case 493 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x84012CD073771F87ULL,
		0x35D319282E9E433AULL,
		0x278C58C8A9BF616FULL,
		0x1FFEDDFDFEE81849ULL,
		0xDE266EBF187A0606ULL,
		0x076FF293238145A4ULL,
		0xE058C58955316E9AULL,
		0xF8736663F9555E02ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9BA4E792E52FBF70ULL,
		0xBC087A9E46A80060ULL,
		0xC545D90DE391823EULL,
		0x47F4E2F5EAB6B761ULL,
		0xB8C774A009C73734ULL,
		0x7ABAE4EBB9A501ABULL,
		0xA5FA946863482048ULL,
		0x01DBF54E380A772CULL
	}};
	t = 1;
	printf("Test Case 494\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 494 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -494;
	} else {
		printf("Test Case 494 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFB6799A74B29E472ULL,
		0xD7D7372A2F9A97E6ULL,
		0x720A51BA80D1DBCFULL,
		0x9A97961B2158D458ULL,
		0x19BF6B182E67D328ULL,
		0x671B6357B8A0A220ULL,
		0x2A11654D1AD7AD6DULL,
		0xC5A1F79EEEEC986EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA15245E07E92E630ULL,
		0x7BFF27BFC6314F28ULL,
		0x3AF086D3AE53C0C2ULL,
		0xB6A0D2F717C8AD5DULL,
		0x2A9BB3EDB8483508ULL,
		0x7CDDFF61FDB62C5AULL,
		0x31147EC4D44F6A29ULL,
		0x5CD6940F492212F0ULL
	}};
	t = 1;
	printf("Test Case 495\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 495 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -495;
	} else {
		printf("Test Case 495 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8FAEA2734782E73EULL,
		0x2A7D90D898B950C0ULL,
		0xF14002BB5DAB1F50ULL,
		0xD056C0300165D96DULL,
		0x4202D7ECD11F5694ULL,
		0xA9D9C58B7BCBEB72ULL,
		0x5C7D3F42C7F075E0ULL,
		0x623207EFE1998314ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF4F55D64376FDA89ULL,
		0x5B4D59B883A3BD4DULL,
		0xA920EAC41173A38BULL,
		0xA3E2B31DF6DA6FE6ULL,
		0x1AA52ABCBAAE6D87ULL,
		0xE5D5A7499A1E7F74ULL,
		0x54775743C361E3BFULL,
		0xB044404C866F1DE1ULL
	}};
	t = -1;
	printf("Test Case 496\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 496 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -496;
	} else {
		printf("Test Case 496 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x77CCEC6792043BC2ULL,
		0xDA37ED324BE96E3FULL,
		0x687F8AF69AEA9365ULL,
		0xE458F31086E4B018ULL,
		0x071BC4A1F8E36683ULL,
		0x0F3AC9A06CABDD05ULL,
		0x9449CBA18306A3DCULL,
		0xFFB7CC41F5E23DAFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x77CCEC6792043BC2ULL,
		0xDA37ED324BE96E3FULL,
		0x687F8AF69AEA9365ULL,
		0xE458F31086E4B018ULL,
		0x071BC4A1F8E36683ULL,
		0x0F3AC9A06CABDD05ULL,
		0x9449CBA18306A3DCULL,
		0xFFB7CC41F5E23DAFULL
	}};
	t = 0;
	printf("Test Case 497\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 497 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -497;
	} else {
		printf("Test Case 497 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x14A8AD76E7D94819ULL,
		0x5496D57F52BD00DDULL,
		0xCF3E21BA88764A02ULL,
		0xBC1F5E91F3009DC1ULL,
		0xA6755FB11C4A58A3ULL,
		0xC6DD67F0941E3E0DULL,
		0x2A333E7A9B4AD14EULL,
		0x8B351575394A2E95ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x83C427262FD03A8CULL,
		0x4F44E2F5FEBFD5DEULL,
		0xB8CF039813829396ULL,
		0xBA4A7D4024EA658BULL,
		0x44C9FBD9F6A48B89ULL,
		0xD017BCB68423CBDAULL,
		0xD0EC6A5550A87656ULL,
		0xB58FA58E9F7F2697ULL
	}};
	t = -1;
	printf("Test Case 498\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 498 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -498;
	} else {
		printf("Test Case 498 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x61BEBCC7E6D4419BULL,
		0x68A02ED08AD480A7ULL,
		0x76688E908E505AC1ULL,
		0xA7FC8B2476EB8E38ULL,
		0xDE0730BCA5D748D8ULL,
		0x8AB1D68622809D28ULL,
		0x01C0376CECF481F3ULL,
		0x74FB70D1A6B02ABEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x16F4BFAF29D16B72ULL,
		0x34217624FD891E41ULL,
		0xDCF1566E5007D402ULL,
		0x4FB480E62697ABF6ULL,
		0x2169ECD229E32EDEULL,
		0x7A2F1ED824C03E47ULL,
		0x6331E425C47ACB08ULL,
		0xA556CF25C945972DULL
	}};
	t = -1;
	printf("Test Case 499\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 499 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -499;
	} else {
		printf("Test Case 499 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE52510AB05E5EB1CULL,
		0xF39AA55DFE2C1C36ULL,
		0x58CA83BDA2B0AE9FULL,
		0x5A992BA28155C8B0ULL,
		0xEB2629376C716CD4ULL,
		0x381CB51DE3E2E811ULL,
		0x5712FD631D2FFE2FULL,
		0x2292A4E25940F0FBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2AF3CA6785E549EFULL,
		0x7410942AD05A7DE9ULL,
		0x6F9A7DE4D49009EBULL,
		0x7B5DB1EC460D983FULL,
		0x82613B9B01B0173AULL,
		0x678178AAB48F34C1ULL,
		0xF1BCBBA17923307BULL,
		0xFA79BDAD16B5DA79ULL
	}};
	t = -1;
	printf("Test Case 500\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 500 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -500;
	} else {
		printf("Test Case 500 PASSED\n");
	}
	printf("---\n\n");
	return 0;
}