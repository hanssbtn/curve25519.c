#include "../tests.h"

int32_t curve25519_key_cmp_test(void) {
	printf("Key Comparison Test\n");
	curve25519_key_t k1 = {.key64 = {
		0x9CE5513345F0F47AULL,
		0x4B4430F835190425ULL,
		0xB98A06ED4F8A399BULL,
		0xE6B475F0C60FA12BULL,
		0x9BE5CCBC28DF09C9ULL,
		0xE945CB231ECD86CFULL,
		0x8F80101363F91FA6ULL,
		0xBDAE3AA3FB326E8EULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0x4677F388AA52B4A9ULL,
		0x2F6CEFA3B6A8B9D0ULL,
		0x9BF850C5E2875163ULL,
		0x79D6F02F5E94D5FFULL,
		0xCB7CE8F0CFD3933FULL,
		0xEA8C53650F8377FEULL,
		0x65CACB83587CD937ULL,
		0x2A0E302C652F3274ULL
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
		0xE21A0C0AE2E66E18ULL,
		0x22AA562BF42CF182ULL,
		0x277418A8C7B19C81ULL,
		0xABB7DE26AC284186ULL,
		0xEE1D2490D2CD13BAULL,
		0x4E4378D7254DFFC2ULL,
		0x3E1BBB319D2C2AC3ULL,
		0x290E745102B43C72ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4CBCD9DF350CAEC5ULL,
		0x50CE47D5A9191EDAULL,
		0x2929926A68082EA7ULL,
		0x8A545B6B3F6F4528ULL,
		0x7605ED85BAE0F5F6ULL,
		0x24B7F14DF4580560ULL,
		0xBBBBF46CC9CCFD8DULL,
		0x2DACB4548A105C80ULL
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
		0x34F3D3BF0657A4CBULL,
		0x6ED768195C051FB5ULL,
		0x7E02BD70B2C13EA5ULL,
		0xEA9D0B7288819B18ULL,
		0xB979D41B84C1F0A4ULL,
		0x0FE37051C599A6E0ULL,
		0xE3432061116E16E6ULL,
		0x7944594A3E840767ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9026066D1026FB46ULL,
		0xDFB634F0EAA32CD8ULL,
		0x68932DCF1490C18CULL,
		0x1EAD38F83349DF56ULL,
		0x5EABC8A42FFACB9EULL,
		0x9BEBE6DCCCB5FF89ULL,
		0xD21A0E4E19B78CEFULL,
		0xBF66164325F935D8ULL
	}};
	t = -1;
	printf("Test Case 3\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xD1D943BA33E2A7EDULL,
		0x94146F5C56611634ULL,
		0xEC72551E3B35152AULL,
		0x5C1E108F7C3528CFULL,
		0xACDEA8AC4580C468ULL,
		0xBF740F82E7E9FDBCULL,
		0xA802FCCAC808CB30ULL,
		0xEB27A1AEEEC6024CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2889EB49707E70E1ULL,
		0x49EC8C893E8FED87ULL,
		0x9CF12EAF2A3CC1CBULL,
		0xF42DBA65BF1B31BDULL,
		0xDFE6A1DA782D7CC6ULL,
		0xD524E34C3E87B3A5ULL,
		0xB56405C462E8B872ULL,
		0xAFC5A795B7F39E37ULL
	}};
	t = 1;
	printf("Test Case 4\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x1FA59B431A0B6443ULL,
		0x2DE2C0074C314FEAULL,
		0xF21D9122DDE265C9ULL,
		0xBF8952AAE1E375C8ULL,
		0x86BF1225E3D80DB7ULL,
		0x6A7C5ECB2358937FULL,
		0x064C90145C74C541ULL,
		0x24A908B2280C908EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1FA59B431A0B6443ULL,
		0x2DE2C0074C314FEAULL,
		0xF21D9122DDE265C9ULL,
		0xBF8952AAE1E375C8ULL,
		0x86BF1225E3D80DB7ULL,
		0x6A7C5ECB2358937FULL,
		0x064C90145C74C541ULL,
		0x24A908B2280C908EULL
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
		0xECD0D33362886C05ULL,
		0xDA3C3A2EE2989C1BULL,
		0x305B64E091AB2AE5ULL,
		0xC6CEC1814A156DBCULL,
		0x68002A934CD25A08ULL,
		0xC0706C630C7325A4ULL,
		0x3E5F8935C597CB7CULL,
		0x6558E5FDD6724364ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF283510C9FC2994BULL,
		0xCC3345FFBF2F6C56ULL,
		0x3C83A372105574B2ULL,
		0x3AE3782B413E74F4ULL,
		0x9F2D417F58F6184DULL,
		0xC53FE00755E4E31CULL,
		0xE17C41BBF3C6FC3FULL,
		0x8580685CAC3C130AULL
	}};
	t = -1;
	printf("Test Case 6\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x4A2DC4CDF4884680ULL,
		0x8017C18B1BB8A590ULL,
		0xA32CA1E3FFBC2A62ULL,
		0x6E00BF2B2EC2856FULL,
		0x01627638EA550DB4ULL,
		0x92B517BF0E7992F3ULL,
		0xDFC72A71F35134A1ULL,
		0x4E44045B67546B5FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC352F691B8D73BC8ULL,
		0xB2EA04402039978CULL,
		0xE9BDA9E54A804E03ULL,
		0xACBCBEEC7DB70F89ULL,
		0xC0121799A79C6AD2ULL,
		0xCA0827721D796E51ULL,
		0xB0C696534A26DB94ULL,
		0x29098F856DAB34C2ULL
	}};
	t = 1;
	printf("Test Case 7\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xF06572E0F3CF6CABULL,
		0x6BC0679C661C4040ULL,
		0x49E29DCBDF41748FULL,
		0xB3B734B34C25F165ULL,
		0xB9AC4CEF8B02126FULL,
		0x8CBE0EA61A952B44ULL,
		0x18797C86520CC276ULL,
		0x2853EF18C81B5A30ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9A39D4E0E84EAF62ULL,
		0x70A928DFDB6112B9ULL,
		0xE405428BC71CE4B7ULL,
		0xAEE6375D7825A811ULL,
		0x62322DBE946634B7ULL,
		0xF88412DC5B3A3746ULL,
		0xAB34AE4A6B345E5DULL,
		0xE969DC38855F4B8BULL
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
		0x9D9DF9B62738AFD1ULL,
		0xBCCA517E5325C881ULL,
		0x5B9694F79BF6A584ULL,
		0x7C0E185D9FF33568ULL,
		0x7253022DE00447C3ULL,
		0x75DBFE6AAB8B7C44ULL,
		0x6D1E13B6932DBD79ULL,
		0x448BB24BFA31BD82ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9D9DF9B62738AFD1ULL,
		0xBCCA517E5325C881ULL,
		0x5B9694F79BF6A584ULL,
		0x7C0E185D9FF33568ULL,
		0x7253022DE00447C3ULL,
		0x75DBFE6AAB8B7C44ULL,
		0x6D1E13B6932DBD79ULL,
		0x448BB24BFA31BD82ULL
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
		0xB3A6C93EED42D969ULL,
		0xA218C42F6B5E99F0ULL,
		0xD50EF7AF8C8C7B56ULL,
		0x93FB8B2929C1CFCDULL,
		0x6E690555FEB8307EULL,
		0x81FF3C1A652AD7CDULL,
		0x27CD3C4BFC84E843ULL,
		0x047FA5D1610E09DCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x89DFFFDE0E6A1ECAULL,
		0xE6787E9BFCE42237ULL,
		0xF8F2A8DB835E89D9ULL,
		0x561E4F37C16F5683ULL,
		0x2A2D5F5E91D88620ULL,
		0xEC71CAAD6EDD73D0ULL,
		0x701EC690B158FAFBULL,
		0xFC80EB232090A38DULL
	}};
	t = -1;
	printf("Test Case 10\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x94A2DB1B56E4BF1FULL,
		0x4EAAC11FA673C342ULL,
		0x6445686E72D1107DULL,
		0x0C7DE280D094F497ULL,
		0x5B692D9A9CC09262ULL,
		0x6369271DE0DDE34DULL,
		0xCB8D22FB2A0B3783ULL,
		0xE77D69F5CE30D7EDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x25D6E9C9D2433A7EULL,
		0xB6155BE3B8610E33ULL,
		0xF59F2E21A69BA32BULL,
		0x2D516A7ED7444672ULL,
		0xE5E824536B20AADCULL,
		0xC38869A88BCE0952ULL,
		0x076FDE8DF83F2FD1ULL,
		0xA1B474A514945560ULL
	}};
	t = 1;
	printf("Test Case 11\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x57535BA120C0654BULL,
		0xD3E77589484A3358ULL,
		0x0818486BBB05E6B2ULL,
		0x1C5AEF1652630A7FULL,
		0x63AE3F93485AE163ULL,
		0xCAC66EAD85AA9AC7ULL,
		0x5A83F15594D87F74ULL,
		0x087B3085DE00DDF8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3FB292F7C24DBC06ULL,
		0xBE4648B2EDBD27DBULL,
		0x61B47E6ED4BE2ECBULL,
		0xCA7CC6DBF74D37BBULL,
		0x936ECA598B34204AULL,
		0x72597DF404930A45ULL,
		0x3912C9792DBBDAEEULL,
		0x675A96F5124818BFULL
	}};
	t = -1;
	printf("Test Case 12\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x670CF2F699B582E1ULL,
		0x7F3010EC80820139ULL,
		0x236DBB5400286EABULL,
		0x16C09D3ED986A823ULL,
		0x7FA6802138D5B631ULL,
		0xD1B84B6BFA149BD4ULL,
		0x1AFA3727FB6DD901ULL,
		0x461826CB82E0D2A0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x670CF2F699B582E1ULL,
		0x7F3010EC80820139ULL,
		0x236DBB5400286EABULL,
		0x16C09D3ED986A823ULL,
		0x7FA6802138D5B631ULL,
		0xD1B84B6BFA149BD4ULL,
		0x1AFA3727FB6DD901ULL,
		0x461826CB82E0D2A0ULL
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
		0x5C306FFFDE8A39A2ULL,
		0x856252FC811E88CAULL,
		0x09F9414066BBAC52ULL,
		0x875D2FFA0B303DFCULL,
		0x0B94A8D7EAF6C1FCULL,
		0x99E83673776F5E9BULL,
		0x19E82382D2092F97ULL,
		0xAC965446DA5CB37DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB6C44BA7B0C7B7B6ULL,
		0x755C78C72A7B04FFULL,
		0xF7C703A83DCD4C8EULL,
		0x6BF7A151E9E195A5ULL,
		0x11E07144731CEF35ULL,
		0x4342C1D33B0A89B5ULL,
		0xC2CA078CD649CA5AULL,
		0x5066622E57D9BA62ULL
	}};
	t = 1;
	printf("Test Case 14\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xB3E64DC6505BF514ULL,
		0xFD764CADBAED9D37ULL,
		0x504BCD9C61B238C4ULL,
		0xBB723713E3AC375DULL,
		0xDE2D1E40EC52D37FULL,
		0x217509F2AEB4A03BULL,
		0x448BE6E9CBA31748ULL,
		0xBE8FA5F0B2F9C84BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x17FD59F7628EF66BULL,
		0x862E9B35623E3FD0ULL,
		0xA0C562A56A95E2E4ULL,
		0xDD797CA82AEFEB9DULL,
		0xD37248642C0B3693ULL,
		0x25DC8109D6F8679EULL,
		0x5FB891EABD29508AULL,
		0xB91C56795C91A301ULL
	}};
	t = 1;
	printf("Test Case 15\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xDA291F7A6259AA53ULL,
		0x7E3E6223667E86C5ULL,
		0xB591A97FFCCBB628ULL,
		0x940C217675AD3505ULL,
		0xD2F8F5C9F3524F7CULL,
		0x3A3A69A43A13F6C7ULL,
		0x60E2B71A15863BB6ULL,
		0xA3A25530D246D275ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCB5BFA98C6D3F7C0ULL,
		0xDFA8C65D88D26812ULL,
		0xE66FE6FBDFE64452ULL,
		0xA1BB7C97D82353F7ULL,
		0xDF1FFB4088CF635CULL,
		0x3F6CF7F8F2B976AEULL,
		0xFDFE0593CF0CF0B3ULL,
		0x205505A9D7FD8583ULL
	}};
	t = 1;
	printf("Test Case 16\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xECEEC091D0108498ULL,
		0xA45D1E3AB66B6020ULL,
		0x7EA195F932710756ULL,
		0x05D94885CA76150BULL,
		0xD108E9A56B29CE17ULL,
		0x19AA75FA93FDDBB5ULL,
		0x473C08DD82476923ULL,
		0xB1E8C3A01540B2D2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xECEEC091D0108498ULL,
		0xA45D1E3AB66B6020ULL,
		0x7EA195F932710756ULL,
		0x05D94885CA76150BULL,
		0xD108E9A56B29CE17ULL,
		0x19AA75FA93FDDBB5ULL,
		0x473C08DD82476923ULL,
		0xB1E8C3A01540B2D2ULL
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
		0xBCB1CA5070225587ULL,
		0x53AAA80C1ED20FF6ULL,
		0x027745E8F77BE9B3ULL,
		0xBA46B50B6CF962BCULL,
		0xBE77F55EBBFA9CE4ULL,
		0x3AF88099A3F3E3D4ULL,
		0xED80BCADB427DFD8ULL,
		0x126ECD5216C5A188ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0AE52B06CB6E7644ULL,
		0x1B09CC308EC16B5AULL,
		0xD4F3FFA038204C60ULL,
		0x74D662BF6161C0D0ULL,
		0x32761C07F1521790ULL,
		0x08083E07762E225AULL,
		0x70B362E9358128DFULL,
		0x65DB552FC2601B49ULL
	}};
	t = -1;
	printf("Test Case 18\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x7732D46701C38C25ULL,
		0x936F038DF8670C83ULL,
		0xBEEDEEEA96D3E3EEULL,
		0x4022DC5E87B47D82ULL,
		0xC4124C2E416D16E9ULL,
		0x1B6CA7197AD354D4ULL,
		0x426A1F53F183A57FULL,
		0x39C0838542E1EF6DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x686D0828C064BD3EULL,
		0xCBF87B3325326481ULL,
		0xF16A56E517DF7019ULL,
		0xC94AF33918CD3BBCULL,
		0x000E6A8C6320A3D3ULL,
		0x204CFC17046683E4ULL,
		0x7162DEC09EF1CC57ULL,
		0xAC9CE6B98E0C5AC3ULL
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
		0x827425325494657FULL,
		0xEC421483C666C84EULL,
		0x52CA6CBDEB973ECBULL,
		0x1349EF83A01B5363ULL,
		0xC803F7C18360024BULL,
		0x1C304CEEF66AD57CULL,
		0x63D2321F0B9EE1B9ULL,
		0x2317F5515414AE36ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5EDA7AE9B3BA9633ULL,
		0xBCE6A2C98F655A1EULL,
		0x0F8A17E6DBBD1D14ULL,
		0x7AB28C7293653897ULL,
		0x125AD223942B87AEULL,
		0xCEBA894FBF81C61EULL,
		0x9D5DBAA78E0AF973ULL,
		0x426C40564948C2FAULL
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
		0xDDCF01D48FCBE805ULL,
		0x7524293886EEA491ULL,
		0xB24C36B49A6B3576ULL,
		0x6ABBAA97E657B6A0ULL,
		0xDAC4B32D6696CDB7ULL,
		0xCEB8A6981782AF66ULL,
		0x15A85CFB5628B72DULL,
		0xC9012882F38C0320ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDDCF01D48FCBE805ULL,
		0x7524293886EEA491ULL,
		0xB24C36B49A6B3576ULL,
		0x6ABBAA97E657B6A0ULL,
		0xDAC4B32D6696CDB7ULL,
		0xCEB8A6981782AF66ULL,
		0x15A85CFB5628B72DULL,
		0xC9012882F38C0320ULL
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
		0xA2F7ED2EAA9244E2ULL,
		0x3A76FC8D43E836BEULL,
		0xFBAC34DE5ACF66D5ULL,
		0x52B9082131A4EBAFULL,
		0x4CCF1D3E74783D92ULL,
		0x0964250483040877ULL,
		0x8E304351863AC584ULL,
		0x04F276FA5ADC2547ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0CC44E9E4D200B02ULL,
		0x2BFB487C754D47D6ULL,
		0xF6C75F3BC2F7D484ULL,
		0xD8F043B7C4454605ULL,
		0xC6E5AF95C3C5634EULL,
		0xDE8EDB651DAF6840ULL,
		0xD5C152B3A575D5FDULL,
		0x02D97111FF32F0FFULL
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
		0xA7440ACC142A8B3CULL,
		0x558E38BBCECDFA0AULL,
		0x4BD3056C9F80CD25ULL,
		0x1911222713369208ULL,
		0x11FCE34314A0FA7DULL,
		0x6B538CBDE39F0048ULL,
		0xD903AC99EF47D7C2ULL,
		0x0D57D801B2E0E696ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDE4739A33D2F6A8FULL,
		0x59BDD161F6A6511DULL,
		0xFF2F4BC5F0B0C3E3ULL,
		0x4A1E4BA83D80485AULL,
		0x9B3965DBEE5334B0ULL,
		0x2F22AFF7A8545B03ULL,
		0x227503237E495DB9ULL,
		0x9E4B3A54A20464D1ULL
	}};
	t = -1;
	printf("Test Case 23\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x510B5C2C664D7E43ULL,
		0xD1952FED7662B694ULL,
		0x176FF9AD97629C22ULL,
		0xAC7F89F7040F967FULL,
		0x31677F70CB2181CBULL,
		0xC170BEE6AB10B9B4ULL,
		0xD0E5B74969723E62ULL,
		0x5DFB0E0E02C0E68BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x39CC217E26AE119AULL,
		0xF3B23ECBE0C65007ULL,
		0x5BE85665A023C36CULL,
		0xD697BE7E9C7CDE5BULL,
		0xE6A5F73DEFB5B817ULL,
		0xFE277F8B09210978ULL,
		0x59DD047C6BB6FFCAULL,
		0xC9F2DAEECEF2C674ULL
	}};
	t = -1;
	printf("Test Case 24\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xB884D506E81C3D40ULL,
		0xABC73DA0D1CD26E3ULL,
		0x90CDBF05BFB85AE3ULL,
		0x3ADE2541CB0559E3ULL,
		0x2EEC6C6FF89FE832ULL,
		0x0E3FF107E0368131ULL,
		0x8ABB1A03A889D169ULL,
		0xF0A64A0BE4FE73AFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB884D506E81C3D40ULL,
		0xABC73DA0D1CD26E3ULL,
		0x90CDBF05BFB85AE3ULL,
		0x3ADE2541CB0559E3ULL,
		0x2EEC6C6FF89FE832ULL,
		0x0E3FF107E0368131ULL,
		0x8ABB1A03A889D169ULL,
		0xF0A64A0BE4FE73AFULL
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
		0x3D42C00F2759A8C5ULL,
		0x2A07E20E053EEAAFULL,
		0xD6043986D40AEB49ULL,
		0xE226E5EBAC7D6689ULL,
		0xE86F240684C9AB70ULL,
		0xE04F6F46DE054373ULL,
		0xA0DE5F15B818C397ULL,
		0xA0A5E467572408DCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2850F9FEBA05DBEBULL,
		0x4B93D445EB9DF31CULL,
		0x3C9C30456646D27FULL,
		0x5BE590C7A7B83AB6ULL,
		0x24C8854B4BD48E33ULL,
		0xBD00F8682D541737ULL,
		0xADA4B05133C85DF4ULL,
		0xD6A0DCB429168524ULL
	}};
	t = -1;
	printf("Test Case 26\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x2B4ADCD35C6287E2ULL,
		0x8A31A10E4D80234AULL,
		0x5B9B8B0A386D77B8ULL,
		0x75C380CD47542467ULL,
		0xBE7354F7C96E1CDAULL,
		0x51DC372AB4EE65DBULL,
		0xF80D293140829050ULL,
		0xC272BAA776FDC57EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF1FE2F2682DEB160ULL,
		0xF3575267F6E4A79BULL,
		0x3F4E9E221FED61BDULL,
		0x07DD3B9BD26DF58DULL,
		0x129A031166E2C8B7ULL,
		0x3038D890FDD82E65ULL,
		0x3AC48B9DBADFB407ULL,
		0xC391DCEDC9B5EE43ULL
	}};
	t = -1;
	printf("Test Case 27\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x36E87762C7384C89ULL,
		0xECD6E85E6A1DCD70ULL,
		0x59334578CDB84A8EULL,
		0x724212E92E7C23C5ULL,
		0x56CDA037ABF5A1C4ULL,
		0x199207C56DFF6518ULL,
		0x79EF001291F7E741ULL,
		0xC2D18D0969A9F047ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9A61A17B46816673ULL,
		0xD939E08A2E9E3670ULL,
		0x90F6D05E16B2CD77ULL,
		0x824813F25B802C72ULL,
		0xD17D9A54E8460D65ULL,
		0x602F7CCAACF5EFB7ULL,
		0x80C249B07E7228B4ULL,
		0x36560CB42A2FFC39ULL
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
		0xDA822D03B43E6AF9ULL,
		0x93692DEAE37BE445ULL,
		0xAA2F0AD9D05DF487ULL,
		0xC49DA6F607C1C159ULL,
		0xCF9CF7390D98FF4BULL,
		0x04FF61B1FC0328B0ULL,
		0x1BC524D5B93F46BFULL,
		0x59C6B0795E6818BBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDA822D03B43E6AF9ULL,
		0x93692DEAE37BE445ULL,
		0xAA2F0AD9D05DF487ULL,
		0xC49DA6F607C1C159ULL,
		0xCF9CF7390D98FF4BULL,
		0x04FF61B1FC0328B0ULL,
		0x1BC524D5B93F46BFULL,
		0x59C6B0795E6818BBULL
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
		0xF203BCB4E2B4F9FAULL,
		0xEA66A1A897EC169EULL,
		0xBADE6062E96B9EBDULL,
		0xF99645423E2F230BULL,
		0x9E84E9DEB5F0C54EULL,
		0xE58A7168AFA26E5AULL,
		0x734AECA0D1BB6E90ULL,
		0x70F159B579E41798ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCD81ECE8C8B4FB2DULL,
		0x0C65F0F9EE9784EBULL,
		0x2137FD694E20D8C5ULL,
		0xB42309A71D41A018ULL,
		0x2098FE216391A14AULL,
		0x12CCF557DEC9A0BEULL,
		0x27F3E7D378F3D125ULL,
		0xA70C0056645BC8F5ULL
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
		0xA564DDDC6C134DE4ULL,
		0x5D1C61D85018AB73ULL,
		0x1A2709DD460D81CEULL,
		0xAADFCE4712FA326AULL,
		0x2D42C1BC6D1E54ACULL,
		0x735C87F2CB7E395BULL,
		0x84CC7E685C2FDE09ULL,
		0x23CBB3F81E80977EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2BBA79B94C54DF56ULL,
		0xE342F818A3031841ULL,
		0x8414DF80E5CB0A09ULL,
		0xE0A3D7B6722D6AACULL,
		0x1EB53F368CB32C0FULL,
		0xA883947BB2638C4DULL,
		0x4C88A467AF794BF0ULL,
		0xCA971488CB693A1CULL
	}};
	t = -1;
	printf("Test Case 31\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xAC1B7D94A2FA10F8ULL,
		0x095089617D11AC87ULL,
		0x93CD9B2B293EECB6ULL,
		0x97D08AD06C601CADULL,
		0x2F3871358CF0B667ULL,
		0xCF8D0713D164B7ACULL,
		0x995AADB0C8E495B8ULL,
		0x0F0C19A69FA2C68DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCC62D331D29718BBULL,
		0x8B466D967CA7256CULL,
		0x18DCEB8851AE3C33ULL,
		0x1B0D731A21AB157AULL,
		0x63FE81CCC8F61422ULL,
		0xEB6814A0662056F7ULL,
		0x70D1A41FC1504C81ULL,
		0x02DDDDF33B338D84ULL
	}};
	t = 1;
	printf("Test Case 32\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xB2B7B1F733278E1BULL,
		0x425297499AB5BA31ULL,
		0x3F9C40CD7166D6E5ULL,
		0xCF00208767B1A452ULL,
		0x090835F30FA7B05BULL,
		0x01C7747D4601BFFAULL,
		0x6C2A3D1D8B08C047ULL,
		0x0968DF5FDF81A7B9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB2B7B1F733278E1BULL,
		0x425297499AB5BA31ULL,
		0x3F9C40CD7166D6E5ULL,
		0xCF00208767B1A452ULL,
		0x090835F30FA7B05BULL,
		0x01C7747D4601BFFAULL,
		0x6C2A3D1D8B08C047ULL,
		0x0968DF5FDF81A7B9ULL
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
		0x5F2EF293830C5839ULL,
		0x062EB8861522BA9CULL,
		0x5B7FA45B3BA8A6CEULL,
		0x1E30AE1FECC6D92CULL,
		0x8AB3FC2C82E11F83ULL,
		0x68DF6E1B7682885CULL,
		0x888A0D411844FE2CULL,
		0x38C8EB0AF22A090CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x039260E34D335921ULL,
		0xD32848004B65DD1AULL,
		0x354DFD2A53875FB6ULL,
		0x51B9EB94440D2296ULL,
		0xF368DD871DA587F4ULL,
		0x0714FF534F9135D6ULL,
		0x8C2E086B550FB9D1ULL,
		0x0812DFD023812D97ULL
	}};
	t = 1;
	printf("Test Case 34\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x22E867B270283722ULL,
		0x2450B83319519A82ULL,
		0x680CA1AE4E323C57ULL,
		0x1A8C7082839AFEBFULL,
		0x398FD26014BB910FULL,
		0x544B51CBFFCB6834ULL,
		0xB5117538FF38C848ULL,
		0x5E45C9C662DCFDC0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE170C95CE7CDCF62ULL,
		0x8C0AD4DCD265DEF2ULL,
		0x6F947ECCFD4A8B35ULL,
		0x12B39DA366B5255AULL,
		0x1563F32B97EFCCE3ULL,
		0x8CFDCBA9228D40D6ULL,
		0x925FAA6FDEE686A3ULL,
		0xAF393795D5581B7BULL
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
		0x6D9DC1462F9C97C0ULL,
		0xC27BE33231D7384FULL,
		0x9E13FC5FA23E8B91ULL,
		0xE0766170C6B4D42BULL,
		0xFC65EB6F5F6FAF1FULL,
		0xD89982B7A3E49666ULL,
		0x3E3A62B15FCC5690ULL,
		0x8C8C25AE4232AECEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0DF5EAD1163DCD07ULL,
		0x94635209B4C2374AULL,
		0xA3B6450EB444BF12ULL,
		0x6C94995A4C2920C7ULL,
		0x285F6030554736D2ULL,
		0x91FE28F12F0B60D7ULL,
		0xA4BB1D087743C8F8ULL,
		0xF6BDFD583A86E92EULL
	}};
	t = -1;
	printf("Test Case 36\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x2F4F16931C2758C5ULL,
		0xFCA8255C0EFF21C5ULL,
		0x1F16B183E13F383DULL,
		0xF2AE7F228E072C65ULL,
		0x6E02115C64DE11B2ULL,
		0xB81E7A8186B3BE99ULL,
		0x8D9F4A372F59EF77ULL,
		0xF72E00146069DD5AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2F4F16931C2758C5ULL,
		0xFCA8255C0EFF21C5ULL,
		0x1F16B183E13F383DULL,
		0xF2AE7F228E072C65ULL,
		0x6E02115C64DE11B2ULL,
		0xB81E7A8186B3BE99ULL,
		0x8D9F4A372F59EF77ULL,
		0xF72E00146069DD5AULL
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
		0x43CE88AC4FEE24CBULL,
		0x2F13641061C6E81DULL,
		0x88358475630DF941ULL,
		0xA5800886A20AD411ULL,
		0x21DCA04243E83363ULL,
		0x4AB38258A3C8F340ULL,
		0x496058746C3FAA88ULL,
		0x3DE6E058F3A8E0EAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEA4F17806710BFC3ULL,
		0x725EF230A5268121ULL,
		0x39922912DDE8D0C5ULL,
		0x06019D22E23B5EA4ULL,
		0x04DECA20205855CFULL,
		0x9485834D0E4DCC6CULL,
		0x660413FED12A5B75ULL,
		0x47AF8BDFDD6C92BAULL
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
		0x83D49ADC2DEA19E6ULL,
		0x9BF4DDCC955876DDULL,
		0x5C147BC18E594D9BULL,
		0xF4D8E282841DB247ULL,
		0xDC41B9D262AE46BDULL,
		0x35D2351A30580D79ULL,
		0xD8EF0C27C40D0EB4ULL,
		0xF2F2B790BC8C189CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0846CA5FC096259DULL,
		0xE19D9FEE52C35DDCULL,
		0x1F29F97DD7531D73ULL,
		0x64E5F1A1DD5B2CB0ULL,
		0x31C289DA144D5A0CULL,
		0x39CC0C437A773635ULL,
		0x225476B350F580BBULL,
		0xB09DCD95D6648029ULL
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
		0x4EFA7DD5C5EC1F76ULL,
		0xA73D15CCCEAF015EULL,
		0x80525348F6F0DDABULL,
		0x1639AA840EFBE152ULL,
		0xE62CE0F57EA7CDF2ULL,
		0xE249AF009C0BB432ULL,
		0xC45DF2E350F3CDBAULL,
		0x82DC440F4EA3F2E8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x97F6D252522C4667ULL,
		0xB9A307E4D673D734ULL,
		0xF116089DC3025E43ULL,
		0x65A0C7CDD07467C8ULL,
		0xC3D2F96DC7473364ULL,
		0xA55B7A4C5AFBAF9AULL,
		0x3C151C5491ECAB85ULL,
		0x3732577206D2D21EULL
	}};
	t = 1;
	printf("Test Case 40\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xFF40DD3D90BA780DULL,
		0x5D1229D396D068CDULL,
		0x88613AF17C5B574BULL,
		0xE68A43B390880226ULL,
		0x5DF81D307A269DFFULL,
		0xC148C24A271690D1ULL,
		0xC3CB7338F74DF9A0ULL,
		0xC74A54ACF7848914ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFF40DD3D90BA780DULL,
		0x5D1229D396D068CDULL,
		0x88613AF17C5B574BULL,
		0xE68A43B390880226ULL,
		0x5DF81D307A269DFFULL,
		0xC148C24A271690D1ULL,
		0xC3CB7338F74DF9A0ULL,
		0xC74A54ACF7848914ULL
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
		0x8D1CAA32FD3F7B38ULL,
		0x99F7D3094F0F4FD6ULL,
		0xACF99C2B056BFF97ULL,
		0xA732374149CF0C18ULL,
		0xF0873D2DDA554B2EULL,
		0x649C8E1F33083D00ULL,
		0x75B441F25988FC09ULL,
		0x88554A41D5C955F1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB2AC6140D8A61A9BULL,
		0x1781421A453CADF4ULL,
		0xC07F8056252D1787ULL,
		0xC6358F00B84DA675ULL,
		0x360671A8B3C8A20CULL,
		0x9435CB95BEA245D3ULL,
		0x7D8E3B811BFBFCE8ULL,
		0x994781E0A2E17884ULL
	}};
	t = -1;
	printf("Test Case 42\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xE6AC0CDC69BA1F0FULL,
		0xCF005489B59E933BULL,
		0xDE4B6CB54AD37312ULL,
		0xE69C542B50B782D6ULL,
		0xC15C7D935D1DDD1FULL,
		0xE10309510085F3DAULL,
		0x16675C6772B7F5CDULL,
		0x1DC681FA04D09F8FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC5A09BACB4FB28FFULL,
		0xC1CD0DCF937CCF96ULL,
		0x5A609A5C06B50BBAULL,
		0x853BDF4546C48FD4ULL,
		0xF38D1A96578DA9D4ULL,
		0x42A4F9FC76ED2150ULL,
		0x63072C09C39E1231ULL,
		0x2082FD500285DC97ULL
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
		0x463ACF9A3DD198DDULL,
		0xB1DAB7B5F72200A5ULL,
		0xDFFC4E838B32C23FULL,
		0x337C15B74373B5C3ULL,
		0x0CF57CE4687F9D7BULL,
		0xB73B4F7B3D21F400ULL,
		0x7589E4202E1D21E7ULL,
		0x11DDAC223B0A7E60ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x48222450884C25D1ULL,
		0xDAE6222FB27E3A09ULL,
		0xDE7AB6A125264B20ULL,
		0x3D8D12A444FF0006ULL,
		0x42C87FEA7E6A1257ULL,
		0xC539BACFA713CFFAULL,
		0x6FE2339CEA7FA0B0ULL,
		0xCA99712DE36B5C7DULL
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
		0x51B5C59D03B18DE6ULL,
		0x15F7FC9F5FA9D805ULL,
		0x39E0B01205160B95ULL,
		0x80E6122745201C97ULL,
		0x30CA39A860A54058ULL,
		0x2BDDB0EFD9AB7422ULL,
		0xC1C0944585FE4C30ULL,
		0xFC58F21C273B8D4CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x51B5C59D03B18DE6ULL,
		0x15F7FC9F5FA9D805ULL,
		0x39E0B01205160B95ULL,
		0x80E6122745201C97ULL,
		0x30CA39A860A54058ULL,
		0x2BDDB0EFD9AB7422ULL,
		0xC1C0944585FE4C30ULL,
		0xFC58F21C273B8D4CULL
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
		0xB963E6CD436C1BD1ULL,
		0x5B95CD47E0FE491BULL,
		0x6D80154785470900ULL,
		0xDF77F37AD8FCD6D8ULL,
		0x0AFD874E2ED1C845ULL,
		0xE184DA3D1F68FBFAULL,
		0x4A612C07172A5FDDULL,
		0x61E053329E22FB21ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD70412EB0DEA7226ULL,
		0xE2DAD91FB92DD16FULL,
		0x5A1D29B21F10787CULL,
		0xF94E01F479F33A6BULL,
		0xA519FB999A4DC818ULL,
		0xF8A83D0DF81EB271ULL,
		0xD91BE2CEA8806893ULL,
		0x44C84DD6B2949201ULL
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
		0x7974EE7CE4373AC7ULL,
		0xB3DC7510AF4784F3ULL,
		0x7C735DAB824E8F09ULL,
		0x6660F0C8B7D095C1ULL,
		0x464B9F37BBF213BBULL,
		0x9DC1C13AF7FF0873ULL,
		0x573DB421B7F02A5DULL,
		0x8224B66C9FA3663EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD6F862C5F3902335ULL,
		0x17D213E8585763D8ULL,
		0x140BE707C9F22149ULL,
		0xDD592540E283FF19ULL,
		0xDADF36D8336983C0ULL,
		0x559E6E059BC1B0C5ULL,
		0xB20449F35E20BC2CULL,
		0x96D845616E34DB09ULL
	}};
	t = -1;
	printf("Test Case 47\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x99ED6BB3A5FA7457ULL,
		0xCCABF703A9307FD9ULL,
		0xFAC7294CDF1A3A32ULL,
		0x93F5A3CC683306F9ULL,
		0x026A5A47E17ADA95ULL,
		0xEC26289EEEB05F21ULL,
		0xBF4D83CB39801937ULL,
		0xDD9D93DED9073939ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3F63656757026CCAULL,
		0x7D29D2AD1BCBC878ULL,
		0x366CEA74E6E24A9BULL,
		0xDCF4D3B4B796ED31ULL,
		0x0AA14A08E6C3EC77ULL,
		0x84B8CBAF1A5329AFULL,
		0xD5BFF98BFC48ED44ULL,
		0xBC20604961AFB611ULL
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
		0xE9263A388810B381ULL,
		0x964D17DB714F8096ULL,
		0x80912ADFF37C431EULL,
		0x76A37BFD1389174BULL,
		0xB5EF3E0D5652FF22ULL,
		0x93FA3AFFD8B5796CULL,
		0xA87A1CD5F5C8F0ABULL,
		0xB104279EE3EAE1AFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE9263A388810B381ULL,
		0x964D17DB714F8096ULL,
		0x80912ADFF37C431EULL,
		0x76A37BFD1389174BULL,
		0xB5EF3E0D5652FF22ULL,
		0x93FA3AFFD8B5796CULL,
		0xA87A1CD5F5C8F0ABULL,
		0xB104279EE3EAE1AFULL
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
		0x0CDE0865FD449477ULL,
		0x76890C25AE750DDCULL,
		0xB089C4930B8E8406ULL,
		0x0348D4234EF0EF62ULL,
		0x7065D52D6CF1CF91ULL,
		0xBD55B388DCFB5B40ULL,
		0x76E78B3A22D94EECULL,
		0xB68982FB3035B9DFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4DEBAF3BA15BDFE3ULL,
		0x655330BA3D3DB74BULL,
		0x9CB4E20E5CA3BA0FULL,
		0xA35F88BC432EE30FULL,
		0x3B57213BE8DD3FCCULL,
		0x31F7C1023431029CULL,
		0x9A67B2D4A43A815FULL,
		0x934185AE6FA36FB8ULL
	}};
	t = 1;
	printf("Test Case 50\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x49AC565D3A80A34AULL,
		0xBAE85C6E0CABA63EULL,
		0xAFEA510DF0BC4970ULL,
		0xAEB1240E2B44035DULL,
		0x2250BDE8F357086DULL,
		0xCC0DD8B967C3EB75ULL,
		0xAD71B0BEF41FBD75ULL,
		0xEEAB1C6926760437ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x73C2E5739BFF853DULL,
		0xDA4F5E6D1ED55273ULL,
		0x5EFC9AFA98456EECULL,
		0x9E225B8C6E25118DULL,
		0x3FDFD73DF707480AULL,
		0x498FD967B5E8438CULL,
		0xA4F413B89929A028ULL,
		0x3264D070C8A48DDAULL
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
		0x9FA3EF2DC67B41AEULL,
		0x7E70B7FA1D66C7F8ULL,
		0xD295E953788A4D35ULL,
		0x45613FD37C1E4814ULL,
		0xE14BB0CBBF1702E1ULL,
		0x1BF1CD441582F45CULL,
		0x64B1A5639DA43EB1ULL,
		0x39721E848E9B32F8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1C249B98797F0126ULL,
		0x80831D2BC5C94199ULL,
		0x5D6B85BC0061A16CULL,
		0x73C70259434E18D5ULL,
		0xBACC8ABCDD662EA1ULL,
		0x393E3C9B46A4CCE0ULL,
		0x3A1C517B947E731EULL,
		0x392E43A4C2543428ULL
	}};
	t = 1;
	printf("Test Case 52\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x252CFF08D54A2D61ULL,
		0xE382C1E7CB4C445FULL,
		0xC1EB9B10372AD2A2ULL,
		0x9AA17F04A81B0EEFULL,
		0x83B0E64CD8CEC646ULL,
		0xA7D74369F92767B1ULL,
		0x476533A5C4868C8FULL,
		0xD492EBE1F16FD4A9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x252CFF08D54A2D61ULL,
		0xE382C1E7CB4C445FULL,
		0xC1EB9B10372AD2A2ULL,
		0x9AA17F04A81B0EEFULL,
		0x83B0E64CD8CEC646ULL,
		0xA7D74369F92767B1ULL,
		0x476533A5C4868C8FULL,
		0xD492EBE1F16FD4A9ULL
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
		0xAF742258FE8C2FA1ULL,
		0x333BDF6F293E584EULL,
		0x72646F3163F62CA0ULL,
		0x1E996D323F4ED549ULL,
		0x9C5400B924EA4E63ULL,
		0x89ABEDE4ADA598F2ULL,
		0xBCF520835A4100CCULL,
		0x597199207447E0B1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x64CB76462C53DD7EULL,
		0xDCF8BE8B6C75BCABULL,
		0xC33C1E6EA362BE7CULL,
		0x3F802BCCFF03EFC5ULL,
		0xE18F25B95C263BCDULL,
		0x5A2B569A505F6564ULL,
		0x09CA9B3CE0D75C2DULL,
		0x8C45A2F40C4C77D3ULL
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
		0x7AF3C68456139D3FULL,
		0x0DA63DB3898F9992ULL,
		0xF69A3EC16AB0D8F9ULL,
		0xF95B832E230961ACULL,
		0x27728C53B69AFDA2ULL,
		0x4C7A3891B75BAE65ULL,
		0x269086363A447A79ULL,
		0xEC354B89B5E48403ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x21B744C1DBA95FA2ULL,
		0xAAF847BB4B2136A7ULL,
		0x6F4F1353A62B2F51ULL,
		0xB35167DC9A0E6BDBULL,
		0x6B238093BDB4EA70ULL,
		0x606D95AD2AB4302CULL,
		0x4637A45E6F7B0821ULL,
		0x74540B0794D7CDB2ULL
	}};
	t = 1;
	printf("Test Case 55\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xA508968592D9A0CDULL,
		0x28A5B07A9A95B62CULL,
		0xAACD4FF31D59E256ULL,
		0xE0133190C0BD19A6ULL,
		0xAEB791BB87130916ULL,
		0xDD63753668174110ULL,
		0xCA3E8FC22379B7B7ULL,
		0x1AA362AA70671461ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x89D1ACEEEAAD41E3ULL,
		0x51A0BD0AF8F09808ULL,
		0x2A36328550627F7EULL,
		0x51EFE164E50E76AFULL,
		0xBD782CA43B498CBBULL,
		0x677A3737F1026804ULL,
		0x3E1E531803B03023ULL,
		0x547006234C088112ULL
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
		0xBAF82F13726026BDULL,
		0xC10A82FF82AF4D18ULL,
		0x1D79109A89D55108ULL,
		0x6EE4365B3B759B09ULL,
		0x1D132090ECF2520CULL,
		0xE70BA53AE604B9D9ULL,
		0xA6489D4BD9F43585ULL,
		0xA15C278CFB31392AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBAF82F13726026BDULL,
		0xC10A82FF82AF4D18ULL,
		0x1D79109A89D55108ULL,
		0x6EE4365B3B759B09ULL,
		0x1D132090ECF2520CULL,
		0xE70BA53AE604B9D9ULL,
		0xA6489D4BD9F43585ULL,
		0xA15C278CFB31392AULL
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
		0x440DFC2EE909890FULL,
		0x91B662D1F6B5E240ULL,
		0xE06E269AF1A83667ULL,
		0x1EAE0858E8B2AE29ULL,
		0x9335977E77FDB20AULL,
		0x610576A6A6D2EC20ULL,
		0x12EA29C6580D9B80ULL,
		0xA5578569D1E2CA91ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA33D9929CB3E0930ULL,
		0xEC47DBDCF3E8DFA8ULL,
		0x35FBC11859EBE89BULL,
		0x0552B66B6BB3A581ULL,
		0x8B5851A50719AE2BULL,
		0x13F17665D0004DB3ULL,
		0xD7C30D194C2F53CFULL,
		0x714129A7825DE705ULL
	}};
	t = 1;
	printf("Test Case 58\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x0B5E4092A924656BULL,
		0x2631E42FBCAA6047ULL,
		0xA2AFC930E7F7D6EAULL,
		0xAF7C67CEED939607ULL,
		0xF008020CA9ACDDC8ULL,
		0xD43CF3E8B014DADFULL,
		0x15A4C28D7C3AA104ULL,
		0x5ADEEC60D66CB733ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x78698B7E39916897ULL,
		0x0C6249AA22B6A6B4ULL,
		0x173DBD52C30715B7ULL,
		0x9D498E821F62789FULL,
		0xA9EFA7E5E9954CF5ULL,
		0x384B4FE024BFB8CEULL,
		0x114D79BA23EF300EULL,
		0x09D6914B22742415ULL
	}};
	t = 1;
	printf("Test Case 59\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xF2EDE152F7A1854AULL,
		0xD9063FD8594CAE7AULL,
		0x67FBBEF069DE8E9EULL,
		0x31F127E65D933222ULL,
		0x7E0DFC993E06ED76ULL,
		0x4816A48C4C316309ULL,
		0xDD339CF1C88CE491ULL,
		0x96CAA267BC329C20ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x82B78260BD483C95ULL,
		0xEF541907BBBAE44BULL,
		0xB94210D077CEEF1AULL,
		0x9042E15D6D940874ULL,
		0x7C85CC8C30D8D9B3ULL,
		0x17A1B47DD6C8E283ULL,
		0x073138DB925B00FCULL,
		0xDB198DB9B99894D1ULL
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
		0x454F67B9544C2357ULL,
		0xBE7D17D348A8EFA5ULL,
		0xE9D7FF7F4C82C29EULL,
		0xB53E49F6275D5B2DULL,
		0xAC6046359BFEC9D8ULL,
		0x20806911E9EA19CAULL,
		0xDA5C222C24B5EA31ULL,
		0x94727BDDDC1ED63DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x454F67B9544C2357ULL,
		0xBE7D17D348A8EFA5ULL,
		0xE9D7FF7F4C82C29EULL,
		0xB53E49F6275D5B2DULL,
		0xAC6046359BFEC9D8ULL,
		0x20806911E9EA19CAULL,
		0xDA5C222C24B5EA31ULL,
		0x94727BDDDC1ED63DULL
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
		0x0D0BF056C77103EEULL,
		0x59BE20B254769ECCULL,
		0x09CA64308E7C13C3ULL,
		0x03946D064F28265FULL,
		0x68967AB6741B0835ULL,
		0x309824A9784F7027ULL,
		0x1BA1F50CB6D25783ULL,
		0x9896FD7493C245AEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD61B039B4E0C2E23ULL,
		0x4029A011442AF723ULL,
		0x7DBEECBD57C64847ULL,
		0x2B0C287D76952766ULL,
		0xB818C663CB55B8FEULL,
		0x0CC2BFD495DB47FFULL,
		0xEE9A42BA65688737ULL,
		0xA1313C5AD0D92F4CULL
	}};
	t = -1;
	printf("Test Case 62\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xC4DC091DB1F4FDCCULL,
		0xD7DC114783121041ULL,
		0x9F5B1464BFBC3203ULL,
		0xBAE0386376DA7820ULL,
		0xFCA19014EA8124D3ULL,
		0x89B6FB1DB36E24A5ULL,
		0x05BD6CA8F31BF9FDULL,
		0x6606F035FF965B33ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2B6565574403130EULL,
		0xEFE02C09AB8C53C0ULL,
		0xE6BC28D4C330DFE8ULL,
		0x23632C45F314C113ULL,
		0x733B2BCFDD72E4F8ULL,
		0x16DADFA6C0C77934ULL,
		0x1CF896E208517886ULL,
		0xE8EE799545340B87ULL
	}};
	t = -1;
	printf("Test Case 63\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x56C2A96B1B835553ULL,
		0x71D338227CFE23CBULL,
		0x2E632169D40699FFULL,
		0x5122021FDA2D0B7EULL,
		0x27128758D6BF8EB0ULL,
		0x0164E918D043E73EULL,
		0xF3EA585B8A6471AFULL,
		0x30BAAEBA1BE61C08ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0077CE7D79BC74B5ULL,
		0x91088345AA332A51ULL,
		0x4477F914F714083BULL,
		0xE72A1E7E4720DE75ULL,
		0x1DC009D8C3757F72ULL,
		0x614D489FA60FBB56ULL,
		0x2F3E762C2CADB2AFULL,
		0x02D15000EE09541DULL
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
		0x7093461659C4DA07ULL,
		0xA19C66B92CDF225AULL,
		0xF05063BC96A6BA9CULL,
		0x080894126EB2C5BBULL,
		0x2B3DC3B2A51EAED0ULL,
		0x9F4B80F4E3A5EBF8ULL,
		0xE11CF2A9620FF17FULL,
		0x93D8DCD50B530568ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7093461659C4DA07ULL,
		0xA19C66B92CDF225AULL,
		0xF05063BC96A6BA9CULL,
		0x080894126EB2C5BBULL,
		0x2B3DC3B2A51EAED0ULL,
		0x9F4B80F4E3A5EBF8ULL,
		0xE11CF2A9620FF17FULL,
		0x93D8DCD50B530568ULL
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
		0x5E67B3D09209477EULL,
		0x88823EDEC72BE9E0ULL,
		0x1E86FF07CE47830EULL,
		0xF18B24F0B07597ADULL,
		0xE1EC1BEA3B7613E9ULL,
		0xFD90E55E89EED370ULL,
		0x314D8CDB639239E7ULL,
		0x0C4E993557EC1127ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7F250270203E9FBBULL,
		0x2FFF8B083D4380B4ULL,
		0xDCFE3D35A83AC6B8ULL,
		0x13B29BB0D8645C03ULL,
		0x482C968A719B6AE9ULL,
		0x2ED2E3FDE84EA52FULL,
		0x7F1CAE0448BFE38FULL,
		0x9D969171E4582AD6ULL
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
		0x067913F9537D3E4BULL,
		0xE1C5E409A9256230ULL,
		0x8D9934D318DEDED5ULL,
		0x400C07E7DF706787ULL,
		0x824EE38FD24D2A6AULL,
		0x6A05C4A413739F3EULL,
		0xC4BDD521565B98B5ULL,
		0x066C44B4E9987C0DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC89FEE8194708D0CULL,
		0xE97A52635BA88E22ULL,
		0xEE93B7722BEEABC1ULL,
		0x2A3C4C8AD792B8EEULL,
		0x97FD05E826C80F1CULL,
		0xFED2411397B4ACABULL,
		0x295AD3927A0D1F22ULL,
		0x399F8341A7634651ULL
	}};
	t = -1;
	printf("Test Case 67\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xDC209F33C077B195ULL,
		0xCEF2FDEE7241CD95ULL,
		0xB7B2BCC8396E9662ULL,
		0x5041E7CB3E44FCF9ULL,
		0x1490E1D9E901F613ULL,
		0xC815FCE800D98819ULL,
		0x4630CDA994A9FC01ULL,
		0x676E625BB73AE38EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB470A2DE22874F3CULL,
		0x2D8B1B815D607320ULL,
		0xE9DD4796CA70F19BULL,
		0x238FDA0D1766F8D1ULL,
		0x8F7EB3490FCCB94DULL,
		0x86DB88339CCFBCE2ULL,
		0xE0DF6E7D2BC6D6B1ULL,
		0xD6B4DF33120640D4ULL
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
		0xD1E8F644A5088B8FULL,
		0x564A720097BB37BCULL,
		0x09827AEF7FD604B9ULL,
		0x8E304865E30E2BA9ULL,
		0x9E37B6F1A1BB7226ULL,
		0x6DFAF3B17CA1E6B8ULL,
		0xC20A292BBA34D820ULL,
		0x33C7F14F37B812E6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD1E8F644A5088B8FULL,
		0x564A720097BB37BCULL,
		0x09827AEF7FD604B9ULL,
		0x8E304865E30E2BA9ULL,
		0x9E37B6F1A1BB7226ULL,
		0x6DFAF3B17CA1E6B8ULL,
		0xC20A292BBA34D820ULL,
		0x33C7F14F37B812E6ULL
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
		0xB8FB3D0F634A5AE7ULL,
		0x745673F74FFC3FD7ULL,
		0xB993C34AC371D7EEULL,
		0x9B213050928BE8E7ULL,
		0xDBFCB0A11F940F69ULL,
		0x79226053B16B74B7ULL,
		0x502BB25CAB237E92ULL,
		0xD801DD4E4FE492FFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1566F605363E4FD3ULL,
		0xF48FA50B295FEF89ULL,
		0x2582C0CCAD67646CULL,
		0x702F45738BC2DA50ULL,
		0xA4FBF9A3BA26ED05ULL,
		0x6899153B2A2BB74AULL,
		0x8E91D1BDB24E7BAAULL,
		0x627EC36C976F3CEAULL
	}};
	t = 1;
	printf("Test Case 70\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xB13FEDE65ACBBB6FULL,
		0xCE9ED92AECB12434ULL,
		0xB57840E17D184136ULL,
		0x49755486DBCEF8EEULL,
		0x6D29F90D92D107E9ULL,
		0x5243743EFDC958EEULL,
		0xF8C03B6EBB4BBC4CULL,
		0x1F5A35B105449E24ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x385AA9BE8B3F6605ULL,
		0xC9ABC1B21CE1E81FULL,
		0x1D679D84877A7CC5ULL,
		0x388331057FDA2F74ULL,
		0x7654E7B6F05C1412ULL,
		0xB0991B65A0435331ULL,
		0x4A875D5B6DE3FA37ULL,
		0x9313BBF5F44051B0ULL
	}};
	t = -1;
	printf("Test Case 71\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x610A02214FBDF14DULL,
		0x5183B9FB284AA4E3ULL,
		0x56964EC5A24DB4F8ULL,
		0xF30533EC77FAEDC6ULL,
		0x6FEF8A65D3C21EBCULL,
		0x9C404C9C6A4179C6ULL,
		0xCBF63E55ABD65D2AULL,
		0x17201D8027AD9E4EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x13C1D2240F876252ULL,
		0xC4D7012E702F3AC3ULL,
		0x0712B3ED2D478C9EULL,
		0xA6D202D7106E0BECULL,
		0x0BEDB19848BC964EULL,
		0xEA1067A3C37576BDULL,
		0x341302F7868EB655ULL,
		0x27E3159430D76BAFULL
	}};
	t = -1;
	printf("Test Case 72\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x6C64C3CC46D4D4BFULL,
		0x0550B98E374B3664ULL,
		0x8FB5308DBA3F62E2ULL,
		0xD7C38EAA299C1ADAULL,
		0xF2F2CBABF8E54EE5ULL,
		0x7F212220F5A42472ULL,
		0x5070C8B989BE99F8ULL,
		0xE9F9ED227E4D6D64ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6C64C3CC46D4D4BFULL,
		0x0550B98E374B3664ULL,
		0x8FB5308DBA3F62E2ULL,
		0xD7C38EAA299C1ADAULL,
		0xF2F2CBABF8E54EE5ULL,
		0x7F212220F5A42472ULL,
		0x5070C8B989BE99F8ULL,
		0xE9F9ED227E4D6D64ULL
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
		0xBB378356EEEE60C2ULL,
		0x4255585350E5ABB7ULL,
		0xFA926AD6855AF968ULL,
		0xA676D61D3504CA2FULL,
		0x12939086C6A8DC72ULL,
		0x522569353D8DBC8FULL,
		0xC075A19FFE48E1A9ULL,
		0x930BB43579B98CB0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE34E2A49BF722BCEULL,
		0x0192295751417A92ULL,
		0xC4E8918CA19459F9ULL,
		0xA41AE13EE571D3DDULL,
		0x146CD041627C4207ULL,
		0x6BCA1E2866EA0BB8ULL,
		0xFC20BE73B3EB2FA4ULL,
		0x1B543699F97E0CF3ULL
	}};
	t = 1;
	printf("Test Case 74\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xBF353EFABA2A7818ULL,
		0x0A8614843D7700F0ULL,
		0x7C4F69F353AACDD8ULL,
		0xEF0E717D37482604ULL,
		0x4BAB29CB8EDD4B7EULL,
		0xC9C6FF54BCBFA2E6ULL,
		0x52696936824F4A47ULL,
		0x86B9067899E43254ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x68701C589B682195ULL,
		0x38842E7533429EB9ULL,
		0xF8835B953C99B70DULL,
		0x9A07456F6E35EAA4ULL,
		0x17E2303ACCF6431EULL,
		0x92D5ECB6BC78900EULL,
		0x3D720CB1CBDA8D86ULL,
		0x1515E1E853520FD0ULL
	}};
	t = 1;
	printf("Test Case 75\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xC8CCFD359CFE47F1ULL,
		0xD62EA43267992A00ULL,
		0x6AE746E3C834C558ULL,
		0x2B2E4C5F08E7C0E4ULL,
		0x6CE545E59B5A11EEULL,
		0x82DE4E20711AAEBCULL,
		0x014CDAB17D1703F6ULL,
		0x1B02A1032F8C4823ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2589EADD45F26E32ULL,
		0x8A62FCED29F5B256ULL,
		0x4CCC19A0285028B3ULL,
		0xC40D06A93BB9A406ULL,
		0xFB489445D681B664ULL,
		0xE2E25C934FCDADA9ULL,
		0x2E9CFFAA4360C1AFULL,
		0x24801E964EB419E7ULL
	}};
	t = -1;
	printf("Test Case 76\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x673AFB374B0E2B43ULL,
		0xC8F15426AEE01BE1ULL,
		0x2120539D21FBF422ULL,
		0x7096D9AAFFA129B0ULL,
		0xAE26D4E3D3546860ULL,
		0x9EFDB77BBC490D90ULL,
		0x1640DF64DF09ACE1ULL,
		0x9CA9E565A395FCE6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x673AFB374B0E2B43ULL,
		0xC8F15426AEE01BE1ULL,
		0x2120539D21FBF422ULL,
		0x7096D9AAFFA129B0ULL,
		0xAE26D4E3D3546860ULL,
		0x9EFDB77BBC490D90ULL,
		0x1640DF64DF09ACE1ULL,
		0x9CA9E565A395FCE6ULL
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
		0xF478D44F52C99291ULL,
		0x21A44284BE5BC00AULL,
		0xB9DB979866312796ULL,
		0x7408188D37C2D122ULL,
		0x622773C410902CE2ULL,
		0x41F0770A27262757ULL,
		0x89ABC2BF466A77E9ULL,
		0xA71C0101B2195E5AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA792E86732E61985ULL,
		0x68B419E599877F5EULL,
		0x09DA432045D902D3ULL,
		0x38FC603520842CF8ULL,
		0x5D03BD6693BF75FCULL,
		0x7C34BDC41BC44367ULL,
		0x4B6D00AEA9181FDEULL,
		0xF55773A30B215D20ULL
	}};
	t = -1;
	printf("Test Case 78\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x6EA50445B20D2582ULL,
		0x0FFB2E67FE537C35ULL,
		0xBEAF1A708F0C35E7ULL,
		0xE534EF27C4A6E913ULL,
		0xD625450159293B2CULL,
		0x069AAAD011C4D725ULL,
		0x8CD6A36E90735336ULL,
		0x4954915B50D9AEECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEEAE0D13C99A887AULL,
		0x8F77C51336928029ULL,
		0xFA27DB62A14AB9C8ULL,
		0xF799D6924CCE072CULL,
		0x12E847468460263CULL,
		0x1729133B98515673ULL,
		0xF0C56AC7A76CD76FULL,
		0xCEDC292B3767931DULL
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
		0x160EDB42E1C9F7A7ULL,
		0x4B95F2DED3350D48ULL,
		0xF0BB61CF1B58F125ULL,
		0x5C92C093683988E9ULL,
		0xEAB9E45E5CDDE5BFULL,
		0xC5BB082DD0585C79ULL,
		0xFC44E7560D8F9164ULL,
		0xEB0C3A2DED1DB15BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBEB9B7BC82115B15ULL,
		0xF7EDFA698C5E5C8EULL,
		0xC0A976A879194652ULL,
		0x929BBA8CE1045861ULL,
		0x27C36C6588D38638ULL,
		0x524A5A23E8C5A5BBULL,
		0xDE26686E76404DDEULL,
		0x4C0677FD16882FBDULL
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
		0xBD0CAC35B8450319ULL,
		0x54D6C9402D799587ULL,
		0x88F013741FECE389ULL,
		0x45D253F8DCBDA564ULL,
		0x53C1446B7F578BEAULL,
		0x4C458C1BDCA23FDEULL,
		0x3241AEF48322A029ULL,
		0xEEDF4E39DB2F2BF9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBD0CAC35B8450319ULL,
		0x54D6C9402D799587ULL,
		0x88F013741FECE389ULL,
		0x45D253F8DCBDA564ULL,
		0x53C1446B7F578BEAULL,
		0x4C458C1BDCA23FDEULL,
		0x3241AEF48322A029ULL,
		0xEEDF4E39DB2F2BF9ULL
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
		0x7C5CA3A6662FF3F7ULL,
		0x19B9C6EE8AA33B60ULL,
		0x6EC84CF79CB1EE3BULL,
		0x1BEDE755FBE2C14BULL,
		0x1C8248BBF56806C8ULL,
		0x58C5DDC7D66BCD1FULL,
		0xA89576D178EE89DDULL,
		0x53368FC8DD1375EAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x46CC1C9C6B4573E8ULL,
		0x3F8D7F5AA26B3114ULL,
		0x74CAD8104B21E1D5ULL,
		0x42871B73D207DE31ULL,
		0xE845D28710632E7AULL,
		0xB8000537DAF5B0A2ULL,
		0x3AC163028DD824DEULL,
		0xA81A15F10D59D28FULL
	}};
	t = -1;
	printf("Test Case 82\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xF8DE71622F3C0B2CULL,
		0xB8C2A525F65E5BCBULL,
		0xBE5C171AAD594564ULL,
		0xD604C20636ADDE55ULL,
		0xB690FFF2017D728CULL,
		0x388B759A23F52761ULL,
		0x0CFA8C21CD845053ULL,
		0x1622FC2282480652ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2FD3BE07AEEBBBF5ULL,
		0xFE262B380FB1F6CDULL,
		0x4E5BBD4E37166742ULL,
		0xECF8A1D690B911F9ULL,
		0x8CF6FC8B09DA6AABULL,
		0x4A71200A5A02F083ULL,
		0x0C98AC44E0927DEAULL,
		0x3AD8DE2C5CB5D205ULL
	}};
	t = -1;
	printf("Test Case 83\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xC400AE64641D123AULL,
		0x73A82BAAF8EACE86ULL,
		0x33D75A8273802DB5ULL,
		0x0CB704E9721231DCULL,
		0x134B0D228D164A9AULL,
		0x157D6610F0113AC8ULL,
		0x11D6C7D7245F2206ULL,
		0x0FFBBC714C1FE32DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8FE1397FA52BCCD1ULL,
		0xD2D7FC79A53DBDA1ULL,
		0xC0564E38182A08F6ULL,
		0xFCA1421225ABCA43ULL,
		0xD1DC81D9B1438D55ULL,
		0x9CBE05AE635B9774ULL,
		0x81914B5E199F8503ULL,
		0xBB94CE7D32598CD8ULL
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
		0x39E94D7A76201F39ULL,
		0x6797041F39A21551ULL,
		0x153C38E1241A9D56ULL,
		0x6AED4A84C78F9AE2ULL,
		0xCC9B0FBAAE97EA32ULL,
		0x3031F817AED5F16BULL,
		0xB8075CF907B54B8FULL,
		0xB205EA8A68F8FC64ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x39E94D7A76201F39ULL,
		0x6797041F39A21551ULL,
		0x153C38E1241A9D56ULL,
		0x6AED4A84C78F9AE2ULL,
		0xCC9B0FBAAE97EA32ULL,
		0x3031F817AED5F16BULL,
		0xB8075CF907B54B8FULL,
		0xB205EA8A68F8FC64ULL
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
		0x008C3470B9462BF1ULL,
		0x2DD759AF97F263F8ULL,
		0x9D37556193183EAFULL,
		0x7A30B22FD012D67AULL,
		0x4526CBED4DB164B7ULL,
		0x286162E70868455DULL,
		0x4FD0B9405CEB6F93ULL,
		0x4B6D00F285F4D401ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x594D34F5D5B305C4ULL,
		0xE5A002CCF6804C92ULL,
		0xD466A479DC47C733ULL,
		0xC14232F66ED75AC0ULL,
		0xD63241ABE12A2C66ULL,
		0xE020443412B0298AULL,
		0x8F4A9D096EC7ABCAULL,
		0xF67A9322F05E61B1ULL
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
		0x86A9C30A564184B5ULL,
		0x34450B904E71C517ULL,
		0xA281C2697A90338EULL,
		0x8D4DFE7777152AF5ULL,
		0xB11F7ECAA218C0ACULL,
		0x90F31E243A08EFA6ULL,
		0x7B53813F7900081BULL,
		0xC92C0088870842DBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF2143F5B9E2A8710ULL,
		0xB18FE2E7438B63A5ULL,
		0xCDDBB81201C199F0ULL,
		0x92F7AE40140EBAF5ULL,
		0x8F847B5F8FFC0A43ULL,
		0xF4E51D600715B490ULL,
		0xD275097E95F007BBULL,
		0x41BEA6AFA3C8EECAULL
	}};
	t = 1;
	printf("Test Case 87\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x47BBC08493DB9939ULL,
		0x6166474AC423C545ULL,
		0x03CD640D0A097C8BULL,
		0xA5955624706C92CAULL,
		0xF297D3D75B455169ULL,
		0xE7679914F23FBA29ULL,
		0x98BC921D2965DE03ULL,
		0x8879AEE40EDA0A2FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1AF6EC772B764B69ULL,
		0x3A06047930A88DC1ULL,
		0xDA62673E11C69365ULL,
		0xE2DCF614C68F42B1ULL,
		0x605FB92981615D6AULL,
		0x1751265D695C5B9DULL,
		0x8AD524F761451C41ULL,
		0x02AFC06C0BD127ECULL
	}};
	t = 1;
	printf("Test Case 88\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xE3EF6441407CA933ULL,
		0xD816356CC56870E7ULL,
		0xB485E3CD5E6170E9ULL,
		0x55D8C32D9DBE2DD3ULL,
		0x90097B843FC64935ULL,
		0x982EB2C426D819A9ULL,
		0x32F15EE900BD2E12ULL,
		0x0A5A31109AEC7CE2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE3EF6441407CA933ULL,
		0xD816356CC56870E7ULL,
		0xB485E3CD5E6170E9ULL,
		0x55D8C32D9DBE2DD3ULL,
		0x90097B843FC64935ULL,
		0x982EB2C426D819A9ULL,
		0x32F15EE900BD2E12ULL,
		0x0A5A31109AEC7CE2ULL
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
		0xE93B6CF8AA50BEC1ULL,
		0x67970695AF600572ULL,
		0x50A2F36DC89470A6ULL,
		0xEE5C802AC7DC9F17ULL,
		0xD222499601230082ULL,
		0xFCDE0A38865734DCULL,
		0xE64B239FD663EFCBULL,
		0x8466C185356247D9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAE8913A7B4FD0AB4ULL,
		0xF3E64AC7006958FFULL,
		0x9D66457F0F18CD2AULL,
		0x096B8C33BE7F59CAULL,
		0xD378D7C75431AE7EULL,
		0x93A2A0FA5A3015B3ULL,
		0x9C0826B275444081ULL,
		0xD17A363C970D37A6ULL
	}};
	t = -1;
	printf("Test Case 90\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xC731BFFE3D2D9BFDULL,
		0x7BF18AC5431698FAULL,
		0x8BF7EA80C3347787ULL,
		0x2F22DA968272E10EULL,
		0x352620887E08C96DULL,
		0x9E06CF390E3C3A63ULL,
		0xEB8CF736DFE6E574ULL,
		0x705E3B9EBB42EE47ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1BBCBDFDEE81CDF3ULL,
		0x51E0D25FA76BD111ULL,
		0x6DEB2EC166AFA3D5ULL,
		0xE140328A084E2409ULL,
		0x8849D059517CC73DULL,
		0x2AC210D3F43DC1BAULL,
		0xC3843DD1CD027DF3ULL,
		0x33A07395E7B3D200ULL
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
		0xA269DEF9147CB04FULL,
		0x43B5F9A701235C1DULL,
		0x27D8836DCE507B35ULL,
		0x9514F1B0E5092583ULL,
		0x33B167706A6B1EBCULL,
		0x5367D7FB05307E0EULL,
		0xDB54AB4DD0DBBE15ULL,
		0x04125854C96A0454ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xED37225ACBBD559BULL,
		0x211B43496AA310E5ULL,
		0x4960ADF5887B4D91ULL,
		0x121CFB01D7408B98ULL,
		0x1714C54E64834028ULL,
		0x9405352C52D3BC33ULL,
		0x5CB7011BB2D2BFFCULL,
		0xFA3883A0268589FBULL
	}};
	t = -1;
	printf("Test Case 92\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x3C429162131AE936ULL,
		0xD3E965CD88BB70ADULL,
		0xD67B7E9BFAD02AABULL,
		0x9F1DD509F286CD8CULL,
		0x789F2AED5DC74480ULL,
		0x24FF8B87077FD0A7ULL,
		0x0BAE066B9558F930ULL,
		0x5D2D74F03168A5DDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3C429162131AE936ULL,
		0xD3E965CD88BB70ADULL,
		0xD67B7E9BFAD02AABULL,
		0x9F1DD509F286CD8CULL,
		0x789F2AED5DC74480ULL,
		0x24FF8B87077FD0A7ULL,
		0x0BAE066B9558F930ULL,
		0x5D2D74F03168A5DDULL
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
		0xF30B33CCF811AD12ULL,
		0x14391CAC1F65D13CULL,
		0x25D32AFF6E8884D9ULL,
		0x2217F9AA4E69A84EULL,
		0xAA37C175B85C2FBAULL,
		0xBCBFC663315CE79EULL,
		0x480EC37158E4AD80ULL,
		0x1C6ECBC035CFEB04ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7A18B309B90381B9ULL,
		0x38965BEF7769D802ULL,
		0xC7C7F7949F93A74AULL,
		0x919D19C341EFD620ULL,
		0x8B4CDEC887945F51ULL,
		0xA4EB55A5AA287AECULL,
		0x1BFE90FCE20462A0ULL,
		0x23155865BD5B3C2DULL
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
		0xA3D19FB800DBFABEULL,
		0x83ED69E19EF19456ULL,
		0xF58E8CB3D34F1A23ULL,
		0xE5B257B4341B4F2BULL,
		0xD57EA006AAC4242EULL,
		0xCB0676C1920A4A4BULL,
		0x6815D0213D186DCBULL,
		0x75F3C8C1A7FC7224ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF1F000DFDEA9A59BULL,
		0xC4DEAB2097EAAD9CULL,
		0x90D984BAA25B78F1ULL,
		0x5F70021DD0A3EDD3ULL,
		0xD549F6F44FA80D6BULL,
		0x13932E06BF44D3F9ULL,
		0x2B2DCFA8C424108FULL,
		0xA56F436CAE100B2CULL
	}};
	t = -1;
	printf("Test Case 95\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xBCC62BB5774CA78EULL,
		0x0781D788F6AE7A5FULL,
		0xB0D8E385BC36AE1FULL,
		0x6137299980AEB0EDULL,
		0x368CBE73E5072137ULL,
		0xC4ABE6AA54D0AE9BULL,
		0x6F445F34DD4CDE27ULL,
		0x7520097CBAC1D426ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x311CE83E40E97E5EULL,
		0x7D9D86623558454FULL,
		0xD3CCEB23909AC1FDULL,
		0x3F79D3E08587055DULL,
		0xFFBDAB684E612900ULL,
		0x892E539B007A65B4ULL,
		0x9D6A6C5E93769570ULL,
		0x5988449FF192B458ULL
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
		0xEC57361307C6CE5DULL,
		0x75347402A51020A7ULL,
		0x38D1D9712E2043B3ULL,
		0xD62BDE85FE8B0A9BULL,
		0xB613691E19F6A0BDULL,
		0xB5C099FBF75108CFULL,
		0xBA8E74BB933822FDULL,
		0xE02DF70C965F8466ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEC57361307C6CE5DULL,
		0x75347402A51020A7ULL,
		0x38D1D9712E2043B3ULL,
		0xD62BDE85FE8B0A9BULL,
		0xB613691E19F6A0BDULL,
		0xB5C099FBF75108CFULL,
		0xBA8E74BB933822FDULL,
		0xE02DF70C965F8466ULL
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
		0xAC09F838AB190B77ULL,
		0x437F91B26387BE2EULL,
		0x8570AF4F11962A35ULL,
		0x03B05EA6E8DD998BULL,
		0x78FD98E61002C5A7ULL,
		0x6B2767A305389134ULL,
		0x6386F6F94D858ADAULL,
		0x24F23F71C2D597BFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4844EE5F25E5325AULL,
		0x2A0EFEC29B05D3C4ULL,
		0xA851670BF20F49BCULL,
		0x91E7847DFB028B52ULL,
		0x5306DB38364E7525ULL,
		0x8E02D6BEFB75E975ULL,
		0x6098D83714D68393ULL,
		0x5DF7D4894496DE08ULL
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
		0x76E6249AD6F8DA9BULL,
		0xA305B1DC64D2A4AEULL,
		0xF1994FFC39A2523EULL,
		0x44F6C647F5D9A9CFULL,
		0x2960976A5581C305ULL,
		0x5F4D94E682A46364ULL,
		0xAE8F7FCA54B6E84AULL,
		0xD9280EC3C9A90C4FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x644C27D6E25E0F66ULL,
		0x0CDA96320323500CULL,
		0xC0FEEAC140472AFFULL,
		0xBA15984EE9875775ULL,
		0xC1B8569835326199ULL,
		0xD92A52C8D11B27A1ULL,
		0x5FE5AA3919CA4E53ULL,
		0xE47386950365FC4AULL
	}};
	t = -1;
	printf("Test Case 99\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x1F1CFC113A120572ULL,
		0x072E765AF4820747ULL,
		0x65F65AC27C968AE5ULL,
		0xC901D1EC8CEAAB30ULL,
		0x5F7FB62480D241EDULL,
		0x02458018C5DC8D68ULL,
		0x3281763872E935F3ULL,
		0xAA1BB9D1D50755EFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x73872E44D9C4C0D8ULL,
		0xAA8FEAB1979BB0C4ULL,
		0x576448B7350F3AC8ULL,
		0xF5CF8A13521B506AULL,
		0xA943917C33156252ULL,
		0xA08525AB66A1124DULL,
		0x589E165824AA2658ULL,
		0x347807FC9E33A7C8ULL
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
		0x4E24091AFA2EBDE1ULL,
		0x40343EBFE82DE3D9ULL,
		0xF546CB90A175DF30ULL,
		0x30CE209D4D21DFD5ULL,
		0xB341178951EF645AULL,
		0x543259CBBB275E5FULL,
		0x79DF138F91214B29ULL,
		0xC43F66BB2FC35BADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4E24091AFA2EBDE1ULL,
		0x40343EBFE82DE3D9ULL,
		0xF546CB90A175DF30ULL,
		0x30CE209D4D21DFD5ULL,
		0xB341178951EF645AULL,
		0x543259CBBB275E5FULL,
		0x79DF138F91214B29ULL,
		0xC43F66BB2FC35BADULL
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
		0xF60216F5775431C8ULL,
		0xA2F19BB3F0EFD887ULL,
		0xBF74456F47DB59E2ULL,
		0x4CB4B06CDC508F67ULL,
		0x8F1C8725A5749C0FULL,
		0x4918770D50E502BAULL,
		0x552D12670BE798B0ULL,
		0xB3EE56C79473F66EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x62D9B00A46625C1FULL,
		0x075B287EA4B20912ULL,
		0x1A66CFC9E7F51858ULL,
		0x4F0E3B440485A135ULL,
		0x90F9DA42D3E4E8DEULL,
		0x14366695AB93EEF9ULL,
		0xF850E15CDD5403F5ULL,
		0x4EA8CBCB304032A7ULL
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
		0x6F7F7CEE20979E36ULL,
		0x1AAB5D3D0DD86F59ULL,
		0xCC9FBBF8A1EA1ADBULL,
		0xAC6C8B2785705709ULL,
		0xCBD024BABAFB361FULL,
		0xC238AED6087A8F01ULL,
		0xCCBA22152B3D6367ULL,
		0x0C5D02BD0E8B98EFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDB399906DEF0B0A2ULL,
		0xA7A3FF2F28F455A9ULL,
		0x1048DBEE633A6A4CULL,
		0x4B79436338E8B094ULL,
		0x5E21549B4F40E1B1ULL,
		0x5E4F098AD78E29BAULL,
		0xBC85BA1E00969DF3ULL,
		0xAC372CADE210D753ULL
	}};
	t = -1;
	printf("Test Case 103\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x07C2AF72DDF1F0FBULL,
		0x9452200357F7472FULL,
		0x420B1D5D4BBFA7C5ULL,
		0xCE1379130283588FULL,
		0x91ED6214DB0BB413ULL,
		0x6DB296E7E2FE4826ULL,
		0x54E9530B15893617ULL,
		0xA2118EBBE48C1DBDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4B67B761A609AD54ULL,
		0x8908F441C2EDCF05ULL,
		0x69F3482D97548FB8ULL,
		0xC782B89A168801ECULL,
		0xDDDDB264E867CEFCULL,
		0xFFF3EE615E07E012ULL,
		0x9CECD8D78F3A1774ULL,
		0x7C0C1428D61E1AA7ULL
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
		0x33225C895A030338ULL,
		0xA67327CBAEF5801DULL,
		0xA6F1B0065E4E5BCBULL,
		0x31A3967AF6CB422BULL,
		0xD577D2ACCA493BDFULL,
		0xC681FD0251A81DD1ULL,
		0x61253D16836E4231ULL,
		0x5928F5F13DA45B03ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x33225C895A030338ULL,
		0xA67327CBAEF5801DULL,
		0xA6F1B0065E4E5BCBULL,
		0x31A3967AF6CB422BULL,
		0xD577D2ACCA493BDFULL,
		0xC681FD0251A81DD1ULL,
		0x61253D16836E4231ULL,
		0x5928F5F13DA45B03ULL
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
		0xC5828A5481475893ULL,
		0xCFBCF912961492A3ULL,
		0xBA344EED5BEAEA20ULL,
		0xCABE6DEFC555809BULL,
		0xED5D25B43CD6BA35ULL,
		0x341E3F9FD0660534ULL,
		0xF6F7EC6AAC0BFD9DULL,
		0x0BA75E5CD070183EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x075E013E9B4C7EA3ULL,
		0x0FCBBF5FFCBD51EFULL,
		0x17A582B54F891D4AULL,
		0x37AE9ED928473887ULL,
		0xCCB267AADCC845CAULL,
		0x7E7199ED2EEA247DULL,
		0x910CB72110D3F5F7ULL,
		0xB59CC4C2ACD44616ULL
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
		0x6CFEFA86A6053567ULL,
		0xA7775BA27A3F6744ULL,
		0x4E520B8844527670ULL,
		0xEAC003E783D28F5BULL,
		0xD0CAC69B25534B34ULL,
		0xF4D48906E5677E99ULL,
		0x29930C2E122F6341ULL,
		0x5BCFB09D8D951DC5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9E2059092EACC106ULL,
		0xC0C259DD40F11D6BULL,
		0x67ABDFE0A004955BULL,
		0x6881E2770E470C63ULL,
		0xC44A4A64204E2B0DULL,
		0x554C5020B8628D17ULL,
		0x016A4B332C79E6ABULL,
		0x80BC4287D0701622ULL
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
		0xBB27B6B8FEB0AF7FULL,
		0xFD9CFC1F34CD3EADULL,
		0x5FED0F7A74022EF8ULL,
		0x910A44B82F384CB9ULL,
		0x2DB742EC3789BFFDULL,
		0x7AE917B45BC16A99ULL,
		0x77246026DF72F31BULL,
		0xB66BEF096DCBB34CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFC5F0DBF5D49AF46ULL,
		0xB71F3952B32445EAULL,
		0x9E24FF25B9E50DD4ULL,
		0x648946BB18F771FBULL,
		0xA57C0786ABC74604ULL,
		0x6E56C05EEFCF07D6ULL,
		0x0D15986AEB4820AFULL,
		0x4E34697A2CDDB267ULL
	}};
	t = 1;
	printf("Test Case 108\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x772624275BC2424EULL,
		0x635874D0D43C49C2ULL,
		0x3DD1957300BE7F38ULL,
		0x800364095D7A2E68ULL,
		0xBD3E75BFB53F4A59ULL,
		0x0BACD26C89B871AEULL,
		0x6090F93989D0A507ULL,
		0x93D516194C8825F4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x772624275BC2424EULL,
		0x635874D0D43C49C2ULL,
		0x3DD1957300BE7F38ULL,
		0x800364095D7A2E68ULL,
		0xBD3E75BFB53F4A59ULL,
		0x0BACD26C89B871AEULL,
		0x6090F93989D0A507ULL,
		0x93D516194C8825F4ULL
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
		0xAB4FA156E60F5B89ULL,
		0xEB18F2A383191B71ULL,
		0x116AE61FD082BECBULL,
		0x120B6253F8334FA6ULL,
		0x37A2C2AB48078F12ULL,
		0x86E8B6BA2351EE61ULL,
		0xF27AD4BA4D77BC82ULL,
		0x9A617DA2CCDA6196ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAEFFD92D10DB0BDDULL,
		0xC332C4F72299EF50ULL,
		0x5F014C1DADF28883ULL,
		0x976725EC0DCFE89BULL,
		0x0CC5D869C4E67D2CULL,
		0x08BD4D010DFC0A9EULL,
		0xE26594027D67BAA9ULL,
		0x9D25A03FB25FB443ULL
	}};
	t = -1;
	printf("Test Case 110\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xA17F2B2DA1AA7115ULL,
		0x91D6F60486AE6CD8ULL,
		0xF183AC76A6448447ULL,
		0xF6EE6CE9541BF4B5ULL,
		0xCA154CF9034FC4E9ULL,
		0x06EB7DBB7C3FB520ULL,
		0x37ACF1846ABEC311ULL,
		0x1604ED15C665FEECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7992A19007BD842FULL,
		0x121BAC408C26F45AULL,
		0xD3D480229CC5C304ULL,
		0x4837E6BACC97921CULL,
		0x59DDA8515E0C951CULL,
		0xEB6FF6A67756E8F7ULL,
		0x19E43E242FF6716BULL,
		0x1DF9DD7EFAFB42C2ULL
	}};
	t = -1;
	printf("Test Case 111\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x6FD480B38AA0340FULL,
		0xC43BA9D81A4AC9FEULL,
		0x159A773824A3DF93ULL,
		0xE3A0A54816FD6465ULL,
		0xD6E6E488A1205BC2ULL,
		0xE5DCC0C7958CDA27ULL,
		0xE575B83EF5F115FDULL,
		0x282EAD8E5AF57DBCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA69B3657228D9B99ULL,
		0x626FF25BDB376804ULL,
		0xECC2A0ABCDF28630ULL,
		0xEBD8F95DCE29979EULL,
		0xF7C1528287CCD190ULL,
		0xAA1090925025025EULL,
		0xD5B3F95BE000C9EBULL,
		0x6965724B1F6FE53EULL
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
		0xFC4434485326D650ULL,
		0xC07E5B1272C1A454ULL,
		0x420903E146C01515ULL,
		0x4D1981315CBEEF9CULL,
		0x03F317CE6730176CULL,
		0xDBBC558BA4DDCAEAULL,
		0xB3E0CDC4154165EFULL,
		0xC64B9EA42990FEB8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFC4434485326D650ULL,
		0xC07E5B1272C1A454ULL,
		0x420903E146C01515ULL,
		0x4D1981315CBEEF9CULL,
		0x03F317CE6730176CULL,
		0xDBBC558BA4DDCAEAULL,
		0xB3E0CDC4154165EFULL,
		0xC64B9EA42990FEB8ULL
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
		0xAA6CD154A8DC7B1BULL,
		0xC08A105A79A878E3ULL,
		0x122CAAAD44B42AE6ULL,
		0xC9B74753D182B1CDULL,
		0x8897BC39BE0DB81BULL,
		0x80536724224A8A4AULL,
		0x461EA33A48CD8B5BULL,
		0x305763D29AE1C792ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x27B5963875C544D4ULL,
		0x7F22AB54FB6F78B8ULL,
		0xB5E27D30A9ECAD5BULL,
		0x3209B357F0B556ACULL,
		0x3B6FF34437A0F50EULL,
		0xF5FB2E669C92FD73ULL,
		0x50EACE1898E46414ULL,
		0x3D86D2C522BF3F0BULL
	}};
	t = -1;
	printf("Test Case 114\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x46666E14F0F061C4ULL,
		0x215C09774EB3CC86ULL,
		0x4CDD45DD7C5A7621ULL,
		0xF86BD7AB46935D35ULL,
		0x79A82F098500B192ULL,
		0x52750288CF39FEC5ULL,
		0x296E9B2FBBD6284CULL,
		0x0D747ABD9C0E639FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC3A61364A8F67490ULL,
		0xA4BE9532EC930A83ULL,
		0x503DD18653650D68ULL,
		0x3F3E68904CA63F1FULL,
		0xDADC556688E90237ULL,
		0x27564C9AD8CB3722ULL,
		0x557724FAB770ED7EULL,
		0x8A2F96C452C3C861ULL
	}};
	t = -1;
	printf("Test Case 115\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x88E04E6D3D200F52ULL,
		0x4AC86EF3D0C9E307ULL,
		0x767D7988A9A20C43ULL,
		0xF6D2A4B2E3AB3890ULL,
		0x7EACA91C031007A5ULL,
		0xC9BE52415835D5DAULL,
		0x1E936315F14FCD6DULL,
		0x17908FD10FCC38C1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDBF7069DE6D82003ULL,
		0xBB64F28DE8319C52ULL,
		0x6BEDC5CD7E36CA69ULL,
		0x92C43D7AB1E4B4F3ULL,
		0x6296953C350BF095ULL,
		0xF1D50E35D0363340ULL,
		0xF3BDAA76ABAD653BULL,
		0x43274C2575EF35BDULL
	}};
	t = -1;
	printf("Test Case 116\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xEDD0AB73D10A797BULL,
		0xE001E18A0367E215ULL,
		0xBCE2741081A6647BULL,
		0x8322AA24262F175CULL,
		0x063FBEDA55EC4CC3ULL,
		0x2FFD12BEE9B90927ULL,
		0xEA6975375C276A14ULL,
		0xAD58AEBEC95D571FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEDD0AB73D10A797BULL,
		0xE001E18A0367E215ULL,
		0xBCE2741081A6647BULL,
		0x8322AA24262F175CULL,
		0x063FBEDA55EC4CC3ULL,
		0x2FFD12BEE9B90927ULL,
		0xEA6975375C276A14ULL,
		0xAD58AEBEC95D571FULL
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
		0xFE6BE9C5853CE273ULL,
		0x5EFF4CD6E315209AULL,
		0xBD64892A2D8F1E17ULL,
		0x9B134F807E1BC9BCULL,
		0x59A9740D8F095D21ULL,
		0xCEF59D54CA1A54CBULL,
		0xEDDF9F8E50E2FB45ULL,
		0x527E06BA1595E59EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x624538E08E927ED3ULL,
		0x7824752B22B949F4ULL,
		0x8951E65290AD93DBULL,
		0x14B3E622A40B63B0ULL,
		0xA5F4F8E2740AABCCULL,
		0xC0BCB5C354AC4D46ULL,
		0x5C9954566A85E3BAULL,
		0x41EAF81D654E1C63ULL
	}};
	t = 1;
	printf("Test Case 118\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xCF5C03806FE12D87ULL,
		0x11EF636255A211A3ULL,
		0x2E89E20DACFB35CEULL,
		0x0312201CCB7961ADULL,
		0x4091A1CD89B48B81ULL,
		0x92D88E253F4255F8ULL,
		0xCC6036D56599B3FEULL,
		0x510744BBBD6F496FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x216747AB88B4AB25ULL,
		0x99C15AE3840DF90EULL,
		0x4FA009A41A0AA025ULL,
		0xC4B835875379B381ULL,
		0x492F18D95F2ED524ULL,
		0xF235FD43946DF3FDULL,
		0xCED0697D62A7EE97ULL,
		0xEE6D6C2DEB7FE9EBULL
	}};
	t = -1;
	printf("Test Case 119\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xB64A4D6671D94053ULL,
		0x4685BC4229DE86ECULL,
		0x8AAA4A757FE89526ULL,
		0x9EC9EACFDEA2365CULL,
		0x8800FCA8C563D677ULL,
		0xE318B97A951A1F28ULL,
		0x99ED45458CCC1BBEULL,
		0x5DED7E0C94D80F3DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEBCBE7B3361BCD74ULL,
		0x5F875180231F7FA0ULL,
		0x92D9BCE9E017AB71ULL,
		0xE3FCF5F4E1A9937CULL,
		0xCACB7D94681BE1B2ULL,
		0x06B4F48C69846198ULL,
		0xEE86B4F014B3BD5BULL,
		0x00BE79A5B100BDC3ULL
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
		0x7C1B2172D880EC67ULL,
		0x97BFDD405A56C115ULL,
		0x7CAEECF85EFE44FAULL,
		0xB0A57069C6D77180ULL,
		0xE5300D0559A3F998ULL,
		0xD37EE4145F523F2DULL,
		0x86C89B9575F82A77ULL,
		0xCE2E16A5659B3A60ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7C1B2172D880EC67ULL,
		0x97BFDD405A56C115ULL,
		0x7CAEECF85EFE44FAULL,
		0xB0A57069C6D77180ULL,
		0xE5300D0559A3F998ULL,
		0xD37EE4145F523F2DULL,
		0x86C89B9575F82A77ULL,
		0xCE2E16A5659B3A60ULL
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
		0x39232473D10EC276ULL,
		0x16BC548CEC06CF38ULL,
		0xC3D43AD565EB565FULL,
		0x6F5CE07A66AFD841ULL,
		0xFA60600E4496A5F1ULL,
		0x2692AB26E24351A4ULL,
		0xD876E98DEFB2352BULL,
		0x10F63804EA0378E5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x683E940DB55563F9ULL,
		0xC83CA8FB1D4143F2ULL,
		0xEE26044442B937C5ULL,
		0x0DB29ECDD23200C6ULL,
		0x06FBDB8E540B1F65ULL,
		0x705DE0CEEA93D39EULL,
		0x373DB039A7C2FB35ULL,
		0x95FA369A4100BD5AULL
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
		0x880961504EF985FDULL,
		0xFECAF320D32F7A27ULL,
		0x3C717BB7065CAA75ULL,
		0x4E2274D3E0DE74A1ULL,
		0x47F22BEA55BE6178ULL,
		0xFF8403EBB4F4CA3EULL,
		0x74F52988FC04FBA0ULL,
		0x5579932A128A5A15ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x39DBA8AD2A3FCCB6ULL,
		0x6DEF90DBAB64C7A7ULL,
		0x7DB33CE53C823926ULL,
		0x4B371201E10D91D5ULL,
		0x20B879E16F5A5E17ULL,
		0x2545C5356A48D015ULL,
		0x049AE4ED8EE62178ULL,
		0x9A634BEAD3372D1BULL
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
		0x13496B027A9236E1ULL,
		0x00769F3C2D5CC933ULL,
		0x9C09432E63883A24ULL,
		0x823B0792D4E99299ULL,
		0xFC39DC2534C5B35AULL,
		0x53E646ACED1AAA0AULL,
		0x002E63CF7D2D4313ULL,
		0xAEACBB85E6043357ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAA4CACA4A8D7096EULL,
		0xA9C10C3F49A6CFEBULL,
		0x7939D25B0978FA1EULL,
		0xA26DD62EFEFBD759ULL,
		0x83E3E5488B3FAA6AULL,
		0x478B9A2C9BD30D77ULL,
		0x2EACA1D8430ECE10ULL,
		0x78055089FEC9F2CFULL
	}};
	t = 1;
	printf("Test Case 124\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xF3F6CE151A2E67A1ULL,
		0xCF3EF11CC0288F58ULL,
		0xA642C1ADEC4F3352ULL,
		0x0BF97AC71F76C616ULL,
		0xB4A9164E35955ED2ULL,
		0xA5D271352E9F00ACULL,
		0xE7D67F09DDC58E8CULL,
		0xEB35F3EE3947FDEEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF3F6CE151A2E67A1ULL,
		0xCF3EF11CC0288F58ULL,
		0xA642C1ADEC4F3352ULL,
		0x0BF97AC71F76C616ULL,
		0xB4A9164E35955ED2ULL,
		0xA5D271352E9F00ACULL,
		0xE7D67F09DDC58E8CULL,
		0xEB35F3EE3947FDEEULL
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
		0x9D32A51CAD01A54DULL,
		0x181F9F2C4C8C2C52ULL,
		0x087CBA1F6AA3BC51ULL,
		0xD3BB2F622BD468F5ULL,
		0xBFE73AA970AE2B0EULL,
		0x8D92F7E02416D6A5ULL,
		0x39F5DF4D637FB807ULL,
		0xEAE827D19A9A64EEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5B15499DFA14D29DULL,
		0xF69B0B558471F519ULL,
		0xAF27EDD3D2C1724CULL,
		0x38A4C4F72761C969ULL,
		0x586A62A502C2BEA1ULL,
		0x0A46D65221AE7A1BULL,
		0x4E9D7211502E8D3CULL,
		0xCA7D7DFE71A4C259ULL
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
		0x4EC7E6A7346DBD9BULL,
		0x7E229CC9FCBF052FULL,
		0x3894AC8E126787E8ULL,
		0xAD9D20FDE7A25DE0ULL,
		0xFB6A0F69C9583AB2ULL,
		0xE84866A71F2394CCULL,
		0x9EF8D406DEA861BFULL,
		0x2FD86FD255F158DDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x60CBCE768EC0B0F6ULL,
		0x013970091D17538EULL,
		0x7059E043041F5046ULL,
		0x0A31B87E6E79844BULL,
		0x32DCF49C9E2F8E1DULL,
		0xA1E47527ACCB233EULL,
		0x018EA205AAB5D7F5ULL,
		0xE5305831B3C2E911ULL
	}};
	t = -1;
	printf("Test Case 127\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x16D8C8645A192883ULL,
		0xF64F0DB04C9CE5A7ULL,
		0x81B57EE17DD13697ULL,
		0x7C9CF1BBB2AAC1B5ULL,
		0x3862A6E534205EEAULL,
		0x9629523EEF32AD72ULL,
		0xB08A335E1C9A6E5EULL,
		0x7EEA1A25DA6D9B01ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3FCDC694399D105DULL,
		0x23C948F426598B02ULL,
		0xD033F834061EE102ULL,
		0xA573B42194B3B871ULL,
		0x61BAC8E1778B49EFULL,
		0x623E9E72FE237007ULL,
		0x9C324171D0FE44A5ULL,
		0x4BF4222B18E7CCA3ULL
	}};
	t = 1;
	printf("Test Case 128\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x6C7F5C282F5250C6ULL,
		0xBD41E90078597F5DULL,
		0x362F4C35262AC7EAULL,
		0x42449DB341852DBDULL,
		0xA518365F481D3AABULL,
		0x9577AD15C0717374ULL,
		0x1A5EEEFDF27D9BBDULL,
		0x834D2D23DB3B2B0AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6C7F5C282F5250C6ULL,
		0xBD41E90078597F5DULL,
		0x362F4C35262AC7EAULL,
		0x42449DB341852DBDULL,
		0xA518365F481D3AABULL,
		0x9577AD15C0717374ULL,
		0x1A5EEEFDF27D9BBDULL,
		0x834D2D23DB3B2B0AULL
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
		0x4C9EE50F3F866FDEULL,
		0xC35A7FE39518B536ULL,
		0xDED521E4752173FDULL,
		0x183F7BEE24E468F1ULL,
		0xCE0A23A4172DC8CCULL,
		0x4E91C94B81B87C6BULL,
		0x99DBED567986F6FAULL,
		0x941EB0D9987B842FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEB133E0A61112481ULL,
		0x65D5296ED236E781ULL,
		0x2BBD5B8845F77A2DULL,
		0x014E0D8183DB0236ULL,
		0x92E971FB353959B0ULL,
		0xFFC27B6E7F5F5412ULL,
		0x5BCA93C6AC051D39ULL,
		0x4CB776452040953EULL
	}};
	t = 1;
	printf("Test Case 130\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x165FD6618FCCE4C2ULL,
		0x79DDE96800B588BCULL,
		0x593CBDBE0579F46CULL,
		0x18C36079ABB04256ULL,
		0xBC2D6FF0EE8C891CULL,
		0x014E73BA02B42986ULL,
		0x94F8174C9F4338DCULL,
		0xAC1C75CC1820B95DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x879215844DA76C8EULL,
		0xF95AFA90936E4D1EULL,
		0xB6BC3440F754974DULL,
		0xC81F464BE90B3ADDULL,
		0x3A911DA831E6C4B4ULL,
		0xFCE5239C521A2FA2ULL,
		0xE43C12058E295E4BULL,
		0xF2246747EC1DA24BULL
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
		0xE27F9F8F3ED0A336ULL,
		0x38205263A52F77EAULL,
		0xF4180846580D12DFULL,
		0x715CFFED5DA61A25ULL,
		0xE28714AA7C7017F6ULL,
		0x098CFED42AD7B2ACULL,
		0xDFA0AD06610098F5ULL,
		0x516946E8A0B2EFB3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEDDED6BA6CD13CB0ULL,
		0x03A76C15CB00CED3ULL,
		0xF0329C3766E9CB87ULL,
		0x877E577883CDA4F5ULL,
		0xD6E6FD35CD4E1FB3ULL,
		0x320DD341312999EAULL,
		0x60FA35B7082CA2F8ULL,
		0xB6C2F14157DD90B5ULL
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
		0x697E6B131990FB73ULL,
		0x11BB701A4D21021FULL,
		0x1B31D95F64F7CDBFULL,
		0x01443C282895CBC9ULL,
		0x7BD8AB2BD45CEC4AULL,
		0x5D8E3DC6A28ED8ACULL,
		0x79390162A7E8095BULL,
		0x9AF75A18E2960A45ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x697E6B131990FB73ULL,
		0x11BB701A4D21021FULL,
		0x1B31D95F64F7CDBFULL,
		0x01443C282895CBC9ULL,
		0x7BD8AB2BD45CEC4AULL,
		0x5D8E3DC6A28ED8ACULL,
		0x79390162A7E8095BULL,
		0x9AF75A18E2960A45ULL
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
		0x85DB64B71FDF29A2ULL,
		0x2B2C649252E6F1DFULL,
		0x324856DB61310037ULL,
		0x48F4D4BF2ABED60DULL,
		0xF00C00E05EFC0E1BULL,
		0x032B00789E7B34C1ULL,
		0x8F52974B10E5501BULL,
		0xE661E83856004EE7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x38CD31CEC670BCA2ULL,
		0x25BD163BB4E1D4C5ULL,
		0x037F235598C56380ULL,
		0xA454D1F4C69AF979ULL,
		0x7B870771904A6D7FULL,
		0xBDFF5CBCB21E383FULL,
		0x9CFEFD34E151008CULL,
		0x6F75C0932DE3C79FULL
	}};
	t = 1;
	printf("Test Case 134\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xBD6A3BA89CFCD5DFULL,
		0xD185CAFC78D80405ULL,
		0x5C9F2F75D8DE5961ULL,
		0xA6B4B108278AAAE7ULL,
		0x94D4D9EBA778C7B3ULL,
		0xFDD0244707F6BC06ULL,
		0x1FC56B6781A78CCEULL,
		0x05466CA42D50424EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x962C0ECB0D6ACA05ULL,
		0xDC03C7A6A413F7B2ULL,
		0x5848083BCDBE6DC3ULL,
		0x93196AFAAF4B66D7ULL,
		0x57F43C8B72288629ULL,
		0xD94E0208D97D92B5ULL,
		0x458B0FF4E6475706ULL,
		0x82BD11AF68C9F495ULL
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
		0x6F9217D11AD635B1ULL,
		0xE0A521C2DA797D62ULL,
		0x91EE8F5A25A0721AULL,
		0x0DE26EABC99EC23CULL,
		0xC3BF916E832E522CULL,
		0x2C1DC3B757D4F0B2ULL,
		0xA948C8D6DB16B48AULL,
		0xBF7C7208943239D7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x89335BBD30D3FDBCULL,
		0xD293CB8C65BE0686ULL,
		0xC5F076A60F16C063ULL,
		0xEFAAFD2A8BEB50AFULL,
		0xA03C041D258FD6EEULL,
		0xCA3997681E0B2CE8ULL,
		0x11F46A3DEB89AB59ULL,
		0xAC7EC6E161D9585DULL
	}};
	t = 1;
	printf("Test Case 136\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xA4AE32F5E9032F8FULL,
		0xDE5BDCE92E7C9EFCULL,
		0x78CF2AA264D57202ULL,
		0xBF96364D27500924ULL,
		0x4BC8E71D2DB707B0ULL,
		0x07708A956536DBABULL,
		0x31C9AB0A58155831ULL,
		0xD48B506145647595ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA4AE32F5E9032F8FULL,
		0xDE5BDCE92E7C9EFCULL,
		0x78CF2AA264D57202ULL,
		0xBF96364D27500924ULL,
		0x4BC8E71D2DB707B0ULL,
		0x07708A956536DBABULL,
		0x31C9AB0A58155831ULL,
		0xD48B506145647595ULL
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
		0x88484B11FFF416B1ULL,
		0xCC118684F068F12AULL,
		0xD556341DE819DF3AULL,
		0x543A5F920A7D4587ULL,
		0x5EE56A75450442F6ULL,
		0x26A82358BE13A772ULL,
		0xF9008CBAA87D975CULL,
		0x3BE6B70ADECFDCE0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6F19B636A4033699ULL,
		0xE8FB23E8CC67BA1EULL,
		0x5A96AA19021A5CB8ULL,
		0x409D974915F8309DULL,
		0xB2380905A3FCB1A4ULL,
		0x5F3C2E4E0C3526C8ULL,
		0x7DA74F1E8F1FB624ULL,
		0x15C6A97DE01D6516ULL
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
		0x3B305AC632F62987ULL,
		0x6F1CEDD667BAF8A9ULL,
		0x39E6F6B7713B7231ULL,
		0xBF4353BB8B5474AAULL,
		0x08D1DD8B00799497ULL,
		0x57D6EB80DA989132ULL,
		0x044AC8D85FDD06D8ULL,
		0xE470EBB2CBDF081BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF193B9761228931EULL,
		0xE5A5BBCAFEFE3675ULL,
		0xE6736D3CD6E32C93ULL,
		0xEFB973845C733557ULL,
		0x751448BD7030FB63ULL,
		0x060B30643F7081ECULL,
		0x9B8053CCCED2D26EULL,
		0xE77A909D002BC3FAULL
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
		0xCB04A0B9422A76AAULL,
		0x03DB7615FC1EADCFULL,
		0x793A13A05627FAABULL,
		0xB17B1AEC5ADC95EDULL,
		0xE11A342A502C60B9ULL,
		0x487859B58EEC6D8BULL,
		0xA5B45252EAC51ABEULL,
		0x1A0B18FBF0513FA2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB28AB18A0D977DF8ULL,
		0x3115BA01DB74BFB7ULL,
		0x77A6D04DAB589734ULL,
		0x5531084F2894EF5CULL,
		0xEC69C41CFCF4BAB0ULL,
		0x1363985806825CA4ULL,
		0x535A1301D13CE3C9ULL,
		0x14C37972ABA91371ULL
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
		0x8038F87C1B150B87ULL,
		0xEB99AC43A4E86D82ULL,
		0x51E9A0BBCF250124ULL,
		0x918CDBF129002182ULL,
		0x5E2C26CE55B7E965ULL,
		0x44EF9BBC5152483DULL,
		0xE7096041D9ADF17AULL,
		0x124F6754148D91F5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8038F87C1B150B87ULL,
		0xEB99AC43A4E86D82ULL,
		0x51E9A0BBCF250124ULL,
		0x918CDBF129002182ULL,
		0x5E2C26CE55B7E965ULL,
		0x44EF9BBC5152483DULL,
		0xE7096041D9ADF17AULL,
		0x124F6754148D91F5ULL
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
		0xF5237B7E109C4CE4ULL,
		0x6267D445D3749FE9ULL,
		0xD209241447459ECCULL,
		0xBF08FC671C492A56ULL,
		0xD0AAFA7B1E5CDEDDULL,
		0x909F67210D8471E8ULL,
		0x338F765C3B155160ULL,
		0xBAA379EE999C4DA6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0D6CD437679D8058ULL,
		0x508125475572EF29ULL,
		0xBA0C26B7EBFB7662ULL,
		0x8633B5A2F2415E12ULL,
		0x1C595952A6762F3FULL,
		0xCF32C37F590693B1ULL,
		0x2F5058EC983C4D2AULL,
		0xDF63435A17483AFAULL
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
		0xDC0CF29BA23524FFULL,
		0x8A560B12EA477308ULL,
		0x12A0FE1FECEBE68BULL,
		0x562AC911E3184502ULL,
		0xABE1BE2024C3CB36ULL,
		0x336ABA54557B87BFULL,
		0xC6B82D82A22AAB2EULL,
		0x23CCAFDE84F203B5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB13A9DEE2B5DFEF2ULL,
		0xE9F13E5E316AA314ULL,
		0x1D1556F49A2EE46CULL,
		0x7A91EFBEFA031726ULL,
		0xD0CF5FC07C1B14C0ULL,
		0x3E98BF4E4FDCC95DULL,
		0x777E065E791DA7FEULL,
		0x0D3E77999F06C3B0ULL
	}};
	t = 1;
	printf("Test Case 143\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x23C0469A97AF2570ULL,
		0xBB41C359EDCF746AULL,
		0x3BA962EC67BA0706ULL,
		0x9DFEAC98E5A08DC4ULL,
		0x385BE854D70A6488ULL,
		0xEEBB29F54D705C1BULL,
		0x6690035B5E9F233BULL,
		0x876B3F287D918EE9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x49C513CF99F9CA77ULL,
		0x4216242F43DF687AULL,
		0x98F48D837A82F51EULL,
		0x6262E827AEAC0EF9ULL,
		0xC6D9A7CC149498CAULL,
		0x594382ED21FFBA95ULL,
		0x6426BA5C783F28D5ULL,
		0x6DD22D556E6BDEF9ULL
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
		0x589F9E8C3935E99FULL,
		0x40D6C090941338A2ULL,
		0xAE0246CE3705FC31ULL,
		0x6F4BE0773195F975ULL,
		0x23713AEF067EB6C2ULL,
		0xD6D748823A4217F5ULL,
		0x1EE0135973694880ULL,
		0x17BC3749EA8DA01EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x589F9E8C3935E99FULL,
		0x40D6C090941338A2ULL,
		0xAE0246CE3705FC31ULL,
		0x6F4BE0773195F975ULL,
		0x23713AEF067EB6C2ULL,
		0xD6D748823A4217F5ULL,
		0x1EE0135973694880ULL,
		0x17BC3749EA8DA01EULL
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
		0xE004AE5297AC5B79ULL,
		0xC6B38AE8BE6F042EULL,
		0x1A81DEB6FA5F8D10ULL,
		0x1773C5A2F80998FCULL,
		0x0A1771C276B907B6ULL,
		0x4891A7F69F27F44AULL,
		0x8AEB337FBE65F834ULL,
		0x4CF3FA53E475CDD1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x87955340F4439E98ULL,
		0x62A732C50D463556ULL,
		0x14B73EE3B391F063ULL,
		0x85E3D068C615526BULL,
		0xF143969949BDC79FULL,
		0x37FE31938AA249D8ULL,
		0xE2BA580E836C60FFULL,
		0x094C2EE36369C767ULL
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
		0x40586943D9CB6C35ULL,
		0x033A6B478938D7A7ULL,
		0x242D01694E909FFFULL,
		0xA1EF76129595B27FULL,
		0x1E3A01D211A98818ULL,
		0x8ED728E28CD66EA8ULL,
		0xD3029509E4347DD2ULL,
		0x4ED28DF9717ACF42ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA588A4DD2D01B75FULL,
		0x101DB6AB3EF4A115ULL,
		0xBACEB496F57B2E30ULL,
		0x67B72037425CF49DULL,
		0xF2476A7E2B108E5EULL,
		0xBEB817D608971CB5ULL,
		0xBC7D151FE234407CULL,
		0xF22BBDD8F364321FULL
	}};
	t = -1;
	printf("Test Case 147\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xB890F3F59E48687FULL,
		0xF4BA0473F9E136F0ULL,
		0x028AE737FA0D38F6ULL,
		0x8C8315C7CFB023ECULL,
		0xF68E0BDD810C21F8ULL,
		0x8BC49B5847F4DC40ULL,
		0xA62E566164BA1687ULL,
		0x71756FC5F99F71ECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4F271D33844576B9ULL,
		0x0BA2CA3297EB6C3DULL,
		0x19F448523A7119B6ULL,
		0xDCD5DC741835D0F6ULL,
		0x559F2B7B5D5A20BFULL,
		0xF3C8ABB221912E29ULL,
		0x6CCBFB21AD03F6CEULL,
		0xAFD285EC13BF0149ULL
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
		0x9F3418344F701A77ULL,
		0xAAADDC474616D950ULL,
		0x3320B6597F1A77C2ULL,
		0x1606CE5EC4B333B2ULL,
		0xA39E45275BC81F55ULL,
		0xABF4899B53BFA13FULL,
		0xCF8F4B4BF10ECF97ULL,
		0x4508200C85773BC8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9F3418344F701A77ULL,
		0xAAADDC474616D950ULL,
		0x3320B6597F1A77C2ULL,
		0x1606CE5EC4B333B2ULL,
		0xA39E45275BC81F55ULL,
		0xABF4899B53BFA13FULL,
		0xCF8F4B4BF10ECF97ULL,
		0x4508200C85773BC8ULL
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
		0xC8EA2594FDBF0AF9ULL,
		0x6250F54EB5D5E53AULL,
		0xE912D2BD4C0CD2A1ULL,
		0x418D8F6418988881ULL,
		0x220C81E537DC2DA0ULL,
		0xF8C56B2B3E26D4DDULL,
		0x313899B80E364D86ULL,
		0x86E0ADC427A155D2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2C313CC4745A9541ULL,
		0x3B0A99B731473533ULL,
		0xA8DC9DA4553D781EULL,
		0xF125AA31A010AF42ULL,
		0x540340F3097FEF53ULL,
		0x4531D40C36114863ULL,
		0x62F3E8FC3068B719ULL,
		0x41AA9AA95F734DD8ULL
	}};
	t = 1;
	printf("Test Case 150\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x600299D3B03F35BEULL,
		0xDD8493FFAB520DE1ULL,
		0x8CA7E9BFBD62E14CULL,
		0x62D2737A0BDF4458ULL,
		0xDDB1021B05E0A5F8ULL,
		0x0BBB684DA7AF251EULL,
		0x68C21D98DF9851E8ULL,
		0xF232AB98BCCA610EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD32BD71E50944C1BULL,
		0x135D8AF9433118CBULL,
		0x7A18E4E4D7C97EECULL,
		0xB45F2F1500FC29C8ULL,
		0x58E61E6E64650462ULL,
		0xB011FCF1946C7376ULL,
		0x9273B079F55ADFDBULL,
		0x666EDD83219B1902ULL
	}};
	t = 1;
	printf("Test Case 151\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x52858B0BA55AADA5ULL,
		0x2AEB28E829AEB734ULL,
		0xD6D0339437F31EC4ULL,
		0x35DB135B0F07AC7EULL,
		0xAF6FACD779FBA62DULL,
		0xC5C46D7B64E2877EULL,
		0x99D7E2A86437EDD4ULL,
		0x19B1A0B24C16B334ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2DF8A08B6339A4E5ULL,
		0x22FEF110B2E31F5FULL,
		0xFE29FA207DCB0780ULL,
		0xE54089882D478229ULL,
		0x82E974FCC9FB0F03ULL,
		0x8E64FE8EFDCBB7EEULL,
		0x46952A4F2B318EB5ULL,
		0x46CE5EA25C5E14AAULL
	}};
	t = -1;
	printf("Test Case 152\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x14680FAC48292426ULL,
		0x8A8D31D6486BF819ULL,
		0xDEDB4760EC2C8183ULL,
		0x044B6D0E979D4C4AULL,
		0x72FD833E044CE925ULL,
		0x3A08ACAA6C159385ULL,
		0x9CE1183B45B83161ULL,
		0x14334E37F0CE808FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x14680FAC48292426ULL,
		0x8A8D31D6486BF819ULL,
		0xDEDB4760EC2C8183ULL,
		0x044B6D0E979D4C4AULL,
		0x72FD833E044CE925ULL,
		0x3A08ACAA6C159385ULL,
		0x9CE1183B45B83161ULL,
		0x14334E37F0CE808FULL
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
		0xCF064DC29FFB85E0ULL,
		0xDE0A5614CB0A1191ULL,
		0xD83D67002B1F82D7ULL,
		0xD4A131CC450A1EFBULL,
		0xA2B14CA32958EAFCULL,
		0xDFA8C6BDB4774F1CULL,
		0x01FCB2512F30951CULL,
		0xFD423AFFD21E83F7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE6D71E39C54BA662ULL,
		0xE5B9E75A9198956CULL,
		0x791F5564B79EFDB8ULL,
		0x9C7BAF4FE9D31883ULL,
		0xE669DFAD5F7C135CULL,
		0x4B9F9CA79496A8EFULL,
		0x7C696187995D363AULL,
		0x72F1A06B48A441EBULL
	}};
	t = 1;
	printf("Test Case 154\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x22A2C4B5AFFE8116ULL,
		0x3B3C47742A7C8F57ULL,
		0x335016D7BC3100C0ULL,
		0xEACCAC1E95B66367ULL,
		0x235EF2225937B8E3ULL,
		0xA8D09904F2F824B4ULL,
		0x6ECB289C47BC8D5AULL,
		0x28C78853279A68CFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x101B463AD47061ACULL,
		0x5F5CF40FC2D24250ULL,
		0xDB57E6B605FDE71CULL,
		0xB817199C7AA5B45AULL,
		0x92B6F13507ABDF45ULL,
		0x46B783EA88D5012CULL,
		0xCDF9DAD79F3A4990ULL,
		0x0AEA47F05209F8E9ULL
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
		0xE45DBE4C717BC9BCULL,
		0x2C2641CBC0BEFCEAULL,
		0xFF34F201D2753743ULL,
		0xFB851B0E236E6C48ULL,
		0xE477E3ACE44EBE09ULL,
		0xE61BC6C1D1A27819ULL,
		0x5DB59839211E2EDEULL,
		0x7F0BE0FBFBFA77DAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7E9EFE8A19E80D40ULL,
		0x7453B061EA3AF62FULL,
		0x1866A7ADA656486CULL,
		0x4FEAA9636C24D875ULL,
		0xF496D0D608786F7DULL,
		0x7044C6EEAD7A7BA5ULL,
		0xEBDE8EA39F7487E9ULL,
		0x3A66266A64DCAC5AULL
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
		0xF8A3488AA0C13CCEULL,
		0x3B633911E06FDBEEULL,
		0xEEF2301B008DB206ULL,
		0x90CA2D7815B89255ULL,
		0x62CE660ECE1A9EBAULL,
		0x57A483CD7107A3C0ULL,
		0xC30721068540C417ULL,
		0xAC588ED07E0CDAFAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF8A3488AA0C13CCEULL,
		0x3B633911E06FDBEEULL,
		0xEEF2301B008DB206ULL,
		0x90CA2D7815B89255ULL,
		0x62CE660ECE1A9EBAULL,
		0x57A483CD7107A3C0ULL,
		0xC30721068540C417ULL,
		0xAC588ED07E0CDAFAULL
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
		0xF72417C722615220ULL,
		0x5B72F9BBE0B79ECCULL,
		0xFD598F1B52D6E638ULL,
		0xAD75086DD1AB0AC3ULL,
		0x38E48B34AADBB225ULL,
		0xB9A718D80FF9E1F9ULL,
		0x65A7DF5442306549ULL,
		0xC4B8DC749CFB1A9BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8369BACC260A24AFULL,
		0xBACEFC72640F0416ULL,
		0x8CD63DCD628463DBULL,
		0xEC6A6F4936A1D03AULL,
		0x2B3AC0BA48274A74ULL,
		0x39D2F25823849DD0ULL,
		0xCCA7147B5E96DEDEULL,
		0xF4C4243F136094FAULL
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
		0xCB8182A8C85E20FBULL,
		0x0066B5F603FC0D76ULL,
		0x964F3929F51C20BDULL,
		0x821DEC817FF25452ULL,
		0x4191F4C3B8E1ABADULL,
		0x2956B66B3AB824B9ULL,
		0x34E4DBCE1BBEF275ULL,
		0x9DB2E8A57B14B3E7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x541E191B36799C7FULL,
		0x4C4FC560743BCD28ULL,
		0x997ED5DCED96EFE7ULL,
		0x622EC3E936BF43D9ULL,
		0x2C27A969BCB020F9ULL,
		0xE4C0B58AF106E18CULL,
		0x21966CA26B741EC4ULL,
		0x5AD2FD8A4BFF7C94ULL
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
		0xCE862C2943EDF8CCULL,
		0x3C3854381D6D8268ULL,
		0x950D6B6A83879DACULL,
		0x96B91B723FDD55E5ULL,
		0x65D5EFCFA1F4F174ULL,
		0xC9B7EF96F1757874ULL,
		0x8AA526C874E7B42BULL,
		0x2D427A271A417F70ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7CBEDA5BAFC80D91ULL,
		0xC8B0DD3D3967184CULL,
		0x4F8DE2316EE4FD58ULL,
		0xD9BDD21C85E5EE44ULL,
		0x1BDBD62567DD73A7ULL,
		0x6634C3471AD34398ULL,
		0xFC5C530563E8E69CULL,
		0xDEE714DE5788B012ULL
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
		0xC78B9E08EFB8275BULL,
		0xAF41CB676D6918D2ULL,
		0xA8BF5C87673946C0ULL,
		0x11C2E80ADC2CC9ADULL,
		0xA12133BB4CE40B72ULL,
		0x1C5A304EE3ED50A9ULL,
		0x04F53C1EC8CEB1D2ULL,
		0x61435C6B6C1F6F64ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC78B9E08EFB8275BULL,
		0xAF41CB676D6918D2ULL,
		0xA8BF5C87673946C0ULL,
		0x11C2E80ADC2CC9ADULL,
		0xA12133BB4CE40B72ULL,
		0x1C5A304EE3ED50A9ULL,
		0x04F53C1EC8CEB1D2ULL,
		0x61435C6B6C1F6F64ULL
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
		0xDF2DF13AEA79A3FCULL,
		0x303BF0E0407F98F2ULL,
		0xCF3C27C6833C3081ULL,
		0x2CF20F2139CC845FULL,
		0x3E3EA234346FA93AULL,
		0xA922D834C781D3D4ULL,
		0xC7567E4B297D407FULL,
		0xE477EA585D893E93ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x210F89E61A56E63EULL,
		0xD793C3CCC507E620ULL,
		0x567D2899AC8BCCCCULL,
		0xEDF2E8D548084E1EULL,
		0x2407A78B83BB0EE1ULL,
		0x5CB8341AA87B6740ULL,
		0xF99BD932C97E3598ULL,
		0x05BDBC63AB68824BULL
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
		0xBC5FC55BD56B396AULL,
		0xB5B5803C12CD1E21ULL,
		0x024431078DE340BBULL,
		0xD383C35DEC1ACDC9ULL,
		0x6D55EF5A21AD2C9EULL,
		0x5B59D4198D46B383ULL,
		0xF51AEA06FB62A9E9ULL,
		0x3E25AD9DDDFE129AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x56044A204207A060ULL,
		0xF487016F5AB15F11ULL,
		0x7B64746706868246ULL,
		0xF40324DC166FB4DDULL,
		0xDD487704F824A955ULL,
		0x871526A189FCF042ULL,
		0x64BBC053632630CCULL,
		0xE7359AF40090BC6BULL
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
		0xD8803E4B6B4943D9ULL,
		0x73A904727D0AD02DULL,
		0x004F2A42B28BE950ULL,
		0xC828AC9B897EBA0DULL,
		0x9A064E7AEEDECD74ULL,
		0x114460722E5C9E05ULL,
		0x9B4DC308746CEFA5ULL,
		0x86B380399B274A9DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAAC75876CAEA1EDEULL,
		0x20C37E0DC234F31BULL,
		0x3E574423B9F58CB8ULL,
		0x7A2EA837A8F6A1EEULL,
		0x7749533AC2BB5F67ULL,
		0xA2B88D82F392FCEAULL,
		0x5370258594A6920DULL,
		0x8009976552DF1B18ULL
	}};
	t = 1;
	printf("Test Case 164\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x696BFF65664E750EULL,
		0x4C7B7379BADD9A06ULL,
		0xF1C11AD365C1BFA4ULL,
		0x65493E6D8215DAB2ULL,
		0x5EEA6329848322F2ULL,
		0x199B29C486E90EC9ULL,
		0x47BF4FB83879C881ULL,
		0xC9274AF6C7D795E7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x696BFF65664E750EULL,
		0x4C7B7379BADD9A06ULL,
		0xF1C11AD365C1BFA4ULL,
		0x65493E6D8215DAB2ULL,
		0x5EEA6329848322F2ULL,
		0x199B29C486E90EC9ULL,
		0x47BF4FB83879C881ULL,
		0xC9274AF6C7D795E7ULL
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
		0xCA129865865CB6D7ULL,
		0xEC521332FC8B7F53ULL,
		0xB8083EB5B22170A7ULL,
		0xC2516EDF14BCD901ULL,
		0xF1AACB356A6CC305ULL,
		0x02D1797ACE69F8AAULL,
		0xFF1BB74FC6FB1800ULL,
		0xC4078C315951457BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9C98A8B04D585902ULL,
		0x5F4FF4DF4C0A7C06ULL,
		0xDA9D698CF0D579D1ULL,
		0x90BBFF5CE9A5AE27ULL,
		0xC3631D209BEEC356ULL,
		0xC0D7084F2105F601ULL,
		0x5091302E3026AECDULL,
		0x758BE2B423852F74ULL
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
		0xE508FD34BB829471ULL,
		0xBC0EC24A3252C2B5ULL,
		0xC8AC10D4BBC58062ULL,
		0x3BCC003A7A15ADDEULL,
		0x2B20FB924E483A45ULL,
		0xA8470669B37CC776ULL,
		0xFA2B990963E17342ULL,
		0x87F0F6589C4E6EC1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD8143EE8816CCBDBULL,
		0xE7447481758005F9ULL,
		0xD8B72838516EE7A5ULL,
		0x1C0EADFF1E106A26ULL,
		0x1308E0617007EB6CULL,
		0x9FB5D7607155ECB2ULL,
		0xFB7949BEAB2EBD6DULL,
		0xD5EA08C866A21EAEULL
	}};
	t = -1;
	printf("Test Case 167\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xA38678324231C763ULL,
		0xEDFBB7D195F856F4ULL,
		0x31B872FAC4B85850ULL,
		0x2AF7FD2A189F74A6ULL,
		0x93C42901B127253CULL,
		0xDCE755DA1FB26A58ULL,
		0x36ACF3D6613F0002ULL,
		0x5C39F5A5877AC0F9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x56AA98C494E01E4BULL,
		0x100D3FA65316E369ULL,
		0x3B67FD779534CB03ULL,
		0xDC3554676729D098ULL,
		0x7E0822A48477CE60ULL,
		0x4542E169E4E45A4AULL,
		0x32C98A32C50E14C5ULL,
		0x0914CDB1C0F7F575ULL
	}};
	t = 1;
	printf("Test Case 168\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x7097357A00DA2DFFULL,
		0xE787045219860200ULL,
		0x6697551E6B872631ULL,
		0xA638EB8B97267DA2ULL,
		0x513BA5B19187D11DULL,
		0x15622C928B5BCA3BULL,
		0x136A3E50FE59732EULL,
		0x1433A669C3EF48F1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7097357A00DA2DFFULL,
		0xE787045219860200ULL,
		0x6697551E6B872631ULL,
		0xA638EB8B97267DA2ULL,
		0x513BA5B19187D11DULL,
		0x15622C928B5BCA3BULL,
		0x136A3E50FE59732EULL,
		0x1433A669C3EF48F1ULL
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
		0x43097C62E22CE172ULL,
		0x0FFBCD268E127D3BULL,
		0x2EAC031AFDEA1F76ULL,
		0x62E7CCFC070B7BAFULL,
		0x19630BA446B1D603ULL,
		0xFA7CF262092B4757ULL,
		0x65642589A40BE064ULL,
		0xA94CA8B35ED95591ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB4CA760D3FDFCC9EULL,
		0x9F01F52BB42D2D99ULL,
		0xB5381B2D52908BCEULL,
		0xCC6EC2BCCB929F84ULL,
		0xA180D755897E7AD3ULL,
		0x4CB1B6F706BB70AAULL,
		0x110EFC60CE991824ULL,
		0x26A4D57A9EA92E44ULL
	}};
	t = 1;
	printf("Test Case 170\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x64530098173C8D11ULL,
		0x24F2B0387FF07252ULL,
		0x9B1BA092CC618B8BULL,
		0x8570C39A00D94C66ULL,
		0x8941A8748C74EDEEULL,
		0x717D4FD35E357C26ULL,
		0x50105024652177C8ULL,
		0xD6924CEA5858C170ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x28074D3A8355625BULL,
		0x1C083BB37D9DEE12ULL,
		0x42E79C796938B6D0ULL,
		0xE861A57D522A11A8ULL,
		0x056CD42BE1DE240EULL,
		0xB03CADEA9F96BFDCULL,
		0xE6B250B35BA87A65ULL,
		0xEB407B2147A28762ULL
	}};
	t = -1;
	printf("Test Case 171\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x11D01EA1E68B0041ULL,
		0x89994FCD6AA598D9ULL,
		0x8838AB2F613D6579ULL,
		0x009CAEF057CC7296ULL,
		0x57A17A1A32FB7A3DULL,
		0xD4861B803E9E0DC6ULL,
		0xE45385E11DB67C0AULL,
		0x236C9F281FD26202ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB070D0F9E81AC490ULL,
		0x299D637A47E84456ULL,
		0xB213824DE9E62C43ULL,
		0xEF81D5458385B716ULL,
		0xEAC6AD54CDC4C9A3ULL,
		0x65B75BBA84101DDBULL,
		0xE67DA78C55BB9EA0ULL,
		0x1364505031108768ULL
	}};
	t = 1;
	printf("Test Case 172\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xA29FCBA8425287DCULL,
		0xA6E676ACB970136EULL,
		0xE6BEC87EFE50AC0CULL,
		0xB931337D95B9A859ULL,
		0x7E1E1A89AC1B32A3ULL,
		0xD168AA9F779D1EB7ULL,
		0xEDA6C291A76B81FCULL,
		0x9CB8D73BE3089EE6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA29FCBA8425287DCULL,
		0xA6E676ACB970136EULL,
		0xE6BEC87EFE50AC0CULL,
		0xB931337D95B9A859ULL,
		0x7E1E1A89AC1B32A3ULL,
		0xD168AA9F779D1EB7ULL,
		0xEDA6C291A76B81FCULL,
		0x9CB8D73BE3089EE6ULL
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
		0x46292E1A4B43C41CULL,
		0x8037123AE8FFF2BAULL,
		0xBCC1B8E32D450276ULL,
		0x298C7338911AEC2EULL,
		0x498C975D71FDE05BULL,
		0x9CF7BF9C2A36062DULL,
		0x02D967374B23599CULL,
		0x71943AEB1478E2CDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA36053EEF9DDDABAULL,
		0xAB4727B7C7875B11ULL,
		0x6F8B20FEAC79DB7BULL,
		0xE22E35A2AEBCF1A0ULL,
		0xB3264DEE198F784CULL,
		0x39496F6C8CD54918ULL,
		0xA187551B2533E8B1ULL,
		0x57328432AEA9D7DFULL
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
		0xD36233ACE0E9E344ULL,
		0x81AF3C754A482ACCULL,
		0x82734FE687C5A1D3ULL,
		0x7B214468895C7174ULL,
		0x62E19FF522F8ADAFULL,
		0x54FAEBAD78C2C40DULL,
		0x22DCABF68922932CULL,
		0x674293ECCCD5F6BAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x93216784BCF6662DULL,
		0xD7AFFAF786C0D6FAULL,
		0x61C20C1CC43BAB86ULL,
		0x6D682750DBA6C67BULL,
		0x5676C6B79BC23446ULL,
		0xCC54CB64DED3DABDULL,
		0x7C8A11C3806A5ADFULL,
		0xFFBC53748669427FULL
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
		0x8EEF5DAA4FB859F1ULL,
		0x1FDE15D43C1DBE40ULL,
		0xC6AC5E115EB2FA76ULL,
		0xFEC5EE399D830745ULL,
		0x5FAEEF972B4E0CC8ULL,
		0x9059FEAC2CCE26D1ULL,
		0xB4A1D7B9C1C55B9FULL,
		0x9EA18FE48C275632ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x50D30553463AD6C2ULL,
		0x7769D2ED8475FC7DULL,
		0x01665476EDD2C5F0ULL,
		0xC2E7D7A36B6E6083ULL,
		0x7904117F3D20A73DULL,
		0x626595A55C04BB86ULL,
		0x5D738761D988B24DULL,
		0xA544D21616AAE0F6ULL
	}};
	t = -1;
	printf("Test Case 176\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x390A8755A92AD754ULL,
		0x76B2738A5D894EB8ULL,
		0x38CD4CFC1F57B58CULL,
		0x003357EF4E28C9B0ULL,
		0xC20F4D20D97B23FBULL,
		0x4A5F21B98B194479ULL,
		0xA3658E4FF961DA7AULL,
		0xB50F7917240C5BBCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x390A8755A92AD754ULL,
		0x76B2738A5D894EB8ULL,
		0x38CD4CFC1F57B58CULL,
		0x003357EF4E28C9B0ULL,
		0xC20F4D20D97B23FBULL,
		0x4A5F21B98B194479ULL,
		0xA3658E4FF961DA7AULL,
		0xB50F7917240C5BBCULL
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
		0x0E39E1AA47D5215DULL,
		0x2FB737479CC4578BULL,
		0x45E6F69ED319CB7FULL,
		0xB3FD05125C0BB0EFULL,
		0xCCB08CEDABAE01CCULL,
		0xDED9E13855228098ULL,
		0x397AF02D88D66F38ULL,
		0x4FBF4D19BC54319EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3A849F43B2F0A0B8ULL,
		0x04AD31D8C8F79D0DULL,
		0x4E187BED1C4937BDULL,
		0xA9DAD42B35EA0301ULL,
		0x022135616C766C4EULL,
		0xDC52A0E9672DD531ULL,
		0x76E94EDBFEDC4935ULL,
		0x540B3C742CE86832ULL
	}};
	t = -1;
	printf("Test Case 178\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x2F467CC8F7A582B1ULL,
		0x6D17BD2EC083A628ULL,
		0xD1BAD9EC1E28F117ULL,
		0xBEDDD56278EB93E9ULL,
		0x7E43921A19834671ULL,
		0x5555459A4C35024EULL,
		0x643441D086936DF5ULL,
		0xCCB844DB511802F8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA218E32930A2DF19ULL,
		0x8E6A72EA76B03F0DULL,
		0x9E58DBB32BFC794EULL,
		0x24A9C69DB4F6EE4EULL,
		0x3D3F12EC5ABD6FBBULL,
		0x0D59698D1E138E55ULL,
		0x86850CC75E13EF58ULL,
		0x1607A5BE15DB02DAULL
	}};
	t = 1;
	printf("Test Case 179\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xF83E1B69239FA94EULL,
		0xAA963719C81A7547ULL,
		0x86A12733AC82D69AULL,
		0x8462A73AEC75CAA9ULL,
		0xF68F98548D47621FULL,
		0x53F3ED78862059D9ULL,
		0xB132D0A280DC2AD0ULL,
		0xE74C6074E1DCED14ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2CD4423BB2CEF5ADULL,
		0xD0279E3D19C3E255ULL,
		0x7D55DF812B2C1314ULL,
		0xA409254821A7F392ULL,
		0xAA4DAB1EC9E284EBULL,
		0xFEA3AC27C8C80B9FULL,
		0xDB40FADE0019A999ULL,
		0xBB0750B4FEA487B9ULL
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
		0x7DCC2596625B802FULL,
		0xB002D16AEF42DAA9ULL,
		0x4A4A34743E718BA7ULL,
		0xEBF630C86AA33080ULL,
		0x9141024535C5F939ULL,
		0x0923D177A1024157ULL,
		0x6FA06C341DFDF15EULL,
		0x88576E3464DBE0EAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7DCC2596625B802FULL,
		0xB002D16AEF42DAA9ULL,
		0x4A4A34743E718BA7ULL,
		0xEBF630C86AA33080ULL,
		0x9141024535C5F939ULL,
		0x0923D177A1024157ULL,
		0x6FA06C341DFDF15EULL,
		0x88576E3464DBE0EAULL
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
		0x0B15B8098089D4CAULL,
		0xADF2AF3CE1435ABAULL,
		0x86C4E7A8441FC970ULL,
		0xCCC305D5B859C6D5ULL,
		0x31BEAC63CDA2ABD7ULL,
		0x573937B5FB7038E6ULL,
		0xE478B32BEA991B41ULL,
		0xB019177AC5908538ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBD5A96597B4059B7ULL,
		0xF46840629BAE0E3FULL,
		0x751C80AAFB7E00D8ULL,
		0x87C8344091F35DFEULL,
		0x14D1894F5D01D8EBULL,
		0x10C7315FA10A31A6ULL,
		0xAB125936544BFD98ULL,
		0xB0E996CF9C630B63ULL
	}};
	t = -1;
	printf("Test Case 182\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x7599425489259E71ULL,
		0xF7326FE0F8A3085DULL,
		0x7854F33810A5B7AEULL,
		0x4E8DE0D71960ED95ULL,
		0x5950722FDECAB8EAULL,
		0xD24607C816460EABULL,
		0x6EFD59BA51547DD7ULL,
		0xEAB4484FF5608F77ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4A4979DE92BBE2CAULL,
		0x4B249EB575431D50ULL,
		0x5A2C93423EFD6AF9ULL,
		0xB1FA6C127AE44FCFULL,
		0x5F1443D4B304851AULL,
		0xDF53CB7E4105ED8AULL,
		0xBD9FF583FE6143C2ULL,
		0xED7EB042DFB92F58ULL
	}};
	t = -1;
	printf("Test Case 183\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xAA621EC6257EE488ULL,
		0xFE2056F13EA062B1ULL,
		0xEA0096212F891709ULL,
		0xEEE329E648D14DC1ULL,
		0x516CEF214234F61BULL,
		0xE58E115EB2A2D9E5ULL,
		0xC098686663314484ULL,
		0xC05D4405BC929CD2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x89BE007FD23276F8ULL,
		0x2138216001332DB2ULL,
		0x681C3367FF23D7E2ULL,
		0x6DA39BB291E5C9E7ULL,
		0x005C5575637FC4D0ULL,
		0xA77F80409C97A1F4ULL,
		0x6CA92989BD2CFD40ULL,
		0x97F1F2D02B1FDAA6ULL
	}};
	t = 1;
	printf("Test Case 184\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xE2026F3AF1665A53ULL,
		0x3FA3043B265D4AF2ULL,
		0x2F45163FF6EDA9C2ULL,
		0xA4AFC582D1504E0BULL,
		0xB5E88A997BB7ADA0ULL,
		0x5F634C9D6046FE62ULL,
		0xAEC4271C91B900CAULL,
		0x116742F16A60CAB4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE2026F3AF1665A53ULL,
		0x3FA3043B265D4AF2ULL,
		0x2F45163FF6EDA9C2ULL,
		0xA4AFC582D1504E0BULL,
		0xB5E88A997BB7ADA0ULL,
		0x5F634C9D6046FE62ULL,
		0xAEC4271C91B900CAULL,
		0x116742F16A60CAB4ULL
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
		0x0FE1C33B09F27356ULL,
		0xF0EE58912F824759ULL,
		0xFA387321354ABD1EULL,
		0xD1D12C36662BDB91ULL,
		0x40CCA789EA22E8BFULL,
		0xAE9EDE9D09787836ULL,
		0xE2D2FF7DDF4328DFULL,
		0x3843CE008857F8B1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x750C91E44CCD3455ULL,
		0x670E197BE1154954ULL,
		0x11595ED3142BC21AULL,
		0x29BF38F598AE607FULL,
		0x5052EAF37AB4CEA5ULL,
		0x29B47F6D25044CCAULL,
		0x56451960BEEAA118ULL,
		0x9E301FD9BAA046A1ULL
	}};
	t = -1;
	printf("Test Case 186\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xC5A2EB818F33C6D5ULL,
		0x3FE5AA2F4BBBC079ULL,
		0xAC70320C10FA8B12ULL,
		0xDAB79CA8B7065803ULL,
		0xBF11EA8A87755DD7ULL,
		0x559EA33385A95E4EULL,
		0x91B81E3C17B496E3ULL,
		0x0C95BBF5EA6F640FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9248A8B4E905FA06ULL,
		0x9C52427C5572836CULL,
		0x9C347A283B2F5D8FULL,
		0x5B20F6ED061EC0F1ULL,
		0x07D9A1D7E21E57E2ULL,
		0xB0EE27CEE71D4975ULL,
		0x679C39192434CAFEULL,
		0xC3A02D479DE74D63ULL
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
		0x05317EC322610EE8ULL,
		0xDBC7D392B7B55243ULL,
		0x1DA7BACE13FED348ULL,
		0xBB4A08E82A510E23ULL,
		0x9B163336E2722490ULL,
		0x4A49273B43FFA428ULL,
		0x1CE6836A3FCE8472ULL,
		0x101057006A0830A5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFF46C12F5BD825EEULL,
		0x16EB945B09985C9EULL,
		0xA6DB7142459FFABEULL,
		0xE5F6D93BEB541C51ULL,
		0xA4A0C33ACDDF2C17ULL,
		0x9A0317FF467690A0ULL,
		0x791C0B74F2477752ULL,
		0x3B32BE4936843346ULL
	}};
	t = -1;
	printf("Test Case 188\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x3AF94D34CCDE2752ULL,
		0xA0ABAB0291F51924ULL,
		0x4AA8BE08C2BD54F1ULL,
		0x7F778BCDCEBA95B4ULL,
		0x9A744D982F85B8BBULL,
		0xCC6094C925E167F4ULL,
		0x8A27B3BE5CC2646AULL,
		0x630C69BD49715E42ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3AF94D34CCDE2752ULL,
		0xA0ABAB0291F51924ULL,
		0x4AA8BE08C2BD54F1ULL,
		0x7F778BCDCEBA95B4ULL,
		0x9A744D982F85B8BBULL,
		0xCC6094C925E167F4ULL,
		0x8A27B3BE5CC2646AULL,
		0x630C69BD49715E42ULL
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
		0x2996579E6B27FC2DULL,
		0x769063E0723957CEULL,
		0xC457DC9957CABC78ULL,
		0xBF264441504BA264ULL,
		0xE6AC2BE457BBEA19ULL,
		0x42FC6AA6DB9943BFULL,
		0x6169EE178B351267ULL,
		0x439D088A73DD804EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCE6C0BAAC4F84BB4ULL,
		0xFDC5219CC3665FB9ULL,
		0xB8319C240F61BEBEULL,
		0xA49137DB9DDDEBE8ULL,
		0x001B792C8DA76AB2ULL,
		0x4CB62DB6796596F3ULL,
		0xBDCF35C2A5045740ULL,
		0xEFAAC777BC5E6BD3ULL
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
		0xAACD62B663CFD803ULL,
		0x09BD9C77C4CB7D7EULL,
		0xB77D0AD7BD143832ULL,
		0xF86FC5C50DBC09ADULL,
		0x00AC3F82FB157195ULL,
		0x1B0C029B0FF40811ULL,
		0xBC3464CCDCF29D09ULL,
		0xDD017A70D685B46DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x00EC6EF50157403FULL,
		0x20646C3FD2746BD3ULL,
		0xCFDC54FBE89034E4ULL,
		0xC439B7EC8BA69C25ULL,
		0x39A50FCE66A2FBB1ULL,
		0x1D679F25A3D56276ULL,
		0xA39BE14CF5FAAB26ULL,
		0x02EE887B211263ABULL
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
		0xBFCABC45618A4DF3ULL,
		0xE095D3387E38196CULL,
		0x297C41C3BDED6CF8ULL,
		0x8E1D13DB356CF0C2ULL,
		0x8EBE3FBC61DC7FEDULL,
		0x1AFEBEFFA81D4135ULL,
		0x86FE2EDC4969B507ULL,
		0x178F7522B94DC9FFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE644664F1EB2B238ULL,
		0x476F24D495D4D293ULL,
		0x87076730B6823284ULL,
		0x6ABB79C5EEA24FA1ULL,
		0x603B943EE9C7F761ULL,
		0x3E5F27B1E4928F05ULL,
		0xE58D839929A0F2D8ULL,
		0xB1AFC622DB5F65AEULL
	}};
	t = -1;
	printf("Test Case 192\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xEEBB0408FEF003BDULL,
		0x12AB1BD68D1A82C4ULL,
		0xCBBDEA833DBFC9A8ULL,
		0x22EE38B9008648F4ULL,
		0x1F0F6FC757F24066ULL,
		0x1A25F362A346DE5BULL,
		0x65FBAE959199FC48ULL,
		0x6A82A26DB790BF6AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEEBB0408FEF003BDULL,
		0x12AB1BD68D1A82C4ULL,
		0xCBBDEA833DBFC9A8ULL,
		0x22EE38B9008648F4ULL,
		0x1F0F6FC757F24066ULL,
		0x1A25F362A346DE5BULL,
		0x65FBAE959199FC48ULL,
		0x6A82A26DB790BF6AULL
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
		0xD9C5D70068AA66C0ULL,
		0x1F2623A2B550CA32ULL,
		0x0D869D31A67FFEB1ULL,
		0xC7FE2804EF68F0D8ULL,
		0x80F01CE1B0B5B927ULL,
		0xB479FCAAD3D1B6A7ULL,
		0x43DAACA8269BFB9CULL,
		0x8FBF00DE7F4549B3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9D04707A7E13AE25ULL,
		0x8310FD5B7112FA52ULL,
		0x7294CBC433A76BF2ULL,
		0x5667701524E0E900ULL,
		0x824F74F2507DFBDCULL,
		0xC2265E5E2E8B900EULL,
		0x0FB10510A187A9A0ULL,
		0x98D9854D53E05713ULL
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
		0x076095AE1315D49DULL,
		0xD0EEDF0F675773BDULL,
		0x2D3DFD6152CEAD43ULL,
		0xD8EAC5563539F6A8ULL,
		0x170D42F9A8F363C7ULL,
		0xB7F41DD325D9BA7DULL,
		0xCA65BBB54666CE13ULL,
		0x0C5D8859827EF2F2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6BE84CF76B80D0B2ULL,
		0x964F14E60C2771DCULL,
		0xB35F1E34B776887EULL,
		0xC4E4FD2D9F813EC5ULL,
		0x675E846BA224C40AULL,
		0xA4C12F6E070BF510ULL,
		0x803EA2264979D40DULL,
		0xAAEB53DF6BEF3BEBULL
	}};
	t = -1;
	printf("Test Case 195\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x9C84AF766DA4FF29ULL,
		0x23C9154A1976E9CAULL,
		0xCDC4512C1965136BULL,
		0xDC989B4410EC38FFULL,
		0x9A86B5201040ED59ULL,
		0x4CB6EE957A7CEAC8ULL,
		0xE6FF99D85063F4B3ULL,
		0x6C96692C14611B98ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x564EF4973D033C0AULL,
		0x99FFAE830B355567ULL,
		0x46547CF2B2BA64F8ULL,
		0xAAE45A7070167C80ULL,
		0x1B5E0B6FD4C8FD8BULL,
		0xA3586423364ACAE4ULL,
		0xAEA2D76B10A50078ULL,
		0x48378F11EB5BAF7EULL
	}};
	t = 1;
	printf("Test Case 196\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x23D380903E4401CEULL,
		0x3BF512A2C9BC9CD7ULL,
		0x18EAE3ECA5D1EE3FULL,
		0xB265EDAC8110F31FULL,
		0x714F3B6D97FC4D3EULL,
		0xD2D0EFE05ABCC297ULL,
		0xA025AF26A7DFC66DULL,
		0x695723562386A481ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x23D380903E4401CEULL,
		0x3BF512A2C9BC9CD7ULL,
		0x18EAE3ECA5D1EE3FULL,
		0xB265EDAC8110F31FULL,
		0x714F3B6D97FC4D3EULL,
		0xD2D0EFE05ABCC297ULL,
		0xA025AF26A7DFC66DULL,
		0x695723562386A481ULL
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
		0xE48BE67EE34AC75BULL,
		0x181D8229BC985702ULL,
		0x3A77AC65198B4292ULL,
		0xEEEB63A421680965ULL,
		0x3564DD66C74DD46FULL,
		0xDD1363D5875419FCULL,
		0xC8079D20D5D8DB2FULL,
		0x3C91FBF4E851223EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF16C7693071315C9ULL,
		0x855E1F3353E56775ULL,
		0xC3CFFD9407F37973ULL,
		0xCC4A6CD36D159749ULL,
		0x3C739CF8AAB03EACULL,
		0xFE6D4FEA8A75C891ULL,
		0x20BBB13B3C1FE2C7ULL,
		0xE1907EAD5F06E907ULL
	}};
	t = -1;
	printf("Test Case 198\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xC46243E76C5B2BE2ULL,
		0x37DFF8B793D00DC5ULL,
		0xCDAF28F0C15A21FAULL,
		0x50337B4C2B019E8FULL,
		0xFB7C86A7BB9E7623ULL,
		0xCE5A9D62DCC7A6C0ULL,
		0x07418034D5203321ULL,
		0x642E26C263978833ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x195767505F28539AULL,
		0x6235BF4475730E43ULL,
		0x1CE36504B278F4CDULL,
		0x666722D3ED29909DULL,
		0x78B4624C8F85EA2BULL,
		0x61C2C9D302562B75ULL,
		0x7B1CBA97B861E5DFULL,
		0xD330E5733F8242D5ULL
	}};
	t = -1;
	printf("Test Case 199\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x5D1F9F6C12B4DB50ULL,
		0x2B93CF212F8CECF9ULL,
		0x9196893A6C394C51ULL,
		0xCD8855C9B11F334DULL,
		0xC12FE3AFCF9180C9ULL,
		0xA52A63A426E32128ULL,
		0xBD85E44019327678ULL,
		0x69F4073D2F708602ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEF4E3B495C24B9CAULL,
		0xB3E7ED7E31A45F41ULL,
		0xAF60869FF9968E21ULL,
		0x1F2FC01D86959B15ULL,
		0x008D81E080C50934ULL,
		0x9B8EA9EA7381A1CCULL,
		0x1C06E7B5C0263181ULL,
		0xA03A303CEA2B8CDAULL
	}};
	t = -1;
	printf("Test Case 200\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
	return 0;
}