#include "../tests.h"

int32_t curve25519_key_cmp_test(void) {
	printf("Key Comparison Test\n");
	curve25519_key_t k1 = {.key64 = {
		0xE2D57946385A108AULL,
		0x7248ECA64D651172ULL,
		0xA924823C1CC564CCULL,
		0xC3002204F19951A4ULL,
		0xBA7C097F6BF222E3ULL,
		0x9B12AF270BA57259ULL,
		0xCA5C6B622D6286D6ULL,
		0x675DB41EB7DBE0DEULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0x041839B9710FAC61ULL,
		0x757343AD2B7FF843ULL,
		0x59D4C103FDB9B274ULL,
		0x575E77901B9EFE45ULL,
		0x942F4D56AABC9CF5ULL,
		0x83AE7AADE0C26C4CULL,
		0xF6D1F01DC2A25B10ULL,
		0xEFC5120E9D5A4E8BULL
	}};
	int t = -1;
	printf("Test Case 1\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x26EF6CD9E9C91A81ULL,
		0x7682C9482C2F4FF7ULL,
		0x9B16A6D04FA68164ULL,
		0x929CE8C141A67BCEULL,
		0xFD1848B3F3752102ULL,
		0x764D45E965228628ULL,
		0x569591255C923C1DULL,
		0x47A8D36A3C743DA6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7909CF820DAEE25BULL,
		0x2D40DBF827628F70ULL,
		0x3994DCE3479BE85EULL,
		0x5A41F14B8EDD0133ULL,
		0x24817DEE950C20C7ULL,
		0x50DC50AB5C4F974EULL,
		0xA38A6C299F531753ULL,
		0x84F69A28A4D36FA9ULL
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
		0x63F23D1AF34AF82DULL,
		0x122CE3C60BC7A493ULL,
		0x858A81EE6388C07DULL,
		0x34934EEF444D5B53ULL,
		0x66AE9DD1332D2A62ULL,
		0xB5F0B5520F7C4217ULL,
		0x793D6BCD5335B018ULL,
		0xAC7D2FAB92B096CEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1FA7C3FB5AA5B8A2ULL,
		0xDE6C88DF8113189AULL,
		0x11A65F68CAD611EDULL,
		0xA019DE9329C6DFD1ULL,
		0x690C47DA59DBF60AULL,
		0x55E432CB322115D1ULL,
		0xE5C342FB6D867E78ULL,
		0xE3C2B7E52909C206ULL
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
		0xAB8C574D23AE891EULL,
		0x63B6E4A7E5333BA7ULL,
		0xF54ADBAA3E11A9ACULL,
		0x407DB63BFC8E6B49ULL,
		0xEFA193A00E46C2EEULL,
		0xA0CCFD0FD3B13AABULL,
		0x6D4243542B02BECCULL,
		0x890A09583C281BB8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2E846DEEB4ABA511ULL,
		0x228D50DAE1C294D0ULL,
		0xC80A7F4568F51520ULL,
		0x1886FBC18E8AC3D6ULL,
		0x42B8C01BC84CCEADULL,
		0x0E19453FA1CB5972ULL,
		0xE8CCB1E041B84F25ULL,
		0x5D66544DFF5D9300ULL
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
		0xFD8192C1D22BC24FULL,
		0xF574A6746C7848A2ULL,
		0xC9E60EF0B8FC029AULL,
		0xAA53DC9916732E68ULL,
		0x7403C5F132A6A617ULL,
		0x8B8F4300153586A7ULL,
		0x50E62ECE96D9DC28ULL,
		0xA340F9DE92DC22F8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFD8192C1D22BC24FULL,
		0xF574A6746C7848A2ULL,
		0xC9E60EF0B8FC029AULL,
		0xAA53DC9916732E68ULL,
		0x7403C5F132A6A617ULL,
		0x8B8F4300153586A7ULL,
		0x50E62ECE96D9DC28ULL,
		0xA340F9DE92DC22F8ULL
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
		0x7D98622998400093ULL,
		0xA8361E11F0C73207ULL,
		0x538F2CEC2EE47A91ULL,
		0xD8699EABE27D24FDULL,
		0x09E5E85CA79C0C3FULL,
		0x62ACCBC4C5216B6DULL,
		0xAECABD13397AB849ULL,
		0x77AD73097D0A01BAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x00D3813A7F266A08ULL,
		0x735A16234D284064ULL,
		0xDBD5E2B05539DD64ULL,
		0x876440EA2049EF0BULL,
		0x8BCDACF63914DED9ULL,
		0x78799DC7E9CDFD4EULL,
		0xEC12F4FDD3CD72BAULL,
		0xBC8893E0854AABFEULL
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
		0xD6C7E1CCE8B05EC5ULL,
		0x99B774C950CE05C1ULL,
		0x87CB84581887BC3DULL,
		0x0BBFECA19E27E0CDULL,
		0x0C3894CDE64FA1F1ULL,
		0x2FBB1D5A0C527899ULL,
		0xE5A7AAD62F2DF7E8ULL,
		0x9EEA252A77B0252BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x36A40E8892DAC3C6ULL,
		0x8E80BE132A46DBDFULL,
		0x563473B5A142EA54ULL,
		0x2F2847BAB2DC0E63ULL,
		0xC7DC9C9F0BBA1C3EULL,
		0x7E57D02F395A07FCULL,
		0x94EACB52BAA07A4CULL,
		0xD02B1501C26A0717ULL
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
		0xD0157381A2579597ULL,
		0xA06E605D3EF0DE79ULL,
		0xB2FCAA72CF86E25AULL,
		0x8C9DBD6B2E888383ULL,
		0xFF1108CD1F2A2E5AULL,
		0x21BB85470831502BULL,
		0xC182EB9FF81B7D46ULL,
		0x4957FE8D1515C469ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8A4983EEA5E8CF2AULL,
		0xEABF7CC6D56049D6ULL,
		0x9C85DD2F836BD047ULL,
		0x0C38E9B3971D49EFULL,
		0xFD8F4C4D6792B91EULL,
		0x09D4B168402E457BULL,
		0xD13858423843E5ECULL,
		0xB5357F2940FC91E8ULL
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
		0x68F597526246AC22ULL,
		0xD1AEAA03FA7A02E7ULL,
		0x142D8B1F1FDDFB81ULL,
		0x020CA620E2655365ULL,
		0x3B9F59FBB0BE4356ULL,
		0xAFAFD6F08A7223D3ULL,
		0x639C9086BF1D7416ULL,
		0x31C443B3F1396D24ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x68F597526246AC22ULL,
		0xD1AEAA03FA7A02E7ULL,
		0x142D8B1F1FDDFB81ULL,
		0x020CA620E2655365ULL,
		0x3B9F59FBB0BE4356ULL,
		0xAFAFD6F08A7223D3ULL,
		0x639C9086BF1D7416ULL,
		0x31C443B3F1396D24ULL
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
		0x6842D1EDA4B70F97ULL,
		0x46381CBDA7EAF6E6ULL,
		0x8C510679773CC25FULL,
		0xB339E40DE26AB680ULL,
		0x31A2CF61437B6DA6ULL,
		0x9115B8F6E8897687ULL,
		0xEBBA8F12F247F042ULL,
		0xBE1B43DD1CF7BC5CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2C860CC679B703E1ULL,
		0xA9D7D3B6E6E2E2BFULL,
		0x9E28FBE71976F16EULL,
		0xDEE0BCF22FFD32CFULL,
		0x10AD48448E02FBD0ULL,
		0xF2227251C740B212ULL,
		0x23BC09C551427F73ULL,
		0xCCA6F225579A30CCULL
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
		0x306FA0C9F1BF0F40ULL,
		0xF4570E642EFFD355ULL,
		0xAEAA4709E7097890ULL,
		0x5ADBCE734807FD9EULL,
		0x15646FC09FD514CBULL,
		0x6C029DD249D0B1A8ULL,
		0x5155C6A3AFDD0978ULL,
		0x03E1AE2F8B71D729ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9AA7AD229C67E463ULL,
		0x85643BE77CE79BBCULL,
		0x59DCB3615DDA0BCAULL,
		0x08EC083D39AB6108ULL,
		0xB8201F4C85B57953ULL,
		0x9D9317BF8D3BA54EULL,
		0x938110FB251393A3ULL,
		0x8F9656827EB9513AULL
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
		0x1A48088140BDFF3BULL,
		0xEBDE9C89CDA8DC53ULL,
		0xCBBD3F685A2397D7ULL,
		0x10BE5ADF433232C3ULL,
		0x2D0BA23E28F9A3BBULL,
		0x4C078F0BEB5DF6A8ULL,
		0x039574FEF73F2B88ULL,
		0x957DBF13DAB2C0FFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x57FF487C25FB0240ULL,
		0x32CDF79AAB2E9B6AULL,
		0xDC197ED401F133FDULL,
		0x872CBD4D4E990250ULL,
		0x84CB816D560211F4ULL,
		0x4D144CCA1D475D5DULL,
		0x3A9EE4C5C093B2ABULL,
		0xEE2C8CEBE468C898ULL
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
		0x5658C2409BD1B18AULL,
		0x757A7CA6569790C7ULL,
		0x3A750AA0CDEA28F3ULL,
		0xAFF300E27AAABB79ULL,
		0xC29705A7D6E1523DULL,
		0x01E696FAACC7A5FFULL,
		0xD233339896C29552ULL,
		0xEF6F0A2F30FC7604ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5658C2409BD1B18AULL,
		0x757A7CA6569790C7ULL,
		0x3A750AA0CDEA28F3ULL,
		0xAFF300E27AAABB79ULL,
		0xC29705A7D6E1523DULL,
		0x01E696FAACC7A5FFULL,
		0xD233339896C29552ULL,
		0xEF6F0A2F30FC7604ULL
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
		0x290C83F3DE079096ULL,
		0xF6D8EF082DB1F533ULL,
		0x145A907C6015EBE2ULL,
		0xF4939610B6CBB656ULL,
		0x511E5433D0171EA2ULL,
		0x2CCE1C6CC4D84690ULL,
		0x6B749A98A5289713ULL,
		0x906338052ED2A606ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEDC822FAEAF878AFULL,
		0x0063EF462A1C0CC8ULL,
		0xE610BB39DC63B8E9ULL,
		0x714536F4D86E62BCULL,
		0x62E33D71AE1B026DULL,
		0x138C8F240DE6C4B5ULL,
		0x4BDC456D1A0F13E7ULL,
		0xBB2D10C9F4A859C1ULL
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
		0xF7B52D2016022DD0ULL,
		0xF5A10B756E732421ULL,
		0xCED8374A8BD6519FULL,
		0xD3459A158E02163CULL,
		0xCABB8D4010EC17BFULL,
		0xD71B1A2AAE0958AFULL,
		0x37C1AFC7437E3BBCULL,
		0xAB5E18A7B465B0DEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFDDC2ECC16A22AABULL,
		0x814BD0F8C4E054CBULL,
		0x0099394C4F9F1D9DULL,
		0x54DEC094A524369AULL,
		0x3F757F264610DA85ULL,
		0x9D6D4BF3DCEF6ACCULL,
		0x10B67658DABA8003ULL,
		0xB788E451A79AF082ULL
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
		0xF5C9831F7701D97DULL,
		0xEFEC920191507C0FULL,
		0x5C455D26EB0F3822ULL,
		0xE64D46EA9693144FULL,
		0x3BF945951D819C13ULL,
		0x28ADE0EFCF4F77FFULL,
		0xF5D0EB4BFCC39B8EULL,
		0xCC2CA940029F1E31ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x45025BB0FED2647EULL,
		0x4E7A40A48B996422ULL,
		0x2B2FA588ED1CDA92ULL,
		0x5656AD40FCCBEC79ULL,
		0x6994A3BD4D2ADA63ULL,
		0xA15912933F8B6AFEULL,
		0x5DD41549E97AF263ULL,
		0x14E27898BF92BB9CULL
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
		0x14E034A6A4B4DD62ULL,
		0x8CA6889A3324B5DDULL,
		0x908652D117CCC2BCULL,
		0x0AC0628D621F3FD8ULL,
		0xE699A3F53B4F90FAULL,
		0xD26F1A6EBB41978CULL,
		0xF340F0231A584835ULL,
		0x9D931E477814BE3CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x14E034A6A4B4DD62ULL,
		0x8CA6889A3324B5DDULL,
		0x908652D117CCC2BCULL,
		0x0AC0628D621F3FD8ULL,
		0xE699A3F53B4F90FAULL,
		0xD26F1A6EBB41978CULL,
		0xF340F0231A584835ULL,
		0x9D931E477814BE3CULL
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
		0xC72842DD6F24792CULL,
		0x62CD7EC9CB6D6751ULL,
		0x98F0F464F177E6BAULL,
		0x82311BCF98B2929FULL,
		0xE12E6AA4C8B966D0ULL,
		0xD9D5BDCE960F912AULL,
		0x11A994A244A66788ULL,
		0x272179F2C0BEF685ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x99D986CFBA354F99ULL,
		0x8EFD0FD643B8C36FULL,
		0x3ED85CF8B2227176ULL,
		0x447DB6503ADD693CULL,
		0x2CB58B4F2B16A505ULL,
		0x9A29424AE5415A85ULL,
		0x312D1CF399520140ULL,
		0x869D3F2D71D71EEBULL
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
		0xD7EC4C2C7AB8F97DULL,
		0x0DBBECAB029F67F7ULL,
		0x3A309F0DCE78630BULL,
		0xE87DEFDA7484CAE3ULL,
		0x660DB9EEDA1E7FD8ULL,
		0x7253AA05F12A531DULL,
		0xE0A7AF9DE6B22F02ULL,
		0x3A4CA8C34CE350D7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6DAB5465C9C318B2ULL,
		0x6444EC9D9C0650CEULL,
		0xFF3B413F952219FAULL,
		0x50472465CB5E4D7BULL,
		0x3E54AA10578B1190ULL,
		0xDE15C95761113D5BULL,
		0xA67EF6FD1FDE34D6ULL,
		0x185AEF6CC66A4A2BULL
	}};
	t = 1;
	printf("Test Case 19\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x82916838D2FD0B9CULL,
		0xB91006B95E3146FEULL,
		0x2E34EC6696162652ULL,
		0x3A70787470B1B01DULL,
		0xD9C09C36AB9EFA94ULL,
		0x9CDA045BD4D15888ULL,
		0x3500AA98F82415F0ULL,
		0x55B808F3D9033316ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8EB37B1E54FC1B5FULL,
		0xDF19994F89126C38ULL,
		0xCD31704F86F59F11ULL,
		0x9A53D19BF454B1C6ULL,
		0x4EC3F772467B7E53ULL,
		0xDE14A20E6727FBAFULL,
		0x539834BC9F866359ULL,
		0x65A5791A51420477ULL
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
		0x0CFFE4BA2744B6ECULL,
		0x1BA20CFF9835BD2DULL,
		0xDAA399BD9D618ED3ULL,
		0x0CBE57F16BC95F56ULL,
		0x3DC2992EFCA1DB2FULL,
		0x68C44A06C735ABD5ULL,
		0xA3272FD1E2262A49ULL,
		0xA364012508C71DFFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0CFFE4BA2744B6ECULL,
		0x1BA20CFF9835BD2DULL,
		0xDAA399BD9D618ED3ULL,
		0x0CBE57F16BC95F56ULL,
		0x3DC2992EFCA1DB2FULL,
		0x68C44A06C735ABD5ULL,
		0xA3272FD1E2262A49ULL,
		0xA364012508C71DFFULL
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
		0x6481169FE1CF2240ULL,
		0x1941BEDCF88D4075ULL,
		0x662C9674D6A9B8EDULL,
		0x48FED7DE554A512BULL,
		0xFC98FFF4256E5309ULL,
		0x6B3B4580AB0E8349ULL,
		0xD142343A108E8968ULL,
		0x9B99A7735740D7BFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDCF1B40324C9C076ULL,
		0xDBA6A52CEEF6DE62ULL,
		0xACD4FBE61A17B331ULL,
		0x4A2187E676FA1C31ULL,
		0x58BA5919FD2A589DULL,
		0xFC87330A9A45B6A5ULL,
		0x51DF0831501C6BF4ULL,
		0xFA9A7FCEC86EF1E9ULL
	}};
	t = -1;
	printf("Test Case 22\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xB7EC5D70C899A6DAULL,
		0xDE7163C46895DD34ULL,
		0xF43B67850F98F04BULL,
		0x7EC82524B5FD7A8FULL,
		0x2795C0E2316AF9A8ULL,
		0xEF59232025CB0952ULL,
		0xBE6F4BDCF7EA8B94ULL,
		0x1291BDA0946C385CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAFE6ACDA0F7D82B7ULL,
		0xAEF2AB62D4921483ULL,
		0xAB0E5EB2682B1F86ULL,
		0x02D2FC1EC9F26E1DULL,
		0x5C4072B8264AB7BCULL,
		0x570A87EDD89A7C24ULL,
		0x0F7495511CA693F3ULL,
		0x31D12C94F3858260ULL
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
		0x7A7621FC6040CD82ULL,
		0x712ADFB298A2CBF4ULL,
		0x6BB7320752F4F725ULL,
		0xF5FE736221853BDCULL,
		0x57DF1120D16E74DDULL,
		0x9A2D2D3C55FBBEA2ULL,
		0x03A4A451BF30BCCFULL,
		0x90DFC9DA134A2E35ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7511934A98ABF455ULL,
		0x4F3B78ACD9FD529FULL,
		0x34EC5F64AB4CCF16ULL,
		0x27EE70940709BA46ULL,
		0x70E519CE120F8D17ULL,
		0x56D888E8DB037DE4ULL,
		0x2E8F685A248CCF90ULL,
		0x33D4A874ADD01873ULL
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
		0x281246351F2ED864ULL,
		0xBBC0EA39FBB751D9ULL,
		0x2CC44E0179C5030FULL,
		0x6F47F58AEDC7CF00ULL,
		0xC946D1880A9658F0ULL,
		0xAD56FA5EF1D55E04ULL,
		0x8772717547CF07C8ULL,
		0x41715DE8A595C254ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x281246351F2ED864ULL,
		0xBBC0EA39FBB751D9ULL,
		0x2CC44E0179C5030FULL,
		0x6F47F58AEDC7CF00ULL,
		0xC946D1880A9658F0ULL,
		0xAD56FA5EF1D55E04ULL,
		0x8772717547CF07C8ULL,
		0x41715DE8A595C254ULL
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
		0xA0124A8DBA3A6A78ULL,
		0xFAC1E0BF749F1B97ULL,
		0xFB97CE793127AEFCULL,
		0xAC60E38AA3459B4DULL,
		0x6647408D177AA754ULL,
		0xB9F8F44507DA94D6ULL,
		0x498BC42A860D6F1BULL,
		0x15D239EEBD4DF723ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCD7804C8C1697090ULL,
		0x72B83B2BC9A9C121ULL,
		0xEEACFEC68396D5BFULL,
		0xB8E7C63A8CF7E55FULL,
		0xB7CC2ED901676589ULL,
		0x5A7FC43CADB86809ULL,
		0xB735D0387A423F0AULL,
		0x0E98CA76D5DCEEEDULL
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
		0xC327A716A4AB4AD1ULL,
		0x7C7A9576D2C30A9AULL,
		0x06627480F5974AE5ULL,
		0x487D2AA00F05C44DULL,
		0x367918B37CF8F661ULL,
		0x807036540A022A7CULL,
		0x66D2FBC7D307F1B3ULL,
		0x53E5A101A5882F03ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x06F5E800C6B481FEULL,
		0x15EB2F070F5C2BE9ULL,
		0x5F6C35F7A35BF70BULL,
		0xB0DEE2536EE3BE5EULL,
		0xDE92EEED67367443ULL,
		0xC4EEAF56AE3C7254ULL,
		0xDB9C7D17BA4A2F26ULL,
		0xB3D9DA2F17A68747ULL
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
		0xDF0EED6A9F065F6CULL,
		0xD270DF1936E523F7ULL,
		0x6263F109D068BBA1ULL,
		0x4C86C057C8BE6F2BULL,
		0x4735B5282AA25031ULL,
		0x9DF36ECF8BF0A278ULL,
		0xE4ACBB973BB89532ULL,
		0x198DD2741A63C5D1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0E7348AD8FF9289BULL,
		0x8A46A746E169A5B9ULL,
		0x39CCDE1553E9D0C6ULL,
		0x76B786495FAC513FULL,
		0xE67714C488EA9C3DULL,
		0x213ABC0A35C41451ULL,
		0x5A28FF9386B56F05ULL,
		0xA656B885BEE465A9ULL
	}};
	t = -1;
	printf("Test Case 28\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x2602E161DDFC0FABULL,
		0x3D51CDD8DBDBDD3AULL,
		0x0F25A59BA9C842BBULL,
		0x9F3470C5B7FF9FD2ULL,
		0xB91A5592BB322A92ULL,
		0x5EDF82C92A7A8820ULL,
		0x9A1BC60BE2658519ULL,
		0xDB7CA6EA73449217ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2602E161DDFC0FABULL,
		0x3D51CDD8DBDBDD3AULL,
		0x0F25A59BA9C842BBULL,
		0x9F3470C5B7FF9FD2ULL,
		0xB91A5592BB322A92ULL,
		0x5EDF82C92A7A8820ULL,
		0x9A1BC60BE2658519ULL,
		0xDB7CA6EA73449217ULL
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
		0xE2632260FC757968ULL,
		0xEFC6B8541CABEA63ULL,
		0x8365375062D33F49ULL,
		0xEFB8652249635325ULL,
		0x3A056810A12EED37ULL,
		0x08967FCF73F8C00DULL,
		0xE7C663C4D20BB590ULL,
		0x1B7395ACFDB3061CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2246146A181155E3ULL,
		0xC0A54568DF266B35ULL,
		0xE5D97F978FD64F0EULL,
		0xA71B2D1C5E046A7DULL,
		0x4A0F6A0CFE8A7ADFULL,
		0x8152DBB494987B2CULL,
		0xD5A80D9BEFA78ABAULL,
		0x00F6FC9395B575E9ULL
	}};
	t = 1;
	printf("Test Case 30\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xF6E895708D72E59CULL,
		0x30852FA40E8BD6D4ULL,
		0x0F3AD46AD56AC879ULL,
		0x79EE8935E71FFEBCULL,
		0x61B0E8D1D5AE5423ULL,
		0x64BB58526ED3D904ULL,
		0xEB801376A9D44526ULL,
		0x1DCEF3B312B09921ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCBB003D7A1417A68ULL,
		0xE0D88A6F0D4A7549ULL,
		0x8F2AA2A418339A48ULL,
		0x543B65494BC26AEAULL,
		0x0357B5E7BA51203CULL,
		0x9ED6C18BBC984D85ULL,
		0x9C29F68ED7F47B8EULL,
		0x00B60E81C5457029ULL
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
		0xC7CF1264B582A098ULL,
		0x1C528CF77F07FBDDULL,
		0xCD2ADAC6BC671B97ULL,
		0x8FF551D4ACB43919ULL,
		0x717D0C65CCECBEEDULL,
		0xE6700E328E953AD3ULL,
		0xA872E12FA5CD4904ULL,
		0x7780F4EA17331E84ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x87C304F87A425F9BULL,
		0xF1E74907E3001357ULL,
		0x3AF71F236B47FB0DULL,
		0x00FCC8DC91032FC0ULL,
		0x14733B74B4817843ULL,
		0xC4976BF487379B7EULL,
		0xAE98C8A41BEBE7E2ULL,
		0x4FDD46BA757B9282ULL
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
		0xBFF23D632B1BF456ULL,
		0x543AF5F73FF377B9ULL,
		0x83C8B2024622E162ULL,
		0x4BE1AE789BC94CA4ULL,
		0xD0F2A00D99B6DE3AULL,
		0xD1CD3ACF54558379ULL,
		0xED909713DF4F459BULL,
		0xCF3A171C3846A2B5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBFF23D632B1BF456ULL,
		0x543AF5F73FF377B9ULL,
		0x83C8B2024622E162ULL,
		0x4BE1AE789BC94CA4ULL,
		0xD0F2A00D99B6DE3AULL,
		0xD1CD3ACF54558379ULL,
		0xED909713DF4F459BULL,
		0xCF3A171C3846A2B5ULL
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
		0xB41411315F7453A5ULL,
		0xE71CC184EC5650EAULL,
		0xD792FD14E122E389ULL,
		0x6CEF75C7CEFB25C4ULL,
		0xB177F9376C2479FCULL,
		0x5E7E2D728167D98CULL,
		0xB1262E0065FB431EULL,
		0x211718566F33474CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFC1EEBF843216B9DULL,
		0x5D181369DAB7E852ULL,
		0xCD7FB9F6AEACFD68ULL,
		0x4E14A49A42C509E7ULL,
		0xBC718F6508E28663ULL,
		0x88CCF785EFE81B68ULL,
		0xDA45F069DD0712D3ULL,
		0x18C170C57E525188ULL
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
		0x7B3527133F81D544ULL,
		0x8998143F28BC2C23ULL,
		0x2286A88F4397DB30ULL,
		0x02428AEB7158008BULL,
		0x1A3EA8B0113A9C2BULL,
		0x5C7E1F906585810AULL,
		0x9D11473BA27C5D49ULL,
		0xC125448BDFF6831EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA01226E936E4BC3AULL,
		0xE3D6AAA077B234CFULL,
		0xDFC86A245A810003ULL,
		0x725F69D262F98BDCULL,
		0x820D180876E5C5E3ULL,
		0x3F5E4E0FE0EA67BCULL,
		0x667CAA74DBFA5D78ULL,
		0x79A1D8EC0E5ECA36ULL
	}};
	t = 1;
	printf("Test Case 35\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xCF9E3EDCB50FDD22ULL,
		0xC12A78C61E2026CCULL,
		0xAD0319A4EC9674BFULL,
		0x021014AC85F291DEULL,
		0x23571C4607D34AF9ULL,
		0xC1F3CD1A6CF751A4ULL,
		0x30A205B8E9D2D63DULL,
		0x0261FBC5A70DDCE9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD5A73EE7B99F3165ULL,
		0x9A3DAF97F009B03BULL,
		0xC295DF2F183FCC69ULL,
		0xDAEA15D33F007F2CULL,
		0x22916DC09DC5C8B6ULL,
		0xBAEBCB0498EAF5A0ULL,
		0x877C598473C827C8ULL,
		0x1CC1241E3C9C445DULL
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
		0xAC6DD82E4480C217ULL,
		0x7C79B84AD6D6DC31ULL,
		0xCDB33909D99D82F9ULL,
		0x5878385326EF919BULL,
		0xCB8B9D0A9BBF50B9ULL,
		0xD1614235AABFA768ULL,
		0x4A98D230E55C6CF5ULL,
		0x8DA867B309964D18ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAC6DD82E4480C217ULL,
		0x7C79B84AD6D6DC31ULL,
		0xCDB33909D99D82F9ULL,
		0x5878385326EF919BULL,
		0xCB8B9D0A9BBF50B9ULL,
		0xD1614235AABFA768ULL,
		0x4A98D230E55C6CF5ULL,
		0x8DA867B309964D18ULL
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
		0x50716D1828DF3B93ULL,
		0xBE8CBA1CAC05AC92ULL,
		0x970AD6F87A4A1B36ULL,
		0x307BD6DD64CA98D0ULL,
		0x9915D0DD16000A95ULL,
		0x9915C4CE8C4DE374ULL,
		0x10C5624E978DA44BULL,
		0xF4D4754F7687F318ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA26352BDB2096C3FULL,
		0x2ED7A1CE461F96ACULL,
		0x66D7A18664A82091ULL,
		0xCCFBFE151360D86AULL,
		0xC6900BD5428AADF3ULL,
		0x2666F0AF1B097CC4ULL,
		0x5F87583C3E0EC922ULL,
		0x8C781DC568436E4FULL
	}};
	t = 1;
	printf("Test Case 38\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x2DB72032183F11CCULL,
		0xE0ED871A0C95164FULL,
		0xDB945166837B7538ULL,
		0x1966AC6EDD6BECCAULL,
		0x49F6224FC59E1E20ULL,
		0xBC9BD320A0B191ECULL,
		0xD01E5CE98CB00427ULL,
		0x4C7E51700CA31CBBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x867FCEEEAB1D60BAULL,
		0x8EA4368941B02511ULL,
		0x5666C456B289229FULL,
		0xDDFB5712B9F75877ULL,
		0x3DDB0A61C37465E0ULL,
		0x432AD95C7F00BFD5ULL,
		0x457B7CC64378DC13ULL,
		0xA99FD44F66F3DDAAULL
	}};
	t = -1;
	printf("Test Case 39\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x53F27457AE274852ULL,
		0x62E5756480C47731ULL,
		0x78044DE0C9715754ULL,
		0x7CB3345D1AAD959EULL,
		0xB39DCA540AA7C0D1ULL,
		0x00ECF1B341B39F17ULL,
		0x6DB46CE42AE29E27ULL,
		0x697014AB81CABBB9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x47D75E52A02F17C5ULL,
		0x2173F32DEB068EFBULL,
		0x7096ED4791F74225ULL,
		0xCDD51DD412D4FFA0ULL,
		0x47BBBA1EA9F915CEULL,
		0x9F1D45A96451E0E9ULL,
		0xE6C658EDC2807ADCULL,
		0x894DB78CEFC28ED8ULL
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
		0xBBB50D8F49960F7AULL,
		0xC306FCF71D333F50ULL,
		0xFF96FF66CAD0293DULL,
		0x76CDF2D9BE68C44CULL,
		0x2C98263545E01A71ULL,
		0x6B57A8EBBDCDB302ULL,
		0x8B295AAFB58740E4ULL,
		0x24509924B10D7C7FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBBB50D8F49960F7AULL,
		0xC306FCF71D333F50ULL,
		0xFF96FF66CAD0293DULL,
		0x76CDF2D9BE68C44CULL,
		0x2C98263545E01A71ULL,
		0x6B57A8EBBDCDB302ULL,
		0x8B295AAFB58740E4ULL,
		0x24509924B10D7C7FULL
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
		0x816B9C2001486AF5ULL,
		0xF38084D7CE935DF3ULL,
		0x0ABFB0EDCA9CA299ULL,
		0xD9F79B8341E9B514ULL,
		0x95C829FCF91CD432ULL,
		0x23DD26E23BD32A5AULL,
		0xFA7EBB8DAE1A1A1AULL,
		0x21BA5F8F18AB7611ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE60FDFE1A400A4B3ULL,
		0x1A39879B599E09C0ULL,
		0x9068DAC1E0624E39ULL,
		0x76F80D64295A7581ULL,
		0x1A0BC8B9B869F68FULL,
		0xA06667BDB21B3D71ULL,
		0x2C18FEAA9AFB9DD6ULL,
		0xDEF311C7A3AA21F9ULL
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
		0x1EF6970FC67FA925ULL,
		0xCC3CF5E1A50D9A28ULL,
		0x89CCC00EF102E24AULL,
		0xA158315BE21EF397ULL,
		0xC0F2705678037630ULL,
		0xEBCBDA5B14FBA488ULL,
		0xB5A06DB8E6FC476AULL,
		0x69B6F86D9F2372DEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0DDBF5B24794AACCULL,
		0x6AE910742BE73911ULL,
		0x5AEE4E1CF7869A9AULL,
		0x6761D27DDBDA68E9ULL,
		0x8FFD26B45E08BAEAULL,
		0xDAB225631B0438FAULL,
		0x50ACCB0281C8EE03ULL,
		0xD8E70CB5471F5BCFULL
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
		0xC142F15A47087A57ULL,
		0x613E7366F4192650ULL,
		0xE1E1D8DF2C5D55FDULL,
		0xEA8B53A15351D0F8ULL,
		0xC72696E9186ED206ULL,
		0xAA45AB68875A2F19ULL,
		0x6C91B791511F3128ULL,
		0xF895A918130D6967ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7E889F46218A9637ULL,
		0x216DDC6C4E6B5981ULL,
		0x95DB1FECD04E0A33ULL,
		0xD941911A47BFBEEEULL,
		0x4A18BF9F5513F2A6ULL,
		0x00FB4A42E2C4A680ULL,
		0x26CB62CFA072D553ULL,
		0x7787BB1D79618841ULL
	}};
	t = 1;
	printf("Test Case 44\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xA5EBBDD2C9746526ULL,
		0xF31FA060B1487FA6ULL,
		0x7FA0240DE9B2484EULL,
		0x24CD414D95361AB6ULL,
		0x1CB20C47F4636CA5ULL,
		0x40AA2E372EFE5200ULL,
		0x4D91995AFFEDFEAEULL,
		0x41D246309EEE3109ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA5EBBDD2C9746526ULL,
		0xF31FA060B1487FA6ULL,
		0x7FA0240DE9B2484EULL,
		0x24CD414D95361AB6ULL,
		0x1CB20C47F4636CA5ULL,
		0x40AA2E372EFE5200ULL,
		0x4D91995AFFEDFEAEULL,
		0x41D246309EEE3109ULL
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
		0xC36818A9174E3445ULL,
		0xAD0012AE0F0D6F9AULL,
		0xBB8915701C5FE2F7ULL,
		0xB064BF17CEEB8D13ULL,
		0xCD6965F0CAA5C976ULL,
		0x93437FDA9916B8AAULL,
		0x438675250EEC457AULL,
		0x7919D47056D9F958ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF908B6448948D493ULL,
		0x00E144CCEEE124E3ULL,
		0x1CAC65D992456025ULL,
		0xD605EF9A67F59D42ULL,
		0x28495566FE430D89ULL,
		0x1703EEC4B8548014ULL,
		0x1B4B48FE0A5E4A79ULL,
		0x1BC1739D48CC7D59ULL
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
		0x7E12C20D7F16CBC3ULL,
		0x8115F9300F6A80C5ULL,
		0x916CD8289AD28B40ULL,
		0xD709078DB2313F63ULL,
		0x5C5A294729E7457CULL,
		0xB53F82ED7BE896B4ULL,
		0x662E2B6E7075A356ULL,
		0x564D6153B48BE6CFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4FFB0E92BB36E919ULL,
		0x6A552E4639533421ULL,
		0x85552FA40D78FC71ULL,
		0x3E8F95BE78C5D17BULL,
		0x573D8F98800D1A53ULL,
		0x8A3A25D072D2DA0CULL,
		0x40C078295D6F05BCULL,
		0x06F862797E296766ULL
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
		0x70343F143AEE7376ULL,
		0xFABFCF44193C51F2ULL,
		0x5958D16C83E9787DULL,
		0xD1E3110CBE464B1EULL,
		0xBFD9598357A98262ULL,
		0xEE71F7DEADB0BD05ULL,
		0x46A45B8603E21A0BULL,
		0x2AF4320124085E1FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2F3A4D5DAB471097ULL,
		0x5A3ABAEFE963DD25ULL,
		0xD98A4FF9D902FC92ULL,
		0x0FEF548AF6794B7CULL,
		0x8333D885428A8F2EULL,
		0x1393AC75850EACF9ULL,
		0x03B37EE74C0E5F0FULL,
		0xE3D9A950DBD5A2E4ULL
	}};
	t = -1;
	printf("Test Case 48\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x6454EFCA7B6EFFFCULL,
		0x4A5B84D24B4798EBULL,
		0x10AAC6737B0AE66DULL,
		0x4E405A0FA5C6B602ULL,
		0x09F80F10C6567846ULL,
		0xB18870FE17595379ULL,
		0xD1D3307211F81F56ULL,
		0x7E8A54F92DEC042EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6454EFCA7B6EFFFCULL,
		0x4A5B84D24B4798EBULL,
		0x10AAC6737B0AE66DULL,
		0x4E405A0FA5C6B602ULL,
		0x09F80F10C6567846ULL,
		0xB18870FE17595379ULL,
		0xD1D3307211F81F56ULL,
		0x7E8A54F92DEC042EULL
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
		0xC7962B88F2DDDBA6ULL,
		0x5062A61FF33E051DULL,
		0x2928FADF4AB5EC66ULL,
		0x0B5D566ABCDA8A7CULL,
		0xC29F017BDBA7BC5AULL,
		0xD0BB253EEAECF30FULL,
		0x2397F558019F957CULL,
		0xF8C5138488EC400CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA493CB09F611CCF8ULL,
		0xFC5C4726C8DD00B5ULL,
		0x1C137ED8965804C9ULL,
		0x6BC1DD2F5460D0B8ULL,
		0xBC3FBC48A12305F1ULL,
		0x563B2EC66AA92CB1ULL,
		0x1EC8E346C1424450ULL,
		0x28EBB41E81D579DAULL
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
		0x4E7E465A24BF7712ULL,
		0x7A2D7F75BFBF780FULL,
		0xD92615922F3ED3F2ULL,
		0xC9D01683E1750FDEULL,
		0x056DFCE6A1318BBBULL,
		0xC54D2BFE178AC737ULL,
		0x777B3AE497A4DE42ULL,
		0x374812417DADB0C4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x763387261C04AAF6ULL,
		0xF54018C2597E9C53ULL,
		0xDB3C78CE72968987ULL,
		0x20F8D03CAE976EC6ULL,
		0xD42D9E7807B66AA3ULL,
		0xC4B05B350700D4DDULL,
		0x3940988C0158715FULL,
		0xFC93822E79DEB547ULL
	}};
	t = -1;
	printf("Test Case 51\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x8D19301D663D753FULL,
		0xCC397C2E53368047ULL,
		0xCEFC35CB0BCB8F13ULL,
		0x410FD5AE375693FFULL,
		0x5794922E87F1E723ULL,
		0x257C6B45B3EC5D54ULL,
		0xA88D9F02F010019FULL,
		0xD568A17E2AD4799BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD3BA4D1B6BAE3BD4ULL,
		0x2B2A3BD31A929587ULL,
		0x0E3DD77B4BC88256ULL,
		0x908C93467C91C9F5ULL,
		0xEB17EFDAF2EA968FULL,
		0xBFCA014DC144A5D2ULL,
		0xD8AD2034BFA9E15BULL,
		0x21EE12666F7982C7ULL
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
		0x550D9192ED1C98D0ULL,
		0xECDC251FDAFDB068ULL,
		0xAEC7761EDB4FE6ADULL,
		0x216A60D41FAE1C28ULL,
		0x13D129E196702012ULL,
		0x472496E03E91D189ULL,
		0x4867325846DDAAEEULL,
		0x1EC987B678CB8CB6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x550D9192ED1C98D0ULL,
		0xECDC251FDAFDB068ULL,
		0xAEC7761EDB4FE6ADULL,
		0x216A60D41FAE1C28ULL,
		0x13D129E196702012ULL,
		0x472496E03E91D189ULL,
		0x4867325846DDAAEEULL,
		0x1EC987B678CB8CB6ULL
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
		0x94D76DA9AD9912F5ULL,
		0x6110B7E38A83A953ULL,
		0x12475EA5992736D4ULL,
		0x815FFB4EF0F50E4EULL,
		0x0DB924489E603797ULL,
		0x820F4C86E62A0C9EULL,
		0x0656ABD52974EB70ULL,
		0x6EBE60B651F5C8ACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEED4E25E2EC3D03AULL,
		0xCEFD91882B028425ULL,
		0x0BD823AD945961EDULL,
		0x0E5E89CA8915BA22ULL,
		0x437D2B60C7B545C3ULL,
		0x225E7DAC13539B4EULL,
		0x227E59DF726FDE7AULL,
		0x57CACA5DD7576D23ULL
	}};
	t = 1;
	printf("Test Case 54\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x6A2A1E3730FDAF59ULL,
		0x07C6FFADAAAE3506ULL,
		0x6CBF08EA1E28AAB1ULL,
		0x31EDAC51A611138DULL,
		0xC147CFD43BAB801CULL,
		0x3B20184AF6E84C22ULL,
		0xDE0D8D7A94388707ULL,
		0x305A03DC283FD146ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4B11047BC2B510DFULL,
		0xBAE257B34CCA2EC8ULL,
		0x634A8F7ED79D064FULL,
		0xC0F7EB601A3AA8FBULL,
		0x53B4C303B7520F8FULL,
		0xC85E3EB68AEDD2F9ULL,
		0xA8F0159368D482B4ULL,
		0x8E9475E1CC1BC630ULL
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
		0x25E777341C9B9D6AULL,
		0x8F5ECB31F176F83EULL,
		0x4BCF96BA98FCB0E9ULL,
		0xFF24E2391B7321ABULL,
		0x71BBC290EC844E92ULL,
		0xB43F86BABE783750ULL,
		0xEF6D7827ED662F4CULL,
		0x3109CFAB57159967ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA6FDA0CB4D0F9405ULL,
		0xE2EEF8F169974E43ULL,
		0x1AC78A7FECD34E55ULL,
		0xC613261B6D477FE5ULL,
		0x550008813A8EBC53ULL,
		0x3DA9C0ADE4E31C91ULL,
		0x2D4200AB613DD652ULL,
		0x3F42C5EA9161B11DULL
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
		0x69A2FF56A4BC2910ULL,
		0xEF85A14F17CE2F59ULL,
		0x52601E6B92EAF38AULL,
		0x7A475D047DB39AFCULL,
		0x9B2F3A9826027A59ULL,
		0xA46A793E6B1B2C9CULL,
		0x22E310F6B01031BCULL,
		0xDF73EEC221070BB4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x69A2FF56A4BC2910ULL,
		0xEF85A14F17CE2F59ULL,
		0x52601E6B92EAF38AULL,
		0x7A475D047DB39AFCULL,
		0x9B2F3A9826027A59ULL,
		0xA46A793E6B1B2C9CULL,
		0x22E310F6B01031BCULL,
		0xDF73EEC221070BB4ULL
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
		0xF8BD199C7CE5BAD6ULL,
		0x901ADF6FD4E9B7AAULL,
		0x5BD6D685DD7C470AULL,
		0xEDC5C9A486251B6BULL,
		0x4B3D4C8639780CFDULL,
		0x3BA6C60E741C08EBULL,
		0xA26665A3BB86F4BBULL,
		0xE653191E05171045ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD7A74873427FD7CAULL,
		0x2358765247936CEEULL,
		0x3ADAD83B3281E50BULL,
		0xF68ACEE35F939FE4ULL,
		0xCDD5DAF6DA94B974ULL,
		0x5621D8CA19D9F4BEULL,
		0xCE20F8D5FDC199F4ULL,
		0x0BD1EB83AE4E597DULL
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
		0x808C39A4664ED1FEULL,
		0xFD66F9B7DAC9C928ULL,
		0xFF8AC5A4E26CC7AEULL,
		0xCC74F92219CA352DULL,
		0xFC7C013664CCF80CULL,
		0x7856AFECC555F5F3ULL,
		0x7CF75C50F718BD88ULL,
		0xC1F7E8CBD09E7460ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7731D02B601B40FBULL,
		0x5C9111D617257243ULL,
		0xCC66D1A9828828E7ULL,
		0x522F7913B0EDF4DAULL,
		0x30BE61831CA72C44ULL,
		0x18C936C1A8F2859DULL,
		0x696392FE77F5B366ULL,
		0x1E452747821D1483ULL
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
		0x9416EA81CDB5CB61ULL,
		0x99EA07E76C6655B5ULL,
		0x7381EB1B35B063C4ULL,
		0x09CD79E967C022CAULL,
		0xBD429C0957F570F7ULL,
		0x0684B11C5FB41351ULL,
		0x55FC3EBB6D161274ULL,
		0x233A6808CF71FE08ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE0A4638698F104FFULL,
		0x40291C2B2D2426CAULL,
		0x20400EF5D2EA9C74ULL,
		0xDA1602F0297C0A12ULL,
		0xA79ABB3F6967BA60ULL,
		0xDF3902B3037D1A3FULL,
		0x505448DCDA26BB68ULL,
		0x83C1F0E6E42BC012ULL
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
		0x217B566416056D7CULL,
		0x4BE08CED18010CC2ULL,
		0xC008E099AE6B3BD0ULL,
		0x7AF0123DB94EF252ULL,
		0x9F0D0473F9D0EDA1ULL,
		0x919AF8CF3938E310ULL,
		0x3C5DD1197539F5B1ULL,
		0x6BBE075E183B0085ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x217B566416056D7CULL,
		0x4BE08CED18010CC2ULL,
		0xC008E099AE6B3BD0ULL,
		0x7AF0123DB94EF252ULL,
		0x9F0D0473F9D0EDA1ULL,
		0x919AF8CF3938E310ULL,
		0x3C5DD1197539F5B1ULL,
		0x6BBE075E183B0085ULL
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
		0xB3ECE75780899AD3ULL,
		0x084CB225C4749E31ULL,
		0x0DFC76F9B4484202ULL,
		0xD5037171B7CEEF42ULL,
		0x07F1EECEF75CE5CFULL,
		0x407C1B5D69EA21CBULL,
		0x86EB306B02DD39ADULL,
		0x084E958E858D981CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE65E96E296A2FB88ULL,
		0x52598E28E09AB852ULL,
		0xB7ECE4C0C9DA68B7ULL,
		0x8C9D7DDEA4CAE8B6ULL,
		0x7A920D8A327476CDULL,
		0x121B0CF71215F285ULL,
		0xF1A12321F9DF28B8ULL,
		0xA22C85DE253D74EEULL
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
		0xF9582A947A9CEB6AULL,
		0x393B6E360B0C3529ULL,
		0x24C312D59E637C46ULL,
		0x6D45567A8FF56789ULL,
		0x5DA703C332697AB6ULL,
		0x99D9DDF4699C9FB0ULL,
		0x74FA75BDAECFF299ULL,
		0x594AA7842968C8E0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3CC18EF0D0AB829AULL,
		0x3EDCCA4DB814B038ULL,
		0x7D91751DB6C3881EULL,
		0x264933BDEC612F13ULL,
		0x60016A1396FCB2E1ULL,
		0x084F8EDD85AA7F00ULL,
		0x0546FB2AC0D023A6ULL,
		0xFA4F8AE4DD498B02ULL
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
		0x4805D3C0F4889AE2ULL,
		0x5C6590D52A910745ULL,
		0x0361AFA03A17ADDFULL,
		0x1C0AFF251D8E9C98ULL,
		0x4911E57DBBD9E1F8ULL,
		0xB432A8435A5DFEC9ULL,
		0x8B601B5F26ACF33CULL,
		0xB14559E8CBA8C13FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDB318D2A32E70624ULL,
		0x4065640CECB3FF21ULL,
		0xFF1130234460595AULL,
		0x32D28FABA3B9CD27ULL,
		0x437908C48F800BDEULL,
		0x606ABB61FE489863ULL,
		0x97B83CF1509F3C22ULL,
		0x3EE6457CDFC506D8ULL
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
		0x539F878BAE139B0EULL,
		0x7DD052D140A055D5ULL,
		0xAE6C8185311D8894ULL,
		0xCC13A7C97394BF2FULL,
		0x344406EFCB0E679BULL,
		0x784577A9DDF9293AULL,
		0x5C61FF6E732863E2ULL,
		0x93E23C15434DE043ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x539F878BAE139B0EULL,
		0x7DD052D140A055D5ULL,
		0xAE6C8185311D8894ULL,
		0xCC13A7C97394BF2FULL,
		0x344406EFCB0E679BULL,
		0x784577A9DDF9293AULL,
		0x5C61FF6E732863E2ULL,
		0x93E23C15434DE043ULL
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
		0x5FFF4B35CF506843ULL,
		0xBE4168A7138C72EEULL,
		0x93E1C1B43721CCFFULL,
		0xC0D9724F47021EE3ULL,
		0x2745988782B12850ULL,
		0x469F3826C4D19AC0ULL,
		0x0469AA89B142BC6FULL,
		0x9B62CD15D0BF4620ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x22D66CBD5FFBAF5EULL,
		0xB2728AD23F5A469AULL,
		0x735CBB6A41764A0AULL,
		0xC86F29D5CCD34868ULL,
		0x977AA8984B4A0E43ULL,
		0x6D784A1F3062DED1ULL,
		0x60B3DE729008499CULL,
		0xFF7C52E722C7B222ULL
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
		0x33B44DDA74154215ULL,
		0x5BF52DEFD4944E13ULL,
		0xB976D7D41E925318ULL,
		0x8D271180451AD895ULL,
		0xCB2D46AD56601A88ULL,
		0xCC3C13FF251524F0ULL,
		0x268B88682DB37D30ULL,
		0x41DA76E1C9163792ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA7DA82BCBD65A418ULL,
		0x8C7EAC5F38BDCEDCULL,
		0xD061FF5595EB8481ULL,
		0x36B9DBED22C21E62ULL,
		0x0C03A570BBA1AE77ULL,
		0x6378A95EE054FAC1ULL,
		0xDCEBB65DD783ABEEULL,
		0x594617133FE3DE92ULL
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
		0x713F6BA9C3354B8DULL,
		0x15B2BDF52F6EB5BDULL,
		0xF87E8338BCEE5CBCULL,
		0xBB1A281D84A882C5ULL,
		0x4A5D38580D5491E0ULL,
		0xA25EF2A599828331ULL,
		0xAC581F9113A98E6DULL,
		0xFD8138BAC13AA3D9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBBA2B34E9D302606ULL,
		0xEE2A6F17C9051D37ULL,
		0x5BD4392EAC384F3DULL,
		0xFFA3FAF65D1F5B93ULL,
		0x232E1647920989C8ULL,
		0x57E30DA0F3AF58DDULL,
		0x07CF6D838472802EULL,
		0xA567D8F5ED5F498DULL
	}};
	t = 1;
	printf("Test Case 68\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xCEECE2AD68B33F8BULL,
		0x4A3DF6437A86F1FFULL,
		0x33885BFA78D7CC4AULL,
		0x0E584587795DF6BEULL,
		0x592C0B5CDE81C63CULL,
		0xEED83AE2424C82E2ULL,
		0x9D26CD92BE595A6FULL,
		0xF5EA8E0B0256D37EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCEECE2AD68B33F8BULL,
		0x4A3DF6437A86F1FFULL,
		0x33885BFA78D7CC4AULL,
		0x0E584587795DF6BEULL,
		0x592C0B5CDE81C63CULL,
		0xEED83AE2424C82E2ULL,
		0x9D26CD92BE595A6FULL,
		0xF5EA8E0B0256D37EULL
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
		0x082BC66A02D612E3ULL,
		0x04E5919B2E9B63E2ULL,
		0xD33409F793F6F9D1ULL,
		0x0CCB573909190158ULL,
		0x4B623C28A9B25CA3ULL,
		0xA6C7B0D4DC4D62D5ULL,
		0xD80D56C384CE7AE3ULL,
		0x611F533352073911ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2388CCE194E3E350ULL,
		0x569BE248B8AE87CBULL,
		0x9D51B721E6B6FD40ULL,
		0x12162D10E4C62639ULL,
		0x2B396AEF4238C969ULL,
		0x8EE354BAC7C48FC8ULL,
		0x38A01B1C1EEF7FFCULL,
		0x0002CDE0308DCBE4ULL
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
		0xA65DD1C12A8D150DULL,
		0x6C2BBEDB6A93D89AULL,
		0x7C8D1DFA3799CB67ULL,
		0x76800F940963E915ULL,
		0x15B444114B0114C1ULL,
		0x9675B257245CE07CULL,
		0x981CD7C11CA48E7EULL,
		0x1B9C66285E06D982ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8E746FC45C2706AAULL,
		0x9A80B28D98D46955ULL,
		0x22FA8B26DDDD47E2ULL,
		0x66527230C87BFDBDULL,
		0x7EA95E3DA89336E6ULL,
		0xF5799A2492AF4770ULL,
		0x39EC0CD402987F25ULL,
		0x75029D53A6601CB8ULL
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
		0x08EBC70BA14585BDULL,
		0x107B9F56FE78DCDEULL,
		0xBCFC1BD3B10A797EULL,
		0x148C1E78450C7286ULL,
		0x7456808BECF275DEULL,
		0x190085147B6D44C6ULL,
		0x781AAB18B4390D75ULL,
		0x16B7C687D6545FDBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCBE294483EBF4BDFULL,
		0x991DD888173CF84BULL,
		0x4FEC13FCDE82FE35ULL,
		0x764A126DD988584BULL,
		0x1DA3F6EE9713F3F8ULL,
		0xDC60DDE14C5EFDCAULL,
		0x2FFDE96E847658D0ULL,
		0xFCEB541963271FE2ULL
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
		0x56AF2BD4E73AC65AULL,
		0x43CD255D6E3E3B18ULL,
		0x5474F9A8A96AEE48ULL,
		0x191F75D7EFECC130ULL,
		0xD143108619C97BDCULL,
		0xF1D93931D7EBB976ULL,
		0xC08E18C284FBE958ULL,
		0x0F34365F61A910E7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x56AF2BD4E73AC65AULL,
		0x43CD255D6E3E3B18ULL,
		0x5474F9A8A96AEE48ULL,
		0x191F75D7EFECC130ULL,
		0xD143108619C97BDCULL,
		0xF1D93931D7EBB976ULL,
		0xC08E18C284FBE958ULL,
		0x0F34365F61A910E7ULL
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
		0x925A157EAA8BD8C9ULL,
		0x5FDA2312877FB03CULL,
		0x586598DC830C0599ULL,
		0xA519CE6D3FF291C9ULL,
		0x52F2A36BF5A714FFULL,
		0x8C50007D34CC69A7ULL,
		0x6ECE72B44D15CACAULL,
		0x3A3B25A8950223A7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1575935540339ED8ULL,
		0x9C0F961F43861C58ULL,
		0xE5A744DEE82449E1ULL,
		0xD3E16FF8727F9E03ULL,
		0xA69263BA4E51665BULL,
		0x4412359683C6083AULL,
		0x4DE94C4A0C94B120ULL,
		0x33951E52EB382962ULL
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
		0xC7E757A72E060C79ULL,
		0xE85465C8D462BD56ULL,
		0x21C4DC6D670B4CF2ULL,
		0xF0936A4EE2F9CD80ULL,
		0xFA39A089877A5BC7ULL,
		0x3B3CD07A9B972E2EULL,
		0x077A139476466149ULL,
		0xEFD8B81E3A0DEE93ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB661E4FE87BF4E47ULL,
		0x9E135825D47AAA7EULL,
		0xF061FD1504F56EFFULL,
		0x310E1E69BBB66888ULL,
		0xF0CF9849EFCEC6D7ULL,
		0x71279E4961AC90A6ULL,
		0xCA7FB8786EB5D9DFULL,
		0x09143154267FA873ULL
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
		0x484DC35A2A96FF6FULL,
		0xF25C9B8F60774C5DULL,
		0x47A39C689259C92EULL,
		0x2AC6F1099FACF3CBULL,
		0xFA5DE0737DCBDD87ULL,
		0x54FAFDC1268575F2ULL,
		0xFD61CBC52BCBE6A0ULL,
		0x5B37D25B92F5D0ACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x95CF5F00751A133BULL,
		0xE3A86B82FEA03271ULL,
		0x6FE0497B9AC4AC8FULL,
		0xD6FDE5799DF67381ULL,
		0xEEEC7DBE11C33DB1ULL,
		0x716868E962BD5706ULL,
		0xE8F3A39ABF902BD6ULL,
		0x90CDA95C3E5779ACULL
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
		0x7867D6C11F37B814ULL,
		0x7950D5569FB8696EULL,
		0x6BCE16E2B9484320ULL,
		0x44F509080FF3CD71ULL,
		0x5E6EAE2CE5C53660ULL,
		0xFC924A273F818E8FULL,
		0x22C77E089FDC2DCBULL,
		0x127DEA32B432EACBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7867D6C11F37B814ULL,
		0x7950D5569FB8696EULL,
		0x6BCE16E2B9484320ULL,
		0x44F509080FF3CD71ULL,
		0x5E6EAE2CE5C53660ULL,
		0xFC924A273F818E8FULL,
		0x22C77E089FDC2DCBULL,
		0x127DEA32B432EACBULL
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
		0x1301E84BFA9DF1DEULL,
		0x63006E3236120B6FULL,
		0xBA6FFDEC14364214ULL,
		0x9A4A26F2D9514F2CULL,
		0x148727082635BF55ULL,
		0x7DF8EB3D9A7557C1ULL,
		0xE19AD1FA488343B2ULL,
		0x18BF07470C6DC8E3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF3B3BCEBD6AE5C27ULL,
		0x7FA9C9DAFBEE04C3ULL,
		0xE3E41BF69EDDD204ULL,
		0x01D66DBFC342396BULL,
		0xBD902B1439416FD5ULL,
		0xD87E7B7A066ABBCBULL,
		0x5BBEB19E6A5B83F7ULL,
		0xC0B52BD93DD2BC9CULL
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
		0x790D256F53B07C39ULL,
		0xAB12B24A3DA1E5CBULL,
		0xFC142875B75CB5BEULL,
		0xD8C28FFAD0C27DB4ULL,
		0x7AF762E809086978ULL,
		0xDC46AA7EE213722FULL,
		0xB762ECC7BDAB8A6EULL,
		0xB74F25E7115722EAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8D5B9207D2928778ULL,
		0xAA4D71B7897061B1ULL,
		0xDE9A9B3F917625D0ULL,
		0x27BFE7361C0AF5C9ULL,
		0x9CF0B302E0F115D7ULL,
		0x4106AEA56F0D4122ULL,
		0x2A7EA2E16FF95BD3ULL,
		0x76F13099B58B1331ULL
	}};
	t = 1;
	printf("Test Case 79\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x734898B1044B52DDULL,
		0xBADAA04659EDD308ULL,
		0xBC210197FD7F0356ULL,
		0xD16873DB04948877ULL,
		0x3F9BE866926787D0ULL,
		0xF68F3595A97EBA98ULL,
		0x4DD0C2557F71E88DULL,
		0x0FAE9A65577C5944ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1C27102885DA1D61ULL,
		0x51D80FE53BDB0C42ULL,
		0x7E5FCE808526A41EULL,
		0x94489D375957A2BAULL,
		0x32EF5F9E58E9A0AEULL,
		0xD1FB0DFA1B7E0864ULL,
		0x65096B2D0177EC0EULL,
		0x3451B9054B4794C9ULL
	}};
	t = -1;
	printf("Test Case 80\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x8C1B3B77F8A48EB1ULL,
		0xB701D09C1DE7AC8DULL,
		0xB16298B02AE2C7F3ULL,
		0x50BC0FCB1C9DED2AULL,
		0xAB24F9CD8F29E564ULL,
		0xF47190DE899D2C46ULL,
		0x207781A971D45F8AULL,
		0x2CE00B64182FF95EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8C1B3B77F8A48EB1ULL,
		0xB701D09C1DE7AC8DULL,
		0xB16298B02AE2C7F3ULL,
		0x50BC0FCB1C9DED2AULL,
		0xAB24F9CD8F29E564ULL,
		0xF47190DE899D2C46ULL,
		0x207781A971D45F8AULL,
		0x2CE00B64182FF95EULL
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
		0xD1D87AE0F2E69C3AULL,
		0xD7510F0CE0791F3FULL,
		0xF08EB5AF85E09A32ULL,
		0xBE2F53939DBB1EC6ULL,
		0xF4C3330EF94CAA58ULL,
		0x8DE3168FB608C390ULL,
		0x99A40D7B28FB6BDDULL,
		0xEF196CB88A15DFDAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF7646BF5F7AE1540ULL,
		0xCEFE513120D127E0ULL,
		0xE002CD138DAB3EBEULL,
		0x2847028CB16448E4ULL,
		0xF2356DC334D5BBA4ULL,
		0x9B537FE5BA3F74ADULL,
		0x2654CC85114894A9ULL,
		0xA0E3C85B7B57B1BEULL
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
		0x7D42DCE2B8071406ULL,
		0x5E2E59166C363661ULL,
		0xC11FCEC226835195ULL,
		0x9DD501AB45BCD7E9ULL,
		0x7D3C29939570E05CULL,
		0x39DFA1CB1FADDEFDULL,
		0x9B0F90B8858F6B33ULL,
		0x5D000DBB7828110EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4608EE6AB47B6923ULL,
		0x4AFD99EF5D146135ULL,
		0xF336F560A051D9DBULL,
		0x6153346DB64E2B28ULL,
		0xB5AF98380AD312A2ULL,
		0xB255B8969F8A110AULL,
		0x217C6B5CC43F2A09ULL,
		0x214C8C6F6D694C3CULL
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
		0x633078FAB43810DBULL,
		0x3B60EFBDF9F22C59ULL,
		0xE5BFCC6D80A81027ULL,
		0x59650756FB1CFA0FULL,
		0x97535E446BB389A4ULL,
		0x72A92E3B2682945DULL,
		0x710A4CC696D3C048ULL,
		0x7C7E008C804C0022ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x61D23CFCFFFE298DULL,
		0x34E4AC8D8CEEA463ULL,
		0x0B570DF7F3C09213ULL,
		0x824A276B598F5DA0ULL,
		0xD331CF856E30326AULL,
		0xAC32C012000B769AULL,
		0x8710526D5627CD2DULL,
		0x29922DD4C84470DAULL
	}};
	t = 1;
	printf("Test Case 84\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x23350C3AED189976ULL,
		0x43C4216FA7D2E6C7ULL,
		0x7BB54B84A1E5DE91ULL,
		0x83B26C2150C15F7CULL,
		0xBEAA5BA237B46680ULL,
		0x361509DFA6A445AAULL,
		0x8C63D4C7D6EAA0C3ULL,
		0xB4AB955225546096ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x23350C3AED189976ULL,
		0x43C4216FA7D2E6C7ULL,
		0x7BB54B84A1E5DE91ULL,
		0x83B26C2150C15F7CULL,
		0xBEAA5BA237B46680ULL,
		0x361509DFA6A445AAULL,
		0x8C63D4C7D6EAA0C3ULL,
		0xB4AB955225546096ULL
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
		0xC8ECF4757CDA5F0AULL,
		0x855B842172FA90A4ULL,
		0x3B570CD81431F5F7ULL,
		0x555787345841A7B0ULL,
		0xADF4CE94CC4A3341ULL,
		0x6D6B232FC276D1B7ULL,
		0xBFB6BCCF915BAEACULL,
		0x8920B98D88EEC5C8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7FDD9C1A656A4057ULL,
		0x60E179F322FBD983ULL,
		0xB8B488A02E728649ULL,
		0xC94070557A7ECC9FULL,
		0x8830DE14685D153DULL,
		0x67B59A28A80A3DEAULL,
		0xF06331D24EFAE2ACULL,
		0xF7EE1D7F07815CC6ULL
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
		0xE289FA480B79AF85ULL,
		0x53ED1E400A6C381EULL,
		0xC078CA844DCCD6BFULL,
		0xB3EAD57C07718184ULL,
		0xEFBBE6D6FA84DF06ULL,
		0x41DAA8F108CC7D72ULL,
		0x21E0FDC36D1F45B4ULL,
		0x5266DB21D973BB02ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x12280EA26839DC15ULL,
		0x5CC3866D636E0C10ULL,
		0xCCC639B2647CEC24ULL,
		0xFE162B8191B92850ULL,
		0xC9BD7521581A43B6ULL,
		0xB8E18966C191E9D8ULL,
		0x0D2E01FBD23DA960ULL,
		0x26AFB5DDAED03014ULL
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
		0xF115A52F4D0B467EULL,
		0xA222686440F18B23ULL,
		0xA744302A7E57E1D4ULL,
		0x20FB063712C51C39ULL,
		0x458A9C1D25C92DDEULL,
		0x52027B84CA116611ULL,
		0xF59AE4FD2CF7C956ULL,
		0x0342463D99C9A2C4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6507C55DBBF1EBE6ULL,
		0xAEC82BE7EAA806CAULL,
		0x1C55FD7460FF61C0ULL,
		0xFDED6B2822D11634ULL,
		0x2DB16E5765465B87ULL,
		0xD483063BE6FA0D9CULL,
		0xB73A7271EB1B7602ULL,
		0xFB64A6354DE45D52ULL
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
		0xB45CA0238509F060ULL,
		0x9FEE28C6E83B8DA1ULL,
		0xC518DA9D0F27D2B1ULL,
		0x1E8330D3895BCA1DULL,
		0xA6239656FE9A3484ULL,
		0x768B27927D087764ULL,
		0x6982B28A27840D86ULL,
		0xEE1685032FD47F37ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB45CA0238509F060ULL,
		0x9FEE28C6E83B8DA1ULL,
		0xC518DA9D0F27D2B1ULL,
		0x1E8330D3895BCA1DULL,
		0xA6239656FE9A3484ULL,
		0x768B27927D087764ULL,
		0x6982B28A27840D86ULL,
		0xEE1685032FD47F37ULL
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
		0x9792A67FDF6F6543ULL,
		0x81C5614012F0B3E1ULL,
		0x69DF789FE9D70CBDULL,
		0xD2538CDB5715DF9BULL,
		0x83FF406CB2149F19ULL,
		0xA053B5BECAE33A2EULL,
		0x2CBA601B0769709CULL,
		0x27BAA5E9565CA4DBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDC9CD4BC8A5E7D47ULL,
		0xE9AF9D561B999AB5ULL,
		0xC391173B646273DCULL,
		0x3F5E881133B083A6ULL,
		0x7F9DC06001F1B46FULL,
		0xEEF61AC004319650ULL,
		0x206B7933A27741E4ULL,
		0x1FCCDCE4BDE29ADCULL
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
		0x8B190A10D7DF91D1ULL,
		0xBF7C7A4957AA27C9ULL,
		0xA81D973353D9510CULL,
		0x8F13AD284D7D7BA1ULL,
		0x92B70548FE962FACULL,
		0xB91A17466A2251F3ULL,
		0xB72D37EFB1538A1AULL,
		0x1FFD98BC70439F01ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE3DFEC2F13DBDAAAULL,
		0x16E6745588E9A00DULL,
		0x0959E5AC7995199BULL,
		0x64CC7D6855F4CDA4ULL,
		0xD9A920AE2A34FBA9ULL,
		0x89EF722920E71B6AULL,
		0x2E7259A344D1F572ULL,
		0xD2E452259199666DULL
	}};
	t = -1;
	printf("Test Case 91\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x6BD147FD2E7D076EULL,
		0x97E837369ED83BE8ULL,
		0xEB68A4B189F8BBC4ULL,
		0x01645A436E95584AULL,
		0x2D30C4B69F909929ULL,
		0x822D336CF10B6CCBULL,
		0x080D31EADAD3F1AFULL,
		0xB8F66F00B60C319EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE6D45E35D0CCE957ULL,
		0xF02416970610FDEDULL,
		0x919AE4C95C8555A4ULL,
		0x87706713C5CF989CULL,
		0x51B7ED1A0C311AD6ULL,
		0x5991FD5B950567E0ULL,
		0x8FE774D6FD42524AULL,
		0x8EF8AC0DE64A5BFEULL
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
		0x1A06A40A9123D79EULL,
		0x00A81F0AA47C91A8ULL,
		0x902A42241FE45236ULL,
		0x6A56660B719233B3ULL,
		0x3935CB070F977E0AULL,
		0x571B62A2BC7804EFULL,
		0x38620343AF0357D2ULL,
		0xB5742E252DFC81E0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1A06A40A9123D79EULL,
		0x00A81F0AA47C91A8ULL,
		0x902A42241FE45236ULL,
		0x6A56660B719233B3ULL,
		0x3935CB070F977E0AULL,
		0x571B62A2BC7804EFULL,
		0x38620343AF0357D2ULL,
		0xB5742E252DFC81E0ULL
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
		0x097B802DD266271EULL,
		0xE5D40093934499DBULL,
		0xB7CEF338C43AD5B6ULL,
		0x670AE260990FC178ULL,
		0x03708421BF712080ULL,
		0xCD687FF635881764ULL,
		0xB0FEE6E1285134B4ULL,
		0x383FFA490F753FC1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEFA9E313BE59A9CBULL,
		0xEF281B491F7BB2C8ULL,
		0x45F067E1B8609E77ULL,
		0x93D81DC87D523DBCULL,
		0x3B07431330A9E86AULL,
		0x4C0099959D008417ULL,
		0x45AB3CDE6D5790F7ULL,
		0x7C485D29621D862DULL
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
		0xFB4F32C3396DB1D8ULL,
		0x418C57777E83810FULL,
		0xFC3C6B2B2C0C13AFULL,
		0x2303C1137C655E60ULL,
		0x038F980433500EDBULL,
		0xCFE7EAECD9C8F97BULL,
		0x7DB7E20EA87E7BD3ULL,
		0x61EB053DC50BF6C7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x58FDFDE0F99C7F18ULL,
		0x3244861EFCD7BB1DULL,
		0xB64673E1B34C560FULL,
		0xFA106E087AB2DA6CULL,
		0x65D58D1C45E7E823ULL,
		0xB5558D2A85471CBDULL,
		0xA6ACC3C1F083735CULL,
		0x5F01617A444A308BULL
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
		0xF605F44F838C2BECULL,
		0xC6EE08D235A0E430ULL,
		0xE1363940F313C83FULL,
		0x5043F9AAF65F9008ULL,
		0x3A8209ED7DBAD639ULL,
		0xE5C3D52E236D18C6ULL,
		0xDE765C3A8A9C1E6DULL,
		0x9F0653B0A649E452ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1AFED4E3A6CA96EEULL,
		0x48217986CA53EB16ULL,
		0xE575A602715F4DC1ULL,
		0x10CE972B47D3E689ULL,
		0xD0904D0EFDF29E3EULL,
		0x2E8F2CEA8086ECD2ULL,
		0x6A8CF230A0310E6CULL,
		0x27065343604F4974ULL
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
		0xD2B59E54D7FF7D06ULL,
		0x4C56DE40EEC14507ULL,
		0x112F78A428467DF1ULL,
		0xD9F3669D42957AE1ULL,
		0xE0008FADFDD574B7ULL,
		0x7FCBB2E1C1CAFD55ULL,
		0x8396FB0C67DFD7BEULL,
		0x2683351F0E29FA43ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD2B59E54D7FF7D06ULL,
		0x4C56DE40EEC14507ULL,
		0x112F78A428467DF1ULL,
		0xD9F3669D42957AE1ULL,
		0xE0008FADFDD574B7ULL,
		0x7FCBB2E1C1CAFD55ULL,
		0x8396FB0C67DFD7BEULL,
		0x2683351F0E29FA43ULL
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
		0xD99392DC67D45C56ULL,
		0x1F72C0AA70242006ULL,
		0x56E56F8782B2783DULL,
		0x4DDF724634E2CB82ULL,
		0xA361FC077ED9BCBAULL,
		0x0E967215F530391BULL,
		0x91534EDBE24BE3C6ULL,
		0x65234B65237FC125ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDB569D1C9A373D76ULL,
		0x69D06515DCAFC5AFULL,
		0x6BB4085172D19FD4ULL,
		0xBDD884DC22C28070ULL,
		0x989086218E329A55ULL,
		0x9E4845340D838505ULL,
		0x1E3E5F0A25F51AF6ULL,
		0x669A044704CFD87BULL
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
		0xD487DAD5DA63C84FULL,
		0xF8F0A602A1D1AA7AULL,
		0x110571BA2285D2EDULL,
		0x5FEA4075BB3E0A66ULL,
		0x6DBE38F90CE20F85ULL,
		0xE9650DC2F1740035ULL,
		0xAC18D066EBE8BCBFULL,
		0x5F90FD91FCD10648ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x31968E0129D1436CULL,
		0x0D76B534D092DB28ULL,
		0xD0AB0D235C3C3749ULL,
		0x6106FB20903FB858ULL,
		0x26262C8C9A48A0B4ULL,
		0x57AD83D984673B04ULL,
		0xEFCD5BDF137FFD78ULL,
		0xDEEFB423AF95ED9DULL
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
		0x7D12D1721EFB6608ULL,
		0xF1128B46C17AF6E4ULL,
		0x2DC156A15364E5DAULL,
		0xDCA87434BD847C86ULL,
		0x56B6B3C62EA82AC7ULL,
		0x6DC9A93463F0C292ULL,
		0x5A7265DBD0E2E229ULL,
		0x54D3B11A45D812DEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x89A2F01532D03A67ULL,
		0x522DB0AFA95E2A12ULL,
		0x1F164A49BF1DE5F0ULL,
		0x1E72C130698D6F5FULL,
		0xABBC67CA302F6ACCULL,
		0x29495A5C37B0768BULL,
		0x87A8A90EE816BDCEULL,
		0x71D2C96360A3A17AULL
	}};
	t = -1;
	printf("Test Case 100\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xC759F61A77E200A4ULL,
		0x8ACBA9CA6936922EULL,
		0xAB146B07A47DD420ULL,
		0x50BECE85D13E7B89ULL,
		0xC5B7B545AF5ED7D5ULL,
		0x6AB3C394895B091AULL,
		0x29652261E704F053ULL,
		0xF5FD7F01C6D94D1CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC759F61A77E200A4ULL,
		0x8ACBA9CA6936922EULL,
		0xAB146B07A47DD420ULL,
		0x50BECE85D13E7B89ULL,
		0xC5B7B545AF5ED7D5ULL,
		0x6AB3C394895B091AULL,
		0x29652261E704F053ULL,
		0xF5FD7F01C6D94D1CULL
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
		0xEBD593FC4097CACEULL,
		0xC007746885D67389ULL,
		0x809354DC493DD55FULL,
		0x45F503905608D398ULL,
		0x8D3712ECBB7F83DCULL,
		0xCC2FB0F0B7BBF1ACULL,
		0xED0E8E76890E4965ULL,
		0xBEA6C2A61D7616B9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEE0466FBB7D2DDCEULL,
		0x7D5ADF73B5D4C775ULL,
		0x27D71A570A76C209ULL,
		0xA35BA5C33ED323D4ULL,
		0xB98496E3607ABD49ULL,
		0x21219573B7F712E6ULL,
		0x20CFA6141239A253ULL,
		0x2D3BCB6C7B247A42ULL
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
		0xB9D428D4A7AAC474ULL,
		0x9A6251F98259C784ULL,
		0x52FC2733D29205B5ULL,
		0x98288A33144E536FULL,
		0x90B57F8F2282728DULL,
		0xC5F9E1631A1901FDULL,
		0x851F1620457C4753ULL,
		0x5D38B5671DD7717CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8A29CF18F3B36AD0ULL,
		0xD1106717E09745A6ULL,
		0x034A5E7D51D97C2BULL,
		0x6B2ED2F992CAA67BULL,
		0xD08A05A86DED88A5ULL,
		0x83160E79F3B632FDULL,
		0xDFBCC744122BA1ABULL,
		0xFC9DDBB7765E71D7ULL
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
		0xA403BA8253DDCE20ULL,
		0x0E0AE1FCD0695342ULL,
		0x8F66983690439883ULL,
		0x8C173AEC308BBE76ULL,
		0x7E0160A7DE28EB35ULL,
		0x01BFB6CE41CDF57CULL,
		0xEA80E90B338BDB16ULL,
		0x4195152D78170F16ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x03C39B5A6DA914EAULL,
		0x847436E6CE8BF4B9ULL,
		0x1492587995EB6720ULL,
		0x619EE0E7C978FBD8ULL,
		0x5D5AA6A8B2887760ULL,
		0xCDE0ACBAE9E79493ULL,
		0x75A508FD68C03E17ULL,
		0x5B77858CBFC3DA6FULL
	}};
	t = -1;
	printf("Test Case 104\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xCAE4B9CE45CBDC13ULL,
		0x9773DA9AD173C90AULL,
		0xDC977571566C1E14ULL,
		0xCC208481DAC3B8A1ULL,
		0xD396517935C1E031ULL,
		0xB2D6B9D82065D780ULL,
		0xC4B74D38E6A398BCULL,
		0xCD5CB8539B448D9CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCAE4B9CE45CBDC13ULL,
		0x9773DA9AD173C90AULL,
		0xDC977571566C1E14ULL,
		0xCC208481DAC3B8A1ULL,
		0xD396517935C1E031ULL,
		0xB2D6B9D82065D780ULL,
		0xC4B74D38E6A398BCULL,
		0xCD5CB8539B448D9CULL
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
		0xF41F6191F74E28A9ULL,
		0xA2D5C5C899050ECCULL,
		0x27C137B7D4DC88C5ULL,
		0xE3E92DA35C518F68ULL,
		0x2E1C899377BCC751ULL,
		0xFBFCDB025139D363ULL,
		0xB970206E83EA2040ULL,
		0x60BDE94E1D230191ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB5C4080FAA83DD7CULL,
		0x713E46B1B5084EAAULL,
		0xF699D3CFF57333BCULL,
		0x4E270ADC53DF6A94ULL,
		0xCECC354DED577589ULL,
		0x5AAEF67D0820BCEAULL,
		0x12398DBC7315DA94ULL,
		0x0890E907718754C6ULL
	}};
	t = 1;
	printf("Test Case 106\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xAC5D228398449E60ULL,
		0xC4A146C38D331D3AULL,
		0x357E9533DF9BFC51ULL,
		0xE55A5BC4C9908E64ULL,
		0x3F43DDE9334EA325ULL,
		0x026A63894D220330ULL,
		0x6B35703A7902403AULL,
		0x47FA2071C0EE948FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2B40747EF5050F7AULL,
		0x71C6308B74F4752CULL,
		0x99915F2C716E9E1BULL,
		0xA0C05951AE55FDBCULL,
		0xCCB0E91AD324423AULL,
		0xA8B4951FB07F4978ULL,
		0x39099AFE8D30932DULL,
		0x6C05EF8EC9CE8D02ULL
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
		0xA8624033DE038123ULL,
		0xF27160803AABEED7ULL,
		0x489915B00998E573ULL,
		0x391CFAAB64D05776ULL,
		0x649393E813226690ULL,
		0xAF434AFBC17AE37CULL,
		0x59D04462D82EC936ULL,
		0x76DB20A30B4F04C6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5A6AADA8BB6096EDULL,
		0xE32A719B59CB5F6DULL,
		0x10AFA3C9D907A40EULL,
		0x9218EC5395CF86ADULL,
		0x808C8D5836EADE10ULL,
		0x3A841B4E858E55B6ULL,
		0xB7C8FA30644E818CULL,
		0xD3F05D7FEAFB428FULL
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
		0xA5331646910B947AULL,
		0x81817B3EDF481605ULL,
		0x3BBEC1094A4BC69CULL,
		0xD1FE1D6C781FE68CULL,
		0x26C25152C54B4330ULL,
		0xBD00B67D2D3FF546ULL,
		0x1267E76DD056D44DULL,
		0x13272CB57907F4B9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA5331646910B947AULL,
		0x81817B3EDF481605ULL,
		0x3BBEC1094A4BC69CULL,
		0xD1FE1D6C781FE68CULL,
		0x26C25152C54B4330ULL,
		0xBD00B67D2D3FF546ULL,
		0x1267E76DD056D44DULL,
		0x13272CB57907F4B9ULL
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
		0x3D9E910562D5839FULL,
		0x7EAF231E09C6A9C4ULL,
		0x097C27212B71CA52ULL,
		0x0A16CD5DAE1C6E85ULL,
		0x7B7BD60C73F6543BULL,
		0xE8A05DB05BCED734ULL,
		0xA8711EB52B0081B6ULL,
		0x8DED7BAD12E709A6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC245A20095E4B3F5ULL,
		0xE133B00DB1E3C11AULL,
		0xAFD10AC10897A964ULL,
		0x9295B1F5CC029E25ULL,
		0x9B1DFD73FDB8A873ULL,
		0x1E3283BC24B648D6ULL,
		0x7923B59077807D31ULL,
		0x11715B534A0D5617ULL
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
		0xA45FA98C70DF32F0ULL,
		0xEDF5CA9C4347B5B7ULL,
		0xA385379553EB0805ULL,
		0xBC68A21BF828DA99ULL,
		0x992C69764514C581ULL,
		0x42AEFAFEF9AB4E63ULL,
		0xA0DE99B4EAF54145ULL,
		0x2A934768B6E88D55ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xED3C31F307F5C9DBULL,
		0xB394D67143502DFAULL,
		0xD7B00AC0D29A0DB0ULL,
		0xF6BFE49AC1980E10ULL,
		0x304D6D91AE4C6DB3ULL,
		0x7C05C38E1FE92F49ULL,
		0x71F699D92F747B97ULL,
		0x2A9D1932F116EE59ULL
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
		0xA8E199D37FE759ADULL,
		0xA01ACC56FC129C9AULL,
		0x6C38D7C94BAD5CA5ULL,
		0x1CB85C46837841E7ULL,
		0xE135B444AE63624AULL,
		0x845713227ACC928BULL,
		0x14BA0FCD1CC8151EULL,
		0xA36CB0BB8C2ABDE3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2427219BBF3EB4D4ULL,
		0xE9807CABD0B0C698ULL,
		0xA340ABB442857380ULL,
		0x50AF619E5D7A082AULL,
		0x257D2206A8066042ULL,
		0x98B0F125075F65E7ULL,
		0x84CA1F18E7B7A8CAULL,
		0x7068E42C9B096D0CULL
	}};
	t = 1;
	printf("Test Case 112\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x2FEB13266339EB05ULL,
		0x3D8D73AA0CB34277ULL,
		0x3DFC268337F15727ULL,
		0x50CCC87D2D7144F3ULL,
		0x32C7AB18C0BB5430ULL,
		0x8EDA0F73C227F3C3ULL,
		0xD29D114B31E38F20ULL,
		0xF1040C7ED7483EA7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2FEB13266339EB05ULL,
		0x3D8D73AA0CB34277ULL,
		0x3DFC268337F15727ULL,
		0x50CCC87D2D7144F3ULL,
		0x32C7AB18C0BB5430ULL,
		0x8EDA0F73C227F3C3ULL,
		0xD29D114B31E38F20ULL,
		0xF1040C7ED7483EA7ULL
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
		0xBE482D771364A89EULL,
		0x110DDDC5A56CD2F9ULL,
		0x74220A0A6D07F992ULL,
		0x55F73CEAB1020AB4ULL,
		0xDFF27ADE821B6A83ULL,
		0x1DA0D086AECADC63ULL,
		0x2B7EFD72E2291169ULL,
		0xCDFEF2043F02610EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x55FBA214C21CD878ULL,
		0x34301A615221438DULL,
		0x22CABC5F46474C2DULL,
		0x3997ACE2B50664DBULL,
		0xDA0C3227FC0A46B0ULL,
		0xBFBA00FBD9031BA2ULL,
		0x3463CAFDC6816DE7ULL,
		0xF524051E9F05B2D9ULL
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
		0x1F92A7C8A4281D99ULL,
		0x2A1D6103306CBC13ULL,
		0x31E56B2D39DF5764ULL,
		0xCE9D7C9F76C79DA2ULL,
		0x795762A8E24BCD70ULL,
		0x2D6B46F5B3C335E3ULL,
		0xB06C7EFC58202438ULL,
		0xBEB3B4D671383FF1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9D36D4BD0F99C497ULL,
		0x45354FC5D8A9BA82ULL,
		0x0B2BD8DAB4F72280ULL,
		0xDA35B5A949521411ULL,
		0x966C2B0B9AE826F7ULL,
		0x62DEE5F8220623FBULL,
		0x133F33B35544C439ULL,
		0x018C92525814D0DBULL
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
		0x02872198CA9D4C02ULL,
		0x4E26FD605F8BAA26ULL,
		0x774E66C4B857AF8EULL,
		0x231E80C279ECA8E9ULL,
		0x650FC0EA538BF6EEULL,
		0x354D58F4E265517CULL,
		0x924FA35C48CF9933ULL,
		0x99A0A952CC127D7CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD85EC72C30DF569CULL,
		0x6F5DB52264EABE09ULL,
		0x151BF68086A19786ULL,
		0x18A4371EDCDC8944ULL,
		0x7F600D30558311B6ULL,
		0xBB723914924D6588ULL,
		0x2FA5A93EDDE32AC9ULL,
		0xE0176061B3CE6C13ULL
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
		0x25A63BB163BB0752ULL,
		0x6B9C712A143EB6ABULL,
		0xFA5E9C28A2600A96ULL,
		0xF245D21F2C585F8FULL,
		0x06504E13DDAB3CB9ULL,
		0x672A367D04E515F8ULL,
		0xB05020DB8F474CE2ULL,
		0xBFE24B5DC7B5E0C2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x25A63BB163BB0752ULL,
		0x6B9C712A143EB6ABULL,
		0xFA5E9C28A2600A96ULL,
		0xF245D21F2C585F8FULL,
		0x06504E13DDAB3CB9ULL,
		0x672A367D04E515F8ULL,
		0xB05020DB8F474CE2ULL,
		0xBFE24B5DC7B5E0C2ULL
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
		0xD74C7C4C7502B33CULL,
		0x4900707E3A0CC335ULL,
		0xE5233D077D2F6EC7ULL,
		0xDEE3F6A261D40188ULL,
		0xCAC7F919D9638D27ULL,
		0x8B19EA4EEF25AE1BULL,
		0x127EC832AC1F9C71ULL,
		0xD61BA4D534DE649BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC9F6875C2E1230FDULL,
		0xB71BCC8FC4843D72ULL,
		0xC66F16A147CAFD73ULL,
		0x504C261B170F4019ULL,
		0x6C282348260597AFULL,
		0x01893420D4F6E64CULL,
		0xD386DDECEFECAA80ULL,
		0x1D8297A606E2954DULL
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
		0x9F73160F669CC431ULL,
		0x92B0635B3C967FC4ULL,
		0x7AF246C9282E4524ULL,
		0x6C7FCA8BDDAE0F82ULL,
		0x2A4316AEEC2D5147ULL,
		0x1D0FFB82320A9073ULL,
		0x31327F48645DF941ULL,
		0xE950F523CBB4A516ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB53FFE0055BB467ULL,
		0x39EC8D21B10DAF22ULL,
		0x63039A478FF9F1C4ULL,
		0xCE5FEC0972893E66ULL,
		0x64F972FDB47C10C7ULL,
		0x84DB243D0CBD6B70ULL,
		0x448B1CC6EA8D5999ULL,
		0x40245BCE97AFFC3CULL
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
		0xD03F4EA32129B757ULL,
		0x9C9DC26C94570631ULL,
		0x984EC8506B1DA7D7ULL,
		0xFE35FB2FA0EAD978ULL,
		0x1E15600D4961E265ULL,
		0x8FE0BCBF2319FB84ULL,
		0xD1D59EFE3B84A257ULL,
		0x2A754CB59F789DEBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x68800C2702B23598ULL,
		0x05F1A374D45D1D3BULL,
		0x1EE37020A27700AEULL,
		0x9B63B767EECE7369ULL,
		0xF543437325486912ULL,
		0xA6EDA812518BC6F0ULL,
		0xFD3B7FE894DD26A1ULL,
		0x7295C4536EC2B2C1ULL
	}};
	t = -1;
	printf("Test Case 120\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x634C62635939806EULL,
		0x57B65A9A0DEA8D3CULL,
		0x28513A9CAC89CF7DULL,
		0x5F95295160744A0FULL,
		0x89BE401DD9F95203ULL,
		0x3EC9DF5AE14407EBULL,
		0xFE016390FBA9D8DDULL,
		0x6C03E693D9020E12ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x634C62635939806EULL,
		0x57B65A9A0DEA8D3CULL,
		0x28513A9CAC89CF7DULL,
		0x5F95295160744A0FULL,
		0x89BE401DD9F95203ULL,
		0x3EC9DF5AE14407EBULL,
		0xFE016390FBA9D8DDULL,
		0x6C03E693D9020E12ULL
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
		0xCDD5D36D82A04039ULL,
		0x769E6C7E8F2852CFULL,
		0xF88F001B69895B1FULL,
		0xFD17413DB0983121ULL,
		0x6E7DB588377D164AULL,
		0x3E523C587C73F279ULL,
		0x82210B1E0F5454B2ULL,
		0x273228B3AF068EFFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA6FF6840D139B8F0ULL,
		0xB4D343C4570ACD48ULL,
		0xA48446FE9C71AC2AULL,
		0x793D05A4871F0513ULL,
		0x9195081427131685ULL,
		0x42D8EFB43BEC4091ULL,
		0x6665A9A7C9A50BC3ULL,
		0x3B0879B4BFED7EA9ULL
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
		0xF83AD3987F65BAECULL,
		0x9CE90DB8AFD731E4ULL,
		0xA7F1105551D913D8ULL,
		0x64F424C9D7D866CFULL,
		0x3C266FDA1864D002ULL,
		0x0CB98EBB3B22BC93ULL,
		0x5FD85833C489981EULL,
		0x3B767D7678904882ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFFA543748C09D8C5ULL,
		0x31308C6E4958F1D3ULL,
		0x7A0A759B3A26FB85ULL,
		0x977D25276E6BB492ULL,
		0xD65318A0D3581143ULL,
		0xDA5C71F203FBE2D9ULL,
		0xB105545AAB781923ULL,
		0x1C0DFD7273B8D982ULL
	}};
	t = 1;
	printf("Test Case 123\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x9BF8341AF009EEC9ULL,
		0x2D129421B2DEF6A7ULL,
		0x0C5C3DC223D60B78ULL,
		0xBC439EEDBF13AB5EULL,
		0xF9C75D018D70DCFDULL,
		0x6A4416AAA05B0298ULL,
		0xEE39F91064F5BCA6ULL,
		0x18C24DFF2123FF4BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x59ACBE94362F720DULL,
		0xAB6D05A5D95F54D2ULL,
		0xD676A5BCAA1BF44AULL,
		0xB92C20D86470C122ULL,
		0x91823B7EAC4BDD50ULL,
		0xC8BBF728E4CE340CULL,
		0x9BBEC445B76A9AAFULL,
		0x3A9F2A2D8273AB23ULL
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
		0x1FE02E1BAE9E6CC1ULL,
		0x1EB5CBE4D8C1F9D4ULL,
		0x348BD04FB3D2E27FULL,
		0x3953A20AF9F321D9ULL,
		0xB425374C944C4623ULL,
		0x6004AAF22130C0B3ULL,
		0xC5CB752FA5D61AAEULL,
		0x25B7C3B1BC604EE3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1FE02E1BAE9E6CC1ULL,
		0x1EB5CBE4D8C1F9D4ULL,
		0x348BD04FB3D2E27FULL,
		0x3953A20AF9F321D9ULL,
		0xB425374C944C4623ULL,
		0x6004AAF22130C0B3ULL,
		0xC5CB752FA5D61AAEULL,
		0x25B7C3B1BC604EE3ULL
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
		0x87D929BE43BE6394ULL,
		0xE9088DED6CF29B05ULL,
		0x692C3812B015D2A2ULL,
		0x7FBD17E7593CA852ULL,
		0x0CE45C21D7E95370ULL,
		0x741C756A7A7A5FA8ULL,
		0xF6A5D9827AAE5FC5ULL,
		0xC0D665522225E919ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB07DEC1679BC59E8ULL,
		0x77DED5942A7026DEULL,
		0xA4702134BA47AA93ULL,
		0x4E163E8D93ADB278ULL,
		0xDB9C001F3B06491AULL,
		0x6CB4C001E7A6B33EULL,
		0xA75F3ED2AF833DD1ULL,
		0x24CC0A9DB058A553ULL
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
		0x1D441B8737DFC38DULL,
		0x78A1255C83AE9498ULL,
		0x875DC1A7107A475FULL,
		0x05F39BD5E8F59F86ULL,
		0x19143C7497F67E6CULL,
		0xB5566851BA962C57ULL,
		0x89DF2784AD1B7ED9ULL,
		0xC84D4D34F3BB582EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEB1798C7B1B14E7BULL,
		0x80C4D686935AC9F0ULL,
		0x2F671454822E058EULL,
		0xBC722203A5E91D4DULL,
		0x9614990730318FF2ULL,
		0xB4F05FA2E30A7128ULL,
		0x45B965B6A361AF39ULL,
		0x28C5ADB45888B908ULL
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
		0xDC778A6AA9E87BC5ULL,
		0x96DDBF137E8E97BDULL,
		0xA4F524D1AE392232ULL,
		0x9488A3BA6826543BULL,
		0x3FEABC838028A7B6ULL,
		0x21B99CF75371DBB9ULL,
		0x2EEB12E9E088C111ULL,
		0x99848A0EC7550F98ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x721C51629A51BD8EULL,
		0x8AFAE3689AB82D5AULL,
		0x8AF3F6DFE65F368FULL,
		0x6B78140A64A17CB2ULL,
		0xF91E3F42B650EF35ULL,
		0xCEE7F9271A0F00E2ULL,
		0x9C01AA26D676B47EULL,
		0x7A882C89D4B30E71ULL
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
		0xC3628D7C6893B34AULL,
		0xD5C07809BE5548B9ULL,
		0x775CA75C2E93D02DULL,
		0xC7F67A615E566A89ULL,
		0xAFBEEB517E6875E5ULL,
		0xE56BEB695CDE8E59ULL,
		0xBBD75699F21A57AAULL,
		0xC14663BD24D6BA95ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC3628D7C6893B34AULL,
		0xD5C07809BE5548B9ULL,
		0x775CA75C2E93D02DULL,
		0xC7F67A615E566A89ULL,
		0xAFBEEB517E6875E5ULL,
		0xE56BEB695CDE8E59ULL,
		0xBBD75699F21A57AAULL,
		0xC14663BD24D6BA95ULL
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
		0x84EEDE587CDCB748ULL,
		0x9F9C2732C223B39EULL,
		0x22652D5AD7C725BDULL,
		0xB2A7D080B88F9A09ULL,
		0x29772559CA708BEFULL,
		0xE198CA55AF49583EULL,
		0x2196E83DB621ECB7ULL,
		0x3E0D201C98D5B0AEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x94452DCD77AC43EAULL,
		0xAD13433C820B26D0ULL,
		0xBD10BA48FAFF45D1ULL,
		0xA932516B22A17B03ULL,
		0x75A1FF6D419B31A1ULL,
		0xAF9B1AC6228D4831ULL,
		0xE351460DD56BD526ULL,
		0xAEF1F5D2A3BEB86CULL
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
		0xEE5BA9ED54A4456CULL,
		0x88147C8C0DC8A149ULL,
		0x69CA1790A6B4B896ULL,
		0xCF77CE09E2EA2605ULL,
		0x3B8112E36B1AF452ULL,
		0xE20D3ACE3F8584D2ULL,
		0xC865749926AD4109ULL,
		0xAE04ED794C2FD3BAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9E68319F21969E87ULL,
		0x363D11E718732BFBULL,
		0x33E732A09E7C2D8AULL,
		0x785BC5FA61BC97ECULL,
		0x0A3890AC67DE6F92ULL,
		0x8FB100F1E0D2827CULL,
		0x06C68EF3F8AAE9CCULL,
		0x8B03BCF8032791FFULL
	}};
	t = 1;
	printf("Test Case 131\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xDEB93D02535346B7ULL,
		0x7317F1A1C72F26E4ULL,
		0x009298189FE59006ULL,
		0x6A5BF2C2BCB532CCULL,
		0xA6BC3B44A373E7CEULL,
		0x3467FFCB7D95E3CDULL,
		0xD8D610BEDC5F92F3ULL,
		0x0A0CF5E0B1DC7319ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1466C5F4EFFE9769ULL,
		0xD6FFE199906D0893ULL,
		0x106686C0E66EC306ULL,
		0xA132ED3F268CB665ULL,
		0x6A4E734A7CAB5BA5ULL,
		0x6AEDF25A361F73AFULL,
		0x79C0200B3BAAEAB7ULL,
		0x711A86B8874121DBULL
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
		0xB04E0D9B1F3F2E9FULL,
		0xC8EB90146813C220ULL,
		0x5CD3C045A8ACA123ULL,
		0x6CC11B7073C20598ULL,
		0x88C34E426C5B7D2FULL,
		0x45E74FDAD310DEF2ULL,
		0xF8CCB2030E2DD2ACULL,
		0x334DA614E0A7FF78ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB04E0D9B1F3F2E9FULL,
		0xC8EB90146813C220ULL,
		0x5CD3C045A8ACA123ULL,
		0x6CC11B7073C20598ULL,
		0x88C34E426C5B7D2FULL,
		0x45E74FDAD310DEF2ULL,
		0xF8CCB2030E2DD2ACULL,
		0x334DA614E0A7FF78ULL
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
		0x91D6B2BB04DD404EULL,
		0x99C4FE9CA95A8E47ULL,
		0x3EC3FB8EB137A6E4ULL,
		0xC79922FE7DA3F49FULL,
		0xB38E6729C1FD2E14ULL,
		0x2FF5CF8F37B9E58DULL,
		0xD138B830472B4400ULL,
		0x6563524E4F9B7F09ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x493AFBC349BF4E8AULL,
		0xF10F4354B360873DULL,
		0xFBCD371C2A679B78ULL,
		0x05C3A6042A03C2E2ULL,
		0x334905E5807B9CADULL,
		0x1625936F5E34F585ULL,
		0x24FB1CCBAFC47289ULL,
		0x2016C5557FD0291EULL
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
		0xA0CE694D5631B1E5ULL,
		0x16349EACCD751B9CULL,
		0xC2B68AD130CB8D04ULL,
		0xB85C16CDDCE6250FULL,
		0xA27CFAD95162EFB5ULL,
		0x7C257D487A9B4210ULL,
		0xCFA17F2B12F87179ULL,
		0xF56AA732DADC123FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x990BB7EDBDA31FAEULL,
		0x9E21EDD6C79A27F4ULL,
		0x2D127F7959EBD69DULL,
		0x5423EA161DCEA3E7ULL,
		0x63A890C2E1719DE2ULL,
		0x20954F04B8381680ULL,
		0x9E07CF95246F4F70ULL,
		0x59EB320CD8C622FBULL
	}};
	t = 1;
	printf("Test Case 135\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xD83A320A58CA8F49ULL,
		0xB2F4A8768B29DADBULL,
		0x2A8C6CE6F887CB3BULL,
		0xF26AA0530173FE11ULL,
		0xF5422DC436EA6407ULL,
		0x01CC3D6B856A6F3BULL,
		0x41E757AFFF3A3926ULL,
		0xCA10FAA0F172F6D7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC787E9BCF6BC0D47ULL,
		0xCB399DA74BAA4D3CULL,
		0xE6D55636CC29D641ULL,
		0xC8950A5849B616C7ULL,
		0x53890992602FFC45ULL,
		0xA5E9FED26A89B9C2ULL,
		0x365355DDD37B20F5ULL,
		0xB378A52CE7AC784FULL
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
		0x639485253F4F8E84ULL,
		0x9B0D744DC7D022F4ULL,
		0x59CE419F959A4B14ULL,
		0x1A2E08D31B091FFEULL,
		0x96F83D351166C9C8ULL,
		0xF2799B622EBCB4CCULL,
		0xFBDEF6FA2D058652ULL,
		0xA0F4A9BD14FD5D3FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x639485253F4F8E84ULL,
		0x9B0D744DC7D022F4ULL,
		0x59CE419F959A4B14ULL,
		0x1A2E08D31B091FFEULL,
		0x96F83D351166C9C8ULL,
		0xF2799B622EBCB4CCULL,
		0xFBDEF6FA2D058652ULL,
		0xA0F4A9BD14FD5D3FULL
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
		0x4BAAB080FE1A738FULL,
		0xECDB1D737C4B94D1ULL,
		0x1434A412CD37AB62ULL,
		0xCE42B17506AD936FULL,
		0x633D1388E40BED08ULL,
		0xE098E2CF4BF36589ULL,
		0xCCE63A79ABE9233FULL,
		0xF7A47E000C82ADC7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD3D4D4741DAF588BULL,
		0xC042E8A54B29AA09ULL,
		0x5B91EA7E9609F7B4ULL,
		0xC1EE4B0133879D43ULL,
		0x5BA81E187409A0C4ULL,
		0x2E124D0388D1C2B1ULL,
		0xFF4492A42838E0AEULL,
		0x82B341922CE1E717ULL
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
		0xCC0ECE8C434DEF42ULL,
		0x6F4C796451064A1DULL,
		0x12C566B53BF1C4D3ULL,
		0x98722E4699689438ULL,
		0x6BA486E7059C7C7AULL,
		0x286938151FEE0DEAULL,
		0x2202984A394AE34BULL,
		0xA6F436970699521EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7AE94C0FBB6A9C07ULL,
		0x4EC9F0E54CB5B362ULL,
		0x9A7FF77FE0346A48ULL,
		0x09FB2DBD5032DFB2ULL,
		0xC370263BCDDBB722ULL,
		0xFD360019A72E0792ULL,
		0xDA0BEDB90BEEBEA7ULL,
		0x147EB6D8C750A768ULL
	}};
	t = 1;
	printf("Test Case 139\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x746C8006B146EDA0ULL,
		0x516451B3945DBBA4ULL,
		0x90C2502509B7BD7EULL,
		0x2AAC4B3D94D3BFB4ULL,
		0x9C8BF7AAC5C51DC7ULL,
		0x8F43AB1F047C15EAULL,
		0xC33BC255C43462AFULL,
		0x217472FFBD26D8DDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x51FD08851274E793ULL,
		0x3D28B4BC0303B26CULL,
		0x1E29A5476857E874ULL,
		0xE3F318FF2C28F38DULL,
		0xA1C05AF0E83588D5ULL,
		0xFD1EAB28EEBD8FC9ULL,
		0x2D636F2B0BDF85E3ULL,
		0xA4913B133AABB146ULL
	}};
	t = -1;
	printf("Test Case 140\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xCE91D3C00379ADE5ULL,
		0x3CE95B683C90289EULL,
		0x8A7FE639826C8F43ULL,
		0x17F65C96628511C3ULL,
		0x4D068198EE1315E9ULL,
		0x6A90F464F953F1C6ULL,
		0x655AE4410D2EFA37ULL,
		0x950797E65AFE386FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCE91D3C00379ADE5ULL,
		0x3CE95B683C90289EULL,
		0x8A7FE639826C8F43ULL,
		0x17F65C96628511C3ULL,
		0x4D068198EE1315E9ULL,
		0x6A90F464F953F1C6ULL,
		0x655AE4410D2EFA37ULL,
		0x950797E65AFE386FULL
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
		0x54976F0A37E6307AULL,
		0xAD6E07299146B730ULL,
		0x21D052966B6CECC3ULL,
		0x8CD85DE0EB5FA18AULL,
		0x884A0F910A6A129EULL,
		0x48CA1D8AB4422ACBULL,
		0x74A668FF75BCCFFFULL,
		0x9077EE0095FC2105ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x233650441A735914ULL,
		0xB436F79C0EF3F95CULL,
		0x0972519262D15D8FULL,
		0x95BDAA4534F371D1ULL,
		0xBF3433FDF0FD6CABULL,
		0xD785DC8899E78FA4ULL,
		0x3A8EE1B7B777D357ULL,
		0x79AF216AFB49DDAFULL
	}};
	t = 1;
	printf("Test Case 142\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xBCECDE3A967DA3CCULL,
		0x3B68AC2707136D23ULL,
		0x42BE7F3ADDB162A4ULL,
		0xC791463D377E3568ULL,
		0xC86F14853822B3D7ULL,
		0xBCE4D7733245CAAAULL,
		0x458F64B4B086A478ULL,
		0x8A66DDD45BE4EA99ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEEA3982B0622762CULL,
		0xB9618B7F3522F39EULL,
		0x7960720AC386E296ULL,
		0x7383CE3B4C02EC9EULL,
		0xADF74E59813D773DULL,
		0x4286B7AB527ED376ULL,
		0xFE67D2F19F4F2B25ULL,
		0xE48FF34B957386D3ULL
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
		0x6E2D3F64735DD868ULL,
		0x9AA17887558956AFULL,
		0xD963B5C4D544033AULL,
		0x61D15029F8558564ULL,
		0xBA4593DCEB35DDD8ULL,
		0xFF365AF768CFAD1CULL,
		0xE5B4C20930CA7BEDULL,
		0x39D7CE21A6AAF945ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x14D05D9FAE8FB053ULL,
		0xFB025944F34A7E2EULL,
		0xC5BA723326E1A463ULL,
		0xD46B280CF9AD54B7ULL,
		0x9B072AC24F8A2176ULL,
		0x3B1886EF565544BEULL,
		0xCA9B3E09A97768E1ULL,
		0x079BF6C63ADFE683ULL
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
		0xEF4FF96855088826ULL,
		0xB76951E0B8617FE6ULL,
		0x6880D8AD19C916D6ULL,
		0xE69578568601A878ULL,
		0x12F02D4CF8FDA929ULL,
		0xB187E8906AE36CB4ULL,
		0x88508310C005376FULL,
		0x77979546E3B82D1AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEF4FF96855088826ULL,
		0xB76951E0B8617FE6ULL,
		0x6880D8AD19C916D6ULL,
		0xE69578568601A878ULL,
		0x12F02D4CF8FDA929ULL,
		0xB187E8906AE36CB4ULL,
		0x88508310C005376FULL,
		0x77979546E3B82D1AULL
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
		0x2893E0AAE1525565ULL,
		0x7511F51D4B29FA4CULL,
		0x4F9C82328834D396ULL,
		0xCC868E231B52E7AEULL,
		0x8EEB143A95A0B559ULL,
		0x2E560499A184D1E4ULL,
		0x4266FA234D9265A8ULL,
		0xED532DF09E7E7DC7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x782DFE03DA4048F8ULL,
		0x5DDFF44AC33C3A16ULL,
		0x2E1CE09C44E47AFDULL,
		0xDB790D1388B2046FULL,
		0xAA12098A98EBC682ULL,
		0x3CAB6471085E9B1FULL,
		0xA2CC51C312E4192EULL,
		0x33E4F12749CC2E3DULL
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
		0xA70E806CE6683320ULL,
		0x255F6E2DF1DE2C62ULL,
		0x9EFC0ED7407C4384ULL,
		0x526DC2BE0715F229ULL,
		0xC9B4F498C1923AB0ULL,
		0x00EA6275E9B96737ULL,
		0x7ECDC11A83ECAB56ULL,
		0xDB22D53C4CBFDC2BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFD115C16A160ACF1ULL,
		0x77571705929E6F1EULL,
		0x99596A2A922312CDULL,
		0xA5C9208458EF1FC8ULL,
		0x502CA73774609A29ULL,
		0xE1179AC4202BE605ULL,
		0xE493F66D77FC425FULL,
		0xB69123BDB6A7D631ULL
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
		0x48C0D52606C9CF3AULL,
		0x697A91F359291116ULL,
		0x43FAE346B0206F0BULL,
		0xB961BC8BBB779A21ULL,
		0x16310102C72AD990ULL,
		0x13A4101690E53468ULL,
		0x4D3B38CC8B1C357EULL,
		0xADE374949058D573ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x15295B420E616E03ULL,
		0x21ECB7FC96660BFDULL,
		0xBB947773101ED847ULL,
		0xCBA302F0B16676C0ULL,
		0x613A577FF452FD1AULL,
		0x9E4C54817EC57AEBULL,
		0x454925DD1725A15CULL,
		0xE11B994438D54005ULL
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
		0x160885F3EEAC9C45ULL,
		0x55860686C69CEE90ULL,
		0x1C5C2F62EDFB749FULL,
		0x4E00A38B30CF00F6ULL,
		0x147EB904A542AC1CULL,
		0x201F0085078A0E58ULL,
		0xAF5698CC794B664EULL,
		0xD8ABC7E08F7BCDF1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x160885F3EEAC9C45ULL,
		0x55860686C69CEE90ULL,
		0x1C5C2F62EDFB749FULL,
		0x4E00A38B30CF00F6ULL,
		0x147EB904A542AC1CULL,
		0x201F0085078A0E58ULL,
		0xAF5698CC794B664EULL,
		0xD8ABC7E08F7BCDF1ULL
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
		0x7680697401048B72ULL,
		0x48D17050452F533FULL,
		0xBF33B23EC145CAD6ULL,
		0xCB9DA60C1632F322ULL,
		0x1DC36E475ED07D2AULL,
		0xAFB5AE45FADC99FEULL,
		0x3652832EEDF1B6CEULL,
		0xFB4A7AA023E70604ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x427C91226B5E9AFDULL,
		0x499394D4F3C939F2ULL,
		0x00B0FC654D2B1BF1ULL,
		0xBB8CAEDE14CAFEB6ULL,
		0xB3BE7A2827F2CB6FULL,
		0x5201CF23B20B9B76ULL,
		0xF7F5160C18E5E05DULL,
		0x68CBB07CA71704FAULL
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
		0x3EA163142142CF7AULL,
		0xD2E305040E048A94ULL,
		0x29829BE51CDF5DFDULL,
		0xE1220C5126981636ULL,
		0x1A96F0F05E17D588ULL,
		0xC33E10E0B383453AULL,
		0x8EB9119A01C4AA1DULL,
		0x11ABE244C68E42CCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1D7BE0AF9EDB7084ULL,
		0xBDAFE7ED887098B3ULL,
		0xEFA57AECA8A1E6D4ULL,
		0x94AE2BF90B988448ULL,
		0x0A6DBE130C8C51CBULL,
		0xC034A96B1B9CD618ULL,
		0x25E02E64451BDB89ULL,
		0x2CC8EF0CF3E962EBULL
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
		0x07448AE820AEA8FBULL,
		0xFFE4C3CB9582E49AULL,
		0x51996DE18121B396ULL,
		0x16E093A3E5CBD9CEULL,
		0x589F9190A580049DULL,
		0x76DA92ECB7F6F133ULL,
		0x3BFC696674D4D5B3ULL,
		0x6607585C8CC11FA1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2831C15AAEF7155AULL,
		0xC58E6BB88F3EEAD5ULL,
		0x75C67DC24F97BA80ULL,
		0xCA51E03B3A224B6FULL,
		0x0B7244317F6D16CAULL,
		0x840ACF075CC2297DULL,
		0x3D8321D1A44877E0ULL,
		0x118316EF297AC64DULL
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
		0xD26F188B805CB04AULL,
		0xABCE4CC63CA26CBAULL,
		0x26A57E029626E757ULL,
		0x45DF180FD91F18F6ULL,
		0x4604FB331C39B970ULL,
		0xA801C5947F600FE5ULL,
		0xD1F7D78B327EA167ULL,
		0x42176F6969C59121ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD26F188B805CB04AULL,
		0xABCE4CC63CA26CBAULL,
		0x26A57E029626E757ULL,
		0x45DF180FD91F18F6ULL,
		0x4604FB331C39B970ULL,
		0xA801C5947F600FE5ULL,
		0xD1F7D78B327EA167ULL,
		0x42176F6969C59121ULL
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
		0x337F3C2356558C2AULL,
		0x604C5750F1AC1BFEULL,
		0x45BA2883F78B497AULL,
		0x4D8F9261298C36EAULL,
		0xF037BEE54E9806DCULL,
		0x3D6E75333AB9FF31ULL,
		0x97215B64CDF3F77AULL,
		0x515BA0C6D0C8B19CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6A2F51AFFEE84965ULL,
		0x7177C0A6340ACB26ULL,
		0x55BF8F04E17ACE7BULL,
		0xCA0120739298D3D2ULL,
		0x604592397B89FF74ULL,
		0x37FA34A5704C41CCULL,
		0x477DCD948019F0D2ULL,
		0xC14B13580108F7F7ULL
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
		0x53A6E0F8DFD779ABULL,
		0x887AC06C1D612CA7ULL,
		0x9E5357823B5B0BD7ULL,
		0xEDC5C72D010BE4A9ULL,
		0x7B1897FD0C9369C1ULL,
		0x9DD554DAA0BCA465ULL,
		0xB676072979123E89ULL,
		0xE110CAC9170B4BCFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0EE22A95A3A70069ULL,
		0x0ADED121024ED893ULL,
		0xAEEB1EF129F9835DULL,
		0xB5D488ABD453D4B7ULL,
		0x40C68091818054BCULL,
		0xECE0150B74437784ULL,
		0x92A62476BE24B6D3ULL,
		0x40DC419F52E0DFF1ULL
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
		0x72EF08E0FF2DD22AULL,
		0xF80476A1A0BD26D9ULL,
		0x65C2DBFE1A42F09EULL,
		0x0095C4285FFFF3CFULL,
		0x16C135F569AFF575ULL,
		0xB0304CAD0D7CAB25ULL,
		0x92E9032E55EFD23CULL,
		0xE382957839165AAEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC7A5EA2F9A969773ULL,
		0x26D81842140AC4F5ULL,
		0x7DF9B52418908EBCULL,
		0x94DFEE7FC1A575D1ULL,
		0x95226CF08088D07FULL,
		0x7D2D5BDF39AE4858ULL,
		0xD52BACC436385EECULL,
		0x9F19EAB1FDD6DD9AULL
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
		0xB600B65C1267C396ULL,
		0x483677F05FBEF1FFULL,
		0x17192DED5C8C7698ULL,
		0x2AD6E88B5AAC1D60ULL,
		0x53B629931F750FF7ULL,
		0x592501783F4D2F93ULL,
		0xD91E1A492D4F0934ULL,
		0x3C983EB287E383EFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB600B65C1267C396ULL,
		0x483677F05FBEF1FFULL,
		0x17192DED5C8C7698ULL,
		0x2AD6E88B5AAC1D60ULL,
		0x53B629931F750FF7ULL,
		0x592501783F4D2F93ULL,
		0xD91E1A492D4F0934ULL,
		0x3C983EB287E383EFULL
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
		0xAD5E1F80B990A0DCULL,
		0x3A3B2D3F5B75DD89ULL,
		0x9888DA2F5B27A0B8ULL,
		0x5780E04913C25471ULL,
		0x447E2AC49F288EB6ULL,
		0x07019E9DB6DA3B2CULL,
		0x510777052F9C0301ULL,
		0x5E7406793FBAD2DEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCD05AF49BFF2F786ULL,
		0x7FDF515BC3EF3F07ULL,
		0x2C3B2559A79FAB5DULL,
		0x9160B36A6F58C3FDULL,
		0xEE664936A783F22BULL,
		0x8218B5EB19C3B065ULL,
		0x476BD1B0FA232FACULL,
		0x21BC5BC7E60CE7F0ULL
	}};
	t = 1;
	printf("Test Case 158\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xAF55416AF2366AC2ULL,
		0x352260B36FC97BA7ULL,
		0xD95CFFF235FB16B7ULL,
		0x85F6B0C0DCFB0C2DULL,
		0x77C2DE2046DFAFCAULL,
		0xF3D85A25726B1562ULL,
		0x134BBE42457417B7ULL,
		0x6F743AAAA7B37BDCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x02A9FFA28C6ABA04ULL,
		0x86DAA418B0D5379DULL,
		0xFC5ACE05ACD5FF29ULL,
		0x9B95E1120B22C811ULL,
		0x8BAEA57F409C6D99ULL,
		0xC288ADAB45331644ULL,
		0x554BE09C653BA22EULL,
		0x7B9CA55B3245220CULL
	}};
	t = -1;
	printf("Test Case 159\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x0FFDEAF3269C40A2ULL,
		0xCF442361FA480C66ULL,
		0x914409E66480FCA9ULL,
		0xF2CF79E041901D59ULL,
		0x51D97AF5408AB550ULL,
		0xC0F65892BB74E6A4ULL,
		0x954199358747E380ULL,
		0xAC5B0F9731CAB9CBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB89E30D6EEF7E1A9ULL,
		0xF45A4FC7BC27AC5FULL,
		0x1F5E0997B2176FF4ULL,
		0x7395F33813DFE0A0ULL,
		0x6847595FD1AF3DF1ULL,
		0xB55209AFDE8D3D2EULL,
		0x08C35E5D20CFEDC9ULL,
		0xF723FF243FCE2006ULL
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
		0x65DBAD28E0A1D253ULL,
		0x7BFDC265552AAB63ULL,
		0x0485AAA29932ADD0ULL,
		0xCE5119FA9EEB24E3ULL,
		0x59C263607A70D2F6ULL,
		0xBCC456A6724DB0F5ULL,
		0x1A6190B3056C1151ULL,
		0xC115FA1C86F90DE2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x65DBAD28E0A1D253ULL,
		0x7BFDC265552AAB63ULL,
		0x0485AAA29932ADD0ULL,
		0xCE5119FA9EEB24E3ULL,
		0x59C263607A70D2F6ULL,
		0xBCC456A6724DB0F5ULL,
		0x1A6190B3056C1151ULL,
		0xC115FA1C86F90DE2ULL
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
		0xA964CDD5EFCB1EF4ULL,
		0xCBFBB2FDE551A61FULL,
		0xD7ABB92328F6A64BULL,
		0xD408BD49DD598F78ULL,
		0x6A7F7FDA3D50A813ULL,
		0x72757CF4712D6CE3ULL,
		0xBA352E39E07756E5ULL,
		0x2F50DCF08D90AF0BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE9E60E8EC128023EULL,
		0xD8C8111F01366BB7ULL,
		0xD51EFCDCB995A08BULL,
		0x7BB049A90C223F32ULL,
		0xCD1D1D394629920EULL,
		0x567D112FACD4E24EULL,
		0x59831AC481FC5FF4ULL,
		0x6B03040170E7E9A5ULL
	}};
	t = -1;
	printf("Test Case 162\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xC9BEB3CD9937B793ULL,
		0xBB9442B62215E27EULL,
		0x6E730F258D0115B2ULL,
		0xE78838D5CC19860BULL,
		0x70CF16FE663FF5DAULL,
		0xD260B534893EF547ULL,
		0xD493D8108E48BD63ULL,
		0x408BEDB3A1526088ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF8E39A75359EA144ULL,
		0x20649A3A3A9125EBULL,
		0xA4819C66CC894C2AULL,
		0x68B0D13762A04D7BULL,
		0x4F33E4232D77DBA8ULL,
		0x95876E5A1390B1B1ULL,
		0xA1221FCCA95C9214ULL,
		0x5DE9F5E090EC40CCULL
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
		0x5FDEE966CB318FD7ULL,
		0x91B82BBA34A647D5ULL,
		0x962209A205CBF233ULL,
		0xA729E6EB3B72B014ULL,
		0xBDBD4B3B1B62F6BAULL,
		0x3433102522DEBCECULL,
		0x866CE294E82FB10AULL,
		0x1E0C64EC13597F91ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB0230EDBFD5CF103ULL,
		0xABF0923D23D177C4ULL,
		0x942F9C273F8A46D6ULL,
		0x158997276C198E4DULL,
		0x561B28E3BF25947BULL,
		0x32FA37893CDB87F6ULL,
		0x83CC04306F8061DEULL,
		0x9277E401311D8BCEULL
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
		0x556D1DA8498DA5E0ULL,
		0x97BCC19872DACD3EULL,
		0x152DF3C395C6A4D3ULL,
		0x55EC26D08DE1A69CULL,
		0x2F1E3B27C3F6E56AULL,
		0xB87C2AFBF7C8EC46ULL,
		0x196289612C0CF538ULL,
		0xD31902D634083A3DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x556D1DA8498DA5E0ULL,
		0x97BCC19872DACD3EULL,
		0x152DF3C395C6A4D3ULL,
		0x55EC26D08DE1A69CULL,
		0x2F1E3B27C3F6E56AULL,
		0xB87C2AFBF7C8EC46ULL,
		0x196289612C0CF538ULL,
		0xD31902D634083A3DULL
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
		0xE023221E254D393DULL,
		0xDAF0F15821FEC709ULL,
		0xD5DFA38A053D7ABDULL,
		0xA602EE1538B5AF70ULL,
		0x6D7E2CC8219491C7ULL,
		0xAFCADE842B6D5A0BULL,
		0x03CE06AC82BA83C6ULL,
		0x0EA1F9D6A5F29189ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8CC95C484390622AULL,
		0x64BF3875E5902267ULL,
		0x6DC95565F8DD8D8BULL,
		0xD7ABD19C6CC55CCDULL,
		0xC1F02049919DAB4EULL,
		0x20617930D829F11AULL,
		0x6F486F11E3DA5876ULL,
		0x48143638B10B68F8ULL
	}};
	t = -1;
	printf("Test Case 166\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xE623ABC0199F1680ULL,
		0x978B13CCB01EF39AULL,
		0x38D9E4FB094E5061ULL,
		0xEE8CF1F2CC400F92ULL,
		0x8B6EF92151772D74ULL,
		0xF7C90A191FC493A2ULL,
		0xC9A963DF1B32FFABULL,
		0x6CBECB739DA0EC8BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x745B7E016DC35457ULL,
		0x38304010BC65070EULL,
		0xA7014DE8A0E72314ULL,
		0x7BE3E86D1A317CBDULL,
		0x42B948917FA86724ULL,
		0xE40D7705E422C16AULL,
		0x7088175DF1288A45ULL,
		0x59890195A1970F21ULL
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
		0x667E38586CD23D14ULL,
		0x0AA4A304CB96EE0AULL,
		0xE5AD046B09CB6A7DULL,
		0xA2C66750A0BFDB39ULL,
		0x1F43FACB932841FFULL,
		0x6F2AA8019CF45593ULL,
		0xA5B944140D2E270CULL,
		0x61316F29194277DCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2451F9E630936ADDULL,
		0x586C0735996ACF7AULL,
		0xFC64D5C3F8F9E7D7ULL,
		0x4FBEB100F7CA9D3FULL,
		0xCFD88CE8A3065CF7ULL,
		0xFF716FE5742EBF48ULL,
		0x3476DF5CCDD928EAULL,
		0x38F4E1096A9D88EAULL
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
		0xB0921C71FBC7E466ULL,
		0x7BD1D00373B6B6B2ULL,
		0xFD79D33A4DA195E6ULL,
		0x360D46EBE346CD49ULL,
		0x03741F0348A7D7A0ULL,
		0x2B10F650E0E510E1ULL,
		0xF4886E67E87DAAF5ULL,
		0x1A2CE4DC5B9BF9A6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB0921C71FBC7E466ULL,
		0x7BD1D00373B6B6B2ULL,
		0xFD79D33A4DA195E6ULL,
		0x360D46EBE346CD49ULL,
		0x03741F0348A7D7A0ULL,
		0x2B10F650E0E510E1ULL,
		0xF4886E67E87DAAF5ULL,
		0x1A2CE4DC5B9BF9A6ULL
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
		0x8594C330A427FD7AULL,
		0x93DBE8FCA1C10CA0ULL,
		0xEB6419A91FC4C837ULL,
		0x32BB8A9C1EF0D3F8ULL,
		0x1F16C17B3E5D218DULL,
		0xD7EBE6D49145553EULL,
		0xF362108FEB13F9B1ULL,
		0x4386704CF0E67932ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x806F490D43E46693ULL,
		0x188CE2ACC24F38DCULL,
		0x5AEB563D9EA38A67ULL,
		0x89BC4868A7FE50D9ULL,
		0x5D8782DF42F83EDBULL,
		0xBEB6B36E3B61295DULL,
		0x78893E49406A73EFULL,
		0xF87AB40D44A3A084ULL
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
		0x1C97374527944490ULL,
		0xD36652BC41FD3726ULL,
		0x5EA4E2CBA392C2FEULL,
		0xB33A1BB2C3190CFBULL,
		0x7EE1D4CF64991E01ULL,
		0x89A3F3E4D5C73A2AULL,
		0xE2B3D2F62AD7ED26ULL,
		0xD7730FFCD7B58212ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4EC3A1C38A671D03ULL,
		0xFE0698F36B880B14ULL,
		0x0EB9A1C0CF033959ULL,
		0xA7F2FE3FF1F4EB71ULL,
		0x92B63B480BAD35DCULL,
		0xEF9310DC9602A4E8ULL,
		0xF3952E2DC946ADF1ULL,
		0x7C10E389EF44F548ULL
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
		0xB9E35CB5D234752CULL,
		0x838299C881D90C0EULL,
		0x1892FE1E7D3E81F7ULL,
		0x6D307A1CBDAB355EULL,
		0xA2600C3F40FC8CE8ULL,
		0xBB8CA9EF370DB6B2ULL,
		0xE91BA6572E457A0EULL,
		0x060366708E43D85CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1C736B2E818B4F5CULL,
		0xD979E2E6CE6F1712ULL,
		0x3C83C430CBAA6880ULL,
		0xECC3AB6D719A8BFBULL,
		0x7ADBC7921F1AFF1AULL,
		0xFF01309B5B246FB7ULL,
		0x5359BC3CB9430A22ULL,
		0xB617AED0F3A26114ULL
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
		0xA409C77DDECC9492ULL,
		0x09663B926E5A63C0ULL,
		0xD6EBE5F46220F70DULL,
		0xB6DDC836E198993DULL,
		0x1AC4FC4275D57F5FULL,
		0xC9028BA34A8ED3E1ULL,
		0x9114C802464B97F1ULL,
		0xF144A73746589EF6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA409C77DDECC9492ULL,
		0x09663B926E5A63C0ULL,
		0xD6EBE5F46220F70DULL,
		0xB6DDC836E198993DULL,
		0x1AC4FC4275D57F5FULL,
		0xC9028BA34A8ED3E1ULL,
		0x9114C802464B97F1ULL,
		0xF144A73746589EF6ULL
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
		0x3BB720451453480CULL,
		0xE78B7B576F79CD5EULL,
		0x0967FB7E4706767CULL,
		0xE2502AA42CEFA8ACULL,
		0xCB19756B1BD1212DULL,
		0x61E129727D306839ULL,
		0x3755AF1C5B2DC69DULL,
		0x3B0645099233172BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x777F1E038741FB64ULL,
		0xC2FE9D5814E06D94ULL,
		0xFD30FDEE09300999ULL,
		0x1F8275B60BE5A7CBULL,
		0x3F9AF63B38F34249ULL,
		0x12887D4A37E7DE32ULL,
		0xB92C506F6FA2AEC4ULL,
		0xB8412C5F1B9430E5ULL
	}};
	t = -1;
	printf("Test Case 174\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xA40A624637F5AE1DULL,
		0xB7C372C8AF233074ULL,
		0xA1F099CB84DBEA94ULL,
		0xB6B19F8472139A46ULL,
		0x7BAEA8FE005E5D47ULL,
		0xDFC39FA1F77F9CAEULL,
		0xA3319ACFCCF5DB89ULL,
		0xAC3D74B13D6CFC44ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x576BDEAD0212D313ULL,
		0x88DCEB005F196CF3ULL,
		0x83B6E29C4379A0EBULL,
		0xCF4E8D7CB2982B87ULL,
		0xE212D0F4E1157BFDULL,
		0x2210EED1199E9C98ULL,
		0x645589E36A995372ULL,
		0xCFD8D04870267EFCULL
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
		0x0A45ADE73DE7415BULL,
		0x7F9840B003A59A27ULL,
		0xE85EBBE87F42F07AULL,
		0xE23CBB1705596E44ULL,
		0x6898ED39DDAA77DFULL,
		0xD9B96412BC45178BULL,
		0xC458A062322C72BFULL,
		0x963AB2F2FF89BAD0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4739EBA9AB18844AULL,
		0x68FB0E71B7BF006FULL,
		0x93617CC71B739518ULL,
		0x0059E6AABE9D79DEULL,
		0x0383CD32622FC9C0ULL,
		0xA08A087E93D7CB7FULL,
		0xC1BD474A773277F6ULL,
		0xC5A723C4BB6B3F7CULL
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
		0xB76BD87BDCBFC19AULL,
		0x1354408E243FB43AULL,
		0x2789FCE494001350ULL,
		0x098F735B1A5CD08CULL,
		0x3B6F58309F322E66ULL,
		0x494501C72603D969ULL,
		0x2B95DAB100957539ULL,
		0x11651711B8B5C31CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB76BD87BDCBFC19AULL,
		0x1354408E243FB43AULL,
		0x2789FCE494001350ULL,
		0x098F735B1A5CD08CULL,
		0x3B6F58309F322E66ULL,
		0x494501C72603D969ULL,
		0x2B95DAB100957539ULL,
		0x11651711B8B5C31CULL
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
		0xB07CB20423BE33C9ULL,
		0xDC1842E768A9CB26ULL,
		0x0AACB46E8F5DB15CULL,
		0x64169B73D32580FCULL,
		0x134DC6A44FF10340ULL,
		0xBD09E9F7A798F825ULL,
		0xBEAF7309EA3BDC05ULL,
		0xF79A15DB41CA5563ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE05C0A82AC6E79DEULL,
		0x7838FC30538391B4ULL,
		0x04B43CDBD276AB7CULL,
		0x47442C7F24EF7E9EULL,
		0x1CE8FD830BD4B573ULL,
		0xE36F341974FD381CULL,
		0xD74711A12E1A3862ULL,
		0xF99CA8C8A97C6C1CULL
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
		0x6883E4243064741CULL,
		0x3AFC75591AACD171ULL,
		0x7441950D692A74CEULL,
		0x301FC1E0231D0FD4ULL,
		0xBABAF71E92472F28ULL,
		0x2F54C7FB684E5587ULL,
		0xE108113D790CB183ULL,
		0x4F08279FFB5D8905ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF75AE260C5DE18E0ULL,
		0x1AD35B0EE29D7B0FULL,
		0x8EB86CF93CB63804ULL,
		0x8D0377130DD201A5ULL,
		0x5B990C4E8F155F54ULL,
		0x171D2873D74B9818ULL,
		0x90DA9E9D9FDFCCE8ULL,
		0x0E8FCFDB591B5E54ULL
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
		0xC654F842ED2755D2ULL,
		0x32C31930A0115330ULL,
		0xC171DFFDAB0F8ADCULL,
		0x462818C43A46C8BEULL,
		0xC56B7F4D0B25A680ULL,
		0x183047551403B2F0ULL,
		0xA44D36F66665DFA5ULL,
		0x7CB490A36F2D70E3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBC3B1788948C70B0ULL,
		0xD76F02AD827871E4ULL,
		0x6457EEF5A2249D89ULL,
		0x38CE4396442DFC37ULL,
		0xCA91BD07A7E3CCB2ULL,
		0x7E51B6023FD75BF2ULL,
		0x544548A7A8C23E9CULL,
		0x627557035813166DULL
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
		0xA47E70945FE6A7F6ULL,
		0x07D590FA4C0BB80BULL,
		0xE427843278BF1E9EULL,
		0x67E1304EE680E0A2ULL,
		0xC7C4D1DEEB863BA1ULL,
		0xE7F92BBEE4B8C30CULL,
		0x7F5CB3EB8D2AA284ULL,
		0x8F3392DA1F8689D2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA47E70945FE6A7F6ULL,
		0x07D590FA4C0BB80BULL,
		0xE427843278BF1E9EULL,
		0x67E1304EE680E0A2ULL,
		0xC7C4D1DEEB863BA1ULL,
		0xE7F92BBEE4B8C30CULL,
		0x7F5CB3EB8D2AA284ULL,
		0x8F3392DA1F8689D2ULL
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
		0xBAE951C7F4A591FFULL,
		0x346C500CE93C42D6ULL,
		0x196BDA3291C49A71ULL,
		0x6B49A4FB8E8DF330ULL,
		0xF78876147EA6F1E8ULL,
		0xF9DA1C239ABB3ADEULL,
		0x3389325DC4D42872ULL,
		0x4224901B8B7FC0E7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x53A7DB028CA96C31ULL,
		0x2C79AA39A3B975B9ULL,
		0xEAB32F1659618E7AULL,
		0x60C96B6D23DA79D3ULL,
		0x86B70D08B47A7B49ULL,
		0xEB372A4DC16FA722ULL,
		0xED076599CB73B47FULL,
		0x7CAC282E975CAC43ULL
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
		0x093D84DD899D51F7ULL,
		0x5D2E73A48A9AA0C9ULL,
		0x5E89F3453A6C2ACEULL,
		0x8CF3ECE57DAE4170ULL,
		0x1633903DAE16084DULL,
		0x63E1E1E519314C89ULL,
		0x19D1C41C382F569FULL,
		0x3FCACB8BAA09AD33ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA87DB7533129E636ULL,
		0x49553539E3D9DD60ULL,
		0xD203A32D3C753EA6ULL,
		0xECAD1D174A45890EULL,
		0x390636D5DCA2C81DULL,
		0xB48A59A93ADA0EDEULL,
		0x41AFE6CB26DCC422ULL,
		0x41AB087A6552A436ULL
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
		0xC195D25B0B40F05CULL,
		0x815AF72E175D5B5AULL,
		0xFB61DC1D72DBC421ULL,
		0xA38EC73ADC77B258ULL,
		0xDBBA721B85F46233ULL,
		0x88E772E9DD09D103ULL,
		0xED240C6ED0D062F1ULL,
		0xAE48110FAA9D7900ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA90470282A82ECB0ULL,
		0xFF00775DE382AAF5ULL,
		0xF1370EBC58F23249ULL,
		0x8609DA0C99EFF879ULL,
		0x399119F79F2C3CAAULL,
		0xF7780FFC80F29861ULL,
		0xDBC5241A2F1EFA31ULL,
		0x9D1BC95BDEB1CF08ULL
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
		0xBBCA51D871EE1D1BULL,
		0x8A9EB11B60EB2AF5ULL,
		0x5373E12FBCA91EC8ULL,
		0xF2E6870949ACD6DFULL,
		0xEA7DD1522379BE6AULL,
		0x2B29B4F88ACBED6EULL,
		0x618B7C7B41D2DC22ULL,
		0xB22CC2C148DF2B03ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBBCA51D871EE1D1BULL,
		0x8A9EB11B60EB2AF5ULL,
		0x5373E12FBCA91EC8ULL,
		0xF2E6870949ACD6DFULL,
		0xEA7DD1522379BE6AULL,
		0x2B29B4F88ACBED6EULL,
		0x618B7C7B41D2DC22ULL,
		0xB22CC2C148DF2B03ULL
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
		0xF8E6153B757DDA12ULL,
		0xE017F4DE6F074943ULL,
		0x54E31C1CE1B791EBULL,
		0xC0DEF16707D495A8ULL,
		0xBF3D8F54C6A49CEEULL,
		0xF90225B9F3A0D4D2ULL,
		0x8DB0376C23F12EA4ULL,
		0x6E2A25F9FDDC194EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBE52678199B9D635ULL,
		0xBE32F6CB0B04A40BULL,
		0xF1509474792D25DBULL,
		0x13081276F1BB30BCULL,
		0x1F4C7BEB0C568876ULL,
		0x336F75396B1058EBULL,
		0x0C5646A7DF70C8EEULL,
		0xB462DD1D7FFF4F65ULL
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
		0x67E9356A86324F6CULL,
		0x70584B12BA1F15B8ULL,
		0x360FE7EFCACC4170ULL,
		0xD0B899D6AD30158FULL,
		0x633A6F19B46A4364ULL,
		0xC45F3AD0D8EA4CBEULL,
		0xE5414C02537822B6ULL,
		0xB013246148918546ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB9A2E7BECA0CB90CULL,
		0x603D0D1243E786E1ULL,
		0xA9DAC7079C781451ULL,
		0xAB2A155938BE46E9ULL,
		0x963ED8643D8FB787ULL,
		0x9C3A34EE7E935B24ULL,
		0x48DF1FF6908494F6ULL,
		0xF13F87DF805F9E3AULL
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
		0xB91C12BE50218D47ULL,
		0xCCED712E4695CA65ULL,
		0x6398086BB59441F5ULL,
		0xF57E64249D430231ULL,
		0xD1904ECE841B1865ULL,
		0x89C14D1188F8BF6AULL,
		0xC3AD76FF14313048ULL,
		0xFA70C1E987F5E172ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA227C813056B168BULL,
		0xBEE0DFA87C9789E2ULL,
		0xA371019B14AEE0D4ULL,
		0xD6DCD5E0235B28D5ULL,
		0x7E1BA50818FEAE7DULL,
		0x99000B046451DA8FULL,
		0x8E07E30809ED924FULL,
		0x601E7142830CD913ULL
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
		0x5DAB533A18F1A9A0ULL,
		0xC197BC54CD33555BULL,
		0x9867D5256D8E4C79ULL,
		0x5B091D6DB3C0424EULL,
		0xCF31839E1F6A89F6ULL,
		0x83C13F14525A1297ULL,
		0xD9DCE34B524ECE94ULL,
		0x5446654E40453987ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5DAB533A18F1A9A0ULL,
		0xC197BC54CD33555BULL,
		0x9867D5256D8E4C79ULL,
		0x5B091D6DB3C0424EULL,
		0xCF31839E1F6A89F6ULL,
		0x83C13F14525A1297ULL,
		0xD9DCE34B524ECE94ULL,
		0x5446654E40453987ULL
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
		0x933FCDF585EF8EA8ULL,
		0x4C9832D87EBB5B2CULL,
		0x73B6EB910C26F151ULL,
		0x709CC349C3BB40C2ULL,
		0x76A04478780888F3ULL,
		0x42018ABBF7FD79CEULL,
		0xF86E1041D1B8DC63ULL,
		0xD3EA379470BD51B2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7EE37FE5D21276DCULL,
		0x80816E9851F0DA77ULL,
		0x0E4A555AB25793E8ULL,
		0xD4FF3B9E714D7D81ULL,
		0xA5E794C23E83D53FULL,
		0x8C82BE55356A77E9ULL,
		0xE345BE86E03E347FULL,
		0x708EFFB282B9C135ULL
	}};
	t = 1;
	printf("Test Case 190\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xD67C28CF343A1E57ULL,
		0xC0F096F5DF4C20FAULL,
		0xB7098C80C3A01A61ULL,
		0x64C7E2B4D6E40CA9ULL,
		0xF8D6A3C4300E6D3DULL,
		0x3F5ABE010256E399ULL,
		0xFDB5BA20C6D7196DULL,
		0x1EFA39EB0263FA07ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7877C78618F34C74ULL,
		0x418B952E3DB4F42DULL,
		0x024FC7D58524DEF4ULL,
		0x32CB736CFF8C13D6ULL,
		0x625F676DD4F1C917ULL,
		0x0EE4309E7DE6E671ULL,
		0x8FC7C2034EAAEE71ULL,
		0x6B9BC446AE420303ULL
	}};
	t = -1;
	printf("Test Case 191\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xC9B18D8598228E7AULL,
		0x8AD58AA424A32169ULL,
		0xFC01B874A338B9FAULL,
		0x457FC827A159C64FULL,
		0x8643645BDE9EF8CBULL,
		0x42F608B1343296A8ULL,
		0x2667E363CBADBAB8ULL,
		0x6AB511DECAB0106EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6EF6C6A5A421B8CBULL,
		0x8108B56397C66A29ULL,
		0x97B619C7591B403FULL,
		0x28C44008BD610BE6ULL,
		0xE1F8F6EC0598431DULL,
		0x43D557FEA66951A8ULL,
		0xB7C29BECA7997E97ULL,
		0x9784D067DD9725ACULL
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
		0x9E68CAE34FD1B8A0ULL,
		0x9687AB64DF52A5BDULL,
		0x8A29C502289D0228ULL,
		0xED761228E78930F4ULL,
		0x47B98E8F71ED5ECDULL,
		0x7EBD6967E22F2373ULL,
		0xDEE0A5847A7976CBULL,
		0x3540E771474E3DD5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9E68CAE34FD1B8A0ULL,
		0x9687AB64DF52A5BDULL,
		0x8A29C502289D0228ULL,
		0xED761228E78930F4ULL,
		0x47B98E8F71ED5ECDULL,
		0x7EBD6967E22F2373ULL,
		0xDEE0A5847A7976CBULL,
		0x3540E771474E3DD5ULL
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
		0x55338DC99F5C968BULL,
		0x871ACAC5F1D6C343ULL,
		0x781E6E68E1A68861ULL,
		0xE1AD059BEF44407EULL,
		0x768C4F0C35CA1BF9ULL,
		0xAA1A576E7FD6F6F9ULL,
		0xDE28560EDB28A246ULL,
		0xAB92B57C012EBB6BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA9B75DD17648C92BULL,
		0x873CF258496CF9A2ULL,
		0x1CA9B79AFD8836E6ULL,
		0xF6C17457F64DF99AULL,
		0x74BDF911252F4F39ULL,
		0x3D65BBAE29E200CAULL,
		0xCE406B5FF741ECB3ULL,
		0x35509188AB4BFB6DULL
	}};
	t = 1;
	printf("Test Case 194\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x96D44B42321A4C75ULL,
		0x29A8667FADA14CEAULL,
		0x855E440E1FFCB337ULL,
		0x5BA562ECE0892CA0ULL,
		0x72DCBC20B9B88392ULL,
		0xD870DE9588CCE86BULL,
		0xB15E9D392CEF846AULL,
		0x4C1089D1D5684664ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x997C1A3736E8C195ULL,
		0x3A97D3688474710AULL,
		0xD7655017065A297AULL,
		0x3CCEC7D6857521C8ULL,
		0x8A906F2352C7F6F0ULL,
		0x276846CB231D5CAEULL,
		0x39F943FC1E857DDCULL,
		0x867AC7ECFBB00516ULL
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
		0x6269178AFAF03AC6ULL,
		0x3A3FE27289BAF0CCULL,
		0xD6593C0E12C2B6EAULL,
		0x3206D1E262925DA2ULL,
		0x26513E728A14D6B9ULL,
		0xD2E9AB2084CF3899ULL,
		0x4C8A1712A61E8BAAULL,
		0x33FCE2FE36B2930EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x74626512B4851F9CULL,
		0x10ED71AE5E461598ULL,
		0x62FB3947F483062EULL,
		0xA10F3113C5DE3D66ULL,
		0x2ED937995B364C27ULL,
		0xBB97EBB81E1CDF1CULL,
		0x417C3781CB0C2943ULL,
		0xB584017CF5820B99ULL
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
		0xB5D8C96D8DB1B3B2ULL,
		0xAF63754C5FD6762BULL,
		0x49C8FE6AEABC10D0ULL,
		0x929A3E85BB673CDAULL,
		0xCAD16B470C818913ULL,
		0x844E08098866C2A2ULL,
		0x7103203B785A257CULL,
		0x112FE55039D0AA5FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB5D8C96D8DB1B3B2ULL,
		0xAF63754C5FD6762BULL,
		0x49C8FE6AEABC10D0ULL,
		0x929A3E85BB673CDAULL,
		0xCAD16B470C818913ULL,
		0x844E08098866C2A2ULL,
		0x7103203B785A257CULL,
		0x112FE55039D0AA5FULL
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
		0x85D55744A2D967A2ULL,
		0xB58B298BD3EFABF5ULL,
		0x881D12F5A25956BDULL,
		0x691B0A8CB0BE28F8ULL,
		0x51C2D731E563E906ULL,
		0x6B25CE4C251D916AULL,
		0x99A0D685BC66E999ULL,
		0xAE71CB4F51DDE737ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDFEE0740A8D08432ULL,
		0xA7CD75F98F708CB3ULL,
		0xB7F1E4BC6EF7F621ULL,
		0xADA91D4B0BC0EDC6ULL,
		0x81939BD23A94C93BULL,
		0x5A6DCD50E61A29CFULL,
		0x671C4FA6F08C2AA6ULL,
		0x44AABDFA54EADC3AULL
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
		0xC5BB05607B32282CULL,
		0x54761BF22A8BC316ULL,
		0x1679EDBE73A2F16AULL,
		0x1613FBF16E0FF832ULL,
		0xD2B9A99B47FF33DFULL,
		0x8201AAEAB4C60F93ULL,
		0x77FEF39B04EC1165ULL,
		0x4C5FFD8020983F5FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDB3031DD7B12C515ULL,
		0x83C491B49164C5EAULL,
		0x880C270CF55C5FDFULL,
		0xA62E48DF36C818FDULL,
		0x3B6358D78A53493CULL,
		0x08007B2CA547E2CDULL,
		0x967A7571D9F52E5DULL,
		0x0AA33BD008D46379ULL
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
		0x8B609165B42C26D4ULL,
		0x1BD2B2927361FA2CULL,
		0xF2C3F008FB8EAD8CULL,
		0xE86B4A9ABB3565D9ULL,
		0x66D4396428B5F3D3ULL,
		0x1A074D4AC57A9006ULL,
		0xF20C4196BFB99D80ULL,
		0x4809066A41B351DCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x25AAFC5156261319ULL,
		0x7163B87C1494D7D3ULL,
		0x935CD13F77ADB824ULL,
		0xA4A5649C9DA3E529ULL,
		0x5476101F8FFC2E2CULL,
		0xF5F664BECF8542DEULL,
		0x30EB2B38D17065D0ULL,
		0xCB7B234CDA472E57ULL
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