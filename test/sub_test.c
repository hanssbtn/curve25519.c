#include "tests.h"

int32_t curve25519_key_sub_test(void) {
	printf("Sub Test\n");
	curve25519_key_t r = {.key64 = {0, 0, 0, 0}};
	curve25519_key_t k1 = {.key64 = {
		0x5303BA7654AA524DULL,
		0x7B368B7E577FBD1CULL,
		0x4278F19193DD55BBULL,
		0x418518BB62EE8F8FULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0x741E9A5543F4D680ULL,
		0xEE059C82059A2734ULL,
		0x0B4173C54798C421ULL,
		0x7CE4E4365ECECDA2ULL
	}};
	curve25519_key_t k3 = {.key64 = {
		0xDEE5202110B57BBAULL,
		0x8D30EEFC51E595E7ULL,
		0x37377DCC4C449199ULL,
		0x44A03485041FC1EDULL
	}};
	printf("Test Case 1\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
	int32_t res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 1 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -1;
	} else {
		printf("Test Case 1 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCDAAB3EE951AD729ULL,
		0x252EE1BF3394090AULL,
		0x53A6F80D2F6B41CEULL,
		0x57A88E9C72EDEAFDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x188640D0D4038F2CULL,
		0x7FFEB4343BC72AEFULL,
		0x4F58F56FB0174B65ULL,
		0x0B7C3BA49BF2008DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB524731DC11747FDULL,
		0xA5302D8AF7CCDE1BULL,
		0x044E029D7F53F668ULL,
		0x4C2C52F7D6FBEA70ULL
	}};
	printf("Test Case 2\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 2 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -2;
	} else {
		printf("Test Case 2 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDDFBAF901B98ECF7ULL,
		0xED11CCA778A087DEULL,
		0xAD1F9E57F10FE925ULL,
		0x3102A948C1C046D1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9641DF6F6F8422A5ULL,
		0x6D02D02342FD76F6ULL,
		0x71DCB0DEDE9CABE7ULL,
		0x49E62086565613A0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x47B9D020AC14CA3FULL,
		0x800EFC8435A310E8ULL,
		0x3B42ED7912733D3EULL,
		0x671C88C26B6A3331ULL
	}};
	printf("Test Case 3\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 3 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -3;
	} else {
		printf("Test Case 3 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7F69FA0BF344D30DULL,
		0x5FCA695A9F0836EDULL,
		0xA7311C8522A5820EULL,
		0x35CB208D86906A18ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF95134CE0A76D97FULL,
		0x353992EADC5FF598ULL,
		0xFB432276DFE799C0ULL,
		0x43C930FB36FB66B0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8618C53DE8CDF97BULL,
		0x2A90D66FC2A84154ULL,
		0xABEDFA0E42BDE84EULL,
		0x7201EF924F950367ULL
	}};
	printf("Test Case 4\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 4 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -4;
	} else {
		printf("Test Case 4 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAA9EE6FE070F3BDDULL,
		0x355E696E7DCA4E32ULL,
		0x33CF6507BF7CB390ULL,
		0x0BF7114B9827DE1FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC44962DC9C07E3CFULL,
		0x54F49FB5E019A729ULL,
		0x7433ADC3E52AA972ULL,
		0x4A1707A1D1C7B005ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE65584216B0757FBULL,
		0xE069C9B89DB0A708ULL,
		0xBF9BB743DA520A1DULL,
		0x41E009A9C6602E19ULL
	}};
	printf("Test Case 5\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 5 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -5;
	} else {
		printf("Test Case 5 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x573C50AD62EE31D1ULL,
		0x70A1A5EAC46234BCULL,
		0xE8A8743B76A2D50BULL,
		0x69A97882EBE1151AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5F312216D9405E98ULL,
		0x1024664CFD4BD7B7ULL,
		0xC4570DEB4742EE10ULL,
		0x74D95DF089CF2CBBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF80B2E9689ADD326ULL,
		0x607D3F9DC7165D04ULL,
		0x245166502F5FE6FBULL,
		0x74D01A926211E85FULL
	}};
	printf("Test Case 6\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 6 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -6;
	} else {
		printf("Test Case 6 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x825DCA59295778B3ULL,
		0x40D7377C9544F9B1ULL,
		0x3298B03533B5CEB2ULL,
		0x56F9DF90B4154E69ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x320938B3E15152AAULL,
		0x0C96FB5640E9C4DAULL,
		0xF0F1F2D54EB03AD6ULL,
		0x4A7723DC4D0FE66AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x505491A548062609ULL,
		0x34403C26545B34D7ULL,
		0x41A6BD5FE50593DCULL,
		0x0C82BBB4670567FEULL
	}};
	printf("Test Case 7\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 7 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -7;
	} else {
		printf("Test Case 7 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x88EA5A71DD60E1BCULL,
		0x5ED8E0F38FFB59A4ULL,
		0x84B8C1A2F99C8CE9ULL,
		0x523FAD233F8B7C7AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x32219728E1D1ECF7ULL,
		0xB049E6E511EA6BB4ULL,
		0x1FFC24D7D33C4029ULL,
		0x4E4886C21574C0DCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x56C8C348FB8EF4C5ULL,
		0xAE8EFA0E7E10EDF0ULL,
		0x64BC9CCB26604CBFULL,
		0x03F726612A16BB9EULL
	}};
	printf("Test Case 8\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 8 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -8;
	} else {
		printf("Test Case 8 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x36738442A6E2E70FULL,
		0x7B10C91066A0B704ULL,
		0xABF024ACB06D07BBULL,
		0x48C0B44AB0D27E79ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE9C920BE8CB78C86ULL,
		0xF79E3DF960E47C43ULL,
		0xA4A4E7C91FD18436ULL,
		0x28EF1FA39D30B099ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4CAA63841A2B5A89ULL,
		0x83728B1705BC3AC0ULL,
		0x074B3CE3909B8384ULL,
		0x1FD194A713A1CDE0ULL
	}};
	printf("Test Case 9\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 9 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -9;
	} else {
		printf("Test Case 9 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD53CE87B3395C730ULL,
		0x9CC3725CF413D0A0ULL,
		0x795DA90063763D9FULL,
		0x659CE5FDEEDDD846ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3EA6C56CF80F5BD5ULL,
		0xDF5732D91ADCC8CBULL,
		0x63D7A7BF81F841ECULL,
		0x7A8F8A06166C55FAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9696230E3B866B48ULL,
		0xBD6C3F83D93707D5ULL,
		0x15860140E17DFBB2ULL,
		0x6B0D5BF7D871824CULL
	}};
	printf("Test Case 10\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 10 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -10;
	} else {
		printf("Test Case 10 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x613A32A217FAD38CULL,
		0xF2F57355A9C9F907ULL,
		0xFD6094F93E0D55A4ULL,
		0x65716BBE866D61EFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7E129CC7CF0CC730ULL,
		0x506B19D412593923ULL,
		0x5F6CBCDF408C5D42ULL,
		0x2A32817E6C0FEC97ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE32795DA48EE0C5CULL,
		0xA28A59819770BFE3ULL,
		0x9DF3D819FD80F862ULL,
		0x3B3EEA401A5D7558ULL
	}};
	printf("Test Case 11\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 11 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -11;
	} else {
		printf("Test Case 11 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7280DB135C07D1AAULL,
		0x6CA9102727346F8EULL,
		0xE7875DEB8D41F70BULL,
		0x16A705BD585E924CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x32570678FA575D9BULL,
		0xFC1FB431B41087B6ULL,
		0x16705022600EC80EULL,
		0x5D338608811492CFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4029D49A61B073FCULL,
		0x70895BF57323E7D8ULL,
		0xD1170DC92D332EFCULL,
		0x39737FB4D749FF7DULL
	}};
	printf("Test Case 12\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 12 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -12;
	} else {
		printf("Test Case 12 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x042774D28D90BE7EULL,
		0x58C771068073FEDBULL,
		0x87362095310DCE26ULL,
		0x4B6DC0C5D28BD0A3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x07E7C941435ADF7DULL,
		0x59B61353EECC4AF5ULL,
		0x971CFB2830ABA947ULL,
		0x2035142EC92B7D3CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFC3FAB914A35DF01ULL,
		0xFF115DB291A7B3E5ULL,
		0xF019256D006224DEULL,
		0x2B38AC9709605366ULL
	}};
	printf("Test Case 13\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 13 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -13;
	} else {
		printf("Test Case 13 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x86B34D7DEA1980FEULL,
		0xCD3BA771F9D5B5B1ULL,
		0xC70F8146846D348BULL,
		0x36D83085A0892E34ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9FFBA46CAE78D3ADULL,
		0xA27050C646E4D776ULL,
		0x73E28779F0E04A09ULL,
		0x35FCA399DCF3D3D1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE6B7A9113BA0AD51ULL,
		0x2ACB56ABB2F0DE3AULL,
		0x532CF9CC938CEA82ULL,
		0x00DB8CEBC3955A63ULL
	}};
	printf("Test Case 14\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 14 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -14;
	} else {
		printf("Test Case 14 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAF4D372A3BC8A604ULL,
		0x27F729385D17EFF9ULL,
		0x1F5980963EE1BB77ULL,
		0x1D4A4781A2C492A9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7E32BF77D8B23A97ULL,
		0x90146552450E2A71ULL,
		0x3EA5188D31D34333ULL,
		0x342ABB2DCE488400ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x311A77B263166B5AULL,
		0x97E2C3E61809C588ULL,
		0xE0B468090D0E7843ULL,
		0x691F8C53D47C0EA8ULL
	}};
	printf("Test Case 15\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 15 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -15;
	} else {
		printf("Test Case 15 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9EFECDC9A86604A8ULL,
		0xE0C36642E885B113ULL,
		0x56CF3D358B22A618ULL,
		0x799F844DAA4AB76CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x87C25C1A5F9082ECULL,
		0x2BFCCEF20FB64996ULL,
		0xF47F86299BA6F52EULL,
		0x52039E8A2906F989ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x173C71AF48D581BCULL,
		0xB4C69750D8CF677DULL,
		0x624FB70BEF7BB0EAULL,
		0x279BE5C38143BDE2ULL
	}};
	printf("Test Case 16\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 16 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -16;
	} else {
		printf("Test Case 16 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3420E560041307C2ULL,
		0xBA86272A32E9BE29ULL,
		0x5476AF7C85F6D423ULL,
		0x565F3EE714CAF74FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAB31977D8489CE53ULL,
		0xA8B3E6333BE6295DULL,
		0xBF68106F78207B1FULL,
		0x75B1D6B527B3EDDBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x88EF4DE27F89395CULL,
		0x11D240F6F70394CBULL,
		0x950E9F0D0DD65904ULL,
		0x60AD6831ED170973ULL
	}};
	printf("Test Case 17\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 17 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -17;
	} else {
		printf("Test Case 17 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x564ADB3898173508ULL,
		0xFD325CDEC7964F08ULL,
		0x6BF998960376880FULL,
		0x0187BB786DC1C98CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEAAFC98CDFA71E81ULL,
		0xAD2FBC3AC956DD42ULL,
		0x350E8302D9F1D981ULL,
		0x7D82D1E5D04FFD5AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6B9B11ABB8701674ULL,
		0x5002A0A3FE3F71C5ULL,
		0x36EB15932984AE8EULL,
		0x0404E9929D71CC32ULL
	}};
	printf("Test Case 18\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 18 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -18;
	} else {
		printf("Test Case 18 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0B26CE74A54C46E6ULL,
		0x38D9833759889AB6ULL,
		0x12DA258AD3C10B8AULL,
		0x4D9BC96CD028C394ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE1E69C58AD146268ULL,
		0x81AC55A1574AB04FULL,
		0x0686501AE3BC2EC6ULL,
		0x4E172AF83DF28F01ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2940321BF837E46BULL,
		0xB72D2D96023DEA66ULL,
		0x0C53D56FF004DCC3ULL,
		0x7F849E7492363493ULL
	}};
	printf("Test Case 19\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 19 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -19;
	} else {
		printf("Test Case 19 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB91F271B959D421FULL,
		0x0A37894BE6D1B65DULL,
		0x960D1DA1C94F13AFULL,
		0x7D9E29A2B14F456DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDD2FC9258242E94BULL,
		0xCC8C909D572BBFB1ULL,
		0x2914211C390D42A5ULL,
		0x6EB596E4C0EC957DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDBEF5DF6135A58D4ULL,
		0x3DAAF8AE8FA5F6ABULL,
		0x6CF8FC859041D109ULL,
		0x0EE892BDF062AFF0ULL
	}};
	printf("Test Case 20\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 20 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -20;
	} else {
		printf("Test Case 20 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2935A990E92D8C39ULL,
		0x2F0D3D74C11EC1EEULL,
		0xADE591E8C083BF2BULL,
		0x6CD1E119E8FDCD5CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xACD82FB2BA20FA19ULL,
		0xB3BFF1874983A3F6ULL,
		0x17ABEBB0FE7B387EULL,
		0x120F838B49110C8BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7C5D79DE2F0C9220ULL,
		0x7B4D4BED779B1DF7ULL,
		0x9639A637C20886ACULL,
		0x5AC25D8E9FECC0D1ULL
	}};
	printf("Test Case 21\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 21 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -21;
	} else {
		printf("Test Case 21 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7CA048D8F878582BULL,
		0x3A4CA01E68C92707ULL,
		0xA4CC7B6BE09BC066ULL,
		0x454F24116175624BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFDB2D3C68C8D1CE3ULL,
		0x73A66BCC03F390F2ULL,
		0xA873A7285D076B5FULL,
		0x333275835901CCCAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7EED75126BEB3B48ULL,
		0xC6A6345264D59614ULL,
		0xFC58D44383945506ULL,
		0x121CAE8E08739580ULL
	}};
	printf("Test Case 22\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 22 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -22;
	} else {
		printf("Test Case 22 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1FE8B3FC3A4B021CULL,
		0xE4ED4A55E08000A0ULL,
		0xDD33F730D8A05227ULL,
		0x4B1423FDC117B95AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA861C6208DB25284ULL,
		0x249946553FC5AA8FULL,
		0x7092AD473B3A8CAFULL,
		0x3AC128756706E532ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7786EDDBAC98AF98ULL,
		0xC0540400A0BA5610ULL,
		0x6CA149E99D65C578ULL,
		0x1052FB885A10D428ULL
	}};
	printf("Test Case 23\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 23 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -23;
	} else {
		printf("Test Case 23 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x07E885489BB4A120ULL,
		0x4AE285B429092EC8ULL,
		0xCADA9F92C5EB14FAULL,
		0x7AE68CEE44A4AE82ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x37E1C96A94045212ULL,
		0x7AB3754FDA2C9633ULL,
		0x566186A1BB373DC7ULL,
		0x15E4281DB07103E4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD006BBDE07B04F0EULL,
		0xD02F10644EDC9894ULL,
		0x747918F10AB3D732ULL,
		0x650264D09433AA9EULL
	}};
	printf("Test Case 24\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 24 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -24;
	} else {
		printf("Test Case 24 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0DB917B49DE8AA56ULL,
		0x6799BE23B7AA9A2AULL,
		0x359AA29652B7387AULL,
		0x3BC05E8A8149D85DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF48BD5BC7504F051ULL,
		0x37E17A28F80482CDULL,
		0x6D94C8C77CD318AAULL,
		0x0A9414CAC0EBB42BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x192D41F828E3BA05ULL,
		0x2FB843FABFA6175CULL,
		0xC805D9CED5E41FD0ULL,
		0x312C49BFC05E2431ULL
	}};
	printf("Test Case 25\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 25 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -25;
	} else {
		printf("Test Case 25 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x44988A953E50B763ULL,
		0xA1350DB06B9F603AULL,
		0x7F8C6A06A87410D9ULL,
		0x08E66007D88BBB7EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x67FDCC0BFEA5C282ULL,
		0x66348AB22E937C76ULL,
		0x1F1D560DB61C3ECDULL,
		0x750AC501FF19BDCBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDC9ABE893FAAF4CEULL,
		0x3B0082FE3D0BE3C3ULL,
		0x606F13F8F257D20CULL,
		0x13DB9B05D971FDB3ULL
	}};
	printf("Test Case 26\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 26 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -26;
	} else {
		printf("Test Case 26 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE7770B443A4ACDD7ULL,
		0x4834919833A36259ULL,
		0xC70AE7538873A74FULL,
		0x1629CADA34D24FD3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9777CBCD95DE61CBULL,
		0x3047F403C808E084ULL,
		0x48154A8B765DD65CULL,
		0x5D187C8C33315A83ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4FFF3F76A46C6BF9ULL,
		0x17EC9D946B9A81D5ULL,
		0x7EF59CC81215D0F3ULL,
		0x39114E4E01A0F550ULL
	}};
	printf("Test Case 27\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 27 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -27;
	} else {
		printf("Test Case 27 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC079870814DDFB37ULL,
		0xD26E29DDF7B3908AULL,
		0x8CDA111D51919848ULL,
		0x443153F5A4503593ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB74246A912C1506AULL,
		0xE6E1D722F3E7B6F1ULL,
		0xF5CC38C0BF501BC8ULL,
		0x41A3CF9CA1CDC203ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0937405F021CAACDULL,
		0xEB8C52BB03CBD999ULL,
		0x970DD85C92417C7FULL,
		0x028D84590282738FULL
	}};
	printf("Test Case 28\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 28 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -28;
	} else {
		printf("Test Case 28 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x96DC5259501B51AEULL,
		0x8A59168A74D25656ULL,
		0x2E3444D4EBC384BEULL,
		0x389D829D76B8EB05ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCD26641CFBEA722EULL,
		0xAD327501E7411979ULL,
		0xAA230EFB1A7DF6E6ULL,
		0x5E7364F4EE48A3ECULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC9B5EE3C5430DF6DULL,
		0xDD26A1888D913CDCULL,
		0x841135D9D1458DD7ULL,
		0x5A2A1DA888704718ULL
	}};
	printf("Test Case 29\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 29 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -29;
	} else {
		printf("Test Case 29 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD571526995903D8CULL,
		0x5A84D5F3E6DE0316ULL,
		0x4E2ACD83DC38889BULL,
		0x2D6DB8B381B2D9CFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEAFADE249BE955C4ULL,
		0x51B1236C12232636ULL,
		0x7EA514C12FA2841BULL,
		0x580E494FA497D60AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEA767444F9A6E7B5ULL,
		0x08D3B287D4BADCDFULL,
		0xCF85B8C2AC960480ULL,
		0x555F6F63DD1B03C4ULL
	}};
	printf("Test Case 30\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 30 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -30;
	} else {
		printf("Test Case 30 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD66442D4B63ECA34ULL,
		0x62EC4A6469229F77ULL,
		0xD6833C2F0525BC6AULL,
		0x6D1F19A92A8959A8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1BEBB4D38C6D1FDBULL,
		0xBA23B811BAB1F43EULL,
		0x44770B1FF6A69496ULL,
		0x4F881240B4F39347ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBA788E0129D1AA59ULL,
		0xA8C89252AE70AB39ULL,
		0x920C310F0E7F27D3ULL,
		0x1D9707687595C661ULL
	}};
	printf("Test Case 31\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 31 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -31;
	} else {
		printf("Test Case 31 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCDDE234B921EBE47ULL,
		0x7A9D6667930EA2D6ULL,
		0x0E772B963CD684F2ULL,
		0x47CA69190369A269ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1303A55D83FD1CBDULL,
		0x96954EBEE91739BAULL,
		0x0B4032FF57A1A2E3ULL,
		0x42B427200F0DC7D2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBADA7DEE0E21A18AULL,
		0xE40817A8A9F7691CULL,
		0x0336F896E534E20EULL,
		0x051641F8F45BDA97ULL
	}};
	printf("Test Case 32\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 32 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -32;
	} else {
		printf("Test Case 32 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1591FE0FF133D4D4ULL,
		0xDDE673610A53750AULL,
		0x0B87E3A9B91378E1ULL,
		0x37D85255287E13B9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4728C068051BE577ULL,
		0xE52FC416771BA0DCULL,
		0xFB62BD8BA8D77231ULL,
		0x1CD5616F4E1177C5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCE693DA7EC17EF5DULL,
		0xF8B6AF4A9337D42DULL,
		0x1025261E103C06AFULL,
		0x1B02F0E5DA6C9BF3ULL
	}};
	printf("Test Case 33\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 33 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -33;
	} else {
		printf("Test Case 33 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA38BD9A7DFCC0099ULL,
		0x596EEE899E9F178BULL,
		0x9D070FA3D1FAB01BULL,
		0x40E1FD095208771CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x20765E8FEB7D91CEULL,
		0xCB15DB09C6FA1B23ULL,
		0xD2CABDAA4C170CEEULL,
		0x637AFFE5D4660919ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x83157B17F44E6EB8ULL,
		0x8E59137FD7A4FC68ULL,
		0xCA3C51F985E3A32CULL,
		0x5D66FD237DA26E02ULL
	}};
	printf("Test Case 34\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 34 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -34;
	} else {
		printf("Test Case 34 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF5FCC1729D780C23ULL,
		0xAC481AF3123A306FULL,
		0x9E83E8DC9BCFEE6DULL,
		0x442B243755AFE85BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFD192F14F90F2DB7ULL,
		0xFCDFFA43D42005B9ULL,
		0x31FE724029D1494EULL,
		0x698BA3C45645E162ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF8E3925DA468DE59ULL,
		0xAF6820AF3E1A2AB5ULL,
		0x6C85769C71FEA51EULL,
		0x5A9F8072FF6A06F9ULL
	}};
	printf("Test Case 35\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 35 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -35;
	} else {
		printf("Test Case 35 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x66659BA8D2F7C8DEULL,
		0xD6E0B7DB3AFFB94CULL,
		0xD63A65D196E16465ULL,
		0x7B9CC4894DF4B68FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5758E95E22DBA2DEULL,
		0xFF5D46721AD05A92ULL,
		0x1C264DB5286E9A83ULL,
		0x5BF3D0D7085CA442ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0F0CB24AB01C2600ULL,
		0xD7837169202F5EBAULL,
		0xBA14181C6E72C9E1ULL,
		0x1FA8F3B24598124DULL
	}};
	printf("Test Case 36\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 36 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -36;
	} else {
		printf("Test Case 36 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9E1F57567D8E6D8EULL,
		0x66C486139F08790EULL,
		0x2244AD6822C43FEBULL,
		0x676B25D3EC129609ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x45B4809D7E3B4BB2ULL,
		0x130965C3E9FB316DULL,
		0xB55320209CE074EDULL,
		0x7A2AB99FCDA11109ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x586AD6B8FF5321C9ULL,
		0x53BB204FB50D47A1ULL,
		0x6CF18D4785E3CAFEULL,
		0x6D406C341E7184FFULL
	}};
	printf("Test Case 37\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 37 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -37;
	} else {
		printf("Test Case 37 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC507571E8C1DCAA7ULL,
		0x6A2FE17AC08BDDBBULL,
		0x955FAA9088A5906BULL,
		0x4FA7D27276ED20B0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF99AE9A05A8C77D2ULL,
		0x602C9EA0A102988EULL,
		0xD69EFCC208FCB3AEULL,
		0x717B13732CD076D9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCB6C6D7E319152C2ULL,
		0x0A0342DA1F89452CULL,
		0xBEC0ADCE7FA8DCBDULL,
		0x5E2CBEFF4A1CA9D6ULL
	}};
	printf("Test Case 38\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 38 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -38;
	} else {
		printf("Test Case 38 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB01726067468C837ULL,
		0xFA94C23370A14D20ULL,
		0xFF401625C0B5A3C7ULL,
		0x7E39DD5FE841C90DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB8D27A755143F2C7ULL,
		0xCE44EC341D90FEF8ULL,
		0x347937D2962D23A4ULL,
		0x221A6890AA32FDC7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF744AB912324D570ULL,
		0x2C4FD5FF53104E27ULL,
		0xCAC6DE532A888023ULL,
		0x5C1F74CF3E0ECB46ULL
	}};
	printf("Test Case 39\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 39 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -39;
	} else {
		printf("Test Case 39 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE99E7AD71DC22E09ULL,
		0xA930AE67C4C32146ULL,
		0xD1DA9D784AC59845ULL,
		0x45AB75D09289A1B2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDE82BD55286F68D7ULL,
		0x3130CAA9680B3E34ULL,
		0xB9CDC5A00E580BA8ULL,
		0x2E2D75E90DBA595FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0B1BBD81F552C532ULL,
		0x77FFE3BE5CB7E312ULL,
		0x180CD7D83C6D8C9DULL,
		0x177DFFE784CF4853ULL
	}};
	printf("Test Case 40\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 40 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -40;
	} else {
		printf("Test Case 40 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x58B2CF16D5CED0B2ULL,
		0xAC684846E51A887FULL,
		0x753B4C15882F5FE0ULL,
		0x6ACC66ACFC1069E3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8D6B237BC6FDD829ULL,
		0xBE4580EE8E14C9F0ULL,
		0x516DE9A551505011ULL,
		0x62BFA22C763840A8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCB47AB9B0ED0F889ULL,
		0xEE22C7585705BE8EULL,
		0x23CD627036DF0FCEULL,
		0x080CC48085D8293BULL
	}};
	printf("Test Case 41\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 41 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -41;
	} else {
		printf("Test Case 41 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF0365B39D2A44CACULL,
		0xD7A378DB4BC0FA0BULL,
		0xB1F46742F95217CAULL,
		0x4405DD54A74F2611ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC726AE2A95ADF812ULL,
		0x8B3AFD7DC95A6DDEULL,
		0x8D59870442A625C4ULL,
		0x0F62C063726033F4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x290FAD0F3CF6549AULL,
		0x4C687B5D82668C2DULL,
		0x249AE03EB6ABF206ULL,
		0x34A31CF134EEF21DULL
	}};
	printf("Test Case 42\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 42 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -42;
	} else {
		printf("Test Case 42 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7387428F44F36781ULL,
		0xA99D76154E7B0E77ULL,
		0x13BD075358CB5E71ULL,
		0x506EBBED325BF3B5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF0D9FF53AE7D1042ULL,
		0xF3385E3A111A2E2EULL,
		0x52EFC0150BE32737ULL,
		0x146848275BCEE8FAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x82AD433B9676573FULL,
		0xB66517DB3D60E048ULL,
		0xC0CD473E4CE83739ULL,
		0x3C0673C5D68D0ABAULL
	}};
	printf("Test Case 43\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 43 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -43;
	} else {
		printf("Test Case 43 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x86AA143D26CA7FADULL,
		0xE9C288C3CA507FA0ULL,
		0x4CA5054A80A65BAFULL,
		0x16AE5520B0821B29ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD7CD6A07956F2335ULL,
		0x6CD82C147C9A3CC3ULL,
		0x59F23EB1C32A1DF7ULL,
		0x5AD939CE5D3BF3DCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAEDCAA35915B5C65ULL,
		0x7CEA5CAF4DB642DCULL,
		0xF2B2C698BD7C3DB8ULL,
		0x3BD51B525346274CULL
	}};
	printf("Test Case 44\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 44 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -44;
	} else {
		printf("Test Case 44 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x60178CF86C636A54ULL,
		0x342A53695304E7ECULL,
		0xC53F8E48373E79CAULL,
		0x47385DC0E58F2781ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x45BFAF5776F02F2AULL,
		0xE6D9DFDF4E9BC463ULL,
		0x0F7BBB6144A0D5B7ULL,
		0x33EC05371E2600F3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1A57DDA0F5733B2AULL,
		0x4D50738A04692389ULL,
		0xB5C3D2E6F29DA412ULL,
		0x134C5889C769268EULL
	}};
	printf("Test Case 45\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 45 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -45;
	} else {
		printf("Test Case 45 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDCC40A73AC8D208FULL,
		0x6B3E81A91B73E49AULL,
		0x7F1D7164314B93AEULL,
		0x190C2825119A9031ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBD1D5F84A1F06366ULL,
		0xBA748FAB976F1DC9ULL,
		0x0FAF4789F16162F1ULL,
		0x2118ED3F883EB1F4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1FA6AAEF0A9CBD16ULL,
		0xB0C9F1FD8404C6D1ULL,
		0x6F6E29DA3FEA30BCULL,
		0x77F33AE5895BDE3DULL
	}};
	printf("Test Case 46\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 46 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -46;
	} else {
		printf("Test Case 46 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4E267E357168F5ECULL,
		0xAB336FDA89F91F11ULL,
		0x80AD5F30625367F0ULL,
		0x653C50220F6AF214ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6CF791B5A38D6C8EULL,
		0x517326D7F0AB9B32ULL,
		0x362E47584E414EEFULL,
		0x2E71190342B02610ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE12EEC7FCDDB895EULL,
		0x59C04902994D83DEULL,
		0x4A7F17D814121901ULL,
		0x36CB371ECCBACC04ULL
	}};
	printf("Test Case 47\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 47 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -47;
	} else {
		printf("Test Case 47 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA75233C3F013DB71ULL,
		0x15571AA673C7B108ULL,
		0xC97F1A15ED75D930ULL,
		0x12F4CA8412FD6699ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5CB98F449B4F6731ULL,
		0x08CD1843FBEBD644ULL,
		0xF067082EF82E37E9ULL,
		0x3CD3A923BDD62875ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4A98A47F54C4742DULL,
		0x0C8A026277DBDAC4ULL,
		0xD91811E6F547A147ULL,
		0x5621216055273E23ULL
	}};
	printf("Test Case 48\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 48 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -48;
	} else {
		printf("Test Case 48 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x45ECB2A972F46389ULL,
		0xE39C84C17E1DDE43ULL,
		0x28D74625BA2F7CEDULL,
		0x38B2F49059C86D5EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x93FEA3F1F3DC52F3ULL,
		0x859766D8619E1B95ULL,
		0x501634C43F1890B1ULL,
		0x0862DEE8921122E2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB1EE0EB77F181096ULL,
		0x5E051DE91C7FC2ADULL,
		0xD8C111617B16EC3CULL,
		0x305015A7C7B74A7BULL
	}};
	printf("Test Case 49\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 49 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -49;
	} else {
		printf("Test Case 49 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAA8C4AAA15D85752ULL,
		0xDBB24E5C9144974AULL,
		0xC84BED9237DF9256ULL,
		0x343B0A6AFC302C9EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA9F75C153F54BBA2ULL,
		0xFA97CA2843C5E8B1ULL,
		0x7DC508D446CDF9B9ULL,
		0x44B56A20D7927538ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0094EE94D6839B9DULL,
		0xE11A84344D7EAE99ULL,
		0x4A86E4BDF111989CULL,
		0x6F85A04A249DB766ULL
	}};
	printf("Test Case 50\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 50 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -50;
	} else {
		printf("Test Case 50 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB0115CF9413275FCULL,
		0xF24A90920BBC0002ULL,
		0xAFDB03D7310CCE17ULL,
		0x3562CECCEE12212CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEB44EE05B0C41611ULL,
		0xE402F11EC51C501CULL,
		0x4DBEB4F0FDE1E9D7ULL,
		0x00D1ACA51F39EF6DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC4CC6EF3906E5FEBULL,
		0x0E479F73469FAFE5ULL,
		0x621C4EE6332AE440ULL,
		0x34912227CED831BFULL
	}};
	printf("Test Case 51\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 51 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -51;
	} else {
		printf("Test Case 51 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1243D852D7BCD6B6ULL,
		0xB72DC9637F8C46ADULL,
		0x8DF1C9ECE81008F7ULL,
		0x19D29B23B773EFEBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDA4DB7F27DBD8DBDULL,
		0x19F719B343B1BE68ULL,
		0x84D7BE89C7D845CEULL,
		0x4749B436B06C0C61ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x37F6206059FF48E6ULL,
		0x9D36AFB03BDA8844ULL,
		0x091A0B632037C329ULL,
		0x5288E6ED0707E38AULL
	}};
	printf("Test Case 52\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 52 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -52;
	} else {
		printf("Test Case 52 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x46BE0DE9A8EE9452ULL,
		0xD1620FAE2C84369AULL,
		0x64A8CEA94E11C085ULL,
		0x20783E642231530AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE9FD6E8CD069B8A6ULL,
		0xA337D9026B57D0A9ULL,
		0x5EEFD058A6A9706BULL,
		0x3609B71F2A7E6E80ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5CC09F5CD884DB99ULL,
		0x2E2A36ABC12C65F0ULL,
		0x05B8FE50A768501AULL,
		0x6A6E8744F7B2E48AULL
	}};
	printf("Test Case 53\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 53 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -53;
	} else {
		printf("Test Case 53 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8F3E25DA6AF1B24CULL,
		0x3F6C384C0EDF37CAULL,
		0x08874B5B668D1FFAULL,
		0x702EB8ABC1F655B6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA25729D5FF07DA72ULL,
		0x23DA69104C7BF786ULL,
		0x217B132164D15153ULL,
		0x12CD1795534365AFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xECE6FC046BE9D7DAULL,
		0x1B91CF3BC2634043ULL,
		0xE70C383A01BBCEA7ULL,
		0x5D61A1166EB2F006ULL
	}};
	printf("Test Case 54\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 54 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -54;
	} else {
		printf("Test Case 54 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA7012FA174459E8CULL,
		0xB0546AF51592C8BFULL,
		0x627F4F9007B9B85EULL,
		0x7E45B0EDEDDA48F6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA60D669938AFCC4CULL,
		0x64F7C8B7B91B111FULL,
		0x8688177A8BBBB2D4ULL,
		0x753F3EA06531B6FFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x00F3C9083B95D240ULL,
		0x4B5CA23D5C77B7A0ULL,
		0xDBF738157BFE058AULL,
		0x0906724D88A891F6ULL
	}};
	printf("Test Case 55\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 55 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -55;
	} else {
		printf("Test Case 55 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5B974303A3D06C8AULL,
		0x8E35A1DB308907EDULL,
		0x4000BC85B020FB05ULL,
		0x30FB7FD8CA02B60BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD10D415365F51593ULL,
		0x696F4ACD02BB2F34ULL,
		0x78F94B2431B5C114ULL,
		0x6F8E4EBF2D6BA00CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8A8A01B03DDB56E4ULL,
		0x24C6570E2DCDD8B8ULL,
		0xC70771617E6B39F1ULL,
		0x416D31199C9715FEULL
	}};
	printf("Test Case 56\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 56 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -56;
	} else {
		printf("Test Case 56 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAE8FF7B0CC290DD7ULL,
		0xB109FFB0A1884BD9ULL,
		0xE396F17261C44A62ULL,
		0x2A0D7B3D4CE0E686ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x02883883239C4E41ULL,
		0xB69ABCC515DAE831ULL,
		0x6C0870C7A0EC9C3EULL,
		0x277A568BF6F5EC02ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAC07BF2DA88CBF96ULL,
		0xFA6F42EB8BAD63A8ULL,
		0x778E80AAC0D7AE23ULL,
		0x029324B155EAFA84ULL
	}};
	printf("Test Case 57\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 57 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -57;
	} else {
		printf("Test Case 57 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2A1587E6A87440E4ULL,
		0x3D6CBA7901A93EDEULL,
		0x33968AD7CEDD8EF7ULL,
		0x25273F19A562A327ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0C3DF6C123EE64C8ULL,
		0x583EE67C0C8FCC84ULL,
		0x3FD6516EB27A1777ULL,
		0x7BF0DC7DEC4CEDCFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1DD791258485DC09ULL,
		0xE52DD3FCF519725AULL,
		0xF3C039691C63777FULL,
		0x2936629BB915B557ULL
	}};
	printf("Test Case 58\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 58 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -58;
	} else {
		printf("Test Case 58 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x40516B32D66519C6ULL,
		0x2A71963BE319A3DDULL,
		0x2074022F1FC4D2D4ULL,
		0x7E0A921ADF446390ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x88E4D526C2C4BC5BULL,
		0x6615B4DDA5BCAC77ULL,
		0xA313296B3623D25CULL,
		0x355A2E70B0B96CA3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB76C960C13A05D6BULL,
		0xC45BE15E3D5CF765ULL,
		0x7D60D8C3E9A10077ULL,
		0x48B063AA2E8AF6ECULL
	}};
	printf("Test Case 59\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 59 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -59;
	} else {
		printf("Test Case 59 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x943912E0E9EC066AULL,
		0xEC3E97E63D0FB014ULL,
		0xCC6D522C8238C4C4ULL,
		0x6C4FEAE72FEA9183ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB311D0912F484633ULL,
		0x727DAC7501F64DE6ULL,
		0x1713763898A1600FULL,
		0x7993A70755DB37C4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE127424FBAA3C024ULL,
		0x79C0EB713B19622DULL,
		0xB559DBF3E99764B5ULL,
		0x72BC43DFDA0F59BFULL
	}};
	printf("Test Case 60\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 60 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -60;
	} else {
		printf("Test Case 60 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7BDAAB9E214CCE80ULL,
		0x6A00CA6AB7359EB2ULL,
		0x711C99A3ECCBBEEBULL,
		0x6AE473AD0EC349CEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x67EDF4FBF0BE1DF4ULL,
		0xAA4600CF1FF1E90AULL,
		0x9A614C458D692248ULL,
		0x1382FB12B6214264ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x13ECB6A2308EB08CULL,
		0xBFBAC99B9743B5A8ULL,
		0xD6BB4D5E5F629CA2ULL,
		0x5761789A58A20769ULL
	}};
	printf("Test Case 61\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 61 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -61;
	} else {
		printf("Test Case 61 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6DC2118C5F24D3D0ULL,
		0x3B9D2F1CC0C137D1ULL,
		0x70BB1098D076D334ULL,
		0x2CB661C7D2D16FDBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x03ED38AB1171D60AULL,
		0x70FDF1CBBBF63BBDULL,
		0xF42962447E9F72F5ULL,
		0x307BEB45231B55DDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x69D4D8E14DB2FDB3ULL,
		0xCA9F3D5104CAFC14ULL,
		0x7C91AE5451D7603EULL,
		0x7C3A7682AFB619FDULL
	}};
	printf("Test Case 62\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 62 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -62;
	} else {
		printf("Test Case 62 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC8B552A1B5C777B2ULL,
		0x7EB192A7509C4DFFULL,
		0x5F92147C5922AA08ULL,
		0x77F6E59B0B1AD20BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x105DD62E61639281ULL,
		0xCC8794335C86F5E5ULL,
		0x670724860BF2202EULL,
		0x01C79090FD663756ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB8577C735463E531ULL,
		0xB229FE73F415581AULL,
		0xF88AEFF64D3089D9ULL,
		0x762F550A0DB49AB4ULL
	}};
	printf("Test Case 63\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 63 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -63;
	} else {
		printf("Test Case 63 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC7CBC93D372146ADULL,
		0x94F3219749A76C3BULL,
		0xE3148350C7DF7A06ULL,
		0x09F47A1DB399B5A2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD329483EFEC93210ULL,
		0xA6C07B88DBEFDE77ULL,
		0x370C13CB44EAB34AULL,
		0x20617839C9132177ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF4A280FE3858148AULL,
		0xEE32A60E6DB78DC3ULL,
		0xAC086F8582F4C6BBULL,
		0x699301E3EA86942BULL
	}};
	printf("Test Case 64\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 64 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -64;
	} else {
		printf("Test Case 64 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9F751A66D458F6F6ULL,
		0x2DAC97E5640AADB1ULL,
		0x31C948786CE60876ULL,
		0x681D77300C7B56C8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA72029402120B7A6ULL,
		0x038A60081A921426ULL,
		0x433E449BF23DE577ULL,
		0x76A60A640F6D8724ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF854F126B3383F3DULL,
		0x2A2237DD4978998AULL,
		0xEE8B03DC7AA822FFULL,
		0x71776CCBFD0DCFA3ULL
	}};
	printf("Test Case 65\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 65 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -65;
	} else {
		printf("Test Case 65 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x71C99A80883ECDE8ULL,
		0xAD797E6E17CE8DE8ULL,
		0x818B94D6F75A8E1CULL,
		0x4291E4B973908EADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xADA174D548FC0BA7ULL,
		0xBDC108878D07469FULL,
		0x7FFFFED53D2403EFULL,
		0x41849B5919114CEFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC42825AB3F42C241ULL,
		0xEFB875E68AC74748ULL,
		0x018B9601BA368A2CULL,
		0x010D49605A7F41BEULL
	}};
	printf("Test Case 66\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 66 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -66;
	} else {
		printf("Test Case 66 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x16C17FB02011DCFAULL,
		0x7892BA7F16BDFF68ULL,
		0x79C72C499F0B0A51ULL,
		0x1A1D4B6BBE4EA959ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4E688D18E1187370ULL,
		0xE85B7CED77D10D0AULL,
		0x3D8F2C27CEE0FC1BULL,
		0x519B523A6869792FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC858F2973EF96977ULL,
		0x90373D919EECF25DULL,
		0x3C380021D02A0E35ULL,
		0x4881F93155E5302AULL
	}};
	printf("Test Case 67\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 67 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -67;
	} else {
		printf("Test Case 67 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFBCD27DDE7E0BC7FULL,
		0x49F3742B12B7F477ULL,
		0x7ADB595EA72A7C33ULL,
		0x06CA19DBB474F057ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x83E9086C2906C8ABULL,
		0x76153C4ABC3495CBULL,
		0x2330BDEBCD0D49B3ULL,
		0x6A065BA89FE462E2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x77E41F71BED9F3C1ULL,
		0xD3DE37E056835EACULL,
		0x57AA9B72DA1D327FULL,
		0x1CC3BE3314908D75ULL
	}};
	printf("Test Case 68\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 68 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -68;
	} else {
		printf("Test Case 68 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2E866FCE27CECC69ULL,
		0xDFC17B5BC4FB1731ULL,
		0x420E3C0054BE5C0AULL,
		0x1D8FBF858CFAD42AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC7A12BFE8AC62373ULL,
		0x2C2F071C389D5ADBULL,
		0x52B3BDA2CCC274D7ULL,
		0x7E78B0B94FF46998ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x66E543CF9D08A8E3ULL,
		0xB392743F8C5DBC55ULL,
		0xEF5A7E5D87FBE733ULL,
		0x1F170ECC3D066A91ULL
	}};
	printf("Test Case 69\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 69 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -69;
	} else {
		printf("Test Case 69 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4AC247154FB36FE5ULL,
		0x4D38E19CE4A3F321ULL,
		0xD49DD7ED7EA25A00ULL,
		0x4CB39F081ED4E85DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x121449C7124D5942ULL,
		0xF7510865386692F3ULL,
		0xF4A3240661F4E0ECULL,
		0x6028A8130044ED9FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x38ADFD4E3D661690ULL,
		0x55E7D937AC3D602EULL,
		0xDFFAB3E71CAD7913ULL,
		0x6C8AF6F51E8FFABDULL
	}};
	printf("Test Case 70\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 70 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -70;
	} else {
		printf("Test Case 70 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDFC62FA4F00CB94EULL,
		0xBA81044DD2EAED86ULL,
		0x94EF4E504AF1AF23ULL,
		0x3478D1ACC01EC740ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x048E28A25592497DULL,
		0xDDA31FC25E019773ULL,
		0xBDEFD13D5E791E68ULL,
		0x52FB70F72DE9C09FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDB3807029A7A6FBEULL,
		0xDCDDE48B74E95613ULL,
		0xD6FF7D12EC7890BAULL,
		0x617D60B5923506A0ULL
	}};
	printf("Test Case 71\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 71 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -71;
	} else {
		printf("Test Case 71 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCE393C7E16A2EB18ULL,
		0x3444C5FAF1829070ULL,
		0x89FAACD05B663B1EULL,
		0x6863AC4911F2D64FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCA96F79E08D5511FULL,
		0x311ECD76A41F94B9ULL,
		0x8110B8CA0B78C279ULL,
		0x514BB9C72E978932ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x03A244E00DCD99F9ULL,
		0x0325F8844D62FBB7ULL,
		0x08E9F4064FED78A5ULL,
		0x1717F281E35B4D1DULL
	}};
	printf("Test Case 72\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 72 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -72;
	} else {
		printf("Test Case 72 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x69825DAA602D1A3BULL,
		0x62294FD23B1E51E6ULL,
		0x1DE71D649828F1DDULL,
		0x68DBAB921DB0D45AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7496596A21AB0DA4ULL,
		0x63B29669BA8B06DCULL,
		0x9505BE59D52FC2D8ULL,
		0x4EDCA844FC4C8D16ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF4EC04403E820C97ULL,
		0xFE76B96880934B09ULL,
		0x88E15F0AC2F92F04ULL,
		0x19FF034D21644743ULL
	}};
	printf("Test Case 73\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 73 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -73;
	} else {
		printf("Test Case 73 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6F0C597E6A599136ULL,
		0x8B5B0A413BC1982FULL,
		0xD5F1EDFA59584E4FULL,
		0x3D9DCA9E9121BA36ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5BD69894BCADD2C8ULL,
		0xA46B5CAF070A9AC5ULL,
		0x87175FAE9CBE1CECULL,
		0x0FAF76747D6B1AE3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1335C0E9ADABBE6EULL,
		0xE6EFAD9234B6FD6AULL,
		0x4EDA8E4BBC9A3162ULL,
		0x2DEE542A13B69F53ULL
	}};
	printf("Test Case 74\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 74 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -74;
	} else {
		printf("Test Case 74 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x57F7653FB51DB3F6ULL,
		0xAB96CCD1889BE2B4ULL,
		0x74938022759560ABULL,
		0x11869C8FF62A4C9EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC6F85C53B82520F3ULL,
		0x621555076F798758ULL,
		0x4EEA9B262C59EE48ULL,
		0x711F1D634C5FE29CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x90FF08EBFCF892F0ULL,
		0x498177CA19225B5BULL,
		0x25A8E4FC493B7263ULL,
		0x20677F2CA9CA6A02ULL
	}};
	printf("Test Case 75\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 75 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -75;
	} else {
		printf("Test Case 75 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x758E6CE9D2DAF256ULL,
		0xC09D6E5A7E2D3261ULL,
		0x5A7B26B9E273E995ULL,
		0x07709DF46E25517FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA96D453497EAC910ULL,
		0x5DAB6CDF65A5760AULL,
		0x61A17111A4C3CADAULL,
		0x6E58338493CA3A85ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCC2127B53AF02933ULL,
		0x62F2017B1887BC56ULL,
		0xF8D9B5A83DB01EBBULL,
		0x19186A6FDA5B16F9ULL
	}};
	printf("Test Case 76\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 76 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -76;
	} else {
		printf("Test Case 76 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x915F1E89FAF03254ULL,
		0xB2FDBFF0DF65A473ULL,
		0xE82F48DF6CD1ED9BULL,
		0x3DFF2A8E77B624EBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB2DD40D43101C105ULL,
		0xF48E7E3B57A88619ULL,
		0x3ED58AC783B9EF25ULL,
		0x2A24FA0DBE3EB302ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDE81DDB5C9EE714FULL,
		0xBE6F41B587BD1E59ULL,
		0xA959BE17E917FE75ULL,
		0x13DA3080B97771E9ULL
	}};
	printf("Test Case 77\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 77 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -77;
	} else {
		printf("Test Case 77 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB22ECC00FBD6A686ULL,
		0x91B40B34F0CAF718ULL,
		0xD0A2D6B49D449624ULL,
		0x0B344AFE6FFBFA7DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x155E85DDB1F58D88ULL,
		0x8B1153159ECD7941ULL,
		0xCB811440F3B13937ULL,
		0x00021FC56B187D75ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9CD0462349E118FEULL,
		0x06A2B81F51FD7DD7ULL,
		0x0521C273A9935CEDULL,
		0x0B322B3904E37D08ULL
	}};
	printf("Test Case 78\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 78 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -78;
	} else {
		printf("Test Case 78 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0F28500B7EF8D8A7ULL,
		0x47B2FF2ACD1EDCFAULL,
		0x0D6A3161C97B1AE2ULL,
		0x6E7088B5BA0AF998ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF2BBF6E37D98D61FULL,
		0x704BAA56BE9418A0ULL,
		0x8DC130AA8F908245ULL,
		0x11DD2A66F8592C04ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1C6C592801600288ULL,
		0xD76754D40E8AC459ULL,
		0x7FA900B739EA989CULL,
		0x5C935E4EC1B1CD93ULL
	}};
	printf("Test Case 79\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 79 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -79;
	} else {
		printf("Test Case 79 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2ECB6ED86706B8C1ULL,
		0x5544C9F7FF18B9ECULL,
		0x65B7A3C50E078C57ULL,
		0x6D361413ADC7B0C7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x64BDC31C53AE080FULL,
		0x685510EF92538FBFULL,
		0xBFDFF8730AC70B3AULL,
		0x70F7F5CA66C3268FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCA0DABBC1358B09FULL,
		0xECEFB9086CC52A2CULL,
		0xA5D7AB520340811CULL,
		0x7C3E1E4947048A37ULL
	}};
	printf("Test Case 80\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 80 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -80;
	} else {
		printf("Test Case 80 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xACA7093FBE71B03FULL,
		0xC8D042CCDB9B7787ULL,
		0x1577DDB255EBF26CULL,
		0x684F0E8348BF751EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x54D609725C09E742ULL,
		0x1A45FB1844C1AA8CULL,
		0xBCE27170623795EFULL,
		0x56DAA0F52CA1A587ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x57D0FFCD6267C8FDULL,
		0xAE8A47B496D9CCFBULL,
		0x58956C41F3B45C7DULL,
		0x11746D8E1C1DCF96ULL
	}};
	printf("Test Case 81\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 81 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -81;
	} else {
		printf("Test Case 81 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE5FE8CFEE708798BULL,
		0xBAD8EA8A639C394BULL,
		0x1EEFB5797AB13E15ULL,
		0x533BA999758C9406ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC2EC358CAE96F4D2ULL,
		0xB389F85503E4E1A3ULL,
		0xA6EE1970F857D554ULL,
		0x15A54156E4B18674ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x23125772387184B9ULL,
		0x074EF2355FB757A8ULL,
		0x78019C08825968C1ULL,
		0x3D96684290DB0D91ULL
	}};
	printf("Test Case 82\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 82 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -82;
	} else {
		printf("Test Case 82 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5BD338755A88FC8EULL,
		0x0D769ABBAEBCCA56ULL,
		0x0DBD8BED3B130C13ULL,
		0x385708CE94664137ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC61E8E216F5030E4ULL,
		0xC1C44A6DAB3C3471ULL,
		0xE05B6F6AEFFB24CEULL,
		0x1B7F8DD43345CB7AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x95B4AA53EB38CBAAULL,
		0x4BB2504E038095E4ULL,
		0x2D621C824B17E744ULL,
		0x1CD77AFA612075BCULL
	}};
	printf("Test Case 83\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 83 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -83;
	} else {
		printf("Test Case 83 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE4C886C8B835503DULL,
		0xB73A9FFB3FA7B73FULL,
		0x8C9E5EDFC4AEDACDULL,
		0x76259CFD4A680286ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x510841080173E4D6ULL,
		0x7348268CBEFF48EFULL,
		0x9BB1E53B9D6EBB86ULL,
		0x468925E5370388DEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x93C045C0B6C16B67ULL,
		0x43F2796E80A86E50ULL,
		0xF0EC79A427401F47ULL,
		0x2F9C7718136479A7ULL
	}};
	printf("Test Case 84\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 84 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -84;
	} else {
		printf("Test Case 84 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7393C4806C834C2FULL,
		0xFEA1DD5241CB6111ULL,
		0xEE45480F12A57624ULL,
		0x385FD2850CDBF221ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD56F5A958B19E10CULL,
		0xB910D549EAB82E4EULL,
		0xA6DABC78DA81A590ULL,
		0x1D973A92C494C23AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9E2469EAE1696B23ULL,
		0x45910808571332C2ULL,
		0x476A8B963823D094ULL,
		0x1AC897F248472FE7ULL
	}};
	printf("Test Case 85\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 85 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -85;
	} else {
		printf("Test Case 85 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA1D9D1ADF35B9961ULL,
		0x0618098431BF8F2DULL,
		0x07FEA4883129D8F7ULL,
		0x341353C6F3D1B9E9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x040344BFC0848E82ULL,
		0x3F255AD575A5E7F4ULL,
		0xE4ED679227E02823ULL,
		0x3D43944491DCAC80ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9DD68CEE32D70ACCULL,
		0xC6F2AEAEBC19A739ULL,
		0x23113CF60949B0D3ULL,
		0x76CFBF8261F50D68ULL
	}};
	printf("Test Case 86\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 86 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -86;
	} else {
		printf("Test Case 86 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB2FA2495BDF94A85ULL,
		0x94B6EF6B710E62EFULL,
		0x85A61392DAFFF5D0ULL,
		0x51A9C752D0E2FD75ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x401DCFA7C34E2B45ULL,
		0xA14E51D974B33DB0ULL,
		0x6B77A46A9378D74AULL,
		0x1F2FBF7DAB264287ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x72DC54EDFAAB1F40ULL,
		0xF3689D91FC5B253FULL,
		0x1A2E6F2847871E85ULL,
		0x327A07D525BCBAEEULL
	}};
	printf("Test Case 87\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 87 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -87;
	} else {
		printf("Test Case 87 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x56D4E31BD2A78AD8ULL,
		0xE89F01348BE63BD0ULL,
		0xBD36CD047DF9FFCBULL,
		0x166E9A00D58D5DAAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA08D1E6D14700AE7ULL,
		0x0A5ECD729FEB0C9DULL,
		0x844B20A6A275A6DCULL,
		0x1F5205734943F0D4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB647C4AEBE377FDEULL,
		0xDE4033C1EBFB2F32ULL,
		0x38EBAC5DDB8458EFULL,
		0x771C948D8C496CD6ULL
	}};
	printf("Test Case 88\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 88 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -88;
	} else {
		printf("Test Case 88 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0DB53B99F2C687EAULL,
		0x0C781A2AEDD87EB1ULL,
		0x7860668AFCC7157AULL,
		0x394A3467510A38C4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x51FA894ADE6FDCF3ULL,
		0x5431EF60E6547A7DULL,
		0x318250C127A473DFULL,
		0x6279A652BF4CBE97ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBBBAB24F1456AAE4ULL,
		0xB8462ACA07840433ULL,
		0x46DE15C9D522A19AULL,
		0x56D08E1491BD7A2DULL
	}};
	printf("Test Case 89\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 89 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -89;
	} else {
		printf("Test Case 89 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x15A0ECD5D1DF19D5ULL,
		0x5761A707179872C2ULL,
		0x599E1ED9856639CAULL,
		0x1D729B72A0A1629FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC678EA4CF2D4540BULL,
		0x42DCCA6E5D191FA8ULL,
		0x59F450C6737765BDULL,
		0x45AE02249EC59E0CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4F280288DF0AC5B7ULL,
		0x1484DC98BA7F5319ULL,
		0xFFA9CE1311EED40DULL,
		0x57C4994E01DBC492ULL
	}};
	printf("Test Case 90\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 90 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -90;
	} else {
		printf("Test Case 90 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6BC8ACEB09DD60B9ULL,
		0x9C9C2E76435917D9ULL,
		0x00395F7F323E3250ULL,
		0x37CCF3FCFD7C4232ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8F75EC997C31D528ULL,
		0xA56E06BC206806C5ULL,
		0xE74573D6ADBE309BULL,
		0x4B6D83127333F426ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDC52C0518DAB8B7EULL,
		0xF72E27BA22F11113ULL,
		0x18F3EBA8848001B4ULL,
		0x6C5F70EA8A484E0BULL
	}};
	printf("Test Case 91\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 91 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -91;
	} else {
		printf("Test Case 91 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE98521B8EBDE756FULL,
		0x9461E1175FF5724BULL,
		0xC2B137C52422C282ULL,
		0x09F88D1CA653C439ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD7E72C4487BFA096ULL,
		0xF10CB45F3876CF09ULL,
		0xC73778F03D66E1ABULL,
		0x3D4017BA308570B7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x119DF574641ED4C6ULL,
		0xA3552CB8277EA342ULL,
		0xFB79BED4E6BBE0D6ULL,
		0x4CB8756275CE5381ULL
	}};
	printf("Test Case 92\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 92 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -92;
	} else {
		printf("Test Case 92 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x78EADEF7731CC964ULL,
		0xBF358AF10A4E9614ULL,
		0x27825131082A7CBFULL,
		0x5F2C816EDCAA76F5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x81B3213A9F5E1005ULL,
		0x3A2C8F48CF7CE985ULL,
		0x34F0FF46644EF668ULL,
		0x710DF11FF4F39E22ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF737BDBCD3BEB94CULL,
		0x8508FBA83AD1AC8EULL,
		0xF29151EAA3DB8657ULL,
		0x6E1E904EE7B6D8D2ULL
	}};
	printf("Test Case 93\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 93 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -93;
	} else {
		printf("Test Case 93 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x26D1FCC22EC67665ULL,
		0x99C437A996D710D4ULL,
		0x715DC3BD7F35B0E0ULL,
		0x3126AE25974163C8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x93D454AFFD78B3C5ULL,
		0x1397DC9CE985BD7AULL,
		0xA71ACCBD8A520282ULL,
		0x31C0D2336623DB45ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x92FDA812314DC28DULL,
		0x862C5B0CAD515359ULL,
		0xCA42F6FFF4E3AE5EULL,
		0x7F65DBF2311D8882ULL
	}};
	printf("Test Case 94\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 94 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -94;
	} else {
		printf("Test Case 94 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7E7B21CF0162D1F9ULL,
		0x6FDF5BC87880237CULL,
		0x2B5209302B3BAA93ULL,
		0x16F5A815AA448A1AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF11CA83B86ED07DCULL,
		0xB9F544C1CB158B9EULL,
		0x639B237171613B5BULL,
		0x50503791571797E2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8D5E79937A75CA0AULL,
		0xB5EA1706AD6A97DDULL,
		0xC7B6E5BEB9DA6F37ULL,
		0x46A57084532CF237ULL
	}};
	printf("Test Case 95\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 95 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -95;
	} else {
		printf("Test Case 95 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5319C7747D4B8BD3ULL,
		0xD6AE78D89885D352ULL,
		0x7EA92959887563DEULL,
		0x5089EB01752CC961ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x261552CAD4B9B3CFULL,
		0xA7D98DAE5C196F69ULL,
		0xB454BC19A9449E8DULL,
		0x7953FC29312C575FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2D0474A9A891D7F1ULL,
		0x2ED4EB2A3C6C63E9ULL,
		0xCA546D3FDF30C551ULL,
		0x5735EED844007201ULL
	}};
	printf("Test Case 96\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 96 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -96;
	} else {
		printf("Test Case 96 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFD523256D99EB8DDULL,
		0x49C476FDCEE490DEULL,
		0x1E6D4BD4C3F451E5ULL,
		0x5ABDDBE81A611056ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x88653D6D957DF406ULL,
		0x10C76AB57B3B89A5ULL,
		0xC71F71170803962BULL,
		0x1B83A745D6B3FBF9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x74ECF4E94420C4D7ULL,
		0x38FD0C4853A90739ULL,
		0x574DDABDBBF0BBBAULL,
		0x3F3A34A243AD145CULL
	}};
	printf("Test Case 97\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 97 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -97;
	} else {
		printf("Test Case 97 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA4B747CB2920A93AULL,
		0x12F6795FCB047E59ULL,
		0x5F0DB575E4BC8F4CULL,
		0x6CC28AEA30A18CD1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBC9A39B6E0815BAAULL,
		0x37ED738EDC9EE1B6ULL,
		0x2592CF32B368B087ULL,
		0x0919519AE3B39FE8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE81D0E14489F4D90ULL,
		0xDB0905D0EE659CA2ULL,
		0x397AE6433153DEC4ULL,
		0x63A9394F4CEDECE9ULL
	}};
	printf("Test Case 98\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 98 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -98;
	} else {
		printf("Test Case 98 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCF731CA91843F2F9ULL,
		0x7AEF2B115F8398DAULL,
		0xF41FE851FAE83B85ULL,
		0x78331231FD0B5842ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3FD69CEF62EAA061ULL,
		0x6B9786B5C3310CABULL,
		0x4AA1BB91C3D44E8CULL,
		0x69EC0BAB642B4676ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8F9C7FB9B5595298ULL,
		0x0F57A45B9C528C2FULL,
		0xA97E2CC03713ECF9ULL,
		0x0E47068698E011CCULL
	}};
	printf("Test Case 99\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 99 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -99;
	} else {
		printf("Test Case 99 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x43EC92D2D20876C4ULL,
		0x5625F3F41F48BF99ULL,
		0xFA09057F1ED910D6ULL,
		0x051841D51D7D7ED7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD7F1AF531A3A158CULL,
		0x4CEBBCD932FF72D2ULL,
		0x889E164C1F04E250ULL,
		0x60C98AEC9922602DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6BFAE37FB7CE6125ULL,
		0x093A371AEC494CC6ULL,
		0x716AEF32FFD42E86ULL,
		0x244EB6E8845B1EAAULL
	}};
	printf("Test Case 100\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 100 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -100;
	} else {
		printf("Test Case 100 PASSED\n");
	}
	printf("---\n\n");
	return 0;
}