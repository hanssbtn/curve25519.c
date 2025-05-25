#include "../tests.h"

int32_t curve25519_key_sub_modulo_test(void) {
	printf("Modular Key Subtraction Test\n");
	curve25519_key_t r = { };
	curve25519_key_t k1 = {.key64 = {
		0x4CBE444D3542384CULL,
		0x6C162EE84BC7C509ULL,
		0x596F4F736E41777DULL,
		0x3D28850AF2AEFD3FULL,
		0x80A56C6BC1078CE1ULL,
		0xBFAFFA7D11D7BAE3ULL,
		0x14F4563FFF1AC44EULL,
		0xCAF36B5BB1C6222EULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0xF2C09AAD3F6EA5CDULL,
		0x5F87CDC7E2000003ULL,
		0x358EE6A2CF6A8E5EULL,
		0x565AE470D63A146DULL,
		0x0E2D1A04CBC81F32ULL,
		0xE09C6837A622E43FULL,
		0x89252C73A0BB684CULL,
		0xD7FB47BD53EFCFB6ULL
	}};
	curve25519_key_t k3 = {.key64 = {
		0x57D9E4E85D3DDA1AULL,
		0x2976176E669FA16EULL,
		0xE4A09D26A0FE9166ULL,
		0x77A2EA1C0A452690ULL,
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
		0xA33A498012F8CFB4ULL,
		0xB8A42AD5B31345CCULL,
		0x9EDB9C6BC28E2B11ULL,
		0x43712654D0204532ULL,
		0xDE643BEAB8AFD58EULL,
		0x8DB9E16BAA622A5FULL,
		0xBAC2FD36FF7B2930ULL,
		0xB86F47C336E13A65ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCF9004CC9A01A915ULL,
		0xD4365AA90D556AAFULL,
		0xDC1749341EE32897ULL,
		0x599432C4B2411562ULL,
		0xBE0BBBF727E0F786ULL,
		0xC5184A50CA5C18C4ULL,
		0xAAA439246EAE3FF4ULL,
		0x52417B75F72CDD60ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA0CD42DAF7AC1E09ULL,
		0xAC6A3E29E6A47823ULL,
		0x27556DF92215A159ULL,
		0x14A9470792A4FE90ULL,
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
		0xA105AAE4572B6DD2ULL,
		0x337A13B7A648BE3AULL,
		0x694049759278C01CULL,
		0x6E5F0193AF6C8BE3ULL,
		0x42E5866CA5E47169ULL,
		0x32FAD7D8EAF6A51AULL,
		0xA4237D2BA054E5E4ULL,
		0xDB903EE9949004ECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF489ABB648F55FBAULL,
		0x72459555F8CF9732ULL,
		0xD0E65B7E0D20E394ULL,
		0xE6B2B5822595343DULL,
		0xF7B2C60B6B6E70F2ULL,
		0xF8541A590F3E41EAULL,
		0xB7EBCFCE07915977ULL,
		0x921D35171413CF02ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD6048D9CBBBA213EULL,
		0x75F49F5C4AD7E00CULL,
		0xA89DA9DC325EB498ULL,
		0x6EBFC1509C47585EULL,
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
		0x68C57E36A2D3FCC6ULL,
		0x3C1AAF149E2B3C42ULL,
		0x6F6B04E1CA5E6FD7ULL,
		0x06748822AE0F0128ULL,
		0x73A949BF757E7F33ULL,
		0xFFCA9AFD94EFFD89ULL,
		0xD1111D76B2AF12A3ULL,
		0x30B885AAEA470A63ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5E3552189742F9D2ULL,
		0xFB0F4CA1C7741628ULL,
		0x25EF73D2F0E46FE0ULL,
		0x6ED513962D1F2046ULL,
		0x5ED9E0833CBED6ABULL,
		0xC6CD275AFFAA3CEDULL,
		0x531CD61FAD6D96B2ULL,
		0xFB98E25DC47D5DC3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2159CB0E7804028AULL,
		0xB6AA8C94FF11BD45ULL,
		0xFBBE27F9A13265C4ULL,
		0x7A51B2001CDF80B4ULL,
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
		0xA8859A5E6C10860DULL,
		0x2FDFC2BA33BAEC06ULL,
		0xF562C21DAC4D5FF9ULL,
		0xC8EAC1295FF45AE5ULL,
		0xE659A7BCBE8635E0ULL,
		0x39101257EBE7913EULL,
		0x3C71A0EBC0B1906AULL,
		0xD28B8B6C0F42FD16ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8BAA02D3AC8492BCULL,
		0xCC8C5266DB6F0F1FULL,
		0x21AEE6BBF90C1868ULL,
		0xC24DC380BE9D6F56ULL,
		0x4DAD32B2E0DD57B3ULL,
		0x17D6623FADDF46C4ULL,
		0x161E768F177FAC1BULL,
		0x0590ABAF4D3A7C28ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC674F701A69CF273ULL,
		0x51E393EC8D86EB19ULL,
		0x840C2522D0A92B4FULL,
		0x73DA33AD6E9A0EE9ULL,
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
		0x882955EB6B5FE845ULL,
		0xFCC7A60FFDF17C53ULL,
		0xB034F45F91B2D3D4ULL,
		0x146C55874D0BA664ULL,
		0xA5DE0F09E383A2B0ULL,
		0xE7ADBEC51AFD690AULL,
		0xF07F1C181B73082DULL,
		0xF5FF85155CE28147ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC718B3E175035806ULL,
		0x6DFF82CA0BBBC74BULL,
		0xB19FFF22F8183A36ULL,
		0xD366A4E142557C91ULL,
		0xA7DE41834BFEB8AAULL,
		0x02E0C1A3F61CF88AULL,
		0x6C1F7553A391657BULL,
		0x03BEDE689CAF4603ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7509240474175255ULL,
		0x8535B6316B866807ULL,
		0xA4C7B6666518C02CULL,
		0x369E6E4A9250F5FEULL,
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
		0xFC0E58CF3B9A1E9FULL,
		0x342DB73E9827D280ULL,
		0x68C93EE4703BA1D8ULL,
		0x816B384CFDD835D7ULL,
		0x8C5BEC110B072B52ULL,
		0x68C7EFDE85EE6963ULL,
		0x775642820923A27EULL,
		0xD5E7E4E1B667903DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE91C9877DE3A2330ULL,
		0x8A2420923964853EULL,
		0x6AB47BEBDB1D856DULL,
		0xD44E67906085195EULL,
		0xFBD8734EDE62E8CCULL,
		0x26B347BDCB61D5E2ULL,
		0x0AF450C024C28CF1ULL,
		0x6BBB0A29257871F8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8675AD29FDC1DD8DULL,
		0x791A8B880FA13257ULL,
		0x149EA5C07B874F62ULL,
		0x6FC5482220D19AC7ULL,
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
		0x5959B2527AAB44B4ULL,
		0x9C53871E97E76B7FULL,
		0xA51130379B0419AFULL,
		0x637B79DEADB74422ULL,
		0xF14507D656B70170ULL,
		0xA935FA45F11B3DB8ULL,
		0xCB8330D61845150AULL,
		0x1318FA77E695A4B3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x904EB4CF2767581EULL,
		0x2E6824C8E31E848AULL,
		0xAF2177EC4E94DB36ULL,
		0x1074B70CA0D3A364ULL,
		0x616B3B587C8E332CULL,
		0xAA9D321A6E1BD12DULL,
		0x767DABB194B2F647ULL,
		0x98C2B49B7ED39712ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x235F5831B55287B6ULL,
		0x389918CB26B303ACULL,
		0x94C17BB6D41FCF6BULL,
		0x7BD5218973B1A6B0ULL,
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
		0x4A38F1B723F49570ULL,
		0xE7D5F68E9F4BA6E3ULL,
		0x4C7FCB7F841445B9ULL,
		0x20592B8AB60E6774ULL,
		0xC049ECF3F2AB8EC9ULL,
		0x3590280E39BF729AULL,
		0x5ABF7D4584C0D541ULL,
		0x5120AEC226E483D0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7C7B6677EC9DB24DULL,
		0xF094933C2D4817FCULL,
		0x40F1365DC83E28C7ULL,
		0x6A7882F7B60D122BULL,
		0xE320CE4D86F59973ULL,
		0x493F5ACA78A1B7C3ULL,
		0x0AA8F1B16198CE4EULL,
		0x70486B8173CE5778ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA1D817F334594D29ULL,
		0x0B3FDB611C6D4ACBULL,
		0xEEE74D1EF3C72501ULL,
		0x15FAA42D954BEA64ULL,
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
		0x02813A1B67242FF8ULL,
		0xACDF3DB3652B62ECULL,
		0xDBE5B47D573C3AA0ULL,
		0x4701C5D947FFC446ULL,
		0x2F49D55AC9E5641CULL,
		0xE23B9F635CA389D5ULL,
		0xC5166D1C8F1A62F2ULL,
		0xF260211CE2872931ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC81636478B26DAC0ULL,
		0x18F6710A2831C2E6ULL,
		0xA24CB1BFFEE9D840ULL,
		0x6A7286764F39E464ULL,
		0xABC685DC82DA94B7ULL,
		0x9FC4F21E68928242ULL,
		0xB5193A2ED5BDE3BDULL,
		0x9204BA95DA05CD17ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBFE8D0926798204AULL,
		0x718684E57780BFC4ULL,
		0x992E9206DC0D4448ULL,
		0x2A20776E3BF98BC0ULL,
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
		0x0BA69A1A57CC3BBEULL,
		0x7C09DAEF922A65CFULL,
		0x12B6E5F0237C4578ULL,
		0x4A47BE054339B8E3ULL,
		0xBAE6B1E10CFFAFF9ULL,
		0x026B102E7C347599ULL,
		0xB0CD677B756E53C8ULL,
		0xBDBAF946C9B59C14ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x34073A935CD6B079ULL,
		0xBAE7A48F86156406ULL,
		0x064F649C42F5AE71ULL,
		0x60A9DDD51F8C36CDULL,
		0xCCBF331EA355875DULL,
		0x64E594F423D238A2ULL,
		0x40A057A8D36E5FE0ULL,
		0x6629AB6796A9F9C6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x317C3062AA379448ULL,
		0x22F281092AAA0E70ULL,
		0xB317DA97EC84CB68ULL,
		0x692F6F51B76799BAULL,
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
		0x0E96F6E7C314395DULL,
		0x128CA6C5C38A53A9ULL,
		0x30D39687468B4E40ULL,
		0x5550093C6902FC99ULL,
		0xE0DB5B0A32D19211ULL,
		0x134EB90AE030A1BDULL,
		0x964EBF1190836AB5ULL,
		0x8FE0A69E343A27DDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDBF828C2D0B507DCULL,
		0x6BF79D5708236966ULL,
		0x6AB983BFA33E3BC8ULL,
		0x0CD5128FA569FF80ULL,
		0xBB776D0E59371E17ULL,
		0x593C1B7118084EF4ULL,
		0xBB3B3BCECCE75043ULL,
		0x911C3E071CA6B01FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBF7421873F4C689DULL,
		0x45586E427163341DULL,
		0x4AFF8EB0AC78FF59ULL,
		0x19A27D1A437CC347ULL,
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
		0xB1ABAEA469CF8026ULL,
		0xAB426921E7098026ULL,
		0x0FB17A07F49ABC8FULL,
		0x71E7123A4349EB1AULL,
		0x1C01AF60C188AC0EULL,
		0x00BEA08D8A9DC617ULL,
		0x3C04869EB661DA3AULL,
		0x0C017134D62BD6ABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA5DF38A124B1A513ULL,
		0x5F987DBE65D3899FULL,
		0xF17098C6EA77421DULL,
		0x388F5F2042B82CE6ULL,
		0x840470763B9E826FULL,
		0xF36BDCA1A40A8FBEULL,
		0x054E087CCB78FB16ULL,
		0x7CB8777FE5C4E458ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9B63CCD325E00627ULL,
		0x45F30067BB1007ADULL,
		0x3D579A49E8B499A6ULL,
		0x7E2CC3F5AFD9B68DULL,
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
		0x6254A0B2745A5B60ULL,
		0x2D801AEA404691EAULL,
		0xFB24CBB94E4BCF8FULL,
		0x68A79BA65EF4141FULL,
		0x7D2350A592A32D9EULL,
		0xAC0DAB428BFFC777ULL,
		0x3AB9720138595112ULL,
		0x09992C2D97C4254FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x02930D1AF9028BD7ULL,
		0x236DEB23FC3DB09EULL,
		0x3C551302A5B7211CULL,
		0x35914D9780F4E84EULL,
		0x6264A16F1F2CFCD1ULL,
		0x401623E8894831A0ULL,
		0x739CEA115E30EB81ULL,
		0xDDDF4B2704211500ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x580F95AC9EE3094AULL,
		0x10D04722AB491F3AULL,
		0x4D0BE6510A93C209ULL,
		0x30ADB508C8339783ULL,
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
		0xF90EF48CC2E3DB87ULL,
		0xB50D6789DC9C2B52ULL,
		0x916E883E54112429ULL,
		0xB8D440631A6A0CA3ULL,
		0x3AF3720BDAF0FF35ULL,
		0x9E19330C5920ED9DULL,
		0x427A779B8A3B0D9DULL,
		0x3B84A2B24625356FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8F84F5CD028B27E2ULL,
		0x2E5C5327675647C7ULL,
		0x173FF3EC4ADBE5FFULL,
		0xE09FFBA2B9404BFDULL,
		0x7C816BB406D7B37FULL,
		0xB8E45B6C2B6A3373ULL,
		0xC4D6EBF0F6A67BE1ULL,
		0x83225C4D9761780CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAE76EFC93C19EF07ULL,
		0x8C8916293E6585BDULL,
		0x20754FA3F142E00EULL,
		0x36CAB7B25237DD45ULL,
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
		0x48AF439D3BCD33B9ULL,
		0xF0AC60F5389AC1BAULL,
		0x7553B480B3395851ULL,
		0xDB4959316B7495DCULL,
		0x41C62FE525404AAAULL,
		0xD2235BFFE3C987EAULL,
		0x13362D662B8D66DFULL,
		0xF8ABCCCEADA673C1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x71ABF59C055F0604ULL,
		0xAFA7D09431CFF8CFULL,
		0xE63378978413E1F8ULL,
		0xF294C68EDCEB646DULL,
		0xAC05E24C0A3BF8CDULL,
		0x31132D645C5F89F6ULL,
		0x2040C978A13BE279ULL,
		0x8C56355663DF576EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x118ED2BB391256D0ULL,
		0x296B7B7720867B13ULL,
		0x9F8D112BB73F1D95ULL,
		0x7D690E7D821765BEULL,
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
		0x77CD576AD870B4ACULL,
		0x1D3DD74280C78AE0ULL,
		0xE23F9EA630835403ULL,
		0xA4C191CAB46CF0ABULL,
		0x095506AA8B7A1B52ULL,
		0xE0BE94C21A27110DULL,
		0x98712B233DCDBFF5ULL,
		0x09DDC65ECAB2975FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA190B813B485B6C1ULL,
		0x39B045BBD1F5E3EDULL,
		0x89831A0A74F847D8ULL,
		0xCD9678439FA13226ULL,
		0xB779C35AC499A8D6ULL,
		0xB0270E22472D5303ULL,
		0x444D1EF2588AEA42ULL,
		0xE70C43B82F205186ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFCC89D2EA93BF76DULL,
		0x1A0B8D3FFFE3DC54ULL,
		0xD61653DDC376C4C4ULL,
		0x02447E422C821CC7ULL,
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
		0x2D04A72414441B67ULL,
		0x3C0834BA89B1D2EAULL,
		0x5FAAD6D631481FCCULL,
		0xCA78EBA073DEBFF1ULL,
		0xFF5B01BFD808A3D2ULL,
		0x050D0E5C572B19D7ULL,
		0x0C7510BAD6DDF6E8ULL,
		0xB220DF4204F945FFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x44B3FCFF9E8097B7ULL,
		0x7850E23986C88DE6ULL,
		0xD813E55E11DEC42FULL,
		0x7BDB5B522F5D7F3DULL,
		0xEA05E3540DC06101ULL,
		0x60839DA095D30957ULL,
		0xAB2D45C81D2C98C1ULL,
		0x354E572E734817EFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x12F32E247C7D7175ULL,
		0x301E0E5FB5FBB807ULL,
		0xF83F117FAFBD5559ULL,
		0x55DDC335E4CE16FBULL,
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
		0x5AE9A64CCE91FAF5ULL,
		0x63F58BDA9577ACEBULL,
		0x47A9912BE027F3ACULL,
		0x66DE53532F738426ULL,
		0x5B76B2A2E88BE5CEULL,
		0x3A48C09E01A67944ULL,
		0x5415A6EBB1A2AD60ULL,
		0x151BEF9BE5F38DC6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB736A34D36FCE199ULL,
		0x2EDA40C15948AB2CULL,
		0x8116A9304A51C427ULL,
		0x9445BC9D62646863ULL,
		0xEAC043B6BB89E893ULL,
		0x40B2F1DFD7D8E224ULL,
		0x8B1C4FA4B111BDCDULL,
		0x9E4FE9DCA0938D6DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5EC77A0E45E0AD00ULL,
		0x4157FB5370B37069ULL,
		0x9B95DC85AB59BF56ULL,
		0x74E1711A194F28F0ULL,
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
		0xB0015DBF467B2B8AULL,
		0xD33AD646C77E44D7ULL,
		0xCEB7B2140B45DBC8ULL,
		0xED6FD7AE87C3F988ULL,
		0x16ABF32EDD0EF287ULL,
		0x33123567663AFE28ULL,
		0xFCD621E852C2EA9CULL,
		0xEFD246917281451CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0D4C778E6183E2CEULL,
		0xC5AA32638EA3122AULL,
		0x4396508D6AF2EFFEULL,
		0x966EAB4BF0B1D61DULL,
		0x78130DCED7E7F28BULL,
		0x68918B68FA0A3583ULL,
		0x99A9677057B1F8D3ULL,
		0x4C208A4B6FE90EB2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2D66F271A8C14BC7ULL,
		0x1CA9DFA74818FB1DULL,
		0x43C50F55E4D6CF98ULL,
		0x23631EC6F9AA3736ULL,
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
		0xF13928AFA31B57A7ULL,
		0xC0EB9CC7391F57CCULL,
		0x1BBBCF24209640EBULL,
		0xB6024234B0643CE0ULL,
		0x92ADD95B73C6F1CFULL,
		0x1E2EB60C0BFDAF78ULL,
		0xB134806A066810A3ULL,
		0xD3574ED48738286EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x08402363DCF52AB5ULL,
		0xE8BBEEE0F769F9A6ULL,
		0xAB71D150AF71AECCULL,
		0x69EC73D109ED5AC7ULL,
		0xA3B32475B1A6DFCEULL,
		0x2B6843375FFB4206ULL,
		0x898A2A77CDC482C4ULL,
		0x1AA8AD641318228EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x622FDF6696E8DD2DULL,
		0xE1A4B977CA119D10ULL,
		0x5392BFC7D96BA136ULL,
		0x3601C514E337C15EULL,
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
		0xCD7A3A627D54BA37ULL,
		0x4DDED356596F34D9ULL,
		0xDC551E50898B7BF5ULL,
		0x819E73F502E75063ULL,
		0x518DEAFA78419046ULL,
		0x13ED3FD4DF90F4F0ULL,
		0xAAE6A9F919883253ULL,
		0x45A7533F440AEB3AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x36190AB4C5F99E69ULL,
		0x51FF61FE66341763ULL,
		0x5453C2535F258137ULL,
		0x583FC94EC9F0E6CEULL,
		0xECF0588205D7FC35ULL,
		0xEAEBB2C85219E330ULL,
		0xAE8DA7A784C7023DULL,
		0xE6A798E2D53F655CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x86C4ED8EB30712C4ULL,
		0x121A6134F2E7BFDFULL,
		0xFD37B4193F131DE2ULL,
		0x4354545EAB2C4888ULL,
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
		0xAB2316955210F542ULL,
		0x40C7BD5C688C060DULL,
		0x35C9DD0B3E80CD3CULL,
		0x3593B1E63F89C9E2ULL,
		0x43F542E755C64DDFULL,
		0x1969386009FDBBF3ULL,
		0x46A49F7B6A190C41ULL,
		0x0E8F4C6FD68E6355ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDA0193CC2A15B0EDULL,
		0xCCEA4AC96A42BCFDULL,
		0x85B59D0D4C5FCCF5ULL,
		0x00AA3DA98DD2D116ULL,
		0xBCCD69F4DF7D7C67ULL,
		0x2471B912B280E5CCULL,
		0x6E8021B8135CC0CAULL,
		0x6968BEECDA5C3275ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE10BB6C6B6CA5A24ULL,
		0xD09A580DFAD112C7ULL,
		0xC57EEAFCD21433EEULL,
		0x38A275AE212A3A05ULL,
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
		0x1BDFD29DA8670CFBULL,
		0x62A932FFE2018F72ULL,
		0x7CD24025BA80D12DULL,
		0x4A574774069AA833ULL,
		0x97FF4D45257639AEULL,
		0x3AC6B1897710E343ULL,
		0x93A965491240804AULL,
		0xA9F7B43F63BB03D7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6C7823D0B0D111BDULL,
		0x74CB04270B068647ULL,
		0x9D19925AC2157B59ULL,
		0x21296FCCF7296B54ULL,
		0x0E919249ACCDD4CCULL,
		0x64A84179544074FFULL,
		0xE9D8E3148C0E47BCULL,
		0x4D5823F1EDB1B720ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x15B17020E094F6CBULL,
		0xB662D13E01EB6757ULL,
		0x14AC0196E3DFBAE1ULL,
		0x68DD432694D29FFCULL,
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
		0x5CBB75CBB49BCBD2ULL,
		0x5E05E76BC8DCDCE7ULL,
		0x1DC34BCE7D5DF05AULL,
		0xC1922071F24A9A63ULL,
		0x1BCF5FEC095007C4ULL,
		0x8BB3C79775738707ULL,
		0x3AFAB9D9CCCC74DEULL,
		0xB8BE30B9E918A5B5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9D40ABC6EA51CA83ULL,
		0x47426352BFAC5D3EULL,
		0x0AAC3DECBE406FA3ULL,
		0xD72EF9F2E44BC871ULL,
		0x9C1CA977E2A63005ULL,
		0x89D7DB3CEC6CF4A8ULL,
		0x205F52CB89E34A6EULL,
		0xDF7C5B76C99E7352ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB401DF42878006C5ULL,
		0x5D689989602A39AFULL,
		0x062859FFADB9CD57ULL,
		0x2A28CE75BA224CA8ULL,
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
		0x1204A42E7247CE08ULL,
		0x7091DB6D6736C22AULL,
		0x7C4621A58118DD1BULL,
		0xEFF84578A67D2BEDULL,
		0x58CB4F47D2D99D4DULL,
		0xE5A3D0C2C4CA7F9BULL,
		0xF761BC614371C3C0ULL,
		0x5F6C77E681DB55B0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA7706762362C29CAULL,
		0xBD3E680283323A4BULL,
		0x668EA9CD872708A2ULL,
		0x8BABF1193DA8CD96ULL,
		0xA10578B7DA4FECECULL,
		0xB7FD3615EA68D568ULL,
		0x5EE7A2F0073BF7EAULL,
		0x71667F469AC54B8EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB1F2162B208BD245ULL,
		0x7A0E69134E83CB65ULL,
		0xB7D73EA6E9EE1643ULL,
		0x392F3C1BB619DF79ULL,
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
		0xBCC56342F0BE0C54ULL,
		0x6B3A44C6A396162EULL,
		0xA1F67543B00A3C9EULL,
		0x49CBF1C192723ADCULL,
		0x3198BE4A3BEA10D6ULL,
		0x5978147329B865D3ULL,
		0x157A226259DCF48DULL,
		0x43D7931FDE2E978BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x930E2EF570CC04A5ULL,
		0x73D57525C28C480AULL,
		0x2DBBFC8B749A9982ULL,
		0x590C7C2F64103FC4ULL,
		0x095EC050D15FA83CULL,
		0xEF9911D990C442E5ULL,
		0xD3B861AD9917B914ULL,
		0x4164D10CD69C02BAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2252E753507D8E8BULL,
		0xAE7F326D9546FD7EULL,
		0x36FD138CD8B676FBULL,
		0x4DC844654E241202ULL,
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
		0x1BD57CDB9F131BB0ULL,
		0xBC98E5876E52C1FEULL,
		0xD2D0FC97CD2D55F1ULL,
		0xD1024B49F5E5AC4CULL,
		0x3924266C2F51C656ULL,
		0x7AE837B848FC29DCULL,
		0x4DD08669C96DC875ULL,
		0xF099229929182F1DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBA218BF0D19B50D4ULL,
		0x2C45DC8E734C28E6ULL,
		0x9C0E0E8DE0CDED70ULL,
		0x6A43AB3815A22568ULL,
		0x2F1A2509544718ADULL,
		0x75EAA8A5D0641786ULL,
		0x6D2CE68EAB06EB2DULL,
		0x687FE2D65DAA2342ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDF302597510D94FDULL,
		0x4DF645B6E19951DCULL,
		0x8F0CA8906FA44132ULL,
		0x1A7E16FC12994961ULL,
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
		0xFD58EB80AFAA3242ULL,
		0xC4F1A93A89DCBA75ULL,
		0x395BDB007F12BD88ULL,
		0x33356DF45C4F760FULL,
		0xB262253E23D45BB2ULL,
		0xDFBDDAAD5D2D3492ULL,
		0x95858370152A33D7ULL,
		0x9F99F1C62F229AA7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1D7C29348B5FE543ULL,
		0x0B3CC3AFD279DC8AULL,
		0x0FC87EC91AFAE1CEULL,
		0x32DE083B99C448F5ULL,
		0x83B9F32BAD62E612ULL,
		0xF0C7ACEB18A353DFULL,
		0xAC79E529D3F54D2FULL,
		0x9EF658F5CA770064ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCCD43109B921C2BFULL,
		0x323FB060E3DA3884ULL,
		0xC14CDAA511F218A8ULL,
		0x18A014A7B4041308ULL,
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
		0x8B6DAE3DC74EAF76ULL,
		0x5A2878310511F654ULL,
		0xDAC76C83C92E0B80ULL,
		0xE35D800B47BB1F3FULL,
		0xBCBC69D5E50E02A5ULL,
		0x0EC351BE7CBF45D3ULL,
		0x4CB032EBB679AC30ULL,
		0x6C73FEF46AD3BBCDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9F85F5BCE72E32E9ULL,
		0x8FD8F68D1992F21EULL,
		0x03ED5BC09F605233ULL,
		0x366CE0D31DC15880ULL,
		0x7DEFFD536160BF94ULL,
		0xB53C457EC122A891ULL,
		0x176C27CB8FB9908DULL,
		0x77010E322D1CD85DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3E3FD3E06BD870EDULL,
		0x145B5319C4BE5C0BULL,
		0xBEF3B788EA51D366ULL,
		0x1C005C0D531F8967ULL,
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
		0xFC2ED9E8B3E83CE2ULL,
		0xF49120E9A4F44510ULL,
		0x8786C70432310BA1ULL,
		0x3CA792293DA89A00ULL,
		0x39297F3D67863FE1ULL,
		0xDD988B81552ED70CULL,
		0x1CE0DBC0ED10C577ULL,
		0xC4F4D52B1EDB78B8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCB29BDDF23126346ULL,
		0x787EF4E7A5D8FF87ULL,
		0x7C1BFCACF3D7C5A2ULL,
		0x5E7E9A5182612FB9ULL,
		0x4EA090E77C7E83D4ULL,
		0x9DA4AFD5CF085EE8ULL,
		0x652CAC44BBF30799ULL,
		0x937885D927A69FC0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x01587CCA73FBC494ULL,
		0xFA44C777E8D11ADEULL,
		0x5029D6C688C374FCULL,
		0x369CBE026D1F9F0CULL,
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
		0x61ECAD49142BDE76ULL,
		0xFE4A646C9E73BC6EULL,
		0x45242074CAD1F899ULL,
		0x2497A3CC3A131A33ULL,
		0x3129B340C51B5D98ULL,
		0x356830BE70D49276ULL,
		0xD0C5B871E6D2AA2BULL,
		0x1C0B6DCC35A82078ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAD871160C361A211ULL,
		0x659CE1E46F3CADA8ULL,
		0x949D0F5F80759DF7ULL,
		0x6A38D8C29DFC3755ULL,
		0x1496FF57FD11197AULL,
		0xC5DEAA8AB0364DACULL,
		0x014E83798FCE79C5ULL,
		0x93CCB73A55C25823ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF22C50760250561AULL,
		0x27176E36C6B544C5ULL,
		0x7C38EDF234FB89B1ULL,
		0x73ADE4B0D8329F9AULL,
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
		0x882066C15D4DB0E4ULL,
		0xE749A242DA31AE40ULL,
		0xB8F72EB7E5E8EF18ULL,
		0x0F4598C86381C2A1ULL,
		0xD5729C393F96B163ULL,
		0xB3F044AA91A19613ULL,
		0xE995A7519520C423ULL,
		0x0D163BABCAF1DB7EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB3AB905864A7380AULL,
		0xED390108C44BEC23ULL,
		0x0F30701AE9D65273ULL,
		0xD12E0172B9ACE821ULL,
		0x86D7718D4C33889DULL,
		0xA3781C23280AFCD8ULL,
		0xE1F7FA50C8BD0007ULL,
		0xC77FD8F0316BB055ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7F7D2BEF195E8203ULL,
		0x6BE6A553C24080EAULL,
		0xCB2E6CBB52E1B8CFULL,
		0x126A3F2E73BF4297ULL,
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
		0xEA4A016C2F5155C2ULL,
		0x6AFB92BDD6DCDB54ULL,
		0x5515A63E0C2F31FAULL,
		0xFA75C245798EFCD2ULL,
		0xFAA255914C04BA0DULL,
		0xCED972DC1D69A45FULL,
		0xA8A8CF93338C2D7DULL,
		0x6EDDB45B7101B445ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB87FBD659CB9A1FCULL,
		0x494A2E5B12331283ULL,
		0x27B88D52F1958C68ULL,
		0xA9F08A5C69E85101ULL,
		0x5708CEE12F3D4FB1ULL,
		0x3D9C6045BDEF3A9BULL,
		0xDE302FE206E2917DULL,
		0x3ADA5247F42D75DDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7A94422AD8317E9EULL,
		0xB0C226B4F0D57C01ULL,
		0x3B44CD37BBC6CDA7ULL,
		0x0905C6CD9727EF39ULL,
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
		0x61E904EE04433645ULL,
		0x5FDEA06778F30A78ULL,
		0xB7545960753D61F9ULL,
		0xCC9EBC78AF4641F2ULL,
		0xCEFAF61F1E2285A8ULL,
		0x889ADC80EC7D0BFCULL,
		0x44FC247F45D44572ULL,
		0xA5C11D7B8E55E0DCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD5D212E1F6FDB8B0ULL,
		0x037ADBE387A024B8ULL,
		0x8853E4A81D80D6BBULL,
		0xCF09BBFC749B2588ULL,
		0x5E68AC16EAC5BCBCULL,
		0x20096BE932957776ULL,
		0x471D360CA3F48F6EULL,
		0x94751398B1A18C8CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x41CDEF43AD0B50FCULL,
		0xE1FA7B0989B2F1B4ULL,
		0xDE17D9BC5EF18FE5ULL,
		0x0EDE7828FD6FA049ULL,
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
		0x99C0C50632367833ULL,
		0x1EB1163388035A37ULL,
		0x8D6C6732471AD414ULL,
		0x2FED645624D9C4E5ULL,
		0x7CE2A914967A652EULL,
		0x20A693B5853498E4ULL,
		0x9D74E70873E5F8A2ULL,
		0x790E4586C64EE730ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA9C77A367B5D19CAULL,
		0x02D443F0BBB9E4C1ULL,
		0x86D61E301E4C07E5ULL,
		0x496B5DA5E59DCDB3ULL,
		0x5DF94671BD9818ABULL,
		0x3ADD3A3E6D958596ULL,
		0xCD3E68814541FC83ULL,
		0xB1ADE0493009568CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x869DEEFBE870B885ULL,
		0x37C019F04DE6530EULL,
		0xEEAD1113152638C5ULL,
		0x7ED10DD48D8F6F82ULL,
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
		0x5781A8D18C534D91ULL,
		0xD8CE692CD3C6EEDBULL,
		0x0F27DAF7B5F1F066ULL,
		0xD27CBDACB0AFFBCAULL,
		0x109A4EDAE0EF6102ULL,
		0x246E81848F09F782ULL,
		0x8BE391EA36B094E6ULL,
		0xE614AA90E80B69F1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5AD5BB465C0959B7ULL,
		0x1CFF60524A4186A4ULL,
		0x210B397247E5EE3AULL,
		0xF3EFA2B18E93D7C0ULL,
		0x32CBF00C544D3C15ULL,
		0x226B3B3955BD1A68ULL,
		0xA7F9D64E642BEE78ULL,
		0x76130665B5FB9963ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE94E0034105B7168ULL,
		0x084B78050AEE3A0DULL,
		0xC2CE7AA6ADBCB681ULL,
		0x7ECB796490751919ULL,
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
		0xBF57BFE5A87C7F6FULL,
		0x892C9336BD9DBE8AULL,
		0xE532D79429D351BAULL,
		0x30DD0662BDDDF968ULL,
		0xD204CA73200C8205ULL,
		0xD8423F5582E1CA31ULL,
		0xA00257D056F5B38BULL,
		0x317E6284702765D9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8A28219675C92471ULL,
		0x8F0D319AC4777558ULL,
		0xA02090CD76F54288ULL,
		0x691175E52D2D2888ULL,
		0xFF396539055D8D02ULL,
		0xC107AC0E8561CA90ULL,
		0xF625A67E2E64FDE8ULL,
		0x6CF64DCB2D29B691ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7F60A4EF28ABB807ULL,
		0x6CD13E259A263B11ULL,
		0x7BD498F8B8590567ULL,
		0x73FEA3FD8258D583ULL,
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
		0x3F6D9ACDAA2DF8C4ULL,
		0xDDC8DEDED14D1866ULL,
		0x392D91444DD09FBCULL,
		0x33AECCF7EDE41808ULL,
		0x2FB300325B1F5AF9ULL,
		0xEE93DFFEE012BED4ULL,
		0xFBBAC70044E5E042ULL,
		0x5A681D0FCF3B0D84ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x001882D923B071B3ULL,
		0xD972F9108481CFE3ULL,
		0x66635FC3FA508809ULL,
		0xBFEC54BA81BC33D6ULL,
		0x78B7C11D29D62F06ULL,
		0xDCC36718F4C47E25ULL,
		0xEF519BABE752D988ULL,
		0xF7CCB312292B030CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x68A07519D75A0993ULL,
		0xA947D7EF3A68E272ULL,
		0xAA66A00637531751ULL,
		0x16D433E412897203ULL,
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
		0xD2F454E6AF4A529FULL,
		0x305354CBA8160D41ULL,
		0xBB4F6F47F3734021ULL,
		0x9D789B4CDA7F0B2EULL,
		0x3D16B0C4C1991CC0ULL,
		0xEC291ED3942427B6ULL,
		0x65CAA4E4E8F27754ULL,
		0x772F3B50BE927B93ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x891BF2C84F291CCEULL,
		0x7D0F2B87AFE4D829ULL,
		0x6CCA0776D0BC1CF8ULL,
		0xF9C26D699F9F477BULL,
		0x521145CD2660F8B6ULL,
		0xFA13C1C923F824C4ULL,
		0xDAACACA1943E0AE4ULL,
		0xBF6A267F3AC67245ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2CA642DF6A768D98ULL,
		0xA26FF8D09EB9A501ULL,
		0xF4F841CFB57F3BC6ULL,
		0x6AF744FCCB292535ULL,
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
		0x3B7D98A7D18B9A36ULL,
		0xB05221C3C474D69CULL,
		0xB99A94923B6E7CAAULL,
		0x79251CABDDF03663ULL,
		0xAFDF1FBA2CF5EF03ULL,
		0x3F74660297FAA490ULL,
		0x17EDA5DABBF8648DULL,
		0x40D1EED2F1D65978ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x964E3C57FC9A9301ULL,
		0x0114BAD5CD92D4D8ULL,
		0x0FAC8909D8D995E7ULL,
		0x92DA461014F6A134ULL,
		0x301D63F67AF7B444ULL,
		0x557AB23121CA894CULL,
		0xB9CB9FC7C54C2E99ULL,
		0xE3F6CF3A4092CBADULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9BF13B5C40ADBBECULL,
		0x6A4E180582060DEEULL,
		0xA2FAF2590024E8F8ULL,
		0x2ED187461900A139ULL,
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
		0x58446030E770EEABULL,
		0x4F1B072591025778ULL,
		0xCA4F600EA121AEBFULL,
		0x556CC74D0F6B2BAAULL,
		0xD4901C157C4137FAULL,
		0xDA5FB178E60D6E65ULL,
		0xAFB9428DA508FEA8ULL,
		0xF202BCAD21AE83E1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x03C7116651F28A52ULL,
		0x50270001CC8E7D97ULL,
		0xCE5CD5C78212D36DULL,
		0x9C17264002692566ULL,
		0x27E959DBD76A8BA2ULL,
		0x47A80D445FF30C5FULL,
		0xAEA893CB276CC1BEULL,
		0x8D4394BE4CEDA636ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF53E23590D5BFB90ULL,
		0xC63666EFAC5E66DEULL,
		0x246C7B25C43FE623ULL,
		0x2DB58E80A1A2EDA6ULL,
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
		0xD339FE5C8F3C87A2ULL,
		0x9044129743F64641ULL,
		0xB08DE0ECE1A7C866ULL,
		0x251DD000DD91ADB3ULL,
		0xFD3D1A6336EC2E38ULL,
		0x1FF10002182B6569ULL,
		0xE56ABA0239337425ULL,
		0x202E47A15E47F3D6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3F85AB72A4F4CE94ULL,
		0x7291F0764945E9FEULL,
		0xFFEC31170CB7CDEBULL,
		0x758CCCE524D86D8AULL,
		0xAFD174EA2C507905ULL,
		0xBFEC6EDBAFAE7788ULL,
		0x7CD6601AB455940BULL,
		0xF30B0F9570CCF71BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x11AEE2E17D6499E0ULL,
		0x5E5FADD47D3BABB5ULL,
		0x36A708338DDF3E3FULL,
		0x62CB54E0F8FAC3FAULL,
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
		0x9ACCCAB781E68319ULL,
		0x82769EF646C8E113ULL,
		0xD1A8B5C632202E37ULL,
		0xD6C84A9718AC5E3EULL,
		0xD7695E45756E55D3ULL,
		0x6C1D7DA1BF66BE03ULL,
		0x0F65D5F64F0C6D0EULL,
		0x10EF8642723C50CAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA2FCED6DA50F3263ULL,
		0xB31321FEF7C1BB59ULL,
		0x0F770D987E44ECF4ULL,
		0xE571A057863CBEE1ULL,
		0x924BFC5275B4305BULL,
		0xB485ABD8FD4DFA2DULL,
		0x62E0D1CF594FC89EULL,
		0x1D662DE0E8CB235AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3A2C675BD278E03AULL,
		0x0FECA0C41EB43788ULL,
		0x5DF045F62DDBA9D8ULL,
		0x17B9C8B9F93C5DF1ULL,
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
		0xED18A37114994C14ULL,
		0x7318456F4B5210F4ULL,
		0x6D580ACA5E52E9C7ULL,
		0xCF334554751DE666ULL,
		0x3DBDF269DF855748ULL,
		0x6B2A2147290B59BAULL,
		0x6F3C69D52313BB11ULL,
		0xC5DDAF04EAC60DE0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x55F08DD6F7491B95ULL,
		0x436222350E812BD6ULL,
		0xB69A21138423C507ULL,
		0xB9D7F97D9B05FF12ULL,
		0x5BFA1A291B5DBAA1ULL,
		0xBB47DB43F102CFB4ULL,
		0x35652DF2DB1235E6ULL,
		0xC8FD3367A4B4A83CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1A3A2F373B317136ULL,
		0x4B4C87B48E1561FEULL,
		0x4CB0CD4D8A68E916ULL,
		0x1EADA52F40ACFDB4ULL,
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
		0x45CC75628F6D67BAULL,
		0x8A6C1CA1767FCCC6ULL,
		0xBA038B828AC3F611ULL,
		0x13878D9FF4C961A7ULL,
		0x1109F9035C55C8A8ULL,
		0x0233BEA039B5EE4DULL,
		0xFAA0B66EB6708CA6ULL,
		0x06F10173B8E59E2CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB38DC845D709839CULL,
		0x9697A4FD05F8F0A6ULL,
		0x1232F56FF33CDD0FULL,
		0xF1268CC2B9D48969ULL,
		0x05C8BD1CF58E2B2EULL,
		0x577C7D5146414287ULL,
		0xD07B270A33105823ULL,
		0xA7DC352993F8CDA3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3DED914FFA054084ULL,
		0x4B08295C93D85B85ULL,
		0xE963DEFE17CEE467ULL,
		0x3F7753DEB61BCC9AULL,
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
		0x39C0E66BDE864A0CULL,
		0xFF01F8968697BAE5ULL,
		0xB4B1FC4126B8CB47ULL,
		0x3EB150ED3759AC76ULL,
		0xC5380A95BC012E57ULL,
		0xE5A4AE27A4EB2DF7ULL,
		0xEFE892C29615152CULL,
		0x5A6B0D8123B638DEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x854900D06173115DULL,
		0x594453C192E6BA7BULL,
		0x262B5F80DD8E7E75ULL,
		0x48C169EF6F0470C1ULL,
		0x998303CDFE431E86ULL,
		0xC9A537D03BF409E5ULL,
		0x6CB7843301C47EF6ULL,
		0x0C8867592CA7A3B2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3156E741A749936AULL,
		0xCDA935CE88605B1CULL,
		0x07CEC6104D2098DAULL,
		0x059490EC747F6051ULL,
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
		0x9E7D6C31A2903C12ULL,
		0x4C85271423827A03ULL,
		0x0225F7080A89E19DULL,
		0x0E654F7FE8EB8739ULL,
		0xA530A91506636882ULL,
		0x2D6823DB5E8ACF26ULL,
		0xB6A7BED347C5DF57ULL,
		0x9E970902DAD1B34FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA15201D87304E30BULL,
		0x06B2EDADB5C21E15ULL,
		0x71B7DB169E815406ULL,
		0xE67AC22C5E1DA482ULL,
		0x0A4C63360FF93106ULL,
		0xAFC79F0671E90DB4ULL,
		0x61357D4D0F744E2DULL,
		0xB166B559488E565CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFB0DC971C34F94D7ULL,
		0xEBA5F1018DC312F0ULL,
		0x3F63D5DDC82419BFULL,
		0x5D16F87F40CDAED5ULL,
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
		0x249923A5DCB87C27ULL,
		0xF62E100D1B58C9A1ULL,
		0x3F54BFE68971D369ULL,
		0x9B6A960854C52294ULL,
		0xADCFF438E382D2DFULL,
		0x1B42331AE5DB178DULL,
		0x7B0D19503F543976ULL,
		0xC02CA1F372B6F4E6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDF1203C6DCC374E9ULL,
		0x7A1819C46FFF7506ULL,
		0xC8623ACD2C7ABB10ULL,
		0x8266B703DC011F2FULL,
		0x7191A9E6E4F915DAULL,
		0xAD0F3C6CA6305507ULL,
		0x5B2EA194F1D82D74ULL,
		0xCEAE6396061997DCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x36C6280AC867159DULL,
		0xD7A694261EB23487ULL,
		0x31F84AE6DD60E08FULL,
		0x71C120E2981FD2E5ULL,
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
		0x13D0D74403D0B1B2ULL,
		0x4B6301C9A7CB8861ULL,
		0x0CA75324CD16EDC3ULL,
		0xF406EFE8EC402B32ULL,
		0x9F193074F85DDE85ULL,
		0x29DF5DCC6585D87EULL,
		0x3CD1415A9110C129ULL,
		0x095CA17B209A2FE8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF9A91032DAADDE42ULL,
		0xE46AE12C9ADA63F3ULL,
		0xB8F1C7A67BDFD056ULL,
		0xB2F4F17BB4FF9A24ULL,
		0xAF31CADAA9A234B6ULL,
		0xC5B610A5B6946ED9ULL,
		0xC81890628538F965ULL,
		0x883ECE50687CF9FDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB680DBF8D8FE0558ULL,
		0x4519945B04C6D2E8ULL,
		0xA71FD050133EC46DULL,
		0x6B7F56C48B9691DAULL,
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
		0x40A35971F875E3F8ULL,
		0xA27DD7DDE22597EBULL,
		0x8E7DE9A7F79E9DFFULL,
		0x01D57C6F3C055344ULL,
		0xFDE5CC3065167DC7ULL,
		0x219B78554905043AULL,
		0xD29A136177199857ULL,
		0x83313BF61FD85013ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA84C026678600B67ULL,
		0x38D30C0B6DBA1C21ULL,
		0xB8252F3BD0E4517CULL,
		0xDC264783C8452756ULL,
		0x98B31BEA411E544EULL,
		0x198FF21362613328ULL,
		0xB4486F2C620B1662ULL,
		0x4D68C1FABC632D06ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9DDD8174D6EC0191ULL,
		0x9B60B99AB0BC8484ULL,
		0x56771A4D46E196E2ULL,
		0x2171503C37235FE0ULL,
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
		0xE6BB977CBAB15A9BULL,
		0x4B6628D79965A528ULL,
		0xE973EDA05AC7D2F3ULL,
		0x299F6AAB5D353EC2ULL,
		0xC2BEB31E4B72B7B0ULL,
		0x1CB5471FC4535732ULL,
		0x92B3F074376D2C81ULL,
		0xD867CE9E3053FB74ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDDCDFD44E61479BBULL,
		0xB152ACEBAFF0C90EULL,
		0xA463DC0EC97B0A31ULL,
		0xC53BAB820B614CB0ULL,
		0x2A3EE3E8550FE14DULL,
		0x9C3A4644A778DF7DULL,
		0xDBA79435F78067E4ULL,
		0xBC06013BAC3FFB6AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xABE65C3A6748B417ULL,
		0xAC559C7231E2A10EULL,
		0x70E5C2CF0E71F7FCULL,
		0x1AE83BC8ECCBF383ULL,
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
		0x19A8D0EAF16EEE29ULL,
		0xF7554C3781BD78DDULL,
		0xB0D98ECA98A6DB1AULL,
		0xE3CBB09230F09193ULL,
		0x599FD056416BC40DULL,
		0x760353297D89446BULL,
		0x076CCB75235B3DC1ULL,
		0x2487029036F8FB8CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x87D1FE5095ED188BULL,
		0x00BA33489EE916FDULL,
		0xF6A3B16841EC84E9ULL,
		0x868A00AD403C8E72ULL,
		0x0951158A53EDBCC4ULL,
		0x2AA2BCE3C58DAC94ULL,
		0xF7FA9BABBA88AC50ULL,
		0x5B8F60A43B9E1DD6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7D868CDF9C36E944ULL,
		0x26F16748322CEBD5ULL,
		0x0528F547E5FBED03ULL,
		0x3203B8EC4030EC01ULL,
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
		0x27A79F3A8A3F71EFULL,
		0xD2E2651A6574EE8EULL,
		0x62B20FD8439E42EBULL,
		0xEB7B47880B4648DEULL,
		0x461E42D76C5FCF2BULL,
		0xCB66BFE562B2EDB5ULL,
		0x5292818218F4FD18ULL,
		0x20A1D66B257FAC29ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7BD960AE66B4CE96ULL,
		0x57828F3A9E180355ULL,
		0x31105A1EBF49EC03ULL,
		0xD43F3509D6FC4240ULL,
		0xE0C506C94B51BB07ULL,
		0xDFE81D2FC3471DDDULL,
		0xD0F6A2C1F462875CULL,
		0x88CBFFF2401DAF7BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB70D28A50BA19E64ULL,
		0x702BFCD5715DC531ULL,
		0x6EC4C63EF211D0CDULL,
		0x20F9E87040D5885FULL,
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
		0x417BEE6D52640844ULL,
		0x810C08D85705A42DULL,
		0x0734C6F90FD18604ULL,
		0xEFDA3A8F97F90D1DULL,
		0xEF48BAB1FB9D20E9ULL,
		0xC64A9AC87B19BB15ULL,
		0x2ADCEE08B4D66E49ULL,
		0xAEA4279992EC4371ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x811F3467E0AD5223ULL,
		0x06DA3D5CE0AADB82ULL,
		0x5AF097F02BE43901ULL,
		0x83185F38A877388AULL,
		0xDB12441C28F04A18ULL,
		0x306FF80EC3B6E391ULL,
		0x7B89B9F48BDB1639ULL,
		0xC2CF9B8D016C1D47ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC0725442B75E98B5ULL,
		0xB8A5F30CAF06C645ULL,
		0xB29DEA06F93C5F79ULL,
		0x6E4EA53488877EC2ULL,
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
		0x413198E43A1FF264ULL,
		0x36448E6ADD05FEA3ULL,
		0x940CF05749516655ULL,
		0xE29C83342864DDA0ULL,
		0x02DE31E2F4E1444CULL,
		0x7674558B70BBE3B1ULL,
		0x7DBCBD53A6BBAA82ULL,
		0xA0C6A8906971144EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5EA79A777BFBABB5ULL,
		0x2245E145B11B22B8ULL,
		0x1838DB4795E9652EULL,
		0x471CB45C1FCFFDA1ULL,
		0xC3B5E2E28E883309ULL,
		0xAB54CF5DD59EE372ULL,
		0x3AC98700F613C046ULL,
		0x267C67CE45AFFFC7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4285B87BEF5CD960ULL,
		0x3AAC97EA3238E528ULL,
		0x6BEE2555EC54C607ULL,
		0x42856BA9573DEC13ULL,
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
		0x4F8397E9520A29E4ULL,
		0x56700BFB245893DDULL,
		0xB0336EADAFD92CDEULL,
		0x59731DD9AF7EE76BULL,
		0xE0C5CE50B3927A7FULL,
		0xFEB478067144CAE0ULL,
		0xA0CD16624B7443FEULL,
		0x96AD6337D1E3633AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC055866DCE416CAFULL,
		0x0A30E34B53684741ULL,
		0xC259BB1C8DB64E59ULL,
		0x53254BA29A849BB4ULL,
		0x699D587897BD8F8CULL,
		0xE1222D4419D17B19ULL,
		0x2A21811CDE9E9D59ULL,
		0x7C19EE25C8FF305AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3F2F8F8FA5639DCCULL,
		0xAFF64188CC0E2437ULL,
		0x8B51DBDF49D99B07ULL,
		0x783132E466D9D908ULL,
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
		0xC7CE4173E801DCEAULL,
		0xDF97FD93BB3BAAB4ULL,
		0x83D34EB77927CF7BULL,
		0x139082DFC758E44DULL,
		0xF42031E04201BF4AULL,
		0x35082EB8EEADB856ULL,
		0x53485DCD022FB6B0ULL,
		0x80F1A8038C0D45CBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD3FE0D09C4D64CB0ULL,
		0x680DAC51EB41E975ULL,
		0x6A5C702091A1A25AULL,
		0x10231F9BF1B15B5DULL,
		0x5C4FA0755103E51DULL,
		0x4500D13478938803ULL,
		0x7FA96EB647AD295AULL,
		0x439C57685194A09FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7CC5CA49E8D9F43EULL,
		0x18A232EB57DCEDA7ULL,
		0x830E5BF696E727E3ULL,
		0x1E175A4E83900D71ULL,
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
		0x85E6118F2D011DD1ULL,
		0xB003D3708962C65EULL,
		0xED9FFD8A5E4E2EACULL,
		0x3FF8A5C54A0DB024ULL,
		0x7AD586F95901B76DULL,
		0x41F905757CF90AAFULL,
		0x45927728A06B4654ULL,
		0x3ADCB7422F5914D4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC1D985B43D8DDF56ULL,
		0xC912D1449CB16604ULL,
		0x2E613BF271CF138EULL,
		0xB4CCAA8F6088C214ULL,
		0xD51677B27AFD2160ULL,
		0x4FE49943460B4DE2ULL,
		0x10632029499B1503ULL,
		0xCD807AAF3B49F815ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5E68D05FE4218112ULL,
		0xD5F911A013FB66BAULL,
		0xA445AB7ECF666D21ULL,
		0x46DCF90623C33272ULL,
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
		0x4AC1CF3D6474A74FULL,
		0xB7C82B62E9A76A78ULL,
		0xBC4037A5B64EE431ULL,
		0x5C700E712E3837A0ULL,
		0x7F4298E2DC469840ULL,
		0xC0097E29EC693D9CULL,
		0x88D2AF0E4F344D30ULL,
		0x34A62F5DCC15303EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1745152ABC69E7C1ULL,
		0xCDD60BFD93417C4AULL,
		0x434444D9CE838C7EULL,
		0xA1749619DDCF68ADULL,
		0x4CBF412CB5DD0AD1ULL,
		0x3BC86A7DAA4F6AB3ULL,
		0x55EFDB4A9B97C96BULL,
		0x493EEF6EA51E8CB6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB2FBBF1C5BB5BD83ULL,
		0x8B9B0AF7263B3CCBULL,
		0x06A761D89106E704ULL,
		0x2C4EF5D71905152BULL,
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
		0x0E4DDB35EAF93440ULL,
		0x3CC00CB107130ECBULL,
		0x73BF9978F82BD528ULL,
		0x3F6394E8036E49AAULL,
		0xD6D9A7EF261D2002ULL,
		0x1D14795530375B2CULL,
		0x5AF61B6988E131BBULL,
		0xC121DD1633DB7EA0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD66AE570F7B0BB9AULL,
		0x6A611318DDC47B83ULL,
		0x8E238F6332DC0BA8ULL,
		0x7984A40C40D6332DULL,
		0xB0045CC476463313ULL,
		0x48027DEF6F4E54ABULL,
		0x204200594253E21DULL,
		0x0C70FFCFDFCFA139ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFB8C1E1B0D2FA80FULL,
		0x730A4AB2CBE58A72ULL,
		0x9C580E803E499AEDULL,
		0x181FC94C3C5AF3CFULL,
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
		0xE0FD8D19CE67BD27ULL,
		0x72FD21D6E2586F52ULL,
		0xB10C7251DDF67B2FULL,
		0xB0CAEAFE18010A30ULL,
		0xDDE2DA8AD2C073D4ULL,
		0x1A9F90925A7D3031ULL,
		0x615E06427B2EFBD8ULL,
		0xCDEECE3825320061ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA5B248F8860E04F5ULL,
		0x34006B86A9F71C8EULL,
		0xA9B2C4266C9D2DE9ULL,
		0x256DBEEBAC378A84ULL,
		0xAA3524224C6F49C1ULL,
		0xE0E3FD68259D88E6ULL,
		0xA9743AC2AE949998ULL,
		0xD92EEC594192AB24ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE71457A53865F6CBULL,
		0xD0D48E94119427EDULL,
		0x540DE323D043E2A8ULL,
		0x5FD8B328357026AFULL,
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
		0xD8959F2E3F077E5EULL,
		0xB08F0623BCC146E7ULL,
		0xD44CE3AF0D6360CFULL,
		0x537D7D96175C5A26ULL,
		0xE171F91423B337B7ULL,
		0x13ACE490E2E53EF3ULL,
		0x25E7CB722FE9B9B1ULL,
		0xEF77640817B374D8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2A9AA1EDFAE1EB86ULL,
		0x3B8EA737CE9801BBULL,
		0x6F4A1C6639FD7F3EULL,
		0x8663B0C118BD6C60ULL,
		0x68A8DC154FFB3EB8ULL,
		0x96A2CE6C82ECCABAULL,
		0x728BDDD5446E01C3ULL,
		0xBC81C23B3D971791ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9BD54B13B17489BCULL,
		0x047FA8522D0A85B4ULL,
		0x04A80C93C7C32ED2ULL,
		0x5D8FD13D5ED4C645ULL,
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
		0x83D0D00552F38B67ULL,
		0x48012F9425A4786CULL,
		0x36B25419EA34DDAFULL,
		0x03D3898EA82D4D60ULL,
		0x4532B78E1A0B4D0AULL,
		0x06A6A9149B3DF276ULL,
		0xFBA33CED42452AC2ULL,
		0x88F94E4D3DA951DDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5C5D9C0C53364B47ULL,
		0xDA19F719B784DAA0ULL,
		0x13C4C2BA55CCCEC5ULL,
		0x2C4CDE335A92BD66ULL,
		0xD93A8BEE1A6BE75AULL,
		0x72B13A65208CDE87ULL,
		0x992634CC80575F87ULL,
		0x336B04C7A5251AF5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2E49ADB8F1665A1BULL,
		0x6455A686A4689330ULL,
		0xC17CC63C5DB4399BULL,
		0x0AA5952FF13AB678ULL,
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
		0x306F528CBA1C148FULL,
		0xCD6ED33F26962DF9ULL,
		0xE078D10431BBA2BDULL,
		0xE0E62AB01F5BB36DULL,
		0x67C31DD8E7C9441AULL,
		0x4948F489B3F7348FULL,
		0x255C7B2B5E6D56AFULL,
		0x4C913F6FD3ED16E4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x999EDC43B8A2717FULL,
		0xEFB871329889BD80ULL,
		0xC212482B6617B272ULL,
		0xCC94178936B6F789ULL,
		0xB253B3B5D7FAD1A9ULL,
		0x0DC83B7BA306300DULL,
		0xB9D445183C44CD94ULL,
		0xAB4CDCCDB586A9FBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x855A377D5A1E9DC2ULL,
		0xB2D1DA2311D31BB9ULL,
		0x149E8FAFDDA84A55ULL,
		0x0478B7376BD8E664ULL,
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
		0x646CA10D11B97BA8ULL,
		0x0D08C07A6273CBBFULL,
		0x153A228FAC2F3BCCULL,
		0x528FC2B31650A261ULL,
		0x0D606DB4BD18AE1CULL,
		0xCCF8A1A0B5B247D9ULL,
		0xEBBDFBD9DAF2B733ULL,
		0x1C04CB9067F7E250ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFC2F68E0ED8BD8AAULL,
		0xE3C191F1FB213116ULL,
		0x2F0DF23B9837D770ULL,
		0x7F05301EAD4817B2ULL,
		0x03C39CA980048C0FULL,
		0xADDF84BCAC7FB684ULL,
		0xA69B94565CCC4D58ULL,
		0x36273B65EA988C18ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD5843FD7352AB041ULL,
		0xC7017861C4D42D47ULL,
		0x29478DD8CDAB1AE1ULL,
		0x726DF8E3052F5709ULL,
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
		0x067F5DF038BFDA5FULL,
		0xC0FB3A2E12060B86ULL,
		0xDCA0C7F08C0C550BULL,
		0xC93DFBAF67DFF748ULL,
		0xBB59803D4B20D1EBULL,
		0x86DFB065888EF5D2ULL,
		0xDF63349A1261DCECULL,
		0x369EA1C8AF96BE7AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDD2415C30C189722ULL,
		0x3CDF8EFAE76679BEULL,
		0x24513A863947A52AULL,
		0xA76C6608AE1859B4ULL,
		0x73090E5EA47FDC32ULL,
		0xFAE30284B8E2847CULL,
		0x14F40E693908C97CULL,
		0xC557D1BE90F70B68ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE54C2F39E88BB982ULL,
		0x4B9D7A91FE386495ULL,
		0xC4CF38AA95FD9270ULL,
		0x72547727457C325EULL,
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
		0x8F6EE6D8936A4A64ULL,
		0x334F073793CD8F92ULL,
		0xBBBB4C6AB4E5BFABULL,
		0x7AEB50E48CA4E4B8ULL,
		0x92EB94ACF5371401ULL,
		0xA3168EF1D1DABDB4ULL,
		0x7422809F5B53760DULL,
		0xD0B7626AB30D5E53ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6B8FA787ED47764DULL,
		0x592D05E780CDBA2EULL,
		0x2418422F52B4B09EULL,
		0xDFF2683C25086C2BULL,
		0x74D5B5904FB1F52BULL,
		0x9A13CEDE93D5F4FDULL,
		0x07FF0A62F8EE89F7ULL,
		0x2D19D92AEA97B4FFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9B1E5D9137E56B58ULL,
		0x308A842B47B5A092ULL,
		0xA4E69731FD2C1A52ULL,
		0x645B482029139B15ULL,
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
		0x7B862317810B328AULL,
		0x7B2C1CBB1F34A83FULL,
		0x4203FA93CB6396D4ULL,
		0x14263360931A36E2ULL,
		0xFBFCD903C903035AULL,
		0x24FBD312FA03CF52ULL,
		0x1215FD862C1F1DD3ULL,
		0xF23005F553D252D6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA08C604EDEB22C61ULL,
		0x264E622698CB36B9ULL,
		0x3500EE6B4FF72E66ULL,
		0x4DF7F17AC2932716ULL,
		0x960FD40C2CDDD76DULL,
		0x8951A631FFE9BA1EULL,
		0x38BE3880BA0E9E9BULL,
		0xFC47B451E6F33133ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFC287F89CFDD8B0BULL,
		0x702063F9A648974CULL,
		0x500A4AF769DF4AAFULL,
		0x46AA6027F9A60DF8ULL,
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
		0x6276F03FAB396C34ULL,
		0x9272BA13AEEC9032ULL,
		0xDC42E18A4034FC02ULL,
		0x854D782BED21DB62ULL,
		0x340B2E4DFDA15CDFULL,
		0x7345675F7F89C306ULL,
		0xA39327DF455C982DULL,
		0x2FC00E09C65C9203ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBA5405D9BB383C29ULL,
		0x8982A352DE33C778ULL,
		0xCE919EDBAA9268F3ULL,
		0xFC0989CBF23A2FD7ULL,
		0x08F40AC6339082B4ULL,
		0x407BBBD0F4F5EDF4ULL,
		0xC9AE7F91730C98DFULL,
		0x43037767CBE3CD68ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0D92308DEE8191E8ULL,
		0x92DF8DE962AA696CULL,
		0x65A23E3BCD8278AAULL,
		0x2D424A6B28D4DA87ULL,
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
		0x5E0CA8594A2D2FCFULL,
		0x5B88CADBF53D7C8BULL,
		0x7EDF95D1FA860249ULL,
		0x26AC39845665E581ULL,
		0x8AB46957C9108492ULL,
		0xB6BCD9575EA078EAULL,
		0x685E9F6866D446A1ULL,
		0x7BCF6632721AF56BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4C2FF0445D28F6A6ULL,
		0x49326A2E36817D54ULL,
		0x9AEAD1B59761383DULL,
		0xBD432A1936E09808ULL,
		0x08F5C625451FDA94ULL,
		0x4B0EE26737427469ULL,
		0xE28A98FFE3788E5BULL,
		0xA7087BCF4051CB5EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5428F19482BD73C0ULL,
		0x0E29085396B0AA70ULL,
		0xC16DB79FE2C22480ULL,
		0x7EEFDA2483618B54ULL,
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
		0x669167E18B382DD9ULL,
		0x32E5460F9498B5EDULL,
		0x693C8127703C28DAULL,
		0xC3C565A5F36820D8ULL,
		0xE820286B418CF40AULL,
		0x318D88C0192B74E6ULL,
		0x04DE1D7E661A2C89ULL,
		0x51B1F5A8A01A0009ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x935D8611571FF9B2ULL,
		0xCE177E8BC253DCAEULL,
		0xA0BAB49B46EF07E1ULL,
		0x8C47570DC7F7A711ULL,
		0x7C7828FE47EE7345ULL,
		0xF882253C8FB07D1DULL,
		0x0A91B8B85E391131ULL,
		0x6C1BEE3255BA31B6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCE23CBFD419F50CDULL,
		0xDC7E8D0A3A85A124ULL,
		0xEFD8C1F154B72FEAULL,
		0x4BC32A2735A91A17ULL,
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
		0x8AAB4F53F1A8049CULL,
		0xF21B2D89CDD8855BULL,
		0x0B52A389C6AF7FDDULL,
		0x6431255D5F0B70F4ULL,
		0xB646CC163CEFD695ULL,
		0xC09F19CD3AB16610ULL,
		0x337ED6FB2228000CULL,
		0xE47549220E61CEACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1A86076C21AA16F5ULL,
		0x5CD5DCFB01958CA5ULL,
		0xC5DEEF27E7FB38AFULL,
		0xD43AF624B1AB6E40ULL,
		0xDF22C0AD739E98B7ULL,
		0xDEC25A252B192E87ULL,
		0xB7BAEA070E6B9CD0ULL,
		0xA36DA0A466ED6991ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5F7EF975B20D1DF1ULL,
		0x1C09C3811CDB3706ULL,
		0xA488E09CCCAB0212ULL,
		0x371931DF88A704A1ULL,
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
		0xB5F89D6999693086ULL,
		0x6590ADF545305E4DULL,
		0x779AA19787A3422AULL,
		0x4AEAE49BED2DB0D8ULL,
		0x7FF726C4D163B2B5ULL,
		0x62BA97AFA3EEE131ULL,
		0x37308DCA1DB7DFF8ULL,
		0xF274FFC745AFCB10ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0A92E38408AF07F9ULL,
		0x67E4332595E94CD1ULL,
		0x69F0D6AA6F8317F0ULL,
		0x7B5DEE6274A6E018ULL,
		0xE3D8CCEDEB8D3100ULL,
		0x281E56DDB0AF62D5ULL,
		0xC7F4D8DC02A5B8E3ULL,
		0xECD39C471328E7A7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD7E70FCBAE91697EULL,
		0xB0DE19F9CAB3D315ULL,
		0x9086A6451CD1F760ULL,
		0x2581BB40F88C9240ULL,
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
		0xF7B5DE2517F38CB8ULL,
		0x64AC1269FE572CC2ULL,
		0x7884EC8261A81986ULL,
		0xDC1359CDD2A47D32ULL,
		0x17C2F6DF2D01B1E1ULL,
		0x0FA4744BE971AB48ULL,
		0xE26BFAD6034A26CFULL,
		0x3A195DA77996204EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF7C5D31002A87169ULL,
		0x47EFC6A7D946A862ULL,
		0xD8745ED55ABC9461ULL,
		0x8BD3677D68B2C5C0ULL,
		0x091D0868D2E2127BULL,
		0xF94D5002E29746EEULL,
		0x342B5E8B8426D5B2ULL,
		0x30E31191B76F58D8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2C9170A675FCC4ACULL,
		0x6DABAE99297B69BEULL,
		0x7DA7C0BBE6298F50ULL,
		0x2E4F3D8B3BB3530FULL,
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
		0x68E52E9C137BBC2CULL,
		0xBD7D5DF4B0A3AAE7ULL,
		0x522D52D0CFB810FCULL,
		0x1B47A24864E60D44ULL,
		0x94E7AC1E8F2FD456ULL,
		0x15C8BA097D8C3BCEULL,
		0x555F3AD3BF59B53AULL,
		0x984EA2BD895C2E5AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x09BC19E80EFBCDB0ULL,
		0x42C915A2FEC4E572ULL,
		0x676497417E25FEF4ULL,
		0x93C236E66F5CB4E0ULL,
		0xD7BA900DC442114BULL,
		0xA82FB60054DD9C25ULL,
		0x035FAB5BEAE0B516ULL,
		0x85FE8671F8BDE94DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x73DB3F3223CAE26AULL,
		0xBF6AE1ADBBCA7881ULL,
		0x16B80758DB88174AULL,
		0x3F699E996D07985EULL,
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
		0xC6AC8160342729D3ULL,
		0xABE2C2D1DD0E9D20ULL,
		0x4F9993A55B978E4BULL,
		0xCB983318C2AA7950ULL,
		0x7F5DED42C65EB68BULL,
		0x45311A045255066BULL,
		0x4667750F56049604ULL,
		0x088395E68DB61DFBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x502D6922D9DC210CULL,
		0x7457ABEB226B2091ULL,
		0x745416A5C4E048DCULL,
		0xFBC8DBC07BA9254CULL,
		0xFF61B03F6EBB88A5ULL,
		0x04E4ADFD2F660524ULL,
		0xCA44B475BB88B21FULL,
		0xABDCD1692AE39DE0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x75F026BC5C83D548ULL,
		0xC2E31FF5EA1DAD06ULL,
		0x486E13CC851B1976ULL,
		0x109081F4F24057F2ULL,
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
		0x70CD9678FE31C644ULL,
		0x8699D37BF0619416ULL,
		0xCF7E788A755D9A16ULL,
		0x1935620258E0D641ULL,
		0x504AD3905986CB7DULL,
		0xC87FC19898196B13ULL,
		0x5EA1CB5EC27596C9ULL,
		0xE070E80075038BBFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x00C54F162958AAD2ULL,
		0x314749ABEAE73489ULL,
		0x4AC6BAD6B67134E5ULL,
		0xAE475AEB722FC87DULL,
		0x10278A78B8AB0403ULL,
		0x93F9498A28E7E535ULL,
		0x55A4A3D1FFADD9D5ULL,
		0x960C8315326FFD85ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF54520E4B578B90AULL,
		0x21485BF486D43E8AULL,
		0xDA4B9C98A8927171ULL,
		0x75D50202C8982A61ULL,
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
		0x7D112C9A623E12B3ULL,
		0x5870C3B53B396D43ULL,
		0x8B3407D41A7E2D26ULL,
		0xEE2DC5710A9E66CFULL,
		0xB56052230E42A443ULL,
		0x734FD7019FF6CE3DULL,
		0x2A4147D6F885921AULL,
		0x844E5FB545A135A5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBBDA5FF897A59626ULL,
		0xC26505F44E69D516ULL,
		0xA19B06820A5AA14AULL,
		0xE4E5D9C2E2ABD51BULL,
		0xF7BA09C1956863BFULL,
		0x51D491BC7C09E4CBULL,
		0x37716B3908FF3FC2ULL,
		0x5C53E106A75C3EF1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE7E58B19BAFE10F6ULL,
		0x8E58060441FA3F0EULL,
		0xF473C0C39E13C4F0ULL,
		0x7876B999A62F3069ULL,
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
		0x76E364E431C0F798ULL,
		0xE636AB147FDD03CEULL,
		0xA247919A178E9757ULL,
		0xB5309969F08A630FULL,
		0xB12B3625425AED43ULL,
		0x58EF59D25833CC93ULL,
		0x1BBA60EA2480F6B6ULL,
		0x27B46EDD9EA21892ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6933313F9C8CED9DULL,
		0x5ADA607164A2FDDEULL,
		0xD033357D529C9261ULL,
		0x70491D8834C24766ULL,
		0x62A74C1A318E2F5FULL,
		0xEF11A3DCF8311367ULL,
		0x0AB65F0E6271495AULL,
		0xB9D6EF8436B2165FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB544F149139836A2ULL,
		0x42454D0F5BA18283ULL,
		0x58ACA2BB9345C088ULL,
		0x13C8632729686F3DULL,
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
		0x2AFEB525834FB7CFULL,
		0x745A6D858DF09A8AULL,
		0x6548D6969EBC8C44ULL,
		0x8EE5A2F3D861E6FFULL,
		0x7114EC6AECA1AE7BULL,
		0x1545AFF1768750FEULL,
		0x04D9331949D3CA60ULL,
		0x85CCC670B1D4C9DDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8CA2A3B1C6B0F7F0ULL,
		0x6C822C5B0287F046ULL,
		0xE2780E643ED51055ULL,
		0x126DA770A00850B8ULL,
		0xD5E1729ECC5820F0ULL,
		0x9161ECBB8938E1E8ULL,
		0x80AD0303BF7724C5ULL,
		0x666FEEEA9094A3D7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA80025C08789C33FULL,
		0x9BA73B2BC50D2778ULL,
		0x215FEB64E9A810DEULL,
		0x243FF96C27DF3B18ULL,
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
		0xBAA09F35451F78E5ULL,
		0x8B5BD43C442571F0ULL,
		0x14CC86E049094366ULL,
		0x22EE45F3DB068A5BULL,
		0xB36AE5C10062A965ULL,
		0x8AE1390E7C49123AULL,
		0xD4857CDC3D8A248BULL,
		0xF434E61F0B5AC9B4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9081FB20A75B5FDFULL,
		0x847B719F524B07FAULL,
		0xAAD6C73E89E68AC6ULL,
		0xABBB434D73CCDA02ULL,
		0xBF17B6C57B6313FDULL,
		0x546EDA3DAAFEF682ULL,
		0x17D38E259F06EC2BULL,
		0xA4BCAFC2B641B96BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6E779D6A5BB44818ULL,
		0x1BDA759C02DA8744ULL,
		0x6C5F2EBD469D16E8ULL,
		0x430B145B08F21B4AULL,
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
		0x61A1846C47946701ULL,
		0x2A857AB3DDBB0B2DULL,
		0x6BBE18C779F54402ULL,
		0xDF86D3D087F8EFB9ULL,
		0x112D903F8F8BFE2FULL,
		0x23A4C318B19D8C1CULL,
		0x79F88BA9EDD0FA61ULL,
		0x7AEE1F7AF1E6114FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDE10B702783480F8ULL,
		0x0499F439C5714E38ULL,
		0xE405FDFE4BC5BDA5ULL,
		0x518230D97FC682DCULL,
		0x66D6509EEBB202DCULL,
		0xCBA96E11B781B3A1ULL,
		0xF1E9C2BAD46DE5F3ULL,
		0x6491D9CF958AE6D9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCC843F4221BB34E0ULL,
		0x353A2583386BDF29ULL,
		0xB9E9EE46F2E48E98ULL,
		0x5FB6FA66BDBABA4EULL,
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
		0x2AC80379E698E62EULL,
		0x1411F4CC89A72068ULL,
		0xC19DBF658326C3E7ULL,
		0x242A1144E46326E8ULL,
		0x6F72C53D5896A0B6ULL,
		0x400C991FA3E8AA20ULL,
		0x006D33726467E38EULL,
		0x3C9744ED368C72ECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9C701EA48CA7ED34ULL,
		0x6E581A0DD51A1EFBULL,
		0x5E9D3C784C675E3DULL,
		0x3FB965B7781374B7ULL,
		0x789CB5382EA25F45ULL,
		0xD80F9DDBB0A77BFFULL,
		0x1ECDBD81934D5A43ULL,
		0x5A16D013A2F6229CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x321E45999432AF15ULL,
		0x154726D4D039DA51ULL,
		0xE0AC04AC40AFC6B5ULL,
		0x038203D9549F9E0CULL,
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
		0x11F5367422AF2F14ULL,
		0xC7629562D02FDFFBULL,
		0xC9163B1027A0637DULL,
		0x5E4DD73904751DDFULL,
		0xD2D0C9ABDD720E90ULL,
		0x6C2A735DFD54B217ULL,
		0x6A91E435153C5B72ULL,
		0xABC242C7ED3B630FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x60DA0F98F2F0B9C1ULL,
		0x66AE208C95C8D8F2ULL,
		0xFF5DEA143CF803B9ULL,
		0xC5913C30CFBC991DULL,
		0xDBDE0F52A0C25B68ULL,
		0x8A84DCC64B6E0F6EULL,
		0xE28F6339168426CBULL,
		0xD07F868CA572F369ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5922D01A31D30C5FULL,
		0xDF48CF5AA2A32C1DULL,
		0xFA177663BA003089ULL,
		0x24A48BD4DC791753ULL,
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
		0xF1803F11414B55DFULL,
		0xA217720EE041FF0FULL,
		0x543085B88F9990C4ULL,
		0xED8092176A0AD84DULL,
		0x3F67E1BCA8FC2003ULL,
		0x91F14313DB084F1DULL,
		0x8970680A13B3D96FULL,
		0xB96E7458867A9D73ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2C7149929C2228F0ULL,
		0x09BB8AA531BDF3C1ULL,
		0x625924856E19F3ADULL,
		0x23357709CAF99B23ULL,
		0xCF70E9D5F87DDF4EULL,
		0x97679206CC5E6F85ULL,
		0x1F0FF3055A5426D2ULL,
		0x0CDA7DD94F60F9E6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x63B7C1BCD7E6CBA9ULL,
		0xC8CC2F59DBBB3BC9ULL,
		0xBC28BFE6A5B42064ULL,
		0x6841B1EFCCDF8427ULL,
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
		0x5F26191CBF0CADAAULL,
		0x62029F5CD2228675ULL,
		0xF48D14830CB78738ULL,
		0xAF102AA6C9FED3CFULL,
		0xFD50245B3661CD94ULL,
		0x6DA3C8A2D6CE1288ULL,
		0x5848FB2E455E5B92ULL,
		0xC945025116037795ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD9E171FBFFED5BBEULL,
		0x87AA069D283F4484ULL,
		0xC1E4F30704D86F4EULL,
		0xF313AAED2F78CFB6ULL,
		0x4D62B826B93427FEULL,
		0xF10C6E1A2C6F549BULL,
		0xD40C506953EE9E0AULL,
		0xF7458F99E614EE37ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA282B6EB53E5E513ULL,
		0x58D00908F3F37338ULL,
		0xD3A97AB7DE753A06ULL,
		0x67E786EAB7EE67FAULL,
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
		0x1B742029E3453789ULL,
		0x59FE2AF39DE6D317ULL,
		0x94EB037108F8F070ULL,
		0x793D57075A9EEC9DULL,
		0xE924D7E39129369CULL,
		0x3447B2A46F85AF4FULL,
		0x32B5471697441570ULL,
		0x6A79AEA7DCF86DA8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCE18FD574FE542ADULL,
		0x4037D01E375EF7ECULL,
		0xCD8BC397B64D7CC3ULL,
		0xF398FF0BD896F763ULL,
		0x075A204C698B2266ULL,
		0xFF75471802AB4757ULL,
		0x98961B5B2289D305ULL,
		0x9012A6F34E67BB86ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD172634274D6F3E9ULL,
		0xF10251AD8EF34A1BULL,
		0xA7FFBDACA6514F70ULL,
		0x70EF7CC8AB826636ULL,
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
		0xA78EF3DD0DE83D24ULL,
		0xCB0A816D8BF7AD16ULL,
		0x6D0F49AA25D774F4ULL,
		0xD4119E8DE0411E39ULL,
		0x08E30550B31A1612ULL,
		0x17C9F0837877A827ULL,
		0xCBDBBA5935D4D6F9ULL,
		0x99E547244C609D0EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF12EEAAD01EBC01FULL,
		0x9A220746FFCEAA66ULL,
		0x7BA3F515EF64AB14ULL,
		0x1B4B5276ABCB8ACFULL,
		0x870330436995C2C0ULL,
		0x62A30DB053ED7456ULL,
		0xE0CDD0C40A0870DFULL,
		0xD8F3ED65D03D70DCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFD99A928F5A0D9DBULL,
		0x14AE257DF8ACB3A2ULL,
		0xD57C00B8B6C9F1B1ULL,
		0x5C999E5DA1AE22D2ULL,
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
		0xE54ABD9A3FFAC089ULL,
		0x7287ABE700918AD0ULL,
		0x71A5888FA69E1EDCULL,
		0xD184E87F85899A54ULL,
		0x1905E56B62A2023DULL,
		0x3628974963F78DE2ULL,
		0xD375DA271E14C98CULL,
		0x9252FF6A2CDC3AD5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9AC60F2C61A8A6D0ULL,
		0x94C59DB04704525CULL,
		0xDCE061193D9C5352ULL,
		0xC58F2595A7013841ULL,
		0x9B5309914C398E8CULL,
		0x3CC75D8BF0478B9DULL,
		0xD480539EEC0C4D57ULL,
		0xE56F350CA2FCD864ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF31150CD31D34424ULL,
		0xE230A055E5AD8E9EULL,
		0x6D371FADD6443B66ULL,
		0x35C5CCCC55B0FED8ULL,
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
		0x36709E145B80BD0EULL,
		0x000B08382B453BC2ULL,
		0xB4C309E90E541019ULL,
		0xB7E8AAB473201FE4ULL,
		0x85744E31FD4C8314ULL,
		0x5BBC2F3774BB817BULL,
		0xADBA149125156783ULL,
		0xC0ACA8F7BC1E7B14ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x65803E8AE4268402ULL,
		0xE794F8D2CF15259FULL,
		0xFDEC1A473D53F611ULL,
		0x0216D29C58383D76ULL,
		0xC1B01FC0DC42F877ULL,
		0xCAE1C85BB6378D45ULL,
		0xEA71588D99FE664DULL,
		0xAA659F73AE49D4E1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE00F44545EC4CCF2ULL,
		0x98E15403A3C6561DULL,
		0xB3A2D828766A47FAULL,
		0x045D41B228788DF6ULL,
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
		0x0F21F37450324EDDULL,
		0x2183653BB651D94CULL,
		0xFB4D27552AB8AEF4ULL,
		0x9ABA50E4F74BF32FULL,
		0xB20CD630551A7FE3ULL,
		0x2103BF13F8146368ULL,
		0x7CAA614D2120F810ULL,
		0xF89741E3A292F769ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x90E60E2E37EDCC9FULL,
		0x75EFF7F48D89775BULL,
		0x849022BF96CE17F3ULL,
		0xEBDB666FD5A8A625ULL,
		0xDAC3051CE3300945ULL,
		0xE2A56E32142CE42AULL,
		0xA9699C7500DA5D81ULL,
		0x2E29F72672FB7706ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7330EE2901122213ULL,
		0xED936ECEFD25451EULL,
		0xD25A3CAA5E65881DULL,
		0x3B18028A32205BB5ULL,
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
		0x7DAA333F576D1FE7ULL,
		0x4E2AA2EFFDC9CCCFULL,
		0x294C64D9D9D94E2FULL,
		0x7BFAFBF47DFA6CE0ULL,
		0x87019426B5976A6AULL,
		0x172B90D3FD56E5A8ULL,
		0xDCB92B2DCD22E699ULL,
		0x503A77E365AF52B2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x51E8EF5749F125E1ULL,
		0x418C0BB317A201E3ULL,
		0x89FA8990D60A1574ULL,
		0x77BEFABBA266F302ULL,
		0x5E5B7F27D8A32FAEULL,
		0x48A6CF3BF5D26570ULL,
		0x336F81B4D489AEA8ULL,
		0xD960253FFABE6914ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x346861BCD9BCAEE3ULL,
		0xB45353CE03D2D342ULL,
		0xC041033DEA8D8679ULL,
		0x28A4457ABB56276AULL,
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
		0x79EE085020F6C46BULL,
		0xF5DCE85F8280AB68ULL,
		0xD2D79490CA06BAF6ULL,
		0x7F8C938EBC268886ULL,
		0x1A467DDECE0D44EEULL,
		0x4ACECB53F0F927B1ULL,
		0x10ECFEBFCA1FE011ULL,
		0xB704F2A66B3E667CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD4F5BB437D0DA6D2ULL,
		0xC897FADF6FC6AB99ULL,
		0x1C8CFCECECF30D2EULL,
		0xB5CD4352538641FBULL,
		0x157299F723E4DBD0ULL,
		0xA10C17BE273E19FEULL,
		0x5D7E7F0A4D799D4FULL,
		0xF2C2DE60A09F6EE7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5C6C216FE5E8B6A4ULL,
		0x602B95BC047E0861ULL,
		0x58B18C945DC19687ULL,
		0x6B8E52987C39069EULL,
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
		0x22D66997B9F4A427ULL,
		0x6ED5B1434498C889ULL,
		0x453CF3D7DCFBC0E7ULL,
		0x5BFE325917380E8FULL,
		0xB81F5BD8113E8ED3ULL,
		0x9DE643327B0201A9ULL,
		0xD9F25893178901C8ULL,
		0x21B80D7F48946B04ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x19608E69F17131BCULL,
		0xC47D35429020F4EDULL,
		0x9BB8EBAB05D58D00ULL,
		0x9F4FC80D7D87DC37ULL,
		0xFA79E4CE4F9C9B08ULL,
		0xC2AB2991B395193CULL,
		0xAB819F1279D91C67ULL,
		0x230F35E337831EF2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x300586A0868DA27AULL,
		0x351E49DE4EA253C0ULL,
		0x8E3F91443F424047ULL,
		0x09BE6B7622417D0AULL,
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
		0xAF5FFE69D6B49199ULL,
		0xFC4859FB3BED9FCDULL,
		0xF8B95ED769BD7654ULL,
		0xD0226D64ECB95143ULL,
		0xFA4998B2F612655CULL,
		0x9EAEE661C1F47531ULL,
		0xFB593BDD5C4071F7ULL,
		0xC7A499C11148366DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA215CB627CCDDF39ULL,
		0xBDFB0ACC7821F648ULL,
		0xF07DF1F7E205CBCFULL,
		0x467152967A049779ULL,
		0xC89C26E5E187FADFULL,
		0x379ED5C0EF466F98ULL,
		0x8DC97914FBD5B8BDULL,
		0x9EBA228E26AC7399ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6D091778667281E5ULL,
		0x8AAFC70E09A07E42ULL,
		0x4B92569DD78F2930ULL,
		0x1C7ECC5D45D3A552ULL,
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
		0x214D2D0C77D123D7ULL,
		0x56364A41240534A7ULL,
		0x06367F2A01C9382BULL,
		0x0AAC49DC9F887BF4ULL,
		0xDB9597EDE1563280ULL,
		0x5DF68B9F29726469ULL,
		0x31B5D397F336A595ULL,
		0xC306722CA2167F40ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC88FD6464EF6DDEBULL,
		0xA43E2455960B1252ULL,
		0x22581777AB6986E4ULL,
		0x1E7FA56D3289E28DULL,
		0xDE02E5CB820D75E3ULL,
		0x04B18FCD26FE7003ULL,
		0x110B65717B44E26FULL,
		0x72B91BB83755E728ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFC83C7E04DA646EFULL,
		0xF2358717EB306977ULL,
		0xBD2AC1682442A8F7ULL,
		0x57A779B745952CFBULL,
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
		0x07017A03483E6FABULL,
		0x04318F578520F362ULL,
		0xA5081AE37B7F35EDULL,
		0x9A93887CCF630A96ULL,
		0xCAE08712F46EE2BAULL,
		0x18EF44E3590B7AB6ULL,
		0x7DEEEB688B25EFB0ULL,
		0x2D1AB8D777708786ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCABB963BD8D030EDULL,
		0xC6B7D53AA71346C5ULL,
		0x5ACA2ADCB491A94BULL,
		0x222123ADD5CC37B9ULL,
		0xD9DECCA6BB8D9DEBULL,
		0x2D7E3EE5F9E8A843ULL,
		0xC1C6139F3DC3D7FFULL,
		0xE46DF10EECB20255ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x02878FD7E0DE7176ULL,
		0x30409DB8FD38E9ACULL,
		0x384DF7E8437D10E4ULL,
		0x42180C9391DE9819ULL,
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
		0x5E742AA8E4DAF769ULL,
		0xB482531F3F4E59CFULL,
		0x9205BF888E5F7D59ULL,
		0xC2AA7B8BFD326BE3ULL,
		0x57C2A3E031DEF36FULL,
		0xF4CA9429E0CF8994ULL,
		0xA26CE2ACC512B48CULL,
		0xB7550D30BD49B2C1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x72F5B465A34CBF1AULL,
		0x132074BFDF00050AULL,
		0x4747033E00A04333ULL,
		0xC07429F799D16AE0ULL,
		0x47F1BF75D2D683D9ULL,
		0x9C370CCFBE168CA8ULL,
		0x4F2C74BECD8732CFULL,
		0x8DD3361C886B0B19ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x44805E0D5CCEC977ULL,
		0xC747F5C087C3DFCFULL,
		0xA64F0D9D4C747C41ULL,
		0x2B7C3E943C6DE3FFULL,
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
		0x3AF0FFB63C26505FULL,
		0x5FEDBA6DE922390EULL,
		0xAC7FE80943B8150AULL,
		0xAB9B0E21577A40F6ULL,
		0xA7B8B405DFEBFFE9ULL,
		0xBAC6B0DD76CBE5FDULL,
		0x63764650DC3731B3ULL,
		0x04BF8F394CCB6FDAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3E97B04E9C8FD524ULL,
		0x497AFDBF4E7C99B2ULL,
		0x595436A4A2D01032ULL,
		0xF6B9767804015FBCULL,
		0xE6EA314ED38E1B93ULL,
		0xF9F5CEF18D91EC29ULL,
		0x1738471E8766F9BFULL,
		0x2CE4E69DE520F71BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9B00B69375865F08ULL,
		0xB57445B33940B4CAULL,
		0xA45F92DD37D05306ULL,
		0x3F569EBAB6C6CD9FULL,
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
		0x3A2CB883E2B2F1CFULL,
		0xAD39C5A17262BDCBULL,
		0x9AE2BDAD4DAE22BDULL,
		0x4653E990A23DA1DBULL,
		0xA664530CC6464BC7ULL,
		0xE2308E6D2C667BC5ULL,
		0xFF78CE613618AF5DULL,
		0x447A1FD9985D780FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0918D2C970B9FB24ULL,
		0xEF9863E5256115CAULL,
		0x9B9BEC4349405C4EULL,
		0x62E2D21D3272B2C2ULL,
		0xD9A0ADE6DF40191BULL,
		0x731457116D554066ULL,
		0x4F613ED86C90AB78ULL,
		0x9354318011FFC7C2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x961E695ABCE47A6BULL,
		0x3BD1995AA9907813ULL,
		0x22C61FB7EE9E5A7DULL,
		0x2F1278BD61B31AA1ULL,
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
		0x48AD5016189B14BAULL,
		0xF4C0EEF59ED8B82FULL,
		0x9CFD54E18E6774BEULL,
		0x684ED751E865B9B7ULL,
		0xFD7FA209C6828AF1ULL,
		0x75778AB4953A2FFBULL,
		0xD1F128E1D870D26BULL,
		0x0FFDD0EE97B11B91ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x639BCF2614967181ULL,
		0xB8536642E9AE83F3ULL,
		0xA2207BC72C378A28ULL,
		0xD414D39F8C8DAC6FULL,
		0x9DA2DD8A9E0B3DFDULL,
		0xDF59BAF39814252AULL,
		0x37A96328565F05A5ULL,
		0xE15BBD342EE3976AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1FD6ABD005BA0AC4ULL,
		0x84DA5F5848CFCF50ULL,
		0xE18432A3B0D44FEAULL,
		0x0048F15DEA59AB28ULL,
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
		0x7428E8AA6A4F1BEBULL,
		0x017926C0E0B14F0AULL,
		0x8F2A4063D5001F41ULL,
		0xA97583378D2D5BBEULL,
		0xF843AB1D5287ED44ULL,
		0xC62CB927431F2E5FULL,
		0x6CE57368ED208741ULL,
		0x0B066BE2E7BE0090ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2E944D93445F4039ULL,
		0x83A7D8F41033F189ULL,
		0xDB31F83DDA268726ULL,
		0xD782992759BAFB32ULL,
		0xA2A4D4BC5E5EAD4FULL,
		0xCF6309ED79C789BCULL,
		0x454B0B7CBEB2DA9AULL,
		0x6E215F8EC47F3CDCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFB286D7B640F57D6ULL,
		0x1FC15060B37FCDBFULL,
		0x94E3B534DF2138E3ULL,
		0x1BF2BE8D6EC36D49ULL,
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
		0x8C19D4E31358FB25ULL,
		0xB379FD6FB26DB8FFULL,
		0x6B654BAFC1FB0047ULL,
		0x5F211CA7D9E4E8D9ULL,
		0x94A1721C93076A29ULL,
		0x4C4957C6933DCE54ULL,
		0xD404A32D089D72B6ULL,
		0xD8847166CDAF3C0BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2887D41C675F7F69ULL,
		0xE88E113669632668ULL,
		0xA4DC754F829BB529ULL,
		0x1DF413EC1F58C259ULL,
		0xB441D51E5DC8C695ULL,
		0x999C715939A5AD70ULL,
		0xC9E1D7A418CBFA38ULL,
		0xFF09FC8262085AF1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB1C34E829345C2E3ULL,
		0x50962074959F746AULL,
		0x47B30CB3D8772DC6ULL,
		0x095A62A3B551905DULL,
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
		0x3E242EFD829F23C3ULL,
		0x51296E6DEF354988ULL,
		0x74A0A6FBFF682B71ULL,
		0x301D9FD0F761B560ULL,
		0xCA7B484A62447EA2ULL,
		0x196490CD4BBAFAC5ULL,
		0xB68AD445DC494BF5ULL,
		0xA6A6D21F41835A78ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x603D041A93A5784BULL,
		0x31749B958174EB00ULL,
		0x59C709D78C29378CULL,
		0x77E8918B1508C8AEULL,
		0x64A0A784BD450804ULL,
		0xEF11F3840D90E236ULL,
		0xF856EF1A1239CEF4ULL,
		0x0B6CA1A80B94EFD7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFC5B08396CE54A43ULL,
		0x67F82BB7A80003D0ULL,
		0x568DA1A4718B81EBULL,
		0x42D83FF7E3BCC08EULL,
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
		0xDF2F98E5469FB28EULL,
		0x4FBC0165C0EDF9C2ULL,
		0x323DCB1D8A917011ULL,
		0xD34DEEF5033BB013ULL,
		0x736497F6CD003044ULL,
		0x0BA5D41257430597ULL,
		0xCF08FAFAA313807EULL,
		0xE83313F9245C86BBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x03D5D9582DC70625ULL,
		0xD83593C7475ED295ULL,
		0x407B3E0C70814828ULL,
		0xA4365E59EEE013FEULL,
		0x086231D1352BA6ABULL,
		0xEACAB9FCA7FA7C38ULL,
		0xD705DFEF41E2856FULL,
		0x75709F90190260CBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBDB4E921A2651BA5ULL,
		0x580C4CD67E538B57ULL,
		0xC23890C187556C01ULL,
		0x37F4D832C3BD3DB3ULL,
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
		0x251952896D3B4A73ULL,
		0xF8544A7F164CABC9ULL,
		0x0931AE770CE81B46ULL,
		0xD1DBACC21D439CDBULL,
		0xCB707D7DBE21E4A1ULL,
		0xB89ABF0D378EE101ULL,
		0xD81A1C5979E6E9A7ULL,
		0x9693F0B6ADDBA977ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7C5ED501EFF94B09ULL,
		0xA315672C5B6472C0ULL,
		0x805A0EEF673A05C0ULL,
		0x8AAE738FF061F214ULL,
		0x15057D6386841F05ULL,
		0xAB93C0CD461DC8CBULL,
		0xCA15204AE4510DB4ULL,
		0x7716ED40D1F532ADULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBC9C816BBEAD553DULL,
		0x4448A0D091B1D127ULL,
		0x9D9509B1D9ECBB9AULL,
		0x73BBBCB0D1174CC4ULL,
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
		0x09FE48B883BDC45EULL,
		0xEC17DB876584E545ULL,
		0x27D899865C7C442DULL,
		0xCE774A00FDECE922ULL,
		0xCCDD44DDB0B3C374ULL,
		0x4ACE19BF2BD25FD2ULL,
		0x6E3D4FD5B377C03EULL,
		0x26ABA1DEB2F4C6E7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3264CDB4C7DF759EULL,
		0x58E80FB09E36395DULL,
		0xCE519452B5274CF2ULL,
		0x837246A8030D180DULL,
		0xEE3287065EFDD3E7ULL,
		0x8C36D44949225E15ULL,
		0x1C0A1EBA788E483AULL,
		0x20C4611F9DEBA940ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE4F1A8F9DCDFDDD4ULL,
		0xDDA41B566D6EEDF0ULL,
		0x8D204F3E65FCC7C9ULL,
		0x2B589FB61A3A37EAULL,
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
		0xB70234BE02A8AA10ULL,
		0x9BBFB81CD5239433ULL,
		0x148067E72F743417ULL,
		0x84214674EBCC6A64ULL,
		0x6735F63CA99491BAULL,
		0x2E1C69F1FC933CEAULL,
		0x3058B00A1F4E733EULL,
		0x16FD2EFA4F3FC883ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0AEEC4BCECCC55CAULL,
		0x599AD0F6115F5D65ULL,
		0xB892D2EEB88FDF59ULL,
		0x325650F33F71F94CULL,
		0x898B026190DACE6CULL,
		0xC0236D33ACDD4545ULL,
		0xA902491E5BC9F2A4ULL,
		0xFAD55D5A96206D9BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9373A286C16F4CCEULL,
		0x951A6B6698C6F947ULL,
		0x72C0DBF77C8F6B84ULL,
		0x7FB413372701EF75ULL,
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
		0x6F54E389956D1A17ULL,
		0x60861A03E53B602CULL,
		0x0519BEE0DE58C166ULL,
		0x424E94D340DC541BULL,
		0x5B9FD4D449874263ULL,
		0x379CDA2821F224CBULL,
		0x7EAA98D661F946E5ULL,
		0xB6BBBDD092DBCAB8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4F48D6E494CD64A6ULL,
		0x614421B933523823ULL,
		0x4EA2AEBB8DC63622ULL,
		0x0E64089C99AD1918ULL,
		0xAC583D20BA988EE1ULL,
		0x48B72E160962C673ULL,
		0xCE937FE9FA0955E1ULL,
		0xA75BE2A574225E53ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x24AC914C380E5B09ULL,
		0x755982FA5731290DULL,
		0xD9E4C33CBE3051D9ULL,
		0x7C25149D36B551F4ULL,
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
		0xABB1B8823E64AB8BULL,
		0xD4C592699211B890ULL,
		0x06E8092B767D60ADULL,
		0xBEAED4A818494FA6ULL,
		0x68F8F1B3758632C1ULL,
		0xA6BB9E96EF0BD51CULL,
		0x5FE0AB532B95C899ULL,
		0x57A58919792BF8EBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC383F1EC66068FBAULL,
		0x37672DCABE83AA8AULL,
		0x0C51C51A8BC5C4C6ULL,
		0x1F327B1870031CB0ULL,
		0x1E5195EDCF13CB6CULL,
		0x586CABD0931E4A76ULL,
		0xB8E066CE5DDFE98AULL,
		0xD09BA4D743348990ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFD0565EC8D596FD6ULL,
		0x3D166E1078D0A2B4ULL,
		0xC4A06FC773B6B82DULL,
		0x2AF43B63AB00BA6AULL,
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
		0x4B5703B361D2182AULL,
		0x26E7D6B4DE25004EULL,
		0x9207BBEA4B0076B9ULL,
		0x75D85159B672FDB7ULL,
		0x7AC05B91B0706719ULL,
		0x93D621DD45332D16ULL,
		0xB2FEC80185BEA96CULL,
		0xA0F8DCC7847360DEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3CED24F40DC8D9FFULL,
		0x07D800719D952868ULL,
		0x8464B60B556ECBC2ULL,
		0x98B425A559E666FDULL,
		0x303CB1DD50897DBEULL,
		0xF340252D215EFFA3ULL,
		0x2866CFAECFA62384ULL,
		0xE573F8E1E6BD9959ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1DF50F85904FE01EULL,
		0xF5535868920E9703ULL,
		0xA031E225FD358B58ULL,
		0x32DDFFC9C588348CULL,
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
		0x3B0A147C84163195ULL,
		0x01F85BE5119CDEFCULL,
		0xA008C8F6419E4677ULL,
		0xD5338ABA01D63455ULL,
		0x3A41934F42AE6F21ULL,
		0xD7169B843D772A3BULL,
		0xCAE045E2ADBFCA7EULL,
		0x399FD576DF4C915BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD9068C09E127D2A4ULL,
		0x803B54A18A7AFCB6ULL,
		0xE184E924B10F0CBCULL,
		0x5F1954716AC0C00CULL,
		0x72F7F8FC140CB23FULL,
		0x6D76A93E454CA7BEULL,
		0xE00C8A152280B262ULL,
		0xFBFDE6294D2B8677ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF6F070CB8EF06442ULL,
		0x2F7AFDA65D7140CAULL,
		0x99F1C0543BECCDF2ULL,
		0x1C23BBCC47FD121DULL,
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
		0xC4DEC2C1A0181897ULL,
		0xB91135B998F57C0CULL,
		0x8F5BE3817493BF85ULL,
		0xB93A37E6D02F0A78ULL,
		0xF5DF57ED074AEB7CULL,
		0xB334D1E50AE50DFAULL,
		0xD6FE9F745BD78D77ULL,
		0x3E7AA9ED977FF19CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9753578B583E9108ULL,
		0x088708335B31FE6CULL,
		0xFBEA2F03A85B6005ULL,
		0x3A3A72CE871B55FCULL,
		0x657AA0A67EA8DE7CULL,
		0x8C089733C49562E4ULL,
		0x1A558B09AB0F7C56ULL,
		0x8D4C3C4AE1C461D9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9C7E9FAE8FE773DAULL,
		0x811AE3D6AD96E2F9ULL,
		0x948ABC5409EAEA6CULL,
		0x4BE40B3F42EB0B89ULL,
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
		0x11FC739D6D04B49FULL,
		0x63F7D27F093545A6ULL,
		0x60B25023FF0162E5ULL,
		0x9866FDD528E0BD9CULL,
		0xD40A2DF7D5DA5C2EULL,
		0x9C4B6D02CBF4AB3DULL,
		0x14DF9D1811D600AFULL,
		0x5108A7BB4F5C1B02ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x64F0A334095FD152ULL,
		0x2C4FD5A737285BC3ULL,
		0x7C618DBE49047F50ULL,
		0xC2804977B6F594C8ULL,
		0xB571937D55C2BCEFULL,
		0x98331DAE1C7AA446ULL,
		0x9CDB5FB4A4C677FEULL,
		0xFE075C549A51588DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x37B2BE98672682CBULL,
		0xD343C369DE29F291ULL,
		0xB4F1DF27E64B2DDBULL,
		0x2817E59C5184061DULL,
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
		0x0A5EBDC42E51BA1FULL,
		0x41D312E914CD9244ULL,
		0x55378CCA8CA971E9ULL,
		0xA5E50F25A740836FULL,
		0x16EF4F48532199A7ULL,
		0x76C1A002490D30ECULL,
		0xCD0CD45DAA8A71E0ULL,
		0x836336ADC1C91894ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x654E354C10A35F5BULL,
		0x04A912F6124D7130ULL,
		0x335BAB26FF911A39ULL,
		0x868BC0F22683974BULL,
		0x1CD83EB53D706312ULL,
		0x7A783921EEE8C464ULL,
		0xD26F204B3E17BCFBULL,
		0x36459B6C6B197FCBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC47CFE4D55FC7697ULL,
		0xB00F454063E83D42ULL,
		0x55449C5FA61F31ADULL,
		0x11BE59E65ECD99F9ULL,
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
		0x910E56F1E27345F9ULL,
		0x5EB6F37E3F9BEB6DULL,
		0x60149FB05552BAB8ULL,
		0xE4463D516865F5C2ULL,
		0x5493D59FCB6701D3ULL,
		0x15FDD3EB61839659ULL,
		0x2B4FCE5A5749DEF1ULL,
		0xAF452298EA8D2B67ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC53BBED564CFA627ULL,
		0xD7BCAD633ADD6D24ULL,
		0xA628D05A67EC8D5DULL,
		0x856B1399FA9BE422ULL,
		0x368FB9AA068A8EE4ULL,
		0x822C1A30DEBFA9C6ULL,
		0xAABCB729DD4B7FADULL,
		0xE7DA90F0E0BE199CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x406EBE97B65CAE09ULL,
		0x781BD7CA6DD39C1FULL,
		0xCFC1408809285162ULL,
		0x78ACC8A8E286B5AEULL,
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
		0x9A29B211B343B797ULL,
		0x91C2AEDC8BD51E0DULL,
		0xB68F8052D417A0DCULL,
		0xC79BD550EACE6139ULL,
		0xB5810388B8994F9FULL,
		0x39B4CC4AC0E5BD67ULL,
		0x3BC480D36AEA9940ULL,
		0x2B804F3AAE3588B6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDE862A47345A172EULL,
		0xC255ED00D32BBAE5ULL,
		0x41E3B6C569B376A4ULL,
		0xF894E39E27B8642DULL,
		0x953261A6018B4C2DULL,
		0x2E9514A0633E811FULL,
		0x2EFCEF07B797220EULL,
		0x9EE617A9BE70CE2CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x874F8F71AAFE20BCULL,
		0x762205259F7C55DCULL,
		0x5A4B6DCA08C7DBA5ULL,
		0x2DEB31365A49AD8AULL,
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
		0x415B75A7FC1342D7ULL,
		0xA859BA4C75D95D35ULL,
		0x3B756F191A825238ULL,
		0xEC5D8891D1304A7DULL,
		0xBD5F12E3FDFD7710ULL,
		0x1ADD71AC8B398B80ULL,
		0x044B1C4054CCCBA1ULL,
		0xD9E511185220165DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9C2B36EBBE61266AULL,
		0x2ABA7E98D9C6A48AULL,
		0xAB279219B1B876E3ULL,
		0x81E2EB6144F49319ULL,
		0x58F77E17576D41B5ULL,
		0x50F80634DC7C62A1ULL,
		0xAF068F08563C865BULL,
		0x62970542CF6F3DE4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8C90551CF71A0A9BULL,
		0x75AD2F778C26C9D3ULL,
		0x387AD34F323423B1ULL,
		0x20105EE1F27BD940ULL,
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
		0x6E2F02627C7088D7ULL,
		0x249AF13CF05CD21AULL,
		0x15BB5DABE813F9CBULL,
		0x3040C4F117CB8E02ULL,
		0x3F3DAD09E6553552ULL,
		0xCDEE394277C87B42ULL,
		0x908952AD476E4C25ULL,
		0xE70CC4A341F874A4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9481A7C1DBD61AABULL,
		0x4A9A4069D5CFD59CULL,
		0x09DC98BCDF5F701CULL,
		0x56FB1DEA28A98387ULL,
		0x2856DDC7EE81D2EFULL,
		0x9A44D4007A091E05ULL,
		0xCA742F7CCE8137B7ULL,
		0xA5AC20AC84A885EAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3FF01E6B69FB0A47ULL,
		0x8525B89EC4F4D38FULL,
		0x7301FE20FBE5920AULL,
		0x0D9DFDA708FF7A0EULL,
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
		0x607AF2A365D1C2E5ULL,
		0x82E732A75D73C34BULL,
		0x952B35D4B61FE72AULL,
		0x1B59A3D25FF36013ULL,
		0x7A5C34F455D0F964ULL,
		0xF02F9B8BEA9773E7ULL,
		0x8E105510EF6D87C1ULL,
		0xBEB0CD29438B9220ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFE1DE048DE32C450ULL,
		0x7ACC5BE744945ABDULL,
		0x895262A32F48B5E2ULL,
		0xEAA45952125A38A5ULL,
		0x24B6A0447FB2953EULL,
		0x56FD9B92D69E0F1AULL,
		0x0D5AF2E90DA5319FULL,
		0x9672B51228D233CDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x18F124745021DCF7ULL,
		0xC586D5B90FE45F08ULL,
		0x26C5651D0A93FA6AULL,
		0x29ECDDEE451D27D3ULL,
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
		0x6A857BC53D8FCC56ULL,
		0xE631EAC99EBA891CULL,
		0xDECF33B7853ADB82ULL,
		0x38DBE3EC3D26474FULL,
		0x782414B3AFA12616ULL,
		0x55A62DE1F8669F4EULL,
		0xAFCC9D9388BCBD3BULL,
		0xA4E224172E910ECCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x035DFA117E544023ULL,
		0x2ECDEDF618C90304ULL,
		0x0B1620BF0AD5C129ULL,
		0x3A4B13784B974064ULL,
		0x4CC41108F7F9049EULL,
		0xE968ED81F48529A0ULL,
		0xCE72F1BB3B92E5E4ULL,
		0x1AA76C38A37A4F2DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD7680D0B0230870EULL,
		0xC87B8B141968FDF2ULL,
		0x47089513EE9B112DULL,
		0x03481B7C96EF7881ULL,
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
		0x7CD9DAAD5ACC40AAULL,
		0xFF8B9F7E667BA305ULL,
		0x72307D1CD04FA531ULL,
		0x5E8FF945C146A026ULL,
		0x8BBDC7BFDC4AF5DFULL,
		0x768DA7D7E7547A9AULL,
		0x41D0E4FA2289C6C6ULL,
		0x96785DE5D5882B53ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFD4111CDAD196EEAULL,
		0xA9CAC55DD05C53B3ULL,
		0x142AE2B0C5363D20ULL,
		0x3DB8B5C70162EFF3ULL,
		0x18D4BC1A0B1643AFULL,
		0x760ACDC4F88A4818ULL,
		0x1A2AF3AD72FB672BULL,
		0x13552974D1EC94EEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8E30837CBB8547C5ULL,
		0x692D38F00822CEAEULL,
		0x40A76BCE1A3B9913ULL,
		0x18110C4548FC0337ULL,
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
		0x042EF61E5583C3EEULL,
		0x92FFD2DD6E95FD92ULL,
		0x39F91CBB0A7E4211ULL,
		0x7F7854482BF7356FULL,
		0xA01CA759B4475723ULL,
		0x8FF8EE7198D5446AULL,
		0x345C4B9E036E478EULL,
		0xBF8F3C7294414224ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x308940CD51509D67ULL,
		0xA28C406B1C929ABEULL,
		0x7BEC407D34BA5ED5ULL,
		0x1B828D9F74F7199AULL,
		0x87A4A7B8EE2D9F78ULL,
		0x3FD527008CC47FB8ULL,
		0x9677CFB134864952ULL,
		0x94F3EB123FB0250CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7575A72E6C046AE0ULL,
		0xD5C32D3A1C809543ULL,
		0x2DF741648C33A02FULL,
		0x3703DAF5448A6D56ULL,
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
		0xB5B4C9799CBD11E3ULL,
		0x1FB9E223557087BEULL,
		0xE95A1958ECAE9CAAULL,
		0xF9A84D594F9F367AULL,
		0xDA72493FDCCCEC94ULL,
		0xD56C781697B6E032ULL,
		0x47C673FFAF430C7FULL,
		0xDF82D887CF76DC83ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF15527D2C327F5B5ULL,
		0x7727A3EB62B9A1F8ULL,
		0x013B434F584B59F4ULL,
		0xAB3A0684A9881364ULL,
		0x92C0F090B5BD72CCULL,
		0x08D4B6A7B71A07C0ULL,
		0xAA9448EAFA1787BAULL,
		0x5BF3CABD91B4279BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x68B2CBA6A5E132C3ULL,
		0x0718F4AD49FF06BCULL,
		0x3D913B1C78D8F812ULL,
		0x55AA52D9D0FDFD78ULL,
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
		0x08B807F65E0D56ADULL,
		0x134BD305F83B7932ULL,
		0x17EA401A78A8E852ULL,
		0x0B0A0EA30BDFFC07ULL,
		0xFA2C1BD9627BE5B7ULL,
		0x69F17D589C4E51FBULL,
		0xCE40A95B773109A6ULL,
		0xAD4BE557E9743D20ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4C60526000233434ULL,
		0x641201C8DF00E75DULL,
		0x35A5129710C5EF0DULL,
		0x188AD17BBD5F6F72ULL,
		0x9FF1EB29F9ADE92BULL,
		0xDB536CD5C4C80F37ULL,
		0x1C29B3F4742555CCULL,
		0x8F22C0EEEB4586D2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x20FAEF9FEC7D9FD9ULL,
		0xDAB044A917287AFAULL,
		0x51AD9ACDDB9FAB8FULL,
		0x6C9AA4BD096F9C43ULL,
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
		0xA8D1324795D6E137ULL,
		0xB5B16069A6B01EB6ULL,
		0xCC573B1E28AC18FEULL,
		0x376AF8479254BD1DULL,
		0xB361CFC7F9FC0762ULL,
		0x5C4DA9847F2B0A7FULL,
		0x9406F4D940562A74ULL,
		0x49ACB18D79F46D46ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9196E2E4CA8D708FULL,
		0x6E2B8784E250C07CULL,
		0x211DB7C4A5DE2AE7ULL,
		0x4B2F23E5D0169F44ULL,
		0xA7061636DDD26ECAULL,
		0x65E81E84801F6CD5ULL,
		0xA405482B4114793AULL,
		0x65E6871AB421C3EAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xECD7DAECF976168DULL,
		0xDA987AE4A018C577ULL,
		0x4B79252D668E3CB1ULL,
		0x3BA6216B1F83417FULL,
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
		0x53058B69F16F286CULL,
		0x93BE03631335B406ULL,
		0x018E6993A70B611CULL,
		0x6FC2F2383954E738ULL,
		0xE5ED5DFA7CE07163ULL,
		0x85841774EAF3B51AULL,
		0xF284BE7EC4E77B86ULL,
		0x3067C9DE0F16D952ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7271E76A81C9D290ULL,
		0x506D5DEB9536C138ULL,
		0x9898957C7424E265ULL,
		0x745A7E4049C9B998ULL,
		0xEB7523C024493714ULL,
		0x9C335BA1AEFF64FFULL,
		0xB6257EDB66B5EBCAULL,
		0xE8F523F7910F9BC5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0E6C48A89617F981ULL,
		0xE54C86D26442D6CFULL,
		0x5F1946572E41D49BULL,
		0x166D142EA49E5096ULL,
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
		0x84ABF8CA0FC4B08DULL,
		0x9534424504AC03A4ULL,
		0xDD0646BB300E2382ULL,
		0x09A19909B7C1C906ULL,
		0xE91ED9F8AA4D4B1FULL,
		0xFCAF00372E0C2404ULL,
		0x2030A9921F78694BULL,
		0xF7096C70A42A2CFCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1D492342DD51E81AULL,
		0x4574099313610066ULL,
		0xC629CAE37E8A5337ULL,
		0xBDC6446C2ADD6B9BULL,
		0xD2897DB8CBA20802ULL,
		0x557387B1C9D415B8ULL,
		0xF713DFC21C341B8AULL,
		0x3A5ED5547BD81C92ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC18E87023FDEC2C3ULL,
		0x22941C7ED19D2289ULL,
		0x312270B82DA75B0AULL,
		0x4D2DC2CB8912CD07ULL,
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
		0x46A1A4A9F53C053AULL,
		0x25FB210EB1A8F746ULL,
		0xCAFB6B5CB276D34FULL,
		0x31ED29F3363D1C98ULL,
		0x861FFB258AC690F3ULL,
		0x100C0BBF350A5179ULL,
		0x9816E56EB07F5E29ULL,
		0x9C486AB6F059CA52ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA33028BE1D612361ULL,
		0xBA79992BF0A116B6ULL,
		0xD5C84E453B1B2053ULL,
		0x814F53EE8A7FD0F1ULL,
		0x762830CEDE45E4ADULL,
		0x42E9ADEEC3491DE7ULL,
		0xCC8FBE093F66E363ULL,
		0x399BC76703CE22CDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x023984C972F47651ULL,
		0xDE9B74D3A3B5883EULL,
		0x2B42F62640FDEC57ULL,
		0x563E13E1C878295DULL,
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
		0x694D30D3CE526735ULL,
		0xDD0C3F16133A9DA6ULL,
		0x38BF9109FDE0FFA3ULL,
		0x25759D8798C1DB38ULL,
		0x5251C557E9E5DDC0ULL,
		0x4B3F8AC3F2047932ULL,
		0x90787FAF9B946509ULL,
		0x96D5A2067F390679ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x483ABF1956A95759ULL,
		0x9B4374D631C8446CULL,
		0x024BDDDD9070DF86ULL,
		0x771EDFB762B4AAFBULL,
		0xEC3F604C24841D77ULL,
		0x2E00CBB21A7E123DULL,
		0x361D816FC016E98BULL,
		0xE27110E904229A88ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x47CD7179C42B98EAULL,
		0x991926E5DF65A181ULL,
		0x9FF570A7021074D5ULL,
		0x754448307B613610ULL,
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
		0x1069C83C2B6A24D1ULL,
		0xA19475A50FE1599CULL,
		0x66229228BC7D114BULL,
		0x2CC57D7E994C7713ULL,
		0xEABD19C8431A19A1ULL,
		0xCD110CDCEA271804ULL,
		0x092AFF278503A4B1ULL,
		0x8663FF362CD73EAFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3A795D04CEB4717CULL,
		0xF474D769ED08BD28ULL,
		0x814D5E5CDDC3B4C4ULL,
		0xD0F6249EAA6136C1ULL,
		0xBE6D08E7F45CE539ULL,
		0xA4593734000B4B28ULL,
		0x96AC7CE9687B745AULL,
		0x73889CA2A2B515F7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x69D2EC830CCB7B11ULL,
		0xB869554DE2F90522ULL,
		0xE39C89041AF08976ULL,
		0x285FFAC66FFD4B8CULL,
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
		0x1633616EFB2AC4E8ULL,
		0x146FC98AD01F5BD1ULL,
		0x61C3CA5B3DCCC600ULL,
		0x5E83F7465AB22D60ULL,
		0xD5EF5CF4EF39BC4EULL,
		0xA061B8D0E8495782ULL,
		0xE5F13D0301477988ULL,
		0x79191624F0DF57B1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x599745099DEAB9CAULL,
		0xA4E2C414F173F7AEULL,
		0xF7C14E94C328A459ULL,
		0x35346FEFCA354E95ULL,
		0x7AE07CB52C3B5074ULL,
		0x4803BD48C2BD042BULL,
		0x429FF443B34CA5A3ULL,
		0x0154BF9A5292215CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x40D165DC4F041013ULL,
		0x8D805BAB717FC31AULL,
		0xA813482C0DDF95B1ULL,
		0x70745FEA0FF2EF80ULL,
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
		0x09D7622692451C80ULL,
		0xFAA2AE6AB3389B28ULL,
		0x3CE98EBD421F8901ULL,
		0x812AF2BDC3A98686ULL,
		0xDF2657E1E0EBC584ULL,
		0xEBC6ADE603C5567DULL,
		0x847CA537A3CBBD6AULL,
		0x058B196C136204CAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9716ADCB6F98894FULL,
		0x000E85FD920A97ECULL,
		0xDA39FCB4B10CEF05ULL,
		0x2BA569D5A70C7C62ULL,
		0xE5617BB0A82851FAULL,
		0xDFCD58A0849CB101ULL,
		0xEB9E671F00050F68ULL,
		0x2012E9B978601C5AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x85F963A98FAFB915ULL,
		0xC196D0BE013693A2ULL,
		0x13ACC9B0E0906E4AULL,
		0x655C9D6B1EE58AB4ULL,
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
		0x042A31E5CC570F3BULL,
		0x6BEB5C0559D19F04ULL,
		0xC0E7F441E9644522ULL,
		0xA32D711A291E91A9ULL,
		0x7852279C7C9354CDULL,
		0xF5706DA09E213B11ULL,
		0x1142C5F3C8F51F34ULL,
		0x86102677193AD4F1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7C0D73EFFFCA430DULL,
		0x8FED68B8EDBCAFEFULL,
		0x8AD99E5C90B68791ULL,
		0xF3C77CEAEA0D2014ULL,
		0xF52E0E368D1929A5ULL,
		0xB649BBFCDAFB32F8ULL,
		0xB5F71A87B1860373ULL,
		0x952A0654C317FA12ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFF78831758AF33ACULL,
		0x3BBC519B63BA22B7ULL,
		0xC349C7F0D32BDC40ULL,
		0x718EB948083DEE96ULL,
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
		0x59C68EAFA3CA9D26ULL,
		0x87295518AF031BADULL,
		0x31B00C1F7B9A68FEULL,
		0x6AE5129FA6CDEA13ULL,
		0xC86509C9FA00137BULL,
		0x53ABF159216F186CULL,
		0x5E1E3E8F0F955E32ULL,
		0xF155407B971F19ACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7437EA7E5BCC77FDULL,
		0xEBFC1E0E1B8E31F8ULL,
		0xD40D929018462C9BULL,
		0xDB6E76029040FBB7ULL,
		0x5EAA9DDA6DBC0C9BULL,
		0xFFFB5D0CE43D9C58ULL,
		0x3B3405ABAB29549DULL,
		0x90F4A2300554B215ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x973AA9C01A172C6AULL,
		0x07633A5BA8CD54BCULL,
		0x8C66EB504B5DA867ULL,
		0x5DCE1BD4BA984ECAULL,
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
		0x25552B715FD7A3B7ULL,
		0x05935AC2049BB7A3ULL,
		0x0D661437F2B38145ULL,
		0x244735A9593162D4ULL,
		0xD6D0D3D7A39B5E09ULL,
		0xFE9C345A5302F59CULL,
		0xBAB92E8C671AEC27ULL,
		0xACBA3032980A3CBDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x48129375C6463C77ULL,
		0x0FEEB96E2CADFF90ULL,
		0x4AB3A03EF06E6398ULL,
		0x0C63D11169EEA75CULL,
		0xD56254191932D20FULL,
		0x80ECCE7AB463C33FULL,
		0xC2B0758D7DA87DBFULL,
		0xF5C5D0D7C2DA0EC6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x13A98E4425162CBAULL,
		0x9DADC085638F31E1ULL,
		0x93FDE9CFA941812FULL,
		0x40298C1394698E20ULL,
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
		0x2AA0C641DB37CC94ULL,
		0xFA21EC4DECAE59A0ULL,
		0x9D0B0D423AA62F7EULL,
		0x63EE4FC7F887C120ULL,
		0xD7C0F010C759614CULL,
		0xB35BC113D4244F11ULL,
		0x55384C251F2B8855ULL,
		0x3EFC7333E75F689AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4B9D9BB178FE7E7FULL,
		0x20D391C2270A8795ULL,
		0xC65E6AD164A975DFULL,
		0x9D5A9472003CEA4AULL,
		0xBFDCCDCF0AC4F96DULL,
		0x663B9358103C1932ULL,
		0x294B0ADAD1D4B51FULL,
		0xCCC7C78FF5EA16B8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6AE040526040B5FEULL,
		0x4C15246ADA1BD128ULL,
		0x5BE4537850E013AFULL,
		0x3A6535ABCFB4FE68ULL,
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
		0x1C9A1C52C2A06CF0ULL,
		0x4D12C400EBF12512ULL,
		0x442DD63455643117ULL,
		0xA305706BFD54B610ULL,
		0x831736DAC18B0757ULL,
		0xE98EDAA7EF66915AULL,
		0x20D8552D69BE7B2CULL,
		0xAEEC60267A26236BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE54D8FC6FB00C250ULL,
		0xD36CC62DB0475F7BULL,
		0x77ECF720C3880B13ULL,
		0x22821CB7F346AA95ULL,
		0x8FA920EB77155660ULL,
		0x10935A3C9F00CB76ULL,
		0xB59360A3BB58B32DULL,
		0x565F787C1B7AEB05ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x59A3CE10D517F14BULL,
		0xAEFB0DC12AC5256CULL,
		0xB87D2B8374F7D5FDULL,
		0x256DB6FE17786A88ULL,
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
		0x621C1923C6E4B1CBULL,
		0x90E2F8769F349F2AULL,
		0xCEDF04BE5F972EA2ULL,
		0x3AE742ADE29D651CULL,
		0x35D7B73A0824CF4BULL,
		0xF0B3C92E342A45ADULL,
		0xC692EB1D9CF71802ULL,
		0x02B9D0FFB6433D32ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5A8BB2EF8B535EB5ULL,
		0xFDE1989752304528ULL,
		0x15E4F9F5BE600472ULL,
		0x22FEEE24EDF0909BULL,
		0x393B533EE022B3D4ULL,
		0x44EB90CDCC243722ULL,
		0x033710E14B52BBDAULL,
		0x874771065B4AC998ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x86C73D7C2BE163C8ULL,
		0x12B9BE2EBDEA82A3ULL,
		0xB89C6FBCBF9CD839ULL,
		0x6AE2938C758DFD7AULL,
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
		0x57F661C96A55951FULL,
		0xDCC75C382BB017C0ULL,
		0xDD546723EF1CB366ULL,
		0x6218F0E92F84F61EULL,
		0xCFD640CEC9089F31ULL,
		0x8BDBAEFA85F8C896ULL,
		0xF1022A701EC987CCULL,
		0x743ED104232EF61BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x87E95A31822F4D11ULL,
		0x6986C4AEF62D682EULL,
		0x66D55A11516FCA1EULL,
		0x5AAB2E93D632E756ULL,
		0xE8C24AFAF755DE32ULL,
		0x74CEB900DEC468C9ULL,
		0xBCD465A75B38C25FULL,
		0x33D7948EC5F8E433ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1D03850908AEEF51ULL,
		0xDF2D1A980748E7FCULL,
		0x354A42DFA52A3779ULL,
		0x16C0BBC12F58B740ULL,
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
		0xFCD6272544EC5569ULL,
		0xFB38862EF0551FCAULL,
		0x7BA23E98456D2C09ULL,
		0x219AB3AD66AB7C69ULL,
		0x847430F3B291C580ULL,
		0xE67792BDD6528621ULL,
		0xC7F797149D82563BULL,
		0xA7970BA0480226BDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x20C9030060EDAADCULL,
		0x9E9A0E01DEDF1043ULL,
		0xD2EAD5C155A6F804ULL,
		0x5B951036E461BCA8ULL,
		0xB5EE678BFA3324CEULL,
		0xFFF91E66763148E4ULL,
		0x71213B568A874A1BULL,
		0x78B42FA087AC6231ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x83E9098A420A85F0ULL,
		0x9363BD255665268EULL,
		0x8C89070DC10A00C1ULL,
		0x3BB24B6D0F04EC95ULL,
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
		0x9610B581C57094A8ULL,
		0x4ACA981093B3CCECULL,
		0x95602A2082887268ULL,
		0x40C11E1D3D60FBD7ULL,
		0x835CD4EA5E36B660ULL,
		0x38C2DB418D1952C3ULL,
		0x7A0B8EF6050EFC89ULL,
		0x1C0A455B7023272BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC3AF07125933F4C7ULL,
		0xCC1253CD854D6B85ULL,
		0x181C1F1C5E7DAD87ULL,
		0x88B3B93F1FB8B61DULL,
		0x1A6F5DD317FB650BULL,
		0x0186417F6AC97D6CULL,
		0x389F80A32C2B7737ULL,
		0x0860815F97908A9EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x65A15BE3D90AB2DEULL,
		0xB1B7171426400C60ULL,
		0x334E2B5055D08F14ULL,
		0x23407C40436B82B2ULL,
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
		0x3FC396FDD59C54FFULL,
		0xAC76EA62429892CFULL,
		0x4796F9BA725FE539ULL,
		0x92E957EAE0AD5BF2ULL,
		0x8C617984FF1F8A88ULL,
		0x1A8BBBFD3F82BA62ULL,
		0x9FE8EBD652500EE1ULL,
		0x83E2AA36361EE8EDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFAEA55F4BF5658FDULL,
		0x8B993C804477A9A7ULL,
		0x37C72EC4F9E13A47ULL,
		0x285B7186F5E907FFULL,
		0x0CE889329A70E31FULL,
		0xDBE5EDE4F7496D74ULL,
		0xB42FE10380CFA4BCULL,
		0x608EC548D8C6D603ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x30CCED440832D669ULL,
		0x6D7A457CB6A2548EULL,
		0x0D476640918E6C53ULL,
		0x2901E19FC5D722ACULL,
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
		0x2A76688F58799F3CULL,
		0xF466CC7AFC2BD074ULL,
		0xABBEC02E262AD1EAULL,
		0x7C950CAAD3E135D1ULL,
		0xD6560B5E6AC487E8ULL,
		0x15ADE4AEAAD00341ULL,
		0xDB14E5EF285C1A59ULL,
		0x00746695AF9FCD0BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x28DFB5E416C7FF7FULL,
		0x91962319F31B2B28ULL,
		0x08FC9A59B8C0FD96ULL,
		0x45A93E02A8C48DB7ULL,
		0x58B3FF1DDE0C2AECULL,
		0x7C1C766E7D2483B6ULL,
		0x189365E712BEBB32ULL,
		0x1A4010E44DAA8AB7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA7A48440250F6C8DULL,
		0x2E6706E7D0859400ULL,
		0x81FB2707A2C5F40FULL,
		0x62B086FCB58480AFULL,
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
		0xDF77711198F08F41ULL,
		0x23F5EC3BA075E1C5ULL,
		0xB4D7BB893D37E646ULL,
		0x9082BBCEC06C2DFAULL,
		0x3CB46D6390C21025ULL,
		0x8935751373B91C4DULL,
		0x7A219F8326C92D1BULL,
		0xD432F3A710E6DCEEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x403272E3D1790CF5ULL,
		0x7473FDA6C537BD12ULL,
		0xA4E8A3DDE82BFD13ULL,
		0xFAFEA9C94DD30B45ULL,
		0xFC7E6EC145316FD8ULL,
		0x793BA5D242E3DE24ULL,
		0x8DB69A86D3B9FE4AULL,
		0x8E07166C7B83BDC2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2748CA44FEEF4F36ULL,
		0x0E96B2421AE55EADULL,
		0x27D1D51FA94CDC3BULL,
		0x0006E8B79F4FC33AULL,
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
		0x44C76DD7BCC801F5ULL,
		0x31B7E9D79F3E50EAULL,
		0x578588E6704757FDULL,
		0xB90E83121FB40AB4ULL,
		0xEA74F5CF112CA430ULL,
		0xD9E9B24767662BB2ULL,
		0xED78BC08598D5439ULL,
		0x3195948160254FB3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2999D261DA024BEDULL,
		0x1031E982CB40450EULL,
		0x17268CD2B8EAC28FULL,
		0xF8C1C37E041D7745ULL,
		0x01CDD08E42BD8B6AULL,
		0x93AE07A893BE2977ULL,
		0xF1E785905A3C1F50ULL,
		0x59F67E825F96F078ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA3FD231487436275ULL,
		0x8E6153E83EEE60C0ULL,
		0x97ED11E39D6A700EULL,
		0x41EA036E30B8B630ULL,
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
		0x7EE35AC1B7DF68E9ULL,
		0xDFE34B8D2BC85794ULL,
		0x9191417478D6672CULL,
		0xE4732F3E78A0C443ULL,
		0xD2693EC523666428ULL,
		0x55A4ADA05E2D9DBBULL,
		0x31AC5BC06D909576ULL,
		0xD59964EF2A44AFB1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF711C3935CD595F5ULL,
		0x1A1DE9D4C2B48F22ULL,
		0x7D88853CF519D7B9ULL,
		0x7E60101B046C6A24ULL,
		0xC1C061E03C87709AULL,
		0x21D6D99875EC2A85ULL,
		0xCCB3C666FD10AF88ULL,
		0x5FE37D4E15B9B04DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x00E26128A021FCA1ULL,
		0x7652DAE4E2CAE278ULL,
		0x10EEE77E36B8B0CFULL,
		0x5F13810C80D642E0ULL,
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
		0x0D3579DFD0E33DEBULL,
		0x84899333208178F5ULL,
		0x33BD03EF2DE0969CULL,
		0x304E14B434CB3055ULL,
		0x9CFFD5135C27023DULL,
		0x107F37F1BC3D91BBULL,
		0x0D207D86230CE9AEULL,
		0x270B59E38782B7E1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5C7AD27C3008C562ULL,
		0x778F712466ECB3C6ULL,
		0x1C0B18F4C4C13B3AULL,
		0xB9B25FE96C54C076ULL,
		0xEA22BDE5D32F1061ULL,
		0x554E6EC364A47524ULL,
		0xB4BB472DB992A8A8ULL,
		0x592BC0AC3A69B599ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3D8C1825F5A85E01ULL,
		0xD637FEEFBA4F038DULL,
		0x36B7FC1A1145023BULL,
		0x05CC73003A2CC676ULL,
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
		0x6583EA75ECFD0098ULL,
		0x7BCDFC4477126F9AULL,
		0xAAEAF744AB243FDEULL,
		0x35082E5F8C4F8866ULL,
		0x5944CC4DF7E0A06BULL,
		0x22DC26CE929AA121ULL,
		0xA8AC92783A66A1F8ULL,
		0x0C080991D3A56558ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xED83C1BEFE08CFFFULL,
		0xC60872EDBE935C97ULL,
		0x6317EC97C7845542ULL,
		0x6804CACC16FC9B9BULL,
		0x43CECF1931FB780DULL,
		0xCA87DFEBD610B6D8ULL,
		0xDAAD452727653309ULL,
		0x8D03E2C4D13F2F01ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA783BE8C4EF82BA8ULL,
		0xD2480EFEB4F7D9DBULL,
		0xDBB884B5B5D661FCULL,
		0x27A12601D07EFDADULL,
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
		0x0F238D3DB57D9090ULL,
		0x1B7DAB433987F0ECULL,
		0x36A7C36BAC9AF805ULL,
		0x2958EC538C459F56ULL,
		0x6E6A5A92CD43066EULL,
		0xF8DF863F55950AACULL,
		0xCA09AAC08A7D8677ULL,
		0x63A8E0138433E060ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7CFD4E6796A70616ULL,
		0xF367C1DB390ADA6CULL,
		0x9F563286FE697904ULL,
		0x35BF7423DBBAA26FULL,
		0x1C5BAD95DD5F2958ULL,
		0xE4756226B2E5ACE5ULL,
		0xCDD69D9EBADEA349ULL,
		0x68A9AB8D7688D521ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC053EC61BAA95B98ULL,
		0x2FD7451026850215ULL,
		0x06E583E97FC737D7ULL,
		0x357B4415B7EEA840ULL,
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
		0x672AA24D5A7717D8ULL,
		0x560530799E8B92F3ULL,
		0x0B9282BF99040FDDULL,
		0x9B779B2AA76A0D61ULL,
		0xDDA90E1FBC12DE32ULL,
		0xD96A0D21F9FBAA60ULL,
		0x605B2E879FCDB050ULL,
		0xB0AC9CBDA2419975ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x63773C5AE872B68EULL,
		0xDCD800C81EDD8337ULL,
		0x68F1613499D65873ULL,
		0x47D3B4DBC6892A64ULL,
		0xDF5197D35DF87A1FULL,
		0x2B19FF051E89D0AEULL,
		0xC53FACBA73164A0BULL,
		0xE74A305EB74D0D42ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC4AEF54869EF3AECULL,
		0x590F47FA12946027ULL,
		0xA8B665FFA266E5C1ULL,
		0x383FFC65C12DB27FULL,
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
		0x3642D87D4CC18045ULL,
		0xEF28DC3EE68A1040ULL,
		0x66EEBF267A116DB3ULL,
		0x2D63C627C8901A7AULL,
		0xC294434FC4A6B7D3ULL,
		0x734A307F6ABED7ACULL,
		0x53DBA7E0A2ED54CEULL,
		0x4D6A5AF2EAD463CCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x05BC2E82B90E2BA1ULL,
		0x04AD94C30D24684AULL,
		0x27C2479906983703ULL,
		0x9E0EA68C38339A0DULL,
		0xDA18A4F191EB9689ULL,
		0xF348EC8AFAE08785ULL,
		0xE309279E90FFEABCULL,
		0x7375976DC5AAD238ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB2E02BF61B7A44A9ULL,
		0xEAAB5DC474658DBCULL,
		0xFE6B815C1CB6F549ULL,
		0x69AA255F14881C4FULL,
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
		0xD56F964EF9491777ULL,
		0x1F3F192BCE42EC4BULL,
		0xEF802E554532517EULL,
		0x417D1A4B58780F3AULL,
		0x9A9B6A6C3A150AF6ULL,
		0xFE3C60000831B97DULL,
		0xFD81C9E37615802BULL,
		0xA26DFD56A07591BEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x31EBC378F884B8C0ULL,
		0xF769D683A10ADB50ULL,
		0xA4146AACFBC9CD80ULL,
		0xD686F1E9110EC42CULL,
		0xE1B4116A3F222F5EULL,
		0x2542B1185954FE65ULL,
		0x9AF64FBA412B3DEFULL,
		0x71263629ACC2574AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x15DB092140D0F83EULL,
		0x5CE5390C21FBD681ULL,
		0xEC1FE5C6242E5905ULL,
		0x3B9DB90E7403F854ULL,
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
		0x06CF59278ACA142DULL,
		0x7D8EB3EA4AD57A62ULL,
		0xB23E2C2BC3424615ULL,
		0xDDAF068AA4C4D189ULL,
		0xB583B1E17504C9E6ULL,
		0xEFFCD14EDEA12674ULL,
		0x0FEEAC29AA66C7BBULL,
		0x1AE0A74072F4F07BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x46CBC0ADEE07C08CULL,
		0xBA84936D2AF60094ULL,
		0x64D22F6B5D0A00A5ULL,
		0x06E874313D246D89ULL,
		0x0506CFA58713873BULL,
		0x6DAD4AB2BD619EC2ULL,
		0xFDB1AE677BD2CEA9ULL,
		0x0438358C54277373ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF28D2D5EEE92399BULL,
		0x1AD81BAA0F4D9E53ULL,
		0x0279A793502F3E2FULL,
		0x33C77315FA20F30DULL,
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
		0x0C351C2A7BDBB98CULL,
		0xABADC3B4D7AE842CULL,
		0x5DF241BADA77DB06ULL,
		0x989C18700F1D50B3ULL,
		0x9D376808A9D1A905ULL,
		0xDAFCA960195F9309ULL,
		0x37206F9511B17F3AULL,
		0x6198E6E30C3C52A7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5D465B527A1C2D12ULL,
		0x434C8A4E44298578ULL,
		0x7DCFFE0B5C975539ULL,
		0x92F58C00D4853EF3ULL,
		0xF260C255310B5845ULL,
		0x02320696074CFDA1ULL,
		0x82D1996F333E0333ULL,
		0x4EDD3F419F03C197ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0ACB597BEF2F8959ULL,
		0x9675636542472C17ULL,
		0xA3D60D4E8304EEF7ULL,
		0x4D816E6570FD9A14ULL,
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
		0xA06365868291A316ULL,
		0xE0306CAA905BAAFAULL,
		0x438980A6A691F231ULL,
		0x07C29B4FFE5C1464ULL,
		0xE702992F24DB9428ULL,
		0x4D01AAF90DCBB246ULL,
		0x66799F21F08B79A7ULL,
		0x425B769BDCEA5359ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6B027AF409711172ULL,
		0x50B6A17B3F01FD71ULL,
		0xBC72C3EFD2138E13ULL,
		0x3344E4BF2DFDFBC7ULL,
		0xDB6744B832FFE21DULL,
		0xF03E1F3A063A76E1ULL,
		0x4D3E49F517108E5BULL,
		0x2615C63CF2451BD4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEE6F743A5FBCFFDEULL,
		0x5480898A70E87E88ULL,
		0x45E5615F1CBD514EULL,
		0x06D5E4A7A4E4565EULL,
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
		0x8F454A7429933D8AULL,
		0x7A89DD1E0822A7BEULL,
		0xABB2900384DFD3E1ULL,
		0x2268061ED1E65C3EULL,
		0xE14CE7CA5DEA71EDULL,
		0x255EF115879A3708ULL,
		0x7605B260BD77CE11ULL,
		0x49A459E400716FCBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE32FDA9957540864ULL,
		0x52CBE1E3BB98ECBDULL,
		0x010434C4D2113ECAULL,
		0x88AE472667876036ULL,
		0xE4C3F830209F66F2ULL,
		0xA4DFA210FC66D27EULL,
		0x3F04E9EC50E621BEULL,
		0xCA58E52082341B38ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x286900BFEB62D370ULL,
		0x3AA3B5E6F62AA77CULL,
		0xD4CC1C86D06E2956ULL,
		0x7EED13FD277989E2ULL,
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
		0x30ECF0C44EE2B610ULL,
		0x340298B45452E048ULL,
		0x46162BBF898AF848ULL,
		0x3A2A1ECDFD0EE039ULL,
		0x21AD770B10C1B0E2ULL,
		0xC9F0D1777D3FDCFDULL,
		0x0090B617D40C2E1CULL,
		0xDB44288207BFD4A1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x070720DEDAF3BCB6ULL,
		0x616A79AB722ED3BAULL,
		0xB4729EC8BC80F063ULL,
		0x9F29BAA48734B539ULL,
		0x63F0FBE0DB7E7479ULL,
		0x12CB4EC5017A1F70ULL,
		0x0158778B44190554ULL,
		0x09AA079D4EF6EF5FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x53E018295BE9F577ULL,
		0x02298587417E2F72ULL,
		0x73FCD5D42B2215B0ULL,
		0x37E1461CE3AC32CBULL,
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
		0x04E3B532515CBF8DULL,
		0x4F14388C006456EBULL,
		0x7739381FD92C69A9ULL,
		0x70975FFC981C6337ULL,
		0xD645E253FD7ABE32ULL,
		0x19E49584DF44B2DCULL,
		0xEBE1C8DE4386E21DULL,
		0x4C0A1D7B178B41ADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE190F3C28D22720DULL,
		0xE415A5BE74145420ULL,
		0x07269CBC5EDCD8A8ULL,
		0xC16A2C8625C2D16FULL,
		0xF05271A82EE5108DULL,
		0x7B75A4D8CD48755BULL,
		0x6DF1E929E41DAC68ULL,
		0x380612CF9AB5B030ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x45757AF06E72145DULL,
		0xEF764C5837C123ECULL,
		0x21ADD029A3ED89CFULL,
		0x27C6C8EAFA0D2A69ULL,
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
		0x1D8507A1548FE75AULL,
		0xE3C21AFE76FA3DE0ULL,
		0x520843FDD1245F8EULL,
		0xF35E019F3AFCA007ULL,
		0x580C7C9B0C011E50ULL,
		0x559D7F1C60EE6CF6ULL,
		0x07E4A16E2C089348ULL,
		0x67A867A406B67B96ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x84A589EC536CEA50ULL,
		0x287C46D708EBB387ULL,
		0x70A70D1A08B6C117ULL,
		0x232D9362ADF11849ULL,
		0x6A3D1B334E57214BULL,
		0x7AB0A71E9B177F1DULL,
		0xA6F0D692BA5019EEULL,
		0x4C8B2B7D0987CF02ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE5A7F31B285E8C73ULL,
		0x3A6DE3D2CBF5D88BULL,
		0x45915376A9CFA1CEULL,
		0x56875C0621F9259EULL,
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
		0xE018AA86B9DC8E69ULL,
		0x57B22C857D17BD7FULL,
		0x9CF1E1334C5E47FEULL,
		0x0F063DEC0F2838EAULL,
		0xE6C433BDC8F8FEABULL,
		0x7DA953104B6FD7F6ULL,
		0x8F8CB21BA256621BULL,
		0xECC3F9E8298FB954ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDC00FA8FBC483CCBULL,
		0x98B4118CC4C02850ULL,
		0x95808187F475B7BEULL,
		0x80903E753668CB49ULL,
		0x9799BEA4ED595A57ULL,
		0xE056908F30256F7AULL,
		0x28AA4EE1F0AE27F5ULL,
		0x9E93067C40B381D0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC46511A79746B7B8ULL,
		0x1946FA22C56317A2ULL,
		0x4D0C1A3BB6E131D5ULL,
		0x29BA217B696FAB48ULL,
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
		0x30712FC42CC25D87ULL,
		0x8FCB5D84E7812D46ULL,
		0x6836AFF3236D7FB1ULL,
		0xF9A0AB800A0A4294ULL,
		0x8B14B7DE3D5FA435ULL,
		0x234B18FDEA8A61FAULL,
		0xCC66783317E3ACFFULL,
		0xEDC4C1A222B5A711ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5ADFEB2224E513EBULL,
		0x026F73101B46E52BULL,
		0x544364CEAD6226B4ULL,
		0xBD76136F16B3A7D0ULL,
		0x8F0BC7181147B82EULL,
		0xBDAB9E5EF9473D83ULL,
		0xE8BBEC697DAF8EB0ULL,
		0x3A92A7853587AAD5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3EE5020C936A5695ULL,
		0xA3081E0C9C31B1C4ULL,
		0xDF440B1159C7D8A0ULL,
		0x559A785C282A0BA7ULL,
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
		0x8C71E0DF1D7FDAA3ULL,
		0xAF3C07A27ECD70BFULL,
		0x23841A0F4215A1C1ULL,
		0x256E2586B124746EULL,
		0xD7919FC417DFD0B7ULL,
		0x5CE29CE8B188EB5AULL,
		0x16CB1D56543886ACULL,
		0xE9D5F3E146ACBE67ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEE9F20B2C20156FFULL,
		0xFF498D859988401EULL,
		0xE5E9231FC6D8E1EBULL,
		0x64D84C04DC9D4A76ULL,
		0x59B2AF6E10BBE778ULL,
		0x0007224DDE837E6CULL,
		0xEFE353A8029D53D3ULL,
		0x75278F786C242B78ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4CEA6CF16AD32584ULL,
		0x7886AD1838135C07ULL,
		0x0402E6CF98464C19ULL,
		0x1278C11244CCF951ULL,
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
		0x0EA603D23F97DE76ULL,
		0xC1B207D18653B093ULL,
		0x75198AB355582940ULL,
		0x4082958102C0D9F1ULL,
		0x0EA4ED187A453CA6ULL,
		0x95A58C39296C482BULL,
		0x255FD35E4DFD2DC7ULL,
		0xFBA723120CE43808ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x95DA0F04011F3DC0ULL,
		0xF025B5FD8D1FAB29ULL,
		0x758C89887FD11BF8ULL,
		0x46E524BDA251EBB2ULL,
		0x8A3BD3C8CB0F26E1ULL,
		0xC0441199F069A738ULL,
		0xA8CABEFE86349581ULL,
		0x7630BC9E8D1EC3F5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2065B6A2407FDED9ULL,
		0x7E0485766F97E969ULL,
		0x7DAE07627D4DA7A5ULL,
		0x4930A5E857BE28FDULL,
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
		0x2B58C28C58E4D8A3ULL,
		0xF5C4CA5C69A51102ULL,
		0x1BBA86A3ABD38AB8ULL,
		0xE23D78EF8E077547ULL,
		0x3467C56446C476E4ULL,
		0x3C1E77877820B681ULL,
		0x6A1E40242C2BA516ULL,
		0xCD0B2EFEBA5A0E2BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x893E709A488FF6AAULL,
		0x27EC8A4E11C45136ULL,
		0x16E2B865CABEBCF3ULL,
		0x0CFD65C81D53444DULL,
		0xA4579C14EF36BB30ULL,
		0xABE4DDF2A0E05A08ULL,
		0x299B075CD7B61593ULL,
		0x1D9354C0D21A8B83ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x048073B90F5EC2A0ULL,
		0x36650C264B6E79B1ULL,
		0x98523BD46A881B27ULL,
		0x610A7857EA2195F3ULL,
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
		0x9E33950184F79B23ULL,
		0xD6BEE56F69F988CEULL,
		0xD332C99F688E8E64ULL,
		0x3EE619B01507812FULL,
		0x60753FE1155D00F1ULL,
		0x139C01EDE007CFF0ULL,
		0xDA1285074F3440BBULL,
		0x862BE13024E8B378ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAD3C18337D1C339DULL,
		0xA650F554DEEB6FF0ULL,
		0x142619D9534429FFULL,
		0xDBD1D3D33873C47FULL,
		0x3265C8D788D2DAE7ULL,
		0x21D48581022D853AULL,
		0x19D58FA54EF43D14ULL,
		0xC76F55D434815FA1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC7432838E45D0B73ULL,
		0x140A684379752FE8ULL,
		0x48191C521ECAEF2DULL,
		0x3310F5828BEA2EB7ULL,
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
		0xBE33725F831E1879ULL,
		0x52C3DB3F016E9FFCULL,
		0x611CB50F17B188CAULL,
		0x1E0E4A10F9985B69ULL,
		0x207FC0D806C41A06ULL,
		0x170FB4BC61B3C1DBULL,
		0x3ED51C604DADD3D6ULL,
		0xAF9F63845D1C30AEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x92C3F3A109103B1AULL,
		0xD21028B4D54F631CULL,
		0x5BC2957705E6BB75ULL,
		0xC52835EA72B055F7ULL,
		0xABF8EB918EF617D1ULL,
		0x956FCB3A4DEB68A4ULL,
		0xA0F9CFEF6ACE15E8ULL,
		0x25F9D7FDC52ADDE1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7773273442A23422ULL,
		0xBE705BD91BDC7AF5ULL,
		0x73E77859BF00FE95ULL,
		0x4778CA2114BA4FD1ULL,
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
		0x975155805EA207FEULL,
		0xCFF61666CB20787DULL,
		0x9DC0457257E27503ULL,
		0x47A62A9C25DA499DULL,
		0x2079247878C63781ULL,
		0xF33757772198BACAULL,
		0x51B6B948635B871BULL,
		0x3E4B910F65625298ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC7D3AE6C3F7FD7A4ULL,
		0xF210955F70EFF731ULL,
		0x0ACF66604B251970ULL,
		0xAACBAA1895BAB348ULL,
		0x4DE4D6A93C1DC3EEULL,
		0xFC4FA4AB3877EE79ULL,
		0xBEC3A85B85B9D2C5ULL,
		0x601893EF49A36E32ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x118133D72023575BULL,
		0x844A0B4BF50ED54BULL,
		0x6305623AF2BE2055ULL,
		0x186C1347AE757D69ULL,
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
		0xDFA1A6045EA49B8DULL,
		0x44707D3A7A49B274ULL,
		0x3ED45D01D40EF872ULL,
		0x3F5CFE4435D00A24ULL,
		0x4A274631488465E3ULL,
		0x5044C352938EC267ULL,
		0x5541476674F485A9ULL,
		0x281E2C27BFD46B51ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4B7A962D6CEF5F62ULL,
		0x3ADFC07DB7F2B1A8ULL,
		0xF188E532C94E1827ULL,
		0xCA993D1C5CEA36F3ULL,
		0x79CCB6E2FE71FB8FULL,
		0x1469531118B3E61AULL,
		0x84EF9B5F9DFACA4CULL,
		0xCA117F40F2FE38FEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x81985575F07100EDULL,
		0xEC236674FED3B433ULL,
		0x396B00D2F3D2B021ULL,
		0x6AA56B6A40B14B7BULL,
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
		0xFEF3FB9F0246FF33ULL,
		0xF32E67F8ADD33C54ULL,
		0x839005E83E06B22BULL,
		0x43FEDA357EE70B3BULL,
		0x4CE44B79E26BFFF5ULL,
		0x9BF01D8ACE850B68ULL,
		0xF7094B32B2B8C93BULL,
		0x849A436696FF3F7CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x51CAC01F260AD82CULL,
		0x35BC1ADE087CF03EULL,
		0xFF4E927B5A3DAC3EULL,
		0xA62CCCCDD43D0463ULL,
		0xC91A55D16A2AE115ULL,
		0x868A94AC462CF08DULL,
		0x153D1878D9ACC528ULL,
		0xCBE5D60D399384AAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3D23B281B5E6BAA5ULL,
		0xEA849E22E26A4886ULL,
		0x0890FB031B91A0C2ULL,
		0x089A48AB88A7C225ULL,
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
		0x2452DB25692634D3ULL,
		0xF9A7D1793E36FBC3ULL,
		0xDC645A7D14CCF8CCULL,
		0x2431AEA39DA2AB82ULL,
		0xF8BD4DE846C07786ULL,
		0xB7B8C077715E33D7ULL,
		0x4571126D2A23A2CAULL,
		0x91A0AE2ABE2C3654ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0A5B55D6B97012AAULL,
		0xB8C512A494A9E362ULL,
		0x918778E910B7AD18ULL,
		0xBBC9804AF4E4FAFBULL,
		0x21E4CD1E4A31125BULL,
		0xA0E16A2933EB26E8ULL,
		0xD4922BB3E7AC81EFULL,
		0x5DDC0C43E8CC8226ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFE1AA34A2CFF2795ULL,
		0xA4D98E71C8A103FAULL,
		0x0BF32113E1C42C39ULL,
		0x1798369C54F26F46ULL,
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
		0xF7CE880021A80759ULL,
		0x8189FCEA70E9DA95ULL,
		0x8D9317064CA4114EULL,
		0xD97D86E3A2AD2B88ULL,
		0x37D7BFA4845400EAULL,
		0x1C6987CEAE3AC28BULL,
		0xAE01A620157BC2C4ULL,
		0x570B93451B2D02DAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x21A513F93914E02CULL,
		0xBACAE6A2DC279CC7ULL,
		0xCAFB226B0CD3167BULL,
		0x607FFDF3935D2768ULL,
		0x3A7DEC7E914D0F6BULL,
		0x65673EF3680FC7BAULL,
		0xDC90D10550CF5AB3ULL,
		0x30FC7771B85CB7F3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x717ECBA8FB9B00EBULL,
		0xF115E6D3FF2378D4ULL,
		0xD957969471686D4DULL,
		0x1F3BAA50BA3B2262ULL,
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
		0x78639C14529CBE9CULL,
		0xA3F8E290389E0926ULL,
		0x87003FCEAA09F19BULL,
		0x177D711A2145AAB5ULL,
		0x7593E1120BB38AFCULL,
		0x36F402C0FAE56494ULL,
		0xB4B0F8603F5AA820ULL,
		0xFB23A678571AC8B5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x17F51E14F14DD3D3ULL,
		0xB49BFE975DF1548BULL,
		0x6D10C61B9F05E8A6ULL,
		0x6C9745983B2712B9ULL,
		0x9489C7E6A3F22F65ULL,
		0x7713DB06323190B3ULL,
		0x158B12796FD3299AULL,
		0x865493FACDB09264ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC7EE3A70C80285B9ULL,
		0x6AA2C9B2A55E27FCULL,
		0xB98F99F5D920D0CFULL,
		0x01A2EA244BE2A819ULL,
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
		0x8CF789A1995522CAULL,
		0x137A6E53693651A4ULL,
		0xA44B629C198F755FULL,
		0x41F553E496584555ULL,
		0x8A7CFBDDED1CC87DULL,
		0xB6806B7906E4B086ULL,
		0x5F7C61D5C340851BULL,
		0x793B848737F4530AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x830A0E085894E3A3ULL,
		0xDBFDBDACCB26FBC5ULL,
		0xAFD4890062D3D546ULL,
		0x29320DB8D80900D9ULL,
		0x7A6D1DA6ADDA7E13ULL,
		0xCDEE3A7547190F49ULL,
		0xD74ADB9159FA0636ULL,
		0x28E559E8562750A3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6C4877CCA4974CABULL,
		0xBD2FF735164944EFULL,
		0x2BD0C7C357327612ULL,
		0x058D99C142BD9FB4ULL,
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
		0x2F5231C6700F285AULL,
		0x6674ADC54758875BULL,
		0xDB148D19B59524C4ULL,
		0x2539373FCB83CE65ULL,
		0x62023AD232E3009CULL,
		0x5EEE44F581731CA4ULL,
		0x82638196C15F941CULL,
		0x6CD8FCEBECB12E24ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5B43762F09FFB95CULL,
		0xB3B78955B0AD642CULL,
		0xADA7895AAA3E6C35ULL,
		0xAFA7AB5F7736F489ULL,
		0x1165D2ACEA8F17C7ULL,
		0xE6E916D10CD2C64BULL,
		0x56C2FF254302CEC6ULL,
		0x8AD7C44096EB2C44ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCB4631202283FDDEULL,
		0x8381FDD8E677F470ULL,
		0xA7406097CD1C033EULL,
		0x01BFF54F0FB12122ULL,
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
		0xD83FBF4D13D7BE04ULL,
		0x54FD94D9ADA6AFABULL,
		0x30BB7494904EDF46ULL,
		0xEB24FD205AA9173BULL,
		0xBF93BF8A16EFD67FULL,
		0x8BD4807192417C90ULL,
		0x1FBD0389A95E7F32ULL,
		0x6F5BB47CD8CF9FA5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF98F90D568D0B590ULL,
		0x7D4D97E188C05D87ULL,
		0x255545AB74FF0832ULL,
		0x81D1E9C2564F2852ULL,
		0xFE41F9E77630EF50ULL,
		0x7AECAE471CC4642AULL,
		0x6FFC19E28E5BD1FEULL,
		0xD0769BB72F1FEC03ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x90D3849B875D5747ULL,
		0x5A192F459577F13EULL,
		0x2208DDB71DB58CCEULL,
		0x7F54C0B5346E98E9ULL,
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
		0xC8C1B6D5A48476ECULL,
		0x9D9A992A45D0D258ULL,
		0x80780B5CE558E677ULL,
		0x5469DFD3B76FF067ULL,
		0x58A8D892ABDE7A32ULL,
		0xDB6E7FFE9BF5952DULL,
		0x4F27AED337D0DAABULL,
		0x7A51C1D54A992F8BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA7F4C9D9BA203BC7ULL,
		0x4AAA73D8D699A575ULL,
		0xF59A29338398305FULL,
		0x960971DA5EEFECA0ULL,
		0xB7F94482A715B694ULL,
		0xA37BBB0EAFB4DFEEULL,
		0x790A4463F9B9FB69ULL,
		0xE03F0EC949E149D6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFADCE75CA031424CULL,
		0xA0F960EE80D2142EULL,
		0x533BAEAC9925D9ECULL,
		0x1D2701C173CC1C9EULL,
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
		0xB622AC9E02F43D8CULL,
		0xCC0402FAB37B71DBULL,
		0x582640741EF6F966ULL,
		0xA89ADF0AA2CF85DDULL,
		0x6FD4D108783692AEULL,
		0xAA80D23F1C04ED1CULL,
		0x7C78A32675BBD54EULL,
		0x994C7A354D88A1C0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2572077AE27F3462ULL,
		0x3F8C64645338FB68ULL,
		0x2BBBA23E05E39090ULL,
		0xA9344F872A3AC3B7ULL,
		0x2B77EED9C5EDF692ULL,
		0x57E08418A7A946A5ULL,
		0xD9705AE0A2F2C801ULL,
		0x252B3DE588725B71ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB67A3811973C37D8ULL,
		0xD043384BA5DD2C27ULL,
		0x5FA5589362EB6250ULL,
		0x3C55835AB9E331D2ULL,
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
		0x60CDEDF443190202ULL,
		0x5136CC78020F0C63ULL,
		0xDC786D37DEE2B1B1ULL,
		0x29D9C88B911416EAULL,
		0x470911A5BF8A8517ULL,
		0x22B44F6C046398AFULL,
		0x73653BD2850A5F79ULL,
		0x110FD3EC9B9999D5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4F0AC735436CF852ULL,
		0x0B625DDB05BC4226ULL,
		0x34D808ED4B738A7AULL,
		0x5D420DFE72EF9A0FULL,
		0x890CDF93AFD32A6DULL,
		0x35B4AFB919F76A6CULL,
		0x749AD142CC555136ULL,
		0x242B380F3C77D359ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4532956D54E37E67ULL,
		0x73C6232BC861A825ULL,
		0x79AC359FFE4F4526ULL,
		0x7686DD693D27F343ULL,
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
		0x6F33C2FFF456CB5FULL,
		0xE233BFAA057FB93CULL,
		0xD473C6C75973A540ULL,
		0x09D77583FBFBA44DULL,
		0x45686B523ABC2836ULL,
		0xDF402DB4957B61C2ULL,
		0xC0C4F46DCE98F9C7ULL,
		0x054E2663126EA209ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA57D29B12E3362C9ULL,
		0x334D042EF460C15CULL,
		0x0BF8C1D01CE4DE17ULL,
		0xAA6E86F6BE83CA47ULL,
		0x3E3998284B79CB87ULL,
		0xDDADE17C72822DE9ULL,
		0xB194D148D1CC3702ULL,
		0xA444939ADEFE2411ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDAA9F18849FD26EDULL,
		0xEA9E0BD0421CAA16ULL,
		0x09A03C74C2F3B067ULL,
		0x46D4B844E02A8CD9ULL,
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
		0xD6DAC00EE54FDC06ULL,
		0xE125F147732EFD34ULL,
		0xD4C1DC39D07ED530ULL,
		0x4123B3B4DE2C666EULL,
		0x05917997FC7A3CF8ULL,
		0xEEBCB0FA0497E738ULL,
		0xE7BFE86791D1CF93ULL,
		0xFD43794974E26A44ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2ED223D960708BFAULL,
		0xD5E5F6833B0136B2ULL,
		0x5EF6FB3ABB53F228ULL,
		0x889662E6A4AA45C4ULL,
		0x2D45916F74BD44DEULL,
		0xA1471D3EAB4E8CF0ULL,
		0xEB5C9E86FF8451C9ULL,
		0xB96152B0AB524A73ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC34D1239AAEC2551ULL,
		0x8AB3E89379112D2CULL,
		0xEC87D854CCAB8F0FULL,
		0x4C1F0B7C24E6D9AFULL,
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
		0x2F48438584B274E5ULL,
		0x72928242EFBD4472ULL,
		0xCDA469DA7096EB58ULL,
		0xD0560B026209BE43ULL,
		0x18DC0FDBE3CA908AULL,
		0xB6F0BDB51741AE3BULL,
		0xD8BA6145302921F2ULL,
		0x88F8C0C22C1D6499ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x78CCFDBD0694C4C3ULL,
		0x0FD43174BE5DE73CULL,
		0x7C7C52CBAC6FAE5AULL,
		0xF6F614EE60AFBEBDULL,
		0xDCCEF1EBF3DA969CULL,
		0x0C5CDA6B90DF4020ULL,
		0xD897D5BC6B24AC07ULL,
		0x49D897C6DE934C4CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA06DB7661BBCCACCULL,
		0xB4B20DB823FBB51AULL,
		0x5648CD5C02D0BDF9ULL,
		0x38260B6183D99AF4ULL,
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
		0xC93A158E8712239BULL,
		0x7F96F87AE30632DFULL,
		0x35EE4351CF47DBA8ULL,
		0xE8EE65453C523DA2ULL,
		0x9D4BF325491FA3B5ULL,
		0x6EBC3CD1ABAE6D24ULL,
		0x5DD8BE478FF413BBULL,
		0xD349CDBE8864B08CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6D1F1B92AAADC779ULL,
		0x1D3BB361F427C43DULL,
		0xDC15811BBF0617CDULL,
		0x5480BCF66F8499C3ULL,
		0xF772E86C908EC68CULL,
		0x23679C1013B298BBULL,
		0xDE37F00797D3FB8EULL,
		0x88A8DA080246B719ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFA52916741E531EDULL,
		0x90EB21D57E3FF62AULL,
		0x4BB75FB4E5055A94ULL,
		0x2851D566B540AADDULL,
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
		0x9EECC881F2DF3713ULL,
		0xF4FA34BC5473034CULL,
		0x88169C732C47DD41ULL,
		0x071F5C77BB769E5AULL,
		0xFC3167A1759C9F06ULL,
		0x66E5127A1C73BD11ULL,
		0xAC211148C154858BULL,
		0x727B5D450E125EA8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5119D41E92FDE908ULL,
		0x84FF201F2892C7B3ULL,
		0x24ECD6429F0F63C8ULL,
		0x03F756AEE2ACE1E9ULL,
		0xC06A4A4C58910E46ULL,
		0xC330A8DA04A44931ULL,
		0xC7AB0DBE7A938700ULL,
		0xD36E03D831497C5CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2D614F05AF98C864ULL,
		0xBCC2C260B4AB6EE2ULL,
		0x4CAE4CB70DDE420DULL,
		0x1F234BF19E9B53B5ULL,
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
		0x2E4A0B5F72287A81ULL,
		0x94939F722E53E481ULL,
		0x5E568F5C9DDCADCFULL,
		0xF1E09F9D679853EFULL,
		0x063C4CB035BDE1D2ULL,
		0x9328A5D69308CAABULL,
		0x58BAC2F1E740EC79ULL,
		0x6E2F0B243A77E399ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7D6048A2E8E85E04ULL,
		0xA15E8A00010CD10CULL,
		0xD35200C5B90D2A0CULL,
		0x6E346136B26F6C58ULL,
		0x39AD60EA3FBC49C1ULL,
		0x9D22949A86B20663ULL,
		0xE4B71BC37CB6E228ULL,
		0x4D02D110ADA6A31DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0E20C21F0D7CAFC1ULL,
		0x781BA45C0228361DULL,
		0xC38F5F7AB54D0BC7ULL,
		0x703CDD4D9C3879E9ULL,
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
		0xEBDDFF3F2FEB23F8ULL,
		0x93F8612D93969B63ULL,
		0x6F431F887660D237ULL,
		0x4B55FC75D6BF76C9ULL,
		0xE30E84F4F3AC402CULL,
		0x93D29115AFBB07A0ULL,
		0x5C1327B39B6A431CULL,
		0x5D7258B84FC2C7F6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x79E5A7597F1517AEULL,
		0x5548A78148BD6387ULL,
		0xBCAEEA6C62391F94ULL,
		0x2A7ED2221A04EEC2ULL,
		0x9F7ED5397A3CEEF7ULL,
		0x4B18FE414CAF79B3ULL,
		0xC759167341D4E446ULL,
		0x9605DBC47EB9218BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x794C6DB9B75C18E5ULL,
		0x0A3B8532FE904914ULL,
		0xC632C4A96053C672ULL,
		0x3AF1B684C4293BD8ULL,
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
		0xDE1171279D5F64FBULL,
		0xA906800DF0BADA7AULL,
		0x8661C9961C840B58ULL,
		0xB01E4964AA0052BFULL,
		0x117683C8ACEEC197ULL,
		0x0C928399F95D5398ULL,
		0x05A3EE285F971F0CULL,
		0x2D04DC8B5CEEE2DEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCC5E68D675E6A146ULL,
		0xAAA1BA1972C6B8C5ULL,
		0xC1E221C0595AF270ULL,
		0x76A66916B6014587ULL,
		0xCBC9720A0A874E3CULL,
		0x5257536ABE1B5AB6ULL,
		0x4706A021F8599662ULL,
		0x790A1887C4072D18ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6963AA9D42D3E182ULL,
		0xA32DECF749BF1325ULL,
		0x0FD93CC9164B6219ULL,
		0x70B0F8D6A6640892ULL,
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
		0x4D73B5F7CC7CB0B7ULL,
		0x8B6CDB5B91954B8AULL,
		0xFB1A9DAAB8DEA86FULL,
		0xBDF5E52FF1901DBFULL,
		0x3B3963500937FDACULL,
		0x91FE968C200DDF6AULL,
		0x8A07BB780BA73466ULL,
		0x863750315C2554A1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x720A51440FE1B6CFULL,
		0x30D98528D4284C80ULL,
		0x657AA3CD269D2590ULL,
		0x82EE626F8B880858ULL,
		0x5C7BFCFB07DEBE65ULL,
		0x7047F9E34BD44957ULL,
		0x278DA4927B2FF527ULL,
		0x8177D819FCC8114DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEB869551EFDA5E85ULL,
		0x5BAE97423DF945D6ULL,
		0x33BF5FF103F4E63EULL,
		0x6F7356388DE013EEULL,
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
		0xA90C11CEBEB2000DULL,
		0xF69A605585535F10ULL,
		0x98FFCC4F9625803FULL,
		0x49C223C461A86DD1ULL,
		0x72AD47F1FD4435EAULL,
		0xC6C1A3D15F2AA318ULL,
		0xF1A6A5E20C00CEDEULL,
		0x375FE2377ED3585FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF0E3457F252B94F0ULL,
		0xA045DB22C1A193CDULL,
		0x06D663DF900D940BULL,
		0xB0BB3318CF7681F0ULL,
		0x6A50E56F141474F1ULL,
		0x429B8D46CC415A78ULL,
		0xD342CD665DF18395ULL,
		0x657F7B8F9881DE7CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF5DF6BBE369D0EF6ULL,
		0xF3FBDDC492529303ULL,
		0x14FB8ACBDC5D191DULL,
		0x40562D97C24A0398ULL,
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
		0x95850FD97BDBAE19ULL,
		0x8895242BA22AEAA2ULL,
		0x6F11D06CA198E43BULL,
		0xAA122FBB9BF1E240ULL,
		0x643D1ABAF99E0646ULL,
		0xEA365757824264E9ULL,
		0xAFB498C5B3821BCCULL,
		0xA4912AAFDA4BDE96ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8586D8538D5DCF3EULL,
		0xD594FB886FBB8443ULL,
		0xE02CBFCA213E6728ULL,
		0xAAA4F977306A2222ULL,
		0x870E016801325E71ULL,
		0x3AE2FDFFDDDD7964ULL,
		0x8D5C3366A5D6111DULL,
		0x32832468D84A2233ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE4FBF9D6CE78CAECULL,
		0xB95F6BA5996A5C17ULL,
		0xA8041CBE87E41326ULL,
		0x6D8224CEB7C9B6D4ULL,
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
		0x932260648D1DCA24ULL,
		0xD63B87F09CE54411ULL,
		0xD74130E19185451FULL,
		0x533A5735599731F2ULL,
		0xFB4D1FDDB78588E4ULL,
		0xF0F636175163CCA0ULL,
		0x4CBD0521FD00B82FULL,
		0x32DED230F8047558ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDDA0559AC895DB15ULL,
		0x81610055F2BDB330ULL,
		0x260BF80D1318462FULL,
		0xC7DFED8A2054FC6BULL,
		0x4A12DE046EBB29BFULL,
		0x23E897D581DE834EULL,
		0xB6B116B5A078FC98ULL,
		0xB53BFB9EBE7C750AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0427D10A92920B95ULL,
		0xC4E0055F77F07327ULL,
		0xF6FA9CEA3A92D778ULL,
		0x3186435FC372410BULL,
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
		0x2E81DFC9A347FD4DULL,
		0x8B98BF8A8BB575E6ULL,
		0xBB07D8827B0D566DULL,
		0xAE7C78BB102535A9ULL,
		0xC89E0FFB68E7BE89ULL,
		0xB5E793CDADAB73DAULL,
		0xDFA2393A0CC3C016ULL,
		0x4578BD2A2A0DE7B8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFB3F65428FB5E27DULL,
		0x0BC2EF0273A070F0ULL,
		0xD6B70C90463C9DBBULL,
		0x41E501778146FC6DULL,
		0x34891CFE84FB23DDULL,
		0x06CC69E636CED8BFULL,
		0x10D9318018C45316ULL,
		0x408DAFAFF7256E43ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2E5E8C10E8B1107EULL,
		0x7DDE08E3BCD40B0DULL,
		0x9627F18C6CBAE6CCULL,
		0x277B77671D6040B8ULL,
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
		0xC5B4906B0667F6C3ULL,
		0xDA0280F1B3DB4B3EULL,
		0xBA1CD670A13AF6E9ULL,
		0x3AAA53C0D89B04A2ULL,
		0x09D0A2CD59990715ULL,
		0xEB1313FD468BF9AAULL,
		0xA04B14D830808A13ULL,
		0x6F3A2CCE8089F534ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6A7C6664EB682F6AULL,
		0x0B47FE248A7C597DULL,
		0x6F7E9F9FA7B481C3ULL,
		0x28CB3835B911AC52ULL,
		0x670BC4DE51E2ED1EULL,
		0x86430E847E02F011ULL,
		0xCD2A6B69460F0DA9ULL,
		0xBC48152B1598E18CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x84711B814007A04EULL,
		0xC59B52BAEDB65E69ULL,
		0xA1775D47C65EECF1ULL,
		0x21CE9DCCFF524339ULL,
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
		0x140ECBE9102E044BULL,
		0xAF672745BD1AB523ULL,
		0x0BDA6B0F3261D348ULL,
		0xA4E876B1BBB52F12ULL,
		0xE3701B2DC94A3682ULL,
		0xE7041E00A52A092EULL,
		0x249E8EFD47AE04D6ULL,
		0xDB9B452A9F438F8CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x40D47A9F0FCCF53AULL,
		0xE3919D02B48D618CULL,
		0xE603B7BF94C3561FULL,
		0x57A87EDE3D233C81ULL,
		0x0E911C96B6273998ULL,
		0x3CD8A14E0B9FDB36ULL,
		0x6B43A564CD8637D7ULL,
		0xFCCBF75EABB19EF4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6C541BB6D792990FULL,
		0x0E4A0CC5D3102686ULL,
		0xA9555FF1BF86EB1CULL,
		0x60058419A63BA915ULL,
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
		0x0A1A9B5C41CDD965ULL,
		0xA518707A26D264E4ULL,
		0xA422B60C28CB8409ULL,
		0x538D8840F7FDFCEDULL,
		0x5A1C2823522A9495ULL,
		0x81DA645D0044F07FULL,
		0x7F10E49B8FCF3E67ULL,
		0x00CAF7853B978765ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEDB1DF6CB665F508ULL,
		0xDBFE5E6B0510C98BULL,
		0x0D50BE56A6B9F4B5ULL,
		0x906390CD6B5BA87CULL,
		0x05B287D6B35A47F2ULL,
		0xBCF0C35C8E1D1111ULL,
		0xB5F312DC9AEC56EDULL,
		0x9ECB27C555A79A87ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA416874F1E5340FFULL,
		0x03C7F82013ACC5B8ULL,
		0x713F1A0DDBBFEB67ULL,
		0x4F22CDEFAE3F7D5DULL,
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
		0xC3DF6C93C59566CFULL,
		0x7054D8724318D512ULL,
		0x0AD6B2515856632EULL,
		0x52A72838FDA23E89ULL,
		0x418E30956BBA2E65ULL,
		0x074E3F1530A958E0ULL,
		0x95BBC617514E6B47ULL,
		0x8BE644C87FB76790ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x459DAB5325509EA4ULL,
		0x0E324CAF07AE7564ULL,
		0x550EE071879D1D81ULL,
		0xE2C464D2946B230DULL,
		0x67980623A88C0315ULL,
		0xA291473FC718B66BULL,
		0x431E8E791ABAB611ULL,
		0x15273F8EEA06EDC8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD8CC0E23991F3891ULL,
		0x562F5570E6E27D06ULL,
		0xF91E135BEAA62B9AULL,
		0x103D89F2A1692F37ULL,
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
		0x2D812F95351E58AAULL,
		0xAB3B9E3D72FE1256ULL,
		0x1C2C8927DB4AF649ULL,
		0xDA24413C9C8D9F01ULL,
		0x69D4514112F226AAULL,
		0x0DBC6D44D5338D9BULL,
		0xE84E6F74CB323429ULL,
		0x36799D23F14F2E23ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1CE2F5B71248B2B1ULL,
		0x57F09238F4FF7A89ULL,
		0x4F3F0355CD8F0966ULL,
		0xB570D9E37A68E3E1ULL,
		0xE14F46258AD1DD4BULL,
		0x14C26254492C6D53ULL,
		0x1BD6EC7E61146AF2ULL,
		0x9F4684873C1FCBF3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x545DDFF457A087C6ULL,
		0x4868ABB9470D626BULL,
		0x26AAF665CE27CB0CULL,
		0x16490E9C072D4E5EULL,
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
		0x58951C5708261CABULL,
		0x227C5108B9A9A7E8ULL,
		0xFF5E54239761811CULL,
		0xB1F423FED8561347ULL,
		0xBC00CEF075D43E0FULL,
		0x85F62C2F94DA563DULL,
		0xCF467B96754DF24AULL,
		0x7A2AF4CE798287DDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x25B1FC45F31554A1ULL,
		0x365487E108EA9DE7ULL,
		0x665E869F4F01A12FULL,
		0x61CDC7E9B40F2479ULL,
		0x05A2740DF749A0E7ULL,
		0x34F82CF2BFB58030ULL,
		0xA56439390FF03C39ULL,
		0x5AD4B637C9B60F55ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x44E49DAFDDA41CA5ULL,
		0xF1DBAC2F5436D00AULL,
		0xD095A7615448E67EULL,
		0x76F3A6733CA0D304ULL,
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
		0x3C3DD137DDE17BDAULL,
		0xF9B2DB6AE9D776ADULL,
		0xF5578404631E4FCAULL,
		0xF1D7651E5F5D7B25ULL,
		0xACCF5D921D8FFBC8ULL,
		0x41852D00992CC44CULL,
		0x7D2BB8D8D5FFA2D8ULL,
		0x8A875F6B71FC8E40ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x40DFCCB4DFDDB97CULL,
		0x6436915A528032C7ULL,
		0x0F93AE659A450578ULL,
		0x034E9BEBB8C405B8ULL,
		0x5E564CE7B8112A3DULL,
		0x3E955036374E08EFULL,
		0xB6258F4CE0498BA9ULL,
		0xBE56BF50C178D2DAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA1567DCE0ED6DBF6ULL,
		0x0517101B1E6713BFULL,
		0x70AE006541E0BB4DULL,
		0x3DC08D28DA274689ULL,
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
		0xCE2E0F238A1EAEC6ULL,
		0xED66E91412042233ULL,
		0x8E4BEF695BAE4AB3ULL,
		0xD43FA60D2011044AULL,
		0x7CD5901CA9CEA59EULL,
		0x0E6B6F11F98E788BULL,
		0x8B0DAA9C6C31AC63ULL,
		0xE7823839F27B4822ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1BCBFEDB72A236BEULL,
		0xEBB6360A1444425FULL,
		0x8A5B28C692A919DCULL,
		0xF170EC01A4D4AC77ULL,
		0x9F60A6C9D45FC4A7ULL,
		0xEE516EC133AA0E07ULL,
		0x19715A3A8ECBA323ULL,
		0x9E6E0BC2BB668681ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x91BCB293C5F1DE41ULL,
		0xC58CBF075DA7AF67ULL,
		0xE124B529A62A9035ULL,
		0x3BCD53BDA85115C9ULL,
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
		0x31C1BD6AB24F8C8FULL,
		0xA99F2C10EAFE9DFBULL,
		0x2FAC9E7967A6A080ULL,
		0x9E96DD8466D42588ULL,
		0x33EA76D48E178AE3ULL,
		0x5705FB4C449AADDAULL,
		0xD0EDF88583EA6563ULL,
		0x2A4F650AD50141BCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB93DA9D4C4EA7242ULL,
		0x3FBD2A91BF012AFFULL,
		0x9389AB6DDEE7A9C3ULL,
		0xB78016F38DF22998ULL,
		0x90C99ACEF9C918F2ULL,
		0x180DF8EE9FE02488ULL,
		0x34FE06A1A39BB1E8ULL,
		0x31BD33EAEFA9D9ECULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAF64BC69F10A03DAULL,
		0xC2B25B659FADD519ULL,
		0xC1C0DADED46D9B08ULL,
		0x4CCA114CE3DB64E6ULL,
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
		0x61CD40FEA96485AAULL,
		0x284271E68E9E2782ULL,
		0x75C753A3B29433DCULL,
		0x05CCC2FD522AF896ULL,
		0x72574A4C96C9EDDAULL,
		0x4B762D6CFC9C923AULL,
		0x4BA72773D8C3BD18ULL,
		0xB904D273072A6B39ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x734C4095D3AA791CULL,
		0x2AFFCF1B51D4D5CDULL,
		0x55C4E965F69CF632ULL,
		0x8D758F7606561B3EULL,
		0x147DC5928F10493DULL,
		0x5D76A0934578EBB4ULL,
		0xB5BD86BAAAF74196ULL,
		0xEFF4C9C2B767640FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDCCAB405FB487A86ULL,
		0x51318B1C6C1409A6ULL,
		0x60B045BA885192F3ULL,
		0x50B87DB322C7ED84ULL,
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
		0xEF9CD0DADAD99C3CULL,
		0xAF0AB427A1380EA7ULL,
		0xF3BAB0ABA5B8AB85ULL,
		0x18C00B9CED43DE5CULL,
		0xBD8C556983E396C4ULL,
		0xEEA5FC9F37033E3CULL,
		0x9B1249CA34CA7BC8ULL,
		0x32054A0EE6FFA6A1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF7950FF9F1BBE40AULL,
		0x80589D87A8F6FD04ULL,
		0x6F4BE3977DE632BFULL,
		0x0AFC92E0ED13B6BFULL,
		0x7A76318555BA9003ULL,
		0xAC732D4539D48737ULL,
		0x4E1D26F58C1564A9ULL,
		0xE19B23C21CCF49CCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xED5114BFC334B4E9ULL,
		0x023CDDFB8D303C6AULL,
		0xF0D1F8A532B3E76AULL,
		0x7D852822035DEF46ULL,
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
		0xA30F09C876AE7739ULL,
		0x52C616D01847210FULL,
		0x454DF6D2684EF853ULL,
		0x40DF9154270C22D9ULL,
		0x735E51B07BCEB874ULL,
		0x9A28A14E0044EB66ULL,
		0xBA59FA8FB7193891ULL,
		0x13F1C495D9DB231CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x735E4924CE55A29DULL,
		0xA527237F8740AC8FULL,
		0x113946BC784BB0B9ULL,
		0x62D10CE6379E57D8ULL,
		0x27C6BBFEBB66751CULL,
		0x36FE059DDDC1C641ULL,
		0x38A4C6B346C71068ULL,
		0xE0A2A049B534CBBEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6830F90637D2CF12ULL,
		0x65F20F75B07DF809ULL,
		0x74FA62CE9C353DBEULL,
		0x7BCDE7BB601EC308ULL,
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
		0x7A6F16419A029B76ULL,
		0xE46E41179A1CE13AULL,
		0x45F9FD14EDA80F50ULL,
		0x5CEE9968248FB460ULL,
		0xAEEE4CCE97252C74ULL,
		0xF12400F1F12ECBE8ULL,
		0x3431F274223D94C1ULL,
		0x797265C43DCB7708ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0A92A55AC0A8EA89ULL,
		0x7E7659EEF13D756BULL,
		0x9E644077330BBA8EULL,
		0x483B5A0BF363BCB5ULL,
		0x1B865D751F2EEB18ULL,
		0x8C1DFD51723B14EDULL,
		0x2432181B714EFCADULL,
		0xFF28BCFA1F7DADA8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5149F82EA7E7619DULL,
		0x64DC70FB810C9527ULL,
		0x079025C7FE06E7C9ULL,
		0x3BA24D5CB0B7DBEDULL,
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
		0x795F26F2E5BCBD9FULL,
		0x8DB9A8C1C8A30A4AULL,
		0x30B70414631400D7ULL,
		0xCA3C01BE791A9A5EULL,
		0xF0A4C1976929E3E8ULL,
		0xB60187F2E59FC2C6ULL,
		0x296B5E0FDDDD4E0DULL,
		0xAFF1748DDCA4C42AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9D14D350105B0815ULL,
		0x1881B2D76530F5E9ULL,
		0x1DC730C90F9C2AE3ULL,
		0x6F2EB13DB7663AB6ULL,
		0xF711F16A5A3A68CCULL,
		0x32E741FD1082D206ULL,
		0x5037E7CA97A20C73ULL,
		0xBFDA3ADB7CC08E8FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE8153A530CEDFB53ULL,
		0xEB1E586805BDD0DFULL,
		0x50936193C04392E3ULL,
		0x7E7FE0FAFD9454A4ULL,
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
		0x57296D3D68B8C54BULL,
		0xD0D516AE7D024B9DULL,
		0x104FB762096B5A2EULL,
		0xE7C513EE9CC0C2E2ULL,
		0x8380DA36348B5DA5ULL,
		0x46C557663B7EB6ABULL,
		0x9E13CB20D0514E84ULL,
		0x6E1F853CEC4745B8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x675556171CEB81B9ULL,
		0x8CF68B4EE0A1F078ULL,
		0x5BE81599C3EFC064ULL,
		0x0C3F4C80BF3AD280ULL,
		0xF06DFFE47BA0C7F7ULL,
		0x8F6D48EC82D46018ULL,
		0xC1072E315B72D238ULL,
		0x734E2B19FD706A9EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC4A07F47BE9F7B66ULL,
		0x7AF0B17105A934E6ULL,
		0x8446ED539E820D07ULL,
		0x1699289D516A7638ULL,
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
		0xBD10DB594F9F18E2ULL,
		0x6F5E0010326DA1CDULL,
		0x314492C88CBACBBDULL,
		0x34085A6B75450F4CULL,
		0x09CBAE5730023520ULL,
		0x52033110D3794086ULL,
		0x963E66C5021AD050ULL,
		0x9D8EE823550516EEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1433DFD2C7DF7486ULL,
		0xC83A1B644263D871ULL,
		0x26A17A8A37F4635EULL,
		0xA523BEAF75E14DDCULL,
		0xCE2C82CFEB16992EULL,
		0x958E108C4CD8D955ULL,
		0xE1EE1577A54F4EE3ULL,
		0xC1D00B274DB7B739ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x827D719AC2B8C964ULL,
		0xA086B857EBD91A85ULL,
		0xCE8F29BA1AFB9E82ULL,
		0x2D39692514DFF642ULL,
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
		0x357877CAD5DB26C2ULL,
		0xAD425CA70EF3A960ULL,
		0x319478169AE982CBULL,
		0xA124A7836B4F7677ULL,
		0x5618152E36B16043ULL,
		0x8BA6EDFCDB1343BAULL,
		0xDA7CA7E51AAE9460ULL,
		0xDC70A8CAEC6D81C2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x078702061C5B8BD0ULL,
		0xDF49294AB90750F4ULL,
		0xCD213DAEE2C6E923ULL,
		0x04C9FEF7E0BC479DULL,
		0xCEFB3769D0FF04B1ULL,
		0xBF5017BB1B80E8A6ULL,
		0xE7EE3613EF8FEAFAULL,
		0xD7E445EF3A56785EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3C3A60EBD1F932C4ULL,
		0x22DD011EC5A5DD52ULL,
		0x65981F741EAFBEC4ULL,
		0x49315527F9FE93AFULL,
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
		0x48AE0822B7176340ULL,
		0x7E8DFB5A70B2456CULL,
		0xA7831415648AE1BFULL,
		0x77AE9D5E68824CE3ULL,
		0xB9749DD1E8DDAEE7ULL,
		0x4482A328A3502D1BULL,
		0x0DB612C1EA3E64DDULL,
		0x4226EA02A75E4A85ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7C0AACC12FBDBAFEULL,
		0x492C27109CF5A50DULL,
		0x3FD00EC6AC29F7CEULL,
		0x3582462DC631F120ULL,
		0xE1BBB0A0D633C987ULL,
		0xFED455E6E545A49BULL,
		0x7AD8C6181861A387ULL,
		0x6EFE31C2A1C740ABULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD21690AA4C91B38BULL,
		0x8D414C0C094CE358ULL,
		0x348C6683DF259C99ULL,
		0x1A37B0B176BBD20FULL,
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
		0x6E49022B9E3ECA4DULL,
		0xF2126F223832A4EEULL,
		0xB087B9C95DDB8F7AULL,
		0xAB18A087821924D0ULL,
		0xDD572193A1C689B0ULL,
		0x3FBBE2AA1DC7750CULL,
		0x4D4DD02E841095AFULL,
		0x963FBF1674A690CCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x14DE0E514EAEC08FULL,
		0xF6B0217342811236ULL,
		0x4CFDBBF903A24BB3ULL,
		0x45AC41982B9FB50AULL,
		0xA0E5F25E82C109ACULL,
		0x25612FC7482A214BULL,
		0xB3A1478493E1A51EULL,
		0x58864679476552C1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5237F5BCEA610BBFULL,
		0xE4D8DB5AAB0C0167ULL,
		0x3326470A0130F950ULL,
		0x0EF446440E28A559ULL,
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
		0x6C651AAF5E17E6D0ULL,
		0xC5A412CCEA127DD5ULL,
		0x1D08A3E1FAA3C7ACULL,
		0x99AA5EA8CC425752ULL,
		0xE1CE7BFF5A1FD24AULL,
		0xFE06756FA5187336ULL,
		0xD64BDE3D8EF7B393ULL,
		0x7F65F9F3AC71A962ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x978E9E7DFF82D19BULL,
		0xE97153256C58D2BFULL,
		0x7F563BFAA95C395BULL,
		0xC90CA53F6366FDD6ULL,
		0x3003AD206D1FF5FCULL,
		0x79854822112CB492ULL,
		0x400AB76AF5CE1D4BULL,
		0x24C68F1753089114ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x38F131488C8FCAB7ULL,
		0x875F792B72B7F788ULL,
		0xEB5E2B2A0D73DD14ULL,
		0x4447961EAE74F525ULL,
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
		0x52BE2EE0047232B6ULL,
		0x03920CCAAC144B0FULL,
		0x1246F8786FDFA43BULL,
		0x6A1627A4850D122FULL,
		0x1312661DCB1A4438ULL,
		0x3773A7A2B69ACC1DULL,
		0xD48C513E45FBE811ULL,
		0x5A427FCA0EA44DCEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC992B5156AA61109ULL,
		0xCAF2701E4562382EULL,
		0x048F30B9AE47B738ULL,
		0x2785168DBA87F553ULL,
		0xE572270136C4A2F8ULL,
		0xE3EFF42E698CF335ULL,
		0xC98425696715374FULL,
		0x7ECB8844441C41ECULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4EF4D8089E82105CULL,
		0x9E2C3FEFD6C04531ULL,
		0xB0EE4957D7D629B4ULL,
		0x5639CEF2DAB6E069ULL,
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
		0x9D62CC3995A81E31ULL,
		0x0B180DF4C2D45BA2ULL,
		0xD433A87560DF8A1FULL,
		0x6D7B382B3E8180E8ULL,
		0x09068A72CADE9796ULL,
		0x3D22A55D2F876AC2ULL,
		0x278A6F9A2321958DULL,
		0x14C8DEA9701BA7E7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1CB01B2DE1C8ECBBULL,
		0xE0EF802C761337E8ULL,
		0xC0B4893D6C788F17ULL,
		0x9598657F49EDA9D0ULL,
		0xC1FE79CFE8DD0F06ULL,
		0xA067CF854912571EULL,
		0xAF8DCF8EBF8AE472ULL,
		0xD45E19FB8D42AB35ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0BE5293940197288ULL,
		0x6DE44BD482220DF7ULL,
		0xE2FEE0E8BCC544FAULL,
		0x67BC047BA0C9596FULL,
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
		0xCD34C6612BEFE68BULL,
		0x2EA58AE13889FDEBULL,
		0x0C105F8704DAEB2AULL,
		0x3C849B20597517F9ULL,
		0x93A95F7598DE023AULL,
		0x84B6E0EFA9421309ULL,
		0x4679DBB18417AFB9ULL,
		0x3A27C843C7BBA985ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6613D888FD4ACB2AULL,
		0x85383262AECDBF00ULL,
		0xC61AA1DFD0C98F9EULL,
		0x9BC152D6835846FDULL,
		0x1A421998EB04B151ULL,
		0x692EC32A1CE06B75ULL,
		0xE084733CC9C2DB81ULL,
		0x19F356341DF12DCBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6C754C99FCE71E8FULL,
		0xBFA1C3D1603B1EF5ULL,
		0x68633EFADCA8DBDFULL,
		0x688C369D0A2B2E80ULL,
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
		0x42918F77F1981439ULL,
		0xEEC97AFC35037942ULL,
		0xD01B38112203440DULL,
		0x9A7F0EBC2EF5BFF2ULL,
		0xB9CA484041E4EFE1ULL,
		0xE22900FA208DA1ADULL,
		0xAE2F905862407AE7ULL,
		0xEE90DAD96D498DADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1CB8A2C3D8912864ULL,
		0xDAB50BAF1D215E27ULL,
		0x07BC7E82B62DB533ULL,
		0xCFE523A9596E7E59ULL,
		0x257D6A0F1DDC610BULL,
		0xEFCF114FDB55D6C5ULL,
		0x4034BE3A151D52E3ULL,
		0xFCDB9DFE5BF63EC5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2941E7FF724C1F3AULL,
		0x0D6E02935E2A39A1ULL,
		0x1B99EA0DDF0D7F70ULL,
		0x2B80F39767E4F81AULL,
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
		0xB7CC95634CD1B112ULL,
		0x9D43D597140D47F7ULL,
		0xD377BAA9C75A525BULL,
		0xD3B56E4F81F76652ULL,
		0x099DFA6153FB8BB0ULL,
		0x172AA58121C9373CULL,
		0xCC4D3CEFED45FD58ULL,
		0xBED75636465B72FCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCCD0F427932D7997ULL,
		0xA01C7A74216F9BDBULL,
		0x398D1F330F952D95ULL,
		0x181042B4F5BC4F35ULL,
		0x2594908CFF43E753ULL,
		0xBB2C94454DBF0A0BULL,
		0x159C4C7AF4447575ULL,
		0xCD6FEEBFEEEDE083ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC46156C04CE69D10ULL,
		0xA4DDEA046C20615DULL,
		0xB82E4CD3ADFF505FULL,
		0x10FE872B867ED52EULL,
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
		0x0B3D70BB6BBF85DCULL,
		0xECF716482DFB7939ULL,
		0x376CAA4DECC42D0CULL,
		0x29D7E4EA8F252E6BULL,
		0xD05B67A7FC403C43ULL,
		0x4515FE26525DFF30ULL,
		0xEC0DCEAB687AC9A1ULL,
		0x871DCEF4DF81AA65ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE57CF39F3CFAFA16ULL,
		0xB13760E6121FAD1DULL,
		0xC5D66C53205C7ED0ULL,
		0xB820468FDD0E2AA0ULL,
		0x42F72ADABFBDE170ULL,
		0xB168521C8174965EULL,
		0xE0A96FB4183BBE69ULL,
		0xBB4568B283C8C808ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x22A183932A1E05D5ULL,
		0x27873ED71E815B5CULL,
		0x227C56B0B5C3587CULL,
		0x33D6CC344F889D9AULL,
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
		0x16EBB918C31CB52AULL,
		0x4F82FE48606A39A9ULL,
		0x9B5234012CB14953ULL,
		0x9920A459F5AD1F52ULL,
		0x1BFFF86A1CF5D2A7ULL,
		0xFDE8BBE35C095180ULL,
		0x1FAD0DD9EFDDB859ULL,
		0x4542F71E9033E289ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4290784A6EE6C642ULL,
		0xF35C3DC90377BE91ULL,
		0x8E8CA8E44A7553BEULL,
		0x143008B6228EE8DBULL,
		0xAD9600570C915D96ULL,
		0xC4E1A8BD14C324C9ULL,
		0x75BC3AE838FA5EF1ULL,
		0xF9C7DB8B75E81F95ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x381613A2C31F4B7FULL,
		0xD333982DF15D1E2CULL,
		0x4684DAFE07FB3B0CULL,
		0x3936B379BA5D26A2ULL,
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
		0xCBE41041BDD28901ULL,
		0x12F62165F1697086ULL,
		0xFD8198024A1DB9E0ULL,
		0xF87C150BF20F6DC3ULL,
		0x01792B04EBCAE2D3ULL,
		0x326C6B24B133CE87ULL,
		0xF8879FB612F9D1D4ULL,
		0x7AE6E7911345598AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF6E5A4354B973FBCULL,
		0x7CCF30677FCF1D1BULL,
		0x5780DA81178F7992ULL,
		0xF538F99D991331B6ULL,
		0x0C55BB9993A121E5ULL,
		0x7C1A038A3B8B32C1ULL,
		0xBEBE94CE24D409FEULL,
		0x546393670B7E3D86ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3840F5FB886DED6AULL,
		0xA66251EBE8A172CDULL,
		0x39D85BEE8C29EA06ULL,
		0x3AC199AB808A64AEULL,
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
		0x405E7AEA61568850ULL,
		0x2135E0AB8350781DULL,
		0x75099F6E9C7A9F31ULL,
		0xD20B15EAF986481AULL,
		0x77EA1A4366DFB3F9ULL,
		0x8567DC3698F13636ULL,
		0x022A912A8C191E33ULL,
		0x97D5B389E748980CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCC5276EE865FEAE9ULL,
		0x939C83D289916CCDULL,
		0xB92EA26082227A29ULL,
		0xEF2653F45440AD40ULL,
		0x1A948EC0DBB4E598ULL,
		0x7616A5201A851520ULL,
		0xF3EE8551E64E5B27ULL,
		0xB9B8BE859804664DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4EBEB95C83513EFCULL,
		0xD3A78A2FBDCBF4A1ULL,
		0xD8C4BF36B67118D1ULL,
		0x5B31209A6964FD0FULL,
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
		0x95A4A1D01E78DC50ULL,
		0x8E213A3BF4A09A16ULL,
		0x3E40F9CCABE1A4DEULL,
		0x39FB18170DFAA9AAULL,
		0x9314B5DD6EA07364ULL,
		0x1CF82B2FB0E6925FULL,
		0xF68100DB83E70E85ULL,
		0x99BE885FF929AB57ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x460782DE0A90D055ULL,
		0xB2D68178ACB62E1CULL,
		0x8B4AD0AE1075B273ULL,
		0x340AB5F911FCADCCULL,
		0xD1F363E03B197653ULL,
		0xE48DB54E1DEEDD46ULL,
		0x1C78E15CD58F8925ULL,
		0x103BCD84F05D47F1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFA8F4A87B9F19F79ULL,
		0x3B18383F18AF4DA6ULL,
		0x102AD5EC7C69BE8DULL,
		0x6F581EA14A54BD22ULL,
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
		0x6F2E36A0D343E3C3ULL,
		0xD107AE34F2D17674ULL,
		0x81DB1B000E008478ULL,
		0x1BF8A4CCF5CA01D3ULL,
		0x0E75A3F312A65B32ULL,
		0xDF58D7D193DABBB9ULL,
		0xB5153E74FF809FEBULL,
		0x51F967C0A557F5F7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x65308CF52BE79426ULL,
		0x91998E4FD863EE15ULL,
		0x1D76DA763F99CCC2ULL,
		0x7E9400D7072A84B9ULL,
		0x47BCA4DFE84FCF44ULL,
		0x569A59F8827FD764ULL,
		0x76EFFAD77B75B3C1ULL,
		0x3E8005C92917F88DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x89738683F0351550ULL,
		0x8BB4CE1DADEB6CF4ULL,
		0x9DEC49EB6805C606ULL,
		0x01692EB2601F1ADFULL,
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
		0x18BEC8313AF803F9ULL,
		0x383673BE1010FB1EULL,
		0xDE0D75A84FA3E3C8ULL,
		0x205A17390EF0BA9BULL,
		0xC533E3BB1E65F12AULL,
		0xA0A3B6839C087131ULL,
		0xBA077E761689BD69ULL,
		0xD393D196EEC1EF8BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE94877A602136ADCULL,
		0x6CBD50EEC57B75DBULL,
		0x53D229152A562333ULL,
		0x8FB7114A680AEED1ULL,
		0xE2F379F709775DF7ULL,
		0xD9A9E407BFBC5903ULL,
		0x938C9D3A3725E2D5ULL,
		0x69DDE2CB81AC1660ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC50603A6544E74E9ULL,
		0x548E6131FDE11C11ULL,
		0x4078BB764E203284ULL,
		0x41A47820D8240832ULL,
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
		0x98FFC5DCDF9785CEULL,
		0x379B58F37F90DDF9ULL,
		0x8BFBA9CFF266049AULL,
		0xD9129799DB699EEDULL,
		0xFBEA8FA99A08C9DEULL,
		0xD6227B248B39E3B3ULL,
		0xF50BEB575808FDB1ULL,
		0x7F2F6745D8ADD4D0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC485FD5C9E094738ULL,
		0x33A12400CB1584A8ULL,
		0x2F36E45B7CB97DB2ULL,
		0x7B82FC76C7A2DDD2ULL,
		0xFBC443CBD2CB7ACBULL,
		0xB40D03A1D8D94241ULL,
		0x6AD960BDD8CF933EULL,
		0xBD53E4BB37017537ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDA290B6BD4A7FA12ULL,
		0x1329F2592ED3503CULL,
		0xE045583D583253FFULL,
		0x2424FBB7135CF1E5ULL,
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
		0x04D443940D91DEF9ULL,
		0x104E0135E148B98AULL,
		0x4300430476B456D3ULL,
		0x6EE1A32FAAC2AFE3ULL,
		0x6D155BEF6699C4A4ULL,
		0x935D7409A8C05F83ULL,
		0x3FB39938143553BBULL,
		0xE4A2AC74919CC328ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6707E06A8BD95C36ULL,
		0x63CC743299D380FEULL,
		0xFF5B87F3BB03E3D6ULL,
		0x50C1FC9025766DC5ULL,
		0xAF968AA7CA0BF12EULL,
		0xC300227352B07AF4ULL,
		0x7F5A893BA91CDE27ULL,
		0xCAD874B1DCB7B87CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBE9F73CABEC5E6CCULL,
		0x9A5BA9540DD125BBULL,
		0xD0DD1A88A151E6EDULL,
		0x7223ED865F4BD79BULL,
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
		0xA4110E8A80E30597ULL,
		0xBC67A1AA95D57D3FULL,
		0x2098BE941E485C5BULL,
		0x47AAB3C2098D14F5ULL,
		0x1BC3ABEFC575FF49ULL,
		0x98F2A56F6B1A3CC0ULL,
		0x71E3A4D2D1EB5951ULL,
		0x97A51441AF3B2714ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBE14F1F541B53BFDULL,
		0x3A838639E5AA9C61ULL,
		0x95788BF86F41C950ULL,
		0x1C93FA8C2354A13CULL,
		0x092C6EDC3441E86AULL,
		0xE6FEB4109C1AC054ULL,
		0xA360DCEC3992C7CDULL,
		0xE8BFE41CB6F8D3DBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA86F2D7CCCE92CECULL,
		0xEC19EF836A1758E8ULL,
		0x3289DED64C2C2C97ULL,
		0x211BDEB2C010CE27ULL,
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
		0x74DDDE5AFC605C96ULL,
		0x64D6B6A12A23158BULL,
		0x6989C3F9AF56B039ULL,
		0x9F3996D48B6D580EULL,
		0x2817F4C673369743ULL,
		0x0FDC76612A2D68D4ULL,
		0x7D87C841B89E7E18ULL,
		0x8649F87D6E4E5ADCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9831B2F5792642EAULL,
		0x991F0341CD16164BULL,
		0x5A021232B94BB818ULL,
		0xC59E51B83E549FC5ULL,
		0x0A1C5DE8F9854F57ULL,
		0x8A2BA85A98524CE3ULL,
		0x2FBDD14271515545ULL,
		0x9D276757CFEE647CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x50049045938AC61CULL,
		0xA3F648590393250AULL,
		0x9B825BAB8B7F0760ULL,
		0x74BCD0B1CF574A94ULL,
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
		0xF0A71B364FCC726AULL,
		0x1EDFD0302ABDE441ULL,
		0x2C98FF41E84F0059ULL,
		0x8F6F143AF9568944ULL,
		0x6BDE03C9AF4F9F6DULL,
		0x915C151E8C9FC5F0ULL,
		0xC1A270E2F3C60754ULL,
		0x624045A7C4C8F5E1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x807D1CEB534404EEULL,
		0x88D55C83A0E46835ULL,
		0xD60F0B13D8F6B391ULL,
		0xAB0762C71A8CE674ULL,
		0x53AA3B373DE9C5C0ULL,
		0x6E4F8DE6D9EBD785ULL,
		0x95024F1D5D0EF440ULL,
		0xD7FAE03930D32895ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x07D9C407D1A6BA7EULL,
		0xC9E685F1108EDFF2ULL,
		0xF64EF7826E8521C4ULL,
		0x6AB4BFDDD5461C1DULL,
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
		0x519C77D092B5CBCEULL,
		0xCC543B64286678B7ULL,
		0x285F5CC87A15AABEULL,
		0xFBFB67C3B74DE340ULL,
		0x92AD7326ABD5E464ULL,
		0x8B4C3F0E1C437182ULL,
		0xEA48F079DFC50701ULL,
		0x165DA3FD85273C79ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6A9CABF4621FCB2AULL,
		0x55A946B33286EA05ULL,
		0x512A5BECFB7CCCDBULL,
		0x30651AD44F27CC80ULL,
		0x4B4C13DEBC2448C1ULL,
		0x7307BB03A86D4782ULL,
		0xF838030ECB371B03ULL,
		0xEF9BB668F0946C3EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7F73F089C4F31629ULL,
		0x10D68E3E27A9CABCULL,
		0xC5B83EC08BA9E59BULL,
		0x0C5F90FD75F0FF7FULL,
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
		0xE4B5BA670043BB4FULL,
		0x05E75D532720CD47ULL,
		0x88CB8ED74604EF35ULL,
		0x74CC3C9D57945CEFULL,
		0x74EA18B4B8836DB1ULL,
		0x79C451B187107D2DULL,
		0xE3395E385067FF11ULL,
		0x76B8FDC65474B79AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9BD3706E2D48B6FEULL,
		0x3A6E0C080A60BF78ULL,
		0x591DA52A7F8C0886ULL,
		0x0DC8D9F2E58A7E42ULL,
		0xD90726E311947942ULL,
		0x247A426A7B5F3087ULL,
		0xCE7E4C853105F11DULL,
		0xD80292E152FCE80EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6C922F179A734AA4ULL,
		0x747795D6D9116E64ULL,
		0x43728A436F06F8F3ULL,
		0x761740A8A9D2AD78ULL,
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
		0xC79A2B79279C8871ULL,
		0xC1A71F8DC3F4D5F4ULL,
		0x26CAD8E8BD85F755ULL,
		0x75A00BBF7B305D67ULL,
		0xC5FBD5657D520CF5ULL,
		0x80F406348007CF74ULL,
		0xE47F1A40BA4F9474ULL,
		0xB3C1B616A93FFB39ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x96FFF7C15987EC93ULL,
		0x76EA06AFC6B293FCULL,
		0x6F9A6D3D183CAC46ULL,
		0xE24E89B9EA3064B4ULL,
		0xB73BFDE96503D3FAULL,
		0x2C421557B0DC061EULL,
		0x41C87AF63718B2FBULL,
		0x9F26EF14BFFA6171ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6114302369B1117FULL,
		0xDD26D9A4BDC224BEULL,
		0xDE4C10BB1F6EC311ULL,
		0x224B0C4E3154CC7AULL,
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
		0x247738D19C33B7B6ULL,
		0x9F303C45CECAF18CULL,
		0x92CD341246F07A19ULL,
		0xA673904F101802DFULL,
		0x94E4540857B9A90DULL,
		0x4C6979DD03894B5FULL,
		0xC0B6752BABD721DBULL,
		0x38B731F6C0EDD69EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x60267A442C374560ULL,
		0x97894F7F7CF71431ULL,
		0x542EF16C63A853BDULL,
		0x67DCEE3127E489C2ULL,
		0xB7E244787F2ECF37ULL,
		0x34A0716601E79893ULL,
		0x23A036496BCF948DULL,
		0xBA777590BB321572ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x929F0DE79498C535ULL,
		0x8F7E2E708FD4679DULL,
		0x8FEB983B64671FF3ULL,
		0x7C0C9942C21225BCULL,
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
		0xDFA2E1C6F2108429ULL,
		0x27EF46105EC77D34ULL,
		0x9E69EAC556FAFFF1ULL,
		0xD73A98DF1D3058FAULL,
		0x52D8740D4C5E3834ULL,
		0xBF3EE013A91C1EA1ULL,
		0x8C9FAD1A26BBBA8EULL,
		0x42A297BBCDF94A12ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x966F80E52B4081ECULL,
		0x0B6759476CDFBA3BULL,
		0x2A29465381F105C4ULL,
		0xFDBFDEA91D6E30CBULL,
		0x39FC1A33484491F1ULL,
		0xE7D536D10D973BE5ULL,
		0xB53D3EE8D0E44130ULL,
		0xBC1C55DBC9B2B96FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF9E8B73E629EAD70ULL,
		0x16370CAC07A16AE4ULL,
		0x6CDCFFC49305FE1BULL,
		0x51688176A23BA05BULL,
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
		0x5E45FA2421D85DC4ULL,
		0xC48833334D228DEDULL,
		0x22CF0C65A2F342F4ULL,
		0x2CCAB1161FF0CEB2ULL,
		0x7F89B7189222B297ULL,
		0xE6419AA65104B1ABULL,
		0xADB2D1A8EB5284D9ULL,
		0x400D61D3322A1471ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2A1FF1499F16BE85ULL,
		0x96030B6C64EBE4BBULL,
		0x0815CCEC35E33A4AULL,
		0x9A287E4532654007ULL,
		0xD5491045B6ACC3C9ULL,
		0xCCE84EF7CF13066AULL,
		0x1D246E489152275BULL,
		0x6C84185976D94FD1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x79BECC27164310B6ULL,
		0xF1C663AE321614CBULL,
		0x8FDBFFC6C91DE961ULL,
		0x79031AE2BB88BE80ULL,
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
		0x7D3D9DBF54E8C421ULL,
		0x81CCA1B660A8537CULL,
		0xC8D8E859407A71F7ULL,
		0x5E2BD6B71AB6984BULL,
		0xA157BE05E1ADFCEDULL,
		0x3C77AC38CDA8699CULL,
		0xBCEAD1F147BB720BULL,
		0xF1580A296CA9CB07ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFB74B33DEAC5D73AULL,
		0x31CFB98384A741F4ULL,
		0x66DED36CB169CA94ULL,
		0x8DE038F3656DE23CULL,
		0x3E2B217AB42D3B51ULL,
		0xCB6B3B245DFDEAD5ULL,
		0x6581C4E3E42C3961ULL,
		0x1510C8A04BDE7883ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3A68272A2B3FAEE2ULL,
		0x17D5B13B6F4FE320ULL,
		0x5B9204E95653108AULL,
		0x02DF581E9376F5B4ULL,
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
		0xC1F4BD1C110E6957ULL,
		0x2BEEBBE924271C7EULL,
		0x04EC5E386256A78AULL,
		0x16665D23FEE7ECD9ULL,
		0x458EDF0BFD08A860ULL,
		0x1FE4F45AFF361A37ULL,
		0xCA0BE58C29641C1AULL,
		0x4AE48110EDEF641DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD71BA015BACB4063ULL,
		0x4660E46B6E268350ULL,
		0x0366082C9877A105ULL,
		0xBB00A9ADDA9D97F1ULL,
		0x1E5A64CC732463BEULL,
		0x035B9648A485B09DULL,
		0x8A3915DC29DD4CE7ULL,
		0x006DCE080EE73F22ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBCA34274CE255A7CULL,
		0x21F1CE372C30460FULL,
		0x7AD12A2BB7E1C81BULL,
		0x690446C73F7FD233ULL,
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
		0xC44DD1456E13A6ADULL,
		0xFF837B554E65E5CBULL,
		0xCDDA7481628DFCFAULL,
		0x6212D1F62A13B664ULL,
		0xC85E00DCC7F4ECA2ULL,
		0xF76D9BB9292B0547ULL,
		0xEE2DFAD69D4439D9ULL,
		0xC9E0C2C62B26DEF8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x303227DB9D09622CULL,
		0x1CCAF328BBFBD042ULL,
		0xC435E4F8A048B7EBULL,
		0xC1B2A944CE558107ULL,
		0xB3713D744E7D5AF8ULL,
		0x4623C4F84CAF5AEEULL,
		0xF3D7F0A7AE0067F2ULL,
		0xBDA8E00B3DBDF3F5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAF40AAEBD8C9E3E3ULL,
		0x33AE68CD4CC55EC2ULL,
		0x326A128046566D74ULL,
		0x70ABD070995117CEULL,
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
		0x40EC22ACA95D58BAULL,
		0xA5E660BE6F7E2F78ULL,
		0x840FA836AAAF0457ULL,
		0x7CAB44C73BC14B49ULL,
		0x6A6A40C46258459CULL,
		0xC241CFDFB0DBB763ULL,
		0x890500CAC0448609ULL,
		0x3413D9998CD38B40ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x73338B9D0DB11D6FULL,
		0x58F240BD1C0EFB09ULL,
		0x822D7A7B0A5F5BD8ULL,
		0x94EC1E6BB2DB6729ULL,
		0x7371A3415F68A02CULL,
		0xF99093A2FF9A259AULL,
		0x2EAF2EA6B4BD6803ULL,
		0xB14D7182388324F3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x769FF8820B3EC719ULL,
		0x17431103A32AD843ULL,
		0x6A9F5F15565E1D5BULL,
		0x513299D20CD5139BULL,
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
		0x88A5D5D2A73E3BC4ULL,
		0x4772031E51CE1E04ULL,
		0x4628F184749D331BULL,
		0x50A6490369F0775CULL,
		0xC60F818BA16B10F4ULL,
		0xB32455C64CC585A4ULL,
		0x0B3FF7D7A9097E83ULL,
		0x8CC5415DFFA5ABD1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1F7FDD5EB72640F1ULL,
		0x8266CE6AEA6EC8B3ULL,
		0xA86FF3A3DB8B9CB9ULL,
		0xC724BE39DF0C95EAULL,
		0xC243ED6732E0720AULL,
		0x543D36297A1BBB7EULL,
		0x531EA9423EF093A5ULL,
		0xC71707845FF868C7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF95DF5DC58AB9026ULL,
		0xDB59E5FAAC9356F5ULL,
		0xF2AAA80E58C47363ULL,
		0x615E21173E9BD4E2ULL,
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
		0x875F60347C657FC5ULL,
		0x0C2C4BFFE213881AULL,
		0x21C12ADD86C7994AULL,
		0xBA9205588DF375C9ULL,
		0xA75ABFE09918966BULL,
		0xE0D40F4C8E2D0EC1ULL,
		0x79071B81BE6AAE3DULL,
		0xEF5341DABCA2B041ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDECC50C01249C4B3ULL,
		0xEDDB7ED9084B9051ULL,
		0x952A3165B2ED32A2ULL,
		0xB2820C7E480AFAE8ULL,
		0x91F6555EC78F71B6ULL,
		0x1C380ED0944A23D5ULL,
		0xACA1692F64E2EF09ULL,
		0x5FB017DD1B3387B9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD57ADEB98477310EULL,
		0x4D78DF8DF176D6D3ULL,
		0xE3AF71B11E00C87CULL,
		0x5A4834803C687F08ULL,
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
		0x04EA31A8C4544B94ULL,
		0xC31C728B80F45D47ULL,
		0x2B928C5860CA44F0ULL,
		0x4AD714BEF4D4AAD0ULL,
		0xEA3766D4BF9BE5FEULL,
		0xC699BD5357B750BFULL,
		0x25DEBDA74D5A0D44ULL,
		0x261F38C30C9E2454ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x28FF52ED7BF78A4CULL,
		0x5F9D641262319926ULL,
		0x55ACFEFA1B353D38ULL,
		0x63D19182BF0C89FFULL,
		0xF9E499C9A7D1FBE3ULL,
		0xBA8B654CFFED36F7ULL,
		0x77ED3BCD56400016ULL,
		0xC96EEBFB1979AFCCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x88354E60D0557DA7ULL,
		0x2DA01F6A26C297CEULL,
		0xA7BED3B8F372FC8EULL,
		0x2930E8EA4D316CF4ULL,
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
		0xA2D462DDD8B859B3ULL,
		0x3F15764C2872F430ULL,
		0x335EACB1A8F37BD0ULL,
		0xD3B8DA6C6A5F1D22ULL,
		0x55CAF9E0C222FC7FULL,
		0x23305FC493260312ULL,
		0xE53C7F944406F8AEULL,
		0x5F03D60FA92DB41AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x624826FB9FD56EF8ULL,
		0xD1AC29F07D2A8E65ULL,
		0x003380CBBEA5FED5ULL,
		0x5B98D2F829A60C87ULL,
		0x01BA29990A923CC4ULL,
		0x95BC2AD937E404AEULL,
		0x2DF93009A8D5B17EULL,
		0x4D246746165EA250ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBB0B2687785F60EFULL,
		0x6CA9274B371428AFULL,
		0x6728FA78F39E0E09ULL,
		0x1F4A79600B75B4B2ULL,
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
		0x05451D6ED0956715ULL,
		0x5449D01CF3E3D1F5ULL,
		0x16F67E634DB7D8BCULL,
		0xED989665B5D40CF4ULL,
		0xDD8F333C585D9971ULL,
		0xA73AD92B1F0C5A46ULL,
		0x8D27E83F01D113F9ULL,
		0xF4C00FEF4892E590ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3B9DC0868933893AULL,
		0x67B59EB49933AF66ULL,
		0xA6729DD75FCFFEB1ULL,
		0xDFD3470B5964E604ULL,
		0x1ABBEF4F4C6F3787ULL,
		0x8AE1B19F96B2AC97ULL,
		0xCA8746A04CE56B60ULL,
		0x17220ACCB12F2712ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB50372180CC46B6AULL,
		0x21D0101E97FFEAA5ULL,
		0x545BDE1AC8E2E0C5ULL,
		0x733A127CD53D6D9AULL,
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
		0x51C31FD4F154D079ULL,
		0x63FDE4D18B8F4084ULL,
		0x0BD55B73BD11DD59ULL,
		0x7BF9B492F210F9B3ULL,
		0x463A2A95DF660233ULL,
		0x55227BD1E46E4FB8ULL,
		0x8F4B582DCBEF48BCULL,
		0x0104600ED31F2E92ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x769EFD7A45E02C7CULL,
		0x6593F17C8A914C40ULL,
		0x5066DCCCC10C963FULL,
		0x18E9E28B62F5352CULL,
		0x9ED636770E408BF9ULL,
		0xF99D2492D671315BULL,
		0xCC97ADCE4AAA2821ULL,
		0x4059064DD9DFFCA9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB3FA5EEDB7042F30ULL,
		0x9434E6B114907604ULL,
		0xA219C8D42C481E03ULL,
		0x7C7F24AC8E7D2D13ULL,
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
		0x388C017C5711B8CAULL,
		0x79BC1AC0DE74DEDCULL,
		0x23612A331E6D1517ULL,
		0xD4BC464C28134ADAULL,
		0xBE109C58F22CB59FULL,
		0xA5E616438B4F7CA7ULL,
		0xF43615B0A4D1F415ULL,
		0x95439D166164E5D5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC96326891CE302BDULL,
		0xBEAF4C0C2AEE15BFULL,
		0xF122BBC041B425ACULL,
		0x2AD2B1F172871334ULL,
		0x8D9F7A7B4FAC2F1DULL,
		0xA1C89498266907A3ULL,
		0x74F9B5AF7DC58170ULL,
		0xAE599F72F4E5B562ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9FF3E1D95942ACD4ULL,
		0x576E0E25ADBC27BBULL,
		0x1534AE9EA891F3E9ULL,
		0x70A53A9CD06D68CAULL,
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
		0xDB31FB13950CA63FULL,
		0x4696CAEE44155991ULL,
		0xE3663E1A35DD5116ULL,
		0x715E491F61B99C78ULL,
		0x53095ECBF05E3ADBULL,
		0xA1AFE918061A53BBULL,
		0x6E051E2FA31D3A9CULL,
		0x2A580E1097959F33ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x496669209D704AB2ULL,
		0xB389A065AAA6AF46ULL,
		0xB9EF7479F3729B19ULL,
		0x17CB8BEE26967B5BULL,
		0x24C0FABF0421E258ULL,
		0xC0F59E193FAFDF50ULL,
		0xE7FDCD60CD384D29ULL,
		0xBC0E40C22D429D41ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x708A6BDE08917BCEULL,
		0xEEB44C5A0D3BF234ULL,
		0x0E8CC8540265F509ULL,
		0x388736D503756AF7ULL,
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
		0xD1BA185080024BB9ULL,
		0x87B74FDD2459EC54ULL,
		0xDE820E5F803D9A7CULL,
		0x45585CB62E1E66DCULL,
		0x94255B079B8C5239ULL,
		0x3C21AAA4E611E310ULL,
		0x62B48AAD0900A529ULL,
		0x9F2707ABFC92ADD2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2CB75AB3151E2381ULL,
		0xF7A4706D2B720F98ULL,
		0x4954BFDE2476F8D4ULL,
		0xA997C3A3F75B6E80ULL,
		0xCF983DA755024070ULL,
		0x56CF0174CE3C7BB5ULL,
		0x90ED811C8E50873BULL,
		0x1F1DD42934C892FEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD1F519E7E362CECDULL,
		0x9A57FC9382953435ULL,
		0xB8B8B9F391EB12F7ULL,
		0x1D1E3E7BDEC2F3CDULL,
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
		0x31CF7949123F30BBULL,
		0x4AB643FAFB22796BULL,
		0x88E73AE8B15BA78CULL,
		0x96EF65EDB8DB1CB0ULL,
		0x5563FACB88773346ULL,
		0xD06B3A0A644DE962ULL,
		0xBBE924F1B23970B9ULL,
		0x36629CFB2B226857ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x444426B5E26DF050ULL,
		0xB6169AA0A2B4F4D8ULL,
		0x29C168535CBA241AULL,
		0x18C1DECD7C78787CULL,
		0xEDC90287BCCB2E25ULL,
		0x0F0F75AC8D50F18CULL,
		0x656F0786149ADF23ULL,
		0x81DE95671B5A53C4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4E8C2CA36B5A01AFULL,
		0x483ECF4841FA4E40ULL,
		0x3546308EBA2B1FD2ULL,
		0x49C6A71A9415B213ULL,
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
		0xF52C1BC21F48D8C4ULL,
		0x56A0D77EC88E162FULL,
		0xF4435CD82FA20FD3ULL,
		0xAC56EC5497991300ULL,
		0x8757D4EC24E9C89AULL,
		0x124A2D02E574A1F7ULL,
		0x05BFFF307E4B78C9ULL,
		0x8E47B718262EF9C4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7FE4E22FBB0EF93DULL,
		0x76D006E31C2A6050ULL,
		0x1D2D2728A3A6D9B2ULL,
		0x045835E207B36520ULL,
		0xD88BD3B199B7C5EDULL,
		0xCF13B82021CF4EC4ULL,
		0x2E08871F48DC6072ULL,
		0x6EFD626B3BD86974ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x678F68430DA645F3ULL,
		0xD9E62A44B6EE0F65ULL,
		0xDC52083D7A78D2EEULL,
		0x4D07481D58BF19BAULL,
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
		0x8CEB7744F5FC89C5ULL,
		0xBADDDA3CAF608F17ULL,
		0xF5B6BBF0756D74DBULL,
		0x793682CFBD387249ULL,
		0x58F5B49411120A02ULL,
		0x8F77D25CD43AE0B7ULL,
		0x6E643404116E7B09ULL,
		0xDDDDD4F89DB39DB9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0548E422C6922714ULL,
		0xBF51B0F122A8D487ULL,
		0x47D3F1CBF9931961ULL,
		0x7B51634F410889B0ULL,
		0xA9C050D7896B40DCULL,
		0x938BC4CD03B94355ULL,
		0xBFD813F618590B98ULL,
		0xE2E0811860C5AAACULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x898F611E522C3E2FULL,
		0x60962CA47FF51710ULL,
		0x96AF8C377508E63FULL,
		0x3F7F92C98781FC7BULL,
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
		0xD0DA7A47F7926813ULL,
		0xBE70A6D42157BAD2ULL,
		0x121E90B5A5F20D75ULL,
		0x4B56291592A51DDBULL,
		0x4DFB3E543C364211ULL,
		0x28D50D010C9442E3ULL,
		0xA9607A7C4362EAC8ULL,
		0xE8BD71FC6BB9D010ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC91091C7BFC9BDEBULL,
		0x1DAB46FC4621E90AULL,
		0x1FB17E24464FA417ULL,
		0x0705B445576475E8ULL,
		0xBF993FA071108049ULL,
		0xA8606E66E9AE7A79ULL,
		0x11812FFC0B547014ULL,
		0xC73A95336EB71F3CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2A55B7305F636E96ULL,
		0xB214EAB909519173ULL,
		0x7D922199B1C8A003ULL,
		0x3DBD3AA5C9A6E781ULL,
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
		0xD22F3AD316924E60ULL,
		0x1F82FA85F93D4D53ULL,
		0x5DFA92E23DED9E9EULL,
		0x13E89641BB1B200AULL,
		0x5BA5778BBFAD8C89ULL,
		0xD82C65A062209105ULL,
		0x2C21252308757398ULL,
		0x3B4D53ADE5C91FC7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD2B47D23CA1E78ADULL,
		0x4FEA87D17B4659A2ULL,
		0x43114D9B90A776DEULL,
		0x61DE85AE7C8C4E4CULL,
		0x8BEFDBD4B9A54035ULL,
		0x7259B1F05CCABE99ULL,
		0xA286C32E0C67B05BULL,
		0x584A808DDCFA79D4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD46FDADA31AF296DULL,
		0xECDF1ED548B42FB1ULL,
		0x87D3CFA4175122DCULL,
		0x647567548D3B73BEULL,
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
		0x42BCDC3BB3BCDE08ULL,
		0x38C87392E49A90C4ULL,
		0x211E3F1B3884A49BULL,
		0x7EEF7A2AA517A624ULL,
		0xB9C016265D06DFEDULL,
		0x32245081F4B7A6F7ULL,
		0xC73946B2FEF6B5A7ULL,
		0x479545E73886C73CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDA101F09F9308078ULL,
		0xCC93FBEEF69FC920ULL,
		0xC925828115FCC9EDULL,
		0x41090C01BE4FF706ULL,
		0x42D39D765075A6E2ULL,
		0xD1AC7C34E219FFC8ULL,
		0x84CB347D7192A389ULL,
		0x5686A22F3D48B8D7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0FC6A753981AD4E6ULL,
		0xBDFDFB14B16198AFULL,
		0x344F708D1F628B09ULL,
		0x0612BB7831FDD225ULL,
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
		0x66AD313A57316D34ULL,
		0x5EA07E41E5BCF8D8ULL,
		0x109BB7E2E4353F4EULL,
		0x71861CEA7C4799CFULL,
		0x8EF168F98C7BEDAAULL,
		0xA6FC3D22171F2781ULL,
		0xD33C7EA8E2BD1261ULL,
		0x4418BA226667E189ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCF0E0457F9A18459ULL,
		0x3E0C94B8CE5FD71EULL,
		0x7AFA6D09382FDE2BULL,
		0xED7EDC1C91833173ULL,
		0x18E04595FAC4995BULL,
		0x966E9819C8156311ULL,
		0x95D67950813741A9ULL,
		0xC26822307B3E2CF7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1E2A6DA9FEC669B0ULL,
		0x959A68C4D2D04A6BULL,
		0xB2C615F825E25C75ULL,
		0x443DCEB6D2F53610ULL,
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
		0x742627EB7DD251EAULL,
		0x19C2F0A3666E6C8DULL,
		0xD16822C35F7E1348ULL,
		0x21091C356A2C06D9ULL,
		0xD3F04566004CB3BAULL,
		0xF6213466A73245ACULL,
		0xC73DE9843E6E9B40ULL,
		0xF8BEC4DBF5E02C9AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2C7B4BB39FBEC65DULL,
		0x102623C4A2E6709AULL,
		0x4AE8AA3658E7BB95ULL,
		0x845E1132505C76A6ULL,
		0x4988CE34A823E256ULL,
		0x3329363C10F43898ULL,
		0x117C20B4BD35BCBFULL,
		0x9C495E3F74E2BF8AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD3068D8AF422A253ULL,
		0xFA6C873110BDECFFULL,
		0x8143475A35075EF5ULL,
		0x5618463E3F6DC0AEULL,
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
		0xCF50EBA3B426ADFDULL,
		0x9F40AA032E2D4DEBULL,
		0xC4AD900C7C3020BFULL,
		0xA4776F5D5E8E3ACAULL,
		0x76C48A89602DC9A7ULL,
		0xA1236EA0AE2E0205ULL,
		0x6FE119DFA0071211ULL,
		0xA5F8F8F12C8D3433ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFAFFF4101C7BC9A3ULL,
		0x64F3DDE7F13B07DDULL,
		0x98B1A706596B40FEULL,
		0x97AC1A9680B0D60BULL,
		0xB1B5AE67077DFD50ULL,
		0xEEB82223D0191E0AULL,
		0x1967D3FF292FAF7FULL,
		0x7F0196B270A6C212ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1485A4ACC1C33A15ULL,
		0xB63A26A4340C1D47ULL,
		0x01FC4857C6BD8161ULL,
		0x5583EA16C21255B2ULL,
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
		0xC0355098FF612627ULL,
		0x0DD6A47391FBF66EULL,
		0x01165943C5ECD2BFULL,
		0x848F40998031055AULL,
		0x4F4B6E3E0D366504ULL,
		0xE1DBD9C0E09B121CULL,
		0x01AA0F1EEFE06BF8ULL,
		0x6D6E11762889E453ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5F7A6BD17FE0F9A7ULL,
		0x80729CD2B3D5BA59ULL,
		0xB4EBCAC225F045D6ULL,
		0xE8ED733B1120BA92ULL,
		0x9C45D340FC39E79EULL,
		0xCFF2DB3F02852614ULL,
		0x507F9E9EF52AD668ULL,
		0x9DD3853B4C1F1C26ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF38FE65804FAC874ULL,
		0x35F9CEE7D5674539ULL,
		0x98774180D6F0C04BULL,
		0x6C929E1B26EA0169ULL,
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
		0x8DA73A38D46A63BBULL,
		0xE1E165A166B65E44ULL,
		0x88CD70BB5DEAC873ULL,
		0x2A1308F6C200F060ULL,
		0xDB70CAD987A12F54ULL,
		0x1279A21406C51D12ULL,
		0x7DAC0A4D8EA2280DULL,
		0xEAB23C308A45DF0DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE7161E894F66E4C0ULL,
		0x741FC049C5FC434DULL,
		0x9DC3A162B17DFE5BULL,
		0xA696FCBFBEBDDD65ULL,
		0x8E9458D7341EACCBULL,
		0xEDA41D4465DCF1B4ULL,
		0xD058B21800BAAEE4ULL,
		0x57C6C8E5D2840DA0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0F4A0807EA62E26FULL,
		0xE5735C2983308AF6ULL,
		0xA568E74BBCC8C60DULL,
		0x526F294E4A08291CULL,
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
		0xAFA78B250AA4C435ULL,
		0x3BA9A4C312D7CBF1ULL,
		0xE414E6048D09788FULL,
		0x8564762C4006D69CULL,
		0x8F1D56BE47042766ULL,
		0x0A7C1EF8D0B77E85ULL,
		0xDB4D39CBB03E87A6ULL,
		0xA062DCF3C2A01D2AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF38A32D1ACE92869ULL,
		0xCEB3B93BB77469D9ULL,
		0x559D2147B7E22929ULL,
		0xE98DCC8BE61CC552ULL,
		0xA24F6A90FACEF03EULL,
		0xF8CE8C35E7A8C3CFULL,
		0x2E2995D5704BC294ULL,
		0xC56B4A48CB232329ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE2AE670CADA1CAD8ULL,
		0x0CB9B475F3931918ULL,
		0x41C21B4A53308FEEULL,
		0x1C966F0116772D8AULL,
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
		0x0427B602EEA49F5FULL,
		0x474B9D3025C1A1B1ULL,
		0x405DF50075672753ULL,
		0x7C51F58D0CE38E3EULL,
		0x9F4C6F58C42D5606ULL,
		0x25D39680CC8C27DDULL,
		0xEB0CC9AA81464D8DULL,
		0x82EE97A16377BDC4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDFA29CC84BB8595BULL,
		0x2A287F1638026A24ULL,
		0x1B6B35A660D38AAEULL,
		0xE410C1D379287545ULL,
		0x2E40252C65B833CAULL,
		0x251EB03103D512C5ULL,
		0x3D1D723917A8E640ULL,
		0x357AA1E227228835ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEC581BD0A84F5C8EULL,
		0x37FD4DF1B8EC592CULL,
		0xF679BA2FC1F0F213ULL,
		0x1777AE1C88610C4CULL,
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
		0x019FCAFEF0CD64DCULL,
		0xD213598F587D452BULL,
		0x741782AC9AF2EAECULL,
		0xF7B8F7661627F55BULL,
		0x74BA5E76C175BC41ULL,
		0x452AB4BD8428FDF6ULL,
		0x8C6A645CD0D534A2ULL,
		0x58499B1BCE56F691ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFAEDB0BD094C7500ULL,
		0x90794FD90A378064ULL,
		0x264AF6C8B9D7851BULL,
		0xAA7E544D1892CADEULL,
		0x2AFC5881F34EC8E4ULL,
		0x098B4DD6CFF6BF3AULL,
		0x52BDBED3A6025D80ULL,
		0x11497539503E18AAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF8E6FC9881491139ULL,
		0x1B434FF50DBB14B8ULL,
		0xDD6D1E403C6754E6ULL,
		0x574042B7B5461ACFULL,
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
		0xDCCDF1154877BC05ULL,
		0x18BDFD0FE347B53FULL,
		0x56D38F1C6CFEF07EULL,
		0x212ADEA4A57BB802ULL,
		0xF11684351CC58DDAULL,
		0x95CBFEF71DA07944ULL,
		0x754BA6588ACC661BULL,
		0x6538680D7065DB79ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1A2D55E62C5FA5CAULL,
		0xAD64AE0A0B748E67ULL,
		0x2BBBD7046C70C697ULL,
		0x0CA230B78D9032E8ULL,
		0x4576C927126DDEB1ULL,
		0xB57DF8CE115A5541ULL,
		0x60AFE71DCD7B827AULL,
		0x66DCD73736B3EEBCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3C565F44A51C163EULL,
		0xB6EE391DAA3C7F64ULL,
		0x3A361AD01A8FF3C7ULL,
		0x56202DB9A854A92BULL,
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
		0x2406F2EF5498EEBDULL,
		0xB93B0A9B3F381446ULL,
		0x82B22BA20B99B074ULL,
		0xD2BABC539DCBDA57ULL,
		0x7121197C16F5DD63ULL,
		0xFDCEB3FAD576D34EULL,
		0x1F2FDFA93698D597ULL,
		0x939E61E131AED948ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x461C732D9E241C35ULL,
		0x6549DEE85F7531C5ULL,
		0xC6C9D03333E1DE5DULL,
		0xD628015B0D240BA4ULL,
		0x57E00507D57ACD39ULL,
		0x58DEB3120914DB7DULL,
		0x33019EA642EF728EULL,
		0x30D4F68380E4ED1AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9D9389036EB93AEBULL,
		0xCF914E41364DAB8AULL,
		0xCAC601DF02DC8585ULL,
		0x2678AAE0CEA0DD83ULL,
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
		0xB2C57CF8A2B59825ULL,
		0x9DC270B16DE9B74DULL,
		0xCEA73331F2912D1BULL,
		0xE66173616129941DULL,
		0x99F745C1258D2804ULL,
		0x8A168C00DAF11275ULL,
		0x6B243555CA554D85ULL,
		0xD69C27E91AA358F3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5D06289970B36137ULL,
		0x34EF432201D901CCULL,
		0x52AEC2A137352D3EULL,
		0xC256A8FC27FB2108ULL,
		0x1C180BE660610647ULL,
		0xF5E4B670C5D02B69ULL,
		0xB3A3C0D2416E285DULL,
		0xA56DD4B292B001CCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x04E1EAD8768F3A06ULL,
		0x6838E0F28EF3015CULL,
		0xB909BC170DAB83BDULL,
		0x70EB247D674D62D4ULL,
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
		0x6DE35ADB86F5E05DULL,
		0x07981DE72F7D5183ULL,
		0xD3C564DB3E39E052ULL,
		0xAA4BD660BDAC8B19ULL,
		0x3DBDB19A070A6F8DULL,
		0x91EE10CE423AA140ULL,
		0xDD5E0E50E802160DULL,
		0x6E090C99C7447429ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6A68664C44F4627DULL,
		0x651DAD67F21B277FULL,
		0xB14D99EAA1D2C9D0ULL,
		0x03E3E09ADEBF450CULL,
		0x96A20675624D1BC5ULL,
		0x1153CD3CF33AA0E4ULL,
		0x3A410EB8B1706930ULL,
		0x86FE154B3AF90B50ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD1965BFFB61BED0BULL,
		0xB9607810F762379EULL,
		0x58C5BB88B606BF62ULL,
		0x7208AB6EB21ED65BULL,
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
		0xB9160C73EDF229C7ULL,
		0xE90B2B3527DEC629ULL,
		0x39E6108B338201ADULL,
		0xB92DD02E20EB601DULL,
		0x1F0D25C3B3BA1EA1ULL,
		0x76D32DE0BF3DA6A8ULL,
		0xD2AA114A982979B5ULL,
		0xA2162FF988568C9BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC86B68F0C7C0F03EULL,
		0xA889C888C1B0AAD6ULL,
		0x51B51204D4B3AF69ULL,
		0x02D7DFC0EFAA3AC4ULL,
		0x9413119BFA43617EULL,
		0xA7E119C8761385F3ULL,
		0x7DAB44FD143D0E0CULL,
		0x17AA2CC6B0951692ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x91C9A168ADD14FD9ULL,
		0xF8705E47426EF61FULL,
		0x86035207F3E64D52ULL,
		0x425E69F937F8AABBULL,
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
		0x588C8129A208AEDBULL,
		0xF090653F1E9A3B76ULL,
		0x4E26922AC9C7937FULL,
		0x2D7A57CC37430451ULL,
		0x023C705D688BC855ULL,
		0xF6D3D467A0408C63ULL,
		0x4464EE48EE4BC84AULL,
		0xC1DCCAB1BA8BF468ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBC1EE10F21A0D855ULL,
		0x415C3FC6E0E70701ULL,
		0x2C96D7C2537727D5ULL,
		0x983448FA521501FBULL,
		0x0A2AADFD0E0C83F6ULL,
		0xADEB8205D9AB4DB5ULL,
		0x9DB901D15B7948EEULL,
		0xB9C4397E06D788B2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6F107A67EF4BFCB3ULL,
		0x81B05FFBB7DA8247ULL,
		0xDF14D428418F535DULL,
		0x48EB9C7E91F5FF4CULL,
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
		0xA85FF8903206032DULL,
		0xF61531F0FD5F7470ULL,
		0x7C8EF26F1B375585ULL,
		0xF442140B446C8D2EULL,
		0x0D83AEDEA7DC77E4ULL,
		0x9A9BE6F818619B2EULL,
		0x91CE43CFCDAAEA1CULL,
		0x3C06259D84F64F0BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2098DE246CD44F77ULL,
		0x65DE95B0C3C33C5BULL,
		0x6915EF16356C43B9ULL,
		0x9FA30456EFF243DBULL,
		0xD1ED491D8F454A57ULL,
		0x6DA72833707AC74DULL,
		0xF6972DCCBBCCB622ULL,
		0x29D7BD4336B75D54ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x601A35156BA27716ULL,
		0x3C8AED7125DFAB5EULL,
		0x1DA647CD8CC6C8EFULL,
		0x07828D1BF1D22A6EULL,
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
		0x6FF77075679F6DB9ULL,
		0x93D753C9EDE1E731ULL,
		0x5FA0CC292D9CB0F9ULL,
		0x373AA2061AA4DAF3ULL,
		0xDCFEDDB1524A3833ULL,
		0xB9A2ACE1BD384552ULL,
		0x7E2C32E68C8A0D15ULL,
		0x3C6E3D6E2E0DCCA5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1C03568E407CC9E3ULL,
		0x92548BC19A91782BULL,
		0x64ABDAD3B67B38FDULL,
		0x13AD1A8AC725DA5BULL,
		0x82191796B75EFC60ULL,
		0x3C0CBE008E167DD3ULL,
		0xB09B60529D63ADACULL,
		0xC61172B19B55960AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD20F81DA260D821DULL,
		0xA5C43D7552540BEDULL,
		0x7E74334AF6D3A1A4ULL,
		0x35539F791AD71B92ULL,
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
		0xF1C498377AA01A6FULL,
		0x3A57D28532D0B1AFULL,
		0x26E22249CA0214B1ULL,
		0x55C53720B8E5F0E1ULL,
		0x7F6B0FE20B293D57ULL,
		0xC235DA5DB801AA63ULL,
		0xD786DAB577C706C5ULL,
		0x67ACB6E1DF335ADCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD45BEDFFC25B26C5ULL,
		0xD5453CA974844C83ULL,
		0x0AF631D58AF7068EULL,
		0x24F26D5E98C75922ULL,
		0x1C988BE198F619A9ULL,
		0xBD75AE3209D02D76ULL,
		0x36870C6679D6FAD1ULL,
		0xCA37BDF4FE69BEDFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC8A84248ABDC3D57ULL,
		0x1999245799A4F068ULL,
		0x01E4902DF0ACD45BULL,
		0x102FBCEB7E0BBF65ULL,
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
		0x28BE1BCD2BC98995ULL,
		0xEC03304AE47BD3AAULL,
		0xCF5F83B81B3F9A62ULL,
		0x8C225DF1DBCE0FB9ULL,
		0xC02298D6992ABF71ULL,
		0x4D88CE6C459BB169ULL,
		0x3E0EAD426B0889B0ULL,
		0x6CB730DFBE06CE3AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD82894DF312A65B3ULL,
		0x3FD33614ACF63E81ULL,
		0x02EFB767926E3C8DULL,
		0xCD8B9AA046C8CF7FULL,
		0xDC77CF2488241C32ULL,
		0x61F52AE98C38DA72ULL,
		0x438641AFC4528221ULL,
		0xCF24F31345156973ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1BEF775C819B5D02ULL,
		0xA41A3F9DBC317DCEULL,
		0xFCAFC41547D67D0CULL,
		0x224BEFAB88DA35C3ULL,
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
		0x06DF7BAEFF929699ULL,
		0xC55B440D51608B64ULL,
		0x11EDDA19F42CA7C7ULL,
		0x8B6BBA6158F91093ULL,
		0x7F03A7A7874E31E7ULL,
		0x084E303422047B40ULL,
		0x8A3A59FC3FBA5055ULL,
		0xB28D601D80998F55ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x04DB68BF780F644EULL,
		0x41E01AE533D09876ULL,
		0x8A2A86839C621560ULL,
		0x8CDA8FC4194991B3ULL,
		0x593ADD807CE2A32AULL,
		0x4AD8506DF77426F2ULL,
		0x98D6BBD10023C56BULL,
		0x7C50DD2B61C97B9BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9DD214BB137A6389ULL,
		0xA2FA60926EFC7687ULL,
		0x5C8CCE01C8233119ULL,
		0x0B8C9A8DD2926C79ULL,
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
		0x486FEC76D1F5B49AULL,
		0xC9DDB74C6C7DFB0EULL,
		0xAE660D4D710B0359ULL,
		0x276A156100DDAFA1ULL,
		0xEA96E0A54BC26F2AULL,
		0x8567C0E90CB4ECA7ULL,
		0x730F5A6FE4B9E049ULL,
		0x3197D3A6D9DEE92DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5DDD94E2C34D5072ULL,
		0xC61596E391E39AF9ULL,
		0x354661040A2025C9ULL,
		0xFF96BAB300AAE205ULL,
		0x23E4897485512696ULL,
		0x9866DD1029130F76ULL,
		0x0D9E6318A1CE001FULL,
		0x67D3E3AFD651CC7FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x690B48D1837928CAULL,
		0x31E9F29AA4A13578ULL,
		0x87E4633D55EE23C9ULL,
		0x1AE8F95887250F7FULL,
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
		0xF3B521179B0ED6D7ULL,
		0x2DA76D20EDDA3307ULL,
		0xCC1034D423933EBCULL,
		0xD2FDBEC4E5C7630BULL,
		0xE654DD9E0BF03E80ULL,
		0xF526F3853408BA98ULL,
		0x955B943936CBAF7BULL,
		0xBCD20B6A149FCD21ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5CF667B5EA8DE003ULL,
		0xB16D2EA4277E49F9ULL,
		0x6528E992A9193E0BULL,
		0xC3CEC726E71274E7ULL,
		0x2C89E525F80ABEA8ULL,
		0x256802CB9D57B4D5ULL,
		0x8B232966B0D65FA7ULL,
		0x81F5B75D953BCC4BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2ADF9B34A491F227ULL,
		0x5291FA0924A2C41CULL,
		0xEB4726815CE3DA47ULL,
		0x4BE37178E78D0DE9ULL,
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
		0xA9F972E160A242C8ULL,
		0x4F7976ED057654F4ULL,
		0x74DABE403BA77461ULL,
		0xEF4E4C7DABA317CFULL,
		0x44359A2ABDAA6CC4ULL,
		0x38853002FCA1B6C8ULL,
		0xEAC4DA5E7BCA6CB0ULL,
		0x74BB6C6B802BE0CBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8AF8F7B80796E2EBULL,
		0x173DD7DD18E03E8DULL,
		0x091E60185120AE50ULL,
		0x1DEC1D0684EACB94ULL,
		0x031E0DA79ECC0035ULL,
		0xED571E927E057202ULL,
		0x72A5C93BB04CF9A6ULL,
		0x276E7B143495C231ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC87F569FEE0F7EDFULL,
		0x611235C2B7C84BD4ULL,
		0x4058E9521F25D972ULL,
		0x4ACE026C5F00D729ULL,
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
		0x4B534E6D1A33FA72ULL,
		0x9983D06CFAE5AA6BULL,
		0x0B4F590040C7F3ACULL,
		0xF37178C579160B87ULL,
		0x06349C9843120A80ULL,
		0xA9709967CED204B3ULL,
		0x928D0D62258C60BEULL,
		0xDD5DC85F95D3EA8DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5AD3E9D39103BC27ULL,
		0xD183ED7E39F3FB43ULL,
		0xB8C4B795D4C4DCF5ULL,
		0x1EFFC4F1C068965AULL,
		0xC731968A8F3AF288ULL,
		0xB82102F65985955BULL,
		0x4D7C8671D3DC8C14ULL,
		0x25F6C566E1BF7073ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4AF24AA23B1DD143ULL,
		0x99D037C62A4A361BULL,
		0x92FEA9168C1CA7F0ULL,
		0x0DBC24BE73B79512ULL,
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
		0x06AE5322297A8CA4ULL,
		0x40ADCF70FA64C702ULL,
		0xAA1EFC71D8351DB7ULL,
		0xB718C3BF6C33239CULL,
		0x608258E2E9ECDFE2ULL,
		0x36D9DA7323E64E09ULL,
		0xBA9C451491DEF14FULL,
		0xB1DDC11AD92D3C7CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x42D806127DCB08CEULL,
		0x729BD078AB627F7EULL,
		0x6513C5DFC01D61AAULL,
		0x1D108929CC88A763ULL,
		0x9FC7DE7312F2BDDFULL,
		0xD69393EB229E9F00ULL,
		0x0F62625D050FCE97ULL,
		0xF2C1C7D821067A29ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5F8479A994D08EDFULL,
		0x188077287FA642D0ULL,
		0xAFA2DDD0FED6E345ULL,
		0x782F3A7CF56B54A4ULL,
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
		0x6F5C7A4265855A00ULL,
		0x4CD1AD18B75CC8C0ULL,
		0x85FAD766CA2C31A9ULL,
		0xCD3E5B4D0BB427AAULL,
		0xFF72623780DC2428ULL,
		0x8BADDC350E76927BULL,
		0x86C3FD7F01F03F6CULL,
		0x56C015C506DCF733ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9BD671EC03DB9618ULL,
		0x610A5854B951F8F2ULL,
		0x0A6871281C08AA17ULL,
		0x288D00A6566C7A81ULL,
		0xED3968D7CFFA9797ULL,
		0x9326D22FAC796066ULL,
		0x901AAB3BC4DF0A82ULL,
		0xAE7A6DC2DE83B2C8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x87FB0C8AA3249F93ULL,
		0xCFD2D19089A03EEEULL,
		0x18B49C39BEB1624CULL,
		0x1F084AF8B287D50AULL,
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
		0x25218735B99D54F0ULL,
		0xD0505E08852DF453ULL,
		0x1EE626E6A711C1CDULL,
		0xDAD8CA7CC9025126ULL,
		0x74064FFE430A4F61ULL,
		0x903F2FB15072016DULL,
		0x3F3DACBEA6686B12ULL,
		0x272AECC3C52DFA65ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x977B4E8D184E136DULL,
		0xDD7ED097A6654E9FULL,
		0xC04A23934D98EDA4ULL,
		0x3AEA3B4D61DEE3E6ULL,
		0xDDED422C16FE8533ULL,
		0x757137E98B3BE98FULL,
		0x7C73B2FF200B1771ULL,
		0xBC5F57A74FD49B6AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD55E45DB2B0F4113ULL,
		0xED64551824D03097ULL,
		0x489715C14B533E12ULL,
		0x7A26B168D2678678ULL,
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
		0xE351602F22325DB1ULL,
		0x6048753838F64685ULL,
		0xAAA29EFE0EC0EC2AULL,
		0xDAE415F0C01509DCULL,
		0x2CACF4EC8FE6EA3AULL,
		0x57C1A436AF9DE32EULL,
		0xE2A0CA9C7BD8F280ULL,
		0x43AC7C3BAFD26453ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEA6AD41308C970DBULL,
		0x018A12EBA0542193ULL,
		0x61A3BF49E8CBEB7AULL,
		0x3DB5EB227BC3FCD2ULL,
		0x0EB9B2FFB68F345AULL,
		0xD0C963326FC6919CULL,
		0xD516C6BC359F2B80ULL,
		0x422C778EF8E7B6BDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6B0255445C6DEC29ULL,
		0x679808EE129840A2ULL,
		0x4B7B72FE92888A9EULL,
		0x562EDC716B26D150ULL,
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
		0x89C202AFE28B9E5EULL,
		0xF00E4020D89C285FULL,
		0xE95D68DB426E264CULL,
		0x53D1757714E1BDD1ULL,
		0xCAFF3F6623ACFEEDULL,
		0xC66137E435974DC4ULL,
		0x322B614B72BAE5D2ULL,
		0x4D5662909ACA280BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB0708E2444D39F81ULL,
		0x80CF2A3A7429598DULL,
		0xF0F134FDC99272F1ULL,
		0xE839F3F694A6A068ULL,
		0x4B4EBCAF21926DCDULL,
		0xED44B1AFFCB0647BULL,
		0xB4C2D049AACE59B1ULL,
		0x237EB963DD23A1F1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCD84DBB5EDA98A6EULL,
		0xA97B01A6D6B96FBAULL,
		0x95F1BA2125F8803BULL,
		0x219A9E24A6F30531ULL,
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
		0x2B405C4102AB0EBBULL,
		0xE4C84DD7683BBB47ULL,
		0x0E18EAA056EEDB51ULL,
		0xB1EBB36730C5350DULL,
		0x85C3511CD997E5AEULL,
		0x5B2911BFB8732273ULL,
		0x994C1A3B3202E0F5ULL,
		0xC54FAF55A77E85F5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6B8DB7E69D0CC3DBULL,
		0x6691D22ABC83D94FULL,
		0x03317AE291FD6037ULL,
		0xB98298DE1E7059F9ULL,
		0xE1B5850A5183B9A5ULL,
		0x54AE72F524815559ULL,
		0xEBAD8070A8E406A1ULL,
		0x84698471D7497316ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x19BEEF1A989CD59FULL,
		0x746A0DBEA19C53C6ULL,
		0xD07243CE1F85E393ULL,
		0x1A937859FA35A821ULL,
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
		0xFFB4B2BC635401DBULL,
		0xED4DF2F6A28ED531ULL,
		0x9DC37BDD6CB8225EULL,
		0xD70E46E4A4B3D108ULL,
		0xB035CC1AD14DAF76ULL,
		0xADE8AD6426AF7660ULL,
		0x925DC88853D55953ULL,
		0x105940C695CA13DBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x06C7E0DA41EFA1DEULL,
		0xDB266BB153934505ULL,
		0x001006D091A3AA0AULL,
		0x9DCCF28D7E857F83ULL,
		0x52AFE5868C9A665CULL,
		0xC6061B4FFDE87F7FULL,
		0xCC122BD3099CD7EFULL,
		0xD743577EDB2E0292ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDACD0BE454013578ULL,
		0x7DC936435C8435A0ULL,
		0x0CECB7F5DF77AD28ULL,
		0x3281F4FCD958E253ULL,
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
		0xC22F94CA5649EB50ULL,
		0xA38422A28498BB38ULL,
		0xD0F1B115BF0916CEULL,
		0x4ACD56AF82A35ECEULL,
		0x205BCD817D28F7CCULL,
		0x9190DC7E46470F65ULL,
		0x08BE0E6F1F3268DAULL,
		0x29AC47A3937555ACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC18C827A800276EBULL,
		0xC2D8A5E4B70BEEEFULL,
		0x76D006AB11FD6707ULL,
		0x955B721C48EFC955ULL,
		0xA2DB40D9D155FFBDULL,
		0xAA60A4BD66DD5589ULL,
		0x3D18C61D332C5D43ULL,
		0xFEF24C817C54835EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA1B7F333579841DFULL,
		0x31D3C35EF73E62DDULL,
		0x94AA6693B5F1682DULL,
		0x0D0D2BA2A892CD05ULL,
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
		0xDE32411117AEBACCULL,
		0x4BE5484A0F672AA1ULL,
		0x93F3707A61693A1AULL,
		0x3CD80D76F147BF85ULL,
		0x4E54A50E790EACF5ULL,
		0x09E2A8986B25CE7FULL,
		0xBA73440D8BC52247ULL,
		0x0A72ED588967FBFDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x966B1438938DE4B7ULL,
		0x7289FDAAF40F1D44ULL,
		0x5A7888A23744BC78ULL,
		0x3A9B5E1D6BB79C89ULL,
		0x6189CA0B8EE6C10BULL,
		0x1D06947E39F65C9BULL,
		0xDF1EDF318E43CFB0ULL,
		0xDA761C4FAEA883F2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6DE3AF47460DD637ULL,
		0x020646826862F532ULL,
		0xC801E07FCB56C009ULL,
		0x21C3B6A9FDFBF498ULL,
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
		0xEC05DFB4D052FB95ULL,
		0x9877A0E849E158B8ULL,
		0x533188C37D7CFF1FULL,
		0x1C4CEC24410B3DEDULL,
		0x39F49CE0890A9C92ULL,
		0x6F4EA131A9B397F7ULL,
		0x2CC85B91D3BB5B53ULL,
		0x04C7E19CCDFEB01EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x19DEE731B71385B0ULL,
		0xFAD36F846F24B68DULL,
		0x9C66849FC7A852A8ULL,
		0xDBAFC99B62BA20E6ULL,
		0xE18AAD0ABCAFE50AULL,
		0x165F08F7325D9949ULL,
		0x9AB43009A56E82ADULL,
		0x5969993E3B43BDCFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF1E0923F6EB6B214ULL,
		0xD134CA1191806FE6ULL,
		0x65C97A5A953CD527ULL,
		0x309BE092A61114B0ULL,
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
		0x44214A0B8B513D7AULL,
		0x8F967A1534DF260FULL,
		0xFFB9A069875EDBD6ULL,
		0xB86469B092B2B674ULL,
		0x34A00997C848AC3FULL,
		0xA74C430840714F63ULL,
		0xE29280673D1D6E1FULL,
		0x516096F83D7AD4DFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4F21457519C9C98CULL,
		0x3BCA85BFB0B9FB84ULL,
		0x6CCAA4A799013A26ULL,
		0x03FC0F373BEAB977ULL,
		0x0094611CDFB52B93ULL,
		0x533AE945E90D2BA3ULL,
		0xA56A99ACBCFBC0B1ULL,
		0x323AC581D17D5311ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAEBB06D4F76C8E34ULL,
		0xCE5F472E7D027912ULL,
		0xA6DB3B70F35D6010ULL,
		0x5405720D5E69419AULL,
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
		0x5BEC10EA51228C30ULL,
		0xDEC05BF4FE080F24ULL,
		0x9C39F9ECB2B35753ULL,
		0xC3300611FCB56A18ULL,
		0x79AD6AA2A7F09C43ULL,
		0xB44C833D85CE8DDDULL,
		0x2470FD8147BB790AULL,
		0x57A0433BD7F870D0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9C8722B582ED4DF7ULL,
		0xED4A8DA890BF763DULL,
		0x9E9ACCC58E2D695AULL,
		0x2D1D55C22DC0269DULL,
		0xECB25B2A7FDA96B9ULL,
		0xA8087570656891A6ULL,
		0x5EC7E6F5D54BF4D8ULL,
		0x896095EDA6EE873FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xACA93A0AC17A0FABULL,
		0xC38FDABF3C6C08FFULL,
		0x54B885DA21138D66ULL,
		0x338669EB166DEEF8ULL,
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
		0xA887C75667B5F89AULL,
		0xA746D5B19C73940AULL,
		0xE5EF097BB681C68DULL,
		0x420B2E3AA704EA54ULL,
		0x9586F3BF61102EEAULL,
		0x6426E7F178026C15ULL,
		0x0B031649BC8E313CULL,
		0x933BDB18F2B3224AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3CF74C130E50A916ULL,
		0xCE0E3D0A18D2723AULL,
		0x8368D890195AE2EBULL,
		0xD4D97EB95F6F793DULL,
		0x769F6C7A939F0F9CULL,
		0xDCE75A665E9E6071ULL,
		0x4A19693E465E5B13ULL,
		0x531D87B6B2858933ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x01EE8F79D82FF65BULL,
		0xECA79B4D487ADC2DULL,
		0x0535E09F2840ADA5ULL,
		0x71B21016CE5A2A78ULL,
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
		0x72F4CF611B1A4869ULL,
		0xFBF3992B39628686ULL,
		0x38B4FDBF74D8049AULL,
		0x72E38A4B03733681ULL,
		0x5D19B8637253C2D3ULL,
		0x7627DDFE37C5C7A1ULL,
		0x23AAC6C312973591ULL,
		0x3A40FB45214D35B1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x46EF2A01C36D79FCULL,
		0xE5649AA3740559BDULL,
		0x0FBE1E2BF3993C7AULL,
		0x79C0B04F651EB24AULL,
		0xAD2E6FE772DE7B8CULL,
		0x157A551D75EC32CBULL,
		0xCE374F955E20A785ULL,
		0x0D286B3700ABC39DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x48F267C7431563EEULL,
		0x70514FE48BA94481ULL,
		0xD81A905C4AD7DDF6ULL,
		0x2AC83C14764B7315ULL,
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
		0x2BE0597F740341FDULL,
		0x8DB9D427138757F6ULL,
		0x3FEFEBC3E5CD33DCULL,
		0x344507C0769BB384ULL,
		0x8A1FA816CBFBB2C2ULL,
		0x61BCC433B30AD494ULL,
		0x04057B27BF419360ULL,
		0x844467F986D95808ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCDE24097BAC06EF5ULL,
		0x270F234E2CC58894ULL,
		0x60C184424708546AULL,
		0x7948AD79C7A36427ULL,
		0xFEDD8D798CAADDC6ULL,
		0xD4E94886CEA55430ULL,
		0xC1EFD73C2C8FD73CULL,
		0x1AA8DB44344108EAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x09CE0C3F1F4272AAULL,
		0x4E0F0C82CDD2DE28ULL,
		0xAE64BC796526CCB9ULL,
		0x68133D30F1940DB4ULL,
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
		0x63E4EE73C5CF0CACULL,
		0x308463731C25743AULL,
		0x175C6A56EA00EB10ULL,
		0x42FE6876F0C9D931ULL,
		0x01393284D1A57488ULL,
		0xBD60D2D67A5FFC33ULL,
		0x906ECC501433512CULL,
		0x92E928F6F6A7DB96ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF27D3173A7785070ULL,
		0x8DD6086C98E867A3ULL,
		0x66A15EED82E53771ULL,
		0x5CDC39BAA1D2CBE1ULL,
		0x84A7B008871E07B2ULL,
		0x47D1663581ACEC08ULL,
		0x7AE77772A238A5F8ULL,
		0x8842A3699188DD35ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEF011B732E70E426ULL,
		0x15F87AEB6DD172E4ULL,
		0xE2D1A44852511D68ULL,
		0x7ADA01B95190CFB8ULL,
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
		0xE9DB4D2EAA6A93AFULL,
		0x0FC57AD95A1DB666ULL,
		0xEACAFDECCABE0039ULL,
		0x97A436C8C851A3CAULL,
		0x354EEEE59C556FD5ULL,
		0xC86E81FD054222EAULL,
		0x32C9151CD3697EF1ULL,
		0x458103D7E2DE9EF1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDA1258D46E6CB945ULL,
		0x67563E8DF8038880ULL,
		0x9619397F7B755D3AULL,
		0x10576469B24C5117ULL,
		0x7D75CD11A32CD988ULL,
		0x5AD5C8F928BFA339ULL,
		0xD4769009DCDE0328ULL,
		0x162A6B2C256CD6DDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5A03F9D138042AF5ULL,
		0xED1AB2DE1D792221ULL,
		0x54F1853DE7FD02E4ULL,
		0x0E277BDD34E90593ULL,
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
		0x13BA4B2B6E671579ULL,
		0x6C536A95312DCAD9ULL,
		0xF094594C8F26E1EFULL,
		0x94146298237BAACDULL,
		0x3F8934FAB69E64E3ULL,
		0x6DC7D815CFFE35DEULL,
		0x354FC7EE83CAC81AULL,
		0x80EE5413E8090600ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF5E651252419184AULL,
		0x4FB0415618905ADDULL,
		0x88B302D5B93EA180ULL,
		0x1CA286507284C5BBULL,
		0x3EA004D5E8A329EEULL,
		0x1817E693D3E48CE0ULL,
		0x2780E8209930FB8BULL,
		0x43C1CF78A779C8FEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x40711F7CDD98BEF6ULL,
		0xD4C1028A846C85AFULL,
		0x74968F07A8BC9DB5ULL,
		0x0C0D8B534639F360ULL,
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
		0x562A63DEFEF07100ULL,
		0xCB0326FDAAD00E32ULL,
		0x1E21BEB0B139FBF9ULL,
		0x56AC1C17B7BEA49CULL,
		0x515262298BAB77F1ULL,
		0x305C4B7BAAE50A0EULL,
		0x5324CFA4DB241900ULL,
		0x0865A9028D9D70A7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE7D68232976F735AULL,
		0x2684052A80D88CE3ULL,
		0x6953E76EE3D6C448ULL,
		0x9EB8A41493FE1449ULL,
		0x74784AB039BFCEC6ULL,
		0x76BC200702D16B6CULL,
		0x171F3687E9494BBDULL,
		0x943111752B94EA13ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x36B35DAE907C16D7ULL,
		0x324595241CE10D55ULL,
		0x9DA2918DB3DDAF99ULL,
		0x77C1F6FFB1048A53ULL,
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
		0x55FA2CA5ACDA8948ULL,
		0x4743200C2BC9C101ULL,
		0xD0F81141EE612674ULL,
		0x09EDD075BC5FB619ULL,
		0xAFA265602216BAA6ULL,
		0x8ABC50B04A6487DEULL,
		0xE3D53EA77BCE1E73ULL,
		0xA3EF4919CFA45A95ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x72D73A5E4CEC2EB6ULL,
		0x5B3C45100C0367BBULL,
		0xF775F19B9EA2E734ULL,
		0x2F2F0CB3C7A4741CULL,
		0x93385550C1560DB7ULL,
		0x0153D8FA89330628ULL,
		0xB057F3187F30C241ULL,
		0x99068A1B1BBD310FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1AE1548FBC880632ULL,
		0x51889FF6CD1F9A4EULL,
		0x7E1B56DFCF19EEC0ULL,
		0x794B1D90A90B6BE8ULL,
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
		0x93D5C234A94C73B9ULL,
		0x9D258870269F4939ULL,
		0x29812D97BE3CC397ULL,
		0xF6CCD527BB48F773ULL,
		0x21F53C33F702875AULL,
		0xD8537AB9A6C488ECULL,
		0xF3DED7935C861CCFULL,
		0xE1C205FDEB7D5F1CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x97860F4897A64B03ULL,
		0x073301FA000323C3ULL,
		0x2E11F912B139BDB1ULL,
		0xA7AA0EB9A3BE6ADDULL,
		0x8BFCB88188FD49CEULL,
		0x8F201F7BBB514A04ULL,
		0xEF8B4E10F49C862CULL,
		0x501C56FD260764B8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3F333F68666D4EAFULL,
		0x739211A719B77BD6ULL,
		0x9FD59DE079AF6223ULL,
		0x6DBAC08B670DB76EULL,
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
		0x4C4A127627503A00ULL,
		0x13386BF96D7856A8ULL,
		0x51EF3461D2B83270ULL,
		0x17886539F54B9B50ULL,
		0x0AB955302E4F0227ULL,
		0xC53B61E88688BCC9ULL,
		0x77E37F1A60ADB864ULL,
		0x936FF5A9C58B0E59ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7273CBAE1EAA87F2ULL,
		0x3162985966736F7AULL,
		0x3A95E53334441B91ULL,
		0x7FE8E80AA4BE980EULL,
		0x910E07741437ADC0ULL,
		0x48B6ED8546A04ADCULL,
		0xA7D73732FCE0F547ULL,
		0x62FA46D7C64B8BA3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE943D0B3E81C3A4FULL,
		0x5D7F1A5B8385D047ULL,
		0xF92BFB876ED90D3FULL,
		0x4917705B33FA6A3EULL,
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
		0x74B53F9D5103E727ULL,
		0x62496AAC069FDFADULL,
		0xD6547F2E19FE6C3CULL,
		0x63EEA82DB383D1C0ULL,
		0x8AFE525C5AE7B653ULL,
		0xA87E9987F161DC8BULL,
		0x5EF2B4971CC2BBCBULL,
		0x8830E4BB857E99C0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC1ED0B517BB84618ULL,
		0x60C9A7984A9F60FEULL,
		0x735340A8A7C16BB7ULL,
		0xB9CC0D9A10BC4ED2ULL,
		0x8791E31CEA3386A3ULL,
		0x798553AF556592B7ULL,
		0xE1B69A1DAFC2CECBULL,
		0x4BFBEBF526297C23ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x34E0B7B6900AB672ULL,
		0xFA80213AE3737427ULL,
		0xF9ED2C8BA03A2E8BULL,
		0x19FF8805C969E828ULL,
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
		0x9B4E6F8ED1402A9FULL,
		0xC928E6921D2F8F36ULL,
		0xD793B9DD0D2D1A8AULL,
		0x12C833D1BBE9417CULL,
		0xDA9E0E46B13D92B0ULL,
		0x1373C6AFA54F04BBULL,
		0x8735327CFD51F95EULL,
		0x4F2E62D7ACE61F54ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBD014F738F5AEA9EULL,
		0xB62954B6634C1CB5ULL,
		0xF6794F2A7E9DF9B1ULL,
		0xF7D204900C590106ULL,
		0x2F37DE591AC0C8E5ULL,
		0xD05931A254FD3E34ULL,
		0xA7748BD7794DFFF6ULL,
		0x7F38E1CBF1505EF3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4F783D5F986B32E0ULL,
		0x08F1B1D5A606EAA4ULL,
		0x17B327442726262DULL,
		0x796756FF87CACED7ULL,
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
		0x5D096B472FF526BCULL,
		0x481B39EC3B481079ULL,
		0xEC591A2D62E0C35DULL,
		0xB05794A73649E4EFULL,
		0xA06CD263C29C1FF0ULL,
		0x70BEF923957ECF74ULL,
		0xB2E3ED85B9D9C2DBULL,
		0x03094B6290E5D283ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC13B79E18A44126DULL,
		0x6C3B80FE5A2494DAULL,
		0xBBF5A39A350E8945ULL,
		0x7B2D28215B653BE4ULL,
		0x0AF1B118715C48D1ULL,
		0xE40D61BF21B4A2A6ULL,
		0x59B9F0E2A50C240AULL,
		0xE12D6689AE5B0583ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCC14E293B52AFE03ULL,
		0xBE3C31D711262248ULL,
		0x6C9EF6C84457CD0CULL,
		0x3BCE64B77B7F1718ULL,
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
		0xD246C20FFC75691FULL,
		0x8289097350CA4FFDULL,
		0xD67CD222B1763BD7ULL,
		0xD2ECB1E7B2809B0BULL,
		0x7FF004F34A800CEBULL,
		0xAA7098826281823AULL,
		0x5F68A50F05557BECULL,
		0xD9CD54BD8318CDDFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3614440C46C8F837ULL,
		0x7AAADDDACAD0343DULL,
		0x75A591E7398C12B2ULL,
		0x83D4ADD348559B84ULL,
		0xDFC43D2B14B3F894ULL,
		0x1CA9DD9923B61891ULL,
		0xBD0382C50AAE5383ULL,
		0x1CA8321EA2BC836FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x62B225BBB1F779FAULL,
		0x135DEA37D82BCAC8ULL,
		0x7BDA5736ACBA28D0ULL,
		0x629B27A9B7DE0C19ULL,
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
		0x6AE50AFF7294A790ULL,
		0x557EBDD9B8A3BDA4ULL,
		0xCFDB4094F558E7AEULL,
		0x93F0472D35E02BDBULL,
		0x40AA8866FD995E86ULL,
		0x7C4772BFFF1DC92EULL,
		0x5BF8789C2EDB89DCULL,
		0xFF3725E53AFCE477ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF118C8FCFBE50F82ULL,
		0x81FC153D7A7F4A9CULL,
		0xA2163FC4AD9FA758ULL,
		0x2B7D9F8004D020ACULL,
		0x10AF26EDED128540ULL,
		0x0B879841C10E9AFFULL,
		0x2785E97D677AAB29ULL,
		0x32C1E288FEA7B1E3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x991CB9FAEAB3DCF9ULL,
		0x8FFD175974654E08ULL,
		0xF6C63F61E01A4EF8ULL,
		0x41DAA75E25B58D2EULL,
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
		0x4F0679BE243A7E06ULL,
		0x79397F517891791EULL,
		0x6D1BEFEF2275535AULL,
		0x530BB06704C78064ULL,
		0x4F7161E202B07FE5ULL,
		0xF0231B1F8E50701BULL,
		0xB90324B1471F35E4ULL,
		0x79AA23D748A70A5AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9D488A2DD57AE034ULL,
		0x4B8D286052468885ULL,
		0x173D92E68C9E824DULL,
		0x2AFC3AD2F9C0FA2FULL,
		0xEFFE6B5FFBE846A8ULL,
		0x8C62E5329A56B9FFULL,
		0x31FE3834CD7B1828ULL,
		0xE06776380505EE59ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDCCE86DD50781A93ULL,
		0xFC34581D5D5BF8A8ULL,
		0x60997782A4333B03ULL,
		0x67F53B3814F0AE6FULL,
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
		0xE54620C28E4EA630ULL,
		0x2E6DFD929668D7E4ULL,
		0x130A9306B1596F2CULL,
		0xCC0F68040F89C848ULL,
		0xB0599AE7809C0400ULL,
		0xE2DCCF13C169A197ULL,
		0xEB6D32D5E7F12799ULL,
		0x3916898A5469B11CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x06CE7EA14CFC8EC7ULL,
		0x9DBB125FEC46E110ULL,
		0x00827C98D9980E93ULL,
		0x235F753F6FBC42FCULL,
		0x7236E2E85CF565ECULL,
		0xE9CABD68B40A6A4AULL,
		0xDDEF55FF6F8DCD0CULL,
		0x9C51F118EED3E843ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x179EF2008C0D8C3AULL,
		0x89618A96A6442C4CULL,
		0x1336DE43B680D185ULL,
		0x6DDE9399B4095584ULL,
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
		0xEB6D52013656E738ULL,
		0x808FB265C3985F5EULL,
		0xCDD7341217571726ULL,
		0x970382D305B705A2ULL,
		0x04F04373CD396B41ULL,
		0x941078DC94434B76ULL,
		0x553D49D3AC02ACF8ULL,
		0x07868E04BDE10252ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x649778264BA87C80ULL,
		0xCA22E277E15DAE18ULL,
		0xE4C5E34DF5ED5D1BULL,
		0x6F49EA8A70541D62ULL,
		0xE05475DE3C665CFAULL,
		0xC0A968A97B141C81ULL,
		0xFE4295FE5B854DF1ULL,
		0x23F6A2F0132D2055ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF5F65E0E6A028897ULL,
		0x17B937839F3BA983ULL,
		0xD248026E1405D50EULL,
		0x6F167D59EC1673B4ULL,
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
		0x23AA2B5F0113042AULL,
		0x6E1447B056320D28ULL,
		0x93CC634102AC537CULL,
		0x13275BFE1D737129ULL,
		0x0AC0488F154200FCULL,
		0x51931C9C2910D66BULL,
		0x15371FCB88FE7F25ULL,
		0xA5F16A03FC85F815ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x730CCC34BBD71A0CULL,
		0x8A63DEA6E1556E6BULL,
		0x948433D43C5FB8D5ULL,
		0x38B72A6D429467B7ULL,
		0x7DF2B7F24E9FCB37ULL,
		0xB8BE6D08F4975AD6ULL,
		0x64C78C64DE8D4870ULL,
		0x9F2821C9B7F517E0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9720D66FC14FE56FULL,
		0x934278E33EE4F6C9ULL,
		0x2FD810AA131AB975ULL,
		0x5C50EA3708605144ULL,
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
		0x2ADBC598E01DA88EULL,
		0x1A4A4FB24C418AE8ULL,
		0x4F8B42FF27AE789FULL,
		0x1D613C93E03168ADULL,
		0x3075495782D9300EULL,
		0x1BF9A9ECE7922726ULL,
		0x360D44A39629A319ULL,
		0x05F1B5E3A4940FFAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1CAEB8D316474FD7ULL,
		0xAB2786E3D4101894ULL,
		0x6AB3BC75D4D331D2ULL,
		0xA6684A0295880DCEULL,
		0xC17ED46187642718ULL,
		0xECCC457A0AB87738ULL,
		0x051E1D7FD8D80F96ULL,
		0xD1E199B9CA57E042ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x86C269491D35A8A1ULL,
		0x6FDFB1DB40818F92ULL,
		0x285755D76CF72C1FULL,
		0x315D20C7AF987036ULL,
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
		0xD77CF5049B8CFD31ULL,
		0xD1D2C821AF17A74AULL,
		0xD109343717809FDBULL,
		0xDB6FC82C1E9ECA71ULL,
		0x00B52CA44F8E19F0ULL,
		0x0193CF24A5CFBA09ULL,
		0xFE08C618F2DAF665ULL,
		0xB6B4ACCA9455F7BAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6FE152475E17B9BEULL,
		0x200851183C663EB5ULL,
		0xDAF49E5ABD95AEECULL,
		0xF1D92B0D3388CD62ULL,
		0x9D895FDB36123FD8ULL,
		0xB27504BFDBB5B379ULL,
		0x6FF538B91AB34322ULL,
		0xF5C474434B0B3292ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x201C089705D7A19AULL,
		0x705C81FF728E61DEULL,
		0x0CFB92166FCF8CC7ULL,
		0x0D3F0133CC2F4114ULL,
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
		0x6604E85609158BD4ULL,
		0xA0F2E30E0E4E1BDAULL,
		0xE59F9E2D51817BC4ULL,
		0x26F38C198F7E24CFULL,
		0x5FBF9FDDA37A85A3ULL,
		0x232FC524118D7F53ULL,
		0xDD956D9700B8F727ULL,
		0x20F2EC21ECDC5FE7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7C6DECD1C2EEE393ULL,
		0x0868BFF6B25C6812ULL,
		0x324F52489EC4F85EULL,
		0xA558BD3E95F08116ULL,
		0x703D81754D001040ULL,
		0x473388D9FE0304B8ULL,
		0x009AAE8C70615F04ULL,
		0x721BBF13D38DB537ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x76E77F011C541305ULL,
		0x3FFB1616427FE6C7ULL,
		0x8088A7761FBD1893ULL,
		0x758B7EF2BB3AF9FAULL,
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
		0xB153FFC5CE126666ULL,
		0x9C09CF97447ABE69ULL,
		0x70B18031E00080C6ULL,
		0xA2AB351B3EED5FF1ULL,
		0x4DA165B1122C18C5ULL,
		0x87109542BBC78CC3ULL,
		0x7D0CB2B1C867C244ULL,
		0xC617DE89133434ADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC76E29B8D6B16498ULL,
		0xFEE9335129298197ULL,
		0x804A2E47E8D4E0CAULL,
		0xAB7C33857F400977ULL,
		0x5D6E0B56F84ED596ULL,
		0xE169E218F498C745ULL,
		0x077795219AB4E7A1ULL,
		0x5E3BBCE61F1556C9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x91853F6CCE38FD02ULL,
		0x33DF3479AC428D83ULL,
		0x6489B550BFB81420ULL,
		0x61DBFFC5FC424663ULL,
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
		0x86D27F695B64082DULL,
		0xE1044606E78DD347ULL,
		0x028B131F90803A18ULL,
		0x4FD4ABBC4F20F3C7ULL,
		0xD735A0964A7EF0C2ULL,
		0x8478CB4B67407C3EULL,
		0x7ECA8714FCD06DE0ULL,
		0xB5E4D78F1F41CC88ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEC6F572D028B3249ULL,
		0x0CC9774897E656A2ULL,
		0x25336E22E4C9A546ULL,
		0x350F749F8DEEA2D3ULL,
		0xC4E9157425E86999ULL,
		0x4F9439A864B944B5ULL,
		0x681BCAA4F3B6F296ULL,
		0x58E6A4391D6F04DAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x51BFCF4DC730E7FBULL,
		0xAE286CF0AFB9BAFDULL,
		0x3B479D9E057EE1D6ULL,
		0x6880D5E1067BF4CBULL,
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
		0x32D5F14B99E7B29CULL,
		0xCE02F457E7E97D13ULL,
		0x9C02C23342D03F1BULL,
		0x0D36CC9636A6E798ULL,
		0x8398606BC7CB1BFAULL,
		0x398B69A2315A5563ULL,
		0x0821B7642BF18A70ULL,
		0xEB14D704D2EE77B0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9EAC1801CDCCCC04ULL,
		0xDFC231097188BE4EULL,
		0xEC1458835442EBAEULL,
		0xEAA6FA22E6158FF4ULL,
		0x86330BABAF98FD5FULL,
		0x979EEF39CC84AF82ULL,
		0x3CC546BDED649E8CULL,
		0xA088AA9430D1B3EAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x31346DCD638B7316ULL,
		0xF75AEECD6E175E2AULL,
		0xDFA7225D37785736ULL,
		0x335E6B2B60D666FFULL,
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
		0x6FC4D81A472E988BULL,
		0x5CD0D0347DDD65EEULL,
		0x6499FCC6B25F831EULL,
		0xF29B425BC9E972F3ULL,
		0x5328CFBAE483066CULL,
		0x8C1ECCC1AE7E742AULL,
		0x6803ABF6079F9E71ULL,
		0x9D36A540BCE67D4CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x259CFD906CBF2F83ULL,
		0x871EB3253D7A3E36ULL,
		0x947C4B582CA59E0BULL,
		0x70D1B0F2D602A060ULL,
		0xE01407C53BA01E63ULL,
		0xA8B86053B617A63AULL,
		0x21E663232943B628ULL,
		0xFE153E1F3965297AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5F3D8900EC1DD84AULL,
		0x96E635621FA5B943ULL,
		0x387680BB875E5FE4ULL,
		0x20BEE062791943C9ULL,
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
		0xF29E4590B5E7B40FULL,
		0xCE69D00D639FCD28ULL,
		0x8C4B8F3174846012ULL,
		0xFBE9A79A5CD5A601ULL,
		0xEDE07F7C06DE12FDULL,
		0xBF930B2219054B5EULL,
		0x098284105A729A76ULL,
		0x693E052A286AD63DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4A2E8D6DBE1E2E8AULL,
		0x37DB650F83E57988ULL,
		0xBBDC8E604787C166ULL,
		0x36B7ADD39137B5A9ULL,
		0x0FC3103FFDC09EEDULL,
		0xFD3B19CF07ECABE5ULL,
		0xE2EAF1DB5547B38FULL,
		0xD38D52C5CCDB850EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA0CE3B0C5228BD98ULL,
		0x6F9C3D526961FFB7ULL,
		0x8AEEB4AFF15AE4EDULL,
		0x7D6C74AC62E3FD31ULL,
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
		0xC5A25D22440A53C6ULL,
		0xA9CF61A6D202E56EULL,
		0x25F8FA4B60BD2F57ULL,
		0xE94E13506CC938DBULL,
		0x9C8E61C74D6F9B28ULL,
		0x2C92FBF8359AE30FULL,
		0x61BEBDAC01A2776EULL,
		0x6381530FB06974BEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBD60AD71586DD9E8ULL,
		0xA2A821D411103EFFULL,
		0x96D030884B449555ULL,
		0x9ECADFF6FDF6E264ULL,
		0x56DFF1D962D8EEBFULL,
		0x23AA46C10B43BABDULL,
		0x23E4BA0540DD443CULL,
		0x968A6FD96C376CA9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x60264D01BDFA1057ULL,
		0x59B2260309E2A2A5ULL,
		0xBD855483B2BE336FULL,
		0x3728ED678E3F899DULL,
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
		0xBFEACE8B850BCA5BULL,
		0xECCC279D7690D90DULL,
		0x4C4D26C3C3DEC8A2ULL,
		0x27C98FEEED6C4249ULL,
		0xC4F2B044B90ED9B6ULL,
		0xB04EBC2B84926351ULL,
		0xFF009E2C72018782ULL,
		0x732D8728FFDA3AADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1B90EC067DAEC962ULL,
		0xCC50039A92299ACCULL,
		0x6C86596C32C1BEBEULL,
		0xD1C3D70CC2D0A9F5ULL,
		0xF8C6AC2E6AE15F65ULL,
		0x05B036C27FB3DF1EULL,
		0xB410E5611D2413C2ULL,
		0x72980B9699EFDE1EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF2E27DD4A21D28D9ULL,
		0x7403F1999D6EDDCBULL,
		0xFF5C3B8629FC387DULL,
		0x6C36109D4B655598ULL,
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
		0xF0553F3261C0C48AULL,
		0x53086A60781AD7D3ULL,
		0x43025A2E8656624FULL,
		0x410FB8EA97F1CA91ULL,
		0x9835D3B4E97C0F50ULL,
		0x5AA48751AB7A20BBULL,
		0x3BCB88D150A1FC52ULL,
		0x6E90BEC3C6784725ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3B160469A0F5EDDEULL,
		0xE613B81804F98FE4ULL,
		0x33C5E4F53D3A3EB0ULL,
		0xC77703D748CB7332ULL,
		0xEF331C8B6C5AE0BBULL,
		0xB0E1850055DF31E1ULL,
		0xFDE89C9609E72721ULL,
		0xEE07EB76E52C8D92ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCBA66AF153B7BDE5ULL,
		0x9FE70A5B2820BC3EULL,
		0x3EEB8605C8D7C8D7ULL,
		0x0DE8127CC063E314ULL,
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
		0x92492DBB58CB57DBULL,
		0x04CD8F243A9AC7D2ULL,
		0x9E73204FB5E4C09AULL,
		0xAD6AC2B52355EA6FULL,
		0x0BC3588832D0173CULL,
		0xB073D01C1E7D68B1ULL,
		0x1F6490A3264AD1F1ULL,
		0x9A1B6AF577F8BEA7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5E6125BE247D151EULL,
		0x82A81BA8E4E348EBULL,
		0x8BE652A8031086AEULL,
		0x178F8E6173F50BF6ULL,
		0x0464BB0CA4499F05ULL,
		0x24A75F067052B831ULL,
		0xE25B467B3057EDC3ULL,
		0x9EA9DD75929E7364ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4BF368545C441AD4ULL,
		0x427E3CB3300DB1E8ULL,
		0x21EDCF9634E218D4ULL,
		0x68B6354FBAC80A4EULL,
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
		0x0B17CFBE9440BC22ULL,
		0x3FD46D9BC572A78BULL,
		0x4F56077D11CC6DD7ULL,
		0x3A00A60C4060927DULL,
		0x9915EC78148BBA92ULL,
		0xB8E368EB472731C8ULL,
		0x2D14BFAAB6DDE9F6ULL,
		0xF68E8E869B341F4FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8D2067D67BA634C7ULL,
		0x85A7EAAC3FEB0F4EULL,
		0xF214C21ED7DCF600ULL,
		0x9553B981F3A81F83ULL,
		0x9FD71918BD142DFFULL,
		0xEF6F12746840E91DULL,
		0x1EB24CD27AE7B940ULL,
		0xAA73AA3733380BC0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7D4AC80F145966BCULL,
		0xA17158949BB6619DULL,
		0x7FDE5177207AB2D2ULL,
		0x70AAD053BC235A35ULL,
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
		0x282015768234515FULL,
		0x9E48ED512B03398EULL,
		0x57EF41F536D2A465ULL,
		0xDF9893AC89A993D6ULL,
		0x72E6CCDC09F0574EULL,
		0x191F4FEF01B2FFCFULL,
		0x1A533E22CA6AEEE5ULL,
		0x006AE14430E27C1FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA878044C1DE5E840ULL,
		0x56F44A54D7C3A21CULL,
		0x5D7A35234A200DA8ULL,
		0x07BFAB28E8DA6A33ULL,
		0x731C60EA2740DE99ULL,
		0x2634A81A861B0486ULL,
		0xCBBDAB9C733ABA6DULL,
		0x713C95B5523FDE15ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x77B417120A5A519DULL,
		0x56298C86ABCEE447ULL,
		0xA4A8CCC2DDDA608BULL,
		0x18B81FB8ACF29F04ULL,
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
		0xE3BAC9802141D2C7ULL,
		0xC9986471FDF4035FULL,
		0x65B34C2BD91FA8B7ULL,
		0x545BFAF939E0E2FCULL,
		0x838B84E8D2407C17ULL,
		0x31117F9A0A74AF2DULL,
		0xFE49576DB47D2BD0ULL,
		0x090FBE7399C2552CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBD358EE59926ECD3ULL,
		0x26238CB0F7CD821CULL,
		0xADE2BCD1B58C86FDULL,
		0xA3F4E5C37680C5B8ULL,
		0xE8A148F829B52295ULL,
		0x09DAAF170DE0A918ULL,
		0x730726F2636D24A5ULL,
		0xDEE9751939B578B1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x254A20538CCA2A6DULL,
		0x7597CB32841F6852ULL,
		0x63A3C1A82BF43222ULL,
		0x7215F8A00548D79AULL,
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
		0x302430F0EDB57198ULL,
		0x913A8D559CACDE65ULL,
		0xBF5E8AF5C1AEF288ULL,
		0x6308A4F1420CE439ULL,
		0x57D94E41C4C9B7ADULL,
		0x048818A3FC17F356ULL,
		0x79B4F2E83FDE4914ULL,
		0x2A27060B79CC15B3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x717DBBE6D3F299C0ULL,
		0x73242F195CCF5CDAULL,
		0x28C6856084755120ULL,
		0x7C1ED76793ACF687ULL,
		0x33306C9B44AA65C0ULL,
		0x32189517F291E7E2ULL,
		0xA5CE21E7296FA244ULL,
		0xFB078DB6594FDEAFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2FB7F3C11E68FC59ULL,
		0x5AA3E505A9C334C8ULL,
		0x0ADB0BBE91A66441ULL,
		0x6595AA2C80D01844ULL,
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
		0x11BB38C0A5A865A0ULL,
		0x63A4FBC591B926DDULL,
		0x0115930328DB9DDAULL,
		0x397CDEA3AFAB1632ULL,
		0x1DA5694E681A2F86ULL,
		0xAC7414D3989F1EE7ULL,
		0x87B1055CCCD598A8ULL,
		0x2E714FC67C60D539ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4F04A76C694DF3B6ULL,
		0xF4C1C34D683B5AA9ULL,
		0x75A72E7AD413304DULL,
		0x85497DC6DA94CA68ULL,
		0xB1FAF9D04A3942B2ULL,
		0x3A9D28415BACE745ULL,
		0xF179FA66DA3B2116ULL,
		0x68DBE908A1FA0DF7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBE031E0CABBD980CULL,
		0x54CA562D35720E29ULL,
		0xD79A050A57B62D49ULL,
		0x0860A10B4057DF85ULL,
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
		0xD7F155901DA9B406ULL,
		0x22BC0026AA461E30ULL,
		0xBD82AEFCBEBA3ED5ULL,
		0x438F2B580B9A6FF9ULL,
		0xF664A1506ABA1632ULL,
		0x10EBC382FE914549ULL,
		0x98594D01ED6B5EA1ULL,
		0xD019A06AAD2285FFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x899A0F016184CBE6ULL,
		0x5E25929A67366409ULL,
		0xDEC32ACDE22CC854ULL,
		0x8FED9FC2FDF1DCE0ULL,
		0x8139EFFDB8FCD6DCULL,
		0xF9582F4E255961B0ULL,
		0xF565C7DAC68A9DABULL,
		0xC6FEEE1B373E6F0CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB2AD98D51E3C4F0AULL,
		0x447E6D64815B82EEULL,
		0x0EE547FEA1EA1AE2ULL,
		0x0D9803608D83FB1DULL,
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
		0x89FB6C40C8FC94DBULL,
		0x99B21AFC04C3A478ULL,
		0xBBED9AF42B14F3D2ULL,
		0xE8B073B76ACAED40ULL,
		0x57DEE76F1323753EULL,
		0x159B222F76D38D93ULL,
		0x350900EAE6012F4FULL,
		0xE902799482AC7DA4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC952B45FB01CE7E7ULL,
		0x4A5672BF3F1E40EEULL,
		0x6CD7EC9C64EB6445ULL,
		0xEE00D63CBDFCD626ULL,
		0x731E4C1B305EA1D0ULL,
		0xC7E8EDE0E7F80A00ULL,
		0x7F2D1574580400D7ULL,
		0x518FA6C0DF12BD94ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB53FC654C217128CULL,
		0xD7CF6BE5FA3AEB57ULL,
		0x4DBAA1F0D9BE7542ULL,
		0x75BAE8E4F5A0996FULL,
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
		0x1EFE23AAD6883EF4ULL,
		0xEFBF09BC916F2D1BULL,
		0x9D64CE875E70CCDDULL,
		0x7405BCED260FE9CDULL,
		0x5BDF7BAB83EB94DCULL,
		0xA32CA91BED090ED4ULL,
		0xBB5563D312C37167ULL,
		0x92DB28F30BB0B2B7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x299D56505C8A0DDAULL,
		0x9DEC68EF9E39F83BULL,
		0x4BC3B254E3FF64E6ULL,
		0x578C7248ED753DBDULL,
		0x1F9B1B6EF8E1E7CFULL,
		0xA644ECA2E5C936AEULL,
		0x2867FFBBCE5434A1ULL,
		0xFD1F2C1D1A4D25FAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE78716571D6DDEA8ULL,
		0xDC389AC406AF4A8CULL,
		0x20DDF7A6A2F46D5AULL,
		0x5660D2660D619034ULL,
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
		0xA6065C47257B61DCULL,
		0x66ACD38ACA95B9D2ULL,
		0xFDFC3167CAFDEAEDULL,
		0xC6DF5E0F70588319ULL,
		0xDC070CBF4332EE14ULL,
		0xF039C8A5D26B4AFDULL,
		0x07D3D7B5CF7034ECULL,
		0x2DEACE6C90E5EB31ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8C3541E413269D9BULL,
		0x9053AAF013B37B91ULL,
		0xF04BB895B07E6A7EULL,
		0x693924A72F9CB6B5ULL,
		0xB84E3E623A9D6F97ULL,
		0x03F3A61CC45BF938ULL,
		0xE2FF2861A6564DF5ULL,
		0x95C7780FEC88768FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x673FBC3258858882ULL,
		0xE8C248F2CD286184ULL,
		0x85427F503457C93BULL,
		0x72E50B28A69B1C4FULL,
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
		0x24BDB263C83A4262ULL,
		0x4B8348F3ADF91FC0ULL,
		0xBCAFC6808C839FFDULL,
		0x4793833A4828B360ULL,
		0x5DB0896B99DE1665ULL,
		0x44674F90932B57B4ULL,
		0x6B7533457FE7AE18ULL,
		0x3C665C176BAD012CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x39E09409E81E7FD3ULL,
		0x9AC532F9FC80AA09ULL,
		0xFB6913F4E91A18CBULL,
		0x28115F2DA944F1B2ULL,
		0xBCCFD3FA3E4485E8ULL,
		0x6A5EFCE2652FBE0BULL,
		0xAEAA87A2CC05D028ULL,
		0x9E35EF2ED606CFAEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCC380D2D78E732F6ULL,
		0x0DFA5BD484D144BEULL,
		0xC75C2CB256F078CCULL,
		0x1AB24E92D58F1A57ULL,
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
		0x4D3D93D87971AD0AULL,
		0x1F847B230659B18AULL,
		0xBBA3485AB2F5ABE9ULL,
		0xC72EB2A8E22116EEULL,
		0xA91CDA2890B9C678ULL,
		0xE5738E04A1263DB0ULL,
		0x5253B8640F4627B3ULL,
		0x4AA0D373C508BC49ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5299E0546B168E81ULL,
		0x34A1CDF753AB3C2BULL,
		0x71763A5809124EB3ULL,
		0xBAB7947E29402E51ULL,
		0x6D34C1F18F2A03B7ULL,
		0x643CA08B5B58703CULL,
		0x3E03D4F6BFE065D6ULL,
		0x3422408DD63FCFD1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDF174BAE49B207A1ULL,
		0x1909ED2C0F3AF49FULL,
		0x4E08D03C72FE2417ULL,
		0x6340EC4C2AB40270ULL,
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
		0x0F438ECB263CE0A3ULL,
		0x0A9D3ED288110FC6ULL,
		0xD0E7E1503296D728ULL,
		0x2E67A8F789549954ULL,
		0xC685498844AE7862ULL,
		0x5571015A40BA3D73ULL,
		0xE10CE905508B8D7BULL,
		0xD1C778DF59547166ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x07A5179AD8672887ULL,
		0x199C39D748B05895ULL,
		0xA855EE3CBBE45ECAULL,
		0x31814D47BA8E69F3ULL,
		0x1A55B12F88DE7A00ULL,
		0xAC74674BFCC5F686ULL,
		0xBA326E8EB3D349C0ULL,
		0x889EB40A0CBFB07BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x96AF145C2EB57C37ULL,
		0x067FE31955A33E78ULL,
		0xED0020AEBA0C8613ULL,
		0x58F393592CDAD248ULL,
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
		0x8AC54A554D996EC5ULL,
		0x32EA6CEC517C9495ULL,
		0x48210E7D72B196F7ULL,
		0x42A9FC291F9CC680ULL,
		0x65274B127228CBF8ULL,
		0x8A8F75C2255E168AULL,
		0xED115560FA3EB7DEULL,
		0xD686562159A75D98ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3979CF94CCE30E19ULL,
		0xEE87B63199C58436ULL,
		0x60CB3CAE45E0F70FULL,
		0xDB43530B89F7410AULL,
		0x7E4C689C9C3E1B74ULL,
		0xE81D23A24B1FB857ULL,
		0x2AE6231AA4086507ULL,
		0x3A94759E5657F764ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x95C9183E418C979BULL,
		0x615AE7751CF90BEDULL,
		0xB9BF483FF8E0EBC3ULL,
		0x0D4DFC90136EB14AULL,
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
		0x86DB1B63C549BC84ULL,
		0x868D00D1DE242258ULL,
		0xCE62A4E1A80FE137ULL,
		0x3DC4917AE839661BULL,
		0x665D7DBD372F0517ULL,
		0xB80B8D172AB813DAULL,
		0xF47BD21F0200E297ULL,
		0x55ABC24C2D1D959CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE374DCDE422CF15FULL,
		0x06B15DC8D9CD836EULL,
		0xF64D07F7E589E0D0ULL,
		0x0AB6643D89333511ULL,
		0x9E74BC5E42EA03E2ULL,
		0x454E16DF4AC4F96EULL,
		0xB2060B058F55033BULL,
		0x0E757354335D65C2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4FF2F29DC55AFA92ULL,
		0x87FB2F54426C8AE9ULL,
		0xB5912AB0C8092820ULL,
		0x451DE60C718D4B6FULL,
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
		0x88B03D812CB66629ULL,
		0x21B2812BB3473ACAULL,
		0xBC61C1E1A81CDDB8ULL,
		0xD4C8E6F6681B1AFFULL,
		0x325CB18F5B5C90E9ULL,
		0x81E45663BE5E9605ULL,
		0x4EE3DD7FA8F2264DULL,
		0x72DFF85BD4CD85E7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x16A60ED57ED503E8ULL,
		0xD8867E80332561CEULL,
		0xF5E1A21E88DD5598ULL,
		0x62CFC8C65B32CDE8ULL,
		0xD2B0F10387BD7700ULL,
		0xE59D4B2CA62B388BULL,
		0xCC80AE6657FE564FULL,
		0x895591EE3C48BCD3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA588C36D177F3A65ULL,
		0x7BB7ACD917C1B900ULL,
		0x21391D85237067C4ULL,
		0x1C845274B09E25FCULL,
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
		0x4B2E341373A3DF39ULL,
		0x8161A159F04C8775ULL,
		0x0108EF8E483AE70AULL,
		0xE18720F4F91A39D8ULL,
		0x2AC1C530AF6B28ACULL,
		0xEB4C22E4E2EAC402ULL,
		0x573D69FD7A4FEC94ULL,
		0x5943D44B00AE4E13ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAAB2219A8B4F077EULL,
		0xC7746F3305B234D0ULL,
		0xFA605D1836EC7B88ULL,
		0xF6A8567BE4B116C0ULL,
		0x25F3FB5AC93279F0ULL,
		0x80953B16C46297D6ULL,
		0xF1D3A441BB593C86ULL,
		0x7436C254E6DFB629ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5708083914BEC6F8ULL,
		0x91139ABF72D0E12DULL,
		0x145BEC5469EC8DA5ULL,
		0x6ACF7500E913AFBCULL,
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
		0x40F19945EF774257ULL,
		0x4881408E5443C418ULL,
		0x483BF935224F2108ULL,
		0xF4C7DAA8855D1666ULL,
		0x23AD99BE6DAECC3EULL,
		0x39F0B4ABC68CACA8ULL,
		0xF20648640A5FF8EEULL,
		0xC5CC115E55EC520FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x13FD752C122C21EBULL,
		0xB5C9F485F3E49D69ULL,
		0xA460C438F8F24AA5ULL,
		0x54081135A6932EABULL,
		0x491F0097DE2BD351ULL,
		0x1AB1D49D5A05D2FDULL,
		0xA316F9E84EC913C4ULL,
		0x5CE56A1D131DA2CAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9E1EDFD32ABC15FAULL,
		0x360C8E2C7C63760BULL,
		0x5B60DB5A01C2DAA3ULL,
		0x32FC9D22C977EC04ULL,
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
		0xE0EED9FE6020F9F1ULL,
		0xC1E78EE13364FDBDULL,
		0x22945110DD6872E2ULL,
		0x8227853AE8473F24ULL,
		0x6BA33D3E97352FB0ULL,
		0x4C4BFBC1461835FBULL,
		0x11E501BB683FB712ULL,
		0x1F77A40BB83BDECEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2E056269D92072EBULL,
		0x56D1D49D6C4ECD19ULL,
		0x44E76247B9F3C679ULL,
		0x45F526CD773BD44CULL,
		0x5BF1DBC6D778A547ULL,
		0x099B1FEF936E7FBDULL,
		0x9B8FA2DDE0290967ULL,
		0xEA551FC30F92445AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x073DEF5AFCFD0E28ULL,
		0x51565B644C473DDBULL,
		0x6E5903AB56D273D5ULL,
		0x1F5201367A3857FBULL,
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
		0xE282E45AB43BDA2EULL,
		0xF7C364EA0A293F88ULL,
		0xFC7337171E9A7FBFULL,
		0x7A20F193897152E5ULL,
		0x6A46165B3D38ED0DULL,
		0xC84E48BF4A39297CULL,
		0xE0205B7919605687ULL,
		0x7FC9AB56ADA7CAD4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x05398A8EE2ADD070ULL,
		0x30C73C9E7949657EULL,
		0x815EB7331CEF1328ULL,
		0xFA21F6367FFA0D79ULL,
		0x5CE3AE7FA72A5CDFULL,
		0x2A8ED32C2202B7A7ULL,
		0x7605F1DA911C5189ULL,
		0xCF682DE77AB7C802ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD9E4C46417B76EB7ULL,
		0x31679C2388F4BFAAULL,
		0x3B002D6C3BC42A63ULL,
		0x2E7799DE9917B0A8ULL,
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
		0x70A5961D77DC182FULL,
		0x437136CA9A1F38E2ULL,
		0x5AD67D3A8AB24620ULL,
		0x3AE87A2A0FF7C6EAULL,
		0xB90C94762CBBBA58ULL,
		0x1DC655687AACA5B6ULL,
		0xC5E1558442B1E4C1ULL,
		0xC370B9947D1B75C1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4D4CD340557CE106ULL,
		0xC2B1851671A28216ULL,
		0x27C4D3C49A62C506ULL,
		0x723B4921EF94C333ULL,
		0x5D6B1124F966D29BULL,
		0xCC70DD0727590EEDULL,
		0xFCFFE9EE7C8F2B9BULL,
		0xE887BFFA8274DCA3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBD5240EAC0F99C53ULL,
		0x936F902686E518AFULL,
		0x0487A1B15976FCA3ULL,
		0x47423DE3551DBE23ULL,
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
		0xCB1F7D6CD58CCE46ULL,
		0x2F656F7DAE433140ULL,
		0xB877877148188617ULL,
		0x1C6634B905A3FB30ULL,
		0x7730591FC02A2145ULL,
		0x50474638E3907BF8ULL,
		0xD0656F6A6B44D38DULL,
		0x1CE17C0F5465ABD0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDF5D612B74B3755BULL,
		0x7EC3FECC85D583F2ULL,
		0xDE93E22E32CD967EULL,
		0xBDBA458C2A151444ULL,
		0x5EAFE2AE06976AB3ULL,
		0xD5AFA085A39B82A2ULL,
		0x1A74FC91E235C7DCULL,
		0x96164BFE9A11D16EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8ED3B122ECA06FC5ULL,
		0xE324094CA6CAB015ULL,
		0xDB94B1676D86ABCAULL,
		0x60D511A884015192ULL,
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
		0x752DC6A8737C38F2ULL,
		0x9233DB511C350070ULL,
		0x83A33FB1F5980EB5ULL,
		0xD494D97E4E318B21ULL,
		0x8596F31C1AE4FF16ULL,
		0xBE09F22DBC9FE9E8ULL,
		0x96875DFEBBF4239CULL,
		0x2D0DEFB9C62C7FECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x767DBBDAC8C7DDC1ULL,
		0x0AC4ED94BAC111DEULL,
		0xC849DD1E64211C5EULL,
		0xB08E7E0F0670E70AULL,
		0x8C8117953FCC4210ULL,
		0x29751B5C65BDD03CULL,
		0x35C0A596BFE343E8ULL,
		0x9CA32555132371D2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF7EEA0D2306067A2ULL,
		0x9586D0CF4703BE18ULL,
		0x18D8C202FBF82725ULL,
		0x13E06661DB18BC01ULL,
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
		0xA0E51DCF569DE57CULL,
		0xD03AC7903BE833DDULL,
		0xA5AD2F4886C8D1B7ULL,
		0x4DD64E0D31E4A667ULL,
		0xACC8619C8FEB9417ULL,
		0x4F9A932F2E47E8BDULL,
		0x408AB7BD1994783CULL,
		0x3E3590F9EAD75E5AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4114A613629EB3E0ULL,
		0x6240448CFD28CD1CULL,
		0x926792B1F26AF8F4ULL,
		0xEF525E21FF8613D6ULL,
		0x8454DC10A4FBAAA5ULL,
		0xB1B289287F51EDCCULL,
		0x2C210D6FABAD7A86ULL,
		0xAE0F224D4574ACAFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x60F64A80D39BD5EFULL,
		0xDE6C00013742A68DULL,
		0x1AF4E414E4A781B8ULL,
		0x44385D8BBF04F1F6ULL,
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
		0x750A6F68DDFEE59FULL,
		0x2748E50646077679ULL,
		0x43A4B1D7D4BB5AF6ULL,
		0xB965D07E10A3FFFFULL,
		0x39F15027F97105C5ULL,
		0xDE71C44FA05A124EULL,
		0x4B3B83F2CF6A568CULL,
		0x92E9C8261D19CCA3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0B54C8382420CA3AULL,
		0xADD8BCE0CE2F2B30ULL,
		0x168F4EDFF816D7F5ULL,
		0x0ED8D8A6357281D5ULL,
		0x7E6EB4F4B0F15FCFULL,
		0x57466184DFDE88EEULL,
		0xDD806B05EC6442D8ULL,
		0xCE749E59F84A8FC7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3F18B0CD7CD0BCA6ULL,
		0x89E0D23E0A2EAF7FULL,
		0x76DB16218F8B6FCCULL,
		0x53F12C2551F486BCULL,
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
		0x67F916605C95951EULL,
		0xD926F01D9A354C9EULL,
		0x63A253E3897EEB9AULL,
		0xAD61CBFE6EF3FB27ULL,
		0x154FC4788DA87988ULL,
		0xF3030C38B08FF62AULL,
		0x87D282446ABC072CULL,
		0x81C20DDBAF44A254ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDE27001083935959ULL,
		0x153EE0D8639C6A7CULL,
		0x55449014FDC6A61EULL,
		0x9C19EC4DB067E964ULL,
		0xB6D7954870DF316DULL,
		0x2CAEA0C63E0CB7EFULL,
		0xE2AFEC1F4005D839ULL,
		0x33BA15802EB6C512ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8FA917741EE2F17CULL,
		0x3470024236141ECBULL,
		0x91800D52E2C33DACULL,
		0x2676BD45D39AE981ULL,
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
		0x1AAA0EF67E91F4E9ULL,
		0xC378AA5118A4507FULL,
		0xCBD49B394DE3E935ULL,
		0x54BE0987139C7AE8ULL,
		0xB4290509A1265E12ULL,
		0x94C7B136CF17451BULL,
		0x56560FC60AAEF3E0ULL,
		0x3C0F35AE672DB0FCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x20F9BE6E6602D06EULL,
		0x8B40D3406EA69545ULL,
		0xF8E0426DC0B6402AULL,
		0x490C1662DC76B2F6ULL,
		0xD062C74CB435E725ULL,
		0x4F4BFC6029EBF469ULL,
		0x9217D4E5B2557B06ULL,
		0xE1185078CE356BA1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC91D7A934440C806ULL,
		0x8894AEED2E6BB5A1ULL,
		0xF4311618AA759971ULL,
		0x0C57F918EC00136AULL,
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
		0xD4B2AC57435C9F49ULL,
		0x1FF114125A0CE562ULL,
		0x1D50C49484C1CDD9ULL,
		0x30566FBAD87E0BD7ULL,
		0x5D7EB6371363A770ULL,
		0xE75B63021B6A18C7ULL,
		0xA01417792F6AEC39ULL,
		0xBA2D5F84EAC9B93AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8F2E9DEC970B7674ULL,
		0x6FF1270C4DECE293ULL,
		0xF05C43CE4E2607BCULL,
		0x3FE1EABCB435E408ULL,
		0x5DFAC5AA2FBC3274ULL,
		0x7A65C839242EBD05ULL,
		0x5962A8C7E49AD85BULL,
		0xCE7C365B24118534ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3319C354772C85B8ULL,
		0xDC74E6DABEEFA19BULL,
		0xAB4AEF17517EB920ULL,
		0x6CC0A131A39FE0BCULL,
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
		0xD2E0BF55B87E7B15ULL,
		0xD962927828C11868ULL,
		0x57C9B4522067BEE0ULL,
		0x8F3706E728DB1587ULL,
		0xE1E7E58627080EEAULL,
		0xEC92B1B86A202771ULL,
		0x1AAEAC435AC3C032ULL,
		0x1C848FF58004AF05ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x595010E65E18D2DFULL,
		0xDFB3A732BF9D1980ULL,
		0x3715544C74AD48DBULL,
		0x97D2F4555C95F8CCULL,
		0xFA7C73E4CF6F160EULL,
		0xEFB4CA2A0EF69BCAULL,
		0x4ED31E74D3EE1A9EULL,
		0x79DF2C46DD3850E2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD3838C625B1A96CAULL,
		0x829F4A66F14EB9AEULL,
		0x634B6CADAF7109FCULL,
		0x1BF0DE7DF69B15E5ULL,
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
		0xA5471C455E5E44AFULL,
		0x26C336EDEF3B7E8EULL,
		0xD30AECDF3556C07CULL,
		0x57CADAB9CE129E24ULL,
		0x28EF7F0146183AA7ULL,
		0x70C01AE613F503D6ULL,
		0x507F680F7E1C7011ULL,
		0xC8701E4B5F35395DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD9A5CFD1DB651769ULL,
		0xE09EC9B0590A7B71ULL,
		0xFFB508B67F6FD0C2ULL,
		0x4D95DFF30A47C412ULL,
		0xBE302D25A5E2A8B7ULL,
		0xDB202ED2C507CC69ULL,
		0xD69FF59EE89A2B16ULL,
		0x9CDEC984EF08978DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA407730D4AECD7DDULL,
		0x7BE1781B4D673D34ULL,
		0xEA80E0DEE73D2CEBULL,
		0x01C7903B6A6ADEDDULL,
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
		0x72CC9E348C992FF1ULL,
		0x7DB1FFB1715E5147ULL,
		0x17100DD22512E3A5ULL,
		0xBA4B72A28FA5C7EAULL,
		0x24D3208AAA50C293ULL,
		0x6956E1257B5C0DD5ULL,
		0x98AF91D08BA8EB09ULL,
		0x2BD62DCE7845A700ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x08496EBAB3594EC2ULL,
		0x3A5EE63337959C70ULL,
		0xB1EC85D76AB6E66BULL,
		0x2A4B2A5792B09488ULL,
		0x91B15EE7EA1F1811ULL,
		0x8E0F7FE012D03BA4ULL,
		0xFFA7EBB49674E7A9ULL,
		0x918F2F2C3FB69E84ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4185EDA2609F2E41ULL,
		0xCFEB89CBBE89E80DULL,
		0x1C46302120147D74ULL,
		0x768A145F623075BAULL,
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
		0x819CCCFCFFB62A3AULL,
		0xAE1F17953B02F2A1ULL,
		0xCEB7661590206460ULL,
		0xAA24BD66D042C424ULL,
		0x6C6FEB39F631DCECULL,
		0xA4DA3E383768CE3FULL,
		0xA2252F37279032CDULL,
		0x1BD08B7DDF4C76CBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAC63069C00FBE606ULL,
		0x646723E453B85B08ULL,
		0x4E28E3B80F875BF8ULL,
		0x6DC3B664F69DF74FULL,
		0xB5B0C20BACCFF41BULL,
		0x360AC69D8CBEA6F5ULL,
		0x1A30E6CCF391AEA8ULL,
		0xBF37298A52D93A7DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF599E33FE342CF97ULL,
		0xBC83B4A63C8C6C89ULL,
		0xAED142213860A5F6ULL,
		0x7B259128B2BFC07DULL,
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
		0x66B3542C2F913531ULL,
		0xCE2BA5683A8CD0BFULL,
		0x3AEE1300B5F3E8B6ULL,
		0x374110878930F802ULL,
		0xA0CE61B344DCED61ULL,
		0x024370A1F504EE4CULL,
		0xD57D63FC5C8EF689ULL,
		0x5D9D29BC8F6AA43DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCDAACA0A2E04F00AULL,
		0x70BD947FA2F5F5F4ULL,
		0xAFA49548B520A9ABULL,
		0xB8A6807F85AFE734ULL,
		0x096F9D88058CCC82ULL,
		0x657604EF9849EBE0ULL,
		0x44F685A025DBDAD0ULL,
		0xA579C2FFD4DA1A52ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1119A88D6771248CULL,
		0xA3EC0D625B5936E9ULL,
		0xFF4E7F681F695C72ULL,
		0x53DBD00BB4F589C4ULL,
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
		0xF7251395C15B7487ULL,
		0x180CA3B5B66F963DULL,
		0x3D9A954BA37297CEULL,
		0x4622C938E3B29107ULL,
		0x6E8D94E45CBBE4A5ULL,
		0xE42948136C0C1770ULL,
		0x0F374D628BB856FCULL,
		0xFBC2A99976C3D8EAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x311BFBD9929CB6DEULL,
		0xFE2D8BB69C0DD197ULL,
		0x49BD17C9F87CBFB3ULL,
		0x0296C1CCBC4F640FULL,
		0x5ABA17B67D090CCBULL,
		0x15C74EDB8323456AULL,
		0x1EBCF7587F62AE05ULL,
		0x0CD98406D36F797AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB76DAC8B634ACD4AULL,
		0xBC6A164BACF0F18DULL,
		0xA60642FF7FACECE2ULL,
		0x3A279B3065E95795ULL,
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
		0x98EEC1D9EECD9912ULL,
		0x10D60BF2C1C43A34ULL,
		0x4997CA23FD97222CULL,
		0x60A77C256F91CA0BULL,
		0xCE432E77B828F0EBULL,
		0x52B01EF3B0402D79ULL,
		0x90543E8B83532637ULL,
		0x3B354BE58CCE048AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x63BE34AA6AF0B61FULL,
		0xEF585E7FC30774ADULL,
		0xE24D55470500545BULL,
		0x4B7A9D3DF99C1A75ULL,
		0x7F533BD1965440C0ULL,
		0x9CCCF1994DD01CF4ULL,
		0xC95D6B3323582CA1ULL,
		0xB878A14457830836ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xECCE91D8896F0683ULL,
		0x213668DD9B5F3950ULL,
		0xEFEDD3FB37D7DA09ULL,
		0x7D2E32D55F172404ULL,
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
		0x85C87A0105293222ULL,
		0x3CFE7D6BDE12CB19ULL,
		0x0A74E11E917B3980ULL,
		0xADC82F3C21A87930ULL,
		0xA1C10A489DC8ADC5ULL,
		0x3F5B4526572E6C4DULL,
		0xAE93CAB4565B0203ULL,
		0x0986614B3CEBC5F2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4E4998A5551A4D8BULL,
		0x86B4DF762C042315ULL,
		0x8C72A67D7FD71FA1ULL,
		0x274255520140CCCDULL,
		0x0FF96B02ADE02078ULL,
		0x7FA9E2FC4CBC361CULL,
		0xE7A05FCA732B3661ULL,
		0x407F30A500F13436ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDB2085BD4C93DCD5ULL,
		0x2A9E30333F02B35FULL,
		0x06241958CABC53E1ULL,
		0x5D97129707994E42ULL,
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
		0x9AC3E38B44D281A6ULL,
		0x4C6C57FA7D99EEE9ULL,
		0xAB58816064577DC1ULL,
		0x316089AF423E9B33ULL,
		0x29F2C53B339DF120ULL,
		0x3B2F6D8B35DE2365ULL,
		0xFFDA4FDBBD2E6E62ULL,
		0xCCDA55AC377510E7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2C3B5853F6AE2C0EULL,
		0xE7A4C854D3CE4D3AULL,
		0xE2B0A247075E6132ULL,
		0x0C8A07985EF684EFULL,
		0x4873FADA7FC9400AULL,
		0x5BF483079022A035ULL,
		0x7E734947C28A1139ULL,
		0x808C7BA325DF283BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE75A9591FFB6A07EULL,
		0x87865F3043A11ACAULL,
		0xFDF2D910915EF09FULL,
		0x7864DF6F7F889FDEULL,
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
		0x7DE687FED28ACDFBULL,
		0x57CBF2607B6D4153ULL,
		0xBD51554ACBCE8EE4ULL,
		0x8BDB2EBAEF772192ULL,
		0x7E92049952B4749AULL,
		0x2DE6AB8C9FA06BC9ULL,
		0x467C25927F6EE2FAULL,
		0x9EA4C2F62B3F062DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFE51727E61DE5B67ULL,
		0x6EC13778B8242737ULL,
		0xB22B52C5C5ABE911ULL,
		0x6C3B5FB6C289461FULL,
		0x8836681E4857889BULL,
		0x33B79DB599B8E602ULL,
		0x34DA2F0F343B85E4ULL,
		0x789CF6822269F092ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x112E4FC3FA777B3FULL,
		0x0C06C8D2A3A6F5A4ULL,
		0xA9309A022FC27716ULL,
		0x44C8283D7C8F1077ULL,
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
		0xB3FE035A0B871A48ULL,
		0x147310C059CF95E8ULL,
		0x675561F57FADC206ULL,
		0x8207F9AC23D9C33CULL,
		0x732E98CC8739DE6BULL,
		0x9FABF23560DC9415ULL,
		0xAFDB7305674D266EULL,
		0x073D897698222364ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x498D58331DA2522BULL,
		0x1130FA3804EF64BFULL,
		0xB6AB0319FC1F630FULL,
		0xB9ECE2CA23192176ULL,
		0x62F7332C08661187ULL,
		0xC79D0629A8D8463DULL,
		0xF2F804FA4F3B6418ULL,
		0xB90689E987F719B0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD2A9C0F9C1552DF3ULL,
		0x15792045A583BF3BULL,
		0xBA6CB481163137B5ULL,
		0x644505D267241273ULL,
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
		0xC46EEB4667B64C4DULL,
		0x363A9D92112246D1ULL,
		0x3F0F0C15232282B3ULL,
		0x267446D4B37473E0ULL,
		0xF5CAD16F9DFB42EFULL,
		0x96A447D1394AEB4BULL,
		0xC88603BB88A2A945ULL,
		0x4B5C85914F7794FBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8CF612A8979F6E17ULL,
		0xD86B0B9E1CF77A24ULL,
		0x82E37ABA193A8B29ULL,
		0xC398313E77E58BE1ULL,
		0x93C6DA607B15D03EULL,
		0x4B62C90632C9AFA8ULL,
		0x17A0A9D07EB20F01ULL,
		0x8941BF9AB8E4272FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC40F84DCFE25E300ULL,
		0x89886416EB59A6EDULL,
		0xFE36EA3E839EDDACULL,
		0x32D5783095713460ULL,
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
		0xD8739E8E2334D899ULL,
		0x77A74D7705EA89CFULL,
		0xC1EAC237187FBD50ULL,
		0x319C20DD06E04719ULL,
		0xC74A7764727DCD44ULL,
		0xC0D7A0AB50EB4A0EULL,
		0xE249477EF5F1985AULL,
		0x5B5D7617AEA6CC9DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x92CB8DC935D57986ULL,
		0x8E3B0AF6375101EFULL,
		0xB0F5E6CC5A8B6C8BULL,
		0x0B272F4B5DA6D284ULL,
		0xFA9A113438513D1BULL,
		0x27942BC2EA3D7AB2ULL,
		0x2E13A102E6513CBCULL,
		0x50F42C1B0E674D21ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA7D73BED8FFCC562ULL,
		0xA96F9D000C664F80ULL,
		0xD0EB91D50FC1EA4FULL,
		0x3215ED1172A66117ULL,
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
		0xA65B61FDAD374DC4ULL,
		0xFEA8412D6892E5E3ULL,
		0x34734D30EAF08252ULL,
		0xFA9406AE8BE120CEULL,
		0x0768C15EE5F6AFB0ULL,
		0xB91C7B4E4E3E11BDULL,
		0x229F5FF28C4A42F3ULL,
		0x62FC250A8C7522BFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5056181B3E0F7565ULL,
		0x2250E91EEC2401C6ULL,
		0x0A835693CAF9E517ULL,
		0x75297D46527433D9ULL,
		0x290ADCF7C4BDDCCEULL,
		0x0F23CD240CBAFE93ULL,
		0xF68D2CD0A5DF849DULL,
		0x8D22598EF699F0B8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x57F531315D972507ULL,
		0x1741325435E3BC54ULL,
		0xB4A38DA553CEDE19ULL,
		0x43BEBDC077F659DFULL,
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
		0xFAA0E5492552B252ULL,
		0x5D7CF31CEDA67FA8ULL,
		0x4767BB8FCBD7DF00ULL,
		0xB6E74E5632285EC8ULL,
		0x2F18EAF51219701FULL,
		0x49A72AD6CA62DE16ULL,
		0xA36BAF51C2EDAA39ULL,
		0xFF49C4EAC2081345ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x24DB61E4999C200CULL,
		0x5E57161AF4C1971CULL,
		0xAB91527F6758EC79ULL,
		0xE13C6FE4CBC1BE97ULL,
		0x4245B1D3F4EA61C5ULL,
		0x30240C651B0F0A65ULL,
		0x95B17EA192795A6DULL,
		0xA09F26EF740BA7E7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFD1FFE4EE0B2B5A3ULL,
		0xC89C61E1FF5654CFULL,
		0xA579A33795C2CAD2ULL,
		0x62FE51BEF9DE9026ULL,
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
		0xE81062A586470918ULL,
		0xCE810DCCF54036E4ULL,
		0x4E85D9F5F5C7FE17ULL,
		0x69792ECEB1EFD269ULL,
		0x4E35B0747DCE7E4EULL,
		0x86DD984FCD18B513ULL,
		0x0FADDAC98B2C8236ULL,
		0x0C51134D93D3B2D3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4E4D141C5E8F561BULL,
		0xBC5DFD5EF4EECD82ULL,
		0x44D7159E21844623ULL,
		0x17C0BC994DE2E15FULL,
		0x9C55BD6BCC91E76BULL,
		0xC23EDD156D796784ULL,
		0x8D2ACE8C884B4F4AULL,
		0xA4EE25B970108FF9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x010161D376B61558ULL,
		0x41B2DB1831F6EC91ULL,
		0x6922956641B146F3ULL,
		0x2A67B632B3041D53ULL,
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
		0xE9B94EF624CA23DFULL,
		0x4A0FE322F03D49C4ULL,
		0x615601D977A1A898ULL,
		0x1B5D8AB0F799F3FCULL,
		0xC1B9C4A4890AA162ULL,
		0x16BC0938A5FD2A59ULL,
		0x3F9F9B250D510F1BULL,
		0xEBC7FF4410585648ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF863A3336B6019D3ULL,
		0x1BFA704C69828915ULL,
		0x6E1E337DFB4A367DULL,
		0xC815FF8FA638DC95ULL,
		0x4F64A8201C6CF101ULL,
		0xB3FC2D39FC910AA9ULL,
		0xAA11EF6AA7435E1BULL,
		0x65DAB54B5DBCD822ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE9F7E76AD8D23B44ULL,
		0xD6901AA3ACC774DFULL,
		0x263F4C06A25FB803ULL,
		0x3480860BD475D0FBULL,
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
		0x99DBE3F3A76DD46EULL,
		0xB208D415DFD6E85BULL,
		0xAD593733A06D345CULL,
		0x72040341641599BCULL,
		0xC16B6BEFBBB197F2ULL,
		0x4C9AD1D61F4C0701ULL,
		0x88CF11C7BD63B94CULL,
		0x682EA15096227029ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8D25188E9096B8B1ULL,
		0x83676CB526C2CD8EULL,
		0xD46A4E59F3EB8605ULL,
		0x46DF971B6CDDC317ULL,
		0xBAE85CACE7E5A38BULL,
		0xC746FF63607E3F6DULL,
		0xF139E91EEB95FDD4ULL,
		0xD2F95E1F3CAE79BAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x042B0F50871D60A7ULL,
		0xF912A4690B9FBAC6ULL,
		0x5912F1E8D10B8214ULL,
		0x510C65793E6E6B0FULL,
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
		0xAB3F6CF4CE3F11AAULL,
		0xA6BBB08440A2AB48ULL,
		0xEF4EB636438E149DULL,
		0xD09D86016D337449ULL,
		0x12F855038D1CD972ULL,
		0x0F3A5C1F0088017BULL,
		0xF5D4A833E9793673ULL,
		0xB6CC51D886E0AF16ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC16196CE082103EFULL,
		0x43E5B53D6DDD7C46ULL,
		0xEFE5FD4DBA5E0EE2ULL,
		0x3B1B3A75042691D3ULL,
		0x96504C8BE663BE67ULL,
		0x22E7383AD50579BAULL,
		0xA4BD2BF11A546FF3ULL,
		0x2B4D0B6C90AAF3FAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6ACF17E98598147BULL,
		0x772D4F2548255594ULL,
		0x08E52AD348A57CB8ULL,
		0x4A66BF92F506A8AAULL,
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
		0xE81A33E41AC4DC5AULL,
		0xFD251D0E4318FA3DULL,
		0xEBDB37815363D7E6ULL,
		0x0A58349D36F92BCBULL,
		0x9C1E3A21B19A8241ULL,
		0x8D022A2C59AEF981ULL,
		0x7D5A5E33273C15F6ULL,
		0x3789178808D0E148ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x595DB906E1325B16ULL,
		0xDDFD51F993DBCB6FULL,
		0x4292DF07113F15E4ULL,
		0x6C0F2ABE2360FBB5ULL,
		0xE4076B197BD96738ULL,
		0xC3F8C8302FF94632ULL,
		0x30839FD6A65F6B71ULL,
		0x4AE6D434F3C16FBDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE21F3615343C8415ULL,
		0xF68C5682E035CC7DULL,
		0x11289A3562E611B7ULL,
		0x3E5F083433E30AC4ULL,
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
		0x2C6F321986CFA4ECULL,
		0xC4D2540C186F169BULL,
		0x5F5592EFE47C48B9ULL,
		0x127DAE923B4E858DULL,
		0xA8F28CB8989CE93FULL,
		0x660D7475EA1F2BAFULL,
		0xB31CA16A732CFFE6ULL,
		0x7966CF6D586FF64AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0570F25E332E515DULL,
		0xFD919E1FFF953DF7ULL,
		0x74B71932EB747F9DULL,
		0x04EFAB4259C835D4ULL,
		0x29D6C664C8B7454AULL,
		0x53DCAB5D0334562AULL,
		0x7D1651B04BAB7E57ULL,
		0x6159496482DB18F8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x051DB02C2FB7AA72ULL,
		0x7A7E8F9E5FB58A75ULL,
		0xEF8E4F5ED6410458ULL,
		0x1F8FE89F959F29ECULL,
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
		0xA1DABF31F551BCFBULL,
		0x41DCFDF492B86363ULL,
		0xC3CA42FB5BB1F729ULL,
		0x4A783B0579F139F4ULL,
		0x9386157ECF5F9095ULL,
		0x82D010B5E5A68742ULL,
		0x3F9D848EA86CD23DULL,
		0x2351D4B419164563ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDA3177C323D31AB5ULL,
		0xB218929406841FB7ULL,
		0x50E4B99D968B99B2ULL,
		0xC1844544C6E4922EULL,
		0xFDB02F432F985F6BULL,
		0xE6F38C3B77216BDBULL,
		0xA58C48443ADE28C8ULL,
		0x7D5F00E7D9134975ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x05697448890FEC6EULL,
		0xB280158CF3F654E6ULL,
		0x51747C6A085384C5ULL,
		0x2AFF6612337E0D0BULL,
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
		0x5EC420DEF3282C1AULL,
		0xB1D74B1F9BA4A03AULL,
		0xB43977A8A76299E6ULL,
		0xA7A28B0CE39252E3ULL,
		0x858184FAB6B88F36ULL,
		0xCD56EB3BF0BC9E4EULL,
		0x44EC72D397D48C2BULL,
		0x8D12DC92E5C974EDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1BF8D6A978AA60CCULL,
		0x098F7BEF2B0F555AULL,
		0x6CE54BD331251853ULL,
		0xA8ACCCD9550ED53DULL,
		0x90D83BEA438F3190ULL,
		0x7343BD4B0EF3259BULL,
		0x1C5CCA0887A58081ULL,
		0x791D594AEBDCD1E9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x93EC22A692A1B251ULL,
		0x0720A0F1F47D3570ULL,
		0x4CA739F9DD393CDDULL,
		0x75673AE2A7A3B044ULL,
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
		0xF0A7F1A7C83FFD42ULL,
		0x7687BF00957AA9E2ULL,
		0x0279A82116D905B7ULL,
		0x06741379C34952F9ULL,
		0x378520DF4CE504C6ULL,
		0xBBE375FEB4B7A105ULL,
		0xCEFBB73D189192CEULL,
		0x35215E64BE6144A5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x60BEF536ED64695BULL,
		0x08599378EC95D828ULL,
		0x4DF629E644FACE08ULL,
		0x9B5B45D203925874ULL,
		0xD00C1C977644A4E2ULL,
		0x647C221987B8783CULL,
		0x2D7AF1A90835CF2CULL,
		0xA58CB6E4F0CB6310ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEBDF9F1AB6A9CD26ULL,
		0x67849F8C56C4DF79ULL,
		0xADA0D2353F7D41C8ULL,
		0x3B29AAA043F676BAULL,
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
		0x9D7BA3BE85E9156DULL,
		0x67B5BEE9EF3D9293ULL,
		0xBF7BF3D6689C5DFBULL,
		0xF426CAB7D2235BFDULL,
		0x69E0D5F18720A684ULL,
		0xDB950FA898DE8EE7ULL,
		0x80AA6E4AD90AF7B0ULL,
		0x3BEDFB8E233C77AFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDD5903ED8ACD4620ULL,
		0x7CC998AFE5E26831ULL,
		0xDB4E2B91955B7AC7ULL,
		0x746E1EE1E7F035C8ULL,
		0x9085C6F8495FDF77ULL,
		0xF8659AE2F150B37DULL,
		0x0A74468B001F09CFULL,
		0x9078431A4717EC83ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x03A6D8D025B95960ULL,
		0xA3F77B90E869BC18ULL,
		0x7037AEBF06463295ULL,
		0x73320D08979FCECEULL,
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
		0xC33A4D5C06616AC7ULL,
		0x12180F75DB4D7E65ULL,
		0x7F12442A000F7822ULL,
		0x4C2ADEF027C75D66ULL,
		0x38D56E28A397E18CULL,
		0xE9BF18BDD30B9EF8ULL,
		0x9985C9A858FB2238ULL,
		0xE9883A1601E50579ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x848E4EA68C6BBD2DULL,
		0x1970F95F124C2EDBULL,
		0x334CDAD541CE9E0FULL,
		0x93C7A6FDEB2F2C09ULL,
		0x271EE1E9A52738CEULL,
		0xD3B5FDEA5C1C135BULL,
		0x4359D6F8A19ABCFFULL,
		0x20663FEE0D65D94EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDFC4D00F3EAEBE2FULL,
		0x3E01117A709008DAULL,
		0x164B6F69F68FE08CULL,
		0x136E59E08778BFCCULL,
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
		0xAFB8470893F10140ULL,
		0x539F55089B4688B3ULL,
		0xB292D0D697843AA0ULL,
		0xBF4CAB0771522122ULL,
		0x4FB487118CEB9D0FULL,
		0x366B8C46927E5141ULL,
		0x0B98166756A3FD3CULL,
		0x46A8CC2729581017ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x91D1694FEC6FFE4EULL,
		0xBDEF620794FCC636ULL,
		0xF053BFA05BA85DF3ULL,
		0xDC946E156ECFBBDBULL,
		0xA414872BF1E9BB8CULL,
		0xCCC6513C969B582AULL,
		0x559958878DFAC5EEULL,
		0x3AF6A43439E38FA3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x97A6D9CDA9C87C9DULL,
		0x4436B67C69FABBDAULL,
		0xC60F406E04FA122AULL,
		0x1F2A2B018DCD7673ULL,
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
		0xD15BA358DE47D975ULL,
		0x9C36E231F27D44F6ULL,
		0x0AD8713814E606CBULL,
		0xC78605C7BA069031ULL,
		0x08D3227AB011F509ULL,
		0x477C961B2C49CF5DULL,
		0x8FB87D0A8172BD49ULL,
		0xD599BA82CCC6E21AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCFFA6AA81B990516ULL,
		0xD6A0EF5478FF2072ULL,
		0x6D153189851C3F57ULL,
		0xE87E053573FB77F7ULL,
		0x5FE127D77332DBF9ULL,
		0x983FCCF52EE84063ULL,
		0x6FC88F08DDBAEA29ULL,
		0x875D0CF86855B272ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x154C6CEBCBCC8E61ULL,
		0xC89BCE8115F95D93ULL,
		0x5B6093ECDD131E27ULL,
		0x7C09C31D2ED82B2EULL,
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
		0x9E8E7349AA116DD6ULL,
		0xDDD04AA03C966B89ULL,
		0x7AB09101B65F3A2CULL,
		0xA6E4CEC9AAF23CABULL,
		0x4AC28F2F08AF6088ULL,
		0x93FED3B009D61D93ULL,
		0x3F5FA5138FD4788EULL,
		0xB387DC2BA2B4556CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEB15636E07A5C703ULL,
		0xE25C8454B4706635ULL,
		0x507363A408CEFBF3ULL,
		0x1C0B7380E97E136BULL,
		0x9A3E8B48893AEF34ULL,
		0x041A96122865E74FULL,
		0xFE4CF771429F3BCEULL,
		0x513A82F0E1535FF5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE711A4128DB47B85ULL,
		0x5754EBBAFECE135FULL,
		0xD302F375237742CEULL,
		0x22549A0175D898CDULL,
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
		0x9ED1C4D35E597D8DULL,
		0x4913D269F09A50BBULL,
		0x33D53C381312BD4CULL,
		0x3E0D86333EF933C1ULL,
		0x327F1FAE26EC52D4ULL,
		0x347F537296DD1BFFULL,
		0x2DBA550B007098DAULL,
		0x7922E6CBC39440D0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9375390631B83114ULL,
		0x16F819A76A961A9DULL,
		0x3A3E113AA0404C57ULL,
		0x273D7E0EB927D213ULL,
		0xB50AA3ADE814DC65ULL,
		0xD90EC5AEC8A46BF4ULL,
		0xA96B57CBDAC399D5ULL,
		0x4D233D081D44BB9FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAAA6F3D6809CE1EAULL,
		0xC4D0C3D3226E57ACULL,
		0x9D50C25D0A804B9AULL,
		0x1EC33B2F359F26E1ULL,
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
		0x52022C5C9A138FFAULL,
		0x1935B24DD82DC675ULL,
		0x7BC86A968E83A0FEULL,
		0x361761CBFC67F7A0ULL,
		0xE3F8995919AC7F5CULL,
		0xB702211D6B54371FULL,
		0x9E48D3955BFA36E2ULL,
		0x707D1F6C2367BD42ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x314C426219FC0FDBULL,
		0xF40B16FDE9912446ULL,
		0xE8B74EB7385BC22DULL,
		0x8824DEFEC8FE21FCULL,
		0x369B43FA012BBCD6ULL,
		0x5CA692AC04154F3DULL,
		0x2D7D0DD7B224AD19ULL,
		0x2D5C1F8E4624E5E5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDC9096182334616CULL,
		0x8EC1C02541F30DD4ULL,
		0x515076068BDA52B3ULL,
		0x24D87DBC0B55CD82ULL,
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
		0x2DA15BCFBC3B5D3AULL,
		0x208F03479E9592A9ULL,
		0x7E74AC849BD00F95ULL,
		0xE2DF519F45D217D5ULL,
		0xCCBC1C1E6A0EBD83ULL,
		0x2DD88D2C97C71F69ULL,
		0x72E3F563948165FCULL,
		0x95AD99B3CFF8619FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x664E2FE99DD24C94ULL,
		0x099E1FDA7A44B362ULL,
		0x4E35BC9DF80D42DEULL,
		0xE8A60CDCBB79939EULL,
		0x4E1ABDA8AE0E381AULL,
		0xF359BFAC14D0EB01ULL,
		0xDBBE875CA91DDB21ULL,
		0x331E76FF06E32523ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x93473160067CE063ULL,
		0xC5C3648094DCA6C9ULL,
		0x9FCD44ED9489691BULL,
		0x1B786B98637F7E8FULL,
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
		0xB276AE4F8F701AFEULL,
		0x35AEF3600B74782CULL,
		0x1B0F75C3C756B57FULL,
		0xA77EA9B9AF71D66EULL,
		0xFA4B3212BBA1064FULL,
		0x5D20C1FCEE2E1BEBULL,
		0xFB01CAEFF607A95FULL,
		0x46D896B41D8E3022ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x28E0F45278FDB84AULL,
		0x07D72F7CE130D3F2ULL,
		0xFD6E4CC123B91B34ULL,
		0x472310DBEF60F81EULL,
		0xCBF429A666F18EF8ULL,
		0xE92D9635C1DE2DF6ULL,
		0x3D56E358B343CF5DULL,
		0x3C7E1F754AEC8826ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6A80FA11A87E19D7ULL,
		0x63F04373BE20F69FULL,
		0x44FF89768CAFF682ULL,
		0x69C94C31040FCDD3ULL,
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
		0x52831759FAB1FF05ULL,
		0x3B025DA1CC0E14B1ULL,
		0xFDE206F1C6A20EDEULL,
		0xEB5F5E6FB61ADD6FULL,
		0x2507D2E0228292C8ULL,
		0x4141D559F2566637ULL,
		0xA3DA2B6E6731AC00ULL,
		0x3BE9FA6D731191FBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x12332CED654DED2BULL,
		0xFD1B51A9AB7EB5B3ULL,
		0x55B8CFC6208D85B3ULL,
		0x5998E373EEF24BBEULL,
		0xEDA2198EE724736DULL,
		0xEA5285EA1D371AABULL,
		0xC5F60CD2E8F6C25FULL,
		0xF7FB35D25B54C544ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x79696C7B655CB547ULL,
		0x256CD691C33495A8ULL,
		0x9805C24062D336F7ULL,
		0x2737AA014D2EF4D6ULL,
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
		0xDDA86AA72C851360ULL,
		0xE82D32B10FA3BD2FULL,
		0xB2717E4FF672C756ULL,
		0xF2640CD40ED0A59DULL,
		0xA77A38BD64053FE7ULL,
		0xAC5351A0559D3877ULL,
		0xFB58EBE256AF1C0AULL,
		0xCFF33AED0C813380ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE9CE56CB0015AFB8ULL,
		0xB01C428DC845EE8AULL,
		0x6AF6DF7948106E31ULL,
		0x917E67916C287FBEULL,
		0xA3D5E0DFFA0B99F2ULL,
		0x64A19323F09976B9ULL,
		0x73F0B5F614DA4441ULL,
		0x2EC6CF63C30B6654ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7E3F1EB9E77E0996ULL,
		0xDC73369A45EC90D9ULL,
		0x60F29FE873FA6105ULL,
		0x4D7D9BA38A249A7BULL,
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
		0x7421143A501097B0ULL,
		0x981E83BDD55BC11DULL,
		0x168E31DC04920A12ULL,
		0x75E1046D9895AA4CULL,
		0xB0B7659EEFF564EFULL,
		0x681C9A082E35FEB0ULL,
		0x8EDB28EEAB94B019ULL,
		0x9D1270097DEC1BBCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3EDA98527E38FE4FULL,
		0x5A5956C4F9187E1CULL,
		0x655564B80292E180ULL,
		0xECE3CB68C91EA43EULL,
		0xB056187B4B787ACAULL,
		0x6956B58139A5AC29ULL,
		0x118300D0E2B6BAC2ULL,
		0x82776AB1BEF3C27BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x43B7EF323C625B51ULL,
		0x0F25190129AF830BULL,
		0x4C4EC18FD2F1937CULL,
		0x7C00040B285445C6ULL,
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
		0x41B8967C4C10A8FAULL,
		0xA3174F49C423B06FULL,
		0x667DBE06BA28E510ULL,
		0x6DC7083DC853747CULL,
		0x7F90F81DF7610CA9ULL,
		0x78227B0B4C82EBF3ULL,
		0xC320186676A140A7ULL,
		0xABD101A826BAF9D4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x672BBAE1295922F8ULL,
		0x83427700D1E66038ULL,
		0x0890CE00605567F5ULL,
		0x6F6833DB55C8768BULL,
		0x3BFDC64C6F3CE4E0ULL,
		0xD897CB06356BF2AAULL,
		0x230D338ED0D85E23ULL,
		0x4617D5AA4EE7C939ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE26640B558157012ULL,
		0xCE6AF90A5FA65116ULL,
		0x20BAE808F5A51CA4ULL,
		0x17DB5C107BE4350BULL,
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
		0xB14F2A4BE3055C3AULL,
		0x23216109070B90B4ULL,
		0xE8712E722362A82CULL,
		0x63174A223AC350E6ULL,
		0x410B428B967EB839ULL,
		0xA7D50A537FE5ED27ULL,
		0x3AB71C6F25581659ULL,
		0x0FEB4EFD474CA01EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1C036262E3849672ULL,
		0x76FE0BA4FF5D6DF8ULL,
		0x228BC0426E604A1BULL,
		0xA2FAB4DF5724EEA5ULL,
		0x5B31A4AA2E61CFD5ULL,
		0xDB1BF045DE9065B2ULL,
		0x3FA1FA4ECD8FB355ULL,
		0x0C5D5BB4FE1D69BEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB399375E73CB44A0ULL,
		0x0F9D3369FA603E16ULL,
		0x0B087EFCBCC110A1ULL,
		0x472EB1FDC0A07481ULL,
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
		0xDFC61C454398E0A5ULL,
		0x768942ECADB79C56ULL,
		0xBAC532198F56BD28ULL,
		0x7BB37CFBA1EEB586ULL,
		0x58B97F7BE58C0E7CULL,
		0x4577DB6E02DB2456ULL,
		0x4F89E3DBBC086195ULL,
		0x44B12445E08CA62FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x96BDCB3ABF14BA6FULL,
		0xEF01297690F9ED4CULL,
		0xF7253E4092E33CF0ULL,
		0x2D3B094055EA3302ULL,
		0xF2648EAC586E2B51ULL,
		0xBC8E1EE67A3BA084ULL,
		0x0F1A14041C36F0D1ULL,
		0x6E508FDFDC40F496ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x79A40FD976F3DDB4ULL,
		0xDA3A1594646B401FULL,
		0x5438CDDAB58A3D3DULL,
		0x20CE7ADFEF40DF43ULL,
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
		0xB790BAF3FDB1F87EULL,
		0x310FF5740689E959ULL,
		0x3BE574FE8E725B16ULL,
		0x344691953F042454ULL,
		0xB831D111BD90F168ULL,
		0x356FBD0F285E12DFULL,
		0xB8C7D6B726406422ULL,
		0xC99D11D6D655546EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD009AB0315FC2D51ULL,
		0xF5AACA4CB7BA0139ULL,
		0x4570EACD8DB98650ULL,
		0x245EEC08AF4D2455ULL,
		0xB8E72D6B618E19BBULL,
		0x99D17CAFD642FFF8ULL,
		0x684DC3FAD9EEF7FFULL,
		0xC8339ACA08B45E80ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCC9B5AA29021CEDBULL,
		0x54E2B94D7ED4B669ULL,
		0xE893522454CEE1E8ULL,
		0x458F5173159B815EULL,
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
		0xB662328CAF092B87ULL,
		0x5C8471619D554E0BULL,
		0x0C935CC55092655BULL,
		0xA9A70225505C7B43ULL,
		0x3EF9CDE45130BAC4ULL,
		0xB77FD9E057749379ULL,
		0x23F0DFF969AC2EB9ULL,
		0x444FF881EB2ECE92ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x917CDBC60FCE3A08ULL,
		0x688C4FF9E15DFAC1ULL,
		0x7AB672057E562EB0ULL,
		0x8E55FA6D344133F2ULL,
		0xD1DB33A1A09EAF80ULL,
		0x3961316FC6E0FCEDULL,
		0x62656D6C1B5699C7ULL,
		0xA38F69E1B6C864FCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x57703CACD4E89B70ULL,
		0xAC85221D31DFABFCULL,
		0x4C8FEBB972F052A9ULL,
		0x77E6337FE34EF38BULL,
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
		0x62CE14E06B30234DULL,
		0x16F112BC1B0E802FULL,
		0xB90B51C76556AE03ULL,
		0x2487D8ED4B719CFDULL,
		0xD39BD84FF3679A94ULL,
		0x6BBF12F6114B7A55ULL,
		0x469AEF6EB662B0E1ULL,
		0x0B98E2664CD55F10ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1E1F608E6063AF5BULL,
		0x36D622DE0F5734B8ULL,
		0x644FD14B34B1E547ULL,
		0x70CFC0038BC3F141ULL,
		0xEBD1E27969F5BCBDULL,
		0x2821595EBA2618F0ULL,
		0xF6029410F58BBCBCULL,
		0xEF647C5DC7EFB19BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xACA9322A71B35CBDULL,
		0xE9847C54FB43C071ULL,
		0x4B591066D08D0643ULL,
		0x637F3E2D79C56B00ULL,
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
		0xCBAD5AB83061F8F9ULL,
		0x88C62F0843AA09FEULL,
		0xA129A1BE1A3B9F49ULL,
		0xB8161C03B19B136CULL,
		0x853D17F58A42B948ULL,
		0x4A0FC525DD136F15ULL,
		0x76ACD899216997EFULL,
		0x70201012D804A181ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F51B904134388CFULL,
		0xE7447850FDD1B129ULL,
		0x15F4DCF235A14313ULL,
		0xB01ACE5454526534ULL,
		0x2A7087B82D4F78E8ULL,
		0x60FF579756C909E1ULL,
		0xF00593D6EB7C1979ULL,
		0x2DCB75D586D76EF7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x36B90ACFE939FFD3ULL,
		0x39F1F9DF34E35E9BULL,
		0x8808F99FE5DB21B6ULL,
		0x608A32C969FE2EA2ULL,
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
		0xCA0F9ACB58720060ULL,
		0xCF92AA0187AD2FB9ULL,
		0x8044A93EAEADB434ULL,
		0xC9E30CD2BAB46CEAULL,
		0x60E9063BD644A342ULL,
		0x0151BFF5E7B276A3ULL,
		0x13351B0F38FA897CULL,
		0x2E08E946A4309745ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8E9C873A810DF29DULL,
		0xCBA599E07122A596ULL,
		0x8970BCE7B8246326ULL,
		0xCAE45FFFAD03BF86ULL,
		0x27AEDF338C72C8BCULL,
		0x17E233E721B9CD89ULL,
		0xA870671598AD04E1ULL,
		0x365D0442244473C8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBA14DECBCC8A7D6EULL,
		0xAA7BDA527973A407ULL,
		0xD006A364C20B000CULL,
		0x4282AB7E0ABDF1DBULL,
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
		0x9796A7813A52760DULL,
		0xDA1EB9F4A7E1BE10ULL,
		0xE1F4A211642A4133ULL,
		0x677717B9F3EA2846ULL,
		0x0ACEA678E22FC9C9ULL,
		0x6DC3723221F6416EULL,
		0x940AADB63DFBAF75ULL,
		0xFAB034857F6F9BB6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8612CCDBF0C474BAULL,
		0x79012483431ED1B0ULL,
		0x43DC381A8F6912CFULL,
		0x4401DC777A2512EFULL,
		0xCAD0C50CF4EC6095ULL,
		0x64429397F94ED292ULL,
		0xD1F571A20C76C396ULL,
		0xA0DA9F9265D2C2CDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x913350AA818FA0F9ULL,
		0xCA3EA0536D9D60EBULL,
		0x6D3F54F62E7C317FULL,
		0x79295758470D47E4ULL,
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
		0x60394B132DC25D1DULL,
		0xFCD8954B111096EFULL,
		0xFF47E642BD8EBB1DULL,
		0xEA2C6D7515544F54ULL,
		0xC7E5BB2A8A2696FFULL,
		0xE2CD41A06602FED4ULL,
		0x3A9937C406FB5735ULL,
		0x1CC5B67808365B4CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3FCDDE4ED936C987ULL,
		0x9ACCCCF9818FEC3DULL,
		0x1B978CACA29571C0ULL,
		0xF7BE02B439B26BB0ULL,
		0x6A30739BF4759CA3ULL,
		0xF8B0D22C9F9B9006ULL,
		0xCD1A6565A78891D7ULL,
		0x87AC41DDC556FA5FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x09540BEE8CD0BADEULL,
		0x2244538102DB1D54ULL,
		0x248393984602954EULL,
		0x1435B9A6C8CA46BDULL,
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
		0xB81EFC45192B0E9CULL,
		0x246B8FC49B38493BULL,
		0xDFD9C270EF240004ULL,
		0x98D3E0C5D3CC7815ULL,
		0x18EAF2699813D7DDULL,
		0xA3E1A1BC1AAC8A69ULL,
		0x25F450D18158F4B2ULL,
		0xA5775FD46596FC35ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD6F6057BDB14910DULL,
		0xF67368CB773B11E1ULL,
		0x302F5384EC0CFC45ULL,
		0x639A301E9FA8C35FULL,
		0xB600F1E1AE4784EEULL,
		0x6A1FE5DCA8F9FDC3ULL,
		0x54C1DF0D30181926ULL,
		0x9481CC15CA06D6A8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8FE50AF5F26ACD68ULL,
		0xC0BA0A24047E17E6ULL,
		0xBD27521012B79A8EULL,
		0x39AD9EF24B89479DULL,
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
		0x1BC72173A06F88D9ULL,
		0x9116FA41E96CC2E3ULL,
		0x30B565FE15DBBE04ULL,
		0xE73193205379258BULL,
		0xBF1E313F7A32F0BAULL,
		0xC60E8068267EE82EULL,
		0x0FBABDF00041B4B7ULL,
		0x02F8C345B71DF3E6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x855B1B1018C8168BULL,
		0x4A9A3909A1175F74ULL,
		0xE4F1D561E4B01D6AULL,
		0xB3F1A448A055873EULL,
		0x62CE856B3B186961ULL,
		0xB6A52E3AA34BFB4DULL,
		0x4B176479B2781A62ULL,
		0xAC5BBAB8D8F514A6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4A3F87E4E59785CEULL,
		0x901EF3F9C1E48CE2ULL,
		0x7C02D82BBD18893AULL,
		0x0E8F33C0AD34C1C3ULL,
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
		0x306DDDC80C0A47ABULL,
		0x614AF87A96E32A1BULL,
		0x5536CA3B755BC6D9ULL,
		0xA5A2714AAE8B732AULL,
		0x793433473848A3FDULL,
		0xF7B276558027FF4FULL,
		0xE1CD68ADCE68568BULL,
		0xAF97F2186C68A095ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x06B8ABCC2F9B7D5DULL,
		0x53709F5BC22FCC14ULL,
		0x7EEB5E61BF4314B6ULL,
		0xB21B45D3DBCEB140ULL,
		0x91A778FC0CEC2EBBULL,
		0x1801086A1FEC98F4ULL,
		0x7E7EE9F52687C75EULL,
		0xB3863A4B25F5F3E3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8898D9244C2831F4ULL,
		0x4230AA0F1D848F85ULL,
		0x93F23B42A16DF2F2ULL,
		0x5E2873EF47C26464ULL,
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
		0xB620A1F4D6DE460AULL,
		0x2008FF004C91ABA5ULL,
		0xB4580BE6188AF9A2ULL,
		0xFD01CDB7FE68D903ULL,
		0x8661B275DDF03576ULL,
		0x6E0FFBE0B6003F30ULL,
		0x2E7DE960AE3EE7BDULL,
		0x3618CE45D383B12FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x24677B26CF12DF98ULL,
		0xFBEF26CBF39AEAFCULL,
		0x127C62DE0E334F27ULL,
		0xC1302F6C130337AFULL,
		0xFE15FC89F2DE2962ULL,
		0x63A0AB140BA326DDULL,
		0x5529425DE935ECAAULL,
		0xBD26B474639DAA36ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCCF627D2EC792E72ULL,
		0xB09FD695A2C85CE9ULL,
		0xE46C737149ACEF4DULL,
		0x2FC17362878AAA44ULL,
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
		0x89CA3FE8903255CAULL,
		0xB82627E19BBE453EULL,
		0xB4A5AF134C27F0C5ULL,
		0x74A779F8774032C7ULL,
		0x933F18DD3D09E10AULL,
		0x86DD46E5563128A4ULL,
		0x1099285FF467805CULL,
		0x3A7A3DC6234C7C17ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0153259B81949E34ULL,
		0xC5685A3DE853D12BULL,
		0xEBFC5D780D929A35ULL,
		0x6283460FD7506249ULL,
		0x15C1FDB30130E52FULL,
		0xB7888665FFF3D05EULL,
		0x8C4DF78428097CF7ULL,
		0x9B719CAF8E2AFFF9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x29092291F0D317F1ULL,
		0xB952608A80858E8AULL,
		0x6BD2923B9489D786ULL,
		0x2D6C1D42C2E83CDFULL,
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
		0x3D287FAAF10CA3BEULL,
		0xFBFC38017DAA8068ULL,
		0xCF7F2A97603DDCAAULL,
		0x458104D53DE88633ULL,
		0x4E32882374850C93ULL,
		0x01D850075F2851DAULL,
		0x53F41E2A1ED5B767ULL,
		0xC301C4DA934DA9C4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA8E38F6D82EDDDE6ULL,
		0x15BF2731FD856A8DULL,
		0xD177B23AB605395EULL,
		0x3345751E4DC0A549ULL,
		0x0CB2077A47D44A11ULL,
		0x2DA57C61960B7BE6ULL,
		0x2C8E594BD4AEC40DULL,
		0x2735273CCBD96E39ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4D58095A105BA88EULL,
		0x65C87B6B5A6CD81CULL,
		0xD722B15BAC00C2A2ULL,
		0x329AF5228B68B791ULL,
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
		0xBD0DECA501FF2215ULL,
		0x3DF571346A9B3A06ULL,
		0x1EE18570A06A264AULL,
		0xCA40E90547028ABDULL,
		0x551911C7DD7C42E8ULL,
		0x9489F49B234A41DAULL,
		0x047BAE44AA7A2242ULL,
		0x98BBD83198AD9AC4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF5AD8876A74FE43ULL,
		0x6737717583531524ULL,
		0xD9129A2EAF9EA6DEULL,
		0x41E1C96071CF6865ULL,
		0xEEE48EFD1311FE54ULL,
		0xCE6BEC8B7236A112ULL,
		0x466C0D241E610B43ULL,
		0xEB8DB1A3818EE6A1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x397E7E37A3505002ULL,
		0x3F3332133032027BULL,
		0x7C20D616BC84E93DULL,
		0x3D38D8BC43C1DF7FULL,
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
		0xEB42E76C8399DAB5ULL,
		0xFD739542C7452A19ULL,
		0x580E943ED0C8A324ULL,
		0xDA95013ACC1D7F5AULL,
		0x65ACA2FE056E0967ULL,
		0x28929F4C9B15E20BULL,
		0x78856A2297FA86BAULL,
		0x9D084FC648971677ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8F1BDD7C9D84D422ULL,
		0x08783D7A821FFED3ULL,
		0x2F6B7CA1A92D726DULL,
		0x73E8A40699505A65ULL,
		0xE7F7DA895D4238AEULL,
		0x4B2DA46DD08359CBULL,
		0x4C16A1E1D5061BF3ULL,
		0xB782771784EFEBE1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x04FCCB40DC960171ULL,
		0xD1F894DA56E564B3ULL,
		0xC114D13A17E30A3CULL,
		0x788A87253D9D773FULL,
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
		0x7B7A107AC11F356FULL,
		0x9F60944007E5FF09ULL,
		0x2BCA3859533520ADULL,
		0x8A7A1654E348B6B1ULL,
		0x11DD40E4E225BDCFULL,
		0x5E9AA4EB95136A6DULL,
		0xFF8185D33A84045CULL,
		0x26C344844EA1F4AAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x985032D0AA7389D2ULL,
		0xC5D9BC9DCEBC1B40ULL,
		0x626F91DE305EC4E7ULL,
		0xF714F28A7BE209D4ULL,
		0xF3FDD143E2C3E9BDULL,
		0x75CD0AAAFF1103FEULL,
		0x684B0F671D254B3DULL,
		0x6B740C81F932B270ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x52546F8FFF3124A7ULL,
		0x680BBD387D851821ULL,
		0x3B703A877EE5D65CULL,
		0x6127742315EA818FULL,
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
		0xB925387F7EE35BF6ULL,
		0xF7F240C7B3BCDCA1ULL,
		0x0447AC8773F42A98ULL,
		0x1DF0EDF96D18C20FULL,
		0xB371B574234B015AULL,
		0x79751E0C89098DC3ULL,
		0xAA8D52C6DFDE61ECULL,
		0x1A3743E33512EAEBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDE1FE0324175070AULL,
		0x92C953442822D47AULL,
		0x57018722A31DC060ULL,
		0x32EFD325E58DBF0BULL,
		0x86CE1BE02037666AULL,
		0x81F7C2BA0855EC48ULL,
		0x594DEDE1AA444BD3ULL,
		0x40C7B6503FE6C13DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7B4E2445B25753A8ULL,
		0x21C47BC2A644006FULL,
		0xBCAF1F6AC5B5B1EDULL,
		0x31901EA3EC1932E3ULL,
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
		0x028EE05D9A8CBCD5ULL,
		0xEC495A164E8B5AE0ULL,
		0xEBD63A815FC421D6ULL,
		0xD07FDDC876390B85ULL,
		0x6FC4ABD93BF8C097ULL,
		0xC204F788A9A84ECCULL,
		0x396E04E2B2F453B6ULL,
		0x9BC0447FA572D7A1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x78EB0ECED8C98688ULL,
		0x5E3696AB3825FC23ULL,
		0xE3245478F3890823ULL,
		0x9D4899E3039DA864ULL,
		0x7CBCE0AFBF41F0B5ULL,
		0x6EB6B576B9ABC919ULL,
		0xB293D47E0629AE2EULL,
		0x38265E2EF9019FB6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9CCBF9B744E61400ULL,
		0xEBB09214B5E1374CULL,
		0x0D1514FA124FABEFULL,
		0x7C0F73DF0B69AFF1ULL,
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
		0x1E7A359869F8A758ULL,
		0xEBE5F6775085A0D1ULL,
		0x7F888DCCD50DF4A9ULL,
		0x923614278C7689CCULL,
		0x4C551089DD5475DCULL,
		0x1C2B24D9DBFAB1AEULL,
		0x83AC4FD6DE314D84ULL,
		0xFB541E389681E663ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE5FC2FAF2D528ABEULL,
		0xC9B8DE0147FA09C8ULL,
		0x5523EDC9E39C6E35ULL,
		0xAF9619B2D8E31CDDULL,
		0x1285F94C36AFABC6ULL,
		0xE4DC2B967A495CADULL,
		0x340979EF55B6ECBBULL,
		0xB94CAFBACE5FAFADULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCD3B790FF91C1D47ULL,
		0x57E6187688DE3536ULL,
		0xFC906061339BE42CULL,
		0x2FBA612068A78BFEULL,
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
		0xE9205E02B19BDFB2ULL,
		0xE2FF3B66001BCBE7ULL,
		0xBA4C6BE4B2929DC0ULL,
		0x3DC085F0EEA0BDD1ULL,
		0x76889E27A970474EULL,
		0x6484D3342A6F568CULL,
		0x814966014FD82671ULL,
		0xD2792345698830F6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xACC89BD116DEF462ULL,
		0x61A92CBBE3615D99ULL,
		0x22B7D88201CDECACULL,
		0x4469BE8A379095B1ULL,
		0x2AC255A4B54031F9ULL,
		0x970DF137C0C0519CULL,
		0xB7CA4AE2B48D21FFULL,
		0x431BFC777647B701ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7BC685A1D9E0190CULL,
		0x00FB9A21CCB529F9ULL,
		0x807299EDBDE759F9ULL,
		0x412A89F8D2A24276ULL,
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
		0x7B7494F0E1B0C5C4ULL,
		0x2C46B664A7113526ULL,
		0x65D10ADEA6ABD3C4ULL,
		0xD68E9A56C33F59C9ULL,
		0x6699FFEF07C18358ULL,
		0xC20A44F7DAD6548DULL,
		0x9CB49C7A1A25B6BCULL,
		0x09786EA9A5431D0AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x755840962ECDEE63ULL,
		0xCF6F473323E9D5C5ULL,
		0xCF6A64803E3EDE27ULL,
		0x5B14ECB8C8F00AEBULL,
		0xD96C281FF18DB0EDULL,
		0x0A2C03BB56B31B6BULL,
		0x6B9A3C5C1D3DB8C9ULL,
		0x3C6843FCAE1DB196ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFAEA5D17FE941226ULL,
		0xA7D51E2D2061DA5BULL,
		0xE050EAD1F2DCA7C9ULL,
		0x6BE0034AA9DD421CULL,
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
		0x20650A10F1C41B42ULL,
		0x012B8BCBCF3033A8ULL,
		0xA28041D05DBBD486ULL,
		0x75468054FBC8D159ULL,
		0xBADDA449669198FBULL,
		0xBC2B2C3F47ED0176ULL,
		0xAA229B61193C8F29ULL,
		0xE3D712784A8567C8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE31E93AA6FA3884BULL,
		0xE05510341AE770F4ULL,
		0x0A0AE6CF84B2F45DULL,
		0x842F9B4BCE2D4040ULL,
		0xA2A11F1334AB510CULL,
		0x425AD8DD47A10958ULL,
		0x4E7D246F4430BD1CULL,
		0xD7CFB0203E763C32ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD6423C71EA4F40AAULL,
		0x35C2DC23BF8F972AULL,
		0x330502E678CA0E28ULL,
		0x3A2F7E1AF7DC096BULL,
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
		0xB7DD05DB0706B5A8ULL,
		0x8925EB94A1ACC8A0ULL,
		0x8E0FADA2C4E3CFB0ULL,
		0xA2DFFFB7A7B9786EULL,
		0x82585CC00839DDA3ULL,
		0x1FA2E288263FC16EULL,
		0x15D34724554A6109ULL,
		0x0C333E88D809C78DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x726467584A19285CULL,
		0xA432C228ADA9D9CBULL,
		0x442433AA33DBA1C8ULL,
		0xE7761D889613B0ECULL,
		0x8CEDAC7F0612EA55ULL,
		0x9770764B4B458A84ULL,
		0x9E94E516FFDFFC52ULL,
		0xB8E454CB310CCC5EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB34EC8290EB5A704ULL,
		0x1C6F3A747527158FULL,
		0xFD2E07F33ED32100ULL,
		0x19209455DB331067ULL,
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
		0x237AA3C554623C4CULL,
		0xBC7DF0AC5379B74BULL,
		0xEF922EF344842A10ULL,
		0x23301EFD3F031752ULL,
		0xA3BD9E06A2548A91ULL,
		0x7F846E3AE6BAC9B6ULL,
		0x62B0400C07ABCF20ULL,
		0xD2F5A1D1B4639BDAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC41D904872B775A5ULL,
		0x5BF35EED7EEA9A2FULL,
		0xD6A62E7197D90A5DULL,
		0x3BE46CBE4455047FULL,
		0xEA9FEAA848F0FAD7ULL,
		0xBC3587029F4D6FDDULL,
		0xDC7FB626F12EF979ULL,
		0x9A184E626A6D6D77ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD9C5B37E26721D73ULL,
		0x5E40E4196ECA7346ULL,
		0x042078830332D674ULL,
		0x582614C3F538F573ULL,
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
		0x33A0EB4382068C3DULL,
		0xB1DDF956C82721ACULL,
		0x3C4C68FB8478827DULL,
		0x1CE8F9842D680D7DULL,
		0x4AB4BF95CC12B955ULL,
		0x9F499D17865BF68EULL,
		0xEAB4772765693AFFULL,
		0xB36B6BDDF5052BE2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9F9A6AEFFD046DCAULL,
		0x3E5ABF701C315EFAULL,
		0x0465D46D913A608CULL,
		0xF366A039370612D5ULL,
		0x0B3F3F4CDA1CCDDAULL,
		0x3A4421314E7B490EULL,
		0x9EA53BAC212E9E91ULL,
		0x2B3181EDD5FCB6F0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFF778B276F831587ULL,
		0x72539E12F74F83BAULL,
		0x822968DA13F15A54ULL,
		0x621B12EF91A3569FULL,
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
		0xD9FC5FBBC375CB68ULL,
		0x505954FAE95B3299ULL,
		0x5D43E95A3ABF319FULL,
		0x268F5A57B4827AD5ULL,
		0xA643E56165EC9C89ULL,
		0xF528CA0FE1D44C5CULL,
		0x5B8DB02FA44508EBULL,
		0x4551792AE6D728B4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCF41B186BA2A5830ULL,
		0xFB78E88BA998B7BCULL,
		0xB3C5E4CEAA89947BULL,
		0xA1623931AA5445CCULL,
		0xDD573B1AF89F170FULL,
		0x1EBDDF0ECE210CDFULL,
		0x84D03FEB5614F910ULL,
		0x1EEFF108D8868C64ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDDDBF4A942CD4412ULL,
		0x28BF4E982C5DE762ULL,
		0x899CAEAF2B57F7C5ULL,
		0x37A756342A2568E2ULL,
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
		0xA9F890A2A5652D63ULL,
		0xD8DA10107358F89AULL,
		0x45F0483AE951AB7AULL,
		0x60FD14043EF66709ULL,
		0xA962DA98F41B293AULL,
		0xF78B21AA26352044ULL,
		0xA936535FFC5A6A0BULL,
		0x5EB293C07C07E88FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x79B48B0A00BE3FDDULL,
		0xECF053060999E352ULL,
		0xAC7B84E57B6D357BULL,
		0xE8507A678BCB3C52ULL,
		0x649CF7936C2E85CDULL,
		0xAFE564222CBA311CULL,
		0xC1B777693784C26AULL,
		0x1788FF932591B3DDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x65A3B86AD1C73130ULL,
		0x8E83DF3971FE9542ULL,
		0xF64969F6A59B57EFULL,
		0x08D8985788B6FD1EULL,
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
		0x4D0116075F485921ULL,
		0xE8CFF5B810E737E3ULL,
		0x22D06B4C380FBF60ULL,
		0x3EE88AE24F3D86C6ULL,
		0x10C90EC323F34D26ULL,
		0xFDC5FF4914672181ULL,
		0xDBE2DBDD7241E7CEULL,
		0x89CA72A6316DE1F4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x726CADD43CA7473FULL,
		0x95C6419869DFCDCBULL,
		0x38483EC7F5E355D8ULL,
		0xA04F5669EAECA225ULL,
		0x1ECCD6B5095B6670ULL,
		0x43739A880AD3F8FCULL,
		0x1B1FCF502AC99B30ULL,
		0xAEE2456B4E9BFAE2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC604BA4B152D5002ULL,
		0xFB44A8C712DF6DD3ULL,
		0x877C097CDE07C917ULL,
		0x1D0FEB360F793169ULL,
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
		0x3B85966138FCA426ULL,
		0x87DD05671B59C36EULL,
		0x9EF74DC5AAAD3E85ULL,
		0xE84683EAE75B8E44ULL,
		0xA327BE2486E6A76CULL,
		0xBA90898599787E52ULL,
		0x9F6C77926F6CD232ULL,
		0x1E81A4D289DF8015ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE21E82FF77D7C57CULL,
		0x21D537D1A05DAFC7ULL,
		0x4908E84BCDED7F64ULL,
		0xFCDDE571D9C1EF89ULL,
		0x8A5A3A37214D6F52ULL,
		0x3F9B050821DF0EE2ULL,
		0xD9DE32C00C2AA95EULL,
		0xDA092D0F4099BC9AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x07E8A89ED5E32E5EULL,
		0xA67978353BC29E4AULL,
		0xA90C9CB49891CEABULL,
		0x154A6575EDF4A2F4ULL,
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
		0xEE2126E132D4A3BDULL,
		0xA9645A03DB3CB71FULL,
		0xD5180FDD0FCB0ABAULL,
		0x9638788F61A7105EULL,
		0xA7AB8364BCF4DF5FULL,
		0xA83ADA55DA02AB7CULL,
		0x131DC1A0C508FBE8ULL,
		0x3C0FDA8F6C0608FDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5FD4EF337C73D33BULL,
		0x2BDE2FEDE44F3F96ULL,
		0x75164DA1EE746F24ULL,
		0xB2F4554F58E719A6ULL,
		0xE5B05C15908A437EULL,
		0x796C4A5A7B0E272EULL,
		0x5B451DA33711BB76ULL,
		0x707669DF662C7B3DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x59940D6E4E33F2B8ULL,
		0x702F89660F391B14ULL,
		0xAA2A19DE340A2C89ULL,
		0x1C0ADD60E70B012DULL,
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
		0x9B35895DC26A66F6ULL,
		0x6B1E484FD195CE8FULL,
		0x01B696C62D44A32AULL,
		0xE8D98BE487706CB6ULL,
		0x88D850B7E4A18CB9ULL,
		0x9B9F7650DF62D05EULL,
		0x00703D2C41F3BD97ULL,
		0x93CC761306A050ADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDC08E468FA34D929ULL,
		0xCABA0E097154F5CDULL,
		0x408232B79E234B5AULL,
		0xA1F835B86614F7BCULL,
		0xF9D828C1AF687FC2ULL,
		0x3AE79CF9E74169F7ULL,
		0x5BCA559E20C57242ULL,
		0x75D2B32E6C132BEEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF9329380AEAD7B22ULL,
		0xFBAE7D2F35360BFAULL,
		0x31D4C3277C00867BULL,
		0x39F4441B124EE946ULL,
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
		0xC83408F787A0B6BFULL,
		0x2D799F0AA778D800ULL,
		0xAC2D836943B0500DULL,
		0xC8174E5E3AF8A841ULL,
		0x17C449CE21FE8336ULL,
		0x98230A6386F81E4AULL,
		0x58A093C9A150BFAEULL,
		0x9E7FC3CDBB18A0B3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x54A5D9C208979A96ULL,
		0x880B9B9B44E868C2ULL,
		0xC26888C1C1A7A1C4ULL,
		0x629B6D742ABF7DD3ULL,
		0x4C8E2B3F29280E60ULL,
		0x542A02BEFB86B679ULL,
		0x0D352FDF68A23700ULL,
		0x7DE0D70546B0C081ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9D96B86E6EDE74ABULL,
		0xBC6525DC1565D83CULL,
		0x1BB5CF6BEBF0F826ULL,
		0x3D1306AB57A471E5ULL,
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
		0x79889B523C61B4F7ULL,
		0x4012741E652B16C4ULL,
		0x50876BB26ABE8998ULL,
		0x9BE198733E88A269ULL,
		0x1A8B322C95D7CCD4ULL,
		0x3042B8F18A458AE1ULL,
		0x1C4BCC9C6A9CE762ULL,
		0xCAED4FBD4803BB34ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x35BD717752D5FF43ULL,
		0xF3995974623E2ADCULL,
		0x24AEA40F4D296078ULL,
		0x07DD1D7CEB47C40EULL,
		0x99632D850F6149E7ULL,
		0x9F8AEAEDCE328679ULL,
		0x2BAB2743EF84B483ULL,
		0xB1638722880F206DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6FBBDAB8DF23257AULL,
		0xC7C1AF37EDBF9345ULL,
		0xE3B152C5632CB628ULL,
		0x5E7841EED18FD7E2ULL,
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
		0x3F935359F5D92E41ULL,
		0x551C3BA164D277DBULL,
		0x3AFD80313D0C2E63ULL,
		0x2DDF4311981CA8ADULL,
		0xC0B596DF7B349960ULL,
		0xB545ABC05AF94404ULL,
		0x97AD8A8A4F33E093ULL,
		0x2EF8974AD6F8691FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4A00CDA35487BAA4ULL,
		0xE020DCB83AE45A5AULL,
		0x36907FFEED911714ULL,
		0x6A55382B7DDFA942ULL,
		0xF49F25299A3544B5ULL,
		0x6BED51D6D5B167ABULL,
		0x073DAD543D01AE7CULL,
		0xB4B93E8D2E425109ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x40E766B6073801F4ULL,
		0x5818B792F298D2AFULL,
		0x7507D63902EE86C3ULL,
		0x68F1370D254492C4ULL,
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
		0xC0BEA5F54AF48664ULL,
		0x631A26EF60B7A4EEULL,
		0x6DD6EFBEBF78EDE4ULL,
		0x4CC61D642BB37150ULL,
		0xFB1990B30A01188BULL,
		0x158E7B607EB8BD6CULL,
		0x75493D6ED9C489BBULL,
		0x72462D5B936C0111ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9E0EDC1D1D7B1160ULL,
		0x143DCF296F6676C1ULL,
		0xFB9E43E392FE512CULL,
		0x2998F1E5550B5B4EULL,
		0x92EF73F15B4D55C6ULL,
		0xB3A185B9902CA7DEULL,
		0x55FB5C37EE721B43ULL,
		0x708ED8CF318D6DADULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x98F00E981C285E42ULL,
		0xD808CE8D5A1C6150ULL,
		0x17C81A021AB70270ULL,
		0x6463B8555DB1F6DEULL,
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
		0x82391134590EE4B6ULL,
		0x00C227186444E9F7ULL,
		0xA9B6780A4E96EB8EULL,
		0x786D83F3053433BAULL,
		0x6C02EB46A6910D4BULL,
		0x6AF4F21B8613929AULL,
		0x9BD9E0AD2B976BF2ULL,
		0xA75B86D1EDB0572AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC078FBDB84BBF7FCULL,
		0x9B34DC363521292EULL,
		0xEEF3A088B475F167ULL,
		0x006D7D89F636762BULL,
		0x9CD0BC040A358919ULL,
		0x8C664BD59B7348F2ULL,
		0xD08708A3CD1FAE94ULL,
		0x11CD504C4859E3CFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8333193C09E88F7DULL,
		0x6EB9F94302EEAFB1ULL,
		0xE90EE8E59FE71615ULL,
		0x2B1C1E3F99D2DD08ULL,
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
		0xF1E13634974C87FEULL,
		0x9196A3B72700D436ULL,
		0x61D24290E36E010AULL,
		0xC91BB5FD3D43200CULL,
		0x9835391D3E3EC9B4ULL,
		0xF211798E7D85778AULL,
		0x67ED072C49D4FCEBULL,
		0x7ABE51F7DBE92DD1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCE0601152E085653ULL,
		0x8EC8DD461AADF7ECULL,
		0x6094602C4D2523FCULL,
		0x013DDECB733E98FEULL,
		0xFECDFEB62443DCA9ULL,
		0x5C2DFA5B1949A92DULL,
		0xBF2874197AA972CFULL,
		0x562957E5D76A8415ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE92DE06D44836231ULL,
		0x4292A811ED337E08ULL,
		0x0E6BB72F56BF5D4CULL,
		0x35FAF5DE74D1B8E9ULL,
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
		0x624E8BB02F8DB5EBULL,
		0xAF8EF7AFF88C42F2ULL,
		0xF486C6031C0647C0ULL,
		0x6150F394ECBC3ABFULL,
		0x53DE03ADD7E2BC93ULL,
		0x1EA60CEAF6D31A82ULL,
		0xAD20B4FC915F9E3BULL,
		0x4A64A8616CDA9F1BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x476973EE6D1BEBBCULL,
		0x466DBB03CDE27316ULL,
		0xB5E185C8A4ADBAD6ULL,
		0x5A268E1665C6C04AULL,
		0x49D23EACC49DF77EULL,
		0xE4FD056A5B09CE2DULL,
		0x0059E11003094CABULL,
		0xDDB4756BBFF361C3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x98A455EA9EA70809ULL,
		0xF83859C34A8B247BULL,
		0xE428B5579828A82CULL,
		0x2951F5F63148959EULL,
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
		0x9A2917FBE6084586ULL,
		0x039D5D100565E0F4ULL,
		0x8CA25EC497A83659ULL,
		0xA6C1566E05F86C88ULL,
		0x44913B04BEE3F525ULL,
		0x2FE289DA47C6B9F3ULL,
		0x7039E1670EF1ECB5ULL,
		0x2587C738121AE510ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAC18CD8AFD68981EULL,
		0xB17FB55E7D3BFBF9ULL,
		0x801BF3CBA2CEBB23ULL,
		0x7E41FC34696E13CBULL,
		0x87D0080ACB2D8A12ULL,
		0x583A9C6E86F61425ULL,
		0x5275AC4F846E8EEEULL,
		0x6ACFCF78A8E537E9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF2BDDB8B15B390ABULL,
		0x550AE5B027228184ULL,
		0x77A64C77845966B9ULL,
		0x5FCE20A33A820C8BULL,
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
		0x5708060FE786808BULL,
		0x69D04234DB107091ULL,
		0x33DC7A1302A59107ULL,
		0xF43CA82C75AF1FF0ULL,
		0xE5C9CD6F60790D07ULL,
		0xD2AE6E64A3F59445ULL,
		0x01678C28136D9294ULL,
		0xB246C78060C68381ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x46F90E7BCC5D4186ULL,
		0x6DE4C171D0EEBF8EULL,
		0x07ED13E2222595C4ULL,
		0x8DD1B91254CEAF52ULL,
		0x302F1A81FE55849CULL,
		0xF7D157D88CC2ED88ULL,
		0x37C0E3E1334E2F65ULL,
		0x8DE62AF38C49C5A6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x050586D0AC6F7FB8ULL,
		0x78BCD98E7BA6712CULL,
		0x1AAC60B62528B437ULL,
		0x4CC22C01AB649F18ULL,
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
		0xC30B64BA16B2A3ACULL,
		0x36D9CB1C04742813ULL,
		0xC1C55735096DF482ULL,
		0x1291C2436BB17474ULL,
		0x1431C84C0E48933EULL,
		0x0DF13A928FCD270DULL,
		0xCFC18802901B6860ULL,
		0x8A8DAEA508854E0AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFB697B4993872AC4ULL,
		0x694DF96B6770D5E1ULL,
		0x7B5A752014C167E2ULL,
		0x0F334F9AD6A72B92ULL,
		0xE497D35F9A3E7963ULL,
		0x80578A57AC42303DULL,
		0x7E645AE3D4062DBBULL,
		0x7E103FA9D7A5EAC2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD87C4489BCAB4FA3ULL,
		0xD25BFA6E63A3F4F2ULL,
		0x5A3F94A4DFD3410CULL,
		0x5DFCEBF1D633059EULL,
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
		0x25B0D9939701A5ADULL,
		0x889E754F241E73BDULL,
		0xA3D17D12288509D4ULL,
		0x886192F81B38208EULL,
		0x9B5DFD3343EA332CULL,
		0x19A89B209D96A89CULL,
		0x37F52A61B91B67CBULL,
		0xA06820ED6D32262FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x81E2651733ACB1C1ULL,
		0x9B173AF663544DF8ULL,
		0x660569105DBB03A0ULL,
		0x0A6E04D75E7DA370ULL,
		0xF4115A713DE559D6ULL,
		0x7224517190F1F50FULL,
		0x51792E8CAC051C2AULL,
		0x5D089E700E035513ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x792E9D49480D382CULL,
		0xCB2A2A54A13CCCA5ULL,
		0x743375A1BC19400CULL,
		0x7E20ECBCDDAD8742ULL,
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
		0x2D499B8CDAFB1257ULL,
		0x3E0C6669A3BB05D9ULL,
		0xC2ED52E9BB4B06F9ULL,
		0x909628EF64EC1979ULL,
		0x823E3E5BD5E3F1BDULL,
		0x92787DAAF93F1AE5ULL,
		0xF0271F10E61CA458ULL,
		0x32292C379E7F1B89ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x169E28224805305EULL,
		0xC8E79533493B1E50ULL,
		0x7F5E93786DFB6AB9ULL,
		0x46E9488B36270563ULL,
		0xDED7001FED2D634BULL,
		0x872A7DBB9BDB3749ULL,
		0xC39AB52928AA954AULL,
		0x3741B1CEA3A206DBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x57FEB04F1E0F06D2ULL,
		0x22B8CEBE3753B0A3ULL,
		0xE06677D76C3DD855ULL,
		0x08090BF96B9625F0ULL,
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
		0xED361857EA6F7237ULL,
		0xB4C25008852D2075ULL,
		0x47FDCB75E70C4A63ULL,
		0x95447035CD2DB47AULL,
		0x71B696B67AEB58D0ULL,
		0x715DF4751A7274E0ULL,
		0xFE9A95BB00BEB3E3ULL,
		0x51408190BE3E67F7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8E53F82D156D2099ULL,
		0x5C4463B1C570FCD4ULL,
		0x5848CD8660006160ULL,
		0xE49278F9266C70F9ULL,
		0x6D30E5B8D27F8343ULL,
		0x4041C8724B9A0040ULL,
		0xB2A30046EEFDBCFFULL,
		0x42535574275926C5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0ABA65D1D50404C5ULL,
		0xA2AC74C173DD7362ULL,
		0x36752D2A29B08EE2ULL,
		0x67E6837B0CC8F0F8ULL,
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
		0x721D7C3342670D8EULL,
		0xD76F4C7BCFDD106BULL,
		0x3D1FEC55B5D6DCA5ULL,
		0x422758A6E0304779ULL,
		0x26B0543DB764DDB3ULL,
		0x63363B02ECDF7A6EULL,
		0xC4F3C344DE9F8FBFULL,
		0x8EFA2948E8049C92ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5294052F8D622C47ULL,
		0x6655EFBEFB611D56ULL,
		0x79162891673A847FULL,
		0x3D07A2C54618BAADULL,
		0x9D2CEC243B565C5DULL,
		0xB2C30694AE0C6CB7ULL,
		0x1FFA37D1489A09D1ULL,
		0x2D6785A4420A8568ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x890AEACC1F2C1632ULL,
		0xA233251A27CFFC2DULL,
		0x411476EC936E396EULL,
		0x00E400523D36FD20ULL,
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
		0x5561610AC30BD026ULL,
		0x5BDD74966A2D06E7ULL,
		0xCDD6447D7C3332EBULL,
		0xF8FA2450AAB407AEULL,
		0x87BFA672C54D2E11ULL,
		0xA161548695126BC3ULL,
		0x2D36CF2D0E9E3328ULL,
		0x7690A97907D6A107ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5618427F5C45575FULL,
		0xC236C3976BB41B6EULL,
		0x007828BA25B392C3ULL,
		0x194E12DDACC8CDA7ULL,
		0x35C9150F022A9B27ULL,
		0x528DE3B43799A52FULL,
		0xE8A340BE9502A1FEULL,
		0xB0CFE0BF78C2CF66ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x29E2B35A5DE84653ULL,
		0x4D097038DE66657DULL,
		0xFB45402963972C6FULL,
		0x3A49DCFE3ADC57D1ULL,
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
		0x561CB5CDBD4971BAULL,
		0x889DB3D410E9E96CULL,
		0xE3D80CBA63F3800CULL,
		0xEC61D45511BC40D6ULL,
		0x10ABC2614B953E5BULL,
		0xA47ECE4A98B84020ULL,
		0x15ACBD8634831BBFULL,
		0x23BFA519084C19A4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC84944CFB5298711ULL,
		0xC93535E4B1FB606AULL,
		0x2DDFFF4FE6B56B94ULL,
		0xCC30782CB52334A5ULL,
		0x1441093D04A78A08ULL,
		0xE70A2AE40D98A055ULL,
		0xED274AE688EAFE2BULL,
		0x85557621AD995C20ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x05AAEC608F68ACD4ULL,
		0xDEB8BF2805A04123ULL,
		0xB9C7111DF5D27865ULL,
		0x23F454DFD3212DA9ULL,
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
		0x0C2363627E8FD8D5ULL,
		0x4976FD442F2AFD3DULL,
		0x88CAB7BAA79DA5FCULL,
		0x3F8E97E063207DDFULL,
		0x6C6298A4154D9E5DULL,
		0xBB7C1632A88F3CEEULL,
		0xA1A45C7C43F6A9FFULL,
		0x2BCCE290C97E2818ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x722DDE7C441946B4ULL,
		0x00908D96C4570B5BULL,
		0xBA095DF6F584D1CEULL,
		0xE2A0D919BEA8CCAFULL,
		0x5E0024BD3648B452ULL,
		0x1492667C86DC8378ULL,
		0x87DA26232729FBD4ULL,
		0xB877DAA32F732CA7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBC92B92B55314C7FULL,
		0x0F9684B66B5B7967ULL,
		0xA2C56AFDF87AAEA9ULL,
		0x7B8CEC0B821903F9ULL,
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
		0x6E9F7364F452EC1BULL,
		0x0E27D562B85E2DA1ULL,
		0x72E0D6BE191E8BFCULL,
		0xD723E5FD3A8BA569ULL,
		0x30ED7938E55668A3ULL,
		0xFAC788040B5F0EC0ULL,
		0xE3C54C568AC82384ULL,
		0x9D53795DBA18AA03ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x072FDD0928FFDB57ULL,
		0x4AC37B3E4A11E397ULL,
		0x5358E8200F978A4EULL,
		0xF82E9F3DA5017BB3ULL,
		0x49E39569EB03BE96ULL,
		0x1F2B1CB037009228ULL,
		0x26D07930BE6906D5ULL,
		0xEB48176332351FFAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB2E76714F3984CEAULL,
		0x5C9C4895F452C896ULL,
		0x2BDF463A5FA543C8ULL,
		0x4CA5D1EFC150A728ULL,
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
		0x051A009ED64797E9ULL,
		0x016AD7E64AB418DBULL,
		0x2827E531A4F47DD8ULL,
		0x469B5F236B87E63BULL,
		0x145F95AABBAED70CULL,
		0x2EA0EDFD6D201DC2ULL,
		0x7FDBF2CE13DAC31BULL,
		0x722766299DA3343DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF3FFC51C87A3B139ULL,
		0xF54EA2B8FD99C3D6ULL,
		0x20D97A1D42857EB1ULL,
		0xA7A7C6A69ED72CD6ULL,
		0x255713FC9D9D4781ULL,
		0xEB1EECF2CED3CF1EULL,
		0x5015993125E96C48ULL,
		0x042E51F051EC597AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8C5D7B5AC53F379FULL,
		0x11685CC0CC6E0159ULL,
		0x1EBFB85FB441E25CULL,
		0x71EC98FE09D5325EULL,
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
		0x5A99FD1096E69143ULL,
		0x6690D3E1B360521CULL,
		0xEB0960A0979A1277ULL,
		0x49339AA933DADBE4ULL,
		0xBACC285181E32920ULL,
		0x9658374C2908534FULL,
		0x071406050F5524F1ULL,
		0x11845C8F5D52BCDBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9AC763A6CDFEB89FULL,
		0xFA852353A34EB770ULL,
		0xA1D67E0B66B0DBEDULL,
		0x75DA84BB2D89F52FULL,
		0x7AB0D07D6C721E1EULL,
		0x2D838BC1EE59D4BEULL,
		0xD9215E94BB68CA9EULL,
		0x86EFB32B741DF685ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x43E1A2E4F7AF7844ULL,
		0xFB9D2712C5F8643BULL,
		0x1B37BD41A5FE9EEAULL,
		0x656A3AC2A426575AULL,
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
		0x8B9C9841AD3C2C5DULL,
		0x5635890C464719B4ULL,
		0xEA17FFA77FC0C2E0ULL,
		0x200AF347FA595C16ULL,
		0xCA6D2DA2AA4805C7ULL,
		0x13287F7D6210E338ULL,
		0x003995C8BE5CC0CFULL,
		0x20EC34146B7EB527ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x68625ACC1E13FB64ULL,
		0xA35FD6DAF52F0130ULL,
		0x6CF0EBDEACBE14E5ULL,
		0x934B05F321EF21D5ULL,
		0xD31C57D4D7356D97ULL,
		0x1094AC46DB310C31ULL,
		0x1D3D0CA85B558CB4ULL,
		0xAB286C0F3FEEDADCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD939FA02E3EAC4FBULL,
		0x14C70C495652038CULL,
		0x2EA36E97861469FDULL,
		0x07CF9E194FC4A15FULL,
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
		0x8E5E4EDD64A54643ULL,
		0xD9C3238D8658AC6BULL,
		0x0E51F5575102AAC9ULL,
		0xC15340251951EAB0ULL,
		0xBF280573ABC08D56ULL,
		0x2672DCA681D43D5CULL,
		0x9DD4F145D057B855ULL,
		0x8027F4DD0D3EF6ACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA74CA796CED78182ULL,
		0x2FCB132C08659837ULL,
		0xB6E043EE36A269DFULL,
		0xAA20BBB1980A68ABULL,
		0x10D8677E4BE900EEULL,
		0x2EC1C93B3E7F0950ULL,
		0x0FDF8D2E1E2DB006ULL,
		0xFD55F82076714CB8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC6E319B2CFCC9972ULL,
		0x6E40F24D7C98CE15ULL,
		0x69DE8CED8C9D7CA3ULL,
		0x025E0871E3CEBC51ULL,
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
		0xC25F0639FCC942F5ULL,
		0xF0183D9FF64C7A0EULL,
		0xB3BB37E29C08AAE5ULL,
		0xF2F51951B1CA015EULL,
		0xF51DC15D22CB6430ULL,
		0xBC309E2C060BF750ULL,
		0x9F2F68C9F0E4FDB6ULL,
		0xA362B522CC4A1556ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x944A254DF1B06FA5ULL,
		0x9376365298A0BC8AULL,
		0x4E858F6B56E5DC88ULL,
		0x65EFE687CB56D25FULL,
		0xA6B084E9D3642A9BULL,
		0x35887C6F9E3D736EULL,
		0x625ED9C14F7F57A5ULL,
		0xED05B486F8D94575ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD24BDA09D46B5DDFULL,
		0x59970944C653511BULL,
		0x6C2AE3BF3A3974F7ULL,
		0x1ED349EB49320A6EULL,
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
		0x31B409A70DE76A99ULL,
		0x76937192A1A746C7ULL,
		0x2DA38ED0F7E0F759ULL,
		0xEB3E721ECE7F34CEULL,
		0xD63B443397FA9E1AULL,
		0x1F0E4C2B856019B3ULL,
		0xECB739CE128A86B3ULL,
		0x6AECC783B5259B9BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6A1D4133A3537DD5ULL,
		0x7AB01DCBAEBA4D10ULL,
		0x11A03A9DC5A03625ULL,
		0x71A57B716D23F547ULL,
		0x50446B1BDAF92C69ULL,
		0x62D1A176770674EAULL,
		0x5BC046D51A88E272ULL,
		0x9127DCF7C65B31C4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAA3B01F978CACC39ULL,
		0xECE4AAA7143B6FA0ULL,
		0xA0AB6528027F22CFULL,
		0x4CD3C772D366F586ULL,
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
		0x33AAA02218FD3548ULL,
		0x65163AF78C246343ULL,
		0x61AE578EAA49C2CBULL,
		0x2E1326F50EE0DA53ULL,
		0x79E90B260FA6C877ULL,
		0x03801E763A240E93ULL,
		0xE2F84D4C465CDA55ULL,
		0xD95F4F37F6640CF3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x42D7874B073EE14EULL,
		0x3FEE963B50DBA81FULL,
		0xA2371B3090FA39C7ULL,
		0x3CF31C03598AF0F1ULL,
		0x6626328645DBF341ULL,
		0x2E39085EB0766F2EULL,
		0x1231AB78F47A20A4ULL,
		0x7CCC999D6575A4C2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDFBF408F05D9FBFFULL,
		0xCDB4EC3AAB0E6424ULL,
		0xBCF341BC40F71943ULL,
		0x2EE6FFE338B960C6ULL,
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
		0xB09D637A66F98039ULL,
		0x6FF82C9C83BC9A6DULL,
		0x0A08B3E56A520708ULL,
		0x3FD628C541F70983ULL,
		0xABC3A91C706872E0ULL,
		0x17F9736B622C21EFULL,
		0x5DC3CD945A222A55ULL,
		0xF3A1F148A26A8371ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD944DA653D04C328ULL,
		0x0418A1F7C6CCE17CULL,
		0x44645C28CBD12B4FULL,
		0xAD19AC6A4E735CDEULL,
		0x67E419C80D65FB16ULL,
		0xC2999476C42EAB25ULL,
		0x6D0F8CBF04D03947ULL,
		0x683F6E89B3AD4EEBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEA87CF9BDC528805ULL,
		0x181AA2F4308F5AF6ULL,
		0x8065F76748AAA3B4ULL,
		0x435BE4B263997886ULL,
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
		0x865B80698723C5AFULL,
		0x78B53E69109170DAULL,
		0x9CFA8CEEF7E8FB5DULL,
		0x976F106F24D35FB7ULL,
		0xAA92DD4877C1B0B7ULL,
		0x986DB13797C5D337ULL,
		0x8CA125B3AE0E492BULL,
		0x5BDDDB9829D3382DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5B66D189108B3253ULL,
		0x324EC26A42AA6E36ULL,
		0x2C420A81783D1CEEULL,
		0xAD5E0118E71D3B13ULL,
		0x1680AF6C760B03A5ULL,
		0xB9BF69E08E542680ULL,
		0xF506126BB08E6406ULL,
		0x496221F764E64AF4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x25A77D88B7B64467ULL,
		0x544512EA34C6A5E4ULL,
		0xF1BD5F1D20A7E1E8ULL,
		0x286E9D3378E15B0AULL,
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
		0xC055240C3EBBE07DULL,
		0x9BC70C2B9075CF04ULL,
		0x68D9A792A2002A80ULL,
		0x37CFCD8613140096ULL,
		0x15961929731765D1ULL,
		0x0EF026537F226CF4ULL,
		0x24CBDD2FD99614FCULL,
		0x52EA2A9E20081CD9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x666C7540529CD9C7ULL,
		0xD18FBC9D1B1E06C8ULL,
		0x5B14AF33E2AD7A0DULL,
		0x2F96DAE3C4AE383EULL,
		0x85942FDE51313BE0ULL,
		0x06F2A3018970EA93ULL,
		0xF75BF3BA75865143ULL,
		0x98D0D414D9865A83ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBA314FF2F4493EEDULL,
		0xF9D8CDB8EDB12291ULL,
		0xCC619FCB99A9BDE9ULL,
		0x27FBCB02C5A8A0FCULL,
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
		0x7516C0F89762F09DULL,
		0x9E84C72D9EE80C7BULL,
		0x801A1DC25BB4D6EBULL,
		0x2B85DCE50640C0DEULL,
		0xB5215FB9F821B647ULL,
		0x5992CD99F4A0F14FULL,
		0xD9FDF50C5171B8E4ULL,
		0x17AEDAAB7BEC7ACDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB2478C7561C5787DULL,
		0xE2E2B0EA8A033D81ULL,
		0x379304865820AFA6ULL,
		0x76971884A8D2C859ULL,
		0x1591F432FB5D3368ULL,
		0x24A871C4B23C8D88ULL,
		0xE977B2472EF11CC4ULL,
		0x15751C825773C59DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x72192A8CBAC8E53AULL,
		0x966BB7EAEFCB9E9BULL,
		0xFC75027F22AB540CULL,
		0x0980FE7BC758DDA2ULL,
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
		0x7B71D1EFB88093B9ULL,
		0xE0CDC01D5D50B8F4ULL,
		0x1AC9E2F2B68A863EULL,
		0xBEB4F4BC52C173CBULL,
		0x6DEF87C8AA990D5EULL,
		0x9F3E6B902234E8C0ULL,
		0x58BB67A918EC5155ULL,
		0x0ECAEE0276BE4090ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x53AB237302A23A15ULL,
		0x58D799469DB5C923ULL,
		0x9734BC4F3DCBDC5EULL,
		0xD7ED98A1D35EC628ULL,
		0x42843EDEC7B7EC9CULL,
		0x13CD2A7E3BC63A61ULL,
		0x8D7E11CF137F5F54ULL,
		0x835CA7F1AADB4200ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x99B38134634933D7ULL,
		0x3AC5CF7EF408D1F1ULL,
		0xAEAFE50046EA961BULL,
		0x1925C298C31476FAULL,
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
		0x6D7223C98966B878ULL,
		0x045C065926582488ULL,
		0xF24F44C3CF828A22ULL,
		0x07FCBC8093BA8FB7ULL,
		0xA063AB109D31B947ULL,
		0x973FB837FF0A2DEFULL,
		0x029597C7036E0DC6ULL,
		0x44C8CC5EA87BBCA6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8B276F407146E35DULL,
		0x1CBB3BB39488B46FULL,
		0x3D13AC1270A8377EULL,
		0xCD5F12716B092F40ULL,
		0xF3D3BD674E00171FULL,
		0xAC27FFB85D8E11E1ULL,
		0x22F6FA1D7C5C4098ULL,
		0x064894E424E82DE6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7FA7FBAAD97DE84EULL,
		0xCD262D978A3B9A20ULL,
		0xE6C6FFDB6B7EC774ULL,
		0x01A5E63EB09890F2ULL,
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
		0xDC9661B1D0BBE6C0ULL,
		0xA06E2706332BB238ULL,
		0x8CCDDF8C0DCEE02CULL,
		0x725A8D8659FB205DULL,
		0x1C77CEA0E635853DULL,
		0x8ECE2AD4F0000309ULL,
		0xA62B124963E51E82ULL,
		0x1C5794C8C447F408ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x12B7F8D87EAF3F54ULL,
		0x610F7C5BEDA03094ULL,
		0x2BE6CC410EFC8CCDULL,
		0xDEC844B7E2C2078BULL,
		0x6DB90C8ABFBD98B6ULL,
		0x8F823C780C2FECA5ULL,
		0x4E68BDDC95DC7E36ULL,
		0x59BCE9B4A8811310ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBA2F382307D9C1FAULL,
		0x24A40C74166ED470ULL,
		0x67BF9B71941A1EA7ULL,
		0x7687ADCA96BE7DAFULL,
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
		0x09586C44638E168BULL,
		0x9D740F23CFC6A70FULL,
		0x36D0D307D129A694ULL,
		0x61F0AB0E720C5E4FULL,
		0x4854FE717B9FEDFAULL,
		0x82A108BB568CC622ULL,
		0xF24123F4A0610403ULL,
		0xF1593E898C788F7BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE9B16549917FB6A8ULL,
		0x926BE41B1C23CB31ULL,
		0xC5D3A3417A3F47B2ULL,
		0xEE8497E6B2C80194ULL,
		0x9490BE8A889DD0D7ULL,
		0x931BD1CC6863DD13ULL,
		0x6B60D77F38BE3E6BULL,
		0x4A299DFFB4846443ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCEC88342E45EB6A5ULL,
		0x98CE52800DB5740BULL,
		0x76488933B913B36FULL,
		0x447DE79DCD82C71EULL,
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
		0xE36CAA9C4CAA39DAULL,
		0xFFAF0C5D5375B38EULL,
		0x9BEF6F50D5FA6FA2ULL,
		0xFCEBF0D9DAA5A12FULL,
		0x80C8182B6B07AD66ULL,
		0xD0FC1C0A1185ADC7ULL,
		0xB7873C1B7AB6D896ULL,
		0xF59543F603594DC4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2D517B72DCD24A4FULL,
		0x67EE35F0B73369D3ULL,
		0x7BA21635ED8A52FFULL,
		0xA2D9F57654F8CF70ULL,
		0x96F8D4A05F1890D9ULL,
		0xE9AD3DCB571E612EULL,
		0x88634BF41FABD716ULL,
		0xEC6217D317F20D5DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6ADF35CD35562CB2ULL,
		0xED75D3BC4797A86EULL,
		0x1FA2FEF26C12559FULL,
		0x37AA889277006110ULL,
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
		0xA05C3BDBF736655BULL,
		0xE636870010850A83ULL,
		0x209B407CF3C5C0F3ULL,
		0xAB01F91F579114F9ULL,
		0x604D0D2D10BDDDBCULL,
		0x56DCD6351F7B8CA9ULL,
		0xD129AF146C209F8FULL,
		0xE78759453B833900ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4903A5B08DADB7D3ULL,
		0xD66CDDCA2BE0A0E5ULL,
		0xD5F41B6E781EACB3ULL,
		0x1E10FEFD3D0BD413ULL,
		0x93AB1F78B63692D7ULL,
		0x9A958786D80CE1EFULL,
		0x29318298E6DEA773ULL,
		0x2F6CA61461F211BAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB761DEF0D99DCF9BULL,
		0x025F57147F11C132ULL,
		0x397DBF644371E85EULL,
		0x60E7936266111562ULL,
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
		0x04E4CED17ED5AABEULL,
		0x88A3A7780E623A2CULL,
		0x464D3AAD91D2DA9CULL,
		0xBB5D430135115511ULL,
		0xD0671D4766B65E76ULL,
		0x456D0615BAC9B8A5ULL,
		0xD23512C9EB43B936ULL,
		0x55CB07F18ABADAA0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x68A418A4083469CBULL,
		0x737D9E1EE224214CULL,
		0xFF49A2D1D3BABECEULL,
		0xA3E51D50FDD7DBE6ULL,
		0x24347146203F2DB3ULL,
		0xA44438AF2C020B17ULL,
		0x30C7449CE6D102E1ULL,
		0x520611E90BB3E3BAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2BC63E5DEC527DF8ULL,
		0x013486925DE1DC0DULL,
		0x3D50328A671F2C5EULL,
		0x26B4AAF312421F66ULL,
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
		0x669345429B3C526EULL,
		0x77860AA6E4630A9EULL,
		0x82B24A8756603E11ULL,
		0xB62B7FBF3D81CBD6ULL,
		0xA979D8CBE4437CC7ULL,
		0xE270E3EB4369AE67ULL,
		0x84592E26BC38305EULL,
		0x052C5F625DC88CF2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4D64223D9791258BULL,
		0x8374C534C1012E45ULL,
		0x08A5BC0B6BA849F0ULL,
		0x748D9B741B7499BDULL,
		0x3CB98B5362025B43ULL,
		0x4E0956A15F9CB9EEULL,
		0xB4CB5AA050885C87ULL,
		0x532F2ABDA5795DDEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3DBAA2E8595624C6ULL,
		0xFB703E69F3CE265FULL,
		0x4919F46FE6D16620ULL,
		0x2D33B4BE7DCE2F0AULL,
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
		0xC92813FC4223FCF9ULL,
		0x47F8D283E041BF38ULL,
		0x7AAC860C6B0EB4E4ULL,
		0xF0E6525013AE1EBEULL,
		0xB428B1A7E002E798ULL,
		0x0AC1AC959A389F85ULL,
		0x37D23EEBE922A002ULL,
		0x827635F5C9BDF50FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7FF144B6473B2709ULL,
		0x809A3951F1F8E7CCULL,
		0x2085538118152559ULL,
		0x3533D662C6DA7E60ULL,
		0x7676DE9389269148ULL,
		0x84EBCA5AB6B59FA8ULL,
		0x81550F74268832ADULL,
		0x63019B67DD967684ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x719C244ADF9DA68EULL,
		0xA51E2DEFB3BAD243ULL,
		0x70BC3E5235E5CA16ULL,
		0x67016CFE5AB068F5ULL,
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
		0xD322C24C6DD34DE5ULL,
		0x5570A1F35725978AULL,
		0xBC05B9CB83B2E7ADULL,
		0x38FEB1DAC256B9EFULL,
		0x58C7238E5BC46F5AULL,
		0xA002BFE0ECE7393AULL,
		0x806B8C9AAECDBCDDULL,
		0xAA424A16402D2DD1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF4432322E0209B90ULL,
		0xCFCE4C84363CCA30ULL,
		0xAC26DAB506F69D30ULL,
		0xF48B62FCA08A4441ULL,
		0x4645636C3BF0F3B5ULL,
		0xB98996E05E90594CULL,
		0x0A4DF93AA9949B28ULL,
		0xE1268BB10A2308E7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9E22243A47170B7DULL,
		0xBB9E6B8441CE0AB0ULL,
		0x9842BF5743374B56ULL,
		0x1E9191E4274DF07BULL,
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
		0x1FE439D820CE613EULL,
		0x326986DB1A880B00ULL,
		0xCD2169D029F18798ULL,
		0x69471FC78B12171CULL,
		0x691AE71EBE095750ULL,
		0x5A8553D7E1B1430EULL,
		0x06C84772E2E355B2ULL,
		0x13B36FFEC242F5CBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8357F4ABADDC40C0ULL,
		0xCFA98B9536D61423ULL,
		0xBB2773B06B4AEFE6ULL,
		0x6093F6BAF3C5F092ULL,
		0xE9C707892B64AE79ULL,
		0xF285EDFD30F00529ULL,
		0x00DD3989124AF116ULL,
		0xB635DBB922A11F3CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x82FF756037632CC5ULL,
		0xD2A919BC206126C7ULL,
		0xF2DE06D4B54586C2ULL,
		0x69572B624951FFC4ULL,
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
		0xCBCDD96C45F4C9B0ULL,
		0x6F075E54ECBABF54ULL,
		0xD0EEBB768554F3E3ULL,
		0xDDA900528A92E9C2ULL,
		0x1F85C510B5BAE4C5ULL,
		0x60008F9EB6D38EA6ULL,
		0x2D9BA193C8AA0349ULL,
		0x4B21F68F0B5118C3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAE727D3013727303ULL,
		0x504EE325CC4E4F77ULL,
		0x160F5BA7C2BE7E61ULL,
		0x56334642C5C39903ULL,
		0x5B9F7F340087C4A9ULL,
		0x6F914ADBEC8B15B6ULL,
		0x32515A4CA1B16B23ULL,
		0xE3351CEADEAC3A28ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3189BAFF1819177EULL,
		0xCF3CB019272E6374ULL,
		0x07E5F45E8B7D0B23ULL,
		0x749E086E65485BC1ULL,
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
		0xC2ABFC9CBB69E41DULL,
		0x063D83AB8BEF6296ULL,
		0xA6A5DD563C7B3E79ULL,
		0x3EABAAEBEA8575B9ULL,
		0xB8D068C7F170C0EBULL,
		0xE3AA7BFF93A6C3FAULL,
		0xBEC5901DEA2CFC99ULL,
		0x633F736B015B5D2EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0E0787A6FEFF1636ULL,
		0x04755FDFAEAF0F83ULL,
		0x8F8ED6684ECABD8DULL,
		0x080EF33F0D2700EEULL,
		0x4255D164CE9B3271ULL,
		0x848A6A366C20F2E1ULL,
		0xD63F350894712CC6ULL,
		0xB536CA2DDF6D71CCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4AD6EDACE81DF23BULL,
		0x208AC7A7BB1D5CDBULL,
		0x9B088C18A7915A4CULL,
		0x0BE5D6BFE6AF6553ULL,
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
		0x3CF863297AC1A38BULL,
		0x0F16EB5F5EA967ABULL,
		0x730175B138F43F30ULL,
		0xE222D9C1F14CEEB4ULL,
		0x753FF72AB02620D5ULL,
		0x7542317FE607D8D8ULL,
		0x1D708963F222F5B4ULL,
		0xA58DB33CB53B796AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x118A62BBCC08B26AULL,
		0xE4D63FE3C9C24E21ULL,
		0x7887F00CB5765445ULL,
		0xC14B4BC9B4CB4A92ULL,
		0xFB0DDEE57DE177E5ULL,
		0x9351B16985C8492FULL,
		0x195B3CE1CD8FD299ULL,
		0x15F8F4EBB4041E23ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4EDD9AB324EA07DFULL,
		0xB3F3AECDDE566C8CULL,
		0x95A2E0F5F15520E7ULL,
		0x70EBCDFE6AB930ACULL,
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
		0xA99C00A765E6910EULL,
		0x6E6AC894BF9887B4ULL,
		0x4A19F7C783F3AB69ULL,
		0x7473AE3EF548DD99ULL,
		0x7DC0879305C2145EULL,
		0x5394C2139E860CBCULL,
		0xC21FCFDA8098D3E1ULL,
		0x051BFA6DE52C33E3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4782BAC54B1E7B93ULL,
		0xF8042B4B34CCFB0AULL,
		0x7A2334B82F97917AULL,
		0xCFBC60BA71E31369ULL,
		0xC02AABE7B5CB99B7ULL,
		0x45F99295E0329490ULL,
		0x6E7120E979A9DC6EULL,
		0x588F2E86C034919EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8657E14FF95E4857ULL,
		0x7B6FA9F3CB2F6328ULL,
		0x3BE4BAD65BD4D502ULL,
		0x419D91D40027E07AULL,
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
		0x2D395CD3FB75FF30ULL,
		0x66F8A7739ADDF168ULL,
		0x8458D1B72296FD8DULL,
		0x0306723D6A5C3DB5ULL,
		0xEE516C98A064C4F9ULL,
		0x005E689BA551679CULL,
		0x81CD02774C27255EULL,
		0xBB1D398E74FED9CDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5431AFAD569BF457ULL,
		0xAC32A34C395D8D47ULL,
		0x046BFE9EA61386F4ULL,
		0x08D8FFDED862A5BEULL,
		0x2B58D5FB9EFDC4E9ULL,
		0x4A0F7FE55E6DA7F6ULL,
		0xC34A8FE2FF8BFDD7ULL,
		0xE7285CB19A39433EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC9EE0874DA240C2FULL,
		0xCA7C8F35E74ED6E1ULL,
		0xC749D51BDB8B5497ULL,
		0x70863B270B4DF127ULL,
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
		0x5C3EFA00E1C86C49ULL,
		0xAA55BC197701D25FULL,
		0x9DC65213EF8952F7ULL,
		0xF8FCE1D066DD278EULL,
		0x5D3D0FEB5AE3AC2AULL,
		0xB065A002B739A10AULL,
		0x6A21A98B684A4C1AULL,
		0x4522989CA76BF0B0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF19F530BDE14C373ULL,
		0xB11230065711F460ULL,
		0xC8328B7BA13FC2DCULL,
		0x72FAF219E9C4B2DCULL,
		0x7C29B98A26792F9DULL,
		0xDAC007E434030501ULL,
		0xDFEDD47FD371C1ACULL,
		0x5BDAD58A839BD25AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD37E7962CB822552ULL,
		0xAFD8209A9A0B074FULL,
		0x59456650666E1C68ULL,
		0x26A8E467CDFCF564ULL,
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
		0x61D9085732DD15FFULL,
		0x41F0E041239FC023ULL,
		0xCEA45F2851FEBB9FULL,
		0x112F2F7C898A598DULL,
		0x3F2D5DD9D67A0B60ULL,
		0xB6C558319769C24BULL,
		0x13ECD276C6CC46B7ULL,
		0xE6FF22D5E942FA78ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5BC9972CB2FEC433ULL,
		0x78D47482E3392778ULL,
		0xCE97C99326B7BF48ULL,
		0x54C9CCC55FE372FDULL,
		0x37C1B50DC0F0A72AULL,
		0xD90B87EE3A1D7E67ULL,
		0xFF98285E3C0FFDB5ULL,
		0xBDA93117C073F752ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x200A7F75B24332A1ULL,
		0xB2B155BE19B8AC84ULL,
		0x049DD539C339D29DULL,
		0x5F2744F138615E11ULL,
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
		0x5760F6C2229513B6ULL,
		0x8B5CA78081252F82ULL,
		0xEA72DF2CD018FEE2ULL,
		0x97FF099F8B3D4E59ULL,
		0x5679AB5FBDDD7EEEULL,
		0x23343ABEEDCA851DULL,
		0x98F28BDF689B26E1ULL,
		0xE9BA10EFDACF0574ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE30767764A184EA4ULL,
		0x2FD91DAAB2FD4CF7ULL,
		0x58888E281BCC3FBDULL,
		0x32D5B79CD2B52999ULL,
		0xE0F0CFBC0EABF8B6ULL,
		0x1AB6ED30AAFA9C87ULL,
		0xA0B7EC6B1805F2ABULL,
		0xE7DD1EF7266BB24CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE6AA2997D9D6B175ULL,
		0x9E1D0CF3B90468B9ULL,
		0x6A9DFC48AA727F2AULL,
		0x2BF53CED7F467CAFULL,
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
		0x383FEC4CA8E39592ULL,
		0x2F2AF45AC9A246E6ULL,
		0xDC273F120837C743ULL,
		0xE6B2C3D42471B4A1ULL,
		0x627DB38D58184FD2ULL,
		0x2393F6A6AE9C8B11ULL,
		0xF6B702DE5F8D919DULL,
		0xF0F535EA40778A27ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3A76B97C588CF79FULL,
		0x192D1F0C982AB839ULL,
		0xA68BC2F7BBC49DBFULL,
		0xD625A103AB097DC8ULL,
		0xB283BB28BDBF187DULL,
		0x122BA2235A5EF444ULL,
		0x26B0A31A02F9384CULL,
		0xB518E1CBC6FEB53AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1CE411BF3994D5D4ULL,
		0xAB7A60CCB29BF10FULL,
		0x168DB3400A786B8CULL,
		0x73419F568157D226ULL,
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
		0x7A536B6D404ECF18ULL,
		0xBD02E7A45B3C9F9FULL,
		0x1944C7A6C1387018ULL,
		0xA1818B95158E6FD4ULL,
		0x6513F5EBD71C7649ULL,
		0xC86BD3C320EF7F74ULL,
		0xD212994FF83CE922ULL,
		0x9CB45E083F1AFCB3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5E5810BD266E9EAEULL,
		0xDC1B9A0F277D14EEULL,
		0xA4A974972A33C47DULL,
		0x799C88BAACC0DBD0ULL,
		0xF640AF2F6781A300ULL,
		0xB75EF3CD734AD5B5ULL,
		0xD461BA19D32F47DCULL,
		0x1A9FD9DB9B0E84C8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8F57DAA8AADB9012ULL,
		0x68D08C0CFA30BCF5ULL,
		0x1CDC7519170A9C01ULL,
		0x76F0A17AC2A760E5ULL,
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
		0xE9E6E5F403ED0981ULL,
		0x46220C1C3B95B137ULL,
		0x48FB9564D1F09A97ULL,
		0x779691FFCF93ECB0ULL,
		0x32E01AFBABAB9EEBULL,
		0x4E97688C65F44C47ULL,
		0x89C72E027133D5FFULL,
		0x5993E01D52420014ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2967E308D76E1185ULL,
		0x6D14767E5A2C5A27ULL,
		0x02E1455018B35E96ULL,
		0x069B69610912CECFULL,
		0xA7F15929058782CFULL,
		0x986D2D238E97D8CAULL,
		0xA4BD037F184A8597ULL,
		0x941B6ABD99C8EC7EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5FEFC82FD5DB22E1ULL,
		0xE352672DD9227B8DULL,
		0x459C9F93EBDF2B65ULL,
		0x40DC94D4287A0621ULL,
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
		0x0EDBDADB7185E46EULL,
		0x826DFA4F349C838EULL,
		0xABF55B36EC4E23D2ULL,
		0xE5EBB6F72195EE6AULL,
		0x818099153222DB92ULL,
		0x78177A4CB471342CULL,
		0x2088433B1E06162EULL,
		0x0AFDFE9571498ABAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5DC8A47F48370380ULL,
		0x1BCDCEA424E017CEULL,
		0xB0E56A06180FDF3BULL,
		0x9BEEC00C54314D3CULL,
		0x1234BEAB667A8928ULL,
		0xAA04AE5386DE6C96ULL,
		0xB3FD26A9EF7B3241ULL,
		0x006EC3DC41593CD6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3655A210644B1CE3ULL,
		0xFD6A72A7D3860C14ULL,
		0x17B62EBDBCDC19BDULL,
		0x5B3FAE67EB1030F0ULL,
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
		0x84868ECD86995844ULL,
		0x69508FB1461241B6ULL,
		0xD32EA4476C6A124FULL,
		0x54546C311D6CF634ULL,
		0x730CA1BF63DD49C2ULL,
		0x4735A27D4C8176CAULL,
		0x69B63FD1DFDE0040ULL,
		0x9DA9581A3A463870ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF9A5406A42E6DB59ULL,
		0x14D13CE53D97A7A3ULL,
		0x7785834FCD92B01DULL,
		0xED7D43DFF2B59FDEULL,
		0x5F5D22296CDF4F45ULL,
		0x7151A0C37E041D35ULL,
		0x54F9FF36E789BE56ULL,
		0x25416B14D6E36A2CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x76EE3EA5ED65ADFFULL,
		0x14579460AF15E633ULL,
		0x6F9AB7F87B592AE8ULL,
		0x4644571DEB61F471ULL,
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
		0x7550BD6EFF83B8BEULL,
		0xD2308903496832AAULL,
		0xC59885053C30DB4AULL,
		0x25985580D7098E56ULL,
		0x24BD50F4543A91C9ULL,
		0xEABD04662E5E1E39ULL,
		0x9B32CD4DB3206665ULL,
		0x7DB061A3801E5322ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x737A7327AFFB8595ULL,
		0xC56E275630F89C1BULL,
		0x517B3B6F29CDEE49ULL,
		0xF228F72F4401C798ULL,
		0x55361D7A306BE47AULL,
		0xA6A1FD3D8CE7FB8FULL,
		0x69FB5C274BA5E772ULL,
		0x505AD5B5DFFECA48ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCFE7EE68A035EDB4ULL,
		0x28C571B50FF8BBC3ULL,
		0xC25815496E91C51DULL,
		0x6E22239757B61721ULL,
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
		0x35236F01171A60CFULL,
		0xBD909564A826A155ULL,
		0x200E9E20595313CEULL,
		0x9072309C327A8935ULL,
		0x37ADA6C2D8592AEFULL,
		0x78B6E49FCF5272ACULL,
		0x4A570CD09DFE68D4ULL,
		0x29818CE2D3C101A4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC8DEA5639B15419BULL,
		0xECE4F52683479CF8ULL,
		0x3172F57EBB66A971ULL,
		0x82636EFB78871E5FULL,
		0x1DA4F496037459F8ULL,
		0xD5DB761996B591EAULL,
		0xCDC32D8708E3779AULL,
		0xBC749FD44A2CA5DEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x498F3C4515FC209AULL,
		0xFD3E082A8C28612CULL,
		0x6C8ECD8DBFEC38EAULL,
		0x3DF9F1C925F90A26ULL,
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
		0xD3CD07CE04C4C571ULL,
		0x3E032873EFFC1896ULL,
		0x160A52CC8C76BA56ULL,
		0x5802F9D9A86FD256ULL,
		0xCE327EB3997F22A1ULL,
		0xE4F85D4952E58B9EULL,
		0x1DB002F129A50C6DULL,
		0x1923B226A0188CF0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x58BF74568C158B85ULL,
		0xDF9E83DF5A78B063ULL,
		0x7C389BAF65E5B34DULL,
		0xC98FA34F682A525EULL,
		0x02BA85BA92B5E6BBULL,
		0xB23A957D32E55D01ULL,
		0xEF37219743A14CF8ULL,
		0xB8F77A7187BF8012ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAEDC886E7A8E1A6DULL,
		0xE6904CE1558A539FULL,
		0x7FC32A754B1F726DULL,
		0x55039B6BDD7D68CCULL,
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
		0xA165029E4B9C2CAAULL,
		0xC6CE83B538253D79ULL,
		0x6AA484494CFC641EULL,
		0x9CC1164734AEE66DULL,
		0x317A11ADB6BAC66EULL,
		0xC4FC8AEA085ABEFBULL,
		0xEE73D69341922382ULL,
		0x488B0F771BA4B0C2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x468DBC0BB2642940ULL,
		0x5B1AFF20D06D51C0ULL,
		0xE0351D568FD2B405ULL,
		0x7AB4DB90197D716BULL,
		0x0DAECFCE1221CB6AULL,
		0x636D2AD71D50BA92ULL,
		0xAAA4587E5474FBEDULL,
		0xA453D0A0F47264FBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAB030DC507ED4401ULL,
		0xE6FBC7634B349354ULL,
		0x9B3C1E0DEF7D9045ULL,
		0x023F8E80ECA8B495ULL,
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
		0x28237C1341CB6256ULL,
		0xADEAE6AE7705B3C6ULL,
		0xDF880F12D98E2C3EULL,
		0xC4447373D2D7587FULL,
		0x256FFB0429AE787FULL,
		0x90B4EC6B905905BCULL,
		0xE08715AB32C7306BULL,
		0xE9F9898C4D5EE06DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0E3733A150409768ULL,
		0x9080C6D7C4FD4198ULL,
		0x02E9542B17AAC217ULL,
		0xC82B1EA5D3E85F73ULL,
		0xAAB947E47EF85800ULL,
		0x561FD157D095BA5BULL,
		0x1DFF167D16C1566CULL,
		0xA9D9497655A50F92ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x510ADF2548939F31ULL,
		0xCF8C24C52905A280ULL,
		0xBCCE9BBFEAC1C609ULL,
		0x00E2D810C483F9ABULL,
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
		0x2483ED33C95A9B9FULL,
		0x3575BA546DACC3E2ULL,
		0x751B9D1ECCDA2ACCULL,
		0x6D0BD82E56C7150AULL,
		0x40FFE944607D18A3ULL,
		0x3A462524E0754B51ULL,
		0x7FB3BA2B3FB4030CULL,
		0xDB7DA7FF008F94DFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x497FEAE6CDF79A7DULL,
		0xC9434966366CD198ULL,
		0x6A4ABFC17F76259CULL,
		0xC46560C888930D38ULL,
		0xEF2453814841ABCAULL,
		0xBBD948454BF90B32ULL,
		0x481349484B70BB9AULL,
		0x47EA607E2694A937ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x019C3D4294352C89ULL,
		0x305B3A1E41B176CAULL,
		0x4CA19F0D8F60A008ULL,
		0x10831486297302CAULL,
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
		0x405A8094063C292FULL,
		0x651E827663C53AC9ULL,
		0xCB0D6949229B75B6ULL,
		0x72C86FB7D7DE72DDULL,
		0x4C9C56CB3AECA982ULL,
		0x16794F695523D1C2ULL,
		0x577B4BB7608A8148ULL,
		0x6637531CC71A746CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x47F779A1310799F2ULL,
		0xD709BAF9C99FAA9DULL,
		0x79BA5FD294F6B891ULL,
		0x89025865D709DB8FULL,
		0x29AFE958F5535EC2ULL,
		0x10C5E57B12BF8729ULL,
		0x90645B2FE48011ADULL,
		0x655225867E37B5B0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x277B45E929F5A7BDULL,
		0x66B680DA7508A2E7ULL,
		0xDEBABD92F7314E27ULL,
		0x0BCADBA0D27CE72DULL,
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
		0x725764335661FDC6ULL,
		0x9137B5F41E0C8695ULL,
		0x40E00D78D653E6F5ULL,
		0x8264E3D2EC5F8BB6ULL,
		0x78F317E272369D8EULL,
		0x03348124DB827A10ULL,
		0xC9F5B49B20B9CE99ULL,
		0xF1CF827DAEE17BEBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4D60F90B570FC090ULL,
		0x871F6EDF7B8FA83EULL,
		0xC83B94EEE675B1DBULL,
		0x0A229529821C4123ULL,
		0x08A916B26BF8DF3FULL,
		0x50019BE989E7785FULL,
		0xE4D4133F59D87DDEULL,
		0x5F7036C33B9506A2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCFF29848EC7C8034ULL,
		0xA3A64DE2BF7F1EADULL,
		0x7BA26C29755030D0ULL,
		0x32678C56879CB364ULL,
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
		0x442176AB979E5D24ULL,
		0xD41FFF98329D87ACULL,
		0x9954651ADA3C6EC3ULL,
		0x86FBF10FC122BFD6ULL,
		0x98EF5A6D06AFFE79ULL,
		0x4680287D5D37B60EULL,
		0x25A9CED9CF53197EULL,
		0x247F21A0119DD565ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9A0A5EDFE3F3E03BULL,
		0x397E10C761CCCE3CULL,
		0xDA272F5A40584FBAULL,
		0x3CCABBF412CA1F00ULL,
		0x87BF70341F463281ULL,
		0x3045A9E3988E82DEULL,
		0x1AB911FBB9FC6216ULL,
		0x43C77DE74C6AA89AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3733DC3E0D5EC30EULL,
		0xE750B9A401EE5292ULL,
		0x5EE93EB7C4C3587CULL,
		0x25738288F3F146F9ULL,
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
		0xD1D45C0184BA18F5ULL,
		0xB3E9903641E2965AULL,
		0x8931DAF5742DF060ULL,
		0x28B9226BE050E6EAULL,
		0xD01B186C32FDA262ULL,
		0xA7E374320C30BE02ULL,
		0x21A7C65F8B78FF7AULL,
		0xFD3E95F9AA8EA617ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8425101F5B44362CULL,
		0x2A6322927578547EULL,
		0xC91B2157F5040891ULL,
		0x6C52277EE3D0C894ULL,
		0x88FE1AA50F9AD3F6ULL,
		0x72A0F69D959F37F9ULL,
		0x554169BC101A0BFCULL,
		0x2C2EE3F80A552E33ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDBFCF7716A208B58ULL,
		0x716511AD6604273CULL,
		0x174879E1CF420C8BULL,
		0x44BB672AC507EA26ULL,
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
		0x15FDF3DE27452F59ULL,
		0x33072F4A6EB515C4ULL,
		0xC9DD37866F6D7D4DULL,
		0x6C0F724924823285ULL,
		0x9A20BE80CEAD6CB4ULL,
		0x1C570CD76DEA6671ULL,
		0x530CBC278BC20AB0ULL,
		0xB8A671300887F9AFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1208D9CF9BDA2577ULL,
		0x1B9F31AAFBFC6D8CULL,
		0x669CF224E42E31FAULL,
		0xF375301566AB217BULL,
		0x2D603E418E933930ULL,
		0x0B78B69E9FA722DBULL,
		0x78EBFD052CDE82D9ULL,
		0x19A54421AC6C37BAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x288823720F4EB2E4ULL,
		0x9868CA0E10B4B08CULL,
		0xC41CA47BA105753FULL,
		0x12C6F25569F5DB62ULL,
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
		0x636711FF23217A46ULL,
		0x49FB3EAB81775880ULL,
		0x7FE591AD2D0A36D2ULL,
		0x491A7979E11B262FULL,
		0xEFD0B6489698CEC9ULL,
		0x7A5175936F0763D9ULL,
		0x0DFE2944B964CF9EULL,
		0x87671BDE6AFB49CCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6A1E9EFB75732791ULL,
		0x1E8B55103EC25604ULL,
		0x101212B6DF93B0B0ULL,
		0xCD92D81997A5F129ULL,
		0x576F8930BA44DF52ULL,
		0xB5DA9485FDF82455ULL,
		0xADD2113F8B462393ULL,
		0x0419C0684B11E7FEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x97B5248E6223E11EULL,
		0x5515519A0AF8702AULL,
		0xB65F0FBB26040FBBULL,
		0x790334E90619B982ULL,
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
		0xEABB6CCE2E3C2172ULL,
		0xAF8CA6EA0405A9E9ULL,
		0x9E4DB20C6765DCB1ULL,
		0xC1B69A5651D3DDEEULL,
		0x8D5487AE6F80BDB1ULL,
		0xD56646148EF17833ULL,
		0x96AA57F154007CB9ULL,
		0xDBD0E6B14689D3E0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDBC3776E5D4712C6ULL,
		0x3B0D5D7A74A8D954ULL,
		0xAAC547CCD8802DD0ULL,
		0xEA2BF77DEF0BB8AFULL,
		0x41A45DB4A280207AULL,
		0x38A11839A42FA21AULL,
		0x467FB50EC854E512ULL,
		0x331B258FB36C9F5DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4B1E30743F0C6879ULL,
		0xB9C417EE68229856ULL,
		0xD9DC97E04A5E31C2ULL,
		0x62854DD4391DF0BCULL,
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
		0xA27F6A564CA2FD0BULL,
		0x40EEFAA9A3F761E2ULL,
		0x60B5E9D74371A58CULL,
		0xC8199454B22D0681ULL,
		0xB36F3EC8D6E2AF0CULL,
		0xD3B992459F43304AULL,
		0x227CAB7BBCFBD847ULL,
		0xD59E454404BAF9A7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC07D77D92920B465ULL,
		0xD408FCC3DEE44A43ULL,
		0x046E0A2A8A4A5416ULL,
		0x02B3A4C5087C0314ULL,
		0x8D887E9157849B7DULL,
		0xEA6A03E6A55BA3C3ULL,
		0x24AE97C74614FC87ULL,
		0x2849D147052D2048ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x82427ABA0B7933BCULL,
		0x0EB51FFEDD71F3AEULL,
		0x08DECC765F6BEFF2ULL,
		0x7FEF271D98BF4787ULL,
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
		0x5BC6C9A139874605ULL,
		0x6ACCBFCA572C627EULL,
		0x2BCE9D36A0E6C953ULL,
		0xD52E8BEDCFF8C2DAULL,
		0x6096DFD8CA903424ULL,
		0x0CEB85A59A370001ULL,
		0xD5FF04ADF551C729ULL,
		0xA6858D0AB545AA71ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB46B00CFC9DAD69ULL,
		0xEBE55C8D49DCB7B1ULL,
		0x43B035AFE0A572B7ULL,
		0x215ED9FB5867ED74ULL,
		0x7498D410456326B1ULL,
		0x8A5B39E83686A0E8ULL,
		0x7A328537D52CC2AAULL,
		0x6504BA7EC21C6E45ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA835D9580199992AULL,
		0xE052A159D97DC87FULL,
		0x8879530F85C00162ULL,
		0x6CEEF2B88FAFC3FBULL,
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
		0x367E6601E6F8C54DULL,
		0x028AA50FFBB5E291ULL,
		0x1241649EA2C3CFF9ULL,
		0xAB27AD8C53CAE1E1ULL,
		0x03463FAFC91A0F84ULL,
		0x7C3A956C566E1E3EULL,
		0x875616DDD2E03035ULL,
		0x7409EDA4E088B3B0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6EBA0F4D11ABF02CULL,
		0x5F32FAA071756990ULL,
		0x9B631D459162B477ULL,
		0xF328F668D9BBA44CULL,
		0xE274E948D8E20535ULL,
		0xABEEC83413FCC1DCULL,
		0xCD394600A4E3AB8FULL,
		0x9B764C6E8214D0A5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA6D729FC7D9E5BE4ULL,
		0x8E9820C967142F6BULL,
		0x1725482DE4DCCC1EULL,
		0x5DE8A5357F42F12CULL,
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
		0x915DA84640C56C31ULL,
		0xE2A22F020378DB0CULL,
		0x038AC6B0192058EBULL,
		0xD2F73CA6D522D7AAULL,
		0xCA8124640BC36B9FULL,
		0x1E30A053F4E87EF2ULL,
		0xB1D035F6F1866282ULL,
		0x75C818EB298C305EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x871A061BA2CFC803ULL,
		0xF1FE5337AB90EB98ULL,
		0x919902A5672B6AB8ULL,
		0xD6FE2F666CD9A4F8ULL,
		0xC9E9714ECE331B7CULL,
		0x6C42B6507693F41AULL,
		0xBE0F165F6A544DBFULL,
		0xD5F7E861F752C5D4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x20C83751C1618739ULL,
		0x59F4984F18748B84ULL,
		0xA09C7488C3640319ULL,
		0x34E0419DDCCF032BULL,
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
		0xE2601B6859C33F3DULL,
		0xA9F28C29E7EA8B54ULL,
		0xD07189B96FA537BCULL,
		0xA5E832F2092E512AULL,
		0xD22A8B58308771B3ULL,
		0x5E9E9D73573FB519ULL,
		0xA73530C076E7D1D0ULL,
		0x6C63EE9F8E3B1618ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x395C6F840455E94EULL,
		0x255F16F659084478ULL,
		0x09C0568D0F15E3E4ULL,
		0x4CCB34CECBE98331ULL,
		0x4F9DEBAEC56BFB23ULL,
		0x357156DF616143BDULL,
		0x2813FC42092A769FULL,
		0x3A644EF1017C428AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x09E35F0A3B80F06CULL,
		0xA14BEF2A0DE71A98ULL,
		0xA59EFDF0AAAADD24ULL,
		0x450EB20C21983520ULL,
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
		0x0BF4F9EEAF36F034ULL,
		0x600F1F58A6BB6F44ULL,
		0x06E60C353F50882DULL,
		0xDEEA6FF1ED46AC76ULL,
		0xB861ABE884032E8EULL,
		0x01C22A10BDD3E7EBULL,
		0x3E0E1492EE69268DULL,
		0x194A23E4BB28A0A7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5B2E6120B8262AC4ULL,
		0x8446BF7F2551F5A8ULL,
		0x961D7D442D8F3310ULL,
		0xCB7870509CB2000CULL,
		0xAC12E0F83624CDCCULL,
		0x06D17325AF83A00CULL,
		0xDFECFAA9619E2E1BULL,
		0x6A20D373B087A323ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8478B87986132074ULL,
		0x1B8386BDA15424B7ULL,
		0x69B2679BF7E23608ULL,
		0x1393F068E47A4DE9ULL,
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
		0x050111994B4AB758ULL,
		0x1FDEC5BF6B571313ULL,
		0x22BCD877042AB1BDULL,
		0xA6418F087F8FDBE3ULL,
		0xC17B00D751966685ULL,
		0x14C6D8F3B4595CA6ULL,
		0x2EB84FA2A91A7BB9ULL,
		0x0024FF9FBD402976ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2401E73A4BF1E973ULL,
		0x5D26697DF21C268CULL,
		0x203B74BAC5E8C75CULL,
		0x685C524462AA5CE0ULL,
		0x9ADDC68D29724A45ULL,
		0x07BCF06A74C08AAAULL,
		0x653E17C59B308BD8ULL,
		0xB5C4C0CAFE9DD258ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9C55D160F4B4FB63ULL,
		0xB230E0A0E9EA17F4ULL,
		0xEAA5AE8C4EFB85C8ULL,
		0x482E905868FE6D6EULL,
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
		0x7D21CD9C897CED72ULL,
		0x2CA7CEDEC13D3340ULL,
		0xBE647C830BCB6EAAULL,
		0xDAF66FDDA6763AD4ULL,
		0x580628994AF1CA9DULL,
		0xDF6413601F544E8DULL,
		0x8C630799CE16B6FAULL,
		0xB6615D6CB5DB7685ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC5990C0817F2F235ULL,
		0x267D51FF3AE3F6D2ULL,
		0x988684876D15EA1BULL,
		0x6A40FE289A89C523ULL,
		0xBCD687CBF68A8B47ULL,
		0x6C89FAABF42EC8BBULL,
		0x8221B0FE0CA735F1ULL,
		0xF9C3355DD4653AEDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC09AA00EF8DD6085ULL,
		0x128A279DEDEB198AULL,
		0xAB90D31A5542ABF6ULL,
		0x702F63EA83794E42ULL,
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
		0x27A30BF601FB5571ULL,
		0xC6AC521BE7C37523ULL,
		0x23A2E2E2EE85D0E0ULL,
		0x7BC86F031EA0E869ULL,
		0xB94CE1DD87499228ULL,
		0xB209F853D60A5353ULL,
		0xE28BE58D89907722ULL,
		0xC49C6C33EA462163ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x76A3F37C840CE40FULL,
		0xFBCB45900D6868C8ULL,
		0xA6DF945E8D9AC79CULL,
		0x26E7FCD81BED966AULL,
		0x3BF1868B106E6A07ULL,
		0x10B0B1C75167CA0EULL,
		0xCE40246B49659CE1ULL,
		0x8B3C216E4323C801ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4C8EA6B72276678BULL,
		0xBE2185678A7B6CABULL,
		0x8001F999E7476F01ULL,
		0x592B8B81D1CC968DULL,
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
		0xD2B2F1197A7EDD11ULL,
		0x4C2D37E2C26FC5B8ULL,
		0x28A032379C620696ULL,
		0xBCE42CFB44E43502ULL,
		0xB8941FEA33B96B6AULL,
		0x474B53513D6B5D6FULL,
		0xE33CBED48784527BULL,
		0x723D3664104FE01EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDF9E79CD178FB648ULL,
		0x9CD580A330107168ULL,
		0xE74EBD7407FA626DULL,
		0xE9B5AFA2E70F31D4ULL,
		0x5B1DC3D3EA305328ULL,
		0x764D9BA47751DFDCULL,
		0xECC1588F43318317ULL,
		0x29620B0A60340128ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD2A6229B4D48C224ULL,
		0xB500FAE4FA27F82FULL,
		0xD7A2A30BB8B26CF9ULL,
		0x23B6ECA881F81BAFULL,
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
		0xE0C1FB74D365FF43ULL,
		0x5337AA3C1738620EULL,
		0x9C4CDF12BD8C9056ULL,
		0x3B7ACF0C9142E96DULL,
		0x424E085B7B5162DDULL,
		0x4F68E48445DF5423ULL,
		0xB3221A339EAE1DC4ULL,
		0x656522E1C909D10EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9E7DEB61429A43A0ULL,
		0x8197F8BB242DCA31ULL,
		0xA98EB8B379E819DFULL,
		0x6861556066139A34ULL,
		0x4D8554FAC5CBDB5EULL,
		0xE8396D5AB8409423ULL,
		0x4257197F84589467ULL,
		0x85CFBEAC78EA1603ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x980EB06E829DD7BFULL,
		0x22AB61ABF89B17DBULL,
		0xB0E0411B2C56DA2EULL,
		0x034659960FE512EBULL,
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
		0xB4C2B1EA359DA5ADULL,
		0x398B199119EAB7DDULL,
		0x3424CA234BBF4A5EULL,
		0xE7BC5BE5EB93D66FULL,
		0x9294783249E09CB1ULL,
		0x46CAB0CEB9F436D4ULL,
		0x9C1CC3259382867AULL,
		0xF4C8F5FF9AF588A0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x43609C0355070FCCULL,
		0x3451407BCCE17D7BULL,
		0x8C1028EACE7D8660ULL,
		0xBD16623A6A63BD8FULL,
		0xE75DB5F332C60D78ULL,
		0x7A041F81F94F4135ULL,
		0x472C681944856A4BULL,
		0x9373C48951781A04ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDB82EB444E87DA7EULL,
		0x6AB36A79E585AFEFULL,
		0x43C2250C36D3F2F0ULL,
		0x1D4B513A69CE8414ULL,
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
		0xA0B7F170D53A3314ULL,
		0x78883DF2711AAC35ULL,
		0xF6EA7C97CE2DEEF1ULL,
		0x81B1DAB181960EDFULL,
		0x5A16A90D1AF1FA5DULL,
		0x90D02E9927E53B62ULL,
		0xCB525BCB186CAA04ULL,
		0x35452C169E965407ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE851FC2C9AFB556EULL,
		0xE86A1116CF7337B2ULL,
		0x54F9579E9FCA9D5CULL,
		0x0ACD051C952BE3E6ULL,
		0x497422F122E5DEC5ULL,
		0x161404BCDF33CDF9ULL,
		0xD371202CF3B2B52DULL,
		0x4ED9A3D3C9EB34AAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3085DD6B0C0AF5B1ULL,
		0xC80C638E6BFDB21BULL,
		0x6D5FFE72A1FDA990ULL,
		0x2ADB0F807DD0D2C6ULL,
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
		0x499E6D987B80729CULL,
		0x1E3D509A27D26B52ULL,
		0xD2F8FB1EA0EEA075ULL,
		0x006664E546D4C7AFULL,
		0x7B96AFEF3710950CULL,
		0x4162A2F734C4DEC5ULL,
		0x02F58953E31E7A55ULL,
		0xC0558045D9061423ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD32337E531E708EFULL,
		0x0C786961BA335586ULL,
		0xF124231BBF739F46ULL,
		0x279C0AC9B07C434EULL,
		0x82CD7E81C8226A9AULL,
		0x3F7BA15C97C67516ULL,
		0xEFFC308CB1763694ULL,
		0xB1CCCA47E6B016AEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x64588BF1C0F3B6E5ULL,
		0x5A0F242BBB62C5C4ULL,
		0xB2D8059440750FD5ULL,
		0x01155DCD8F1C239BULL,
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
		0x95DF06A6FA7FA4B5ULL,
		0xA2253207F94AE52CULL,
		0x138D8B77B73BC123ULL,
		0xFEB8B41F9D36E12AULL,
		0xA25E9F4DD7931DFBULL,
		0xA4A07994F2632F05ULL,
		0x4EC5EF0A732637D4ULL,
		0x3FBC73788F897214ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4FE7ED4F0403DE90ULL,
		0x996039FE27264CFBULL,
		0xACADF10E61727555ULL,
		0xCC8C4914CF035AF1ULL,
		0xAF75BD7412260D84ULL,
		0x214ED62AC7B849B1ULL,
		0xC9986FD7085605F2ULL,
		0xA68DE2D835517542ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x54889FAB44AC3582ULL,
		0x86E339CC2782A2A7ULL,
		0x2BA07C0B30B0B36DULL,
		0x6F15E2D832830D52ULL,
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
		0xACE27E2B5DAB8E72ULL,
		0xAD6BEDCA585DE33FULL,
		0x71CFE4B088C92D4CULL,
		0xAE3D5B2F58101E57ULL,
		0x806280E74A890485ULL,
		0xAC2A53CDC6B6EE25ULL,
		0xE33AB696A49ACD0BULL,
		0xC7B4F9CFF9351997ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x62C09D9A4A76E688ULL,
		0x4F7858A7A7EC4EC0ULL,
		0x9D90CB4082B2EB2DULL,
		0x51E332AC6884C421ULL,
		0x8909789D748FFB36ULL,
		0x584EAA94756BE317ULL,
		0x12B7B1A04142A7F5ULL,
		0xDA75605270F0D10CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x01591B86D62C0945ULL,
		0xD08EB3A4C1953892ULL,
		0xC7B1D602C52BC36FULL,
		0x13CAF12529AE1EF6ULL,
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
	printf("Test Case 501\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 501 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -1;
	} else {
		printf("Test Case 501 PASSED\n");
	}
	printf("---\n\n");
	return 0;
}