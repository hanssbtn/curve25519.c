#include "../tests.h"

int32_t curve25519_key_x2_test(void) {
	printf("Key Doubling Test\n");
	curve25519_key_t k1 = {.key64 = {
		0xE546405D0BF7403FULL,
		0x8DAAC505EBDD52E5ULL,
		0xE13EBD9CECF83AD2ULL,
		0x86BC4788E25C46D4ULL,
		0x026AF651A920995DULL,
		0xC4523E7580EFFF2DULL,
		0x0AE6A5D431D692FCULL,
		0x351971D5CDA18CF9ULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0xCA8C80BA17EE807EULL,
		0x1B558A0BD7BAA5CBULL,
		0xC27D7B39D9F075A5ULL,
		0x0D788F11C4B88DA9ULL,
		0x04D5ECA3524132BBULL,
		0x88A47CEB01DFFE5AULL,
		0x15CD4BA863AD25F9ULL,
		0x6A32E3AB9B4319F2ULL
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
		0xD48E48D6D6180F3CULL,
		0x74F8D4863E625BBCULL,
		0x5AC7DF71AF9521E6ULL,
		0x21FB55F0BB36D30FULL,
		0xCB635D7E0B8AE5B8ULL,
		0xBEBA16273099C4D1ULL,
		0x472F0B5E31C489D8ULL,
		0x122D746DF6726F5EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA91C91ADAC301E78ULL,
		0xE9F1A90C7CC4B779ULL,
		0xB58FBEE35F2A43CCULL,
		0x43F6ABE1766DA61EULL,
		0x96C6BAFC1715CB70ULL,
		0x7D742C4E613389A3ULL,
		0x8E5E16BC638913B1ULL,
		0x245AE8DBECE4DEBCULL
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
		0x7EDABCD366413993ULL,
		0x7D15AB967DD572FEULL,
		0xA73E0E9E2C518FA9ULL,
		0x458B71A02C803176ULL,
		0xA4C1680695837277ULL,
		0x786BE4BDBD29C460ULL,
		0x01D58006D34E41D3ULL,
		0x03CEDE1DA04BC146ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFDB579A6CC827326ULL,
		0xFA2B572CFBAAE5FCULL,
		0x4E7C1D3C58A31F52ULL,
		0x8B16E340590062EDULL,
		0x4982D00D2B06E4EEULL,
		0xF0D7C97B7A5388C1ULL,
		0x03AB000DA69C83A6ULL,
		0x079DBC3B4097828CULL
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
		0x04EB0236A8F0ECD6ULL,
		0x530F51D7D0C877F8ULL,
		0xA159EEB5F39B0E2CULL,
		0x498A6A885733903BULL,
		0x3B6D647FA650EFD0ULL,
		0xE79FE6FA26C9F5BAULL,
		0x6D9E707C69104B0AULL,
		0x131B634D5C9C6B08ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x09D6046D51E1D9ACULL,
		0xA61EA3AFA190EFF0ULL,
		0x42B3DD6BE7361C58ULL,
		0x9314D510AE672077ULL,
		0x76DAC8FF4CA1DFA0ULL,
		0xCF3FCDF44D93EB74ULL,
		0xDB3CE0F8D2209615ULL,
		0x2636C69AB938D610ULL
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
		0x5C9D47118FA9FCDBULL,
		0xF8F682962F9D86A6ULL,
		0x8EDD97EDCD3E3530ULL,
		0x8C94597447DD6065ULL,
		0xA4B651C521AFD3B8ULL,
		0xC0EA65F2B864623EULL,
		0x814D683A6DAD621CULL,
		0x22190B35CD836587ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB93A8E231F53F9B6ULL,
		0xF1ED052C5F3B0D4CULL,
		0x1DBB2FDB9A7C6A61ULL,
		0x1928B2E88FBAC0CBULL,
		0x496CA38A435FA771ULL,
		0x81D4CBE570C8C47DULL,
		0x029AD074DB5AC439ULL,
		0x4432166B9B06CB0FULL
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
		0xF0AE3DEEFBAA9018ULL,
		0x5980114CA1BE4473ULL,
		0xE9283868C45C8057ULL,
		0x7A42CC36411FB37EULL,
		0x6F69B90100E3E071ULL,
		0x91EA09976A3EF1CDULL,
		0xE434C1269332CCAEULL,
		0x261C96BA37A549E3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE15C7BDDF7552030ULL,
		0xB3002299437C88E7ULL,
		0xD25070D188B900AEULL,
		0xF485986C823F66FDULL,
		0xDED3720201C7C0E2ULL,
		0x23D4132ED47DE39AULL,
		0xC869824D2665995DULL,
		0x4C392D746F4A93C7ULL
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
		0xCAD86B818859CD52ULL,
		0x62C7B41A4218D8DAULL,
		0x2766444242906B0BULL,
		0xCEF00AC9F9219852ULL,
		0xD467310D5A0DD0B4ULL,
		0xE19FF10C476892BCULL,
		0x7E4D6BBB33D783DDULL,
		0x3DE067201CF93ADBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x95B0D70310B39AA4ULL,
		0xC58F68348431B1B5ULL,
		0x4ECC88848520D616ULL,
		0x9DE01593F24330A4ULL,
		0xA8CE621AB41BA169ULL,
		0xC33FE2188ED12579ULL,
		0xFC9AD77667AF07BBULL,
		0x7BC0CE4039F275B6ULL
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
		0x7D86EC8531DA6D18ULL,
		0xA0C65A081C7EA9EDULL,
		0x8379B1B76F817D4FULL,
		0xEE0DDC83FC29E285ULL,
		0x95429D71B1FE3CF4ULL,
		0x3AA1F12880C1B3D7ULL,
		0xA3E7D0206F6063DDULL,
		0x16028876956B988DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFB0DD90A63B4DA30ULL,
		0x418CB41038FD53DAULL,
		0x06F3636EDF02FA9FULL,
		0xDC1BB907F853C50BULL,
		0x2A853AE363FC79E9ULL,
		0x7543E251018367AFULL,
		0x47CFA040DEC0C7BAULL,
		0x2C0510ED2AD7311BULL
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
		0x576AC53151677259ULL,
		0xA5F65B448B7AFACDULL,
		0x0FAF62DDAFDF098EULL,
		0xCB6CCFDBF2797566ULL,
		0xD915ECB0A8C05D75ULL,
		0x76AA0678DBED8EB7ULL,
		0xAB9829081745A259ULL,
		0x2874B071AA470260ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAED58A62A2CEE4B2ULL,
		0x4BECB68916F5F59AULL,
		0x1F5EC5BB5FBE131DULL,
		0x96D99FB7E4F2EACCULL,
		0xB22BD9615180BAEBULL,
		0xED540CF1B7DB1D6FULL,
		0x573052102E8B44B2ULL,
		0x50E960E3548E04C1ULL
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
		0x37407A7BA04F4B71ULL,
		0xAF9F072EDD7B838AULL,
		0xD01D317268F2BF42ULL,
		0xBF9869E677584507ULL,
		0xDBEA854D77925DDCULL,
		0x09400B8E80AE8899ULL,
		0x17564136E5942B24ULL,
		0x38CE8E32EF6E4459ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6E80F4F7409E96E2ULL,
		0x5F3E0E5DBAF70714ULL,
		0xA03A62E4D1E57E85ULL,
		0x7F30D3CCEEB08A0FULL,
		0xB7D50A9AEF24BBB9ULL,
		0x1280171D015D1133ULL,
		0x2EAC826DCB285648ULL,
		0x719D1C65DEDC88B2ULL
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
		0x2FA44BF0975E4F8BULL,
		0x013A891CB7A3BEE7ULL,
		0x752EA840A1D63B37ULL,
		0xADF5C58386B8FE19ULL,
		0x73F5BC24A773CFEEULL,
		0x02D8CCB5B724CCFEULL,
		0x8F6DC5BC3292F4F5ULL,
		0x0E4DACCD51CEE61EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5F4897E12EBC9F16ULL,
		0x027512396F477DCEULL,
		0xEA5D508143AC766EULL,
		0x5BEB8B070D71FC32ULL,
		0xE7EB78494EE79FDDULL,
		0x05B1996B6E4999FCULL,
		0x1EDB8B786525E9EAULL,
		0x1C9B599AA39DCC3DULL
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
		0x0ECAE3CA99593E6DULL,
		0x5590FE2CF778BB4AULL,
		0x0B99E5D3A00B334AULL,
		0xE200DE724E910489ULL,
		0xAAB0A47041A4EB60ULL,
		0x28AA766C4DA08531ULL,
		0x362196ABEDD45C97ULL,
		0x2383CC277F428503ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1D95C79532B27CDAULL,
		0xAB21FC59EEF17694ULL,
		0x1733CBA740166694ULL,
		0xC401BCE49D220912ULL,
		0x556148E08349D6C1ULL,
		0x5154ECD89B410A63ULL,
		0x6C432D57DBA8B92EULL,
		0x4707984EFE850A06ULL
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
		0x099D827EB3F75A6AULL,
		0x8CAC8D4689329C33ULL,
		0xFF6521ADA27680D2ULL,
		0x99D690F029B1C9B5ULL,
		0x5CD56A35E6DF3101ULL,
		0xA8E2019DD4530157ULL,
		0x8C1B33627AE2DDA6ULL,
		0x068C42C544D718B1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x133B04FD67EEB4D4ULL,
		0x19591A8D12653866ULL,
		0xFECA435B44ED01A5ULL,
		0x33AD21E05363936BULL,
		0xB9AAD46BCDBE6203ULL,
		0x51C4033BA8A602AEULL,
		0x183666C4F5C5BB4DULL,
		0x0D18858A89AE3163ULL
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
		0xC4AEB8BC57F28E1AULL,
		0xBB124487E80B1311ULL,
		0xD04F5DFE328235CBULL,
		0x5B881E8C98B3CB38ULL,
		0x2510E46C355E3BEDULL,
		0xF5592B352090B0C3ULL,
		0x09F2DF9F0D4AD02FULL,
		0x006930FCC0286669ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x895D7178AFE51C34ULL,
		0x7624890FD0162623ULL,
		0xA09EBBFC65046B97ULL,
		0xB7103D1931679671ULL,
		0x4A21C8D86ABC77DAULL,
		0xEAB2566A41216186ULL,
		0x13E5BF3E1A95A05FULL,
		0x00D261F98050CCD2ULL
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
		0xB3CCB6008E77066AULL,
		0x82C3F9D35A5BC0B4ULL,
		0x966678E69A516024ULL,
		0xE8DCA704CAABA986ULL,
		0xC983723033EC6680ULL,
		0xB3B9241FD74252DEULL,
		0x8DF41D51EE4F9961ULL,
		0x22488A523353B314ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x67996C011CEE0CD4ULL,
		0x0587F3A6B4B78169ULL,
		0x2CCCF1CD34A2C049ULL,
		0xD1B94E099557530DULL,
		0x9306E46067D8CD01ULL,
		0x6772483FAE84A5BDULL,
		0x1BE83AA3DC9F32C3ULL,
		0x449114A466A76629ULL
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
		0xE1F3254B275A1483ULL,
		0xA0BC49B06E2EE8C5ULL,
		0xFEF7B138D18D3AEBULL,
		0x3666735476ED65AEULL,
		0x3D36A6D5C3880AEDULL,
		0xAB3D8F797BF69080ULL,
		0x24878E17DAC0C7DAULL,
		0x047D8F33FFFCEB36ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC3E64A964EB42906ULL,
		0x41789360DC5DD18BULL,
		0xFDEF6271A31A75D7ULL,
		0x6CCCE6A8EDDACB5DULL,
		0x7A6D4DAB871015DAULL,
		0x567B1EF2F7ED2100ULL,
		0x490F1C2FB5818FB5ULL,
		0x08FB1E67FFF9D66CULL
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
		0xC51A1659B6B20D93ULL,
		0xD0B3FB21A545BFCCULL,
		0xA2268F57E7ED7A9CULL,
		0xD0186FB39A649A94ULL,
		0x516475F486C1E15CULL,
		0x73BD40AABEBE167DULL,
		0x01B3C9E5BB42510FULL,
		0x09E62A69D35E1F2AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8A342CB36D641B26ULL,
		0xA167F6434A8B7F99ULL,
		0x444D1EAFCFDAF539ULL,
		0xA030DF6734C93529ULL,
		0xA2C8EBE90D83C2B9ULL,
		0xE77A81557D7C2CFAULL,
		0x036793CB7684A21EULL,
		0x13CC54D3A6BC3E54ULL
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
		0x223D01FBEEF57EFAULL,
		0xDFBDA3FF61426BCBULL,
		0x6446D4218E796FF6ULL,
		0x9DC6AC3C8513D589ULL,
		0x9642C7B82F3CF826ULL,
		0xBD792754EC3E9898ULL,
		0xF6B62CE8413B7C2DULL,
		0x3EC693726ABFCBA7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x447A03F7DDEAFDF4ULL,
		0xBF7B47FEC284D796ULL,
		0xC88DA8431CF2DFEDULL,
		0x3B8D58790A27AB12ULL,
		0x2C858F705E79F04DULL,
		0x7AF24EA9D87D3131ULL,
		0xED6C59D08276F85BULL,
		0x7D8D26E4D57F974FULL
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
		0x5D8F24140F410017ULL,
		0x726C8EF7E2399CF6ULL,
		0x0433789DBD4FB7D2ULL,
		0x661ABAAC76241555ULL,
		0x231C146F55BF6CB4ULL,
		0x8BDFDEAF01B03A23ULL,
		0x1C4BE24FA3796A18ULL,
		0x260A0A3170E11C28ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB1E48281E82002EULL,
		0xE4D91DEFC47339ECULL,
		0x0866F13B7A9F6FA4ULL,
		0xCC357558EC482AAAULL,
		0x463828DEAB7ED968ULL,
		0x17BFBD5E03607446ULL,
		0x3897C49F46F2D431ULL,
		0x4C141462E1C23850ULL
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
		0x1C86D26B23AD945BULL,
		0xC4A47EFAB1FF44CDULL,
		0x22710A2A6D6EBA64ULL,
		0x4996D96B63DF1493ULL,
		0xFD003102BFA062B7ULL,
		0x53088566B2C0E117ULL,
		0xE5F177D30F228A15ULL,
		0x03496673BE9CAACEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x390DA4D6475B28B6ULL,
		0x8948FDF563FE899AULL,
		0x44E21454DADD74C9ULL,
		0x932DB2D6C7BE2926ULL,
		0xFA0062057F40C56EULL,
		0xA6110ACD6581C22FULL,
		0xCBE2EFA61E45142AULL,
		0x0692CCE77D39559DULL
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
		0xBE4F19CE71ECAE83ULL,
		0x63F3BA03F3BD68ECULL,
		0x2DB950E80DF47D00ULL,
		0xCC29581F5B62C036ULL,
		0xD06CA484202F616FULL,
		0x3896E4E72895008EULL,
		0x391DCA2055EA3EA4ULL,
		0x3F059F9DB6AB5BE4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7C9E339CE3D95D06ULL,
		0xC7E77407E77AD1D9ULL,
		0x5B72A1D01BE8FA00ULL,
		0x9852B03EB6C5806CULL,
		0xA0D94908405EC2DFULL,
		0x712DC9CE512A011DULL,
		0x723B9440ABD47D48ULL,
		0x7E0B3F3B6D56B7C8ULL
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
		0x254201461F1917D2ULL,
		0xADE84C38B1A3ED2BULL,
		0xC44C995448D9AB3FULL,
		0xAC1AAB1DD7D644C9ULL,
		0xD18DB74124A48147ULL,
		0x0F7F4423D37B01DBULL,
		0x3292F645BD6F3AB9ULL,
		0x0F660309B850BF22ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4A84028C3E322FA4ULL,
		0x5BD098716347DA56ULL,
		0x889932A891B3567FULL,
		0x5835563BAFAC8993ULL,
		0xA31B6E824949028FULL,
		0x1EFE8847A6F603B7ULL,
		0x6525EC8B7ADE7572ULL,
		0x1ECC061370A17E44ULL
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
		0xF529B2B931B8EBBFULL,
		0x0D0FC051806E8C38ULL,
		0xF295EDD01F341163ULL,
		0x441551E937F3384EULL,
		0x2B9F00B563C97B6EULL,
		0x56AFBC9747A651A6ULL,
		0x937A7877811C7EA7ULL,
		0x2A9B06ED3076826AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEA5365726371D77EULL,
		0x1A1F80A300DD1871ULL,
		0xE52BDBA03E6822C6ULL,
		0x882AA3D26FE6709DULL,
		0x573E016AC792F6DCULL,
		0xAD5F792E8F4CA34CULL,
		0x26F4F0EF0238FD4EULL,
		0x55360DDA60ED04D5ULL
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
		0xF500A8EE249E779DULL,
		0xB19DDB3DEBCDBA29ULL,
		0xA44417F370274B46ULL,
		0x44D0019F0DF908D6ULL,
		0x1A835E68B769BADDULL,
		0x4DF51B85135B9102ULL,
		0x577F9B7D7DEEAD1FULL,
		0x0151426F18426C72ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEA0151DC493CEF3AULL,
		0x633BB67BD79B7453ULL,
		0x48882FE6E04E968DULL,
		0x89A0033E1BF211ADULL,
		0x3506BCD16ED375BAULL,
		0x9BEA370A26B72204ULL,
		0xAEFF36FAFBDD5A3EULL,
		0x02A284DE3084D8E4ULL
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
		0x686DFB73334BB2E2ULL,
		0xC8E8BFAF00F24937ULL,
		0xAA2D5FF96A5E203FULL,
		0x6B8E82F35EE7A696ULL,
		0x41F09584F4350828ULL,
		0xF4CA55EAFAC7616AULL,
		0xD3D8A5B3C7EBC77CULL,
		0x196145E414033D5DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD0DBF6E6669765C4ULL,
		0x91D17F5E01E4926EULL,
		0x545ABFF2D4BC407FULL,
		0xD71D05E6BDCF4D2DULL,
		0x83E12B09E86A1050ULL,
		0xE994ABD5F58EC2D4ULL,
		0xA7B14B678FD78EF9ULL,
		0x32C28BC828067ABBULL
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
		0x113D075B614BF7F8ULL,
		0xFA4C9371A4083A40ULL,
		0x7803D0CEA290A3DBULL,
		0x6FE1A3C8E3AA1740ULL,
		0x5BA52B874C2A9D72ULL,
		0x76A8F9578E9690D7ULL,
		0xE7BF9C5296FF3817ULL,
		0x21842A26747D81FDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x227A0EB6C297EFF0ULL,
		0xF49926E348107480ULL,
		0xF007A19D452147B7ULL,
		0xDFC34791C7542E80ULL,
		0xB74A570E98553AE4ULL,
		0xED51F2AF1D2D21AEULL,
		0xCF7F38A52DFE702EULL,
		0x4308544CE8FB03FBULL
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
		0x7AB66158C564B179ULL,
		0x069372ADE0395064ULL,
		0x8B621D43E58992E1ULL,
		0x77F42FA25E71BCD2ULL,
		0x5A06E9FF1529D6E5ULL,
		0x3E66DC28BA7FD604ULL,
		0x46AEF1CC0C0DF11FULL,
		0x200CC7BFE6B13862ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF56CC2B18AC962F2ULL,
		0x0D26E55BC072A0C8ULL,
		0x16C43A87CB1325C2ULL,
		0xEFE85F44BCE379A5ULL,
		0xB40DD3FE2A53ADCAULL,
		0x7CCDB85174FFAC08ULL,
		0x8D5DE398181BE23EULL,
		0x40198F7FCD6270C4ULL
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
		0xB10203062072FA34ULL,
		0x2AFAD958BDD7FE39ULL,
		0x19231D98B77395C3ULL,
		0xADA1F7C36EDAB4AAULL,
		0x6F0CCA6AE2B7F4F1ULL,
		0xCEB33B6B9931CC50ULL,
		0xD1C073894E2E9E7BULL,
		0x38D60446B76AE2C4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6204060C40E5F468ULL,
		0x55F5B2B17BAFFC73ULL,
		0x32463B316EE72B86ULL,
		0x5B43EF86DDB56954ULL,
		0xDE1994D5C56FE9E3ULL,
		0x9D6676D7326398A0ULL,
		0xA380E7129C5D3CF7ULL,
		0x71AC088D6ED5C589ULL
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
		0xB4B6150C419689F5ULL,
		0x8250A659B33A25AFULL,
		0xF09C4434352395FAULL,
		0x6654C79320EEC225ULL,
		0xA7E81BFFF3DD962EULL,
		0xAEBA0A25C7607A07ULL,
		0x08899F878688EBD9ULL,
		0x189190404C8AFD4DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x696C2A18832D13EAULL,
		0x04A14CB366744B5FULL,
		0xE13888686A472BF5ULL,
		0xCCA98F2641DD844BULL,
		0x4FD037FFE7BB2C5CULL,
		0x5D74144B8EC0F40FULL,
		0x11133F0F0D11D7B3ULL,
		0x312320809915FA9AULL
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
		0x4862F95AB3A90798ULL,
		0x0034DDCA2E011C2BULL,
		0x265B26ADE07F2346ULL,
		0xD17ED8E4AB983279ULL,
		0xF2E3B6D45FD74C8BULL,
		0x64225985C141C61EULL,
		0x7632D73946B3F14CULL,
		0x2D11A5469D59D6BFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x90C5F2B567520F30ULL,
		0x0069BB945C023856ULL,
		0x4CB64D5BC0FE468CULL,
		0xA2FDB1C9573064F2ULL,
		0xE5C76DA8BFAE9917ULL,
		0xC844B30B82838C3DULL,
		0xEC65AE728D67E298ULL,
		0x5A234A8D3AB3AD7EULL
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
		0x5E595CB049DCBAECULL,
		0x29B44CD3966FA0B3ULL,
		0x6E925095EF38E052ULL,
		0xB9DF90D9F3876ADDULL,
		0xD8706D66485A1AB3ULL,
		0x745C0D16162C83B7ULL,
		0xB8C2DC09E4544E08ULL,
		0x387205E0AADDB131ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBCB2B96093B975D8ULL,
		0x536899A72CDF4166ULL,
		0xDD24A12BDE71C0A4ULL,
		0x73BF21B3E70ED5BAULL,
		0xB0E0DACC90B43567ULL,
		0xE8B81A2C2C59076FULL,
		0x7185B813C8A89C10ULL,
		0x70E40BC155BB6263ULL
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
		0x587CBC81442DA24CULL,
		0x7542F95D11940688ULL,
		0x02924A6175A58816ULL,
		0x8FE77D67C0012236ULL,
		0xB90934B632F7CC03ULL,
		0x2E615ECC5A53DA4BULL,
		0x805E7ADEEB08151FULL,
		0x15E7DD703354D3F7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB0F97902885B4498ULL,
		0xEA85F2BA23280D10ULL,
		0x052494C2EB4B102CULL,
		0x1FCEFACF8002446CULL,
		0x7212696C65EF9807ULL,
		0x5CC2BD98B4A7B497ULL,
		0x00BCF5BDD6102A3EULL,
		0x2BCFBAE066A9A7EFULL
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
		0x54032F4D531D38FBULL,
		0x3B7108780FF7149FULL,
		0x433261644FD38EC6ULL,
		0x1F6C18E8FFEDB61EULL,
		0x26C7BD2F1F50EE8BULL,
		0x50C0494D98DF77A5ULL,
		0xD7B65D7BD3D50A83ULL,
		0x33767EED6B1924F9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA8065E9AA63A71F6ULL,
		0x76E210F01FEE293EULL,
		0x8664C2C89FA71D8CULL,
		0x3ED831D1FFDB6C3CULL,
		0x4D8F7A5E3EA1DD16ULL,
		0xA180929B31BEEF4AULL,
		0xAF6CBAF7A7AA1506ULL,
		0x66ECFDDAD63249F3ULL
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
		0x3BACFA17CAC99786ULL,
		0xEC321A8009BB4E04ULL,
		0x14040D7836CFD876ULL,
		0xE65F864FF58E6B55ULL,
		0x3F6DAC5FA7812D10ULL,
		0x5F53B74FEEC0A830ULL,
		0x29547031FC83B070ULL,
		0x3D42F94D6C88DAA3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7759F42F95932F0CULL,
		0xD864350013769C08ULL,
		0x28081AF06D9FB0EDULL,
		0xCCBF0C9FEB1CD6AAULL,
		0x7EDB58BF4F025A21ULL,
		0xBEA76E9FDD815060ULL,
		0x52A8E063F90760E0ULL,
		0x7A85F29AD911B546ULL
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
		0x043F3BC53F747300ULL,
		0xF92EE58B33944CE2ULL,
		0xB0E46C3115E94B94ULL,
		0xF8BD0C06A8B0E3FFULL,
		0x589DE88654AF1CE9ULL,
		0x6A5F7ACBA7F9A576ULL,
		0xD7E789468092FD29ULL,
		0x34630D64CE5A503FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x087E778A7EE8E600ULL,
		0xF25DCB16672899C4ULL,
		0x61C8D8622BD29729ULL,
		0xF17A180D5161C7FFULL,
		0xB13BD10CA95E39D3ULL,
		0xD4BEF5974FF34AECULL,
		0xAFCF128D0125FA52ULL,
		0x68C61AC99CB4A07FULL
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
		0x495EC90547466F1AULL,
		0xF2000B187DBF2D16ULL,
		0x4B8D252B49445A84ULL,
		0x9293C96BCD000180ULL,
		0xF04F53E920A1C8BCULL,
		0xC6EB6AA683B21DEFULL,
		0x82FAE9E1ED563C8AULL,
		0x00066C342018EA37ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x92BD920A8E8CDE34ULL,
		0xE4001630FB7E5A2CULL,
		0x971A4A569288B509ULL,
		0x252792D79A000300ULL,
		0xE09EA7D241439179ULL,
		0x8DD6D54D07643BDFULL,
		0x05F5D3C3DAAC7915ULL,
		0x000CD8684031D46FULL
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
		0x5B00BA22FB67A27DULL,
		0xEEBA6137D883B4E6ULL,
		0xB3E1486A9A9DEA38ULL,
		0x4EED589F110028DEULL,
		0x02C70816E5BE0334ULL,
		0xBFC1B8440F2BE9BCULL,
		0xCE424543EB2BADB5ULL,
		0x3A5E94CEF7B551BBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB6017445F6CF44FAULL,
		0xDD74C26FB10769CCULL,
		0x67C290D5353BD471ULL,
		0x9DDAB13E220051BDULL,
		0x058E102DCB7C0668ULL,
		0x7F8370881E57D378ULL,
		0x9C848A87D6575B6BULL,
		0x74BD299DEF6AA377ULL
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
		0xBC62394CD60980C9ULL,
		0x97E39236D1DFD7DCULL,
		0x242193C96C6AE010ULL,
		0xD53FA130945E7A87ULL,
		0xB8F5328BD86EC492ULL,
		0x7C004255289C1E04ULL,
		0xDF680F556D0CE347ULL,
		0x1EFDF05E0FC05D57ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x78C47299AC130192ULL,
		0x2FC7246DA3BFAFB9ULL,
		0x48432792D8D5C021ULL,
		0xAA7F426128BCF50EULL,
		0x71EA6517B0DD8925ULL,
		0xF80084AA51383C09ULL,
		0xBED01EAADA19C68EULL,
		0x3DFBE0BC1F80BAAFULL
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
		0x62063CCEAF3BB427ULL,
		0x67AED8F02D33978AULL,
		0xD869C8C8BA298D1AULL,
		0xB309E6D0B540D944ULL,
		0x90A50CB28F4B8CC5ULL,
		0x6AC4B84C09BA6865ULL,
		0x1FC662A2068AC15FULL,
		0x26FC1066C6482B2DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC40C799D5E77684EULL,
		0xCF5DB1E05A672F14ULL,
		0xB0D3919174531A34ULL,
		0x6613CDA16A81B289ULL,
		0x214A19651E97198BULL,
		0xD58970981374D0CBULL,
		0x3F8CC5440D1582BEULL,
		0x4DF820CD8C90565AULL
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
		0xEDBBB3BACAE0DE7BULL,
		0xBE0EB9DF482E8346ULL,
		0x2FF3C2161C6E1226ULL,
		0xA4A24BD49EC445C9ULL,
		0x052284E9167975BCULL,
		0x1743C4ACCCCD21BAULL,
		0xEBD7C746286F1D83ULL,
		0x086349056074C10EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDB77677595C1BCF6ULL,
		0x7C1D73BE905D068DULL,
		0x5FE7842C38DC244DULL,
		0x494497A93D888B92ULL,
		0x0A4509D22CF2EB79ULL,
		0x2E878959999A4374ULL,
		0xD7AF8E8C50DE3B06ULL,
		0x10C6920AC0E9821DULL
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
		0xD5425FE993D837B8ULL,
		0x12FC215E74FD49B6ULL,
		0x5B6070D3D1C00A2CULL,
		0x55B899C05C127E03ULL,
		0x77FD9A436BA72E68ULL,
		0x51541827AE949037ULL,
		0xDBA6D79315A1A755ULL,
		0x38DF5E803C6079A4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAA84BFD327B06F70ULL,
		0x25F842BCE9FA936DULL,
		0xB6C0E1A7A3801458ULL,
		0xAB713380B824FC06ULL,
		0xEFFB3486D74E5CD0ULL,
		0xA2A8304F5D29206EULL,
		0xB74DAF262B434EAAULL,
		0x71BEBD0078C0F349ULL
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
		0x6529EE818D7AEBCBULL,
		0x8DC8CB0D6FF5EBA5ULL,
		0xD44F39BDFD96A282ULL,
		0xF7E89EE730488A5CULL,
		0xB6ABEAEA158926E0ULL,
		0x98174590CE4F1BABULL,
		0xE8AB719C769A30F6ULL,
		0x3145B9D0A5C0F0EAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCA53DD031AF5D796ULL,
		0x1B91961ADFEBD74AULL,
		0xA89E737BFB2D4505ULL,
		0xEFD13DCE609114B9ULL,
		0x6D57D5D42B124DC1ULL,
		0x302E8B219C9E3757ULL,
		0xD156E338ED3461EDULL,
		0x628B73A14B81E1D5ULL
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
		0xA46EB7605EA3459EULL,
		0xD33CD1F3BB4AE095ULL,
		0xE466AF43C2D5266CULL,
		0x54A52AF0207F8A27ULL,
		0x7FB82BF40B9E33EFULL,
		0x7C04CCFF62344C45ULL,
		0xB66571912CE16870ULL,
		0x2C1C996F9FEFC0E7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x48DD6EC0BD468B3CULL,
		0xA679A3E77695C12BULL,
		0xC8CD5E8785AA4CD9ULL,
		0xA94A55E040FF144FULL,
		0xFF7057E8173C67DEULL,
		0xF80999FEC468988AULL,
		0x6CCAE32259C2D0E0ULL,
		0x583932DF3FDF81CFULL
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
		0x317654D2F39204DAULL,
		0xE17CF89B53F71BF9ULL,
		0xF683F642A7FFD959ULL,
		0xE4E94E031670D133ULL,
		0x4F7ED1DAB1AA0725ULL,
		0x9946BC54C8AB8475ULL,
		0x6F795F2301D0C325ULL,
		0x2A2C284D6D3B4DE5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x62ECA9A5E72409B4ULL,
		0xC2F9F136A7EE37F2ULL,
		0xED07EC854FFFB2B3ULL,
		0xC9D29C062CE1A267ULL,
		0x9EFDA3B563540E4BULL,
		0x328D78A9915708EAULL,
		0xDEF2BE4603A1864BULL,
		0x5458509ADA769BCAULL
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
		0xAE863C0F71CC8764ULL,
		0xE44D4C61BB8FDC7FULL,
		0xE2C3D50D2E8D4914ULL,
		0x6AE90142845C277AULL,
		0x4EFDB5EB62F54368ULL,
		0xACA69A741581F478ULL,
		0x19A622D0B700226FULL,
		0x31D2F81BEB92095EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5D0C781EE3990EC8ULL,
		0xC89A98C3771FB8FFULL,
		0xC587AA1A5D1A9229ULL,
		0xD5D2028508B84EF5ULL,
		0x9DFB6BD6C5EA86D0ULL,
		0x594D34E82B03E8F0ULL,
		0x334C45A16E0044DFULL,
		0x63A5F037D72412BCULL
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
		0x697925BF467E77B4ULL,
		0xB7893FFB5B69E7BCULL,
		0xE668ECFAF839F69DULL,
		0x755993BB9BB27652ULL,
		0x254BD61E41BB08E8ULL,
		0xDCBE780506C2C35BULL,
		0x770C16AE32A87103ULL,
		0x1A2AE26209462A3DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD2F24B7E8CFCEF68ULL,
		0x6F127FF6B6D3CF78ULL,
		0xCCD1D9F5F073ED3BULL,
		0xEAB327773764ECA5ULL,
		0x4A97AC3C837611D0ULL,
		0xB97CF00A0D8586B6ULL,
		0xEE182D5C6550E207ULL,
		0x3455C4C4128C547AULL
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
		0xC52250DA218B8710ULL,
		0xEFACAD40CD784624ULL,
		0xEF2756E5AE87A118ULL,
		0x695B5AA8374FB8F7ULL,
		0xA953E6CB6ABECA1EULL,
		0xDD7C160B69369ABEULL,
		0x75ADC7D266AA4518ULL,
		0x131A52C9F5A6DA30ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8A44A1B443170E20ULL,
		0xDF595A819AF08C49ULL,
		0xDE4EADCB5D0F4231ULL,
		0xD2B6B5506E9F71EFULL,
		0x52A7CD96D57D943CULL,
		0xBAF82C16D26D357DULL,
		0xEB5B8FA4CD548A31ULL,
		0x2634A593EB4DB460ULL
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
		0x97DD86481D44CA3BULL,
		0x8FB22BA415A6D8F4ULL,
		0x30364DD287AE280CULL,
		0x04AE9E0CE1BE2763ULL,
		0xCD5BA846480E3F09ULL,
		0xC0338738E6FCFF0EULL,
		0xBB453569AD4F25E9ULL,
		0x2CF8E7F44CE37EB3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2FBB0C903A899476ULL,
		0x1F6457482B4DB1E9ULL,
		0x606C9BA50F5C5019ULL,
		0x095D3C19C37C4EC6ULL,
		0x9AB7508C901C7E12ULL,
		0x80670E71CDF9FE1DULL,
		0x768A6AD35A9E4BD3ULL,
		0x59F1CFE899C6FD67ULL
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
		0x84A00FC3F11BE07EULL,
		0x4077B6B68BF1A9E7ULL,
		0xD30E4CECB9BB3E17ULL,
		0x7FBC7D1DB4F2D5FCULL,
		0x7231AD86CB43B38AULL,
		0x97EAC011A8FDBC30ULL,
		0xD633330C76590CCFULL,
		0x03AABFA2D943570EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x09401F87E237C0FCULL,
		0x80EF6D6D17E353CFULL,
		0xA61C99D973767C2EULL,
		0xFF78FA3B69E5ABF9ULL,
		0xE4635B0D96876714ULL,
		0x2FD5802351FB7860ULL,
		0xAC666618ECB2199FULL,
		0x07557F45B286AE1DULL
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
		0x8CE53D9EECA65693ULL,
		0x12FAF61D8660E508ULL,
		0x212BCD61A5A61D37ULL,
		0x289668200F222BE6ULL,
		0x1160FE8A0AE42414ULL,
		0x2C4E83EF2A0274C7ULL,
		0xE9F447087290B9ADULL,
		0x13CCD861FDCE4693ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x19CA7B3DD94CAD26ULL,
		0x25F5EC3B0CC1CA11ULL,
		0x42579AC34B4C3A6EULL,
		0x512CD0401E4457CCULL,
		0x22C1FD1415C84828ULL,
		0x589D07DE5404E98EULL,
		0xD3E88E10E521735AULL,
		0x2799B0C3FB9C8D27ULL
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
		0xDFB9B3953CB47F07ULL,
		0xFD77AB14E47C7927ULL,
		0xE0458D485E76F0ECULL,
		0x8165F1026169D873ULL,
		0x047B87A538A618D5ULL,
		0x6034692735F4BCB3ULL,
		0x3D44BC8EB8AD83DDULL,
		0x046CBE341A035D3BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBF73672A7968FE0EULL,
		0xFAEF5629C8F8F24FULL,
		0xC08B1A90BCEDE1D9ULL,
		0x02CBE204C2D3B0E7ULL,
		0x08F70F4A714C31ABULL,
		0xC068D24E6BE97966ULL,
		0x7A89791D715B07BAULL,
		0x08D97C683406BA76ULL
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
		0x71DB12DF742F5ADDULL,
		0xE85E3FF2AA172D95ULL,
		0xEE136D831DD7831BULL,
		0x236D8F43AE161300ULL,
		0xACAFDE5AE4595D57ULL,
		0xBC752CD2AAEDE256ULL,
		0x90DB009EB471A098ULL,
		0x146E4354BDA965FAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE3B625BEE85EB5BAULL,
		0xD0BC7FE5542E5B2AULL,
		0xDC26DB063BAF0637ULL,
		0x46DB1E875C2C2601ULL,
		0x595FBCB5C8B2BAAEULL,
		0x78EA59A555DBC4ADULL,
		0x21B6013D68E34131ULL,
		0x28DC86A97B52CBF5ULL
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
		0x921B8A683767E114ULL,
		0x96A8DE3633BCD68BULL,
		0x2442F3157B92D71DULL,
		0xA872BE51B8BE27CAULL,
		0x8ED4475BCA4C279CULL,
		0xA44B92FB13FD7D1CULL,
		0x4979BEEDA98E34C9ULL,
		0x26B2FF0FB6855FD9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x243714D06ECFC228ULL,
		0x2D51BC6C6779AD17ULL,
		0x4885E62AF725AE3BULL,
		0x50E57CA3717C4F94ULL,
		0x1DA88EB794984F39ULL,
		0x489725F627FAFA39ULL,
		0x92F37DDB531C6993ULL,
		0x4D65FE1F6D0ABFB2ULL
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
		0x930208A78E6E1771ULL,
		0xD3EC576049E43426ULL,
		0x354FCDC177D81314ULL,
		0x3849C79B8081416CULL,
		0x6623DCBED1A649ABULL,
		0x228A9579DCCF18BEULL,
		0xC8695A3A1ED39403ULL,
		0x3EB2A1E24C874215ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2604114F1CDC2EE2ULL,
		0xA7D8AEC093C8684DULL,
		0x6A9F9B82EFB02629ULL,
		0x70938F37010282D8ULL,
		0xCC47B97DA34C9356ULL,
		0x45152AF3B99E317CULL,
		0x90D2B4743DA72806ULL,
		0x7D6543C4990E842BULL
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
		0xA79AD8D2926EEF3AULL,
		0x682CAE01DDA66E13ULL,
		0xBF1B374CAEB28717ULL,
		0xBC572D8E1E7C0C58ULL,
		0x82C9E682FE65695EULL,
		0x1920C7B541ECF6C7ULL,
		0x77ED0904C45338B3ULL,
		0x1E6E9531D741293BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4F35B1A524DDDE74ULL,
		0xD0595C03BB4CDC27ULL,
		0x7E366E995D650E2EULL,
		0x78AE5B1C3CF818B1ULL,
		0x0593CD05FCCAD2BDULL,
		0x32418F6A83D9ED8FULL,
		0xEFDA120988A67166ULL,
		0x3CDD2A63AE825276ULL
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
		0xD05059EFEE6179E4ULL,
		0x93CD34157B87DAFAULL,
		0x076B5B8DFC783BF3ULL,
		0xE1F77CECFA6C6337ULL,
		0x1DE9E95DF85B9E67ULL,
		0x78D75798123D38F0ULL,
		0x004F6095E8778C90ULL,
		0x3A287106B734FBF0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA0A0B3DFDCC2F3C8ULL,
		0x279A682AF70FB5F5ULL,
		0x0ED6B71BF8F077E7ULL,
		0xC3EEF9D9F4D8C66EULL,
		0x3BD3D2BBF0B73CCFULL,
		0xF1AEAF30247A71E0ULL,
		0x009EC12BD0EF1920ULL,
		0x7450E20D6E69F7E0ULL
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
		0xD602445E2D2D4C0EULL,
		0x5185F863E9EC2276ULL,
		0x3A5A2BF7B6F3995FULL,
		0x375B3ABB5AFB122DULL,
		0x6BA58CDA1A603C9FULL,
		0x3EC9B04B1C53BC48ULL,
		0x63D3E4B851E58CC8ULL,
		0x3E6FD613FC5894EFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAC0488BC5A5A981CULL,
		0xA30BF0C7D3D844EDULL,
		0x74B457EF6DE732BEULL,
		0x6EB67576B5F6245AULL,
		0xD74B19B434C0793EULL,
		0x7D93609638A77890ULL,
		0xC7A7C970A3CB1990ULL,
		0x7CDFAC27F8B129DEULL
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
		0xADD7025507E06CC2ULL,
		0x2DB7FF5369F2D6A0ULL,
		0x77DA239C24467C5FULL,
		0x9441E8D2BB91F735ULL,
		0xD4F3CD74B03FC1B9ULL,
		0xFE7F843366B084B9ULL,
		0x1C48E00CE0F67DD6ULL,
		0x00060843CF219F2AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5BAE04AA0FC0D984ULL,
		0x5B6FFEA6D3E5AD41ULL,
		0xEFB44738488CF8BEULL,
		0x2883D1A57723EE6AULL,
		0xA9E79AE9607F8373ULL,
		0xFCFF0866CD610973ULL,
		0x3891C019C1ECFBADULL,
		0x000C10879E433E54ULL
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
		0x11B51F565FC26928ULL,
		0x7D8EB92BDE031AF9ULL,
		0x92EB4914BBCB9587ULL,
		0x8F12321C0FE287C4ULL,
		0x6E6732E7EB9615B0ULL,
		0x257C966D8BEBCD99ULL,
		0x986838BF6A76125EULL,
		0x22FA920AC2A898BCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x236A3EACBF84D250ULL,
		0xFB1D7257BC0635F2ULL,
		0x25D6922977972B0EULL,
		0x1E2464381FC50F89ULL,
		0xDCCE65CFD72C2B61ULL,
		0x4AF92CDB17D79B32ULL,
		0x30D0717ED4EC24BCULL,
		0x45F5241585513179ULL
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
		0x3D9B635450149ED2ULL,
		0xF91C8F5B8DE8EB33ULL,
		0x6B19B957DACEC511ULL,
		0x662AE9E26892D8F7ULL,
		0x260D01E1F6847007ULL,
		0xB52680E9E9D8F17AULL,
		0x0C4E6B5F9E3BF678ULL,
		0x1ECA7B9A1B293558ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7B36C6A8A0293DA4ULL,
		0xF2391EB71BD1D666ULL,
		0xD63372AFB59D8A23ULL,
		0xCC55D3C4D125B1EEULL,
		0x4C1A03C3ED08E00EULL,
		0x6A4D01D3D3B1E2F4ULL,
		0x189CD6BF3C77ECF1ULL,
		0x3D94F73436526AB0ULL
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
		0x53E879BE366A077CULL,
		0xC34AD62D26982C6DULL,
		0xB699F80BCFE0E2C0ULL,
		0xC929300D86C2069FULL,
		0x6263567EE689DD9FULL,
		0x5FF1353C50418A10ULL,
		0x3DEC5FDA4B176E23ULL,
		0x379A932017378030ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA7D0F37C6CD40EF8ULL,
		0x8695AC5A4D3058DAULL,
		0x6D33F0179FC1C581ULL,
		0x9252601B0D840D3FULL,
		0xC4C6ACFDCD13BB3FULL,
		0xBFE26A78A0831420ULL,
		0x7BD8BFB4962EDC46ULL,
		0x6F3526402E6F0060ULL
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
		0x17FC493E4EE88773ULL,
		0x7C3025F8BB1AD3F0ULL,
		0xA0A303EC6F25F8C5ULL,
		0xCF67EEF0D9067236ULL,
		0xA033F3AE93A821D5ULL,
		0x86A21BD27EC1CC40ULL,
		0xDCA75E2A1254B991ULL,
		0x2CBB8C77AF54EDB6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2FF8927C9DD10EE6ULL,
		0xF8604BF17635A7E0ULL,
		0x414607D8DE4BF18AULL,
		0x9ECFDDE1B20CE46DULL,
		0x4067E75D275043ABULL,
		0x0D4437A4FD839881ULL,
		0xB94EBC5424A97323ULL,
		0x597718EF5EA9DB6DULL
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
		0xF151A5324E0BFE24ULL,
		0xCD5EE0411D591B53ULL,
		0x13A0B76EEC6FE748ULL,
		0x5676AFA7DDE0440FULL,
		0xD7CA72D8D0E5D072ULL,
		0x1C8A1303EAE7357EULL,
		0x2306B37F63CB9360ULL,
		0x3D96BFF5A0A4A57CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE2A34A649C17FC48ULL,
		0x9ABDC0823AB236A7ULL,
		0x27416EDDD8DFCE91ULL,
		0xACED5F4FBBC0881EULL,
		0xAF94E5B1A1CBA0E4ULL,
		0x39142607D5CE6AFDULL,
		0x460D66FEC79726C0ULL,
		0x7B2D7FEB41494AF8ULL
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
		0xC76FC1897CA26455ULL,
		0x28A4878E4FD1ED5DULL,
		0x51E261BFECAFC3B5ULL,
		0x083A10CB9F044823ULL,
		0x8FBFF0ECECC7C0E6ULL,
		0x71D8E0187CCAA812ULL,
		0x209CDF0E04B5C21DULL,
		0x211833837C7DD913ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8EDF8312F944C8AAULL,
		0x51490F1C9FA3DABBULL,
		0xA3C4C37FD95F876AULL,
		0x107421973E089046ULL,
		0x1F7FE1D9D98F81CCULL,
		0xE3B1C030F9955025ULL,
		0x4139BE1C096B843AULL,
		0x42306706F8FBB226ULL
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
		0xC78A1123006FB9E4ULL,
		0x418B5837ACD0A247ULL,
		0x695325396F734940ULL,
		0x88524B1015A9413BULL,
		0x01CEC563D24393B7ULL,
		0x6AFC3FDE7D2CA12EULL,
		0x7F0F8DB509291B6FULL,
		0x1CEA0B11FB849B0CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8F14224600DF73C8ULL,
		0x8316B06F59A1448FULL,
		0xD2A64A72DEE69280ULL,
		0x10A496202B528276ULL,
		0x039D8AC7A487276FULL,
		0xD5F87FBCFA59425CULL,
		0xFE1F1B6A125236DEULL,
		0x39D41623F7093618ULL
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
		0xC4DA1371DC3F3323ULL,
		0x873E265193ECD4CBULL,
		0xF14CBF64DC846285ULL,
		0xB41A097F83F909F4ULL,
		0xA8F7EA350E70A2EDULL,
		0x3C6A9755B1555B1CULL,
		0x1A5BEA55A08E41E8ULL,
		0x35D9C700515D41E9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x89B426E3B87E6646ULL,
		0x0E7C4CA327D9A997ULL,
		0xE2997EC9B908C50BULL,
		0x683412FF07F213E9ULL,
		0x51EFD46A1CE145DBULL,
		0x78D52EAB62AAB639ULL,
		0x34B7D4AB411C83D0ULL,
		0x6BB38E00A2BA83D2ULL
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
		0x77643BA6D30E8301ULL,
		0x4AB6D2E6BA0527CCULL,
		0x3876C6F723345FCBULL,
		0xABE1C566FABDF6EFULL,
		0xD08E1881B1DCF6E6ULL,
		0x57C53A06EC57EFB2ULL,
		0x68BF41C3A597E77EULL,
		0x1F76CA45F7CCC3BCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEEC8774DA61D0602ULL,
		0x956DA5CD740A4F98ULL,
		0x70ED8DEE4668BF96ULL,
		0x57C38ACDF57BEDDEULL,
		0xA11C310363B9EDCDULL,
		0xAF8A740DD8AFDF65ULL,
		0xD17E83874B2FCEFCULL,
		0x3EED948BEF998778ULL
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
		0x86822F28DFB8AF0DULL,
		0x0329D4F9AC7576FDULL,
		0x186440C9F10208EEULL,
		0x8F38EC0026BD04B7ULL,
		0x994637323EA2F778ULL,
		0x4C84371E14FC9CB3ULL,
		0x6A697BE0EBF3AD11ULL,
		0x16B5A65C631FED94ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0D045E51BF715E1AULL,
		0x0653A9F358EAEDFBULL,
		0x30C88193E20411DCULL,
		0x1E71D8004D7A096EULL,
		0x328C6E647D45EEF1ULL,
		0x99086E3C29F93967ULL,
		0xD4D2F7C1D7E75A22ULL,
		0x2D6B4CB8C63FDB28ULL
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
		0x2EE799984DA25E69ULL,
		0xE358DFD22A1C59D6ULL,
		0x649A9C9AB0F6F31DULL,
		0x2E8E57271F4DC944ULL,
		0xC33204E518C9C28EULL,
		0x652352B6CBFF1162ULL,
		0x86CFB2F2C6D84AD5ULL,
		0x3B7ED895DCE1AA40ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5DCF33309B44BCD2ULL,
		0xC6B1BFA45438B3ACULL,
		0xC935393561EDE63BULL,
		0x5D1CAE4E3E9B9288ULL,
		0x866409CA3193851CULL,
		0xCA46A56D97FE22C5ULL,
		0x0D9F65E58DB095AAULL,
		0x76FDB12BB9C35481ULL
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
		0x964166A67D92E788ULL,
		0xBFF2654ED792A4D9ULL,
		0x14D16731D29F1084ULL,
		0xDDF63E82BE6E1CE3ULL,
		0x775F0E6505052A2BULL,
		0xE674C722CAC95E63ULL,
		0xDD9F7212CE2488F2ULL,
		0x2563FBB1EB553841ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2C82CD4CFB25CF10ULL,
		0x7FE4CA9DAF2549B3ULL,
		0x29A2CE63A53E2109ULL,
		0xBBEC7D057CDC39C6ULL,
		0xEEBE1CCA0A0A5457ULL,
		0xCCE98E459592BCC6ULL,
		0xBB3EE4259C4911E5ULL,
		0x4AC7F763D6AA7083ULL
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
		0x25D7C77E1FB1C2ECULL,
		0xC71D14B41BA9AB9FULL,
		0x4BA18E7EE06FA8AEULL,
		0x7F4566EDF9068DC5ULL,
		0x6D05EC7DBBE9BBE1ULL,
		0x615CB5B772E10136ULL,
		0x6583852DF630969BULL,
		0x137EF166C8DF345DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4BAF8EFC3F6385D8ULL,
		0x8E3A29683753573EULL,
		0x97431CFDC0DF515DULL,
		0xFE8ACDDBF20D1B8AULL,
		0xDA0BD8FB77D377C2ULL,
		0xC2B96B6EE5C2026CULL,
		0xCB070A5BEC612D36ULL,
		0x26FDE2CD91BE68BAULL
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
		0xF8F493BC4F4143FAULL,
		0xD3E7DBDA2236C4FDULL,
		0x3A075FEF1B79AA63ULL,
		0xF7169CADE8C0781EULL,
		0x041A149E286CCBBEULL,
		0x0F9A6CEB2CB14059ULL,
		0x9F63081231CFE5F0ULL,
		0x214A0B9C87896E6EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF1E927789E8287F4ULL,
		0xA7CFB7B4446D89FBULL,
		0x740EBFDE36F354C7ULL,
		0xEE2D395BD180F03CULL,
		0x0834293C50D9977DULL,
		0x1F34D9D6596280B2ULL,
		0x3EC61024639FCBE0ULL,
		0x429417390F12DCDDULL
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
		0x6DB1DC723F0C7AEAULL,
		0x83A330DBB12FA9CDULL,
		0x751916A452A937EDULL,
		0x0EA0D3EC17A0DD05ULL,
		0x9A928B58A24CF5FFULL,
		0x04EE688F11E81466ULL,
		0xDBB7F90EFADE33FBULL,
		0x283EC2F4B89195E4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDB63B8E47E18F5D4ULL,
		0x074661B7625F539AULL,
		0xEA322D48A5526FDBULL,
		0x1D41A7D82F41BA0AULL,
		0x352516B14499EBFEULL,
		0x09DCD11E23D028CDULL,
		0xB76FF21DF5BC67F6ULL,
		0x507D85E971232BC9ULL
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
		0x70BC60B34F85A0A1ULL,
		0xF814FF6C1FFF70CCULL,
		0x0C712E35DF66AEA6ULL,
		0x4E63145B35CDD872ULL,
		0xC3E3C12677DA9C3EULL,
		0x046E437B2D0F8B4CULL,
		0x4DDA74A70231DB71ULL,
		0x0A9ABD32184B0203ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE178C1669F0B4142ULL,
		0xF029FED83FFEE198ULL,
		0x18E25C6BBECD5D4DULL,
		0x9CC628B66B9BB0E4ULL,
		0x87C7824CEFB5387CULL,
		0x08DC86F65A1F1699ULL,
		0x9BB4E94E0463B6E2ULL,
		0x15357A6430960406ULL
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
		0x5BF5555AC21761E0ULL,
		0x88FF19F385827B46ULL,
		0xACB7F2CFFC896CCBULL,
		0xE322F9F310479080ULL,
		0x28C9535C07C7CA68ULL,
		0xC450564F48CBF8FBULL,
		0xE0F62E2C756E979BULL,
		0x322A1F35C9F8DD94ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB7EAAAB5842EC3C0ULL,
		0x11FE33E70B04F68CULL,
		0x596FE59FF912D997ULL,
		0xC645F3E6208F2101ULL,
		0x5192A6B80F8F94D1ULL,
		0x88A0AC9E9197F1F6ULL,
		0xC1EC5C58EADD2F37ULL,
		0x64543E6B93F1BB29ULL
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
		0xDD30971B47362F9DULL,
		0x3C66AD165516921AULL,
		0xEDEDF5821460DF10ULL,
		0x9A2CEC6A3B5DD8B1ULL,
		0xB7FB547B632BBE9DULL,
		0x71577A5C76926657ULL,
		0x2DDBAE64ED711A1EULL,
		0x29AFFAE197C472B8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBA612E368E6C5F3AULL,
		0x78CD5A2CAA2D2435ULL,
		0xDBDBEB0428C1BE20ULL,
		0x3459D8D476BBB163ULL,
		0x6FF6A8F6C6577D3BULL,
		0xE2AEF4B8ED24CCAFULL,
		0x5BB75CC9DAE2343CULL,
		0x535FF5C32F88E570ULL
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
		0x81FC8A40A4848B41ULL,
		0xD0C4E4929ECE90B3ULL,
		0xDF4FB55746D480BAULL,
		0xE657498B95A3D4C8ULL,
		0xF461B9F7F73AF8DAULL,
		0xC4C77D315579F48EULL,
		0x38742749F41D67AAULL,
		0x0D10F11F13E2BE5BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x03F9148149091682ULL,
		0xA189C9253D9D2167ULL,
		0xBE9F6AAE8DA90175ULL,
		0xCCAE93172B47A991ULL,
		0xE8C373EFEE75F1B5ULL,
		0x898EFA62AAF3E91DULL,
		0x70E84E93E83ACF55ULL,
		0x1A21E23E27C57CB6ULL
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
		0x6DEE69CDA8436700ULL,
		0x633503310BFE11BAULL,
		0xE3DB6C1C8682CF52ULL,
		0x6C6284845AC9AFD5ULL,
		0x051B7B61FC490F11ULL,
		0x60179EEC83CAAB40ULL,
		0x5F81A05F23909D8EULL,
		0x0D25EA2D9E619185ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDBDCD39B5086CE00ULL,
		0xC66A066217FC2374ULL,
		0xC7B6D8390D059EA4ULL,
		0xD8C50908B5935FABULL,
		0x0A36F6C3F8921E22ULL,
		0xC02F3DD907955680ULL,
		0xBF0340BE47213B1CULL,
		0x1A4BD45B3CC3230AULL
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
		0xCA4418320FD625B6ULL,
		0xBACDF09291C2954BULL,
		0x9D31564A542E7CF6ULL,
		0x50882366A8E0BB5AULL,
		0x89703A40194A33AFULL,
		0xA0C860D9D4D934C5ULL,
		0x93E7479C8EF354B5ULL,
		0x20C6ED23382D8010ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x948830641FAC4B6CULL,
		0x759BE12523852A97ULL,
		0x3A62AC94A85CF9EDULL,
		0xA11046CD51C176B5ULL,
		0x12E074803294675EULL,
		0x4190C1B3A9B2698BULL,
		0x27CE8F391DE6A96BULL,
		0x418DDA46705B0021ULL
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
		0xEB55E075C910992EULL,
		0xE4D03736E561960EULL,
		0x842E8478E022098AULL,
		0x36F7C219B9B14625ULL,
		0x2CED1B7868AF37C2ULL,
		0x730294A604FE3FFFULL,
		0xF4405C07B5D0C141ULL,
		0x3CEB0D0AAF7ED2F7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD6ABC0EB9221325CULL,
		0xC9A06E6DCAC32C1DULL,
		0x085D08F1C0441315ULL,
		0x6DEF843373628C4BULL,
		0x59DA36F0D15E6F84ULL,
		0xE605294C09FC7FFEULL,
		0xE880B80F6BA18282ULL,
		0x79D61A155EFDA5EFULL
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
		0x1C046BDACD9F7481ULL,
		0xEB994F5EAD739E33ULL,
		0x47D79F5666274568ULL,
		0xA917594B487FE69AULL,
		0x861C71DB9D9B5C2CULL,
		0x958868128C573801ULL,
		0x746E14B8C33CD436ULL,
		0x0606DB211C70B7E0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3808D7B59B3EE902ULL,
		0xD7329EBD5AE73C66ULL,
		0x8FAF3EACCC4E8AD1ULL,
		0x522EB29690FFCD34ULL,
		0x0C38E3B73B36B859ULL,
		0x2B10D02518AE7003ULL,
		0xE8DC29718679A86DULL,
		0x0C0DB64238E16FC0ULL
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
		0x5F1D6A229DE1DA20ULL,
		0x0861D09EAA782362ULL,
		0xD47970AB12C280DCULL,
		0xDC455B3B62CAD264ULL,
		0xA718EBF328FC5262ULL,
		0xB75DE1EAE1E83682ULL,
		0x8D21D903C1668F3EULL,
		0x28989EE8E34F70FDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBE3AD4453BC3B440ULL,
		0x10C3A13D54F046C4ULL,
		0xA8F2E156258501B8ULL,
		0xB88AB676C595A4C9ULL,
		0x4E31D7E651F8A4C5ULL,
		0x6EBBC3D5C3D06D05ULL,
		0x1A43B20782CD1E7DULL,
		0x51313DD1C69EE1FBULL
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
		0x7A672D48652955B7ULL,
		0xC194ACB7B169F2FFULL,
		0x4EEAF6353E6C00CBULL,
		0xCAF889F97C202FD0ULL,
		0x027AF5AF848CE4DDULL,
		0x760DCCD78E09C60DULL,
		0xFE9ABFAED1246A17ULL,
		0x2DB5AAF5534D7EE1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF4CE5A90CA52AB6EULL,
		0x8329596F62D3E5FEULL,
		0x9DD5EC6A7CD80197ULL,
		0x95F113F2F8405FA0ULL,
		0x04F5EB5F0919C9BBULL,
		0xEC1B99AF1C138C1AULL,
		0xFD357F5DA248D42EULL,
		0x5B6B55EAA69AFDC3ULL
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
		0xF53CA9301FE223A7ULL,
		0x29A95E1DC4165B5FULL,
		0xCDA598229FB7DF45ULL,
		0x9FDAFB7FDC2F590CULL,
		0x899AAD925C156663ULL,
		0x1279B4AA1187F539ULL,
		0x3E6BC35F67201466ULL,
		0x0976EA76CA9BBC4FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEA7952603FC4474EULL,
		0x5352BC3B882CB6BFULL,
		0x9B4B30453F6FBE8AULL,
		0x3FB5F6FFB85EB219ULL,
		0x13355B24B82ACCC7ULL,
		0x24F36954230FEA73ULL,
		0x7CD786BECE4028CCULL,
		0x12EDD4ED9537789EULL
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
		0x1E0F716D0A018045ULL,
		0x9C6CD7DBF7C08E52ULL,
		0x2B0A7721C24C1961ULL,
		0x91411926B1B2D729ULL,
		0x5F2808B2B5BF0F5FULL,
		0x36183B409E57E4F5ULL,
		0x21C918CA7F98942CULL,
		0x0CE33A61E3C91403ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3C1EE2DA1403008AULL,
		0x38D9AFB7EF811CA4ULL,
		0x5614EE43849832C3ULL,
		0x2282324D6365AE52ULL,
		0xBE5011656B7E1EBFULL,
		0x6C3076813CAFC9EAULL,
		0x43923194FF312858ULL,
		0x19C674C3C7922806ULL
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
		0xF1A0897617611895ULL,
		0xB71B61B968658F6AULL,
		0xFCA7B5824A6395C6ULL,
		0x2FBAC34BB8AF5CF7ULL,
		0x05971FF2BC799DFFULL,
		0xDEDFF4CB923A1505ULL,
		0x9E51BE44C54D109EULL,
		0x2505FCAC137E3F44ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE34112EC2EC2312AULL,
		0x6E36C372D0CB1ED5ULL,
		0xF94F6B0494C72B8DULL,
		0x5F758697715EB9EFULL,
		0x0B2E3FE578F33BFEULL,
		0xBDBFE99724742A0AULL,
		0x3CA37C898A9A213DULL,
		0x4A0BF95826FC7E89ULL
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
		0x925A95DD44577789ULL,
		0x3AA7F3FA34E4C36CULL,
		0xDAEC28F25F5FA5E6ULL,
		0xE3F398F767072FA1ULL,
		0x895540E9E012BA6EULL,
		0x4D8AB09AC41C77D9ULL,
		0x4F63F5C1DA99AFCFULL,
		0x0B1E8C419A280BE3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x24B52BBA88AEEF12ULL,
		0x754FE7F469C986D9ULL,
		0xB5D851E4BEBF4BCCULL,
		0xC7E731EECE0E5F43ULL,
		0x12AA81D3C02574DDULL,
		0x9B1561358838EFB3ULL,
		0x9EC7EB83B5335F9EULL,
		0x163D1883345017C6ULL
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
		0xB188E3A6B11A3959ULL,
		0x2453DB6134972014ULL,
		0x689BF43CC6F058F7ULL,
		0x7FB4C7F6BE313655ULL,
		0x35CA32B4DA0983AEULL,
		0xF7E240DC0AD1FA0BULL,
		0x98EC965282D5A762ULL,
		0x176125B0FCD16B05ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6311C74D623472B2ULL,
		0x48A7B6C2692E4029ULL,
		0xD137E8798DE0B1EEULL,
		0xFF698FED7C626CAAULL,
		0x6B946569B413075CULL,
		0xEFC481B815A3F416ULL,
		0x31D92CA505AB4EC5ULL,
		0x2EC24B61F9A2D60BULL
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
		0x0D7741040FCBE2B0ULL,
		0x50094AC887507B5FULL,
		0xB24FBE6BC41F2DBCULL,
		0xCD4DAFE53BAAF02DULL,
		0x12859ED34BDE57B5ULL,
		0xE920165C400D7D0FULL,
		0x7E1164F4C0A3FFF5ULL,
		0x1DDB29E30A9E3950ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1AEE82081F97C560ULL,
		0xA01295910EA0F6BEULL,
		0x649F7CD7883E5B78ULL,
		0x9A9B5FCA7755E05BULL,
		0x250B3DA697BCAF6BULL,
		0xD2402CB8801AFA1EULL,
		0xFC22C9E98147FFEBULL,
		0x3BB653C6153C72A0ULL
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
		0x4345066E7AC12315ULL,
		0xCDA102C0E8AB8EB3ULL,
		0x2082472B1D2E09F0ULL,
		0x2811333B50B82A4CULL,
		0xC7F6CEFC1683D18DULL,
		0x0D2A0E66966E9F6FULL,
		0xA3F2675BB7838D03ULL,
		0x210700D94986D23FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x868A0CDCF582462AULL,
		0x9B420581D1571D66ULL,
		0x41048E563A5C13E1ULL,
		0x50226676A1705498ULL,
		0x8FED9DF82D07A31AULL,
		0x1A541CCD2CDD3EDFULL,
		0x47E4CEB76F071A06ULL,
		0x420E01B2930DA47FULL
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
		0x614B889351943E63ULL,
		0xCE119F1AC5AE7DB8ULL,
		0xADF954351EABF21FULL,
		0xF2F82FD1E1664F36ULL,
		0x9DC62BE7462BC0BFULL,
		0x768EAA3CAA935FD4ULL,
		0x4E837338F1B402D6ULL,
		0x3E8F60C1F2C364E6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC2971126A3287CC6ULL,
		0x9C233E358B5CFB70ULL,
		0x5BF2A86A3D57E43FULL,
		0xE5F05FA3C2CC9E6DULL,
		0x3B8C57CE8C57817FULL,
		0xED1D54795526BFA9ULL,
		0x9D06E671E36805ACULL,
		0x7D1EC183E586C9CCULL
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
		0xAA98317E61AADFC9ULL,
		0x0383A0055518C4E7ULL,
		0x9595BEDB8EFBD803ULL,
		0x57FD904AACBD4BB5ULL,
		0xA54D740572D843ABULL,
		0xFF7C280998CD3C1BULL,
		0x4A9C3C29EEE99B04ULL,
		0x3995E382FDA15506ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x553062FCC355BF92ULL,
		0x0707400AAA3189CFULL,
		0x2B2B7DB71DF7B006ULL,
		0xAFFB2095597A976BULL,
		0x4A9AE80AE5B08756ULL,
		0xFEF85013319A7837ULL,
		0x95387853DDD33609ULL,
		0x732BC705FB42AA0CULL
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
		0xACC6BBC351DB8C3AULL,
		0x83D7EC0E1B8A0337ULL,
		0x209B58BB052FEF21ULL,
		0x1E17201994FB5F9BULL,
		0x2D2C4CAF9AD5F8A8ULL,
		0x4A797631459CE947ULL,
		0x8107C428E05E9C1BULL,
		0x2DD79DD31BCCAB0CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x598D7786A3B71874ULL,
		0x07AFD81C3714066FULL,
		0x4136B1760A5FDE43ULL,
		0x3C2E403329F6BF36ULL,
		0x5A58995F35ABF150ULL,
		0x94F2EC628B39D28EULL,
		0x020F8851C0BD3836ULL,
		0x5BAF3BA637995619ULL
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
		0x53B73F82789F48D8ULL,
		0xBC100BBA7B6DD015ULL,
		0xC03CCB7AA42A5F6FULL,
		0xFAF660D5C6886F64ULL,
		0xC74A07C539E1915AULL,
		0x2D65EBA3D37AC6C4ULL,
		0x233CA0BA21E15ACDULL,
		0x1D5AA60675BA6DD4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA76E7F04F13E91B0ULL,
		0x78201774F6DBA02AULL,
		0x807996F54854BEDFULL,
		0xF5ECC1AB8D10DEC9ULL,
		0x8E940F8A73C322B5ULL,
		0x5ACBD747A6F58D89ULL,
		0x4679417443C2B59AULL,
		0x3AB54C0CEB74DBA8ULL
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
		0xFECED51F6C1E102DULL,
		0x0015899CF133857EULL,
		0x9DF9008E2EE92AC3ULL,
		0x88BE92B676411B69ULL,
		0x843E7675BED7AA8CULL,
		0xDDBE436AE6C7A729ULL,
		0xBB77A6DE9DD2E6EBULL,
		0x050D39977ABE8006ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFD9DAA3ED83C205AULL,
		0x002B1339E2670AFDULL,
		0x3BF2011C5DD25586ULL,
		0x117D256CEC8236D3ULL,
		0x087CECEB7DAF5519ULL,
		0xBB7C86D5CD8F4E53ULL,
		0x76EF4DBD3BA5CDD7ULL,
		0x0A1A732EF57D000DULL
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
		0x07024933041D9082ULL,
		0xB8CFC493523C5DC7ULL,
		0xFD7E6563B6A83ABFULL,
		0xBE36426B605D2867ULL,
		0x584454695C406035ULL,
		0x460889C7A72FC65DULL,
		0xF9CA3936D44A1801ULL,
		0x2BB23BB2D2524338ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0E049266083B2104ULL,
		0x719F8926A478BB8EULL,
		0xFAFCCAC76D50757FULL,
		0x7C6C84D6C0BA50CFULL,
		0xB088A8D2B880C06BULL,
		0x8C11138F4E5F8CBAULL,
		0xF394726DA8943002ULL,
		0x57647765A4A48671ULL
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
		0xB7AEE3E221482E89ULL,
		0x2B44F8422E4CAF37ULL,
		0xFB208D8CD34800B6ULL,
		0xC8BCA6248869FDE0ULL,
		0xAE4F3081A2212123ULL,
		0x309866A4A4CBF3EAULL,
		0xFACB35CCDBB4209AULL,
		0x253D2951E7864D38ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6F5DC7C442905D12ULL,
		0x5689F0845C995E6FULL,
		0xF6411B19A690016CULL,
		0x91794C4910D3FBC1ULL,
		0x5C9E610344424247ULL,
		0x6130CD494997E7D5ULL,
		0xF5966B99B7684134ULL,
		0x4A7A52A3CF0C9A71ULL
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
		0xD8D2B6FAD1165510ULL,
		0x4D2742A5CAB9F7EBULL,
		0x2CDDFB3A7E3581ECULL,
		0xC8E3A87AA903D792ULL,
		0x82A714964F5971A2ULL,
		0x65C47CB67D0AC0D2ULL,
		0x83235552C28DB945ULL,
		0x0AFEA0AC06729001ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB1A56DF5A22CAA20ULL,
		0x9A4E854B9573EFD7ULL,
		0x59BBF674FC6B03D8ULL,
		0x91C750F55207AF24ULL,
		0x054E292C9EB2E345ULL,
		0xCB88F96CFA1581A5ULL,
		0x0646AAA5851B728AULL,
		0x15FD41580CE52003ULL
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
		0x7CD210F085E7826CULL,
		0x58AE85BFB77090FCULL,
		0x0D55C55E938FC785ULL,
		0x1B656078BCC9BFC6ULL,
		0x6365C71A0ED137AFULL,
		0xECF8593CB1402FF6ULL,
		0x9320CFA85A942CFBULL,
		0x04F059A081DCE620ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF9A421E10BCF04D8ULL,
		0xB15D0B7F6EE121F8ULL,
		0x1AAB8ABD271F8F0AULL,
		0x36CAC0F179937F8CULL,
		0xC6CB8E341DA26F5EULL,
		0xD9F0B27962805FECULL,
		0x26419F50B52859F7ULL,
		0x09E0B34103B9CC41ULL
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
		0xC3ED5E2FEF2E4CD1ULL,
		0x2D3AE7D6FF6B614BULL,
		0x10D5EB1109F514F5ULL,
		0x189D8B6EA3410105ULL,
		0x43ADAD3728EACB2BULL,
		0x99111356C47258D9ULL,
		0xA12C867EF6CED67DULL,
		0x1469AEB2DF3C8DBEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x87DABC5FDE5C99A2ULL,
		0x5A75CFADFED6C297ULL,
		0x21ABD62213EA29EAULL,
		0x313B16DD4682020AULL,
		0x875B5A6E51D59656ULL,
		0x322226AD88E4B1B2ULL,
		0x42590CFDED9DACFBULL,
		0x28D35D65BE791B7DULL
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
		0x8993FFAD8B958D15ULL,
		0x0BFCD4E53D30F880ULL,
		0x3F3D0B28F7B86847ULL,
		0x0B410AF70621AF46ULL,
		0xA6638A006B3F81D7ULL,
		0x1313992C1CF373C3ULL,
		0x9CD63A1A1FCCB10EULL,
		0x3415CC8BD4B934ECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1327FF5B172B1A2AULL,
		0x17F9A9CA7A61F101ULL,
		0x7E7A1651EF70D08EULL,
		0x168215EE0C435E8CULL,
		0x4CC71400D67F03AEULL,
		0x2627325839E6E787ULL,
		0x39AC74343F99621CULL,
		0x682B9917A97269D9ULL
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
		0x3F0858A0CEA04082ULL,
		0x735C066897B7E6B6ULL,
		0xF82257423C962DEBULL,
		0x2EEAA014108687C9ULL,
		0xE7A9F61018395648ULL,
		0x30A5CD05C9F61D7FULL,
		0x30B4C7789B96297CULL,
		0x3282FD6AC2671CDDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7E10B1419D408104ULL,
		0xE6B80CD12F6FCD6CULL,
		0xF044AE84792C5BD6ULL,
		0x5DD54028210D0F93ULL,
		0xCF53EC203072AC90ULL,
		0x614B9A0B93EC3AFFULL,
		0x61698EF1372C52F8ULL,
		0x6505FAD584CE39BAULL
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
		0x832B83EF42389907ULL,
		0x365B351BC1026BBAULL,
		0xEEB82E546DE0E74BULL,
		0xC2A384380CB545C5ULL,
		0x81F818607AE7D049ULL,
		0x3CB0E7F6F3DAC7F7ULL,
		0x82957AE64E745F72ULL,
		0x3956DDED7EA8F43DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x065707DE8471320EULL,
		0x6CB66A378204D775ULL,
		0xDD705CA8DBC1CE96ULL,
		0x85470870196A8B8BULL,
		0x03F030C0F5CFA093ULL,
		0x7961CFEDE7B58FEFULL,
		0x052AF5CC9CE8BEE4ULL,
		0x72ADBBDAFD51E87BULL
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
		0x9F17F1020F7C788FULL,
		0x98D597DE4A2639B6ULL,
		0x80E4D7813DE02A78ULL,
		0x0AF6B655E41B7D2CULL,
		0x6C1D4317BB4E9219ULL,
		0xF10C0DBC6C7F48D0ULL,
		0x5DA5A62B759436DFULL,
		0x17474F2C6F9F075CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3E2FE2041EF8F11EULL,
		0x31AB2FBC944C736DULL,
		0x01C9AF027BC054F1ULL,
		0x15ED6CABC836FA59ULL,
		0xD83A862F769D2432ULL,
		0xE2181B78D8FE91A0ULL,
		0xBB4B4C56EB286DBFULL,
		0x2E8E9E58DF3E0EB8ULL
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
		0x33DB6DF993464B95ULL,
		0xE06884874DE9821CULL,
		0x3A109652EE98873CULL,
		0xADAFF226691F4DECULL,
		0x5FCCAB7883AD6AEDULL,
		0x0B0162990AA9B96BULL,
		0xF2508EBB4331FAFBULL,
		0x25DF39537A9B6995ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x67B6DBF3268C972AULL,
		0xC0D1090E9BD30438ULL,
		0x74212CA5DD310E79ULL,
		0x5B5FE44CD23E9BD8ULL,
		0xBF9956F1075AD5DBULL,
		0x1602C532155372D6ULL,
		0xE4A11D768663F5F6ULL,
		0x4BBE72A6F536D32BULL
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
		0xC6D29C04E564773EULL,
		0x83618D7879112663ULL,
		0x08EBF2F297F6B799ULL,
		0xC403A3B516A3E24BULL,
		0xB1D07A34E5209C27ULL,
		0x37FD912F98706992ULL,
		0xDCD7B6B3BAB9A70EULL,
		0x2838025F69CE5B5DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8DA53809CAC8EE7CULL,
		0x06C31AF0F2224CC7ULL,
		0x11D7E5E52FED6F33ULL,
		0x8807476A2D47C496ULL,
		0x63A0F469CA41384FULL,
		0x6FFB225F30E0D325ULL,
		0xB9AF6D6775734E1CULL,
		0x507004BED39CB6BBULL
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
		0xAD26429EDD673E93ULL,
		0x0A347C5F4D30B743ULL,
		0xD74527C13FD8886CULL,
		0x1FF8A1FC6A00C01CULL,
		0x8101A26AD1E81496ULL,
		0x783287EE8A9FEFADULL,
		0x3968AD5A05DB7FE6ULL,
		0x2CC173830FD17178ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5A4C853DBACE7D26ULL,
		0x1468F8BE9A616E87ULL,
		0xAE8A4F827FB110D8ULL,
		0x3FF143F8D4018039ULL,
		0x020344D5A3D0292CULL,
		0xF0650FDD153FDF5BULL,
		0x72D15AB40BB6FFCCULL,
		0x5982E7061FA2E2F0ULL
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
		0x0B51278AC7CC34CAULL,
		0x405E6178965498C7ULL,
		0xA49C05626CF0CAC4ULL,
		0xFF4B86E9ABF40101ULL,
		0xB145735096A239C0ULL,
		0x07580ECCA088AE35ULL,
		0x032C606DBD9DA090ULL,
		0x07EAC40AFD4A3BBDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x16A24F158F986994ULL,
		0x80BCC2F12CA9318EULL,
		0x49380AC4D9E19588ULL,
		0xFE970DD357E80203ULL,
		0x628AE6A12D447381ULL,
		0x0EB01D9941115C6BULL,
		0x0658C0DB7B3B4120ULL,
		0x0FD58815FA94777AULL
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
		0x075181F9F6D6AC92ULL,
		0x7216783781E279AAULL,
		0x641F30C07CAF65C5ULL,
		0xB1BE156A4701C166ULL,
		0x021BA45787AAE343ULL,
		0x7AB3BAE820D3CA32ULL,
		0xD0580EC4AFEB7633ULL,
		0x388E96E409350F12ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0EA303F3EDAD5924ULL,
		0xE42CF06F03C4F354ULL,
		0xC83E6180F95ECB8AULL,
		0x637C2AD48E0382CCULL,
		0x043748AF0F55C687ULL,
		0xF56775D041A79464ULL,
		0xA0B01D895FD6EC66ULL,
		0x711D2DC8126A1E25ULL
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
		0x945D104416E99F35ULL,
		0xCB30B31AEE71E3FEULL,
		0xEBB19E2FF78D9EDBULL,
		0x98289F52A8723122ULL,
		0x45C91B0CF1C9D0D0ULL,
		0x0C274467D01DA258ULL,
		0x2117A92FE43E8411ULL,
		0x23095EF1BA3C6439ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x28BA20882DD33E6AULL,
		0x96616635DCE3C7FDULL,
		0xD7633C5FEF1B3DB7ULL,
		0x30513EA550E46245ULL,
		0x8B923619E393A1A1ULL,
		0x184E88CFA03B44B0ULL,
		0x422F525FC87D0822ULL,
		0x4612BDE37478C872ULL
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
		0xE168E08769B20BA8ULL,
		0xA2FBD57BD746BAB3ULL,
		0x23EA5180167C3AA1ULL,
		0xCCF8FB817667E7BEULL,
		0x23360FCD740E15C2ULL,
		0x4414ACAFB1F2EEB1ULL,
		0x052C1D55FF9316DAULL,
		0x112B60302A9DFEF0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC2D1C10ED3641750ULL,
		0x45F7AAF7AE8D7567ULL,
		0x47D4A3002CF87543ULL,
		0x99F1F702ECCFCF7CULL,
		0x466C1F9AE81C2B85ULL,
		0x8829595F63E5DD62ULL,
		0x0A583AABFF262DB4ULL,
		0x2256C060553BFDE0ULL
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
		0xF65F3F44FB6E93AAULL,
		0x60844C5E696EEBB0ULL,
		0x77E578C3DF2C4A74ULL,
		0x842888DD544E3DDDULL,
		0x886D078E1103DFB3ULL,
		0x4DBD26BD0AAC147AULL,
		0x525866E6FF396189ULL,
		0x1199C477AE875399ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xECBE7E89F6DD2754ULL,
		0xC10898BCD2DDD761ULL,
		0xEFCAF187BE5894E8ULL,
		0x085111BAA89C7BBAULL,
		0x10DA0F1C2207BF67ULL,
		0x9B7A4D7A155828F5ULL,
		0xA4B0CDCDFE72C312ULL,
		0x233388EF5D0EA732ULL
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
		0xA0496ED6F05252C0ULL,
		0xAF3C6CECD34F7122ULL,
		0x08BE35CF7E6F3BC2ULL,
		0xC7FAE27C6DE08E84ULL,
		0x5220B0F2D9617D3CULL,
		0x9B41773C6A55904DULL,
		0xA9F98F90CBA35FCAULL,
		0x1E22483184B4DD8FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4092DDADE0A4A580ULL,
		0x5E78D9D9A69EE245ULL,
		0x117C6B9EFCDE7785ULL,
		0x8FF5C4F8DBC11D08ULL,
		0xA44161E5B2C2FA79ULL,
		0x3682EE78D4AB209AULL,
		0x53F31F219746BF95ULL,
		0x3C4490630969BB1FULL
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
		0x6C512C99373CDBF5ULL,
		0xFE5AB938C89269FBULL,
		0x0C5346C47974E4F8ULL,
		0x3D88B866D3D00178ULL,
		0x51B6D89CEAE220ABULL,
		0x625079ACDDF1FD58ULL,
		0xEA53896D22429A04ULL,
		0x3AD303DF0DE5D91CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD8A259326E79B7EAULL,
		0xFCB572719124D3F6ULL,
		0x18A68D88F2E9C9F1ULL,
		0x7B1170CDA7A002F0ULL,
		0xA36DB139D5C44156ULL,
		0xC4A0F359BBE3FAB0ULL,
		0xD4A712DA44853408ULL,
		0x75A607BE1BCBB239ULL
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
		0xE5DD6020B35E3240ULL,
		0xC397F2115364CABEULL,
		0x1178D468247B2FEBULL,
		0x7C4F7918746F6378ULL,
		0xA00932BC9D7BDE3BULL,
		0xD750BBA47B6285BBULL,
		0x7D11305F76F5FD65ULL,
		0x02A9BF5910F470C1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCBBAC04166BC6480ULL,
		0x872FE422A6C9957DULL,
		0x22F1A8D048F65FD7ULL,
		0xF89EF230E8DEC6F0ULL,
		0x401265793AF7BC76ULL,
		0xAEA17748F6C50B77ULL,
		0xFA2260BEEDEBFACBULL,
		0x05537EB221E8E182ULL
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
		0x98E9E931FDC08FC9ULL,
		0x9FBB7D8353F2A71EULL,
		0x8F79A51C973692EDULL,
		0x37BE08AB763D6FF6ULL,
		0x0E3E048F77CC7A47ULL,
		0x5F9B36FF48131FAAULL,
		0x8DCD59E04D949D35ULL,
		0x2B087186FAF0B7AEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x31D3D263FB811F92ULL,
		0x3F76FB06A7E54E3DULL,
		0x1EF34A392E6D25DBULL,
		0x6F7C1156EC7ADFEDULL,
		0x1C7C091EEF98F48EULL,
		0xBF366DFE90263F54ULL,
		0x1B9AB3C09B293A6AULL,
		0x5610E30DF5E16F5DULL
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
		0x7E094B245FA6C867ULL,
		0xC0BFF25F84A616FEULL,
		0x658A32A2292E3B9BULL,
		0x4F9457175A62D192ULL,
		0x90199EFEB7F6ACD4ULL,
		0x064FDD56A82045ACULL,
		0x25D70C3A157DAB5EULL,
		0x3713D6075D77690FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFC129648BF4D90CEULL,
		0x817FE4BF094C2DFCULL,
		0xCB146544525C7737ULL,
		0x9F28AE2EB4C5A324ULL,
		0x20333DFD6FED59A8ULL,
		0x0C9FBAAD50408B59ULL,
		0x4BAE18742AFB56BCULL,
		0x6E27AC0EBAEED21EULL
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
		0xCDBDECA56DD55CA7ULL,
		0xB84BE9B500885CD9ULL,
		0x98A9C86D6BD63531ULL,
		0x6E77AC6AD490CE6DULL,
		0x1A8C4BF9545BEBA0ULL,
		0x13B763E302E888E7ULL,
		0xB11F9C458267B07BULL,
		0x237A742FC7E62FAAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9B7BD94ADBAAB94EULL,
		0x7097D36A0110B9B3ULL,
		0x315390DAD7AC6A63ULL,
		0xDCEF58D5A9219CDBULL,
		0x351897F2A8B7D740ULL,
		0x276EC7C605D111CEULL,
		0x623F388B04CF60F6ULL,
		0x46F4E85F8FCC5F55ULL
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
		0x2A4894020692A0FFULL,
		0xE738FB82BA3F02FBULL,
		0x0533144EE8A7A016ULL,
		0x51F2B31B370FEAC5ULL,
		0xD14599D3713E3C78ULL,
		0x2AFDCEAAE15269E3ULL,
		0x36A482FC8BA9CB2AULL,
		0x1DA23E2B126AA5AAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x549128040D2541FEULL,
		0xCE71F705747E05F6ULL,
		0x0A66289DD14F402DULL,
		0xA3E566366E1FD58AULL,
		0xA28B33A6E27C78F0ULL,
		0x55FB9D55C2A4D3C7ULL,
		0x6D4905F917539654ULL,
		0x3B447C5624D54B54ULL
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
		0x9DD3F33081BB65A5ULL,
		0xA05A0508710BDF44ULL,
		0x7E2809E623FB6ADFULL,
		0x937E8ED7A93B7FE9ULL,
		0x6407366855F8D898ULL,
		0xC2A2FBFBCB4E0F97ULL,
		0x51553EA52B0D1092ULL,
		0x051DC984B05A2586ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3BA7E6610376CB4AULL,
		0x40B40A10E217BE89ULL,
		0xFC5013CC47F6D5BFULL,
		0x26FD1DAF5276FFD2ULL,
		0xC80E6CD0ABF1B131ULL,
		0x8545F7F7969C1F2EULL,
		0xA2AA7D4A561A2125ULL,
		0x0A3B930960B44B0CULL
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
		0xE85AD78FABF59980ULL,
		0x71389BFB7299F523ULL,
		0x5B05376C0BB051E8ULL,
		0x5A3E5D32AF44EB96ULL,
		0x2E5D3F3E6873911FULL,
		0xBF3FFC1979EEA66EULL,
		0x7AE37E2591F36BB3ULL,
		0x31FBC8470EC7DF0EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD0B5AF1F57EB3300ULL,
		0xE27137F6E533EA47ULL,
		0xB60A6ED81760A3D0ULL,
		0xB47CBA655E89D72CULL,
		0x5CBA7E7CD0E7223EULL,
		0x7E7FF832F3DD4CDCULL,
		0xF5C6FC4B23E6D767ULL,
		0x63F7908E1D8FBE1CULL
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
		0x00769483DB608D39ULL,
		0xE4F46FAC4F918BC1ULL,
		0x47EF558CAD62E848ULL,
		0xFA6C2555AEC6A3F4ULL,
		0x07A999110D0539DCULL,
		0x59F0E5F2FB703A4DULL,
		0x43782F508DA83C6FULL,
		0x386C641DC383448AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x00ED2907B6C11A72ULL,
		0xC9E8DF589F231782ULL,
		0x8FDEAB195AC5D091ULL,
		0xF4D84AAB5D8D47E8ULL,
		0x0F5332221A0A73B9ULL,
		0xB3E1CBE5F6E0749AULL,
		0x86F05EA11B5078DEULL,
		0x70D8C83B87068914ULL
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
		0xF208CC898B50E0C4ULL,
		0xF08F7950E9AD6F1AULL,
		0x7136D35C40F93576ULL,
		0xE3F4A320AD6921ECULL,
		0xFF7E43D5DB4D25EEULL,
		0x0249AD6C5E302EDAULL,
		0x6383D09B42B5435EULL,
		0x3DB8AC14258754F2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE411991316A1C188ULL,
		0xE11EF2A1D35ADE35ULL,
		0xE26DA6B881F26AEDULL,
		0xC7E946415AD243D8ULL,
		0xFEFC87ABB69A4BDDULL,
		0x04935AD8BC605DB5ULL,
		0xC707A136856A86BCULL,
		0x7B7158284B0EA9E4ULL
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
		0x9A851AAF232965A6ULL,
		0x2F262C76BD04043EULL,
		0xC10BE4C29CBDA104ULL,
		0x26D63795F0D77ED8ULL,
		0x367E7A5852BC3699ULL,
		0x7457C4D2EDCA7D80ULL,
		0xA2DF34D01019AA24ULL,
		0x3BC0AB1C1A179FD1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x350A355E4652CB4CULL,
		0x5E4C58ED7A08087DULL,
		0x8217C985397B4208ULL,
		0x4DAC6F2BE1AEFDB1ULL,
		0x6CFCF4B0A5786D32ULL,
		0xE8AF89A5DB94FB00ULL,
		0x45BE69A020335448ULL,
		0x77815638342F3FA3ULL
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
		0x317AF09170AAA24FULL,
		0x8DF971DC896FE16BULL,
		0x7323CA8DF66EFD9AULL,
		0xF0DF17708E226616ULL,
		0x029AA2844F51156CULL,
		0x0E1E1FA9F7BD9CA7ULL,
		0x97ABBE2A3B9F6446ULL,
		0x10C76BED174DEB6BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x62F5E122E155449EULL,
		0x1BF2E3B912DFC2D6ULL,
		0xE647951BECDDFB35ULL,
		0xE1BE2EE11C44CC2CULL,
		0x053545089EA22AD9ULL,
		0x1C3C3F53EF7B394EULL,
		0x2F577C54773EC88CULL,
		0x218ED7DA2E9BD6D7ULL
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
		0xC45F42633DF93B05ULL,
		0x897D7A76A91031C7ULL,
		0x9F6555023CACE7D5ULL,
		0x64CD3D390885A69BULL,
		0xC0B2DB44EF62C2BCULL,
		0x96754A9AABE67B9BULL,
		0x27AA71CF6470EBC5ULL,
		0x2EBDB2BF7B81C737ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x88BE84C67BF2760AULL,
		0x12FAF4ED5220638FULL,
		0x3ECAAA047959CFABULL,
		0xC99A7A72110B4D37ULL,
		0x8165B689DEC58578ULL,
		0x2CEA953557CCF737ULL,
		0x4F54E39EC8E1D78BULL,
		0x5D7B657EF7038E6EULL
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
		0xD852B4F4619F7CF5ULL,
		0x89FFDD871AEBD286ULL,
		0x8EEE6BAF726D7C9BULL,
		0xFC4288DF05880E8CULL,
		0x36D769D6093F8E85ULL,
		0xCDD93B70D1909074ULL,
		0xD631390C4C66D717ULL,
		0x040A4710780CB276ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB0A569E8C33EF9EAULL,
		0x13FFBB0E35D7A50DULL,
		0x1DDCD75EE4DAF937ULL,
		0xF88511BE0B101D19ULL,
		0x6DAED3AC127F1D0BULL,
		0x9BB276E1A32120E8ULL,
		0xAC62721898CDAE2FULL,
		0x08148E20F01964EDULL
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
		0x1166D57E21CE38F1ULL,
		0xBA4AAF7CDCE79639ULL,
		0x2A0BEAB77DEADD8BULL,
		0x09DC5FBA623CA8B3ULL,
		0x765A0AD535E04C58ULL,
		0x9EB35A58F8884F65ULL,
		0x96CE7AE5233FF0CFULL,
		0x2D805A21F54EE148ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x22CDAAFC439C71E2ULL,
		0x74955EF9B9CF2C72ULL,
		0x5417D56EFBD5BB17ULL,
		0x13B8BF74C4795166ULL,
		0xECB415AA6BC098B0ULL,
		0x3D66B4B1F1109ECAULL,
		0x2D9CF5CA467FE19FULL,
		0x5B00B443EA9DC291ULL
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
		0x66341DE4F303DCEFULL,
		0x14B8C56D0E3313BEULL,
		0x06ED0D2481563E47ULL,
		0x800410EB7DC82CD9ULL,
		0x0550CA0422B61212ULL,
		0x947A14CA24C6F5E5ULL,
		0x0554EF99820B542FULL,
		0x0B3ACA8A945EA257ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCC683BC9E607B9DEULL,
		0x29718ADA1C66277CULL,
		0x0DDA1A4902AC7C8EULL,
		0x000821D6FB9059B2ULL,
		0x0AA19408456C2425ULL,
		0x28F42994498DEBCAULL,
		0x0AA9DF330416A85FULL,
		0x1675951528BD44AEULL
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
		0x8442B20C3BA32C9AULL,
		0xDE0830A1B7F121FEULL,
		0xC380C175D4C0E017ULL,
		0xFE11D837D9961C7FULL,
		0x91E0B0B9B9F25E3CULL,
		0x6EEFBADB763406C6ULL,
		0xB8A59A2CD84C7016ULL,
		0x17666C89E5585303ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0885641877465934ULL,
		0xBC1061436FE243FDULL,
		0x870182EBA981C02FULL,
		0xFC23B06FB32C38FFULL,
		0x23C1617373E4BC79ULL,
		0xDDDF75B6EC680D8DULL,
		0x714B3459B098E02CULL,
		0x2ECCD913CAB0A607ULL
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
		0xF264951B66BF1AD0ULL,
		0xA04C47033F612BFBULL,
		0x600B6E51C394C41CULL,
		0x08DAAC61F6DBA515ULL,
		0x050E435D1D7BD7B5ULL,
		0xCBD74E039F571D4CULL,
		0xBA3438D76A2496B6ULL,
		0x084EDEDAE33EAF4CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE4C92A36CD7E35A0ULL,
		0x40988E067EC257F7ULL,
		0xC016DCA387298839ULL,
		0x11B558C3EDB74A2AULL,
		0x0A1C86BA3AF7AF6AULL,
		0x97AE9C073EAE3A98ULL,
		0x746871AED4492D6DULL,
		0x109DBDB5C67D5E99ULL
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
		0x6C1F32FFBC605EAEULL,
		0xC42F4C25447A84ADULL,
		0x154EEDBA9A4D5457ULL,
		0x590C26807762F9F8ULL,
		0x56F34FAC5981779CULL,
		0x044279E92CADD202ULL,
		0xA841A972F6386FE9ULL,
		0x1CB74EBA1BAE48E9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD83E65FF78C0BD5CULL,
		0x885E984A88F5095AULL,
		0x2A9DDB75349AA8AFULL,
		0xB2184D00EEC5F3F0ULL,
		0xADE69F58B302EF38ULL,
		0x0884F3D2595BA404ULL,
		0x508352E5EC70DFD2ULL,
		0x396E9D74375C91D3ULL
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
		0x9B8C3B1E7B1742B0ULL,
		0x7C996946700B0552ULL,
		0x50182691BA71B0F6ULL,
		0x41350D6317D1F08CULL,
		0xAFD164367C4B34DBULL,
		0x496C433F130C6F59ULL,
		0xA8F4BA1EC6E4F541ULL,
		0x39BCD208D43F3672ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3718763CF62E8560ULL,
		0xF932D28CE0160AA5ULL,
		0xA0304D2374E361ECULL,
		0x826A1AC62FA3E118ULL,
		0x5FA2C86CF89669B6ULL,
		0x92D8867E2618DEB3ULL,
		0x51E9743D8DC9EA82ULL,
		0x7379A411A87E6CE5ULL
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
		0x3B8AEA826ADF1CFDULL,
		0x21D3A143FF1B8F0EULL,
		0xF998B715311B37FAULL,
		0xCC2CFFF63E897EB0ULL,
		0xE15153F600E36169ULL,
		0x96531834DABF52ACULL,
		0x9F0488D8D7D92B17ULL,
		0x2702AD34FFCCD189ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7715D504D5BE39FAULL,
		0x43A74287FE371E1CULL,
		0xF3316E2A62366FF4ULL,
		0x9859FFEC7D12FD61ULL,
		0xC2A2A7EC01C6C2D3ULL,
		0x2CA63069B57EA559ULL,
		0x3E0911B1AFB2562FULL,
		0x4E055A69FF99A313ULL
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
		0xDCC19F4DA1B5EF6DULL,
		0xE82B32F42A0D2196ULL,
		0xA92C92BF9372E95BULL,
		0x4D9112B208C8CAF4ULL,
		0x9014760981ACE9B3ULL,
		0xC1171C4674012BDFULL,
		0x2966E09A52A6A7EBULL,
		0x2EA92CE07DB027CEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB9833E9B436BDEDAULL,
		0xD05665E8541A432DULL,
		0x5259257F26E5D2B7ULL,
		0x9B222564119195E9ULL,
		0x2028EC130359D366ULL,
		0x822E388CE80257BFULL,
		0x52CDC134A54D4FD7ULL,
		0x5D5259C0FB604F9CULL
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
		0x90F083D1F2961B7CULL,
		0x9E524A0EF18E8444ULL,
		0x4D7CCD4E5BC78ACDULL,
		0xF08FE66FFE4DD68EULL,
		0x98B2A24C220E85FDULL,
		0x1515DC6AED42355FULL,
		0x080F28BEC00370C4ULL,
		0x0B0C612A0FFE8C8CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x21E107A3E52C36F8ULL,
		0x3CA4941DE31D0889ULL,
		0x9AF99A9CB78F159BULL,
		0xE11FCCDFFC9BAD1CULL,
		0x31654498441D0BFBULL,
		0x2A2BB8D5DA846ABFULL,
		0x101E517D8006E188ULL,
		0x1618C2541FFD1918ULL
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
		0xA2691A5B62C856DBULL,
		0xF8780B7E111CA8E0ULL,
		0x9CE2F8202C4F225EULL,
		0xDFDF6BCC0F1C9B15ULL,
		0xB4622C66C02F9D8CULL,
		0x82508EDA5AF03B0BULL,
		0x021BE117AD9C5C69ULL,
		0x1FFCFE31891FDA9FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x44D234B6C590ADB6ULL,
		0xF0F016FC223951C1ULL,
		0x39C5F040589E44BDULL,
		0xBFBED7981E39362BULL,
		0x68C458CD805F3B19ULL,
		0x04A11DB4B5E07617ULL,
		0x0437C22F5B38B8D3ULL,
		0x3FF9FC63123FB53EULL
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
		0x471D5AC40EC66861ULL,
		0x9B1FE39813BF7087ULL,
		0x2F75D5D85847E9DAULL,
		0x82891844C33B7928ULL,
		0x0A0E283DCAEB591BULL,
		0x802EDFDBE465E3F1ULL,
		0xA049380B724B93ACULL,
		0x3656B9DE4334B17BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8E3AB5881D8CD0C2ULL,
		0x363FC730277EE10EULL,
		0x5EEBABB0B08FD3B5ULL,
		0x051230898676F250ULL,
		0x141C507B95D6B237ULL,
		0x005DBFB7C8CBC7E2ULL,
		0x40927016E4972759ULL,
		0x6CAD73BC866962F7ULL
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
		0xB6141FD9A9996122ULL,
		0xB26839BBB519E8BBULL,
		0xBFE82D60172B4797ULL,
		0x02BFC4666E8DFFE5ULL,
		0xDDA01754E1EA45D1ULL,
		0x7D62C8CE541BE048ULL,
		0x5815D6351C33DF74ULL,
		0x0390F0B278577D6BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6C283FB35332C244ULL,
		0x64D073776A33D177ULL,
		0x7FD05AC02E568F2FULL,
		0x057F88CCDD1BFFCBULL,
		0xBB402EA9C3D48BA2ULL,
		0xFAC5919CA837C091ULL,
		0xB02BAC6A3867BEE8ULL,
		0x0721E164F0AEFAD6ULL
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
		0xD04305070767F1F4ULL,
		0x21155EAAFE083A36ULL,
		0x3A5BF3F202A8E86DULL,
		0xD00A8039651939F5ULL,
		0x2B9EDCABE7C8FEE5ULL,
		0xDA1E5C94D1D6A68BULL,
		0x4155641FC59D6811ULL,
		0x3F9E2F14140D30D0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA0860A0E0ECFE3E8ULL,
		0x422ABD55FC10746DULL,
		0x74B7E7E40551D0DAULL,
		0xA0150072CA3273EAULL,
		0x573DB957CF91FDCBULL,
		0xB43CB929A3AD4D16ULL,
		0x82AAC83F8B3AD023ULL,
		0x7F3C5E28281A61A0ULL
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
		0xF021A5FB067E0A8BULL,
		0xD1BAA552C63FD551ULL,
		0x52AF2C2AEE06080DULL,
		0xE228E129C8CE24D5ULL,
		0x19B95E81D37CE7B6ULL,
		0x49C5087E12211AD1ULL,
		0xA0280B3894AA51A3ULL,
		0x087BC76EE3EB6E61ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE0434BF60CFC1516ULL,
		0xA3754AA58C7FAAA3ULL,
		0xA55E5855DC0C101BULL,
		0xC451C253919C49AAULL,
		0x3372BD03A6F9CF6DULL,
		0x938A10FC244235A2ULL,
		0x405016712954A346ULL,
		0x10F78EDDC7D6DCC3ULL
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
		0xF66BC092C58A5079ULL,
		0x26C7BEA3C7A7B4A5ULL,
		0xAE02C4BDA5D95B65ULL,
		0x2288C462B91884A9ULL,
		0xC8E44A8CF0B8C594ULL,
		0x89A15CFF15CA1852ULL,
		0x541C8102ED52B1F6ULL,
		0x30A5E8430B633594ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xECD781258B14A0F2ULL,
		0x4D8F7D478F4F694BULL,
		0x5C05897B4BB2B6CAULL,
		0x451188C572310953ULL,
		0x91C89519E1718B28ULL,
		0x1342B9FE2B9430A5ULL,
		0xA8390205DAA563EDULL,
		0x614BD08616C66B28ULL
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
		0x798ABA26D2949150ULL,
		0xAF644C3F64BC0955ULL,
		0x6DE6A1DE9C4234A5ULL,
		0xA3BC8D51D55B9761ULL,
		0x89993CA3DC6246C6ULL,
		0x610A7BA008E777ECULL,
		0x3C70A41C48EA514BULL,
		0x2BCECE70F64411B6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF315744DA52922A0ULL,
		0x5EC8987EC97812AAULL,
		0xDBCD43BD3884694BULL,
		0x47791AA3AAB72EC2ULL,
		0x13327947B8C48D8DULL,
		0xC214F74011CEEFD9ULL,
		0x78E1483891D4A296ULL,
		0x579D9CE1EC88236CULL
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
		0xB654EEAFB3781355ULL,
		0x12B95C1152D86EAAULL,
		0xA186C776C01DDAF0ULL,
		0x39D2AA99B574B798ULL,
		0x97575726A52C865BULL,
		0xC50599DAD60A8314ULL,
		0x09221B13B1B9C878ULL,
		0x068AA2CD4E9A0306ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6CA9DD5F66F026AAULL,
		0x2572B822A5B0DD55ULL,
		0x430D8EED803BB5E0ULL,
		0x73A555336AE96F31ULL,
		0x2EAEAE4D4A590CB6ULL,
		0x8A0B33B5AC150629ULL,
		0x12443627637390F1ULL,
		0x0D15459A9D34060CULL
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
		0x1083DBA6C8C569A5ULL,
		0x4E7295988DA4EDB1ULL,
		0xD6E0BAAA63917902ULL,
		0x68EA10FD94C88E38ULL,
		0x741716A84C648B23ULL,
		0xF5354176E3ADB99DULL,
		0x75FE9BB84AB4F1F0ULL,
		0x14FCAE7BD171DCC0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2107B74D918AD34AULL,
		0x9CE52B311B49DB62ULL,
		0xADC17554C722F204ULL,
		0xD1D421FB29911C71ULL,
		0xE82E2D5098C91646ULL,
		0xEA6A82EDC75B733AULL,
		0xEBFD37709569E3E1ULL,
		0x29F95CF7A2E3B980ULL
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
		0x32483D9F70CFBE0BULL,
		0xC6D0674F204770DFULL,
		0x717DC1A2682E6BB2ULL,
		0x338857502F2CF02DULL,
		0x7B4089BC16A624D5ULL,
		0xBA5D016A98C72283ULL,
		0x706C5D748EF8BD67ULL,
		0x29F08552A7564403ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x64907B3EE19F7C16ULL,
		0x8DA0CE9E408EE1BEULL,
		0xE2FB8344D05CD765ULL,
		0x6710AEA05E59E05AULL,
		0xF68113782D4C49AAULL,
		0x74BA02D5318E4506ULL,
		0xE0D8BAE91DF17ACFULL,
		0x53E10AA54EAC8806ULL
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
		0x60EA5C11A43BB80AULL,
		0x726B541330336B26ULL,
		0xBE598B718BD91869ULL,
		0xC3356DDAC1552321ULL,
		0xFD7F79A5542F3D15ULL,
		0xE65D5D2C36D75396ULL,
		0x5EDFB2D319B18534ULL,
		0x131DBDADBE59A5D3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC1D4B82348777014ULL,
		0xE4D6A8266066D64CULL,
		0x7CB316E317B230D2ULL,
		0x866ADBB582AA4643ULL,
		0xFAFEF34AA85E7A2BULL,
		0xCCBABA586DAEA72DULL,
		0xBDBF65A633630A69ULL,
		0x263B7B5B7CB34BA6ULL
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
		0xD3BFBAB2BC6D566EULL,
		0x576B9767EC83812CULL,
		0x264DADC181F1D476ULL,
		0x375E5F7F559FC192ULL,
		0x908660F92819455DULL,
		0xABACB51EB5D422AAULL,
		0xB17ABB3234949A27ULL,
		0x2639BD17A41C95A1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA77F756578DAACDCULL,
		0xAED72ECFD9070259ULL,
		0x4C9B5B8303E3A8ECULL,
		0x6EBCBEFEAB3F8324ULL,
		0x210CC1F250328ABAULL,
		0x57596A3D6BA84555ULL,
		0x62F576646929344FULL,
		0x4C737A2F48392B43ULL
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
		0x05861BAA227E49EFULL,
		0x3057568979586DA7ULL,
		0x4CFB7834BD59458AULL,
		0xC84BF40D3C8EDA38ULL,
		0x9424C6691187242AULL,
		0xE2C33F2EB553D6B5ULL,
		0x2F7835DA2677D3A4ULL,
		0x389649DFB2E16855ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0B0C375444FC93DEULL,
		0x60AEAD12F2B0DB4EULL,
		0x99F6F0697AB28B14ULL,
		0x9097E81A791DB470ULL,
		0x28498CD2230E4855ULL,
		0xC5867E5D6AA7AD6BULL,
		0x5EF06BB44CEFA749ULL,
		0x712C93BF65C2D0AAULL
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
		0xACF90CADC3C5A31CULL,
		0x44E764FFDA420419ULL,
		0xF8C1878DADD3FCA4ULL,
		0x01FD5D2A2E790F9BULL,
		0x41B25C1EBD67B2C8ULL,
		0x0B9783CD2BD7E6ECULL,
		0xD5F621D023FC5259ULL,
		0x3D676084B38C90F0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x59F2195B878B4638ULL,
		0x89CEC9FFB4840833ULL,
		0xF1830F1B5BA7F948ULL,
		0x03FABA545CF21F37ULL,
		0x8364B83D7ACF6590ULL,
		0x172F079A57AFCDD8ULL,
		0xABEC43A047F8A4B2ULL,
		0x7ACEC109671921E1ULL
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
		0x730666CEC05B5A4BULL,
		0x5EB6FF92F8A9733AULL,
		0xC6576D9C4F580A43ULL,
		0x358F405EB5B4CC6FULL,
		0x516E93A10B66DF02ULL,
		0x22F83BDAB0E24B23ULL,
		0xACBA63CCA7C5D8FEULL,
		0x2F2163C3C635DB29ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE60CCD9D80B6B496ULL,
		0xBD6DFF25F152E674ULL,
		0x8CAEDB389EB01486ULL,
		0x6B1E80BD6B6998DFULL,
		0xA2DD274216CDBE04ULL,
		0x45F077B561C49646ULL,
		0x5974C7994F8BB1FCULL,
		0x5E42C7878C6BB653ULL
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
		0xA19BFB4F481E61F4ULL,
		0xA565E4E5A7B250CDULL,
		0x0A5A41008A6DDF21ULL,
		0x9FEC24828822EE16ULL,
		0xC3905D2747018178ULL,
		0xEE777B64F208D592ULL,
		0x6E7D97A67BAB9F23ULL,
		0x0E6A79B255D6B9DEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4337F69E903CC3E8ULL,
		0x4ACBC9CB4F64A19BULL,
		0x14B4820114DBBE43ULL,
		0x3FD849051045DC2CULL,
		0x8720BA4E8E0302F1ULL,
		0xDCEEF6C9E411AB25ULL,
		0xDCFB2F4CF7573E47ULL,
		0x1CD4F364ABAD73BCULL
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
		0xF515319507D71E23ULL,
		0x0D303C1AE3A68311ULL,
		0x33C0B2CB8E91C710ULL,
		0x8D1B9D9BC4853E82ULL,
		0x834E2887213AA5A5ULL,
		0x74560CF424146419ULL,
		0x605DEC62359A7DAFULL,
		0x11DEF0CB1C3256C4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEA2A632A0FAE3C46ULL,
		0x1A607835C74D0623ULL,
		0x678165971D238E20ULL,
		0x1A373B37890A7D04ULL,
		0x069C510E42754B4BULL,
		0xE8AC19E84828C833ULL,
		0xC0BBD8C46B34FB5EULL,
		0x23BDE1963864AD88ULL
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
		0x2719E9023A23C29AULL,
		0x2D60A0065892DE4EULL,
		0x786A4916A21DA942ULL,
		0xD5298D3615FAC054ULL,
		0x9FC5E77ABA207333ULL,
		0x4EBE10D4A684C6A2ULL,
		0x8F81B660BF480AD3ULL,
		0x13BBB2E64241816CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4E33D20474478534ULL,
		0x5AC1400CB125BC9CULL,
		0xF0D4922D443B5284ULL,
		0xAA531A6C2BF580A8ULL,
		0x3F8BCEF57440E667ULL,
		0x9D7C21A94D098D45ULL,
		0x1F036CC17E9015A6ULL,
		0x277765CC848302D9ULL
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
		0x592C02E955DC3331ULL,
		0xA04D30976B2E0D71ULL,
		0xD7BA8105BDCD4561ULL,
		0x2ACD67E5E5ECFBE5ULL,
		0x1E3CFE3EB238578FULL,
		0xC50F644B1AEEFE9DULL,
		0x9837385D4521F02EULL,
		0x262E9738E0F3B0FBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB25805D2ABB86662ULL,
		0x409A612ED65C1AE2ULL,
		0xAF75020B7B9A8AC3ULL,
		0x559ACFCBCBD9F7CBULL,
		0x3C79FC7D6470AF1EULL,
		0x8A1EC89635DDFD3AULL,
		0x306E70BA8A43E05DULL,
		0x4C5D2E71C1E761F7ULL
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
		0x50550CA5A7DA5C5EULL,
		0x9C36FFB7DE04DF7AULL,
		0xF1F94F7E731C842FULL,
		0xC89268E3F6F6411FULL,
		0xC223C4B5B21022C5ULL,
		0x9EABFC19393C3DADULL,
		0x7BAFA86266D69267ULL,
		0x1837117F48559A85ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA0AA194B4FB4B8BCULL,
		0x386DFF6FBC09BEF4ULL,
		0xE3F29EFCE639085FULL,
		0x9124D1C7EDEC823FULL,
		0x8447896B6420458BULL,
		0x3D57F83272787B5BULL,
		0xF75F50C4CDAD24CFULL,
		0x306E22FE90AB350AULL
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
		0x79C6CEC9DF883C82ULL,
		0x7D5B0908D0FCDACDULL,
		0x7CDE02A926B56B0AULL,
		0x9537316A010534D5ULL,
		0x36870BB1A761341BULL,
		0xD081B50F92BE7316ULL,
		0x4D5588201CF6C179ULL,
		0x35B221F993BFCF6EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF38D9D93BF107904ULL,
		0xFAB61211A1F9B59AULL,
		0xF9BC05524D6AD614ULL,
		0x2A6E62D4020A69AAULL,
		0x6D0E17634EC26837ULL,
		0xA1036A1F257CE62CULL,
		0x9AAB104039ED82F3ULL,
		0x6B6443F3277F9EDCULL
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
		0x174B778694D53034ULL,
		0xC4D4EE61879643CCULL,
		0x72A6D4B6960D2CB8ULL,
		0x0DC00115C8B140E0ULL,
		0x09B728FADFE9BBE5ULL,
		0x47FA3A0EED8958C5ULL,
		0x1B0C7984623A5897ULL,
		0x27A70C65FBFF50EBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2E96EF0D29AA6068ULL,
		0x89A9DCC30F2C8798ULL,
		0xE54DA96D2C1A5971ULL,
		0x1B80022B916281C0ULL,
		0x136E51F5BFD377CAULL,
		0x8FF4741DDB12B18AULL,
		0x3618F308C474B12EULL,
		0x4F4E18CBF7FEA1D6ULL
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
		0x44EEA19837E53AC9ULL,
		0xD1B8F6AAF2C8E202ULL,
		0x7BC0333BA096E595ULL,
		0x8AB98972186FD51BULL,
		0xC5ECD5D38771413AULL,
		0xD3F415AF7655063BULL,
		0xE0A90CDDA6145E19ULL,
		0x0B5ED33F791067B0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x89DD43306FCA7592ULL,
		0xA371ED55E591C404ULL,
		0xF7806677412DCB2BULL,
		0x157312E430DFAA36ULL,
		0x8BD9ABA70EE28275ULL,
		0xA7E82B5EECAA0C77ULL,
		0xC15219BB4C28BC33ULL,
		0x16BDA67EF220CF61ULL
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
		0x7DB1973B3D45BB1AULL,
		0x0706CB7B5963B5D1ULL,
		0x7E84368C21E3E0E3ULL,
		0x1372056DF2EFD797ULL,
		0xB7F37A1996ECBF1BULL,
		0xE6ACEEF07D4D0DC3ULL,
		0x8873C5316713EEEFULL,
		0x1190A2BEE8DC5130ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFB632E767A8B7634ULL,
		0x0E0D96F6B2C76BA2ULL,
		0xFD086D1843C7C1C6ULL,
		0x26E40ADBE5DFAF2EULL,
		0x6FE6F4332DD97E36ULL,
		0xCD59DDE0FA9A1B87ULL,
		0x10E78A62CE27DDDFULL,
		0x2321457DD1B8A261ULL
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
		0xC1A5B8EDB48A0382ULL,
		0xEEA95A6FBE13E97EULL,
		0x457CD65E0CD8D8E6ULL,
		0xEEEB4C62D8B9D789ULL,
		0x005EC0229F5C86C4ULL,
		0x37E04B24508C5173ULL,
		0x86C6DD278E27CE7DULL,
		0x082E8ECD66347873ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x834B71DB69140704ULL,
		0xDD52B4DF7C27D2FDULL,
		0x8AF9ACBC19B1B1CDULL,
		0xDDD698C5B173AF12ULL,
		0x00BD80453EB90D89ULL,
		0x6FC09648A118A2E6ULL,
		0x0D8DBA4F1C4F9CFAULL,
		0x105D1D9ACC68F0E7ULL
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
		0xC91CBBB3402438E1ULL,
		0xD18E5AFBB562C3C3ULL,
		0x83D7E76B9982ABF5ULL,
		0xDC4A27C60B9E98F4ULL,
		0xE55F71C0D028AEDDULL,
		0xE63783EF6ABA3630ULL,
		0x79762EC2F9A9A24FULL,
		0x0AE129C77A179F45ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x92397766804871C2ULL,
		0xA31CB5F76AC58787ULL,
		0x07AFCED7330557EBULL,
		0xB8944F8C173D31E9ULL,
		0xCABEE381A0515DBBULL,
		0xCC6F07DED5746C61ULL,
		0xF2EC5D85F353449FULL,
		0x15C2538EF42F3E8AULL
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
		0x5BC9C22BC9E4EFDBULL,
		0x12CF7B5FB398A09FULL,
		0xE51D27C9DF1C3205ULL,
		0x9B4A5095FBBE7363ULL,
		0x5087DEC39CA2F348ULL,
		0x6E7E310C8CBB5812ULL,
		0xAA609D9A250F8899ULL,
		0x276466CB27CE09F5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB793845793C9DFB6ULL,
		0x259EF6BF6731413EULL,
		0xCA3A4F93BE38640AULL,
		0x3694A12BF77CE6C7ULL,
		0xA10FBD873945E691ULL,
		0xDCFC62191976B024ULL,
		0x54C13B344A1F1132ULL,
		0x4EC8CD964F9C13EBULL
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
		0xEF7507E1E71E6864ULL,
		0xFB52ED79F6CDA38BULL,
		0x4021B087355625EDULL,
		0x8F4F5B5FB0C468DDULL,
		0xF387B840B16CCC77ULL,
		0x1285F169BBAEA160ULL,
		0xC1E8D27637FDFC6DULL,
		0x2B1535D3F0A0EBF1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDEEA0FC3CE3CD0C8ULL,
		0xF6A5DAF3ED9B4717ULL,
		0x8043610E6AAC4BDBULL,
		0x1E9EB6BF6188D1BAULL,
		0xE70F708162D998EFULL,
		0x250BE2D3775D42C1ULL,
		0x83D1A4EC6FFBF8DAULL,
		0x562A6BA7E141D7E3ULL
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
		0x2AF12EE768DB3F68ULL,
		0x194225F208B6EC45ULL,
		0xDA28500E1657077EULL,
		0x995A1A71080FADF0ULL,
		0x330048BAAA2B8E7EULL,
		0xD2DD51096C61552FULL,
		0x5AE21DC19D30B5E4ULL,
		0x091E6EE4FA234F8CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x55E25DCED1B67ED0ULL,
		0x32844BE4116DD88AULL,
		0xB450A01C2CAE0EFCULL,
		0x32B434E2101F5BE1ULL,
		0x6600917554571CFDULL,
		0xA5BAA212D8C2AA5EULL,
		0xB5C43B833A616BC9ULL,
		0x123CDDC9F4469F18ULL
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
		0x3062D4EB4E032212ULL,
		0x04A717937363EA40ULL,
		0xD9053117667BEBBDULL,
		0xD1283F1582123256ULL,
		0x2AC690A792F1EDDBULL,
		0x1F5421A36A439C6AULL,
		0xCC39B164B9BAE5EDULL,
		0x29AF242910B60D38ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x60C5A9D69C064424ULL,
		0x094E2F26E6C7D480ULL,
		0xB20A622ECCF7D77AULL,
		0xA2507E2B042464ADULL,
		0x558D214F25E3DBB7ULL,
		0x3EA84346D48738D4ULL,
		0x987362C97375CBDAULL,
		0x535E4852216C1A71ULL
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
		0x3C9AE64447279CA3ULL,
		0x1921B1EFC95DE383ULL,
		0x9E95C943802A24C9ULL,
		0x48EE4B5674E55DC9ULL,
		0xB61FBE0EF435F857ULL,
		0x9280A002E5ED445CULL,
		0xE7CACB6AE6F64BC2ULL,
		0x1B5959C3DF07C523ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7935CC888E4F3946ULL,
		0x324363DF92BBC706ULL,
		0x3D2B928700544992ULL,
		0x91DC96ACE9CABB93ULL,
		0x6C3F7C1DE86BF0AEULL,
		0x25014005CBDA88B9ULL,
		0xCF9596D5CDEC9785ULL,
		0x36B2B387BE0F8A47ULL
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
		0x5DEFC22AE7C822BAULL,
		0x2A4ECD08A9D07D2FULL,
		0xB78961D4E5085A09ULL,
		0x9A36729EC3856E03ULL,
		0x6981416915FC63DBULL,
		0xB094C288F9A1EBFEULL,
		0x299C238D76FB4E1AULL,
		0x3995644B1A98049DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBBDF8455CF904574ULL,
		0x549D9A1153A0FA5EULL,
		0x6F12C3A9CA10B412ULL,
		0x346CE53D870ADC07ULL,
		0xD30282D22BF8C7B7ULL,
		0x61298511F343D7FCULL,
		0x5338471AEDF69C35ULL,
		0x732AC8963530093AULL
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
		0x0CF3144142925CE3ULL,
		0x5BDD33E2FF2559F2ULL,
		0x76B4CED354F93C16ULL,
		0x9D3BB035F7119A59ULL,
		0x71ACA390EFD50077ULL,
		0x99175F06D28D040CULL,
		0x13D229F1F7C0EA4AULL,
		0x198F3477F76C1F7AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x19E628828524B9C6ULL,
		0xB7BA67C5FE4AB3E4ULL,
		0xED699DA6A9F2782CULL,
		0x3A77606BEE2334B2ULL,
		0xE3594721DFAA00EFULL,
		0x322EBE0DA51A0818ULL,
		0x27A453E3EF81D495ULL,
		0x331E68EFEED83EF4ULL
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
		0xE5130B52F3C0C3A8ULL,
		0x800C339720820166ULL,
		0xE2AB14C0C8037010ULL,
		0x1CE6BA2DB73342D4ULL,
		0xB4FBC890A7A37E67ULL,
		0x4275750305010D35ULL,
		0xB96316BB9375CF4DULL,
		0x20A0FF8A0A60DC31ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCA2616A5E7818750ULL,
		0x0018672E410402CDULL,
		0xC55629819006E021ULL,
		0x39CD745B6E6685A9ULL,
		0x69F791214F46FCCEULL,
		0x84EAEA060A021A6BULL,
		0x72C62D7726EB9E9AULL,
		0x4141FF1414C1B863ULL
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
		0xB43376CCBA1E70F2ULL,
		0x8387A3E3078F7E76ULL,
		0x9B626773E6FB8532ULL,
		0x51CF6E6344BD0FD0ULL,
		0x2071B85C5631A11AULL,
		0x3CABD75341A82471ULL,
		0xB32C89BAE25072FCULL,
		0x0EFC96F079F2393DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6866ED99743CE1E4ULL,
		0x070F47C60F1EFCEDULL,
		0x36C4CEE7CDF70A65ULL,
		0xA39EDCC6897A1FA1ULL,
		0x40E370B8AC634234ULL,
		0x7957AEA6835048E2ULL,
		0x66591375C4A0E5F8ULL,
		0x1DF92DE0F3E4727BULL
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
		0xFAA3D8C8072B1C48ULL,
		0xD187F6D53E9C1EC2ULL,
		0x15D514A9E1225697ULL,
		0x0A82CE3F7B92D3EEULL,
		0x68593997A6B3E39BULL,
		0xE497EB4678F0B8A2ULL,
		0x17944FF548BD5869ULL,
		0x1DC286CDC926C477ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF547B1900E563890ULL,
		0xA30FEDAA7D383D85ULL,
		0x2BAA2953C244AD2FULL,
		0x15059C7EF725A7DCULL,
		0xD0B2732F4D67C736ULL,
		0xC92FD68CF1E17144ULL,
		0x2F289FEA917AB0D3ULL,
		0x3B850D9B924D88EEULL
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
		0x6B7D49E6D67920E9ULL,
		0x57DFD2190D1D7966ULL,
		0x13D8264F135C8C0DULL,
		0x426B19C242267C3AULL,
		0x14679191CA951776ULL,
		0xA7B7DE3BD2BDBCEAULL,
		0x0ECD73A0E558EE32ULL,
		0x00FDB538273535B6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD6FA93CDACF241D2ULL,
		0xAFBFA4321A3AF2CCULL,
		0x27B04C9E26B9181AULL,
		0x84D63384844CF874ULL,
		0x28CF2323952A2EECULL,
		0x4F6FBC77A57B79D4ULL,
		0x1D9AE741CAB1DC65ULL,
		0x01FB6A704E6A6B6CULL
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
		0x4409983CE06930DAULL,
		0x052F92030391FEB8ULL,
		0x78D33D17F930D761ULL,
		0x4C3BEB79652CF3D3ULL,
		0xD98253E3E097390EULL,
		0x9C57B4943F2BB8BAULL,
		0x1EEF21FA37923FA0ULL,
		0x2B3D26EE9E8CD6ADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x88133079C0D261B4ULL,
		0x0A5F24060723FD70ULL,
		0xF1A67A2FF261AEC2ULL,
		0x9877D6F2CA59E7A6ULL,
		0xB304A7C7C12E721CULL,
		0x38AF69287E577175ULL,
		0x3DDE43F46F247F41ULL,
		0x567A4DDD3D19AD5AULL
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
		0x9AE8386E19953EB7ULL,
		0xCECEDE0D0D121F29ULL,
		0x128586DC9BAA306FULL,
		0x88A7378F31CA44D8ULL,
		0x8454333C47858CD0ULL,
		0x4D63F6605102E6CFULL,
		0x131AAFA6A561A43AULL,
		0x0375892F16ABED25ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x35D070DC332A7D6EULL,
		0x9D9DBC1A1A243E53ULL,
		0x250B0DB9375460DFULL,
		0x114E6F1E639489B0ULL,
		0x08A866788F0B19A1ULL,
		0x9AC7ECC0A205CD9FULL,
		0x26355F4D4AC34874ULL,
		0x06EB125E2D57DA4AULL
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
		0xC86ED93FE94D9AACULL,
		0x9B0F3E845011B0E4ULL,
		0x68BA8C5CA7DB8B8EULL,
		0xBDC9E0AD81381942ULL,
		0xCB89F3EA5EBC5847ULL,
		0xBAB7CE7D0D095531ULL,
		0xADBBCF9C8CCEDF2CULL,
		0x0CBCC10E346228A6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x90DDB27FD29B3558ULL,
		0x361E7D08A02361C9ULL,
		0xD17518B94FB7171DULL,
		0x7B93C15B02703284ULL,
		0x9713E7D4BD78B08FULL,
		0x756F9CFA1A12AA63ULL,
		0x5B779F39199DBE59ULL,
		0x1979821C68C4514DULL
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
		0xE5501AA0ACB2DEF2ULL,
		0xD61D4700E079D7C5ULL,
		0x7BEE4FF134CFC2E1ULL,
		0xC3DBC8A404F0DB23ULL,
		0x2A1947377BED38AAULL,
		0x97687BA5F9D343DBULL,
		0x6EEB889413B76243ULL,
		0x0C13EB0865323288ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCAA035415965BDE4ULL,
		0xAC3A8E01C0F3AF8BULL,
		0xF7DC9FE2699F85C3ULL,
		0x87B7914809E1B646ULL,
		0x54328E6EF7DA7155ULL,
		0x2ED0F74BF3A687B6ULL,
		0xDDD71128276EC487ULL,
		0x1827D610CA646510ULL
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
		0x165FBA2FF1678775ULL,
		0x8B993262B6BDF334ULL,
		0x56FA682531F5158CULL,
		0x3F515179309D2DAEULL,
		0x2B30E507A3FC956EULL,
		0x9F54E28C4533678BULL,
		0x59C7A08C8EB14B15ULL,
		0x3E39C7BF7E007EA4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2CBF745FE2CF0EEAULL,
		0x173264C56D7BE668ULL,
		0xADF4D04A63EA2B19ULL,
		0x7EA2A2F2613A5B5CULL,
		0x5661CA0F47F92ADCULL,
		0x3EA9C5188A66CF16ULL,
		0xB38F41191D62962BULL,
		0x7C738F7EFC00FD48ULL
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
		0x87064C8B91143B02ULL,
		0x904BB1A6F0AF72C7ULL,
		0x205E7AE6106787F0ULL,
		0x85D625D5C22CB0BDULL,
		0x2A39D182D7562977ULL,
		0xCE2DB30DEC9B16C8ULL,
		0x9103A45E2F65304FULL,
		0x1BA2326086F074E4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0E0C991722287604ULL,
		0x2097634DE15EE58FULL,
		0x40BCF5CC20CF0FE1ULL,
		0x0BAC4BAB8459617AULL,
		0x5473A305AEAC52EFULL,
		0x9C5B661BD9362D90ULL,
		0x220748BC5ECA609FULL,
		0x374464C10DE0E9C9ULL
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
		0x67667A7BA72B67C3ULL,
		0x3D2E93562901BD51ULL,
		0xD8F5F256BF08BE78ULL,
		0xA1E5CBAE687EFDFDULL,
		0x871C8879A53D4EE7ULL,
		0x911CD724D80E44D2ULL,
		0x72DDE089149EC228ULL,
		0x27091B63D8D41F2BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCECCF4F74E56CF86ULL,
		0x7A5D26AC52037AA2ULL,
		0xB1EBE4AD7E117CF0ULL,
		0x43CB975CD0FDFBFBULL,
		0x0E3910F34A7A9DCFULL,
		0x2239AE49B01C89A5ULL,
		0xE5BBC112293D8451ULL,
		0x4E1236C7B1A83E56ULL
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
		0x1BC49C425FB62B03ULL,
		0x5B8F0640F2A4CFE1ULL,
		0xBF0D67E91734F671ULL,
		0x903030920367E11EULL,
		0x4982140060D0C7C8ULL,
		0xFFD14236FFDE0958ULL,
		0x2D42699867BF346DULL,
		0x0FAE5C9A79CCEF4CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x37893884BF6C5606ULL,
		0xB71E0C81E5499FC2ULL,
		0x7E1ACFD22E69ECE2ULL,
		0x2060612406CFC23DULL,
		0x93042800C1A18F91ULL,
		0xFFA2846DFFBC12B0ULL,
		0x5A84D330CF7E68DBULL,
		0x1F5CB934F399DE98ULL
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
		0xA515CF1A5DAEA6D1ULL,
		0x31DB86EDCDBE054BULL,
		0xDD809CE067D79837ULL,
		0xBAD400917F523259ULL,
		0x88DC463654F11261ULL,
		0xDB050D9DB0CCE418ULL,
		0xE647069D4A9B5C2FULL,
		0x10C9471A984FB530ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4A2B9E34BB5D4DA2ULL,
		0x63B70DDB9B7C0A97ULL,
		0xBB0139C0CFAF306EULL,
		0x75A80122FEA464B3ULL,
		0x11B88C6CA9E224C3ULL,
		0xB60A1B3B6199C831ULL,
		0xCC8E0D3A9536B85FULL,
		0x21928E35309F6A61ULL
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
		0x39EB344F2C5DDAA9ULL,
		0x5A54672055E9C914ULL,
		0x2B9430FCA2D72D83ULL,
		0x50D6FBDC3A22B5E2ULL,
		0x7C56130A94748693ULL,
		0xEB7CF6D61E689525ULL,
		0x19EFC3CDDDEBF0ECULL,
		0x3744BF5F185AA103ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x73D6689E58BBB552ULL,
		0xB4A8CE40ABD39228ULL,
		0x572861F945AE5B06ULL,
		0xA1ADF7B874456BC4ULL,
		0xF8AC261528E90D26ULL,
		0xD6F9EDAC3CD12A4AULL,
		0x33DF879BBBD7E1D9ULL,
		0x6E897EBE30B54206ULL
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
		0x7EB06E61F8509D52ULL,
		0x1AF6E5DFEF3364D7ULL,
		0x108C1860B90D1F5CULL,
		0xBD5F2DDABB9229D3ULL,
		0xE980C843519421D0ULL,
		0x0A4B84BAFD3A1087ULL,
		0x09210A3AFB525C90ULL,
		0x23C870032EE58927ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFD60DCC3F0A13AA4ULL,
		0x35EDCBBFDE66C9AEULL,
		0x211830C1721A3EB8ULL,
		0x7ABE5BB5772453A6ULL,
		0xD3019086A32843A1ULL,
		0x14970975FA74210FULL,
		0x12421475F6A4B920ULL,
		0x4790E0065DCB124EULL
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
		0xF73FBBC8D95E7772ULL,
		0x26BD234604003D7DULL,
		0x76526672B19AC418ULL,
		0x4925E37B7B2DDC90ULL,
		0x4D2AA36CE17CBE0BULL,
		0x5B4BF968EFC68B5FULL,
		0xDA7394A5B00EC534ULL,
		0x35393DB4A5ACE38FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEE7F7791B2BCEEE4ULL,
		0x4D7A468C08007AFBULL,
		0xECA4CCE563358830ULL,
		0x924BC6F6F65BB920ULL,
		0x9A5546D9C2F97C16ULL,
		0xB697F2D1DF8D16BEULL,
		0xB4E7294B601D8A68ULL,
		0x6A727B694B59C71FULL
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
		0x5E33CBD882918F00ULL,
		0x4CA09625147DF425ULL,
		0x5FA4077F9F51DF4EULL,
		0x78653400445218EBULL,
		0x1AAC9939358E8342ULL,
		0xC5476ECADD4F9018ULL,
		0x8670A6298C085E78ULL,
		0x0304D77C06EB3C85ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBC6797B105231E00ULL,
		0x99412C4A28FBE84AULL,
		0xBF480EFF3EA3BE9CULL,
		0xF0CA680088A431D6ULL,
		0x355932726B1D0684ULL,
		0x8A8EDD95BA9F2030ULL,
		0x0CE14C531810BCF1ULL,
		0x0609AEF80DD6790BULL
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
		0x4F53ECA533F4B483ULL,
		0xA36E126025AD16C9ULL,
		0xAE4FA68897A06531ULL,
		0xBB1E75705ED8D10CULL,
		0x73AB2276EFA8DA76ULL,
		0x77B7333F152DCBE0ULL,
		0x9AE0D92E0DEC500CULL,
		0x085B1DB358A24404ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9EA7D94A67E96906ULL,
		0x46DC24C04B5A2D92ULL,
		0x5C9F4D112F40CA63ULL,
		0x763CEAE0BDB1A219ULL,
		0xE75644EDDF51B4EDULL,
		0xEF6E667E2A5B97C0ULL,
		0x35C1B25C1BD8A018ULL,
		0x10B63B66B1448809ULL
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
		0x953AA9C4297BB2A1ULL,
		0xD47568FAB4EDA420ULL,
		0x91A50131C8AE4E10ULL,
		0x8FBCBF6EA0EF7DBCULL,
		0x8E176CAD01F10AEFULL,
		0x0A9D17995EAF0993ULL,
		0x47FDC8F017357E4CULL,
		0x313991A0835964E3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2A75538852F76542ULL,
		0xA8EAD1F569DB4841ULL,
		0x234A0263915C9C21ULL,
		0x1F797EDD41DEFB79ULL,
		0x1C2ED95A03E215DFULL,
		0x153A2F32BD5E1327ULL,
		0x8FFB91E02E6AFC98ULL,
		0x6273234106B2C9C6ULL
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
		0x06923CE75E68339BULL,
		0x37F8AAC43D6E74BFULL,
		0x8C379C2208878D6BULL,
		0xA197B4685EA8F4B7ULL,
		0x15104AEBD11D59CAULL,
		0xFE8F7308ABCCB7C1ULL,
		0x42BA98E89091E052ULL,
		0x1ED531A4179A4224ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0D2479CEBCD06736ULL,
		0x6FF155887ADCE97EULL,
		0x186F3844110F1AD6ULL,
		0x432F68D0BD51E96FULL,
		0x2A2095D7A23AB395ULL,
		0xFD1EE61157996F82ULL,
		0x857531D12123C0A5ULL,
		0x3DAA63482F348448ULL
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
		0x257ED611F55A8AF1ULL,
		0xEDC6D204BF6251CEULL,
		0x37BB990FD25884BFULL,
		0x1BBE9EBA764FCE0AULL,
		0xF28552E06AD1B3BBULL,
		0x2737DF622023522CULL,
		0x601892275036C9F4ULL,
		0x124D62DA9053E8DBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4AFDAC23EAB515E2ULL,
		0xDB8DA4097EC4A39CULL,
		0x6F77321FA4B1097FULL,
		0x377D3D74EC9F9C14ULL,
		0xE50AA5C0D5A36776ULL,
		0x4E6FBEC44046A459ULL,
		0xC031244EA06D93E8ULL,
		0x249AC5B520A7D1B6ULL
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
		0x5A3167E2B0499C7DULL,
		0x2A5DB85DEFD96DE5ULL,
		0xC8086B1F5490729BULL,
		0x7AC4E07627FF0684ULL,
		0x7E55204B85CBC310ULL,
		0x7DB8A99B16C39497ULL,
		0x98FA0504F4864F85ULL,
		0x208D1A40387179BBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB462CFC5609338FAULL,
		0x54BB70BBDFB2DBCAULL,
		0x9010D63EA920E536ULL,
		0xF589C0EC4FFE0D09ULL,
		0xFCAA40970B978620ULL,
		0xFB7153362D87292EULL,
		0x31F40A09E90C9F0AULL,
		0x411A348070E2F377ULL
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
		0x277703E5CE5712D3ULL,
		0x84B59012ED070412ULL,
		0x9802E2C3AB5E33FBULL,
		0xEB35F840E50436A2ULL,
		0xE317BF8BCFDA5F47ULL,
		0x7C818A95164DDEC7ULL,
		0x1A15FDEF5E333F3DULL,
		0x2FB05C325AA2F301ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4EEE07CB9CAE25A6ULL,
		0x096B2025DA0E0824ULL,
		0x3005C58756BC67F7ULL,
		0xD66BF081CA086D45ULL,
		0xC62F7F179FB4BE8FULL,
		0xF903152A2C9BBD8FULL,
		0x342BFBDEBC667E7AULL,
		0x5F60B864B545E602ULL
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
		0x722CD453F2DD9E61ULL,
		0xBB1BA0231C3827E5ULL,
		0x653DA8FFA435FB88ULL,
		0xD19E00DA8067A1DAULL,
		0xAD0CBC34417B5763ULL,
		0xF2EA52D872CAB026ULL,
		0xE6A6A1B9A5768DD8ULL,
		0x2A15719A15271457ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE459A8A7E5BB3CC2ULL,
		0x7637404638704FCAULL,
		0xCA7B51FF486BF711ULL,
		0xA33C01B500CF43B4ULL,
		0x5A19786882F6AEC7ULL,
		0xE5D4A5B0E595604DULL,
		0xCD4D43734AED1BB1ULL,
		0x542AE3342A4E28AFULL
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
		0xB904C90D9472529AULL,
		0xB59BD2E6000AAA2BULL,
		0xCFBAC030DF7B16C9ULL,
		0x1F1ECBBDC8174D33ULL,
		0xEBF2A88D856200E2ULL,
		0x75DCD3ECF3F235AFULL,
		0xA1B48F1F791EF998ULL,
		0x2F34EEBB9DAAD8EEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7209921B28E4A534ULL,
		0x6B37A5CC00155457ULL,
		0x9F758061BEF62D93ULL,
		0x3E3D977B902E9A67ULL,
		0xD7E5511B0AC401C4ULL,
		0xEBB9A7D9E7E46B5FULL,
		0x43691E3EF23DF330ULL,
		0x5E69DD773B55B1DDULL
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
		0xCC1FA7EDA256A1BAULL,
		0xFD2277D251F11E26ULL,
		0xABA21A38F1BF8A15ULL,
		0x072EC5178AA2DBE1ULL,
		0xD616607A3F2645F4ULL,
		0x87FA1A22042461C7ULL,
		0x637D1B71ACDDF653ULL,
		0x07F9A8A032C50F56ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x983F4FDB44AD4374ULL,
		0xFA44EFA4A3E23C4DULL,
		0x57443471E37F142BULL,
		0x0E5D8A2F1545B7C3ULL,
		0xAC2CC0F47E4C8BE8ULL,
		0x0FF434440848C38FULL,
		0xC6FA36E359BBECA7ULL,
		0x0FF35140658A1EACULL
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
		0x396B61D5C32D165FULL,
		0x418D194A214E3E70ULL,
		0x6E9E4780821278DDULL,
		0x5F0548224006EC00ULL,
		0x92B96EBF45473DD9ULL,
		0x6DACBB5DCB7260E6ULL,
		0x2916A2A7EADE3B05ULL,
		0x3DFA666CA25C7FA1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x72D6C3AB865A2CBEULL,
		0x831A3294429C7CE0ULL,
		0xDD3C8F010424F1BAULL,
		0xBE0A9044800DD800ULL,
		0x2572DD7E8A8E7BB2ULL,
		0xDB5976BB96E4C1CDULL,
		0x522D454FD5BC760AULL,
		0x7BF4CCD944B8FF42ULL
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
		0x3F9350DAD5E07317ULL,
		0x840518E24D702557ULL,
		0x4C0F9242935F5F2DULL,
		0xE7CB0A42C6AD786CULL,
		0xA09F6B5E8F3F5C14ULL,
		0x0A7A7015EA0269D8ULL,
		0x2F002B75819B621AULL,
		0x10E2B5691FF13965ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7F26A1B5ABC0E62EULL,
		0x080A31C49AE04AAEULL,
		0x981F248526BEBE5BULL,
		0xCF9614858D5AF0D8ULL,
		0x413ED6BD1E7EB829ULL,
		0x14F4E02BD404D3B1ULL,
		0x5E0056EB0336C434ULL,
		0x21C56AD23FE272CAULL
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
		0x8EA712AD0AC742DFULL,
		0xCC9D9AB981586F44ULL,
		0xBC230CDA67322E24ULL,
		0xECDC83DB2BBD4963ULL,
		0x1F5431FCAE726D8BULL,
		0x102CBA399D76B4B0ULL,
		0x22956696CDB946F6ULL,
		0x0DE2215096919DD4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1D4E255A158E85BEULL,
		0x993B357302B0DE89ULL,
		0x784619B4CE645C49ULL,
		0xD9B907B6577A92C7ULL,
		0x3EA863F95CE4DB17ULL,
		0x205974733AED6960ULL,
		0x452ACD2D9B728DECULL,
		0x1BC442A12D233BA8ULL
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
		0x5143D203F886C7B8ULL,
		0x5371A5748D6C8943ULL,
		0x90CCA4D8A766D208ULL,
		0xC26968FDB13F9F77ULL,
		0x02B76FBEEF8D67FEULL,
		0xD18AF42AFA8805B4ULL,
		0xCF740279A2B2025CULL,
		0x2CFE7EA6FE473096ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA287A407F10D8F70ULL,
		0xA6E34AE91AD91286ULL,
		0x219949B14ECDA410ULL,
		0x84D2D1FB627F3EEFULL,
		0x056EDF7DDF1ACFFDULL,
		0xA315E855F5100B68ULL,
		0x9EE804F3456404B9ULL,
		0x59FCFD4DFC8E612DULL
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
		0x89F6E22D6EBA5CD5ULL,
		0x016C635E85810328ULL,
		0xD0707C359BA5F97DULL,
		0x2983C6B3CC7179FDULL,
		0xD5004A17582E4BC7ULL,
		0x121A015DFCB80359ULL,
		0x74AF2256FB9F2FF7ULL,
		0x2EC81FF1C419C618ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x13EDC45ADD74B9AAULL,
		0x02D8C6BD0B020651ULL,
		0xA0E0F86B374BF2FAULL,
		0x53078D6798E2F3FBULL,
		0xAA00942EB05C978EULL,
		0x243402BBF97006B3ULL,
		0xE95E44ADF73E5FEEULL,
		0x5D903FE388338C30ULL
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
		0x428C5E1118E1B877ULL,
		0x722572342D7A46E7ULL,
		0x269C7FCC3C7D7621ULL,
		0x9A64EBA2C7FE362EULL,
		0x3772F8A98C170F95ULL,
		0x944F23DD327847D1ULL,
		0xEB2991C8BD62D902ULL,
		0x18F2E62729EDFA5EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8518BC2231C370EEULL,
		0xE44AE4685AF48DCEULL,
		0x4D38FF9878FAEC42ULL,
		0x34C9D7458FFC6C5CULL,
		0x6EE5F153182E1F2BULL,
		0x289E47BA64F08FA2ULL,
		0xD65323917AC5B205ULL,
		0x31E5CC4E53DBF4BDULL
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
		0x4F583B861287D052ULL,
		0xC3122F13A1374567ULL,
		0xEE99F57BF2CF1EFEULL,
		0x9E47299ADD116040ULL,
		0x64BA697E732CE462ULL,
		0x113D6FF8F465B011ULL,
		0x2416C3F71BD08794ULL,
		0x10D282D0862FDA50ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9EB0770C250FA0A4ULL,
		0x86245E27426E8ACEULL,
		0xDD33EAF7E59E3DFDULL,
		0x3C8E5335BA22C081ULL,
		0xC974D2FCE659C8C5ULL,
		0x227ADFF1E8CB6022ULL,
		0x482D87EE37A10F28ULL,
		0x21A505A10C5FB4A0ULL
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
		0xE911BD6DEB4070C1ULL,
		0x73E2D5ECF249BEF6ULL,
		0x3B2D6E59FFCBD336ULL,
		0x229F2BB2136BEBEFULL,
		0x0E2A32DB267C7CA0ULL,
		0x75A7ECAD3042CFB0ULL,
		0x3A88AC3C404AFAF2ULL,
		0x3AE9BB3E9354F7DAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD2237ADBD680E182ULL,
		0xE7C5ABD9E4937DEDULL,
		0x765ADCB3FF97A66CULL,
		0x453E576426D7D7DEULL,
		0x1C5465B64CF8F940ULL,
		0xEB4FD95A60859F60ULL,
		0x751158788095F5E4ULL,
		0x75D3767D26A9EFB4ULL
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
		0xBEE4D206449E3F8CULL,
		0x0E06F8DADD059655ULL,
		0x733C3CA93CD41770ULL,
		0x6F4791CBC42F3AE4ULL,
		0xBBAFA2E03767A785ULL,
		0xCFCE2EE18CBD6425ULL,
		0xE7AB9A4C59FDD48BULL,
		0x2D55366B06DDDAD6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7DC9A40C893C7F18ULL,
		0x1C0DF1B5BA0B2CABULL,
		0xE678795279A82EE0ULL,
		0xDE8F2397885E75C8ULL,
		0x775F45C06ECF4F0AULL,
		0x9F9C5DC3197AC84BULL,
		0xCF573498B3FBA917ULL,
		0x5AAA6CD60DBBB5ADULL
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
		0x34661E9AE3F7C265ULL,
		0x8D9C42D9E70DD271ULL,
		0x48B3AC9F5DF6B038ULL,
		0xC8141D80EE96F900ULL,
		0x9F0AD7440D8C12F5ULL,
		0x805B323C5EB43298ULL,
		0x7807EEEC1121E223ULL,
		0x219806103D53706CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x68CC3D35C7EF84CAULL,
		0x1B3885B3CE1BA4E2ULL,
		0x9167593EBBED6071ULL,
		0x90283B01DD2DF200ULL,
		0x3E15AE881B1825EBULL,
		0x00B66478BD686531ULL,
		0xF00FDDD82243C447ULL,
		0x43300C207AA6E0D8ULL
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
		0xA3D2C2B98DDAF934ULL,
		0xD4A206CFF2EDE724ULL,
		0x8E5980BDEE76FF56ULL,
		0x6B30B5CD35DE3CF7ULL,
		0x472E1C32F38D71A4ULL,
		0x3E6467D70EBA7EBBULL,
		0x8699EE4ACB7EE8DDULL,
		0x25755418B4EBE62DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x47A585731BB5F268ULL,
		0xA9440D9FE5DBCE49ULL,
		0x1CB3017BDCEDFEADULL,
		0xD6616B9A6BBC79EFULL,
		0x8E5C3865E71AE348ULL,
		0x7CC8CFAE1D74FD76ULL,
		0x0D33DC9596FDD1BAULL,
		0x4AEAA83169D7CC5BULL
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
		0xA70E93071F466253ULL,
		0x098E3499A1AD8556ULL,
		0x7198AB7C0420B702ULL,
		0xB7EAE52DD9536331ULL,
		0x666DC25A63FF648BULL,
		0xC8AFB5C43C5090F6ULL,
		0x4645459188B0D92EULL,
		0x277F2506B6416EE7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4E1D260E3E8CC4A6ULL,
		0x131C6933435B0AADULL,
		0xE33156F808416E04ULL,
		0x6FD5CA5BB2A6C662ULL,
		0xCCDB84B4C7FEC917ULL,
		0x915F6B8878A121ECULL,
		0x8C8A8B231161B25DULL,
		0x4EFE4A0D6C82DDCEULL
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
		0x886E79911F4A693CULL,
		0x82048B9378AE059DULL,
		0xC4870D86F823ED7BULL,
		0xB8742702686587ADULL,
		0xBB30C06DBCB50A87ULL,
		0x8DCE0594A557294EULL,
		0xFBFBFBF4651729BFULL,
		0x19323550646B72E0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x10DCF3223E94D278ULL,
		0x04091726F15C0B3BULL,
		0x890E1B0DF047DAF7ULL,
		0x70E84E04D0CB0F5BULL,
		0x766180DB796A150FULL,
		0x1B9C0B294AAE529DULL,
		0xF7F7F7E8CA2E537FULL,
		0x32646AA0C8D6E5C1ULL
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
		0x5ABF69419FF81C07ULL,
		0x10CB2815F57F1107ULL,
		0x0E612F07C31FFFD1ULL,
		0x819F7C1A0FF650EDULL,
		0xC13D727C4C16B882ULL,
		0x3205023D9871358FULL,
		0x110E03990F4DD29DULL,
		0x2B557912FEB63E3CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB57ED2833FF0380EULL,
		0x2196502BEAFE220EULL,
		0x1CC25E0F863FFFA2ULL,
		0x033EF8341FECA1DAULL,
		0x827AE4F8982D7105ULL,
		0x640A047B30E26B1FULL,
		0x221C07321E9BA53AULL,
		0x56AAF225FD6C7C78ULL
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
		0xA122046C92C6FAFFULL,
		0x02540C0E3FC52B8BULL,
		0xE0E049EDF9B5ECBEULL,
		0x8FC0512BE7FC89DEULL,
		0x551902C3D61174CAULL,
		0xFA7D2F23D9FEB9E0ULL,
		0xC31B011C5284A501ULL,
		0x162E7E77E9172825ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x424408D9258DF5FEULL,
		0x04A8181C7F8A5717ULL,
		0xC1C093DBF36BD97CULL,
		0x1F80A257CFF913BDULL,
		0xAA320587AC22E995ULL,
		0xF4FA5E47B3FD73C0ULL,
		0x86360238A5094A03ULL,
		0x2C5CFCEFD22E504BULL
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
		0x689CE9AA86F7626FULL,
		0x9D1196CD2030B556ULL,
		0x7AD4DBF29D4C8583ULL,
		0x51E9A75B7D049064ULL,
		0xF188036AA894AFADULL,
		0x8BAD3CDAF6F70AB5ULL,
		0x546430DE83DC97CFULL,
		0x14BEA86E6B527665ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD139D3550DEEC4DEULL,
		0x3A232D9A40616AACULL,
		0xF5A9B7E53A990B07ULL,
		0xA3D34EB6FA0920C8ULL,
		0xE31006D551295F5AULL,
		0x175A79B5EDEE156BULL,
		0xA8C861BD07B92F9FULL,
		0x297D50DCD6A4ECCAULL
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
		0x0775AA14BEBACAC7ULL,
		0x34A8E8E054A44A19ULL,
		0xD62A9548B2F8D5EFULL,
		0x3114FD84D1264D7BULL,
		0x4CD8A5D8F480F4B6ULL,
		0x4C78B2F22455EADBULL,
		0x8DBA127ED7769F3DULL,
		0x030805EEEBFD3E8AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0EEB54297D75958EULL,
		0x6951D1C0A9489432ULL,
		0xAC552A9165F1ABDEULL,
		0x6229FB09A24C9AF7ULL,
		0x99B14BB1E901E96CULL,
		0x98F165E448ABD5B6ULL,
		0x1B7424FDAEED3E7AULL,
		0x06100BDDD7FA7D15ULL
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
		0xB9F1A96B1861347DULL,
		0x7E3DFBC0DDBF266AULL,
		0xF2FCC7EBD3F20BFEULL,
		0xCF6AF517248B7971ULL,
		0x0E0E3703D4F5C7D7ULL,
		0x76CD498CD15530FBULL,
		0x89BF207EDA50FAE7ULL,
		0x3F81AF66B22E6009ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x73E352D630C268FAULL,
		0xFC7BF781BB7E4CD5ULL,
		0xE5F98FD7A7E417FCULL,
		0x9ED5EA2E4916F2E3ULL,
		0x1C1C6E07A9EB8FAFULL,
		0xED9A9319A2AA61F6ULL,
		0x137E40FDB4A1F5CEULL,
		0x7F035ECD645CC013ULL
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
		0x345D3566B3A8F26DULL,
		0x33CE418A15C61D00ULL,
		0xB319D7127216F5E2ULL,
		0xDE514AD80E595689ULL,
		0xEF2909ACC64A58EFULL,
		0xF5FCFE8298118102ULL,
		0x83A13C5147B0B642ULL,
		0x2CFAC9478ACEB185ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x68BA6ACD6751E4DAULL,
		0x679C83142B8C3A00ULL,
		0x6633AE24E42DEBC4ULL,
		0xBCA295B01CB2AD13ULL,
		0xDE5213598C94B1DFULL,
		0xEBF9FD0530230205ULL,
		0x074278A28F616C85ULL,
		0x59F5928F159D630BULL
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
		0xC096F8027C231CE7ULL,
		0xE2379EB73E74E370ULL,
		0x7F72DAAA3E3D1684ULL,
		0x7E01394A5496C9B7ULL,
		0xA3A96D8BB068FAF5ULL,
		0xBF088DD47A24C293ULL,
		0x85B4157DDDFCD9BAULL,
		0x2D184059B61A5B43ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x812DF004F84639CEULL,
		0xC46F3D6E7CE9C6E1ULL,
		0xFEE5B5547C7A2D09ULL,
		0xFC027294A92D936EULL,
		0x4752DB1760D1F5EAULL,
		0x7E111BA8F4498527ULL,
		0x0B682AFBBBF9B375ULL,
		0x5A3080B36C34B687ULL
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
		0xED87686939B4C995ULL,
		0x8AB9B07D45B42981ULL,
		0xDDBFC7C3E8E0AF24ULL,
		0x9A2DA3AEA101DF3EULL,
		0x5D03B7532234F981ULL,
		0xCE818497A32BE177ULL,
		0xF747D43B1EB122A2ULL,
		0x17B20091D6A6A246ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDB0ED0D27369932AULL,
		0x157360FA8B685303ULL,
		0xBB7F8F87D1C15E49ULL,
		0x345B475D4203BE7DULL,
		0xBA076EA64469F303ULL,
		0x9D03092F4657C2EEULL,
		0xEE8FA8763D624545ULL,
		0x2F640123AD4D448DULL
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
		0x60B0DD333838A269ULL,
		0x9D9CBDCEAC284C91ULL,
		0xD02F66EB7C9AE202ULL,
		0xC43BC742FC71501EULL,
		0xF7037856F078AEE0ULL,
		0x138D1C894319253FULL,
		0x715BA6641EDB2590ULL,
		0x18A4E3094C6543BFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC161BA66707144D2ULL,
		0x3B397B9D58509922ULL,
		0xA05ECDD6F935C405ULL,
		0x88778E85F8E2A03DULL,
		0xEE06F0ADE0F15DC1ULL,
		0x271A391286324A7FULL,
		0xE2B74CC83DB64B20ULL,
		0x3149C61298CA877EULL
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
		0x26A044D1724E0D61ULL,
		0x58B2747A431E610DULL,
		0xFB76D25281E82DB4ULL,
		0x2D1AE09B0F55D2DEULL,
		0x4291F43CA8847388ULL,
		0xF235BBD3E19F86F7ULL,
		0x1846EAFEF4C374B4ULL,
		0x363A9CE22EFA773DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4D4089A2E49C1AC2ULL,
		0xB164E8F4863CC21AULL,
		0xF6EDA4A503D05B68ULL,
		0x5A35C1361EABA5BDULL,
		0x8523E8795108E710ULL,
		0xE46B77A7C33F0DEEULL,
		0x308DD5FDE986E969ULL,
		0x6C7539C45DF4EE7AULL
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
		0x44F6A0DDABF0D00BULL,
		0xF3B83762687485AAULL,
		0xE6FAD97DD67CFCE9ULL,
		0x19DFAFAF94AC35F7ULL,
		0x012DEFC6706A9BF6ULL,
		0x0BB5C4754965E9E4ULL,
		0xC991465E2F1308DDULL,
		0x1AC076D7F4A5DEC9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x89ED41BB57E1A016ULL,
		0xE7706EC4D0E90B54ULL,
		0xCDF5B2FBACF9F9D3ULL,
		0x33BF5F5F29586BEFULL,
		0x025BDF8CE0D537ECULL,
		0x176B88EA92CBD3C8ULL,
		0x93228CBC5E2611BAULL,
		0x3580EDAFE94BBD93ULL
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
		0xB6397B12B7AB9C9EULL,
		0x16DA1E63F84F875AULL,
		0xB81881F3D791A675ULL,
		0x1E8E04DF3358C5B7ULL,
		0xBA4FD8CDA010901FULL,
		0x7AA8A5AC99259260ULL,
		0xDA395EC480272C94ULL,
		0x29F884BB3E945D00ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6C72F6256F57393CULL,
		0x2DB43CC7F09F0EB5ULL,
		0x703103E7AF234CEAULL,
		0x3D1C09BE66B18B6FULL,
		0x749FB19B4021203EULL,
		0xF5514B59324B24C1ULL,
		0xB472BD89004E5928ULL,
		0x53F109767D28BA01ULL
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
		0x5DBDCE6A3CE1D372ULL,
		0x4175C5BE09F6B6E5ULL,
		0xF6AFC710F0D4B331ULL,
		0x154D45B7CAEF1A53ULL,
		0x7AC0D249BEFE8AE5ULL,
		0x3A97009C45F0C44CULL,
		0x838F1E506EC51EF6ULL,
		0x1AB6D93A4188CCD4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB7B9CD479C3A6E4ULL,
		0x82EB8B7C13ED6DCAULL,
		0xED5F8E21E1A96662ULL,
		0x2A9A8B6F95DE34A7ULL,
		0xF581A4937DFD15CAULL,
		0x752E01388BE18898ULL,
		0x071E3CA0DD8A3DECULL,
		0x356DB274831199A9ULL
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
		0x92C69071FDB00E7FULL,
		0xC17B44E2317C1FEAULL,
		0xBFC2E43A14BA67E8ULL,
		0x5E48F4A69DF5A3DBULL,
		0x9C832B42D3E4FED8ULL,
		0x6285BB40707F860DULL,
		0x15CF33A2400271FAULL,
		0x04F2785873E97341ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x258D20E3FB601CFEULL,
		0x82F689C462F83FD5ULL,
		0x7F85C8742974CFD1ULL,
		0xBC91E94D3BEB47B7ULL,
		0x39065685A7C9FDB0ULL,
		0xC50B7680E0FF0C1BULL,
		0x2B9E67448004E3F4ULL,
		0x09E4F0B0E7D2E682ULL
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
		0xE334987AA79A854AULL,
		0x97B43612F4D40D3EULL,
		0x36FC9AF5DAAB77A5ULL,
		0xD4F8ADB2F65A44FEULL,
		0xB95EEFAADC569F12ULL,
		0x4FB14D00AB8568C1ULL,
		0xC95EC50B3274035EULL,
		0x109AE201158CAB7DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC66930F54F350A94ULL,
		0x2F686C25E9A81A7DULL,
		0x6DF935EBB556EF4BULL,
		0xA9F15B65ECB489FCULL,
		0x72BDDF55B8AD3E25ULL,
		0x9F629A01570AD183ULL,
		0x92BD8A1664E806BCULL,
		0x2135C4022B1956FBULL
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
		0xFEA11D4797F715ADULL,
		0x62637A20D1BEA30CULL,
		0x64A03DF6D57F8841ULL,
		0x2EB95A1E1DB2BFEEULL,
		0x18CEC7C5CC941363ULL,
		0xF4F16529A23C1440ULL,
		0x472BC2276194F2BCULL,
		0x2B35C911EE4F335AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFD423A8F2FEE2B5AULL,
		0xC4C6F441A37D4619ULL,
		0xC9407BEDAAFF1082ULL,
		0x5D72B43C3B657FDCULL,
		0x319D8F8B992826C6ULL,
		0xE9E2CA5344782880ULL,
		0x8E57844EC329E579ULL,
		0x566B9223DC9E66B4ULL
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
		0x31C27F444F2A0C73ULL,
		0xEF8675B7E14F212FULL,
		0x2EFEEFDAECA43026ULL,
		0x8731EC4C04AAD4A6ULL,
		0x615B341605D4EF7BULL,
		0xA4591BEA42BC4883ULL,
		0x37CA1CECE822DED3ULL,
		0x23527575F88C4761ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6384FE889E5418E6ULL,
		0xDF0CEB6FC29E425EULL,
		0x5DFDDFB5D948604DULL,
		0x0E63D8980955A94CULL,
		0xC2B6682C0BA9DEF7ULL,
		0x48B237D485789106ULL,
		0x6F9439D9D045BDA7ULL,
		0x46A4EAEBF1188EC2ULL
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
		0x8BFEA91F6AF469CBULL,
		0x3E5EDED20AABA630ULL,
		0x2C8C1BCE1B3BDA03ULL,
		0x12B63D7B33475C49ULL,
		0xA0756BF3F54027DCULL,
		0x5B3B8B239C397526ULL,
		0x5D95D4BD46706870ULL,
		0x30C316E706F19A5AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x17FD523ED5E8D396ULL,
		0x7CBDBDA415574C61ULL,
		0x5918379C3677B406ULL,
		0x256C7AF6668EB892ULL,
		0x40EAD7E7EA804FB8ULL,
		0xB67716473872EA4DULL,
		0xBB2BA97A8CE0D0E0ULL,
		0x61862DCE0DE334B4ULL
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
		0x3A627FE991FD73AAULL,
		0x65F039C45E61F41AULL,
		0x86A60EE657275472ULL,
		0x94649B9297765ADBULL,
		0x34C52B37B8FAEFB7ULL,
		0xCFCAE9D16A691B48ULL,
		0x52F49F49F204500FULL,
		0x2ADD353B90DDD25CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x74C4FFD323FAE754ULL,
		0xCBE07388BCC3E834ULL,
		0x0D4C1DCCAE4EA8E4ULL,
		0x28C937252EECB5B7ULL,
		0x698A566F71F5DF6FULL,
		0x9F95D3A2D4D23690ULL,
		0xA5E93E93E408A01FULL,
		0x55BA6A7721BBA4B8ULL
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
		0x20ADD5122D246739ULL,
		0x249695CE2401414DULL,
		0xB920F7BE9FBDA9C9ULL,
		0x8B3CE967E4BE9B10ULL,
		0x6BD14DF2657D59D5ULL,
		0xD277A25BDE7B310EULL,
		0xC3A311C6FF088D4EULL,
		0x0A52DAA978EA55ECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x415BAA245A48CE72ULL,
		0x492D2B9C4802829AULL,
		0x7241EF7D3F7B5392ULL,
		0x1679D2CFC97D3621ULL,
		0xD7A29BE4CAFAB3ABULL,
		0xA4EF44B7BCF6621CULL,
		0x8746238DFE111A9DULL,
		0x14A5B552F1D4ABD9ULL
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
		0x98A88F977CE53DA7ULL,
		0xCE3F40341B38D39BULL,
		0xC950A67C45CB0B65ULL,
		0xC9B14B69255FD607ULL,
		0xAB8B872B1232469AULL,
		0x097233462D43CF0DULL,
		0xEED61008D6971D94ULL,
		0x14A846E6856ED317ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x31511F2EF9CA7B4EULL,
		0x9C7E80683671A737ULL,
		0x92A14CF88B9616CBULL,
		0x936296D24ABFAC0FULL,
		0x57170E5624648D35ULL,
		0x12E4668C5A879E1BULL,
		0xDDAC2011AD2E3B28ULL,
		0x29508DCD0ADDA62FULL
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
		0xC3B2C9E099FDF358ULL,
		0x3E81B6476117DDDCULL,
		0x570A031A7B840427ULL,
		0xD4629CFC2580F510ULL,
		0x1E915189BD7DE0D5ULL,
		0xAF411FC7F0FCFF20ULL,
		0x7DFDF198142D2D4CULL,
		0x0DB10F35AAB0D85DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x876593C133FBE6B0ULL,
		0x7D036C8EC22FBBB9ULL,
		0xAE140634F708084EULL,
		0xA8C539F84B01EA20ULL,
		0x3D22A3137AFBC1ABULL,
		0x5E823F8FE1F9FE40ULL,
		0xFBFBE330285A5A99ULL,
		0x1B621E6B5561B0BAULL
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
		0x84F35DBAB17A4CA8ULL,
		0xDE1CDE760C7876FEULL,
		0xDA57DB766461AEA6ULL,
		0x84C9E60EA81750AAULL,
		0x9968F1F2CD4DF394ULL,
		0x7C58C0B9C87643CBULL,
		0xC5D83E1BF1E40993ULL,
		0x08B8339DDC7C29C0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x09E6BB7562F49950ULL,
		0xBC39BCEC18F0EDFDULL,
		0xB4AFB6ECC8C35D4DULL,
		0x0993CC1D502EA155ULL,
		0x32D1E3E59A9BE729ULL,
		0xF8B1817390EC8797ULL,
		0x8BB07C37E3C81326ULL,
		0x1170673BB8F85381ULL
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
		0x57114DD7C14BDA0CULL,
		0xA345D121DC0AA8FAULL,
		0x507220BE97B50905ULL,
		0x42D8D3A6A8D85F7EULL,
		0xC13847467A1A113BULL,
		0x8929FDA895BDE103ULL,
		0x8BC9516D8FF35A25ULL,
		0x0006C4F0A72845AAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAE229BAF8297B418ULL,
		0x468BA243B81551F4ULL,
		0xA0E4417D2F6A120BULL,
		0x85B1A74D51B0BEFCULL,
		0x82708E8CF4342276ULL,
		0x1253FB512B7BC207ULL,
		0x1792A2DB1FE6B44BULL,
		0x000D89E14E508B55ULL
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
		0xA245294634FDC376ULL,
		0x3C900098AFA5F199ULL,
		0x0C37BBE87E71775AULL,
		0x7D39AA65D95E922FULL,
		0x6C1CAEFB89BFB7D4ULL,
		0xEC389ACDF66FF7CEULL,
		0xAE3BCEF1B093CC90ULL,
		0x0DD73DB4C28FBD5FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x448A528C69FB86ECULL,
		0x792001315F4BE333ULL,
		0x186F77D0FCE2EEB4ULL,
		0xFA7354CBB2BD245EULL,
		0xD8395DF7137F6FA8ULL,
		0xD871359BECDFEF9CULL,
		0x5C779DE361279921ULL,
		0x1BAE7B69851F7ABFULL
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
		0xC61B43CB0FD95070ULL,
		0x8B98542F9776E48CULL,
		0x8BBC97420DC3ACCDULL,
		0x198D9DACE757A027ULL,
		0x0FB41E22B9EEF6B1ULL,
		0x984D29BA015BBE8DULL,
		0x15B9BC3DAB8834EBULL,
		0x2084D3C685AFB410ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8C3687961FB2A0E0ULL,
		0x1730A85F2EEDC919ULL,
		0x17792E841B87599BULL,
		0x331B3B59CEAF404FULL,
		0x1F683C4573DDED62ULL,
		0x309A537402B77D1AULL,
		0x2B73787B571069D7ULL,
		0x4109A78D0B5F6820ULL
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
		0x71EB7D0E7C778150ULL,
		0x256ECD7DA63EFE4DULL,
		0x3757E70D7C31C1DAULL,
		0x255AE55FBC12D89FULL,
		0x521DCCBB6EF5604EULL,
		0xAC65E21AACF63642ULL,
		0x0B1464A7F8919E2CULL,
		0x03DF071B125BE8CBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE3D6FA1CF8EF02A0ULL,
		0x4ADD9AFB4C7DFC9AULL,
		0x6EAFCE1AF86383B4ULL,
		0x4AB5CABF7825B13EULL,
		0xA43B9976DDEAC09CULL,
		0x58CBC43559EC6C84ULL,
		0x1628C94FF1233C59ULL,
		0x07BE0E3624B7D196ULL
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
		0xB860C96B100E0DE6ULL,
		0x7B6E3BFCE22457ACULL,
		0x82C6136EE5EEE812ULL,
		0x4E4C4F31DE22B6ECULL,
		0x9568DC50EB96F99AULL,
		0x8CBC5530F81231FCULL,
		0x33A10DF6972E34B3ULL,
		0x0D49C013C7365406ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x70C192D6201C1BCCULL,
		0xF6DC77F9C448AF59ULL,
		0x058C26DDCBDDD024ULL,
		0x9C989E63BC456DD9ULL,
		0x2AD1B8A1D72DF334ULL,
		0x1978AA61F02463F9ULL,
		0x67421BED2E5C6967ULL,
		0x1A9380278E6CA80CULL
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
		0xD61B3934BD1DC014ULL,
		0x9F2C3DDA8CD877E9ULL,
		0x7DBC3AEBB546BDC6ULL,
		0xCF577411D85695D5ULL,
		0x2EFFB728254EAD4DULL,
		0xAF31884EEE1725D9ULL,
		0x9974710CB0527630ULL,
		0x074DB9523BE8C94FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAC3672697A3B8028ULL,
		0x3E587BB519B0EFD3ULL,
		0xFB7875D76A8D7B8DULL,
		0x9EAEE823B0AD2BAAULL,
		0x5DFF6E504A9D5A9BULL,
		0x5E63109DDC2E4BB2ULL,
		0x32E8E21960A4EC61ULL,
		0x0E9B72A477D1929FULL
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
		0x0E1CFC95AB1B0A73ULL,
		0xB4DA34CEC2C318F8ULL,
		0x658D1B9C0018AF15ULL,
		0x75B62B3DB2830EA2ULL,
		0xB52E188B9B3DD158ULL,
		0x88732B22DDCC16E7ULL,
		0x535B1B13524DA4B7ULL,
		0x14E49D02636C923DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1C39F92B563614E6ULL,
		0x69B4699D858631F0ULL,
		0xCB1A373800315E2BULL,
		0xEB6C567B65061D44ULL,
		0x6A5C3117367BA2B0ULL,
		0x10E65645BB982DCFULL,
		0xA6B63626A49B496FULL,
		0x29C93A04C6D9247AULL
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
		0xE98FB38E32FB7E32ULL,
		0xE2FFADCC03605F68ULL,
		0xD845925DA16F8272ULL,
		0x2D185FAF0E066A37ULL,
		0x3FA9F99D3531A342ULL,
		0x1F97256333D09759ULL,
		0x1BCDE0D0BE93E11AULL,
		0x022FB7568E90785FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD31F671C65F6FC64ULL,
		0xC5FF5B9806C0BED1ULL,
		0xB08B24BB42DF04E5ULL,
		0x5A30BF5E1C0CD46FULL,
		0x7F53F33A6A634684ULL,
		0x3F2E4AC667A12EB2ULL,
		0x379BC1A17D27C234ULL,
		0x045F6EAD1D20F0BEULL
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
		0x9C8F34FD50EA0EFDULL,
		0xDD9DB50E83FBB92EULL,
		0x3A6F28E074674045ULL,
		0x078E6F66EC953574ULL,
		0xBAA7FF1F51980371ULL,
		0x5092B44CD668BEABULL,
		0x43EE9381801C23A1ULL,
		0x2039EBDBF32758D3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x391E69FAA1D41DFAULL,
		0xBB3B6A1D07F7725DULL,
		0x74DE51C0E8CE808BULL,
		0x0F1CDECDD92A6AE8ULL,
		0x754FFE3EA33006E2ULL,
		0xA1256899ACD17D57ULL,
		0x87DD270300384742ULL,
		0x4073D7B7E64EB1A6ULL
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
		0xD32F8471EF3FF83FULL,
		0x3A03F93321FDEC42ULL,
		0x06F008BC7FA649FFULL,
		0x1B34E62B019E5253ULL,
		0x186EFF9966671AFEULL,
		0xF1AD301B8C12B0DDULL,
		0xF43740BBEE00447FULL,
		0x3E8D618037466B73ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA65F08E3DE7FF07EULL,
		0x7407F26643FBD885ULL,
		0x0DE01178FF4C93FEULL,
		0x3669CC56033CA4A6ULL,
		0x30DDFF32CCCE35FCULL,
		0xE35A6037182561BAULL,
		0xE86E8177DC0088FFULL,
		0x7D1AC3006E8CD6E7ULL
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
		0x0B4FF9C33BD3FB9DULL,
		0xFFDD41AC353AD2F7ULL,
		0xB88429FF4EC88F0BULL,
		0x24C6D04866DBA4DEULL,
		0x0E17A86A223E68D8ULL,
		0x2E45D3222CF19C3FULL,
		0xF5B033BB915FD2D7ULL,
		0x0F8E9DF77610E44AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x169FF38677A7F73AULL,
		0xFFBA83586A75A5EEULL,
		0x710853FE9D911E17ULL,
		0x498DA090CDB749BDULL,
		0x1C2F50D4447CD1B0ULL,
		0x5C8BA64459E3387EULL,
		0xEB60677722BFA5AEULL,
		0x1F1D3BEEEC21C895ULL
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
		0xBD45F10D638E0AD2ULL,
		0x0203CA351FA66E70ULL,
		0xBE53F3BFE0779813ULL,
		0x89DFF84EEE7289AAULL,
		0xD5590903537D6632ULL,
		0xA5C1B71C1C903428ULL,
		0x3E988B429A10E657ULL,
		0x111F4D4A7B539CBBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7A8BE21AC71C15A4ULL,
		0x0407946A3F4CDCE1ULL,
		0x7CA7E77FC0EF3026ULL,
		0x13BFF09DDCE51355ULL,
		0xAAB21206A6FACC65ULL,
		0x4B836E3839206851ULL,
		0x7D3116853421CCAFULL,
		0x223E9A94F6A73976ULL
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
		0x58A67D3CED9A8C93ULL,
		0x42B7E768009D8703ULL,
		0x95C588FA42BAEF72ULL,
		0x74A8BFEED83F0C23ULL,
		0x5D5841B52ED191E6ULL,
		0x981AF730B910D37CULL,
		0xC4C301B3260BBE99ULL,
		0x37CE988AF6D0B406ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB14CFA79DB351926ULL,
		0x856FCED0013B0E06ULL,
		0x2B8B11F48575DEE4ULL,
		0xE9517FDDB07E1847ULL,
		0xBAB0836A5DA323CCULL,
		0x3035EE617221A6F8ULL,
		0x898603664C177D33ULL,
		0x6F9D3115EDA1680DULL
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
		0xA49973D816207A40ULL,
		0xE006FF1B287C7B48ULL,
		0xFB2733E97AAFDB78ULL,
		0xA7E44924C2BEEE9EULL,
		0x94C50454B8F14C2AULL,
		0xAC0886449EA8C531ULL,
		0x497B368A762754D7ULL,
		0x11EBDD905BB71688ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4932E7B02C40F480ULL,
		0xC00DFE3650F8F691ULL,
		0xF64E67D2F55FB6F1ULL,
		0x4FC89249857DDD3DULL,
		0x298A08A971E29855ULL,
		0x58110C893D518A63ULL,
		0x92F66D14EC4EA9AFULL,
		0x23D7BB20B76E2D10ULL
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
		0xE79D9CE642CC73BCULL,
		0x0833B3D7C8440668ULL,
		0x182A4A0080B96730ULL,
		0xE2D5B767656F9100ULL,
		0xE13DAF3F9B56AFD7ULL,
		0xFFA7D81CDA4E6FB4ULL,
		0xA6D031A35B951EA4ULL,
		0x1A8AAE3BCE293912ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCF3B39CC8598E778ULL,
		0x106767AF90880CD1ULL,
		0x305494010172CE60ULL,
		0xC5AB6ECECADF2200ULL,
		0xC27B5E7F36AD5FAFULL,
		0xFF4FB039B49CDF69ULL,
		0x4DA06346B72A3D49ULL,
		0x35155C779C527225ULL
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
		0xEF8837D9C483DAB3ULL,
		0x089F8C5E11E8D3FDULL,
		0x0317AC26A27A6B93ULL,
		0x60C45FEB6D6AA0E0ULL,
		0x5D2917FFE42A2BB6ULL,
		0xD35FD0D804A86BFBULL,
		0xC82BE46B088EC093ULL,
		0x07D269B6EBA5149AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDF106FB38907B566ULL,
		0x113F18BC23D1A7FBULL,
		0x062F584D44F4D726ULL,
		0xC188BFD6DAD541C0ULL,
		0xBA522FFFC854576CULL,
		0xA6BFA1B00950D7F6ULL,
		0x9057C8D6111D8127ULL,
		0x0FA4D36DD74A2935ULL
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
		0xA9BE25BFA0870B29ULL,
		0xE43E1DCB187D9782ULL,
		0x4B866B710B44E313ULL,
		0xAD94459216D0E003ULL,
		0x71949DD746F9FC83ULL,
		0x68AEAE8F95B814FFULL,
		0x49ACE83881509FBFULL,
		0x3B4416FAE99897C0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x537C4B7F410E1652ULL,
		0xC87C3B9630FB2F05ULL,
		0x970CD6E21689C627ULL,
		0x5B288B242DA1C006ULL,
		0xE3293BAE8DF3F907ULL,
		0xD15D5D1F2B7029FEULL,
		0x9359D07102A13F7EULL,
		0x76882DF5D3312F80ULL
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
		0x3096C2AA74346E05ULL,
		0x09F9619A805F4D04ULL,
		0x0AF8A52C0F31DA5BULL,
		0x6E68346B496D2E99ULL,
		0x3522F8DC29F22A26ULL,
		0x40308E663C5106C3ULL,
		0x51F59832FEFBDEA6ULL,
		0x20039558DDF8800DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x612D8554E868DC0AULL,
		0x13F2C33500BE9A08ULL,
		0x15F14A581E63B4B6ULL,
		0xDCD068D692DA5D32ULL,
		0x6A45F1B853E4544CULL,
		0x80611CCC78A20D86ULL,
		0xA3EB3065FDF7BD4CULL,
		0x40072AB1BBF1001AULL
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
		0x5CBA241797437B34ULL,
		0x5FB47B607EF49889ULL,
		0xBA956F526C6BEF0AULL,
		0xFF23192C6DA28F9FULL,
		0xA54EA6FAAC9F9235ULL,
		0x2CCB0A980F8CFC19ULL,
		0x140D30E320A46749ULL,
		0x30D33F859D386A12ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB974482F2E86F668ULL,
		0xBF68F6C0FDE93112ULL,
		0x752ADEA4D8D7DE14ULL,
		0xFE463258DB451F3FULL,
		0x4A9D4DF5593F246BULL,
		0x599615301F19F833ULL,
		0x281A61C64148CE92ULL,
		0x61A67F0B3A70D424ULL
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
		0xE5E5EA63D519B1FCULL,
		0xFDD00D8636A4D781ULL,
		0xE00AC98D5549AC48ULL,
		0x68498BCEE4BE0B9EULL,
		0x3E3D2C285C895051ULL,
		0xB2F0309B0C726D2EULL,
		0x40F4B11B86A6C1B6ULL,
		0x1B1CF8523F05AA5BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCBCBD4C7AA3363F8ULL,
		0xFBA01B0C6D49AF03ULL,
		0xC015931AAA935891ULL,
		0xD093179DC97C173DULL,
		0x7C7A5850B912A0A2ULL,
		0x65E0613618E4DA5CULL,
		0x81E962370D4D836DULL,
		0x3639F0A47E0B54B6ULL
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
		0xCA31C9B2B7F9DCE4ULL,
		0x392871FE4ADEE61FULL,
		0xB8D55FDD1155D3EDULL,
		0x3E2A616C7261A20FULL,
		0x9850AFC145A5FC9FULL,
		0x41EC685C8A95932AULL,
		0x023127D9CEF2767DULL,
		0x1C1545FE4F5BAAEDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x946393656FF3B9C8ULL,
		0x7250E3FC95BDCC3FULL,
		0x71AABFBA22ABA7DAULL,
		0x7C54C2D8E4C3441FULL,
		0x30A15F828B4BF93EULL,
		0x83D8D0B9152B2655ULL,
		0x04624FB39DE4ECFAULL,
		0x382A8BFC9EB755DAULL
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
		0x4D867CB6E7F44309ULL,
		0xBD1B50B91B64E981ULL,
		0xA301B83F970424C6ULL,
		0x9A52100A2BC47024ULL,
		0x2E6FF02EE9981E99ULL,
		0x532F55DB5764A8C7ULL,
		0x39CD448CD6C89490ULL,
		0x2EDACE14110E0EFFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9B0CF96DCFE88612ULL,
		0x7A36A17236C9D302ULL,
		0x4603707F2E08498DULL,
		0x34A420145788E049ULL,
		0x5CDFE05DD3303D33ULL,
		0xA65EABB6AEC9518EULL,
		0x739A8919AD912920ULL,
		0x5DB59C28221C1DFEULL
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
		0x46B12561296DA1ABULL,
		0xAAAEDC29B1412CB8ULL,
		0xE976E9443154F5F9ULL,
		0x899DD8C5097AF69BULL,
		0x7A6EAF0EE92C1389ULL,
		0x6D7D6A6A10673E17ULL,
		0xCDDC92643171C3E2ULL,
		0x22977AE11AA52DFFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8D624AC252DB4356ULL,
		0x555DB85362825970ULL,
		0xD2EDD28862A9EBF3ULL,
		0x133BB18A12F5ED37ULL,
		0xF4DD5E1DD2582713ULL,
		0xDAFAD4D420CE7C2EULL,
		0x9BB924C862E387C4ULL,
		0x452EF5C2354A5BFFULL
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
		0x00CE415F83B54A13ULL,
		0x50F50D0A5BF74401ULL,
		0x0600438249E6A6DCULL,
		0x14856AB16CB39204ULL,
		0x480B3CE15C1A3F86ULL,
		0x8076F07D689699D1ULL,
		0x9B80A70EAA908A1AULL,
		0x2DD9CF7576B466A6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x019C82BF076A9426ULL,
		0xA1EA1A14B7EE8802ULL,
		0x0C00870493CD4DB8ULL,
		0x290AD562D9672408ULL,
		0x901679C2B8347F0CULL,
		0x00EDE0FAD12D33A2ULL,
		0x37014E1D55211435ULL,
		0x5BB39EEAED68CD4DULL
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
		0xCC2622A6499DBDD7ULL,
		0x00BA179C19662E8BULL,
		0xE650112C126FBBB2ULL,
		0xBBA1C6AE4C798763ULL,
		0x767366485F770201ULL,
		0x0F0D2E4E1CD59FB0ULL,
		0xDFA22138EB5440A3ULL,
		0x206128A6CDCC2141ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x984C454C933B7BAEULL,
		0x01742F3832CC5D17ULL,
		0xCCA0225824DF7764ULL,
		0x77438D5C98F30EC7ULL,
		0xECE6CC90BEEE0403ULL,
		0x1E1A5C9C39AB3F60ULL,
		0xBF444271D6A88146ULL,
		0x40C2514D9B984283ULL
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
		0x89E0469A9EEE7390ULL,
		0xF79E8DF804B65DD6ULL,
		0xFA6CDF47DD2D9E90ULL,
		0x2B981B35CA860DF3ULL,
		0xC42378766A80C58EULL,
		0xE6285BEC1EA84BBCULL,
		0x961F280A4EA1404AULL,
		0x262DE191FB18EE72ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x13C08D353DDCE720ULL,
		0xEF3D1BF0096CBBADULL,
		0xF4D9BE8FBA5B3D21ULL,
		0x5730366B950C1BE7ULL,
		0x8846F0ECD5018B1CULL,
		0xCC50B7D83D509779ULL,
		0x2C3E50149D428095ULL,
		0x4C5BC323F631DCE5ULL
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
		0x2D268B3DBD738B48ULL,
		0xE8D3B4FA4F925316ULL,
		0x6E6974998794FF18ULL,
		0x971EE0ED55599736ULL,
		0x03928A5644D7DF71ULL,
		0xE05392C3C9E982BBULL,
		0x5ADDB736A2C4C8CFULL,
		0x265CC53F70089DB3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5A4D167B7AE71690ULL,
		0xD1A769F49F24A62CULL,
		0xDCD2E9330F29FE31ULL,
		0x2E3DC1DAAAB32E6CULL,
		0x072514AC89AFBEE3ULL,
		0xC0A7258793D30576ULL,
		0xB5BB6E6D4589919FULL,
		0x4CB98A7EE0113B66ULL
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
		0xC1D2C06BA665421DULL,
		0x89E4D0393FF002B0ULL,
		0x2265B0777505984CULL,
		0x22D9B5A801C49BD5ULL,
		0xBC83D60C1A6A305CULL,
		0x95D211250944ABC6ULL,
		0x84D3E3BD951475CCULL,
		0x388963DC023EF5C2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x83A580D74CCA843AULL,
		0x13C9A0727FE00561ULL,
		0x44CB60EEEA0B3099ULL,
		0x45B36B50038937AAULL,
		0x7907AC1834D460B8ULL,
		0x2BA4224A1289578DULL,
		0x09A7C77B2A28EB99ULL,
		0x7112C7B8047DEB85ULL
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
		0x13D87ADFD7869CF7ULL,
		0x4E8D762E64D219E7ULL,
		0x521659C12B8B8B37ULL,
		0x95B5B1179FB40F44ULL,
		0x1B3C7D45395C3861ULL,
		0x116D7E3A7A083A0CULL,
		0xBBC5340DC68BE002ULL,
		0x2CE1A36876D2A566ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x27B0F5BFAF0D39EEULL,
		0x9D1AEC5CC9A433CEULL,
		0xA42CB3825717166EULL,
		0x2B6B622F3F681E88ULL,
		0x3678FA8A72B870C3ULL,
		0x22DAFC74F4107418ULL,
		0x778A681B8D17C004ULL,
		0x59C346D0EDA54ACDULL
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
		0x892DB9002C2B797DULL,
		0x72A02291D73A00F7ULL,
		0x58432A447234D09AULL,
		0xF735E6D9F7115A6EULL,
		0xC7B343DFFC03D81BULL,
		0x9B58AD5EE286F6CBULL,
		0x472A8006AEFD716BULL,
		0x01F62F04E6BF4B68ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x125B72005856F2FAULL,
		0xE5404523AE7401EFULL,
		0xB0865488E469A134ULL,
		0xEE6BCDB3EE22B4DCULL,
		0x8F6687BFF807B037ULL,
		0x36B15ABDC50DED97ULL,
		0x8E55000D5DFAE2D7ULL,
		0x03EC5E09CD7E96D0ULL
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
		0x8B973453E0F4B3C7ULL,
		0x808417276EFEEE88ULL,
		0x41C2E559703FDDB3ULL,
		0xC70B708AB0C6B0FAULL,
		0xD40279A7D323A5AFULL,
		0x73A9A6F6466FE91AULL,
		0x2886BC7649116811ULL,
		0x186E3FB9359B85C5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x172E68A7C1E9678EULL,
		0x01082E4EDDFDDD11ULL,
		0x8385CAB2E07FBB67ULL,
		0x8E16E115618D61F4ULL,
		0xA804F34FA6474B5FULL,
		0xE7534DEC8CDFD235ULL,
		0x510D78EC9222D022ULL,
		0x30DC7F726B370B8AULL
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
		0x10204F9621957A81ULL,
		0xE564D15E8585DC93ULL,
		0x51540587AF2C17E2ULL,
		0xEC3AE33A001E7272ULL,
		0x378FEBCF395AB4BFULL,
		0xA0B9BC116F886810ULL,
		0x00D49DC6FD2E7A69ULL,
		0x25D5D4866E955EF6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x20409F2C432AF502ULL,
		0xCAC9A2BD0B0BB926ULL,
		0xA2A80B0F5E582FC5ULL,
		0xD875C674003CE4E4ULL,
		0x6F1FD79E72B5697FULL,
		0x41737822DF10D020ULL,
		0x01A93B8DFA5CF4D3ULL,
		0x4BABA90CDD2ABDECULL
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
		0x94D043F9DD161AD9ULL,
		0x40422AB3138D9660ULL,
		0x23B751560A647AD2ULL,
		0x27FA8B693926E404ULL,
		0xE5785DF699B2E1BBULL,
		0x9B52F96B6C3A9994ULL,
		0xBD0769D3F7F12A13ULL,
		0x22073F05CCA11D48ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x29A087F3BA2C35B2ULL,
		0x80845566271B2CC1ULL,
		0x476EA2AC14C8F5A4ULL,
		0x4FF516D2724DC808ULL,
		0xCAF0BBED3365C376ULL,
		0x36A5F2D6D8753329ULL,
		0x7A0ED3A7EFE25427ULL,
		0x440E7E0B99423A91ULL
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
		0xBF264111C3F7EDA4ULL,
		0x6E80B57575C2CA57ULL,
		0x3FA3598C698AD84EULL,
		0x134D44C6007C5B86ULL,
		0xB9BABDCB0E512A6CULL,
		0xB105FB8D81C8F351ULL,
		0xDCCE383BC464521BULL,
		0x03FCB200E63165C4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7E4C822387EFDB48ULL,
		0xDD016AEAEB8594AFULL,
		0x7F46B318D315B09CULL,
		0x269A898C00F8B70CULL,
		0x73757B961CA254D8ULL,
		0x620BF71B0391E6A3ULL,
		0xB99C707788C8A437ULL,
		0x07F96401CC62CB89ULL
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
		0xAC751FC63B49EB0CULL,
		0xB89E332057BFD3E5ULL,
		0x6FB69146ACB1B675ULL,
		0x402F327EFC581F27ULL,
		0xEF2171360161367AULL,
		0xF5CCC742A4B2D752ULL,
		0x409B625C63AA7C8CULL,
		0x3CBA6182E4AFC79CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x58EA3F8C7693D618ULL,
		0x713C6640AF7FA7CBULL,
		0xDF6D228D59636CEBULL,
		0x805E64FDF8B03E4EULL,
		0xDE42E26C02C26CF4ULL,
		0xEB998E854965AEA5ULL,
		0x8136C4B8C754F919ULL,
		0x7974C305C95F8F38ULL
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
		0xC1501C09A7418C59ULL,
		0x92DE45998543A942ULL,
		0x9D596198BE515138ULL,
		0xB3D2AD36198F7448ULL,
		0xC44DEC8E8A2F8D3EULL,
		0x759A9496FCB0F351ULL,
		0xEC610324E47F1BBDULL,
		0x09B3C717552FD921ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x82A038134E8318B2ULL,
		0x25BC8B330A875285ULL,
		0x3AB2C3317CA2A271ULL,
		0x67A55A6C331EE891ULL,
		0x889BD91D145F1A7DULL,
		0xEB35292DF961E6A3ULL,
		0xD8C20649C8FE377AULL,
		0x13678E2EAA5FB243ULL
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
		0x5820D61731098A6AULL,
		0xA2C0FEC2F088DFB6ULL,
		0xC95889164DA6B0F9ULL,
		0xAE90F683757D361FULL,
		0xD47E16B4B4A6ADDDULL,
		0x8AF1B326CA7F4179ULL,
		0xE8F6BD5CA4A2C023ULL,
		0x16BB96959BF44998ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB041AC2E621314D4ULL,
		0x4581FD85E111BF6CULL,
		0x92B1122C9B4D61F3ULL,
		0x5D21ED06EAFA6C3FULL,
		0xA8FC2D69694D5BBBULL,
		0x15E3664D94FE82F3ULL,
		0xD1ED7AB949458047ULL,
		0x2D772D2B37E89331ULL
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
		0x4CB29EF6A82963D6ULL,
		0xA00C7E1E5AC98FDBULL,
		0x609EFDAA0E68A8D3ULL,
		0x1E85E108E3C8D97EULL,
		0xB4A8A04D26D61CA8ULL,
		0x9457A8769F70F787ULL,
		0xFBD2D83822AEC8FBULL,
		0x3832255D548251BBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x99653DED5052C7ACULL,
		0x4018FC3CB5931FB6ULL,
		0xC13DFB541CD151A7ULL,
		0x3D0BC211C791B2FCULL,
		0x6951409A4DAC3950ULL,
		0x28AF50ED3EE1EF0FULL,
		0xF7A5B070455D91F7ULL,
		0x70644ABAA904A377ULL
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
		0xC6A00853BC85E445ULL,
		0x54F00CD3C4E8DCC7ULL,
		0xFE01768C57D7AA6BULL,
		0x110F9F80DF745BB8ULL,
		0x19AFDF7D59EC3D17ULL,
		0xC3FD4756F7D6F3A4ULL,
		0x3D848D4B961BF5EDULL,
		0x22C3AE063DF3859EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8D4010A7790BC88AULL,
		0xA9E019A789D1B98FULL,
		0xFC02ED18AFAF54D6ULL,
		0x221F3F01BEE8B771ULL,
		0x335FBEFAB3D87A2EULL,
		0x87FA8EADEFADE748ULL,
		0x7B091A972C37EBDBULL,
		0x45875C0C7BE70B3CULL
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
		0xDB57171B256C9742ULL,
		0x820EDADCD8BFE167ULL,
		0x0F55E0C3ED216D7BULL,
		0x68102C08C85172CAULL,
		0xD861F27C23E892A2ULL,
		0x1DC730F3C04EB6B1ULL,
		0xA2B99FC140257031ULL,
		0x185A92659EC49DF4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB6AE2E364AD92E84ULL,
		0x041DB5B9B17FC2CFULL,
		0x1EABC187DA42DAF7ULL,
		0xD020581190A2E594ULL,
		0xB0C3E4F847D12544ULL,
		0x3B8E61E7809D6D63ULL,
		0x45733F82804AE062ULL,
		0x30B524CB3D893BE9ULL
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
		0x8863D6DD16C7085EULL,
		0x2DB7FFD3B2C8E604ULL,
		0xCB06E9468529B145ULL,
		0xF78F650383A8C938ULL,
		0x185E815496E5B80DULL,
		0xAA8CECF4D34AF1D9ULL,
		0x97392EF19DF5F7F9ULL,
		0x2450431B2909699FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x10C7ADBA2D8E10BCULL,
		0x5B6FFFA76591CC09ULL,
		0x960DD28D0A53628AULL,
		0xEF1ECA0707519271ULL,
		0x30BD02A92DCB701BULL,
		0x5519D9E9A695E3B2ULL,
		0x2E725DE33BEBEFF3ULL,
		0x48A086365212D33FULL
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
		0x1017915C52C6E81FULL,
		0x0C0BF218DD872EE4ULL,
		0xD8125E783A05ED08ULL,
		0x0AAF0E0A82F69B93ULL,
		0x43A740E024433B90ULL,
		0x4FBC0A6DCFD5417FULL,
		0x99F0ECDF9129750FULL,
		0x3280D249FA3CD891ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x202F22B8A58DD03EULL,
		0x1817E431BB0E5DC8ULL,
		0xB024BCF0740BDA10ULL,
		0x155E1C1505ED3727ULL,
		0x874E81C048867720ULL,
		0x9F7814DB9FAA82FEULL,
		0x33E1D9BF2252EA1EULL,
		0x6501A493F479B123ULL
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
		0x427E2BFA242CF371ULL,
		0xE0D94BCBCBF43BDCULL,
		0x570F2A1DE1625254ULL,
		0xEA8F5A4FEC15DD85ULL,
		0xCC87BDBED0B84D3DULL,
		0x4C3CF53D597AD32CULL,
		0xC91500EC09EE5240ULL,
		0x032E169D887AEEEEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x84FC57F44859E6E2ULL,
		0xC1B2979797E877B8ULL,
		0xAE1E543BC2C4A4A9ULL,
		0xD51EB49FD82BBB0AULL,
		0x990F7B7DA1709A7BULL,
		0x9879EA7AB2F5A659ULL,
		0x922A01D813DCA480ULL,
		0x065C2D3B10F5DDDDULL
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
		0xFDC3D97003991563ULL,
		0xF07C5E9CF3E8E6E8ULL,
		0x5282382B923C26A2ULL,
		0x01850540F97BD3FFULL,
		0xF3A620BF3E850FF0ULL,
		0x9B10956355B105FEULL,
		0x21E5A436FD268875ULL,
		0x1007726EDBD7AFB6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFB87B2E007322AC6ULL,
		0xE0F8BD39E7D1CDD1ULL,
		0xA504705724784D45ULL,
		0x030A0A81F2F7A7FEULL,
		0xE74C417E7D0A1FE0ULL,
		0x36212AC6AB620BFDULL,
		0x43CB486DFA4D10EBULL,
		0x200EE4DDB7AF5F6CULL
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
		0x4139886FBFD914E3ULL,
		0x410D037B8E50B73AULL,
		0xE745ED0670E7AC04ULL,
		0x00EA43409A86C345ULL,
		0x70DDCF9B5C7239BEULL,
		0xCE9986D3925401D5ULL,
		0x5319179475B40E22ULL,
		0x218E71B020C3C2AFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x827310DF7FB229C6ULL,
		0x821A06F71CA16E74ULL,
		0xCE8BDA0CE1CF5808ULL,
		0x01D48681350D868BULL,
		0xE1BB9F36B8E4737CULL,
		0x9D330DA724A803AAULL,
		0xA6322F28EB681C45ULL,
		0x431CE3604187855EULL
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
		0x04700D9BAB6172CFULL,
		0x8CEF62966DFC5840ULL,
		0xD40C5970B88BF903ULL,
		0x09EF8059DA3BD1A1ULL,
		0xC7C5364EC4EC9F40ULL,
		0xB1C292C2D8CC2718ULL,
		0xECFAE17671892CECULL,
		0x1E7CB0C64EC9AEBBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x08E01B3756C2E59EULL,
		0x19DEC52CDBF8B080ULL,
		0xA818B2E17117F207ULL,
		0x13DF00B3B477A343ULL,
		0x8F8A6C9D89D93E80ULL,
		0x63852585B1984E31ULL,
		0xD9F5C2ECE31259D9ULL,
		0x3CF9618C9D935D77ULL
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
		0xE29CEB65B30FF9CFULL,
		0xAE8C2E225FD4D641ULL,
		0xFC69F4C2564C6531ULL,
		0xE2084307DDF63FEAULL,
		0x00C5EEEA16994FAFULL,
		0x823C2D874F5FF4CAULL,
		0x7F9B3908E5F68604ULL,
		0x2599CBB527A2C4ADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC539D6CB661FF39EULL,
		0x5D185C44BFA9AC83ULL,
		0xF8D3E984AC98CA63ULL,
		0xC410860FBBEC7FD5ULL,
		0x018BDDD42D329F5FULL,
		0x04785B0E9EBFE994ULL,
		0xFF367211CBED0C09ULL,
		0x4B33976A4F45895AULL
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
		0x1C5544D47722727CULL,
		0x145B23E11475F732ULL,
		0xC99E562834CDCC16ULL,
		0x998C5F4DDD637AC6ULL,
		0x62E9BFB27FAA199CULL,
		0x05B9958CB8A42608ULL,
		0x268F6C0D183E5DDEULL,
		0x08BA08C2B15E9C38ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x38AA89A8EE44E4F8ULL,
		0x28B647C228EBEE64ULL,
		0x933CAC50699B982CULL,
		0x3318BE9BBAC6F58DULL,
		0xC5D37F64FF543339ULL,
		0x0B732B1971484C10ULL,
		0x4D1ED81A307CBBBCULL,
		0x1174118562BD3870ULL
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
		0xBCEAAC2C131A2A5AULL,
		0x5147DF04BC2F53EEULL,
		0x42E5F2A91E0F77D8ULL,
		0x60537D3E4CDA928BULL,
		0x03D53D6821D44BD6ULL,
		0x2E898AF608686F1EULL,
		0x24F1EC937FDD8652ULL,
		0x36FAF41A2D0AF9BDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x79D55858263454B4ULL,
		0xA28FBE09785EA7DDULL,
		0x85CBE5523C1EEFB0ULL,
		0xC0A6FA7C99B52516ULL,
		0x07AA7AD043A897ACULL,
		0x5D1315EC10D0DE3CULL,
		0x49E3D926FFBB0CA4ULL,
		0x6DF5E8345A15F37AULL
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
		0x203B006C6B8AD110ULL,
		0x8423C69D34D6E921ULL,
		0x048C0F851DF88805ULL,
		0x841C8F09D58491FAULL,
		0xFD87E60B930E3B73ULL,
		0x9B08523776AE7CF0ULL,
		0xE1FBF9645F6D0DA4ULL,
		0x1BAEF247C78E4572ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x407600D8D715A220ULL,
		0x08478D3A69ADD242ULL,
		0x09181F0A3BF1100BULL,
		0x08391E13AB0923F4ULL,
		0xFB0FCC17261C76E7ULL,
		0x3610A46EED5CF9E1ULL,
		0xC3F7F2C8BEDA1B49ULL,
		0x375DE48F8F1C8AE5ULL
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
		0xCBDD5B58FBF4FCEFULL,
		0xA74CAB351CCE2F8DULL,
		0xE3C35AB67974CDDEULL,
		0x88BEF4C09916E422ULL,
		0xD03C47C94E7CD6FCULL,
		0x73FAE8A3E45B3207ULL,
		0x68279118E9B4B7FDULL,
		0x08BAB9C24D5DC89EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x97BAB6B1F7E9F9DEULL,
		0x4E99566A399C5F1BULL,
		0xC786B56CF2E99BBDULL,
		0x117DE981322DC845ULL,
		0xA0788F929CF9ADF9ULL,
		0xE7F5D147C8B6640FULL,
		0xD04F2231D3696FFAULL,
		0x117573849ABB913CULL
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
		0xBE9BCA51BE2AF821ULL,
		0xAFF368CE5C24F146ULL,
		0x87CAF9C4EF1A2019ULL,
		0xC06642F9B2DECF81ULL,
		0xBFE929A32ED508C0ULL,
		0x60B867372275CB2FULL,
		0xBFD902BDE2B6F802ULL,
		0x03E723142FB400B4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7D3794A37C55F042ULL,
		0x5FE6D19CB849E28DULL,
		0x0F95F389DE344033ULL,
		0x80CC85F365BD9F03ULL,
		0x7FD253465DAA1181ULL,
		0xC170CE6E44EB965FULL,
		0x7FB2057BC56DF004ULL,
		0x07CE46285F680169ULL
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
		0xE7F9300E61F16E4FULL,
		0x2C0E764EA23FA2C7ULL,
		0x7519B3E3E3261AEBULL,
		0x3B6DD087EBA8D362ULL,
		0x1D741EB50772A122ULL,
		0x63B717E7DAF77F14ULL,
		0xEB0B98A8B9A75015ULL,
		0x274D29D80CD28F88ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCFF2601CC3E2DC9EULL,
		0x581CEC9D447F458FULL,
		0xEA3367C7C64C35D6ULL,
		0x76DBA10FD751A6C4ULL,
		0x3AE83D6A0EE54244ULL,
		0xC76E2FCFB5EEFE28ULL,
		0xD6173151734EA02AULL,
		0x4E9A53B019A51F11ULL
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
		0xCFCD9F6D9FEDC258ULL,
		0x54656D0F3AD31840ULL,
		0x8D69D1B63F0FDDC1ULL,
		0x9068762867A58596ULL,
		0xB92AFE8E96E75117ULL,
		0xC6301FB476568523ULL,
		0x33642B3724C931D4ULL,
		0x0CC9422C12BC8E97ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9F9B3EDB3FDB84B0ULL,
		0xA8CADA1E75A63081ULL,
		0x1AD3A36C7E1FBB82ULL,
		0x20D0EC50CF4B0B2DULL,
		0x7255FD1D2DCEA22FULL,
		0x8C603F68ECAD0A47ULL,
		0x66C8566E499263A9ULL,
		0x1992845825791D2EULL
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
		0x5CFE5230932BB978ULL,
		0xE07375356A93B017ULL,
		0x96340B2FA5BDC652ULL,
		0x1816671DE7B19A3FULL,
		0x3E55122637BF5B72ULL,
		0xAFB92E4BD4C9BE15ULL,
		0xA2C646439C7CA665ULL,
		0x194F8613A097ABBFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB9FCA461265772F0ULL,
		0xC0E6EA6AD527602EULL,
		0x2C68165F4B7B8CA5ULL,
		0x302CCE3BCF63347FULL,
		0x7CAA244C6F7EB6E4ULL,
		0x5F725C97A9937C2AULL,
		0x458C8C8738F94CCBULL,
		0x329F0C27412F577FULL
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
		0x39A53573BB505603ULL,
		0xA62CD544CA78EC88ULL,
		0x902DD7DC5972DBCDULL,
		0x09C1AF6EA42127E0ULL,
		0xF60EDA252F139AA8ULL,
		0x84A9149F5FF6BD47ULL,
		0xC24A7D4B311715A5ULL,
		0x344AC72248CAC72EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x734A6AE776A0AC06ULL,
		0x4C59AA8994F1D910ULL,
		0x205BAFB8B2E5B79BULL,
		0x13835EDD48424FC1ULL,
		0xEC1DB44A5E273550ULL,
		0x0952293EBFED7A8FULL,
		0x8494FA96622E2B4BULL,
		0x68958E4491958E5DULL
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
		0x2C4AEA0CBEFF56D2ULL,
		0xB87CA8277EDEACE3ULL,
		0x95A757E02F5E07FBULL,
		0xDCC88CDAF4CB0577ULL,
		0x5D5220FF1F8CF2BEULL,
		0x38EE16EDBC6ACD0AULL,
		0x83FAC2F50399ACD7ULL,
		0x285ECED7C12C41C0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5895D4197DFEADA4ULL,
		0x70F9504EFDBD59C6ULL,
		0x2B4EAFC05EBC0FF7ULL,
		0xB99119B5E9960AEFULL,
		0xBAA441FE3F19E57DULL,
		0x71DC2DDB78D59A14ULL,
		0x07F585EA073359AEULL,
		0x50BD9DAF82588381ULL
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
		0xFCB2280FB443BF2CULL,
		0x81871EA554CEAE27ULL,
		0x1BFC8B5689F43946ULL,
		0x94026A6D23CB154AULL,
		0xDBF3D82021AF2B74ULL,
		0x6252A23CF210D1F0ULL,
		0xDDAD811EB00F07ECULL,
		0x3E986C8C64ADDCAEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF964501F68877E58ULL,
		0x030E3D4AA99D5C4FULL,
		0x37F916AD13E8728DULL,
		0x2804D4DA47962A94ULL,
		0xB7E7B040435E56E9ULL,
		0xC4A54479E421A3E1ULL,
		0xBB5B023D601E0FD8ULL,
		0x7D30D918C95BB95DULL
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
		0xAF2802D4C9FCE674ULL,
		0xAB1B89DE3889F266ULL,
		0x61A399DE5CEDB61DULL,
		0x5E70AD91DA34985BULL,
		0xD569EB27813A2C8AULL,
		0x3F53A1F07256AD75ULL,
		0x4D15550151590BA0ULL,
		0x1FEAD978B95F7389ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5E5005A993F9CCE8ULL,
		0x563713BC7113E4CDULL,
		0xC34733BCB9DB6C3BULL,
		0xBCE15B23B46930B6ULL,
		0xAAD3D64F02745914ULL,
		0x7EA743E0E4AD5AEBULL,
		0x9A2AAA02A2B21740ULL,
		0x3FD5B2F172BEE712ULL
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
		0x9F2CBF00B2E14ABCULL,
		0x15CFDAB8F7828875ULL,
		0x998BBFD6283AC67DULL,
		0xBE1673DFD6117ADAULL,
		0xA1305664372B7013ULL,
		0xA5B220FE1DCD45CBULL,
		0x3D087B7DDE5F038BULL,
		0x3BB0F783D80CA18FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3E597E0165C29578ULL,
		0x2B9FB571EF0510EBULL,
		0x33177FAC50758CFAULL,
		0x7C2CE7BFAC22F5B5ULL,
		0x4260ACC86E56E027ULL,
		0x4B6441FC3B9A8B97ULL,
		0x7A10F6FBBCBE0717ULL,
		0x7761EF07B019431EULL
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
		0x604586B4965148BEULL,
		0x634379D67D17F557ULL,
		0x5E01FE1EE8513C69ULL,
		0x71E56364EE5000DAULL,
		0x4F2B005253C96FB0ULL,
		0x3F028891BE03B08DULL,
		0x506FDB58875C77B3ULL,
		0x0A72726EA4B67A68ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC08B0D692CA2917CULL,
		0xC686F3ACFA2FEAAEULL,
		0xBC03FC3DD0A278D2ULL,
		0xE3CAC6C9DCA001B4ULL,
		0x9E5600A4A792DF60ULL,
		0x7E0511237C07611AULL,
		0xA0DFB6B10EB8EF66ULL,
		0x14E4E4DD496CF4D0ULL
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
		0x743A683FCBE29F30ULL,
		0x681CB52CB46FA8DFULL,
		0x7ACE52F7884A6C1FULL,
		0x3221A9CC1AD7F593ULL,
		0x8E9BF2BFA1B384E0ULL,
		0xA9CA73124637BD79ULL,
		0x2D26160A7D7B8C1FULL,
		0x1620F1435A6ED779ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE874D07F97C53E60ULL,
		0xD0396A5968DF51BEULL,
		0xF59CA5EF1094D83EULL,
		0x6443539835AFEB26ULL,
		0x1D37E57F436709C0ULL,
		0x5394E6248C6F7AF3ULL,
		0x5A4C2C14FAF7183FULL,
		0x2C41E286B4DDAEF2ULL
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
		0x46083593B0E6E568ULL,
		0x40FFB8F8465A0E37ULL,
		0xD64B10AA6FBAB979ULL,
		0xAFB06FF7B12B34D7ULL,
		0xFB9356EA8D9D9B8FULL,
		0xD756DEE05747D582ULL,
		0xC878025FCBDBE355ULL,
		0x394346CF592CCB50ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8C106B2761CDCAD0ULL,
		0x81FF71F08CB41C6EULL,
		0xAC962154DF7572F2ULL,
		0x5F60DFEF625669AFULL,
		0xF726ADD51B3B371FULL,
		0xAEADBDC0AE8FAB05ULL,
		0x90F004BF97B7C6ABULL,
		0x72868D9EB25996A1ULL
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
		0x19D801297603B938ULL,
		0x6798B08911D550F7ULL,
		0x0BD7119F21BAED19ULL,
		0x5AF66628361FDAF8ULL,
		0x19ED6FE2308D1F26ULL,
		0xE4F30637822E8C4AULL,
		0xBF939E6FB4751E56ULL,
		0x24B48F07C7CE183AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x33B00252EC077270ULL,
		0xCF31611223AAA1EEULL,
		0x17AE233E4375DA32ULL,
		0xB5ECCC506C3FB5F0ULL,
		0x33DADFC4611A3E4CULL,
		0xC9E60C6F045D1894ULL,
		0x7F273CDF68EA3CADULL,
		0x49691E0F8F9C3075ULL
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
		0x30BC9F4A7363D733ULL,
		0x5EB380DA65166370ULL,
		0x63DCAE2982EE4CFAULL,
		0x42D8306B48E4CCF6ULL,
		0xFD8A0BC743925ED4ULL,
		0x3FD3CEAFEFF3C5A0ULL,
		0x274D92D156077488ULL,
		0x24CDEAC7F909022BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x61793E94E6C7AE66ULL,
		0xBD6701B4CA2CC6E0ULL,
		0xC7B95C5305DC99F4ULL,
		0x85B060D691C999ECULL,
		0xFB14178E8724BDA8ULL,
		0x7FA79D5FDFE78B41ULL,
		0x4E9B25A2AC0EE910ULL,
		0x499BD58FF2120456ULL
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
		0xDCEF25423311DAEFULL,
		0x886852C624CFC52CULL,
		0xD037DE3B1C72E0E3ULL,
		0x41CAFD8F508C7D04ULL,
		0x68B5E47297DD9418ULL,
		0x81559BD6F3808EABULL,
		0x687DD53583106354ULL,
		0x0CCC337A5A362DCDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB9DE4A846623B5DEULL,
		0x10D0A58C499F8A59ULL,
		0xA06FBC7638E5C1C7ULL,
		0x8395FB1EA118FA09ULL,
		0xD16BC8E52FBB2830ULL,
		0x02AB37ADE7011D56ULL,
		0xD0FBAA6B0620C6A9ULL,
		0x199866F4B46C5B9AULL
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
		0x884F7EEC96DD5533ULL,
		0x85D521C9F2C90F6FULL,
		0xFC5144C7090F3B0DULL,
		0xEAE232798305C683ULL,
		0x4545E9D2AD7CE525ULL,
		0x4BC09A0A2510F970ULL,
		0x15D69273301A21A3ULL,
		0x208526AE20E1800FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x109EFDD92DBAAA66ULL,
		0x0BAA4393E5921EDFULL,
		0xF8A2898E121E761BULL,
		0xD5C464F3060B8D07ULL,
		0x8A8BD3A55AF9CA4BULL,
		0x978134144A21F2E0ULL,
		0x2BAD24E660344346ULL,
		0x410A4D5C41C3001EULL
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
		0x4EC05EEC127A64E9ULL,
		0x72AD6CA2144376BAULL,
		0x54B4CA8420C20645ULL,
		0x807B31CE94D38B9FULL,
		0x3B4774206D95B4CCULL,
		0x6DB53A5A60431A1BULL,
		0xF276198B5568A0A9ULL,
		0x3723979D40DCCBA6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9D80BDD824F4C9D2ULL,
		0xE55AD9442886ED74ULL,
		0xA969950841840C8AULL,
		0x00F6639D29A7173EULL,
		0x768EE840DB2B6999ULL,
		0xDB6A74B4C0863436ULL,
		0xE4EC3316AAD14152ULL,
		0x6E472F3A81B9974DULL
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
		0x6E2232255E808D2BULL,
		0x7856C06C446B263EULL,
		0x84EC8594E150F671ULL,
		0x5ACFBB8A514124BAULL,
		0xF79734CA11BE6A5DULL,
		0xC0792BA0093F93DAULL,
		0x666F3A1F5ECEE6AFULL,
		0x1FF1DCAFB191DBFBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDC44644ABD011A56ULL,
		0xF0AD80D888D64C7CULL,
		0x09D90B29C2A1ECE2ULL,
		0xB59F7714A2824975ULL,
		0xEF2E6994237CD4BAULL,
		0x80F25740127F27B5ULL,
		0xCCDE743EBD9DCD5FULL,
		0x3FE3B95F6323B7F6ULL
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
		0xBA05BA400E6F1EFBULL,
		0x5B5D36974A3D498CULL,
		0xD9D9B6C570E435F7ULL,
		0x668DB008FE3933E5ULL,
		0x9B84D409834829DFULL,
		0xDA942FA384AD8172ULL,
		0x2E6EB8F9992F7A4FULL,
		0x0698D29085A29251ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x740B74801CDE3DF6ULL,
		0xB6BA6D2E947A9319ULL,
		0xB3B36D8AE1C86BEEULL,
		0xCD1B6011FC7267CBULL,
		0x3709A813069053BEULL,
		0xB5285F47095B02E5ULL,
		0x5CDD71F3325EF49FULL,
		0x0D31A5210B4524A2ULL
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
		0xA84E7D76683D1799ULL,
		0xE27B77A7D5659D12ULL,
		0xD5CB5715299C9710ULL,
		0xF579744625413B3BULL,
		0xDDFC9F0A92D9AC29ULL,
		0x54CB8A7E737E95A1ULL,
		0x0AFBE38EB776084FULL,
		0x25AB7E95FB6319E1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x509CFAECD07A2F32ULL,
		0xC4F6EF4FAACB3A25ULL,
		0xAB96AE2A53392E21ULL,
		0xEAF2E88C4A827677ULL,
		0xBBF93E1525B35853ULL,
		0xA99714FCE6FD2B43ULL,
		0x15F7C71D6EEC109EULL,
		0x4B56FD2BF6C633C2ULL
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
		0x59AAAE6062340DE9ULL,
		0xCCAC78BB48B814BFULL,
		0x1DFEF80D70003E77ULL,
		0x2BF027ECEC28940CULL,
		0x7A95B399F060ABE5ULL,
		0x49A13609AB7447AFULL,
		0xADDD9C7A3803B25CULL,
		0x21B1517E4EB517C5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB3555CC0C4681BD2ULL,
		0x9958F1769170297EULL,
		0x3BFDF01AE0007CEFULL,
		0x57E04FD9D8512818ULL,
		0xF52B6733E0C157CAULL,
		0x93426C1356E88F5EULL,
		0x5BBB38F4700764B8ULL,
		0x4362A2FC9D6A2F8BULL
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
		0xFAADF97D4190A57DULL,
		0xE888863FA0B933E5ULL,
		0x4B818728E860A134ULL,
		0x016C9CC8A3B80EBCULL,
		0xBCB080AB0BFF83DBULL,
		0x30CFA4BF9264D13BULL,
		0xA1C3F2FDCC84AAD8ULL,
		0x2E6E2DBD7ABA7D3DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF55BF2FA83214AFAULL,
		0xD1110C7F417267CBULL,
		0x97030E51D0C14269ULL,
		0x02D9399147701D78ULL,
		0x7961015617FF07B6ULL,
		0x619F497F24C9A277ULL,
		0x4387E5FB990955B0ULL,
		0x5CDC5B7AF574FA7BULL
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
		0x4070AE4721DC15D7ULL,
		0x0887DEC9C73F2487ULL,
		0x97B2AC2145AA117DULL,
		0x0E5D893CC8DA94CEULL,
		0xE828C2A2A27C29D4ULL,
		0x522742E37241C4DBULL,
		0x5DD2721E14A1DEBDULL,
		0x06981D52EF4F1650ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x80E15C8E43B82BAEULL,
		0x110FBD938E7E490EULL,
		0x2F6558428B5422FAULL,
		0x1CBB127991B5299DULL,
		0xD051854544F853A8ULL,
		0xA44E85C6E48389B7ULL,
		0xBBA4E43C2943BD7AULL,
		0x0D303AA5DE9E2CA0ULL
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
		0x4D434455B128AE52ULL,
		0xEFCD15C6B1EA6599ULL,
		0x1587ABEF31800022ULL,
		0x2D5E42F9567244FBULL,
		0x882742394F3051DCULL,
		0xAC0EE990F4BE7ACAULL,
		0x77F1A90DA31CAA41ULL,
		0x06BE26F3FC53BEBAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9A8688AB62515CA4ULL,
		0xDF9A2B8D63D4CB32ULL,
		0x2B0F57DE63000045ULL,
		0x5ABC85F2ACE489F6ULL,
		0x104E84729E60A3B8ULL,
		0x581DD321E97CF595ULL,
		0xEFE3521B46395483ULL,
		0x0D7C4DE7F8A77D74ULL
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
		0x8A68B05C518D4BA6ULL,
		0xAC3266458C424228ULL,
		0xBCDB6F5221BC70FEULL,
		0x7513FB7A8E3F8BF7ULL,
		0x88011155428ED0BBULL,
		0x0B08BA0B92052D88ULL,
		0x575922998158CABFULL,
		0x215018FF990E4015ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x14D160B8A31A974CULL,
		0x5864CC8B18848451ULL,
		0x79B6DEA44378E1FDULL,
		0xEA27F6F51C7F17EFULL,
		0x100222AA851DA176ULL,
		0x16117417240A5B11ULL,
		0xAEB2453302B1957EULL,
		0x42A031FF321C802AULL
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
		0x37AFADB471A93344ULL,
		0xBB7F1723E417312CULL,
		0x48BF1C4898D631A2ULL,
		0x4C44DE4845AD42B8ULL,
		0x37F7498DE16C2210ULL,
		0xC57EFD9F21F6275EULL,
		0x3EF2E96297F30F94ULL,
		0x354F63456E96023BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6F5F5B68E3526688ULL,
		0x76FE2E47C82E6258ULL,
		0x917E389131AC6345ULL,
		0x9889BC908B5A8570ULL,
		0x6FEE931BC2D84420ULL,
		0x8AFDFB3E43EC4EBCULL,
		0x7DE5D2C52FE61F29ULL,
		0x6A9EC68ADD2C0476ULL
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
		0x094FF4F6A7D98CC3ULL,
		0x8AA0E916671E6E8DULL,
		0x06F38F05E85C0D87ULL,
		0xBC4F86D22D42EA57ULL,
		0x79C54F2FCF685CF2ULL,
		0x9EFF3106FBA768A1ULL,
		0xAD92AF1D4547315DULL,
		0x32D8AFE50465B277ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x129FE9ED4FB31986ULL,
		0x1541D22CCE3CDD1AULL,
		0x0DE71E0BD0B81B0FULL,
		0x789F0DA45A85D4AEULL,
		0xF38A9E5F9ED0B9E5ULL,
		0x3DFE620DF74ED142ULL,
		0x5B255E3A8A8E62BBULL,
		0x65B15FCA08CB64EFULL
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
		0xD729A7A776C94D5EULL,
		0x6D208233003A504BULL,
		0x9E53C84EA2FCDA98ULL,
		0x093C372225BA841EULL,
		0x2D13BE5AFB42A675ULL,
		0x3B94FCC963CBC36EULL,
		0x0835457AB1306FD7ULL,
		0x1CA1E8A788004F35ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAE534F4EED929ABCULL,
		0xDA4104660074A097ULL,
		0x3CA7909D45F9B530ULL,
		0x12786E444B75083DULL,
		0x5A277CB5F6854CEAULL,
		0x7729F992C79786DCULL,
		0x106A8AF56260DFAEULL,
		0x3943D14F10009E6AULL
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
		0x0DB5A2964B7AB7B7ULL,
		0x0E63E93DF1BEB12AULL,
		0xC05DFC61A120C37BULL,
		0x0B88938EFD0DDBEFULL,
		0xDEC15CD2A3E0F1AFULL,
		0x0E2E7B26737E7280ULL,
		0x423146690176165DULL,
		0x124BF4D1AB7DFD4BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1B6B452C96F56F6EULL,
		0x1CC7D27BE37D6254ULL,
		0x80BBF8C3424186F6ULL,
		0x1711271DFA1BB7DFULL,
		0xBD82B9A547C1E35EULL,
		0x1C5CF64CE6FCE501ULL,
		0x84628CD202EC2CBAULL,
		0x2497E9A356FBFA96ULL
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
		0xFCC91CB9F655991AULL,
		0x63C7D9F18AC15F99ULL,
		0x0A51255E4A46B219ULL,
		0xD59EB569AAB77148ULL,
		0x3A8F712431952ABBULL,
		0xE776FB0C79467AD1ULL,
		0xC073B6A75AE783ABULL,
		0x22796ECAC32A6C63ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF9923973ECAB3234ULL,
		0xC78FB3E31582BF33ULL,
		0x14A24ABC948D6432ULL,
		0xAB3D6AD3556EE290ULL,
		0x751EE248632A5577ULL,
		0xCEEDF618F28CF5A2ULL,
		0x80E76D4EB5CF0757ULL,
		0x44F2DD958654D8C7ULL
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
		0x099633CB3CE52984ULL,
		0x2E585FE7B9D2A5BDULL,
		0x55D660D656B8B29DULL,
		0x37D85BCA39DC2241ULL,
		0x2C054EDA1FA7CF86ULL,
		0xA9AE811F3D11610DULL,
		0x856FAC6143E5FB1CULL,
		0x2823559451AF6D31ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x132C679679CA5308ULL,
		0x5CB0BFCF73A54B7AULL,
		0xABACC1ACAD71653AULL,
		0x6FB0B79473B84482ULL,
		0x580A9DB43F4F9F0CULL,
		0x535D023E7A22C21AULL,
		0x0ADF58C287CBF639ULL,
		0x5046AB28A35EDA63ULL
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
		0xBA5E9C8F3AB80DF1ULL,
		0xA9104DD045579CC9ULL,
		0x414499E5611EF226ULL,
		0xCF999CE26113F9A4ULL,
		0xD57A7C340F676994ULL,
		0x858859CE6B0EA7E9ULL,
		0xE4B9C193088939A3ULL,
		0x3028BB2DFBF75194ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x74BD391E75701BE2ULL,
		0x52209BA08AAF3993ULL,
		0x828933CAC23DE44DULL,
		0x9F3339C4C227F348ULL,
		0xAAF4F8681ECED329ULL,
		0x0B10B39CD61D4FD3ULL,
		0xC973832611127347ULL,
		0x6051765BF7EEA329ULL
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
		0x33E898B245C9D6A6ULL,
		0x28A1E2163F4DA701ULL,
		0x9A68A322EA6D84B8ULL,
		0xAFB0E8BA4E639BACULL,
		0x788C85A113BE048AULL,
		0xAD548F761B6BDDC2ULL,
		0x821360521A4C2152ULL,
		0x0CD3C315D4767B35ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x67D131648B93AD4CULL,
		0x5143C42C7E9B4E02ULL,
		0x34D14645D4DB0970ULL,
		0x5F61D1749CC73759ULL,
		0xF1190B42277C0915ULL,
		0x5AA91EEC36D7BB84ULL,
		0x0426C0A4349842A5ULL,
		0x19A7862BA8ECF66BULL
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
		0x5519EA20293DBEAEULL,
		0xFC4F641CD23A448AULL,
		0x3B06E994100E599FULL,
		0x62033B4389F3719DULL,
		0x7F774DE3E8D34305ULL,
		0x89FBC66F58D9F9BEULL,
		0x92B7C65E2333DD9DULL,
		0x27902A618581899EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAA33D440527B7D5CULL,
		0xF89EC839A4748914ULL,
		0x760DD328201CB33FULL,
		0xC406768713E6E33AULL,
		0xFEEE9BC7D1A6860AULL,
		0x13F78CDEB1B3F37CULL,
		0x256F8CBC4667BB3BULL,
		0x4F2054C30B03133DULL
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
		0xE18C1280286A2702ULL,
		0x92722129B6C3B0CFULL,
		0x20AC0F31E507C5EEULL,
		0xED469C622E0CE9D8ULL,
		0xA7221000CEC22F6FULL,
		0x4FBA72A6B77B9303ULL,
		0xC1064AD1EA3EE80DULL,
		0x1A8D7F02FB11CE03ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC318250050D44E04ULL,
		0x24E442536D87619FULL,
		0x41581E63CA0F8BDDULL,
		0xDA8D38C45C19D3B0ULL,
		0x4E4420019D845EDFULL,
		0x9F74E54D6EF72607ULL,
		0x820C95A3D47DD01AULL,
		0x351AFE05F6239C07ULL
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
		0x8CEEF78424509AF0ULL,
		0xBED7137EF09A039EULL,
		0x86702C51B23C3DF7ULL,
		0x9D78A2C9E5822523ULL,
		0xBDF0257EFF4AECD7ULL,
		0x53C13935677FA2F4ULL,
		0xD83AA25B3981AFF9ULL,
		0x266FA3768ADDD322ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x19DDEF0848A135E0ULL,
		0x7DAE26FDE134073DULL,
		0x0CE058A364787BEFULL,
		0x3AF14593CB044A47ULL,
		0x7BE04AFDFE95D9AFULL,
		0xA782726ACEFF45E9ULL,
		0xB07544B673035FF2ULL,
		0x4CDF46ED15BBA645ULL
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
		0x5C8106C871C417BEULL,
		0xC68875A60123DD72ULL,
		0x3840C38F54A98B30ULL,
		0x9CA79B66A9E1D9CCULL,
		0xA7F5F8877B7F4C9CULL,
		0xFF99BB3F3534124CULL,
		0x6119A4B23F969913ULL,
		0x13A8B451A316A966ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB9020D90E3882F7CULL,
		0x8D10EB4C0247BAE4ULL,
		0x7081871EA9531661ULL,
		0x394F36CD53C3B398ULL,
		0x4FEBF10EF6FE9939ULL,
		0xFF33767E6A682499ULL,
		0xC23349647F2D3227ULL,
		0x275168A3462D52CCULL
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
		0x800EAFC33A922236ULL,
		0xBB3D42E3F6E4F8E2ULL,
		0x01641F375B766F0BULL,
		0xC8B95DB41C37AAF6ULL,
		0xA776E99E2821C5FAULL,
		0x874E0675E4E757ADULL,
		0x58CD6FDEA7B9389AULL,
		0x28C146A19F8700EBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x001D5F867524446CULL,
		0x767A85C7EDC9F1C5ULL,
		0x02C83E6EB6ECDE17ULL,
		0x9172BB68386F55ECULL,
		0x4EEDD33C50438BF5ULL,
		0x0E9C0CEBC9CEAF5BULL,
		0xB19ADFBD4F727135ULL,
		0x51828D433F0E01D6ULL
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
		0x035C6DEF6B6C533DULL,
		0xA0F08BB1040FE480ULL,
		0x65B7F5EF85C7C65DULL,
		0x2BE2681862B42753ULL,
		0xF71BA13FCF33EE82ULL,
		0x804AC2C24B4BBB82ULL,
		0x8DB997C35AAC8436ULL,
		0x0F6571A6E1EBBB2BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x06B8DBDED6D8A67AULL,
		0x41E11762081FC900ULL,
		0xCB6FEBDF0B8F8CBBULL,
		0x57C4D030C5684EA6ULL,
		0xEE37427F9E67DD04ULL,
		0x0095858496977705ULL,
		0x1B732F86B559086DULL,
		0x1ECAE34DC3D77657ULL
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
		0x59E2E7806AC182C4ULL,
		0x4254B2DD0CF279C3ULL,
		0xAC12CA7FF5B5FCA9ULL,
		0xB2A9C7C70AEC3A37ULL,
		0xA1D3F6FE4A57AB9EULL,
		0x16E67665C21EA612ULL,
		0xD9326883E4D64E69ULL,
		0x0A51EDF870AFFA31ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB3C5CF00D5830588ULL,
		0x84A965BA19E4F386ULL,
		0x582594FFEB6BF952ULL,
		0x65538F8E15D8746FULL,
		0x43A7EDFC94AF573DULL,
		0x2DCCECCB843D4C25ULL,
		0xB264D107C9AC9CD2ULL,
		0x14A3DBF0E15FF463ULL
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
		0x8EB43A5E5CAFDC44ULL,
		0x99829AC472B1EB12ULL,
		0xF8C05DBE905FD9E9ULL,
		0x6A3040E35C212698ULL,
		0x378B00719BEC09FFULL,
		0xFAB326F3D6C98E3FULL,
		0xC3C6D8AE0DA09B83ULL,
		0x225F9B42124C5B3CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1D6874BCB95FB888ULL,
		0x33053588E563D625ULL,
		0xF180BB7D20BFB3D3ULL,
		0xD46081C6B8424D31ULL,
		0x6F1600E337D813FEULL,
		0xF5664DE7AD931C7EULL,
		0x878DB15C1B413707ULL,
		0x44BF36842498B679ULL
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
		0x57B910FAF9B49C92ULL,
		0x38BEB742290F3E86ULL,
		0xBC9F8C9D029C52BCULL,
		0xF5665CA9DBDF5F5CULL,
		0x66D1205674D07EC5ULL,
		0xD0CADC2DD8BDCD17ULL,
		0x5324530096D0FADDULL,
		0x135CFCA72A0A6692ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF7221F5F3693924ULL,
		0x717D6E84521E7D0CULL,
		0x793F193A0538A578ULL,
		0xEACCB953B7BEBEB9ULL,
		0xCDA240ACE9A0FD8BULL,
		0xA195B85BB17B9A2EULL,
		0xA648A6012DA1F5BBULL,
		0x26B9F94E5414CD24ULL
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
		0x1A186763848B2512ULL,
		0x668B26159AAB8309ULL,
		0x302A04665CDD891DULL,
		0xB84A6B2FBCFCB116ULL,
		0x9885BB97F911302BULL,
		0x69250A6AE87560E3ULL,
		0x2B7E1484E5DB8CA4ULL,
		0x026A4F709F311FE1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3430CEC709164A24ULL,
		0xCD164C2B35570612ULL,
		0x605408CCB9BB123AULL,
		0x7094D65F79F9622CULL,
		0x310B772FF2226057ULL,
		0xD24A14D5D0EAC1C7ULL,
		0x56FC2909CBB71948ULL,
		0x04D49EE13E623FC2ULL
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
		0x4D36AE52893A78EFULL,
		0xE97ABC5961FD639FULL,
		0x42EBD2E717828A40ULL,
		0xF4660C275D48455DULL,
		0x720DEBF2E208D052ULL,
		0x95ACF745EBE76D6DULL,
		0x00019E47E71434EEULL,
		0x172124A3E2DEAB0FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9A6D5CA51274F1DEULL,
		0xD2F578B2C3FAC73EULL,
		0x85D7A5CE2F051481ULL,
		0xE8CC184EBA908ABAULL,
		0xE41BD7E5C411A0A5ULL,
		0x2B59EE8BD7CEDADAULL,
		0x00033C8FCE2869DDULL,
		0x2E424947C5BD561EULL
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
		0xB577A817013C66B2ULL,
		0x3AC1271BB9602D5CULL,
		0x68B3E9CE89FDAAD5ULL,
		0x15C478E5D8B192E0ULL,
		0x11C28807AC08D8FDULL,
		0x515526629BC79C6FULL,
		0x35FF1B3326101D9AULL,
		0x2C3DB5A3B30C9B7EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6AEF502E0278CD64ULL,
		0x75824E3772C05AB9ULL,
		0xD167D39D13FB55AAULL,
		0x2B88F1CBB16325C0ULL,
		0x2385100F5811B1FAULL,
		0xA2AA4CC5378F38DEULL,
		0x6BFE36664C203B34ULL,
		0x587B6B47661936FCULL
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
		0x016761892171337EULL,
		0xF38B8BA936FDDDACULL,
		0x0E93B9ADD2A28824ULL,
		0xE38BF385599A2F04ULL,
		0x13B31BFF84ADBFB8ULL,
		0x981455360CBD0C36ULL,
		0x7E41013800067A58ULL,
		0x2B05D690003D43BEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x02CEC31242E266FCULL,
		0xE71717526DFBBB58ULL,
		0x1D27735BA5451049ULL,
		0xC717E70AB3345E08ULL,
		0x276637FF095B7F71ULL,
		0x3028AA6C197A186CULL,
		0xFC820270000CF4B1ULL,
		0x560BAD20007A877CULL
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
		0x0C17560721FD7484ULL,
		0x2C49809CB88B6731ULL,
		0x8400EB39897BCE04ULL,
		0x71439511A73D68FEULL,
		0x12D0AC7006648316ULL,
		0xECFA1C69AFB236A8ULL,
		0x06BCD49107172865ULL,
		0x0D6C93798E431A76ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x182EAC0E43FAE908ULL,
		0x589301397116CE62ULL,
		0x0801D67312F79C08ULL,
		0xE2872A234E7AD1FDULL,
		0x25A158E00CC9062CULL,
		0xD9F438D35F646D50ULL,
		0x0D79A9220E2E50CBULL,
		0x1AD926F31C8634ECULL
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
		0xD73A646CEA50F3AEULL,
		0x26CEE7AB407AAFBDULL,
		0xB9FA791C6C4B45AEULL,
		0x13BA6697840595EAULL,
		0x9131FAF10913074CULL,
		0x27EE3A8D832C6341ULL,
		0xBE513F938229B022ULL,
		0x11904EB5799890A0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAE74C8D9D4A1E75CULL,
		0x4D9DCF5680F55F7BULL,
		0x73F4F238D8968B5CULL,
		0x2774CD2F080B2BD5ULL,
		0x2263F5E212260E98ULL,
		0x4FDC751B0658C683ULL,
		0x7CA27F2704536044ULL,
		0x23209D6AF3312141ULL
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
		0xDB6BBAE4E29E1C46ULL,
		0x41578333B9AF8435ULL,
		0xB7A8FCB2A4C3929CULL,
		0x29B11BE279101476ULL,
		0x57B65970CE120C1BULL,
		0xF8E2C59CE6E47C2BULL,
		0x243E3A791F687C3AULL,
		0x347085572456F9B9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB6D775C9C53C388CULL,
		0x82AF0667735F086BULL,
		0x6F51F96549872538ULL,
		0x536237C4F22028EDULL,
		0xAF6CB2E19C241836ULL,
		0xF1C58B39CDC8F856ULL,
		0x487C74F23ED0F875ULL,
		0x68E10AAE48ADF372ULL
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
		0x4EBF508A7900E741ULL,
		0x186946F1F749E401ULL,
		0xEE9F6145BB1ACD5BULL,
		0x7E76F9A347EEAE92ULL,
		0xD206C3B84C0E474BULL,
		0x7D4F75B6660FE8A4ULL,
		0x7380BFBA81B1540FULL,
		0x1D70DE524E799E4CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9D7EA114F201CE82ULL,
		0x30D28DE3EE93C802ULL,
		0xDD3EC28B76359AB6ULL,
		0xFCEDF3468FDD5D25ULL,
		0xA40D8770981C8E96ULL,
		0xFA9EEB6CCC1FD149ULL,
		0xE7017F750362A81EULL,
		0x3AE1BCA49CF33C98ULL
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
		0x0E52B5910DB57439ULL,
		0x9ADC79F3FF0251D4ULL,
		0xF586BC1C72B70690ULL,
		0x01757A33788B89A2ULL,
		0x89A6053463C5B5A0ULL,
		0x92DD03ACA5345891ULL,
		0xEAC42FFD97D9DCECULL,
		0x18E52941B595D08BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1CA56B221B6AE872ULL,
		0x35B8F3E7FE04A3A8ULL,
		0xEB0D7838E56E0D21ULL,
		0x02EAF466F1171345ULL,
		0x134C0A68C78B6B40ULL,
		0x25BA07594A68B123ULL,
		0xD5885FFB2FB3B9D9ULL,
		0x31CA52836B2BA117ULL
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
		0x3C94044750A8DEB1ULL,
		0x663DEF2F5915F9DEULL,
		0x6F999D8B43BA9B52ULL,
		0x58BE5272F16CB834ULL,
		0x713D22DD30A4E3CBULL,
		0x444B37857E8D5A35ULL,
		0xE0A21218877F7999ULL,
		0x3836A51D304ADA28ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7928088EA151BD62ULL,
		0xCC7BDE5EB22BF3BCULL,
		0xDF333B16877536A4ULL,
		0xB17CA4E5E2D97068ULL,
		0xE27A45BA6149C796ULL,
		0x88966F0AFD1AB46AULL,
		0xC14424310EFEF332ULL,
		0x706D4A3A6095B451ULL
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
		0xB3831BB01135981BULL,
		0x16069F4EE2B99CD3ULL,
		0x7F2684EDB4E72EEEULL,
		0x8F0F3ABE7A2E6D61ULL,
		0x15F2D0AC81D3DFE4ULL,
		0x2627D14A5BE7E074ULL,
		0xF1D5335110D715CDULL,
		0x2A34EB8DCD8097D0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x67063760226B3036ULL,
		0x2C0D3E9DC57339A7ULL,
		0xFE4D09DB69CE5DDCULL,
		0x1E1E757CF45CDAC2ULL,
		0x2BE5A15903A7BFC9ULL,
		0x4C4FA294B7CFC0E8ULL,
		0xE3AA66A221AE2B9AULL,
		0x5469D71B9B012FA1ULL
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
		0xC8F4A7EA3B520F05ULL,
		0x2BBA69ECEE84FF33ULL,
		0xD8FF11939391F8CEULL,
		0x228D9D19942EACFDULL,
		0x0EC38790CD2F18DFULL,
		0x13642D539C41517CULL,
		0x331802BA34977CBAULL,
		0x2CA670AE394F541DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x91E94FD476A41E0AULL,
		0x5774D3D9DD09FE67ULL,
		0xB1FE23272723F19CULL,
		0x451B3A33285D59FBULL,
		0x1D870F219A5E31BEULL,
		0x26C85AA73882A2F8ULL,
		0x66300574692EF974ULL,
		0x594CE15C729EA83AULL
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
		0xD471CAE144EAFC4AULL,
		0xC774E2DCEF982B09ULL,
		0x66430D8FC5EAC1A0ULL,
		0x0D9F8524A55181D0ULL,
		0xD09470AFC430AE03ULL,
		0x84D584EA3919F99DULL,
		0xED59BC497016CEDCULL,
		0x319629210E499E1BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA8E395C289D5F894ULL,
		0x8EE9C5B9DF305613ULL,
		0xCC861B1F8BD58341ULL,
		0x1B3F0A494AA303A0ULL,
		0xA128E15F88615C06ULL,
		0x09AB09D47233F33BULL,
		0xDAB37892E02D9DB9ULL,
		0x632C52421C933C37ULL
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
		0xA585A79B4AB9895FULL,
		0xCAD57F79D6B737F4ULL,
		0x29A4E1396666EE50ULL,
		0x75CB05B4D63F700AULL,
		0x3E26C7E7B38A2E60ULL,
		0x44BFA1AE90766DFFULL,
		0x8AC5F001DAB08D0CULL,
		0x255158BD708540DDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4B0B4F36957312BEULL,
		0x95AAFEF3AD6E6FE9ULL,
		0x5349C272CCCDDCA1ULL,
		0xEB960B69AC7EE014ULL,
		0x7C4D8FCF67145CC0ULL,
		0x897F435D20ECDBFEULL,
		0x158BE003B5611A18ULL,
		0x4AA2B17AE10A81BBULL
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
		0x082169C36001D716ULL,
		0x4D978C4E806947EDULL,
		0xF773388AEAB0D597ULL,
		0xB0435CEA4AC54293ULL,
		0x8FEE3058AC32CE37ULL,
		0x825CC63F8296508EULL,
		0x9DE8C38B400B7D76ULL,
		0x071B991E7315EBC1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1042D386C003AE2CULL,
		0x9B2F189D00D28FDAULL,
		0xEEE67115D561AB2EULL,
		0x6086B9D4958A8527ULL,
		0x1FDC60B158659C6FULL,
		0x04B98C7F052CA11DULL,
		0x3BD187168016FAEDULL,
		0x0E37323CE62BD783ULL
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
		0x4A6DE7F76D7CDF24ULL,
		0xEAACD024099868A4ULL,
		0x56BBD0BB9909828DULL,
		0x9AA21987DDE9F821ULL,
		0xA5BD4A4575B64B0DULL,
		0xC493A3BF05F8A80AULL,
		0xB81D9906E84D191AULL,
		0x28DF71AF426B7019ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x94DBCFEEDAF9BE48ULL,
		0xD559A0481330D148ULL,
		0xAD77A1773213051BULL,
		0x3544330FBBD3F042ULL,
		0x4B7A948AEB6C961BULL,
		0x8927477E0BF15015ULL,
		0x703B320DD09A3235ULL,
		0x51BEE35E84D6E033ULL
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
		0x6389BAF6BBA7E25CULL,
		0x39855BE731A09750ULL,
		0xFA909C55DB5B3B6FULL,
		0x80D66910206BC13DULL,
		0x1EE9BA496EE55468ULL,
		0x184783A7830AC3F0ULL,
		0x5FE252BAC09CD581ULL,
		0x2F80DA0B0DCB5633ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC71375ED774FC4B8ULL,
		0x730AB7CE63412EA0ULL,
		0xF52138ABB6B676DEULL,
		0x01ACD22040D7827BULL,
		0x3DD37492DDCAA8D1ULL,
		0x308F074F061587E0ULL,
		0xBFC4A5758139AB02ULL,
		0x5F01B4161B96AC66ULL
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
		0x037CB06A2B5F9557ULL,
		0x63BBDA7EF28E87D9ULL,
		0x9515361C2F6E4932ULL,
		0x7B0061BB9D7DC29CULL,
		0x687E49446469EDC4ULL,
		0xA29CA853FFD48BABULL,
		0x25E79C543D64AA8CULL,
		0x1CDB634161B11CB3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x06F960D456BF2AAEULL,
		0xC777B4FDE51D0FB2ULL,
		0x2A2A6C385EDC9264ULL,
		0xF600C3773AFB8539ULL,
		0xD0FC9288C8D3DB88ULL,
		0x453950A7FFA91756ULL,
		0x4BCF38A87AC95519ULL,
		0x39B6C682C3623966ULL
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
		0x929C6F7A10CD59B9ULL,
		0xA5E65114D6643F93ULL,
		0xAD1365FEE85800B9ULL,
		0xC3BA806FEEB9FAA9ULL,
		0xD34767B1598C1F10ULL,
		0xA1B76F179C288E44ULL,
		0xBA1346C914AA41E8ULL,
		0x12D5223B1CB7BD3FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2538DEF4219AB372ULL,
		0x4BCCA229ACC87F27ULL,
		0x5A26CBFDD0B00173ULL,
		0x877500DFDD73F553ULL,
		0xA68ECF62B3183E21ULL,
		0x436EDE2F38511C89ULL,
		0x74268D92295483D1ULL,
		0x25AA4476396F7A7FULL
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
		0x0154E317086D6981ULL,
		0x32CF350B7C7389E2ULL,
		0x6783C93FDEFFA6F2ULL,
		0xC32D1E12A0AA0BA7ULL,
		0xC9D08F33C3E433CFULL,
		0x5CC36FFBA679F852ULL,
		0x5E618213229F6966ULL,
		0x36E678D0607D9388ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x02A9C62E10DAD302ULL,
		0x659E6A16F8E713C4ULL,
		0xCF07927FBDFF4DE4ULL,
		0x865A3C254154174EULL,
		0x93A11E6787C8679FULL,
		0xB986DFF74CF3F0A5ULL,
		0xBCC30426453ED2CCULL,
		0x6DCCF1A0C0FB2710ULL
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
		0x9C9FD5D03A71D459ULL,
		0xCD8BD46B112F401CULL,
		0x7A5FE5BA487368E5ULL,
		0x55478BF598842D59ULL,
		0xAAF65A3D6A2F77CBULL,
		0x76529781BA6A5A9DULL,
		0xBF1CC302D4D56AD9ULL,
		0x28429E12C8B8DB32ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x393FABA074E3A8B2ULL,
		0x9B17A8D6225E8039ULL,
		0xF4BFCB7490E6D1CBULL,
		0xAA8F17EB31085AB2ULL,
		0x55ECB47AD45EEF96ULL,
		0xECA52F0374D4B53BULL,
		0x7E398605A9AAD5B2ULL,
		0x50853C259171B665ULL
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
		0x357454242D5340C1ULL,
		0x997F321FFF59481DULL,
		0x4D67D7FFA6DC06E9ULL,
		0xCAE9B52BBF1D91B3ULL,
		0xAFFE7052B01D4F46ULL,
		0x18B83F5211677B0AULL,
		0xFF5DE85B4CFB0E60ULL,
		0x0AEE5D74520183BBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6AE8A8485AA68182ULL,
		0x32FE643FFEB2903AULL,
		0x9ACFAFFF4DB80DD3ULL,
		0x95D36A577E3B2366ULL,
		0x5FFCE0A5603A9E8DULL,
		0x31707EA422CEF615ULL,
		0xFEBBD0B699F61CC0ULL,
		0x15DCBAE8A4030777ULL
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
		0xBFE80E7C563D8673ULL,
		0x1AA4EABF33545C5AULL,
		0xB2A8BF97E6DE3141ULL,
		0xA1CCDAE2AD47B3B0ULL,
		0xE83D07979D7ECD53ULL,
		0x7EB63FC887DFD8B0ULL,
		0x67800173C51250F6ULL,
		0x0F80125001F23A02ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7FD01CF8AC7B0CE6ULL,
		0x3549D57E66A8B8B5ULL,
		0x65517F2FCDBC6282ULL,
		0x4399B5C55A8F6761ULL,
		0xD07A0F2F3AFD9AA7ULL,
		0xFD6C7F910FBFB161ULL,
		0xCF0002E78A24A1ECULL,
		0x1F0024A003E47404ULL
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
		0x76C28B7BCB6500CEULL,
		0x8BB297BF0283B51CULL,
		0x275DF70FFF63FFA6ULL,
		0x0814F62DDA9044A4ULL,
		0x562F2AC005B9AF65ULL,
		0xB41986AB29FA1C76ULL,
		0x36411D7890DFB190ULL,
		0x38CEBC7F1D1136F4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xED8516F796CA019CULL,
		0x17652F7E05076A38ULL,
		0x4EBBEE1FFEC7FF4DULL,
		0x1029EC5BB5208948ULL,
		0xAC5E55800B735ECAULL,
		0x68330D5653F438ECULL,
		0x6C823AF121BF6321ULL,
		0x719D78FE3A226DE8ULL
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
		0x92493E837E9810A9ULL,
		0x4F22DF4DFC34A331ULL,
		0x215563D9F4FB5C4AULL,
		0x0CC545F4CA161EF5ULL,
		0x43D33E998042243BULL,
		0xFA3FA412CEFC5AD4ULL,
		0x26E0A4EFD23AEA6CULL,
		0x203486CEAE1CF492ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x24927D06FD302152ULL,
		0x9E45BE9BF8694663ULL,
		0x42AAC7B3E9F6B894ULL,
		0x198A8BE9942C3DEAULL,
		0x87A67D3300844876ULL,
		0xF47F48259DF8B5A8ULL,
		0x4DC149DFA475D4D9ULL,
		0x40690D9D5C39E924ULL
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
		0x5FEC84A98343A3C9ULL,
		0x12A41C217079640DULL,
		0x2694C328E6AD57C7ULL,
		0x5199046E015F72E3ULL,
		0x16C15BE050C5DEACULL,
		0x248BFCFF54B660C8ULL,
		0x3AFAF618A3EA1EE8ULL,
		0x0F5ADE02010A88CFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBFD9095306874792ULL,
		0x25483842E0F2C81AULL,
		0x4D298651CD5AAF8EULL,
		0xA33208DC02BEE5C6ULL,
		0x2D82B7C0A18BBD58ULL,
		0x4917F9FEA96CC190ULL,
		0x75F5EC3147D43DD0ULL,
		0x1EB5BC040215119EULL
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
		0xEABA637DD8833C10ULL,
		0x2951976018559DC2ULL,
		0xECEF0A2FF4292192ULL,
		0x71CA9F0EAB52B852ULL,
		0x805A9AD2ED68040FULL,
		0xE630FDC3DB2710EBULL,
		0x64A11DAE4BFE4CA1ULL,
		0x2737AFAE4686D9DFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD574C6FBB1067820ULL,
		0x52A32EC030AB3B85ULL,
		0xD9DE145FE8524324ULL,
		0xE3953E1D56A570A5ULL,
		0x00B535A5DAD0081EULL,
		0xCC61FB87B64E21D7ULL,
		0xC9423B5C97FC9943ULL,
		0x4E6F5F5C8D0DB3BEULL
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
		0xFE2AB7A76BFC39FEULL,
		0xB5065CA0DD70B434ULL,
		0xD4162CC708092BA0ULL,
		0xF25E16A9AEB39537ULL,
		0x58BDD4CED1DA290BULL,
		0xA06B862AF924FB7CULL,
		0xB1E058FE4B7750AEULL,
		0x150983E3C0F703C4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFC556F4ED7F873FCULL,
		0x6A0CB941BAE16869ULL,
		0xA82C598E10125741ULL,
		0xE4BC2D535D672A6FULL,
		0xB17BA99DA3B45217ULL,
		0x40D70C55F249F6F8ULL,
		0x63C0B1FC96EEA15DULL,
		0x2A1307C781EE0789ULL
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
		0x0B2628B277D94703ULL,
		0xC02CB26D5577D17BULL,
		0xACF71173360B9ADAULL,
		0x921F9A933FE7D319ULL,
		0x6A3789F3311C7524ULL,
		0x6BC3F70238A46B85ULL,
		0xE670530A8B321538ULL,
		0x17B8BB099C4D7F7DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x164C5164EFB28E06ULL,
		0x805964DAAAEFA2F6ULL,
		0x59EE22E66C1735B5ULL,
		0x243F35267FCFA633ULL,
		0xD46F13E66238EA49ULL,
		0xD787EE047148D70AULL,
		0xCCE0A61516642A70ULL,
		0x2F717613389AFEFBULL
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
		0x1672C73867A37274ULL,
		0xFCAFD9C82AD64501ULL,
		0xBB0E8D1B204DD3A3ULL,
		0xE7D871028309FE66ULL,
		0xF6E25B6F1AAFEEFFULL,
		0xA127E8C013704122ULL,
		0x2C598D76D4CE16BBULL,
		0x0AF6FAF35ACD25EBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2CE58E70CF46E4E8ULL,
		0xF95FB39055AC8A02ULL,
		0x761D1A36409BA747ULL,
		0xCFB0E2050613FCCDULL,
		0xEDC4B6DE355FDDFFULL,
		0x424FD18026E08245ULL,
		0x58B31AEDA99C2D77ULL,
		0x15EDF5E6B59A4BD6ULL
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
		0xF7E764781B7DC2A4ULL,
		0x540F9278420EE7EDULL,
		0x3376B31CB3305D7BULL,
		0xBE2B27A2386C9ABCULL,
		0x4C92988EBD69FC7DULL,
		0x7D471B21CC87AC4CULL,
		0x55951FA8166655D3ULL,
		0x2B09E7088048E7AEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEFCEC8F036FB8548ULL,
		0xA81F24F0841DCFDBULL,
		0x66ED66396660BAF6ULL,
		0x7C564F4470D93578ULL,
		0x9925311D7AD3F8FBULL,
		0xFA8E3643990F5898ULL,
		0xAB2A3F502CCCABA6ULL,
		0x5613CE110091CF5CULL
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
		0xD2C207C7C5D9ACCCULL,
		0x6A90A7FA6900C73FULL,
		0xCB731902F36ECB63ULL,
		0x04E0587E2CECF6F2ULL,
		0x80470FFCF43E42B2ULL,
		0xAA2942DC6F45040EULL,
		0x80057DFC845B6B05ULL,
		0x31D5693CA450AE6AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA5840F8F8BB35998ULL,
		0xD5214FF4D2018E7FULL,
		0x96E63205E6DD96C6ULL,
		0x09C0B0FC59D9EDE5ULL,
		0x008E1FF9E87C8564ULL,
		0x545285B8DE8A081DULL,
		0x000AFBF908B6D60BULL,
		0x63AAD27948A15CD5ULL
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
		0x25427E534DDA348DULL,
		0xE5D73043EFEC2482ULL,
		0xEB7F0E347D8F0318ULL,
		0x375C3FBA3588A74DULL,
		0x1863A703E2A97391ULL,
		0x7A48836D0F7974FDULL,
		0x5CCCD6BE8F70DA9FULL,
		0x314AC86B2D308164ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4A84FCA69BB4691AULL,
		0xCBAE6087DFD84904ULL,
		0xD6FE1C68FB1E0631ULL,
		0x6EB87F746B114E9BULL,
		0x30C74E07C552E722ULL,
		0xF49106DA1EF2E9FAULL,
		0xB999AD7D1EE1B53EULL,
		0x629590D65A6102C8ULL
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
		0xD447F85757F4580DULL,
		0x1EC872ECBE0996B9ULL,
		0xD68E37872B2BCA87ULL,
		0xAA80220CBB6FF884ULL,
		0x5C2A5B476092A98FULL,
		0x7965BEDDA1EDD08EULL,
		0xC032E9D1A84B742FULL,
		0x390A1A804A84E755ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA88FF0AEAFE8B01AULL,
		0x3D90E5D97C132D73ULL,
		0xAD1C6F0E5657950EULL,
		0x5500441976DFF109ULL,
		0xB854B68EC125531FULL,
		0xF2CB7DBB43DBA11CULL,
		0x8065D3A35096E85EULL,
		0x721435009509CEABULL
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
		0x316B91A024F4AB56ULL,
		0x5DBA5189A183979BULL,
		0xD0652F3AE16E9C9BULL,
		0xF52DDCCB05B13528ULL,
		0xCECF7FC8640CB2CFULL,
		0x51FEAC853B19EA31ULL,
		0x5969B15871AB895CULL,
		0x19E7F38C64991B90ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x62D7234049E956ACULL,
		0xBB74A31343072F36ULL,
		0xA0CA5E75C2DD3936ULL,
		0xEA5BB9960B626A51ULL,
		0x9D9EFF90C819659FULL,
		0xA3FD590A7633D463ULL,
		0xB2D362B0E35712B8ULL,
		0x33CFE718C9323720ULL
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
		0xE56F624695A4B330ULL,
		0x7B963AAFE2E4AD7DULL,
		0x3D741AE94B6D9D63ULL,
		0x452154789E2E3ABBULL,
		0xEF1E051B10F3C7EFULL,
		0xCB461D9E1A40C469ULL,
		0xDD2EFDF0F62BB531ULL,
		0x18AD3532AB758A5FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCADEC48D2B496660ULL,
		0xF72C755FC5C95AFBULL,
		0x7AE835D296DB3AC6ULL,
		0x8A42A8F13C5C7576ULL,
		0xDE3C0A3621E78FDEULL,
		0x968C3B3C348188D3ULL,
		0xBA5DFBE1EC576A63ULL,
		0x315A6A6556EB14BFULL
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
		0x468FA6276420CA78ULL,
		0x3F79D889242CE25BULL,
		0xC58689E1E29AC014ULL,
		0x4698705C33D36C14ULL,
		0xDBC5E01A0A1C8B36ULL,
		0xB5177CAE1E1AB9F9ULL,
		0xA7742717B4C8FB44ULL,
		0x34ABB25B449BA3DBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8D1F4C4EC84194F0ULL,
		0x7EF3B1124859C4B6ULL,
		0x8B0D13C3C5358028ULL,
		0x8D30E0B867A6D829ULL,
		0xB78BC0341439166CULL,
		0x6A2EF95C3C3573F3ULL,
		0x4EE84E2F6991F689ULL,
		0x695764B6893747B7ULL
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
		0x69706334242394EBULL,
		0xC8125625EB520B46ULL,
		0xEA38A6B3F7C3FB7CULL,
		0x489E84DBE6E1981CULL,
		0xDDF7D9FB37E1E460ULL,
		0xE5B4169AFD9A72A1ULL,
		0x97AF55F44EBCB842ULL,
		0x1F1031821C39DE09ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD2E0C668484729D6ULL,
		0x9024AC4BD6A4168CULL,
		0xD4714D67EF87F6F9ULL,
		0x913D09B7CDC33039ULL,
		0xBBEFB3F66FC3C8C0ULL,
		0xCB682D35FB34E543ULL,
		0x2F5EABE89D797085ULL,
		0x3E2063043873BC13ULL
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
		0x9C379D9FF990E906ULL,
		0x170DD248D8DEDAF1ULL,
		0xAC214B21C8454014ULL,
		0x4438C88BC435B170ULL,
		0x25E141DD49D048C0ULL,
		0x1D97C1F392D8E6F5ULL,
		0xB8F8A01442714D55ULL,
		0x35BED9516C4E01EFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x386F3B3FF321D20CULL,
		0x2E1BA491B1BDB5E3ULL,
		0x58429643908A8028ULL,
		0x88719117886B62E1ULL,
		0x4BC283BA93A09180ULL,
		0x3B2F83E725B1CDEAULL,
		0x71F1402884E29AAAULL,
		0x6B7DB2A2D89C03DFULL
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
		0x1F8142E44FD5D710ULL,
		0x7A4F5A1F74E72167ULL,
		0x07A2CBE6B5ED7656ULL,
		0xD476E586AD0C7C15ULL,
		0x509D23251C816EF6ULL,
		0x00F464C9DECC5223ULL,
		0x533DD47C6237A879ULL,
		0x2696B83724AAFEABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3F0285C89FABAE20ULL,
		0xF49EB43EE9CE42CEULL,
		0x0F4597CD6BDAECACULL,
		0xA8EDCB0D5A18F82AULL,
		0xA13A464A3902DDEDULL,
		0x01E8C993BD98A446ULL,
		0xA67BA8F8C46F50F2ULL,
		0x4D2D706E4955FD56ULL
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
		0xF949A666B196EF8CULL,
		0x24D02CD4DB27235BULL,
		0xB3B8BFFE46629C25ULL,
		0x04235DF8933839ACULL,
		0xEF04678D1A5A6533ULL,
		0xF9B06F6CED6DD8B0ULL,
		0x8EDC2049CF2177EFULL,
		0x03575CCDBE73E045ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF2934CCD632DDF18ULL,
		0x49A059A9B64E46B7ULL,
		0x67717FFC8CC5384AULL,
		0x0846BBF126707359ULL,
		0xDE08CF1A34B4CA66ULL,
		0xF360DED9DADBB161ULL,
		0x1DB840939E42EFDFULL,
		0x06AEB99B7CE7C08BULL
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
		0x14A0589DBC656CF3ULL,
		0x94C73FAC6BDC5F6CULL,
		0x1EA6B2EE902CF81EULL,
		0xBF58224B3D54F037ULL,
		0xD010A719FF978895ULL,
		0x479F031505A99F8FULL,
		0x18A7D5822454849BULL,
		0x19A163B0DC411DB0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2940B13B78CAD9E6ULL,
		0x298E7F58D7B8BED8ULL,
		0x3D4D65DD2059F03DULL,
		0x7EB044967AA9E06EULL,
		0xA0214E33FF2F112BULL,
		0x8F3E062A0B533F1FULL,
		0x314FAB0448A90936ULL,
		0x3342C761B8823B60ULL
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
		0x58EDE90B02FFB0D1ULL,
		0x041324B7328C6809ULL,
		0x64EF4C6506D5D68AULL,
		0x1C848EB90C0A1D17ULL,
		0xD8AF090700F0D13BULL,
		0xA091582B5FCE29F7ULL,
		0x5F8E9FD7EFB2DA8FULL,
		0x13ACA1B90E5107C4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB1DBD21605FF61A2ULL,
		0x0826496E6518D012ULL,
		0xC9DE98CA0DABAD14ULL,
		0x39091D7218143A2EULL,
		0xB15E120E01E1A276ULL,
		0x4122B056BF9C53EFULL,
		0xBF1D3FAFDF65B51FULL,
		0x275943721CA20F88ULL
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
		0x75C6855693ABA47DULL,
		0x67E890CB14028F90ULL,
		0x34D35B1100548BEDULL,
		0x99A16816832BA780ULL,
		0x05CC553C49E2018BULL,
		0x63960C61617836C1ULL,
		0x4B35670901C941BAULL,
		0x106606FCC4892427ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEB8D0AAD275748FAULL,
		0xCFD1219628051F20ULL,
		0x69A6B62200A917DAULL,
		0x3342D02D06574F00ULL,
		0x0B98AA7893C40317ULL,
		0xC72C18C2C2F06D82ULL,
		0x966ACE1203928374ULL,
		0x20CC0DF98912484EULL
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
		0x113220059FB33494ULL,
		0x076892B6B102BE75ULL,
		0x944410CA3B5DF12EULL,
		0x963996BDB0C1737EULL,
		0x250D09E8C36EB84DULL,
		0x95FAC344A28EB1F9ULL,
		0xAB18C34805E32311ULL,
		0x3DA259F66F6CDB09ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2264400B3F666928ULL,
		0x0ED1256D62057CEAULL,
		0x2888219476BBE25CULL,
		0x2C732D7B6182E6FDULL,
		0x4A1A13D186DD709BULL,
		0x2BF58689451D63F2ULL,
		0x563186900BC64623ULL,
		0x7B44B3ECDED9B613ULL
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
		0x67EFCBA12ACFCBE1ULL,
		0x05B4FD480BF2F0ACULL,
		0xAE592A39362A0251ULL,
		0x56176D7B77A69CB9ULL,
		0x6CFAA0BE1980DBF9ULL,
		0xB237C389BF85B73CULL,
		0x25EF47F2B39D4731ULL,
		0x21FE5DCBBD113E45ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCFDF9742559F97C2ULL,
		0x0B69FA9017E5E158ULL,
		0x5CB254726C5404A2ULL,
		0xAC2EDAF6EF4D3973ULL,
		0xD9F5417C3301B7F2ULL,
		0x646F87137F0B6E78ULL,
		0x4BDE8FE5673A8E63ULL,
		0x43FCBB977A227C8AULL
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
		0x60AA277DE8447A77ULL,
		0xB9CA3D072886F2FAULL,
		0x813ECD8B18E7E4CBULL,
		0x031826996886B8C1ULL,
		0x47F1FFC9C247C6EFULL,
		0x88AE3EA81D40990FULL,
		0xBB8C3EE0C6C79587ULL,
		0x2F2FCE31B3A2DA42ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC1544EFBD088F4EEULL,
		0x73947A0E510DE5F4ULL,
		0x027D9B1631CFC997ULL,
		0x06304D32D10D7183ULL,
		0x8FE3FF93848F8DDEULL,
		0x115C7D503A81321EULL,
		0x77187DC18D8F2B0FULL,
		0x5E5F9C636745B485ULL
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
		0xB7B940854554AA9AULL,
		0xED30D6E220566652ULL,
		0x0843C5A23CA62AD8ULL,
		0x966092749F21F621ULL,
		0xB74F632B8A5F9314ULL,
		0xC10039E69BB2D90DULL,
		0xDE6C481969D6D8D7ULL,
		0x0FB7B953867A5262ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6F72810A8AA95534ULL,
		0xDA61ADC440ACCCA5ULL,
		0x10878B44794C55B1ULL,
		0x2CC124E93E43EC42ULL,
		0x6E9EC65714BF2629ULL,
		0x820073CD3765B21BULL,
		0xBCD89032D3ADB1AFULL,
		0x1F6F72A70CF4A4C5ULL
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
		0x33C79F414EAD420EULL,
		0xB3BEA65A22A15DB9ULL,
		0x814CE45F3501BF85ULL,
		0x5B7EBD6E53FF903FULL,
		0x610D3E057285BC4BULL,
		0xAB683CB5E1729A1EULL,
		0x9C577136CD87B34BULL,
		0x32F26A498CBE28FCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x678F3E829D5A841CULL,
		0x677D4CB44542BB72ULL,
		0x0299C8BE6A037F0BULL,
		0xB6FD7ADCA7FF207FULL,
		0xC21A7C0AE50B7896ULL,
		0x56D0796BC2E5343CULL,
		0x38AEE26D9B0F6697ULL,
		0x65E4D493197C51F9ULL
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
		0x2C6F339AE02450A3ULL,
		0x5AA5819249C84C4AULL,
		0x078C001BC4C0BBF6ULL,
		0x8C9DE21E958EF0D7ULL,
		0x13DB36894B01199CULL,
		0xF62C0AA4A67F4547ULL,
		0x1A036F68A5FFD931ULL,
		0x1EEE45ED8B97EFEAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x58DE6735C048A146ULL,
		0xB54B032493909894ULL,
		0x0F180037898177ECULL,
		0x193BC43D2B1DE1AEULL,
		0x27B66D1296023339ULL,
		0xEC5815494CFE8A8EULL,
		0x3406DED14BFFB263ULL,
		0x3DDC8BDB172FDFD4ULL
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
		0x65EC2A792E860B78ULL,
		0x870DC16F0DB1BE09ULL,
		0x50ECC610C6497CC0ULL,
		0xF8BA3656E4FC9D7CULL,
		0x867D3600EAD09D6DULL,
		0x38AA7A941CCFC7C5ULL,
		0x0B6E0003F2D9252AULL,
		0x2D42F463CEBB4583ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCBD854F25D0C16F0ULL,
		0x0E1B82DE1B637C12ULL,
		0xA1D98C218C92F981ULL,
		0xF1746CADC9F93AF8ULL,
		0x0CFA6C01D5A13ADBULL,
		0x7154F528399F8F8BULL,
		0x16DC0007E5B24A54ULL,
		0x5A85E8C79D768B06ULL
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
		0x683EB945BF5B83A2ULL,
		0xD51AE4481234F088ULL,
		0x8A7E33064B84C446ULL,
		0xF3A0D4237BBA5C67ULL,
		0x593118C5FC857490ULL,
		0xC376A469962EE111ULL,
		0xDABCF5EC9E266F40ULL,
		0x0B1E79004A2BE6BCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD07D728B7EB70744ULL,
		0xAA35C8902469E110ULL,
		0x14FC660C9709888DULL,
		0xE741A846F774B8CFULL,
		0xB262318BF90AE921ULL,
		0x86ED48D32C5DC222ULL,
		0xB579EBD93C4CDE81ULL,
		0x163CF2009457CD79ULL
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
		0x836199FA583B9DECULL,
		0xC2A419265A96CD12ULL,
		0x90702B58444C5F60ULL,
		0x3DE789F49A8C9982ULL,
		0x8C7B2A5BD256FC42ULL,
		0xD9925900BFEF2E7EULL,
		0xA1B57950F38FB11EULL,
		0x2FE4415B9A9BDFEBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x06C333F4B0773BD8ULL,
		0x8548324CB52D9A25ULL,
		0x20E056B08898BEC1ULL,
		0x7BCF13E935193305ULL,
		0x18F654B7A4ADF884ULL,
		0xB324B2017FDE5CFDULL,
		0x436AF2A1E71F623DULL,
		0x5FC882B73537BFD7ULL
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
		0xE49018AA660DA7C5ULL,
		0x46E3CE0095C2D2DFULL,
		0x2A424316A4626E7EULL,
		0x24879918F582FD11ULL,
		0x4E18814CD922681EULL,
		0x31845B44C950B99BULL,
		0x1C7FD80D72EA90C9ULL,
		0x37B9766C558CCDEFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC9203154CC1B4F8AULL,
		0x8DC79C012B85A5BFULL,
		0x5484862D48C4DCFCULL,
		0x490F3231EB05FA22ULL,
		0x9C310299B244D03CULL,
		0x6308B68992A17336ULL,
		0x38FFB01AE5D52192ULL,
		0x6F72ECD8AB199BDEULL
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
		0x230CFAA32AADBCE7ULL,
		0xAA532ADA5EC87037ULL,
		0xA72A7A7C582EDCBCULL,
		0x6521A7C5055A52E1ULL,
		0x26EB1D6299364C48ULL,
		0x506C867AF7AEAC96ULL,
		0x2C3F8D2CA4A51BECULL,
		0x1B3E9852AC34953DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4619F546555B79CEULL,
		0x54A655B4BD90E06EULL,
		0x4E54F4F8B05DB979ULL,
		0xCA434F8A0AB4A5C3ULL,
		0x4DD63AC5326C9890ULL,
		0xA0D90CF5EF5D592CULL,
		0x587F1A59494A37D8ULL,
		0x367D30A558692A7AULL
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
		0x7E120488B33DFB3BULL,
		0x336685AF88614C72ULL,
		0xE49524A4BDE43FF4ULL,
		0x996009E50CB88128ULL,
		0x4625D3F270942B5BULL,
		0x480F6B6952A6B66FULL,
		0x6FC45FF4A9A61E1CULL,
		0x1AFDBB7E81A82D07ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFC240911667BF676ULL,
		0x66CD0B5F10C298E4ULL,
		0xC92A49497BC87FE8ULL,
		0x32C013CA19710251ULL,
		0x8C4BA7E4E12856B7ULL,
		0x901ED6D2A54D6CDEULL,
		0xDF88BFE9534C3C38ULL,
		0x35FB76FD03505A0EULL
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
		0x3A77F049EA836958ULL,
		0xF36760CAAD43AC33ULL,
		0x35F51EBF80ECF7AEULL,
		0x67AC013B4BD5743BULL,
		0x591292B7FA1436B6ULL,
		0xC3D83312A8400BBBULL,
		0x307BA5B53EED9341ULL,
		0x2A087419B332E12DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x74EFE093D506D2B0ULL,
		0xE6CEC1955A875866ULL,
		0x6BEA3D7F01D9EF5DULL,
		0xCF58027697AAE876ULL,
		0xB225256FF4286D6CULL,
		0x87B0662550801776ULL,
		0x60F74B6A7DDB2683ULL,
		0x5410E8336665C25AULL
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
		0xF0293DDFC1601D8BULL,
		0x2DE49F79A75D6CA1ULL,
		0xEFA8E57067A90A10ULL,
		0x42C4E3301EBDD69EULL,
		0x95CB7256CE774141ULL,
		0xF7C0E9ABF1A68D2AULL,
		0x5D52350B8C46F238ULL,
		0x208199536B95BA74ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE0527BBF82C03B16ULL,
		0x5BC93EF34EBAD943ULL,
		0xDF51CAE0CF521420ULL,
		0x8589C6603D7BAD3DULL,
		0x2B96E4AD9CEE8282ULL,
		0xEF81D357E34D1A55ULL,
		0xBAA46A17188DE471ULL,
		0x410332A6D72B74E8ULL
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
		0x3565EEA39470A4B0ULL,
		0x487DB881CBD61CF5ULL,
		0x9AFEE40CEB26E32FULL,
		0xD17D52F48947E758ULL,
		0x9AFCE0177948D1A3ULL,
		0xB19944502EAA143CULL,
		0x32F715EC93E27B1FULL,
		0x11F033EEE4A8898BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6ACBDD4728E14960ULL,
		0x90FB710397AC39EAULL,
		0x35FDC819D64DC65EULL,
		0xA2FAA5E9128FCEB1ULL,
		0x35F9C02EF291A347ULL,
		0x633288A05D542879ULL,
		0x65EE2BD927C4F63FULL,
		0x23E067DDC9511316ULL
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
		0x04A18358A08A2517ULL,
		0x9848467C517B08A9ULL,
		0xD4214BAD0FF49038ULL,
		0x4B382EFC111BCB78ULL,
		0x66528307A08A31CDULL,
		0xF456E333401EDDFAULL,
		0x99795A440BF00B17ULL,
		0x25A0EBBFC9ED00F3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x094306B141144A2EULL,
		0x30908CF8A2F61152ULL,
		0xA842975A1FE92071ULL,
		0x96705DF8223796F1ULL,
		0xCCA5060F4114639AULL,
		0xE8ADC666803DBBF4ULL,
		0x32F2B48817E0162FULL,
		0x4B41D77F93DA01E7ULL
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
		0x495A3D3BAEC4E08DULL,
		0x4E6D11D22C5112AEULL,
		0x09B8EDC6D5D0C1F0ULL,
		0xCD76C506422D513FULL,
		0xBA6492596172910EULL,
		0x5EFD3AEE51D4A6DDULL,
		0xE9ABD621C85E56E4ULL,
		0x1AD4F7D5617DD602ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x92B47A775D89C11AULL,
		0x9CDA23A458A2255CULL,
		0x1371DB8DABA183E0ULL,
		0x9AED8A0C845AA27EULL,
		0x74C924B2C2E5221DULL,
		0xBDFA75DCA3A94DBBULL,
		0xD357AC4390BCADC8ULL,
		0x35A9EFAAC2FBAC05ULL
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
		0x02E60ADDCE0152C0ULL,
		0x465B46EBD10D8568ULL,
		0xBE7F95E8354F91AFULL,
		0x79A24F9F1C5542FAULL,
		0x86BAA86D836B1DA4ULL,
		0xFEA5073A943D6ED8ULL,
		0xC98CCD3DAB7EB9E7ULL,
		0x154E5AC92CBFC4A0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x05CC15BB9C02A580ULL,
		0x8CB68DD7A21B0AD0ULL,
		0x7CFF2BD06A9F235EULL,
		0xF3449F3E38AA85F5ULL,
		0x0D7550DB06D63B48ULL,
		0xFD4A0E75287ADDB1ULL,
		0x93199A7B56FD73CFULL,
		0x2A9CB592597F8941ULL
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
		0x023911E5D452C47AULL,
		0x027E79CC256C1882ULL,
		0xD1F9586FCDF0BEE9ULL,
		0xF9AF7B6B2B8CF242ULL,
		0xE81560880B812989ULL,
		0x63BCEE5F07E6E397ULL,
		0x2B598905B315BAF7ULL,
		0x052438D257DCFE49ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x047223CBA8A588F4ULL,
		0x04FCF3984AD83104ULL,
		0xA3F2B0DF9BE17DD2ULL,
		0xF35EF6D65719E485ULL,
		0xD02AC11017025313ULL,
		0xC779DCBE0FCDC72FULL,
		0x56B3120B662B75EEULL,
		0x0A4871A4AFB9FC92ULL
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
		0x0F1C9E43BCFA051CULL,
		0x065B51CF17542C4AULL,
		0x16DA84FF3B7937D0ULL,
		0x973985DDFF69CF8AULL,
		0xA92D66C38A61585FULL,
		0xADDE77DADC92EB5AULL,
		0x435676C70D43C70DULL,
		0x34F8985E88C64998ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1E393C8779F40A38ULL,
		0x0CB6A39E2EA85894ULL,
		0x2DB509FE76F26FA0ULL,
		0x2E730BBBFED39F14ULL,
		0x525ACD8714C2B0BFULL,
		0x5BBCEFB5B925D6B5ULL,
		0x86ACED8E1A878E1BULL,
		0x69F130BD118C9330ULL
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
		0x027A8011340EAC8BULL,
		0x365C7631A5D10C6AULL,
		0x54BB3C118922A005ULL,
		0x3934A311AAC9421AULL,
		0x6B1EDD3656927CA7ULL,
		0xDB765BC40D6AA48CULL,
		0xF4566DACFA5CA992ULL,
		0x39625F2B009BBB70ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x04F50022681D5916ULL,
		0x6CB8EC634BA218D4ULL,
		0xA97678231245400AULL,
		0x7269462355928434ULL,
		0xD63DBA6CAD24F94EULL,
		0xB6ECB7881AD54918ULL,
		0xE8ACDB59F4B95325ULL,
		0x72C4BE56013776E1ULL
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
		0x2EDEE5B1EB52956CULL,
		0x137102E496845AF5ULL,
		0x8144BC97DB539D5DULL,
		0xB0B8452A68C502C8ULL,
		0x9DE9FE62755FB5E5ULL,
		0xD2AD45B5E34656B4ULL,
		0xD60D5DEFC5874962ULL,
		0x15320B0E1655692FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5DBDCB63D6A52AD8ULL,
		0x26E205C92D08B5EAULL,
		0x0289792FB6A73ABAULL,
		0x61708A54D18A0591ULL,
		0x3BD3FCC4EABF6BCBULL,
		0xA55A8B6BC68CAD69ULL,
		0xAC1ABBDF8B0E92C5ULL,
		0x2A64161C2CAAD25FULL
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
		0xE52401826512B751ULL,
		0x61456FE2D342BB7CULL,
		0x6B96CF965790D0A7ULL,
		0x2EA1E36C64442801ULL,
		0x69A47FDBF13ECA3BULL,
		0xBA297BA436745008ULL,
		0xC3A721998AEA303CULL,
		0x34570264E57A7AF9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCA480304CA256EA2ULL,
		0xC28ADFC5A68576F9ULL,
		0xD72D9F2CAF21A14EULL,
		0x5D43C6D8C8885002ULL,
		0xD348FFB7E27D9476ULL,
		0x7452F7486CE8A010ULL,
		0x874E433315D46079ULL,
		0x68AE04C9CAF4F5F3ULL
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
		0xCD4EF4C4A5F051BCULL,
		0xD6AC144116EE7783ULL,
		0xE824CE9FE1209561ULL,
		0xCAA631BEBBD4FE0EULL,
		0x3D6641B7B5B4F0D4ULL,
		0x5491F8C15A3FD986ULL,
		0x48252C71D8D8617EULL,
		0x3AE5199618AD9C08ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9A9DE9894BE0A378ULL,
		0xAD5828822DDCEF07ULL,
		0xD0499D3FC2412AC3ULL,
		0x954C637D77A9FC1DULL,
		0x7ACC836F6B69E1A9ULL,
		0xA923F182B47FB30CULL,
		0x904A58E3B1B0C2FCULL,
		0x75CA332C315B3810ULL
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
		0xCAD775AAC1C7A731ULL,
		0xB01ACEDBE1623DE0ULL,
		0x9C4786C6F0803EE5ULL,
		0x3B51F000380FC27EULL,
		0xB18720A93439AD5AULL,
		0x1DE11CB9B52273C1ULL,
		0xD653BC0C56780F3FULL,
		0x28DDF1392E250534ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x95AEEB55838F4E62ULL,
		0x60359DB7C2C47BC1ULL,
		0x388F0D8DE1007DCBULL,
		0x76A3E000701F84FDULL,
		0x630E415268735AB4ULL,
		0x3BC239736A44E783ULL,
		0xACA77818ACF01E7EULL,
		0x51BBE2725C4A0A69ULL
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
		0xBFC2B3F7657E73FCULL,
		0xC4D893D9969E35E7ULL,
		0x2D81F3D0852335E4ULL,
		0x05319192D666E5B2ULL,
		0xC340042030063CD5ULL,
		0xCFE0E96A44D075F8ULL,
		0x618FB47B0F5380C0ULL,
		0x2560D98076FCF7C0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7F8567EECAFCE7F8ULL,
		0x89B127B32D3C6BCFULL,
		0x5B03E7A10A466BC9ULL,
		0x0A632325ACCDCB64ULL,
		0x86800840600C79AAULL,
		0x9FC1D2D489A0EBF1ULL,
		0xC31F68F61EA70181ULL,
		0x4AC1B300EDF9EF80ULL
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
		0x8B4F3CC1B4700D62ULL,
		0x2BB04EC8044E2872ULL,
		0x0A2FAB4C03A6CB1BULL,
		0xADD35B365E4C36A3ULL,
		0xD11888A7D675E8E9ULL,
		0x83607C6BD9785A6CULL,
		0x399AE4BBCCB8912AULL,
		0x315CCDF4510BB4F5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x169E798368E01AC4ULL,
		0x57609D90089C50E5ULL,
		0x145F5698074D9636ULL,
		0x5BA6B66CBC986D46ULL,
		0xA231114FACEBD1D3ULL,
		0x06C0F8D7B2F0B4D9ULL,
		0x7335C97799712255ULL,
		0x62B99BE8A21769EAULL
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
		0x07456A854812E0EEULL,
		0xF271A3B2AE0D18F7ULL,
		0x35EA34DBB9E17851ULL,
		0xE0BBE2896053AC62ULL,
		0x73411EB05C6D7DCCULL,
		0xD03A9FFA93A7C457ULL,
		0x5B833FFEF3239F23ULL,
		0x094355F68FFC6696ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0E8AD50A9025C1DCULL,
		0xE4E347655C1A31EEULL,
		0x6BD469B773C2F0A3ULL,
		0xC177C512C0A758C4ULL,
		0xE6823D60B8DAFB99ULL,
		0xA0753FF5274F88AEULL,
		0xB7067FFDE6473E47ULL,
		0x1286ABED1FF8CD2CULL
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
		0x98EF36F7DB8AA39EULL,
		0xE0DBBDB5D4A0CA82ULL,
		0x9C84D7CE9BA3CD00ULL,
		0x62AFD1584B0E950BULL,
		0x4DAE37586A60CF4DULL,
		0x177D9D3920DE9FDEULL,
		0x1272C9B92CE52176ULL,
		0x24FA04BAF6953C17ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x31DE6DEFB715473CULL,
		0xC1B77B6BA9419505ULL,
		0x3909AF9D37479A01ULL,
		0xC55FA2B0961D2A17ULL,
		0x9B5C6EB0D4C19E9AULL,
		0x2EFB3A7241BD3FBCULL,
		0x24E5937259CA42ECULL,
		0x49F40975ED2A782EULL
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
		0x3C30E9D9F8034065ULL,
		0x97AD4ABEA1E4CC81ULL,
		0x51AA83BFE6568BFDULL,
		0xCAE1859B77413837ULL,
		0x8ACA0237C61F0096ULL,
		0x7CBA81DA5C869EA7ULL,
		0x1AB0B2C34A11CE5FULL,
		0x0DE06B8B12CB91B6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7861D3B3F00680CAULL,
		0x2F5A957D43C99902ULL,
		0xA355077FCCAD17FBULL,
		0x95C30B36EE82706EULL,
		0x1594046F8C3E012DULL,
		0xF97503B4B90D3D4FULL,
		0x3561658694239CBEULL,
		0x1BC0D7162597236CULL
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
		0x538E1D8972D67D28ULL,
		0x16FBB0172B808319ULL,
		0x7957903E34DD4580ULL,
		0xDDE2A39C98E9CAEBULL,
		0x6C8EF2E26D88DEA4ULL,
		0xB236B80B67995C93ULL,
		0x893E6026A9BA2A7AULL,
		0x211E9C154F0394EAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA71C3B12E5ACFA50ULL,
		0x2DF7602E57010632ULL,
		0xF2AF207C69BA8B00ULL,
		0xBBC5473931D395D6ULL,
		0xD91DE5C4DB11BD49ULL,
		0x646D7016CF32B926ULL,
		0x127CC04D537454F5ULL,
		0x423D382A9E0729D5ULL
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
		0xB9CA14CE09EA81BAULL,
		0xF2820D39DA826D4AULL,
		0xDE4C0EC8BEB75989ULL,
		0x78D05F1978E4D070ULL,
		0x13AF23FB315A90DDULL,
		0x6FE58575CBD19336ULL,
		0xA7F5A61422E563D6ULL,
		0x1F8CB3F30DF6C105ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7394299C13D50374ULL,
		0xE5041A73B504DA95ULL,
		0xBC981D917D6EB313ULL,
		0xF1A0BE32F1C9A0E1ULL,
		0x275E47F662B521BAULL,
		0xDFCB0AEB97A3266CULL,
		0x4FEB4C2845CAC7ACULL,
		0x3F1967E61BED820BULL
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
		0x71EAAFBCDD26ACA3ULL,
		0xBE321CA4D5278439ULL,
		0x7C0DB708B3125EF1ULL,
		0x9691EDB40433DB68ULL,
		0x40254AC2D95E59CCULL,
		0xE743CB46018DDA11ULL,
		0xBC914009C39022EFULL,
		0x0DE96A3A7DAAC156ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE3D55F79BA4D5946ULL,
		0x7C643949AA4F0872ULL,
		0xF81B6E116624BDE3ULL,
		0x2D23DB680867B6D0ULL,
		0x804A9585B2BCB399ULL,
		0xCE87968C031BB422ULL,
		0x79228013872045DFULL,
		0x1BD2D474FB5582ADULL
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
		0x13E77DEDB994547FULL,
		0x17D9B7963F4642B9ULL,
		0x03E40151B893FEBDULL,
		0x3621E1953BC3A662ULL,
		0x386DAFAA9319089DULL,
		0x916BA039A0A89BBBULL,
		0x1D9D3E2E653B1A53ULL,
		0x12CBFE3B9B47EE81ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x27CEFBDB7328A8FEULL,
		0x2FB36F2C7E8C8572ULL,
		0x07C802A37127FD7AULL,
		0x6C43C32A77874CC4ULL,
		0x70DB5F552632113AULL,
		0x22D7407341513776ULL,
		0x3B3A7C5CCA7634A7ULL,
		0x2597FC77368FDD02ULL
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
		0x237AE8D8FC87BAB1ULL,
		0x776CADCCFC64E9DDULL,
		0x880279352BC73BB0ULL,
		0x640D5A257224DEEBULL,
		0xB88B104295BDD751ULL,
		0x0E835A906C63B93EULL,
		0x37A791BFC1DC1B1FULL,
		0x0203EB2C59B32890ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x46F5D1B1F90F7562ULL,
		0xEED95B99F8C9D3BAULL,
		0x1004F26A578E7760ULL,
		0xC81AB44AE449BDD7ULL,
		0x711620852B7BAEA2ULL,
		0x1D06B520D8C7727DULL,
		0x6F4F237F83B8363EULL,
		0x0407D658B3665120ULL
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
		0x226B88CC1DD596D6ULL,
		0xECE49F1F51D93B4BULL,
		0x0AC5FE9D912EC7C5ULL,
		0x905822445EC683F1ULL,
		0x90B440A893425279ULL,
		0x7A19E8AEBE702E18ULL,
		0x42E1CD71B0FA8959ULL,
		0x287762406D8C1F04ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x44D711983BAB2DACULL,
		0xD9C93E3EA3B27696ULL,
		0x158BFD3B225D8F8BULL,
		0x20B04488BD8D07E2ULL,
		0x216881512684A4F3ULL,
		0xF433D15D7CE05C31ULL,
		0x85C39AE361F512B2ULL,
		0x50EEC480DB183E08ULL
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
		0xAD58F4A845FDCFC0ULL,
		0x3B2BEB955F0CA6C4ULL,
		0x6992B2F93719CB27ULL,
		0xCFF77106DAC6028CULL,
		0x830C12A85C3C3BFBULL,
		0x38D80A4CAE0DA3F7ULL,
		0xE9F90FF2C127F4EEULL,
		0x29F8CBE0A003EE1FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5AB1E9508BFB9F80ULL,
		0x7657D72ABE194D89ULL,
		0xD32565F26E33964EULL,
		0x9FEEE20DB58C0518ULL,
		0x06182550B87877F7ULL,
		0x71B014995C1B47EFULL,
		0xD3F21FE5824FE9DCULL,
		0x53F197C14007DC3FULL
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
		0x0EC38F8B47E7B311ULL,
		0x44F7EFA2AFB9C830ULL,
		0xD37C6CADAB7BC72FULL,
		0x4731B5A6AFF02ADAULL,
		0xC8B0FCD5956FD212ULL,
		0x0A120205FB387157ULL,
		0xB984A2092A91D819ULL,
		0x107220AC66EF1BF3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1D871F168FCF6622ULL,
		0x89EFDF455F739060ULL,
		0xA6F8D95B56F78E5EULL,
		0x8E636B4D5FE055B5ULL,
		0x9161F9AB2ADFA424ULL,
		0x1424040BF670E2AFULL,
		0x730944125523B032ULL,
		0x20E44158CDDE37E7ULL
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
		0xC532CA27D8A2B8CAULL,
		0x526C6F6E95C9845EULL,
		0x0F1F955A5037D140ULL,
		0xC402B3B55E0A9AA9ULL,
		0x04D4DFC7D2E88E8AULL,
		0x0BF5724DA7BC2930ULL,
		0x49E0727A8DAB3109ULL,
		0x1D8974A5329D82A5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8A65944FB1457194ULL,
		0xA4D8DEDD2B9308BDULL,
		0x1E3F2AB4A06FA280ULL,
		0x8805676ABC153552ULL,
		0x09A9BF8FA5D11D15ULL,
		0x17EAE49B4F785260ULL,
		0x93C0E4F51B566212ULL,
		0x3B12E94A653B054AULL
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
		0xCA8E8D0D65CD67C6ULL,
		0x4DCEDA6C2175219AULL,
		0xA0A5C64EAB1B2DA5ULL,
		0x9EDC8799D927F4B6ULL,
		0x125019DB6B676AFCULL,
		0xE56FA0FBFEA705A3ULL,
		0xAA221AADF88F1F94ULL,
		0x3257F40896659BFFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x951D1A1ACB9ACF8CULL,
		0x9B9DB4D842EA4335ULL,
		0x414B8C9D56365B4AULL,
		0x3DB90F33B24FE96DULL,
		0x24A033B6D6CED5F9ULL,
		0xCADF41F7FD4E0B46ULL,
		0x5444355BF11E3F29ULL,
		0x64AFE8112CCB37FFULL
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
		0x89267057E61BBD7AULL,
		0xE9149C5FCF7A27EDULL,
		0x503129C5039D02ABULL,
		0x11E7304EC35CF50CULL,
		0xE61E14D02F574A9BULL,
		0xEFD426EA36EC1E32ULL,
		0x5F7F4664D4552EF0ULL,
		0x22571B2A60772E4EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x124CE0AFCC377AF4ULL,
		0xD22938BF9EF44FDBULL,
		0xA062538A073A0557ULL,
		0x23CE609D86B9EA18ULL,
		0xCC3C29A05EAE9536ULL,
		0xDFA84DD46DD83C65ULL,
		0xBEFE8CC9A8AA5DE1ULL,
		0x44AE3654C0EE5C9CULL
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
		0x7A0103D3AE18AB30ULL,
		0xD1AD0B78A5035B34ULL,
		0xF341B39DE15954E0ULL,
		0x60A87DF5883F4E87ULL,
		0x8C1B38D661A22EDAULL,
		0xDC7457184E9112CBULL,
		0xF92958681140FBB8ULL,
		0x1DB2AC9FB0C55471ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF40207A75C315660ULL,
		0xA35A16F14A06B668ULL,
		0xE683673BC2B2A9C1ULL,
		0xC150FBEB107E9D0FULL,
		0x183671ACC3445DB4ULL,
		0xB8E8AE309D222597ULL,
		0xF252B0D02281F771ULL,
		0x3B65593F618AA8E3ULL
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
		0xA18BBEA17415FA6EULL,
		0xB075F7D97DDE5EB8ULL,
		0x76205296A80AB597ULL,
		0x49D3B4D40EF2A4C9ULL,
		0x59D26345E612875EULL,
		0x894BBE56F15498F5ULL,
		0x964EF684E06D9620ULL,
		0x1B20B43F1F8CF639ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x43177D42E82BF4DCULL,
		0x60EBEFB2FBBCBD71ULL,
		0xEC40A52D50156B2FULL,
		0x93A769A81DE54992ULL,
		0xB3A4C68BCC250EBCULL,
		0x12977CADE2A931EAULL,
		0x2C9DED09C0DB2C41ULL,
		0x3641687E3F19EC73ULL
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
		0x6D5E01646C0573FCULL,
		0x7482AB67A22783C8ULL,
		0x038B167AC4386194ULL,
		0xB7DBA222D49C43EAULL,
		0x2987BB6E666D0CEDULL,
		0x263CF00B400495D5ULL,
		0x18A00BCEC121931CULL,
		0x0D5A73558CDED060ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDABC02C8D80AE7F8ULL,
		0xE90556CF444F0790ULL,
		0x07162CF58870C328ULL,
		0x6FB74445A93887D4ULL,
		0x530F76DCCCDA19DBULL,
		0x4C79E01680092BAAULL,
		0x3140179D82432638ULL,
		0x1AB4E6AB19BDA0C0ULL
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
		0xB2399A9680250866ULL,
		0x237AC8E98230F156ULL,
		0x3E5D54FD50EBB4E5ULL,
		0x85CD6C239806CA3DULL,
		0xE4EF82CFA16F02CFULL,
		0x8119D96EF63A0E74ULL,
		0x17B9C7DC432D35FEULL,
		0x28154F0BDD33A6AEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6473352D004A10CCULL,
		0x46F591D30461E2ADULL,
		0x7CBAA9FAA1D769CAULL,
		0x0B9AD847300D947AULL,
		0xC9DF059F42DE059FULL,
		0x0233B2DDEC741CE9ULL,
		0x2F738FB8865A6BFDULL,
		0x502A9E17BA674D5CULL
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
		0x28E82AE2381FC026ULL,
		0x4398610F716A410EULL,
		0x3B8437EA93D45F9CULL,
		0x5644B150FAC6C25DULL,
		0x2D4E18E1C180127DULL,
		0x909E842B53F79746ULL,
		0x0D92E5B95EAC05D7ULL,
		0x0AB9EABBF5AB6C01ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x51D055C4703F804CULL,
		0x8730C21EE2D4821CULL,
		0x77086FD527A8BF38ULL,
		0xAC8962A1F58D84BAULL,
		0x5A9C31C3830024FAULL,
		0x213D0856A7EF2E8CULL,
		0x1B25CB72BD580BAFULL,
		0x1573D577EB56D802ULL
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
		0x655A5525750A938EULL,
		0x79BDE7162146F116ULL,
		0xEF42ABA4ECEE1138ULL,
		0x13F94A1ABD27AD8DULL,
		0x357F44BF3E20F5CEULL,
		0x216886ACB0BF8365ULL,
		0x7C6D32F2288C94C0ULL,
		0x1497EEFBD9407648ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCAB4AA4AEA15271CULL,
		0xF37BCE2C428DE22CULL,
		0xDE855749D9DC2270ULL,
		0x27F294357A4F5B1BULL,
		0x6AFE897E7C41EB9CULL,
		0x42D10D59617F06CAULL,
		0xF8DA65E451192980ULL,
		0x292FDDF7B280EC90ULL
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
		0x48A13946004BFB2EULL,
		0xEF6B8F709503000DULL,
		0x58326CB462DC3701ULL,
		0x4B6FB3E93334A9E2ULL,
		0x3D0AB31BC4D51036ULL,
		0x6BCE785F13E4531FULL,
		0x5D4E2924642DA82DULL,
		0x1B3240F1A85EEEB8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9142728C0097F65CULL,
		0xDED71EE12A06001AULL,
		0xB064D968C5B86E03ULL,
		0x96DF67D2666953C4ULL,
		0x7A15663789AA206CULL,
		0xD79CF0BE27C8A63EULL,
		0xBA9C5248C85B505AULL,
		0x366481E350BDDD70ULL
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
		0xD6E01AB62C33964BULL,
		0xFAF81454204FB4A0ULL,
		0xA09E77D2792F6E47ULL,
		0x641EC7A419048743ULL,
		0xBAC7F8F488C9D5ABULL,
		0x8DA97EE4B351F869ULL,
		0x83AECF8B9442B079ULL,
		0x1528FD1992447FACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xADC0356C58672C96ULL,
		0xF5F028A8409F6941ULL,
		0x413CEFA4F25EDC8FULL,
		0xC83D8F4832090E87ULL,
		0x758FF1E91193AB56ULL,
		0x1B52FDC966A3F0D3ULL,
		0x075D9F17288560F3ULL,
		0x2A51FA332488FF59ULL
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
		0x327995A9F511C022ULL,
		0xCD8A1F133A70E4C3ULL,
		0xDD1EA9282B8C1BA7ULL,
		0x8136D7817AE8B1D3ULL,
		0x3733793B960C67C3ULL,
		0x1631FB07A3565FF7ULL,
		0x9CDBA0E339C4546CULL,
		0x3EBDB61A4DF3C56EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x64F32B53EA238044ULL,
		0x9B143E2674E1C986ULL,
		0xBA3D52505718374FULL,
		0x026DAF02F5D163A7ULL,
		0x6E66F2772C18CF87ULL,
		0x2C63F60F46ACBFEEULL,
		0x39B741C67388A8D8ULL,
		0x7D7B6C349BE78ADDULL
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
		0xEFE6902B61FC5C79ULL,
		0x67B91B1E4489A96FULL,
		0xDB31C748D7AFF1DCULL,
		0x291E8A991BB4B92CULL,
		0x98D3A7A36873BA35ULL,
		0x31E5D2BEA6B55A2AULL,
		0x86C2D63235EF3C52ULL,
		0x1955775162C20689ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDFCD2056C3F8B8F2ULL,
		0xCF72363C891352DFULL,
		0xB6638E91AF5FE3B8ULL,
		0x523D153237697259ULL,
		0x31A74F46D0E7746AULL,
		0x63CBA57D4D6AB455ULL,
		0x0D85AC646BDE78A4ULL,
		0x32AAEEA2C5840D13ULL
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
		0xCC5A4E785ADA3C19ULL,
		0x8E1B7AADE40960FAULL,
		0x1E3266B53F497A88ULL,
		0x5227D1A1E91FFCB0ULL,
		0x6E2797F3A7392F05ULL,
		0x3DD0DF890EE4DF21ULL,
		0xB7AC898B784F4CFFULL,
		0x2A53EEB18E61E7EEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x98B49CF0B5B47832ULL,
		0x1C36F55BC812C1F5ULL,
		0x3C64CD6A7E92F511ULL,
		0xA44FA343D23FF960ULL,
		0xDC4F2FE74E725E0AULL,
		0x7BA1BF121DC9BE42ULL,
		0x6F591316F09E99FEULL,
		0x54A7DD631CC3CFDDULL
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
		0x208B20187DBD46ADULL,
		0xA89584F33E85022BULL,
		0xD124C4F4B0A09C8EULL,
		0xE7A170CB76818A9CULL,
		0x3FBE7FEC59F4B73BULL,
		0x706BA6FEB28EF0FBULL,
		0x497AC68939A0F475ULL,
		0x192288A5D8C8C02DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x41164030FB7A8D5AULL,
		0x512B09E67D0A0456ULL,
		0xA24989E96141391DULL,
		0xCF42E196ED031539ULL,
		0x7F7CFFD8B3E96E77ULL,
		0xE0D74DFD651DE1F6ULL,
		0x92F58D127341E8EAULL,
		0x3245114BB191805AULL
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
		0xCBF4ABFF2316E5BAULL,
		0xB89545E361DBF2EDULL,
		0x017EAB5C2ABA0DD0ULL,
		0x28A936F1479FB624ULL,
		0xF98D96D7B9DB8B45ULL,
		0x5B6D10CDE3D0F408ULL,
		0xD6F35FA6C92202A6ULL,
		0x12D5562E76720E90ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x97E957FE462DCB74ULL,
		0x712A8BC6C3B7E5DBULL,
		0x02FD56B855741BA1ULL,
		0x51526DE28F3F6C48ULL,
		0xF31B2DAF73B7168AULL,
		0xB6DA219BC7A1E811ULL,
		0xADE6BF4D9244054CULL,
		0x25AAAC5CECE41D21ULL
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
		0x733F3112A05EC50AULL,
		0x307F4508BEB53127ULL,
		0xCB9F598254922461ULL,
		0x93ACA6D97F517E1EULL,
		0xB25307B826D67DF5ULL,
		0x80C53D4AAF3F796BULL,
		0x1E2AAD4760FC8FE5ULL,
		0x298006BEF4AD65D3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE67E622540BD8A14ULL,
		0x60FE8A117D6A624EULL,
		0x973EB304A92448C2ULL,
		0x27594DB2FEA2FC3DULL,
		0x64A60F704DACFBEBULL,
		0x018A7A955E7EF2D7ULL,
		0x3C555A8EC1F91FCBULL,
		0x53000D7DE95ACBA6ULL
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
		0xEAB639EA75D6F771ULL,
		0x9AF1FD483072F386ULL,
		0x1DA76D8E96DF2730ULL,
		0x6A06661EF7FA4D00ULL,
		0xE8C527ED16F631D9ULL,
		0xE8EEF779C557632BULL,
		0xC99F342FEA24E7BCULL,
		0x20940FF7E3D22F38ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD56C73D4EBADEEE2ULL,
		0x35E3FA9060E5E70DULL,
		0x3B4EDB1D2DBE4E61ULL,
		0xD40CCC3DEFF49A00ULL,
		0xD18A4FDA2DEC63B2ULL,
		0xD1DDEEF38AAEC657ULL,
		0x933E685FD449CF79ULL,
		0x41281FEFC7A45E71ULL
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
		0x48AC0F7762D162A4ULL,
		0x5DB2D6307C6A6628ULL,
		0xB71A427790D48744ULL,
		0x9D707BF6A6598769ULL,
		0x120C8694F420B37EULL,
		0x399E60685078FF7EULL,
		0xFA4FE97DB0FCA668ULL,
		0x144A938371D50705ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x91581EEEC5A2C548ULL,
		0xBB65AC60F8D4CC50ULL,
		0x6E3484EF21A90E88ULL,
		0x3AE0F7ED4CB30ED3ULL,
		0x24190D29E84166FDULL,
		0x733CC0D0A0F1FEFCULL,
		0xF49FD2FB61F94CD0ULL,
		0x28952706E3AA0E0BULL
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
		0x99895E5DC695C78EULL,
		0x29FA6109F1E46A84ULL,
		0x876C2BC3323B51BCULL,
		0x23EAB5947FCD4B34ULL,
		0xAF01E0F34E2D7C5CULL,
		0x3883DCCF759E10A2ULL,
		0xEA32724E2EF0FAD3ULL,
		0x11A7ABD881C246CBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3312BCBB8D2B8F1CULL,
		0x53F4C213E3C8D509ULL,
		0x0ED857866476A378ULL,
		0x47D56B28FF9A9669ULL,
		0x5E03C1E69C5AF8B8ULL,
		0x7107B99EEB3C2145ULL,
		0xD464E49C5DE1F5A6ULL,
		0x234F57B103848D97ULL
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
		0xAC1B895EEB3518E9ULL,
		0xE1DACD1E7DC04312ULL,
		0xC12FD8F0C2E4B645ULL,
		0x42A81CD65E0DF634ULL,
		0x962F6F41EDE1E656ULL,
		0x6C6BE6E040997A60ULL,
		0x0DE34D16B4077435ULL,
		0x174975FC5A08A5EBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x583712BDD66A31D2ULL,
		0xC3B59A3CFB808625ULL,
		0x825FB1E185C96C8BULL,
		0x855039ACBC1BEC69ULL,
		0x2C5EDE83DBC3CCACULL,
		0xD8D7CDC08132F4C1ULL,
		0x1BC69A2D680EE86AULL,
		0x2E92EBF8B4114BD6ULL
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
		0x4A0181242FDA5D0AULL,
		0xCFA058E67B878BC3ULL,
		0x02BB14E72C6AD29DULL,
		0x855F0E7F82BA87A0ULL,
		0x18A6DCAEE19F3ED4ULL,
		0x0D9F0BB82AEE29FFULL,
		0xCEC2ED693B4EEC34ULL,
		0x0E433CAAC96B61F0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x940302485FB4BA14ULL,
		0x9F40B1CCF70F1786ULL,
		0x057629CE58D5A53BULL,
		0x0ABE1CFF05750F40ULL,
		0x314DB95DC33E7DA9ULL,
		0x1B3E177055DC53FEULL,
		0x9D85DAD2769DD868ULL,
		0x1C86795592D6C3E1ULL
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
		0xF061D290140E955DULL,
		0x70290742C8CCC833ULL,
		0x1A026FFBD13CD296ULL,
		0xE2003F13606541ABULL,
		0x349854D9C3800818ULL,
		0x8221460F00F2B3D7ULL,
		0x586CF6C5B1FD1DE0ULL,
		0x246EB23189890519ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE0C3A520281D2ABAULL,
		0xE0520E8591999067ULL,
		0x3404DFF7A279A52CULL,
		0xC4007E26C0CA8356ULL,
		0x6930A9B387001031ULL,
		0x04428C1E01E567AEULL,
		0xB0D9ED8B63FA3BC1ULL,
		0x48DD646313120A32ULL
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
		0x2CEDB0BCA302DCC5ULL,
		0xAD741749231685EFULL,
		0x60BAB4A27811F65AULL,
		0xCBF67B71B9305F84ULL,
		0xD839F8AB7F1BEE6EULL,
		0x05590896E12A7A6FULL,
		0xEF37D171735D7436ULL,
		0x37D817F5230B254DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x59DB61794605B98AULL,
		0x5AE82E92462D0BDEULL,
		0xC1756944F023ECB5ULL,
		0x97ECF6E37260BF08ULL,
		0xB073F156FE37DCDDULL,
		0x0AB2112DC254F4DFULL,
		0xDE6FA2E2E6BAE86CULL,
		0x6FB02FEA46164A9BULL
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
		0x152A21B030A3C11DULL,
		0xF6919E370978A795ULL,
		0x5D660A1E1528A0C6ULL,
		0x3A74894482E9BB52ULL,
		0xC3B1362ADF59A39DULL,
		0xF32265BC93D280ACULL,
		0xF9750F31A74CA9E3ULL,
		0x1C65B1F9C5CB9AABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2A5443606147823AULL,
		0xED233C6E12F14F2AULL,
		0xBACC143C2A51418DULL,
		0x74E9128905D376A4ULL,
		0x87626C55BEB3473AULL,
		0xE644CB7927A50159ULL,
		0xF2EA1E634E9953C7ULL,
		0x38CB63F38B973557ULL
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
		0xC74104318400082FULL,
		0x5178F91A093B872EULL,
		0xFDD80E57E508F017ULL,
		0xF1BDE801BBB21DBEULL,
		0x9C5C72339C6F0F10ULL,
		0x7A1259D4E0EC1257ULL,
		0xDFF41F88C01B3174ULL,
		0x24E250DB8E3C2718ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8E8208630800105EULL,
		0xA2F1F23412770E5DULL,
		0xFBB01CAFCA11E02EULL,
		0xE37BD00377643B7DULL,
		0x38B8E46738DE1E21ULL,
		0xF424B3A9C1D824AFULL,
		0xBFE83F11803662E8ULL,
		0x49C4A1B71C784E31ULL
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
		0x4F3CDDFD2A5637CAULL,
		0x084B300BA74C52F9ULL,
		0x6B5AE24EF2204702ULL,
		0x648E253746EB3BECULL,
		0x2CFDB798FCADE8D7ULL,
		0x23E8F910213F1411ULL,
		0x203BE63F5F2D9119ULL,
		0x00017A773F3BDDB0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9E79BBFA54AC6F94ULL,
		0x109660174E98A5F2ULL,
		0xD6B5C49DE4408E04ULL,
		0xC91C4A6E8DD677D8ULL,
		0x59FB6F31F95BD1AEULL,
		0x47D1F220427E2822ULL,
		0x4077CC7EBE5B2232ULL,
		0x0002F4EE7E77BB60ULL
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
		0x6AE8BD3A55AB6961ULL,
		0x73C72F27A294C7A5ULL,
		0xCEBCE38685110C40ULL,
		0xFE4CF973A4BD0DECULL,
		0x4AFDEED11B2BF48AULL,
		0x0F44551844E1F689ULL,
		0x78AC1F28C8EA0B27ULL,
		0x09C673E5DE98459CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD5D17A74AB56D2C2ULL,
		0xE78E5E4F45298F4AULL,
		0x9D79C70D0A221880ULL,
		0xFC99F2E7497A1BD9ULL,
		0x95FBDDA23657E915ULL,
		0x1E88AA3089C3ED12ULL,
		0xF1583E5191D4164EULL,
		0x138CE7CBBD308B38ULL
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
		0xFC6A3FD6D611714EULL,
		0xA44DF38564140F86ULL,
		0x22DE17CF95D459DFULL,
		0x0EE913B7618C876FULL,
		0x0D089CE888139EC0ULL,
		0x13A52C9ABC2B4ED3ULL,
		0x9970A0F0422F64CEULL,
		0x1F723CB4A5C318D8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF8D47FADAC22E29CULL,
		0x489BE70AC8281F0DULL,
		0x45BC2F9F2BA8B3BFULL,
		0x1DD2276EC3190EDEULL,
		0x1A1139D110273D80ULL,
		0x274A593578569DA6ULL,
		0x32E141E0845EC99CULL,
		0x3EE479694B8631B1ULL
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
		0x5ED2F6FE0DBC6EDEULL,
		0x084D6298CCB85FD3ULL,
		0x04530D2205E7F9CCULL,
		0x5D00FADD5D8B11D4ULL,
		0x87E740C792EA6429ULL,
		0xC065E48497DB3997ULL,
		0xD379C1326D88694DULL,
		0x182A2BADB24AE044ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBDA5EDFC1B78DDBCULL,
		0x109AC5319970BFA6ULL,
		0x08A61A440BCFF398ULL,
		0xBA01F5BABB1623A8ULL,
		0x0FCE818F25D4C852ULL,
		0x80CBC9092FB6732FULL,
		0xA6F38264DB10D29BULL,
		0x3054575B6495C089ULL
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
		0xF28C61D38EFE2F8FULL,
		0x394A7732B484A5A6ULL,
		0x99E32688A5671A2EULL,
		0xA29630612977F01BULL,
		0x25C94DFBFAC4919FULL,
		0xF51F66E3346EFD53ULL,
		0x686C167484E5BCABULL,
		0x076F4C1C50C37C65ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE518C3A71DFC5F1EULL,
		0x7294EE6569094B4DULL,
		0x33C64D114ACE345CULL,
		0x452C60C252EFE037ULL,
		0x4B929BF7F589233FULL,
		0xEA3ECDC668DDFAA6ULL,
		0xD0D82CE909CB7957ULL,
		0x0EDE9838A186F8CAULL
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
		0xA7F4BCF0E4B81A9FULL,
		0xB9CF6DECF86A4ABCULL,
		0xED1826F477783425ULL,
		0x74CDD99E3891A6A2ULL,
		0x84A45B6473E587F7ULL,
		0x46A620C7DE5BF583ULL,
		0x0536D8268E4DF272ULL,
		0x10127F31431385E3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4FE979E1C970353EULL,
		0x739EDBD9F0D49579ULL,
		0xDA304DE8EEF0684BULL,
		0xE99BB33C71234D45ULL,
		0x0948B6C8E7CB0FEEULL,
		0x8D4C418FBCB7EB07ULL,
		0x0A6DB04D1C9BE4E4ULL,
		0x2024FE6286270BC6ULL
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
		0xA2716A256752FA8BULL,
		0x241BC104C6B57269ULL,
		0x77ADE6F46A43BAE8ULL,
		0xCCB3DED886DBA93CULL,
		0x67E117665741ADE9ULL,
		0x78868969D30E5366ULL,
		0x20A84B3F2AFC171CULL,
		0x19ED69B35C370122ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x44E2D44ACEA5F516ULL,
		0x483782098D6AE4D3ULL,
		0xEF5BCDE8D48775D0ULL,
		0x9967BDB10DB75278ULL,
		0xCFC22ECCAE835BD3ULL,
		0xF10D12D3A61CA6CCULL,
		0x4150967E55F82E38ULL,
		0x33DAD366B86E0244ULL
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
		0xBCEAB0F2E263C715ULL,
		0xFF0608F967B3123DULL,
		0x14D172B2ACF5A7C7ULL,
		0x276A27E50F135DF2ULL,
		0xD9E2464F129B6652ULL,
		0x162A96D18C8E4286ULL,
		0x216BB2C88B4A3737ULL,
		0x347ECA75B4BE98C8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x79D561E5C4C78E2AULL,
		0xFE0C11F2CF66247BULL,
		0x29A2E56559EB4F8FULL,
		0x4ED44FCA1E26BBE4ULL,
		0xB3C48C9E2536CCA4ULL,
		0x2C552DA3191C850DULL,
		0x42D7659116946E6EULL,
		0x68FD94EB697D3190ULL
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
		0x31F314734F56A29DULL,
		0x76E8D39261C5B2CDULL,
		0x95685CB84BD9D87AULL,
		0x8F3E07DE64ED3F1DULL,
		0x305DF0280C82A24AULL,
		0x4476FDB416EDF336ULL,
		0x078C9B8DBDF38952ULL,
		0x11D1CED96F98CFC6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x63E628E69EAD453AULL,
		0xEDD1A724C38B659AULL,
		0x2AD0B97097B3B0F4ULL,
		0x1E7C0FBCC9DA7E3BULL,
		0x60BBE05019054495ULL,
		0x88EDFB682DDBE66CULL,
		0x0F19371B7BE712A4ULL,
		0x23A39DB2DF319F8CULL
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
		0x3F3BE6C52830E0A8ULL,
		0x4DA9AD7639E6B30AULL,
		0xD9EDDAE83D8FDC1DULL,
		0xBAC903AA48F79120ULL,
		0x14F5AFE9E3EB7ECAULL,
		0xF073771B0B1F183EULL,
		0xD480B41AF10DE826ULL,
		0x3A9EE348E9813CEEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7E77CD8A5061C150ULL,
		0x9B535AEC73CD6614ULL,
		0xB3DBB5D07B1FB83AULL,
		0x7592075491EF2241ULL,
		0x29EB5FD3C7D6FD95ULL,
		0xE0E6EE36163E307CULL,
		0xA9016835E21BD04DULL,
		0x753DC691D30279DDULL
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
		0x2507757CFD8DE158ULL,
		0xCCCF6663EE804993ULL,
		0x869054CD7C300692ULL,
		0xBBB22E685ADECF1FULL,
		0x5F6C2FAB1B615CA1ULL,
		0x6B0C09488034D48AULL,
		0x81FA7D2F2FFAECA5ULL,
		0x319538A59B351838ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4A0EEAF9FB1BC2B0ULL,
		0x999ECCC7DD009326ULL,
		0x0D20A99AF8600D25ULL,
		0x77645CD0B5BD9E3FULL,
		0xBED85F5636C2B943ULL,
		0xD61812910069A914ULL,
		0x03F4FA5E5FF5D94AULL,
		0x632A714B366A3071ULL
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
		0x71E1D7098C1004ECULL,
		0xF09633100355BE5AULL,
		0x50E8AE4EBC3C10CFULL,
		0x0030C32868EC4EDBULL,
		0x5E866A1A59F34E4CULL,
		0x9C513D2FF241BEE8ULL,
		0xD85167B7C1F4051EULL,
		0x148FA54675BB5EDBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE3C3AE13182009D8ULL,
		0xE12C662006AB7CB4ULL,
		0xA1D15C9D7878219FULL,
		0x00618650D1D89DB6ULL,
		0xBD0CD434B3E69C98ULL,
		0x38A27A5FE4837DD0ULL,
		0xB0A2CF6F83E80A3DULL,
		0x291F4A8CEB76BDB7ULL
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
		0xAF055768C237E5A5ULL,
		0xD280532D60CC8AB3ULL,
		0xD25E0D06B0C23873ULL,
		0x7B3F30A7D6695CBCULL,
		0x65DC345A4FB7A0DFULL,
		0xCD0443146FDD9C2EULL,
		0x00BAE01BEACEB708ULL,
		0x2431F6FC6119CDDAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5E0AAED1846FCB4AULL,
		0xA500A65AC1991567ULL,
		0xA4BC1A0D618470E7ULL,
		0xF67E614FACD2B979ULL,
		0xCBB868B49F6F41BEULL,
		0x9A088628DFBB385CULL,
		0x0175C037D59D6E11ULL,
		0x4863EDF8C2339BB4ULL
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
		0xCC91D4222B0E3EDAULL,
		0xAE2544096C9FA01DULL,
		0xC2CC9B86D24BCF7DULL,
		0x51528C1923F4A9A3ULL,
		0xF0091AFF9B6B914BULL,
		0xAEF5670E6F635BEEULL,
		0x015F38F30E63B374ULL,
		0x3AB2A276B62FE815ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9923A844561C7DB4ULL,
		0x5C4A8812D93F403BULL,
		0x8599370DA4979EFBULL,
		0xA2A5183247E95347ULL,
		0xE01235FF36D72296ULL,
		0x5DEACE1CDEC6B7DDULL,
		0x02BE71E61CC766E9ULL,
		0x756544ED6C5FD02AULL
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
		0x7AE5DF0DC5682F78ULL,
		0x6D9C08002A1EB90DULL,
		0xC70AB6574D0D1382ULL,
		0x0A1AE85EE5DB87B1ULL,
		0x88ED40A122BE5A19ULL,
		0xBF0725264E3C5E02ULL,
		0xBA6EF4764FEA4B46ULL,
		0x3348A7EBBE6DE702ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF5CBBE1B8AD05EF0ULL,
		0xDB381000543D721AULL,
		0x8E156CAE9A1A2704ULL,
		0x1435D0BDCBB70F63ULL,
		0x11DA8142457CB432ULL,
		0x7E0E4A4C9C78BC05ULL,
		0x74DDE8EC9FD4968DULL,
		0x66914FD77CDBCE05ULL
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
		0xCC52C7B33075CEA3ULL,
		0x5A6CFAB6FEE381EAULL,
		0x01F10C184A45AEFCULL,
		0x84FC2855A4E9AD37ULL,
		0xA17C9051D964851BULL,
		0x992A00B8C666497FULL,
		0x65065119EB29F7F0ULL,
		0x0DC92311AE12B2FBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x98A58F6660EB9D46ULL,
		0xB4D9F56DFDC703D5ULL,
		0x03E21830948B5DF8ULL,
		0x09F850AB49D35A6EULL,
		0x42F920A3B2C90A37ULL,
		0x325401718CCC92FFULL,
		0xCA0CA233D653EFE1ULL,
		0x1B9246235C2565F6ULL
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
		0xDE8CE1A328F2F156ULL,
		0x47451B89E591047DULL,
		0x6BA19A2FC76652BAULL,
		0x056E9F61F56480E0ULL,
		0xD70286F29B6DC04BULL,
		0xCA2E5CF2A9DA2B39ULL,
		0xE653F46DEDC41F4AULL,
		0x0D3489D3F0C4E7EDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBD19C34651E5E2ACULL,
		0x8E8A3713CB2208FBULL,
		0xD743345F8ECCA574ULL,
		0x0ADD3EC3EAC901C0ULL,
		0xAE050DE536DB8096ULL,
		0x945CB9E553B45673ULL,
		0xCCA7E8DBDB883E95ULL,
		0x1A6913A7E189CFDBULL
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
		0x1F4A9214D57D6852ULL,
		0x54A9A758256EAD53ULL,
		0xFB747CDA29025C4CULL,
		0xA238BBD626349256ULL,
		0xEA394668423E4A61ULL,
		0xC3355ECA8C0E019CULL,
		0xC0CEF5766B2D77BEULL,
		0x090A81D4622429F3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3E952429AAFAD0A4ULL,
		0xA9534EB04ADD5AA6ULL,
		0xF6E8F9B45204B898ULL,
		0x447177AC4C6924ADULL,
		0xD4728CD0847C94C3ULL,
		0x866ABD95181C0339ULL,
		0x819DEAECD65AEF7DULL,
		0x121503A8C44853E7ULL
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
		0x87EB48CC8B9F239BULL,
		0x1111D1F0228F0195ULL,
		0x9AFB841F9A6201EDULL,
		0x95831465F1AF22A8ULL,
		0xC8FF2ADA194E6AADULL,
		0x7879359AD9833366ULL,
		0x55E4E95A56EA2E40ULL,
		0x00EB0C23D6455AFBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0FD69199173E4736ULL,
		0x2223A3E0451E032BULL,
		0x35F7083F34C403DAULL,
		0x2B0628CBE35E4551ULL,
		0x91FE55B4329CD55BULL,
		0xF0F26B35B30666CDULL,
		0xABC9D2B4ADD45C80ULL,
		0x01D61847AC8AB5F6ULL
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
		0x4608B0F37A5CCDF4ULL,
		0x33973FB2CAE5487FULL,
		0x9349FE23138064D8ULL,
		0x95EF6983133FB5F8ULL,
		0x88E73A8B416F785AULL,
		0x03F9B163B4EC884BULL,
		0xB68D8A8E190C9197ULL,
		0x30BA0B827E1F7DBCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8C1161E6F4B99BE8ULL,
		0x672E7F6595CA90FEULL,
		0x2693FC462700C9B0ULL,
		0x2BDED306267F6BF1ULL,
		0x11CE751682DEF0B5ULL,
		0x07F362C769D91097ULL,
		0x6D1B151C3219232EULL,
		0x61741704FC3EFB79ULL
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
		0xD439DB835476E81AULL,
		0x75256EAB86BDADCEULL,
		0x50CAC5C954E92BC6ULL,
		0x3F094EBDB4AE7240ULL,
		0x717BCC80C0F6AE7BULL,
		0x301AA001CA5D8E65ULL,
		0xE88C58BAE2B5501DULL,
		0x33B8961FBA405CB2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA873B706A8EDD034ULL,
		0xEA4ADD570D7B5B9DULL,
		0xA1958B92A9D2578CULL,
		0x7E129D7B695CE480ULL,
		0xE2F7990181ED5CF6ULL,
		0x6035400394BB1CCAULL,
		0xD118B175C56AA03AULL,
		0x67712C3F7480B965ULL
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
		0x94E0EB3DE354B470ULL,
		0xB45132116A4D254DULL,
		0xDE261973AF713467ULL,
		0x5E092292D54E4950ULL,
		0xCE393FD408537C2BULL,
		0x2608E98EC216B108ULL,
		0x19A5968942FEAE3CULL,
		0x28F62363CCE32B5EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x29C1D67BC6A968E0ULL,
		0x68A26422D49A4A9BULL,
		0xBC4C32E75EE268CFULL,
		0xBC124525AA9C92A1ULL,
		0x9C727FA810A6F856ULL,
		0x4C11D31D842D6211ULL,
		0x334B2D1285FD5C78ULL,
		0x51EC46C799C656BCULL
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
		0xE131BB0419EFA597ULL,
		0x2ED015EE6D9EF419ULL,
		0x28B14E8E93442D82ULL,
		0x54E32FF5D62CB2F3ULL,
		0xD4764148895331DAULL,
		0xD1FD0406627824D9ULL,
		0x6C8C537074B216A1ULL,
		0x11044212FB7D43CDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC263760833DF4B2EULL,
		0x5DA02BDCDB3DE833ULL,
		0x51629D1D26885B04ULL,
		0xA9C65FEBAC5965E6ULL,
		0xA8EC829112A663B4ULL,
		0xA3FA080CC4F049B3ULL,
		0xD918A6E0E9642D43ULL,
		0x22088425F6FA879AULL
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
		0x77791B67D4B7F944ULL,
		0x4C3E40AD00D6D23CULL,
		0x100CB9717D5451ADULL,
		0x3868B7A1C3EB3C3EULL,
		0x3CD5BE7FCF2F053AULL,
		0xD47A41DADC7ED540ULL,
		0xDFA5B8875F0F47EEULL,
		0x011869C1EBDBD0D6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEEF236CFA96FF288ULL,
		0x987C815A01ADA478ULL,
		0x201972E2FAA8A35AULL,
		0x70D16F4387D6787CULL,
		0x79AB7CFF9E5E0A74ULL,
		0xA8F483B5B8FDAA80ULL,
		0xBF4B710EBE1E8FDDULL,
		0x0230D383D7B7A1ADULL
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
		0x08419138465CE4BFULL,
		0x8542A6C9CF28AE0DULL,
		0x59599ED880732AD6ULL,
		0xA82E02B5D04ABEEDULL,
		0x183A79FEDBF4E42FULL,
		0x7C1B987804672B51ULL,
		0x5CA6D96E07137A57ULL,
		0x38B08A4845FA449FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x108322708CB9C97EULL,
		0x0A854D939E515C1AULL,
		0xB2B33DB100E655ADULL,
		0x505C056BA0957DDAULL,
		0x3074F3FDB7E9C85FULL,
		0xF83730F008CE56A2ULL,
		0xB94DB2DC0E26F4AEULL,
		0x716114908BF4893EULL
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
		0x794ACDC16A40B3E1ULL,
		0x4EB52ED7D1238F79ULL,
		0xC21254E28CEFA4C1ULL,
		0x13B5C3790653AE07ULL,
		0x10CFA8D0C0D3DA02ULL,
		0xB994868142912D23ULL,
		0xEF294FA7A72F4F31ULL,
		0x191E8C3A93180D3DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF2959B82D48167C2ULL,
		0x9D6A5DAFA2471EF2ULL,
		0x8424A9C519DF4982ULL,
		0x276B86F20CA75C0FULL,
		0x219F51A181A7B404ULL,
		0x73290D0285225A46ULL,
		0xDE529F4F4E5E9E63ULL,
		0x323D187526301A7BULL
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
		0x6F9188AD18A730BDULL,
		0x0450EF5827F94C3EULL,
		0xDF9E5BDC670FECFFULL,
		0xF83EB9E90D23CE51ULL,
		0x3E8AF981D63C03EAULL,
		0x2D31280804558F0AULL,
		0x5E07BAAA7B2279D5ULL,
		0x3E1E9BF1DA36AB92ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDF23115A314E617AULL,
		0x08A1DEB04FF2987CULL,
		0xBF3CB7B8CE1FD9FEULL,
		0xF07D73D21A479CA3ULL,
		0x7D15F303AC7807D5ULL,
		0x5A62501008AB1E14ULL,
		0xBC0F7554F644F3AAULL,
		0x7C3D37E3B46D5724ULL
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
		0x0B21311120A6A5C8ULL,
		0x519084E792DA399CULL,
		0xF0FA019A6E16899DULL,
		0xF54712D42AB7A97CULL,
		0x5F9219DF3A4C682EULL,
		0x1B9CE938D06B9D6CULL,
		0x086A1CE3F0F6B022ULL,
		0x1A81E8441F88CE82ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x16426222414D4B90ULL,
		0xA32109CF25B47338ULL,
		0xE1F40334DC2D133AULL,
		0xEA8E25A8556F52F9ULL,
		0xBF2433BE7498D05DULL,
		0x3739D271A0D73AD8ULL,
		0x10D439C7E1ED6044ULL,
		0x3503D0883F119D04ULL
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
		0x5E1C2394D2CF0016ULL,
		0xFBF87EE316EB72B1ULL,
		0xBE111F2F7E373E31ULL,
		0x6B14A45D513958CDULL,
		0xB2AB1C5A25D377BBULL,
		0xED419D584C76AA07ULL,
		0x3C1BDF44E94AE945ULL,
		0x033D67416F315814ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBC384729A59E002CULL,
		0xF7F0FDC62DD6E562ULL,
		0x7C223E5EFC6E7C63ULL,
		0xD62948BAA272B19BULL,
		0x655638B44BA6EF76ULL,
		0xDA833AB098ED540FULL,
		0x7837BE89D295D28BULL,
		0x067ACE82DE62B028ULL
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
		0xF64D5ACF48C1DE3AULL,
		0x823A5E9B0B4DBA34ULL,
		0x3023723F1D163F10ULL,
		0x64215A0CD0D69581ULL,
		0xCE48E284A653F966ULL,
		0x47469DFE855F0F09ULL,
		0xF51ED5DD827509FCULL,
		0x365E63D9D3E1A23EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEC9AB59E9183BC74ULL,
		0x0474BD36169B7469ULL,
		0x6046E47E3A2C7E21ULL,
		0xC842B419A1AD2B02ULL,
		0x9C91C5094CA7F2CCULL,
		0x8E8D3BFD0ABE1E13ULL,
		0xEA3DABBB04EA13F8ULL,
		0x6CBCC7B3A7C3447DULL
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
		0x70724B67071BECB4ULL,
		0x1AE3A818BBCCEACFULL,
		0x0F893B042833A5F6ULL,
		0x2703BCD8852EC5D5ULL,
		0x2385D4AECC6B9D7AULL,
		0x1858E35C1BEBAEE1ULL,
		0xF3824749BD450F47ULL,
		0x056CA617B50C1C9EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE0E496CE0E37D968ULL,
		0x35C750317799D59EULL,
		0x1F12760850674BECULL,
		0x4E0779B10A5D8BAAULL,
		0x470BA95D98D73AF4ULL,
		0x30B1C6B837D75DC2ULL,
		0xE7048E937A8A1E8EULL,
		0x0AD94C2F6A18393DULL
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
		0x232FA30E139D47F9ULL,
		0xAC235BFD61BE07B8ULL,
		0xF00D52B455EE2E6CULL,
		0xE4EAE0C430E46DD7ULL,
		0x2F3ABDA54998E1E3ULL,
		0x38A8F16661349DD2ULL,
		0x8AE2D19FE9DFD4E6ULL,
		0x3BA41413B62B5FEFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x465F461C273A8FF2ULL,
		0x5846B7FAC37C0F70ULL,
		0xE01AA568ABDC5CD9ULL,
		0xC9D5C18861C8DBAFULL,
		0x5E757B4A9331C3C7ULL,
		0x7151E2CCC2693BA4ULL,
		0x15C5A33FD3BFA9CCULL,
		0x774828276C56BFDFULL
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
		0xBA74FC90544D4189ULL,
		0x99C3105CE98FA909ULL,
		0x7A8F797F11536C6EULL,
		0xE39C28F0760FCF00ULL,
		0x8B5CBEFF3C1524FDULL,
		0x2F57665C801BE1B4ULL,
		0x3A09E150B00C2007ULL,
		0x1B1E6E3DB1229CA7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x74E9F920A89A8312ULL,
		0x338620B9D31F5213ULL,
		0xF51EF2FE22A6D8DDULL,
		0xC73851E0EC1F9E00ULL,
		0x16B97DFE782A49FBULL,
		0x5EAECCB90037C369ULL,
		0x7413C2A16018400EULL,
		0x363CDC7B6245394EULL
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
		0x61FF41A4C64D089CULL,
		0x973B88D3AA6EED03ULL,
		0x8ABEE57213DE8852ULL,
		0x050BC66D665BE4B6ULL,
		0x1AB7C670D3BC7BFBULL,
		0xD36C68096D8B00AEULL,
		0x804771DC44CDB736ULL,
		0x04D1215ED3F09C74ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC3FE83498C9A1138ULL,
		0x2E7711A754DDDA06ULL,
		0x157DCAE427BD10A5ULL,
		0x0A178CDACCB7C96DULL,
		0x356F8CE1A778F7F6ULL,
		0xA6D8D012DB16015CULL,
		0x008EE3B8899B6E6DULL,
		0x09A242BDA7E138E9ULL
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
		0xE63CD9A51D03D5F6ULL,
		0x7390CCE067FCA600ULL,
		0xAC09B564E263B938ULL,
		0x73C2AD950E08AFF4ULL,
		0xACC7E1B1E0DD5006ULL,
		0xB61F0E3BDABE3336ULL,
		0x59086BE5CA849953ULL,
		0x2997C72215111A3EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCC79B34A3A07ABECULL,
		0xE72199C0CFF94C01ULL,
		0x58136AC9C4C77270ULL,
		0xE7855B2A1C115FE9ULL,
		0x598FC363C1BAA00CULL,
		0x6C3E1C77B57C666DULL,
		0xB210D7CB950932A7ULL,
		0x532F8E442A22347CULL
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
		0xD2143BA7F2295C1EULL,
		0x4FDEF87E60637B30ULL,
		0x928E0E6DED2FBD33ULL,
		0x188F39E4F33D64C3ULL,
		0xCA609AE79282AE2CULL,
		0x0457776C9760A24BULL,
		0x9B119D7D764A5427ULL,
		0x3CD24316D8D07D65ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA428774FE452B83CULL,
		0x9FBDF0FCC0C6F661ULL,
		0x251C1CDBDA5F7A66ULL,
		0x311E73C9E67AC987ULL,
		0x94C135CF25055C58ULL,
		0x08AEEED92EC14497ULL,
		0x36233AFAEC94A84EULL,
		0x79A4862DB1A0FACBULL
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
		0xC015F33FE3903407ULL,
		0x4D07844BA9659428ULL,
		0xACB959FD4BF7E6F3ULL,
		0x39DE42B9441F9FD2ULL,
		0x08A7584AFB214131ULL,
		0x64C7A68F87E23A9CULL,
		0xF78103E92E62A793ULL,
		0x36512D810C99F3D1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x802BE67FC720680EULL,
		0x9A0F089752CB2851ULL,
		0x5972B3FA97EFCDE6ULL,
		0x73BC8572883F3FA5ULL,
		0x114EB095F6428262ULL,
		0xC98F4D1F0FC47538ULL,
		0xEF0207D25CC54F26ULL,
		0x6CA25B021933E7A3ULL
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
		0xA61683FBCB7A8139ULL,
		0x5FA53D0FC515BD01ULL,
		0x5127A6FD1986AAF2ULL,
		0x4B88A6FFC597A022ULL,
		0xE739A66F5732CF14ULL,
		0xB53A82EE04F11C74ULL,
		0x1A1D65740AF1A709ULL,
		0x2DD7002B0E337A88ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4C2D07F796F50272ULL,
		0xBF4A7A1F8A2B7A03ULL,
		0xA24F4DFA330D55E4ULL,
		0x97114DFF8B2F4044ULL,
		0xCE734CDEAE659E28ULL,
		0x6A7505DC09E238E9ULL,
		0x343ACAE815E34E13ULL,
		0x5BAE00561C66F510ULL
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
		0xC3E6406962B2803BULL,
		0xC9F7D6BF4BEE9346ULL,
		0xF23DEC614CBDF0D7ULL,
		0xAF014086E3ED4CD5ULL,
		0x713F9A86CAF90CEBULL,
		0x11350AA66BBB45F8ULL,
		0xD61418469D48A491ULL,
		0x265E38FA646999EBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x87CC80D2C5650076ULL,
		0x93EFAD7E97DD268DULL,
		0xE47BD8C2997BE1AFULL,
		0x5E02810DC7DA99ABULL,
		0xE27F350D95F219D7ULL,
		0x226A154CD7768BF0ULL,
		0xAC28308D3A914922ULL,
		0x4CBC71F4C8D333D7ULL
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
		0xFD0E1FB793D95461ULL,
		0xBD32DB787D7BB383ULL,
		0x2399337CA8FE74A9ULL,
		0x202BCC4708EAF103ULL,
		0x239CE9929A27957CULL,
		0x0886CAB7B101EBA1ULL,
		0xC0F9F9061F7C7064ULL,
		0x344E331CE056E497ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFA1C3F6F27B2A8C2ULL,
		0x7A65B6F0FAF76707ULL,
		0x473266F951FCE953ULL,
		0x4057988E11D5E206ULL,
		0x4739D325344F2AF8ULL,
		0x110D956F6203D742ULL,
		0x81F3F20C3EF8E0C8ULL,
		0x689C6639C0ADC92FULL
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
		0x00F7CB0FB0456BBCULL,
		0xC9BB0631B86CEB84ULL,
		0xA2C7EFD024700F48ULL,
		0x3A2212942676BCA1ULL,
		0x2DD8ACBE3D9B84EAULL,
		0x324996701B3B6F45ULL,
		0xB64596139B1365EFULL,
		0x28F542116281CCCCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x01EF961F608AD778ULL,
		0x93760C6370D9D708ULL,
		0x458FDFA048E01E91ULL,
		0x744425284CED7943ULL,
		0x5BB1597C7B3709D4ULL,
		0x64932CE03676DE8AULL,
		0x6C8B2C273626CBDEULL,
		0x51EA8422C5039999ULL
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
		0x3B5C98496F8B87AFULL,
		0x49B17C1182846CF9ULL,
		0x79A0D88DA7C84997ULL,
		0xB984531B43FD293AULL,
		0xD1167338402C0AFAULL,
		0xB04D14857CC3984CULL,
		0x2F32526E10336061ULL,
		0x39A0469B9C2AF6C4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x76B93092DF170F5EULL,
		0x9362F8230508D9F2ULL,
		0xF341B11B4F90932EULL,
		0x7308A63687FA5274ULL,
		0xA22CE670805815F5ULL,
		0x609A290AF9873099ULL,
		0x5E64A4DC2066C0C3ULL,
		0x73408D373855ED88ULL
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
		0x8574164AB86CC58EULL,
		0xCAABF715CEC6EDEEULL,
		0x504C188A8DFA9CF6ULL,
		0x9921F63445F8B7A4ULL,
		0x3FD9204CABA03215ULL,
		0x32C9B7E3E1ACBCB4ULL,
		0xB60B123A2816B903ULL,
		0x1E2CF1C87C97122AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0AE82C9570D98B1CULL,
		0x9557EE2B9D8DDBDDULL,
		0xA09831151BF539EDULL,
		0x3243EC688BF16F48ULL,
		0x7FB240995740642BULL,
		0x65936FC7C3597968ULL,
		0x6C162474502D7206ULL,
		0x3C59E390F92E2455ULL
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
		0x5FAFC4F9C3D44746ULL,
		0x2DAF231AB7CAD779ULL,
		0x590542053608D6A6ULL,
		0xDF1F118549C25107ULL,
		0xB0C630E84B681BA0ULL,
		0xBAE0814A7C0598D7ULL,
		0x50266E741DB23CC4ULL,
		0x238155DE991A81EEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBF5F89F387A88E8CULL,
		0x5B5E46356F95AEF2ULL,
		0xB20A840A6C11AD4CULL,
		0xBE3E230A9384A20EULL,
		0x618C61D096D03741ULL,
		0x75C10294F80B31AFULL,
		0xA04CDCE83B647989ULL,
		0x4702ABBD323503DCULL
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
		0x313D895A50DDD76BULL,
		0x9EC182FF0FF48B83ULL,
		0x7EDF2E48B78018C2ULL,
		0x62A23B558A03B27FULL,
		0x2AA62A7D9AD81236ULL,
		0xCACAF92BE491CD0BULL,
		0xA004F6009CFCEF05ULL,
		0x0B404BCE69631C38ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x627B12B4A1BBAED6ULL,
		0x3D8305FE1FE91706ULL,
		0xFDBE5C916F003185ULL,
		0xC54476AB140764FEULL,
		0x554C54FB35B0246CULL,
		0x9595F257C9239A16ULL,
		0x4009EC0139F9DE0BULL,
		0x1680979CD2C63871ULL
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
		0x45E8250CCD1130B8ULL,
		0x8D87790A2ADAA64DULL,
		0xDA9E18FC63962B6FULL,
		0x5EE709BB2BFDF1F0ULL,
		0x30D21748FF1D26F6ULL,
		0x7A84AB35B601EFDAULL,
		0x7569EF5B71FC3B97ULL,
		0x389D5A229D879A75ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8BD04A199A226170ULL,
		0x1B0EF21455B54C9AULL,
		0xB53C31F8C72C56DFULL,
		0xBDCE137657FBE3E1ULL,
		0x61A42E91FE3A4DECULL,
		0xF509566B6C03DFB4ULL,
		0xEAD3DEB6E3F8772EULL,
		0x713AB4453B0F34EAULL
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
		0x44CB67B60292192EULL,
		0x71F667537F9F2392ULL,
		0x0746E569CE7D3BD1ULL,
		0x202439002E36D237ULL,
		0x59F9BD6F58B3642BULL,
		0xE986976279E2E64BULL,
		0x2985C8E0AEA09B00ULL,
		0x16E631C32540A2CCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8996CF6C0524325CULL,
		0xE3ECCEA6FF3E4724ULL,
		0x0E8DCAD39CFA77A2ULL,
		0x404872005C6DA46EULL,
		0xB3F37ADEB166C856ULL,
		0xD30D2EC4F3C5CC96ULL,
		0x530B91C15D413601ULL,
		0x2DCC63864A814598ULL
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
		0xB248B16A8EB4B4F1ULL,
		0x0B3D2ACF5737D931ULL,
		0x3FCE87B1A2B6E04EULL,
		0xF277B80DA7AF67F7ULL,
		0x4FABC1856560D813ULL,
		0xA8336AC678AAA711ULL,
		0x0C777AC1EC8D7A00ULL,
		0x26F5B7287C60DBD0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x649162D51D6969E2ULL,
		0x167A559EAE6FB263ULL,
		0x7F9D0F63456DC09CULL,
		0xE4EF701B4F5ECFEEULL,
		0x9F57830ACAC1B027ULL,
		0x5066D58CF1554E22ULL,
		0x18EEF583D91AF401ULL,
		0x4DEB6E50F8C1B7A0ULL
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
		0x43624F60E138FDC6ULL,
		0x7B3978478128AEA7ULL,
		0x753A067F52940606ULL,
		0xEF9DC01616FA0736ULL,
		0xECBED32CDAFB9DFBULL,
		0x3DE56173D0A79446ULL,
		0x01987271A7EBEF67ULL,
		0x194B1C59507874F4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x86C49EC1C271FB8CULL,
		0xF672F08F02515D4EULL,
		0xEA740CFEA5280C0CULL,
		0xDF3B802C2DF40E6CULL,
		0xD97DA659B5F73BF7ULL,
		0x7BCAC2E7A14F288DULL,
		0x0330E4E34FD7DECEULL,
		0x329638B2A0F0E9E8ULL
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
		0x428ACF489404CBF8ULL,
		0x3C4606CA11331AB2ULL,
		0xC41983B35AC38E2FULL,
		0xD406F74C78290188ULL,
		0xBC760C92693630BBULL,
		0x209B85C79D695198ULL,
		0xF242EC705F8C303DULL,
		0x0E7B7E5C3ED28504ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x85159E91280997F0ULL,
		0x788C0D9422663564ULL,
		0x88330766B5871C5EULL,
		0xA80DEE98F0520311ULL,
		0x78EC1924D26C6177ULL,
		0x41370B8F3AD2A331ULL,
		0xE485D8E0BF18607AULL,
		0x1CF6FCB87DA50A09ULL
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
		0x563980583458FA1EULL,
		0x4DB4706E6F9541B7ULL,
		0x0233AC8D7D4E9C53ULL,
		0xA4907D32FB2E8153ULL,
		0x1E8C81039293F123ULL,
		0x2A8B172ADF370F97ULL,
		0xDF82C01EAE6844A1ULL,
		0x3FF04C5BB8559421ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAC7300B068B1F43CULL,
		0x9B68E0DCDF2A836EULL,
		0x0467591AFA9D38A6ULL,
		0x4920FA65F65D02A6ULL,
		0x3D1902072527E247ULL,
		0x55162E55BE6E1F2EULL,
		0xBF05803D5CD08942ULL,
		0x7FE098B770AB2843ULL
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
		0x7DEF86CC13AE59BFULL,
		0x8DC3AA76193DF49EULL,
		0x8772508BA597DB93ULL,
		0x51B12DE61D2F77D0ULL,
		0x60E2CB9AA045303AULL,
		0x819BF0A342907C9AULL,
		0xADE76CB6075E1665ULL,
		0x1ADF551B8BCB22F2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFBDF0D98275CB37EULL,
		0x1B8754EC327BE93CULL,
		0x0EE4A1174B2FB727ULL,
		0xA3625BCC3A5EEFA1ULL,
		0xC1C59735408A6074ULL,
		0x0337E1468520F934ULL,
		0x5BCED96C0EBC2CCBULL,
		0x35BEAA37179645E5ULL
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
		0x2F0D3693442CC0FBULL,
		0xFD4C03F38864D8A3ULL,
		0xD2E6656262288589ULL,
		0x1513AC7D01724CB1ULL,
		0xEE1E377BD91C6897ULL,
		0x0C59DC35EC0DFADCULL,
		0xEEFE36AF85B4C7BFULL,
		0x1A2FA79FE967E04FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5E1A6D26885981F6ULL,
		0xFA9807E710C9B146ULL,
		0xA5CCCAC4C4510B13ULL,
		0x2A2758FA02E49963ULL,
		0xDC3C6EF7B238D12EULL,
		0x18B3B86BD81BF5B9ULL,
		0xDDFC6D5F0B698F7EULL,
		0x345F4F3FD2CFC09FULL
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
		0xB7294137DA6B9683ULL,
		0xAA77CA2AFA785E11ULL,
		0xCA5550EBEA061CFFULL,
		0xC6DBBEB2B8B19B74ULL,
		0x32504D623F83A1B7ULL,
		0xD3EA53185BD49B42ULL,
		0x7F213825E530AC0FULL,
		0x35C2E3A9470B432FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6E52826FB4D72D06ULL,
		0x54EF9455F4F0BC23ULL,
		0x94AAA1D7D40C39FFULL,
		0x8DB77D65716336E9ULL,
		0x64A09AC47F07436FULL,
		0xA7D4A630B7A93684ULL,
		0xFE42704BCA61581FULL,
		0x6B85C7528E16865EULL
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
		0x4AC1059BC49E5EC5ULL,
		0xFAC34B228BBA50CEULL,
		0xB92908935B0442C1ULL,
		0x853DFB73B68745CBULL,
		0x2F396E486B128022ULL,
		0x84E6D5E19AD4C019ULL,
		0xA6CD71473E524D39ULL,
		0x0AE41B3E5D928C81ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x95820B37893CBD8AULL,
		0xF58696451774A19CULL,
		0x72521126B6088583ULL,
		0x0A7BF6E76D0E8B97ULL,
		0x5E72DC90D6250045ULL,
		0x09CDABC335A98032ULL,
		0x4D9AE28E7CA49A73ULL,
		0x15C8367CBB251903ULL
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
		0xBC5F01B78833F28EULL,
		0x2FF8DEC21B71B741ULL,
		0x53304A0852C5538CULL,
		0xB77A9AF35AE83B5AULL,
		0x6CC153927CCDCCCFULL,
		0xAE9A0F8A0F1575C3ULL,
		0x43315A171AA1FB69ULL,
		0x294655E98425E5AAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x78BE036F1067E51CULL,
		0x5FF1BD8436E36E83ULL,
		0xA6609410A58AA718ULL,
		0x6EF535E6B5D076B4ULL,
		0xD982A724F99B999FULL,
		0x5D341F141E2AEB86ULL,
		0x8662B42E3543F6D3ULL,
		0x528CABD3084BCB54ULL
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
		0x2EAA5D290C4E61D2ULL,
		0x3F7CCE4C88B9C459ULL,
		0x9E0535BAB98F19B7ULL,
		0x270EA2BC349BD535ULL,
		0x1F1AB593E23BB3E4ULL,
		0x2839D90964F85F81ULL,
		0x32FACC5CF41F015FULL,
		0x31D517DBD6CD4887ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5D54BA52189CC3A4ULL,
		0x7EF99C99117388B2ULL,
		0x3C0A6B75731E336EULL,
		0x4E1D45786937AA6BULL,
		0x3E356B27C47767C8ULL,
		0x5073B212C9F0BF02ULL,
		0x65F598B9E83E02BEULL,
		0x63AA2FB7AD9A910EULL
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
		0x35801C3D1A21C02BULL,
		0xBE7036D5A8A9A1B6ULL,
		0x2D60BB3BE0CDE778ULL,
		0x13D70167F3603822ULL,
		0x81CAA00677D1DC82ULL,
		0xFE7C82D1B68F2A6AULL,
		0x707D74FCECC1A471ULL,
		0x22FD020906B05A65ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6B00387A34438056ULL,
		0x7CE06DAB5153436CULL,
		0x5AC17677C19BCEF1ULL,
		0x27AE02CFE6C07044ULL,
		0x0395400CEFA3B904ULL,
		0xFCF905A36D1E54D5ULL,
		0xE0FAE9F9D98348E3ULL,
		0x45FA04120D60B4CAULL
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
		0x1094FA276F81982CULL,
		0x8401DE408C8C6EF8ULL,
		0x1501ED2CA1875C4CULL,
		0xA7225DE33507E73BULL,
		0x99CE6D7D02CD44DCULL,
		0x13DCDBD4B6C4468BULL,
		0x7FCDA3486746569AULL,
		0x38AECEA7AA90E225ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2129F44EDF033058ULL,
		0x0803BC811918DDF0ULL,
		0x2A03DA59430EB899ULL,
		0x4E44BBC66A0FCE76ULL,
		0x339CDAFA059A89B9ULL,
		0x27B9B7A96D888D17ULL,
		0xFF9B4690CE8CAD34ULL,
		0x715D9D4F5521C44AULL
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
		0x260FF1933E94F2EBULL,
		0x1DCD73B888641258ULL,
		0x4F4FE85D6ECECEB1ULL,
		0x9D064A6853D146A9ULL,
		0xB41AE1B9B9E6DDCDULL,
		0x026981F3CD115A85ULL,
		0xD9EE10F90CA82D5AULL,
		0x3097561BEC4EEA25ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4C1FE3267D29E5D6ULL,
		0x3B9AE77110C824B0ULL,
		0x9E9FD0BADD9D9D62ULL,
		0x3A0C94D0A7A28D52ULL,
		0x6835C37373CDBB9BULL,
		0x04D303E79A22B50BULL,
		0xB3DC21F219505AB4ULL,
		0x612EAC37D89DD44BULL
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
		0xF549BF60C0AD5121ULL,
		0x734CC64431D167E8ULL,
		0xE365CF24FA2E63F2ULL,
		0xBE04605974FEB899ULL,
		0xBBB4F6D1968B86FEULL,
		0xB50E00C568195A09ULL,
		0x02506D14F6ACB383ULL,
		0x30B18A3BCF16B0BBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEA937EC1815AA242ULL,
		0xE6998C8863A2CFD1ULL,
		0xC6CB9E49F45CC7E4ULL,
		0x7C08C0B2E9FD7133ULL,
		0x7769EDA32D170DFDULL,
		0x6A1C018AD032B413ULL,
		0x04A0DA29ED596707ULL,
		0x616314779E2D6176ULL
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
		0x5AE7425334355E28ULL,
		0x87DF138B50BEDE6BULL,
		0x160DD6C39AEFE4DBULL,
		0xC5EE11DF63E7BCDFULL,
		0xB95F9AE19070A334ULL,
		0xD10D64C7CE951349ULL,
		0x2B4249E225A3CBEEULL,
		0x275F2E022420B424ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB5CE84A6686ABC50ULL,
		0x0FBE2716A17DBCD6ULL,
		0x2C1BAD8735DFC9B7ULL,
		0x8BDC23BEC7CF79BEULL,
		0x72BF35C320E14669ULL,
		0xA21AC98F9D2A2693ULL,
		0x568493C44B4797DDULL,
		0x4EBE5C0448416848ULL
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
		0xBAA3A324CE781017ULL,
		0xBC2324B5E4BE5760ULL,
		0x11F1E8BA119D8CAFULL,
		0xA4A7BCB20F4B7546ULL,
		0x7C20596FA7AF6FB6ULL,
		0x9962D9025101E4D3ULL,
		0xE8F06743D69096D9ULL,
		0x0418895624A891EFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x754746499CF0202EULL,
		0x7846496BC97CAEC1ULL,
		0x23E3D174233B195FULL,
		0x494F79641E96EA8CULL,
		0xF840B2DF4F5EDF6DULL,
		0x32C5B204A203C9A6ULL,
		0xD1E0CE87AD212DB3ULL,
		0x083112AC495123DFULL
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
		0x3430A78C8E0F0549ULL,
		0xA258A6C3FE96854FULL,
		0x73D95AB756EAFADEULL,
		0xAE7DEEE933A63CEDULL,
		0xAF98B140A9A2DB25ULL,
		0xFDD639C341E64C0BULL,
		0x3BBBDFD50ECE76DFULL,
		0x0841748BCFC927D2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x68614F191C1E0A92ULL,
		0x44B14D87FD2D0A9EULL,
		0xE7B2B56EADD5F5BDULL,
		0x5CFBDDD2674C79DAULL,
		0x5F3162815345B64BULL,
		0xFBAC738683CC9817ULL,
		0x7777BFAA1D9CEDBFULL,
		0x1082E9179F924FA4ULL
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
		0xB9FD151786AC090BULL,
		0x18F34E49C76ED1A7ULL,
		0xC772F88765E1A71DULL,
		0x14D07EAF1DF437FDULL,
		0xDF9A82340A966015ULL,
		0xF97FB16C2A4933F6ULL,
		0x9E4282BE448EC1BCULL,
		0x2144495FC19E915CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x73FA2A2F0D581216ULL,
		0x31E69C938EDDA34FULL,
		0x8EE5F10ECBC34E3AULL,
		0x29A0FD5E3BE86FFBULL,
		0xBF350468152CC02AULL,
		0xF2FF62D8549267EDULL,
		0x3C85057C891D8379ULL,
		0x428892BF833D22B9ULL
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
		0x95814DB4F9E5A52AULL,
		0x5C94FDEFFDD257CDULL,
		0x2D0A7B5FC9E6B113ULL,
		0xF30F390EB6924B98ULL,
		0xB6ED6AA6BC40D8DFULL,
		0x58CE8D9FE328C1E2ULL,
		0x4A7455ECA01B45F1ULL,
		0x36C63EA3424A9C3AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2B029B69F3CB4A54ULL,
		0xB929FBDFFBA4AF9BULL,
		0x5A14F6BF93CD6226ULL,
		0xE61E721D6D249730ULL,
		0x6DDAD54D7881B1BFULL,
		0xB19D1B3FC65183C5ULL,
		0x94E8ABD940368BE2ULL,
		0x6D8C7D4684953874ULL
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
		0x706C5A0E195B8C35ULL,
		0x378B911E55FD134EULL,
		0xAEB354BE42548F5EULL,
		0x1FA471BD6B4CF0F1ULL,
		0x1AA0C37E7DF1657AULL,
		0xCC07DB57431D4E98ULL,
		0xA464013FA2853761ULL,
		0x16796DBCFF03ACA3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE0D8B41C32B7186AULL,
		0x6F17223CABFA269CULL,
		0x5D66A97C84A91EBCULL,
		0x3F48E37AD699E1E3ULL,
		0x354186FCFBE2CAF4ULL,
		0x980FB6AE863A9D30ULL,
		0x48C8027F450A6EC3ULL,
		0x2CF2DB79FE075947ULL
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
		0x0FD202A7343BEB9EULL,
		0xA75AA1581447840DULL,
		0xEF0128873141F038ULL,
		0x2E1C835E86E3BA43ULL,
		0x6764B48C392B1D05ULL,
		0x2DCBA96E93CCADBAULL,
		0x7DF7926FB0A5957EULL,
		0x014A9CA3B8797F68ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1FA4054E6877D73CULL,
		0x4EB542B0288F081AULL,
		0xDE02510E6283E071ULL,
		0x5C3906BD0DC77487ULL,
		0xCEC9691872563A0AULL,
		0x5B9752DD27995B74ULL,
		0xFBEF24DF614B2AFCULL,
		0x0295394770F2FED0ULL
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