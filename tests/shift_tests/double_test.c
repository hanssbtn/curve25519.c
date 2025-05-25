#include "../tests.h"

int32_t curve25519_key_x2_test(void) {
	printf("Key Doubling Test\n");
	curve25519_key_t k1 = {.key64 = {
		0x4950A6253AF2B7D2ULL,
		0xB6F2FE7EAA937103ULL,
		0x61A5EE6CEA7C6856ULL,
		0xA77828D832B9AAF7ULL,
		0x6DEE3DD11F6E65AFULL,
		0x963BF018C9CF7BF9ULL,
		0x20A51370D484BEE8ULL,
		0x01F3B6A70D33E604ULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0x92A14C4A75E56FA4ULL,
		0x6DE5FCFD5526E206ULL,
		0xC34BDCD9D4F8D0ADULL,
		0x4EF051B0657355EEULL,
		0xDBDC7BA23EDCCB5FULL,
		0x2C77E031939EF7F2ULL,
		0x414A26E1A9097DD1ULL,
		0x03E76D4E1A67CC08ULL
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
		0x69CDD01689D8BB80ULL,
		0x19211B22AD9B6807ULL,
		0xE67A332602CD0BD7ULL,
		0x6BBB2139508E9590ULL,
		0xF57BF11F532EE8E8ULL,
		0xD1A814A27C5DF18BULL,
		0x65E3E94E3BBB986CULL,
		0x2A9B86CEA91D32CFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD39BA02D13B17700ULL,
		0x324236455B36D00EULL,
		0xCCF4664C059A17AEULL,
		0xD7764272A11D2B21ULL,
		0xEAF7E23EA65DD1D0ULL,
		0xA3502944F8BBE317ULL,
		0xCBC7D29C777730D9ULL,
		0x55370D9D523A659EULL
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
		0x10D78345EED4365EULL,
		0xBF773AB58342FE04ULL,
		0xDDD312AC3BF43994ULL,
		0x746A4132C492965BULL,
		0x73CFACAA3B15D368ULL,
		0xD8943B75A056A096ULL,
		0x44BCC910429548F7ULL,
		0x00D20B28149DC494ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x21AF068BDDA86CBCULL,
		0x7EEE756B0685FC08ULL,
		0xBBA6255877E87329ULL,
		0xE8D4826589252CB7ULL,
		0xE79F5954762BA6D0ULL,
		0xB12876EB40AD412CULL,
		0x89799220852A91EFULL,
		0x01A41650293B8928ULL
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
		0xBA59A6B09EF1155DULL,
		0xCF66539EDC4B2AE5ULL,
		0xC37A8E3B513EEEBDULL,
		0xF2EC53CEB9D696B9ULL,
		0xB0B25CE710534892ULL,
		0xC9EB83F6964008DAULL,
		0xC5A8192361537AD1ULL,
		0x2D4D52B1A391629BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x74B34D613DE22ABAULL,
		0x9ECCA73DB89655CBULL,
		0x86F51C76A27DDD7BULL,
		0xE5D8A79D73AD2D73ULL,
		0x6164B9CE20A69125ULL,
		0x93D707ED2C8011B5ULL,
		0x8B503246C2A6F5A3ULL,
		0x5A9AA5634722C537ULL
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
		0x88F0A556E53C0E44ULL,
		0xA6A6A120CF4FCA46ULL,
		0x92170CBD8226FAA6ULL,
		0x895949D7F73406FAULL,
		0xD3C85FF026A57D7BULL,
		0xA84649EB3BA4549FULL,
		0xD9E22A2EA9E94C99ULL,
		0x0BF4F2112F37A0FFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x11E14AADCA781C88ULL,
		0x4D4D42419E9F948DULL,
		0x242E197B044DF54DULL,
		0x12B293AFEE680DF5ULL,
		0xA790BFE04D4AFAF7ULL,
		0x508C93D67748A93FULL,
		0xB3C4545D53D29933ULL,
		0x17E9E4225E6F41FFULL
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
		0x17453A57A23750E1ULL,
		0x49F96C6EE9CABE89ULL,
		0x1F97657281F8A123ULL,
		0x9E7DD19C522CE473ULL,
		0x86D66217C133548AULL,
		0x271977AC4DE7A9DEULL,
		0xAB05562DD4509FC6ULL,
		0x3421BA491ACD8002ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2E8A74AF446EA1C2ULL,
		0x93F2D8DDD3957D12ULL,
		0x3F2ECAE503F14246ULL,
		0x3CFBA338A459C8E6ULL,
		0x0DACC42F8266A915ULL,
		0x4E32EF589BCF53BDULL,
		0x560AAC5BA8A13F8CULL,
		0x68437492359B0005ULL
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
		0x5BEAA1EC879A0B06ULL,
		0xC2CD33B4D16F30E3ULL,
		0x354A17ED9B360E85ULL,
		0x7B9135C872A37909ULL,
		0x06E61E600FBBB760ULL,
		0xB8171869E2DE39D0ULL,
		0x9C743556056A9E71ULL,
		0x1E935752D85E1174ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB7D543D90F34160CULL,
		0x859A6769A2DE61C6ULL,
		0x6A942FDB366C1D0BULL,
		0xF7226B90E546F212ULL,
		0x0DCC3CC01F776EC0ULL,
		0x702E30D3C5BC73A0ULL,
		0x38E86AAC0AD53CE3ULL,
		0x3D26AEA5B0BC22E9ULL
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
		0x39D2434CBB995602ULL,
		0x1A58BD165F2182B7ULL,
		0xBCD234534FF75132ULL,
		0x457DD37FDE04A2B5ULL,
		0x87137248B2764FC0ULL,
		0x90CEC46791E73C2AULL,
		0xC1AA9037A4C56F71ULL,
		0x025D3EE50E079655ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x73A486997732AC04ULL,
		0x34B17A2CBE43056EULL,
		0x79A468A69FEEA264ULL,
		0x8AFBA6FFBC09456BULL,
		0x0E26E49164EC9F80ULL,
		0x219D88CF23CE7855ULL,
		0x8355206F498ADEE3ULL,
		0x04BA7DCA1C0F2CABULL
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
		0x4CA5AF304D5A5536ULL,
		0x3B729B8E0A8893CCULL,
		0x251CEDCB15609209ULL,
		0xD7161E4A3173092CULL,
		0xF180FB5979C0A53BULL,
		0x7B747C2672BC1DAEULL,
		0xDB4E03BB2439D972ULL,
		0x01D6C354BD5AEDEFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x994B5E609AB4AA6CULL,
		0x76E5371C15112798ULL,
		0x4A39DB962AC12412ULL,
		0xAE2C3C9462E61258ULL,
		0xE301F6B2F3814A77ULL,
		0xF6E8F84CE5783B5DULL,
		0xB69C07764873B2E4ULL,
		0x03AD86A97AB5DBDFULL
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
		0x98E4FF74BCDB165BULL,
		0x353A22AC3717694BULL,
		0x6EA6C8A06E1D2BAEULL,
		0x9F253904D785C67DULL,
		0xE0715979BEC7A27BULL,
		0x3EED686ACAB87997ULL,
		0x9BB1978FBA64D02EULL,
		0x3949A26D00DF19D2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x31C9FEE979B62CB6ULL,
		0x6A7445586E2ED297ULL,
		0xDD4D9140DC3A575CULL,
		0x3E4A7209AF0B8CFAULL,
		0xC0E2B2F37D8F44F7ULL,
		0x7DDAD0D59570F32FULL,
		0x37632F1F74C9A05CULL,
		0x729344DA01BE33A5ULL
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
		0x363EDE943DBAAE7AULL,
		0x7ECCC58621323F41ULL,
		0x62681BC3D5763224ULL,
		0x55F5E1A8D95D5DC4ULL,
		0x379B13FB9E0D6243ULL,
		0x2C7FD4C54273DB9FULL,
		0x88340EB73EEB7611ULL,
		0x048F071A6E6BC155ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6C7DBD287B755CF4ULL,
		0xFD998B0C42647E82ULL,
		0xC4D03787AAEC6448ULL,
		0xABEBC351B2BABB88ULL,
		0x6F3627F73C1AC486ULL,
		0x58FFA98A84E7B73EULL,
		0x10681D6E7DD6EC22ULL,
		0x091E0E34DCD782ABULL
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
		0x9D7F3FC794A99278ULL,
		0x1AA516635C7610DDULL,
		0xB5C4A8CCA1722A69ULL,
		0xA567A9AC192A2770ULL,
		0x0C225BAED58DD159ULL,
		0x098AF3CD0F6BE5DCULL,
		0x29D871A291B197E4ULL,
		0x2B311FE3EFB96C01ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3AFE7F8F295324F0ULL,
		0x354A2CC6B8EC21BBULL,
		0x6B89519942E454D2ULL,
		0x4ACF535832544EE1ULL,
		0x1844B75DAB1BA2B3ULL,
		0x1315E79A1ED7CBB8ULL,
		0x53B0E34523632FC8ULL,
		0x56623FC7DF72D802ULL
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
		0x1DDD127F605BD97EULL,
		0x2DCF6028CC72F04EULL,
		0x2A0710156EDA4E05ULL,
		0x28694B7A162FAF24ULL,
		0x538B739DCDE270F0ULL,
		0xC14C7082BEA54A21ULL,
		0x41782668C2FE9BF3ULL,
		0x227ACB7CC536987EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3BBA24FEC0B7B2FCULL,
		0x5B9EC05198E5E09CULL,
		0x540E202ADDB49C0AULL,
		0x50D296F42C5F5E48ULL,
		0xA716E73B9BC4E1E0ULL,
		0x8298E1057D4A9442ULL,
		0x82F04CD185FD37E7ULL,
		0x44F596F98A6D30FCULL
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
		0x3E01ACFA63F0023BULL,
		0x743EDA008786CF6EULL,
		0xC58DFEBF7A5BB8FCULL,
		0x2B0913DD1852941BULL,
		0x47E0903905C2CD72ULL,
		0xC617B6A2A8906A47ULL,
		0xA10A1DB878A044F3ULL,
		0x3028F84345135A75ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7C0359F4C7E00476ULL,
		0xE87DB4010F0D9EDCULL,
		0x8B1BFD7EF4B771F8ULL,
		0x561227BA30A52837ULL,
		0x8FC120720B859AE4ULL,
		0x8C2F6D455120D48EULL,
		0x42143B70F14089E7ULL,
		0x6051F0868A26B4EBULL
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
		0x3171DA9572CA7F1DULL,
		0x4C551937C1A1AE2AULL,
		0x6914AB8FE3F0C841ULL,
		0x43BF74E9D199972AULL,
		0x92E4BC21AF95F8F5ULL,
		0x102B43E6674C0DF4ULL,
		0x88E645CC85C3D9C9ULL,
		0x181E47D15B9F6D1CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x62E3B52AE594FE3AULL,
		0x98AA326F83435C54ULL,
		0xD229571FC7E19082ULL,
		0x877EE9D3A3332E54ULL,
		0x25C978435F2BF1EAULL,
		0x205687CCCE981BE9ULL,
		0x11CC8B990B87B392ULL,
		0x303C8FA2B73EDA39ULL
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
		0xEADF5F1D3AC6C04DULL,
		0xEA85EAC3522270B3ULL,
		0x1CA3DC315B59C88DULL,
		0x85B6CC7D3FD27D4BULL,
		0x0AFD2E1FD2C89ED2ULL,
		0x734C5F58CE50CB8DULL,
		0x4AAB990A154B6D93ULL,
		0x1E1D879EB4212438ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD5BEBE3A758D809AULL,
		0xD50BD586A444E167ULL,
		0x3947B862B6B3911BULL,
		0x0B6D98FA7FA4FA96ULL,
		0x15FA5C3FA5913DA5ULL,
		0xE698BEB19CA1971AULL,
		0x955732142A96DB26ULL,
		0x3C3B0F3D68424870ULL
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
		0xF889D9A371D4FFCEULL,
		0x69E4079FCA7907F2ULL,
		0x6B9457492D67A015ULL,
		0x9299933E9A929C86ULL,
		0xECE31A8FC124AF57ULL,
		0xA4E842CE06DFDAF0ULL,
		0xFF7499863605AAACULL,
		0x33BA06BCE734DB01ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF113B346E3A9FF9CULL,
		0xD3C80F3F94F20FE5ULL,
		0xD728AE925ACF402AULL,
		0x2533267D3525390CULL,
		0xD9C6351F82495EAFULL,
		0x49D0859C0DBFB5E1ULL,
		0xFEE9330C6C0B5559ULL,
		0x67740D79CE69B603ULL
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
		0x6F2931BE4E164D1EULL,
		0x46C6E2CBF9873CA3ULL,
		0xEBEE36BADA98E387ULL,
		0x3EEA770A9C0E2592ULL,
		0xB511FDFAC7CC2805ULL,
		0xCAFA6D5B5891F47FULL,
		0xD59EE6D4E1685AA1ULL,
		0x0A0712EE949E7898ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDE52637C9C2C9A3CULL,
		0x8D8DC597F30E7946ULL,
		0xD7DC6D75B531C70EULL,
		0x7DD4EE15381C4B25ULL,
		0x6A23FBF58F98500AULL,
		0x95F4DAB6B123E8FFULL,
		0xAB3DCDA9C2D0B543ULL,
		0x140E25DD293CF131ULL
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
		0xBC5727DD3236B1BCULL,
		0xC0C1EFF8D4205344ULL,
		0x094F92824864629BULL,
		0xB86112EDB64BC9CBULL,
		0x5367F23AB3A42BD0ULL,
		0x9F60BECC020F4F59ULL,
		0xF72F923A0DD9C26FULL,
		0x2D21E84DF916172BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x78AE4FBA646D6378ULL,
		0x8183DFF1A840A689ULL,
		0x129F250490C8C537ULL,
		0x70C225DB6C979396ULL,
		0xA6CFE475674857A1ULL,
		0x3EC17D98041E9EB2ULL,
		0xEE5F24741BB384DFULL,
		0x5A43D09BF22C2E57ULL
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
		0xE8AD05D2F28EB5B9ULL,
		0xC4C9FA354C0C7DBBULL,
		0x4633BCD586E45211ULL,
		0x35FE1D75D53D6580ULL,
		0x02CBB5B7442FB3C2ULL,
		0xA6225D135DC7EA7BULL,
		0x7E6585458C9F353BULL,
		0x0F0956A29B469DACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD15A0BA5E51D6B72ULL,
		0x8993F46A9818FB77ULL,
		0x8C6779AB0DC8A423ULL,
		0x6BFC3AEBAA7ACB00ULL,
		0x05976B6E885F6784ULL,
		0x4C44BA26BB8FD4F6ULL,
		0xFCCB0A8B193E6A77ULL,
		0x1E12AD45368D3B58ULL
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
		0x915AC8E61012603BULL,
		0x756B536FCA9F8EBDULL,
		0x2F3F13AE11610FC3ULL,
		0xAE3C4278333DE145ULL,
		0x599FF76A8594616DULL,
		0x2876ABCC917A69BBULL,
		0xACDD03D05B357452ULL,
		0x19213852060D3EA4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x22B591CC2024C076ULL,
		0xEAD6A6DF953F1D7BULL,
		0x5E7E275C22C21F86ULL,
		0x5C7884F0667BC28AULL,
		0xB33FEED50B28C2DBULL,
		0x50ED579922F4D376ULL,
		0x59BA07A0B66AE8A4ULL,
		0x324270A40C1A7D49ULL
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
		0x3BC0A76F6E3D4802ULL,
		0x04A66F5145A4C6C5ULL,
		0xC001231BFE45CBA1ULL,
		0x3CAA92BEB0B3C9B1ULL,
		0xC8FC5603B993994DULL,
		0x2DF303A6D4E21C25ULL,
		0x39F1732EA0ABB1E7ULL,
		0x3D6623752294BF8CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x77814EDEDC7A9004ULL,
		0x094CDEA28B498D8AULL,
		0x80024637FC8B9742ULL,
		0x7955257D61679363ULL,
		0x91F8AC077327329AULL,
		0x5BE6074DA9C4384BULL,
		0x73E2E65D415763CEULL,
		0x7ACC46EA45297F18ULL
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
		0x3F7FC502E875523CULL,
		0x05695E659CD3F7D1ULL,
		0xE77FFA33793720FDULL,
		0xEDB3641DA4B28951ULL,
		0x53B5935C9F120B74ULL,
		0xF8723A61086EBDADULL,
		0xB2014E80201556F6ULL,
		0x18C6DBBD2A7945FEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7EFF8A05D0EAA478ULL,
		0x0AD2BCCB39A7EFA2ULL,
		0xCEFFF466F26E41FAULL,
		0xDB66C83B496512A3ULL,
		0xA76B26B93E2416E9ULL,
		0xF0E474C210DD7B5AULL,
		0x64029D00402AADEDULL,
		0x318DB77A54F28BFDULL
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
		0xDE25CB7845937871ULL,
		0xBF96F2A1CA042B3CULL,
		0x069FC53DCDC0B872ULL,
		0xBC336E636E7B3500ULL,
		0x5F82B16C30EC06B8ULL,
		0xE0F7D0CAD7C6C9A1ULL,
		0x81B77053F99A3E05ULL,
		0x1C324C5FCAF66BA5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBC4B96F08B26F0E2ULL,
		0x7F2DE54394085679ULL,
		0x0D3F8A7B9B8170E5ULL,
		0x7866DCC6DCF66A00ULL,
		0xBF0562D861D80D71ULL,
		0xC1EFA195AF8D9342ULL,
		0x036EE0A7F3347C0BULL,
		0x386498BF95ECD74BULL
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
		0xE020C2BB37766DE3ULL,
		0x690CD172686F9683ULL,
		0x52D3BE96579A8B37ULL,
		0x765FEC58A993CE87ULL,
		0x3383AE5A459C14D9ULL,
		0x0C7E4D4F59838EB7ULL,
		0xED13E157ED59323EULL,
		0x2EE4EAB4DE63FE29ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC04185766EECDBC6ULL,
		0xD219A2E4D0DF2D07ULL,
		0xA5A77D2CAF35166EULL,
		0xECBFD8B153279D0EULL,
		0x67075CB48B3829B2ULL,
		0x18FC9A9EB3071D6EULL,
		0xDA27C2AFDAB2647CULL,
		0x5DC9D569BCC7FC53ULL
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
		0x04F9975608CEB461ULL,
		0x287FE49D51034261ULL,
		0x7B7C97DF99405244ULL,
		0x2D421C6558561184ULL,
		0x648C70F2C3FC5D82ULL,
		0x4B8A8D4701E17363ULL,
		0xEE32FAF0F53CEF10ULL,
		0x2CE8E601F3FE541DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x09F32EAC119D68C2ULL,
		0x50FFC93AA20684C2ULL,
		0xF6F92FBF3280A488ULL,
		0x5A8438CAB0AC2308ULL,
		0xC918E1E587F8BB04ULL,
		0x97151A8E03C2E6C6ULL,
		0xDC65F5E1EA79DE20ULL,
		0x59D1CC03E7FCA83BULL
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
		0x64987F532560379AULL,
		0x83F407DCCA9CF138ULL,
		0xEB21E7FF6717FCB6ULL,
		0xB5CCA38EC48D4363ULL,
		0x6ED2FC04A5C702A4ULL,
		0xE8A70D349495B956ULL,
		0x527081563D8A42BBULL,
		0x15388443F6061992ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC930FEA64AC06F34ULL,
		0x07E80FB99539E270ULL,
		0xD643CFFECE2FF96DULL,
		0x6B99471D891A86C7ULL,
		0xDDA5F8094B8E0549ULL,
		0xD14E1A69292B72ACULL,
		0xA4E102AC7B148577ULL,
		0x2A710887EC0C3324ULL
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
		0x8D5697EFCF0CE8F3ULL,
		0x8B0C36E6B97D81F5ULL,
		0x0BA3611395A6EFC6ULL,
		0xAAAEA271AD1D8232ULL,
		0x8E010ACB5C1FCAE4ULL,
		0x2135599B5C4BFAA4ULL,
		0xF1059BD0B7905B51ULL,
		0x3B5FD9D36A6ED654ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1AAD2FDF9E19D1E6ULL,
		0x16186DCD72FB03EBULL,
		0x1746C2272B4DDF8DULL,
		0x555D44E35A3B0464ULL,
		0x1C021596B83F95C9ULL,
		0x426AB336B897F549ULL,
		0xE20B37A16F20B6A2ULL,
		0x76BFB3A6D4DDACA9ULL
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
		0x9335BA4D482F8E60ULL,
		0x60F90E1A1E503E25ULL,
		0xDCD93B4793E7AE59ULL,
		0x429E3D5091B3E19EULL,
		0x4D26C5ECAF65F1BAULL,
		0x67BF20711286CB56ULL,
		0x49EA9C9672E6BE4EULL,
		0x0C09A5283019D442ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x266B749A905F1CC0ULL,
		0xC1F21C343CA07C4BULL,
		0xB9B2768F27CF5CB2ULL,
		0x853C7AA12367C33DULL,
		0x9A4D8BD95ECBE374ULL,
		0xCF7E40E2250D96ACULL,
		0x93D5392CE5CD7C9CULL,
		0x18134A506033A884ULL
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
		0xCDA27819C821A6A0ULL,
		0xEF0A780A6D199D4AULL,
		0xA1C385D49C6452E9ULL,
		0xAC19172B788D198DULL,
		0xBAF658DAF7015005ULL,
		0x3740690D87E66664ULL,
		0x471AA5A8CCB47CC9ULL,
		0x36963E5C161458D5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9B44F03390434D40ULL,
		0xDE14F014DA333A95ULL,
		0x43870BA938C8A5D3ULL,
		0x58322E56F11A331BULL,
		0x75ECB1B5EE02A00BULL,
		0x6E80D21B0FCCCCC9ULL,
		0x8E354B519968F992ULL,
		0x6D2C7CB82C28B1AAULL
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
		0xBA4E006159084668ULL,
		0x09493521EBA17E0CULL,
		0x9A4401D5FD236E2CULL,
		0x295AF559549ED948ULL,
		0x480212FCCDA43C6AULL,
		0x2D574913DED646C0ULL,
		0x961BC43CA800CD97ULL,
		0x0C059EE0FA263CDBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x749C00C2B2108CD0ULL,
		0x12926A43D742FC19ULL,
		0x348803ABFA46DC58ULL,
		0x52B5EAB2A93DB291ULL,
		0x900425F99B4878D4ULL,
		0x5AAE9227BDAC8D80ULL,
		0x2C37887950019B2EULL,
		0x180B3DC1F44C79B7ULL
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
		0xD463D4B6B0D520F6ULL,
		0xF3AA09FD69C87B02ULL,
		0x89F1A94F2C4C9E8CULL,
		0x6200FFB10DFE6B72ULL,
		0x3EE00881E0A07193ULL,
		0x32B9A4A0B6581C6EULL,
		0x1C2E36284E207662ULL,
		0x0C896289172BA060ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA8C7A96D61AA41ECULL,
		0xE75413FAD390F605ULL,
		0x13E3529E58993D19ULL,
		0xC401FF621BFCD6E5ULL,
		0x7DC01103C140E326ULL,
		0x657349416CB038DCULL,
		0x385C6C509C40ECC4ULL,
		0x1912C5122E5740C0ULL
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
		0x489A6523880807D2ULL,
		0xDC51179A3053A65DULL,
		0x9568CB49C5194740ULL,
		0x4443093530F8232CULL,
		0xBE86B6CD2485D6C8ULL,
		0x2BE823E55B7CB691ULL,
		0x1D2DB371A7D58A11ULL,
		0x097EF8AAC505F1C3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9134CA4710100FA4ULL,
		0xB8A22F3460A74CBAULL,
		0x2AD196938A328E81ULL,
		0x8886126A61F04659ULL,
		0x7D0D6D9A490BAD90ULL,
		0x57D047CAB6F96D23ULL,
		0x3A5B66E34FAB1422ULL,
		0x12FDF1558A0BE386ULL
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
		0xA2DF72AEF76657C6ULL,
		0xA5126B2BDB5A8D6FULL,
		0x06CD413406B05633ULL,
		0x7767893E254CF149ULL,
		0x01005CE8D6709999ULL,
		0xDB31D950EE679137ULL,
		0xF2A2A58433141624ULL,
		0x252D728524E60A14ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x45BEE55DEECCAF8CULL,
		0x4A24D657B6B51ADFULL,
		0x0D9A82680D60AC67ULL,
		0xEECF127C4A99E292ULL,
		0x0200B9D1ACE13332ULL,
		0xB663B2A1DCCF226EULL,
		0xE5454B0866282C49ULL,
		0x4A5AE50A49CC1429ULL
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
		0x08A4F617155C87ADULL,
		0xDDD0018F238E2166ULL,
		0x1387A2D9D9B60CEFULL,
		0x1D2C94E97F87C6F7ULL,
		0xED2E42BFB72DF24CULL,
		0xE56DF3F164B21962ULL,
		0x96B82AF5CD656E60ULL,
		0x0E231896181603CFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1149EC2E2AB90F5AULL,
		0xBBA0031E471C42CCULL,
		0x270F45B3B36C19DFULL,
		0x3A5929D2FF0F8DEEULL,
		0xDA5C857F6E5BE498ULL,
		0xCADBE7E2C96432C5ULL,
		0x2D7055EB9ACADCC1ULL,
		0x1C46312C302C079FULL
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
		0x3047F1BD9A513CF3ULL,
		0x2DC84E9BE72AE6F5ULL,
		0x18A2D5E918E006BDULL,
		0x3BB7C72A28B20AB2ULL,
		0xF703E9EBC77EBDD8ULL,
		0x615399B2F13B893FULL,
		0xE872123B3334EA37ULL,
		0x2C198F78DAC2C363ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x608FE37B34A279E6ULL,
		0x5B909D37CE55CDEAULL,
		0x3145ABD231C00D7AULL,
		0x776F8E5451641564ULL,
		0xEE07D3D78EFD7BB0ULL,
		0xC2A73365E277127FULL,
		0xD0E424766669D46EULL,
		0x58331EF1B58586C7ULL
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
		0x98719A1D25783EA2ULL,
		0xA8A2A7414F0D64DAULL,
		0x61EF439921538E4EULL,
		0xAB2DC080284F5703ULL,
		0xF3DFB6710C1D8FB6ULL,
		0xBDB25288901D4004ULL,
		0xCDDA8403C5C53A66ULL,
		0x2B31791D9C6CD449ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x30E3343A4AF07D44ULL,
		0x51454E829E1AC9B5ULL,
		0xC3DE873242A71C9DULL,
		0x565B8100509EAE06ULL,
		0xE7BF6CE2183B1F6DULL,
		0x7B64A511203A8009ULL,
		0x9BB508078B8A74CDULL,
		0x5662F23B38D9A893ULL
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
		0xA600DA1A0B0D64FBULL,
		0x206865DA67111CBCULL,
		0x6353508BA40CDC2BULL,
		0xD3CEF9514A4CFBFBULL,
		0x96FB3E16E41DB341ULL,
		0xF3EFA20ECC25421AULL,
		0xC2F493F6325A5101ULL,
		0x08A21D7258B33AA3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4C01B434161AC9F6ULL,
		0x40D0CBB4CE223979ULL,
		0xC6A6A1174819B856ULL,
		0xA79DF2A29499F7F6ULL,
		0x2DF67C2DC83B6683ULL,
		0xE7DF441D984A8435ULL,
		0x85E927EC64B4A203ULL,
		0x11443AE4B1667547ULL
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
		0x6315251C9CA752D7ULL,
		0xEB65D3196922D3B0ULL,
		0x4C091AFAA9615832ULL,
		0x27367DB8A9AD25C7ULL,
		0xA74138A036118F35ULL,
		0x28974CE61265F6FFULL,
		0x1339C3507F50B349ULL,
		0x0030C31BB127DF7CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC62A4A39394EA5AEULL,
		0xD6CBA632D245A760ULL,
		0x981235F552C2B065ULL,
		0x4E6CFB71535A4B8EULL,
		0x4E8271406C231E6AULL,
		0x512E99CC24CBEDFFULL,
		0x267386A0FEA16692ULL,
		0x00618637624FBEF8ULL
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
		0x904EDCF85B8FAA88ULL,
		0x1F5F5DE8DA2AABDEULL,
		0xF7F459F99195BD06ULL,
		0xABF5A79AF31D460FULL,
		0x35CC1BEE457BA38BULL,
		0x2E2BA61ABA0D63B4ULL,
		0x72C8CD0D1DC8974FULL,
		0x298607FA5D1149DFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x209DB9F0B71F5510ULL,
		0x3EBEBBD1B45557BDULL,
		0xEFE8B3F3232B7A0CULL,
		0x57EB4F35E63A8C1FULL,
		0x6B9837DC8AF74717ULL,
		0x5C574C35741AC768ULL,
		0xE5919A1A3B912E9EULL,
		0x530C0FF4BA2293BEULL
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
		0xE32C5C90AC68E35DULL,
		0x5C0DF573E9EE8DEBULL,
		0x151FCAC1EF84A181ULL,
		0x946296BAFB510497ULL,
		0x5933630B64A9C734ULL,
		0x965D30CA34BF76FFULL,
		0xD521057FEC49FC70ULL,
		0x086286E368A7A8EDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC658B92158D1C6BAULL,
		0xB81BEAE7D3DD1BD7ULL,
		0x2A3F9583DF094302ULL,
		0x28C52D75F6A2092EULL,
		0xB266C616C9538E69ULL,
		0x2CBA6194697EEDFEULL,
		0xAA420AFFD893F8E1ULL,
		0x10C50DC6D14F51DBULL
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
		0x50B7BF1D9928F971ULL,
		0xE6EE817F0D460099ULL,
		0xC05E648BC0036256ULL,
		0xD3A88C9AB3A31ED9ULL,
		0x79FCF38B20F887A9ULL,
		0x1B94B6E6D67D3AA4ULL,
		0x71515DFB793876DAULL,
		0x3095C49677DF4698ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA16F7E3B3251F2E2ULL,
		0xCDDD02FE1A8C0132ULL,
		0x80BCC9178006C4ADULL,
		0xA751193567463DB3ULL,
		0xF3F9E71641F10F53ULL,
		0x37296DCDACFA7548ULL,
		0xE2A2BBF6F270EDB4ULL,
		0x612B892CEFBE8D30ULL
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
		0xEDA4249DF94A5450ULL,
		0xE076E58F4B054F32ULL,
		0xBBBFAF71F503E5F2ULL,
		0xF4BAE504051F88D0ULL,
		0xAED1A86303702408ULL,
		0x79E2A1504FF287CDULL,
		0x5B0141C829E0F8B9ULL,
		0x04AFC2152F9234F7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDB48493BF294A8A0ULL,
		0xC0EDCB1E960A9E65ULL,
		0x777F5EE3EA07CBE5ULL,
		0xE975CA080A3F11A1ULL,
		0x5DA350C606E04811ULL,
		0xF3C542A09FE50F9BULL,
		0xB602839053C1F172ULL,
		0x095F842A5F2469EEULL
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
		0xE9295B84486D528BULL,
		0x5CD1C74B88682BFCULL,
		0x3CD4F96273B81ACAULL,
		0x34C52361909C926FULL,
		0xC59FD33B637DC07AULL,
		0x8D1230794CD66265ULL,
		0x02040B4C0FC06E3CULL,
		0x3DA8C08CAAEA3637ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD252B70890DAA516ULL,
		0xB9A38E9710D057F9ULL,
		0x79A9F2C4E7703594ULL,
		0x698A46C3213924DEULL,
		0x8B3FA676C6FB80F4ULL,
		0x1A2460F299ACC4CBULL,
		0x040816981F80DC79ULL,
		0x7B51811955D46C6EULL
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
		0xD7AAE34E58548971ULL,
		0xA0C14DF475BA6983ULL,
		0xFC24EAD83E7895E7ULL,
		0xA3C42F3F4B17FE77ULL,
		0x7EA60755EECF55A6ULL,
		0x5E4DAC30D21BB975ULL,
		0x6A2371AC98ABA1A0ULL,
		0x3E9FFD1EB3FF61FAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF55C69CB0A912E2ULL,
		0x41829BE8EB74D307ULL,
		0xF849D5B07CF12BCFULL,
		0x47885E7E962FFCEFULL,
		0xFD4C0EABDD9EAB4DULL,
		0xBC9B5861A43772EAULL,
		0xD446E35931574340ULL,
		0x7D3FFA3D67FEC3F4ULL
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
		0x942589077F94351DULL,
		0x465BCC3862218F4FULL,
		0xBE21B4688E29C2BBULL,
		0x8CDF98265EFE2B77ULL,
		0x8548302C2324D856ULL,
		0x6A70A13BFA825BA7ULL,
		0xABA770606E82257CULL,
		0x0531F96AB3B3510EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x284B120EFF286A3AULL,
		0x8CB79870C4431E9FULL,
		0x7C4368D11C538576ULL,
		0x19BF304CBDFC56EFULL,
		0x0A9060584649B0ADULL,
		0xD4E14277F504B74FULL,
		0x574EE0C0DD044AF8ULL,
		0x0A63F2D56766A21DULL
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
		0x2D51CCC8245152ABULL,
		0xC995725B28846407ULL,
		0xB87483CED1BFE250ULL,
		0x3AA73C4141400C87ULL,
		0x1E4A45208BD7D169ULL,
		0x4160A9D8B7068587ULL,
		0xDF75FD3025712017ULL,
		0x0CDFD050A2CFD801ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5AA3999048A2A556ULL,
		0x932AE4B65108C80EULL,
		0x70E9079DA37FC4A1ULL,
		0x754E78828280190FULL,
		0x3C948A4117AFA2D2ULL,
		0x82C153B16E0D0B0EULL,
		0xBEEBFA604AE2402EULL,
		0x19BFA0A1459FB003ULL
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
		0xAF20FA7DB24162E6ULL,
		0x45E2448F3A392E3BULL,
		0x45F8A13644CFCD25ULL,
		0xB2B5831E89E5E158ULL,
		0x059D4CF471B6867FULL,
		0x19595F6D2036641EULL,
		0xDDC1258B60B0D379ULL,
		0x295D40C065F88468ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5E41F4FB6482C5CCULL,
		0x8BC4891E74725C77ULL,
		0x8BF1426C899F9A4AULL,
		0x656B063D13CBC2B0ULL,
		0x0B3A99E8E36D0CFFULL,
		0x32B2BEDA406CC83CULL,
		0xBB824B16C161A6F2ULL,
		0x52BA8180CBF108D1ULL
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
		0x891367E7AB647B5AULL,
		0x52DDF350BFDAAFBDULL,
		0x9ADE46B5B7C80541ULL,
		0x91907DCAB7F65069ULL,
		0xA8D5BAFF85B64EA7ULL,
		0x3048A10E8DF1823FULL,
		0x4A7EC763BA19224AULL,
		0x3FC75DDD7BFC6462ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1226CFCF56C8F6B4ULL,
		0xA5BBE6A17FB55F7BULL,
		0x35BC8D6B6F900A82ULL,
		0x2320FB956FECA0D3ULL,
		0x51AB75FF0B6C9D4FULL,
		0x6091421D1BE3047FULL,
		0x94FD8EC774324494ULL,
		0x7F8EBBBAF7F8C8C4ULL
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
		0x5D81BD2505DCD628ULL,
		0x8C7E4684FD5AC63FULL,
		0xF7F213CABC6FA75BULL,
		0xC65936BAACB054A6ULL,
		0xD6FE652945F068F3ULL,
		0xE2F940ACE8D9BDD5ULL,
		0x5AD55F636A6FF46DULL,
		0x26C313C47236A898ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB037A4A0BB9AC50ULL,
		0x18FC8D09FAB58C7EULL,
		0xEFE4279578DF4EB7ULL,
		0x8CB26D755960A94DULL,
		0xADFCCA528BE0D1E7ULL,
		0xC5F28159D1B37BABULL,
		0xB5AABEC6D4DFE8DBULL,
		0x4D862788E46D5130ULL
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
		0xDD49B1619FE472DBULL,
		0x615403F39DDB5B23ULL,
		0xA85C0113180160D6ULL,
		0x95E95DFD0D0B8658ULL,
		0x9F9C5D3D261557B4ULL,
		0xC542D16CC031EB50ULL,
		0x08B09418AE833C85ULL,
		0x39B3D7D6F9FD44C5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBA9362C33FC8E5B6ULL,
		0xC2A807E73BB6B647ULL,
		0x50B802263002C1ACULL,
		0x2BD2BBFA1A170CB1ULL,
		0x3F38BA7A4C2AAF69ULL,
		0x8A85A2D98063D6A1ULL,
		0x116128315D06790BULL,
		0x7367AFADF3FA898AULL
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
		0xEA3E29BDCDA39BD0ULL,
		0x720BC9EAE173E33EULL,
		0x4F5A1F7027BC523FULL,
		0x7755A939A2D3688DULL,
		0x87A9CF0FC7C46298ULL,
		0x76C9935214CB29F1ULL,
		0x024049DA5095CC5FULL,
		0x123054C1D5B86C1FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD47C537B9B4737A0ULL,
		0xE41793D5C2E7C67DULL,
		0x9EB43EE04F78A47EULL,
		0xEEAB527345A6D11AULL,
		0x0F539E1F8F88C530ULL,
		0xED9326A4299653E3ULL,
		0x048093B4A12B98BEULL,
		0x2460A983AB70D83EULL
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
		0xA834A54C7C903152ULL,
		0xCAF559BF14E1AF5CULL,
		0x36FAAC8168D4B502ULL,
		0xEE7A2F75DCB637A2ULL,
		0x1D32C5583D66C348ULL,
		0xBCA0417DDD5B3C39ULL,
		0x81621BE63CAFAD6FULL,
		0x0054C06582F032E4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x50694A98F92062A4ULL,
		0x95EAB37E29C35EB9ULL,
		0x6DF55902D1A96A05ULL,
		0xDCF45EEBB96C6F44ULL,
		0x3A658AB07ACD8691ULL,
		0x794082FBBAB67872ULL,
		0x02C437CC795F5ADFULL,
		0x00A980CB05E065C9ULL
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
		0xE00AC1DF6E06F272ULL,
		0x8FF53FC170AB9DE4ULL,
		0x51CF0981280B0FC5ULL,
		0x776B29312151E1E8ULL,
		0x13E25DE3850FF842ULL,
		0x99046488B0D6AEEDULL,
		0x0CAB7A697A95B3CBULL,
		0x39ECC9B9E743632DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC01583BEDC0DE4E4ULL,
		0x1FEA7F82E1573BC9ULL,
		0xA39E130250161F8BULL,
		0xEED6526242A3C3D0ULL,
		0x27C4BBC70A1FF084ULL,
		0x3208C91161AD5DDAULL,
		0x1956F4D2F52B6797ULL,
		0x73D99373CE86C65AULL
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
		0x575B80D9FB4F3539ULL,
		0x313DCAAC0A22C454ULL,
		0xD365629F5DDBFAE1ULL,
		0x17C2D2A09EF7220CULL,
		0xEAC08DF6A6C48D2EULL,
		0xB9BE5451A52B2EA4ULL,
		0xF1365A4C49F4CAEAULL,
		0x059A0AAB4B30CB6BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAEB701B3F69E6A72ULL,
		0x627B9558144588A8ULL,
		0xA6CAC53EBBB7F5C2ULL,
		0x2F85A5413DEE4419ULL,
		0xD5811BED4D891A5CULL,
		0x737CA8A34A565D49ULL,
		0xE26CB49893E995D5ULL,
		0x0B341556966196D7ULL
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
		0x0405A53A0775826AULL,
		0xFA38651383949133ULL,
		0xF77ABECE8656C573ULL,
		0x7B6993CA2A29D8CBULL,
		0xA6B852B5645545DBULL,
		0x6B54FADD8C6C06D8ULL,
		0x5F718DC8143A8F17ULL,
		0x1956A3C18AA2D68EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x080B4A740EEB04D4ULL,
		0xF470CA2707292266ULL,
		0xEEF57D9D0CAD8AE7ULL,
		0xF6D327945453B197ULL,
		0x4D70A56AC8AA8BB6ULL,
		0xD6A9F5BB18D80DB1ULL,
		0xBEE31B9028751E2EULL,
		0x32AD47831545AD1CULL
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
		0x687325DBFF5D230BULL,
		0x18B9BBB57D57CDEDULL,
		0x94A67DD2FC56C3C8ULL,
		0x44056D815C3A0F8DULL,
		0x84ACB818DCEDA633ULL,
		0xDE27EBA9EE749505ULL,
		0x1AD524D265C2BFBEULL,
		0x37917DE2751E3A79ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD0E64BB7FEBA4616ULL,
		0x3173776AFAAF9BDAULL,
		0x294CFBA5F8AD8790ULL,
		0x880ADB02B8741F1BULL,
		0x09597031B9DB4C66ULL,
		0xBC4FD753DCE92A0BULL,
		0x35AA49A4CB857F7DULL,
		0x6F22FBC4EA3C74F2ULL
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
		0x549B0813320F3AA6ULL,
		0x333F549E764A5BC4ULL,
		0x12E1CB32DC955F8AULL,
		0xF0E9808B47CE42B6ULL,
		0x7C757A387820D6A7ULL,
		0x40BD4C464A52354EULL,
		0xED09D26CF219802BULL,
		0x3A7DA0BD55E6E50EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA9361026641E754CULL,
		0x667EA93CEC94B788ULL,
		0x25C39665B92ABF14ULL,
		0xE1D301168F9C856CULL,
		0xF8EAF470F041AD4FULL,
		0x817A988C94A46A9CULL,
		0xDA13A4D9E4330056ULL,
		0x74FB417AABCDCA1DULL
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
		0x43C2172139E31340ULL,
		0xE70EF7738D3B4DDFULL,
		0x9755E89F160D71CBULL,
		0xCAEF69E6D4698D12ULL,
		0x4E0E4134C5F85F6DULL,
		0x2E0DEB987D21260BULL,
		0xD6904DE0B614185EULL,
		0x2DFC18381DA8A3C1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x87842E4273C62680ULL,
		0xCE1DEEE71A769BBEULL,
		0x2EABD13E2C1AE397ULL,
		0x95DED3CDA8D31A25ULL,
		0x9C1C82698BF0BEDBULL,
		0x5C1BD730FA424C16ULL,
		0xAD209BC16C2830BCULL,
		0x5BF830703B514783ULL
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
		0xE3C97A33879FC5D2ULL,
		0x5542FEA5B9DABB82ULL,
		0x54FD14BD8D283B34ULL,
		0x9CF3E60989AD43B7ULL,
		0xEBF0798616D0DADBULL,
		0x00CB6422C1F75A8DULL,
		0x57DF86A35345881CULL,
		0x0F69764C0950FD06ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC792F4670F3F8BA4ULL,
		0xAA85FD4B73B57705ULL,
		0xA9FA297B1A507668ULL,
		0x39E7CC13135A876EULL,
		0xD7E0F30C2DA1B5B7ULL,
		0x0196C84583EEB51BULL,
		0xAFBF0D46A68B1038ULL,
		0x1ED2EC9812A1FA0CULL
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
		0x4FFFB982D8007D86ULL,
		0xAAD85258B9953088ULL,
		0x9F48FE7A969ADA3EULL,
		0x5A51A636645772E1ULL,
		0xAB31929C28884DA6ULL,
		0x599EAD14583F4143ULL,
		0x70EB52E1E3EC9060ULL,
		0x28759209DD2F2FDAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9FFF7305B000FB0CULL,
		0x55B0A4B1732A6110ULL,
		0x3E91FCF52D35B47DULL,
		0xB4A34C6CC8AEE5C3ULL,
		0x5663253851109B4CULL,
		0xB33D5A28B07E8287ULL,
		0xE1D6A5C3C7D920C0ULL,
		0x50EB2413BA5E5FB4ULL
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
		0x4AA8C6631D553D96ULL,
		0xD064C937AB1B704DULL,
		0xD742AD52601E5144ULL,
		0x96F8C3F04CBD9520ULL,
		0x9F9A03D559262999ULL,
		0x1555F9B75319840BULL,
		0x1C1094A7C08DCCB0ULL,
		0x0E7D85380A8F1908ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x95518CC63AAA7B2CULL,
		0xA0C9926F5636E09AULL,
		0xAE855AA4C03CA289ULL,
		0x2DF187E0997B2A41ULL,
		0x3F3407AAB24C5333ULL,
		0x2AABF36EA6330817ULL,
		0x3821294F811B9960ULL,
		0x1CFB0A70151E3210ULL
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
		0x894A2B934A5A371CULL,
		0xB8EE7AB97E9ADF13ULL,
		0x3E8FE86EF0076A26ULL,
		0xA9D40747CD92D8BDULL,
		0x18A311941619C28BULL,
		0xCF34B1BFB13C9C5AULL,
		0xCD14FA8ABEDB1AE3ULL,
		0x35F834787A6774A2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1294572694B46E38ULL,
		0x71DCF572FD35BE27ULL,
		0x7D1FD0DDE00ED44DULL,
		0x53A80E8F9B25B17AULL,
		0x314623282C338517ULL,
		0x9E69637F627938B4ULL,
		0x9A29F5157DB635C7ULL,
		0x6BF068F0F4CEE945ULL
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
		0xF0CA71AACFAF42C7ULL,
		0x4F084AFCFDBD7E04ULL,
		0xEB4329086B026D14ULL,
		0x124B36C4BD1736B0ULL,
		0x27217AA04D7815FCULL,
		0x0B56A7EEC8F00638ULL,
		0xF27E13E47191853BULL,
		0x31DED17205124345ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE194E3559F5E858EULL,
		0x9E1095F9FB7AFC09ULL,
		0xD6865210D604DA28ULL,
		0x24966D897A2E6D61ULL,
		0x4E42F5409AF02BF8ULL,
		0x16AD4FDD91E00C70ULL,
		0xE4FC27C8E3230A76ULL,
		0x63BDA2E40A24868BULL
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
		0xF0A0DE24791E51ECULL,
		0x25CEB6122F666082ULL,
		0x28CBE4A612D58606ULL,
		0x646FE17AC1604D24ULL,
		0x60BF407800BB9ECBULL,
		0x7879C9893D30A410ULL,
		0x53B316081138432AULL,
		0x2175B33E379DDBE4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE141BC48F23CA3D8ULL,
		0x4B9D6C245ECCC105ULL,
		0x5197C94C25AB0C0CULL,
		0xC8DFC2F582C09A48ULL,
		0xC17E80F001773D96ULL,
		0xF0F393127A614820ULL,
		0xA7662C1022708654ULL,
		0x42EB667C6F3BB7C8ULL
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
		0xF8EE608ED266799EULL,
		0xB553DEDC982D3B31ULL,
		0x962557CB6CC18B59ULL,
		0x57F08E8623E287AEULL,
		0x66EFAB7BC4BF2251ULL,
		0x4B28E64651048B2AULL,
		0x5A83D9E385C1F5F0ULL,
		0x0E6E88B1C82D93B1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF1DCC11DA4CCF33CULL,
		0x6AA7BDB9305A7663ULL,
		0x2C4AAF96D98316B3ULL,
		0xAFE11D0C47C50F5DULL,
		0xCDDF56F7897E44A2ULL,
		0x9651CC8CA2091654ULL,
		0xB507B3C70B83EBE0ULL,
		0x1CDD1163905B2762ULL
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
		0x9EC314DD4A372D1AULL,
		0xCF07A46930C9BB1DULL,
		0xE4503A8A8C114178ULL,
		0xD69EF9E8C6742A72ULL,
		0xF7C3736DD1A07132ULL,
		0xEC9BC12DA912368DULL,
		0xF3BF4027DEBC6233ULL,
		0x15D29058C889F67FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3D8629BA946E5A34ULL,
		0x9E0F48D26193763BULL,
		0xC8A07515182282F1ULL,
		0xAD3DF3D18CE854E5ULL,
		0xEF86E6DBA340E265ULL,
		0xD937825B52246D1BULL,
		0xE77E804FBD78C467ULL,
		0x2BA520B19113ECFFULL
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
		0x22F64A7DDAEAE244ULL,
		0x9FF0F6169DB171F4ULL,
		0xEA21F076ABEFBC17ULL,
		0x0D4C062C66C29BFEULL,
		0xFE5A3958F2CD4353ULL,
		0xC32E7038FB43F374ULL,
		0x8F7E896C011BF262ULL,
		0x0C42A58CEE4AE887ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x45EC94FBB5D5C488ULL,
		0x3FE1EC2D3B62E3E8ULL,
		0xD443E0ED57DF782FULL,
		0x1A980C58CD8537FDULL,
		0xFCB472B1E59A86A6ULL,
		0x865CE071F687E6E9ULL,
		0x1EFD12D80237E4C5ULL,
		0x18854B19DC95D10FULL
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
		0x92EEBC4097FC0544ULL,
		0x46595C8405019AE7ULL,
		0xFC82C6E216B6FA39ULL,
		0x3DFFD003292A7BFFULL,
		0x552EA33DCBD76640ULL,
		0xAAB5D0C025C02C47ULL,
		0x2CA8A3258EA4D758ULL,
		0x0C883D222D894FEEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x25DD78812FF80A88ULL,
		0x8CB2B9080A0335CFULL,
		0xF9058DC42D6DF472ULL,
		0x7BFFA0065254F7FFULL,
		0xAA5D467B97AECC80ULL,
		0x556BA1804B80588EULL,
		0x5951464B1D49AEB1ULL,
		0x19107A445B129FDCULL
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
		0x0A5E950BD478ADAFULL,
		0x05757358E298F0E9ULL,
		0x7030F22D06B9327EULL,
		0x04DE8290B8E9BEA9ULL,
		0xA6C7BE0A74517633ULL,
		0x1A086C479A84CE5BULL,
		0xFABB0EC47CEE2D34ULL,
		0x200E8F2D6661761BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x14BD2A17A8F15B5EULL,
		0x0AEAE6B1C531E1D2ULL,
		0xE061E45A0D7264FCULL,
		0x09BD052171D37D52ULL,
		0x4D8F7C14E8A2EC66ULL,
		0x3410D88F35099CB7ULL,
		0xF5761D88F9DC5A68ULL,
		0x401D1E5ACCC2EC37ULL
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
		0x62C555660A8901E1ULL,
		0x31A1CAF2CCCD0F61ULL,
		0x8ABC3018A3626B0FULL,
		0x56E75430AB025DCAULL,
		0xA22A54F5FEC20897ULL,
		0x220206B4ADAD5725ULL,
		0xA6AEE82FDFFC0BD4ULL,
		0x1BDB43AD517402EAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC58AAACC151203C2ULL,
		0x634395E5999A1EC2ULL,
		0x1578603146C4D61EULL,
		0xADCEA8615604BB95ULL,
		0x4454A9EBFD84112EULL,
		0x44040D695B5AAE4BULL,
		0x4D5DD05FBFF817A8ULL,
		0x37B6875AA2E805D5ULL
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
		0x031A17D53886A3CDULL,
		0x08DA8E9079146F9BULL,
		0x9778308169D681C0ULL,
		0x995A2C04FA1A16CCULL,
		0xC286F70A5A9E19D2ULL,
		0x08DB626B23D51042ULL,
		0xD30F0691FA878D19ULL,
		0x3F3C918563DFE434ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x06342FAA710D479AULL,
		0x11B51D20F228DF36ULL,
		0x2EF06102D3AD0380ULL,
		0x32B45809F4342D99ULL,
		0x850DEE14B53C33A5ULL,
		0x11B6C4D647AA2085ULL,
		0xA61E0D23F50F1A32ULL,
		0x7E79230AC7BFC869ULL
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
		0x54C5F4DA057FB474ULL,
		0xDFC644C61E2172BEULL,
		0x90EB3226ED42484BULL,
		0x5A99C0E52BE3C2B2ULL,
		0x9216B51317FFCEE1ULL,
		0xFACF90D94D78DACDULL,
		0x19C357E529638830ULL,
		0x3DB99D6767BE97A0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA98BE9B40AFF68E8ULL,
		0xBF8C898C3C42E57CULL,
		0x21D6644DDA849097ULL,
		0xB53381CA57C78565ULL,
		0x242D6A262FFF9DC2ULL,
		0xF59F21B29AF1B59BULL,
		0x3386AFCA52C71061ULL,
		0x7B733ACECF7D2F40ULL
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
		0x08532674C8B73DF6ULL,
		0x75B6C499A0E3B7D0ULL,
		0x8879CBA826A69474ULL,
		0x8C72402892133B69ULL,
		0xB2355CF602CD40CBULL,
		0x2DFBC3840590D8CDULL,
		0x0F93CE388CF2132BULL,
		0x3F6A7087314C97B7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x10A64CE9916E7BECULL,
		0xEB6D893341C76FA0ULL,
		0x10F397504D4D28E8ULL,
		0x18E48051242676D3ULL,
		0x646AB9EC059A8197ULL,
		0x5BF787080B21B19BULL,
		0x1F279C7119E42656ULL,
		0x7ED4E10E62992F6EULL
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
		0x4E22EE8548E8C3F1ULL,
		0xEAC6A57C28E6739EULL,
		0x40AEFE40AD36B890ULL,
		0x59415B42A14730D5ULL,
		0xC6E129FD8FBEEDDBULL,
		0xCBC9EFC2042908DBULL,
		0x7F1DB3EB7A4C4E59ULL,
		0x34197E9F119E3EE1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9C45DD0A91D187E2ULL,
		0xD58D4AF851CCE73CULL,
		0x815DFC815A6D7121ULL,
		0xB282B685428E61AAULL,
		0x8DC253FB1F7DDBB6ULL,
		0x9793DF84085211B7ULL,
		0xFE3B67D6F4989CB3ULL,
		0x6832FD3E233C7DC2ULL
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
		0x7A3A0C9A1D76628FULL,
		0xA08F0024DF3D6969ULL,
		0xDDAA87697A2ACA7BULL,
		0x4A8944B016983D6DULL,
		0x616CD9DC96E18CB0ULL,
		0x730C16112D8AAADEULL,
		0xC4CC599E4DCA11BBULL,
		0x27C7D9126B445010ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF47419343AECC51EULL,
		0x411E0049BE7AD2D2ULL,
		0xBB550ED2F45594F7ULL,
		0x951289602D307ADBULL,
		0xC2D9B3B92DC31960ULL,
		0xE6182C225B1555BCULL,
		0x8998B33C9B942376ULL,
		0x4F8FB224D688A021ULL
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
		0x5403D0171CC35C97ULL,
		0xE26C2F85647F9029ULL,
		0xFE86D3A0C8BB7F49ULL,
		0xB2F57B70DF54B84FULL,
		0x6C5BF9CFADD7FC25ULL,
		0x3CC3A336DCA4C821ULL,
		0xBF11DD1F89A114B1ULL,
		0x2A3C835752B525A3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA807A02E3986B92EULL,
		0xC4D85F0AC8FF2052ULL,
		0xFD0DA7419176FE93ULL,
		0x65EAF6E1BEA9709FULL,
		0xD8B7F39F5BAFF84BULL,
		0x7987466DB9499042ULL,
		0x7E23BA3F13422962ULL,
		0x547906AEA56A4B47ULL
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
		0xE2704A5B7327CAE3ULL,
		0x24D80CE6E8C78F82ULL,
		0xDC5898ABACF09E58ULL,
		0xE00682CDF589B66FULL,
		0x4FCB3FFDFC782D37ULL,
		0xBCD77A990FF0820BULL,
		0x515961C1316F2C35ULL,
		0x36EB12502B7FC942ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC4E094B6E64F95C6ULL,
		0x49B019CDD18F1F05ULL,
		0xB8B1315759E13CB0ULL,
		0xC00D059BEB136CDFULL,
		0x9F967FFBF8F05A6FULL,
		0x79AEF5321FE10416ULL,
		0xA2B2C38262DE586BULL,
		0x6DD624A056FF9284ULL
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
		0xF93FB2AD298B41ACULL,
		0x5DA6ECB3B3840D61ULL,
		0x93CAC2CDFCD43B72ULL,
		0x887AB9CE30D0D96FULL,
		0x6A21ACAF8E9F1674ULL,
		0x9B6ADD61CEEC7912ULL,
		0x6D59CECE96118D85ULL,
		0x0DBC329C52FB3416ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF27F655A53168358ULL,
		0xBB4DD96767081AC3ULL,
		0x2795859BF9A876E4ULL,
		0x10F5739C61A1B2DFULL,
		0xD443595F1D3E2CE9ULL,
		0x36D5BAC39DD8F224ULL,
		0xDAB39D9D2C231B0BULL,
		0x1B786538A5F6682CULL
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
		0x28F6E3F68CFEF27FULL,
		0x9319E9B8FCEC3F8EULL,
		0xCC40568250A2CCDEULL,
		0xB275833217B2C735ULL,
		0xDF1B7178F2EA50D2ULL,
		0xA07C5519E6CB5D26ULL,
		0xC859905638BDDC7DULL,
		0x0E4EF6649ACB7781ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x51EDC7ED19FDE4FEULL,
		0x2633D371F9D87F1CULL,
		0x9880AD04A14599BDULL,
		0x64EB06642F658E6BULL,
		0xBE36E2F1E5D4A1A5ULL,
		0x40F8AA33CD96BA4DULL,
		0x90B320AC717BB8FBULL,
		0x1C9DECC93596EF03ULL
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
		0x263ED9D120E18BAAULL,
		0x72E39F8434C199B0ULL,
		0xD913E17A6C492731ULL,
		0xBD2A4F3DD9623481ULL,
		0x60833DDB1036D920ULL,
		0x201B5C16EEBB5A69ULL,
		0xC3A92D1DC2854262ULL,
		0x0B72DADB4D09492FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4C7DB3A241C31754ULL,
		0xE5C73F0869833360ULL,
		0xB227C2F4D8924E62ULL,
		0x7A549E7BB2C46903ULL,
		0xC1067BB6206DB241ULL,
		0x4036B82DDD76B4D2ULL,
		0x87525A3B850A84C4ULL,
		0x16E5B5B69A12925FULL
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
		0x7DEAFC57FB5A30E4ULL,
		0x27AD1DCCA920A1F9ULL,
		0x5566178335633F9EULL,
		0x286ABB9CCDC85344ULL,
		0xD78FD1F5699B91FAULL,
		0x4EBAD027091F10ACULL,
		0x0554B7B8A4C2C47AULL,
		0x1C005A9BAF0824C5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFBD5F8AFF6B461C8ULL,
		0x4F5A3B99524143F2ULL,
		0xAACC2F066AC67F3CULL,
		0x50D577399B90A688ULL,
		0xAF1FA3EAD33723F4ULL,
		0x9D75A04E123E2159ULL,
		0x0AA96F71498588F4ULL,
		0x3800B5375E10498AULL
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
		0xB99A5549E21C861AULL,
		0x2E292123D0077B8DULL,
		0x8D67F3DAC9E1E468ULL,
		0x751307C28E35EDB7ULL,
		0x5442DD44CAF82F52ULL,
		0xC683F7BAA2744676ULL,
		0x341E27369398137FULL,
		0x27AB717AD395C0CCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7334AA93C4390C34ULL,
		0x5C524247A00EF71BULL,
		0x1ACFE7B593C3C8D0ULL,
		0xEA260F851C6BDB6FULL,
		0xA885BA8995F05EA4ULL,
		0x8D07EF7544E88CECULL,
		0x683C4E6D273026FFULL,
		0x4F56E2F5A72B8198ULL
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
		0xD0ED5381FB6301CCULL,
		0xE9E506FD12693F7AULL,
		0x4BDD0061DD589E62ULL,
		0x83CE5420F8EE3E59ULL,
		0x94BDFACC94DCFA68ULL,
		0xF543207B81BA36D8ULL,
		0x1B67FCA892DA9AD6ULL,
		0x24848FFDBBE4B88FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA1DAA703F6C60398ULL,
		0xD3CA0DFA24D27EF5ULL,
		0x97BA00C3BAB13CC5ULL,
		0x079CA841F1DC7CB2ULL,
		0x297BF59929B9F4D1ULL,
		0xEA8640F703746DB1ULL,
		0x36CFF95125B535ADULL,
		0x49091FFB77C9711EULL
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
		0xED30CEEC435D2273ULL,
		0x492E58996B435476ULL,
		0xDC9FF05884CFD914ULL,
		0xB2A502F177EFB7E0ULL,
		0x101DF507CFC2A131ULL,
		0xDD342A040A9C573DULL,
		0x1596BF5A4ADC1685ULL,
		0x0FEAF4F7F2EDE6C3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDA619DD886BA44E6ULL,
		0x925CB132D686A8EDULL,
		0xB93FE0B1099FB228ULL,
		0x654A05E2EFDF6FC1ULL,
		0x203BEA0F9F854263ULL,
		0xBA6854081538AE7AULL,
		0x2B2D7EB495B82D0BULL,
		0x1FD5E9EFE5DBCD86ULL
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
		0xA5FAD413870B6688ULL,
		0x3A2BB0F09FF29F0CULL,
		0x14DB6F43B9663B63ULL,
		0xD0B83355BBAED670ULL,
		0x9FE59F598EB93B28ULL,
		0x82E31EE1686FF9C0ULL,
		0x2F7EC7B1B6271614ULL,
		0x0BBC00AF24DB8AE5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4BF5A8270E16CD10ULL,
		0x745761E13FE53E19ULL,
		0x29B6DE8772CC76C6ULL,
		0xA17066AB775DACE0ULL,
		0x3FCB3EB31D727651ULL,
		0x05C63DC2D0DFF381ULL,
		0x5EFD8F636C4E2C29ULL,
		0x1778015E49B715CAULL
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
		0x64E678E0E6822E68ULL,
		0xA5EF77DB9A69FDC3ULL,
		0x39FBF298D9864AE7ULL,
		0xEBE8D521404D2D74ULL,
		0x253ED3CCC8CC136FULL,
		0x9C80FCD488ECE16CULL,
		0x4CE3D1A00D05D223ULL,
		0x0D4F8C9B3F322109ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC9CCF1C1CD045CD0ULL,
		0x4BDEEFB734D3FB86ULL,
		0x73F7E531B30C95CFULL,
		0xD7D1AA42809A5AE8ULL,
		0x4A7DA799919826DFULL,
		0x3901F9A911D9C2D8ULL,
		0x99C7A3401A0BA447ULL,
		0x1A9F19367E644212ULL
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
		0x67ABE7407BBAA56AULL,
		0x1835114F9446124DULL,
		0x7D200E23F073FDB4ULL,
		0x419FCADFDD15ABE6ULL,
		0xE09B87AAD64324C3ULL,
		0x85F2D662EC794BA4ULL,
		0x2759E871EF875C64ULL,
		0x391E45D96A94AF8FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCF57CE80F7754AD4ULL,
		0x306A229F288C249AULL,
		0xFA401C47E0E7FB68ULL,
		0x833F95BFBA2B57CCULL,
		0xC1370F55AC864986ULL,
		0x0BE5ACC5D8F29749ULL,
		0x4EB3D0E3DF0EB8C9ULL,
		0x723C8BB2D5295F1EULL
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
		0x53D45EACA46000A6ULL,
		0x887527F679F5404EULL,
		0xD0DC12D52814ED93ULL,
		0x35B5E3B7C27CB08DULL,
		0xC7FC6703FC3CDCAFULL,
		0x12D1D532E76BCC41ULL,
		0xCA1891546F7B07B9ULL,
		0x2B9E730398A64E79ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA7A8BD5948C0014CULL,
		0x10EA4FECF3EA809CULL,
		0xA1B825AA5029DB27ULL,
		0x6B6BC76F84F9611BULL,
		0x8FF8CE07F879B95EULL,
		0x25A3AA65CED79883ULL,
		0x943122A8DEF60F72ULL,
		0x573CE607314C9CF3ULL
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
		0x26636D3D87CD6206ULL,
		0xED8C0D13FA2B41F5ULL,
		0xF85CE6BC941F6391ULL,
		0x3F26586037089846ULL,
		0x742848265502ACAEULL,
		0x1FAE99789B02D885ULL,
		0xB28DC98B27198E5BULL,
		0x2DE175DD9483A407ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4CC6DA7B0F9AC40CULL,
		0xDB181A27F45683EAULL,
		0xF0B9CD79283EC723ULL,
		0x7E4CB0C06E11308DULL,
		0xE850904CAA05595CULL,
		0x3F5D32F13605B10AULL,
		0x651B93164E331CB6ULL,
		0x5BC2EBBB2907480FULL
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
		0xF60FC273D01F19B3ULL,
		0xA53B2B011DA2F653ULL,
		0x7092194E8CC21CBDULL,
		0x07591D455DDFE31FULL,
		0xD2D33D8F86DEF6CDULL,
		0x2074FAB93A147371ULL,
		0xCB7E9D2F8121B6B4ULL,
		0x130C7E890221945DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEC1F84E7A03E3366ULL,
		0x4A7656023B45ECA7ULL,
		0xE124329D1984397BULL,
		0x0EB23A8ABBBFC63EULL,
		0xA5A67B1F0DBDED9AULL,
		0x40E9F5727428E6E3ULL,
		0x96FD3A5F02436D68ULL,
		0x2618FD12044328BBULL
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
		0x8BE6DFC50339C5F5ULL,
		0xC1AD095325D2DB16ULL,
		0xD27580A946F05E24ULL,
		0x4E7231F9269ACB8AULL,
		0x5960B46BC074FBAAULL,
		0xE58EEB68E95182F2ULL,
		0x2D1342D69B1AAFDFULL,
		0x27097E85AE017B44ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x17CDBF8A06738BEAULL,
		0x835A12A64BA5B62DULL,
		0xA4EB01528DE0BC49ULL,
		0x9CE463F24D359715ULL,
		0xB2C168D780E9F754ULL,
		0xCB1DD6D1D2A305E4ULL,
		0x5A2685AD36355FBFULL,
		0x4E12FD0B5C02F688ULL
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
		0xD66C9228FD54B625ULL,
		0xC367A8344F59EF62ULL,
		0xE1B4557A03B9AB3CULL,
		0x4AF99A391F6CABFDULL,
		0xA62789BE446A6A21ULL,
		0xEE215425CCC899C6ULL,
		0x23FAF2699DBE5D29ULL,
		0x1E34E782B0EECDCCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xACD92451FAA96C4AULL,
		0x86CF50689EB3DEC5ULL,
		0xC368AAF407735679ULL,
		0x95F334723ED957FBULL,
		0x4C4F137C88D4D442ULL,
		0xDC42A84B9991338DULL,
		0x47F5E4D33B7CBA53ULL,
		0x3C69CF0561DD9B98ULL
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
		0xA6F08A33730D621CULL,
		0x1FC465BAA33E14B0ULL,
		0xA8A4314D308A8A03ULL,
		0x731246F48EDB0429ULL,
		0x4249FD75B1D6968DULL,
		0x024F057049EA5803ULL,
		0x189792EB009F8090ULL,
		0x283568CD1407221CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4DE11466E61AC438ULL,
		0x3F88CB75467C2961ULL,
		0x5148629A61151406ULL,
		0xE6248DE91DB60853ULL,
		0x8493FAEB63AD2D1AULL,
		0x049E0AE093D4B006ULL,
		0x312F25D6013F0120ULL,
		0x506AD19A280E4438ULL
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
		0x14CBAC23FCB8B6FAULL,
		0x7403D56198874C3BULL,
		0x0762997197B82571ULL,
		0xFB9748683E710E28ULL,
		0x86A3B41970019273ULL,
		0xDE958BC4BE2FEAB1ULL,
		0xF31B2E921E1CEA76ULL,
		0x2320CFF1B685F3D0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x29975847F9716DF4ULL,
		0xE807AAC3310E9876ULL,
		0x0EC532E32F704AE2ULL,
		0xF72E90D07CE21C50ULL,
		0x0D476832E00324E7ULL,
		0xBD2B17897C5FD563ULL,
		0xE6365D243C39D4EDULL,
		0x46419FE36D0BE7A1ULL
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
		0xA526B678147BD6CAULL,
		0x14EE602721462708ULL,
		0xEC40696942D0166DULL,
		0xD1AA5B618F85A986ULL,
		0x4B73D4EF774E3F50ULL,
		0x9EABCED12954888AULL,
		0xD9557AA189B46E88ULL,
		0x0332E258A3BC2F2AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4A4D6CF028F7AD94ULL,
		0x29DCC04E428C4E11ULL,
		0xD880D2D285A02CDAULL,
		0xA354B6C31F0B530DULL,
		0x96E7A9DEEE9C7EA1ULL,
		0x3D579DA252A91114ULL,
		0xB2AAF5431368DD11ULL,
		0x0665C4B147785E55ULL
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
		0x226FE47ECE866696ULL,
		0xBDBAF92D7318F2C2ULL,
		0x5A6101F67A3737AEULL,
		0x893D4C81DB53CE65ULL,
		0x08E0AB6F985C2D46ULL,
		0x93683B698E47AF63ULL,
		0x8B6209C82422A902ULL,
		0x2E7BF6DFC7755ECAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x44DFC8FD9D0CCD2CULL,
		0x7B75F25AE631E584ULL,
		0xB4C203ECF46E6F5DULL,
		0x127A9903B6A79CCAULL,
		0x11C156DF30B85A8DULL,
		0x26D076D31C8F5EC6ULL,
		0x16C4139048455205ULL,
		0x5CF7EDBF8EEABD95ULL
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
		0x22219AE001CCA8A3ULL,
		0xA475BC2D6FA4B2F2ULL,
		0x247FEEFBF235ED12ULL,
		0xC87D5DABDD8A0641ULL,
		0xE12CD448A92F1C46ULL,
		0xFFBAAE9CB63B58D9ULL,
		0x162E49A816712214ULL,
		0x1C0BEA1E0CAC7D8EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x444335C003995146ULL,
		0x48EB785ADF4965E4ULL,
		0x48FFDDF7E46BDA25ULL,
		0x90FABB57BB140C82ULL,
		0xC259A891525E388DULL,
		0xFF755D396C76B1B3ULL,
		0x2C5C93502CE24429ULL,
		0x3817D43C1958FB1CULL
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
		0x0B9CA36B4A2C8C93ULL,
		0x3311FA968D2C1082ULL,
		0x35275348E43E2CEEULL,
		0xDD530C4D23F2CFF4ULL,
		0x3D2DF961BEAC40A0ULL,
		0x296B47BD40C35D29ULL,
		0xEB4244637EC0A753ULL,
		0x21EFD8671F9AE502ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x173946D694591926ULL,
		0x6623F52D1A582104ULL,
		0x6A4EA691C87C59DCULL,
		0xBAA6189A47E59FE8ULL,
		0x7A5BF2C37D588141ULL,
		0x52D68F7A8186BA52ULL,
		0xD68488C6FD814EA6ULL,
		0x43DFB0CE3F35CA05ULL
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
		0x0D939A635B4191D8ULL,
		0x22C0543686332D06ULL,
		0x27E1ACBBA6C30540ULL,
		0x359C8FD6DF53797FULL,
		0x2B2808F73AF279A8ULL,
		0x720954895C813122ULL,
		0x2EC1B52AFB6E35D6ULL,
		0x2EB9E621EB4BF56BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1B2734C6B68323B0ULL,
		0x4580A86D0C665A0CULL,
		0x4FC359774D860A80ULL,
		0x6B391FADBEA6F2FEULL,
		0x565011EE75E4F350ULL,
		0xE412A912B9026244ULL,
		0x5D836A55F6DC6BACULL,
		0x5D73CC43D697EAD6ULL
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
		0x8B3BD9D14732A786ULL,
		0x684759B86FB125F8ULL,
		0x40D1FCE3F202E4D1ULL,
		0x85AB3604937DCD91ULL,
		0x70C0F871067D16E9ULL,
		0xDC43398C8F97DF86ULL,
		0x44DEC23C1B7EDD4DULL,
		0x21F620B4C594E21EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1677B3A28E654F0CULL,
		0xD08EB370DF624BF1ULL,
		0x81A3F9C7E405C9A2ULL,
		0x0B566C0926FB9B22ULL,
		0xE181F0E20CFA2DD3ULL,
		0xB88673191F2FBF0CULL,
		0x89BD847836FDBA9BULL,
		0x43EC41698B29C43CULL
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
		0xC2E27367A3E4BEC1ULL,
		0x6CE7F72738A93BCBULL,
		0xEE86F8185E7D4B93ULL,
		0xF2C1AA97B091617FULL,
		0xB42919AA3C5B2DEAULL,
		0xFFBBC157AB61ADD9ULL,
		0x221334AA95DD7A95ULL,
		0x0CB066A81FE15322ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x85C4E6CF47C97D82ULL,
		0xD9CFEE4E71527797ULL,
		0xDD0DF030BCFA9726ULL,
		0xE583552F6122C2FFULL,
		0x6852335478B65BD5ULL,
		0xFF7782AF56C35BB3ULL,
		0x442669552BBAF52BULL,
		0x1960CD503FC2A644ULL
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
		0xD2958CB395055363ULL,
		0x4FDBA1EB4D358963ULL,
		0xA74E73130BC9B547ULL,
		0x8AD8EEF1E9026649ULL,
		0x46925FFD325CCBC1ULL,
		0x288B50ED8CE2F3BFULL,
		0xCBF5136FF78AD52AULL,
		0x32246507C5268A0DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA52B19672A0AA6C6ULL,
		0x9FB743D69A6B12C7ULL,
		0x4E9CE62617936A8EULL,
		0x15B1DDE3D204CC93ULL,
		0x8D24BFFA64B99783ULL,
		0x5116A1DB19C5E77EULL,
		0x97EA26DFEF15AA54ULL,
		0x6448CA0F8A4D141BULL
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
		0x124CF8E72B71D908ULL,
		0xF17C677A34B31807ULL,
		0xF88C22E2151E66E1ULL,
		0xB55668B8A38E0FAAULL,
		0x35284D2996CC64F3ULL,
		0x218FCB3FCFD81F1DULL,
		0x6F3BFB033DD73762ULL,
		0x351D8822E0D69120ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2499F1CE56E3B210ULL,
		0xE2F8CEF46966300EULL,
		0xF11845C42A3CCDC3ULL,
		0x6AACD171471C1F55ULL,
		0x6A509A532D98C9E7ULL,
		0x431F967F9FB03E3AULL,
		0xDE77F6067BAE6EC4ULL,
		0x6A3B1045C1AD2240ULL
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
		0x8344B6A25E45D0A3ULL,
		0xFB4FE31352AC77FAULL,
		0x73BCFFFF6E454DC0ULL,
		0xC650DA2630A51F5BULL,
		0x9C27E414427DFC95ULL,
		0x523609B7555387C8ULL,
		0xDAC1225046708FC6ULL,
		0x0890A44BDED40ECDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x06896D44BC8BA146ULL,
		0xF69FC626A558EFF5ULL,
		0xE779FFFEDC8A9B81ULL,
		0x8CA1B44C614A3EB6ULL,
		0x384FC82884FBF92BULL,
		0xA46C136EAAA70F91ULL,
		0xB58244A08CE11F8CULL,
		0x11214897BDA81D9BULL
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
		0x253C2FCD358E4265ULL,
		0x94244C0C21B597DBULL,
		0x6B8B9CB71EB39EDFULL,
		0x917C1DEAB101429FULL,
		0xD22E3DCABB2338F2ULL,
		0xB3987DD6E4DDC697ULL,
		0x6EAFA12AA1150412ULL,
		0x2BE8BD43E000195AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4A785F9A6B1C84CAULL,
		0x28489818436B2FB6ULL,
		0xD717396E3D673DBFULL,
		0x22F83BD56202853EULL,
		0xA45C7B95764671E5ULL,
		0x6730FBADC9BB8D2FULL,
		0xDD5F4255422A0825ULL,
		0x57D17A87C00032B4ULL
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
		0x9F6A2D1B61C04082ULL,
		0xA632528A2E9DC6CCULL,
		0x1F467E8BAF3B5482ULL,
		0xB66A94F1BF9CC875ULL,
		0xAFD1DD4991607BA8ULL,
		0x5A5E9DBE249ABD18ULL,
		0x5948B06CEB5EC379ULL,
		0x28ACE6CF7F5A0182ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3ED45A36C3808104ULL,
		0x4C64A5145D3B8D99ULL,
		0x3E8CFD175E76A905ULL,
		0x6CD529E37F3990EAULL,
		0x5FA3BA9322C0F751ULL,
		0xB4BD3B7C49357A31ULL,
		0xB29160D9D6BD86F2ULL,
		0x5159CD9EFEB40304ULL
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
		0xB9BA9EC3274BA3F8ULL,
		0x10D960233EA16D9CULL,
		0x9F1E6E227F73B032ULL,
		0xFC43CB62AC8CFBD6ULL,
		0xA06670DD43D64D2AULL,
		0xB590F1A43363929EULL,
		0xA29834D09E66BFB9ULL,
		0x0AEB72913ABAA285ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x73753D864E9747F0ULL,
		0x21B2C0467D42DB39ULL,
		0x3E3CDC44FEE76064ULL,
		0xF88796C55919F7ADULL,
		0x40CCE1BA87AC9A55ULL,
		0x6B21E34866C7253DULL,
		0x453069A13CCD7F73ULL,
		0x15D6E5227575450BULL
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
		0x7B206C327F2DA5CBULL,
		0xF34F8DA66966091BULL,
		0x7C286CD0B7F1DBBDULL,
		0xFC4C3696A9323F77ULL,
		0xB27565D4485AD8EBULL,
		0x52A7A21D4F37942BULL,
		0xB06D1E20BC363A09ULL,
		0x03E7F28FCA3EACB2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF640D864FE5B4B96ULL,
		0xE69F1B4CD2CC1236ULL,
		0xF850D9A16FE3B77BULL,
		0xF8986D2D52647EEEULL,
		0x64EACBA890B5B1D7ULL,
		0xA54F443A9E6F2857ULL,
		0x60DA3C41786C7412ULL,
		0x07CFE51F947D5965ULL
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
		0x42AD4473380EEF7CULL,
		0x01A872DCAD882502ULL,
		0xCB176699F51DA6EDULL,
		0x416864D0B1BA7CBFULL,
		0x7297EC2CED926AE2ULL,
		0xFD75FE423FB3BFB4ULL,
		0xB81C7F0A013A12F6ULL,
		0x19991EA2174C1FDFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x855A88E6701DDEF8ULL,
		0x0350E5B95B104A04ULL,
		0x962ECD33EA3B4DDAULL,
		0x82D0C9A16374F97FULL,
		0xE52FD859DB24D5C4ULL,
		0xFAEBFC847F677F68ULL,
		0x7038FE14027425EDULL,
		0x33323D442E983FBFULL
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
		0x85C4BE928093D6D0ULL,
		0xDCEA629773E22C33ULL,
		0xF6400278968EB629ULL,
		0x7DE74CA028D1CDDEULL,
		0xCCDE4A1D9DF21B07ULL,
		0x611C73838CDDC897ULL,
		0x2F72698F66A33D56ULL,
		0x171B4151BB44B07EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0B897D250127ADA0ULL,
		0xB9D4C52EE7C45867ULL,
		0xEC8004F12D1D6C53ULL,
		0xFBCE994051A39BBDULL,
		0x99BC943B3BE4360EULL,
		0xC238E70719BB912FULL,
		0x5EE4D31ECD467AACULL,
		0x2E3682A3768960FCULL
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
		0x7230848069CF4C1FULL,
		0xDAA9C3373DC9AE2CULL,
		0x72A74117034EC9FCULL,
		0x1C35769D6BC68169ULL,
		0x8A6033B22236176BULL,
		0x9CA91D5A64F8B93FULL,
		0x8E17203563EFCC3BULL,
		0x3CD4C74E4612AD65ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE4610900D39E983EULL,
		0xB553866E7B935C58ULL,
		0xE54E822E069D93F9ULL,
		0x386AED3AD78D02D2ULL,
		0x14C06764446C2ED6ULL,
		0x39523AB4C9F1727FULL,
		0x1C2E406AC7DF9877ULL,
		0x79A98E9C8C255ACBULL
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
		0x8ED83FAEBA183DDCULL,
		0xDA676666607BBD97ULL,
		0x461121B20A70EF02ULL,
		0xD1D348E0A32A774BULL,
		0xFFB7093840EE1F8EULL,
		0xE0086AC2ABFF1C52ULL,
		0x0CE9AF98146B60DEULL,
		0x275CDCB426D8C72AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1DB07F5D74307BB8ULL,
		0xB4CECCCCC0F77B2FULL,
		0x8C22436414E1DE05ULL,
		0xA3A691C14654EE96ULL,
		0xFF6E127081DC3F1DULL,
		0xC010D58557FE38A5ULL,
		0x19D35F3028D6C1BDULL,
		0x4EB9B9684DB18E54ULL
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
		0x37129A33F6F85CCBULL,
		0x715787F3995F7880ULL,
		0x2EBC7F2E7C26C9FBULL,
		0x4D3480EEA93E94C0ULL,
		0x1AF64DF7E115F52DULL,
		0xDBBC591E354E2D7AULL,
		0x08BD18EE231200A6ULL,
		0x318E5F3AEA8F7993ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6E253467EDF0B996ULL,
		0xE2AF0FE732BEF100ULL,
		0x5D78FE5CF84D93F6ULL,
		0x9A6901DD527D2980ULL,
		0x35EC9BEFC22BEA5AULL,
		0xB778B23C6A9C5AF4ULL,
		0x117A31DC4624014DULL,
		0x631CBE75D51EF326ULL
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
		0x42B659C7955197C4ULL,
		0xF2BBFCDCA4732AE3ULL,
		0x4E08F47A93817277ULL,
		0x01584C831F57EBF5ULL,
		0x40BA11F73DA117F5ULL,
		0x51A7C77260533E93ULL,
		0x2207C1C28B95FBB2ULL,
		0x183B09EE313DE2D4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x856CB38F2AA32F88ULL,
		0xE577F9B948E655C6ULL,
		0x9C11E8F52702E4EFULL,
		0x02B099063EAFD7EAULL,
		0x817423EE7B422FEAULL,
		0xA34F8EE4C0A67D26ULL,
		0x440F8385172BF764ULL,
		0x307613DC627BC5A8ULL
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
		0xC14C6A3366A598A0ULL,
		0x3E7246D7BA3C16EEULL,
		0xCECAF057650B0CDDULL,
		0xDBBD00023533CEBDULL,
		0x9F66804FB7A0DE34ULL,
		0xADAF86BB31434DF4ULL,
		0xE872641A6AFDC3B2ULL,
		0x0F2DACD6D912A38CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8298D466CD4B3140ULL,
		0x7CE48DAF74782DDDULL,
		0x9D95E0AECA1619BAULL,
		0xB77A00046A679D7BULL,
		0x3ECD009F6F41BC69ULL,
		0x5B5F0D7662869BE9ULL,
		0xD0E4C834D5FB8765ULL,
		0x1E5B59ADB2254719ULL
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
		0xFAD9293CFBCDFF37ULL,
		0x49C3B2A9CC91D3DFULL,
		0xD5C20B98D6BE9727ULL,
		0x22E59E58284BD469ULL,
		0x3C289B7124E73177ULL,
		0x80B5BB8560121795ULL,
		0xD75F9497EEDC5FACULL,
		0x326B03B16A371717ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF5B25279F79BFE6EULL,
		0x938765539923A7BFULL,
		0xAB841731AD7D2E4EULL,
		0x45CB3CB05097A8D3ULL,
		0x785136E249CE62EEULL,
		0x016B770AC0242F2AULL,
		0xAEBF292FDDB8BF59ULL,
		0x64D60762D46E2E2FULL
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
		0x9B4B381FEFB0E48FULL,
		0x4842F2274384BFB7ULL,
		0xC1B73B2B104CA6B8ULL,
		0xA1BD85E0A4489E96ULL,
		0x55C21F2DBF721487ULL,
		0x54FEA03F843D55FFULL,
		0xAB1DBE78F080F28FULL,
		0x1B23F3B783B6F1D6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3696703FDF61C91EULL,
		0x9085E44E87097F6FULL,
		0x836E765620994D70ULL,
		0x437B0BC148913D2DULL,
		0xAB843E5B7EE4290FULL,
		0xA9FD407F087AABFEULL,
		0x563B7CF1E101E51EULL,
		0x3647E76F076DE3ADULL
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
		0xE31A4980CE92F74CULL,
		0x79D388BDDD1A4CA7ULL,
		0x12E112C51B00C6FAULL,
		0xD3AA4C8F4936519AULL,
		0x5B6D92E3E54381D6ULL,
		0x055710F6FE35AB3CULL,
		0x7CF249F910BCD35BULL,
		0x1C1709C1E53E9ADBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC63493019D25EE98ULL,
		0xF3A7117BBA34994FULL,
		0x25C2258A36018DF4ULL,
		0xA754991E926CA334ULL,
		0xB6DB25C7CA8703ADULL,
		0x0AAE21EDFC6B5678ULL,
		0xF9E493F22179A6B6ULL,
		0x382E1383CA7D35B6ULL
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
		0x02ACD393532B7D85ULL,
		0x266F25055409D56BULL,
		0x783741DEBA48AE0FULL,
		0xA30BB66762EBA90DULL,
		0x64A596D52E2643E1ULL,
		0x5D11A8DFD3E5A344ULL,
		0x1C5A6CC0B4022233ULL,
		0x02DF8944ECF0FF42ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0559A726A656FB0AULL,
		0x4CDE4A0AA813AAD6ULL,
		0xF06E83BD74915C1EULL,
		0x46176CCEC5D7521AULL,
		0xC94B2DAA5C4C87C3ULL,
		0xBA2351BFA7CB4688ULL,
		0x38B4D98168044466ULL,
		0x05BF1289D9E1FE84ULL
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
		0x3B09F3497DF3BD2BULL,
		0x7988EE73C5B29910ULL,
		0x38B32B957F2D20E7ULL,
		0xEF69E458DED675F0ULL,
		0x21FB7E592D7C858EULL,
		0xA3FB512BB2A7B446ULL,
		0xD445E76C53ED7539ULL,
		0x3FF21246334F25CCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7613E692FBE77A56ULL,
		0xF311DCE78B653220ULL,
		0x7166572AFE5A41CEULL,
		0xDED3C8B1BDACEBE0ULL,
		0x43F6FCB25AF90B1DULL,
		0x47F6A257654F688CULL,
		0xA88BCED8A7DAEA73ULL,
		0x7FE4248C669E4B99ULL
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
		0xF6FAE52C3B4EFCBAULL,
		0x3D189F2DD312CF0BULL,
		0x96527974924EA9F6ULL,
		0x4EA31EF939A3C6BEULL,
		0xAACCD5F3BE88176DULL,
		0x753E1F1C0CF610C2ULL,
		0xBC1EB65C70FF7DA3ULL,
		0x2794194FD739FDA6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEDF5CA58769DF974ULL,
		0x7A313E5BA6259E17ULL,
		0x2CA4F2E9249D53ECULL,
		0x9D463DF273478D7DULL,
		0x5599ABE77D102EDAULL,
		0xEA7C3E3819EC2185ULL,
		0x783D6CB8E1FEFB46ULL,
		0x4F28329FAE73FB4DULL
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
		0x6E2B8718708ADF09ULL,
		0xEAA69933ABF38058ULL,
		0x3646D32B59B3C85DULL,
		0x286F337C9BCB6C67ULL,
		0x838DC64A26B3180EULL,
		0xD295B96808A038B1ULL,
		0x333708D943F74D85ULL,
		0x25AA603F7070DBD1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDC570E30E115BE12ULL,
		0xD54D326757E700B0ULL,
		0x6C8DA656B36790BBULL,
		0x50DE66F93796D8CEULL,
		0x071B8C944D66301CULL,
		0xA52B72D011407163ULL,
		0x666E11B287EE9B0BULL,
		0x4B54C07EE0E1B7A2ULL
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
		0x52E3D11FD46AC0B8ULL,
		0xCE1DD262E3EEE0CBULL,
		0x751E37A3689805C8ULL,
		0x62E30F7BA16B0C89ULL,
		0x2C0FC0D6BE29C356ULL,
		0x212F821DC4E03B56ULL,
		0xCFFB729A77A39DBEULL,
		0x3F59F7B10D88F42EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA5C7A23FA8D58170ULL,
		0x9C3BA4C5C7DDC196ULL,
		0xEA3C6F46D1300B91ULL,
		0xC5C61EF742D61912ULL,
		0x581F81AD7C5386ACULL,
		0x425F043B89C076ACULL,
		0x9FF6E534EF473B7CULL,
		0x7EB3EF621B11E85DULL
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
		0xE5B49650B6D5AE07ULL,
		0x147360BC010875A5ULL,
		0x9F74BAD272B9DE7EULL,
		0xC4A90F63E17DC7C6ULL,
		0x52ADA3258B3F3C3EULL,
		0x85D110C816972859ULL,
		0xC8E399F896922339ULL,
		0x053363D87DA9C5A6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCB692CA16DAB5C0EULL,
		0x28E6C1780210EB4BULL,
		0x3EE975A4E573BCFCULL,
		0x89521EC7C2FB8F8DULL,
		0xA55B464B167E787DULL,
		0x0BA221902D2E50B2ULL,
		0x91C733F12D244673ULL,
		0x0A66C7B0FB538B4DULL
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
		0xE2C1EABA112AD7FCULL,
		0x8BEF6B54A6AF69EDULL,
		0x9523B62C47919B52ULL,
		0x2DBA52A6DB0BE072ULL,
		0x86D5AE461A75E3EBULL,
		0x1DCCA8A4FD725E36ULL,
		0xD055477F7B9DCA81ULL,
		0x28E8703A5223AC21ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC583D5742255AFF8ULL,
		0x17DED6A94D5ED3DBULL,
		0x2A476C588F2336A5ULL,
		0x5B74A54DB617C0E5ULL,
		0x0DAB5C8C34EBC7D6ULL,
		0x3B995149FAE4BC6DULL,
		0xA0AA8EFEF73B9502ULL,
		0x51D0E074A4475843ULL
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
		0x022B278C7308C8A7ULL,
		0x71A987E41409FFCFULL,
		0x2424BF58238FB1C7ULL,
		0x5D8D06947B268F6AULL,
		0x8C72E840CEC7BD41ULL,
		0x5A9CEB908048B7C0ULL,
		0xF6D5190D6ADD4038ULL,
		0x042EF37F0032D9F0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x04564F18E611914EULL,
		0xE3530FC82813FF9EULL,
		0x48497EB0471F638EULL,
		0xBB1A0D28F64D1ED4ULL,
		0x18E5D0819D8F7A82ULL,
		0xB539D72100916F81ULL,
		0xEDAA321AD5BA8070ULL,
		0x085DE6FE0065B3E1ULL
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
		0x26FB91B250927CA3ULL,
		0x3728AFBDCDB6699EULL,
		0xD39AFBF19A049A87ULL,
		0xD5AF2F00E8C3627BULL,
		0x9FC0F23B916746A6ULL,
		0x77ECB229361D1767ULL,
		0x5514C00D7131A726ULL,
		0x38558671B0C4D489ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4DF72364A124F946ULL,
		0x6E515F7B9B6CD33CULL,
		0xA735F7E33409350EULL,
		0xAB5E5E01D186C4F7ULL,
		0x3F81E47722CE8D4DULL,
		0xEFD964526C3A2ECFULL,
		0xAA29801AE2634E4CULL,
		0x70AB0CE36189A912ULL
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
		0xE355B99AFBA24A72ULL,
		0xE02CD91935F34720ULL,
		0xB579D02A29CA278DULL,
		0xCDDB40964D90B082ULL,
		0x417DB21D030D84ADULL,
		0x9B20B8DB22DEDAA2ULL,
		0xF274660025C4B23CULL,
		0x064B4931F8E5C061ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC6AB7335F74494E4ULL,
		0xC059B2326BE68E41ULL,
		0x6AF3A05453944F1BULL,
		0x9BB6812C9B216105ULL,
		0x82FB643A061B095BULL,
		0x364171B645BDB544ULL,
		0xE4E8CC004B896479ULL,
		0x0C969263F1CB80C3ULL
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
		0x7E97302AFD8E75D8ULL,
		0xCA6FED14C7376BE2ULL,
		0x6CFC1423D2CD34E6ULL,
		0x300FFBE83AB0CD6EULL,
		0xCE16B38E2DE2F589ULL,
		0x12BAD4451286621EULL,
		0xE856A49BA6D87091ULL,
		0x29A6AAEFF1D50DF0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFD2E6055FB1CEBB0ULL,
		0x94DFDA298E6ED7C4ULL,
		0xD9F82847A59A69CDULL,
		0x601FF7D075619ADCULL,
		0x9C2D671C5BC5EB12ULL,
		0x2575A88A250CC43DULL,
		0xD0AD49374DB0E122ULL,
		0x534D55DFE3AA1BE1ULL
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
		0xBD941E55C23E5D17ULL,
		0x54044240CFF98A5CULL,
		0x0A6D8A76B259394FULL,
		0x02D38A27B863A6B3ULL,
		0x2F2FF52AA1066B70ULL,
		0x0DD41BF77E5515F8ULL,
		0x83A4635389477663ULL,
		0x2A1615AD4147F5BFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7B283CAB847CBA2EULL,
		0xA80884819FF314B9ULL,
		0x14DB14ED64B2729EULL,
		0x05A7144F70C74D66ULL,
		0x5E5FEA55420CD6E0ULL,
		0x1BA837EEFCAA2BF0ULL,
		0x0748C6A7128EECC6ULL,
		0x542C2B5A828FEB7FULL
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
		0x6A0B110B2DB2607CULL,
		0x5F3269C6659CF0FEULL,
		0x9451D5D1D1DE79F1ULL,
		0x60203EB72E7D2E2BULL,
		0xFFAC355CE1CE1BA7ULL,
		0x5BE9D44BC209B6D2ULL,
		0x510898C09BE8542CULL,
		0x2C39A75C7D224716ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD41622165B64C0F8ULL,
		0xBE64D38CCB39E1FCULL,
		0x28A3ABA3A3BCF3E2ULL,
		0xC0407D6E5CFA5C57ULL,
		0xFF586AB9C39C374EULL,
		0xB7D3A89784136DA5ULL,
		0xA211318137D0A858ULL,
		0x58734EB8FA448E2CULL
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
		0xD3FEC63B6BB34B1DULL,
		0x2CF071CDE325ECD2ULL,
		0x0D0D7BE4A1D4D8C8ULL,
		0x3EEA7BB5E95B58CEULL,
		0x19DA8994C69E88E9ULL,
		0xB6C158AD85F25661ULL,
		0xA4349E3B3360A64EULL,
		0x34FFF49861178C66ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA7FD8C76D766963AULL,
		0x59E0E39BC64BD9A5ULL,
		0x1A1AF7C943A9B190ULL,
		0x7DD4F76BD2B6B19CULL,
		0x33B513298D3D11D2ULL,
		0x6D82B15B0BE4ACC2ULL,
		0x48693C7666C14C9DULL,
		0x69FFE930C22F18CDULL
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
		0xCC34F45D71BE2F2BULL,
		0x4D9A7FA695FFC21CULL,
		0x2F04267241978749ULL,
		0x4F3E68AB511D82DFULL,
		0xCB082D6889EAFB31ULL,
		0xF9A189F18C735BC9ULL,
		0x9289606797AD363DULL,
		0x312EA8BDC2EB3853ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9869E8BAE37C5E56ULL,
		0x9B34FF4D2BFF8439ULL,
		0x5E084CE4832F0E92ULL,
		0x9E7CD156A23B05BEULL,
		0x96105AD113D5F662ULL,
		0xF34313E318E6B793ULL,
		0x2512C0CF2F5A6C7BULL,
		0x625D517B85D670A7ULL
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
		0x35527F8F287F4211ULL,
		0xAD204B7A130B81CBULL,
		0x880B768D4625F97EULL,
		0xB5FDD69B2F9FACB3ULL,
		0xBAA6ED0A9DE6CD19ULL,
		0x990242EAD6D2624BULL,
		0x1858CC5BEBE902EEULL,
		0x3F7F332B86B77C59ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6AA4FF1E50FE8422ULL,
		0x5A4096F426170396ULL,
		0x1016ED1A8C4BF2FDULL,
		0x6BFBAD365F3F5967ULL,
		0x754DDA153BCD9A33ULL,
		0x320485D5ADA4C497ULL,
		0x30B198B7D7D205DDULL,
		0x7EFE66570D6EF8B2ULL
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
		0x2F6F818FD1E90935ULL,
		0x688F141B436AE89BULL,
		0xE52D329CDC14E8E9ULL,
		0x1CE92EFE7EE50935ULL,
		0x4CC1F456DBC29E32ULL,
		0x65717116227146D4ULL,
		0x3F9C1B1AD0FB9AF6ULL,
		0x33A439C6C060A989ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5EDF031FA3D2126AULL,
		0xD11E283686D5D136ULL,
		0xCA5A6539B829D1D2ULL,
		0x39D25DFCFDCA126BULL,
		0x9983E8ADB7853C64ULL,
		0xCAE2E22C44E28DA8ULL,
		0x7F383635A1F735ECULL,
		0x6748738D80C15312ULL
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
		0x4F9DEBC224264166ULL,
		0x2DCD6557C1D1210FULL,
		0xD1713BE0CD952505ULL,
		0x7B2AAFF40A28AE83ULL,
		0x0C8C53949CBAAF55ULL,
		0x00BBE2483F5E2289ULL,
		0xBA52F7561850EE6CULL,
		0x27D6393A51E9AA07ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9F3BD784484C82CCULL,
		0x5B9ACAAF83A2421EULL,
		0xA2E277C19B2A4A0AULL,
		0xF6555FE814515D07ULL,
		0x1918A72939755EAAULL,
		0x0177C4907EBC4512ULL,
		0x74A5EEAC30A1DCD8ULL,
		0x4FAC7274A3D3540FULL
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
		0x42C69ED8B67FCD04ULL,
		0x9DDD80659F5D6D28ULL,
		0xA93804B31AF24C5BULL,
		0x088C4A88A6BDE4CFULL,
		0x59132512B1F8F50FULL,
		0x0403A96D8BA5CA19ULL,
		0xB133BB198650D9D8ULL,
		0x346F38BD83E3E39FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x858D3DB16CFF9A08ULL,
		0x3BBB00CB3EBADA50ULL,
		0x5270096635E498B7ULL,
		0x111895114D7BC99FULL,
		0xB2264A2563F1EA1EULL,
		0x080752DB174B9432ULL,
		0x626776330CA1B3B0ULL,
		0x68DE717B07C7C73FULL
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
		0xDA6B6713EEC9D795ULL,
		0xDE9DCB24C1F30B6BULL,
		0xFC5BE564C2343DD1ULL,
		0xBDC246635DB13FD4ULL,
		0x437D7CC7336268C0ULL,
		0xBB8C819D2BE7B075ULL,
		0xD1ACB20BB70CB4C9ULL,
		0x1DB8D42078982CCDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB4D6CE27DD93AF2AULL,
		0xBD3B964983E616D7ULL,
		0xF8B7CAC984687BA3ULL,
		0x7B848CC6BB627FA9ULL,
		0x86FAF98E66C4D181ULL,
		0x7719033A57CF60EAULL,
		0xA35964176E196993ULL,
		0x3B71A840F130599BULL
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
		0x7DE98AF573992F69ULL,
		0x758596BF2CC1BDBEULL,
		0xCC6AD67B91F615DCULL,
		0x4375991966FB8226ULL,
		0x082A124B6963CB5CULL,
		0x9B9B1F903BB32023ULL,
		0x1B43A78E405296A2ULL,
		0x21B519E166518E10ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFBD315EAE7325ED2ULL,
		0xEB0B2D7E59837B7CULL,
		0x98D5ACF723EC2BB8ULL,
		0x86EB3232CDF7044DULL,
		0x10542496D2C796B8ULL,
		0x37363F2077664046ULL,
		0x36874F1C80A52D45ULL,
		0x436A33C2CCA31C20ULL
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
		0xBC57550CF04EEE1FULL,
		0xD92D4D281E2D1C06ULL,
		0xB20F042315F40FE7ULL,
		0x7A1F0BDD9CB85E73ULL,
		0x1EA635CA1E9FD6EFULL,
		0x80D4ACFD545122B6ULL,
		0x92D42D8A2B2F8349ULL,
		0x2F41F1971388161CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x78AEAA19E09DDC3EULL,
		0xB25A9A503C5A380DULL,
		0x641E08462BE81FCFULL,
		0xF43E17BB3970BCE7ULL,
		0x3D4C6B943D3FADDEULL,
		0x01A959FAA8A2456CULL,
		0x25A85B14565F0693ULL,
		0x5E83E32E27102C39ULL
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
		0x5954DE776D6F3321ULL,
		0x03E42BADE8E30FA4ULL,
		0xEFBD6F58D36964FFULL,
		0xD4C86A5603B82033ULL,
		0x06FCE53E6A55C6EEULL,
		0xAC200D9333867F64ULL,
		0x88B2E127114625D3ULL,
		0x16210C68204F8D55ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB2A9BCEEDADE6642ULL,
		0x07C8575BD1C61F48ULL,
		0xDF7ADEB1A6D2C9FEULL,
		0xA990D4AC07704067ULL,
		0x0DF9CA7CD4AB8DDDULL,
		0x58401B26670CFEC8ULL,
		0x1165C24E228C4BA7ULL,
		0x2C4218D0409F1AABULL
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
		0x75D2D2D0DC058173ULL,
		0x2253F114817C9055ULL,
		0x3C33F3FDBDAE654DULL,
		0x732394DEBAA16145ULL,
		0x2A1EA7D40D3A3382ULL,
		0xFFA6D705A1A1EF26ULL,
		0xD2950233B5796E3AULL,
		0x35437D17AE692FCBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEBA5A5A1B80B02E6ULL,
		0x44A7E22902F920AAULL,
		0x7867E7FB7B5CCA9AULL,
		0xE64729BD7542C28AULL,
		0x543D4FA81A746704ULL,
		0xFF4DAE0B4343DE4CULL,
		0xA52A04676AF2DC75ULL,
		0x6A86FA2F5CD25F97ULL
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
		0xDE285973E8AA174EULL,
		0x83A8F53966977081ULL,
		0xB021A31EFE75259AULL,
		0xBC81D9F0AA9E3938ULL,
		0x118C2BEFAEDD752CULL,
		0x56BCB0F3004560AEULL,
		0x8EEA05B9EB4E08A8ULL,
		0x3C16F59E1FD32309ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBC50B2E7D1542E9CULL,
		0x0751EA72CD2EE103ULL,
		0x6043463DFCEA4B35ULL,
		0x7903B3E1553C7271ULL,
		0x231857DF5DBAEA59ULL,
		0xAD7961E6008AC15CULL,
		0x1DD40B73D69C1150ULL,
		0x782DEB3C3FA64613ULL
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
		0x9758B6089F275FCFULL,
		0xA291F5451483D2FBULL,
		0x2B91C4A03A7B1C8DULL,
		0x280C9847B0952AFEULL,
		0x8E98E9944DE0EF75ULL,
		0xF3D3DC2EEB03D4CBULL,
		0x2D194506BA6DD833ULL,
		0x0615A5E557C65B80ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2EB16C113E4EBF9EULL,
		0x4523EA8A2907A5F7ULL,
		0x5723894074F6391BULL,
		0x5019308F612A55FCULL,
		0x1D31D3289BC1DEEAULL,
		0xE7A7B85DD607A997ULL,
		0x5A328A0D74DBB067ULL,
		0x0C2B4BCAAF8CB700ULL
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
		0x2F637043C3BB6674ULL,
		0xB4237DF7BA05FB68ULL,
		0xA98101F9447672B9ULL,
		0x9CD7EC02C862BD2EULL,
		0xF5D54F5EE233EB1EULL,
		0x953DC685862AFFA8ULL,
		0xA22BB4F036FA8CDFULL,
		0x3529E69ACCFB998FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5EC6E0878776CCE8ULL,
		0x6846FBEF740BF6D0ULL,
		0x530203F288ECE573ULL,
		0x39AFD80590C57A5DULL,
		0xEBAA9EBDC467D63DULL,
		0x2A7B8D0B0C55FF51ULL,
		0x445769E06DF519BFULL,
		0x6A53CD3599F7331FULL
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
		0x3A67EADD525CC903ULL,
		0xC84E18DCB48F0B20ULL,
		0x7876BF3CCA5D68A8ULL,
		0xF9C8B5E0AEB262ADULL,
		0xEB0986F9B90A9ECEULL,
		0xDD0FCA1DEB2810A5ULL,
		0x105D0DDF7B4657C1ULL,
		0x1E92EF13A746B55BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x74CFD5BAA4B99206ULL,
		0x909C31B9691E1640ULL,
		0xF0ED7E7994BAD151ULL,
		0xF3916BC15D64C55AULL,
		0xD6130DF372153D9DULL,
		0xBA1F943BD650214BULL,
		0x20BA1BBEF68CAF83ULL,
		0x3D25DE274E8D6AB6ULL
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
		0x14FB1D75A4574E97ULL,
		0x6C66E33D5FE5549DULL,
		0x1825527E2BD35580ULL,
		0x7F25F0DB95970C27ULL,
		0xF3C8C55065A33576ULL,
		0x30789ED7836F78ACULL,
		0xE8D320BFCF6299AFULL,
		0x01F632856D67C925ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x29F63AEB48AE9D2EULL,
		0xD8CDC67ABFCAA93AULL,
		0x304AA4FC57A6AB00ULL,
		0xFE4BE1B72B2E184EULL,
		0xE7918AA0CB466AECULL,
		0x60F13DAF06DEF159ULL,
		0xD1A6417F9EC5335EULL,
		0x03EC650ADACF924BULL
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
		0xE7BAFB7E03640F39ULL,
		0x21ABE531F6946FEEULL,
		0xC16289794C44DEE4ULL,
		0xE8924ED954FC6FC8ULL,
		0x75E27600FBD8927DULL,
		0xF25026E12D2A75E1ULL,
		0xC87F69E6AC367421ULL,
		0x24EE83F2417C21BCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCF75F6FC06C81E72ULL,
		0x4357CA63ED28DFDDULL,
		0x82C512F29889BDC8ULL,
		0xD1249DB2A9F8DF91ULL,
		0xEBC4EC01F7B124FBULL,
		0xE4A04DC25A54EBC2ULL,
		0x90FED3CD586CE843ULL,
		0x49DD07E482F84379ULL
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
		0x06318194F6F8E0C2ULL,
		0x54E9D4799EA762A6ULL,
		0xA84249248AEA1A53ULL,
		0x3EAC27F3505F32CAULL,
		0xFE1E6192289075E6ULL,
		0x03F9D28ACE4C5EB5ULL,
		0xFE98377919B4E4E2ULL,
		0x2506BB2C951AF1E3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0C630329EDF1C184ULL,
		0xA9D3A8F33D4EC54CULL,
		0x5084924915D434A6ULL,
		0x7D584FE6A0BE6595ULL,
		0xFC3CC3245120EBCCULL,
		0x07F3A5159C98BD6BULL,
		0xFD306EF23369C9C4ULL,
		0x4A0D76592A35E3C7ULL
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
		0x917EEDA8BA30A23EULL,
		0x3EF59FCC48D97905ULL,
		0x6B33F73251292F30ULL,
		0xA07D480CF46C5ABEULL,
		0x6664C5D0DF96AD05ULL,
		0x34CD5F28CAEFD7F4ULL,
		0x7342A2F7C4AC590DULL,
		0x3A8423F49EAB2C3AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x22FDDB517461447CULL,
		0x7DEB3F9891B2F20BULL,
		0xD667EE64A2525E60ULL,
		0x40FA9019E8D8B57CULL,
		0xCCC98BA1BF2D5A0BULL,
		0x699ABE5195DFAFE8ULL,
		0xE68545EF8958B21AULL,
		0x750847E93D565874ULL
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
		0xB0C3D580AB30F902ULL,
		0xF3971A7892098749ULL,
		0xD1EDC44D6B8B0110ULL,
		0xDC2237759604CC90ULL,
		0x037C8AE083468006ULL,
		0x4D6C09C8CE3FB70DULL,
		0xB25153632CAA13E4ULL,
		0x37CA609F03D496D6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6187AB015661F204ULL,
		0xE72E34F124130E93ULL,
		0xA3DB889AD7160221ULL,
		0xB8446EEB2C099921ULL,
		0x06F915C1068D000DULL,
		0x9AD813919C7F6E1AULL,
		0x64A2A6C6595427C8ULL,
		0x6F94C13E07A92DADULL
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
		0x55BB6CA2947FA471ULL,
		0x658177F7775BBA57ULL,
		0xB6389D57C40D5A8AULL,
		0xF7135B65894FDFC1ULL,
		0xDB8E260F9CFA8869ULL,
		0x97B6880D4CBDC4CDULL,
		0x69344D59E1961C14ULL,
		0x2C6C120B9F1CA242ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAB76D94528FF48E2ULL,
		0xCB02EFEEEEB774AEULL,
		0x6C713AAF881AB514ULL,
		0xEE26B6CB129FBF83ULL,
		0xB71C4C1F39F510D3ULL,
		0x2F6D101A997B899BULL,
		0xD2689AB3C32C3829ULL,
		0x58D824173E394484ULL
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
		0xB9D315E935BA2272ULL,
		0xFA2CA38F514AA5D3ULL,
		0xADD063EAC3767FE7ULL,
		0xA59E44812816B2F1ULL,
		0x24A4D57B1593B4A9ULL,
		0x14CE4D5C65D5C8B5ULL,
		0x10EC0C3061CB9C52ULL,
		0x0B69FE1443C77607ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x73A62BD26B7444E4ULL,
		0xF459471EA2954BA7ULL,
		0x5BA0C7D586ECFFCFULL,
		0x4B3C8902502D65E3ULL,
		0x4949AAF62B276953ULL,
		0x299C9AB8CBAB916AULL,
		0x21D81860C39738A4ULL,
		0x16D3FC28878EEC0EULL
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
		0xBD559CA175F78913ULL,
		0x7526004A0FB8C4F1ULL,
		0xE8209C3DD934A1AFULL,
		0x95B6F65026D2F0E1ULL,
		0xB6B09D2392693A71ULL,
		0xB455A4D21C56B0A7ULL,
		0xB9D7F67AA94C36B3ULL,
		0x1B7200C45C78F82DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7AAB3942EBEF1226ULL,
		0xEA4C00941F7189E3ULL,
		0xD041387BB269435EULL,
		0x2B6DECA04DA5E1C3ULL,
		0x6D613A4724D274E3ULL,
		0x68AB49A438AD614FULL,
		0x73AFECF552986D67ULL,
		0x36E40188B8F1F05BULL
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
		0x3494F366CAC0D0CAULL,
		0xE23FB4F8A0F5D046ULL,
		0x4ABF2187CD90097BULL,
		0x96D9F834E509146FULL,
		0xFE8089BCC642C693ULL,
		0x1577CFEBA588D3D2ULL,
		0xF56BAC92E4648871ULL,
		0x16FF08036D02FF05ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6929E6CD9581A194ULL,
		0xC47F69F141EBA08CULL,
		0x957E430F9B2012F7ULL,
		0x2DB3F069CA1228DEULL,
		0xFD0113798C858D27ULL,
		0x2AEF9FD74B11A7A5ULL,
		0xEAD75925C8C910E2ULL,
		0x2DFE1006DA05FE0BULL
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
		0x597D447B89BC7F42ULL,
		0x22F432133440774BULL,
		0xBF49A51A8755EF1BULL,
		0x6C5EED15F3598718ULL,
		0x83043C1DF2D22562ULL,
		0x8DBEA87D9A6B6145ULL,
		0x6C010D5AAFDD413BULL,
		0x29CBF9649BB38C36ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB2FA88F71378FE84ULL,
		0x45E864266880EE96ULL,
		0x7E934A350EABDE36ULL,
		0xD8BDDA2BE6B30E31ULL,
		0x0608783BE5A44AC4ULL,
		0x1B7D50FB34D6C28BULL,
		0xD8021AB55FBA8277ULL,
		0x5397F2C93767186CULL
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
		0xD9C982DA53C14B45ULL,
		0x74565CEC5CF3D84CULL,
		0x2DF11673484DCA94ULL,
		0x7D902DE93DF6DFDCULL,
		0xC280E527712C8808ULL,
		0xDFBE5FCEA155CBDDULL,
		0xB5D0AC484FDBD311ULL,
		0x1D063A86EA5B33CAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB39305B4A782968AULL,
		0xE8ACB9D8B9E7B099ULL,
		0x5BE22CE6909B9528ULL,
		0xFB205BD27BEDBFB8ULL,
		0x8501CA4EE2591010ULL,
		0xBF7CBF9D42AB97BBULL,
		0x6BA158909FB7A623ULL,
		0x3A0C750DD4B66795ULL
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
		0xD6601C583F800C7FULL,
		0x3999E627140489EAULL,
		0x77AC8A62392AB3F4ULL,
		0xC865C9775E08D938ULL,
		0xC1F5657124D47D8FULL,
		0x32379BD9405DCC17ULL,
		0x6A915E590FCD5CE3ULL,
		0x349849B6D495B798ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xACC038B07F0018FEULL,
		0x7333CC4E280913D5ULL,
		0xEF5914C4725567E8ULL,
		0x90CB92EEBC11B270ULL,
		0x83EACAE249A8FB1FULL,
		0x646F37B280BB982FULL,
		0xD522BCB21F9AB9C6ULL,
		0x6930936DA92B6F30ULL
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
		0x8F27F1CFE2581D9AULL,
		0xA9B97F2BC421298BULL,
		0x1CEFC2B04E96B6A2ULL,
		0xDACE063F0C4209E7ULL,
		0xB66DA25373BDA5A5ULL,
		0x7CA50CDA7A9D3C3AULL,
		0x98C5DC1511D2A221ULL,
		0x1B7D76DA477E0468ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1E4FE39FC4B03B34ULL,
		0x5372FE5788425317ULL,
		0x39DF85609D2D6D45ULL,
		0xB59C0C7E188413CEULL,
		0x6CDB44A6E77B4B4BULL,
		0xF94A19B4F53A7875ULL,
		0x318BB82A23A54442ULL,
		0x36FAEDB48EFC08D1ULL
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
		0xBD367C92300F0DF9ULL,
		0xD95F01787BCC140CULL,
		0xE399CF0E167322E1ULL,
		0x3BE58C280489D905ULL,
		0x7CB3D75B4D2A9DCBULL,
		0xB9D84B34F4145637ULL,
		0xE6193A941AF882E8ULL,
		0x021D25C4014FF4D8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7A6CF924601E1BF2ULL,
		0xB2BE02F0F7982819ULL,
		0xC7339E1C2CE645C3ULL,
		0x77CB18500913B20BULL,
		0xF967AEB69A553B96ULL,
		0x73B09669E828AC6EULL,
		0xCC32752835F105D1ULL,
		0x043A4B88029FE9B1ULL
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
		0x83B3957DF49EDE26ULL,
		0x9B2082128F5B610DULL,
		0x83B7C3836689977DULL,
		0xF6E557D5F415F51BULL,
		0x7376F9DA55FBBA1DULL,
		0xEBCEE45111FBA983ULL,
		0x7CD1A0ACEDDE45DFULL,
		0x27E5E7F0DF492230ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x07672AFBE93DBC4CULL,
		0x364104251EB6C21BULL,
		0x076F8706CD132EFBULL,
		0xEDCAAFABE82BEA37ULL,
		0xE6EDF3B4ABF7743BULL,
		0xD79DC8A223F75306ULL,
		0xF9A34159DBBC8BBFULL,
		0x4FCBCFE1BE924460ULL
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
		0x1826B46D4DEC77AAULL,
		0x4D536AC305CF6321ULL,
		0x585A17BDC98EDC81ULL,
		0xD35F3A4C00A5E31AULL,
		0xECC75D71056DDD99ULL,
		0x4EE46A990E757282ULL,
		0x5AD742B844115687ULL,
		0x04823DBD08E97888ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x304D68DA9BD8EF54ULL,
		0x9AA6D5860B9EC642ULL,
		0xB0B42F7B931DB902ULL,
		0xA6BE7498014BC634ULL,
		0xD98EBAE20ADBBB33ULL,
		0x9DC8D5321CEAE505ULL,
		0xB5AE85708822AD0EULL,
		0x09047B7A11D2F110ULL
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
		0x67814B30939245C3ULL,
		0xF937E310E72BC83DULL,
		0x110FFAC040676A0FULL,
		0xED4445C9B2AF428CULL,
		0x6EABD689C7DA3DCCULL,
		0x307C75D39771F85AULL,
		0x389BBF66C5621FE4ULL,
		0x32DCC050AF7EDD0BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCF02966127248B86ULL,
		0xF26FC621CE57907AULL,
		0x221FF58080CED41FULL,
		0xDA888B93655E8518ULL,
		0xDD57AD138FB47B99ULL,
		0x60F8EBA72EE3F0B4ULL,
		0x71377ECD8AC43FC8ULL,
		0x65B980A15EFDBA16ULL
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
		0x19946363F6170996ULL,
		0x88A7464060163CA5ULL,
		0x5B476FF3F74E6496ULL,
		0x47F950F6C482FDB5ULL,
		0xD39AEE3F001776C2ULL,
		0x7D297619CED4518DULL,
		0x05EBE5689481CD15ULL,
		0x3665B61E06F8726DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3328C6C7EC2E132CULL,
		0x114E8C80C02C794AULL,
		0xB68EDFE7EE9CC92DULL,
		0x8FF2A1ED8905FB6AULL,
		0xA735DC7E002EED84ULL,
		0xFA52EC339DA8A31BULL,
		0x0BD7CAD129039A2AULL,
		0x6CCB6C3C0DF0E4DAULL
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
		0xAE2B1975189E6A03ULL,
		0xAACBB9A7669F00B5ULL,
		0xDE52944ED97275CDULL,
		0x3AE13B7B243CFAA9ULL,
		0x3C74D965FD63FFC0ULL,
		0xA75B2586490B0164ULL,
		0xE0A1AD543022386BULL,
		0x3CE3F139ACF7A1C7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5C5632EA313CD406ULL,
		0x5597734ECD3E016BULL,
		0xBCA5289DB2E4EB9BULL,
		0x75C276F64879F553ULL,
		0x78E9B2CBFAC7FF80ULL,
		0x4EB64B0C921602C8ULL,
		0xC1435AA8604470D7ULL,
		0x79C7E27359EF438FULL
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
		0x1166768A7587AF90ULL,
		0xA98921C6385F0213ULL,
		0x376FE3F6499969E1ULL,
		0x22DC1AC8C084EB43ULL,
		0x4C735BFE7C1F40B2ULL,
		0x3A97F18E122C940AULL,
		0xF5466FA60B342885ULL,
		0x3ACF354EB22600A8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x22CCED14EB0F5F20ULL,
		0x5312438C70BE0426ULL,
		0x6EDFC7EC9332D3C3ULL,
		0x45B835918109D686ULL,
		0x98E6B7FCF83E8164ULL,
		0x752FE31C24592814ULL,
		0xEA8CDF4C1668510AULL,
		0x759E6A9D644C0151ULL
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
		0xCB7A077564E7FF4AULL,
		0xC7B055CFF8DA6E7DULL,
		0x3B44426A8258B8B1ULL,
		0x4E9187296A69466EULL,
		0xFADCCA0960914452ULL,
		0x0ADD4AD5E9783C71ULL,
		0xD8990CCA4CA9E776ULL,
		0x099B5C5B8679F9F7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x96F40EEAC9CFFE94ULL,
		0x8F60AB9FF1B4DCFBULL,
		0x768884D504B17163ULL,
		0x9D230E52D4D28CDCULL,
		0xF5B99412C12288A4ULL,
		0x15BA95ABD2F078E3ULL,
		0xB13219949953CEECULL,
		0x1336B8B70CF3F3EFULL
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
		0xB59FCF46A8DB2173ULL,
		0x458430657D4B426EULL,
		0x403F1338FE24CEF3ULL,
		0x985BD2CC4BF9ACC8ULL,
		0x2764CE1375440EE8ULL,
		0x1CD989C7D33B9746ULL,
		0x3102B739FFDF34F6ULL,
		0x197D55D45C332ECEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6B3F9E8D51B642E6ULL,
		0x8B0860CAFA9684DDULL,
		0x807E2671FC499DE6ULL,
		0x30B7A59897F35990ULL,
		0x4EC99C26EA881DD1ULL,
		0x39B3138FA6772E8CULL,
		0x62056E73FFBE69ECULL,
		0x32FAABA8B8665D9CULL
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
		0x6E4195BB8811AE93ULL,
		0x0257E90A425D865EULL,
		0x7E0E2B6D7CA13C5DULL,
		0xD208960CE09075DAULL,
		0x7FAF5BF965251818ULL,
		0x3FAA8B392CD62F3FULL,
		0x37EA7C3DA1A90662ULL,
		0x3DED0A119A29DAADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDC832B7710235D26ULL,
		0x04AFD21484BB0CBCULL,
		0xFC1C56DAF94278BAULL,
		0xA4112C19C120EBB4ULL,
		0xFF5EB7F2CA4A3031ULL,
		0x7F55167259AC5E7EULL,
		0x6FD4F87B43520CC4ULL,
		0x7BDA14233453B55AULL
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
		0xC84533910C5B8213ULL,
		0xA92FE56C5028C835ULL,
		0x884BA7937BD370BBULL,
		0x92078EA50F8927D3ULL,
		0x9E714B7A2C675C03ULL,
		0xA9433F6D2929C419ULL,
		0x02BAAB973CDA752BULL,
		0x3C2E2896637DBB29ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x908A672218B70426ULL,
		0x525FCAD8A051906BULL,
		0x10974F26F7A6E177ULL,
		0x240F1D4A1F124FA7ULL,
		0x3CE296F458CEB807ULL,
		0x52867EDA52538833ULL,
		0x0575572E79B4EA57ULL,
		0x785C512CC6FB7652ULL
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
		0x44D2A06A94777B25ULL,
		0x63A1E70AE669D4FBULL,
		0xF1F26640AFA3FF9AULL,
		0x30760CF426E25386ULL,
		0xD682BBCFB259DBA1ULL,
		0xDD540694CFFDDEBCULL,
		0x6AB9CEBEBFF7EC61ULL,
		0x15A36779EA84844FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x89A540D528EEF64AULL,
		0xC743CE15CCD3A9F6ULL,
		0xE3E4CC815F47FF34ULL,
		0x60EC19E84DC4A70DULL,
		0xAD05779F64B3B742ULL,
		0xBAA80D299FFBBD79ULL,
		0xD5739D7D7FEFD8C3ULL,
		0x2B46CEF3D509089EULL
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
		0x8144A27C28FEBCABULL,
		0xFFE2BEF11577F421ULL,
		0x5009A2EC431BB656ULL,
		0x6FA26F7A12025D3AULL,
		0x4D8674F1245AF9CAULL,
		0xAEE876220DB9678CULL,
		0x6D8A5B564280F68EULL,
		0x06087F27EBEEB003ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x028944F851FD7956ULL,
		0xFFC57DE22AEFE843ULL,
		0xA01345D886376CADULL,
		0xDF44DEF42404BA74ULL,
		0x9B0CE9E248B5F394ULL,
		0x5DD0EC441B72CF18ULL,
		0xDB14B6AC8501ED1DULL,
		0x0C10FE4FD7DD6006ULL
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
		0x8037D53D5F53ABCDULL,
		0x7B82071E9CA509F3ULL,
		0xB64BB3BB4AD36B35ULL,
		0x82D7E882FBDB3A08ULL,
		0xA24181112264E403ULL,
		0x594E36132338F7DEULL,
		0x1761F4BFCEF53D5AULL,
		0x3CF8A820755F034CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x006FAA7ABEA7579AULL,
		0xF7040E3D394A13E7ULL,
		0x6C97677695A6D66AULL,
		0x05AFD105F7B67411ULL,
		0x4483022244C9C807ULL,
		0xB29C6C264671EFBDULL,
		0x2EC3E97F9DEA7AB4ULL,
		0x79F15040EABE0698ULL
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
		0xDDFEBBE153DD3EF9ULL,
		0x73060BCDE4ABA76AULL,
		0xC68F911AC95064E9ULL,
		0xC0D7A6E08E8F2427ULL,
		0x19AB69691D178FD7ULL,
		0xD95A8AFA49073435ULL,
		0xF12A5FF0FF58E09FULL,
		0x05CA271A5D8D153FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBBFD77C2A7BA7DF2ULL,
		0xE60C179BC9574ED5ULL,
		0x8D1F223592A0C9D2ULL,
		0x81AF4DC11D1E484FULL,
		0x3356D2D23A2F1FAFULL,
		0xB2B515F4920E686AULL,
		0xE254BFE1FEB1C13FULL,
		0x0B944E34BB1A2A7FULL
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
		0x1EF3074A9BF4F0BDULL,
		0x1F5477E416812EBEULL,
		0xC47D058035A3876EULL,
		0xA22ADEA80F50B211ULL,
		0x9A75ADAC048CC7D6ULL,
		0x5DEDD024E649BB4DULL,
		0x93A7BE23AB0A06EDULL,
		0x15289291C347E2ADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3DE60E9537E9E17AULL,
		0x3EA8EFC82D025D7CULL,
		0x88FA0B006B470EDCULL,
		0x4455BD501EA16423ULL,
		0x34EB5B5809198FADULL,
		0xBBDBA049CC93769BULL,
		0x274F7C4756140DDAULL,
		0x2A512523868FC55BULL
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
		0x8B988FBB789F0B82ULL,
		0xDB6E6EB9D28ACEC4ULL,
		0x94342CA6A00A4511ULL,
		0x02C32BE3B2F0ACF7ULL,
		0x81790B151016C985ULL,
		0x4076A1F9D7E5D614ULL,
		0xE165D135E27C357CULL,
		0x0022534EE0662EB4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x17311F76F13E1704ULL,
		0xB6DCDD73A5159D89ULL,
		0x2868594D40148A23ULL,
		0x058657C765E159EFULL,
		0x02F2162A202D930AULL,
		0x80ED43F3AFCBAC29ULL,
		0xC2CBA26BC4F86AF8ULL,
		0x0044A69DC0CC5D69ULL
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
		0xEB506D64B8C547F1ULL,
		0xE718DE068B8BFB5FULL,
		0x95CD6CD8945A867FULL,
		0x68D58366B68775FCULL,
		0x965862BE79AF52E4ULL,
		0x83A9F59CED729AB2ULL,
		0xFC55E326CF55A5C6ULL,
		0x2171F5F2AB93B9B4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD6A0DAC9718A8FE2ULL,
		0xCE31BC0D1717F6BFULL,
		0x2B9AD9B128B50CFFULL,
		0xD1AB06CD6D0EEBF9ULL,
		0x2CB0C57CF35EA5C8ULL,
		0x0753EB39DAE53565ULL,
		0xF8ABC64D9EAB4B8DULL,
		0x42E3EBE557277369ULL
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
		0xB24720829DB1C862ULL,
		0xA9DB9BBC4EEE9049ULL,
		0xCB626AFD5F017836ULL,
		0x1BD1237A7F991B24ULL,
		0x372792B22D5D9F5CULL,
		0xE4EB2126116C5121ULL,
		0x1BE5CE039749AF6DULL,
		0x14A010763F0F6949ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x648E41053B6390C4ULL,
		0x53B737789DDD2093ULL,
		0x96C4D5FABE02F06DULL,
		0x37A246F4FF323649ULL,
		0x6E4F25645ABB3EB8ULL,
		0xC9D6424C22D8A242ULL,
		0x37CB9C072E935EDBULL,
		0x294020EC7E1ED292ULL
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
		0x82524A882CD9A321ULL,
		0xEF85A341C7421ABCULL,
		0x9EC4774DEF9EB548ULL,
		0xAE8DD0967D005278ULL,
		0xE26C386C2A4E5DF1ULL,
		0xDA265250490684AFULL,
		0xA725DB59BAD644DBULL,
		0x2456E6227CB0773AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x04A4951059B34642ULL,
		0xDF0B46838E843579ULL,
		0x3D88EE9BDF3D6A91ULL,
		0x5D1BA12CFA00A4F1ULL,
		0xC4D870D8549CBBE3ULL,
		0xB44CA4A0920D095FULL,
		0x4E4BB6B375AC89B7ULL,
		0x48ADCC44F960EE75ULL
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
		0x353378788A79DB73ULL,
		0x5E3A242DC47A89B0ULL,
		0x28AE0301E3CDEDBBULL,
		0x8D425F63A8F6572BULL,
		0x72FEBF5F95966C01ULL,
		0xDD4418A5AFA02E1AULL,
		0x477DC73403559C3BULL,
		0x2896B159117A5DFCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6A66F0F114F3B6E6ULL,
		0xBC74485B88F51360ULL,
		0x515C0603C79BDB76ULL,
		0x1A84BEC751ECAE56ULL,
		0xE5FD7EBF2B2CD803ULL,
		0xBA88314B5F405C34ULL,
		0x8EFB8E6806AB3877ULL,
		0x512D62B222F4BBF8ULL
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
		0x5467B4F4C2B3B9C0ULL,
		0x947C3AB67F08B9BEULL,
		0xF52E46FF286208C2ULL,
		0x6FE37FF0C3514035ULL,
		0x43C8FE21CEB55D7FULL,
		0x6CA36AA5B2C1F54BULL,
		0xA65899D1B074B321ULL,
		0x09FA19D72EE9135FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA8CF69E985677380ULL,
		0x28F8756CFE11737CULL,
		0xEA5C8DFE50C41185ULL,
		0xDFC6FFE186A2806BULL,
		0x8791FC439D6ABAFEULL,
		0xD946D54B6583EA96ULL,
		0x4CB133A360E96642ULL,
		0x13F433AE5DD226BFULL
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
		0xB136DCFF4B2CD652ULL,
		0x3B257C0649E554A4ULL,
		0xDAE1278B307FB97CULL,
		0xFA3C647861572370ULL,
		0x2D39DDAE33C27901ULL,
		0x103732491720F6BCULL,
		0x23E0F107BEC1DBBBULL,
		0x250011B29AC0B17EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x626DB9FE9659ACA4ULL,
		0x764AF80C93CAA949ULL,
		0xB5C24F1660FF72F8ULL,
		0xF478C8F0C2AE46E1ULL,
		0x5A73BB5C6784F203ULL,
		0x206E64922E41ED78ULL,
		0x47C1E20F7D83B776ULL,
		0x4A002365358162FCULL
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
		0x3BAE880455F3926AULL,
		0xC3F011A2A3300519ULL,
		0x847B207A1825AB49ULL,
		0xAEED82C1DB788763ULL,
		0x09F3984710A38C16ULL,
		0x2213DA81FC25596AULL,
		0x3524E7720CA62552ULL,
		0x3F41D2F3D0519886ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x775D1008ABE724D4ULL,
		0x87E0234546600A32ULL,
		0x08F640F4304B5693ULL,
		0x5DDB0583B6F10EC7ULL,
		0x13E7308E2147182DULL,
		0x4427B503F84AB2D4ULL,
		0x6A49CEE4194C4AA4ULL,
		0x7E83A5E7A0A3310CULL
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
		0xEB3B745D1CAD8FE1ULL,
		0x15C1DCA7A2508882ULL,
		0xC1FEE65B1C340248ULL,
		0x9091126B393C9C7AULL,
		0x61F18E95FEE92BEEULL,
		0x0FA26C02404EEE1BULL,
		0x84D2367FFD155457ULL,
		0x175B2CF1E3EA8AA6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD676E8BA395B1FC2ULL,
		0x2B83B94F44A11105ULL,
		0x83FDCCB638680490ULL,
		0x212224D6727938F5ULL,
		0xC3E31D2BFDD257DDULL,
		0x1F44D804809DDC36ULL,
		0x09A46CFFFA2AA8AEULL,
		0x2EB659E3C7D5154DULL
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
		0x887DE761E0A7A57BULL,
		0x0A89090CD774AF0EULL,
		0x84BA888FC359B958ULL,
		0x10207C75848C2AC1ULL,
		0x532562008C008BE1ULL,
		0xE964ADE617917B6BULL,
		0xE11B6E894F01BC02ULL,
		0x350D09749B2306EFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x10FBCEC3C14F4AF6ULL,
		0x15121219AEE95E1DULL,
		0x0975111F86B372B0ULL,
		0x2040F8EB09185583ULL,
		0xA64AC401180117C2ULL,
		0xD2C95BCC2F22F6D6ULL,
		0xC236DD129E037805ULL,
		0x6A1A12E936460DDFULL
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
		0x54F086294681AC1CULL,
		0x5688518C6C05E656ULL,
		0x01E1E06C688CDABCULL,
		0x019AE0304091F76DULL,
		0x25ED147328307DFAULL,
		0x2883474EC009C8FDULL,
		0x8F20665DFF05D5D4ULL,
		0x24E5DA1CAA99BF87ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA9E10C528D035838ULL,
		0xAD10A318D80BCCACULL,
		0x03C3C0D8D119B578ULL,
		0x0335C0608123EEDAULL,
		0x4BDA28E65060FBF4ULL,
		0x51068E9D801391FAULL,
		0x1E40CCBBFE0BABA8ULL,
		0x49CBB43955337F0FULL
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
		0xB4736B48A044F824ULL,
		0x056686FA7C1267FEULL,
		0x66AC17CAA3AB3C43ULL,
		0x397D215BCC7E0DDFULL,
		0x5D23F16A2C2CFC9EULL,
		0x3B7351991A7F2B9BULL,
		0xDE715DF47BC846CFULL,
		0x076D8E8DBD487341ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x68E6D6914089F048ULL,
		0x0ACD0DF4F824CFFDULL,
		0xCD582F9547567886ULL,
		0x72FA42B798FC1BBEULL,
		0xBA47E2D45859F93CULL,
		0x76E6A33234FE5736ULL,
		0xBCE2BBE8F7908D9EULL,
		0x0EDB1D1B7A90E683ULL
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
		0xB0522401D35501BEULL,
		0x140A2B38B7FE21E5ULL,
		0xF2BEF1881BD523B8ULL,
		0x7A7A074213C9C69BULL,
		0x05F279EBAF0F8130ULL,
		0x9D9CDF727389AB44ULL,
		0xC51B7420841F8AE2ULL,
		0x2DC5A6150E1F4379ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x60A44803A6AA037CULL,
		0x281456716FFC43CBULL,
		0xE57DE31037AA4770ULL,
		0xF4F40E8427938D37ULL,
		0x0BE4F3D75E1F0260ULL,
		0x3B39BEE4E7135688ULL,
		0x8A36E841083F15C5ULL,
		0x5B8B4C2A1C3E86F3ULL
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
		0xE8383442834A7A53ULL,
		0x69B9D85AD36E5902ULL,
		0xEB11BE010BAD8962ULL,
		0x06FAFEC8022EE473ULL,
		0x48CE209102FABF0CULL,
		0x44163F2AFA08456DULL,
		0x98AA453D40B83885ULL,
		0x1AD13EF4364F306FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD07068850694F4A6ULL,
		0xD373B0B5A6DCB205ULL,
		0xD6237C02175B12C4ULL,
		0x0DF5FD90045DC8E7ULL,
		0x919C412205F57E18ULL,
		0x882C7E55F4108ADAULL,
		0x31548A7A8170710AULL,
		0x35A27DE86C9E60DFULL
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
		0x790B4D1B8ED7FCEEULL,
		0x30ACE8F773CCD591ULL,
		0x67AEF3459084A9AEULL,
		0x98FBDBCF467DA1CAULL,
		0xF8A889E97862AA25ULL,
		0x1EB0F7CB621B3A5CULL,
		0xC37FB0E36F2ED2BBULL,
		0x1A8D56C46D28C8BCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF2169A371DAFF9DCULL,
		0x6159D1EEE799AB22ULL,
		0xCF5DE68B2109535CULL,
		0x31F7B79E8CFB4394ULL,
		0xF15113D2F0C5544BULL,
		0x3D61EF96C43674B9ULL,
		0x86FF61C6DE5DA576ULL,
		0x351AAD88DA519179ULL
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
		0xCFD46391AB130E4EULL,
		0x0B664BD487A10B33ULL,
		0x4F7D85622340134CULL,
		0x9147701A16215958ULL,
		0x810E3E26D82C9B9FULL,
		0xF26F8B25D19C83C4ULL,
		0x11FDA613D3D71D57ULL,
		0x20E40C4C4F21E41FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9FA8C72356261C9CULL,
		0x16CC97A90F421667ULL,
		0x9EFB0AC446802698ULL,
		0x228EE0342C42B2B0ULL,
		0x021C7C4DB059373FULL,
		0xE4DF164BA3390789ULL,
		0x23FB4C27A7AE3AAFULL,
		0x41C818989E43C83EULL
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
		0xD5296BD3881326B9ULL,
		0x19DC8264E66515E9ULL,
		0x0872E094CC57EB80ULL,
		0x2641EFC01FFFF946ULL,
		0x367391BEBFD1D831ULL,
		0xB387A7B3E2E2D588ULL,
		0x616AC3DB969C4B50ULL,
		0x23F12BECB64B759AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAA52D7A710264D72ULL,
		0x33B904C9CCCA2BD3ULL,
		0x10E5C12998AFD700ULL,
		0x4C83DF803FFFF28CULL,
		0x6CE7237D7FA3B062ULL,
		0x670F4F67C5C5AB10ULL,
		0xC2D587B72D3896A1ULL,
		0x47E257D96C96EB34ULL
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
		0x3721B844E65A5596ULL,
		0x478C5FCC0EC93889ULL,
		0xCF1BC40904E8C035ULL,
		0xE8C823282964436EULL,
		0x5CF76D5CDADD3FCCULL,
		0x0A45B6CA58EC782DULL,
		0x76C3454E47FB0987ULL,
		0x28157EA3B3C05C19ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6E437089CCB4AB2CULL,
		0x8F18BF981D927112ULL,
		0x9E37881209D1806AULL,
		0xD190465052C886DDULL,
		0xB9EEDAB9B5BA7F99ULL,
		0x148B6D94B1D8F05AULL,
		0xED868A9C8FF6130EULL,
		0x502AFD476780B832ULL
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
		0x913B59EC2B0DB7B2ULL,
		0x24EEC819EEB37C89ULL,
		0xDEED70C37AECBA1BULL,
		0x6E0CD58ADA835E0BULL,
		0xF73C1181DEC36094ULL,
		0x2D1B97DF6DA97ACBULL,
		0xF317AF1CE5D32270ULL,
		0x0D2035864F49EED6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2276B3D8561B6F64ULL,
		0x49DD9033DD66F913ULL,
		0xBDDAE186F5D97436ULL,
		0xDC19AB15B506BC17ULL,
		0xEE782303BD86C128ULL,
		0x5A372FBEDB52F597ULL,
		0xE62F5E39CBA644E0ULL,
		0x1A406B0C9E93DDADULL
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
		0xF18BB964164DA623ULL,
		0xE2C5B27304C40D5EULL,
		0xDC60E84A3B4E8F13ULL,
		0x4263BE601134B52CULL,
		0x090651C62D9B4BBCULL,
		0x70EF23C67345AC99ULL,
		0xE9CE0265F8844F5FULL,
		0x1BA8D983E29A9B47ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE31772C82C9B4C46ULL,
		0xC58B64E609881ABDULL,
		0xB8C1D094769D1E27ULL,
		0x84C77CC022696A59ULL,
		0x120CA38C5B369778ULL,
		0xE1DE478CE68B5932ULL,
		0xD39C04CBF1089EBEULL,
		0x3751B307C535368FULL
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
		0x2D26A81441AC5278ULL,
		0xFB5117CE1FE0C0AAULL,
		0x7811ED802F02C17CULL,
		0x3F0E15089ACC4C7AULL,
		0x09F5A89C1DF83D4EULL,
		0x72614593CD6175FFULL,
		0x9E82057A786B102DULL,
		0x259B256711060C8BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5A4D50288358A4F0ULL,
		0xF6A22F9C3FC18154ULL,
		0xF023DB005E0582F9ULL,
		0x7E1C2A11359898F4ULL,
		0x13EB51383BF07A9CULL,
		0xE4C28B279AC2EBFEULL,
		0x3D040AF4F0D6205AULL,
		0x4B364ACE220C1917ULL
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
		0xB51F3175177D4D89ULL,
		0xF1B18825DBE69152ULL,
		0x8E7A459674709077ULL,
		0x94239E9546B194C5ULL,
		0x3F6C5066380731AAULL,
		0x715B7FE09A5B1146ULL,
		0x026AAAE7B5860864ULL,
		0x0F072BECD57B5EBAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6A3E62EA2EFA9B12ULL,
		0xE363104BB7CD22A5ULL,
		0x1CF48B2CE8E120EFULL,
		0x28473D2A8D63298BULL,
		0x7ED8A0CC700E6355ULL,
		0xE2B6FFC134B6228CULL,
		0x04D555CF6B0C10C8ULL,
		0x1E0E57D9AAF6BD74ULL
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
		0x5FB4E2B7E1463AE9ULL,
		0xEC8855E26F4D61F4ULL,
		0xAD9E93CA690B239DULL,
		0x7E1F43AEF01FDC96ULL,
		0x1C5F012C4B45A658ULL,
		0x64BD6B1195AFC61DULL,
		0xBC8B4378A1A84A91ULL,
		0x285E5A9EBA7D843FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBF69C56FC28C75D2ULL,
		0xD910ABC4DE9AC3E8ULL,
		0x5B3D2794D216473BULL,
		0xFC3E875DE03FB92DULL,
		0x38BE0258968B4CB0ULL,
		0xC97AD6232B5F8C3AULL,
		0x791686F143509522ULL,
		0x50BCB53D74FB087FULL
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
		0x916B8EB9B6B446C9ULL,
		0x9E03542CCB12640DULL,
		0x02535F94202E9BC8ULL,
		0x48D909F126E00277ULL,
		0x3847A9A3A704599BULL,
		0xE38612E25003DB15ULL,
		0xF1796D1DC06D83DBULL,
		0x1C1C5DD561E8510AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x22D71D736D688D92ULL,
		0x3C06A8599624C81BULL,
		0x04A6BF28405D3791ULL,
		0x91B213E24DC004EEULL,
		0x708F53474E08B336ULL,
		0xC70C25C4A007B62AULL,
		0xE2F2DA3B80DB07B7ULL,
		0x3838BBAAC3D0A215ULL
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
		0x3FE54F3A5C46DF56ULL,
		0x571DAF9D7067BF60ULL,
		0x7FE7D668E7DA02D4ULL,
		0xC91C88E06EE9F3A2ULL,
		0xEAEB564D15BBF639ULL,
		0xFFE28A135C2865C4ULL,
		0x85D52BFB0D0C70CEULL,
		0x3D960938553458F9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7FCA9E74B88DBEACULL,
		0xAE3B5F3AE0CF7EC0ULL,
		0xFFCFACD1CFB405A8ULL,
		0x923911C0DDD3E744ULL,
		0xD5D6AC9A2B77EC73ULL,
		0xFFC51426B850CB89ULL,
		0x0BAA57F61A18E19DULL,
		0x7B2C1270AA68B1F3ULL
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
		0xD33DD10EC69A3401ULL,
		0x8049BFD6CCC186ACULL,
		0xBBB31E06C721EAC0ULL,
		0xC3C02FF1E9273E67ULL,
		0xA309CB4DEFC043F8ULL,
		0xEE542F01B2157711ULL,
		0xF9FA57EA36C160D4ULL,
		0x0C97F62CD8CDF845ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA67BA21D8D346802ULL,
		0x00937FAD99830D59ULL,
		0x77663C0D8E43D581ULL,
		0x87805FE3D24E7CCFULL,
		0x4613969BDF8087F1ULL,
		0xDCA85E03642AEE23ULL,
		0xF3F4AFD46D82C1A9ULL,
		0x192FEC59B19BF08BULL
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
		0x2A00F3A8DF0A158BULL,
		0xFFB1B20C988A8095ULL,
		0xF66AAF530E98217BULL,
		0xEEFE146F0511E17BULL,
		0x15A59D0A74015E76ULL,
		0xBF966A0129F08B0FULL,
		0x73B3E520BD1FDF70ULL,
		0x2315F8DCEB17CB17ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5401E751BE142B16ULL,
		0xFF6364193115012AULL,
		0xECD55EA61D3042F7ULL,
		0xDDFC28DE0A23C2F7ULL,
		0x2B4B3A14E802BCEDULL,
		0x7F2CD40253E1161EULL,
		0xE767CA417A3FBEE1ULL,
		0x462BF1B9D62F962EULL
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
		0xDB33992BB4801B45ULL,
		0xAAF1F8965B5AFC7BULL,
		0xCC2FE891AD49D10FULL,
		0xC85F133D13CAF30BULL,
		0x57CF195E36DD2517ULL,
		0xD19D528F49202D57ULL,
		0xF59FFEE8BC503E76ULL,
		0x1ABCF613B37250BDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB66732576900368AULL,
		0x55E3F12CB6B5F8F7ULL,
		0x985FD1235A93A21FULL,
		0x90BE267A2795E617ULL,
		0xAF9E32BC6DBA4A2FULL,
		0xA33AA51E92405AAEULL,
		0xEB3FFDD178A07CEDULL,
		0x3579EC2766E4A17BULL
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
		0xDD5917EA5E5AF03EULL,
		0xAA45450B889C6FECULL,
		0x7404117971F66A49ULL,
		0x39B947ADB52BD6FEULL,
		0x443961480D3F4B94ULL,
		0x9E34640816D86A6FULL,
		0x03290EA4E7DD198AULL,
		0x319A4F740553D978ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBAB22FD4BCB5E07CULL,
		0x548A8A171138DFD9ULL,
		0xE80822F2E3ECD493ULL,
		0x73728F5B6A57ADFCULL,
		0x8872C2901A7E9728ULL,
		0x3C68C8102DB0D4DEULL,
		0x06521D49CFBA3315ULL,
		0x63349EE80AA7B2F0ULL
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
		0xE3846C15A0AF50F7ULL,
		0xDC3B3ACECBC29FBFULL,
		0x210EC2E0635743AEULL,
		0x076F2D94065D7C65ULL,
		0x8E37375D4831CD09ULL,
		0xE623447175EEDE65ULL,
		0x021D89745EC7E826ULL,
		0x281033929F796F93ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC708D82B415EA1EEULL,
		0xB876759D97853F7FULL,
		0x421D85C0C6AE875DULL,
		0x0EDE5B280CBAF8CAULL,
		0x1C6E6EBA90639A12ULL,
		0xCC4688E2EBDDBCCBULL,
		0x043B12E8BD8FD04DULL,
		0x502067253EF2DF26ULL
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
		0xBE84C093253F2C7FULL,
		0x60DBAC114097CE69ULL,
		0xB4E94779D9F54279ULL,
		0x5DDFA910ED957470ULL,
		0x3E12DBEAA9519F03ULL,
		0x8EB03B47EB75603CULL,
		0xD16BD857CC040B55ULL,
		0x00FF53E80A09DDE3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7D0981264A7E58FEULL,
		0xC1B75822812F9CD3ULL,
		0x69D28EF3B3EA84F2ULL,
		0xBBBF5221DB2AE8E1ULL,
		0x7C25B7D552A33E06ULL,
		0x1D60768FD6EAC078ULL,
		0xA2D7B0AF980816ABULL,
		0x01FEA7D01413BBC7ULL
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
		0x2871B18A189AD1BEULL,
		0x6B3C52F2040FDCC0ULL,
		0xF65AD436CA74BE03ULL,
		0xA2F179661C6587DBULL,
		0x81FE0DC5E4E9DD90ULL,
		0x6D3F22BD6DAAD948ULL,
		0xC107B236A2C8732FULL,
		0x3A8ACD0C7FAC05A6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x50E363143135A37CULL,
		0xD678A5E4081FB980ULL,
		0xECB5A86D94E97C06ULL,
		0x45E2F2CC38CB0FB7ULL,
		0x03FC1B8BC9D3BB21ULL,
		0xDA7E457ADB55B291ULL,
		0x820F646D4590E65EULL,
		0x75159A18FF580B4DULL
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
		0x2479779AAD0E4921ULL,
		0x4FD797375EA9743FULL,
		0xF29C20FD025A8B8AULL,
		0x99F5A37CEC2C5FA7ULL,
		0x6AB7B5CA34E6ECC8ULL,
		0xFA8A2BCBAD15B3E5ULL,
		0xFFD68987A6AFB98FULL,
		0x2551E7E566E9C7B7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x48F2EF355A1C9242ULL,
		0x9FAF2E6EBD52E87EULL,
		0xE53841FA04B51714ULL,
		0x33EB46F9D858BF4FULL,
		0xD56F6B9469CDD991ULL,
		0xF51457975A2B67CAULL,
		0xFFAD130F4D5F731FULL,
		0x4AA3CFCACDD38F6FULL
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
		0x7732A317F20D4F9AULL,
		0x91F0D46290FC7154ULL,
		0xF7835A9E29B9D8A1ULL,
		0xF33E874BDFF2B465ULL,
		0x9CC645B9BAA4AB41ULL,
		0x87EEAC26E1577173ULL,
		0x25A6155A62ED72E0ULL,
		0x3C487B8ABF0B974CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEE65462FE41A9F34ULL,
		0x23E1A8C521F8E2A8ULL,
		0xEF06B53C5373B143ULL,
		0xE67D0E97BFE568CBULL,
		0x398C8B7375495683ULL,
		0x0FDD584DC2AEE2E7ULL,
		0x4B4C2AB4C5DAE5C1ULL,
		0x7890F7157E172E98ULL
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
		0x4A13EADC04DDE147ULL,
		0xCC81878A3E31F55BULL,
		0xCA46D55C17408693ULL,
		0x9E4B7B75D35DD0B0ULL,
		0x25C730905DA39A1BULL,
		0xF08682DF8813A526ULL,
		0x2D782B0E6A955E4CULL,
		0x38E05227571CB9AEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9427D5B809BBC28EULL,
		0x99030F147C63EAB6ULL,
		0x948DAAB82E810D27ULL,
		0x3C96F6EBA6BBA161ULL,
		0x4B8E6120BB473437ULL,
		0xE10D05BF10274A4CULL,
		0x5AF0561CD52ABC99ULL,
		0x71C0A44EAE39735CULL
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
		0x839758D84C19598AULL,
		0x54F37F6B9C25B7C9ULL,
		0xB401CAF630DD27BBULL,
		0x75D0DD71F41342CDULL,
		0x3E9AD577798AFAEBULL,
		0xC23675B14BEE36E3ULL,
		0x1AA59D4C1B34746AULL,
		0x3F018D404E8B5DD6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x072EB1B09832B314ULL,
		0xA9E6FED7384B6F93ULL,
		0x680395EC61BA4F76ULL,
		0xEBA1BAE3E826859BULL,
		0x7D35AAEEF315F5D6ULL,
		0x846CEB6297DC6DC6ULL,
		0x354B3A983668E8D5ULL,
		0x7E031A809D16BBACULL
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
		0x4857DA1C3DCD1396ULL,
		0xFB9DC0DFFF2AEE01ULL,
		0x195DC38F6CB4DC6AULL,
		0x9DE09923939B56B4ULL,
		0x242A075A55B43940ULL,
		0xA25C02AD3FA786A9ULL,
		0x46498C60778E9AABULL,
		0x25C174EF3925DBC3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x90AFB4387B9A272CULL,
		0xF73B81BFFE55DC02ULL,
		0x32BB871ED969B8D5ULL,
		0x3BC132472736AD68ULL,
		0x48540EB4AB687281ULL,
		0x44B8055A7F4F0D52ULL,
		0x8C9318C0EF1D3557ULL,
		0x4B82E9DE724BB786ULL
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
		0x3F1DAF0EED34E191ULL,
		0x7BBE86DCBA7B263EULL,
		0x0173611EE8A84CD5ULL,
		0xBC735C16C97A4A91ULL,
		0xC3E6B50C31448410ULL,
		0x4A15A8725070ADC4ULL,
		0xB6C0768B15A12ACEULL,
		0x1E0C00E9A58FD2B9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7E3B5E1DDA69C322ULL,
		0xF77D0DB974F64C7CULL,
		0x02E6C23DD15099AAULL,
		0x78E6B82D92F49522ULL,
		0x87CD6A1862890821ULL,
		0x942B50E4A0E15B89ULL,
		0x6D80ED162B42559CULL,
		0x3C1801D34B1FA573ULL
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
		0xBE7063AA72F5F005ULL,
		0xB9E3F7F5B0D75326ULL,
		0xEF594444E921304DULL,
		0xAE816EB8DCF8FEF5ULL,
		0xAE17C27B7C74AA1DULL,
		0x0CE5CFB98F8F0F2BULL,
		0x09A151D1BCE2BE2AULL,
		0x21B8A46993BF32FBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7CE0C754E5EBE00AULL,
		0x73C7EFEB61AEA64DULL,
		0xDEB28889D242609BULL,
		0x5D02DD71B9F1FDEBULL,
		0x5C2F84F6F8E9543BULL,
		0x19CB9F731F1E1E57ULL,
		0x1342A3A379C57C54ULL,
		0x437148D3277E65F6ULL
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
		0x5115E80B60263169ULL,
		0xAB597D38D1351988ULL,
		0x0CC9C64B14DA79ABULL,
		0xAFA8F6224C61B8FCULL,
		0x4E536A4573CA1C34ULL,
		0xF6941B9C826A1E69ULL,
		0xF810B2CF3088421BULL,
		0x380591321A1ED0DFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA22BD016C04C62D2ULL,
		0x56B2FA71A26A3310ULL,
		0x19938C9629B4F357ULL,
		0x5F51EC4498C371F8ULL,
		0x9CA6D48AE7943869ULL,
		0xED28373904D43CD2ULL,
		0xF021659E61108437ULL,
		0x700B2264343DA1BFULL
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
		0x87089B63FE7E11D3ULL,
		0x209F039A9D4C25DDULL,
		0x1E46384815941058ULL,
		0x4B2342DB4932F28CULL,
		0x1471CC5426C125A4ULL,
		0x02DFAC08135F9C3CULL,
		0x509508FE137E8B2CULL,
		0x1D4AE38C5D3E707FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0E1136C7FCFC23A6ULL,
		0x413E07353A984BBBULL,
		0x3C8C70902B2820B0ULL,
		0x964685B69265E518ULL,
		0x28E398A84D824B48ULL,
		0x05BF581026BF3878ULL,
		0xA12A11FC26FD1658ULL,
		0x3A95C718BA7CE0FEULL
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
		0xA7BCE54406D18FF8ULL,
		0x7E6FE38579627658ULL,
		0xC071BD1985965E99ULL,
		0x2F9F1B7F4A6833F7ULL,
		0x4DB747E0384A66F5ULL,
		0x7F36FFF2ECA5930DULL,
		0x62D861253DE40E60ULL,
		0x237505A5C7892137ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4F79CA880DA31FF0ULL,
		0xFCDFC70AF2C4ECB1ULL,
		0x80E37A330B2CBD32ULL,
		0x5F3E36FE94D067EFULL,
		0x9B6E8FC07094CDEAULL,
		0xFE6DFFE5D94B261AULL,
		0xC5B0C24A7BC81CC0ULL,
		0x46EA0B4B8F12426EULL
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
		0x225038437E29EC0BULL,
		0xC2C14CC6C92314E8ULL,
		0xF895CC3B881617C7ULL,
		0x3596DD298524DE09ULL,
		0xF3EE60F1B4C0E9BAULL,
		0x978F418F96164A6AULL,
		0x4940994B6030604BULL,
		0x353EAC3DEAD14797ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x44A07086FC53D816ULL,
		0x8582998D924629D0ULL,
		0xF12B9877102C2F8FULL,
		0x6B2DBA530A49BC13ULL,
		0xE7DCC1E36981D374ULL,
		0x2F1E831F2C2C94D5ULL,
		0x92813296C060C097ULL,
		0x6A7D587BD5A28F2EULL
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
		0xD32A4C78A325D13DULL,
		0x03E617C8939479BCULL,
		0x3766DB9DEC86F689ULL,
		0xED90C8E46BC3D0A0ULL,
		0xD36EE2193DE9EC29ULL,
		0x7E57E22EF365AF25ULL,
		0x702E4E0D4D4E217FULL,
		0x1BEAAB2040904765ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA65498F1464BA27AULL,
		0x07CC2F912728F379ULL,
		0x6ECDB73BD90DED12ULL,
		0xDB2191C8D787A140ULL,
		0xA6DDC4327BD3D853ULL,
		0xFCAFC45DE6CB5E4BULL,
		0xE05C9C1A9A9C42FEULL,
		0x37D5564081208ECAULL
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
		0x67D01F87B438F802ULL,
		0xBAFA3E634954B39AULL,
		0x0B90A9D1ACB494C5ULL,
		0xFCC1C8DD2025DB63ULL,
		0x0AA3FD80C05B39FCULL,
		0xC64C865A043F46EEULL,
		0xB322E31B794FA3DEULL,
		0x2A619D0E04372775ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCFA03F0F6871F004ULL,
		0x75F47CC692A96734ULL,
		0x172153A35969298BULL,
		0xF98391BA404BB6C6ULL,
		0x1547FB0180B673F9ULL,
		0x8C990CB4087E8DDCULL,
		0x6645C636F29F47BDULL,
		0x54C33A1C086E4EEBULL
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
		0xCE518F92F8AB53B7ULL,
		0x775D683E5C16F0FEULL,
		0xB2A0D0F0F355631AULL,
		0xDFB60882E4C294FFULL,
		0x61C8BC0AD459DA8FULL,
		0xB0E112572D6BD0A2ULL,
		0xCF93CBA1A6512511ULL,
		0x2012CA33024F5844ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9CA31F25F156A76EULL,
		0xEEBAD07CB82DE1FDULL,
		0x6541A1E1E6AAC634ULL,
		0xBF6C1105C98529FFULL,
		0xC3917815A8B3B51FULL,
		0x61C224AE5AD7A144ULL,
		0x9F2797434CA24A23ULL,
		0x40259466049EB089ULL
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
		0x2784854F8419F9C6ULL,
		0xFFA10E6346098F5FULL,
		0xA4878A63E05A4A69ULL,
		0xB473BAD6EBC7360EULL,
		0xFFE905EE9A0C0E4DULL,
		0xC8FE297AE0C2A03AULL,
		0xB0F4931D6D4BEDE8ULL,
		0x2CEAD20AF43F6669ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4F090A9F0833F38CULL,
		0xFF421CC68C131EBEULL,
		0x490F14C7C0B494D3ULL,
		0x68E775ADD78E6C1DULL,
		0xFFD20BDD34181C9BULL,
		0x91FC52F5C1854075ULL,
		0x61E9263ADA97DBD1ULL,
		0x59D5A415E87ECCD3ULL
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
		0xD7336B03B52AEDF8ULL,
		0x6B91CF5662F81B53ULL,
		0xB7C0C9886EEB123AULL,
		0x36579539607E97AFULL,
		0xB267D004B4EC4C38ULL,
		0x44EFB093560DE172ULL,
		0xFD98EF27A17731B0ULL,
		0x3031C542E50DC351ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAE66D6076A55DBF0ULL,
		0xD7239EACC5F036A7ULL,
		0x6F819310DDD62474ULL,
		0x6CAF2A72C0FD2F5FULL,
		0x64CFA00969D89870ULL,
		0x89DF6126AC1BC2E5ULL,
		0xFB31DE4F42EE6360ULL,
		0x60638A85CA1B86A3ULL
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
		0x5CF7F61AF17A4A1BULL,
		0xFDBDAF11C0160E30ULL,
		0x000587A70B533355ULL,
		0xB8DD340D5696A071ULL,
		0xA871A5B5E1EC7492ULL,
		0x0F7129CE722B933BULL,
		0xB1C4C7C998B3A56AULL,
		0x2DF2B6B106B1A27CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB9EFEC35E2F49436ULL,
		0xFB7B5E23802C1C60ULL,
		0x000B0F4E16A666ABULL,
		0x71BA681AAD2D40E2ULL,
		0x50E34B6BC3D8E925ULL,
		0x1EE2539CE4572677ULL,
		0x63898F9331674AD4ULL,
		0x5BE56D620D6344F9ULL
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
		0x1171235EB7352157ULL,
		0xB80A0101599C4D8DULL,
		0xF7DAFB9BF7CD658DULL,
		0xB83796B340CB1FCEULL,
		0xEAD7718A57F53C8FULL,
		0x5C2723CA21D5E20EULL,
		0x820D7302DB3F8B94ULL,
		0x320EC17C73952F1BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x22E246BD6E6A42AEULL,
		0x70140202B3389B1AULL,
		0xEFB5F737EF9ACB1BULL,
		0x706F2D6681963F9DULL,
		0xD5AEE314AFEA791FULL,
		0xB84E479443ABC41DULL,
		0x041AE605B67F1728ULL,
		0x641D82F8E72A5E37ULL
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
		0xB66C63123096F4A3ULL,
		0xBFB0B11D67E2CDA0ULL,
		0x6738322C731BEBBFULL,
		0x51BFEDA2D9201EF2ULL,
		0xE0279DD969342404ULL,
		0xD6C8CD88554DA0A3ULL,
		0x18DA50F6C9009124ULL,
		0x0B9D1BA88D196390ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6CD8C624612DE946ULL,
		0x7F61623ACFC59B41ULL,
		0xCE706458E637D77FULL,
		0xA37FDB45B2403DE4ULL,
		0xC04F3BB2D2684808ULL,
		0xAD919B10AA9B4147ULL,
		0x31B4A1ED92012249ULL,
		0x173A37511A32C720ULL
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
		0xF31CEBC0F3605529ULL,
		0x14CF3C09295132FCULL,
		0x3EBFDE7B72A1B332ULL,
		0x537E7ED056AB213EULL,
		0xB47832CB5A754E54ULL,
		0xF957EFEF2C9A2166ULL,
		0x270DF8AD5DBA69A8ULL,
		0x106F84B2569544D3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE639D781E6C0AA52ULL,
		0x299E781252A265F9ULL,
		0x7D7FBCF6E5436664ULL,
		0xA6FCFDA0AD56427CULL,
		0x68F06596B4EA9CA8ULL,
		0xF2AFDFDE593442CDULL,
		0x4E1BF15ABB74D351ULL,
		0x20DF0964AD2A89A6ULL
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
		0x7D868617724084C4ULL,
		0x7EBEA3DADED1C607ULL,
		0xCDD3D75217F19AE8ULL,
		0xFF1DD3D2DF61CC6EULL,
		0x3D1877F344C65F72ULL,
		0xFADD426B43516B1BULL,
		0x0B88189D641871FAULL,
		0x3A3C3942D06FE85BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFB0D0C2EE4810988ULL,
		0xFD7D47B5BDA38C0EULL,
		0x9BA7AEA42FE335D0ULL,
		0xFE3BA7A5BEC398DDULL,
		0x7A30EFE6898CBEE5ULL,
		0xF5BA84D686A2D636ULL,
		0x1710313AC830E3F5ULL,
		0x74787285A0DFD0B6ULL
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
		0x02232AAD30375711ULL,
		0xE3B8C3C0202E2A33ULL,
		0xA136E8E2EF099B5BULL,
		0xF35E3714D6B2C0FAULL,
		0xD60FEEC380D5EE6DULL,
		0xC074DD2A0A0E4BF1ULL,
		0xA62CD64A43D67173ULL,
		0x009B8A4BE5B3FADBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0446555A606EAE22ULL,
		0xC7718780405C5466ULL,
		0x426DD1C5DE1336B7ULL,
		0xE6BC6E29AD6581F5ULL,
		0xAC1FDD8701ABDCDBULL,
		0x80E9BA54141C97E3ULL,
		0x4C59AC9487ACE2E7ULL,
		0x01371497CB67F5B7ULL
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
		0x713F9EF3287462ADULL,
		0x717E8F94BEB9C3ECULL,
		0xDB72AE3ADE2C9E7DULL,
		0x019D269026F498E5ULL,
		0x9EB4D47C945A2CBDULL,
		0xDB4F33DF5EC9F1FEULL,
		0xD49203E43631D9BBULL,
		0x21B68856C1BD3473ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE27F3DE650E8C55AULL,
		0xE2FD1F297D7387D8ULL,
		0xB6E55C75BC593CFAULL,
		0x033A4D204DE931CBULL,
		0x3D69A8F928B4597AULL,
		0xB69E67BEBD93E3FDULL,
		0xA92407C86C63B377ULL,
		0x436D10AD837A68E7ULL
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
		0x3A02E38846A07336ULL,
		0x34656A5FECB9CE9EULL,
		0xAB03B1DC3A0D936CULL,
		0x92F824A9D1E4FA06ULL,
		0xD6A72E5C4AA2593CULL,
		0x0BEC95EEA6257D71ULL,
		0xF71239E48C905A29ULL,
		0x2154C593DA797588ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7405C7108D40E66CULL,
		0x68CAD4BFD9739D3CULL,
		0x560763B8741B26D8ULL,
		0x25F04953A3C9F40DULL,
		0xAD4E5CB89544B279ULL,
		0x17D92BDD4C4AFAE3ULL,
		0xEE2473C91920B452ULL,
		0x42A98B27B4F2EB11ULL
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
		0x862C154A78CE092FULL,
		0x9F3CD5093F5934E1ULL,
		0x87419B62200C92F3ULL,
		0xE0B120DAC0EB0441ULL,
		0xE505F48AE8FB9819ULL,
		0x753CBCF064C02791ULL,
		0xA051B286A8FF3283ULL,
		0x156033F7D3E99D5BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0C582A94F19C125EULL,
		0x3E79AA127EB269C3ULL,
		0x0E8336C4401925E7ULL,
		0xC16241B581D60883ULL,
		0xCA0BE915D1F73033ULL,
		0xEA7979E0C9804F23ULL,
		0x40A3650D51FE6506ULL,
		0x2AC067EFA7D33AB7ULL
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
		0x519676DD2E3756C7ULL,
		0xD743B674DDEA4FE9ULL,
		0x4EB8272B68D74872ULL,
		0x19E1FC0B67C24985ULL,
		0x75272F89312408E3ULL,
		0x388B21F35304F804ULL,
		0x7DFA330096696EF4ULL,
		0x3B5F2D2AECB63243ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA32CEDBA5C6EAD8EULL,
		0xAE876CE9BBD49FD2ULL,
		0x9D704E56D1AE90E5ULL,
		0x33C3F816CF84930AULL,
		0xEA4E5F12624811C6ULL,
		0x711643E6A609F008ULL,
		0xFBF466012CD2DDE8ULL,
		0x76BE5A55D96C6486ULL
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
		0xE3368532AE02FA85ULL,
		0xC607D46D280D9DC3ULL,
		0x9E6973ECE096057FULL,
		0xCD0ACD0EE1C21698ULL,
		0x3538C34968EAD90CULL,
		0x4A447E4421193D15ULL,
		0x05F24F2D248BEF81ULL,
		0x3C909467DCF657A7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC66D0A655C05F50AULL,
		0x8C0FA8DA501B3B87ULL,
		0x3CD2E7D9C12C0AFFULL,
		0x9A159A1DC3842D31ULL,
		0x6A718692D1D5B219ULL,
		0x9488FC8842327A2AULL,
		0x0BE49E5A4917DF02ULL,
		0x792128CFB9ECAF4EULL
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
		0xDF24F3D1799B2012ULL,
		0x2FA52E2A6A6894CFULL,
		0x8642E34FE2CFC93EULL,
		0xA4AF67FC8BA79FECULL,
		0x2A94D8B0F4580C7EULL,
		0x8524B142BA5308F7ULL,
		0xF812D11987EA7526ULL,
		0x386C21505C69A53EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBE49E7A2F3364024ULL,
		0x5F4A5C54D4D1299FULL,
		0x0C85C69FC59F927CULL,
		0x495ECFF9174F3FD9ULL,
		0x5529B161E8B018FDULL,
		0x0A49628574A611EEULL,
		0xF025A2330FD4EA4DULL,
		0x70D842A0B8D34A7DULL
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
		0x7FE389732B45A544ULL,
		0xBACC1D4F813417BFULL,
		0xB4F6DC5D51BE7E8CULL,
		0x3F247FEA33A870A6ULL,
		0x405EF3004E06D25DULL,
		0x93C9AAB7F63B761FULL,
		0x054B80E392FCA39CULL,
		0x27553F2CB3729F8AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFFC712E6568B4A88ULL,
		0x75983A9F02682F7EULL,
		0x69EDB8BAA37CFD19ULL,
		0x7E48FFD46750E14DULL,
		0x80BDE6009C0DA4BAULL,
		0x2793556FEC76EC3EULL,
		0x0A9701C725F94739ULL,
		0x4EAA7E5966E53F14ULL
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
		0x374D172FAB5ABBDBULL,
		0x0DD7DFA106C56210ULL,
		0x9763D23D20E0D6A8ULL,
		0xFFD63938C7146223ULL,
		0x595C35DCEB337169ULL,
		0xE344746FDC5C1B24ULL,
		0x39BED287426B9BE3ULL,
		0x0CA86B2F2E95D7D7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6E9A2E5F56B577B6ULL,
		0x1BAFBF420D8AC420ULL,
		0x2EC7A47A41C1AD50ULL,
		0xFFAC72718E28C447ULL,
		0xB2B86BB9D666E2D3ULL,
		0xC688E8DFB8B83648ULL,
		0x737DA50E84D737C7ULL,
		0x1950D65E5D2BAFAEULL
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
		0x0F3CC2F970E701C9ULL,
		0x1CA5684DD8F01698ULL,
		0xBF0D45D1BA442036ULL,
		0xCC852E0D34BA4173ULL,
		0xC938055075F22583ULL,
		0xA4CACC3B81C40F8AULL,
		0x2DC9FC7BB88D79EBULL,
		0x103904F5ED9C0159ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1E7985F2E1CE0392ULL,
		0x394AD09BB1E02D30ULL,
		0x7E1A8BA37488406CULL,
		0x990A5C1A697482E7ULL,
		0x92700AA0EBE44B07ULL,
		0x4995987703881F15ULL,
		0x5B93F8F7711AF3D7ULL,
		0x207209EBDB3802B2ULL
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
		0xCE363DA189D1AC24ULL,
		0xFF1A664DE1BDD3BCULL,
		0xE6D69253581C918DULL,
		0x75621C04B85080CDULL,
		0x1121D61AD1585980ULL,
		0xB94A7FA6D89159E6ULL,
		0x6B60BB7997D91F47ULL,
		0x3226F11B5A0C73FAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9C6C7B4313A35848ULL,
		0xFE34CC9BC37BA779ULL,
		0xCDAD24A6B039231BULL,
		0xEAC4380970A1019BULL,
		0x2243AC35A2B0B300ULL,
		0x7294FF4DB122B3CCULL,
		0xD6C176F32FB23E8FULL,
		0x644DE236B418E7F4ULL
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
		0x7CE8930A888BD303ULL,
		0x1FA387A31B935AB2ULL,
		0x91B87BA100DA3B03ULL,
		0x8AE9E9C713D5208DULL,
		0xE405D97119ED9D9EULL,
		0x954FF4A8E7A0EF6FULL,
		0x375C429C1BE227ABULL,
		0x17E0902A8C0E18EAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF9D126151117A606ULL,
		0x3F470F463726B564ULL,
		0x2370F74201B47606ULL,
		0x15D3D38E27AA411BULL,
		0xC80BB2E233DB3B3DULL,
		0x2A9FE951CF41DEDFULL,
		0x6EB8853837C44F57ULL,
		0x2FC12055181C31D4ULL
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
		0x1F9119A94F77A4C0ULL,
		0xA109459D6AB6C160ULL,
		0x482322363B3655A7ULL,
		0xF4F46E9C3D9980FDULL,
		0x7A2F16663C172A20ULL,
		0xE38860B9D98BD2D6ULL,
		0x864A52F22B2298FBULL,
		0x2E5F29E8B0DD24FFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3F2233529EEF4980ULL,
		0x42128B3AD56D82C0ULL,
		0x9046446C766CAB4FULL,
		0xE9E8DD387B3301FAULL,
		0xF45E2CCC782E5441ULL,
		0xC710C173B317A5ACULL,
		0x0C94A5E4564531F7ULL,
		0x5CBE53D161BA49FFULL
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
		0xE7A31488C7C09BE4ULL,
		0x185C83646B292CB0ULL,
		0x9837254BFC5F2F2CULL,
		0x7E32E98118CEB71AULL,
		0xD7A6B410E79F52D7ULL,
		0x9C31EC37A9649871ULL,
		0x25FDA189210ED0F1ULL,
		0x2CAD57E1D320956CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCF4629118F8137C8ULL,
		0x30B906C8D6525961ULL,
		0x306E4A97F8BE5E58ULL,
		0xFC65D302319D6E35ULL,
		0xAF4D6821CF3EA5AEULL,
		0x3863D86F52C930E3ULL,
		0x4BFB4312421DA1E3ULL,
		0x595AAFC3A6412AD8ULL
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
		0x85CC5E5FEA199DA7ULL,
		0x3DCEB73C382BD738ULL,
		0x5734A72F4BB0F7BCULL,
		0xDAFFF3C26A81C0E6ULL,
		0xE9E8AC80177B6CD2ULL,
		0xA12E4B6D9D754C1CULL,
		0x4C14BF61E54FA9EDULL,
		0x040BBB38B9425543ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0B98BCBFD4333B4EULL,
		0x7B9D6E787057AE71ULL,
		0xAE694E5E9761EF78ULL,
		0xB5FFE784D50381CCULL,
		0xD3D159002EF6D9A5ULL,
		0x425C96DB3AEA9839ULL,
		0x98297EC3CA9F53DBULL,
		0x081776717284AA86ULL
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
		0x4A362314E2540567ULL,
		0xCC865FA553C9CBA7ULL,
		0x776EE6A91FF53D99ULL,
		0x8D1F04739B8DC786ULL,
		0x86694184BB4ADD15ULL,
		0x87EE925B2EAD1AA9ULL,
		0xA1E98E199B639879ULL,
		0x13CA8659480350E1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x946C4629C4A80ACEULL,
		0x990CBF4AA793974EULL,
		0xEEDDCD523FEA7B33ULL,
		0x1A3E08E7371B8F0CULL,
		0x0CD283097695BA2BULL,
		0x0FDD24B65D5A3553ULL,
		0x43D31C3336C730F3ULL,
		0x27950CB29006A1C3ULL
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
		0xC4D21E474D31CBDCULL,
		0x9BDC2A226C46E82FULL,
		0xE8740D6799A39BC8ULL,
		0x1AD0343072E64845ULL,
		0x386C7554A9FBC2D5ULL,
		0x5630827BF35DFD3CULL,
		0x980BE50ACE262A73ULL,
		0x1773AD3EE3055D7AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x89A43C8E9A6397B8ULL,
		0x37B85444D88DD05FULL,
		0xD0E81ACF33473791ULL,
		0x35A06860E5CC908BULL,
		0x70D8EAA953F785AAULL,
		0xAC6104F7E6BBFA78ULL,
		0x3017CA159C4C54E6ULL,
		0x2EE75A7DC60ABAF5ULL
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
		0x0A332AF2F0EA5518ULL,
		0x2034A997A7CA17B5ULL,
		0x7C33D4DA7E1CE2DFULL,
		0xCF3073E933282261ULL,
		0x22CE555952DF0111ULL,
		0x8BA8E84362D0E03BULL,
		0x560D174432ECE8C2ULL,
		0x0AE80EF92C50F47FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x146655E5E1D4AA30ULL,
		0x4069532F4F942F6AULL,
		0xF867A9B4FC39C5BEULL,
		0x9E60E7D2665044C2ULL,
		0x459CAAB2A5BE0223ULL,
		0x1751D086C5A1C076ULL,
		0xAC1A2E8865D9D185ULL,
		0x15D01DF258A1E8FEULL
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
		0xD480680B11D9D5EFULL,
		0xDFBD6A2BFBBB16B0ULL,
		0x5D4AA1DEDD099A1EULL,
		0x79AFB5DD2E812AC4ULL,
		0x2152BC7159108CB2ULL,
		0xE5D2FCCC31AB51A4ULL,
		0x5ACCE17923B7A8DDULL,
		0x2BFF1A05CA6C24E0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA900D01623B3ABDEULL,
		0xBF7AD457F7762D61ULL,
		0xBA9543BDBA13343DULL,
		0xF35F6BBA5D025588ULL,
		0x42A578E2B2211964ULL,
		0xCBA5F9986356A348ULL,
		0xB599C2F2476F51BBULL,
		0x57FE340B94D849C0ULL
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
		0x0A8859B9683AA894ULL,
		0x37872443D26E13A9ULL,
		0xDAE771BCAD2A788AULL,
		0x7D43CDB7430BC9ECULL,
		0xF7BAFE1548A2571AULL,
		0x66458E03A372C53EULL,
		0xE24FF007213DE491ULL,
		0x26D1BE406AAC87CFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1510B372D0755128ULL,
		0x6F0E4887A4DC2752ULL,
		0xB5CEE3795A54F114ULL,
		0xFA879B6E861793D9ULL,
		0xEF75FC2A9144AE34ULL,
		0xCC8B1C0746E58A7DULL,
		0xC49FE00E427BC922ULL,
		0x4DA37C80D5590F9FULL
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
		0x782E4373CADA4182ULL,
		0xCA4B3D87B3C56660ULL,
		0x86AF640D34093EF5ULL,
		0xA5E0628C7F738DACULL,
		0xAD461D45300B0A6DULL,
		0x8B2AA9960B332EE4ULL,
		0xD4E77D2E92B327D8ULL,
		0x19F3725A5976D661ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF05C86E795B48304ULL,
		0x94967B0F678ACCC0ULL,
		0x0D5EC81A68127DEBULL,
		0x4BC0C518FEE71B59ULL,
		0x5A8C3A8A601614DBULL,
		0x1655532C16665DC9ULL,
		0xA9CEFA5D25664FB1ULL,
		0x33E6E4B4B2EDACC3ULL
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
		0xB3F4B3F0665667D6ULL,
		0x228F86B97691F528ULL,
		0x271004DBBB31E375ULL,
		0x66E3015F000572BFULL,
		0x7044A3185EBA4AAFULL,
		0x0EE5F2F62EA21415ULL,
		0x347629FF8F98810AULL,
		0x208E4C27D7D76BF9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x67E967E0CCACCFACULL,
		0x451F0D72ED23EA51ULL,
		0x4E2009B77663C6EAULL,
		0xCDC602BE000AE57EULL,
		0xE0894630BD74955EULL,
		0x1DCBE5EC5D44282AULL,
		0x68EC53FF1F310214ULL,
		0x411C984FAFAED7F2ULL
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
		0xA13FA33C5A5D862BULL,
		0x5AF6409A473BEC7DULL,
		0x59DCD87FC3E7BCE9ULL,
		0x4129F18C2DCE6903ULL,
		0x4AFA00B172672D1DULL,
		0x7E5C479635BE123FULL,
		0x9811553BA9B96ED5ULL,
		0x2E7FBF5A3AF3A43CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x427F4678B4BB0C56ULL,
		0xB5EC81348E77D8FBULL,
		0xB3B9B0FF87CF79D2ULL,
		0x8253E3185B9CD206ULL,
		0x95F40162E4CE5A3AULL,
		0xFCB88F2C6B7C247EULL,
		0x3022AA775372DDAAULL,
		0x5CFF7EB475E74879ULL
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
		0x8C85864AF43821C2ULL,
		0x45C62A3E4F80D32FULL,
		0xA8BE272C51CAE02CULL,
		0x404BBF9C17D346DCULL,
		0xC20B817A09E4A298ULL,
		0x4451D7B8455F1989ULL,
		0x74C5BBA78A8981A8ULL,
		0x09999451966F534FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x190B0C95E8704384ULL,
		0x8B8C547C9F01A65FULL,
		0x517C4E58A395C058ULL,
		0x80977F382FA68DB9ULL,
		0x841702F413C94530ULL,
		0x88A3AF708ABE3313ULL,
		0xE98B774F15130350ULL,
		0x133328A32CDEA69EULL
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
		0x63AE2CD5F3AEE079ULL,
		0x3C5225062A8EA4C9ULL,
		0xF19BE390386B0E36ULL,
		0x239940A5DF4688D6ULL,
		0x6C2D13B61412279DULL,
		0xC55285C2598D0436ULL,
		0xD6C3D47876CD2A7DULL,
		0x2FF5E32F27CE25C8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC75C59ABE75DC0F2ULL,
		0x78A44A0C551D4992ULL,
		0xE337C72070D61C6CULL,
		0x4732814BBE8D11ADULL,
		0xD85A276C28244F3AULL,
		0x8AA50B84B31A086CULL,
		0xAD87A8F0ED9A54FBULL,
		0x5FEBC65E4F9C4B91ULL
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
		0xB822599AAE06B0CEULL,
		0x5C51DD3B265E2DA8ULL,
		0x642F3CE691A036A4ULL,
		0xB7C62727647D87B0ULL,
		0x93060300832797AEULL,
		0x93A7B450072020A0ULL,
		0x3413A4AFFED85C2AULL,
		0x1CD78EE8DC601C8CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7044B3355C0D619CULL,
		0xB8A3BA764CBC5B51ULL,
		0xC85E79CD23406D48ULL,
		0x6F8C4E4EC8FB0F60ULL,
		0x260C0601064F2F5DULL,
		0x274F68A00E404141ULL,
		0x6827495FFDB0B855ULL,
		0x39AF1DD1B8C03918ULL
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
		0x44D10A1A514DDB41ULL,
		0x9D3F22C5C6FD7B21ULL,
		0x303042E8B11C79A6ULL,
		0xB751E5B42EC33FEFULL,
		0x3BF455D32E218F12ULL,
		0xDB6E08C7FA54B6ABULL,
		0x8888B90E35944A6CULL,
		0x3D185E438E361B63ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x89A21434A29BB682ULL,
		0x3A7E458B8DFAF642ULL,
		0x606085D16238F34DULL,
		0x6EA3CB685D867FDEULL,
		0x77E8ABA65C431E25ULL,
		0xB6DC118FF4A96D56ULL,
		0x1111721C6B2894D9ULL,
		0x7A30BC871C6C36C7ULL
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
		0x05F63DB52A59C22AULL,
		0x22A4E043C9BC401DULL,
		0x3B04514D083F5DE4ULL,
		0xB18911EAE3B0C49AULL,
		0x1A28BFF87C5DB757ULL,
		0x8B792D2263D3666FULL,
		0xD0851B2319BCFF9FULL,
		0x3D80972C3FE3A633ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0BEC7B6A54B38454ULL,
		0x4549C0879378803AULL,
		0x7608A29A107EBBC8ULL,
		0x631223D5C7618934ULL,
		0x34517FF0F8BB6EAFULL,
		0x16F25A44C7A6CCDEULL,
		0xA10A36463379FF3FULL,
		0x7B012E587FC74C67ULL
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
		0x179ECA5ACE27439DULL,
		0x677501D4148AD5B1ULL,
		0x721C3F5C61FB9BDDULL,
		0x809087B17DB4DE04ULL,
		0xFCEE5E03AF11B7A3ULL,
		0xF42859E581A94E21ULL,
		0x3BC066A945A17396ULL,
		0x24B48D7C5E04B3CBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2F3D94B59C4E873AULL,
		0xCEEA03A82915AB62ULL,
		0xE4387EB8C3F737BAULL,
		0x01210F62FB69BC08ULL,
		0xF9DCBC075E236F47ULL,
		0xE850B3CB03529C43ULL,
		0x7780CD528B42E72DULL,
		0x49691AF8BC096796ULL
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
		0xCD86129E6C67A7A4ULL,
		0xB79D1EC1A241A7A0ULL,
		0x2D9E251AA4A3B7DAULL,
		0x216DB7562AD9AABBULL,
		0xC822679383118057ULL,
		0x7DF329E409E29751ULL,
		0x0A729D37ABA76274ULL,
		0x3D11AA0D5793A5F0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9B0C253CD8CF4F48ULL,
		0x6F3A3D8344834F41ULL,
		0x5B3C4A3549476FB5ULL,
		0x42DB6EAC55B35576ULL,
		0x9044CF27062300AEULL,
		0xFBE653C813C52EA3ULL,
		0x14E53A6F574EC4E8ULL,
		0x7A23541AAF274BE0ULL
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
		0x32779A128E55BA0FULL,
		0xAA79D5FA236DCA13ULL,
		0x442C5300E82D2DA2ULL,
		0xAFE3BF642E3270A6ULL,
		0x5D49B81EAF087E65ULL,
		0x7CD76818A361C4B1ULL,
		0xB1C262A774BC8000ULL,
		0x3916C18AE1FA41ECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x64EF34251CAB741EULL,
		0x54F3ABF446DB9426ULL,
		0x8858A601D05A5B45ULL,
		0x5FC77EC85C64E14CULL,
		0xBA93703D5E10FCCBULL,
		0xF9AED03146C38962ULL,
		0x6384C54EE9790000ULL,
		0x722D8315C3F483D9ULL
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
		0xADDA61F06040049BULL,
		0x363B9A8BEECFAFC6ULL,
		0x75602438BDCAB869ULL,
		0xEC2E75DF6A34DD60ULL,
		0x638472FF656C49F8ULL,
		0x84DCB3937D8C2CF8ULL,
		0xF9007F6496ACB523ULL,
		0x1E78899887627ADEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5BB4C3E0C0800936ULL,
		0x6C773517DD9F5F8DULL,
		0xEAC048717B9570D2ULL,
		0xD85CEBBED469BAC0ULL,
		0xC708E5FECAD893F1ULL,
		0x09B96726FB1859F0ULL,
		0xF200FEC92D596A47ULL,
		0x3CF113310EC4F5BDULL
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
		0x2FCCFBFFD29C59B7ULL,
		0x6031CD6AAF18C2CEULL,
		0x87B7920C272BD5C0ULL,
		0xC374B866EA5CDC36ULL,
		0xC80A5FE33DB921E8ULL,
		0x327941B59BD424E8ULL,
		0x8FF85F4A850282F5ULL,
		0x115E4A3F7AB77935ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5F99F7FFA538B36EULL,
		0xC0639AD55E31859CULL,
		0x0F6F24184E57AB80ULL,
		0x86E970CDD4B9B86DULL,
		0x9014BFC67B7243D1ULL,
		0x64F2836B37A849D1ULL,
		0x1FF0BE950A0505EAULL,
		0x22BC947EF56EF26BULL
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
		0x28A691AD8139BC6AULL,
		0xC26AB38902E71042ULL,
		0x3A50D737EAC3DADEULL,
		0xDC14348413A01D55ULL,
		0x29193550DE438B9BULL,
		0x31B29CE8F7A457DAULL,
		0x351DCC656BC95420ULL,
		0x3642743F3EF26673ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x514D235B027378D4ULL,
		0x84D5671205CE2084ULL,
		0x74A1AE6FD587B5BDULL,
		0xB828690827403AAAULL,
		0x52326AA1BC871737ULL,
		0x636539D1EF48AFB4ULL,
		0x6A3B98CAD792A840ULL,
		0x6C84E87E7DE4CCE6ULL
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
		0x80308F32E3DD6930ULL,
		0x5F44692C69FD1012ULL,
		0x138CB4D1B1EA0E18ULL,
		0xDDC53AB2876BAF52ULL,
		0x0F77CF7C709DD615ULL,
		0x14B393603916D438ULL,
		0x40E84CB3363DF70EULL,
		0x2697E1CBB82AB30DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x00611E65C7BAD260ULL,
		0xBE88D258D3FA2025ULL,
		0x271969A363D41C30ULL,
		0xBB8A75650ED75EA4ULL,
		0x1EEF9EF8E13BAC2BULL,
		0x296726C0722DA870ULL,
		0x81D099666C7BEE1CULL,
		0x4D2FC3977055661AULL
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
		0x1ED292FD9A8068FFULL,
		0x54EFDAC7541AB2DDULL,
		0x02DCC78C81B0E517ULL,
		0x64851CA1614B6797ULL,
		0xEB1654CF0D231341ULL,
		0x90DBD35A5F108582ULL,
		0xDB8A1869947A7397ULL,
		0x3644325ADB5D0126ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3DA525FB3500D1FEULL,
		0xA9DFB58EA83565BAULL,
		0x05B98F190361CA2EULL,
		0xC90A3942C296CF2EULL,
		0xD62CA99E1A462682ULL,
		0x21B7A6B4BE210B05ULL,
		0xB71430D328F4E72FULL,
		0x6C8864B5B6BA024DULL
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
		0x9305D1A83C720CFAULL,
		0x2CE3C9317878887EULL,
		0x77D5D89B27D9EFF4ULL,
		0x7467BE6DED251581ULL,
		0xA67CED17E0CC859AULL,
		0xB4C61407E23BA9D5ULL,
		0x05C05E825E371EE2ULL,
		0x184FCD13C1633787ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x260BA35078E419F4ULL,
		0x59C79262F0F110FDULL,
		0xEFABB1364FB3DFE8ULL,
		0xE8CF7CDBDA4A2B02ULL,
		0x4CF9DA2FC1990B34ULL,
		0x698C280FC47753ABULL,
		0x0B80BD04BC6E3DC5ULL,
		0x309F9A2782C66F0EULL
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
		0x9CF6ECA0EE6997AFULL,
		0xB736824C4E57109FULL,
		0x80FF8AF382C0CD78ULL,
		0xA3CA60885D2DED8AULL,
		0x388B9D63D9A561C0ULL,
		0xA6D287B68A24095AULL,
		0x5548E8B7A3FC3830ULL,
		0x2BA1B4608FE818CCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x39EDD941DCD32F5EULL,
		0x6E6D04989CAE213FULL,
		0x01FF15E705819AF1ULL,
		0x4794C110BA5BDB15ULL,
		0x71173AC7B34AC381ULL,
		0x4DA50F6D144812B4ULL,
		0xAA91D16F47F87061ULL,
		0x574368C11FD03198ULL
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
		0xFDC428F5DA765479ULL,
		0x097154441D863CC6ULL,
		0xC4E6DA41712106ACULL,
		0xEC5DF9939FFBDEA6ULL,
		0x8C9570059CBF1C8AULL,
		0xE03113EB37471BB5ULL,
		0x7908F23725BE312DULL,
		0x297788DF965DB31AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFB8851EBB4ECA8F2ULL,
		0x12E2A8883B0C798DULL,
		0x89CDB482E2420D58ULL,
		0xD8BBF3273FF7BD4DULL,
		0x192AE00B397E3915ULL,
		0xC06227D66E8E376BULL,
		0xF211E46E4B7C625BULL,
		0x52EF11BF2CBB6634ULL
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
		0xB9551F7218495B88ULL,
		0x44865E624EE751AFULL,
		0x39F20568EA60249DULL,
		0x5EF4F65D0B149DCBULL,
		0xA5331A938D056E45ULL,
		0x1F2DE1EF010CC487ULL,
		0x512C99381A95DB8DULL,
		0x0216EB263C3FC62CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x72AA3EE43092B710ULL,
		0x890CBCC49DCEA35FULL,
		0x73E40AD1D4C0493AULL,
		0xBDE9ECBA16293B96ULL,
		0x4A6635271A0ADC8AULL,
		0x3E5BC3DE0219890FULL,
		0xA2593270352BB71AULL,
		0x042DD64C787F8C58ULL
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
		0x2AD912CAA086B89DULL,
		0x0C0CE56A19BEED76ULL,
		0x9334A7B61A2CBD1FULL,
		0x1FD31E00CA9CB996ULL,
		0x38010D309E7644D1ULL,
		0x59C3807856E0CB17ULL,
		0xDE873891F99A9B61ULL,
		0x29CDABD0AF3DD9ACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x55B22595410D713AULL,
		0x1819CAD4337DDAECULL,
		0x26694F6C34597A3EULL,
		0x3FA63C019539732DULL,
		0x70021A613CEC89A2ULL,
		0xB38700F0ADC1962EULL,
		0xBD0E7123F33536C2ULL,
		0x539B57A15E7BB359ULL
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
		0xEEF940C1D7AC4D0AULL,
		0x7283966275956E1AULL,
		0x12BEF96B0E47629EULL,
		0x8AC13D913B8DC3C2ULL,
		0x0419BE4550674E66ULL,
		0x8416D48303421392ULL,
		0x94256AD0A3299BA8ULL,
		0x0A725A11F444CD21ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDDF28183AF589A14ULL,
		0xE5072CC4EB2ADC35ULL,
		0x257DF2D61C8EC53CULL,
		0x15827B22771B8784ULL,
		0x08337C8AA0CE9CCDULL,
		0x082DA90606842724ULL,
		0x284AD5A146533751ULL,
		0x14E4B423E8899A43ULL
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
		0xE78FB53A82BB058CULL,
		0xC63F30E30642FD08ULL,
		0x652B6F2461FFF352ULL,
		0x497F692FC85A9BE4ULL,
		0x82FEF6C6175B4561ULL,
		0x004EE863404BAA98ULL,
		0x0557F38E570F487BULL,
		0x04FDD35BE628E8B3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCF1F6A7505760B18ULL,
		0x8C7E61C60C85FA11ULL,
		0xCA56DE48C3FFE6A5ULL,
		0x92FED25F90B537C8ULL,
		0x05FDED8C2EB68AC2ULL,
		0x009DD0C680975531ULL,
		0x0AAFE71CAE1E90F6ULL,
		0x09FBA6B7CC51D166ULL
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
		0xAB0FB6006538B902ULL,
		0x13CD20AD1BEABF6CULL,
		0x5F258D8376FB2743ULL,
		0x94D6445B42943733ULL,
		0x7DD70D137E2A4DDEULL,
		0xA07E74BBB619846AULL,
		0xAEED36EC64184722ULL,
		0x3D262A4CDFC5EEDAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x561F6C00CA717204ULL,
		0x279A415A37D57ED9ULL,
		0xBE4B1B06EDF64E86ULL,
		0x29AC88B685286E66ULL,
		0xFBAE1A26FC549BBDULL,
		0x40FCE9776C3308D4ULL,
		0x5DDA6DD8C8308E45ULL,
		0x7A4C5499BF8BDDB5ULL
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
		0x4412CFB9B6B96473ULL,
		0x61471EAF4F5BD84EULL,
		0xAFA9131F0B89F69FULL,
		0x443AFFF5E6D87DBDULL,
		0x667D59950DD307BCULL,
		0xB19582531CF6B08BULL,
		0x53FEEC5BEAA153C5ULL,
		0x0CDA71A197E2D05AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x88259F736D72C8E6ULL,
		0xC28E3D5E9EB7B09CULL,
		0x5F52263E1713ED3EULL,
		0x8875FFEBCDB0FB7BULL,
		0xCCFAB32A1BA60F78ULL,
		0x632B04A639ED6116ULL,
		0xA7FDD8B7D542A78BULL,
		0x19B4E3432FC5A0B4ULL
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
		0xB36EF26AC86C1AC0ULL,
		0x5729658E82E1DDA4ULL,
		0x85AF0ADCCBB9D98EULL,
		0x0E790178520CE464ULL,
		0xA1C5446DCB909287ULL,
		0x7D3C5082125BF7CEULL,
		0x770E2B03E5224198ULL,
		0x0B42425026F85944ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x66DDE4D590D83580ULL,
		0xAE52CB1D05C3BB49ULL,
		0x0B5E15B99773B31CULL,
		0x1CF202F0A419C8C9ULL,
		0x438A88DB9721250EULL,
		0xFA78A10424B7EF9DULL,
		0xEE1C5607CA448330ULL,
		0x168484A04DF0B288ULL
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
		0xCA1BDBB0FBA66101ULL,
		0xC02EA5E300B95CC9ULL,
		0xD84025772A900F51ULL,
		0x103218A1187416E3ULL,
		0x0A68D0FA8A7D8535ULL,
		0x45BF14B8EB3C915FULL,
		0x8C17F87AD6B4019DULL,
		0x0847A08D3A0F8292ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9437B761F74CC202ULL,
		0x805D4BC60172B993ULL,
		0xB0804AEE55201EA3ULL,
		0x2064314230E82DC7ULL,
		0x14D1A1F514FB0A6AULL,
		0x8B7E2971D67922BEULL,
		0x182FF0F5AD68033AULL,
		0x108F411A741F0525ULL
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
		0x787A555F27FE107CULL,
		0xFAD03C9165822EE3ULL,
		0xF29BA967ED11D73BULL,
		0x8276F9280FBF4793ULL,
		0x594FE07EC2016D6FULL,
		0x3F57DF6BC646EC86ULL,
		0x44075CC27E4C76F1ULL,
		0x30E6D66126874CAEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF0F4AABE4FFC20F8ULL,
		0xF5A07922CB045DC6ULL,
		0xE53752CFDA23AE77ULL,
		0x04EDF2501F7E8F27ULL,
		0xB29FC0FD8402DADFULL,
		0x7EAFBED78C8DD90CULL,
		0x880EB984FC98EDE2ULL,
		0x61CDACC24D0E995CULL
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
		0x9CB377B105F6ED44ULL,
		0x389C51735BDFCBB0ULL,
		0xEB2723CAFD77F4A3ULL,
		0xCDFC10A2E69A5584ULL,
		0x26EFCC0E5855F828ULL,
		0x7E64DB06A0003707ULL,
		0x380811A9B0BB7B4BULL,
		0x3A7CC4F59AF0C806ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3966EF620BEDDA88ULL,
		0x7138A2E6B7BF9761ULL,
		0xD64E4795FAEFE946ULL,
		0x9BF82145CD34AB09ULL,
		0x4DDF981CB0ABF051ULL,
		0xFCC9B60D40006E0EULL,
		0x701023536176F696ULL,
		0x74F989EB35E1900CULL
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
		0x163DECE89EE7A06FULL,
		0xBA4996C17FBF071AULL,
		0xCA3CD67831FD600CULL,
		0x26E45AE0AF4464CAULL,
		0xEC6983BE12383E1CULL,
		0xCBE1B3E9008D5059ULL,
		0xFE8536528A31815FULL,
		0x25020D84E52E2503ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2C7BD9D13DCF40DEULL,
		0x74932D82FF7E0E34ULL,
		0x9479ACF063FAC019ULL,
		0x4DC8B5C15E88C995ULL,
		0xD8D3077C24707C38ULL,
		0x97C367D2011AA0B3ULL,
		0xFD0A6CA5146302BFULL,
		0x4A041B09CA5C4A07ULL
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
		0x71D4456636D06927ULL,
		0xBF1789B065AEC3E8ULL,
		0xDB09FBD709355C4AULL,
		0xC52C43FBB927A1F7ULL,
		0x5CA4536210EB2D6CULL,
		0xDFE1EE387C83DD20ULL,
		0xA9092BE468075CA5ULL,
		0x104C69FB9E10901FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE3A88ACC6DA0D24EULL,
		0x7E2F1360CB5D87D0ULL,
		0xB613F7AE126AB895ULL,
		0x8A5887F7724F43EFULL,
		0xB948A6C421D65AD9ULL,
		0xBFC3DC70F907BA40ULL,
		0x521257C8D00EB94BULL,
		0x2098D3F73C21203FULL
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
		0xA534C77D8413C090ULL,
		0x34BF0166AB5B30B3ULL,
		0x1E4A52DCB72A73C8ULL,
		0x89CDE12002E31BE0ULL,
		0x01F2F0AEDEDCD504ULL,
		0x305FEB2E4C404387ULL,
		0x63E75207A3A10F50ULL,
		0x37CEDDC21163B3E4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4A698EFB08278120ULL,
		0x697E02CD56B66167ULL,
		0x3C94A5B96E54E790ULL,
		0x139BC24005C637C0ULL,
		0x03E5E15DBDB9AA09ULL,
		0x60BFD65C9880870EULL,
		0xC7CEA40F47421EA0ULL,
		0x6F9DBB8422C767C8ULL
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
		0xFB3882457F84F9FDULL,
		0x3485CB1859D4D22CULL,
		0xEF5930A5D81EF1A0ULL,
		0x82E7168C9356FDC2ULL,
		0x29F6777893B1D328ULL,
		0x4CF66841D6237E51ULL,
		0x9E59DD69A2AB4738ULL,
		0x308759974573CB2FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF671048AFF09F3FAULL,
		0x690B9630B3A9A459ULL,
		0xDEB2614BB03DE340ULL,
		0x05CE2D1926ADFB85ULL,
		0x53ECEEF12763A651ULL,
		0x99ECD083AC46FCA2ULL,
		0x3CB3BAD345568E70ULL,
		0x610EB32E8AE7965FULL
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
		0x8129C39710FD9EDCULL,
		0x4FAD68D9505DA6B0ULL,
		0xDA4B5D6EBD08AADDULL,
		0x0B46E9524354C068ULL,
		0xDF3BB869845A5DFFULL,
		0xBB77860677B2841FULL,
		0x0EFC4B7B3B85A745ULL,
		0x2CD591B396B88FFEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0253872E21FB3DB8ULL,
		0x9F5AD1B2A0BB4D61ULL,
		0xB496BADD7A1155BAULL,
		0x168DD2A486A980D1ULL,
		0xBE7770D308B4BBFEULL,
		0x76EF0C0CEF65083FULL,
		0x1DF896F6770B4E8BULL,
		0x59AB23672D711FFCULL
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
		0x446397980C9BD2D9ULL,
		0xBF7F3B51A2BB9161ULL,
		0xDBCE815131983523ULL,
		0x4DCF558DE50E01B0ULL,
		0x7C8A5C1267CAFA4FULL,
		0x5A45A2CD77B435C9ULL,
		0xB8594989B885C6E0ULL,
		0x278112B3502A5BDCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x88C72F301937A5B2ULL,
		0x7EFE76A3457722C2ULL,
		0xB79D02A263306A47ULL,
		0x9B9EAB1BCA1C0361ULL,
		0xF914B824CF95F49EULL,
		0xB48B459AEF686B92ULL,
		0x70B29313710B8DC0ULL,
		0x4F022566A054B7B9ULL
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
		0x0974116833AFBDEBULL,
		0xE2EFF68A62FF8D1AULL,
		0x524370919218CD8DULL,
		0xC660AC0275D2AFF4ULL,
		0x04ECA166515470BFULL,
		0x488238225B941FFFULL,
		0x5AB4FBF2FBAC202CULL,
		0x1CA3B4F44069D458ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x12E822D0675F7BD6ULL,
		0xC5DFED14C5FF1A34ULL,
		0xA486E12324319B1BULL,
		0x8CC15804EBA55FE8ULL,
		0x09D942CCA2A8E17FULL,
		0x91047044B7283FFEULL,
		0xB569F7E5F7584058ULL,
		0x394769E880D3A8B0ULL
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
		0x48ED19A1AF6C38F4ULL,
		0x701CC6C0B910AD77ULL,
		0xFD2B090EB2513026ULL,
		0x6F6113A60D39DE39ULL,
		0xA369FCAF7539E81CULL,
		0x4C091DC9762EDEA6ULL,
		0x4C9E7B91F6917B7EULL,
		0x34980439841865F9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x91DA33435ED871E8ULL,
		0xE0398D8172215AEEULL,
		0xFA56121D64A2604CULL,
		0xDEC2274C1A73BC73ULL,
		0x46D3F95EEA73D038ULL,
		0x98123B92EC5DBD4DULL,
		0x993CF723ED22F6FCULL,
		0x693008730830CBF2ULL
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
		0xA5ADACB49F5D9359ULL,
		0xD504C3EA9002B270ULL,
		0x6AA36A8C0C33E589ULL,
		0x85246B4F55CD8976ULL,
		0xF6AAC55B9335CDD5ULL,
		0x625D96DB97B34A5EULL,
		0xCB73ACCD20F9113DULL,
		0x1C51BABCF16FCC83ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4B5B59693EBB26B2ULL,
		0xAA0987D5200564E1ULL,
		0xD546D5181867CB13ULL,
		0x0A48D69EAB9B12ECULL,
		0xED558AB7266B9BABULL,
		0xC4BB2DB72F6694BDULL,
		0x96E7599A41F2227AULL,
		0x38A37579E2DF9907ULL
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
		0xF7A96E911DE75363ULL,
		0xB213E9F0D1A15C2FULL,
		0x22B2B36A0CE81F45ULL,
		0x5B0C8CA7F9A81D6EULL,
		0xBA34B1BEFFA83A22ULL,
		0x580AD12552445523ULL,
		0x7D1C6A0A3D425B59ULL,
		0x2771BBF3BE6F4F8DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEF52DD223BCEA6C6ULL,
		0x6427D3E1A342B85FULL,
		0x456566D419D03E8BULL,
		0xB619194FF3503ADCULL,
		0x7469637DFF507444ULL,
		0xB015A24AA488AA47ULL,
		0xFA38D4147A84B6B2ULL,
		0x4EE377E77CDE9F1AULL
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
		0x183E52A5A8E07569ULL,
		0x6605F5619D44DA8EULL,
		0x1D6BFA376F47DB7AULL,
		0xE0FABCE00669FC6DULL,
		0x2788B258F01EDCF3ULL,
		0x6E4C674A1DDCC076ULL,
		0xC0CA7B3D73EE2465ULL,
		0x2A95223BD896B525ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x307CA54B51C0EAD2ULL,
		0xCC0BEAC33A89B51CULL,
		0x3AD7F46EDE8FB6F4ULL,
		0xC1F579C00CD3F8DAULL,
		0x4F1164B1E03DB9E7ULL,
		0xDC98CE943BB980ECULL,
		0x8194F67AE7DC48CAULL,
		0x552A4477B12D6A4BULL
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
		0x55BB90D22350C59BULL,
		0x3CBF2F120737150BULL,
		0x344910633FCC858AULL,
		0xF44F76267EBC1FF4ULL,
		0x8715A6ECE5CFC099ULL,
		0x663F031A31219982ULL,
		0xC74C344513A3FC79ULL,
		0x2FE3FFA3782062DEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAB7721A446A18B36ULL,
		0x797E5E240E6E2A16ULL,
		0x689220C67F990B14ULL,
		0xE89EEC4CFD783FE8ULL,
		0x0E2B4DD9CB9F8133ULL,
		0xCC7E063462433305ULL,
		0x8E98688A2747F8F2ULL,
		0x5FC7FF46F040C5BDULL
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
		0x4ADBF9F776767F9BULL,
		0x90A3FFA349A49AC9ULL,
		0x0E66CC6BD7A619ACULL,
		0x7F9B0A5B869A77A9ULL,
		0x8171EAC10637BC8BULL,
		0x15A1F61A87C5214DULL,
		0x683AE7101095F31EULL,
		0x061AD407404DCCE6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x95B7F3EEECECFF36ULL,
		0x2147FF4693493592ULL,
		0x1CCD98D7AF4C3359ULL,
		0xFF3614B70D34EF52ULL,
		0x02E3D5820C6F7916ULL,
		0x2B43EC350F8A429BULL,
		0xD075CE20212BE63CULL,
		0x0C35A80E809B99CCULL
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
		0x081636AD5AAA2455ULL,
		0x547143C32C34DB40ULL,
		0xC931D3D6EE360D51ULL,
		0x041257830CF53F67ULL,
		0x375D0553012968FCULL,
		0xF67942A6BCDDC6BCULL,
		0xB89ABF4B17D0368AULL,
		0x03E88791B0E8D18BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x102C6D5AB55448AAULL,
		0xA8E287865869B680ULL,
		0x9263A7ADDC6C1AA2ULL,
		0x0824AF0619EA7ECFULL,
		0x6EBA0AA60252D1F8ULL,
		0xECF2854D79BB8D78ULL,
		0x71357E962FA06D15ULL,
		0x07D10F2361D1A317ULL
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
		0xB0C2587645121970ULL,
		0x2DCCD0FA6C142325ULL,
		0x9078D7E1873F5AD3ULL,
		0xA058516934CF2181ULL,
		0xB6000BB8D59A8DC6ULL,
		0xCD2FE3BE8C900FB6ULL,
		0x362BB264F68005E0ULL,
		0x1CB260C15E3DC273ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6184B0EC8A2432E0ULL,
		0x5B99A1F4D828464BULL,
		0x20F1AFC30E7EB5A6ULL,
		0x40B0A2D2699E4303ULL,
		0x6C001771AB351B8DULL,
		0x9A5FC77D19201F6DULL,
		0x6C5764C9ED000BC1ULL,
		0x3964C182BC7B84E6ULL
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
		0xACD408A230E78FCAULL,
		0x1FAE8E5786DC2B39ULL,
		0x50D30820B362BE7DULL,
		0xD7C01CCD909467F2ULL,
		0x19B7C1676322967DULL,
		0x12A27930DE738130ULL,
		0x0313674702F80DA9ULL,
		0x2937F32695DB924CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x59A8114461CF1F94ULL,
		0x3F5D1CAF0DB85673ULL,
		0xA1A6104166C57CFAULL,
		0xAF80399B2128CFE4ULL,
		0x336F82CEC6452CFBULL,
		0x2544F261BCE70260ULL,
		0x0626CE8E05F01B52ULL,
		0x526FE64D2BB72498ULL
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
		0x5696F7B83F22CA79ULL,
		0x33AD9FCFC3C9B05FULL,
		0xE9EF8FF1B20FDCC1ULL,
		0x4DF97EF8A025D870ULL,
		0x6EA6496E66E328E1ULL,
		0xCE89479CBBFDF7A2ULL,
		0x9EA052C8590A374FULL,
		0x16854B4A086A6269ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAD2DEF707E4594F2ULL,
		0x675B3F9F879360BEULL,
		0xD3DF1FE3641FB982ULL,
		0x9BF2FDF1404BB0E1ULL,
		0xDD4C92DCCDC651C2ULL,
		0x9D128F3977FBEF44ULL,
		0x3D40A590B2146E9FULL,
		0x2D0A969410D4C4D3ULL
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
		0x24E99B3F9C3196DFULL,
		0xEEF6FFDD0D2B0F7AULL,
		0x41E462D20599F32BULL,
		0xF41A3E81947B1DE3ULL,
		0x7A417C0AFDBCE16CULL,
		0xFB61C9E493F33D7EULL,
		0xE918F5BA57696A97ULL,
		0x170971640F2304ADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x49D3367F38632DBEULL,
		0xDDEDFFBA1A561EF4ULL,
		0x83C8C5A40B33E657ULL,
		0xE8347D0328F63BC6ULL,
		0xF482F815FB79C2D9ULL,
		0xF6C393C927E67AFCULL,
		0xD231EB74AED2D52FULL,
		0x2E12E2C81E46095BULL
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
		0xC9EA84804C96160DULL,
		0x3A57C82E982A09DCULL,
		0xEE3044960C43A5E0ULL,
		0x23FB7A9235E860C2ULL,
		0x91CA732AB437EF24ULL,
		0x9D700203342BCD3EULL,
		0x1CD0DC62BA4A7410ULL,
		0x208E568DF20018B0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x93D50900992C2C1AULL,
		0x74AF905D305413B9ULL,
		0xDC60892C18874BC0ULL,
		0x47F6F5246BD0C185ULL,
		0x2394E655686FDE48ULL,
		0x3AE0040668579A7DULL,
		0x39A1B8C57494E821ULL,
		0x411CAD1BE4003160ULL
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
		0xF6B61C6558DA13CDULL,
		0x0514234387D19BFFULL,
		0xECEE73B2D53399B2ULL,
		0xEE54D65928657518ULL,
		0xD44F2F349A23FF27ULL,
		0x4B3185363A8AF710ULL,
		0x94D0D01A9979627BULL,
		0x3919AB37D19FA368ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xED6C38CAB1B4279AULL,
		0x0A2846870FA337FFULL,
		0xD9DCE765AA673364ULL,
		0xDCA9ACB250CAEA31ULL,
		0xA89E5E693447FE4FULL,
		0x96630A6C7515EE21ULL,
		0x29A1A03532F2C4F6ULL,
		0x7233566FA33F46D1ULL
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
		0x9F94B9571D347F1CULL,
		0xF5914FF0280BC1FFULL,
		0xF3A3091187B5E654ULL,
		0x63ED92E3B0830D5FULL,
		0xD8D79F884AC4F016ULL,
		0x487151A1508A5B6EULL,
		0x6E109F9EC7FAA308ULL,
		0x037984CE38A703BCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3F2972AE3A68FE38ULL,
		0xEB229FE0501783FFULL,
		0xE74612230F6BCCA9ULL,
		0xC7DB25C761061ABFULL,
		0xB1AF3F109589E02CULL,
		0x90E2A342A114B6DDULL,
		0xDC213F3D8FF54610ULL,
		0x06F3099C714E0778ULL
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
		0x6EB32894A525159CULL,
		0x827D1CFDF7B58D15ULL,
		0x6613A001435F5FFDULL,
		0x6D08F228CEACFB06ULL,
		0x4D9B931C6921C9CAULL,
		0x50E85C65EE1653A9ULL,
		0x964C8ABD69F8A799ULL,
		0x0757B99352F9F770ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDD6651294A4A2B38ULL,
		0x04FA39FBEF6B1A2AULL,
		0xCC27400286BEBFFBULL,
		0xDA11E4519D59F60CULL,
		0x9B372638D2439394ULL,
		0xA1D0B8CBDC2CA752ULL,
		0x2C99157AD3F14F32ULL,
		0x0EAF7326A5F3EEE1ULL
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
		0xD73990FCE9DEFE8EULL,
		0xA6A5A6EB9E09B0CCULL,
		0x02AB388393FE2090ULL,
		0x4994422371F8A248ULL,
		0x4A32AAC7958BEEBFULL,
		0xED39CECC02C551ABULL,
		0xFED35283D2EE0A59ULL,
		0x26744B4B95448A84ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAE7321F9D3BDFD1CULL,
		0x4D4B4DD73C136199ULL,
		0x0556710727FC4121ULL,
		0x93288446E3F14490ULL,
		0x9465558F2B17DD7EULL,
		0xDA739D98058AA356ULL,
		0xFDA6A507A5DC14B3ULL,
		0x4CE896972A891509ULL
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
		0x0467B035E9BB88BDULL,
		0x55E07D9C648FCACAULL,
		0x10C1F8A05FD3609EULL,
		0x03AC3718AD39AFBAULL,
		0x5A3C2C52E7EE8D7FULL,
		0x2DBD4807EFD31D9BULL,
		0xFDC61BE491C21352ULL,
		0x33D092ECC11CFC77ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x08CF606BD377117AULL,
		0xABC0FB38C91F9594ULL,
		0x2183F140BFA6C13CULL,
		0x07586E315A735F74ULL,
		0xB47858A5CFDD1AFEULL,
		0x5B7A900FDFA63B36ULL,
		0xFB8C37C9238426A4ULL,
		0x67A125D98239F8EFULL
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
		0xED1D326EABF490E6ULL,
		0x9E42A4392153E2D4ULL,
		0xE2F4F76F989C2614ULL,
		0xBBE0D283E08502E0ULL,
		0x414DBDDAC84A216FULL,
		0xDD8DFFDE210256B8ULL,
		0xA432C14E97CEB04DULL,
		0x293A40D2B37819D2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDA3A64DD57E921CCULL,
		0x3C85487242A7C5A9ULL,
		0xC5E9EEDF31384C29ULL,
		0x77C1A507C10A05C1ULL,
		0x829B7BB5909442DFULL,
		0xBB1BFFBC4204AD70ULL,
		0x4865829D2F9D609BULL,
		0x527481A566F033A5ULL
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
		0x875FA5FA34137CEFULL,
		0x607B1E658133CD83ULL,
		0x8629DBEE76B9974FULL,
		0x445AE662415A07E2ULL,
		0x5F5D4F2F2287F71CULL,
		0x40D51792A50C1589ULL,
		0x8734A6F68AA5674CULL,
		0x09D8E24E76DC1175ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0EBF4BF46826F9DEULL,
		0xC0F63CCB02679B07ULL,
		0x0C53B7DCED732E9EULL,
		0x88B5CCC482B40FC5ULL,
		0xBEBA9E5E450FEE38ULL,
		0x81AA2F254A182B12ULL,
		0x0E694DED154ACE98ULL,
		0x13B1C49CEDB822EBULL
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
		0x64ABE38504715337ULL,
		0x91756093285E1A3DULL,
		0xEA04154521D78D4AULL,
		0x4CC229E121AA8A12ULL,
		0x62E427924F589E60ULL,
		0x86FF61CE1B37426BULL,
		0xB2062F5B86686D37ULL,
		0x1182722A6BEC5F48ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC957C70A08E2A66EULL,
		0x22EAC12650BC347AULL,
		0xD4082A8A43AF1A95ULL,
		0x998453C243551425ULL,
		0xC5C84F249EB13CC0ULL,
		0x0DFEC39C366E84D6ULL,
		0x640C5EB70CD0DA6FULL,
		0x2304E454D7D8BE91ULL
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
		0xED39F3F711DED9E7ULL,
		0x915FC50501E594B4ULL,
		0xFC2FD72FF56538DEULL,
		0x62DCCDFF0B426CB2ULL,
		0x0116A87FC75BBCE5ULL,
		0xA6218DD08A9923A0ULL,
		0x866698096EEA348CULL,
		0x3A528057071FDEA6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDA73E7EE23BDB3CEULL,
		0x22BF8A0A03CB2969ULL,
		0xF85FAE5FEACA71BDULL,
		0xC5B99BFE1684D965ULL,
		0x022D50FF8EB779CAULL,
		0x4C431BA115324740ULL,
		0x0CCD3012DDD46919ULL,
		0x74A500AE0E3FBD4DULL
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
		0x7C5763FEA549D2FDULL,
		0xE4B9856830916BCDULL,
		0x455F81DB3307513BULL,
		0x0D547992C8E329F3ULL,
		0xCC7A58D7A3223AA7ULL,
		0xB9184F0EDDB45768ULL,
		0xB9281D979DAB4A28ULL,
		0x3C9746F4B2C50C49ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF8AEC7FD4A93A5FAULL,
		0xC9730AD06122D79AULL,
		0x8ABF03B6660EA277ULL,
		0x1AA8F32591C653E6ULL,
		0x98F4B1AF4644754EULL,
		0x72309E1DBB68AED1ULL,
		0x72503B2F3B569451ULL,
		0x792E8DE9658A1893ULL
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
		0x440CB53D93D06A49ULL,
		0x6C5B63EE6848D2C7ULL,
		0xDAAAE76AC7A252F5ULL,
		0x3B64AEB7C3D4B1B9ULL,
		0x6584DC9D33A7DCD2ULL,
		0xE1C5C519056FD274ULL,
		0x708626DCDF57CAA6ULL,
		0x3FAC60ABDC049C9FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x88196A7B27A0D492ULL,
		0xD8B6C7DCD091A58EULL,
		0xB555CED58F44A5EAULL,
		0x76C95D6F87A96373ULL,
		0xCB09B93A674FB9A4ULL,
		0xC38B8A320ADFA4E8ULL,
		0xE10C4DB9BEAF954DULL,
		0x7F58C157B809393EULL
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
		0x24A2AFDE0E70F521ULL,
		0x4C23EE7388665989ULL,
		0x04B9A85B09E70850ULL,
		0xE33A7D632D64BCCEULL,
		0x1F06912F91EB5C68ULL,
		0x0E40D4C3CC2F40C0ULL,
		0x859CEC825BF45AEBULL,
		0x139E70FAC9DB04CFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x49455FBC1CE1EA42ULL,
		0x9847DCE710CCB312ULL,
		0x097350B613CE10A0ULL,
		0xC674FAC65AC9799CULL,
		0x3E0D225F23D6B8D1ULL,
		0x1C81A987985E8180ULL,
		0x0B39D904B7E8B5D6ULL,
		0x273CE1F593B6099FULL
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
		0x3A7A7FDB33046C97ULL,
		0x33DB6C623E8EC1EDULL,
		0x64CF9BD349358FAAULL,
		0xD8F281C7641BEFFFULL,
		0x5585A1F4A292F56EULL,
		0x4E484CA0E34FF55EULL,
		0x187ABECD61FA5C01ULL,
		0x2FBD22B865C07297ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x74F4FFB66608D92EULL,
		0x67B6D8C47D1D83DAULL,
		0xC99F37A6926B1F54ULL,
		0xB1E5038EC837DFFEULL,
		0xAB0B43E94525EADDULL,
		0x9C909941C69FEABCULL,
		0x30F57D9AC3F4B802ULL,
		0x5F7A4570CB80E52EULL
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
		0x6E1393E4B9C6E6E8ULL,
		0xEB5D7660D7B33EC2ULL,
		0xA146FAB76CA60F64ULL,
		0x2F8CD5C1FA76199EULL,
		0x63805DD467E3319EULL,
		0x3A160E70E562230CULL,
		0x48840380F92251F4ULL,
		0x13FDC21658FA2661ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDC2727C9738DCDD0ULL,
		0xD6BAECC1AF667D84ULL,
		0x428DF56ED94C1EC9ULL,
		0x5F19AB83F4EC333DULL,
		0xC700BBA8CFC6633CULL,
		0x742C1CE1CAC44618ULL,
		0x91080701F244A3E8ULL,
		0x27FB842CB1F44CC2ULL
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
		0xAEB5E39F2F02DB7EULL,
		0xE300BD05E505111DULL,
		0xA77930D7E8D91312ULL,
		0x30B39CF8D339AAB6ULL,
		0x0772D32B31530127ULL,
		0x05A32B9CD65F0A40ULL,
		0x4E9DBB09C3F104F9ULL,
		0x042359383710D5B5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5D6BC73E5E05B6FCULL,
		0xC6017A0BCA0A223BULL,
		0x4EF261AFD1B22625ULL,
		0x616739F1A673556DULL,
		0x0EE5A65662A6024EULL,
		0x0B465739ACBE1480ULL,
		0x9D3B761387E209F2ULL,
		0x0846B2706E21AB6AULL
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
		0x3C2BCC808ED961CFULL,
		0x734A76B41C382C34ULL,
		0x1C2FCE3367F0D33DULL,
		0xCCE446E46BCDD693ULL,
		0x5125036DBC5A6F23ULL,
		0x499F3D3689DFA7BDULL,
		0xA7B374F1D1341DEBULL,
		0x39AAAAFC5DFAA4EDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x785799011DB2C39EULL,
		0xE694ED6838705868ULL,
		0x385F9C66CFE1A67AULL,
		0x99C88DC8D79BAD26ULL,
		0xA24A06DB78B4DE47ULL,
		0x933E7A6D13BF4F7AULL,
		0x4F66E9E3A2683BD6ULL,
		0x735555F8BBF549DBULL
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
		0xD5E08363A739CECCULL,
		0xCF5C77FB366BB4FAULL,
		0xDDE2E633EC1C056DULL,
		0x5A70E40E8930A6DDULL,
		0x5EA2A7E03DEE05F0ULL,
		0x9A1EFD6DC6327B09ULL,
		0x240675D05933681FULL,
		0x2F60715C0024C9D7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xABC106C74E739D98ULL,
		0x9EB8EFF66CD769F5ULL,
		0xBBC5CC67D8380ADBULL,
		0xB4E1C81D12614DBBULL,
		0xBD454FC07BDC0BE0ULL,
		0x343DFADB8C64F612ULL,
		0x480CEBA0B266D03FULL,
		0x5EC0E2B8004993AEULL
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
		0xE341B9E4B229EFF6ULL,
		0x44BB8A6DFD4E39F5ULL,
		0x5C46B5A00748D493ULL,
		0xFE90809E80807D3DULL,
		0xBC78A0E03738919EULL,
		0xB5D5F0B0D6A6B2C4ULL,
		0x9B7C958D73DE34C3ULL,
		0x297ED6E7774891A9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC68373C96453DFECULL,
		0x897714DBFA9C73EBULL,
		0xB88D6B400E91A926ULL,
		0xFD21013D0100FA7AULL,
		0x78F141C06E71233DULL,
		0x6BABE161AD4D6589ULL,
		0x36F92B1AE7BC6987ULL,
		0x52FDADCEEE912353ULL
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
		0x9965D28D97FBC860ULL,
		0xCF544AF9F2A81FA0ULL,
		0x79CD72A4C1A21BE4ULL,
		0x2C375E19E64470EFULL,
		0x106A5EECB2CF0275ULL,
		0x7C92C7918ECAD19EULL,
		0x76CE2DD2EE5A2223ULL,
		0x1800280D3DB28075ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x32CBA51B2FF790C0ULL,
		0x9EA895F3E5503F41ULL,
		0xF39AE549834437C9ULL,
		0x586EBC33CC88E1DEULL,
		0x20D4BDD9659E04EAULL,
		0xF9258F231D95A33CULL,
		0xED9C5BA5DCB44446ULL,
		0x3000501A7B6500EAULL
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
		0x7A8798BBB22AA511ULL,
		0x161FF2AA178CD263ULL,
		0x71531D0CBA5CCBFFULL,
		0x03060FE5E6062BCFULL,
		0x93D670773881BB21ULL,
		0x900130C6A81064B9ULL,
		0x8AABF2C655BC2ABAULL,
		0x3DD8078307DE15DEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF50F317764554A22ULL,
		0x2C3FE5542F19A4C6ULL,
		0xE2A63A1974B997FEULL,
		0x060C1FCBCC0C579EULL,
		0x27ACE0EE71037642ULL,
		0x2002618D5020C973ULL,
		0x1557E58CAB785575ULL,
		0x7BB00F060FBC2BBDULL
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
		0xAE975ADA9F4F42E2ULL,
		0x14342B56942432D8ULL,
		0x4F486819251CE2D1ULL,
		0xA4DB9A1E9B0D7D54ULL,
		0x5D48B45BC191EA1BULL,
		0x95D35FE0D39E675BULL,
		0x6486EE8626E65C31ULL,
		0x1D49AEDB2CDD4118ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5D2EB5B53E9E85C4ULL,
		0x286856AD284865B1ULL,
		0x9E90D0324A39C5A2ULL,
		0x49B7343D361AFAA8ULL,
		0xBA9168B78323D437ULL,
		0x2BA6BFC1A73CCEB6ULL,
		0xC90DDD0C4DCCB863ULL,
		0x3A935DB659BA8230ULL
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
		0x7A4EAA996507037AULL,
		0x52A8C842C7CA8A23ULL,
		0xC11A8A33B8085767ULL,
		0x186D420F445095CBULL,
		0xCB5351ACE689D1CAULL,
		0x0665D33426A77AD1ULL,
		0x2D7350F77C861C10ULL,
		0x151CC64C5E67C478ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF49D5532CA0E06F4ULL,
		0xA55190858F951446ULL,
		0x823514677010AECEULL,
		0x30DA841E88A12B97ULL,
		0x96A6A359CD13A394ULL,
		0x0CCBA6684D4EF5A3ULL,
		0x5AE6A1EEF90C3820ULL,
		0x2A398C98BCCF88F0ULL
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
		0x1B4D225BC63D9C04ULL,
		0x650E3E1B17C46ABDULL,
		0x7C1A5267355A6B81ULL,
		0xBBC083A7B8D55A0EULL,
		0x478887426C1ABFCBULL,
		0x1128A3EC545F5F83ULL,
		0x2DB5BCB5179DE06BULL,
		0x22C55EFF030D15B9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x369A44B78C7B3808ULL,
		0xCA1C7C362F88D57AULL,
		0xF834A4CE6AB4D702ULL,
		0x7781074F71AAB41CULL,
		0x8F110E84D8357F97ULL,
		0x225147D8A8BEBF06ULL,
		0x5B6B796A2F3BC0D6ULL,
		0x458ABDFE061A2B72ULL
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
		0xA5D9A07B192F3417ULL,
		0x2C97DA999DB30675ULL,
		0x674AA2394A3A4255ULL,
		0x66411BC1BE5F258BULL,
		0x33DB33D845B80B69ULL,
		0x1F91C6C208B81857ULL,
		0xCE7C572A9709AEB4ULL,
		0x27E7E7C5D66AEB7FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4BB340F6325E682EULL,
		0x592FB5333B660CEBULL,
		0xCE954472947484AAULL,
		0xCC8237837CBE4B16ULL,
		0x67B667B08B7016D2ULL,
		0x3F238D84117030AEULL,
		0x9CF8AE552E135D68ULL,
		0x4FCFCF8BACD5D6FFULL
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
		0xEB351FEF5CA98059ULL,
		0xFC1176B6974226C4ULL,
		0xE56841D82111B1CDULL,
		0x973D60E6552A58B3ULL,
		0x395C4A6B7E639502ULL,
		0x547678F465117987ULL,
		0x35824A2EC64E3444ULL,
		0x2C31D91FF3F0F098ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD66A3FDEB95300B2ULL,
		0xF822ED6D2E844D89ULL,
		0xCAD083B04223639BULL,
		0x2E7AC1CCAA54B167ULL,
		0x72B894D6FCC72A05ULL,
		0xA8ECF1E8CA22F30EULL,
		0x6B04945D8C9C6888ULL,
		0x5863B23FE7E1E130ULL
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
		0x870DD2335227CD34ULL,
		0xF3AFA7B4A5F73FBAULL,
		0xD4909B44A69DBC00ULL,
		0x3F00EC3EF4215E8CULL,
		0xE62246448C68E7F7ULL,
		0x332445B2E0A267E2ULL,
		0x49D533D584C09498ULL,
		0x0BE0F7DDF401AD34ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0E1BA466A44F9A68ULL,
		0xE75F4F694BEE7F75ULL,
		0xA92136894D3B7801ULL,
		0x7E01D87DE842BD19ULL,
		0xCC448C8918D1CFEEULL,
		0x66488B65C144CFC5ULL,
		0x93AA67AB09812930ULL,
		0x17C1EFBBE8035A68ULL
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
		0x21B2680E7633B4B3ULL,
		0x846A55090337CEA8ULL,
		0x8AF795B39FDBC4F3ULL,
		0xB7F7BAEF8E2ABC1AULL,
		0x540076BDB684CA2FULL,
		0xF9B0284CCFE644CAULL,
		0xB79CC782CFB88414ULL,
		0x10074D0B8DE16733ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4364D01CEC676966ULL,
		0x08D4AA12066F9D50ULL,
		0x15EF2B673FB789E7ULL,
		0x6FEF75DF1C557835ULL,
		0xA800ED7B6D09945FULL,
		0xF36050999FCC8994ULL,
		0x6F398F059F710829ULL,
		0x200E9A171BC2CE67ULL
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
		0xA7A3BA1FA3EDA42CULL,
		0x190FB94AB43621BBULL,
		0xA840B245900F2641ULL,
		0xE04E8277C0AAE522ULL,
		0x8F5FD94B7CD71AA9ULL,
		0xED50519669758693ULL,
		0xE81B1FED0F285F25ULL,
		0x0FB566F3863B0E05ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4F47743F47DB4858ULL,
		0x321F7295686C4377ULL,
		0x5081648B201E4C82ULL,
		0xC09D04EF8155CA45ULL,
		0x1EBFB296F9AE3553ULL,
		0xDAA0A32CD2EB0D27ULL,
		0xD0363FDA1E50BE4BULL,
		0x1F6ACDE70C761C0BULL
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
		0x5A5771F222178E0BULL,
		0xA58A0BDEA92D427AULL,
		0x21471A06437569FDULL,
		0xE0E274D9CB5E46D8ULL,
		0x31064960232DA4B3ULL,
		0xEEEA0FC19ABE605DULL,
		0x786CEDA04DEAFF8CULL,
		0x0CD050C424807084ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB4AEE3E4442F1C16ULL,
		0x4B1417BD525A84F4ULL,
		0x428E340C86EAD3FBULL,
		0xC1C4E9B396BC8DB0ULL,
		0x620C92C0465B4967ULL,
		0xDDD41F83357CC0BAULL,
		0xF0D9DB409BD5FF19ULL,
		0x19A0A1884900E108ULL
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
		0xCE8B6E303292A43EULL,
		0x6E65BF567531C234ULL,
		0xCEED4803DEA9D843ULL,
		0xD98B5B0EAA70C181ULL,
		0xF78BBDDB2743E3B1ULL,
		0xE573732DAE9F8160ULL,
		0xA1A2CD60A135A1C6ULL,
		0x24B560ECAC2C98CCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9D16DC606525487CULL,
		0xDCCB7EACEA638469ULL,
		0x9DDA9007BD53B086ULL,
		0xB316B61D54E18303ULL,
		0xEF177BB64E87C763ULL,
		0xCAE6E65B5D3F02C1ULL,
		0x43459AC1426B438DULL,
		0x496AC1D958593199ULL
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
		0x2207903D57D39F75ULL,
		0x78DDC4E9D3A268C3ULL,
		0xC0002A5B8761C57CULL,
		0x6D09BD1B72FC2F7CULL,
		0x24FE8E6E3670ED8AULL,
		0x7579FB537E68C724ULL,
		0x4FD158F1E69B18E0ULL,
		0x079BEEF9A1876BFEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x440F207AAFA73EEAULL,
		0xF1BB89D3A744D186ULL,
		0x800054B70EC38AF8ULL,
		0xDA137A36E5F85EF9ULL,
		0x49FD1CDC6CE1DB14ULL,
		0xEAF3F6A6FCD18E48ULL,
		0x9FA2B1E3CD3631C0ULL,
		0x0F37DDF3430ED7FCULL
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
		0xA6D98EC207D907B0ULL,
		0x88664D5017DC87F3ULL,
		0xF0DBDB34FEEC993EULL,
		0x78FA9A43E284BE71ULL,
		0x9DD71544C76BEDF6ULL,
		0x8DE8926BE1BFDA16ULL,
		0xABD9A6707EABF71FULL,
		0x1FEAF48514E369CAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4DB31D840FB20F60ULL,
		0x10CC9AA02FB90FE7ULL,
		0xE1B7B669FDD9327DULL,
		0xF1F53487C5097CE3ULL,
		0x3BAE2A898ED7DBECULL,
		0x1BD124D7C37FB42DULL,
		0x57B34CE0FD57EE3FULL,
		0x3FD5E90A29C6D395ULL
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
		0x0588E149632CFB30ULL,
		0xBCB3E5D0F5E737D6ULL,
		0x1EB3FB28DC070DE5ULL,
		0x52CD7575853C9FFDULL,
		0xE59BDD46EB62B601ULL,
		0xFE76534F5493E509ULL,
		0xF2FB3DA8601FACB7ULL,
		0x14BA826C4EA1B456ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0B11C292C659F660ULL,
		0x7967CBA1EBCE6FACULL,
		0x3D67F651B80E1BCBULL,
		0xA59AEAEB0A793FFAULL,
		0xCB37BA8DD6C56C02ULL,
		0xFCECA69EA927CA13ULL,
		0xE5F67B50C03F596FULL,
		0x297504D89D4368ADULL
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
		0x0F1E00F1D0EAE346ULL,
		0x2F137978ADDAF8A7ULL,
		0x80B87D03CFCCF4EDULL,
		0x35A771DAD6E7E817ULL,
		0xC73A9785965954C5ULL,
		0xBAB30ADB502CE8B3ULL,
		0x4D7A6F7B1EBDB792ULL,
		0x33097423E3634BC8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1E3C01E3A1D5C68CULL,
		0x5E26F2F15BB5F14EULL,
		0x0170FA079F99E9DAULL,
		0x6B4EE3B5ADCFD02FULL,
		0x8E752F0B2CB2A98AULL,
		0x756615B6A059D167ULL,
		0x9AF4DEF63D7B6F25ULL,
		0x6612E847C6C69790ULL
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
		0x8741F4A0AE840527ULL,
		0x99D86E80D0943A74ULL,
		0x7A2266C9E969BA53ULL,
		0x9443BAD65EC0ADDDULL,
		0x023369D21D4C6384ULL,
		0xC74C32C58FD965E4ULL,
		0xEE122A8F748E185DULL,
		0x1B7181A2B33F21C8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0E83E9415D080A4EULL,
		0x33B0DD01A12874E9ULL,
		0xF444CD93D2D374A7ULL,
		0x288775ACBD815BBAULL,
		0x0466D3A43A98C709ULL,
		0x8E98658B1FB2CBC8ULL,
		0xDC24551EE91C30BBULL,
		0x36E30345667E4391ULL
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
		0x92579F3467166F20ULL,
		0x46A09EC88D66ACA2ULL,
		0x24F5C6C7C3A00FE8ULL,
		0x2681EF96FBC04E8FULL,
		0x22F87E37BD31363CULL,
		0xE8356467F99220BCULL,
		0xAB391BE2662A89F3ULL,
		0x31E0C712520CA8F1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x24AF3E68CE2CDE40ULL,
		0x8D413D911ACD5945ULL,
		0x49EB8D8F87401FD0ULL,
		0x4D03DF2DF7809D1EULL,
		0x45F0FC6F7A626C78ULL,
		0xD06AC8CFF3244178ULL,
		0x567237C4CC5513E7ULL,
		0x63C18E24A41951E3ULL
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
		0x801DEFB9660AC32EULL,
		0x8ACA67982A84861DULL,
		0xAF6D55A2036A9E17ULL,
		0x33BF86D4C20615D3ULL,
		0x749325B8C4B044EEULL,
		0xD591352645D10BBCULL,
		0x96A663C43CC0FB20ULL,
		0x0B7058B5FFDE990FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x003BDF72CC15865CULL,
		0x1594CF3055090C3BULL,
		0x5EDAAB4406D53C2FULL,
		0x677F0DA9840C2BA7ULL,
		0xE9264B71896089DCULL,
		0xAB226A4C8BA21778ULL,
		0x2D4CC7887981F641ULL,
		0x16E0B16BFFBD321FULL
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
		0xFC897509EBF86564ULL,
		0x345D22648941D411ULL,
		0xD32194EF67C47420ULL,
		0xE08E2739247B98A1ULL,
		0x2AC339A4C50E1F65ULL,
		0x34980C8E4E537212ULL,
		0x9B27130B29502F84ULL,
		0x24F2B944CB18EBE5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF912EA13D7F0CAC8ULL,
		0x68BA44C91283A823ULL,
		0xA64329DECF88E840ULL,
		0xC11C4E7248F73143ULL,
		0x558673498A1C3ECBULL,
		0x6930191C9CA6E424ULL,
		0x364E261652A05F08ULL,
		0x49E572899631D7CBULL
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
		0x6B80A66EAB5D299FULL,
		0x5E146F8EACFFA918ULL,
		0xC907BEC05EEC9CDDULL,
		0x5735B05994E219F5ULL,
		0x1D82A783388EDC44ULL,
		0xCC33611EEAD818F0ULL,
		0x54156BDEDA4B4A85ULL,
		0x1ED4241DD904CA75ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD7014CDD56BA533EULL,
		0xBC28DF1D59FF5230ULL,
		0x920F7D80BDD939BAULL,
		0xAE6B60B329C433EBULL,
		0x3B054F06711DB888ULL,
		0x9866C23DD5B031E0ULL,
		0xA82AD7BDB496950BULL,
		0x3DA8483BB20994EAULL
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
		0xD4F5D1D584FED3DCULL,
		0xEC61095A3F0C570CULL,
		0xA558351866C0CE44ULL,
		0xB1C8C98B8B196B36ULL,
		0x84AA52F752FBCB44ULL,
		0x80DD6F88DB5BB71CULL,
		0xD60B15463FA4967BULL,
		0x369522D550099392ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA9EBA3AB09FDA7B8ULL,
		0xD8C212B47E18AE19ULL,
		0x4AB06A30CD819C89ULL,
		0x639193171632D66DULL,
		0x0954A5EEA5F79689ULL,
		0x01BADF11B6B76E39ULL,
		0xAC162A8C7F492CF7ULL,
		0x6D2A45AAA0132725ULL
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
		0x340CF0C01049466BULL,
		0x55F513DE27F9946BULL,
		0x803CD65CEFCF9D2DULL,
		0x1F7F490060B2AD33ULL,
		0xE66305E7CB131C54ULL,
		0x59AC851ED86D98DEULL,
		0xDB8D571324642C29ULL,
		0x1CE4BD5FDE1CEC4FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6819E18020928CD6ULL,
		0xABEA27BC4FF328D6ULL,
		0x0079ACB9DF9F3A5AULL,
		0x3EFE9200C1655A67ULL,
		0xCCC60BCF962638A8ULL,
		0xB3590A3DB0DB31BDULL,
		0xB71AAE2648C85852ULL,
		0x39C97ABFBC39D89FULL
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
		0xDEB042D2EB410529ULL,
		0x67907A265361B641ULL,
		0x2CECBFD295BEFE53ULL,
		0x78484058E16E7E2EULL,
		0xD6AD08FC016944B2ULL,
		0x2B680875FEEA4178ULL,
		0x734000793D1AEBCDULL,
		0x37F3301A0F1B7D49ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBD6085A5D6820A52ULL,
		0xCF20F44CA6C36C83ULL,
		0x59D97FA52B7DFCA6ULL,
		0xF09080B1C2DCFC5CULL,
		0xAD5A11F802D28964ULL,
		0x56D010EBFDD482F1ULL,
		0xE68000F27A35D79AULL,
		0x6FE660341E36FA92ULL
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
		0x2456BCB9EDEB8088ULL,
		0x7331A1B5BF7AF9CDULL,
		0x88B618871598D655ULL,
		0xDFB02B2B5E190C99ULL,
		0x94FF687402AC7E19ULL,
		0x3237524D80A123C1ULL,
		0xB21368DCD93F7D7CULL,
		0x2BFCC2A89804C3D6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x48AD7973DBD70110ULL,
		0xE663436B7EF5F39AULL,
		0x116C310E2B31ACAAULL,
		0xBF605656BC321933ULL,
		0x29FED0E80558FC33ULL,
		0x646EA49B01424783ULL,
		0x6426D1B9B27EFAF8ULL,
		0x57F98551300987ADULL
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
		0xB857E605B861997CULL,
		0x06349F6B34059AFBULL,
		0x8727D482E57A6BCDULL,
		0xE4C7AD9A5ADFF541ULL,
		0xCA40737A0E4BA54DULL,
		0xA9F54644B74DB90BULL,
		0xE6B02C3ABC526D6EULL,
		0x24C980713D8794A8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x70AFCC0B70C332F8ULL,
		0x0C693ED6680B35F7ULL,
		0x0E4FA905CAF4D79AULL,
		0xC98F5B34B5BFEA83ULL,
		0x9480E6F41C974A9BULL,
		0x53EA8C896E9B7217ULL,
		0xCD60587578A4DADDULL,
		0x499300E27B0F2951ULL
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
		0xDF90842AB23E2553ULL,
		0xE25E4B8640EB6BE0ULL,
		0x4B55169793A47A75ULL,
		0x9ED1B7EED9DC7B1DULL,
		0x68D33A8B0BAC8E34ULL,
		0x1942C1193E47959FULL,
		0x24425F61598A20DBULL,
		0x1758B58A8E84B99DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBF210855647C4AA6ULL,
		0xC4BC970C81D6D7C1ULL,
		0x96AA2D2F2748F4EBULL,
		0x3DA36FDDB3B8F63AULL,
		0xD1A6751617591C69ULL,
		0x328582327C8F2B3EULL,
		0x4884BEC2B31441B6ULL,
		0x2EB16B151D09733AULL
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
		0xFF520E251CC7A762ULL,
		0x5B1818F931860FE1ULL,
		0x93C4C02F0C619517ULL,
		0x3AAFCFF9F469A1A0ULL,
		0x6178B06BFCC49D06ULL,
		0x6D083CDCC56EAA7CULL,
		0x6A3C1B5E04AEC90EULL,
		0x1F76DD85D4817CC0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFEA41C4A398F4EC4ULL,
		0xB63031F2630C1FC3ULL,
		0x2789805E18C32A2EULL,
		0x755F9FF3E8D34341ULL,
		0xC2F160D7F9893A0CULL,
		0xDA1079B98ADD54F8ULL,
		0xD47836BC095D921CULL,
		0x3EEDBB0BA902F980ULL
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
		0x6C93A20A29C0A728ULL,
		0x87326D686B7844C7ULL,
		0x2A965D3684B9A7E7ULL,
		0xA26BEC6C5F74D409ULL,
		0x75D9FD5EE8046499ULL,
		0x386DADD41A3EFB31ULL,
		0xE886715C3CF34B38ULL,
		0x383A54C295D7387AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD927441453814E50ULL,
		0x0E64DAD0D6F0898EULL,
		0x552CBA6D09734FCFULL,
		0x44D7D8D8BEE9A812ULL,
		0xEBB3FABDD008C933ULL,
		0x70DB5BA8347DF662ULL,
		0xD10CE2B879E69670ULL,
		0x7074A9852BAE70F5ULL
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
		0xBAC5872078EE2278ULL,
		0x75AEDC5D01266C23ULL,
		0x2BA9F68A93250FA4ULL,
		0xE500814E8CD2BE65ULL,
		0xB5E231D5F34AEC2BULL,
		0x9AEB0DF22193B2FBULL,
		0xAD01400856085E48ULL,
		0x2C908A2EB2955454ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x758B0E40F1DC44F0ULL,
		0xEB5DB8BA024CD847ULL,
		0x5753ED15264A1F48ULL,
		0xCA01029D19A57CCAULL,
		0x6BC463ABE695D857ULL,
		0x35D61BE4432765F7ULL,
		0x5A028010AC10BC91ULL,
		0x5921145D652AA8A9ULL
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
		0x1C139FA062A3C238ULL,
		0x18E1FAC3458DE80FULL,
		0x1E07D4F5A177146BULL,
		0xCBBE575809016615ULL,
		0x57846B87AEA5364CULL,
		0x9ED4700AFFDFC095ULL,
		0x5287FECFAD8A0E92ULL,
		0x3A54454DF3FC2802ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x38273F40C5478470ULL,
		0x31C3F5868B1BD01EULL,
		0x3C0FA9EB42EE28D6ULL,
		0x977CAEB01202CC2AULL,
		0xAF08D70F5D4A6C99ULL,
		0x3DA8E015FFBF812AULL,
		0xA50FFD9F5B141D25ULL,
		0x74A88A9BE7F85004ULL
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
		0x5E0C6BAEC6717F08ULL,
		0x05D5F61735DA45BBULL,
		0x6E3250982D1D7D4FULL,
		0x76083316F7E42E67ULL,
		0x9B9ED6CF80AD2566ULL,
		0xCEEB7DFAB3596C54ULL,
		0x2CCF25A4F78B9E1CULL,
		0x00260CC206D81415ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBC18D75D8CE2FE10ULL,
		0x0BABEC2E6BB48B76ULL,
		0xDC64A1305A3AFA9EULL,
		0xEC10662DEFC85CCEULL,
		0x373DAD9F015A4ACCULL,
		0x9DD6FBF566B2D8A9ULL,
		0x599E4B49EF173C39ULL,
		0x004C19840DB0282AULL
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
		0x500624F2D72ABF54ULL,
		0x4BFCB04ED3749B09ULL,
		0xEFE47C07657E7F1BULL,
		0xC0411654DAEE1807ULL,
		0x04E9CD4D42A8C96DULL,
		0x2F155D8C18F3936EULL,
		0x92077C1CA0D1FA53ULL,
		0x0D87F70F04072130ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA00C49E5AE557EA8ULL,
		0x97F9609DA6E93612ULL,
		0xDFC8F80ECAFCFE36ULL,
		0x80822CA9B5DC300FULL,
		0x09D39A9A855192DBULL,
		0x5E2ABB1831E726DCULL,
		0x240EF83941A3F4A6ULL,
		0x1B0FEE1E080E4261ULL
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
		0x01F5056B2B12054BULL,
		0x49BE0F8FA889D6CDULL,
		0xBED03EC9437EA384ULL,
		0x984755A5817FDD58ULL,
		0x264F3FAAA4E65614ULL,
		0x3A363F54A2FC54BCULL,
		0x8BC82F47E53042F1ULL,
		0x288B5B552350DB9BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x03EA0AD656240A96ULL,
		0x937C1F1F5113AD9AULL,
		0x7DA07D9286FD4708ULL,
		0x308EAB4B02FFBAB1ULL,
		0x4C9E7F5549CCAC29ULL,
		0x746C7EA945F8A978ULL,
		0x17905E8FCA6085E2ULL,
		0x5116B6AA46A1B737ULL
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
		0xF895FE5859132AFFULL,
		0xE908D7257013767DULL,
		0x681CEB6162EAF4C7ULL,
		0xBAD62860E53FF39CULL,
		0xBBDC0A104CD2F02FULL,
		0xACB8A39793939C4AULL,
		0xD5783AF748E8F249ULL,
		0x3D263469F5E45EF0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF12BFCB0B22655FEULL,
		0xD211AE4AE026ECFBULL,
		0xD039D6C2C5D5E98FULL,
		0x75AC50C1CA7FE738ULL,
		0x77B8142099A5E05FULL,
		0x5971472F27273895ULL,
		0xAAF075EE91D1E493ULL,
		0x7A4C68D3EBC8BDE1ULL
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
		0xD61E9DD42DA64862ULL,
		0x0D992C17F6D9A0B7ULL,
		0xE02966B089CCFF16ULL,
		0xBD28D78E56320FEDULL,
		0xC6D1B26F82AB9D16ULL,
		0xED125FFCA6A6642AULL,
		0x5BFDC74DFEBFB1A5ULL,
		0x2DF30A477564074EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAC3D3BA85B4C90C4ULL,
		0x1B32582FEDB3416FULL,
		0xC052CD611399FE2CULL,
		0x7A51AF1CAC641FDBULL,
		0x8DA364DF05573A2DULL,
		0xDA24BFF94D4CC855ULL,
		0xB7FB8E9BFD7F634BULL,
		0x5BE6148EEAC80E9CULL
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
		0xCECC38779549519AULL,
		0xBAA319F1222299FBULL,
		0x5E2D742E333A8CD8ULL,
		0xF36F975FBD2D930FULL,
		0x0E8D04D989A716A8ULL,
		0x59FA45BD5B2EBBFCULL,
		0xE2CB5E37C53DC6FEULL,
		0x02622514DF9A0C37ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9D9870EF2A92A334ULL,
		0x754633E2444533F7ULL,
		0xBC5AE85C667519B1ULL,
		0xE6DF2EBF7A5B261EULL,
		0x1D1A09B3134E2D51ULL,
		0xB3F48B7AB65D77F8ULL,
		0xC596BC6F8A7B8DFCULL,
		0x04C44A29BF34186FULL
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
		0xF68B62DA6C09053FULL,
		0xE09AD5232AB21D6AULL,
		0x81F5C4EC5FA97AF1ULL,
		0x48ABCC93D6EC0BB0ULL,
		0xF95B89684015ECC8ULL,
		0x3836C10C5E8D5C9CULL,
		0x15BF6AC23E8FCD95ULL,
		0x16CED3BE2ACED9D5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xED16C5B4D8120A7EULL,
		0xC135AA4655643AD5ULL,
		0x03EB89D8BF52F5E3ULL,
		0x91579927ADD81761ULL,
		0xF2B712D0802BD990ULL,
		0x706D8218BD1AB939ULL,
		0x2B7ED5847D1F9B2AULL,
		0x2D9DA77C559DB3AAULL
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
		0xB045784DC852766EULL,
		0x866F808954635FE3ULL,
		0x8F3DBE123D6632A4ULL,
		0xFFBD63BD9C805C0DULL,
		0xE164CCF9064AD40EULL,
		0xA1C44FD9BF498CB7ULL,
		0x1BE4AAA494BAB005ULL,
		0x0526820448A53811ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x608AF09B90A4ECDCULL,
		0x0CDF0112A8C6BFC7ULL,
		0x1E7B7C247ACC6549ULL,
		0xFF7AC77B3900B81BULL,
		0xC2C999F20C95A81DULL,
		0x43889FB37E93196FULL,
		0x37C955492975600BULL,
		0x0A4D0408914A7022ULL
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
		0x0A18B654ABA4A1DBULL,
		0xE00BFBA0A14A7C9BULL,
		0x6E78F55B94CE4E88ULL,
		0x00712125E5B24800ULL,
		0x689C5C8E2C623BE1ULL,
		0x98C9C177238E281BULL,
		0xCB2285DCA6BF4835ULL,
		0x0BC7A73E568A0840ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x14316CA9574943B6ULL,
		0xC017F7414294F936ULL,
		0xDCF1EAB7299C9D11ULL,
		0x00E2424BCB649000ULL,
		0xD138B91C58C477C2ULL,
		0x319382EE471C5036ULL,
		0x96450BB94D7E906BULL,
		0x178F4E7CAD141081ULL
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
		0xADDE6E371D1FD55CULL,
		0x71B7EA4C18176495ULL,
		0xBD214C35A22A9AA1ULL,
		0x9F4316C53BC9E638ULL,
		0x7774AFE0915E2AD4ULL,
		0xADCA384E7237E27DULL,
		0xAB389294F63FEC06ULL,
		0x2E687182FE486938ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5BBCDC6E3A3FAAB8ULL,
		0xE36FD498302EC92BULL,
		0x7A42986B44553542ULL,
		0x3E862D8A7793CC71ULL,
		0xEEE95FC122BC55A9ULL,
		0x5B94709CE46FC4FAULL,
		0x56712529EC7FD80DULL,
		0x5CD0E305FC90D271ULL
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
		0x3DB2CAF83B534893ULL,
		0xE6068999D02ED695ULL,
		0xA4E817F82C8457F5ULL,
		0xF6C67B410C4249F2ULL,
		0x839C2DCAC250E58EULL,
		0x591FFEB4D376B88CULL,
		0xA8D4E88CBEE2B59EULL,
		0x3C7ED56162BD902AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7B6595F076A69126ULL,
		0xCC0D1333A05DAD2AULL,
		0x49D02FF05908AFEBULL,
		0xED8CF682188493E5ULL,
		0x07385B9584A1CB1DULL,
		0xB23FFD69A6ED7119ULL,
		0x51A9D1197DC56B3CULL,
		0x78FDAAC2C57B2055ULL
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
		0x90E26470356C8346ULL,
		0x82CFC8195A8D29B7ULL,
		0xFC82E3DF4DA9CA3EULL,
		0x9D5098E0708E22C4ULL,
		0x7ABB38C6903C4B69ULL,
		0xC94CD45A4BDFE35EULL,
		0xB202B5C7979220D9ULL,
		0x378E0C3184970D7DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x21C4C8E06AD9068CULL,
		0x059F9032B51A536FULL,
		0xF905C7BE9B53947DULL,
		0x3AA131C0E11C4589ULL,
		0xF576718D207896D3ULL,
		0x9299A8B497BFC6BCULL,
		0x64056B8F2F2441B3ULL,
		0x6F1C1863092E1AFBULL
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
		0x3B267560AF18D2FFULL,
		0x4821DDA9B2E20025ULL,
		0x9708DF75BD42D831ULL,
		0x72A974E121AE3F7FULL,
		0x08CDCA61E0EA7243ULL,
		0xAC1ABD702B525DC0ULL,
		0x08596EB4EDB35D64ULL,
		0x1604B47892E83A27ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x764CEAC15E31A5FEULL,
		0x9043BB5365C4004AULL,
		0x2E11BEEB7A85B062ULL,
		0xE552E9C2435C7EFFULL,
		0x119B94C3C1D4E486ULL,
		0x58357AE056A4BB80ULL,
		0x10B2DD69DB66BAC9ULL,
		0x2C0968F125D0744EULL
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
		0xA9477325F7412617ULL,
		0x0C4AE52F38135AB9ULL,
		0xCB254BAB497C8FCEULL,
		0x06F01149B5DD64E4ULL,
		0x414B457B39210B2BULL,
		0x74D14DA3F207F025ULL,
		0xCB79BB8E55188173ULL,
		0x244F58E33B424C9FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x528EE64BEE824C2EULL,
		0x1895CA5E7026B573ULL,
		0x964A975692F91F9CULL,
		0x0DE022936BBAC9C9ULL,
		0x82968AF672421656ULL,
		0xE9A29B47E40FE04AULL,
		0x96F3771CAA3102E6ULL,
		0x489EB1C67684993FULL
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
		0xF44FB82D0C5D3368ULL,
		0x526413C0F637DAB4ULL,
		0xCF6ED4E38B459774ULL,
		0xEE6D791780D4C8CAULL,
		0x8514927ACE1682C6ULL,
		0x34F88A116F815BC0ULL,
		0x019A3FD67C869D2EULL,
		0x30E439F3DB13CDA2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE89F705A18BA66D0ULL,
		0xA4C82781EC6FB569ULL,
		0x9EDDA9C7168B2EE8ULL,
		0xDCDAF22F01A99195ULL,
		0x0A2924F59C2D058DULL,
		0x69F11422DF02B781ULL,
		0x03347FACF90D3A5CULL,
		0x61C873E7B6279B44ULL
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
		0x2155521C70DA6210ULL,
		0x372D0446D2B8BFEFULL,
		0xFFDA95A947FBBB74ULL,
		0xC4C4F90A8BAE596CULL,
		0xC45540CCFE5E368FULL,
		0xADD0C0672495771CULL,
		0xE0DE687F0B33366BULL,
		0x1CCFDDFDC28E7C68ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x42AAA438E1B4C420ULL,
		0x6E5A088DA5717FDEULL,
		0xFFB52B528FF776E8ULL,
		0x8989F215175CB2D9ULL,
		0x88AA8199FCBC6D1FULL,
		0x5BA180CE492AEE39ULL,
		0xC1BCD0FE16666CD7ULL,
		0x399FBBFB851CF8D1ULL
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
		0x5F37E98E500E642FULL,
		0xCE56ACD87AEED1C9ULL,
		0x5C0AC02584F86B66ULL,
		0x4EE267ED1D3640EDULL,
		0x0940A80E7DE5729AULL,
		0x08F18F2524977981ULL,
		0x6944F4B76DA26123ULL,
		0x1E226D8D96308E41ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBE6FD31CA01CC85EULL,
		0x9CAD59B0F5DDA392ULL,
		0xB815804B09F0D6CDULL,
		0x9DC4CFDA3A6C81DAULL,
		0x1281501CFBCAE534ULL,
		0x11E31E4A492EF302ULL,
		0xD289E96EDB44C246ULL,
		0x3C44DB1B2C611C82ULL
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
		0xA9B4D2F966DC8039ULL,
		0x9AD48BAF8318DADEULL,
		0x61F658808B154E9BULL,
		0xBA3C253CCF849AB4ULL,
		0x6049F86F0EA3FFC9ULL,
		0x7FAA1E0F2383DE9DULL,
		0xD0FB8EDCFE31D15EULL,
		0x2CEB7EC5E9AE442FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5369A5F2CDB90072ULL,
		0x35A9175F0631B5BDULL,
		0xC3ECB101162A9D37ULL,
		0x74784A799F093568ULL,
		0xC093F0DE1D47FF93ULL,
		0xFF543C1E4707BD3AULL,
		0xA1F71DB9FC63A2BCULL,
		0x59D6FD8BD35C885FULL
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
		0xBB74D50C9F9AE23CULL,
		0xA40E9E984777144BULL,
		0x9FB7A12B9B603260ULL,
		0x21E3CA68225A19D7ULL,
		0x2E16DB5431BDCD4CULL,
		0xC90E114D5B89C8DBULL,
		0x59CD0E22782C7D84ULL,
		0x2F4A3463CD80A078ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x76E9AA193F35C478ULL,
		0x481D3D308EEE2897ULL,
		0x3F6F425736C064C1ULL,
		0x43C794D044B433AFULL,
		0x5C2DB6A8637B9A98ULL,
		0x921C229AB71391B6ULL,
		0xB39A1C44F058FB09ULL,
		0x5E9468C79B0140F0ULL
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
		0x0F5D7F35DF5E2C2CULL,
		0x24980713FA282C8AULL,
		0xA3A27C1CAA0325D1ULL,
		0xDDAEAF44DC6A3ABCULL,
		0x82368D23DCCB6D82ULL,
		0x56E87037B2C7CB04ULL,
		0xBC718A0867E42C07ULL,
		0x2BD58659EDE1DAF8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1EBAFE6BBEBC5858ULL,
		0x49300E27F4505914ULL,
		0x4744F83954064BA2ULL,
		0xBB5D5E89B8D47579ULL,
		0x046D1A47B996DB05ULL,
		0xADD0E06F658F9609ULL,
		0x78E31410CFC8580EULL,
		0x57AB0CB3DBC3B5F1ULL
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
		0x228935A620578FCEULL,
		0xF5B8F80150368F9AULL,
		0x483B99A0DEDD5122ULL,
		0xF07BF1C7A9B5F54DULL,
		0x0700AB5DEE36E8F4ULL,
		0x9191198A7D3613B2ULL,
		0x2CBBA41E4127B6FCULL,
		0x176F64AC9821DF3EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x45126B4C40AF1F9CULL,
		0xEB71F002A06D1F34ULL,
		0x90773341BDBAA245ULL,
		0xE0F7E38F536BEA9AULL,
		0x0E0156BBDC6DD1E9ULL,
		0x23223314FA6C2764ULL,
		0x5977483C824F6DF9ULL,
		0x2EDEC9593043BE7CULL
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
		0xC89E740A0E6937C4ULL,
		0xC2BAF39FC015FA9DULL,
		0x80A2C8F2584F2407ULL,
		0x5C68CDF125A7D705ULL,
		0xC46452011E4A2F17ULL,
		0x0C1FFAC8877D4145ULL,
		0x1E41FB458D44E57BULL,
		0x00DC2E32F0D6C0E2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x913CE8141CD26F88ULL,
		0x8575E73F802BF53BULL,
		0x014591E4B09E480FULL,
		0xB8D19BE24B4FAE0BULL,
		0x88C8A4023C945E2EULL,
		0x183FF5910EFA828BULL,
		0x3C83F68B1A89CAF6ULL,
		0x01B85C65E1AD81C4ULL
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
		0x71BDBAC0FED71E74ULL,
		0x911C0B07424CC5D8ULL,
		0x7F8A38F20ECA6822ULL,
		0x2FF1326BFE0C3D42ULL,
		0x68CD6F40440505D4ULL,
		0xBF663C31173BF357ULL,
		0x0B1C59095FB34107ULL,
		0x26782905417EB91FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE37B7581FDAE3CE8ULL,
		0x2238160E84998BB0ULL,
		0xFF1471E41D94D045ULL,
		0x5FE264D7FC187A84ULL,
		0xD19ADE80880A0BA8ULL,
		0x7ECC78622E77E6AEULL,
		0x1638B212BF66820FULL,
		0x4CF0520A82FD723EULL
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
		0x0464F41A6B68E1D5ULL,
		0x201329590DA5D540ULL,
		0xB8301E829B812476ULL,
		0x0F427D92DF05A630ULL,
		0x9ED19D22E3D3ED25ULL,
		0x2CAA25BE385045B3ULL,
		0x958DF35224DD7911ULL,
		0x1F43BE02D80E6035ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x08C9E834D6D1C3AAULL,
		0x402652B21B4BAA80ULL,
		0x70603D05370248ECULL,
		0x1E84FB25BE0B4C61ULL,
		0x3DA33A45C7A7DA4AULL,
		0x59544B7C70A08B67ULL,
		0x2B1BE6A449BAF222ULL,
		0x3E877C05B01CC06BULL
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
		0x181C63C5783BC5A5ULL,
		0x1CD7A136D0B510FEULL,
		0x51EA47DB5329DD3EULL,
		0x89C08C46FD6BE468ULL,
		0xF165047BADB121C8ULL,
		0x56D29F911AB2D11EULL,
		0xAC32401E69D2AA55ULL,
		0x22342688FAD571F3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3038C78AF0778B4AULL,
		0x39AF426DA16A21FCULL,
		0xA3D48FB6A653BA7CULL,
		0x1381188DFAD7C8D0ULL,
		0xE2CA08F75B624391ULL,
		0xADA53F223565A23DULL,
		0x5864803CD3A554AAULL,
		0x44684D11F5AAE3E7ULL
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
		0x49C881CACD756474ULL,
		0x8121249C0716A2C4ULL,
		0x642823E1C5413F2CULL,
		0x82A0FC0D0DF2154DULL,
		0x10F901B54A512026ULL,
		0x100ACA518E87FEE9ULL,
		0x982040514426E6F7ULL,
		0x0987123BEAB0D778ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x939103959AEAC8E8ULL,
		0x024249380E2D4588ULL,
		0xC85047C38A827E59ULL,
		0x0541F81A1BE42A9AULL,
		0x21F2036A94A2404DULL,
		0x201594A31D0FFDD2ULL,
		0x304080A2884DCDEEULL,
		0x130E2477D561AEF1ULL
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
		0x00CA473491433748ULL,
		0xA62E8E94C4128910ULL,
		0x302D66BF9709085EULL,
		0xC7ED59B2160823FEULL,
		0xF7E362C1B5FE6E86ULL,
		0xCC29D2325021ECE2ULL,
		0x92211CE0E3883F8FULL,
		0x152FBB4841C97B96ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x01948E6922866E90ULL,
		0x4C5D1D2988251220ULL,
		0x605ACD7F2E1210BDULL,
		0x8FDAB3642C1047FCULL,
		0xEFC6C5836BFCDD0DULL,
		0x9853A464A043D9C5ULL,
		0x244239C1C7107F1FULL,
		0x2A5F76908392F72DULL
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
		0x1068D1E7225FE9E0ULL,
		0xF29545CA4AF5EB69ULL,
		0xB57429B6743168E2ULL,
		0x59A74022A15C502EULL,
		0x6E1583559C5657B4ULL,
		0x8BBD4164931389ACULL,
		0x60E9D0CF05BF6B6EULL,
		0x000A643445FC5999ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x20D1A3CE44BFD3C0ULL,
		0xE52A8B9495EBD6D2ULL,
		0x6AE8536CE862D1C5ULL,
		0xB34E804542B8A05DULL,
		0xDC2B06AB38ACAF68ULL,
		0x177A82C926271358ULL,
		0xC1D3A19E0B7ED6DDULL,
		0x0014C8688BF8B332ULL
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
		0x7CC4B5AD64E2EFAFULL,
		0x1F482B9E61754358ULL,
		0x7AE5F6A67ED989C1ULL,
		0x36743D823C746AC7ULL,
		0x5D6E2A4E136FAB52ULL,
		0x566BEA5B5CA8F82FULL,
		0xA7A3CF9B90F7E9E6ULL,
		0x04EF8C864A1ADA38ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF9896B5AC9C5DF5EULL,
		0x3E90573CC2EA86B0ULL,
		0xF5CBED4CFDB31382ULL,
		0x6CE87B0478E8D58EULL,
		0xBADC549C26DF56A4ULL,
		0xACD7D4B6B951F05EULL,
		0x4F479F3721EFD3CCULL,
		0x09DF190C9435B471ULL
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
		0x33711F54B9E0DBBCULL,
		0xB9B746B15D779C9CULL,
		0x78124DBD2FB24E02ULL,
		0x68DFF689224AFAEAULL,
		0xCDD3F8969A3AE07FULL,
		0x55D23425B3DD0ED3ULL,
		0x02120C3C8776242FULL,
		0x0206EAF7587F06A5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x66E23EA973C1B778ULL,
		0x736E8D62BAEF3938ULL,
		0xF0249B7A5F649C05ULL,
		0xD1BFED124495F5D4ULL,
		0x9BA7F12D3475C0FEULL,
		0xABA4684B67BA1DA7ULL,
		0x042418790EEC485EULL,
		0x040DD5EEB0FE0D4AULL
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
		0x367DCADEA4158225ULL,
		0x633C8E0C20323DECULL,
		0x1DDD220332D26857ULL,
		0x3ACFF7A39C160AE7ULL,
		0x730B9D40837B814FULL,
		0x6844FC23359E9881ULL,
		0xE69354E43935BDA2ULL,
		0x0F8B2D9FE5315190ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6CFB95BD482B044AULL,
		0xC6791C1840647BD8ULL,
		0x3BBA440665A4D0AEULL,
		0x759FEF47382C15CEULL,
		0xE6173A8106F7029EULL,
		0xD089F8466B3D3102ULL,
		0xCD26A9C8726B7B44ULL,
		0x1F165B3FCA62A321ULL
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
		0x8E13880CF141B589ULL,
		0xA32B449351B62853ULL,
		0x3822EA6A83554F3CULL,
		0x1289F2886EA28917ULL,
		0xDF8C441EACF780ABULL,
		0x5FFE991B147ED372ULL,
		0xD262892B59C3F019ULL,
		0x24E36F802A001428ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1C271019E2836B12ULL,
		0x46568926A36C50A7ULL,
		0x7045D4D506AA9E79ULL,
		0x2513E510DD45122EULL,
		0xBF18883D59EF0156ULL,
		0xBFFD323628FDA6E5ULL,
		0xA4C51256B387E032ULL,
		0x49C6DF0054002851ULL
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
		0x74F72CB02A4183A4ULL,
		0x5FA50223EC0B4E03ULL,
		0x4A2CFF5226DDC7B3ULL,
		0xD65832F7AE2256F9ULL,
		0x1D2ACFBF409D95CDULL,
		0xABE42283B25A71E6ULL,
		0x30DEF525AC8B4DDFULL,
		0x2AAA87B72922CC29ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE9EE596054830748ULL,
		0xBF4A0447D8169C06ULL,
		0x9459FEA44DBB8F66ULL,
		0xACB065EF5C44ADF2ULL,
		0x3A559F7E813B2B9BULL,
		0x57C8450764B4E3CCULL,
		0x61BDEA4B59169BBFULL,
		0x55550F6E52459852ULL
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
		0x9349D5FE8358D88FULL,
		0x8180C35B226180ACULL,
		0x208A965900B123E2ULL,
		0x5674092AA8A433C0ULL,
		0xCDD8C0BC3DEA03FBULL,
		0xF1A18E2CBACDF989ULL,
		0xA911851CBB84394DULL,
		0x30D11D308935E1CEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2693ABFD06B1B11EULL,
		0x030186B644C30159ULL,
		0x41152CB2016247C5ULL,
		0xACE8125551486780ULL,
		0x9BB181787BD407F6ULL,
		0xE3431C59759BF313ULL,
		0x52230A397708729BULL,
		0x61A23A61126BC39DULL
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
		0xC5E5CCDD1A7F5EA5ULL,
		0xECAAB6BFF5F55204ULL,
		0xD18AD1C0A0F452D1ULL,
		0xBCDBCF45DD23FBC3ULL,
		0x217D1BF8CB20F1B0ULL,
		0x9F5FE3B2D172EA61ULL,
		0x87CCB85B5FADAA0EULL,
		0x272E195C57CC3464ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8BCB99BA34FEBD4AULL,
		0xD9556D7FEBEAA409ULL,
		0xA315A38141E8A5A3ULL,
		0x79B79E8BBA47F787ULL,
		0x42FA37F19641E361ULL,
		0x3EBFC765A2E5D4C2ULL,
		0x0F9970B6BF5B541DULL,
		0x4E5C32B8AF9868C9ULL
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
		0x8FC56E4ECF210D09ULL,
		0x1B28D853B666829AULL,
		0x84E8DC361331050EULL,
		0xFF587119A6195E9EULL,
		0xCB7C1DA995BE61A6ULL,
		0x4CB676FAED0642ACULL,
		0xC21F8CED485E25A7ULL,
		0x1AE2B799D36021A7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1F8ADC9D9E421A12ULL,
		0x3651B0A76CCD0535ULL,
		0x09D1B86C26620A1CULL,
		0xFEB0E2334C32BD3DULL,
		0x96F83B532B7CC34DULL,
		0x996CEDF5DA0C8559ULL,
		0x843F19DA90BC4B4EULL,
		0x35C56F33A6C0434FULL
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
		0x7DF33DAEFA748216ULL,
		0x2383FA05074AB696ULL,
		0x52FBD51F810AE9E4ULL,
		0xBBEE4E279AE4D602ULL,
		0xDEDC2629F6C937FFULL,
		0x247A6B802B11663DULL,
		0x149CC9B0250124CDULL,
		0x336267885E8B08DBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFBE67B5DF4E9042CULL,
		0x4707F40A0E956D2CULL,
		0xA5F7AA3F0215D3C8ULL,
		0x77DC9C4F35C9AC04ULL,
		0xBDB84C53ED926FFFULL,
		0x48F4D7005622CC7BULL,
		0x293993604A02499AULL,
		0x66C4CF10BD1611B6ULL
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
		0xA8A07894B878E558ULL,
		0x45E1068190CA8B44ULL,
		0xCCED0AB3FC15F97FULL,
		0x0127A3AA6267B10AULL,
		0x6D9C8750626A2F02ULL,
		0x66BD991B34B5B6CBULL,
		0x19B338BA42D49ACEULL,
		0x1400AB5B5CDCE67FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5140F12970F1CAB0ULL,
		0x8BC20D0321951689ULL,
		0x99DA1567F82BF2FEULL,
		0x024F4754C4CF6215ULL,
		0xDB390EA0C4D45E04ULL,
		0xCD7B3236696B6D96ULL,
		0x3366717485A9359CULL,
		0x280156B6B9B9CCFEULL
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
		0xB3640A108E1710E6ULL,
		0xF64F75A3E7203C3FULL,
		0x7CA769D9ACA2FA50ULL,
		0x42C7DBBE52FDCDA7ULL,
		0x647E651C50E4B462ULL,
		0x335FBDC28E483EF2ULL,
		0x55F600B8B5422C8CULL,
		0x19D6BFBDD17871CBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x66C814211C2E21CCULL,
		0xEC9EEB47CE40787FULL,
		0xF94ED3B35945F4A1ULL,
		0x858FB77CA5FB9B4EULL,
		0xC8FCCA38A1C968C4ULL,
		0x66BF7B851C907DE4ULL,
		0xABEC01716A845918ULL,
		0x33AD7F7BA2F0E396ULL
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
		0xBA8B54C218377A49ULL,
		0x43E3FCD5D1D5FA19ULL,
		0x5899D96873D13A8FULL,
		0x55993DB5231A3E58ULL,
		0x863EB77F375F4728ULL,
		0x78DE55B32A4F6116ULL,
		0x551C5F57CE71A49CULL,
		0x3EDB2A7ABF0FB187ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7516A984306EF492ULL,
		0x87C7F9ABA3ABF433ULL,
		0xB133B2D0E7A2751EULL,
		0xAB327B6A46347CB0ULL,
		0x0C7D6EFE6EBE8E50ULL,
		0xF1BCAB66549EC22DULL,
		0xAA38BEAF9CE34938ULL,
		0x7DB654F57E1F630EULL
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
		0xDB8A2C9567CF7B13ULL,
		0xDEF2D3CF7279D5A4ULL,
		0x184D51108B5D3BAEULL,
		0x6591DC922890FA50ULL,
		0x9C024A1CC7A155EEULL,
		0x2DFF987570F83A5AULL,
		0x612989B1C1C0130EULL,
		0x0E1D668FB3F269D9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB714592ACF9EF626ULL,
		0xBDE5A79EE4F3AB49ULL,
		0x309AA22116BA775DULL,
		0xCB23B9245121F4A0ULL,
		0x380494398F42ABDCULL,
		0x5BFF30EAE1F074B5ULL,
		0xC25313638380261CULL,
		0x1C3ACD1F67E4D3B2ULL
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
		0xAD41724A1B012CEAULL,
		0x3514C15F0ADB8C4AULL,
		0x583EA5D1741DBD04ULL,
		0x7156EA24C11B9DF3ULL,
		0x06FFB24E7EC7AC06ULL,
		0xBA6EFBED341017E3ULL,
		0xE9DA8F79C8DEE17DULL,
		0x3253C7E1CC19522AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5A82E494360259D4ULL,
		0x6A2982BE15B71895ULL,
		0xB07D4BA2E83B7A08ULL,
		0xE2ADD44982373BE6ULL,
		0x0DFF649CFD8F580CULL,
		0x74DDF7DA68202FC6ULL,
		0xD3B51EF391BDC2FBULL,
		0x64A78FC39832A455ULL
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
		0xE97BFBC43E11CF46ULL,
		0xE9A752C941C68FDAULL,
		0x25AB768FFBBBB541ULL,
		0xF35CBFEDB319C3E9ULL,
		0xA966BA5418FD30DAULL,
		0x757FFE2F88B98F64ULL,
		0xE0F573F5D7F8477FULL,
		0x221CDEF259AA4AE2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD2F7F7887C239E8CULL,
		0xD34EA592838D1FB5ULL,
		0x4B56ED1FF7776A83ULL,
		0xE6B97FDB663387D2ULL,
		0x52CD74A831FA61B5ULL,
		0xEAFFFC5F11731EC9ULL,
		0xC1EAE7EBAFF08EFEULL,
		0x4439BDE4B35495C5ULL
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
		0xFED38C83C85AB48CULL,
		0x2DB23C13F664E096ULL,
		0x3FF4B14C8703B195ULL,
		0x1670F3AC22202D36ULL,
		0x2B744BED4AA10175ULL,
		0xDC18E33BA9650DF2ULL,
		0xE3A7E74F15694AE1ULL,
		0x073EA22A82453A37ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFDA7190790B56918ULL,
		0x5B647827ECC9C12DULL,
		0x7FE962990E07632AULL,
		0x2CE1E75844405A6CULL,
		0x56E897DA954202EAULL,
		0xB831C67752CA1BE4ULL,
		0xC74FCE9E2AD295C3ULL,
		0x0E7D4455048A746FULL
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
		0xD90DC7C9B1D08167ULL,
		0x3965E0F24E4980ECULL,
		0xC4101E8F345232C7ULL,
		0x65A9F7A94E87E4E9ULL,
		0x9B76306474DFE77EULL,
		0x08F114351055516DULL,
		0x93622DDFE248DE5BULL,
		0x13CB809E162351ABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB21B8F9363A102CEULL,
		0x72CBC1E49C9301D9ULL,
		0x88203D1E68A4658EULL,
		0xCB53EF529D0FC9D3ULL,
		0x36EC60C8E9BFCEFCULL,
		0x11E2286A20AAA2DBULL,
		0x26C45BBFC491BCB6ULL,
		0x2797013C2C46A357ULL
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
		0x3006CBF79BDF6D42ULL,
		0xE2D36320F5CA9347ULL,
		0xD905E0F3AF6AA313ULL,
		0x5ADB433039775451ULL,
		0x32AB564A07F5A6C9ULL,
		0x64455E1C7A38EF64ULL,
		0x107F3708C27768BFULL,
		0x23AA4B8DE3EC3745ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x600D97EF37BEDA84ULL,
		0xC5A6C641EB95268EULL,
		0xB20BC1E75ED54627ULL,
		0xB5B6866072EEA8A3ULL,
		0x6556AC940FEB4D92ULL,
		0xC88ABC38F471DEC8ULL,
		0x20FE6E1184EED17EULL,
		0x4754971BC7D86E8AULL
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
		0x9CC7802478CAC9E6ULL,
		0xD35DFE5D57C1CE52ULL,
		0x5A48374532F173D6ULL,
		0x5275D55784BA5B04ULL,
		0xC1B7E5EEE796866CULL,
		0xD7AF471D38925291ULL,
		0x259118417D70618EULL,
		0x39E820D1063E622FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x398F0048F19593CCULL,
		0xA6BBFCBAAF839CA5ULL,
		0xB4906E8A65E2E7ADULL,
		0xA4EBAAAF0974B608ULL,
		0x836FCBDDCF2D0CD8ULL,
		0xAF5E8E3A7124A523ULL,
		0x4B223082FAE0C31DULL,
		0x73D041A20C7CC45EULL
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
		0xDAA81FA69D1165F6ULL,
		0x32C98DF6C4F05950ULL,
		0x2521E0CA73668BD7ULL,
		0x2FBBF955F8AC21CCULL,
		0x1540E58CD0F48152ULL,
		0xBCC622B43839905BULL,
		0x6E7ABAD580E4CD79ULL,
		0x265E0A5D86C395EBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB5503F4D3A22CBECULL,
		0x65931BED89E0B2A1ULL,
		0x4A43C194E6CD17AEULL,
		0x5F77F2ABF1584398ULL,
		0x2A81CB19A1E902A4ULL,
		0x798C4568707320B6ULL,
		0xDCF575AB01C99AF3ULL,
		0x4CBC14BB0D872BD6ULL
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
		0xF005BF836EF1130DULL,
		0xFE0DC3251CA84523ULL,
		0x80C45EE490EFC028ULL,
		0xEEB146C11F9E77B8ULL,
		0x62B6175EF005ADFDULL,
		0xD0AF5FD7212C79EFULL,
		0xF936E3A50C108D47ULL,
		0x12B14F6DD0AD3C3EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE00B7F06DDE2261AULL,
		0xFC1B864A39508A47ULL,
		0x0188BDC921DF8051ULL,
		0xDD628D823F3CEF71ULL,
		0xC56C2EBDE00B5BFBULL,
		0xA15EBFAE4258F3DEULL,
		0xF26DC74A18211A8FULL,
		0x25629EDBA15A787DULL
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
		0xCD89937385076A6AULL,
		0xD54C10F8A7173795ULL,
		0xD13253F7A6549E82ULL,
		0xADFAD1F8B9E7EF98ULL,
		0xAB83FAD960358AD7ULL,
		0x5B241693AB9E59D8ULL,
		0x70CC759535959A46ULL,
		0x2E502BB97C72677EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9B1326E70A0ED4D4ULL,
		0xAA9821F14E2E6F2BULL,
		0xA264A7EF4CA93D05ULL,
		0x5BF5A3F173CFDF31ULL,
		0x5707F5B2C06B15AFULL,
		0xB6482D27573CB3B1ULL,
		0xE198EB2A6B2B348CULL,
		0x5CA05772F8E4CEFCULL
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
		0xEEB62111F961675FULL,
		0x9900F62889B0EF76ULL,
		0x1771616273F298D8ULL,
		0x47D06328B8AB3B5CULL,
		0x7F048AA7EA2E701EULL,
		0x620AA858556026C0ULL,
		0xD4430E8C682636F4ULL,
		0x23A8C7BE646E2821ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDD6C4223F2C2CEBEULL,
		0x3201EC511361DEEDULL,
		0x2EE2C2C4E7E531B1ULL,
		0x8FA0C651715676B8ULL,
		0xFE09154FD45CE03CULL,
		0xC41550B0AAC04D80ULL,
		0xA8861D18D04C6DE8ULL,
		0x47518F7CC8DC5043ULL
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
		0x0D550F22DE2A5BC0ULL,
		0x8271E82AB414FA9FULL,
		0x2B90FB1850ECE355ULL,
		0xFC713553AAF7B9A1ULL,
		0xEDC42921C0FDF91EULL,
		0x092386D49BCFD3ABULL,
		0xFFE68E110A4DD53CULL,
		0x1485D0B75AA259A7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1AAA1E45BC54B780ULL,
		0x04E3D0556829F53EULL,
		0x5721F630A1D9C6ABULL,
		0xF8E26AA755EF7342ULL,
		0xDB88524381FBF23DULL,
		0x12470DA9379FA757ULL,
		0xFFCD1C22149BAA78ULL,
		0x290BA16EB544B34FULL
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
		0xC760678E2387C78DULL,
		0x48AF2BC0998AC152ULL,
		0xCDB8D690DC3B20BFULL,
		0xE4FDC77F45859922ULL,
		0x69750C173F8ABBC6ULL,
		0x80CA327A564DA65EULL,
		0x5E201A0FBCECC390ULL,
		0x19CC6F7B2E76BC21ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8EC0CF1C470F8F1AULL,
		0x915E5781331582A5ULL,
		0x9B71AD21B876417EULL,
		0xC9FB8EFE8B0B3245ULL,
		0xD2EA182E7F15778DULL,
		0x019464F4AC9B4CBCULL,
		0xBC40341F79D98721ULL,
		0x3398DEF65CED7842ULL
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
		0xE858351667A3567BULL,
		0x4A03281F70748CD3ULL,
		0x44E0B6EBCD17A3F0ULL,
		0x89B5F93E26F465D6ULL,
		0xC2CAAE3C0AF92CE6ULL,
		0xF372C3AD7A941C21ULL,
		0x48A208D7FB4DDBFBULL,
		0x0E71EBF896A9B8B3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD0B06A2CCF46ACF6ULL,
		0x9406503EE0E919A7ULL,
		0x89C16DD79A2F47E0ULL,
		0x136BF27C4DE8CBACULL,
		0x85955C7815F259CDULL,
		0xE6E5875AF5283843ULL,
		0x914411AFF69BB7F7ULL,
		0x1CE3D7F12D537166ULL
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
		0x7969B5FEB0232E35ULL,
		0xB4776F7169469DAFULL,
		0x61C278008E078C50ULL,
		0xC1FC698A4761683FULL,
		0xE5D45A5DB4CC43D5ULL,
		0xDAD9C123A2882954ULL,
		0x24DACCBEDA6AB6EBULL,
		0x3DD78BEF95699A85ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF2D36BFD60465C6AULL,
		0x68EEDEE2D28D3B5EULL,
		0xC384F0011C0F18A1ULL,
		0x83F8D3148EC2D07EULL,
		0xCBA8B4BB699887ABULL,
		0xB5B38247451052A9ULL,
		0x49B5997DB4D56DD7ULL,
		0x7BAF17DF2AD3350AULL
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
		0x207376009C58790CULL,
		0x116B1F5CDA7A4912ULL,
		0x9D773738CF3ABDCEULL,
		0xBC95611756E0D6C8ULL,
		0x206EE1B5CAF9C1CFULL,
		0x9ADC98E5398F8F97ULL,
		0xB194E76D9A810EEBULL,
		0x081F08D6F5DAECC2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x40E6EC0138B0F218ULL,
		0x22D63EB9B4F49224ULL,
		0x3AEE6E719E757B9CULL,
		0x792AC22EADC1AD91ULL,
		0x40DDC36B95F3839FULL,
		0x35B931CA731F1F2EULL,
		0x6329CEDB35021DD7ULL,
		0x103E11ADEBB5D985ULL
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
		0xE93CF726350FE106ULL,
		0x525BA2B2BF4B100AULL,
		0x043BBF4F3FAA2607ULL,
		0x2940478FF840CAE0ULL,
		0x07E2EDE0D2A28633ULL,
		0x24ABFC263028D682ULL,
		0xD66A63BBFC5E9FA2ULL,
		0x33D9A09FC0BC65E1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD279EE4C6A1FC20CULL,
		0xA4B745657E962015ULL,
		0x08777E9E7F544C0EULL,
		0x52808F1FF08195C0ULL,
		0x0FC5DBC1A5450C66ULL,
		0x4957F84C6051AD04ULL,
		0xACD4C777F8BD3F44ULL,
		0x67B3413F8178CBC3ULL
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
		0x5DECACB80D516134ULL,
		0x86D68173A4B06FF6ULL,
		0xDBD1931B564E810EULL,
		0x142AC84745681664ULL,
		0x1BC2E0122563CBC1ULL,
		0x98C645EB583EB038ULL,
		0xAA890085A31304D5ULL,
		0x05C806D379487185ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBBD959701AA2C268ULL,
		0x0DAD02E74960DFECULL,
		0xB7A32636AC9D021DULL,
		0x2855908E8AD02CC9ULL,
		0x3785C0244AC79782ULL,
		0x318C8BD6B07D6070ULL,
		0x5512010B462609ABULL,
		0x0B900DA6F290E30BULL
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
		0x3F511C724CF49F23ULL,
		0x4F474D2A09A1A7A4ULL,
		0x3F1026A038EE3D82ULL,
		0x3106678354499E6EULL,
		0x94EEB9A0FED82F6AULL,
		0xA558B4604B735AD0ULL,
		0x1EADC21305FC5505ULL,
		0x188E2F08AA69FCC2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7EA238E499E93E46ULL,
		0x9E8E9A5413434F48ULL,
		0x7E204D4071DC7B04ULL,
		0x620CCF06A8933CDCULL,
		0x29DD7341FDB05ED4ULL,
		0x4AB168C096E6B5A1ULL,
		0x3D5B84260BF8AA0BULL,
		0x311C5E1154D3F984ULL
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
		0xF460B479D1B237A0ULL,
		0xD7131D32F604E20EULL,
		0xEBB5E60160C87393ULL,
		0x18424E6CA670C0A4ULL,
		0x249C9DDD7E1D4C72ULL,
		0xFEE346966260AA69ULL,
		0x37C09848F5CF2942ULL,
		0x2B244A788C1906ACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE8C168F3A3646F40ULL,
		0xAE263A65EC09C41DULL,
		0xD76BCC02C190E727ULL,
		0x30849CD94CE18149ULL,
		0x49393BBAFC3A98E4ULL,
		0xFDC68D2CC4C154D2ULL,
		0x6F813091EB9E5285ULL,
		0x564894F118320D58ULL
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
		0x84E8EFC85E26FB81ULL,
		0xB5FFB3E827C7DCFDULL,
		0x623EE0521E58E06EULL,
		0xF27756F5A33B97F1ULL,
		0x5B60F83FACF1AA2EULL,
		0xD9D337218B369B69ULL,
		0x942E12155B802849ULL,
		0x364B175C8B7009A1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x09D1DF90BC4DF702ULL,
		0x6BFF67D04F8FB9FBULL,
		0xC47DC0A43CB1C0DDULL,
		0xE4EEADEB46772FE2ULL,
		0xB6C1F07F59E3545DULL,
		0xB3A66E43166D36D2ULL,
		0x285C242AB7005093ULL,
		0x6C962EB916E01343ULL
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
		0x0F787A1B050ECAF1ULL,
		0x1945C062B7BB05AAULL,
		0x24DE707B49E96CFEULL,
		0x4C491B3648564A5AULL,
		0x7CA5FFC2F00313FBULL,
		0x32DD0A6D1CB88461ULL,
		0xEE24A17C3DA5B3D2ULL,
		0x19E90F692F077E32ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1EF0F4360A1D95E2ULL,
		0x328B80C56F760B54ULL,
		0x49BCE0F693D2D9FCULL,
		0x9892366C90AC94B4ULL,
		0xF94BFF85E00627F6ULL,
		0x65BA14DA397108C2ULL,
		0xDC4942F87B4B67A4ULL,
		0x33D21ED25E0EFC65ULL
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
		0xAEAE89ED83289BC0ULL,
		0x8FD35AC7547B2A91ULL,
		0xC826E4B8CDFB5C72ULL,
		0xE30DB7313A76DD9AULL,
		0xB4C5317D38645D4EULL,
		0x97ADD0CD65535673ULL,
		0x98FE710043C30D12ULL,
		0x1A123903D8D87EEFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5D5D13DB06513780ULL,
		0x1FA6B58EA8F65523ULL,
		0x904DC9719BF6B8E5ULL,
		0xC61B6E6274EDBB35ULL,
		0x698A62FA70C8BA9DULL,
		0x2F5BA19ACAA6ACE7ULL,
		0x31FCE20087861A25ULL,
		0x34247207B1B0FDDFULL
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
		0x2B9B845AECCF71F3ULL,
		0x8394F234195EDA90ULL,
		0x3C54B05CED5B2F9EULL,
		0x63B703A888CB5D02ULL,
		0xA8E539C8F5CACE58ULL,
		0x8C6CC191EBBF7972ULL,
		0x3AAF8BB7FCDB4B4FULL,
		0x3DCBDA4FC66368C8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x573708B5D99EE3E6ULL,
		0x0729E46832BDB520ULL,
		0x78A960B9DAB65F3DULL,
		0xC76E07511196BA04ULL,
		0x51CA7391EB959CB0ULL,
		0x18D98323D77EF2E5ULL,
		0x755F176FF9B6969FULL,
		0x7B97B49F8CC6D190ULL
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
		0xACDEB7DC713C5035ULL,
		0x83CEE3CA597AF4CAULL,
		0xD9DDDC35745FD757ULL,
		0x98A617D4A7DC4BC4ULL,
		0xFACD402806F2724EULL,
		0x946FBCB8123B25BBULL,
		0xC33700BF5A8751E2ULL,
		0x1AE70BB733D33112ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x59BD6FB8E278A06AULL,
		0x079DC794B2F5E995ULL,
		0xB3BBB86AE8BFAEAFULL,
		0x314C2FA94FB89789ULL,
		0xF59A80500DE4E49DULL,
		0x28DF797024764B77ULL,
		0x866E017EB50EA3C5ULL,
		0x35CE176E67A66225ULL
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
		0xF15F812EC860BECEULL,
		0x2D9194E00FD6DDA2ULL,
		0x7C15C6A1DF64A3F4ULL,
		0x4E384C159812BF9FULL,
		0x86AD76420C78E477ULL,
		0xA2BF4E31E1518E87ULL,
		0xB097C0C6DE4974BFULL,
		0x3E21D93DC4501DC7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE2BF025D90C17D9CULL,
		0x5B2329C01FADBB45ULL,
		0xF82B8D43BEC947E8ULL,
		0x9C70982B30257F3EULL,
		0x0D5AEC8418F1C8EEULL,
		0x457E9C63C2A31D0FULL,
		0x612F818DBC92E97FULL,
		0x7C43B27B88A03B8FULL
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
		0xB5483EFE74504E0BULL,
		0xC669E8C81A1E95A8ULL,
		0x72BD2EAAAD2DB2E1ULL,
		0xB13FDEA7C02B474DULL,
		0x1039D7B026AC143DULL,
		0xE7DF18930B5B0D93ULL,
		0x16477EE68616CEF5ULL,
		0x2A35DB5721553338ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6A907DFCE8A09C16ULL,
		0x8CD3D190343D2B51ULL,
		0xE57A5D555A5B65C3ULL,
		0x627FBD4F80568E9AULL,
		0x2073AF604D58287BULL,
		0xCFBE312616B61B26ULL,
		0x2C8EFDCD0C2D9DEBULL,
		0x546BB6AE42AA6670ULL
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
		0x0258AEA151C2BCF0ULL,
		0x80B29944FA9E9DA2ULL,
		0xDC22E1AB24DA02B0ULL,
		0x6B221DF94D6C140BULL,
		0x778367492A5703C5ULL,
		0x3954922057126137ULL,
		0x9D566C0EBB60AAE6ULL,
		0x346F36A9EF40C21AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x04B15D42A38579E0ULL,
		0x01653289F53D3B44ULL,
		0xB845C35649B40561ULL,
		0xD6443BF29AD82817ULL,
		0xEF06CE9254AE078AULL,
		0x72A92440AE24C26EULL,
		0x3AACD81D76C155CCULL,
		0x68DE6D53DE818435ULL
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
		0x14980D9FF22ACFB1ULL,
		0x368C81A062BB3853ULL,
		0x83481759A6DCE78FULL,
		0x4D8EC38AA54865A8ULL,
		0xBD111BF8067E29D7ULL,
		0x1E8B173D1D813A7DULL,
		0x0E4BA6B9306B456EULL,
		0x173577E7D08D96D2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x29301B3FE4559F62ULL,
		0x6D190340C57670A6ULL,
		0x06902EB34DB9CF1EULL,
		0x9B1D87154A90CB51ULL,
		0x7A2237F00CFC53AEULL,
		0x3D162E7A3B0274FBULL,
		0x1C974D7260D68ADCULL,
		0x2E6AEFCFA11B2DA4ULL
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
		0x4B571AB310CC525BULL,
		0xE9569BB79B886F2BULL,
		0xA683385DE7075D2EULL,
		0x589CD9E666B2BA22ULL,
		0x4D6936102CBD6E42ULL,
		0x66226ACEBB5CCA35ULL,
		0x8D3023D61822DC4FULL,
		0x2209E6BB4B1A78E6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x96AE35662198A4B6ULL,
		0xD2AD376F3710DE56ULL,
		0x4D0670BBCE0EBA5DULL,
		0xB139B3CCCD657445ULL,
		0x9AD26C20597ADC84ULL,
		0xCC44D59D76B9946AULL,
		0x1A6047AC3045B89EULL,
		0x4413CD769634F1CDULL
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
		0xA8513D768A0F5C4FULL,
		0x439F1316A56F8073ULL,
		0x5FDF6CB0E7DD9E2FULL,
		0xB991628B406F55AAULL,
		0x78D6B8B34BC8C80DULL,
		0xB9EB5795B0B3CAC8ULL,
		0x3512F098811DDE46ULL,
		0x2716438EB7372D30ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x50A27AED141EB89EULL,
		0x873E262D4ADF00E7ULL,
		0xBFBED961CFBB3C5EULL,
		0x7322C51680DEAB54ULL,
		0xF1AD71669791901BULL,
		0x73D6AF2B61679590ULL,
		0x6A25E131023BBC8DULL,
		0x4E2C871D6E6E5A60ULL
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
		0x30A6566E7C2745E7ULL,
		0xD804B263205B969FULL,
		0x042F0529E37B74F8ULL,
		0x70CFE79291EAFF4CULL,
		0xB5DB58F06444108DULL,
		0xF09350839C9EF2D7ULL,
		0xEC981328E953E4BFULL,
		0x2683A5EDC91E56A7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x614CACDCF84E8BCEULL,
		0xB00964C640B72D3EULL,
		0x085E0A53C6F6E9F1ULL,
		0xE19FCF2523D5FE98ULL,
		0x6BB6B1E0C888211AULL,
		0xE126A107393DE5AFULL,
		0xD9302651D2A7C97FULL,
		0x4D074BDB923CAD4FULL
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
		0x3D5FA99A32834258ULL,
		0x0342B9E0D013E296ULL,
		0xDA4E12A267EA79A1ULL,
		0x61B12DD5A21A75E6ULL,
		0x93CCDDDB2CBC2B2EULL,
		0xEDB49C2E8BFF811FULL,
		0x2EB9E2A39CDFED49ULL,
		0x134579E879797029ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7ABF5334650684B0ULL,
		0x068573C1A027C52CULL,
		0xB49C2544CFD4F342ULL,
		0xC3625BAB4434EBCDULL,
		0x2799BBB65978565CULL,
		0xDB69385D17FF023FULL,
		0x5D73C54739BFDA93ULL,
		0x268AF3D0F2F2E052ULL
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
		0x8B0AEA2FBEC3A893ULL,
		0xEA74E86E1F7575B3ULL,
		0x22D8E4F54EFA55C7ULL,
		0xB86C78060B9AE6E9ULL,
		0xF2F14293A6F5E00BULL,
		0x1957075B1A4C959DULL,
		0x9E7C152C3AF76BDAULL,
		0x0EFA90286DA25668ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1615D45F7D875126ULL,
		0xD4E9D0DC3EEAEB67ULL,
		0x45B1C9EA9DF4AB8FULL,
		0x70D8F00C1735CDD2ULL,
		0xE5E285274DEBC017ULL,
		0x32AE0EB634992B3BULL,
		0x3CF82A5875EED7B4ULL,
		0x1DF52050DB44ACD1ULL
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
		0xD54FF2F1C5554FF2ULL,
		0x5159DD76198CBAE2ULL,
		0x4BDF3877AEA7DADDULL,
		0x1A3FD3535428BD3AULL,
		0x4E941C65B5C79F97ULL,
		0xA562DF9277D110B7ULL,
		0x5DD3D9AF471AECDDULL,
		0x0B7C1AD4504083CFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAA9FE5E38AAA9FE4ULL,
		0xA2B3BAEC331975C5ULL,
		0x97BE70EF5D4FB5BAULL,
		0x347FA6A6A8517A74ULL,
		0x9D2838CB6B8F3F2EULL,
		0x4AC5BF24EFA2216EULL,
		0xBBA7B35E8E35D9BBULL,
		0x16F835A8A081079EULL
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
		0x46EBE52C2C2399FFULL,
		0x6440DFF1087C8916ULL,
		0xDE0ABE12AC022F1CULL,
		0xD6092A29D017F758ULL,
		0xE7771EE729C51E72ULL,
		0x243F243B43910C0FULL,
		0x9F6B5769C82B6423ULL,
		0x32BAAE88B7638D63ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8DD7CA58584733FEULL,
		0xC881BFE210F9122CULL,
		0xBC157C2558045E38ULL,
		0xAC125453A02FEEB1ULL,
		0xCEEE3DCE538A3CE5ULL,
		0x487E48768722181FULL,
		0x3ED6AED39056C846ULL,
		0x65755D116EC71AC7ULL
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
		0xD4854AE9C3C67B13ULL,
		0x21564CE250EF3280ULL,
		0x0F86AC675B7D9D14ULL,
		0x5772051C7888EE20ULL,
		0xD07F436BFA9F8BCDULL,
		0x7EE7E05A3DD9B897ULL,
		0xD19A86AC29E3BCDFULL,
		0x37E1C78E65D03C2CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA90A95D3878CF626ULL,
		0x42AC99C4A1DE6501ULL,
		0x1F0D58CEB6FB3A28ULL,
		0xAEE40A38F111DC40ULL,
		0xA0FE86D7F53F179AULL,
		0xFDCFC0B47BB3712FULL,
		0xA3350D5853C779BEULL,
		0x6FC38F1CCBA07859ULL
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
		0x172D12297BFB9FACULL,
		0x01227E3455F94379ULL,
		0x9316508EA8FBF6B3ULL,
		0xD75545F0F98BBDBDULL,
		0xF0ED15BBFC3E4BCEULL,
		0xC4DEB7F3C5AD97E4ULL,
		0x4DA1E236D320A9D2ULL,
		0x27330A48ADAE27B9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2E5A2452F7F73F58ULL,
		0x0244FC68ABF286F2ULL,
		0x262CA11D51F7ED66ULL,
		0xAEAA8BE1F3177B7BULL,
		0xE1DA2B77F87C979DULL,
		0x89BD6FE78B5B2FC9ULL,
		0x9B43C46DA64153A5ULL,
		0x4E6614915B5C4F72ULL
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
		0xA5B28E0ACAEFC7DEULL,
		0x1980E5E722EA5652ULL,
		0xE99533774476EE98ULL,
		0xB40F5FFC06FB9767ULL,
		0x0C4895A3F9C17603ULL,
		0xED7D16646CF5BB4BULL,
		0xBB8804BC7ACA9468ULL,
		0x1E30340098E59842ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4B651C1595DF8FBCULL,
		0x3301CBCE45D4ACA5ULL,
		0xD32A66EE88EDDD30ULL,
		0x681EBFF80DF72ECFULL,
		0x18912B47F382EC07ULL,
		0xDAFA2CC8D9EB7696ULL,
		0x77100978F59528D1ULL,
		0x3C60680131CB3085ULL
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
		0xAC99BEDD672D1942ULL,
		0xCA479BF284015BC1ULL,
		0x89AB990758316034ULL,
		0x60E53F97CD8BE6D4ULL,
		0x0EF8455E321473E6ULL,
		0x674267CF56B0167BULL,
		0xDE29CA8BCB7DF10BULL,
		0x28C508CD6FFD9FB0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x59337DBACE5A3284ULL,
		0x948F37E50802B783ULL,
		0x1357320EB062C069ULL,
		0xC1CA7F2F9B17CDA9ULL,
		0x1DF08ABC6428E7CCULL,
		0xCE84CF9EAD602CF6ULL,
		0xBC53951796FBE216ULL,
		0x518A119ADFFB3F61ULL
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
		0x35350EA986612576ULL,
		0xBBB1587B8BE4CFE9ULL,
		0x7B8BC31E151DEFCDULL,
		0xC71CE93FB96EB071ULL,
		0xFDDF89CAEED15940ULL,
		0x14A4F4D37B620E42ULL,
		0xD446C3C2D925DEB0ULL,
		0x3BF2744A63D7FA3BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6A6A1D530CC24AECULL,
		0x7762B0F717C99FD2ULL,
		0xF717863C2A3BDF9BULL,
		0x8E39D27F72DD60E2ULL,
		0xFBBF1395DDA2B281ULL,
		0x2949E9A6F6C41C85ULL,
		0xA88D8785B24BBD60ULL,
		0x77E4E894C7AFF477ULL
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
		0x207C34679736DAF7ULL,
		0x664BE84C16A6DE90ULL,
		0x5F792A8C0DA99EA6ULL,
		0xD11A68BBB1EF4D47ULL,
		0x55CD414F9E28986FULL,
		0x630CFDDA48B66DEDULL,
		0x3F6D756C804C5A17ULL,
		0x26A47155449A7478ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x40F868CF2E6DB5EEULL,
		0xCC97D0982D4DBD20ULL,
		0xBEF255181B533D4CULL,
		0xA234D17763DE9A8EULL,
		0xAB9A829F3C5130DFULL,
		0xC619FBB4916CDBDAULL,
		0x7EDAEAD90098B42EULL,
		0x4D48E2AA8934E8F0ULL
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
		0xCD8E10A71CC2F830ULL,
		0xC381EBF89E2F7A77ULL,
		0x344987F941644BF8ULL,
		0xBAA93C3C8D1F0D15ULL,
		0xE50D7BE58D71AD06ULL,
		0xFEB4FCF8883060F2ULL,
		0xA6476516AC0999EDULL,
		0x0A58A90B4BBEF572ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9B1C214E3985F060ULL,
		0x8703D7F13C5EF4EFULL,
		0x68930FF282C897F1ULL,
		0x755278791A3E1A2AULL,
		0xCA1AF7CB1AE35A0DULL,
		0xFD69F9F11060C1E5ULL,
		0x4C8ECA2D581333DBULL,
		0x14B15216977DEAE5ULL
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
		0x345BEE91B01AC421ULL,
		0x6F030681DF3D00F2ULL,
		0x4A7BF0F32FA281C2ULL,
		0xA2555457A64FBA99ULL,
		0x7A139EFF9703E668ULL,
		0xF016EF05CBFC567AULL,
		0x9A1A95FC0B9C97A7ULL,
		0x38DE828074112ADAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x68B7DD2360358842ULL,
		0xDE060D03BE7A01E4ULL,
		0x94F7E1E65F450384ULL,
		0x44AAA8AF4C9F7532ULL,
		0xF4273DFF2E07CCD1ULL,
		0xE02DDE0B97F8ACF4ULL,
		0x34352BF817392F4FULL,
		0x71BD0500E82255B5ULL
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
		0x50D7D106C269FB32ULL,
		0xD7381F26F67E98FBULL,
		0xFE4F3ABDF9083BB0ULL,
		0xA395C4EE5E13DF36ULL,
		0x60A488A40D20ED7FULL,
		0x6E2165E6EFBAB5C7ULL,
		0xD8A56FDB4F3C4902ULL,
		0x11FF7C45B4074229ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA1AFA20D84D3F664ULL,
		0xAE703E4DECFD31F6ULL,
		0xFC9E757BF2107761ULL,
		0x472B89DCBC27BE6DULL,
		0xC14911481A41DAFFULL,
		0xDC42CBCDDF756B8EULL,
		0xB14ADFB69E789204ULL,
		0x23FEF88B680E8453ULL
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
		0xD702652580CC6B25ULL,
		0x0105BD9ADC2A0EA9ULL,
		0x024B7EC7C770FBF9ULL,
		0xD1A5B282497E0658ULL,
		0xF48310454724BFEAULL,
		0x3505DA7D6062B20BULL,
		0x08B65B44B99D6F7AULL,
		0x174A244C21DFE58FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAE04CA4B0198D64AULL,
		0x020B7B35B8541D53ULL,
		0x0496FD8F8EE1F7F2ULL,
		0xA34B650492FC0CB0ULL,
		0xE906208A8E497FD5ULL,
		0x6A0BB4FAC0C56417ULL,
		0x116CB689733ADEF4ULL,
		0x2E94489843BFCB1EULL
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
		0x6D7D52891550AD95ULL,
		0xC746A06707DCF428ULL,
		0x28B95FC64685232DULL,
		0x7BE95DD61D4B4BFFULL,
		0xF1399B4443E371A7ULL,
		0xCCF4359C9F7155E7ULL,
		0x19624B55D709EC8FULL,
		0x0BA05271150AED95ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDAFAA5122AA15B2AULL,
		0x8E8D40CE0FB9E850ULL,
		0x5172BF8C8D0A465BULL,
		0xF7D2BBAC3A9697FEULL,
		0xE273368887C6E34EULL,
		0x99E86B393EE2ABCFULL,
		0x32C496ABAE13D91FULL,
		0x1740A4E22A15DB2AULL
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
		0xDABA8CD4D97CAB5AULL,
		0xBF587E3CFC581C22ULL,
		0x3CE0A5F0DB57D412ULL,
		0x367A2B5069270F4CULL,
		0x4AB2723815FA674DULL,
		0x698FA434F39CA204ULL,
		0xB20D1EC7A3E84021ULL,
		0x23EDA2F7847EF612ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB57519A9B2F956B4ULL,
		0x7EB0FC79F8B03845ULL,
		0x79C14BE1B6AFA825ULL,
		0x6CF456A0D24E1E98ULL,
		0x9564E4702BF4CE9AULL,
		0xD31F4869E7394408ULL,
		0x641A3D8F47D08042ULL,
		0x47DB45EF08FDEC25ULL
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
		0x0838016F4E130036ULL,
		0x6B0A5A2E07BBC0EAULL,
		0x0478D06694229DB7ULL,
		0x7C76C6CDA4F06996ULL,
		0x07B528CBF72D065EULL,
		0xF4EAF9C4FDE9FE0BULL,
		0x8C320AFE740E9AD9ULL,
		0x089DBB6383104EDCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x107002DE9C26006CULL,
		0xD614B45C0F7781D4ULL,
		0x08F1A0CD28453B6EULL,
		0xF8ED8D9B49E0D32CULL,
		0x0F6A5197EE5A0CBCULL,
		0xE9D5F389FBD3FC16ULL,
		0x186415FCE81D35B3ULL,
		0x113B76C706209DB9ULL
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
		0x18796685FD3FD1CAULL,
		0xF9E432D53C401F08ULL,
		0xBCE4730BD03E5F46ULL,
		0xA33DD990528DDE2CULL,
		0xD39B8A774CE98999ULL,
		0x32E6C6CD0E4FA59CULL,
		0x73FD81405F761D60ULL,
		0x33DEE58682F0E760ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x30F2CD0BFA7FA394ULL,
		0xF3C865AA78803E10ULL,
		0x79C8E617A07CBE8DULL,
		0x467BB320A51BBC59ULL,
		0xA73714EE99D31333ULL,
		0x65CD8D9A1C9F4B39ULL,
		0xE7FB0280BEEC3AC0ULL,
		0x67BDCB0D05E1CEC0ULL
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
		0xB7B257533F0911C3ULL,
		0x7756A149640A8D08ULL,
		0x4FAE6C9718D7A94AULL,
		0xE1B6EA3F7DA23A71ULL,
		0x2D4C80B4DAFF5158ULL,
		0xF377FEE97EE13D7FULL,
		0x604BE9B48B147545ULL,
		0x3E4138C6CF787311ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6F64AEA67E122386ULL,
		0xEEAD4292C8151A11ULL,
		0x9F5CD92E31AF5294ULL,
		0xC36DD47EFB4474E2ULL,
		0x5A990169B5FEA2B1ULL,
		0xE6EFFDD2FDC27AFEULL,
		0xC097D3691628EA8BULL,
		0x7C82718D9EF0E622ULL
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
		0x57A90F2AC0E06910ULL,
		0x21424E9AF2AD040DULL,
		0x7B41BC36EC23F6DCULL,
		0xF997B1FAF76EAC87ULL,
		0x0C33DD3CC37B0A79ULL,
		0x3F120590F0278041ULL,
		0xBC0BBF53D0098FC8ULL,
		0x3F64250F03A1A9B4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF521E5581C0D220ULL,
		0x42849D35E55A081AULL,
		0xF683786DD847EDB8ULL,
		0xF32F63F5EEDD590EULL,
		0x1867BA7986F614F3ULL,
		0x7E240B21E04F0082ULL,
		0x78177EA7A0131F90ULL,
		0x7EC84A1E07435369ULL
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
		0x1BCD73C6CA8F847DULL,
		0xBFE91F85DBBD753BULL,
		0x8C45A6459B1953C0ULL,
		0x110478E8653C63A1ULL,
		0xD41756D736B4BF31ULL,
		0x52C0331ED48F916DULL,
		0x419F1ADD8869715DULL,
		0x2676756EE0CD5448ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x379AE78D951F08FAULL,
		0x7FD23F0BB77AEA76ULL,
		0x188B4C8B3632A781ULL,
		0x2208F1D0CA78C743ULL,
		0xA82EADAE6D697E62ULL,
		0xA580663DA91F22DBULL,
		0x833E35BB10D2E2BAULL,
		0x4CECEADDC19AA890ULL
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
		0x00938020D0B877EBULL,
		0x283F5C67D6F596F1ULL,
		0xD6C2AA42E6735516ULL,
		0xE8AB97A8168EDD7AULL,
		0x58256B8D2BCE1D43ULL,
		0x0195037E49035E2DULL,
		0x7E4B966A2B1D4EE3ULL,
		0x11C1FE66F8F2845EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x01270041A170EFD6ULL,
		0x507EB8CFADEB2DE2ULL,
		0xAD855485CCE6AA2CULL,
		0xD1572F502D1DBAF5ULL,
		0xB04AD71A579C3A87ULL,
		0x032A06FC9206BC5AULL,
		0xFC972CD4563A9DC6ULL,
		0x2383FCCDF1E508BCULL
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
		0x84FC2EFF068F46ACULL,
		0x98C1B097DE6AF068ULL,
		0xB237296C6217AA13ULL,
		0x944D4A61CF3A3B89ULL,
		0x24ABFFB3ECE82ED8ULL,
		0x23CBCEE3D81CA556ULL,
		0x310219002EB84DDEULL,
		0x04424AF6B69198FCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x09F85DFE0D1E8D58ULL,
		0x3183612FBCD5E0D1ULL,
		0x646E52D8C42F5427ULL,
		0x289A94C39E747713ULL,
		0x4957FF67D9D05DB1ULL,
		0x47979DC7B0394AACULL,
		0x620432005D709BBCULL,
		0x088495ED6D2331F8ULL
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
		0x6453C57F5DFAFF59ULL,
		0xC6D7567022D2E537ULL,
		0xFC8AA26323DBDBEEULL,
		0x393CCE0E0C9481D4ULL,
		0xADF10704923E6BD1ULL,
		0x111D33F17AF6F9C6ULL,
		0xFA16CF6BB8787972ULL,
		0x0E98C23917A1242AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC8A78AFEBBF5FEB2ULL,
		0x8DAEACE045A5CA6EULL,
		0xF91544C647B7B7DDULL,
		0x72799C1C192903A9ULL,
		0x5BE20E09247CD7A2ULL,
		0x223A67E2F5EDF38DULL,
		0xF42D9ED770F0F2E4ULL,
		0x1D3184722F424855ULL
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
		0x2331AF3675D96AE0ULL,
		0x8FFF46B81C2B851AULL,
		0x7141DAFAF9B843D4ULL,
		0x7ED67451373FC131ULL,
		0x906AA1DAAB68EBC0ULL,
		0x136E38C9442646F2ULL,
		0x81E300ADBD12D131ULL,
		0x364531C92657E403ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x46635E6CEBB2D5C0ULL,
		0x1FFE8D7038570A34ULL,
		0xE283B5F5F37087A9ULL,
		0xFDACE8A26E7F8262ULL,
		0x20D543B556D1D780ULL,
		0x26DC7192884C8DE5ULL,
		0x03C6015B7A25A262ULL,
		0x6C8A63924CAFC807ULL
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
		0xC4E8A00899968AB1ULL,
		0xFE565767953F3886ULL,
		0x0F36AC4EF24F47EFULL,
		0x5FF3A0B8976A7DFAULL,
		0x436526D543CAB812ULL,
		0xA73E099381965FBCULL,
		0x2B6B443AADD6F09BULL,
		0x2918C67D1C038F16ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x89D14011332D1562ULL,
		0xFCACAECF2A7E710DULL,
		0x1E6D589DE49E8FDFULL,
		0xBFE741712ED4FBF4ULL,
		0x86CA4DAA87957024ULL,
		0x4E7C1327032CBF78ULL,
		0x56D688755BADE137ULL,
		0x52318CFA38071E2CULL
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
		0x52D7D825218F52A0ULL,
		0x8F3795F55D0C8C65ULL,
		0x4D708EA4EC062944ULL,
		0xAF3BDA8693863737ULL,
		0x13B05C2FCACA9428ULL,
		0x625350FB34371411ULL,
		0xAE518AA15858A047ULL,
		0x00C2BE505ECF0CF6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA5AFB04A431EA540ULL,
		0x1E6F2BEABA1918CAULL,
		0x9AE11D49D80C5289ULL,
		0x5E77B50D270C6E6EULL,
		0x2760B85F95952851ULL,
		0xC4A6A1F6686E2822ULL,
		0x5CA31542B0B1408EULL,
		0x01857CA0BD9E19EDULL
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
		0x3BC21F17FF08E880ULL,
		0xBCE46BD39FC50D91ULL,
		0xA148A3AEDF1DDB45ULL,
		0x5DFB8C1B7FA40F06ULL,
		0xB4760CC8BCA83FCCULL,
		0xCC515F6A83D153F5ULL,
		0xAF523C705459667CULL,
		0x177717CC22D586D4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x77843E2FFE11D100ULL,
		0x79C8D7A73F8A1B22ULL,
		0x4291475DBE3BB68BULL,
		0xBBF71836FF481E0DULL,
		0x68EC199179507F98ULL,
		0x98A2BED507A2A7EBULL,
		0x5EA478E0A8B2CCF9ULL,
		0x2EEE2F9845AB0DA9ULL
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
		0x0316BD567A392A45ULL,
		0xD210D74ED4EE7C99ULL,
		0xD6A308D95E8933D2ULL,
		0xF4FD11C7346111BCULL,
		0x02F9A93D54BBA873ULL,
		0x7CE879B12AF3FE7DULL,
		0x2F0E9FC122B32AD5ULL,
		0x211A0C063B670BDFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x062D7AACF472548AULL,
		0xA421AE9DA9DCF932ULL,
		0xAD4611B2BD1267A5ULL,
		0xE9FA238E68C22379ULL,
		0x05F3527AA97750E7ULL,
		0xF9D0F36255E7FCFAULL,
		0x5E1D3F82456655AAULL,
		0x4234180C76CE17BEULL
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
		0xD7DC0327C9D43FDBULL,
		0x151A6EC5B831697AULL,
		0x02822BD7FD35E22FULL,
		0x6E20A524B480C7B3ULL,
		0x02DA0EA979892B8CULL,
		0x237649D686DDB46AULL,
		0xC3CE9E3CA6000F4BULL,
		0x2C6E8127ED5B0A87ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAFB8064F93A87FB6ULL,
		0x2A34DD8B7062D2F5ULL,
		0x050457AFFA6BC45EULL,
		0xDC414A4969018F66ULL,
		0x05B41D52F3125718ULL,
		0x46EC93AD0DBB68D4ULL,
		0x879D3C794C001E96ULL,
		0x58DD024FDAB6150FULL
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
		0x5002BCAEF55FE54DULL,
		0x7506B4974768C4C0ULL,
		0x2A48380E5FB7EE21ULL,
		0xBBA0720BB44A911CULL,
		0x3592A94085B1F0E5ULL,
		0x88C49FD860089017ULL,
		0xF74E040A3A47A039ULL,
		0x1B545CDEC28843E7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA005795DEABFCA9AULL,
		0xEA0D692E8ED18980ULL,
		0x5490701CBF6FDC42ULL,
		0x7740E41768952238ULL,
		0x6B2552810B63E1CBULL,
		0x11893FB0C011202EULL,
		0xEE9C0814748F4073ULL,
		0x36A8B9BD851087CFULL
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
		0xB720179AD1974B22ULL,
		0x09AA19CF0535E980ULL,
		0xA4EA24FB32E58983ULL,
		0xA1A30658831A69D4ULL,
		0x0B9AE0FADEF4D002ULL,
		0x26FD95340FC876BCULL,
		0x8CCAB707F1C40659ULL,
		0x32A3A7AF0F2CDFA3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6E402F35A32E9644ULL,
		0x1354339E0A6BD301ULL,
		0x49D449F665CB1306ULL,
		0x43460CB10634D3A9ULL,
		0x1735C1F5BDE9A005ULL,
		0x4DFB2A681F90ED78ULL,
		0x19956E0FE3880CB2ULL,
		0x65474F5E1E59BF47ULL
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
		0x736B54A4C07BDA14ULL,
		0x80825D77AAA021AFULL,
		0x265240DA29B3F501ULL,
		0xFBC39A7B88A320F0ULL,
		0x37D9320F62C8947AULL,
		0xD4D29A05429B8172ULL,
		0x9FA707878942924FULL,
		0x151C43B4C7936BBAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE6D6A94980F7B428ULL,
		0x0104BAEF5540435EULL,
		0x4CA481B45367EA03ULL,
		0xF78734F7114641E0ULL,
		0x6FB2641EC59128F5ULL,
		0xA9A5340A853702E4ULL,
		0x3F4E0F0F1285249FULL,
		0x2A3887698F26D775ULL
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
		0x9E199257DDDEA607ULL,
		0xA52CD436754E7822ULL,
		0x9CE600B599795195ULL,
		0x0D02A5DF41C24287ULL,
		0x37C7BF06288FF9D3ULL,
		0xCA59F6C08166B33DULL,
		0xEB01B7375B40DDD2ULL,
		0x23F94E4E45F9C0DEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3C3324AFBBBD4C0EULL,
		0x4A59A86CEA9CF045ULL,
		0x39CC016B32F2A32BULL,
		0x1A054BBE8384850FULL,
		0x6F8F7E0C511FF3A6ULL,
		0x94B3ED8102CD667AULL,
		0xD6036E6EB681BBA5ULL,
		0x47F29C9C8BF381BDULL
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
		0x6BC05627DCCF08F0ULL,
		0x018E07B7A7F4535AULL,
		0xFE90FE91710C0AE7ULL,
		0xB0BC8981D473BFF2ULL,
		0xC8496E4505A9E463ULL,
		0x44FE3975ED0EE1D9ULL,
		0xAFF2569ECBE5D50FULL,
		0x0C81E7F4FD5C5F1CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD780AC4FB99E11E0ULL,
		0x031C0F6F4FE8A6B4ULL,
		0xFD21FD22E21815CEULL,
		0x61791303A8E77FE5ULL,
		0x9092DC8A0B53C8C7ULL,
		0x89FC72EBDA1DC3B3ULL,
		0x5FE4AD3D97CBAA1EULL,
		0x1903CFE9FAB8BE39ULL
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
		0x0235E1C8E76AEE35ULL,
		0xC4E019E1C4E5A435ULL,
		0xE0A854D2D2C03AF8ULL,
		0xF2CE541D80680646ULL,
		0x74593E012DE8F69FULL,
		0x1C6CE911740B3D0FULL,
		0x32418DC5E6F0FE6DULL,
		0x04FF29A9C66A2B9CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x046BC391CED5DC6AULL,
		0x89C033C389CB486AULL,
		0xC150A9A5A58075F1ULL,
		0xE59CA83B00D00C8DULL,
		0xE8B27C025BD1ED3FULL,
		0x38D9D222E8167A1EULL,
		0x64831B8BCDE1FCDAULL,
		0x09FE53538CD45738ULL
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
		0xA19333EBC12B2401ULL,
		0x33F5E045D07CF437ULL,
		0xAE7509612C10D17AULL,
		0xBADF829EA00A5C4CULL,
		0xC7DC7341995C34DAULL,
		0xBB1A67C7118D0332ULL,
		0x1A947DAD8BD825EBULL,
		0x1B8734E4C98CE488ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x432667D782564802ULL,
		0x67EBC08BA0F9E86FULL,
		0x5CEA12C25821A2F4ULL,
		0x75BF053D4014B899ULL,
		0x8FB8E68332B869B5ULL,
		0x7634CF8E231A0665ULL,
		0x3528FB5B17B04BD7ULL,
		0x370E69C99319C910ULL
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
		0x1D842EAD67FD0AC7ULL,
		0x0E084C494F62E1FBULL,
		0xCFCEE5A151E8D13BULL,
		0x1E60A43F6AFB1785ULL,
		0x6CD386FE0938EDCCULL,
		0x0E9293BA133221BAULL,
		0xFDC8453713FF2369ULL,
		0x23E0381E5DFD08D7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3B085D5ACFFA158EULL,
		0x1C1098929EC5C3F6ULL,
		0x9F9DCB42A3D1A276ULL,
		0x3CC1487ED5F62F0BULL,
		0xD9A70DFC1271DB98ULL,
		0x1D25277426644374ULL,
		0xFB908A6E27FE46D2ULL,
		0x47C0703CBBFA11AFULL
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
		0x070EEF05FC8ED22EULL,
		0x41B7C868D9016A8CULL,
		0x3521AF4320EE2550ULL,
		0xD63AFCB30902D297ULL,
		0xAE6B24D5D3452938ULL,
		0xC71B076977F31CC2ULL,
		0x9F9EAF2596F260B2ULL,
		0x0A3D5BCDF3C41579ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0E1DDE0BF91DA45CULL,
		0x836F90D1B202D518ULL,
		0x6A435E8641DC4AA0ULL,
		0xAC75F9661205A52EULL,
		0x5CD649ABA68A5271ULL,
		0x8E360ED2EFE63985ULL,
		0x3F3D5E4B2DE4C165ULL,
		0x147AB79BE7882AF3ULL
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
		0xF405CA17E3520F6EULL,
		0xABAF82D2E71BD83EULL,
		0xC5378F7D7653B2FEULL,
		0x119E9A1231A2B206ULL,
		0xF305CD11A9EAB16DULL,
		0x425240CB76C65CDDULL,
		0x04F221576A1AB94CULL,
		0x0013DC2BC0E5F3D6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE80B942FC6A41EDCULL,
		0x575F05A5CE37B07DULL,
		0x8A6F1EFAECA765FDULL,
		0x233D34246345640DULL,
		0xE60B9A2353D562DAULL,
		0x84A48196ED8CB9BBULL,
		0x09E442AED4357298ULL,
		0x0027B85781CBE7ACULL
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
		0xA977D7B55CEAF1A5ULL,
		0x897667E2F09AAC39ULL,
		0xB9B733C5BE4670A9ULL,
		0x35AC433CD1048C37ULL,
		0x5056DA8D02DCDED1ULL,
		0xB47040F52DC6EE77ULL,
		0xCDE399AD2B7D92CCULL,
		0x19A24658F338478DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x52EFAF6AB9D5E34AULL,
		0x12ECCFC5E1355873ULL,
		0x736E678B7C8CE153ULL,
		0x6B588679A209186FULL,
		0xA0ADB51A05B9BDA2ULL,
		0x68E081EA5B8DDCEEULL,
		0x9BC7335A56FB2599ULL,
		0x33448CB1E6708F1BULL
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
		0x74948D29B1360629ULL,
		0x1FE675010A9C57B7ULL,
		0x4468B62BAA005B6EULL,
		0xC42F3D7A21E10635ULL,
		0x87811227BA38D292ULL,
		0x25CB03D95C82C7A0ULL,
		0x7C23A76FC049E26AULL,
		0x0723683CAB27AAE8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE9291A53626C0C52ULL,
		0x3FCCEA021538AF6EULL,
		0x88D16C575400B6DCULL,
		0x885E7AF443C20C6AULL,
		0x0F02244F7471A525ULL,
		0x4B9607B2B9058F41ULL,
		0xF8474EDF8093C4D4ULL,
		0x0E46D079564F55D0ULL
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
		0xAB4E543FD2E2FCD7ULL,
		0xAFBD182A4F7BF5E3ULL,
		0x7CDF1732598D8B38ULL,
		0xDD33B9FD31E1FDEEULL,
		0xF354638DE34B0FF7ULL,
		0x9DB1CC2CF2F21E97ULL,
		0x8219DD93AF27E39AULL,
		0x30C966A2A79CFA69ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x569CA87FA5C5F9AEULL,
		0x5F7A30549EF7EBC7ULL,
		0xF9BE2E64B31B1671ULL,
		0xBA6773FA63C3FBDCULL,
		0xE6A8C71BC6961FEFULL,
		0x3B639859E5E43D2FULL,
		0x0433BB275E4FC735ULL,
		0x6192CD454F39F4D3ULL
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
		0xE36B7708E26E637DULL,
		0x4F288B41BFA1C43BULL,
		0x9C0D18F4ACCC2BA0ULL,
		0x229A57F134135EE7ULL,
		0xF2F380D671B704E9ULL,
		0x1F2635FDE58920FFULL,
		0xFDA639510150B2E7ULL,
		0x066198723B43AFB6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC6D6EE11C4DCC6FAULL,
		0x9E5116837F438877ULL,
		0x381A31E959985740ULL,
		0x4534AFE26826BDCFULL,
		0xE5E701ACE36E09D2ULL,
		0x3E4C6BFBCB1241FFULL,
		0xFB4C72A202A165CEULL,
		0x0CC330E476875F6DULL
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
		0xC3EE8BE909BF8A98ULL,
		0x31B13B70D923E9CDULL,
		0x466050AD31DE7B75ULL,
		0x6010CBE813A53C6DULL,
		0xC8DD5CBE869332B1ULL,
		0x72D0127956563B14ULL,
		0x2E29B176E6373086ULL,
		0x1E264CDF52ECAADBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x87DD17D2137F1530ULL,
		0x636276E1B247D39BULL,
		0x8CC0A15A63BCF6EAULL,
		0xC02197D0274A78DAULL,
		0x91BAB97D0D266562ULL,
		0xE5A024F2ACAC7629ULL,
		0x5C5362EDCC6E610CULL,
		0x3C4C99BEA5D955B6ULL
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
		0xF7C08C8847762237ULL,
		0x09374388CDC06B5DULL,
		0x735BFE7E5F3B38DCULL,
		0xFDD4F7FF1750BACEULL,
		0xDA926744985DB987ULL,
		0x51D8576D92DC2593ULL,
		0x2E5B486CE8860DDBULL,
		0x151EABCC216C0A40ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEF8119108EEC446EULL,
		0x126E87119B80D6BBULL,
		0xE6B7FCFCBE7671B8ULL,
		0xFBA9EFFE2EA1759CULL,
		0xB524CE8930BB730FULL,
		0xA3B0AEDB25B84B27ULL,
		0x5CB690D9D10C1BB6ULL,
		0x2A3D579842D81480ULL
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
		0xB489892367C21BF8ULL,
		0x777740CB27C0DCD7ULL,
		0x923F7D9A1105E8C9ULL,
		0x44F3A9209E89A0A2ULL,
		0xDD9661967D0E4D7DULL,
		0x3A7B16BC3E3A6483ULL,
		0xAB1C48F425EFA842ULL,
		0x0140C2AAC7E9123AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x69131246CF8437F0ULL,
		0xEEEE81964F81B9AFULL,
		0x247EFB34220BD192ULL,
		0x89E752413D134145ULL,
		0xBB2CC32CFA1C9AFAULL,
		0x74F62D787C74C907ULL,
		0x563891E84BDF5084ULL,
		0x028185558FD22475ULL
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
		0xE85F52C1C0933DF1ULL,
		0xDC1A73B385DC8433ULL,
		0x7E1B3D628B5304FBULL,
		0xFA3CC53E0BA4AFE8ULL,
		0x7D87615B901300DFULL,
		0xBB9CE062DF8B4049ULL,
		0x20445B92B2AF24BCULL,
		0x046C8A4E972CF5B8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD0BEA58381267BE2ULL,
		0xB834E7670BB90867ULL,
		0xFC367AC516A609F7ULL,
		0xF4798A7C17495FD0ULL,
		0xFB0EC2B7202601BFULL,
		0x7739C0C5BF168092ULL,
		0x4088B725655E4979ULL,
		0x08D9149D2E59EB70ULL
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
		0x790CCE3F6E319447ULL,
		0xE208B8A74B05856DULL,
		0x2B0158B0733A9A30ULL,
		0x338CC9BC1F2BE669ULL,
		0x968AE0AC2EF4B8DFULL,
		0xCD94EA6E438976C9ULL,
		0x7E9EA212CF88DF2EULL,
		0x2A8DBCBEA9E2AF0BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF2199C7EDC63288EULL,
		0xC411714E960B0ADAULL,
		0x5602B160E6753461ULL,
		0x671993783E57CCD2ULL,
		0x2D15C1585DE971BEULL,
		0x9B29D4DC8712ED93ULL,
		0xFD3D44259F11BE5DULL,
		0x551B797D53C55E16ULL
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
		0xDBE4854C4013D8CDULL,
		0xF3EA8E851D66E8CFULL,
		0x783BDDE2545329E4ULL,
		0x0E1EDE62315E5D0CULL,
		0xB782C20AEDD00A16ULL,
		0xA8AD17794826BB04ULL,
		0x794908D137898976ULL,
		0x39C7A8F19D72836CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB7C90A988027B19AULL,
		0xE7D51D0A3ACDD19FULL,
		0xF077BBC4A8A653C9ULL,
		0x1C3DBCC462BCBA18ULL,
		0x6F058415DBA0142CULL,
		0x515A2EF2904D7609ULL,
		0xF29211A26F1312EDULL,
		0x738F51E33AE506D8ULL
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
		0xFF76064CE82ADE15ULL,
		0x6E8F97348FEF7F42ULL,
		0x4D2C8F2F050FD2BAULL,
		0xBA8EA8408E229498ULL,
		0xE452AB116417124DULL,
		0xF5B23541716499F0ULL,
		0xE46F056CAF3D6C44ULL,
		0x381E59E7B79DBD81ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFEEC0C99D055BC2AULL,
		0xDD1F2E691FDEFE85ULL,
		0x9A591E5E0A1FA574ULL,
		0x751D50811C452930ULL,
		0xC8A55622C82E249BULL,
		0xEB646A82E2C933E1ULL,
		0xC8DE0AD95E7AD889ULL,
		0x703CB3CF6F3B7B03ULL
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
		0x3D8507711313F195ULL,
		0x5F92AFEC91BAC10CULL,
		0x25AD3391A8F51DAFULL,
		0x0A179D1F42A089A6ULL,
		0x9D9C45082D9D9433ULL,
		0x990220AD07B4D1B4ULL,
		0x883C2DA46AEF5708ULL,
		0x2DF19A9B07A3AC0AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7B0A0EE22627E32AULL,
		0xBF255FD923758218ULL,
		0x4B5A672351EA3B5EULL,
		0x142F3A3E8541134CULL,
		0x3B388A105B3B2866ULL,
		0x3204415A0F69A369ULL,
		0x10785B48D5DEAE11ULL,
		0x5BE335360F475815ULL
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
		0x329592551EF04CCBULL,
		0x26827DB680DBBCC9ULL,
		0x68676D16BB339F29ULL,
		0x0D0651FBF32D3F7BULL,
		0x5C5A6341E8FB77C7ULL,
		0xC1193D28BA8D4100ULL,
		0xAE05750A13BA5F55ULL,
		0x265609DEDC64AB02ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x652B24AA3DE09996ULL,
		0x4D04FB6D01B77992ULL,
		0xD0CEDA2D76673E52ULL,
		0x1A0CA3F7E65A7EF6ULL,
		0xB8B4C683D1F6EF8EULL,
		0x82327A51751A8200ULL,
		0x5C0AEA142774BEABULL,
		0x4CAC13BDB8C95605ULL
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
		0xF8E8EDD4EFD0B714ULL,
		0x60B64298AC836B72ULL,
		0x790550AFB1EEDCD0ULL,
		0xB46F471E0DDD9691ULL,
		0xF15617E616C32885ULL,
		0xFA4D38624E5353B8ULL,
		0xC30BC54CA5A84A35ULL,
		0x32001AD04B43FA3CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF1D1DBA9DFA16E28ULL,
		0xC16C85315906D6E5ULL,
		0xF20AA15F63DDB9A0ULL,
		0x68DE8E3C1BBB2D22ULL,
		0xE2AC2FCC2D86510BULL,
		0xF49A70C49CA6A771ULL,
		0x86178A994B50946BULL,
		0x640035A09687F479ULL
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
		0xFE5375A893D6906AULL,
		0x5E0FC4F6E48B19E8ULL,
		0x9D0789D54D825EA5ULL,
		0x7A775C7C95BA4236ULL,
		0x0C17398BACDCF69CULL,
		0xC75ECF1C83948459ULL,
		0x8F58CC16085944ACULL,
		0x3105E64145DAF14FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFCA6EB5127AD20D4ULL,
		0xBC1F89EDC91633D1ULL,
		0x3A0F13AA9B04BD4AULL,
		0xF4EEB8F92B74846DULL,
		0x182E731759B9ED38ULL,
		0x8EBD9E39072908B2ULL,
		0x1EB1982C10B28959ULL,
		0x620BCC828BB5E29FULL
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
		0x465CCB565B7810B2ULL,
		0x1B7FA86D2432C5F1ULL,
		0x0B8C5F26E10349B9ULL,
		0x552E696627CCB6AAULL,
		0x31319EF9976E8AB0ULL,
		0x02741EA5219F5BE9ULL,
		0xBD8B19A7346656A7ULL,
		0x23B4B4A1DF5C2BB4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8CB996ACB6F02164ULL,
		0x36FF50DA48658BE2ULL,
		0x1718BE4DC2069372ULL,
		0xAA5CD2CC4F996D54ULL,
		0x62633DF32EDD1560ULL,
		0x04E83D4A433EB7D2ULL,
		0x7B16334E68CCAD4EULL,
		0x47696943BEB85769ULL
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
		0x1E9C5EC3D3FCED5CULL,
		0x09778FD6DDD36ABAULL,
		0x9BF9F10D736A40AFULL,
		0x38BB56E476D17657ULL,
		0x2837095C74031B44ULL,
		0x0D5F3C6C4CFFE5B4ULL,
		0x088F36E62BE5D6BEULL,
		0x2C6C52DF6612A42FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3D38BD87A7F9DAB8ULL,
		0x12EF1FADBBA6D574ULL,
		0x37F3E21AE6D4815EULL,
		0x7176ADC8EDA2ECAFULL,
		0x506E12B8E8063688ULL,
		0x1ABE78D899FFCB68ULL,
		0x111E6DCC57CBAD7CULL,
		0x58D8A5BECC25485EULL
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
		0xD479AC15A9A832A9ULL,
		0xA1650C894F8617A7ULL,
		0x547B5D480FB4FBC8ULL,
		0x0ED53C5CE607DCA3ULL,
		0xF59D3B6E66E83A7EULL,
		0xAD82AD6D640B7F06ULL,
		0x67D3E487FC1F123EULL,
		0x004EB59A200DD5D2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA8F3582B53506552ULL,
		0x42CA19129F0C2F4FULL,
		0xA8F6BA901F69F791ULL,
		0x1DAA78B9CC0FB946ULL,
		0xEB3A76DCCDD074FCULL,
		0x5B055ADAC816FE0DULL,
		0xCFA7C90FF83E247DULL,
		0x009D6B34401BABA4ULL
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
		0x1C6E13AE4F40A888ULL,
		0x90213F1550C7607FULL,
		0xA6A63ECBB8177DE4ULL,
		0xDF88D473002A6050ULL,
		0xD68B164BED504C30ULL,
		0xDAC588C14E81052FULL,
		0x8B3E58A9A2FB6F16ULL,
		0x0BCE8E58D0E1EE91ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x38DC275C9E815110ULL,
		0x20427E2AA18EC0FEULL,
		0x4D4C7D97702EFBC9ULL,
		0xBF11A8E60054C0A1ULL,
		0xAD162C97DAA09861ULL,
		0xB58B11829D020A5FULL,
		0x167CB15345F6DE2DULL,
		0x179D1CB1A1C3DD23ULL
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
		0xA88095E38EC24E96ULL,
		0xB2A3E4417638952BULL,
		0x383552D77058EF8DULL,
		0xE6E3BFAD3218AE1EULL,
		0xFFFE4342442BE382ULL,
		0x74285AF97BCDAC2EULL,
		0x9B6378482DABF357ULL,
		0x0ABAD37856B22B58ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x51012BC71D849D2CULL,
		0x6547C882EC712A57ULL,
		0x706AA5AEE0B1DF1BULL,
		0xCDC77F5A64315C3CULL,
		0xFFFC86848857C705ULL,
		0xE850B5F2F79B585DULL,
		0x36C6F0905B57E6AEULL,
		0x1575A6F0AD6456B1ULL
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
		0xC0A067DC2EB38954ULL,
		0x32864D251AFD0FA7ULL,
		0x99865E238EA9619BULL,
		0xE156B30578F8F569ULL,
		0x648B0154900EA2D4ULL,
		0xFD91C648DCF2BF24ULL,
		0x93A10A5436BA36E8ULL,
		0x3BBDA3620A56DADBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8140CFB85D6712A8ULL,
		0x650C9A4A35FA1F4FULL,
		0x330CBC471D52C336ULL,
		0xC2AD660AF1F1EAD3ULL,
		0xC91602A9201D45A9ULL,
		0xFB238C91B9E57E48ULL,
		0x274214A86D746DD1ULL,
		0x777B46C414ADB5B7ULL
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
		0x5210283DFDC7FFEBULL,
		0xD6D211E3F7BD21DDULL,
		0x6D9A8BC10AECB0DDULL,
		0x5357408B346AA296ULL,
		0xB601682067D2C41CULL,
		0x9D533CB72B7D3626ULL,
		0xA5EFD07C0B8E2679ULL,
		0x0BCBA2D1B1E9E4BBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA420507BFB8FFFD6ULL,
		0xADA423C7EF7A43BAULL,
		0xDB35178215D961BBULL,
		0xA6AE811668D5452CULL,
		0x6C02D040CFA58838ULL,
		0x3AA6796E56FA6C4DULL,
		0x4BDFA0F8171C4CF3ULL,
		0x179745A363D3C977ULL
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
		0x3B97E897E410693BULL,
		0xA6F7DEB3FDF725C0ULL,
		0x5443DF846EFBF522ULL,
		0xF96D1FC35B2113C4ULL,
		0xC2B4DE73EDFFE333ULL,
		0xE7462D4CB8E8C877ULL,
		0x02BE53ACB1DF3D47ULL,
		0x23C244518D304439ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x772FD12FC820D276ULL,
		0x4DEFBD67FBEE4B80ULL,
		0xA887BF08DDF7EA45ULL,
		0xF2DA3F86B6422788ULL,
		0x8569BCE7DBFFC667ULL,
		0xCE8C5A9971D190EFULL,
		0x057CA75963BE7A8FULL,
		0x478488A31A608872ULL
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
		0x275349AFE0C5FFB0ULL,
		0x94A9BFBE8E003895ULL,
		0x0D363724300C7463ULL,
		0x5A0CDB3780B50BE9ULL,
		0x3DB929085A9EE7ABULL,
		0x60FE6B279D67E035ULL,
		0x9F55C8DA4B49AD5BULL,
		0x2A777362F51720A7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4EA6935FC18BFF60ULL,
		0x29537F7D1C00712AULL,
		0x1A6C6E486018E8C7ULL,
		0xB419B66F016A17D2ULL,
		0x7B725210B53DCF56ULL,
		0xC1FCD64F3ACFC06AULL,
		0x3EAB91B496935AB6ULL,
		0x54EEE6C5EA2E414FULL
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
		0x54D0BAE995C6E2A2ULL,
		0x309A0887324C4B21ULL,
		0xC3C8485BFEB0C475ULL,
		0x9BEF4C3B8D48F02EULL,
		0x51C01D854800C12BULL,
		0xB5A0E71E299C89AAULL,
		0xC61DA0EC96DAFD8AULL,
		0x2267C34118F55AEEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA9A175D32B8DC544ULL,
		0x6134110E64989642ULL,
		0x879090B7FD6188EAULL,
		0x37DE98771A91E05DULL,
		0xA3803B0A90018257ULL,
		0x6B41CE3C53391354ULL,
		0x8C3B41D92DB5FB15ULL,
		0x44CF868231EAB5DDULL
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
		0xC5E77045E1151333ULL,
		0x941E3D7D694E92CFULL,
		0x9F1B6B864FB4FC48ULL,
		0x0044404E7DBF0FC3ULL,
		0x87ABA4231990D576ULL,
		0xD38DC4DF4B6AC5FEULL,
		0x6ADFE345B689F217ULL,
		0x1A44DB35B10D366EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8BCEE08BC22A2666ULL,
		0x283C7AFAD29D259FULL,
		0x3E36D70C9F69F891ULL,
		0x0088809CFB7E1F87ULL,
		0x0F5748463321AAECULL,
		0xA71B89BE96D58BFDULL,
		0xD5BFC68B6D13E42FULL,
		0x3489B66B621A6CDCULL
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
		0x9A43064287ABAA3BULL,
		0x3B34937B33DC519FULL,
		0xA368A59236B97EE9ULL,
		0x8189753D8D5336F9ULL,
		0x5CC5CD41AB6ECD37ULL,
		0x1F107E416B79E3DBULL,
		0x4F4A56486B4A0C57ULL,
		0x1EF1B3FB65E42135ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x34860C850F575476ULL,
		0x766926F667B8A33FULL,
		0x46D14B246D72FDD2ULL,
		0x0312EA7B1AA66DF3ULL,
		0xB98B9A8356DD9A6FULL,
		0x3E20FC82D6F3C7B6ULL,
		0x9E94AC90D69418AEULL,
		0x3DE367F6CBC8426AULL
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
		0xBC662A1AADDFBABCULL,
		0x8290227CEF8FEEE1ULL,
		0x491F200E74272C1FULL,
		0x7D04440463613D58ULL,
		0x70A3B6A7D333EE23ULL,
		0xFC916A24EBFCB636ULL,
		0xDCB6614B233969FCULL,
		0x0629B7DACC615D29ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x78CC54355BBF7578ULL,
		0x052044F9DF1FDDC3ULL,
		0x923E401CE84E583FULL,
		0xFA088808C6C27AB0ULL,
		0xE1476D4FA667DC46ULL,
		0xF922D449D7F96C6CULL,
		0xB96CC2964672D3F9ULL,
		0x0C536FB598C2BA53ULL
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
		0x6F060D16ABD9F010ULL,
		0xEFA9EC0D93E8DDF3ULL,
		0x4F0A97C81ACD24F4ULL,
		0xFCA044D3F5049862ULL,
		0xC2461D2E322A5598ULL,
		0xAEB4F5A30F040165ULL,
		0xED0A861F2A3376A5ULL,
		0x2D4220DD4C75C52FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDE0C1A2D57B3E020ULL,
		0xDF53D81B27D1BBE6ULL,
		0x9E152F90359A49E9ULL,
		0xF94089A7EA0930C4ULL,
		0x848C3A5C6454AB31ULL,
		0x5D69EB461E0802CBULL,
		0xDA150C3E5466ED4BULL,
		0x5A8441BA98EB8A5FULL
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
		0xBF85349CB982BC77ULL,
		0xD320BF428C4BAA7AULL,
		0xA2F4BBC75845F09EULL,
		0x84C3F84DB142611AULL,
		0xD6FFEBACDFEC312CULL,
		0xFB40BBA6B4465788ULL,
		0x8E45EDB46938C057ULL,
		0x2A9BAFD1BA878D0EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7F0A6939730578EEULL,
		0xA6417E85189754F5ULL,
		0x45E9778EB08BE13DULL,
		0x0987F09B6284C235ULL,
		0xADFFD759BFD86259ULL,
		0xF681774D688CAF11ULL,
		0x1C8BDB68D27180AFULL,
		0x55375FA3750F1A1DULL
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
		0xA24A049EDDCADD57ULL,
		0x447593EA073B6126ULL,
		0x1717ED4B63431714ULL,
		0x5EDAA095EABFF975ULL,
		0x2EFBDE334381B31DULL,
		0x11EB172A6E8F8DECULL,
		0xEACC6F45FAE75AB2ULL,
		0x214A822261E7548DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4494093DBB95BAAEULL,
		0x88EB27D40E76C24DULL,
		0x2E2FDA96C6862E28ULL,
		0xBDB5412BD57FF2EAULL,
		0x5DF7BC668703663AULL,
		0x23D62E54DD1F1BD8ULL,
		0xD598DE8BF5CEB564ULL,
		0x42950444C3CEA91BULL
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
		0x5619CC6EFFEDB281ULL,
		0x09DA9C43403F3C77ULL,
		0x6EF47FDE2B8BE6CEULL,
		0xCA55699DABDB09EAULL,
		0x8348AD532FB18006ULL,
		0x3FBC51E4A795F89DULL,
		0x258A0280388F819DULL,
		0x3470F62E69D1405EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAC3398DDFFDB6502ULL,
		0x13B53886807E78EEULL,
		0xDDE8FFBC5717CD9CULL,
		0x94AAD33B57B613D4ULL,
		0x06915AA65F63000DULL,
		0x7F78A3C94F2BF13BULL,
		0x4B140500711F033AULL,
		0x68E1EC5CD3A280BCULL
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
		0x3D269C605EDB646DULL,
		0x081B8732228BDD7BULL,
		0x9044B1ADBAA448DAULL,
		0xB3432F800D6D4EC9ULL,
		0x83AF854AC41F3797ULL,
		0x258A5B078C46E262ULL,
		0x1A7D90C0E0DB55ADULL,
		0x3B1DACE517552604ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7A4D38C0BDB6C8DAULL,
		0x10370E644517BAF6ULL,
		0x2089635B754891B4ULL,
		0x66865F001ADA9D93ULL,
		0x075F0A95883E6F2FULL,
		0x4B14B60F188DC4C5ULL,
		0x34FB2181C1B6AB5AULL,
		0x763B59CA2EAA4C08ULL
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
		0xDF60D9E225A940A7ULL,
		0x5BEA8CC768DF8B39ULL,
		0xE84D9B081972610CULL,
		0x7733A9DA2C3B2DF9ULL,
		0xC351DB81ADC9390AULL,
		0xD49449D6535E9667ULL,
		0x0323B2F00DDD19FBULL,
		0x27D60E25FE401043ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBEC1B3C44B52814EULL,
		0xB7D5198ED1BF1673ULL,
		0xD09B361032E4C218ULL,
		0xEE6753B458765BF3ULL,
		0x86A3B7035B927214ULL,
		0xA92893ACA6BD2CCFULL,
		0x064765E01BBA33F7ULL,
		0x4FAC1C4BFC802086ULL
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
		0xFC7E5F2451CF1E48ULL,
		0x5BD9832A4AB555D9ULL,
		0xB553F72B72D2413CULL,
		0xEB4E5F50289D833DULL,
		0xB7F3A2A45FFF9BF6ULL,
		0x23FD6CC9241AF5D3ULL,
		0x6E049F1A079EAC7BULL,
		0x285A1F2C64538554ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF8FCBE48A39E3C90ULL,
		0xB7B30654956AABB3ULL,
		0x6AA7EE56E5A48278ULL,
		0xD69CBEA0513B067BULL,
		0x6FE74548BFFF37EDULL,
		0x47FAD9924835EBA7ULL,
		0xDC093E340F3D58F6ULL,
		0x50B43E58C8A70AA8ULL
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
		0xDCC752220F1C3435ULL,
		0x8B2F47A7109DBD05ULL,
		0x72692B0F01179082ULL,
		0x3CFC6016A890256EULL,
		0x2F2786E459118A38ULL,
		0x97239EEE3D581FC8ULL,
		0xC1EB7F36FACED3DEULL,
		0x1CB8CA3D04BDAE0EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB98EA4441E38686AULL,
		0x165E8F4E213B7A0BULL,
		0xE4D2561E022F2105ULL,
		0x79F8C02D51204ADCULL,
		0x5E4F0DC8B2231470ULL,
		0x2E473DDC7AB03F90ULL,
		0x83D6FE6DF59DA7BDULL,
		0x3971947A097B5C1DULL
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
		0x9EB8BEBE5E1E8B66ULL,
		0x26C44B6EBCCF0DD2ULL,
		0xC0CB159B2D1B47D4ULL,
		0xC12DC99679192412ULL,
		0x727D56A8F66F9C23ULL,
		0x89F50C7A3BC962E5ULL,
		0x8BBBF63EC7C40604ULL,
		0x1D0CC6FE03D23164ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3D717D7CBC3D16CCULL,
		0x4D8896DD799E1BA5ULL,
		0x81962B365A368FA8ULL,
		0x825B932CF2324825ULL,
		0xE4FAAD51ECDF3847ULL,
		0x13EA18F47792C5CAULL,
		0x1777EC7D8F880C09ULL,
		0x3A198DFC07A462C9ULL
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
		0xEB93C2F747FA041EULL,
		0x3FF77340FD71C099ULL,
		0xC254562BCA2C567CULL,
		0x348CA3F74913810EULL,
		0xF4160E97DE4720D6ULL,
		0x8AA965E8266856B9ULL,
		0xB7204B2968A448AEULL,
		0x24453B24988487FDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD72785EE8FF4083CULL,
		0x7FEEE681FAE38133ULL,
		0x84A8AC579458ACF8ULL,
		0x691947EE9227021DULL,
		0xE82C1D2FBC8E41ACULL,
		0x1552CBD04CD0AD73ULL,
		0x6E409652D148915DULL,
		0x488A764931090FFBULL
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
		0x5F8153B7DC2A660EULL,
		0x5C0D5FE5F3B4234FULL,
		0x14E9D17686728810ULL,
		0x232D0E10B4E25BE3ULL,
		0xA225570AA5D1087CULL,
		0xB0420B1733037BEFULL,
		0x4D20FDFBC069111AULL,
		0x27F9570013E5AE59ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBF02A76FB854CC1CULL,
		0xB81ABFCBE768469EULL,
		0x29D3A2ED0CE51020ULL,
		0x465A1C2169C4B7C6ULL,
		0x444AAE154BA210F8ULL,
		0x6084162E6606F7DFULL,
		0x9A41FBF780D22235ULL,
		0x4FF2AE0027CB5CB2ULL
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
		0xD9D2D2211DB3C5BAULL,
		0x5DA85F80834EB5E6ULL,
		0x3D3C1321E8869DC9ULL,
		0x84A1B83ED68F3F32ULL,
		0x383AF8E85A21CCCDULL,
		0x64C7F7A3EC4615FAULL,
		0xC7B4ABA8E2D57D56ULL,
		0x058380D3842EB49FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB3A5A4423B678B74ULL,
		0xBB50BF01069D6BCDULL,
		0x7A782643D10D3B92ULL,
		0x0943707DAD1E7E64ULL,
		0x7075F1D0B443999BULL,
		0xC98FEF47D88C2BF4ULL,
		0x8F695751C5AAFAACULL,
		0x0B0701A7085D693FULL
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
		0xC35F447292B49459ULL,
		0x0D5D1CB874446EFFULL,
		0xC1A00E2F02431F9AULL,
		0x0B05DFC153BD3321ULL,
		0x9F05AF65D6C970D9ULL,
		0x3CE1C8A11386DC2BULL,
		0x83C5E4ED672F2648ULL,
		0x0D91E4EAE05AC63BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x86BE88E5256928B2ULL,
		0x1ABA3970E888DDFFULL,
		0x83401C5E04863F34ULL,
		0x160BBF82A77A6643ULL,
		0x3E0B5ECBAD92E1B2ULL,
		0x79C39142270DB857ULL,
		0x078BC9DACE5E4C90ULL,
		0x1B23C9D5C0B58C77ULL
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
		0x4DF4F56FF3D1AA51ULL,
		0x2E67203F5D310EF0ULL,
		0x4F325B852A057F89ULL,
		0x7F13DC0047180D4FULL,
		0x05C01D255DAB5E8FULL,
		0x9E462D97B87905B2ULL,
		0x62EC497C8E8812E7ULL,
		0x149EBD251D39B72EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9BE9EADFE7A354A2ULL,
		0x5CCE407EBA621DE0ULL,
		0x9E64B70A540AFF12ULL,
		0xFE27B8008E301A9EULL,
		0x0B803A4ABB56BD1EULL,
		0x3C8C5B2F70F20B64ULL,
		0xC5D892F91D1025CFULL,
		0x293D7A4A3A736E5CULL
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