#include "../tests.h"

int32_t curve25519_key_x2_test(void) {
	printf("Key Doubling Test\n");
	curve25519_key_t k1 = {.key64 = {
		0xE71DF5C3465A6846ULL,
		0xCD6FF8DA9304BEEBULL,
		0x5486C428D59F36C9ULL,
		0xE841AEFCFD0B9049ULL,
		0x138BB1033B13B6B7ULL,
		0xB42286F55E699DF0ULL,
		0x7FBABF5B5E3A558AULL,
		0x182878045BE31C3AULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0xCE3BEB868CB4D08CULL,
		0x9ADFF1B526097DD7ULL,
		0xA90D8851AB3E6D93ULL,
		0xD0835DF9FA172092ULL,
		0x2717620676276D6FULL,
		0x68450DEABCD33BE0ULL,
		0xFF757EB6BC74AB15ULL,
		0x3050F008B7C63874ULL
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
		0xF4A308D61AB07D6DULL,
		0x166D1056E8E1AFFCULL,
		0x8BCEBD0BD197F33DULL,
		0xBF453589481ADC3EULL,
		0x13F0F3EB7C75775EULL,
		0xBEFC600D16E66E92ULL,
		0xED350FD2F8BB086FULL,
		0x3E68EE16123AB56FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE94611AC3560FADAULL,
		0x2CDA20ADD1C35FF9ULL,
		0x179D7A17A32FE67AULL,
		0x7E8A6B129035B87DULL,
		0x27E1E7D6F8EAEEBDULL,
		0x7DF8C01A2DCCDD24ULL,
		0xDA6A1FA5F17610DFULL,
		0x7CD1DC2C24756ADFULL
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
		0xB9B995BAE4000CE5ULL,
		0xA69283838D134A20ULL,
		0xCCAEBA2371F6297AULL,
		0x6CF8E4953152E11FULL,
		0x1C4A0742793B221CULL,
		0x25649028BFD6ABFFULL,
		0x171100055EF297FFULL,
		0x18A51063F3AB70FCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x73732B75C80019CAULL,
		0x4D2507071A269441ULL,
		0x995D7446E3EC52F5ULL,
		0xD9F1C92A62A5C23FULL,
		0x38940E84F2764438ULL,
		0x4AC920517FAD57FEULL,
		0x2E22000ABDE52FFEULL,
		0x314A20C7E756E1F8ULL
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
		0x5B7916FBD2CFCBA6ULL,
		0x3C427B287A2B4E77ULL,
		0xA18C6E926A7D76B8ULL,
		0xA0584F2E8AC5E8F0ULL,
		0x3EEF709B7F2C5CB5ULL,
		0x9101B7C2458B3519ULL,
		0xC7873B72E74754C9ULL,
		0x0186D29C3666F696ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB6F22DF7A59F974CULL,
		0x7884F650F4569CEEULL,
		0x4318DD24D4FAED70ULL,
		0x40B09E5D158BD1E1ULL,
		0x7DDEE136FE58B96BULL,
		0x22036F848B166A32ULL,
		0x8F0E76E5CE8EA993ULL,
		0x030DA5386CCDED2DULL
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
		0xBB43CC99C3985038ULL,
		0x2914C1C0930974FFULL,
		0x62F74CB0096D1728ULL,
		0x5718EAFFEC1F1624ULL,
		0xE930A1B02CB6EC72ULL,
		0xFD0304F49EEAF900ULL,
		0x18450A272177CA72ULL,
		0x25A28C001C99ABCCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x768799338730A070ULL,
		0x522983812612E9FFULL,
		0xC5EE996012DA2E50ULL,
		0xAE31D5FFD83E2C48ULL,
		0xD2614360596DD8E4ULL,
		0xFA0609E93DD5F201ULL,
		0x308A144E42EF94E5ULL,
		0x4B45180039335798ULL
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
		0xC8A65136D1C9E3AFULL,
		0x3073342886E0B026ULL,
		0x05D215FBC970AEC6ULL,
		0xC5EDE745ECCABFB0ULL,
		0xF63571C5F75FE869ULL,
		0x6031F72FC6AFD431ULL,
		0x5703882A86E704D2ULL,
		0x14311043F34DA896ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x914CA26DA393C75EULL,
		0x60E668510DC1604DULL,
		0x0BA42BF792E15D8CULL,
		0x8BDBCE8BD9957F60ULL,
		0xEC6AE38BEEBFD0D3ULL,
		0xC063EE5F8D5FA863ULL,
		0xAE0710550DCE09A4ULL,
		0x28622087E69B512CULL
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
		0x9E58ACA05EC6BA20ULL,
		0x5CC91035796BC960ULL,
		0x1F3BA2AE631CD50BULL,
		0x1EC61CFC0FFF63BAULL,
		0xBB03B0140FBA31A2ULL,
		0x835BE6AD2F420AF8ULL,
		0xC9C9838F287021FFULL,
		0x39A53157F35F3827ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3CB15940BD8D7440ULL,
		0xB992206AF2D792C1ULL,
		0x3E77455CC639AA16ULL,
		0x3D8C39F81FFEC774ULL,
		0x760760281F746344ULL,
		0x06B7CD5A5E8415F1ULL,
		0x9393071E50E043FFULL,
		0x734A62AFE6BE704FULL
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
		0x74AD31BC103D1A25ULL,
		0xD29F086B2E808DF5ULL,
		0x2AE9885C0F8454B6ULL,
		0x802FEB4710BB11B0ULL,
		0xB653010F2A1CE400ULL,
		0x2E5ACDCCA6DB70FBULL,
		0x2E0849BCA450CB01ULL,
		0x1407D207DD71E768ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE95A6378207A344AULL,
		0xA53E10D65D011BEAULL,
		0x55D310B81F08A96DULL,
		0x005FD68E21762360ULL,
		0x6CA6021E5439C801ULL,
		0x5CB59B994DB6E1F7ULL,
		0x5C10937948A19602ULL,
		0x280FA40FBAE3CED0ULL
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
		0x0228E0975F8DBB4AULL,
		0x39C78C3A4A96497DULL,
		0x87A70EBF2A397E24ULL,
		0xDD51CB39171291E8ULL,
		0x51A8C8CFCF3E5FA2ULL,
		0xA7165E15793D7BABULL,
		0x70CECD6A5AF522FAULL,
		0x1E19CCE6C59E91E4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0451C12EBF1B7694ULL,
		0x738F1874952C92FAULL,
		0x0F4E1D7E5472FC48ULL,
		0xBAA396722E2523D1ULL,
		0xA351919F9E7CBF45ULL,
		0x4E2CBC2AF27AF756ULL,
		0xE19D9AD4B5EA45F5ULL,
		0x3C3399CD8B3D23C8ULL
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
		0xBE453686B707E871ULL,
		0x58A8C77D0B661507ULL,
		0xC6F7891664FFF558ULL,
		0xB3F19A7BDA849A92ULL,
		0x528DF6C179812899ULL,
		0xDF6A524F4B759E5AULL,
		0x6A6A3849EF42698DULL,
		0x0F960922ACD6A81AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7C8A6D0D6E0FD0E2ULL,
		0xB1518EFA16CC2A0FULL,
		0x8DEF122CC9FFEAB0ULL,
		0x67E334F7B5093525ULL,
		0xA51BED82F3025133ULL,
		0xBED4A49E96EB3CB4ULL,
		0xD4D47093DE84D31BULL,
		0x1F2C124559AD5034ULL
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
		0xA3D38A9A4E11A120ULL,
		0x9473664B7CE02D7FULL,
		0x7DA41C8F4C736393ULL,
		0x22C7C91AF4020D0CULL,
		0xE86A566BF17BDFA4ULL,
		0x0FF3624E81559FC2ULL,
		0x0187EF6B136D7225ULL,
		0x221D0727FDCFF161ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x47A715349C234240ULL,
		0x28E6CC96F9C05AFFULL,
		0xFB48391E98E6C727ULL,
		0x458F9235E8041A18ULL,
		0xD0D4ACD7E2F7BF48ULL,
		0x1FE6C49D02AB3F85ULL,
		0x030FDED626DAE44AULL,
		0x443A0E4FFB9FE2C2ULL
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
		0xCA283ACE39E77831ULL,
		0x3B1B1188BB9335F8ULL,
		0xBA212DCBEE6394E1ULL,
		0xCB89A649ABCCEB28ULL,
		0x681304B3CB890EB8ULL,
		0x2C3EE380195CCE50ULL,
		0x1CE0EE657CF9B978ULL,
		0x2EDA6CCCF04E77B8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9450759C73CEF062ULL,
		0x7636231177266BF1ULL,
		0x74425B97DCC729C2ULL,
		0x97134C935799D651ULL,
		0xD026096797121D71ULL,
		0x587DC70032B99CA0ULL,
		0x39C1DCCAF9F372F0ULL,
		0x5DB4D999E09CEF70ULL
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
		0xD7C0896752240842ULL,
		0x3B7BCE3D486F1045ULL,
		0xA92ABFE471FA2055ULL,
		0xC9238459D9328471ULL,
		0x4647AE33FA4C6E4FULL,
		0xD17D936925F0C495ULL,
		0x053D1057C0B58B5AULL,
		0x0E065E5EE84FCF1FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF8112CEA4481084ULL,
		0x76F79C7A90DE208BULL,
		0x52557FC8E3F440AAULL,
		0x924708B3B26508E3ULL,
		0x8C8F5C67F498DC9FULL,
		0xA2FB26D24BE1892AULL,
		0x0A7A20AF816B16B5ULL,
		0x1C0CBCBDD09F9E3EULL
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
		0x6426A10C29C2DCC2ULL,
		0x162F86126A5EBF31ULL,
		0xBAD394FD55CFC139ULL,
		0xDC307BAC6C1075D7ULL,
		0xFE18144444F81062ULL,
		0x1839FE79FE034CDDULL,
		0x366CC607218ED806ULL,
		0x18CDF80EE772A105ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC84D42185385B984ULL,
		0x2C5F0C24D4BD7E62ULL,
		0x75A729FAAB9F8272ULL,
		0xB860F758D820EBAFULL,
		0xFC30288889F020C5ULL,
		0x3073FCF3FC0699BBULL,
		0x6CD98C0E431DB00CULL,
		0x319BF01DCEE5420AULL
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
		0x24F284872FBD57E1ULL,
		0x66CEAB93AEE157F1ULL,
		0x52CB498C74452740ULL,
		0x6D8F981B8B14F072ULL,
		0xB2E813B0909D894BULL,
		0x0C09E5F4DEA0F113ULL,
		0xCAFF54E7965AA1D6ULL,
		0x0A11FEB083674A37ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x49E5090E5F7AAFC2ULL,
		0xCD9D57275DC2AFE2ULL,
		0xA5969318E88A4E80ULL,
		0xDB1F30371629E0E4ULL,
		0x65D02761213B1296ULL,
		0x1813CBE9BD41E227ULL,
		0x95FEA9CF2CB543ACULL,
		0x1423FD6106CE946FULL
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
		0xAF4D0CBB8B5C6EA5ULL,
		0x18076B7BAB0A9274ULL,
		0xEAF467465EAFE49AULL,
		0x0D2FA39A7A8A6C92ULL,
		0x6BF87647F5E6DF77ULL,
		0xE4F57EC68677FE20ULL,
		0x2E43B76973619F94ULL,
		0x0BA49E1D617F58F6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5E9A197716B8DD4AULL,
		0x300ED6F7561524E9ULL,
		0xD5E8CE8CBD5FC934ULL,
		0x1A5F4734F514D925ULL,
		0xD7F0EC8FEBCDBEEEULL,
		0xC9EAFD8D0CEFFC40ULL,
		0x5C876ED2E6C33F29ULL,
		0x17493C3AC2FEB1ECULL
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
		0x780F522587A957BAULL,
		0xD2A309F89238BFDCULL,
		0x96DD2D21097ADDDCULL,
		0x1A6F0745AC13A0E5ULL,
		0x5BDBAAA4D05A0491ULL,
		0x9EE53B963B73994CULL,
		0xC51A7E4F2B5C9FBBULL,
		0x33914319ABC29914ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF01EA44B0F52AF74ULL,
		0xA54613F124717FB8ULL,
		0x2DBA5A4212F5BBB9ULL,
		0x34DE0E8B582741CBULL,
		0xB7B75549A0B40922ULL,
		0x3DCA772C76E73298ULL,
		0x8A34FC9E56B93F77ULL,
		0x6722863357853229ULL
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
		0x175A3637C02CC93EULL,
		0xE4D1B02F3659A5E1ULL,
		0xAA524E60E2E36F3DULL,
		0x03F9DDA3462EA5F4ULL,
		0x6AB21CF4EA9409C7ULL,
		0xFC33527C9CEC98ABULL,
		0xF63A516694DE3A47ULL,
		0x3A8A7EF9073553D3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2EB46C6F8059927CULL,
		0xC9A3605E6CB34BC2ULL,
		0x54A49CC1C5C6DE7BULL,
		0x07F3BB468C5D4BE9ULL,
		0xD56439E9D528138EULL,
		0xF866A4F939D93156ULL,
		0xEC74A2CD29BC748FULL,
		0x7514FDF20E6AA7A7ULL
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
		0xC764DBD8579ECED1ULL,
		0x4195B619514D65BEULL,
		0x27AB412B35BF6405ULL,
		0xE1052CE7955572FCULL,
		0x5FBCC00387B96B2AULL,
		0xC6F6271BA4E7F897ULL,
		0x77DC955783170A80ULL,
		0x3399D9FD1B06DD17ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8EC9B7B0AF3D9DA2ULL,
		0x832B6C32A29ACB7DULL,
		0x4F5682566B7EC80AULL,
		0xC20A59CF2AAAE5F8ULL,
		0xBF7980070F72D655ULL,
		0x8DEC4E3749CFF12EULL,
		0xEFB92AAF062E1501ULL,
		0x6733B3FA360DBA2EULL
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
		0xB15ABBECB3223C9CULL,
		0x1A05A362D8C3F066ULL,
		0x2F139885A81CCD7CULL,
		0x064D8DF4F71E9F3CULL,
		0x719D866F08D82D86ULL,
		0x68357BECEB826194ULL,
		0x1CD391A9791DF692ULL,
		0x0BB03097AE32C85BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x62B577D966447938ULL,
		0x340B46C5B187E0CDULL,
		0x5E27310B50399AF8ULL,
		0x0C9B1BE9EE3D3E78ULL,
		0xE33B0CDE11B05B0CULL,
		0xD06AF7D9D704C328ULL,
		0x39A72352F23BED24ULL,
		0x1760612F5C6590B6ULL
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
		0x7B11EF439C6F7BD0ULL,
		0x54892A91E773D7CDULL,
		0x53A3D7E2A6D80784ULL,
		0xD10EA7A5B8F5EA5BULL,
		0x30BA19A564F5DA77ULL,
		0x86811ACA9C2AB591ULL,
		0xA93E94BE07547E31ULL,
		0x0330F96C5DC424FEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF623DE8738DEF7A0ULL,
		0xA9125523CEE7AF9AULL,
		0xA747AFC54DB00F08ULL,
		0xA21D4F4B71EBD4B6ULL,
		0x6174334AC9EBB4EFULL,
		0x0D02359538556B22ULL,
		0x527D297C0EA8FC63ULL,
		0x0661F2D8BB8849FDULL
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
		0x6FEF138D1648F8AAULL,
		0x949C5CFC60B74B6AULL,
		0x590B8C9711026367ULL,
		0x8AA4B681E8A12A74ULL,
		0x929079D19B71DEA4ULL,
		0x14E811E27487C4F7ULL,
		0x87567341D21F2979ULL,
		0x2688E04FA1D1C606ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDFDE271A2C91F154ULL,
		0x2938B9F8C16E96D4ULL,
		0xB217192E2204C6CFULL,
		0x15496D03D14254E8ULL,
		0x2520F3A336E3BD49ULL,
		0x29D023C4E90F89EFULL,
		0x0EACE683A43E52F2ULL,
		0x4D11C09F43A38C0DULL
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
		0xC048513274569662ULL,
		0x195DFE3F278541E2ULL,
		0x211318E1D2E54716ULL,
		0xE3CA7A78CD69E917ULL,
		0x67945F11F8DA10F5ULL,
		0xA6920ECEF29B7ACAULL,
		0x31C7BA586C7A8EB0ULL,
		0x2D06296FD406A142ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8090A264E8AD2CC4ULL,
		0x32BBFC7E4F0A83C5ULL,
		0x422631C3A5CA8E2CULL,
		0xC794F4F19AD3D22EULL,
		0xCF28BE23F1B421EBULL,
		0x4D241D9DE536F594ULL,
		0x638F74B0D8F51D61ULL,
		0x5A0C52DFA80D4284ULL
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
		0x22DEEC79A6DDD05EULL,
		0x55385A8A75278E10ULL,
		0x99272EE6F63E66BBULL,
		0xA82EF36B2C5EEC52ULL,
		0x5ABD8B92128D5A7AULL,
		0xE986C81897F22483ULL,
		0xADB4E7E72FC65F63ULL,
		0x1A4B58C63D2518C6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x45BDD8F34DBBA0BCULL,
		0xAA70B514EA4F1C20ULL,
		0x324E5DCDEC7CCD76ULL,
		0x505DE6D658BDD8A5ULL,
		0xB57B1724251AB4F5ULL,
		0xD30D90312FE44906ULL,
		0x5B69CFCE5F8CBEC7ULL,
		0x3496B18C7A4A318DULL
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
		0x6DABDBEAECCD37CAULL,
		0x45FED3EC56071492ULL,
		0x80B8A2C2FF704B49ULL,
		0x3128DE9234555A42ULL,
		0xA119075B8BCF9FA8ULL,
		0x16FD9A05415B395FULL,
		0x21E52546DF3F9403ULL,
		0x0B7681A3487769B1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDB57B7D5D99A6F94ULL,
		0x8BFDA7D8AC0E2924ULL,
		0x01714585FEE09692ULL,
		0x6251BD2468AAB485ULL,
		0x42320EB7179F3F50ULL,
		0x2DFB340A82B672BFULL,
		0x43CA4A8DBE7F2806ULL,
		0x16ED034690EED362ULL
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
		0x4B404195337AF0C4ULL,
		0x93A73A642B3EA945ULL,
		0x11B0EAC69ABC4A15ULL,
		0x64920D8DC9E2A798ULL,
		0x4960ECF4FF1C7C34ULL,
		0x38D78916DA904957ULL,
		0xD3C03D9A860B2175ULL,
		0x120BDA112278312AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9680832A66F5E188ULL,
		0x274E74C8567D528AULL,
		0x2361D58D3578942BULL,
		0xC9241B1B93C54F30ULL,
		0x92C1D9E9FE38F868ULL,
		0x71AF122DB52092AEULL,
		0xA7807B350C1642EAULL,
		0x2417B42244F06255ULL
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
		0xDD36060076A72491ULL,
		0x15CF3154B93E90EDULL,
		0x581A62E958126E59ULL,
		0x0C31CFD66C4D875FULL,
		0xB7BA2A07BB6B6034ULL,
		0x0AA6057C243C151CULL,
		0x64B3C4454E026869ULL,
		0x2BC7FD82B15E846DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBA6C0C00ED4E4922ULL,
		0x2B9E62A9727D21DBULL,
		0xB034C5D2B024DCB2ULL,
		0x18639FACD89B0EBEULL,
		0x6F74540F76D6C068ULL,
		0x154C0AF848782A39ULL,
		0xC967888A9C04D0D2ULL,
		0x578FFB0562BD08DAULL
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
		0xF0BC47278D68A7AAULL,
		0x163A69D4E1CD02ADULL,
		0xA3E9FB432DAD05F4ULL,
		0x0D1C9375E9CA0534ULL,
		0xDD3407E20516BA8BULL,
		0xE3218D7B2040C0D0ULL,
		0x889A05D4865CCA25ULL,
		0x107784F962B90D91ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE1788E4F1AD14F54ULL,
		0x2C74D3A9C39A055BULL,
		0x47D3F6865B5A0BE8ULL,
		0x1A3926EBD3940A69ULL,
		0xBA680FC40A2D7516ULL,
		0xC6431AF6408181A1ULL,
		0x11340BA90CB9944BULL,
		0x20EF09F2C5721B23ULL
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
		0xE14690BA42179181ULL,
		0x960CD9296FE6874EULL,
		0x69229EB680D9D27FULL,
		0x292F1E4020749E84ULL,
		0x6F4DD7C3ADCE72EFULL,
		0xC276CE21CBCE82A3ULL,
		0xEE5B97B866E4D02FULL,
		0x14D1E25E13E062BBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC28D2174842F2302ULL,
		0x2C19B252DFCD0E9DULL,
		0xD2453D6D01B3A4FFULL,
		0x525E3C8040E93D08ULL,
		0xDE9BAF875B9CE5DEULL,
		0x84ED9C43979D0546ULL,
		0xDCB72F70CDC9A05FULL,
		0x29A3C4BC27C0C577ULL
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
		0xDEC845219B1002A2ULL,
		0xEB6E3C48674A24CFULL,
		0xD023EB3D5320779BULL,
		0x84751A513F23F33CULL,
		0x8625A5FA1FD0B7A5ULL,
		0xAE5C4F86F4E7E342ULL,
		0xE831BE3A60B05A91ULL,
		0x2646FA43F1798D4DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBD908A4336200544ULL,
		0xD6DC7890CE94499FULL,
		0xA047D67AA640EF37ULL,
		0x08EA34A27E47E679ULL,
		0x0C4B4BF43FA16F4BULL,
		0x5CB89F0DE9CFC685ULL,
		0xD0637C74C160B523ULL,
		0x4C8DF487E2F31A9BULL
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
		0xBC7F1E59D060075EULL,
		0x1DF1FD34057E590EULL,
		0xC9F2D5FCEC693F52ULL,
		0xF5BA01EEC55F270BULL,
		0x091E87E9E3ED1C91ULL,
		0xB14DEDF0AB5FD5A4ULL,
		0x9CBDD92BAE7794D2ULL,
		0x3C3D6A54978DBD4DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x78FE3CB3A0C00EBCULL,
		0x3BE3FA680AFCB21DULL,
		0x93E5ABF9D8D27EA4ULL,
		0xEB7403DD8ABE4E17ULL,
		0x123D0FD3C7DA3923ULL,
		0x629BDBE156BFAB48ULL,
		0x397BB2575CEF29A5ULL,
		0x787AD4A92F1B7A9BULL
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
		0x46C622C8D7439AE8ULL,
		0x29E08FE8D789350FULL,
		0x30ED924221DE7E9FULL,
		0x535263EF6409E1F8ULL,
		0xA5E02A4AECF06C7AULL,
		0xE8A190302EE3438FULL,
		0x9F9079B2AC3B0D02ULL,
		0x2466E92E5AAF85B5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8D8C4591AE8735D0ULL,
		0x53C11FD1AF126A1EULL,
		0x61DB248443BCFD3EULL,
		0xA6A4C7DEC813C3F0ULL,
		0x4BC05495D9E0D8F4ULL,
		0xD14320605DC6871FULL,
		0x3F20F36558761A05ULL,
		0x48CDD25CB55F0B6BULL
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
		0x48B6EFC409C14DAAULL,
		0x96FD650222785849ULL,
		0x934929B5866BA24EULL,
		0x2D4E59D448DF166DULL,
		0x90919BC226BBE225ULL,
		0x4BC36EBC9C099917ULL,
		0x92A166952455EE52ULL,
		0x206D03A404765FEAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x916DDF8813829B54ULL,
		0x2DFACA0444F0B092ULL,
		0x2692536B0CD7449DULL,
		0x5A9CB3A891BE2CDBULL,
		0x212337844D77C44AULL,
		0x9786DD793813322FULL,
		0x2542CD2A48ABDCA4ULL,
		0x40DA074808ECBFD5ULL
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
		0x05C25E9D83A377ECULL,
		0xE03C0003780370A8ULL,
		0xB07A128D7AA1E9AEULL,
		0x83750ED78F061AA3ULL,
		0x34B179C18B0FC5A9ULL,
		0x0EBD4CB933B07DE8ULL,
		0x419F3A6FCA371908ULL,
		0x0DE255BA4595427DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0B84BD3B0746EFD8ULL,
		0xC0780006F006E150ULL,
		0x60F4251AF543D35DULL,
		0x06EA1DAF1E0C3547ULL,
		0x6962F383161F8B53ULL,
		0x1D7A99726760FBD0ULL,
		0x833E74DF946E3210ULL,
		0x1BC4AB748B2A84FAULL
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
		0x78894C3180871737ULL,
		0xE2A2FE38741A5D01ULL,
		0xBC1643B53877D88CULL,
		0xDFE0F203B20EFC53ULL,
		0x6C72ACE94776041FULL,
		0x4668418515B7BF6AULL,
		0xA0A4FC59AC873D70ULL,
		0x377A9785EA3268E6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF1129863010E2E6EULL,
		0xC545FC70E834BA02ULL,
		0x782C876A70EFB119ULL,
		0xBFC1E407641DF8A7ULL,
		0xD8E559D28EEC083FULL,
		0x8CD0830A2B6F7ED4ULL,
		0x4149F8B3590E7AE0ULL,
		0x6EF52F0BD464D1CDULL
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
		0x59405C6E1E7DF77AULL,
		0x0D9FDD2CA8DCE2A1ULL,
		0xDED3939A26443F2BULL,
		0xD757D2FF20D05F8FULL,
		0xDEE62366ED906DF1ULL,
		0xC0561E7739966173ULL,
		0xEDD2F498E1CCF565ULL,
		0x084DF87370B257A7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB280B8DC3CFBEEF4ULL,
		0x1B3FBA5951B9C542ULL,
		0xBDA727344C887E56ULL,
		0xAEAFA5FE41A0BF1FULL,
		0xBDCC46CDDB20DBE3ULL,
		0x80AC3CEE732CC2E7ULL,
		0xDBA5E931C399EACBULL,
		0x109BF0E6E164AF4FULL
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
		0x96766217FB89E896ULL,
		0x19E42D82DB82E00DULL,
		0x4B49FE710EA14E8DULL,
		0x0DA35990A66582C1ULL,
		0x0AA715C3353C1EBAULL,
		0x3E7115E6E76AD702ULL,
		0x757AEA3F33943539ULL,
		0x22A3E136482DAB96ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2CECC42FF713D12CULL,
		0x33C85B05B705C01BULL,
		0x9693FCE21D429D1AULL,
		0x1B46B3214CCB0582ULL,
		0x154E2B866A783D74ULL,
		0x7CE22BCDCED5AE04ULL,
		0xEAF5D47E67286A72ULL,
		0x4547C26C905B572CULL
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
		0x49BC114AA2EC4847ULL,
		0x12C3525694E11931ULL,
		0x14934DA03B4F4F70ULL,
		0xF76969596778D767ULL,
		0xB06B445CDE689872ULL,
		0xFBD11096387D5243ULL,
		0xF02DBC29E57DDE5FULL,
		0x187FF3D22B3430F0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9378229545D8908EULL,
		0x2586A4AD29C23262ULL,
		0x29269B40769E9EE0ULL,
		0xEED2D2B2CEF1AECEULL,
		0x60D688B9BCD130E5ULL,
		0xF7A2212C70FAA487ULL,
		0xE05B7853CAFBBCBFULL,
		0x30FFE7A4566861E1ULL
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
		0xF10D2A2A14C8E2B7ULL,
		0xA85F31D4232BB9F8ULL,
		0x4F678B9E0E1318E1ULL,
		0xAED58989A0B6EAFEULL,
		0xBB6B72CB1A7898A7ULL,
		0x62D1FAB0320E0A0AULL,
		0xA2CCDF434B52BB6AULL,
		0x0D48CCC90A14F1E2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE21A54542991C56EULL,
		0x50BE63A8465773F1ULL,
		0x9ECF173C1C2631C3ULL,
		0x5DAB1313416DD5FCULL,
		0x76D6E59634F1314FULL,
		0xC5A3F560641C1415ULL,
		0x4599BE8696A576D4ULL,
		0x1A9199921429E3C5ULL
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
		0x3E08E4F27AC701C5ULL,
		0xD7DBF4F2B9FF8604ULL,
		0x3F411B1F293C8487ULL,
		0x80CBAC71AA96C75EULL,
		0x7EBC57FAAEFD47A5ULL,
		0x46987257B49BE478ULL,
		0x040C1E58A83089BAULL,
		0x25BFA768AC26897FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7C11C9E4F58E038AULL,
		0xAFB7E9E573FF0C08ULL,
		0x7E82363E5279090FULL,
		0x019758E3552D8EBCULL,
		0xFD78AFF55DFA8F4BULL,
		0x8D30E4AF6937C8F0ULL,
		0x08183CB150611374ULL,
		0x4B7F4ED1584D12FEULL
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
		0x78119C52A4F31260ULL,
		0x20D086A011A770C8ULL,
		0x75121DB3CFD8E40EULL,
		0xDCFD1ECAD36B99D1ULL,
		0xF26B28CAB98F44C7ULL,
		0x39393E89DBBE6425ULL,
		0x1FA11B4BD94DAE35ULL,
		0x0308CED4CC140E40ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF02338A549E624C0ULL,
		0x41A10D40234EE190ULL,
		0xEA243B679FB1C81CULL,
		0xB9FA3D95A6D733A2ULL,
		0xE4D65195731E898FULL,
		0x72727D13B77CC84BULL,
		0x3F423697B29B5C6AULL,
		0x06119DA998281C80ULL
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
		0x7EDB8F778F78565DULL,
		0x0A42FD2377A5BCF4ULL,
		0x2719E034CFD69930ULL,
		0xEC696A659A147DCAULL,
		0xD8569E9F8BDF302FULL,
		0x729FD7889F0F5240ULL,
		0xB2DD92B5EA94D8AAULL,
		0x0FC2EAFCDDE63317ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFDB71EEF1EF0ACBAULL,
		0x1485FA46EF4B79E8ULL,
		0x4E33C0699FAD3260ULL,
		0xD8D2D4CB3428FB94ULL,
		0xB0AD3D3F17BE605FULL,
		0xE53FAF113E1EA481ULL,
		0x65BB256BD529B154ULL,
		0x1F85D5F9BBCC662FULL
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
		0xD2199487B137A2EDULL,
		0x01FDCBE1EEF4DB7BULL,
		0x1C319B927ABC897CULL,
		0x8512AF3293A37297ULL,
		0xFBFAD3D3D8CF455DULL,
		0x75F3B66CE960525BULL,
		0xC581483EE4F7A1EDULL,
		0x2F368D819453F65BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA433290F626F45DAULL,
		0x03FB97C3DDE9B6F7ULL,
		0x38633724F57912F8ULL,
		0x0A255E652746E52EULL,
		0xF7F5A7A7B19E8ABBULL,
		0xEBE76CD9D2C0A4B7ULL,
		0x8B02907DC9EF43DAULL,
		0x5E6D1B0328A7ECB7ULL
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
		0xF5FE0B2BF25251DEULL,
		0x26FADBA11D416B32ULL,
		0x7D9FDC2BA93AD39BULL,
		0x0D09B337B8C43B7EULL,
		0x5E0F7DE31EA4E862ULL,
		0x4D826BE68143EBC6ULL,
		0x2AF93A309A48297AULL,
		0x327786CBA976F954ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEBFC1657E4A4A3BCULL,
		0x4DF5B7423A82D665ULL,
		0xFB3FB8575275A736ULL,
		0x1A13666F718876FCULL,
		0xBC1EFBC63D49D0C4ULL,
		0x9B04D7CD0287D78CULL,
		0x55F27461349052F4ULL,
		0x64EF0D9752EDF2A8ULL
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
		0xD35CA88B4C30163CULL,
		0xCE11BF46DAA568FBULL,
		0x75C327E0C7E8DE72ULL,
		0xE303BBD781EDE9E5ULL,
		0xF45B684E116580B4ULL,
		0x124ECA8C7EC0BC61ULL,
		0x0FC007E19E4D1448ULL,
		0x1AE6ADC8BB62A824ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA6B9511698602C78ULL,
		0x9C237E8DB54AD1F7ULL,
		0xEB864FC18FD1BCE5ULL,
		0xC60777AF03DBD3CAULL,
		0xE8B6D09C22CB0169ULL,
		0x249D9518FD8178C3ULL,
		0x1F800FC33C9A2890ULL,
		0x35CD5B9176C55048ULL
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
		0x7453F7EEE4F6CF22ULL,
		0x09C6BAAFA8C85D1EULL,
		0x57F79472A9FB93B7ULL,
		0xE382462E678F35DCULL,
		0xBABF4B8874FB792DULL,
		0x9FA23D9F99138E82ULL,
		0xD8F8C071DE966460ULL,
		0x367E10AB262A1466ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE8A7EFDDC9ED9E44ULL,
		0x138D755F5190BA3CULL,
		0xAFEF28E553F7276EULL,
		0xC7048C5CCF1E6BB8ULL,
		0x757E9710E9F6F25BULL,
		0x3F447B3F32271D05ULL,
		0xB1F180E3BD2CC8C1ULL,
		0x6CFC21564C5428CDULL
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
		0x394D3E6E033E185BULL,
		0x4DD9D78EE96F15E0ULL,
		0x674773005193117EULL,
		0xA3A108F653CE35A1ULL,
		0x09AE0E9E46868E4BULL,
		0xBAB6916C4D00E323ULL,
		0x8A13ACC2D4C8A64BULL,
		0x2A03B186CE8D302BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x729A7CDC067C30B6ULL,
		0x9BB3AF1DD2DE2BC0ULL,
		0xCE8EE600A32622FCULL,
		0x474211ECA79C6B42ULL,
		0x135C1D3C8D0D1C97ULL,
		0x756D22D89A01C646ULL,
		0x14275985A9914C97ULL,
		0x5407630D9D1A6057ULL
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
		0x4C93143F7007DE3BULL,
		0x2348184A45A7CE70ULL,
		0x72233136DE417F1FULL,
		0x48B5EA5D3020263BULL,
		0x2C2E2CD2612A9482ULL,
		0x752C51C28BCD9658ULL,
		0xCAB71328A27A409FULL,
		0x32A9D0AF1E6C9E8CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9926287EE00FBC76ULL,
		0x469030948B4F9CE0ULL,
		0xE446626DBC82FE3EULL,
		0x916BD4BA60404C76ULL,
		0x585C59A4C2552904ULL,
		0xEA58A385179B2CB0ULL,
		0x956E265144F4813EULL,
		0x6553A15E3CD93D19ULL
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
		0x2CDB2641D4752317ULL,
		0xC8841F8D5B2785E0ULL,
		0x15263F9756389308ULL,
		0x939B754B8F84EABBULL,
		0x53FF03AC04208409ULL,
		0xFD5A36FA72777BA5ULL,
		0x352D9F1BE3345FD8ULL,
		0x0B424E02614B18C3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x59B64C83A8EA462EULL,
		0x91083F1AB64F0BC0ULL,
		0x2A4C7F2EAC712611ULL,
		0x2736EA971F09D576ULL,
		0xA7FE075808410813ULL,
		0xFAB46DF4E4EEF74AULL,
		0x6A5B3E37C668BFB1ULL,
		0x16849C04C2963186ULL
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
		0x461B6B0FDC3BFE80ULL,
		0xDD2AAB61B91E9340ULL,
		0xD954E7C56674FE99ULL,
		0xED3D8088D0B3973BULL,
		0x4C3DDEBF57F76EE2ULL,
		0x7443CD7AEC420063ULL,
		0x438F9C7C594860C1ULL,
		0x104C28CDF4C9F959ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8C36D61FB877FD00ULL,
		0xBA5556C3723D2680ULL,
		0xB2A9CF8ACCE9FD33ULL,
		0xDA7B0111A1672E77ULL,
		0x987BBD7EAFEEDDC5ULL,
		0xE8879AF5D88400C6ULL,
		0x871F38F8B290C182ULL,
		0x2098519BE993F2B2ULL
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
		0x736B4A963D5200D3ULL,
		0x82998867AEE6C954ULL,
		0xCCAF04A299A945C8ULL,
		0xD7BC272E6F68F2B4ULL,
		0xD63F0E5D1238BFFFULL,
		0xA3B62CF2EEF0C18AULL,
		0x2ABF8962186FC5D6ULL,
		0x2EDEF73BF3404517ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE6D6952C7AA401A6ULL,
		0x053310CF5DCD92A8ULL,
		0x995E094533528B91ULL,
		0xAF784E5CDED1E569ULL,
		0xAC7E1CBA24717FFFULL,
		0x476C59E5DDE18315ULL,
		0x557F12C430DF8BADULL,
		0x5DBDEE77E6808A2EULL
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
		0x8E40DBEBD3DD981DULL,
		0x3E548CF5317D87DDULL,
		0x4D5A8E48146FF020ULL,
		0x58444ADCC0794CF9ULL,
		0x8B92D2E921F522E1ULL,
		0x5C4518821E2D185AULL,
		0x1A74340ED0F190F6ULL,
		0x29D62243684F27C6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1C81B7D7A7BB303AULL,
		0x7CA919EA62FB0FBBULL,
		0x9AB51C9028DFE040ULL,
		0xB08895B980F299F2ULL,
		0x1725A5D243EA45C2ULL,
		0xB88A31043C5A30B5ULL,
		0x34E8681DA1E321ECULL,
		0x53AC4486D09E4F8CULL
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
		0x33C20D9E8C8DDE43ULL,
		0xC848FA7B1E645520ULL,
		0x6CC25CE204412F54ULL,
		0x2BFD917D416505CAULL,
		0x94A5FE5D8719DCE0ULL,
		0xEF8121E233AE6F2CULL,
		0x0D395DEB2BC58367ULL,
		0x1DD033A8D1CD170DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x67841B3D191BBC86ULL,
		0x9091F4F63CC8AA40ULL,
		0xD984B9C408825EA9ULL,
		0x57FB22FA82CA0B94ULL,
		0x294BFCBB0E33B9C0ULL,
		0xDF0243C4675CDE59ULL,
		0x1A72BBD6578B06CFULL,
		0x3BA06751A39A2E1AULL
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
		0xE5F19136D473C8F1ULL,
		0xEE6C58CEE77B83EAULL,
		0xFF28F32A77B21583ULL,
		0xBEC6FB860FB85F56ULL,
		0x8092A2425A775D57ULL,
		0x85EFCA083A1D9976ULL,
		0x9C54B7F565C82342ULL,
		0x28F22C7F83778FC5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCBE3226DA8E791E2ULL,
		0xDCD8B19DCEF707D5ULL,
		0xFE51E654EF642B07ULL,
		0x7D8DF70C1F70BEADULL,
		0x01254484B4EEBAAFULL,
		0x0BDF9410743B32EDULL,
		0x38A96FEACB904685ULL,
		0x51E458FF06EF1F8BULL
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
		0x247CDAB2993527EBULL,
		0x0C9778E811B48307ULL,
		0x74765CA4321DFCECULL,
		0x434562E7F3C3764CULL,
		0xE7C736641ED03D5FULL,
		0x43813FABAC642898ULL,
		0xC52E1EDC23C4DE9DULL,
		0x2221455BB4438576ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x48F9B565326A4FD6ULL,
		0x192EF1D02369060EULL,
		0xE8ECB948643BF9D8ULL,
		0x868AC5CFE786EC98ULL,
		0xCF8E6CC83DA07ABEULL,
		0x87027F5758C85131ULL,
		0x8A5C3DB84789BD3AULL,
		0x44428AB768870AEDULL
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
		0xD4F1C4190DEA6503ULL,
		0x0490AEAF3E632822ULL,
		0x24B1E0C88B55C696ULL,
		0x5185726EEB88303EULL,
		0x2331FC4B991A051DULL,
		0x9ACFF294CCD710D4ULL,
		0x2A7F5FEEC859DD58ULL,
		0x1DAB7B9F091DFEDBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA9E388321BD4CA06ULL,
		0x09215D5E7CC65045ULL,
		0x4963C19116AB8D2CULL,
		0xA30AE4DDD710607CULL,
		0x4663F89732340A3AULL,
		0x359FE52999AE21A8ULL,
		0x54FEBFDD90B3BAB1ULL,
		0x3B56F73E123BFDB6ULL
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
		0x2B2A3216654733AAULL,
		0x0868B3718182F155ULL,
		0x73814E90939D8B9CULL,
		0xAEB6FD4F10B98117ULL,
		0xC95C8AA9A2ECA309ULL,
		0xAE260B5F340ABC85ULL,
		0xBAAFEA270045E348ULL,
		0x30541775C759D679ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5654642CCA8E6754ULL,
		0x10D166E30305E2AAULL,
		0xE7029D21273B1738ULL,
		0x5D6DFA9E2173022EULL,
		0x92B9155345D94613ULL,
		0x5C4C16BE6815790BULL,
		0x755FD44E008BC691ULL,
		0x60A82EEB8EB3ACF3ULL
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
		0xF45BDAA69486DC76ULL,
		0xE7C86DC49C35F003ULL,
		0x59444CEE130E53FEULL,
		0xE5CD54C4BD9E8BE2ULL,
		0x9A7EB28742D71446ULL,
		0xDFB47C442B839846ULL,
		0x600FCBFE1B6CD5A2ULL,
		0x02D70405D8B728D4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE8B7B54D290DB8ECULL,
		0xCF90DB89386BE007ULL,
		0xB28899DC261CA7FDULL,
		0xCB9AA9897B3D17C4ULL,
		0x34FD650E85AE288DULL,
		0xBF68F8885707308DULL,
		0xC01F97FC36D9AB45ULL,
		0x05AE080BB16E51A8ULL
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
		0xB57DDDB417801233ULL,
		0x54CDCA37F3949F8EULL,
		0xF7E62E1650F2E4C9ULL,
		0x96256490EFD39D8CULL,
		0xB52C4126B2B80E73ULL,
		0x5363A456F02157AFULL,
		0xCB04B53B81286E55ULL,
		0x22622BC7C1B236CCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6AFBBB682F002466ULL,
		0xA99B946FE7293F1DULL,
		0xEFCC5C2CA1E5C992ULL,
		0x2C4AC921DFA73B19ULL,
		0x6A58824D65701CE7ULL,
		0xA6C748ADE042AF5FULL,
		0x96096A770250DCAAULL,
		0x44C4578F83646D99ULL
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
		0xFDE2BF851811BB16ULL,
		0xE8D4D7B3062FAA1CULL,
		0x015C59812C7240E3ULL,
		0x496ECFFEA00775E5ULL,
		0xBA5E4F257A42D51AULL,
		0x7DEDE8D3BA1F4035ULL,
		0xE7071C490031F35AULL,
		0x2F61138E810BE9F4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFBC57F0A3023762CULL,
		0xD1A9AF660C5F5439ULL,
		0x02B8B30258E481C7ULL,
		0x92DD9FFD400EEBCAULL,
		0x74BC9E4AF485AA34ULL,
		0xFBDBD1A7743E806BULL,
		0xCE0E38920063E6B4ULL,
		0x5EC2271D0217D3E9ULL
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
		0x9327340F31C86386ULL,
		0x0FE994740A57CB21ULL,
		0x543AA79BB4D0106AULL,
		0xDA15D3A30CAB85C6ULL,
		0x0542B96995001C6BULL,
		0x127E680A66E907C8ULL,
		0xDC9E2CFD9FA82755ULL,
		0x1B20D95ACF221293ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x264E681E6390C70CULL,
		0x1FD328E814AF9643ULL,
		0xA8754F3769A020D4ULL,
		0xB42BA74619570B8CULL,
		0x0A8572D32A0038D7ULL,
		0x24FCD014CDD20F90ULL,
		0xB93C59FB3F504EAAULL,
		0x3641B2B59E442527ULL
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
		0x4905950838B82DB1ULL,
		0xDB9BD182E39A30C8ULL,
		0x51AFC25D08BB8427ULL,
		0xE5CE765D4545000CULL,
		0x14FC953A725BFA1BULL,
		0xB4CE82ACBC349C48ULL,
		0x54A90E296875CE90ULL,
		0x0081B30D7D3E3B9AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x920B2A1071705B62ULL,
		0xB737A305C7346190ULL,
		0xA35F84BA1177084FULL,
		0xCB9CECBA8A8A0018ULL,
		0x29F92A74E4B7F437ULL,
		0x699D055978693890ULL,
		0xA9521C52D0EB9D21ULL,
		0x0103661AFA7C7734ULL
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
		0x32DCFD05C9115026ULL,
		0xE1629B81CF101532ULL,
		0xAEA1BA638D3456E4ULL,
		0xEADFD254D8BEFA7AULL,
		0x39A8BA4FDD4FAE53ULL,
		0x8227AB41CF63F240ULL,
		0x1E84AA9EC467608FULL,
		0x069D3EED4505258DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x65B9FA0B9222A04CULL,
		0xC2C537039E202A64ULL,
		0x5D4374C71A68ADC9ULL,
		0xD5BFA4A9B17DF4F5ULL,
		0x7351749FBA9F5CA7ULL,
		0x044F56839EC7E480ULL,
		0x3D09553D88CEC11FULL,
		0x0D3A7DDA8A0A4B1AULL
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
		0x930315513BE789A0ULL,
		0xC529128764BD9AA5ULL,
		0x8A7141F065C1CEC6ULL,
		0x6EFA839E74250907ULL,
		0xB413AF9EA5CF0A2DULL,
		0x746613A9398AC3B1ULL,
		0x0F4D393FDB0FD565ULL,
		0x3282CFA74C489945ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x26062AA277CF1340ULL,
		0x8A52250EC97B354BULL,
		0x14E283E0CB839D8DULL,
		0xDDF5073CE84A120FULL,
		0x68275F3D4B9E145AULL,
		0xE8CC275273158763ULL,
		0x1E9A727FB61FAACAULL,
		0x65059F4E9891328AULL
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
		0x651939214826C674ULL,
		0x3B6A1B80A1DFC043ULL,
		0xA28FF8BEB1F125E5ULL,
		0x49530CCFE5709389ULL,
		0xDFC168EE4A83A636ULL,
		0x8BD0043EB82F979BULL,
		0x286C54BE419D7780ULL,
		0x2C897AA46CE566C8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCA327242904D8CE8ULL,
		0x76D4370143BF8086ULL,
		0x451FF17D63E24BCAULL,
		0x92A6199FCAE12713ULL,
		0xBF82D1DC95074C6CULL,
		0x17A0087D705F2F37ULL,
		0x50D8A97C833AEF01ULL,
		0x5912F548D9CACD90ULL
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
		0xF1053257D82A0968ULL,
		0xEF5B9E526E455A72ULL,
		0x5E78433A25B4D2A1ULL,
		0xEFA6856CF6026C0DULL,
		0x50314222EB27FC63ULL,
		0x98D1BC5562BA12C9ULL,
		0x9D646015C56957A3ULL,
		0x0716776962098876ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE20A64AFB05412D0ULL,
		0xDEB73CA4DC8AB4E5ULL,
		0xBCF086744B69A543ULL,
		0xDF4D0AD9EC04D81AULL,
		0xA0628445D64FF8C7ULL,
		0x31A378AAC5742592ULL,
		0x3AC8C02B8AD2AF47ULL,
		0x0E2CEED2C41310EDULL
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
		0x61495821E5A7A337ULL,
		0x71A3B6CE820C77BEULL,
		0x9F423B4A29B57BD6ULL,
		0x71191E658BA2AE18ULL,
		0xF2D8A80CDA3960CBULL,
		0x80E6110F60291591ULL,
		0x5D38469F5C8B7666ULL,
		0x2ADBC8B39415AF47ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC292B043CB4F466EULL,
		0xE3476D9D0418EF7CULL,
		0x3E847694536AF7ACULL,
		0xE2323CCB17455C31ULL,
		0xE5B15019B472C196ULL,
		0x01CC221EC0522B23ULL,
		0xBA708D3EB916ECCDULL,
		0x55B79167282B5E8EULL
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
		0xA0F948DBFA502C84ULL,
		0xD53701C4330C8966ULL,
		0xC9D21205F2223E74ULL,
		0xE86DAEF304BC1DF6ULL,
		0xC36CF50288B80CC6ULL,
		0xA1DDB7BF3AED5D9BULL,
		0x33A598F9AF5C7626ULL,
		0x2B8246804DC67E96ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x41F291B7F4A05908ULL,
		0xAA6E0388661912CDULL,
		0x93A4240BE4447CE9ULL,
		0xD0DB5DE609783BEDULL,
		0x86D9EA051170198DULL,
		0x43BB6F7E75DABB37ULL,
		0x674B31F35EB8EC4DULL,
		0x57048D009B8CFD2CULL
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
		0x70D21DAB93D35CD4ULL,
		0xFC7EAE99AD04608EULL,
		0x0DA24778FFC26E87ULL,
		0xA9C1B673FDA68802ULL,
		0x78C15238808F4A2AULL,
		0xEFB52D18596F7225ULL,
		0xAEA4946193B2E4E2ULL,
		0x01CA92B38B296F6CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE1A43B5727A6B9A8ULL,
		0xF8FD5D335A08C11CULL,
		0x1B448EF1FF84DD0FULL,
		0x53836CE7FB4D1004ULL,
		0xF182A471011E9455ULL,
		0xDF6A5A30B2DEE44AULL,
		0x5D4928C32765C9C5ULL,
		0x039525671652DED9ULL
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
		0xC2ED55FC104737ECULL,
		0x5A413784C04FEA79ULL,
		0x38DE62EAC880D0C5ULL,
		0x507CAFA023FF9934ULL,
		0xA45E75FB2A781D64ULL,
		0x434D48A682E43BEEULL,
		0x9042E226CFCBEC3EULL,
		0x17D598C1DACC51E3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x85DAABF8208E6FD8ULL,
		0xB4826F09809FD4F3ULL,
		0x71BCC5D59101A18AULL,
		0xA0F95F4047FF3268ULL,
		0x48BCEBF654F03AC8ULL,
		0x869A914D05C877DDULL,
		0x2085C44D9F97D87CULL,
		0x2FAB3183B598A3C7ULL
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
		0x7FF87A547B882E6FULL,
		0x2300214FC441E40DULL,
		0xF3C02D3854F50BD4ULL,
		0x31230C59CE0DD5B5ULL,
		0x7C98C68DEBA2F0C8ULL,
		0x3F78166A6E5FC930ULL,
		0xFBB80366E55C6E4BULL,
		0x10153D5AFB66CB21ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFFF0F4A8F7105CDEULL,
		0x4600429F8883C81AULL,
		0xE7805A70A9EA17A8ULL,
		0x624618B39C1BAB6BULL,
		0xF9318D1BD745E190ULL,
		0x7EF02CD4DCBF9260ULL,
		0xF77006CDCAB8DC96ULL,
		0x202A7AB5F6CD9643ULL
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
		0x728713EC05F9360FULL,
		0x3F264274228C1D76ULL,
		0x1E099368BA33E306ULL,
		0x901613741E09AE7EULL,
		0xF8A560E6605FE4DBULL,
		0x359C8BF782B7E23CULL,
		0xB3478CCC7CB4D222ULL,
		0x1A0B08FC8E594241ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE50E27D80BF26C1EULL,
		0x7E4C84E845183AECULL,
		0x3C1326D17467C60CULL,
		0x202C26E83C135CFCULL,
		0xF14AC1CCC0BFC9B7ULL,
		0x6B3917EF056FC479ULL,
		0x668F1998F969A444ULL,
		0x341611F91CB28483ULL
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
		0xAE14AA28DE5D92DCULL,
		0xD4A198F808D6D8B8ULL,
		0x6E4A2981E6AED2C9ULL,
		0xA58572A148355A8CULL,
		0xCC12ECFEEC8F8BFAULL,
		0xD19F17719BB350B7ULL,
		0xA6F7AF96E4F6151DULL,
		0x0A29A68FF8E543F2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5C295451BCBB25B8ULL,
		0xA94331F011ADB171ULL,
		0xDC945303CD5DA593ULL,
		0x4B0AE542906AB518ULL,
		0x9825D9FDD91F17F5ULL,
		0xA33E2EE33766A16FULL,
		0x4DEF5F2DC9EC2A3BULL,
		0x14534D1FF1CA87E5ULL
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
		0x17E9D7D01F9BD89CULL,
		0xEB29BD99C0C22F4FULL,
		0xEA3B1838AB4FB076ULL,
		0xA439189004E707CBULL,
		0xA027892E6B7790F8ULL,
		0x9F0A8669291FDA2DULL,
		0xD2D66BB231301BC6ULL,
		0x29A07BA3338B96FCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2FD3AFA03F37B138ULL,
		0xD6537B3381845E9EULL,
		0xD4763071569F60EDULL,
		0x4872312009CE0F97ULL,
		0x404F125CD6EF21F1ULL,
		0x3E150CD2523FB45BULL,
		0xA5ACD7646260378DULL,
		0x5340F74667172DF9ULL
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
		0xBFBD72DB4BF81FE9ULL,
		0x289E520EE2A98616ULL,
		0x57D46E1559380856ULL,
		0xC62522DD742DE4D9ULL,
		0x102025A689335A3FULL,
		0xC5912B44E8FCD0A8ULL,
		0x44DDBF0933BF7F69ULL,
		0x0F967E4410A009F5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7F7AE5B697F03FD2ULL,
		0x513CA41DC5530C2DULL,
		0xAFA8DC2AB27010ACULL,
		0x8C4A45BAE85BC9B2ULL,
		0x20404B4D1266B47FULL,
		0x8B225689D1F9A150ULL,
		0x89BB7E12677EFED3ULL,
		0x1F2CFC88214013EAULL
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
		0xAF7278B12745514EULL,
		0xC8EBDE7701173733ULL,
		0x078E886131FB75A6ULL,
		0xAB08F87157E463E1ULL,
		0x5CE19040F83C3B0CULL,
		0x5AAE99C824B0D7BFULL,
		0xD9B2C9EE0CE190CDULL,
		0x1BCBB08E77657DFBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5EE4F1624E8AA29CULL,
		0x91D7BCEE022E6E67ULL,
		0x0F1D10C263F6EB4DULL,
		0x5611F0E2AFC8C7C2ULL,
		0xB9C32081F0787619ULL,
		0xB55D33904961AF7EULL,
		0xB36593DC19C3219AULL,
		0x3797611CEECAFBF7ULL
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
		0x17CB4A2A2FF9AD66ULL,
		0x5BD949CC57864BA7ULL,
		0xAEB2664639367ABDULL,
		0x3C8580357039C01FULL,
		0x8F97549EF54F093BULL,
		0xFA5EC15E807D474DULL,
		0xD1EEC5BD44DE6D83ULL,
		0x13A1697F177D08CDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2F9694545FF35ACCULL,
		0xB7B29398AF0C974EULL,
		0x5D64CC8C726CF57AULL,
		0x790B006AE073803FULL,
		0x1F2EA93DEA9E1276ULL,
		0xF4BD82BD00FA8E9BULL,
		0xA3DD8B7A89BCDB07ULL,
		0x2742D2FE2EFA119BULL
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
		0x3C74AFC81685CEA3ULL,
		0xD17D47F4A2B108A4ULL,
		0xFB3AC8ED90D43D0EULL,
		0x8654403634F127A6ULL,
		0xFF8228EAEEDD07DAULL,
		0x922EEBC3ED348626ULL,
		0xF77E2536D471B07EULL,
		0x3738C189AE64835FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x78E95F902D0B9D46ULL,
		0xA2FA8FE945621148ULL,
		0xF67591DB21A87A1DULL,
		0x0CA8806C69E24F4DULL,
		0xFF0451D5DDBA0FB5ULL,
		0x245DD787DA690C4DULL,
		0xEEFC4A6DA8E360FDULL,
		0x6E7183135CC906BFULL
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
		0x3DD6B8965DE8D167ULL,
		0x83A283F1F9C846A7ULL,
		0xABD53DB54B477C58ULL,
		0xABD991E29A62106AULL,
		0x3D55C1E681DEE100ULL,
		0x5C514A90C82B4129ULL,
		0xEFD9CEDD369129D7ULL,
		0x18DAEDE41F487897ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7BAD712CBBD1A2CEULL,
		0x074507E3F3908D4EULL,
		0x57AA7B6A968EF8B1ULL,
		0x57B323C534C420D5ULL,
		0x7AAB83CD03BDC201ULL,
		0xB8A2952190568252ULL,
		0xDFB39DBA6D2253AEULL,
		0x31B5DBC83E90F12FULL
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
		0x698ED5829E01AD8EULL,
		0xC6CA192C1BC577EAULL,
		0x0795230A97693677ULL,
		0x31D04BEA230264FEULL,
		0x69A2874947560E10ULL,
		0x5DEA0463275B3EF0ULL,
		0x66AB7C2FF41438F3ULL,
		0x010EB22F5E1E250BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD31DAB053C035B1CULL,
		0x8D943258378AEFD4ULL,
		0x0F2A46152ED26CEFULL,
		0x63A097D44604C9FCULL,
		0xD3450E928EAC1C20ULL,
		0xBBD408C64EB67DE0ULL,
		0xCD56F85FE82871E6ULL,
		0x021D645EBC3C4A16ULL
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
		0xC979C22D141E4F22ULL,
		0x46CFCFCFE2AED100ULL,
		0xB04D2749D183FC6AULL,
		0x26EEC56CEAD2456DULL,
		0x6DDD6D86802C9D1DULL,
		0x0D85D0AABDB5A119ULL,
		0x6A84D9C4F3DC77CCULL,
		0x14A0A6ADAB4030F7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x92F3845A283C9E44ULL,
		0x8D9F9F9FC55DA201ULL,
		0x609A4E93A307F8D4ULL,
		0x4DDD8AD9D5A48ADBULL,
		0xDBBADB0D00593A3AULL,
		0x1B0BA1557B6B4232ULL,
		0xD509B389E7B8EF98ULL,
		0x29414D5B568061EEULL
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
		0xB226E728049375FCULL,
		0xF8423329A4417402ULL,
		0x9B8FE0F0BABEA585ULL,
		0x060B3600A0C6934AULL,
		0xC7D1ECA5621BF268ULL,
		0x88CA21FB293A0F2EULL,
		0x5F2DDC8CAB6CD364ULL,
		0x0DABCD9F4E3ECCDFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x644DCE500926EBF8ULL,
		0xF08466534882E805ULL,
		0x371FC1E1757D4B0BULL,
		0x0C166C01418D2695ULL,
		0x8FA3D94AC437E4D0ULL,
		0x119443F652741E5DULL,
		0xBE5BB91956D9A6C9ULL,
		0x1B579B3E9C7D99BEULL
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
		0xC034F35B60485761ULL,
		0x1E4E83503A9973EAULL,
		0xCF3F036730A4BD10ULL,
		0x6F5DB8CCC45890A3ULL,
		0x345FEF7EC8A80E43ULL,
		0x1B06C67580E3A1F8ULL,
		0xEF74566724C4FCFEULL,
		0x1569A6FF7E9C497FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8069E6B6C090AEC2ULL,
		0x3C9D06A07532E7D5ULL,
		0x9E7E06CE61497A20ULL,
		0xDEBB719988B12147ULL,
		0x68BFDEFD91501C86ULL,
		0x360D8CEB01C743F0ULL,
		0xDEE8ACCE4989F9FCULL,
		0x2AD34DFEFD3892FFULL
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
		0x40BA33681825E2EFULL,
		0xF326CDB93D78B2B9ULL,
		0xCF69BDB68B2D2B8DULL,
		0x74ACF1B177A24DFEULL,
		0x0004412BD7F072C4ULL,
		0x79A511F7E62B15B3ULL,
		0xD2C05199F1AA46CEULL,
		0x0C556355FBDCB4E8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x817466D0304BC5DEULL,
		0xE64D9B727AF16572ULL,
		0x9ED37B6D165A571BULL,
		0xE959E362EF449BFDULL,
		0x00088257AFE0E588ULL,
		0xF34A23EFCC562B66ULL,
		0xA580A333E3548D9CULL,
		0x18AAC6ABF7B969D1ULL
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
		0x5F26D746843AFB8CULL,
		0xCBF78ED4E4FDF14BULL,
		0xB85940D44A552371ULL,
		0x624C90B314222260ULL,
		0x975726006DC104A2ULL,
		0x2B50B856F1250CA3ULL,
		0x07F1A4AD5585862DULL,
		0x1C9F18B281A837B6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBE4DAE8D0875F718ULL,
		0x97EF1DA9C9FBE296ULL,
		0x70B281A894AA46E3ULL,
		0xC4992166284444C1ULL,
		0x2EAE4C00DB820944ULL,
		0x56A170ADE24A1947ULL,
		0x0FE3495AAB0B0C5AULL,
		0x393E316503506F6CULL
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
		0xE03F16EA7B039616ULL,
		0x4AFCE3C3FDB4046CULL,
		0xC430B5B95792BB81ULL,
		0x24A2F3D765BBC15CULL,
		0x927618D97EE64520ULL,
		0x3307C5F18150CDCCULL,
		0xE956CC494ED04E91ULL,
		0x2512C16082FA01EAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC07E2DD4F6072C2CULL,
		0x95F9C787FB6808D9ULL,
		0x88616B72AF257702ULL,
		0x4945E7AECB7782B9ULL,
		0x24EC31B2FDCC8A40ULL,
		0x660F8BE302A19B99ULL,
		0xD2AD98929DA09D22ULL,
		0x4A2582C105F403D5ULL
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
		0x9924CC52484D800AULL,
		0xE10E388FFEB42A1AULL,
		0x5D98F432ABFA500CULL,
		0x88A1BF2E18529EB5ULL,
		0xF904711C48F16783ULL,
		0x4CA762F9A2B68020ULL,
		0x5C6D9D4210E00A40ULL,
		0x3984D2DA6959844AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x324998A4909B0014ULL,
		0xC21C711FFD685435ULL,
		0xBB31E86557F4A019ULL,
		0x11437E5C30A53D6AULL,
		0xF208E23891E2CF07ULL,
		0x994EC5F3456D0041ULL,
		0xB8DB3A8421C01480ULL,
		0x7309A5B4D2B30894ULL
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
		0x0B590B80F9D2866DULL,
		0x58417EE033DFE335ULL,
		0x82E1DAA30C85F9E4ULL,
		0xB3F041D0015D6692ULL,
		0x2BDF26D03810D3DBULL,
		0x1F770E7B04B8882FULL,
		0x678998C9F59D4168ULL,
		0x0E79A72DA8C642BFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x16B21701F3A50CDAULL,
		0xB082FDC067BFC66AULL,
		0x05C3B546190BF3C8ULL,
		0x67E083A002BACD25ULL,
		0x57BE4DA07021A7B7ULL,
		0x3EEE1CF60971105EULL,
		0xCF133193EB3A82D0ULL,
		0x1CF34E5B518C857EULL
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
		0xC3F795A043FE27B5ULL,
		0x6B64F0058AEE8343ULL,
		0x5A92C91AA2137978ULL,
		0x259B1A7850DC1574ULL,
		0x4B455F33D7CCC4CBULL,
		0xC17CA2EC8B6B1472ULL,
		0x1FF8379C9EB710C5ULL,
		0x233D45AE3CE2E52CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x87EF2B4087FC4F6AULL,
		0xD6C9E00B15DD0687ULL,
		0xB52592354426F2F0ULL,
		0x4B3634F0A1B82AE8ULL,
		0x968ABE67AF998996ULL,
		0x82F945D916D628E4ULL,
		0x3FF06F393D6E218BULL,
		0x467A8B5C79C5CA58ULL
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
		0x2BD5BA57CE66F2C8ULL,
		0xB96E7ADC1288E34EULL,
		0x12D81EF7F18DB48AULL,
		0xDDD96F567E1DEAEAULL,
		0x6BEB1C791A676672ULL,
		0x700D7CEF02992093ULL,
		0x2A63B928B33F3B11ULL,
		0x37B0A7FEB538827CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x57AB74AF9CCDE590ULL,
		0x72DCF5B82511C69CULL,
		0x25B03DEFE31B6915ULL,
		0xBBB2DEACFC3BD5D4ULL,
		0xD7D638F234CECCE5ULL,
		0xE01AF9DE05324126ULL,
		0x54C77251667E7622ULL,
		0x6F614FFD6A7104F8ULL
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
		0xB31E3CEDE66B53ACULL,
		0x0D2A338F71B30966ULL,
		0x60C1E1C587896535ULL,
		0x586C07EC2CC86B2EULL,
		0xFB9EEC17CE45F274ULL,
		0x1C6FD196F0C1702DULL,
		0x16F5A945F15E83ECULL,
		0x128D4770D2615A34ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x663C79DBCCD6A758ULL,
		0x1A54671EE36612CDULL,
		0xC183C38B0F12CA6AULL,
		0xB0D80FD85990D65CULL,
		0xF73DD82F9C8BE4E8ULL,
		0x38DFA32DE182E05BULL,
		0x2DEB528BE2BD07D8ULL,
		0x251A8EE1A4C2B468ULL
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
		0x30ECF17C8D515EECULL,
		0x05AE4C4BD8140965ULL,
		0x9DF01C3474F9EA82ULL,
		0xD6BC4ECEDE4E3C30ULL,
		0x8EDF690EF1C8AFA2ULL,
		0x63F750928C411A7BULL,
		0xC900965D04B2657DULL,
		0x02B4C818BD2500F0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x61D9E2F91AA2BDD8ULL,
		0x0B5C9897B02812CAULL,
		0x3BE03868E9F3D504ULL,
		0xAD789D9DBC9C7861ULL,
		0x1DBED21DE3915F45ULL,
		0xC7EEA125188234F7ULL,
		0x92012CBA0964CAFAULL,
		0x056990317A4A01E1ULL
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
		0x047E79C391E4F835ULL,
		0xA8E2D1D2CED04642ULL,
		0xFE3A45074B48FB41ULL,
		0xA10946E7DB24D20BULL,
		0xFA689FD0E17577AEULL,
		0xEA3CEAE0B55FCA73ULL,
		0x723EFC203A67B05AULL,
		0x1DF94164C351955EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x08FCF38723C9F06AULL,
		0x51C5A3A59DA08C84ULL,
		0xFC748A0E9691F683ULL,
		0x42128DCFB649A417ULL,
		0xF4D13FA1C2EAEF5DULL,
		0xD479D5C16ABF94E7ULL,
		0xE47DF84074CF60B5ULL,
		0x3BF282C986A32ABCULL
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
		0xB9F24A0CB5612DACULL,
		0xABF8B54CF80CA8A5ULL,
		0x4C1C3F0B59966051ULL,
		0x1863100056A25CE4ULL,
		0xEA87C25612D9E4D3ULL,
		0x6412A1BE7442BDEBULL,
		0x2E99F1334D4D0930ULL,
		0x3C594DB43BE1D7C6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x73E494196AC25B58ULL,
		0x57F16A99F019514BULL,
		0x98387E16B32CC0A3ULL,
		0x30C62000AD44B9C8ULL,
		0xD50F84AC25B3C9A6ULL,
		0xC825437CE8857BD7ULL,
		0x5D33E2669A9A1260ULL,
		0x78B29B6877C3AF8CULL
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
		0xECD3F6E5E0FACC69ULL,
		0x10DC8CF300AF0BD6ULL,
		0xCF5DEA1278226389ULL,
		0x824558BFC8D3ABC6ULL,
		0x918E47436F84EB38ULL,
		0xC67B2AAF6C68141EULL,
		0xF63C68B595668550ULL,
		0x102674A815CE7A12ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD9A7EDCBC1F598D2ULL,
		0x21B919E6015E17ADULL,
		0x9EBBD424F044C712ULL,
		0x048AB17F91A7578DULL,
		0x231C8E86DF09D671ULL,
		0x8CF6555ED8D0283DULL,
		0xEC78D16B2ACD0AA1ULL,
		0x204CE9502B9CF425ULL
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
		0x27BBC35AE9A6D062ULL,
		0x6A23C52D61CEB612ULL,
		0xF5BE1BE851FA6AE7ULL,
		0xB7015AFADC4EBC92ULL,
		0xC60293F8C0E1429DULL,
		0x441D7E05787AD93EULL,
		0x0D50696A6690D2FAULL,
		0x25723569AB97AA24ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4F7786B5D34DA0C4ULL,
		0xD4478A5AC39D6C24ULL,
		0xEB7C37D0A3F4D5CEULL,
		0x6E02B5F5B89D7925ULL,
		0x8C0527F181C2853BULL,
		0x883AFC0AF0F5B27DULL,
		0x1AA0D2D4CD21A5F4ULL,
		0x4AE46AD3572F5448ULL
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
		0x325579C25F84437EULL,
		0xE7D5E5117B81D7E6ULL,
		0xFBD710BB7FE9FC33ULL,
		0x22BCF26652D76B6DULL,
		0xFFD7ABDAAE338061ULL,
		0x2D3222D959220D8EULL,
		0x0D89C4D768CD4CE4ULL,
		0x05D82BCF97D8DCA3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x64AAF384BF0886FCULL,
		0xCFABCA22F703AFCCULL,
		0xF7AE2176FFD3F867ULL,
		0x4579E4CCA5AED6DBULL,
		0xFFAF57B55C6700C2ULL,
		0x5A6445B2B2441B1DULL,
		0x1B1389AED19A99C8ULL,
		0x0BB0579F2FB1B946ULL
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
		0x5FB9BD0A590D4E05ULL,
		0x9C5E73825FF337E8ULL,
		0x61AABFF82D37AD75ULL,
		0x87542CBDB0AFCCDEULL,
		0x1A567FD980F4A127ULL,
		0xC723743F96C430ECULL,
		0x6ADDC897E34D93CDULL,
		0x2A96C7DCA999EB8EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBF737A14B21A9C0AULL,
		0x38BCE704BFE66FD0ULL,
		0xC3557FF05A6F5AEBULL,
		0x0EA8597B615F99BCULL,
		0x34ACFFB301E9424FULL,
		0x8E46E87F2D8861D8ULL,
		0xD5BB912FC69B279BULL,
		0x552D8FB95333D71CULL
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
		0xFE93F0F95B2BFB94ULL,
		0xAAFC8802C3E373F1ULL,
		0x185D19915F705B71ULL,
		0xFD29DEA25DDB8CCDULL,
		0xC7C38D419A9A143DULL,
		0xDDA48490A6BA325AULL,
		0x926F9D2AE6F31DE4ULL,
		0x20344B32BD010C67ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFD27E1F2B657F728ULL,
		0x55F9100587C6E7E3ULL,
		0x30BA3322BEE0B6E3ULL,
		0xFA53BD44BBB7199AULL,
		0x8F871A833534287BULL,
		0xBB4909214D7464B5ULL,
		0x24DF3A55CDE63BC9ULL,
		0x406896657A0218CFULL
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
		0xCE9378EB6B04D33AULL,
		0x5124D7B0D0D1E025ULL,
		0x9CEF3305D4A747C6ULL,
		0x3540D7609C876D4EULL,
		0x0B894969A6B8080EULL,
		0x625F4F913522C4BDULL,
		0x3B8A525E47CF54DAULL,
		0x2BFA48B4178C4336ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9D26F1D6D609A674ULL,
		0xA249AF61A1A3C04BULL,
		0x39DE660BA94E8F8CULL,
		0x6A81AEC1390EDA9DULL,
		0x171292D34D70101CULL,
		0xC4BE9F226A45897AULL,
		0x7714A4BC8F9EA9B4ULL,
		0x57F491682F18866CULL
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
		0x8D6BDAD0DF7BA76FULL,
		0xF53F995BCD3FB96FULL,
		0x6403F15924060581ULL,
		0x73D14149363A6355ULL,
		0x1BE663F3C2DFBAA1ULL,
		0xD04D7FE37F0190C9ULL,
		0x098CADC4B2028E9CULL,
		0x188C2FD1F3ACF368ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1AD7B5A1BEF74EDEULL,
		0xEA7F32B79A7F72DFULL,
		0xC807E2B2480C0B03ULL,
		0xE7A282926C74C6AAULL,
		0x37CCC7E785BF7542ULL,
		0xA09AFFC6FE032192ULL,
		0x13195B8964051D39ULL,
		0x31185FA3E759E6D0ULL
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
		0x243B6CA0F84FA013ULL,
		0x5370DE518BB980E7ULL,
		0x832F9C63E749A8A1ULL,
		0x968853E779F49A3CULL,
		0x5568F7536E9B47A6ULL,
		0x6BC60A65CB71EA14ULL,
		0xCA94C58B8DEA3402ULL,
		0x04B6B3D585F8EB45ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4876D941F09F4026ULL,
		0xA6E1BCA3177301CEULL,
		0x065F38C7CE935142ULL,
		0x2D10A7CEF3E93479ULL,
		0xAAD1EEA6DD368F4DULL,
		0xD78C14CB96E3D428ULL,
		0x95298B171BD46804ULL,
		0x096D67AB0BF1D68BULL
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
		0x165F191516A4580AULL,
		0x4353A1C5EC53697FULL,
		0xF2BD16D05F418F72ULL,
		0x7AA65E334FB3BD20ULL,
		0x9B58C0F56DD8F44CULL,
		0xE9158667E589D46DULL,
		0xCAAFA1A1F54F018EULL,
		0x36A5A0FE5A29D2FFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2CBE322A2D48B014ULL,
		0x86A7438BD8A6D2FEULL,
		0xE57A2DA0BE831EE4ULL,
		0xF54CBC669F677A41ULL,
		0x36B181EADBB1E898ULL,
		0xD22B0CCFCB13A8DBULL,
		0x955F4343EA9E031DULL,
		0x6D4B41FCB453A5FFULL
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
		0x22B21BA213B24834ULL,
		0xB0B02DF1901B9AE7ULL,
		0xA33F8F0952A8BC0FULL,
		0x768EBFC8DD21E842ULL,
		0xD8947B809D6FD715ULL,
		0x1BD88C2E99495D97ULL,
		0xC6DDF33A69EE3AEAULL,
		0x019DE10E7B2B992AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4564374427649068ULL,
		0x61605BE3203735CEULL,
		0x467F1E12A551781FULL,
		0xED1D7F91BA43D085ULL,
		0xB128F7013ADFAE2AULL,
		0x37B1185D3292BB2FULL,
		0x8DBBE674D3DC75D4ULL,
		0x033BC21CF6573255ULL
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
		0xC3FDB2B5EE31DFFEULL,
		0x1FB2713CC3F62B76ULL,
		0xA90356CC4A0301F8ULL,
		0xCA4D68D89EE59C37ULL,
		0xD04668FE5D884C00ULL,
		0x81529BC4B7A11C26ULL,
		0x634774FF23AA7DF5ULL,
		0x1D3F6BD8B992EC79ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x87FB656BDC63BFFCULL,
		0x3F64E27987EC56EDULL,
		0x5206AD98940603F0ULL,
		0x949AD1B13DCB386FULL,
		0xA08CD1FCBB109801ULL,
		0x02A537896F42384DULL,
		0xC68EE9FE4754FBEBULL,
		0x3A7ED7B17325D8F2ULL
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
		0x9DFDDA4468152A04ULL,
		0xB3FFA55A6D3FE8D1ULL,
		0x0053450C4524138AULL,
		0x3B7BB649C7E50041ULL,
		0xA0AB34CDA5C074E5ULL,
		0xED1449375795EED6ULL,
		0x70BE25ACCA77048CULL,
		0x04C06E34E6C7F0D4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3BFBB488D02A5408ULL,
		0x67FF4AB4DA7FD1A3ULL,
		0x00A68A188A482715ULL,
		0x76F76C938FCA0082ULL,
		0x4156699B4B80E9CAULL,
		0xDA28926EAF2BDDADULL,
		0xE17C4B5994EE0919ULL,
		0x0980DC69CD8FE1A8ULL
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
		0x55AA3141F7DAE590ULL,
		0xCBD7078E7AE0A668ULL,
		0xED3781DEB00378A4ULL,
		0xDB2EF02C52C41D2FULL,
		0xDFD5E7EE190F9F2FULL,
		0xCAED0FF0A6622D90ULL,
		0x214F8044A29E47E5ULL,
		0x1F85055541581838ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAB546283EFB5CB20ULL,
		0x97AE0F1CF5C14CD0ULL,
		0xDA6F03BD6006F149ULL,
		0xB65DE058A5883A5FULL,
		0xBFABCFDC321F3E5FULL,
		0x95DA1FE14CC45B21ULL,
		0x429F0089453C8FCBULL,
		0x3F0A0AAA82B03070ULL
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
		0x8237246997255520ULL,
		0x604D4D9C6C032A2AULL,
		0x1CB067B6ADB76915ULL,
		0xC653D2E496F58187ULL,
		0x0657322FB466A711ULL,
		0xCEF9B25CF494BD07ULL,
		0x94B54A85CECFE4A0ULL,
		0x37550F302AC30340ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x046E48D32E4AAA40ULL,
		0xC09A9B38D8065455ULL,
		0x3960CF6D5B6ED22AULL,
		0x8CA7A5C92DEB030EULL,
		0x0CAE645F68CD4E23ULL,
		0x9DF364B9E9297A0EULL,
		0x296A950B9D9FC941ULL,
		0x6EAA1E6055860681ULL
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
		0x903C0884E8AE03DDULL,
		0x46AB8DCF58DF1C7EULL,
		0x830F6652250BE7BDULL,
		0x44621BE4D1A5ACB2ULL,
		0x4F612708FC4624EBULL,
		0x8A7D99E951732841ULL,
		0x9E859A44E3CDE001ULL,
		0x2C62E55B783C0BD7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x20781109D15C07BAULL,
		0x8D571B9EB1BE38FDULL,
		0x061ECCA44A17CF7AULL,
		0x88C437C9A34B5965ULL,
		0x9EC24E11F88C49D6ULL,
		0x14FB33D2A2E65082ULL,
		0x3D0B3489C79BC003ULL,
		0x58C5CAB6F07817AFULL
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
		0x16CBF51DF0A03347ULL,
		0x0EFE7E80D3ED7633ULL,
		0x99B57697B56B9F0AULL,
		0xC906F4814AB9BC0AULL,
		0xC2278ED21337D316ULL,
		0x2ECDC2D1731DDF6EULL,
		0xF74DFC0FC3E4EC45ULL,
		0x341C062E001A60FAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2D97EA3BE140668EULL,
		0x1DFCFD01A7DAEC66ULL,
		0x336AED2F6AD73E14ULL,
		0x920DE90295737815ULL,
		0x844F1DA4266FA62DULL,
		0x5D9B85A2E63BBEDDULL,
		0xEE9BF81F87C9D88AULL,
		0x68380C5C0034C1F5ULL
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
		0x05FCDE1419889ABAULL,
		0xE25FEA4D117B4A5DULL,
		0x4692715CDC9665CEULL,
		0x20DAF1D032DD62E2ULL,
		0x10189ED63669483AULL,
		0xA50285EA57F15D34ULL,
		0x90E40F9D7CC97E53ULL,
		0x0D66FE7596D59954ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0BF9BC2833113574ULL,
		0xC4BFD49A22F694BAULL,
		0x8D24E2B9B92CCB9DULL,
		0x41B5E3A065BAC5C4ULL,
		0x20313DAC6CD29074ULL,
		0x4A050BD4AFE2BA68ULL,
		0x21C81F3AF992FCA7ULL,
		0x1ACDFCEB2DAB32A9ULL
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
		0x8428B4592C82C503ULL,
		0xA43F89318A262A87ULL,
		0xC144610C36489ABFULL,
		0xCDF45969A0B6A158ULL,
		0xD22D8EDA2965BEB6ULL,
		0xAC05B40B825EF9F4ULL,
		0x59CCED0BDFDDA56EULL,
		0x3BB87DB4D2D53C48ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x085168B259058A06ULL,
		0x487F1263144C550FULL,
		0x8288C2186C91357FULL,
		0x9BE8B2D3416D42B1ULL,
		0xA45B1DB452CB7D6DULL,
		0x580B681704BDF3E9ULL,
		0xB399DA17BFBB4ADDULL,
		0x7770FB69A5AA7890ULL
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
		0x8DB045B25CC6F1CDULL,
		0x880F0B4F092C558FULL,
		0xCC64CFE9EFEC9D34ULL,
		0x02EF750DFD0AB5F9ULL,
		0x93AC4FE5DD2844D6ULL,
		0x8BEDAE6C8F64DA24ULL,
		0x870727F332FC2B04ULL,
		0x2333EC5A835ACCB0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1B608B64B98DE39AULL,
		0x101E169E1258AB1FULL,
		0x98C99FD3DFD93A69ULL,
		0x05DEEA1BFA156BF3ULL,
		0x27589FCBBA5089ACULL,
		0x17DB5CD91EC9B449ULL,
		0x0E0E4FE665F85609ULL,
		0x4667D8B506B59961ULL
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
		0x504AC56B8731AEAEULL,
		0x7F01087E0714096EULL,
		0x8C817F58AFC4F007ULL,
		0x07F0F3EA5F3B089DULL,
		0x70A626CDD1198C66ULL,
		0xAC1107AEE815B06CULL,
		0xB9C2616236889CB6ULL,
		0x1146BF781BFD7EB2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA0958AD70E635D5CULL,
		0xFE0210FC0E2812DCULL,
		0x1902FEB15F89E00EULL,
		0x0FE1E7D4BE76113BULL,
		0xE14C4D9BA23318CCULL,
		0x58220F5DD02B60D8ULL,
		0x7384C2C46D11396DULL,
		0x228D7EF037FAFD65ULL
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
		0xB0CAACDCC1B23C26ULL,
		0xCFB7BEF9F3A827EFULL,
		0x10466474F876E3D6ULL,
		0x05DFBAFF60E7D9B4ULL,
		0x5FABC7F10DC8A1DEULL,
		0xD035FFE8B67C4F53ULL,
		0x757CFF8E58FD6C74ULL,
		0x3A3A9BDA359BA3E6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x619559B98364784CULL,
		0x9F6F7DF3E7504FDFULL,
		0x208CC8E9F0EDC7ADULL,
		0x0BBF75FEC1CFB368ULL,
		0xBF578FE21B9143BCULL,
		0xA06BFFD16CF89EA6ULL,
		0xEAF9FF1CB1FAD8E9ULL,
		0x747537B46B3747CCULL
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
		0x3C2B2B634050B916ULL,
		0x59E75B482F824F34ULL,
		0x648B71639D801CBBULL,
		0x31F9CA709182B92EULL,
		0x2601BFA188B78CB1ULL,
		0x6AC480A25A3D4F6EULL,
		0xB08936E34C56F87FULL,
		0x331155087626363AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x785656C680A1722CULL,
		0xB3CEB6905F049E68ULL,
		0xC916E2C73B003976ULL,
		0x63F394E12305725CULL,
		0x4C037F43116F1962ULL,
		0xD5890144B47A9EDCULL,
		0x61126DC698ADF0FEULL,
		0x6622AA10EC4C6C75ULL
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
		0x19A05C57AD3C4C02ULL,
		0xD307DC76BA8BC11DULL,
		0x42C2265F0FB599F7ULL,
		0x01A3EAF5059E1D2EULL,
		0xDC53BFAD2AB46BD7ULL,
		0x031FA085329CAED0ULL,
		0x487F4FBAAB4DD8C4ULL,
		0x37A5934D407EA4FAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3340B8AF5A789804ULL,
		0xA60FB8ED7517823AULL,
		0x85844CBE1F6B33EFULL,
		0x0347D5EA0B3C3A5CULL,
		0xB8A77F5A5568D7AEULL,
		0x063F410A65395DA1ULL,
		0x90FE9F75569BB188ULL,
		0x6F4B269A80FD49F4ULL
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
		0xB5F2C0234F1B56B4ULL,
		0xEFABC0364A644743ULL,
		0x1FDE9EEFB2CF3154ULL,
		0x39AABBB49E73BECBULL,
		0xBD63F44A6DCB572DULL,
		0x38E485C7D5128DA4ULL,
		0x8971C232C010EFF4ULL,
		0x360681D66248E0E7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6BE580469E36AD68ULL,
		0xDF57806C94C88E87ULL,
		0x3FBD3DDF659E62A9ULL,
		0x735577693CE77D96ULL,
		0x7AC7E894DB96AE5AULL,
		0x71C90B8FAA251B49ULL,
		0x12E384658021DFE8ULL,
		0x6C0D03ACC491C1CFULL
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
		0xDA8D6D0E24172171ULL,
		0x3C33FEA1577274FCULL,
		0x3437F850D2563E68ULL,
		0x07034C1A743F2D90ULL,
		0x091EBE93B8607444ULL,
		0xE068C94A172C324CULL,
		0xBE80F3618DA28C05ULL,
		0x1F4999819A4E60D2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB51ADA1C482E42E2ULL,
		0x7867FD42AEE4E9F9ULL,
		0x686FF0A1A4AC7CD0ULL,
		0x0E069834E87E5B20ULL,
		0x123D7D2770C0E888ULL,
		0xC0D192942E586498ULL,
		0x7D01E6C31B45180BULL,
		0x3E933303349CC1A5ULL
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
		0x1F802CA14397B832ULL,
		0x6EB11A611A2D46E8ULL,
		0xA8E8B208F8951233ULL,
		0x91CAE8F3FC57C51BULL,
		0x2B8F3428191E312EULL,
		0x85FFE0FE17E90448ULL,
		0xA9F120D51057D549ULL,
		0x0CC3587D3D6DEA6AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3F005942872F7064ULL,
		0xDD6234C2345A8DD0ULL,
		0x51D16411F12A2466ULL,
		0x2395D1E7F8AF8A37ULL,
		0x571E6850323C625DULL,
		0x0BFFC1FC2FD20890ULL,
		0x53E241AA20AFAA93ULL,
		0x1986B0FA7ADBD4D5ULL
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
		0x51B93702B5A0EC32ULL,
		0x35F80D44E5213ACDULL,
		0x63EA541E371E3B6CULL,
		0x01CD98208EBD38DCULL,
		0x2ED1589A5D66E26BULL,
		0x71E6B40A8E746197ULL,
		0xC55CDBBECE2877F2ULL,
		0x31D8F42A2305DD60ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA3726E056B41D864ULL,
		0x6BF01A89CA42759AULL,
		0xC7D4A83C6E3C76D8ULL,
		0x039B30411D7A71B8ULL,
		0x5DA2B134BACDC4D6ULL,
		0xE3CD68151CE8C32EULL,
		0x8AB9B77D9C50EFE4ULL,
		0x63B1E854460BBAC1ULL
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
		0x16903725FA2082B4ULL,
		0x1BD49789006C8D20ULL,
		0x1EB5FE5405876098ULL,
		0x4FF977F2AB97CA27ULL,
		0x3E141B5F82378963ULL,
		0x2ACA7ED4F0C24753ULL,
		0x3B6144DFB61C9129ULL,
		0x1EC0F5DA32F5EF94ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2D206E4BF4410568ULL,
		0x37A92F1200D91A40ULL,
		0x3D6BFCA80B0EC130ULL,
		0x9FF2EFE5572F944EULL,
		0x7C2836BF046F12C6ULL,
		0x5594FDA9E1848EA6ULL,
		0x76C289BF6C392252ULL,
		0x3D81EBB465EBDF28ULL
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
		0x573C1B0C92290B01ULL,
		0x3DE436E5D7731AF0ULL,
		0xB3DB0B346FA3E955ULL,
		0xD1786074B1BBE2C6ULL,
		0x2826288EF15512D1ULL,
		0xCF303C644FCFFB40ULL,
		0xC775B84609096C46ULL,
		0x1906A30DE3A723DEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAE78361924521602ULL,
		0x7BC86DCBAEE635E0ULL,
		0x67B61668DF47D2AAULL,
		0xA2F0C0E96377C58DULL,
		0x504C511DE2AA25A3ULL,
		0x9E6078C89F9FF680ULL,
		0x8EEB708C1212D88DULL,
		0x320D461BC74E47BDULL
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
		0xC475DDFF71C7C013ULL,
		0xB0B3C2B1F355A6C7ULL,
		0xBA7C27E32312AAC3ULL,
		0x9062B868ABFA1BD1ULL,
		0xDCCCEC2BC32461D0ULL,
		0xD3D47B8812FEBBBEULL,
		0xB66B4594B3E3344BULL,
		0x096C890E95ACC6A2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x88EBBBFEE38F8026ULL,
		0x61678563E6AB4D8FULL,
		0x74F84FC646255587ULL,
		0x20C570D157F437A3ULL,
		0xB999D8578648C3A1ULL,
		0xA7A8F71025FD777DULL,
		0x6CD68B2967C66897ULL,
		0x12D9121D2B598D45ULL
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
		0x54DA080AE966A0FEULL,
		0x71F2EED66FA4C7B8ULL,
		0x0CCF78E033E19C89ULL,
		0xB65B56714846753DULL,
		0x32E4A569592A7990ULL,
		0x0A95D59EB770A9EBULL,
		0x5896CE0E12993531ULL,
		0x13B4E7E627DB1195ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA9B41015D2CD41FCULL,
		0xE3E5DDACDF498F70ULL,
		0x199EF1C067C33912ULL,
		0x6CB6ACE2908CEA7AULL,
		0x65C94AD2B254F321ULL,
		0x152BAB3D6EE153D6ULL,
		0xB12D9C1C25326A62ULL,
		0x2769CFCC4FB6232AULL
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
		0x5AE2ED4283105AADULL,
		0xD2062E12E13A28D3ULL,
		0x438D5CFD1ED1B64DULL,
		0xD7D2808F7D9BE512ULL,
		0xD2F93D84C6C13203ULL,
		0xB91B8195B0945F90ULL,
		0xE4D52A581FB29998ULL,
		0x314743B6A03AE23BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB5C5DA850620B55AULL,
		0xA40C5C25C27451A6ULL,
		0x871AB9FA3DA36C9BULL,
		0xAFA5011EFB37CA24ULL,
		0xA5F27B098D826407ULL,
		0x7237032B6128BF21ULL,
		0xC9AA54B03F653331ULL,
		0x628E876D4075C477ULL
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
		0x836F7A0E6527331AULL,
		0x2608D6156D708B07ULL,
		0xE02418A6FA3954D4ULL,
		0x652451E03BE45823ULL,
		0xDC6499623FCF9999ULL,
		0xBEADC3F0153048E0ULL,
		0x7873276FBB8F38F1ULL,
		0x16552BE027000838ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x06DEF41CCA4E6634ULL,
		0x4C11AC2ADAE1160FULL,
		0xC048314DF472A9A8ULL,
		0xCA48A3C077C8B047ULL,
		0xB8C932C47F9F3332ULL,
		0x7D5B87E02A6091C1ULL,
		0xF0E64EDF771E71E3ULL,
		0x2CAA57C04E001070ULL
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
		0xE4B9F9B4944184CCULL,
		0xC302BF1550ED1346ULL,
		0x50226CC25FCCC4D5ULL,
		0x92811E830A01D931ULL,
		0x913E884829D65D35ULL,
		0x7EC264249C9D45E1ULL,
		0xBDDBD515138DEBFFULL,
		0x1F85E69E7FD53D94ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC973F36928830998ULL,
		0x86057E2AA1DA268DULL,
		0xA044D984BF9989ABULL,
		0x25023D061403B262ULL,
		0x227D109053ACBA6BULL,
		0xFD84C849393A8BC3ULL,
		0x7BB7AA2A271BD7FEULL,
		0x3F0BCD3CFFAA7B29ULL
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
		0x4927B5BB6170A79FULL,
		0x5EE9128D36CB1FDEULL,
		0x80106DBE9E234F4FULL,
		0x1922A67FA2410194ULL,
		0xD1219DD619C430DCULL,
		0x9035AD870767E66EULL,
		0xBD1983DA200E6DC0ULL,
		0x2807FAB555716F94ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x924F6B76C2E14F3EULL,
		0xBDD2251A6D963FBCULL,
		0x0020DB7D3C469E9EULL,
		0x32454CFF44820329ULL,
		0xA2433BAC338861B8ULL,
		0x206B5B0E0ECFCCDDULL,
		0x7A3307B4401CDB81ULL,
		0x500FF56AAAE2DF29ULL
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
		0x2E826F252A33E8C8ULL,
		0xCFE92D53BED673C7ULL,
		0x4A64B60AFB54BB06ULL,
		0x7B2449E96623D4CBULL,
		0x117ACF17EE5FD3E7ULL,
		0x9DD69AF455C0EC31ULL,
		0x17B9171092FAADAAULL,
		0x0291FB9BA2C54444ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5D04DE4A5467D190ULL,
		0x9FD25AA77DACE78EULL,
		0x94C96C15F6A9760DULL,
		0xF64893D2CC47A996ULL,
		0x22F59E2FDCBFA7CEULL,
		0x3BAD35E8AB81D862ULL,
		0x2F722E2125F55B55ULL,
		0x0523F737458A8888ULL
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
		0x44B9A8643603CD6BULL,
		0xEE45CA020497DDCCULL,
		0xF14E9EFD65520ECFULL,
		0x194DA1A10A5BAFD1ULL,
		0x89730F2956138A77ULL,
		0xC0FE8264010CA260ULL,
		0x6BBFB64D4D7939E0ULL,
		0x2B212984C4CB351AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x897350C86C079AD6ULL,
		0xDC8B9404092FBB98ULL,
		0xE29D3DFACAA41D9FULL,
		0x329B434214B75FA3ULL,
		0x12E61E52AC2714EEULL,
		0x81FD04C8021944C1ULL,
		0xD77F6C9A9AF273C1ULL,
		0x5642530989966A34ULL
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
		0xD17BC7C0E370B95EULL,
		0x93E1518384B28B83ULL,
		0xDC21F57A3CC20A22ULL,
		0x3A0BE85C488B82A5ULL,
		0xD3FAC2726B1D56B3ULL,
		0xB63AAE70EC420A70ULL,
		0x99EA2CDF4CADB1AEULL,
		0x05A559CB649BF3E5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA2F78F81C6E172BCULL,
		0x27C2A30709651707ULL,
		0xB843EAF479841445ULL,
		0x7417D0B89117054BULL,
		0xA7F584E4D63AAD66ULL,
		0x6C755CE1D88414E1ULL,
		0x33D459BE995B635DULL,
		0x0B4AB396C937E7CBULL
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
		0xF788720D6B8B01FDULL,
		0xD3492ABC5627D2C6ULL,
		0x7E2FDE440D179AA7ULL,
		0xDB1BF5499B198D2EULL,
		0x314DA538393CCFE0ULL,
		0x7E032564EBD407F2ULL,
		0x2CAB9DB2EBDAAB61ULL,
		0x0ECEBB9223378911ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEF10E41AD71603FAULL,
		0xA6925578AC4FA58DULL,
		0xFC5FBC881A2F354FULL,
		0xB637EA9336331A5CULL,
		0x629B4A7072799FC1ULL,
		0xFC064AC9D7A80FE4ULL,
		0x59573B65D7B556C2ULL,
		0x1D9D7724466F1222ULL
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
		0x5F215C7EB37F42B6ULL,
		0xEAAB39B405C4D817ULL,
		0x2B0D2F90043597EEULL,
		0x0F4B43E862C8ACE8ULL,
		0xF96082D459BFF7CDULL,
		0x8F1D64EA39F6F66DULL,
		0x8513B24F64C541E7ULL,
		0x3E59AEB0D965E252ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBE42B8FD66FE856CULL,
		0xD55673680B89B02EULL,
		0x561A5F20086B2FDDULL,
		0x1E9687D0C59159D0ULL,
		0xF2C105A8B37FEF9AULL,
		0x1E3AC9D473EDECDBULL,
		0x0A27649EC98A83CFULL,
		0x7CB35D61B2CBC4A5ULL
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
		0xA7A776E179A3DC9BULL,
		0x83EBDAACD91028ABULL,
		0x29840C64B08F1DCCULL,
		0x35C05E80152CF26CULL,
		0x2CAFEE81414F118BULL,
		0xAACE3AE7270EB3D8ULL,
		0x8637B3A7A02E43BAULL,
		0x0965D8A4ED07DE58ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4F4EEDC2F347B936ULL,
		0x07D7B559B2205157ULL,
		0x530818C9611E3B99ULL,
		0x6B80BD002A59E4D8ULL,
		0x595FDD02829E2316ULL,
		0x559C75CE4E1D67B0ULL,
		0x0C6F674F405C8775ULL,
		0x12CBB149DA0FBCB1ULL
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
		0x952980A13D3B2ACCULL,
		0xCC53FBC59215C7CCULL,
		0x22369B133EB8BB88ULL,
		0x5A822EA635072450ULL,
		0xF8FDA29E35AF1745ULL,
		0x53B3D6E09850C6DBULL,
		0x229EAF671ACDBCF3ULL,
		0x3F17BAD498B6EBF1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2A5301427A765598ULL,
		0x98A7F78B242B8F99ULL,
		0x446D36267D717711ULL,
		0xB5045D4C6A0E48A0ULL,
		0xF1FB453C6B5E2E8AULL,
		0xA767ADC130A18DB7ULL,
		0x453D5ECE359B79E6ULL,
		0x7E2F75A9316DD7E2ULL
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
		0x3916AD2F05AEA71EULL,
		0x8C16D3921C0634EBULL,
		0xCCB1F13AA5AAC5A9ULL,
		0xA7220A31014C677BULL,
		0x02CCB1F559635C3CULL,
		0xF99C80EC9A148D94ULL,
		0xCC9C962960E70EE7ULL,
		0x2ABD0CB7F8ACD271ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x722D5A5E0B5D4E3CULL,
		0x182DA724380C69D6ULL,
		0x9963E2754B558B53ULL,
		0x4E4414620298CEF7ULL,
		0x059963EAB2C6B879ULL,
		0xF33901D934291B28ULL,
		0x99392C52C1CE1DCFULL,
		0x557A196FF159A4E3ULL
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
		0xE3D6E20686933AD1ULL,
		0x8C44D065C1FE2C1BULL,
		0x7D76045252B7C345ULL,
		0x75B3A2E611B0B74CULL,
		0x05104091121BDFE2ULL,
		0x9D46252D8CB4BAE1ULL,
		0x5CB08537F97575DDULL,
		0x2568342BDFDBE334ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC7ADC40D0D2675A2ULL,
		0x1889A0CB83FC5837ULL,
		0xFAEC08A4A56F868BULL,
		0xEB6745CC23616E98ULL,
		0x0A2081222437BFC4ULL,
		0x3A8C4A5B196975C2ULL,
		0xB9610A6FF2EAEBBBULL,
		0x4AD06857BFB7C668ULL
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
		0x39E823FB29E1B611ULL,
		0x83C41AE1213418A6ULL,
		0x3A2C4E2D34F742D7ULL,
		0x661A246E286C99A9ULL,
		0xC1D7BBAA55EE5EE4ULL,
		0x9A45839F5C3A53A3ULL,
		0x7583AF7D6B86B06FULL,
		0x30CFC402A9233166ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x73D047F653C36C22ULL,
		0x078835C24268314CULL,
		0x74589C5A69EE85AFULL,
		0xCC3448DC50D93352ULL,
		0x83AF7754ABDCBDC8ULL,
		0x348B073EB874A747ULL,
		0xEB075EFAD70D60DFULL,
		0x619F8805524662CCULL
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
		0x3F790FE4587E8738ULL,
		0xC1A16C41FDE1645FULL,
		0x844EC76AFE450407ULL,
		0xAF595AA419D1FF79ULL,
		0x262154385C39FC5CULL,
		0x106553A43F45B61BULL,
		0x1587849C10EBC65AULL,
		0x0DCFD72EF90B9235ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7EF21FC8B0FD0E70ULL,
		0x8342D883FBC2C8BEULL,
		0x089D8ED5FC8A080FULL,
		0x5EB2B54833A3FEF3ULL,
		0x4C42A870B873F8B9ULL,
		0x20CAA7487E8B6C36ULL,
		0x2B0F093821D78CB4ULL,
		0x1B9FAE5DF217246AULL
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
		0xD441DB28E1BE251CULL,
		0xEAF7A497F8BE65B5ULL,
		0xCCB2D117196AAADBULL,
		0xA679388D03D20048ULL,
		0x3EC15047C1B84185ULL,
		0xBE213B17917241BFULL,
		0xAF3DFAF7415F8C3BULL,
		0x1A8E2FF1CE1AE2ECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA883B651C37C4A38ULL,
		0xD5EF492FF17CCB6BULL,
		0x9965A22E32D555B7ULL,
		0x4CF2711A07A40091ULL,
		0x7D82A08F8370830BULL,
		0x7C42762F22E4837EULL,
		0x5E7BF5EE82BF1877ULL,
		0x351C5FE39C35C5D9ULL
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
		0xDCE9A7374D3951B5ULL,
		0xC42CA14F0449040DULL,
		0x23A7E9F29AB84ECBULL,
		0x8356C8EE42224ED9ULL,
		0x06A64D5F55EE3660ULL,
		0x90DEF85990FE1DC4ULL,
		0x913B4CBB90810122ULL,
		0x353EB21389EBA3C8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB9D34E6E9A72A36AULL,
		0x8859429E0892081BULL,
		0x474FD3E535709D97ULL,
		0x06AD91DC84449DB2ULL,
		0x0D4C9ABEABDC6CC1ULL,
		0x21BDF0B321FC3B88ULL,
		0x2276997721020245ULL,
		0x6A7D642713D74791ULL
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
		0x9ACD16AB0B4BB0B6ULL,
		0xAFB01C74DD6AE708ULL,
		0x14BE6D0F91FEF4A7ULL,
		0x2AF25E959FC19E7BULL,
		0x5BD6D35330F6FB5CULL,
		0x5A08E16E26470D83ULL,
		0x38F587335EC98B63ULL,
		0x01D8A2A8F0D71EECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x359A2D561697616CULL,
		0x5F6038E9BAD5CE11ULL,
		0x297CDA1F23FDE94FULL,
		0x55E4BD2B3F833CF6ULL,
		0xB7ADA6A661EDF6B8ULL,
		0xB411C2DC4C8E1B06ULL,
		0x71EB0E66BD9316C6ULL,
		0x03B14551E1AE3DD8ULL
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
		0x57682217B8108674ULL,
		0x20B63FD5D5F52D8CULL,
		0x60602D64B0A8D7E9ULL,
		0x505D31BCD9126041ULL,
		0xB415DC68FBBCADCBULL,
		0x3ED86DC02C84B080ULL,
		0xA033404A2B0A7E1CULL,
		0x14DFFC3035955C8AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAED0442F70210CE8ULL,
		0x416C7FABABEA5B18ULL,
		0xC0C05AC96151AFD2ULL,
		0xA0BA6379B224C082ULL,
		0x682BB8D1F7795B96ULL,
		0x7DB0DB8059096101ULL,
		0x406680945614FC38ULL,
		0x29BFF8606B2AB915ULL
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
		0x400035F34ABE4745ULL,
		0x49F9C334B73B4CA3ULL,
		0xCD511B61D993BCEBULL,
		0x428D6CB27C3F3717ULL,
		0xDBF70AE38467C14DULL,
		0xEEBC1B14789B9C6DULL,
		0x6653F30CF35998EBULL,
		0x3E59D8557EC7A2ABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x80006BE6957C8E8AULL,
		0x93F386696E769946ULL,
		0x9AA236C3B32779D6ULL,
		0x851AD964F87E6E2FULL,
		0xB7EE15C708CF829AULL,
		0xDD783628F13738DBULL,
		0xCCA7E619E6B331D7ULL,
		0x7CB3B0AAFD8F4556ULL
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
		0x86329885B2256FB7ULL,
		0xC147E7C87FB374A0ULL,
		0x303012A5C5B1CE32ULL,
		0xE5797CB3F3A73321ULL,
		0x70A55BE337A70356ULL,
		0x3217F29990B0F9DEULL,
		0x50AD38FC2935C843ULL,
		0x30C1CC9CE9C97D6CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0C65310B644ADF6EULL,
		0x828FCF90FF66E941ULL,
		0x6060254B8B639C65ULL,
		0xCAF2F967E74E6642ULL,
		0xE14AB7C66F4E06ADULL,
		0x642FE5332161F3BCULL,
		0xA15A71F8526B9086ULL,
		0x61839939D392FAD8ULL
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
		0xBF5215027DDF7BE9ULL,
		0xA5CC8F50A85576D1ULL,
		0xFFA6F37248239C63ULL,
		0x828EFC456A4B7C0DULL,
		0xE633DAF553F8206CULL,
		0xFDBF7189543F6EF1ULL,
		0x299C1AD1D03542B2ULL,
		0x3BDEB2CC0C098C65ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7EA42A04FBBEF7D2ULL,
		0x4B991EA150AAEDA3ULL,
		0xFF4DE6E4904738C7ULL,
		0x051DF88AD496F81BULL,
		0xCC67B5EAA7F040D9ULL,
		0xFB7EE312A87EDDE3ULL,
		0x533835A3A06A8565ULL,
		0x77BD6598181318CAULL
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
		0x6A5DFB6601485506ULL,
		0xD9B267F317DC1203ULL,
		0xCAC7E633DF12DB7AULL,
		0x2B77380A7ABAF087ULL,
		0x6C79C14308898919ULL,
		0x4E80F7B27E1ADF87ULL,
		0x054352E5BCBEC158ULL,
		0x0CB18A84FB2BC4A0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD4BBF6CC0290AA0CULL,
		0xB364CFE62FB82406ULL,
		0x958FCC67BE25B6F5ULL,
		0x56EE7014F575E10FULL,
		0xD8F3828611131232ULL,
		0x9D01EF64FC35BF0EULL,
		0x0A86A5CB797D82B0ULL,
		0x19631509F6578940ULL
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
		0x6EBB5EC1EF388C1BULL,
		0x4B25C85B2D4109DFULL,
		0x6157F8E85B8E085FULL,
		0x51C09AB214777962ULL,
		0xCCBA6D9DC969DFB2ULL,
		0x492D85848ED4CC74ULL,
		0xDE3955A22B047A85ULL,
		0x0CBD0758731AE608ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDD76BD83DE711836ULL,
		0x964B90B65A8213BEULL,
		0xC2AFF1D0B71C10BEULL,
		0xA381356428EEF2C4ULL,
		0x9974DB3B92D3BF64ULL,
		0x925B0B091DA998E9ULL,
		0xBC72AB445608F50AULL,
		0x197A0EB0E635CC11ULL
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
		0x58EFA1AA9134745BULL,
		0x9B8832D54E7CA585ULL,
		0xF5E389120D5B7F88ULL,
		0x55A46B9F516A0CB1ULL,
		0x7C42772C712CF6BDULL,
		0x2FC3D92E52D15267ULL,
		0x93380231E0230D32ULL,
		0x17D9B892FF2DFE57ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB1DF43552268E8B6ULL,
		0x371065AA9CF94B0AULL,
		0xEBC712241AB6FF11ULL,
		0xAB48D73EA2D41963ULL,
		0xF884EE58E259ED7AULL,
		0x5F87B25CA5A2A4CEULL,
		0x26700463C0461A64ULL,
		0x2FB37125FE5BFCAFULL
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
		0xA2F135AE706150F8ULL,
		0xA9BBAECDE4A430F2ULL,
		0x60EA122AB5B9D3EAULL,
		0x0FCEF9CE64FBD9A3ULL,
		0x941E831767993298ULL,
		0x0E1651A4A8DD5382ULL,
		0xFA510CBB0B14923FULL,
		0x37805BC8E496399BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x45E26B5CE0C2A1F0ULL,
		0x53775D9BC94861E5ULL,
		0xC1D424556B73A7D5ULL,
		0x1F9DF39CC9F7B346ULL,
		0x283D062ECF326530ULL,
		0x1C2CA34951BAA705ULL,
		0xF4A219761629247EULL,
		0x6F00B791C92C7337ULL
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
		0x2F84681073B66A45ULL,
		0xCDBBBFF577E71574ULL,
		0xD322B478A975679FULL,
		0x6D91450BF4D6191AULL,
		0x25159BDBB16C961AULL,
		0xDF9666D5F40A4103ULL,
		0xCCEAC5458357EE99ULL,
		0x1AC606CFBF52254CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5F08D020E76CD48AULL,
		0x9B777FEAEFCE2AE8ULL,
		0xA64568F152EACF3FULL,
		0xDB228A17E9AC3235ULL,
		0x4A2B37B762D92C34ULL,
		0xBF2CCDABE8148206ULL,
		0x99D58A8B06AFDD33ULL,
		0x358C0D9F7EA44A99ULL
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
		0xF5A43077DD39B1A9ULL,
		0xFED346EFE7CAFF23ULL,
		0xE57FD2DD1F294D3EULL,
		0xEDC675C272DE8F65ULL,
		0x13546A1356C47165ULL,
		0x68875C34EA60B9A5ULL,
		0xEA502616BAE8C66CULL,
		0x3F4295887503E79DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEB4860EFBA736352ULL,
		0xFDA68DDFCF95FE47ULL,
		0xCAFFA5BA3E529A7DULL,
		0xDB8CEB84E5BD1ECBULL,
		0x26A8D426AD88E2CBULL,
		0xD10EB869D4C1734AULL,
		0xD4A04C2D75D18CD8ULL,
		0x7E852B10EA07CF3BULL
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
		0xF5EC4A972037C3E7ULL,
		0x1B9FA9E57CDC6932ULL,
		0x479C3E0F30D3057CULL,
		0x71B05FAC904B10B6ULL,
		0x50C6ED5A46E8EE47ULL,
		0xCF9A8018D3CF2C7AULL,
		0x7E12510EF314D114ULL,
		0x026A7502F013C058ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEBD8952E406F87CEULL,
		0x373F53CAF9B8D265ULL,
		0x8F387C1E61A60AF8ULL,
		0xE360BF592096216CULL,
		0xA18DDAB48DD1DC8EULL,
		0x9F350031A79E58F4ULL,
		0xFC24A21DE629A229ULL,
		0x04D4EA05E02780B0ULL
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
		0x1EF069E8B09DD2E7ULL,
		0x61879976C1DD7E92ULL,
		0xA40BB8F671867639ULL,
		0xC2A66E664FEDBA1FULL,
		0x3A612FDD2915CE67ULL,
		0x04615DC6BDFA82EDULL,
		0x2C10E2B7853836D0ULL,
		0x37D5CF058F801DAEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3DE0D3D1613BA5CEULL,
		0xC30F32ED83BAFD24ULL,
		0x481771ECE30CEC72ULL,
		0x854CDCCC9FDB743FULL,
		0x74C25FBA522B9CCFULL,
		0x08C2BB8D7BF505DAULL,
		0x5821C56F0A706DA0ULL,
		0x6FAB9E0B1F003B5CULL
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
		0x0317BEF931A2DD8FULL,
		0x3512537B31F385E4ULL,
		0x4B1C29BC46F6564EULL,
		0x7FB61BB574FDA83CULL,
		0xE68EDE40CD001A47ULL,
		0x4B25ED19C53919D4ULL,
		0x8DD78CF5942A8E6EULL,
		0x027636534DF423D3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x062F7DF26345BB1EULL,
		0x6A24A6F663E70BC8ULL,
		0x963853788DECAC9CULL,
		0xFF6C376AE9FB5078ULL,
		0xCD1DBC819A00348EULL,
		0x964BDA338A7233A9ULL,
		0x1BAF19EB28551CDCULL,
		0x04EC6CA69BE847A7ULL
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
		0x94BDFAF093B29A3FULL,
		0x7CCF7A6401A075F6ULL,
		0xD533893CA6841135ULL,
		0xD543A32EFA27F337ULL,
		0x60D2C5CFEFF1FAD5ULL,
		0xBFF8CB672148B14DULL,
		0xE8D3AA156680E0F8ULL,
		0x2DB6BB45EB4F7519ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x297BF5E12765347EULL,
		0xF99EF4C80340EBEDULL,
		0xAA6712794D08226AULL,
		0xAA87465DF44FE66FULL,
		0xC1A58B9FDFE3F5ABULL,
		0x7FF196CE4291629AULL,
		0xD1A7542ACD01C1F1ULL,
		0x5B6D768BD69EEA33ULL
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
		0x0B618DD8C81F8AD6ULL,
		0x5894A66B70EA26D6ULL,
		0xF507B83F47417CBAULL,
		0x648FDACE89D1C7E1ULL,
		0x2BED06FDB670738AULL,
		0x1BD6BB27FCC2E37AULL,
		0xEA2392491ED05DB0ULL,
		0x18A45E2673C03360ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x16C31BB1903F15ACULL,
		0xB1294CD6E1D44DACULL,
		0xEA0F707E8E82F974ULL,
		0xC91FB59D13A38FC3ULL,
		0x57DA0DFB6CE0E714ULL,
		0x37AD764FF985C6F4ULL,
		0xD44724923DA0BB60ULL,
		0x3148BC4CE78066C1ULL
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
		0x1F5C1B800EE90E1CULL,
		0xC62422A1590E23F8ULL,
		0x82EBBD500112652EULL,
		0x4D132F76128EB3E9ULL,
		0x91BFE02EB3E35E21ULL,
		0x1E668F2A4D751A85ULL,
		0x89013ED3CD258243ULL,
		0x25BD6D6BF3BA3286ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3EB837001DD21C38ULL,
		0x8C484542B21C47F0ULL,
		0x05D77AA00224CA5DULL,
		0x9A265EEC251D67D3ULL,
		0x237FC05D67C6BC42ULL,
		0x3CCD1E549AEA350BULL,
		0x12027DA79A4B0486ULL,
		0x4B7ADAD7E774650DULL
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
		0xB87E5387AB8608CFULL,
		0x77424D7B4A48944BULL,
		0xD4BBAF1B14F3760EULL,
		0x3A6912942148F26BULL,
		0xCE52C890B89605D2ULL,
		0x0BAF3268B7E3D5A5ULL,
		0xA02A576807112B3AULL,
		0x1927575F8BCDA59FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x70FCA70F570C119EULL,
		0xEE849AF694912897ULL,
		0xA9775E3629E6EC1CULL,
		0x74D225284291E4D7ULL,
		0x9CA59121712C0BA4ULL,
		0x175E64D16FC7AB4BULL,
		0x4054AED00E225674ULL,
		0x324EAEBF179B4B3FULL
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
		0xE416810FC5C504A6ULL,
		0x9FA8AFC80E5FC1D1ULL,
		0x46C958DEE9817543ULL,
		0xFAEB1DA6B3B6EC81ULL,
		0x0D7FF5F8064F26ACULL,
		0xD7AD76AE2BAD20F7ULL,
		0xA36DCAF14457A3E6ULL,
		0x07771CE15C332037ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC82D021F8B8A094CULL,
		0x3F515F901CBF83A3ULL,
		0x8D92B1BDD302EA87ULL,
		0xF5D63B4D676DD902ULL,
		0x1AFFEBF00C9E4D59ULL,
		0xAF5AED5C575A41EEULL,
		0x46DB95E288AF47CDULL,
		0x0EEE39C2B866406FULL
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
		0x593B47BFA2FFFAE1ULL,
		0xFD0C9E09A62075E3ULL,
		0x0B83DA40D14836C2ULL,
		0x551C9AF2CCC19573ULL,
		0x43830650873DE5CEULL,
		0xED89D3127ADD43B4ULL,
		0xED161B1FA88D7073ULL,
		0x222BCEBBA2E63FBBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB2768F7F45FFF5C2ULL,
		0xFA193C134C40EBC6ULL,
		0x1707B481A2906D85ULL,
		0xAA3935E599832AE6ULL,
		0x87060CA10E7BCB9CULL,
		0xDB13A624F5BA8768ULL,
		0xDA2C363F511AE0E7ULL,
		0x44579D7745CC7F77ULL
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
		0x12E7375A4BAC5AE6ULL,
		0xCCD7216A1A9F0741ULL,
		0x876552014C820FF1ULL,
		0x348F8A1A5CB29F86ULL,
		0x5B25803F6C07D230ULL,
		0x977E48AE2BBA0B9BULL,
		0xA212E6E11D54EC61ULL,
		0x16DD0882B82BDAAEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x25CE6EB49758B5CCULL,
		0x99AE42D4353E0E82ULL,
		0x0ECAA40299041FE3ULL,
		0x691F1434B9653F0DULL,
		0xB64B007ED80FA460ULL,
		0x2EFC915C57741736ULL,
		0x4425CDC23AA9D8C3ULL,
		0x2DBA11057057B55DULL
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
		0x58E6B69F04DB2084ULL,
		0x12F8A0D0D7C575F9ULL,
		0x7A510751A87E74A7ULL,
		0x41202FFB375EFDD3ULL,
		0xDAAF419BF4107CCFULL,
		0x020D377E9C150BE7ULL,
		0xA0790F75C1E31C91ULL,
		0x0D684F49E08ED0E2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB1CD6D3E09B64108ULL,
		0x25F141A1AF8AEBF2ULL,
		0xF4A20EA350FCE94EULL,
		0x82405FF66EBDFBA6ULL,
		0xB55E8337E820F99EULL,
		0x041A6EFD382A17CFULL,
		0x40F21EEB83C63922ULL,
		0x1AD09E93C11DA1C5ULL
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
		0xDC15FB973218FE4DULL,
		0x269214B19C1C0E56ULL,
		0x314130F8ECF750E9ULL,
		0xCC2AD5DE75AEBFB5ULL,
		0xD78481E6FBD8FCFBULL,
		0xDD789B53DC1A9B5BULL,
		0xAF671A365A65407FULL,
		0x2FD447B153AFBC04ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB82BF72E6431FC9AULL,
		0x4D24296338381CADULL,
		0x628261F1D9EEA1D2ULL,
		0x9855ABBCEB5D7F6AULL,
		0xAF0903CDF7B1F9F7ULL,
		0xBAF136A7B83536B7ULL,
		0x5ECE346CB4CA80FFULL,
		0x5FA88F62A75F7809ULL
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
		0xCF524F8721518251ULL,
		0x646B1B56D4CD92D1ULL,
		0x72710BFCC5F74B1BULL,
		0xD2ED7F8502847567ULL,
		0xD86D5DE296F91BBAULL,
		0x6B672F1123A99468ULL,
		0xA021FDBC546DB2B5ULL,
		0x1B989C0E177B5DC5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9EA49F0E42A304A2ULL,
		0xC8D636ADA99B25A3ULL,
		0xE4E217F98BEE9636ULL,
		0xA5DAFF0A0508EACEULL,
		0xB0DABBC52DF23775ULL,
		0xD6CE5E22475328D1ULL,
		0x4043FB78A8DB656AULL,
		0x3731381C2EF6BB8BULL
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
		0xED39CF28056DE6A0ULL,
		0x6B396973CF89F5F9ULL,
		0xBF439DD01F5F062CULL,
		0x9EC5C3AC3EC1C33AULL,
		0x416ED62323139485ULL,
		0x1CA2043B9197E755ULL,
		0x42923AE930CC724DULL,
		0x1B44BF2C958E09C1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDA739E500ADBCD40ULL,
		0xD672D2E79F13EBF3ULL,
		0x7E873BA03EBE0C58ULL,
		0x3D8B87587D838675ULL,
		0x82DDAC464627290BULL,
		0x39440877232FCEAAULL,
		0x852475D26198E49AULL,
		0x36897E592B1C1382ULL
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
		0x4F70AC7E458877D0ULL,
		0x104ABF12242B8F33ULL,
		0x54F7B6BA558A28D3ULL,
		0x8E8FEDB4A5642EC9ULL,
		0x14BA5AD8D15BAAF1ULL,
		0x711F819B4CF0F4B9ULL,
		0x51C254D4525D1EB2ULL,
		0x0DAD0017AC8E98FCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9EE158FC8B10EFA0ULL,
		0x20957E2448571E66ULL,
		0xA9EF6D74AB1451A6ULL,
		0x1D1FDB694AC85D92ULL,
		0x2974B5B1A2B755E3ULL,
		0xE23F033699E1E972ULL,
		0xA384A9A8A4BA3D64ULL,
		0x1B5A002F591D31F8ULL
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
		0x61AED68E61EA65F2ULL,
		0x58E42B99687F4B6AULL,
		0x0B2EDA4FCE19DE12ULL,
		0x041F83676905F8C6ULL,
		0xF8B04E61B8837F79ULL,
		0xD1CFF1DBA6C769FEULL,
		0x7CAF1982D6577566ULL,
		0x25787294149DB246ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC35DAD1CC3D4CBE4ULL,
		0xB1C85732D0FE96D4ULL,
		0x165DB49F9C33BC24ULL,
		0x083F06CED20BF18CULL,
		0xF1609CC37106FEF2ULL,
		0xA39FE3B74D8ED3FDULL,
		0xF95E3305ACAEEACDULL,
		0x4AF0E528293B648CULL
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
		0x7AC6038294B995F1ULL,
		0xD8707DBFEFBE596CULL,
		0xF9B2C5DE7769DB31ULL,
		0x2CAE0AA89EE8D6FCULL,
		0xC39C297C04AD04E3ULL,
		0x9F5C6346C93D5BFAULL,
		0x0C4B74D50B831BD2ULL,
		0x1072A6D5B951FB5CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF58C070529732BE2ULL,
		0xB0E0FB7FDF7CB2D8ULL,
		0xF3658BBCEED3B663ULL,
		0x595C15513DD1ADF9ULL,
		0x873852F8095A09C6ULL,
		0x3EB8C68D927AB7F5ULL,
		0x1896E9AA170637A5ULL,
		0x20E54DAB72A3F6B8ULL
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
		0xAFF1928CDEA70466ULL,
		0x01802DF3636C059DULL,
		0x3524B154A6D90BD0ULL,
		0xB7827B079A985057ULL,
		0xC21168C3A547CF67ULL,
		0x16A614828F1C5C8FULL,
		0x6E4892652984DB88ULL,
		0x2D668F1CC6459184ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5FE32519BD4E08CCULL,
		0x03005BE6C6D80B3BULL,
		0x6A4962A94DB217A0ULL,
		0x6F04F60F3530A0AEULL,
		0x8422D1874A8F9ECFULL,
		0x2D4C29051E38B91FULL,
		0xDC9124CA5309B710ULL,
		0x5ACD1E398C8B2308ULL
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
		0x462A196EC5FB0A21ULL,
		0x7246103145354758ULL,
		0xCD74A4459EA7198EULL,
		0xFF8E7B9E96C835FBULL,
		0xFCFF70A0664CE5D1ULL,
		0xDFCFB1A7CA3D5510ULL,
		0xAD5397B994B3132FULL,
		0x1F1C87C9761D24DFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8C5432DD8BF61442ULL,
		0xE48C20628A6A8EB0ULL,
		0x9AE9488B3D4E331CULL,
		0xFF1CF73D2D906BF7ULL,
		0xF9FEE140CC99CBA3ULL,
		0xBF9F634F947AAA21ULL,
		0x5AA72F732966265FULL,
		0x3E390F92EC3A49BFULL
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
		0xDD512DF7E4DC59ADULL,
		0x95BBFB79B20988B1ULL,
		0x85918F3B95110A33ULL,
		0x7E9237D67CCA75CEULL,
		0xC2C3FFF20AD73550ULL,
		0xE37906A5440332ADULL,
		0xE3A7FBF48A599ADBULL,
		0x1E4A14BE9EC63C47ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBAA25BEFC9B8B35AULL,
		0x2B77F6F364131163ULL,
		0x0B231E772A221467ULL,
		0xFD246FACF994EB9DULL,
		0x8587FFE415AE6AA0ULL,
		0xC6F20D4A8806655BULL,
		0xC74FF7E914B335B7ULL,
		0x3C94297D3D8C788FULL
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
		0x79CED3E593DF02A9ULL,
		0xC528D25354FF6D84ULL,
		0xC120718B57329F5FULL,
		0xD8E8B1E4178E00B0ULL,
		0x3D398CBA14BBD007ULL,
		0xB8A8A90C0A1CD6EAULL,
		0x055BBA8ECDA109F9ULL,
		0x3778CEA387042C30ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF39DA7CB27BE0552ULL,
		0x8A51A4A6A9FEDB08ULL,
		0x8240E316AE653EBFULL,
		0xB1D163C82F1C0161ULL,
		0x7A7319742977A00FULL,
		0x715152181439ADD4ULL,
		0x0AB7751D9B4213F3ULL,
		0x6EF19D470E085860ULL
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
		0xCC78E0DF1FF6F2AAULL,
		0x14F06378D9228239ULL,
		0xBE421D1EFB4F7FDFULL,
		0x4E0A0D7F83BD6007ULL,
		0xD0504096F8BDB153ULL,
		0x9F0BCDDD068BC2B8ULL,
		0x88791BEC513F1441ULL,
		0x1EE885CADEA4DA87ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x98F1C1BE3FEDE554ULL,
		0x29E0C6F1B2450473ULL,
		0x7C843A3DF69EFFBEULL,
		0x9C141AFF077AC00FULL,
		0xA0A0812DF17B62A6ULL,
		0x3E179BBA0D178571ULL,
		0x10F237D8A27E2883ULL,
		0x3DD10B95BD49B50FULL
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
		0x5C5794121D06EC5EULL,
		0x0D6762EF16020CF8ULL,
		0xF409CFB4E91E8F3DULL,
		0xB662933ADB31DA3AULL,
		0x2FFD9C74851B258CULL,
		0x3BB374020A0707F8ULL,
		0x2D6AE1BD4FA4165EULL,
		0x0114EAEF24B1F5EDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB8AF28243A0DD8BCULL,
		0x1ACEC5DE2C0419F0ULL,
		0xE8139F69D23D1E7AULL,
		0x6CC52675B663B475ULL,
		0x5FFB38E90A364B19ULL,
		0x7766E804140E0FF0ULL,
		0x5AD5C37A9F482CBCULL,
		0x0229D5DE4963EBDAULL
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
		0x1C9A07168623706BULL,
		0x30E00288D32FDDFEULL,
		0x3E6F1FEDA510A3A9ULL,
		0x44AB6C008CD48E2FULL,
		0xE1FB8D322FD80D84ULL,
		0x9A00FF38DC367943ULL,
		0x989FFDB38E960DD7ULL,
		0x19C07072BBFF68ADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x39340E2D0C46E0D6ULL,
		0x61C00511A65FBBFCULL,
		0x7CDE3FDB4A214752ULL,
		0x8956D80119A91C5EULL,
		0xC3F71A645FB01B08ULL,
		0x3401FE71B86CF287ULL,
		0x313FFB671D2C1BAFULL,
		0x3380E0E577FED15BULL
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
		0xF4D1D92511C49C94ULL,
		0xDFD51C7B82980D79ULL,
		0xA6A74CF8FE0643BDULL,
		0xF776036AD74FF749ULL,
		0x9CF2FC2E317D85B5ULL,
		0x1C00320C4EF46A40ULL,
		0x56D8280A534C4AE4ULL,
		0x27894A8C0AF441EAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE9A3B24A23893928ULL,
		0xBFAA38F705301AF3ULL,
		0x4D4E99F1FC0C877BULL,
		0xEEEC06D5AE9FEE93ULL,
		0x39E5F85C62FB0B6BULL,
		0x380064189DE8D481ULL,
		0xADB05014A69895C8ULL,
		0x4F12951815E883D4ULL
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
		0xC1A2C9B396165B3AULL,
		0xDFDAE83F81739646ULL,
		0xC44850CCDC96B4CBULL,
		0x090A1DF66BF53698ULL,
		0x33C9D700417FEE2FULL,
		0x818ACE1648B2C72FULL,
		0x23684F7CE5CA10CBULL,
		0x10990D017F7A4669ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x834593672C2CB674ULL,
		0xBFB5D07F02E72C8DULL,
		0x8890A199B92D6997ULL,
		0x12143BECD7EA6D31ULL,
		0x6793AE0082FFDC5EULL,
		0x03159C2C91658E5EULL,
		0x46D09EF9CB942197ULL,
		0x21321A02FEF48CD2ULL
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
		0x8C16C2A70979C8ADULL,
		0x266ED59E1BC0F076ULL,
		0x10918E988E78D759ULL,
		0xC2532AC7C10BDE47ULL,
		0x8252EA2A966EC0C0ULL,
		0x2DFDE24D5C98D397ULL,
		0x7F5CB3603FCFC096ULL,
		0x0E63451C7D1328A9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x182D854E12F3915AULL,
		0x4CDDAB3C3781E0EDULL,
		0x21231D311CF1AEB2ULL,
		0x84A6558F8217BC8EULL,
		0x04A5D4552CDD8181ULL,
		0x5BFBC49AB931A72FULL,
		0xFEB966C07F9F812CULL,
		0x1CC68A38FA265152ULL
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
		0x2002B7541F643B2BULL,
		0x1D3AEDC7C55503D5ULL,
		0x3316D1B67C99AA44ULL,
		0xCD7447EB9DE3D951ULL,
		0x9350A863F4FF94C4ULL,
		0x87136F841D5194FEULL,
		0x37BE6286F4D3873FULL,
		0x0657DB5413612573ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x40056EA83EC87656ULL,
		0x3A75DB8F8AAA07AAULL,
		0x662DA36CF9335488ULL,
		0x9AE88FD73BC7B2A2ULL,
		0x26A150C7E9FF2989ULL,
		0x0E26DF083AA329FDULL,
		0x6F7CC50DE9A70E7FULL,
		0x0CAFB6A826C24AE6ULL
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
		0xCB50B7962F6768D1ULL,
		0x97F31F22FD61722AULL,
		0x81813A5C67224F33ULL,
		0x2C513555C0B38978ULL,
		0xDF1C63974AD5BA61ULL,
		0xB13168C3FA15272DULL,
		0x48A0A5C8BDABF59BULL,
		0x3D7B2A8B4A409671ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x96A16F2C5ECED1A2ULL,
		0x2FE63E45FAC2E455ULL,
		0x030274B8CE449E67ULL,
		0x58A26AAB816712F1ULL,
		0xBE38C72E95AB74C2ULL,
		0x6262D187F42A4E5BULL,
		0x91414B917B57EB37ULL,
		0x7AF6551694812CE2ULL
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
		0x885201F365C8C639ULL,
		0xA673AC7CAACC95F5ULL,
		0x68E094469C0C7B11ULL,
		0x90EEC93D22353A71ULL,
		0xFDDA1D281F928BDFULL,
		0x54749EE2A7B1527EULL,
		0x5474A46503ED005CULL,
		0x29DDFB84F4D52FD3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x10A403E6CB918C72ULL,
		0x4CE758F955992BEBULL,
		0xD1C1288D3818F623ULL,
		0x21DD927A446A74E2ULL,
		0xFBB43A503F2517BFULL,
		0xA8E93DC54F62A4FDULL,
		0xA8E948CA07DA00B8ULL,
		0x53BBF709E9AA5FA6ULL
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
		0x0016ABDBACCB63A2ULL,
		0x1624A49862F29AFBULL,
		0xE6B81E687FE66ED9ULL,
		0x8C78D596A730F827ULL,
		0xD7C2E01A898E425EULL,
		0xA634D31BC59C2C79ULL,
		0x4BB8E15650A409B7ULL,
		0x19B13B27BEFB70A0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x002D57B75996C744ULL,
		0x2C494930C5E535F6ULL,
		0xCD703CD0FFCCDDB2ULL,
		0x18F1AB2D4E61F04FULL,
		0xAF85C035131C84BDULL,
		0x4C69A6378B3858F3ULL,
		0x9771C2ACA148136FULL,
		0x3362764F7DF6E140ULL
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
		0x8C8CC7C425E84279ULL,
		0x3297400CAF6ADA3AULL,
		0xE30DD2619D5C4C7AULL,
		0x1272792CF4923E48ULL,
		0x398E6AEB5F89ADD3ULL,
		0x61AC1EDA4DA96ACAULL,
		0x2032440244BF1F8AULL,
		0x22E3993122819493ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x19198F884BD084F2ULL,
		0x652E80195ED5B475ULL,
		0xC61BA4C33AB898F4ULL,
		0x24E4F259E9247C91ULL,
		0x731CD5D6BF135BA6ULL,
		0xC3583DB49B52D594ULL,
		0x40648804897E3F14ULL,
		0x45C7326245032926ULL
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
		0x36DBE7880A8176F5ULL,
		0xEF18FF6C7A047447ULL,
		0x9372110F44B8AE0EULL,
		0xFD273FA779CA4521ULL,
		0xD938E678315EC3FAULL,
		0x002B4AD70DB2D9E2ULL,
		0xA542F0BC83D39FF9ULL,
		0x102563313BF3C9DEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6DB7CF101502EDEAULL,
		0xDE31FED8F408E88EULL,
		0x26E4221E89715C1DULL,
		0xFA4E7F4EF3948A43ULL,
		0xB271CCF062BD87F5ULL,
		0x005695AE1B65B3C5ULL,
		0x4A85E17907A73FF2ULL,
		0x204AC66277E793BDULL
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
		0x90C66B9395FEE063ULL,
		0xC79A0AA335566063ULL,
		0x57F6EE9A2FFADB9CULL,
		0xB32BAAE0BB72A929ULL,
		0xEFF0C409831583BDULL,
		0x82675D8707A65F12ULL,
		0x91FB372F4C48ED83ULL,
		0x03F22D45CF2DC3E9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x218CD7272BFDC0C6ULL,
		0x8F3415466AACC0C7ULL,
		0xAFEDDD345FF5B739ULL,
		0x665755C176E55252ULL,
		0xDFE18813062B077BULL,
		0x04CEBB0E0F4CBE25ULL,
		0x23F66E5E9891DB07ULL,
		0x07E45A8B9E5B87D3ULL
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
		0xF39872DE53A4D9CAULL,
		0xEFA73FE998F4A347ULL,
		0x639436E8EB6FDF1AULL,
		0x7D13CE6ADE057630ULL,
		0x64F63BCE5C1CA014ULL,
		0x1220F883843F3CF6ULL,
		0xB35AB45C4F3C282DULL,
		0x051B84807368131BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE730E5BCA749B394ULL,
		0xDF4E7FD331E9468FULL,
		0xC7286DD1D6DFBE35ULL,
		0xFA279CD5BC0AEC60ULL,
		0xC9EC779CB8394028ULL,
		0x2441F107087E79ECULL,
		0x66B568B89E78505AULL,
		0x0A370900E6D02637ULL
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
		0x04C18605FC37CE14ULL,
		0x712BB7BBEAE5C5DDULL,
		0x7F75BF195DF6D340ULL,
		0x059608923C456BAEULL,
		0x0E362185C8F439ADULL,
		0xE76060B98426E31BULL,
		0xA78FBA7E0AA97897ULL,
		0x132C9606F7B33C32ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x09830C0BF86F9C28ULL,
		0xE2576F77D5CB8BBAULL,
		0xFEEB7E32BBEDA680ULL,
		0x0B2C1124788AD75CULL,
		0x1C6C430B91E8735AULL,
		0xCEC0C173084DC636ULL,
		0x4F1F74FC1552F12FULL,
		0x26592C0DEF667865ULL
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
		0x2D0F6309AC4FD8E8ULL,
		0x4AD927EB7FB7DCBCULL,
		0x8F751AE2B9ACAC64ULL,
		0x420AB88E3DB0EBCDULL,
		0x736001B4F3A29956ULL,
		0xE45A9C681E766D26ULL,
		0xD626C8660B8425BDULL,
		0x001230EE9599DBD8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5A1EC613589FB1D0ULL,
		0x95B24FD6FF6FB978ULL,
		0x1EEA35C5735958C8ULL,
		0x8415711C7B61D79BULL,
		0xE6C00369E74532ACULL,
		0xC8B538D03CECDA4CULL,
		0xAC4D90CC17084B7BULL,
		0x002461DD2B33B7B1ULL
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
		0xDEE14E7FDB9CB1B8ULL,
		0x906476D28CDF9E59ULL,
		0x379DDF059F089EE3ULL,
		0x570327041E639FDFULL,
		0xAF5B988C462F387BULL,
		0x23C8F8A658FC0F8DULL,
		0x3FBEB5A44263E32BULL,
		0x2F12F6F4EA274A84ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBDC29CFFB7396370ULL,
		0x20C8EDA519BF3CB3ULL,
		0x6F3BBE0B3E113DC7ULL,
		0xAE064E083CC73FBEULL,
		0x5EB731188C5E70F6ULL,
		0x4791F14CB1F81F1BULL,
		0x7F7D6B4884C7C656ULL,
		0x5E25EDE9D44E9508ULL
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
		0xAA11CEB73F9D4235ULL,
		0x157F05C0C239F5A3ULL,
		0xD42B25BCC63B9597ULL,
		0x42416BC6FDC03F67ULL,
		0x974ACB9681F19687ULL,
		0xC3D12DBCAA2F473FULL,
		0x8A7D660550373497ULL,
		0x3B257E1929C88606ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x54239D6E7F3A846AULL,
		0x2AFE0B818473EB47ULL,
		0xA8564B798C772B2EULL,
		0x8482D78DFB807ECFULL,
		0x2E95972D03E32D0EULL,
		0x87A25B79545E8E7FULL,
		0x14FACC0AA06E692FULL,
		0x764AFC3253910C0DULL
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
		0x3D9356711E0F78C9ULL,
		0x76FDB7A487976E17ULL,
		0x47EF14B3D756A3FAULL,
		0x4BFDB3AF31B5570DULL,
		0x47B8B18FB35E9C35ULL,
		0xE074318C6185F6E3ULL,
		0x5E93FCC08C22FF3FULL,
		0x1F63BE6EA1E1C035ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7B26ACE23C1EF192ULL,
		0xEDFB6F490F2EDC2EULL,
		0x8FDE2967AEAD47F4ULL,
		0x97FB675E636AAE1AULL,
		0x8F71631F66BD386AULL,
		0xC0E86318C30BEDC6ULL,
		0xBD27F9811845FE7FULL,
		0x3EC77CDD43C3806AULL
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
		0x07AFE66EEB075F4DULL,
		0x58BB28B8ABCD7E6EULL,
		0xA2B2A69158199717ULL,
		0x4D820D36B6511A7FULL,
		0xF230C0807DB87430ULL,
		0x59104819229B5C53ULL,
		0x278416BE4793360AULL,
		0x12F3FB296EBC27BCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F5FCCDDD60EBE9AULL,
		0xB1765171579AFCDCULL,
		0x45654D22B0332E2EULL,
		0x9B041A6D6CA234FFULL,
		0xE4618100FB70E860ULL,
		0xB22090324536B8A7ULL,
		0x4F082D7C8F266C14ULL,
		0x25E7F652DD784F78ULL
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
		0x39EB4C128FEF881BULL,
		0x7F7C895DF1CB24BEULL,
		0x025B8857A0D2F61DULL,
		0xF74AFDF3EC6DC7BEULL,
		0xA7016724E589CF20ULL,
		0x61DE6877C8E8CD64ULL,
		0xF3DA9E8B07BEEFD1ULL,
		0x2494C01F590E8C17ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x73D698251FDF1036ULL,
		0xFEF912BBE396497CULL,
		0x04B710AF41A5EC3AULL,
		0xEE95FBE7D8DB8F7CULL,
		0x4E02CE49CB139E41ULL,
		0xC3BCD0EF91D19AC9ULL,
		0xE7B53D160F7DDFA2ULL,
		0x4929803EB21D182FULL
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
		0xC44B9ABFA8202A07ULL,
		0x60124246C2FD9CD1ULL,
		0xA5B5EF4058F0840FULL,
		0xB3F2F2D39C201E20ULL,
		0xD0F7616FCF3E1BCEULL,
		0x373C58FED426A80DULL,
		0x8AC739353BCDBAF3ULL,
		0x2C6D7AFFFA9432FBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8897357F5040540EULL,
		0xC024848D85FB39A3ULL,
		0x4B6BDE80B1E1081EULL,
		0x67E5E5A738403C41ULL,
		0xA1EEC2DF9E7C379DULL,
		0x6E78B1FDA84D501BULL,
		0x158E726A779B75E6ULL,
		0x58DAF5FFF52865F7ULL
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
		0xCA1947587C322F6CULL,
		0x643A28701BCFD800ULL,
		0x6EA6C62C5A3CAA57ULL,
		0x026B7603F8A5037FULL,
		0x52AE58F2EF553228ULL,
		0x13E9A4C3C34C22F5ULL,
		0x0FF0DEEF63DE2BC0ULL,
		0x07DF4F58382138E9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x94328EB0F8645ED8ULL,
		0xC87450E0379FB001ULL,
		0xDD4D8C58B47954AEULL,
		0x04D6EC07F14A06FEULL,
		0xA55CB1E5DEAA6450ULL,
		0x27D34987869845EAULL,
		0x1FE1BDDEC7BC5780ULL,
		0x0FBE9EB0704271D2ULL
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
		0xE4BE7DD43F1A501CULL,
		0x9B9A044320658E42ULL,
		0x8F55AAB7152ECDA9ULL,
		0x893C2B0A85FCC7BEULL,
		0x142BF1440F582339ULL,
		0x8574D96583859EF0ULL,
		0xCA5CE5F4BCB3A506ULL,
		0x33E98DB882FDC368ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC97CFBA87E34A038ULL,
		0x3734088640CB1C85ULL,
		0x1EAB556E2A5D9B53ULL,
		0x127856150BF98F7DULL,
		0x2857E2881EB04673ULL,
		0x0AE9B2CB070B3DE0ULL,
		0x94B9CBE979674A0DULL,
		0x67D31B7105FB86D1ULL
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
		0x6844C76AD6B64990ULL,
		0x3BD265A7F20A3C73ULL,
		0x097F77AAA3662C64ULL,
		0x4B6FE484FFE0FCD6ULL,
		0xD5532A1F6F9FCDC7ULL,
		0x4C7601D30E4DE6A2ULL,
		0x0AF934E1E4DEEFC7ULL,
		0x2F6BCEEB357148C8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD0898ED5AD6C9320ULL,
		0x77A4CB4FE41478E6ULL,
		0x12FEEF5546CC58C8ULL,
		0x96DFC909FFC1F9ACULL,
		0xAAA6543EDF3F9B8EULL,
		0x98EC03A61C9BCD45ULL,
		0x15F269C3C9BDDF8EULL,
		0x5ED79DD66AE29190ULL
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
		0x10C8BDEB6744DC13ULL,
		0xC9038944FFAFE015ULL,
		0xFD6E2CAB79AC09E3ULL,
		0x7D4A5E2DD17FF132ULL,
		0x9F8C39F7B08B3E2BULL,
		0x6A2EC5D6576F109EULL,
		0xB6E8D520BE69D370ULL,
		0x39B3ABD6252EB066ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x21917BD6CE89B826ULL,
		0x92071289FF5FC02AULL,
		0xFADC5956F35813C7ULL,
		0xFA94BC5BA2FFE265ULL,
		0x3F1873EF61167C56ULL,
		0xD45D8BACAEDE213DULL,
		0x6DD1AA417CD3A6E0ULL,
		0x736757AC4A5D60CDULL
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
	return 0;
}