#include "../tests.h"

int32_t curve25519_key_sub_modulo_test(void) {
	printf("Modular Key Subtraction Test\n");
	curve25519_key_t r = { };
	curve25519_key_t k1 = {.key64 = {
		0x4E7B82F352BACB7FULL,
		0xE9022E7DDA619372ULL,
		0x7ED5D7E69BCF90DBULL,
		0x82A53E6D1DB1BF2AULL,
		0x703E6B6690A4BDCEULL,
		0xB010583B815AD0A4ULL,
		0x3ACADC887E46DE15ULL,
		0x61FDD1ECB6F77168ULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0xEA1686649FBE1DCFULL,
		0xC1CCB959D3006888ULL,
		0xF2FEE66ACC96260EULL,
		0x7DFD85C52D4536B1ULL,
		0xC727294C5295F582ULL,
		0x92848B38DBC85F31ULL,
		0x1E53C3F7863D2324ULL,
		0xE20D7CA664DBE43CULL
	}};
	curve25519_key_t k3 = {.key64 = {
		0x7DD8CC73E92E6626ULL,
		0x89F5E3889B1E01EEULL,
		0xC5849700A0AB2A97ULL,
		0x0254611820837D04ULL,
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
		0x13FE6365FBBE7F74ULL,
		0xD2E75C87F781BA1DULL,
		0x32BC536D693B7C4FULL,
		0xA90142CF5FCCDAF7ULL,
		0x5BE779337A17A8FAULL,
		0xD0A78791168CE80EULL,
		0x10A7006FE5131B58ULL,
		0x77B50D295BA9C58FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC6AA3E58561118F4ULL,
		0x7879F19EB908EE73ULL,
		0xBC8E605F983E224EULL,
		0xF40A202AF11A2E85ULL,
		0x63B6A6B717B9E8A1ULL,
		0xC2AEE4AA7F49263BULL,
		0x979F7D4218332B1BULL,
		0x9E66610F606BA861ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x249363843F97F2BFULL,
		0x6D559923B28790FAULL,
		0x6D4B6BDA3A3B0311ULL,
		0x76A4AE7FB9EB0131ULL,
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
		0x7E682F8FCF359E90ULL,
		0x1B8E811D3C671DFAULL,
		0xB08A66CE27AE48A9ULL,
		0xC13A5B3C5A4CEAE9ULL,
		0x7102B85BA96C4075ULL,
		0xB9CC470A48049E83ULL,
		0xF70AD5575AA3141FULL,
		0x17C3CFDC8AEDF771ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD90EEA1786A0D2ABULL,
		0xCBF8CB5B2442ABE1ULL,
		0x10CA9B7E30E0B79CULL,
		0x6C62FC157EA44D87ULL,
		0x37FE683C0074CEE6ULL,
		0xA1CE4C4C37659DE6ULL,
		0x5179B748D7412E8AULL,
		0xD7BDA8BD9CCD2FCEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1BFD2A2B5D4FA2E4ULL,
		0xDF48EDF88FBE896FULL,
		0x334A41777755A52DULL,
		0x55C12DBE34863FADULL,
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
		0x1A6A5C9C610BB1A3ULL,
		0xA3911D0BE9033127ULL,
		0x76D848C52EBCBDF5ULL,
		0xC604803760C9B02FULL,
		0xE46380989D933E9AULL,
		0x6793A703E173A7A5ULL,
		0x05F36153911CF2DFULL,
		0xFE40E210F8BED5E6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0B999D99570A0542ULL,
		0x05B0D9C77CD3545EULL,
		0x93D319E510674EA0ULL,
		0x4D39CAC370796217ULL,
		0x633E2DCFE054C38BULL,
		0x2AB11C9718F9E2D2ULL,
		0xB28E6BF1D96D5870ULL,
		0x054E11CFB362A2C3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3A5B08CF2147F619ULL,
		0xA780CF6A2E43142EULL,
		0x44019B6162665BD8ULL,
		0x6CD59F243BFFE530ULL,
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
		0x5F414E76E39FD406ULL,
		0xB2BBB6AE526F5686ULL,
		0xC40C32955E7C3F8CULL,
		0x31E33B95EC189407ULL,
		0x216A852C8E281B85ULL,
		0x6B239B3620128051ULL,
		0xB1286EECD6155A30ULL,
		0x41F5519745308080ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4F750A8D3F7A837BULL,
		0x5AE370011972CD61ULL,
		0xD2F04674C865CD2AULL,
		0x27CDD118ABC04D94ULL,
		0xB0E0B05EAB7B782AULL,
		0xABB220A6E616CEA3ULL,
		0xCA488211231BD947ULL,
		0x6DDD41B467EF8C6EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC441DA7949C58F16ULL,
		0xC2B077EFD458E8E3ULL,
		0x365914BD271F94EEULL,
		0x05A7C62A17FC811BULL,
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
		0xC8524D8A45E6BB0FULL,
		0x75FCE2BA5442AD10ULL,
		0xE04AFB2C9C6C155BULL,
		0x14D765210B7C18FDULL,
		0x01BB9AEE3BA0041BULL,
		0xC504ED84213E338CULL,
		0x1B5A78803F970E6EULL,
		0xF0B4FE7F93A69661ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1E09428AFDC58E30ULL,
		0xCBFBEF67BDF07556ULL,
		0xC19C61FB55B40F3DULL,
		0x67AA1BE8E70E5FBBULL,
		0xD2044BAFFD531892ULL,
		0x576816DE18CF95AAULL,
		0x5FA445FCE995C7C2ULL,
		0xB8BEB04723114DECULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBF7ECE3C878C2452ULL,
		0xEF48CFF7D6BDA727ULL,
		0xFBBA18B00AE883B5ULL,
		0x7BBCE598DA967A95ULL,
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
		0xDAD0E27D54D5377FULL,
		0xB9FDDDED2E3A0FE1ULL,
		0xF9FFAC9A11AAABB3ULL,
		0x0193B52759B4D28CULL,
		0x780E59C6A5B5A266ULL,
		0x47BE903BC40BC94BULL,
		0x8FF639DB8E7030DDULL,
		0x5FACDF2DFACA5011ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB2E0A2E966EBF524ULL,
		0xF93843DC83E828C2ULL,
		0xEA1253CF65DE36DAULL,
		0xD4F01DD05050705CULL,
		0xEA15EF0E8AAE6269ULL,
		0xD5AABD0C5E682702ULL,
		0x0E76292065A25591ULL,
		0x3680F310DFE4562CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3AD016E7F0FCC2A7ULL,
		0xAFB6F319C09BFDE4ULL,
		0x48EFD492BA5B020BULL,
		0x4928A3A907877A41ULL,
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
		0x6C123D23AF82F07AULL,
		0xE2986545CE59DB78ULL,
		0x4F785D42D970D3FAULL,
		0xE580C3D4B2376864ULL,
		0xF59984F2661E8161ULL,
		0xDE2291DD02E6ACC1ULL,
		0xD3F74EC4F8010CAEULL,
		0x62BF7154A170FC6CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0EC74B980FCA91E6ULL,
		0x1B47A2CB1EC98D50ULL,
		0x5800E6FB7EC948ECULL,
		0x03DD0B2F4C09D7A8ULL,
		0xBB1FB37FE7E0FDDAULL,
		0xA5292F5788EA8343ULL,
		0x4D983C75B680D3ACULL,
		0x6156AC7BFA8C87EAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0B60088A5CD9E4C4ULL,
		0x3C55624ACAFE76E5ULL,
		0xE9942E0B13B00163ULL,
		0x1730F0CE2C16DC1BULL,
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
		0xA692C95EF2DDF16CULL,
		0x4003D84509D64542ULL,
		0x1A8AF9B8C6228FFCULL,
		0x244CD0D428F4AA0BULL,
		0x3F967A15FAB69E1AULL,
		0x72B1336B8685DF9DULL,
		0x0A9A3D0C5FB0757CULL,
		0xC4DFFC2F21F4A5D8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x50D845010D9BC0B6ULL,
		0x00C3CD15CAFDA915ULL,
		0x81F91D8BFFE2BD52ULL,
		0xB13CF3D8AA828182ULL,
		0x178231FD02827350ULL,
		0xA52339B815E3AD56ULL,
		0x56520FB994E47951ULL,
		0x0F4E64E8BAB506E2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x48BD3812BD008E8EULL,
		0xC2531BD1F6EC12BDULL,
		0x5B489676E0874104ULL,
		0x66AC516ED1E3C101ULL,
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
		0xA6E90CE12BB35EABULL,
		0xF5E379BC84D499F7ULL,
		0xD95526D70C08DDBAULL,
		0xA28C8D463E1043F6ULL,
		0x527C0C7B21B92F2DULL,
		0xB3ED8582CD3D0EC8ULL,
		0x3598B0CEF523363DULL,
		0xECA79934F3952B1BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x12F61B7427246A5CULL,
		0x0F02ADB38918B2A6ULL,
		0x93CCAC6871F42C85ULL,
		0xD7DA054A196671AAULL,
		0xA30B90C73350B762ULL,
		0x30C4E74CF4A1EC6DULL,
		0xC8503DB7D362EF44ULL,
		0x8CF64CA3DE12E85DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9EA54E226810BE72ULL,
		0x5EE8480722C300C7ULL,
		0x7E498FDD9C9F3A3FULL,
		0x7F03E58555FFBA6AULL,
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
		0x6267F0E86073862DULL,
		0xF5A9FA363F5281AAULL,
		0xE0061F5739A8BF68ULL,
		0xF2ECB0BE713A4FB8ULL,
		0xB359ABF544141E9EULL,
		0x7B51FE10B3EA9DA8ULL,
		0x71170E2B21EB138DULL,
		0x04CBFDE9467E20CAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x88B4D7E1E68D817BULL,
		0x2C16E30EA4D1D6DBULL,
		0x88081822FB6399AEULL,
		0x021EDBD302546DC0ULL,
		0x4CE8213370F8F1BCULL,
		0x709A2D0A441D3756ULL,
		0xCADC23CF4DB2741FULL,
		0x841D2324ACBF1488ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0E8DB1CBCFEEAB92ULL,
		0x60DC1E1C32FDDB0AULL,
		0x04BCD0D5BEACD010ULL,
		0x0AC24E1A4141B3B7ULL,
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
		0x4C5F1B5A11944C04ULL,
		0x88BBC4479CAC8F7CULL,
		0x94C7D39857CF3D96ULL,
		0xDFDD97A79FB1793CULL,
		0xC756A35DE9FBD254ULL,
		0xB0F34E13846B983AULL,
		0x8B0AE493B2D08D9BULL,
		0x5AAE433B8B966992ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCD5D6EBA9489BB99ULL,
		0x05796DA1794D2D53ULL,
		0x374480ECC3AD55E5ULL,
		0x2E2A154ADAC18DE1ULL,
		0xAE469718B8726C1FULL,
		0x7988CD901B069FF9ULL,
		0x06999DCA3899EADDULL,
		0x1B546B0350598DB6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x37637EE4D76FBDC5ULL,
		0xBD116A27C85C3BD2ULL,
		0x0653D493B83E0FEDULL,
		0x19099AB58FF88E17ULL,
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
		0xF7FBBC57424A135CULL,
		0x227BAAF38BFBBB5FULL,
		0x624B2D69FBCE5FEFULL,
		0x98F2B38052906536ULL,
		0x65F75C6000A28452ULL,
		0xAB987CB0BE36C864ULL,
		0x02579C1B70EBA7B4ULL,
		0x6C1F74BD65F5DBE7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x07B363507F909173ULL,
		0x8CBA62E486F7CFDDULL,
		0x2736489D4B9EFC91ULL,
		0x2CF423CD003C4341ULL,
		0x8DE1DF0050634AAFULL,
		0x16C6E113DA66DE72ULL,
		0x73EB5BBD10FCC051ULL,
		0x3CCC63453F819690ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0378F53AEC1C1125ULL,
		0xACDE6158D5E0A569ULL,
		0x5F2672CEEDA5BC25ULL,
		0x7253278907966CCEULL,
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
		0xA0B601079FC80AC6ULL,
		0x6E1318DA3BAE3701ULL,
		0xDA11C5BE5F6D388CULL,
		0xECB8ABF8E0778CC5ULL,
		0x390131AA94EA1782ULL,
		0xBE701074C80557A9ULL,
		0xB9E2EA8C52D8576CULL,
		0xAA8E3B0519D448F4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7619AD6035C83945ULL,
		0x1612A85588B11A07ULL,
		0x31FFCBAE5D5F0ECDULL,
		0x5A03A22B068FBA53ULL,
		0x838880CBBA6668BEULL,
		0xD42131440186B70BULL,
		0x322A6B6F10A4F08FULL,
		0x019ABCA2FDB6FA07ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1A8694BBD98BC662ULL,
		0x1FB591C229C8F463ULL,
		0xCD74D867D5AF6E8AULL,
		0x26D9CC5E064189B4ULL,
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
		0x21853542FD3CB715ULL,
		0xC8E22AF9779287C1ULL,
		0x8DDD53EF5E0131D3ULL,
		0xB2F7295B3EADA0C9ULL,
		0x0D34FF82A593E77DULL,
		0x321C3CDBA2A95799ULL,
		0x26E358810E407D07ULL,
		0x9A33D447D3006356ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6C54D58EF47B5511ULL,
		0x0CC005E4BF14C732ULL,
		0x009E10F06DC99C42ULL,
		0x5C38D3287E9B25CCULL,
		0x82081D1A2EE545BBULL,
		0x386B8EAF10C4EE1EULL,
		0x1B933EBA8003A548ULL,
		0xBA444E486A264647ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5DD9FB35A6AD6425ULL,
		0xCC5BFFB2606568BFULL,
		0x3B2316780D3F9BEAULL,
		0x144C3A1C5072CB39ULL,
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
		0xE033AC08A0966983ULL,
		0x02CD3C572914590AULL,
		0x228B8CC7B19D53ECULL,
		0x5B0E04E6D8CE8962ULL,
		0x3E9EE405ED7943A6ULL,
		0x23F0BE37E94C3C93ULL,
		0x810BA80ED1CA7019ULL,
		0xDBFF6FDA37C0EAAAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x167C80F1B573F464ULL,
		0xA05D0956DC5DCBCEULL,
		0x764245C366783412ULL,
		0xC53AC5DE6CB64837ULL,
		0xA20F71F9D518AC94ULL,
		0x9C46100E0C228C59ULL,
		0xA03EF10F8C0DC632ULL,
		0xC615066AF9A95DAEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x070218E28978E22AULL,
		0x85C60D3720E6B5CAULL,
		0x0AAC70E8A5265811ULL,
		0x569EE58BA3972E8EULL,
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
		0x62D3F9FC3343504FULL,
		0x9F84020108E4D49BULL,
		0x43FA909E66DC47D4ULL,
		0xBB1926BDF8BBB01FULL,
		0xA0214CD69C0912D9ULL,
		0x5FFD2B283B026E3DULL,
		0xC686DF1AEE7A282DULL,
		0x31C889886256CBF5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEB0B5ED2521A3413ULL,
		0x0EE1777F151E0EC3ULL,
		0x1BD035A7A0710419ULL,
		0xB3F1DCDA87D601C1ULL,
		0x1E2AC9068ACCC87DULL,
		0x6528A45FB2604323ULL,
		0x0E977C851BCCADA6ULL,
		0x28ED9692A5A807F7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC2602C0C701C260AULL,
		0xCC2E8C463BD92BC6ULL,
		0x75B2FD340C2B73C4ULL,
		0x57A75A5D72D6C62DULL,
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
		0x39945426123C751FULL,
		0x780E447B8CC1CA3DULL,
		0x358D8105735578A8ULL,
		0x345258C3D83DD34CULL,
		0xD73FE9F309E6EDA2ULL,
		0x24D6FD0481281323ULL,
		0x8C6C17646D7AD18CULL,
		0xB8A185CF07E593B1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x88A30BC6A74D9626ULL,
		0x538274176E1154C3ULL,
		0x0AB5630C8B0B09D0ULL,
		0xB1CD5BF9FCEA223EULL,
		0x7A5157C4F55F03DFULL,
		0x832F14AD0A896DCCULL,
		0x26FD0CD595C1BF94ULL,
		0x0F1D1730121F6990ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7C5AFB36771B958EULL,
		0x23784D5FBA3D0071ULL,
		0x3953AF2CEDC3199AULL,
		0x2C2D686256BDF203ULL,
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
		0x2C9A3585C50E511CULL,
		0xF2C0E0814DB6CD53ULL,
		0x9D42245A696BB595ULL,
		0xB9C2ED4A05A60E2BULL,
		0x45A79A0968B3C107ULL,
		0x23CAE1D9ABF6840BULL,
		0x4F16E1D6EEBB7976ULL,
		0x3EC0B6B15EA90191ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7F04C26F777AC404ULL,
		0xD250272DFB22DF24ULL,
		0xE09F1E4897E592C1ULL,
		0x6FCE44865A034A40ULL,
		0xBC661F326852BEE2ULL,
		0xD1F885D7F57764CEULL,
		0x66B88A905F09D103ULL,
		0xF8F61C2592555926ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0D4DAF005BF9DA81ULL,
		0x45AA61946972912BULL,
		0x3AA3FA8B25E523CCULL,
		0x26079984000DC3C9ULL,
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
		0x265B56F25CF5C3D7ULL,
		0xBFC203E35109B8F0ULL,
		0xE27DC081E0B9CF92ULL,
		0x92E437DD06200885ULL,
		0xBFAD906EF0B896CEULL,
		0x58FABF4285C81EEDULL,
		0x8892EE35636268A8ULL,
		0x48BF4740244C75EBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6B95720ADED31ACCULL,
		0x56409D5A219C95CAULL,
		0xF5D3CBFE4C287416ULL,
		0x01182E4A13D3FB5CULL,
		0x905523A2D736E220ULL,
		0xDEC168C5912ECE2DULL,
		0x99AA75AB6BE75655ULL,
		0xEF3E3FF8566E5130ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC1E60B334763773CULL,
		0x8E043D157E2F1FACULL,
		0x632BD8FE50D613BAULL,
		0x5AF31E3B814580E8ULL,
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
		0xF2844EBC2CFDDF01ULL,
		0x63C482D929486A31ULL,
		0x37A107BB035E51D7ULL,
		0xB3D14FB9EF240C03ULL,
		0x3AE1DE41D1BE9F1EULL,
		0x479CAACA20635E0BULL,
		0x9292FF09BCC0CA2BULL,
		0x0FF3242BA0E849C9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9F11F7FB48F18185ULL,
		0xA54A5B6C0A2AAAB3ULL,
		0x416C0FF2432DFF4CULL,
		0xD83E1C23347EC000ULL,
		0x5A4D47BC1371D121ULL,
		0xC362E2F13653D9AAULL,
		0xE8ECC8EA4612220EULL,
		0xE83DC1584E557BF2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA980AE9B2372EC37ULL,
		0x5F0DD19FDD6B65DFULL,
		0x24E100745E1D46C6ULL,
		0x407FDEF4FC6FD9E0ULL,
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
		0x4D894F19EE89273EULL,
		0x04246E7A383BF043ULL,
		0xD7FFB67B7EC28D64ULL,
		0xA3BE89DB2AF281A0ULL,
		0xA32B431C837FCEA3ULL,
		0x465D2CC5FC97A5CAULL,
		0x03689B147EDF9323ULL,
		0xCAE5EFC02ECA3D25ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBE443CFF07C26D83ULL,
		0xDC7C2F3113BE1D12ULL,
		0x974CAF9978B2CCC1ULL,
		0xF42486AE6514A3E1ULL,
		0xCACB6E19CD74800EULL,
		0xD751F74D99477FC2ULL,
		0x6DF26B36CE85AA7AULL,
		0x83A469A9F13150EFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAD7EB081EC746555ULL,
		0xA3522F27E263785AULL,
		0x703E21CA336849A2ULL,
		0x4353EA79EA90EDB3ULL,
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
		0x021CC438533482F0ULL,
		0xAF628BE5A4AB7C61ULL,
		0x461F625F54FD9F9DULL,
		0x6CF11F0A995D0875ULL,
		0x91017ECE30133F09ULL,
		0x3E9FAE72812C2DB1ULL,
		0x2C0594FF10D8AED6ULL,
		0xAA523706DCDFCE9CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x289A110F4DEDB7B4ULL,
		0xA449BF873F5E95C5ULL,
		0xCA91EA7A455CC240ULL,
		0x124ED8604295D1F6ULL,
		0x7289DC04117E3585ULL,
		0xE1053B961DAFE001ULL,
		0x697865E2AB37EA60ULL,
		0x0DA71B512EF3E72AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5F44DD298F663851ULL,
		0xF005D91529C06EC0ULL,
		0x5C82761C257E06C8ULL,
		0x1C0863A227CB9161ULL,
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
		0x2D1A95B74985791EULL,
		0xAEC6DE327E0899B1ULL,
		0x06459D3E283BC4C7ULL,
		0x512E872EA39475CAULL,
		0xA1CE6D349FE5FD19ULL,
		0x83625F9F17827F0FULL,
		0x0ADAD4CF04BA12D9ULL,
		0xA1B000A65BE70760ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCFEC64D566DAE717ULL,
		0x1BEDC3EE97A0B85BULL,
		0xCC200F4C82E7F5ABULL,
		0xEB362B0F09266171ULL,
		0xD8606746B08A044AULL,
		0xB36EE9C68522B958ULL,
		0xD57EB64B7C480C04ULL,
		0x05FAE5393BB26B8CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x438312336A518418ULL,
		0x70FC9869A09F3A77ULL,
		0x25D21577E640D2B3ULL,
		0x02DA6E52623D35B2ULL,
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
		0x7321EFC2952382C0ULL,
		0x66F72E3D22BFFE53ULL,
		0xC1AF669DC7CC62D4ULL,
		0xBA4DDE94B4BA83E3ULL,
		0xD6CFE2E3309ED7F2ULL,
		0x7CF35867D7DEA0CCULL,
		0x6BC5735BC4C460C5ULL,
		0x1F6E85B24E425A00ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB266E2D1EE3D80F6ULL,
		0x02EC6327F244B9D4ULL,
		0xFDED75AD61E4C8C1ULL,
		0xB122CBAAE8EB3A8EULL,
		0xA600ACECDBFABA1FULL,
		0xDA74C81027CBD413ULL,
		0xE755FAB6302B6FF1ULL,
		0xDC130500A00169CFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFF7D0F8137426AF4ULL,
		0x82D438195345A7FBULL,
		0x6C4DD984749B597DULL,
		0x08C02D49A972F088ULL,
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
		0x48B55AAF1AE9E154ULL,
		0x1945AA6F9C7E9964ULL,
		0xACA5DA2B54EEB31FULL,
		0xF3337160C7DDEC47ULL,
		0x55D242F3F3849CB5ULL,
		0x8ABD9BDE1EE05149ULL,
		0x8966663B81EF7218ULL,
		0x2E061DB5CAA859FCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFEFAC73B83F17D82ULL,
		0xB5BE225059723214ULL,
		0x5CE08CE4B6E5F56CULL,
		0xA0453A6C0EF66F2CULL,
		0xE8ACAA8F73214805ULL,
		0x9172F94A4B13AD12ULL,
		0x15E863782B563E6DULL,
		0xCE2CF3CCB065C853ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7D4F325EA5B6F275ULL,
		0x649BAA10B36CC763ULL,
		0x7479B64578C66913ULL,
		0x0D2A6F8E9EC91C42ULL,
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
		0x05A774C6DE610287ULL,
		0xC3B1BA906F046390ULL,
		0x06AE5A74239813E7ULL,
		0x10993632ED16EF69ULL,
		0xA2281DCBB5277F52ULL,
		0x304849874B45894FULL,
		0x279086983131ABD7ULL,
		0x106D7D260CB4F909ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE9BC5E29CADD113CULL,
		0x8C221523E816CC12ULL,
		0xB6370A146299A74EULL,
		0xE1F42A92AF87F371ULL,
		0x8306955534004240ULL,
		0xC8D88045962BB8A5ULL,
		0xBD3D76780CBF408DULL,
		0x0030D5E376F77FBCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBAE558343F570230ULL,
		0x9227852D68C290BDULL,
		0x18CBB52529FA597EULL,
		0x17A5DF8277AEFD4FULL,
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
		0x6ACF76A027DC032BULL,
		0x465BEECEC2EE3748ULL,
		0x309373DB9DD031D4ULL,
		0x8C41CDC8358BB3EFULL,
		0x5CED0C0DDFB89F61ULL,
		0xEE523BAA1ACF16F9ULL,
		0xB81754F2F17B9FEEULL,
		0xB8F0790A554928A1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x01C62FD97A805CB9ULL,
		0xD6D0317E7259EE23ULL,
		0x79A23E83D63D0BF4ULL,
		0xA3BB9AF24F3F5CD2ULL,
		0x1694EFED43949CFDULL,
		0x0C1A16FAEA9203E2ULL,
		0x08A2C984E1FA1E04ULL,
		0x12C4779A84B35189ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDA1D739DDAB404EDULL,
		0x03E12F5179A51E99ULL,
		0xC23DE7AE14CC6EBDULL,
		0x130E696EDC8A44C6ULL,
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
		0x32EE14C060CDAFB9ULL,
		0x92A051E1B1688D96ULL,
		0xF80F0816285A95D7ULL,
		0xA7B82B8B8472B12DULL,
		0x3AE058332F3C624CULL,
		0x0017D84D910CE446ULL,
		0xE096072DA206B248ULL,
		0x8B58E0E8AF3649C2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD465BA26614065F3ULL,
		0xC5C01E5F68B55436ULL,
		0xAB7FDCD2919E9FC8ULL,
		0x70A9F8EF78330D90ULL,
		0x817E90B10ED669C4ULL,
		0xDE7A7C37E073FE0EULL,
		0xE06F42BE6A1570FAULL,
		0xB62AC0DB1528E6D4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE30BF7EACEB02CFFULL,
		0xCA3BDEBA7F6565A4ULL,
		0x525053C5E48BA781ULL,
		0x5BE6F4A0EA3C52F1ULL,
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
		0x153ACCD48B230D26ULL,
		0x2DF2B93D05D323CDULL,
		0x657BFE65CEB4B79FULL,
		0x989549954D3A862DULL,
		0xE7BB5B67DE21B912ULL,
		0x53BAFA646B23C349ULL,
		0xFC2CDC145643000FULL,
		0x8DC8BF83399428B6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDF9194F0E307BA0EULL,
		0x3951B29AEDBB9052ULL,
		0xD5B12E4CFF5C62D5ULL,
		0x2EAF4EF8F19B18F8ULL,
		0x93133CF7E3454B5EULL,
		0x2C6CEAFA3FEF126AULL,
		0xC905B8C146C341A1ULL,
		0x4B6F3A1AB1BEC515ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC69DBC82E4D39D4CULL,
		0xCA37506481E9D4A0ULL,
		0x279A0E6D1C4E9923ULL,
		0x432FC820854C3722ULL,
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
		0x48C05891B1BC8D7CULL,
		0xBA461E9C864E6D6EULL,
		0x27B2197CD8836888ULL,
		0x119209A5ABE9329AULL,
		0xFA1911883D21AAA3ULL,
		0x776F5D0B46EAD349ULL,
		0x41A169DD8633E53EULL,
		0x52721B1B7AAB1D75ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x91C65403C9F1842AULL,
		0x67319F560ED23543ULL,
		0xD15E328C67806893ULL,
		0x3EE8263D1FB0D398ULL,
		0xF0B1CB84ED1B6E46ULL,
		0xD293259BFC86B634ULL,
		0x3826CE62BBD6FD8AULL,
		0x1CDD02F5830A7E5EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1C4E690BC8B8003DULL,
		0xCBC4B9CB8258894AULL,
		0xBE86FB2A7ACD649FULL,
		0x46CB790B4E0FFC6CULL,
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
		0x84834889C8EB4698ULL,
		0x0AA4562611394BB6ULL,
		0x047E8B4223230555ULL,
		0x5F3D4529AC5823F6ULL,
		0x6008631A190E0EB1ULL,
		0xEF860E89545A2521ULL,
		0x627FFC3DA13FFD60ULL,
		0x4A18331579A9CF13ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2C3DC60F8F2717BEULL,
		0x85D03ACADBEA5CE5ULL,
		0x8DF72F389838FB32ULL,
		0x2C518511AD086F00ULL,
		0x55603E58699B977EULL,
		0x75C3F89F7AB3C7E5ULL,
		0x077519F11E67B87BULL,
		0x2233FCB5C3951535ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xED3AF73A44C1E150ULL,
		0x97A35C118400C5BAULL,
		0xFA24F364F7044432ULL,
		0x1ECBD24D06634BF6ULL,
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
		0x21C8A68D97B6AF99ULL,
		0xD74E6DCF8F3994E6ULL,
		0x2631C7D060BA2404ULL,
		0xAB282E75F5966C6AULL,
		0xB93C9F4A68630926ULL,
		0x491C1CED63900F99ULL,
		0x5499062646E6945DULL,
		0x710415B8968CB769ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE08537028C68EE24ULL,
		0xA28F42FFF2CAFEA9ULL,
		0x69D5D051288647B9ULL,
		0x3524E0C0A3288F57ULL,
		0x7E437C9CF41A41AFULL,
		0xE721386865D0B9B4ULL,
		0xD7CBAD242CD0C4EAULL,
		0x69E7191AC95B5B5AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x023E954A4E1B5D58ULL,
		0xBFFD168D46D55643ULL,
		0x42D72DCF1770A745ULL,
		0x0450CD21C7C18739ULL,
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
		0xF8676E86862A7332ULL,
		0xADAF23708C3434ABULL,
		0x1CD5DE9CDE5320DAULL,
		0x396A1F8877704535ULL,
		0xCD35E45474C5EBF3ULL,
		0x0EABD72B3388ADD0ULL,
		0x0B6EA370DF846812ULL,
		0xBC560D6AE11E12B0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB2CEB2C5DB084FEFULL,
		0x5916476EBFBE4AF2ULL,
		0x29B5A602B176D457ULL,
		0x26FE751BFAA8F3F2ULL,
		0xC7953A2C09699F2DULL,
		0xEE574E5EBAF7317CULL,
		0xE1593E7BF7F34CB4ULL,
		0x82DE239B86197A50ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1B71FDC09AD589EAULL,
		0x21252A5BB20E5E32ULL,
		0x324D34F48C665C56ULL,
		0x1A385F33FF75EF63ULL,
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
		0xD3B5EA1E1C493DA8ULL,
		0x1D83576D486DF19EULL,
		0x41F64772356D7CE3ULL,
		0x8EF8929F3C369BC6ULL,
		0x081D35140FA106DBULL,
		0xF61907AD2C6EFD90ULL,
		0x243F06A22B744D0DULL,
		0x784621BB9BD3D7AFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x011DB09A0EA7B25CULL,
		0x75A3753DC5321441ULL,
		0xD2173891A6AD2838ULL,
		0x4E3078C2C659C047ULL,
		0xF4A141550E2F3E31ULL,
		0x62B98E430B942E15ULL,
		0x6891D106E225D2AEULL,
		0x59FD90993DF90A19ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB6FE67DE44855533ULL,
		0x880BE7F063B6A97CULL,
		0x4B9503ED70667EDAULL,
		0x3F8DA4F664575FB8ULL,
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
		0x3D8B95EB4562148AULL,
		0x035515D071F28FB7ULL,
		0x73EFD03ABE9EFA7CULL,
		0x7D88B8CA402EEE43ULL,
		0xEDDD98AE6E4108F1ULL,
		0x288128321146787BULL,
		0xB56EF8F564DAB674ULL,
		0xEB500B92937C3EA0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3A0C2F5D4ED05951ULL,
		0xA6F396A7093D7FC8ULL,
		0x135EA19453A716AFULL,
		0x28FE7FBD12129356ULL,
		0xA00F16A1029DA40CULL,
		0xA398D2C7DD385820ULL,
		0x4677337691743A67ULL,
		0x9FBD589A6DC26EA4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9026B48BF0D2B6ECULL,
		0x16DE2CED22CDDD7CULL,
		0xD9587F79CC2E4DA8ULL,
		0x0C50C9E2C7B13A65ULL,
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
		0x2D148C190D76CFF0ULL,
		0x389F43C29DB4B4D6ULL,
		0x6522F3A2EC869FD2ULL,
		0x22061D1D86E4B722ULL,
		0x2C7CE56128EDAB46ULL,
		0x19677D60813E7435ULL,
		0xDB472817A2FD68EFULL,
		0x4EEE8FA584C609AFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2D406D0CFAA4C057ULL,
		0x1AA80B1B96C65D35ULL,
		0x8852DE0037A3A406ULL,
		0xCC794D31651A0FEAULL,
		0x68808A03150E2834ULL,
		0xF2A9CB8573680FD1ULL,
		0x1CA216D4C5700E90ULL,
		0xB562FFF37DE8A7E1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1749AF0305FF81E5ULL,
		0xDE1F9F2B14C13E70ULL,
		0x2950A58F97DE65C5ULL,
		0x2044245926A72BE8ULL,
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
		0x7BFD21E6FFA7581EULL,
		0x6360BD8BA6532CEEULL,
		0x49B81111E2A28A99ULL,
		0x510920E71EC0ECF8ULL,
		0xE4611A06B18CCC5BULL,
		0x444595C117CC8B81ULL,
		0x772A0C722BB02A9EULL,
		0x0EE617ADED84EC0AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3510B94DB69196C9ULL,
		0x5F8F279296ABBD3CULL,
		0xDE5C83089438C130ULL,
		0xA333DCEA64BB67E0ULL,
		0xF40B56C4A7B067CEULL,
		0x6D750E78B978CEC5ULL,
		0x2C19F0873449723AULL,
		0x443A0F55885EDAA1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF3A76466BFCCAD00ULL,
		0xE6C5AAB710157397ULL,
		0x8FBFB2EA07A9283AULL,
		0x435E811BBDAC1AB8ULL,
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
		0xE785BBC2A2E7EF85ULL,
		0x43A2269F6C468E06ULL,
		0xB392FD7C8A8A34B5ULL,
		0x93D74693EF53E8E8ULL,
		0x6615F96C86959B2DULL,
		0x7892E5F6A65EBEACULL,
		0x230ECAED32397389ULL,
		0x1305031BB3EED9D6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8E73083C5AC904A2ULL,
		0x68E96DDA34B8CB3DULL,
		0xB8E921E352742012ULL,
		0xF1768C110F349D88ULL,
		0xC18B2E2F90B563A3ULL,
		0xA021546136838A1BULL,
		0x032C0EB7428F79EBULL,
		0x8580543E55C2F6A1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC5ACDE92C76726C6ULL,
		0xFB9454F3D2179041ULL,
		0xB651CB9ACB512210ULL,
		0x2412AF5EDAA30542ULL,
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
		0x5EC7E0BECB535206ULL,
		0x88BFDED57FD64A60ULL,
		0xC0C5C58444E16402ULL,
		0x27B0077027569286ULL,
		0x1365EC2CF1E1E976ULL,
		0xF4A47408D1D03778ULL,
		0x26C8E1131D59CFF3ULL,
		0xEA7A8DACC3C9C4CAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC660ABA38F49F9D5ULL,
		0x52C0644791CC689EULL,
		0x49B76E5A340BB3C8ULL,
		0xE2EF5CDB9A6E8C21ULL,
		0xB3DD04A3512EFF1AULL,
		0x01166AA179D1C72BULL,
		0xB94737E169068892ULL,
		0xD533AA473CA21DEAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC6B9938916982225ULL,
		0x5D14DFE4FDCE8D17ULL,
		0xB84D748AD53248C4ULL,
		0x6D466BA69CCACB8FULL,
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
		0xC6F820EE71B1942CULL,
		0xF7780C2CC808D0B7ULL,
		0xC97BF3FE7FF308F7ULL,
		0xD261412172ACDDEFULL,
		0xD1335E7313BA1C10ULL,
		0x92A37E66597346DAULL,
		0xAC7ED29714C86A4AULL,
		0x3EFFFB02C8DA6EDCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2DA8EFFBB5E41E2FULL,
		0x2CFC0E780E026A86ULL,
		0x1C6862893EA8311EULL,
		0xF7762FE9A36C646AULL,
		0x63BFD449D9CF5A77ULL,
		0xC8069975379EBB6AULL,
		0x19E8D27950E5F6DEULL,
		0x8F4B8D2A1E9C35D9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD875B31154A630D8ULL,
		0xDDC5F97FBF9318E1ULL,
		0x6F5795E054E7F9D9ULL,
		0x6FB35F61147CF00DULL,
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
		0x8CF6FC1C38A58D7AULL,
		0x298940EE7FAB1951ULL,
		0xA6FCBE6803718B8AULL,
		0x62AB447B254D9804ULL,
		0x846B5DD8F261CD02ULL,
		0x2F32439B88D3A350ULL,
		0x2113951743ABDA15ULL,
		0x7E44EB56F546A693ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4ED1EDC3E36458EBULL,
		0x9E1CAEEAB6426F64ULL,
		0x51DEAEEBBA2186F0ULL,
		0x2BAA26F6E90908C5ULL,
		0x3DB184C01CFC87ECULL,
		0xBDCEAAF0A4FAC7DAULL,
		0x9A21BE6DDDF4F97FULL,
		0x7C05E3C86CF932D3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBDBB4808024975E6ULL,
		0x60353B619B993D7BULL,
		0x5D03ECA162755AC8ULL,
		0x0C5C3CAC77C3BDADULL,
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
		0x34B841C09E468967ULL,
		0xC0A139B1B343B175ULL,
		0x154BD7B910844747ULL,
		0x50D5AD83D6A45215ULL,
		0x3A015BFDF07DEC44ULL,
		0xFD4BC525B2675F1AULL,
		0xE36742715BD932B8ULL,
		0xF15F5B6A57436297ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x149BA5C944FA42E1ULL,
		0xEAC05238FD74E153ULL,
		0xA9BC10BFB865C850ULL,
		0x7EC01DCF1B4A5C72ULL,
		0x63BF7EC3A878DC3EULL,
		0x7C25EF99F01BD2AEULL,
		0x6AF06C176CCE72EDULL,
		0x3D83664AE732E708ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEDE3729E0A0CAB59ULL,
		0x017E9A378D05A823ULL,
		0x4D339852D3B6F72CULL,
		0x04BBF25F5DCC4CEEULL,
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
		0xAFC3897439479BE4ULL,
		0x5366A3347766E566ULL,
		0x21B3E64BB2907193ULL,
		0xCAD64F3B8863C2D5ULL,
		0xFF4C34091ED04538ULL,
		0x5A1B2EB95F1C0595ULL,
		0x6E772557CDF90CC3ULL,
		0x6F633D059D7B1F84ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6B8B214B59AFB1A8ULL,
		0xBA0B902F92254357ULL,
		0xE087D3CA3EE52A57ULL,
		0xBBEC6AF64AEFC6C9ULL,
		0xFE090F73F21EAA72ULL,
		0xCC414B9DD9C49F33ULL,
		0x9D70A1D65C9F8E18ULL,
		0x57508BE4A1AEA630ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x742FD64D81F4E425ULL,
		0xA7B2C91AB03AD49BULL,
		0x482397B846F4148CULL,
		0x21B02F2A9DCDFE7CULL,
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
		0xB9F3A505CC2355D0ULL,
		0xDD5914FD8C39A56BULL,
		0x909B8C0623FB7245ULL,
		0x46D5FDB4A3AE5380ULL,
		0xF6BF6057B19134ADULL,
		0x0E650E9CA7286369ULL,
		0xEAB545F87CA3A547ULL,
		0x938D8EE660C504E3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x48D273EB531281BDULL,
		0xBFD81BC01F2BC841ULL,
		0x3BDCC1F01C320B04ULL,
		0xEED79AA140B5EF8AULL,
		0x8F60BF67FCDB34E3ULL,
		0x6C8FC4F0065B5548ULL,
		0x13E4510041FF9441ULL,
		0x9FEEABEC3DF31C43ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC92D14AF4C14CBB0ULL,
		0x2329E8DD4B7DF61FULL,
		0x37C326EEBC23EE17ULL,
		0x019414348E20EBD6ULL,
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
		0x0FF02C278EF7A53EULL,
		0xA1821676FD3A4B4AULL,
		0xF58B9A7DDB7D595BULL,
		0x7C23B239C99DB06EULL,
		0xBF0D5694AA4A4F11ULL,
		0x1D828BB47E9156C9ULL,
		0x808380F7182E002AULL,
		0xE05CB85FBA7251E4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x106AF95F892C1372ULL,
		0xAE1F5457C06D3AB6ULL,
		0xD28A91A7DC4CB1D5ULL,
		0x26B465A6AEA0C042ULL,
		0xF15EDF143772BDACULL,
		0x3361DC5B23F80A71ULL,
		0x167D237FC0F3E186ULL,
		0x771670C1BB8F561DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x876AEFD911CB2917ULL,
		0xB43CC962AF8E659CULL,
		0xDFF2E88CF1D133DAULL,
		0x75DDEE06F0AE4FC5ULL,
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
		0x42BB78FD64AB34F5ULL,
		0xC80DF52574D68EF7ULL,
		0x289397F9BF700F5FULL,
		0x1D6CD088CAB30BA8ULL,
		0x4AB02EA842440FA7ULL,
		0xE8C1F32617A06E8DULL,
		0xA72BBB86BDB406C3ULL,
		0xB91703C799ED5C6DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB7C553B961FEB75EULL,
		0x4591E8336BE90664ULL,
		0xA91D6DE582498DDFULL,
		0xBF0B11C6387968CCULL,
		0x7556FA03D38688CDULL,
		0xC70F674ABA9C9211ULL,
		0xF21327E257BE4849ULL,
		0x79D55CA3C1A4E9DFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3633F5AC72CE8336ULL,
		0x82FCCF81D78042F4ULL,
		0x611C147B5FA0C7A1ULL,
		0x42208E14ACFAA3E4ULL,
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
		0xE7040A502889B90FULL,
		0x5FF13C41B72B8024ULL,
		0x9A1806FD29C91397ULL,
		0xA780A9AE6900F7BCULL,
		0x5AB94F80ED9C4AAAULL,
		0xCA1CF08DD346E3DFULL,
		0x539BF572F7E95B13ULL,
		0x88FEF6023381077BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x337771D1524008ACULL,
		0xCC431FE6BA30459CULL,
		0xDE873AFF20AD87B9ULL,
		0x79D38188CDA6DB15ULL,
		0x865CF92DACFFB060ULL,
		0x29D1EE1D96501ECDULL,
		0x065B7295C6E977D1ULL,
		0xD937A2BB70400EB2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x394168DA6D889597ULL,
		0x5ED07904099C7B2EULL,
		0x332438D34F1747C1ULL,
		0x454384A696FF0A88ULL,
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
		0xF9808FD3FC329419ULL,
		0xF53E7F426D671EBFULL,
		0xCC900C1895E8201DULL,
		0xFE0368E753C4BD5FULL,
		0xA91789D2A09ADE06ULL,
		0xD2244DEC7D2C2E0EULL,
		0x959D6505AAE7E269ULL,
		0x30C128B8C1817ADFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC494E2B28B48BFCCULL,
		0x815A0EFDFE0DA224ULL,
		0x40B8B5E2578874C8ULL,
		0x87676A6C7A704C29ULL,
		0x019D4B2969BB11F6ULL,
		0xE8AFA0BEC8BD49F6ULL,
		0x6F54F298055D4BFDULL,
		0x34B61388362CDA30ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1110FA3F96221E9AULL,
		0x1B36250D37CF5844ULL,
		0x3A98527CD0F1FF5AULL,
		0x604123AF87E44B36ULL,
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
		0x8E1447BFDBCC3A9CULL,
		0xC5B2F19BD869F07DULL,
		0xA8ECD51885F57D4AULL,
		0xA1C0465894AD2F92ULL,
		0x2FFDA6CB1F1C75F5ULL,
		0x939878F5C9647616ULL,
		0xE7D9B7014E91A399ULL,
		0xD0E4F177DA5648C2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0BD34E8DD43D62B7ULL,
		0x6811CE8F36E553C2ULL,
		0x338A46DCE96163B6ULL,
		0x51BD78136134F32CULL,
		0xD87CC44F806C1985ULL,
		0xD132D9FC18DB9021ULL,
		0x70A326AF12C7464EULL,
		0xA6CC5B8F70F7AAAEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7F62978B95BC917CULL,
		0x38B6BC1CD5D6BF00ULL,
		0x277BFA707C9DF2ADULL,
		0x0FA90EC4D783B370ULL,
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
		0x58211B3E5B58918DULL,
		0x025C0412E3D86358ULL,
		0xE68BB62735176D25ULL,
		0xB0859B966371FA32ULL,
		0xD497F4220E7CAB25ULL,
		0xA9D67C86BED5622DULL,
		0x1C3E1F13C328B6ACULL,
		0xF76490B5FF05F59FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3BC1EDD63C1B1811ULL,
		0x80069105A840274AULL,
		0x37AC830C8A9CBC29ULL,
		0xAC943632606BE30DULL,
		0x3817EFAC1002432EULL,
		0xAAF7EA562CAF0D92ULL,
		0x66A3F15F56F6FF9DULL,
		0xE64ED21E512138CCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x575FD6EBE568E885ULL,
		0x575F2642ED48CB27ULL,
		0xA3C1FBE2B9DBDD35ULL,
		0x0D2BAFE7D2FA1E6CULL,
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
		0xBA03655DC7CBC4B1ULL,
		0x0A9F92A849503972ULL,
		0x44E5A5FD9D04CE13ULL,
		0xC9071F3F60DD0897ULL,
		0xE455DE9AC729CC6AULL,
		0xA0E742C8757A8F21ULL,
		0x4B496BD0E006E0EFULL,
		0x0140374C7A4F1083ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4C799C58BC1E1AEDULL,
		0x971A73633BBD8DE4ULL,
		0xADBE78EA3F6A4962ULL,
		0xE5592408392135E1ULL,
		0x60FF442F74E43EB5ULL,
		0xF0390C291B238809ULL,
		0x6BDAE284C52C6474ULL,
		0x25B4A64C93B476CBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEC64B4F34200B1BEULL,
		0xAD613AEC767DB931ULL,
		0xC18F8E5F5A08FEE6ULL,
		0x7A65813362AEA400ULL,
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
		0x457247AEC1FC8AD7ULL,
		0xF912FA0BE1A1C118ULL,
		0x55A377E2B921ED81ULL,
		0x5555998CE895E7FEULL,
		0xFF65DDB0DDA4B5B9ULL,
		0x3CFAAD9B0714916DULL,
		0x70A7A0C2A5A07C9DULL,
		0xE400EF3492A9510FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7386D48356DACDA7ULL,
		0x275B378173553C50ULL,
		0x27E737602B125315ULL,
		0x3566407E5C5614ACULL,
		0x1D00F0B3FAA3C128ULL,
		0xCC592516A579AF55ULL,
		0xFF07E0BC62BE36B0ULL,
		0xD774B1B17D9FE31BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6CE6A0B51D460AEFULL,
		0x89B20630EB4A1479ULL,
		0x0B72C1707BA5FB85ULL,
		0x7CC07A83ABA62575ULL,
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
		0x624AE2EB57F561A6ULL,
		0xF3E26DA211CAFC6AULL,
		0xCF2347EF511A93E2ULL,
		0x3C2C49BA7F461AECULL,
		0x3D6AE9FE48E48F09ULL,
		0xA0BA0AF52220E037ULL,
		0x3BC3BDFE2B059C93ULL,
		0x01794D64A3B87C27ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBC5D30CA3E30BB30ULL,
		0x07647A245EC8663FULL,
		0x6B3A5CF535FF3970ULL,
		0x5B528089BCD5E6B2ULL,
		0xC801FA1EB8D84394ULL,
		0xB910C5804E559844ULL,
		0xD699057D6C7DE796ULL,
		0xA368F0C62841FE85ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x13814D507B97D631ULL,
		0x4F9E42D5232F4428ULL,
		0x68404E16634037FDULL,
		0x574788B71606DA2FULL,
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
		0xF03B43376090CE6CULL,
		0xCABB458A108BC79EULL,
		0x988CF22C721F7955ULL,
		0xD320DF70B625B75AULL,
		0x38F4C9B9F24F9F96ULL,
		0xC6ED9CA509DD500FULL,
		0xB5E30105E71418B3ULL,
		0xFFAC2F6BEFBB0317ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5A27D17E634BE10BULL,
		0xA3D30AE53A45316EULL,
		0x3102DD3DD41ABE2AULL,
		0xEB9D4485B108EE29ULL,
		0xC8DFECDE76F24007ULL,
		0xAD78B72027DF0382ULL,
		0x7C2EC1E42A2AD167ULL,
		0xBABA54F7D4AF4D28ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x392C3A4D4D211E17ULL,
		0xEE424C5E6205F309ULL,
		0xF84B73F0A8A55076ULL,
		0x236A082708D9CAB3ULL,
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
		0xA2321064D1BFF74AULL,
		0x18283DBC882FD8F9ULL,
		0x222DE74D07DF9225ULL,
		0x88EEFDC9DCA12F64ULL,
		0xB7943F35C665B974ULL,
		0x7F66EA6474ED1F0CULL,
		0xBB6050777253E3FFULL,
		0x7BCFB93569F5A1E2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB91F61E5E9326C80ULL,
		0xECCFE8947EAA11D9ULL,
		0x47A4168A74C78353ULL,
		0xB5C3E1A45E7B83B2ULL,
		0x62337C8451F9DB0DULL,
		0x4F467928DEC57891ULL,
		0x3BBE91B0985A06F2ULL,
		0xBB4826879837F717ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x956F94D630908C98ULL,
		0x5029240053687D6EULL,
		0xCC8C2246EE2EDEC6ULL,
		0x674AE1F2A04D05E6ULL,
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
		0x197319ECC47E2B35ULL,
		0x36C6ACA9B45BAC62ULL,
		0xC7CA008A078A1ED2ULL,
		0x2DA53C25535297BDULL,
		0x1C4964EE2243422BULL,
		0xE108F1DF996A0F6CULL,
		0xF9D622B7E08E35A0ULL,
		0x14BF5B29A666C156ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8A2C57A85BA6B69BULL,
		0x5547E2F89328C7EDULL,
		0xD9BF4DB03ECDEAFCULL,
		0xAB930F165EBC5036ULL,
		0x74B4ADF504604A60ULL,
		0x51F82159BC83B534ULL,
		0x68E64A126CC258F5ULL,
		0x6DB4FD647D5B28A5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6F59EB3ED8883AA8ULL,
		0x1DFDBD8FEB6448B7ULL,
		0x71A4DB68F8FEF54DULL,
		0x4D9C18530C4EF1E2ULL,
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
		0xEC7D64471B8C9369ULL,
		0x0A31FA4836080E8FULL,
		0x116ED11203D58705ULL,
		0x8F0AB97A4B34E5DBULL,
		0xDC0E7429FF65743FULL,
		0xBE4A70BCF72669ACULL,
		0x5CAADE205516BC8BULL,
		0x4C71EEADC5155C5BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x78D3FB2152133000ULL,
		0xC51CDDD22EFF5561ULL,
		0xC2C34C3DF91304E7ULL,
		0x56C4767BB0A3E0D6ULL,
		0x87B0FDA682BE467CULL,
		0xF45DA47A751B0938ULL,
		0x1BF11393F969B764ULL,
		0x1309B6A3239EEA28ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF98900AA4A4A2F9EULL,
		0x3E3B6E5554B90A72ULL,
		0xEA3F95A9A67145DFULL,
		0x3DBE94929225F89FULL,
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
		0x2186B665F0B7FC43ULL,
		0x9E071C0C601A307BULL,
		0x84F9747A0E519BE5ULL,
		0x0BA8FCB69A122AE4ULL,
		0x8A50BD29ACB3218EULL,
		0x6B63D6954915B94FULL,
		0x5390767A905B0CEEULL,
		0xD34B68D5D37A3100ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8E8E97700EC3E0F5ULL,
		0xCFA5255700D1F5D5ULL,
		0xAE7744B6AD91C6F1ULL,
		0xDE740F6B56F56156ULL,
		0x1A57A8F3F41B87B9ULL,
		0xEF5BF548ED016ACEULL,
		0x8D648ECDAA890AA2ULL,
		0x3D7C43EAC77FC3A8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x31F11EEF4874F40AULL,
		0x378D680B0A4BE1DCULL,
		0x4106936D7DEC2C28ULL,
		0x69F4682F0A490495ULL,
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
		0x82694D8A640355E6ULL,
		0xCB236785A43E76DCULL,
		0x19D75391FB6EFBF2ULL,
		0x6118DA67B36A97ECULL,
		0xC685A05C584AF5B2ULL,
		0x74EBC243177D8574ULL,
		0x7D226348BFEFF803ULL,
		0x6EC54F2D709911C6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x78B01793134031DAULL,
		0x9AF315E83FC8BDBFULL,
		0x753A0C69A3BB685CULL,
		0xBA3046A2CBC82F70ULL,
		0x220E82F917B9A3A8ULL,
		0x16D9918AF2DCED77ULL,
		0x61615DEF082A3C74ULL,
		0x739EAB9A7524291EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x736792B2E655514FULL,
		0x26E38CF2D44C48C3ULL,
		0xC34412799F0D6ADEULL,
		0x6EA4DB963AFCF16FULL,
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
		0x79DA424065C7B004ULL,
		0x91966264FE53C89BULL,
		0x164AD7922A95539CULL,
		0xF7660D7FA543A959ULL,
		0x7C00403BFE378479ULL,
		0x4D50B39EC217ABC7ULL,
		0x6D2BF74AF1FE901AULL,
		0xE6BCCFDD9B1E3A29ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F81D8B4E3855976ULL,
		0x44EF35ACD79EFC9BULL,
		0xF71BF120FEF9EB01ULL,
		0xF58395224718055AULL,
		0x7C829A5CC27A2D0DULL,
		0xE94D7A07D304B377ULL,
		0x64BB7AD7F17E4E28ULL,
		0x6A0C0FDAEFF46ED3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x56FF08AE605D5355ULL,
		0x2521B91FA385A7E0ULL,
		0x5FE15F833EA53270ULL,
		0x041EF8C2C65FD2C3ULL,
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
		0xEBCDD21CCC011469ULL,
		0x4739DAF38155C5BFULL,
		0xF86E65242DDCD949ULL,
		0xCFBAD7DC6976AB3EULL,
		0xCF443239704764C8ULL,
		0x1CC7C3B5149839D6ULL,
		0x9F82B82ED670F263ULL,
		0x56778B59C16AA629ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD3998B8DA7D41A7FULL,
		0xD458B4FC17450094ULL,
		0x47A5A58171C5FF7AULL,
		0xA6407E51DF7971DDULL,
		0x2D54E5762D90D8AEULL,
		0x72C817E76E407040ULL,
		0x2EB7CBBB1A519860ULL,
		0xC93D40C43F524D74ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x21B9AB8B0B45C340ULL,
		0xAED4A67E1B18B187ULL,
		0x6EE7D8D0A8BE3633ULL,
		0x20216BBBD99A6450ULL,
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
		0xAD6E3DDF63AA0FB2ULL,
		0x4DA51328ED6F800FULL,
		0x2CBF21C4E4D228B4ULL,
		0x634C2D587E1518CCULL,
		0xEC2EFC134B634708ULL,
		0x7B720217056FD7A8ULL,
		0x0CF75F68650BED4EULL,
		0x33EAA14221EAD49BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC991F864641897EBULL,
		0x473D0458CC6A4323ULL,
		0x919D1E7B72258DF8ULL,
		0x2E86958508D05B9DULL,
		0xBEB9A62B2BEBA9BDULL,
		0x5B2A0B275019690DULL,
		0xA8191882286514BDULL,
		0x834D8316C1C509EFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA34705EFAB52CF21ULL,
		0xD116B6650BD9A7F4ULL,
		0x942089767370C046ULL,
		0x6C181243BAE0D29FULL,
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
		0x8DDFE14B8E46BC13ULL,
		0x797DEF0202590B9CULL,
		0xA24F8A17307D6BD3ULL,
		0x670850C8AD398910ULL,
		0x4FDA94BE2CE2BE78ULL,
		0x29FBE19AD5B6BF27ULL,
		0xC4436BCBD3A134D1ULL,
		0x7BA4414FDD86BDE4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x56D4D241E30648B6ULL,
		0x16A51446A9EC7821ULL,
		0xF13D9A1DB554512FULL,
		0xC2B09C8EC498C586ULL,
		0x76CDA2F24F46BAF2ULL,
		0x7ECAB03DE62D2EF2ULL,
		0xBE08DA36B1E1564AULL,
		0x5060B4685205D5E4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6EF6F34C9068FA25ULL,
		0xCC262E86E6D7FB53ULL,
		0x9DC38C1C7DA422A1ULL,
		0x105E9E989DC3338AULL,
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
		0x6E8B5E1D81E5C034ULL,
		0xAB806C27148A21F9ULL,
		0xC49E5170ED67B70BULL,
		0x5017435F7C68A71DULL,
		0x53FC7C06D099A2F0ULL,
		0xB3E07DC86D0CEF9BULL,
		0xDE0A87B81157E48AULL,
		0x6D3AA4481BD5EF59ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x63114ED8793C9468ULL,
		0x3B1129CB2FE0398BULL,
		0xB69647761174824EULL,
		0xA859B7FD96B373E1ULL,
		0xF1E82D72AF0A9E24ULL,
		0x31A694A3C79A2146ULL,
		0xCAB4456FD53C2CAEULL,
		0x6B7C327460C40431ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9A7DB94203E3E201ULL,
		0xC507DDCC73B488F4ULL,
		0xECD5E0B3C8107F78ULL,
		0x6A0270CFAA5E1B2EULL,
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
		0xC68B5F7B4CF8DCFAULL,
		0xD1C886FFE6A84023ULL,
		0x9508004A9CED7FB4ULL,
		0xFDD336749417084DULL,
		0x7210C52A1FBE53CAULL,
		0x7F06913E7AD7DD21ULL,
		0x95350FB8805E14DAULL,
		0xEC760583D6E45B3FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x42C12C0F670BFBB5ULL,
		0x67843F6C823CD69BULL,
		0x749CE00D98DFDC03ULL,
		0x3AF4A13384D0DDEAULL,
		0x2A2E3292FABB9BCEULL,
		0x15BAC28649638BA5ULL,
		0x2FA0E2ED846B575AULL,
		0x5C53DD8DCF220B17ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2F6BF5DB645433F1ULL,
		0x0B84F6EABBAF81FBULL,
		0x3469C65E6A15C4C1ULL,
		0x27F083C6361E1062ULL,
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
		0xCA63BE69919426D5ULL,
		0x298B342BAEDBEE68ULL,
		0x686EC221C918414EULL,
		0x21914F1263BA06E8ULL,
		0x327BC4737E16B903ULL,
		0x1576A1AE862748ACULL,
		0xD1E8B58AACD8BBB1ULL,
		0xBE0D9DE4D76C7E49ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5FD7B562B78C0C6BULL,
		0xEC8FDB9B691A9644ULL,
		0x6B4FA3604C77E316ULL,
		0x754C3447845A43E5ULL,
		0x3A05EC4D94AA0453ULL,
		0x87E2F9C349461BFAULL,
		0xE3E5FD7D1DD9CD8FULL,
		0xF70D00A3D603E6E2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4C0A1EA7802AEB34ULL,
		0x40E6457B4F2DFA8FULL,
		0x518670C4B677B732ULL,
		0x365C727114E63C4AULL,
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
		0x2DB59BFB5749AFE3ULL,
		0x85C72B4D6ED7D27AULL,
		0x33A84792C3C96AA2ULL,
		0xF98A0A7DB9770FEBULL,
		0xA4EA15963EB54839ULL,
		0x940B050324A6F3FBULL,
		0xBE47950257E59383ULL,
		0xA050B4BB0089825AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x425CF70A6FA7E3F0ULL,
		0x95203FAC343D2E72ULL,
		0x6BB83B8CB95172D7ULL,
		0xB00C8BACFDB01CC1ULL,
		0x2600A1B7DC556FF8ULL,
		0x77100576E89AD796ULL,
		0x8924D8296B1C270AULL,
		0x06BD78D77815EC15ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC1FFD7F381DBE903ULL,
		0x3DE8DA722466DB18ULL,
		0xAB181439305E11C5ULL,
		0x15586296FCEF416FULL,
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
		0x9826217DA7A4661BULL,
		0x5E9548D92243025CULL,
		0x10C71088461F0FC7ULL,
		0xE9B7099FB03D0FA8ULL,
		0xD489B8A4FD644508ULL,
		0x991C060217FDFC8EULL,
		0x2FD21019635AC991ULL,
		0xD8521B552CA81CF5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE53775CDC4D49066ULL,
		0x1DFE6267787BFD61ULL,
		0xB0AA753A971258B7ULL,
		0xA71FFF550AA2BC56ULL,
		0xB38A7906AA7C056DULL,
		0xBB72DD01F8C26338ULL,
		0xF93B8A3CD5F701E5ULL,
		0x2EF487DC8C5CCE2CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x98D21D3031494A6DULL,
		0x27B2FC764C9FC7C3ULL,
		0x7A747A0AABDC5A93ULL,
		0x667AEE3270C80509ULL,
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
		0xD1F9306A594F9970ULL,
		0x11E6131F3A6D9695ULL,
		0xEBDF8C53DCEBDC68ULL,
		0xF50480C7C8FB4C08ULL,
		0xA08DC1A1FD2AADC0ULL,
		0x246A353C625337C7ULL,
		0x8E47FFA271039292ULL,
		0x35DBCE17DA9ECB3BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD8F27BC3BB376CCAULL,
		0xE90B1C9F4B7A692DULL,
		0xEE93836A37C0943BULL,
		0x04D23DD120328B80ULL,
		0x9A0B68AE34A0633EULL,
		0x861ED873DB0E4A17ULL,
		0xCE736B714DB646AFULL,
		0x6E223E2E97B337B7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF05FE8D6629F3AD5ULL,
		0xA80ABC44032E7588ULL,
		0x76DA0834E2A48BCFULL,
		0x15BD9F9697C0A616ULL,
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
		0x6BAB71592517569BULL,
		0x5A5BE7D3E8E7807EULL,
		0xE31C7ECFB4DD64F1ULL,
		0x8BA52F324F6089CEULL,
		0xE9C2173214D41F25ULL,
		0x4D2BDB1A9234407BULL,
		0xE41D040F43CBAB48ULL,
		0x10AC8E73E54FE631ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0665D70FC96A4D66ULL,
		0x65659C4E008D630BULL,
		0xDABAC4A437BF2179ULL,
		0xB9CAC4D8697E15C6ULL,
		0xE3D0B8AB01D1C168ULL,
		0x768EE177067D0485ULL,
		0x0F849790FE3B7CCEULL,
		0x2389C5ECF9F01A34ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4719A2562E06F2D1ULL,
		0xD04359CCA58D03F8ULL,
		0x9701D4E9D085298DULL,
		0x05042E60D61ABBB5ULL,
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
		0x133CB1A6E75F5A40ULL,
		0x49F4FD6C1D5C8535ULL,
		0xCAA716AF19E52B44ULL,
		0x7F2CE35FA763B430ULL,
		0x56ECAFD5B677E7C2ULL,
		0x78DD1AF75CCD24F3ULL,
		0x7187C82A27E701B9ULL,
		0xC42C71C90F006D20ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE2ACA4F6A2578F56ULL,
		0x0CBC38AC72CD251BULL,
		0x0C6B5E0D7EBF0D3FULL,
		0xDE2D11B9DABDC38CULL,
		0xFBB6DDBD0B04A166ULL,
		0xD3EFF6A7043A11BEULL,
		0x24FFEA0D26EE0B4FULL,
		0x436094385593EBB4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBA8D3C59B8243F51ULL,
		0xB86C28ACD06439DEULL,
		0x1A66B0EFC01AB1B3ULL,
		0x3F42B52152C126B8ULL,
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
		0xEAD862FD571ACBFCULL,
		0xCA5850B39599726FULL,
		0x92B0C5F01CD6F2E0ULL,
		0x0E3EC4C097270D5EULL,
		0x55DBDBFB3DD40D44ULL,
		0x673E7F25F1606B11ULL,
		0x6F30EE2F763C56DFULL,
		0xAFE091D830020C80ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x54BF03A55E29A94AULL,
		0x41880D8E06CC9649ULL,
		0xC90AAB88C3064AE4ULL,
		0x4E83EB0CBEA6263CULL,
		0x630048C8F6A09AD0ULL,
		0xE65D435EFB4594F2ULL,
		0x1587A6B872B169FBULL,
		0xFEF1EBEBF3501121ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA2B138CE8A941E22ULL,
		0xAA3F22AE16C8A4BEULL,
		0x18C6B611E06FD1C1ULL,
		0x03277AC4DAEC3749ULL,
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
		0x23E09CE81EA13403ULL,
		0x17BABC9928DEA010ULL,
		0x00E260E592A572CCULL,
		0x9281DCB0599F5640ULL,
		0xEA9EB509208EE4DFULL,
		0x953A7DCC9C126490ULL,
		0x348D4E458E5367D4ULL,
		0x47A0FA4B02FDCD42ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x463B038BD1736670ULL,
		0xD5F007D4E1C17885ULL,
		0x50D194D6BD671340ULL,
		0xCEE973732911F320ULL,
		0x363F0F09023CBBFEULL,
		0xC26D5CD9EF5581CEULL,
		0x90AA78F44AFC8E44ULL,
		0x5AEA74EFD79310D6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA3D83D60CD5FDE74ULL,
		0x8C3D98C9EB26D071ULL,
		0x03BC761ED422AAE4ULL,
		0x66B034C5A2655B1AULL,
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
		0x28461B4CE72B4275ULL,
		0xE3785B30FC78B736ULL,
		0xD5A4701AF00E6C22ULL,
		0x4A4E2ADE5CCC6FF7ULL,
		0x8E906F210C5DBF5BULL,
		0x3BA4A882B3514B74ULL,
		0x963B439DABB9B5BCULL,
		0xB004F7E0DBD81F9BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC0507395BBE4B01EULL,
		0x079C4497113BE8BAULL,
		0x6EF970ACB5094CBCULL,
		0x9560A4ED1306D815ULL,
		0x50939B5257D1DCB7ULL,
		0xBF0125110FB54695ULL,
		0x352F78F4E3C3A650ULL,
		0x6AB3E84E2D26B198ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9B7D1865F80A3818ULL,
		0x5C2199783465879EULL,
		0xCE6B147BE98B695BULL,
		0x7EF5D5B7381BEC62ULL,
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
		0x8C9EEACEB1491963ULL,
		0x8125B80ABD942347ULL,
		0xA04034832E3BA2C2ULL,
		0x3F125FB421645106ULL,
		0xFD45F366BC4E89AEULL,
		0xB5F07E5F9BAA3C24ULL,
		0xEF1A6EBAA6A99E43ULL,
		0x96A7F17B2338CCA8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB6B77281FE4212ECULL,
		0xDC0000820302EC44ULL,
		0x2E62D1134DC9CE07ULL,
		0xD6CDE15D2D2DA4F5ULL,
		0x7DD0F89109A39786ULL,
		0x1246B82BCD131111ULL,
		0x3A2A36257F0CA18FULL,
		0xFDC84753DB61BECFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC144B4053866F607ULL,
		0xF059233965019BE7ULL,
		0x4D85C993C1BF578AULL,
		0x1977C02B9E22BA62ULL,
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
		0x033E20EE39FA3D14ULL,
		0xA44025548658CB2AULL,
		0x310FF3C1604E2161ULL,
		0xF6C5AF5F4A4C3EC5ULL,
		0x6D8278157B061140ULL,
		0x09653538A7A9E73FULL,
		0x828D1D80503EFD58ULL,
		0xB60A5C5C740FA728ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x58145E16136F2344ULL,
		0xD3C1C90F73C812F1ULL,
		0xD395711DBCED7820ULL,
		0x8C8EB3D2BE106805ULL,
		0xBCBF6A983444DCCAULL,
		0x2BF8418F3D2455BBULL,
		0x38445483B83B916EULL,
		0x8291136D5B305DA0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE81DC370A738E484ULL,
		0xAEAA876AE26451C4ULL,
		0x6448582233E2ADF7ULL,
		0x0E37CF0A3D60C0FAULL,
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
		0x61B4459058B7D90AULL,
		0x7AE301BEBE2CAC6EULL,
		0x3C716EA45479C1ABULL,
		0x747E7370C5598176ULL,
		0xB82823A34029FDEEULL,
		0x9A0FB58CB427406DULL,
		0x452A151B1D63D96DULL,
		0x61695A577808E26BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD3DDC2EB80E2967BULL,
		0xAFE371F51E9B8431ULL,
		0x3899A677D29FCCDAULL,
		0xB21CADC008113874ULL,
		0x9A0969577D9DEFF3ULL,
		0x35DDB15E7E47F714ULL,
		0x423D62FA7FE25E21ULL,
		0x5DFBD4DCE4779F43ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x066629E3B89F55D1ULL,
		0xAA6C2EA59EB60B77ULL,
		0x72FA3903E3124227ULL,
		0x44A395E2A4D840F2ULL,
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
		0xF71F6E769B0FFC1BULL,
		0x20170D516CB9A5B6ULL,
		0x98C1D3AE155ABA23ULL,
		0x85B80985DA2E2D28ULL,
		0x8C15A2E3D56FDFEEULL,
		0x693B4011E6D1D2A6ULL,
		0xFE97C89E80DE7CDAULL,
		0xDE0DA030705433CFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCD76F3DD5DA531AAULL,
		0x7B40B3C724AB4747ULL,
		0xD29F1D1457EE5A54ULL,
		0xEE1230C4928F8339ULL,
		0xAFDCC3085524DDE0ULL,
		0xA8771E4672617C1FULL,
		0xC54CDF1364221111ULL,
		0xEE99B61E70A0513AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDA19B52E488D1813ULL,
		0x41F35DBD90BB3673ULL,
		0x4741614001645F9BULL,
		0x22DA976D3C524C15ULL,
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
		0x1B4E906512577BF1ULL,
		0xBABCA90500039D03ULL,
		0x2B90E6E50C0BEF53ULL,
		0xD563022E378C8718ULL,
		0x134134A772C67119ULL,
		0x4791C4236AE8CFA2ULL,
		0x7030B1E7AF89DF3DULL,
		0xCEF7045E84DBB46BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x24C293F7D202E2F8ULL,
		0xB86D50070C346F24ULL,
		0xC5DD46C9E5B593AEULL,
		0x0E8AD97DF7C211CFULL,
		0x4FD05209014CDAC4ULL,
		0xE07B255D6D7B8317ULL,
		0xAD31B698F4B04E6DULL,
		0x280E8A5FC07F2D6FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF94D9FF21860ED60ULL,
		0x4FAAEA6192088A77ULL,
		0x578CEDCAE2A1DA6EULL,
		0x0D5A448165867EA7ULL,
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
		0x99BFE76D95E7EB43ULL,
		0x4A1F13FAEFF4AD68ULL,
		0x22F8589E15AE4E88ULL,
		0x107E18731206AC1EULL,
		0x3BDFB5C293065BA2ULL,
		0x19F4EE7A91A5BC1AULL,
		0xB12ED9817F7F7DCDULL,
		0xB5D4578830B7FF0AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF0177B8D1038AADFULL,
		0xB977CDA7561376F9ULL,
		0x608278A4E554BE46ULL,
		0x10F2900968D95607ULL,
		0xB663F684D943CE46ULL,
		0x2AC65AB6150386CBULL,
		0x971CE825432D2C2AULL,
		0xF766D8675D52503DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7A06CF0A18903A90ULL,
		0x1191357E19F52016ULL,
		0xA11FB3AA2491AE71ULL,
		0x43CC67490A454888ULL,
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
		0x2128DE9A9B14DD6EULL,
		0xF7A1D7121D965D45ULL,
		0x91842F880BB4D184ULL,
		0x331190C934FFC038ULL,
		0x225DE4F2B3F3E317ULL,
		0x34FD9640F0A2A1C6ULL,
		0xFA5850660A3EAB81ULL,
		0x35E0CD86134A1B3CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDBC89735413D5C1EULL,
		0x2B3DFCE82151B69CULL,
		0xFCBEF576F97A2523ULL,
		0x281CB511E4CDF30FULL,
		0xF6FAC39A285A4688ULL,
		0xBCED1D7E223B979EULL,
		0x44DA227E64F0D869ULL,
		0x335B1909F6FDD8FBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB6173A8A12A4BE8AULL,
		0x9ED5C7149F902878ULL,
		0x85800A739BC801DDULL,
		0x6ACDA6238383A2E9ULL,
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
		0x869F8F2ABE426A66ULL,
		0xD9F862FEBE401279ULL,
		0xC9C65AC7F1C8B8DCULL,
		0x89372B62685A110EULL,
		0xB122AB52728850FAULL,
		0x52D8C11092B3F623ULL,
		0xACA01DE08BEF83C7ULL,
		0xBDCF62922DC00DB8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD056357615DF695CULL,
		0xD455DA8F4C3C4A33ULL,
		0x94F30D172C09A46CULL,
		0xD787377DE341BE1EULL,
		0x348B22700CB81F48ULL,
		0x5BF0FA074D249E1CULL,
		0x09CCB16DC30F6E8BULL,
		0x63DD7609CBF7C814ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x34C7AB4FC54A6364ULL,
		0xAC0A13CFC54AD962ULL,
		0x603566BA97023B56ULL,
		0x0B99102308D2A960ULL,
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
		0x3F5C6F24AC450D44ULL,
		0xA40E38D4CEF39AAAULL,
		0xD0835985FACCD93BULL,
		0xC388E08834E58AA5ULL,
		0xEFD1351784C4A41AULL,
		0x68A0A430A36BAC33ULL,
		0x0F1D81A9201CA9E1ULL,
		0x90E50C08CBEE9CEBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2FA6B76FD635E7B1ULL,
		0x7F3AEAF86FB35891ULL,
		0x6A10BC0D9109BCF3ULL,
		0x746B61A3C31E3215ULL,
		0xB40DF1A7695D7793ULL,
		0x90A5C51489F5035DULL,
		0xB55A3F3B9E5636BFULL,
		0x04DED2840E1183BFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEEB1BA58E75FC4BBULL,
		0x34106C0826DD51E5ULL,
		0xB96E79B9AD38334EULL,
		0x180A0898A09914FFULL,
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
		0xDA9C58329CD1D3A8ULL,
		0xC379983088D736F2ULL,
		0x5063D8D2829E89BAULL,
		0x8BB20063C485B812ULL,
		0x0ABB4797CB12CEB1ULL,
		0xAA02469DB3773E57ULL,
		0x164766F5408D83A2ULL,
		0xBA83333E26D3862EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x19F953DA58466425ULL,
		0x5BEF0D3F7A1BD1C4ULL,
		0x8F85B39B3659A90EULL,
		0x305E2271248097ADULL,
		0x82F79E0765D2B472ULL,
		0x07842F1A6ECF1502ULL,
		0x73C937FDFA2B2C2CULL,
		0x6015406E30865F8EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE7AE2FC74C0F56DEULL,
		0x8642086D3FB187BAULL,
		0xDF991DEBBEDDDC48ULL,
		0x47A5E8D12F78DC16ULL,
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
		0x7A5CC6C3E93ADBA4ULL,
		0x9BDF0C35B610FC20ULL,
		0x8009003CC8B482C0ULL,
		0xC8A707EC6AA1FCF2ULL,
		0xD410BF19C648FC40ULL,
		0x2D5D9F8B587AF048ULL,
		0xAF381C3AA2EEBC9FULL,
		0x23B7AC11918C9F30ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5AF4AE085620388BULL,
		0x44394E498A521A43ULL,
		0xAE2ABE2D3CB7AF30ULL,
		0x8BA3CACD17DD56DBULL,
		0x2B1F708F5731C149ULL,
		0x3D9E5B041FF2974CULL,
		0x132EF04CA93CFE48ULL,
		0x3B4BA3464A971344ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3339C148108D633EULL,
		0xEE09E9FE8FFC175EULL,
		0xFB3AC7629C5F1477ULL,
		0x3D0C8B4BDB376B35ULL,
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
		0xFD50E18EDBF5D97FULL,
		0xBA8C8902ECCDBF9EULL,
		0x2A456F62462F1724ULL,
		0x5F5542317C1DC927ULL,
		0xF0C5FADF8C04DA2FULL,
		0x623C8C1B2AEBA858ULL,
		0x3D196B6F97BA965BULL,
		0xE784E92FE082FE1EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0A6322E209289723ULL,
		0x38F0616CDD9B889BULL,
		0x797A8F2C7D972957ULL,
		0xE3558195B5EAB9E0ULL,
		0x21576D83E784AC40ULL,
		0xC84DE2703488B2F4ULL,
		0x221B4DF35C358F79ULL,
		0x9EC58CBCF41067D0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBD56BA473DD41552ULL,
		0x5B0956F6A1E2A3FAULL,
		0xB28340A69E56F34AULL,
		0x486779AADF355EDEULL,
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
		0xC6E3157F8E9D5DB4ULL,
		0x5E357736FBA58AC7ULL,
		0x2A0DC480482B9B39ULL,
		0xA6B7D7786A5801FCULL,
		0x4DCDA1347C8736DAULL,
		0xAD3CCEC3B8881297ULL,
		0xB09B495DD1E83F36ULL,
		0x00CB3959152BD8B8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x17B297E454B0BE5CULL,
		0x4522F5F09F167ACFULL,
		0xB36497B7044F15CEULL,
		0x657F426D80CFF3F9ULL,
		0x3D9616E57995D9A2ULL,
		0x000FE17665FA7960ULL,
		0x3832D3A849219DE2ULL,
		0x56330D04C9E2D1D6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x176F0555A9C073CDULL,
		0xCDBDBAC09D93CE25ULL,
		0x562AA5BB915877FCULL,
		0x13CF298E165F13A0ULL,
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
		0x0682CAB6A12D63E9ULL,
		0x235BB1042F924D9FULL,
		0x0A103A5B3074670CULL,
		0x826B4DC3997DD625ULL,
		0x2A0CA90058779B4FULL,
		0x95BC54C865AA7C80ULL,
		0xA37D7A255A2C3C57ULL,
		0xACFCF829872A118CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5F1FC5AE7C3623BEULL,
		0x8EB6CED57E455815ULL,
		0xCCFB3F6DA1BE7BFAULL,
		0xECA09CD96BE4D39DULL,
		0xDCA5CB3586B27FB4ULL,
		0x4B0DADB4E1EA90FFULL,
		0x64FB9DE0CDA0DADCULL,
		0x563D81500EA8A81FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x24A7F12348395AF5ULL,
		0xAA91AF143FC9EA95ULL,
		0x845BAD1A6B66635EULL,
		0x7636553210CEA8BEULL,
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
		0xA6BEADD2D05C7C60ULL,
		0x0BE85B29927BB76FULL,
		0x6557D13327054AABULL,
		0x0E5060F81A32553EULL,
		0x037A00AC6ACF095AULL,
		0xC52CF23B2ABF027AULL,
		0x2A21B0A34AA82086ULL,
		0x748B6671E1AF43D7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB1D713174C14099DULL,
		0x4B457ED0304BC811ULL,
		0x3AEB1F0DB3C80E95ULL,
		0x7665BBFF1476EDE3ULL,
		0xD5A96916D1D85A7CULL,
		0xFB1C46B5D23B1373ULL,
		0x15793F3A111820D9ULL,
		0x0B252E1FE417519BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC1DE1AF038E669F1ULL,
		0xBF1C522485C56A48ULL,
		0x3B6D87C3FE9D2FBBULL,
		0x3D170124AA495C46ULL,
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
		0xF3A13F959BBB5B3BULL,
		0xAB6DBF452612C031ULL,
		0x9BEACC600FF11A8AULL,
		0xE38EAFAC9EBEBEE4ULL,
		0xF908AA9ABA1E36CDULL,
		0xC14944D9BE48B492ULL,
		0xB4047E851DB8AABCULL,
		0x50D194907188D034ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x62BF3A47DA24435AULL,
		0x5D47EBFAE0A6D699ULL,
		0x6E073B4107342EC8ULL,
		0xBB4AB3C5CAA39CD4ULL,
		0x8C40C8221205E6BFULL,
		0x622CE16F873DEF16ULL,
		0xCD571D0568B9C926ULL,
		0xD42A7248434C3446ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB68DA336B532F710ULL,
		0x6C5C950E71053A10ULL,
		0x6BA00A13E6926814ULL,
		0x2913129DB11A4760ULL,
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
		0x22D2A9120F3B6ACDULL,
		0x4EAD9F36847D7AE4ULL,
		0x607E4BC081F950E9ULL,
		0xF8558F1BA72B1EBDULL,
		0xA8B3520E1A0CEFE1ULL,
		0x53D8D4F9D06F37F3ULL,
		0x9C38FEEC49AF3F02ULL,
		0x4161350D81AA3607ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x678088F715FEAFB7ULL,
		0x5D2F9F9C97AE2027ULL,
		0x51F89FFE239C78EDULL,
		0x79AF97ABD886EACBULL,
		0xF730F8A573F36A80ULL,
		0x584D1FF439BEFEB5ULL,
		0x58E9ED82D137A8C6ULL,
		0xC02DCDCDCD5E48BCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x14AB65A3A10684BDULL,
		0x483ADE6E4AF7D9E5ULL,
		0x0C42416A401D24E3ULL,
		0x2C474AE491E96D1EULL,
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
		0x5FB4733FF3F9697DULL,
		0x503AE1B63AEA2127ULL,
		0xA5736C3BA60BCDB3ULL,
		0x92C09BE13015F391ULL,
		0x33E6C23B2691019EULL,
		0xB5C2FA802EBB934FULL,
		0xC0F59DD12C5F04A6ULL,
		0x14DE40069A406DA7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x278F1B2A5473B9A9ULL,
		0x38EC6403CD95B6E2ULL,
		0x0DCB673FB7AF6539ULL,
		0xAB7FC1BC6AD068B2ULL,
		0xC5E6F3D6AEB6905DULL,
		0x261FBA6B04D4E5D1ULL,
		0xA593026A8C08A179ULL,
		0x3A83AFF84F83AFDBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8C1DFAFF69F27E96ULL,
		0x698A00D6A5922AE3ULL,
		0xA84B1637BB2F213DULL,
		0x50B23C43DD49B72BULL,
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
		0x58D57FA70E358A01ULL,
		0x2647891618839AE0ULL,
		0xB3E9D8AC9F6001F3ULL,
		0xE7071E96FC57FDD9ULL,
		0x6C5EE1B358340674ULL,
		0xA43C829C3C39FC4BULL,
		0xA9E65682767FC09EULL,
		0xF24FAA70CBCCA20DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCE94B98F11AF1DACULL,
		0x5838567EA759B16FULL,
		0x994941846362B392ULL,
		0x2A92F3B036D39ACBULL,
		0xD26A7BD00196635CULL,
		0x67A9C22B06680666ULL,
		0xD7E032910C112452ULL,
		0xCD84FDA646C2212AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6487E5D6D7ECA2C9ULL,
		0xCBD7C3656E54695FULL,
		0x4789ECFE086881B1ULL,
		0x3289D0F6851384B9ULL,
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
		0x3B029F6ECC94C299ULL,
		0xC9EB545FA617FC30ULL,
		0xFEA9D0EE18C1D3FEULL,
		0x303EC4144E17ABEDULL,
		0x1196E1B31134853CULL,
		0x726B07789C869D95ULL,
		0xC40A91D6FFAF7AB3ULL,
		0x7550E0C0623AE9BAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x73341AE7A1D9A4F0ULL,
		0x1F91FC7B4E23D602ULL,
		0x9C7CF633C6F4A93CULL,
		0x6A728516443FC18FULL,
		0x11E1EB553736A831ULL,
		0x5DC953011BC71C92ULL,
		0xE81721A8738672DFULL,
		0x028FC4B73807E4D4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBCAB16758669EFBEULL,
		0xBA5A21A174614C9FULL,
		0x084F81A31FE4543DULL,
		0x4E76685A4D6AA47DULL,
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
		0x81E89496E86DD460ULL,
		0x1071090D78D4A8B5ULL,
		0x465BEDB24769B749ULL,
		0x73EB11D5D2745EB8ULL,
		0x47F690A4F87EF93BULL,
		0x584D002EFE09F54FULL,
		0xE5FA6816136D6786ULL,
		0x0B86BC415AC5A60FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6096A57415E5BA9AULL,
		0xFCD743BFE3D7FCC1ULL,
		0xCF2477E66B5A57FEULL,
		0xD600F4DCBD8D32ECULL,
		0x4BB8FCE9742888EAULL,
		0xDA4A69E15D0A5343ULL,
		0x101F5957B3B926A3ULL,
		0x126DEE694D72340DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9275DCF8775CC593ULL,
		0xC7FC14D37AEEB9BBULL,
		0x35BBA60E10D100E8ULL,
		0x1798AB0B0F4A1837ULL,
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
		0xDA896F9F1EBF83B8ULL,
		0x28668D2389821580ULL,
		0xE94BCA235DC798B9ULL,
		0xFBE494F7902B29E1ULL,
		0x0AC640FA9CFD0042ULL,
		0xEFEF7AEB4A3DFD52ULL,
		0x87A380C2F5A1E19AULL,
		0xD4188979774C1707ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC7B052E2CB5B2E0AULL,
		0xCCAA1BE17E31AADCULL,
		0xF258FDCCD6CBD60CULL,
		0xB2DF81224A26A536ULL,
		0x4261C29D6842907AULL,
		0xA659508F610CC32BULL,
		0x78157F8C4537AE10ULL,
		0x07994E9808A9FA1EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD1C3DE922710F1E5ULL,
		0x4806BAE6A89F0C65ULL,
		0x4606FA74B6BF6933ULL,
		0x23E7D14BB214CF43ULL,
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
		0x5F97FB70483D032CULL,
		0x675BA57D20C07DE9ULL,
		0xDF8BAA26AADBC9A3ULL,
		0x00AD115E67856855ULL,
		0x7D0E730AC546FC28ULL,
		0x40CCA99C9CC59363ULL,
		0xE009B0E47784D80AULL,
		0x5FB163525F7CEA05ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD9C2016AAA3F9C93ULL,
		0xDFA9B58AAF577CDBULL,
		0x45C46F99139AB941ULL,
		0x731CCBD8F16E190CULL,
		0x52B50BD86DC3578AULL,
		0xCDD9E67E951020BCULL,
		0xE6F64140F77894F8ULL,
		0xD7036569786E60E6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCF1B4B7E9B87D34EULL,
		0x97BAE667965805DDULL,
		0x92A9CCD2991304F8ULL,
		0x5763F617C23FA9E2ULL,
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
		0xC99288873A6C608BULL,
		0x113F035BAC628A58ULL,
		0xCF790A218FEC8F0DULL,
		0x12EECD71AAB926DAULL,
		0x7CFD4C8220CF3253ULL,
		0xEA8BF38CB8BA31CDULL,
		0xE1F68CD5482F0D09ULL,
		0x241FC2DC12826E73ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE25980BA944A9A2BULL,
		0x4255783596F8FEF7ULL,
		0xA9B1A3546F6ADC8DULL,
		0x5FCAEC657FC48454ULL,
		0x74593A394E053DFAULL,
		0xE362A10BB43E1FECULL,
		0xC0667F2D87F53FE8ULL,
		0x638AF3556449068DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2F93BE9BF01C0A1AULL,
		0xDF0BCA4CBFD432C8ULL,
		0x21296DB3A9162566ULL,
		0x493AAF0A077A0EAFULL,
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
		0x104661AE014BA749ULL,
		0x6FFE5E9497046209ULL,
		0xA74BE8D9053FB3C2ULL,
		0x74FA918427375193ULL,
		0x2485DF980531ECDCULL,
		0x945EB18465B88D17ULL,
		0x760A57DB5C696232ULL,
		0x6752FDF8ED68B984ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD228E4FE7BD21319ULL,
		0x4CC117FD25DB64F0ULL,
		0xA1CE29320A7CE50FULL,
		0x0AE60D1AAF5056DAULL,
		0x6C7499E21604045FULL,
		0x2642D2A095714EB5ULL,
		0xDBF9970007261C4AULL,
		0xEF852FFBABCAB920ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x90ADD5B1064A13C6ULL,
		0x7B605C685BBC3F99ULL,
		0xE3FA6035A2BF2F33ULL,
		0x32A11801355B0981ULL,
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
		0x6F90BE6847A72C6AULL,
		0xCFEB9D3FD6FC199AULL,
		0x1176C78CDAA29B31ULL,
		0xFE36E02DFC83D8FDULL,
		0x431E530E086F5EC3ULL,
		0xD11F774771A532FDULL,
		0x3918A6F74B92F631ULL,
		0x2C303651E74A8D1EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAB0A4A6589E9D4A0ULL,
		0x56C2C8CA49D94D68ULL,
		0xE152F2E703EB022DULL,
		0xC449256DC3839FD6ULL,
		0xB6598D9EF6D34059ULL,
		0x15FDA608730C80E1ULL,
		0xDFA9932806FF90C4ULL,
		0xF489881CE01CBE39ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA9BBC27F5AE9D712ULL,
		0x402DE3CF57CD3C48ULL,
		0x76A0C56A0498A74EULL,
		0x7CAB969F49CCEF0BULL,
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
		0x2AE7000E22D2DBB7ULL,
		0x36215983BDECE626ULL,
		0x174E3878DCFBF7FCULL,
		0x629C1BEF091DAB20ULL,
		0x4633F725CA6FABCDULL,
		0x8D61B7C3BB594EAFULL,
		0xBE5EE3C838EC7700ULL,
		0xD8632C3BBABC3F2BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1930B1CC2259AB0DULL,
		0x9864C1488D84D4B5ULL,
		0xCA88B6A4F1A7F6D1ULL,
		0x5D3968AA78D108FCULL,
		0x8ABF1AA8A709FFE3ULL,
		0x72FBF195B55FB18EULL,
		0x841708022E161A85ULL,
		0xCE3C162D3F9CB524ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE50F08D54190B59FULL,
		0x88D803101375644CULL,
		0xF37021398725BB70ULL,
		0x072FF96AD6FB1F35ULL,
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
		0x51914A663BE46D25ULL,
		0x2495BC206D7C994FULL,
		0xC025746EEBDCE787ULL,
		0xB4E94953539868F0ULL,
		0x9AD97F798347CA95ULL,
		0xBEFC82F64E457403ULL,
		0xCE681C6347EA59E5ULL,
		0x5652D0A30453489FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC25B112397B78D75ULL,
		0x5683B987266CEA10ULL,
		0x9FB8451459FB81F4ULL,
		0xDB4051AD066B0DA5ULL,
		0x9F2F3539F3A6E777ULL,
		0x6FE8722090E16B21ULL,
		0xE0532F1D445F27A7ULL,
		0xCE96DDF670B12E4EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEA7D3EB1F60E9365ULL,
		0x8B0C825363E900C9ULL,
		0x778867BF188ADAD2ULL,
		0x7F8EFD44373D434EULL,
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
		0x39B92088191F24D4ULL,
		0xFDAAAE2C510DC9AAULL,
		0x0B66D599B689279BULL,
		0xE1DDA5144EED269DULL,
		0x554E1561F54E0A70ULL,
		0x1D89B543B10CCEDAULL,
		0x36D6DBFC0BF270C1ULL,
		0xA6CC2A0FE2CB89F2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x025944A89C456178ULL,
		0x67A334FA4F68971BULL,
		0x380513080DDC63D5ULL,
		0xA0E588FD54922D68ULL,
		0x15651B23FE16E54AULL,
		0x7D0C1CA9FD51818FULL,
		0x6A2CB7E7504CFBEDULL,
		0x9C16790B8FE7B1AFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB3F501122F094739ULL,
		0x68AC2002AF72ABBAULL,
		0x34A31DA5833C1B30ULL,
		0x57F062BB482D131FULL,
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
		0x70C1866C42C8B2E9ULL,
		0x5A0DF1EC7C4A79C7ULL,
		0x9A1CC811D6310DA4ULL,
		0x61D9EC60EFB789F5ULL,
		0x924CDE3FABB191BCULL,
		0xD43D8DECAC9EE4A6ULL,
		0xA47FFD5A842E6C4CULL,
		0x58460EC66D84363BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDAEA1FFB9710D408ULL,
		0x5E64E0B3EA3B3E98ULL,
		0x8D7393FF1283AE25ULL,
		0xF367465E08534BD6ULL,
		0xE339AE7BADFB35D8ULL,
		0xD582EFC16FA73398ULL,
		0xBBA002794B8BBE24ULL,
		0xF532E22B3200E3BFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x92B07D8854C97F29ULL,
		0xCB5C8BA39ED38336ULL,
		0x9DE871812BD3396EULL,
		0x234B450DBCE27C83ULL,
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
		0xBCA8587CC18B1985ULL,
		0xD01D7A10CC5CBDDDULL,
		0x7B028A5FA84693E1ULL,
		0x26654E6DCF4DE995ULL,
		0xA3D440D931F34DEEULL,
		0xDFAF9301ED76352FULL,
		0xA659EEC53CB32712ULL,
		0xE30865C86026B7A4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDE724310BD87156DULL,
		0xE3BC0D414059C05DULL,
		0x3BCE36AA78989D7AULL,
		0x6E8C3CAA94D69E67ULL,
		0x2A6178CCCF92602BULL,
		0xB95514B443565141ULL,
		0x118A581E0D426B62ULL,
		0x92C6DD19207E1D62ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE53FC7429E6750BFULL,
		0x9DD02C56CCBED2E5ULL,
		0x5604B0863A69D28CULL,
		0x21935BC6AD7E3110ULL,
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
		0x409C584F2A041C41ULL,
		0x34443D93D8E4BE26ULL,
		0x8A2D0B8E6E88BF6DULL,
		0x47F5A1E0EC7EF2D4ULL,
		0x0E2C71BE440D1763ULL,
		0x1B9BEF051FBC5BA4ULL,
		0x9697A9B6B192F06EULL,
		0x0561EFB95898E33AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1CD3567DAF0D3770ULL,
		0xFC399ABA803C78BEULL,
		0xAABD121C954C32E6ULL,
		0x7B4EE437A19213CAULL,
		0x50ACAF765651FC36ULL,
		0xC0FB6546CCEEFA17ULL,
		0xB222D518F96AA791ULL,
		0xF2CFFDC16A62F094ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x44BFD87EC4BCE83AULL,
		0xABDF1519A324C04CULL,
		0xC8C788DB2F375D3BULL,
		0x0E50A876A6EEE3A9ULL,
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
		0xA90402DF9380CC1AULL,
		0x75BA6A8A7A07818EULL,
		0x2E5BBED60741A06BULL,
		0x8F393C74198249BCULL,
		0x3D3C0854BD0F8052ULL,
		0x9AADD526370B8AD1ULL,
		0x6E952D66BE8C6BB8ULL,
		0x3F66265DECBCD46BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD3D04A8C7331413FULL,
		0x054A7309E0D47848ULL,
		0xBF8C410900FABC7FULL,
		0x113E94B109EEC8A4ULL,
		0x6E212B824B14C977ULL,
		0x8EF27E3F65E67C15ULL,
		0xF050A9957B832B15ULL,
		0x989D708C5A694CAFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x93307F900B86AD6FULL,
		0x2E3EDDC3A4B33926ULL,
		0x2CFB0EDCF9A67C20ULL,
		0x3FC5A4DEC7F9A6ECULL,
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
		0x2A174E791419A5F9ULL,
		0x15B0BAE5FCF375F7ULL,
		0xE225CC66EBDB57E1ULL,
		0xB5AB13EDB47D76ACULL,
		0x766BE1FFDEB42441ULL,
		0x45B891E2A36589EAULL,
		0x399DA3CDFD9B2E20ULL,
		0x6012AD8D7C3A543AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x659A4813592B7022ULL,
		0x8F8B794C62E97AB0ULL,
		0x58EE71FF2160426BULL,
		0x50FFDA7A46C24B1EULL,
		0x4FB641466F6E562DULL,
		0xC95CF460009B427AULL,
		0xE827760E53D5D927ULL,
		0x592A2E06BF780B9CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8372E1EC3F4ACCF5ULL,
		0xFBBEA2FDC41095ECULL,
		0xA0C224DAFDC5B257ULL,
		0x6B2E27737291F2E8ULL,
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
		0x21517056A836C43BULL,
		0x365946B95D0371EBULL,
		0xC8172CA3529E5AF7ULL,
		0x096AE8AF3251A66BULL,
		0x0920B0E00C79210EULL,
		0x92A6D962A7A6B870ULL,
		0x37A1FBB5476ECC26ULL,
		0x971F533B6D1915E4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0852B74C243A0F40ULL,
		0xEB004363A1B14214ULL,
		0x00C1DFDE6DFFBE4EULL,
		0xF7A9638CB52A6E43ULL,
		0xA86D2BA4C6BFF870ULL,
		0x0C24FAFED8033EB1ULL,
		0x0BCDEB08989BA95FULL,
		0x4C394B978191A0ECULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x73A47FD6DD78BDEBULL,
		0x42A006268D964219ULL,
		0x48CFC666D7F5C646ULL,
		0x2FE6A777734294FFULL,
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
		0x0C6C6A213B2365FCULL,
		0xF29E68F6FDEF27BDULL,
		0xCA6CF005E59D62A8ULL,
		0xE7FECF596967751DULL,
		0xFAF22DFF6430F755ULL,
		0xF42AA3ADF2C8A423ULL,
		0xA318081C25638A42ULL,
		0x37A5AB950944C351ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x998B661FCD6EDC41ULL,
		0xB85300BFEA022F7BULL,
		0x82BF975CF20CD1DBULL,
		0x0E3F9A555B7F7783ULL,
		0xD41DF4BF0B197E17ULL,
		0xBB531AEF8A68C399ULL,
		0xCC826AC4743B1705ULL,
		0x67BE463C6FA1FFE8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3661838EA73087F8ULL,
		0xAA49B47A92284CC3ULL,
		0x21E2B3AD3F91ABE3ULL,
		0x3618402ADC10FF2AULL,
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
		0x401624FCC30665AFULL,
		0xCF56A90B14D15FD8ULL,
		0x5DCB2752C1B05AB9ULL,
		0x16C24EEF9840759FULL,
		0x8F330870243B2825ULL,
		0x2E7FAB03A19C0142ULL,
		0x3DCBA5C63CA1B111ULL,
		0x73356EC29068139AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x185E79C3365E0A72ULL,
		0xE42EC3D6E340E392ULL,
		0xDA3EA8536692EB96ULL,
		0x3F12F895DCA53EA2ULL,
		0xFA13763FB2D51EBEULL,
		0xD97AE360D70258BFULL,
		0xF9578B361ACFEAB9ULL,
		0xEC3D4CD3B869BA63ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4A675E6A61CDBDC8ULL,
		0x89DD875E445F7FA8ULL,
		0xACC870646040E019ULL,
		0x60845FCDCB5C750AULL,
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
		0x658B755EB4CF9886ULL,
		0xD6B28CA2E252DEEFULL,
		0x0DFA607E79C4EA41ULL,
		0xC983AA685BD700DAULL,
		0x9A2EB7BFF1B7152CULL,
		0xC614D8A3796C2C10ULL,
		0x0041FCBF274160B2ULL,
		0x4ABA9F56E54A1914ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x73FD4D320AC2C0E3ULL,
		0xED6F3A82CB757B1DULL,
		0x22FB0893BF6461B7ULL,
		0xA4014B69097D04D3ULL,
		0xC474D7E4E9F5833FULL,
		0xEA9832E0FE43DCD9ULL,
		0x2AE53ED22D645BB0ULL,
		0x83E140A0F52D0152ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAB2562AFD0C87F8EULL,
		0x7DC3ECFE5ED925F5ULL,
		0x96C38917D12F46D0ULL,
		0x29C66E00F6AB82CCULL,
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
		0xF3DCE9964F35D76DULL,
		0x2F571830E4C6FCA1ULL,
		0xF870007C7C559116ULL,
		0x2850264E6625C5C8ULL,
		0x0477B62849CA4C52ULL,
		0x6048D85967ACC11FULL,
		0x75217DCE5ACC1F72ULL,
		0xC7422D4D8F9569ECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x680E4885C458491BULL,
		0xD82CB1DFED1D4FF4ULL,
		0x1C0A4ECE2E2B2928ULL,
		0x0E75FD9971C8F90BULL,
		0xF54676A5BF2CC55AULL,
		0xD51A2A48D716EF19ULL,
		0x0546FDE798AB2D54ULL,
		0x5442BE513DCB9489ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCD1E0E711E3F99A8ULL,
		0x00183CC66DE6D96DULL,
		0x76D4ADEF1F0E5850ULL,
		0x2BC4A22918527980ULL,
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
		0x5224A9898DF8D17BULL,
		0x36F0A9466BCFB6C7ULL,
		0x670F9BC5BB94F2A4ULL,
		0xD2D86FBA1CC68AD9ULL,
		0xB62402EDF21FC258ULL,
		0x678459266F999AA5ULL,
		0xD30886B2860B3746ULL,
		0xF343667FCE572712ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1BCE92F729785FEBULL,
		0xA65E76A47ADF00B2ULL,
		0x7972973AFF46B6BBULL,
		0x67E35A62F2F374F9ULL,
		0x826ECB2BA6C373B6ULL,
		0x66A706F56D052DE1ULL,
		0x42D1800709D39783ULL,
		0xD53B878A13A32E3BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE33C5D6994341E47ULL,
		0xB16C65E852F8DB34ULL,
		0x55C801FF2C8FF2DAULL,
		0x60202DD0E08A05DFULL,
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
		0x90A0444EA0A59740ULL,
		0xC12EFE20438B0DC5ULL,
		0x29C95AF7615B8234ULL,
		0x9148AEFC05858B46ULL,
		0x32E78003589AB40AULL,
		0xCD7B94D4CFD78B42ULL,
		0xB348EA09BE6DFC1FULL,
		0x49AE31AF205F942BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF6DCC03A20DE6443ULL,
		0xE0CD3CF6BE524049ULL,
		0xEC8152569593B069ULL,
		0x5903B28DEF1A35EFULL,
		0x785C335E554D6372ULL,
		0x9EF0B8B3BC03D084ULL,
		0xC995951A6787D35FULL,
		0xC6509261A3278D01ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4A70E492FD4126CEULL,
		0xC8FE6E1276A685A5ULL,
		0xEDE6A427B1F1DE51ULL,
		0x382AA1EEACBC658EULL,
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
		0xE44493FBB6AE11ABULL,
		0x78966C4C570AFC62ULL,
		0x06DD71030F9E9A81ULL,
		0xF85D2DF203B1D849ULL,
		0x877A6BDCAF0EFD27ULL,
		0xCB55BA2B0EDFE4C7ULL,
		0xC45284DE1D124568ULL,
		0xFEBFD74A91AAF6D7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x32D2B9F3E86AEA04ULL,
		0x99FAB4FA6E70BBF5ULL,
		0x43C97A191E040D3BULL,
		0x98654C9DBCDC7627ULL,
		0x94B37DC569C4C3FBULL,
		0x932DD7217C8C5452ULL,
		0x7A64C90C053AFD02ULL,
		0x872970BD5206AFE0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBAF9317C1747A6DBULL,
		0x34876ABDA101B1C9ULL,
		0xBC5DD8197B8F4C72ULL,
		0x204B1A4BB937EAD6ULL,
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
		0x0A7CBD59A47F4AA0ULL,
		0xF7BA9480AFCDAA5AULL,
		0x7485628C013BBB49ULL,
		0x310D183883EAAFADULL,
		0x6444DDE04D21232CULL,
		0x22E7FBF3DABDBFC4ULL,
		0x1B40BC7F1E3635F0ULL,
		0x3443BD02DE130937ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x514A00BBA8849A03ULL,
		0xF2506D3CDAB7565BULL,
		0xCAC669399E50A6D6ULL,
		0x74E175503471E29BULL,
		0xC657D2B1F663BBBCULL,
		0xB5534BCD7516FCC1ULL,
		0x3A481B71A87E99F3ULL,
		0xFC37D393BA157EDAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2A62657EDC1806C9ULL,
		0x497C4CF6EBD74662ULL,
		0x0EA6E151DC2C3BEBULL,
		0x0DF04967A71B56DBULL,
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
		0x76603135E385B413ULL,
		0x985E651262210E42ULL,
		0x4F304DB2CA775BB1ULL,
		0xA3ECE9D31F64A50CULL,
		0x55B747531EB6CDDAULL,
		0x49414C784EB540DBULL,
		0xF5D7DE5F4F9F52C1ULL,
		0x45F8180A0AFA4F70ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4955A37877821D02ULL,
		0x6840C5F3AC02037AULL,
		0xD79B82422C13F495ULL,
		0xCB0C5239221A4DCFULL,
		0x99D28CCA0E687A5AULL,
		0x8966378F8C664F88ULL,
		0x68E303A89D987EB1ULL,
		0x4985A1DD1FF57C9CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x10FE3E15D7A3FBEBULL,
		0xAAA2B9AB8DD6DD10ULL,
		0x63ED428F0B66E172ULL,
		0x51DE2244E001A2C9ULL,
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
		0xAFF8BD8D887EE246ULL,
		0x8CF581407DEB2EC9ULL,
		0x1FA19E948EFC3F63ULL,
		0xB22C789D312BFA55ULL,
		0x2755F24E0D1AE9B0ULL,
		0xBE519D9DFD1486D5ULL,
		0x465D1EB5D08F0868ULL,
		0x40EF7211B59A4ACDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xACB8E173340F1723ULL,
		0x638A1D742EC4406BULL,
		0x56A9FAC43A4DBFBFULL,
		0x5A6A17D136F60BB4ULL,
		0x2F98BF202DCC7AFAULL,
		0x8EA1FDC07B169D2CULL,
		0x8877AA32796175F0ULL,
		0xBED4B0B1D897558DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC95574E97A143768ULL,
		0x3D7D1EAD9AD79D72ULL,
		0xF906EF4F45723D7BULL,
		0x27BB1506C8A65616ULL,
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
		0xB396FAF3B399211EULL,
		0x38B28B6E027E52FAULL,
		0x567F9F5D12ABB852ULL,
		0x778F7456542EB111ULL,
		0xA35E674EC6E30A95ULL,
		0x3641E7CD91DBA457ULL,
		0x11C7921A8364A044ULL,
		0x2D4D0BD377614A8CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC2DBBE18A4B5C130ULL,
		0x70E5B4D531854F70ULL,
		0x09E0DBB8884B2681ULL,
		0xB5F396F50362D6A8ULL,
		0xEB6853DFF4838FF8ULL,
		0x348B62A77716F805ULL,
		0x41E6762E1911CB16ULL,
		0x9E5C6CADD26E5B0DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3F421F4E490F90A3ULL,
		0x08E49A40CA2A97ABULL,
		0x2808E8BC52AC36A5ULL,
		0x79537CF7CCDB673CULL,
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
		0xE493797C4D51016BULL,
		0x74A52670FB5C927EULL,
		0x9C973075B109D2C1ULL,
		0x00A7CA717F477DD9ULL,
		0x4DEF44BFAA8B1567ULL,
		0xC29C86F8F9D82E66ULL,
		0x1E8A1E0998FCFC18ULL,
		0xE9D4685F877DCE00ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x535290129605ED39ULL,
		0x30A06B2574A7290DULL,
		0x72D3EC739E02FD3EULL,
		0x3E5E62DF7922CB0FULL,
		0xEAB5A5A108657658ULL,
		0xBB66A059B1389C79ULL,
		0x9FDEF552C77C91D3ULL,
		0x599673DE696B0A5DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4BCE87F5C8E0B38AULL,
		0x5604F6F04E651288ULL,
		0xF72B4F252C169BC2ULL,
		0x2B7BB2BC7CEDBCE8ULL,
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
		0x4052DE8B73C68491ULL,
		0xA9803E4CF1817177ULL,
		0xA8FE498EE28F8071ULL,
		0xFD47AD7C0D8B83F7ULL,
		0x516488FBC53D017AULL,
		0x770908B6A845359BULL,
		0xB3C715F735566A2BULL,
		0x2F064DCC7CD6FB56ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x195CF996FAEF5693ULL,
		0xF984FB495F9A2D01ULL,
		0xDCF25EBBE6482AF6ULL,
		0xD4E4D365D4CE52CEULL,
		0xFB8845C7AF759B7BULL,
		0x9B3144B3A768A90EULL,
		0x0751A3B9E9974C48ULL,
		0xE7A56823EBA3C939ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE5A7DEAFB4704DC3ULL,
		0x52025B75B2A4214AULL,
		0x657ADFEC3AA5C527ULL,
		0x40C4F11BC656A190ULL,
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
		0x740C3FA2B573F0F5ULL,
		0xED281F9BA0D88C83ULL,
		0xC557009A5B5452FBULL,
		0x01D930FEADF5B876ULL,
		0xB95F3D5FD721D6C1ULL,
		0x4EF01A6E043CBED6ULL,
		0x6A56F407EDD8AB8BULL,
		0xA9020D81A81A5936ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x81A501B7641574E1ULL,
		0xB5E7BC3A9947918AULL,
		0x51076924B39BCB6AULL,
		0x506D42405DFCAF39ULL,
		0x3696A67CAF7BC02AULL,
		0xD518BBAF5EAE6CD7ULL,
		0x139FD8F20B258142ULL,
		0xD724152AF3E1D6B9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5C2DA3A33405D561ULL,
		0x4D3873AD9AB126E6ULL,
		0x537D9CB54E50CE53ULL,
		0x585ECB9D105C67D8ULL,
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
		0x27DE351DDE1451B9ULL,
		0xCE2A517E7EFCA894ULL,
		0xAC91ABA53E9AB5B8ULL,
		0x2EA2C33514F210D1ULL,
		0xB0A70B0695149CF2ULL,
		0x3B3FD94824C1AD12ULL,
		0x7FD28CC09C2D24BBULL,
		0xF58F1764A195CD5CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC9F0AE637749C956ULL,
		0xE4AE7CB84C0A21DBULL,
		0xF562A10D79064527ULL,
		0x344D48185C479843ULL,
		0x5A04E2BF94374393ULL,
		0x5E6ADD6871794B8AULL,
		0x44193B5DFD1F4B0AULL,
		0x03A1FA4B0E1ADE53ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x39FF814487A5D1C2ULL,
		0xB11937FACFB100F5ULL,
		0x94B11F3B61A2C0D1ULL,
		0x6387CCE89CE9F3ECULL,
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
		0x9359AC6C0AD00C11ULL,
		0x32E494E5CD0779C1ULL,
		0xDCAC28C8868EF02BULL,
		0x064F10983B97EB6DULL,
		0xCD6AD445A48A0E3FULL,
		0x95C9D79CBF646BC1ULL,
		0xA6170D0D3B7ABA97ULL,
		0xBB3281C3833FBF7AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4B68EB92721416D2ULL,
		0xD78776A454A2249DULL,
		0x65E7052666585D79ULL,
		0x871D4566178F274EULL,
		0x308E578F33177A72ULL,
		0xBAC4ECBD1D8C1EE1ULL,
		0xDB1765DA106F4C6CULL,
		0x60EF163C1CCCFDD5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x90AB43EE6FBDE788ULL,
		0xDE17FB737E80BE7BULL,
		0x98B7F53A83E8ED0DULL,
		0x6533C14B59118295ULL,
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
		0xE142B660C902F334ULL,
		0x1D6254D2B713F4EBULL,
		0x55D15090985FF5B4ULL,
		0xA0017DC49D461417ULL,
		0x36E7D630D0C085A2ULL,
		0xD96DC088415267B7ULL,
		0x4496DCB353C2F7A3ULL,
		0x190972F45655CEECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF62E234CDA80D87ULL,
		0x24745A69220CFD12ULL,
		0x88A23B1CB5AAB8DEULL,
		0x487C10FB1060E2D3ULL,
		0x331078CD52FC49D5ULL,
		0xD85194193F25B604ULL,
		0x85EC51790FB23C8BULL,
		0x9510699C873E5F2CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC3D7B0F0A67BC35CULL,
		0x231C92E3E7A9586BULL,
		0x1A7FC019FD310266ULL,
		0x6E7CCFD24A5FC7BAULL,
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
		0x20F076EAA38983F1ULL,
		0x1CC9B1E33BB59C04ULL,
		0x5B56341FE93AE3ADULL,
		0xD56F88FAD667106DULL,
		0x7ED30551AE2F39CCULL,
		0x8D8FDFF4870C2677ULL,
		0x477FC4EDC3E9A0AAULL,
		0x1A2D4BA9BC7F66D7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD5E2D789B2F6F0E1ULL,
		0x0208EE9D6308D28FULL,
		0x1FCDA5FB779070FDULL,
		0x61BFB9430944E177ULL,
		0xAFAC41C2CBE9F901ULL,
		0xA687425ABEA1202EULL,
		0x840379134EF4C4EDULL,
		0x24146F637F0A6AC3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0ACEA69686DA30F9ULL,
		0x66082819988FB843ULL,
		0x3FFBD091CE0310BAULL,
		0x7B608224EC7F99E5ULL,
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
		0x92DD2FEDB531CBA8ULL,
		0xA630E7235F7AD833ULL,
		0xF24941A57F451D6BULL,
		0x42C660002CE6334BULL,
		0x6297CE83FFBC092AULL,
		0x07B07909236C8C58ULL,
		0x0ABBC556A93FFA48ULL,
		0xAA875F54141D6B37ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE6046DCB4578B474ULL,
		0x9D4309896C24503DULL,
		0x69C0E6EBA7A20BFDULL,
		0x3EA59556678216D7ULL,
		0x5E7DCE5495CC71A9ULL,
		0x124D436C2E489DB6ULL,
		0x56CE0A559AD7A29EULL,
		0x5AA8A4014EDBCE01ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x48B4C92C2949960FULL,
		0x75A7D2E656ABF402ULL,
		0x3DD21CE1FB2014A8ULL,
		0x5F3098F30D21726DULL,
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
		0x973249BE14CC0C73ULL,
		0x3E8D291B3FFBCB1DULL,
		0xE20BE11882E6AD18ULL,
		0x9298F812B7985A30ULL,
		0x4ABBCF6AA03253EBULL,
		0xE3CEB33AE39D5EB8ULL,
		0x03022A47A3DC1C68ULL,
		0x6BCF505EADB4435CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF04DB0DADEA776B2ULL,
		0xDBCD77B5375280F8ULL,
		0xCBB2EEA96C2FA005ULL,
		0x067E519795B2B297ULL,
		0x2EAC245E9B5B3630ULL,
		0xB0B7CCCFC3AD456DULL,
		0x78656B0485EFABFAULL,
		0xE6DE7C9700C6AC70ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD137FCABEE12FCD7ULL,
		0xF825E54CC64D0B4AULL,
		0xA99D566587CFBD6DULL,
		0x47DA161ECD2A0E8FULL,
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
		0x254EACBFAE8EC1F9ULL,
		0x47D43BB9B566E306ULL,
		0x936DB089C49794BDULL,
		0xE371039391E1B8C4ULL,
		0x06A182E277CA75A8ULL,
		0x2BE64C3587A4A7BCULL,
		0x2FDC462EF2BD7A55ULL,
		0xB482CEEA2D46ACE3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC0C6023E58F9FE90ULL,
		0x7D6D87DCB9E9A41DULL,
		0x98812CB58B574652ULL,
		0xF6C1F720AAD63ED0ULL,
		0xE521FCDCAA21AF33ULL,
		0x3B1D166FCFCF90E6ULL,
		0xBAAA2E169D73A196ULL,
		0xC7343DBD485CD170ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5D768F5DDCA23855ULL,
		0x8844AF36451EA28BULL,
		0x605C1770E2367AC2ULL,
		0x2658991CE1C20CF1ULL,
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
		0x2933DD2C13884754ULL,
		0xF3A12F4D5C338A88ULL,
		0xDF5B91B1115642D1ULL,
		0xBDA82CB19B909EB1ULL,
		0x4FB44D7F6BF9E7ABULL,
		0x53895BD0597D2C94ULL,
		0xE5C16B2EF9F4BB23ULL,
		0x95506437919BE846ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1158AE926D1FE624ULL,
		0x7A006955CAAAD0E3ULL,
		0x75308D42DB020E16ULL,
		0xA14797D7B85272CAULL,
		0x34A1AB9F59D88FB9ULL,
		0x60CD929CD7AB98BBULL,
		0xAF82A8DE067F0236ULL,
		0xB6920C00C1A9C064ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1C9F35DC575B6E5EULL,
		0x8180A39CD6A4ABDFULL,
		0x777BDC7259CDA7E7ULL,
		0x2CA1ACFCC130177BULL,
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
		0x6D15C739FF493966ULL,
		0x9A31169E672DE28DULL,
		0xCF80DB2653BD3503ULL,
		0x801E7DAE8D73E73DULL,
		0x651E7D2BD0159193ULL,
		0x5497D745C6D7E054ULL,
		0x0EECFDEFCC4076FAULL,
		0xE17F930FE9B2B9E7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x82D8B9CBB0D91A4EULL,
		0x26D3316BBBA7841DULL,
		0x399AE1B3E25AC6EEULL,
		0x412773B615E94492ULL,
		0x285E79C0DC699D9FULL,
		0xB4530F03BC591B52ULL,
		0x8F4CBF1538E8111CULL,
		0x44DF914F99C2EF72ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEEBD8F4E79F658BAULL,
		0x3D939F003A579CC4ULL,
		0x87AF4DE450818CFBULL,
		0x7EB74C845522AFF6ULL,
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
		0xA73E65B0146E8B8EULL,
		0x3C78A2F2CB7BDF7AULL,
		0x2CD3DCE781ECFBADULL,
		0xB1405BB290638990ULL,
		0x7F4A74FAED42F307ULL,
		0x0CC5BFD594D8EBBCULL,
		0xF779DB00141C581CULL,
		0xDD178C54BC612962ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3D1D0F24B9392811ULL,
		0xCA40521D072D1B80ULL,
		0xBD6A31765B0C1FACULL,
		0x71EDB6296D0B24B0ULL,
		0x77439E338B2CA004ULL,
		0xF3D70EB472CF2FF4ULL,
		0xE170DF5BDEB8069FULL,
		0xD1ACB9DF35030BDAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9B253823EA85B628ULL,
		0x25A69BC0D1C0A3ABULL,
		0xB4BF05D113C4F46CULL,
		0x712DE2FB3B50C712ULL,
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
		0x505D11FF6335F684ULL,
		0xE3C88FD4D866ECD1ULL,
		0x71D0CEB663AA7B0FULL,
		0x3D807A005CDC64ABULL,
		0x834A633FDA78D8C5ULL,
		0xBA947E903524BF0FULL,
		0x67AC4ABF636013EDULL,
		0x32893B06091CC3FBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFA6990019D7EDBDEULL,
		0x5DB91E8327581B01ULL,
		0xE3B11E72EBA8A450ULL,
		0x527C219070684B9BULL,
		0xE4680BA779F783E1ULL,
		0xE1D67B4C6CDA095FULL,
		0x3B29C25255C3DDBDULL,
		0xD804CA6B0B76DC8DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEB8C829C18E9B0C8ULL,
		0xB243ED616C25C9E0ULL,
		0x297FF0737D31E1D9ULL,
		0x5AAD0F719314736AULL,
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
		0x529C030806766608ULL,
		0xE2DEA0DCA5CC097EULL,
		0xA86DCAA2EF550CFDULL,
		0x9EE3B6525B381B47ULL,
		0xDD6491E9C7E2FF62ULL,
		0x49B8EC74415A9BE9ULL,
		0x78F8ED109CB78A3DULL,
		0x807D3B51FA0A9F94ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x12127664C1544F11ULL,
		0x16CB60E2FCD39EFCULL,
		0xD2704FF3FC4FFE03ULL,
		0x453BB460F4D31616ULL,
		0x7DCE6AB52DA7D273ULL,
		0x8CD45FF9ECC78D78ULL,
		0x2700FBFA5F8CE44DULL,
		0x5788290F53166B41ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x70D35E7229EAC355ULL,
		0xD6001A2236CC8F56ULL,
		0x00CB43FC0759B090ULL,
		0x6E08B7D62EA4C98FULL,
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
		0xEEDB8E7539563AD0ULL,
		0xCEB8133352CCCE5AULL,
		0x4383BC8B22ACC96CULL,
		0x7FD94B5B500B73B1ULL,
		0xF7D813D89A779E7AULL,
		0xC88BF3AAC7D9B97EULL,
		0xEE2478267C033907ULL,
		0x358110A962889359ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA4CD1CDF1CF8D693ULL,
		0xB3C9D1AA4E66814AULL,
		0xB1C7467F19A3A97EULL,
		0x8ABE1893B5800F92ULL,
		0x559E3EE9DE1B40B2ULL,
		0xAC4ACAC38F6A0FBEULL,
		0x89D511236F4760B3ULL,
		0x98CDFC238CEDCA19ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5EA40D0612134DB3ULL,
		0x4C9A53DB64F97FA8ULL,
		0x7585C07FECEB3C6AULL,
		0x37B03EA54F8543ADULL,
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
		0x16E7F14AE5FF8B1FULL,
		0xA75106E66EDE1E43ULL,
		0x96055DDD8D181E27ULL,
		0x1790BF277BBE9897ULL,
		0x3C74572AE168C1D3ULL,
		0x016448F51CF35E36ULL,
		0x3874C0EECB7236EEULL,
		0x9B219ACB9A3AB38DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFDB9F670DAC7647EULL,
		0x925931AE9B2C85C3ULL,
		0x0BC119F48396F51CULL,
		0x1CE33B44723479D7ULL,
		0xB2D9CCE8A48F8729ULL,
		0x3C3763A556737818ULL,
		0x4ACE3388CBAD9B23ULL,
		0x46D57AC7A6E668ABULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x861E80AF1376DDA5ULL,
		0x59A1DF0F4AADC0E1ULL,
		0xD0FD410D00B04924ULL,
		0x7DFA4479280D3C49ULL,
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
		0x600C06906631A8E6ULL,
		0xD28819D54A4E29D2ULL,
		0x0C211921C6F88145ULL,
		0x59DFC95AEAD4F0A4ULL,
		0xC315BA9825F2028DULL,
		0x34DD5C0010EE788BULL,
		0x4812387620EC6B28ULL,
		0x756FCC6933C92257ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFD15F235EA411F37ULL,
		0x1FC114B4031FADDAULL,
		0xB745C41E8A30CCBFULL,
		0xDA4046BDB44B754CULL,
		0xFACE5AA59BCC0FF0ULL,
		0x70452B3B615F5E95ULL,
		0xE09EEE6327C56057ULL,
		0x646D4AEB76FDFBCCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1D8E525AFD928D49ULL,
		0xE15E4253566C5673ULL,
		0xAFF853D438934F83ULL,
		0x05FEBB473CB133E2ULL,
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
		0xD33A40E461F9CB2EULL,
		0x26D94BDD093591EBULL,
		0xA8CEF23148A5B52BULL,
		0xC3F4BCDC88DC6240ULL,
		0x8A70FF49F28A6ACEULL,
		0x2C18A60D65EB66AEULL,
		0xFAA3E3D48C497FE0ULL,
		0xEBBA85F8FDD6F397ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x270C9A3A46D2816BULL,
		0x291ADE4295C69C00ULL,
		0xD95CCA2E19AABFBFULL,
		0xC72FEE2C49340641ULL,
		0xC9B49BD5DD8BBB3BULL,
		0x61492290E2B74E75ULL,
		0x916B3BFD38458E33ULL,
		0xF595F30DE1C5BA26ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x482469E538F5595CULL,
		0x188BF215ED2A8E58ULL,
		0x6DDB11F9A790D512ULL,
		0x06329D966A36E2D4ULL,
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
		0x4C93CAA75465B241ULL,
		0xAA30F7D90129B80DULL,
		0xFAE9716F265B8C40ULL,
		0xD0AED7D88C0B136AULL,
		0xB0FF561EC8F36564ULL,
		0xE42B963DBE297BA3ULL,
		0x7B97576DDC745ADEULL,
		0xE5E1C0BCA4BDFCD6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC8CD6A5D1AAC5459ULL,
		0x9670090B865B736BULL,
		0x8E815DA65AD2C97FULL,
		0x817532D9EB3A7E26ULL,
		0xF97CD8EC223CCC41ULL,
		0xBFA63CBC28411BE4ULL,
		0xC02EA163F0732EA3ULL,
		0x54B4EC407DFAD9E3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC124F5CEF8D41C4BULL,
		0x7F8C3809BB4C7AF0ULL,
		0x3DF31941D3B55388ULL,
		0x5BE12F6C61C7C54CULL,
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
		0x82D9B53EC400A5E4ULL,
		0xEAF3942A4A6A18A1ULL,
		0xE0812CC24172295EULL,
		0xE490D0A11F7DD65DULL,
		0x32A2DFA61D368E40ULL,
		0x19706C481A3EC1E6ULL,
		0x15481ED7A5A3DFDEULL,
		0x46214E8DBAA30080ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x06930353D15A058DULL,
		0xBEE73BD127403D62ULL,
		0x3510DA99EF3D3D85ULL,
		0xFABCC00637ABE451ULL,
		0x39AF63E6B5CEB875ULL,
		0x7D1E39ADC5FDD3CAULL,
		0x15595DCE0348EF6CULL,
		0x21267C905C4B8324ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x706B10544C105D37ULL,
		0x603FDB41A4CD3366ULL,
		0xA8E0F9966BB49CB6ULL,
		0x670F3C36E8CE8DB4ULL,
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
		0x4DC71CDBC395D3DDULL,
		0xF1CCDE1D52F6C243ULL,
		0x8389BB18051E63EBULL,
		0xF1BEFA94300E270FULL,
		0x449169C7AAA29EC3ULL,
		0x953FACCA78A1D674ULL,
		0x101F221089F56CBBULL,
		0xB69426212E9DF891ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5EF43CF85BDEFCC9ULL,
		0x9438A49426C514D7ULL,
		0xDC513F99A8CF44BDULL,
		0xD060B1855F1FCAD3ULL,
		0xFB54CB12C4C05692ULL,
		0x6CD1425973AA1CE4ULL,
		0x405ED3C668B4E96BULL,
		0x0BAD3EB7ECF50451ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCDD26EBD874D9210ULL,
		0x5DF8064FE8F738B0ULL,
		0x7DC41A7F4BE29D14ULL,
		0x7FA4A2AE90029DB4ULL,
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
		0xC5E614992B38C8D2ULL,
		0xB5855E6BF283B82CULL,
		0xEC59AC5C32D37E85ULL,
		0x3C0993762CCAB442ULL,
		0x305CDE5395D15DFAULL,
		0x2FA5320B77C0C320ULL,
		0xC194A8C4E8B8DF4AULL,
		0xCB1C2ADE7471D425ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6786A14FC0AE8038ULL,
		0x73C5409A2EA6CF53ULL,
		0x172911E6A68DDC4FULL,
		0x57F97EBAD8987F39ULL,
		0xC71F1CEDF9DA7B66ULL,
		0x19AE49CEB6F0BD83ULL,
		0x991341B5664DE3CEULL,
		0x80EA901A985E7305ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFD8A285E912FEC21ULL,
		0x846696D662BDBE10ULL,
		0xD865E6C2E826F6A1ULL,
		0x676D0DCDFF129FCFULL,
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
		0x7D4CFB5D03CD8D23ULL,
		0x1B3815D48B6E9EC2ULL,
		0x3E1399594B76480DULL,
		0xF37942391F37EABAULL,
		0x7D2F47D9657A169DULL,
		0xF5F19ADAD9F4000EULL,
		0xCEFE84561A2EFF51ULL,
		0x0D31096C377165A8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3C1B1F450D11F023ULL,
		0x439F9FA5DB74D3F0ULL,
		0x94F0C1B9931A6FA0ULL,
		0xC6D947C8A5A6D414ULL,
		0xD50DA35C80912D6FULL,
		0x6C82DF4EC546CDDAULL,
		0x99F41C2A83F5A7AEULL,
		0xBCF8B61D0D5D59B8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x363046A1F14E35F8ULL,
		0x3E084CF9C1AF3E7DULL,
		0x88AE4E1804DEDAB3ULL,
		0x14FC5830B88ADC4DULL,
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
		0xF612290CCB483F4DULL,
		0x32F353286A007459ULL,
		0x9928851D31B77C58ULL,
		0xD08E3243DC3EA068ULL,
		0x9460834873C5420EULL,
		0xDD957026FA1B54E4ULL,
		0x7654F09FA4C4BA6AULL,
		0x38D8509F28EE2886ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD8AB9DD86D157A2FULL,
		0xAB217B37883EBA78ULL,
		0x80E2104FADD43DF7ULL,
		0xCA0CE0F9DB772B32ULL,
		0x1E8DE9859FA463A2ULL,
		0x94C909589F356D00ULL,
		0x5BC414863E4A68CFULL,
		0xADA591B0CA334734ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9AA95E1FDB13C68DULL,
		0x56291A925FE225CAULL,
		0x09C72092BA0B5B6DULL,
		0x3009A8AC1084E766ULL,
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
		0x4CE7CBC2B73B3335ULL,
		0x312E2D8827D5FBF6ULL,
		0x2ECA2EF80A73E265ULL,
		0x4E89C295CBDE48EEULL,
		0x5AD20E2C50D1033BULL,
		0xD088043D72ED60DCULL,
		0x1E198AAA7F492FCFULL,
		0x74F3F087ACB6944AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x380413D705230396ULL,
		0x270278679D4D8224ULL,
		0x9F40715B4A5FA08BULL,
		0x3DF3DB036D2759DDULL,
		0x0310AF5B6F9E73ACULL,
		0x98CCA30BF1A8CD4FULL,
		0xB9BD591AB168F6B2ULL,
		0x6889E12EA69A283CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1B97CAED1F997F12ULL,
		0x4FFC2279BAB660CDULL,
		0x753918F54F5CBC30ULL,
		0x68542EC946EEF90DULL,
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
		0xCE6AE5AB959982B0ULL,
		0x51ABE1FE28F6969AULL,
		0x1465500427CAD43CULL,
		0xFDF90395B24E6850ULL,
		0x2620DFA3743D4F8EULL,
		0x3C22B2B15884C9A6ULL,
		0x83BBFB4E2338FA26ULL,
		0x7A7A6C66E178BDDAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF39BD7A9CBBFAA4AULL,
		0xA17AD7718A356097ULL,
		0x46E643FDA23176F0ULL,
		0xB02DF9E21638C848ULL,
		0x0353D3F4EA3BA61BULL,
		0x9DDDFF333D09EDBDULL,
		0x46CE6E16AD32874AULL,
		0x9538F8ADCD58C7B9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x053EC9EA4618FEE0ULL,
		0x2E63AF44B2FDDA9EULL,
		0xD8C202420A8E69E5ULL,
		0x5582372C98D428F6ULL,
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
		0x45606A16A97C8192ULL,
		0xE3DB4D111CB37D6DULL,
		0x1874667D6E67F49CULL,
		0x95F802915079BF7EULL,
		0x24E74FE032E5A47EULL,
		0x86AD4273E95CF8A4ULL,
		0x0884665389A1525CULL,
		0xD1CF9665EB6C015AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC71930167190F811ULL,
		0x76AB22E1BDC41A61ULL,
		0x247EA68F51589EECULL,
		0x2448BE2232AC5B99ULL,
		0x68BFA0327DC6574EULL,
		0xD4D26AF4A4D1C239ULL,
		0xCF29C9271B5AAA91ULL,
		0xE048C6A89942ACACULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6C2B4DC91A90FE55ULL,
		0xD3AC27138B9976E3ULL,
		0x776914867B8C3DC6ULL,
		0x4BB21A894FEFF59BULL,
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
		0x754986F2A275A621ULL,
		0x62FEB2C9DD0E67F0ULL,
		0x67EBD83973BD4C27ULL,
		0x8642F2CF08FC1D1CULL,
		0x0626248F986F2212ULL,
		0x2AD77BDED4B2EE6FULL,
		0x92E75FCC54A6B204ULL,
		0x75D3E756B95F180BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x015E74C7E6213469ULL,
		0xBD9EA6DCC4753EBFULL,
		0xD2BD1FDEB2B10C09ULL,
		0xD7FC7BDC2D44B3E5ULL,
		0x296F746C36619430ULL,
		0x49653F4FDD32A0B7ULL,
		0x08D53D62958CA208ULL,
		0x221CF35F69CF9732ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3709376B4A57830CULL,
		0x1C550925D5A4B27CULL,
		0x13DFD40D1EEA9F81ULL,
		0x1B6EADA8AB048981ULL,
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
		0xD7ED232D7AE4E5AFULL,
		0xC9FD96A9B558DC89ULL,
		0xFE718862A01E58A4ULL,
		0x168FF98FE3745FD6ULL,
		0xF290371E425BD55FULL,
		0xD6B0BEC7F6B5058DULL,
		0xBA87E802042B2B59ULL,
		0x3D867317FEAEC938ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xADF34D87EDB5107CULL,
		0x1DACB53AC6EDE930ULL,
		0x2659A4061CD25569ULL,
		0xCEC998FD14750C5BULL,
		0xB144E8EB749D02C2ULL,
		0x41D29702B7FC78EBULL,
		0x5110BF22823D6443ULL,
		0x222074A43D461885ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDB277130178318F3ULL,
		0xC54AC8B63DCFD36EULL,
		0x7FC7F589CC979095ULL,
		0x58EA25C184898E1DULL,
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
		0x1034C532AC33FDD6ULL,
		0xBFB38BD759DFC8FDULL,
		0xF53F4FF0C4B59CA4ULL,
		0xCFD974015BDF6EE7ULL,
		0x91546BCA7C065747ULL,
		0xBC723C020254B2E5ULL,
		0x6451D6E08F0B774FULL,
		0xA3BF7F6FAA9E219AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCE03229E19D497EBULL,
		0xAA69E542C865A4B0ULL,
		0xD7650A845A904304ULL,
		0x3AD227D09AB51A32ULL,
		0x45CA89F672E6D30AULL,
		0x59D1414A73229386ULL,
		0x405FED99144CF926ULL,
		0xF002E926A89B6FE0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x78A9280DED0D0557ULL,
		0xB92EDDD3D2EACC71ULL,
		0x73C2E608A26C13C4ULL,
		0x43059B070D90B656ULL,
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
		0xC41183911E30D96CULL,
		0x3EDB61156B760A51ULL,
		0x1DD4B158F1DFDF1CULL,
		0x908080177295AF0EULL,
		0x2C8CC22F44650B2CULL,
		0x1CFA1FD2D07A86B5ULL,
		0x17084BA1E10A34B8ULL,
		0x2A7CDBCE9BC168C6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8A474AB73E04F974ULL,
		0x6D3BB706BC688B0CULL,
		0x5602EE7A4C89D2B0ULL,
		0x2A0D98A347E90374ULL,
		0xF9C6B11297D56816ULL,
		0x26EC07BD76E2FDF9ULL,
		0xE2D6388CF07414D4ULL,
		0xD51431BE12FC911DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC330C31B7D7E1186ULL,
		0x57B73D39FB8BCB0EULL,
		0x874097FA5B9EC842ULL,
		0x13FC25E877E4AE91ULL,
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
		0x04FFC962B285436EULL,
		0xB7EE4E772B23545EULL,
		0x20A61953C0D9EEDBULL,
		0x51ACA4355DBEF705ULL,
		0x036092A2853C487DULL,
		0x6D06ADDF20F2706BULL,
		0xC50F3FA0060B0B59ULL,
		0x5FF9E087CA412955ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA5901E2E9A075159ULL,
		0x904F4E7F41E13A99ULL,
		0x090EFBFA1AAC429CULL,
		0xDD9213DC89D23163ULL,
		0xB4DC2700D9CBCD06ULL,
		0x91A6F1B18D232724ULL,
		0xE9BC13DD4BD3C1C1ULL,
		0xE74D9D3B852E83E8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0717A5338B3042A1ULL,
		0xB7D4EEBBDA06FA34ULL,
		0xA5EF9C414A6298C9ULL,
		0x5DAC8DAB14B153CAULL,
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
		0x01C4C8098CC787C9ULL,
		0xF41BF90D04E1F2CBULL,
		0x1E6525F79A589321ULL,
		0x4039B34780CCAEE0ULL,
		0x5FBB625951E38032ULL,
		0x064FA63469966B52ULL,
		0xD18190CF7BB20A8BULL,
		0xA52978613BCD00B6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6D8FAFA1589C8F90ULL,
		0x7E8A81DAEE78E8DAULL,
		0x6F14CA124726D3D3ULL,
		0xA999E29E83DB6FACULL,
		0x545AD0CFE140154CULL,
		0x7451C640F018472BULL,
		0xACE9DCCE2AC93CCCULL,
		0xAF83E94420A80C49ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x448AB2CEEC6CD611ULL,
		0x2140B5561F2267BCULL,
		0x1DD5141755C04998ULL,
		0x0D330EFB046D8767ULL,
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
		0x16A151A3B5F886E2ULL,
		0x8C70F910C45EDF15ULL,
		0x9D188016F684D7D1ULL,
		0x73DD8EB62CAFE5DBULL,
		0x70AA5C2ED77A1EDDULL,
		0xC9F55FA47E2EE24BULL,
		0xEA7CA6AEEC130840ULL,
		0xE43C8770C5D580D2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1D1849F361B62377ULL,
		0x4F9FC6B1ABB69DF5ULL,
		0xBB3DE4C66022F72DULL,
		0xDCA0782120E1412CULL,
		0x29CD6C4C83D991F1ULL,
		0x318123D55D1AF5FBULL,
		0x954402287DD4CD7FULL,
		0x58A84EB28EAF7786ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7E54A348BE17516BULL,
		0xDE12131E019D550AULL,
		0x88430744F39E9960ULL,
		0x4F3D82D13B740603ULL,
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
		0x0D2A0156FB7627C6ULL,
		0xFBDCF7099F9A73F0ULL,
		0x292DA24860793739ULL,
		0x2425AF5B50B17B0DULL,
		0x1AC216A132D7B931ULL,
		0xCB16D3FDDE6C1525ULL,
		0xFAB659FF091E3E23ULL,
		0x0F66B08D608F8040ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA18561C7F4D775B0ULL,
		0x47B77AFC1B3527F6ULL,
		0x370E5D5DA1DC2080ULL,
		0xBA1F32A69F8336B3ULL,
		0x85E775C8B05FD3F4ULL,
		0x7D835D18BEFAB982ULL,
		0xCA405A63E9033FCEULL,
		0xDC89DDA70B87D136ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x84187FB2646AB477ULL,
		0x380922102F38E61BULL,
		0x23A335F1829ED763ULL,
		0x76CDCAE550523FDDULL,
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
		0xCA79AE5B7CE15429ULL,
		0xD1B3F9C6E4ABD127ULL,
		0xBE1EB875E506E315ULL,
		0x432C62A4150B22AAULL,
		0x0F71665C5CFF9027ULL,
		0x909F450A033662B5ULL,
		0x7C8D9643A92B5DADULL,
		0xD6539FF211846633ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x518C5A59A67031FFULL,
		0xB11A96A3B39D3BEAULL,
		0x8F366F47ABF9E951ULL,
		0xE38D33062C7FEAD1ULL,
		0xBE3BE1D90CE45EC7ULL,
		0x49AF58C775EA736EULL,
		0x6333D3CAAA1C32CDULL,
		0xE7E3736E640EEF25ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x86DEFF7FBA7A75E5ULL,
		0xA83675042A5419ADULL,
		0xF23B2724154D570EULL,
		0x4445CB29A7FAE3F0ULL,
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
		0x117EA0452D3BCFD9ULL,
		0xB445A012A9565B92ULL,
		0x092D656E7ACD7AABULL,
		0x8D9E2FE69F9A928BULL,
		0x7498F6D73B1A9EBBULL,
		0xEB107A98F5247CE2ULL,
		0x7E4662187CA22A95ULL,
		0x2F5C37BBF360FA3EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE1CA46559214D9E4ULL,
		0xD4EE37A47D93D111ULL,
		0x434E9B815A966B3AULL,
		0x7C44788763366C0CULL,
		0xA1700B606B4A1E25ULL,
		0x57339DCFC2AC2F8AULL,
		0xA9942E93F8BBC05DULL,
		0x047F75CCF974A621ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x87C74D92741A0D1DULL,
		0xD2202E4BA99E0589ULL,
		0x58526F98B46AD3D6ULL,
		0x6E1E80D85578A2C6ULL,
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
		0xEE598BE1EFDDD3C5ULL,
		0x9FFD25FC343EB32BULL,
		0x4DED08F1D70E1063ULL,
		0x97AC34EC8D082E9BULL,
		0x7DF5F6F304108FF5ULL,
		0xB1B02B811BC1DA6FULL,
		0x3FE549B987D22EEBULL,
		0xC7836FFF439D2276ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5E26B45C2C043C2AULL,
		0x41F451E3C24BFA29ULL,
		0x79ED3A590A0C980FULL,
		0xBBFBC589A2B0A9DDULL,
		0xF16A79C97E60A47BULL,
		0x499539A7F3EF1480ULL,
		0xCCA065D5E5AF72CCULL,
		0x8AD9CACF198050CDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6CE76BAF9BF68CFAULL,
		0xD208BA545B3C1A6BULL,
		0xF039A262DE2964FDULL,
		0x5CDEF4892A9EA3BEULL,
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
		0x72F3E86949E3A7F6ULL,
		0x253E59A5114B1322ULL,
		0x69818BCB2673AA0BULL,
		0xE51161073465C6D7ULL,
		0xE3A32D783DD3B4DEULL,
		0x447729F91D751EA0ULL,
		0x710DD753C9DFB0B9ULL,
		0x82858C41F67F8EF7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0735E69CA5738D7BULL,
		0x457C3A86DBC0E60BULL,
		0xBF1F8D67B7377D3FULL,
		0x318C6D92F58BB7C5ULL,
		0x82F2FD16E3AEE955ULL,
		0xBF48D7345E3D033DULL,
		0xE46777281B534061ULL,
		0x7E0555D045BD0A75ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC5E5304005E650F7ULL,
		0xA4A2685297DE3DD7ULL,
		0x8B1444DF5814D9C9ULL,
		0x5E8D08547BB9BA4CULL,
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
		0x9CFAB3447218A98FULL,
		0xB5111A199A29C51FULL,
		0xCF7DAD783651FB42ULL,
		0xCFC9580F7CC07966ULL,
		0x87B0866C179E0546ULL,
		0x509F4F7BD4D968C3ULL,
		0x69C97997BDAE07D9ULL,
		0xA644806A52689D11ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x087B5AA46E078532ULL,
		0xA82D7EA3A329C41FULL,
		0x276B5B51901D21B8ULL,
		0x29187FE00C89E2E7ULL,
		0xDF235CF5F2B99C81ULL,
		0x034E6E652B1A92F5ULL,
		0x9E23E8BE2F17AD9EULL,
		0xCCD17DD51F28B85CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x997380297DF8B0CAULL,
		0x86E504D32953BD87ULL,
		0xE2A5D271D0863E57ULL,
		0x6DC33A550BB28955ULL,
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
		0xCF89E0B24D1F5518ULL,
		0xC4E3D92A6E542835ULL,
		0x23F9983FB8AAFF27ULL,
		0x6A8CAB8279D216BFULL,
		0xD6BBDAD9E9746367ULL,
		0x5059173613299634ULL,
		0x3D5F34211786A504ULL,
		0xA8BA7D64F5B30ED2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x179A824EAF37DD0CULL,
		0x325BA2D484A66653ULL,
		0xCC7587BD6CC31BE9ULL,
		0x4E36B426E22BEBAFULL,
		0xFC90F811D4B5524FULL,
		0x83BCBA5A3F08A4BAULL,
		0xF99B814EE392CF82ULL,
		0x28E871B0D311333DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1A4D0816B244046EULL,
		0xF1BDFEF7669199F9ULL,
		0x66909BB602199482ULL,
		0x1583B418BBACC311ULL,
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
		0xABAFF5723F545D7BULL,
		0xF4A6728D96973E81ULL,
		0x479904BF81BFA165ULL,
		0x869FBD41B33B0192ULL,
		0x5CBC1DD15DF7B422ULL,
		0xB84186B372D6013CULL,
		0x4B088B3C32F7F314ULL,
		0x9E797C5BAB5C4EB6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0419366030FECDA3ULL,
		0x33558871E5B6C734ULL,
		0x6041B250A301BF48ULL,
		0xF88361F6AD78E6FCULL,
		0x64252FA38B7FFA88ULL,
		0xDE86C02FAEBE8DDDULL,
		0xA05D1711BA87ACEDULL,
		0xA17D78EB828E3A82ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8DFE19DF4C1B1C8EULL,
		0x130A61AACC5B9766ULL,
		0x3CCA90BCBF684BE2ULL,
		0x1B84DDF114591A41ULL,
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
		0x8C1CEB06E20A3DD9ULL,
		0x3220EEE3AD3B83A3ULL,
		0x41D7FB866287222FULL,
		0x0D1C2F76C9158C19ULL,
		0x6C7242712C72A768ULL,
		0x267139EDAE94227DULL,
		0xDAEBE0756D438372ULL,
		0x6CE82FD2430E80F6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDC25A33E6EAB6DC7ULL,
		0x1FB15F9C0412B4E1ULL,
		0xCCE4C30E03F2BFE4ULL,
		0x0964734990D585E0ULL,
		0xBA3FB7B9E9BDE484ULL,
		0x26F2692FCA903F69ULL,
		0x95AF8228AC6BD348ULL,
		0xAEC6DBCE83F14D44ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2377DEFC5A33BC6EULL,
		0xFF428B7781BC83AEULL,
		0xBBE937DCFE988886ULL,
		0x3CAA34BB9695B2AEULL,
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
		0x68EE9DE6B8B84C51ULL,
		0xBCA9C07CD90E89EAULL,
		0xA90E8CB347D29015ULL,
		0x93C88746493FEAF1ULL,
		0x67A4CDEB208F44DCULL,
		0x01BAD6FD17B887DAULL,
		0x8106627F042FD601ULL,
		0x41466318165359ADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2FEA14DDC3EBBDCEULL,
		0x3C26CB1DC02B4C47ULL,
		0xE96D382BBFF8C6B5ULL,
		0x05A796B179584CDBULL,
		0x26942FDED0064256ULL,
		0x0BFBBB4721CA8762ULL,
		0x700C2551F0C045D3ULL,
		0x5B4089051194367BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE17BFEDCE922EDE2ULL,
		0xFAE112619A374F7CULL,
		0x44C669386A693032ULL,
		0x32FF4F678446D784ULL,
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
		0xC4A7062ECDE14CE5ULL,
		0xAAC0CBC5BF0F2A03ULL,
		0xFF9FD0C008164CBEULL,
		0xF30B1D870AE9D746ULL,
		0xB562E41A0CB5DFE1ULL,
		0xBC3121C09379EE0CULL,
		0x83E74D62AAB1D091ULL,
		0x43D46CC887504FF6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x972D50C9DC743605ULL,
		0xFDBDC26AFB4C2A4FULL,
		0xBE0B02D17019701DULL,
		0x352A3EC6BD6AE871ULL,
		0x163E7FB4850293FEULL,
		0x526B3B4461FB34DCULL,
		0xA14223E9933DE48CULL,
		0xEC6C60E7250C27FDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCCE09C77160A56EFULL,
		0x60633FCA1C927CEBULL,
		0xE618F5E81331E56EULL,
		0x3752A234E39CDDC6ULL,
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
		0xCAC6C191438EC279ULL,
		0x3C73DDE58A1809E1ULL,
		0xF1143C56208E119DULL,
		0xBE7E924B9730C792ULL,
		0xEDBC1C1EF20FD9F1ULL,
		0x5C362E6D23CCAD92ULL,
		0x92178B86FA775D9FULL,
		0x7E6A99F25B26CD55ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6BAC24E3F5EE9A4CULL,
		0x4074F7B17B06845BULL,
		0x86D67CFEF2802688ULL,
		0xEE0EAED2947E91B8ULL,
		0x60E63A6E0D47C394ULL,
		0x7D6B7BFE6C616A4CULL,
		0xC7A978D813ECF7E8ULL,
		0xC921EECE74DDE413ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x46DA1CEF43537846ULL,
		0x0E1562A348FD81FFULL,
		0x7694854D6699043AULL,
		0x39394ACD3184D59EULL,
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
		0x58CC86E8C5405EC0ULL,
		0xE67D3002A1828D54ULL,
		0xB223A80458CC64C8ULL,
		0xB3E206B8A58EDCEFULL,
		0x781439DCF4955BCCULL,
		0xB75F9FDC249DE873ULL,
		0x6A78EA5C58A880D5ULL,
		0x97143260466ACC52ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB91B8354CEE020C4ULL,
		0x2566DAC741D4F135ULL,
		0xAF927529BBC11322ULL,
		0xCAB2955746E1597FULL,
		0x993ADAEA49B913E6ULL,
		0x8CCC6C831CB3B2FFULL,
		0x5FA7D4BD8E485D1CULL,
		0x9DB28ACEF45DA630ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB3F51B995312E9E7ULL,
		0x12EFF4728C718B51ULL,
		0x9D9A686CA7509F23ULL,
		0x6DAE50F38CA12C7DULL,
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
		0x21FF8DF18520F036ULL,
		0x4A6ECDD6DB4FA566ULL,
		0x4C7684AE40C92A9AULL,
		0xF91F9ED711C036FAULL,
		0x2C8714D74516C616ULL,
		0xF1558B5330796E34ULL,
		0xE3EBC9AD1C19D753ULL,
		0x4683894EA259225AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE2D5F36DD9D4B3E8ULL,
		0x30C0CA60891192E5ULL,
		0x995C3268CFFF1228ULL,
		0x0CE1640CD830BA11ULL,
		0xEBECA887414BCDAFULL,
		0x1376C256CB1CA819ULL,
		0x8F8BF713620B3426ULL,
		0xFB5E3879B537410AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD615AE643B6D17BCULL,
		0x08BFD8ED5E037A65ULL,
		0x395395170EF65141ULL,
		0x13C83A656C96EED5ULL,
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
		0x653DF2334001D5DCULL,
		0x3CB041ECDB95F54EULL,
		0x20E6C63E6F0AA3DAULL,
		0x3F4D8D225F2E2941ULL,
		0xF14FABCC8F777859ULL,
		0x6C57FE65A00C7F97ULL,
		0x81C843116DC8C8F6ULL,
		0xD7B5C0E0CFD57909ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6CEE65D60DE84292ULL,
		0x1539871FB2CB5CE3ULL,
		0x86CF67E2727B9F67ULL,
		0x3F4E78B1545BBAC0ULL,
		0xC1E16DAB5B9CDEA8ULL,
		0xC94341016DE0DDE8ULL,
		0x586ED8B7959D5C7EULL,
		0x5230BB8FD466DC1EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x02ACC54AE48C6675ULL,
		0x5C8AD7AC9B44986CULL,
		0xBD5D27B213011E35ULL,
		0x51BDDE765D3DB968ULL,
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
		0x98232A746699EBAFULL,
		0x51FD86BD72D80AA7ULL,
		0xC799D7CDAC2EDCADULL,
		0xEF222A5FDCCA98EBULL,
		0x62F8658C983E75F7ULL,
		0xD0E41E5EB836316AULL,
		0xEAA7355B0B0111A3ULL,
		0x2F59C484AE8938C0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF00C857064E613FCULL,
		0xF2ACC3B3EE7FB0E6ULL,
		0x851805B68EF6C5DCULL,
		0x0D48C959E51BCBA4ULL,
		0x89B70764D7063539ULL,
		0xC3C6D4E7B335BDE2ULL,
		0x062FA6DDE8F1BCFBULL,
		0x34749375DCE04B43ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE7CA9EEAB00D73E7ULL,
		0x51A9AAB442697FEAULL,
		0x2C40F8AA2B7EA7C2ULL,
		0x1FDEA93916C20DF7ULL,
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
		0x7B3FF1B55E570D45ULL,
		0x402F2374206EEB09ULL,
		0xBB8B398C21298EEAULL,
		0x364272406E8F35E5ULL,
		0x76EEA565118048A8ULL,
		0x1D974FBE56F5B08AULL,
		0x3996AE000653F9CAULL,
		0x0281E4C4B754E5FBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0225D67B30414A09ULL,
		0xF99C4565A0180B89ULL,
		0x3E041B7995756E47ULL,
		0x7DAF5B70969DAC1CULL,
		0x9679ABB1892EA0CFULL,
		0x717A2EED556E2905ULL,
		0x2BC15942E666551AULL,
		0xA7F04ABA45232F0DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCA772BE06A34A9BCULL,
		0xD2E5BD14BA74FD39ULL,
		0x8B31B22548FA92B5ULL,
		0x2A2FF45CCB52B11FULL,
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
		0x364EB2BDC5844316ULL,
		0xE9659F5656FC265CULL,
		0x8F3B4A45D721E71AULL,
		0x0544EF50272203A8ULL,
		0x83F96E34893930FBULL,
		0x8FF97BE86DCBF192ULL,
		0x0C26904AFBCA8FE9ULL,
		0xA84E3E52CF87D759ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x49E30C2ACE33262BULL,
		0xC78AF2A8D0A65F98ULL,
		0x37644AEC34C925CEULL,
		0xF9975D92400E99ABULL,
		0x4CF35405B923F400ULL,
		0x4E9547A1E15B4480ULL,
		0x589959AF25BFA8C3ULL,
		0xB5A33979CD20098AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x17538985DA7829BBULL,
		0xD6BA6F265F0F7778ULL,
		0xFECD1A7B67F710F9ULL,
		0x111049F4427BF6ABULL,
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
		0x8496E27078CA2A23ULL,
		0x76E1AAAFE510E4CDULL,
		0x672BC1809011EA0FULL,
		0x6A2150B826B9032BULL,
		0x5137A2C55C3AF4F8ULL,
		0x8CB195A82D610E26ULL,
		0x415F5A8ECBCD9378ULL,
		0xB603AB0573E13883ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x33F3A0E13098FCA9ULL,
		0xE00D2345BA61C4F6ULL,
		0x6BDF4B15C10409E1ULL,
		0x5878AC3EE0AA26E6ULL,
		0x0FEBB9BDAC12574DULL,
		0x19C70E1679CA698FULL,
		0x195D3359FF79AA98ULL,
		0x346E724C4E0215DBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x01E7D8B36E3897AEULL,
		0xA5A4A70AD30B8E4BULL,
		0xEB9E48412382717EULL,
		0x4DCF0FF4E52E013AULL,
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
		0x8DA2C5C07085AA40ULL,
		0x4EF262FE951B46EBULL,
		0x52E55007D2786101ULL,
		0x2159C3EE782F5052ULL,
		0x849EA8B5E8882071ULL,
		0x3698D783289A2FB5ULL,
		0xCFD484BEC2A2788DULL,
		0xAE5A006D992D9C0CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5B72E49F2960FE94ULL,
		0x3D1037226F22C05BULL,
		0x96861B31A3FF712CULL,
		0xCD3BB55EF4182931ULL,
		0x27AA7DF2F2674E1CULL,
		0x752ACEB99385BF86ULL,
		0xA60E68A157BD8E62ULL,
		0xE490E2A8C445A742ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFE6E3A11D003E2F4ULL,
		0xC83779C847012D97ULL,
		0xEFC761340C73B22DULL,
		0x47F879C71E857D22ULL,
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
		0xEB0C88F0A9062446ULL,
		0x1FA1CF2DC4E74D53ULL,
		0x06C5BB24060A5C8AULL,
		0x6A34871495FB5C63ULL,
		0xE58F98BEE7A6DD0BULL,
		0x7AF9FFE31A4A1B3EULL,
		0x9C6FF91ADCD90079ULL,
		0xBFF8EB2AAE95BDE8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8EAFFC210BDC2C82ULL,
		0x097F2AA10898149DULL,
		0x4CB39D30FE99164EULL,
		0x2FB378FEFD802C8EULL,
		0xC93F936EA2C4EE4EULL,
		0xB3271307C2B85B05ULL,
		0x948A9A554317CB40ULL,
		0x52F6D9A1EBBC30D7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x903D56B9D6B36A32ULL,
		0xBF71CD1BBBF1C130ULL,
		0xE61E2F47DA1F2CA9ULL,
		0x68CFA86284C6205BULL,
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
		0xB6777E558A840884ULL,
		0x9E3B9F0C4ACF8566ULL,
		0xFF637D14A344C568ULL,
		0xE888040CCFC274CBULL,
		0xA84C2693261C156BULL,
		0xADACB9035A31182BULL,
		0x4DF2367B8FB2C539ULL,
		0xBB801AEF36DEBD45ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1610F3126F0CFB64ULL,
		0x820D022EC372B6D9ULL,
		0x64289FE4AFEE5A8DULL,
		0x5CD434FBFBCB6FEAULL,
		0x0CB1C4EF250AB3E2ULL,
		0x9E68B84B15DB473AULL,
		0x8E19BFE54170330BULL,
		0xACB554C449E6661EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB951099B440B87D5ULL,
		0x6046B837AC19D26AULL,
		0x155C777F91381DB1ULL,
		0x3DCD397000D3F4A2ULL,
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
		0x77082EBF59D71B43ULL,
		0x9CBA7B61C23D4E4AULL,
		0x84F31D0D856A3C0FULL,
		0x6DF1262854B2D1A5ULL,
		0xDB8EFEEAD0B35BD0ULL,
		0xB585BD608141D506ULL,
		0x5BAB58B391D8B3F6ULL,
		0xF699D65C3BB85F69ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x84AAB113C9F6D874ULL,
		0x0846A74DB7FF436CULL,
		0xEA42360C091F8338ULL,
		0xAF6F43CB22B44BBFULL,
		0x78AC0746FC3E5BF1ULL,
		0x1CA7B0D76EB98B13ULL,
		0x09D70E5261C25B10ULL,
		0xA8340AD6F4C853EBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA00E3FFD193E3F8BULL,
		0x4569B06CCA7904FEULL,
		0xC033F16E9F9BEB12ULL,
		0x619E1825B9A03AA5ULL,
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
		0xEF1BAE20DAB19550ULL,
		0x4A426406A6EBF29DULL,
		0x679D13446416B9A7ULL,
		0xBF5BAC4700A26E65ULL,
		0xBA397D7C0D5DA779ULL,
		0xFD3B4ADC66FA830FULL,
		0x1F0480E05B839800ULL,
		0xC97B7147644A4CFCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x79EAD4A5AAEDB0BDULL,
		0x37220A93606939C2ULL,
		0xB9F64CDC43A5460EULL,
		0xDDD91C70D056D3F6ULL,
		0x730844C701F62F04ULL,
		0xA3185AA5A5B81D4EULL,
		0xA266403A2456F3FBULL,
		0x2E2E9CDB2622D54BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x067F445AE11FC948ULL,
		0x74500193F65DD38CULL,
		0x2D245F145111CC64ULL,
		0x6EEA17E76A275EA1ULL,
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
		0x4D088CF3E5E0386BULL,
		0x6F6C281CA4600BF2ULL,
		0x83650AE08EC6B086ULL,
		0xF8AC3CEFD297FD12ULL,
		0xA7D75005C4178B92ULL,
		0x6EB2724AB33C5274ULL,
		0xD6CCC3174FD3032FULL,
		0x15695BCC2EF5C2C3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAA8E7A91E12828FDULL,
		0x4556CA19294425B7ULL,
		0x56048DD2E81EE2C6ULL,
		0x6EAE3B4792590F62ULL,
		0x57556FC7F63B9C32ULL,
		0x3D02EDD110D04A24ULL,
		0x6A2D625836B1776EULL,
		0x7AEDA9C7FCF16305ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x95C15B8E935D9574ULL,
		0x8A23081197252226ULL,
		0x4D08D96B61A28C6DULL,
		0x785A6E47ACE523F4ULL,
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
		0xE33C346E32DD16AAULL,
		0x02A9FBA49902654CULL,
		0x014D7C787C4CA08AULL,
		0x1EABE53FB2931DA9ULL,
		0x36C267ECF03D3C9BULL,
		0x77DACCA48BFEA75DULL,
		0xD9AA095FD14EFD89ULL,
		0x8B10C0E935EB04CEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEDFB6ED5D8A7C158ULL,
		0xA3FB04FE1F8C71EFULL,
		0x0E6AFD515090B550ULL,
		0xD2E86D0784E4DFE6ULL,
		0x0EF43CC73365D740ULL,
		0x3450386FFAC39849ULL,
		0x86717777258B731EULL,
		0x6B7A64B830427F52ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDDDB2D32622E6159ULL,
		0x6540F674083A305AULL,
		0x4D4827B0AAC27725ULL,
		0x7C15277F04B20E37ULL,
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
		0x308575471997CDF6ULL,
		0x37DFFAF3BEA9975CULL,
		0xA8301C3A66800D58ULL,
		0x0B72BC7293294E9DULL,
		0x7B1A8C6AE61FA6AAULL,
		0xE9B0020CCA176C6EULL,
		0x383EF420686ED154ULL,
		0x89696AA8E0196A2FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC87299808702E84EULL,
		0xCB5F461E76A27881ULL,
		0xECAFF65FED3DE2A9ULL,
		0xFBF1C3402484C6B4ULL,
		0x6AD9400563A71E86ULL,
		0x128EC1B2DA596C17ULL,
		0x8323B1DF7A715BFBULL,
		0x7F47819203252F98ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD1C432D7F0791B13ULL,
		0x5B70422EDE3B2BC6ULL,
		0x9D8BFB7DCCE19604ULL,
		0x108992973AE53A47ULL,
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
		0xA338F5F1C643B281ULL,
		0x71096CC83E233F56ULL,
		0x998E81118A065592ULL,
		0x77C54C5BCE0F212DULL,
		0x014036F45230C885ULL,
		0x364C3957D52167DFULL,
		0x19973E99C9E24DA6ULL,
		0xBA9FBACCFB6A5ADDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x52149AB78C4BB953ULL,
		0xA56CBBE98F177BADULL,
		0x97A22C345A9A6015ULL,
		0x39076C93C1EF22DDULL,
		0x55F4767FA89E2484ULL,
		0x0187020FAA97FDCFULL,
		0xD81DEDBF030C8E0CULL,
		0xDD5CBBED46630C22ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBE62EC8B65BC5096ULL,
		0xA0E2E594FF7181FCULL,
		0xB9EE5556B3266660ULL,
		0x16AFB4FCEB35ADF5ULL,
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
		0x19340FC707728C39ULL,
		0x37DB3C5F7CAFB746ULL,
		0x5B37D1FB5B6010CBULL,
		0xE257F7D00D021203ULL,
		0xAC3EEEDBF80C289DULL,
		0xB3D7D8B01B92D90AULL,
		0x9970276E7FF46555ULL,
		0xBA3411EE7C22C89FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9F4C55FC6F97FD05ULL,
		0x9CF20A622A3C49E2ULL,
		0xAA227D52EB9C7640ULL,
		0x8AC13D30A5F4370AULL,
		0xB632308E048AED4DULL,
		0x17ED145E1EDD4BF0ULL,
		0x62EB0DE358E7FD65ULL,
		0x5722BD05184BD027ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFFCBF95CBD095F4EULL,
		0xBFC25628D5665F3DULL,
		0xC8D71F503B9B0841ULL,
		0x0C29554438F6BCD0ULL,
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
		0xB978D55F14A02A51ULL,
		0x1AD6DAAF211310A7ULL,
		0x953FA6C5E22D4387ULL,
		0xC233F67B5C6221F2ULL,
		0x35F1CA7D697ADCDBULL,
		0x9DA92CA74482BCE8ULL,
		0x05CEE8AA7B594BBFULL,
		0x8F174ECB712296E3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x65106F6A2CB66A7EULL,
		0x369C197AC7D4D7F5ULL,
		0x4F8EEA8EC78E3F89ULL,
		0x004E5E0A29C59B86ULL,
		0x48D155865D092FFFULL,
		0xB7499972E944E427ULL,
		0x6643B6BC82A1CBC8ULL,
		0x8763F37D08DD73DEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8739C2A0C0C968B4ULL,
		0x166A9AF9E46C6555ULL,
		0xF45A258A05DC02A4ULL,
		0x66852614ACDFB91BULL,
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
		0x0B5B43413B19F8E0ULL,
		0x3EFB3E8FAAC995ABULL,
		0xD9B6E61F51C063FFULL,
		0x83D521C197F9FEE7ULL,
		0x873A241B3544162FULL,
		0x253CA8C94C0EA7B4ULL,
		0x6F0BBBAC4A3608E3ULL,
		0xC61727E1C8BDC20AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x041D389AA94849AAULL,
		0xCB55C98CB6414EFCULL,
		0x788C5B54BCA31477ULL,
		0xCD5ECB89F01DC5FFULL,
		0xB488E03196A3FDB8ULL,
		0xEF8A30D3E9DF8088ULL,
		0x29AC368592F9CBFAULL,
		0xA554EDE0FF1AC3D8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4D8E1F541D95518BULL,
		0x6C23436F87881730ULL,
		0xAD584E89C80E59FFULL,
		0x134AF255960DF45EULL,
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
		0x0E7FB6912425ABE7ULL,
		0xA635F8C374159083ULL,
		0xDB0992F21B361250ULL,
		0x2F63BC844940CA36ULL,
		0xBE25DEDDA4C327E2ULL,
		0x668DBE7D1AB09F3AULL,
		0x2361C3F189CA66D2ULL,
		0x2CC29D6A0961A47DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9299F2424A716DDCULL,
		0x67A5F9AA43788FC6ULL,
		0x6D9DFA0E58917019ULL,
		0x106477EC4D2DCD27ULL,
		0x352283169822F9F7ULL,
		0x8322D7CB29F1D355ULL,
		0x71F899C3F2210E7BULL,
		0xD45BCE23C7A191EBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD26563DAB97B0B37ULL,
		0x006E3D82ECEF44CEULL,
		0xC307DBA845C7BF1DULL,
		0x3E420905BE95BEAFULL,
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
		0x07BCA83FA5D116E7ULL,
		0xB4DC080A1C93BC17ULL,
		0xA709DF6D40D1F7FAULL,
		0x913FAE5B9634D1BEULL,
		0xCC068C25825B0BEFULL,
		0x95EDEE61507C681BULL,
		0xFD3CCBF7A2A4F65FULL,
		0x2CABF7CF42D1FFB7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x035E58B06F8C8791ULL,
		0x0C6694757D1B36C4ULL,
		0x1C1448CC1293835FULL,
		0xB160470CB87F231EULL,
		0x2F1799C6A2D62405ULL,
		0x5DD3C4CE6BB40C1AULL,
		0x1B43C106D9E48468ULL,
		0x95F38DC7CFCAF37EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4FD649A463FEF9B2ULL,
		0xFC579F6295362D90ULL,
		0x15ED365EFACF5F4DULL,
		0x3F3F2469F0C17F38ULL,
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
		0x28C2A962F28A2EECULL,
		0x6112C3B547B9CDE9ULL,
		0xD48EEE9B687E44A6ULL,
		0xFEBA98E8A72DF51CULL,
		0xADF039C47F74A89CULL,
		0xCAA112D768861243ULL,
		0x044FD81BF4435984ULL,
		0x99F4AF9590EE368CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2B83F1DC0308871AULL,
		0x00B644E61A1B5914ULL,
		0x80CF7ADFA27D1089ULL,
		0xA2BAE8C3A56A55E2ULL,
		0xED386F58C85AA424ULL,
		0xE14A36FF12F982F3ULL,
		0x1E0310360E75105FULL,
		0x45AD0CF879E295E6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9886C3841D5E537DULL,
		0x034120EBE07BBAABULL,
		0x83251FDBE2A00F98ULL,
		0x5EA1D3766D7D77DAULL,
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
		0x18CCA50A62EFAF9AULL,
		0x2E6DC07F83789EBCULL,
		0x0B46452D2DD34123ULL,
		0xF8A31CDC33E9CA08ULL,
		0x2EF35E5A44004C5BULL,
		0x63F01C39B7E0B1BAULL,
		0x696E88C60663AC23ULL,
		0x99195595762E1E0EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD41A7E4927967F6EULL,
		0x8F0A7E999B314B46ULL,
		0x85F47AB9D227B427ULL,
		0x00BEF6296610C63DULL,
		0x7127789CCF884827ULL,
		0xFFD9156D7DB18404ULL,
		0x579B13BDD859AE6DULL,
		0x79DC849A3F5DBE90ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x70F640E08529D0B5ULL,
		0x7ACE44368B481C6FULL,
		0x2AB529AA312735E8ULL,
		0x1AEB2BFCF0C73081ULL,
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
		0xB4755C128465DAD8ULL,
		0x83A9E67F21A36A17ULL,
		0x7275A048371BFF7DULL,
		0x96C8CA9489828345ULL,
		0x8E7E46C28DEBC3C1ULL,
		0x7AA20FDC36DE6030ULL,
		0x49331A16CEC4704EULL,
		0xA6FE3F3674CFBE42ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3B7E3908E98E4525ULL,
		0x518CCC9A00690E4FULL,
		0xA12738CEA9408A48ULL,
		0x6F76411EC8EA81C5ULL,
		0x73F3BDD0A815C179ULL,
		0x875C2417B563573CULL,
		0x4204315113D7A5CCULL,
		0x83C34CE0849CDBB0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x698776F1B89BED21ULL,
		0x4E7E1910597DB004ULL,
		0xE244F4D34D01847FULL,
		0x621282376825A32CULL,
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
		0xB726ABFBD22A2363ULL,
		0x3944C025ED213BCDULL,
		0x238C4D5446D90982ULL,
		0x4BBCDCE88E5AAC08ULL,
		0xE1120501F0EF842FULL,
		0x86BBD1AAC8F5341AULL,
		0xE5883AC8D27D36C7ULL,
		0x304188CB1497BB82ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x43A30E3B250AF68CULL,
		0x31F5658E87D4FFBCULL,
		0x2158262FF6E06ADAULL,
		0x133F8EBF068B9776ULL,
		0x343D84C1AE8F9062ULL,
		0x5F18133644E5E6ABULL,
		0xFC9CEA445FADBC71ULL,
		0xD1591C25BAFEA07FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1B0EA74A875D59B5ULL,
		0xE99D9FE2FF91BAA5ULL,
		0x95221ACD5AC4C771ULL,
		0x4EFD6EB4D4891700ULL,
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
		0x76AFC0931B743258ULL,
		0x19D58C64DB5ED557ULL,
		0x7F5C8C1AB1E42334ULL,
		0x6D7C44BD23C5D5FBULL,
		0xCA2CB730DA4B293CULL,
		0xA5955E843386A6D7ULL,
		0x7DEC862DB7D31AECULL,
		0x68C73E17C5E6EBFEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA6B02244EC7A5AD3ULL,
		0x3122A8750112A86BULL,
		0x48A9200DD1ED240AULL,
		0x4EECF1D691CCA37BULL,
		0x6177EBD3B010477EULL,
		0xA392B5B82B80DD35ULL,
		0x8573355E09997E59ULL,
		0x43EC8638A002E133ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5AD5CE2273B75A8AULL,
		0x3517F2390B281B07ULL,
		0x18B56AE0BC843CFCULL,
		0x17069E0631D2CCA1ULL,
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
		0xA45139BDD0752EF4ULL,
		0x389DD8198386ED3EULL,
		0x98FB95DE40787561ULL,
		0x5BBD0C16912BA014ULL,
		0x7A877530F798A07CULL,
		0x9D8967DA83C4FF17ULL,
		0x0CFA780C305DF30DULL,
		0xCE2F411224EA31C6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6E554526D4AF701FULL,
		0x6AA7DFAFD3FC1FCDULL,
		0x22E104CC6F8E42D8ULL,
		0x238B5736BF989330ULL,
		0x65849104DF04F6E1ULL,
		0x2AF8D813580321A7ULL,
		0xA51C1C8D60B0BD17ULL,
		0xB19055F1F2E18286ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5469D322A1B0EC6FULL,
		0xCF6B4FFA2E51AC14ULL,
		0xE11C25E4A4A0351DULL,
		0x77C89BA73EDD104DULL,
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
		0x6F71479F5AA1DAF4ULL,
		0xCED8F40CF507168EULL,
		0x98556FB49049B68AULL,
		0x1CCC8DB6D6EDD78EULL,
		0xF78D7DA36B48D271ULL,
		0x62196A30477EAEF2ULL,
		0xAF22A825EAD1ED81ULL,
		0x76F4E58845A6D6B5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x657850E8FB516AFCULL,
		0x628C3F1CD4FFE9B1ULL,
		0xA3FE0DFA08338261ULL,
		0x5C170F46B2E56410ULL,
		0x2976B5C31E5ECDF0ULL,
		0xFDE3D9AFED31D5F6ULL,
		0x48582BCE9F15AFCFULL,
		0xF4827002DE22B358ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA15AA201CA0D184CULL,
		0x4C4027FD876F6263ULL,
		0x3665D6AFC6075C7EULL,
		0x1DB2F03D81A5B35BULL,
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
		0x5AEAD1ABB9DE66E4ULL,
		0x39FCF0C56C2CCF06ULL,
		0x3A9F779E32ABB8BFULL,
		0x1FD6F2BA0E17257DULL,
		0xD49C41ACA7369FECULL,
		0x46F3DF3694D26C15ULL,
		0x20C1DC0746422153ULL,
		0xFB126602846522E8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x209B517221DC089BULL,
		0x6BBCA7ABCB3B47E7ULL,
		0x983E36C0CD93583EULL,
		0x6E4014F0C026B71CULL,
		0xE1861F03A84C83F6ULL,
		0x8D1ED35FFA4CAFCAULL,
		0x4C4AF1A633182B93ULL,
		0x70A27679C944D272ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4F98A54F6EC287C5ULL,
		0x63E00AF490CB7A3FULL,
		0x2C080B463D52DAF6ULL,
		0x3E346C1514BC5FDEULL,
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
		0x4CE2FAE463D184C0ULL,
		0x2E520CC75C8A92A7ULL,
		0x239E8F40C91E3EC0ULL,
		0xA4C41636A07E839CULL,
		0x880A819FA146DC8CULL,
		0xD2ED0D8B98991F7AULL,
		0x12D29B052285ABB6ULL,
		0x9A4740312E073DB9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2D94738B8D680070ULL,
		0x242BD1220B8F6ED7ULL,
		0xF0F833B073623086ULL,
		0x5ED15DE488FDB4CEULL,
		0xBC528ACFFB912164ULL,
		0x277459D8A3D3E3FBULL,
		0x401CE26CC07CC7A6ULL,
		0xCF972B9326D3AA52ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5C9D2A2B6F634B10ULL,
		0x7E10E835A641F8A2ULL,
		0x799FC22EE30DE8B3ULL,
		0x5C15C7C72928B010ULL,
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
		0xF8543CDB2EEDBCF5ULL,
		0x108897D575CD5579ULL,
		0xC3AD379D797C9957ULL,
		0x75763550988850BFULL,
		0xAFD34FCFA130E16FULL,
		0xE905760390D1B824ULL,
		0x9C84698AE6D92671ULL,
		0x2C1E314F78DC0BEEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3ECEFDD8FAF050DCULL,
		0xFACAEC6CDB323E8EULL,
		0xD0B33C1F6245779EULL,
		0x4D10BD829032AC34ULL,
		0xBA19DC61EEC82B05ULL,
		0x5A46029DC59060A7ULL,
		0x38A7273AA5D676C0ULL,
		0x12CA6908466DD197ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x330C614AAF88805AULL,
		0x4628CC84C64E1378ULL,
		0xC5D1D367BD9D3613ULL,
		0x6AD5325F84B24D83ULL,
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
		0xD19C2A1C662648F6ULL,
		0x7A81BBFA8D11ED70ULL,
		0x084DFCEECAF258D7ULL,
		0xCD2B95CBACE3314FULL,
		0x128E992D4F035B35ULL,
		0x49983BCC36E71706ULL,
		0xAAA98765AAD32B60ULL,
		0xD2D952A77E00F02CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x01DF9725889DF75CULL,
		0xD194EFF0DC012EB1ULL,
		0xB4DF8F2C61986AA0ULL,
		0x32B3560C6C0D97DBULL,
		0xE8F44A3DFE820468ULL,
		0x3A1DFCA2C785F6E2ULL,
		0x7AE05015C052EB88ULL,
		0xFF5491D4F85C6565ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFCA44A7CD0BB3324ULL,
		0xF5122C30397B83F7ULL,
		0x6B4CA39F38636848ULL,
		0x002CDEFF17423304ULL,
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
	printf("Test Case 201\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 201 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -1;
	} else {
		printf("Test Case 201 PASSED\n");
	}
	printf("---\n\n");
	return 0;
}