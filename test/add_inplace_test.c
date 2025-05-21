#include "tests.h"

int32_t curve25519_key_add_inplace_test(void) {
	printf("Add Inplace Test\n");
	curve25519_key_t k1 = {.key64 = {
		0xD29AAC68526D4B4BULL,
		0x50F493F4B544A79DULL,
		0x33BB5A19E19C3E15ULL,
		0x21BA90B23D80D58AULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0x5C73650A904AEBBAULL,
		0x0286719CE2C9ABDCULL,
		0x1237C319C1746DADULL,
		0x093A8858DEE03DC2ULL
	}};
	curve25519_key_t k3 = {.key64 = {
		0x2F0E1172E2B83705ULL,
		0x537B0591980E537AULL,
		0x45F31D33A310ABC2ULL,
		0x2AF5190B1C61134CULL
	}};
	printf("Test Case 1\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	int32_t res = curve25519_key_cmp(&k1, &k3);
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
		0xD7D7FB9158111ED9ULL,
		0x403302BA85FD859CULL,
		0x034B4C203C10F0ECULL,
		0x2F70FB6CAE6CF583ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7BBFF7B4D9B3E815ULL,
		0x10B11D2D4E6E5017ULL,
		0xB5F2F853CDEE021EULL,
		0x30E459A05C79DA65ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5397F34631C506EEULL,
		0x50E41FE7D46BD5B4ULL,
		0xB93E447409FEF30AULL,
		0x6055550D0AE6CFE8ULL
	}};
	printf("Test Case 2\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x9846643F444A6BBBULL,
		0x8E31A03B8F5ACECCULL,
		0x86DA35BD4E575EE5ULL,
		0x0B41597FB9EB576CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1A13E719C9E391BCULL,
		0x83265F71EBFDFF0EULL,
		0xC421524A8A356060ULL,
		0x7EA4BF6ABBE8B358ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB25A4B590E2DFD8AULL,
		0x1157FFAD7B58CDDAULL,
		0x4AFB8807D88CBF46ULL,
		0x09E618EA75D40AC5ULL
	}};
	printf("Test Case 3\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x18F1EEBC9FB8A1E6ULL,
		0xC61358A6678DD66BULL,
		0xCAB27386273370A6ULL,
		0x7EB5B481D000E9CDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB547855AA9B304F0ULL,
		0x16225C7043186539ULL,
		0xA37AA20D77168DF5ULL,
		0x605ABD1000605866ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCE397417496BA6E9ULL,
		0xDC35B516AAA63BA4ULL,
		0x6E2D15939E49FE9BULL,
		0x5F107191D0614234ULL
	}};
	printf("Test Case 4\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x4DAB63C2316D54E9ULL,
		0x2A1098C0FDF7381AULL,
		0xFE14FE32ADCA9B76ULL,
		0x42C575DA987DFE5AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x99479D01BD7D6196ULL,
		0x90CD85380A259FB3ULL,
		0x90B3F7F736D95604ULL,
		0x3D4C7A212D5B50BFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE6F300C3EEEAB692ULL,
		0xBADE1DF9081CD7CDULL,
		0x8EC8F629E4A3F17AULL,
		0x0011EFFBC5D94F1AULL
	}};
	printf("Test Case 5\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x86230CE92977429CULL,
		0x6A0BDCBDC3FADB43ULL,
		0x381E3FC7FD489FD4ULL,
		0x15A4D2BAC19ABB3FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9EC5AA090060205DULL,
		0x3FE8FBA2D1E8E2E8ULL,
		0xBAEBD147ED7EF4E8ULL,
		0x0488818B57041C51ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x24E8B6F229D762F9ULL,
		0xA9F4D86095E3BE2CULL,
		0xF30A110FEAC794BCULL,
		0x1A2D5446189ED790ULL
	}};
	printf("Test Case 6\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x83A3EDE4978986A1ULL,
		0xA8707B6621E993D1ULL,
		0x15DF2A065C0C36DAULL,
		0x1E79645BF98E6B11ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x275B70D17A36F2D8ULL,
		0x60CA56BB09C33225ULL,
		0xE1DEC42C44FF41AEULL,
		0x760B5939F3D86AF9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAAFF5EB611C0798CULL,
		0x093AD2212BACC5F6ULL,
		0xF7BDEE32A10B7889ULL,
		0x1484BD95ED66D60AULL
	}};
	printf("Test Case 7\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xC85CA26D1B7F6459ULL,
		0x7E1308535E88CF49ULL,
		0xB0B099FF279E5E74ULL,
		0x0B37D574698E13F4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x590F0336184F5EA9ULL,
		0x26C4C86C497FE45BULL,
		0x05AF9DB5C0982509ULL,
		0x222FFF2A7CB9566DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x216BA5A333CEC302ULL,
		0xA4D7D0BFA808B3A5ULL,
		0xB66037B4E836837DULL,
		0x2D67D49EE6476A61ULL
	}};
	printf("Test Case 8\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x6DF028AF1B1C44BFULL,
		0xB9B5BA89297C59FEULL,
		0x019262C5151AFC20ULL,
		0x7F7BE0B9EB0217C4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2EF3D5D778C244A9ULL,
		0xF8FCBB0A05E7D28AULL,
		0xE5647EE8AC0AA514ULL,
		0x669501DC0EFC17CDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9CE3FE8693DE897BULL,
		0xB2B275932F642C88ULL,
		0xE6F6E1ADC125A135ULL,
		0x6610E295F9FE2F91ULL
	}};
	printf("Test Case 9\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xDBFA80C0DB27191FULL,
		0x2266D67EE349FF62ULL,
		0x7BEFA1AD294E4640ULL,
		0x26F9E893C0E382F7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5342F02531726C02ULL,
		0xA89E0D05F53318EEULL,
		0xF4F18DDF332FB333ULL,
		0x60BBF32E78A5FB1FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2F3D70E60C998534ULL,
		0xCB04E384D87D1851ULL,
		0x70E12F8C5C7DF973ULL,
		0x07B5DBC239897E17ULL
	}};
	printf("Test Case 10\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xD2DB3A297ADAE86FULL,
		0x3366CB1103DC06C3ULL,
		0x993816F50BE508F1ULL,
		0x36663370F3B5090BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4D1551FC1456F105ULL,
		0x9DF494CAF60EEB85ULL,
		0x607C1CB5A4463914ULL,
		0x3BA9EF6E0A839D17ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1FF08C258F31D974ULL,
		0xD15B5FDBF9EAF249ULL,
		0xF9B433AAB02B4205ULL,
		0x721022DEFE38A622ULL
	}};
	printf("Test Case 11\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xEFD9C1AA7182ECDAULL,
		0x7ED0097B8F0CCEB2ULL,
		0xB045C7E70E4F6466ULL,
		0x11E8B13B7A85FCB9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4AB0AB1C6C587F53ULL,
		0x4AC39A9D912DA304ULL,
		0x26BD01FDA8C8531DULL,
		0x092EEA61AD1D7F10ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3A8A6CC6DDDB6C2DULL,
		0xC993A419203A71B7ULL,
		0xD702C9E4B717B783ULL,
		0x1B179B9D27A37BC9ULL
	}};
	printf("Test Case 12\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x687191C9EB1820C5ULL,
		0x62F38EB9598AA943ULL,
		0x8035EE154DB1AC6EULL,
		0x036876249EE7E6FAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFA8A7C64BCF17D1CULL,
		0xCB5824921CDFA21CULL,
		0x805001CB1C7ABADBULL,
		0x00734A5A59C45A2CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x62FC0E2EA8099DE1ULL,
		0x2E4BB34B766A4B60ULL,
		0x0085EFE06A2C674AULL,
		0x03DBC07EF8AC4127ULL
	}};
	printf("Test Case 13\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x7607837456451A1FULL,
		0xFF1096431363FCFAULL,
		0xB9D3CD52ABD09B4EULL,
		0x4F81B19BE1A95B84ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC815190108D9A6C9ULL,
		0x66FDCA7D99452847ULL,
		0xBFEAA45D3DCD9F54ULL,
		0x24436E4E6A87918EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3E1C9C755F1EC0E8ULL,
		0x660E60C0ACA92542ULL,
		0x79BE71AFE99E3AA3ULL,
		0x73C51FEA4C30ED13ULL
	}};
	printf("Test Case 14\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xD4D313413FBB2F1DULL,
		0x934916800523D47BULL,
		0xE46A4D1D532CD98BULL,
		0x69D455D4E0128C12ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCEE6675B867F56A4ULL,
		0xD141EEF136B23970ULL,
		0xDCAC4619A5DE65ACULL,
		0x23018F9AB221D024ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA3B97A9CC63A85D4ULL,
		0x648B05713BD60DECULL,
		0xC1169336F90B3F38ULL,
		0x0CD5E56F92345C37ULL
	}};
	printf("Test Case 15\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x73D74E8421E427D1ULL,
		0xF3E54CCDDB1FFA1AULL,
		0xC1D7B4E9196F73F4ULL,
		0x6E47BEDC27431F6CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x733EB996BCF419D6ULL,
		0x82F5213CCF4F0C07ULL,
		0x44425E5D1D8BB673ULL,
		0x434CA294325B464EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE716081ADED841BAULL,
		0x76DA6E0AAA6F0621ULL,
		0x061A134636FB2A68ULL,
		0x31946170599E65BBULL
	}};
	printf("Test Case 16\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xB0C79FE1456D98FEULL,
		0x07164B8B9DE1CB3FULL,
		0x20432782D311438CULL,
		0x3CA30F5AE3B18E6CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5118C0F0B051C47DULL,
		0x1006D181B834B360ULL,
		0xA529577ACCC0A8F3ULL,
		0x1D49B839E42DEC3CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x01E060D1F5BF5D7BULL,
		0x171D1D0D56167EA0ULL,
		0xC56C7EFD9FD1EC7FULL,
		0x59ECC794C7DF7AA8ULL
	}};
	printf("Test Case 17\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xC445FEC4F1F3F4B3ULL,
		0x93875713735E2821ULL,
		0x2B87804E1B9B5B04ULL,
		0x2F6762B82572F2AEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1E38E65DAF299008ULL,
		0xCC50B4CA2B74284AULL,
		0xE9DDE43C0A5F2AE8ULL,
		0x3628949BD01114E0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE27EE522A11D84BBULL,
		0x5FD80BDD9ED2506BULL,
		0x1565648A25FA85EDULL,
		0x658FF753F584078FULL
	}};
	printf("Test Case 18\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xDC8B3A0C7F2F2238ULL,
		0xAE99F79AED51AB70ULL,
		0xEE77F7D445419057ULL,
		0x5B910602EE658BB8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD9225A6187EC0762ULL,
		0x580D64949B713989ULL,
		0xC68B7596D315EB0BULL,
		0x69C4EAC544C4CFEDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB5AD946E071B29ADULL,
		0x06A75C2F88C2E4FAULL,
		0xB5036D6B18577B63ULL,
		0x4555F0C8332A5BA6ULL
	}};
	printf("Test Case 19\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xA88782984672B840ULL,
		0xB12C29B816BF03F3ULL,
		0x839F8F8F62A0040FULL,
		0x2DFC4E67577E26D1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFB300E6408A9286BULL,
		0x5EC40912B86AB1ABULL,
		0x0CEAB756690D2DC5ULL,
		0x0D9FBE57823D2900ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA3B790FC4F1BE0ABULL,
		0x0FF032CACF29B59FULL,
		0x908A46E5CBAD31D5ULL,
		0x3B9C0CBED9BB4FD1ULL
	}};
	printf("Test Case 20\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xFABA057B705294BBULL,
		0xD770F602C6A88D01ULL,
		0xA8F7882C0D87BFD0ULL,
		0x48965A17DCB5E5BAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x80C6C514E834DE6EULL,
		0x0E96F43F98A2926FULL,
		0x578D950DAC291397ULL,
		0x4F9A5D55AE646943ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7B80CA905887733CULL,
		0xE607EA425F4B1F71ULL,
		0x00851D39B9B0D367ULL,
		0x1830B76D8B1A4EFEULL
	}};
	printf("Test Case 21\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x7851CF785547C77BULL,
		0x5BD6F8ADF6F6B324ULL,
		0x3F29DFA9C8F670D0ULL,
		0x2AAD1E12FC441DBBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9984E4A0049796FAULL,
		0x9D1C3C9E0F52304FULL,
		0x259FAD32D38641E8ULL,
		0x321D696A6AE3A8F6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x11D6B41859DF5E75ULL,
		0xF8F3354C0648E374ULL,
		0x64C98CDC9C7CB2B8ULL,
		0x5CCA877D6727C6B1ULL
	}};
	printf("Test Case 22\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x983A7C2C7B39BB9EULL,
		0x2542B52B51EC563CULL,
		0x8D1DDBCA576FD754ULL,
		0x53FDB1EEDB6C9C54ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE10CF70FDEB3E297ULL,
		0x3414D1397890026FULL,
		0xCEC7E0E0952D0F60ULL,
		0x21AB8AC8DE7F531DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7947733C59ED9E35ULL,
		0x59578664CA7C58ACULL,
		0x5BE5BCAAEC9CE6B4ULL,
		0x75A93CB7B9EBEF72ULL
	}};
	printf("Test Case 23\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x74530985FB0EEC54ULL,
		0xE879A33B401EFD97ULL,
		0x1E49430E86DF7CF4ULL,
		0x608E79B7EAA426E2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x62355D146BC96B44ULL,
		0xCD9B8D7D21C380C6ULL,
		0x777A1F91B6DF9737ULL,
		0x2F2CD345DBD061A2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD688669A66D857ABULL,
		0xB61530B861E27E5DULL,
		0x95C362A03DBF142CULL,
		0x0FBB4CFDC6748884ULL
	}};
	printf("Test Case 24\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x456E002862AEE895ULL,
		0xB366840DBF981894ULL,
		0x5BEDE75904C9A9F3ULL,
		0x56719227AEB0A4B6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x443E258667710A41ULL,
		0x688E026A1739E843ULL,
		0x2E90B5D8A48F8142ULL,
		0x38D7ECC19F435C7FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x89AC25AECA1FF2E9ULL,
		0x1BF48677D6D200D7ULL,
		0x8A7E9D31A9592B36ULL,
		0x0F497EE94DF40135ULL
	}};
	printf("Test Case 25\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x4C2E347A6A0448DBULL,
		0xEBE0A90446758683ULL,
		0xE90012ACC194518CULL,
		0x1461CBC043687D93ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x50FE45B1BCBA9EF4ULL,
		0x0066E3FC17F8F3B1ULL,
		0x85518C297E0639C3ULL,
		0x3737A40535D4DA61ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9D2C7A2C26BEE7CFULL,
		0xEC478D005E6E7A34ULL,
		0x6E519ED63F9A8B4FULL,
		0x4B996FC5793D57F5ULL
	}};
	printf("Test Case 26\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x38F74FE3AF33FA87ULL,
		0xB737DEA16B75C657ULL,
		0x503C944493689EACULL,
		0x3BDF76F0273262B2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9568E5084735780BULL,
		0x1E46E3775A0F7412ULL,
		0x181FD7A5C3D38A8AULL,
		0x5CEC4D5E15F2B20CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCE6034EBF66972A5ULL,
		0xD57EC218C5853A69ULL,
		0x685C6BEA573C2936ULL,
		0x18CBC44E3D2514BEULL
	}};
	printf("Test Case 27\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xF9B442BA41F981A1ULL,
		0x4BE86B5EF60AB440ULL,
		0x10C115EA068606ECULL,
		0x0B5369C5A2B27C86ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1C82F6A56D6C1428ULL,
		0x8F3A8B2C23EAC806ULL,
		0x755D069FD788D19CULL,
		0x7C18DF06050C8C49ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1637395FAF6595DCULL,
		0xDB22F68B19F57C47ULL,
		0x861E1C89DE0ED888ULL,
		0x076C48CBA7BF08CFULL
	}};
	printf("Test Case 28\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x86F14271BBF7A85EULL,
		0xE5CDC3280E4D5545ULL,
		0xC4E6124AC4ED7D61ULL,
		0x3D43D42BAF0915F1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBBCF881675851C53ULL,
		0x9BB7B08D5EACEB60ULL,
		0xCC5258C9E7FF54CAULL,
		0x2D918F3151079C3FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x42C0CA88317CC4B1ULL,
		0x818573B56CFA40A6ULL,
		0x91386B14ACECD22CULL,
		0x6AD5635D0010B231ULL
	}};
	printf("Test Case 29\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xC900F5E56244AC02ULL,
		0x67C23048B8C7DB16ULL,
		0x6917E5F24DC4F67AULL,
		0x24C2969A059B12A9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x135B6FC0340D0423ULL,
		0x453F1475D3D1B7CDULL,
		0x23173E458D6ABB1AULL,
		0x076BF760F38E20E6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDC5C65A59651B025ULL,
		0xAD0144BE8C9992E3ULL,
		0x8C2F2437DB2FB194ULL,
		0x2C2E8DFAF929338FULL
	}};
	printf("Test Case 30\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x67AB5943444F42CCULL,
		0x0956D858FC94C011ULL,
		0xDE84D8168CF696B9ULL,
		0x0C08DCDCD75D1BBCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x14472D08F72EE4D1ULL,
		0x6EACBCB137BEE819ULL,
		0xAB00F2061CFAE4FFULL,
		0x7CF28377025C8A3EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7BF2864C3B7E27B0ULL,
		0x7803950A3453A82AULL,
		0x8985CA1CA9F17BB8ULL,
		0x08FB6053D9B9A5FBULL
	}};
	printf("Test Case 31\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x621450347A322574ULL,
		0x7698D42CEEFD3B44ULL,
		0x619B38E5256D73EEULL,
		0x0639FEF4CD39F82AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x309143923B992F4EULL,
		0x9F39A51D6A89E33DULL,
		0xA1CF0688E892DA20ULL,
		0x219CB27A56A55086ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x92A593C6B5CB54C2ULL,
		0x15D2794A59871E81ULL,
		0x036A3F6E0E004E0FULL,
		0x27D6B16F23DF48B1ULL
	}};
	printf("Test Case 32\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x6853ADE9584DD05CULL,
		0xBBD83005CF7B1D7FULL,
		0xFC932848B664C76FULL,
		0x3229190C125375D7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x23171664292F125EULL,
		0x227315DD247F7E08ULL,
		0x87107A5B733BABEBULL,
		0x440B91F5CA06350EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8B6AC44D817CE2BAULL,
		0xDE4B45E2F3FA9B87ULL,
		0x83A3A2A429A0735AULL,
		0x7634AB01DC59AAE6ULL
	}};
	printf("Test Case 33\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x24CA651203D81C8CULL,
		0x5B0FBAFDC5094B43ULL,
		0xB00A8E510BE60434ULL,
		0x67D8409195FB3CC2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x18C4DA0E752D4FFAULL,
		0x5858C3437C7AE9B9ULL,
		0x42C24966D8A43F20ULL,
		0x17B03178E8CDB882ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3D8F3F2079056C86ULL,
		0xB3687E41418434FCULL,
		0xF2CCD7B7E48A4354ULL,
		0x7F88720A7EC8F544ULL
	}};
	printf("Test Case 34\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x86775C8DF4271069ULL,
		0x9C792DA9EE22D257ULL,
		0xADE613149283330BULL,
		0x0E328028EC372406ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEEE86520D37B18F5ULL,
		0x76C6B3A8AC73B715ULL,
		0x9EDC2EDE29A2D6D3ULL,
		0x699A8F9B930F15BEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x755FC1AEC7A2295EULL,
		0x133FE1529A96896DULL,
		0x4CC241F2BC2609DFULL,
		0x77CD0FC47F4639C5ULL
	}};
	printf("Test Case 35\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x35A9E589929FF05EULL,
		0x599DA7791AC6DFB0ULL,
		0x2952276350480FC5ULL,
		0x00B898E3D53FDC69ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x92959F88E715FA33ULL,
		0x627798702ECCF69FULL,
		0xEAB7FF0ACE63F514ULL,
		0x611CD0A463372B18ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC83F851279B5EA91ULL,
		0xBC153FE94993D64FULL,
		0x140A266E1EAC04D9ULL,
		0x61D5698838770782ULL
	}};
	printf("Test Case 36\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x0C15B54BA9B6E7D3ULL,
		0xCD30482FCFD7FA33ULL,
		0x59E231EF4107B0F0ULL,
		0x78E2CD7C757EF6C1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB6C6C6EF214C6210ULL,
		0xFF22CB924D30792AULL,
		0x75D027BB5FE5A8FBULL,
		0x52CA6C84B51BA37AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC2DC7C3ACB0349F6ULL,
		0xCC5313C21D08735DULL,
		0xCFB259AAA0ED59ECULL,
		0x4BAD3A012A9A9A3BULL
	}};
	printf("Test Case 37\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x2F55839FB743DC23ULL,
		0x2F9C868E0A70540EULL,
		0x5E844F53E966721DULL,
		0x45ABCB1F7714D068ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD62896F8A209487EULL,
		0x6749D23098EA0595ULL,
		0x9FCD1990B6AFFAD1ULL,
		0x434CFCEBA2D12810ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x057E1A98594D24B4ULL,
		0x96E658BEA35A59A4ULL,
		0xFE5168E4A0166CEEULL,
		0x08F8C80B19E5F878ULL
	}};
	printf("Test Case 38\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xD24260AC98CDF4BFULL,
		0x846EAE5F7A510FA3ULL,
		0xC8FCC76E33218701ULL,
		0x55521F841859053BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x25EAD283DF085FFFULL,
		0x51946D46ED01E18CULL,
		0xE13C973467309DFCULL,
		0x7BCB718299488DBCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF82D333077D654D1ULL,
		0xD6031BA66752F12FULL,
		0xAA395EA29A5224FDULL,
		0x511D9106B1A192F8ULL
	}};
	printf("Test Case 39\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xB66DF71B9B06E55AULL,
		0x958E688042323495ULL,
		0x10FFC6D45906878BULL,
		0x07ACBA9FE9A2C0FAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF3FA14C9357B4C70ULL,
		0xDCB1014755385B01ULL,
		0xA4CEC6C1C4F73330ULL,
		0x0F74917EFB8B48C5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAA680BE4D08231CAULL,
		0x723F69C7976A8F97ULL,
		0xB5CE8D961DFDBABCULL,
		0x17214C1EE52E09BFULL
	}};
	printf("Test Case 40\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x08FDCAD3A4017A62ULL,
		0x1139D202FB44E68BULL,
		0x3B7DB95958231866ULL,
		0x651F504D368BBA96ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF2A417115C0D1725ULL,
		0x12530CA0909590E2ULL,
		0x60CA35972A70C999ULL,
		0x7F4C90B90C9F5C04ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFBA1E1E5000E919AULL,
		0x238CDEA38BDA776DULL,
		0x9C47EEF08293E1FFULL,
		0x646BE106432B169AULL
	}};
	printf("Test Case 41\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xBEA9AAD7EC7A1762ULL,
		0x8A4449F66BB9CC90ULL,
		0x852851836B094CD0ULL,
		0x42EEB7147E33823FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x56CF2A68F25D98D6ULL,
		0x2647BEE9E1660094ULL,
		0xA3D31B104AC20214ULL,
		0x5F7C90A52120E00BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1578D540DED7B04BULL,
		0xB08C08E04D1FCD25ULL,
		0x28FB6C93B5CB4EE4ULL,
		0x226B47B99F54624BULL
	}};
	printf("Test Case 42\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x15C80FBC9EB83D6FULL,
		0x6223AF571E5CCECFULL,
		0xF2C9808BD0703FC4ULL,
		0x4E83EDB44F23A04CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2BF853F2F9283CB5ULL,
		0x0DA246511CFC8CB8ULL,
		0xD4C3F844A3B4DFA1ULL,
		0x2A72CAAFABEC7AD1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x41C063AF97E07A24ULL,
		0x6FC5F5A83B595B87ULL,
		0xC78D78D074251F65ULL,
		0x78F6B863FB101B1EULL
	}};
	printf("Test Case 43\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xD42547049BB80841ULL,
		0x929F1B92B2B8D0D9ULL,
		0x8645DC9DD35FDE69ULL,
		0x0848703D6CE8E8F7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD97872C59112525BULL,
		0x2490141492D42B5AULL,
		0x3BCE787EF2D6EA8EULL,
		0x79E9C219045AB75CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAD9DB9CA2CCA5AAFULL,
		0xB72F2FA7458CFC34ULL,
		0xC214551CC636C8F7ULL,
		0x023232567143A053ULL
	}};
	printf("Test Case 44\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x2CEC2FA0C394E895ULL,
		0xF4BA1F32DF14DAE9ULL,
		0x30E7C2E1748BE022ULL,
		0x24156D61A6D0DC90ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x69E57BDB4A6782BBULL,
		0x3746FEBFAE574F2EULL,
		0xEE0ABEBC3DAD85CCULL,
		0x4FD9841F31E0F376ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x96D1AB7C0DFC6B50ULL,
		0x2C011DF28D6C2A17ULL,
		0x1EF2819DB23965EFULL,
		0x73EEF180D8B1D007ULL
	}};
	printf("Test Case 45\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x34EA028620FDA236ULL,
		0x201077457909037DULL,
		0xEBE64C3BE0F24E3CULL,
		0x375BC40EB50AD123ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9945405F216220D1ULL,
		0x34C555ADA4EED145ULL,
		0x962CD6D3F90FEE51ULL,
		0x070E81826FC827BCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCE2F42E5425FC307ULL,
		0x54D5CCF31DF7D4C2ULL,
		0x8213230FDA023C8DULL,
		0x3E6A459124D2F8E0ULL
	}};
	printf("Test Case 46\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x4D2CF798631AB7DCULL,
		0xEC7E9259E6707DAAULL,
		0x75CCA790804799C5ULL,
		0x553A8A2C10DFAD58ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x05CA5F7AC316052DULL,
		0x94AD8B20A5C9DC13ULL,
		0x6569BA2CFA17DBCBULL,
		0x24A9A3339CFC89EEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x52F757132630BD09ULL,
		0x812C1D7A8C3A59BDULL,
		0xDB3661BD7A5F7591ULL,
		0x79E42D5FADDC3746ULL
	}};
	printf("Test Case 47\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x171FB6916F13D84EULL,
		0xC431DD0CFB579819ULL,
		0x639CE02DEABB6F9EULL,
		0x1CF3F06BF9C6C175ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD2434D5CD50695AEULL,
		0x1C58C2656C936D99ULL,
		0xDCDF026065DD7F99ULL,
		0x7B0B0420AC0C5E2AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE96303EE441A6E0FULL,
		0xE08A9F7267EB05B2ULL,
		0x407BE28E5098EF37ULL,
		0x17FEF48CA5D31FA0ULL
	}};
	printf("Test Case 48\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xEB6537B0884DF813ULL,
		0x5AD9EC691E5845B1ULL,
		0x330DF8F2CD67C462ULL,
		0x0851BFEFAA24A9E8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x12C934A12E4D898DULL,
		0x7B7A911EB3BDD45AULL,
		0xED5C18456E4F50F1ULL,
		0x79C478AF4BBECC3FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFE2E6C51B69B81B3ULL,
		0xD6547D87D2161A0BULL,
		0x206A11383BB71553ULL,
		0x0216389EF5E37628ULL
	}};
	printf("Test Case 49\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xBB73C4F2F35EB744ULL,
		0x066F507308A9A433ULL,
		0x28F2E5076051E46AULL,
		0x29409AC6C70487EBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBBC1AD550BEC82E3ULL,
		0xE2AFD21FDF984E79ULL,
		0xA2DD82C962D3894CULL,
		0x43F177E4EF35FFABULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x77357247FF4B3A27ULL,
		0xE91F2292E841F2ADULL,
		0xCBD067D0C3256DB6ULL,
		0x6D3212ABB63A8796ULL
	}};
	printf("Test Case 50\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x16973C889B6C0B65ULL,
		0x27BBFFA32B820DEDULL,
		0x28A936E01EEFECC7ULL,
		0x49E1602B71F44DFEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xED06B7F187AC36B7ULL,
		0x21FCE1CF35A7E632ULL,
		0xBA640E5D97418B6EULL,
		0x2B3BB80D94D868B0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x039DF47A2318421CULL,
		0x49B8E1726129F420ULL,
		0xE30D453DB6317835ULL,
		0x751D183906CCB6AEULL
	}};
	printf("Test Case 51\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xF6648475EAEF90DEULL,
		0x806E9B93F50A8F36ULL,
		0x2CE3CDCB42EEAEB4ULL,
		0x0D993F7BFB45B547ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0583769853BF89CAULL,
		0x0DBF6C24869114BAULL,
		0x4198F5EE8BFA11EAULL,
		0x0661C5EC2EA374E9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFBE7FB0E3EAF1AA8ULL,
		0x8E2E07B87B9BA3F0ULL,
		0x6E7CC3B9CEE8C09EULL,
		0x13FB056829E92A30ULL
	}};
	printf("Test Case 52\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xE292CC9140D62938ULL,
		0x6671FF5E7B1812B4ULL,
		0x557319555EC52ED7ULL,
		0x3D5556DCD84581E1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x42B4910BBE62DB02ULL,
		0x12978D585B64A568ULL,
		0x7BB96875DFDCE01DULL,
		0x6E01130952FF4EFAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x25475D9CFF39044DULL,
		0x79098CB6D67CB81DULL,
		0xD12C81CB3EA20EF4ULL,
		0x2B5669E62B44D0DBULL
	}};
	printf("Test Case 53\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x53AAEC145FC81706ULL,
		0x723D3CFD9ABC313FULL,
		0xBAD655274C91D267ULL,
		0x487F8C9B535E36A4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1DD107C1EE64EB96ULL,
		0x3A6A7D197A1E40E3ULL,
		0xC023A911A0F07412ULL,
		0x05A889FAEA558BD3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x717BF3D64E2D029CULL,
		0xACA7BA1714DA7222ULL,
		0x7AF9FE38ED824679ULL,
		0x4E2816963DB3C278ULL
	}};
	printf("Test Case 54\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x650C4903D2A14E22ULL,
		0xA8D85F27C304C231ULL,
		0xEF5045D0EE8B1400ULL,
		0x0024289816A37002ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8D04ABD618C14226ULL,
		0x42EB791DFBD24237ULL,
		0x6F89EB00C69199B3ULL,
		0x10479A856E8C6B74ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF210F4D9EB629048ULL,
		0xEBC3D845BED70468ULL,
		0x5EDA30D1B51CADB3ULL,
		0x106BC31D852FDB77ULL
	}};
	printf("Test Case 55\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xBD9362ED9935A613ULL,
		0xB6EAEA621B836864ULL,
		0xBAE6D6CE3FE9AC87ULL,
		0x775E827A54D1F2EAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4F1AB983137EE684ULL,
		0xBB7797A893F25CDAULL,
		0x5C8A7DFD67D2407EULL,
		0x2EE0EEBB6C0ECE47ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0CAE1C70ACB48CAAULL,
		0x7262820AAF75C53FULL,
		0x177154CBA7BBED06ULL,
		0x263F7135C0E0C132ULL
	}};
	printf("Test Case 56\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x197AC9E6BFEEAEC8ULL,
		0x3C97C3950FC4B4BBULL,
		0x05BC1C07695F0947ULL,
		0x32060DCFAD8D8505ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAB6B589C5D898F85ULL,
		0x954F5B1A03FEC884ULL,
		0x1852F1A86CEB489AULL,
		0x2FD03BCFFD884293ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC4E622831D783E4DULL,
		0xD1E71EAF13C37D3FULL,
		0x1E0F0DAFD64A51E1ULL,
		0x61D6499FAB15C798ULL
	}};
	printf("Test Case 57\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xB7F2698DE0D2EF1EULL,
		0x09698DD91396F281ULL,
		0x1CBA0B09942B542AULL,
		0x221A207D15B94EE1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x26D0D5DAF45EDE62ULL,
		0x13DBEC8E2F33E568ULL,
		0x57269501E8A0D1A9ULL,
		0x0DE701E58F7F6BB5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDEC33F68D531CD80ULL,
		0x1D457A6742CAD7E9ULL,
		0x73E0A00B7CCC25D3ULL,
		0x30012262A538BA96ULL
	}};
	printf("Test Case 58\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x03882086089C79FFULL,
		0x9D382DE4DE1BB5DCULL,
		0xF6FD5DDD761E63E1ULL,
		0x77CD4593B8CFBFEAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9B6BD0666ED03071ULL,
		0xBD0790694F157030ULL,
		0x26B57D5806AEF676ULL,
		0x474FD6E3E3B08C53ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9EF3F0EC776CAA83ULL,
		0x5A3FBE4E2D31260CULL,
		0x1DB2DB357CCD5A58ULL,
		0x3F1D1C779C804C3EULL
	}};
	printf("Test Case 59\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xF661414A9E6F3F59ULL,
		0x822F8DD31B2C854DULL,
		0x9606D435BF25D53DULL,
		0x039D314C6A129815ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8535638640247D19ULL,
		0x17C6613F22430B4CULL,
		0x6DB0F6FF50455EA1ULL,
		0x1508100C6261AED4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7B96A4D0DE93BC72ULL,
		0x99F5EF123D6F909AULL,
		0x03B7CB350F6B33DEULL,
		0x18A54158CC7446EAULL
	}};
	printf("Test Case 60\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xD33D4B8DB9A2B9CFULL,
		0xE34F7AA3E95BD93BULL,
		0xD62A4869724FFDF8ULL,
		0x7AC93949A504161BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x800D01287416D6D9ULL,
		0xEECA81E05E052406ULL,
		0xBDC6C7FE6C277722ULL,
		0x5F2DA42E699A5FDBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x534A4CB62DB990BBULL,
		0xD219FC844760FD42ULL,
		0x93F11067DE77751BULL,
		0x59F6DD780E9E75F7ULL
	}};
	printf("Test Case 61\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x7F4BA1E0403143B5ULL,
		0x6CEAED0B1A693B37ULL,
		0xDDAAC5216215839CULL,
		0x0C91250098F36CF4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4FDCD216D2B62F9BULL,
		0xD6C2288A6B517BD4ULL,
		0x9C4CC36F9C84C305ULL,
		0x270DD3A562C2E15BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCF2873F712E77350ULL,
		0x43AD159585BAB70BULL,
		0x79F78890FE9A46A2ULL,
		0x339EF8A5FBB64E50ULL
	}};
	printf("Test Case 62\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xA0854FC058C5783AULL,
		0xDD77E67506936BDDULL,
		0x245075D6716C967CULL,
		0x44EE135BF5AC5737ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x458DAE9020231AC8ULL,
		0xC7279BDE606A5E2CULL,
		0xC89761F2B2A52C5DULL,
		0x43E50E046DAFD96CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE612FE5078E89315ULL,
		0xA49F825366FDCA09ULL,
		0xECE7D7C92411C2DAULL,
		0x08D32160635C30A3ULL
	}};
	printf("Test Case 63\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x743684E4723F4BF7ULL,
		0xB63862485877C4E0ULL,
		0xC300409D2DC5710EULL,
		0x4C5BD6AFB684261DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9814F2E0164DF0BFULL,
		0x9D114B1F549599D7ULL,
		0x2CC286B8903930DCULL,
		0x4B8D9EB6AB490C1CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0C4B77C4888D3CC9ULL,
		0x5349AD67AD0D5EB8ULL,
		0xEFC2C755BDFEA1EBULL,
		0x17E9756661CD3239ULL
	}};
	printf("Test Case 64\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xC6F5AE9D19C916BDULL,
		0x9D9E625A9D1C54A1ULL,
		0x96ABB10AB0243852ULL,
		0x4DF901264D12E32CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFF6924BE30377980ULL,
		0x7D6F0BB540DCBF9FULL,
		0xF4E72DA16506EB46ULL,
		0x5DC3E85B0BFD4FABULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC65ED35B4A009050ULL,
		0x1B0D6E0FDDF91441ULL,
		0x8B92DEAC152B2399ULL,
		0x2BBCE981591032D8ULL
	}};
	printf("Test Case 65\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x48BF4425D8F2C397ULL,
		0xF634D75344192373ULL,
		0xACDB24342A9D16E7ULL,
		0x411F6B2BA7DDCAF5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9BF6186394BC424FULL,
		0xA4B974C9517B63B0ULL,
		0x405BF7F910DB26D6ULL,
		0x3ADC55C51755ABA5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE4B55C896DAF05E6ULL,
		0x9AEE4C1C95948723ULL,
		0xED371C2D3B783DBEULL,
		0x7BFBC0F0BF33769AULL
	}};
	printf("Test Case 66\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x6A7C51BFC3AA2B80ULL,
		0x919BBAD962297C65ULL,
		0xBB990001C38638B9ULL,
		0x57387A8FF6C1DFF3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x523DFE0135A338F6ULL,
		0x42DB8B93EF122EBCULL,
		0x441771F8AFBF82E4ULL,
		0x3B70E7EE76A3E455ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBCBA4FC0F94D6489ULL,
		0xD477466D513BAB21ULL,
		0xFFB071FA7345BB9DULL,
		0x12A9627E6D65C448ULL
	}};
	printf("Test Case 67\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x8AB4E603B3676FC0ULL,
		0xB4E89E96A5163D68ULL,
		0x846E8552C00DA584ULL,
		0x6FD4C72F7CED7B7DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x83C5B96E1C2F63E2ULL,
		0x0D83DDE90C0C6EB7ULL,
		0xE1ED6AE94D4F7348ULL,
		0x59289B12900865A2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0E7A9F71CF96D3B5ULL,
		0xC26C7C7FB122AC20ULL,
		0x665BF03C0D5D18CCULL,
		0x48FD62420CF5E120ULL
	}};
	printf("Test Case 68\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x1BDF24E2C2B28327ULL,
		0x58237EC764601C1DULL,
		0xF82814DD01CF3761ULL,
		0x2E183DFD28F49D30ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8E77FBEB4F229DC7ULL,
		0xC7D629F64077F691ULL,
		0xC2866320FDA8D9F4ULL,
		0x60D499449C92995EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAA5720CE11D52101ULL,
		0x1FF9A8BDA4D812AEULL,
		0xBAAE77FDFF781156ULL,
		0x0EECD741C587368FULL
	}};
	printf("Test Case 69\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xD06EA31F1DE45FA2ULL,
		0x30DFB7B82DD02CEFULL,
		0xDFE823C2801982DDULL,
		0x38D99CB19AA9FB1DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x925C197B95CCB801ULL,
		0x150413F3A86482B9ULL,
		0x57DE20C555D1E2D2ULL,
		0x14FFCD4A2D6B0983ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x62CABC9AB3B117A3ULL,
		0x45E3CBABD634AFA9ULL,
		0x37C64487D5EB65AFULL,
		0x4DD969FBC81504A1ULL
	}};
	printf("Test Case 70\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x6B83865053298344ULL,
		0x71672D0DB7EECCBDULL,
		0x6AFCC40EF75762ECULL,
		0x45BEC7D1FD6A959EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4809D0223893D917ULL,
		0x7571F44E65DEED90ULL,
		0x6472CF79BC62D6E3ULL,
		0x0EA482EE06B617AAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB38D56728BBD5C5BULL,
		0xE6D9215C1DCDBA4DULL,
		0xCF6F9388B3BA39CFULL,
		0x54634AC00420AD48ULL
	}};
	printf("Test Case 71\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x1397E6047169B824ULL,
		0x51385ED6FF5A3C54ULL,
		0x3C7F311A243A9FC9ULL,
		0x422BE8E01E9BB62FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEC4BAED6270457D2ULL,
		0x59E592BA36260EDBULL,
		0x3AD1A217BFB04EC4ULL,
		0x350AD47E6B132F07ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFFE394DA986E0FF6ULL,
		0xAB1DF19135804B2FULL,
		0x7750D331E3EAEE8DULL,
		0x7736BD5E89AEE536ULL
	}};
	printf("Test Case 72\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xB0F9F91408D9BCEEULL,
		0xFB5982611118280CULL,
		0x0EC6B57C61EE88BFULL,
		0x0DB4D8133B088452ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA6BC1FAC436FE642ULL,
		0x239047E531C44BFBULL,
		0xC6E84A1EB97254C2ULL,
		0x5F62236A947D7034ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x57B618C04C49A330ULL,
		0x1EE9CA4642DC7408ULL,
		0xD5AEFF9B1B60DD82ULL,
		0x6D16FB7DCF85F486ULL
	}};
	printf("Test Case 73\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xC8E972E3C918BC4EULL,
		0x62CEC37BCA1C7D2CULL,
		0x4EE57F7A0B9E8E0AULL,
		0x4C1F52EDC538718DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD4068C9D098B2D65ULL,
		0xACB4F1E999DF91D9ULL,
		0x71CE2F18CDD6D803ULL,
		0x691C76C8D28E57D3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9CEFFF80D2A3E9C6ULL,
		0x0F83B56563FC0F06ULL,
		0xC0B3AE92D975660EULL,
		0x353BC9B697C6C960ULL
	}};
	printf("Test Case 74\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xB73F420ACCA9E754ULL,
		0x7EE9D03693ABACABULL,
		0x01A88B5D80D4F165ULL,
		0x561F9DDEC987E87EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x19510E98F653F4B4ULL,
		0x42A6192C3BE4257DULL,
		0x9A3BD9A3968FAF9BULL,
		0x193341386C81088AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD09050A3C2FDDC08ULL,
		0xC18FE962CF8FD228ULL,
		0x9BE465011764A100ULL,
		0x6F52DF173608F108ULL
	}};
	printf("Test Case 75\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x0825079EFDAD1D43ULL,
		0xFD3EB0F98CFFF5ABULL,
		0xE78EC14843C82D82ULL,
		0x75470E5680B53BF7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD3AF87D96536CB3CULL,
		0xC72EB5EF62FC7036ULL,
		0x0DE47D2EB75FE091ULL,
		0x31A540AD7E78233FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDBD48F7862E3E892ULL,
		0xC46D66E8EFFC65E1ULL,
		0xF5733E76FB280E14ULL,
		0x26EC4F03FF2D5F36ULL
	}};
	printf("Test Case 76\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x7396EAC75284248BULL,
		0x20ED530FDDF1F3EEULL,
		0x649D898101A17770ULL,
		0x25500B47AA0D3BD1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2AA7EDABA9285BC4ULL,
		0x83888562F097567DULL,
		0x333BE3AAE2A6F5E2ULL,
		0x12011DB2A5BFE964ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9E3ED872FBAC804FULL,
		0xA475D872CE894A6BULL,
		0x97D96D2BE4486D52ULL,
		0x375128FA4FCD2535ULL
	}};
	printf("Test Case 77\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x62DA3FEA1CBCA6C2ULL,
		0x69320DCA7B713683ULL,
		0xE14A0279B364BBD8ULL,
		0x6485AB80A5B0928BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0A07D55B2D634ACCULL,
		0x61F1A35B98DB97DEULL,
		0x46F564714FF4EC65ULL,
		0x7B660F064B6A8539ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6CE215454A1FF1A1ULL,
		0xCB23B126144CCE61ULL,
		0x283F66EB0359A83DULL,
		0x5FEBBA86F11B17C5ULL
	}};
	printf("Test Case 78\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xBF5BEA1D1D6992DBULL,
		0x3505F0A2532F13E6ULL,
		0x640B332DE8C589EDULL,
		0x75D7357040F880F0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x79C5F8FECE1E4BB5ULL,
		0x02DDD57C186E62FFULL,
		0x994FCE616557DC01ULL,
		0x72D0E39D01028076ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3921E31BEB87DEA3ULL,
		0x37E3C61E6B9D76E6ULL,
		0xFD5B018F4E1D65EEULL,
		0x68A8190D41FB0166ULL
	}};
	printf("Test Case 79\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xBF291A33D30D2C77ULL,
		0xC4B78F780C6E0616ULL,
		0x33F1A813BC58C35FULL,
		0x41DAA5A5C1F6FBEFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF8D6169428B77D06ULL,
		0xE5AD5EBADDB1C51AULL,
		0x25FEB9C006386082ULL,
		0x346104C6E2757A4FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB7FF30C7FBC4A97DULL,
		0xAA64EE32EA1FCB31ULL,
		0x59F061D3C29123E2ULL,
		0x763BAA6CA46C763EULL
	}};
	printf("Test Case 80\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xBBF476320EAD8F06ULL,
		0xE47A8DFD632AFA82ULL,
		0x546126A72DD86872ULL,
		0x15123F7F66BA484FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x81D1CF113310E921ULL,
		0xD07B20C748282FBEULL,
		0xEAE06B21A76D23A7ULL,
		0x035E41B5E59E7836ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3DC6454341BE7827ULL,
		0xB4F5AEC4AB532A41ULL,
		0x3F4191C8D5458C1AULL,
		0x187081354C58C086ULL
	}};
	printf("Test Case 81\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x94B3EC7D3E1F8ED4ULL,
		0x4FFEF42EFBAC79F6ULL,
		0x828159061179E7E5ULL,
		0x63FC91C7708980CDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD0D05471B181E5AFULL,
		0xBFCC61BC22166FCAULL,
		0x613D802744133321ULL,
		0x13A9439118569445ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x658440EEEFA17483ULL,
		0x0FCB55EB1DC2E9C1ULL,
		0xE3BED92D558D1B07ULL,
		0x77A5D55888E01512ULL
	}};
	printf("Test Case 82\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x1C3B0555AB693547ULL,
		0x8E4D9D8E38F071BEULL,
		0x5992EE8EF7CEA060ULL,
		0x2E1CF713DF4E5FCBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8AF5EB87FF7FE6DFULL,
		0xF4A5F4FB21C9A9D8ULL,
		0xAD25532931B63B54ULL,
		0x3CC36CDFCAD7290EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA730F0DDAAE91C26ULL,
		0x82F392895ABA1B96ULL,
		0x06B841B82984DBB5ULL,
		0x6AE063F3AA2588DAULL
	}};
	printf("Test Case 83\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xF6BC690AA20BB8C7ULL,
		0xA08C1B1C170C90BCULL,
		0x281ECB4769048B60ULL,
		0x0E5DB49475CC0DCEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xABE19C9B9472E988ULL,
		0xA1CEACDBBD1C68BEULL,
		0xDAEFA01C86B4135EULL,
		0x240AFEA9E37F6890ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA29E05A6367EA24FULL,
		0x425AC7F7D428F97BULL,
		0x030E6B63EFB89EBFULL,
		0x3268B33E594B765FULL
	}};
	printf("Test Case 84\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x35B8ECE811838EC5ULL,
		0xD75F4C10F7FDBA6AULL,
		0xBEC988848990B535ULL,
		0x2B4441ECACDB5FC7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAAE2E1C3D4988C6CULL,
		0xD7E00E42346487A0ULL,
		0xC271CBDCF123D3C4ULL,
		0x2714E67983D16CCFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE09BCEABE61C1B31ULL,
		0xAF3F5A532C62420AULL,
		0x813B54617AB488FAULL,
		0x5259286630ACCC97ULL
	}};
	printf("Test Case 85\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x0B44EE04C7B08120ULL,
		0xAB4AF23A0E7887FAULL,
		0x785165A82F3BAC9EULL,
		0x355CD4BFE6D0A154ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAA5719EC3A001F81ULL,
		0x2EFEF6E643073F6EULL,
		0xB8566E6FD605F937ULL,
		0x25ECD46C0F8F666CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB59C07F101B0A0A1ULL,
		0xDA49E920517FC768ULL,
		0x30A7D4180541A5D5ULL,
		0x5B49A92BF66007C1ULL
	}};
	printf("Test Case 86\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x5229C32F92B30424ULL,
		0xCD186B06B0BFF65AULL,
		0xC7402318407D89D0ULL,
		0x19ACDF185DC535ADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC2FC0C312BDBA4A7ULL,
		0x25E87579ADFCEE78ULL,
		0x6355D8C27B0EC7ABULL,
		0x796EA9C505EFFB8BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1525CF60BE8EA8DEULL,
		0xF300E0805EBCE4D3ULL,
		0x2A95FBDABB8C517BULL,
		0x131B88DD63B53139ULL
	}};
	printf("Test Case 87\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xDB186B3E32DF5CC1ULL,
		0xC1472971A459D50BULL,
		0x8EA980B836DC4E7FULL,
		0x724AA1B984A078DDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2A666E09DDDDE790ULL,
		0x127ED69EA0AFAB68ULL,
		0x7686F16765732080ULL,
		0x663D3BC3C23BECA5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x057ED94810BD4464ULL,
		0xD3C6001045098074ULL,
		0x0530721F9C4F6EFFULL,
		0x5887DD7D46DC6583ULL
	}};
	printf("Test Case 88\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xE1717929E684F65DULL,
		0xBAFE196B948BB959ULL,
		0xB849F5C6713FBD9EULL,
		0x5152ADD1A2149AC2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x72A36AF1C4DEE7EEULL,
		0xECA646E069C76A72ULL,
		0xD30FE4F45F50D7A7ULL,
		0x3013F0B8FEDD04F7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5414E41BAB63DE5EULL,
		0xA7A4604BFE5323CCULL,
		0x8B59DABAD0909546ULL,
		0x01669E8AA0F19FBAULL
	}};
	printf("Test Case 89\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xE24E9CB678E314C3ULL,
		0x516D9ECD21D8702DULL,
		0x39E265A4C8039972ULL,
		0x16D897E8D582273FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2D8091D7C193A2AAULL,
		0x1C5EFAE5A128F6DCULL,
		0xA564D3DA8BACB0BBULL,
		0x6804CE7C8E7B7E1BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0FCF2E8E3A76B76DULL,
		0x6DCC99B2C301670AULL,
		0xDF47397F53B04A2DULL,
		0x7EDD666563FDA55AULL
	}};
	printf("Test Case 90\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x4458698DA952A4BCULL,
		0xD49FAE70A69FADEEULL,
		0x3C93BEB487A4FD3BULL,
		0x7D4F27AE2C3EEB75ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4400DF5DBB6FACC8ULL,
		0xECC7C309944DC065ULL,
		0x544CB0AB1FF42772ULL,
		0x3A439B53FA12A177ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x885948EB64C25197ULL,
		0xC167717A3AED6E53ULL,
		0x90E06F5FA79924AEULL,
		0x3792C30226518CECULL
	}};
	printf("Test Case 91\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x29E20583A24845E5ULL,
		0x47957556B579D78DULL,
		0xF04FB3B4E26E6CCAULL,
		0x7191D5A84CA2F82AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9D915C520DDEC559ULL,
		0x7CCD4DA7EAD6E4E3ULL,
		0xC3B8C82D3CA7677EULL,
		0x1200BBD87C4CF579ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC77361D5B0270B51ULL,
		0xC462C2FEA050BC70ULL,
		0xB4087BE21F15D448ULL,
		0x03929180C8EFEDA4ULL
	}};
	printf("Test Case 92\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xCF9F1E85ABEF1EDBULL,
		0xFDD6EFDC013CBD29ULL,
		0x2D5C2183244940D9ULL,
		0x6114325D6736CF25ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDDF344C91051767BULL,
		0xDA356928EA85BEECULL,
		0xE0BA00A0BD6A6119ULL,
		0x026578085D1FB2C4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAD92634EBC409556ULL,
		0xD80C5904EBC27C16ULL,
		0x0E162223E1B3A1F3ULL,
		0x6379AA65C45681EAULL
	}};
	printf("Test Case 93\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x191B1641F2D9ECA4ULL,
		0x5DBAF0988CB082CDULL,
		0x14400701039A0B1DULL,
		0x72707A04201C7313ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2FE5EECA19A33645ULL,
		0x008087355D547F95ULL,
		0xED82E4BDB3C511E8ULL,
		0x780C5B209B866E33ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4901050C0C7D22FCULL,
		0x5E3B77CDEA050262ULL,
		0x01C2EBBEB75F1D05ULL,
		0x6A7CD524BBA2E147ULL
	}};
	printf("Test Case 94\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xA217FC15A512AA36ULL,
		0x226C293D56902B96ULL,
		0x7A0F7AA4DAF7FAC0ULL,
		0x648B3FCBB05E8E62ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE2985CD4B45F7ADDULL,
		0x88845EE784894FAAULL,
		0x839626F355F40FFEULL,
		0x7CECF129EF633D40ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x84B058EA59722526ULL,
		0xAAF08824DB197B41ULL,
		0xFDA5A19830EC0ABEULL,
		0x617830F59FC1CBA2ULL
	}};
	printf("Test Case 95\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x6A8B859F2A4485B0ULL,
		0x07A3987AD9939D5EULL,
		0x17965902C3F07A50ULL,
		0x4604CF7BB6348B7BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8007315AA97A2E25ULL,
		0x3154044AD24EE786ULL,
		0x0373D06223747E46ULL,
		0x2B15FEBC3F70654EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEA92B6F9D3BEB3D5ULL,
		0x38F79CC5ABE284E4ULL,
		0x1B0A2964E764F896ULL,
		0x711ACE37F5A4F0C9ULL
	}};
	printf("Test Case 96\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x402CE069B640AB93ULL,
		0x1FE4E8F4F057FC6FULL,
		0x2EC8457ED3BD1967ULL,
		0x53CA598473317F25ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC75C879D8689AEFFULL,
		0x58AA2FF0214F1CFBULL,
		0x6BA407F647617DCFULL,
		0x12DE7A62B8EB53A6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x078968073CCA5A92ULL,
		0x788F18E511A7196BULL,
		0x9A6C4D751B1E9736ULL,
		0x66A8D3E72C1CD2CBULL
	}};
	printf("Test Case 97\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xAC3EE519ECE04A6AULL,
		0x31486FEDA22546B3ULL,
		0x1B70DA46B20505DCULL,
		0x7F47CA5211708353ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x377BF1D978260917ULL,
		0xF5B8DFA987EBD424ULL,
		0x178115863B8E1FBAULL,
		0x4224BB54DF42C9A9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE3BAD6F365065394ULL,
		0x27014F972A111AD7ULL,
		0x32F1EFCCED932597ULL,
		0x416C85A6F0B34CFCULL
	}};
	printf("Test Case 98\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x2727AC8C4E26DAA1ULL,
		0x081E48D8FA24BEC7ULL,
		0x9478E7832FA12AFDULL,
		0x29031AD024F9B0ECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x564F958CF4232B9BULL,
		0x1203E1EE344645CBULL,
		0x68EA8FECCDFB1F45ULL,
		0x5D3BFAD1B02D4C96ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7D774219424A064FULL,
		0x1A222AC72E6B0492ULL,
		0xFD63776FFD9C4A42ULL,
		0x063F15A1D526FD82ULL
	}};
	printf("Test Case 99\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xD2D5F078212AC962ULL,
		0xDE770F2423B8AF23ULL,
		0x472B0BCA793C41E2ULL,
		0x437557E54BDDD06BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB6B36D4FEA986C19ULL,
		0x17D18A2051D78434ULL,
		0xD477752CAD6F6DA5ULL,
		0x2DEBF2D23E696271ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x89895DC80BC3357BULL,
		0xF648994475903358ULL,
		0x1BA280F726ABAF87ULL,
		0x71614AB78A4732DDULL
	}};
	printf("Test Case 100\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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