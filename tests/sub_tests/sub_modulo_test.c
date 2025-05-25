#include "../tests.h"

int32_t curve25519_key_sub_modulo_test(void) {
	printf("Modular Key Subtraction Test\n");
	curve25519_key_t r = { };
	curve25519_key_t k1 = {.key64 = {
		0x2D4C66F239F02343ULL,
		0xF883D367A2F9607EULL,
		0x47E45D37FAA91104ULL,
		0x7EE057D09D924BA0ULL,
		0xCA42EFFCAD5C4E58ULL,
		0xF86388077631DB89ULL,
		0x70D3418E5C93400AULL,
		0x1534174FF9794AA3ULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0x432D36BADB104760ULL,
		0xDCBE66EE669D1A82ULL,
		0x74AE6AA7670D7591ULL,
		0x68F73319AB7C85AFULL,
		0x81D3DA4F259C6589ULL,
		0x61A438C825F60C5FULL,
		0x423423AA600C7BACULL,
		0x2D4A7E3B43B94FF1ULL
	}};
	curve25519_key_t k3 = {.key64 = {
		0xAA9C67F9855C6A18ULL,
		0x7C2B2FDF253D0642ULL,
		0xBED462680F9CC17DULL,
		0x0295DDC9EC94FC63ULL,
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
		0xEE7C428C770E636DULL,
		0xB3F0C67E4E3C9302ULL,
		0xF1ACB4D1E1803202ULL,
		0x30C1201F4CC25B68ULL,
		0x9FC7166CE3776FBEULL,
		0x540435EB9EEE19E6ULL,
		0x31B4F56F7DB7A156ULL,
		0x2D5094701B79B975ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB7EBA60ED42DDEA0ULL,
		0x42A767A362B1355AULL,
		0xC9CA35F15A3B54F0ULL,
		0xFB2DA1603CAC1E3CULL,
		0x63281AF46B7CE1B8ULL,
		0x6FA76ADB6D735BECULL,
		0xAA0C4A4E3E574DE9ULL,
		0xACBBA020A4BE27EDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3629F05F721196B9ULL,
		0x570F834243C390CDULL,
		0x4AEBE5CFEF913F3CULL,
		0x4BAFC28AAFEDD74AULL,
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
		0x51C88C09213609D7ULL,
		0xC3760E808FB63276ULL,
		0x9CEEA492F7192E31ULL,
		0xA03F5937D54DD933ULL,
		0xDEE9DABFB40AFBBBULL,
		0xCA172291FD4C3246ULL,
		0xC3F5E17B3CB03D50ULL,
		0x7FC3775E3528886BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xACDCB4710DE21CC5ULL,
		0x5E914D0B9ED20092ULL,
		0xD047DEB3F11B8DAAULL,
		0x80766A915E6A1539ULL,
		0x2A33F38A691BC74CULL,
		0xD3B29A3EB495BD33ULL,
		0xCEE880A31E5D39ABULL,
		0x2449CC1A8F202008ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x77EC298132D5B78DULL,
		0xF7D0FDD1BBF992D0ULL,
		0x2CA325F386502B03ULL,
		0x33D85AB11C2342AAULL,
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
		0xB1A2D0F9E158AF7FULL,
		0x3571CAD060BF1C08ULL,
		0xEF704B3881FB0A48ULL,
		0xBF2A4F85F2560158ULL,
		0x4EECB865D2F191D1ULL,
		0x66E1BDBD075EADCEULL,
		0xED598022C35D62EDULL,
		0x32D7AA38B3C3EF03ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4EB5FAE620FE4662ULL,
		0x1A86D86E5CD834BCULL,
		0x0F86E19E9ED75188ULL,
		0xFC5E202DF4103AE7ULL,
		0xF408B9CFC4BEF52EULL,
		0x1EEBD3E6FB6E877BULL,
		0xBE840B16A1A2DA6FULL,
		0xAC83410CEACDCDBAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE0C4A059DBDDA690ULL,
		0xC96BA827C98C9785ULL,
		0xD398C966E4D3FB7EULL,
		0x3353CBD7D2CEB74EULL,
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
		0x94083810C3091BEFULL,
		0x078DA3C1AA43CEABULL,
		0x91A9CF255DB47627ULL,
		0xD6AEE5F20A0CC00DULL,
		0xB12FC0AF674AE752ULL,
		0x9ABC0171BAF4F865ULL,
		0x0E5D6EE3AF58B642ULL,
		0x56F54B831795945DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD3C8539D10633B06ULL,
		0x5BE2C080FE87625FULL,
		0x83FAB8D31B0BAD64ULL,
		0x06AB0AEE370FB9D4ULL,
		0x5879DC1FF4FBCBA3ULL,
		0xBD593E362149FE49ULL,
		0x1149099E1492B4DDULL,
		0x81B0CE910B6DF804ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEB3FD1BEAA63FBFFULL,
		0x8853DE197B1D8C80ULL,
		0x9EB61EA73C0CFDBBULL,
		0x782E66F1A0DE3B6EULL,
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
		0xC41D0CC5D068DC17ULL,
		0x5F432C58F0E2093EULL,
		0x8FB3B794CE86F95EULL,
		0x7695721867521E55ULL,
		0x04541F6B3C0E1BDFULL,
		0xFD2DF83482303A46ULL,
		0xE6435D1FD730C863ULL,
		0x42DE016E2175B6C3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x56139D9B611735D0ULL,
		0x3B072D6B00499E6CULL,
		0xADF4F5488DE03CB0ULL,
		0xE668A4C0220FFE6CULL,
		0x0D2C5049B8E29CCEULL,
		0xE8513F20783B7EDAULL,
		0xA1A1A16957E6662CULL,
		0x87C19B21F04E52E7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1DF22E23E7C6812BULL,
		0x3CFF77E76AEC3CD9ULL,
		0x11C09F6325B150DBULL,
		0x5663FCA7911AF29BULL,
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
		0x0EB4F228F55DC318ULL,
		0x538C9D6B29393C72ULL,
		0x7A9C3740CDC3AC78ULL,
		0xC5640F527F1F5CCBULL,
		0x53BECA1C6E0A0CCFULL,
		0x932A87EC0638DB07ULL,
		0xD54435E0AF42FB66ULL,
		0x152704CA3078E52FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD964A8DA1206D89CULL,
		0x1F304164549D1CEFULL,
		0x736A95EEC5AEAB48ULL,
		0xB5C63BC94CDE15AAULL,
		0x96C642ECB727F9DEULL,
		0xAE8765F006D10558ULL,
		0xFD0A10AB81776CCBULL,
		0xC116BAD855E8B6E8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x42345A6408E5B679ULL,
		0x2493676EBE05D772ULL,
		0x1FD32736D44C2C2EULL,
		0x0A08CD6FA3A825A5ULL,
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
		0x02E5E27BAC43F7D6ULL,
		0xFC1666D552B55FBAULL,
		0x8E4664120F37FCC9ULL,
		0x4AD15CE03C2AB46FULL,
		0xE0D96D95A8347667ULL,
		0xF4AC4235079E074FULL,
		0x5411CE753A4FBE33ULL,
		0x7B40AA9E18C43E19ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x259F768477D33F7EULL,
		0x8DB4E4CC9F99B0DBULL,
		0x41156376823EAC2FULL,
		0x09135CF841E3F6CAULL,
		0x3D822665FF668855ULL,
		0xBA718FF1D2BCBE9DULL,
		0x7B6AB2CCC9EACE38ULL,
		0xA67CDFE696036881ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1C3AFD0A43020E0DULL,
		0x1317F8028C8C7963ULL,
		0x75FF1B9C3BF4EFE5ULL,
		0x56CE172562E6722FULL,
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
		0xDEF0405357BE8166ULL,
		0x347AF286B6C7AB01ULL,
		0x3C6B18400D4C643FULL,
		0xE1276EDCFCECBBDEULL,
		0x7AECF6190D53487EULL,
		0x4E086A6C49A13574ULL,
		0x867E65F8BA29B4A9ULL,
		0x3D697F50D12B8696ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA4B7B3137F1F5FE2ULL,
		0x1FA49D54E3766447ULL,
		0xCEF083C4928252DFULL,
		0x021C6650A492F553ULL,
		0x0E6345279E66C061ULL,
		0xF2C7B044668FC1A5ULL,
		0x9977E720579D48E8ULL,
		0x039CACD5DBAAA2E0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x56A8D1164FBB5728ULL,
		0xA071F71D87E87784ULL,
		0x9C71689A1BA20FEDULL,
		0x737246CCC97B938BULL,
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
		0xE3CD409932818B36ULL,
		0x016C0E1B02D14C7BULL,
		0x0B3103C3659F0D41ULL,
		0x51C035737BEDBBB4ULL,
		0x4C65D97528F30927ULL,
		0x5AD76946BD766433ULL,
		0xCF96329E42A944DAULL,
		0x593CCF0641FBCE00ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE99B6B8D9657C860ULL,
		0x6A656E7D3A693DC2ULL,
		0x2A3C988940580D3DULL,
		0xA1DE2CE23D7889F0ULL,
		0x451060E5E9808458ULL,
		0x8D72F157F22B0643ULL,
		0x7141C543894725ACULL,
		0x18D3AB5CDE03C7E9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x10E1BA4F07297AE6ULL,
		0x13F06D0FF598005AULL,
		0xE17CA6B1A9D7A0D0ULL,
		0x3F7D53B61546193BULL,
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
		0x4ECC7C2CCE31EFE4ULL,
		0x25C2A2898A673444ULL,
		0x10F517229350CA5FULL,
		0x91404CBF49FF761CULL,
		0xD0EB43B0E77DBADBULL,
		0xB98EF47506BD27F5ULL,
		0xA5869C6810E81A9EULL,
		0x0A4474E18A23313BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6049FD60AF40A655ULL,
		0xBC58C9774397F81AULL,
		0x586E3DF5FF6E6971ULL,
		0x5830BA06DE5527FAULL,
		0x9073CE545442079CULL,
		0x3264509210949247ULL,
		0x92FEB861836E102DULL,
		0xD4380F9E7AED5388ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x803DEA89F9CDE075ULL,
		0x79BE2CC2D0D57407ULL,
		0x78B2B22593FFEDC7ULL,
		0x3EE69AACADA936B6ULL,
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
		0xCE815BA6948CDC6DULL,
		0xB98F9E3F3E22D34AULL,
		0x39BCD2561F5CD7CAULL,
		0x741555650E43EB42ULL,
		0x65DFC4DBA077DD55ULL,
		0x1827904134502FDEULL,
		0x15288EEE3089015FULL,
		0x1CA6C3FA296AD77BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4AD9B16011F88311ULL,
		0x5D75DD3D405B87D5ULL,
		0x70DDE62F2EE3B508ULL,
		0x295343892F138A6BULL,
		0x72003DB139FD3C84ULL,
		0x8DE0E1019F612CE1ULL,
		0xCF712F8DEB90EEF8ULL,
		0xFC4D5F1D61CCD9BDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB6D5BA91B8C8337CULL,
		0xE297C4721941BD01ULL,
		0x221714712D4BDDFAULL,
		0x18070AA180A40AEFULL,
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
		0xE1E1224F13553AA5ULL,
		0xFF4D57C1DDD62DA0ULL,
		0x150BD32840BE064AULL,
		0x55E117B5054AB848ULL,
		0xC6EC777C95699A4CULL,
		0xC6395C7BF5CEDD7AULL,
		0x02EDE9EDC8A7A706ULL,
		0xC59F65B579D845CEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F0DAD709E2CAD3AULL,
		0x757FB37361D0B85DULL,
		0x2A8AA648127743DEULL,
		0xA89F64127BA60E8BULL,
		0xD8D209AE518B0596ULL,
		0xF58F5BCC61612AC1ULL,
		0x43BBB82855979AE1ULL,
		0x09E8F16926B137ECULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2ABFC17C8832A484ULL,
		0x8309BE5E844DFCB7ULL,
		0x4BF4902F42A88FE3ULL,
		0x0A56F6F6E170B93FULL,
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
		0xAF5707917D1E44D8ULL,
		0xACD79EA749DCE520ULL,
		0x7A1EB8C2837923EFULL,
		0xEC04662066376601ULL,
		0x2373BAF5E0A45337ULL,
		0x9561F6D95B311CA9ULL,
		0xF0EE7CF2E2CBC7A6ULL,
		0xB84FE8F7A760DB90ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3A91D0357174B487ULL,
		0xBDEEA9AAF2CEDAD5ULL,
		0x7091251D3D4AACC5ULL,
		0x9A2B0EA3022D555FULL,
		0xC3BAD3A9E757107CULL,
		0xD13B51F08B603884ULL,
		0xEC608FEF6DDB659FULL,
		0x79BA6BE1DDF3B49BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAA378CA30D21797CULL,
		0x0CA56F8B300FE7B1ULL,
		0xB69EC228A1DD042BULL,
		0x1C09E8B94A3DD900ULL,
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
		0xB94CFD220E9C5CA0ULL,
		0x03D16BB562793306ULL,
		0xB162737483441993ULL,
		0xD58491ED647B3A4DULL,
		0x3BE155E462DECE21ULL,
		0x02295AF24823A589ULL,
		0x8B5CE0F5902D4DC5ULL,
		0x26996E68F531BFD3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x145DA976B41E0FC6ULL,
		0x59E6A4A156538B3FULL,
		0xB57571688CA7181FULL,
		0x1CDB6B0689A6C9C5ULL,
		0xA747504161C3EC56ULL,
		0xF71F9A3B18D0CD8CULL,
		0xAAF03D120516C38EULL,
		0x3FB6E491A0E05807ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB3CC29DD847BD077ULL,
		0x4D5D62451271B745ULL,
		0x4C0D55D29BF58579ULL,
		0x7E499CDD5EE9D8CBULL,
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
		0x3F9050DDBBA42B56ULL,
		0xC871FC5A380A9517ULL,
		0xD404B903C6967C40ULL,
		0xF3A0E891D049E702ULL,
		0x0BE839A5A22F039FULL,
		0x79FE8713B7F51BF3ULL,
		0xECC1C7B851692A2CULL,
		0x9837DC5FE00A2F37ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x57003631629497C7ULL,
		0x6402778C8A151B87ULL,
		0x119BA1B026E30D9BULL,
		0xC1B787C3A274023FULL,
		0x4104028EC1E4BAD0ULL,
		0x610FCC0071DE8F6FULL,
		0x7EB14D409AC2F28BULL,
		0xE6CE7E51D12BC0C6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x06704811A4166094ULL,
		0x17DF49AA154E5520ULL,
		0x18DB4518BC5FB08FULL,
		0x078D56E462DA499AULL,
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
		0xB270E4429D2F0672ULL,
		0xFC91198AD73A9368ULL,
		0x4A4B630E7ACF126DULL,
		0x08F2D5ADE0E22EC5ULL,
		0x0AD1125C49CCEB6BULL,
		0x5A5777EBC4FEAAF6ULL,
		0xA1B707D8D17B6ECFULL,
		0x3930A3630D8670FBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD5465FBE2A505B04ULL,
		0xCA9685B02B1930CDULL,
		0xA6F5E05F17875B55ULL,
		0x49803AD11476489EULL,
		0x97678CE4340D6CABULL,
		0xA9E0FE366DB84DBAULL,
		0xB88A4D67E0CE54B2ULL,
		0xF0DF4FD2B87FD600ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFED45457AD4B77C6ULL,
		0x6390A4C5A093396DULL,
		0x3FF92F731CF9975AULL,
		0x7B8502496B66E765ULL,
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
		0xDA60D9629DC4E76EULL,
		0xD04853FFFA487FE9ULL,
		0x6E02F5A84AEA20D3ULL,
		0xE4CA37B2024CB51EULL,
		0x6343394D65E4DA6CULL,
		0xD45F6EBDD66EA1C2ULL,
		0x23E935E48B94F220ULL,
		0xBB197EA81F3A414FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3337B4712DB826A7ULL,
		0x827B553D70FA1D60ULL,
		0xE5AE4C4C1E250649ULL,
		0x60573BEA3E2368F1ULL,
		0xAD858EE26F7698BBULL,
		0x53C91EBE9D913209ULL,
		0x01E241DBAE863A52ULL,
		0x99B7C4E3CF67CA92ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA15070D2046A81CBULL,
		0x641CDEA4FA2CF7F4ULL,
		0x955CE2ACFCF46331ULL,
		0x78F48EEB9D66EC3FULL,
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
		0xEC4E1789DB1C1C31ULL,
		0x752D4CC67DB6408EULL,
		0xFF3E622A301A0163ULL,
		0x2DE01EF63DD2E853ULL,
		0x5C0892D29DD1AF50ULL,
		0xE4FDE536F92D5B46ULL,
		0xA1735DA03A2DC1B5ULL,
		0x2198EF1CA4A0040AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x171B2032610CCECFULL,
		0x06B4B5B78331C865ULL,
		0x805A3D708DC0736EULL,
		0xA9BF1F6CEA52947AULL,
		0x2A98616C8DF9CC29ULL,
		0x58B6C42404F1232BULL,
		0x9F7A9DDA4B8766DEULL,
		0x80EF3F135B7481DFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2BDA4C7DD41B02F2ULL,
		0x41077FDF3B74CC33ULL,
		0xC9D09C1B0F0B09F4ULL,
		0x5D5120EA2FF5A63BULL,
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
		0x46B6D54BCCAE7C1EULL,
		0xC315402ABAC024BCULL,
		0xDFF61921937F7F63ULL,
		0x01DB301BEDDF3FD0ULL,
		0x6BC50677058ACFEAULL,
		0x02D5469C0439C745ULL,
		0xF5F0E15D0AD6462AULL,
		0x529F2F9E7A64E0D0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x091918D7AC79BCD8ULL,
		0x5F0363260835D1BCULL,
		0xEEB29CE74B0B7EDFULL,
		0x2A981EA2C41DA31FULL,
		0x2E080CEB6318839AULL,
		0xCE1BC0650D53B3AEULL,
		0xF6777D7368CA32BCULL,
		0xAEA920B5FC55503BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x67AAC72E3D2C1112ULL,
		0x379BC92D58B13B73ULL,
		0xDD4850E8563EE2BAULL,
		0x2DC947FBE01112CEULL,
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
		0xCE7930459BA6F41EULL,
		0xE051146BCA0FB930ULL,
		0x2A4CF67CC7369206ULL,
		0xD0D438F3A6274189ULL,
		0xF993DEB04E86B170ULL,
		0x38D31D3DC7F674CCULL,
		0x88AAE200D1A7235AULL,
		0xD6A7DC6AA44CB866ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD27F87D19701E809ULL,
		0xF0615C3A866A67F6ULL,
		0x5A31C0C65119A20AULL,
		0xE53949A8414AFC1DULL,
		0xA45A83E529483BACULL,
		0x9672FFE858C6C3A4ULL,
		0xA896A76C1B850CEEULL,
		0x940033B5B2B04F80ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA27D229B8BEA8896ULL,
		0x0A3412DFC4B99D36ULL,
		0x131BE7C97F2C43F6ULL,
		0x507DFA274213D78BULL,
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
		0x19D46EE9A29DF1E3ULL,
		0xB85CCDAFA639A704ULL,
		0x25E59AE341DE554EULL,
		0x6A0EF2FBF39A05FBULL,
		0xC6669E92C7B3625FULL,
		0x0BFFBD1EDD8B67F7ULL,
		0x448691412CDE710DULL,
		0x88DDFAFDC8003936ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x820EEE11455176C2ULL,
		0xB3F7DA07A82AB2E3ULL,
		0xF8CF4EA8003D70B3ULL,
		0xD33668E7F5657B1DULL,
		0x3980534FCFBD2D51ULL,
		0xF896CE3DBC5DCE2DULL,
		0x5CEB231BF5FCCDACULL,
		0xA540A905AC8AC440ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x81F4ACC92BD85A77ULL,
		0xE5F86912EAD3C831ULL,
		0x8E28A5C1671F24DDULL,
		0x6032B4E811A3E75DULL,
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
		0x2BDFF59280F529B0ULL,
		0x4A276389AE12B126ULL,
		0xED487C9F73E64B58ULL,
		0x787628B4277E1696ULL,
		0x4B660C428471C554ULL,
		0x7406A40B0DAFB4FBULL,
		0xF2CAAE15D3A83279ULL,
		0x96F5381F367DE33EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAB13436B4319430FULL,
		0x3DA61890B7865575ULL,
		0xD095428170993EA5ULL,
		0xFCAA90FF52C1AE92ULL,
		0xC6F2BC1BAD2D7BBBULL,
		0xDA89CCDF2AFE4E53ULL,
		0xAA7CD1F7868FB3D6ULL,
		0xF9A52D758A72F190ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x29EA97EB31FED10AULL,
		0xD5093B7C9CE1988EULL,
		0xD841E69D74EFD8D5ULL,
		0x55AD2CE45E5C47E2ULL,
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
		0x943FA0C6E881ECA9ULL,
		0x9CC990555EC9FBBEULL,
		0x5352E9439BC17798ULL,
		0xF1AFA7BCF370596FULL,
		0x0950F5306B4E3869ULL,
		0xFD634BCAF2A5C15FULL,
		0x9DB82763CCF63C4EULL,
		0xDCE4917EAC1A2327ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x954B8815B6629D6DULL,
		0x74D22C81B79E5959ULL,
		0x96C18A356FF9F576ULL,
		0x4737C57005F23F4CULL,
		0x550007AF3AE9082AULL,
		0x3E2190A30E3C9818ULL,
		0x6EF13CFD325E4E10ULL,
		0x5438A38041C566A0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC2F759DE61247BA1ULL,
		0x8BB92BBF8EC7C2E3ULL,
		0xAE182A491E54DF72ULL,
		0x73FD3610B6121633ULL,
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
		0xE8DB11563427243BULL,
		0x2D9A772AA805FB91ULL,
		0x54A57ED0F7B16209ULL,
		0x51950D4BC6095784ULL,
		0xDD8C5D23BB83D0C1ULL,
		0x9821E1A13AF105C5ULL,
		0xC48F4DD5BF432CE2ULL,
		0xD71C650D2E0FEF5EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x671DD10CF19DEF18ULL,
		0x79BB9E51449D69C4ULL,
		0x196C91CCFB4A5052ULL,
		0x2008E3E5EA9960D2ULL,
		0xA54973CEF8C359A8ULL,
		0x562274B0DA3B5E47ULL,
		0x3AE334537DC2DC3DULL,
		0xDE3D20BFA29DAB0EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDBABE2DE2B1AE2B3ULL,
		0x7FC90487BE5F6E89ULL,
		0xAAC4B659B5730A3EULL,
		0x22B04CE88E661AA6ULL,
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
		0xD3241F3DEC149B69ULL,
		0x8D41A30B4053DE86ULL,
		0x2A68B7CE460CAA0AULL,
		0x6EBE7231787755BDULL,
		0xBBFD99FBC8F806DAULL,
		0xBD001E87D35A3B8BULL,
		0xED3A817029E22B68ULL,
		0xBB77FA4D26131CA5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB9399572CD307F32ULL,
		0x754F445BBF44EC6FULL,
		0x0E2F0BA4A0A995A4ULL,
		0x2DC3F4C101CB5EE4ULL,
		0xD7CB23519BC49D67ULL,
		0x4895B8A94CC33E20ULL,
		0xCD74DCDBFB898C79ULL,
		0x172B3ABBA7CD3BFBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF968270DD485C6ECULL,
		0x5FBD7DB77B788FF4ULL,
		0xD3901A28868AABF1ULL,
		0x245EED09350B5019ULL,
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
		0x4A0871643582F8E5ULL,
		0x688B30C632C8CD87ULL,
		0xA29DF1ECCCACFE57ULL,
		0x239649DB9B4A7161ULL,
		0x2186B7B0B21044B6ULL,
		0x2D499358CC1E9002ULL,
		0x0691F2A6DB75B0A6ULL,
		0x7DAB515FCB46E1BFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2571375E25CA14B2ULL,
		0x2BC6F6FC803A43DFULL,
		0x719BEB25015DAC8EULL,
		0x7CD490D4F17CFA93ULL,
		0xA9FD467A9231B49FULL,
		0x75AF766795069E03ULL,
		0x1C3BA3E07B268858ULL,
		0x1ADB9FFD9E454A9CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE2FE080ECAC249B1ULL,
		0x7DA48597E01C756DULL,
		0xF9D1B83A170F4D52ULL,
		0x51960D995809E5FCULL,
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
		0xEC3327B57CD56DA3ULL,
		0x4A23AE2F4F633357ULL,
		0xF23A68E46B201903ULL,
		0x921CBD8A2677A7BCULL,
		0xB380D8305D169E68ULL,
		0x2B89C692BEDD8A87ULL,
		0x7D759CAC9DC9942DULL,
		0x6AF847896BC94E87ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3EB37181E8344D59ULL,
		0x4F2161FE08832566ULL,
		0x0F82CBF70919BB6CULL,
		0xB16277010147CE79ULL,
		0x0E973964059A5EB4ULL,
		0xB32EF8E4E05E0D86ULL,
		0x9951CAE6EAA48BA9ULL,
		0x0F1C55D33F09B87AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x282D488891129703ULL,
		0xD87CD4004DCC9C30ULL,
		0xC008C045F985A11AULL,
		0x03602793C9A01F2DULL,
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
		0xAC7A97B607B59972ULL,
		0x068E0B5132428F72ULL,
		0x6B97C794531FED2EULL,
		0xFE69755F7C27DA1AULL,
		0xEAB13B7BCDBEDB23ULL,
		0x19369AB95BE225BAULL,
		0x31BE167FE6780B6BULL,
		0x795C176FBAC81E83ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5513A9D5F23A185BULL,
		0xB05FC8121269CB70ULL,
		0x27A532671C58FD8AULL,
		0xA790BC15E34FBE68ULL,
		0x840D1B7051CE98DEULL,
		0xF2FD943948A3AD3BULL,
		0x105717908C08D719ULL,
		0xCE4068F9AD2AC7B6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x93C3AF947B25557AULL,
		0x02A53A41FB1EA6EBULL,
		0x393C6CB4A348B3AFULL,
		0x3CF49ECF9E32FE25ULL,
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
		0xBC25D88E87D6E5E1ULL,
		0xE81C8096455B1271ULL,
		0xB1F7DC083FA0B80EULL,
		0x3397DD1161F2BB3FULL,
		0xF45E7A33A3F81FA3ULL,
		0x92E0CB07FD2F4027ULL,
		0x8D9981CBEC377896ULL,
		0x5615306B4ACD250DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8174859B6CD3FB9CULL,
		0x12EB20F6609A0C38ULL,
		0x96B1D7C9133C812FULL,
		0x8E9154ECE37D0291ULL,
		0x11D339FBC5009CA1ULL,
		0x18F5A5D608051016ULL,
		0x1D0386B50416632FULL,
		0x702C89FC22280086ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDB5CDB3E33C05BE6ULL,
		0xEE18E50A490428E0ULL,
		0xD18949A5A14D643BULL,
		0x458F3CA486F924C8ULL,
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
		0xD4F9DAC4C2B3B0B4ULL,
		0x41D6C52963A14084ULL,
		0x6DB24697676C252CULL,
		0xB65954B882241422ULL,
		0x72522A96DFD92F45ULL,
		0xEF043C805140540BULL,
		0x1702E726F167659BULL,
		0x895CD54A88496FC8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x78C948F2193C6688ULL,
		0xFFE1C243C28E5BCAULL,
		0x59EE776518BBE935ULL,
		0xA3EDB99EEA556259ULL,
		0x1AAA197FE932C756ULL,
		0x08B2FF4241841FF8ULL,
		0x87B469E3EE8F059EULL,
		0x47D369043FAEE669ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5F231B3B462AB90FULL,
		0x72041A1BF7029F99ULL,
		0x596A6724BACE7BA6ULL,
		0x4CD1AD885EBF15D2ULL,
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
		0xB7BF15566BC099DAULL,
		0x525F1BB474B05692ULL,
		0x484D4A94DF83E58CULL,
		0x55BC1A7E43849D03ULL,
		0xC3386A5D7B26DCA1ULL,
		0x5F7E86F05E4953C0ULL,
		0xF45E27091DB5020CULL,
		0xA0E7A83396C186D7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4843EEE79DBF2E0BULL,
		0xE0C40C7560E4F87AULL,
		0xFCD65FDB766026E6ULL,
		0x8E99D72D64FDDC6FULL,
		0x1AD60C851FFC7782ULL,
		0x82FE31395ABCC3BBULL,
		0x2C66F745C440CAA7ULL,
		0x1A45598DC19E1AFFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6E15148C564C714EULL,
		0x2CA7C8699AA8BEEFULL,
		0xFA2801B8B063F79EULL,
		0x4339EFEE81C8C2C0ULL,
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
		0xCD4DC8AE99B41256ULL,
		0x4CEF60367929D76CULL,
		0x3448D33112BB41AFULL,
		0xA8E3B1024B8118E1ULL,
		0xBF7C2C3AD4602648ULL,
		0x16A8978CDC88E42BULL,
		0x7D9F4A530DF3519BULL,
		0xCA0DAED593980868ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6190032EAE121698ULL,
		0x7E90BE0284C04BE9ULL,
		0xA3FC35877D101353ULL,
		0x95333D84F3472309ULL,
		0x6340FA340626F8F2ULL,
		0xC5163059ABF4A985ULL,
		0x26D498C8CF93C02AULL,
		0x7EFA1881C93342B2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1C873282881EB824ULL,
		0xEA19F3CD2A6A4035ULL,
		0x7262F82ED7DAC507ULL,
		0x3898C3ED632F4EE8ULL,
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
		0x65C4B4832BB5DB2AULL,
		0xFD7D0B98FECF82A3ULL,
		0x6264D30F1856952FULL,
		0xD4A524C12D0C9DF3ULL,
		0xC2F57F20CB363EACULL,
		0x964FEA951E794CB6ULL,
		0x72B1F2D3EF6C16F8ULL,
		0x2870C224BC65CC14ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA8DBDDDD331BEA3CULL,
		0xD22A656B67D64769ULL,
		0x02DB860E9D5B7FC2ULL,
		0x63F7FAEFA78A73E0ULL,
		0xABED77B748740DD0ULL,
		0x7D444A251B49ED46ULL,
		0x3CDB70FB97B4F530ULL,
		0xB281BB113B1D72E5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2819F04F616D2E8BULL,
		0xE30C76CE100165DDULL,
		0x5D60931D802A1920ULL,
		0x722836B6B63F6715ULL,
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
		0x31AEA6F37CB880F9ULL,
		0xAADE5D73F6B4C98AULL,
		0x603324550A11482EULL,
		0x69AF3F7A4FD81549ULL,
		0xE4864B9567A04003ULL,
		0xD345CC596591FBDEULL,
		0x65E8A99543898665ULL,
		0x3076F05D7F7A2E59ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x507368A310B3C401ULL,
		0x1F53DA7B43BBBB7AULL,
		0xFC0460862A44E774ULL,
		0x0A1EBE6ED34AC5D1ULL,
		0x7E639E7E86BE549EULL,
		0x3C69D273F23E7260ULL,
		0x8A59A4941C6A36D6ULL,
		0x0F1378BC915CCC98ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0A60EFB5CD8DAEB4ULL,
		0xF0319B07D15F76D3ULL,
		0xFB6981FAAE72300AULL,
		0x545442EED4E9D217ULL,
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
		0x2EDEB54742F5B1B7ULL,
		0x861C13C9B1BE6C3DULL,
		0x53957F9FAAFDE435ULL,
		0x70E7A8C4241B64EAULL,
		0x48FB0FE89174E18BULL,
		0x0333AE5D29994F0BULL,
		0x04693C5762575C7DULL,
		0xBCEC345BD7B1F269ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7713826FCC56ADA3ULL,
		0x7C355D7EA2F24E1AULL,
		0x17220955CB9B53B9ULL,
		0x1788C7F27A25004DULL,
		0x28B29133AFFDA005ULL,
		0xEAC51F14D0F199BBULL,
		0x1C133013D2E60119ULL,
		0x2904B2928416B6D4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x828E01B0EE52C13CULL,
		0xAA4FFB0837B10807ULL,
		0xB93948512A362131ULL,
		0x4DBC24B413013CB7ULL,
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
		0x30FC5D0629073573ULL,
		0xCEBA75E07829AEE0ULL,
		0x7B9A7BC0EB82845FULL,
		0xF71987BD6F656C19ULL,
		0xE39C5087F96CA2B9ULL,
		0xCD2D321692815BBAULL,
		0x546866F02405DB8EULL,
		0x20B00E7827A9D3AEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDCA55CEA2E787707ULL,
		0x1A36C751F59FA776ULL,
		0x332AD61BD6583A0DULL,
		0xC2EBB1909DABF12FULL,
		0x52FE509DF622CF2AULL,
		0xCFD3E737ADCB4C26ULL,
		0xC528005DBA68C81AULL,
		0x5A7FE7581E2015D4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCBCAFCD877842463ULL,
		0x4FC4CBA475905776ULL,
		0x8BFEDF60C27B2D8AULL,
		0x1F53A4EE3C2BA935ULL,
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
		0xDD07BF2B9F0F5768ULL,
		0x8A0687307576AFF2ULL,
		0x73A35E31E378513EULL,
		0x11A1F5E5AF8FE7C9ULL,
		0x5B6204CC8630EE76ULL,
		0xF77E7155C5BEDC67ULL,
		0xEB8E23943AC485EBULL,
		0xCA96439C558117AFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x60FFF79DD64C30F1ULL,
		0xE8AA251F13FB1A65ULL,
		0x728E6D999772D1E7ULL,
		0xC1701255CA60A464ULL,
		0x525D4AD431698EE5ULL,
		0xF9CCBC3FAE26A1E1ULL,
		0x42099443BDBEF744ULL,
		0x2497A817EB0AE891ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD2BB626A5E5B597AULL,
		0x49BD4358E2144572ULL,
		0x2AC2368ADAD8AC20ULL,
		0x73FCF937B2BA41F2ULL,
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
		0x0AB3C273401B62BBULL,
		0x16EA7E5608ED2446ULL,
		0xFDDDCF7748517D9EULL,
		0x428F95EDD1CF1458ULL,
		0xDBA10FC1BF6B3238ULL,
		0xFEBFBF5151D8876AULL,
		0xFA0CA499512612D8ULL,
		0x8D656CE2288B5C99ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9FAA808B26539D30ULL,
		0x9F303B3F811C01FAULL,
		0x2D7DB5C69E982C76ULL,
		0x722F60B1F3B8A9DCULL,
		0x071EC23BB5D03710ULL,
		0xF6F5BF06C9F34DA3ULL,
		0x9E3B68B75B9B8FCFULL,
		0xFE257E5D862FC1D1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF660C3CD86C90AF5ULL,
		0x9FB64E26B3D7B5F4ULL,
		0x716EFD3B1C48C47EULL,
		0x13DD9CEBF7AF643AULL,
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
		0xE698B6A681538049ULL,
		0xE4BE9E5A8FBA2A48ULL,
		0x5903126AA173258DULL,
		0xB787A50799A25E67ULL,
		0xCAF4DC41B0CB5CACULL,
		0x1469F6C4AD3E1144ULL,
		0x8DF90E605AA68CBBULL,
		0x8BFD04A361AB6A03ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7AC66E6F0D505604ULL,
		0xF949026B54E5F7D9ULL,
		0x71DE17E7E7E54504ULL,
		0x49DF5B48E4167A09ULL,
		0x35385C4E27270492ULL,
		0xF7B6F6863ACAFFBEULL,
		0x04E7B7BBB6EDA7CAULL,
		0x1296948674006D74ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA5CD465DE26840CDULL,
		0x2E07A53437E8CC69ULL,
		0x3FB7D6F306FFDC2DULL,
		0x72DCEE09FCED61ACULL,
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
		0x7D0880C34195DC76ULL,
		0x42100B65F6055766ULL,
		0xA61E063913AC52BCULL,
		0xA98FDC26B3174CB8ULL,
		0x0A656EEAF38FBECCULL,
		0x87A7894F502B75D8ULL,
		0x3C303CB2FF0C46BAULL,
		0x38864BE9CA6AFB86ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF9233A805FEB3D82ULL,
		0x3570A57A4E5AC672ULL,
		0xB08C0B71DE756D3BULL,
		0x98769B900A0CEE17ULL,
		0x8BFAD5F626856D15ULL,
		0xD3C51AA1C48A5480ULL,
		0x24997FE0020605FDULL,
		0xCF71354A9AF77A65ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x47B7FA995132BCC7ULL,
		0xC03BD3AE619583F0ULL,
		0x75F20218C4248183ULL,
		0x2A3A9C37B42F898AULL,
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
		0x0B15FF9AB9121240ULL,
		0x0A14DD4579BE4E23ULL,
		0x3B809DAC2DAAC836ULL,
		0xB8B8C65BA800AE18ULL,
		0xC11D5FAC0CB87820ULL,
		0xB095CC2ECD586A4BULL,
		0xBCB137EE946BE5FEULL,
		0xE2D06BB51BD08B16ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3DA15B3EA83BC95AULL,
		0x666F6F6F2AF50E7DULL,
		0x130905FBE779E28EULL,
		0x17D3DF7C955F3EA5ULL,
		0x149E9EA55C59431CULL,
		0xFF0E4D7B61686DFFULL,
		0xB51A9CB97B580AEAULL,
		0xD0DEFC5FADF6C50CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x68454B5A3EF827F0ULL,
		0xFDC23C785468B307ULL,
		0x48D2A191FF236A93ULL,
		0x4ABB6D8D60F4D4F0ULL,
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
		0x4638E00BCFBC9DB3ULL,
		0x64D929BD2B6C261FULL,
		0x45B484AEB52AD4A1ULL,
		0x0BD08D4FF751D879ULL,
		0x69CD6CE9172F61A2ULL,
		0xA519CDA3098C76E0ULL,
		0x7186A4C3BEF717DFULL,
		0xD5079AADDBEC54E4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x76E62D3A34F6A2D4ULL,
		0xD6398EC5C4F1882FULL,
		0x1DA9CA9C2765AD79ULL,
		0xF4C861B0C0B23F3DULL,
		0xE538A4F18924D92FULL,
		0x4FCF363935DD51AEULL,
		0x0766800E1BE869EAULL,
		0xF1CD99A0D1C67337ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7D686190B0563B20ULL,
		0x37B214ACD27A2349ULL,
		0xE8D02D08C1F2F992ULL,
		0x51A4538EB83F18F9ULL,
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
		0x29AB5F2D5BDA53CBULL,
		0xBE6E12A4C35708D5ULL,
		0x6156BBA7969FE21CULL,
		0xB6C23447EFBC9ABFULL,
		0xE0A392AAC873478DULL,
		0x892D4B638C7B3E30ULL,
		0x99C0230BE0F4B3BDULL,
		0x2C4FD4CC44F7BFEEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAC38A8CB958F9B39ULL,
		0x46044EE35C79EB25ULL,
		0x0CC22BA229565D63ULL,
		0x5633CD472D20DACAULL,
		0xC65ACB66B16106E0ULL,
		0x23D0E2062DE321C6ULL,
		0xFE59BFECF05EFBCEULL,
		0x845C86A1D6A22CC7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x64404A7D33005052ULL,
		0x8421679D7171556FULL,
		0x65C7469D2382D242ULL,
		0x4EAC014D234F97B0ULL,
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
		0x808B4386876B3121ULL,
		0xC79783479BC8EFA3ULL,
		0xA7B2FE30086B5132ULL,
		0xA4B59701C1CE6CB8ULL,
		0x7EBFA2E849BF0DB1ULL,
		0xD578EA42472C9CDAULL,
		0x60F07CA006F1961DULL,
		0xCEEFF1D7FD64B44BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDCF12373F6234C05ULL,
		0xF2D7F11AD742B004ULL,
		0x67F51FFF86E4C5B1ULL,
		0xB537FA04321242FEULL,
		0x65CD28286CC625C0ULL,
		0x258B0A1C2D99604CULL,
		0xE320853992B0FF39ULL,
		0x7DEE29A635F34178ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5798588D5E3A5497ULL,
		0xF20ED7D490613CB6ULL,
		0xEC9C9765C31CF172ULL,
		0x75C154612A9334F8ULL,
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
		0x84E5FF350C2DC21DULL,
		0x6814D7FFFBAA735CULL,
		0x657860A188774F15ULL,
		0x937BA6563B9DC693ULL,
		0xC828C0A9EA479C49ULL,
		0x1DEBC715BBD65FFDULL,
		0x6CA9D47B3BC7F4D2ULL,
		0xE576044E10B4672BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x13C25F9141FE175FULL,
		0xC1A54A3AA893C9EDULL,
		0xC6DAA25B778626E5ULL,
		0xA459CF163E267E65ULL,
		0x4491619DB3A74C91ULL,
		0xC41ED49E34E9BD85ULL,
		0xBA3EB42EFE2E4576ULL,
		0xDA5304145FA71F08ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF99BBB73E5FB8047ULL,
		0xFADB8B835A36C752ULL,
		0x1A84899735C12FBEULL,
		0x1653DFD0456FFD54ULL,
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
		0x668E9C5153C1C448ULL,
		0x04FB630F5EFADC65ULL,
		0xAD057081502AC522ULL,
		0xD28000F170DEA4F2ULL,
		0xCF5C93B0F9617879ULL,
		0x5CDC28A10C54AA3CULL,
		0xF58005E4AFA7FBABULL,
		0xB9A928B3DB69AC28ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x356C3BFC53D16EBFULL,
		0xC5A8351F09B826E8ULL,
		0x63FBD007DC0B7569ULL,
		0xEAD56B9E957C34A0ULL,
		0x7AC3166DD28DA412ULL,
		0xDEB69699FDBA5920ULL,
		0x832B46BCD8112FF5ULL,
		0xF3EAD821D91A6B3FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBFEAF84CC361DB7DULL,
		0xF8E6DAFC802ABFB1ULL,
		0x419E006374818CA8ULL,
		0x41EA8AFF332612F9ULL,
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
		0x90889675033D201BULL,
		0xD5E4B8366B5B3E6EULL,
		0xF51CB8B4ED26E503ULL,
		0x3E8F029D0CB09468ULL,
		0x120BEF3E4D68648DULL,
		0x69FD80D0586E76C0ULL,
		0x8C24204E65147AA6ULL,
		0x1306617E533C9263ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFD9BCF0B9E08B721ULL,
		0xEB61615D2537757CULL,
		0xB932A8A8724E8AA3ULL,
		0x1586EFA851770859ULL,
		0xABA25A14FBB9CC97ULL,
		0xAF039E074A7ADC69ULL,
		0x05F25086AF340084ULL,
		0x6BB618BB986D40D7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC698EB8B851EF57DULL,
		0xAB9B00B1584CB1C4ULL,
		0x274EE7B17A2A7B61ULL,
		0x7EF2DFDC75FFA6EBULL,
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
		0x551E03A3E90943C5ULL,
		0xD3A685EA1CF7D2E9ULL,
		0x7442578863BC19F7ULL,
		0x84C6AD7B63D0D18CULL,
		0xA5AF163A3DD83DC3ULL,
		0x2F47FB5B750AD5BDULL,
		0x5D42053310087622ULL,
		0x6AA2680FC52051FEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x49A477D8C9FA90BFULL,
		0xF92D2A25764FC2D3ULL,
		0xEAF41F1C22F79991ULL,
		0x4598A4D82ABE3CE8ULL,
		0xA2C400BC7220A26AULL,
		0xCCBE8228A6F4C92AULL,
		0xE873B9E6CB537140ULL,
		0x92B9E8C698E26ABEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7A5EBC775C4FC158ULL,
		0x7AE1594F3DEDEDE8ULL,
		0xDFED65BE73A339DAULL,
		0x4BB0ED7FCA42E80EULL,
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
		0x5A76F76390F1B6A0ULL,
		0x45A5508C70BD8228ULL,
		0x4F91B387A3D6CC4BULL,
		0x9A3F049D5089CF0DULL,
		0xC899AE09A7B66329ULL,
		0x8BFC7F03DB7DE518ULL,
		0xE0049CCD1BC9EDD2ULL,
		0x9C0ADB6CE04ACBCCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x08B8004E1323E25EULL,
		0xC7279D9BE3CE7DF8ULL,
		0xDD839CE6905EB3E0ULL,
		0x8DEF0742E34E768FULL,
		0xE75E222B04D7020BULL,
		0xF1EACE3454CDEF18ULL,
		0x3708563F96E725BCULL,
		0x940F6BB0614C2357ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC095BA21AAF63EDCULL,
		0x5D1DF1BE8B0D882BULL,
		0x87808FA2CD21CB9FULL,
		0x3BA29355470859F4ULL,
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
		0xC1033AF2E322227FULL,
		0x6F69CDAAF0632BD6ULL,
		0x13C974DD9316D1C4ULL,
		0x606730E694A1A9E5ULL,
		0xC6C70624E933165DULL,
		0xB6A3EA67F8F7D5B4ULL,
		0xFD6E36344CBD4963ULL,
		0xD8EB61E607F53DE4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDAC8D03E21264867ULL,
		0x23F746910B2DE70CULL,
		0x47E1D3B2586D385DULL,
		0x0E7D2D9D88C41E9BULL,
		0xF4C78F5310BFD07DULL,
		0xEA343F8C8F7DDA43ULL,
		0x50FA96F3EFB2C993ULL,
		0x2C95C40719DCF949ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x12260DDAE3183D21ULL,
		0xA405E3AB8D509789ULL,
		0x651144B90A38923FULL,
		0x669F72606377BA65ULL,
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
		0xA3B071624DA770A8ULL,
		0x8A14724159A06FB5ULL,
		0xFE159535AC014153ULL,
		0x039856B0CD8B7B45ULL,
		0x5BAD65AABE5FF153ULL,
		0x94C00AF5443BC661ULL,
		0xFE5D83CAAD3BFD27ULL,
		0x3EE87B8F3D453AC3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8A14D1CDB741E9F2ULL,
		0xF3695ADEC4192BACULL,
		0x73903C70BB28A81DULL,
		0x6A477678544859A0ULL,
		0xD3E1A60FABFDA106ULL,
		0xCC51681FB802B9DAULL,
		0xBA267264EA9FEC66ULL,
		0x13A151BA747D1083ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x41DA109950FD7308ULL,
		0x5717431565FF2001ULL,
		0xAAB1EDDFD40315D3ULL,
		0x05E115CE46F9672FULL,
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
		0x25AD644343352550ULL,
		0x75FAFFA38660FB5FULL,
		0xD120575BA81DA6B7ULL,
		0xB8824355FC374E93ULL,
		0x2CD40BB402D13139ULL,
		0xD0D0CFC2D77DF2D9ULL,
		0x66353833E17FFF02ULL,
		0x054C42535543BB60ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x957DDCD144822141ULL,
		0x05A6D61D203E6BF6ULL,
		0xD59664BDEE20B5EBULL,
		0xD8873355695045BAULL,
		0xD508A93A509F6544ULL,
		0x02D4CBD5C9857262ULL,
		0x86FA01C7ADAE912DULL,
		0xDEF857F7D410B881ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x986025827217459AULL,
		0x03BCBEB67905A0F9ULL,
		0x1E5406AD6B133E89ULL,
		0x106FD995C07975EEULL,
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
		0x837CF739271CE51AULL,
		0xF454B1AEDDF6754DULL,
		0xE6720A8FE07752B3ULL,
		0x5F339842806B62EBULL,
		0xFAE2C3FE51E0B01EULL,
		0xFEA604A63DA099CAULL,
		0xB117E6B4658257A1ULL,
		0x10231B283790B5EAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC7C52D9970C155F8ULL,
		0x90BBD3B09D6F6B60ULL,
		0x53AEEBBB45EB8DB1ULL,
		0xFD3EDC5826742E69ULL,
		0x10671D72E48A30C8ULL,
		0x670043F2A6EA719CULL,
		0x9071CE1831E99059ULL,
		0x397E0BB18437EE19ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8A128251F13274DCULL,
		0xE63378A69F9100E3ULL,
		0x6B6AC604433959C8ULL,
		0x3E750788F924DD8DULL,
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
		0x4158FDE535EDD892ULL,
		0xA40C2665CC9870EAULL,
		0x2A16367C326E0586ULL,
		0xE96A6781F9F6204FULL,
		0x82C35C0A20F434BDULL,
		0x26EC178A34064382ULL,
		0x839B259ABFD8D282ULL,
		0x46993709A27586C7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD63F878AA54A9C24ULL,
		0x66A39B8750417908ULL,
		0x939197239F98EBFFULL,
		0x01B18137AB086330ULL,
		0x862D3330C82F9ACDULL,
		0x14326D01750EF1CBULL,
		0x85BB4D1B271A4395ULL,
		0xF15FA08CCB7FD2A8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE963869DBDD2126BULL,
		0x04F7DB2AD50D190AULL,
		0x45BEC2493F1E50B8ULL,
		0x0E453CD2376679B8ULL,
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
		0x97FD59E0342E0EADULL,
		0xC7965844F67F7779ULL,
		0xBBD64543F2BFFC0CULL,
		0x6583744C0C5ED71CULL,
		0x62E346C344E473EEULL,
		0xFD1B7F23E01ABA97ULL,
		0x4A8DC5F4BDEC3B28ULL,
		0xD0DA4046951C482DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x54F3403661384EF1ULL,
		0x186B230D12264489ULL,
		0x72D5081508B01C8EULL,
		0x6E84293542D7E526ULL,
		0xA13F304CB1B7F0B5ULL,
		0xA67B7FFB31849978ULL,
		0x568CDC5FFF98569EULL,
		0xC651480CD6E39295ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x01656F43AB913A6BULL,
		0x8AEB1541CEA21D81ULL,
		0x8123E9432A83CC07ULL,
		0x075423A905F1E684ULL,
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
		0x209BADE85CC4A4A3ULL,
		0x9BBBF77F8FB82F21ULL,
		0x1C569639B2EA6125ULL,
		0x2A986A80EBAF2652ULL,
		0x1C6EEFD75DA948D1ULL,
		0xA08A31A699912B9EULL,
		0x9960E9B1BACF1A9EULL,
		0x1EBE5C1AAD850AF7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x28AF7C2BFFF292CCULL,
		0x692265672485EBD7ULL,
		0xDF6C490C7ADDA9FBULL,
		0xFB08B24820E61DEDULL,
		0x00B4ADBC9E20554DULL,
		0xE2D32AA79B25D17CULL,
		0xA76C43573A466416ULL,
		0x7A1E91FA14BA76F5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x159201B4CB263548ULL,
		0x5BC49BF22F21A45AULL,
		0x273AFE9C4C57CF50ULL,
		0x1F47B90F78DB00AEULL,
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
		0xEE5F8B1EC52A20AFULL,
		0x637F54B505CD2D1AULL,
		0x1A46672184985F89ULL,
		0xF678D14916C9E286ULL,
		0x768F19138C32198BULL,
		0x640671C57C3FB29FULL,
		0x6D09786BFDC3DAC5ULL,
		0x210DE61149044997ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x159E970037EAF13AULL,
		0x47FB53DCDBA2F08BULL,
		0xBB1A73D45781DE25ULL,
		0x12B509D36C59C65DULL,
		0xAD9ACE0B82231616ULL,
		0x2F80D8BA556813EEULL,
		0xDAC468B0F03812A8ULL,
		0xBC023E2D5DF8F962ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAD0417500B79AF7CULL,
		0xE758B87FEE2BCACDULL,
		0x156C49112FD635B9ULL,
		0x637EB34A8E1E03F6ULL,
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
		0xA3778A7D41086C36ULL,
		0xFBDD2CDE86F4296FULL,
		0x00107FC07A089C00ULL,
		0x2BEA749B904A1302ULL,
		0x198DA46BAD884865ULL,
		0xB520575806394F0CULL,
		0x13D83734E63E8112ULL,
		0xB62F0EAC7E6030FEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8F6B7B1B54AC7BBFULL,
		0xCC5E259D559D9AE1ULL,
		0x960B22EFE55D408AULL,
		0xBCA834323271976BULL,
		0x8F0552B6397AB1FDULL,
		0x3CD7180C9736C54BULL,
		0xA1C8EB95AD526AACULL,
		0xFAB4438DE33D30A3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA448305126604245ULL,
		0x0A5E6C73ABB70122ULL,
		0x584A967307B6AEACULL,
		0x437C66F4650A8903ULL,
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
		0x0907C6AD53A045EAULL,
		0xE3F0AE5F09843026ULL,
		0xC0F28A7D476BC873ULL,
		0x54506BC9C845CCDAULL,
		0xF274A1CCBBAC2578ULL,
		0x3D0E12FFBCBB5F2EULL,
		0x3B60ECE4257FF21FULL,
		0x57DB106262FC56D1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD6ADE2611724FEBEULL,
		0x6886E1E263F9DB07ULL,
		0x17A73E27FD85BCB0ULL,
		0xED81889D7A57D6CAULL,
		0x1B3648036E7515F5ULL,
		0x9E1F16180187F8C6ULL,
		0x480F738E8AFA1FD0ULL,
		0x90DD174D88A06EE5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x259B382DB2A79335ULL,
		0x12E356E26F2B88AEULL,
		0xC7634F0A39C3436FULL,
		0x7081DC44B7926316ULL,
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
		0xCDBCAD181D4C4007ULL,
		0xA2D295F35B2B2B10ULL,
		0x54F704473A769E52ULL,
		0x8487019C13E497C4ULL,
		0x7051D1FDB4A0F0F6ULL,
		0x7C66E4C124DF0591ULL,
		0x57EACC7D5258B67AULL,
		0x481F968D5B6B8B1EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x53DE95DF41FA51E0ULL,
		0x1BA97B8C7F2B1F0AULL,
		0x4A4B18A5F52C3985ULL,
		0x057B34DB5FC0A914ULL,
		0x5840AD6368CDDF1FULL,
		0xB23EFC170783E77BULL,
		0x7ECFACAD554DB0D9ULL,
		0x51412CD9B0603FEAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0C6986201CA693EBULL,
		0x8915A3A73786834EULL,
		0x44B2A480D4ED3AABULL,
		0x240F7D6C17D11862ULL,
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
		0x987D5B6B96F47012ULL,
		0xED6757181BEC856FULL,
		0xD05E53EB515FC071ULL,
		0x278D7F3247F80695ULL,
		0x09ECBA92D4832498ULL,
		0x76CAF36524D694FBULL,
		0xD8C4E683AD8352E5ULL,
		0xE7BE53FC833142C9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8F677FA88C961FDBULL,
		0xA7926DEEC7025AA3ULL,
		0x2E6F085C0FA5ABCDULL,
		0xBA18BDA2470D98F1ULL,
		0x66B66ADE3D1B234CULL,
		0x87960D92132C6EA2ULL,
		0x50B5EC6A663C7FE5ULL,
		0x1AEB435DC92AF4B1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4325B09183CE85E0ULL,
		0xC7AF067DF42BDBF4ULL,
		0xD4286B4FD63D66A1ULL,
		0x54C9391F9DDA0548ULL,
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
		0x2AE687CE4FBFB252ULL,
		0x2C8CF2D53E313E32ULL,
		0xB5B00442F266DBFDULL,
		0xF8C90FEBD20786A8ULL,
		0x898E4C444792AC04ULL,
		0x2406185EA494A66CULL,
		0xDFBF1214300A921BULL,
		0xF784666C9A26358CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEE3DCAE51C06DE7CULL,
		0xC8ABCB8808ADD04DULL,
		0xC0DC749FC58C4910ULL,
		0xEAA20FCBA8E55E15ULL,
		0xB2291E0EDF56D6B4ULL,
		0x1B402A81ED97202CULL,
		0x553943FE108B625CULL,
		0x4C2E64970F83EFAAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x35AD98D6AC9A816CULL,
		0xB14276105F255B5EULL,
		0x84B026EBD9BBA947ULL,
		0x7CEB45D2BD388833ULL,
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
		0x8A268230BA91F7FAULL,
		0x552515896796C205ULL,
		0x05FFD0B8579B55A8ULL,
		0x18F327B640EFE846ULL,
		0x0F3672E2D06A3107ULL,
		0xA78D94BD14A1F9BEULL,
		0x1A1B7E0B46B9F096ULL,
		0x4E016659CDF914A1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB3D8C8C10F13C1B6ULL,
		0xA2C0B15D9A3259A1ULL,
		0x5D90CB37AC6496BEULL,
		0xA1FD655C8CCC5F43ULL,
		0x63462FCDC0C8E186ULL,
		0x07CF25EFB78B8BE6ULL,
		0xD7F1C3402FE9B125ULL,
		0xAEE6B8B8B782128CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5BF7AE8FFD700130ULL,
		0x68A8D6A79EB8B667ULL,
		0x7AA0BFA60E2029C7ULL,
		0x14EB884309CDD804ULL,
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
		0x51865050D64DE4F8ULL,
		0x34FFBB9734A62D43ULL,
		0x3A8DCC3E3272EADDULL,
		0xF05D4180F9DB3CB1ULL,
		0x86C0EED85AFC9B62ULL,
		0x1AEAC1FECB780236ULL,
		0xA7552347CA8EE1E2ULL,
		0x0AA0421626CBBA11ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x533604402C48863DULL,
		0x5E431DD4B841DA3FULL,
		0x62C4F2A1D755C68DULL,
		0xE43615A44DD6B013ULL,
		0xA1B558EB915608D6ULL,
		0x2DBD3D6915A9D1E3ULL,
		0xE46B4FAD62E86E3FULL,
		0x5BD0A68BDF7A4B84ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFE088D3698BF1DA8ULL,
		0x0B7E4BFB78FF7F51ULL,
		0xC67E4287BDD24E7FULL,
		0x7EF84263421AF582ULL,
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
		0xEC2174B04030CEB4ULL,
		0x2ED7FE0ACC9EABE3ULL,
		0xC3D9AC9BD10C531CULL,
		0x734F326DD9560235ULL,
		0xFDEC08BD696CD183ULL,
		0xE9B7AC1D217940B3ULL,
		0xC9DF358CE88F0872ULL,
		0x18DA7AF796B9E6FEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2DC3153B65D4C187ULL,
		0x8B096CC27ED6A1CAULL,
		0x6D79D9FAB7C3A8D1ULL,
		0x5BE5E4741F9DEA4CULL,
		0xB1FE5E15A0D446ABULL,
		0x75595A54462EA591ULL,
		0xCD4BF7642AF64688ULL,
		0xBC6F364FF927BE5CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x03A5B45CA100A59AULL,
		0xE9CEB518DADB1131ULL,
		0xD43B0CAD3DF57317ULL,
		0x4F557EDB1D6A1FF4ULL,
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
		0x4707FF270A80069DULL,
		0x1AFA1B002CEA9C29ULL,
		0x11C8B64362642449ULL,
		0xBB29337B76D24B42ULL,
		0x2541D53C333C27A0ULL,
		0x521D1AE596A646EEULL,
		0xA8B808D2A53C1AA5ULL,
		0xCB4BB9B12BB0A4B4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD8EDC6090FCE586DULL,
		0x80DA71ADFACDD909ULL,
		0x4F80CABB5367DD2AULL,
		0x57DB2D45EA99DF33ULL,
		0x3C0336BBB4258E19ULL,
		0x7B8779B85A3461E7ULL,
		0x029F471F4EEAF85EULL,
		0x53BE6910FB617058ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0D65C030D80C7AE6ULL,
		0x745596092B04C226ULL,
		0x69F4AC26DF075DA2ULL,
		0x2247FDFCB7FA31CFULL,
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
		0x84B5FFB89FFC524DULL,
		0x0B50D7D1965EFA6FULL,
		0xE51B8B9EB52B1C06ULL,
		0x68199AFCD31439EFULL,
		0x2D06E2C7381CCF4AULL,
		0x4220A8B2A1CF83EDULL,
		0x7AC090708944BBC5ULL,
		0x713096EAC278DFEDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA89D28091C4339ACULL,
		0x9020211AF4A354AAULL,
		0xE6FD01C341C6455CULL,
		0x9D72E2C144203ACBULL,
		0xD50527537A02FF5FULL,
		0x3ED1FB880810EF44ULL,
		0x17E92BF3AA31A00EULL,
		0x49A7238A4B96F2EEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEC5AAADDBB8DF654ULL,
		0xF8DE6B097405B6C1ULL,
		0xAA177464903AF3D3ULL,
		0x290DD88D347D2D0CULL,
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
		0x23F5A4AFF329F14CULL,
		0x89B1231C679EB2D9ULL,
		0xB1FD50413CB8FD83ULL,
		0x791DAD9048699C4DULL,
		0xB1489BFB62B89F5DULL,
		0x4787C493D2B4AE76ULL,
		0x43DB5FB2D0013194ULL,
		0x64EE8CF0993BE3E4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFF14B3034132CD81ULL,
		0xC5B8524F6A5D8936ULL,
		0x1D2DE87F904045D9ULL,
		0x90D59873A749F851ULL,
		0xAD75CF050C50E704ULL,
		0x9DC5B6EBBC563A86ULL,
		0x10C46237FC32FA50ULL,
		0x9BF74315E5F7A7F4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB62B5E3D855C7FBEULL,
		0xF6C6D7C04F465F42ULL,
		0x2A3907FD1D14EBB4ULL,
		0x3CFD0B933D4089A4ULL,
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
		0x1A0D823D18E9E74DULL,
		0x14C267FF41094245ULL,
		0x020903127DFC264BULL,
		0x7A5FE0A530EF4B91ULL,
		0x0D94B1D0D137B8D4ULL,
		0xD9782AFC3B5A82E1ULL,
		0x6C39C8C544A2DAF8ULL,
		0x6CE350F3D2685B15ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x09E6EB1B6AC89690ULL,
		0x10B212D832937558ULL,
		0xE469E913E8905A99ULL,
		0xFE83F59BFD774F40ULL,
		0x290CCBEB708D5348ULL,
		0x9E8CAFAD9C2AA04EULL,
		0x49E466350BD2984EULL,
		0x56C95A5BC898C099ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFC52B72E076C63E4ULL,
		0xC304A2D2AF916EBAULL,
		0x364BBB670455B0F6ULL,
		0x43B6859AA848EABDULL,
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
		0xA94C653AA3542C23ULL,
		0x84EC7EC65246DD3BULL,
		0x50192C7ADE31B3D9ULL,
		0x0430BFEB4C598457ULL,
		0xC2C9844814E3C007ULL,
		0xCEC9A719F666AB9AULL,
		0x7530D3C5925DD0D7ULL,
		0x81D220ECFD2AF84CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFB89A5DA2DA83EA0ULL,
		0x4E55500EBEBD965DULL,
		0xA934D8B310CC195CULL,
		0x555FA3DB7959B910ULL,
		0xEBAF01A53FD9CF0CULL,
		0x3762DA518EBE282EULL,
		0x045D595A31C0054BULL,
		0xCCAEB62C90BE1769ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9BB2238C1525B110ULL,
		0xAFD99476F68CC8DFULL,
		0x66487FB824D1D15BULL,
		0x1212F49FEB292D09ULL,
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
		0xC7F4AB4424CBD62AULL,
		0x17948225E3DCCCBDULL,
		0x7773E2268CE4870BULL,
		0xC88A4DDFD6662D05ULL,
		0x6299F045A7A7EA86ULL,
		0xE22B4E770AA06733ULL,
		0x2AEE0CD46CFF3628ULL,
		0x173109036B6E23B6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3AA0C1A8F2061DCEULL,
		0xEE505CE39B5FD70EULL,
		0x5428E923BB75BE50ULL,
		0x078BFE75F3857D5FULL,
		0x7F86CBCD8B191D9FULL,
		0x0D44B93CC586C8FAULL,
		0x62A6173810455C81ULL,
		0x3EAE8C17F29CBE68ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x422B536F6FF821D5ULL,
		0xC37E4BE88A4A7221ULL,
		0xDDF96E38950517A3ULL,
		0x645CDA5DD1F5B931ULL,
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
		0x69D90B90AD0115F9ULL,
		0x7852BF5DE6B6BF68ULL,
		0x7AC2054A94D1E329ULL,
		0xF01C4E60AB1900C3ULL,
		0x564B747A9BEC3DE3ULL,
		0xC1C762439C17340BULL,
		0xC4E5AB1FAD0530FBULL,
		0xC081B41641CB8666ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC3410BD177200840ULL,
		0xB493BC48A3BE1EB3ULL,
		0x1AC8D0BC66267A8BULL,
		0x33C5172AD04BDC55ULL,
		0x2F8250D377FBF079ULL,
		0x613894B9CF6DBD11ULL,
		0xED120790DB7468C6ULL,
		0xD4237890E2556D4EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x68734A8E8B8C8B16ULL,
		0x18F18589A42049D6ULL,
		0x69637BC14A29208AULL,
		0x52540D020654DDF8ULL,
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
		0x0AC9DD33F3AB6EE8ULL,
		0x20B7D2B5A5607B0AULL,
		0xDEE5CE5062F908B9ULL,
		0xA8DB6A93E717E579ULL,
		0xE67C4AFA1ABE95A2ULL,
		0x022D187CA560C039ULL,
		0x9C9533A1E442117EULL,
		0xFB456AC6A2535D81ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x184A2DE533421435ULL,
		0x1DF1E8654B9912FFULL,
		0x94F8C11DA0D70F72ULL,
		0x73B83E148A910912ULL,
		0x4AF705E06A90846BULL,
		0x4EF69317AA24E42BULL,
		0x5860A2DF124BE297ULL,
		0x523D2D19C5A2CCA6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0847F11EE73FEC93ULL,
		0x9CDDB74DA4AA1236ULL,
		0x69BA8A1DECACEF85ULL,
		0x4C5C54281EBC5CF3ULL,
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
		0x795FA25B1AA66C1AULL,
		0x801617FB1D814701ULL,
		0x68B49DACFB3C6879ULL,
		0xC3E7E4569E6B93BBULL,
		0xA61172EA36613ADDULL,
		0x365FDD337A8B8B1EULL,
		0x039D6682B8544CE9ULL,
		0x5C3D338175417FC7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDF3B910700EEC07DULL,
		0x20CCDE1EC2D613CAULL,
		0xB26C0FDCB70EA2FFULL,
		0x0E5EA758E6E51674ULL,
		0xA4A947E1E3D5463DULL,
		0xBBA8F1DC41E999DCULL,
		0x0D5B556AF1B9655EULL,
		0x9BD08AE9ECB73C60ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCF9A74905A7DFA07ULL,
		0x967028CEC2B50302ULL,
		0x44171757BF2C2408ULL,
		0x45AA437BFC0C7E8FULL,
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
		0x571DD5CCE4DF2872ULL,
		0x2203E2D7FD4FF9FBULL,
		0x05B6C1131FAF09E9ULL,
		0x6DE533B85959FE25ULL,
		0x0A00775261B0C893ULL,
		0x51F52E7B64A1388DULL,
		0xC67C1192B1018217ULL,
		0xD3370C10261ED170ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBA1329C01ED83EDCULL,
		0x6CB8A5EC4FAF2AA8ULL,
		0x74BBD9DA7F0147D9ULL,
		0xE4756E80C8A5689BULL,
		0x53FF3F01BA0E5198ULL,
		0x0BA655AFF123EDCCULL,
		0xEB760F4C1BDFDD1BULL,
		0x3E65D05DCCB21765ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA1390805A8249609ULL,
		0x24FF6B1ED239E7EDULL,
		0x13DF3DB2C3AC3F82ULL,
		0x207EA1B0D6D83326ULL,
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
		0x8C6FA4201D0BDA44ULL,
		0x2F31B55457A52656ULL,
		0xF8CF13DEE3CC96E6ULL,
		0x74DD0C213B140ACFULL,
		0xD668C4AA02C2C4E1ULL,
		0x50E7AC235FEA4401ULL,
		0x92FBC5A4BF965C5FULL,
		0x1C9E9D45CFC815AEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBF0B3B70E901E4C6ULL,
		0xD86859E69486D05FULL,
		0x695D08787969ABE0ULL,
		0x0BF5AB8AFED94AE9ULL,
		0xBBF6EC28F60D969BULL,
		0x486E37A3CC2BFC53ULL,
		0x50CFCB1CDC17FA30ULL,
		0x3B320F5FE0E386D6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBA4A8BD716EED337ULL,
		0x98D0A65DB15CF9CEULL,
		0x61F93B922F257E00ULL,
		0x5F0470B7B227F400ULL,
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
		0x853E5D48B24DFD65ULL,
		0x1F1062D9CF7300EDULL,
		0x329F8E21FD88CF4BULL,
		0x7C42F0C3DA6E6710ULL,
		0x64D0A02F49E2F4BBULL,
		0x358CF68FEE8CB869ULL,
		0xD4ADD12657367B3EULL,
		0x1D5905654BCE32C7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCAB1100A2F1B3C1FULL,
		0x78639F5A2E24AA45ULL,
		0x768B2E919CA2F2F2ULL,
		0x06DE99D262BD890DULL,
		0x7D2F3FCCEBD2190EULL,
		0x29DE46CAAC4E71DEULL,
		0x06C54403063353A3ULL,
		0x57B10E9D3B33F45FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1C819BD879B35BB1ULL,
		0x629ADAC7768CCF46ULL,
		0x4C9952CE675DBD5CULL,
		0x4C52F8A3EE962191ULL,
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
		0xC823A70D5A5AF2FBULL,
		0xA1521EE2EE79955CULL,
		0xD5A351195BFFA3F9ULL,
		0xBB9B9DC591593F53ULL,
		0xAAA3B6BEBD23C080ULL,
		0x4CAA8CB9A47DB13EULL,
		0x88AA0FCE74B318B5ULL,
		0xB77F68C919F4D359ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x166AC15D5A731ECCULL,
		0xE721BC139C1EBD10ULL,
		0x2C27157537F47AD4ULL,
		0xEC5A3FDB904F694AULL,
		0x7540E4EEEBB32964ULL,
		0x3D149DBCECBBA767ULL,
		0x3DA3C8449594581EULL,
		0x29B05287461C4C20ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9E640A89169E4562ULL,
		0x0A71DC5299284E3EULL,
		0xCC6ADA1B429BBF91ULL,
		0x5BFEABAF732DE88AULL,
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
		0x82E3CA829F276674ULL,
		0xE8C7912012A87F7EULL,
		0xAEEDA9D895F9D8FFULL,
		0xB8E17711F99F1B90ULL,
		0x19960CBA7EBA12B3ULL,
		0xAC52773B05FEAE17ULL,
		0x2AEBFBDB58F58653ULL,
		0x3421B551477A5398ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9AA85AD3AA44C24CULL,
		0x5A458FF75C84693DULL,
		0x9871349EE969002FULL,
		0x54316D61AE7527EFULL,
		0xB840BCCDD8FA5E84ULL,
		0x5BCE930206E7C6C7ULL,
		0x31D4E814B1AC5A5BULL,
		0xCE6428CDE9708127ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5AE54CCF8F575FB8ULL,
		0x8215E19E938A6C09ULL,
		0x0FE964B6816D5FACULL,
		0x7ED2E530409F3066ULL,
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
		0x7DEF2F894AC2F3B9ULL,
		0x6DDBAFDA903B5BECULL,
		0xF504DC2842A4B2BAULL,
		0xCC395DD6703CC85CULL,
		0x6B0231F13F240210ULL,
		0xDA4017D84DD7CAD5ULL,
		0x9324B8D1DD610D7BULL,
		0xA5DEB74760A79CDAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCEB06273F0BCCB11ULL,
		0x228B269D37E30AC6ULL,
		0x573566A186C844BBULL,
		0xC3B5263F49035271ULL,
		0x89B6E3F5D70495D6ULL,
		0xA97D9C5B5D0A5713ULL,
		0x4D2298E131D15FF0ULL,
		0x87F7E40721EF9918ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x206C6066CEB039DCULL,
		0x882EDDC916D77FEDULL,
		0x02203340333030A8ULL,
		0x78C79320768A04C2ULL,
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
		0xD1E984C52BCAF904ULL,
		0xEDC8599AD42C2E18ULL,
		0x26F6148C3F16B6A3ULL,
		0x11EC1101BF3318A0ULL,
		0x02F7B9E8D6BC221EULL,
		0x152F19BBC4F3CE68ULL,
		0x51CAFE7318289087ULL,
		0x250EF621BD44D18FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEBB3786DD48EBD74ULL,
		0xA4FB1683EA3C1F7AULL,
		0x1DF2001E91370ADAULL,
		0x215DA19B8113EF8CULL,
		0x19951E4C2E68360EULL,
		0xF9662BDDCA1F3E6EULL,
		0x11FC30527D9ABF90ULL,
		0xC01D78C95DCE718AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8AD9259853B14273ULL,
		0x68A0920A257D6DB6ULL,
		0x81B6AD449EECB051ULL,
		0x6C670A8469B169DBULL,
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
		0x3398FB18CC3DC506ULL,
		0x965F342B104F3C5FULL,
		0x1BB3A61BE75BF389ULL,
		0x13A4021B09155F2AULL,
		0x80083595FE0492F4ULL,
		0xFA2040C8CDCCEC93ULL,
		0x0D0D110A1E27204AULL,
		0x6AA9D89B63D8A977ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3D5FC2509BEB5AEBULL,
		0xEEC4B37C1A0A5B76ULL,
		0xD0E8194E3FAA64C4ULL,
		0xE2A9077DCD317DCBULL,
		0xCFB2B295717E5CB5ULL,
		0x6266DB1EEA4B3369ULL,
		0x0825C0EB28DE4986ULL,
		0x04AA277F0D9ABA8CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x22EAAADD0C3E7989ULL,
		0x2D1F97E6BB865D19ULL,
		0x0521716610816FF3ULL,
		0x54EF44D209155841ULL,
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
		0xB9285CD578FF7475ULL,
		0x2772C3C90306CAB3ULL,
		0x95DD34F03FC9D220ULL,
		0x33A5A726651ABCC6ULL,
		0x6A78CC960F76A5F7ULL,
		0x57791920D1206719ULL,
		0xDE37F78926952ECBULL,
		0x3ED8EC7934249CD3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x575B3B3F512B2E41ULL,
		0x349890C008796B28ULL,
		0x5815A691E650C928ULL,
		0xBD1089509E31B37BULL,
		0x5C5D423C00072D9AULL,
		0x547D72AED6AE7B37ULL,
		0x4B1999C7D0B58278ULL,
		0x40D7271EF6CCC09DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x79E3AAF4726023DCULL,
		0x6434E7F427766319ULL,
		0x1449791118AC9D4AULL,
		0x2AD8693AE1F3B965ULL,
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
		0xF1AA5153ABF5FCD4ULL,
		0x874C88C08998B7D7ULL,
		0x64EEF7703A6A0395ULL,
		0xF9C1D8D8CC369D4DULL,
		0x11AABFE553B3DAE0ULL,
		0x1E380E0623D57DA5ULL,
		0x03EFA99C7087C6E8ULL,
		0xF52010E74B118CD7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x35125012469B3E77ULL,
		0x8D4F87ACCA7852FBULL,
		0xED984DD3CBF93267ULL,
		0x2B8D1B9CB0ACC2FFULL,
		0xAA3A061A69044311ULL,
		0xA696727E3DA14035ULL,
		0x1F26E8ACCDBB199DULL,
		0x9408F29D74097F9FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x175395603B6B4951ULL,
		0xBBFA173FEAE18366ULL,
		0x6D234D2E98D28A3BULL,
		0x37A33C3206BBD099ULL,
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
		0xE938776BF0691304ULL,
		0xB70B637FBBB847D6ULL,
		0x727AD9002A9E57F0ULL,
		0xAA655819282E11F2ULL,
		0x3CAA4AA2F11BACCBULL,
		0x1640344BDDF0B217ULL,
		0x65CCB151B06C8ADFULL,
		0x0E79FC106C125D3DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x797DE432ADE2C86FULL,
		0x95E8D20B6062EB18ULL,
		0xBD9AA38A02B2B133ULL,
		0x4B31099231049E4BULL,
		0x904AFC6132B4E5E7ULL,
		0x35CAAAC6778153D5ULL,
		0x41D21A5848B612A4ULL,
		0x9B0BC6BF9FDCDD36ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x05E030FB85C7CD62ULL,
		0x7294FB418FDD5A7EULL,
		0x0C129E7B8D017F7AULL,
		0x01903885471A74B6ULL,
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
		0x013EC2B5A23ECE73ULL,
		0xCE4ACA1620B6E982ULL,
		0x8FF9EFA05D45E506ULL,
		0xA4C74138CEC40839ULL,
		0xE4D57FF7F49DBA10ULL,
		0x16DBD110CD3178C0ULL,
		0xD3F3C99D40EA0070ULL,
		0x2E6FCDAC5AEDFCE2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0B4C86209631EBAEULL,
		0xD550142FD7A08673ULL,
		0xE8D3DF74C52E7517ULL,
		0xF1D1C2AECB828232ULL,
		0x6DD27200E6393E4FULL,
		0x86D0B58D05D8FCCFULL,
		0xBA2A37C432A53C5DULL,
		0xCBAD23CCF00DD521ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA0664F412EF73DDBULL,
		0x5AA0CB75E038C8E6ULL,
		0x7B11B663B64C8AB0ULL,
		0x5BDAB5B3E0876CB0ULL,
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
		0x3EC3608AE1DB5480ULL,
		0x8EA0817724305451ULL,
		0x3DD6E0FF5B9EA72BULL,
		0xDC78B0226A685CF1ULL,
		0x3B99295C9EC24B50ULL,
		0xFF66D7C1E2FB7431ULL,
		0xCA6B6EB6847B6822ULL,
		0x43BEAD8F0F73E2A5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x02104921D0B06A9DULL,
		0x25F18E54C90A70CAULL,
		0xB03F0C939B11C484ULL,
		0x8DD85946A9408844ULL,
		0x4380DC355E0EA232ULL,
		0x33A69E7D1B8AA609ULL,
		0x8EC83CFF83C817C8ULL,
		0x054CB83849556B3DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x104E8B3CABD605C0ULL,
		0xA7377357F5E47D76ULL,
		0x67D13595DB2AD021ULL,
		0x138AC1BD29AD8E25ULL,
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
		0x495ED7EDAAFBD6F4ULL,
		0xAC456D0A63BC518CULL,
		0xCD47550A1BDFD99BULL,
		0x099D1840F7C990B9ULL,
		0x3A63A2B408EF2C6FULL,
		0x131024DB7B52A7E3ULL,
		0xB1821C30B95370CBULL,
		0xF231277AAA74FC99ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB3168F91740ECD94ULL,
		0x1277DD50C4093B8EULL,
		0x82A3CE08E4144B05ULL,
		0x50B52DFF152AC96EULL,
		0x35DE7C2D803D7377ULL,
		0xA7BF0593300C5657ULL,
		0x5D586DB846D9B0BAULL,
		0x1994E80277E5FD58ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x420C0054814E82DDULL,
		0x87D83474CC2330C6ULL,
		0xC8D36CE235DE1106ULL,
		0x6019561963D8AAFDULL,
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
		0xA6208E8FB3F534E1ULL,
		0x3140C747E86691E4ULL,
		0x6271BD9E408C2F99ULL,
		0x225F1DBDB9F0F61DULL,
		0xE9A975A7D1AA4900ULL,
		0x07A41808E116AE79ULL,
		0x60D5B34A1C7CECE7ULL,
		0x86F03984E97EBBABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC3AE58760A3E9A7BULL,
		0xC0516E2615E8B5F5ULL,
		0xC416D7116BC38380ULL,
		0xD436D17C07001AF7ULL,
		0x61FA3D38F0D8F7BFULL,
		0xC7FF4E7C3812260FULL,
		0x622733718BAF11DFULL,
		0x31E5F0E4A13BCF85ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0674968F08C8ABC1ULL,
		0xE3654402E92A1BBFULL,
		0x6C41E0B253572F2BULL,
		0x6DAF140C6CDFE8C9ULL,
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
		0xE69A20356B588CE1ULL,
		0xB555E5212F631DC9ULL,
		0xB354B1CD9160C771ULL,
		0xBB692FF5C14C0000ULL,
		0xAA781FD7BF56273CULL,
		0x9D573C6B25135C46ULL,
		0xF8B6255F1BCA98D5ULL,
		0x164689732840F0E4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBF2D01FD3ACB8FAAULL,
		0x30AABDF1F29539C3ULL,
		0x5862832920B370F1ULL,
		0xF5F580FF0EFD29AEULL,
		0xF415DFFF569C9CCBULL,
		0x70301795CDB03346ULL,
		0xEA15C4A615FB6AA2ULL,
		0xF7F83F8539112B1BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3A029857BC1784F1ULL,
		0x387A9EDA3585F9FBULL,
		0x86C08A1B4D6E3219ULL,
		0x4512A8483366322AULL,
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
		0x33608813D9EC4FB3ULL,
		0x4ED1D9D2D7BA4CBEULL,
		0x2AA8870D45942A08ULL,
		0x19F0E09F15C9C323ULL,
		0xF9BC7D6B4B949FB8ULL,
		0xB520BE45D4CF62A4ULL,
		0x04D224C328C0277EULL,
		0x02B69C31096DF244ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x25C3C541DD7A6F4AULL,
		0x4BDEFB687CB91265ULL,
		0x90E7F01ED812CF66ULL,
		0x350944579C9F5662ULL,
		0xD86E10C8F71D8386ULL,
		0x4CF8AB33722D7D24ULL,
		0x357E59415C2BFF0DULL,
		0x7B8C8B9D82B3B4ECULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFF40E2EA86200D16ULL,
		0x78E5B324FF094B5DULL,
		0x6030CC32CB7F5B77ULL,
		0x7526122D78CF87C9ULL,
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
		0x635374677F03D82CULL,
		0xFAA260B7A7E86FD3ULL,
		0x2EE1722A9BBAD405ULL,
		0x2EB0E1F843878771ULL,
		0xFE5506C05675915AULL,
		0x277847D77B29E2B8ULL,
		0x6A39B481DF945907ULL,
		0x9969291F5AFFE5A8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8C698DC355B212CEULL,
		0x88C768E59FA4112BULL,
		0x10663447A315761CULL,
		0x55C359606FAB90C0ULL,
		0xBE016433E9ADF675ULL,
		0x1256E068E8D76599ULL,
		0x4A2D837473A6BA91ULL,
		0xD8BC2394C92D1A34ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6354077C4EF2C1E0ULL,
		0x94D0523BC082F14BULL,
		0xE04A85E0FDEAE370ULL,
		0x729C5B29792629EDULL,
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
		0xC19BBBA22A184891ULL,
		0x038C047C854287A8ULL,
		0x1C891ED6C72AA9E1ULL,
		0x0CD97A8F9E7D26AFULL,
		0xDD94433CD2170635ULL,
		0xF31969B381642085ULL,
		0x092346A33033D424ULL,
		0xBFD0D36E45BA3C83ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF4BA9A4E36F72FDAULL,
		0xD05D29A7660E6C82ULL,
		0x462D50408A1EA5F4ULL,
		0x6C07B5BF1EE5101CULL,
		0x79CDDC363D17CB7BULL,
		0x2E3E00307D7F20D7ULL,
		0x1B929A9F038A36ADULL,
		0xC7B4A5F30C20F1BFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9C546C4E1103D007ULL,
		0x6BC08447B3320F08ULL,
		0x19D55734DE3963B3ULL,
		0x7500851B0C592FA8ULL,
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
		0x21B38D314237CAE7ULL,
		0x2764BAF8DDEA640BULL,
		0xB261B76354AC1A72ULL,
		0xC7C9DA1375D12945ULL,
		0x11583A27176798BFULL,
		0x29975354CE4443FFULL,
		0x82A64B8946364560ULL,
		0x8B8D923DD6267B96ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x615C327ACD127AE4ULL,
		0xE33234B5C5584CDDULL,
		0x1857592D18363217ULL,
		0x249C9ED8532917C2ULL,
		0x653962C86BC4A14DULL,
		0x01F957247F69F969ULL,
		0x7AC51AA83EAFF238ULL,
		0x7EE66CB6310DC2B0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4CEB52C3EF560B4EULL,
		0x25A5F56ECCF92965ULL,
		0xC5779F9D5A664050ULL,
		0x03FCCD5DA45383A8ULL,
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
		0x4E58869FFF48F23DULL,
		0x0175745BE24AEE18ULL,
		0x4188D8D84719DE4FULL,
		0xB91EAA6654D568E9ULL,
		0x134EF513BDD07419ULL,
		0x001C6FEC73977CE1ULL,
		0xE60C779918E321D5ULL,
		0xFCBA1BFB0CBE689BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFFCB3DE9C141AF5DULL,
		0x67486E46B9BFCED5ULL,
		0xDDCB3F7B6ADA7654ULL,
		0x6BD93E9E61C3D9FFULL,
		0xB9BC423FBB3C21BEULL,
		0x4F8DC08FE520D817ULL,
		0x3C7A862DAFC03BEEULL,
		0x3512628BD9859AE5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9A53D42EA00B80C3ULL,
		0xCF5B0DD24E279525ULL,
		0x8F676F4E776D8838ULL,
		0x702AF2498D801806ULL,
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
		0xCF53F44A2CB60253ULL,
		0x2615A7C4BD185E96ULL,
		0x304F688144DF16E7ULL,
		0x2C337073FE5288B1ULL,
		0xA34B635F5A8812C3ULL,
		0x4F0EE5732CDC60C1ULL,
		0xEF239E4AD8BA2AFDULL,
		0x7C1761866CD146DCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB4535938BE899B1EULL,
		0xD54528B888EAB885ULL,
		0xF6B8306DF7A760FEULL,
		0xA57506C5CDAE4E70ULL,
		0x7481E23B749F1637ULL,
		0xE12A0D336DF3FBFBULL,
		0x3CEFEF63AF12088DULL,
		0x2B86F679DF07E59BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0CE9C6658EC1E59FULL,
		0xA0C898828AAC9B7CULL,
		0xAD432E637C2CD272ULL,
		0x7C2E4D8B3C88AA00ULL,
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
		0x7CAF0C4FE7917F86ULL,
		0xB25A71854FABAA1FULL,
		0x57FA76F74B9C2B64ULL,
		0x8175AE0992164CCAULL,
		0xCED83FC3D62A3911ULL,
		0xD31169B33C39253FULL,
		0xCBCB4B30D876CD0DULL,
		0x7746C8805D91FDA2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA6B9E1F2C08155D9ULL,
		0xD442FA42C812883DULL,
		0xF1B500803FE77AFEULL,
		0x1EA8F893FD08EA81ULL,
		0xB4663611B64BA661ULL,
		0x1F6148381EF1647EULL,
		0x5EE4E14841F39D74ULL,
		0x274CF627F0C505EAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC2E29ACDE219F195ULL,
		0x8A3C6F88E03FBE8BULL,
		0x90792EFD632DC136ULL,
		0x41E1EE95BB7A27A8ULL,
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
		0x35E940EE05665990ULL,
		0xAA160099BB24BA9FULL,
		0x4C846DD41463C6A4ULL,
		0xBD6A28BA4DCA1F7BULL,
		0x6F2E23FE14D84C87ULL,
		0xF610F2A45D76A482ULL,
		0xEF25DE0414D4ECA7ULL,
		0x83E6E029131D7636ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2316B0300D55DF3FULL,
		0x2A94EC3132FCF4A2ULL,
		0xF79BFF96AFC51E31ULL,
		0xC7D8AB5A8933DA4EULL,
		0xAFC25501795C0F96ULL,
		0xBD9995D919749DD6ULL,
		0x25D68D30ABB38CCFULL,
		0x1E1E8EAE12DE54D6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7CD34A3D0C818851ULL,
		0xE138DA94A074C37BULL,
		0x36AE6D9EFF92E28BULL,
		0x114D95A1CDF5398AULL,
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
		0x0F7178DB282C5C69ULL,
		0x6437ABD22ACD0AFEULL,
		0xA89CF6B76D1BDE34ULL,
		0xD7BE0A9004B1DA45ULL,
		0x969ED941415BE0A3ULL,
		0xD7B7863252443534ULL,
		0xC778399821977B40ULL,
		0x935D5AF1784D08B0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x71002826D1323EBAULL,
		0x0503A662601DE414ULL,
		0xC2498DF03A5C7DF3ULL,
		0x3936D7716AFDD307ULL,
		0x0355DA6648795B98ULL,
		0x20D8A4B0777CC422ULL,
		0x8540A0454822C6FEULL,
		0x738D8C84141FA2E2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7B4725354899DE0FULL,
		0x84497EB64449EFABULL,
		0xBA942B137A122228ULL,
		0x575FD75B787123DBULL,
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
		0x5D8624480008ECD2ULL,
		0x067C114CC32E9FAFULL,
		0x8FD8DC1FDA105DF6ULL,
		0x1D4A3FFBC1BD5E50ULL,
		0x92E3E4A90441C961ULL,
		0x7CD6E547BBD15806ULL,
		0x2E63BB35B7188142ULL,
		0x911BF815482ED903ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4DFA57DA120D40BEULL,
		0x3300FEDD9814D3EBULL,
		0x5816A1B2EFC02B01ULL,
		0xD06CF4F09E70B958ULL,
		0x9D239A474D762E35ULL,
		0x640A973A7A26024FULL,
		0xC80D922D201D4A4BULL,
		0x613A5FEAF0DCC5F0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8A16D6EF1034B580ULL,
		0x81CEA866EA8884ECULL,
		0x688C51B3539A5BA2ULL,
		0x6859E154197B79B3ULL,
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
		0xCA1B8F8B2EFB36C5ULL,
		0x2ADC971F3D6E49DBULL,
		0xF5E1F9EDEB1531E0ULL,
		0x5630B4566A46D91FULL,
		0x77E362B4BFB11043ULL,
		0xC5E814AE1CC38713ULL,
		0x0C80893B43B71DCAULL,
		0x06975B4582FAEC68ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCF8AF0DB80B0983AULL,
		0xC8CF7E35201F5D07ULL,
		0xB89984DAB848C984ULL,
		0x830B3F224D0BF58BULL,
		0x3152CDE52A361ABEULL,
		0x91375CD0B0094194ULL,
		0x581A3D7C953832E5ULL,
		0x0643B3025816594EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7406B57FDE8B1036ULL,
		0x344863C840F53DB8ULL,
		0x0477B36119A34661ULL,
		0x5F906F2C7B28B965ULL,
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
		0x11AF9962781E4814ULL,
		0xA2D14C0540873608ULL,
		0x7F3EBA8F5123CAFBULL,
		0xE346EFAD79D17510ULL,
		0x4F16B624B17A0D51ULL,
		0xA494CA99876B50B1ULL,
		0xC3807491A68BD4DAULL,
		0xA746AB99784B82DAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEB54FD9135ED7FEEULL,
		0x5B74C6F0D63B8458ULL,
		0x4F3D14FCEAD324E5ULL,
		0x0916E07BF1461AABULL,
		0xCFC07ADE5750A390ULL,
		0x0E3FC6C9308546FFULL,
		0x39F10607031E8D95ULL,
		0x4F8FBE389D2F0149ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0D276842A4567CCDULL,
		0x97FB160150712208ULL,
		0x9B4C0E26A8893A6AULL,
		0x5F574B920EC695FFULL,
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
		0x32E65926D37D32D8ULL,
		0x449B4D0614055DBDULL,
		0x684DBC78C4D3DEA9ULL,
		0xC1A530FD76B8E5E5ULL,
		0x90AA9141FC2999CDULL,
		0xCD780C1C07A65047ULL,
		0xFCC963D361FDF632ULL,
		0xCD68ECDD17B50008ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x98117D74ED70C402ULL,
		0x6FF81D4C395895D5ULL,
		0x54C41DE77B59F856ULL,
		0x7452734C72A5DA14ULL,
		0x43CF56097C39DB83ULL,
		0x7DD13C09185B4D4AULL,
		0x0D05080F3B1289E5ULL,
		0xC36605715B46A9F6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x035FA614E3A2AE0BULL,
		0xA76612895FCF3981ULL,
		0xAAAF3DAF106BF9CCULL,
		0x49C117AEFC73D2A0ULL,
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
		0xBA3AF5A621264673ULL,
		0xBDDE38501173E232ULL,
		0x53FAEF61025625EBULL,
		0xF99FAA05755E6072ULL,
		0xB2C996131B585695ULL,
		0x998E760841573265ULL,
		0xCB08ACFDB3E82E7DULL,
		0xDC051E1EBA405DE8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x44CC5620CE5C0587ULL,
		0xEF090550D4E39F3EULL,
		0x9F341901AE41E483ULL,
		0x16EBB9BB1E505186ULL,
		0x2888E59472D7B7D5ULL,
		0xA96CC3CA4A7374C1ULL,
		0x87E3982FDAEA7123ULL,
		0x3DEF96381A89024CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFB08D25255E1D4FCULL,
		0x73D5A831E25E6960ULL,
		0xAC47ECED89BE5CC1ULL,
		0x59E61C860C45A81DULL,
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
		0x94DBF0241FEEE035ULL,
		0xF9FA7BB88D9CDB6BULL,
		0xA1C6F5A2B7B71F0FULL,
		0x42D42265195E212DULL,
		0xA30DAE9037D0F6B1ULL,
		0xA42B60BF09123B7EULL,
		0xC68AEF5D1D4C3370ULL,
		0xB9D95CD392AFF3BCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x699751839BE14B81ULL,
		0xA6923925E7D731AEULL,
		0x4033409CEC9D707DULL,
		0x48615CCA0BE2A561ULL,
		0x0F883F26189957B7ULL,
		0x7E7EC3B2DA746FE2ULL,
		0x0BBB8D40D90E1B0BULL,
		0x0D469FAAED4B4F36ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x11132861264F3199ULL,
		0xEB0792619131E2FBULL,
		0x1C5C4537EC514D95ULL,
		0x183AD9A39A6BE7CCULL,
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
		0xC0427D7C91A32BDDULL,
		0x922E45C745E2F42CULL,
		0xA14791BCA13F24A1ULL,
		0x202F1ED9360EA1F8ULL,
		0xFA43D765FBEA8BD0ULL,
		0xB5ABADAC83E279DBULL,
		0xACA763D4D9D742FDULL,
		0x3C0A22956BA79D2CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x125249D974C7EE6AULL,
		0xF2F3CAE5C7400B59ULL,
		0x1869E1FCE8B6CC47ULL,
		0x1808AE5FA28D5456ULL,
		0x4D7B7D615A6681EFULL,
		0x68DBBA2E0933AB7CULL,
		0x1161515960F36599ULL,
		0x19DB24D11D327833ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x53AD90531674B597ULL,
		0x06189FA7B4958B07ULL,
		0x95446E13AA5B353DULL,
		0x1B201B9D38E4CAAFULL,
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
		0x09A5718159E42FB7ULL,
		0x99B02B9C6CCAD588ULL,
		0xB33402EAE3B36BC2ULL,
		0x089B7FCC098623AAULL,
		0xD9B010E69F907E6EULL,
		0xC2767AB86B9B9B4CULL,
		0xBE69BDDC93034F7EULL,
		0x229F4A86B39527ABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC1BAA7177800A0F0ULL,
		0x3051FE9F057D5AC1ULL,
		0x6F1D9D056995D92CULL,
		0x3B389C15B5957BABULL,
		0xA2B1527A1F846F40ULL,
		0x8128B7AD68263A64ULL,
		0x52BAB7230166B17EULL,
		0x19CF29B4666D67D8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x71BB0E84E3ADCFC1ULL,
		0x1AE9209FEAB9DD3EULL,
		0x40116571175D06A0ULL,
		0x1C47C2EDC7D72161ULL,
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
		0x44E34CB97623B90CULL,
		0x43E11483979ADFE4ULL,
		0x58D7EAEE04C0636DULL,
		0xD71FCB5E32F8797FULL,
		0x16C02B5DF74D4022ULL,
		0x5D6B6C3AF8FFC192ULL,
		0x42B6BDD735BBA39CULL,
		0x4F4297F9DB415DF7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD74EF1BB4D767E4CULL,
		0x5D88DC2947CF9E11ULL,
		0x8B5AF6EF384D8A62ULL,
		0x5CD843DCD1B76F37ULL,
		0xBB258E1E58E99F29ULL,
		0xAD91E7E2826CBE82ULL,
		0xEF2B6BA64AD0AE33ULL,
		0x48B874FF00417891ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0687B26FAB771FDCULL,
		0x00A1DD7BE99DB61AULL,
		0x342B2741AB534695ULL,
		0x72C8B8BDE33D1752ULL,
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
		0x253CCACA0EE5CC84ULL,
		0x7259DA3DE5352846ULL,
		0x60585E64EC11D007ULL,
		0x5B5DEDE027F9F67EULL,
		0xAD0274E1079532CFULL,
		0x1D28F2DF7843366DULL,
		0xB42EFF450FB34FF1ULL,
		0x47528A77A57931ECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBF6E1C5B79B4C75CULL,
		0x167D6EDE71DB6704ULL,
		0xE5C1A44F87D0EC3CULL,
		0xFED23DD13391359EULL,
		0xD11FF8BC2B196711ULL,
		0xB3D1292A34722F3DULL,
		0x0935DDA0A7C2E4AEULL,
		0xD540E9C7715172AAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x096D1BE74F914018ULL,
		0xFEE45C478460D25CULL,
		0xDB91B87CD1F0CFA6ULL,
		0x4B298A36B24F24C4ULL,
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
		0x0B24FFF812B74304ULL,
		0x3D0C7523A41688F3ULL,
		0x71FA20C36863695FULL,
		0x7C2938686EA42C81ULL,
		0x1328F414A89C94F8ULL,
		0xB8EC9F5B31049810ULL,
		0xC6E45231B9CA4CC8ULL,
		0xC6BE464F29D008CBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB161945C16A6DEA4ULL,
		0x2AA19100E5731A68ULL,
		0xBB98620D8691A08EULL,
		0xF5A4E8074FC7ABBBULL,
		0x51A8E995DB0B5E96ULL,
		0x5C1A94AC776C8E0CULL,
		0xD288A2315FD4CB7DULL,
		0x1638ABA529154276ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x12C4FA6E7F9E7AB5ULL,
		0xD9987A124B34EB19ULL,
		0xFBFDDEC33C42FA00ULL,
		0x3A59459D3A95F161ULL,
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
		0xCF487A90A0DD3C68ULL,
		0x024ABFD01F560372ULL,
		0x9022DECD77A80511ULL,
		0x3DEAC5645255C278ULL,
		0x64399D3C84BE0850ULL,
		0x2EA68E29BD47133CULL,
		0xCAAECABB9434656AULL,
		0x19774B654C25545DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xECB44301675F3D71ULL,
		0xC45966B3B59B0EB6ULL,
		0xBE2BFF0D504D5E00ULL,
		0xB2ADE55215F98E8FULL,
		0xCC2552EB2A9E08C8ULL,
		0x5F7FB34EF9C2507CULL,
		0xC8E9C82C97EF3C8AULL,
		0x7854E7942454C32FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x75973FA29A3DEAEDULL,
		0xFDB5D5956F6FDD2CULL,
		0x153540F9999EB848ULL,
		0x7657B11E2551C0BDULL,
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
		0xB8B4D46B01D97A8DULL,
		0xFDCDB6D8DDBCEB0FULL,
		0x203CA85F72B21158ULL,
		0x68891E069485C2EFULL,
		0x66012D65A12FC9C8ULL,
		0x8EA797D0E5FDB1D8ULL,
		0xEADBAA73BE563CF9ULL,
		0xA29ACD07381901AEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x95929D0F9DD44D68ULL,
		0xBA8E270F287A7F34ULL,
		0xE17A29D4DEEC8DA7ULL,
		0x20B52366D8C8D62FULL,
		0x856DB3AC00628BADULL,
		0x2AA56A65377741BCULL,
		0xF295FF2540E19649ULL,
		0x15AC80D0C3476378ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x790648E9427C6845ULL,
		0x1B924DC59D370FFEULL,
		0x1919EC31331641E0ULL,
		0x33334AB512DA68C2ULL,
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
		0xD953CDB91146804FULL,
		0xC1C7D5F47BC1B59AULL,
		0x1126F6C64924AF00ULL,
		0x6B41F9A13DFA94EDULL,
		0x9F9CA11156807C2FULL,
		0x41695ADE7A489516ULL,
		0x0BAF2F53797C8557ULL,
		0x1BA9529E121CCBCEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE9D6E848ED54110FULL,
		0xF38FBC54928038E7ULL,
		0x67BC953EA524F539ULL,
		0x9FE646A0240D52EAULL,
		0x7F6197D37B4C0F04ULL,
		0x31C4A831FE4D5716ULL,
		0x75EFB684882DE4EDULL,
		0xE5D00801C1D7A8CBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB840449EADBA9F1BULL,
		0x20AA9F3A508CB0B7ULL,
		0xE3D6503F75AB8985ULL,
		0x499CC63504307464ULL,
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
		0xC3EC31810243BC8EULL,
		0x1D33200FA0DC30ECULL,
		0xE65E36A9221898F2ULL,
		0x03D1B64DF3B32723ULL,
		0x92F12FA72CCBF956ULL,
		0xD08602EB5DA440E7ULL,
		0x03DCAFADB2CEAC75ULL,
		0x50F440B417CC1791ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x17784555EC7D839DULL,
		0x8709EDFFD7EB1911ULL,
		0xE4A77C10A738F66AULL,
		0x61E15A8ED3F1796EULL,
		0x55C7F2BD57329BEEULL,
		0x4EC364EE64D33193ULL,
		0x44DE69807E76938FULL,
		0xED62F1F06FD88B3BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC092F6E0CA8A12D1ULL,
		0xD90CA59CB7F95E5CULL,
		0x5B75254E3FF354BEULL,
		0x69820CCA0DE8826FULL,
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
		0x0EE1746F7C8B1962ULL,
		0x68336530944E541EULL,
		0x283D8443020B2C0EULL,
		0x33401575DD926C62ULL,
		0x499AB7816E881018ULL,
		0x0B77A7EACAE07C97ULL,
		0xC82E3AE4019CD39AULL,
		0xF0B01EA8198ECE6DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1976F4DB16DA2E83ULL,
		0x02A59A501C726455ULL,
		0x445FAC27D28D6602ULL,
		0xE78E52AB3D5E0463ULL,
		0x8F21E5A0684C2AACULL,
		0xD5CD73800C4CD5E8ULL,
		0xB2B9B10A8AFBE561ULL,
		0x361E931767F7BFB3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA359A6FB5294FCD6ULL,
		0x5CD192B8C1C6ADB8ULL,
		0x132A4E62CB612264ULL,
		0x7D4C7A44FCA0979EULL,
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
		0x00F33822820416B2ULL,
		0x05F1050A8B3092A9ULL,
		0xB82C654D9B956608ULL,
		0xCC47CCD33142EC7EULL,
		0xB74EF699E67EE4A0ULL,
		0x8B1BA541B4CB65B0ULL,
		0x0B3CD71F8D5E4D93ULL,
		0x622BEF26C56D9E82ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x89B46E2CE5F83B82ULL,
		0x1E8F57DA032E0468ULL,
		0xA91B54D3FF1B5D82ULL,
		0x86BC3BA30CE0BA53ULL,
		0x62939886A32D5BC7ULL,
		0xAB947EBA281DDB19ULL,
		0xDBF1D03E3F8FDA30ULL,
		0x62BE3B4D21D61343ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0B0EC0D19A262B66ULL,
		0x1571654F69C520B7ULL,
		0x143415EB291F2933ULL,
		0x2FD4437E6CE0DD66ULL,
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
		0x9BE6395BB8C1D5BAULL,
		0x2285944B9497CA9BULL,
		0x32C297679842895EULL,
		0x5888FC5C0A7E6B23ULL,
		0xD5BCC326DC434629ULL,
		0xB8C7166AF6241052ULL,
		0x2C00577C95D167DBULL,
		0x64C347AEE5DA5FA5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFD27625D57A860E1ULL,
		0x69124D97E2A58A0EULL,
		0x2F93DBDD6F8B5495ULL,
		0xBBCBC74018A4E671ULL,
		0xFB2E5FE704987C97ULL,
		0x15B8A83A07092E75ULL,
		0xBFD6191A86237FD1ULL,
		0xD0041E3C066DD659ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0FE1927864735E12ULL,
		0xED97A1F72FEFC755ULL,
		0x1173FE187C87A65CULL,
		0x311D5C291BF5E5E4ULL,
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
		0x85D3E540AF132924ULL,
		0xD00FCABC32E02190ULL,
		0x7AAA33C5EA318EF6ULL,
		0x98B9B33CD9223815ULL,
		0x7DADC4835475CCE0ULL,
		0xE1083FA505F6CEB5ULL,
		0xFBA812F7AF63DC88ULL,
		0x5F72640A441BB852ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0352F6E61CC2F62AULL,
		0x2B2E90547BA19F7FULL,
		0x8FE995DE3AFC3CDBULL,
		0x9EE25DD8CE51064EULL,
		0xAD652C73B7A7BA9DULL,
		0xBD4328A42DB34EBAULL,
		0xB81B16D2B4DA5977ULL,
		0xE281192A9C823522ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6D4780ABD8E6E607ULL,
		0xF422A487D143814CULL,
		0xF1AE0B64DF9EC6A6ULL,
		0x05A87296EB9AAAF0ULL,
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
		0xCA3C227CB028D5AFULL,
		0xC579FE5E5035769DULL,
		0xE55BB8A3EEFA47C9ULL,
		0x1F721A2268766761ULL,
		0xD624E3F9F3C87D3BULL,
		0xB1644F68892184E6ULL,
		0x5E731589D29C2588ULL,
		0x7B544FD1028F9060ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x83B2F4BF921F10DFULL,
		0xFB15E8A8905F0856ULL,
		0x17EBEA0FA06CB7C4ULL,
		0x6B75ADF07E89021AULL,
		0xD7445235EAAFEF69ULL,
		0x84FDDDC898206CFAULL,
		0x1A4DBA3FE142AEF8ULL,
		0x6175C43B79CEA456ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1BDED0D677AED281ULL,
		0x6198F37385FFFB4FULL,
		0xEAFB5B8E21D5296BULL,
		0x0B05246436906ECDULL,
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
		0x519B91F144C1D9E2ULL,
		0x121D41E8EF9E375BULL,
		0x417D101E4E9DFE51ULL,
		0x1E1DFC7A4B365AB4ULL,
		0x5E12B3F4F1447199ULL,
		0x9897FF8CA1755579ULL,
		0xB6758B3A37F3529DULL,
		0x6448B52E2BC2DFEFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1B03CAC9461983F8ULL,
		0xBAC5E839934A833BULL,
		0x136A18DA3BACEE95ULL,
		0xBC08F02CD15445C6ULL,
		0xB8949D1D7ED67DC2ULL,
		0x784CE097992720FAULL,
		0x5860F83F7F5FF611ULL,
		0xBB8564C53E2D3EBBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC74F2B22FAFA85C0ULL,
		0x227DF20E97EF7EECULL,
		0x2520C87B78D0CC88ULL,
		0x6F12FBE0BE1802B4ULL,
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
		0xA0485A2C9B1955ACULL,
		0x2222A2DD0364962FULL,
		0xC5C1CA8F4DB7FA69ULL,
		0x8E404274E70CE970ULL,
		0x86D0E930F0FCCAD0ULL,
		0xD137853CFC62E5E6ULL,
		0x486D12F0A2ADBFC4ULL,
		0x279A53A09F73ECDFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC7804D9F6EB11A32ULL,
		0x7DAD9139A73F1617ULL,
		0x0C18C35F8B4F60F8ULL,
		0xC0549EF66280376AULL,
		0xB78CA00474A452A0ULL,
		0x0E5EFA402539822FULL,
		0xEEF33836D29C185AULL,
		0x412AF51BBB57DDE6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9CEAE927A18A1202ULL,
		0x9099B32B4C4A4D3AULL,
		0x01BF7EC4A5077349ULL,
		0x0273AB3860B6EAE4ULL,
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
		0x488FFACC26D296E8ULL,
		0x6EE373D9C4F9BAC0ULL,
		0xEC1965F6B4B460EAULL,
		0x4115A3A270451FB2ULL,
		0x4EB7D844698EF938ULL,
		0x7D7ED3850FAEA96DULL,
		0x8BB7FF43F7A3F5BBULL,
		0xBB735FE263E9EAA9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD4AB7C7A5B37A464ULL,
		0xCA24AB327BF84F23ULL,
		0xB744027DBD20363BULL,
		0xBED0BFB60FD5E90FULL,
		0x60F3871695656F55ULL,
		0xA1060BD130782877ULL,
		0xFCBF32666E776BC5ULL,
		0x9C3CCAFF86224978ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBF088B1F49C56ACEULL,
		0x5EAC6D5A6B18901DULL,
		0x6DC3CC5B5430A52DULL,
		0x245EFD994C1123D8ULL,
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
		0x1E11ACCB3B38B79BULL,
		0xE1A8DD190796B0ACULL,
		0x367753E61E71DB20ULL,
		0xE6989A4D794E3909ULL,
		0x55F805FE472FC570ULL,
		0xA7D80A5007B212D0ULL,
		0x5B04BD59E210E2A0ULL,
		0x368C9DB30218F5D5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB4BABD099E04028CULL,
		0x6A81822A8B15B73AULL,
		0x6D959D5D1A9672EBULL,
		0x7EFF651A29A888A2ULL,
		0x4B58E3EC3F75A458ULL,
		0x0227A64FEE24E439ULL,
		0x6CB67AC6C360D225ULL,
		0xB93231DE6AC1BFA0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFCF5FE6EC2D59BCDULL,
		0x0F5632F24775E3DCULL,
		0x287F985F91FDDA90ULL,
		0x030536C1C697BC42ULL,
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
		0x124CCB265CDBB6BDULL,
		0x3618A00C4A4C8AB8ULL,
		0x61740D23434F2117ULL,
		0xD38B161C4AD5A556ULL,
		0x6CCAF4E04DC192FCULL,
		0xBA1DED7B7420C7FEULL,
		0x9C8E644677826282ULL,
		0xECE77BF1A45D7864ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC4B8FFB2BE0608BDULL,
		0xE3143976A6D72448ULL,
		0x6651314795124279ULL,
		0xE9DFACAB894458EAULL,
		0x4C747611CDFEC1E6ULL,
		0x916E6B3B30FED95EULL,
		0x8724557C6E23DD52ULL,
		0x514A55BE69FAD271ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1A6A9E1A95C0BAAEULL,
		0x5D11BC1F9A7ED234ULL,
		0x28E10DD91244A3C3ULL,
		0x02FF150B6C35EE81ULL,
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
		0xD4CF8755A5FEC3E3ULL,
		0x1A942021D1ED1646ULL,
		0x6602F66DDFF1AAC9ULL,
		0x804178E295C69D6EULL,
		0x25C88319A85D281AULL,
		0xA1E762695EB210A1ULL,
		0x4B5DAB644CA36697ULL,
		0xAC82C3A3AC657E43ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7AC0450771124FEFULL,
		0x91AE6A86A4FC3B4FULL,
		0xA758C2BC367A7E1AULL,
		0x0676F4A5DE5AC7A9ULL,
		0x10FDA0FD035F1F49ULL,
		0x85EC2C4B607146D6ULL,
		0x65E9CE0E08166958ULL,
		0x6A5DE3BBA036A9BBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x702CD28EB2A1C476ULL,
		0xB02FBE0EEA8ECF1CULL,
		0xCDDD0E7FD664C40CULL,
		0x4B43C0AE865F61F0ULL,
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
		0x31000346232EB2B0ULL,
		0x9483BF305E5CF971ULL,
		0x3BDB1A15F241A610ULL,
		0x42BBAFAB0942AC3EULL,
		0x3FD63F58B3BEE28CULL,
		0x3A02B8DB482C0EB0ULL,
		0x3177E88C789C0297ULL,
		0xE78A90E30BFF2C14ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x98B3287BC41627ADULL,
		0x5617C1CACABA1952ULL,
		0x247465791473EF9CULL,
		0x0DC6D0EB99B23674ULL,
		0x800340A458D41F4CULL,
		0x0FC10E6D765273A2ULL,
		0x12364F116E8671AFULL,
		0x0A5CF7477EA5BF47ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x119EA98FDDF18B69ULL,
		0x842B49B2B9EFE429ULL,
		0xBB237CE05D0138EAULL,
		0x09B9ABD66AD69C3CULL,
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
		0x7680BA83ADBB7577ULL,
		0xF2B4B0D2DC92C78EULL,
		0x01A2437A83D283CBULL,
		0x35FA09D1D0CD2CF1ULL,
		0x872B958C55429DFAULL,
		0xC8064E9A20C8E1FCULL,
		0x68963DA98CC697C7ULL,
		0xEAEC43D17293032EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC7624C0FA3BE60C8ULL,
		0xC774A7CD18EC14FAULL,
		0x4499092666B63F09ULL,
		0x34340FCBA04BC0DFULL,
		0x16B8C2ABDA2924BCULL,
		0x33D5857B312F36D5ULL,
		0x655B16FFC6BE5DE3ULL,
		0x8DFD4D388C55B7C5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6029BBC64FC515E4ULL,
		0x2A7DE39D54761A6EULL,
		0x37D0F7878254DCB0ULL,
		0x4D3E94B85D9A9DA8ULL,
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
		0x4B8749E905E84020ULL,
		0x5C039A12AF237489ULL,
		0x6CFEA1AD60412C72ULL,
		0xEA2AA68ED7268D69ULL,
		0x0B9B6C50CF160D91ULL,
		0x5AD7BFD9D9CB9055ULL,
		0xE7785F202ED47207ULL,
		0xFE6FF76335579B0CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x712EEA44B9E20E11ULL,
		0x25DB9DA9F17958C4ULL,
		0x735E6986C76FA754ULL,
		0x60C58B0F86F3EAFCULL,
		0xF0A16FD585B453EDULL,
		0x21FAC4B9A0D5B95CULL,
		0x886CDCEAB56AD81AULL,
		0x98600A3D4835EECBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDB73D9F13087C2B4ULL,
		0xA6F5433132280498ULL,
		0x15558C169E7E5E54ULL,
		0x2FC24F2083323421ULL,
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
		0x66640B939CF45D77ULL,
		0xE3AF641A5689E05AULL,
		0xC5E8AFF0F28FA25AULL,
		0xBAD85513CF1B63D5ULL,
		0xF4E407CA31DF7D73ULL,
		0x5098C452B388686AULL,
		0x9DFED24FD9A99E7CULL,
		0x584835D54281B7F1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFAA834CBF00BF374ULL,
		0x0DCF79B90970831BULL,
		0x20A20A6164F14372ULL,
		0x40BE96BA54704796ULL,
		0x64FC58E40702B6CAULL,
		0x526443482B194F3DULL,
		0x5B6AEB65FBA9F004ULL,
		0x9687593F9B6693F0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC81FCCF209ADE5C3ULL,
		0x91AB11F18D971A01ULL,
		0x873AEC46819244B8ULL,
		0x3CBA7C9048B2746FULL,
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
		0x36816C837B2CCE80ULL,
		0xDF1006847D7E577BULL,
		0x77976009F1387CFDULL,
		0x5CFCBFE0A70BFF86ULL,
		0x9322CAF080638815ULL,
		0x81586FE0C7DA6E01ULL,
		0x477E8A3A2AF055B5ULL,
		0xE82B5FC1A4B6755EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF0CD17BA93FAFB47ULL,
		0xC329D033C24BAFA3ULL,
		0x84B193AC05AF2827ULL,
		0x3B1E13F6308BF427ULL,
		0x5C07E7F6D9ED7EDAULL,
		0x10B1631366AB9486ULL,
		0xB72B04D08A267EF2ULL,
		0xF93E67612B0A4698ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x73B205D79CB7319CULL,
		0xD4B21CCD2826F021ULL,
		0x5F4B9A0BC97F35D8ULL,
		0x190B8A3C860EFCB2ULL,
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
		0x7A2F8B3A39608FECULL,
		0xCA2CC78057B03DA5ULL,
		0x2BBE0B7CCD881554ULL,
		0x204ED4697AC7DECEULL,
		0xFAA7BF4C9A912EE2ULL,
		0x803F84328B2F0374ULL,
		0x6774AAB683C137A9ULL,
		0x2718D719F825C175ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAE2ED981AC38D181ULL,
		0xFEE0637EB34BE00FULL,
		0x324B5641D58ABFD6ULL,
		0x6E5DCCAB9351AE75ULL,
		0x7FF9A8D681788BBFULL,
		0xD4CB4254D2AF9142ULL,
		0xD8C00C854F0F7AA4ULL,
		0x155106892CBB7EDEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x01D8074046CFF5E9ULL,
		0x3E8E2AEB074F5114ULL,
		0x28423088CA5F642FULL,
		0x5599FD3C193C12B2ULL,
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
		0xEC8854710D1F1307ULL,
		0xD1A786FBB9BE0255ULL,
		0x30AC7B580582DB43ULL,
		0xFE4FAA3C6B94D904ULL,
		0xFE68CCBC1766EBC6ULL,
		0x5419E8736FA51734ULL,
		0xB5361E9D071DDF25ULL,
		0x6872FD655D755350ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x63E7C096576708DCULL,
		0xB6BA50E1CB6FBC93ULL,
		0x1DCF1C0A3C822C10ULL,
		0x8BD6F13F0022C31DULL,
		0x3EFA0E0A8D5C638FULL,
		0x0EC311AA0B76A6EEULL,
		0x125D4DB9EE9C65B9ULL,
		0x6DF2718C142DBF01ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF310E23533484242ULL,
		0x65D117FECD32F042ULL,
		0x3F0C61036C38B545ULL,
		0x218D7B3E4C1219B9ULL,
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
		0x662DA7DE17A796C3ULL,
		0x1515184F805714A2ULL,
		0x99F7E866E047B076ULL,
		0x5E1D0565BDF4F181ULL,
		0x685701792A8E2FCCULL,
		0x4076D1C475E63515ULL,
		0x91870C4C66E6A12BULL,
		0x6152DF6BFEF7EC1CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x14FF3379145A68B3ULL,
		0xDD3774DF335493FCULL,
		0xF7171F57D853725CULL,
		0xFE30E077E26CEE81ULL,
		0x2B9685F325C55111ULL,
		0x8A625A0289EA0F4CULL,
		0x1C63ADD6F48B5EABULL,
		0xEE75781B4B1CE017ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x55C0CA49B91E3A8EULL,
		0x3EE76A3954701C85ULL,
		0x0620CE7E01801D0EULL,
		0x6CC97AE88E0BCBCFULL,
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
		0xD5B21B377065A249ULL,
		0x19245E82DFFF0971ULL,
		0x389BE98CCAC88E04ULL,
		0xD5360CAA5A29060EULL,
		0xED4FBE029BC8E706ULL,
		0xFC97F506C9D90DBFULL,
		0xE0B25D8DFDB3BAB1ULL,
		0xFC0B18D496A2C12EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x103D4243210C14ADULL,
		0xFC08C0639AF57800ULL,
		0xBB61855326C8770AULL,
		0xE38C771ABFFFFC7DULL,
		0xBDEF1C28949D3614ULL,
		0x72FA3A36087ABF83ULL,
		0x908CAE7391DB2B8DULL,
		0xCCDBF2E92D2367CDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCDCCDF515FD5D27FULL,
		0x8A85591BF9092E60ULL,
		0x62D26225A6255665ULL,
		0x72A9368143104E02ULL,
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
		0x23E4DDCD36215AE2ULL,
		0xEF96DBAFAD3E417DULL,
		0x870B3619510EDDD3ULL,
		0x2295FC11A2C9154DULL,
		0xB7CB37A670565DB3ULL,
		0x49214F7AA527DFBDULL,
		0x044EB0DAA5D4E011ULL,
		0xDE1DACA59746E7F5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8A6100FABBC6D180ULL,
		0xBE11B6DB1E45859BULL,
		0x58B6DE692DF45C18ULL,
		0x2B284A53CBADFC1CULL,
		0xB5EBB7B205034934ULL,
		0xEB2F9B60538105DDULL,
		0x27651B1C60AC8077ULL,
		0x08A3CB1681F1AB24ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE0B0DB1A68AF98E9ULL,
		0x2365E0BCADBD1321ULL,
		0xF90091EE6718B27FULL,
		0x27852CFB01C22031ULL,
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
		0xDC42C14714B4EDBCULL,
		0x71E0C6103534605DULL,
		0x9A14224147C16CB9ULL,
		0xDB0050BF1B6D8365ULL,
		0x2960F744F6496B89ULL,
		0x85CCEE5ECDC88271ULL,
		0x95A421FACD5CCA45ULL,
		0x451CF15DAAA846E6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA10D154D8E6064B0ULL,
		0x08C9CB635458C024ULL,
		0x097F0F8F4E0601CBULL,
		0xA154A6C74963D564ULL,
		0xE29BFD4824C39554ULL,
		0x640CD3D73394F7D4ULL,
		0xB3979BFED27C9333ULL,
		0x13AA45084E751BCAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBC72C780A0325607ULL,
		0x6B9AEACDC482336BULL,
		0x1E70F6193703979FULL,
		0x10B13EA381A21425ULL,
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
		0xB37549672BF9C982ULL,
		0x732E16FB8EF2200BULL,
		0x271825CEC87B4228ULL,
		0xA0DDCF5543AC6CBBULL,
		0xA577F04BF69939DCULL,
		0x5BF4259C89985C5AULL,
		0xF9A4FAFF72BF2569ULL,
		0xDD5E0467204D7FFBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC7C433163FB5AE5BULL,
		0xA5863065F76C7FC6ULL,
		0x6045B54EE9437EAEULL,
		0xD082ACD2691974B6ULL,
		0xB56517F1D16D132FULL,
		0xD47F075F73F35BFEULL,
		0x9B9EFF28A9CCE9CAULL,
		0xD72480F6CBED19AFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8E7D33B270D1D8E8ULL,
		0xE90A63A6CE03ADEAULL,
		0xBBB5D261B32C9D01ULL,
		0x3CE4A52F60E2275AULL,
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
		0x249FC07686E9AA70ULL,
		0xCD8067AFC5F1F594ULL,
		0x55ECD35F596D84B1ULL,
		0xFDF68FF1C4CFE108ULL,
		0x786CDC4635DB12B9ULL,
		0x8074223BD25A1616ULL,
		0x03A628D7B51505CAULL,
		0xCA59C514F298BD97ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x218CB71EDB069113ULL,
		0x64153538E69640FAULL,
		0x64E7B65A4C91A9DDULL,
		0xEDC114292531F3BCULL,
		0x3207A9BE066D2C70ULL,
		0x34F812C11BE38C1CULL,
		0x8A285FC2825533F7ULL,
		0x8084C76A34E7C694ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7618898EB63349D5ULL,
		0x9DD57EADF4F42FC0ULL,
		0xF9B0F62A95550031ULL,
		0x05D32320C7E297A9ULL,
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
		0xC89934FFFF6A8ECFULL,
		0x766E17F44A6D1679ULL,
		0xB2CCE255D0E2F1D1ULL,
		0x238A9DE95C2C174FULL,
		0x6AE2C0A0E82F078AULL,
		0x665F94DCAC665D0DULL,
		0xB36E811DC2C2E189ULL,
		0xC0ACEB692CD801F0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7D0D70102936BE96ULL,
		0x9666B3E763AAF1ADULL,
		0xF372AAE818496E1DULL,
		0x079DA17A26340135ULL,
		0x388B3AA5B26279D9ULL,
		0xC1B8720F98908433ULL,
		0x3B7AA5A2141E0B69ULL,
		0xC0F5BA9C62C851B6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC489A839D290D87FULL,
		0x50D68E7DD880552FULL,
		0x8D8CCBC9A5114C66ULL,
		0x111E3AD5344C3EC7ULL,
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
		0x029F64508F7EACB5ULL,
		0x5804E8942498A092ULL,
		0x6F168632FE1A8FD3ULL,
		0x1AE18224C7FDDFABULL,
		0xE08B6947EF99E061ULL,
		0x197D731AC0AFA9C2ULL,
		0x83F4DC09B59BBD90ULL,
		0xD83A6FA9B53095CEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3010A95EF661F463ULL,
		0xF0A53147B3FC8BAAULL,
		0xC18ECBD3C448A76BULL,
		0x0CEBF08CEC3E316FULL,
		0x3C0D5CAF5FE3A561ULL,
		0x24753643CF809DAAULL,
		0x59266B77B95FECBDULL,
		0x4E314003BAE3BFC8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3D449996EE297D5DULL,
		0xC698BF343D97E090ULL,
		0x082C700AAAB2E7B7ULL,
		0x0B52A43B03277326ULL,
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
		0xEB3D23F3ADE48248ULL,
		0x71022BC5A6526CF2ULL,
		0xDACD6F587005B37FULL,
		0xAB3724B6FB4C29A9ULL,
		0x6587B415218925B2ULL,
		0xDB3E294C24CE19FFULL,
		0xBF968575BBC64AE5ULL,
		0xD275ABEE56310C0EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE016B1B53FB952B1ULL,
		0xEDB285E872676276ULL,
		0x7F285D2FEF1FEEF3ULL,
		0x587CB88329CB7520ULL,
		0x66FBBEFF4D3FD039ULL,
		0xF4AAFEF03A62C6C5ULL,
		0xBBE25E8CD9FF827BULL,
		0xA4C0F7DF3E09095CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD3ECD37BF10DE097ULL,
		0xBD27EF81FFD96517ULL,
		0xE862D8BA04678443ULL,
		0x1B8D267167711AF5ULL,
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
		0x9175E03FB9D081C5ULL,
		0x43EF37E8A4103D8FULL,
		0x850557C769EA64D1ULL,
		0xDAAF5B3DDC094A80ULL,
		0x6BE50D728390B02AULL,
		0xF966069A773D49FAULL,
		0xE790C768E60ED533ULL,
		0xDF7FD751E5396E84ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0CAA3CA36F350E63ULL,
		0x9C6ECE7DA632699EULL,
		0xACB93B40A4034DD6ULL,
		0xCEBF82577C1D8F6DULL,
		0x2BF98097327AEC9AULL,
		0xDBA7CFC614BD3DE5ULL,
		0x9E76ED80677FB2DBULL,
		0x3920309B734DF170ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x01C28C2A53D67E65ULL,
		0x11BC8CF19CDF9F19ULL,
		0xB22275098F26300FULL,
		0x3E2297FB48E04C15ULL,
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
		0x3E3613EAC156960AULL,
		0x4F2ED0FDEBB91F15ULL,
		0x806FE9262AA433E2ULL,
		0x3070E5D790244A73ULL,
		0x4E7195FAE85BDF86ULL,
		0x3C73E070755D4C82ULL,
		0x3C13FDC6BDCBBA5BULL,
		0xF66E81C5ECAB9F4EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE66BE44A2A9524ACULL,
		0x4E7EBD55644ACF4DULL,
		0xEAEDB9F15165AB21ULL,
		0x8DFF90F30866B2FEULL,
		0xFC34A8CAB44BF6E2ULL,
		0x50473A0D2CC8CC17ULL,
		0x4CFE3C776BC252A5ULL,
		0xA5FAD04C8ED77905ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8CD564C8511DFB6BULL,
		0x0F50C6654D795F8FULL,
		0x12BCE0FB06A3EDC2ULL,
		0x139DACE8753B4648ULL,
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
		0x74B1CEC595C4D024ULL,
		0x666251739744282AULL,
		0xD52E07610333E5DFULL,
		0x8A8FFAD0C95CC609ULL,
		0x347363BCD3A4BE2EULL,
		0xF0D33AEAC0F0A8EEULL,
		0x0111EEF669D8F47AULL,
		0xC7588D170EF0692BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x96A6EE1F3ABDDFC3ULL,
		0x19EDD15EF3B2E8D7ULL,
		0x5EEFF92028C1F328ULL,
		0x2F7CEF6704575DA1ULL,
		0x9D4EFE2C904421F2ULL,
		0x58C1C65B42E72943ULL,
		0x730270A6388DA492ULL,
		0x30BDAE83B573BED4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4D71F4105B5E24A0ULL,
		0xDF0BCD6158FA32A5ULL,
		0x8C8ACE282B9FCF3DULL,
		0x361015490D86B141ULL,
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
		0x3A00E5A5D5818CB4ULL,
		0x657DCA57A8DF7477ULL,
		0x273198FBD349D0B6ULL,
		0x85A28C84DE9080BEULL,
		0x940ABF95DECA1377ULL,
		0x06575EB44906E855ULL,
		0x0D0BD9D09C3286A2ULL,
		0xA574602F9E69902AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF362265384F29A48ULL,
		0xDBABA931FF29D409ULL,
		0x30D43BDD4C16EB80ULL,
		0xC9ACD7632CF399C3ULL,
		0x2EDE26930D3A6872ULL,
		0xAE1524368FABB617ULL,
		0x9FFE22AE83BFB6B1ULL,
		0x0A79E7E1288F211CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4B3D75BD6BE25881ULL,
		0xA3A6CFCF2D3F15B0ULL,
		0x26668C2E283DC2E2ULL,
		0x3D2390C7300962F9ULL,
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
		0xE30D9B900DA6CCCAULL,
		0x924E958F0BF1EB19ULL,
		0x873029229CB80EC5ULL,
		0x7B01769C80492730ULL,
		0x6ED2216B02F38241ULL,
		0xF820E247864D7716ULL,
		0x7FF25556805EBAC1ULL,
		0x82917AD1507D97BCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x35C6822B18C145EEULL,
		0x912AACCE7481BD9DULL,
		0xB921AEA78F082998ULL,
		0x0EA5D23AF3E57459ULL,
		0x3A8CD635B4067096ULL,
		0x37D43F4F90FF6B66ULL,
		0x132B49980AEE91B3ULL,
		0xD50A36FF139422B1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6F90434EAC162476ULL,
		0x8C84198F0105E9A4ULL,
		0xF39A38C07C55FD5DULL,
		0x2E6FB596970B1288ULL,
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
		0x9D01A22D2934CA1AULL,
		0x1D0B67334CFC03DFULL,
		0x222E4419DF460A6FULL,
		0x974B111C25F81241ULL,
		0x809D76BC28FC4043ULL,
		0x61CA319ADCCFC3A1ULL,
		0x0F916465F28CA252ULL,
		0x20AC39B9A7570F3AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5D2B70286F3ADFF7ULL,
		0xE896A4262F420537ULL,
		0x80FDF33A362E0451ULL,
		0x5DDB5E6C7A848984ULL,
		0x582AE6B9CBAC5380ULL,
		0x4C782497D2234A88ULL,
		0x8D9F724198DC7B64ULL,
		0x7236F613BE5B1DFDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x40D7925E93D70D4DULL,
		0x5EA2B180B353F864ULL,
		0xEB1A4244F93DCD74ULL,
		0x1ED7BD5040D957B7ULL,
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
		0x5F3B107343C7E241ULL,
		0x3005BAFE2D865208ULL,
		0xCC99C3E0711E4B93ULL,
		0xC76052AF4D9A75B5ULL,
		0x9716824B49A0BF3DULL,
		0xA513FB7D241170DCULL,
		0x429FCF88B1A7E225ULL,
		0xB6E664083682F838ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA6EE638CE47B4F42ULL,
		0x25EF5251958BDD60ULL,
		0xBDB10803B82F1D37ULL,
		0x24F6F0C2CBEDF8EDULL,
		0xCDB89B3143345391ULL,
		0x121BC332E80DE1A5ULL,
		0xC3818A1CBF276B59ULL,
		0xE492E252847077ACULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9C3CFAC353648D90ULL,
		0xDAEEC3B18081B6C9ULL,
		0xED6709E2B800D0B9ULL,
		0x5ACEA2E4F06B917CULL,
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
		0x82C0170D4FAC5EEFULL,
		0x45F3026A8D5AA515ULL,
		0x99403B1EB22B0CC5ULL,
		0x818345CEB2354D94ULL,
		0xA6F1AA033590DA86ULL,
		0x320742B83036CB7AULL,
		0x8636476C3A8F2A37ULL,
		0xB9674F45FFC29CFCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9F155D1DBC0FDC97ULL,
		0x51DD2D4016F7AD93ULL,
		0xED06817152CAECCDULL,
		0x4616555C3757A51CULL,
		0x660FFBD2C7018FFBULL,
		0xFF9F456E43EB3E10ULL,
		0x18202C3BE2CDA668ULL,
		0x9E1CAF1F8842391AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x852A951FFCE19392ULL,
		0x6F856E238999F547ULL,
		0x0381C2DA6619B093ULL,
		0x4880B62837EC7C14ULL,
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
		0x1D419C62C9322DD5ULL,
		0x1A95B015DBA0E407ULL,
		0xEA57C22C9CE91754ULL,
		0x566880C1B23F8D61ULL,
		0x79452AF4A9B106EAULL,
		0x3686FACCFBF2DC21ULL,
		0x0699B797C3BDB3CDULL,
		0x056EB9A8C9A86D58ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x436190D8F480497AULL,
		0x4614211755876633ULL,
		0x91C42FD1C250A94DULL,
		0xABF9D56C13AFD89CULL,
		0xF714503D6C3701F5ULL,
		0xCCBF1733F9C2A7EBULL,
		0x9972968E7BF6A84FULL,
		0x4B12F35F33038D3AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2D2082BCF4CE9F17ULL,
		0x882D57B4D9413DC5ULL,
		0x8C6279BB822422A4ULL,
		0x540E1A41FB08F923ULL,
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
		0x8FE58A6703115609ULL,
		0xAC9EB628BB761D45ULL,
		0x1DE6C792766277D8ULL,
		0x6685F1024FE628C5ULL,
		0x54836BCA2B6D7E2CULL,
		0x44E0568CF8A4D120ULL,
		0x089E894493345A77ULL,
		0xA2DF5E9BEFC93CCBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE77E9C9CC2139D5FULL,
		0xED9EAFDA88C0B671ULL,
		0x2D60E6D3852B78CCULL,
		0xD60A4B1CBE9CAEDCULL,
		0x56350F5EB53D268EULL,
		0xD980E47234576A57ULL,
		0x2854B0A98CF642E3ULL,
		0x9F3AB7F40D5CDCC0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6808A5BDCC2ABA1EULL,
		0xAF2AF6475632A8A9ULL,
		0x3B7C07C1DE6E7EEDULL,
		0x1AEC62D12D5FBB86ULL,
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
		0x4F6E5777718570B9ULL,
		0x2344EC9D5B2BFB01ULL,
		0x60F497FE37E6C269ULL,
		0xCDC3C3781E5ECDFAULL,
		0x46D7D8769EF9DB53ULL,
		0xC444EA122998FF4EULL,
		0xF4EDCFE3BC7F589FULL,
		0xB7090D795F9F94F7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEB30CFAEF82A0EF2ULL,
		0x14B596E3B22B7EB4ULL,
		0x444B7DE646E01DB7ULL,
		0x831F667CD542CE33ULL,
		0x05839EA9797CFD01ULL,
		0x8800E4BCED943F88ULL,
		0x7FDFFED329869A13ULL,
		0x3429E4C63B590F3AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x16BE1C3C09E464D8ULL,
		0x00A8206091B4F3BAULL,
		0x7CB6228DC1F2ED83ULL,
		0x37C46792AB93D9E6ULL,
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
		0xFA80E702BADF740CULL,
		0xD6889D6C3D99FA19ULL,
		0x822C73AA3DEDCCA8ULL,
		0xC248AD497D97480DULL,
		0x3B7352E54E8BCC0EULL,
		0xD30E47BA984983CAULL,
		0xDE58F932DEAF3CDAULL,
		0x68424BEEBE7B3392ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC8EEDA1657F57CBAULL,
		0x0A65E7D57FEEAC62ULL,
		0xB33BF078BEDCEEF1ULL,
		0xB8E1399871CD048DULL,
		0x37238ACCB23A1A89ULL,
		0x7552D76DE60C25C1ULL,
		0x69F8D3AD6065BA1FULL,
		0x4113B4BB47BB1076ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD569C093970A51E1ULL,
		0xB5F560F932C7430DULL,
		0x153615023DFA4587ULL,
		0x5A51E554AC4F79B9ULL,
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
		0x8DD1A73E452CEE3FULL,
		0xDCE1317A5C241344ULL,
		0x26CB90132CF31B54ULL,
		0x0ECB0E1CBD6CE1DFULL,
		0xCF4233618F05823AULL,
		0x4AFF83FE258E0EE9ULL,
		0xFD72A9853A62DC62ULL,
		0x94CC48F7C0E579B7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD181FE5F47C184A2ULL,
		0xA333EC3D039751D2ULL,
		0x9A49EB4AA142901FULL,
		0x39E44EF08C4EBF03ULL,
		0x510D9055409F5B08ULL,
		0x737D4006708A6268ULL,
		0xE0A6FB7244123C5AULL,
		0x990EADA13B836931ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x781FDCB2A0953AE3ULL,
		0x37035C0237185CAAULL,
		0xD2BD7B991BA84C5FULL,
		0x330BCE03FDAC96C3ULL,
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
		0xDB861046A47824C0ULL,
		0x383CAE4D014153A1ULL,
		0x3C9879BDD14C9385ULL,
		0x94971E82E4A5ABDAULL,
		0xBDD87932E461E1F3ULL,
		0x084E2321CA37C9EFULL,
		0x5ECFFFC7751AF7A3ULL,
		0x0B7C69D22F2AA5A5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6C99497FEC53AAD0ULL,
		0x5B067B30C62C0D0EULL,
		0x7A6049C5CC429F0CULL,
		0xC4478DE027BD8973ULL,
		0xD571C70BC5362DACULL,
		0x4FE468ACFDA41D09ULL,
		0x91D50DBC540EBBD5ULL,
		0x2598F32B2CE1B801ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEE2B389558A13BCFULL,
		0x3CE7E0729900F0B3ULL,
		0x2F781D9EECDAD502ULL,
		0x70132D6D13BB68B7ULL,
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
		0xF4BF98CF44DBA184ULL,
		0x26675D38734F8204ULL,
		0xF2C9C12614561509ULL,
		0x3DE9F8076998BFF0ULL,
		0x15D175B57F534CA4ULL,
		0xB4BFC01B3B823B24ULL,
		0xF7C49E24E951D3EFULL,
		0xBED162D7E9A5F968ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE6C103EEE7E88146ULL,
		0x6E7088DA7CE9A277ULL,
		0x9BA871A57C0CA696ULL,
		0x62CA7E701A5C41D8ULL,
		0x951B6AD89B4235EBULL,
		0x0AAD51F3DEF41294ULL,
		0xE1EDD565E70F4910ULL,
		0x7AD5E87C922BDED2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x290431AA377C811DULL,
		0xF6B32E35B37FE4DAULL,
		0x95031BDAEE2A0BA5ULL,
		0x7273A3264B5C705FULL,
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
		0xB3F133B88E3CC446ULL,
		0x247E897950CB0461ULL,
		0x2C0A5295E483D434ULL,
		0x39CD25EEE90AFC0BULL,
		0x9581B2C607409974ULL,
		0x71DCC8245348DDE0ULL,
		0xAA0308F767C6C53AULL,
		0x940CC60D0DFE1604ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x30588950A8780CC7ULL,
		0xD666B03668DF9963ULL,
		0xF3048B4ED2310BD7ULL,
		0x34564AEB367E444BULL,
		0x3432E03B61DF47B9ULL,
		0x15495F64821502CDULL,
		0xD82D56018197814BULL,
		0x5F36535FD1DB8B2BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF54BEAFC7236DA5EULL,
		0x0BF965BBF59DEFDEULL,
		0x5EBE57C73D56DDE4ULL,
		0x5D4BE0BA9FAD53EEULL,
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
		0xF187F4F4A883B80CULL,
		0x8DC061C8700F46C6ULL,
		0xAEE0D95831F3DFDAULL,
		0x1436A178D2FF9F15ULL,
		0x33131EC3D68F9F5EULL,
		0x2D987BE91496BFB9ULL,
		0xD14C77CCDF1AF2C1ULL,
		0x163C46FF0A5D930FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC78F8C2BF1FE2030ULL,
		0x6F6D59FDBAACB139ULL,
		0x6DD79E1698C408C8ULL,
		0x33095E8DE734527CULL,
		0xDFA55DD15CAF93ACULL,
		0xB3F823E3E04025A2ULL,
		0x57DF931F93CECC0AULL,
		0x88A10D5B3F3335B6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8C430CC6CDC751AFULL,
		0x2C2018907A3D74DDULL,
		0x47332CFAC67D9628ULL,
		0x6637D13B141527E1ULL,
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
		0xCF62E92CE2944170ULL,
		0x497D3E0930731FD0ULL,
		0x990FE3D49AEDF144ULL,
		0xC05FA5677C8F2E61ULL,
		0x26FC6250A0503C54ULL,
		0xA7A21EFB4F882FD3ULL,
		0x3FE79F53A9CDEB0EULL,
		0x422A783FE23C2E9CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB2CC9679B65770F6ULL,
		0xBF05A71A298B859AULL,
		0x11EAB46E5CEB242AULL,
		0xEAE04FFD9ED85336ULL,
		0xF008869CB010444BULL,
		0x81F3E390AEA8A6F3ULL,
		0xA85E523B2CE102C2ULL,
		0xAAE802F5797168BAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x44C8EF68D5BB9F70ULL,
		0x225468C2E815EB58ULL,
		0x0586A108C92D4867ULL,
		0x495CBE756BD03AA8ULL,
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
		0x939A03E0C4BBD627ULL,
		0x41C73DB699A7C5DBULL,
		0x7D9B226076C9D5C8ULL,
		0xA507E2D7E838069BULL,
		0xE4AAFCAE8094669BULL,
		0xCEE435E0E13D6FBBULL,
		0x450BF56B16A8FFC5ULL,
		0x4EFCF55FD767AEA7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x791CAC317056C666ULL,
		0xF0070A30AE6220E4ULL,
		0x849310C95EF20BA4ULL,
		0x1B2E256592287A3BULL,
		0x6B1B3B5E9BC0A4B5ULL,
		0x5AD3C2F0DB0BBB2AULL,
		0x3A6EFE983276FAD1ULL,
		0xC5FE48169C898B2BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x25D4098B4BD3D54CULL,
		0x8C314326D6A6728FULL,
		0x8C54B4E4F744866CULL,
		0x5FA776511308D0C9ULL,
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
		0x2B73ADF3A96DCB50ULL,
		0x4716492BE859E0ABULL,
		0x6F17F4A1FE7483E5ULL,
		0x7191B0370757A090ULL,
		0x90656EBAA70E1382ULL,
		0xC4C49E8167C5D47BULL,
		0x19606274EEB1CB6EULL,
		0xCB84FB8304CCE6C5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x018D4368842F982AULL,
		0x69C6B8B608EF98B6ULL,
		0x80F1AF4A26FD8C0AULL,
		0x414404B0E68B2E18ULL,
		0xDC42F913734CCF47ULL,
		0xB91E3F30C7BD7DC7ULL,
		0x55E1651EE8CEE063ULL,
		0x396E151B8203AD9EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE703E15CD3EE5719ULL,
		0x9801B66DA0A726A1ULL,
		0xF2FFE01CB725DB7EULL,
		0x5FB3DEE38AAAEE38ULL,
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
		0x3A4E4DCB64C650A7ULL,
		0xCE0B6CFEB7CA8B23ULL,
		0x312F8F0F0693B6B4ULL,
		0xF8573D88D568E4ADULL,
		0xFF8101F60FC95D54ULL,
		0x6D75573404AFAFDBULL,
		0x8FCB66818BDBE1B5ULL,
		0xC344BCDB7B27E11BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x69927A36090FDDC4ULL,
		0x5A5BEB37DF1670D3ULL,
		0xA5F7EB0CF59E33A9ULL,
		0x84EB1BEE7364550DULL,
		0x58B1BE533DAE57CCULL,
		0xAC63952D78CD0C74ULL,
		0x4B50FB86F32FD234ULL,
		0x4C560A8763342837ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x937FDDC08BB947BFULL,
		0x1C524EBF9C585BB2ULL,
		0xB5638534BA7FD028ULL,
		0x1ADA9A15F0320181ULL,
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
		0xD521D89EA3F94E96ULL,
		0x9F4F14DD3BE24619ULL,
		0xC82A3827853EC0C3ULL,
		0x0D6257F54801FE67ULL,
		0x1FD5A8B1F39ADB51ULL,
		0x3BAA99B9CE4556E2ULL,
		0x94D844E3442C266EULL,
		0x829EC6F60FB4DEC0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCF61AAE4E4842B40ULL,
		0xA20AD33E971A5410ULL,
		0xA0A52F8206962A6EULL,
		0xF70205BF77D15E4BULL,
		0x8DE5C99624A4147FULL,
		0xE5955C58D156E478ULL,
		0x86FB341C18DD9270ULL,
		0x8460E07D280B177AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAF5B4BDA7816A649ULL,
		0xC46B5E04302CEDB4ULL,
		0x36558635EC528DEFULL,
		0x5390882833643482ULL,
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
		0xC689586E4E79F6DBULL,
		0xF66A62DF550A6159ULL,
		0x3AD048F40558ED9FULL,
		0xFD565D396DCCC549ULL,
		0x5110E739B5D5B0D4ULL,
		0xFF97AB105CC5EC59ULL,
		0xEA615A6E41447D0DULL,
		0xF8114B250B0CFB8FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5103BE1B88281CAFULL,
		0xFF7A277C3C1D90C4ULL,
		0x2AF396E5BF2ADA9EULL,
		0x0562E868622CB2D2ULL,
		0xF4D5D9A250593E5BULL,
		0xEE88887229605F3FULL,
		0xE535ACDDB57909A0ULL,
		0xB4418C846FAD39E4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x26499ECBD6CAD9C4ULL,
		0x7F2F5EDEB9FFC259ULL,
		0xD458758306613531ULL,
		0x08C9C0A81BD6D1D9ULL,
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
		0xF382F3D5E37E5550ULL,
		0x3E8C35C472BA1658ULL,
		0x932C7FF849DDB916ULL,
		0xF76643A8132E74F7ULL,
		0xACA7173D85048C33ULL,
		0xD9BD423DC9CD8856ULL,
		0x2B064802817044B3ULL,
		0x05843E3ECFC9CC02ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7CB62307BB291D75ULL,
		0x755F98641B218D7FULL,
		0xF05FBDDD9A64A6A6ULL,
		0xEEA71C27BE6519D8ULL,
		0x8FBC3715DE59BA5AULL,
		0xA8C00315157A08F6ULL,
		0x17A144020C21B1ACULL,
		0x60C324A6EDB7A40AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC1AA16B0E5B05BFDULL,
		0x0EC3FD6B1BFD711DULL,
		0x83CB5A2C1922E581ULL,
		0x7D68F40BE37B49F1ULL,
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
		0x9C76C07936DA9873ULL,
		0x97C998C393A76ED8ULL,
		0x253C439A48BB116DULL,
		0x9E8E4E1EEF7BBB81ULL,
		0xA7E91E1DC60EBDDFULL,
		0x6B10D24955C9B5DFULL,
		0x854F1B482C204787ULL,
		0x9CAD66F4FA82452DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCB7214BFA0C1D625ULL,
		0x0C94F85060BC29ABULL,
		0x31B736832735B1CEULL,
		0x838A2BCCB5590E6AULL,
		0xAB738095D7D82A6FULL,
		0x6BC7F4CFC420FDF0ULL,
		0x4175C2FA9BF06FE2ULL,
		0x724F8E7C544E7FFFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4A7A0DE6F232A5D2ULL,
		0x7005807ED1F692A6ULL,
		0x05C8289A889F621DULL,
		0x64F2443AE5D1F1F5ULL,
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
		0x61337019F213AF99ULL,
		0xA65ABEF298596198ULL,
		0xFF432BF936CDA277ULL,
		0x5DC842348BF4EF37ULL,
		0xA02C7ED7D95A7FC9ULL,
		0x982BEF94D08C7178ULL,
		0xEDC0CD71D5B411FAULL,
		0x2CCF240478384898ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x382EC181193B2CF9ULL,
		0x59E347A804BB2171ULL,
		0xC8531EC16586B7BDULL,
		0x591D29B5B3F256B6ULL,
		0xA00EBE5E4D5EC5B4ULL,
		0xE03F992560942B9EULL,
		0x935962BB3DB7A8A2ULL,
		0x39498379311EB09BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2D6F40A3A0362172ULL,
		0x998C4BD532789E83ULL,
		0xA249E45260BE8DBFULL,
		0x2A80ED2B65CF281CULL,
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
		0xB121A989154128C1ULL,
		0xDDFF02EA30DB904AULL,
		0xCDD80940EC65A308ULL,
		0xE1F3F0AA26BA707FULL,
		0x911A015089B4ACE6ULL,
		0x85AE482BE08ECFE3ULL,
		0xB7D1E726E3B29231ULL,
		0x85E3637137ED4739ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5C9983314DB2F497ULL,
		0xE47CF4906327C8E9ULL,
		0x51668F51336610F5ULL,
		0x2AEA49377C71B3C5ULL,
		0xB9EAF2F2085BD436ULL,
		0x892193DFCDC1ACCDULL,
		0xFF62B63F18E1E30BULL,
		0x23D39B2771A72DD9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4584485EFABE6084ULL,
		0x7664D1A49826FC9FULL,
		0xDCF2BC57D3F991B6ULL,
		0x4561626618B080EFULL,
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
		0x529B442FDF4DCED9ULL,
		0x73D3C1D453482B80ULL,
		0xE9E3588D7CF4D834ULL,
		0x2F654F1427B460BDULL,
		0x8AF889F5A91BB923ULL,
		0x35E9887174BD76FFULL,
		0xF24CDF66BECF287CULL,
		0x257B54D8B36D00FEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1FAE888EF205F8EBULL,
		0x2AAD81D26F85B5FAULL,
		0x884F193B43278087ULL,
		0xB83D97024A1BD14AULL,
		0x6397E0562EE38F92ULL,
		0xBD18FEF01596E80EULL,
		0x13D0A0E3E956B03BULL,
		0x5C3BD75C6E12E508ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0B45E94D119E001EULL,
		0x381AA936037BAD52ULL,
		0x680586BDE9AF313FULL,
		0x5694588428F8B618ULL,
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
		0xB82BF3D9005FFC0CULL,
		0x2EDF757308B7F23FULL,
		0x2ADA91AC45664416ULL,
		0x689B4AD60F6A7ED4ULL,
		0xD02ED06192866470ULL,
		0x45B58103A7B8EA4DULL,
		0x14870966D3B0F741ULL,
		0x8E95AEE671F7BF23ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3AB3AE4D06E2046BULL,
		0x9A2711C8312AC55CULL,
		0x0F662291A1D51CB5ULL,
		0x78CA470BA58DFB07ULL,
		0xB6A179D38E0EA3DDULL,
		0x2658071DE1574EF0ULL,
		0x91A61B986150CFCAULL,
		0x758DDE4040FC125DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x48731EA0A3448DF8ULL,
		0x3C987BC64A0A3CB5ULL,
		0x88D7BBBF9DD7030FULL,
		0x26F9FC75AF38291EULL,
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
		0xF65B5A8E46BC266CULL,
		0x2907224762229EF3ULL,
		0x5AA78B86286355D1ULL,
		0x9B73CAFC93886168ULL,
		0xECA0D37A373B076EULL,
		0xC143E89E81E22F9DULL,
		0x6C34CA6E70BA4A44ULL,
		0xFEA0D098B5EEFD13ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7AD49495DD7F5CFFULL,
		0xDBC2DED4D315F78BULL,
		0x000616FD893B9F34ULL,
		0x62450AF3A8BC1FC0ULL,
		0xCDD0ABB935422528ULL,
		0x37CEFC7EBFBD1ED7ULL,
		0x2303D82F98A70FD2ULL,
		0xA64FFC582E6824D7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0E6CAC9EB42E61BFULL,
		0xB49F5029608D24D1ULL,
		0x37E569DCB202639CULL,
		0x552E419D08D05A9BULL,
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
		0xA765AF49E4D58E94ULL,
		0xEECAA4B3FADDF20DULL,
		0x476ECB15B89FBF21ULL,
		0x6B8940E5FDFFAA85ULL,
		0x3FCD64F951F005A2ULL,
		0x5A2BEF4148F4F75BULL,
		0xBD586C85806670D6ULL,
		0xC9E9F70865AAE8DEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1AFFAB79B70C6B51ULL,
		0x26145A5A7893449CULL,
		0x597A6E5D703FB4BCULL,
		0x9FAA21037A358193ULL,
		0x17559578D1FFE2A0ULL,
		0x9F9853D20D3BB475ULL,
		0x1ECC851DCF0CBC22ULL,
		0xBD0F8DCDA304549BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8E2ED0E32B6E55C8ULL,
		0x7A9F5CDC5FCA9B9BULL,
		0x76B8B61C9BB0DD13ULL,
		0x344ABE9B68842AFBULL,
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
		0x465B463480EAE9CFULL,
		0xFC524EBB3F5745ACULL,
		0xD8A118AFC42415B6ULL,
		0xE3E0D4312F895503ULL,
		0x6AA8511D5A04DED6ULL,
		0x91C2ADE69E16D22DULL,
		0xB937BF65EA433D5EULL,
		0xC0168B79DA5C31A5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x62168527E45004E3ULL,
		0xD1A78F01D40A3235ULL,
		0x929E8628BF958D16ULL,
		0x94FB1100959DE40CULL,
		0x2BF99FCEAC25C8B6ULL,
		0xD52D7F2F9B4D951DULL,
		0xEFAEE71D62D9389AULL,
		0x3EE30DC6E91546D0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x323312BA6BB8307EULL,
		0x28CFAEE3D52C23E0ULL,
		0x3052AD4B1E4B3DAEULL,
		0x7C8A6BC06A724C8DULL,
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
		0x18DF7CC9B9DA340EULL,
		0x0EDE2804AF424707ULL,
		0x8CD82EB0EA861551ULL,
		0x27496A4150077628ULL,
		0x19F4315B92A8F708ULL,
		0xA70BF63B3F40E0BAULL,
		0x6BF9B80DD004A2F9ULL,
		0x116886EB287EFEF0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB83B5869DBE2DA6AULL,
		0x10C008EC77B1727AULL,
		0x29ADFF8DA916DA42ULL,
		0x4FEC499291D474FFULL,
		0x1C840D132039CBB0ULL,
		0xC8D75DAD1869B0B8ULL,
		0x37F250B04DDE6C10ULL,
		0x2507176C34152DA0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFF498720DA77C82FULL,
		0xF9ECC431FB81F4D7ULL,
		0x1C438704931B619FULL,
		0x6DD3AD8705E81311ULL,
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
		0x74B46BBA00860E69ULL,
		0xADC755EE4EE32162ULL,
		0x898F8E18611CC368ULL,
		0x6CCB405AF952C9F9ULL,
		0x5F606739670DEF1EULL,
		0x736CF0BB58994353ULL,
		0xCDCA716EB8DACF84ULL,
		0x490B4C46034125F6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x048D914A0289B5C9ULL,
		0xA98B15DEF9FF0B2FULL,
		0xD5290768646DC38FULL,
		0x9CCC1BEE9FA56C98ULL,
		0xA9963817F721DBA9ULL,
		0x44A57F147495307BULL,
		0x76A4D69D1B9A0B8DULL,
		0xDD957641079CBB48ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6C29D9669B0738A7ULL,
		0xF5D71ED52D7EE238ULL,
		0xA3FB81CD544C1689ULL,
		0x437CE929B4153341ULL,
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
		0xC17F7B40D8453759ULL,
		0xA1DB1DBFD01D6ABEULL,
		0xF427503C5C91C883ULL,
		0x4681B3F4D05EEAD6ULL,
		0x32DE1F330389A058ULL,
		0xD9600994942F9C6AULL,
		0xD18163D5D3712C98ULL,
		0x9BC90299A40C9265ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x05D491B914BF3878ULL,
		0xC56C93F2D432E470ULL,
		0xBE3707BBD4CB0615ULL,
		0xBB030E95DF646C2EULL,
		0x84C9CAE70C414F22ULL,
		0xC2DACA394BB7F509ULL,
		0x6BB581FB48D49334ULL,
		0xC6D969BD096FE3EAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x92AF6CCE78420BDBULL,
		0x3435F159BDAD5EA8ULL,
		0x5233CEF11B058749ULL,
		0x270F561DE43C64F9ULL,
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
		0x9947993ECB0250BDULL,
		0x09191530AB5634D9ULL,
		0x55B861DF7FE8D82EULL,
		0x32FD52DE8C1903BDULL,
		0xCA60CEB2C924B208ULL,
		0xF8ACE7EDE360C8B3ULL,
		0x837D9CDBE2686C75ULL,
		0x8658222D175D4639ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBBDCE4C2D0440C15ULL,
		0x2ADA8F369959A649ULL,
		0x8B1883CCFDC3DEE1ULL,
		0xA7820057EB16B7B7ULL,
		0xF65997BC6AA94668ULL,
		0x6DF54D29A3774863ULL,
		0x0265DAF0D0E5D104ULL,
		0x7AE32388D25247A7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x567CDD0E01103E8EULL,
		0x757F7F1B8EA59A69ULL,
		0xF426A6F71B880C27ULL,
		0x3ED91EE8E0A415C4ULL,
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
		0x6FFC32D443FB81EBULL,
		0xCFF00F03F9FD8086ULL,
		0x43113A6EBB48F3BBULL,
		0xD1FDA835D35D517FULL,
		0xFE41CD0A12F4F5C7ULL,
		0x2D4A69CE880779A6ULL,
		0x262252994FD700D3ULL,
		0xDB50DC5D24453AA6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x826E08152E9D5FF7ULL,
		0x96C32D668E594F0DULL,
		0x4892194B938E09C8ULL,
		0xBD845D727CD6B4E0ULL,
		0x866E262C620B6249ULL,
		0xCF81866663D7A097ULL,
		0x3768C66292FB5CA6ULL,
		0x95D10FB767F30422ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB6F8EFA7580A0824ULL,
		0x24FEA312CABE69C4ULL,
		0x6A09F14330554889ULL,
		0x6571AB5D4ABAB434ULL,
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
		0x443B85BF01A0682BULL,
		0x8EBB9CCE9814F62AULL,
		0xAD99FD9C0BAA0C39ULL,
		0x30DC98D63DBBDB8DULL,
		0x829D87B1E13D9A4EULL,
		0xD16908B050F9D6CFULL,
		0x642D7E9E64794702ULL,
		0x27041F83A3932181ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3A22B72C9A543745ULL,
		0x4616AFAA4DE9112BULL,
		0xA937BEB67766BA55ULL,
		0x8E8F50865650C600ULL,
		0x9919BAEB7739B346ULL,
		0xCCC0A118E6C40834ULL,
		0x9D67005D92E7BB09ULL,
		0xC35E3B86A9E6153DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB3A9340623E07886ULL,
		0xF9A44D9E0E288FFDULL,
		0x85D8FC84AFDE18DAULL,
		0x6CED1FDCF71AE79CULL,
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
		0x4CBA37CAA327EEDCULL,
		0x3B1DCD3E3407CD9EULL,
		0xCDE28F5075B38B78ULL,
		0xD1F560A0B3ABF05BULL,
		0xBA96CEB06E0F1481ULL,
		0xFF1148FC7EA7DD0BULL,
		0x1E6004743E771CEBULL,
		0xD49DA2ACEE2823A1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7E6FF8B793770FA2ULL,
		0x8C445CDA6A76B416ULL,
		0x6210BE519DB1C135ULL,
		0xAC88A4B12A115305ULL,
		0x6DA2890FC8D63D2BULL,
		0xA7A2D7FFE410E3ABULL,
		0xAE66962CD6C74EDEULL,
		0x8A7CB663B00A8F1EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3A8C94EB9620D7A0ULL,
		0xA93E35E2BBFA1DD3ULL,
		0x0AD82F983C1A603DULL,
		0x264FCECEC1FEA8B3ULL,
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
		0xE8E98AA923BFC015ULL,
		0xB3366C66F55EAAC3ULL,
		0x97647B1A65C0F9B5ULL,
		0xA0250B3359C3FABAULL,
		0x985C3F631D8C986DULL,
		0x2871A096AC8CE882ULL,
		0xE63980A249CA51AEULL,
		0x6A1F187D07368394ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4D8075EEA0DD2A21ULL,
		0x70076F1BB065895FULL,
		0x5FC798158B0DC406ULL,
		0xC30E935EF0D9212DULL,
		0x851D9AB525BDB34BULL,
		0x4B3C40100CCB1266ULL,
		0xC5340C86B1ADF820ULL,
		0x531510E8F8171718ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x76B5868D4B989972ULL,
		0x191B5146FBBEE98FULL,
		0x1E6C1F1D6EE880BEULL,
		0x489397CEA794F3FAULL,
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
		0x2C434DBED5EF4C9EULL,
		0xA5B211C3B3B88453ULL,
		0xF7E98B83EBEB9115ULL,
		0xC7AF1A1E16920618ULL,
		0x186D495525A04CECULL,
		0xA3DAE1DD1BD27A8FULL,
		0x41E8B4BBDDBE67A7ULL,
		0x56A18A674B2643A9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x010219568415E072ULL,
		0xD40844E640F24376ULL,
		0x8A94D806240BB53DULL,
		0x337DE850C014F9E6ULL,
		0xDDCBB27A6EE0AF38ULL,
		0x48B143F6D172E2A1ULL,
		0xC66C1B13ED5099C5ULL,
		0x9E57CEC72ED9F7AAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDF3D98DF724AD355ULL,
		0x59D73D0C7CF6CE13ULL,
		0xC1D3826B782C6B71ULL,
		0x6F230B9189D053F8ULL,
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
		0x506B369727334366ULL,
		0x14739438601F49FDULL,
		0x241F6EE8234588DBULL,
		0x9C1B76C31C851317ULL,
		0xB85CB180658E98E1ULL,
		0x56964EFCF6D19577ULL,
		0x5633AB18D35BC503ULL,
		0x16649E3F75713B62ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2FDA7B1494E6B76AULL,
		0x80017B7377E8B23AULL,
		0x23AABA0BAE3B5D2BULL,
		0x6A23AF3F07C15E26ULL,
		0xD034CA4E9F05DE40ULL,
		0x4BF43D61DF45C0BEULL,
		0xC5952E6EE19C5E49ULL,
		0xA9746807FC4DC205ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x967D0CE60A983C9EULL,
		0x2880B5CA66F82B35ULL,
		0x77FB361657736B4DULL,
		0x5D9FD3C01007B8AEULL,
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
		0x11B4AFB4C5C24B8BULL,
		0xA222655F0409A891ULL,
		0x1F7678BDAA1FBACDULL,
		0x7F40A92BE21E1769ULL,
		0xF0E04FF08A1874F5ULL,
		0x94E50A874932B48CULL,
		0x24709CF9F371BB77ULL,
		0xAC2408E10C996F2AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF1F747688B13941AULL,
		0x7A0F5E3EDB4D119BULL,
		0x4C53A615460C9AEFULL,
		0xA5B8178F2D7858EFULL,
		0xEB5496BCAB53C59DULL,
		0xC3FF92C31800811EULL,
		0x4B0224CFAA2AB101ULL,
		0xF01C0D254A602EA3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF27AE5FF4BE0BCF2ULL,
		0x2A22CE3F76303949ULL,
		0x1988A8EF449EAD5BULL,
		0x42B7EF7B8925527EULL,
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
		0x101A2A678F633A6DULL,
		0x1EB4FB6733B09F85ULL,
		0xF5D728ECB90BB70CULL,
		0xC0E08FFE3ECD1442ULL,
		0x03C5DEC4E224F197ULL,
		0x3262D8F9841115D5ULL,
		0x522FF95FA06ED7BDULL,
		0xC6A4EC642E4B078CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7D18A5A97137B8A7ULL,
		0x5E8767D9131D89DFULL,
		0x20119170A650E479ULL,
		0x07B9AAA288AC862AULL,
		0x25ACAEE103981CF3ULL,
		0x8EF7ABB83280CEFCULL,
		0x4EB20201E1805353ULL,
		0x712B6B512DAA4BC3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8ABEA0912713140CULL,
		0x02164B403BFD99D6ULL,
		0x5A784F666A227A41ULL,
		0x69300E2DCDFC6DEFULL,
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
		0x140BB4578409C14BULL,
		0xD840A29261BC3256ULL,
		0xC322E9300D133302ULL,
		0x426055C7952A0374ULL,
		0xD3ADBA74560DF354ULL,
		0x8E92E0AA08C06C4EULL,
		0x95EA3EB4CDE9A1B6ULL,
		0x465A360D9C101E10ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDCDEFC154333F633ULL,
		0x99B64416F41FECBEULL,
		0x8FC6E28C941B3EF6ULL,
		0x6B3CDC4CBE343FC8ULL,
		0x78C54E81499B4DBAULL,
		0x4286A9A2A655DBFFULL,
		0x6222F28F65D1DE99ULL,
		0x3B0ADCA0DAEF8B81ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB5ACBE5619DA602DULL,
		0x885A8994096DB15EULL,
		0xE2F15430EC7EEA65ULL,
		0x04EABF9F81CB84EDULL,
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
		0x10F94BDCE6BA19EFULL,
		0x4673B5E7570BC27BULL,
		0x2F24E6F3AB3C8D01ULL,
		0xF25B0C7AE7E51979ULL,
		0xB985A7CDEDCF2C7CULL,
		0xC01DBD224D02DF88ULL,
		0xB5B784A13E3B75EDULL,
		0xDFF9F600AD582772ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6AE2D1ADFAF8AFF2ULL,
		0x4FEC0585AF58B69EULL,
		0xA00A3B68C5CCC6C4ULL,
		0xB6BE593A59ED6D12ULL,
		0xC141B7788658D048ULL,
		0xD517AF3CA25216EEULL,
		0xDF1BADC117939323ULL,
		0x95C2712224D37667ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x802C26DC47531B57ULL,
		0xD96DC078FDF0D2B7ULL,
		0x6A3C90D0A25B7035ULL,
		0x3FDA6C48D1A9F402ULL,
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
		0xD021770478C09907ULL,
		0x2B87C50DCF19803DULL,
		0x496847E233F8B1E9ULL,
		0x99CAF0EEAB65DFBDULL,
		0x5924781D2584CCAFULL,
		0xF9983F3118F0B80DULL,
		0x917CC66F4C26174EULL,
		0x8B1EDD1EEBC3D81AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1DDCCE07CACC239BULL,
		0x7E871E73B24C88F9ULL,
		0xEB3E2A6897533A29ULL,
		0x4BAE919501131531ULL,
		0xAAA9F65916567A5DULL,
		0xAAA497E32A8A0B7AULL,
		0x73F967B135B14F6DULL,
		0xD6DF1B4956F55D68ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9873EC16EED4ABF6ULL,
		0x652B7C2B800A950AULL,
		0xBFAA2DB0F1FB2331ULL,
		0x0F93250DC0F900FBULL,
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
		0x80A3FAF8E6503AADULL,
		0x3E9DAFE5ED7D868EULL,
		0x83A3CDFAD7EEA6C1ULL,
		0x91E5904A549F904EULL,
		0x6FBB162772638F31ULL,
		0x4EE80A8987F9DA19ULL,
		0x22582AABCFF00B79ULL,
		0x68E84576113B39CCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD289994BCCB4F88CULL,
		0x086F980BEFF2FF18ULL,
		0x6B9436A8628108BBULL,
		0x26FC81A8967E154AULL,
		0x7390FC16B67BBD88ULL,
		0x2421951E9DC61249ULL,
		0x25F38EE71B53343FULL,
		0xBE5A0E676381FF5BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1C5A4028FE045F5CULL,
		0x8FA385B8C13A3055ULL,
		0x8EFEB68544B590A8ULL,
		0x3C053ACF87A027C9ULL,
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
		0xFD243717C9B5D0D5ULL,
		0xF0E9DCF0CA43E56BULL,
		0xA9E08BB0DDCF8013ULL,
		0xECA7EE8C32070830ULL,
		0x0F0070ADDA9412FEULL,
		0x246386D5895D7417ULL,
		0x317068673CBE0649ULL,
		0x816D9AAFA7A72EA8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3703814A3E1D93D6ULL,
		0xFE6D526CB4BBF642ULL,
		0xE7D30138277ADE6BULL,
		0xE014E3F04202B5E3ULL,
		0xE8933B40FC1B3807ULL,
		0xFC80F514AED696ACULL,
		0xB19D7E7525D9320DULL,
		0xC9165CF2F305FD8CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7A56A3F69188BC07ULL,
		0xDE1E2D24858CCCEBULL,
		0xBB5C44681C4C226FULL,
		0x6986349EBFF19C61ULL,
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
		0xEDB6765C2EDD59ACULL,
		0x5B263B464F262C81ULL,
		0x6236F229759D5589ULL,
		0x2430917AB0D7251AULL,
		0x51CCEF01B7950FA3ULL,
		0xCD32784B62A9429EULL,
		0x128A11CD68B89851ULL,
		0x9284E5D3858D61B1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9826559130DE7E9AULL,
		0xB2B51370D06CED7AULL,
		0x8966B36CB514DFFEULL,
		0xC781C7E31E88CBDCULL,
		0x90EC89F0BCE76F3DULL,
		0x4B0E116452E85337ULL,
		0xB8CF69BE731B10CFULL,
		0x0E5F4A9CB7E8E4B6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF6DF215033C4ACF5ULL,
		0xF9D86E21D55CC847ULL,
		0x2A8530F535EA92E9ULL,
		0x7A43D3BA18B8E667ULL,
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
		0xF08F81449A3162A9ULL,
		0x972531AC8F6B6ED7ULL,
		0x1552C97B4BFAF517ULL,
		0xB5B69FC5C8C9D5CCULL,
		0xEF33422940E311FEULL,
		0x4737122A57399D12ULL,
		0x7A5AD5A34CFAA5DCULL,
		0x9B84E0FD88ABD3C5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC6F97195C7E21F7DULL,
		0x0B40B9A53FEB7669ULL,
		0xB174C33CF6B4C488ULL,
		0x953DB9493B651885ULL,
		0xD5B856F288AD060DULL,
		0x5B40F8A2D2186BC8ULL,
		0xD67D6D93999F0179ULL,
		0xF4C7153977C44003ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF1D4F9CE2A5506F1ULL,
		0x926C4225126D496DULL,
		0xB6BB7892F4E0973EULL,
		0x60A525970FC4AC04ULL,
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
		0x1BE5FD42CF630424ULL,
		0x0A872F5146CD3655ULL,
		0xED8D5C66878DC031ULL,
		0xF75CB18EB56FFB0FULL,
		0xFCDDB16E5C6D9D32ULL,
		0x80F78AB50A722EB8ULL,
		0x8AE22285E8BDE74BULL,
		0x4D829090B2B1A654ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x984E3CAC32FD42C7ULL,
		0xC6C6BCB66FDB6574ULL,
		0xF80BA3A6435E69FFULL,
		0x8190EF8CCCF97105ULL,
		0xC3E60F8944EA571DULL,
		0x4512ECAD6EB0BBDAULL,
		0x9E2C631F71EA543AULL,
		0x29714A31B2A10DFAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF859C89819E2294CULL,
		0x27AFE7BBF5A8DDDCULL,
		0x187C21F5E7972AC0ULL,
		0x505C341BEAED2763ULL,
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
		0x4E507CE51661B825ULL,
		0x5347B81AC3C204B5ULL,
		0x0989DD1E99F93FA6ULL,
		0xA6FAD76610106042ULL,
		0x6181CB319BB71707ULL,
		0x937CA0EA530922ABULL,
		0xCC2966D08CE7D533ULL,
		0x8D659B5713052FB2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCFDD923E8690B6E3ULL,
		0x791D8B5C54ED6E4AULL,
		0xD4F74FAA6DD33A9CULL,
		0x705F058ED71BD60CULL,
		0xB33B5514E11DDE54ULL,
		0x60F1F5BB8F3A396BULL,
		0xE32C08EB1CAE7144ULL,
		0xCF38D2359E96C697ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5CE872EA428F6A58ULL,
		0x5ABF95AF7F8B35DEULL,
		0xCA2E7D82D4AADA8BULL,
		0x7141ACCE81582433ULL,
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
		0xD13F50FD2DFAB444ULL,
		0x626E82AF7DB8B9E2ULL,
		0x3CCD6530F0F5EEA0ULL,
		0xA0D78B1B26CECD71ULL,
		0x0CF7E03FD2677498ULL,
		0xC0938B9FE29F7465ULL,
		0xFEEA0055A8D6B9B2ULL,
		0xE693380E644BF1D7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFC64ABA62E93FC92ULL,
		0x7B487CA040C4F005ULL,
		0x86F9FAF49F483578ULL,
		0xF3540ABC5FEAD202ULL,
		0xADBE9AEA57E86D9FULL,
		0x64EDFBD1FFBA073FULL,
		0x2070D8BEE054027CULL,
		0x9D318E26B2183B39ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF75AF0072E41C237ULL,
		0x81B95E9EEB01FD68ULL,
		0xBBCF4A9E1514EB39ULL,
		0x1202B8C33A911703ULL,
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
		0x47516CBFBF0A2DEBULL,
		0xF2ECCFD146F6B31EULL,
		0xFCB8F2C4E9E8AC78ULL,
		0x54982C851B1ED6A6ULL,
		0xEC52E1C634D0408CULL,
		0x6739AAA76C5BD3A2ULL,
		0x864DB3A5C49161AFULL,
		0x8563C0EA17594569ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x131B3742619F4964ULL,
		0x4F4DCE984429987DULL,
		0xF29A64DF346996EBULL,
		0xB1B4995FA184F048ULL,
		0x66AE698B46D64B6DULL,
		0xE6A94F42B2E9B9CEULL,
		0xEA09D7CDAA051571ULL,
		0xA97A05B77EFE1BFDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0AA00E3CB085463DULL,
		0xB90C922C89BCF02DULL,
		0x3C312FF9A65266AEULL,
		0x47955CA817220C57ULL,
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
		0xBE582DE2C0AD2AA3ULL,
		0xB757AEAC0DAF005AULL,
		0xA9B132E753C00CABULL,
		0xA5F100FDE458558EULL,
		0xBF51B6BA0EA67FF4ULL,
		0x9AC39D3529D7B4B3ULL,
		0x8AB021B5798F6D33ULL,
		0xEFF69F51A29475F0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1A5FC2EA414BDD75ULL,
		0xB704722D24F2B077ULL,
		0xA13D29F7CCF90261ULL,
		0x32E32A794FF1A0AEULL,
		0x9C65B32005B7E46CULL,
		0xD4AE2770AB14E57EULL,
		0xA906960A8E0C6B2FULL,
		0x29838F330932BD7CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD300F3D5D2CC67BFULL,
		0x6782B7A9B9A711C6ULL,
		0x879EC44E7C3956D9ULL,
		0x68223B0F58E81613ULL,
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
		0xE85F49D785C693EDULL,
		0x8EC80FFCF71737D0ULL,
		0x13C23B12A72C188DULL,
		0xBAF51EBFE23FDD80ULL,
		0xD1DEF9E9FC7B4EE8ULL,
		0xF07EA6554336E6B1ULL,
		0xC73045DE46E1365FULL,
		0x7D2A99D486B0EF0AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE371EC90201BDB71ULL,
		0x5672A1D18CE4B0B2ULL,
		0x84690ACAF9314F60ULL,
		0x3025DABB9F449F75ULL,
		0x9677C19261451F6FULL,
		0x8CCCC939D3D0B14BULL,
		0xECB281538BC779B0ULL,
		0xD30D442217C41DF7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD63FBA486FB5C297ULL,
		0x04BC403DF35E744AULL,
		0xFE045CDF73CCCB36ULL,
		0x4B29FC80BA2246D6ULL,
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
		0xCD004F645C4D654CULL,
		0xCD1345A760AF27F7ULL,
		0x944664D6BAD0456EULL,
		0x6A7C0A32957434A3ULL,
		0x2E1560B0F542E320ULL,
		0x51916333786138EDULL,
		0xF549FB2CE69E4789ULL,
		0xF05B99F7E4919E62ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD475217D36293884ULL,
		0x7D9EFFE8281E71A7ULL,
		0x5937588FBCA23917ULL,
		0xD9EEDD168518F054ULL,
		0xFD61359C89054D23ULL,
		0x96C400E591A14FF2ULL,
		0x6756624EF5B92604ULL,
		0xDF642DF1C14E5524ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x334992EF374870A2ULL,
		0x09F0DD4F790D4B73ULL,
		0x4D37BD38C031060BULL,
		0x154736054C582398ULL,
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
		0xCB3538BA7B64290AULL,
		0xEC001ED9419F574AULL,
		0x4A680CB5B8E093A9ULL,
		0x1021A7D5171AFE76ULL,
		0xF9AB59E0293AC8F1ULL,
		0x2C529003BD62F9CAULL,
		0x7FD2275E8561BC9BULL,
		0xB2AC293209DCDF81ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2F83AFD24E451A6CULL,
		0x2A9BF0B512E9AFDFULL,
		0xAD6746778D86067FULL,
		0xD26C96FDFA986EBCULL,
		0xFFAF54400C2ACF14ULL,
		0x59AA04A32365E7BDULL,
		0xD9083611644E66BCULL,
		0x0A5E1B15907EB142ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB71A5EAC7D7E28FCULL,
		0x0668DE7B0A465558ULL,
		0x5EFA97B114394C3EULL,
		0x394B2911207D6D06ULL,
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
		0x656D6E634B1A91DCULL,
		0x90FE7BA0A9AE970BULL,
		0xB3672798B1B728A7ULL,
		0xFF932767CE458BD4ULL,
		0x966F493E7F5961D3ULL,
		0xE5960723C911F033ULL,
		0x049DC6804AEE5A86ULL,
		0x90AB37928678DBB4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEE499CB649E1CD75ULL,
		0x57AE0E9B39C876A2ULL,
		0x108EC6C5A1156EF0ULL,
		0xA1B59F0E16FA8D56ULL,
		0xE6A30DD6B79AA156ULL,
		0xF9F51543BFCFEF76ULL,
		0xD3315ED9AF50C567ULL,
		0x5D5629084B7DB436ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8F74A314A7895812ULL,
		0x33345446CFB23C6AULL,
		0xF8EFC38E2A05DC4EULL,
		0x7C7DB0DE7892DB13ULL,
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
		0xAFA066B67CFDB35DULL,
		0xF7087127BD825A20ULL,
		0x897F6DABE2B0FCC6ULL,
		0x89958AB81F1EBB3DULL,
		0x6B7D7D6A9F1F1A09ULL,
		0x5054D455537CBED5ULL,
		0x3FCCB83F1E640496ULL,
		0xB9A5303BA94E31C1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4637F87C63E16258ULL,
		0x55CEF78962944DD4ULL,
		0x09C365DF0A927C2CULL,
		0xE0C8DF901DF49CADULL,
		0xE1C03929BC98FE67ULL,
		0x76471D17E19957E3ULL,
		0x66D86AB19B306D03ULL,
		0x77DB5A76B51B3EB6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDB808FDBB9046C67ULL,
		0xFF42ACBD42AF5426ULL,
		0xB3FF8ACE51C70066ULL,
		0x6CC2666440BA322CULL,
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
		0x5461F00E657DC90CULL,
		0xA6AE9990E67F418CULL,
		0x06EEAC3A000C3C58ULL,
		0xB2E7D372BD384B3FULL,
		0xD4DD672102C082BBULL,
		0x5C4F603C64CA8716ULL,
		0x3C0A7CBD2DCA3EE5ULL,
		0x34867C17C740625DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x968C205C430E5610ULL,
		0x7C7096BA01124794ULL,
		0x04D5E635F83A6A3AULL,
		0xD3B66DAC89366DF2ULL,
		0x6F1A75C6F9C22FEDULL,
		0xE6B93D2A6C26812DULL,
		0x5421E233A2089E59ULL,
		0x00C604673814C450ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD8C5A30F782FBEADULL,
		0x9E873781CDC5DA9CULL,
		0x6E9FB66EC68FA6D1ULL,
		0x0DC329FB747B5337ULL,
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
		0xDFC7255E44EAF1F6ULL,
		0x7417CE7256C09747ULL,
		0xD1B0878CE2C98006ULL,
		0x18544CE3C83E630FULL,
		0xCB3D585831BEAFD9ULL,
		0xD1EE906AA43409DBULL,
		0xEC2E62592B967C05ULL,
		0xD99984AC898DC9F7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE8EB83D2C32F1CA2ULL,
		0xCFB2B6A5E3E6D2B0ULL,
		0xD7B25D1FFA8FE11BULL,
		0x7403D8194EB0B76AULL,
		0x9DD51A0F986F30B0ULL,
		0x11D4226EA37A5C6FULL,
		0xACF66709D1F523AEULL,
		0x1AD071A4E670C128ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB454E0524388B97FULL,
		0x28516B348E6982A5ULL,
		0x5C4D7834362CBBF1ULL,
		0x762947ECAFDCFA68ULL,
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
		0xDB05DE34BF560260ULL,
		0x28FD8715505C3578ULL,
		0x82E68DA5E9E70D4AULL,
		0x25F7137155A068C9ULL,
		0xE04AA93345DBC898ULL,
		0xF5FD15D093AA24E3ULL,
		0xD053EA7C072E8DC3ULL,
		0xE95A089C4DB08322ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFD78C8A4551719F4ULL,
		0x205352C0D752D98BULL,
		0x49BC9F7BE86EFEABULL,
		0x536A835D9C07C423ULL,
		0xDB73A4C7C26F0C8DULL,
		0x8AA8DDF2869DD712ULL,
		0xCE483AEE0AE64F98ULL,
		0xEB8B8F1CF89A5668ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9577BD85EC62D1E8ULL,
		0xF72A7F4A68DCE8F3ULL,
		0x86E5FD3D74314910ULL,
		0x7F3298FA5AE34842ULL,
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
		0x895F9ECD262F9EE5ULL,
		0xABF6A95AF1859434ULL,
		0x8A33F17B6646784BULL,
		0x70B2AD18FBDD2B95ULL,
		0xFCB11A2EBF00EA5FULL,
		0x0224B10621C5249DULL,
		0xE8F88ED682E71F4FULL,
		0x6DC4907612E4025FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2A800A7AFEC0F3F6ULL,
		0x6F79D9FE069E4ABBULL,
		0x92D4EF550406FA35ULL,
		0x7A94E2DDC7027039ULL,
		0xAB1BADB0B2E6CFADULL,
		0x81D2CAE799DB62C9ULL,
		0xD20E500BD6219AAAULL,
		0x0F73D459827598B6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7B0DAF07F34EA35CULL,
		0x48A4F7E5179A0EFDULL,
		0x5E24543C07912E81ULL,
		0x7619B678A53E6A75ULL,
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
		0xAAC851610B1FACDFULL,
		0xDE40E3119E48FE4CULL,
		0xB4F47AAD70F8477CULL,
		0xCC8983DCBCE235EBULL,
		0x94F5DD30637F582DULL,
		0x38321610B51C7FE6ULL,
		0x345AC5A453DD9FBEULL,
		0xC97C81C790F054CBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDB1C6E0CA6D3F198ULL,
		0x5659F269CCE4A856ULL,
		0x58FDCBA1BA1BCC68ULL,
		0x0D9AE056B1F39821ULL,
		0xD749C3D969758010ULL,
		0x19772CE9F8623C5CULL,
		0x014C26C202B2C356ULL,
		0x0DB7E91F4524FD65ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF737A63D81C1D3D0ULL,
		0x17A58C67D50A5C67ULL,
		0xF02244A3C3393289ULL,
		0x1E1D4C814B1D96F5ULL,
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
		0x23A70248B9D0169FULL,
		0x2E145A21F47605BFULL,
		0xB925B19AC713476FULL,
		0xF7A1A38F1BCC4553ULL,
		0x182B1FEA15F229CDULL,
		0x8B1608C9773CDE20ULL,
		0xB85C5D4A754768DAULL,
		0x88DA07D773995D16ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x56C06532CD4A2D9DULL,
		0xEC6D34420C8DD03AULL,
		0x81A03705EAF1FAD8ULL,
		0x433302A48428CCA3ULL,
		0x225D244C6366D9D2ULL,
		0x9F41B66289082031ULL,
		0xCAA00C6CAC9A2306ULL,
		0x518F0209A19A7DFEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4979F67E6D33C987ULL,
		0x432B612743BC66FDULL,
		0x81797B80A5D9AA0BULL,
		0x69917D77C378963DULL,
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
		0x6205E51A70E82DD2ULL,
		0x327ED9798FCFD4A6ULL,
		0xCF8F9EC05F797DE6ULL,
		0x91F7F8D54A96EAC2ULL,
		0x91E61B56CE64E5DDULL,
		0x29C96340607DAE00ULL,
		0x0BE817EDE4D70CC4ULL,
		0x88252913D34A6D63ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC9244BAF70866F0BULL,
		0xC0311C55D299EA11ULL,
		0xAE33F0E537D7C4E0ULL,
		0xDF1BBAEA860C60EBULL,
		0x6AD5EF0C85DDD367ULL,
		0x7093451F1A7A779AULL,
		0xA54D607F703C038BULL,
		0x8E0892250C7936ABULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x65482C71C46E7C12ULL,
		0xF056361421AFFDBEULL,
		0x5C52E84076A51770ULL,
		0x531AA55C4798A910ULL,
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
		0x6F6269D7ED8BAEA0ULL,
		0xF8CA1DB2FE92931FULL,
		0xDF11B0EF5FAC8AD2ULL,
		0xE60E335186247441ULL,
		0xED7AB0AA5C26633AULL,
		0xDAE58086E30F7A5BULL,
		0xDBFEEC74DB4FC94CULL,
		0xBCE897600EA49B54ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFDCEF6133A5F37F0ULL,
		0xF4A3E60C9E69D4E2ULL,
		0xD4354AC3691C43EAULL,
		0xE2B9EC391B900BB0ULL,
		0x17EA3F164C45D528ULL,
		0xF874863684EC3C39ULL,
		0xDD1BECC2B719E5F8ULL,
		0x1A495516128F3C1EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x25044FBF0E8190ECULL,
		0xA0EB5F945963F768ULL,
		0xE08E5A9D5690055BULL,
		0x26F81E13D5C08A94ULL,
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
		0x80972BC94E096C3CULL,
		0x5434805C522C0F3AULL,
		0x3D6C235AA8C91D47ULL,
		0x43BCDC10B720F037ULL,
		0xE8E4DCF67E84AA64ULL,
		0xCEA93658883220E9ULL,
		0xD5F3200C9B7C7B87ULL,
		0x0A102A7F0F9CB6FAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1624FC92769AE387ULL,
		0xA9D5F8E1A585FD90ULL,
		0xF4C75907DA3615FBULL,
		0xB607035AB7660C8DULL,
		0x7D3B4AE6BB0776C9ULL,
		0xFCC24A6AE8792734ULL,
		0x84FEF4B9FDC0DF99ULL,
		0xFFA73E388E23639DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x659DDD8DDC042C39ULL,
		0xD2A58CC0621B2298ULL,
		0x4CE33896386C2C98ULL,
		0x1948EB2D37BD4383ULL,
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
		0x867321210EC2C751ULL,
		0xFC2F076C96D8A715ULL,
		0x2F7461D59F0A158EULL,
		0xA4F0859C9C97B0C5ULL,
		0x3E60D957BB880279ULL,
		0xA1D92797492163FDULL,
		0x28B98D178E6F1FBCULL,
		0x032A6A3C5614A92EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCBAF48D626F766C8ULL,
		0x4D024ED15CAFCF19ULL,
		0xBCCFE80F0E20F3F9ULL,
		0x6DFDE7D2FC5CC2E6ULL,
		0xC2BDCC9F547BBE2FULL,
		0x729D424A641CAE8DULL,
		0x03D30F3D0B97BDA0ULL,
		0x1886F03CAE6A3C73ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x14F7BBAA339D8313ULL,
		0xB210C20538DBC688ULL,
		0xECDB2835FCE1B1C4ULL,
		0x0B36B9BC838711A5ULL,
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
		0xE80A18C4C7883801ULL,
		0x6C12F8FE02844755ULL,
		0x94B500A542C90BFAULL,
		0x80F24B35453C8D1CULL,
		0xCCE06BE15946861EULL,
		0x0C67F2A6CC3E71C6ULL,
		0xDAD9DE738C15D404ULL,
		0x23D0A49CDD951F9CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x659434E110412E49ULL,
		0x269DE84481A56DCBULL,
		0x1AC76E0EE8EC5D16ULL,
		0xC7BAFFE6501D4802ULL,
		0x1709320620AF8B6AULL,
		0x44F2DCE4A41FBA25ULL,
		0x700FB1C598FCAA6DULL,
		0x8587616918033114ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x80687A6E1DB03E36ULL,
		0xE0D64B8B756E1B8BULL,
		0x53F034686F98DB45ULL,
		0x381744FE48C8AD5AULL,
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
		0x7692B13EA97F1B3AULL,
		0xDE46717D2F1EA746ULL,
		0x689A97D4984CE54BULL,
		0x678D402141C10C7DULL,
		0xD643FE18CF87AC1CULL,
		0x017E9713C1A23795ULL,
		0x87AB4F526E63F385ULL,
		0x7DC68725B8F21A1DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4FAAC412E9B6B94FULL,
		0xF423DC632CECF8B9ULL,
		0x404BD99C71A7042AULL,
		0x92A84604864C8B32ULL,
		0x0A5E202B09E9BBACULL,
		0xA0486F156982BD04ULL,
		0x9DD4C013CED78389ULL,
		0x2F0E7E22E3592F7EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6B06DE77153A1440ULL,
		0x582C84DB16DDE031ULL,
		0xDE280183D57E8071ULL,
		0x04365088702754E1ULL,
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
		0x12E440C6C7AC85ACULL,
		0x350C147D0CD011B6ULL,
		0x200F2E5D88A995AEULL,
		0x5173B2CC07AE733BULL,
		0xCD20AD899673A3CDULL,
		0xCE55EF19D59762F7ULL,
		0xDF5DB2271C535E25ULL,
		0xD5CDBCE55D73642CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA1BDE5470129602BULL,
		0x9341A4D7E943EBCDULL,
		0xA43D7F2F84DE4FC0ULL,
		0xBA28717B07DC8FF6ULL,
		0x5B15E77FD4D0AEF9ULL,
		0x4656781B29006C95ULL,
		0x2F4E71768A891FABULL,
		0x970A30EA253404A6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5EBFC0F284B37E3CULL,
		0xD1B61972C1F4B885ULL,
		0x9E154963A7D08C1DULL,
		0x6852089B593A1142ULL,
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
		0x28F1E6DF8503320FULL,
		0x07DAA1A6E1DC6531ULL,
		0x8A2F918A47CEFC14ULL,
		0x9B2380D585C8E28DULL,
		0x1150BEC0E748A4E1ULL,
		0xED580EEA5B1C9C52ULL,
		0x7A556F621689BDEAULL,
		0x91BBBCDB5DD631F3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x88964305B456F171ULL,
		0x7FA78167EB328C2AULL,
		0xC60C283131092C68ULL,
		0x6503DB3BFBE3C621ULL,
		0xAAA3506ACDF87D20ULL,
		0x0E8E1C1B79F10FD2ULL,
		0xB3370623320E49BFULL,
		0x4BED576549F13011ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDE1A04A1929228D3ULL,
		0x9A2D2AF46320B3EFULL,
		0x52A708AF01190E2EULL,
		0x12C2B5207DE363EFULL,
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
		0x126DC802E2CFAEE1ULL,
		0x3CA277857CA1F879ULL,
		0x9791D13FB75F664DULL,
		0x9A48FC229F845208ULL,
		0x4C67B885431F71B0ULL,
		0x1A0B7FE7F81ADC70ULL,
		0x76AF99E2FE0BDA93ULL,
		0x9131A79D1A47D38EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF7B805595A7105F7ULL,
		0x0C88736629C7B58CULL,
		0x6F00AEB6EF424088ULL,
		0x23CC9425CC06A5EDULL,
		0x2CB66047B38A852AULL,
		0x37CBD4B1476C98E9ULL,
		0x04FF52EE68261E6CULL,
		0x25668055EDAB30C7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCF08DBCCD879C72EULL,
		0xC58D6E3D8CB848FAULL,
		0x08BBAAD70837138AULL,
		0x76A43C8D72BDD5B6ULL,
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
		0xC82AD6FBD905C3AAULL,
		0x8F88ADCA22C93050ULL,
		0xEF02806A1902390DULL,
		0x12B9288D31FD8BBEULL,
		0xC11237ED7EBEE069ULL,
		0xEB7A87B20AA8BBD0ULL,
		0x91932B029C4AA122ULL,
		0x3717DC72241FACC5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x887C7DEC50FFE314ULL,
		0x630372C56C699050ULL,
		0x414AB1DCDF696AABULL,
		0xAB297A84245D0FDCULL,
		0x71EC665C9BCA9A1EULL,
		0x6904A197541D20FEULL,
		0xFE50A09DF27542C3ULL,
		0x4B95290B5AF83C1DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFF4B749138484F20ULL,
		0x8A0562FBCF189B37ULL,
		0x8998597E6F44D08FULL,
		0x5CF64F4AE97B34C2ULL,
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
		0x348618E48D53B1ABULL,
		0x2DD93C01CFB943B8ULL,
		0xA6208722E20AAFDEULL,
		0xD74D3DE70FECE223ULL,
		0xBA216825226803B9ULL,
		0x11812887E20806C1ULL,
		0x8A431C5E303DA3CDULL,
		0x282EAC4C1F610D2DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3CCDAC07457C2E9DULL,
		0xD389411FC6061DDBULL,
		0x7EA4D643C257B936ULL,
		0x59608AB6F61FE4B8ULL,
		0xB6219FB0116DC56BULL,
		0xFD890A72B0BC2D80ULL,
		0xA22259304B310F60ULL,
		0x059A679D5FE70F98ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8FB02E3DCCFCC373ULL,
		0x512472075AF56583ULL,
		0x9C58A9AF1F90FEB2ULL,
		0x1FEEE52085E8A185ULL,
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
		0x6CB2757EDCF6E66DULL,
		0x2F8E550F16252A5DULL,
		0xEC9C505E156AD88BULL,
		0x6EB4B623EEDA45B6ULL,
		0xF6BD0F4E3C0702D5ULL,
		0x949AC37E318F7E4EULL,
		0x7ABC638852AFADD2ULL,
		0xC87CC013972D6D7CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x517FEF5FBAE4E4A9ULL,
		0xAEFD664ADC50F173ULL,
		0x4A2B6703FE2A32A7ULL,
		0xE0DC1411F0298421ULL,
		0x526F412C4D4BC4FFULL,
		0x38C05166C92D27A9ULL,
		0x6D51FDE3741E80D0ULL,
		0x20B8DFF34784ECACULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7EBF1F2891DD3318ULL,
		0x22FDDE3DB86D1580ULL,
		0xA03BFFD320CD543DULL,
		0x74EBE6DDD1B3E077ULL,
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
		0xED56D1604595F378ULL,
		0xBCC0B04F3C41CBE9ULL,
		0x96662025CD831240ULL,
		0x101FAD07917B148AULL,
		0x7728358C580E1C4EULL,
		0x8571C538E638B853ULL,
		0x1E831E20E4D462F7ULL,
		0x807F06B304D5695EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD4AB6BAB94BBEDF0ULL,
		0x879ED87075E66F56ULL,
		0xB6BDBCD00F2DDB80ULL,
		0x0BDBF5D2DD71C250ULL,
		0x3498F2023057EE48ULL,
		0x368AD4334D25D48EULL,
		0x654C0237B1A92430ULL,
		0xD892C6018A4B2B75ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF9EF6C3695E4D86BULL,
		0xEB699EB37F292BDAULL,
		0x5DD687F356C08855ULL,
		0x7155518CE48E82C5ULL,
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
		0x138090F960CE82A4ULL,
		0x0C47A812972D1DD7ULL,
		0x90A3DA0B13636FF9ULL,
		0x545A6F3BB9202C27ULL,
		0xA6C678AA6FF3494EULL,
		0x0907257EEBA13DBBULL,
		0xC931456FD605F303ULL,
		0x65899CBA43100F88ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDE1D09776187FFD3ULL,
		0x82716A1070F9343CULL,
		0xDB4C3C7F0C48D8BAULL,
		0x10C60B0379E83158ULL,
		0xA612E197F7991204ULL,
		0x9247351E3ECE8215ULL,
		0x830EFBD928ED8F9EULL,
		0x26F2031C63C80467ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x500BF43FDCAAB936ULL,
		0x2A53EC5BCD7BC43EULL,
		0x1E6E89E9B8B95828ULL,
		0x0E1531A763E9A1BFULL,
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
		0xF586B22BDE651203ULL,
		0x6D8B2F37B0F6C10FULL,
		0xBA2FCC9B793C9465ULL,
		0xE0154D255483E990ULL,
		0x09EF50DFDCA76661ULL,
		0xA108FADCC4D9E120ULL,
		0xDD31EDB33ABBF62EULL,
		0x2775F0F38869D544ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x84648E6D6FC03FD9ULL,
		0x32B2F4DB2AC2D337ULL,
		0x3AB5D0CB2AC19F29ULL,
		0xE89CF31F117D5763ULL,
		0xC01B387D5172682CULL,
		0xE30CA0A45040A023ULL,
		0x9130A5289CFDF09DULL,
		0xD603DEC8C9851175ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x669DC25F18828A2CULL,
		0x6E4D9EBDD4F3934BULL,
		0xC7AAC063B8AFC8B8ULL,
		0x0E670C5E98FBA2F2ULL,
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
		0xC337828D9B477D82ULL,
		0x7E060A0F3F1BADF5ULL,
		0x75374CB6C6D500DCULL,
		0x031F1D81CF9818CEULL,
		0xAC12BDBC6A3D2C69ULL,
		0x7C1674124CF6FE40ULL,
		0x6EB27DC9DA83B626ULL,
		0x89079CCAC5E0E2DCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x82389CE6E1A58053ULL,
		0x515EF065302D01CFULL,
		0x10BA180A8D640860ULL,
		0x09F3391A0DF0FF3EULL,
		0x3CDC6CD6E995AFC3ULL,
		0xCD2809CF90512555ULL,
		0xEAD5EA20482D8E55ULL,
		0xEC946011829ED001ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC30EE7B7D27E7B99ULL,
		0x240ADF920F8CDF18ULL,
		0xF73B1FD7F23AE176ULL,
		0x3246E7E7BD75E5FFULL,
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
		0x7E728297CF0F676FULL,
		0xFAB6851E927FE0B0ULL,
		0xD332B53F32443EA3ULL,
		0x62FABC78786B4F78ULL,
		0xBBA65F32974773B6ULL,
		0x27D06DABDB44E417ULL,
		0xDEA17E3C9C397919ULL,
		0xA5B43D6A15F5CA27ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDEE27310207528FFULL,
		0x1130B70A7FB21301ULL,
		0x9050A82623B0E324ULL,
		0x67B4639331FF73E0ULL,
		0x891B5EB2D352475BULL,
		0x42D19B6AD0727D55ULL,
		0x96162A8F828838F1ULL,
		0x006E09E6150A4F9EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2032227EC4FED795ULL,
		0xE75903BBAE090E82ULL,
		0x079078CADEE2E16BULL,
		0x03B1FE7D69600BF9ULL,
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
		0x12BF9BCB8EF35D11ULL,
		0x0F7874F2068E0614ULL,
		0xC5843D8B3971D320ULL,
		0xAE535D0BBD32AF4EULL,
		0x2E6B9094DD4807C3ULL,
		0x9C8D665808727BA1ULL,
		0xC0DF2FE8A311A964ULL,
		0x4683B8279E3674A1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD495F3F62C595CF1ULL,
		0x145247F7EF8122EEULL,
		0x55992095D39BD81AULL,
		0xEC0C2E599E0762CAULL,
		0xABA1D2C70162C1BDULL,
		0x392EAFD6FF617F71ULL,
		0x9426D454855D0EFFULL,
		0xD8E3CE82F7233514ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA81BD46406A261C0ULL,
		0xBB3544216F925232ULL,
		0x1348B4F1CEA4E612ULL,
		0x0803DD22EC06BB79ULL,
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
		0x3E79F6C1F849A646ULL,
		0xBAA5E247677C0452ULL,
		0xDB69F66089141211ULL,
		0x407CE4E1D7FF568BULL,
		0x34FDB6548E509328ULL,
		0xAA05EF61D42FF596ULL,
		0xF2B1E4DE81A0D0C8ULL,
		0x4A2DAF47B828F4A2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDF7B9EF1C35A15A8ULL,
		0x14957CA000C866A5ULL,
		0x649696920F34B6ADULL,
		0xBD7538685C56AC13ULL,
		0xE3EEB8E7B98CAF1AULL,
		0xB387D400D24BD9FBULL,
		0xA45A3545AC4C324AULL,
		0xDE50B4E4E692F90BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6737F5F7CA03675BULL,
		0x3CC8760DAE8FB694ULL,
		0x17D7707E246EE217ULL,
		0x05D4D72497EC02EEULL,
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
		0xCD7196949851D862ULL,
		0x804BEE741507F439ULL,
		0x68D035107A085308ULL,
		0xDCD0165194D12B7FULL,
		0x253CD12BC22EB79AULL,
		0x715ECF43B9EB2323ULL,
		0x6BC600A9C54B3776ULL,
		0xFB9805D0A77E5E0EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2497EFA4BC4059D4ULL,
		0x71116D86A6811C7FULL,
		0xC44606CD5B9EF637ULL,
		0x59B1614C2470E396ULL,
		0xF732360FBD021D21ULL,
		0x9F0FD66F34690227ULL,
		0x553EB210C731A1A3ULL,
		0x713A6501EF49F607ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7E6CAD18A0B06FA2ULL,
		0x46F370793FD7BD03ULL,
		0xFC9FD8F8D6359A1CULL,
		0x0D0493B4C827B8F5ULL,
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
		0xDCCF0906E1BD6678ULL,
		0x6715D7D13A945CECULL,
		0x2C334BA4783B1FE3ULL,
		0xE02E7B6BF9FECFA3ULL,
		0xA61B8722214A95A4ULL,
		0x67DE25879AD59CC5ULL,
		0x7F271A495173A8D1ULL,
		0x6687B00B304A3A3EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1E009718754972B6ULL,
		0x2B67CFB7F75CC9CFULL,
		0xA3548F7A2C7A4BF2ULL,
		0x830038F8E9804105ULL,
		0xB65C52B07CF1F823ULL,
		0xA1E1BD95A7C1D01DULL,
		0xDC043ED09A3F8319ULL,
		0x7D8EAAFCDE5D6EB5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x55303ACCD19B5463ULL,
		0x9F2576035827F40BULL,
		0xC00B50157D7E6D38ULL,
		0x7225029339A4C4E5ULL,
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
		0x375761B5515BF3FCULL,
		0xF747A894D7874E9AULL,
		0xE8AE51FABCF76E10ULL,
		0xDF3272BA9A8AFD7CULL,
		0xE2BF8A1EC9F62152ULL,
		0x2BC3676E7FC2CB4CULL,
		0xEAAEAEEA46E1CFDEULL,
		0xB1D006AB9C0D3D5FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xABCE497CE2C91EBBULL,
		0x0FB9C13D1EC4153EULL,
		0x21923795FA5772E8ULL,
		0xA282B69B26A45F28ULL,
		0x4FCD58FDA009418AULL,
		0x77DA1B2A4F2BF1C2ULL,
		0x03245E7D6AF11136ULL,
		0x381A8EF48CFD66ACULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5B7C6324A7BC0F9DULL,
		0x9C2F3976EF2783EDULL,
		0x25A40A8D685C480DULL,
		0x4D9F814BB0407D09ULL,
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
		0x105BD13A234C91FAULL,
		0x5799028E53EC33F9ULL,
		0x69B228BCCA1EEA15ULL,
		0x765355B0487C5175ULL,
		0x49EEFF46D69573C3ULL,
		0xBD52A4CFE2359EAFULL,
		0x23FDB5811BA49B12ULL,
		0xB9ED01843861B1A7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB45B626A12B13A9EULL,
		0x6BA1AAF4F1CB270AULL,
		0xBD61442558909F48ULL,
		0x3251E06936A34283ULL,
		0xC355390D6A4CA959ULL,
		0x4EEEE487B035C8DBULL,
		0x588694BC3123153CULL,
		0xC14EB3BE4B5220AAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x56D3DB56236962F2ULL,
		0x4EC5E250CE1ACA54ULL,
		0xDFFFC1D240C828A1ULL,
		0x2B8100A842289477ULL,
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
		0x86A8E4DC128D4468ULL,
		0xA0A4EDB41534E1B8ULL,
		0x584FF0847C3FF9D3ULL,
		0x595048F7D3537871ULL,
		0x08A2BD4614CDA391ULL,
		0xB037D4882A10CD3DULL,
		0x994E726816E5A3C6ULL,
		0xB800F96F0DA9EC32ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4705552806CABD8CULL,
		0xF913C302C8E6FE0AULL,
		0xD35242D0D21757A0ULL,
		0x55E287570754321EULL,
		0xDD5079EFEE168F9BULL,
		0x90E7193FA1CD325BULL,
		0x1501117CB76CB40DULL,
		0x622974FC0513C4AEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xADD98E7DCAEF7F3BULL,
		0x4D8CF7758656E11AULL,
		0x287A10A3D61C37ADULL,
		0x416B6AB4124923FEULL,
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
		0xF7B2B9619CE75FF1ULL,
		0xD68C11D8B6788C52ULL,
		0x3A8B865782230673ULL,
		0x3809B7D74080D541ULL,
		0x48DD132484A61268ULL,
		0x0950606C4C33A236ULL,
		0xA8F68D0AA4B71540ULL,
		0xC43F515D4EDEF2C8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA9ACFA0E21486540ULL,
		0xF6DC8AB57701AE31ULL,
		0x23E56BF8DB06CA6BULL,
		0x7548B6598BFEBC7DULL,
		0x077B1A2BF0AD5955ULL,
		0x0663C47AEE8DE116ULL,
		0xBB885C1B26DA6AC5ULL,
		0x526E32221B62FE6FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0290B439728A75F6ULL,
		0x4ECEACF7261188EBULL,
		0x55015DEB55DD8A4AULL,
		0x27CBA44758E85DF7ULL,
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
		0x981D379AE4E80AD2ULL,
		0x4A483627AB8D8F65ULL,
		0xAC586B8BD2089DD3ULL,
		0xD028787C44071071ULL,
		0x019F69A110FBF8DAULL,
		0xCD0983A97611AB39ULL,
		0x82B303E5E3F97CEFULL,
		0xD990786E1A3AA1DEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFC30CC653786CA6CULL,
		0x41805A954F733A46ULL,
		0xFA2C803D0FB12C6CULL,
		0xDEB975A632B88263ULL,
		0xA9EE8B7D239B0D38ULL,
		0xEABCAE47F7CB30C8ULL,
		0xA0F1F5A4A75C1733ULL,
		0x064745F187A1AD0BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA02D648AE9C43F0CULL,
		0xA02F880B1A9081CBULL,
		0x34D408FDC1B48B4AULL,
		0x4E4C8153D402E55BULL,
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
		0x1D31BF24BB294944ULL,
		0x0CC1D7FDC3895251ULL,
		0xBE446CE00C7705C5ULL,
		0xFE6B6EB64EFE7B28ULL,
		0x866409F811896A52ULL,
		0xAF705209FC8F9E48ULL,
		0xEE8CBD86AC20C77EULL,
		0x16842EAB9D5BB6D6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFFC33702ACECDFD2ULL,
		0xAF74722A5246BEC6ULL,
		0xE5A7E5C0F2A7B6A1ULL,
		0xA3DB3F36C9AA60AFULL,
		0xA76E5612BF6EB504ULL,
		0xC8FB193202200076ULL,
		0x937B192007FA3A4FULL,
		0x11A9E33738CAEBCDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x35E73C2C3E33532CULL,
		0x92B3D5E29DD400B1ULL,
		0x5D3AEE5B77884419ULL,
		0x12F762C672D23DDCULL,
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
		0x3496774AAAE5F576ULL,
		0xF079FA9C5D3A80C6ULL,
		0x13F3BE994FB74D81ULL,
		0x569026E676E7DB19ULL,
		0x247F19947A88D3EBULL,
		0x0ED8F1DE16D72509ULL,
		0x6934084B687B184DULL,
		0x016FB636B645D6AEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x46A97527230FEF4FULL,
		0xE59F42878AFA6B4BULL,
		0x98AEB08714947B10ULL,
		0x04AF59F54DD2420BULL,
		0xC3702702106FC633ULL,
		0x05CFA5ED7D86C2ABULL,
		0xCE0F4521FD246743ULL,
		0x4A57467697752598ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x562503DF478E0DD5ULL,
		0x623BFDCB942EAF57ULL,
		0x82BA06382A0119EEULL,
		0x7F816375BC0FE242ULL,
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
		0x6D31C0D00028CD09ULL,
		0x026C8E9DABD3B649ULL,
		0x9382F8A4A6BA42F5ULL,
		0x93A0412192611F7FULL,
		0x0B52D113F3B0EF41ULL,
		0xC8EBCF2E13A208B6ULL,
		0x872BECA9E1EBA22AULL,
		0xCE3B4FDD0CDB6B2EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB08C47C78C2FD972ULL,
		0x08DB4AD90CA1B3AAULL,
		0x17A5518FA0957EFFULL,
		0xA5C36B6E0BBF7EEDULL,
		0x79099DB772B368C9ULL,
		0x4217E35CA194B1E8ULL,
		0xD06BA13A125844E2ULL,
		0x286E92C48B848126ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x738318C3999AED0AULL,
		0xFD0644DB8D2CE522ULL,
		0x9C68D9ADD6049CB9ULL,
		0x0A40E756B9885DB7ULL,
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
		0xC0ABE09CFF641254ULL,
		0xDF69A942D41821B6ULL,
		0x313D6DA15B27F2A2ULL,
		0x3FF765501B5CA818ULL,
		0xD65EB0412590FA2EULL,
		0x6AF8F677B28E4CECULL,
		0x462BAA39BA633928ULL,
		0xAC5FB71AA9EB4596ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4DE0016C821FC65BULL,
		0x08112298DB5CFF53ULL,
		0x42390F1AB9111EEDULL,
		0x066930EE52082D84ULL,
		0x06FD61752348C9B9ULL,
		0xC40025AB976593DEULL,
		0xB6AA51467E106DF2ULL,
		0x0978A102239F4871ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3B3D9178D3FB80E7ULL,
		0xA04784F600C69A96ULL,
		0x3C3792A19660FDACULL,
		0x67DB7C05B89C0E01ULL,
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
		0x5100F1DA4352DB9AULL,
		0x516CD8810DB7673EULL,
		0xDBDC535D52B0CDAFULL,
		0xED2AA4477ED07897ULL,
		0x3B640B6B887B1195ULL,
		0x8566602D8990A24FULL,
		0xA3EE8E7B8C801DDBULL,
		0x2BB54573F506EA79ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF08C3191425EB24CULL,
		0x37E98B6CE46CF802ULL,
		0x7219EFB546451C84ULL,
		0x76A38D673712C7C5ULL,
		0xFF8D49377F24E8FDULL,
		0xE6F72D5F0E13F687ULL,
		0x56B373565A4D0F7BULL,
		0x6C20E3D6C67FA1D6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4255940263BE2E75ULL,
		0x9E04D7BA7DCBEECEULL,
		0xE0886B2D7FFFD35CULL,
		0x668D94352FD2790FULL,
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
		0x2152974DD5049CFDULL,
		0xC76126C6CB60A514ULL,
		0xC016651C7F1761CCULL,
		0xA9887B46FAA90542ULL,
		0x25F1EB25D8DE8C90ULL,
		0xFAF9C39D4936D1B3ULL,
		0xDCDA89EADCBF1DEEULL,
		0xA2C715DB32195010ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x337DC6D5686D303FULL,
		0xAD099EC05ABF91CBULL,
		0x7D0101DB82229F33ULL,
		0xF89AF6EAAEE6DD72ULL,
		0x81E7AB55A1A59B82ULL,
		0x0632ECDACF5EA6A7ULL,
		0x513297457B88E9D7ULL,
		0x2048BA8E8AE55D0DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x475A49609F0B37A4ULL,
		0x6FDB68E486B77703ULL,
		0xFE0367CD6B007E27ULL,
		0x0FAF11BD1D783A56ULL,
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
		0x2D58E3362EF8030EULL,
		0x3A1CE18A05E9CB81ULL,
		0x5493DE6D15A974C1ULL,
		0xCC865E1EDB83758EULL,
		0x0BC4B1A277B8BEA8ULL,
		0xFEFE86BF1264B52EULL,
		0xDADF5D39CD3A0E3AULL,
		0x915928CC0776352DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE03CD31834D09578ULL,
		0xEB22F5DCDDD61977ULL,
		0x2225CCADA98B0EDAULL,
		0x2AA4A0F09FB9AC04ULL,
		0x93AB8807C98BC099ULL,
		0xF74E2E85CC785A00ULL,
		0x86DFA762CBA195F6ULL,
		0x04C475C59BF3D1B1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x20D83D13D4D526EEULL,
		0x7327042D89293AC9ULL,
		0xAA630FA9A8C03FFFULL,
		0x7FF4502231248DFEULL,
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
		0xA4973147DFC94912ULL,
		0x7190AB77EDC32E1FULL,
		0x42372D2F8F3B62B9ULL,
		0x42C1F919306493CDULL,
		0x8BDDB07ABEAB2C12ULL,
		0x9E691771EB3E77ADULL,
		0x4E4CB9F24A82C685ULL,
		0xE96E2060452C9087ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA9DE81EE033A4487ULL,
		0x6B8776D41C4B563BULL,
		0x378975EDBB68D320ULL,
		0x226C7A376266B3FEULL,
		0x97244FCEF6F16147ULL,
		0xEBB97C718A85ACE7ULL,
		0xDFF64C65BD3E7570ULL,
		0x6F021A25B232B297ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4E3D08D982232159ULL,
		0x8C1A36B22CE5F146ULL,
		0x6B81FA1ECBF698ABULL,
		0x4C5E6B939F14D159ULL,
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
		0xDA70FE60E5660E1DULL,
		0x241E8D0D9F1F8161ULL,
		0x0B0EA49C4B284B5FULL,
		0x24987572099E3930ULL,
		0x84B39155F9203CD0ULL,
		0xC3B67EF56D6D5DEAULL,
		0x9918D270C2C63988ULL,
		0xF7813393EFFCB97AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5DABC4C54B07C9E7ULL,
		0xF47D3A67F20A34E1ULL,
		0xBFABEEC296CEB503ULL,
		0x0C6C0A94364C7C19ULL,
		0x749992EE27A42D50ULL,
		0x5760E37A0463098DULL,
		0xAF7FF6C7183FCEEAULL,
		0x3C0F52DDA0198654ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE0A0FD04B2C8954BULL,
		0x445666F7449DD250ULL,
		0xF8135109044D69DFULL,
		0x6B13C5EDAF0B54B6ULL,
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
		0xB158DBF177AEF834ULL,
		0xC11B51D09393DBD7ULL,
		0x2A59F88A58701FDBULL,
		0x5DBE0A2E335E46E2ULL,
		0xA651E293424B702FULL,
		0x6256C5DED2889820ULL,
		0x23B3802895B2CEE8ULL,
		0x3E5AC3D9F621754FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x050DA28CB4771B72ULL,
		0xB4D6179C3731B5CFULL,
		0x64DB8CCCE5D14EA9ULL,
		0xE6F7FD943B7F25D3ULL,
		0x79543AB42E8233EBULL,
		0x2FE8F554356648A8ULL,
		0x00182AA631764E62ULL,
		0x051AE9C3ED0B3611ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x59F22481B316CFF7ULL,
		0x88922EC7AF79F1DFULL,
		0x0E8D1D185399E51DULL,
		0x76406BDF512C8448ULL,
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
		0x50617DA02CB29458ULL,
		0x0ABE2AC6C29FA05BULL,
		0x7718F37959ED8C54ULL,
		0x77E054DD457B7A30ULL,
		0x2178273CB01FCE93ULL,
		0xEF82F0438E572C1EULL,
		0xF4A44D08C200271AULL,
		0xE5A998CC4568A42DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x994107A79B48DE9AULL,
		0xB0907946BA6D1549ULL,
		0x412D994EB45801F7ULL,
		0x2706F029F852754EULL,
		0x688E52BBA5EFBAE8ULL,
		0x3E4FB36188FC1A7FULL,
		0x68E7CCA88D7599B8ULL,
		0xA8DA7F3AE4156DE4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x29D60120148CA276ULL,
		0xA7C8BB0CD3B728A1ULL,
		0xF3E6687272268702ULL,
		0x57973047BF8313CCULL,
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
		0xCC836BF817B48EA8ULL,
		0x28180A3663365769ULL,
		0x00EB6345CBA81149ULL,
		0xD20701798D2EB1BCULL,
		0x6CCF014DD66F85E6ULL,
		0xDD702E4A8930A8CFULL,
		0x28B63B68FB45E3C4ULL,
		0x2B83ED31C94E76B3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x679B81586422E3AEULL,
		0x87D98E07FDACAF02ULL,
		0x9291DC4E4A7CD3F0ULL,
		0x0A787AD50792C08DULL,
		0x5D90386BE18ABB6DULL,
		0x8D6B5177F236E3FBULL,
		0x1405B556E7346AE9ULL,
		0xB2BAAF3032FAB7BAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA839BC2A0D87B60BULL,
		0x80F74370CE9CDFE1ULL,
		0x808D6DA67BC32DE6ULL,
		0x356DBAE0D60A4A27ULL,
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
		0x64F96AB57F6A113EULL,
		0xF3BE97E372C6CCA4ULL,
		0x9FA0AC2719494619ULL,
		0xF77AAA62EECECA77ULL,
		0xCDB9533B9FD3E2AAULL,
		0x0F7114DE4E4E73CEULL,
		0xF9A694009695285CULL,
		0x97E8ED80D36A0108ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8E26DBA31F721BE4ULL,
		0x330360A12F11C81DULL,
		0x721AF94E381E9A9FULL,
		0xF81E733D7170C02CULL,
		0x3412DC6A4B33AC2CULL,
		0xA916C6F51D17364AULL,
		0xD5C21AE1A98AB862ULL,
		0x7389E1B5E826520DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA5883224EFC00CCCULL,
		0xF222C7DF91E82635ULL,
		0x816FAD7010B74A7FULL,
		0x6577F744696A0392ULL,
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
		0x28C8BAA94AE162B1ULL,
		0xFC2CA69AC0379FB9ULL,
		0xF5047736AFC6AD7FULL,
		0x352F88D9AADC362AULL,
		0x4D3F6FB6A87F613EULL,
		0xA3CEAF0B931F0D67ULL,
		0xDCD735287F315FB9ULL,
		0xEFA38C57F2A0C8CFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3EABF77796B02931ULL,
		0x71645DA3CA7B0947ULL,
		0xD3A417058B1A94CCULL,
		0xAA6EE81162ADAE0FULL,
		0x04FD4BED2CB3315AULL,
		0x2BB92713C9CD9A12ULL,
		0xF5439311A717B2A1ULL,
		0x7AB9A20BFFDF90F4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA3EE131A148057CBULL,
		0x5DFA77BED7D3B51AULL,
		0x814A6F95387BCA55ULL,
		0x6579680E50DCD299ULL,
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
		0x54F64935E65C0647ULL,
		0xD455528381113ACEULL,
		0x6C084A9FE5E3EE44ULL,
		0xDE26E0B108816066ULL,
		0x13973E8749C5ACC9ULL,
		0x34FE6C85C1A79F3FULL,
		0x664AB0E165660E35ULL,
		0x5BEF598B1E6B287EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x592156F99775218CULL,
		0x3FC8826DE97C9B86ULL,
		0xFFC176B6C7A82E92ULL,
		0xAF4AB67F78CB0D3CULL,
		0x4E0AFFBB1F52AAC3ULL,
		0x1CFAAD76F7FD4955ULL,
		0xB113EF65915CE179ULL,
		0xD34ADDA9713E5A7FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4EA6448A9BF92EF3ULL,
		0x251B2C4786DD5FFBULL,
		0x52678C4A9798639EULL,
		0x77468DB1445CE6F8ULL,
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
		0x05AE42BECE7FED49ULL,
		0x2F5572A6A482DD6CULL,
		0xCF7DBE7907885FEFULL,
		0x750E9012F3A9DB3DULL,
		0x75B3D73F4FBB51B6ULL,
		0xD2BD063B16C04F8AULL,
		0x20F87DCF070EB3E0ULL,
		0xDAC5CE15BBF0C954ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x47DD153AC813B0EDULL,
		0x28C699DEB745F016ULL,
		0x44F3B52303512B5AULL,
		0x26DD23B448C7B85BULL,
		0x083EA814CE6C3C24ULL,
		0xEFAFD826F40B3580ULL,
		0x361C970DD00838F5ULL,
		0xE4B6B7186CF927A3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFD362DD338296FCFULL,
		0xBA83AFC5141ECAE1ULL,
		0x672E4A042F2D7372ULL,
		0x546ED5F863A42325ULL,
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
		0x247A76F05FCD3055ULL,
		0x4B523FF400F280ECULL,
		0x3E003FE6F570D74CULL,
		0xC90612E3482498A1ULL,
		0xD69E6D305E52C02DULL,
		0x8FC247BEE8E3C4AEULL,
		0xDA734BE89C9FA82EULL,
		0x16845E8094EF358FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF9A61994DA9A8159ULL,
		0xB47208540C1DE8C6ULL,
		0x4D2304590E608395ULL,
		0x22EF84B749040F79ULL,
		0x4B6316483EFE493BULL,
		0xF585EBD50EE8EFD8ULL,
		0x7D1B2C5231372E71ULL,
		0x6AF40B1DB01E1597ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD5A343D02BBC5520ULL,
		0x7BD5DC5650102FFDULL,
		0xCBF1EBE1D89265B5ULL,
		0x1D82EED9F62B4805ULL,
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
		0x33099E016DAA8BFEULL,
		0x44A783C630F79ED2ULL,
		0xD9C23AE0CDC6B582ULL,
		0x6203DD2035BE45D1ULL,
		0x4697FFDF8DC6E653ULL,
		0x7B61106E8558B770ULL,
		0x5D8957D52CFDA343ULL,
		0xE54677E6B3569984ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7D4D8BC29AF4159AULL,
		0x0BBD751A322C5699ULL,
		0x9E92D3CFA11C05C3ULL,
		0xEF0CAB8BA10C21C2ULL,
		0x75AFC22C54177849ULL,
		0x722F286ED02525B4ULL,
		0x097E3760C1084681ULL,
		0x748FD5CFC9842A3AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB8353AD962C0CE40ULL,
		0x96527EA0E472EA19ULL,
		0xB4D638593316748CULL,
		0x2E1340FB49EEA917ULL,
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
		0x6999CB3F5D8745CBULL,
		0xB3F5F16D10439F54ULL,
		0x5C84E20D74799406ULL,
		0x81ABECF6D651D5A8ULL,
		0x44E0B69CAEF19879ULL,
		0xE3CEC5F72FF6A474ULL,
		0x5B5EEDCFF03F034DULL,
		0xEE098763C074E35EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9D4E05B9D295C86EULL,
		0xAC18F1487A153307ULL,
		0x322B405B5A1D7E7EULL,
		0x6F15C8914E0D5280ULL,
		0xE79F2E90B4BD10A6ULL,
		0xD072315B3BB4B613ULL,
		0x5F87CF3F87CE3A51ULL,
		0x986E57B9CB6EB23AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA405F74CAEBDA88AULL,
		0xE79B0F4AD7F7CE9AULL,
		0x8C482B219B19EAF2ULL,
		0x479F379FE72FCE7FULL,
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
		0x8522BF48E1A25C82ULL,
		0x4188E946A1DA469BULL,
		0x4B0641BB85B0203CULL,
		0xCBEE50960BFA08F6ULL,
		0x23ED33224E295C0FULL,
		0xB0D91A5326AB392BULL,
		0xE84351B5D3500B04ULL,
		0x9AF72C4A795D662CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3CD2877F098BB976ULL,
		0x57F5BEA9340EEB16ULL,
		0x9091D6767808BBD0ULL,
		0x155BFF9F15305DF2ULL,
		0x1558A41A59A50A98ULL,
		0xF2C33CA29E990336ULL,
		0xB722B4077CFA714BULL,
		0x977300A1F181509CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x725D72F823BABADCULL,
		0x20D212D1A07F5DE5ULL,
		0x054BD325DE5C35D8ULL,
		0x3C30CBFB2174DE6BULL,
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
		0xA965F7FF1D4A4573ULL,
		0x888F42671A448AFDULL,
		0xE85BAD80A11EAB81ULL,
		0x7BB6C0CC4571732DULL,
		0x4C26E72213012113ULL,
		0xC62C2B322BD95BE2ULL,
		0x8238F3589EEA6D75ULL,
		0x9110DA1624A0DD77ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x533A1E24D75F333DULL,
		0x526F7B7945DF6509ULL,
		0x6688E92B5C7EDEF9ULL,
		0xC87492F3B86426C2ULL,
		0xA17323A6FFEC41DBULL,
		0x805AAF8994AD53DCULL,
		0x071FECB0F3267E98ULL,
		0x628EC448F9BFF1E4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xACDADE1F1B04357DULL,
		0x933821F444EE56CBULL,
		0xC789C138C3B54160ULL,
		0x1A916A4CEA70444FULL,
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
		0x411DC6FE59260B0EULL,
		0xB611000EEEDC42E2ULL,
		0x8C356CF830A7E73EULL,
		0x97F3CE9DDDE5C900ULL,
		0x1D807B43A0CD07C1ULL,
		0x9A9261D0141C25F0ULL,
		0x930C3AF705EF7D81ULL,
		0xD61024A932B20AEEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x490DFEB9B0D50D88ULL,
		0xB0EE69078CB22ADFULL,
		0x852744A3F1CCD6A9ULL,
		0xDB6109361720EAF3ULL,
		0x8142F5B8BE2E8BA7ULL,
		0xF009483D24882F05ULL,
		0x390ECAE5F4754F55ULL,
		0x06ED05E9EC211BA9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x29319AE24BD76DD6ULL,
		0x557C62D6F220BED6ULL,
		0x62ACCADCD6FDEB10ULL,
		0x7BC955CC40486258ULL,
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
		0x93A14F5009768D8EULL,
		0xA8C6BE43CBD46639ULL,
		0xC710AE40932DD4ADULL,
		0x90C72C07C4FE398AULL,
		0xAAFF15A749F40361ULL,
		0xF61597AE74993DDBULL,
		0x6643538995B1B8E6ULL,
		0x959FC0C2CD4D5868ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFF572B6CFEF75ADEULL,
		0xC9F7AF280DF8C5DFULL,
		0x79A0850805BD199CULL,
		0x66E91B11A88605D8ULL,
		0x7DDE61B3420183F4ULL,
		0x35E9E51D45B35D4BULL,
		0xAECA388FAC7AC555ULL,
		0x6B150515D6A4EC6BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4724DA1C387E1DC2ULL,
		0x654B90A8B3FAF5C0ULL,
		0x896A2A512B98E2B3ULL,
		0x7A75ECA2B9783B35ULL,
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
		0xCDC3DF663E7E4C56ULL,
		0x1A65B12B811CCE75ULL,
		0xBE2A2710B651B8B0ULL,
		0x4DBCE10A86F41C6EULL,
		0xD8EF4650AF169B46ULL,
		0x330FFFC13E662DAEULL,
		0x82568E81CF686C3BULL,
		0x51CDAF5DC0CC859AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7F6F5CCFA32096B8ULL,
		0x04A8BA9419E3DAFDULL,
		0x1935B6DDE82047A0ULL,
		0x592A9A0B6254131BULL,
		0xF0239CAC71ED6533ULL,
		0x50478461F35E1828ULL,
		0x02DFCB49D10C4393ULL,
		0xEE43894803381435ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDC8FB0F7AF7BB8F3ULL,
		0xBF7F46BC8A6C2558ULL,
		0x90956A828FDF79FBULL,
		0x3B13EE3948A8DE64ULL,
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
		0xE20C05DFF7236485ULL,
		0x4208B695F55DCA3CULL,
		0x3ED4D81A08FED0ECULL,
		0x0D69B333E4377245ULL,
		0x72C01B069BBE715CULL,
		0xF145D8CE98805171ULL,
		0xBED741F716B5B163ULL,
		0xFB60AF7A8D3E6416ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x79FF91C8C3018EF2ULL,
		0x3AFDA2DCCD2C66BAULL,
		0xFD4A80B493552BC1ULL,
		0xC7B048FBE9682C3DULL,
		0x13CDC444CB4E03D4ULL,
		0x567528B8438DC3B3ULL,
		0x0A4E98E527CA6992ULL,
		0x6935F09C928ED673ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x800554DC24D21ACEULL,
		0x02053709C4326DC4ULL,
		0x0DD3700EEC964E48ULL,
		0x7811BF2B30DE4C54ULL,
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
		0xCD72B1B593B2F456ULL,
		0x5CCF83CD60CCBFD7ULL,
		0x2B7F2F7739E881E7ULL,
		0x54EB1D17C53BB9B8ULL,
		0xB6C50E7C2BD4734FULL,
		0xD58745370BD2380AULL,
		0x6E34B397735E4FFEULL,
		0x9EE2E5EB78F79F77ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDCD61DCB4CC08418ULL,
		0xB73921100C24A92EULL,
		0xEC0DEEB64BADA5E5ULL,
		0x03A86830339C8DF6ULL,
		0x92EDA5EAC2BD5117ULL,
		0xC93899342CC8C4E6ULL,
		0xFBBBA068CB842498ULL,
		0x47855765E2374A4EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4296197FE061867CULL,
		0x7943EB2A700F2E06ULL,
		0x3D6A19ADD89D4D27ULL,
		0x4925DCBBF22BCFC2ULL,
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
		0xB947B93197F6ED68ULL,
		0x10440BEE64D79F54ULL,
		0x5254C70D430165D2ULL,
		0x24A9EDC7D3ECACB3ULL,
		0xC1914B63A8CF6336ULL,
		0xC094E9AFB113C74BULL,
		0x0CF3B95BD7900D5EULL,
		0x110169A9A19E1978ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF26DB797CC551948ULL,
		0x0A4CB1B5B0DCCCC0ULL,
		0xFABC3719A53B5754ULL,
		0xAA76B7DA8C8734E1ULL,
		0x22EAFB7C2FE1E4E5ULL,
		0x96D2AF5E6798B6D3ULL,
		0xBC81EF1F5CDB0E43ULL,
		0x1870AF44AD35DFCBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5389DDF5BEE293DAULL,
		0x38CC02499C3F447BULL,
		0x487C94EDD4A3EC86ULL,
		0x5FAEE0E98EDE0765ULL,
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
		0x1824AA210A438AD3ULL,
		0xCA27A79CFE3F81A8ULL,
		0x231B7D90EEE27BD9ULL,
		0xC410007FC39840F4ULL,
		0x76C77C2AFB82BDB5ULL,
		0x5859331A8B175A6BULL,
		0xB63E1756E0EC4095ULL,
		0xA147FD750F0C40C8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8861D9DD09985D87ULL,
		0x6B63A0F185F79DAAULL,
		0x63CF04E6A8D79379ULL,
		0xCD4D0AB0A9A3BBE9ULL,
		0xE7714B561DFAC6C2ULL,
		0x158EC6D6C0A66682ULL,
		0x1ACDE50FB58A5103ULL,
		0xD8C90539F6CC09D5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD68E0FDCE2D9D41BULL,
		0x48D018BB850C1882ULL,
		0xD1F3EF3AB6947816ULL,
		0x399BCE94B37CAD33ULL,
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
		0x8960D1220E1B4EE6ULL,
		0x13DD7DE85C2BC114ULL,
		0x4D9232742B7874F3ULL,
		0x7F59EADD174C6D5EULL,
		0x987B596D0863FA09ULL,
		0x1ADE013EE40381B0ULL,
		0x3FE139EFAD81FDCFULL,
		0x5EE54C6C2F7297C7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC09DA53C0F66FAB7ULL,
		0x758E69FD20E71916ULL,
		0xA905FEA1A98BEFDFULL,
		0xF5CBBFFFB6A31674ULL,
		0x213691B74DF3279CULL,
		0xDD7C87B1FF3FCB0DULL,
		0xAC746DD00D0023CAULL,
		0x3E9FDF185F58E147ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7CF8D0DFAB7390F5ULL,
		0xBAC71ED53051C441ULL,
		0x86B280845532E1B4ULL,
		0x53DC654E447A6DD9ULL,
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
		0x3CC3D3508DC967F3ULL,
		0xF43489399524340FULL,
		0x29E88A308810FFC1ULL,
		0xC6B6ED2E1D1D5961ULL,
		0x5966B51DC205707CULL,
		0x118219A3E3E7B351ULL,
		0x6FC2C964B3C12EB8ULL,
		0x92D87ECF059C0B07ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8A08698E8CCA64BEULL,
		0xBFED7B069152ED85ULL,
		0x0B9E2871B01B9769ULL,
		0xAEA032586F9B1E28ULL,
		0x4E4FFB6F985EF246ULL,
		0xACE20248886DD8E8ULL,
		0x17726E80A01B93DBULL,
		0x21E48A1605F38501ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x581AF99C2FB5C1ACULL,
		0x240A85C297E7B221ULL,
		0x3A37DF99C28A650FULL,
		0x5C4D0E4BA086202AULL,
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
		0xD373D13EB890256BULL,
		0xE17875A78F0D4E22ULL,
		0x57E38AE74F665A0DULL,
		0xBDFDE21B6864A95FULL,
		0xD28005534BCB1A24ULL,
		0x69AF6EDA2CDACEE3ULL,
		0x8554B152039F4ACDULL,
		0xAC8140237C6C52D6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x93FCDF842CB13D54ULL,
		0x3E94E8C443C5A7C7ULL,
		0x06B989905CDF985CULL,
		0x53A28C3E6580916BULL,
		0x8D11B80272953C8AULL,
		0x16F7227686D5E4FFULL,
		0xCE510D1B39761252ULL,
		0xEADE19B4E3120F1CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8DD66BBAC9DDCB9DULL,
		0xEA3EE3ADF0025E3DULL,
		0x7BB46178F4A523FFULL,
		0x28930A47C64A2585ULL,
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
		0xCD498294A1CD0252ULL,
		0xFA747EA78AA11BC8ULL,
		0x37A3373E6B06E368ULL,
		0xE1551F8839E971C1ULL,
		0x5944BA6B7847BFF9ULL,
		0x9D35106C4455312AULL,
		0x3C5E64C447282EDEULL,
		0xDA24697CE3522D4DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x35F8076D0B4440DFULL,
		0xC0ED1EEC938B748FULL,
		0x4FCA4FE1B0FB62E7ULL,
		0x49DE7F0564D59388ULL,
		0x4EC200B9B104C384ULL,
		0x07BD3F1D48D7756AULL,
		0xCCCC8E0AA8A487EAULL,
		0xBEF54DC197FF6067ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x26B90B8B2A7A3B7CULL,
		0x695071744BBF85BBULL,
		0x777EC6EA419648CFULL,
		0x2074BE50035E4847ULL,
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
		0x6A1A5DFAEE300026ULL,
		0x23BE6350E73E5D6EULL,
		0x9742F00CE9606F1CULL,
		0xC9EB5A97ED8910C8ULL,
		0x5FFEB3070C8717BEULL,
		0xFBB90E5448E6404CULL,
		0xDDC5EDC4B78A5DA7ULL,
		0xDD26FC245F2CECF6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA07B138ECB83133EULL,
		0x1BF2F3132C65148BULL,
		0x9A6D87B23E1B3D83ULL,
		0x018FAFF426E57667ULL,
		0x02A17D6975B3BFACULL,
		0x5BBF3F64BCDB7810ULL,
		0x3B6E57B5AE130E9BULL,
		0xAC6CEB2581241D2CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA5753FD0860C00C4ULL,
		0xC6E027CC847301D8ULL,
		0x15D5AE9612FAED78ULL,
		0x03FA3078BBF27275ULL,
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
		0xE1AC8304DCEE95DAULL,
		0x5F9B84F6475B0B2FULL,
		0x7007BD7B583B3CD1ULL,
		0xA8080AE257B35BD6ULL,
		0x59AFB71AF6DBAA8EULL,
		0xED7833A079CDE469ULL,
		0xCA91BBA350155D2BULL,
		0x3817881E985CFDC6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB76CB10121129C27ULL,
		0xE786606B4046ABB3ULL,
		0x24C549656354FE57ULL,
		0xF050641BD3EBA040ULL,
		0xB02C6CA90D225A06ULL,
		0x1B4C6E310AEDC3A1ULL,
		0xB789B96CDCAE39DDULL,
		0x087DAD0255B3643EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x53BCDEEC6D5DEEDAULL,
		0xAA9473157C593D1FULL,
		0x1E72C82B16357C2CULL,
		0x488E2CF868F485C9ULL,
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
		0x471034A7902D482CULL,
		0xFF0E3175A7D383A3ULL,
		0x4D0CB02A0A9F5BACULL,
		0x202BAE69FB01AC43ULL,
		0xE60EDB44DAB019A6ULL,
		0x2DC2767B1CCF736CULL,
		0xE41C6EB12679349CULL,
		0x23837FECE985C259ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8AFC0A92D9547826ULL,
		0x9E577632EA3CFA9BULL,
		0x58760CE1F113BD9BULL,
		0xD69E39C73D5A8797ULL,
		0x229DB0BB82F0ED40ULL,
		0xEB1A5FE205B1518CULL,
		0xE65E74E8F9AEFF10ULL,
		0x0A0BA7D7DA70F532ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBEE07A77BD39679CULL,
		0x45AA15FC2C0F9064ULL,
		0x9EC9B6FEBF8F90BDULL,
		0x115787C2FABD9875ULL,
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
		0x53359F88099DA7B4ULL,
		0xDD575B3B1AF4F0C8ULL,
		0xEFA2204374EC198EULL,
		0xAF211FFA6076018AULL,
		0xFAB3F2E0847B71C3ULL,
		0xC1970686EE1F6E2AULL,
		0xDC5814A8162F173DULL,
		0x6F1E373BAC3246DFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE59FD11461A8BD43ULL,
		0x3AE886DC80CE2576ULL,
		0x53E768829BD4B25DULL,
		0x8BA915827062851EULL,
		0xE58A0D3CFA2216AAULL,
		0x200E9B27496C6638ULL,
		0xB0FD7DA76B9060A4ULL,
		0x518832D76634ECB3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x91CDE4BA313870D2ULL,
		0x9CAEC4910CB9F940ULL,
		0x0B2D21DA2CA681FFULL,
		0x07BCB15A53AEDEFBULL,
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
		0x81D3A60C20020073ULL,
		0x9FC00237EBB97DBCULL,
		0xEC3FBD9CC059D6F7ULL,
		0xC4CEEEB4F6E04E8AULL,
		0x5B1B26518EED05B9ULL,
		0xD613E96741EEDFEBULL,
		0x055EF2374D666C97ULL,
		0x6D1EA10C81C85D61ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEBB93570EE0630B4ULL,
		0x597ADB22EC4AB1DCULL,
		0xCC6AF3145FC0ABFDULL,
		0x6B975ED2D2F33FD8ULL,
		0xC1C9A26643BC048DULL,
		0x590F0B2CA8F04C5EULL,
		0x607ACC05A2F66DDAULL,
		0xD038FF804AB61146ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x583405885B41FA20ULL,
		0xD4FE23C7B538B2BEULL,
		0x99B275E7AD38FB1AULL,
		0x234D8AB250A45AA6ULL,
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
		0x742C65B6504F640EULL,
		0x962D5906850F4596ULL,
		0x533EE8E7F34D4E8DULL,
		0x6E6960A15EDE026AULL,
		0xF6534B4CD5D73409ULL,
		0xAB3709BA93436A86ULL,
		0x4546EC692AE24C14ULL,
		0x53230A7E1A63AF5FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0FEED294342BD4A8ULL,
		0x26ABBF5E3FE23B7AULL,
		0x9B47B9B0C187F88CULL,
		0x9331F64CBEC60B9EULL,
		0xDFF9A8710AD0B058ULL,
		0xD4D70F720EF6A4E9ULL,
		0xC987EE4A8F088108ULL,
		0xADF10C9F886E16A9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB58BBFC23F1B1998ULL,
		0x41C0C06BE8925F6DULL,
		0x1650E7C2541979C3ULL,
		0x60A3195E4A8CA1BCULL,
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
		0xA26AE903440E0679ULL,
		0xF56A6A0EDA36BC60ULL,
		0xA4780576A775FF7AULL,
		0x76E5EFDDF0C3C0A0ULL,
		0x336C129F972E3C2FULL,
		0xE7CD280375B549D3ULL,
		0x96FD88F9BF405A05ULL,
		0x8A8EC20B6AE27DC8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x630C236C87F2D066ULL,
		0x23981E40FF4480FFULL,
		0xC4F464542AA77587ULL,
		0xCA4B4F8021932EC5ULL,
		0x6B200875FD12AAFBULL,
		0x430D41A707ABCEEAULL,
		0x8BA810014558FECDULL,
		0x7959FE56C22996C3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFAA847C39C32C417ULL,
		0x464E7D86305A79EEULL,
		0x8E3396049526145CULL,
		0x3A6FAD2EDAA2DC9AULL,
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
		0xAAC2EC2BF4C021A5ULL,
		0x9CFFEFB5A328CA1CULL,
		0x2FC96E8C3626A75CULL,
		0xE5032B75F989B8F9ULL,
		0x446E59B0D0503527ULL,
		0x0BE2C95458D12F19ULL,
		0x3409D40944337D9AULL,
		0x7DAF667E8195FF21ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC925964207AB8945ULL,
		0x1A42C264CEF059F3ULL,
		0x0AD1905E3683987BULL,
		0x01FFF453F28B8E1DULL,
		0xEF8B7CFF5A093037ULL,
		0xE035AE6A0D20788AULL,
		0x0979DFDED367803AULL,
		0x094C9CB97CDE885CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7B4A18417B9F56ACULL,
		0xFE6F2C1810738949ULL,
		0x76561C7ABDEAAB01ULL,
		0x29AD2A60BA39CC20ULL,
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
		0xDD8978F14E01771BULL,
		0x748D77F88B2EF8CDULL,
		0x54071F555BF0D597ULL,
		0x6DDF06B8B9F0D49BULL,
		0x5C90FFA532DF81F9ULL,
		0x2A5B5D8F08E220D7ULL,
		0xDC5FBF412CCF2139ULL,
		0x965513D8ED7A905CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x37A24A9A6E0B7599ULL,
		0x43AE14C35B656687ULL,
		0x570DB85423D6BBDCULL,
		0x2BDBD244714A1D61ULL,
		0x0E889AA3F74F6B56ULL,
		0xA0A426D3858407D4ULL,
		0x9B74F4668732B63DULL,
		0xD27632BCEBC2E68DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3B262C85B7595C5EULL,
		0xA211830AAFC148C4ULL,
		0x9FD38375CD51FB11ULL,
		0x55189E9C89E9EBFDULL,
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
		0x109BF80410495A61ULL,
		0x0712F9474C0006CAULL,
		0x902D950199F41C22ULL,
		0x59211455CC5A0E9EULL,
		0x5F836AF9302DBD96ULL,
		0x1C055466BFFDCB0AULL,
		0x30FFE070C1DF4C2AULL,
		0x48043C2A8D6F1DB0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5246F7CF45EA9F10ULL,
		0x87BB8E2E929BD05AULL,
		0xCAECFBB51A670076ULL,
		0x9B7B3FC686FBF982ULL,
		0xD03B31F1B687ECD1ULL,
		0x3A7A6D2726E6F80CULL,
		0xF6C66145EDADD772ULL,
		0x611D134D0844DCA7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x030D7750D8FBB7F7ULL,
		0xF9F5BE8972C78813ULL,
		0x69C979A7FEE46EF6ULL,
		0x03F5E57109A3BC54ULL,
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
		0xB60B5075A5CE3759ULL,
		0xEDBADB4D2CD8C0C0ULL,
		0xC18658E1BC5064A8ULL,
		0x3FC19FFF91DC14C5ULL,
		0x956CB31FFB79FE5EULL,
		0x2E3BC9FF8A210E00ULL,
		0x6B07530D1C4BAF80ULL,
		0x893F9414CC2BFE01ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8C55E016354EDD66ULL,
		0x743EEEFD497889FBULL,
		0xA7D26698AE74E323ULL,
		0xD797F9CC3588103FULL,
		0xB28C897EF958C2D8ULL,
		0xE6AC6639AFDEA59EULL,
		0x3D9DBCD9BA0648D5ULL,
		0x87B1CDDDB38B2BD1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD6FB9E45C16E2FC4ULL,
		0x18C4BBAE493BB54CULL,
		0xD7603DE9A428BECCULL,
		0x23351261043337ACULL,
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
		0xFD5E256BD0485449ULL,
		0xBC3071ABEF832D0AULL,
		0x0577F7016ECAB4CBULL,
		0x99B52C28B8E77D9EULL,
		0x3735A4097420B780ULL,
		0xFFD88355CDDEED81ULL,
		0x591ECF6A1F2C7A6AULL,
		0x887C8037E4A608A6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5D0EE9252DC866F5ULL,
		0x8F3A801B3AF01775ULL,
		0xD9549C76BE15D745ULL,
		0xF7EBE6EE08F62F35ULL,
		0x9028B5CF517FBA0AULL,
		0x642833C6F7FF5B0EULL,
		0x687CFED81E78322BULL,
		0x328F4F14C0EF0D05ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6C3A98E7C6658EA0ULL,
		0x4921C0C473C2D29AULL,
		0xE4285036CB7796F7ULL,
		0x62FE9071FD1AA84BULL,
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
		0x851C5414BE4A7192ULL,
		0xEBE2886F63A3E8DEULL,
		0xEBE26CDE53C59F76ULL,
		0x2B3B01D388B207EAULL,
		0xC42C997EF712F93EULL,
		0x3C3DF30A03D75955ULL,
		0x271FDFB06B9B3C85ULL,
		0x9A68F1A263240FDFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F1C80F256E064FDULL,
		0x48D8C91AB599C42FULL,
		0x02A8CDD3B6E90601ULL,
		0xD594789CE6DAF75DULL,
		0xC347E1485A939C2AULL,
		0x55FFE647EC274422ULL,
		0x34FAEF06D9122C0FULL,
		0xA2DF5CA0D54A5AFCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x97F32B3DA251DD41ULL,
		0xD03FA424322D4A41ULL,
		0xDAB558365D350AF5ULL,
		0x1412A771B027EA3DULL,
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
		0x00074860588C37BEULL,
		0x89B1AF116E1A8F8AULL,
		0xDC5B4C7AF5715B5FULL,
		0xD298EB9434D05A8DULL,
		0x2137337E543A8D8EULL,
		0x026FFB4A8E880DB2ULL,
		0x0756FCCA1B6AF65DULL,
		0x262C1D54FBB97815ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x47398DCE0D61E8E7ULL,
		0xDE2E3818EBC38067ULL,
		0x0B98E1ECFE2A09E9ULL,
		0xA2D4471074D5E0A5ULL,
		0x05F9B3981B7F8FF5ULL,
		0x0CACA649CD4B4205ULL,
		0xC32E57CDC635128AULL,
		0x4EFA890253207E51ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC3EEB6BEB6EBF2A9ULL,
		0x26821515315D4AD4ULL,
		0xEECAE8029D4722C6ULL,
		0x2120A8C8C6AF8CE4ULL,
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
		0xB38D3258C1BD8602ULL,
		0x461C63D6BD810A3AULL,
		0x204CC46CE5E396B8ULL,
		0x7166F10B49A830CAULL,
		0x257AB51F8A7D4F82ULL,
		0x3D3D2ACF5E2FAD02ULL,
		0xBF9D184031DC5C4AULL,
		0xE67774A335F4C67DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF479148949A6403FULL,
		0x3E5A9F4983962373ULL,
		0x75604B9EAA7561BDULL,
		0x1F6073A0E5894CA2ULL,
		0x3EE328D0F1D18FDAULL,
		0x0B83E4CBEC45C9F2ULL,
		0x0279EF501DA59C11ULL,
		0xC206269BEFB8DB52ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF992F17A2195B984ULL,
		0x6942291022A29B22ULL,
		0xBE248C713B8EBD78ULL,
		0x3AD8127ED103CCA5ULL,
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
		0xBAE27278FE524EB6ULL,
		0x29C1E34DDAD88841ULL,
		0x6D7F49D9406E218BULL,
		0x2288C6173049A2F8ULL,
		0x995BFF24F8DFADA6ULL,
		0x3B9885D804853074ULL,
		0x1E52F3816FFB6FA1ULL,
		0x6CCF1AC07B6FB087ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x549250A9050C7961ULL,
		0x4B2BBFCE0E6B39D1ULL,
		0x4BF857A6FFEF2C01ULL,
		0x10DEBA1F156A9B37ULL,
		0x98DDD75CC0698BBDULL,
		0xA0D69C273E8B41DDULL,
		0xFC5CA6268D2D0481ULL,
		0x657AAB98F3E9CAAAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x790A09885ACEDE11ULL,
		0xD75ED3BD2F86B8DAULL,
		0x2C166DAFEB22DC3AULL,
		0x28328BD638BF266EULL,
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
		0x8B681FF0E3D1914BULL,
		0xA319D92BDCCBFB95ULL,
		0xE7EEC4DF778EE6F8ULL,
		0xFFBDA7C0C4E9DCF6ULL,
		0xCC9A11067B689FADULL,
		0x91427041F5CE5E99ULL,
		0x30D24280EF1FA1B1ULL,
		0xAB9C21F3C397861DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x28B46DE5272413B6ULL,
		0x94664198393B777FULL,
		0x70D99B10A74D4F61ULL,
		0x7358A707D8A52221ULL,
		0x2A05AA206D6907BFULL,
		0x88F0A72112C796C1ULL,
		0xD6BD0C63775F5462ULL,
		0x5869B8C54187B7EDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x84BAF831D09E0CC4ULL,
		0x4AD7727556922E3EULL,
		0xD63B322E96CD1152ULL,
		0x65E09DA03A9D55DCULL,
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
		0xFB7BD0C03B4EE3E8ULL,
		0xDF308D9118416F6DULL,
		0x9E73CA446F3356F0ULL,
		0xFFD32A2041D480AEULL,
		0x81B4F166CBB1465BULL,
		0x636485BED836EEBAULL,
		0x556DC6AD7842E8FAULL,
		0xE850E6E1A4B093AAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5508E3B0F07EFFA2ULL,
		0x52C5402743BDDC08ULL,
		0x74BC5BE069C4A674ULL,
		0xBCF1832006F34DFCULL,
		0x21EFF7C53CF60468ULL,
		0x17DA81A4AAF4508CULL,
		0xEADBC379275FC5C9ULL,
		0x2F5AEABEC9A6B8BAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDDAFFB0A7A9BB26DULL,
		0xC2E7E94C8C670E47ULL,
		0xFB63E8280725E9CDULL,
		0x3765142CBE57B23BULL,
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
		0xD79B71876B927D6EULL,
		0x3D420537554C27DBULL,
		0xD939446102FA0654ULL,
		0xA346EB364C363441ULL,
		0x69622E931203BBB6ULL,
		0x45DF417188B93E07ULL,
		0xB37C488C9E7E10DCULL,
		0xE94F2FEBF567F0BBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFA6B1EEC9FE357B6ULL,
		0x8F4EAF89CB8D691FULL,
		0x9A7ACC4A93287247ULL,
		0x20A6581D632AA8F8ULL,
		0xB289BC756C90EB9AULL,
		0x237B2948EAFEC732ULL,
		0x9D6DDA6F7AF1EE50ULL,
		0xA51CE93C599A9B59ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x015143015ABA0B6FULL,
		0xC8CEEBB4F36C624FULL,
		0x84E2D069B69EB4D9ULL,
		0x2217112A098637D8ULL,
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
		0xEC34420CD9492615ULL,
		0xFE81D28C169EC4BBULL,
		0x90C61C19DFA89D39ULL,
		0x95CB5D1EADDBF3D8ULL,
		0x4E14F02CFF130026ULL,
		0xED9D2CF57893B6C0ULL,
		0xBC84B04DE1E37798ULL,
		0xE0F96B0899CDA301ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9D030A46298FA2AAULL,
		0xB2DEF3199ED75DDBULL,
		0xFF272BD579308297ULL,
		0x204FAC273C9E793DULL,
		0xC924E8D8EFC398F5ULL,
		0x6B404C758BA30E85ULL,
		0xBE9E40523FBA3E6DULL,
		0xB1B9060304CFEEFDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0AD24E40F582D5BBULL,
		0xA56C326FA3805F90ULL,
		0x41D38F9E78969717ULL,
		0x790AAFCB8EE63332ULL,
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
		0xDD9966C875E6D3C0ULL,
		0x358741F760609A71ULL,
		0x7698968CF109CCF7ULL,
		0xA5AF7B41CF2EF9F4ULL,
		0x72FB7C5D44AE51AEULL,
		0x92719E1A3A3AD0F0ULL,
		0xEA017362975B6BD2ULL,
		0x4A0A7E7C28B3492BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x94B2F2EBD4F3EC54ULL,
		0x8F049D986B458386ULL,
		0xEA5BFED59BD636C8ULL,
		0x8A7C4629248DFB89ULL,
		0x434D14CE3A6C9420ULL,
		0x7EB9AEDAA488AA31ULL,
		0xBF7B672145CA06D7ULL,
		0x60D39C8BA8CCBDD5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5CC9D31826B509FBULL,
		0x93D027CF2D8CD74CULL,
		0xDC22696970C89373ULL,
		0x3958BECBA6D9AD34ULL,
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
		0x214E82D22D59C3F4ULL,
		0xAD57CEF95AD3C04DULL,
		0x51A0D7EF946D5BC3ULL,
		0x233E0F6102E0AA67ULL,
		0x123D576B83AD310CULL,
		0x7ED54853563D2165ULL,
		0x802276A811788691ULL,
		0x2581C68EFEAB7DADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4F7DED7D04DA89A9ULL,
		0x7923805BCB0F5526ULL,
		0x6C56D1020850D73EULL,
		0x15F8CC1290288A6DULL,
		0x2D2BF165C5BE070AULL,
		0x9FAF4A4499D4D901ULL,
		0x392ED9FD971F91BDULL,
		0x03DE553F21DB14DBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD265BA2F59FF7755ULL,
		0x53D804CD873F29FAULL,
		0x6D73483BB550DBF8ULL,
		0x0B88152939A7AF30ULL,
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
		0xCB93B752A0832FF1ULL,
		0xB916CA48C64B13D2ULL,
		0x0BFFE82827F9B009ULL,
		0x0386FFC6709B3E62ULL,
		0x8026CBDAC9896CA3ULL,
		0x80737AB92B9CBFC0ULL,
		0x5EFC2EBD3B24598DULL,
		0xDE71C5EAE0B7C1B0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF138D4685FFB5709ULL,
		0x86C883C381B78E29ULL,
		0x1EB774EDED3EEE9EULL,
		0x1CF87CA316FF3E22ULL,
		0x44D46CCED0855316ULL,
		0xA414E33061F525E4ULL,
		0xB1F3D5631D848A55ULL,
		0xAE56E3C284EEBE57ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA894FEB13723A4E0ULL,
		0xE858C4D333745C59ULL,
		0x9C85B69AA07383B5ULL,
		0x0A8C1520F9727F69ULL,
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
		0x4C1796B75C7546D5ULL,
		0xAE23E063256DE62EULL,
		0x9311E5609FCA4D6CULL,
		0xBBC21C33C1C50228ULL,
		0x631FF7FA56E6E732ULL,
		0x672560D7881BBABBULL,
		0x7CA14BDDA6C0C75CULL,
		0x32C8AE3DE7AB73E1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCA177354D3087003ULL,
		0x6D873F67FE8AA2DCULL,
		0x5280CDC10B67A298ULL,
		0x01EC200106D24B36ULL,
		0x324BCE1BC3B12A41ULL,
		0x42AE97602B1492ECULL,
		0x03F21D8C758D493BULL,
		0xA0C3095F3B8DE61BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC17E5A6C6366E038ULL,
		0xAA3E88B2F5F32C12ULL,
		0x2A91F7ACE20763BFULL,
		0x66AC75404755C268ULL,
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
		0xC7EE37D9171EDE44ULL,
		0x340A4A36DE6BA2FBULL,
		0x8EBB9661242053D8ULL,
		0x45A54EE405A1E1A7ULL,
		0x696B7479D225C012ULL,
		0xF10313843C87ED82ULL,
		0x8785A063F26DA35DULL,
		0x5AE87D1EED33A26CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x278A144E5CD32095ULL,
		0x3512B71F94EA9380ULL,
		0xB8E0683859B243C3ULL,
		0xC53585BF77284D48ULL,
		0x4485EFCADA31FF2FULL,
		0x3A2E0F88B220B9A6ULL,
		0x4206EF9368FAD71CULL,
		0x9E806FEF29BC2CE6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1A75D583887A5DBFULL,
		0x22962A6DD4D2C229ULL,
		0x26A96D1D317861D6ULL,
		0x77E1BE3B9235064DULL,
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
		0x18A7B63B47C5F949ULL,
		0xFE5D70629605F7DAULL,
		0x14F60C62981D00DFULL,
		0x028B663E4C45057FULL,
		0xC677C532128EF88BULL,
		0x384805886561A315ULL,
		0x81720AAC5C4BE50CULL,
		0x90BD44514BD85C88ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB9686AC76D4A8EC4ULL,
		0xE79F7E7383F09EA7ULL,
		0x14F551C03C5D2155ULL,
		0x62043BFE4F92AAC5ULL,
		0xA102CAE41FC7F307ULL,
		0x7D9A553BBE748B51ULL,
		0xC18C771F0B9C1513ULL,
		0x44CCFD92D4239983ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEE9C7305E4063DACULL,
		0xCC861D4FD946E04FULL,
		0x7C14A19C55D8BE75ULL,
		0x6631AA85C1874D6EULL,
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
		0x9F5BBCFE2D17772FULL,
		0x0B5E31CED83E01EEULL,
		0x1CF75D3166463264ULL,
		0x12ECA97734721A39ULL,
		0xE72393AFB67B11A8ULL,
		0x21E90495CF54BA0BULL,
		0xA428B7C3D8A0D434ULL,
		0xDAA4724321963ABEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x328B1872C0AE1D83ULL,
		0x1E843A0BC7DB734CULL,
		0x375FB034D32D23BBULL,
		0x6144E8D3385DA0AAULL,
		0x5672431908E23AB1ULL,
		0x023D30416DAA66C1ULL,
		0x4FCD5475E3426E04ULL,
		0x163B2CD36B1095ABULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE7229AE931194691ULL,
		0xA05B7C498FAAEBB3ULL,
		0x6B286A8EFF1C39CDULL,
		0x59480F3913EAFA6DULL,
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
		0x9D6B193AA8EB6243ULL,
		0x9763754CE4154C12ULL,
		0x80E076CE15A1A533ULL,
		0x06286F25415E7A9EULL,
		0xEAD4BDEB8A47BA3CULL,
		0x564242ED26537C04ULL,
		0x3AA5E3A279D2251EULL,
		0xFF2FC742E71221FEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4748EB1F9F2C5869ULL,
		0x566BD5878BAD3AF1ULL,
		0xE2E6C55D0AA1900CULL,
		0xFD52B84E5008757CULL,
		0xDD8A1836779678EFULL,
		0xB7C122CE3CD5A44FULL,
		0x29DF9C65718DC9D5ULL,
		0xAE09AFEAA78A32F0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4F36C6FBD00EBCEAULL,
		0xC822645C01161601ULL,
		0x1B6844804525A1EEULL,
		0x147D2DF05F838138ULL,
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
		0x7BB4F1ED587E21D9ULL,
		0x0402F876818CAEC8ULL,
		0x90AA9E8A4C10DFC7ULL,
		0x44E410AA17E3F5C4ULL,
		0x1D0FB386F7D6D2B2ULL,
		0x3EB009F3AE1A17D5ULL,
		0xD7E48724734CFFE3ULL,
		0x6E85DFDEC4764DABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9D4CCA7829027F38ULL,
		0x67E86CC3D34552F7ULL,
		0x3B0FC2AB2F036D67ULL,
		0xEA4B72366831F518ULL,
		0xE254AC81BF113F1FULL,
		0x98494E501C24CB5FULL,
		0x98895EE34828FA8BULL,
		0xE908D18D74F74F47ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x962B323B9CCF87A1ULL,
		0x4F5A65FA58B0B537ULL,
		0xBD22D58B84663D62ULL,
		0x2B28BE857C8BC38DULL,
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
		0xD7843B7B0C6725C9ULL,
		0x59CE5E5CF791CFCCULL,
		0x0181C33ECD9693D4ULL,
		0x4506140EC62D1D0AULL,
		0x22E2CA2F980F13EBULL,
		0x22798413DF906016ULL,
		0x8366026C1B752B3DULL,
		0x7A094E53292040A1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB70B196DDE9138D4ULL,
		0x4B63CFB88EDB5C58ULL,
		0xC02DAA961951FA32ULL,
		0x42820531CE517822ULL,
		0x4BD59F2CB7BFD1C4ULL,
		0xADE169CFAFDE585BULL,
		0x310AB79E98F48E20ULL,
		0x4286D8CF5CE0E7A9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0C6D847A7999BFEFULL,
		0x5CFE74C37D239930ULL,
		0x7AE1332A135BEBDBULL,
		0x3FE1806D4942D9C3ULL,
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
		0x47518A2A96B95DF0ULL,
		0xA09FE5798B1A3AA1ULL,
		0x51B680F67565E65DULL,
		0x41B2F07C524A112DULL,
		0xB50FB5277E52D99EULL,
		0x5878C2BFAAF25336ULL,
		0x8D9581C87F1B91EDULL,
		0xCFA8D9EB79D3BD32ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB30D007417895109ULL,
		0xE84C806797347498ULL,
		0x299FA243F28E4615ULL,
		0x696DCF5EE94EAA37ULL,
		0x026DCDAB790162C3ULL,
		0x1882BF5475426BBBULL,
		0x63AED9C56967DD06ULL,
		0x5812355FE027339FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x184CE61F4947B402ULL,
		0x36D7E6FBEC022265ULL,
		0x6053CF27BB847A9BULL,
		0x18A18DD63897D2CEULL,
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
		0x8CD797694519BFCCULL,
		0x8E16346613DB2133ULL,
		0xA39AEB030FA1AD52ULL,
		0x26BF645CA840C5AEULL,
		0x137D9E617AA6B2C4ULL,
		0x8BAB54A2A182538BULL,
		0xA53718F1F09BE4EFULL,
		0x68D2AAF20FB1C033ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x021F6C3C8CD83994ULL,
		0x517AA7FC1D4BE534ULL,
		0x9EDD2727EC35D17BULL,
		0x5168CA4180187A93ULL,
		0xF8FE7F2458C1394AULL,
		0xD5B38277C7085A72ULL,
		0x62F7C398F070C145ULL,
		0x658B9DA2A8B1D9FAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7996CE3FC0518E54ULL,
		0x3F64BEC664AA3593ULL,
		0xDA246F1129D32708ULL,
		0x51E293E47224779AULL,
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
		0x015AA23BDC2A318BULL,
		0xB6D71C1058D77AECULL,
		0x3DB2A28263DDB219ULL,
		0x6587DB7EC33ED0CFULL,
		0x079CC0DCBB565E4FULL,
		0xB4D5ECF83A5F08DEULL,
		0x09B0333FAD2177B2ULL,
		0xCC28949A26E29DE9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7D741A251BFBB07EULL,
		0x9FBA21B9F852E594ULL,
		0x903B2880F5D69D5EULL,
		0x83DA62F4413AA18AULL,
		0xBF4F50B3AEB88E0AULL,
		0x343C553315A58FBEULL,
		0x88D4394435D121D6ULL,
		0xB57B82B5F0E169CAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3F652E2E9F9B6BBDULL,
		0x2DE98199D40C8FFCULL,
		0xCE1E955523F3D376ULL,
		0x3F5E206A8631EBCBULL,
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
		0x280D7E035DA54B5CULL,
		0x2A4D804121A27289ULL,
		0xE0C5405165E7B354ULL,
		0x5E1BB066E40F7488ULL,
		0x7412C74A9C5A9DE9ULL,
		0x02AF1997F5DA9A8BULL,
		0xD6655802F965E63DULL,
		0x00D0D517789CA7DFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD812C2F25217DC98ULL,
		0x2D525455D431A9C7ULL,
		0x45A8BFC9935DBEB1ULL,
		0xC583209704C91EB1ULL,
		0xB45F8BE78EC7257BULL,
		0x940918D53E7DD894ULL,
		0x136A5CF1B2DDA821ULL,
		0xDE445DEE54D1CEE5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC4958BC50F714A1FULL,
		0x699F48D285359361ULL,
		0x8C5DC5184AC32CB5ULL,
		0x39723FEB2F628B10ULL,
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
		0x67B927839896B0A8ULL,
		0x5FCBB21B384CAFA8ULL,
		0x886E48A5FDBA1BEDULL,
		0x801030082158ABB7ULL,
		0x9CB3791DD68E7DA8ULL,
		0x112CD813669E7994ULL,
		0xA015D582A734FDBDULL,
		0xD0BCAA1DB7857511ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4B39484F42E1369AULL,
		0x54A71643B9779A43ULL,
		0xED4C19F560166A0BULL,
		0x2BDDC0923EAF70E5ULL,
		0x4DC04AAD03BD4D32ULL,
		0x47AEFB0E3C665555ULL,
		0x54C57C65DA0E469DULL,
		0x97CE119DD4DD3379ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD498C3F3A0C2ACD5ULL,
		0xF3D36A9BC32A76CAULL,
		0xC90F68F71162E099ULL,
		0x479D127187A2F76CULL,
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
		0x0AFA6100E62FCC1FULL,
		0x0F75C1665AA8D009ULL,
		0xAF150651C9CB7E97ULL,
		0x836F780B13C7AA93ULL,
		0x56617F5BFAAC047EULL,
		0xFDAFE600B3F4A6AEULL,
		0x6F4D1DE1ED887A36ULL,
		0x2EEB71950CD46D89ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3FC09CD5EC1ADFCEULL,
		0x2D23677D181063CDULL,
		0x79A52AE0C408EBBBULL,
		0x2CC250EC5B4D863DULL,
		0xA2368EEC95C2F008ULL,
		0xFEE62A90E6667F75ULL,
		0x55E4EB1A95056E46ULL,
		0x50E5CC47171FF846ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x899974B3F4ADF517ULL,
		0xB4442C81C5B23EA6ULL,
		0xFAE765082936587BULL,
		0x4B83B0B131438C4BULL,
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
		0xD5E4B7DB926CCAF7ULL,
		0x40ADA922401C1C81ULL,
		0x5DCB6F5E61164985ULL,
		0xB0091B81C36C715CULL,
		0x2E7D276F8B8B39ACULL,
		0x5517C93736432F11ULL,
		0xB95D1E2A7C8F3052ULL,
		0x13A3E61C0E024DA2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3F9859B8F624EDB3ULL,
		0x6308296555AE2DD4ULL,
		0x18E2F032B0234F02ULL,
		0xB6FC66425C3F3585ULL,
		0x1E02F8E40C004491ULL,
		0x9E56984B75DCEADCULL,
		0x22D507DA9C263EABULL,
		0x68C94BF8C2D60138ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x086F46D78AE83D58ULL,
		0xFE52C2BB799C0E8EULL,
		0x9D1BCF070086D941ULL,
		0x557F967C8FC093A9ULL,
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
		0x4BF2C89761553139ULL,
		0x46F7C3E8FE897807ULL,
		0x41F1BE3B777EB486ULL,
		0xEF1E6560E0C02660ULL,
		0x73A1DD460219D30BULL,
		0x2C0A2E872C2C68FBULL,
		0xEA70C7F670B9296DULL,
		0x19A50E4E94FA0C62ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5B4D8CD1C047DD85ULL,
		0x9B0449DF304D0FA8ULL,
		0x51A6079ABA4747B8ULL,
		0x2EFF365BF8A96924ULL,
		0x2B003CF0E0514FDCULL,
		0xC3EE2719F4C494FEULL,
		0xCFA40E3A5E97DC7CULL,
		0x5FD0AC4548914D8CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB8A30868A4D0CB32ULL,
		0x201C944007A5DFF7ULL,
		0xEAAF488B6E28D87DULL,
		0x55A5BC663FA31103ULL,
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
		0xACCEF05B32C9956EULL,
		0x89B4A6E186535062ULL,
		0x2EA27AF4EEF21AC3ULL,
		0x4C3B3D2289D0108DULL,
		0xE4A4E911A09B3668ULL,
		0x12D769AE9BF7BE45ULL,
		0x2FB05B5871F43559ULL,
		0x046E60313DDEF08BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF043DA41AD2F4637ULL,
		0x8CD5AD775336CED4ULL,
		0xA7FADB06D3FE4C50ULL,
		0x664614965D0401D5ULL,
		0xABCA9D1557CF2CF7ULL,
		0xED0D1E802E4DEF88ULL,
		0x8A1D024775089FA6ULL,
		0xCDA2DF5CBB05A888ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2CF25D8C53E3B189ULL,
		0x98E6224E7A5131A4ULL,
		0x1A86D873A5EC06E4ULL,
		0x082A4817990CBF1CULL,
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
		0x22015FE13B2AD7A5ULL,
		0x826BA9FFF1B86BB0ULL,
		0x184C55473E4C22F0ULL,
		0xE88D200F83C21B06ULL,
		0xC0747F6BE3A92945ULL,
		0xD86B1E817A812BE4ULL,
		0x3564583EC0FB4EF6ULL,
		0xC24407776C1A76BDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0DEAEE5F7A823BEDULL,
		0xEF6278425004305AULL,
		0x0822915718C5DB15ULL,
		0x9038A5271BBDA12DULL,
		0xBA4F38A1032971BCULL,
		0xE6863A077B267541ULL,
		0x8FAABC37652DBA5AULL,
		0xF712A5D217D65636ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFD9EF39F139DD8F1ULL,
		0x7B031BD9892B5788ULL,
		0xA9B6ED07C60A5700ULL,
		0x01A8F972EA214DD5ULL,
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
		0x47AB283A6C543A47ULL,
		0x82D359DFF3C7F876ULL,
		0xC7334FB1D3C89213ULL,
		0xF99FD5D7B01EB90EULL,
		0x6CA0A6A35176CB73ULL,
		0xE6891486056A2300ULL,
		0x8EEDB635B1504FA5ULL,
		0x0014C1F94994118FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x34F696B040483889ULL,
		0x35989B5EA8F264C9ULL,
		0x9306F8A51093D0D1ULL,
		0xEDEA702FF6ABDDB5ULL,
		0xC73859F1D9089D5AULL,
		0xB3ADAFCF4788D266ULL,
		0x6D7E99DE0E797377ULL,
		0xB077E904AC828880ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA02FF3E20C66D585ULL,
		0xD9CBB1A17A478A7BULL,
		0x2AAA8C0EEF19701DULL,
		0x5CFD99F70A0D3398ULL,
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
		0x50E7255A90017EB3ULL,
		0xC7595007A323A97EULL,
		0x7523D200A9EA8195ULL,
		0xA263FB20BD0CB71CULL,
		0x4F8592BA80109E6DULL,
		0x5DE599CF18A33C7AULL,
		0xB0D0CB11DB76BBFEULL,
		0xCDD130ACA863ACA4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7CB713B40B968570ULL,
		0x305AAB0FAA0932BFULL,
		0x87BB15D2DE198DACULL,
		0x737704BA698F0F5AULL,
		0x3E8796F5B51EFB81ULL,
		0xE53E0E307A5F70E0ULL,
		0x9B3510469EFC2263ULL,
		0xD5912D88D07CEF08ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x59E370DCA4492825ULL,
		0x7FDD5E83772AAF9DULL,
		0x22867658C603C0D7ULL,
		0x086D6DB85FBDCCEDULL,
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
		0xAE323EA90BBDC361ULL,
		0xFF2CF4F7029659B3ULL,
		0xFE7021B136398790ULL,
		0x62535F63BB3694F8ULL,
		0xCA13466A3A014129ULL,
		0x6AD6FEB3014A10D8ULL,
		0x4A288E6FDCE811FFULL,
		0xF992A7D49AFC7B76ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x86DA10B9860D5CA1ULL,
		0x818F012DA9BF383CULL,
		0x68EED29EEAD6F50BULL,
		0x0B3474B8CCBD83F2ULL,
		0xB158A8EF338DA2B4ULL,
		0xAE3E65C89C9050BEULL,
		0x8379E3F7965B34CDULL,
		0xB6B1548B56548572ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD30B8E327AD9ED9AULL,
		0x7C44A6944C69A556ULL,
		0x136E9CECC44B67E7ULL,
		0x4491478B1F679596ULL,
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
		0xBA2A157D1F530D1FULL,
		0xC26F3E97EBE77104ULL,
		0xAC00F70E058E9731ULL,
		0xAA7A2A01AC884BDFULL,
		0x13D42126A9E9661BULL,
		0x6B59BFB46F963F43ULL,
		0xEC8BD1DF90025A48ULL,
		0xAD4DFC6A32AF39AEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDB8FCA31B5F5C3D8ULL,
		0xAD12E216FF33B3A2ULL,
		0x922FFD930D04DE38ULL,
		0xD16DA9DC98762C75ULL,
		0x89ACF9709F0A9B50ULL,
		0x23F224473BCEA3ECULL,
		0x1C78A16C160F8FEFULL,
		0x24781665709E2A62ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x606A3051066F6661ULL,
		0xAEBD6EB69C54CC3AULL,
		0xFCAA2A9F1293C239ULL,
		0x28CCA4D9E29A64D0ULL,
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
		0x857F670F47A37951ULL,
		0xA87D6064B2BE1488ULL,
		0xBFE2B5D56D0D3761ULL,
		0x07ABD1EB0DA6E28CULL,
		0x5CB10A6B587E8AA4ULL,
		0x5396E9792B46E17EULL,
		0xA2DA584250C33BDEULL,
		0x70C224663B093EA0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBD030EB82FCF2A10ULL,
		0xE6EAA60B9CB4D5B0ULL,
		0xB0B16869D07E0A3BULL,
		0xD625FFFD69733645ULL,
		0xE6B5578C94DB101BULL,
		0x3F1651CBE832B3ECULL,
		0x5B7785AD5090DE25ULL,
		0x8AE7C62B5DEDAD26ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4BD8E56822187ED9ULL,
		0xCCA93E110B08026FULL,
		0xA7DC8F89A409169EULL,
		0x4FEFCEAA764B446DULL,
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
		0xE780D8EC7CB2D0B8ULL,
		0xFEAD21D6B72585FBULL,
		0x8C20662E0616B89AULL,
		0xB6DCCB33627C2525ULL,
		0x52FB4521CA35CECAULL,
		0xE2FF85426A7124DEULL,
		0x13B39F98BE7F8119ULL,
		0xC83A68D6E8A32923ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6669A5D616BFD08FULL,
		0x7AA33B6E7B5D0231ULL,
		0xF99686AEF9A3743FULL,
		0xD104DF75982F5AE6ULL,
		0xAB66D86B53900AEFULL,
		0xA0A265227AD18C04ULL,
		0xAA62C32E9B431B5AULL,
		0x2CEDF70B70A8F655ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x611F562C028E1602ULL,
		0x5DDCAB25CD793419ULL,
		0x348A9740476A5EBFULL,
		0x7330CFF1997054BCULL,
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
		0xCB043955B77B663FULL,
		0x7FB81139BB92B485ULL,
		0xE299B566DB6CE78BULL,
		0xF0970D42E981EBC4ULL,
		0x217290F69F538BCBULL,
		0xCEA53C6C477D775DULL,
		0xE572326F50FB990BULL,
		0xA49F1ADA73E9D58FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x99CA41CB2C5BD941ULL,
		0x89B136855950ACF8ULL,
		0xA31129BB17F7FE23ULL,
		0xD8652E2BDA929EE0ULL,
		0xB43054067DB24F55ULL,
		0xCB0A06819094F3F2ULL,
		0xF0FE82639E77A7EAULL,
		0x40D9E4762A14206EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x690F032F890E88A9ULL,
		0x7F10DB8B88C58959ULL,
		0x88B4AD68430AB44EULL,
		0x6777F1FA04A82FC8ULL,
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
		0x6FD115F3FC15CCFEULL,
		0x838234A95D824A38ULL,
		0x2C9EA29FFCC4D45AULL,
		0x50DBC0D23501A66FULL,
		0x9F123BF0B2E6C527ULL,
		0xB262A1A412302523ULL,
		0xCBFE8CE591348306ULL,
		0x389E07B5BCADD83BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x268F909531927B23ULL,
		0x11858F128F751653ULL,
		0xD6215B2AA731C711ULL,
		0xF10C3B9CCA1935FEULL,
		0x6278D26808001546ULL,
		0xB1056F888770892FULL,
		0x01C305661250F5CCULL,
		0x2D641D0CE215B117ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x48072FA828C16D67ULL,
		0xA5D215AD667E5A26ULL,
		0x5B5364622B5A03E5ULL,
		0x0A685A45DD7E3FE6ULL,
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
		0xB0E6E04330254594ULL,
		0x8979C27EEE8FA866ULL,
		0x5293F2D12E45118FULL,
		0x6B0E2D819D401E9AULL,
		0x53F62A406FB34EE7ULL,
		0x51890B42A9155D5CULL,
		0x16935F02FC6CC729ULL,
		0x9AF10CF771A563B1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0A9B750EC864F6F1ULL,
		0xF0D1E7B91E6ADCDCULL,
		0x2DA2501CC30A8874ULL,
		0x1A318B1B40971112ULL,
		0xD6B4A2A4BA88AB5CULL,
		0x2009E57DE440E671ULL,
		0xDA62B09248064206ULL,
		0x622513A416068ED6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3E058C514C149688ULL,
		0xF18775FB07AE7259ULL,
		0x142B876F32724C53ULL,
		0x3F23A4C5F63CA5EDULL,
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
		0x1F6DCFF29F5982CAULL,
		0x026E26A65D92B938ULL,
		0xAE4E6F97E7BC318DULL,
		0xB604714A6AC19F04ULL,
		0x1678EF7DB09CA0A6ULL,
		0x17DBEE581E4139B5ULL,
		0xC9B18BA7E0096402ULL,
		0x7F7445FE2AF14644ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x10A26C12BD48D681ULL,
		0x5684D401EEBDC479ULL,
		0x59E89E7FBEC55033ULL,
		0xAA9853D43BEA5BBCULL,
		0x59B12FBDC655F94BULL,
		0xC8F273BE4F8FD2CFULL,
		0x6E0739716D9347CBULL,
		0x96E7865752C00FB7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1471DA5CA88D8346ULL,
		0x629185791D2A3AD9ULL,
		0xEFAE052D267F1169ULL,
		0x1050903A46255C43ULL,
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
		0x9E543FD1BA07A37AULL,
		0xEEF321AC56B82CB3ULL,
		0x3E76C01B1CD9349AULL,
		0x48EBEFA093F0A132ULL,
		0x3D469950CF084554ULL,
		0x73B7C6E33B0BDAAEULL,
		0x6D72DFB1D6F23978ULL,
		0x6CDC92BA5E1302C2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA77C0A3180D2D0AEULL,
		0xAE7B3EE613AE80E3ULL,
		0x69CB590A26D3CDD4ULL,
		0x37ECBFF4E22CCEA9ULL,
		0xD2DA8EA22051E49AULL,
		0xD142A1AF012836E9ULL,
		0x134B1DE25B1DED4BULL,
		0xE986409515424008ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC2E1CB8E28472BA9ULL,
		0x5DDB6886DAD3FAF7ULL,
		0x36922BDD5788B566ULL,
		0x0FCF613480C0BA32ULL,
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
		0xC05D3BA82C1EC2A1ULL,
		0x1F59529DE21D16ADULL,
		0xCB1AF7A24B25F0D1ULL,
		0xB523CA57B830FAF3ULL,
		0x8504997C2359D6B6ULL,
		0x7EFF5CA1FA198483ULL,
		0x21C4BAFC33F64021ULL,
		0x2C7627F3C15CEAE2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x44DC8379F3C62473ULL,
		0xA5ED3126789722A8ULL,
		0xE693BB3911090ACDULL,
		0x953907A7385B8021ULL,
		0xEECCA4CEBB8CB3B2ULL,
		0x0C2DA4DB8AC98C29ULL,
		0x23F7FF757CA6C828ULL,
		0x95F5143C1B81BA6FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC7CF09EBA0CBCE66ULL,
		0x848D68EBEF64D151ULL,
		0x90EB12686FE8B50AULL,
		0x7713AFF31E5EABE3ULL,
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
		0x6CD179E023561050ULL,
		0x98A1916933780BEEULL,
		0x5DBE43F679665892ULL,
		0x53C44375470FFB76ULL,
		0x08763A457115BED3ULL,
		0xA538BE91C34A2201ULL,
		0xAC65C3229610D0AAULL,
		0x86AA0C76988014E8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC35FD3A59EAD06DFULL,
		0x8168DC65AFD5558DULL,
		0xD0371BA756190DFAULL,
		0xB749273A1FA15C97ULL,
		0xBBD889EC23F319D9ULL,
		0xE719D2FF8B43DD33ULL,
		0x7381AEACFB2A3E75ULL,
		0x65E7E5BD04AA4E71ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x08D9D37BF7CD8725ULL,
		0x4FCFACB7D490ECDAULL,
		0xFF6231C42186FE6CULL,
		0x794CDBC7192A1490ULL,
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
		0x3A6DEF08BE315488ULL,
		0xA0B6B77FE3595E6FULL,
		0x58944345CE05B2CDULL,
		0x50F776882794D209ULL,
		0x96DF7F56BF2A4D72ULL,
		0x07684A0E736333DDULL,
		0x1403DA2A949A6C10ULL,
		0x8A39E5BD1E57D5E6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBF142FE410B5A968ULL,
		0x486ED2CD946D491BULL,
		0x9363428D388DA40CULL,
		0x2F72F4C70AB81F41ULL,
		0x0C8E62F7FACEBC94ULL,
		0x35142B44F5528A03ULL,
		0x057046F334FE1E7FULL,
		0x1FD8C959DDAD95F8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0363F535D3132E61ULL,
		0x90C4769B05654BC4ULL,
		0xEF18DAF0C6AB9240ULL,
		0x6BEEB87CB622301DULL,
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
		0x50D53418EECFFDA6ULL,
		0x96C7EECDC44A1C67ULL,
		0xCD995550900612D5ULL,
		0xEEB2F62024D81444ULL,
		0x24A99E23F641ED86ULL,
		0x0134D45C4D087EDDULL,
		0x9C8841631367F947ULL,
		0x3739E00651DB4FB4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD5A9A9EB7566FF1CULL,
		0x88C4EA4455E7243FULL,
		0x507CEE208F324930ULL,
		0x72D72F0BB403EB52ULL,
		0xB30A8F1A6863D11BULL,
		0x82D9425A74318EA6ULL,
		0x26AA6E4EBC0DBF25ULL,
		0xD9425025962C27DCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x58C7C598886132DCULL,
		0xCF9AB0CF9E4AA03CULL,
		0xFC09BC34F8386A9DULL,
		0x6E9B22704CD41313ULL,
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
		0x0B2DE9FD2E1A2E42ULL,
		0xE8A0C7E0E67AB491ULL,
		0x8970406E561C43F9ULL,
		0xB587D48A19286BCDULL,
		0xF4DA1E8A7AA746E5ULL,
		0x917AB516E0ED6DADULL,
		0xB09F30F747F1BDF9ULL,
		0x74698B1EF284D23EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x03D858ED7B312DBBULL,
		0xE9D07335939DB268ULL,
		0xF63252806AE5D807ULL,
		0x949394FC50BD14A3ULL,
		0xAD896E1C863D05CAULL,
		0xA2514692D0DB9E51ULL,
		0x8A0407385A0F24F4ULL,
		0xA5601DC217CAF1BEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9D4FC161FAAEA96CULL,
		0x7EF6BC45B581C9DBULL,
		0x4E4620453AD922ADULL,
		0x5C5A7B564002AA2FULL,
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
		0x9FA9686B1EFBBF1BULL,
		0x7E904BBD29C0504EULL,
		0x53EADE2AE6735F79ULL,
		0x03886F086627470AULL,
		0x54E876D22A63BD67ULL,
		0x0A7DEA4F6667BA74ULL,
		0x2B14B82F02DEC16AULL,
		0x67A8885C1ADF357CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB58C8B095E3D2EF8ULL,
		0x49DE1E0195AAA323ULL,
		0x47DBF5089FB67C7DULL,
		0x9ED8F0B29D671523ULL,
		0xB447E0E6B9EEFA60ULL,
		0xE4CECEC5423C3A7FULL,
		0x357D8DDD08F31DD8ULL,
		0x0DA019444273FCCDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC1F31E5472138508ULL,
		0xCCB0443CF28AAB7AULL,
		0x807F314D5FB72A87ULL,
		0x41EFFBDFE8AA9BDFULL,
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
		0x961D26D497CBCA83ULL,
		0x323188EADEAD3303ULL,
		0x5FB5C4F749635F25ULL,
		0x9FD9DFBE65A831C1ULL,
		0x08D982DF61F2C0E2ULL,
		0x714A0E21C6ECBF50ULL,
		0xFB612D6090652D78ULL,
		0x5B1676A6F351F742ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEFDFEBCAD0AFC572ULL,
		0x42768D7882881F20ULL,
		0xEAF56EC045B85F2EULL,
		0x04C28EBEFE7261BBULL,
		0x12DEC7800DAD240FULL,
		0xA6A098B42BDEBFFCULL,
		0x54DFF4233DB0656BULL,
		0x0482C45B853219EFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x29750B3049714E51ULL,
		0x04E269B76038FA59ULL,
		0x2BEED5514A80B1DDULL,
		0x7503C831BFF0AA70ULL,
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
		0x297706492DCED52BULL,
		0xDE12CBB5778EB0B6ULL,
		0x2735DCE4C62C7F48ULL,
		0x98491988A636CECCULL,
		0xA77A2BEC02A912B4ULL,
		0x3B5B7D8D30CD290DULL,
		0x513C8867E9ADF77FULL,
		0x94887C893B06E38CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2C725A8FF65B89A2ULL,
		0x262DAA312E674FCCULL,
		0x241680BA1D783CF3ULL,
		0x57BCDA77EC37720FULL,
		0xA31A6D53EEF6C31BULL,
		0x71C4DB0D75EAAF1EULL,
		0x68A51BE6D93FFA41ULL,
		0xDAE15716C876F7BEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA33AF64C23EB1AB0ULL,
		0xA441407A06C57A64ULL,
		0x899977531907D981ULL,
		0x4F5BCE0DBB5C5D4DULL,
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
		0x0B404DFB7236219EULL,
		0x4B07ADD691A05064ULL,
		0xF3694DC2BBAAA518ULL,
		0x4CAFB0DB0B1A481AULL,
		0x573EAABE2FC20DB9ULL,
		0xD020F61F6DE9F1E4ULL,
		0x4DC6ADCA8BB3D553ULL,
		0x6DE17F36A5C9226FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4E25178BF8063ED2ULL,
		0x0DD6BC785D9E2B87ULL,
		0x69FD9B8AF2415D9CULL,
		0x9F5919BD5721702FULL,
		0x7647960AA2BACC48ULL,
		0xB1F085A8D79135D7ULL,
		0x2B6659061CFF0B62ULL,
		0x976835E8B1890FECULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x21C849166943989BULL,
		0xB861A2F8852E0EC6ULL,
		0xA3B84760383F4146ULL,
		0x035778AFF57B9762ULL,
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
		0xC96C473A4E71AD56ULL,
		0x7CE59307FA0F855BULL,
		0xFF7659E295C26698ULL,
		0x74385887455B0BA7ULL,
		0x98C62856254745EEULL,
		0xD1B923AB6C00F127ULL,
		0x652DDAD79D77E9F5ULL,
		0x657B24B83DF7C265ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x018CAA028DA01C33ULL,
		0x608BB950E73ECF1DULL,
		0x0594148A47A87326ULL,
		0xBCBFE2746AD35FBEULL,
		0x3DB84E61A0422F61ULL,
		0x9B185FF9FF48FF5BULL,
		0x64F640347ACF65B5ULL,
		0x02B015663CC0DCDDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4BEDF7837F92EC25ULL,
		0x3836E60D361E9A94ULL,
		0x0223398F731D94FAULL,
		0x619CBC3F08ADBE1AULL,
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
		0x88B621E0961A356CULL,
		0xF536FB847A41E7F3ULL,
		0x2A8E14435E85A092ULL,
		0xF9D7870BC930998AULL,
		0xE5A77BA984EA0BEFULL,
		0x1502A2B8826F5E21ULL,
		0x3DCEBFEE735B105AULL,
		0x8E678A09B3C74D96ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5AD8F1361197D4BFULL,
		0xD482C2A3C10F205CULL,
		0x86C360ACC0155F9BULL,
		0x0A9752847F87FCE6ULL,
		0x3556E3C2CE0B9F03ULL,
		0xBEA133C0B0D2B940ULL,
		0x007DED11B78A0C41ULL,
		0x7BCEAD8D49865055ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x59D3BCE9A9868C3AULL,
		0xF32AB1A9D6734117ULL,
		0xBDCA005A7F76DC93ULL,
		0x31F0EEFF0F4E3452ULL,
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
		0xF7B0571B981638A6ULL,
		0x9429DFD8FB4C9981ULL,
		0x162145A92BC98CD6ULL,
		0xCBAD867EC4A01FD3ULL,
		0x409BF7A5E84FC374ULL,
		0x0E56A7B4B85BC11EULL,
		0x3C19DE6A544EBF7BULL,
		0x44B2288CB76969C1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3AC01891E6F2B01EULL,
		0x3212605A02D510B7ULL,
		0x02E4BB08BD34CD98ULL,
		0x0D848AE68797B862ULL,
		0xC618DF906223E4E4ULL,
		0x6639C7A66FC8F552ULL,
		0x1E82834C63C460F8ULL,
		0x1AE6CADC14DBECECULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEC65D1BB9BA692DFULL,
		0x5660C19DBE41C8FEULL,
		0x77B41112231EC6A3ULL,
		0x7258E3D05E08EF13ULL,
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
		0x9C2FD9B92105E711ULL,
		0xE75F938EB688FC58ULL,
		0xFA7979945B9F24A3ULL,
		0x762001A4726DC781ULL,
		0xFCA887AF245ACA8BULL,
		0x1250BA14DA9743D2ULL,
		0x6126448F3627F491ULL,
		0xD32698411A804844ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCD5B354EDEA8E721ULL,
		0x1E6E75348247FD93ULL,
		0xF4E092C3C4512661ULL,
		0xF64F249EA43C3870ULL,
		0x371F03AA46D80A2BULL,
		0xCDEBDC5F9A94EA6FULL,
		0xDDF89D3F358FC5EEULL,
		0x80632284CD60CD05ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x213E3D2323C58FE5ULL,
		0xEFEA0741B49A4394ULL,
		0x7E5FBCB0ADE4EA58ULL,
		0x48D456F940DDDA58ULL,
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
		0xC03CA05064DFA000ULL,
		0x6577E03EDB532F60ULL,
		0x0E1D602A2CDB4E4EULL,
		0xBC97918EFF8B96F7ULL,
		0xAA2B3ED136ED41F1ULL,
		0x5C908AFA6D1618C3ULL,
		0xC5B282A0E059F80EULL,
		0x4DBB18C5ABFDEE45ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9A3AE0C8B1980E58ULL,
		0x7A5BD680ED5FE94AULL,
		0x605F8081DF9E8CC9ULL,
		0xF2C9BD11C619FE21ULL,
		0xDC08E6848EEA4F81ULL,
		0xA2D62C5B5032183CULL,
		0x46C098B74A379449ULL,
		0x8557E9C20C13AB74ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBF1ADAE8A3B78D05ULL,
		0x7CC6155C37CB5A18ULL,
		0x85A69854965790B8ULL,
		0x0886CF06F63783EEULL,
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
		0x8C707905B7C003C2ULL,
		0x0ED04D07F7BDCEBEULL,
		0x06BDDE857CE98AC2ULL,
		0xEDB65A6BB4383CECULL,
		0x5D4A154B2D4A8BA2ULL,
		0x1B653FCB465D9D41ULL,
		0xDAFE5B7EF51BF366ULL,
		0xCFA2034CE51BB805ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2B7D92E20281FC42ULL,
		0xCA466F44C8ACAC62ULL,
		0x003110C2662CFEF8ULL,
		0xB2B131878528B6CAULL,
		0x90E9FEF90AE23A9BULL,
		0xCBA3B4DD3252C0E7ULL,
		0xD9A6C8BE9EEADE3FULL,
		0xC1FF209A5726160BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB7363654D0BA0ED6ULL,
		0x1B447D1A28ADD7B0ULL,
		0x398C964FE205AF79ULL,
		0x4132CF654185913EULL,
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
		0x925A402AA56B8240ULL,
		0x36956D904319E35CULL,
		0xC7DDD590CD02545DULL,
		0xEC6061FF757B22D0ULL,
		0x6A056E7629B4D239ULL,
		0xB904D5F357654981ULL,
		0x15163727FCEECA64ULL,
		0x93E5767B8EE3DEC6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4D09B7BA11E2C949ULL,
		0x5B91CE0B1D2F8C28ULL,
		0xED6DBBECE3FC0421ULL,
		0xEE6A9E90FF3253B3ULL,
		0x655825A6DB6C617DULL,
		0xB4CF3FF9F2CF0946ULL,
		0x36F3B2078C5EF301ULL,
		0x0C60906F5D49DECFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF7095736324977D7ULL,
		0x7AF7E28A1437DFF6ULL,
		0xD38FDC749E6048EEULL,
		0x1BAFE93DD324CDC1ULL,
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
		0x1842DED926590E1BULL,
		0x216181F5F7D494BEULL,
		0xF0075865ED16D1F5ULL,
		0xBB83372B380ED412ULL,
		0xC3AD62A32F9AE06BULL,
		0x73C4A9AB048AB50FULL,
		0xAF5C61B994753938ULL,
		0xDCCDCD5CDA161F2AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF739687470A8A50BULL,
		0x8BC5952593683465ULL,
		0x357342A2C6F780EFULL,
		0x3D267289F0CCD660ULL,
		0x78C251BF67C81E03ULL,
		0xD20A436A89E6FDFBULL,
		0x22BC03CAB71AE81AULL,
		0x80FD014DF8AD37B8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3FEDF8345EF94694ULL,
		0x97471A6298B98D5BULL,
		0x9A62073801875B6BULL,
		0x1F5B0ED6BCD458B3ULL,
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
		0xDA06D94F308453B5ULL,
		0x2A406BA18CC39A7CULL,
		0xC540F0215F67B1E7ULL,
		0x02035D85B1F6BCF6ULL,
		0xA8A54356DD73D731ULL,
		0x4DBFE5309FBC15EEULL,
		0x639B5637A3E9FCF6ULL,
		0x3F45419A03034BEEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE136CE4D09CDABF3ULL,
		0x14941C0795C5B2BFULL,
		0x5472AAD9B4F13CF7ULL,
		0xF4CEC1E43E6D13F4ULL,
		0x132B84D658A53A84ULL,
		0x9582F2A8432609F6ULL,
		0x471BCB87995B91ADULL,
		0x9A702F16BFC6E301ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x28E25215DD61E749ULL,
		0x6EB84FD7B543AEA3ULL,
		0xABBCDB693B9A61BBULL,
		0x04D55B1D6E813C34ULL,
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
		0xD89FFE786E6D1B41ULL,
		0x0781154B091B6CA1ULL,
		0x34F70405F2E8E646ULL,
		0xED33B9CE8AAC6D09ULL,
		0x17D68298F1486192ULL,
		0xE4E2B2815F34E319ULL,
		0x18F7503FD8BBA99CULL,
		0x0A1CE79BE7F435ABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB222115D6D38D700ULL,
		0x03AF799F6645A939ULL,
		0xE27C1BFAABAFEFC0ULL,
		0xEE4A12C5D6361657ULL,
		0x81AB4ADB0BFFD20EULL,
		0xFE7E21D81D33B705ULL,
		0x6A002F03D1A77400ULL,
		0xBE690B5EB354F77BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x70E8334B09F98DD7ULL,
		0x36BF14CB6F024E50ULL,
		0x4B29D6F45438EBAAULL,
		0x3B9C581E841991C5ULL,
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
		0x9FAC8C352945E6CAULL,
		0x4643D1B90AC0CD20ULL,
		0x98E68452B9C9F835ULL,
		0xA9631A92E0D8EAA8ULL,
		0xEC91F3AF48BB0D2EULL,
		0x60DF476C0FD3DDAEULL,
		0x413DC6DD8483593DULL,
		0x40E3E4732434B7F7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9C5B232EA66FBD42ULL,
		0x250E2CC4F1C24A9DULL,
		0x910A8EFF906F19B1ULL,
		0x9EC7C7F4018531C8ULL,
		0x9403C83D395DD0F2ULL,
		0xBE1BF23CD7721D97ULL,
		0x6A25B659136387FAULL,
		0xF4010C05A2BC3D34ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x286BDBF4CAAD166EULL,
		0x4A3449F6778105FAULL,
		0xF56E68FBF413EE68ULL,
		0x744772E01735F1CBULL,
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
		0xD01F8015DD6810F5ULL,
		0xC0AFDAD2F31D527CULL,
		0xAA160CA324F85D6FULL,
		0x1B2B795A3AC37EE7ULL,
		0xF2A146307ED39BAEULL,
		0xC589A3A1F102F04AULL,
		0x4002194841589FC9ULL,
		0x3351C1CE65726C62ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3EDA51DD61F72FDBULL,
		0x2B4CCE01594C6351ULL,
		0xFAD8C1F8F259D4DCULL,
		0x86D6BB19A098AAF2ULL,
		0x57C712B6F1E2ACC2ULL,
		0x389B510ADB10A948ULL,
		0xB1DDDC6A79C3C262ULL,
		0x626C53E59534424DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8DA8D24367345705ULL,
		0x80C34F3EDBC7798EULL,
		0xC89E5395D2B765F2ULL,
		0x16630ECF83651301ULL,
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
		0x18EF0D77BE04DEF6ULL,
		0x6A5470D0731352C5ULL,
		0x862A02A4DB9193A8ULL,
		0x9981524A27D12F7AULL,
		0x0443B7C3D8A22B46ULL,
		0x873AACA1641CE1DDULL,
		0x7CCEC08827A3C3D7ULL,
		0x6F8FFC08058A225BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3114E753C40B3D83ULL,
		0x0DA26E2C0D80FDA4ULL,
		0xF26DB624FE2FD506ULL,
		0x88820D46051F35C1ULL,
		0x3F9DBBEC55ECB085ULL,
		0x89EFA60A36B59525ULL,
		0x329D152D508DBCBCULL,
		0xB28372C7064CDDB6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x187D882160E9D89DULL,
		0xF5D4FD1522E7B868ULL,
		0x971BBBFBCAA6CCA3ULL,
		0x20DBA4AA05CA2A41ULL,
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
		0x970A9000BFAB2C24ULL,
		0x705E4BDAFC0D7A0DULL,
		0x02B9714A9D6EC58DULL,
		0x219C07A93755A3E4ULL,
		0xFB272F2C1EA0736CULL,
		0x74DC498AC56D8DB5ULL,
		0x64F790ECA553E2FDULL,
		0xCA2C019E26B39C89ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE1C67BBCA76DA2EFULL,
		0x32C33AA23531E770ULL,
		0xF60DE4D931901607ULL,
		0x263E0D934843CD39ULL,
		0x0F5EC9EEA496D71FULL,
		0x118F1DC3854B1F59ULL,
		0xDD570A880783EB39ULL,
		0xB744BDA5CD59A778ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB5031B6435AABD02ULL,
		0xFB0F90CC4BF7F467ULL,
		0x2E7F7F60D8BD76ACULL,
		0x49B210F3326C371EULL,
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
		0xBEECFA4C37BAA91CULL,
		0xA16727AA7AB201E8ULL,
		0xB721732A078C5CBCULL,
		0xC25A8A2EF6F7404FULL,
		0x89D18C7962818C61ULL,
		0xF2F516A3EFC6AA4CULL,
		0xB85E7B984AC6DF42ULL,
		0x0B5EA8599BE89DDAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2147D3F02A222DB4ULL,
		0x83FBAF600A97F62EULL,
		0x0E18B1730542BC3AULL,
		0xDAA8EF978A4BE43AULL,
		0xB7D708ED64AB2A0AULL,
		0x239C2D1D32ACBC86ULL,
		0x856C591F7A3BEB69ULL,
		0x5640E17E06886901ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC8D4AD23BB6B129DULL,
		0xE49E224A81F35717ULL,
		0x38F9DFA5F6E9D2D6ULL,
		0x4A1D1F2F98F33453ULL,
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
		0x6122DB5C5B89C003ULL,
		0x55BB86252788A939ULL,
		0x883BEF4D631B54C7ULL,
		0x21F7D8682B0A1256ULL,
		0x36FFA48EE8D90478ULL,
		0xCB3EA3109E78CC18ULL,
		0x2B7786B395831283ULL,
		0x671718DB927BEC0CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x95BC4EDEB5E25160ULL,
		0x96D2F34FAB96BFABULL,
		0xDAB3DBAA6FD269D5ULL,
		0x389A4C9B75324B1BULL,
		0x514855C24F26E5F8ULL,
		0x5BC0DABADB61DF2EULL,
		0xD43E305C6C6E2FBBULL,
		0xD21A6206289C2DFDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE49C3EDC7617F343ULL,
		0x4B944F9071591445ULL,
		0xA00AE4930C6294B2ULL,
		0x06E0AF7A6D0DFD5BULL,
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
		0x043C6BD2DDBDA69BULL,
		0x0518485424501B25ULL,
		0x2BFB34EDACBF2C8FULL,
		0xACFBBF0F164BEEF2ULL,
		0x398468BB960B9781ULL,
		0xE61547FE2E918F5DULL,
		0x4334F3384E387422ULL,
		0x8A67E39A9CAE7DCDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x260D7AC8443A672CULL,
		0x5B99D41FDD6509F6ULL,
		0xF66C44EF69848AB9ULL,
		0x350654EC8C79B64EULL,
		0xBC0A536D15872B79ULL,
		0xC740C8984E330F22ULL,
		0xAD43CE1B5B2F99A6ULL,
		0xF1C325BC7EA2DC57ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7E4E1AB1AD2B4665ULL,
		0x3D095D5394F219DDULL,
		0x775A724A568B1042ULL,
		0x2069991AFF8C3017ULL,
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
		0xCF629737D94AC68FULL,
		0x6E1C1575B3D11F82ULL,
		0x8AA53EA360DB2496ULL,
		0x9E1E3B721E6E34BCULL,
		0x09C7EAAA3264A2A9ULL,
		0xCB20390B931E0983ULL,
		0x2E37140F11D4AC3DULL,
		0xD9D23545E1EDAC14ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3B4493C1C309655AULL,
		0x719C6A56B44C8B00ULL,
		0xA9EE8A3F057652F8ULL,
		0x927E95BA7DC314F3ULL,
		0x99391DB12EEC79D6ULL,
		0x832B88ACE0A61501ULL,
		0xBB5A017BC1204E28ULL,
		0xCE7CB2EE2CBA67C8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4950706C9A1770C0ULL,
		0xAAD1D92D7D52DFB9ULL,
		0xED877642562AC8C6ULL,
		0x3A50FEBC864742FBULL,
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
		0xBE0AAD733677180DULL,
		0x79F76D44A3D471E4ULL,
		0xCF4B6C214D4C7B17ULL,
		0x75D7C9BE8E7FCAAAULL,
		0xE808DF2EDF267665ULL,
		0x3F28B91EF563A93FULL,
		0x1C7E344D7A9AB519ULL,
		0x909DD1F193986F72ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x72B35294D97FA50BULL,
		0x07FC0F203E2D78DAULL,
		0x906E417716ED7215ULL,
		0x3C28D4240018BC65ULL,
		0xF4BCBA7D35F9D1C8ULL,
		0xDFEE115EC63C3AA1ULL,
		0x87748BD67AE24A62ULL,
		0x9A2CEE30F1A515ABULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x68A4CD3D7997E217ULL,
		0x94B044AB6581647CULL,
		0x5E4C2C542BBEE014ULL,
		0x4E70C432988661BFULL,
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
		0xE9497B22D387467DULL,
		0x14A2D09021ABA89BULL,
		0xFEFA9A8C7D835CDFULL,
		0x349A36D0893D3AB6ULL,
		0x76DA42A89ECF8590ULL,
		0xB1DD573E9CF1A7B5ULL,
		0x7D3EC29B139A1B53ULL,
		0xBC56DF86A255742AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4B139811FF70A297ULL,
		0x714A4927049A2D52ULL,
		0xA683465C066AF453ULL,
		0x397B4F4C948E2AE3ULL,
		0xAC7443489E4A4697ULL,
		0xB2429373DC77C2D9ULL,
		0x4FF029F85791F068ULL,
		0xF20BFF70E6368FC6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA959CB50E7DDFBACULL,
		0x94519781AF2973E9ULL,
		0x1221FC58604EC76DULL,
		0x023C2ABDE144F6B2ULL,
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
		0x488854A772696860ULL,
		0x65C9CF93642ACB54ULL,
		0xD62347CAEDA9DD9FULL,
		0xF1DBA15813EFC15BULL,
		0x6576022115BBE084ULL,
		0x8F14AB0214575B84ULL,
		0xDC836E319041AC78ULL,
		0x4F393DDBB063D789ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0466C504580DCF74ULL,
		0x19C4EF55BC2F6F3AULL,
		0xA0F2E6636A336E31ULL,
		0x764207D97DCFA85EULL,
		0x2E05923CF7E1A08BULL,
		0x65179570E3BCC646ULL,
		0x3B61F9A0E1AB7A14ULL,
		0x791BFD3BC2B54C8CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7ED22B7F88C116FEULL,
		0x879613CADEED8356ULL,
		0x2027AEE16DC1EA4CULL,
		0x43F1313BDE08BAA3ULL,
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
		0x119CE8CF8A330C91ULL,
		0x38D77888F7DD9682ULL,
		0x46074BCFA08FCD13ULL,
		0x019C5E714B334826ULL,
		0xAAA495A8735D30BEULL,
		0x41A4DCB92B97F320ULL,
		0xDE908A03A69C30ADULL,
		0xA8B035078568DA32ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6DBD722F3C66A764ULL,
		0x51782C39020463E6ULL,
		0x06362BF206C8870AULL,
		0xA919C7167D204FDCULL,
		0xB8D45F19408511D5ULL,
		0x9F2E59DF4633B2E1ULL,
		0x6C542DF556EA8114ULL,
		0xD40F39FCFC7F6E35ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x88C78FE1D9E0FAA6ULL,
		0x04F6B8A802BABBF3ULL,
		0x34C6C9FD6E2756B1ULL,
		0x6867DAEB20B8FFE9ULL,
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
		0x6A352FE688147911ULL,
		0xC60E834809AEF56AULL,
		0x6817E294CA56E019ULL,
		0xFC2E417559A55568ULL,
		0xBB7BBC538CDF49B6ULL,
		0xA8AEDD68BA4ECCDBULL,
		0x9A4C98319CB02022ULL,
		0x8DA0626A3679167AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDEE43E1F2DA654DEULL,
		0x19A4F253BB911BDFULL,
		0x35DE3134754740ACULL,
		0xF2FDBF59D35E3073ULL,
		0xD123702DC7735491ULL,
		0x9714BE31C037D8B9ULL,
		0x1D0AF0C6EF3065BFULL,
		0x826A7CBFEFC181FEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x546C3F62A87487EAULL,
		0x494A331D6D861693ULL,
		0xC9F88B3616054A22ULL,
		0x3330996205872F6FULL,
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
		0x8B4DAB081D805076ULL,
		0xC588566CFD438C0EULL,
		0x648CAB249A024760ULL,
		0xADF46453313B7DD3ULL,
		0x5243A91579EF9E1EULL,
		0x31C88E3EDD3AE8E4ULL,
		0xB291377AFEDDE944ULL,
		0xBE3F2C31A199F253ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAC2F457E53C05FA3ULL,
		0x875C7C00E2A1A893ULL,
		0x4B1F9DA249329991ULL,
		0x3DA82917A287E884ULL,
		0x319C2C3D963A375EULL,
		0xDE0028DD27116B06ULL,
		0x4D89C11157D59435ULL,
		0xCCAEA0D9AFE0CAECULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB7FAED9596AD3107ULL,
		0xADEAE6ED24CA9273ULL,
		0x1888A1311C0C4DEFULL,
		0x4BC0EA49702F6EA8ULL,
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
		0x0AA80D1BBAAFB943ULL,
		0xE7F9087D0911FA03ULL,
		0xCF117BE8030D98AEULL,
		0x17F7F6C94DAF40C1ULL,
		0xC96EDE2DFA77FE9DULL,
		0xF471B407C1841763ULL,
		0xEA260ABCE14B2083ULL,
		0x577AA60F9F54CD9DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD788F92C9296E722ULL,
		0x5069F77ECFC41B59ULL,
		0x6ABF1984F5F7D231ULL,
		0x9D47088C3A960997ULL,
		0x2C25262812D781BDULL,
		0xBB4C66E7678270CCULL,
		0xC64C799342F44DE2ULL,
		0x812298D9C6D47DC8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8C1064CF89EB5A57ULL,
		0x131883CB958C992AULL,
		0xB69DEE908DF90A6CULL,
		0x4BC2E43B362510CDULL,
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
		0xC5D622F745440AEBULL,
		0x8C9AEC86D7E0CF23ULL,
		0xEBCF9D6BDFFCD9A0ULL,
		0xAF78A20240F58551ULL,
		0xA4274F8CDE6D95C9ULL,
		0x6DC0675EAE2CC453ULL,
		0x5997262AFA93646AULL,
		0xD0C10E82EEE1C917ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE7CF3A634AFE3EB3ULL,
		0xBEEC3F686C45A6D4ULL,
		0x16F459E2D03CB1C4ULL,
		0x209FD3EAECBF0143ULL,
		0x62BC1EE06211DA53ULL,
		0xE963E9810AECC8CCULL,
		0xE3BA90FF3BFF881CULL,
		0xA922A103057CAE3BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x93F0222E6FE3A0A0ULL,
		0x73695C04A71A7E62ULL,
		0x5399680759B2DB5DULL,
		0x705D0F13F93880A2ULL,
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
		0x13C09043887BB320ULL,
		0xDF91BBDE0128E80FULL,
		0x0AFDA9B1A225712BULL,
		0xE754383966E80B4EULL,
		0x6F6811D0B3F77EFEULL,
		0x618A0283E60DBB90ULL,
		0x02422197C36DFCD8ULL,
		0x19080E384D905C56ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x925A8905AB8D8B13ULL,
		0x017DC44C4EED6EBEULL,
		0x8A3B47B2A48908C5ULL,
		0x45AB056CE8FE6626ULL,
		0xE7E590265F45C109ULL,
		0x7EF40CA3CA6AA8ECULL,
		0xB4085098F2816842ULL,
		0x40FFC163E1D09629ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9EC546866F50599AULL,
		0x805676D5CC703D96ULL,
		0x1D5767D200BA76A6ULL,
		0x32E49A547C610FBBULL,
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
		0x54707381EB9713F5ULL,
		0x9E690A0056F478A5ULL,
		0xE6BD7F5110414DA3ULL,
		0x0EFE6FBB59F08E7DULL,
		0x9F4138785EB903EBULL,
		0x9D2C000685E92AE9ULL,
		0xA6F0626D583B7180ULL,
		0xA824E8AB06B1901BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC4A9471DD04B6B64ULL,
		0xD1CCE6D2F6154F48ULL,
		0xDC8BEADF4EEACB5FULL,
		0x4323AD032B462C37ULL,
		0x459E4A4301EF075BULL,
		0x9DBB84523CE70ED6ULL,
		0xEE71FC6B28E9F5E6ULL,
		0x35C82E858D60EDC1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDDF6884FE1472864ULL,
		0xB74E7FF0372F543BULL,
		0x6CF4B8C4C76EDB1FULL,
		0x459E644830A27B97ULL,
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
		0xA60EEFC510428868ULL,
		0x05BC221EED8C4946ULL,
		0x8D27EA829C26C503ULL,
		0x6969B5359467380FULL,
		0xC97F09EA8E37BCCDULL,
		0xE0A346359A42B62BULL,
		0x526D626F94834741ULL,
		0x19DEAB9052796942ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBE81AF32EF305784ULL,
		0xE38A15A8BA18B338ULL,
		0x233024FAC648904EULL,
		0x3DD102654DAE1F84ULL,
		0x2D20C1FF336C1C52ULL,
		0x5D06B5EC3BE6EA35ULL,
		0xAF8E9B250DE00C9CULL,
		0xC09A0666621D511DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1D8BED819B4BFF70ULL,
		0xAB6F775A3513DCA9ULL,
		0x97095A97D218E945ULL,
		0x6BC93709F464ADFBULL,
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
		0x4345B1AFBE75879EULL,
		0x97B421E59BD81EFAULL,
		0xAEDE6C926A1A471FULL,
		0x2CAAF8D7FE633971ULL,
		0x2A1374A819EB92BAULL,
		0x841B06BA615D8D83ULL,
		0x6830295AB413E588ULL,
		0x1744F05271AB484BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFA80F3C5A4C5B7FCULL,
		0x7D2B9A1EAD29A21CULL,
		0x58B86FDA046F6148ULL,
		0xCA0775B58AE57E66ULL,
		0x1C41F819F95B33D9ULL,
		0xD9B5CA6E53CB9930ULL,
		0x05738A15C8666CFCULL,
		0xCC1C6611B0857D30ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x55DD3B02EF1DE0F3ULL,
		0x658F7B10F258C131ULL,
		0xFE25A0F3616ACA92ULL,
		0x0AA808BF1F19E11BULL,
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
		0xFC0E7272FA34925CULL,
		0xC4DA453C6B0415E7ULL,
		0xC5A152A223D00C78ULL,
		0xD0BFB3DD0B42A4BCULL,
		0xF0C7BC0092220D51ULL,
		0xBC21F335163FC8FCULL,
		0xBE00BE27314753BCULL,
		0x479F484A5F46B916ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6DF6AF9CD57AF009ULL,
		0xCBB867D5A7611613ULL,
		0x3B051311B6ED595DULL,
		0x5B288ED3256F8F44ULL,
		0x34637EF1BE6939B3ULL,
		0x92D934690324FF15ULL,
		0x04E2C1AC0788A055ULL,
		0x8EDF5024E1D68525ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x84F8D30992290A38ULL,
		0x19EE2FB1999CF83AULL,
		0x050FB9D89F31546BULL,
		0x6215FA9A847ACB5AULL,
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
		0xD0817A7C66B90961ULL,
		0x05F17231804CE508ULL,
		0x3FDF569393B7057BULL,
		0xB820D2B8DB9EB67BULL,
		0x963C58E3DD238D07ULL,
		0x83680A5303BEC004ULL,
		0x760E49015FA526D1ULL,
		0x37B3C50FAE18DAA2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x775F70DF9DD2C3E7ULL,
		0x5E7757BC9CCC45C9ULL,
		0x15559F3A79548A8CULL,
		0xCBF25FCE85F9708FULL,
		0x4FDE5C2896C53C7AULL,
		0xD1E979ADB2293C20ULL,
		0x3044CDA8639C16DBULL,
		0xC9CC3C652C5BE817ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCB158D693AE63724ULL,
		0x004392FEFFB23321ULL,
		0x8672068E83BAD967ULL,
		0x3C8CBC3997B14698ULL,
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
		0x831F22D8DA2E9BC9ULL,
		0x0F5F392288FF2845ULL,
		0xF201A8D1FFAFE4F6ULL,
		0xD357F5F5D18760BBULL,
		0x8CB55A0542EE98AFULL,
		0xD1F392E8B0335BA8ULL,
		0x95BE58AC481398C4ULL,
		0xA42856EA6942F08DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE2B629051855C972ULL,
		0x15846D86EEC8AEEFULL,
		0xD14EA7873A2519A2ULL,
		0xE3D26314D55153E0ULL,
		0x33CD042196C6A85CULL,
		0xC62A5EC9F45B148CULL,
		0x879B9D0AFE49A975ULL,
		0x1E6E09E259FF6C25ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD2E5B99F4FC6818EULL,
		0xB9B8882B7C51078AULL,
		0x39DADB3BB984510FULL,
		0x492D0213403BB44DULL,
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
		0x79449C62557F18A1ULL,
		0xD9E992B59210E50FULL,
		0xBB3494152D27F29EULL,
		0x550FEA358803A934ULL,
		0x820058F8B4631A03ULL,
		0x4837746B5921F374ULL,
		0x2D5F9F9AA464E8BDULL,
		0xF4F34A8F9F92BD76ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA1D5ECAC5EF6D4C8ULL,
		0x5704EF5E255DDA14ULL,
		0x79E7744CC4A80B48ULL,
		0x8FC9D83592594490ULL,
		0xC307BC0F687F5C2CULL,
		0xC2F8DC5F279E8D6EULL,
		0x38B481CBF5AC2AFAULL,
		0xCE1539F94A1FA017ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3055FA573A567294ULL,
		0x4A2F3526C6342FD5ULL,
		0x92B38C7657EC1236ULL,
		0x0A3C8850A4C0C0BCULL,
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
		0x2E435F481431DD06ULL,
		0xDDDC1852DF42918AULL,
		0x865187D84771337BULL,
		0xC894AA06871A0D82ULL,
		0xB400111EBD456A6AULL,
		0x457DA62997DBF2C6ULL,
		0xB148CE195DEC25F1ULL,
		0x7BEF8A45274D6D69ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8031F516E0DC576CULL,
		0x364CD4A5D1969AEBULL,
		0x3027578EFB56DE83ULL,
		0x2ACD5CF1C49A2ECDULL,
		0xE5AEDE8747DDA19BULL,
		0x7BCEDAE2987186F8ULL,
		0x9E8333CF4BCE9660ULL,
		0x3E8ECA7308FD640CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4E1EECACA0BD55BDULL,
		0x97817036F777F72BULL,
		0x1F7F1747FC7DA476ULL,
		0x3A23C64542614286ULL,
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
		0xF642E82E74067627ULL,
		0x6B2387E05BEA97F9ULL,
		0xB14795D64833B600ULL,
		0x9A8E46B81A4C09FCULL,
		0x76075CA5D5A7B86AULL,
		0xF7B890FE48F3CBF6ULL,
		0xC4EF13A4702B849FULL,
		0xFDD73DA7F7999DF2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x524D4C172FDB8865ULL,
		0x36405F4194933D83ULL,
		0xD08F042D8E35CD9FULL,
		0x3F2A829EE143F342ULL,
		0x03EAD2294309EE50ULL,
		0x03C69FE719958889ULL,
		0x7F5AEFE92DAFED66ULL,
		0x752D213E3DDD2D9BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x94322A950796F0A9ULL,
		0x6ACCF20FCF555CB5ULL,
		0x34B5DF7498565AFBULL,
		0x24A3FBCACB00C3AEULL,
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
		0x05CCDE7EB257807FULL,
		0x2C340A2B6242D3ECULL,
		0x995755B81864C6DDULL,
		0x91C83FAE521BA051ULL,
		0xCD89925C22184854ULL,
		0x5DC73D47E938E517ULL,
		0xF7D1941F1952FA1DULL,
		0x31B47C8668DE1524ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE4917C77B6DF801FULL,
		0x618DE5B77E3CD1F5ULL,
		0x19CFFF7642078628ULL,
		0x41732B17D0147722ULL,
		0x1B7EC8EBCF85AAB8ULL,
		0xA09B618DAC6AEC46ULL,
		0x79446064B9A83E22ULL,
		0x7059597641C881A9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8ED548B33D3B6432ULL,
		0xDF28C218EA98F116ULL,
		0x487D03EC09B527ECULL,
		0x03DC48FC4F3B0D84ULL,
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
		0x77D73B2D68F79BFCULL,
		0x33A915E09749B2D5ULL,
		0xB407E72605C7D86BULL,
		0x76A719537654584DULL,
		0xAE040630C7CD474FULL,
		0x993FFDEFEE5EA49FULL,
		0xC181F2E081C1FED7ULL,
		0x8FC092D52023E8CDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5435264BBB89E27DULL,
		0x71C7FC0495E8A90BULL,
		0xF46E4E43B3AD6B33ULL,
		0x8540C929511C6E90ULL,
		0xC727442532382AC8ULL,
		0x837CFBA068363937ULL,
		0x2BCFB5E5330FE74AULL,
		0xEA0DD2D703454A2CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6866E299E18FF388ULL,
		0xFCD371A9EB60FB36ULL,
		0xF80EA6300089EC28ULL,
		0x09EECFE26E4375B8ULL,
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
		0x3753AA2513B2BA2DULL,
		0xD3A6F671004E612FULL,
		0x4332B326C2B8C00DULL,
		0x26933EA0530196D3ULL,
		0x275C1015E8ED7476ULL,
		0x39B6AACF24E93AD1ULL,
		0x0B16264FB26BF17AULL,
		0x0454792AB7BFBAB2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2841370CD62148FBULL,
		0x86E62935A4F1324AULL,
		0x3FEB28754C51B54CULL,
		0x6FC376F831C52C2BULL,
		0x701E58BB08E7F259ULL,
		0x54389B164C8166BFULL,
		0x3474BE28DFCE63C6ULL,
		0x98C1C320EC81DF37ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x423BAA957E62BE29ULL,
		0x5D7722AB7AC6A986ULL,
		0xDF3D0074B9CA1375ULL,
		0x2E96CD1C4C6AFEE3ULL,
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
		0x130639B334D5C9EFULL,
		0xD614672A59E44F95ULL,
		0xF80A4398B4F1E5DDULL,
		0x1A038C5F4DA118DDULL,
		0x0C35DC35DCAB7758ULL,
		0x3EB8C1356BB4DCFCULL,
		0xBF47E6D9F046593BULL,
		0x2043042D3CADE18FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x44AA8758F7C36231ULL,
		0x289C2B7AF64B640BULL,
		0x16B71A20DF778FD4ULL,
		0xEBA772FE9B8AC912ULL,
		0x8BC4EF4D987AE574ULL,
		0x84CC70EA428CCBA9ULL,
		0x51FC846DE802FA1AULL,
		0x2E280C1628A9D723ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDF1EDCD45C480F24ULL,
		0x468C26D77F8B7DC8ULL,
		0x1A83C5810F7A74E5ULL,
		0x1E5CECCDAAAFDBE4ULL,
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
		0x6AF339F7070DFA61ULL,
		0x2BD3B014F8BF0DC4ULL,
		0x564666CC594513C4ULL,
		0x933EBA2842C55C53ULL,
		0x4C583A7F61AEF664ULL,
		0xDB63BD7CE73B2DE2ULL,
		0x60796B7202130A09ULL,
		0xABE25912F98801B3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6CD4FC14E89BF0BFULL,
		0x350570AC8CBA37CAULL,
		0x4C2655BFE39A95D1ULL,
		0x128345FFBF022A9DULL,
		0x9B9E3E0A468F4456ULL,
		0x64E4C6462115A1EAULL,
		0x0718A0FBEB9B7472ULL,
		0x00B7AB8B36FA860AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x39B9B74425267B7FULL,
		0x8DA6F189D5979CBEULL,
		0x4E7E1E93CB6AB26EULL,
		0x6911364F64C38CD9ULL,
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
		0x82C30F1A82E79EB6ULL,
		0x1449B2448F65D91FULL,
		0xDB684883E8874606ULL,
		0x20990232C2F16878ULL,
		0xBD2D7EB0C8B530BEULL,
		0xD5E9139627037EA0ULL,
		0xF1A3DE04031A1FA8ULL,
		0x136E8B920A02FB00ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA4A5831A5E9DC2D0ULL,
		0x137E23C20820DF13ULL,
		0x76DBA7B18233D8D7ULL,
		0x27835CB6271B2706ULL,
		0x219AA3E0128C426BULL,
		0x28C4F85AB1E5A413ULL,
		0x16E184E75C4D5267ULL,
		0x057D329E0946A641ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF5EA06FB2E5D3C84ULL,
		0xB4279955E9B36B10ULL,
		0xDD65DB1328B9E4EEULL,
		0x0AE8D9B4B7CAD5ECULL,
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
		0x80F6651A6915B630ULL,
		0xF51AA5DEEC208845ULL,
		0x77F4B7AC02E02EAEULL,
		0x0E0B64683F0C2A98ULL,
		0x32D0DA81F9C0C9CCULL,
		0xF971A0A6AF137B25ULL,
		0x21700D116A94940AULL,
		0x0EBEF5314F996CEDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x024AF9E0680FA8B1ULL,
		0xFAE52093E44A49C7ULL,
		0xE7B3DCC517E5F0F7ULL,
		0xEF732CBC07E93D3CULL,
		0xAD14E702962D8A07ULL,
		0x9FA4FB8B467019A7ULL,
		0xD87678AB26DD230BULL,
		0x1596674854BBB32EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x58919022C8E18471ULL,
		0x4E96075C9016B720ULL,
		0x654CE214F835039EULL,
		0x1A9D4841740C7F9AULL,
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
		0x71660F21BBCA54B7ULL,
		0x16D66CB8C8FC7561ULL,
		0x1E3FD0E848F873C1ULL,
		0xB75A0533CF62C9C9ULL,
		0x3F6CEFA4C1D54735ULL,
		0xA4EAD90856DF7485ULL,
		0x6A6225024DB6B2E3ULL,
		0x400A8AF678D3D432ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFF3DFD3F3F3C38F5ULL,
		0xB86A76C454B7688EULL,
		0x409CCA412F9536E9ULL,
		0x801B83E67F5483D2ULL,
		0x5D960743FF8FAD5DULL,
		0x34860C50B3A262A7ULL,
		0x62FABAC65B6F38FCULL,
		0x553A2505173D9485ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF80E903F52E2F160ULL,
		0x0D625936AF55B3C1ULL,
		0xF6FCCB8D0FFF5532ULL,
		0x122DA321CC5BB9A5ULL,
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
		0x538F6C25DCCB1EE0ULL,
		0xF7BF1A8846CB2929ULL,
		0x6BCEC2EDDCC72DF5ULL,
		0x029B8E71DEA5EC0DULL,
		0x4599FC61480726F6ULL,
		0xF167C4C32D1626A5ULL,
		0xFAAC6F944F301A7DULL,
		0x3E8A6511FABF684EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9F85AE89409ABBE7ULL,
		0xAF8770D8EC0F85F6ULL,
		0x732CD6458D46A7DBULL,
		0xF3606BE0B4F329EEULL,
		0x230C71F86FC4DAABULL,
		0xC19A8AC7BFFBF010ULL,
		0xFC8839C613AA0DA8ULL,
		0x49F3EEF31EFDB850ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD50C492CB607B5A9ULL,
		0x60AE45018C9FBD55ULL,
		0xB201E94525666DBFULL,
		0x5D90AB25C872E1D2ULL,
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
		0x1364C1867D9445BBULL,
		0xC1EC9C9F84800094ULL,
		0xCF0D03800BF96BA9ULL,
		0xBDED2B7310E5AF4EULL,
		0xA687260042A254ECULL,
		0x824D602611295BABULL,
		0x527C29C61B376F47ULL,
		0x3D2482FFC1DDA1B0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6008CA3DFE2D88D1ULL,
		0x6759A0F4956542B2ULL,
		0xDFB818E2525CBD8CULL,
		0x566A3A039F7556A7ULL,
		0x39281E90DE15158FULL,
		0xD5A4D6817E33B2FDULL,
		0x2188C3AD8DEE1684ULL,
		0x83830D64AC6568F5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEF7711D16C5E2329ULL,
		0xFB976A18BF91C7C5ULL,
		0x33761242B27FDB02ULL,
		0x757A6674A148C470ULL,
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
		0xDD6BD9C6D09F951BULL,
		0xD6F03855591B359FULL,
		0x908AA2CB2D8EC98FULL,
		0xC75F265A3400D42CULL,
		0xF5736652ECBFC79AULL,
		0x571C120DEBAB2973ULL,
		0xF3FC4DC9B857AB60ULL,
		0x159C658C8EED85C7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3CC9931A70D5367AULL,
		0x8E9D947FB99E055EULL,
		0x331EEC57030EDD07ULL,
		0xC6ADE78961700E03ULL,
		0xF81810FF83B20DFCULL,
		0xA119EC2239BFF1D7ULL,
		0x379153F5238AB4F6ULL,
		0x29F8385F6909D703ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3C30F10DF7D3EB90ULL,
		0x4CA444D208677169ULL,
		0x554CCC0240EC8039ULL,
		0x7B0FF384725CB75DULL,
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
		0x519A6149957AF6DEULL,
		0xFBE3B068EB418915ULL,
		0xEAE523A156B65011ULL,
		0x96AD3EE70217E109ULL,
		0xC8C872AEBC8DEDA5ULL,
		0xFD4A8EFAB6462FE8ULL,
		0x77956AC53DAA4D71ULL,
		0x56944514D97D2489ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAED0D17E2C870AEEULL,
		0x7A78A58270B7D776ULL,
		0x764EC27C390A880FULL,
		0xF0B4DBF38B5D2404ULL,
		0x4B70865504369721ULL,
		0x20D901FAFE55E484ULL,
		0x4099A72E638D8674ULL,
		0x7686A058C8C8E27EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3DD6A51CC5EAC2B7ULL,
		0x3A45F8DBC834E289ULL,
		0x9DF569897DF151B1ULL,
		0x67FED6DDF17C8AAFULL,
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
		0x9FA18F03349B9D9BULL,
		0xC4D6AAD469272283ULL,
		0xCECE038BE083D958ULL,
		0x8B8E83894328901DULL,
		0x8F8B3840F638FE05ULL,
		0x1BE9AFD2549B4724ULL,
		0xF3638BF581ACCD3AULL,
		0x7EC52157B52C0087ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5FE5F37F5EF3ADA6ULL,
		0x33B9665C5CBC9A62ULL,
		0x062692EFD243D471ULL,
		0x865623AE24BE0A8CULL,
		0x78A88F0085D6F82DULL,
		0x0C0E808D64A467E8ULL,
		0x252FD638B5CFCADEULL,
		0x41248B1BA6A93489ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA560BB148434CF5BULL,
		0xEBA648B3AB0FAB0CULL,
		0x64546AA2510E5E91ULL,
		0x2B0EACC545D4CD64ULL,
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
		0x0822E27A9482BB8DULL,
		0xAAEE0227D34D90B8ULL,
		0x702514EB0D8D07BEULL,
		0x9CAECE3AE58C4F61ULL,
		0x07A4479A2961EA84ULL,
		0x0548C0DCB8BB9705ULL,
		0x38C24750364CBB0BULL,
		0xBF1F3609EC2ACAFBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x26C7EDE065F946CBULL,
		0xF8D6AFC19F943EB7ULL,
		0x08D5ED9FBF65C287ULL,
		0xD2CD545853F960E4ULL,
		0xB6188B390E6C0AEAULL,
		0x333D55F5A34CFCEDULL,
		0x691854DEC25DFDC3ULL,
		0xA48514F6A54FC5EEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFC18EB042F08A623ULL,
		0xDFC930B362243176ULL,
		0x3A89242283975DDFULL,
		0x3CC262BF1615AE64ULL,
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
		0x2561607D1592DCABULL,
		0x73DDE541FB99CFDFULL,
		0x0EB6A23C50DAFDA6ULL,
		0x40DCD29CF9743F1CULL,
		0x2FFFFB004F21F052ULL,
		0xB854444E4BC472F2ULL,
		0x52927F3E2F98AED3ULL,
		0x278B31CB62E6C0CBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDC99FB6DE6A26155ULL,
		0x37851AD9E5F36B6EULL,
		0x177AC87A4A4925D0ULL,
		0x07F7D0162F7C0159ULL,
		0x725BF824020E681AULL,
		0x7A5958B40F8DB507ULL,
		0xDE9F487A1DEEC8D5ULL,
		0xF1CDB1949A120E0DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6F1FD1C29FD6AF32ULL,
		0x6F97C34D05C69548ULL,
		0x2D55FADCA5C9FB93ULL,
		0x33060AA8998AC5E2ULL,
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
		0x4B3F8E78F2CF684FULL,
		0x92FA86093D81B77BULL,
		0xC29C29CD3EC956CAULL,
		0x78CFD8D23F985298ULL,
		0xEE5695AD75D6B744ULL,
		0x0451EAB45318693AULL,
		0xD59B8946D330201EULL,
		0x3E5AD54F81CEDA62ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2106C71DC56111E1ULL,
		0xC8E21137F982D4E9ULL,
		0x72BFE9FE1026A640ULL,
		0x3C96CAA51F0B2122ULL,
		0xBADC2DFEF6FBD6EDULL,
		0x965711AF550CB431ULL,
		0xDDCD88B3B7BEEFBCULL,
		0x8B7C60A774A4E078ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCE642B4201EBA1A3ULL,
		0x1D54AB8EF9BBC1EFULL,
		0x187055A5416FDF00ULL,
		0x493E5F1F14C84A31ULL,
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
		0x92ACA4AA43FCA386ULL,
		0xFA4152523BDD0A82ULL,
		0xB205936F145EFCA2ULL,
		0x2B117C2577383193ULL,
		0x38A98059A4027CE3ULL,
		0x095841E86D325825ULL,
		0xBA00D8CCF7D9D521ULL,
		0x20E84F86EC7B959EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6D8DAAA17BAA4E6AULL,
		0x76F6D685E806A159ULL,
		0x4A5428ADE8848172ULL,
		0x75B94B3807B6CFBDULL,
		0x8ED8ED52B239F6F7ULL,
		0x7B263511E1A0BD42ULL,
		0x602CDCB3199118D1ULL,
		0x0B382BCB6FB6DA55ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5A14CD10AC163683ULL,
		0x9EB863A50B7366CEULL,
		0xBD28D6982AA66EFFULL,
		0x6D7D7EC1F4B52EB9ULL,
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
		0x97ABFF6755E1FDD2ULL,
		0x4F1E62031FC987B0ULL,
		0xA4F96E2D5788B66DULL,
		0x1E754AA8E04F99D9ULL,
		0xF147A779A8DA5B38ULL,
		0x254DBA6EF7314471ULL,
		0x6FA72071937241A1ULL,
		0x1AA2BA11878E6B5EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCC3707957971F106ULL,
		0xE3935F71F9FEF50FULL,
		0x470FE891105F8F50ULL,
		0xB9E83DE3AAADF9A2ULL,
		0x74B679A39BCE08A5ULL,
		0xA53C3D9A2BE18FA8ULL,
		0x307D6D7AE7DC56EBULL,
		0x4C3D393FD83B15B5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4901C597CC444D6EULL,
		0x6E238A27539F6889ULL,
		0xBE1A1639BF69FE0DULL,
		0x079E2BE53C005756ULL,
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
		0xDC118C82C6FDC1A3ULL,
		0x91B3470E56A90690ULL,
		0x0D7132E5D5ED791EULL,
		0xD9EE67B81D4AE72AULL,
		0x88362AF3C22CF62CULL,
		0xE63968C86EE646BDULL,
		0x7D7482FD74CF3B11ULL,
		0x87E5CAB8B1165E4CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8270120B3B717EA3ULL,
		0x8137F2847D381C22ULL,
		0x7A5D7EF29CB840E7ULL,
		0x732B3CC691645EC1ULL,
		0xEF797421BED419C8ULL,
		0x953BAF211CD1272BULL,
		0xC9BC3C749F7DF290ULL,
		0xAE3BE559D1CE8856ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x05A49DA40ABCF907ULL,
		0x1624E36008939A0BULL,
		0x406E2C42E345FB69ULL,
		0x35FB3706B0904AE1ULL,
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
		0x69F59AEBC70BDEC1ULL,
		0xD76883A70F0D565BULL,
		0xBE78B65DBB271FA5ULL,
		0xCA4908234C734E1EULL,
		0x54F96B9F6B788206ULL,
		0xC0D9F4B2BA8A85C3ULL,
		0xCA44C8E57DCB510FULL,
		0xE1CAEE9F61681208ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x68BA0F5C6E31772EULL,
		0x8BC0C9888F9E5412ULL,
		0x23744A3B9D68F623ULL,
		0xB5BC0C2E2BF5CDE8ULL,
		0xAE0C33CCCF8F3D9AULL,
		0x314A4E27B47AB7BEULL,
		0xDA82FE61A102355FULL,
		0xFDADB35B14A4A612ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC871D4D27D7A8EF0ULL,
		0x9AFA72C165C796F9ULL,
		0x31C87BB4E39845B7ULL,
		0x70E3C818857F86B8ULL,
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
		0x7C5EACC057BCC9BCULL,
		0x210155F953ED0443ULL,
		0xB69914D7D6F19D45ULL,
		0xC7718DEDC2122034ULL,
		0xA49BBCC33F256D31ULL,
		0x78BDE6D7928EF4EEULL,
		0x0D8C732CCF96B285ULL,
		0x5128E73B6FE3F58FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x13F75F4FC195DE69ULL,
		0x82E4D701FC163F87ULL,
		0xDA92791A2A27220BULL,
		0x44A66A29E1E6C239ULL,
		0x95745EC39D6E4720ULL,
		0x1BDFE91578D0FB0FULL,
		0xF7CC08EF6C47A9A7ULL,
		0xA551D2C648E47AD1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA83F416297569011ULL,
		0x671029C72A09DBD8ULL,
		0x169660DA6A85CC3BULL,
		0x04B82D27AA17960CULL,
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
		0x8A126108A443AFABULL,
		0x9AF7FDD7D9CBC6DFULL,
		0xEFFF37244755C015ULL,
		0xCB8FD9D0CFCC5770ULL,
		0x25AB5536B3139BEAULL,
		0xC3ABB3BD92922339ULL,
		0x5359CCEB44FF7BCBULL,
		0x0B5C3D8B27F257C4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB2CB5C17172834A1ULL,
		0x4DAE3B07F24B94BEULL,
		0xB0904EB6744F2D64ULL,
		0xCBAB46870A4DCF29ULL,
		0xE0FF26C556397102ULL,
		0x1E262CA9FA6340EBULL,
		0x8070FD5F55B71653ULL,
		0x05B80CB90DA381DCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x08D5E9C5557DD98DULL,
		0xDF1BCFB87E75C999ULL,
		0x8DFDB73357C5A299ULL,
		0x5643D279AD3248B0ULL,
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
		0x772DE579B2B088FFULL,
		0xBD5469CC89925F8CULL,
		0xCDB0DA93C5BCAA96ULL,
		0x459D7D6649894651ULL,
		0x70A5BE5882A1E3D5ULL,
		0x1BBCAB84286A5ABEULL,
		0xC5AA4E144B518836ULL,
		0x1716C7FA58929E45ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEE88410CC0491B42ULL,
		0xC403ED891529FF04ULL,
		0xD4E2C26237ED98EAULL,
		0xE4AF27DBE1B31E85ULL,
		0xC7628539390C8DC7ULL,
		0x5A9F52A8D9034504ULL,
		0x03597FF6C4CD96FEULL,
		0x37ED3008EC767130ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA8A01F11DE923300ULL,
		0xA3ABACD13DB59A16ULL,
		0xD0CCB0938564DFF2ULL,
		0x011AE3607404D906ULL,
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
		0x393F1B92B774C5A4ULL,
		0x8D62B92C81B8D2B1ULL,
		0x91962BE814C39EFEULL,
		0x0B041708195DEB5EULL,
		0x599BC277BC774E64ULL,
		0x47FF2091ADD4F471ULL,
		0xC944FFFCF9AC29D8ULL,
		0x1E1D7A0115E6F540ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x62C47704BEA13881ULL,
		0xCEB271EF8E0C5406ULL,
		0x2991DA84A623D4A4ULL,
		0x07B0EC78DF3D7F0DULL,
		0x77A250AEA6F5AA38ULL,
		0x9D04AC7705042E8CULL,
		0xD0DD2FFCA362D3C3ULL,
		0x13DD2E071F376D60ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x618188672A11EBE4ULL,
		0x1FDD833202A9DEA4ULL,
		0x476D31703D82916BULL,
		0x08DE71A9D82E9790ULL,
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
		0x49CD35F0FD66E031ULL,
		0x0FDBD007CA16297FULL,
		0x914206B5CEC232AFULL,
		0x597A426B47056023ULL,
		0xF511D4D08C0AA46EULL,
		0xDCB0C468B9FFA47CULL,
		0xB144A87F23617B67ULL,
		0x3365422A1FC5089FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x28E8592D3AA31F2CULL,
		0xD5F14DF5DC7CD0C4ULL,
		0x3D328C171912ECF9ULL,
		0x276107168C4F11C5ULL,
		0x09BC32D675ED1014ULL,
		0x0E1FAEAFD22D8D64ULL,
		0x016299C81BDE8A4FULL,
		0x8F680EF4A9AEDC13ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0F9AE7E30B27C460ULL,
		0xE373BB8456C8C66EULL,
		0x6F9DA9C9D31F0F63ULL,
		0x09AED5444200EB40ULL,
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
		0x284523E76A59822AULL,
		0x93021C317D1F43B9ULL,
		0x969E91FD8418B30AULL,
		0x2C14814DFAA7A2E0ULL,
		0x5ED22B79626F1D61ULL,
		0x3980E23489E4324FULL,
		0x8F7EFD9AF833839DULL,
		0x447ADC467F305263ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9AA8A90C9ACEF040ULL,
		0xE5465BA56FFE98F2ULL,
		0xB87D9E57D523B3FEULL,
		0xDB5D47C0DD4DFBA6ULL,
		0xCA5DF83FE5101F7BULL,
		0xE24A95317F52196CULL,
		0x475FEE8DC6D00DADULL,
		0xC831C7D3263E0866ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x96DC15636BA43F03ULL,
		0x9FCB2EFF9ED05C68ULL,
		0x92BD2F9B03B88092ULL,
		0x439042AC5150A2D2ULL,
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
		0x4FC157B6AD67057BULL,
		0x9817A748860B68C0ULL,
		0x371D22F51F1BC8CDULL,
		0x0F228462A2C69835ULL,
		0x4182B0F6B499E306ULL,
		0xCDB6C6A2277E9096ULL,
		0xDE774FFC56BAB49DULL,
		0x1B3A91986E04121AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD3D49DC1F2E44638ULL,
		0x07AFD53FF9B5680FULL,
		0x5F16EC31A2DB7AFEULL,
		0xA00DC79315C6E33BULL,
		0x91D1CA313AAF01B2ULL,
		0x2B12E0B3D5A2B5F9ULL,
		0xC9E04C5B895C941CULL,
		0xD6D87FB408D0303BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x902EFB44D3602D80ULL,
		0xB4BBF368B2F873F2ULL,
		0xE670C0A1F839210DULL,
		0x15A364B692B33C16ULL,
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
		0xAC92AB47D48FF5D3ULL,
		0x15EAD3E601E040EEULL,
		0x00A3AA1A78FC0C12ULL,
		0xC374A9B22B032BC0ULL,
		0x83002697999B1E84ULL,
		0xF0DE3555CE31260CULL,
		0x7170543438D503A5ULL,
		0xFA928AE42D6F0E0FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x06687760A0A8D586ULL,
		0x5FDA90D1F1B9F025ULL,
		0xF34FB883E5E70B44ULL,
		0xDDC1984924F9F964ULL,
		0x85DFB5C7C335E830ULL,
		0xF54FC0F95B4C6057ULL,
		0x8A3F748426F8E236ULL,
		0x0117621AF5F33E4EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x38FAF2C106ED3630ULL,
		0x0D3588CD1E1BA9A7ULL,
		0x5E9525B939C1F747ULL,
		0x6DFB1F47426A08FDULL,
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
		0x14FB7AA5EDB3478DULL,
		0xE230DCF285141B0BULL,
		0xC9467415F0C73B7AULL,
		0x645429B13AC4670EULL,
		0x146D22A603375C4BULL,
		0x6F932DA28A5F49FDULL,
		0x3AA78F03FD418C37ULL,
		0xF75A4FCD798162B0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6718EF6DB486E273ULL,
		0xCD0C160AD52EB02CULL,
		0xB0D1F92AEA8237ADULL,
		0x098701343FCF70D2ULL,
		0x1774EA9EABE652B2ULL,
		0x7248AC5B232F04F5ULL,
		0xCD5B014F4040B14FULL,
		0x0CC58F2234E30D43ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3ABADC4F2F33D702ULL,
		0xAE33F781010FAA0EULL,
		0x51D183BF1465823CULL,
		0x2CE1C1E92A75A454ULL,
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
		0x0FFEBF379F8E6B36ULL,
		0xDC77764AC97EAB99ULL,
		0x9AEB6A260C6D7866ULL,
		0x26F603C17AC70BA4ULL,
		0xD726CB0274C71D6AULL,
		0x9A247782B3D89C4AULL,
		0x8471A94E30AD4F34ULL,
		0x49BB151267CE435AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x85B36CA1CD074B38ULL,
		0x6090BE4B1644991AULL,
		0x058D0BF2FF451E4BULL,
		0x33BABFAC3D92CC22ULL,
		0xA3CAC3978C88387FULL,
		0xD8920A5A4FCEAB2FULL,
		0xB2C74482295E1EE4ULL,
		0x936BF2B9502178B2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x29F46C744BDD193EULL,
		0x37A2EBFE8CB3DC88ULL,
		0xB4A9547C22E985F2ULL,
		0x02FA5D4EC0DA546BULL,
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
		0x1B2F353A8B1F9BF3ULL,
		0xDE70C007B820695EULL,
		0xAC5DE72793A3B034ULL,
		0x00031C0FB94457B4ULL,
		0x680C64D6812BF1B2ULL,
		0x5C82F81A47B9FF15ULL,
		0x267A407A53554B8CULL,
		0x43910E974D1B1378ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFCD892E4A4DF6284ULL,
		0x0BC08F4E5EED5C3CULL,
		0x9D11144EA6B08E95ULL,
		0x85B3C9CA16784E32ULL,
		0xDC82429E9CD0F29AULL,
		0x977376DDD68DE8E3ULL,
		0xA2CFBB957170A28AULL,
		0xC9C8184E7572B272ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD4D7B6A1CBC213F4ULL,
		0x12FD5FB225BE587BULL,
		0x9A9C8CD274E437E3ULL,
		0x0E23E115A5CA7053ULL,
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
		0xD882CDE0EF60B8BFULL,
		0x94C55D7650C6264FULL,
		0x3C43560A493103F8ULL,
		0x08784117EF533B03ULL,
		0x269E24C4096DBFF3ULL,
		0x911CBCE919BA72F4ULL,
		0xEA3D1CE33C757D0DULL,
		0x2CA9BD8BAAE20E09ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB8AC8DA0D649A840ULL,
		0xBF5E92EFFD8C6420ULL,
		0xE5AD8B1BA99CB825ULL,
		0xC556FAEDF0D64C89ULL,
		0x36D296E3490D7449ULL,
		0xC5153EC292B7B6F7ULL,
		0xFF88E1EB4DB49102ULL,
		0x2C495E274B91CC76ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB80D4F9CA7624B95ULL,
		0x1E83843E5DA1A9BAULL,
		0x2D568BBC1037556DULL,
		0x516F6F102466AA48ULL,
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
		0xECC3FAAEB7D967A5ULL,
		0xAB778F1819DAB281ULL,
		0x9EA83245C6B70868ULL,
		0x6F45B17180F53511ULL,
		0xB0504A34C9A28627ULL,
		0x3E8E6586A65556D3ULL,
		0xFDE2C91F30A3A39CULL,
		0x986608D7CFE313CCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x42EEB7E11B9BB41AULL,
		0x842D60D6662530D6ULL,
		0x84609994BCC81C65ULL,
		0x1696467D17B777D1ULL,
		0x2BE272581C747DE5ULL,
		0xF022657B2EB07BFCULL,
		0xA9D3087439AEB873ULL,
		0xC513EFC7003E50CBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x52234D8F5112EC60ULL,
		0xCB522FF5762DFDA9ULL,
		0x949E3211B249D3FEULL,
		0x36DF23733BB2AF72ULL,
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
		0x7F25934097901CD6ULL,
		0x15A28865DFC7F7D4ULL,
		0x1A3C24094A761CC7ULL,
		0x58AC74919B9EDA56ULL,
		0x89822032B7545C78ULL,
		0x798863E85975A4A3ULL,
		0xEE4E59C4B1208F92ULL,
		0xC8377B50110CEFEEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x10734C129D5B57ACULL,
		0xDD908864E00CEB47ULL,
		0xB8170887AF03967CULL,
		0xD0902668C90E5A4BULL,
		0xBD64D9D226ABC2A8ULL,
		0x7DC9FAF805F63A49ULL,
		0xEE2FCBA392769B95ULL,
		0x8A2D70B7364D53B0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBB0AB983733B9B4DULL,
		0x965593AD64A4D5E1ULL,
		0x66AE346C28ACBDD7ULL,
		0x3D99E0D94B01B13EULL,
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
		0x00624AD779C6B6B7ULL,
		0x3B7CD047EB1EB759ULL,
		0xAABA9BB2683340F4ULL,
		0xCED2C4DCD45686F5ULL,
		0x054B1769A34A5C39ULL,
		0xDC38D4F2449FF690ULL,
		0x610DCC8E356F34EBULL,
		0x5D178DABA47BBF4FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7BD1E36DFEBF6115ULL,
		0x57D218E483B51D7FULL,
		0xE8BD501236F3FA3AULL,
		0xFD25A165C4B29872ULL,
		0xED5288F019CAD93EULL,
		0x0C4E304E5E74F03DULL,
		0x2F92F1611E2F9062ULL,
		0xB3FB8E23F0F4B8BBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x13758D73E3F4C4E3ULL,
		0xC07F27B791CC8A09ULL,
		0x1A39D451A4B1B32EULL,
		0x6BD5119BB5AEE882ULL,
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
		0xBF3F8CB09B949709ULL,
		0x9B8FEE2F1CBF1537ULL,
		0xA0BE6C58209F2C1DULL,
		0x10CB575927643A2EULL,
		0x3326694F6E382C2EULL,
		0xBB93F2C20F2470B9ULL,
		0x0023618A24065415ULL,
		0x2C8B9DB91EA6D99AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFB7AFD744A5E2634ULL,
		0x8236DE45218F29D0ULL,
		0x6EADBDA28B41720CULL,
		0x907B5B2298B4A054ULL,
		0x4C49E08E63F3361BULL,
		0x855DB8B7FA4E7199ULL,
		0xE41717329D45A234ULL,
		0x83A25CBE5519EB51ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0880DBE3D772F5A6ULL,
		0x2565AD6912F3CA23ULL,
		0x5BE3B7B395F8217FULL,
		0x12EFA170799AF88EULL,
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
		0x53D9D86874525225ULL,
		0x8BB247505600B00FULL,
		0xEE840406B1D281A0ULL,
		0xCD5F9956F8F6C1C1ULL,
		0xA97F355FBE13E823ULL,
		0x95B772652CD360A4ULL,
		0x5E107EAD9FA34236ULL,
		0xBA806423B4A309E1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4CDD4C76B1A09D75ULL,
		0x9D8A4F1C35029697ULL,
		0x84BB1DC0378B8766ULL,
		0x386E83CF3132B4B0ULL,
		0xD2AAD33B888CAD26ULL,
		0xA0BC7C8CDD2130D4ULL,
		0x312149C3EDA729C0ULL,
		0xB7989A78F5DA865DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEA831D51B4C47664ULL,
		0x4B68764FF5713251ULL,
		0x154AC0F6E5B29BBCULL,
		0x035904E0198792B0ULL,
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
		0x8660749A72F71F8BULL,
		0x0754D9CBC81F12EEULL,
		0xE3C1232BB0C962A3ULL,
		0xCE8BA5D55F377893ULL,
		0x28073005A47023A2ULL,
		0x5FD2B4820DB00049ULL,
		0x944816F4953B9269ULL,
		0xC089473CCA0591EAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x830BE5E1B721D86FULL,
		0x78B51FA5B998D924ULL,
		0x2963F8AA6BDBB6F1ULL,
		0x42F7DD17645839C0ULL,
		0x479035CAC4FD3BCAULL,
		0x45E88A0CCAF62338ULL,
		0xEE112AC9F8BDB808ULL,
		0x2F8D30CA8A3C2127ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x54FDB375E6E3B470ULL,
		0x6762078DF61D0A4BULL,
		0x668438D47F9C161BULL,
		0x10FF1DB372C5FBB8ULL,
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
		0xA6EFDE23150D5FA7ULL,
		0x060CE14043C3C3E8ULL,
		0xBBC5D08AA0A55A9BULL,
		0xC44E06D922D1E1F5ULL,
		0x7E6EAA83B5888E47ULL,
		0xEEB21D634E16AC7BULL,
		0x1579D3DF871E2F69ULL,
		0xA41ACC573549B21EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x75DF22435D92D4C3ULL,
		0x2B5B56B29220F457ULL,
		0xFC6F8A594ED2AC1EULL,
		0xA8A1154F535C38F7ULL,
		0xCC216E4454E31058ULL,
		0x07F828C3F73B3534ULL,
		0xFF4DBC2055CFEE1EULL,
		0x75C601CF90FE8CC7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA887AD48100B3D55ULL,
		0x1A4BDA349636840FULL,
		0x09E1CC92A3705FC1ULL,
		0x7C4301AC329D33C5ULL,
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
		0x29E3B250A711A1F4ULL,
		0xD0416ABFCD974FECULL,
		0xAB0D18FEE610E0E9ULL,
		0x2AEE88026C260B65ULL,
		0xE7C59CC4C4F51935ULL,
		0x79F4C17D3D6DB981ULL,
		0x7AE489EB6A14DDCCULL,
		0x411BE51B78E96B4EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x66299DE25E9738A0ULL,
		0xF4ED47FB90473D0AULL,
		0xAF0FF38DBCBC688DULL,
		0xD9E15D1A02346641ULL,
		0x7CCEE1202CA42017ULL,
		0x541F774F2FC68855ULL,
		0xA631466E07F2A5F2ULL,
		0xBAC0BBE756059C43ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA459EEDCE47F60F6ULL,
		0x78FD259A44215F79ULL,
		0x8E992A0DBA68C2BDULL,
		0x429548A597C260BFULL,
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
		0x5152B1186C512D04ULL,
		0xDA79BB6DFA6DF7C4ULL,
		0x6D8EB666768BDB74ULL,
		0xC605332673FC393BULL,
		0x0A9AE04A1376AB5DULL,
		0xCEAAB6DC5F1E2F45ULL,
		0xD0B25FEFF2F6B428ULL,
		0x1852BF1AECF90AB4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x98EFE9C9B471DAC4ULL,
		0x45F1F966ECB6C745ULL,
		0x22053C0DEE6AE139ULL,
		0x9F6B087182B106F5ULL,
		0xF3E2127E8EC26B55ULL,
		0xACECBD0AE7274AA7ULL,
		0xD0992C0E2A70E800ULL,
		0x802D2A3F8B688DFEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x17D153846AA0D123ULL,
		0x96BAD71EDC5D1FD0ULL,
		0x4F472DDC4BFD4830ULL,
		0x3C2E43456CBDB54AULL,
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
		0xD3C3B7C5936CB0A8ULL,
		0x563C18B253EE9EB8ULL,
		0x63E1CA72A8D9A079ULL,
		0x32991051F7B7B54AULL,
		0xD03ED15F29A4DDC1ULL,
		0xE95C82A311DC7BC6ULL,
		0xA84CF4B71086D932ULL,
		0xD4D4BF255D1C72D9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8010F0A1D2DD30A3ULL,
		0x5FF08DB36F1E736CULL,
		0xC9AA5C6847C1101FULL,
		0xB4119335AF16B095ULL,
		0xC62699856B4448DDULL,
		0x4FA7EC1DD189843BULL,
		0xBD8FB4B3C5CF35A1ULL,
		0x4B0D448229BFA0A4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD34B117602E59CC2ULL,
		0xC719E2C67120E9EFULL,
		0x724EEE87785AD7F6ULL,
		0x7223B155E868388FULL,
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
		0x9084994956BDFBFDULL,
		0xB75E32F329F793EDULL,
		0x3BCE97DF4E2D4A90ULL,
		0x7597CCD4B16657EDULL,
		0x3D74D408B910FD4AULL,
		0x94C8457D95DA2093ULL,
		0x84038B6F59988470ULL,
		0x4405D120C40B2F1DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9D2795D5E61987AAULL,
		0x907379913195CAC4ULL,
		0x7C947D1BB88D7E46ULL,
		0x31F6905DB99C8A0BULL,
		0xE86592E2AE53969CULL,
		0xEE49526CBBDA45B4ULL,
		0x3A1915D01FF8DBF4ULL,
		0x1D9AB49E62385E2DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x93A0AF1908C1B2F8ULL,
		0xDDC2CDE2545C4629ULL,
		0xB80790662352CEA4ULL,
		0x778777D17D14D18CULL,
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
		0xFF2EBB5E2D425FFDULL,
		0xA16705B702ACB855ULL,
		0xB7F41C93F586F4C6ULL,
		0x3D3EF750676D6FADULL,
		0x75C871611619984BULL,
		0x79DB15D5DD25401AULL,
		0x52641656EC7BF93BULL,
		0xC8AA6040E4F01205ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEE5E6E236B0175A1ULL,
		0x211CDC157B6634ABULL,
		0x49779CB2FC42BD2AULL,
		0xD827A63B31BA634AULL,
		0x05A0891C553CB86BULL,
		0x5CDEB964E40F9C75ULL,
		0x6988C3C926F670F2ULL,
		0xBCD00116E170D746ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB6BCC76F630A25C2ULL,
		0xCDBFE266807CCE38ULL,
		0xFF0AC0EC4B167276ULL,
		0x27817151BA95C4B9ULL,
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
		0x952F6C04C3183906ULL,
		0xC87E9C7EC3523B4EULL,
		0xCDC5BF73C9928742ULL,
		0x0DF367D36608A232ULL,
		0xBFFD10DFBB33210BULL,
		0xD09E818C9EB1FA06ULL,
		0x0DDB676F77B7DA68ULL,
		0x5E9F9497E025C468ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x396D3ECF9A822974ULL,
		0x740CA0A22439AB61ULL,
		0x4B711BFA4EA09826ULL,
		0xF0106E7ED90AB7A7ULL,
		0x0D70F35804A1FCFCULL,
		0x7BF55BC9F797462CULL,
		0xE98291BBF61B9283ULL,
		0xD69911714B6BBB00ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDC8E8F5A422166FAULL,
		0xE58D96C16D0F4263ULL,
		0xE7845C1EB8249B26ULL,
		0x4EDA710EA09B4FDAULL,
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
		0x4B7A31B016163A9BULL,
		0x51D675030C8B3471ULL,
		0x337224FE146EEFEEULL,
		0x61E7815D40EF2DB3ULL,
		0xD8CCF02EB176CA3BULL,
		0x746151381CA92EF1ULL,
		0x65A1FE22FA3720B8ULL,
		0x8F67B2E6EBF7B31DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF309A2E6445FA17CULL,
		0xA0FD6CDD7A3F9F71ULL,
		0x48DABBABFA800FC4ULL,
		0x3F3B8A3D258DAB1BULL,
		0xC3CEF57E78E40BF9ULL,
		0xABDDC6872CA31F68ULL,
		0xC9C0AFCE19070A34ULL,
		0xF687FBCC20803F36ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7623C4F2377ED49EULL,
		0x745F9E693331E358ULL,
		0x0E0909EB871237B9ULL,
		0x53E1251A4F1CB6D3ULL,
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
		0x357C1616EE80A1C9ULL,
		0x017BE403C303265DULL,
		0x3D13C521A0E790EBULL,
		0x5AD12C156849D775ULL,
		0x947371785C593600ULL,
		0x542B56E7EE80F1E2ULL,
		0xE654B788F0E85B97ULL,
		0x7548D32AD1CACEF3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEA7C4A2058C22CDAULL,
		0xF4F8326DD86B8D09ULL,
		0xAD4EE2C851099CFAULL,
		0x2383EBB356B38F52ULL,
		0xA98B7327DA4D0D7FULL,
		0x286716A65D4C2000ULL,
		0x7A6B9FDD0A64C0BEULL,
		0x39ADBDB3EBFE1297ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x296F8BE9E38C796BULL,
		0x8BA53B51786EC0DCULL,
		0x945E65DD8766F02CULL,
		0x105270082DFA3DDAULL,
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
		0xF4BB6209B4614507ULL,
		0x003F8241E5D48671ULL,
		0x51F2E4C74FC6B5DCULL,
		0xE691DB05B238CFE8ULL,
		0xC37B0F582AF541E0ULL,
		0x409F7F2A39F74FC6ULL,
		0x6BBC3A3D65DAA516ULL,
		0x3B0AF52E227BDC4EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD7A7DD8DA439B9C0ULL,
		0xF4C2398DBC37F9BCULL,
		0x8CABA65DCF421B49ULL,
		0xE91A6F26BAE2F7F0ULL,
		0xA64CE2FFBC81107BULL,
		0x041BE990EE639E90ULL,
		0x1AC9FFB422FE5B25ULL,
		0xF05A38EA9C8DACDFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x71EE199C7566DC43ULL,
		0x07057D756188DABDULL,
		0xC93BEEC96D379461ULL,
		0x13B35DE4D8B0E27DULL,
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
		0xF2997DB8A84541ACULL,
		0x82B6D318FA248310ULL,
		0x181C8EDD1449FC61ULL,
		0x007753FEC3F51C63ULL,
		0x5F70C1ADF2AE3C09ULL,
		0xBEF1DD7B74229C92ULL,
		0x9271E7D06D0F435FULL,
		0xAD69102AC7D7BE81ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAFE7A64DD0BE51A6ULL,
		0xCB7B237D912A7B31ULL,
		0x27E08E99675D9F75ULL,
		0xE37E8DDD910CA632ULL,
		0xBFEFC1F59F74F333ULL,
		0x3DC04C7AB5D40E48ULL,
		0xF1D4A938DB704E79ULL,
		0x70CA989CC4FF1075ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEFD7CCC73207C0FAULL,
		0xE49735B7A8A326CCULL,
		0xC7934AC34A84B722ULL,
		0x1C7E85359F124BEAULL,
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
		0x65D7FD3BAD7A9261ULL,
		0x876B3BC582ABC955ULL,
		0x4BC7BB427CF3F615ULL,
		0xA27E096A8A63349DULL,
		0xAB89ED7131174CD2ULL,
		0x12C4046F61861F26ULL,
		0x31A493519246B254ULL,
		0x0E2FD54E139DB759ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE64651A5B83041DBULL,
		0x4CC2873BE8FE105AULL,
		0x9D04845209375AC9ULL,
		0xEF032A1012A1F6E2ULL,
		0x26819338B43AB053ULL,
		0x1460B6B599D65401ULL,
		0xDA92D079FC641F59ULL,
		0xBF691AC984DFFB30ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3ECF0FF87E09875EULL,
		0xFD663E1D3DC5E08CULL,
		0x9B6622F0B35E6C8DULL,
		0x64FA8F07A7EB2BB7ULL,
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
		0x7F3DBD6F5FB4FB9BULL,
		0xEDB1855406B24C42ULL,
		0xC32411A89AEE7B2BULL,
		0x8AA7E859E87DCA22ULL,
		0x8E863E3ECCC78049ULL,
		0x91690635500F25DCULL,
		0x1D7F6E1B2DD9323FULL,
		0xE5BAC338C3302371ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x64C9E3FDD9A73946ULL,
		0x073B5E3CBE142545ULL,
		0x7CB575BD54A1A891ULL,
		0xAD71CAFB4620841EULL,
		0x8C1487A5FAEADE24ULL,
		0xB885EB4443F2E519ULL,
		0x83454EF6F4B73F6FULL,
		0x9813306B94825863ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7754F420ACCDD575ULL,
		0x182C26DF14CFC3EFULL,
		0x2B0F3B4BC156DD75ULL,
		0x6415E7D390296A09ULL,
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
		0xE3FC8A844F96DB4BULL,
		0x9EB677CC5ED12B0AULL,
		0xE19C26A3A6DDA5C0ULL,
		0x33440A72E5CC4B87ULL,
		0x63BF7EF2D1CC5553ULL,
		0xAD0F893AA5855E84ULL,
		0xBA3F38ECD01B4462ULL,
		0x5B8A95C7E6B74BDCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x929A4A35487FF349ULL,
		0xF1ED2B44943AF0D5ULL,
		0xAADD9E07895841F5ULL,
		0x531721E533239970ULL,
		0x287B65D823D6EF8AULL,
		0xA5676E5777D453DDULL,
		0xB27C1F05B3609E2FULL,
		0xD4D4AB074CA2A5B2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1D7DFA44D9840119ULL,
		0xCFBD4A4092DDCF08ULL,
		0x5DB460EA613A0F5DULL,
		0x5F2DC12491B95C54ULL,
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
		0x1B264E7CC286491EULL,
		0xFA2F6DFE38B2DF55ULL,
		0xDDC5B43C79CE9512ULL,
		0xF7E50339CAA6D37AULL,
		0xC7AB204A81B6C956ULL,
		0xA30591ABE630F0D1ULL,
		0xAF88CE12AA3AA8DAULL,
		0xE42EA26EEFA54D01ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x07BD415DF5A6C96EULL,
		0xBEAA8C6C6505AFB8ULL,
		0x01F126D31BF97D50ULL,
		0x63848D5A3C508362ULL,
		0xCF6A755D82D79C81ULL,
		0xEDBFDE8BAF9DF051ULL,
		0x73A1E177312CCD2DULL,
		0xC246B819B049118CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xED026C4CA200281FULL,
		0x23DD7859ED7F429BULL,
		0xC01BAC7D55E3B365ULL,
		0x1CCD3E86F607237FULL,
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
		0xE9B735D985221971ULL,
		0xC79E1850CDF23FD8ULL,
		0x8681D670CA104F45ULL,
		0x7ED7D72FE232C4F7ULL,
		0x103599F0076E6572ULL,
		0xEAC004229F7D8F3BULL,
		0x097B9A84BDDC8B07ULL,
		0x364FDA940528E6B9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x919AFDA8BE96951FULL,
		0xA675820B85677124ULL,
		0x17D89F15148C6812ULL,
		0x69C36534C8BECB81ULL,
		0x9B21022DBE3741CBULL,
		0x92D33AC9500D2EE7ULL,
		0x51CDDC48911C8624ULL,
		0xB4D56CCF5F37FF85ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB92ABF07A4BACC4AULL,
		0x2E4E798713391B17ULL,
		0xB273744A5A04A0F2ULL,
		0x4D40BD2BBB364B23ULL,
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
		0x9652F7B53F9D342CULL,
		0xD5D1C728E5CAC822ULL,
		0x1FFD6C9D1FEAC083ULL,
		0xAF98B36DC519A057ULL,
		0xE20AC0344FCAD39BULL,
		0x9B62FE31922BAAC5ULL,
		0x00DC224FE5B6AFA0ULL,
		0xA696617A667867F4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEAA86376284153F4ULL,
		0xBEB221FFBD4E01D9ULL,
		0x367F4A5CA2A20A7EULL,
		0x78F1903C5367C111ULL,
		0x4E64AF69024603ECULL,
		0xA48AA8BA5BBF7155ULL,
		0x77D6FB24B022E26CULL,
		0x36AE99E94592367FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9651126C9912B6A5ULL,
		0xBB3C54DB3C8D4CFEULL,
		0x4041F2AA71392BBBULL,
		0x530EC2BC53DD3692ULL,
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
		0x77AE4A0E56BCE5FCULL,
		0xB0C8DAE132CB472AULL,
		0x84DD369B71607B4BULL,
		0x225B7F56621C19ACULL,
		0x1D004CDB85353559ULL,
		0xC7358A9DD25C06CDULL,
		0x41C94B23A5AC45C1ULL,
		0x8C37E5805068183FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x159E99149145F19BULL,
		0x955FB67D3F82BE07ULL,
		0xA041A0DCDE51397AULL,
		0x5E853B10CDF102D6ULL,
		0xC25CB66703DD4816ULL,
		0x4DDFD5BFDB35684BULL,
		0xFA259F906AE5A863ULL,
		0x9002B4221B6DB519ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD6580644F8842C2DULL,
		0x1E21FD56A3041056ULL,
		0x86E70D994C8A9DD7ULL,
		0x33BB98417155CE5EULL,
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
		0x192EEA638527BEADULL,
		0x6124453496475DC9ULL,
		0x88A5AAA8F5797EE7ULL,
		0x5E8ED8488954DEE9ULL,
		0x69513FD68A0EBCB8ULL,
		0x9364E55A75501E30ULL,
		0x1B06E19A1661200EULL,
		0xA06FA78C4CC2F8E8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA33A1344EA5B1AE6ULL,
		0x756AD18548FAAD74ULL,
		0x4E250E8A7BC8AFEBULL,
		0x21EFAD6999E591C0ULL,
		0x48F75DEC7913F41CULL,
		0xAEC9D1F5CE98FB04ULL,
		0xE43B37468ED4D95EULL,
		0x0BAD91B80B714F7EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x434C5FDD20066E33ULL,
		0xDABE54A00C7BE8E1ULL,
		0x5CBBE48498834D17ULL,
		0x516E6860A18E72C7ULL,
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
		0x2C63FA3ED1608D9DULL,
		0x8B3DEC334D9413FBULL,
		0xB0EB443FBD404809ULL,
		0x76B7D8078197C541ULL,
		0x943849F86FA5211FULL,
		0x0F778F3F5534CF86ULL,
		0x5BBE9BAD28003B30ULL,
		0xAD7486666DBDCCD4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7DF27404F484CBA9ULL,
		0x7C0650BE65E4838EULL,
		0xB4C9765B84DACD4DULL,
		0x58C3461245E425EEULL,
		0x16F4B25403B1A1B9ULL,
		0xE89EF46ECFC9D0F2ULL,
		0x6D75601EE82FA0E2ULL,
		0xFCAF157A64B30FE8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x467A08A1E300A950ULL,
		0xD35E9668B5915A77ULL,
		0x5B00A501B15C622FULL,
		0x5B4354FE934BAA58ULL,
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
		0xD0CF34DF412DACF6ULL,
		0x3AB2241EC22D91D6ULL,
		0x2B75287356BCF8BCULL,
		0x0CBB80A0ABB59CFFULL,
		0xC4AFFB22470025EBULL,
		0x661F2918F0309638ULL,
		0xD4F3FFEC09C22C1DULL,
		0xB822433DEA846E4EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3159156A3264CEEEULL,
		0x4754E57527D92C44ULL,
		0xEAA0FE45319E03E3ULL,
		0xF228CB2D1C898848ULL,
		0xEBC140A56402126AULL,
		0xD46314CA89D738D5ULL,
		0x9522599392FA8118ULL,
		0xF4B0791988D03F9DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD2E5CDFEC07FC1B2ULL,
		0x9548424CCB98423EULL,
		0xB9F2DB4FC6C25786ULL,
		0x1D76B6DA0FEB0305ULL,
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
		0x0BC0896EC840DBBEULL,
		0xC327D76E001FC61CULL,
		0x031E06912FCD6BA8ULL,
		0x3C440926B1859225ULL,
		0x7AD4D7B417DB083BULL,
		0x253166B90B7A9D3AULL,
		0x75606064F3D9E227ULL,
		0xBA89E6B742189687ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x05633396CC17001AULL,
		0x78B1E989E25C39CBULL,
		0xBBCAFBE99FC95082ULL,
		0x40478936CAC919E7ULL,
		0x4F2DA37C3FA2B478ULL,
		0x792BE3746E3C910FULL,
		0xB4910ED7F85EC8F8ULL,
		0xDE10790EDB7DCE3CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x812F1622148649C5ULL,
		0xD3476A1374F95AB9ULL,
		0xE6192594E449D813ULL,
		0x3602C6EF21B63355ULL,
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
		0x6D3F95ACBB8F9D4CULL,
		0xA1CD75DBAAC052B5ULL,
		0x752963CB981347BFULL,
		0x12C2444364C1EF92ULL,
		0x61700410081C165DULL,
		0x095B32B1FD9590A7ULL,
		0x27E2BF8E80ECEC9BULL,
		0xA91EF8CED2465750ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCCB27477D42F010BULL,
		0xCA16A991FA468248ULL,
		0xD6E87D1D77220DC3ULL,
		0x5AC9AD1ED8C1DB54ULL,
		0x7C6E952D0E7BBFD5ULL,
		0xC69255AB23EDC38CULL,
		0xEC7183FE2793BE1AULL,
		0x93E8D4DAAA9F75D2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9EC396E5F52D74D0ULL,
		0xC1879B4DFF62426AULL,
		0x710FBE1B642E2105ULL,
		0x5E01ED626EC58CD4ULL,
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
		0x9BD5276191DC8D5EULL,
		0xCD8B04D77BC1F6A4ULL,
		0x247034AD13C23419ULL,
		0x96CE1F8504EF003FULL,
		0x1076AC290BD2E9D9ULL,
		0x60D16EB4AEC431C0ULL,
		0xEFA1A54B025341CAULL,
		0x2409A92F1D7B919EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2C8208CB572BE44FULL,
		0xBC11BEADCBBA3CA3ULL,
		0x25C5A26800EC5C71ULL,
		0x4953188523EDA230ULL,
		0x4FB448DE7A7D94FFULL,
		0xA8E765CFF1DCB390ULL,
		0xFB6DF3AE4A9E42A0ULL,
		0xF79AF0DD6F3F874EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0C2DDBA7CD5B3CBEULL,
		0x5E36981DBA647518ULL,
		0x3E56EF8857B3B7D9ULL,
		0x65EA631FBDEAE5EDULL,
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
		0x9E40EB9BDF4FF805ULL,
		0x6F64AFB1882C59CFULL,
		0x2E240B2791B14F16ULL,
		0x98EBDFADF8998EE5ULL,
		0x5C2B7300B1A9F37BULL,
		0xCABB483F998F4D95ULL,
		0xA7303007D5DC738EULL,
		0x982BBCFFC2F37B59ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x40697DC02BD316AFULL,
		0x37CA2062C5E8CDC9ULL,
		0x73F6DEE8C0B23821ULL,
		0x97C161F19427EFECULL,
		0xA8B001A6E9747511ULL,
		0x75499DE1878AC042ULL,
		0x2BC4F8E25990557AULL,
		0x686F6731F252CBE9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x022A412F6B6DA61CULL,
		0xE679D9456EF0864DULL,
		0x0C175BCF444B8DF9ULL,
		0x171F3A495C4BA9ABULL,
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
		0x7210A6FFB8AFC8E8ULL,
		0x9075232D5BF8F875ULL,
		0x899EF1E4B2561E0AULL,
		0x49539B368EDBBA52ULL,
		0x5CBE64A8F9C53A83ULL,
		0xC429371F9E885EE9ULL,
		0xAF961B8C8158F488ULL,
		0x8CDF7241564ECB81ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF502629C6E5A29AAULL,
		0x26733AFF6A752F33ULL,
		0x86E0AF2A51B2E967ULL,
		0xE1258A3A16F5A7BCULL,
		0xF2FF0D532FD1C167ULL,
		0x2751410E3768BADDULL,
		0x6EA815784796C878ULL,
		0xFC2AB70BE22A4F55ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2F753B1F447996CDULL,
		0xB2106EC3403622F3ULL,
		0xA61329BAF375BF1AULL,
		0x6301DAEBB5508127ULL,
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
		0x628368BC37B8BEECULL,
		0xC663AC1A353E5DC5ULL,
		0x19981F4A7A902291ULL,
		0xDE1FDB34AC61D059ULL,
		0x2379D517C2FDF4F1ULL,
		0x7F1393F010CFFB4AULL,
		0xEAC0955FA8A892B8ULL,
		0xB4539362B456265CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF3BBD17571550C69ULL,
		0xA82CB4B91ED512FCULL,
		0xD2BE85D53F89780BULL,
		0xE1076BC03856C438ULL,
		0x854900A1D88A2B05ULL,
		0x383D0D00E5E1C74AULL,
		0x2E3F8136955C319BULL,
		0x58F06C201DD06C62ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEA0720C79393AD8CULL,
		0xA20EFEE175C502B9ULL,
		0x4202978E185D14DEULL,
		0x0DD04356CBE4A758ULL,
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
		0x19EE7889694D724BULL,
		0x5864EB1675B9ADCEULL,
		0x92CF48D2DC2D2669ULL,
		0x85F6B68E9BEB9271ULL,
		0xF76411EBC694E5C4ULL,
		0xC31CBF965B637F6EULL,
		0x8C35D7323C87333EULL,
		0xF6B866B7F96201F8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9AA0FC4909C8600FULL,
		0x1856F9C27932B417ULL,
		0xC4015E883073C952ULL,
		0x1968099CA7164875ULL,
		0x4C2C3C89D29F9631ULL,
		0x9BD08241B58C2272ULL,
		0x7CA07888F54BF000ULL,
		0xC4F6642760F142D2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE99728CA95EEE32BULL,
		0x155F0BE49A7EC737ULL,
		0x1EF9F76B3E855851ULL,
		0x4F5B0E689591A9A2ULL,
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
		0xA18C59CA42F68CB0ULL,
		0xB6D22C46890DC056ULL,
		0xB1991A82A8B981BDULL,
		0x9B4777355E9DA020ULL,
		0x6877CB306A50C120ULL,
		0x5180517EEB98BF4EULL,
		0x6B0F8913B9185624ULL,
		0x9D31BD1BF56C2A0BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0ED19B37F8FE8550ULL,
		0xF54D741AF07724AFULL,
		0xCB311BA34CD1802EULL,
		0x5F23651FC5E13FCDULL,
		0xD85924174913EC55ULL,
		0x1AE5FB19DF8B7803ULL,
		0xE18D6C8B11104553ULL,
		0xC98CE822C225C941ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF7478C4D38FF9C8BULL,
		0xDC6D8B2B628F30B8ULL,
		0x4FB83B284D1A809CULL,
		0x269BAF13352EBE3DULL,
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
		0xC6FA2E45F76E2653ULL,
		0xD68096039B4BB20FULL,
		0x9D0363E13F00EB11ULL,
		0x260D8355AFD804EEULL,
		0x14CFB45C0B3C40F8ULL,
		0x6F8F42F419009778ULL,
		0x0CC4140D056FA014ULL,
		0x2DF93F40BACB212BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x68CDB6376BF34985ULL,
		0x41FA714E43D0F6E7ULL,
		0xEE54E1CA9DE210CEULL,
		0xE11AD5D5CD428C3CULL,
		0xAB9B3686F7742202ULL,
		0x95FCE573AD77AD1BULL,
		0x7CA14EE5E2F0D765ULL,
		0x2574CC27A5288CFDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFBF725AF7B2F7565ULL,
		0xE04005C54DCD84DFULL,
		0x13D7C5E5BFF0A437ULL,
		0x089BC33918B77775ULL,
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
		0xDAC43AB9658ADF13ULL,
		0xE32A7A322E22EEF0ULL,
		0x86EC61DEF21D06E3ULL,
		0xC0395310FB4BC62FULL,
		0xA218555C3474C62BULL,
		0x3F59D1E957E99B80ULL,
		0xC0E43F2452AD8779ULL,
		0xD68690E9996D3B0CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0466EBAFE3249084ULL,
		0x796FA6430BFCDF54ULL,
		0xDC1A930961A7839BULL,
		0x1F9AFE27B414245FULL,
		0x44681CFB50551805ULL,
		0xC240359B4E4C2CADULL,
		0x7AD8F0470ED78E53ULL,
		0x8F66C4BCE6618C4CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBE85AD6B5F1A29D5ULL,
		0xFB8807848F8482FCULL,
		0x107F83ADA2387ED8ULL,
		0x2F56A38BDAF3925AULL,
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
		0xF54458EB04D1F55BULL,
		0xDD7F75CBC603967EULL,
		0x160C97E241213C43ULL,
		0x251359D0DEC6AA78ULL,
		0x097043ECA97AC3BCULL,
		0x640C137B854D1D1BULL,
		0x219C7A1B36F70F99ULL,
		0xD4E6CD32EF53BF0CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAB413E42BF291A18ULL,
		0x6A95997F9E4ABB32ULL,
		0x39F327913874DE7EULL,
		0xEEEA63423A17FA6DULL,
		0x8ECD2479BFCD73A0ULL,
		0x351D7BA60A2CEE7DULL,
		0x91378173C494FF0DULL,
		0xD69898EFAEF416ECULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7E39C5B6F562BF32ULL,
		0x6A5465FC6E7FC6ACULL,
		0x4B16592C033AD294ULL,
		0x75C4B88A32E1A4BAULL,
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
		0x3162CE45CDF32DC8ULL,
		0x966E848D86148FD6ULL,
		0x32221801426C3BA8ULL,
		0x12E663E9C20B5BE8ULL,
		0x252C6654AE1B571CULL,
		0x4E5686C694A7E2F0ULL,
		0xE30B0FE869C8226FULL,
		0x6150815DFF6E5E70ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0DC6BBF54A144711ULL,
		0x59DC0AF960938C6BULL,
		0xCDBE02BB99F747C3ULL,
		0xAADB7A64C626DC32ULL,
		0x210E48F0152DC8DEULL,
		0x154D6EF28F89A9A4ULL,
		0xAD28CC7CDEA760FDULL,
		0xF8CB97CD50B2A16DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC0146F3F3722006EULL,
		0xB3EC030CE7FD84B3ULL,
		0x63FA173C4F51AAD9ULL,
		0x6BC594FEEBC28E2FULL,
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
		0x87EB6808508CFC31ULL,
		0xB1FB3324B481437EULL,
		0x21A42B767EF999FAULL,
		0x0B9E30AD42605F8AULL,
		0x9099F07300D90A30ULL,
		0x23975D59D2EAEF47ULL,
		0xD1D56188903B848AULL,
		0xDC8B2BE6C31FFF6AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA93CE0B3DD7364E0ULL,
		0x4F97EB60CA568D50ULL,
		0x5C52267465684427ULL,
		0x86B44E192F73EF47ULL,
		0x3169D7993D448BB2ULL,
		0x013A4943EF703921ULL,
		0x688CB22C4A16E8C7ULL,
		0xCAF1A8FA24993EDBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFFD237A77B245E51ULL,
		0x7C344303AE61BFDFULL,
		0x661C0CB4830074CAULL,
		0x21B351B39AED058CULL,
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
		0xFD56937F1412D62DULL,
		0xE44D50154FE39CCEULL,
		0x72FEF7A4A8E81B16ULL,
		0xC7E1F3801FE2FCEAULL,
		0xA8621EC85D148CEEULL,
		0x277BE48CE837F345ULL,
		0x97AF625BDC747569ULL,
		0xB480216359322810ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA6BFEC1408511CF1ULL,
		0xF565E4CD950FF208ULL,
		0x9ACDCE15477B919EULL,
		0x51EB3E698A6CC8C8ULL,
		0x12245D024D8B3A1DULL,
		0xA5CA1095DBE1D7BEULL,
		0x554C357B78D81C10ULL,
		0xF1D680FAE11616B3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA3C16AD15A2402ECULL,
		0x2F4CE1F38F9BC0E6ULL,
		0xB2E9D2DE2AA1CC9BULL,
		0x5B24849869A0C7F9ULL,
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
		0x28CFC5A318A67CEEULL,
		0xF6BEFB7A070C31DBULL,
		0x8691D6E625222D50ULL,
		0x59EECE0221A8E73AULL,
		0xA4A83ADF2E28B65CULL,
		0xD9315140722E2A58ULL,
		0x6F26AF0CBD68E3E3ULL,
		0xAD234B4673868582ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDBA2D8592486DBA1ULL,
		0x18AFA2B8C873912CULL,
		0x0E5862A5A5755CEFULL,
		0x6694D2CBC85CE292ULL,
		0xC607C9D373F36448ULL,
		0xA1498C650E000563ULL,
		0xAAED42EF70ACD65FULL,
		0x428C510F3CCE1675ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x58FDB5079809D292ULL,
		0x2A7691521D721D07ULL,
		0x98BF8099E396D202ULL,
		0x45C31F6878AC808DULL,
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
		0x29EF113FFEFE32B9ULL,
		0xCE5DD9BD590BFFEAULL,
		0x08780C27DCAA0EB9ULL,
		0x86BEB9807FD27B57ULL,
		0x927C019306B0F23CULL,
		0x7209F5CE7B4B6581ULL,
		0xAE82189C46271287ULL,
		0x07C2391FBD382CF8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2997117918A263A6ULL,
		0xF90F3A731D5E8989ULL,
		0x281951090C924DF6ULL,
		0x9A759E21A47783CDULL,
		0x88B745A53C356116ULL,
		0x68C81B38DC39867CULL,
		0x2EC777EC1AE61678ULL,
		0x501261B8137626D7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x738BE512F4B35915ULL,
		0x3515117FD8549120ULL,
		0xD61295453BBD2AFEULL,
		0x306314C20E27E082ULL,
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
		0x0A28A60E3E902C90ULL,
		0x3E4EA25C67AC88CDULL,
		0x25A21C45F868123DULL,
		0x6BC99CA62ED1061DULL,
		0x10BA7210A8D61528ULL,
		0xC15A168DF85E8E6DULL,
		0xBF0F08D88BA13EB7ULL,
		0xACAD0E0BF7B0A342ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD7D8808D2F5EAF97ULL,
		0x503B84969D1BD1F0ULL,
		0xEAC6610DAEA1D057ULL,
		0xE55EC1784165423DULL,
		0xCA22B62944C2477EULL,
		0xB118D71D1DE70BF0ULL,
		0x603CF3940198DFA3ULL,
		0xD3E1E06F36B88AAEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xACD609D9EA22033EULL,
		0x57C28886384E154EULL,
		0x4E0AE364C7045EE0ULL,
		0x3493A072923F69E5ULL,
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
		0xF2F6864C17B79659ULL,
		0xC209F821290C9E89ULL,
		0x9E62C2B3F004B7FAULL,
		0x15891D0C4EFB126AULL,
		0x3CC8DE2A4CC972FBULL,
		0x3B4A8285C9837B5EULL,
		0x090025108F782003ULL,
		0xFD4C30D570317E54ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE1734C02E5C32F56ULL,
		0x4285629F1A7724E8ULL,
		0x65303E7E42204411ULL,
		0x59D966EE0D91DFA2ULL,
		0xE548655634802F36ULL,
		0xC1C938B9DD1C4407ULL,
		0xDCAE7CC0F767F97BULL,
		0x8A4962B7244690E4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0E9529C4CCD478B4ULL,
		0x88B589C725E7B072ULL,
		0xCD518006404A2C05ULL,
		0x4E1A4E9D86487148ULL,
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
		0x5241797A0F58CF54ULL,
		0x73EF9DFBF3FB2EE1ULL,
		0x17146154BF9BED46ULL,
		0xDB166D558048F4DCULL,
		0xB54822F1A3C7EA85ULL,
		0xFF11432339033E74ULL,
		0xC6D099468B4355E7ULL,
		0xEECE05F9B09F181CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x44DA003AC3D5BEA9ULL,
		0x5924519425FFA9AFULL,
		0x3C2544CF560515D2ULL,
		0x4DB0954ED2C75D31ULL,
		0x898E428B7843EA80ULL,
		0x3DC839D80339CD93ULL,
		0x36BAB45F2E664F0BULL,
		0x8EF82811B0DB1C4DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8AFEC869C11B1390ULL,
		0xCBA2AD91C9E2469EULL,
		0x3E2F16DD3265DC38ULL,
		0x4724C876A498F87AULL,
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
		0x692A5152458B37CAULL,
		0xBEF8A16EC261CB37ULL,
		0xA8300E2E3DAA3DAEULL,
		0x58A5181122BE25E6ULL,
		0x3CAE3020AFD455C9ULL,
		0x657D280A8353F6F7ULL,
		0x32A091C1246122A9ULL,
		0xF4C755ABB755A27AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2D63D6710CFDA3C4ULL,
		0x0AD9D5E7D6C99365ULL,
		0x6A20BE26A176F40AULL,
		0x04268BD200E8D664ULL,
		0xFBCA39D23F8DEF0AULL,
		0x5FBE68240F8453A6ULL,
		0x36D3B94025C6A12CULL,
		0xBA57FDD10D598B11ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDD9D0A85E300D5B6ULL,
		0x8E6F47BC1C6A75BBULL,
		0x9E77732D67228233ULL,
		0x010596B45D40C917ULL,
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
		0x972D92D169C41A99ULL,
		0xC575D0859EB80F7AULL,
		0xA10792D4475FB3B0ULL,
		0xCEA73B4D4A020B9CULL,
		0xFAEEA0E948252C89ULL,
		0x09752E08BD148B6BULL,
		0x53D3390DC24EC97AULL,
		0x3F7ADDBD4C19F991ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB9CED82403654D91ULL,
		0xA9A4C891A9DB35A8ULL,
		0x3F2F0B51EB869513ULL,
		0x8D39BDA31A6F36FFULL,
		0x44FC5C0DB076DB9DULL,
		0x2360BABEED3845A7ULL,
		0x39E55BD6ADA7E110ULL,
		0x1F4F9FF575DD4D94ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDF54F345EA3ED0CEULL,
		0x42DA24E8CF8F3504ULL,
		0x3B275DAF6C9F9E55ULL,
		0x07D8A953FC945C2FULL,
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
		0x19B362B6F6469F9DULL,
		0xDE70B0D78AED43F7ULL,
		0x485F8DBD16C8E7B1ULL,
		0x487A0DAA0B56A59FULL,
		0xE4A69B4BAA49954BULL,
		0xF4ABF3CA99F1388BULL,
		0x1FEEE3D26D553918ULL,
		0x762B38AEE462FB4DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x09517A1D01F95171ULL,
		0xD658326B3343BA44ULL,
		0x431AA73D66B4A584ULL,
		0xF0A08005CB0F86CBULL,
		0xBFBF1B5B1ACC3E9AULL,
		0x639040368CD4731BULL,
		0x482DEF881E0AED08ULL,
		0xB3A05F1E80E3A810ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8ABEE64F40E82AF6ULL,
		0x9235266649EED858ULL,
		0x0BE92987751B8CA2ULL,
		0x3875D913052D79DCULL,
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
		0x17882AC2034C31B2ULL,
		0x77DA2E556D8CDA5BULL,
		0xCBB71EE0BAAC516AULL,
		0x3DB6EBCE655A6254ULL,
		0x6B7F604F99E46919ULL,
		0x08A12D3294B5B230ULL,
		0x66C979A8BF7A4461ULL,
		0xABD86EDABF22CCD9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x590559155B5FB667ULL,
		0xDEBB6E549ACF8921ULL,
		0x35524B2BD26BD318ULL,
		0xE760FCC28EA59E92ULL,
		0xCE5F513C5DD4FEFFULL,
		0x727098F20A01D67DULL,
		0x06FB4C7E9BD2C810ULL,
		0x694E653687CD258AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x11450E8792363C7DULL,
		0xE454C195696FEDBDULL,
		0xCEFF87F6331CF247ULL,
		0x36D35D6C0D6B998AULL,
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
		0xE8D46AA6400A7B7BULL,
		0x1A5200E61CDED50AULL,
		0xD9B38E31F47EDDD1ULL,
		0xA1C972F335AE22E4ULL,
		0xFB03FEF009806208ULL,
		0x334357C2ADB6B4E9ULL,
		0xE6DA8F32C83C19F8ULL,
		0xD42ECAF59AB7F663ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x841EC82C047147FAULL,
		0x04076C87AB0C1532ULL,
		0x8B72B4D172C780CBULL,
		0x1F3742CB8F782F77ULL,
		0xBE6B319BAD6008E7ULL,
		0x5B231F693DC0845CULL,
		0xF03E5B0F67E66865ULL,
		0x51A70AFB2435D224ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x63641CFFE866714CULL,
		0x2B12F1A5105DF4CFULL,
		0xE97096A0CE6FB8D2ULL,
		0x62B8AF553D8754C5ULL,
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
		0xABF35EABB21A9DF3ULL,
		0x418C9D92B00819E4ULL,
		0xFB4E5B590C470F60ULL,
		0x30B2665E4B70EACFULL,
		0xE93E01D805AC05B6ULL,
		0x340A900C66D8447CULL,
		0x9F6300C952EAF64BULL,
		0x3CCC15EF86EDC9ACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x50D1ABE0E5D4A32BULL,
		0x17942099C7304542ULL,
		0x95F25FA0F123D8C9ULL,
		0x17B877991DC35A9EULL,
		0x9AC7ACC248968BB3ULL,
		0x3F82553F99684891ULL,
		0xC032E3E136635FABULL,
		0xA75FBD224C0FD973ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x00B25404DD7614DAULL,
		0x7631375F67773990ULL,
		0x8680462C57439255ULL,
		0x470F1D3BEA9F38A2ULL,
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
		0x5534765CB7320163ULL,
		0x73AC33DD4E01307CULL,
		0x12EC8FBB1BFA6F29ULL,
		0x740DB8F0E0DC50B7ULL,
		0x39CE2924CD4B4EB3ULL,
		0xE158C144DFC6596FULL,
		0xDCB477124B460127ULL,
		0xF6FBFA851F7E4336ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6EC40A9324567757ULL,
		0xC68B6FCF1308F086ULL,
		0x5B5DB9CB73A856DFULL,
		0x92F0A3D68A8CA70EULL,
		0xFC0E5A915FD146ABULL,
		0xEFDF74A84000A5CAULL,
		0xA8AD45EF6F6E79A5ULL,
		0xA987628DB4925242ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x10E915ABD2F8BCDEULL,
		0x8522234DF250EA57ULL,
		0x70A0211C4A503593ULL,
		0x606BA3D435556DE8ULL,
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
		0x0AB4533B0C671A91ULL,
		0x0AD44273720C3D07ULL,
		0x42D1628AE300A41CULL,
		0x73AF0FAD27A82410ULL,
		0xD86E789A745C4E74ULL,
		0xB88FE23667D79D9EULL,
		0xD1DFA3EA5649A400ULL,
		0xE83EABB1DD4DBD42ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9061AAB40C5EEEEAULL,
		0x9B70C26787523537ULL,
		0x40CE2CE7DD019D52ULL,
		0x19C60FB5BADB2815ULL,
		0xBAAB07693EB22AD4ULL,
		0xCACC23A21FB3EA38ULL,
		0x74A9C78C4B4E7D52ULL,
		0x94DD7C54D851B134ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE55575D4F7497742ULL,
		0xBA71CA0EA006A8F7ULL,
		0xD801EB98A746C49AULL,
		0x3A5607C62A36C61CULL,
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
		0x4D03EE97F6F145C9ULL,
		0x845779B95564C7B0ULL,
		0xFD679D97D4EE6F56ULL,
		0x7E7066B36A1957F5ULL,
		0x36E23E5DD9332599ULL,
		0x4877BC9F01484B2FULL,
		0x3B04260BFE97E6CAULL,
		0x62D459D131997D53ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB4AECDDBD84048D4ULL,
		0x1AF12DDCEE7AF0ECULL,
		0x82316CDEB5F7713AULL,
		0x47CA6792A2F53AAEULL,
		0x71CB288A03B1A501ULL,
		0xC03866E90C3154AAULL,
		0x10FBB95B8A0CFC66ULL,
		0xB3D23371924ED423ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD9C25E2DCFEA11BDULL,
		0xA2CD04DEC8526E78ULL,
		0xB87652EA6B95C8E2ULL,
		0x30F7B1526C393A6DULL,
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
		0x5E5910BC57A89747ULL,
		0x5242C0C76FB92A19ULL,
		0x58E771C39969CF26ULL,
		0xC01D882B79B47E66ULL,
		0x3A9BAE066C87C7F2ULL,
		0xED27A73C3A2AA571ULL,
		0xB1202DA431C757B5ULL,
		0xFFA39794F4F218A8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x06CFED5A638EFACEULL,
		0x806B206EF285D1B0ULL,
		0xDE716036072660F2ULL,
		0xD8F9A20C4B11E136ULL,
		0xFE9D50127470E08AULL,
		0x36595D9F91F48FC6ULL,
		0x40AA6E26564596A2ULL,
		0x2AAB8546E87B6068ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3F4B1598C77FFA96ULL,
		0xF4768D99753A8FAEULL,
		0x2BF07E3C27861720ULL,
		0x03F69DB50841F6C0ULL,
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
		0xF24F92AEE8464A00ULL,
		0x8941A24814B9AED4ULL,
		0xE2577CC948E39B96ULL,
		0x4488ECEBE312F28EULL,
		0xFF3316D100A97297ULL,
		0x4ECB36E829CE8C95ULL,
		0x07983911010D11EBULL,
		0xBC73875468BB3FC6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x13619CFFE0070646ULL,
		0xB3953A9090CAE454ULL,
		0x5A26A7BF27ACE286ULL,
		0x89831CDA72001D79ULL,
		0x1D09345D45CE1BD4ULL,
		0x2BB1BE3D64F71052ULL,
		0xB2340E1C4E845534ULL,
		0x0CA5D6ED2D7E06BDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x712592DCC4CE2875ULL,
		0x0B745110BBEB3C94ULL,
		0x350F355CA182BC3FULL,
		0x538DFF643C294C52ULL,
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
		0xB5E59A19132FE7C2ULL,
		0x51502FDC58C70970ULL,
		0x3BCACBF29286B984ULL,
		0x5B41B9BECF16F082ULL,
		0xF6F759C9F4A57611ULL,
		0x0667DBAC3C7FF6AEULL,
		0x34452D341B7D59F0ULL,
		0x93ED781F7A35637BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9BC395D7FDCECDB9ULL,
		0x258EE3959C6B18A6ULL,
		0x444C169E4EAFF084ULL,
		0xAB2C2C7C507FCB78ULL,
		0xABB791E8E0ABFC68ULL,
		0xB904E1F985E05A17ULL,
		0x80180676642ED41FULL,
		0x5D5EFC48E72EC9E7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4599AFAA0C692A3CULL,
		0xA8725CCDD80D2F3FULL,
		0xB632757D797EA5EBULL,
		0x493BEF1C5191F0F6ULL,
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
		0x611AEDC142D1DFBFULL,
		0xC6045DABC6A5D5B5ULL,
		0xC052EAA6040ECDF7ULL,
		0xD8514CA60A0D139BULL,
		0xFD48C6AB2835431EULL,
		0x136AFEAD062E9669ULL,
		0x96A687CA85DF24FBULL,
		0x9C4560202AA81E9BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x306593E81DE72D58ULL,
		0xBE1EB2B25AFFD74EULL,
		0x855636D254C90BE0ULL,
		0x620C78815293387DULL,
		0xCC295E5A790C6EBCULL,
		0xE48584BC9E414770ULL,
		0x23E31DEC328FA427ULL,
		0x6F7F8D32C874D7A0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7B5ED5D324FA39FDULL,
		0xFDF5C4A8D8DFB764ULL,
		0x43FE6AD40D12E16FULL,
		0x1BA223614B166471ULL,
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
		0x4BAFD6395BAB9D79ULL,
		0x5716BFDDB4989198ULL,
		0x3CF30F04350AFBAAULL,
		0x348FEB0C9CD952DAULL,
		0x60DEB9C0330A3AE3ULL,
		0x4025D500421BF0B3ULL,
		0xF8A7960982FB722EULL,
		0x0A78C5F5DB4B1363ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0D68CDA8F9FD20D5ULL,
		0x35B4F7F06E862999ULL,
		0x310FC10E80C2F516ULL,
		0x96F7BFD492D052ACULL,
		0xBDBACB2E4FD09280ULL,
		0x4269A8B620B32D6FULL,
		0x56897F0FAEEA54B9ULL,
		0x6665EDD578C5678FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x759C72381C3D792FULL,
		0xCB505AEE3B9F6409ULL,
		0x1C5AB70B2ED265F1ULL,
		0x78644006A9E081BEULL,
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
		0x78622F521D26C690ULL,
		0x8FE53F18D9AD2204ULL,
		0x4DCBA656E50E604FULL,
		0xA31A5D650568251CULL,
		0x94B67CBD1626CEFBULL,
		0x22E6860046A147DDULL,
		0x83A38E78145F86CBULL,
		0xA27E60E74FA7807BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x14C7932C0BA9C3F6ULL,
		0x1543FEA19EFCC02BULL,
		0x9C27C50BE5591CDBULL,
		0x7D429E29C4B650A3ULL,
		0x54281C00AEBF43C1ULL,
		0xF21873E2484FE951ULL,
		0x4E8ACA079AB9444FULL,
		0x6012EB8C818C80F5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF8BCF81D6ADBAEB2ULL,
		0xB937F0EAFAC46AAAULL,
		0x935109FD0E6321BDULL,
		0x01CB2AB5D8B3C264ULL,
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
		0xFE53F0652A717E6BULL,
		0x1F2FA9E7C146BFBBULL,
		0x1ECC6911A06B8994ULL,
		0xCC2F2D7576F9AC6CULL,
		0x33795A1C7405822FULL,
		0x81C59ED774A19BDCULL,
		0x63E40EA767838B2FULL,
		0xB32BB2A6B78F1FFEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB196C1841770F1B4ULL,
		0xF764CE5DC8808ED1ULL,
		0xF5F419D7DC1B29E3ULL,
		0xA034BCCB9A556822ULL,
		0x02090EB18B99E87BULL,
		0xC06355F2F2623A17ULL,
		0x5A4FF827C9075227ULL,
		0x952B7DA1433A439EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA36860BF92F95E1AULL,
		0xDC61AD754E2EB42FULL,
		0x94D3A62B4AC0D6D6ULL,
		0x20024F79213CFA8AULL,
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
		0xAFA97CFC9F288768ULL,
		0x5A0787C5C8D1A3A9ULL,
		0x058304B6BE1EE4EAULL,
		0x18357CBCEAF8CAFEULL,
		0x33C4E8C3CA8353D7ULL,
		0x90CB358839AE230BULL,
		0x95CE4A44D2E0CA3FULL,
		0x028207FED01C2AE5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA44D0D94D4B292CBULL,
		0xBC7627AAC34F9F88ULL,
		0xC3CF13764B1048B2ULL,
		0x5445DBADD73536DAULL,
		0x594D74554FF972CBULL,
		0xB9F76804072F471DULL,
		0x7A77D3F1F3597167ULL,
		0x2CD51F6FCD07B9D8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7917B7CDFAED5B5BULL,
		0x8101E1BA8456A96FULL,
		0x5089818DA125CC41ULL,
		0x7B9A264988CC5C15ULL,
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
		0xD4AC6CCF5E3A4FFFULL,
		0x67DE1C902FB5BD04ULL,
		0x078DCF628E1C182DULL,
		0x1BCC60B34A921222ULL,
		0xA84B665C15CE0B3FULL,
		0x97E1BCAE2E6AFF3EULL,
		0x50B2914A58E4DB60ULL,
		0x07DC61CC0DF11CE4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5AFA9CFA786D67D4ULL,
		0x1BD4F4C6E2BAA93EULL,
		0x5B0A234EB3B8AE9CULL,
		0xCC67ED99C98564EAULL,
		0xD8890B8DDDE97F89ULL,
		0xD1C8BF32334694C9ULL,
		0x0FF3AFBFBB855A56ULL,
		0x563304C3C9F335A7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x508B4A7131B9A354ULL,
		0xB3BEC8309462E11DULL,
		0x48D926A736909104ULL,
		0x2E88425398BD004FULL,
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
		0xB1D08DECB9CF7604ULL,
		0x7703D0C577B27CB7ULL,
		0x1144C4F32B31E2B5ULL,
		0x028B890C6298BF62ULL,
		0x90808EC70C75E91FULL,
		0x5CDE96DE71C727BAULL,
		0x44D3F93F8FCDEFFBULL,
		0xB104E0E6434A43B5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD415E43CD5980E7FULL,
		0x1814E8D6232501E4ULL,
		0xC106541ADB75B3F2ULL,
		0x6C6ED14728A3A916ULL,
		0x467B5BE3FF82777CULL,
		0x8BC730E8AF485F9FULL,
		0x6FE40302F71E3B72ULL,
		0xDEE328825FA9D7F7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDA803763D05A449AULL,
		0x68680A6A335F2EDFULL,
		0xEBDCFDD6F9D0FB12ULL,
		0x471E169903C51478ULL,
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
		0x30451855296BB0E5ULL,
		0x1C10A9AF1BF99B4FULL,
		0x29FBEFEBD76B143EULL,
		0x60A30A9422B42F16ULL,
		0xB3B6AE1BBAA22927ULL,
		0xA8EA65E00DC54A16ULL,
		0x8B9F11F86D0C374BULL,
		0x403D7B9E7075AA7DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x33CBACD4E83A2CA8ULL,
		0xED1CEC4D74B8FC3EULL,
		0xA83A8D1BAE3DAEEFULL,
		0xCC3C1FC3EDD5F815ULL,
		0x93D2CBFCB2DB4474ULL,
		0x421AB9E1E3AFB503ULL,
		0x66A0F75FF94B65F6ULL,
		0xCC2A827ABB9FD6FEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB84CFC1B68B7739EULL,
		0x71C7451BE674BFE7ULL,
		0xFF79557157CC77FBULL,
		0x4F37E61D0C9B9BDFULL,
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
		0x99C2D02FEF677D50ULL,
		0x3D600A6900370908ULL,
		0x050616191B796C92ULL,
		0xEED42569305422E9ULL,
		0x7ECDA6F54B018C21ULL,
		0x8CC1A13640354C4EULL,
		0x2153C8CB7D2A59C7ULL,
		0xF82954EE0828AAE8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC5283591DD550078ULL,
		0x4FABE5B35EC65436ULL,
		0x1597AB9AFFFBFC4FULL,
		0x7EEA75DCCC5474FAULL,
		0xC2331D039296B241ULL,
		0x1D65A2997EC5F3FBULL,
		0x71771CDC74F533C1ULL,
		0x8242A9371334ED10ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD38B147F71EED6B1ULL,
		0x755BEFFA57F7D119ULL,
		0x0A2FEFF953611537ULL,
		0x70272CB4C02DDBF3ULL,
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
		0x3C405988CD8B1724ULL,
		0xD833DCAC8C244F70ULL,
		0xBD846F754D9E51A9ULL,
		0x86BD636369ED05E5ULL,
		0x4F51C5EF8DEBFC47ULL,
		0x9D53355A1854E64CULL,
		0x99A015E542A27F66ULL,
		0x494214C3FBA275C2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x965F82EA3609F0B6ULL,
		0x8EADB376F03E4712ULL,
		0x952814B2E9ADDE6AULL,
		0xD2739ABD2A5E46F5ULL,
		0xC729C2FF699CB1D4ULL,
		0x480CDA0B4E9D4DAEULL,
		0x70DBB31ED7776683ULL,
		0x3B04A567A18CBC95ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDBD14643FB4633B9ULL,
		0xF1F7B6E78D26AFBFULL,
		0x358304364C5624FDULL,
		0x5168505B9EC83BA4ULL,
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
		0xD4B86BF2B2B7AC25ULL,
		0x501916A55A8C6EDCULL,
		0x68614FF66E1AD34AULL,
		0xCC8073B32B44D3ABULL,
		0x4E5D569BA631253DULL,
		0x35C2C79B70891AB5ULL,
		0xE272727C05AA3CE0ULL,
		0xD535C77204E72EADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB375325CFFB5A36AULL,
		0x90836AA118B91C1AULL,
		0x13F7C50DD9DE6CD0ULL,
		0x7AF37FE9A26FA18EULL,
		0x0EAD369B207A60B5ULL,
		0x2ED3B936B0BDBEADULL,
		0x6DC0DD7E46A67E5EULL,
		0xEB34A6F3AA01B135ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9567F9A98C233479ULL,
		0xC711CEF8BA02FBFBULL,
		0xA6C5A892EECAADC6ULL,
		0x0DB7C68B06E5D1FEULL,
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
		0x58142355B645E4C6ULL,
		0x08DD31D4D298BC30ULL,
		0xA0FD0BFF38C547D8ULL,
		0x53211EA9B4544F15ULL,
		0x20ED0F45C4CB5838ULL,
		0x6E76E1D144F3E573ULL,
		0x60548B097184FBFAULL,
		0x446BA661B878AC1FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9AD67C094A4F8464ULL,
		0xF84CD81329F0C7D2ULL,
		0xD8EC1A2E882BEFE3ULL,
		0x5CC06572FDA09ADFULL,
		0x77753008EEF2F421ULL,
		0x2717F582683A3DBBULL,
		0x3E2245F026B111E8ULL,
		0xAB08FD80362F498DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE508CA542A15397FULL,
		0xA8A76D766C36D9A0ULL,
		0xDB873391CC0E16AAULL,
		0x3B05CAB00D9855E6ULL,
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
		0x163019E4819AF15FULL,
		0xFCB7B5E1863DE296ULL,
		0x6823A2F5C6AC0209ULL,
		0xCB5680291994E001ULL,
		0xE659358637BDB967ULL,
		0xDE906426FF684043ULL,
		0x0D5A7226EBCC053DULL,
		0x1FCB3A18EFC4096EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x99138FE645861BECULL,
		0x984730EF6383B72AULL,
		0xF0FB202ED9BDEE6EULL,
		0xA94BBF0E2CCC05F0ULL,
		0x7814C3A2AFE59337ULL,
		0x1C97F7A7881626CBULL,
		0xC6C8AD2829ACC00CULL,
		0x1008281AFE0659E6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDB4571C4662A80DFULL,
		0x2F509FDDD8E9F34BULL,
		0xF0CBC097BD9258FEULL,
		0x78FF6CCCCEF0E824ULL,
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
		0xDF95FEB0BC1BFCE6ULL,
		0xC9C69806BDFC718EULL,
		0x3F2F6CAE511968F9ULL,
		0x7BA5DFDB920D3834ULL,
		0xF85EBE76BE46C383ULL,
		0x55887AB92F226F80ULL,
		0x73E90B40D900AC11ULL,
		0x30200ADEBC63AC82ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEBE8502AABD2427EULL,
		0x299A5054980A65F7ULL,
		0xB7F6E5D92F41DF69ULL,
		0xCE625007955E45BDULL,
		0xE6305D346C3C193FULL,
		0x75D4219233B4FEB8ULL,
		0xC2D0AB8402F39257ULL,
		0xE7EF10EF575E8893ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA6901E5E3DDEFC58ULL,
		0xD4F1837B7830C949ULL,
		0xD0D6BCDCE7C95B27ULL,
		0x6488A95CFB7247E4ULL,
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
		0xC6149ABA13518977ULL,
		0x47B8A30BA72DA087ULL,
		0xAABEBC88A0CCAEF9ULL,
		0x95CED9F8D49F55F0ULL,
		0x4F7BCB49848F47B6ULL,
		0xF55FC32EC01C259DULL,
		0x5CC0ED2DC5CB7566ULL,
		0x32121901F782EF4CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCCDD21DC553FBE52ULL,
		0x01AD6DA31C367D7FULL,
		0x11128F29E369F92AULL,
		0xFB53EAC57D0A106BULL,
		0x40CE29A6D6BFB5BAULL,
		0x77ABC96144D4FEB3ULL,
		0x63A8A103E3278C06ULL,
		0x0CF37326B84F7762ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x26FD77038AE1774BULL,
		0xEEC249E8D786E9C6ULL,
		0x93477B9661B75A21ULL,
		0x1D078DBEB9391240ULL,
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
		0xCE490C73D614E06DULL,
		0x741E5F4E66510330ULL,
		0x272D5E16C58D391FULL,
		0xE1AC1C9BE3AF9D71ULL,
		0x180AAB14D52E337BULL,
		0x941CCC667CAE6D3FULL,
		0x24AA0BB0C3DA4D63ULL,
		0xFBC22C4E527297A2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC01D3C985C92A9D9ULL,
		0x0636F79F51362EB6ULL,
		0x10849DDFBB42CAECULL,
		0xEFCF24E8E24F4ED4ULL,
		0xDC60FD4050D02F30ULL,
		0x1436069EAC9C63C9ULL,
		0x2493E5FD4AC31BDAULL,
		0xF569C88DBD892659ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE95B9D671F76D9C9ULL,
		0x6A28C357F7C83BE0ULL,
		0x19F258DB03BBC89CULL,
		0x62FBC6491C071F73ULL,
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
		0x0FF7D31956338C3CULL,
		0xE72C57273C384B19ULL,
		0x4802D3B0DC91065CULL,
		0xFB4FF7ABC3D92C2FULL,
		0xB50325C480DDC65FULL,
		0xB869525CE8D04A4BULL,
		0x48F7A63C0E00A700ULL,
		0x3C7728C5A3117448ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBC1BA11779533385ULL,
		0xDC8263AA2C8E525BULL,
		0x6A3BA41FCAC85AB2ULL,
		0x2DA7C088DF1FA745ULL,
		0xFF12AFD22A6A167BULL,
		0xB54B8F4A2E5F56CCULL,
		0x9E590E55DE1F680DULL,
		0xC086EE600DE5D706ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x558DB3FAB20C71BDULL,
		0x8114E844BC6E1D8CULL,
		0x3151BBBC2D3803BCULL,
		0x3350E2370932DCA9ULL,
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
		0xE2E03E86A6266895ULL,
		0x737F15439B23C51DULL,
		0x27DF21B88AE8BF33ULL,
		0x97F22332129E15D4ULL,
		0x0AF8C2D9038F7ADEULL,
		0x3C6FAEF356ACDD7CULL,
		0x4963A4740C0CAD40ULL,
		0xB8050FC3180C721EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3CED89D27E757A6AULL,
		0x0380E479782EFD71ULL,
		0xCF55890D72546073ULL,
		0x10BFEA96EC4A8E7EULL,
		0x7F51EC3286F11182ULL,
		0xA85B772052CD6682ULL,
		0x0FCFAECCE699D864ULL,
		0xF47EFC0BE4484FB4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x60B6916AA7349090ULL,
		0x6AFE7A1CB62070B7ULL,
		0xE4800F7AA79FF758ULL,
		0x0D1925CCD570A319ULL,
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
		0x1002334F8F94D571ULL,
		0xD0B8F18F837CDFD2ULL,
		0x56BCC1859EE207F3ULL,
		0x5AC953C856EA9584ULL,
		0x03634AE6BBB3242AULL,
		0x60BC572F52FDD0F6ULL,
		0x80297F7DA2DB3AC0ULL,
		0xFC2C9C1DFDB28B8BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1416ADAD7119D9A3ULL,
		0x63B7A9C8FC6620EFULL,
		0x4D051BC59F1C8AB2ULL,
		0x3DF0FE40678F71D4ULL,
		0x1F0112EF1C955143ULL,
		0xFA98E22567C37EA1ULL,
		0xB34FC81DB24EB814ULL,
		0x889E73860E55BDE9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE27FD463BCE84C9EULL,
		0x9644A73F71BEF77CULL,
		0x7208DDFDB4A0E2B2ULL,
		0x43F25C157721A9B4ULL,
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
		0x2E3A681FCF3AC9E5ULL,
		0xA4B3B50BFB08A17BULL,
		0xBE76AFBEE8A0B18FULL,
		0xA801EB037E449BC6ULL,
		0x41B86734D34B30EDULL,
		0x0F8241AB76DAA496ULL,
		0x52461A1E60591B3EULL,
		0x545178D627479F55ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x56ABD03B91066E32ULL,
		0x8D0E72B49D04F177ULL,
		0xC4815266D463082AULL,
		0xFFE127B05596470BULL,
		0x6E9CF35CBE49133EULL,
		0x4BB349E4DB86360FULL,
		0x23C9FF2DCA285395ULL,
		0x435AB2A8F3B903B4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2DA1C9F75C84C3F9ULL,
		0x285E09D26C8C1807ULL,
		0xE0615D0E5F7B4C72ULL,
		0x2CC22E08CFD96EA7ULL,
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
		0x527A1B0830FC031DULL,
		0xE79684A52FB8042CULL,
		0xFC8436B58440770FULL,
		0xE9E2637863988210ULL,
		0x4B05860616B25128ULL,
		0x3D9A1636CA77BD68ULL,
		0xC992BCFB23B5924FULL,
		0x3F8CC1F2D6295D2EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFE78CFDB65650D43ULL,
		0x0848FCA5EA9AB835ULL,
		0xE547B9529A8A1527ULL,
		0x42C3221055AB40C6ULL,
		0x90614CE11ACB16E4ULL,
		0x7BED9183A0C71C23ULL,
		0x4A22EB0CEE565674ULL,
		0x43E0F08F598031F2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0861C6AA2FE99BF2ULL,
		0x9EE93A9775553C2AULL,
		0x01D5A6BED5D94461ULL,
		0x02A0562C8F09AC45ULL,
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
		0x6E9193FCA5B53CEDULL,
		0x095679AC8EB5A7FEULL,
		0x59CE757A61382497ULL,
		0x45965F5CEFE6A921ULL,
		0x1E81505FA2D3DCB3ULL,
		0xC0AFDCB6EAD11329ULL,
		0xB98E3FEF9693946CULL,
		0x61CC68CBFAC3FEA6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2F9ABFF429A66D18ULL,
		0xECB428FF7DCA9CC7ULL,
		0xF25C900FEA066EB1ULL,
		0x6E133604BAD0316DULL,
		0x7AC052AABBEFED5EULL,
		0xB40519FA2BAE95E6ULL,
		0xA84CBD959E89ED7FULL,
		0x93CE35B26902F6F7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8D9C7CE2C1E45543ULL,
		0xFDFB38B17009A31BULL,
		0xF72B3EC548A07D14ULL,
		0x6B3EBF23D7BD9BAFULL,
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
		0x0A344D36FD7668FAULL,
		0x7106CF66B5C4FCD3ULL,
		0x967CBB3519A2C808ULL,
		0xF99E4EE5B3035275ULL,
		0x237A0065D1ECF2EAULL,
		0x5C4AB812DB24B9C2ULL,
		0x1FAAD57C2243555DULL,
		0xFE0830E5B50208ACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA39441E7E61580A7ULL,
		0x6376176743610939ULL,
		0xC816A497298ECC64ULL,
		0x5AB4A1CF5371A538ULL,
		0x3A9D53D311580649ULL,
		0xF8D0DD971DE13BF9ULL,
		0xC759103FCB40336EULL,
		0xBEDC91A0BD972F89ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF761A917AD7C09A2ULL,
		0xD1A7265D8A689F6BULL,
		0xEA895D92DA8B0506ULL,
		0x7F635153196DE855ULL,
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
		0xB050B25EA4553E35ULL,
		0x5D02CD8BB1DAC163ULL,
		0xE565D7D5FF7DD5EEULL,
		0x63D51CCA12F0C4FAULL,
		0x059ECA704A5878FFULL,
		0xB387633AA89E292AULL,
		0xF7D130237C34189AULL,
		0x635B11CEC6912C1EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD8EB3271A97E7055ULL,
		0x9FF716DABAD590CFULL,
		0x6355FCC4BAB8829DULL,
		0xE5D34946243939D5ULL,
		0x5DDD1C0C843A344FULL,
		0xD8415472C43E1EB3ULL,
		0xDC2B5DA0E5AD266FULL,
		0x068754189BC7D2C6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBE2562BC635501EEULL,
		0x4971E85CDD46BE30ULL,
		0x9CAD1A739CCD45ADULL,
		0x456FFC8E489ACE39ULL,
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
		0x632BBA913D89606BULL,
		0x226EAC759A5AF14CULL,
		0x2973D88B92312779ULL,
		0x83196095B2CD3A38ULL,
		0xA2737A4D7ABF532AULL,
		0x0D1593E0878DB851ULL,
		0x1D3EDBDD187079CDULL,
		0x7E97A19E4CD6F939ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5FD6A0DC891EC199ULL,
		0x82093020F63B673FULL,
		0x77090A3287A69549ULL,
		0xE330520CF3E92E0AULL,
		0xE5F6DF4311A30917ULL,
		0xFF32C85762286F18ULL,
		0x4E9C5F13F9E9D6AFULL,
		0x6FDC171265F95895ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFDD41D404E9D9DDDULL,
		0xB00FB2B031286878ULL,
		0x5E8954339286C87FULL,
		0x4FBF9F4D03C9E47EULL,
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
		0x5D1E9860BD19D65BULL,
		0x1C24AC2476F88973ULL,
		0x21C65CF9BAA9B76AULL,
		0xEB68A2285A9EC90FULL,
		0x1AE7CE8BBA04F8F5ULL,
		0x2D04B61C4D07439BULL,
		0xA377EEF02FFF7269ULL,
		0x4C6C45DF1EE36496ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0B30270FF7D5564EULL,
		0xB0AF21B2B60E0957ULL,
		0xC5ACD9360FFCE386ULL,
		0x95547DA1922938F8ULL,
		0xF88E9B3128919B5AULL,
		0x1841B67245802DA1ULL,
		0xE8A70D0B4F1D0764ULL,
		0xF29CD1EC1ED661ECULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6B2C10C25C64616CULL,
		0x80677DAEDEF7C317ULL,
		0x171B0BBD0C48B6A4ULL,
		0x2ADF5A98CA63F548ULL,
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
		0x7CDC4C9D55FEA024ULL,
		0x50F94542B85DC956ULL,
		0xC6BC3209E6EA898FULL,
		0x11CE8E9A9F3BCBC7ULL,
		0xECE1B409AD5BE642ULL,
		0xBF6125FDBD764312ULL,
		0xB6BC8488B92C49ACULL,
		0x3C2BDCBD923DA5D9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4FBD07F3ABFA6A1AULL,
		0x1E0AA4033E8CE8BDULL,
		0xB43AA4250054A747ULL,
		0xF8D34101507534FDULL,
		0x03A05ABCBA10E470ULL,
		0xBD52D0B56DE58515ULL,
		0xC80324973B11CF39ULL,
		0x9653B311FD044088ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCCD28615C726790FULL,
		0x810F49FB494D1449ULL,
		0x8205CBBD9E840F5AULL,
		0x37117D11754BA0CDULL,
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
		0xF1D937A41852FD11ULL,
		0x0ECA9620C1ACB910ULL,
		0x88F54106104DE806ULL,
		0x34580AA1D2B3AE8AULL,
		0xAFDD0FF519DF3867ULL,
		0xA3236DD76D146F36ULL,
		0x8C1674BC039D2BD2ULL,
		0x3E29E365BF233220ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF6A1B0CE049EC157ULL,
		0x6ECAAB8ED5289583ULL,
		0x4D106EE0D0779BF4ULL,
		0x5C9F26DB4C8A02B2ULL,
		0xABFBE1B3EE4236B0ULL,
		0xA7EF1BAB2E5D2CFDULL,
		0xB18974812D8A535DULL,
		0xB8EDB10C82D223BEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8EA464828D027A25ULL,
		0xE9C41D233BB7F803ULL,
		0xACD2DAE106A26D6EULL,
		0x1EA85D057A31CE5EULL,
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
		0x3D8D9DBBB5DAC25FULL,
		0x164368C10D06F913ULL,
		0x287921330F02946EULL,
		0xCF7DA83DF3F86BB4ULL,
		0x95F65100FEAB5EEDULL,
		0x270982F2EE34D754ULL,
		0x7ACBC3C8590D14F5ULL,
		0x329F3ECC6245F91FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x29DFC01D768A0362ULL,
		0xFB1F9C18C6579C7DULL,
		0x90D49886A645B889ULL,
		0xF6C33E175B5C402AULL,
		0xF0DE678296984EE3ULL,
		0xBE5DAA55CDEC4335ULL,
		0xDE3A10DF893136D0ULL,
		0xC22D9C8568DFFC0CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x953A8661B2251D48ULL,
		0xA4A5F3FB11755922ULL,
		0xD545173B435FD54BULL,
		0x099880AF9DBFBC4CULL,
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
		0x2E9ABFDFD1D60D0DULL,
		0xAC1F7BA9CA95FECAULL,
		0x2831E51F8F03DDCEULL,
		0xEDB5395D3D1AF678ULL,
		0x8147D1A0335AD3EFULL,
		0xEC15D4F2303DCDC0ULL,
		0x682037B163B58FC2ULL,
		0xD51F5D873F939CB7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCD0B17517FD1D70CULL,
		0x5B9BFAA2C66CB76DULL,
		0xFDBD16B3EAC580C4ULL,
		0xD52FAC1D07422AE3ULL,
		0x3F5838B9F3BE9CB2ULL,
		0x6F7F67859E87ED76ULL,
		0x4FB208EEEE99AEEBULL,
		0x9C463C65F6B8DF9BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2B205ABBC3346A52ULL,
		0xCED7BF24A5289262ULL,
		0xCACFBF490661BD06ULL,
		0x08C078310650DDBFULL,
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
		0x8E53762B9CC189D9ULL,
		0x9A4115234DB0DF32ULL,
		0xEAC5A327842F23B9ULL,
		0x33BADA4A86FE3E9EULL,
		0xE569C594CF3F0BDBULL,
		0xF363E9C37E64E267ULL,
		0x70064ADF8C985FFFULL,
		0xB3E66F4CFBE5E7F4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFE8A43D33EDF4CC8ULL,
		0xCE269537FECA22D2ULL,
		0x13785EEDEBADDF40ULL,
		0x320754B77D7D9308ULL,
		0x85A9DA56B3F1C39BULL,
		0x52AC36E711531840ULL,
		0xCA327C702345DA6DULL,
		0x37D011028B80E7FFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC6461D906B5AF93DULL,
		0xA75F0CA37F8ABE37ULL,
		0x74BDE8C33AC1183CULL,
		0x6D05849FB87EA9E7ULL,
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
		0x47EB3FD3B87091A1ULL,
		0xAF912F104F0EE033ULL,
		0x9CCFEFF2EDDD7F2FULL,
		0xD3D7158EB0C17436ULL,
		0x787D560EF4EE2C46ULL,
		0xDC7332F28671AE2CULL,
		0xCB4308E15F63A97CULL,
		0x138EAAA760E1B3BCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4573ABD5A0BB37C1ULL,
		0xAFAF6C2D595F5C0AULL,
		0xADC81BF1C7D792ABULL,
		0x7EFF8412613F6C93ULL,
		0xF26B55E6152390B0ULL,
		0x7BA9A8BBD487C3E9ULL,
		0xA3309698B950799BULL,
		0x7016259FECB2FF8BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE9239A0F4FC87023ULL,
		0x5DCC47015E684A08ULL,
		0xE1C4CAC9CCDF07F8ULL,
		0x18BB50978E70C6EEULL,
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
		0xA4E2CFB6BDCFDF96ULL,
		0x81E51524A902905AULL,
		0xAAFCA9D376E51896ULL,
		0x549FB4494DB3F2A6ULL,
		0x78F3273AC3009612ULL,
		0x36B987299474B067ULL,
		0xDF52B8B4854256E6ULL,
		0x21E5355653996EFEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9823761EF69A6A61ULL,
		0x2DB10601C2E7DBCFULL,
		0xD5F847785FB92F96ULL,
		0x9A21B4783C01AE80ULL,
		0x14203B5E64338921ULL,
		0x092FEA5DE179D6CEULL,
		0xFC6DA697E40E7B4CULL,
		0xB881FB0FE4B36AECULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x040E5C4DD9A55D91ULL,
		0x16A1555F77570150ULL,
		0x8305129B04DE81E3ULL,
		0x5F38A64587D6DECDULL,
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
		0x786E04F8F2EADFB9ULL,
		0xAFD5ADFB89183BDDULL,
		0x2212E730E19406DDULL,
		0xD3F889D376AAED90ULL,
		0x295B7F7C461FD934ULL,
		0x1B7DCF376B47978BULL,
		0xAA7259713EA78100ULL,
		0x93CECD053419D6A9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5017D5BCBCC1BE48ULL,
		0x75C42E700DF690F8ULL,
		0x553E57FAA3848B67ULL,
		0x8BAE33B3093FDF4BULL,
		0x389095C0045861B6ULL,
		0xE6F7810A39456751ULL,
		0x293A013D1F70D08FULL,
		0x7C396E3DD2F280DFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE674E12DF9C4DEAAULL,
		0x06011A40E774D37EULL,
		0xFB31A6F2E02DAC1EULL,
		0x487667B8D941CA53ULL,
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
		0xDF5EBCEE1E9A55CDULL,
		0xD3EA530775AF4D0AULL,
		0xDFB3D14393EB13DEULL,
		0x0430DD1AB7CF7629ULL,
		0x360554AD823D1A3EULL,
		0x3A85FB16CA55DFA7ULL,
		0x2322790A9694D05AULL,
		0xFE08D30AD619195DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x77AF71188C18B30FULL,
		0x17C889F5243921CCULL,
		0xE2B4FB600F027008ULL,
		0xFD649FA837B746E0ULL,
		0x6D4836C8166DBE7DULL,
		0xB0185AAC22BB35A2ULL,
		0x481EEC3BD6CD0E7AULL,
		0x2BDBC5BE5DFB01F1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x33C1BBE3934945D8ULL,
		0x486798E7326B67F4ULL,
		0x7F85BC93FC8F6B05ULL,
		0x397C36CC548FA94BULL,
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
		0x8330F7327E7711B8ULL,
		0x5B5153AA6602F93EULL,
		0x3DE87FCB8E908003ULL,
		0xD869FD366CE5486CULL,
		0x68D550880C7F591EULL,
		0xA50894307682C34BULL,
		0x92AE202F3BB64DF5ULL,
		0x0582A30ED57FC40DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x968316ACA0B12424ULL,
		0x3FCED58FC02A0C17ULL,
		0xED9D0CA353C5070AULL,
		0x988C8946ED062122ULL,
		0xAC71781E9BE63F08ULL,
		0x331FC08BAFA487EDULL,
		0x1E47F8998F1D8232ULL,
		0x9636F3B9C6D2539AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE380002C947FC9A7ULL,
		0x0411E8902AD5BD10ULL,
		0x9775535FD979B7FCULL,
		0x45197A8FAD9DD86CULL,
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
		0x39914DAAC589F57BULL,
		0x7BA01390551366C6ULL,
		0x0E55F2727E9EA59FULL,
		0x119CEC59AAC912E5ULL,
		0x3F64F9C3D355964DULL,
		0xB9BF3E13D423377DULL,
		0x7CA209186D012E90ULL,
		0x8233D22D96F4952AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x949712DC7282EACFULL,
		0x5EAFD1D7F38060A7ULL,
		0x186821DCB7A07955ULL,
		0x768D37881993D8C7ULL,
		0x9AD4A964B4A05D07ULL,
		0x73CADB4E6B882B40ULL,
		0x361B0D5678D72E05ULL,
		0xDA4999ADB89A6754ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x126628ECE1ED890FULL,
		0x7F36EB05E896D71FULL,
		0x6DF72F60053A40F6ULL,
		0x07D417CC929807ECULL,
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
		0x7C53D01C63530DABULL,
		0x8F175F96929249DCULL,
		0x36A31709D2785D04ULL,
		0x668D5BC763170523ULL,
		0x629492DCE52C20AEULL,
		0xE0AC5517C240052FULL,
		0x5621FAA563E68A21ULL,
		0xB8C0D9EA567E3047ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE9EF28F92141E1A0ULL,
		0x647E7A853BA267CDULL,
		0xBCCDAA85C3A42E0DULL,
		0x6B8F4BAB76899068ULL,
		0x5E2349BBD216C629ULL,
		0xC0CE9EA60EDCE948ULL,
		0xBB437177BCF2067BULL,
		0x37D864F8C1DF0630ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3B35820C173C9E9BULL,
		0xE581F9F1F7A60659ULL,
		0x76DDC94AD71FB99FULL,
		0x1D7F6BF7FC2DB415ULL,
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
		0xA1DB4A5B1FA33540ULL,
		0x15C9913515257D24ULL,
		0xE60E53A8F15AB73DULL,
		0xBACED858E0C3DC13ULL,
		0x25A49687C889CCFDULL,
		0x529F9B1015569FE6ULL,
		0x1674481373139732ULL,
		0x6614F2F43B846B9FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x93FC59AEF4E27281ULL,
		0xD937F0F8802C699CULL,
		0xF90003F609B0D034ULL,
		0xBDAF23EA71500E9AULL,
		0x61F078307A40413EULL,
		0xEA90B381DE69689BULL,
		0xC4B52DA7DEA35853ULL,
		0x691D54711E7CA2E6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1A9B71A1C9AB8106ULL,
		0xAEC7FF58BC2F48A1ULL,
		0x0F6C3BAAF0533C0BULL,
		0x09E13BE4BE9B98D5ULL,
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
		0xF5459F6D68F102E0ULL,
		0xEC3819F25B645A78ULL,
		0x9F18AD6B32F30A11ULL,
		0x196D616B601FB17EULL,
		0x00160D71A0731684ULL,
		0x21CE2EA7FD43A6F3ULL,
		0x3171874264DD5B57ULL,
		0x2D7633FA7E6E0CEAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3B3F03B6690F2221ULL,
		0xB5FF74774A1BF440ULL,
		0xEA74A110505E25CBULL,
		0xECDEDD44FAD25F59ULL,
		0x35BD36552F33A269ULL,
		0xA5B35C9095F53A6CULL,
		0xC74642131CB9AEBEULL,
		0xF86F279042C7BBEFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC33689EFCF4D1827ULL,
		0xA233D4F466EC823AULL,
		0x7710515F97E082E8ULL,
		0x0B9A5BEB3FFD5750ULL,
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
		0xC5322705C378E030ULL,
		0x4706AA40E5F29EC8ULL,
		0xBAFB21BA9B3DDCEDULL,
		0x88A35472C60406DFULL,
		0xC59A8A9C3A14490DULL,
		0x838686E2D12812DBULL,
		0x036C2F81A7C14118ULL,
		0x25D2B8543EE08BABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC2A8C8A5E98B4CEAULL,
		0xA0E4662424D3817EULL,
		0x7699F34F9678B5E3ULL,
		0xBC0C5746468129FDULL,
		0x16780914B10398CAULL,
		0x86163C88D8F90121ULL,
		0x384657D3AE790CF5ULL,
		0x80B86DCCCE359F66ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x01A8987E3267BB24ULL,
		0x44CD4D77981BBF00ULL,
		0x6BFF323E057CE43BULL,
		0x4E7E0D4738E1EF18ULL,
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
		0x340560B1F01369FEULL,
		0xBC0D5B708D80FA73ULL,
		0x04E90AF715F12940ULL,
		0x851A6BB91D59966BULL,
		0x83AB55F6E085FC03ULL,
		0x3BF91128C85E68BCULL,
		0xCD9C7087077A72B1ULL,
		0xA3496A774AF29FEBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBDB303E6BDD9E0E0ULL,
		0x65E423090DFD3AEDULL,
		0x8C906CB5C15CEE38ULL,
		0x0877C39458705793ULL,
		0x3F5F639FB1E7E729ULL,
		0x79F75A3DACE39C49ULL,
		0x71149FF65AC7A2A9ULL,
		0xB332565D26470148ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x999855BC1DB0A12EULL,
		0x226A5F4D93BE18A1ULL,
		0x348193BAF71F1C2FULL,
		0x200FA4063662CB17ULL,
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
		0x9169E6651F1958B2ULL,
		0x43CE895C4509601EULL,
		0x6BA35BA44C707E62ULL,
		0x576992B213634297ULL,
		0xA93FE71A662E4FC9ULL,
		0x08A2357624CE2E47ULL,
		0x886F90CF10C65371ULL,
		0x620B4D439E8E3553ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9AAA117B54EC4E1AULL,
		0xEBBE3AF65B4E1C51ULL,
		0x7FB4871A07A531EAULL,
		0x4C74D8DB9A71533FULL,
		0x254FA6BF9BBD1160ULL,
		0xD2916B5E9026AD08ULL,
		0xFA9A70FF7CFE9F16ULL,
		0x5E789BEE763C114FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8C696263D6FC4E41ULL,
		0x5E8E4DE5FA98733AULL,
		0xF9918D5A347011DBULL,
		0x12BB0C7A752347DEULL,
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
		0xCCD692A66DEA5697ULL,
		0x97AB9B2A24142E62ULL,
		0x106BFB35071F9441ULL,
		0xAA843F303D0A63EAULL,
		0x73615E51A572F48FULL,
		0x3F17B696817BB498ULL,
		0x9225F12799934DABULL,
		0x8DC7C1651840F0F0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2415A6FFB6540B01ULL,
		0x07BF2B3AD3D5ADA3ULL,
		0x1411078F22641682ULL,
		0x56DB73C039F089A0ULL,
		0xEA0B4478EB7A7579ULL,
		0x49A609EEE506D278ULL,
		0x405055B0D285F1B9ULL,
		0xE202D996C37F04BEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0B88C1D2527926FFULL,
		0xFECC10D08998116EULL,
		0x2210074770B723A9ULL,
		0x52E3341097E2E9C2ULL,
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
		0x7CAE2208E5480A56ULL,
		0x0787B387F3AAE64DULL,
		0x235AD0D68574CCE4ULL,
		0x72768E783BAD77D8ULL,
		0xC6F8A658723AADF9ULL,
		0x08C7FAFEB4C05059ULL,
		0x37531517C7F5B0DEULL,
		0x87452AC75B6164D6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1E9CAC10DC5DF669ULL,
		0xC50764515DE1DC74ULL,
		0xB16F42AAEBAC222DULL,
		0x459B79B8220BCEA8ULL,
		0x6271DCF2B140417FULL,
		0xC191CECA183A7CA8ULL,
		0x10E3C3990939962BULL,
		0x7A66CEC3FFD98B01ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4A135B12AE162E55ULL,
		0xD48ADF05D1A6762EULL,
		0x2671A6FBE9B4A12CULL,
		0x15DCBD3FAFCBFED3ULL,
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
		0x75F2D9188ABB3F28ULL,
		0xDE714948E0BE46E4ULL,
		0xEBE80567522237CBULL,
		0x4E7F0DCB7BDB4E82ULL,
		0xABB615A7F3A540CBULL,
		0xFC6F43555C11F417ULL,
		0x98B1BBF37C3F53F0ULL,
		0x2F18AE5D5CB39EFEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8482C7BE1A720A47ULL,
		0x5F222D2B19E2CDFEULL,
		0x11139B973B44CE9AULL,
		0xBEAA5E78585A8D97ULL,
		0x54BFD54F84D16213ULL,
		0x07A734740F93767EULL,
		0xBA1AE4AC56D548AAULL,
		0x57FF6376D4581828ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD9FD9E7AE3BC4327ULL,
		0xD501518F21A21DA8ULL,
		0xE5385E5FA49B15B9ULL,
		0x7D95CD8B6116C4AAULL,
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
		0xFD4FAC2525669ADDULL,
		0x2128C2F65C904892ULL,
		0x306EE8CA0FA28D81ULL,
		0x62FC46688149053DULL,
		0x4FC66CBE3948699CULL,
		0xD4E6B61F325E4C17ULL,
		0xDE6C14D5B4F2AEC3ULL,
		0xFDC8B499D6F10C23ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x71CE377FDA7499A3ULL,
		0x93991A878CCF35DDULL,
		0x1836F1115701C5E4ULL,
		0x063FAB5B3329CE90ULL,
		0xE5838B3D5C4DCB56ULL,
		0x04EA5045301DF872ULL,
		0x32DEE552110A58E4ULL,
		0x854AF4FA806B6F18ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x516EEDC61825824AULL,
		0x6D06C6CB254D7D1DULL,
		0x8F2D05430D1D86D5ULL,
		0x3F670CB425F48668ULL,
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