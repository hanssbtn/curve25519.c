#include "../tests.h"

int32_t curve25519_key_rshift_inplace_test(void) {
	printf("Inplace Key Right Shift Test\n");
	curve25519_key_t k1 = {.key64 = {
		0x3D319118339453ABULL,
		0x0D161BB18681FC3EULL,
		0x8038AE5F72A8B39FULL,
		0x3193ADB7EA01DB93ULL,
		0xCCC4B305BE8F1BA9ULL,
		0x589429EFC3D10A61ULL,
		0x496EC5AE8DDB2BCCULL,
		0x0000000000000000ULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0x37630D03F87C7A63ULL,
		0x5CBEE551673E1A2CULL,
		0x5B6FD403B7270071ULL,
		0x660B7D1E37526327ULL,
		0x53DF87A214C39989ULL,
		0x8B5D1BB65798B128ULL,
		0x00000000000092DDULL,
		0x0000000000000000ULL
	}};
	int shift = 47;
	printf("Test Case 1\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	int32_t res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 1 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -1;
	} else {
		printf("Test Case 1 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6C36B4633C527EC7ULL,
		0x0EC6C8C08342125EULL,
		0xAD46BE0212332F29ULL,
		0x34AAA591141DD411ULL,
		0xBF4D5C28D69E153DULL,
		0xEB4B358BB6A0642FULL,
		0xBCD39716B165EB92ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEC6C8C08342125E6ULL,
		0xD46BE0212332F290ULL,
		0x4AAA591141DD411AULL,
		0xF4D5C28D69E153D3ULL,
		0xB4B358BB6A0642FBULL,
		0xCD39716B165EB92EULL,
		0x000000000000000BULL,
		0x0000000000000000ULL
	}};
	shift = 60;
	printf("Test Case 2\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 2 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -2;
	} else {
		printf("Test Case 2 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x32C3070A74BDB66CULL,
		0x858793D480525067ULL,
		0xA663327021F223A0ULL,
		0xFDC42E7317B09F8DULL,
		0x93B9D71210DB9E80ULL,
		0x105DF8658336A321ULL,
		0x18F6D6B686678985ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x27A900A4A0CE6586ULL,
		0x64E043E447410B0FULL,
		0x5CE62F613F1B4CC6ULL,
		0xAE2421B73D01FB88ULL,
		0xF0CB066D46432773ULL,
		0xAD6D0CCF130A20BBULL,
		0x00000000000031EDULL,
		0x0000000000000000ULL
	}};
	shift = 47;
	printf("Test Case 3\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 3 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -3;
	} else {
		printf("Test Case 3 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x710B1BD7FB86E092ULL,
		0x8801D89C11079F5FULL,
		0x6DAF796C9F0B30F6ULL,
		0x32DF1C7A6378538DULL,
		0x3042260C78376900ULL,
		0x66098BC202D5F032ULL,
		0xED56A2A17C77D50CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x710B1BD7FB86E092ULL,
		0x8801D89C11079F5FULL,
		0x6DAF796C9F0B30F6ULL,
		0x32DF1C7A6378538DULL,
		0x3042260C78376900ULL,
		0x66098BC202D5F032ULL,
		0xED56A2A17C77D50CULL,
		0x0000000000000000ULL
	}};
	shift = 0;
	printf("Test Case 4\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 4 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -4;
	} else {
		printf("Test Case 4 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF932CA6441DCA9BDULL,
		0xF52535BE0554518DULL,
		0xDA804A7AD5B54703ULL,
		0xA845201AB3934384ULL,
		0x19F69EFEE0AA0A3DULL,
		0x9603D17083D28E34ULL,
		0xC0C81130C4519CF2ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC0AA8A31BF26594CULL,
		0x5AB6A8E07EA4A6B7ULL,
		0x567268709B50094FULL,
		0xDC154147B508A403ULL,
		0x107A51C6833ED3DFULL,
		0x188A339E52C07A2EULL,
		0x0000000018190226ULL,
		0x0000000000000000ULL
	}};
	shift = 35;
	printf("Test Case 5\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 5 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -5;
	} else {
		printf("Test Case 5 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x20C448CD003FD4C8ULL,
		0xA41E96DF755AD3D5ULL,
		0xA1FC3A198CF9A9EBULL,
		0x55865D9891EBE33FULL,
		0x8003C7B84DF8B5F3ULL,
		0xBB7CFA4F16B2EB1CULL,
		0xB2A41F684DD9B4A0ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB4F548311233400FULL,
		0x6A7AE907A5B7DD56ULL,
		0xF8CFE87F0E86633EULL,
		0x2D7CD5619766247AULL,
		0xBAC72000F1EE137EULL,
		0x6D282EDF3E93C5ACULL,
		0x00002CA907DA1376ULL,
		0x0000000000000000ULL
	}};
	shift = 18;
	printf("Test Case 6\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 6 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -6;
	} else {
		printf("Test Case 6 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x85D18AC39AD73FC0ULL,
		0x21084D1458440229ULL,
		0x3970F8A3F6769F6EULL,
		0x466ADE8A418351F6ULL,
		0x840C5A8A262357D3ULL,
		0x6E1A1BE30D833EA7ULL,
		0x7C14F3E04252E430ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD145844022985D18ULL,
		0x8A3F6769F6E21084ULL,
		0xE8A418351F63970FULL,
		0xA8A262357D3466ADULL,
		0xBE30D833EA7840C5ULL,
		0x3E04252E4306E1A1ULL,
		0x000000000007C14FULL,
		0x0000000000000000ULL
	}};
	shift = 44;
	printf("Test Case 7\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 7 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -7;
	} else {
		printf("Test Case 7 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC2F25B62B6A06250ULL,
		0x8A1FB6B15A67AAA7ULL,
		0xC2A2D098F0F77FF9ULL,
		0xC36DEEF57D1DA145ULL,
		0x64BFDBB38A031CC1ULL,
		0xFFC767961B3456B1ULL,
		0xE357507C4237D7ACULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x699EAA9F0BC96D8AULL,
		0xC3DDFFE6287EDAC5ULL,
		0xF47685170A8B4263ULL,
		0x280C73070DB7BBD5ULL,
		0x6CD15AC592FF6ECEULL,
		0x08DF5EB3FF1D9E58ULL,
		0x000000038D5D41F1ULL,
		0x0000000000000000ULL
	}};
	shift = 30;
	printf("Test Case 8\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 8 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -8;
	} else {
		printf("Test Case 8 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x97A203EB03DC91C0ULL,
		0xAE876799FE15F95CULL,
		0x91B6FD90BD4A1F64ULL,
		0x11116533E35DDBDDULL,
		0x4A7CC1FF4D1FFA0AULL,
		0x261237D4AEBF2C75ULL,
		0xC3D2299C607136A3ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC97A203EB03DC91CULL,
		0x4AE876799FE15F95ULL,
		0xD91B6FD90BD4A1F6ULL,
		0xA11116533E35DDBDULL,
		0x54A7CC1FF4D1FFA0ULL,
		0x3261237D4AEBF2C7ULL,
		0x0C3D2299C607136AULL,
		0x0000000000000000ULL
	}};
	shift = 4;
	printf("Test Case 9\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 9 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -9;
	} else {
		printf("Test Case 9 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3DD3AFBC36BFE52AULL,
		0xC18D5A24B9653F7FULL,
		0x8755076AE1DD2F6AULL,
		0x841B27FCDC92AB1DULL,
		0xFC5908F4BD6E448BULL,
		0x9B5A300BF0FC198FULL,
		0x2A7639765613D417ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9653F7F3DD3AFBC3ULL,
		0x1DD2F6AC18D5A24BULL,
		0xC92AB1D8755076AEULL,
		0xD6E448B841B27FCDULL,
		0x0FC198FFC5908F4BULL,
		0x613D4179B5A300BFULL,
		0x00000002A7639765ULL,
		0x0000000000000000ULL
	}};
	shift = 28;
	printf("Test Case 10\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 10 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -10;
	} else {
		printf("Test Case 10 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC46388D1FBDCF55EULL,
		0xF0CA0D2A9B1DF51FULL,
		0x3B89186A66E94F1BULL,
		0xA3D7AA81F2D33621ULL,
		0x2E8AFC5845EB05DCULL,
		0xFC55A6D5730E219EULL,
		0x066B59DB95A7C8D3ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEA3F88C711A3F7B9ULL,
		0x9E37E1941A55363BULL,
		0x6C42771230D4CDD2ULL,
		0x0BB947AF5503E5A6ULL,
		0x433C5D15F8B08BD6ULL,
		0x91A7F8AB4DAAE61CULL,
		0x00000CD6B3B72B4FULL,
		0x0000000000000000ULL
	}};
	shift = 15;
	printf("Test Case 11\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 11 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -11;
	} else {
		printf("Test Case 11 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x80B25C8E862865CEULL,
		0xAF2D7F805251B48BULL,
		0x6F50F4D7DB197C6AULL,
		0x9365F06DC6B58EE1ULL,
		0xE0B96454E87828E1ULL,
		0x98B431FB4707A61AULL,
		0x2C3E491F122E13A0ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5E5AFF00A4A36917ULL,
		0xDEA1E9AFB632F8D5ULL,
		0x26CBE0DB8D6B1DC2ULL,
		0xC172C8A9D0F051C3ULL,
		0x316863F68E0F4C35ULL,
		0x587C923E245C2741ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 63;
	printf("Test Case 12\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 12 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -12;
	} else {
		printf("Test Case 12 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5C1C6E91D226245DULL,
		0xFF6711FEF8EA8C09ULL,
		0xA6808BDD5D961A5EULL,
		0xB9637E0F81042BD9ULL,
		0xA7902C070564F037ULL,
		0x5CB6D630CE4B9AD2ULL,
		0xD6CFA5FFAA3617E5ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x88FF7C754604AE0EULL,
		0x45EEAECB0D2F7FB3ULL,
		0xBF07C08215ECD340ULL,
		0x160382B2781BDCB1ULL,
		0x6B186725CD6953C8ULL,
		0xD2FFD51B0BF2AE5BULL,
		0x0000000000006B67ULL,
		0x0000000000000000ULL
	}};
	shift = 49;
	printf("Test Case 13\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 13 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -13;
	} else {
		printf("Test Case 13 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x552EAE7FA6B0E24BULL,
		0x37A8830A4262A46FULL,
		0xF68AC87EC0C10D69ULL,
		0xE6747F87A59E14D9ULL,
		0x7495B1975EC12261ULL,
		0xD95A65C4853F8CD1ULL,
		0x86FB7202796D7E3BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD54BAB9FE9AC3892ULL,
		0x4DEA20C29098A91BULL,
		0x7DA2B21FB030435AULL,
		0x799D1FE1E9678536ULL,
		0x5D256C65D7B04898ULL,
		0xF6569971214FE334ULL,
		0x21BEDC809E5B5F8EULL,
		0x0000000000000000ULL
	}};
	shift = 2;
	printf("Test Case 14\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 14 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -14;
	} else {
		printf("Test Case 14 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8BCD03BDE829A193ULL,
		0x3B8C0B0982F4C953ULL,
		0xBCABF11AF54B3BDBULL,
		0xB82E30EF17DC1BE5ULL,
		0xDBEFA96B92B2B2B5ULL,
		0x73CD0AF16CF25804ULL,
		0x5874D094418E5D89ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x260BD3254E2F340EULL,
		0x6BD52CEF6CEE302CULL,
		0xBC5F706F96F2AFC4ULL,
		0xAE4ACACAD6E0B8C3ULL,
		0xC5B3C960136FBEA5ULL,
		0x5106397625CF342BULL,
		0x000000000161D342ULL,
		0x0000000000000000ULL
	}};
	shift = 38;
	printf("Test Case 15\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 15 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -15;
	} else {
		printf("Test Case 15 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4694F874B6DCEBC1ULL,
		0xB5FD14E322213FC9ULL,
		0xDE199225D7E15548ULL,
		0x93B476C06EE715B3ULL,
		0x776A9AD87D6503A9ULL,
		0x5573D0B85A45A327ULL,
		0xC3A6F3CB10BB0F98ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6BFA29C644427F92ULL,
		0xBC33244BAFC2AA91ULL,
		0x2768ED80DDCE2B67ULL,
		0xEED535B0FACA0753ULL,
		0xAAE7A170B48B464EULL,
		0x874DE79621761F30ULL,
		0x0000000000000001ULL,
		0x0000000000000000ULL
	}};
	shift = 63;
	printf("Test Case 16\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 16 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -16;
	} else {
		printf("Test Case 16 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBF4FAB77E06592CEULL,
		0x3B02AB6019A68A39ULL,
		0x990FC4F13451A5CDULL,
		0xF8448C9387E31B98ULL,
		0x45D1413F8B21D7BAULL,
		0x934E12DEEC8BFF12ULL,
		0x93F716E623923271ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2AB6019A68A39BF4ULL,
		0xFC4F13451A5CD3B0ULL,
		0x48C9387E31B98990ULL,
		0x1413F8B21D7BAF84ULL,
		0xE12DEEC8BFF1245DULL,
		0x716E623923271934ULL,
		0x000000000000093FULL,
		0x0000000000000000ULL
	}};
	shift = 52;
	printf("Test Case 17\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 17 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -17;
	} else {
		printf("Test Case 17 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x80B0CB3ADCB760A3ULL,
		0x5D138182292A6D38ULL,
		0xD95A5F3EA4DC3664ULL,
		0xF4E17BB67DC3B4C6ULL,
		0x8E0477DEEA8BC60DULL,
		0x252535E23D14169AULL,
		0x1A3E5857CA4E6402ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x69C4058659D6E5BBULL,
		0xB322E89C0C114953ULL,
		0xA636CAD2F9F526E1ULL,
		0x306FA70BDDB3EE1DULL,
		0xB4D47023BEF7545EULL,
		0x20112929AF11E8A0ULL,
		0x0000D1F2C2BE5273ULL,
		0x0000000000000000ULL
	}};
	shift = 13;
	printf("Test Case 18\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 18 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -18;
	} else {
		printf("Test Case 18 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBDEDD98B64AF084AULL,
		0xB8BC751CC915FA98ULL,
		0xF0874115B03700E2ULL,
		0x7D52B28E4CD8FC98ULL,
		0x0BC7C489729CF3BEULL,
		0xD7F1D9D43D22A91EULL,
		0x9EFDE17B3759B4CFULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2F7B7662D92BC212ULL,
		0xAE2F1D4732457EA6ULL,
		0x3C21D0456C0DC038ULL,
		0x9F54ACA393363F26ULL,
		0x82F1F1225CA73CEFULL,
		0xF5FC76750F48AA47ULL,
		0x27BF785ECDD66D33ULL,
		0x0000000000000000ULL
	}};
	shift = 2;
	printf("Test Case 19\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 19 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -19;
	} else {
		printf("Test Case 19 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x427B99D791B35FE8ULL,
		0x16A00D455BD706E6ULL,
		0x1C35D3527317B961ULL,
		0x570CE1087B989971ULL,
		0x473A0CD5C2B6A610ULL,
		0xC9ED973BDB037368ULL,
		0x9E4998BC3BCAB314ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB8373213DCCEBC8DULL,
		0xBDCB08B5006A2ADEULL,
		0xC4CB88E1AE9A9398ULL,
		0xB53082B8670843DCULL,
		0x1B9B4239D066AE15ULL,
		0x5598A64F6CB9DED8ULL,
		0x000004F24CC5E1DEULL,
		0x0000000000000000ULL
	}};
	shift = 21;
	printf("Test Case 20\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 20 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -20;
	} else {
		printf("Test Case 20 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1124BCBB6D0EB59CULL,
		0x23401D77F7DDDF44ULL,
		0x4F4089A54A067512ULL,
		0xC3A06BFDFDCAB1BAULL,
		0xE2A371D9DB651742ULL,
		0x2BE33E9F269E4DFAULL,
		0x7A82E94E7C6200BEULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDF441124BCBB6D0EULL,
		0x751223401D77F7DDULL,
		0xB1BA4F4089A54A06ULL,
		0x1742C3A06BFDFDCAULL,
		0x4DFAE2A371D9DB65ULL,
		0x00BE2BE33E9F269EULL,
		0x00007A82E94E7C62ULL,
		0x0000000000000000ULL
	}};
	shift = 16;
	printf("Test Case 21\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 21 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -21;
	} else {
		printf("Test Case 21 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4A3E4F77BF199E44ULL,
		0xECBC5278A2472A8AULL,
		0xB4ED70910DBC18AFULL,
		0x0EBEE9754588F6ABULL,
		0xABCAA6044B31E3B6ULL,
		0x7CDF7EABFC29B361ULL,
		0xC951B91DF76E84C2ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x514947C9EEF7E333ULL,
		0x15FD978A4F1448E5ULL,
		0xD5769DAE1221B783ULL,
		0x76C1D7DD2EA8B11EULL,
		0x6C357954C089663CULL,
		0x984F9BEFD57F8536ULL,
		0x00192A3723BEEDD0ULL,
		0x0000000000000000ULL
	}};
	shift = 11;
	printf("Test Case 22\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 22 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -22;
	} else {
		printf("Test Case 22 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6CD1821795593777ULL,
		0x921B45A607F433F0ULL,
		0x90F81F1CC08BC5E7ULL,
		0x8CD84EC75901C0DCULL,
		0x7A6090D699F3DE9DULL,
		0xE65D278BE4B98321ULL,
		0xEE55A664DDFABE09ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA2D303FA19F83668ULL,
		0x0F8E6045E2F3C90DULL,
		0x2763AC80E06E487CULL,
		0x486B4CF9EF4EC66CULL,
		0x93C5F25CC190BD30ULL,
		0xD3326EFD5F04F32EULL,
		0x000000000000772AULL,
		0x0000000000000000ULL
	}};
	shift = 49;
	printf("Test Case 23\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 23 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -23;
	} else {
		printf("Test Case 23 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8C309D46D199EF54ULL,
		0xB67EB45D6323968FULL,
		0x19A83C991148BEF9ULL,
		0xA871624A17E7274CULL,
		0xEECDD162FD093DC4ULL,
		0x304B6E6084F6A85FULL,
		0x4E61FAB5DB5B36FDULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3F5A2EB191CB47C6ULL,
		0xD41E4C88A45F7CDBULL,
		0x38B1250BF393A60CULL,
		0x66E8B17E849EE254ULL,
		0x25B730427B542FF7ULL,
		0x30FD5AEDAD9B7E98ULL,
		0x0000000000000027ULL,
		0x0000000000000000ULL
	}};
	shift = 57;
	printf("Test Case 24\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 24 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -24;
	} else {
		printf("Test Case 24 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCE384E5EB7AAD97AULL,
		0x3B90C8072EAC6D28ULL,
		0x02903DB1A2D42E0DULL,
		0x7B232BC3B5B0214EULL,
		0xB555FA879A28A3DBULL,
		0xEE0CA62FF2AF27ECULL,
		0x0FCE81849E12E607ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAB1B4A338E1397ADULL,
		0xB50B834EE43201CBULL,
		0x6C085380A40F6C68ULL,
		0x8A28F6DEC8CAF0EDULL,
		0xABC9FB2D557EA1E6ULL,
		0x84B981FB83298BFCULL,
		0x00000003F3A06127ULL,
		0x0000000000000000ULL
	}};
	shift = 26;
	printf("Test Case 25\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 25 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -25;
	} else {
		printf("Test Case 25 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x94B0E0466FB8DE36ULL,
		0x67EE99CFFAFB457CULL,
		0x4132C8305385D3DDULL,
		0x39D5848D4F4ADF7CULL,
		0xFC5F7D00D39B3106ULL,
		0x5848422DBECE7FD3ULL,
		0x78F1916920562FF4ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF92961C08CDF71BCULL,
		0xBACFDD339FF5F68AULL,
		0xF882659060A70BA7ULL,
		0x0C73AB091A9E95BEULL,
		0xA7F8BEFA01A73662ULL,
		0xE8B090845B7D9CFFULL,
		0x00F1E322D240AC5FULL,
		0x0000000000000000ULL
	}};
	shift = 7;
	printf("Test Case 26\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 26 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -26;
	} else {
		printf("Test Case 26 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA2823022C70CA191ULL,
		0x0B1FC04E2519379AULL,
		0x734B1EB4E2A51BCFULL,
		0xA597CE6CFC199EB9ULL,
		0xA04E1C14B6342080ULL,
		0x0B6199D7E7D0D3D8ULL,
		0xC9261880EA0E2F34ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC04E2519379AA282ULL,
		0x1EB4E2A51BCF0B1FULL,
		0xCE6CFC199EB9734BULL,
		0x1C14B6342080A597ULL,
		0x99D7E7D0D3D8A04EULL,
		0x1880EA0E2F340B61ULL,
		0x000000000000C926ULL,
		0x0000000000000000ULL
	}};
	shift = 48;
	printf("Test Case 27\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 27 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -27;
	} else {
		printf("Test Case 27 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDD15408EE2FE98EDULL,
		0x74FEE3BA66405D1AULL,
		0xFD073C77B07631D2ULL,
		0x4D61BAE3E652A6B3ULL,
		0x815D83EFCDC0FA79ULL,
		0x099AC900D0BEBA79ULL,
		0x1DAE8FBCD1E58B0AULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEE99901746B74550ULL,
		0x1DEC1D8C749D3FB8ULL,
		0xB8F994A9ACFF41CFULL,
		0xFBF3703E9E53586EULL,
		0x40342FAE9E605760ULL,
		0xEF347962C28266B2ULL,
		0x0000000000076BA3ULL,
		0x0000000000000000ULL
	}};
	shift = 42;
	printf("Test Case 28\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 28 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -28;
	} else {
		printf("Test Case 28 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4DA624A4D6E3ACDFULL,
		0xE857172512294A48ULL,
		0x9EC6BB31D8DD9156ULL,
		0x8362ECED11D009DBULL,
		0x58B01D28A0199079ULL,
		0x0F43C54D3AD5C8C1ULL,
		0x58E6E43D3FB34FE5ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x512294A484DA624AULL,
		0x1D8DD9156E857172ULL,
		0xD11D009DB9EC6BB3ULL,
		0x8A01990798362ECEULL,
		0xD3AD5C8C158B01D2ULL,
		0xD3FB34FE50F43C54ULL,
		0x00000000058E6E43ULL,
		0x0000000000000000ULL
	}};
	shift = 36;
	printf("Test Case 29\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 29 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -29;
	} else {
		printf("Test Case 29 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x307720D8343171D5ULL,
		0xEC1AA1B502B5A9A8ULL,
		0x03DE26A0891F0D21ULL,
		0x7EA85996001BF8D2ULL,
		0x28AFBF07AAF62274ULL,
		0x1398B3C24B925C38ULL,
		0xB7E06BF1C60AAACAULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA86D40AD6A6A0C1DULL,
		0x89A82247C3487B06ULL,
		0x16658006FE3480F7ULL,
		0xEFC1EABD889D1FAAULL,
		0x2CF092E4970E0A2BULL,
		0x1AFC7182AAB284E6ULL,
		0x0000000000002DF8ULL,
		0x0000000000000000ULL
	}};
	shift = 50;
	printf("Test Case 30\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 30 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -30;
	} else {
		printf("Test Case 30 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x33E656E1625EC6C6ULL,
		0x42A0033D674B3C8EULL,
		0x81DEB1AEEC6D0205ULL,
		0xC45F7023507D32B6ULL,
		0xBE070842917B7F28ULL,
		0x0195ABED3C8CD3D4ULL,
		0xDAE7A992455D2BC6ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x74B3C8E33E656E16ULL,
		0xC6D020542A0033D6ULL,
		0x07D32B681DEB1AEEULL,
		0x17B7F28C45F70235ULL,
		0xC8CD3D4BE0708429ULL,
		0x55D2BC60195ABED3ULL,
		0x0000000DAE7A9924ULL,
		0x0000000000000000ULL
	}};
	shift = 28;
	printf("Test Case 31\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 31 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -31;
	} else {
		printf("Test Case 31 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDED10B8C237250F3ULL,
		0xF3BCD60FE4E8634DULL,
		0xDC417D1A6187D2EAULL,
		0x331A02569B9C6F11ULL,
		0x4D0510EDF97127FDULL,
		0xB1BE476E7586DE48ULL,
		0xCEF0316DEEBB4935ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE779AC1FC9D0C69BULL,
		0xB882FA34C30FA5D5ULL,
		0x663404AD3738DE23ULL,
		0x9A0A21DBF2E24FFAULL,
		0x637C8EDCEB0DBC90ULL,
		0x9DE062DBDD76926BULL,
		0x0000000000000001ULL,
		0x0000000000000000ULL
	}};
	shift = 63;
	printf("Test Case 32\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 32 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -32;
	} else {
		printf("Test Case 32 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0B619475C651816AULL,
		0x6F890AC700C7763BULL,
		0xF0BE9B4B930EB76EULL,
		0xF21D0CDE09C7801CULL,
		0x18B8B6FE55F975DDULL,
		0xB75555A2C9834E33ULL,
		0x5E2BBDCBBF2CEC5CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x763B0B619475C651ULL,
		0xB76E6F890AC700C7ULL,
		0x801CF0BE9B4B930EULL,
		0x75DDF21D0CDE09C7ULL,
		0x4E3318B8B6FE55F9ULL,
		0xEC5CB75555A2C983ULL,
		0x00005E2BBDCBBF2CULL,
		0x0000000000000000ULL
	}};
	shift = 16;
	printf("Test Case 33\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 33 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -33;
	} else {
		printf("Test Case 33 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1477A8012B908A03ULL,
		0x201AF0C2B43B8731ULL,
		0xA574FE4D6B799A71ULL,
		0x941A9E880538CCE3ULL,
		0x34A250A8A5094E92ULL,
		0x6BD2378CD7EE3F96ULL,
		0x49CB19777BF12D90ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0EE1CC451DEA004AULL,
		0xDE669C4806BC30ADULL,
		0x4E3338E95D3F935AULL,
		0x4253A4A506A7A201ULL,
		0xFB8FE58D28942A29ULL,
		0xFC4B641AF48DE335ULL,
		0x0000001272C65DDEULL,
		0x0000000000000000ULL
	}};
	shift = 26;
	printf("Test Case 34\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 34 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -34;
	} else {
		printf("Test Case 34 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDC36215767560C5DULL,
		0xEE28063E11C4907DULL,
		0x5319392B5C5386D1ULL,
		0x7435CAE9109881AFULL,
		0x01844DDE4CEA7C5CULL,
		0x41CA373726DCBBF0ULL,
		0x45FC58037302A423ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x83EEE1B10ABB3AB0ULL,
		0x368F714031F08E24ULL,
		0x0D7A98C9C95AE29CULL,
		0xE2E3A1AE574884C4ULL,
		0xDF800C226EF26753ULL,
		0x211A0E51B9B936E5ULL,
		0x00022FE2C01B9815ULL,
		0x0000000000000000ULL
	}};
	shift = 13;
	printf("Test Case 35\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 35 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -35;
	} else {
		printf("Test Case 35 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEB7ED64E99536CA9ULL,
		0x9AA1C9178F886910ULL,
		0xDD4ED69D4F41C8ADULL,
		0xB7616A3EE873D14CULL,
		0xB5C9DB9BC27AA31BULL,
		0x43095CA853FFDA06ULL,
		0xFC110FF1B6641D08ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD221D6FDAC9D32A6ULL,
		0x915B3543922F1F10ULL,
		0xA299BA9DAD3A9E83ULL,
		0x46376EC2D47DD0E7ULL,
		0xB40D6B93B73784F5ULL,
		0x3A108612B950A7FFULL,
		0x0001F8221FE36CC8ULL,
		0x0000000000000000ULL
	}};
	shift = 15;
	printf("Test Case 36\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 36 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -36;
	} else {
		printf("Test Case 36 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFE6C547DEF115401ULL,
		0xD6187226650EB583ULL,
		0x11A733680A049864ULL,
		0x74B8768BA2A59793ULL,
		0xCD44462849C391BCULL,
		0x6799A6DD5E7799B0ULL,
		0xF85DD13E5121C8EBULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x226650EB583FE6C5ULL,
		0x3680A049864D6187ULL,
		0x68BA2A5979311A73ULL,
		0x62849C391BC74B87ULL,
		0x6DD5E7799B0CD444ULL,
		0x13E5121C8EB6799AULL,
		0x00000000000F85DDULL,
		0x0000000000000000ULL
	}};
	shift = 44;
	printf("Test Case 37\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 37 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -37;
	} else {
		printf("Test Case 37 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA7EB32033BC8A2E2ULL,
		0xC150E8B803C6CB16ULL,
		0xCC3D39E697527869ULL,
		0x991B956FD0DE3AFBULL,
		0x44F5A7938FBD9986ULL,
		0xBDCBA3B756E3B27DULL,
		0x30C794972E82DB4DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x170078D962D4FD66ULL,
		0x3CD2EA4F0D382A1DULL,
		0xADFA1BC75F7987A7ULL,
		0xF271F7B330D32372ULL,
		0x76EADC764FA89EB4ULL,
		0x92E5D05B69B7B974ULL,
		0x00000000000618F2ULL,
		0x0000000000000000ULL
	}};
	shift = 43;
	printf("Test Case 38\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 38 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -38;
	} else {
		printf("Test Case 38 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0DE542D0D06A21B8ULL,
		0x9F9753F46D323747ULL,
		0x47DF5D2EFA9A852AULL,
		0xFAA5959970229038ULL,
		0x0BCCB53DF50EED93ULL,
		0x6C571353F7079663ULL,
		0xE652E7852745CA83ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFA36991BA386F2A1ULL,
		0x977D4D42954FCBA9ULL,
		0xCCB811481C23EFAEULL,
		0x9EFA8776C9FD52CAULL,
		0xA9FB83CB3185E65AULL,
		0xC293A2E541B62B89ULL,
		0x0000000000732973ULL,
		0x0000000000000000ULL
	}};
	shift = 41;
	printf("Test Case 39\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 39 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -39;
	} else {
		printf("Test Case 39 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x08163F441A4CC731ULL,
		0xDCCA763B50735E6DULL,
		0xF4C2786934097DDAULL,
		0x7803F726C37FA958ULL,
		0x69D2C82DDD041898ULL,
		0x660B825179817B92ULL,
		0x2FC973B49F88F3E9ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x08163F441A4CC731ULL,
		0xDCCA763B50735E6DULL,
		0xF4C2786934097DDAULL,
		0x7803F726C37FA958ULL,
		0x69D2C82DDD041898ULL,
		0x660B825179817B92ULL,
		0x2FC973B49F88F3E9ULL,
		0x0000000000000000ULL
	}};
	shift = 0;
	printf("Test Case 40\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 40 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -40;
	} else {
		printf("Test Case 40 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7BE035A2934608DBULL,
		0xA63D7ABCBEA5E7F6ULL,
		0xEBB68ACF1776F809ULL,
		0xCDA4307E5AB16024ULL,
		0xCFC7FD4B50C3C079ULL,
		0x143E1250298EB5D1ULL,
		0xBD88C2A4D10CD81FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEA5E7F67BE035A29ULL,
		0x776F809A63D7ABCBULL,
		0xAB16024EBB68ACF1ULL,
		0x0C3C079CDA4307E5ULL,
		0x98EB5D1CFC7FD4B5ULL,
		0x10CD81F143E12502ULL,
		0x0000000BD88C2A4DULL,
		0x0000000000000000ULL
	}};
	shift = 28;
	printf("Test Case 41\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 41 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -41;
	} else {
		printf("Test Case 41 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCDC2CB685F556C3CULL,
		0x6D43765EB91314E5ULL,
		0x9D6B143EADB2C5BEULL,
		0x99D4418D1D3D9E43ULL,
		0xFF431A13824D5A18ULL,
		0xE20687710D9299E7ULL,
		0x25757D9E3ADEB7ADULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x86ECBD722629CB9BULL,
		0xD6287D5B658B7CDAULL,
		0xA8831A3A7B3C873AULL,
		0x863427049AB43133ULL,
		0x0D0EE21B2533CFFEULL,
		0xEAFB3C75BD6F5BC4ULL,
		0x000000000000004AULL,
		0x0000000000000000ULL
	}};
	shift = 55;
	printf("Test Case 42\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 42 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -42;
	} else {
		printf("Test Case 42 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF3F6FE6C3E64EE72ULL,
		0xA049FF3E729B0590ULL,
		0xCC75BA1B2A832020ULL,
		0x7268226A4B2AAEB3ULL,
		0x9FD4BD246393A320ULL,
		0x91FE4E11D07866D2ULL,
		0xB2D7081EC93D4A90ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x21E7EDFCD87CC9DCULL,
		0x414093FE7CE5360BULL,
		0x6798EB7436550640ULL,
		0x40E4D044D496555DULL,
		0xA53FA97A48C72746ULL,
		0x2123FC9C23A0F0CDULL,
		0x0165AE103D927A95ULL,
		0x0000000000000000ULL
	}};
	shift = 7;
	printf("Test Case 43\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 43 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -43;
	} else {
		printf("Test Case 43 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4935D38B14F564D6ULL,
		0xE86230B799D7F394ULL,
		0x7AD591913798F013ULL,
		0x734ED5C111848E7AULL,
		0xB84AF0DC39155E42ULL,
		0x4EE7E4EB5505B478ULL,
		0x5C35EED19692BDCEULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x616F33AFE728926BULL,
		0x23226F31E027D0C4ULL,
		0xAB8223091CF4F5ABULL,
		0xE1B8722ABC84E69DULL,
		0xC9D6AA0B68F17095ULL,
		0xDDA32D257B9C9DCFULL,
		0x000000000000B86BULL,
		0x0000000000000000ULL
	}};
	shift = 47;
	printf("Test Case 44\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 44 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -44;
	} else {
		printf("Test Case 44 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x13864830FA9066C7ULL,
		0xD348F172FA320CBCULL,
		0x9DA1DCCDCB8595BFULL,
		0x80F27504B8EE075AULL,
		0xC04EB24E3DEDE2BCULL,
		0xFE209E33EA151F2CULL,
		0x2BDF7EE3AB0C12E1ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE09C324187D48336ULL,
		0xFE9A478B97D19065ULL,
		0xD4ED0EE66E5C2CADULL,
		0xE40793A825C7703AULL,
		0x6602759271EF6F15ULL,
		0x0FF104F19F50A8F9ULL,
		0x015EFBF71D586097ULL,
		0x0000000000000000ULL
	}};
	shift = 5;
	printf("Test Case 45\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 45 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -45;
	} else {
		printf("Test Case 45 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x260BDA542155EB06ULL,
		0x696DBAD7C8998425ULL,
		0x8742D100EB9EAC85ULL,
		0x9C561E554BE76620ULL,
		0xB542721992B4AF08ULL,
		0x0F47C1BDD3BA2C65ULL,
		0x4956AFF5F3050574ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x425260BDA542155EULL,
		0xC85696DBAD7C8998ULL,
		0x6208742D100EB9EAULL,
		0xF089C561E554BE76ULL,
		0xC65B542721992B4AULL,
		0x5740F47C1BDD3BA2ULL,
		0x0004956AFF5F3050ULL,
		0x0000000000000000ULL
	}};
	shift = 12;
	printf("Test Case 46\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 46 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -46;
	} else {
		printf("Test Case 46 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCBA12C7A2EEEF1BBULL,
		0x82DAB8F77BF224D5ULL,
		0xBA035FEBE42552EDULL,
		0xF3506D57ABB0B44CULL,
		0x50CD7B72BDEE496FULL,
		0x73B931189FAF2B57ULL,
		0xE5DA7944028884A1ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDDEFC893572E84B1ULL,
		0xAF90954BB60B6AE3ULL,
		0x5EAEC2D132E80D7FULL,
		0xCAF7B925BFCD41B5ULL,
		0x627EBCAD5D4335EDULL,
		0x100A221285CEE4C4ULL,
		0x00000000039769E5ULL,
		0x0000000000000000ULL
	}};
	shift = 38;
	printf("Test Case 47\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 47 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -47;
	} else {
		printf("Test Case 47 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x59827C0B8BF86EBFULL,
		0x4B10C1F7BE7D79D8ULL,
		0xACA3DD813B1867B6ULL,
		0x49AB98715794FF1EULL,
		0x415447B801893C91ULL,
		0x5D84092DC4A8BE4EULL,
		0xD9369E081A6F7118ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDEF9F5E7616609F0ULL,
		0x04EC619ED92C4307ULL,
		0xC55E53FC7AB28F76ULL,
		0xE00624F24526AE61ULL,
		0xB712A2F93905511EULL,
		0x2069BDC461761024ULL,
		0x000000000364DA78ULL,
		0x0000000000000000ULL
	}};
	shift = 38;
	printf("Test Case 48\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 48 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -48;
	} else {
		printf("Test Case 48 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x32F8490C8048238EULL,
		0x1B43CF51C6C2BE3BULL,
		0x25DBDC122EC51AF9ULL,
		0x3A3D4FB34C96CFF1ULL,
		0x7E97ABE21E1D3D74ULL,
		0x0F3F86507159C186ULL,
		0x12636FDFA59C8069ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCCBE1243201208E3ULL,
		0x46D0F3D471B0AF8EULL,
		0x4976F7048BB146BEULL,
		0x0E8F53ECD325B3FCULL,
		0x9FA5EAF887874F5DULL,
		0x43CFE1941C567061ULL,
		0x0498DBF7E967201AULL,
		0x0000000000000000ULL
	}};
	shift = 2;
	printf("Test Case 49\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 49 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -49;
	} else {
		printf("Test Case 49 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA2EA0FB1201D053DULL,
		0x9D96E35176523B72ULL,
		0xFD63BD43A440EF2BULL,
		0x5617CB0417337076ULL,
		0x7D87E01139F305CAULL,
		0xC3B5C604811CCC05ULL,
		0xB5668EAC5DF57A17ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x35176523B72A2EA0ULL,
		0xD43A440EF2B9D96EULL,
		0xB0417337076FD63BULL,
		0x01139F305CA5617CULL,
		0x604811CCC057D87EULL,
		0xEAC5DF57A17C3B5CULL,
		0x00000000000B5668ULL,
		0x0000000000000000ULL
	}};
	shift = 44;
	printf("Test Case 50\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 50 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -50;
	} else {
		printf("Test Case 50 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE93174BF03A2880CULL,
		0x526087DA35D8486FULL,
		0x018223A6B00FCEC2ULL,
		0x9971D7E701B60601ULL,
		0x33BBB479D12ED1A2ULL,
		0x1C1426D5D7099C05ULL,
		0xC1F11475D0F07EC9ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x87DA35D8486FE931ULL,
		0x23A6B00FCEC25260ULL,
		0xD7E701B606010182ULL,
		0xB479D12ED1A29971ULL,
		0x26D5D7099C0533BBULL,
		0x1475D0F07EC91C14ULL,
		0x000000000000C1F1ULL,
		0x0000000000000000ULL
	}};
	shift = 48;
	printf("Test Case 51\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 51 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -51;
	} else {
		printf("Test Case 51 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6091CDE66919AD37ULL,
		0x12E719ECB92E562AULL,
		0x8A67031FAEC8A36FULL,
		0xB2B38149F4783A2CULL,
		0x219F0210844DCFFCULL,
		0x085C51B5DD6B82C4ULL,
		0x42ECC80830577700ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x958A982473799A46ULL,
		0x28DBC4B9C67B2E4BULL,
		0x0E8B2299C0C7EBB2ULL,
		0x73FF2CACE0527D1EULL,
		0xE0B10867C0842113ULL,
		0xDDC00217146D775AULL,
		0x000010BB32020C15ULL,
		0x0000000000000000ULL
	}};
	shift = 18;
	printf("Test Case 52\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 52 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -52;
	} else {
		printf("Test Case 52 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x32D62826A9BF3B41ULL,
		0xE05B22C61D6FC5CCULL,
		0x9E6CA1C4F16206E2ULL,
		0xD672255200B44DEBULL,
		0x463D6FD01D0B9A29ULL,
		0x76E4EEF99EB4F986ULL,
		0x17590FA1D44CA186ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD6FC5CC32D62826AULL,
		0x16206E2E05B22C61ULL,
		0x0B44DEB9E6CA1C4FULL,
		0xD0B9A29D67225520ULL,
		0xEB4F986463D6FD01ULL,
		0x44CA18676E4EEF99ULL,
		0x000000017590FA1DULL,
		0x0000000000000000ULL
	}};
	shift = 28;
	printf("Test Case 53\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 53 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -53;
	} else {
		printf("Test Case 53 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x815119DFD98425C6ULL,
		0x890B71CF5D127A1AULL,
		0xFAC6C72E9D759B86ULL,
		0x34F579FA4285E309ULL,
		0x39F25F4BCC8C1F3EULL,
		0xA32A6ED00BD9434FULL,
		0x98AEC2231A967F31ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x71CF5D127A1A8151ULL,
		0xC72E9D759B86890BULL,
		0x79FA4285E309FAC6ULL,
		0x5F4BCC8C1F3E34F5ULL,
		0x6ED00BD9434F39F2ULL,
		0xC2231A967F31A32AULL,
		0x00000000000098AEULL,
		0x0000000000000000ULL
	}};
	shift = 48;
	printf("Test Case 54\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 54 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -54;
	} else {
		printf("Test Case 54 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEDFA5570E4AF948AULL,
		0x296049135E3F1148ULL,
		0x32CD799C017F729DULL,
		0x36ACAE70F8104016ULL,
		0x089C93C0DC119E82ULL,
		0xA320802DB1AE8738ULL,
		0x4258E0856B083B6AULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE2291DBF4AAE1C95ULL,
		0xEE53A52C09226BC7ULL,
		0x0802C659AF33802FULL,
		0x33D046D595CE1F02ULL,
		0xD0E7011392781B82ULL,
		0x076D54641005B635ULL,
		0x0000084B1C10AD61ULL,
		0x0000000000000000ULL
	}};
	shift = 19;
	printf("Test Case 55\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 55 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -55;
	} else {
		printf("Test Case 55 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC64047DDE7EAB2FDULL,
		0x627336F25F317D8FULL,
		0x2C9FA68636421EB5ULL,
		0x6D2BBA194BB55DAEULL,
		0xBB91E92712E981EFULL,
		0x0ECED407448E9BFAULL,
		0x0D5F3D916626F50BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3F19011F779FAACBULL,
		0xD589CCDBC97CC5F6ULL,
		0xB8B27E9A18D9087AULL,
		0xBDB4AEE8652ED576ULL,
		0xEAEE47A49C4BA607ULL,
		0x2C3B3B501D123A6FULL,
		0x00357CF645989BD4ULL,
		0x0000000000000000ULL
	}};
	shift = 6;
	printf("Test Case 56\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 56 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -56;
	} else {
		printf("Test Case 56 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5EEC2F2A53AC653AULL,
		0x795BAAB967504F57ULL,
		0x281F6EDC1322E246ULL,
		0x057FBE5080849B71ULL,
		0x4E7AD7068DE96CB3ULL,
		0x79D36F4E9D4B9412ULL,
		0xEC0155C027478AECULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEAAE59D413D5D7BBULL,
		0xDBB704C8B8919E56ULL,
		0xEF94202126DC4A07ULL,
		0xB5C1A37A5B2CC15FULL,
		0xDBD3A752E504939EULL,
		0x557009D1E2BB1E74ULL,
		0x0000000000003B00ULL,
		0x0000000000000000ULL
	}};
	shift = 50;
	printf("Test Case 57\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 57 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -57;
	} else {
		printf("Test Case 57 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3BECEDD7E2D32B6FULL,
		0xF8072146CC3CD017ULL,
		0x06F7BF94B118AA8FULL,
		0xD335A5BA36D978D3ULL,
		0x1A45732FFB54D734ULL,
		0x440F945D73B0055AULL,
		0xA7F5EB6966FFAFB4ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC851B30F3405CEFBULL,
		0xEFE52C462AA3FE01ULL,
		0x696E8DB65E34C1BDULL,
		0x5CCBFED535CD34CDULL,
		0xE5175CEC01568691ULL,
		0x7ADA59BFEBED1103ULL,
		0x00000000000029FDULL,
		0x0000000000000000ULL
	}};
	shift = 50;
	printf("Test Case 58\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 58 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -58;
	} else {
		printf("Test Case 58 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6FDB047559268D7EULL,
		0x2C7C4BCFD7F91538ULL,
		0x724CAE5666EC0773ULL,
		0x0737160FA13F77FAULL,
		0xCE594903E554E361ULL,
		0x25EA3DEFDB9CC344ULL,
		0x6BAA50C845DA5078ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA70DFB608EAB24D1ULL,
		0xEE658F8979FAFF22ULL,
		0xFF4E4995CACCDD80ULL,
		0x6C20E6E2C1F427EEULL,
		0x6899CB29207CAA9CULL,
		0x0F04BD47BDFB7398ULL,
		0x000D754A1908BB4AULL,
		0x0000000000000000ULL
	}};
	shift = 11;
	printf("Test Case 59\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 59 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -59;
	} else {
		printf("Test Case 59 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x228D368A56C8BEAFULL,
		0xFE2A6B6640010EB1ULL,
		0x15E3F9B68BE60947ULL,
		0x4C3057350B4A86EDULL,
		0xE519A48BDC2A0191ULL,
		0x5630F6B38A716608ULL,
		0xCC9990538692781DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAD9900043AC48A34ULL,
		0xE6DA2F98251FF8A9ULL,
		0x5CD42D2A1BB4578FULL,
		0x922F70A8064530C1ULL,
		0xDACE29C598239466ULL,
		0x414E1A49E07558C3ULL,
		0x0000000000033266ULL,
		0x0000000000000000ULL
	}};
	shift = 46;
	printf("Test Case 60\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 60 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -60;
	} else {
		printf("Test Case 60 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7DED84E3CD4F540CULL,
		0x2568DAE45981E30AULL,
		0x7AF4C20822392A76ULL,
		0xE38713BA3ADA976CULL,
		0x98B2B0D2423AAC54ULL,
		0x8327B14E284E2CD1ULL,
		0x098E002AB4B1953AULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5C8B303C614FBDB0ULL,
		0x410447254EC4AD1BULL,
		0x77475B52ED8F5E98ULL,
		0x1A4847558A9C70E2ULL,
		0x29C509C59A331656ULL,
		0x05569632A75064F6ULL,
		0x00000000000131C0ULL,
		0x0000000000000000ULL
	}};
	shift = 43;
	printf("Test Case 61\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 61 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -61;
	} else {
		printf("Test Case 61 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8499E44E7446952AULL,
		0xE7DF4A14DB360B1FULL,
		0x8D692EF6CDC94259ULL,
		0x5AD8EE438B66EC8FULL,
		0x79D2A2CAB976039BULL,
		0xB191A632123D1FA3ULL,
		0xEF558EE403C05F45ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2C7E12679139D11AULL,
		0x09679F7D28536CD8ULL,
		0xB23E35A4BBDB3725ULL,
		0x0E6D6B63B90E2D9BULL,
		0x7E8DE74A8B2AE5D8ULL,
		0x7D16C64698C848F4ULL,
		0x0003BD563B900F01ULL,
		0x0000000000000000ULL
	}};
	shift = 14;
	printf("Test Case 62\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 62 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -62;
	} else {
		printf("Test Case 62 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x046727137D2DE137ULL,
		0x5DE2149F2FFA84EDULL,
		0xDED373CA8AF97AD0ULL,
		0xAF938A6635126460ULL,
		0xE1640D1F6391C1C8ULL,
		0xCA460BC7CEECA8FDULL,
		0x032E55F315BA4B02ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4119C9C4DF4B784DULL,
		0x17788527CBFEA13BULL,
		0x37B4DCF2A2BE5EB4ULL,
		0x2BE4E2998D449918ULL,
		0x78590347D8E47072ULL,
		0xB29182F1F3BB2A3FULL,
		0x00CB957CC56E92C0ULL,
		0x0000000000000000ULL
	}};
	shift = 2;
	printf("Test Case 63\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 63 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -63;
	} else {
		printf("Test Case 63 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x864D4D240D33287FULL,
		0xF54E82E4A372D447ULL,
		0xBF72934D39A4DB08ULL,
		0xD12AF384F0886EA3ULL,
		0x80269EC26507C144ULL,
		0xA0BF150AC1161A8BULL,
		0x163D85387C578AA0ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x372D447864D4D240ULL,
		0x9A4DB08F54E82E4AULL,
		0x0886EA3BF72934D3ULL,
		0x507C144D12AF384FULL,
		0x1161A8B80269EC26ULL,
		0xC578AA0A0BF150ACULL,
		0x0000000163D85387ULL,
		0x0000000000000000ULL
	}};
	shift = 28;
	printf("Test Case 64\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 64 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -64;
	} else {
		printf("Test Case 64 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9425A851DD32E88FULL,
		0x1939DE7148AB501CULL,
		0x757FD78FED1A2EBDULL,
		0x4ED7C22F98154D40ULL,
		0x967D910BE054816FULL,
		0x999079599FD6E535ULL,
		0x7D362D53B0FB1FE0ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD40725096A14774CULL,
		0x8BAF464E779C522AULL,
		0x53501D5FF5E3FB46ULL,
		0x205BD3B5F08BE605ULL,
		0xB94D659F6442F815ULL,
		0xC7F826641E5667F5ULL,
		0x00001F4D8B54EC3EULL,
		0x0000000000000000ULL
	}};
	shift = 18;
	printf("Test Case 65\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 65 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -65;
	} else {
		printf("Test Case 65 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x89C413E5C5B391D3ULL,
		0x1441EB9285EBAE34ULL,
		0x8F07006E4C00AD97ULL,
		0x1B7357D506FB9976ULL,
		0x3F8E1569134699C9ULL,
		0x37B74BC823D41ED1ULL,
		0x5E59E6DAEBC5C556ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEB9285EBAE3489C4ULL,
		0x006E4C00AD971441ULL,
		0x57D506FB99768F07ULL,
		0x1569134699C91B73ULL,
		0x4BC823D41ED13F8EULL,
		0xE6DAEBC5C55637B7ULL,
		0x0000000000005E59ULL,
		0x0000000000000000ULL
	}};
	shift = 48;
	printf("Test Case 66\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 66 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -66;
	} else {
		printf("Test Case 66 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5E478C009A747207ULL,
		0xC3AD75472FAC3D04ULL,
		0x56167DDA505482ACULL,
		0xD0645921A8A1D7E2ULL,
		0x198583EDBB82737DULL,
		0xF0003F50EFFDF142ULL,
		0xDEB0EB8AAF5DCAFAULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE822F23C6004D3A3ULL,
		0x15661D6BAA397D61ULL,
		0xBF12B0B3EED282A4ULL,
		0x9BEE8322C90D450EULL,
		0x8A10CC2C1F6DDC13ULL,
		0x57D78001FA877FEFULL,
		0x0006F5875C557AEEULL,
		0x0000000000000000ULL
	}};
	shift = 13;
	printf("Test Case 67\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 67 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -67;
	} else {
		printf("Test Case 67 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE0D138693F4B907CULL,
		0x69AA25316D6C9A57ULL,
		0x5DA785032C016C8FULL,
		0x564CF12918A11334ULL,
		0x46F8C14F87ABB5AFULL,
		0x6584CE0E7D09042CULL,
		0xD2D3AD117C30F636ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3544A62DAD934AFCULL,
		0xB4F0A065802D91EDULL,
		0xC99E25231422668BULL,
		0xDF1829F0F576B5EAULL,
		0xB099C1CFA1208588ULL,
		0x5A75A22F861EC6CCULL,
		0x000000000000001AULL,
		0x0000000000000000ULL
	}};
	shift = 59;
	printf("Test Case 68\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 68 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -68;
	} else {
		printf("Test Case 68 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA0A4D2EE8021D68DULL,
		0x8DA12A653CB7F59DULL,
		0x48D517C2E017DF82ULL,
		0xCE6FB54957EDEA4BULL,
		0xAEF1787607595C9FULL,
		0x8A69C814B03DC20FULL,
		0xD8A9375D75D3ED32ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x653CB7F59DA0A4D2ULL,
		0xC2E017DF828DA12AULL,
		0x4957EDEA4B48D517ULL,
		0x7607595C9FCE6FB5ULL,
		0x14B03DC20FAEF178ULL,
		0x5D75D3ED328A69C8ULL,
		0x0000000000D8A937ULL,
		0x0000000000000000ULL
	}};
	shift = 40;
	printf("Test Case 69\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 69 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -69;
	} else {
		printf("Test Case 69 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB312A2CAEB758AF4ULL,
		0xAE11F5892C82E3E2ULL,
		0x191C1ED63A018991ULL,
		0xFCDC47E6AD264F6AULL,
		0x6CB20B4DD743D353ULL,
		0x0ED2AA3DB69616BAULL,
		0x0E84AFF86C3D347DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x964171F159895165ULL,
		0x1D00C4C8D708FAC4ULL,
		0x569327B50C8E0F6BULL,
		0xEBA1E9A9FE6E23F3ULL,
		0xDB4B0B5D365905A6ULL,
		0x361E9A3E8769551EULL,
		0x00000000074257FCULL,
		0x0000000000000000ULL
	}};
	shift = 33;
	printf("Test Case 70\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 70 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -70;
	} else {
		printf("Test Case 70 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC7BF3F5455FBD32DULL,
		0x53D6646E72DA39D1ULL,
		0x36C68C5BB613F03FULL,
		0x8FDED386B007D7B1ULL,
		0x3BA2716E408B1109ULL,
		0x9B4ADDC04A010447ULL,
		0xB887F3F42E926435ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8E3DF9FAA2AFDE99ULL,
		0xFA9EB3237396D1CEULL,
		0x89B63462DDB09F81ULL,
		0x4C7EF69C35803EBDULL,
		0x39DD138B72045888ULL,
		0xACDA56EE02500822ULL,
		0x05C43F9FA1749321ULL,
		0x0000000000000000ULL
	}};
	shift = 5;
	printf("Test Case 71\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 71 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -71;
	} else {
		printf("Test Case 71 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x325D4D61609FE617ULL,
		0x8FA814514D3D35F7ULL,
		0xFFC7B6A322FE7262ULL,
		0xDD88FC19FE628D2BULL,
		0xD68E0AED1E455950ULL,
		0xAF97BA803788C4C3ULL,
		0xB612D9C35B911037ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x14D3D35F7325D4D6ULL,
		0x322FE72628FA8145ULL,
		0x9FE628D2BFFC7B6AULL,
		0xD1E455950DD88FC1ULL,
		0x03788C4C3D68E0AEULL,
		0x35B911037AF97BA8ULL,
		0x000000000B612D9CULL,
		0x0000000000000000ULL
	}};
	shift = 36;
	printf("Test Case 72\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 72 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -72;
	} else {
		printf("Test Case 72 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF9F180C35E5AA5C4ULL,
		0x8D6F4A5AEF27441EULL,
		0x92563CF3BAD9BE72ULL,
		0x310003F79367844EULL,
		0x9936C0D2C58DD3DAULL,
		0xB4B2A9930CD93959ULL,
		0x2265BBD1205A4E26ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF27441EF9F180C35ULL,
		0xAD9BE728D6F4A5AEULL,
		0x367844E92563CF3BULL,
		0x58DD3DA310003F79ULL,
		0xCD939599936C0D2CULL,
		0x05A4E26B4B2A9930ULL,
		0x00000002265BBD12ULL,
		0x0000000000000000ULL
	}};
	shift = 28;
	printf("Test Case 73\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 73 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -73;
	} else {
		printf("Test Case 73 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF82E901033625F72ULL,
		0x9B27CBD4AC268E7DULL,
		0xC26658ADD782D393ULL,
		0x2D19D6ECE66782FAULL,
		0xDDCC68AE80B52B9FULL,
		0xC3E40801BB715465ULL,
		0x62D619A9B3967808ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x97A9584D1CFBF05DULL,
		0xB15BAF05A727364FULL,
		0xADD9CCCF05F584CCULL,
		0xD15D016A573E5A33ULL,
		0x100376E2A8CBBB98ULL,
		0x3353672CF01187C8ULL,
		0x000000000000C5ACULL,
		0x0000000000000000ULL
	}};
	shift = 47;
	printf("Test Case 74\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 74 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -74;
	} else {
		printf("Test Case 74 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xABD49AD001CD5817ULL,
		0xB3746A60687A84DEULL,
		0x26B7FA5371AE6D4BULL,
		0x54279ED5155BFF94ULL,
		0x1E45351C14EE3E60ULL,
		0x9D7DB98D73FDAC52ULL,
		0xD4C4DCA1D959E937ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x66E8D4C0D0F509BDULL,
		0x4D6FF4A6E35CDA97ULL,
		0xA84F3DAA2AB7FF28ULL,
		0x3C8A6A3829DC7CC0ULL,
		0x3AFB731AE7FB58A4ULL,
		0xA989B943B2B3D26FULL,
		0x0000000000000001ULL,
		0x0000000000000000ULL
	}};
	shift = 63;
	printf("Test Case 75\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 75 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -75;
	} else {
		printf("Test Case 75 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x669AC47495294205ULL,
		0x025EF1BFED5D0325ULL,
		0xABD98A7579197F57ULL,
		0x0066FA62DE27EA77ULL,
		0xA1ABAF19DC30465BULL,
		0x586AADCAF4D29A29ULL,
		0xBF23747A31535006ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x64ACD3588E92A528ULL,
		0xEAE04BDE37FDABA0ULL,
		0x4EF57B314EAF232FULL,
		0xCB600CDF4C5BC4FDULL,
		0x45343575E33B8608ULL,
		0x00CB0D55B95E9A53ULL,
		0x0017E46E8F462A6AULL,
		0x0000000000000000ULL
	}};
	shift = 11;
	printf("Test Case 76\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 76 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -76;
	} else {
		printf("Test Case 76 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x10B527082A5FFAC7ULL,
		0x77204CE60FC58BF3ULL,
		0xBD74D51FF00EA123ULL,
		0xEA2B03819422053BULL,
		0xC4CECE9F549D794AULL,
		0x7DEFB30F17A9798BULL,
		0xD4C286103B34F97BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5F9885A9384152FFULL,
		0x091BB90267307E2CULL,
		0x29DDEBA6A8FF8075ULL,
		0xCA5751581C0CA110ULL,
		0xCC5E267674FAA4EBULL,
		0xCBDBEF7D9878BD4BULL,
		0x0006A6143081D9A7ULL,
		0x0000000000000000ULL
	}};
	shift = 13;
	printf("Test Case 77\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 77 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -77;
	} else {
		printf("Test Case 77 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5F701BDFF3EF070BULL,
		0xB639E8912C51811FULL,
		0x8B4FE542E77D0587ULL,
		0x1B28E8BE3F8BC34FULL,
		0xA5014CE2CB620D82ULL,
		0xF754CB207D7002C7ULL,
		0x0818536C47FE589DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2C51811F5F701BDFULL,
		0xE77D0587B639E891ULL,
		0x3F8BC34F8B4FE542ULL,
		0xCB620D821B28E8BEULL,
		0x7D7002C7A5014CE2ULL,
		0x47FE589DF754CB20ULL,
		0x000000000818536CULL,
		0x0000000000000000ULL
	}};
	shift = 32;
	printf("Test Case 78\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 78 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -78;
	} else {
		printf("Test Case 78 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBEC1A4AF73A8D13AULL,
		0x65998DCA6A934B80ULL,
		0x8E578B13C44FA68CULL,
		0x1A25183F3A16FB50ULL,
		0x6554CEC7A33C767CULL,
		0x13830AE7B6BCCE17ULL,
		0x4EAD5F75D0D4ACCEULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4B80BEC1A4AF73A8ULL,
		0xA68C65998DCA6A93ULL,
		0xFB508E578B13C44FULL,
		0x767C1A25183F3A16ULL,
		0xCE176554CEC7A33CULL,
		0xACCE13830AE7B6BCULL,
		0x00004EAD5F75D0D4ULL,
		0x0000000000000000ULL
	}};
	shift = 16;
	printf("Test Case 79\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 79 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -79;
	} else {
		printf("Test Case 79 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB3BA952E5D61F11EULL,
		0x6B30F334C36F1F44ULL,
		0x2BCC19AEFDE5E689ULL,
		0x2F81945D14C0A962ULL,
		0x15DAB34C4CC0D4A3ULL,
		0xC5D66FD442726025ULL,
		0xC9A3525C4C8CEDB1ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF334C36F1F44B3BAULL,
		0x19AEFDE5E6896B30ULL,
		0x945D14C0A9622BCCULL,
		0xB34C4CC0D4A32F81ULL,
		0x6FD44272602515DAULL,
		0x525C4C8CEDB1C5D6ULL,
		0x000000000000C9A3ULL,
		0x0000000000000000ULL
	}};
	shift = 48;
	printf("Test Case 80\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 80 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -80;
	} else {
		printf("Test Case 80 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x373409D370875B5DULL,
		0x29EAE7794BCD378EULL,
		0x23D6FEDA6CEB52FAULL,
		0x8F86E9BB12CB4764ULL,
		0xB018CF9B44ECA015ULL,
		0x59DFA4DC501862B0ULL,
		0xD0BD498B4543C400ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD378E373409D3708ULL,
		0xB52FA29EAE7794BCULL,
		0xB476423D6FEDA6CEULL,
		0xCA0158F86E9BB12CULL,
		0x862B0B018CF9B44EULL,
		0x3C40059DFA4DC501ULL,
		0x00000D0BD498B454ULL,
		0x0000000000000000ULL
	}};
	shift = 20;
	printf("Test Case 81\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 81 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -81;
	} else {
		printf("Test Case 81 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7C538DF023DEE8EFULL,
		0x379D2D4F8069726FULL,
		0xA5ED8AB5C9DCCB57ULL,
		0x2CBE69FD20088166ULL,
		0x4B7987803429BD16ULL,
		0x64F2CBF3A420618CULL,
		0xFD824800CBFE2596ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDF14E37C08F7BA3BULL,
		0xCDE74B53E01A5C9BULL,
		0xA97B62AD727732D5ULL,
		0x8B2F9A7F48022059ULL,
		0x12DE61E00D0A6F45ULL,
		0x993CB2FCE9081863ULL,
		0x3F60920032FF8965ULL,
		0x0000000000000000ULL
	}};
	shift = 2;
	printf("Test Case 82\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 82 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -82;
	} else {
		printf("Test Case 82 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8C14200D8114A99CULL,
		0x214E9D8F28A0F1F0ULL,
		0xE1465AA7FFCFE98AULL,
		0x132EDD6A3198A0BAULL,
		0x4FFBAD646231DF37ULL,
		0xD2C5DFA146457F65ULL,
		0x98AC57090891F120ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE3E11828401B0229ULL,
		0xD314429D3B1E5141ULL,
		0x4175C28CB54FFF9FULL,
		0xBE6E265DBAD46331ULL,
		0xFECA9FF75AC8C463ULL,
		0xE241A58BBF428C8AULL,
		0x00013158AE121123ULL,
		0x0000000000000000ULL
	}};
	shift = 15;
	printf("Test Case 83\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 83 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -83;
	} else {
		printf("Test Case 83 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8E44463F9BA529A9ULL,
		0x49C3985632408F8BULL,
		0x6129B55D659D99ECULL,
		0xA41904EB81ACE932ULL,
		0x686C7D4E6DFD7253ULL,
		0x97FB1C92CC88CF11ULL,
		0x40B0026D0D9C916EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8730AC64811F171CULL,
		0x536ABACB3B33D893ULL,
		0x3209D70359D264C2ULL,
		0xD8FA9CDBFAE4A748ULL,
		0xF6392599119E22D0ULL,
		0x6004DA1B3922DD2FULL,
		0x0000000000000081ULL,
		0x0000000000000000ULL
	}};
	shift = 55;
	printf("Test Case 84\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 84 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -84;
	} else {
		printf("Test Case 84 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC5316E76A180316AULL,
		0xDE33ABB0B5C88EC6ULL,
		0x271FFC217248C175ULL,
		0x62750C6188D09270ULL,
		0xC83D094DF51E9157ULL,
		0x6010EDF6D8F8EF60ULL,
		0x206DA779F54CA9CAULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8D8A62DCED430062ULL,
		0xEBBC6757616B911DULL,
		0xE04E3FF842E49182ULL,
		0xAEC4EA18C311A124ULL,
		0xC1907A129BEA3D22ULL,
		0x94C021DBEDB1F1DEULL,
		0x0040DB4EF3EA9953ULL,
		0x0000000000000000ULL
	}};
	shift = 7;
	printf("Test Case 85\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 85 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -85;
	} else {
		printf("Test Case 85 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x57AE58A871F9BFBEULL,
		0xB2A876CD707A18FDULL,
		0xA42ECC375E8C356AULL,
		0x7C5333417B271AD0ULL,
		0xC4FB93519DADDD88ULL,
		0x90656EA2F2FA1AB2ULL,
		0x243B60415658C482ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDB35C1E863F55EB9ULL,
		0x30DD7A30D5AACAA1ULL,
		0xCD05EC9C6B4290BBULL,
		0x4D4676B77621F14CULL,
		0xBA8BCBE86ACB13EEULL,
		0x81055963120A4195ULL,
		0x00000000000090EDULL,
		0x0000000000000000ULL
	}};
	shift = 46;
	printf("Test Case 86\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 86 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -86;
	} else {
		printf("Test Case 86 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8C1368F909B105E5ULL,
		0x06CF75DA96447D8FULL,
		0x2B621EA2C26242BEULL,
		0xC680AB50EA7A6587ULL,
		0xB7576ABAE7F13C26ULL,
		0x6D1CDAC1F9EBB95BULL,
		0x2C551E860EB85043ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8C1368F909B105E5ULL,
		0x06CF75DA96447D8FULL,
		0x2B621EA2C26242BEULL,
		0xC680AB50EA7A6587ULL,
		0xB7576ABAE7F13C26ULL,
		0x6D1CDAC1F9EBB95BULL,
		0x2C551E860EB85043ULL,
		0x0000000000000000ULL
	}};
	shift = 0;
	printf("Test Case 87\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 87 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -87;
	} else {
		printf("Test Case 87 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x95807A285C7BC8B9ULL,
		0x5CDA91AD86F73436ULL,
		0x0B67131950917156ULL,
		0x897E51ABC46125AFULL,
		0xB276ACCEA834B2C8ULL,
		0x8088E309C40EF115ULL,
		0x23770427A1F3C8BAULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6A46B61BDCD0DA56ULL,
		0x9C4C654245C55973ULL,
		0xF946AF118496BC2DULL,
		0xDAB33AA0D2CB2225ULL,
		0x238C27103BC456C9ULL,
		0xDC109E87CF22EA02ULL,
		0x000000000000008DULL,
		0x0000000000000000ULL
	}};
	shift = 54;
	printf("Test Case 88\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 88 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -88;
	} else {
		printf("Test Case 88 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x47214424D89D8F54ULL,
		0x78F809FBD85BC21FULL,
		0x2B40545EDC8E0009ULL,
		0xA57A9AE7E1116FD3ULL,
		0xFFF6B67A2B60E672ULL,
		0xCB9866A729F7AB52ULL,
		0x9AB073CC89015F10ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0FA390A2126C4EC7ULL,
		0x04BC7C04FDEC2DE1ULL,
		0xE995A02A2F6E4700ULL,
		0x3952BD4D73F088B7ULL,
		0xA97FFB5B3D15B073ULL,
		0x8865CC335394FBD5ULL,
		0x004D5839E64480AFULL,
		0x0000000000000000ULL
	}};
	shift = 9;
	printf("Test Case 89\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 89 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -89;
	} else {
		printf("Test Case 89 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x129B0BA663C18292ULL,
		0xAF3A1829F0EBB841ULL,
		0xB7BB131728FCEBBEULL,
		0x759BC097CE5F0021ULL,
		0xBF8693569D56945BULL,
		0x3E3C69DCF1F78142ULL,
		0xD630946A3A7D1CA8ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x743053E1D7708225ULL,
		0x76262E51F9D77D5EULL,
		0x37812F9CBE00436FULL,
		0x0D26AD3AAD28B6EBULL,
		0x78D3B9E3EF02857FULL,
		0x6128D474FA39507CULL,
		0x00000000000001ACULL,
		0x0000000000000000ULL
	}};
	shift = 55;
	printf("Test Case 90\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 90 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -90;
	} else {
		printf("Test Case 90 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD314A6418C07833BULL,
		0xCEC0D0DABE829F98ULL,
		0xD353BC27DFD91CD2ULL,
		0x20363576F0BD5334ULL,
		0x9FA5896B9BEE6435ULL,
		0x0F0035E4FB63B3FAULL,
		0x83BF7D78AB718791ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBE829F98D314A641ULL,
		0xDFD91CD2CEC0D0DAULL,
		0xF0BD5334D353BC27ULL,
		0x9BEE643520363576ULL,
		0xFB63B3FA9FA5896BULL,
		0xAB7187910F0035E4ULL,
		0x0000000083BF7D78ULL,
		0x0000000000000000ULL
	}};
	shift = 32;
	printf("Test Case 91\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 91 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -91;
	} else {
		printf("Test Case 91 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2C3E465D7687991EULL,
		0x0319A540E66ABE12ULL,
		0x1275D5C973184584ULL,
		0x6D3E342C6D801489ULL,
		0x44F4455DE772C546ULL,
		0xBF8C3D823C747EA7ULL,
		0x60211E01D4B50AA0ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0C66950399AAF848ULL,
		0x49D75725CC611610ULL,
		0xB4F8D0B1B6005224ULL,
		0x13D115779DCB1519ULL,
		0xFE30F608F1D1FA9DULL,
		0x8084780752D42A82ULL,
		0x0000000000000001ULL,
		0x0000000000000000ULL
	}};
	shift = 62;
	printf("Test Case 92\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 92 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -92;
	} else {
		printf("Test Case 92 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0C236040FDE97DB9ULL,
		0x117D35661F134EACULL,
		0xC0FF0CA92D7D1A03ULL,
		0xB2EBCE163C6828F7ULL,
		0x54DC3CE717F4ED68ULL,
		0x820096B538E4A6E9ULL,
		0x7200C637AEA83695ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4D5987C4D3AB0308ULL,
		0xC32A4B5F4680C45FULL,
		0xF3858F1A0A3DF03FULL,
		0x0F39C5FD3B5A2CBAULL,
		0x25AD4E3929BA5537ULL,
		0x318DEBAA0DA56080ULL,
		0x0000000000001C80ULL,
		0x0000000000000000ULL
	}};
	shift = 50;
	printf("Test Case 93\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 93 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -93;
	} else {
		printf("Test Case 93 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x61F467ED6740FFC1ULL,
		0x1526DADA1EA6DECEULL,
		0x668B6FF733FB92B3ULL,
		0x1BBF54E27DDF848BULL,
		0xE8E6A0EC9F8E7F67ULL,
		0x71308ABA1F770AC3ULL,
		0xB55D8EB9C48D0EF8ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB5B43D4DBD9CC3E8ULL,
		0xDFEE67F725662A4DULL,
		0xA9C4FBBF0916CD16ULL,
		0x41D93F1CFECE377EULL,
		0x15743EEE1587D1CDULL,
		0x1D73891A1DF0E261ULL,
		0x0000000000016ABBULL,
		0x0000000000000000ULL
	}};
	shift = 47;
	printf("Test Case 94\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 94 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -94;
	} else {
		printf("Test Case 94 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2635FE210C3B6103ULL,
		0x46ACFB4A9C675F69ULL,
		0x6C941A82D87C6EC8ULL,
		0x8CC26096537308D5ULL,
		0x3131C12D9D04548FULL,
		0x94B6DFDA243EA387ULL,
		0x38E609AFE9880E9EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x675F692635FE210CULL,
		0x7C6EC846ACFB4A9CULL,
		0x7308D56C941A82D8ULL,
		0x04548F8CC2609653ULL,
		0x3EA3873131C12D9DULL,
		0x880E9E94B6DFDA24ULL,
		0x00000038E609AFE9ULL,
		0x0000000000000000ULL
	}};
	shift = 24;
	printf("Test Case 95\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 95 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -95;
	} else {
		printf("Test Case 95 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8B69810595EBDCBBULL,
		0x5B1D8D75D37B40DBULL,
		0x0E8B3D7F0A7CBACFULL,
		0x1693024CD6CD0D13ULL,
		0xDEC7395BA01E9D37ULL,
		0xEAD25649784DDA6CULL,
		0x1CEEB81B4AA2ECF8ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6F681B716D3020B2ULL,
		0x4F9759EB63B1AEBAULL,
		0xD9A1A261D167AFE1ULL,
		0x03D3A6E2D260499AULL,
		0x09BB4D9BD8E72B74ULL,
		0x545D9F1D5A4AC92FULL,
		0x000000039DD70369ULL,
		0x0000000000000000ULL
	}};
	shift = 27;
	printf("Test Case 96\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 96 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -96;
	} else {
		printf("Test Case 96 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x84414143B2D39373ULL,
		0x9724D0877FC71FD1ULL,
		0xE0D18B8D9985C1CEULL,
		0xFA3B46F2AF9198B3ULL,
		0xA961003CB534FC88ULL,
		0x949DB5B015D18E62ULL,
		0x68C7CB281149BC66ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1FD184414143B2D3ULL,
		0xC1CE9724D0877FC7ULL,
		0x98B3E0D18B8D9985ULL,
		0xFC88FA3B46F2AF91ULL,
		0x8E62A961003CB534ULL,
		0xBC66949DB5B015D1ULL,
		0x000068C7CB281149ULL,
		0x0000000000000000ULL
	}};
	shift = 16;
	printf("Test Case 97\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 97 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -97;
	} else {
		printf("Test Case 97 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x95B8749E39AB8947ULL,
		0x80EB24CF68EAC225ULL,
		0xE2444972FCAA2B1EULL,
		0x4C62650165625D99ULL,
		0x7216FE69CFC0DAF2ULL,
		0x67766AE00478C9D1ULL,
		0x154BA1550C53150AULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB2B70E93C7357128ULL,
		0xD01D6499ED1D5844ULL,
		0x3C48892E5F954563ULL,
		0x498C4CA02CAC4BB3ULL,
		0x2E42DFCD39F81B5EULL,
		0x4CEECD5C008F193AULL,
		0x02A9742AA18A62A1ULL,
		0x0000000000000000ULL
	}};
	shift = 3;
	printf("Test Case 98\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 98 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -98;
	} else {
		printf("Test Case 98 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDA1CB491464C2DFAULL,
		0xC7A75CC2DD939664ULL,
		0x61983014D70F5C34ULL,
		0x259240D2ECD81E09ULL,
		0x3C29ACA221145D86ULL,
		0x0216FDF8FCAFC56AULL,
		0x02B5EFF1CE6347D0ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x39664DA1CB491464ULL,
		0xF5C34C7A75CC2DD9ULL,
		0x81E0961983014D70ULL,
		0x45D86259240D2ECDULL,
		0xFC56A3C29ACA2211ULL,
		0x347D00216FDF8FCAULL,
		0x0000002B5EFF1CE6ULL,
		0x0000000000000000ULL
	}};
	shift = 20;
	printf("Test Case 99\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 99 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -99;
	} else {
		printf("Test Case 99 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x81E9C9553F591AADULL,
		0xDC90FAD184BBEB27ULL,
		0x606A436069C0F5C2ULL,
		0x137802CF2D4AEE27ULL,
		0x3AD288D2FE31D5B6ULL,
		0x51033613594B1608ULL,
		0xF93D8C41ECDA09B8ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA30977D64F03D392ULL,
		0xC0D381EB85B921F5ULL,
		0x9E5A95DC4EC0D486ULL,
		0xA5FC63AB6C26F005ULL,
		0x26B2962C1075A511ULL,
		0x83D9B41370A2066CULL,
		0x0000000001F27B18ULL,
		0x0000000000000000ULL
	}};
	shift = 39;
	printf("Test Case 100\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 100 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -100;
	} else {
		printf("Test Case 100 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA500C10BFA7253F8ULL,
		0xF095C14F819B5B99ULL,
		0x1BA2F6BFAFC25514ULL,
		0xD7C21294E5F48C0DULL,
		0x2E3A26885C85A84FULL,
		0x64B008FF036BB383ULL,
		0x27196EFED6A05CDAULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x095C14F819B5B99AULL,
		0xBA2F6BFAFC25514FULL,
		0x7C21294E5F48C0D1ULL,
		0xE3A26885C85A84FDULL,
		0x4B008FF036BB3832ULL,
		0x7196EFED6A05CDA6ULL,
		0x0000000000000002ULL,
		0x0000000000000000ULL
	}};
	shift = 60;
	printf("Test Case 101\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 101 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -101;
	} else {
		printf("Test Case 101 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDD29CE945AA47B24ULL,
		0x31E28F01567D11CBULL,
		0x03F1A7E4A6462E79ULL,
		0x58485291691FADA7ULL,
		0xAAEA5CE90850DC1DULL,
		0xCFAF45777E8152CCULL,
		0xFCFA9B1F79D09444ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF01567D11CBDD29CULL,
		0x7E4A6462E7931E28ULL,
		0x291691FADA703F1AULL,
		0xCE90850DC1D58485ULL,
		0x5777E8152CCAAEA5ULL,
		0xB1F79D09444CFAF4ULL,
		0x00000000000FCFA9ULL,
		0x0000000000000000ULL
	}};
	shift = 44;
	printf("Test Case 102\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 102 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -102;
	} else {
		printf("Test Case 102 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x01EA312215D6AF05ULL,
		0x285E5F7ED12C7A58ULL,
		0x6D9EC48841F99893ULL,
		0x9080CFBC2454A621ULL,
		0x05DF8DC693BFCA73ULL,
		0x37794852E2271C8AULL,
		0xFD5789F7BA1F5A87ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7ED12C7A5801EA31ULL,
		0x8841F99893285E5FULL,
		0xBC2454A6216D9EC4ULL,
		0xC693BFCA739080CFULL,
		0x52E2271C8A05DF8DULL,
		0xF7BA1F5A87377948ULL,
		0x0000000000FD5789ULL,
		0x0000000000000000ULL
	}};
	shift = 40;
	printf("Test Case 103\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 103 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -103;
	} else {
		printf("Test Case 103 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6047FFADEFB0A2EFULL,
		0x7D537540EBC04B77ULL,
		0x0B0E1BDAAD669CA2ULL,
		0xE947DF397990EF83ULL,
		0xDDBAA812EF48F84CULL,
		0xFCD257F0F40F1D5DULL,
		0x899A3B7596F91229ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x537540EBC04B7760ULL,
		0x0E1BDAAD669CA27DULL,
		0x47DF397990EF830BULL,
		0xBAA812EF48F84CE9ULL,
		0xD257F0F40F1D5DDDULL,
		0x9A3B7596F91229FCULL,
		0x0000000000000089ULL,
		0x0000000000000000ULL
	}};
	shift = 56;
	printf("Test Case 104\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 104 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -104;
	} else {
		printf("Test Case 104 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x00B250C56C5F2C24ULL,
		0xCA761314A9B867E7ULL,
		0x51FD28584CA078C0ULL,
		0x6F0A1F6161D8C586ULL,
		0x0F186F6E937F966FULL,
		0x662BB85426B3FA9FULL,
		0xDC3B00F99A8C817CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x700B250C56C5F2C2ULL,
		0x0CA761314A9B867EULL,
		0x651FD28584CA078CULL,
		0xF6F0A1F6161D8C58ULL,
		0xF0F186F6E937F966ULL,
		0xC662BB85426B3FA9ULL,
		0x0DC3B00F99A8C817ULL,
		0x0000000000000000ULL
	}};
	shift = 4;
	printf("Test Case 105\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 105 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -105;
	} else {
		printf("Test Case 105 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5FFBC65C86B9A199ULL,
		0x83F3BADAFAA6DEE0ULL,
		0x239BCC3C2BD98084ULL,
		0x7C71A40527D58CCAULL,
		0xEEB9EB1527A9C2FDULL,
		0xEC1A6EF99B9AA76AULL,
		0xC2B81241609B5A7BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7B817FEF19721AE6ULL,
		0x02120FCEEB6BEA9BULL,
		0x33288E6F30F0AF66ULL,
		0x0BF5F1C690149F56ULL,
		0x9DABBAE7AC549EA7ULL,
		0x69EFB069BBE66E6AULL,
		0x00030AE04905826DULL,
		0x0000000000000000ULL
	}};
	shift = 14;
	printf("Test Case 106\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 106 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -106;
	} else {
		printf("Test Case 106 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAF328D97E9807DA9ULL,
		0x2E7C085A249DBDF4ULL,
		0xA75EFFF13A083F5FULL,
		0x037E5A8B211B95E1ULL,
		0x66C4F4921204E7DAULL,
		0x87819D91513DFC2CULL,
		0x512B9CEBA60FEF3DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBE95E651B2FD300FULL,
		0xEBE5CF810B4493B7ULL,
		0xBC34EBDFFE274107ULL,
		0xFB406FCB51642372ULL,
		0x858CD89E9242409CULL,
		0xE7B0F033B22A27BFULL,
		0x000A25739D74C1FDULL,
		0x0000000000000000ULL
	}};
	shift = 11;
	printf("Test Case 107\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 107 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -107;
	} else {
		printf("Test Case 107 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1651F5FF763C6C84ULL,
		0xB6C2FA2DBEEA709FULL,
		0x2BFD8F6DA2F876BCULL,
		0x85F32FB776307D01ULL,
		0xBB51EA8291305FC7ULL,
		0xB6D8392A8E4FB21DULL,
		0x7DDF8E0F3565A234ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7C5947D7FDD8F1B2ULL,
		0xF2DB0BE8B6FBA9C2ULL,
		0x04AFF63DB68BE1DAULL,
		0x1E17CCBEDDD8C1F4ULL,
		0x76ED47AA0A44C17FULL,
		0xD2DB60E4AA393EC8ULL,
		0x01F77E383CD59688ULL,
		0x0000000000000000ULL
	}};
	shift = 6;
	printf("Test Case 108\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 108 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -108;
	} else {
		printf("Test Case 108 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x33DA93F2216D360EULL,
		0xA2ACDD28A689B1F1ULL,
		0x568218F63F4FC586ULL,
		0x3B9AE558CBBF3517ULL,
		0x595F80C691278A49ULL,
		0xB744EC99ED37486BULL,
		0xF15467B33B0E82FDULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8AB374A29A26C7C4ULL,
		0x5A0863D8FD3F161AULL,
		0xEE6B95632EFCD45DULL,
		0x657E031A449E2924ULL,
		0xDD13B267B4DD21ADULL,
		0xC5519ECCEC3A0BF6ULL,
		0x0000000000000003ULL,
		0x0000000000000000ULL
	}};
	shift = 62;
	printf("Test Case 109\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 109 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -109;
	} else {
		printf("Test Case 109 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x622A9A32206047A9ULL,
		0x52290D6CC26310E0ULL,
		0x20F14DDFE8EA5D17ULL,
		0x85CFDC78B3FA02D6ULL,
		0x949D57519AC739C7ULL,
		0x7B3818660D3CCC4BULL,
		0x10D847A66448B06AULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0622A9A32206047AULL,
		0x752290D6CC26310EULL,
		0x620F14DDFE8EA5D1ULL,
		0x785CFDC78B3FA02DULL,
		0xB949D57519AC739CULL,
		0xA7B3818660D3CCC4ULL,
		0x010D847A66448B06ULL,
		0x0000000000000000ULL
	}};
	shift = 4;
	printf("Test Case 110\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 110 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -110;
	} else {
		printf("Test Case 110 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1BFF0F2016ADD468ULL,
		0xB263A7D71D0A6A93ULL,
		0xC86BDAC035F2D93CULL,
		0x7ECA8FBB468159DDULL,
		0xC927CC9B5C46628FULL,
		0x5B8A3EDBF1C930EBULL,
		0xF1D9890850D56099ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD52637FE1E402D5BULL,
		0xB27964C74FAE3A14ULL,
		0xB3BB90D7B5806BE5ULL,
		0xC51EFD951F768D02ULL,
		0x61D7924F9936B88CULL,
		0xC132B7147DB7E392ULL,
		0x0001E3B31210A1AAULL,
		0x0000000000000000ULL
	}};
	shift = 15;
	printf("Test Case 111\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 111 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -111;
	} else {
		printf("Test Case 111 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1E780418D21F1453ULL,
		0x2B018C64CC32BEBEULL,
		0xBD02E2ECC4CD99A1ULL,
		0x6FDA9090FC023B37ULL,
		0xE72C0B85CA96BE5AULL,
		0x005CA68A22C20F17ULL,
		0x19F5925FDE302F31ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x80C63266195F5F0FULL,
		0x8171766266CCD095ULL,
		0xED48487E011D9BDEULL,
		0x9605C2E54B5F2D37ULL,
		0x2E53451161078BF3ULL,
		0xFAC92FEF18179880ULL,
		0x000000000000000CULL,
		0x0000000000000000ULL
	}};
	shift = 57;
	printf("Test Case 112\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 112 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -112;
	} else {
		printf("Test Case 112 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x60A2CFE2240A5E49ULL,
		0x7070B3BBF49D9747ULL,
		0x74378517DFAE2F4DULL,
		0x27C1E6523AF113AFULL,
		0xBD0170D111BCC544ULL,
		0x794FBEA5E614C12FULL,
		0x81D64AF329539ACAULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA4ECBA3B05167F11ULL,
		0xFD717A6B83859DDFULL,
		0xD7889D7BA1BC28BEULL,
		0x8DE62A213E0F3291ULL,
		0x30A6097DE80B8688ULL,
		0x4A9CD653CA7DF52FULL,
		0x000000040EB25799ULL,
		0x0000000000000000ULL
	}};
	shift = 29;
	printf("Test Case 113\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 113 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -113;
	} else {
		printf("Test Case 113 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4A668C97049EC05DULL,
		0x5AF6999D64244866ULL,
		0x8AE89AA3B8164BEEULL,
		0x8D145E5EA14BFAF3ULL,
		0xDFFE21CA2EFE5829ULL,
		0x6D0F33F2E42AD820ULL,
		0xD02177EFC3289849ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xED333AC84890CC94ULL,
		0xD13547702C97DCB5ULL,
		0x28BCBD4297F5E715ULL,
		0xFC43945DFCB0531AULL,
		0x1E67E5C855B041BFULL,
		0x42EFDF86513092DAULL,
		0x00000000000001A0ULL,
		0x0000000000000000ULL
	}};
	shift = 55;
	printf("Test Case 114\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 114 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -114;
	} else {
		printf("Test Case 114 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8FF7272F21B6A00AULL,
		0x046D6DFEDF3F28E5ULL,
		0x8547C9D1803BCD8DULL,
		0xCF00D50689DF4BA9ULL,
		0x20288BB49F1CBDA0ULL,
		0x09F207BBA6FEF27AULL,
		0x692F832F164DE9CCULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8DADBFDBE7E51CB1ULL,
		0xA8F93A300779B1A0ULL,
		0xE01AA0D13BE97530ULL,
		0x05117693E397B419ULL,
		0x3E40F774DFDE4F44ULL,
		0x25F065E2C9BD3981ULL,
		0x000000000000000DULL,
		0x0000000000000000ULL
	}};
	shift = 59;
	printf("Test Case 115\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 115 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -115;
	} else {
		printf("Test Case 115 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC5E1A507BA9690F1ULL,
		0x682565356A2FF74FULL,
		0x608A7CA59D0BAFDCULL,
		0xB010A3BD35C13CE0ULL,
		0x82B4922740180D1DULL,
		0x2C71493119FE7EFFULL,
		0x003F94A2F9AD47D3ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x56A2FF74FC5E1A50ULL,
		0x59D0BAFDC6825653ULL,
		0xD35C13CE0608A7CAULL,
		0x740180D1DB010A3BULL,
		0x119FE7EFF82B4922ULL,
		0x2F9AD47D32C71493ULL,
		0x000000000003F94AULL,
		0x0000000000000000ULL
	}};
	shift = 36;
	printf("Test Case 116\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 116 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -116;
	} else {
		printf("Test Case 116 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4B4E514A35662D05ULL,
		0x486AF80030E57875ULL,
		0x6BE9CA0D908EE7E3ULL,
		0x86A87945FA8ADB9BULL,
		0x3E83F3249C92B589ULL,
		0x2EE4CCA7CC5732F0ULL,
		0xB7F6C4089FF56EEEULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2BC3AA5A728A51ABULL,
		0x773F1A4357C00187ULL,
		0x56DCDB5F4E506C84ULL,
		0x95AC4C3543CA2FD4ULL,
		0xB99781F41F9924E4ULL,
		0xAB77717726653E62ULL,
		0x000005BFB62044FFULL,
		0x0000000000000000ULL
	}};
	shift = 21;
	printf("Test Case 117\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 117 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -117;
	} else {
		printf("Test Case 117 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x95B50FACBB0DFF60ULL,
		0x91F0BC2D083C4891ULL,
		0xD2EF338CD4638EDAULL,
		0xA48D22282EA1E189ULL,
		0x9323542B91A01DD7ULL,
		0xFE809E6056EBEE91ULL,
		0xE6B62A0E19C42888ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE1785A107891232BULL,
		0xDE6719A8C71DB523ULL,
		0x1A44505D43C313A5ULL,
		0x46A85723403BAF49ULL,
		0x013CC0ADD7DD2326ULL,
		0x6C541C33885111FDULL,
		0x00000000000001CDULL,
		0x0000000000000000ULL
	}};
	shift = 55;
	printf("Test Case 118\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 118 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -118;
	} else {
		printf("Test Case 118 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD526431774BE120FULL,
		0xF86B80E9220B912AULL,
		0x1D5B24E5E1CA04D7ULL,
		0x3754DC673B7FE7A6ULL,
		0xC438EAF2677C9EF3ULL,
		0x18EDCF72275D7ECDULL,
		0x722A8AAD080C6A87ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9105C8956A93218BULL,
		0xF0E5026BFC35C074ULL,
		0x9DBFF3D30EAD9272ULL,
		0x33BE4F799BAA6E33ULL,
		0x13AEBF66E21C7579ULL,
		0x840635438C76E7B9ULL,
		0x0000000039154556ULL,
		0x0000000000000000ULL
	}};
	shift = 33;
	printf("Test Case 119\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 119 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -119;
	} else {
		printf("Test Case 119 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x615126960B2636EBULL,
		0xD28AC4F64D595D7AULL,
		0x60C1A7F5B92B68E7ULL,
		0xE8CC3D5A9723853EULL,
		0x5665B54DD375D3DAULL,
		0xB000FE9DC357D3CDULL,
		0xD0E11EECD0AC39F5ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6575E985449A582CULL,
		0xADA39F4A2B13D935ULL,
		0x8E14F983069FD6E4ULL,
		0xD74F6BA330F56A5CULL,
		0x5F4F355996D5374DULL,
		0xB0E7D6C003FA770DULL,
		0x00000343847BB342ULL,
		0x0000000000000000ULL
	}};
	shift = 22;
	printf("Test Case 120\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 120 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -120;
	} else {
		printf("Test Case 120 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x766716B11724E4B4ULL,
		0xD4456A07055DD696ULL,
		0xB9A3B0BFC1337EF9ULL,
		0x3412EDB95B649D0AULL,
		0xD038794A2B9859CBULL,
		0x466A697D30BEE405ULL,
		0x0DA98B33EC63F49DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEB4B3B338B588B92ULL,
		0xBF7CEA22B50382AEULL,
		0x4E855CD1D85FE099ULL,
		0x2CE59A0976DCADB2ULL,
		0x7202E81C3CA515CCULL,
		0xFA4EA33534BE985FULL,
		0x000006D4C599F631ULL,
		0x0000000000000000ULL
	}};
	shift = 17;
	printf("Test Case 121\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 121 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -121;
	} else {
		printf("Test Case 121 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9CA20390964705DEULL,
		0x303E2503380D7BDDULL,
		0x9A691FB8C5D655F8ULL,
		0x6C20CD9ABD5605C4ULL,
		0x8F3138D4B4C8C2DAULL,
		0x820F785500D853A1ULL,
		0x42B7CA14FF4F791BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x03380D7BDD9CA203ULL,
		0xB8C5D655F8303E25ULL,
		0x9ABD5605C49A691FULL,
		0xD4B4C8C2DA6C20CDULL,
		0x5500D853A18F3138ULL,
		0x14FF4F791B820F78ULL,
		0x000000000042B7CAULL,
		0x0000000000000000ULL
	}};
	shift = 40;
	printf("Test Case 122\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 122 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -122;
	} else {
		printf("Test Case 122 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2E05F7586AA9B7FEULL,
		0x5156DB7EE4296A2DULL,
		0x1577796567933485ULL,
		0x5686C85C7949DCF8ULL,
		0xF503A9AF9499564DULL,
		0x9CF068E0401C074CULL,
		0xDFFEC562803CDB49ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8AB6DBF7214B5169ULL,
		0xABBBCB2B3C99A42AULL,
		0xB43642E3CA4EE7C0ULL,
		0xA81D4D7CA4CAB26AULL,
		0xE783470200E03A67ULL,
		0xFFF62B1401E6DA4CULL,
		0x0000000000000006ULL,
		0x0000000000000000ULL
	}};
	shift = 61;
	printf("Test Case 123\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 123 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -123;
	} else {
		printf("Test Case 123 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x58C430687F0CFAA0ULL,
		0x4B094683FC4E9E55ULL,
		0x7C6B8E999F64AE40ULL,
		0x0A09DCCF4E34F1FDULL,
		0xC5337B6326BF96FEULL,
		0xE4685E1575EF49ABULL,
		0x48DE6DCB573DB709ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8D07F89D3CAAB188ULL,
		0x1D333EC95C809612ULL,
		0xB99E9C69E3FAF8D7ULL,
		0xF6C64D7F2DFC1413ULL,
		0xBC2AEBDE93578A66ULL,
		0xDB96AE7B6E13C8D0ULL,
		0x00000000000091BCULL,
		0x0000000000000000ULL
	}};
	shift = 47;
	printf("Test Case 124\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 124 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -124;
	} else {
		printf("Test Case 124 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x38D7336386A93D79ULL,
		0x15F704CB25E02816ULL,
		0xA2A6780D953AD396ULL,
		0xCF82B8D9EA2F44B2ULL,
		0x8E9BF51FE7222022ULL,
		0x807F067D2F1AD237ULL,
		0xECA0E30C045153BAULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1C6B99B1C3549EBCULL,
		0x0AFB826592F0140BULL,
		0x51533C06CA9D69CBULL,
		0x67C15C6CF517A259ULL,
		0xC74DFA8FF3911011ULL,
		0x403F833E978D691BULL,
		0x765071860228A9DDULL,
		0x0000000000000000ULL
	}};
	shift = 1;
	printf("Test Case 125\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 125 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -125;
	} else {
		printf("Test Case 125 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x626DBBB8108CDB03ULL,
		0xFFCB4C49C367FF32ULL,
		0x16EDF2159B96FFA0ULL,
		0x48DC4C4BE829444DULL,
		0x2E09F10BD98E3918ULL,
		0xDD2817BC6D982824ULL,
		0xB5F84147616328BFULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFE64C4DB77702119ULL,
		0xFF41FF96989386CFULL,
		0x889A2DDBE42B372DULL,
		0x723091B89897D052ULL,
		0x50485C13E217B31CULL,
		0x517FBA502F78DB30ULL,
		0x00016BF0828EC2C6ULL,
		0x0000000000000000ULL
	}};
	shift = 15;
	printf("Test Case 126\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 126 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -126;
	} else {
		printf("Test Case 126 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4EE1DEA3AA5C6406ULL,
		0x4A0B73A95D709DBDULL,
		0x7B8D2D66BDB88A50ULL,
		0xE716FD897A7BC93CULL,
		0xD0FF1DEBEDA5A7D6ULL,
		0x76138A569562B6C2ULL,
		0xCCC7BA17942CE255ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x95D709DBD4EE1DEAULL,
		0x6BDB88A504A0B73AULL,
		0x97A7BC93C7B8D2D6ULL,
		0xBEDA5A7D6E716FD8ULL,
		0x69562B6C2D0FF1DEULL,
		0x7942CE25576138A5ULL,
		0x000000000CCC7BA1ULL,
		0x0000000000000000ULL
	}};
	shift = 36;
	printf("Test Case 127\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 127 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -127;
	} else {
		printf("Test Case 127 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4819C95BC2AAB30DULL,
		0x1A0EE798C0C2D864ULL,
		0x8EBFBB11EAD373EBULL,
		0x0F92262A69F7900FULL,
		0xF29BBC76324CE39FULL,
		0x28432D752FD94331ULL,
		0xC23ABF03012027B7ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x32240CE4ADE15559ULL,
		0xF58D0773CC60616CULL,
		0x07C75FDD88F569B9ULL,
		0xCF87C9131534FBC8ULL,
		0x98F94DDE3B192671ULL,
		0xDB942196BA97ECA1ULL,
		0x00611D5F81809013ULL,
		0x0000000000000000ULL
	}};
	shift = 9;
	printf("Test Case 128\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 128 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -128;
	} else {
		printf("Test Case 128 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x465BE5B9E1573DEDULL,
		0xA47CDEBA4B78EB3CULL,
		0xEC7959D8092DC46EULL,
		0xAF371544E58675A7ULL,
		0x4A1D8AFE1FE01AB9ULL,
		0xFF928065730A8F84ULL,
		0x1F0468753F91924FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x59E232DF2DCF0AB9ULL,
		0x237523E6F5D25BC7ULL,
		0xAD3F63CACEC0496EULL,
		0xD5CD79B8AA272C33ULL,
		0x7C2250EC57F0FF00ULL,
		0x927FFC94032B9854ULL,
		0x0000F82343A9FC8CULL,
		0x0000000000000000ULL
	}};
	shift = 13;
	printf("Test Case 129\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 129 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -129;
	} else {
		printf("Test Case 129 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x03F78D4F3B50D64CULL,
		0xD09A834F69F3C4A4ULL,
		0x0B2F8BFF0D5DA769ULL,
		0x4690EF1591DE0F0DULL,
		0x856E6D1F5E2792E2ULL,
		0xDADC87D37E1C2809ULL,
		0x777C84BDECE187EEULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF3C4A403F78D4F3BULL,
		0x5DA769D09A834F69ULL,
		0xDE0F0D0B2F8BFF0DULL,
		0x2792E24690EF1591ULL,
		0x1C2809856E6D1F5EULL,
		0xE187EEDADC87D37EULL,
		0x000000777C84BDECULL,
		0x0000000000000000ULL
	}};
	shift = 24;
	printf("Test Case 130\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 130 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -130;
	} else {
		printf("Test Case 130 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF0FF9FC975287C7AULL,
		0x787ADE166C74B3AAULL,
		0x91903F84E3F27E4FULL,
		0x7E8751FD7A7F088CULL,
		0x5DD12CE05541E7C7ULL,
		0x349803C5653734BDULL,
		0xD9AABF14A74D8DF7ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB7859B1D2CEABC3FULL,
		0x0FE138FC9F93DE1EULL,
		0xD47F5E9FC2232464ULL,
		0x4B38155079F1DFA1ULL,
		0x00F1594DCD2F5774ULL,
		0xAFC529D3637DCD26ULL,
		0x000000000000366AULL,
		0x0000000000000000ULL
	}};
	shift = 50;
	printf("Test Case 131\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 131 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -131;
	} else {
		printf("Test Case 131 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAAAF0D00CEFADE85ULL,
		0x4D30A7FF20A87D80ULL,
		0x196F3ED7C91EE2FEULL,
		0x4DAD3C556BCD2F55ULL,
		0xA42D084EF1F513F0ULL,
		0xA95A9F07484A4518ULL,
		0x97D48562FE59058CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4FFE4150FB01555EULL,
		0x7DAF923DC5FC9A61ULL,
		0x78AAD79A5EAA32DEULL,
		0x109DE3EA27E09B5AULL,
		0x3E0E90948A31485AULL,
		0x0AC5FCB20B1952B5ULL,
		0x0000000000012FA9ULL,
		0x0000000000000000ULL
	}};
	shift = 47;
	printf("Test Case 132\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 132 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -132;
	} else {
		printf("Test Case 132 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x19F80A51E97F2CD5ULL,
		0x8077E23EF649FB5BULL,
		0xAFF0FCDEC1B4AC0EULL,
		0xFA4D6FBC0136717DULL,
		0xC9925858F709E2F6ULL,
		0x10851A7AC171F991ULL,
		0xE8D471B3EC9C91F5ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB19F80A51E97F2CDULL,
		0xE8077E23EF649FB5ULL,
		0xDAFF0FCDEC1B4AC0ULL,
		0x6FA4D6FBC0136717ULL,
		0x1C9925858F709E2FULL,
		0x510851A7AC171F99ULL,
		0x0E8D471B3EC9C91FULL,
		0x0000000000000000ULL
	}};
	shift = 4;
	printf("Test Case 133\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 133 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -133;
	} else {
		printf("Test Case 133 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC585290D46AD314DULL,
		0x57ABBE23CDCA1CFCULL,
		0x775126424D13A525ULL,
		0x631882735A8F54E2ULL,
		0xCB2A79077BD14C4DULL,
		0xA9912848AB809696ULL,
		0x656727DB33CAAD70ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x11E6E50E7E62C294ULL,
		0x212689D292ABD5DFULL,
		0x39AD47AA713BA893ULL,
		0x83BDE8A626B18C41ULL,
		0x2455C04B4B65953CULL,
		0xED99E556B854C894ULL,
		0x000000000032B393ULL,
		0x0000000000000000ULL
	}};
	shift = 41;
	printf("Test Case 134\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 134 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -134;
	} else {
		printf("Test Case 134 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE49871A00B2D6B6BULL,
		0xB2A422F7D24D65EEULL,
		0xC3DDEF690561AC91ULL,
		0xD45CFCBA113AD940ULL,
		0xBF817C20A2429DE3ULL,
		0xEC5AF39ACEF8462CULL,
		0xBD3E66541AAEA4EFULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEFA49ACBDDC930E3ULL,
		0xD20AC35923654845ULL,
		0x742275B28187BBDEULL,
		0x4144853BC7A8B9F9ULL,
		0x359DF08C597F02F8ULL,
		0xA8355D49DFD8B5E7ULL,
		0x00000000017A7CCCULL,
		0x0000000000000000ULL
	}};
	shift = 39;
	printf("Test Case 135\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 135 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -135;
	} else {
		printf("Test Case 135 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2BC0AAB4A1C76BD3ULL,
		0xAD868FA541A1F95BULL,
		0x9122ADADA0F18DFCULL,
		0x2131A36CDD9A71DBULL,
		0x848F84B8A425631DULL,
		0x3A15E86A31E91078ULL,
		0xD0F26DB81291BB1BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x657815569438ED7AULL,
		0x95B0D1F4A8343F2BULL,
		0x722455B5B41E31BFULL,
		0xA426346D9BB34E3BULL,
		0x1091F0971484AC63ULL,
		0x6742BD0D463D220FULL,
		0x1A1E4DB702523763ULL,
		0x0000000000000000ULL
	}};
	shift = 3;
	printf("Test Case 136\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 136 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -136;
	} else {
		printf("Test Case 136 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5B84AAEE3475ADF9ULL,
		0x3D1437F6E930E410ULL,
		0x8A9F210FFB206CE2ULL,
		0x7C16561AA37E67C6ULL,
		0xAFD62D720D256B5DULL,
		0x066D9F9B7BC69F96ULL,
		0x49A8F4F795B94167ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDD261C820B70955DULL,
		0xFF640D9C47A286FEULL,
		0x546FCCF8D153E421ULL,
		0x41A4AD6BAF82CAC3ULL,
		0x6F78D3F2D5FAC5AEULL,
		0xF2B7282CE0CDB3F3ULL,
		0x0000000009351E9EULL,
		0x0000000000000000ULL
	}};
	shift = 35;
	printf("Test Case 137\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 137 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -137;
	} else {
		printf("Test Case 137 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF26791B2B0BCFA8EULL,
		0x5A9B71580A568CF7ULL,
		0xDAF62DB45C3CBD61ULL,
		0xB20AA8BDDB77477FULL,
		0x50687CEFE90C1FAEULL,
		0x512747610A9D8729ULL,
		0x8A1900DA5206C652ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF26791B2B0BCFA8EULL,
		0x5A9B71580A568CF7ULL,
		0xDAF62DB45C3CBD61ULL,
		0xB20AA8BDDB77477FULL,
		0x50687CEFE90C1FAEULL,
		0x512747610A9D8729ULL,
		0x8A1900DA5206C652ULL,
		0x0000000000000000ULL
	}};
	shift = 0;
	printf("Test Case 138\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 138 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -138;
	} else {
		printf("Test Case 138 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9BFE0FDEBCF855ECULL,
		0x63027D4B267D5B7BULL,
		0xA69DAC038F521714ULL,
		0xC984D4FA5A739503ULL,
		0x00D58624F0CB64FAULL,
		0xA95371EF7B259B0EULL,
		0x0E6D0D1CF276B713ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB9BFE0FDEBCF855EULL,
		0x463027D4B267D5B7ULL,
		0x3A69DAC038F52171ULL,
		0xAC984D4FA5A73950ULL,
		0xE00D58624F0CB64FULL,
		0x3A95371EF7B259B0ULL,
		0x00E6D0D1CF276B71ULL,
		0x0000000000000000ULL
	}};
	shift = 4;
	printf("Test Case 139\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 139 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -139;
	} else {
		printf("Test Case 139 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x16B9AD31B48C4242ULL,
		0x3470AF8425D33A24ULL,
		0x4313AD0C3ABFBEE6ULL,
		0xB5D481BF6C195E2BULL,
		0x6C2623B5B8ABCB3EULL,
		0x342880F4B258BCCBULL,
		0x969932E26AAE753CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4482D735A6369188ULL,
		0xDCC68E15F084BA67ULL,
		0xC5686275A18757F7ULL,
		0x67D6BA9037ED832BULL,
		0x996D84C476B71579ULL,
		0xA78685101E964B17ULL,
		0x0012D3265C4D55CEULL,
		0x0000000000000000ULL
	}};
	shift = 11;
	printf("Test Case 140\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 140 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -140;
	} else {
		printf("Test Case 140 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x42E0C32171D7E1B5ULL,
		0xB83D74699BFD505CULL,
		0x0E8004A3AE04B75EULL,
		0xE2969A481B2CEBA2ULL,
		0x48FED26B392F1175ULL,
		0xAE9F29E2A57FAF7EULL,
		0x1C51B01E3D07BFBFULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x74699BFD505C42E0ULL,
		0x04A3AE04B75EB83DULL,
		0x9A481B2CEBA20E80ULL,
		0xD26B392F1175E296ULL,
		0x29E2A57FAF7E48FEULL,
		0xB01E3D07BFBFAE9FULL,
		0x0000000000001C51ULL,
		0x0000000000000000ULL
	}};
	shift = 48;
	printf("Test Case 141\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 141 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -141;
	} else {
		printf("Test Case 141 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1ECC129943253711ULL,
		0xD080E738EAD6DB5FULL,
		0x4EF8CCAC6E26E7D3ULL,
		0x24CC6D87B82701AAULL,
		0xD531A6B03F8E9697ULL,
		0xE52326AECAE4D082ULL,
		0x437C8C759E6C631BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB6D7C7B304A650C9ULL,
		0xB9F4F42039CE3AB5ULL,
		0xC06A93BE332B1B89ULL,
		0xA5A5C9331B61EE09ULL,
		0x3420B54C69AC0FE3ULL,
		0x18C6F948C9ABB2B9ULL,
		0x000010DF231D679BULL,
		0x0000000000000000ULL
	}};
	shift = 18;
	printf("Test Case 142\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 142 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -142;
	} else {
		printf("Test Case 142 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0D519766E5AA2E3BULL,
		0x16F8DD16313E060FULL,
		0x75262ED729656D7BULL,
		0xE4573BE8AC15D876ULL,
		0x3F5B2D00428BC8D3ULL,
		0x523C2C2999D91A96ULL,
		0x94A9BF5F8510FA3EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8B189F030786A8CBULL,
		0x6B94B2B6BD8B7C6EULL,
		0xF4560AEC3B3A9317ULL,
		0x802145E469F22B9DULL,
		0x14CCEC8D4B1FAD96ULL,
		0xAFC2887D1F291E16ULL,
		0x00000000004A54DFULL,
		0x0000000000000000ULL
	}};
	shift = 41;
	printf("Test Case 143\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 143 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -143;
	} else {
		printf("Test Case 143 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC42F9432D1761BC9ULL,
		0x8C673AFC0639EE6BULL,
		0xCD756756EF4A27D9ULL,
		0x770505F70F6DDEA7ULL,
		0x699C1318F1C4F4CAULL,
		0x065B0BA863D6D712ULL,
		0x563918EDC1D7C221ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF80C73DCD7885F28ULL,
		0xADDE944FB318CE75ULL,
		0xEE1EDBBD4F9AEACEULL,
		0x31E389E994EE0A0BULL,
		0x50C7ADAE24D33826ULL,
		0xDB83AF84420CB617ULL,
		0x0000000000AC7231ULL,
		0x0000000000000000ULL
	}};
	shift = 39;
	printf("Test Case 144\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 144 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -144;
	} else {
		printf("Test Case 144 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7519D23466890D14ULL,
		0xF41E792759863DA7ULL,
		0xDADED8EFF3A8D831ULL,
		0x25AB9B38C6BD2EC2ULL,
		0xD061FFDC68DA64AFULL,
		0x02738231DDE8EA71ULL,
		0xB6840DA315B71582ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC7B4EEA33A468CD1ULL,
		0x1B063E83CF24EB30ULL,
		0xA5D85B5BDB1DFE75ULL,
		0x4C95E4B5736718D7ULL,
		0x1D4E3A0C3FFB8D1BULL,
		0xE2B0404E70463BBDULL,
		0x000016D081B462B6ULL,
		0x0000000000000000ULL
	}};
	shift = 19;
	printf("Test Case 145\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 145 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -145;
	} else {
		printf("Test Case 145 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9E840E8940992392ULL,
		0xE62414CB13E24D73ULL,
		0xBA81268A1A99105AULL,
		0x7B199B735402C6E3ULL,
		0x851AB186C30577DDULL,
		0xAA5BACEF068F16E7ULL,
		0x3733573669AC1AA8ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2414CB13E24D739EULL,
		0x81268A1A99105AE6ULL,
		0x199B735402C6E3BAULL,
		0x1AB186C30577DD7BULL,
		0x5BACEF068F16E785ULL,
		0x33573669AC1AA8AAULL,
		0x0000000000000037ULL,
		0x0000000000000000ULL
	}};
	shift = 56;
	printf("Test Case 146\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 146 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -146;
	} else {
		printf("Test Case 146 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2755E450180565ADULL,
		0x7773878C2BEAD54EULL,
		0x25FE3F51314DE230ULL,
		0x3A6E4ADA9FDEE41DULL,
		0x58FAD943E0408EC6ULL,
		0x2FF94090BB905D9DULL,
		0x8497AEF4BC4B0035ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD54E2755E4501805ULL,
		0xE2307773878C2BEAULL,
		0xE41D25FE3F51314DULL,
		0x8EC63A6E4ADA9FDEULL,
		0x5D9D58FAD943E040ULL,
		0x00352FF94090BB90ULL,
		0x00008497AEF4BC4BULL,
		0x0000000000000000ULL
	}};
	shift = 16;
	printf("Test Case 147\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 147 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -147;
	} else {
		printf("Test Case 147 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2B611D9E2ED394D5ULL,
		0x23544B1E0DD2236AULL,
		0x54C2C0A587CE7AE5ULL,
		0xD95D36A15C7955A4ULL,
		0xD889CB4F96D49168ULL,
		0xC194D69F00FDE992ULL,
		0xE9E296DCAD2A4234ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1BA446D456C23B3CULL,
		0x0F9CF5CA46A8963CULL,
		0xB8F2AB48A985814BULL,
		0x2DA922D1B2BA6D42ULL,
		0x01FBD325B113969FULL,
		0x5A5484698329AD3EULL,
		0x00000001D3C52DB9ULL,
		0x0000000000000000ULL
	}};
	shift = 31;
	printf("Test Case 148\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 148 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -148;
	} else {
		printf("Test Case 148 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEDD21F98EB1BEE19ULL,
		0xDEFA7616C3431275ULL,
		0x725D9CC5469EE100ULL,
		0x1E3CCB686308A17DULL,
		0x1F5ECF7D690B6AB5ULL,
		0x889FFF10EF136B17ULL,
		0xAEAD95D06D4717DEULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x85B0D0C49D7B7487ULL,
		0x3151A7B84037BE9DULL,
		0xDA18C2285F5C9767ULL,
		0xDF5A42DAAD478F32ULL,
		0xC43BC4DAC5C7D7B3ULL,
		0x741B51C5F7A227FFULL,
		0x00000000002BAB65ULL,
		0x0000000000000000ULL
	}};
	shift = 42;
	printf("Test Case 149\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 149 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -149;
	} else {
		printf("Test Case 149 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC97DE8127DFD8567ULL,
		0x4BA2DEECFCFA20A1ULL,
		0x68E6368AB2B13E7FULL,
		0x8DBCE6ECEFABEF0DULL,
		0xE09C418182ED8307ULL,
		0x1C2742CBB59EA3C7ULL,
		0xFFEF3FCAC4C46E38ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB7BB3F3E8828725FULL,
		0x8DA2ACAC4F9FD2E8ULL,
		0x39BB3BEAFBC35A39ULL,
		0x106060BB60C1E36FULL,
		0xD0B2ED67A8F1F827ULL,
		0xCFF2B1311B8E0709ULL,
		0x0000000000003FFBULL,
		0x0000000000000000ULL
	}};
	shift = 50;
	printf("Test Case 150\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 150 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -150;
	} else {
		printf("Test Case 150 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7E91725B1DEDC1A5ULL,
		0xAF38B3DF488F4CE2ULL,
		0xD22C1DB8F897291BULL,
		0xDF7F93A9D1735A94ULL,
		0x84303C6CBA4BEEDDULL,
		0x1C2E3BA3FE4A707CULL,
		0xFE3FAB8C71431951ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF488F4CE27E91725ULL,
		0x8F897291BAF38B3DULL,
		0x9D1735A94D22C1DBULL,
		0xCBA4BEEDDDF7F93AULL,
		0x3FE4A707C84303C6ULL,
		0xC714319511C2E3BAULL,
		0x000000000FE3FAB8ULL,
		0x0000000000000000ULL
	}};
	shift = 36;
	printf("Test Case 151\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 151 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -151;
	} else {
		printf("Test Case 151 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x44B47DB1159E5735ULL,
		0x7726B84A5311670BULL,
		0xFE415A99DECE2058ULL,
		0xC2A319BDC66CA9BDULL,
		0x606815D1D587B493ULL,
		0xA25407C539E90911ULL,
		0x1298CCD220BB23C1ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x70B44B47DB1159E5ULL,
		0x0587726B84A53116ULL,
		0x9BDFE415A99DECE2ULL,
		0x493C2A319BDC66CAULL,
		0x911606815D1D587BULL,
		0x3C1A25407C539E90ULL,
		0x0001298CCD220BB2ULL,
		0x0000000000000000ULL
	}};
	shift = 12;
	printf("Test Case 152\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 152 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -152;
	} else {
		printf("Test Case 152 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x94670FF95166C6B9ULL,
		0xB15C8B861D3F0717ULL,
		0x57D0103E1BD0D0EDULL,
		0xA93C113234FFC104ULL,
		0xF25A3A553478F0C8ULL,
		0x29029BC2EFE40E30ULL,
		0xC879A076472505FCULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFC1C5E519C3FE545ULL,
		0x4343B6C5722E1874ULL,
		0xFF04115F4040F86FULL,
		0xE3C322A4F044C8D3ULL,
		0x9038C3C968E954D1ULL,
		0x9417F0A40A6F0BBFULL,
		0x00000321E681D91CULL,
		0x0000000000000000ULL
	}};
	shift = 22;
	printf("Test Case 153\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 153 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -153;
	} else {
		printf("Test Case 153 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x56D5DEC0D9857B7CULL,
		0x0B2088E130413A4EULL,
		0xA83F2E00FF0F8B2FULL,
		0x758D45E16FB90B37ULL,
		0xE323B780E718D145ULL,
		0xCAC4A3AA3B81DC7FULL,
		0x118A677F48635E99ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2384C104E9395B57ULL,
		0xB803FC3E2CBC2C82ULL,
		0x1785BEE42CDEA0FCULL,
		0xDE039C634515D635ULL,
		0x8EA8EE0771FF8C8EULL,
		0x9DFD218D7A672B12ULL,
		0x0000000000004629ULL,
		0x0000000000000000ULL
	}};
	shift = 46;
	printf("Test Case 154\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 154 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -154;
	} else {
		printf("Test Case 154 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7BEC38A06438DE2DULL,
		0xBBFC3EC472259BA6ULL,
		0x95D6D61E288F334AULL,
		0x4B8DA87BA38B95D4ULL,
		0x5E42CFD1B5CCF1BAULL,
		0xA9067BEAE839DB9CULL,
		0xA392C10A2E0C01BDULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFC3EC472259BA67BULL,
		0xD6D61E288F334ABBULL,
		0x8DA87BA38B95D495ULL,
		0x42CFD1B5CCF1BA4BULL,
		0x067BEAE839DB9C5EULL,
		0x92C10A2E0C01BDA9ULL,
		0x00000000000000A3ULL,
		0x0000000000000000ULL
	}};
	shift = 56;
	printf("Test Case 155\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 155 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -155;
	} else {
		printf("Test Case 155 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE28F2FB8B109A4B4ULL,
		0xC65C1680800B4FBBULL,
		0xDDAAAEA8F195846EULL,
		0xE254199F8A2A1FC9ULL,
		0xB00F87F63BE434AEULL,
		0x808EF94B2DADCF6EULL,
		0x0720E8CFE4FE5F6AULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9F77C51E5F716213ULL,
		0x08DD8CB82D010016ULL,
		0x3F93BB555D51E32BULL,
		0x695DC4A8333F1454ULL,
		0x9EDD601F0FEC77C8ULL,
		0xBED5011DF2965B5BULL,
		0x00000E41D19FC9FCULL,
		0x0000000000000000ULL
	}};
	shift = 15;
	printf("Test Case 156\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 156 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -156;
	} else {
		printf("Test Case 156 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA91324AFF1CE49A8ULL,
		0x356771258F780731ULL,
		0xCA681616509EB0BCULL,
		0x64D9467EB2C3D793ULL,
		0x0653FC9DAE65F7B1ULL,
		0x955937B457C239EEULL,
		0x5A8499965CD38DE3ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1EF00E635226495FULL,
		0xA13D61786ACEE24BULL,
		0x6587AF2794D02C2CULL,
		0x5CCBEF62C9B28CFDULL,
		0xAF8473DC0CA7F93BULL,
		0xB9A71BC72AB26F68ULL,
		0x00000000B509332CULL,
		0x0000000000000000ULL
	}};
	shift = 31;
	printf("Test Case 157\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 157 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -157;
	} else {
		printf("Test Case 157 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x40341B795D784441ULL,
		0xEBC2C0EDE6075F22ULL,
		0xEA2988AAB09D9C71ULL,
		0x084733DCA6A76FB0ULL,
		0xC280A8DDAFA89FF9ULL,
		0xE7B1544AEDF02C42ULL,
		0x33A06B31973476FAULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC0EDE6075F224034ULL,
		0x88AAB09D9C71EBC2ULL,
		0x33DCA6A76FB0EA29ULL,
		0xA8DDAFA89FF90847ULL,
		0x544AEDF02C42C280ULL,
		0x6B31973476FAE7B1ULL,
		0x00000000000033A0ULL,
		0x0000000000000000ULL
	}};
	shift = 48;
	printf("Test Case 158\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 158 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -158;
	} else {
		printf("Test Case 158 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB2299AB93F22A8E2ULL,
		0x5FFE21100239CC4AULL,
		0x6082E49B8E04F178ULL,
		0xCBD8866166A78D3BULL,
		0x8587B2E5E669EB73ULL,
		0x6ED6AE2802236D79ULL,
		0x3FA395808F27B58BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFC42200473989564ULL,
		0x05C9371C09E2F0BFULL,
		0xB10CC2CD4F1A76C1ULL,
		0x0F65CBCCD3D6E797ULL,
		0xAD5C500446DAF30BULL,
		0x472B011E4F6B16DDULL,
		0x000000000000007FULL,
		0x0000000000000000ULL
	}};
	shift = 55;
	printf("Test Case 159\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 159 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -159;
	} else {
		printf("Test Case 159 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xECCEE61DD048DB1BULL,
		0x178C1F36F3BBCB68ULL,
		0xE4B66A19ADF5727BULL,
		0x686061CD5CF7F1C6ULL,
		0x67581F6086732CFEULL,
		0xC54DBFB82D69EDD6ULL,
		0x54CEEC1FE49B3ED1ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDDE5B47667730EE8ULL,
		0xFAB93D8BC60F9B79ULL,
		0x7BF8E3725B350CD6ULL,
		0x39967F343030E6AEULL,
		0xB4F6EB33AC0FB043ULL,
		0x4D9F68E2A6DFDC16ULL,
		0x0000002A67760FF2ULL,
		0x0000000000000000ULL
	}};
	shift = 25;
	printf("Test Case 160\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 160 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -160;
	} else {
		printf("Test Case 160 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3BFD2DED32E3CFC9ULL,
		0xC4F19476FAAD4923ULL,
		0xE8D33DE14784E65EULL,
		0x361E94198E96F1C4ULL,
		0x51334A38171349D8ULL,
		0x10C46510499DE75CULL,
		0x0737577924ABEC2DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3B7D56A4919DFE96ULL,
		0xF0A3C2732F6278CAULL,
		0x0CC74B78E274699EULL,
		0x1C0B89A4EC1B0F4AULL,
		0x8824CEF3AE2899A5ULL,
		0xBC9255F616886232ULL,
		0x0000000000039BABULL,
		0x0000000000000000ULL
	}};
	shift = 41;
	printf("Test Case 161\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 161 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -161;
	} else {
		printf("Test Case 161 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA2DB65D6D2A89D1BULL,
		0xFE83F1616CF03969ULL,
		0x6A313CDB72CD2E23ULL,
		0xEF4225E94556BD7DULL,
		0xA2886CB721EE9CFDULL,
		0xDD809F5B52F27B8BULL,
		0x8787320EA618954BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x969A2DB65D6D2A89ULL,
		0xE23FE83F1616CF03ULL,
		0xD7D6A313CDB72CD2ULL,
		0xCFDEF4225E94556BULL,
		0xB8BA2886CB721EE9ULL,
		0x54BDD809F5B52F27ULL,
		0x0008787320EA6189ULL,
		0x0000000000000000ULL
	}};
	shift = 12;
	printf("Test Case 162\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 162 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -162;
	} else {
		printf("Test Case 162 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x80673122628667CAULL,
		0xD09BF8A6200145F9ULL,
		0x59C0B87035DE7D32ULL,
		0x460164D08FEA6095ULL,
		0x12F373FF4BBEC411ULL,
		0x9297EF213EFB4FD6ULL,
		0xB1C6177EE7336694ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFC531000A2FCC033ULL,
		0x5C381AEF3E99684DULL,
		0xB26847F5304AACE0ULL,
		0xB9FFA5DF6208A300ULL,
		0xF7909F7DA7EB0979ULL,
		0x0BBF7399B34A494BULL,
		0x00000000000058E3ULL,
		0x0000000000000000ULL
	}};
	shift = 49;
	printf("Test Case 163\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 163 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -163;
	} else {
		printf("Test Case 163 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4930323E697A29A5ULL,
		0x33DDF586298DF727ULL,
		0xDDC7A0C5AC6215E3ULL,
		0x60EE73F098F44096ULL,
		0x2A833EF05E303D55ULL,
		0x3B05BB257F6FEB74ULL,
		0xB9B8BC4EDDAC798DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA637DC9D24C0C8F9ULL,
		0xB188578CCF77D618ULL,
		0x63D1025B771E8316ULL,
		0x78C0F55583B9CFC2ULL,
		0xFDBFADD0AA0CFBC1ULL,
		0x76B1E634EC16EC95ULL,
		0x00000002E6E2F13BULL,
		0x0000000000000000ULL
	}};
	shift = 30;
	printf("Test Case 164\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 164 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -164;
	} else {
		printf("Test Case 164 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5935C1D496C7FE5BULL,
		0x46C5F1AA05161A06ULL,
		0x0F7DDE6677501D56ULL,
		0x583A21313D79BD15ULL,
		0x698564F9FD2ED035ULL,
		0x06C2959E031A1BB5ULL,
		0x1D436DC69DD60040ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x28B0D032C9AE0EA4ULL,
		0xBA80EAB2362F8D50ULL,
		0xEBCDE8A87BEEF333ULL,
		0xE97681AAC1D10989ULL,
		0x18D0DDAB4C2B27CFULL,
		0xEEB002003614ACF0ULL,
		0x00000000EA1B6E34ULL,
		0x0000000000000000ULL
	}};
	shift = 29;
	printf("Test Case 165\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 165 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -165;
	} else {
		printf("Test Case 165 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x79E5D15BFB5978D7ULL,
		0x73DD9019A7115DE1ULL,
		0x390ED1AA55D107A0ULL,
		0x4F894B2B6DA1B769ULL,
		0x25313E588D9AFDC4ULL,
		0x2169AAA530E87197ULL,
		0x80EF87C82305EC0EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x57785E797456FED6ULL,
		0x41E81CF7640669C4ULL,
		0x6DDA4E43B46A9574ULL,
		0xBF7113E252CADB68ULL,
		0x1C65C94C4F962366ULL,
		0x7B03885A6AA94C3AULL,
		0x0000203BE1F208C1ULL,
		0x0000000000000000ULL
	}};
	shift = 18;
	printf("Test Case 166\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 166 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -166;
	} else {
		printf("Test Case 166 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x340E69E3C1F37E8BULL,
		0xCC0D0C58BF8322DFULL,
		0x1A47D9EBE6F025B5ULL,
		0xDF1790C1234B8B35ULL,
		0xC4E616F2DC63020CULL,
		0x9ACCD23F0FAD48C7ULL,
		0xFB656C6A84A3F14AULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9A0734F1E0F9BF45ULL,
		0xE606862C5FC1916FULL,
		0x8D23ECF5F37812DAULL,
		0x6F8BC86091A5C59AULL,
		0xE2730B796E318106ULL,
		0x4D66691F87D6A463ULL,
		0x7DB2B6354251F8A5ULL,
		0x0000000000000000ULL
	}};
	shift = 1;
	printf("Test Case 167\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 167 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -167;
	} else {
		printf("Test Case 167 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x274152C1588DF3AAULL,
		0x43170BD16CBF4818ULL,
		0xCFAD7C8A8BECB2C1ULL,
		0x69563EB4D1B696A3ULL,
		0x1FA88ED293B9060DULL,
		0x8497116432B78AE5ULL,
		0x4552E77649E667C3ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC5C2F45B2FD20609ULL,
		0xEB5F22A2FB2CB050ULL,
		0x558FAD346DA5A8F3ULL,
		0xEA23B4A4EE41835AULL,
		0x25C4590CADE2B947ULL,
		0x54B9DD927999F0E1ULL,
		0x0000000000000011ULL,
		0x0000000000000000ULL
	}};
	shift = 58;
	printf("Test Case 168\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 168 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -168;
	} else {
		printf("Test Case 168 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBB48A78957DCADA2ULL,
		0xC4CD5E553D979495ULL,
		0xC0804F27A4EC0845ULL,
		0xEC366768A0AB2661ULL,
		0xC63DB5B5475B781BULL,
		0xED5573597010D4FCULL,
		0xB6A4D079E8B9A724ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3D979495BB48A789ULL,
		0xA4EC0845C4CD5E55ULL,
		0xA0AB2661C0804F27ULL,
		0x475B781BEC366768ULL,
		0x7010D4FCC63DB5B5ULL,
		0xE8B9A724ED557359ULL,
		0x00000000B6A4D079ULL,
		0x0000000000000000ULL
	}};
	shift = 32;
	printf("Test Case 169\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 169 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -169;
	} else {
		printf("Test Case 169 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3CC47F4D1FE220C7ULL,
		0xFF1C35538C616563ULL,
		0xE4136A3EB3B87E1DULL,
		0x1EF1EAC0FE3A0C96ULL,
		0xC70B5523CACCC3C8ULL,
		0xC1256E3DC4122E14ULL,
		0xE73BB4D5582226C4ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5633CC47F4D1FE22ULL,
		0xE1DFF1C35538C616ULL,
		0xC96E4136A3EB3B87ULL,
		0x3C81EF1EAC0FE3A0ULL,
		0xE14C70B5523CACCCULL,
		0x6C4C1256E3DC4122ULL,
		0x000E73BB4D558222ULL,
		0x0000000000000000ULL
	}};
	shift = 12;
	printf("Test Case 170\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 170 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -170;
	} else {
		printf("Test Case 170 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x14E5B3C169924EFCULL,
		0xBE566EE54B1AB756ULL,
		0xAD61215F1679B539ULL,
		0xEEAE1FF29005C1F0ULL,
		0xC2846047043D0E23ULL,
		0x34CEF776C6E9946CULL,
		0xFB6A6435858015B8ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB952C6ADD585396ULL,
		0x857C59E6D4E6F959ULL,
		0x7FCA401707C2B584ULL,
		0x811C10F4388FBAB8ULL,
		0xDDDB1BA651B30A11ULL,
		0x90D6160056E0D33BULL,
		0x000000000003EDA9ULL,
		0x0000000000000000ULL
	}};
	shift = 46;
	printf("Test Case 171\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 171 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -171;
	} else {
		printf("Test Case 171 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x05EB4F1AA7DCC7B8ULL,
		0x4EAB60F8A28F9300ULL,
		0x9C6CCFE9A3259D19ULL,
		0x9891D18D66247314ULL,
		0xED33B2EBF83F1934ULL,
		0xB7F12B9A6291D63EULL,
		0x4C68F7E47EC68D72ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC1F1451F26000BD6ULL,
		0x9FD3464B3A329D56ULL,
		0xA31ACC48E62938D9ULL,
		0x65D7F07E32693123ULL,
		0x5734C523AC7DDA67ULL,
		0xEFC8FD8D1AE56FE2ULL,
		0x00000000000098D1ULL,
		0x0000000000000000ULL
	}};
	shift = 47;
	printf("Test Case 172\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 172 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -172;
	} else {
		printf("Test Case 172 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6BE9337541B02A50ULL,
		0x67EB0E760D28C52EULL,
		0x131A351E51700FE2ULL,
		0x750CE1C621E0365DULL,
		0xEB9D7D95D9206A2FULL,
		0xD788A4B3CD361326ULL,
		0xCAEB27B58AF343D5ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x629735F499BAA0D8ULL,
		0x07F133F5873B0694ULL,
		0x1B2E898D1A8F28B8ULL,
		0x3517BA8670E310F0ULL,
		0x099375CEBECAEC90ULL,
		0xA1EAEBC45259E69BULL,
		0x0000657593DAC579ULL,
		0x0000000000000000ULL
	}};
	shift = 17;
	printf("Test Case 173\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 173 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -173;
	} else {
		printf("Test Case 173 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x682F55D82A153872ULL,
		0x987E9A0E5412AED0ULL,
		0xC95083146535197FULL,
		0x3D45B8F576F7509CULL,
		0xF7311A7EF8D564ADULL,
		0xE3A14A7843B58A88ULL,
		0xFFBE84A635DEEEFBULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE9A0E5412AED0682ULL,
		0x083146535197F987ULL,
		0x5B8F576F7509CC95ULL,
		0x11A7EF8D564AD3D4ULL,
		0x14A7843B58A88F73ULL,
		0xE84A635DEEEFBE3AULL,
		0x0000000000000FFBULL,
		0x0000000000000000ULL
	}};
	shift = 52;
	printf("Test Case 174\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 174 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -174;
	} else {
		printf("Test Case 174 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2E5487FA25BE4641ULL,
		0xBF5D62274D27B27CULL,
		0xB33D1C11E4A6F08CULL,
		0xEE9C174461BC25AEULL,
		0x8911B2C8799FF979ULL,
		0x2C517147001705DEULL,
		0xEF24B1358C109402ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC44E9A4F64F85CA9ULL,
		0x3823C94DE1197EBAULL,
		0x2E88C3784B5D667AULL,
		0x6590F33FF2F3DD38ULL,
		0xE28E002E0BBD1223ULL,
		0x626B1821280458A2ULL,
		0x000000000001DE49ULL,
		0x0000000000000000ULL
	}};
	shift = 47;
	printf("Test Case 175\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 175 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -175;
	} else {
		printf("Test Case 175 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x89D8F345C4E7939EULL,
		0x7697985D9715B4BCULL,
		0xC5B457DC9099A685ULL,
		0x0139541589902809ULL,
		0xED836AE03E65A0C2ULL,
		0x9A97D53C566758D2ULL,
		0x740C107B5B7513D2ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB2E2B697913B1E68ULL,
		0x921334D0AED2F30BULL,
		0xB132050138B68AFBULL,
		0x07CCB41840272A82ULL,
		0x8ACCEB1A5DB06D5CULL,
		0x6B6EA27A5352FAA7ULL,
		0x000000000E81820FULL,
		0x0000000000000000ULL
	}};
	shift = 35;
	printf("Test Case 176\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 176 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -176;
	} else {
		printf("Test Case 176 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x39EF1CD646A9AECCULL,
		0x788C24F6E6B7CED6ULL,
		0xC501C731C9468152ULL,
		0xC466A40C42511256ULL,
		0xA8603A589DC247D7ULL,
		0xEE4D493387BF9CBFULL,
		0x4A1EF7A54410FBF2ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x849EDCD6F9DAC73DULL,
		0x38E63928D02A4F11ULL,
		0xD481884A224AD8A0ULL,
		0x074B13B848FAF88CULL,
		0xA92670F7F397F50CULL,
		0xDEF4A8821F7E5DC9ULL,
		0x0000000000000943ULL,
		0x0000000000000000ULL
	}};
	shift = 51;
	printf("Test Case 177\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 177 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -177;
	} else {
		printf("Test Case 177 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4DA53BBCE6F4A37FULL,
		0xF4DB82B8EF9649C7ULL,
		0xEB6FFBB4A9A18AB0ULL,
		0xF28043520BFA0EB4ULL,
		0x666846969A67FFC8ULL,
		0x9AC6B36E3C89D2B1ULL,
		0x84CF5A9338030E27ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC938E9B4A7779CDEULL,
		0x31561E9B70571DF2ULL,
		0x41D69D6DFF769534ULL,
		0xFFF91E50086A417FULL,
		0x3A562CCD08D2D34CULL,
		0x61C4F358D66DC791ULL,
		0x00001099EB526700ULL,
		0x0000000000000000ULL
	}};
	shift = 19;
	printf("Test Case 178\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 178 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -178;
	} else {
		printf("Test Case 178 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5EC0B8BDC880098AULL,
		0x6F55DEA0EB7EA605ULL,
		0xE1FE94B63C126B31ULL,
		0x754960BE6F69CA9FULL,
		0x9E4632982F36ED0BULL,
		0xD247B520FF7FD242ULL,
		0x1BFB159FC7DFE3CFULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xABD81717B9100131ULL,
		0x2DEABBD41D6FD4C0ULL,
		0xFC3FD296C7824D66ULL,
		0x6EA92C17CDED3953ULL,
		0x53C8C65305E6DDA1ULL,
		0xFA48F6A41FEFFA48ULL,
		0x037F62B3F8FBFC79ULL,
		0x0000000000000000ULL
	}};
	shift = 3;
	printf("Test Case 179\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 179 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -179;
	} else {
		printf("Test Case 179 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA46A50308B8BEA05ULL,
		0x9017E0DDDFAD4D3AULL,
		0xAE5B541C561E1005ULL,
		0x2DC036922EA64CF8ULL,
		0x2EE672E17F5BF1C2ULL,
		0xCC50A34E5A7BD592ULL,
		0x834C8F55A0BC5BBCULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x017E0DDDFAD4D3AAULL,
		0xE5B541C561E10059ULL,
		0xDC036922EA64CF8AULL,
		0xEE672E17F5BF1C22ULL,
		0xC50A34E5A7BD5922ULL,
		0x34C8F55A0BC5BBCCULL,
		0x0000000000000008ULL,
		0x0000000000000000ULL
	}};
	shift = 60;
	printf("Test Case 180\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 180 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -180;
	} else {
		printf("Test Case 180 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEC6855A285F94480ULL,
		0xC1FACBD6B6C03FD5ULL,
		0xF751BF738DEA5EC4ULL,
		0xC7099486EC294E9EULL,
		0x2C2C168F4418978EULL,
		0xB497CA79AD73CAD1ULL,
		0xDC84F48FEC212B03ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF6342AD142FCA240ULL,
		0x60FD65EB5B601FEAULL,
		0x7BA8DFB9C6F52F62ULL,
		0x6384CA437614A74FULL,
		0x96160B47A20C4BC7ULL,
		0xDA4BE53CD6B9E568ULL,
		0x6E427A47F6109581ULL,
		0x0000000000000000ULL
	}};
	shift = 1;
	printf("Test Case 181\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 181 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -181;
	} else {
		printf("Test Case 181 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBCB8240FE07C7490ULL,
		0x7BFCD593ACA63169ULL,
		0xBAEC12E350B420FCULL,
		0xEB3FFA5AA6D3BEA9ULL,
		0x7EB906AA10D2D6ADULL,
		0x76AB467E4A2C3340ULL,
		0x6BCA396211760A1CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7594C62D37970481ULL,
		0x6A16841F8F7F9AB2ULL,
		0x54DA77D5375D825CULL,
		0x421A5AD5BD67FF4BULL,
		0xC94586680FD720D5ULL,
		0x422EC1438ED568CFULL,
		0x000000000D79472CULL,
		0x0000000000000000ULL
	}};
	shift = 35;
	printf("Test Case 182\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 182 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -182;
	} else {
		printf("Test Case 182 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x948EC9A4DFC1CAEAULL,
		0xA60ECB0CD2F4D57BULL,
		0x7106B5A0CBF563A8ULL,
		0xE2EDC8815F4151B4ULL,
		0x5EFD0CE0E13097F5ULL,
		0x2820A693F958D41CULL,
		0xD031CFABC2CA52AEULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAAF7291D9349BF83ULL,
		0xC7514C1D9619A5E9ULL,
		0xA368E20D6B4197EAULL,
		0x2FEBC5DB9102BE82ULL,
		0xA838BDFA19C1C261ULL,
		0xA55C50414D27F2B1ULL,
		0x0001A0639F578594ULL,
		0x0000000000000000ULL
	}};
	shift = 15;
	printf("Test Case 183\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 183 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -183;
	} else {
		printf("Test Case 183 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7AB99FA45C3CB25CULL,
		0x6ED590A1AAEB0DB0ULL,
		0x04EB6C196FE3E7CBULL,
		0x691E0052DA5BE15AULL,
		0xC2FD42163843CEF7ULL,
		0x63FA9187E0E582FCULL,
		0xA9E52DAF230B6AD1ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x355D61B60F5733F4ULL,
		0x2DFC7CF96DDAB214ULL,
		0x5B4B7C2B409D6D83ULL,
		0xC70879DEED23C00AULL,
		0xFC1CB05F985FA842ULL,
		0xE4616D5A2C7F5230ULL,
		0x00000000153CA5B5ULL,
		0x0000000000000000ULL
	}};
	shift = 35;
	printf("Test Case 184\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 184 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -184;
	} else {
		printf("Test Case 184 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x74AC76BE97A39ABEULL,
		0x475C9FED3C8994F3ULL,
		0x60A4AD18DE7C7E1BULL,
		0xB6DB8BAEAF21FB45ULL,
		0x3BB45C9EF1DD3BEFULL,
		0x6622CF8C7443EEDAULL,
		0xF0405E18E4D7736BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6E958ED7D2F47357ULL,
		0x68EB93FDA791329EULL,
		0xAC1495A31BCF8FC3ULL,
		0xF6DB7175D5E43F68ULL,
		0x47768B93DE3BA77DULL,
		0x6CC459F18E887DDBULL,
		0x1E080BC31C9AEE6DULL,
		0x0000000000000000ULL
	}};
	shift = 3;
	printf("Test Case 185\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 185 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -185;
	} else {
		printf("Test Case 185 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8B1716C1173F2377ULL,
		0xB38F52196003330DULL,
		0xBBEEBE423A4CBCC4ULL,
		0x7BB9313A8CF9168DULL,
		0x334A6925C820B843ULL,
		0xEB7AB9897F2A28A5ULL,
		0x42FA24E7480BF3AEULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x003330D8B1716C11ULL,
		0xA4CBCC4B38F52196ULL,
		0xCF9168DBBEEBE423ULL,
		0x820B8437BB9313A8ULL,
		0xF2A28A5334A6925CULL,
		0x80BF3AEEB7AB9897ULL,
		0x000000042FA24E74ULL,
		0x0000000000000000ULL
	}};
	shift = 28;
	printf("Test Case 186\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 186 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -186;
	} else {
		printf("Test Case 186 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF8DDB99D004129A2ULL,
		0x97FD5FED35F0BE47ULL,
		0x307B9F112216B512ULL,
		0x36C9C26E9822D3C6ULL,
		0x2C787C0F0F5C00FDULL,
		0xD7EB5D45FA0234A9ULL,
		0x902644807B1EFE05ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5FF57FB4D7C2F91FULL,
		0xC1EE7C44885AD44AULL,
		0xDB2709BA608B4F18ULL,
		0xB1E1F03C3D7003F4ULL,
		0x5FAD7517E808D2A4ULL,
		0x40991201EC7BF817ULL,
		0x0000000000000002ULL,
		0x0000000000000000ULL
	}};
	shift = 62;
	printf("Test Case 187\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 187 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -187;
	} else {
		printf("Test Case 187 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1E6590D55AE7A963ULL,
		0x2B6F0DA68CD5F57AULL,
		0x9275A32868D6257FULL,
		0x1F994F879F707561ULL,
		0xABDF7940109D7A8FULL,
		0x8D480B7C2FA36655ULL,
		0x4D43EA45629DF79EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6DE1B4D19ABEAF43ULL,
		0x4EB4650D1AC4AFE5ULL,
		0xF329F0F3EE0EAC32ULL,
		0x7BEF280213AF51E3ULL,
		0xA9016F85F46CCAB5ULL,
		0xA87D48AC53BEF3D1ULL,
		0x0000000000000009ULL,
		0x0000000000000000ULL
	}};
	shift = 59;
	printf("Test Case 188\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 188 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -188;
	} else {
		printf("Test Case 188 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF618C8208B87B048ULL,
		0xB730A68B2BE32A86ULL,
		0xD73ED46732D0370CULL,
		0x43ADEAF0432BC923ULL,
		0xCB3C205A7307F7EFULL,
		0x59B3EEA8EFF5B68AULL,
		0xEB1938CCDE91F460ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x595F195437B0C641ULL,
		0x399681B865B98534ULL,
		0x82195E491EB9F6A3ULL,
		0xD3983FBF7A1D6F57ULL,
		0x477FADB45659E102ULL,
		0x66F48FA302CD9F75ULL,
		0x000000000758C9C6ULL,
		0x0000000000000000ULL
	}};
	shift = 37;
	printf("Test Case 189\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 189 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -189;
	} else {
		printf("Test Case 189 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x50300BAD29E19A76ULL,
		0x56AEE9B48B5581FBULL,
		0xCCD673524BEFE983ULL,
		0xFC2E9058C9A0DCD3ULL,
		0xF9ECAF96E38480B0ULL,
		0x0BCB1A9ECB4DBC45ULL,
		0x2C45768E7A21CCAFULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x81FB50300BAD29E1ULL,
		0xE98356AEE9B48B55ULL,
		0xDCD3CCD673524BEFULL,
		0x80B0FC2E9058C9A0ULL,
		0xBC45F9ECAF96E384ULL,
		0xCCAF0BCB1A9ECB4DULL,
		0x00002C45768E7A21ULL,
		0x0000000000000000ULL
	}};
	shift = 16;
	printf("Test Case 190\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 190 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -190;
	} else {
		printf("Test Case 190 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD50B8B9CDC88913AULL,
		0x04FD7ED3F4765334ULL,
		0x3032AB0D33139B21ULL,
		0x067500A4344777EAULL,
		0xE0A467259AF794FBULL,
		0x094B6F66812FEF7EULL,
		0x99F21D7CF591B76CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD1D94CD3542E2E73ULL,
		0xCC4E6C8413F5FB4FULL,
		0xD11DDFA8C0CAAC34ULL,
		0x6BDE53EC19D40290ULL,
		0x04BFBDFB82919C96ULL,
		0xD646DDB0252DBD9AULL,
		0x0000000267C875F3ULL,
		0x0000000000000000ULL
	}};
	shift = 30;
	printf("Test Case 191\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 191 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -191;
	} else {
		printf("Test Case 191 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF8ECD6EA3EF5CC46ULL,
		0xB1DA2E72882E0EA3ULL,
		0x88D1CA7AC29E8BF9ULL,
		0xB6286C73B4AA2F8BULL,
		0x5DCDA376057A254AULL,
		0x50D8BF2BF5E95449ULL,
		0x42A79C4F763E147CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x105C1D47F1D9ADD4ULL,
		0x853D17F363B45CE5ULL,
		0x69545F1711A394F5ULL,
		0x0AF44A956C50D8E7ULL,
		0xEBD2A892BB9B46ECULL,
		0xEC7C28F8A1B17E57ULL,
		0x00000000854F389EULL,
		0x0000000000000000ULL
	}};
	shift = 31;
	printf("Test Case 192\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 192 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -192;
	} else {
		printf("Test Case 192 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6F4B12DF599E0180ULL,
		0xAFFE213A24A11475ULL,
		0xAE42E15E36EC2D64ULL,
		0xE4A964C61DA5E390ULL,
		0x42C9053DB5C7D4C3ULL,
		0xBBE588A5C7940260ULL,
		0xD659022AE22395AEULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8928451D5BD2C4B7ULL,
		0x8DBB0B592BFF884EULL,
		0x876978E42B90B857ULL,
		0x6D71F530F92A5931ULL,
		0x71E5009810B2414FULL,
		0xB888E56BAEF96229ULL,
		0x000000003596408AULL,
		0x0000000000000000ULL
	}};
	shift = 34;
	printf("Test Case 193\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 193 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -193;
	} else {
		printf("Test Case 193 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x73EF56E71D26D9CCULL,
		0x4C77A5DEB9C47931ULL,
		0x396235897A76EE9EULL,
		0xFCC0E764246CADD6ULL,
		0xD921E2BB195974ABULL,
		0xB88839CDB372BF59ULL,
		0xCA57DF4C03E243A4ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEF5CE23C98B9F7ABULL,
		0xC4BD3B774F263BD2ULL,
		0xB2123656EB1CB11AULL,
		0x5D8CACBA55FE6073ULL,
		0xE6D9B95FACEC90F1ULL,
		0xA601F121D25C441CULL,
		0x0000000000652BEFULL,
		0x0000000000000000ULL
	}};
	shift = 41;
	printf("Test Case 194\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 194 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -194;
	} else {
		printf("Test Case 194 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x544B86F5930CAB95ULL,
		0x0B4797BB637B5FF7ULL,
		0x3C773C5636C395ECULL,
		0xC4902B714DA01706ULL,
		0xCDAAA48E3E187452ULL,
		0xACC30D51AE01B9E6ULL,
		0x710F288561ADFEFDULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5EED8DED7FDD512EULL,
		0xF158DB0E57B02D1EULL,
		0xADC536805C18F1DCULL,
		0x9238F861D14B1240ULL,
		0x3546B806E79B36AAULL,
		0xA21586B7FBF6B30CULL,
		0x000000000001C43CULL,
		0x0000000000000000ULL
	}};
	shift = 46;
	printf("Test Case 195\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 195 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -195;
	} else {
		printf("Test Case 195 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD063FAED406BBDBAULL,
		0x373450B145A071F8ULL,
		0x36A446900A797D57ULL,
		0x29FC270776D8F852ULL,
		0x8FCA0C2547A06EB4ULL,
		0x8C913B1AA6070F6DULL,
		0x72C52AC499E7DEBBULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x51681C7E3418FEBBULL,
		0x029E5F55CDCD142CULL,
		0xDDB63E148DA911A4ULL,
		0x51E81BAD0A7F09C1ULL,
		0xA981C3DB63F28309ULL,
		0x2679F7AEE3244EC6ULL,
		0x000000001CB14AB1ULL,
		0x0000000000000000ULL
	}};
	shift = 34;
	printf("Test Case 196\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 196 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -196;
	} else {
		printf("Test Case 196 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDC8F752DE0A57E46ULL,
		0x4043E1155D48B931ULL,
		0x44E221890186C859ULL,
		0xA9BC99AC2FB2367BULL,
		0x6CC2E1E53A1BF0E6ULL,
		0xA06BFD285E71CF03ULL,
		0x237836753E5E20FEULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF84557522E4C7723ULL,
		0x88624061B2165010ULL,
		0x266B0BEC8D9ED138ULL,
		0xB8794E86FC39AA6FULL,
		0xFF4A179C73C0DB30ULL,
		0x0D9D4F97883FA81AULL,
		0x00000000000008DEULL,
		0x0000000000000000ULL
	}};
	shift = 50;
	printf("Test Case 197\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 197 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -197;
	} else {
		printf("Test Case 197 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9C51909A6691CFCFULL,
		0x5E263B4C29354AC1ULL,
		0xD52AE525C9FC7B7DULL,
		0xF2F32036BEB90970ULL,
		0x3D50D71A3BEB0F2CULL,
		0xC063D825CF262361ULL,
		0xF0382748886FF2C9ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAA560CE28C84D334ULL,
		0xE3DBEAF131DA6149ULL,
		0xC84B86A957292E4FULL,
		0x587967979901B5F5ULL,
		0x311B09EA86B8D1DFULL,
		0x7F964E031EC12E79ULL,
		0x00000781C13A4443ULL,
		0x0000000000000000ULL
	}};
	shift = 21;
	printf("Test Case 198\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 198 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -198;
	} else {
		printf("Test Case 198 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5B6B5D2E512AAC02ULL,
		0x426E5847B69768A1ULL,
		0xF755BF934EF19813ULL,
		0xF4946C44926DFF57ULL,
		0xBFAF7FE0FD8ECC18ULL,
		0x69117D332BA56DB6ULL,
		0x7E7B67BD40C51F09ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x856DAD74B944AAB0ULL,
		0x4D09B9611EDA5DA2ULL,
		0x5FDD56FE4D3BC660ULL,
		0x63D251B11249B7FDULL,
		0xDAFEBDFF83F63B30ULL,
		0x25A445F4CCAE95B6ULL,
		0x01F9ED9EF503147CULL,
		0x0000000000000000ULL
	}};
	shift = 6;
	printf("Test Case 199\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 199 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -199;
	} else {
		printf("Test Case 199 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3C07D945059E6F55ULL,
		0x99CF13170F3E471CULL,
		0x776438828E76F6B2ULL,
		0x8CD321762F6BBBE7ULL,
		0x37DDD8D314060DBCULL,
		0xAB934787D9D3E5D9ULL,
		0x3289D5FA699A73B8ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE262E1E7C8E38780ULL,
		0x871051CEDED65339ULL,
		0x642EC5ED777CEEECULL,
		0xBB1A6280C1B7919AULL,
		0x68F0FB3A7CBB26FBULL,
		0x3ABF4D334E771572ULL,
		0x0000000000000651ULL,
		0x0000000000000000ULL
	}};
	shift = 51;
	printf("Test Case 200\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 200 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -200;
	} else {
		printf("Test Case 200 PASSED\n");
	}
	printf("---\n\n");
	return 0;
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000010000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000100000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 60;
	printf("Test Case 201\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 201 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -201;
	} else {
		printf("Test Case 201 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0040000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000004ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 52;
	printf("Test Case 202\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 202 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -202;
	} else {
		printf("Test Case 202 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000004000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000400000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 4;
	printf("Test Case 203\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 203 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -203;
	} else {
		printf("Test Case 203 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000200000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000002ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 20;
	printf("Test Case 204\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 204 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -204;
	} else {
		printf("Test Case 204 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000100ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000010000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 44;
	printf("Test Case 205\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 205 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -205;
	} else {
		printf("Test Case 205 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000100000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000010ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 28;
	printf("Test Case 206\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 206 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -206;
	} else {
		printf("Test Case 206 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000080ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000008000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 56;
	printf("Test Case 207\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 207 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -207;
	} else {
		printf("Test Case 207 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000100000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000010ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 40;
	printf("Test Case 208\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 208 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -208;
	} else {
		printf("Test Case 208 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x4000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000400000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 28;
	printf("Test Case 209\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 209 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -209;
	} else {
		printf("Test Case 209 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000100000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 40;
	printf("Test Case 210\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 210 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -210;
	} else {
		printf("Test Case 210 PASSED\n");
	}
	printf("---\n\n");
	return 0;
}