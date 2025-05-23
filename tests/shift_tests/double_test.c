#include "../tests.h"

int32_t curve25519_key_x2_test(void) {
	printf("Key Doubling Test\n");
	curve25519_key_t k1 = {.key64 = {
		0x5FFB6603AA0106FFULL,
		0x2C954DA7771C84E0ULL,
		0xEA3AC4D28E622286ULL,
		0xD4EE8BF00EBD354AULL,
		0x02DF66AB0CB32C6CULL,
		0x65BB88069692F1F6ULL,
		0xCA9E60BC2A445675ULL,
		0x013C08BACFF6BE4FULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0xBFF6CC0754020DFEULL,
		0x592A9B4EEE3909C0ULL,
		0xD47589A51CC4450CULL,
		0xA9DD17E01D7A6A95ULL,
		0x05BECD56196658D9ULL,
		0xCB77100D2D25E3ECULL,
		0x953CC1785488ACEAULL,
		0x027811759FED7C9FULL
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
		0xD0B3E14DEFF61544ULL,
		0x29E212720D91C9D3ULL,
		0x54B91AC3498EA78BULL,
		0x5D5662BE06209FE4ULL,
		0x1246476B86457257ULL,
		0xCFE0A8271DDCC8C4ULL,
		0x12A3634BE2DC2D1DULL,
		0x165F943FEBBFE8B5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA167C29BDFEC2A88ULL,
		0x53C424E41B2393A7ULL,
		0xA9723586931D4F16ULL,
		0xBAACC57C0C413FC8ULL,
		0x248C8ED70C8AE4AEULL,
		0x9FC1504E3BB99188ULL,
		0x2546C697C5B85A3BULL,
		0x2CBF287FD77FD16AULL
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
		0x1E54066DB6DB48A8ULL,
		0x497A07BC8C0AB345ULL,
		0xF04E1003CF8B69BCULL,
		0x27873457314C3D7DULL,
		0x5080EA29948C1795ULL,
		0x0B66DA3D74FCB817ULL,
		0x1BE01143C7F97A58ULL,
		0x3B98A41B253D871AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3CA80CDB6DB69150ULL,
		0x92F40F791815668AULL,
		0xE09C20079F16D378ULL,
		0x4F0E68AE62987AFBULL,
		0xA101D45329182F2AULL,
		0x16CDB47AE9F9702EULL,
		0x37C022878FF2F4B0ULL,
		0x773148364A7B0E34ULL
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
		0xBF9E3BC292D72E72ULL,
		0x903C102EF73C83C8ULL,
		0x34A5ADB2BD67D0A4ULL,
		0xB12BB6F72D329025ULL,
		0x88B2A7AA252823B4ULL,
		0x5B20C7D319CB8C6FULL,
		0x6F92AE033C80FD2FULL,
		0x36724AFF439AACEEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7F3C778525AE5CE4ULL,
		0x2078205DEE790791ULL,
		0x694B5B657ACFA149ULL,
		0x62576DEE5A65204AULL,
		0x11654F544A504769ULL,
		0xB6418FA6339718DFULL,
		0xDF255C067901FA5EULL,
		0x6CE495FE873559DCULL
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
		0x7035571D121C1D7FULL,
		0x58FAFC960B6F46BDULL,
		0x0C16FA849D65B472ULL,
		0x7B330F46F927E00BULL,
		0x90706CB578D81FACULL,
		0x7DD5D313D9BA9E79ULL,
		0x22C1B03C9B903FA2ULL,
		0x2479DD2AAE1BE5D8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE06AAE3A24383AFEULL,
		0xB1F5F92C16DE8D7AULL,
		0x182DF5093ACB68E4ULL,
		0xF6661E8DF24FC016ULL,
		0x20E0D96AF1B03F58ULL,
		0xFBABA627B3753CF3ULL,
		0x4583607937207F44ULL,
		0x48F3BA555C37CBB0ULL
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
		0x2D889D9D21B2B95EULL,
		0x88FB86204178D3E2ULL,
		0x57AF36E657E67474ULL,
		0xC9345578AAE3F0B0ULL,
		0xA01756308683D029ULL,
		0xF462960067A033D2ULL,
		0x71AE584329D27C0DULL,
		0x099EC80F19517A6DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5B113B3A436572BCULL,
		0x11F70C4082F1A7C4ULL,
		0xAF5E6DCCAFCCE8E9ULL,
		0x9268AAF155C7E160ULL,
		0x402EAC610D07A053ULL,
		0xE8C52C00CF4067A5ULL,
		0xE35CB08653A4F81BULL,
		0x133D901E32A2F4DAULL
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
		0x3CE6E9CED3B8079BULL,
		0xC690E2FA645D201AULL,
		0xF5A05C82919E4D68ULL,
		0xF80C7AF25079B873ULL,
		0x2D4D82C3D529432FULL,
		0xB6A027FF0B205400ULL,
		0x6F70548A463A45A1ULL,
		0x3D300A7FD044A15CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x79CDD39DA7700F36ULL,
		0x8D21C5F4C8BA4034ULL,
		0xEB40B905233C9AD1ULL,
		0xF018F5E4A0F370E7ULL,
		0x5A9B0587AA52865FULL,
		0x6D404FFE1640A800ULL,
		0xDEE0A9148C748B43ULL,
		0x7A6014FFA08942B8ULL
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
		0x6DD2E2B9BFEF1DFAULL,
		0xF3C2EF86F1104B05ULL,
		0x7988DA88776CE847ULL,
		0xCD2C88A37E3F49D0ULL,
		0xE670BDC929B3FC3CULL,
		0xA499540FCA14E659ULL,
		0x095347736D700A13ULL,
		0x1013113D24F87E38ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDBA5C5737FDE3BF4ULL,
		0xE785DF0DE220960AULL,
		0xF311B510EED9D08FULL,
		0x9A591146FC7E93A0ULL,
		0xCCE17B925367F879ULL,
		0x4932A81F9429CCB3ULL,
		0x12A68EE6DAE01427ULL,
		0x2026227A49F0FC70ULL
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
		0x7E0BE730851641BAULL,
		0x5791F9C75251B56DULL,
		0xCF133228D0569169ULL,
		0xC7C5EBFCA47EF9FBULL,
		0xDAB1B164BE75EC98ULL,
		0x2E0530680F472CFDULL,
		0xFDA08087518509E1ULL,
		0x162317268ED9FDF4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFC17CE610A2C8374ULL,
		0xAF23F38EA4A36ADAULL,
		0x9E266451A0AD22D2ULL,
		0x8F8BD7F948FDF3F7ULL,
		0xB56362C97CEBD931ULL,
		0x5C0A60D01E8E59FBULL,
		0xFB41010EA30A13C2ULL,
		0x2C462E4D1DB3FBE9ULL
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
		0x33174965F1348C7FULL,
		0xE75944B2C88189C2ULL,
		0xF07D2028BBF67CBBULL,
		0x4CDC43C847953740ULL,
		0x4103051CD52996C4ULL,
		0xF9CB6502E72D83C1ULL,
		0x51C7B9D6568E5654ULL,
		0x133F94F79AB34D1DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x662E92CBE26918FEULL,
		0xCEB2896591031384ULL,
		0xE0FA405177ECF977ULL,
		0x99B887908F2A6E81ULL,
		0x82060A39AA532D88ULL,
		0xF396CA05CE5B0782ULL,
		0xA38F73ACAD1CACA9ULL,
		0x267F29EF35669A3AULL
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
		0xC22C89653DE1361BULL,
		0xC4575EE8FC1C2DE7ULL,
		0x668194FE54A0BD5CULL,
		0xA8DB181A565F64C5ULL,
		0x71B4C27814947792ULL,
		0x4FCF9B7212E71602ULL,
		0xE6DF387421F06B52ULL,
		0x2A8A1557DE88E823ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x845912CA7BC26C36ULL,
		0x88AEBDD1F8385BCFULL,
		0xCD0329FCA9417AB9ULL,
		0x51B63034ACBEC98AULL,
		0xE36984F02928EF25ULL,
		0x9F9F36E425CE2C04ULL,
		0xCDBE70E843E0D6A4ULL,
		0x55142AAFBD11D047ULL
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
		0x1F14F7ADE4E5CC7EULL,
		0x4131CC45620E0703ULL,
		0xD76F6B7AC440BE3FULL,
		0x7900F9C0E122AAA5ULL,
		0x605E2A36F8387082ULL,
		0x5E573A29373ACAD6ULL,
		0x539B89FDD3F65D59ULL,
		0x034565DFDAFC723EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3E29EF5BC9CB98FCULL,
		0x8263988AC41C0E06ULL,
		0xAEDED6F588817C7EULL,
		0xF201F381C245554BULL,
		0xC0BC546DF070E104ULL,
		0xBCAE74526E7595ACULL,
		0xA73713FBA7ECBAB2ULL,
		0x068ACBBFB5F8E47CULL
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
		0x26D93703C8961913ULL,
		0xCD1FCD4A1B26FAA8ULL,
		0x060E5E46C57E66D7ULL,
		0x9039378D339F702CULL,
		0x72D518E30CA65BADULL,
		0xDEFF1EFBC1C05B90ULL,
		0x51A1B491E529BC28ULL,
		0x1258A37E6C7BCA03ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4DB26E07912C3226ULL,
		0x9A3F9A94364DF550ULL,
		0x0C1CBC8D8AFCCDAFULL,
		0x20726F1A673EE058ULL,
		0xE5AA31C6194CB75BULL,
		0xBDFE3DF78380B720ULL,
		0xA3436923CA537851ULL,
		0x24B146FCD8F79406ULL
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
		0x7AC21D35E51A2FDEULL,
		0x9228D7AB33C3309AULL,
		0x531400ABFC8E563AULL,
		0x240DDAC0CC242544ULL,
		0xE4AB53BA8A1305A9ULL,
		0x73F36C1080EE3DB6ULL,
		0xDDBE53C646BBB118ULL,
		0x11E60C0B1A656370ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF5843A6BCA345FBCULL,
		0x2451AF5667866134ULL,
		0xA6280157F91CAC75ULL,
		0x481BB58198484A88ULL,
		0xC956A77514260B52ULL,
		0xE7E6D82101DC7B6DULL,
		0xBB7CA78C8D776230ULL,
		0x23CC181634CAC6E1ULL
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
		0xBC12EFFA9A3D7A61ULL,
		0xB01AA46A8E8DC5A9ULL,
		0xC1E090FB2F36F57EULL,
		0xB1DCF6D0F372E930ULL,
		0x4F01478D02F696ADULL,
		0x8AC97745DE2BBC1CULL,
		0xF4364521193126DCULL,
		0x2B79C0D5FDF128B2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7825DFF5347AF4C2ULL,
		0x603548D51D1B8B53ULL,
		0x83C121F65E6DEAFDULL,
		0x63B9EDA1E6E5D261ULL,
		0x9E028F1A05ED2D5BULL,
		0x1592EE8BBC577838ULL,
		0xE86C8A4232624DB9ULL,
		0x56F381ABFBE25165ULL
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
		0xA3D32FAD98E960E4ULL,
		0x57DB28E482594BDEULL,
		0x99018EA91C17BD09ULL,
		0xFB6540A5F0A92AF8ULL,
		0xBD411AA7F60E3B8BULL,
		0xF354B60E7795EF27ULL,
		0x33C4C478923C67A7ULL,
		0x13B2529E7EBDE4DCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x47A65F5B31D2C1C8ULL,
		0xAFB651C904B297BDULL,
		0x32031D52382F7A12ULL,
		0xF6CA814BE15255F1ULL,
		0x7A82354FEC1C7717ULL,
		0xE6A96C1CEF2BDE4FULL,
		0x678988F12478CF4FULL,
		0x2764A53CFD7BC9B8ULL
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
		0x1A47DC636670500AULL,
		0x249963492AD8D7E4ULL,
		0xABFF6D3CE6BB1A35ULL,
		0xA43A14D2C67794CBULL,
		0xDFCD578BB3061799ULL,
		0x0E1D0F6C61D12075ULL,
		0x90AF4710D98AABAAULL,
		0x2395B27CCB994FB3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x348FB8C6CCE0A014ULL,
		0x4932C69255B1AFC8ULL,
		0x57FEDA79CD76346AULL,
		0x487429A58CEF2997ULL,
		0xBF9AAF17660C2F33ULL,
		0x1C3A1ED8C3A240EBULL,
		0x215E8E21B3155754ULL,
		0x472B64F997329F67ULL
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
		0xDA3D92AE93C49C0FULL,
		0x1CB06B76FDCA08DFULL,
		0x64EA4A120A76E1B2ULL,
		0xDD09BC58F7423BBBULL,
		0x66767BBE5A41676BULL,
		0x7741EBA9351745D1ULL,
		0xD39533C23E8BD308ULL,
		0x3C865E06F7CB8456ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB47B255D2789381EULL,
		0x3960D6EDFB9411BFULL,
		0xC9D4942414EDC364ULL,
		0xBA1378B1EE847776ULL,
		0xCCECF77CB482CED7ULL,
		0xEE83D7526A2E8BA2ULL,
		0xA72A67847D17A610ULL,
		0x790CBC0DEF9708ADULL
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
		0x0531974F3F4D4C1CULL,
		0xECB5C8913FD9A6DEULL,
		0x949CB2DD839027D9ULL,
		0x16642BA51F4CDC2CULL,
		0x8930BF6A6E892531ULL,
		0x668E6D8670C93121ULL,
		0xB8EB8E7DEF66C1B5ULL,
		0x2FF3126344CA880CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0A632E9E7E9A9838ULL,
		0xD96B91227FB34DBCULL,
		0x293965BB07204FB3ULL,
		0x2CC8574A3E99B859ULL,
		0x12617ED4DD124A62ULL,
		0xCD1CDB0CE1926243ULL,
		0x71D71CFBDECD836AULL,
		0x5FE624C689951019ULL
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
		0x154EBD7297EA952EULL,
		0x21C7BE91CD51DA8FULL,
		0x78167A406FF7F590ULL,
		0x6B9244E4028452BEULL,
		0x2963C6AA38B59DE0ULL,
		0x607F919357525A3EULL,
		0x64D78595E2B34B8DULL,
		0x3AFD653666C5BF95ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2A9D7AE52FD52A5CULL,
		0x438F7D239AA3B51EULL,
		0xF02CF480DFEFEB20ULL,
		0xD72489C80508A57CULL,
		0x52C78D54716B3BC0ULL,
		0xC0FF2326AEA4B47CULL,
		0xC9AF0B2BC566971AULL,
		0x75FACA6CCD8B7F2AULL
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
		0x51F51C62FE1C944BULL,
		0x4711F47EC3E2CAB8ULL,
		0xC4B7AB5FC7363F47ULL,
		0xD608076EEF867032ULL,
		0xD210F6517FB90D48ULL,
		0x0B41544B5F037195ULL,
		0x09990A45804799EDULL,
		0x2A1362C210966376ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA3EA38C5FC392896ULL,
		0x8E23E8FD87C59570ULL,
		0x896F56BF8E6C7E8EULL,
		0xAC100EDDDF0CE065ULL,
		0xA421ECA2FF721A91ULL,
		0x1682A896BE06E32BULL,
		0x1332148B008F33DAULL,
		0x5426C584212CC6ECULL
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
		0x632B612405AB371EULL,
		0x3E0ACF1D1E150D7CULL,
		0x820AAB825B4ACB4FULL,
		0x0E6D972010D1DCE5ULL,
		0x1958164402D5205EULL,
		0x7FED5B6ED9DB617AULL,
		0x53FC7ED8377B63BCULL,
		0x245BCA5B26C40A7CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC656C2480B566E3CULL,
		0x7C159E3A3C2A1AF8ULL,
		0x04155704B695969EULL,
		0x1CDB2E4021A3B9CBULL,
		0x32B02C8805AA40BCULL,
		0xFFDAB6DDB3B6C2F4ULL,
		0xA7F8FDB06EF6C778ULL,
		0x48B794B64D8814F8ULL
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
		0x21AC46E4DD2893B6ULL,
		0x6D32984B0A2D855BULL,
		0x408171F04C9E1954ULL,
		0x51C0A3B676D6A30AULL,
		0x12890D237207EACBULL,
		0x921C814A0AA6E8C8ULL,
		0x20A4AFF279F202A6ULL,
		0x04D3DB52A6565FA1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x43588DC9BA51276CULL,
		0xDA653096145B0AB6ULL,
		0x8102E3E0993C32A8ULL,
		0xA381476CEDAD4614ULL,
		0x25121A46E40FD596ULL,
		0x24390294154DD190ULL,
		0x41495FE4F3E4054DULL,
		0x09A7B6A54CACBF42ULL
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
		0x0F7C049BC4221C23ULL,
		0x4F41E54CC6378D6FULL,
		0xC28DC9084CA2AF49ULL,
		0xB9DC604D7BB6D149ULL,
		0xC26F212EFBFA835FULL,
		0xB7DEC8426C197E9AULL,
		0x0B955FC17D8413C4ULL,
		0x3AD342790D74B097ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1EF8093788443846ULL,
		0x9E83CA998C6F1ADEULL,
		0x851B921099455E92ULL,
		0x73B8C09AF76DA293ULL,
		0x84DE425DF7F506BFULL,
		0x6FBD9084D832FD35ULL,
		0x172ABF82FB082789ULL,
		0x75A684F21AE9612EULL
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
		0x3A804A9F50DE83FFULL,
		0xC80EA5E74E6835BBULL,
		0xD76DDD055B45EED0ULL,
		0xAAD5E33475005B05ULL,
		0x46D97EDF76F91489ULL,
		0xF7C8B3C281E4825BULL,
		0x649AE68A2A2329A0ULL,
		0x04768ABB7CE5F4B1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7500953EA1BD07FEULL,
		0x901D4BCE9CD06B76ULL,
		0xAEDBBA0AB68BDDA1ULL,
		0x55ABC668EA00B60BULL,
		0x8DB2FDBEEDF22913ULL,
		0xEF91678503C904B6ULL,
		0xC935CD1454465341ULL,
		0x08ED1576F9CBE962ULL
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
		0x46A951C6FFA91080ULL,
		0x185336AC6C773DECULL,
		0x2DDA97E80464CA72ULL,
		0xAD082D16139805FAULL,
		0xCED58440ECC432EEULL,
		0x2F7CAAA4C62E7A75ULL,
		0xB32A0B8F01B6489DULL,
		0x3C74619954EBBC7EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8D52A38DFF522100ULL,
		0x30A66D58D8EE7BD8ULL,
		0x5BB52FD008C994E4ULL,
		0x5A105A2C27300BF4ULL,
		0x9DAB0881D98865DDULL,
		0x5EF955498C5CF4EBULL,
		0x6654171E036C913AULL,
		0x78E8C332A9D778FDULL
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
		0x1E911CBD7A5E0191ULL,
		0x15819D1EDDE4A317ULL,
		0x9E252B24E6F7BABDULL,
		0x01979E5DD56F1A4BULL,
		0x7CD0AE10F64050E9ULL,
		0x8FE1D52575D202BCULL,
		0x425755AB3A3FB98AULL,
		0x003F3B4C458CD0FFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3D22397AF4BC0322ULL,
		0x2B033A3DBBC9462EULL,
		0x3C4A5649CDEF757AULL,
		0x032F3CBBAADE3497ULL,
		0xF9A15C21EC80A1D2ULL,
		0x1FC3AA4AEBA40578ULL,
		0x84AEAB56747F7315ULL,
		0x007E76988B19A1FEULL
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
		0xFDE01A44EEC86D3CULL,
		0x31AA1C987F1989F1ULL,
		0x240945B520E7BDB0ULL,
		0x3A9DB57E4BF32698ULL,
		0x38A1B029B4EADFCEULL,
		0x48FF8492D086DA0FULL,
		0x19F1FFF52F33E1AFULL,
		0x3D20F3BD59D92C7DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFBC03489DD90DA78ULL,
		0x63543930FE3313E3ULL,
		0x48128B6A41CF7B60ULL,
		0x753B6AFC97E64D30ULL,
		0x7143605369D5BF9CULL,
		0x91FF0925A10DB41EULL,
		0x33E3FFEA5E67C35EULL,
		0x7A41E77AB3B258FAULL
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
		0xDBD4AFBB5D31E648ULL,
		0x22F74E8B01D6C3F9ULL,
		0xF6830C214B12FE55ULL,
		0xB01E3F2CDC4CF769ULL,
		0x3A6C4FB36F83F309ULL,
		0xFFD7546B487DBAD0ULL,
		0x5C49FDA5A06FBE25ULL,
		0x1B7BA0E20AFECA99ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB7A95F76BA63CC90ULL,
		0x45EE9D1603AD87F3ULL,
		0xED0618429625FCAAULL,
		0x603C7E59B899EED3ULL,
		0x74D89F66DF07E613ULL,
		0xFFAEA8D690FB75A0ULL,
		0xB893FB4B40DF7C4BULL,
		0x36F741C415FD9532ULL
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
		0xE6B13FEF9EC5BD96ULL,
		0xE55CBBE3C6AA0318ULL,
		0x6D0B6F0B8578355CULL,
		0x8ECC1E91324857A9ULL,
		0xEC9C3A253555DF6FULL,
		0x36710CDE5781016FULL,
		0x0609073B18C27E26ULL,
		0x1D7A3DB11F4E604FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCD627FDF3D8B7B2CULL,
		0xCAB977C78D540631ULL,
		0xDA16DE170AF06AB9ULL,
		0x1D983D226490AF52ULL,
		0xD938744A6AABBEDFULL,
		0x6CE219BCAF0202DFULL,
		0x0C120E763184FC4CULL,
		0x3AF47B623E9CC09EULL
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
		0x19D572EAC88A5E16ULL,
		0xFDBD38B73A51270EULL,
		0x44907A164AAD69F1ULL,
		0x71BA77F1E1BE5664ULL,
		0x5247A83CD880EA5BULL,
		0xDF9706084AA4D723ULL,
		0xC932252E782AF32AULL,
		0x2A39A4CB02BAE23DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x33AAE5D59114BC2CULL,
		0xFB7A716E74A24E1CULL,
		0x8920F42C955AD3E3ULL,
		0xE374EFE3C37CACC8ULL,
		0xA48F5079B101D4B6ULL,
		0xBF2E0C109549AE46ULL,
		0x92644A5CF055E655ULL,
		0x547349960575C47BULL
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
		0xC20FDE6A1F4F451FULL,
		0x3E24B13C493091D8ULL,
		0xEEE7AFB23D4A1A39ULL,
		0x2FF5FE6DA595BD85ULL,
		0xB3D88FC264D51CD2ULL,
		0xB427F2D97F0EF615ULL,
		0x20A8EC6629337563ULL,
		0x2717496AD3BFBE8DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x841FBCD43E9E8A3EULL,
		0x7C496278926123B1ULL,
		0xDDCF5F647A943472ULL,
		0x5FEBFCDB4B2B7B0BULL,
		0x67B11F84C9AA39A4ULL,
		0x684FE5B2FE1DEC2BULL,
		0x4151D8CC5266EAC7ULL,
		0x4E2E92D5A77F7D1AULL
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
		0x07701FD403906827ULL,
		0xD7949D0E5A96214DULL,
		0x8E76DA9F2C2C164AULL,
		0xE84412FAD7A415E0ULL,
		0xF73C97F2FA3124E8ULL,
		0xE695E7BF3CBCE621ULL,
		0x45CF2CBB555679ACULL,
		0x31A66E172EE153ABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0EE03FA80720D04EULL,
		0xAF293A1CB52C429AULL,
		0x1CEDB53E58582C95ULL,
		0xD08825F5AF482BC1ULL,
		0xEE792FE5F46249D1ULL,
		0xCD2BCF7E7979CC43ULL,
		0x8B9E5976AAACF359ULL,
		0x634CDC2E5DC2A756ULL
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
		0xD46ED52B607ED7C3ULL,
		0x01183A1DB04A9B65ULL,
		0x8C1A74E30B228291ULL,
		0x6E34EBD80F67A0F8ULL,
		0x75E57BB81C6E6077ULL,
		0x30B8850CACCD9B32ULL,
		0x70407D0A45AEDD62ULL,
		0x2FEE0B759776A105ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA8DDAA56C0FDAF86ULL,
		0x0230743B609536CBULL,
		0x1834E9C616450522ULL,
		0xDC69D7B01ECF41F1ULL,
		0xEBCAF77038DCC0EEULL,
		0x61710A19599B3664ULL,
		0xE080FA148B5DBAC4ULL,
		0x5FDC16EB2EED420AULL
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
		0x4254BF665B5CFD1AULL,
		0x7A382A32F70FA591ULL,
		0x4C351B59A33727C9ULL,
		0x99290CD51FA7FB81ULL,
		0xD625FFC3058F5EE6ULL,
		0xC5E5C200A7F357E8ULL,
		0xA182BB9CD00321F6ULL,
		0x233A8D5E20C8C3C2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x84A97ECCB6B9FA34ULL,
		0xF4705465EE1F4B22ULL,
		0x986A36B3466E4F92ULL,
		0x325219AA3F4FF702ULL,
		0xAC4BFF860B1EBDCDULL,
		0x8BCB84014FE6AFD1ULL,
		0x43057739A00643EDULL,
		0x46751ABC41918785ULL
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
		0x7E9EBE3AE940BC0CULL,
		0x1F966148EFD74549ULL,
		0x55E7A94858FDAFC4ULL,
		0x795E75B722246C73ULL,
		0x19E1BDFF1F815A58ULL,
		0x5CEF781E026F2116ULL,
		0xBF71D5166D9C15D5ULL,
		0x316FC4E01B445910ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFD3D7C75D2817818ULL,
		0x3F2CC291DFAE8A92ULL,
		0xABCF5290B1FB5F88ULL,
		0xF2BCEB6E4448D8E6ULL,
		0x33C37BFE3F02B4B0ULL,
		0xB9DEF03C04DE422CULL,
		0x7EE3AA2CDB382BAAULL,
		0x62DF89C03688B221ULL
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
		0x1F961E4082A3EC36ULL,
		0x1E1AAC26ED125A48ULL,
		0xF569C85C3DC03B91ULL,
		0x3DAC497E212E0DD9ULL,
		0x95BADC95E17CCF2FULL,
		0x8DF365B2D4BF5CADULL,
		0x640C72C94BBA3FFFULL,
		0x34F3AB1864FB2B66ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3F2C3C810547D86CULL,
		0x3C35584DDA24B490ULL,
		0xEAD390B87B807722ULL,
		0x7B5892FC425C1BB3ULL,
		0x2B75B92BC2F99E5EULL,
		0x1BE6CB65A97EB95BULL,
		0xC818E59297747FFFULL,
		0x69E75630C9F656CCULL
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
		0x9D49F6239656D191ULL,
		0x1FFBD9EB9B105ED4ULL,
		0x055F273B2BC58D99ULL,
		0x51678C951C2D8DD7ULL,
		0x487BDAEC0B3A591AULL,
		0xF6D8366CF62DF043ULL,
		0xE9529BB8CE35FC8BULL,
		0x3FD989530B6D45D0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3A93EC472CADA322ULL,
		0x3FF7B3D73620BDA9ULL,
		0x0ABE4E76578B1B32ULL,
		0xA2CF192A385B1BAEULL,
		0x90F7B5D81674B234ULL,
		0xEDB06CD9EC5BE086ULL,
		0xD2A537719C6BF917ULL,
		0x7FB312A616DA8BA1ULL
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
		0x7DB4D991B9F2DDD6ULL,
		0x071F9117D92E41F9ULL,
		0x292E8410113B122BULL,
		0x0631359A4BE88A82ULL,
		0xE0CDB5FB8D999168ULL,
		0xFB96B9644AB95B54ULL,
		0x1C22331379F40BC2ULL,
		0x3FDD2DC29888D815ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFB69B32373E5BBACULL,
		0x0E3F222FB25C83F2ULL,
		0x525D082022762456ULL,
		0x0C626B3497D11504ULL,
		0xC19B6BF71B3322D0ULL,
		0xF72D72C89572B6A9ULL,
		0x38446626F3E81785ULL,
		0x7FBA5B853111B02AULL
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
		0x6118D69D0445CE4AULL,
		0xB1C2935C38677609ULL,
		0xB8088AC1DB94C9EEULL,
		0xDD20EECA73EE63E6ULL,
		0x80255FBCDEB7C874ULL,
		0xDB52FD30747D8BFFULL,
		0xFB948A0B47C97E83ULL,
		0x2EF8DF45CB31F75DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC231AD3A088B9C94ULL,
		0x638526B870CEEC12ULL,
		0x70111583B72993DDULL,
		0xBA41DD94E7DCC7CDULL,
		0x004ABF79BD6F90E9ULL,
		0xB6A5FA60E8FB17FFULL,
		0xF72914168F92FD07ULL,
		0x5DF1BE8B9663EEBBULL
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
		0x2DEB9FEC1D4C67AFULL,
		0x9696CD1E77E2AB6FULL,
		0xE8482D03B2713C7AULL,
		0x9EB47CCEF1451353ULL,
		0x6DD71F7CABE27B28ULL,
		0xE55636790E20859FULL,
		0x5AF9F4DBD3796ECBULL,
		0x3C842A71F6BEC0A3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5BD73FD83A98CF5EULL,
		0x2D2D9A3CEFC556DEULL,
		0xD0905A0764E278F5ULL,
		0x3D68F99DE28A26A7ULL,
		0xDBAE3EF957C4F651ULL,
		0xCAAC6CF21C410B3EULL,
		0xB5F3E9B7A6F2DD97ULL,
		0x790854E3ED7D8146ULL
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
		0xB1E7414FE1490190ULL,
		0xED4D003B4EB98CD3ULL,
		0x27611BB1DD490066ULL,
		0x4D43474B5C96F48CULL,
		0x773AE677D663266BULL,
		0x5CE2FCD659322DAEULL,
		0x8A2F3ECFA8AA067FULL,
		0x3AACD11BDA01A816ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x63CE829FC2920320ULL,
		0xDA9A00769D7319A7ULL,
		0x4EC23763BA9200CDULL,
		0x9A868E96B92DE918ULL,
		0xEE75CCEFACC64CD6ULL,
		0xB9C5F9ACB2645B5CULL,
		0x145E7D9F51540CFEULL,
		0x7559A237B403502DULL
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
		0xEA3C7E47BB30215EULL,
		0xF0156FBF891A368AULL,
		0xFBFDC8879FC26A33ULL,
		0xCBF1F692D47A667FULL,
		0x3E89FADFFC9CF8ACULL,
		0x5035716A927DEEB0ULL,
		0x5B8535633D644D42ULL,
		0x0515F8F5B350884DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD478FC8F766042BCULL,
		0xE02ADF7F12346D15ULL,
		0xF7FB910F3F84D467ULL,
		0x97E3ED25A8F4CCFFULL,
		0x7D13F5BFF939F159ULL,
		0xA06AE2D524FBDD60ULL,
		0xB70A6AC67AC89A84ULL,
		0x0A2BF1EB66A1109AULL
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
		0xBC0F89DFE8D2E442ULL,
		0xE4070273238E180DULL,
		0x1E5C1FCDB0BFC3A5ULL,
		0xDC68475515A2BAD0ULL,
		0x53623E287709459FULL,
		0xAD497102FA5DFC06ULL,
		0xE2E40BD00D782A53ULL,
		0x29BDD16C5DA97F49ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x781F13BFD1A5C884ULL,
		0xC80E04E6471C301BULL,
		0x3CB83F9B617F874BULL,
		0xB8D08EAA2B4575A0ULL,
		0xA6C47C50EE128B3FULL,
		0x5A92E205F4BBF80CULL,
		0xC5C817A01AF054A7ULL,
		0x537BA2D8BB52FE93ULL
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
		0xC8F7597F09805266ULL,
		0xA15FE0AC12E7EDC0ULL,
		0x299ACEF8660C4893ULL,
		0x267CCA411ABD8AE4ULL,
		0xE4BF9BF0CA14CBEDULL,
		0x8BE5F9FEF52D4758ULL,
		0x76959F3A3A08983BULL,
		0x22DF1F935F870F95ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x91EEB2FE1300A4CCULL,
		0x42BFC15825CFDB81ULL,
		0x53359DF0CC189127ULL,
		0x4CF99482357B15C8ULL,
		0xC97F37E1942997DAULL,
		0x17CBF3FDEA5A8EB1ULL,
		0xED2B3E7474113077ULL,
		0x45BE3F26BF0E1F2AULL
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
		0x7310D6D8B8038290ULL,
		0x68430D9BB6D3A88DULL,
		0xCBA08B4321207B9DULL,
		0xFF407D80891EA2CAULL,
		0x55B24FA122C8E938ULL,
		0xEA96E9DC3BFACB85ULL,
		0x2915D8752B3FDBD0ULL,
		0x1AD5372E7BB10FD2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE621ADB170070520ULL,
		0xD0861B376DA7511AULL,
		0x974116864240F73AULL,
		0xFE80FB01123D4595ULL,
		0xAB649F424591D271ULL,
		0xD52DD3B877F5970AULL,
		0x522BB0EA567FB7A1ULL,
		0x35AA6E5CF7621FA4ULL
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
		0xE7A82D2164DAD0DCULL,
		0xC6234685B5DECEB8ULL,
		0x85D35D3A4C6B82AEULL,
		0x2C41F979C210BD9BULL,
		0x843C8B21277B87B6ULL,
		0x77D87EF50402FF3FULL,
		0xF80E78471554643BULL,
		0x05CA1123231D30A6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCF505A42C9B5A1B8ULL,
		0x8C468D0B6BBD9D71ULL,
		0x0BA6BA7498D7055DULL,
		0x5883F2F384217B37ULL,
		0x087916424EF70F6CULL,
		0xEFB0FDEA0805FE7FULL,
		0xF01CF08E2AA8C876ULL,
		0x0B942246463A614DULL
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
		0x185A07F03704E0D0ULL,
		0x066714B2F6336AA6ULL,
		0xFDF4D978B2C1E03FULL,
		0x31310CD7DF4E1487ULL,
		0x374F706422CD39FBULL,
		0xC69EB80B3683ED08ULL,
		0xE6DB761681E995C5ULL,
		0x0D9425415B989619ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x30B40FE06E09C1A0ULL,
		0x0CCE2965EC66D54CULL,
		0xFBE9B2F16583C07EULL,
		0x626219AFBE9C290FULL,
		0x6E9EE0C8459A73F6ULL,
		0x8D3D70166D07DA10ULL,
		0xCDB6EC2D03D32B8BULL,
		0x1B284A82B7312C33ULL
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
		0x866C003274F463BEULL,
		0x37E90BDD2F07EE4BULL,
		0x4FE411B990AAFD4BULL,
		0xCC6D59113ABCDAE5ULL,
		0x1BCCF257C139E7B4ULL,
		0xC13D13F14C52C833ULL,
		0x39835CA554054058ULL,
		0x004D892084B53F2DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0CD80064E9E8C77CULL,
		0x6FD217BA5E0FDC97ULL,
		0x9FC823732155FA96ULL,
		0x98DAB2227579B5CAULL,
		0x3799E4AF8273CF69ULL,
		0x827A27E298A59066ULL,
		0x7306B94AA80A80B1ULL,
		0x009B1241096A7E5AULL
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
		0xFF611011B7CF9B78ULL,
		0xF8A824055F76EB22ULL,
		0x59B351B01D26E0B2ULL,
		0x99C2AB10AEED0849ULL,
		0xD32400E77912E83FULL,
		0x1EB7F74B5C3BB8EEULL,
		0xB6A6F6EDFFF98111ULL,
		0x1F21E6BCEE9C1EE9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFEC220236F9F36F0ULL,
		0xF150480ABEEDD645ULL,
		0xB366A3603A4DC165ULL,
		0x338556215DDA1092ULL,
		0xA64801CEF225D07FULL,
		0x3D6FEE96B87771DDULL,
		0x6D4DEDDBFFF30222ULL,
		0x3E43CD79DD383DD3ULL
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
		0xDEF907BF64C383CEULL,
		0x6C6F2C9B3705E16AULL,
		0x8002113AA2939611ULL,
		0x07F7335A300D612AULL,
		0x8F0F01DD1ED6C3E3ULL,
		0xCCB34CC7C1AF58E9ULL,
		0x54668BD25A894514ULL,
		0x2F6A63CAF7D2482FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBDF20F7EC987079CULL,
		0xD8DE59366E0BC2D5ULL,
		0x0004227545272C22ULL,
		0x0FEE66B4601AC255ULL,
		0x1E1E03BA3DAD87C6ULL,
		0x9966998F835EB1D3ULL,
		0xA8CD17A4B5128A29ULL,
		0x5ED4C795EFA4905EULL
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
		0xB9CA5A5ABE47D641ULL,
		0x84499ED22CEA4DECULL,
		0xFDB23C904C626982ULL,
		0x6B3D90E527871EF5ULL,
		0xF1782E3B19E762F7ULL,
		0xD1C6F594C89B6F48ULL,
		0xA7BD69E971AF18A5ULL,
		0x1564C819496CEB18ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7394B4B57C8FAC82ULL,
		0x08933DA459D49BD9ULL,
		0xFB64792098C4D305ULL,
		0xD67B21CA4F0E3DEBULL,
		0xE2F05C7633CEC5EEULL,
		0xA38DEB299136DE91ULL,
		0x4F7AD3D2E35E314BULL,
		0x2AC9903292D9D631ULL
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
		0x8646E02F8E0D17A4ULL,
		0x3E3BACE8F2C5E2BDULL,
		0x0FB29B71D87FE354ULL,
		0x813419B7384127E1ULL,
		0xEE34EC7396DD3AA4ULL,
		0x8A86B83DAE699EFAULL,
		0x8F2455CE82AA9776ULL,
		0x3EE26F2A2B72CDF9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0C8DC05F1C1A2F48ULL,
		0x7C7759D1E58BC57BULL,
		0x1F6536E3B0FFC6A8ULL,
		0x0268336E70824FC2ULL,
		0xDC69D8E72DBA7549ULL,
		0x150D707B5CD33DF5ULL,
		0x1E48AB9D05552EEDULL,
		0x7DC4DE5456E59BF3ULL
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
		0x85B62CDFB17990F3ULL,
		0x2397616E554D15FBULL,
		0x3C5F64F1F33F77DCULL,
		0xB5DC483D3F7FD460ULL,
		0xED2CE41DBE16C569ULL,
		0x328C927B9AA6DD59ULL,
		0x61F474FA5D3A88A4ULL,
		0x15B43B0AD22A6278ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0B6C59BF62F321E6ULL,
		0x472EC2DCAA9A2BF7ULL,
		0x78BEC9E3E67EEFB8ULL,
		0x6BB8907A7EFFA8C0ULL,
		0xDA59C83B7C2D8AD3ULL,
		0x651924F7354DBAB3ULL,
		0xC3E8E9F4BA751148ULL,
		0x2B687615A454C4F0ULL
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
		0x68073A3415E1467AULL,
		0xE273512F2BC08315ULL,
		0x2B55D6E28DFEAE94ULL,
		0x4BF6011F2C3B418BULL,
		0xF3580F7C2A1A0FE5ULL,
		0x52E42CFD6C5811D8ULL,
		0x81182728E12F5846ULL,
		0x1B6C755EC0CF3633ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD00E74682BC28CF4ULL,
		0xC4E6A25E5781062AULL,
		0x56ABADC51BFD5D29ULL,
		0x97EC023E58768316ULL,
		0xE6B01EF854341FCAULL,
		0xA5C859FAD8B023B1ULL,
		0x02304E51C25EB08CULL,
		0x36D8EABD819E6C67ULL
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
		0x8CACE40EB78BCB37ULL,
		0xEFF0D733301F15B3ULL,
		0xA4F0E423A5776203ULL,
		0x5FDBBC2749E742FFULL,
		0x8DFBA9DE3404661DULL,
		0x82340D9AEDB0248BULL,
		0x8FF1D3F43B3EFD62ULL,
		0x172223F023F57A28ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1959C81D6F17966EULL,
		0xDFE1AE66603E2B67ULL,
		0x49E1C8474AEEC407ULL,
		0xBFB7784E93CE85FFULL,
		0x1BF753BC6808CC3AULL,
		0x04681B35DB604917ULL,
		0x1FE3A7E8767DFAC5ULL,
		0x2E4447E047EAF451ULL
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
		0xB1D2353D50962778ULL,
		0x14EA12FFCC2ABA2EULL,
		0x2D6B2463C546C144ULL,
		0xBF015377406017E6ULL,
		0x8C56F13E8306CF68ULL,
		0x6113191AB3752FCFULL,
		0xF89494910A8DC8C4ULL,
		0x388B17FF168B32C2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x63A46A7AA12C4EF0ULL,
		0x29D425FF9855745DULL,
		0x5AD648C78A8D8288ULL,
		0x7E02A6EE80C02FCCULL,
		0x18ADE27D060D9ED1ULL,
		0xC226323566EA5F9FULL,
		0xF1292922151B9188ULL,
		0x71162FFE2D166585ULL
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
		0x149E3D2A61F20576ULL,
		0xB29849473297ABF0ULL,
		0x1577258CF48279C8ULL,
		0x2202A9CA36322CE0ULL,
		0x6A0F823BC538FB4EULL,
		0xC1090C294A39A4DAULL,
		0xECDFF8B959E6DD6AULL,
		0x2104195834A25906ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x293C7A54C3E40AECULL,
		0x6530928E652F57E0ULL,
		0x2AEE4B19E904F391ULL,
		0x440553946C6459C0ULL,
		0xD41F04778A71F69CULL,
		0x82121852947349B4ULL,
		0xD9BFF172B3CDBAD5ULL,
		0x420832B06944B20DULL
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
		0x0D57CB5B886EB06BULL,
		0x834F6BEAB784A29EULL,
		0xFD770FA2DFEA8A93ULL,
		0xC057F9A3FD9B0DD4ULL,
		0x31610A2FDE7AFCB0ULL,
		0x3D5AF2A7CB478180ULL,
		0xE3F94DB66CD18AF2ULL,
		0x1D876BF620740D89ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1AAF96B710DD60D6ULL,
		0x069ED7D56F09453CULL,
		0xFAEE1F45BFD51527ULL,
		0x80AFF347FB361BA9ULL,
		0x62C2145FBCF5F961ULL,
		0x7AB5E54F968F0300ULL,
		0xC7F29B6CD9A315E4ULL,
		0x3B0ED7EC40E81B13ULL
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
		0x39C47B2533AFFAF2ULL,
		0x0A6A89CF3B2F194CULL,
		0x55713405613AD6A2ULL,
		0xF2123ACBAEE1C90CULL,
		0x4A85C10FECB5F6ACULL,
		0xFFEBAAC715033DD4ULL,
		0xFEEA68E1142CF317ULL,
		0x3A5BDB5F784B8C2FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7388F64A675FF5E4ULL,
		0x14D5139E765E3298ULL,
		0xAAE2680AC275AD44ULL,
		0xE42475975DC39218ULL,
		0x950B821FD96BED59ULL,
		0xFFD7558E2A067BA8ULL,
		0xFDD4D1C22859E62FULL,
		0x74B7B6BEF097185FULL
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
		0x570A4889BA6339DFULL,
		0x7FE0FD9CF5849E81ULL,
		0xA4A032CF7B98DAE4ULL,
		0x35FEC1373BC66A28ULL,
		0xB5F39FAC25ACACE5ULL,
		0xBD140E9C381D8E2DULL,
		0x85DE5AA75B167571ULL,
		0x2492BFF2732741D8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAE14911374C673BEULL,
		0xFFC1FB39EB093D02ULL,
		0x4940659EF731B5C8ULL,
		0x6BFD826E778CD451ULL,
		0x6BE73F584B5959CAULL,
		0x7A281D38703B1C5BULL,
		0x0BBCB54EB62CEAE3ULL,
		0x49257FE4E64E83B1ULL
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
		0xE58063A0553CA0C5ULL,
		0x9F9DF30FFFD78BB9ULL,
		0x82972510A0A9386DULL,
		0x193A21644CDE2C7FULL,
		0x88BF4C0BB905D98DULL,
		0xE855E4F98A3621B0ULL,
		0x90AA27D191595ECCULL,
		0x324ABE68B28F5583ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCB00C740AA79418AULL,
		0x3F3BE61FFFAF1773ULL,
		0x052E4A21415270DBULL,
		0x327442C899BC58FFULL,
		0x117E9817720BB31AULL,
		0xD0ABC9F3146C4361ULL,
		0x21544FA322B2BD99ULL,
		0x64957CD1651EAB07ULL
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
		0xEC595D18A0FBE075ULL,
		0x53170C368CF565E3ULL,
		0x345FE64FF2EF7C4EULL,
		0x42DDDF46A85907ACULL,
		0x9B0AF00F31E91EE9ULL,
		0x174F08721688857BULL,
		0x2CB8F96C108AC25DULL,
		0x043C9AA073093EAFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD8B2BA3141F7C0EAULL,
		0xA62E186D19EACBC7ULL,
		0x68BFCC9FE5DEF89CULL,
		0x85BBBE8D50B20F58ULL,
		0x3615E01E63D23DD2ULL,
		0x2E9E10E42D110AF7ULL,
		0x5971F2D8211584BAULL,
		0x08793540E6127D5EULL
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
		0xFF991AB64B199A95ULL,
		0xAED09436203FCB7AULL,
		0x87681A0E7B0F25ACULL,
		0xAF9AF00F59D8A8D9ULL,
		0x4BE8BDD0E0426571ULL,
		0x438B3F0DF500FB38ULL,
		0xA1DCC71A0FE22100ULL,
		0x07BE28CBE47B2FFDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFF32356C9633352AULL,
		0x5DA1286C407F96F5ULL,
		0x0ED0341CF61E4B59ULL,
		0x5F35E01EB3B151B3ULL,
		0x97D17BA1C084CAE3ULL,
		0x87167E1BEA01F670ULL,
		0x43B98E341FC44200ULL,
		0x0F7C5197C8F65FFBULL
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
		0x679466DAC8E3504AULL,
		0xB30C7E01FB1A0F4BULL,
		0x5BC4BFD4F454B392ULL,
		0x3F96E07F72EE3D11ULL,
		0xBCFD1A69BEF24D75ULL,
		0xD6A3E986A23D3655ULL,
		0xD871DB3C4E9C8612ULL,
		0x14DB425BE93D9C2DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCF28CDB591C6A094ULL,
		0x6618FC03F6341E96ULL,
		0xB7897FA9E8A96725ULL,
		0x7F2DC0FEE5DC7A22ULL,
		0x79FA34D37DE49AEAULL,
		0xAD47D30D447A6CABULL,
		0xB0E3B6789D390C25ULL,
		0x29B684B7D27B385BULL
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
		0x3FDEFCD2FF3048CBULL,
		0x4603BC99C7999553ULL,
		0x3ED39AEA9B6408AEULL,
		0xA9D3CF5B79BBB7FBULL,
		0x894B9FEBC164F77EULL,
		0xD7DE3EF20347B19CULL,
		0xF0C7B1D84E193BB5ULL,
		0x25EA8AF8FE8BC9C1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7FBDF9A5FE609196ULL,
		0x8C0779338F332AA6ULL,
		0x7DA735D536C8115CULL,
		0x53A79EB6F3776FF6ULL,
		0x12973FD782C9EEFDULL,
		0xAFBC7DE4068F6339ULL,
		0xE18F63B09C32776BULL,
		0x4BD515F1FD179383ULL
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
		0x080AC8D31AD7CC64ULL,
		0x0A6179722F25DF7AULL,
		0x7D22973F2DA2B404ULL,
		0xD687A4902EECF438ULL,
		0x716E9E74D8D851EBULL,
		0xD6AEE7499D5D09F2ULL,
		0x2040D5FC98D64D4FULL,
		0x0582C2F7905A1220ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x101591A635AF98C8ULL,
		0x14C2F2E45E4BBEF4ULL,
		0xFA452E7E5B456808ULL,
		0xAD0F49205DD9E870ULL,
		0xE2DD3CE9B1B0A3D7ULL,
		0xAD5DCE933ABA13E4ULL,
		0x4081ABF931AC9A9FULL,
		0x0B0585EF20B42440ULL
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
		0x5F10D027D9AD5D4BULL,
		0xE1F9239251B0EDF6ULL,
		0xCB889BBEC057E527ULL,
		0x3CF37D5223DFD560ULL,
		0xD80A281A3FE6D9C2ULL,
		0x805BD92C8F4F439FULL,
		0x5F2281AB5C5730D8ULL,
		0x3E2F241788BDEC4EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBE21A04FB35ABA96ULL,
		0xC3F24724A361DBECULL,
		0x9711377D80AFCA4FULL,
		0x79E6FAA447BFAAC1ULL,
		0xB01450347FCDB384ULL,
		0x00B7B2591E9E873FULL,
		0xBE450356B8AE61B1ULL,
		0x7C5E482F117BD89CULL
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
		0x5314A2A7E0633237ULL,
		0x798A82A8A763BC1CULL,
		0x283517FCF595427DULL,
		0x6FB7A6D29B5F1975ULL,
		0x949AE4247E5B83A0ULL,
		0x6BAC26031619130CULL,
		0x5B524AD4A7789568ULL,
		0x3918ADD1D24734CAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA629454FC0C6646EULL,
		0xF31505514EC77838ULL,
		0x506A2FF9EB2A84FAULL,
		0xDF6F4DA536BE32EAULL,
		0x2935C848FCB70740ULL,
		0xD7584C062C322619ULL,
		0xB6A495A94EF12AD0ULL,
		0x72315BA3A48E6994ULL
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
		0x890E01476B18776EULL,
		0x9F14FD7411C4E8C3ULL,
		0x5F0219B16925713CULL,
		0x13591D75014549D8ULL,
		0xF66ABA1080583A1FULL,
		0x8B3CA20A80B14A4BULL,
		0xE4315362C1AAE9FBULL,
		0x2B8E1211AAA01EB4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x121C028ED630EEDCULL,
		0x3E29FAE82389D187ULL,
		0xBE043362D24AE279ULL,
		0x26B23AEA028A93B0ULL,
		0xECD5742100B0743EULL,
		0x1679441501629497ULL,
		0xC862A6C58355D3F7ULL,
		0x571C242355403D69ULL
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
		0x4FE790AFD1F3FE09ULL,
		0x71E35D50670A0672ULL,
		0xBD6781445059E79AULL,
		0x66DAE7D93E148688ULL,
		0xDB20305DF43DDBE5ULL,
		0x6F5C2229899CC538ULL,
		0x68DF11DDCF3B82C3ULL,
		0x1C2809E913875CE8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9FCF215FA3E7FC12ULL,
		0xE3C6BAA0CE140CE4ULL,
		0x7ACF0288A0B3CF34ULL,
		0xCDB5CFB27C290D11ULL,
		0xB64060BBE87BB7CAULL,
		0xDEB8445313398A71ULL,
		0xD1BE23BB9E770586ULL,
		0x385013D2270EB9D0ULL
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
		0x71EF9DA6AD268EF9ULL,
		0xDFF65417A03BD687ULL,
		0x6FCA59AA395F0A5BULL,
		0x3E060A1285D84822ULL,
		0x6988DB4021D650FAULL,
		0xBE25CFB5FEA9A024ULL,
		0x2298E372D3CD97E6ULL,
		0x0AB04181A69C58B8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE3DF3B4D5A4D1DF2ULL,
		0xBFECA82F4077AD0EULL,
		0xDF94B35472BE14B7ULL,
		0x7C0C14250BB09044ULL,
		0xD311B68043ACA1F4ULL,
		0x7C4B9F6BFD534048ULL,
		0x4531C6E5A79B2FCDULL,
		0x156083034D38B170ULL
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
		0x987A544BF3CB562DULL,
		0x78DC2D6286C24C3AULL,
		0xCF8F054CA5EB93C6ULL,
		0xCBD330625FE7C4E3ULL,
		0xF6CDF741A82A6C9CULL,
		0xEF0FB6A903FE1011ULL,
		0x4E60D6A5DC8A9011ULL,
		0x0C992E7EE582C98DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x30F4A897E796AC5AULL,
		0xF1B85AC50D849875ULL,
		0x9F1E0A994BD7278CULL,
		0x97A660C4BFCF89C7ULL,
		0xED9BEE835054D939ULL,
		0xDE1F6D5207FC2023ULL,
		0x9CC1AD4BB9152023ULL,
		0x19325CFDCB05931AULL
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
		0xEB8A3296A69D57D6ULL,
		0xF828DBD82CA35B60ULL,
		0x1BD9220C2B4E3BE4ULL,
		0x3DD9FA516006D692ULL,
		0xB08F749D198607D4ULL,
		0xC4D6DE86B6CCAE00ULL,
		0x84F6D5189F4E15CAULL,
		0x204D954DA10E861EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD714652D4D3AAFACULL,
		0xF051B7B05946B6C1ULL,
		0x37B24418569C77C9ULL,
		0x7BB3F4A2C00DAD24ULL,
		0x611EE93A330C0FA8ULL,
		0x89ADBD0D6D995C01ULL,
		0x09EDAA313E9C2B95ULL,
		0x409B2A9B421D0C3DULL
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
		0xEE98EE8C79285C9FULL,
		0xF75BAAACE81D5734ULL,
		0x5A656ECD9DD05D2EULL,
		0x567613430D7A7983ULL,
		0x2AC76AA7431B9722ULL,
		0x8514AF124D9DD4B4ULL,
		0x0F8DFC6986968BD9ULL,
		0x06202996CB229BA6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDD31DD18F250B93EULL,
		0xEEB75559D03AAE69ULL,
		0xB4CADD9B3BA0BA5DULL,
		0xACEC26861AF4F306ULL,
		0x558ED54E86372E44ULL,
		0x0A295E249B3BA968ULL,
		0x1F1BF8D30D2D17B3ULL,
		0x0C40532D9645374CULL
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
		0x383F2298C429DA01ULL,
		0x356B6FA9A0DDCEBEULL,
		0x20230F440DD237FEULL,
		0x8BBCC0596AD11D5FULL,
		0xCC6BD8139203D441ULL,
		0x35468855822A9547ULL,
		0xD5506E0C9DDB0C37ULL,
		0x0BD737C17DB37C81ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x707E45318853B402ULL,
		0x6AD6DF5341BB9D7CULL,
		0x40461E881BA46FFCULL,
		0x177980B2D5A23ABEULL,
		0x98D7B0272407A883ULL,
		0x6A8D10AB04552A8FULL,
		0xAAA0DC193BB6186EULL,
		0x17AE6F82FB66F903ULL
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
		0x9C86B340B22ABB89ULL,
		0x75AE9BDD7FEFCB12ULL,
		0x1BF4B04D84E8184BULL,
		0x5CD50F2A8AA81276ULL,
		0xF84D854D3133EAA4ULL,
		0x181767DC2F506001ULL,
		0x75765EC1883ADD35ULL,
		0x3D6CFA91E85B3FBDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x390D668164557712ULL,
		0xEB5D37BAFFDF9625ULL,
		0x37E9609B09D03096ULL,
		0xB9AA1E55155024ECULL,
		0xF09B0A9A6267D548ULL,
		0x302ECFB85EA0C003ULL,
		0xEAECBD831075BA6AULL,
		0x7AD9F523D0B67F7AULL
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
		0xC8ED9246E4F8404BULL,
		0x3382E388B2766B01ULL,
		0xD9EDA532A2F87E03ULL,
		0xB0A2CFC0218D286AULL,
		0x96EA4368E68361D9ULL,
		0x044ACE2567D9C19FULL,
		0xA42BBDA9B6BA6900ULL,
		0x170E5CF4367673D9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x91DB248DC9F08096ULL,
		0x6705C71164ECD603ULL,
		0xB3DB4A6545F0FC06ULL,
		0x61459F80431A50D5ULL,
		0x2DD486D1CD06C3B3ULL,
		0x08959C4ACFB3833FULL,
		0x48577B536D74D200ULL,
		0x2E1CB9E86CECE7B3ULL
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
		0x30D6A2DEE791706DULL,
		0x9E435AA7BEBA9DABULL,
		0x53FDAAF5A9D817E8ULL,
		0xC406C163BEDE7134ULL,
		0x87C0F32ACB7EBC29ULL,
		0x448F6D5B572333E9ULL,
		0xA5B1913EABF9A916ULL,
		0x3585EB5372FB1066ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x61AD45BDCF22E0DAULL,
		0x3C86B54F7D753B56ULL,
		0xA7FB55EB53B02FD1ULL,
		0x880D82C77DBCE268ULL,
		0x0F81E65596FD7853ULL,
		0x891EDAB6AE4667D3ULL,
		0x4B63227D57F3522CULL,
		0x6B0BD6A6E5F620CDULL
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
		0x249624850C5101FFULL,
		0xAE71ED68AB6F9ABAULL,
		0x07717268FDE6A394ULL,
		0xB2395E11F51BC52EULL,
		0x46410B8718A83130ULL,
		0x15489F7628F3A185ULL,
		0xBF34744FA01E5DCCULL,
		0x28540E537A31FAA1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x492C490A18A203FEULL,
		0x5CE3DAD156DF3574ULL,
		0x0EE2E4D1FBCD4729ULL,
		0x6472BC23EA378A5CULL,
		0x8C82170E31506261ULL,
		0x2A913EEC51E7430AULL,
		0x7E68E89F403CBB98ULL,
		0x50A81CA6F463F543ULL
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
		0x75E059E544EB67C8ULL,
		0xB2E1E5BA920EEF3EULL,
		0xEBFED7D886AA5A0FULL,
		0xD2E88BA6690CEF64ULL,
		0xF78FA71190BE488DULL,
		0x0D1247F370AA5425ULL,
		0x610ADC2C8665E9DDULL,
		0x2C8C092F205D5595ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEBC0B3CA89D6CF90ULL,
		0x65C3CB75241DDE7CULL,
		0xD7FDAFB10D54B41FULL,
		0xA5D1174CD219DEC9ULL,
		0xEF1F4E23217C911BULL,
		0x1A248FE6E154A84BULL,
		0xC215B8590CCBD3BAULL,
		0x5918125E40BAAB2AULL
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
		0xB7F9F5E7A1E932BBULL,
		0x2FBE16EEB2FA32F4ULL,
		0xD1059C2B9C4DD285ULL,
		0x5C49E125B1EF1969ULL,
		0x9115E04CDF76CC36ULL,
		0x2310DB329D374B19ULL,
		0x2774EAD4F62F079BULL,
		0x28F05F61DFB00D37ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6FF3EBCF43D26576ULL,
		0x5F7C2DDD65F465E9ULL,
		0xA20B3857389BA50AULL,
		0xB893C24B63DE32D3ULL,
		0x222BC099BEED986CULL,
		0x4621B6653A6E9633ULL,
		0x4EE9D5A9EC5E0F36ULL,
		0x51E0BEC3BF601A6EULL
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
		0xB91C04986B27BF8DULL,
		0x93F6B99796EE9FBBULL,
		0x972483D1C77C9F10ULL,
		0x901EC27192FFB192ULL,
		0xC9F23D9FBAADCF6BULL,
		0x3C6B33A3760D1994ULL,
		0x6587933A11F0A48AULL,
		0x0C7A6653CF8B4D84ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x72380930D64F7F1AULL,
		0x27ED732F2DDD3F77ULL,
		0x2E4907A38EF93E21ULL,
		0x203D84E325FF6325ULL,
		0x93E47B3F755B9ED7ULL,
		0x78D66746EC1A3329ULL,
		0xCB0F267423E14914ULL,
		0x18F4CCA79F169B08ULL
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
		0x400D4DED9FF39EDDULL,
		0xEB0A3BE22B1B7C25ULL,
		0x17E81FADE6998824ULL,
		0x038A9A6AF067F2C7ULL,
		0x2595D9257D90D5BAULL,
		0xC8586F038E57633CULL,
		0xDB6A18CEDF6574DCULL,
		0x208F42D59CF48D71ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x801A9BDB3FE73DBAULL,
		0xD61477C45636F84AULL,
		0x2FD03F5BCD331049ULL,
		0x071534D5E0CFE58EULL,
		0x4B2BB24AFB21AB74ULL,
		0x90B0DE071CAEC678ULL,
		0xB6D4319DBECAE9B9ULL,
		0x411E85AB39E91AE3ULL
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
		0x047D9BDF7119C36FULL,
		0x215EAE88476E6C5CULL,
		0x710442F76CE25932ULL,
		0xBE7DCC563EC8AEFBULL,
		0x8C0DB473639A5F94ULL,
		0xA9D8949A97AA1B30ULL,
		0x930106809C96C4A8ULL,
		0x3FC0D1FC9497462CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x08FB37BEE23386DEULL,
		0x42BD5D108EDCD8B8ULL,
		0xE20885EED9C4B264ULL,
		0x7CFB98AC7D915DF6ULL,
		0x181B68E6C734BF29ULL,
		0x53B129352F543661ULL,
		0x26020D01392D8951ULL,
		0x7F81A3F9292E8C59ULL
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
		0xC12E9D2C066310D7ULL,
		0xAF862B8B96AF11ABULL,
		0x674CC415F1DD120DULL,
		0xF640E6A88CFE81A1ULL,
		0x59362DC61A20CD0EULL,
		0x73B2F81DEBAA6E38ULL,
		0x293D31B1CE1EC087ULL,
		0x3D9A63118FE0B2E7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x825D3A580CC621AEULL,
		0x5F0C57172D5E2357ULL,
		0xCE99882BE3BA241BULL,
		0xEC81CD5119FD0342ULL,
		0xB26C5B8C34419A1DULL,
		0xE765F03BD754DC70ULL,
		0x527A63639C3D810EULL,
		0x7B34C6231FC165CEULL
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
		0x6855881F464C8334ULL,
		0x3EF082E4DD22D9A9ULL,
		0xE277C4F4EBA11AFFULL,
		0xBE1A88D77728AA12ULL,
		0xF5B9E369ECDFFE83ULL,
		0x7F0C1B0359073901ULL,
		0x3177410CCE95E3CEULL,
		0x1E20A1A48BA61282ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD0AB103E8C990668ULL,
		0x7DE105C9BA45B352ULL,
		0xC4EF89E9D74235FEULL,
		0x7C3511AEEE515425ULL,
		0xEB73C6D3D9BFFD07ULL,
		0xFE183606B20E7203ULL,
		0x62EE82199D2BC79CULL,
		0x3C414349174C2504ULL
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
		0xA45E9EF65FE95F1AULL,
		0x116A6EDBB9C931C1ULL,
		0x298D208EABEFE6E6ULL,
		0x5C096401914C7404ULL,
		0x995339DD893655E5ULL,
		0x751717555DADCB5AULL,
		0xC803EBFAA6FFC923ULL,
		0x3CBD801AEA232395ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x48BD3DECBFD2BE34ULL,
		0x22D4DDB773926383ULL,
		0x531A411D57DFCDCCULL,
		0xB812C8032298E808ULL,
		0x32A673BB126CABCAULL,
		0xEA2E2EAABB5B96B5ULL,
		0x9007D7F54DFF9246ULL,
		0x797B0035D446472BULL
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
		0x9D62EABA9F641458ULL,
		0x136769317B314F60ULL,
		0x5817964F9773F351ULL,
		0x0822EAE68418A8CCULL,
		0x16FDD092BFBE442CULL,
		0xFAAC7FF822731AF8ULL,
		0xD89AB2D231B88593ULL,
		0x012DE3B9C0D328CBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3AC5D5753EC828B0ULL,
		0x26CED262F6629EC1ULL,
		0xB02F2C9F2EE7E6A2ULL,
		0x1045D5CD08315198ULL,
		0x2DFBA1257F7C8858ULL,
		0xF558FFF044E635F0ULL,
		0xB13565A463710B27ULL,
		0x025BC77381A65197ULL
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
		0x616D9AE9F8E979F0ULL,
		0x3478E14643074B7AULL,
		0x41D9282BD3FA4C74ULL,
		0xB3D3BA9C45EE3652ULL,
		0x80ECB311EF69A819ULL,
		0x21BDE9BC3788DD28ULL,
		0xF2A03201A9929EC8ULL,
		0x13385976D77D8573ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC2DB35D3F1D2F3E0ULL,
		0x68F1C28C860E96F4ULL,
		0x83B25057A7F498E8ULL,
		0x67A775388BDC6CA4ULL,
		0x01D96623DED35033ULL,
		0x437BD3786F11BA51ULL,
		0xE540640353253D90ULL,
		0x2670B2EDAEFB0AE7ULL
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
		0xB32359CE78BAA22BULL,
		0xB66A761D72F5B2C5ULL,
		0x4DA909096575248BULL,
		0x14FAAF883BC5909BULL,
		0xAEA1390ABD59A994ULL,
		0x2D828B26B530D9A8ULL,
		0xD11386B9B8C234EDULL,
		0x3FBCA987E6917775ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6646B39CF1754456ULL,
		0x6CD4EC3AE5EB658BULL,
		0x9B521212CAEA4917ULL,
		0x29F55F10778B2136ULL,
		0x5D4272157AB35328ULL,
		0x5B05164D6A61B351ULL,
		0xA2270D73718469DAULL,
		0x7F79530FCD22EEEBULL
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
		0x5602FE2D82906E67ULL,
		0xA42FCA1B0E475C88ULL,
		0x8B78ADFAE1240473ULL,
		0x215F60EA406E9F0EULL,
		0xFA0E4973FE256FF6ULL,
		0x2ADCA969247682BBULL,
		0x54C1C78BF4A69471ULL,
		0x38036AEEF2AE22B8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAC05FC5B0520DCCEULL,
		0x485F94361C8EB910ULL,
		0x16F15BF5C24808E7ULL,
		0x42BEC1D480DD3E1DULL,
		0xF41C92E7FC4ADFECULL,
		0x55B952D248ED0577ULL,
		0xA9838F17E94D28E2ULL,
		0x7006D5DDE55C4570ULL
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
		0x1CE8D12A960EDB79ULL,
		0xEEC8B372DE977235ULL,
		0x50DA062CE08D8FF2ULL,
		0x31587DBE9C6AED41ULL,
		0x910B7B39A18B790AULL,
		0x9B319F4F8656AA9BULL,
		0x084DE682EB49DF8BULL,
		0x1FF3AA14E93F8A31ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x39D1A2552C1DB6F2ULL,
		0xDD9166E5BD2EE46AULL,
		0xA1B40C59C11B1FE5ULL,
		0x62B0FB7D38D5DA82ULL,
		0x2216F6734316F214ULL,
		0x36633E9F0CAD5537ULL,
		0x109BCD05D693BF17ULL,
		0x3FE75429D27F1462ULL
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
		0x0C10126E62B8C8EFULL,
		0x676C05059ED84764ULL,
		0x445ED03D49CC2941ULL,
		0xFAAC0D7EA2729F19ULL,
		0xF3DB2530D1A53688ULL,
		0xCC21401D8D485CEFULL,
		0xA583D4902F844BC1ULL,
		0x3ED1AB4C70F744D2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x182024DCC57191DEULL,
		0xCED80A0B3DB08EC8ULL,
		0x88BDA07A93985282ULL,
		0xF5581AFD44E53E32ULL,
		0xE7B64A61A34A6D11ULL,
		0x9842803B1A90B9DFULL,
		0x4B07A9205F089783ULL,
		0x7DA35698E1EE89A5ULL
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
		0x5689105576DC99AEULL,
		0x798F98BE46F36700ULL,
		0xE51C7B39BB68BC41ULL,
		0xD920E82AFC82778AULL,
		0xD8284057D20EE1BDULL,
		0x23B854DA79ADD23CULL,
		0x8AF213D0C1D087CBULL,
		0x1D0B1B3AC283F5EFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAD1220AAEDB9335CULL,
		0xF31F317C8DE6CE00ULL,
		0xCA38F67376D17882ULL,
		0xB241D055F904EF15ULL,
		0xB05080AFA41DC37BULL,
		0x4770A9B4F35BA479ULL,
		0x15E427A183A10F96ULL,
		0x3A1636758507EBDFULL
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
		0x9D7CA2067DE672BAULL,
		0xCEEF7430AE73AC44ULL,
		0xBFBF4FDA2145FEDDULL,
		0xCCC32C7B01D67BA6ULL,
		0xE18E1D3157C6FC4EULL,
		0x825B078E070522D9ULL,
		0x30FAA3DA7140A003ULL,
		0x2C0716041B9C4EA2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3AF9440CFBCCE574ULL,
		0x9DDEE8615CE75889ULL,
		0x7F7E9FB4428BFDBBULL,
		0x998658F603ACF74DULL,
		0xC31C3A62AF8DF89DULL,
		0x04B60F1C0E0A45B3ULL,
		0x61F547B4E2814007ULL,
		0x580E2C0837389D44ULL
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
		0x5BD15F8C24A0D767ULL,
		0xE459536F9ABD1969ULL,
		0x6E76E82B8A94591BULL,
		0x48450C97A717B48AULL,
		0x71C64776B3BD6AABULL,
		0x8A2F174B36C04D33ULL,
		0xBD8508E1CD5CBCF3ULL,
		0x1CBF0F0EDEB5C5AEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB7A2BF184941AECEULL,
		0xC8B2A6DF357A32D2ULL,
		0xDCEDD0571528B237ULL,
		0x908A192F4E2F6914ULL,
		0xE38C8EED677AD556ULL,
		0x145E2E966D809A66ULL,
		0x7B0A11C39AB979E7ULL,
		0x397E1E1DBD6B8B5DULL
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
		0x793E5A5666D77669ULL,
		0xB82B6496AD57A2F5ULL,
		0x77BD0B9C86CC2CABULL,
		0x6D5786C005795C6CULL,
		0xA0704B2A530DB06FULL,
		0xA1A95BD76CB1A31CULL,
		0xFD5818358FEECC56ULL,
		0x29A058280FBC675CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF27CB4ACCDAEECD2ULL,
		0x7056C92D5AAF45EAULL,
		0xEF7A17390D985957ULL,
		0xDAAF0D800AF2B8D8ULL,
		0x40E09654A61B60DEULL,
		0x4352B7AED9634639ULL,
		0xFAB0306B1FDD98ADULL,
		0x5340B0501F78CEB9ULL
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
		0xF48A5D6D180292F7ULL,
		0x890FA31C8028EE70ULL,
		0x0C13A2D95DD9695AULL,
		0x443D20CCEF117AB5ULL,
		0x29FE127CCA98390EULL,
		0x37B93492F035781AULL,
		0xBA32F4081CB4CF30ULL,
		0x3FDF898C7AEE6285ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE914BADA300525EEULL,
		0x121F46390051DCE1ULL,
		0x182745B2BBB2D2B5ULL,
		0x887A4199DE22F56AULL,
		0x53FC24F99530721CULL,
		0x6F726925E06AF034ULL,
		0x7465E81039699E60ULL,
		0x7FBF1318F5DCC50BULL
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
		0x63D28744444E6D36ULL,
		0x69DF69B9785DDB5DULL,
		0xA36FEFBED08A183FULL,
		0x27C5C185BECB59FCULL,
		0x94904F2FB9211EE6ULL,
		0x64915B319EEEB82FULL,
		0x26B797B717E0A2D2ULL,
		0x3893C927EEA613FDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC7A50E88889CDA6CULL,
		0xD3BED372F0BBB6BAULL,
		0x46DFDF7DA114307EULL,
		0x4F8B830B7D96B3F9ULL,
		0x29209E5F72423DCCULL,
		0xC922B6633DDD705FULL,
		0x4D6F2F6E2FC145A4ULL,
		0x7127924FDD4C27FAULL
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
		0x5C35987D50DF32A9ULL,
		0x20DEF63A0930B4ACULL,
		0xCAC793F458B34BBCULL,
		0x2BBD75571BADD0A6ULL,
		0x6C3915418424B63BULL,
		0x408A991229A4AE07ULL,
		0x804D2E8A460092BAULL,
		0x3BA57A98B3533561ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB86B30FAA1BE6552ULL,
		0x41BDEC7412616958ULL,
		0x958F27E8B1669778ULL,
		0x577AEAAE375BA14DULL,
		0xD8722A8308496C76ULL,
		0x8115322453495C0EULL,
		0x009A5D148C012574ULL,
		0x774AF53166A66AC3ULL
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
		0xD7B9936AF69D1738ULL,
		0x03B4207EF570E01EULL,
		0xF9040EE65BC700BCULL,
		0x0BE096254E12C2BDULL,
		0x470415BA6D994BADULL,
		0xA001D41EB7049052ULL,
		0x9BAF87E5DF7741F5ULL,
		0x038344FDE5D90978ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF7326D5ED3A2E70ULL,
		0x076840FDEAE1C03DULL,
		0xF2081DCCB78E0178ULL,
		0x17C12C4A9C25857BULL,
		0x8E082B74DB32975AULL,
		0x4003A83D6E0920A4ULL,
		0x375F0FCBBEEE83EBULL,
		0x070689FBCBB212F1ULL
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
		0x3F065F6F93CB3BA0ULL,
		0x4130C7BA3053DAC9ULL,
		0x5D9E105C0776719CULL,
		0x7447482590A7A93CULL,
		0x27A4FF1F41898F3DULL,
		0xFDF379C3E39BCB76ULL,
		0xA0397C9299A728FBULL,
		0x0BE0BEBB030BC251ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7E0CBEDF27967740ULL,
		0x82618F7460A7B592ULL,
		0xBB3C20B80EECE338ULL,
		0xE88E904B214F5278ULL,
		0x4F49FE3E83131E7AULL,
		0xFBE6F387C73796ECULL,
		0x4072F925334E51F7ULL,
		0x17C17D76061784A3ULL
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
		0x00FF41465017C2AEULL,
		0x828021E96ECE58D1ULL,
		0x5280374EC82B5823ULL,
		0x63AC940CC07DCF0AULL,
		0x4F868F25927D06A0ULL,
		0x792A8A1376EEB90DULL,
		0xC67E2AE407E62C43ULL,
		0x25B70784E8241840ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x01FE828CA02F855CULL,
		0x050043D2DD9CB1A2ULL,
		0xA5006E9D9056B047ULL,
		0xC759281980FB9E14ULL,
		0x9F0D1E4B24FA0D40ULL,
		0xF2551426EDDD721AULL,
		0x8CFC55C80FCC5886ULL,
		0x4B6E0F09D0483081ULL
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
		0x2ABC651942E60EC2ULL,
		0x1FC04447855EE57BULL,
		0x8D38C9F52F3034ACULL,
		0x26AE3E2E4962D288ULL,
		0xC8DF05BB2582819FULL,
		0x150B3B59771906FBULL,
		0xE602DBDCB940A246ULL,
		0x3ACDF44EA4C58E33ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5578CA3285CC1D84ULL,
		0x3F80888F0ABDCAF6ULL,
		0x1A7193EA5E606958ULL,
		0x4D5C7C5C92C5A511ULL,
		0x91BE0B764B05033EULL,
		0x2A1676B2EE320DF7ULL,
		0xCC05B7B97281448CULL,
		0x759BE89D498B1C67ULL
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
		0xB65785DDE61F2F1BULL,
		0xCE7DAEA3F13FB5D2ULL,
		0x616B7842616C8A0DULL,
		0x42E29F65564F8712ULL,
		0x06E310BFE336DF3EULL,
		0x17903CA6BB5FC2D2ULL,
		0x0A094AF668BAAF61ULL,
		0x16BF65CF9789C1DAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6CAF0BBBCC3E5E36ULL,
		0x9CFB5D47E27F6BA5ULL,
		0xC2D6F084C2D9141BULL,
		0x85C53ECAAC9F0E24ULL,
		0x0DC6217FC66DBE7CULL,
		0x2F20794D76BF85A4ULL,
		0x141295ECD1755EC2ULL,
		0x2D7ECB9F2F1383B4ULL
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
		0xF6303BD25519FCCCULL,
		0x6F46967B80559212ULL,
		0xF9A7D0F2A7942B12ULL,
		0x7D92EF684BFFEFC1ULL,
		0xE7C387C4C0CEFC6CULL,
		0xD59673E29D8BE697ULL,
		0x1E2A53F4C8F5CBFEULL,
		0x1DCD20429BDE0105ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEC6077A4AA33F998ULL,
		0xDE8D2CF700AB2425ULL,
		0xF34FA1E54F285624ULL,
		0xFB25DED097FFDF83ULL,
		0xCF870F89819DF8D8ULL,
		0xAB2CE7C53B17CD2FULL,
		0x3C54A7E991EB97FDULL,
		0x3B9A408537BC020AULL
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
		0x94172E9960A7BF09ULL,
		0x5FFBE97A1FD1CEB1ULL,
		0xC31A720C1CB311B7ULL,
		0x270EF16A7B40B151ULL,
		0x0699C8AFB8EBCF11ULL,
		0xF1D19807DC4822B3ULL,
		0xFAB7F5FD19E831BCULL,
		0x0C8A849F20FF2985ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x282E5D32C14F7E12ULL,
		0xBFF7D2F43FA39D63ULL,
		0x8634E4183966236EULL,
		0x4E1DE2D4F68162A3ULL,
		0x0D33915F71D79E22ULL,
		0xE3A3300FB8904566ULL,
		0xF56FEBFA33D06379ULL,
		0x1915093E41FE530BULL
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
		0x5ACCC1CCCA8D9FD1ULL,
		0xF2497071CC4D14A3ULL,
		0x736B8EE2F09602AAULL,
		0x55C17FE69741671CULL,
		0x6F99DFBF79F17F47ULL,
		0xEFDA1309C3B7BFADULL,
		0xE5F0EA2586F42E1EULL,
		0x16866B0297DC18E6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB5998399951B3FA2ULL,
		0xE492E0E3989A2946ULL,
		0xE6D71DC5E12C0555ULL,
		0xAB82FFCD2E82CE38ULL,
		0xDF33BF7EF3E2FE8EULL,
		0xDFB42613876F7F5AULL,
		0xCBE1D44B0DE85C3DULL,
		0x2D0CD6052FB831CDULL
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
		0x04B0A7BBAC7B5B10ULL,
		0xECC3CE3515DA4948ULL,
		0x9442870EE2EF9AE5ULL,
		0x6184F05145FEC54AULL,
		0xCBE29A0D4402773FULL,
		0x637D9DEF2085A35CULL,
		0x1D44A80D86842CCFULL,
		0x28341FFDBAFF80E9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x09614F7758F6B620ULL,
		0xD9879C6A2BB49290ULL,
		0x28850E1DC5DF35CBULL,
		0xC309E0A28BFD8A95ULL,
		0x97C5341A8804EE7EULL,
		0xC6FB3BDE410B46B9ULL,
		0x3A89501B0D08599EULL,
		0x50683FFB75FF01D2ULL
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
		0xBD8C4D6BDA17D986ULL,
		0x14198D06A90F1723ULL,
		0x794E403F9F3F8ED2ULL,
		0xC98C645A08BE2E5FULL,
		0x2C18380E2EC2D017ULL,
		0xA366DA570F62E040ULL,
		0xE154F0D0058D5A8EULL,
		0x09118986A4EF62E8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7B189AD7B42FB30CULL,
		0x28331A0D521E2E47ULL,
		0xF29C807F3E7F1DA4ULL,
		0x9318C8B4117C5CBEULL,
		0x5830701C5D85A02FULL,
		0x46CDB4AE1EC5C080ULL,
		0xC2A9E1A00B1AB51DULL,
		0x1223130D49DEC5D1ULL
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
		0x9BA957E5B3350727ULL,
		0xC62A7B41FD8F730EULL,
		0x1CC7F6D50010D68AULL,
		0xECABE5B05F37F99AULL,
		0xCA775E58680200C3ULL,
		0xA92B64F60DADD582ULL,
		0x1FE1DEFE62657471ULL,
		0x332997FF7324B88DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3752AFCB666A0E4EULL,
		0x8C54F683FB1EE61DULL,
		0x398FEDAA0021AD15ULL,
		0xD957CB60BE6FF334ULL,
		0x94EEBCB0D0040187ULL,
		0x5256C9EC1B5BAB05ULL,
		0x3FC3BDFCC4CAE8E3ULL,
		0x66532FFEE649711AULL
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
		0xC27DEC08FD85D471ULL,
		0xF078DDB2C046AA31ULL,
		0x4C6A6BA0FA12F036ULL,
		0x24BF3A99FD822D6CULL,
		0xADA4B24815BB256CULL,
		0x9BAB100E5E801D7AULL,
		0x210D2E3AA22463D8ULL,
		0x3A05718CBF798596ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x84FBD811FB0BA8E2ULL,
		0xE0F1BB65808D5463ULL,
		0x98D4D741F425E06DULL,
		0x497E7533FB045AD8ULL,
		0x5B4964902B764AD8ULL,
		0x3756201CBD003AF5ULL,
		0x421A5C754448C7B1ULL,
		0x740AE3197EF30B2CULL
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
		0xF4A69B4EFA0EC612ULL,
		0x0AF85736C3A86B70ULL,
		0x6C5FF6734AF72427ULL,
		0x33014F664C195627ULL,
		0x3151CD33C3469776ULL,
		0xC1529D8D6B30A053ULL,
		0xA70B6E28FE14CACBULL,
		0x12E58822933ADF6FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE94D369DF41D8C24ULL,
		0x15F0AE6D8750D6E1ULL,
		0xD8BFECE695EE484EULL,
		0x66029ECC9832AC4EULL,
		0x62A39A67868D2EECULL,
		0x82A53B1AD66140A6ULL,
		0x4E16DC51FC299597ULL,
		0x25CB10452675BEDFULL
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
		0x9A4728885CD0CFECULL,
		0x5DCE0B28949941DAULL,
		0xADAF93F7A5A574BFULL,
		0x1722B078D4DA42A9ULL,
		0x2F39D625BCC7CEF9ULL,
		0xC7C4966A3E28A6F9ULL,
		0x30C440E92E877C42ULL,
		0x105C9B5BF2A71EF8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x348E5110B9A19FD8ULL,
		0xBB9C1651293283B5ULL,
		0x5B5F27EF4B4AE97EULL,
		0x2E4560F1A9B48553ULL,
		0x5E73AC4B798F9DF2ULL,
		0x8F892CD47C514DF2ULL,
		0x618881D25D0EF885ULL,
		0x20B936B7E54E3DF0ULL
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
		0xA8AB14E23921A7E8ULL,
		0x3B6891F4F9085417ULL,
		0x1D8E22069157F589ULL,
		0xFA4136E0021E5C92ULL,
		0x6E8DAA30364DB51BULL,
		0x516257CEA15F5826ULL,
		0x1C56A5DA0B124271ULL,
		0x3CA6F78FAF2874C1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x515629C472434FD0ULL,
		0x76D123E9F210A82FULL,
		0x3B1C440D22AFEB12ULL,
		0xF4826DC0043CB924ULL,
		0xDD1B54606C9B6A37ULL,
		0xA2C4AF9D42BEB04CULL,
		0x38AD4BB4162484E2ULL,
		0x794DEF1F5E50E982ULL
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
		0x8A4F54536DEC570BULL,
		0xA915C6405BE9FC72ULL,
		0x941A96D62FC8E2B8ULL,
		0x2AB1EA9104760A56ULL,
		0xD7F6B9D586072153ULL,
		0xE1A279A92B1A80E0ULL,
		0xBA3BF33C23713CBBULL,
		0x2C3084DB285D1E8FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x149EA8A6DBD8AE16ULL,
		0x522B8C80B7D3F8E5ULL,
		0x28352DAC5F91C571ULL,
		0x5563D52208EC14ADULL,
		0xAFED73AB0C0E42A6ULL,
		0xC344F352563501C1ULL,
		0x7477E67846E27977ULL,
		0x586109B650BA3D1FULL
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
		0x6A787506FB9025CDULL,
		0x941B5DABB1FBDB61ULL,
		0xA15344B7306B92E6ULL,
		0x19DCC3EC71737DA4ULL,
		0x9FEBB6F688245C0AULL,
		0x6A91816FEAE2C12AULL,
		0x3DBACCFDE6AFB88FULL,
		0x3D0C5712F37CA16AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD4F0EA0DF7204B9AULL,
		0x2836BB5763F7B6C2ULL,
		0x42A6896E60D725CDULL,
		0x33B987D8E2E6FB49ULL,
		0x3FD76DED1048B814ULL,
		0xD52302DFD5C58255ULL,
		0x7B7599FBCD5F711EULL,
		0x7A18AE25E6F942D4ULL
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
		0xEE23F9B1EE875E0AULL,
		0xF19675285DE1F2A4ULL,
		0x97FED0AE5729AEA6ULL,
		0x8C2043654DA1EC50ULL,
		0xF195652941D8874FULL,
		0x517DF685FB294D5DULL,
		0x2FB71ECF712F6686ULL,
		0x32F44E4634F75F6BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDC47F363DD0EBC14ULL,
		0xE32CEA50BBC3E549ULL,
		0x2FFDA15CAE535D4DULL,
		0x184086CA9B43D8A1ULL,
		0xE32ACA5283B10E9FULL,
		0xA2FBED0BF6529ABBULL,
		0x5F6E3D9EE25ECD0CULL,
		0x65E89C8C69EEBED6ULL
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
		0xF4C267E575580D4DULL,
		0xB4669A5E13354B39ULL,
		0x04474E9651D47627ULL,
		0x21D184F3592E91F9ULL,
		0x38D199720272917DULL,
		0xE83728DCC4969163ULL,
		0xE584CE6CEB975055ULL,
		0x1D590D4DCBDE236CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE984CFCAEAB01A9AULL,
		0x68CD34BC266A9673ULL,
		0x088E9D2CA3A8EC4FULL,
		0x43A309E6B25D23F2ULL,
		0x71A332E404E522FAULL,
		0xD06E51B9892D22C6ULL,
		0xCB099CD9D72EA0ABULL,
		0x3AB21A9B97BC46D9ULL
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
		0x5636EE10294C5F22ULL,
		0x247A7FDFA9B8C52FULL,
		0x59F1AF3B274F1671ULL,
		0xF9FD19BD09075930ULL,
		0x296C8106DB92CF72ULL,
		0x0BC882ECFCC80E0CULL,
		0xD8A22B395C51B8E4ULL,
		0x2733D75490BC40DAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAC6DDC205298BE44ULL,
		0x48F4FFBF53718A5EULL,
		0xB3E35E764E9E2CE2ULL,
		0xF3FA337A120EB260ULL,
		0x52D9020DB7259EE5ULL,
		0x179105D9F9901C18ULL,
		0xB1445672B8A371C8ULL,
		0x4E67AEA9217881B5ULL
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
		0x8C0B59F06D5C9ACFULL,
		0x845AC091832DAA39ULL,
		0x2417639691A178F8ULL,
		0x1C7A442CC009A03DULL,
		0x7F84C2E2C8012FFBULL,
		0x344E81C3759577D0ULL,
		0x52C172EBFFAC070FULL,
		0x344D1884991825EFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1816B3E0DAB9359EULL,
		0x08B58123065B5473ULL,
		0x482EC72D2342F1F1ULL,
		0x38F488598013407AULL,
		0xFF0985C590025FF6ULL,
		0x689D0386EB2AEFA0ULL,
		0xA582E5D7FF580E1EULL,
		0x689A310932304BDEULL
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
		0xF38ABEE9B5D23153ULL,
		0xBB06EEBB27275FADULL,
		0x912E045DB0F016E1ULL,
		0x04196F66A31E0960ULL,
		0x3C4530807E9975BEULL,
		0x334AAD2BE875CE08ULL,
		0x1CE6CC5F1BA3D0BBULL,
		0x0216A298A17D1445ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE7157DD36BA462A6ULL,
		0x760DDD764E4EBF5BULL,
		0x225C08BB61E02DC3ULL,
		0x0832DECD463C12C1ULL,
		0x788A6100FD32EB7CULL,
		0x66955A57D0EB9C10ULL,
		0x39CD98BE3747A176ULL,
		0x042D453142FA288AULL
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
		0x889860341543FE20ULL,
		0xE54DBD9170E43553ULL,
		0xFD8E53B93E5DABDBULL,
		0x2DF6D61AFB7ABF36ULL,
		0x98DDD9EF3F603A7EULL,
		0x62D04E0D8DE47876ULL,
		0x2CD1A4C4026A294FULL,
		0x1E9B3AA4037215B4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1130C0682A87FC40ULL,
		0xCA9B7B22E1C86AA7ULL,
		0xFB1CA7727CBB57B7ULL,
		0x5BEDAC35F6F57E6DULL,
		0x31BBB3DE7EC074FCULL,
		0xC5A09C1B1BC8F0EDULL,
		0x59A3498804D4529EULL,
		0x3D36754806E42B68ULL
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
		0x7C282B5CDD20B767ULL,
		0x71BF78D1F9D37103ULL,
		0xA7AD6044C8FE9A1DULL,
		0xB36C8185890F8BDFULL,
		0x0918E59614A0D308ULL,
		0x347DEF3830C13431ULL,
		0x3DEFC1AC89F1F10BULL,
		0x26DD7A3A45C8BB1BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF85056B9BA416ECEULL,
		0xE37EF1A3F3A6E206ULL,
		0x4F5AC08991FD343AULL,
		0x66D9030B121F17BFULL,
		0x1231CB2C2941A611ULL,
		0x68FBDE7061826862ULL,
		0x7BDF835913E3E216ULL,
		0x4DBAF4748B917636ULL
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
		0x7373ED767989CA2BULL,
		0x322F47E301183DE1ULL,
		0x4F98A52E95A7475BULL,
		0x85F27828830498ABULL,
		0xA9A1D6D6737023FBULL,
		0x29B7151232823513ULL,
		0xB2310FD942D57BD1ULL,
		0x0A8B0BD642BC3ECAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE6E7DAECF3139456ULL,
		0x645E8FC602307BC2ULL,
		0x9F314A5D2B4E8EB6ULL,
		0x0BE4F05106093156ULL,
		0x5343ADACE6E047F7ULL,
		0x536E2A2465046A27ULL,
		0x64621FB285AAF7A2ULL,
		0x151617AC85787D95ULL
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
		0xCEAE54F6D0D93BC9ULL,
		0x1742F8C75BA14F3DULL,
		0x47AD9620B90FABABULL,
		0x2CB643021CABEA8EULL,
		0x437AC08A2669BEA4ULL,
		0xDE49C2DE22256F7EULL,
		0xCF0ED0D7636B1186ULL,
		0x2E0A7A64A6771453ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9D5CA9EDA1B27792ULL,
		0x2E85F18EB7429E7BULL,
		0x8F5B2C41721F5756ULL,
		0x596C86043957D51CULL,
		0x86F581144CD37D48ULL,
		0xBC9385BC444ADEFCULL,
		0x9E1DA1AEC6D6230DULL,
		0x5C14F4C94CEE28A7ULL
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
		0x5957A882AEE9C6FBULL,
		0x18B9C1F0A89BCDACULL,
		0xFFFE5000104D72D1ULL,
		0x8945A4A34C2A0B75ULL,
		0x7F361F9781004EF2ULL,
		0xDF025C904D8CD1E5ULL,
		0x41B63B4D79167511ULL,
		0x1E400E1ABED33508ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB2AF51055DD38DF6ULL,
		0x317383E151379B58ULL,
		0xFFFCA000209AE5A2ULL,
		0x128B4946985416EBULL,
		0xFE6C3F2F02009DE5ULL,
		0xBE04B9209B19A3CAULL,
		0x836C769AF22CEA23ULL,
		0x3C801C357DA66A10ULL
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
		0x6FD0D40190E98E09ULL,
		0x97583482D1946426ULL,
		0xCAF62D95D62347B6ULL,
		0xC0CE218D271013E2ULL,
		0xBCC1D503652E758BULL,
		0xCB00751722A81933ULL,
		0x5B8F4EC6FEDC3801ULL,
		0x26D84B9E359C298CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDFA1A80321D31C12ULL,
		0x2EB06905A328C84CULL,
		0x95EC5B2BAC468F6DULL,
		0x819C431A4E2027C5ULL,
		0x7983AA06CA5CEB17ULL,
		0x9600EA2E45503267ULL,
		0xB71E9D8DFDB87003ULL,
		0x4DB0973C6B385318ULL
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
		0xDAFBDFD35784A23AULL,
		0x917BB3DCEBB42BDCULL,
		0xF9888382812DAB72ULL,
		0x01A32255805D12ABULL,
		0xA218E2A8243158F1ULL,
		0x6683B906A46170CBULL,
		0x23BE1EFF118971CFULL,
		0x3F6FE74C0F9144E2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB5F7BFA6AF094474ULL,
		0x22F767B9D76857B9ULL,
		0xF3110705025B56E5ULL,
		0x034644AB00BA2557ULL,
		0x4431C5504862B1E2ULL,
		0xCD07720D48C2E197ULL,
		0x477C3DFE2312E39EULL,
		0x7EDFCE981F2289C4ULL
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
		0xF71A7C48635353C4ULL,
		0x2CA7808D5D38405DULL,
		0x31F611763AD076E6ULL,
		0xB40084FCA20D7D98ULL,
		0x8E09D1D3B2260DE8ULL,
		0xE16DED6C5B8AD2B0ULL,
		0x949384CB5455A9E9ULL,
		0x3B6E133D1B27379DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEE34F890C6A6A788ULL,
		0x594F011ABA7080BBULL,
		0x63EC22EC75A0EDCCULL,
		0x680109F9441AFB30ULL,
		0x1C13A3A7644C1BD1ULL,
		0xC2DBDAD8B715A561ULL,
		0x29270996A8AB53D3ULL,
		0x76DC267A364E6F3BULL
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
		0x5A25119088EC45C8ULL,
		0x78DA8AB7B223B2FEULL,
		0xCDB740D66B4EAD8FULL,
		0x9B364885FB9F06BEULL,
		0x87B34413D1188BD8ULL,
		0x9CACDFC4159189B7ULL,
		0xDA900889FC468D5CULL,
		0x3D530C57BAEE86A0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB44A232111D88B90ULL,
		0xF1B5156F644765FCULL,
		0x9B6E81ACD69D5B1EULL,
		0x366C910BF73E0D7DULL,
		0x0F668827A23117B1ULL,
		0x3959BF882B23136FULL,
		0xB5201113F88D1AB9ULL,
		0x7AA618AF75DD0D41ULL
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
		0x6874834116F2961AULL,
		0xF62F0939F66FB27BULL,
		0xDCCE1D2492631BFDULL,
		0x64D33B68FBE53B1EULL,
		0x3332816ABD7FF224ULL,
		0xC5028E69ACAA42C4ULL,
		0x9AA9E08AC0D2EB80ULL,
		0x169D4287FBC118D3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD0E906822DE52C34ULL,
		0xEC5E1273ECDF64F6ULL,
		0xB99C3A4924C637FBULL,
		0xC9A676D1F7CA763DULL,
		0x666502D57AFFE448ULL,
		0x8A051CD359548588ULL,
		0x3553C11581A5D701ULL,
		0x2D3A850FF78231A7ULL
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
		0x4823D600FA96F4BCULL,
		0x553F9D902B9BD727ULL,
		0xAB9669C41C11616EULL,
		0x0C264644FF1B2A79ULL,
		0x7D9F4B3E85C9B5D2ULL,
		0xF3406E671F857D35ULL,
		0x26A9EFC272BE1F16ULL,
		0x39678D7DF5594FB6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9047AC01F52DE978ULL,
		0xAA7F3B205737AE4EULL,
		0x572CD3883822C2DCULL,
		0x184C8C89FE3654F3ULL,
		0xFB3E967D0B936BA4ULL,
		0xE680DCCE3F0AFA6AULL,
		0x4D53DF84E57C3E2DULL,
		0x72CF1AFBEAB29F6CULL
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
		0x3773ABAB530ED522ULL,
		0x63E797CE5E7409BEULL,
		0x59AD90036CFBA8B0ULL,
		0xB57B0BE3C2566C78ULL,
		0xA089A6DF08FAFD50ULL,
		0x88D36402BBC30BF7ULL,
		0xAF0D0F9F2A1D7A61ULL,
		0x1518B903F65C778AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6EE75756A61DAA44ULL,
		0xC7CF2F9CBCE8137CULL,
		0xB35B2006D9F75160ULL,
		0x6AF617C784ACD8F0ULL,
		0x41134DBE11F5FAA1ULL,
		0x11A6C805778617EFULL,
		0x5E1A1F3E543AF4C3ULL,
		0x2A317207ECB8EF15ULL
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
		0x6D9991F0195CE3FAULL,
		0x0779D019127222C8ULL,
		0xBB551B4044FD7F96ULL,
		0x136EEA695C9C8D2AULL,
		0xB58E489484A8D2B3ULL,
		0x7023FA68124A7809ULL,
		0x7B3878F366E9E230ULL,
		0x017DCB8FB8CE6629ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDB3323E032B9C7F4ULL,
		0x0EF3A03224E44590ULL,
		0x76AA368089FAFF2CULL,
		0x26DDD4D2B9391A55ULL,
		0x6B1C91290951A566ULL,
		0xE047F4D02494F013ULL,
		0xF670F1E6CDD3C460ULL,
		0x02FB971F719CCC52ULL
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
		0x97B65FDD804D954DULL,
		0xC7B26F47898EF472ULL,
		0x84C5954C3B97EE5EULL,
		0xBFF03B3E6D2A50BAULL,
		0x64FF3DC993DCADB3ULL,
		0x04F555B3B9F0B482ULL,
		0xA0D7E2B9F6B1694CULL,
		0x2259E8EC6B878AD1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2F6CBFBB009B2A9AULL,
		0x8F64DE8F131DE8E5ULL,
		0x098B2A98772FDCBDULL,
		0x7FE0767CDA54A175ULL,
		0xC9FE7B9327B95B67ULL,
		0x09EAAB6773E16904ULL,
		0x41AFC573ED62D298ULL,
		0x44B3D1D8D70F15A3ULL
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
		0x8580B38ECFF52C35ULL,
		0x31BC41099EB7CFFCULL,
		0x05FF21A4F914F9F9ULL,
		0xEB2BF352F63B716DULL,
		0x6ABAC9C48734B49FULL,
		0xE21D4C6FECB2F2BCULL,
		0xBD4C47C3424FA309ULL,
		0x14147FF60C0BF585ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0B01671D9FEA586AULL,
		0x637882133D6F9FF9ULL,
		0x0BFE4349F229F3F2ULL,
		0xD657E6A5EC76E2DAULL,
		0xD57593890E69693FULL,
		0xC43A98DFD965E578ULL,
		0x7A988F86849F4613ULL,
		0x2828FFEC1817EB0BULL
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
		0x6BBB68EA4031496DULL,
		0x3DFABC1F7E6A23F4ULL,
		0x5DF027E54436BFA9ULL,
		0xB388E05E6E6A861EULL,
		0x5A784081B5AF7101ULL,
		0x9AA73ED5A9BED632ULL,
		0x3B8AE280213AF15AULL,
		0x1A58DFF810D16915ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD776D1D4806292DAULL,
		0x7BF5783EFCD447E8ULL,
		0xBBE04FCA886D7F52ULL,
		0x6711C0BCDCD50C3CULL,
		0xB4F081036B5EE203ULL,
		0x354E7DAB537DAC64ULL,
		0x7715C5004275E2B5ULL,
		0x34B1BFF021A2D22AULL
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
		0x2BDF16A701448077ULL,
		0x707E029EF82E7B33ULL,
		0x2A783816A7A979A2ULL,
		0x74D9781D4ED78B01ULL,
		0xD5B7C6B037DF0DD8ULL,
		0xB5141F7FF88EBAA6ULL,
		0x8C8CDB0A28A1759AULL,
		0x269AC20E35ACAB37ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x57BE2D4E028900EEULL,
		0xE0FC053DF05CF666ULL,
		0x54F0702D4F52F344ULL,
		0xE9B2F03A9DAF1602ULL,
		0xAB6F8D606FBE1BB0ULL,
		0x6A283EFFF11D754DULL,
		0x1919B6145142EB35ULL,
		0x4D35841C6B59566FULL
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
		0x977E359BB96B2A04ULL,
		0xE7AB8C73B4921C7CULL,
		0xF59BB5262F457D1FULL,
		0xC6B30CE121287F3AULL,
		0x85F8039A92E448C6ULL,
		0x7BDDCF949E56417CULL,
		0x731F37FEE4447842ULL,
		0x25503DC96ACD8FCCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2EFC6B3772D65408ULL,
		0xCF5718E7692438F9ULL,
		0xEB376A4C5E8AFA3FULL,
		0x8D6619C24250FE75ULL,
		0x0BF0073525C8918DULL,
		0xF7BB9F293CAC82F9ULL,
		0xE63E6FFDC888F084ULL,
		0x4AA07B92D59B1F98ULL
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
		0xDD5421FCEAFB0D34ULL,
		0xEAD2DF954C6B17B0ULL,
		0x067745DDABD32E37ULL,
		0x1EF6CB103F90FAE9ULL,
		0xA9FC7A8191FED832ULL,
		0xDB2DFBB0D8D6CB11ULL,
		0x48D5353A92987EFBULL,
		0x1573676C89F585A2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBAA843F9D5F61A68ULL,
		0xD5A5BF2A98D62F61ULL,
		0x0CEE8BBB57A65C6FULL,
		0x3DED96207F21F5D2ULL,
		0x53F8F50323FDB064ULL,
		0xB65BF761B1AD9623ULL,
		0x91AA6A752530FDF7ULL,
		0x2AE6CED913EB0B44ULL
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
		0x5AF3A078EB45CD0DULL,
		0x2C7E3C782BCF8975ULL,
		0x651206848F7E5114ULL,
		0x8140EEB1C45AAAB8ULL,
		0x57B27011F3AE5CA1ULL,
		0x35B4CEB90978B8C5ULL,
		0xAC3DCEBB58B7482AULL,
		0x3EB9B7EE148AE3EFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB5E740F1D68B9A1AULL,
		0x58FC78F0579F12EAULL,
		0xCA240D091EFCA228ULL,
		0x0281DD6388B55570ULL,
		0xAF64E023E75CB943ULL,
		0x6B699D7212F1718AULL,
		0x587B9D76B16E9054ULL,
		0x7D736FDC2915C7DFULL
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
		0x4D1589F1E0BE3A51ULL,
		0xDF8912C05A6BA769ULL,
		0x1189413B28A64F90ULL,
		0x31BC0BA0BF8DE2E3ULL,
		0x9BCEF491755E5A71ULL,
		0x2FFE198941F8898EULL,
		0xB5F432E646ACBFABULL,
		0x22AB0B000D18DE13ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9A2B13E3C17C74A2ULL,
		0xBF122580B4D74ED2ULL,
		0x23128276514C9F21ULL,
		0x637817417F1BC5C6ULL,
		0x379DE922EABCB4E2ULL,
		0x5FFC331283F1131DULL,
		0x6BE865CC8D597F56ULL,
		0x455616001A31BC27ULL
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
		0xF81E2DC6293FD87BULL,
		0x7617DF776FA63A2AULL,
		0x89086918B0A40CE2ULL,
		0xEA9F6DCC675180DEULL,
		0x4B9E45F7C45EC55FULL,
		0x9D1DF808A2151811ULL,
		0x0B7A38902A8D9481ULL,
		0x1426CF279184A49FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF03C5B8C527FB0F6ULL,
		0xEC2FBEEEDF4C7455ULL,
		0x1210D231614819C4ULL,
		0xD53EDB98CEA301BDULL,
		0x973C8BEF88BD8ABFULL,
		0x3A3BF011442A3022ULL,
		0x16F47120551B2903ULL,
		0x284D9E4F2309493EULL
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
		0x847CE88820C6BF71ULL,
		0x86435AD8835EAC51ULL,
		0xBE2B02E3D7B71430ULL,
		0x7C592EEC59A2FBEFULL,
		0x9FC7A212E5F198DDULL,
		0xC3302373700C50C8ULL,
		0xBF82CC4A9573771CULL,
		0x29ED400CC3E242FDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x08F9D110418D7EE2ULL,
		0x0C86B5B106BD58A3ULL,
		0x7C5605C7AF6E2861ULL,
		0xF8B25DD8B345F7DFULL,
		0x3F8F4425CBE331BAULL,
		0x866046E6E018A191ULL,
		0x7F0598952AE6EE39ULL,
		0x53DA801987C485FBULL
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
		0x62B2F01CE32CE628ULL,
		0x094F1E783DAD086DULL,
		0xE2C5A0D1F88663D1ULL,
		0x67F6BECD14A590C6ULL,
		0xCD76A1636DA0B5BBULL,
		0xD1F28364C847FEB4ULL,
		0x52298139CE40DAD7ULL,
		0x0E5962A7C5A8BC39ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC565E039C659CC50ULL,
		0x129E3CF07B5A10DAULL,
		0xC58B41A3F10CC7A2ULL,
		0xCFED7D9A294B218DULL,
		0x9AED42C6DB416B76ULL,
		0xA3E506C9908FFD69ULL,
		0xA45302739C81B5AFULL,
		0x1CB2C54F8B517872ULL
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
		0x36D3D44F1BAAD6B5ULL,
		0xA7A1283F7A2BBCBAULL,
		0x7D1252E3DAA5E2F4ULL,
		0x4DA5A95E1E2FCAD6ULL,
		0xCCFD64693BE94EFEULL,
		0xA0D1F385F92C72B9ULL,
		0x94EAF06F624B5127ULL,
		0x25F152A1825F8E66ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6DA7A89E3755AD6AULL,
		0x4F42507EF4577974ULL,
		0xFA24A5C7B54BC5E9ULL,
		0x9B4B52BC3C5F95ACULL,
		0x99FAC8D277D29DFCULL,
		0x41A3E70BF258E573ULL,
		0x29D5E0DEC496A24FULL,
		0x4BE2A54304BF1CCDULL
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
		0x7D6B46253EBCBF4CULL,
		0x480BC2057D5E8804ULL,
		0xFD2666309C2000B9ULL,
		0x6DA06370F18C1E05ULL,
		0x3323F8DBBDDBE024ULL,
		0x5A6C638B497E6F33ULL,
		0xB653CA38990CAA10ULL,
		0x3FFF361666D304E3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFAD68C4A7D797E98ULL,
		0x9017840AFABD1008ULL,
		0xFA4CCC6138400172ULL,
		0xDB40C6E1E3183C0BULL,
		0x6647F1B77BB7C048ULL,
		0xB4D8C71692FCDE66ULL,
		0x6CA7947132195420ULL,
		0x7FFE6C2CCDA609C7ULL
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
		0x3ECE5657AFDB3EAEULL,
		0xBF7C7BBCE7D3D9AAULL,
		0xEA3CC3AA9AA59A09ULL,
		0xA64F6329092C0199ULL,
		0x20A187E9C4515D05ULL,
		0xD3C2E696D8148070ULL,
		0xBCC3A282113F04BAULL,
		0x22024D3FA54D6D3FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7D9CACAF5FB67D5CULL,
		0x7EF8F779CFA7B354ULL,
		0xD4798755354B3413ULL,
		0x4C9EC65212580333ULL,
		0x41430FD388A2BA0BULL,
		0xA785CD2DB02900E0ULL,
		0x79874504227E0975ULL,
		0x44049A7F4A9ADA7FULL
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
		0x5F82C08CF132567FULL,
		0x399B24B69287EB0EULL,
		0xB4FA39C4E854C1D7ULL,
		0x6AE332EBF729A8ACULL,
		0xA1E490BDF1452F0EULL,
		0x0F5BD1AF29CA94EEULL,
		0x4543C88C487C9BEAULL,
		0x02348C855A86B44CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBF058119E264ACFEULL,
		0x7336496D250FD61CULL,
		0x69F47389D0A983AEULL,
		0xD5C665D7EE535159ULL,
		0x43C9217BE28A5E1CULL,
		0x1EB7A35E539529DDULL,
		0x8A87911890F937D4ULL,
		0x0469190AB50D6898ULL
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
		0x9F06F2E157B634EAULL,
		0x733248DD485A8A28ULL,
		0xE3F7D8AA81CC7709ULL,
		0x3D09587FE4815554ULL,
		0x47056CCF731718CEULL,
		0x2C20CFB20AD8BC15ULL,
		0x652C15FF46BFB8F0ULL,
		0x33D24B428C70842FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3E0DE5C2AF6C69D4ULL,
		0xE66491BA90B51451ULL,
		0xC7EFB1550398EE12ULL,
		0x7A12B0FFC902AAA9ULL,
		0x8E0AD99EE62E319CULL,
		0x58419F6415B1782AULL,
		0xCA582BFE8D7F71E0ULL,
		0x67A4968518E1085EULL
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
		0x8BB19D26FE71E8B6ULL,
		0xA9BECCC32005A90BULL,
		0x12F1274BF92FE3FDULL,
		0xB0C34DCEF884905AULL,
		0xFD2A2F08EB399324ULL,
		0x7CD46878F1AFF27BULL,
		0x352611CD5E824F83ULL,
		0x3A70D390C522DC8AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x17633A4DFCE3D16CULL,
		0x537D9986400B5217ULL,
		0x25E24E97F25FC7FBULL,
		0x61869B9DF10920B4ULL,
		0xFA545E11D6732649ULL,
		0xF9A8D0F1E35FE4F7ULL,
		0x6A4C239ABD049F06ULL,
		0x74E1A7218A45B914ULL
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
		0xA72F1EDD1BA89C8DULL,
		0x7BF145B1E6CDB3AFULL,
		0xD321DAB6629FFDB9ULL,
		0x4D4AC3FE3BE4F3E9ULL,
		0xF6BD8D62E9296BBEULL,
		0x8564C24787E88695ULL,
		0x7CD6EB91EC6C0FE3ULL,
		0x12CAF46ABA736EBFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4E5E3DBA3751391AULL,
		0xF7E28B63CD9B675FULL,
		0xA643B56CC53FFB72ULL,
		0x9A9587FC77C9E7D3ULL,
		0xED7B1AC5D252D77CULL,
		0x0AC9848F0FD10D2BULL,
		0xF9ADD723D8D81FC7ULL,
		0x2595E8D574E6DD7EULL
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
		0x9827803FC8636555ULL,
		0x8945BBE135B425D8ULL,
		0xE31202D682B78E52ULL,
		0x07E65E3A078D2C42ULL,
		0xB003DF0879910A2DULL,
		0x17D04491DCE74E3FULL,
		0xF98017CC358DBA69ULL,
		0x162B1B504F44373FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x304F007F90C6CAAAULL,
		0x128B77C26B684BB1ULL,
		0xC62405AD056F1CA5ULL,
		0x0FCCBC740F1A5885ULL,
		0x6007BE10F322145AULL,
		0x2FA08923B9CE9C7FULL,
		0xF3002F986B1B74D2ULL,
		0x2C5636A09E886E7FULL
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
		0x67AC8C99E39898BFULL,
		0x5B6D05749DE9224DULL,
		0x4D1DB7C1DB52D8DCULL,
		0x09BB670D5C30FA3AULL,
		0x1561698FFA2E34DFULL,
		0x141F5AB9829F9CAAULL,
		0x4ECC40DB1127D6EEULL,
		0x03D28F16C90C401EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCF591933C731317EULL,
		0xB6DA0AE93BD2449AULL,
		0x9A3B6F83B6A5B1B8ULL,
		0x1376CE1AB861F474ULL,
		0x2AC2D31FF45C69BEULL,
		0x283EB573053F3954ULL,
		0x9D9881B6224FADDCULL,
		0x07A51E2D9218803CULL
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
		0x3EED362BFB509F5EULL,
		0xC170E0B7EFECD365ULL,
		0xE2D277CE1DA01F1DULL,
		0x552E78412E53CFB7ULL,
		0x76724A3261D95B79ULL,
		0x2558E08EF4D5BBB8ULL,
		0xD4C18C31EDB37B98ULL,
		0x30432514BFF50D0AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7DDA6C57F6A13EBCULL,
		0x82E1C16FDFD9A6CAULL,
		0xC5A4EF9C3B403E3BULL,
		0xAA5CF0825CA79F6FULL,
		0xECE49464C3B2B6F2ULL,
		0x4AB1C11DE9AB7770ULL,
		0xA9831863DB66F730ULL,
		0x60864A297FEA1A15ULL
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
		0x4D7F727C7417E0A4ULL,
		0x53964764BFA69B0DULL,
		0x3C12D822E14EAC0FULL,
		0xBD7E4D3AF40FC41EULL,
		0xEC6C0A102CC76687ULL,
		0xB2E512F0094EC071ULL,
		0xA8C9DA2029D51A06ULL,
		0x0BD52246607DD65EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9AFEE4F8E82FC148ULL,
		0xA72C8EC97F4D361AULL,
		0x7825B045C29D581EULL,
		0x7AFC9A75E81F883CULL,
		0xD8D81420598ECD0FULL,
		0x65CA25E0129D80E3ULL,
		0x5193B44053AA340DULL,
		0x17AA448CC0FBACBDULL
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
		0xE8A53D86D22A133BULL,
		0xFC1E1DD323662C10ULL,
		0x8E7AF84D0ACEF771ULL,
		0x238AEDD067BC1C9EULL,
		0x04F3D99551961055ULL,
		0xB933435C4328DA89ULL,
		0x5F81BE30F9EAA6E5ULL,
		0x25C9FB448A6B056BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD14A7B0DA4542676ULL,
		0xF83C3BA646CC5821ULL,
		0x1CF5F09A159DEEE3ULL,
		0x4715DBA0CF78393DULL,
		0x09E7B32AA32C20AAULL,
		0x726686B88651B512ULL,
		0xBF037C61F3D54DCBULL,
		0x4B93F68914D60AD6ULL
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
		0x76729A823769DA53ULL,
		0x2B048F99E881ECF0ULL,
		0x3D53522AA16099E5ULL,
		0x53B12C7A59C58E58ULL,
		0x601475D4E935F283ULL,
		0xD050EB04964F84AFULL,
		0x7F6F7C2A9200CBABULL,
		0x21F055DFF54A7ED4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xECE535046ED3B4A6ULL,
		0x56091F33D103D9E0ULL,
		0x7AA6A45542C133CAULL,
		0xA76258F4B38B1CB0ULL,
		0xC028EBA9D26BE506ULL,
		0xA0A1D6092C9F095EULL,
		0xFEDEF85524019757ULL,
		0x43E0ABBFEA94FDA8ULL
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
		0x1C228CF438616C4BULL,
		0x6ADA4E1D65DED4E0ULL,
		0x664B2E0204D08D44ULL,
		0xDC776D991B39A2B5ULL,
		0x58CFEE8FEB6DACFAULL,
		0x044D8AB28FD823E7ULL,
		0xF5E3B849E3522D07ULL,
		0x2FFB4D095BB26A52ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x384519E870C2D896ULL,
		0xD5B49C3ACBBDA9C0ULL,
		0xCC965C0409A11A88ULL,
		0xB8EEDB323673456AULL,
		0xB19FDD1FD6DB59F5ULL,
		0x089B15651FB047CEULL,
		0xEBC77093C6A45A0EULL,
		0x5FF69A12B764D4A5ULL
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
		0x8FA21C89968B049DULL,
		0xC3FDE88E7812E67DULL,
		0xD64DCEB07381D090ULL,
		0xC36080C08E205826ULL,
		0x67300BDB8B1EB4E8ULL,
		0x104B4EB6C9135186ULL,
		0x72DCCAC8E8755178ULL,
		0x23D532F601947766ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1F4439132D16093AULL,
		0x87FBD11CF025CCFBULL,
		0xAC9B9D60E703A121ULL,
		0x86C101811C40B04DULL,
		0xCE6017B7163D69D1ULL,
		0x20969D6D9226A30CULL,
		0xE5B99591D0EAA2F0ULL,
		0x47AA65EC0328EECCULL
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
		0x8D67C19D80F2D0E0ULL,
		0x4924B4C56A3B8718ULL,
		0x2D73A4FB464A4A00ULL,
		0x6BE14E1A4C84011CULL,
		0xEEA280C0F8D939EAULL,
		0x594998AAB163A615ULL,
		0x0BD0F8653EC28512ULL,
		0x329C80946F723488ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1ACF833B01E5A1C0ULL,
		0x9249698AD4770E31ULL,
		0x5AE749F68C949400ULL,
		0xD7C29C3499080238ULL,
		0xDD450181F1B273D4ULL,
		0xB293315562C74C2BULL,
		0x17A1F0CA7D850A24ULL,
		0x65390128DEE46910ULL
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
		0x0D62113DCA0ADA85ULL,
		0x174E4C1AF75990E7ULL,
		0x9EC37620B6FC4C05ULL,
		0x44C5CE8157A542A5ULL,
		0xB0C946E9F423168CULL,
		0x6ECCE3D931189E2FULL,
		0x54551B5DA68154CAULL,
		0x13910712E080F5D4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1AC4227B9415B50AULL,
		0x2E9C9835EEB321CEULL,
		0x3D86EC416DF8980AULL,
		0x898B9D02AF4A854BULL,
		0x61928DD3E8462D18ULL,
		0xDD99C7B262313C5FULL,
		0xA8AA36BB4D02A994ULL,
		0x27220E25C101EBA8ULL
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
		0x2035CE3BFCBA22C9ULL,
		0x663DCE2516133B86ULL,
		0xE8F8646DD3C95DB3ULL,
		0x96287D5212F557C7ULL,
		0x2B191AF0AA6DEDBEULL,
		0xF634C260D1EFEE57ULL,
		0x8C8F93CD607E9178ULL,
		0x039DD4152B619E09ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x406B9C77F9744592ULL,
		0xCC7B9C4A2C26770CULL,
		0xD1F0C8DBA792BB66ULL,
		0x2C50FAA425EAAF8FULL,
		0x563235E154DBDB7DULL,
		0xEC6984C1A3DFDCAEULL,
		0x191F279AC0FD22F1ULL,
		0x073BA82A56C33C13ULL
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
		0xE4FEB731AC0E6178ULL,
		0x8D3E6DF5940BDB21ULL,
		0xEB843D0DC29876A3ULL,
		0x950A316E36A2546EULL,
		0x50EE9674F66875AEULL,
		0xFE2DEA2E4D833AB2ULL,
		0xC087B4ACDD377EC9ULL,
		0x221FB63A2BAF9CD4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC9FD6E63581CC2F0ULL,
		0x1A7CDBEB2817B643ULL,
		0xD7087A1B8530ED47ULL,
		0x2A1462DC6D44A8DDULL,
		0xA1DD2CE9ECD0EB5DULL,
		0xFC5BD45C9B067564ULL,
		0x810F6959BA6EFD93ULL,
		0x443F6C74575F39A9ULL
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
		0x496AF3658D40E54FULL,
		0x6337440650CF49CEULL,
		0x4ECF834687B9F41BULL,
		0x70C9DA5D60480147ULL,
		0xA79C121663A62FB3ULL,
		0x1BBA1AE71643D08FULL,
		0x96E69EBE89E4BAE2ULL,
		0x3CC5D21D759384B5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x92D5E6CB1A81CA9EULL,
		0xC66E880CA19E939CULL,
		0x9D9F068D0F73E836ULL,
		0xE193B4BAC090028EULL,
		0x4F38242CC74C5F66ULL,
		0x377435CE2C87A11FULL,
		0x2DCD3D7D13C975C4ULL,
		0x798BA43AEB27096BULL
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
		0x4C373367FFD919C8ULL,
		0xAF64052122F5F46FULL,
		0x4E91486277D66D77ULL,
		0x16AAE6D43F6331CAULL,
		0xDD9C86FB78B0F4C2ULL,
		0x753A22E1C2BF9628ULL,
		0x0D46AE8B49F127E3ULL,
		0x2CFA85CB0FF66CF3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x986E66CFFFB23390ULL,
		0x5EC80A4245EBE8DEULL,
		0x9D2290C4EFACDAEFULL,
		0x2D55CDA87EC66394ULL,
		0xBB390DF6F161E984ULL,
		0xEA7445C3857F2C51ULL,
		0x1A8D5D1693E24FC6ULL,
		0x59F50B961FECD9E6ULL
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
		0xD62AC4384B97BEFEULL,
		0xEBCBC463274E61F0ULL,
		0xF9A7A28213F98438ULL,
		0x3B9255A53E96FF02ULL,
		0x28C3DFB81CF284F0ULL,
		0x5E6CF04410E17761ULL,
		0x6F7680D86258E496ULL,
		0x19EC93DB9725558BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAC558870972F7DFCULL,
		0xD79788C64E9CC3E1ULL,
		0xF34F450427F30871ULL,
		0x7724AB4A7D2DFE05ULL,
		0x5187BF7039E509E0ULL,
		0xBCD9E08821C2EEC2ULL,
		0xDEED01B0C4B1C92CULL,
		0x33D927B72E4AAB16ULL
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
		0x2D0BB5AC9F7B9A7CULL,
		0x7FAE971B386CD9A2ULL,
		0x003C1E3CB21202FAULL,
		0x1B4E5562F572070DULL,
		0xAD09B0DD62AAA40DULL,
		0x698C26005C68F522ULL,
		0x6E816A0768E1FFD8ULL,
		0x062C9BBE7330C976ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5A176B593EF734F8ULL,
		0xFF5D2E3670D9B344ULL,
		0x00783C79642405F4ULL,
		0x369CAAC5EAE40E1AULL,
		0x5A1361BAC555481AULL,
		0xD3184C00B8D1EA45ULL,
		0xDD02D40ED1C3FFB0ULL,
		0x0C59377CE66192ECULL
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
		0x65656CF6FF5D5E3AULL,
		0x46C56BDC8D30838CULL,
		0xD5B5759FF2C2F03DULL,
		0x0F7321E6A3E60A7FULL,
		0x4542D29380FE807AULL,
		0x4D43383922B4D559ULL,
		0x4AC331B9D3295532ULL,
		0x0086D808F672264BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCACAD9EDFEBABC74ULL,
		0x8D8AD7B91A610718ULL,
		0xAB6AEB3FE585E07AULL,
		0x1EE643CD47CC14FFULL,
		0x8A85A52701FD00F4ULL,
		0x9A8670724569AAB2ULL,
		0x95866373A652AA64ULL,
		0x010DB011ECE44C96ULL
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
		0xD2CF7CFD19DCA6D8ULL,
		0xB62AE390DD78F0DCULL,
		0x93A29E76C158B4F7ULL,
		0x6C80C848CCE531DFULL,
		0x86B195C61650FDE1ULL,
		0xC5BE894AF74D6862ULL,
		0x2EFE724CB100F65BULL,
		0x11CE103CD9F58634ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA59EF9FA33B94DB0ULL,
		0x6C55C721BAF1E1B9ULL,
		0x27453CED82B169EFULL,
		0xD901909199CA63BFULL,
		0x0D632B8C2CA1FBC2ULL,
		0x8B7D1295EE9AD0C5ULL,
		0x5DFCE4996201ECB7ULL,
		0x239C2079B3EB0C68ULL
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
		0x66BDBC079960344EULL,
		0x0B7A8EDAE693BF8FULL,
		0x6D06F89734799628ULL,
		0xCA32251EF8139A7FULL,
		0x6C59960D54A685DFULL,
		0x5E6D5E37F2C82852ULL,
		0x2FAC40D8429F233AULL,
		0x2E7D639461C5A220ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCD7B780F32C0689CULL,
		0x16F51DB5CD277F1EULL,
		0xDA0DF12E68F32C50ULL,
		0x94644A3DF02734FEULL,
		0xD8B32C1AA94D0BBFULL,
		0xBCDABC6FE59050A4ULL,
		0x5F5881B0853E4674ULL,
		0x5CFAC728C38B4440ULL
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
		0x0F94D68C14CD4218ULL,
		0x2CC564FF6CB4ACE5ULL,
		0x9419C4E0928C7889ULL,
		0x07EE9671448BDF2DULL,
		0x38F56557C98F606AULL,
		0x01CD9C072D9A4822ULL,
		0x56F96185B79FC718ULL,
		0x170805BF9684E7FAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1F29AD18299A8430ULL,
		0x598AC9FED96959CAULL,
		0x283389C12518F112ULL,
		0x0FDD2CE28917BE5BULL,
		0x71EACAAF931EC0D4ULL,
		0x039B380E5B349044ULL,
		0xADF2C30B6F3F8E30ULL,
		0x2E100B7F2D09CFF4ULL
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
		0x146195FD98F4A507ULL,
		0x832DFD8C42BB0A48ULL,
		0xCAA39379163284B3ULL,
		0x6990AB98073CDBF4ULL,
		0x8CEABDCCDB716E77ULL,
		0x9ACCF89EF2DE8D03ULL,
		0x5661350400C1339BULL,
		0x1AE1955588FB9BB7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x28C32BFB31E94A0EULL,
		0x065BFB1885761490ULL,
		0x954726F22C650967ULL,
		0xD32157300E79B7E9ULL,
		0x19D57B99B6E2DCEEULL,
		0x3599F13DE5BD1A07ULL,
		0xACC26A0801826737ULL,
		0x35C32AAB11F7376EULL
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
		0xB246CA2E5A3977EEULL,
		0xC394ED47E651D095ULL,
		0xA12189C99BFDFEE0ULL,
		0x4444C8C3927DC60FULL,
		0xA610F79C63CF4C2BULL,
		0x02F1D1AA937B1F01ULL,
		0xFB749907DC473409ULL,
		0x168A95D0BE60DDC8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x648D945CB472EFDCULL,
		0x8729DA8FCCA3A12BULL,
		0x4243139337FBFDC1ULL,
		0x8889918724FB8C1FULL,
		0x4C21EF38C79E9856ULL,
		0x05E3A35526F63E03ULL,
		0xF6E9320FB88E6812ULL,
		0x2D152BA17CC1BB91ULL
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
		0x5869A17113DA7737ULL,
		0x66EA32F111464626ULL,
		0x2243FEFEB5EB9E5AULL,
		0x6CB45E96583F304FULL,
		0xD95B24A327DE9765ULL,
		0xB72A975BE2503B4BULL,
		0x7FBF6F2152B56AC4ULL,
		0x08F615A97BB5C13BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB0D342E227B4EE6EULL,
		0xCDD465E2228C8C4CULL,
		0x4487FDFD6BD73CB4ULL,
		0xD968BD2CB07E609EULL,
		0xB2B649464FBD2ECAULL,
		0x6E552EB7C4A07697ULL,
		0xFF7EDE42A56AD589ULL,
		0x11EC2B52F76B8276ULL
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
		0x02842842A6946B36ULL,
		0x368A9BF7663F08B2ULL,
		0x5B6041629421FE28ULL,
		0x4966101F8C8521B6ULL,
		0xD0D5281730BA5371ULL,
		0x259ECE20788685E6ULL,
		0x2CE592C98269F1B9ULL,
		0x22F770D167D13F42ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x050850854D28D66CULL,
		0x6D1537EECC7E1164ULL,
		0xB6C082C52843FC50ULL,
		0x92CC203F190A436CULL,
		0xA1AA502E6174A6E2ULL,
		0x4B3D9C40F10D0BCDULL,
		0x59CB259304D3E372ULL,
		0x45EEE1A2CFA27E84ULL
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
		0xAE0B88EA9F34B3ADULL,
		0x3276A95E76D91D6EULL,
		0x4978184FFC31C07EULL,
		0x58FFD6A9F11931B9ULL,
		0xB93B3E36A2BEDA52ULL,
		0x155B112AC2EE7DFEULL,
		0x8B14BEC7367D49FDULL,
		0x17E477198C64B66CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5C1711D53E69675AULL,
		0x64ED52BCEDB23ADDULL,
		0x92F0309FF86380FCULL,
		0xB1FFAD53E2326372ULL,
		0x72767C6D457DB4A4ULL,
		0x2AB6225585DCFBFDULL,
		0x16297D8E6CFA93FAULL,
		0x2FC8EE3318C96CD9ULL
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
		0x90A4FC54A42E558EULL,
		0x69C5DAEDC62EFCCDULL,
		0x308395BBEB06B5A6ULL,
		0xB032B4BFCCFC9263ULL,
		0x55AEB2D06D4134CEULL,
		0xEB06269C038C84BEULL,
		0x8490BF8942F76B2EULL,
		0x006CACAB7AA89F75ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2149F8A9485CAB1CULL,
		0xD38BB5DB8C5DF99BULL,
		0x61072B77D60D6B4CULL,
		0x6065697F99F924C6ULL,
		0xAB5D65A0DA82699DULL,
		0xD60C4D380719097CULL,
		0x09217F1285EED65DULL,
		0x00D95956F5513EEBULL
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
		0x0C623FF2909276F4ULL,
		0xAEDEAA4013BFE4C9ULL,
		0x0AB991DC7D569903ULL,
		0xF07A73C47BDF2D2AULL,
		0xA09806E1C25CB59DULL,
		0x30ED230F6239449CULL,
		0xCE63B5E1BBAFE75DULL,
		0x1210C1193F56C7FCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x18C47FE52124EDE8ULL,
		0x5DBD5480277FC992ULL,
		0x157323B8FAAD3207ULL,
		0xE0F4E788F7BE5A54ULL,
		0x41300DC384B96B3BULL,
		0x61DA461EC4728939ULL,
		0x9CC76BC3775FCEBAULL,
		0x242182327EAD8FF9ULL
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
		0x87AD1879BD0E7E26ULL,
		0x5201CE5212F1127CULL,
		0x9C942AE941044FCBULL,
		0x1CD9571134DE5CFFULL,
		0x75997AF900F53445ULL,
		0xC22054A55DEA35A7ULL,
		0x0B63C6795E10EC8BULL,
		0x1DDACD3EDB2EEC2CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F5A30F37A1CFC4CULL,
		0xA4039CA425E224F9ULL,
		0x392855D282089F96ULL,
		0x39B2AE2269BCB9FFULL,
		0xEB32F5F201EA688AULL,
		0x8440A94ABBD46B4EULL,
		0x16C78CF2BC21D917ULL,
		0x3BB59A7DB65DD858ULL
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
		0xB8981058FDDB72F6ULL,
		0x3B70CC5BF46EDCDFULL,
		0xB02537E39D75D54AULL,
		0x3618321A89748EEBULL,
		0xC9E3276E0527395AULL,
		0xCF1132410B37987EULL,
		0x694272E3D35FAA52ULL,
		0x09DE84714E48DB98ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x713020B1FBB6E5ECULL,
		0x76E198B7E8DDB9BFULL,
		0x604A6FC73AEBAA94ULL,
		0x6C30643512E91DD7ULL,
		0x93C64EDC0A4E72B4ULL,
		0x9E226482166F30FDULL,
		0xD284E5C7A6BF54A5ULL,
		0x13BD08E29C91B730ULL
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
		0xD5160526AAD9E813ULL,
		0xD74188D7EBE264CAULL,
		0xBDAE74D7AF4E3159ULL,
		0x6E128A974AB69C61ULL,
		0x03D252A6926F5520ULL,
		0x8B118CBB2CA3C6FEULL,
		0x32604616387F9927ULL,
		0x2D6F459925F0784AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAA2C0A4D55B3D026ULL,
		0xAE8311AFD7C4C995ULL,
		0x7B5CE9AF5E9C62B3ULL,
		0xDC25152E956D38C3ULL,
		0x07A4A54D24DEAA40ULL,
		0x1623197659478DFCULL,
		0x64C08C2C70FF324FULL,
		0x5ADE8B324BE0F094ULL
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
		0x8EDB4486DCE86796ULL,
		0x2223ACCB79099B31ULL,
		0xB6AD6F21DEEAACE1ULL,
		0x10A5857D5D958975ULL,
		0xEE05FAEB8F092C48ULL,
		0xBA48E2BE198E6046ULL,
		0x8DC4E6C7CFD43C2AULL,
		0x059CB1A797291A44ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1DB6890DB9D0CF2CULL,
		0x44475996F2133663ULL,
		0x6D5ADE43BDD559C2ULL,
		0x214B0AFABB2B12EBULL,
		0xDC0BF5D71E125890ULL,
		0x7491C57C331CC08DULL,
		0x1B89CD8F9FA87855ULL,
		0x0B39634F2E523489ULL
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
		0xCFEDEA2F361476D4ULL,
		0x4F31E19BABF139C7ULL,
		0xAB6B7E6F3F8F939DULL,
		0xDE5925D7C2E23473ULL,
		0x7A5DF36359633D10ULL,
		0xEE8C13FC8342397DULL,
		0x38E769E1DFE90589ULL,
		0x2669DD3594156E42ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9FDBD45E6C28EDA8ULL,
		0x9E63C33757E2738FULL,
		0x56D6FCDE7F1F273AULL,
		0xBCB24BAF85C468E7ULL,
		0xF4BBE6C6B2C67A21ULL,
		0xDD1827F9068472FAULL,
		0x71CED3C3BFD20B13ULL,
		0x4CD3BA6B282ADC84ULL
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
		0xAE4446C00F49CA1CULL,
		0x96883D936A859EB5ULL,
		0xD02321CD41500FA6ULL,
		0x9103CB3DA7DF5528ULL,
		0x4AE3AC3A9AB2EE18ULL,
		0xD2344DE1A9449C5BULL,
		0x7161C3808C89B1D3ULL,
		0x23A054234B5F4449ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5C888D801E939438ULL,
		0x2D107B26D50B3D6BULL,
		0xA046439A82A01F4DULL,
		0x2207967B4FBEAA51ULL,
		0x95C758753565DC31ULL,
		0xA4689BC3528938B6ULL,
		0xE2C38701191363A7ULL,
		0x4740A84696BE8892ULL
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
		0x60969D1D83496FD7ULL,
		0xE2F9200D7386A044ULL,
		0x95339A378A89A737ULL,
		0xA597C666F894BCAEULL,
		0x87AF8852EBF3D09AULL,
		0x4D7F33BFBB5B129DULL,
		0xD9B35B0A585DE7ABULL,
		0x2958721039F57D53ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC12D3A3B0692DFAEULL,
		0xC5F2401AE70D4088ULL,
		0x2A67346F15134E6FULL,
		0x4B2F8CCDF129795DULL,
		0x0F5F10A5D7E7A135ULL,
		0x9AFE677F76B6253BULL,
		0xB366B614B0BBCF56ULL,
		0x52B0E42073EAFAA7ULL
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
		0x9C0FD5BE09AAF6EAULL,
		0xC9BC470508D61130ULL,
		0x81CE9AB51F5482E2ULL,
		0x0183C65E397B8F8DULL,
		0xD6945CADDD66D461ULL,
		0xC843F78172170883ULL,
		0x16F6DA760DC2E296ULL,
		0x296580C5C3AD7879ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x381FAB7C1355EDD4ULL,
		0x93788E0A11AC2261ULL,
		0x039D356A3EA905C5ULL,
		0x03078CBC72F71F1BULL,
		0xAD28B95BBACDA8C2ULL,
		0x9087EF02E42E1107ULL,
		0x2DEDB4EC1B85C52DULL,
		0x52CB018B875AF0F2ULL
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
		0x1CF4C5EA4411032EULL,
		0xA2CE91FBE2FDD662ULL,
		0x33A476DBA5CFF931ULL,
		0x5F0233B05BACBEE9ULL,
		0xBE9072338D5F3AFDULL,
		0xEDFE761D0E4D0F3DULL,
		0x2CB978C746A98315ULL,
		0x3834A7C9DA00D7C6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x39E98BD48822065CULL,
		0x459D23F7C5FBACC4ULL,
		0x6748EDB74B9FF263ULL,
		0xBE046760B7597DD2ULL,
		0x7D20E4671ABE75FAULL,
		0xDBFCEC3A1C9A1E7BULL,
		0x5972F18E8D53062BULL,
		0x70694F93B401AF8CULL
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
		0xCAA281670147851BULL,
		0x45F7C0C80DA099A1ULL,
		0xC88E0E27EA7F481FULL,
		0xB62FE927B7F41521ULL,
		0x12197557440DCD23ULL,
		0xE17607A0457FCF70ULL,
		0x58142A83B9F217D3ULL,
		0x3C988D2BDAE81786ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x954502CE028F0A36ULL,
		0x8BEF81901B413343ULL,
		0x911C1C4FD4FE903EULL,
		0x6C5FD24F6FE82A43ULL,
		0x2432EAAE881B9A47ULL,
		0xC2EC0F408AFF9EE0ULL,
		0xB028550773E42FA7ULL,
		0x79311A57B5D02F0CULL
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
		0x07D74E264C35CCA6ULL,
		0x3EC4CE790519D00BULL,
		0x9B0B5C02D10605D0ULL,
		0x51EF632E5B064DEBULL,
		0x5A73224AAD356456ULL,
		0x0E315802110D4CE3ULL,
		0x3BDD935118F5355DULL,
		0x2131A1381BFB57E1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0FAE9C4C986B994CULL,
		0x7D899CF20A33A016ULL,
		0x3616B805A20C0BA0ULL,
		0xA3DEC65CB60C9BD7ULL,
		0xB4E644955A6AC8ACULL,
		0x1C62B004221A99C6ULL,
		0x77BB26A231EA6ABAULL,
		0x4263427037F6AFC2ULL
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
		0x0590E7DC10B743D6ULL,
		0xD28E17CC22B1E0B3ULL,
		0x03153A95ED73A7C2ULL,
		0x9E1FD8464352F441ULL,
		0x039C276F2627CABEULL,
		0x14BCD1AE0EA72279ULL,
		0x9D1FE2D35ED1549EULL,
		0x3F71687D0836AF40ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0B21CFB8216E87ACULL,
		0xA51C2F984563C166ULL,
		0x062A752BDAE74F85ULL,
		0x3C3FB08C86A5E882ULL,
		0x07384EDE4C4F957DULL,
		0x2979A35C1D4E44F2ULL,
		0x3A3FC5A6BDA2A93CULL,
		0x7EE2D0FA106D5E81ULL
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
		0xB00E75250AEA4023ULL,
		0x4E2D70F8C7BA8FFEULL,
		0x4755D74A127C1022ULL,
		0xA641C9DAD4CC8A8EULL,
		0x88547E4AD33A14D1ULL,
		0x9BE7926295DBE437ULL,
		0xE65F963D9755FFB8ULL,
		0x12263624F412642CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x601CEA4A15D48046ULL,
		0x9C5AE1F18F751FFDULL,
		0x8EABAE9424F82044ULL,
		0x4C8393B5A999151CULL,
		0x10A8FC95A67429A3ULL,
		0x37CF24C52BB7C86FULL,
		0xCCBF2C7B2EABFF71ULL,
		0x244C6C49E824C859ULL
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
		0x46017F049E2AAF1EULL,
		0x358128B4B4F28AA3ULL,
		0xBE4F21E78B2A38AAULL,
		0x72595FA3605C86D8ULL,
		0x7723D153577E2506ULL,
		0x8B16475C1F928A61ULL,
		0x6E2D9EBE9779AFE4ULL,
		0x1AD5F8C99BEA564AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8C02FE093C555E3CULL,
		0x6B02516969E51546ULL,
		0x7C9E43CF16547154ULL,
		0xE4B2BF46C0B90DB1ULL,
		0xEE47A2A6AEFC4A0CULL,
		0x162C8EB83F2514C2ULL,
		0xDC5B3D7D2EF35FC9ULL,
		0x35ABF19337D4AC94ULL
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
		0xAF786771C1B49B95ULL,
		0x3CC96F2DCF348044ULL,
		0x8730FDDD1E1A4529ULL,
		0x92A9BB67BDDB56E8ULL,
		0xF42A7B8D96446A0AULL,
		0xC41E4D4CC4E4B4BBULL,
		0xFDE244579E5C2981ULL,
		0x3D85A9542FC23954ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5EF0CEE38369372AULL,
		0x7992DE5B9E690089ULL,
		0x0E61FBBA3C348A52ULL,
		0x255376CF7BB6ADD1ULL,
		0xE854F71B2C88D415ULL,
		0x883C9A9989C96977ULL,
		0xFBC488AF3CB85303ULL,
		0x7B0B52A85F8472A9ULL
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
		0x6BFB7622C41C2DF7ULL,
		0xED46FCB679185EE6ULL,
		0xF1CE4479166819F7ULL,
		0xC96ECE5E244EC3E6ULL,
		0xB6B43DC3FE4B5C3DULL,
		0x0A918E4EC2E77508ULL,
		0x0FBC9B75696C268DULL,
		0x0139B0092A258E63ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD7F6EC4588385BEEULL,
		0xDA8DF96CF230BDCCULL,
		0xE39C88F22CD033EFULL,
		0x92DD9CBC489D87CDULL,
		0x6D687B87FC96B87BULL,
		0x15231C9D85CEEA11ULL,
		0x1F7936EAD2D84D1AULL,
		0x02736012544B1CC6ULL
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
		0x21C417166F79B97AULL,
		0x1A7ECE5BF65FD4AEULL,
		0x49BFE7ECA9FD2335ULL,
		0x820134123C708C02ULL,
		0xF040E73D6B45A579ULL,
		0xAC5D1323F7828B32ULL,
		0x31ADDB4CDF0CC579ULL,
		0x2A1130F9CB444C43ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x43882E2CDEF372F4ULL,
		0x34FD9CB7ECBFA95CULL,
		0x937FCFD953FA466AULL,
		0x0402682478E11804ULL,
		0xE081CE7AD68B4AF3ULL,
		0x58BA2647EF051665ULL,
		0x635BB699BE198AF3ULL,
		0x542261F396889886ULL
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
		0x672362DF842BB8C2ULL,
		0xDDC2A70BCA1B1F23ULL,
		0xFE4E8BFD3AAD9AA4ULL,
		0x673B5772568C082BULL,
		0x5688C365DA0EC3E8ULL,
		0xB8633EC799BB8CB2ULL,
		0x15C223165899EFBDULL,
		0x35682FD722815ECAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCE46C5BF08577184ULL,
		0xBB854E1794363E46ULL,
		0xFC9D17FA755B3549ULL,
		0xCE76AEE4AD181057ULL,
		0xAD1186CBB41D87D0ULL,
		0x70C67D8F33771964ULL,
		0x2B84462CB133DF7BULL,
		0x6AD05FAE4502BD94ULL
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
		0x551109C1BB4AD39AULL,
		0xED521A3D0A783642ULL,
		0x5B8E3E6C127C2283ULL,
		0x1901796EC9369911ULL,
		0x111224C7201C58A5ULL,
		0x3AB1AE84B87DB1CEULL,
		0xA47C236D70105F28ULL,
		0x207B8E87DA5DC666ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAA2213837695A734ULL,
		0xDAA4347A14F06C84ULL,
		0xB71C7CD824F84507ULL,
		0x3202F2DD926D3222ULL,
		0x2224498E4038B14AULL,
		0x75635D0970FB639CULL,
		0x48F846DAE020BE50ULL,
		0x40F71D0FB4BB8CCDULL
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
		0x3ABA05959AAC2683ULL,
		0xD120D2F7CAE86536ULL,
		0x01FED03C9197092CULL,
		0xB8B18640948BB456ULL,
		0xDD295FBD5D79FB19ULL,
		0xB614FC8A761AABE0ULL,
		0xEC510316FFE8D787ULL,
		0x375F7A30262AF0E9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x75740B2B35584D06ULL,
		0xA241A5EF95D0CA6CULL,
		0x03FDA079232E1259ULL,
		0x71630C81291768ACULL,
		0xBA52BF7ABAF3F633ULL,
		0x6C29F914EC3557C1ULL,
		0xD8A2062DFFD1AF0FULL,
		0x6EBEF4604C55E1D3ULL
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
		0x099DFFB26253072EULL,
		0x2915D9400C9DD704ULL,
		0x694E57E19DEC3C50ULL,
		0xDFD0448F8B69A898ULL,
		0x0209A3267C577093ULL,
		0x49DF4089BDBAEE58ULL,
		0xBF6D513A1B59D667ULL,
		0x29ACE3741170F8D3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x133BFF64C4A60E5CULL,
		0x522BB280193BAE08ULL,
		0xD29CAFC33BD878A0ULL,
		0xBFA0891F16D35130ULL,
		0x0413464CF8AEE127ULL,
		0x93BE81137B75DCB0ULL,
		0x7EDAA27436B3ACCEULL,
		0x5359C6E822E1F1A7ULL
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
		0x87F83D41879B7CF2ULL,
		0xA8B082F1D17CA1E1ULL,
		0x9D1DCEE4A3CA1687ULL,
		0x58F667C8E34F1B28ULL,
		0x945800F889D4391EULL,
		0x44EBC17EB19F8EECULL,
		0x6F50142825BCF743ULL,
		0x0CBADBC93EC86C86ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0FF07A830F36F9E4ULL,
		0x516105E3A2F943C3ULL,
		0x3A3B9DC947942D0FULL,
		0xB1ECCF91C69E3651ULL,
		0x28B001F113A8723CULL,
		0x89D782FD633F1DD9ULL,
		0xDEA028504B79EE86ULL,
		0x1975B7927D90D90CULL
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
		0xBDF92D24139935B6ULL,
		0x74601E9B4A576EFBULL,
		0xFB44F07819510A23ULL,
		0x11D05EE427F4A8D9ULL,
		0x70E0502C6665E630ULL,
		0x3B0CFF533B9CD968ULL,
		0xAD6E2C9410996D0FULL,
		0x23DA2A26942DB10CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7BF25A4827326B6CULL,
		0xE8C03D3694AEDDF7ULL,
		0xF689E0F032A21446ULL,
		0x23A0BDC84FE951B3ULL,
		0xE1C0A058CCCBCC60ULL,
		0x7619FEA67739B2D0ULL,
		0x5ADC59282132DA1EULL,
		0x47B4544D285B6219ULL
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
		0x8FEF156CC92D0725ULL,
		0x48954064E1AB94A5ULL,
		0xBD12E8EEFBCE2283ULL,
		0xD65C6E0DC8F3E09FULL,
		0x22CBD007FE007363ULL,
		0x4A350B6F2E286CB4ULL,
		0xEEC2D609A6D39B63ULL,
		0x2F0DD41B4B19B889ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1FDE2AD9925A0E4AULL,
		0x912A80C9C357294BULL,
		0x7A25D1DDF79C4506ULL,
		0xACB8DC1B91E7C13FULL,
		0x4597A00FFC00E6C7ULL,
		0x946A16DE5C50D968ULL,
		0xDD85AC134DA736C6ULL,
		0x5E1BA83696337113ULL
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
		0x4F38C14C57443408ULL,
		0xE7F451ECB69C4E7EULL,
		0x30BD71C117AA4A4AULL,
		0x00197EBA0BC119CFULL,
		0x71C2C815827CCEAEULL,
		0xA8812DB698A87F3BULL,
		0x28DD0F76156CD887ULL,
		0x00B2DE01BC4EC204ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9E718298AE886810ULL,
		0xCFE8A3D96D389CFCULL,
		0x617AE3822F549495ULL,
		0x0032FD741782339EULL,
		0xE385902B04F99D5CULL,
		0x51025B6D3150FE76ULL,
		0x51BA1EEC2AD9B10FULL,
		0x0165BC03789D8408ULL
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
		0xA05066AB9F0632D2ULL,
		0x74BC421528DD51D2ULL,
		0xA0C65BA74DB329B7ULL,
		0x1368D4B36A2E15DBULL,
		0x79C428676D59C981ULL,
		0x912DED3AA0F654A2ULL,
		0x20875FF69C7EF7B3ULL,
		0x3C392377AAEEB690ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x40A0CD573E0C65A4ULL,
		0xE978842A51BAA3A5ULL,
		0x418CB74E9B66536EULL,
		0x26D1A966D45C2BB7ULL,
		0xF38850CEDAB39302ULL,
		0x225BDA7541ECA944ULL,
		0x410EBFED38FDEF67ULL,
		0x787246EF55DD6D20ULL
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
		0xE9CC5EA620590C92ULL,
		0x0947B12B17B66061ULL,
		0x5528DAC96B80403AULL,
		0x7594393E6C6E2588ULL,
		0xBDB05D3D64BC5574ULL,
		0xEB2C64D4C7BD22C3ULL,
		0x49197BA6F3CB9926ULL,
		0x336B628794494F01ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD398BD4C40B21924ULL,
		0x128F62562F6CC0C3ULL,
		0xAA51B592D7008074ULL,
		0xEB28727CD8DC4B10ULL,
		0x7B60BA7AC978AAE8ULL,
		0xD658C9A98F7A4587ULL,
		0x9232F74DE797324DULL,
		0x66D6C50F28929E02ULL
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
		0xE2A79354220941DFULL,
		0x7D7B483C2DD1B9BAULL,
		0xA54A72ECC6417CCDULL,
		0x1F2B9F70F70DA8C6ULL,
		0xFFC3096AA0137B36ULL,
		0xD5068F6880C545F5ULL,
		0xFBD160656812278CULL,
		0x089E6F963E2F9EF0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC54F26A8441283BEULL,
		0xFAF690785BA37375ULL,
		0x4A94E5D98C82F99AULL,
		0x3E573EE1EE1B518DULL,
		0xFF8612D54026F66CULL,
		0xAA0D1ED1018A8BEBULL,
		0xF7A2C0CAD0244F19ULL,
		0x113CDF2C7C5F3DE1ULL
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
		0x37F5C864DA7995F5ULL,
		0xA846E6EFF7A19524ULL,
		0x173E86857651188BULL,
		0x09D421B8DC231FC3ULL,
		0x42867AC5A3D6108CULL,
		0xA2637EB6F80D9973ULL,
		0x1232D925E8D38D77ULL,
		0x29192AF40DE2C6A0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6FEB90C9B4F32BEAULL,
		0x508DCDDFEF432A48ULL,
		0x2E7D0D0AECA23117ULL,
		0x13A84371B8463F86ULL,
		0x850CF58B47AC2118ULL,
		0x44C6FD6DF01B32E6ULL,
		0x2465B24BD1A71AEFULL,
		0x523255E81BC58D40ULL
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
		0xB7361C281F56C95DULL,
		0xDA2FB522C3621ECAULL,
		0xD413CD57FEFD2BACULL,
		0xA4F8A160E23ECEDCULL,
		0x9043DD34F3F68642ULL,
		0xF2A516CBA102A117ULL,
		0xFC2592DCD535451AULL,
		0x02C3B9F5A6D73549ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6E6C38503EAD92BAULL,
		0xB45F6A4586C43D95ULL,
		0xA8279AAFFDFA5759ULL,
		0x49F142C1C47D9DB9ULL,
		0x2087BA69E7ED0C85ULL,
		0xE54A2D974205422FULL,
		0xF84B25B9AA6A8A35ULL,
		0x058773EB4DAE6A93ULL
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
		0x6403A376BA65D99EULL,
		0xC02212B716F083A3ULL,
		0x7535CFC08E15EDC0ULL,
		0x26E4A04131047E85ULL,
		0x4B24A3A7757A9FD9ULL,
		0xB0A74F0F628B14AFULL,
		0x6DC1918351D08600ULL,
		0x0C4A8D692AD6CB56ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC80746ED74CBB33CULL,
		0x8044256E2DE10746ULL,
		0xEA6B9F811C2BDB81ULL,
		0x4DC940826208FD0AULL,
		0x9649474EEAF53FB2ULL,
		0x614E9E1EC516295EULL,
		0xDB832306A3A10C01ULL,
		0x18951AD255AD96ACULL
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
		0xF191BC5BF0D82CACULL,
		0x24A8633E71DAE6ADULL,
		0x7EB5F4CF37F12AD1ULL,
		0x707DD41D7AEDA585ULL,
		0x7AD0739EC1666902ULL,
		0xBC81E7BD3FF2927AULL,
		0xB20206F834B04D36ULL,
		0x368605D2D0D98C5AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE32378B7E1B05958ULL,
		0x4950C67CE3B5CD5BULL,
		0xFD6BE99E6FE255A2ULL,
		0xE0FBA83AF5DB4B0AULL,
		0xF5A0E73D82CCD204ULL,
		0x7903CF7A7FE524F4ULL,
		0x64040DF069609A6DULL,
		0x6D0C0BA5A1B318B5ULL
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
		0xDC2FD5922D642944ULL,
		0xEB313F922C551E40ULL,
		0xD888432306C4999CULL,
		0xEFBEB9669010F5DAULL,
		0x59CC88F56AB39591ULL,
		0xF78B691C2DD3E745ULL,
		0x50821775711F898AULL,
		0x2B472036915A3BADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB85FAB245AC85288ULL,
		0xD6627F2458AA3C81ULL,
		0xB11086460D893339ULL,
		0xDF7D72CD2021EBB5ULL,
		0xB39911EAD5672B23ULL,
		0xEF16D2385BA7CE8AULL,
		0xA1042EEAE23F1315ULL,
		0x568E406D22B4775AULL
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
		0xFEC88ECA1B1DA763ULL,
		0x2AA2160684663D2DULL,
		0x5ADA9472562A8E31ULL,
		0x7EDCAC9271DB37E9ULL,
		0x7FD946ADB85F4011ULL,
		0x7F49E350272BD9E4ULL,
		0x53891AE5C6C77E2BULL,
		0x1E0A92A74A3E462DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFD911D94363B4EC6ULL,
		0x55442C0D08CC7A5BULL,
		0xB5B528E4AC551C62ULL,
		0xFDB95924E3B66FD2ULL,
		0xFFB28D5B70BE8022ULL,
		0xFE93C6A04E57B3C8ULL,
		0xA71235CB8D8EFC56ULL,
		0x3C15254E947C8C5AULL
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
		0x234CED4B731587B2ULL,
		0x7C91444722456722ULL,
		0x67024EC3E7DAF3DDULL,
		0xF64A9839FF3382D4ULL,
		0x6BBB11CAB3D92037ULL,
		0x0007E8F36554E66FULL,
		0x6827415403A8FFE0ULL,
		0x22D9F5F853657D8EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4699DA96E62B0F64ULL,
		0xF922888E448ACE44ULL,
		0xCE049D87CFB5E7BAULL,
		0xEC953073FE6705A8ULL,
		0xD776239567B2406FULL,
		0x000FD1E6CAA9CCDEULL,
		0xD04E82A80751FFC0ULL,
		0x45B3EBF0A6CAFB1CULL
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
		0x3C65C301D6D292ADULL,
		0x462E3C4609D40D29ULL,
		0x045B1023D9246DABULL,
		0x0558654C6B5577E2ULL,
		0x1F50ED45253D667DULL,
		0x6E80809A4B47A40EULL,
		0x0A021ED016A345F7ULL,
		0x18C3AD37BA01621CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x78CB8603ADA5255AULL,
		0x8C5C788C13A81A52ULL,
		0x08B62047B248DB56ULL,
		0x0AB0CA98D6AAEFC4ULL,
		0x3EA1DA8A4A7ACCFAULL,
		0xDD010134968F481CULL,
		0x14043DA02D468BEEULL,
		0x31875A6F7402C438ULL
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
		0xC898E57E1DFD8137ULL,
		0x64685E3A348FB9D7ULL,
		0xF22B4E9232CCFAE8ULL,
		0xC89B5A6F0DD2C53CULL,
		0xD69F16282A5D5002ULL,
		0xCA94A2F47C6707FEULL,
		0x029BE0D3CD97E4B9ULL,
		0x0D28A3920F49828BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9131CAFC3BFB026EULL,
		0xC8D0BC74691F73AFULL,
		0xE4569D246599F5D0ULL,
		0x9136B4DE1BA58A79ULL,
		0xAD3E2C5054BAA005ULL,
		0x952945E8F8CE0FFDULL,
		0x0537C1A79B2FC973ULL,
		0x1A5147241E930516ULL
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
		0x77566BB87E134935ULL,
		0x925D2F8A298F446FULL,
		0x896F5E73DDF75CAEULL,
		0x59862D1739DDC9E6ULL,
		0xFB9F4E63AD01F3F7ULL,
		0xA38D9D09EA485A66ULL,
		0x6A39689F8A17696FULL,
		0x262A5737986476DBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEEACD770FC26926AULL,
		0x24BA5F14531E88DEULL,
		0x12DEBCE7BBEEB95DULL,
		0xB30C5A2E73BB93CDULL,
		0xF73E9CC75A03E7EEULL,
		0x471B3A13D490B4CDULL,
		0xD472D13F142ED2DFULL,
		0x4C54AE6F30C8EDB6ULL
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
		0xDB376511529E0AA2ULL,
		0x4895B01EFE028892ULL,
		0x93415EEEA6006E3BULL,
		0xBA73B67059B8F85BULL,
		0xD71C51388D0D8D47ULL,
		0x396C69312660ADBEULL,
		0x7E36DF81CF4F18CAULL,
		0x32BF5AF65235A561ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB66ECA22A53C1544ULL,
		0x912B603DFC051125ULL,
		0x2682BDDD4C00DC76ULL,
		0x74E76CE0B371F0B7ULL,
		0xAE38A2711A1B1A8FULL,
		0x72D8D2624CC15B7DULL,
		0xFC6DBF039E9E3194ULL,
		0x657EB5ECA46B4AC2ULL
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
		0xBB0E78B4D57DC857ULL,
		0x1CE65D6FE28D99FCULL,
		0x8E1A208797291C93ULL,
		0x615A71F8F899E0CFULL,
		0xBBE1F0CFB77FA846ULL,
		0x783AD09E53E60A8FULL,
		0xBD25F22C507A1D51ULL,
		0x1AEBB67397123025ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x761CF169AAFB90AEULL,
		0x39CCBADFC51B33F9ULL,
		0x1C34410F2E523926ULL,
		0xC2B4E3F1F133C19FULL,
		0x77C3E19F6EFF508CULL,
		0xF075A13CA7CC151FULL,
		0x7A4BE458A0F43AA2ULL,
		0x35D76CE72E24604BULL
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
		0xE350A51DC21BB0A7ULL,
		0xA78EF1AC439A14CBULL,
		0xA1C4E36FCCACA28BULL,
		0xA5C5CB62EC7CF2ABULL,
		0x85AC0B283F8BDA23ULL,
		0x0D90813D223DED56ULL,
		0x62EB6F1314EF4FF3ULL,
		0x130862E1EA576C07ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC6A14A3B8437614EULL,
		0x4F1DE35887342997ULL,
		0x4389C6DF99594517ULL,
		0x4B8B96C5D8F9E557ULL,
		0x0B5816507F17B447ULL,
		0x1B21027A447BDAADULL,
		0xC5D6DE2629DE9FE6ULL,
		0x2610C5C3D4AED80EULL
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
		0x626651131CD59B6DULL,
		0xCACB8363E3E1EB87ULL,
		0x5119D0EEDDDFDC54ULL,
		0x0D1D6F4ED4119B66ULL,
		0x4A9B14C812E0B7E6ULL,
		0x761F1C609EDC55F2ULL,
		0xC2F7F52B4C0FF417ULL,
		0x3451C223A6C26E5DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC4CCA22639AB36DAULL,
		0x959706C7C7C3D70EULL,
		0xA233A1DDBBBFB8A9ULL,
		0x1A3ADE9DA82336CCULL,
		0x9536299025C16FCCULL,
		0xEC3E38C13DB8ABE4ULL,
		0x85EFEA56981FE82EULL,
		0x68A384474D84DCBBULL
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
		0x1248FED9ECB74F6DULL,
		0x356542160D07822CULL,
		0xA7DA9F7B50548500ULL,
		0x03A7E2B30F395A9AULL,
		0xB3FACB2EDE4C0CECULL,
		0x2F5B618090C368EBULL,
		0x4BE24BCF75297875ULL,
		0x11F7FBD73375AE3AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2491FDB3D96E9EDAULL,
		0x6ACA842C1A0F0458ULL,
		0x4FB53EF6A0A90A00ULL,
		0x074FC5661E72B535ULL,
		0x67F5965DBC9819D8ULL,
		0x5EB6C3012186D1D7ULL,
		0x97C4979EEA52F0EAULL,
		0x23EFF7AE66EB5C74ULL
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
		0xEF4E1B56F55CAC5DULL,
		0xB3E1E4862D06902BULL,
		0xD16CDDA50CA9409CULL,
		0x66CEC804291B308FULL,
		0x473CA20AE1A59E89ULL,
		0x085E1D5192E18D09ULL,
		0x174358E4FA94006DULL,
		0x1493493AB8C3A04CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDE9C36ADEAB958BAULL,
		0x67C3C90C5A0D2057ULL,
		0xA2D9BB4A19528139ULL,
		0xCD9D90085236611FULL,
		0x8E794415C34B3D12ULL,
		0x10BC3AA325C31A12ULL,
		0x2E86B1C9F52800DAULL,
		0x2926927571874098ULL
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
		0x14B8DED8779E2793ULL,
		0x8F2472FE8154E519ULL,
		0x52E8390AB6B34C78ULL,
		0x02C387AF7804B640ULL,
		0x0159FC5E2509F147ULL,
		0x2B325D73807A3919ULL,
		0x55C197B23505F28AULL,
		0x127A24E18EF6B00DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2971BDB0EF3C4F26ULL,
		0x1E48E5FD02A9CA32ULL,
		0xA5D072156D6698F1ULL,
		0x05870F5EF0096C80ULL,
		0x02B3F8BC4A13E28EULL,
		0x5664BAE700F47232ULL,
		0xAB832F646A0BE514ULL,
		0x24F449C31DED601AULL
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
		0xB1096FFA392E8A24ULL,
		0x0191977481389938ULL,
		0x19D8BD28DDF6143FULL,
		0x81FBEBE04A81EFF5ULL,
		0x490DD2D1FC7B99A9ULL,
		0x554DD9D6977245AEULL,
		0x75CEA5AB5B4D4183ULL,
		0x209CBBE33FD2A62DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6212DFF4725D1448ULL,
		0x03232EE902713271ULL,
		0x33B17A51BBEC287EULL,
		0x03F7D7C09503DFEAULL,
		0x921BA5A3F8F73353ULL,
		0xAA9BB3AD2EE48B5CULL,
		0xEB9D4B56B69A8306ULL,
		0x413977C67FA54C5AULL
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
		0xA723F966F490E342ULL,
		0x97BB28A80C9640DFULL,
		0x66BB4D9B268C5290ULL,
		0x3E547F6D7E05F440ULL,
		0xAADA70EBB047F8DDULL,
		0x1A9B80E8079CF0AFULL,
		0xC86B5EE2AD6D8AF8ULL,
		0x0595C473DB11BECAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4E47F2CDE921C684ULL,
		0x2F765150192C81BFULL,
		0xCD769B364D18A521ULL,
		0x7CA8FEDAFC0BE880ULL,
		0x55B4E1D7608FF1BAULL,
		0x353701D00F39E15FULL,
		0x90D6BDC55ADB15F0ULL,
		0x0B2B88E7B6237D95ULL
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
		0x713BE19B3B3AAC79ULL,
		0x3E9D83EB8DD1844CULL,
		0xD945ABAD87D3745CULL,
		0x49E0B8DFC5A723FFULL,
		0x4D1942471A723A1AULL,
		0x8E4E890A60F9D52AULL,
		0x3A52FF994AB5AA42ULL,
		0x0004C23C8F531D16ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE277C336767558F2ULL,
		0x7D3B07D71BA30898ULL,
		0xB28B575B0FA6E8B8ULL,
		0x93C171BF8B4E47FFULL,
		0x9A32848E34E47434ULL,
		0x1C9D1214C1F3AA54ULL,
		0x74A5FF32956B5485ULL,
		0x000984791EA63A2CULL
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
		0xA87BF6D181192666ULL,
		0x1F8205D7D3D310B3ULL,
		0x8617B211751F3294ULL,
		0xE971C32E9998631AULL,
		0xA4F887B8CC3288A7ULL,
		0xC7C36826215EEF42ULL,
		0xCDB2448159C22297ULL,
		0x1E9FE4F2563E016EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x50F7EDA302324CCCULL,
		0x3F040BAFA7A62167ULL,
		0x0C2F6422EA3E6528ULL,
		0xD2E3865D3330C635ULL,
		0x49F10F719865114FULL,
		0x8F86D04C42BDDE85ULL,
		0x9B648902B384452FULL,
		0x3D3FC9E4AC7C02DDULL
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
		0x5257316D913A8C3AULL,
		0x43F5EB6C680DFFDFULL,
		0xAF1294C4304A4D6AULL,
		0x78F08693CD54D072ULL,
		0x63F9F9996D97A5BBULL,
		0xE6D0427F642BB157ULL,
		0xE17743CD1E729F17ULL,
		0x1D8128B84F7FAE0DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA4AE62DB22751874ULL,
		0x87EBD6D8D01BFFBEULL,
		0x5E25298860949AD4ULL,
		0xF1E10D279AA9A0E5ULL,
		0xC7F3F332DB2F4B76ULL,
		0xCDA084FEC85762AEULL,
		0xC2EE879A3CE53E2FULL,
		0x3B0251709EFF5C1BULL
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
		0xF136A11E3F599993ULL,
		0x110CBC8D10071523ULL,
		0xB12C3AFCB78BA6DBULL,
		0x2AADA5E231623191ULL,
		0x87AAD603374AD947ULL,
		0x1CF261F543D512BCULL,
		0x9DCF1872C30A41CEULL,
		0x18F24FDA4CFAB864ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE26D423C7EB33326ULL,
		0x2219791A200E2A47ULL,
		0x625875F96F174DB6ULL,
		0x555B4BC462C46323ULL,
		0x0F55AC066E95B28EULL,
		0x39E4C3EA87AA2579ULL,
		0x3B9E30E58614839CULL,
		0x31E49FB499F570C9ULL
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
		0x1DA50871D6D0659BULL,
		0x099786831A6F9DC9ULL,
		0x2AEE56293C364AA6ULL,
		0x8320AB9DFA9A0057ULL,
		0xD99061157A95AC2BULL,
		0x1117DDCD622E2839ULL,
		0x9A44F7B89FF53D65ULL,
		0x04274BA10086FD10ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3B4A10E3ADA0CB36ULL,
		0x132F0D0634DF3B92ULL,
		0x55DCAC52786C954CULL,
		0x0641573BF53400AEULL,
		0xB320C22AF52B5857ULL,
		0x222FBB9AC45C5073ULL,
		0x3489EF713FEA7ACAULL,
		0x084E9742010DFA21ULL
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
		0x934FB757C012D457ULL,
		0xE216E6F90ACB4AE7ULL,
		0x8367C96C9E9FEE41ULL,
		0x358C93BD13B46A0CULL,
		0xD9650AA7909969DCULL,
		0x14DF62AE5544FB31ULL,
		0x3331BCB2F9A82006ULL,
		0x26A2C9113A19C9D5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x269F6EAF8025A8AEULL,
		0xC42DCDF2159695CFULL,
		0x06CF92D93D3FDC83ULL,
		0x6B19277A2768D419ULL,
		0xB2CA154F2132D3B8ULL,
		0x29BEC55CAA89F663ULL,
		0x66637965F350400CULL,
		0x4D459222743393AAULL
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
		0x8FA78B81BDF9C0E5ULL,
		0x5B89C37D59DCDADFULL,
		0x7C10B25DEDB82751ULL,
		0xAF7D718B572E0472ULL,
		0x7FB3E34436FE2C3DULL,
		0x2C1E8C15169762EEULL,
		0x8CB60D09174C5AFAULL,
		0x2B908429DFEE8080ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1F4F17037BF381CAULL,
		0xB71386FAB3B9B5BFULL,
		0xF82164BBDB704EA2ULL,
		0x5EFAE316AE5C08E4ULL,
		0xFF67C6886DFC587BULL,
		0x583D182A2D2EC5DCULL,
		0x196C1A122E98B5F4ULL,
		0x57210853BFDD0101ULL
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
		0x5521DDB062E893F8ULL,
		0xE9AB58745C4B3B4DULL,
		0x0F2A7FDD126DA5D7ULL,
		0xF4EF81C5B10D7E07ULL,
		0xC224C2ECF2D7E61CULL,
		0xB3DD0794BEDF3351ULL,
		0xD7E8FF9F152C47C5ULL,
		0x1BD2AA52694E9DC4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAA43BB60C5D127F0ULL,
		0xD356B0E8B896769AULL,
		0x1E54FFBA24DB4BAFULL,
		0xE9DF038B621AFC0EULL,
		0x844985D9E5AFCC39ULL,
		0x67BA0F297DBE66A3ULL,
		0xAFD1FF3E2A588F8BULL,
		0x37A554A4D29D3B89ULL
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
		0x00411B17B4C5F9A2ULL,
		0x776155A5610200E4ULL,
		0xF4233F316F61E853ULL,
		0x7FF896406528D31BULL,
		0xC59325A6738D09D4ULL,
		0x0FBD3025C334CDDEULL,
		0x598FAAA69FB37698ULL,
		0x2CA01DD4922A0CD7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0082362F698BF344ULL,
		0xEEC2AB4AC20401C8ULL,
		0xE8467E62DEC3D0A6ULL,
		0xFFF12C80CA51A637ULL,
		0x8B264B4CE71A13A8ULL,
		0x1F7A604B86699BBDULL,
		0xB31F554D3F66ED30ULL,
		0x59403BA9245419AEULL
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
		0x44FB5C0848A90FF7ULL,
		0x8B0F680D645A5135ULL,
		0x537BFB77C1195CF3ULL,
		0x71245A604457D404ULL,
		0x537BADE404CFCD1DULL,
		0x62C14E8BA8E48085ULL,
		0xDCD3C85A954D1D79ULL,
		0x330F9E257E7BE81AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x89F6B81091521FEEULL,
		0x161ED01AC8B4A26AULL,
		0xA6F7F6EF8232B9E7ULL,
		0xE248B4C088AFA808ULL,
		0xA6F75BC8099F9A3AULL,
		0xC5829D1751C9010AULL,
		0xB9A790B52A9A3AF2ULL,
		0x661F3C4AFCF7D035ULL
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
		0xF574B0D48CDE204BULL,
		0xDEF065F186EEB7E4ULL,
		0x94A56BA4A3FDC8B4ULL,
		0xE550AF7A79A5F549ULL,
		0xDB2B97AB410DE93CULL,
		0x2AB4C4DBF4BE348CULL,
		0x9444BDD14B44B8ADULL,
		0x0CF08E8BECA5C554ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEAE961A919BC4096ULL,
		0xBDE0CBE30DDD6FC9ULL,
		0x294AD74947FB9169ULL,
		0xCAA15EF4F34BEA93ULL,
		0xB6572F56821BD279ULL,
		0x556989B7E97C6919ULL,
		0x28897BA29689715AULL,
		0x19E11D17D94B8AA9ULL
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
		0x289ECE9D68C02E59ULL,
		0x1ECFDB2333884204ULL,
		0xE7B4691B9DA7A47EULL,
		0x65F36A02AFC862BAULL,
		0x41E8FA88019C5125ULL,
		0xE64D5DA191377F5CULL,
		0xA08D355528336A85ULL,
		0x171377B336DBF006ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x513D9D3AD1805CB2ULL,
		0x3D9FB64667108408ULL,
		0xCF68D2373B4F48FCULL,
		0xCBE6D4055F90C575ULL,
		0x83D1F5100338A24AULL,
		0xCC9ABB43226EFEB8ULL,
		0x411A6AAA5066D50BULL,
		0x2E26EF666DB7E00DULL
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
		0xE14FBC7B8D87DF40ULL,
		0xFA150AF614DCD943ULL,
		0x5FEE7B2C09D7DEDDULL,
		0xA1A908228D3DF122ULL,
		0x26A1D9E69E5AF153ULL,
		0x9F5CB031FDF9601FULL,
		0x85913E9100816782ULL,
		0x3462177CFD7EC96CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC29F78F71B0FBE80ULL,
		0xF42A15EC29B9B287ULL,
		0xBFDCF65813AFBDBBULL,
		0x435210451A7BE244ULL,
		0x4D43B3CD3CB5E2A7ULL,
		0x3EB96063FBF2C03EULL,
		0x0B227D220102CF05ULL,
		0x68C42EF9FAFD92D9ULL
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
		0x73399248B25597D2ULL,
		0x0A752BC8BEBA74DAULL,
		0xE54A62DC7B60A72EULL,
		0xE5ABC26536E2B00DULL,
		0xB80A14460DE63C3BULL,
		0x0335775EEA076612ULL,
		0x8C7A7B858FD2D61EULL,
		0x11AB5F28FA436C10ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE673249164AB2FA4ULL,
		0x14EA57917D74E9B4ULL,
		0xCA94C5B8F6C14E5CULL,
		0xCB5784CA6DC5601BULL,
		0x7014288C1BCC7877ULL,
		0x066AEEBDD40ECC25ULL,
		0x18F4F70B1FA5AC3CULL,
		0x2356BE51F486D821ULL
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
		0xBFE900437144304DULL,
		0xD452F911B290ACB4ULL,
		0x1B9D6D041B8B9423ULL,
		0xC9FBD042D9C4663CULL,
		0x3838369FE62A877CULL,
		0x2E34EBDF41FD7359ULL,
		0x9509D6DC4FD8C599ULL,
		0x13189A307298A31EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7FD20086E288609AULL,
		0xA8A5F22365215969ULL,
		0x373ADA0837172847ULL,
		0x93F7A085B388CC78ULL,
		0x70706D3FCC550EF9ULL,
		0x5C69D7BE83FAE6B2ULL,
		0x2A13ADB89FB18B32ULL,
		0x26313460E531463DULL
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
		0x97D209D888DF98F8ULL,
		0x24701D04C5C675AEULL,
		0xDDED27E42BAD0838ULL,
		0xBFF2EBD7795D8064ULL,
		0x75D9261502E57237ULL,
		0xA1018A0934110007ULL,
		0x46A912586B0F8ED9ULL,
		0x0AB4EBED53D57FDAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2FA413B111BF31F0ULL,
		0x48E03A098B8CEB5DULL,
		0xBBDA4FC8575A1070ULL,
		0x7FE5D7AEF2BB00C9ULL,
		0xEBB24C2A05CAE46FULL,
		0x420314126822000EULL,
		0x8D5224B0D61F1DB3ULL,
		0x1569D7DAA7AAFFB4ULL
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
		0xED4C4A1ED0F1DF59ULL,
		0x3B45E9753D1C4710ULL,
		0xE52DE981696AF8D5ULL,
		0x85C5EE180BDE6B38ULL,
		0xB206876E1F5AEBA4ULL,
		0xA2B158D5A45A82BBULL,
		0x6C747542888F31A4ULL,
		0x03AC880984CD1E6AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDA98943DA1E3BEB2ULL,
		0x768BD2EA7A388E21ULL,
		0xCA5BD302D2D5F1AAULL,
		0x0B8BDC3017BCD671ULL,
		0x640D0EDC3EB5D749ULL,
		0x4562B1AB48B50577ULL,
		0xD8E8EA85111E6349ULL,
		0x07591013099A3CD4ULL
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
		0xE5227028A5287845ULL,
		0x73F1D65D479B18D0ULL,
		0x73018B03D8B8F736ULL,
		0xE1ED9AA09390CC5EULL,
		0xF8E6387F6E1CC6F2ULL,
		0x6FF48E3E1C1D30B6ULL,
		0x3FC7BE243A140747ULL,
		0x2445FD827F5EAD64ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCA44E0514A50F08AULL,
		0xE7E3ACBA8F3631A1ULL,
		0xE6031607B171EE6CULL,
		0xC3DB3541272198BCULL,
		0xF1CC70FEDC398DE5ULL,
		0xDFE91C7C383A616DULL,
		0x7F8F7C4874280E8EULL,
		0x488BFB04FEBD5AC8ULL
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
		0xD11F1992428BDDC0ULL,
		0x6B76531F2B197D2BULL,
		0x26B689766AF4E7EDULL,
		0xD326638F4B9E65A5ULL,
		0xFF45C1B6DEA5B31AULL,
		0x27E51C9D61F999E4ULL,
		0xDBDB42C4DC3EAC8EULL,
		0x3DBDBDB297F65D8FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA23E33248517BB80ULL,
		0xD6ECA63E5632FA57ULL,
		0x4D6D12ECD5E9CFDAULL,
		0xA64CC71E973CCB4AULL,
		0xFE8B836DBD4B6635ULL,
		0x4FCA393AC3F333C9ULL,
		0xB7B68589B87D591CULL,
		0x7B7B7B652FECBB1FULL
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
		0x913F3199A407A5DFULL,
		0xF3AADE1EBE672341ULL,
		0x6AE32C660B9A0474ULL,
		0x3C4A23EDBD5D11F6ULL,
		0x22FFA5BC71724A24ULL,
		0x9A2215B6D6BDDE25ULL,
		0xD830B958F1B3AB9AULL,
		0x187B2BD83F75772FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x227E6333480F4BBEULL,
		0xE755BC3D7CCE4683ULL,
		0xD5C658CC173408E9ULL,
		0x789447DB7ABA23ECULL,
		0x45FF4B78E2E49448ULL,
		0x34442B6DAD7BBC4AULL,
		0xB06172B1E3675735ULL,
		0x30F657B07EEAEE5FULL
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
		0x51D23641E040FBABULL,
		0x318C04B7E9F0B62FULL,
		0x19B09B28AAD093F9ULL,
		0x555AFC5C41DD5007ULL,
		0xCC04AD00755F4975ULL,
		0x346787FA450A3CC8ULL,
		0x6FEA6A5D28A7055CULL,
		0x1CFEB476363CFBF9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA3A46C83C081F756ULL,
		0x6318096FD3E16C5EULL,
		0x3361365155A127F2ULL,
		0xAAB5F8B883BAA00EULL,
		0x98095A00EABE92EAULL,
		0x68CF0FF48A147991ULL,
		0xDFD4D4BA514E0AB8ULL,
		0x39FD68EC6C79F7F2ULL
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
		0x6591BD96668C7635ULL,
		0x0EC2263BF7D58F56ULL,
		0x402FA6F4AACE2AA2ULL,
		0xA051D9C727B83A5FULL,
		0x8A7B41B12EB8C22BULL,
		0xB39FAEECF168D85CULL,
		0x589C6CF674A6B9AFULL,
		0x29DFFC448BEF3E12ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCB237B2CCD18EC6AULL,
		0x1D844C77EFAB1EACULL,
		0x805F4DE9559C5544ULL,
		0x40A3B38E4F7074BEULL,
		0x14F683625D718457ULL,
		0x673F5DD9E2D1B0B9ULL,
		0xB138D9ECE94D735FULL,
		0x53BFF88917DE7C24ULL
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
		0xF143DD085C91C8B3ULL,
		0x6BEC180A52B6BAA8ULL,
		0x0036C582F8CACD33ULL,
		0xA98A4C237B92AB2CULL,
		0x12F669AAF5D83E78ULL,
		0x7BD78AB1587267B1ULL,
		0x571805ADFE35F2F6ULL,
		0x392AD1249F548461ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE287BA10B9239166ULL,
		0xD7D83014A56D7551ULL,
		0x006D8B05F1959A66ULL,
		0x53149846F7255658ULL,
		0x25ECD355EBB07CF1ULL,
		0xF7AF1562B0E4CF62ULL,
		0xAE300B5BFC6BE5ECULL,
		0x7255A2493EA908C2ULL
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
		0x3C114EF41EAD83F8ULL,
		0xAC48CC1983549E66ULL,
		0x204BD02E734C299DULL,
		0xF6FBDC2FB143821FULL,
		0x82E21FA3044190ACULL,
		0x49CBFAD113E47697ULL,
		0x16A36A22B46B4855ULL,
		0x077A82C738AC1937ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x78229DE83D5B07F0ULL,
		0x5891983306A93CCCULL,
		0x4097A05CE698533BULL,
		0xEDF7B85F6287043EULL,
		0x05C43F4608832159ULL,
		0x9397F5A227C8ED2FULL,
		0x2D46D44568D690AAULL,
		0x0EF5058E7158326EULL
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
		0x11440C3F7E5015F6ULL,
		0x6010AB6712E3980CULL,
		0x9D3C7936DFAF35EBULL,
		0xF2137611FBAF2DA2ULL,
		0x9C75C32C428FE5A4ULL,
		0xC50B539B2DE7DFE1ULL,
		0x94FD7FA12360081AULL,
		0x30533DAD8525DFF1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2288187EFCA02BECULL,
		0xC02156CE25C73018ULL,
		0x3A78F26DBF5E6BD6ULL,
		0xE426EC23F75E5B45ULL,
		0x38EB8658851FCB49ULL,
		0x8A16A7365BCFBFC3ULL,
		0x29FAFF4246C01035ULL,
		0x60A67B5B0A4BBFE3ULL
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
		0x3811F363A09B6113ULL,
		0x8984C25C76680C91ULL,
		0x238A960B8B6A9602ULL,
		0x4F5B26425A90FAE6ULL,
		0x6BACB23488817FF2ULL,
		0x2F8E4CA5FD8A4794ULL,
		0xC957BEDCAB7F66EEULL,
		0x1FF3B3C0E26286A9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7023E6C74136C226ULL,
		0x130984B8ECD01922ULL,
		0x47152C1716D52C05ULL,
		0x9EB64C84B521F5CCULL,
		0xD75964691102FFE4ULL,
		0x5F1C994BFB148F28ULL,
		0x92AF7DB956FECDDCULL,
		0x3FE76781C4C50D53ULL
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
		0x1F8F014A8D2F28F1ULL,
		0x441F75BA1F471B7FULL,
		0x79748DEC9A913C84ULL,
		0x5F115D4C926FDFB4ULL,
		0x54E1F44831277945ULL,
		0x59632AD16564F1E8ULL,
		0x4C9B58656B35126DULL,
		0x25171D5ECECCC780ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3F1E02951A5E51E2ULL,
		0x883EEB743E8E36FEULL,
		0xF2E91BD935227908ULL,
		0xBE22BA9924DFBF68ULL,
		0xA9C3E890624EF28AULL,
		0xB2C655A2CAC9E3D0ULL,
		0x9936B0CAD66A24DAULL,
		0x4A2E3ABD9D998F00ULL
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
		0x829384391895FBDCULL,
		0xB6ADC39D7BABE596ULL,
		0xD9C8631445817A3CULL,
		0x29379DEB3F12C555ULL,
		0xA9138C1735F427FBULL,
		0x63E5671DCA1A1DDDULL,
		0x7520C2958A1AD7A3ULL,
		0x3966F2B8858AD0B6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x05270872312BF7B8ULL,
		0x6D5B873AF757CB2DULL,
		0xB390C6288B02F479ULL,
		0x526F3BD67E258AABULL,
		0x5227182E6BE84FF6ULL,
		0xC7CACE3B94343BBBULL,
		0xEA41852B1435AF46ULL,
		0x72CDE5710B15A16CULL
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
		0xCF065372570A72F5ULL,
		0x2A4E69626E1EC855ULL,
		0x475637A89968B4EFULL,
		0x1C923DEF629550C4ULL,
		0xEB14FF3B8A3B996AULL,
		0x92FBD1EFDB127DD9ULL,
		0xFB65E913154725F3ULL,
		0x2C9B577B9A85DFC2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9E0CA6E4AE14E5EAULL,
		0x549CD2C4DC3D90ABULL,
		0x8EAC6F5132D169DEULL,
		0x39247BDEC52AA188ULL,
		0xD629FE77147732D4ULL,
		0x25F7A3DFB624FBB3ULL,
		0xF6CBD2262A8E4BE7ULL,
		0x5936AEF7350BBF85ULL
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
		0x4F53DF23EE23CA60ULL,
		0x50D24FD28EC46DEEULL,
		0xD2A302B698F7BC05ULL,
		0x04ED373A94E3A452ULL,
		0x1E5C94DED3146851ULL,
		0x2C04A4FA22F3BBABULL,
		0x274B1C30645E6A75ULL,
		0x11B6EAFB2C3229BEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9EA7BE47DC4794C0ULL,
		0xA1A49FA51D88DBDCULL,
		0xA546056D31EF780AULL,
		0x09DA6E7529C748A5ULL,
		0x3CB929BDA628D0A2ULL,
		0x580949F445E77756ULL,
		0x4E963860C8BCD4EAULL,
		0x236DD5F65864537CULL
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
		0xC030442A39080417ULL,
		0xE685BDD9F87AB388ULL,
		0x4EEF01B6AEBBEA7CULL,
		0xDF58D6125070D387ULL,
		0x3810E91108DEFD42ULL,
		0xBBFCE60887B450F8ULL,
		0x07CEDEE159A4DC80ULL,
		0x02C2EBF013137487ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x806088547210082EULL,
		0xCD0B7BB3F0F56711ULL,
		0x9DDE036D5D77D4F9ULL,
		0xBEB1AC24A0E1A70EULL,
		0x7021D22211BDFA85ULL,
		0x77F9CC110F68A1F0ULL,
		0x0F9DBDC2B349B901ULL,
		0x0585D7E02626E90EULL
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
		0x6B6155A7D2A19945ULL,
		0x0CA2BACB48160925ULL,
		0x0B52299F7E28E263ULL,
		0x991CB49AC12072F7ULL,
		0xE0ACC22A53099493ULL,
		0x82655DC2DC76D68EULL,
		0xAF3C4ECE9A57B721ULL,
		0x294D8765551D5D1FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD6C2AB4FA543328AULL,
		0x19457596902C124AULL,
		0x16A4533EFC51C4C6ULL,
		0x323969358240E5EEULL,
		0xC1598454A6132927ULL,
		0x04CABB85B8EDAD1DULL,
		0x5E789D9D34AF6E43ULL,
		0x529B0ECAAA3ABA3FULL
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
		0xA19D64CB6065B768ULL,
		0xA95212AF5F3B9867ULL,
		0x55B7BE132682047AULL,
		0x99A9619A32F890B5ULL,
		0x7A9CCF49663ABCB4ULL,
		0xF5EFF9E56445EE72ULL,
		0xC13E3E1C8F1FFB7DULL,
		0x03DE909C2D2106E2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x433AC996C0CB6ED0ULL,
		0x52A4255EBE7730CFULL,
		0xAB6F7C264D0408F5ULL,
		0x3352C33465F1216AULL,
		0xF5399E92CC757969ULL,
		0xEBDFF3CAC88BDCE4ULL,
		0x827C7C391E3FF6FBULL,
		0x07BD21385A420DC5ULL
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
		0x8963CE55659DFC59ULL,
		0xD895F2E30F889175ULL,
		0xA99A3C46C62C3B40ULL,
		0xCD10ECB06A266E39ULL,
		0xB7321B0F026FACF2ULL,
		0xEAC0DA42BAA4DB65ULL,
		0x04FA454B70413658ULL,
		0x351C023289E16FE0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x12C79CAACB3BF8B2ULL,
		0xB12BE5C61F1122EBULL,
		0x5334788D8C587681ULL,
		0x9A21D960D44CDC73ULL,
		0x6E64361E04DF59E5ULL,
		0xD581B4857549B6CBULL,
		0x09F48A96E0826CB1ULL,
		0x6A38046513C2DFC0ULL
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
		0xEDD82F3BEFE92C02ULL,
		0x7D57F124EC8A8F15ULL,
		0x2BECAA4BF5219032ULL,
		0x4A361EF626ABE4D3ULL,
		0x1742F70DF4C9A79EULL,
		0x8E117DB0C328796BULL,
		0xA1661829F0A5363AULL,
		0x373FB941C8524F62ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDBB05E77DFD25804ULL,
		0xFAAFE249D9151E2BULL,
		0x57D95497EA432064ULL,
		0x946C3DEC4D57C9A6ULL,
		0x2E85EE1BE9934F3CULL,
		0x1C22FB618650F2D6ULL,
		0x42CC3053E14A6C75ULL,
		0x6E7F728390A49EC5ULL
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
		0x77C22BFA2D73BEB0ULL,
		0x7C22698C62752C06ULL,
		0x896DC89544FF69FBULL,
		0xB39312CC76E7C860ULL,
		0x87CE8ADA56B0ABF1ULL,
		0x44C0F7D118B5A9DDULL,
		0x35A63351E64DB926ULL,
		0x1C5E5B6A0EA525DEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEF8457F45AE77D60ULL,
		0xF844D318C4EA580CULL,
		0x12DB912A89FED3F6ULL,
		0x67262598EDCF90C1ULL,
		0x0F9D15B4AD6157E3ULL,
		0x8981EFA2316B53BBULL,
		0x6B4C66A3CC9B724CULL,
		0x38BCB6D41D4A4BBCULL
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
		0x59EBEC7CFF87554BULL,
		0x1FFAC8CA293F4290ULL,
		0x6E8ED1C6099E4CAEULL,
		0x376D23981978A2E0ULL,
		0xB0E321FA8CA818A1ULL,
		0xF69F44C5DFEE37A5ULL,
		0x389D5A52304690E7ULL,
		0x253311BD4AF94E8CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB3D7D8F9FF0EAA96ULL,
		0x3FF59194527E8520ULL,
		0xDD1DA38C133C995CULL,
		0x6EDA473032F145C0ULL,
		0x61C643F519503142ULL,
		0xED3E898BBFDC6F4BULL,
		0x713AB4A4608D21CFULL,
		0x4A66237A95F29D18ULL
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
		0xC03847C892272C77ULL,
		0x3B011EFB4447E320ULL,
		0x13333195869A6879ULL,
		0x792320D422E5BAB4ULL,
		0x44B94691FF16F679ULL,
		0xFC648444CE4E3500ULL,
		0x2E8379628104A27FULL,
		0x0B71F371118B3AC1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x80708F91244E58EEULL,
		0x76023DF6888FC641ULL,
		0x2666632B0D34D0F2ULL,
		0xF24641A845CB7568ULL,
		0x89728D23FE2DECF2ULL,
		0xF8C908899C9C6A00ULL,
		0x5D06F2C5020944FFULL,
		0x16E3E6E223167582ULL
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
		0x289C950F7E64648DULL,
		0x99506D6F876B2FD4ULL,
		0x7764F184C80B687FULL,
		0x1D0DDE25E9168D5AULL,
		0x4C5128F9FC41AC4EULL,
		0xC3EE88A4F0B7A41FULL,
		0xFA93FAF25079AF1AULL,
		0x280C1D15E83313B0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x51392A1EFCC8C91AULL,
		0x32A0DADF0ED65FA8ULL,
		0xEEC9E3099016D0FFULL,
		0x3A1BBC4BD22D1AB4ULL,
		0x98A251F3F883589CULL,
		0x87DD1149E16F483EULL,
		0xF527F5E4A0F35E35ULL,
		0x50183A2BD0662761ULL
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
		0x80769470B1680827ULL,
		0x56D29E55EBB6FE65ULL,
		0xFBD9567F8533BA9CULL,
		0x3737539F2637B523ULL,
		0x0BDB4D3E8B91A184ULL,
		0x420F5DAF45FA75E6ULL,
		0xC346328FDD2C8652ULL,
		0x0AFEF3773270F221ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x00ED28E162D0104EULL,
		0xADA53CABD76DFCCBULL,
		0xF7B2ACFF0A677538ULL,
		0x6E6EA73E4C6F6A47ULL,
		0x17B69A7D17234308ULL,
		0x841EBB5E8BF4EBCCULL,
		0x868C651FBA590CA4ULL,
		0x15FDE6EE64E1E443ULL
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
		0x9F5A3A0405B97240ULL,
		0x39D913AC4E453AF1ULL,
		0x6C9E7837178E7AC9ULL,
		0xBED5F5C957D9D172ULL,
		0x6F65F63CDEC4078AULL,
		0x27B8AA187F885948ULL,
		0x91DBDEF79781A626ULL,
		0x37A628DD5CBBB88CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3EB474080B72E480ULL,
		0x73B227589C8A75E3ULL,
		0xD93CF06E2F1CF592ULL,
		0x7DABEB92AFB3A2E4ULL,
		0xDECBEC79BD880F15ULL,
		0x4F715430FF10B290ULL,
		0x23B7BDEF2F034C4CULL,
		0x6F4C51BAB9777119ULL
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
		0x6450BF80810C85FCULL,
		0x11B3506049B0FB8AULL,
		0xF268DFB5842F4F5FULL,
		0xE295B9160A9EA906ULL,
		0x0DB82891CC5DEF02ULL,
		0x3C076902EC2DC188ULL,
		0xB1EC7C00DF919D36ULL,
		0x0263C349C21A9D1AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC8A17F0102190BF8ULL,
		0x2366A0C09361F714ULL,
		0xE4D1BF6B085E9EBEULL,
		0xC52B722C153D520DULL,
		0x1B70512398BBDE05ULL,
		0x780ED205D85B8310ULL,
		0x63D8F801BF233A6CULL,
		0x04C7869384353A35ULL
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
		0x2C413AD56145FDE5ULL,
		0x2E71C5777C468171ULL,
		0x5405887786FD4797ULL,
		0x6AC732475C22D31DULL,
		0x9F67DEDCA7132C0DULL,
		0x1227C6EBB9CCE2D5ULL,
		0x0989485267F6F68AULL,
		0x1FD98FAB30ACFBBFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x588275AAC28BFBCAULL,
		0x5CE38AEEF88D02E2ULL,
		0xA80B10EF0DFA8F2EULL,
		0xD58E648EB845A63AULL,
		0x3ECFBDB94E26581AULL,
		0x244F8DD77399C5ABULL,
		0x131290A4CFEDED14ULL,
		0x3FB31F566159F77EULL
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
		0xAD544B1FEC2EFA04ULL,
		0xD2C0AF4DD3E86B37ULL,
		0x98B0BE0276550EE2ULL,
		0x057BB6E83E7D6493ULL,
		0x069F615DFEF88B11ULL,
		0xA7470940AFE4913CULL,
		0x5C1EB6C8B356BF48ULL,
		0x2A0B32B23C781DB5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5AA8963FD85DF408ULL,
		0xA5815E9BA7D0D66FULL,
		0x31617C04ECAA1DC5ULL,
		0x0AF76DD07CFAC927ULL,
		0x0D3EC2BBFDF11622ULL,
		0x4E8E12815FC92278ULL,
		0xB83D6D9166AD7E91ULL,
		0x5416656478F03B6AULL
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
		0x1A4F6002CF7D8EFFULL,
		0xDA84A187D2F82991ULL,
		0x4D0564AE3914C3F9ULL,
		0x0C991889E31CC650ULL,
		0xFCE89791DBB55256ULL,
		0x80961C2F5714D6C4ULL,
		0x5843252562ED3A11ULL,
		0x3EC391C96E104B41ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x349EC0059EFB1DFEULL,
		0xB509430FA5F05322ULL,
		0x9A0AC95C722987F3ULL,
		0x19323113C6398CA0ULL,
		0xF9D12F23B76AA4ACULL,
		0x012C385EAE29AD89ULL,
		0xB0864A4AC5DA7423ULL,
		0x7D872392DC209682ULL
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
		0x5060FF46B920E827ULL,
		0xA02AA638859A236AULL,
		0x57254A75B35F4144ULL,
		0x0EAF8E0355031489ULL,
		0x8434759EB801D31FULL,
		0x813A3282EAFFAF6BULL,
		0x477DD73196EB14E0ULL,
		0x05126061D40CED4AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA0C1FE8D7241D04EULL,
		0x40554C710B3446D4ULL,
		0xAE4A94EB66BE8289ULL,
		0x1D5F1C06AA062912ULL,
		0x0868EB3D7003A63EULL,
		0x02746505D5FF5ED7ULL,
		0x8EFBAE632DD629C1ULL,
		0x0A24C0C3A819DA94ULL
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
		0x51782AA08DA29E15ULL,
		0xE5EDC2E58C36A359ULL,
		0xDEAC0020B9CF7914ULL,
		0x4A7BFA50EC653554ULL,
		0xD9FBC8CF9B131881ULL,
		0x145275A08A8A5D6AULL,
		0x0FB027CDE6D46160ULL,
		0x3FADB735CD9E8A34ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA2F055411B453C2AULL,
		0xCBDB85CB186D46B2ULL,
		0xBD580041739EF229ULL,
		0x94F7F4A1D8CA6AA9ULL,
		0xB3F7919F36263102ULL,
		0x28A4EB411514BAD5ULL,
		0x1F604F9BCDA8C2C0ULL,
		0x7F5B6E6B9B3D1468ULL
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
		0x48133AFCC8D2056DULL,
		0x17E28C8AC65A3C0CULL,
		0x243ACAF1CC79A706ULL,
		0xE02000D13FA9373AULL,
		0x73D2720D6B3C6347ULL,
		0xB323751BC029D3D2ULL,
		0x3726D96BF1E110D0ULL,
		0x3429442118AEB721ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x902675F991A40ADAULL,
		0x2FC519158CB47818ULL,
		0x487595E398F34E0CULL,
		0xC04001A27F526E74ULL,
		0xE7A4E41AD678C68FULL,
		0x6646EA378053A7A4ULL,
		0x6E4DB2D7E3C221A1ULL,
		0x68528842315D6E42ULL
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
		0x8099B426C5589E38ULL,
		0x7ECD66185E1CBEB6ULL,
		0xAD0519BE38FFA5E6ULL,
		0x36BD4F422D523B38ULL,
		0x0151403A3EBF3F02ULL,
		0xA52D2772781A95A0ULL,
		0xC094E3469DD0739EULL,
		0x1CB427D4F367D6A9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0133684D8AB13C70ULL,
		0xFD9ACC30BC397D6DULL,
		0x5A0A337C71FF4BCCULL,
		0x6D7A9E845AA47671ULL,
		0x02A280747D7E7E04ULL,
		0x4A5A4EE4F0352B40ULL,
		0x8129C68D3BA0E73DULL,
		0x39684FA9E6CFAD53ULL
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
		0xD1D037ED3ADE3843ULL,
		0xBEE55AB0FC8FF57CULL,
		0xDA026AC2863C64CAULL,
		0x951EDCFCE174D907ULL,
		0x06CD4D327ADF89C0ULL,
		0x6235EEEEC429A0D0ULL,
		0x3DC062FE39690C5AULL,
		0x11CD6CC35C9CDFA8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA3A06FDA75BC7086ULL,
		0x7DCAB561F91FEAF9ULL,
		0xB404D5850C78C995ULL,
		0x2A3DB9F9C2E9B20FULL,
		0x0D9A9A64F5BF1381ULL,
		0xC46BDDDD885341A0ULL,
		0x7B80C5FC72D218B4ULL,
		0x239AD986B939BF50ULL
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
		0xDA020E04DDB292C0ULL,
		0x6C3600A516076B75ULL,
		0xD0C1084B9FCB1D46ULL,
		0x70002AE8B041D252ULL,
		0xE56D542DE3AB6E3FULL,
		0x51099FCDF18879F1ULL,
		0x8392672B367D062FULL,
		0x1A8BD40B21EEC036ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB4041C09BB652580ULL,
		0xD86C014A2C0ED6EBULL,
		0xA18210973F963A8CULL,
		0xE00055D16083A4A5ULL,
		0xCADAA85BC756DC7EULL,
		0xA2133F9BE310F3E3ULL,
		0x0724CE566CFA0C5EULL,
		0x3517A81643DD806DULL
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
		0x48A83D22A20D63ABULL,
		0x39D1159754050574ULL,
		0x226FFF95BF307BA1ULL,
		0x2BB9EC5A28DD9A28ULL,
		0x0D8CB3D75B12DA3AULL,
		0xEFA9FC4ED9DC3A98ULL,
		0xB9157F0FC3C960BEULL,
		0x0530BF8903491ECFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x91507A45441AC756ULL,
		0x73A22B2EA80A0AE8ULL,
		0x44DFFF2B7E60F742ULL,
		0x5773D8B451BB3450ULL,
		0x1B1967AEB625B474ULL,
		0xDF53F89DB3B87530ULL,
		0x722AFE1F8792C17DULL,
		0x0A617F1206923D9FULL
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
		0x4DD68825C44CA512ULL,
		0x9A1CA9A1A475DB0BULL,
		0xF79D2073D0453237ULL,
		0xF83A2B52D36EE3A7ULL,
		0xE67CF140D075012BULL,
		0x0E6092B335EB2B15ULL,
		0x9F3636BF9C923444ULL,
		0x0DF7297F9FFA49E4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9BAD104B88994A24ULL,
		0x3439534348EBB616ULL,
		0xEF3A40E7A08A646FULL,
		0xF07456A5A6DDC74FULL,
		0xCCF9E281A0EA0257ULL,
		0x1CC125666BD6562BULL,
		0x3E6C6D7F39246888ULL,
		0x1BEE52FF3FF493C9ULL
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
		0x775770618B493D18ULL,
		0xA025D554B52DE319ULL,
		0x0D55DEBB935DA8C2ULL,
		0xA3F9D1D5870D8375ULL,
		0x150794B5027CA557ULL,
		0x2714D852B351162FULL,
		0x00A8576E548513EFULL,
		0x272016A76E0FCA0AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEEAEE0C316927A30ULL,
		0x404BAAA96A5BC632ULL,
		0x1AABBD7726BB5185ULL,
		0x47F3A3AB0E1B06EAULL,
		0x2A0F296A04F94AAFULL,
		0x4E29B0A566A22C5EULL,
		0x0150AEDCA90A27DEULL,
		0x4E402D4EDC1F9414ULL
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
		0x74F10167922C39C3ULL,
		0xCD03D5C7565009F0ULL,
		0x5C0208F0C9567741ULL,
		0x0C95E4C8E1C06F7FULL,
		0xEC8319E59FBF74C7ULL,
		0x2DAFF5DD55F2FB2DULL,
		0xC7BE7E5B08DAC7E3ULL,
		0x29917CFB34AEE995ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE9E202CF24587386ULL,
		0x9A07AB8EACA013E0ULL,
		0xB80411E192ACEE83ULL,
		0x192BC991C380DEFEULL,
		0xD90633CB3F7EE98EULL,
		0x5B5FEBBAABE5F65BULL,
		0x8F7CFCB611B58FC6ULL,
		0x5322F9F6695DD32BULL
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
		0x9E7A99D7037CB3B8ULL,
		0x50F7144C3C33010DULL,
		0xBFA4A328E419923EULL,
		0x0C7C07F246EC0F0AULL,
		0x3438BA39A23712DCULL,
		0xBDF33B6ADA56E613ULL,
		0xE7CAFDD48252DCCDULL,
		0x21B6C5DA46BE26A9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3CF533AE06F96770ULL,
		0xA1EE28987866021BULL,
		0x7F494651C833247CULL,
		0x18F80FE48DD81E15ULL,
		0x68717473446E25B8ULL,
		0x7BE676D5B4ADCC26ULL,
		0xCF95FBA904A5B99BULL,
		0x436D8BB48D7C4D53ULL
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
		0xBC8F9EED8278D91CULL,
		0x3C2DCE33E36DDA8CULL,
		0xBDC8E9CF2F81A104ULL,
		0x09DC77A5A05CF618ULL,
		0xAF00384D4B284856ULL,
		0x466360308CE2C4A6ULL,
		0x7130503A9F9E8601ULL,
		0x1175A55E04553BD0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x791F3DDB04F1B238ULL,
		0x785B9C67C6DBB519ULL,
		0x7B91D39E5F034208ULL,
		0x13B8EF4B40B9EC31ULL,
		0x5E00709A965090ACULL,
		0x8CC6C06119C5894DULL,
		0xE260A0753F3D0C02ULL,
		0x22EB4ABC08AA77A0ULL
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
		0x861134A62B36561EULL,
		0xF96AD5FD8CA88377ULL,
		0x07FF3513A0C31CD7ULL,
		0x484BCFFC8082C1FEULL,
		0x2BDDC5B699E6ADEDULL,
		0xDEF25BDA1117B508ULL,
		0xA6C9B3CE5D311466ULL,
		0x1EA09FB474C3059AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0C22694C566CAC3CULL,
		0xF2D5ABFB195106EFULL,
		0x0FFE6A27418639AFULL,
		0x90979FF9010583FCULL,
		0x57BB8B6D33CD5BDAULL,
		0xBDE4B7B4222F6A10ULL,
		0x4D93679CBA6228CDULL,
		0x3D413F68E9860B35ULL
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
		0x566A601455EB9E97ULL,
		0xE4D37694A9E35389ULL,
		0x027C8AA02ACBC2CCULL,
		0xF4A612E0424E8C0AULL,
		0x270062121C1F13E0ULL,
		0xE32E3F42EA4D7523ULL,
		0x245F9FA601486F1AULL,
		0x2643BF2F0A5C0151ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xACD4C028ABD73D2EULL,
		0xC9A6ED2953C6A712ULL,
		0x04F9154055978599ULL,
		0xE94C25C0849D1814ULL,
		0x4E00C424383E27C1ULL,
		0xC65C7E85D49AEA46ULL,
		0x48BF3F4C0290DE35ULL,
		0x4C877E5E14B802A2ULL
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
		0x3F09F8A76C371462ULL,
		0x60E426F97BFF5671ULL,
		0x14F76E40890C03F6ULL,
		0x34BF1764207DB228ULL,
		0x4D7C64D3B71D1D3BULL,
		0x04CD06D6DE56678CULL,
		0x2094FB4AF7A7CD20ULL,
		0x12729C58997C1B01ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7E13F14ED86E28C4ULL,
		0xC1C84DF2F7FEACE2ULL,
		0x29EEDC81121807ECULL,
		0x697E2EC840FB6450ULL,
		0x9AF8C9A76E3A3A76ULL,
		0x099A0DADBCACCF18ULL,
		0x4129F695EF4F9A40ULL,
		0x24E538B132F83602ULL
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
		0xDC39EB9F5F7EEA81ULL,
		0xCD59AA63405F13CEULL,
		0x23C6DD3DA5A2D129ULL,
		0x771FBA6B7B0E9C3DULL,
		0x603FB0887658F24AULL,
		0x8206B84EAFD3F7B6ULL,
		0x04D7E8C90D140195ULL,
		0x05D70890DA76BB0FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB873D73EBEFDD502ULL,
		0x9AB354C680BE279DULL,
		0x478DBA7B4B45A253ULL,
		0xEE3F74D6F61D387AULL,
		0xC07F6110ECB1E494ULL,
		0x040D709D5FA7EF6CULL,
		0x09AFD1921A28032BULL,
		0x0BAE1121B4ED761EULL
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
		0xE876F50C6E324E48ULL,
		0x5817389CFEFB14B5ULL,
		0xB69CDF90ACD120CBULL,
		0xBB432F86EF386495ULL,
		0xD0BEA820F9197BBBULL,
		0x2940E9A578FD288DULL,
		0xA696F6A72D918021ULL,
		0x0255035717577BD3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD0EDEA18DC649C90ULL,
		0xB02E7139FDF6296BULL,
		0x6D39BF2159A24196ULL,
		0x76865F0DDE70C92BULL,
		0xA17D5041F232F777ULL,
		0x5281D34AF1FA511BULL,
		0x4D2DED4E5B230042ULL,
		0x04AA06AE2EAEF7A7ULL
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
		0x574AF741FB9DE3F4ULL,
		0xB2201D8829E13D92ULL,
		0x2CD991A9D003411EULL,
		0x99C22877C7B32986ULL,
		0x9E6EE209EE35A776ULL,
		0x834BD3188F829D9CULL,
		0x0241C5B8E6E2AE93ULL,
		0x1F6E958D32531D9FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAE95EE83F73BC7E8ULL,
		0x64403B1053C27B24ULL,
		0x59B32353A006823DULL,
		0x338450EF8F66530CULL,
		0x3CDDC413DC6B4EEDULL,
		0x0697A6311F053B39ULL,
		0x04838B71CDC55D27ULL,
		0x3EDD2B1A64A63B3EULL
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
		0x471ECDA4137DCA0BULL,
		0x1689B256D83741D1ULL,
		0x175FE32502481077ULL,
		0x6005134EFACC3EF9ULL,
		0xA30B07D45D1C955DULL,
		0xA31F8F513627511EULL,
		0x09B540EB654B0855ULL,
		0x17A8F71CA15571CCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8E3D9B4826FB9416ULL,
		0x2D1364ADB06E83A2ULL,
		0x2EBFC64A049020EEULL,
		0xC00A269DF5987DF2ULL,
		0x46160FA8BA392ABAULL,
		0x463F1EA26C4EA23DULL,
		0x136A81D6CA9610ABULL,
		0x2F51EE3942AAE398ULL
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
		0xD6F8957454A3FFD5ULL,
		0x1B9BCD2625452387ULL,
		0x90AAF936EBD2800DULL,
		0x72EDFC662126EC2BULL,
		0x8B6BDD630ACFAA2EULL,
		0xCE053A455C1653CEULL,
		0xA598CAE480448B63ULL,
		0x30C5348A3722D2BEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xADF12AE8A947FFAAULL,
		0x37379A4C4A8A470FULL,
		0x2155F26DD7A5001AULL,
		0xE5DBF8CC424DD857ULL,
		0x16D7BAC6159F545CULL,
		0x9C0A748AB82CA79DULL,
		0x4B3195C9008916C7ULL,
		0x618A69146E45A57DULL
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
		0x95299F991CFDCBE4ULL,
		0xD4D02E458295D51DULL,
		0x4846437AE989C5BBULL,
		0x1932A9A7967BBB39ULL,
		0x4671F99B96BCAB50ULL,
		0xFCB25F820DA27BD8ULL,
		0xB3D676C3D40B50D7ULL,
		0x348084CED1491708ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2A533F3239FB97C8ULL,
		0xA9A05C8B052BAA3BULL,
		0x908C86F5D3138B77ULL,
		0x3265534F2CF77672ULL,
		0x8CE3F3372D7956A0ULL,
		0xF964BF041B44F7B0ULL,
		0x67ACED87A816A1AFULL,
		0x6901099DA2922E11ULL
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
		0x30BC67C5A7D9AFB2ULL,
		0xEA049B676B74CE1BULL,
		0x06FD47E8B5FC1055ULL,
		0xFC53D8B8C5C1C94CULL,
		0x16BDB1BE1F7F28EBULL,
		0x114EF7FE877C2738ULL,
		0xAF3CD5034A6C35A3ULL,
		0x1DD3616854743C35ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6178CF8B4FB35F64ULL,
		0xD40936CED6E99C36ULL,
		0x0DFA8FD16BF820ABULL,
		0xF8A7B1718B839298ULL,
		0x2D7B637C3EFE51D7ULL,
		0x229DEFFD0EF84E70ULL,
		0x5E79AA0694D86B46ULL,
		0x3BA6C2D0A8E8786BULL
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
		0x39AEA851B14101BBULL,
		0xFD6FB1C2EBD02A0FULL,
		0x5E6D45B9406153D2ULL,
		0x65D3319386190437ULL,
		0x5803F4782A0D1D5BULL,
		0x87273CD0082875C9ULL,
		0x4A79AC1416FD0F2EULL,
		0x2E22DF545F670335ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x735D50A362820376ULL,
		0xFADF6385D7A0541EULL,
		0xBCDA8B7280C2A7A5ULL,
		0xCBA663270C32086EULL,
		0xB007E8F0541A3AB6ULL,
		0x0E4E79A01050EB92ULL,
		0x94F358282DFA1E5DULL,
		0x5C45BEA8BECE066AULL
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
		0x18B510023EDEA348ULL,
		0x0DF9DF2A379DF163ULL,
		0x1D56564D106586CDULL,
		0x64F357625265495EULL,
		0x4C4CF857AB1C0CD3ULL,
		0xB0D7CB6555462CC8ULL,
		0x65881FA315DED5C3ULL,
		0x375270BB58642183ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x316A20047DBD4690ULL,
		0x1BF3BE546F3BE2C6ULL,
		0x3AACAC9A20CB0D9AULL,
		0xC9E6AEC4A4CA92BCULL,
		0x9899F0AF563819A6ULL,
		0x61AF96CAAA8C5990ULL,
		0xCB103F462BBDAB87ULL,
		0x6EA4E176B0C84306ULL
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
		0x53DB064ABFF753DAULL,
		0x867AD3D99D2B230BULL,
		0x5DC0EB352D941D6AULL,
		0xFA4E42180D5202C7ULL,
		0x86A4B79B231E4785ULL,
		0x3B689CF64FD56EA3ULL,
		0x3F8082CE9121B876ULL,
		0x38E7A790138CA6B4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA7B60C957FEEA7B4ULL,
		0x0CF5A7B33A564616ULL,
		0xBB81D66A5B283AD5ULL,
		0xF49C84301AA4058EULL,
		0x0D496F36463C8F0BULL,
		0x76D139EC9FAADD47ULL,
		0x7F01059D224370ECULL,
		0x71CF4F2027194D68ULL
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
		0x38A0A9F784A2EA38ULL,
		0x21E90205CFDFD453ULL,
		0x0280CE6873631D3AULL,
		0x30A687ECAAA6B7BFULL,
		0xCB2C0D8495B4BE90ULL,
		0xA196D72397374F3BULL,
		0x01ED82807D018B44ULL,
		0x384379C5401C6F02ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x714153EF0945D470ULL,
		0x43D2040B9FBFA8A6ULL,
		0x05019CD0E6C63A74ULL,
		0x614D0FD9554D6F7EULL,
		0x96581B092B697D20ULL,
		0x432DAE472E6E9E77ULL,
		0x03DB0500FA031689ULL,
		0x7086F38A8038DE04ULL
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
		0x21DD686F24DDCA17ULL,
		0xC2811E1ED399B054ULL,
		0x3F39141F77B255B8ULL,
		0x383A24F4E50DD855ULL,
		0x13C0665FAA67DA4BULL,
		0x9FA76CA0A67133BDULL,
		0xF1F563650394FC4DULL,
		0x1460AA159661F521ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x43BAD0DE49BB942EULL,
		0x85023C3DA73360A8ULL,
		0x7E72283EEF64AB71ULL,
		0x707449E9CA1BB0AAULL,
		0x2780CCBF54CFB496ULL,
		0x3F4ED9414CE2677AULL,
		0xE3EAC6CA0729F89BULL,
		0x28C1542B2CC3EA43ULL
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
		0x21425C71D444AD62ULL,
		0x57005EC1A11E4E9FULL,
		0xE9C3809044276797ULL,
		0x00D1F377A954770FULL,
		0x038242D68B0DA35DULL,
		0x303D9DCC51827750ULL,
		0xE60461B4ABF85E56ULL,
		0x16E2239552F6AD16ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4284B8E3A8895AC4ULL,
		0xAE00BD83423C9D3EULL,
		0xD3870120884ECF2EULL,
		0x01A3E6EF52A8EE1FULL,
		0x070485AD161B46BAULL,
		0x607B3B98A304EEA0ULL,
		0xCC08C36957F0BCACULL,
		0x2DC4472AA5ED5A2DULL
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
		0x0E73A2C80FAAAE3DULL,
		0x4856420E5994D2AAULL,
		0xDA0CF4F1E5E3B245ULL,
		0xCFE42353CC213735ULL,
		0x5A4C157D705CCE0DULL,
		0xC911A3711A376B95ULL,
		0x1DA0344A74D4BBC8ULL,
		0x1023D0C7EE16793CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1CE745901F555C7AULL,
		0x90AC841CB329A554ULL,
		0xB419E9E3CBC7648AULL,
		0x9FC846A798426E6BULL,
		0xB4982AFAE0B99C1BULL,
		0x922346E2346ED72AULL,
		0x3B406894E9A97791ULL,
		0x2047A18FDC2CF278ULL
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
		0x5EBD61357A22232BULL,
		0x933D81BA43E5BCE3ULL,
		0x39276675B553E06BULL,
		0x4ACD809CE285E3C9ULL,
		0x834A09D4E30C0592ULL,
		0xBCECD8B439F817ABULL,
		0xD34B9322CBF55C2FULL,
		0x0F4F6412F0109438ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBD7AC26AF4444656ULL,
		0x267B037487CB79C6ULL,
		0x724ECCEB6AA7C0D7ULL,
		0x959B0139C50BC792ULL,
		0x069413A9C6180B24ULL,
		0x79D9B16873F02F57ULL,
		0xA697264597EAB85FULL,
		0x1E9EC825E0212871ULL
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
		0x3D81E61421D91D09ULL,
		0x9BD0915D3F1602C8ULL,
		0xB9127A9003929387ULL,
		0x287089AFEB6466E8ULL,
		0xE295A7183D80DE7FULL,
		0xD572D6130C49333CULL,
		0x1CDF931C6F62C5E4ULL,
		0x2F5F47792E885DBCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7B03CC2843B23A12ULL,
		0x37A122BA7E2C0590ULL,
		0x7224F5200725270FULL,
		0x50E1135FD6C8CDD1ULL,
		0xC52B4E307B01BCFEULL,
		0xAAE5AC2618926679ULL,
		0x39BF2638DEC58BC9ULL,
		0x5EBE8EF25D10BB78ULL
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
		0xBAD885E85C7C5737ULL,
		0xAAB853DB691F64DBULL,
		0x22AAC70601D8D940ULL,
		0x0E077F41160E8ECDULL,
		0xDFE7FD536FF8677EULL,
		0x2EDADBD2A858D9B6ULL,
		0x6232E4283158956CULL,
		0x2D71F0B4BAA2E631ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x75B10BD0B8F8AE6EULL,
		0x5570A7B6D23EC9B7ULL,
		0x45558E0C03B1B281ULL,
		0x1C0EFE822C1D1D9AULL,
		0xBFCFFAA6DFF0CEFCULL,
		0x5DB5B7A550B1B36DULL,
		0xC465C85062B12AD8ULL,
		0x5AE3E1697545CC62ULL
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
		0x272D9E474BB20519ULL,
		0x2BFF5455AFCBFEBDULL,
		0xBEDEB36D451C5B03ULL,
		0x7F92466758EBC1B4ULL,
		0xBAE63B23D1541611ULL,
		0x88033C986892ADCDULL,
		0x7E81BAE980BFF892ULL,
		0x0AB88D302F09B638ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4E5B3C8E97640A32ULL,
		0x57FEA8AB5F97FD7AULL,
		0x7DBD66DA8A38B606ULL,
		0xFF248CCEB1D78369ULL,
		0x75CC7647A2A82C22ULL,
		0x10067930D1255B9BULL,
		0xFD0375D3017FF125ULL,
		0x15711A605E136C70ULL
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
		0xAA99E432DD3716BDULL,
		0xABA479FC1E40D1FAULL,
		0x2B85D7E0712E0885ULL,
		0x003A23476249BDB2ULL,
		0x1A77F4B39172FBEDULL,
		0xB4FA6C26DCE6ED3BULL,
		0x9F39111BCA920CFBULL,
		0x1F7051053F588DC2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5533C865BA6E2D7AULL,
		0x5748F3F83C81A3F5ULL,
		0x570BAFC0E25C110BULL,
		0x0074468EC4937B64ULL,
		0x34EFE96722E5F7DAULL,
		0x69F4D84DB9CDDA76ULL,
		0x3E722237952419F7ULL,
		0x3EE0A20A7EB11B85ULL
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
		0xA60A3A44FB5C7275ULL,
		0x527F7A188F11EE0DULL,
		0x7F7029265EF2D8E7ULL,
		0x5CBFDC2BC085DB6EULL,
		0x164045ABC9EFCCA2ULL,
		0x5BBAFD3BC62C6752ULL,
		0x1E25C068D70620C6ULL,
		0x2AB0141E89BA1C69ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4C147489F6B8E4EAULL,
		0xA4FEF4311E23DC1BULL,
		0xFEE0524CBDE5B1CEULL,
		0xB97FB857810BB6DCULL,
		0x2C808B5793DF9944ULL,
		0xB775FA778C58CEA4ULL,
		0x3C4B80D1AE0C418CULL,
		0x5560283D137438D2ULL
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
		0x52DA3A9FCFEB1F86ULL,
		0x8FCED2D4094A8EEDULL,
		0xE82E261464E16A85ULL,
		0x2B6A29F32E0A267DULL,
		0x051AD1B208D9D917ULL,
		0xA7E1E725050FA067ULL,
		0x9AE61390020FA06FULL,
		0x11F0EA44BF5A2A18ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA5B4753F9FD63F0CULL,
		0x1F9DA5A812951DDAULL,
		0xD05C4C28C9C2D50BULL,
		0x56D453E65C144CFBULL,
		0x0A35A36411B3B22EULL,
		0x4FC3CE4A0A1F40CEULL,
		0x35CC2720041F40DFULL,
		0x23E1D4897EB45431ULL
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
		0x76F563A5E1AADA4DULL,
		0x04B842983E27684EULL,
		0xA9F3A884C754D19DULL,
		0xEE40AAFEF66CCFB0ULL,
		0x302BB32141EA0AD3ULL,
		0x8786E90B7330CD9AULL,
		0x81EC9C3BF14EA27AULL,
		0x2B273D6E090172A3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEDEAC74BC355B49AULL,
		0x097085307C4ED09CULL,
		0x53E751098EA9A33AULL,
		0xDC8155FDECD99F61ULL,
		0x6057664283D415A7ULL,
		0x0F0DD216E6619B34ULL,
		0x03D93877E29D44F5ULL,
		0x564E7ADC1202E547ULL
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
		0xCEA059E2E61472E3ULL,
		0x3AA1562CBBE46D34ULL,
		0x47B019EE2A118C75ULL,
		0x1ACF02B9A39942E9ULL,
		0x479C0002A6622134ULL,
		0xE8ADC5F8C26B3F85ULL,
		0xB685C0E41482EF43ULL,
		0x0312914D191E74BFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9D40B3C5CC28E5C6ULL,
		0x7542AC5977C8DA69ULL,
		0x8F6033DC542318EAULL,
		0x359E0573473285D2ULL,
		0x8F3800054CC44268ULL,
		0xD15B8BF184D67F0AULL,
		0x6D0B81C82905DE87ULL,
		0x0625229A323CE97FULL
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
		0x7DD49AF10F846761ULL,
		0xC27247655162E3F4ULL,
		0xD86D9D981120F4C3ULL,
		0x0C32AB9E8CCAC02BULL,
		0x2D67DE432FFEAB2FULL,
		0xDE10C1130F58B491ULL,
		0x76E459CDD41857EEULL,
		0x1B11C224E44CEECDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFBA935E21F08CEC2ULL,
		0x84E48ECAA2C5C7E8ULL,
		0xB0DB3B302241E987ULL,
		0x1865573D19958057ULL,
		0x5ACFBC865FFD565EULL,
		0xBC2182261EB16922ULL,
		0xEDC8B39BA830AFDDULL,
		0x36238449C899DD9AULL
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
		0x16C8A7E3B5CF8072ULL,
		0x21FB31674AFA2AC8ULL,
		0x18F6313DF4155804ULL,
		0x13049E6C97248162ULL,
		0xB0440EEDC1EED03AULL,
		0x539A967FD315522FULL,
		0xA01B1E9470DBF98EULL,
		0x375BE0285128F94FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2D914FC76B9F00E4ULL,
		0x43F662CE95F45590ULL,
		0x31EC627BE82AB008ULL,
		0x26093CD92E4902C4ULL,
		0x60881DDB83DDA074ULL,
		0xA7352CFFA62AA45FULL,
		0x40363D28E1B7F31CULL,
		0x6EB7C050A251F29FULL
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
		0x0DA22947D7B140A1ULL,
		0x93F335AF9623B7D9ULL,
		0x422FF71636E336A5ULL,
		0x7DA8F95CCFE80DEAULL,
		0x00E2AECA4A52FA5DULL,
		0x813AE9B668B6258DULL,
		0x62402AD8E09FB591ULL,
		0x159861B7D4005374ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1B44528FAF628142ULL,
		0x27E66B5F2C476FB2ULL,
		0x845FEE2C6DC66D4BULL,
		0xFB51F2B99FD01BD4ULL,
		0x01C55D9494A5F4BAULL,
		0x0275D36CD16C4B1AULL,
		0xC48055B1C13F6B23ULL,
		0x2B30C36FA800A6E8ULL
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
		0xEB2D5D76454AE636ULL,
		0xDFCBB4C46795BDE9ULL,
		0x29FCC4CF18826E3EULL,
		0x98930C7E8DA1B50CULL,
		0x56DB1849049490F9ULL,
		0x8758CB55CA29ECA9ULL,
		0xF1354778274EDC7DULL,
		0x3E4DD13406060BD5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD65ABAEC8A95CC6CULL,
		0xBF976988CF2B7BD3ULL,
		0x53F9899E3104DC7DULL,
		0x312618FD1B436A18ULL,
		0xADB63092092921F3ULL,
		0x0EB196AB9453D952ULL,
		0xE26A8EF04E9DB8FBULL,
		0x7C9BA2680C0C17ABULL
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
		0xD3C6B58226689BAFULL,
		0xB25B00ED9F9C4B46ULL,
		0xE42329B88E9C064CULL,
		0x6415032E5F39FFE3ULL,
		0x85FF0911AB628454ULL,
		0xE3D4F81A5E6CAC6DULL,
		0x63329CECB9F1E9AAULL,
		0x1A03A6A19A608F5FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA78D6B044CD1375EULL,
		0x64B601DB3F38968DULL,
		0xC84653711D380C99ULL,
		0xC82A065CBE73FFC7ULL,
		0x0BFE122356C508A8ULL,
		0xC7A9F034BCD958DBULL,
		0xC66539D973E3D355ULL,
		0x34074D4334C11EBEULL
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
		0xC9B6A03BA8FB89D9ULL,
		0x3CAAB42271FD9584ULL,
		0xAFB4769316F998CCULL,
		0xB1C15734CEF3739DULL,
		0x015AB21A6C7BD522ULL,
		0x57277CD1D028B09DULL,
		0x6E7AB2851F5EACDFULL,
		0x380AAE110E7E3530ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x936D407751F713B2ULL,
		0x79556844E3FB2B09ULL,
		0x5F68ED262DF33198ULL,
		0x6382AE699DE6E73BULL,
		0x02B56434D8F7AA45ULL,
		0xAE4EF9A3A051613AULL,
		0xDCF5650A3EBD59BEULL,
		0x70155C221CFC6A60ULL
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
		0xFBB41CAB61F982CCULL,
		0x1D147729BE94D574ULL,
		0xE044DABD3D28918AULL,
		0x3CFA2277887F638BULL,
		0x73D426CDEDFB8491ULL,
		0x3E1FE2090C20D1F5ULL,
		0xA98A9A63CEA5DE33ULL,
		0x1C7A7EA6608E77BFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF7683956C3F30598ULL,
		0x3A28EE537D29AAE9ULL,
		0xC089B57A7A512314ULL,
		0x79F444EF10FEC717ULL,
		0xE7A84D9BDBF70922ULL,
		0x7C3FC4121841A3EAULL,
		0x531534C79D4BBC66ULL,
		0x38F4FD4CC11CEF7FULL
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
		0x71002A6D2C161DE3ULL,
		0x60729E0BC8FFD5B4ULL,
		0xAF04B8927989DA72ULL,
		0x249E8BEE8FFE5199ULL,
		0x338B981B03EE6F44ULL,
		0xBD923F8B63453B8AULL,
		0xC174BCFABD351DC2ULL,
		0x3093B0FA090CEAADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE20054DA582C3BC6ULL,
		0xC0E53C1791FFAB68ULL,
		0x5E097124F313B4E4ULL,
		0x493D17DD1FFCA333ULL,
		0x6717303607DCDE88ULL,
		0x7B247F16C68A7714ULL,
		0x82E979F57A6A3B85ULL,
		0x612761F41219D55BULL
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
		0xDB7AD785BC7FCA13ULL,
		0x8E4E6BBCE6350D76ULL,
		0x505622ADEED447F3ULL,
		0xACFC6329FC673E1DULL,
		0x93CF598AD0BFD95AULL,
		0x77956E1189DA5BA0ULL,
		0xABB9AE8ADAB9770DULL,
		0x15FDB9DB0C8F493EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB6F5AF0B78FF9426ULL,
		0x1C9CD779CC6A1AEDULL,
		0xA0AC455BDDA88FE7ULL,
		0x59F8C653F8CE7C3AULL,
		0x279EB315A17FB2B5ULL,
		0xEF2ADC2313B4B741ULL,
		0x57735D15B572EE1AULL,
		0x2BFB73B6191E927DULL
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
		0x137E9FC5C7129A1EULL,
		0xBE31387F4FD7A662ULL,
		0xFC0CC0FB2BEF8651ULL,
		0x160033AAEAA528A0ULL,
		0xBD8F0BFEA00495B3ULL,
		0x19DEBE6832E502FBULL,
		0x8B71505A663A9102ULL,
		0x04066C6D94D53772ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x26FD3F8B8E25343CULL,
		0x7C6270FE9FAF4CC4ULL,
		0xF81981F657DF0CA3ULL,
		0x2C006755D54A5141ULL,
		0x7B1E17FD40092B66ULL,
		0x33BD7CD065CA05F7ULL,
		0x16E2A0B4CC752204ULL,
		0x080CD8DB29AA6EE5ULL
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
		0xC973A77AC3806991ULL,
		0x82F5DEDCD7919C02ULL,
		0x9CB0A0A2B7BD4DD1ULL,
		0x67BD37203624C9B8ULL,
		0x574568BF5998A0BEULL,
		0xCF882FD8C6A72876ULL,
		0xE829E64517300F2DULL,
		0x39724301F928D0A8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x92E74EF58700D322ULL,
		0x05EBBDB9AF233805ULL,
		0x396141456F7A9BA3ULL,
		0xCF7A6E406C499371ULL,
		0xAE8AD17EB331417CULL,
		0x9F105FB18D4E50ECULL,
		0xD053CC8A2E601E5BULL,
		0x72E48603F251A151ULL
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
		0x9631BCCB3F357201ULL,
		0x69567AFC1B27C07BULL,
		0x2A128523EF9596A5ULL,
		0x716CC68E3B463189ULL,
		0x94E8410620D8F73BULL,
		0x33C148F45BC16F1BULL,
		0x0B91F9C3CC995D08ULL,
		0x013B9A37A731497FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2C6379967E6AE402ULL,
		0xD2ACF5F8364F80F7ULL,
		0x54250A47DF2B2D4AULL,
		0xE2D98D1C768C6312ULL,
		0x29D0820C41B1EE76ULL,
		0x678291E8B782DE37ULL,
		0x1723F3879932BA10ULL,
		0x0277346F4E6292FEULL
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
		0xCB89F3C74EE75ABEULL,
		0xE579370B6FE10F86ULL,
		0xD5F5C9348193E52BULL,
		0xA0E7C03FF33A3111ULL,
		0x4BD0F690C95AF828ULL,
		0x056BE7C9B0D96D8CULL,
		0xB73970BAEB736B05ULL,
		0x35AF1119759CB64AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9713E78E9DCEB57CULL,
		0xCAF26E16DFC21F0DULL,
		0xABEB92690327CA57ULL,
		0x41CF807FE6746223ULL,
		0x97A1ED2192B5F051ULL,
		0x0AD7CF9361B2DB18ULL,
		0x6E72E175D6E6D60AULL,
		0x6B5E2232EB396C95ULL
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
		0x70FFDCFBE6A447F8ULL,
		0x88033F9CA9FAC8F2ULL,
		0x62F78B568BE6EBC5ULL,
		0xBAE25DCA5ED00D0EULL,
		0x73340A6D86EB6B11ULL,
		0xAFBAEA5736652620ULL,
		0xC26F4E184CD7D2EEULL,
		0x04BD1C9AC538E224ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE1FFB9F7CD488FF0ULL,
		0x10067F3953F591E4ULL,
		0xC5EF16AD17CDD78BULL,
		0x75C4BB94BDA01A1CULL,
		0xE66814DB0DD6D623ULL,
		0x5F75D4AE6CCA4C40ULL,
		0x84DE9C3099AFA5DDULL,
		0x097A39358A71C449ULL
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
		0xFA51ACD4E0518E16ULL,
		0xD01EA938B7167178ULL,
		0xF7CB8052D1020C52ULL,
		0x80CE430B771CF8D3ULL,
		0x3555F0DD2C8BE1C8ULL,
		0x8D40E424CB0DD9D5ULL,
		0x650FDE678053E75FULL,
		0x127623BADB5890BEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF4A359A9C0A31C2CULL,
		0xA03D52716E2CE2F1ULL,
		0xEF9700A5A20418A5ULL,
		0x019C8616EE39F1A7ULL,
		0x6AABE1BA5917C391ULL,
		0x1A81C849961BB3AAULL,
		0xCA1FBCCF00A7CEBFULL,
		0x24EC4775B6B1217CULL
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
		0xF4C7BA6161DE0BB8ULL,
		0x4E64E3022490E08DULL,
		0x7C2402EDC3A38F0EULL,
		0x01391578B276A861ULL,
		0xFC8397C702696D5CULL,
		0xFCAD374E86DCB4E1ULL,
		0xE8EC17FEEAF0CD7EULL,
		0x0F26F06C9FF3F0ADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE98F74C2C3BC1770ULL,
		0x9CC9C6044921C11BULL,
		0xF84805DB87471E1CULL,
		0x02722AF164ED50C2ULL,
		0xF9072F8E04D2DAB8ULL,
		0xF95A6E9D0DB969C3ULL,
		0xD1D82FFDD5E19AFDULL,
		0x1E4DE0D93FE7E15BULL
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
		0x633CF52FF78E3430ULL,
		0x52C22D9DB46BEE73ULL,
		0x8FEE181C66C02879ULL,
		0x075FED6D2E7A7552ULL,
		0x57FBD54FD264D3CEULL,
		0xED7333B41DF769A5ULL,
		0x5DC4DFD18D99D123ULL,
		0x11EE04BCD9667CE3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC679EA5FEF1C6860ULL,
		0xA5845B3B68D7DCE6ULL,
		0x1FDC3038CD8050F2ULL,
		0x0EBFDADA5CF4EAA5ULL,
		0xAFF7AA9FA4C9A79CULL,
		0xDAE667683BEED34AULL,
		0xBB89BFA31B33A247ULL,
		0x23DC0979B2CCF9C6ULL
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
		0x2B384CB68E42C759ULL,
		0xFB4D1188DB5BE3D7ULL,
		0x2A4FF5F21791E3CBULL,
		0x0F33946C8638A2DAULL,
		0x38AB2F9784588061ULL,
		0xBF670AE7C2B1E305ULL,
		0xCB5952760DFDF4C8ULL,
		0x1B3B913776F8B0B9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5670996D1C858EB2ULL,
		0xF69A2311B6B7C7AEULL,
		0x549FEBE42F23C797ULL,
		0x1E6728D90C7145B4ULL,
		0x71565F2F08B100C2ULL,
		0x7ECE15CF8563C60AULL,
		0x96B2A4EC1BFBE991ULL,
		0x3677226EEDF16173ULL
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
		0xB78EC4C27CDBC4C3ULL,
		0xB3BC41D50A2F2094ULL,
		0x4A183FDB03E54905ULL,
		0x5C5F3508D5F6EA8CULL,
		0xA4C856685AD0004DULL,
		0x6DE396A154788650ULL,
		0x709D4F945D7840EDULL,
		0x25B7F95065CF89F1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6F1D8984F9B78986ULL,
		0x677883AA145E4129ULL,
		0x94307FB607CA920BULL,
		0xB8BE6A11ABEDD518ULL,
		0x4990ACD0B5A0009AULL,
		0xDBC72D42A8F10CA1ULL,
		0xE13A9F28BAF081DAULL,
		0x4B6FF2A0CB9F13E2ULL
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
		0xAC499972DE5FE546ULL,
		0x196961C629C0F944ULL,
		0x2C44470651DD49D8ULL,
		0x7C1BC7F9A5FB6611ULL,
		0x6F88250129695066ULL,
		0x2E0F2CFC630C0085ULL,
		0xB5BC41743A76E95BULL,
		0x32C3E92F52B0ECD9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x589332E5BCBFCA8CULL,
		0x32D2C38C5381F289ULL,
		0x58888E0CA3BA93B0ULL,
		0xF8378FF34BF6CC22ULL,
		0xDF104A0252D2A0CCULL,
		0x5C1E59F8C618010AULL,
		0x6B7882E874EDD2B6ULL,
		0x6587D25EA561D9B3ULL
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
		0x643C5A02C256F96BULL,
		0x529ECF2986653434ULL,
		0xFDF7AF1DBBC9F273ULL,
		0xF5C872BC8AE862B1ULL,
		0xEE844890596F476BULL,
		0x9DBF91B923CBD059ULL,
		0x92D91139B1CFD243ULL,
		0x07614615198C83DBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC878B40584ADF2D6ULL,
		0xA53D9E530CCA6868ULL,
		0xFBEF5E3B7793E4E6ULL,
		0xEB90E57915D0C563ULL,
		0xDD089120B2DE8ED7ULL,
		0x3B7F23724797A0B3ULL,
		0x25B22273639FA487ULL,
		0x0EC28C2A331907B7ULL
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
		0xF15F105E4ACFBE52ULL,
		0x045B69159A0064D0ULL,
		0xC4011018FDEB5922ULL,
		0x53075F27E4B66546ULL,
		0x0681639E7FC88C2BULL,
		0x8D5EAB42EFB175BBULL,
		0x80321333A8BF9E4DULL,
		0x329BC1DF2D37443EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE2BE20BC959F7CA4ULL,
		0x08B6D22B3400C9A1ULL,
		0x88022031FBD6B244ULL,
		0xA60EBE4FC96CCA8DULL,
		0x0D02C73CFF911856ULL,
		0x1ABD5685DF62EB76ULL,
		0x00642667517F3C9BULL,
		0x653783BE5A6E887DULL
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
		0xE3FF8BF2BC40EEC2ULL,
		0x19CBB56B3E8200E0ULL,
		0x4EE2D65D154972E2ULL,
		0xDFE491254BE6C000ULL,
		0xC827FCF7AEA33611ULL,
		0x311A6BE66455B4DCULL,
		0x9CEA02784152234BULL,
		0x081EE1E290558758ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC7FF17E57881DD84ULL,
		0x33976AD67D0401C1ULL,
		0x9DC5ACBA2A92E5C4ULL,
		0xBFC9224A97CD8000ULL,
		0x904FF9EF5D466C23ULL,
		0x6234D7CCC8AB69B9ULL,
		0x39D404F082A44696ULL,
		0x103DC3C520AB0EB1ULL
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
		0x0C9C88CEF982E599ULL,
		0xDA4A4C2D2CCF3AAEULL,
		0x32F767B2058FEEA1ULL,
		0xBA4A889DCB33A88CULL,
		0x0EC97A9A01B912AAULL,
		0x6B5C266DB00DF0E5ULL,
		0x51E7A94D2E7E058EULL,
		0x1FA6B72507C8B9DDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1939119DF305CB32ULL,
		0xB494985A599E755CULL,
		0x65EECF640B1FDD43ULL,
		0x7495113B96675118ULL,
		0x1D92F53403722555ULL,
		0xD6B84CDB601BE1CAULL,
		0xA3CF529A5CFC0B1CULL,
		0x3F4D6E4A0F9173BAULL
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
		0x0710CCC139E50B61ULL,
		0x40A7BD321DD249ECULL,
		0x04D057F1DDD31B97ULL,
		0x2B3E7CFB7A5B5258ULL,
		0xB529B1F718ADA507ULL,
		0x42FAE33CE2FD6491ULL,
		0x46E1772ABBA940A4ULL,
		0x2FA7D9F726EE77D7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0E21998273CA16C2ULL,
		0x814F7A643BA493D8ULL,
		0x09A0AFE3BBA6372EULL,
		0x567CF9F6F4B6A4B0ULL,
		0x6A5363EE315B4A0EULL,
		0x85F5C679C5FAC923ULL,
		0x8DC2EE5577528148ULL,
		0x5F4FB3EE4DDCEFAEULL
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
		0x07B288274471690DULL,
		0xD131B60E661D6410ULL,
		0x41FD478D01650335ULL,
		0xBE5720BDCD8B6D4EULL,
		0xF8FBEA4D6A2CD2B5ULL,
		0xD4B0DCF7C56E7ED1ULL,
		0xA9E5E230D3DC8A95ULL,
		0x30FA6A85A140C3CEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F65104E88E2D21AULL,
		0xA2636C1CCC3AC820ULL,
		0x83FA8F1A02CA066BULL,
		0x7CAE417B9B16DA9CULL,
		0xF1F7D49AD459A56BULL,
		0xA961B9EF8ADCFDA3ULL,
		0x53CBC461A7B9152BULL,
		0x61F4D50B4281879DULL
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
		0xFD57C5346084E529ULL,
		0x1DAEB61D34DA0964ULL,
		0xE4C2F30C82CBB6F3ULL,
		0x8ED1230C7B3ED171ULL,
		0x3C4E8A3751388660ULL,
		0xF5FB3C02F8482D7EULL,
		0xECD4244DBBF5C26DULL,
		0x09AC892B4B826E18ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFAAF8A68C109CA52ULL,
		0x3B5D6C3A69B412C9ULL,
		0xC985E61905976DE6ULL,
		0x1DA24618F67DA2E3ULL,
		0x789D146EA2710CC1ULL,
		0xEBF67805F0905AFCULL,
		0xD9A8489B77EB84DBULL,
		0x135912569704DC31ULL
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
		0xF09BAC9B115C3866ULL,
		0xBC75B52F6F8BD0F4ULL,
		0x26095E052AD2C691ULL,
		0xCB11371102E034D9ULL,
		0x266D6338CAF94C8BULL,
		0xCA2B2E758CB385BAULL,
		0x14D61FD9EED0C698ULL,
		0x3185157B0CCCB1D0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE137593622B870CCULL,
		0x78EB6A5EDF17A1E9ULL,
		0x4C12BC0A55A58D23ULL,
		0x96226E2205C069B2ULL,
		0x4CDAC67195F29917ULL,
		0x94565CEB19670B74ULL,
		0x29AC3FB3DDA18D31ULL,
		0x630A2AF6199963A0ULL
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
		0x2B8C0BAC92465842ULL,
		0xF438C08A88761108ULL,
		0x4EE23528F1B59E14ULL,
		0x5A465E85B21E38D9ULL,
		0xE749A15E62DF898CULL,
		0x6257E02BA190D37DULL,
		0xCBB4CDEE1050F8C6ULL,
		0x13358087F19B9A48ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x57181759248CB084ULL,
		0xE871811510EC2210ULL,
		0x9DC46A51E36B3C29ULL,
		0xB48CBD0B643C71B2ULL,
		0xCE9342BCC5BF1318ULL,
		0xC4AFC0574321A6FBULL,
		0x97699BDC20A1F18CULL,
		0x266B010FE3373491ULL
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
		0xBBCBFB3D2E0C9C44ULL,
		0x9D074919E93FAA1DULL,
		0xBD0ABCFC46B5EB44ULL,
		0x036607FBA9EEFA35ULL,
		0xBA648DA0397B6BCDULL,
		0xC299C6173D136AE1ULL,
		0xB16B9410DE1BCE70ULL,
		0x2425142F12B01DDFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7797F67A5C193888ULL,
		0x3A0E9233D27F543BULL,
		0x7A1579F88D6BD689ULL,
		0x06CC0FF753DDF46BULL,
		0x74C91B4072F6D79AULL,
		0x85338C2E7A26D5C3ULL,
		0x62D72821BC379CE1ULL,
		0x484A285E25603BBFULL
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
		0xE56F3C8737416A91ULL,
		0xF35F6B122CAFBF0FULL,
		0x8284833598AFA79CULL,
		0x3150577561D5C18FULL,
		0x99A1010E35806384ULL,
		0x1F6FB62CDBEF350FULL,
		0x134FE65C9CCA487BULL,
		0x390A0F0C93DE82DDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCADE790E6E82D522ULL,
		0xE6BED624595F7E1FULL,
		0x0509066B315F4F39ULL,
		0x62A0AEEAC3AB831FULL,
		0x3342021C6B00C708ULL,
		0x3EDF6C59B7DE6A1FULL,
		0x269FCCB9399490F6ULL,
		0x72141E1927BD05BAULL
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
		0xA77E04A308ACB678ULL,
		0x1DEC078AD9CFF3B3ULL,
		0x1678078E058B8D39ULL,
		0x02AB3E8331AEFB60ULL,
		0xA1C2EFFA1295AC13ULL,
		0xF156FF3C006B97DDULL,
		0x46A0EC8E6034DB65ULL,
		0x36510F2EEDA5AB8AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4EFC094611596CF0ULL,
		0x3BD80F15B39FE767ULL,
		0x2CF00F1C0B171A72ULL,
		0x05567D06635DF6C0ULL,
		0x4385DFF4252B5826ULL,
		0xE2ADFE7800D72FBBULL,
		0x8D41D91CC069B6CBULL,
		0x6CA21E5DDB4B5714ULL
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
		0xC9D8053FE252581BULL,
		0xD940CCBE08B51C30ULL,
		0x145CE6668650C663ULL,
		0xD7ACB71E321DEFDDULL,
		0xBBDAE0D78CBE16EEULL,
		0x72120A603B1488A1ULL,
		0xB5280B41DC521F1CULL,
		0x008300620D92312DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x93B00A7FC4A4B036ULL,
		0xB281997C116A3861ULL,
		0x28B9CCCD0CA18CC7ULL,
		0xAF596E3C643BDFBAULL,
		0x77B5C1AF197C2DDDULL,
		0xE42414C076291143ULL,
		0x6A501683B8A43E38ULL,
		0x010600C41B24625BULL
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
		0x1FC30C156D8D375FULL,
		0x9C5D14ADEE5DA9FEULL,
		0xF474446E826F3D5FULL,
		0x16E98D7EFBC5E025ULL,
		0xA43A65D591C3062AULL,
		0x92364AE628AC7998ULL,
		0x44DEAB0CCB6F7B95ULL,
		0x07F1B6615377C597ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3F86182ADB1A6EBEULL,
		0x38BA295BDCBB53FCULL,
		0xE8E888DD04DE7ABFULL,
		0x2DD31AFDF78BC04BULL,
		0x4874CBAB23860C54ULL,
		0x246C95CC5158F331ULL,
		0x89BD561996DEF72BULL,
		0x0FE36CC2A6EF8B2EULL
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
		0xAA7F741661F7B62CULL,
		0x98AF017B55471AADULL,
		0x31F6560947D4DC38ULL,
		0x84E6DE204B847DC2ULL,
		0x22612512C2A28516ULL,
		0x7CF964E1F4BEC324ULL,
		0x92D56D5D373DF0D4ULL,
		0x19A50F03F4C38A5DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x54FEE82CC3EF6C58ULL,
		0x315E02F6AA8E355BULL,
		0x63ECAC128FA9B871ULL,
		0x09CDBC409708FB84ULL,
		0x44C24A2585450A2DULL,
		0xF9F2C9C3E97D8648ULL,
		0x25AADABA6E7BE1A8ULL,
		0x334A1E07E98714BBULL
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
		0x8C89C577C7BAA94BULL,
		0x31C766B42A49A326ULL,
		0x4B29D4FDC99B3992ULL,
		0x8E8AAED6A6203040ULL,
		0xCD9450220E6D2E5EULL,
		0x890D0F9021D2B671ULL,
		0x66BF693B6683C02EULL,
		0x3773420BB0CB7C8BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x19138AEF8F755296ULL,
		0x638ECD685493464DULL,
		0x9653A9FB93367324ULL,
		0x1D155DAD4C406080ULL,
		0x9B28A0441CDA5CBDULL,
		0x121A1F2043A56CE3ULL,
		0xCD7ED276CD07805DULL,
		0x6EE684176196F916ULL
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
		0xAB5D2E3B8F5AFAF4ULL,
		0x8B92C2E126692D2DULL,
		0xA5F7B84B143F9DCDULL,
		0xCC98140F35EEC7B6ULL,
		0x60C0535BBA756B4BULL,
		0xC5AA10EC120B5070ULL,
		0x5009CAAC3DC4B35BULL,
		0x34FE629EADBE7D77ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x56BA5C771EB5F5E8ULL,
		0x172585C24CD25A5BULL,
		0x4BEF7096287F3B9BULL,
		0x9930281E6BDD8F6DULL,
		0xC180A6B774EAD697ULL,
		0x8B5421D82416A0E0ULL,
		0xA01395587B8966B7ULL,
		0x69FCC53D5B7CFAEEULL
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
		0xEEBF7AC1AA86B4EFULL,
		0xA48747B57AD50831ULL,
		0xDD99572ED1F942EBULL,
		0xA7D0C3222E9CB566ULL,
		0x8ED684DE0418DD5CULL,
		0x943385D5B243D66AULL,
		0xF0F5406A9E15108DULL,
		0x276C200184DAA24AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDD7EF583550D69DEULL,
		0x490E8F6AF5AA1063ULL,
		0xBB32AE5DA3F285D7ULL,
		0x4FA186445D396ACDULL,
		0x1DAD09BC0831BAB9ULL,
		0x28670BAB6487ACD5ULL,
		0xE1EA80D53C2A211BULL,
		0x4ED8400309B54495ULL
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
		0xDC9C2AE75C725AC4ULL,
		0x70E9C61A20E9464BULL,
		0x1655DFCA5F150B08ULL,
		0xB2CEF84F259FF3B0ULL,
		0xD1264F815C37107AULL,
		0xC10EDE9E43A118BCULL,
		0xD449B9095A480DCDULL,
		0x02F52AEC7ED9136FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB93855CEB8E4B588ULL,
		0xE1D38C3441D28C97ULL,
		0x2CABBF94BE2A1610ULL,
		0x659DF09E4B3FE760ULL,
		0xA24C9F02B86E20F5ULL,
		0x821DBD3C87423179ULL,
		0xA8937212B4901B9BULL,
		0x05EA55D8FDB226DFULL
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
		0xB3D6404F1D124214ULL,
		0x07B9017AD285CE2FULL,
		0x89D44A2E01CE1CB9ULL,
		0x530E73C70CF6F1B6ULL,
		0x3A5E7AD8CD251FFFULL,
		0xFF972BE6590267E3ULL,
		0x8D0D72A6B4031300ULL,
		0x0247B7EB41231053ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x67AC809E3A248428ULL,
		0x0F7202F5A50B9C5FULL,
		0x13A8945C039C3972ULL,
		0xA61CE78E19EDE36DULL,
		0x74BCF5B19A4A3FFEULL,
		0xFF2E57CCB204CFC6ULL,
		0x1A1AE54D68062601ULL,
		0x048F6FD6824620A7ULL
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
		0x55FAFF5B36B5A08CULL,
		0x1919FCC7D31583AFULL,
		0x21005687343379A4ULL,
		0x6194CE44FBB01EC5ULL,
		0xAE43BA9238DDE875ULL,
		0x52D11846B2906910ULL,
		0xEBF73E538828CDAEULL,
		0x366EF114BB9888E7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xABF5FEB66D6B4118ULL,
		0x3233F98FA62B075EULL,
		0x4200AD0E6866F348ULL,
		0xC3299C89F7603D8AULL,
		0x5C87752471BBD0EAULL,
		0xA5A2308D6520D221ULL,
		0xD7EE7CA710519B5CULL,
		0x6CDDE229773111CFULL
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
		0xF6B06975E4DE1A98ULL,
		0x0C2512BF579FC48EULL,
		0x5779C5C0B9110877ULL,
		0x5F61BFD9DCDCD39EULL,
		0x0A0141319939CF79ULL,
		0x4869C77461020569ULL,
		0xF2AEB4077EDAA978ULL,
		0x3414CFB025AD587FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xED60D2EBC9BC3530ULL,
		0x184A257EAF3F891DULL,
		0xAEF38B81722210EEULL,
		0xBEC37FB3B9B9A73CULL,
		0x1402826332739EF2ULL,
		0x90D38EE8C2040AD2ULL,
		0xE55D680EFDB552F0ULL,
		0x68299F604B5AB0FFULL
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
		0xB72F4C2ECB75D6AFULL,
		0x7A4F8686A58B145BULL,
		0xC68FD08457E38AA6ULL,
		0xB175668380208968ULL,
		0x8068F3954B68EF75ULL,
		0x07B9938282B01D39ULL,
		0x96831BDA61DC5021ULL,
		0x05D46757ADACBE13ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6E5E985D96EBAD5EULL,
		0xF49F0D0D4B1628B7ULL,
		0x8D1FA108AFC7154CULL,
		0x62EACD07004112D1ULL,
		0x00D1E72A96D1DEEBULL,
		0x0F73270505603A73ULL,
		0x2D0637B4C3B8A042ULL,
		0x0BA8CEAF5B597C27ULL
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
		0x48F05F4BDBABF590ULL,
		0x5D2ACAB879BA70F3ULL,
		0xDA887BA6E1F99CA0ULL,
		0xA10071A6AE57E018ULL,
		0x1818237AAA3E3486ULL,
		0x1FC6F409D6429E4CULL,
		0x116864DC4955FB7CULL,
		0x150C2C60E55F8E65ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x91E0BE97B757EB20ULL,
		0xBA559570F374E1E6ULL,
		0xB510F74DC3F33940ULL,
		0x4200E34D5CAFC031ULL,
		0x303046F5547C690DULL,
		0x3F8DE813AC853C98ULL,
		0x22D0C9B892ABF6F8ULL,
		0x2A1858C1CABF1CCAULL
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
		0x0100810EDC55D3F4ULL,
		0x4553E42CD8FC8A68ULL,
		0x0D563F21F3759F77ULL,
		0x2C2D60A248A4A94EULL,
		0x598488106D1725BEULL,
		0x41856B019BC25814ULL,
		0x6CAEDF0128F5C85FULL,
		0x15FDD3899A5C334FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0201021DB8ABA7E8ULL,
		0x8AA7C859B1F914D0ULL,
		0x1AAC7E43E6EB3EEEULL,
		0x585AC1449149529CULL,
		0xB3091020DA2E4B7CULL,
		0x830AD6033784B028ULL,
		0xD95DBE0251EB90BEULL,
		0x2BFBA71334B8669EULL
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
		0xF21D26CC6BD4F8D9ULL,
		0x8F2AE8F97EBB3BA2ULL,
		0xE85D3A1D0D5D767DULL,
		0x91B52E01CB9481B9ULL,
		0xB8ABAD1FB09C3F2BULL,
		0x1A813C5B7267B5F7ULL,
		0xD983F369C7205B4BULL,
		0x15564C61A32DD5DBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE43A4D98D7A9F1B2ULL,
		0x1E55D1F2FD767745ULL,
		0xD0BA743A1ABAECFBULL,
		0x236A5C0397290373ULL,
		0x71575A3F61387E57ULL,
		0x350278B6E4CF6BEFULL,
		0xB307E6D38E40B696ULL,
		0x2AAC98C3465BABB7ULL
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
		0x099DF4C8CDAE2952ULL,
		0x4AAA942D7F8073C1ULL,
		0x3604E6668DB1FC05ULL,
		0xB858B3FE1587AEABULL,
		0xB1E32A4FD4150048ULL,
		0x4C45BE57908CB761ULL,
		0xFED1F427DD23B6FAULL,
		0x2492DA958D56C5C5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x133BE9919B5C52A4ULL,
		0x9555285AFF00E782ULL,
		0x6C09CCCD1B63F80AULL,
		0x70B167FC2B0F5D56ULL,
		0x63C6549FA82A0091ULL,
		0x988B7CAF21196EC3ULL,
		0xFDA3E84FBA476DF4ULL,
		0x4925B52B1AAD8B8BULL
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
		0x2CECBFCFBD710D3AULL,
		0x9CB424B27A77C70AULL,
		0x5F78917C395432ECULL,
		0x5C9F81190A7410ACULL,
		0x32504E62E68A5764ULL,
		0x58EFDC70B499B451ULL,
		0x7F6CEC267DC78898ULL,
		0x278C13EB5ACED099ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x59D97F9F7AE21A74ULL,
		0x39684964F4EF8E14ULL,
		0xBEF122F872A865D9ULL,
		0xB93F023214E82158ULL,
		0x64A09CC5CD14AEC8ULL,
		0xB1DFB8E1693368A2ULL,
		0xFED9D84CFB8F1130ULL,
		0x4F1827D6B59DA132ULL
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
		0xA7CEB2FB7A8FAD95ULL,
		0x0F45961C7AB217E2ULL,
		0x589A65D7757F402AULL,
		0xA988D5F6DEE7037CULL,
		0x4EBCEB2DB79CE09DULL,
		0x2724D931696949C5ULL,
		0x618D5E8B79B8AB27ULL,
		0x3B7CE5A772360442ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4F9D65F6F51F5B2AULL,
		0x1E8B2C38F5642FC5ULL,
		0xB134CBAEEAFE8054ULL,
		0x5311ABEDBDCE06F8ULL,
		0x9D79D65B6F39C13BULL,
		0x4E49B262D2D2938AULL,
		0xC31ABD16F371564EULL,
		0x76F9CB4EE46C0884ULL
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
		0xEC582108B81231B6ULL,
		0xC63114B6D95B01C7ULL,
		0x9EE0151D491F031CULL,
		0x88DC93E62FE532D2ULL,
		0xC60B242C81D80176ULL,
		0x6440FCAC539F4E47ULL,
		0xD80CC7F7A5EB95DAULL,
		0x278E8C79757B227EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD8B042117024636CULL,
		0x8C62296DB2B6038FULL,
		0x3DC02A3A923E0639ULL,
		0x11B927CC5FCA65A5ULL,
		0x8C16485903B002EDULL,
		0xC881F958A73E9C8FULL,
		0xB0198FEF4BD72BB4ULL,
		0x4F1D18F2EAF644FDULL
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
		0xC2037AA946D4DC42ULL,
		0x222582428949F053ULL,
		0xCA445D8A3700D276ULL,
		0x96E776F469338263ULL,
		0xEC7415E55E096CE3ULL,
		0x7AFD30B7EFF66A9FULL,
		0xC9E7DA121863D920ULL,
		0x003AEB0649E9AB47ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8406F5528DA9B884ULL,
		0x444B04851293E0A7ULL,
		0x9488BB146E01A4ECULL,
		0x2DCEEDE8D26704C7ULL,
		0xD8E82BCABC12D9C7ULL,
		0xF5FA616FDFECD53FULL,
		0x93CFB42430C7B240ULL,
		0x0075D60C93D3568FULL
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
		0xBF943B0BBB73ACE9ULL,
		0xED39E32E06C5D817ULL,
		0xC130A0AEB9F8743DULL,
		0xFFAB31C0FC0FA414ULL,
		0x419462F9C4D7EF06ULL,
		0xB682D81F032EC8DDULL,
		0x21BECE4396CAA42AULL,
		0x3E50408C5F55DFA8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7F28761776E759D2ULL,
		0xDA73C65C0D8BB02FULL,
		0x8261415D73F0E87BULL,
		0xFF566381F81F4829ULL,
		0x8328C5F389AFDE0DULL,
		0x6D05B03E065D91BAULL,
		0x437D9C872D954855ULL,
		0x7CA08118BEABBF50ULL
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
		0xCBAEE1D1970388F5ULL,
		0xFC365B4B2D0E47E6ULL,
		0x3760B73D7BB84752ULL,
		0x4C9AA27EF5D35724ULL,
		0xD38317ABC4681D5CULL,
		0x3A176896868FD9C3ULL,
		0x5A452FF028EBCE73ULL,
		0x12A5C1CCE3D62D4BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x975DC3A32E0711EAULL,
		0xF86CB6965A1C8FCDULL,
		0x6EC16E7AF7708EA5ULL,
		0x993544FDEBA6AE48ULL,
		0xA7062F5788D03AB8ULL,
		0x742ED12D0D1FB387ULL,
		0xB48A5FE051D79CE6ULL,
		0x254B8399C7AC5A96ULL
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
		0xD87ACC908DD6A307ULL,
		0x02CA88228224AA91ULL,
		0x5036D909DD36386EULL,
		0x9341F5EF53DDBCB6ULL,
		0xAB90BD2DD2EB176CULL,
		0xA4EC96E8C304BC36ULL,
		0xDF11D81AF960E085ULL,
		0x14A6A9F29D3478C1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB0F599211BAD460EULL,
		0x0595104504495523ULL,
		0xA06DB213BA6C70DCULL,
		0x2683EBDEA7BB796CULL,
		0x57217A5BA5D62ED9ULL,
		0x49D92DD18609786DULL,
		0xBE23B035F2C1C10BULL,
		0x294D53E53A68F183ULL
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
		0x83E6C93F325D1F93ULL,
		0x62BF13FD48E76616ULL,
		0x86BBE9BA53D38923ULL,
		0x7CF379BE3DC032EAULL,
		0xBD2CC500B61D6BBAULL,
		0x7BE5F3DA97D94EA5ULL,
		0x51C5CE2DB81EF8A7ULL,
		0x1C659DA837D436C5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x07CD927E64BA3F26ULL,
		0xC57E27FA91CECC2DULL,
		0x0D77D374A7A71246ULL,
		0xF9E6F37C7B8065D5ULL,
		0x7A598A016C3AD774ULL,
		0xF7CBE7B52FB29D4BULL,
		0xA38B9C5B703DF14EULL,
		0x38CB3B506FA86D8AULL
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
		0x08053DF4BE6325C6ULL,
		0x8A019CC2B2D67E15ULL,
		0xEE9E31E153A40403ULL,
		0x734E3C8B6ED30596ULL,
		0x3B16BC499487CC6EULL,
		0xB543D94C59FDD743ULL,
		0x62C8D90F8C76F9B5ULL,
		0x14BF0547B03F48E6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x100A7BE97CC64B8CULL,
		0x1403398565ACFC2AULL,
		0xDD3C63C2A7480807ULL,
		0xE69C7916DDA60B2DULL,
		0x762D7893290F98DCULL,
		0x6A87B298B3FBAE86ULL,
		0xC591B21F18EDF36BULL,
		0x297E0A8F607E91CCULL
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
		0xE8A0E1FCF8268999ULL,
		0xE143D3BC623C247CULL,
		0xCEB21A3FBE3D1CD3ULL,
		0xE3B28AC933D9E27AULL,
		0x046809EEA17F14E6ULL,
		0x8A54BC686C9C5BAFULL,
		0xBC20F0977DE454A6ULL,
		0x198BB859CF3DD790ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD141C3F9F04D1332ULL,
		0xC287A778C47848F9ULL,
		0x9D64347F7C7A39A7ULL,
		0xC765159267B3C4F5ULL,
		0x08D013DD42FE29CDULL,
		0x14A978D0D938B75EULL,
		0x7841E12EFBC8A94DULL,
		0x331770B39E7BAF21ULL
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
		0xDAF9C240B5E60FD3ULL,
		0x5DE1D8B5CF46040DULL,
		0x29DF57528DE30DE1ULL,
		0x392A68E12BD863CBULL,
		0xC39D36042EBA2D87ULL,
		0x8A698EC3F97FF515ULL,
		0x217D4B424522D12DULL,
		0x30DE7C6571A3C7E3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB5F384816BCC1FA6ULL,
		0xBBC3B16B9E8C081BULL,
		0x53BEAEA51BC61BC2ULL,
		0x7254D1C257B0C796ULL,
		0x873A6C085D745B0EULL,
		0x14D31D87F2FFEA2BULL,
		0x42FA96848A45A25BULL,
		0x61BCF8CAE3478FC6ULL
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
		0xE1156EA4ABFB5E01ULL,
		0x87C0220665A16B2AULL,
		0x9C5D907EABF27D30ULL,
		0x67DE1A43CD16E2CBULL,
		0x8FF65070D36FDA57ULL,
		0x45ED2DE3A3607847ULL,
		0xA1BD17F19E1CAB3BULL,
		0x13A1877D92687C4CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC22ADD4957F6BC02ULL,
		0x0F80440CCB42D655ULL,
		0x38BB20FD57E4FA61ULL,
		0xCFBC34879A2DC597ULL,
		0x1FECA0E1A6DFB4AEULL,
		0x8BDA5BC746C0F08FULL,
		0x437A2FE33C395676ULL,
		0x27430EFB24D0F899ULL
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
		0x87D022F3562E442EULL,
		0x672215E49F7B7040ULL,
		0xFC871BE8ABD935C4ULL,
		0x3EE14B4335324551ULL,
		0x88AB75E3DA8CB638ULL,
		0xE0CDD827F6280C44ULL,
		0x76224F73E639B4F5ULL,
		0x09B36B40361CD527ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0FA045E6AC5C885CULL,
		0xCE442BC93EF6E081ULL,
		0xF90E37D157B26B88ULL,
		0x7DC296866A648AA3ULL,
		0x1156EBC7B5196C70ULL,
		0xC19BB04FEC501889ULL,
		0xEC449EE7CC7369EBULL,
		0x1366D6806C39AA4EULL
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
		0x3439C5364421B70CULL,
		0x48587A4A62297DD0ULL,
		0x50196ED204992305ULL,
		0xA3CE3F7F89C27884ULL,
		0xB91817676C114C7CULL,
		0x83AAD71614DF2CDCULL,
		0xFAD1768F24B8AE0FULL,
		0x3F53EAA20ECB4D06ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x68738A6C88436E18ULL,
		0x90B0F494C452FBA0ULL,
		0xA032DDA40932460AULL,
		0x479C7EFF1384F108ULL,
		0x72302ECED82298F9ULL,
		0x0755AE2C29BE59B9ULL,
		0xF5A2ED1E49715C1FULL,
		0x7EA7D5441D969A0DULL
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
		0xC5025539739F6FB2ULL,
		0x4FF1E6426512EA4FULL,
		0xBB8F57018F9379EBULL,
		0x223C23E3755378A5ULL,
		0x9954B2C0F6AC61F6ULL,
		0xBBF63C74D62D2D2CULL,
		0x4C8A2AB3F07AE980ULL,
		0x0441DDD75792A8ADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8A04AA72E73EDF64ULL,
		0x9FE3CC84CA25D49FULL,
		0x771EAE031F26F3D6ULL,
		0x447847C6EAA6F14BULL,
		0x32A96581ED58C3ECULL,
		0x77EC78E9AC5A5A59ULL,
		0x99145567E0F5D301ULL,
		0x0883BBAEAF25515AULL
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
		0x9893E8C9BEBF14AFULL,
		0x1A8232F76BE24244ULL,
		0xEE163AA2A9E9B07CULL,
		0x5305249F4D91F46EULL,
		0xC8A2D11EB5ECAA1EULL,
		0x8AAA19D12FCF13F3ULL,
		0x8A61D19998E04D20ULL,
		0x1A766F3ED01A3CEEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3127D1937D7E295EULL,
		0x350465EED7C48489ULL,
		0xDC2C754553D360F8ULL,
		0xA60A493E9B23E8DDULL,
		0x9145A23D6BD9543CULL,
		0x155433A25F9E27E7ULL,
		0x14C3A33331C09A41ULL,
		0x34ECDE7DA03479DDULL
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
		0x94E6EBF3D32675E3ULL,
		0xD111A547E256273BULL,
		0x440A643D0A96F7D0ULL,
		0xAD68A2978A3B31AEULL,
		0xDDC0A9CC6AEC3E49ULL,
		0xB4C87FDCD5619DC8ULL,
		0x437B6C48FB1FBCA0ULL,
		0x1C12BB6C64C96473ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x29CDD7E7A64CEBC6ULL,
		0xA2234A8FC4AC4E77ULL,
		0x8814C87A152DEFA1ULL,
		0x5AD1452F1476635CULL,
		0xBB815398D5D87C93ULL,
		0x6990FFB9AAC33B91ULL,
		0x86F6D891F63F7941ULL,
		0x382576D8C992C8E6ULL
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
		0x529D05C5598826FAULL,
		0x46F0D1B4FEC2F879ULL,
		0xC38091BE1B919BB4ULL,
		0xEFFE589FCA8C77FCULL,
		0xC2F93A9DFADD8755ULL,
		0x218D34B3647EBF36ULL,
		0xFF86AB850F332C19ULL,
		0x0A610FA51142FEEFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA53A0B8AB3104DF4ULL,
		0x8DE1A369FD85F0F2ULL,
		0x8701237C37233768ULL,
		0xDFFCB13F9518EFF9ULL,
		0x85F2753BF5BB0EABULL,
		0x431A6966C8FD7E6DULL,
		0xFF0D570A1E665832ULL,
		0x14C21F4A2285FDDFULL
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
		0xF5D747A8C979CA0CULL,
		0x26AE70FE6BD1B3EFULL,
		0x1C9DD4DE89425EA0ULL,
		0x120D1E572F657FE5ULL,
		0x85B53F85D0297A33ULL,
		0x3DB4D65F044407CCULL,
		0xA041E27A8CF0021CULL,
		0x2F3B526CF6CE4BC5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEBAE8F5192F39418ULL,
		0x4D5CE1FCD7A367DFULL,
		0x393BA9BD1284BD40ULL,
		0x241A3CAE5ECAFFCAULL,
		0x0B6A7F0BA052F466ULL,
		0x7B69ACBE08880F99ULL,
		0x4083C4F519E00438ULL,
		0x5E76A4D9ED9C978BULL
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
		0x63F8A5C1087E012DULL,
		0x3F5638FBF11DC1BEULL,
		0x7C6E71CE3CD3360DULL,
		0x6D5C05F8239BBB0AULL,
		0xD3C87D20F82C397FULL,
		0x5F3B0C1E8FF7D453ULL,
		0x393662D52EC4C9C5ULL,
		0x3D4FB4EBB1C295DFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC7F14B8210FC025AULL,
		0x7EAC71F7E23B837CULL,
		0xF8DCE39C79A66C1AULL,
		0xDAB80BF047377614ULL,
		0xA790FA41F05872FEULL,
		0xBE76183D1FEFA8A7ULL,
		0x726CC5AA5D89938AULL,
		0x7A9F69D763852BBEULL
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
		0xDE705EE89B45BB9EULL,
		0x0FA7BBAE59801C35ULL,
		0x95E6B0CE75B7D0ABULL,
		0x98AD8D55E97693C7ULL,
		0x7F33AE41DD16C24EULL,
		0xF1128032C332E565ULL,
		0x72284AEAB028A482ULL,
		0x04CBF00D321FD380ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBCE0BDD1368B773CULL,
		0x1F4F775CB300386BULL,
		0x2BCD619CEB6FA156ULL,
		0x315B1AABD2ED278FULL,
		0xFE675C83BA2D849DULL,
		0xE22500658665CACAULL,
		0xE45095D560514905ULL,
		0x0997E01A643FA700ULL
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
		0x26478AB441BA91DEULL,
		0x6E8238D9F518F84DULL,
		0xEE7EE35E52290C5AULL,
		0x89059CD62E539E9EULL,
		0xCDF0F57463BDED27ULL,
		0x38D7C97315AB94F0ULL,
		0x31D7175F75733BB2ULL,
		0x20ED8D6B015C26F0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4C8F1568837523BCULL,
		0xDD0471B3EA31F09AULL,
		0xDCFDC6BCA45218B4ULL,
		0x120B39AC5CA73D3DULL,
		0x9BE1EAE8C77BDA4FULL,
		0x71AF92E62B5729E1ULL,
		0x63AE2EBEEAE67764ULL,
		0x41DB1AD602B84DE0ULL
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
		0xAE2AC3A8CBC71F43ULL,
		0xC5F1B6398B1767EAULL,
		0x47E5066DC8C5EC47ULL,
		0x4A470C09493C3C94ULL,
		0xE899D8FEC407F174ULL,
		0x42F76B5F67A369C2ULL,
		0x7665527956FF82FDULL,
		0x2C70D35E241BB307ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5C558751978E3E86ULL,
		0x8BE36C73162ECFD5ULL,
		0x8FCA0CDB918BD88FULL,
		0x948E181292787928ULL,
		0xD133B1FD880FE2E8ULL,
		0x85EED6BECF46D385ULL,
		0xECCAA4F2ADFF05FAULL,
		0x58E1A6BC4837660EULL
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
		0xE758CFDF46F89BBDULL,
		0xF21579F8A9B1E2BEULL,
		0xFC94CDDACD0F38D6ULL,
		0xAF20E14F6E8C471BULL,
		0x25BAA888EF931132ULL,
		0xAB5D2FDA75B9B6BFULL,
		0x470E81FA24D4E39BULL,
		0x1AE8ED7E17137385ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCEB19FBE8DF1377AULL,
		0xE42AF3F15363C57DULL,
		0xF9299BB59A1E71ADULL,
		0x5E41C29EDD188E37ULL,
		0x4B755111DF262265ULL,
		0x56BA5FB4EB736D7EULL,
		0x8E1D03F449A9C737ULL,
		0x35D1DAFC2E26E70AULL
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
		0xCA707C8D69D4AE0EULL,
		0xF80CE7DB645A7044ULL,
		0x623C8A7EB7FBD4F8ULL,
		0xBA144ABC693289BBULL,
		0xBD7B1C514F07D4FDULL,
		0xDC110529A205A911ULL,
		0xC2B907C9A8CECA5CULL,
		0x319D2FEB93E03D2CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x94E0F91AD3A95C1CULL,
		0xF019CFB6C8B4E089ULL,
		0xC47914FD6FF7A9F1ULL,
		0x74289578D2651376ULL,
		0x7AF638A29E0FA9FBULL,
		0xB8220A53440B5223ULL,
		0x85720F93519D94B9ULL,
		0x633A5FD727C07A59ULL
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
		0xD8BD1CD0813FBFE0ULL,
		0x78E0406CE12B0C5FULL,
		0x3ED372D507FEC22EULL,
		0x8A4025B87D383C93ULL,
		0xF034989A3C295F87ULL,
		0x5D0B0CE9B90F2202ULL,
		0x1AB43B5E8AF8F5A7ULL,
		0x00B3AE8BFE7684B7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB17A39A1027F7FC0ULL,
		0xF1C080D9C25618BFULL,
		0x7DA6E5AA0FFD845CULL,
		0x14804B70FA707926ULL,
		0xE06931347852BF0FULL,
		0xBA1619D3721E4405ULL,
		0x356876BD15F1EB4EULL,
		0x01675D17FCED096EULL
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
		0xAFE35C99653089D6ULL,
		0xCCD755366755D029ULL,
		0x84F329F391BC1752ULL,
		0x0BC2FFD4B660EF31ULL,
		0x568702793B5A0913ULL,
		0xFE74254BB2E2806CULL,
		0x3DF89C4680747E69ULL,
		0x2B3C0D8757205A41ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5FC6B932CA6113ACULL,
		0x99AEAA6CCEABA053ULL,
		0x09E653E723782EA5ULL,
		0x1785FFA96CC1DE63ULL,
		0xAD0E04F276B41226ULL,
		0xFCE84A9765C500D8ULL,
		0x7BF1388D00E8FCD3ULL,
		0x56781B0EAE40B482ULL
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
		0xB2B0989FDEDC766FULL,
		0x5B53482A6A9D1A36ULL,
		0xCF032A7E395FDDFDULL,
		0xA58CCCE2DE2D9124ULL,
		0xFC07CEFE390DE1BDULL,
		0xFD93E55BADB92B82ULL,
		0x67994158FF7D4EFDULL,
		0x1139E4829E431AC2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6561313FBDB8ECDEULL,
		0xB6A69054D53A346DULL,
		0x9E0654FC72BFBBFAULL,
		0x4B1999C5BC5B2249ULL,
		0xF80F9DFC721BC37BULL,
		0xFB27CAB75B725705ULL,
		0xCF3282B1FEFA9DFBULL,
		0x2273C9053C863584ULL
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
		0x2D050F276746EA9CULL,
		0xA152A7E09EB8367EULL,
		0x207E8F325A83228BULL,
		0x6DC496153A3255AFULL,
		0x0A2D24CA1B3AF710ULL,
		0x712C1683C487BE47ULL,
		0x966E1230B7137F86ULL,
		0x151152D85F09DB49ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5A0A1E4ECE8DD538ULL,
		0x42A54FC13D706CFCULL,
		0x40FD1E64B5064517ULL,
		0xDB892C2A7464AB5EULL,
		0x145A49943675EE20ULL,
		0xE2582D07890F7C8EULL,
		0x2CDC24616E26FF0CULL,
		0x2A22A5B0BE13B693ULL
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
		0xADC13C7B8704E167ULL,
		0x72E94CF989EBC32CULL,
		0xD231F659A5474798ULL,
		0xCF040623A0BA89DBULL,
		0xB8E1DD865B8D3CB1ULL,
		0x90EE78DA8E98D7D4ULL,
		0xA898FBD10E00BE14ULL,
		0x0CBA3801D995F322ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5B8278F70E09C2CEULL,
		0xE5D299F313D78659ULL,
		0xA463ECB34A8E8F30ULL,
		0x9E080C47417513B7ULL,
		0x71C3BB0CB71A7963ULL,
		0x21DCF1B51D31AFA9ULL,
		0x5131F7A21C017C29ULL,
		0x19747003B32BE645ULL
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
		0xB5F76BA45C1D9AE6ULL,
		0xDD103C01169F463BULL,
		0x0CD12178683CD963ULL,
		0x73C7C2B694F3E341ULL,
		0x1A7351DFCF330B17ULL,
		0xC700B814B2E71213ULL,
		0xA6231334D9059F79ULL,
		0x33C0B1C33BC6AC35ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6BEED748B83B35CCULL,
		0xBA2078022D3E8C77ULL,
		0x19A242F0D079B2C7ULL,
		0xE78F856D29E7C682ULL,
		0x34E6A3BF9E66162EULL,
		0x8E01702965CE2426ULL,
		0x4C462669B20B3EF3ULL,
		0x67816386778D586BULL
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
		0x42C8B1343DE1BC7AULL,
		0xEA02E1B4D93CB7EDULL,
		0x9CF64C38ABAEEE2DULL,
		0x617C3ED454EEA7B1ULL,
		0x4AF527F3DE669D20ULL,
		0x55C1E6DBED7227B4ULL,
		0x7DA4C8C42B4EF142ULL,
		0x1F96E3A4B04FF3BFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x859162687BC378F4ULL,
		0xD405C369B2796FDAULL,
		0x39EC9871575DDC5BULL,
		0xC2F87DA8A9DD4F63ULL,
		0x95EA4FE7BCCD3A40ULL,
		0xAB83CDB7DAE44F68ULL,
		0xFB499188569DE284ULL,
		0x3F2DC749609FE77EULL
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
		0x5CA06EA2624F05ECULL,
		0x2457B65A968D391FULL,
		0x638E5CE514BB9419ULL,
		0xA8C360287DD3F038ULL,
		0x2897E48A83C3AE41ULL,
		0xB9367EA68C8C5647ULL,
		0xAD278B9DB6BF9890ULL,
		0x1B386DD1F61BE522ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB940DD44C49E0BD8ULL,
		0x48AF6CB52D1A723EULL,
		0xC71CB9CA29772832ULL,
		0x5186C050FBA7E070ULL,
		0x512FC91507875C83ULL,
		0x726CFD4D1918AC8EULL,
		0x5A4F173B6D7F3121ULL,
		0x3670DBA3EC37CA45ULL
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
		0x1D3634869625D1CFULL,
		0x263D602DF7156B5EULL,
		0xFDFC6DDBF1AEB992ULL,
		0xCF2093AA73430AF7ULL,
		0x3788D8DA9D5AA41BULL,
		0xC2905D37D88E4EF2ULL,
		0x2E3411A93F0C2B47ULL,
		0x3C2571687CF59446ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3A6C690D2C4BA39EULL,
		0x4C7AC05BEE2AD6BCULL,
		0xFBF8DBB7E35D7324ULL,
		0x9E412754E68615EFULL,
		0x6F11B1B53AB54837ULL,
		0x8520BA6FB11C9DE4ULL,
		0x5C6823527E18568FULL,
		0x784AE2D0F9EB288CULL
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
		0x8B9169978718A4ECULL,
		0x88532574E031EAEFULL,
		0x8425F2A5BA410BFEULL,
		0xAA50D04572EDE15AULL,
		0xEB9E1DBEDE1C5F7EULL,
		0x65AFDDCBD4504E5CULL,
		0x79C0DD654C2BF473ULL,
		0x3980430DC63FB4F4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1722D32F0E3149D8ULL,
		0x10A64AE9C063D5DFULL,
		0x084BE54B748217FDULL,
		0x54A1A08AE5DBC2B5ULL,
		0xD73C3B7DBC38BEFDULL,
		0xCB5FBB97A8A09CB9ULL,
		0xF381BACA9857E8E6ULL,
		0x7300861B8C7F69E8ULL
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
		0x3CE23778C580E932ULL,
		0x301B6A59107CD298ULL,
		0x17A864674687204FULL,
		0x86A4163D936152D2ULL,
		0x1D7267F1857FB620ULL,
		0x92A298FDB4629673ULL,
		0xA077FBD75F2DC000ULL,
		0x0DB78508B5414C19ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x79C46EF18B01D264ULL,
		0x6036D4B220F9A530ULL,
		0x2F50C8CE8D0E409EULL,
		0x0D482C7B26C2A5A4ULL,
		0x3AE4CFE30AFF6C41ULL,
		0x254531FB68C52CE6ULL,
		0x40EFF7AEBE5B8001ULL,
		0x1B6F0A116A829833ULL
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
		0xC1CAA87798362C00ULL,
		0x582D82EC3C3C69BAULL,
		0x4F3672913A06E599ULL,
		0x57379D4F404ABF8AULL,
		0xABE9D71AE5115DA8ULL,
		0x2592E5E9A0080663ULL,
		0x00B90EE8CE36BBC0ULL,
		0x25ECC7FC54B29762ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x839550EF306C5800ULL,
		0xB05B05D87878D375ULL,
		0x9E6CE522740DCB32ULL,
		0xAE6F3A9E80957F14ULL,
		0x57D3AE35CA22BB50ULL,
		0x4B25CBD340100CC7ULL,
		0x01721DD19C6D7780ULL,
		0x4BD98FF8A9652EC4ULL
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
		0x10CF2D34C639C38BULL,
		0x5099B979C5B8593FULL,
		0xAC56EF697FA1BC2DULL,
		0x35404E43CF533FD6ULL,
		0xE054E99A38E38554ULL,
		0xBFE6E5E7CE91ADD7ULL,
		0xE48EFD33C244C6FAULL,
		0x21E57A850585A285ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x219E5A698C738716ULL,
		0xA13372F38B70B27EULL,
		0x58ADDED2FF43785AULL,
		0x6A809C879EA67FADULL,
		0xC0A9D33471C70AA8ULL,
		0x7FCDCBCF9D235BAFULL,
		0xC91DFA6784898DF5ULL,
		0x43CAF50A0B0B450BULL
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
		0x33D164E50D9961C8ULL,
		0xD72616461C37EA9FULL,
		0x9F43EBE709BEB504ULL,
		0x417FD7F6B0AD164EULL,
		0x481498D3EA1006AEULL,
		0x6BD5A4D9EC5DD80DULL,
		0xFB2AE812754D8F55ULL,
		0x37AA228F8ACFA63DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x67A2C9CA1B32C390ULL,
		0xAE4C2C8C386FD53EULL,
		0x3E87D7CE137D6A09ULL,
		0x82FFAFED615A2C9DULL,
		0x902931A7D4200D5CULL,
		0xD7AB49B3D8BBB01AULL,
		0xF655D024EA9B1EAAULL,
		0x6F54451F159F4C7BULL
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
		0x1E0CB75C91D27469ULL,
		0x52BB991D3A4BC4AFULL,
		0x770D0C8EB7596CF8ULL,
		0x3750C8E6D642AD5BULL,
		0x8E0BB1243B9E6F7DULL,
		0xD4D52345D3423354ULL,
		0xAA07981C01005520ULL,
		0x07969125C951352EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3C196EB923A4E8D2ULL,
		0xA577323A7497895EULL,
		0xEE1A191D6EB2D9F0ULL,
		0x6EA191CDAC855AB6ULL,
		0x1C176248773CDEFAULL,
		0xA9AA468BA68466A9ULL,
		0x540F30380200AA41ULL,
		0x0F2D224B92A26A5DULL
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
		0x957B1E1A38F13E4BULL,
		0x0997944C15F2F10EULL,
		0xF518AAD127121B1DULL,
		0x4B93CEADF31C400EULL,
		0x8F36D8222BE75EF7ULL,
		0x1829FE626CCB6723ULL,
		0xAA854E9B14F65CD8ULL,
		0x2BE0C5B3AF47BF36ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2AF63C3471E27C96ULL,
		0x132F28982BE5E21DULL,
		0xEA3155A24E24363AULL,
		0x97279D5BE638801DULL,
		0x1E6DB04457CEBDEEULL,
		0x3053FCC4D996CE47ULL,
		0x550A9D3629ECB9B0ULL,
		0x57C18B675E8F7E6DULL
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
		0xAFB66EA5D993ADD3ULL,
		0xEA18527AA6ACEA96ULL,
		0x3AAA2F270F7E72B7ULL,
		0xB924782A86AEA6B4ULL,
		0xB1400FAF656036F8ULL,
		0xDEFDFB58AEA9D1F5ULL,
		0xE88EED5F8B9B03AAULL,
		0x081010827906D74AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5F6CDD4BB3275BA6ULL,
		0xD430A4F54D59D52DULL,
		0x75545E4E1EFCE56FULL,
		0x7248F0550D5D4D68ULL,
		0x62801F5ECAC06DF1ULL,
		0xBDFBF6B15D53A3EBULL,
		0xD11DDABF17360755ULL,
		0x10202104F20DAE95ULL
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
		0xDAC7C2A35412C0EEULL,
		0xDF89C6F472209F54ULL,
		0xEED2CFB399F6A41FULL,
		0xC685C07A44A84678ULL,
		0xDA86C8FA6DED6263ULL,
		0x75B54F2F4FB8098EULL,
		0xE6D3D24553AB2B17ULL,
		0x1F87E86768FBCEE6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB58F8546A82581DCULL,
		0xBF138DE8E4413EA9ULL,
		0xDDA59F6733ED483FULL,
		0x8D0B80F489508CF1ULL,
		0xB50D91F4DBDAC4C7ULL,
		0xEB6A9E5E9F70131DULL,
		0xCDA7A48AA756562EULL,
		0x3F0FD0CED1F79DCDULL
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
		0x92B7B83CEF4AEAC7ULL,
		0x2C2D0305C7744ED4ULL,
		0xD1137D592B96B856ULL,
		0x7B55668C37690745ULL,
		0x8F4D36E480492BC0ULL,
		0x357403C3BB982C1BULL,
		0x168AFDE73C8F968BULL,
		0x0A0F83103944D480ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x256F7079DE95D58EULL,
		0x585A060B8EE89DA9ULL,
		0xA226FAB2572D70ACULL,
		0xF6AACD186ED20E8BULL,
		0x1E9A6DC900925780ULL,
		0x6AE8078777305837ULL,
		0x2D15FBCE791F2D16ULL,
		0x141F06207289A900ULL
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
		0xB13E1353FDB3CB86ULL,
		0x01EECC44DD2AF854ULL,
		0xAFE8C94EAF44293AULL,
		0x1D4BC39D18F101D5ULL,
		0x7F99E8E2BE5739F5ULL,
		0xD4EEDF840B979E22ULL,
		0xE1F1618939D4688FULL,
		0x3F2747FB97A66336ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x627C26A7FB67970CULL,
		0x03DD9889BA55F0A9ULL,
		0x5FD1929D5E885274ULL,
		0x3A97873A31E203ABULL,
		0xFF33D1C57CAE73EAULL,
		0xA9DDBF08172F3C44ULL,
		0xC3E2C31273A8D11FULL,
		0x7E4E8FF72F4CC66DULL
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
		0x47652758284AB920ULL,
		0x71A0C03B356E4C95ULL,
		0xDC7F879424F75A70ULL,
		0x662E392684C77F5AULL,
		0x57BC2997F23E4C2EULL,
		0xFAC1EE27954C08F1ULL,
		0x84C3731E833A97EFULL,
		0x3F7DB649DF6DC447ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8ECA4EB050957240ULL,
		0xE34180766ADC992AULL,
		0xB8FF0F2849EEB4E0ULL,
		0xCC5C724D098EFEB5ULL,
		0xAF78532FE47C985CULL,
		0xF583DC4F2A9811E2ULL,
		0x0986E63D06752FDFULL,
		0x7EFB6C93BEDB888FULL
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
		0x5CFD5B4476031A07ULL,
		0x66699FCE9955B330ULL,
		0xDA8C851B70DD51FEULL,
		0x632FD2EB02C62C3FULL,
		0x2DEEF0176A7A1B7DULL,
		0x62D3001C05CC0073ULL,
		0x29682EA68D4A35D3ULL,
		0x1DD04E10815674DCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB9FAB688EC06340EULL,
		0xCCD33F9D32AB6660ULL,
		0xB5190A36E1BAA3FCULL,
		0xC65FA5D6058C587FULL,
		0x5BDDE02ED4F436FAULL,
		0xC5A600380B9800E6ULL,
		0x52D05D4D1A946BA6ULL,
		0x3BA09C2102ACE9B8ULL
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
		0xBAD0F740619DAF40ULL,
		0x9D1036BE941C9391ULL,
		0x11B6D5671A25F4A8ULL,
		0x8A06221FB58995A5ULL,
		0x43177E358479DEB5ULL,
		0xB0743F4DA2ABA28FULL,
		0xC429E3EF8F6E0E34ULL,
		0x30073F80F411CDCFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x75A1EE80C33B5E80ULL,
		0x3A206D7D28392723ULL,
		0x236DAACE344BE951ULL,
		0x140C443F6B132B4AULL,
		0x862EFC6B08F3BD6BULL,
		0x60E87E9B4557451EULL,
		0x8853C7DF1EDC1C69ULL,
		0x600E7F01E8239B9FULL
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
		0xE31A644DF3633E16ULL,
		0xFA0B77064828B231ULL,
		0xDD41E6BC69B1D45FULL,
		0xA3589FA4CFAC9190ULL,
		0xFC1C17EBF3B90371ULL,
		0x1B991E302475A1F2ULL,
		0x993C4FA16B4EC2CCULL,
		0x36083A29D133B59AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC634C89BE6C67C2CULL,
		0xF416EE0C90516463ULL,
		0xBA83CD78D363A8BFULL,
		0x46B13F499F592321ULL,
		0xF8382FD7E77206E3ULL,
		0x37323C6048EB43E5ULL,
		0x32789F42D69D8598ULL,
		0x6C107453A2676B35ULL
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
		0x8121CBDD85F92594ULL,
		0x8DD7682BF4EABE29ULL,
		0xD5086F52741137DFULL,
		0x66DDC644257E5495ULL,
		0x4024D3266B06E0FDULL,
		0x43D00BB069311AFDULL,
		0x90F6E71AA9C18E13ULL,
		0x286EA354A2B1F114ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x024397BB0BF24B28ULL,
		0x1BAED057E9D57C53ULL,
		0xAA10DEA4E8226FBFULL,
		0xCDBB8C884AFCA92BULL,
		0x8049A64CD60DC1FAULL,
		0x87A01760D26235FAULL,
		0x21EDCE3553831C26ULL,
		0x50DD46A94563E229ULL
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
		0xD1C1FC9819C5668BULL,
		0xB2667C725D4372BCULL,
		0x82E99A0179DC2586ULL,
		0xB6ADC5BCCC77CB20ULL,
		0xFE1868D808EBCEA9ULL,
		0x7D0810F00460E69FULL,
		0x08C4E0F2C44036BFULL,
		0x01A63A1EF2C9175CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA383F930338ACD16ULL,
		0x64CCF8E4BA86E579ULL,
		0x05D33402F3B84B0DULL,
		0x6D5B8B7998EF9641ULL,
		0xFC30D1B011D79D53ULL,
		0xFA1021E008C1CD3FULL,
		0x1189C1E588806D7EULL,
		0x034C743DE5922EB8ULL
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
		0x28EA463B33006245ULL,
		0xE29B09BA583EF64DULL,
		0x8DA64A767A2CB5A8ULL,
		0x82A3C7E0AC0AEDA9ULL,
		0x3BA9BEC685BB1EB6ULL,
		0x2181397136846EF1ULL,
		0x539DCEC4D4B1D11EULL,
		0x3A1F479D1953C79AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x51D48C766600C48AULL,
		0xC5361374B07DEC9AULL,
		0x1B4C94ECF4596B51ULL,
		0x05478FC15815DB53ULL,
		0x77537D8D0B763D6DULL,
		0x430272E26D08DDE2ULL,
		0xA73B9D89A963A23CULL,
		0x743E8F3A32A78F34ULL
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
		0x05CD44BA1633FCC9ULL,
		0xF912307263A6F235ULL,
		0xB9E606D8DCFAD745ULL,
		0x84AA61FDA67060D5ULL,
		0x5F28E19AACD593D2ULL,
		0xEAE3E80B9FB833F0ULL,
		0x4208AC8B0BA5D5ABULL,
		0x116426B0C121C500ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0B9A89742C67F992ULL,
		0xF22460E4C74DE46AULL,
		0x73CC0DB1B9F5AE8BULL,
		0x0954C3FB4CE0C1ABULL,
		0xBE51C33559AB27A5ULL,
		0xD5C7D0173F7067E0ULL,
		0x84115916174BAB57ULL,
		0x22C84D6182438A00ULL
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
		0xBD3967CC72B01141ULL,
		0x00D0DCEE461D3B4DULL,
		0x8EC1D27C65216DE6ULL,
		0x17085F82DC312340ULL,
		0x15A0CD79803DAB01ULL,
		0xB46E43CE92943DDAULL,
		0x1E392EEEAD77343AULL,
		0x33129BAEA0C3C2CEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7A72CF98E5602282ULL,
		0x01A1B9DC8C3A769BULL,
		0x1D83A4F8CA42DBCCULL,
		0x2E10BF05B8624681ULL,
		0x2B419AF3007B5602ULL,
		0x68DC879D25287BB4ULL,
		0x3C725DDD5AEE6875ULL,
		0x6625375D4187859CULL
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
		0xD490E6499242BD72ULL,
		0xF96EC2AFA95993F6ULL,
		0x8A4265E7BB36A993ULL,
		0x44DD391C20581390ULL,
		0xB071DCD5EDB490E1ULL,
		0x498137E22A18B7B2ULL,
		0x9C7C677A64267B26ULL,
		0x03EF4C8767DC13D9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA921CC9324857AE4ULL,
		0xF2DD855F52B327EDULL,
		0x1484CBCF766D5327ULL,
		0x89BA723840B02721ULL,
		0x60E3B9ABDB6921C2ULL,
		0x93026FC454316F65ULL,
		0x38F8CEF4C84CF64CULL,
		0x07DE990ECFB827B3ULL
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
		0x010027B907A3E77EULL,
		0x51EA5D7E1FE447DCULL,
		0xC53133E1CEE9F4E4ULL,
		0x797C41CE52A769F3ULL,
		0x1D9FA579ECCAADA8ULL,
		0x2F8109FA7C21599CULL,
		0x8758C0203585601CULL,
		0x00BD323DE6D7108BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x02004F720F47CEFCULL,
		0xA3D4BAFC3FC88FB8ULL,
		0x8A6267C39DD3E9C8ULL,
		0xF2F8839CA54ED3E7ULL,
		0x3B3F4AF3D9955B50ULL,
		0x5F0213F4F842B338ULL,
		0x0EB180406B0AC038ULL,
		0x017A647BCDAE2117ULL
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
		0x41603FBE6E801CEDULL,
		0xCE6BA9913897F171ULL,
		0x55BC1495DC62C625ULL,
		0xBC55DC4F33794131ULL,
		0x2E27278FE063B487ULL,
		0xE344562A047D5AACULL,
		0x59C67C8EACEC8652ULL,
		0x0C1876D3765A48EEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x82C07F7CDD0039DAULL,
		0x9CD75322712FE2E2ULL,
		0xAB78292BB8C58C4BULL,
		0x78ABB89E66F28262ULL,
		0x5C4E4F1FC0C7690FULL,
		0xC688AC5408FAB558ULL,
		0xB38CF91D59D90CA5ULL,
		0x1830EDA6ECB491DCULL
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
		0x59FAA7A2C98F71BCULL,
		0x06DA0792DFC7C003ULL,
		0xE444244FB4E50414ULL,
		0x95841C8E3F1CBFA3ULL,
		0xC1F9F9864AF3ECD5ULL,
		0x06AE87A0A966A750ULL,
		0x3FBDFEE0911FCCC5ULL,
		0x0D7AC3200BA56A3AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB3F54F45931EE378ULL,
		0x0DB40F25BF8F8006ULL,
		0xC888489F69CA0828ULL,
		0x2B08391C7E397F47ULL,
		0x83F3F30C95E7D9ABULL,
		0x0D5D0F4152CD4EA1ULL,
		0x7F7BFDC1223F998AULL,
		0x1AF58640174AD474ULL
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
		0x1E4BAAB6659E0734ULL,
		0xE3D3E98BB1C3AD60ULL,
		0x85E99BDB1BBE1BD9ULL,
		0xFC5763447023D6A0ULL,
		0x63C38D4E85F546E9ULL,
		0x5A97A9B649602F7FULL,
		0x3FBD863F68ACFF63ULL,
		0x0C64802CEAFB9F71ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3C97556CCB3C0E68ULL,
		0xC7A7D31763875AC0ULL,
		0x0BD337B6377C37B3ULL,
		0xF8AEC688E047AD41ULL,
		0xC7871A9D0BEA8DD3ULL,
		0xB52F536C92C05EFEULL,
		0x7F7B0C7ED159FEC6ULL,
		0x18C90059D5F73EE2ULL
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
		0x34797BABEBD60ABAULL,
		0xFA521AC57DBDD244ULL,
		0x5094B0EF14C4E1E2ULL,
		0xCA0BAEC320068924ULL,
		0x04C67DCE5C673E14ULL,
		0xFC302BE963D7AEAAULL,
		0xB8A88DCB30B80366ULL,
		0x3AF91D124304CAE0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x68F2F757D7AC1574ULL,
		0xF4A4358AFB7BA488ULL,
		0xA12961DE2989C3C5ULL,
		0x94175D86400D1248ULL,
		0x098CFB9CB8CE7C29ULL,
		0xF86057D2C7AF5D54ULL,
		0x71511B96617006CDULL,
		0x75F23A24860995C1ULL
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
		0xA8160E956051E2E8ULL,
		0x80299FE511BC5A80ULL,
		0x830BEAEB37583D8DULL,
		0x9B943481C03BB998ULL,
		0x455044DE87DB2403ULL,
		0x93328FD82C2AA640ULL,
		0xF294F27F84CF1F4AULL,
		0x3FB201888888602AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x502C1D2AC0A3C5D0ULL,
		0x00533FCA2378B501ULL,
		0x0617D5D66EB07B1BULL,
		0x3728690380777331ULL,
		0x8AA089BD0FB64807ULL,
		0x26651FB058554C80ULL,
		0xE529E4FF099E3E95ULL,
		0x7F6403111110C055ULL
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
		0x088348B7DD10BA60ULL,
		0x4F80567C6D888C10ULL,
		0xDF7B57AC7817293BULL,
		0xDF1CCDD5831A4F39ULL,
		0x9B802EB29E69E6B5ULL,
		0xE8718BDF610008E6ULL,
		0x7D146820BC984B6FULL,
		0x317FEB06FB920879ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1106916FBA2174C0ULL,
		0x9F00ACF8DB111820ULL,
		0xBEF6AF58F02E5276ULL,
		0xBE399BAB06349E73ULL,
		0x37005D653CD3CD6BULL,
		0xD0E317BEC20011CDULL,
		0xFA28D041793096DFULL,
		0x62FFD60DF72410F2ULL
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
		0xEB8F1AC1BEADA60AULL,
		0x1FDC10FABB84EA53ULL,
		0x3E40ADF75F052FF5ULL,
		0x8D874DB9125FFCD9ULL,
		0x3AE9F82001DA2DA0ULL,
		0x800F960200EF548FULL,
		0x03E3F63E25B89097ULL,
		0x33742365C5F69A63ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD71E35837D5B4C14ULL,
		0x3FB821F57709D4A7ULL,
		0x7C815BEEBE0A5FEAULL,
		0x1B0E9B7224BFF9B2ULL,
		0x75D3F04003B45B41ULL,
		0x001F2C0401DEA91EULL,
		0x07C7EC7C4B71212FULL,
		0x66E846CB8BED34C6ULL
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
		0x46C8F04D059DBE88ULL,
		0x37FFB4168F20E588ULL,
		0xBABEB9876D3BA5E3ULL,
		0x67279D8C764E9DD8ULL,
		0x39FF2234F6649FCEULL,
		0x7F80AC2B7B5BA43AULL,
		0xB36980C83DBEFB7AULL,
		0x2802B7CF30845CFCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8D91E09A0B3B7D10ULL,
		0x6FFF682D1E41CB10ULL,
		0x757D730EDA774BC6ULL,
		0xCE4F3B18EC9D3BB1ULL,
		0x73FE4469ECC93F9CULL,
		0xFF015856F6B74874ULL,
		0x66D301907B7DF6F4ULL,
		0x50056F9E6108B9F9ULL
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
		0xA2269B329550BB85ULL,
		0xD931B657D0D5AB22ULL,
		0xD6FA14FC91BDFF3EULL,
		0xA6F9BB493AD9C080ULL,
		0x9A6268C5A1BEC55FULL,
		0x2EB3C8F3905DDC5CULL,
		0x02B9F23C3BBBCEC0ULL,
		0x1646EA1BB7E07A44ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x444D36652AA1770AULL,
		0xB2636CAFA1AB5645ULL,
		0xADF429F9237BFE7DULL,
		0x4DF3769275B38101ULL,
		0x34C4D18B437D8ABFULL,
		0x5D6791E720BBB8B9ULL,
		0x0573E47877779D80ULL,
		0x2C8DD4376FC0F488ULL
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
		0x02F367E5BBBD0FDCULL,
		0x6954D5472D337152ULL,
		0x2A8956BD6270C13AULL,
		0xF7BF1127CEC9353CULL,
		0x08737294A4CE6A89ULL,
		0xCB963F070B790834ULL,
		0xC3B1E171AAEE4A42ULL,
		0x00FEEC0886F3563DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x05E6CFCB777A1FB8ULL,
		0xD2A9AA8E5A66E2A4ULL,
		0x5512AD7AC4E18274ULL,
		0xEF7E224F9D926A78ULL,
		0x10E6E529499CD513ULL,
		0x972C7E0E16F21068ULL,
		0x8763C2E355DC9485ULL,
		0x01FDD8110DE6AC7BULL
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
		0xBD396A88FA2E4738ULL,
		0xB854560525A46AB6ULL,
		0xD4F10577D0B390BAULL,
		0xA73343C840CC2C85ULL,
		0x930A01B4E138B5D0ULL,
		0x86ACBC14EC84BB29ULL,
		0x2157D66268836DAFULL,
		0x37A9FA0383A3AA8AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7A72D511F45C8E70ULL,
		0x70A8AC0A4B48D56DULL,
		0xA9E20AEFA1672175ULL,
		0x4E6687908198590BULL,
		0x26140369C2716BA1ULL,
		0x0D597829D9097653ULL,
		0x42AFACC4D106DB5FULL,
		0x6F53F40707475514ULL
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
		0xCADE6E5E1FC3204AULL,
		0x28B6605C4E3967B8ULL,
		0x2ACE65281DBF653BULL,
		0x31EEA0F30811C16CULL,
		0xEA0E65B572509B71ULL,
		0xC56C03F470A4730DULL,
		0x45DD3BC40EE84DF7ULL,
		0x14CAE5CD505AC9FBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x95BCDCBC3F864094ULL,
		0x516CC0B89C72CF71ULL,
		0x559CCA503B7ECA76ULL,
		0x63DD41E6102382D8ULL,
		0xD41CCB6AE4A136E2ULL,
		0x8AD807E8E148E61BULL,
		0x8BBA77881DD09BEFULL,
		0x2995CB9AA0B593F6ULL
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
		0x3E549509BF81EDC5ULL,
		0x915B1A907D7EDA17ULL,
		0x8B8196FAF3951BA2ULL,
		0xAC21F8B6510B5F8EULL,
		0x376070E72D77D875ULL,
		0x57A385AE16101B9FULL,
		0x8124DB574C60D6EAULL,
		0x022F4AFECAE26C24ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7CA92A137F03DB8AULL,
		0x22B63520FAFDB42EULL,
		0x17032DF5E72A3745ULL,
		0x5843F16CA216BF1DULL,
		0x6EC0E1CE5AEFB0EBULL,
		0xAF470B5C2C20373EULL,
		0x0249B6AE98C1ADD4ULL,
		0x045E95FD95C4D849ULL
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
		0x36A9160362A43AA9ULL,
		0x8F8CFDC38826671BULL,
		0x9838B8552CFE79A9ULL,
		0x03019A7A9C7D65B1ULL,
		0x3CB110EA26C0D07CULL,
		0x13F1DFB365E37703ULL,
		0xA4530FE29031364CULL,
		0x2AE082F50BD96B4BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6D522C06C5487552ULL,
		0x1F19FB87104CCE36ULL,
		0x307170AA59FCF353ULL,
		0x060334F538FACB63ULL,
		0x796221D44D81A0F8ULL,
		0x27E3BF66CBC6EE06ULL,
		0x48A61FC520626C98ULL,
		0x55C105EA17B2D697ULL
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
		0x4586C547CC65E3ACULL,
		0x8E01A2677ED5222FULL,
		0x9A38A01F9907882CULL,
		0xFAD796948A2A7E4DULL,
		0xF3ED922938101190ULL,
		0x8F5A96C1557A8258ULL,
		0x554E1D7F74E413A9ULL,
		0x17A2E73F6CD8DC0FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8B0D8A8F98CBC758ULL,
		0x1C0344CEFDAA445EULL,
		0x3471403F320F1059ULL,
		0xF5AF2D291454FC9BULL,
		0xE7DB245270202321ULL,
		0x1EB52D82AAF504B1ULL,
		0xAA9C3AFEE9C82753ULL,
		0x2F45CE7ED9B1B81EULL
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
		0xAC23DD2E19F430C7ULL,
		0x5DB824A36B2EB6B1ULL,
		0x419541313BEC9CA4ULL,
		0x748AFF1794258221ULL,
		0x0E43D046854B17D2ULL,
		0x87CEBD8C01E70923ULL,
		0x11E04C237E68E641ULL,
		0x135F041F64B15498ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5847BA5C33E8618EULL,
		0xBB704946D65D6D63ULL,
		0x832A826277D93948ULL,
		0xE915FE2F284B0442ULL,
		0x1C87A08D0A962FA4ULL,
		0x0F9D7B1803CE1246ULL,
		0x23C09846FCD1CC83ULL,
		0x26BE083EC962A930ULL
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
		0x3453CA4AC3CE88D9ULL,
		0x23CD081CCE97EE0CULL,
		0xD8BB15EDF39C9191ULL,
		0x2AAA277A06239846ULL,
		0x64452ED8EB19A6FBULL,
		0xBBD5AF6A0CFEF82EULL,
		0xF4FB6C2D8E4D6776ULL,
		0x02923B738CDE01E6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x68A79495879D11B2ULL,
		0x479A10399D2FDC18ULL,
		0xB1762BDBE7392322ULL,
		0x55544EF40C47308DULL,
		0xC88A5DB1D6334DF6ULL,
		0x77AB5ED419FDF05CULL,
		0xE9F6D85B1C9ACEEDULL,
		0x052476E719BC03CDULL
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
		0x92BB70D0C7336165ULL,
		0xFB2010F9F1A43E44ULL,
		0x36D9662D68F53917ULL,
		0x466B083C3A6C43E2ULL,
		0x2834E68C7F5809B9ULL,
		0xB3495F6A47C392A8ULL,
		0x10ABD941DA034EB5ULL,
		0x2C6463B3711DDF38ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2576E1A18E66C2CAULL,
		0xF64021F3E3487C89ULL,
		0x6DB2CC5AD1EA722FULL,
		0x8CD6107874D887C4ULL,
		0x5069CD18FEB01372ULL,
		0x6692BED48F872550ULL,
		0x2157B283B4069D6BULL,
		0x58C8C766E23BBE70ULL
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
		0xE0F45DD6315BA397ULL,
		0x4D74DD9FDCB32A3AULL,
		0xADC31B53CCF3662AULL,
		0x8D1AA562C0D9245AULL,
		0xD0674DB368943C53ULL,
		0x801D9ED7D37A4DD0ULL,
		0x538A794CEBA3F607ULL,
		0x2251CE1B6EB2F9B3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC1E8BBAC62B7472EULL,
		0x9AE9BB3FB9665475ULL,
		0x5B8636A799E6CC54ULL,
		0x1A354AC581B248B5ULL,
		0xA0CE9B66D12878A7ULL,
		0x003B3DAFA6F49BA1ULL,
		0xA714F299D747EC0FULL,
		0x44A39C36DD65F366ULL
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
		0x99AB5A783D557984ULL,
		0x053A68AF8D9FC945ULL,
		0xDFAC461C998D095AULL,
		0xB72944CB30C1AD6DULL,
		0x520C540C471A220DULL,
		0x70C1A879BFD177A9ULL,
		0x02B840AF80AF9E9AULL,
		0x0E4E99C36F3F1242ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3356B4F07AAAF308ULL,
		0x0A74D15F1B3F928BULL,
		0xBF588C39331A12B4ULL,
		0x6E52899661835ADBULL,
		0xA418A8188E34441BULL,
		0xE18350F37FA2EF52ULL,
		0x0570815F015F3D34ULL,
		0x1C9D3386DE7E2484ULL
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
		0x8C4815E7F5376A22ULL,
		0xF174355E8DCC1D7BULL,
		0x09E7404A8B8EA8B6ULL,
		0x3DD7ABF727385B8AULL,
		0x7E69142D42AC4E82ULL,
		0x6098760551831A37ULL,
		0x0BA32BE7191A96D4ULL,
		0x0422B4116F833498ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x18902BCFEA6ED444ULL,
		0xE2E86ABD1B983AF7ULL,
		0x13CE8095171D516DULL,
		0x7BAF57EE4E70B714ULL,
		0xFCD2285A85589D04ULL,
		0xC130EC0AA306346EULL,
		0x174657CE32352DA8ULL,
		0x08456822DF066930ULL
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
		0xA123111F2F92B823ULL,
		0x992D6F985AA2F84DULL,
		0x1565676BB219D3EBULL,
		0xAEE656C89D47E065ULL,
		0xD283D4AF40EBF7F9ULL,
		0xE3348750CBEE60A8ULL,
		0x3CED56107179BA30ULL,
		0x0D34BD1B154C785BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4246223E5F257046ULL,
		0x325ADF30B545F09BULL,
		0x2ACACED76433A7D7ULL,
		0x5DCCAD913A8FC0CAULL,
		0xA507A95E81D7EFF3ULL,
		0xC6690EA197DCC151ULL,
		0x79DAAC20E2F37461ULL,
		0x1A697A362A98F0B6ULL
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
		0x519959ACAA2ACB37ULL,
		0x153AA7C18006886CULL,
		0xB53EEEFD0B2E9DDFULL,
		0x1E015DD51C727C57ULL,
		0x73C9B006FDB12BB4ULL,
		0x5D2E88CBED00EBC6ULL,
		0xF32ECEF417EC97A8ULL,
		0x3C67966CFDD94861ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA332B3595455966EULL,
		0x2A754F83000D10D8ULL,
		0x6A7DDDFA165D3BBEULL,
		0x3C02BBAA38E4F8AFULL,
		0xE793600DFB625768ULL,
		0xBA5D1197DA01D78CULL,
		0xE65D9DE82FD92F50ULL,
		0x78CF2CD9FBB290C3ULL
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
		0x4572F510798F2053ULL,
		0xB5981179E7F7B1CBULL,
		0xEB10BBB74E327ADEULL,
		0x8FCD849B923735FBULL,
		0x09BD4BE07256B1F4ULL,
		0xD60E038B570E0876ULL,
		0xAB8426F1416DDE4EULL,
		0x12DFC9DDF0CCC607ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8AE5EA20F31E40A6ULL,
		0x6B3022F3CFEF6396ULL,
		0xD621776E9C64F5BDULL,
		0x1F9B0937246E6BF7ULL,
		0x137A97C0E4AD63E9ULL,
		0xAC1C0716AE1C10ECULL,
		0x57084DE282DBBC9DULL,
		0x25BF93BBE1998C0FULL
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
		0x1D17A95368F2B905ULL,
		0x259EC52974D0A494ULL,
		0xF891AEFD1BC512B1ULL,
		0xF7A633E6C3198E6EULL,
		0x05F7F52497AB8CD7ULL,
		0x477C5DE7501681B2ULL,
		0x61E59C345FF00434ULL,
		0x347761316E15523FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3A2F52A6D1E5720AULL,
		0x4B3D8A52E9A14928ULL,
		0xF1235DFA378A2562ULL,
		0xEF4C67CD86331CDDULL,
		0x0BEFEA492F5719AFULL,
		0x8EF8BBCEA02D0364ULL,
		0xC3CB3868BFE00868ULL,
		0x68EEC262DC2AA47EULL
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
		0x3B39650B7B5FEB20ULL,
		0x724FB7D18B1E4068ULL,
		0x96392E91F3563BFFULL,
		0x40578ACDAFA0EDB4ULL,
		0x1A500585926B00ECULL,
		0x91BDB47D546C0032ULL,
		0x1F5DB69FE8F1CCB2ULL,
		0x37F81D1FCB520E3EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7672CA16F6BFD640ULL,
		0xE49F6FA3163C80D0ULL,
		0x2C725D23E6AC77FEULL,
		0x80AF159B5F41DB69ULL,
		0x34A00B0B24D601D8ULL,
		0x237B68FAA8D80064ULL,
		0x3EBB6D3FD1E39965ULL,
		0x6FF03A3F96A41C7CULL
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
		0xE67D6EFF669F2C55ULL,
		0xB18EBBDF3CE1DC0BULL,
		0x62A55D6E245A5244ULL,
		0x60581B7193684739ULL,
		0x53E2430A3D7A5C1FULL,
		0x80AA57D64F7337E4ULL,
		0x12A4639AAD8E1B3EULL,
		0x237BBC4DCD75B1BCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCCFADDFECD3E58AAULL,
		0x631D77BE79C3B817ULL,
		0xC54ABADC48B4A489ULL,
		0xC0B036E326D08E72ULL,
		0xA7C486147AF4B83EULL,
		0x0154AFAC9EE66FC8ULL,
		0x2548C7355B1C367DULL,
		0x46F7789B9AEB6378ULL
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
		0xEA17935FC8AB46F3ULL,
		0x45F1FF80313ABB0EULL,
		0x95E96E957B585925ULL,
		0x10C230DFA46FD1D5ULL,
		0x3DE2473C5FCD332AULL,
		0xAE46FDA036A9EF8FULL,
		0x60CD40E7F37ED2A3ULL,
		0x319BF8E2C5189F24ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD42F26BF91568DE6ULL,
		0x8BE3FF006275761DULL,
		0x2BD2DD2AF6B0B24AULL,
		0x218461BF48DFA3ABULL,
		0x7BC48E78BF9A6654ULL,
		0x5C8DFB406D53DF1EULL,
		0xC19A81CFE6FDA547ULL,
		0x6337F1C58A313E48ULL
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
		0x6B8F22393656652AULL,
		0xF09734764A346951ULL,
		0x8BEB5DDC59EECF91ULL,
		0xAFA0B59521BF909EULL,
		0x9669D2454E774279ULL,
		0x2DAAF2676D7D8BBCULL,
		0x40C11BF84EC2C8BCULL,
		0x0FC130D409C20583ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD71E44726CACCA54ULL,
		0xE12E68EC9468D2A2ULL,
		0x17D6BBB8B3DD9F23ULL,
		0x5F416B2A437F213DULL,
		0x2CD3A48A9CEE84F3ULL,
		0x5B55E4CEDAFB1779ULL,
		0x818237F09D859178ULL,
		0x1F8261A813840B06ULL
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
		0x594B62994EE95422ULL,
		0x9AA8E6B44F059BFDULL,
		0x9D2169BC87E6374AULL,
		0xD8AE290CC60A3A16ULL,
		0x5F5C253634D178D6ULL,
		0x7DD9F7BFBBCEBDDBULL,
		0xE963CC4F1DCAFBDAULL,
		0x37D22A44925A4E21ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB296C5329DD2A844ULL,
		0x3551CD689E0B37FAULL,
		0x3A42D3790FCC6E95ULL,
		0xB15C52198C14742DULL,
		0xBEB84A6C69A2F1ADULL,
		0xFBB3EF7F779D7BB6ULL,
		0xD2C7989E3B95F7B4ULL,
		0x6FA4548924B49C43ULL
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
		0x8F7DC5E9CD18BFAEULL,
		0xED63876BC61F9392ULL,
		0xFB8FFBA08E78CCC5ULL,
		0x4FFA099D4EA4E3C0ULL,
		0xD6CD402F7996B6DEULL,
		0xC945E15BB10B8973ULL,
		0x75AE0EDF8840E5EBULL,
		0x0E817EA08DF0E4A1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1EFB8BD39A317F5CULL,
		0xDAC70ED78C3F2725ULL,
		0xF71FF7411CF1998BULL,
		0x9FF4133A9D49C781ULL,
		0xAD9A805EF32D6DBCULL,
		0x928BC2B7621712E7ULL,
		0xEB5C1DBF1081CBD7ULL,
		0x1D02FD411BE1C942ULL
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
		0x1D298C0FBF1B8519ULL,
		0x228593D1D4EE1FA4ULL,
		0xAA91903D0512C4CCULL,
		0x15D129186077E45CULL,
		0xEF1DBB09D9E47094ULL,
		0x778F970A14D8A57BULL,
		0xAB18C9BCC1C19186ULL,
		0x1563F5E8DB5A0338ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3A53181F7E370A32ULL,
		0x450B27A3A9DC3F48ULL,
		0x5523207A0A258998ULL,
		0x2BA25230C0EFC8B9ULL,
		0xDE3B7613B3C8E128ULL,
		0xEF1F2E1429B14AF7ULL,
		0x563193798383230CULL,
		0x2AC7EBD1B6B40671ULL
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
		0xBB9CC8D145B3A9C4ULL,
		0xA7AAD2CF98A574AEULL,
		0x4D71856623F99154ULL,
		0x9858D657024C7D68ULL,
		0xA065B06DC527DC74ULL,
		0xEA0CF60493F9FE78ULL,
		0x2424F0DBBBF55F04ULL,
		0x2CCB5B36C1EA643DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x773991A28B675388ULL,
		0x4F55A59F314AE95DULL,
		0x9AE30ACC47F322A9ULL,
		0x30B1ACAE0498FAD0ULL,
		0x40CB60DB8A4FB8E9ULL,
		0xD419EC0927F3FCF1ULL,
		0x4849E1B777EABE09ULL,
		0x5996B66D83D4C87AULL
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
		0xF3B21505DFF7536EULL,
		0x25953E0C7213E347ULL,
		0x5E94F9905099B9A9ULL,
		0x8826EFB9420BA8A8ULL,
		0xB0376A1A5FFD1827ULL,
		0xB8C482A43EDB0DEEULL,
		0x58517777F9A1CA0FULL,
		0x2BA0DD96A94D6A7CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE7642A0BBFEEA6DCULL,
		0x4B2A7C18E427C68FULL,
		0xBD29F320A1337352ULL,
		0x104DDF7284175150ULL,
		0x606ED434BFFA304FULL,
		0x718905487DB61BDDULL,
		0xB0A2EEEFF343941FULL,
		0x5741BB2D529AD4F8ULL
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
		0x90D84D1AABD8B9FEULL,
		0x6053722AA7F29D30ULL,
		0x9A117319F55C5AEDULL,
		0xFFE55E404595BBC2ULL,
		0xCF6604351B1A95E3ULL,
		0xB4888D92FF94B2E6ULL,
		0x60E3870885CDEF15ULL,
		0x3968090680BEE478ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x21B09A3557B173FCULL,
		0xC0A6E4554FE53A61ULL,
		0x3422E633EAB8B5DAULL,
		0xFFCABC808B2B7785ULL,
		0x9ECC086A36352BC7ULL,
		0x69111B25FF2965CDULL,
		0xC1C70E110B9BDE2BULL,
		0x72D0120D017DC8F0ULL
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
		0xDDDF586149EA1C98ULL,
		0xC20BCFB8535B1F63ULL,
		0x5F0F788B3772289BULL,
		0x203832D0D38D489BULL,
		0x15D6CDCE6CC5162BULL,
		0x3A41527277DC5056ULL,
		0x1C4EFFE4BFB5B1A6ULL,
		0x12254FADC868545CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBBBEB0C293D43930ULL,
		0x84179F70A6B63EC7ULL,
		0xBE1EF1166EE45137ULL,
		0x407065A1A71A9136ULL,
		0x2BAD9B9CD98A2C56ULL,
		0x7482A4E4EFB8A0ACULL,
		0x389DFFC97F6B634CULL,
		0x244A9F5B90D0A8B8ULL
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
		0xA130F0A12113D5AEULL,
		0x2F4CACF0526B6265ULL,
		0xA51F1A0C65F0DD50ULL,
		0x16C4CBEB3D3345AAULL,
		0x7E6715ADA8C0A9CAULL,
		0xE94E0DB194895D5DULL,
		0x1739C8FE6340ADDDULL,
		0x3362100209B1FB78ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4261E1424227AB5CULL,
		0x5E9959E0A4D6C4CBULL,
		0x4A3E3418CBE1BAA0ULL,
		0x2D8997D67A668B55ULL,
		0xFCCE2B5B51815394ULL,
		0xD29C1B632912BABAULL,
		0x2E7391FCC6815BBBULL,
		0x66C420041363F6F0ULL
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
		0x38F818B09ED81036ULL,
		0x4AF93AA1E339CB28ULL,
		0xA83F1B33289EB010ULL,
		0x85FB7CEA3033598FULL,
		0xD08BE3875EA7ABB7ULL,
		0xA41349FBE9EABA1AULL,
		0x75AB0C48CE8A635FULL,
		0x3CBBBC4B9E732025ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x71F031613DB0206CULL,
		0x95F27543C6739650ULL,
		0x507E3666513D6020ULL,
		0x0BF6F9D46066B31FULL,
		0xA117C70EBD4F576FULL,
		0x482693F7D3D57435ULL,
		0xEB5618919D14C6BFULL,
		0x797778973CE6404AULL
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
		0xF83FCD695A205524ULL,
		0x1C6CC7444411412DULL,
		0x16C28374ECA61D29ULL,
		0x2A7C7112AB168D03ULL,
		0x01BBEDC5FEB37BFAULL,
		0xB8664CDA6322934AULL,
		0xDABA7A067016E527ULL,
		0x0FCDAEEA31B3C179ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF07F9AD2B440AA48ULL,
		0x38D98E888822825BULL,
		0x2D8506E9D94C3A52ULL,
		0x54F8E225562D1A06ULL,
		0x0377DB8BFD66F7F4ULL,
		0x70CC99B4C6452694ULL,
		0xB574F40CE02DCA4FULL,
		0x1F9B5DD4636782F3ULL
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
		0x387E38469CB1185BULL,
		0x7ECBFF9B588D9E1CULL,
		0x2ED1962C9104E6B0ULL,
		0x45A8D5CFB28EFF85ULL,
		0x9DE0003D337E450AULL,
		0x8FB0FC276083A945ULL,
		0x384AB8CE6744327FULL,
		0x3832CEA45F2FEC3AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x70FC708D396230B6ULL,
		0xFD97FF36B11B3C38ULL,
		0x5DA32C592209CD60ULL,
		0x8B51AB9F651DFF0AULL,
		0x3BC0007A66FC8A14ULL,
		0x1F61F84EC107528BULL,
		0x7095719CCE8864FFULL,
		0x70659D48BE5FD874ULL
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
		0x537DAF4C143599ABULL,
		0x3D611235769B817AULL,
		0x24469B10A910260BULL,
		0x7B1E57A8F4B83AECULL,
		0x08FE925182C828C0ULL,
		0xFF3FB84F5B60A333ULL,
		0x32405D48CECA284EULL,
		0x3565CFB471E39778ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA6FB5E98286B3356ULL,
		0x7AC2246AED3702F4ULL,
		0x488D362152204C16ULL,
		0xF63CAF51E97075D8ULL,
		0x11FD24A305905180ULL,
		0xFE7F709EB6C14666ULL,
		0x6480BA919D94509DULL,
		0x6ACB9F68E3C72EF0ULL
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
		0x9DAFF44B202AF0ABULL,
		0x5F24F54257EA52CBULL,
		0xCBA148FCE3E14432ULL,
		0x428F819A8DCB82AFULL,
		0x43134A1087D5CD45ULL,
		0x9DAB2117D17FBBF9ULL,
		0x9E8A93E9DA2ACE26ULL,
		0x041130E22930EF17ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3B5FE8964055E156ULL,
		0xBE49EA84AFD4A597ULL,
		0x974291F9C7C28864ULL,
		0x851F03351B97055FULL,
		0x862694210FAB9A8AULL,
		0x3B56422FA2FF77F2ULL,
		0x3D1527D3B4559C4DULL,
		0x082261C45261DE2FULL
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
		0x4AAC329CDC530C93ULL,
		0x51FFCF2069DAEE0EULL,
		0x8311A7832D0A8434ULL,
		0xB0D1D5511828F039ULL,
		0x44A167365A7F4A06ULL,
		0x06B6D2A4C991BF2BULL,
		0xD8DDE384FA3DC0E0ULL,
		0x059CB2E9F6E11AA4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x95586539B8A61926ULL,
		0xA3FF9E40D3B5DC1CULL,
		0x06234F065A150868ULL,
		0x61A3AAA23051E073ULL,
		0x8942CE6CB4FE940DULL,
		0x0D6DA54993237E56ULL,
		0xB1BBC709F47B81C0ULL,
		0x0B3965D3EDC23549ULL
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
		0xF4F0D931F5E9D5B3ULL,
		0xC2115BF1F3C4A31CULL,
		0x5AC73FC64C6CAA84ULL,
		0x1031184C9A63F6B4ULL,
		0x4C62CBE04CE9178BULL,
		0xD9B735BAC40FEBE7ULL,
		0xAC9A990A6D507A58ULL,
		0x2ABD8333ED9B8B27ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE9E1B263EBD3AB66ULL,
		0x8422B7E3E7894639ULL,
		0xB58E7F8C98D95509ULL,
		0x2062309934C7ED68ULL,
		0x98C597C099D22F16ULL,
		0xB36E6B75881FD7CEULL,
		0x59353214DAA0F4B1ULL,
		0x557B0667DB37164FULL
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
		0x08FA7FB0144A86C7ULL,
		0x1FDE5D00A53A2508ULL,
		0x1BF21B9F188B99E4ULL,
		0xA42D4F07E6042972ULL,
		0x14C201C3C7963146ULL,
		0x0E4D7C05E71D7ECCULL,
		0xD56F8E6463D9FAD1ULL,
		0x3662EA10ABDE9BC7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x11F4FF6028950D8EULL,
		0x3FBCBA014A744A10ULL,
		0x37E4373E311733C8ULL,
		0x485A9E0FCC0852E4ULL,
		0x298403878F2C628DULL,
		0x1C9AF80BCE3AFD98ULL,
		0xAADF1CC8C7B3F5A2ULL,
		0x6CC5D42157BD378FULL
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
		0x6BE146B50DA1884DULL,
		0x6001F68C81F2BEB8ULL,
		0x1832C1345078F7A8ULL,
		0x1A97750F27E811E6ULL,
		0xB1AD5770A8A14F7CULL,
		0x0DA18070E6F13BD9ULL,
		0x4DCCA331FC257524ULL,
		0x03B6FC4F6AAA22FBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD7C28D6A1B43109AULL,
		0xC003ED1903E57D70ULL,
		0x30658268A0F1EF50ULL,
		0x352EEA1E4FD023CCULL,
		0x635AAEE151429EF8ULL,
		0x1B4300E1CDE277B3ULL,
		0x9B994663F84AEA48ULL,
		0x076DF89ED55445F6ULL
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
		0x84FA67F045BE0A63ULL,
		0x1332BF3B69FA5C0AULL,
		0xF9721C3E4063F5BAULL,
		0x0FBEFEAE6717C4CBULL,
		0x47ED5D3FBCC3CAA6ULL,
		0xBACA498C50D8ED52ULL,
		0x438EF74BA0BF62D2ULL,
		0x0F14C971FD3B305EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x09F4CFE08B7C14C6ULL,
		0x26657E76D3F4B815ULL,
		0xF2E4387C80C7EB74ULL,
		0x1F7DFD5CCE2F8997ULL,
		0x8FDABA7F7987954CULL,
		0x75949318A1B1DAA4ULL,
		0x871DEE97417EC5A5ULL,
		0x1E2992E3FA7660BCULL
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
		0x2368239F4BFBFE31ULL,
		0xE907C73A265E7801ULL,
		0xAC003E581490B9A5ULL,
		0x84676347C0330697ULL,
		0xF5D89CF0E3BD11FDULL,
		0x97D1C3BB9A0DAA15ULL,
		0x920E600585B06FFBULL,
		0x3C6F3846DAB36DECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x46D0473E97F7FC62ULL,
		0xD20F8E744CBCF002ULL,
		0x58007CB02921734BULL,
		0x08CEC68F80660D2FULL,
		0xEBB139E1C77A23FBULL,
		0x2FA38777341B542BULL,
		0x241CC00B0B60DFF7ULL,
		0x78DE708DB566DBD9ULL
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
		0x599C3B8EFAA49826ULL,
		0x553C565D7C5761E6ULL,
		0x43E706F213D3E617ULL,
		0x55D73F928836EE57ULL,
		0x76C4DFAA0188CDBBULL,
		0xA24E42C324DC16FFULL,
		0xF8C29DFA8FABB988ULL,
		0x1AACDC6676A850F5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB338771DF549304CULL,
		0xAA78ACBAF8AEC3CCULL,
		0x87CE0DE427A7CC2EULL,
		0xABAE7F25106DDCAEULL,
		0xED89BF5403119B76ULL,
		0x449C858649B82DFEULL,
		0xF1853BF51F577311ULL,
		0x3559B8CCED50A1EBULL
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
		0x3419AD7EEA89A3B8ULL,
		0x01F12C1CB194091DULL,
		0x85DDCC50A4FFEECCULL,
		0x33B10AE4B296B2D4ULL,
		0xE1E70405344F2D60ULL,
		0xB37DDBC22CB6E7A5ULL,
		0x877864873905D168ULL,
		0x066819DF3191D654ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x68335AFDD5134770ULL,
		0x03E258396328123AULL,
		0x0BBB98A149FFDD98ULL,
		0x676215C9652D65A9ULL,
		0xC3CE080A689E5AC0ULL,
		0x66FBB784596DCF4BULL,
		0x0EF0C90E720BA2D1ULL,
		0x0CD033BE6323ACA9ULL
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
		0x3329DD17A693E767ULL,
		0x7A596756C84017F9ULL,
		0x2953C51F49A1B988ULL,
		0x0C4E08C4C2B63483ULL,
		0xC5EDD0465A58928FULL,
		0xDB20761D448C1AA7ULL,
		0x463F5E4616EF9616ULL,
		0x250DA3463B56A589ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6653BA2F4D27CECEULL,
		0xF4B2CEAD90802FF2ULL,
		0x52A78A3E93437310ULL,
		0x189C1189856C6906ULL,
		0x8BDBA08CB4B1251EULL,
		0xB640EC3A8918354FULL,
		0x8C7EBC8C2DDF2C2DULL,
		0x4A1B468C76AD4B12ULL
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
		0xE3292633B39B5CD1ULL,
		0xBCD42F9FFA493653ULL,
		0xE11F1F473454C516ULL,
		0x2402C7EA01337945ULL,
		0x3F657197E3578FFFULL,
		0xC4D3935320C38C07ULL,
		0x22AB57CD97F11F1FULL,
		0x1CB6175250329598ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC6524C676736B9A2ULL,
		0x79A85F3FF4926CA7ULL,
		0xC23E3E8E68A98A2DULL,
		0x48058FD40266F28BULL,
		0x7ECAE32FC6AF1FFEULL,
		0x89A726A64187180EULL,
		0x4556AF9B2FE23E3FULL,
		0x396C2EA4A0652B30ULL
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
		0xA9B44BDD2242096FULL,
		0x17B25A8B198579AFULL,
		0x9E4EFF6D3A5D861CULL,
		0x7B52F07BCFB2126EULL,
		0x67B6E09F33E9745DULL,
		0xB8A3F35EB7701F7FULL,
		0x58F16420976F668BULL,
		0x1EEBB5E6BBA5E4B9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x536897BA448412DEULL,
		0x2F64B516330AF35FULL,
		0x3C9DFEDA74BB0C38ULL,
		0xF6A5E0F79F6424DDULL,
		0xCF6DC13E67D2E8BAULL,
		0x7147E6BD6EE03EFEULL,
		0xB1E2C8412EDECD17ULL,
		0x3DD76BCD774BC972ULL
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
		0xD930D45D2D882459ULL,
		0x1381D5E106772CC9ULL,
		0xAEF4496825667808ULL,
		0xF8339637A38DE1D3ULL,
		0xD64539FDA9EE8143ULL,
		0x71A5A3BD78F8E5D0ULL,
		0xB1CB92CBE2C412E2ULL,
		0x397089400C0A6CA6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB261A8BA5B1048B2ULL,
		0x2703ABC20CEE5993ULL,
		0x5DE892D04ACCF010ULL,
		0xF0672C6F471BC3A7ULL,
		0xAC8A73FB53DD0287ULL,
		0xE34B477AF1F1CBA1ULL,
		0x63972597C58825C4ULL,
		0x72E112801814D94DULL
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
		0x57C971F7F6AA79E5ULL,
		0x53B6F4A47B3654CAULL,
		0xD2A133E0CAA27491ULL,
		0xA30D9FCCA71EBDB9ULL,
		0x0B85D50E9FAA2980ULL,
		0x0FA223B7DF91D83DULL,
		0x48176C34F0D769FFULL,
		0x3D33DC96EC91D574ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF92E3EFED54F3CAULL,
		0xA76DE948F66CA994ULL,
		0xA54267C19544E922ULL,
		0x461B3F994E3D7B73ULL,
		0x170BAA1D3F545301ULL,
		0x1F44476FBF23B07AULL,
		0x902ED869E1AED3FEULL,
		0x7A67B92DD923AAE8ULL
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
		0x49A5EAB479032CFEULL,
		0x011C269436874AEBULL,
		0xAA20D0DE071213C5ULL,
		0x56528A00BBCFAE90ULL,
		0xDF8D5ABFE53C5DB6ULL,
		0xA75DAB1CC3B7F192ULL,
		0xE82B65CDDBAAA077ULL,
		0x2F00DDEE823FF155ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x934BD568F20659FCULL,
		0x02384D286D0E95D6ULL,
		0x5441A1BC0E24278AULL,
		0xACA51401779F5D21ULL,
		0xBF1AB57FCA78BB6CULL,
		0x4EBB5639876FE325ULL,
		0xD056CB9BB75540EFULL,
		0x5E01BBDD047FE2ABULL
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
		0x6964021DCA023174ULL,
		0x2CFE3CE424C2F5F3ULL,
		0xA57D5292A9BEFB55ULL,
		0xCDF78EFC6FA6F0ACULL,
		0xBEFA9968A58E0D6DULL,
		0xA8F1E7FF545939AFULL,
		0xF1EDF8023216ECEEULL,
		0x20469662BFF1D0E8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD2C8043B940462E8ULL,
		0x59FC79C84985EBE6ULL,
		0x4AFAA525537DF6AAULL,
		0x9BEF1DF8DF4DE159ULL,
		0x7DF532D14B1C1ADBULL,
		0x51E3CFFEA8B2735FULL,
		0xE3DBF004642DD9DDULL,
		0x408D2CC57FE3A1D1ULL
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
		0x83E019A6A44043DFULL,
		0xCDD2E1FF561D5914ULL,
		0x7636C41F3EC95B6EULL,
		0x3963B97C003D2168ULL,
		0x5F0DBAE87581350BULL,
		0x897C0C10C629C6A2ULL,
		0xD62C6EE9094C85FCULL,
		0x1616435E305C7A56ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x07C0334D488087BEULL,
		0x9BA5C3FEAC3AB229ULL,
		0xEC6D883E7D92B6DDULL,
		0x72C772F8007A42D0ULL,
		0xBE1B75D0EB026A16ULL,
		0x12F818218C538D44ULL,
		0xAC58DDD212990BF9ULL,
		0x2C2C86BC60B8F4ADULL
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
		0xCD31ABD5410ECDAFULL,
		0xF79245EDB74EB259ULL,
		0x0A6FAB3306591923ULL,
		0x4AEEC458FB48B0E5ULL,
		0x0B745E09708520C5ULL,
		0x21D00E864B7D9EB7ULL,
		0xDDB660A97909CFB8ULL,
		0x16C53CF75F9DD919ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9A6357AA821D9B5EULL,
		0xEF248BDB6E9D64B3ULL,
		0x14DF56660CB23247ULL,
		0x95DD88B1F69161CAULL,
		0x16E8BC12E10A418AULL,
		0x43A01D0C96FB3D6EULL,
		0xBB6CC152F2139F70ULL,
		0x2D8A79EEBF3BB233ULL
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
		0x7432B3382DF96332ULL,
		0x84D9DA796BFC35D5ULL,
		0x8E77857BEEDEEA23ULL,
		0x262CED6977320181ULL,
		0x84FE8BC800610F3BULL,
		0x8C67FFCDF791519FULL,
		0xCB292E5A5CA79975ULL,
		0x1649551165921CC6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE86566705BF2C664ULL,
		0x09B3B4F2D7F86BAAULL,
		0x1CEF0AF7DDBDD447ULL,
		0x4C59DAD2EE640303ULL,
		0x09FD179000C21E76ULL,
		0x18CFFF9BEF22A33FULL,
		0x96525CB4B94F32EBULL,
		0x2C92AA22CB24398DULL
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
		0xFEF7BC97388A570BULL,
		0xEE91A65ED4ACE2C3ULL,
		0x387333BB398B207CULL,
		0xE851A9DE5C583B50ULL,
		0x4924D2AEB3450A3DULL,
		0x2F81F18879BC2CE9ULL,
		0xB364AB39C4466CC9ULL,
		0x168DD87BBEDA95ACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFDEF792E7114AE16ULL,
		0xDD234CBDA959C587ULL,
		0x70E66776731640F9ULL,
		0xD0A353BCB8B076A0ULL,
		0x9249A55D668A147BULL,
		0x5F03E310F37859D2ULL,
		0x66C95673888CD992ULL,
		0x2D1BB0F77DB52B59ULL
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
		0xFE8B5DC4C5280087ULL,
		0x925C179B690F6015ULL,
		0x743AF4B460A4EB7CULL,
		0x4DEBC4DEBB084BD3ULL,
		0xCA659888EC6C1070ULL,
		0x37375936DA625B06ULL,
		0x8EAC7176AA3D0A9FULL,
		0x02DB82874AAB934FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFD16BB898A50010EULL,
		0x24B82F36D21EC02BULL,
		0xE875E968C149D6F9ULL,
		0x9BD789BD761097A6ULL,
		0x94CB3111D8D820E0ULL,
		0x6E6EB26DB4C4B60DULL,
		0x1D58E2ED547A153EULL,
		0x05B7050E9557269FULL
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
		0x7DAF8DB0CB91C00DULL,
		0x50F407D2A12FCEF3ULL,
		0x9A898D6A7AFFDA66ULL,
		0x66DD00EDD8652BF6ULL,
		0x298150E91ADD20F2ULL,
		0xDB86EC3BB6581C75ULL,
		0x948D4AF19F9732BFULL,
		0x1099ADC9D78E58EFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFB5F1B619723801AULL,
		0xA1E80FA5425F9DE6ULL,
		0x35131AD4F5FFB4CCULL,
		0xCDBA01DBB0CA57EDULL,
		0x5302A1D235BA41E4ULL,
		0xB70DD8776CB038EAULL,
		0x291A95E33F2E657FULL,
		0x21335B93AF1CB1DFULL
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
		0xDB459A17C6399586ULL,
		0x06F4D7CE1910CF9CULL,
		0xCE02E1AC51556801ULL,
		0x01957E483FF90559ULL,
		0x6950833E878A02A9ULL,
		0xF48F64B4131128D0ULL,
		0xBEDA0B638D2CEC51ULL,
		0x32FA27E86848ECDFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB68B342F8C732B0CULL,
		0x0DE9AF9C32219F39ULL,
		0x9C05C358A2AAD002ULL,
		0x032AFC907FF20AB3ULL,
		0xD2A1067D0F140552ULL,
		0xE91EC968262251A0ULL,
		0x7DB416C71A59D8A3ULL,
		0x65F44FD0D091D9BFULL
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
		0xBCEFCD9C07487560ULL,
		0x93677446126DE0ACULL,
		0x44A542EE5862278AULL,
		0xACC6DA23697B4FBBULL,
		0x1A98605C92678E1AULL,
		0x7161428643FCD7A1ULL,
		0x1F40FFE8C4FC8DEFULL,
		0x0BB2EACB7E3EEA10ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x79DF9B380E90EAC0ULL,
		0x26CEE88C24DBC159ULL,
		0x894A85DCB0C44F15ULL,
		0x598DB446D2F69F76ULL,
		0x3530C0B924CF1C35ULL,
		0xE2C2850C87F9AF42ULL,
		0x3E81FFD189F91BDEULL,
		0x1765D596FC7DD420ULL
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
		0x074A2FD7E08E5113ULL,
		0x4E681A84C2FB6B3FULL,
		0xBD1A9BFF3B0AE318ULL,
		0x8661B07B74A165F1ULL,
		0x45912338360A7DFBULL,
		0x099A4D6B3B655384ULL,
		0xF3E6B4B7F1E4C827ULL,
		0x2C062E32304A039BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0E945FAFC11CA226ULL,
		0x9CD0350985F6D67EULL,
		0x7A3537FE7615C630ULL,
		0x0CC360F6E942CBE3ULL,
		0x8B2246706C14FBF7ULL,
		0x13349AD676CAA708ULL,
		0xE7CD696FE3C9904EULL,
		0x580C5C6460940737ULL
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
		0x28078035247EF615ULL,
		0xDF0D9C4CBEB07166ULL,
		0xE0E65F595B3B8B49ULL,
		0xAB00F12E64AD90B2ULL,
		0x3658210F8D24CE95ULL,
		0x4DE901E3ABD58302ULL,
		0xEA0992D93768B88BULL,
		0x046EDFA862BFFD98ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x500F006A48FDEC2AULL,
		0xBE1B38997D60E2CCULL,
		0xC1CCBEB2B6771693ULL,
		0x5601E25CC95B2165ULL,
		0x6CB0421F1A499D2BULL,
		0x9BD203C757AB0604ULL,
		0xD41325B26ED17116ULL,
		0x08DDBF50C57FFB31ULL
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
		0xFB98BC583AC0D441ULL,
		0x0422EF0F8D3B5AD6ULL,
		0x30B12409B31E38C5ULL,
		0xFBF49E5ECE6E90E4ULL,
		0x24E4C5F1EC0222B3ULL,
		0x6C3C9CB1D245816CULL,
		0xAA625B06248825E3ULL,
		0x3C27346ED2E63CADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF73178B07581A882ULL,
		0x0845DE1F1A76B5ADULL,
		0x61624813663C718AULL,
		0xF7E93CBD9CDD21C8ULL,
		0x49C98BE3D8044567ULL,
		0xD8793963A48B02D8ULL,
		0x54C4B60C49104BC6ULL,
		0x784E68DDA5CC795BULL
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
		0xD03847FD3609CCD7ULL,
		0x8C2AB595BDEB5686ULL,
		0xAD8C01AE1076FA62ULL,
		0x20AA8C62D932B056ULL,
		0x72CE5C10C0B8E31FULL,
		0x71529123CFFB60D5ULL,
		0x4943C512F7D934D2ULL,
		0x03904A0B2D0C743CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA0708FFA6C1399AEULL,
		0x18556B2B7BD6AD0DULL,
		0x5B18035C20EDF4C5ULL,
		0x415518C5B26560ADULL,
		0xE59CB8218171C63EULL,
		0xE2A522479FF6C1AAULL,
		0x92878A25EFB269A4ULL,
		0x072094165A18E878ULL
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
		0xB8B4E17E7A4B4B71ULL,
		0xA0C6CCAB271F613EULL,
		0x7B6ACCAD7115A3B0ULL,
		0x1C8898F7C3ACF680ULL,
		0x7769F6287F633A40ULL,
		0xA2DFA63AEE17D85DULL,
		0x00CD22AB2E78D751ULL,
		0x2B9DEA39E52F4101ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7169C2FCF49696E2ULL,
		0x418D99564E3EC27DULL,
		0xF6D5995AE22B4761ULL,
		0x391131EF8759ED00ULL,
		0xEED3EC50FEC67480ULL,
		0x45BF4C75DC2FB0BAULL,
		0x019A45565CF1AEA3ULL,
		0x573BD473CA5E8202ULL
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
		0xA1A7E93C0D8CE846ULL,
		0x179CD19EBDF03335ULL,
		0xECCCDCD95EBD03AEULL,
		0x21E2363D7415A5E8ULL,
		0xF2FBB69D363552EEULL,
		0x61339139112DB1B7ULL,
		0x1A05494F18029DEBULL,
		0x3217498AB721E422ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x434FD2781B19D08CULL,
		0x2F39A33D7BE0666BULL,
		0xD999B9B2BD7A075CULL,
		0x43C46C7AE82B4BD1ULL,
		0xE5F76D3A6C6AA5DCULL,
		0xC2672272225B636FULL,
		0x340A929E30053BD6ULL,
		0x642E93156E43C844ULL
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
		0x70D24BA33756B737ULL,
		0xE971218F296C6746ULL,
		0x264D273D88A309A2ULL,
		0xA1F5E77FC5DEAB9CULL,
		0xE6150168F82336A0ULL,
		0x64D800A834A908C4ULL,
		0x6E1DF74C2959AF14ULL,
		0x11F53D6645B69BABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE1A497466EAD6E6EULL,
		0xD2E2431E52D8CE8CULL,
		0x4C9A4E7B11461345ULL,
		0x43EBCEFF8BBD5738ULL,
		0xCC2A02D1F0466D41ULL,
		0xC9B0015069521189ULL,
		0xDC3BEE9852B35E28ULL,
		0x23EA7ACC8B6D3756ULL
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
		0x5418192F23C0CA6FULL,
		0xA996B5C7101C29D7ULL,
		0x263697DB7E54DD56ULL,
		0xBA0E1093D7074710ULL,
		0x0336CE9F7F26E5E3ULL,
		0xE6AB13F4188B83CBULL,
		0xDF92325B451C85E2ULL,
		0x18D48578DC7FE390ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA830325E478194DEULL,
		0x532D6B8E203853AEULL,
		0x4C6D2FB6FCA9BAADULL,
		0x741C2127AE0E8E20ULL,
		0x066D9D3EFE4DCBC7ULL,
		0xCD5627E831170796ULL,
		0xBF2464B68A390BC5ULL,
		0x31A90AF1B8FFC721ULL
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
		0x4FFDB6673DC92520ULL,
		0xAD331C5D27E2547EULL,
		0x2DE22D88D80F77B9ULL,
		0xFF7D1BD0BD88FDF8ULL,
		0x2C82312C8975E64DULL,
		0x0EF4F22DD8EB7BC9ULL,
		0xD0BCDAF6832909A5ULL,
		0x23CFD1CAAB2E71EEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9FFB6CCE7B924A40ULL,
		0x5A6638BA4FC4A8FCULL,
		0x5BC45B11B01EEF73ULL,
		0xFEFA37A17B11FBF0ULL,
		0x5904625912EBCC9BULL,
		0x1DE9E45BB1D6F792ULL,
		0xA179B5ED0652134AULL,
		0x479FA395565CE3DDULL
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
		0xAF90E6DC4911FCDFULL,
		0x17E23FB23E412BCAULL,
		0x52EBB427987597DAULL,
		0xF8A7D23A28FABF2BULL,
		0x578C5735E3466DEBULL,
		0xA3E5F1F01684D5D3ULL,
		0xA54EEC3F53DCB5ABULL,
		0x3E037D6B6F72A6F5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5F21CDB89223F9BEULL,
		0x2FC47F647C825795ULL,
		0xA5D7684F30EB2FB4ULL,
		0xF14FA47451F57E56ULL,
		0xAF18AE6BC68CDBD7ULL,
		0x47CBE3E02D09ABA6ULL,
		0x4A9DD87EA7B96B57ULL,
		0x7C06FAD6DEE54DEBULL
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
		0x788DD7CF917803C1ULL,
		0x0E768C0F70E95008ULL,
		0x7875F8B8F64363DAULL,
		0x1D98C94ED2487433ULL,
		0x610BFCAC9F8E4643ULL,
		0x66F509101ABCB27AULL,
		0xDD1A361B4858C7D6ULL,
		0x32585A62982CE6CCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF11BAF9F22F00782ULL,
		0x1CED181EE1D2A010ULL,
		0xF0EBF171EC86C7B4ULL,
		0x3B31929DA490E866ULL,
		0xC217F9593F1C8C86ULL,
		0xCDEA1220357964F4ULL,
		0xBA346C3690B18FACULL,
		0x64B0B4C53059CD99ULL
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
		0xE7E1ED2793A15CF2ULL,
		0xD729B7F8CCD25F74ULL,
		0xDBC63A4841355708ULL,
		0xA2D4E2AA5B311BA0ULL,
		0xCEA7A33F145D0C4DULL,
		0xB4253E727521A9ADULL,
		0xE65A12A0B594B7FDULL,
		0x0BCE60C2D62ECC5AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCFC3DA4F2742B9E4ULL,
		0xAE536FF199A4BEE9ULL,
		0xB78C7490826AAE11ULL,
		0x45A9C554B6623741ULL,
		0x9D4F467E28BA189BULL,
		0x684A7CE4EA43535BULL,
		0xCCB425416B296FFBULL,
		0x179CC185AC5D98B5ULL
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
		0x1E113F95DB63F939ULL,
		0xB9E299708435D35CULL,
		0x83D51E0798B5F889ULL,
		0x34D9C6C96EF9B14BULL,
		0x7FBA3008589AAF56ULL,
		0xBDECED6832C98677ULL,
		0xF86F91C584A7B617ULL,
		0x2808C15A1472EA31ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3C227F2BB6C7F272ULL,
		0x73C532E1086BA6B8ULL,
		0x07AA3C0F316BF113ULL,
		0x69B38D92DDF36297ULL,
		0xFF746010B1355EACULL,
		0x7BD9DAD065930CEEULL,
		0xF0DF238B094F6C2FULL,
		0x501182B428E5D463ULL
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
		0x83793FCCB07927A7ULL,
		0x06D6083FB9255B46ULL,
		0xF8D3FA1075068063ULL,
		0xFD627F60B5A216E5ULL,
		0xC71C10993E443EB4ULL,
		0x30290F973FDB1488ULL,
		0xB26A9F35C52039DCULL,
		0x26AD5F6B7B331C4BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x06F27F9960F24F4EULL,
		0x0DAC107F724AB68DULL,
		0xF1A7F420EA0D00C6ULL,
		0xFAC4FEC16B442DCBULL,
		0x8E3821327C887D69ULL,
		0x60521F2E7FB62911ULL,
		0x64D53E6B8A4073B8ULL,
		0x4D5ABED6F6663897ULL
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
		0x5FE41908D8B8571FULL,
		0xBC5571C2F2FFBE9DULL,
		0xBC40D2B9C2D177F1ULL,
		0xE528CC29CA2C66E2ULL,
		0x86C68E141D1B3701ULL,
		0x0747D41FF4F9DA54ULL,
		0xF236E450E59557D5ULL,
		0x253D1C0E57E6B22EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBFC83211B170AE3EULL,
		0x78AAE385E5FF7D3AULL,
		0x7881A57385A2EFE3ULL,
		0xCA5198539458CDC5ULL,
		0x0D8D1C283A366E03ULL,
		0x0E8FA83FE9F3B4A9ULL,
		0xE46DC8A1CB2AAFAAULL,
		0x4A7A381CAFCD645DULL
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
		0xFD3B7F1F4A813B7EULL,
		0xBD7B8BF853DAF1BCULL,
		0x674F17FEEA5FDDE0ULL,
		0xFE40AD062061D202ULL,
		0x125EF61448C8ED38ULL,
		0x2AB2B22694D795ECULL,
		0xF6BE477C027A93ABULL,
		0x0CAA997E4908F29FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFA76FE3E950276FCULL,
		0x7AF717F0A7B5E379ULL,
		0xCE9E2FFDD4BFBBC1ULL,
		0xFC815A0C40C3A404ULL,
		0x24BDEC289191DA71ULL,
		0x5565644D29AF2BD8ULL,
		0xED7C8EF804F52756ULL,
		0x195532FC9211E53FULL
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
		0xE9716C1E7E955F6CULL,
		0x393D1BCCA83C1DE6ULL,
		0xA3D4D3FDE8FEDFABULL,
		0x099FBC6947F6AF41ULL,
		0xC6DD25AF4FB48547ULL,
		0x0677DED934987108ULL,
		0xECAF8D110349BF4AULL,
		0x121BB6BF1D741E77ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD2E2D83CFD2ABED8ULL,
		0x727A379950783BCDULL,
		0x47A9A7FBD1FDBF56ULL,
		0x133F78D28FED5E83ULL,
		0x8DBA4B5E9F690A8EULL,
		0x0CEFBDB26930E211ULL,
		0xD95F1A2206937E94ULL,
		0x24376D7E3AE83CEFULL
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
		0x46070F23DD3B1596ULL,
		0xBF78F784A49B0C43ULL,
		0xCFF47E5EB7136205ULL,
		0x4EB1B682B5AFF09DULL,
		0xF5B66F05ABAC8513ULL,
		0xA19E5F99339C5C84ULL,
		0xC7195FC46B2A0A7FULL,
		0x1AFBB48FF5FD9FF1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8C0E1E47BA762B2CULL,
		0x7EF1EF0949361886ULL,
		0x9FE8FCBD6E26C40BULL,
		0x9D636D056B5FE13BULL,
		0xEB6CDE0B57590A26ULL,
		0x433CBF326738B909ULL,
		0x8E32BF88D65414FFULL,
		0x35F7691FEBFB3FE3ULL
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
		0x4AC5AF244F4A4E9EULL,
		0x8FDDC8779D593C53ULL,
		0x8F715F9CF60851E9ULL,
		0x4136A729ACC17DACULL,
		0x38FDDE58C3782959ULL,
		0x46EEECF01B5E9600ULL,
		0x3CCB2D3BDEB6B949ULL,
		0x22E4D4BE776F818EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x958B5E489E949D3CULL,
		0x1FBB90EF3AB278A6ULL,
		0x1EE2BF39EC10A3D3ULL,
		0x826D4E535982FB59ULL,
		0x71FBBCB186F052B2ULL,
		0x8DDDD9E036BD2C00ULL,
		0x79965A77BD6D7292ULL,
		0x45C9A97CEEDF031CULL
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
		0xD0D2E75505A169DFULL,
		0xDFF5C083967C70A2ULL,
		0xBC033A47980AC8CBULL,
		0x78F0ED978CA0F34DULL,
		0x197C06C0CB5C0C70ULL,
		0x9B2CF5FE401EABCEULL,
		0x67E6846D3FEA1831ULL,
		0x28704A957FD64FC4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA1A5CEAA0B42D3BEULL,
		0xBFEB81072CF8E145ULL,
		0x7806748F30159197ULL,
		0xF1E1DB2F1941E69BULL,
		0x32F80D8196B818E0ULL,
		0x3659EBFC803D579CULL,
		0xCFCD08DA7FD43063ULL,
		0x50E0952AFFAC9F88ULL
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
		0xF3DE1E6E83997DCFULL,
		0x69AF3AD8889CE36AULL,
		0x978332B324348262ULL,
		0x6C0FA7C25E0402B2ULL,
		0x0A89BDFB250765C4ULL,
		0x5D54728A29D26E20ULL,
		0xD5252666D5CDC303ULL,
		0x069DD11EF95FA6E1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE7BC3CDD0732FB9EULL,
		0xD35E75B11139C6D5ULL,
		0x2F066566486904C4ULL,
		0xD81F4F84BC080565ULL,
		0x15137BF64A0ECB88ULL,
		0xBAA8E51453A4DC40ULL,
		0xAA4A4CCDAB9B8606ULL,
		0x0D3BA23DF2BF4DC3ULL
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