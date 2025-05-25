#include "../tests.h"

int32_t curve25519_key_and_test(void) {
	printf("Key AND Test\n");
	curve25519_key_t k1 = {.key64 = {
		0xF14D6103289DF44CULL,
		0xA021F099BB760866ULL,
		0x13DE031BD4DCFDBCULL,
		0xC9362995451DEF94ULL,
		0x3BE2F7757DAA9CE3ULL,
		0x0A9D1FCA9961210BULL,
		0x311AD689BC185340ULL,
		0x157123FF90AA0A22ULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0x3AE12936F60D4F8FULL,
		0xD9657A7A12B6E292ULL,
		0x226E41265191FAF1ULL,
		0x6DFC208DF19A44C4ULL,
		0x1C9CF76EF19DA70CULL,
		0x4433C506D7E80146ULL,
		0xB6DC0AAF47DA2A8DULL,
		0x119FB6233828867FULL
	}};
	curve25519_key_t k3 = {.key64 = {
		0x30412102200D440CULL,
		0x8021701812360002ULL,
		0x024E01025090F8B0ULL,
		0x4934208541184484ULL,
		0x1880F76471888400ULL,
		0x0011050291600102ULL,
		0x3018028904180200ULL,
		0x1111222310280222ULL
	}};
	curve25519_key_t r = {};
	printf("Test Case 1\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	int32_t res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 1 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -1;
	} else {
		printf("Test Case 1 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7D0CB9B6FC3D690EULL,
		0x512379A64AC04AC8ULL,
		0x156908E9420FA95CULL,
		0xFF13267A7DE23429ULL,
		0xDED99B9F9D46AD01ULL,
		0x2EC44EAB84E2BE92ULL,
		0x6E2CFA84F36E2F39ULL,
		0x68979B2C23FF7581ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4B2F7F1432543E3EULL,
		0xEA1E709ECEBCAD18ULL,
		0x781D67141A0984F3ULL,
		0x2A8AF1FC852D4125ULL,
		0xFBD653572A2BB689ULL,
		0xD406B390CB93ED12ULL,
		0xF7BDDEAACB55B77EULL,
		0xC400E8B861A6982EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x490C39143014280EULL,
		0x400270864A800808ULL,
		0x1009000002098050ULL,
		0x2A02207805200021ULL,
		0xDAD013170802A401ULL,
		0x040402808082AC12ULL,
		0x662CDA80C3442738ULL,
		0x4000882821A61000ULL
	}};
	printf("Test Case 2\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 2 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -2;
	} else {
		printf("Test Case 2 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB92F9468116C1C7DULL,
		0x33926F07CBB0F398ULL,
		0xBB91EAC87CC14788ULL,
		0x3DA2F55177F7FCEBULL,
		0xE946C54AA696BF2DULL,
		0x558B073856DF05F6ULL,
		0xB18750EB0370C670ULL,
		0x1B6463287825FA45ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x52846299B5EDE95EULL,
		0xEDC81BE542D21A90ULL,
		0x52B8D8B178A7780DULL,
		0x9F9D57886E4CB8E6ULL,
		0x6A40643DF8AACDEAULL,
		0xA66FF6B12D121E21ULL,
		0xD2CC8358765E0022ULL,
		0x71A6D41B2B20FBAAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x10040008116C085CULL,
		0x21800B0542901290ULL,
		0x1290C88078814008ULL,
		0x1D8055006644B8E2ULL,
		0x68404408A0828D28ULL,
		0x040B063004120420ULL,
		0x9084004802500020ULL,
		0x112440082820FA00ULL
	}};
	printf("Test Case 3\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 3 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -3;
	} else {
		printf("Test Case 3 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA10CB75CB1DF8FC2ULL,
		0x9D232455E1A92256ULL,
		0x9B9F69715913CA43ULL,
		0x4E667892C1DBE0FDULL,
		0xA3F198B1D2D70775ULL,
		0x9779F1817E2A80E2ULL,
		0x44C0A3C4E26CEE5AULL,
		0x4F9D8D09D3511CCAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5206BF9D73F8D986ULL,
		0x8C6C18247D9BBD7BULL,
		0x9C7F30827306235BULL,
		0xF9F568766CD52B43ULL,
		0x0C8548C858F52EEAULL,
		0xE30EF60FBC5A9B6DULL,
		0xAC3C8BE0BA0875A8ULL,
		0x4DB9C062BBB41429ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0004B71C31D88982ULL,
		0x8C20000461892052ULL,
		0x981F200051020243ULL,
		0x4864681240D12041ULL,
		0x0081088050D50660ULL,
		0x8308F0013C0A8060ULL,
		0x040083C0A2086408ULL,
		0x4D99800093101408ULL
	}};
	printf("Test Case 4\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 4 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -4;
	} else {
		printf("Test Case 4 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1721A4FB555BD363ULL,
		0xF3EF5A7DE72781EFULL,
		0x33C412C418186BDDULL,
		0xB6E2AB1D284BAFC2ULL,
		0xAEC6BC50C18577E1ULL,
		0x8749BA44DE13BCD8ULL,
		0xF00565DF2D164828ULL,
		0xB3B60DE45D9CBF3AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x53847BE4F6127557ULL,
		0xA42C2047310D879DULL,
		0x27CA7A8105A636ABULL,
		0xC5070194B277F3FEULL,
		0x10DDCC10215FFC67ULL,
		0x0EF2F0B2481543DFULL,
		0x95ADE4CD8E769D68ULL,
		0x05EE6B3398EC06D1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x130020E054125143ULL,
		0xA02C00452105818DULL,
		0x23C0128000002289ULL,
		0x840201142043A3C2ULL,
		0x00C48C1001057461ULL,
		0x0640B000481100D8ULL,
		0x900564CD0C160828ULL,
		0x01A60920188C0610ULL
	}};
	printf("Test Case 5\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 5 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -5;
	} else {
		printf("Test Case 5 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x00CE94104227D9AAULL,
		0x604D5B3F8CE459E8ULL,
		0x7C7B8D206292D99CULL,
		0x8490DE72430A8DC6ULL,
		0x75B9EDB2589D981BULL,
		0xF9EDB1E2E3ADE76AULL,
		0xDC9428E8DBBFE099ULL,
		0x6CD7FB592A7E1EBDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5E16D4EFD58BC0F4ULL,
		0xB60ABCAEB521BE98ULL,
		0x2F22993F500F36EEULL,
		0x6AD08F7F09AB5F4EULL,
		0x023450C5A1ACC77AULL,
		0xB69E8FBA8272CE81ULL,
		0xA43761A7D4A1AED1ULL,
		0x3F4BA0061E413096ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x000694004003C0A0ULL,
		0x2008182E84201888ULL,
		0x2C2289204002108CULL,
		0x00908E72010A0D46ULL,
		0x00304080008C801AULL,
		0xB08C81A28220C600ULL,
		0x841420A0D0A1A091ULL,
		0x2C43A0000A401094ULL
	}};
	printf("Test Case 6\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 6 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -6;
	} else {
		printf("Test Case 6 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAAF729F0DA199351ULL,
		0x06206A4CE637086FULL,
		0x464846B9846A9EA0ULL,
		0x92D32B6EE7BD96FAULL,
		0x46FE61AD9AB9C75FULL,
		0xAB02D0A3D033B732ULL,
		0x41BA44607DB758D6ULL,
		0x8C9AA7DEED1639D3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE730C534444A2211ULL,
		0x2F0D9F67DF7954D7ULL,
		0x223A3F22C836A01EULL,
		0x07E6C1E475838A4EULL,
		0x858DB2481F06EC81ULL,
		0x8DEFA8B02707C4A0ULL,
		0x95158AF4790227BFULL,
		0x727F838E1D5B18E4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA230013040080211ULL,
		0x06000A44C6310047ULL,
		0x0208062080228000ULL,
		0x02C201646581824AULL,
		0x048C20081A00C401ULL,
		0x890280A000038420ULL,
		0x0110006079020096ULL,
		0x001A838E0D1218C0ULL
	}};
	printf("Test Case 7\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 7 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -7;
	} else {
		printf("Test Case 7 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCF42259A0639E0AEULL,
		0xDE9A06038AE95676ULL,
		0x7DEE017B7AF2B7F2ULL,
		0xB20BE229265B00A2ULL,
		0x78676902DB5E781DULL,
		0xB23BED58F233AE76ULL,
		0xD26B6BC0410DEA43ULL,
		0xD5D2B0BBBBD75B60ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE36B4F753D319280ULL,
		0x99B144C1BC9749E3ULL,
		0x90D9516C6608CADCULL,
		0x4A964A789E83C76AULL,
		0x49E1B081417648EEULL,
		0x29B133563CF1E0C7ULL,
		0x0D5BA81D16D7ACAFULL,
		0xA983C2CCA9E2C9B2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC342051004318080ULL,
		0x9890040188814062ULL,
		0x10C80168620082D0ULL,
		0x0202422806030022ULL,
		0x486120004156480CULL,
		0x203121503031A046ULL,
		0x004B28000005A803ULL,
		0x81828088A9C24920ULL
	}};
	printf("Test Case 8\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 8 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -8;
	} else {
		printf("Test Case 8 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x440A6A588D561DE0ULL,
		0x47DE1B0C4AF12226ULL,
		0x00D14427614E627EULL,
		0x828E5BDFC256AF61ULL,
		0x4B823704B083477BULL,
		0xA5548D05DFC592E0ULL,
		0x47F9937B121457B8ULL,
		0xB7F46654FCAB4F35ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1E3BF49DC0A46B2AULL,
		0x073E1FBE2243EF2BULL,
		0xAB7F65FF39BE31C2ULL,
		0x68E9124EB450E95FULL,
		0x9DEBF3F77B10221EULL,
		0x250D9CC5654C0BCCULL,
		0x0999D08FFA3DA16FULL,
		0xB1BA9D5226680F2FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x040A601880040920ULL,
		0x071E1B0C02412222ULL,
		0x00514427210E2042ULL,
		0x0088124E8050A941ULL,
		0x098233043000021AULL,
		0x25048C05454402C0ULL,
		0x0199900B12140128ULL,
		0xB1B0045024280F25ULL
	}};
	printf("Test Case 9\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 9 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -9;
	} else {
		printf("Test Case 9 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8EB9BC0FF966C51DULL,
		0x01199BA5C0204E1AULL,
		0xB2296DFCE230F3E2ULL,
		0x1145E5E94FF5226FULL,
		0x4F6EF7ABBB3A7BEBULL,
		0xE1F1F8DC8419A48CULL,
		0xB0204DDB40F53FBAULL,
		0x1E1870E9D62F7718ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBE84B50929BE10BCULL,
		0x7D4D363E8D4B43EBULL,
		0xE08396C6470011A9ULL,
		0x514100052664E45EULL,
		0xFFF7B44CAB393352ULL,
		0x213BAC55C240A032ULL,
		0xFEE8E6FDAF832286ULL,
		0x36D8D9487537B015ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8E80B4092926001CULL,
		0x010912248000420AULL,
		0xA00104C4420011A0ULL,
		0x114100010664204EULL,
		0x4F66B408AB383342ULL,
		0x2131A8548000A000ULL,
		0xB02044D900812282ULL,
		0x1618504854273010ULL
	}};
	printf("Test Case 10\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 10 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -10;
	} else {
		printf("Test Case 10 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3D09BA3746D93E30ULL,
		0x5DA5A479161E5F53ULL,
		0xB169BDDA066524A3ULL,
		0xAFC4A529A68CA25EULL,
		0xE68AAD3E840E05D1ULL,
		0xE7AF498C14592085ULL,
		0x205BDDF814FAD909ULL,
		0xC78E31FACFFEFD71ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6DA674963B641AA7ULL,
		0xD12D7CF837DEEBE9ULL,
		0x5BFD660AC5F0B1E4ULL,
		0xD12F754C488AA9C2ULL,
		0xF45F2D897C48FDF6ULL,
		0x4B4AA2153E730003ULL,
		0xEDED5A6C092AEEACULL,
		0xD498B36B770FAC7CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2D00301602401A20ULL,
		0x51252478161E4B41ULL,
		0x1169240A046020A0ULL,
		0x810425080088A042ULL,
		0xE40A2D08040805D0ULL,
		0x430A000414510001ULL,
		0x20495868002AC808ULL,
		0xC488316A470EAC70ULL
	}};
	printf("Test Case 11\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 11 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -11;
	} else {
		printf("Test Case 11 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE9BB812E9C2BAD0BULL,
		0xFB2FE9B148D3E057ULL,
		0x8B3559AD52AB7D82ULL,
		0x0A7C27F3C8FFC720ULL,
		0x0B7C84A11DD7C091ULL,
		0xA087865FA0CC3CB8ULL,
		0x43009FEA44B2136CULL,
		0x43EE60949584828DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8523F601941B4654ULL,
		0xD441ADEF7149CF10ULL,
		0x961AA5527D507234ULL,
		0x4B0B6D750D159442ULL,
		0x64CB31C7F065E07DULL,
		0x510370F26A2CB1B3ULL,
		0xF91D48E24BBF2FA9ULL,
		0xB6F4423888D7CD14ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x81238000940B0400ULL,
		0xD001A9A14041C010ULL,
		0x8210010050007000ULL,
		0x0A08257108158400ULL,
		0x004800811045C011ULL,
		0x00030052200C30B0ULL,
		0x410008E240B20328ULL,
		0x02E4401080848004ULL
	}};
	printf("Test Case 12\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 12 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -12;
	} else {
		printf("Test Case 12 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA324057007E2B2AEULL,
		0x40397B5D330DF9D7ULL,
		0x3ED6957E92E410CDULL,
		0x8A4E1F2E4ECD42E2ULL,
		0xD31945662EABF05BULL,
		0x6EF53B6E405F6860ULL,
		0xD58E3262AF91649AULL,
		0xAB9F6839D2717049ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x128BDFD8DFCF1CEFULL,
		0x6ED164B9D5F06B24ULL,
		0x96D863E2EBA7610BULL,
		0xDC9673F4B2B66C8FULL,
		0xD3CE9D443DB7B56AULL,
		0x0A04FD6B327AF417ULL,
		0x6D7108EF5A7B272CULL,
		0x1BA9DC1FCDFF25E3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0200055007C210AEULL,
		0x4011601911006904ULL,
		0x16D0016282A40009ULL,
		0x8806132402844082ULL,
		0xD30805442CA3B04AULL,
		0x0A04396A005A6000ULL,
		0x450000620A112408ULL,
		0x0B894819C0712041ULL
	}};
	printf("Test Case 13\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 13 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -13;
	} else {
		printf("Test Case 13 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF5989EEC0D03CC3CULL,
		0x6F9E5ED6CCC27DBEULL,
		0xAD7F43BCFE73975EULL,
		0x21E6500B6C683B0FULL,
		0x1774FFB102A2D2B0ULL,
		0x03C09E9023EB1B10ULL,
		0xF39393F98C46C3B8ULL,
		0x9E11BDDA9AA2748BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF7A63650A62F6324ULL,
		0x3B5DD467D77C0E12ULL,
		0x253D89F8B3D76C98ULL,
		0x02C46CD87EBE0D9DULL,
		0xF16430BC9A7D0815ULL,
		0xB6434CB67CDD4640ULL,
		0x8B1CF6CDF9424C69ULL,
		0x2984F4B8FB56FB46ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF580164004034024ULL,
		0x2B1C5446C4400C12ULL,
		0x253D01B8B2530418ULL,
		0x00C440086C28090DULL,
		0x116430B002200010ULL,
		0x02400C9020C90200ULL,
		0x831092C988424028ULL,
		0x0800B4989A027002ULL
	}};
	printf("Test Case 14\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 14 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -14;
	} else {
		printf("Test Case 14 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6653EDC25A43F45FULL,
		0x518E9EEE919A7B5EULL,
		0xC9A778C42A9E7623ULL,
		0x0A883124FCA829D2ULL,
		0xDCE1CF9F0128E18EULL,
		0x0397B8077138E065ULL,
		0x2B19E31A688ACC45ULL,
		0xBFF6A2E82974AFD1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x28304EBD84D1032EULL,
		0x93433244AF9CDF20ULL,
		0x4C29E6A53E505E44ULL,
		0x9FCBE598EC0DF18BULL,
		0x3074CE6EEF31345EULL,
		0x0104D830565B57DFULL,
		0x36554D5E73E3280FULL,
		0x77B85256D1381DA2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x20104C800041000EULL,
		0x1102124481985B00ULL,
		0x482160842A105600ULL,
		0x0A882100EC082182ULL,
		0x1060CE0E0120200EULL,
		0x0104980050184045ULL,
		0x2211411A60820805ULL,
		0x37B0024001300D80ULL
	}};
	printf("Test Case 15\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 15 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -15;
	} else {
		printf("Test Case 15 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD94182AA464E1349ULL,
		0xA31CF8CCF11B75F2ULL,
		0x114BC72A10F41501ULL,
		0x17A52071A3FDCF32ULL,
		0x87C5002C8388465FULL,
		0xF1A293A1A582BBA0ULL,
		0x27487235CB224C72ULL,
		0x232000485883080AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x28B3D6A0227A531FULL,
		0x3A7EE616D79DBCA6ULL,
		0xA674375D3F32ADCDULL,
		0x0197043AF72C97B1ULL,
		0xF78E5734975D2A44ULL,
		0xF11BC1487FBD5BCDULL,
		0xF1BAD9AB925A0B5DULL,
		0x75A216E0CEAD0610ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x080182A0024A1309ULL,
		0x221CE004D11934A2ULL,
		0x0040070810300501ULL,
		0x01850030A32C8730ULL,
		0x8784002483080244ULL,
		0xF102810025801B80ULL,
		0x2108502182020850ULL,
		0x2120004048810000ULL
	}};
	printf("Test Case 16\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 16 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -16;
	} else {
		printf("Test Case 16 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAA5905C09450030CULL,
		0x2BE392C4A7CD34A7ULL,
		0x1015D3BC9F6E03A9ULL,
		0x69B9819AC01FB457ULL,
		0xA1C39B737CD09A3BULL,
		0xA4982BAA07B5B1A6ULL,
		0x250A4230C7C55137ULL,
		0xB5CE2F06B885EDB8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x40399B19B37B0177ULL,
		0x410D9C14C785148BULL,
		0xCB6B32B07B822784ULL,
		0xE560C7E516253D62ULL,
		0x601B40588421C156ULL,
		0x45554C221477649EULL,
		0x84CC9F85F9423B92ULL,
		0xB1A3B26E149F0707ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0019010090500104ULL,
		0x0101900487851483ULL,
		0x000112B01B020380ULL,
		0x6120818000053442ULL,
		0x2003005004008012ULL,
		0x0410082204352086ULL,
		0x04080200C1401112ULL,
		0xB182220610850500ULL
	}};
	printf("Test Case 17\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 17 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -17;
	} else {
		printf("Test Case 17 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x827B6752D1212C02ULL,
		0xCC2C11ED1581D2BAULL,
		0x3E6B731ECA798E5FULL,
		0x085369E431AAB2AFULL,
		0xAABE7EE924A7FB14ULL,
		0x9B74EDFA30EC485BULL,
		0x76AF29F0BE69B14FULL,
		0xA0CD26181F56709CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x32D36CF8069A7644ULL,
		0xDB6AE030CE636919ULL,
		0x5DE68229B1E3AB09ULL,
		0x96CFE1971962400EULL,
		0xCE38B5290437D17EULL,
		0x68CAC55F0F8F8A40ULL,
		0xFD3A92FB3AF409FFULL,
		0x2DCAFD3D17522B6AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0253645000002400ULL,
		0xC828002004014018ULL,
		0x1C62020880618A09ULL,
		0x004361841122000EULL,
		0x8A3834290427D114ULL,
		0x0840C55A008C0840ULL,
		0x742A00F03A60014FULL,
		0x20C8241817522008ULL
	}};
	printf("Test Case 18\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 18 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -18;
	} else {
		printf("Test Case 18 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCE0144268319BE2EULL,
		0xC333B6B868BE00FFULL,
		0xE06C9088304DF48FULL,
		0x370009052C7A7260ULL,
		0x6BD390A64A264976ULL,
		0xA6DF9E9461D342CFULL,
		0xC8FAEADA24A94A60ULL,
		0xB1C2288BE6B5CF3DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD4AA047759A14536ULL,
		0x8D7E1C1BD66C1AA3ULL,
		0x3CD53AC36337974DULL,
		0x39938A336847FE63ULL,
		0x8C91F9C59463F081ULL,
		0x047AD409F7BDEF8CULL,
		0x40ABF5BCB2313DA0ULL,
		0x1823DB503995D546ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC400042601010426ULL,
		0x81321418402C00A3ULL,
		0x204410802005940DULL,
		0x3100080128427260ULL,
		0x0891908400224000ULL,
		0x045A94006191428CULL,
		0x40AAE09820210820ULL,
		0x100208002095C504ULL
	}};
	printf("Test Case 19\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 19 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -19;
	} else {
		printf("Test Case 19 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6F6ED9FD5A2EC130ULL,
		0xF8F76C9134A424C6ULL,
		0x111F341F8F03621FULL,
		0x443873398B9AE7FEULL,
		0x7479F2FC61DFBFBAULL,
		0x5FD2F8FED4F5EAF4ULL,
		0xC3CEAC2BB8139516ULL,
		0x6CB593A6D2C03D37ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF9B9B06F0336FD64ULL,
		0xE2FB7727040E7E9CULL,
		0xCFBF535773DDBD7BULL,
		0x62FA42D8B7F42B1CULL,
		0x005AB75D71B267BEULL,
		0xCC7773F036CBBE95ULL,
		0xCA3A084A3D070F18ULL,
		0x7D6C96EF7043AD22ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6928906D0226C120ULL,
		0xE0F3640104042484ULL,
		0x011F10170301201BULL,
		0x403842188390231CULL,
		0x0058B25C619227BAULL,
		0x4C5270F014C1AA94ULL,
		0xC20A080A38030510ULL,
		0x6C2492A650402D22ULL
	}};
	printf("Test Case 20\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 20 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -20;
	} else {
		printf("Test Case 20 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x66DE84BD9D70C6A8ULL,
		0xD44BDD2D4FCE929EULL,
		0x7FED45A45318DED2ULL,
		0xA9CF37C4C781C0E1ULL,
		0xCEA924E14D8EE6ADULL,
		0xEF0E5DEF1407B7F6ULL,
		0xB4C047A08E895B0BULL,
		0xDDCF89D30AA654EBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x75DC7F689A18C7A1ULL,
		0x8E783557506B4133ULL,
		0xA08CA74F5E7CD63FULL,
		0x63DA09B3B2231767ULL,
		0xA282C88EA8FC8195ULL,
		0x8C3A7CF58D6DFC76ULL,
		0x4CF5A9750684C94AULL,
		0x969F93429C2F33A0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x64DC04289810C6A0ULL,
		0x84481505404A0012ULL,
		0x208C05045218D612ULL,
		0x21CA018082010061ULL,
		0x82800080088C8085ULL,
		0x8C0A5CE50405B476ULL,
		0x04C001200680490AULL,
		0x948F8142082610A0ULL
	}};
	printf("Test Case 21\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 21 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -21;
	} else {
		printf("Test Case 21 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB2D07EF575EBFF16ULL,
		0x23ECC2054D0DECD6ULL,
		0x035DF658241B2519ULL,
		0xB279AEDB0CAB74C1ULL,
		0xF2AEB828B039EDBBULL,
		0xFC55818D3707794FULL,
		0xF68D65222A81A7ACULL,
		0xB277FF694791A9DAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x70998410FD7C2352ULL,
		0x5200638FC0C7D415ULL,
		0x810DB4C6A6C18617ULL,
		0x011CEF9A17344205ULL,
		0x9EF25554EBFB0155ULL,
		0x7D805AA47ECA4075ULL,
		0x3A70AFF327555563ULL,
		0x683CE5AAC3155345ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3090041075682312ULL,
		0x020042054005C414ULL,
		0x010DB44024010411ULL,
		0x0018AE9A04204001ULL,
		0x92A21000A0390111ULL,
		0x7C00008436024045ULL,
		0x3200252222010520ULL,
		0x2034E52843110140ULL
	}};
	printf("Test Case 22\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 22 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -22;
	} else {
		printf("Test Case 22 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x27D22C0A05037697ULL,
		0xE18C80AB77A69293ULL,
		0xB508480C6472EE29ULL,
		0x76B6D038040C85B6ULL,
		0xE37A79A8FC58CA78ULL,
		0x9C000227A768AB57ULL,
		0x0062B2E9767CEA3EULL,
		0x42D727DCEF1839FFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x56CF5ECE14B95486ULL,
		0xDD10A306F4BB0429ULL,
		0xD8378280459B0FA1ULL,
		0x75E15699CA105A01ULL,
		0x980C4E84E4B5CE8BULL,
		0x41ECB181C14EEBE3ULL,
		0x0C5AD6BB53F31A51ULL,
		0x7E0DDBBD09860998ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x06C20C0A04015486ULL,
		0xC100800274A20001ULL,
		0x9000000044120E21ULL,
		0x74A0501800000000ULL,
		0x80084880E410CA08ULL,
		0x000000018148AB43ULL,
		0x004292A952700A10ULL,
		0x4205039C09000998ULL
	}};
	printf("Test Case 23\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 23 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -23;
	} else {
		printf("Test Case 23 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x074A156ECD811362ULL,
		0x542D485E705CB289ULL,
		0xFC7572BBF8540A84ULL,
		0x737BB107D55926AFULL,
		0xCBCED05E87F2DEB8ULL,
		0x6D192E1557B5D87FULL,
		0x08549E3C2394F251ULL,
		0x2FC5A56D7375B6D7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBD62EC1B78793C7CULL,
		0xE19EA2AA93D8B440ULL,
		0xF734BE4F35537150ULL,
		0x44F73ED0A26A3B96ULL,
		0x6D1C664B8B17E456ULL,
		0x16B4684C3B048D7EULL,
		0xFF8E3F0EB576AC6CULL,
		0x7322FCEA8E89DB58ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0542040A48011060ULL,
		0x400C000A1058B000ULL,
		0xF434320B30500000ULL,
		0x4073300080482286ULL,
		0x490C404A8312C410ULL,
		0x041028041304887EULL,
		0x08041E0C2114A040ULL,
		0x2300A46802019250ULL
	}};
	printf("Test Case 24\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 24 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -24;
	} else {
		printf("Test Case 24 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB1469E1E110DEC37ULL,
		0x1A95A0C7F6212361ULL,
		0x5AC78353F5523FE1ULL,
		0x29FD95EFBB0A810EULL,
		0x875B963748F97620ULL,
		0x611BA8411A44802FULL,
		0x3CEA63AFBBBE26B3ULL,
		0xAD9039E05A19F885ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4D124D2565304FC6ULL,
		0x42674BE78E65106DULL,
		0x34DA8D7CE394497FULL,
		0x641D812156CA3C3AULL,
		0xF23900111AA08BDFULL,
		0x741D3BCF4B3F5567ULL,
		0x33E7528221CE053BULL,
		0x446B5C5AA68FCAB1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x01020C0401004C06ULL,
		0x020500C786210061ULL,
		0x10C28150E1100961ULL,
		0x201D8121120A000AULL,
		0x8219001108A00200ULL,
		0x601928410A040027ULL,
		0x30E24282218E0433ULL,
		0x040018400209C881ULL
	}};
	printf("Test Case 25\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 25 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -25;
	} else {
		printf("Test Case 25 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8B4164CFA8C9BEB2ULL,
		0xBBBF38319566D280ULL,
		0x656F3150475532C8ULL,
		0x9CBDCC7B238C41FBULL,
		0xD97BC8273F6E9F6CULL,
		0xE4EF26315A65B35BULL,
		0x2A2D5F7AFE2A390DULL,
		0xB9E8EA1B6672D91CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1EC1C41865103146ULL,
		0x8DD5963FD7F175E5ULL,
		0x4D8D8E9190CE563BULL,
		0x88770125D47E2C7FULL,
		0x65BB7103EEE9E78CULL,
		0xCE4C09177DF0DEDAULL,
		0x6C5438F43995FF03ULL,
		0x28CC625EA73C57EDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0A41440820003002ULL,
		0x8995103195605080ULL,
		0x450D001000441208ULL,
		0x88350021000C007BULL,
		0x413B40032E68870CULL,
		0xC44C00115860925AULL,
		0x2804187038003901ULL,
		0x28C8621A2630510CULL
	}};
	printf("Test Case 26\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 26 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -26;
	} else {
		printf("Test Case 26 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFD2135AF753DBAA5ULL,
		0x41567F6E222BE3C9ULL,
		0xAB848119FF5D5A6EULL,
		0x0EADB29D39A1198AULL,
		0x62B34344CF367789ULL,
		0xD52606F2E90DCD51ULL,
		0x4139F9973862AF2BULL,
		0x0737024F6EC48A3AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x02958244C5306378ULL,
		0xCAACCA25BD51F64DULL,
		0xA0A49E2CD3C4B5F0ULL,
		0x3B076DE185B35429ULL,
		0x6BA63CBC9F489827ULL,
		0xF3916F7F6DB50129ULL,
		0xA802B3E487B16D8AULL,
		0x5D84A8DEF5C0BBF3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0001000445302220ULL,
		0x40044A242001E249ULL,
		0xA0848008D3441060ULL,
		0x0A05208101A11008ULL,
		0x62A200048F001001ULL,
		0xD100067269050101ULL,
		0x0000B18400202D0AULL,
		0x0504004E64C08A32ULL
	}};
	printf("Test Case 27\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 27 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -27;
	} else {
		printf("Test Case 27 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x557EF3C73EE91220ULL,
		0xD109E999FE8D0E01ULL,
		0xFBD8AA377379BAB0ULL,
		0xE555D3D8C22834D2ULL,
		0x69AF4057E48E7B09ULL,
		0x3D0B6A812DCE1390ULL,
		0xB13E9FDDC469567DULL,
		0x468D7B10B14C9729ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE2AAD2259E84F155ULL,
		0x1FAB27D2B1C68B6CULL,
		0xE5488BC8B3F8C828ULL,
		0xB4F32DF1C4379233ULL,
		0xA6FDA498496B238DULL,
		0x6964206458C39414ULL,
		0x166292333DE8FA1FULL,
		0x509C918D24FA3B51ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x402AD2051E801000ULL,
		0x11092190B0840A00ULL,
		0xE1488A0033788820ULL,
		0xA45101D0C0201012ULL,
		0x20AD0010400A2309ULL,
		0x2900200008C21010ULL,
		0x102292110468521DULL,
		0x408C110020481301ULL
	}};
	printf("Test Case 28\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 28 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -28;
	} else {
		printf("Test Case 28 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCE454D6EC39BC2AEULL,
		0x6C007AB3599693F8ULL,
		0x9E458AE147F5AC2CULL,
		0x0DE5058B8C9770E1ULL,
		0x02FFAE9262AED06BULL,
		0xB3355A886F39E781ULL,
		0x1889A9FFF9724BEBULL,
		0x30818D8EC925994FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x444047EE38440449ULL,
		0x4C80E65337269E45ULL,
		0x4A490AFF57D870FBULL,
		0x734A25EE26AEE278ULL,
		0x18FF36FBDF911810ULL,
		0xE3EAD55263EC3F76ULL,
		0x5021EE46E49E2FE6ULL,
		0x53F384AA3B52DC2EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4440456E00000008ULL,
		0x4C00621311069240ULL,
		0x0A410AE147D02028ULL,
		0x0140058A04866060ULL,
		0x00FF269242801000ULL,
		0xA320500063282700ULL,
		0x1001A846E0120BE2ULL,
		0x1081848A0900980EULL
	}};
	printf("Test Case 29\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 29 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -29;
	} else {
		printf("Test Case 29 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE49B33F3F428F931ULL,
		0x17049F2B591ED15DULL,
		0x94CF8D6A8048EB1FULL,
		0x47D10F0FD13933ECULL,
		0xE17CDC3BEA7DD649ULL,
		0xBACDD3A79140CA41ULL,
		0x04C2D4584FF29AA0ULL,
		0x00FCD4945A296452ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2EB011FFC44CF151ULL,
		0xD5506FA84529BBABULL,
		0x666DED6B6E6BF827ULL,
		0xECFFD6587F732DBBULL,
		0x96C74E7402780E14ULL,
		0xD1B055582F681481ULL,
		0x4BE55AC773E8E70AULL,
		0x6A9BD6FDDC2867F5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x249011F3C408F111ULL,
		0x15000F2841089109ULL,
		0x044D8D6A0048E807ULL,
		0x44D10608513121A8ULL,
		0x80444C3002780600ULL,
		0x9080510001400001ULL,
		0x00C0504043E08200ULL,
		0x0098D49458286450ULL
	}};
	printf("Test Case 30\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 30 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -30;
	} else {
		printf("Test Case 30 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE403913F61E172A3ULL,
		0xA8656E57EA728372ULL,
		0xA78BA28C8516458AULL,
		0x1671797FF5E47426ULL,
		0xA887FBD784AFC142ULL,
		0x46ACA11C2C883A11ULL,
		0x90FF7CB2507D23F9ULL,
		0xAA3B357AB6FBBFC2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD3F45F0627BCCD2FULL,
		0x97292E75AEA63208ULL,
		0x5D4A18ABB275DF27ULL,
		0x8439C7F8AA362EBFULL,
		0x8CFBEFFED2783CEAULL,
		0x65C6CEC22FCC3BE8ULL,
		0xF94842529469824AULL,
		0x0BAF66F3B5824176ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC000110621A04023ULL,
		0x80212E55AA220200ULL,
		0x050A008880144502ULL,
		0x04314178A0242426ULL,
		0x8883EBD680280042ULL,
		0x448480002C883A00ULL,
		0x9048401210690248ULL,
		0x0A2B2472B4820142ULL
	}};
	printf("Test Case 31\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 31 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -31;
	} else {
		printf("Test Case 31 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x60CA8CA07C205148ULL,
		0xC8BFB4EBD745044CULL,
		0x29456BB29C49357EULL,
		0xC153C5D3A870AB2CULL,
		0x9FA544F06F0D071BULL,
		0xB77253A8F307E8C1ULL,
		0xCA1AFEA1F0E439CAULL,
		0xB23DFDB1C652F711ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBCAA7EA3EEC1D8F0ULL,
		0x05D8858FB8CAFDDFULL,
		0x460FFE9F59BB15AAULL,
		0x2FC80E992AEF025BULL,
		0x8CBD5E154DE996A9ULL,
		0x4FA8B1EB2E9CC261ULL,
		0x42AD356041F19A6AULL,
		0xF7A6E02F13A86384ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x208A0CA06C005040ULL,
		0x0098848B9040044CULL,
		0x00056A921809152AULL,
		0x0140049128600208ULL,
		0x8CA544104D090609ULL,
		0x072011A82204C041ULL,
		0x4208342040E0184AULL,
		0xB224E02102006300ULL
	}};
	printf("Test Case 32\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 32 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -32;
	} else {
		printf("Test Case 32 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4461C926BCCB153DULL,
		0xB1F86D8F279F4F28ULL,
		0xDFE5E8B1B6AF88D7ULL,
		0x177DDA019E400766ULL,
		0x26233C94A64F1883ULL,
		0x3AA76A47FCF5D31CULL,
		0xFA2735057338F2E7ULL,
		0xFE8356D05ABB2CD7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6A6F0995952E94B6ULL,
		0xE16C21F1C7346E3DULL,
		0x7DD06A27988C493AULL,
		0x802B3F0E57F8900DULL,
		0xEE73D3894704E805ULL,
		0x88C5535A94B55125ULL,
		0x9EFE328136CDD710ULL,
		0x15EE8DC333BC3B8DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x40610904940A1434ULL,
		0xA168218107144E28ULL,
		0x5DC06821908C0812ULL,
		0x00291A0016400004ULL,
		0x2623108006040801ULL,
		0x0885424294B55104ULL,
		0x9A2630013208D200ULL,
		0x148204C012B82885ULL
	}};
	printf("Test Case 33\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 33 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -33;
	} else {
		printf("Test Case 33 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xADA919EED8BE891BULL,
		0xE25706091BFB7A82ULL,
		0x5CB8F9F478FAD942ULL,
		0x438617D4B9A99A6CULL,
		0x51170795DD15838FULL,
		0x7C1B4E1E05C29C1CULL,
		0x9DED2329774D2CBEULL,
		0x3A0D9A5EFA65B347ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE8001D5EC872E127ULL,
		0xD8D47B43C2E4A274ULL,
		0xE0A603059F62DC66ULL,
		0x8FCE7659090657C5ULL,
		0x63453B4157875677ULL,
		0x8B7B1A912E168C54ULL,
		0x151E2CC55E25B032ULL,
		0x240A05A0204AAD0AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA800194EC8328103ULL,
		0xC054020102E02200ULL,
		0x40A001041862D842ULL,
		0x0386165009001244ULL,
		0x4105030155050207ULL,
		0x081B0A1004028C14ULL,
		0x150C200156052032ULL,
		0x200800002040A102ULL
	}};
	printf("Test Case 34\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 34 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -34;
	} else {
		printf("Test Case 34 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x675FF4F77C26A8F5ULL,
		0x99E5670B509805D3ULL,
		0x8F81D7061C335283ULL,
		0x739F59C02D8BFA45ULL,
		0xE285AD9DEA8EF39BULL,
		0x210D189BBBF19409ULL,
		0xF169494F506A2BCAULL,
		0xEFBA696464F93721ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAE6659395ECA42DDULL,
		0xDA6470BA7DFCE840ULL,
		0xA8BEFADDBF24ADB3ULL,
		0x3D01D588D4DA368BULL,
		0xB2F123AB7A10BCF9ULL,
		0xE2141A8F423FC2AFULL,
		0x8ED7F34D862AC89EULL,
		0x596F8EBEA9C6340CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x264650315C0200D5ULL,
		0x9864600A50980040ULL,
		0x8880D2041C200083ULL,
		0x31015180048A3201ULL,
		0xA28121896A00B099ULL,
		0x2004188B02318009ULL,
		0x8041414D002A088AULL,
		0x492A082420C03400ULL
	}};
	printf("Test Case 35\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 35 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -35;
	} else {
		printf("Test Case 35 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA506AFCEC4B069C1ULL,
		0x6A2D4CCA1639F420ULL,
		0x1FF11E956DD28FA2ULL,
		0x2C3D75D71C810435ULL,
		0xA211D1D1DFE26F6AULL,
		0x8969ADBF370C617FULL,
		0x34032752DCB3BAA3ULL,
		0xD2C983403D5E1CD6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x20C4789DFCEA52CCULL,
		0x5AA0C700F3D77C45ULL,
		0x5A855305EE56CAF7ULL,
		0x5CC95178C14375D9ULL,
		0x5D93C11BE0509938ULL,
		0xE912945308A8CE19ULL,
		0x5DBA956F4F338F78ULL,
		0x5581DD35A698F874ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2004288CC4A040C0ULL,
		0x4A20440012117400ULL,
		0x1A8112056C528AA2ULL,
		0x0C09515000010411ULL,
		0x0011C111C0400928ULL,
		0x8900841300084019ULL,
		0x140205424C338A20ULL,
		0x5081810024181854ULL
	}};
	printf("Test Case 36\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 36 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -36;
	} else {
		printf("Test Case 36 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3ED8177995427F55ULL,
		0xD2F5607D7B027D7DULL,
		0x7DF9899826714EB5ULL,
		0x552D3BE97FA3F71CULL,
		0x986504F34082D49FULL,
		0xBE2CB13CF1A324A1ULL,
		0x1E8F60A251D25782ULL,
		0xD7BFF55FDB60D006ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x073A39323E5E0819ULL,
		0xE472377E0D042A50ULL,
		0x76E82C3092B174F4ULL,
		0x980AC4A8DE4871DFULL,
		0x508AC93C6EEBD4E9ULL,
		0xD64BE13239B13A11ULL,
		0x8643752F91DB3417ULL,
		0x6CD276FCAA13312CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0618113014420811ULL,
		0xC070207C09002850ULL,
		0x74E80810023144B4ULL,
		0x100800A85E00711CULL,
		0x100000304082D489ULL,
		0x9608A13031A12001ULL,
		0x0603602211D21402ULL,
		0x4492745C8A001004ULL
	}};
	printf("Test Case 37\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 37 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -37;
	} else {
		printf("Test Case 37 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xECA3C6D7698A2633ULL,
		0x01ACD548D8EEA995ULL,
		0x92817EAC49CB71ACULL,
		0xA67E4CE018247C1CULL,
		0x38761E1A10DEC5CAULL,
		0x1E0261813220B3D4ULL,
		0xD549EBF7930A3BE7ULL,
		0x0FE3C36AD1A0CE38ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1812AD10A50176D7ULL,
		0x1A02CE47C707F00FULL,
		0xD84C4E8DEF840093ULL,
		0xC20E664F14881DBFULL,
		0x4C29B6A5774DC383ULL,
		0xBB7CD78E68AE4F8CULL,
		0xEB0D00D94D9A5F9DULL,
		0x05E45A06CE542FD2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0802841021002613ULL,
		0x0000C440C006A005ULL,
		0x90004E8C49800080ULL,
		0x820E444010001C1CULL,
		0x08201600104CC182ULL,
		0x1A00418020200384ULL,
		0xC10900D1010A1B85ULL,
		0x05E04202C0000E10ULL
	}};
	printf("Test Case 38\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 38 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -38;
	} else {
		printf("Test Case 38 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE5B20EE60A1FC620ULL,
		0xF921D7C8B99304DEULL,
		0x580D1C6E19DD759EULL,
		0x1D736EF5E0149C63ULL,
		0xF651B81CDC8876B8ULL,
		0x171CD889618BE2AEULL,
		0xDBAF67BAE9AA1B71ULL,
		0x79273CA7794A0FC3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x91F47A8686CB504FULL,
		0x42B506C29AE777D1ULL,
		0x4CB3E64D36A9D00FULL,
		0x7142487B03164DAEULL,
		0xFF8F88A733E6B9DDULL,
		0x0291C937E8DB0858ULL,
		0x62979460DC53E50BULL,
		0x576F7C10D22F8746ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x81B00A86020B4000ULL,
		0x402106C0988304D0ULL,
		0x4801044C1089500EULL,
		0x1142487100140C22ULL,
		0xF601880410803098ULL,
		0x0210C801608B0008ULL,
		0x42870420C8020101ULL,
		0x51273C00500A0742ULL
	}};
	printf("Test Case 39\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 39 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -39;
	} else {
		printf("Test Case 39 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x40CFD81BBD43EDDBULL,
		0xEB34B104726522D3ULL,
		0xC9DABAC0978DB4C8ULL,
		0x6F98F7F34F566697ULL,
		0x7BDC8E52AA38DEA3ULL,
		0x88C77204916097F9ULL,
		0xC4AF9C5AD68D2CDDULL,
		0xCD85D0B25C918F59ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x81ED23F438AA0BA3ULL,
		0x570A117C20D66DD3ULL,
		0xE4432B69A44177B8ULL,
		0xA0159932516CCEEAULL,
		0x4E3E52C78D43782FULL,
		0x34E595A0AF3D0EDDULL,
		0x0A364D2411AA287EULL,
		0xBD3739F4122757FBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x00CD001038020983ULL,
		0x43001104204420D3ULL,
		0xC0422A4084013488ULL,
		0x2010913241444682ULL,
		0x4A1C024288005823ULL,
		0x00C51000812006D9ULL,
		0x00260C001088285CULL,
		0x8D0510B010010759ULL
	}};
	printf("Test Case 40\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 40 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -40;
	} else {
		printf("Test Case 40 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3801FBB628550BE4ULL,
		0x4280A744E5657F8CULL,
		0x48967F276A53E3EFULL,
		0xFB4111B02B2B4DB4ULL,
		0x66ABFE33D608A2CFULL,
		0xEB9A27D0D7FA94BFULL,
		0x593D09B62447D7E5ULL,
		0xB69621B760DD8B1DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x486BF0074A8D0F91ULL,
		0x52A0745CCE232AE3ULL,
		0xA74158288B682A4AULL,
		0x65634F7CDFD18AE0ULL,
		0xA6FB32B40E397A23ULL,
		0x1073054582655B36ULL,
		0xB92EAD4C66A64370ULL,
		0xCF1F6E732DC5A7C4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0801F00608050B80ULL,
		0x42802444C4212A80ULL,
		0x000058200A40224AULL,
		0x614101300B0108A0ULL,
		0x26AB323006082203ULL,
		0x0012054082601036ULL,
		0x192C090424064360ULL,
		0x8616203320C58304ULL
	}};
	printf("Test Case 41\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 41 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -41;
	} else {
		printf("Test Case 41 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3107870252AA29FAULL,
		0x800D09EC48D49199ULL,
		0x8DB5B43536D82B94ULL,
		0x0724815342EBA62FULL,
		0x6B1D95C3D550C0C6ULL,
		0xD5DCAADDDFE1F474ULL,
		0xC9CC8C0F88C49E7AULL,
		0xB61EFC7CC59FC264ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4C5BF37D877D3BB5ULL,
		0xC65672208A6E1C75ULL,
		0x28FFB21AC7BB2069ULL,
		0x58E6623D7937AEADULL,
		0x3AF8984CC9414AD0ULL,
		0x84A9658EE3CF4C21ULL,
		0x0838283B8ED3BCD2ULL,
		0x55C1E9F977E7DC07ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x00038300022829B0ULL,
		0x8004002008441011ULL,
		0x08B5B01006982000ULL,
		0x002400114023A62DULL,
		0x2A189040C14040C0ULL,
		0x8488208CC3C14420ULL,
		0x0808080B88C09C52ULL,
		0x1400E8784587C004ULL
	}};
	printf("Test Case 42\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 42 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -42;
	} else {
		printf("Test Case 42 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFA40DDAEF0A8E165ULL,
		0xC5012247FD87FD25ULL,
		0xC49D20C2179C586EULL,
		0x885EF1DB2BE7A108ULL,
		0x7637CA09671BE065ULL,
		0xF0B8EAAA2E9F5902ULL,
		0x74F6FD74A93225C6ULL,
		0xB63330822412697EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB6B099AB72131188ULL,
		0xB3738A6B82D84CAEULL,
		0x0EC043F5D60A5F34ULL,
		0x8E14FC45879B72E2ULL,
		0xCCD7F4F55D6CFFA0ULL,
		0xFB9DCF91768E60C9ULL,
		0xEC7022AA761478E7ULL,
		0xD9D0F6388F70AACCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB20099AA70000100ULL,
		0x8101024380804C24ULL,
		0x048000C016085824ULL,
		0x8814F04103832000ULL,
		0x4417C0014508E020ULL,
		0xF098CA80268E4000ULL,
		0x64702020201020C6ULL,
		0x901030000410284CULL
	}};
	printf("Test Case 43\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 43 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -43;
	} else {
		printf("Test Case 43 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAF299FC3EBEBA99AULL,
		0x0078E519C25A71ACULL,
		0x6129E6384E8DFF64ULL,
		0xE42699A917259FBFULL,
		0x526CF070C8F30E15ULL,
		0xEB85D286C2D2A5EFULL,
		0x32A9D49E7F0B241EULL,
		0x75F462F89945C077ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x02C5A41254D51AD3ULL,
		0xFACDE06ED9953D64ULL,
		0x261206738381AA6DULL,
		0x450F23DDAC0D5BE0ULL,
		0x13372C5F69527D27ULL,
		0x04240A3D1EE9C99AULL,
		0x4FD7F049D740DBC4ULL,
		0xDEB4F940AC2502A2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0201840240C10892ULL,
		0x0048E008C0103124ULL,
		0x200006300281AA64ULL,
		0x4406018904051BA0ULL,
		0x1224205048520C05ULL,
		0x0004020402C0818AULL,
		0x0281D00857000004ULL,
		0x54B4604088050022ULL
	}};
	printf("Test Case 44\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 44 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -44;
	} else {
		printf("Test Case 44 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8E14DCD7B9406D9FULL,
		0x0EBBB6FBA236B57AULL,
		0x67A627CA97B15DFFULL,
		0xEDE463DC4F5ED62EULL,
		0x63847C69CF652713ULL,
		0x3BBB99B7B0DF3F65ULL,
		0x589B1C7310D45286ULL,
		0x477EE4BA57A58548ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x511014F117A45D83ULL,
		0xFCB69474B65E86A3ULL,
		0xD940425B0BE0C860ULL,
		0x8F69887A5EFCAA9BULL,
		0x18E2BCC40EC86D19ULL,
		0x5AB9CA7DC5B3A8A5ULL,
		0x0B17172230035F17ULL,
		0x8CC7AE026FA0B8C9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x001014D111004D83ULL,
		0x0CB29470A2168422ULL,
		0x4100024A03A04860ULL,
		0x8D6000584E5C820AULL,
		0x00803C400E402511ULL,
		0x1AB9883580932825ULL,
		0x0813142210005206ULL,
		0x0446A40247A08048ULL
	}};
	printf("Test Case 45\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 45 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -45;
	} else {
		printf("Test Case 45 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x22A090A35765A617ULL,
		0x347725F74FF117EFULL,
		0x2D2E75417B2A9B39ULL,
		0xEFD6AB87FF01DE95ULL,
		0x68ADB71E7A53998FULL,
		0x753BFDE7C8F1B29EULL,
		0xD2D82CA259C40F00ULL,
		0x99FB795938E60B48ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5BB5821D84CB3999ULL,
		0x79CE445BCAD59E4FULL,
		0xC4D0466471286B4DULL,
		0x08A3ECAF6C869855ULL,
		0x88E4D05B154025C5ULL,
		0x9723ACB5E53D3879ULL,
		0x836ECFF90592C3C5ULL,
		0x68DEEC328E6DDE00ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x02A0800104412011ULL,
		0x304604534AD1164FULL,
		0x0400444071280B09ULL,
		0x0882A8876C009815ULL,
		0x08A4901A10400185ULL,
		0x1523ACA5C0313018ULL,
		0x82480CA001800300ULL,
		0x08DA681008640A00ULL
	}};
	printf("Test Case 46\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 46 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -46;
	} else {
		printf("Test Case 46 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x563EFBC7BCDD7AC2ULL,
		0x2591EB2F3F7A3BD2ULL,
		0x3CA22FC9A13B4F6DULL,
		0x3D269CD8CD274110ULL,
		0x4D182F6F01037BD5ULL,
		0x8824BCDEB7242CD1ULL,
		0x9557003C5646B0C6ULL,
		0x1518233C27DD9E94ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2630B4E9B69CD79AULL,
		0x6EE001CFF5C8B1C5ULL,
		0x0CCE70F94A969E43ULL,
		0x42D66788FCBBCF96ULL,
		0x8D61ED583B9469CBULL,
		0x8F36B2C1D860650EULL,
		0x86FD059013EAADB2ULL,
		0x6B72B5FB6342EC99ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0630B0C1B49C5282ULL,
		0x2480010F354831C0ULL,
		0x0C8220C900120E41ULL,
		0x00060488CC234110ULL,
		0x0D002D48010069C1ULL,
		0x8824B0C090202400ULL,
		0x845500101242A082ULL,
		0x0110213823408C90ULL
	}};
	printf("Test Case 47\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 47 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -47;
	} else {
		printf("Test Case 47 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB47148A00B27ECAEULL,
		0xE1E47E63BD6EA5FEULL,
		0xEB93E02E41F99805ULL,
		0xD29CD5BEABC7D97AULL,
		0xEB7460F855040259ULL,
		0xAADDBE08AA73E0EBULL,
		0xD656B42336CD3C76ULL,
		0x503A23DECD1BD16CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFA9BAA02ED68861CULL,
		0x097995C4E8E24A33ULL,
		0x595602953367647CULL,
		0xF0BD60DFD926E944ULL,
		0x3C2E7DF8411A4AA1ULL,
		0x36E2D64711670D56ULL,
		0xF00B06E7202F44E6ULL,
		0x658A529745FD6C38ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB01108000920840CULL,
		0x01601440A8620032ULL,
		0x4912000401610004ULL,
		0xD09C409E8906C940ULL,
		0x282460F841000201ULL,
		0x22C0960000630042ULL,
		0xD0020423200D0466ULL,
		0x400A029645194028ULL
	}};
	printf("Test Case 48\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 48 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -48;
	} else {
		printf("Test Case 48 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7A504FAEC063A5E0ULL,
		0xD24F5A05A1A4A6EDULL,
		0x85CA56BEB4A7C655ULL,
		0xAC2FE7D3012F783AULL,
		0x67A328B280731E26ULL,
		0xBEBFC11D34CC4634ULL,
		0x9D8CB1122FE1BD12ULL,
		0xDF2B10159E5FB0DFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x99E4F2771CB1FC33ULL,
		0xDFE5FC1C64C6BD3FULL,
		0xEC1D3BF12915DF0BULL,
		0x9C5D2032AFD0FBFCULL,
		0x442E27EAA3EF2EA5ULL,
		0x141F6C29EFBFF461ULL,
		0xB768012DABBE5BE0ULL,
		0x5D1A2DC8EC10C87CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x184042260021A420ULL,
		0xD24558042084A42DULL,
		0x840812B02005C601ULL,
		0x8C0D201201007838ULL,
		0x442220A280630E24ULL,
		0x141F4009248C4420ULL,
		0x950801002BA01900ULL,
		0x5D0A00008C10805CULL
	}};
	printf("Test Case 49\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 49 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -49;
	} else {
		printf("Test Case 49 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBEEEF63CD6362651ULL,
		0xC697853D5BD12F4AULL,
		0x56E7770E9872035AULL,
		0xEE4D9496AD0A627FULL,
		0xBC9A2AF37F45EA96ULL,
		0x517E394D1893A872ULL,
		0xC9F65567129A7ABDULL,
		0xCFB49DCA1D13032DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4F6F839F4E000A16ULL,
		0xB46903B154C76ED1ULL,
		0xE9F2D242B701D0B9ULL,
		0xBE625813AD312B4AULL,
		0x4314E2D1CFD93381ULL,
		0x522B1E02B407A75AULL,
		0x4AC96EAFD1135E82ULL,
		0xD05DD65CD3373741ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0E6E821C46000210ULL,
		0x8401013150C12E40ULL,
		0x40E2520290000018ULL,
		0xAE401012AD00224AULL,
		0x001022D14F412280ULL,
		0x502A18001003A052ULL,
		0x48C0442710125A80ULL,
		0xC014944811130301ULL
	}};
	printf("Test Case 50\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 50 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -50;
	} else {
		printf("Test Case 50 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x161E1D4E30F47CB6ULL,
		0x4C9D151A5EBCCAB5ULL,
		0x168D4A00EF2AD47FULL,
		0x78B6EBD0BABED01AULL,
		0xDA9F901CC649CCC9ULL,
		0x8C7C4DD75F864511ULL,
		0xBD5B5CCFA3DAF21DULL,
		0x669EC01232C652DAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6055F6F44018A6FBULL,
		0x3F6F454270A54487ULL,
		0x0316D2159F88BE39ULL,
		0xAB391A2F9E2A971DULL,
		0x463E8B6C2D5B0424ULL,
		0x42D3FCB75D2107ECULL,
		0x97CE5C9863D97FB7ULL,
		0xBE8FB55E6D47B57AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x00141444001024B2ULL,
		0x0C0D050250A44085ULL,
		0x020442008F089439ULL,
		0x28300A009A2A9018ULL,
		0x421E800C04490400ULL,
		0x00504C975D000500ULL,
		0x954A5C8823D87215ULL,
		0x268E80122046105AULL
	}};
	printf("Test Case 51\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 51 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -51;
	} else {
		printf("Test Case 51 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7146D005B43AA636ULL,
		0x51BB720AA9C36FE8ULL,
		0x0564F5976E338319ULL,
		0xE39E03942007C721ULL,
		0x765BCD0C623101FBULL,
		0x3CFADB7FFA97C209ULL,
		0x4C526A7134B2AB81ULL,
		0xACF514006EA39392ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0A9320A2F8D4D5FFULL,
		0x6A5ECD43DB296A5EULL,
		0xBD03A98F15D0BA65ULL,
		0x99D4E52CF2D8D8C9ULL,
		0x1433B331E3DC9372ULL,
		0x6F762A222E4CFE8DULL,
		0xEC7003A9D04A6A28ULL,
		0x4A11442DAEF1CA9EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x00020000B0108436ULL,
		0x401A400289016A48ULL,
		0x0500A18704108201ULL,
		0x819401042000C001ULL,
		0x1413810062100172ULL,
		0x2C720A222A04C209ULL,
		0x4C50022110022A00ULL,
		0x081104002EA18292ULL
	}};
	printf("Test Case 52\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 52 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -52;
	} else {
		printf("Test Case 52 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6614E95C307604B4ULL,
		0xE22DD889219C3448ULL,
		0xF4DEF254B80CF861ULL,
		0x3EAB87BB6B7629FCULL,
		0x2F4350812F2F71C2ULL,
		0xB7674F538FFC73F8ULL,
		0xB26FEF08A9881501ULL,
		0x27A3D74A06CD5C0FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x358CAB2CE6AA4CB5ULL,
		0xA994D9391BF036DCULL,
		0xDA6041E1B5A7FA74ULL,
		0x77655572830FC178ULL,
		0xD6CCA171AF70742DULL,
		0x5CF7D65E81322247ULL,
		0x8DCF4463E1C189F2ULL,
		0x8247E76D14285359ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2404A90C202204B4ULL,
		0xA004D80901903448ULL,
		0xD0404040B004F860ULL,
		0x3621053203060178ULL,
		0x064000012F207000ULL,
		0x1467465281302240ULL,
		0x804F4400A1800100ULL,
		0x0203C74804085009ULL
	}};
	printf("Test Case 53\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 53 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -53;
	} else {
		printf("Test Case 53 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1B897616D4239C05ULL,
		0xF73CAD2C2CEB8604ULL,
		0x62C7B236F17953C9ULL,
		0xD78A43C3D496953BULL,
		0x25A06C99A63CFCA6ULL,
		0x1655E11D12DFEF88ULL,
		0x6432DBD1FD6D7733ULL,
		0x605F4EF7CFD383F2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF3B4FE340A429969ULL,
		0x1B7417E7CA293D80ULL,
		0x6373D0715F26BC16ULL,
		0xB6F05C8FDC793373ULL,
		0xE64C0911DFA1C3BCULL,
		0xCE88EA2DB2FB32A6ULL,
		0x48DC26A7DFD8263CULL,
		0x134EFEEC03944D65ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1380761400029801ULL,
		0x1334052408290400ULL,
		0x6243903051201000ULL,
		0x96804083D4101133ULL,
		0x240008118620C0A4ULL,
		0x0600E00D12DB2280ULL,
		0x40100281DD482630ULL,
		0x004E4EE403900160ULL
	}};
	printf("Test Case 54\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 54 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -54;
	} else {
		printf("Test Case 54 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x31D1EE62886E1764ULL,
		0x9CD994EC0508A5B4ULL,
		0x4E3100FE9775C1D1ULL,
		0xC3530198B16EB725ULL,
		0xD96024C3FF2BD202ULL,
		0x1531F6972FD6FB69ULL,
		0x9F900AA4F29BB2FFULL,
		0x6631C8368CE162B5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x13D1A2C0501CD736ULL,
		0x575CD77AC2BB4957ULL,
		0xFE287E02B3EE99E2ULL,
		0xF7EF88DE98413AE6ULL,
		0x0987C63279718376ULL,
		0x251F01EE9D02E502ULL,
		0x10FF91F91F7E21CCULL,
		0x1722D7173BDA7270ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x11D1A240000C1724ULL,
		0x1458946800080114ULL,
		0x4E200002936481C0ULL,
		0xC343009890403224ULL,
		0x0900040279218202ULL,
		0x051100860D02E100ULL,
		0x109000A0121A20CCULL,
		0x0620C01608C06230ULL
	}};
	printf("Test Case 55\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 55 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -55;
	} else {
		printf("Test Case 55 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6DBAEA713C4024A3ULL,
		0x2C276B89134D9ABBULL,
		0x0E22BAC14EA45C08ULL,
		0xC53116EFC9EC3A01ULL,
		0xD615072D8E7957E4ULL,
		0xB475F07D1751BBC7ULL,
		0x33538EF331518907ULL,
		0x985449F40F583C0EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4A6BF94CCA83B976ULL,
		0x68892AE9AD7196E3ULL,
		0x9E984AD2E9491CAFULL,
		0xC88988F32D017F74ULL,
		0xF73CA4AAA25F8194ULL,
		0xF3EB66DFED93AB93ULL,
		0x154A8C334A7E22F7ULL,
		0x926837D286D3518BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x482AE84008002022ULL,
		0x28012A89014192A3ULL,
		0x0E000AC048001C08ULL,
		0xC00100E309003A00ULL,
		0xD614042882590184ULL,
		0xB061605D0511AB83ULL,
		0x11428C3300500007ULL,
		0x904001D00650100AULL
	}};
	printf("Test Case 56\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 56 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -56;
	} else {
		printf("Test Case 56 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x808CA393604A159BULL,
		0x4272BF6C30E12907ULL,
		0xFBFC15272CE2AAFAULL,
		0xF8765D7BF9CD0677ULL,
		0x0C50381E76CA8143ULL,
		0xED307E7B53E879AFULL,
		0x792855C816D972B5ULL,
		0x61C94C01AD2295F7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6820ED7FE7EF2897ULL,
		0x5B08CB3B829D5998ULL,
		0xC0DA539CAEA3C2A3ULL,
		0x3B641B57859340B0ULL,
		0xEA99E547E618F87BULL,
		0xE5C75FD4D77C845DULL,
		0x337E3AE57EA30BAEULL,
		0x1C735298471EDF86ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0000A113604A0093ULL,
		0x42008B2800810900ULL,
		0xC0D811042CA282A2ULL,
		0x3864195381810030ULL,
		0x0810200666088043ULL,
		0xE5005E505368000DULL,
		0x312810C0168102A4ULL,
		0x0041400005029586ULL
	}};
	printf("Test Case 57\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 57 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -57;
	} else {
		printf("Test Case 57 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA6E26E1AD3F88D20ULL,
		0x5BE7F202EE107925ULL,
		0x3C400E4D1BC8D2BDULL,
		0x9AB23231DFA4FEFBULL,
		0x291897E009D8D6C2ULL,
		0x10E5169639B12630ULL,
		0x1C68BF40DAC0DCCFULL,
		0xA30419B9DB56DD2BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF6F9DA080EE5DE2CULL,
		0x8459A316730451B4ULL,
		0x03CE13EEC14062C7ULL,
		0x2E3F0350CB6484D4ULL,
		0xEA6C466A1D26775DULL,
		0x4ACDBCC5A35BF259ULL,
		0x3DB78608AAF2B9FEULL,
		0x2F9E5C51D226A534ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA6E04A0802E08C20ULL,
		0x0041A20262005124ULL,
		0x0040024C01404285ULL,
		0x0A320210CB2484D0ULL,
		0x2808066009005640ULL,
		0x00C5148421112210ULL,
		0x1C2086008AC098CEULL,
		0x23041811D2068520ULL
	}};
	printf("Test Case 58\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 58 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -58;
	} else {
		printf("Test Case 58 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB233A75A044A4BC4ULL,
		0xF2E2C55BED13C607ULL,
		0x178A1E0FDD20ACA5ULL,
		0xB0F672736CDA7F87ULL,
		0xB93CB4911F0279ACULL,
		0x4DFDC6C7BF1761F6ULL,
		0x63096CC8A104FAB0ULL,
		0x4554833424B73949ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x04DB06A9ED8FAE12ULL,
		0xABF5B42BDAF2C96CULL,
		0xA1CDCB8F9336BA59ULL,
		0x61722152C4BDB5B1ULL,
		0x2CFF2B99797B0CCAULL,
		0x5F42B8239E3A618DULL,
		0x8A3B26EE10DA18F3ULL,
		0xFBB722532AE89E6CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x00130608040A0A00ULL,
		0xA2E0840BC812C004ULL,
		0x01880A0F9120A801ULL,
		0x2072205244983581ULL,
		0x283C209119020888ULL,
		0x4D4080039E126184ULL,
		0x020924C8000018B0ULL,
		0x4114021020A01848ULL
	}};
	printf("Test Case 59\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 59 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -59;
	} else {
		printf("Test Case 59 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4D7BB90FB07001E7ULL,
		0x48E3488C8CFE8F00ULL,
		0x1D3C5A78CFA9764FULL,
		0x6AF5C9E9E7C5B9E1ULL,
		0x55A4F041ED598491ULL,
		0x10E2B87225DF496AULL,
		0xFD339A723775EC51ULL,
		0x6E112D16BF58CA40ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x95D51BAA7ABD9F2EULL,
		0x4BFA32D508652B00ULL,
		0x31B0C273D38231E7ULL,
		0xCD0D0BF1A7361521ULL,
		0xDA4AF7C940A9D0DFULL,
		0x9D437F92DDF0E985ULL,
		0x7DA3493FFDEBAD4DULL,
		0x5A5EB0453BED1858ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0551190A30300126ULL,
		0x48E2008408640B00ULL,
		0x11304270C3803047ULL,
		0x480509E1A7041121ULL,
		0x5000F04140098091ULL,
		0x1042381205D04900ULL,
		0x7D2308323561AC41ULL,
		0x4A1020043B480840ULL
	}};
	printf("Test Case 60\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 60 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -60;
	} else {
		printf("Test Case 60 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5BE3B4DEA45F9A49ULL,
		0xEA3E668311AD1BA4ULL,
		0xBE24393DFB0D8ACBULL,
		0x22C147F8FB83D958ULL,
		0xA8DF7E3E017867DCULL,
		0x624E21DF24278BC4ULL,
		0x08323229E059A8EDULL,
		0xC921E5C1157D220DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4DA88BBAD04B43AEULL,
		0xB3F179DD6FAD5575ULL,
		0x5F46139859424B25ULL,
		0x89CA97E4702DBCB5ULL,
		0x8680A50B4A4989F4ULL,
		0xF62E727385DBA259ULL,
		0x934376C0938D565FULL,
		0x032484B6BD5BC2E4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x49A0809A804B0208ULL,
		0xA230608101AD1124ULL,
		0x1E04111859000A01ULL,
		0x00C007E070019810ULL,
		0x8080240A004801D4ULL,
		0x620E205304038240ULL,
		0x000232008009004DULL,
		0x0120848015590204ULL
	}};
	printf("Test Case 61\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 61 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -61;
	} else {
		printf("Test Case 61 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFFCF81CDAB19D6A3ULL,
		0x5F5AEBAA7B475D3DULL,
		0x529C8568C582F36DULL,
		0x1260A99D81AC7DFAULL,
		0x176D104C1F19634DULL,
		0xC5A14A937FB970B9ULL,
		0xE8E057DB166B2F5BULL,
		0xF2ACAD95E5CB34ADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF9B9A497552D942ULL,
		0xC47749E15C7FFBAFULL,
		0xF7CECDB28EBE5429ULL,
		0x1526D1086BF2C0B7ULL,
		0x48BFAECB1C2D1908ULL,
		0x1912FC2B352D2765ULL,
		0x5AD7F84AB75CA9E0ULL,
		0xBC6B1BC6E65A2B71ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAF8B80492110D002ULL,
		0x445249A05847592DULL,
		0x528C852084825029ULL,
		0x1020810801A040B2ULL,
		0x002D00481C090108ULL,
		0x0100480335292021ULL,
		0x48C0504A16482940ULL,
		0xB0280984E44A2021ULL
	}};
	printf("Test Case 62\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 62 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -62;
	} else {
		printf("Test Case 62 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x36A043223B41359CULL,
		0x98AA1542F8C9E73FULL,
		0xA4195FEC66D3F9C9ULL,
		0x73443BCD012F7F2BULL,
		0xBFEE94FD15C12FD9ULL,
		0x822B3EC1C98AB0FAULL,
		0xA3CF9668B9CDA8C9ULL,
		0xC493F08EEB3343C3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB33EAA43D36899F0ULL,
		0x95019C7CB6095120ULL,
		0x521BACCB551EC861ULL,
		0x6B355F2D3B959337ULL,
		0xB59C673E1969D4D2ULL,
		0x6B6D5B36AB205DEAULL,
		0x54D7AA1801C0AD46ULL,
		0xB0F0376EB32A086DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3220020213401190ULL,
		0x90001440B0094120ULL,
		0x00190CC84412C841ULL,
		0x63041B0D01051323ULL,
		0xB58C043C114104D0ULL,
		0x02291A00890010EAULL,
		0x00C7820801C0A840ULL,
		0x8090300EA3220041ULL
	}};
	printf("Test Case 63\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 63 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -63;
	} else {
		printf("Test Case 63 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8E03B67FE5F7BFC4ULL,
		0xCB162E037419F460ULL,
		0x25978CEB10F508FFULL,
		0x7C87F19AC097F653ULL,
		0xF783EAF4E899A137ULL,
		0xD655DB6EA0F4D688ULL,
		0x800F440AD33E931BULL,
		0x0997D008B7E6C3B1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x786166D5B0CB99D0ULL,
		0x757994FBBABE007FULL,
		0xA139BA849729E56CULL,
		0x83617336FDC1C79BULL,
		0xDCA75E9D47A7B54EULL,
		0x839913CB339A73CDULL,
		0x29AE7BF9CB4B5D59ULL,
		0x56B4E057E5D95C21ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x08012655A0C399C0ULL,
		0x4110040330180060ULL,
		0x211188801021006CULL,
		0x00017112C081C613ULL,
		0xD4834A944081A106ULL,
		0x8211134A20905288ULL,
		0x000E4008C30A1119ULL,
		0x0094C000A5C04021ULL
	}};
	printf("Test Case 64\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 64 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -64;
	} else {
		printf("Test Case 64 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE29EEE7CCBDB09D6ULL,
		0xFE91127F859E550FULL,
		0x7B4D4BE0010A5D25ULL,
		0x04DEEAED0BD68E97ULL,
		0xBD60AFA788399664ULL,
		0xDB83FB5606273AF4ULL,
		0x5ECED37651725AC9ULL,
		0xD72377D098EF4B84ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAEFA66898F4AF74DULL,
		0x8DB4E0C1805268D0ULL,
		0x84363CDB032B0DB0ULL,
		0x4F9DE63D56C91642ULL,
		0xA94C748F1DAFAFACULL,
		0xB145F9F4DD32C787ULL,
		0x86B485DA940F50F8ULL,
		0x6A7D0D481B6CBBB7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA29A66088B4A0144ULL,
		0x8C90004180124000ULL,
		0x000408C0010A0D20ULL,
		0x049CE22D02C00602ULL,
		0xA940248708298624ULL,
		0x9101F95404220284ULL,
		0x06848152100250C8ULL,
		0x42210540186C0B84ULL
	}};
	printf("Test Case 65\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 65 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -65;
	} else {
		printf("Test Case 65 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4C85BD28F5E6972DULL,
		0xBA00EB5C90E3569AULL,
		0xF2FDDD468AD81381ULL,
		0xA33A736085F7FB54ULL,
		0xB90187EAE8179510ULL,
		0xDB5B21AA53D8F346ULL,
		0xC37FC4E15079B1D1ULL,
		0x7CC8EF30F433B2F6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD81CC82C6133DE2BULL,
		0x3F4D94BAB863A8D5ULL,
		0x927A836BCC223CA7ULL,
		0x449FA27044E28266ULL,
		0x3923CE5A495BC7FEULL,
		0x25AD3C9487B89702ULL,
		0xF6ACC8D950CCDE61ULL,
		0x12B34837968A85ECULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4804882861229629ULL,
		0x3A00801890630090ULL,
		0x9278814288001081ULL,
		0x001A226004E28244ULL,
		0x3901864A48138510ULL,
		0x0109208003989302ULL,
		0xC22CC0C150489041ULL,
		0x10804830940280E4ULL
	}};
	printf("Test Case 66\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 66 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -66;
	} else {
		printf("Test Case 66 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x574BCA9F7C183C94ULL,
		0x8BE870F2690FE34FULL,
		0x85B08C46FBF4DDC9ULL,
		0x2C3A34BC07050DABULL,
		0x913F1D1D9EB69D9AULL,
		0xD6068EE28BC7F823ULL,
		0xD3DE3E8E8E8B7D5DULL,
		0x6005377EE4376E5DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE56C90DFDA264C69ULL,
		0xBEA8839F6220DCDEULL,
		0xD9C97327EED6D88FULL,
		0x1D0C4DC8640FF8ADULL,
		0x85771003FE9E20A3ULL,
		0x8079FC00A2B102C8ULL,
		0x66853ECD50BCF82FULL,
		0xFE3CA29B3D7DED3CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4548809F58000C00ULL,
		0x8AA800926000C04EULL,
		0x81800006EAD4D889ULL,
		0x0C080488040508A9ULL,
		0x813710019E960082ULL,
		0x80008C0082810000ULL,
		0x42843E8C0088780DULL,
		0x6004221A24356C1CULL
	}};
	printf("Test Case 67\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 67 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -67;
	} else {
		printf("Test Case 67 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x84542F73ACE04B74ULL,
		0x275F079BB9BE27F0ULL,
		0x8A9533AC7CF88778ULL,
		0x2AE45F4B5A4ED8E7ULL,
		0x7C74C8AB25CF3A7EULL,
		0x624B156F836F5FACULL,
		0xD805AEE679E61B0BULL,
		0xABF40CFAC5A3A5D7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x15BC447F28D18B45ULL,
		0x01300A0742768096ULL,
		0xFBB4F00BBEE4FD8FULL,
		0x43BDDE07AC60AC55ULL,
		0x72972D110953CA30ULL,
		0x1CE97FA9585B7859ULL,
		0xC8CBFFF0BBE50863ULL,
		0x61B2F29FA856A3C2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0414047328C00B44ULL,
		0x0110020300360090ULL,
		0x8A9430083CE08508ULL,
		0x02A45E0308408845ULL,
		0x7014080101430A30ULL,
		0x00491529004B5808ULL,
		0xC801AEE039E40803ULL,
		0x21B0009A8002A1C2ULL
	}};
	printf("Test Case 68\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 68 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -68;
	} else {
		printf("Test Case 68 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAD4E402F2357E40BULL,
		0x85E2663A56CD2D7EULL,
		0x5500EBE1A823FC84ULL,
		0x72279D6224651FB7ULL,
		0xD5B0EEBA67238B37ULL,
		0x0890EAA19F2BA291ULL,
		0x3A85444A8FBE3DC3ULL,
		0x7B529DB2F3D77BC9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x18CB2FFB434C5033ULL,
		0x77354FB1B7EC97C0ULL,
		0x7C7DBA71E38AE09FULL,
		0x567DE97AF7FD2688ULL,
		0x1ECBCA1B1126A3A2ULL,
		0x8FAE26250557871DULL,
		0x8EAB66B9B80F30A3ULL,
		0xA523C434F4BBB992ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x084A002B03444003ULL,
		0x0520463016CC0540ULL,
		0x5400AA61A002E084ULL,
		0x5225896224650680ULL,
		0x1480CA1A01228322ULL,
		0x0880222105038211ULL,
		0x0A814408880E3083ULL,
		0x21028430F0933980ULL
	}};
	printf("Test Case 69\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 69 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -69;
	} else {
		printf("Test Case 69 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC20C32DD1E5EE503ULL,
		0x16EFBC0B2A35A1C4ULL,
		0x2E10530A4AAE25BEULL,
		0x5B624B5EC6FCAC9BULL,
		0x94D2ABB998A62CC9ULL,
		0x38ABA0600CEB8162ULL,
		0xEE378C9AAE12DE85ULL,
		0x01506B22EC65E4B7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4D84952A4BFD6509ULL,
		0x75F55F845E57AD28ULL,
		0x595ECDA66695A571ULL,
		0xEAC3B8B20FC79D73ULL,
		0xE16D65B8A1984FB6ULL,
		0x1656A2A844BE86E2ULL,
		0x851E94D9AA124818ULL,
		0x34C1E6380222B5B6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x400410080A5C6501ULL,
		0x14E51C000A15A100ULL,
		0x0810410242842530ULL,
		0x4A42081206C48C13ULL,
		0x804021B880800C80ULL,
		0x1002A02004AA8062ULL,
		0x84168498AA124800ULL,
		0x004062200020A4B6ULL
	}};
	printf("Test Case 70\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 70 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -70;
	} else {
		printf("Test Case 70 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4E1BB2F6B2E77CA4ULL,
		0xAEE26065FEF185E2ULL,
		0xA1C19C9D7C9302FAULL,
		0x3D96D89E48A28EDEULL,
		0xC0A98247E6DD3CC1ULL,
		0xBF75772C2E9BE695ULL,
		0x7332C8E565395F66ULL,
		0xD1124F45EE0AD00EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x94AB0DAE721B0BA5ULL,
		0xE8C29391F1DB4429ULL,
		0x26905DAD2C92380EULL,
		0xC96603842460E1C4ULL,
		0x8D010CFDC9D06C73ULL,
		0x8277DE2C91B42DE3ULL,
		0xBEBA4D51659AE069ULL,
		0x38FCB198146B11A0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x040B00A6320308A4ULL,
		0xA8C20001F0D10420ULL,
		0x20801C8D2C92000AULL,
		0x09060084002080C4ULL,
		0x80010045C0D02C41ULL,
		0x8275562C00902481ULL,
		0x3232484165184060ULL,
		0x10100100040A1000ULL
	}};
	printf("Test Case 71\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 71 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -71;
	} else {
		printf("Test Case 71 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0B6AECC7E42ED81AULL,
		0xC292E5055C16FC15ULL,
		0x3B9F357025DE0D0BULL,
		0x5EE75E5CDC570F22ULL,
		0x4C127520407E663BULL,
		0xE4CAAEC52B1F716BULL,
		0x01B05649407F81FAULL,
		0xCAE37039BBBB404CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x877A7BB6A9D0829DULL,
		0x0C3CA4213D4DBDCAULL,
		0xC8710B0842E897B5ULL,
		0x4D368373975F0633ULL,
		0x547E1F2C04861056ULL,
		0xEE31F43A4CC6772EULL,
		0xD5E4D3257B303050ULL,
		0x6608E67F67560BA1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x036A6886A0008018ULL,
		0x0010A4011C04BC00ULL,
		0x0811010000C80501ULL,
		0x4C26025094570622ULL,
		0x4412152000060012ULL,
		0xE400A4000806712AULL,
		0x01A0520140300050ULL,
		0x4200603923120000ULL
	}};
	printf("Test Case 72\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 72 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -72;
	} else {
		printf("Test Case 72 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x340B7537209C1BFEULL,
		0xE107C9928A8219D9ULL,
		0xFFB8F15146B9F85BULL,
		0xA65E6B1856C07CF9ULL,
		0xBE21012D90CBBF2AULL,
		0xB6A73AFD62A1DB77ULL,
		0x7D1F325768ED9150ULL,
		0x56DB05BFE6FDB03DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x54A111CD7009B80FULL,
		0x24F83D529C1E87B4ULL,
		0x9CCDF47165BC33C7ULL,
		0x1383DCD2309F5157ULL,
		0x18FDD8776496D068ULL,
		0x7AFF772313B565FEULL,
		0xC42F8B2D40AFA417ULL,
		0x3F63D4360A22A407ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x140111052008180EULL,
		0x2000091288020190ULL,
		0x9C88F05144B83043ULL,
		0x0202481010805051ULL,
		0x1821002500829028ULL,
		0x32A7322102A14176ULL,
		0x440F020540AD8010ULL,
		0x164304360220A005ULL
	}};
	printf("Test Case 73\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 73 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -73;
	} else {
		printf("Test Case 73 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6F4BA9D0416A9004ULL,
		0x5ADBE04217DAD839ULL,
		0x1E2A45F0B0611E43ULL,
		0x40111C1A7EDC19E6ULL,
		0x88F6A55B3BE69B12ULL,
		0x182AC458D5BAF292ULL,
		0xAE27B79B3E6D0881ULL,
		0x3A69371AE8D104C1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0E79EE7CBBD4054EULL,
		0xA33A7461093D805DULL,
		0x4378C4B72C3077B1ULL,
		0x77C1782ED21F845DULL,
		0xAB69963A0E829E31ULL,
		0x4B6DFEB336C8EA14ULL,
		0xAF6F35705522B7FFULL,
		0xF10108D1EAB2B7A6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0E49A85001400004ULL,
		0x021A604001188019ULL,
		0x022844B020201601ULL,
		0x4001180A521C0044ULL,
		0x8860841A0A829A10ULL,
		0x0828C4101488E210ULL,
		0xAE27351014200081ULL,
		0x30010010E8900480ULL
	}};
	printf("Test Case 74\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 74 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -74;
	} else {
		printf("Test Case 74 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8201F71609DF2E48ULL,
		0x4FAB4D6A7F143F8EULL,
		0x447E7E32A6F7B256ULL,
		0xF02A22592311B55AULL,
		0x88379DD82F2D1962ULL,
		0xF3AC382F1756097AULL,
		0x39FEBB82DDDA5BA3ULL,
		0x4EA04FC3A4075853ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD32777426BA24A09ULL,
		0xD32E0F63CED050BAULL,
		0x3DCE87C5701771F1ULL,
		0x0213A146DDC0E62AULL,
		0x4021B9C5F619977DULL,
		0xEB8F44EEF1BD4437ULL,
		0xC756E13FB9C7F716ULL,
		0x617B8EAFA6F93E9DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8201770209820A08ULL,
		0x432A0D624E10108AULL,
		0x044E060020173050ULL,
		0x000220400100A40AULL,
		0x002199C026091160ULL,
		0xE38C002E11140032ULL,
		0x0156A10299C25302ULL,
		0x40200E83A4011811ULL
	}};
	printf("Test Case 75\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 75 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -75;
	} else {
		printf("Test Case 75 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD0A12EE0A6AEB14BULL,
		0xEE498C3B00966273ULL,
		0x1A588941AF82FE6FULL,
		0x7D61A8DC4C3F482CULL,
		0x0C69C00F00ADCB78ULL,
		0xAE0B6C0036CEDD43ULL,
		0x538F0467D8380461ULL,
		0x99317EE4463375E4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x96FA9DDDB7489FA8ULL,
		0xF1ED5CFA01627D8FULL,
		0x170922FB3A9C93CBULL,
		0x51619E1D9240CB96ULL,
		0xC599BCB2001FF86CULL,
		0x360A7128AE3F4D78ULL,
		0x77961C7B013D88A7ULL,
		0x8FE639A637069EF6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x90A00CC0A6089108ULL,
		0xE0490C3A00026003ULL,
		0x120800412A80924BULL,
		0x5161881C00004804ULL,
		0x04098002000DC868ULL,
		0x260A6000260E4D40ULL,
		0x5386046300380021ULL,
		0x892038A4060214E4ULL
	}};
	printf("Test Case 76\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 76 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -76;
	} else {
		printf("Test Case 76 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8CB276CF36499BB3ULL,
		0x31E57AA81A260C00ULL,
		0xF4C686DB1F895CE9ULL,
		0x56B71F06ED24E9BEULL,
		0x0012A5618ED119C3ULL,
		0xE13EB92C48AF20F6ULL,
		0xF5C6E849AF366794ULL,
		0x1B260FEE84334484ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1955F0EB0BA6FEAFULL,
		0x8B700ECD02E0503AULL,
		0x796C51A6ECB9C88BULL,
		0x3274F7136D0156B7ULL,
		0x2B8FC0067A81E202ULL,
		0x3600F7E69847F1CDULL,
		0x2645436AB93F3B01ULL,
		0x5D77DE4BE5D0DAF5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x081070CB02009AA3ULL,
		0x01600A8802200000ULL,
		0x704400820C894889ULL,
		0x123417026D0040B6ULL,
		0x000280000A810002ULL,
		0x2000B124080720C4ULL,
		0x24444048A9362300ULL,
		0x19260E4A84104084ULL
	}};
	printf("Test Case 77\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 77 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -77;
	} else {
		printf("Test Case 77 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x87A7CF2D402F3BCEULL,
		0xB8AD87F49E52D8D5ULL,
		0x417AD046FD69F2E4ULL,
		0x2B9D2A339A85299AULL,
		0xCDD44304C0C9A6E7ULL,
		0x77D3D4EACA972FE5ULL,
		0xB505C5ECF4C932ADULL,
		0x8464A29337C0C613ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEF615E35D1FC503DULL,
		0x1E1FD15BDDB9685EULL,
		0x23959BEBDF5A9EADULL,
		0xC91FF2123F6298DEULL,
		0xEB2559CCA15904B0ULL,
		0xD24E1FAC5F94A0E4ULL,
		0xC26EB827A1D5BD4DULL,
		0xC07EAAA1F9E5B1B8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x87214E25402C100CULL,
		0x180D81509C104854ULL,
		0x01109042DD4892A4ULL,
		0x091D22121A00089AULL,
		0xC9044104804904A0ULL,
		0x524214A84A9420E4ULL,
		0x80048024A0C1300DULL,
		0x8064A28131C08010ULL
	}};
	printf("Test Case 78\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 78 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -78;
	} else {
		printf("Test Case 78 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7203D69BA3A55950ULL,
		0xBD22A4135BC686F4ULL,
		0x908AFDB4AD814983ULL,
		0x1BD6AEC388E0AA9EULL,
		0xFF1DD17820198A42ULL,
		0x85B84868948867FEULL,
		0xF43E39488187DC75ULL,
		0xBC29F4D2CEE60791ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD8A4F61D4C2C710FULL,
		0x6A3559F603AA1778ULL,
		0x2714AA1DBDA3365BULL,
		0x550F1C6FEEE4F574ULL,
		0x813D86E51C9B04A6ULL,
		0x2735897C53A5CA72ULL,
		0xAB27599DC70AA4EEULL,
		0xB16682453BDAABC0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5000D61900245100ULL,
		0x2820001203820670ULL,
		0x0000A814AD810003ULL,
		0x11060C4388E0A014ULL,
		0x811D806000190002ULL,
		0x0530086810804272ULL,
		0xA026190881028464ULL,
		0xB02080400AC20380ULL
	}};
	printf("Test Case 79\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 79 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -79;
	} else {
		printf("Test Case 79 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA6ED1E4ADE615B6BULL,
		0xD71B90151A25C1A1ULL,
		0xC8AA2E253ABC3455ULL,
		0xECF02FF39FF766F7ULL,
		0xE22622FCFB79E40CULL,
		0xFACB4171C9823947ULL,
		0x86A0B4AFA2AA4DADULL,
		0xF2B0EEA15E5C672AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2DD7899930902CEEULL,
		0x45A76F6088C8C874ULL,
		0xF2C4D6976211EF72ULL,
		0xDF684E331982C5A8ULL,
		0x3E0582D7CC2A6A0CULL,
		0xE769F163932FB15FULL,
		0x12D877C5EEEA01E9ULL,
		0x912F46A9F977FC45ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x24C508081000086AULL,
		0x450300000800C020ULL,
		0xC080060522102450ULL,
		0xCC600E33198244A0ULL,
		0x220402D4C828600CULL,
		0xE249416181023147ULL,
		0x02803485A2AA01A9ULL,
		0x902046A158546400ULL
	}};
	printf("Test Case 80\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 80 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -80;
	} else {
		printf("Test Case 80 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB89B0A66B9EDEC35ULL,
		0x7CDB19DB4693089AULL,
		0x0F06F6989C70A77AULL,
		0xEE2E9DE3F4E3F487ULL,
		0x4DC8BD744A2A1A65ULL,
		0xC09AE4DAD0A863C8ULL,
		0x0E468B7D7F54E0F2ULL,
		0xFCCAFF5A6B5A7232ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2FDBEDF5CC2F7D86ULL,
		0x3623B33C517B4EE0ULL,
		0x114239835F76E318ULL,
		0x2CCCC50BE9AE844FULL,
		0x588464905134DA66ULL,
		0x42150834CDF862D4ULL,
		0xACCA1FBB6863C8C9ULL,
		0x17E1158D1256EDE2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x289B0864882D6C04ULL,
		0x3403111840130880ULL,
		0x010230801C70A318ULL,
		0x2C0C8503E0A28407ULL,
		0x4880241040201A64ULL,
		0x40100010C0A862C0ULL,
		0x0C420B396840C0C0ULL,
		0x14C0150802526022ULL
	}};
	printf("Test Case 81\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 81 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -81;
	} else {
		printf("Test Case 81 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x209C8A3C076B8E66ULL,
		0xD9FE954A7A027E26ULL,
		0xFE989741BC46B0E7ULL,
		0x68B32E06E407E8A8ULL,
		0x4E53E7D4B2B2A4F3ULL,
		0xA7FE548DE84860B6ULL,
		0x540DDC56B48B7848ULL,
		0xB2718CEF2E24A023ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC6D7186826C4BB89ULL,
		0xDD66AAC6A57D3480ULL,
		0x02425167B8D43B02ULL,
		0x74DDEDD7AA1E92E8ULL,
		0xD20E55DCDAD2A201ULL,
		0x2CAB4E0CCBD42CD2ULL,
		0x7EEFBAA49E0055C0ULL,
		0xE811FD7690910735ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0094082806408A00ULL,
		0xD966804220003400ULL,
		0x02001141B8443002ULL,
		0x60912C06A00680A8ULL,
		0x420245D49292A001ULL,
		0x24AA440CC8402092ULL,
		0x540D980494005040ULL,
		0xA0118C6600000021ULL
	}};
	printf("Test Case 82\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 82 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -82;
	} else {
		printf("Test Case 82 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB69FAC5536C76A54ULL,
		0xC04D5AA97B43CCF6ULL,
		0x2102D07F7917E9EBULL,
		0xF63E21444A64AA89ULL,
		0x25F7214F599088DFULL,
		0x792ACE028A71B9E7ULL,
		0x33B2C78F252EA9C1ULL,
		0x54D83D0C8F353D66ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x77D301E66F439C6BULL,
		0x8DDFF2A5A6494ED9ULL,
		0xF8D4BD59CE7FFDF2ULL,
		0x2DE63FDD3CE7416CULL,
		0x982DBB1718758FAEULL,
		0xA68A226A6F157A3DULL,
		0x707E1DCC2181C2B9ULL,
		0x3F80257994FF5CAAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3693004426430840ULL,
		0x804D52A122414CD0ULL,
		0x200090594817E9E2ULL,
		0x2426214408640008ULL,
		0x002521071810888EULL,
		0x200A02020A113825ULL,
		0x3032058C21008081ULL,
		0x1480250884351C22ULL
	}};
	printf("Test Case 83\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 83 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -83;
	} else {
		printf("Test Case 83 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBEEF9FE4DD959BDDULL,
		0xC303BA7B105993DBULL,
		0x7494F3193BE977B5ULL,
		0x279B897E0D34A5EBULL,
		0x4E2B9628B63A4FBEULL,
		0x118EC91186F50E89ULL,
		0x1A0EF33505B62D08ULL,
		0xF159A59F12BF56F8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD06473A50E5DA902ULL,
		0xB0E8870FEC9F2564ULL,
		0x99E9284905BF3188ULL,
		0x2FCD3AE3C646C9A4ULL,
		0xCD859E681006C30AULL,
		0x8587FFC97E7A6F4BULL,
		0x6BCF3630E1EE54F5ULL,
		0x17D0AA7C4A0D4DE9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x906413A40C158900ULL,
		0x8000820B00190140ULL,
		0x1080200901A93180ULL,
		0x27890862040481A0ULL,
		0x4C0196281002430AULL,
		0x0186C90106700E09ULL,
		0x0A0E323001A60400ULL,
		0x1150A01C020D44E8ULL
	}};
	printf("Test Case 84\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 84 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -84;
	} else {
		printf("Test Case 84 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x42CD3319EC60EFF1ULL,
		0x55E331C947330545ULL,
		0x1F0A057B7D4B8AFDULL,
		0x5FE2CAAC03B8F215ULL,
		0x33CC6B6DB06C2324ULL,
		0xAA3A5A66FCB16923ULL,
		0x700A06F4F16CF698ULL,
		0x9C9568905317D6B9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE35962E41E751874ULL,
		0xE8CD2B2ACCF67210ULL,
		0xE07F7732DE942BBDULL,
		0x41EE0BCAE961A8D3ULL,
		0x6C8A93FC014F2F08ULL,
		0x14BB7FA667A0DA4AULL,
		0x5D531B287CF85EEDULL,
		0xB532B7CE1AC58046ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x424922000C600870ULL,
		0x40C1210844320000ULL,
		0x000A05325C000ABDULL,
		0x41E20A880120A011ULL,
		0x2088036C004C2300ULL,
		0x003A5A2664A04802ULL,
		0x5002022070685688ULL,
		0x9410208012058000ULL
	}};
	printf("Test Case 85\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 85 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -85;
	} else {
		printf("Test Case 85 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD6CABD1C3502D229ULL,
		0x89C8C8959E7DDD9CULL,
		0xBACD77D0A3243921ULL,
		0xFAA4DE9E460FE3FAULL,
		0xA6BA16371EEF3AA4ULL,
		0x4009E3EF79657150ULL,
		0x5C241472B137E4CBULL,
		0x7D68434EF48823E0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x394552B609AF4D83ULL,
		0xE674B24AC2521701ULL,
		0xB1FD70118A8129C8ULL,
		0x3C0766E941D62057ULL,
		0x495ED03A33D2B24CULL,
		0xE9BE5E191AF62AE0ULL,
		0x182A27390DDB49E9ULL,
		0xAEB3BBF076607756ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1040101401024001ULL,
		0x8040800082501500ULL,
		0xB0CD701082002900ULL,
		0x3804468840062052ULL,
		0x001A103212C23204ULL,
		0x4008420918642040ULL,
		0x18200430011340C9ULL,
		0x2C20034074002340ULL
	}};
	printf("Test Case 86\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 86 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -86;
	} else {
		printf("Test Case 86 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD0BFE6B28D1DB098ULL,
		0x3F698B7D6505CC07ULL,
		0xBE74A4ABA604C99AULL,
		0xDBE797C860704D03ULL,
		0x733B04BF40431479ULL,
		0xF382457BAAB3D5ECULL,
		0xD254F6433365DC1AULL,
		0xCB54A3BDDD6D965BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC9FBD6859EC1AC04ULL,
		0xD78F488ABE946B8EULL,
		0xAF50BBA87012A365ULL,
		0x0C670C292BB9229EULL,
		0x826DF461BFB3C391ULL,
		0x7782CF9684E2836FULL,
		0x263B5B8534DB809AULL,
		0x82BEA6042FC2F18AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC0BBC6808C01A000ULL,
		0x1709080824044806ULL,
		0xAE50A0A820008100ULL,
		0x0867040820300002ULL,
		0x0229042100030011ULL,
		0x7382451280A2816CULL,
		0x021052013041801AULL,
		0x8214A2040D40900AULL
	}};
	printf("Test Case 87\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 87 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -87;
	} else {
		printf("Test Case 87 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8ABC887269120DBFULL,
		0x5B756541DDED607CULL,
		0x6D9A30BE4F0A6971ULL,
		0x9362598C5007CD98ULL,
		0xA09AB237336FD911ULL,
		0x59ACA949BF2C312AULL,
		0xAE446D58E8F0D712ULL,
		0x87AFC86ACB0A5ACEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x451FF4853B76EE8FULL,
		0xE12069CA287C6C1FULL,
		0x0330F8A532DE48EDULL,
		0xB72A0DB035F82BFFULL,
		0xF158E156D6D5100DULL,
		0xEFFF268B5B0078B3ULL,
		0x6E1171F9302B1647ULL,
		0xD0EDFE9A3FCADA39ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x001C800029120C8FULL,
		0x41206140086C601CULL,
		0x011030A4020A4861ULL,
		0x9322098010000998ULL,
		0xA018A01612451001ULL,
		0x49AC20091B003022ULL,
		0x2E00615820201602ULL,
		0x80ADC80A0B0A5A08ULL
	}};
	printf("Test Case 88\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 88 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -88;
	} else {
		printf("Test Case 88 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6E415673060DF1AEULL,
		0xAA09F4403666A9D2ULL,
		0xC7347459945CF972ULL,
		0x8615B54660D35C33ULL,
		0x409BC7E24167162AULL,
		0xF807110EAB02B8C4ULL,
		0xBF1F4F74435DF797ULL,
		0x622919AABB4F2D56ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9E0C29CD3D4ED2A9ULL,
		0xD2912D1F2B0FCF21ULL,
		0x7428074793BC00F5ULL,
		0x6A3532CA39AB09FFULL,
		0x8F509BDECCA024D9ULL,
		0xCDEC684794F5C731ULL,
		0x323A41B7767717C0ULL,
		0x0A9BB69D8D540E48ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0E000041040CD0A8ULL,
		0x8201240022068900ULL,
		0x44200441901C0070ULL,
		0x0215304220830833ULL,
		0x001083C240200408ULL,
		0xC804000680008000ULL,
		0x321A413442551780ULL,
		0x0209108889440C40ULL
	}};
	printf("Test Case 89\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 89 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -89;
	} else {
		printf("Test Case 89 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7035EF022ECA0801ULL,
		0x919AA8E97440B217ULL,
		0x04EDE99522AEB8E1ULL,
		0x336869D55B5B68A4ULL,
		0x90BA8698AFC605FFULL,
		0x7DAB40D681A8027FULL,
		0xA48DA5476332DAF8ULL,
		0xFCD812F20B706710ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE022EE0C72135B5FULL,
		0xADF557A9F91E66D3ULL,
		0x1DCF13C398A52C44ULL,
		0xBCC3EB2FB9C8C89DULL,
		0xD444E11DA5269F1AULL,
		0xBFF90D59E862BE84ULL,
		0xF29B49988E8B29A3ULL,
		0x04C3FDF135895B6AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6020EE0022020801ULL,
		0x819000A970002213ULL,
		0x04CD018100A42840ULL,
		0x3040690519484884ULL,
		0x90008018A506051AULL,
		0x3DA9005080200204ULL,
		0xA0890100020208A0ULL,
		0x04C010F001004300ULL
	}};
	printf("Test Case 90\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 90 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -90;
	} else {
		printf("Test Case 90 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x144220236598ADF7ULL,
		0x6614E428E0630E11ULL,
		0x6AF9195440307F5EULL,
		0xE2D59A707D820D3CULL,
		0xF49DFEC6F4A4DCC2ULL,
		0xB8145172BC365C8DULL,
		0xC934BBA492838DBDULL,
		0x709AF1C223BBD38FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x789DA8B1E98348D1ULL,
		0x78A87EC87480A679ULL,
		0x26F4736C89D3688AULL,
		0x148ED29F65204FCFULL,
		0x7C6233FB61792C7FULL,
		0xA527AAB90BF2F09EULL,
		0xEE4DD49767CB63E0ULL,
		0xF30C1C794AD9B857ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x10002021618008D1ULL,
		0x6000640860000611ULL,
		0x22F011440010680AULL,
		0x0084921065000D0CULL,
		0x740032C260200C42ULL,
		0xA00400300832508CULL,
		0xC8049084028301A0ULL,
		0x7008104002999007ULL
	}};
	printf("Test Case 91\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 91 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -91;
	} else {
		printf("Test Case 91 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE4386E2166E0004FULL,
		0x7E65E93779AFABF4ULL,
		0xED2DC7309BF2DCDCULL,
		0xEA420F0D71957D4BULL,
		0xAF16CEF15D74E974ULL,
		0x13C339818DBD7460ULL,
		0xAE08BCFEA19CFC9EULL,
		0xDF0EA0ACC3B6B7F2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x30C8AFB27780964CULL,
		0xA4A14A3209C2E1ECULL,
		0xB90BFEC2A445CCF5ULL,
		0x24579C819784C136ULL,
		0xB76C0B7FDED333C2ULL,
		0xF2D47BD27338D9D5ULL,
		0x0C13B1AEC014BF1AULL,
		0xF1525B886E46C95DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x20082E206680004CULL,
		0x242148320982A1E4ULL,
		0xA909C6008040CCD4ULL,
		0x20420C0111844102ULL,
		0xA7040A715C502140ULL,
		0x12C0398001385040ULL,
		0x0C00B0AE8014BC1AULL,
		0xD102008842068150ULL
	}};
	printf("Test Case 92\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 92 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -92;
	} else {
		printf("Test Case 92 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8B06F8AF29229D06ULL,
		0x5EEEF5864AD85E4BULL,
		0x403BCDFC4B43F616ULL,
		0xECC43F3F2D60D46FULL,
		0x4A0EE1FA7F81B9A7ULL,
		0xB215C684C4EBD58AULL,
		0x25BD34E174D12377ULL,
		0x36F045DC1DECB5A8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC3BE110A89F62DCEULL,
		0x44CBF33740808A4EULL,
		0xE02028F56D8C7A39ULL,
		0xC525FD5D3EA4D2B8ULL,
		0x3E11F411F4F0AE28ULL,
		0xA2378471ECEE277AULL,
		0x2DB9A5096434C4A0ULL,
		0xFD5F2CD5E72F7434ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8306100A09220D06ULL,
		0x44CAF10640800A4AULL,
		0x402008F449007210ULL,
		0xC4043D1D2C20D028ULL,
		0x0A00E0107480A820ULL,
		0xA2158400C4EA050AULL,
		0x25B9240164100020ULL,
		0x345004D4052C3420ULL
	}};
	printf("Test Case 93\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 93 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -93;
	} else {
		printf("Test Case 93 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x739AB3A1D4CB4F39ULL,
		0x6FA56E6103426252ULL,
		0xA041C4F2BE23AF61ULL,
		0xAE54144FB7E46E31ULL,
		0x83556F99524DAC9CULL,
		0x761F4575BB6B61DFULL,
		0x85970D69A766B63DULL,
		0x52CAAAE71726E25AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x982072A4CD86AAB5ULL,
		0xE078269F692B0462ULL,
		0x1743FAB4BCD04050ULL,
		0xF1A4021CA44C6F93ULL,
		0x67F13E1BE553F6CBULL,
		0x44E9DE6D1017ED1EULL,
		0x273D47B1C080362DULL,
		0x0DBABEF20898C6A5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x100032A0C4820A31ULL,
		0x6020260101020042ULL,
		0x0041C0B0BC000040ULL,
		0xA004000CA4446E11ULL,
		0x03512E194041A488ULL,
		0x440944651003611EULL,
		0x051505218000362DULL,
		0x008AAAE20000C200ULL
	}};
	printf("Test Case 94\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 94 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -94;
	} else {
		printf("Test Case 94 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9F6478ED6B50A9DAULL,
		0xB1BEF06ED09BC759ULL,
		0x60E6A65A2C1B1D49ULL,
		0x58D77072D43333B8ULL,
		0xC15894AA071E7AF0ULL,
		0xB9F0BB8CBB26CDDBULL,
		0x9A00DB30DFF1FD18ULL,
		0xE535A0139F0A9A91ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x989C6A80D82ECDA6ULL,
		0x4B6ED98E6114B719ULL,
		0xFCA99C7BE174CFB4ULL,
		0x4AEEC788F181D720ULL,
		0x731B6E3FE12944E9ULL,
		0x870FF1C5F8500866ULL,
		0xAF81EFA7B3B18DE7ULL,
		0x00748AA4A34DB1F3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9804688048008982ULL,
		0x012ED00E40108719ULL,
		0x60A0845A20100D00ULL,
		0x48C64000D0011320ULL,
		0x4118042A010840E0ULL,
		0x8100B184B8000842ULL,
		0x8A00CB2093B18D00ULL,
		0x0034800083089091ULL
	}};
	printf("Test Case 95\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 95 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -95;
	} else {
		printf("Test Case 95 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8A8C9C43C809E9C7ULL,
		0x0AF7306F0DB4AC85ULL,
		0xD63DA7C7B44E4A65ULL,
		0x43B9087EE115C7ACULL,
		0x3439E7B29CEFD145ULL,
		0x58E3EC3F53FA96E8ULL,
		0xADEB486C333A6B0CULL,
		0x4A4116809CBCE586ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5969C59295B637EFULL,
		0x82C8300D51786F1FULL,
		0xD6C084E9BF22D1BAULL,
		0x79144FED54B7544AULL,
		0x4F51986F2C0FEFF5ULL,
		0x00BD05B20DC5C60EULL,
		0x41D3F5F52D9040BBULL,
		0xDFC8874526AC3FC4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x08088402800021C7ULL,
		0x02C0300D01302C05ULL,
		0xD60084C1B4024020ULL,
		0x4110086C40154408ULL,
		0x041180220C0FC145ULL,
		0x00A1043201C08608ULL,
		0x01C3406421104008ULL,
		0x4A40060004AC2584ULL
	}};
	printf("Test Case 96\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 96 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -96;
	} else {
		printf("Test Case 96 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1E44224D24D592D3ULL,
		0xF68F8E82EAAA6990ULL,
		0x9120A53D77BC945EULL,
		0x56AC7330097447DCULL,
		0xEFFDDB63632ED91EULL,
		0x5F90E2CD878CF516ULL,
		0x71C7DAAD1AE61DB2ULL,
		0xCF19E01975EFE3CCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5D6CA83EE7D573F3ULL,
		0x807F39D2AF565277ULL,
		0x95029689BFBC48AEULL,
		0x485B131857911913ULL,
		0x8C9ECE213C291FC2ULL,
		0xFF254B9521D56D65ULL,
		0x4CD0AA99FF4AC381ULL,
		0xDBBACB079D9B2484ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1C44200C24D512D3ULL,
		0x800F0882AA024010ULL,
		0x9100840937BC000EULL,
		0x4008131001100110ULL,
		0x8C9CCA2120281902ULL,
		0x5F00428501846504ULL,
		0x40C08A891A420180ULL,
		0xCB18C001158B2084ULL
	}};
	printf("Test Case 97\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 97 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -97;
	} else {
		printf("Test Case 97 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x10D464ECCC8578E0ULL,
		0x86546830BFDED811ULL,
		0x33A4E5AA23E1A5CCULL,
		0xAF783E36E1A1C5E6ULL,
		0xC3EFCC2EDCFD315EULL,
		0xE8F588038ABA2D7DULL,
		0x2CCEEF13ECAA44DCULL,
		0x696547D8636BD23BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDDE98559E2D37090ULL,
		0xB93BF54E80F5FCB4ULL,
		0x4D3C108C5717AA18ULL,
		0x13FE9E23EDA40210ULL,
		0x58D6819568B24F2BULL,
		0x07921B86139E7311ULL,
		0x0A96379A733BD687ULL,
		0x9ECC6DA3D53D2F53ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x10C00448C0817080ULL,
		0x8010600080D4D810ULL,
		0x012400880301A008ULL,
		0x03781E22E1A00000ULL,
		0x40C6800448B0010AULL,
		0x00900802029A2111ULL,
		0x08862712602A4484ULL,
		0x0844458041290213ULL
	}};
	printf("Test Case 98\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 98 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -98;
	} else {
		printf("Test Case 98 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x03671038572A97D4ULL,
		0x9FE7DE5780CD08BDULL,
		0xD3C6F748BB398944ULL,
		0x9D90E9CD8BFECC8EULL,
		0xE38E67098B74F03AULL,
		0x5950EBEB68D4E3B0ULL,
		0x542288554B181B58ULL,
		0x9FDA59B6D0DF5B48ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFC9C13AC22CD8D3EULL,
		0xFBA894BB044F1055ULL,
		0xDC76E1CDD44EB954ULL,
		0xBC28C64E672FB43FULL,
		0x909EACA3068FE159ULL,
		0x0FD08188ACC05185ULL,
		0xBAB40BE1ACD2F39AULL,
		0x73BB665D663AC3E6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0004102802088514ULL,
		0x9BA09413004D0015ULL,
		0xD046E14890088944ULL,
		0x9C00C04C032E840EULL,
		0x808E24010204E018ULL,
		0x0950818828C04180ULL,
		0x1020084108101318ULL,
		0x139A4014401A4340ULL
	}};
	printf("Test Case 99\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 99 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -99;
	} else {
		printf("Test Case 99 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA9599C3950615EC4ULL,
		0x04F8C542CC03CB98ULL,
		0x510E9C13FC1F99FAULL,
		0xA61A750A8368A653ULL,
		0xADFD8ECB0FC19860ULL,
		0xE5BD63884966FE4BULL,
		0x8473F5E9A72E9FCBULL,
		0x1CC11C9DC1FD86C6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x66F5BF383B78B170ULL,
		0xE738BA877FA318F7ULL,
		0x0E2630F88A06D8C1ULL,
		0x6EE5B21DF37C95EEULL,
		0x020F5BAAD9A77017ULL,
		0xD9A6666792726ABFULL,
		0xB677E9E70C3E50A5ULL,
		0x7B0FB021AB7D2B5EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x20519C3810601040ULL,
		0x043880024C030890ULL,
		0x00061010880698C0ULL,
		0x2600300883688442ULL,
		0x000D0A8A09811000ULL,
		0xC1A4620000626A0BULL,
		0x8473E1E1042E1081ULL,
		0x18011001817D0246ULL
	}};
	printf("Test Case 100\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 100 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -100;
	} else {
		printf("Test Case 100 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x61EA0013B4B4508BULL,
		0x1276C0FDFDD9DEAEULL,
		0x43A1F1311EDDE2D9ULL,
		0x45D3DE48BEF53129ULL,
		0xE2703B018737F837ULL,
		0x007F9071A3E74272ULL,
		0xE838A93926078980ULL,
		0x7CD3FF4727F2E474ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1E512C9D2B3A9646ULL,
		0xC7ED4F1D458093EFULL,
		0xBBB090504CB0DF7AULL,
		0x2B761456DDE1BB6CULL,
		0xFDD4A8EE484DD21EULL,
		0xC0C60D9B06855DEDULL,
		0xBC57FB5BF1D88A7BULL,
		0xB751AB8CCDA510C7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0040001120301002ULL,
		0x0264401D458092AEULL,
		0x03A090100C90C258ULL,
		0x015214409CE13128ULL,
		0xE05028000005D016ULL,
		0x0046001102854060ULL,
		0xA810A91920008800ULL,
		0x3451AB0405A00044ULL
	}};
	printf("Test Case 101\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 101 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -101;
	} else {
		printf("Test Case 101 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x714103FCA3F1A72CULL,
		0x406FC44E82CE9620ULL,
		0x46678711DE27C8CFULL,
		0xB960AA449CD83B47ULL,
		0xDF15C2EB47BB3FABULL,
		0xDE0E6594BE5BA2C2ULL,
		0x67E5DA6A82DA3305ULL,
		0x09B4F772318C26AAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD8CDBEBA04049581ULL,
		0xB6FB910D24EADCF0ULL,
		0x9800D154DEFA3AC6ULL,
		0xA56D486617040578ULL,
		0xB458A2623694366DULL,
		0x97F1FCD3ABC387E7ULL,
		0x103760A351287BC2ULL,
		0x9F43DC8FB32DE450ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x504102B800008500ULL,
		0x006B800C00CA9420ULL,
		0x00008110DE2208C6ULL,
		0xA160084414000140ULL,
		0x9410826206903629ULL,
		0x96006490AA4382C2ULL,
		0x0025402200083300ULL,
		0x0900D402310C2400ULL
	}};
	printf("Test Case 102\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 102 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -102;
	} else {
		printf("Test Case 102 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x93217E8D41A65EA7ULL,
		0x580AC6F8B9573885ULL,
		0x63DFF03CB6505E8BULL,
		0x9C32C86395B524EDULL,
		0x882CC457079BCD69ULL,
		0x78AECC306E4676E5ULL,
		0x673262501B756D01ULL,
		0xC4E6ACA7239A36A4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x070E8C85246987E3ULL,
		0x569E1F0B819138A0ULL,
		0xB224F852C4834DBFULL,
		0xFAA3FDC27E063E3BULL,
		0xABC2B10DBF9AE1A7ULL,
		0xAC47E095B1B292B4ULL,
		0x21C884AFD5047CE8ULL,
		0x22B19379541B8C3FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x03000C85002006A3ULL,
		0x500A060881113880ULL,
		0x2204F01084004C8BULL,
		0x9822C84214042429ULL,
		0x88008005079AC121ULL,
		0x2806C010200212A4ULL,
		0x2100000011046C00ULL,
		0x00A08021001A0424ULL
	}};
	printf("Test Case 103\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 103 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -103;
	} else {
		printf("Test Case 103 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1C398E801DC4AC2EULL,
		0x35EB172F821C7DA3ULL,
		0xBDB9F8473B715590ULL,
		0xB1C873CFA0FA92DEULL,
		0x1E6BBA785AD02105ULL,
		0x72AD1FF015E5A4B6ULL,
		0x6747EF581CF86103ULL,
		0x4B59AEA082F53719ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x81DE54C4F8D101BDULL,
		0x842E3D5317D39D7AULL,
		0x6FDE07E84145A228ULL,
		0x2E4AD3C5823102EBULL,
		0x8017737C7489F8A4ULL,
		0x1AC563D8A479FD2DULL,
		0x94EBBC14E96CE7A6ULL,
		0x9D520CB32FC7407EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0018048018C0002CULL,
		0x042A150302101D22ULL,
		0x2D98004001410000ULL,
		0x204853C5803002CAULL,
		0x0003327850802004ULL,
		0x128503D00461A424ULL,
		0x0443AC1008686102ULL,
		0x09500CA002C50018ULL
	}};
	printf("Test Case 104\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 104 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -104;
	} else {
		printf("Test Case 104 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x99696C6EB82A363EULL,
		0x18569291D9C02755ULL,
		0x72B1F7867BFF65B9ULL,
		0xE807A111060D09BEULL,
		0x8AA6033F1D369FE1ULL,
		0x606ABF1B698792CDULL,
		0xB002282131C16B9BULL,
		0xCE815BA225B6D692ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1AA8C4C33DEF53C5ULL,
		0xB1E6C1E0BCD21E06ULL,
		0x0DC1CFCCD05A870DULL,
		0xD920A793239B5B74ULL,
		0x868B1A565A589B90ULL,
		0x70EA8CFE94E31F52ULL,
		0xF4A0753FE4070695ULL,
		0x1A4E132E3A313FE4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x18284442382A1204ULL,
		0x1046808098C00604ULL,
		0x0081C784505A0509ULL,
		0xC800A11102090934ULL,
		0x8282021618109B80ULL,
		0x606A8C1A00831240ULL,
		0xB000202120010291ULL,
		0x0A00132220301680ULL
	}};
	printf("Test Case 105\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 105 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -105;
	} else {
		printf("Test Case 105 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x642680D64E4F911FULL,
		0x02FF8A5C83B97AD5ULL,
		0xC379DD8810C2A366ULL,
		0xD6D1342B664E2CC9ULL,
		0x6B8D02B5BFC0B43FULL,
		0xD96644313E92EEB6ULL,
		0xF910166FFFD0C90EULL,
		0xB3DBB94787AC017AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD92CE2177EE86EE9ULL,
		0x15340144FAB85E34ULL,
		0x55324B4597C10160ULL,
		0xABFF1CCCEFEF2D72ULL,
		0x3B53D9C9AC754DB5ULL,
		0x7EF2D2AE578851E2ULL,
		0x47C92E8EA6F9F5D1ULL,
		0x3832AB312CC54CB0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x402480164E480009ULL,
		0x0034004482B85A14ULL,
		0x4130490010C00160ULL,
		0x82D11408664E2C40ULL,
		0x2B010081AC400435ULL,
		0x58624020168040A2ULL,
		0x4100060EA6D0C100ULL,
		0x3012A90104840030ULL
	}};
	printf("Test Case 106\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 106 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -106;
	} else {
		printf("Test Case 106 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x95AF209F37021378ULL,
		0x4DD27E58EBFE86B8ULL,
		0xA44E8CFA5B4B20CAULL,
		0xF769505972451375ULL,
		0x93E4C69B48744CB0ULL,
		0x0BA0E3E7032E28FCULL,
		0x18798BB151B7ED55ULL,
		0xEC43DA2D30221D7AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCE4A4F682EB54A3FULL,
		0xEB9C61990D5EC434ULL,
		0x0CA979F0A086EF48ULL,
		0x6F797BFBCF16DB26ULL,
		0x4C5F785FDDDD6D4EULL,
		0xC3A4498056C67E4DULL,
		0xD3FB9A92F38A81A6ULL,
		0xECEED9714E7C2258ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x840A000826000238ULL,
		0x49906018095E8430ULL,
		0x040808F000022048ULL,
		0x6769505942041324ULL,
		0x0044401B48544C00ULL,
		0x03A041800206284CULL,
		0x10798A9051828104ULL,
		0xEC42D82100200058ULL
	}};
	printf("Test Case 107\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 107 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -107;
	} else {
		printf("Test Case 107 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8ACCC57B0DAF9039ULL,
		0xDF90A9A6D3600732ULL,
		0xD7921275B458710BULL,
		0x1D831CD20A27CA54ULL,
		0x863B34E3DA3FF9D6ULL,
		0x93B941720AA31E2EULL,
		0xBF4DAA34857FAABCULL,
		0xC1B7B4737813637AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEC39B463A462441EULL,
		0x95A83BD9609527B7ULL,
		0xF5283C066471A096ULL,
		0x31D77FDADBAF92ACULL,
		0x4EC9D7A48DEBD26DULL,
		0xB44C9BF7BEAEC767ULL,
		0x06144802E9AF1169ULL,
		0x68266B3011DAF14CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8808846304220018ULL,
		0x9580298040000732ULL,
		0xD500100424502002ULL,
		0x11831CD20A278204ULL,
		0x060914A0882BD044ULL,
		0x900801720AA20626ULL,
		0x06040800812F0028ULL,
		0x4026203010126148ULL
	}};
	printf("Test Case 108\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 108 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -108;
	} else {
		printf("Test Case 108 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8B754E4BC28D2703ULL,
		0xA263B1C5D2E0A7B4ULL,
		0x6AB66AB4C346131BULL,
		0x4653B96A71266DFFULL,
		0xA00C113DDBA5FCE4ULL,
		0x59805D023A81EA22ULL,
		0x3D79248D7486A2D3ULL,
		0x4DCC9890AC205A8BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8848EBD15F09995FULL,
		0x11B3D8496D2D7C9AULL,
		0xCC994555BD6FAF4CULL,
		0xD4DA2EC90406EEF5ULL,
		0x615AF9EC341F53C1ULL,
		0xD7B0623E7B17BD26ULL,
		0x5B5AF82710A28127ULL,
		0x87DDB95274317688ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x88404A4142090103ULL,
		0x0023904140202490ULL,
		0x4890401481460308ULL,
		0x4452284800066CF5ULL,
		0x2008112C100550C0ULL,
		0x518040023A01A822ULL,
		0x1958200510828003ULL,
		0x05CC981024205288ULL
	}};
	printf("Test Case 109\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 109 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -109;
	} else {
		printf("Test Case 109 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8D05E290F69F330BULL,
		0x82E7D2012701ACBCULL,
		0x0A75ABB3DC7ACB03ULL,
		0x5BA8DF55858E3656ULL,
		0x26196F48B55B7BD2ULL,
		0x0744681E7130BEF9ULL,
		0xA19AEE16CCBC226CULL,
		0xB7BD183B6D5D276CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0C3B860811CF01B6ULL,
		0x09B83AF7A068575BULL,
		0xB6D5295F9B0A52F1ULL,
		0xDC81638AD86A29DDULL,
		0x7522B07BA57A4435ULL,
		0x186C799490E6A528ULL,
		0xDFCD1CDB4ECD41B3ULL,
		0x2B71F66D3181C816ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0C018200108F0102ULL,
		0x00A0120120000418ULL,
		0x02552913980A4201ULL,
		0x58804300800A2054ULL,
		0x24002048A55A4010ULL,
		0x004468141020A428ULL,
		0x81880C124C8C0020ULL,
		0x2331102921010004ULL
	}};
	printf("Test Case 110\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 110 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -110;
	} else {
		printf("Test Case 110 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0E65B34CF84C994CULL,
		0xBB5DC83EA0126E69ULL,
		0xF2FD4B189B75867BULL,
		0x91DDCD6B25BEC0ADULL,
		0x1F6C09C3806AF982ULL,
		0x66E39780E0580F1AULL,
		0xF583519FC3763BBDULL,
		0x04E7363F2BC0E03FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x00E78892DC8D56B4ULL,
		0xBC9A65BFAC2A45ABULL,
		0x914045C9662EAFC5ULL,
		0x584A267626359F12ULL,
		0x0E313EE545E832FFULL,
		0xAC5BB8AC6EA2F44EULL,
		0x19C021453E3E4A48ULL,
		0xA4BFD804A524AB1EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x00658000D80C1004ULL,
		0xB818403EA0024429ULL,
		0x9040410802248641ULL,
		0x1048046224348000ULL,
		0x0E2008C100683082ULL,
		0x244390806000040AULL,
		0x1180010502360A08ULL,
		0x04A710042100A01EULL
	}};
	printf("Test Case 111\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 111 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -111;
	} else {
		printf("Test Case 111 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x54A34A69E697914BULL,
		0x9D01B486F056E2FFULL,
		0x555763DBFFF368C1ULL,
		0xB2CC1D07ABE811B4ULL,
		0xF46AE623E43EE877ULL,
		0x5E4BAD713E2CCEE8ULL,
		0x8425F1C3EFE03EF2ULL,
		0xCAB94F62AB6ECB34ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDEEDD37AD2ED9164ULL,
		0x0C8F9C7E2F5B3F8AULL,
		0x779AFBC6577345CCULL,
		0xD174B0EC2D5A3001ULL,
		0x5B6A9B10E2FD24B6ULL,
		0x09F5F5D35800529BULL,
		0x23C6AA7BE926FEFAULL,
		0xC41A458BE48095D4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x54A14268C2859140ULL,
		0x0C0194062052228AULL,
		0x551263C2577340C0ULL,
		0x9044100429481000ULL,
		0x506A8200E03C2036ULL,
		0x0841A55118004288ULL,
		0x0004A043E9203EF2ULL,
		0xC0184502A0008114ULL
	}};
	printf("Test Case 112\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 112 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -112;
	} else {
		printf("Test Case 112 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6885AAB760D61990ULL,
		0x4CDDF5967282D95FULL,
		0xACCD7BC08F1BAF27ULL,
		0x600066958CCD9F93ULL,
		0xF234E2FE0BF9826BULL,
		0x52567D859255CE74ULL,
		0x986DE97F7C22E9ADULL,
		0xA7E0978E46398AA7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9AED17EBE3263681ULL,
		0x3A71A7FB54BE8F13ULL,
		0x5D622626A4D9E6D2ULL,
		0x190B0A5C99FF9C52ULL,
		0x2B460FD3B98386CFULL,
		0x69CA9F61DC1691CFULL,
		0xB7C75EF84E8486F3ULL,
		0xFCA5DAACFABF4C9EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x088502A360061080ULL,
		0x0851A59250828913ULL,
		0x0C4022008419A602ULL,
		0x0000021488CD9C12ULL,
		0x220402D20981824BULL,
		0x40421D0190148044ULL,
		0x904548784C0080A1ULL,
		0xA4A0928C42390886ULL
	}};
	printf("Test Case 113\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 113 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -113;
	} else {
		printf("Test Case 113 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA0453DCDB06FC578ULL,
		0x0A797294892C8876ULL,
		0x2EF0B4BBBBB58DABULL,
		0x9B35B2DA731F5391ULL,
		0x81A0BFC18F489941ULL,
		0xD7B29C4E46E53B18ULL,
		0x85326BFAE5B2B4F8ULL,
		0xE1E10C0EB3EAF63BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x971D6583F5D4D240ULL,
		0x4BF63CC1A43E8672ULL,
		0x096DBE2B1454CB57ULL,
		0x1FC690C34236C910ULL,
		0xAD71F6B62F101E60ULL,
		0x57B946ECDD9561B8ULL,
		0xBABD6F3A2E517204ULL,
		0x0E915F3FA2C61DBEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x80052581B044C040ULL,
		0x0A703080802C8072ULL,
		0x0860B42B10148903ULL,
		0x1B0490C242164110ULL,
		0x8120B6800F001840ULL,
		0x57B0044C44852118ULL,
		0x80306B3A24103000ULL,
		0x00810C0EA2C2143AULL
	}};
	printf("Test Case 114\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 114 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -114;
	} else {
		printf("Test Case 114 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA746CFF125515DE2ULL,
		0x7392794BDB611131ULL,
		0x20054B026A338DE5ULL,
		0xF521028D5B0B8ED9ULL,
		0x5ED40D98EFABB947ULL,
		0x94088F57CBFDC0CEULL,
		0xE92FA25DF3052F06ULL,
		0xF2F7DEB5D6851921ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC9D360FEAC11C993ULL,
		0xA307FEB5813809B9ULL,
		0x0F9A4E890B0F548AULL,
		0x54649F656742AF2BULL,
		0xD828038F613BC15CULL,
		0xCC01543FA8DA5013ULL,
		0xB4E0ACE08A7EC7CBULL,
		0xCA1BE50C39F7EBD8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x814240F024114982ULL,
		0x2302780181200131ULL,
		0x00004A000A030480ULL,
		0x5420020543028E09ULL,
		0x58000188612B8144ULL,
		0x8400041788D84002ULL,
		0xA020A04082040702ULL,
		0xC213C40410850900ULL
	}};
	printf("Test Case 115\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 115 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -115;
	} else {
		printf("Test Case 115 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA2F3452F57A8C589ULL,
		0xB4758C4D92B08543ULL,
		0x39ED914D15214532ULL,
		0xAC1B127E045E0DD7ULL,
		0x5BA1F821E958C352ULL,
		0x9D85480A722073F8ULL,
		0x1511167846EA4F4DULL,
		0x3428D3C280B6EB9DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xECA12FB6D0667824ULL,
		0x284E595FA3ACC791ULL,
		0x6630C994927A05EEULL,
		0x656DACE67299F70EULL,
		0x8EDDBB79E7629AE5ULL,
		0xB021CAC278ADC249ULL,
		0xDD3F663787341619ULL,
		0x231B294ADB69DD27ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA0A1052650204000ULL,
		0x2044084D82A08501ULL,
		0x2020810410200522ULL,
		0x2409006600180506ULL,
		0x0A81B821E1408240ULL,
		0x9001480270204248ULL,
		0x1511063006200609ULL,
		0x200801428020C905ULL
	}};
	printf("Test Case 116\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 116 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -116;
	} else {
		printf("Test Case 116 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE1E7D2E5FD40221AULL,
		0x20D69030AA496F91ULL,
		0x2B31E1427004D474ULL,
		0x25C998426B9CFC11ULL,
		0xC4E705CD08564971ULL,
		0xF38FF5C7B4274B98ULL,
		0x3D9A81EBEC7A4846ULL,
		0x3C5B3EBC32949697ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x41732E1401533741ULL,
		0xF918A019C6AC69EDULL,
		0xBEFBCFB8E583B807ULL,
		0x6C6CD45831344620ULL,
		0xDA46AF3685BDCEAFULL,
		0x36C022A08C09767EULL,
		0xB8C9521394622772ULL,
		0xB837D11FDEECA6B4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4163020401402200ULL,
		0x2010801082086981ULL,
		0x2A31C10060009004ULL,
		0x2448904021144400ULL,
		0xC046050400144821ULL,
		0x3280208084014218ULL,
		0x3888000384620042ULL,
		0x3813101C12848694ULL
	}};
	printf("Test Case 117\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 117 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -117;
	} else {
		printf("Test Case 117 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE2E912C8AF41F129ULL,
		0x1CDFFF8F3CC18B48ULL,
		0xB1DE0AE65793F410ULL,
		0xE37A0672C7A27A26ULL,
		0xF70B6732FB066AB6ULL,
		0xA75D252B654930B6ULL,
		0xF35E569CCA6D9E95ULL,
		0x690655AEAD9B8456ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5E4A9DD3430F3945ULL,
		0x00D607AE4848650AULL,
		0xD1ECC4EBE30748BFULL,
		0xC45A22A2CEDFC373ULL,
		0xAC4C800E0F653535ULL,
		0x501356CE0EB500D6ULL,
		0x5B9DE6378C9725A2ULL,
		0x33CE1FFB6624A513ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x424810C003013101ULL,
		0x00D6078E08400108ULL,
		0x91CC00E243034010ULL,
		0xC05A0222C6824222ULL,
		0xA40800020B042034ULL,
		0x0011040A04010096ULL,
		0x531C461488050480ULL,
		0x210615AA24008412ULL
	}};
	printf("Test Case 118\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 118 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -118;
	} else {
		printf("Test Case 118 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x60559628467BF567ULL,
		0xE8D4307158558656ULL,
		0xF1564945231C08EEULL,
		0x44EF5FB2CEB95083ULL,
		0x62B713F94B83012CULL,
		0x580357E61696BD66ULL,
		0xED145A5B0D319BD3ULL,
		0xE76879F7D4FFEB0CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x05E138DB87F013C1ULL,
		0x7A6F757A7967C9E2ULL,
		0xD77097CDC45350B4ULL,
		0x0F122F555F2187D3ULL,
		0x0317491B4A714B66ULL,
		0x3CCA483BD746D09AULL,
		0x4A6554577951B1EDULL,
		0xE4561EB8E7BE0AD7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0041100806701141ULL,
		0x6844307058458042ULL,
		0xD1500145001000A4ULL,
		0x04020F104E210083ULL,
		0x021701194A010124ULL,
		0x1802402216069002ULL,
		0x48045053091191C1ULL,
		0xE44018B0C4BE0A04ULL
	}};
	printf("Test Case 119\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 119 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -119;
	} else {
		printf("Test Case 119 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x06139E766722BC09ULL,
		0xC9F88BB2E221A8A8ULL,
		0x0B952A8BF2953C82ULL,
		0x7F1D2D99EB23B4F2ULL,
		0xBCA14910DE40A2B7ULL,
		0x559101ED1A0A5190ULL,
		0xDA5CC9BFDF64C25EULL,
		0x4A13B372FF03B921ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0DD11CB1C89D1C7EULL,
		0xB2AE5C9D9FFC36F0ULL,
		0x7564F866582183F4ULL,
		0x8C8C7CBAF8273DF0ULL,
		0x91F62BD5B5E08DC1ULL,
		0x51AF89CDF94236B0ULL,
		0xCDFA563941B0E47CULL,
		0xCB8BC9F4934F6D39ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x04111C3040001C08ULL,
		0x80A80890822020A0ULL,
		0x0104280250010080ULL,
		0x0C0C2C98E82334F0ULL,
		0x90A0091094408081ULL,
		0x518101CD18021090ULL,
		0xC85840394120C05CULL,
		0x4A03817093032921ULL
	}};
	printf("Test Case 120\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 120 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -120;
	} else {
		printf("Test Case 120 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4D3621FBBE627C1CULL,
		0x33D74374B7AF9BD4ULL,
		0xF4FB5409678A7E60ULL,
		0x19BA646E98285985ULL,
		0x11D1214D4AC177F3ULL,
		0xAE9DEB72683B2D05ULL,
		0x64D11E8BABED9BBCULL,
		0x61CBF3472DA1A0AFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC3DE60F6273670E4ULL,
		0x16AB91F54A73F980ULL,
		0x89D36A3836BEA6AFULL,
		0x34126524FAF482C6ULL,
		0x24BC43189E9628C2ULL,
		0xF006B9F55D9359D4ULL,
		0x6CE69D89D340997AULL,
		0x41D4D6EC9599BC62ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x411620F226227004ULL,
		0x1283017402239980ULL,
		0x80D34008268A2620ULL,
		0x1012642498200084ULL,
		0x009001080A8020C2ULL,
		0xA004A97048130904ULL,
		0x64C01C8983409938ULL,
		0x41C0D2440581A022ULL
	}};
	printf("Test Case 121\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 121 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -121;
	} else {
		printf("Test Case 121 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8D7B0C34D5D9B0E7ULL,
		0xF0A232229822A80AULL,
		0x04C72AC49F73EF56ULL,
		0xC64BCB1FCB218AB9ULL,
		0x8B82DCF9450E48FAULL,
		0x6D15CE2C202567D2ULL,
		0xADAAEC9F62B94C1DULL,
		0x5A3513ADC1D9C705ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC39AA30EBFB42B99ULL,
		0xDE748945EDA158D4ULL,
		0x44450D6FEBE68CD6ULL,
		0xB48649A65FFDCFFCULL,
		0x30F6D17C1FB92CAFULL,
		0xE139F4FB044013E8ULL,
		0xC242905D431E7D8CULL,
		0x12443AF9F132A575ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x811A000495902081ULL,
		0xD020000088200800ULL,
		0x044508448B628C56ULL,
		0x840249064B218AB8ULL,
		0x0082D078050808AAULL,
		0x6111C428000003C0ULL,
		0x8002801D42184C0CULL,
		0x120412A9C1108505ULL
	}};
	printf("Test Case 122\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 122 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -122;
	} else {
		printf("Test Case 122 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA6047146671B5A74ULL,
		0x0789BF4770EFE7E7ULL,
		0x2FD8030DB7BD3ED1ULL,
		0x914E3349B2DC34D2ULL,
		0x481175A88683AE28ULL,
		0x5E775744302464FAULL,
		0xBC9BE08A4342AD37ULL,
		0x45E0BAA90F452159ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC93C4B24AD569D2EULL,
		0xE3C5886A8FD5901EULL,
		0xCED46CF6FBCA7CF1ULL,
		0x6BA1B949409521F7ULL,
		0x62BDA7693440AE30ULL,
		0xE61384E70EF09625ULL,
		0x9CE61989997190DFULL,
		0x1176EC0D44EA344BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8004410425121824ULL,
		0x0381884200C58006ULL,
		0x0ED00004B3883CD1ULL,
		0x01003149009420D2ULL,
		0x401125280400AE20ULL,
		0x4613044400200420ULL,
		0x9C82008801408017ULL,
		0x0160A80904402049ULL
	}};
	printf("Test Case 123\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 123 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -123;
	} else {
		printf("Test Case 123 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA8CCF9407EBBAD06ULL,
		0x8FD6DBC3D41DDBEEULL,
		0x57972D5C7B480AC8ULL,
		0xDE9EB9D842830407ULL,
		0xBDC40F5E2B29E1F1ULL,
		0x41F768A74AAB496EULL,
		0x563F9719FC798EFDULL,
		0x4B7FB5D49ACDA3A4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEA65C179B6390B19ULL,
		0xD87FED29F7E96712ULL,
		0x82BDD1B73CCE5927ULL,
		0xFA83DA91D32AF654ULL,
		0x166CA2A0BEC26FB4ULL,
		0x90BAF59266E1E53BULL,
		0xCF9281EE7E48792CULL,
		0xA1E57C85364D434BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA844C14036390900ULL,
		0x8856C901D4094302ULL,
		0x0295011438480800ULL,
		0xDA82989042020404ULL,
		0x144402002A0061B0ULL,
		0x00B2608242A1412AULL,
		0x461281087C48082CULL,
		0x01653484124D0300ULL
	}};
	printf("Test Case 124\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 124 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -124;
	} else {
		printf("Test Case 124 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC4D6216AD222C494ULL,
		0x7C90F8909F52EA4AULL,
		0xF577A1250E9937C3ULL,
		0xCDD4D582090BE6D7ULL,
		0x5D11D93F0724C7A2ULL,
		0x35B2A3D1D39E7329ULL,
		0x9951CF041A145DBEULL,
		0x2FDB47BE3440933BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x780130ED061DA7AAULL,
		0x4714EB2120B39A72ULL,
		0x333CE0B3DA811FCAULL,
		0x92AC48F2F64C2A4EULL,
		0xAB6AEE1754F2A94EULL,
		0x23C979E3D6EED272ULL,
		0x944F3260DA96A16DULL,
		0x11AF4E8553ED05E0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4000206802008480ULL,
		0x4410E80000128A42ULL,
		0x3134A0210A8117C2ULL,
		0x8084408200082246ULL,
		0x0900C81704208102ULL,
		0x218021C1D28E5220ULL,
		0x904102001A14012CULL,
		0x018B468410400120ULL
	}};
	printf("Test Case 125\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 125 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -125;
	} else {
		printf("Test Case 125 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6C83663E693695B3ULL,
		0x47A7435807D3E5F1ULL,
		0x1195CA6B184E876AULL,
		0xAB0EB1BE60F7A5A0ULL,
		0xB76D6CF6CD5AC888ULL,
		0x280B1B7098604A98ULL,
		0x0F538DDEF154F5BFULL,
		0x840E9AC01730AEBDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4B647640A6E16215ULL,
		0xCB464AA96B12257FULL,
		0x54E9E93ACDD9D528ULL,
		0xB1526BE27AA18348ULL,
		0x90698DDAA3653630ULL,
		0x678B25CD8934CAD2ULL,
		0x659BA8142F60CD11ULL,
		0x77F0A345234ED204ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4800660020200011ULL,
		0x4306420803122571ULL,
		0x1081C82A08488528ULL,
		0xA10221A260A18100ULL,
		0x90690CD281400000ULL,
		0x200B014088204A90ULL,
		0x051388142140C511ULL,
		0x0400824003008204ULL
	}};
	printf("Test Case 126\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 126 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -126;
	} else {
		printf("Test Case 126 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC8F91A77433181B6ULL,
		0xB35E47AB5650974FULL,
		0x39EF27A306211797ULL,
		0x23E25CCAF24D1C0DULL,
		0xCB782153CA28FF40ULL,
		0x38B941E2AFCD5D59ULL,
		0xE6C2F2C8C1F79873ULL,
		0x765F75395F89B787ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x77C3FA64ED32C780ULL,
		0x6A29EAD4D02E1F15ULL,
		0xABE71F919CB46F60ULL,
		0x8C9825360F91928BULL,
		0xAA8D8699E77FFA5FULL,
		0x5F952A6DD6E268A6ULL,
		0xC90B0CD4D98E77B1ULL,
		0xBA5AAD85F39166CDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x40C11A6441308180ULL,
		0x2208428050001705ULL,
		0x29E7078104200700ULL,
		0x0080040202011009ULL,
		0x8A080011C228FA40ULL,
		0x1891006086C04800ULL,
		0xC00200C0C1861031ULL,
		0x325A250153812685ULL
	}};
	printf("Test Case 127\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 127 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -127;
	} else {
		printf("Test Case 127 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5B7BA47DD3DDEF46ULL,
		0x58972CADAEA6066FULL,
		0x671699509CA34438ULL,
		0x4B92E82DE952508BULL,
		0x00FC3AD6A97571A8ULL,
		0x2A4B6F9944851153ULL,
		0xF7B5E9B28C3FB67CULL,
		0x430C971DDE9D76E7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCD6F4553019B415BULL,
		0x266D11D732D28B26ULL,
		0xE39A53E814969C21ULL,
		0x0A4F6DD54FCABB1BULL,
		0x5563AEAB8E05EF9BULL,
		0x920B089C9D1FE71FULL,
		0x21FB3ECF5F669CC7ULL,
		0xD2548E78BEAAB76FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x496B045101994142ULL,
		0x0005008522820226ULL,
		0x6312114014820420ULL,
		0x0A0268054942100BULL,
		0x00602A8288056188ULL,
		0x020B089804050113ULL,
		0x21B128820C269444ULL,
		0x420486189E883667ULL
	}};
	printf("Test Case 128\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 128 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -128;
	} else {
		printf("Test Case 128 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x02337E205798A777ULL,
		0x9E9347FED8A637E2ULL,
		0x7EAE9B53C1EC4DA1ULL,
		0x4D9F450EB22072BDULL,
		0x816211188BA61541ULL,
		0x5631BA3B3F687F77ULL,
		0xB31697DC35B9984FULL,
		0x084DF8F66CF00B47ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x77746510803C5352ULL,
		0xE1B9B21D41C2C00CULL,
		0xB06CFC34FDC3318FULL,
		0x21EA34176F685954ULL,
		0xBB68AAC36EBF507FULL,
		0xEA28BCE3C2573135ULL,
		0x112771257A87BCD8ULL,
		0x5ECF7C13F74DCBC5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0230640000180352ULL,
		0x8091021C40820000ULL,
		0x302C9810C1C00181ULL,
		0x018A040622205014ULL,
		0x816000000AA61041ULL,
		0x4220B82302403135ULL,
		0x1106110430819848ULL,
		0x084D781264400B45ULL
	}};
	printf("Test Case 129\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 129 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -129;
	} else {
		printf("Test Case 129 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFA933D3422B62B63ULL,
		0x48C59213F629CEA7ULL,
		0xF53998B1B716CFF7ULL,
		0x7B5596D7123EEDB6ULL,
		0x091B3EEB7CBF2D8DULL,
		0x9E62D459A403401DULL,
		0x70998B6E9AFD9C87ULL,
		0x4B11894C50D9A6F7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7E5AF221403BC7C1ULL,
		0xEFB57445F2C1A91CULL,
		0x37C8AA78F1AC625AULL,
		0xB7EEB27D02140190ULL,
		0xB32F92D6D0646856ULL,
		0x6F71E54CCC765BA0ULL,
		0x4B4BE3EC661CD8B7ULL,
		0x5A425518A5369B64ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7A12302000320341ULL,
		0x48851001F2018804ULL,
		0x35088830B1044252ULL,
		0x3344925502140190ULL,
		0x010B12C250242804ULL,
		0x0E60C44884024000ULL,
		0x4009836C021C9887ULL,
		0x4A00010800108264ULL
	}};
	printf("Test Case 130\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 130 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -130;
	} else {
		printf("Test Case 130 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA5DAE65E1F5FF5F2ULL,
		0x0D45FB5E311A1053ULL,
		0x134A24B421CF7AC5ULL,
		0x090A93930FE52FB4ULL,
		0x12191E527495C368ULL,
		0x1FC79FE9696F3179ULL,
		0x69D3E01289317CB9ULL,
		0x5CE14B2C57DF2831ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x01B307C703E45D8FULL,
		0xAA4DCADA0139CA6FULL,
		0x965E33581E2F66ACULL,
		0xB2654E31EC2495E5ULL,
		0xCBC33D56E6B11C21ULL,
		0x02EDD7F396640419ULL,
		0x39180EBBA0A982BDULL,
		0x09E436A151C50A2BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0192064603445582ULL,
		0x0845CA5A01180043ULL,
		0x124A2010000F6284ULL,
		0x000002110C2405A4ULL,
		0x02011C5264910020ULL,
		0x02C597E100640019ULL,
		0x29100012802100B9ULL,
		0x08E0022051C50821ULL
	}};
	printf("Test Case 131\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 131 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -131;
	} else {
		printf("Test Case 131 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8CFA37810963873BULL,
		0x439099B94C15FD17ULL,
		0x00BF709323A363A7ULL,
		0x90626B702FB9770BULL,
		0xA67FEB878C875C75ULL,
		0x326BA468B56759F9ULL,
		0xB0C90086042ABEB4ULL,
		0xB741EA309A0EB338ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x20D4A9218AD9E364ULL,
		0x2285A5F52A3A689FULL,
		0x1658B4D1CD847C7CULL,
		0x65E7205080BC3588ULL,
		0x2D74F1B05048AB97ULL,
		0xA67AE7FED1192897ULL,
		0x13C046ED8F6759A6ULL,
		0x9C1072A1A7561A7FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x00D0210108418320ULL,
		0x028081B108106817ULL,
		0x0018309101806024ULL,
		0x0062205000B83508ULL,
		0x2474E18000000815ULL,
		0x226AA46891010891ULL,
		0x10C00084042218A4ULL,
		0x9400622082061238ULL
	}};
	printf("Test Case 132\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 132 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -132;
	} else {
		printf("Test Case 132 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x868AA5EE94A22BBAULL,
		0xF8CEFA76C1730288ULL,
		0xEE08FE988F60CEB0ULL,
		0xA0DBA1917572192BULL,
		0xA4BB221F0F695A9CULL,
		0xC37CD528EB1787F1ULL,
		0x422C3C1AC20EA86AULL,
		0xB31EBC157B48BC22ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD891E50B37447C35ULL,
		0x9A52ED1AB2F5FAB2ULL,
		0xD0D52CEC5DF898EDULL,
		0x453BAE99BD366DB7ULL,
		0xD3F1340C5EAC3976ULL,
		0x662324ABA15953B1ULL,
		0xCD5BA6E9931F85DCULL,
		0xC7323896FFA15135ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8080A50A14002830ULL,
		0x9842E81280710280ULL,
		0xC0002C880D6088A0ULL,
		0x001BA09135320923ULL,
		0x80B1200C0E281814ULL,
		0x42200428A11103B1ULL,
		0x40082408820E8048ULL,
		0x831238147B001020ULL
	}};
	printf("Test Case 133\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 133 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -133;
	} else {
		printf("Test Case 133 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x96EED59235040D11ULL,
		0xC561D7834F84B746ULL,
		0x284B740E5C69FD6BULL,
		0x1F07A745F1C6855DULL,
		0xD4B2AB9C298A6086ULL,
		0x9AB9E6E5B86E9328ULL,
		0xC4773CF0F713CBC3ULL,
		0xC53A1E9BC110004CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEB868479C0465530ULL,
		0x8B0CB8B264670AA0ULL,
		0xBB55ED06AC1ED89BULL,
		0x3AE88EE19D05CCF4ULL,
		0xE7437DE76F09DFB5ULL,
		0xE59C22C403AB6690ULL,
		0xE192D33A626AA862ULL,
		0x05DBB42FD0C12DF5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8286841000040510ULL,
		0x8100908244040200ULL,
		0x284164060C08D80BULL,
		0x1A00864191048454ULL,
		0xC402298429084084ULL,
		0x809822C4002A0200ULL,
		0xC012103062028842ULL,
		0x051A140BC0000044ULL
	}};
	printf("Test Case 134\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 134 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -134;
	} else {
		printf("Test Case 134 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFAF5F8E63A0AB9D1ULL,
		0xF04DA98FB0645930ULL,
		0xA45C9625647DF4CBULL,
		0xA5573705AB8A4854ULL,
		0x0C23A8CC3723D6DFULL,
		0x7768B4CCEE48CA4DULL,
		0x1D7869F771981263ULL,
		0xC314200E10113F03ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA48461565D32311AULL,
		0x565FE817D48DE31CULL,
		0xC0D0548FA5FEDD6CULL,
		0xC90196C66A791727ULL,
		0xFD53294C30C75552ULL,
		0xB48FD382B7CF8DC0ULL,
		0x3DCAC6F2FCE64054ULL,
		0x4C454618401D637DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA084604618023110ULL,
		0x504DA80790044110ULL,
		0x80501405247CD448ULL,
		0x810116042A080004ULL,
		0x0C03284C30035452ULL,
		0x34089080A6488840ULL,
		0x1D4840F270800040ULL,
		0x4004000800112301ULL
	}};
	printf("Test Case 135\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 135 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -135;
	} else {
		printf("Test Case 135 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x26956F14F8497225ULL,
		0xD2B61FCD5075031FULL,
		0x0DE09F67A01F3AA7ULL,
		0x0FE042FC3AB72C20ULL,
		0xEE9346698E048FD7ULL,
		0x839EACEC2A504A51ULL,
		0x60CBC0215369D126ULL,
		0xB15BE752069A8A9EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1B94D4DF26FDB7A1ULL,
		0x20112223F4027FEEULL,
		0x09DE49B94EAFFF21ULL,
		0xD37346913DE6D4DBULL,
		0x3EC7FA3711AA733FULL,
		0x4589E25716014136ULL,
		0xA7E4BC898DB93438ULL,
		0x86BB7D1D5FF561C1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0294441420493221ULL,
		0x001002015000030EULL,
		0x09C00921000F3A21ULL,
		0x0360429038A60400ULL,
		0x2E83422100000317ULL,
		0x0188A04402004010ULL,
		0x20C0800101291020ULL,
		0x801B651006900080ULL
	}};
	printf("Test Case 136\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 136 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -136;
	} else {
		printf("Test Case 136 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x32DF124B271CF38FULL,
		0x84196EF268340B42ULL,
		0x75B8F23595880238ULL,
		0x13CA61206A06588BULL,
		0x292F14CC78D1BED8ULL,
		0x57D9EBA81B3BDD44ULL,
		0xBB046E9B60EA678EULL,
		0x534B5FD604109C85ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2D0AB2F692AB3A5BULL,
		0x71E89306226F9606ULL,
		0x7DFBDEB5918E0B95ULL,
		0x697586DE6E24B73EULL,
		0x6B1C236945E3278AULL,
		0x2A318144D1E8C5CBULL,
		0x4F8A358E33D56244ULL,
		0xBD601B2B4E9E4649ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x200A12420208320BULL,
		0x0008020220240202ULL,
		0x75B8D23591880210ULL,
		0x014000006A04100AULL,
		0x290C004840C12688ULL,
		0x021181001128C540ULL,
		0x0B00248A20C06204ULL,
		0x11401B0204100401ULL
	}};
	printf("Test Case 137\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 137 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -137;
	} else {
		printf("Test Case 137 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD0912CC8814B7145ULL,
		0xFC096898C252E158ULL,
		0xC7FCE488D228A7EAULL,
		0xE244E8510BDD9E22ULL,
		0x5E7413E446CCD452ULL,
		0xE33F6401127CD1E2ULL,
		0x4323412746441264ULL,
		0xC70F5443CC3F37DAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6085DD06F651F8E5ULL,
		0x28EDAA50B0886414ULL,
		0xE1F3FFC2AE1387EEULL,
		0x7EC8533ADF8070ADULL,
		0x0F3A34CAF71D2EEBULL,
		0x8EF91AF54E127D16ULL,
		0x4262278807147B6CULL,
		0xF844A0D83050D20AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x40810C0080417045ULL,
		0x2809281080006010ULL,
		0xC1F0E480820087EAULL,
		0x624040100B801020ULL,
		0x0E3010C0460C0442ULL,
		0x8239000102105102ULL,
		0x4222010006041264ULL,
		0xC00400400010120AULL
	}};
	printf("Test Case 138\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 138 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -138;
	} else {
		printf("Test Case 138 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE53555435682C14CULL,
		0x95E278CB4461C870ULL,
		0x186ED18D7D7E7EA8ULL,
		0x02626EE321204654ULL,
		0xA0FA56BEAEDB8A65ULL,
		0x5829F2C2E98F36CFULL,
		0xEE3C1AB31B2C5634ULL,
		0x87339CD2507E3332ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2B365F66481E8DCAULL,
		0x4A55AFDDC9390D01ULL,
		0x65DA65B3DCC2CEDAULL,
		0x56D579FB1B4E2728ULL,
		0x7B656477D11C3A1CULL,
		0x3E3C5E409C0F942EULL,
		0x3410CAE56B68D7A3ULL,
		0x2A37D39EC939841CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2134554240028148ULL,
		0x004028C940210800ULL,
		0x004A41815C424E88ULL,
		0x024068E301000600ULL,
		0x2060443680180A04ULL,
		0x18285240880F140EULL,
		0x24100AA10B285620ULL,
		0x0233909240380010ULL
	}};
	printf("Test Case 139\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 139 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -139;
	} else {
		printf("Test Case 139 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9CF17DD13A03923FULL,
		0x7D38736B589A7618ULL,
		0x01C4EF199055BF06ULL,
		0x660B7DBFA329524AULL,
		0x3CFEE2713FD67072ULL,
		0xB3850BAF3AD72041ULL,
		0x61C5AC7964875173ULL,
		0x6F9ECBCCE3D1B041ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD2F5B5DB85DDEC74ULL,
		0x54F6E2D15A4761C3ULL,
		0x6C05664037BCD2D2ULL,
		0x58D05BC64C17E98BULL,
		0x1A6C6A6D6129FE4FULL,
		0x7E2B98345B605C25ULL,
		0xFC5D159A7E63043EULL,
		0xF906CB8EC3F6404DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x90F135D100018034ULL,
		0x5430624158026000ULL,
		0x0004660010149202ULL,
		0x400059860001400AULL,
		0x186C626121007042ULL,
		0x320108241A400001ULL,
		0x6045041864030032ULL,
		0x6906CB8CC3D00041ULL
	}};
	printf("Test Case 140\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 140 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -140;
	} else {
		printf("Test Case 140 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x742FC358E93CA7B0ULL,
		0xBE6EEF027D0D3CBFULL,
		0xDB1725D6DE9C72A8ULL,
		0x39F99A7CFE65301BULL,
		0x9AA914DEAC525DD3ULL,
		0x94EFA4C3600E5234ULL,
		0xAD16CEBDE755C83DULL,
		0xC764941FD6D047BAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7274BE5DF600FF58ULL,
		0x25A27DC5433EEDD6ULL,
		0x82C1D3718D4A5570ULL,
		0x91B0622530B26A5BULL,
		0x90FEF9EE263A9111ULL,
		0x1E2965640ED5C453ULL,
		0x8323C1CB1F037D4DULL,
		0xB0B583EFAB8EFBD0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x70248258E000A710ULL,
		0x24226D00410C2C96ULL,
		0x820101508C085020ULL,
		0x11B002243020201BULL,
		0x90A810CE24121111ULL,
		0x1429244000044010ULL,
		0x8102C0890701480DULL,
		0x8024800F82804390ULL
	}};
	printf("Test Case 141\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 141 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -141;
	} else {
		printf("Test Case 141 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF1A32C3A45501EB7ULL,
		0x1708C04691602F24ULL,
		0xA16F44FAC3986502ULL,
		0xC8BB3A1A67FFBFE0ULL,
		0xE69E6E6D28127E9FULL,
		0xA566B42B68433A13ULL,
		0x3067DD1A56142A2EULL,
		0x9E6E318E2B40A4F2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA57E4FFFFA9EB8E4ULL,
		0x26A1EBE1E14C2BC3ULL,
		0x696F2C5F7D0E4F89ULL,
		0x562D465C92AB436EULL,
		0xCC8AC36B716E777FULL,
		0x30A552794219D565ULL,
		0x38551F62479D8929ULL,
		0xFCB127BCF179C357ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA1220C3A401018A4ULL,
		0x0600C04081402B00ULL,
		0x216F045A41084500ULL,
		0x4029021802AB0360ULL,
		0xC48A42692002761FULL,
		0x2024102940011001ULL,
		0x30451D0246140828ULL,
		0x9C20218C21408052ULL
	}};
	printf("Test Case 142\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 142 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -142;
	} else {
		printf("Test Case 142 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5D28304C2E1E8672ULL,
		0x83646D2F4F744F10ULL,
		0xFBDC10D5D52AD9D3ULL,
		0x3A80D0D9596EA4ABULL,
		0xA654D0DD8CE51145ULL,
		0xF26B9E04DD1BD033ULL,
		0x7EB9319314C19EECULL,
		0xC933D3AD4D93FF47ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1311B5811DC1CA1AULL,
		0xF282597A7C47A58EULL,
		0xC1A2F115D166A336ULL,
		0xA15D5D8044A141F0ULL,
		0xB5182A06C9654040ULL,
		0xF3411EFDD8F919D7ULL,
		0xEE1AD87B3A9ACAA2ULL,
		0x4EC8926FDEC677C1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x110030000C008212ULL,
		0x8200492A4C440500ULL,
		0xC1801015D1228112ULL,
		0x20005080402000A0ULL,
		0xA410000488650040ULL,
		0xF2411E04D8191013ULL,
		0x6E18101310808AA0ULL,
		0x4800922D4C827741ULL
	}};
	printf("Test Case 143\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 143 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -143;
	} else {
		printf("Test Case 143 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x00BC362E9C43E2D9ULL,
		0x04790015CA7BCE36ULL,
		0x3AFB8E778DB5811DULL,
		0xB4EFFE2ADB63723DULL,
		0x422CAC0000F2D03AULL,
		0x9C90991780859564ULL,
		0xA7ACB444050E4641ULL,
		0xD44E37A9190E6F63ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x83E16B7FC1BA4DDBULL,
		0xAD694390BF99AF71ULL,
		0xEE77520A4817798DULL,
		0x72EBBDF0BCC81BBCULL,
		0xD39D1F7E8B1D38F1ULL,
		0xFBA7494655BC06BBULL,
		0xE12D7B66448A8824ULL,
		0x42755133B74E103FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x00A0222E800240D9ULL,
		0x046900108A198E30ULL,
		0x2A7302020815010DULL,
		0x30EBBC209840123CULL,
		0x420C0C0000101030ULL,
		0x9880090600840420ULL,
		0xA12C3044040A0000ULL,
		0x40441121110E0023ULL
	}};
	printf("Test Case 144\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 144 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -144;
	} else {
		printf("Test Case 144 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x532A9D8B9B365BDEULL,
		0xF0DE745C9EE957BBULL,
		0xA9CE7058A0A78EB2ULL,
		0xAFBFFA36A4517CE2ULL,
		0x68AD701373476FC9ULL,
		0x2B8821AE5DA41B61ULL,
		0xC9DE0B476D8FE863ULL,
		0x8B001B4AA203E8B9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC377E74A77226261ULL,
		0x40CAE9BFA368E842ULL,
		0x6D74C8E583A3D601ULL,
		0x04E67075D0DDA4A2ULL,
		0xB005A845DA4C38FBULL,
		0x0E62D988C201A831ULL,
		0xE0B47F47D871C69DULL,
		0x265F9FA8C6ABD089ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4322850A13224240ULL,
		0x40CA601C82684002ULL,
		0x2944404080A38600ULL,
		0x04A67034805124A2ULL,
		0x20052001524428C9ULL,
		0x0A00018840000821ULL,
		0xC0940B474801C001ULL,
		0x02001B088203C089ULL
	}};
	printf("Test Case 145\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 145 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -145;
	} else {
		printf("Test Case 145 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x05A059228773F589ULL,
		0x8F84C4EB9A79986BULL,
		0x44237E90467B8390ULL,
		0x65E6EFBA79AE0D83ULL,
		0x547AFFC48DD7854AULL,
		0x5EEC10053B74D771ULL,
		0x26F77DBA72D3E60DULL,
		0xD5D0F1B66DDFACA3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0A8DA56A66CD49A2ULL,
		0x34CCE9787903CBE0ULL,
		0xF862B49868E87A34ULL,
		0xD79CDA6867EF5763ULL,
		0x52C0A69EDBD8D7FCULL,
		0xE80CE1DF24A2B380ULL,
		0x49659D4F24B24A3EULL,
		0x9B72A4C3666F00CAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0080012206414180ULL,
		0x0484C06818018860ULL,
		0x4022349040680210ULL,
		0x4584CA2861AE0503ULL,
		0x5040A68489D08548ULL,
		0x480C000520209300ULL,
		0x00651D0A2092420CULL,
		0x9150A082644F0082ULL
	}};
	printf("Test Case 146\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 146 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -146;
	} else {
		printf("Test Case 146 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x727E2F8B71744D76ULL,
		0xAD5AA28F4C5E27ABULL,
		0xC8BC362F831D6DD7ULL,
		0xD4622FCBBF7844F3ULL,
		0xAC873AAEE173D8E0ULL,
		0x406AEEBD76F38745ULL,
		0xD71D9E67878C7666ULL,
		0xFD77D6979A542492ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC071DFCAFC278FD9ULL,
		0x351835CDD86F5B74ULL,
		0x3C1158F976F3D9D0ULL,
		0x9D3108CBCD327CCDULL,
		0x63117EF32B5172A1ULL,
		0xF05DB922E235A73AULL,
		0x8F3E9992434C7683ULL,
		0xB3B42FDC1D6763C1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x40700F8A70240D50ULL,
		0x2518208D484E0320ULL,
		0x08101029021149D0ULL,
		0x942008CB8D3044C1ULL,
		0x20013AA2215150A0ULL,
		0x4048A82062318700ULL,
		0x871C9802030C7602ULL,
		0xB134069418442080ULL
	}};
	printf("Test Case 147\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 147 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -147;
	} else {
		printf("Test Case 147 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3C4358E968ED5EFBULL,
		0x3F434AE4B3334425ULL,
		0x1A6A695205A67E74ULL,
		0x747F6FD4D99210DEULL,
		0x285EF1B9166897B0ULL,
		0x30067AC986A4F36DULL,
		0x1C47C54D386F7E3EULL,
		0x129DA847F8CEFBFDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x426332B3E0A44B87ULL,
		0xDF076A3D9FF92695ULL,
		0x8D29DC09292803BFULL,
		0xCAB6E212E7720B4CULL,
		0x8AA0A080CA675CB1ULL,
		0x6049F714BD782645ULL,
		0x27F9FAE5A0CBCC2FULL,
		0x1387E7CBC81CB4DBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x004310A160A44A83ULL,
		0x1F034A2493310405ULL,
		0x0828480001200234ULL,
		0x40366210C112004CULL,
		0x0800A080026014B0ULL,
		0x2000720084202245ULL,
		0x0441C045204B4C2EULL,
		0x1285A043C80CB0D9ULL
	}};
	printf("Test Case 148\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 148 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -148;
	} else {
		printf("Test Case 148 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7E456ED5EFAAF7CFULL,
		0xB756B8898B1774FEULL,
		0xB1BD27D46FF44A78ULL,
		0xDC61B3142FF13C47ULL,
		0x256C4794E9E73094ULL,
		0xAB7266724A00B489ULL,
		0x620713405E9CA3DBULL,
		0x492198CD483C87E4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x91EACFC7C505D0C3ULL,
		0xB8E1D5E217F30E31ULL,
		0xD3F53FB1E8AFD3B4ULL,
		0x66362DDF8F610510ULL,
		0xFA25888309D6762EULL,
		0xE13E8277911B8B78ULL,
		0xD4EAECB059EE7D96ULL,
		0xCA59107FE337CB59ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x10404EC5C500D0C3ULL,
		0xB040908003130430ULL,
		0x91B5279068A44230ULL,
		0x442021140F610400ULL,
		0x2024008009C63004ULL,
		0xA132027200008008ULL,
		0x40020000588C2192ULL,
		0x4801104D40348340ULL
	}};
	printf("Test Case 149\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 149 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -149;
	} else {
		printf("Test Case 149 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2900569F38A72445ULL,
		0x86C6AF1CE841ED54ULL,
		0x97F4C9B3299C1E24ULL,
		0x4CC4350606D7B749ULL,
		0x66E29256A9F4FE11ULL,
		0x4CD70DD1EAA1EAD0ULL,
		0xBDAF6C03909BBD38ULL,
		0xD0CF7FBDEEEAD8E0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD281F3C90CEE0292ULL,
		0x10CB5D83BA6DC7F4ULL,
		0x1439CDBE30EA6185ULL,
		0xB4076408088B7B50ULL,
		0xC8D4BFFCD3994DF1ULL,
		0x3C5D1A7DFB10831FULL,
		0x29721F9F840AC2F1ULL,
		0x953F92709C26AE2EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0000528908A60000ULL,
		0x00C20D00A841C554ULL,
		0x1430C9B220880004ULL,
		0x0404240000833340ULL,
		0x40C0925481904C11ULL,
		0x0C550851EA008210ULL,
		0x29220C03800A8030ULL,
		0x900F12308C228820ULL
	}};
	printf("Test Case 150\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 150 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -150;
	} else {
		printf("Test Case 150 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8F70AEFC99230EA0ULL,
		0x9402ECD3DDCE76CAULL,
		0xEF7AA900B9EDD794ULL,
		0x07C470078363B887ULL,
		0x7D612B7DC2768B4EULL,
		0x377ED81B6736A431ULL,
		0x752933A2C18591D4ULL,
		0x3F4FF2A0585E8648ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5FE558199AA369D1ULL,
		0x24A8B0F8DFB104B8ULL,
		0xD1E9C696718417F1ULL,
		0x005C547CCBCA258CULL,
		0xFBD3982A0763580AULL,
		0x31DF241ED297A85FULL,
		0xA8773FD43A514B1EULL,
		0xB9A223079E07CBDEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0F60081898230880ULL,
		0x0400A0D0DD800488ULL,
		0xC168800031841790ULL,
		0x0044500483422084ULL,
		0x794108280262080AULL,
		0x315E001A4216A011ULL,
		0x2021338000010114ULL,
		0x3902220018068248ULL
	}};
	printf("Test Case 151\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 151 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -151;
	} else {
		printf("Test Case 151 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0040FDFDB0F5AFD3ULL,
		0x8EF31C614F8F04AEULL,
		0xEDDE08656C77BB3FULL,
		0xE5808179C52858BCULL,
		0xE96C20CC2E673584ULL,
		0x09A424C77130B2A5ULL,
		0x26FF74E2664077E6ULL,
		0x7020CCC101B148B2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x860F4DD0813A4A58ULL,
		0x12A055B538CE64DBULL,
		0x4504EE22C10FC1D9ULL,
		0xE94C3199716C68C5ULL,
		0x7166CA1FDCB70D4DULL,
		0x5E5698802C92801AULL,
		0x79B9EBA777AA5EEFULL,
		0xB2F29DCFF6A64E19ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x00004DD080300A50ULL,
		0x02A01421088E048AULL,
		0x4504082040078119ULL,
		0xE100011941284884ULL,
		0x6164000C0C270504ULL,
		0x0804008020108000ULL,
		0x20B960A2660056E6ULL,
		0x30208CC100A04810ULL
	}};
	printf("Test Case 152\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 152 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -152;
	} else {
		printf("Test Case 152 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1DB02C88C70A23B6ULL,
		0x08C9D56E65225E79ULL,
		0xF6914BE564ECD95DULL,
		0x429D55CEA449917AULL,
		0xDE79C045A5E7FA99ULL,
		0x1233C3B7FF253F5BULL,
		0x780CB0C86D8DA3EFULL,
		0x2355E644E924B893ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD554D91267203D9BULL,
		0xF1407070DAABC08CULL,
		0x7C4BDF24D43728CAULL,
		0x7986721D1C41C750ULL,
		0xFDB996E6C1A5D9B1ULL,
		0x442FFF8BFF37D5EEULL,
		0x0F22A1649F584A4EULL,
		0x6F11020681A16C57ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1510080047002192ULL,
		0x0040506040224008ULL,
		0x74014B2444240848ULL,
		0x4084500C04418150ULL,
		0xDC39804481A5D891ULL,
		0x0023C383FF25154AULL,
		0x0800A0400D08024EULL,
		0x2311020481202813ULL
	}};
	printf("Test Case 153\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 153 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -153;
	} else {
		printf("Test Case 153 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x48671B9DE538CD14ULL,
		0xF769A57652C2E7D7ULL,
		0x545C4C786A1749F1ULL,
		0x906363BA6D52E660ULL,
		0x2D79CFCEFFD8B42DULL,
		0x95DAA1B62A51801FULL,
		0xF5B07A371026E0E0ULL,
		0x82EA8D1F713B4C05ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6E6E4B48A40B554FULL,
		0x0489E751E7447FD5ULL,
		0xB9D88A8B6E31E743ULL,
		0xDC857B063F35AC6EULL,
		0x37DCBA100F93F0FBULL,
		0x14865B169FEA1976ULL,
		0x056E62AFB59F7444ULL,
		0xEF185B3D0FBF9E7FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x48660B08A4084504ULL,
		0x0409A550424067D5ULL,
		0x105808086A114141ULL,
		0x900163022D10A460ULL,
		0x25588A000F90B029ULL,
		0x148201160A400016ULL,
		0x0520622710066040ULL,
		0x8208091D013B0C05ULL
	}};
	printf("Test Case 154\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 154 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -154;
	} else {
		printf("Test Case 154 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9DD3507A013BA3E8ULL,
		0x75F607749E866F19ULL,
		0xA0298A7F3FC0B3DDULL,
		0x0F907DC1F9055DFFULL,
		0xD981EC038FD8167BULL,
		0x73071D54DE35671FULL,
		0xD2F603447BAE34CCULL,
		0xFD9B11D1F02C8007ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDD23ECCE06397CCAULL,
		0x9D8420D6E7D30DEDULL,
		0x5A0B87EFAA73B631ULL,
		0x52D28BA30671E8ABULL,
		0x10F4D2C6264CCC3FULL,
		0x5CD6E6E3088BB458ULL,
		0x6604CC4FC3BCAF47ULL,
		0x6CD225A61B574D51ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9D03404A003920C8ULL,
		0x1584005486820D09ULL,
		0x0009826F2A40B211ULL,
		0x02900981000148ABULL,
		0x1080C0020648043BULL,
		0x5006044008012418ULL,
		0x4204004443AC2444ULL,
		0x6C92018010040001ULL
	}};
	printf("Test Case 155\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 155 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -155;
	} else {
		printf("Test Case 155 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x036B4BB8F84FA895ULL,
		0x473F0B2FC8DC6DCEULL,
		0xDBB9B0CDBFDEDF9DULL,
		0x2B3BC0E8196E1B61ULL,
		0x5A0B7BABD11FA4BFULL,
		0x8176F49BFC1FFA98ULL,
		0x5570D002B325A1F7ULL,
		0x66B715BC97461EAFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2CE832FFC8485EE4ULL,
		0x6A85BC0E6002487FULL,
		0x322026C05F50FF04ULL,
		0x13DE041E01E8BDC9ULL,
		0xA6368200ED1E6BC1ULL,
		0x7E93EC6C8FA5FD14ULL,
		0xDE86435639FB8CD9ULL,
		0x3782207C2F00557AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x006802B8C8480884ULL,
		0x4205080E4000484EULL,
		0x122020C01F50DF04ULL,
		0x031A000801681941ULL,
		0x02020200C11E2081ULL,
		0x0012E4088C05F810ULL,
		0x54004002312180D1ULL,
		0x2682003C0700142AULL
	}};
	printf("Test Case 156\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 156 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -156;
	} else {
		printf("Test Case 156 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF58F04F9FBF8D6AEULL,
		0xC69F71B0C8820A77ULL,
		0xFD8B66F452BA2D1DULL,
		0x4D91A0DE34364D21ULL,
		0xECA86C079D01BE59ULL,
		0xE828557EA1CEBBA0ULL,
		0x1D98512000A681F1ULL,
		0xF6F369E9C43B0913ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3442F7AC09D4F46BULL,
		0xCFD223EDB3387D44ULL,
		0x35843F245812C616ULL,
		0x9403A746FAE93F6BULL,
		0xA99844EA2717FF09ULL,
		0x6701E9248C7BF5F0ULL,
		0x04AA2BDB04B47DD3ULL,
		0xD30649CA0AE5105AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x340204A809D0D42AULL,
		0xC69221A080000844ULL,
		0x3580262450120414ULL,
		0x0401A04630200D21ULL,
		0xA88844020501BE09ULL,
		0x60004124804AB1A0ULL,
		0x0488010000A401D1ULL,
		0xD20249C800210012ULL
	}};
	printf("Test Case 157\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 157 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -157;
	} else {
		printf("Test Case 157 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEDA24E9D90C66FE8ULL,
		0xF6570E81D1396B84ULL,
		0xB598EB700E4400EEULL,
		0xE06A016347D30B2AULL,
		0x2F8480778466E945ULL,
		0xB251771A0E754B47ULL,
		0x7F69C8A91A4BB876ULL,
		0x19D221FE805EAAF7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1254207EE07F7439ULL,
		0x2D76FC5642488FF8ULL,
		0x63A1DCFBA01769AEULL,
		0xFCBA65DE1BC86194ULL,
		0x6ABEA28766A9214FULL,
		0x42887CCF51D75733ULL,
		0x4239F6A2E2C0C3F0ULL,
		0x194A8837E43E5F20ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0000001C80466428ULL,
		0x24560C0040080B80ULL,
		0x2180C870000400AEULL,
		0xE02A014203C00100ULL,
		0x2A84800704202145ULL,
		0x0200740A00554303ULL,
		0x4229C0A002408070ULL,
		0x19420036801E0A20ULL
	}};
	printf("Test Case 158\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 158 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -158;
	} else {
		printf("Test Case 158 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDEC8358A5D146099ULL,
		0x90C176E2AFA2A823ULL,
		0xDE5BB9AFA71EFB08ULL,
		0xC9A7A1A664C2814AULL,
		0x5F091BAB37987F6AULL,
		0x8B62D37092EFE585ULL,
		0xD3C855B21D74267AULL,
		0xD7194D666C59B5F1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x322179C9B0BCE544ULL,
		0x03F916E853B7DB76ULL,
		0xE070CFB465DF5A90ULL,
		0xA017A79C84B73A27ULL,
		0xD62F3E26F880E664ULL,
		0x8EBD7C2F14CFCCDEULL,
		0x587D543B653BC045ULL,
		0x6DB90B6381EE3AF2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1200318810146000ULL,
		0x00C116E003A28822ULL,
		0xC05089A4251E5A00ULL,
		0x8007A18404820002ULL,
		0x56091A2230806660ULL,
		0x8A20502010CFC484ULL,
		0x5048543205300040ULL,
		0x45190962004830F0ULL
	}};
	printf("Test Case 159\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 159 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -159;
	} else {
		printf("Test Case 159 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x84CE68E391359DFEULL,
		0x29F31AD66C00A885ULL,
		0x4CEA88CC99B8C36AULL,
		0xF0C6FB5C675041B8ULL,
		0xD5CEB52597578D26ULL,
		0x81B2C296B0C2124FULL,
		0xC57A25942B7C6902ULL,
		0x9ECB5948C861DE04ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9B009DAD58FD631DULL,
		0x04B8B373D2616B4CULL,
		0x3B7CCAF16394CCA2ULL,
		0xAE70C9B187437238ULL,
		0x3E89C73935124948ULL,
		0x460778ADDD65E7D9ULL,
		0x61911F8971296E77ULL,
		0x95C3C8CD86C4EC52ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x800008A11035011CULL,
		0x00B0125240002804ULL,
		0x086888C00190C022ULL,
		0xA040C91007404038ULL,
		0x1488852115120900ULL,
		0x0002408490400249ULL,
		0x4110058021286802ULL,
		0x94C348488040CC00ULL
	}};
	printf("Test Case 160\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 160 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -160;
	} else {
		printf("Test Case 160 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5F984115B308EF0EULL,
		0x57DA0774F47117C8ULL,
		0x60C130E54180650DULL,
		0x5152DBE6D8266888ULL,
		0x9171431B66B57A6AULL,
		0x8475C3896489033EULL,
		0xF0ED67A0EE9FBA3FULL,
		0xD9E48DA13DDA2CD7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC58C399605A5DA9BULL,
		0xD179CEA8D5F84E50ULL,
		0x884E92D8666BF759ULL,
		0x77CCDFB1DDCC8D53ULL,
		0x97C436939CE00DE9ULL,
		0xA764589AF4D86328ULL,
		0x9520445588071DA7ULL,
		0xF9BFC1E408247274ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x458801140100CA0AULL,
		0x51580620D4700640ULL,
		0x004010C040006509ULL,
		0x5140DBA0D8040800ULL,
		0x9140021304A00868ULL,
		0x8464408864880328ULL,
		0x9020440088071827ULL,
		0xD9A481A008002054ULL
	}};
	printf("Test Case 161\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 161 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -161;
	} else {
		printf("Test Case 161 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1825F6514E716B38ULL,
		0x49CB7C7897FF5129ULL,
		0x4BED4DE88A721AD9ULL,
		0x6FE4DB467595FB47ULL,
		0xB051F59BE953050CULL,
		0xF14DF439754B0D16ULL,
		0xF03426127EF630A5ULL,
		0xACB1CFF81C69AEC7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x08AD8101D2235172ULL,
		0x9AA5FCA8BAD18E31ULL,
		0x0EF852DFBC87EB36ULL,
		0xC093FDFEDEE26373ULL,
		0x64CEABB7EE13864DULL,
		0x7AACB6A0A6324254ULL,
		0x31A864C1A1B744C8ULL,
		0x232E2956DADF6FD1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0825800142214130ULL,
		0x08817C2892D10021ULL,
		0x0AE840C888020A10ULL,
		0x4080D94654806343ULL,
		0x2040A193E813040CULL,
		0x700CB42024020014ULL,
		0x3020240020B60080ULL,
		0x2020095018492EC1ULL
	}};
	printf("Test Case 162\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 162 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -162;
	} else {
		printf("Test Case 162 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x28B39927F72A94AFULL,
		0x6805BEF008E8AF8CULL,
		0x59370091A480AAF5ULL,
		0xD36059FE9E73071EULL,
		0x9138F6C06F3DCE4CULL,
		0x9AEBD5400D827110ULL,
		0x207F24F1CA9B7331ULL,
		0x7A03F45375880943ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD2660CFA62A133FFULL,
		0xCFB6922357DBF9A2ULL,
		0xE99D046384821D88ULL,
		0xA34F7CC9D75E1EB0ULL,
		0x980CE51BF4EB9CBEULL,
		0xD8410597D6E04688ULL,
		0x8527566DBC3456DEULL,
		0x0E0627F5D648EB87ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x00220822622010AFULL,
		0x4804922000C8A980ULL,
		0x4915000184800880ULL,
		0x834058C896520610ULL,
		0x9008E40064298C0CULL,
		0x9841050004804000ULL,
		0x0027046188105210ULL,
		0x0A02245154080903ULL
	}};
	printf("Test Case 163\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 163 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -163;
	} else {
		printf("Test Case 163 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x24819211AA0DBA77ULL,
		0x7659200289C35E40ULL,
		0xDF9F34777C43D781ULL,
		0xE9EC561A729509DEULL,
		0x5F42FE5F97F478AEULL,
		0x6030595F58B35781ULL,
		0x274D28BFD2A07E1AULL,
		0xB1FBF7EFBF7389FFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0347A08C5BB7744BULL,
		0x434B3141BDC9B29BULL,
		0xDB7DB02E59F03C5CULL,
		0xF7BAC539F6919111ULL,
		0xAFA6F975A05B7606ULL,
		0xAC6064541D5B14FFULL,
		0x7649D26935F13368ULL,
		0x6900C4639CF3AB9DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x000180000A053043ULL,
		0x4249200089C11200ULL,
		0xDB1D302658401400ULL,
		0xE1A8441872910110ULL,
		0x0F02F85580507006ULL,
		0x2020405418131481ULL,
		0x2649002910A03208ULL,
		0x2100C4639C73899DULL
	}};
	printf("Test Case 164\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 164 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -164;
	} else {
		printf("Test Case 164 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8A55743AEE5B6A25ULL,
		0x5087BCCCCBF87273ULL,
		0xC0CD77BAA9145A6CULL,
		0x3E6013D36C2294F3ULL,
		0x0B4A0D5DE0B32D18ULL,
		0x0CD1E621E6ED69CAULL,
		0xAB572F17A18ED8C0ULL,
		0x555F74D9B1839131ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0C654BC3D97C08C0ULL,
		0xA83C7BE722601C17ULL,
		0x7EB824795EE3E09FULL,
		0x3E09B0F6B2CA6551ULL,
		0xCDE6848027C55946ULL,
		0x0556C8AC75B929C1ULL,
		0xC4A5DC85720C3F68ULL,
		0x16AA72A2B4281386ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x08454002C8580800ULL,
		0x000438C402601013ULL,
		0x408824380800400CULL,
		0x3E0010D220020451ULL,
		0x0942040020810900ULL,
		0x0450C02064A929C0ULL,
		0x80050C05200C1840ULL,
		0x140A7080B0001100ULL
	}};
	printf("Test Case 165\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 165 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -165;
	} else {
		printf("Test Case 165 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x46A0201E717F79D7ULL,
		0x18A6953BC54CFDD3ULL,
		0xF76CE815DDFC854EULL,
		0xDF1D0044EEC38A2CULL,
		0xEA09D7AC14C50ED6ULL,
		0xD31D234252AE9F8AULL,
		0x25D9E5E909DC8C15ULL,
		0x418E71111126912EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x82C3B909EFEDD378ULL,
		0x7FB3E1466D3A7342ULL,
		0xDA9F70A3D57F421EULL,
		0x48EB8C83A42626B6ULL,
		0xF540F766C0DA0E99ULL,
		0x1E7FB5595FF9EEF4ULL,
		0x0CBCEA0101BBB613ULL,
		0x702BFC20FB533078ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x02802008616D5150ULL,
		0x18A2810245087142ULL,
		0xD20C6001D57C000EULL,
		0x48090000A4020224ULL,
		0xE000D72400C00E90ULL,
		0x121D214052A88E80ULL,
		0x0498E00101988411ULL,
		0x400A700011021028ULL
	}};
	printf("Test Case 166\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 166 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -166;
	} else {
		printf("Test Case 166 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB6852D16B1953963ULL,
		0x5B6A811695C0FCB1ULL,
		0xD1B43521B5F39212ULL,
		0x7588AC55A49F3AC7ULL,
		0x5E9A18981BB0D688ULL,
		0x0D7259CEBBD54642ULL,
		0xA4DD810455E6FD41ULL,
		0x842AD0B783EB7A91ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2DDD9E161A7830A1ULL,
		0xE3A117041B6842F3ULL,
		0x1DC3B230DA081F42ULL,
		0x415750CE14E0CB89ULL,
		0x3187D2A2AE0F2EB3ULL,
		0x62A4CDF70E443F91ULL,
		0x5FCBD415C080D9DCULL,
		0x5385E3C25B539188ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x24850C1610103021ULL,
		0x43200104114040B1ULL,
		0x1180302090001202ULL,
		0x4100004404800A81ULL,
		0x108210800A000680ULL,
		0x002049C60A440600ULL,
		0x04C980044080D940ULL,
		0x0000C08203431080ULL
	}};
	printf("Test Case 167\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 167 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -167;
	} else {
		printf("Test Case 167 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3468388C5F78A9E6ULL,
		0xA22467B695E71B3AULL,
		0xCF742441A866F38BULL,
		0xEF21F1B1F05C4B0AULL,
		0x085BE993E2B1596DULL,
		0xFB758A540E057A30ULL,
		0xE60580BA6DE9E170ULL,
		0xCCE9FDF0B7467650ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x140A7437524173E0ULL,
		0xFFF958C740756122ULL,
		0x57F36C8654A30189ULL,
		0x593364B910FFE886ULL,
		0x4F630FF58583A70CULL,
		0x338B610DCE092B5EULL,
		0x2A8E468860F20BB7ULL,
		0x395274FAAC604B10ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x14083004524021E0ULL,
		0xA220408600650122ULL,
		0x4770240000220189ULL,
		0x492160B1105C4802ULL,
		0x084309918081010CULL,
		0x330100040E012A10ULL,
		0x2204008860E00130ULL,
		0x084074F0A4404210ULL
	}};
	printf("Test Case 168\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 168 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -168;
	} else {
		printf("Test Case 168 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAB7E8E04E34A6151ULL,
		0xA96636BB2B16A96AULL,
		0x957FF2ED4CD437CBULL,
		0xCA5D043FFF145F66ULL,
		0x2968A32E389F8AB1ULL,
		0xF01F6FE92C424FFAULL,
		0x53CA4D35D471359FULL,
		0x9FB1518BEBD6AEE2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBCEFE90D1254F06CULL,
		0xB522A71AA85180D6ULL,
		0xBB2F6830C22CD406ULL,
		0x5ED375DCA19ACCBCULL,
		0x708EBCD42DCDB32CULL,
		0x7A2EFF04D4DC9BD6ULL,
		0x0E2C983782816B90ULL,
		0xBDF7DE059FBF9EEAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA86E880402406040ULL,
		0xA122261A28108042ULL,
		0x912F602040041402ULL,
		0x4A51041CA1104C24ULL,
		0x2008A004288D8220ULL,
		0x700E6F0004400BD2ULL,
		0x0208083580012190ULL,
		0x9DB150018B968EE2ULL
	}};
	printf("Test Case 169\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 169 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -169;
	} else {
		printf("Test Case 169 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1C15065DD95F1041ULL,
		0x51A0C6129AF5E7B8ULL,
		0x43EC883D61A1433BULL,
		0xB20B761C878C41D6ULL,
		0x292AF5ACD057346DULL,
		0x8BE4DA43C991583EULL,
		0x216A577915FE5899ULL,
		0x10B0E9CFC616A169ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1744A82510E52647ULL,
		0x890CAC23614B17E1ULL,
		0x300ACCF06A065E0DULL,
		0x817F15DEBF31CB79ULL,
		0x935A2C4FCB34BF9BULL,
		0x6D2C2755C1717FA4ULL,
		0xA43227D372AA70C6ULL,
		0x09EBA055D99752D2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1404000510450041ULL,
		0x01008402004107A0ULL,
		0x0008883060004209ULL,
		0x800B141C87004150ULL,
		0x010A240CC0143409ULL,
		0x09240241C1115824ULL,
		0x2022075110AA5080ULL,
		0x00A0A045C0160040ULL
	}};
	printf("Test Case 170\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 170 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -170;
	} else {
		printf("Test Case 170 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD99D24D82E687607ULL,
		0xA0F9D9026B0416DCULL,
		0x2F74F49BDF746C9AULL,
		0xFC8BFA93BC3F006EULL,
		0x8000C786E5A3DC17ULL,
		0xBBBCB1F99A0E33DFULL,
		0x405792579F4EC1B1ULL,
		0x248BFBE7D2320AA8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4EB29A20177E0305ULL,
		0x08FB6D40962D34B4ULL,
		0x3C3ADB9C70F33421ULL,
		0xE9CB7F553DBD56B0ULL,
		0xA6941F6D6DAC9511ULL,
		0x522C6020178E12AAULL,
		0x97E4A7BF25C9C549ULL,
		0xD62CEE5DDB6801B2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4890000006680205ULL,
		0x00F9490002041494ULL,
		0x2C30D09850702400ULL,
		0xE88B7A113C3D0020ULL,
		0x8000070465A09411ULL,
		0x122C2020120E128AULL,
		0x004482170548C101ULL,
		0x0408EA45D22000A0ULL
	}};
	printf("Test Case 171\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 171 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -171;
	} else {
		printf("Test Case 171 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAFA17F74E5807472ULL,
		0x9E8F3F14ABCA6C56ULL,
		0xE923650A1CBD56F1ULL,
		0xF95A1E06B5CC25B2ULL,
		0xA4137BA98D18CB25ULL,
		0xD378B4619D6BCC92ULL,
		0x088DD2C3D68E9088ULL,
		0x0A86E638675CD8BBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0901258052B47D9DULL,
		0xD8ECA45E84992B4FULL,
		0x2266D822DBB2201FULL,
		0xF1905AB30FED5DAEULL,
		0xE0BB004D9C4F66A0ULL,
		0x88188FF77C63FA78ULL,
		0xE5E8AD71DC3D121AULL,
		0xFD57EF1E0EE23949ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0901250040807410ULL,
		0x988C241480882846ULL,
		0x2022400218B00011ULL,
		0xF1101A0205CC05A2ULL,
		0xA01300098C084220ULL,
		0x801884611C63C810ULL,
		0x00888041D40C1008ULL,
		0x0806E61806401809ULL
	}};
	printf("Test Case 172\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 172 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -172;
	} else {
		printf("Test Case 172 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8784EDFE50F36B3AULL,
		0x5F107826ED10625CULL,
		0x3DCBE69BC4EF385FULL,
		0xDE2005550F6D6EBEULL,
		0xCFB25FA1F3AA5DE0ULL,
		0x99D8AA14F780DD23ULL,
		0x063901708C966314ULL,
		0xA83CCAC01FE7EC1DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDCAEA23F9BC6FAE5ULL,
		0x2573156586B670C0ULL,
		0xB42C769DFD3126CBULL,
		0x46DD77DB456A24A1ULL,
		0x714CD669582F9647ULL,
		0x8E51770F4C9EFFFEULL,
		0x0033B4AACA4B7A80ULL,
		0x873D18D47281B1F4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8484A03E10C26A20ULL,
		0x0510102484106040ULL,
		0x34086699C421204BULL,
		0x46000551056824A0ULL,
		0x41005621502A1440ULL,
		0x885022044480DD22ULL,
		0x0031002088026200ULL,
		0x803C08C01281A014ULL
	}};
	printf("Test Case 173\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 173 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -173;
	} else {
		printf("Test Case 173 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF37FC538DAE03676ULL,
		0xBA4101785A94EC3FULL,
		0x35124D9457FB8F3EULL,
		0xF540CB38636B00C5ULL,
		0x1D46FFBED384E2D7ULL,
		0xB3B538D8A90C99AFULL,
		0x4A94D0DA6B805924ULL,
		0xD33DB1EDF98A484DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x890E7074FB72B9A1ULL,
		0x233C9CEFD7DC3C47ULL,
		0x311841790563AD0AULL,
		0xCA5A9599396237E6ULL,
		0x0409963328696AABULL,
		0x1F033E238B71A7CDULL,
		0x85E6973644CF5D05ULL,
		0xCC10E0137D1185C8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x810E4030DA603020ULL,
		0x2200006852942C07ULL,
		0x3110411005638D0AULL,
		0xC0408118216200C4ULL,
		0x0400963200006283ULL,
		0x130138008900818DULL,
		0x0084901240805904ULL,
		0xC010A00179000048ULL
	}};
	printf("Test Case 174\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 174 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -174;
	} else {
		printf("Test Case 174 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB126155912994B02ULL,
		0x0EC27A9E6822A330ULL,
		0x412F621A0C435239ULL,
		0x4F41C1944025A034ULL,
		0xF1F58CDDE7CD8C9BULL,
		0xF0757A08B48FEA31ULL,
		0x4D9A7B5C2F8F2E48ULL,
		0x941735CC7E7D4596ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2E1E23BACE6A7790ULL,
		0xB1C9FEFEB1C457CBULL,
		0x79042D63C7397E63ULL,
		0x1A27331DC5086FA1ULL,
		0xCE25783F867C8631ULL,
		0x87E1F9C2C2491984ULL,
		0x766D4578B039D245ULL,
		0xAD2EE672864EEE34ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2006011802084300ULL,
		0x00C07A9E20000300ULL,
		0x4104200204015221ULL,
		0x0A01011440002020ULL,
		0xC025081D864C8411ULL,
		0x8061780080090800ULL,
		0x4408415820090240ULL,
		0x84062440064C4414ULL
	}};
	printf("Test Case 175\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 175 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -175;
	} else {
		printf("Test Case 175 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x393BAEF099D927FFULL,
		0xE17BF4FCD65195ADULL,
		0xC6AC801D8CF3578AULL,
		0x852DD93F16B6D432ULL,
		0xCD4E7487C1782623ULL,
		0xDE34AEC1280B6007ULL,
		0x79AC595C41D69EBAULL,
		0x2CBB6B85D569157AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCA408F6C92F38536ULL,
		0xFC784EB7D7A4130CULL,
		0xE0D3BBE0A1CD270EULL,
		0xEC9A77671629EFCCULL,
		0xA02604B304EDD05FULL,
		0x299D539DA747F44AULL,
		0xF85629BA261393D0ULL,
		0x7489FDD409D27C91ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x08008E6090D10536ULL,
		0xE07844B4D600110CULL,
		0xC080800080C1070AULL,
		0x840851271620C400ULL,
		0x8006048300680003ULL,
		0x0814028120036002ULL,
		0x7804091800129290ULL,
		0x2489698401401410ULL
	}};
	printf("Test Case 176\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 176 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -176;
	} else {
		printf("Test Case 176 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9DDC037EB41533AEULL,
		0x25A243F78F82FED4ULL,
		0xF53AFDAA3B59F2A5ULL,
		0x8E3467F11748070BULL,
		0x5A78A45C190388C0ULL,
		0x956226DF7B155060ULL,
		0xFF141167064E2204ULL,
		0xE62B15C01DA5A196ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x06E84E33F50E05DAULL,
		0x6F9A45E72889EE02ULL,
		0x70CA7E271DFDCC00ULL,
		0x678A2C40B738161BULL,
		0xDDFA966F559FF5DEULL,
		0x7F1DA1AA50AB38A5ULL,
		0xF35BDB17C482AEC0ULL,
		0xC24EF36C083D4D54ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x04C80232B404018AULL,
		0x258241E70880EE00ULL,
		0x700A7C221959C000ULL,
		0x060024401708060BULL,
		0x5878844C110380C0ULL,
		0x1500208A50011020ULL,
		0xF310110704022200ULL,
		0xC20A114008250114ULL
	}};
	printf("Test Case 177\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 177 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -177;
	} else {
		printf("Test Case 177 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC2D9433455E7C45AULL,
		0x9893B3AC75B8A404ULL,
		0x3826BD6E00B60112ULL,
		0x01940B595302F484ULL,
		0x43921AEFEF1E45DCULL,
		0x33F1C42309C4C8B6ULL,
		0x8E47F953782D039BULL,
		0x6B766718D43D0122ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFC23100942A84ABDULL,
		0xCC204D757087730DULL,
		0x3EA24E2A0DB6B4F4ULL,
		0x9889C33012E1F3E1ULL,
		0x2CA82AA31BA46C0FULL,
		0x9847D138D5FA608DULL,
		0x60E1C1C2D3FFB7DEULL,
		0x40F5C073F68ADD59ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC001000040A04018ULL,
		0x8800012470802004ULL,
		0x38220C2A00B60010ULL,
		0x008003101200F080ULL,
		0x00800AA30B04440CULL,
		0x1041C02001C04084ULL,
		0x0041C142502D039AULL,
		0x40744010D4080100ULL
	}};
	printf("Test Case 178\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 178 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -178;
	} else {
		printf("Test Case 178 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xABFA6BD2426B8D75ULL,
		0x50017468FB02BED4ULL,
		0xB4C473D966995EEEULL,
		0x4559E8E303954E97ULL,
		0x823895F9CD0875DFULL,
		0x0F6767FFDE26D819ULL,
		0x5836F0C1F3AB131CULL,
		0x1ECDE7C8DE2ACB3AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEB55E33B08D35775ULL,
		0x245153A6DF8773ADULL,
		0xFF2A0095BC34EDFFULL,
		0x94D7FB7F4E2E9B18ULL,
		0x7FC4B612EFF36BA5ULL,
		0x4353E0808A12DCE7ULL,
		0x526C02F58BF6207BULL,
		0xE5843B2CE90CC106ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAB50631200430575ULL,
		0x00015020DB023284ULL,
		0xB400009124104CEEULL,
		0x0451E86302040A10ULL,
		0x02009410CD006185ULL,
		0x034360808A02D801ULL,
		0x502400C183A20018ULL,
		0x04842308C808C102ULL
	}};
	printf("Test Case 179\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 179 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -179;
	} else {
		printf("Test Case 179 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x20623D4A885B92EBULL,
		0x04CFF09F82A149C4ULL,
		0x9719AD2AE0DC4AF6ULL,
		0x0FF7299F07013674ULL,
		0x32DFA9925C4ECB3EULL,
		0xACAC0B36BC2F3509ULL,
		0xCEB8ED5C805B96EDULL,
		0x048C84BD2FA63C15ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x187798DA25813E27ULL,
		0x3490478F8729E8C4ULL,
		0x5288BF862FE11FC6ULL,
		0xEF12C260868BE38BULL,
		0x0BBE6A539CDDBEC2ULL,
		0xE56BC893DBE284DEULL,
		0x404C70137A4C3DA4ULL,
		0xE6DFE0DC3D2AA774ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0062184A00011223ULL,
		0x0480408F822148C4ULL,
		0x1208AD0220C00AC6ULL,
		0x0F12000006012200ULL,
		0x029E28121C4C8A02ULL,
		0xA428081298220408ULL,
		0x40086010004814A4ULL,
		0x048C809C2D222414ULL
	}};
	printf("Test Case 180\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 180 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -180;
	} else {
		printf("Test Case 180 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB22EF5C802457844ULL,
		0x7A0FF9EC80510CBDULL,
		0x6E50B41ECD0F5748ULL,
		0x5AA58D41B048A712ULL,
		0x1B503444792FDAE3ULL,
		0x2F742BB801B2BE65ULL,
		0x858442BA124C7CFBULL,
		0xAB0C291C58276870ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE198C1A212B22AFFULL,
		0x974F5A85F90A0CE5ULL,
		0x726EEEBA7029503DULL,
		0x454C76ADBA040277ULL,
		0xE1D94DA39B63C6E0ULL,
		0xE8940918BB86755BULL,
		0x21420CEFB94C91ADULL,
		0x36A55AABB1C907B2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA008C18002002844ULL,
		0x120F588480000CA5ULL,
		0x6240A41A40095008ULL,
		0x40040401B0000212ULL,
		0x015004001923C2E0ULL,
		0x2814091801823441ULL,
		0x010000AA104C10A9ULL,
		0x2204080810010030ULL
	}};
	printf("Test Case 181\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 181 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -181;
	} else {
		printf("Test Case 181 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD2EFAA7CA1D8172CULL,
		0x65A0444E53600A8FULL,
		0x22345E59185A6FF6ULL,
		0x775717114045FB52ULL,
		0x3192FDB53AD104A7ULL,
		0xC332EFFFBD6589D8ULL,
		0x333B3EEF5BCC4F8FULL,
		0xF5A935335D4704CAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEBC18EEB40AC041DULL,
		0x262F592B3519D3B7ULL,
		0xB605E6FA64A75A33ULL,
		0xD5FFD0D37722B057ULL,
		0x515D6F8C0E4EAD3FULL,
		0x43C452542696B94CULL,
		0xC00AEE0DE17E0957ULL,
		0xA23636AD47A9FD30ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC2C18A680088040CULL,
		0x2420400A11000287ULL,
		0x2204465800024A32ULL,
		0x555710114000B052ULL,
		0x11106D840A400427ULL,
		0x4300425424048948ULL,
		0x000A2E0D414C0907ULL,
		0xA020342145010400ULL
	}};
	printf("Test Case 182\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 182 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -182;
	} else {
		printf("Test Case 182 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEC1C178AF11B951DULL,
		0x87221615C4BB0839ULL,
		0xF7B224EFBF61C42DULL,
		0xDC1FF27388979543ULL,
		0x6D4D6A1DFA9EAA9DULL,
		0x0583AA7DBDF3DA42ULL,
		0x7A97EBA3764CA8D5ULL,
		0xF35A922A98B2B05AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9E16B5BD48D2F4DBULL,
		0x7F445E53023F4EA7ULL,
		0x3E2D0A5A6EA496D4ULL,
		0x7CE69F64F61B9716ULL,
		0x1DC104A073A1AA3BULL,
		0xA8DBF28B5C59DA77ULL,
		0x26062FCB3D163F00ULL,
		0x7AB6C96382F6D0CFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8C14158840129419ULL,
		0x07001611003B0821ULL,
		0x3620004A2E208404ULL,
		0x5C06926080139502ULL,
		0x0D4100007280AA19ULL,
		0x0083A2091C51DA42ULL,
		0x22062B8334042800ULL,
		0x7212802280B2904AULL
	}};
	printf("Test Case 183\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 183 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -183;
	} else {
		printf("Test Case 183 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFD3CD71E6F40E911ULL,
		0xC3EF33408357C163ULL,
		0x935AF7B101F12E04ULL,
		0x68E24D43273FFFB2ULL,
		0x44DA073298F37FDFULL,
		0x1EFC1335B41F1FDDULL,
		0x36E68D0C1F0A0E3DULL,
		0xBF083D0570885874ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD1F766CD94D07C48ULL,
		0x4713EC4027743DE8ULL,
		0x98C10C642E2172CCULL,
		0xCB213E2D946F90B6ULL,
		0x494ABDFF578C31F1ULL,
		0xCE88A38A0BCFA09BULL,
		0x29D48C1265A94A1AULL,
		0xE353BDBB2F5B64FCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD134460C04406800ULL,
		0x4303204003540160ULL,
		0x9040042000212204ULL,
		0x48200C01042F90B2ULL,
		0x404A0532108031D1ULL,
		0x0E880300000F0099ULL,
		0x20C48C0005080A18ULL,
		0xA3003D0120084074ULL
	}};
	printf("Test Case 184\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 184 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -184;
	} else {
		printf("Test Case 184 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x24FB98AB5490B741ULL,
		0x527757ED46E757FBULL,
		0x512FD110307DE2FFULL,
		0xFAB64F409827E472ULL,
		0x32BF7F7C82C64123ULL,
		0x66782EB0FAA10D28ULL,
		0x4BEBE67B4ECB866FULL,
		0x3E32C0D8C5348216ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDE0690A52DFD71AFULL,
		0x75623217C6C1417CULL,
		0xEA73E87E3FD43B93ULL,
		0xEDBF50C59AC683CDULL,
		0x5B0CCC4A494A398EULL,
		0xC720049F442E3E9BULL,
		0xCE0F804A6213CA82ULL,
		0x3A5B79364B5489C5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x040290A104903101ULL,
		0x5062120546C14178ULL,
		0x4023C01030542293ULL,
		0xE8B6404098068040ULL,
		0x120C4C4800420102ULL,
		0x4620049040200C08ULL,
		0x4A0B804A42038202ULL,
		0x3A12401041148004ULL
	}};
	printf("Test Case 185\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 185 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -185;
	} else {
		printf("Test Case 185 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x641B19B2470648A7ULL,
		0x0D54555AF7EE3A60ULL,
		0xE66926D89524C667ULL,
		0x8C1772DA34FAAE4AULL,
		0xC413C3730B1334B7ULL,
		0xF2F749178BBF33B9ULL,
		0x1FA39367878A7CCBULL,
		0x8820C6FDEA8AA611ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xABD0EAE412196FD1ULL,
		0xE6C1EAC61AE9DC27ULL,
		0x88E742CC6F8693A9ULL,
		0xADDD98B74C7FA9BFULL,
		0x4BB323E40C3FA306ULL,
		0x0CB62B68F9173C8FULL,
		0x3FBAB131CD43B723ULL,
		0x5F9F23BE2CDBCEFCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x201008A002004881ULL,
		0x0440404212E81820ULL,
		0x806102C805048221ULL,
		0x8C151092047AA80AULL,
		0x4013036008132006ULL,
		0x00B6090089173089ULL,
		0x1FA2912185023403ULL,
		0x080002BC288A8610ULL
	}};
	printf("Test Case 186\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 186 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -186;
	} else {
		printf("Test Case 186 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE5B0C87DBBB28A72ULL,
		0x5665C184626FF420ULL,
		0x5DC71505E2BC5214ULL,
		0x505FA84E48079269ULL,
		0x1A292F3E7F97BDE1ULL,
		0x9C09F2D182D835FBULL,
		0x54B44CC81B74CE82ULL,
		0xF7C1D817469177A1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC9187F12FAF99F07ULL,
		0x3BEBE4BDE0D9F7F7ULL,
		0x9102B3809FF8D7F7ULL,
		0xFE81CB3E9B2EB51CULL,
		0x9528C2B22D3E14E9ULL,
		0xA2534CE42637FF64ULL,
		0xF2F3E31A93CAFC13ULL,
		0x8DEF3ABDE3C2CB95ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC1104810BAB08A02ULL,
		0x1261C0846049F420ULL,
		0x1102110082B85214ULL,
		0x5001880E08069008ULL,
		0x102802322D1614E1ULL,
		0x800140C002103560ULL,
		0x50B040081340CC02ULL,
		0x85C1181542804381ULL
	}};
	printf("Test Case 187\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 187 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -187;
	} else {
		printf("Test Case 187 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF35D41B68853C287ULL,
		0x7CB4E5E8B62F2B3CULL,
		0x93B8F25BFB0107BEULL,
		0x4467AF241423465DULL,
		0xC9730032E3E5E56CULL,
		0x14215DEC9D0486D7ULL,
		0xA00D73479FDD1BB2ULL,
		0x161311ED95A9C491ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB76D4BB5AE60DBA7ULL,
		0x70A51D8549D2F213ULL,
		0x0DF0094ADEE34925ULL,
		0x03247E7CF851F216ULL,
		0xB7CD1BF095FDDEE4ULL,
		0x4BA4A719AD35498DULL,
		0xDB90029575C71587ULL,
		0x1CE50BB2C99A56E1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB34D41B48840C287ULL,
		0x70A4058000022210ULL,
		0x01B0004ADA010124ULL,
		0x00242E2410014214ULL,
		0x8141003081E5C464ULL,
		0x002005088D040085ULL,
		0x8000020515C51182ULL,
		0x140101A081884481ULL
	}};
	printf("Test Case 188\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 188 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -188;
	} else {
		printf("Test Case 188 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5A2C0DE3025F3FFAULL,
		0x0AD74EE91D4DD4B1ULL,
		0xFCF6B2CE0584201BULL,
		0x63544D93B3C60DAAULL,
		0xEE219FFB49B60902ULL,
		0x34183BC4E09903E5ULL,
		0x5E090CC1479BC0E9ULL,
		0x50390EB081EA8EBCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x711C8E1E533DF242ULL,
		0x0D32CE1386055C65ULL,
		0xD34D223178FB028FULL,
		0x2E9F01C8BDCDF71CULL,
		0xFF23E6B34153DD5CULL,
		0x40CD3CA5B1D44C4DULL,
		0x279B1D30D8BDDFECULL,
		0xC7DE59095659AC4BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x500C0C02021D3242ULL,
		0x08124E0104055421ULL,
		0xD04422000080000BULL,
		0x22140180B1C40508ULL,
		0xEE2186B341120900ULL,
		0x00083884A0900045ULL,
		0x06090C004099C0E8ULL,
		0x4018080000488C08ULL
	}};
	printf("Test Case 189\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 189 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -189;
	} else {
		printf("Test Case 189 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x10EA23F9D52815F6ULL,
		0x7E2660DDD00DA05AULL,
		0x5336D2C08042852DULL,
		0xCA031F1710A23C3CULL,
		0xEE968276BEB936A1ULL,
		0x29C764341F510C66ULL,
		0x58CD5C961B24B061ULL,
		0x9B47E8191C8F54E9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6A2FAFB3C23C4116ULL,
		0xF7B45228F484F30AULL,
		0x3CB2AEF42FDFB7ECULL,
		0x170FD288239DE7FDULL,
		0x9199D158A8F3E8E7ULL,
		0x076909F179C0416FULL,
		0xC2543EAF1E95009DULL,
		0xBA55293DFA070E1EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x002A23B1C0280116ULL,
		0x76244008D004A00AULL,
		0x103282C00042852CULL,
		0x020312000080243CULL,
		0x80908050A8B120A1ULL,
		0x0141003019400066ULL,
		0x40441C861A040001ULL,
		0x9A45281918070408ULL
	}};
	printf("Test Case 190\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 190 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -190;
	} else {
		printf("Test Case 190 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x172AC5AEF5C43EFDULL,
		0xF739AB08DC1C0AF6ULL,
		0xC869FFCA5F72640DULL,
		0x02DEA03B53CBDC1AULL,
		0x7EF7476D6CBF3665ULL,
		0xB2E66ACE0B84670FULL,
		0x543CB128A8DEB9D9ULL,
		0x2403B7BF5FAD1B0AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x75C453751E84DD13ULL,
		0x8E7C72C5DE377198ULL,
		0x73B83CFB642B61D2ULL,
		0x79CF2BC611AD288EULL,
		0xD6C7D0B1CB71B89EULL,
		0x6AACD1A55B4F82E0ULL,
		0xAECF6524F89394B0ULL,
		0x4A72EC3D455FF773ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1500412414841C11ULL,
		0x86382200DC140090ULL,
		0x40283CCA44226000ULL,
		0x00CE20021189080AULL,
		0x56C7402148313004ULL,
		0x22A440840B040200ULL,
		0x040C2120A8929090ULL,
		0x0002A43D450D1302ULL
	}};
	printf("Test Case 191\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 191 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -191;
	} else {
		printf("Test Case 191 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2105DA1F27F3B932ULL,
		0xA3A59D351014F118ULL,
		0x31890503D9831621ULL,
		0x3331DB7C68C27FEBULL,
		0x7A31A30EE6A85800ULL,
		0x7B525DC5B32B82D6ULL,
		0xFA7E0C27D5332C5AULL,
		0x8D6948849233CB47ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x793510D3DF46809FULL,
		0x7309BBA036D08D91ULL,
		0x9BEB4C8D3071078CULL,
		0x7DD95B150B5F21B6ULL,
		0x215ECD8A9929F3CEULL,
		0x2412FBC97C312A17ULL,
		0x47C967D9F9F28C43ULL,
		0x6F47A2DD156F51ABULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2105101307428012ULL,
		0x2301992010108110ULL,
		0x1189040110010600ULL,
		0x31115B14084221A2ULL,
		0x2010810A80285000ULL,
		0x201259C130210216ULL,
		0x42480401D1320C42ULL,
		0x0D41008410234103ULL
	}};
	printf("Test Case 192\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 192 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -192;
	} else {
		printf("Test Case 192 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4A190D2947F5ADBEULL,
		0x30624D34C0E3308DULL,
		0x4A288665D8627EE7ULL,
		0xB3921EEC10BC2D5FULL,
		0xE9B42E7C9DB151B3ULL,
		0x6BE88C0060D4322EULL,
		0xEB4F7D66A644FD7CULL,
		0xE783552E1E3F8A68ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0E8EC6DDD4CF048FULL,
		0xCAE971C44DADCD23ULL,
		0x071CA7DCC56A306BULL,
		0x9539CB9DA3C64DFAULL,
		0x547F5A00979720A7ULL,
		0xEB411F728D85E2B2ULL,
		0xA084ED75C8038ABEULL,
		0x8D4F99DE0048A246ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0A08040944C5048EULL,
		0x0060410440A10001ULL,
		0x02088644C0623063ULL,
		0x91100A8C00840D5AULL,
		0x40340A00959100A3ULL,
		0x6B400C0000842222ULL,
		0xA0046D648000883CULL,
		0x8503110E00088240ULL
	}};
	printf("Test Case 193\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 193 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -193;
	} else {
		printf("Test Case 193 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1B9C7EBC906F4B56ULL,
		0xAAED4C8C4D296503ULL,
		0xAABE62028F739992ULL,
		0x522B17600CB9E574ULL,
		0x3B832840016870BFULL,
		0xDB273F5694A38809ULL,
		0x2A4BF399CA2371DBULL,
		0xB71B2B4BF0FB30EFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x62B9BB7E5A3EC2ABULL,
		0x1958673B187396ECULL,
		0xF061D3CEC4942450ULL,
		0x20A9AFDEA8EDED17ULL,
		0xB49519FBA4E04EA8ULL,
		0xC219F53585BE53BBULL,
		0x269CA74397A42FC5ULL,
		0x8DB00C4176F0E1E8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x02983A3C102E4202ULL,
		0x0848440808210400ULL,
		0xA020420284100010ULL,
		0x0029074008A9E514ULL,
		0x30810840006040A8ULL,
		0xC201351484A20009ULL,
		0x2208A301822021C1ULL,
		0x8510084170F020E8ULL
	}};
	printf("Test Case 194\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 194 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -194;
	} else {
		printf("Test Case 194 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3ED178C56A63FC60ULL,
		0xF16BE716040AD082ULL,
		0xE146DC1EA69F05D7ULL,
		0x14660630B68DFDE5ULL,
		0x4840804E94C53BDFULL,
		0x6B930894C1E16ED8ULL,
		0xEEF8B43B6C379DD2ULL,
		0x4E863A2931185E7EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x63BD054859D265A6ULL,
		0x76F47A598DFB2C8FULL,
		0xE25CF5FF57F19380ULL,
		0xE34A7031589B23F9ULL,
		0xF3D764B596FA7962ULL,
		0x3CD5A209F98A8838ULL,
		0x651E36DE46C1BCA1ULL,
		0x116EBCE8D4093867ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2291004048426420ULL,
		0x70606210040A0082ULL,
		0xE044D41E06910180ULL,
		0x00420030108921E1ULL,
		0x4040000494C03942ULL,
		0x28910000C1800818ULL,
		0x6418341A44019C80ULL,
		0x0006382810081866ULL
	}};
	printf("Test Case 195\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 195 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -195;
	} else {
		printf("Test Case 195 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x756173EDE230FA4AULL,
		0xD3392414E77E9089ULL,
		0xFBB5DCE540D0BFB6ULL,
		0x16544014631042F8ULL,
		0x51B39F3AF11B8B68ULL,
		0x6D8F0D6F1AFC8384ULL,
		0x71CB0183887C1132ULL,
		0x726C9F48368623D1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4F0B4BD78EF70ABAULL,
		0xF568CC67BE88C0DAULL,
		0xFA128305B9973007ULL,
		0x25E8F28B963DD7EEULL,
		0xFCEB9C0E7A21618BULL,
		0x550E5909FE50A0B1ULL,
		0xAF4385579ED3C11EULL,
		0xC70315464B8D6D99ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x450143C582300A0AULL,
		0xD1280404A6088088ULL,
		0xFA10800500903006ULL,
		0x04404000021042E8ULL,
		0x50A39C0A70010108ULL,
		0x450E09091A508080ULL,
		0x2143010388500112ULL,
		0x4200154002842191ULL
	}};
	printf("Test Case 196\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 196 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -196;
	} else {
		printf("Test Case 196 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDE25744456DD66E5ULL,
		0x8E2E4E0121916FDAULL,
		0x42211932240A3A8BULL,
		0x601941270D8CDB2FULL,
		0x5C8B6DF88577D398ULL,
		0xA56207A776BED64EULL,
		0xA601F15F9B34E9F7ULL,
		0xD03F02F648A2951BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBEAEAD1DC1C9A396ULL,
		0x5C2DDE845A09A7C7ULL,
		0x0DBCAC66A95A6A54ULL,
		0xC7969633ECEEC929ULL,
		0xFF2CA47219A18275ULL,
		0x26D321A714A023CCULL,
		0xE75800D676E7E02FULL,
		0x688E15D040697793ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9E24240440C92284ULL,
		0x0C2C4E00000127C2ULL,
		0x00200822200A2A00ULL,
		0x401000230C8CC929ULL,
		0x5C08247001218210ULL,
		0x244201A714A0024CULL,
		0xA60000561224E027ULL,
		0x400E00D040201513ULL
	}};
	printf("Test Case 197\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 197 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -197;
	} else {
		printf("Test Case 197 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC3482B9295DFDC8DULL,
		0x8B933EE48E422646ULL,
		0xF0488E0F960C70EFULL,
		0x50C36B120301200FULL,
		0xBF5D444FA11DB513ULL,
		0x34F889A4265D3ACFULL,
		0x731515968E563E71ULL,
		0xE3203C11A67A4307ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE08971C95ECF0F4BULL,
		0x12D02DA25F13014FULL,
		0x793436A80C138F3DULL,
		0x07925F3211CFE4B3ULL,
		0x90381B23284ED834ULL,
		0x855B416F8B3A79A1ULL,
		0xBDDCE91C80CA521DULL,
		0xD27244E8A7AE2E18ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC008218014CF0C09ULL,
		0x02902CA00E020046ULL,
		0x700006080400002DULL,
		0x00824B1201012003ULL,
		0x90180003200C9010ULL,
		0x0458012402183881ULL,
		0x3114011480421211ULL,
		0xC2200400A62A0200ULL
	}};
	printf("Test Case 198\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 198 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -198;
	} else {
		printf("Test Case 198 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3605588318B10885ULL,
		0xCA3A0AF0B5A38759ULL,
		0x995246893847B620ULL,
		0xA7FE95D2A63463F4ULL,
		0xB8210C22AC292E5AULL,
		0x66AA58C368BAF5FDULL,
		0x3786AF1F77D9678AULL,
		0x6A0413E03F16A9FBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5BEFC1CF201CA1DFULL,
		0x448F5A04B187D669ULL,
		0x35FAAEC82EAAF842ULL,
		0x676280572238225DULL,
		0x6F15606CFB35EF68ULL,
		0x225FCFE71D05A325ULL,
		0xA3C8AE5E0B4494F5ULL,
		0x33F481E8EC9E3BECULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1205408300100085ULL,
		0x400A0A00B1838649ULL,
		0x115206882802B000ULL,
		0x2762805222302254ULL,
		0x28010020A8212E48ULL,
		0x220A48C30800A125ULL,
		0x2380AE1E03400480ULL,
		0x220401E02C1629E8ULL
	}};
	printf("Test Case 199\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 199 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -199;
	} else {
		printf("Test Case 199 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9A1F0239813188C4ULL,
		0x39D7E0E089E263A8ULL,
		0x6891068CF4E9EB4EULL,
		0x3E03D6C5AA607E66ULL,
		0x1F33AB668058ADA7ULL,
		0x9FCA2D76CA207D6DULL,
		0x8A3184413C1DFE5FULL,
		0xB351511389F2F5BAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD03D27FCCABA697AULL,
		0x561763B550FA27CEULL,
		0x22A3D360EB631DAAULL,
		0x47E20FD41AA9F020ULL,
		0xADAD3124C680AAF3ULL,
		0x19AB271CD192F3C5ULL,
		0xB6186F2970C93600ULL,
		0x42848BF682AA5127ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x901D023880300840ULL,
		0x101760A000E22388ULL,
		0x20810200E061090AULL,
		0x060206C40A207020ULL,
		0x0D2121248000A8A3ULL,
		0x198A2514C0007145ULL,
		0x8210040130093600ULL,
		0x0200011280A25122ULL
	}};
	printf("Test Case 200\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 200 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -200;
	} else {
		printf("Test Case 200 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6224AA4E354BC5E4ULL,
		0xFF3CDB59A03F78A9ULL,
		0xC4546CA72D03224BULL,
		0x75E18E63BA2E06C3ULL,
		0x369CAAA016F877F0ULL,
		0x820EA75032E3AEC5ULL,
		0x55E288F05458E960ULL,
		0x6C89135CB325CE57ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFE8BDCD10BFF2557ULL,
		0x19264BD40A07B656ULL,
		0xA6ACE973401978F5ULL,
		0xB0354DF810DF0471ULL,
		0x81C0E1154834D173ULL,
		0xA4113F2AB6D68918ULL,
		0xB56E47CB1D075786ULL,
		0xF2B7311AB4D358EBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x62008840014B0544ULL,
		0x19244B5000073000ULL,
		0x8404682300012041ULL,
		0x30210C60100E0441ULL,
		0x0080A00000305170ULL,
		0x8000270032C28800ULL,
		0x156200C014004100ULL,
		0x60811118B0014843ULL
	}};
	printf("Test Case 201\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 201 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -201;
	} else {
		printf("Test Case 201 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1FFDDDDA0A0052A9ULL,
		0xAEEC284E639862D2ULL,
		0xBBC3393698B5C821ULL,
		0x12B483C2671D595DULL,
		0xF14EAC21FA9633C7ULL,
		0xA265BBBA9C22D97AULL,
		0xA27BB4D3BCAEF3B2ULL,
		0xF04C1AA10495C10CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x789AB5553D4A4298ULL,
		0x737DC7B778B2790AULL,
		0x2C5986D43BB67F0BULL,
		0xEE5AFB77E346E08FULL,
		0x1708524BCE3CC289ULL,
		0xA222AA3ECB34CAE0ULL,
		0x3F3EEF2EF565DE1AULL,
		0x4BE60016F9782C55ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1898955008004288ULL,
		0x226C000660906002ULL,
		0x2841001418B44801ULL,
		0x021083426304400DULL,
		0x11080001CA140281ULL,
		0xA220AA3A8820C860ULL,
		0x223AA402B424D212ULL,
		0x4044000000100004ULL
	}};
	printf("Test Case 202\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 202 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -202;
	} else {
		printf("Test Case 202 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBE1358BC2CB161A9ULL,
		0x3855F72DDFACCF19ULL,
		0xC1E568675353ACC9ULL,
		0x2D446B7AF7FF584BULL,
		0x1E891627DF612038ULL,
		0x16964EA012A6A036ULL,
		0xE2EC0C708670A96FULL,
		0x975BAA92808AF900ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCEE880915F7B4A47ULL,
		0x1A01A4BB8BE8B97DULL,
		0x472DED84A8476277ULL,
		0x4C14F956AAD58CF5ULL,
		0xE451B3D1F6695F50ULL,
		0x31DCFF022AE6DB8DULL,
		0xDA499E1CD8820D47ULL,
		0x3AAC99BF16E35151ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8E0000900C314001ULL,
		0x1801A4298BA88919ULL,
		0x4125680400432041ULL,
		0x0C046952A2D50841ULL,
		0x04011201D6610010ULL,
		0x10944E0002A68004ULL,
		0xC2480C1080000947ULL,
		0x1208889200825100ULL
	}};
	printf("Test Case 203\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 203 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -203;
	} else {
		printf("Test Case 203 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x832268E854143EDAULL,
		0xCC4178A98F019884ULL,
		0x3BB82F8F014AC3B5ULL,
		0x028825A28A0A0573ULL,
		0xA254ECA48E0734ADULL,
		0x8BB72590C4752828ULL,
		0xC9C10684171005EDULL,
		0x8DDA5177EF32AE44ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1C96E6FE2C668B05ULL,
		0xB762A4052A071489ULL,
		0x3061B5E91442C482ULL,
		0xD7DD21BCC1C79848ULL,
		0x9511FBDF73175EE5ULL,
		0xAFDEE50DF17C1CD7ULL,
		0xA8D1F4F4BCD69BC5ULL,
		0x8CA0829FBCEAE0CAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x000260E804040A00ULL,
		0x844020010A011080ULL,
		0x302025890042C080ULL,
		0x028821A080020040ULL,
		0x8010E884020714A5ULL,
		0x8B962500C0740800ULL,
		0x88C10484141001C5ULL,
		0x8C800017AC22A040ULL
	}};
	printf("Test Case 204\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 204 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -204;
	} else {
		printf("Test Case 204 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3428E3E5A3FA0B6CULL,
		0xE1EB177A587BAAC3ULL,
		0x4D13CC65AAB1E01DULL,
		0x2889EAE910A6C57CULL,
		0x19A8556DA24B22C2ULL,
		0x06ED746C2991CF64ULL,
		0xB3D11624E8D2D808ULL,
		0xAF91967AD3756397ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x87F6D920A93A5B0EULL,
		0xAE2C0B64E3C336EEULL,
		0xCD54FC2DAEF7BD77ULL,
		0x31D1F2FD3826DA30ULL,
		0xBFD5121EF74F0484ULL,
		0xDD09A3B18201AC03ULL,
		0xD52EF9F48820D6A2ULL,
		0xFC818D6485562E56ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0420C120A13A0B0CULL,
		0xA0280360404322C2ULL,
		0x4D10CC25AAB1A015ULL,
		0x2081E2E91026C030ULL,
		0x1980100CA24B0080ULL,
		0x0409202000018C00ULL,
		0x910010248800D000ULL,
		0xAC81846081542216ULL
	}};
	printf("Test Case 205\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 205 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -205;
	} else {
		printf("Test Case 205 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFCC5D0CC909F530DULL,
		0xD847B9D535F81C78ULL,
		0xA799A3CE995C0B26ULL,
		0x0A779FA1F9C4AFEFULL,
		0xFCD811E3D30B8C9BULL,
		0xD67CCE36E536A002ULL,
		0x05177CF34BA4AF25ULL,
		0xCB42EA2A71662615ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD1FF68DCC3E55B86ULL,
		0x60AB5D268113E66BULL,
		0x1F2C25F7D216AAC2ULL,
		0xDCC014DAC1894460ULL,
		0x9A4577A403D95A9AULL,
		0x037F55DC8332076AULL,
		0x58D3F55B13E3DFAAULL,
		0x27A3D6195579AC54ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD0C540CC80855304ULL,
		0x4003190401100468ULL,
		0x070821C690140A02ULL,
		0x08401480C1800460ULL,
		0x984011A00309089AULL,
		0x027C441481320002ULL,
		0x0013745303A08F20ULL,
		0x0302C20851602414ULL
	}};
	printf("Test Case 206\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 206 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -206;
	} else {
		printf("Test Case 206 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x67E0AE9344CC317CULL,
		0x43EDE037537D8860ULL,
		0x3BB853155699DFB1ULL,
		0x108DB404714DF840ULL,
		0x3DE3B8B23F96C9F8ULL,
		0xD62FCC0A5521B77CULL,
		0x1F6848CDED1EC4F7ULL,
		0x5C7FC7874F593178ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8500781D6B02AFB4ULL,
		0x6FE2545AB58FE9CFULL,
		0xDEF905ED5DF46294ULL,
		0x2A868659550C4464ULL,
		0x55E903F2AD44A567ULL,
		0xE7E2D880C4D9BA68ULL,
		0xB8124598BB2F1D6FULL,
		0x689465C865AD5F20ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0500281140002134ULL,
		0x43E04012110D8840ULL,
		0x1AB8010554904290ULL,
		0x00848400510C4040ULL,
		0x15E100B22D048160ULL,
		0xC622C8004401B268ULL,
		0x18004088A90E0467ULL,
		0x4814458045091120ULL
	}};
	printf("Test Case 207\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 207 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -207;
	} else {
		printf("Test Case 207 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE0AA00549368198BULL,
		0x468D631B3678AA56ULL,
		0x196DB07CB19B963AULL,
		0x18AB962C8A0E2146ULL,
		0x130B78A386EAC7C9ULL,
		0xDA7328609DB047C6ULL,
		0x9CD7B6CBE3DF6CC1ULL,
		0x9873E9D549161313ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x82C3535F2D69162FULL,
		0x6D7170C96275A3CDULL,
		0x2530D9F6A83ED345ULL,
		0x49110EC03942EDA7ULL,
		0xAB6632F72B57F1BDULL,
		0x2087975184D6BE68ULL,
		0xCF6724DE47962DE1ULL,
		0xBA888C63187AB0EFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x808200540168100BULL,
		0x440160092270A244ULL,
		0x01209074A01A9200ULL,
		0x0801060008022106ULL,
		0x030230A30242C189ULL,
		0x0003004084900640ULL,
		0x8C4724CA43962CC1ULL,
		0x9800884108121003ULL
	}};
	printf("Test Case 208\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 208 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -208;
	} else {
		printf("Test Case 208 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x57F2A7D17943DCE5ULL,
		0x37D3DFC50EC91D6AULL,
		0x4C8A69A8792B779EULL,
		0xDCA67FA17470A21EULL,
		0x8D7C8A90BEBCA814ULL,
		0x4A056E8B843AC0E3ULL,
		0xD501429C46E1EB68ULL,
		0xF3980868E8F275A9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1830ED00327906BBULL,
		0xC0D64221055F9806ULL,
		0x87FB8A9BFB3F02B3ULL,
		0x40B18C8DD304E9EBULL,
		0xF307D88F914374F2ULL,
		0x65294E5184A5B2E3ULL,
		0x9304D0C0EB55C14EULL,
		0x3E47905EC894B2BEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1030A500304104A1ULL,
		0x00D2420104491802ULL,
		0x048A0888792B0292ULL,
		0x40A00C815000A00AULL,
		0x8104888090002010ULL,
		0x40014E01842080E3ULL,
		0x910040804241C148ULL,
		0x32000048C89030A8ULL
	}};
	printf("Test Case 209\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 209 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -209;
	} else {
		printf("Test Case 209 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x545848C8A28D5EDEULL,
		0x1A3F438E2E90AAA0ULL,
		0x098B9CD4AD41ADCDULL,
		0x6269806371ADAB7FULL,
		0x11C7FEC3B454C214ULL,
		0xB42FF577403D09B8ULL,
		0xF74804C22AE510A1ULL,
		0x58ABFE1F6984BAB0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA43D67DC71C05189ULL,
		0xFEE9DAC2CA01926EULL,
		0x041093BEA945DEDBULL,
		0x03455BDBD5FFE602ULL,
		0xF7E90584DE6786F7ULL,
		0xCCD7618858A2E280ULL,
		0xE38DA2AE39A92A35ULL,
		0x558E6FDD0385F442ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x041840C820805088ULL,
		0x1A2942820A008220ULL,
		0x00009094A9418CC9ULL,
		0x0241004351ADA202ULL,
		0x11C1048094448214ULL,
		0x8407610040200080ULL,
		0xE308008228A10021ULL,
		0x508A6E1D0184B000ULL
	}};
	printf("Test Case 210\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 210 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -210;
	} else {
		printf("Test Case 210 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD4EA32D0A0B8A6A2ULL,
		0xE0A79B9A29513424ULL,
		0x2963EB674C74BB3EULL,
		0xFD902922A794608FULL,
		0x3259CDBE03FC4657ULL,
		0xEDD9DC10BE32FBC2ULL,
		0x95F41313A5C44FCBULL,
		0xC730D802771C6DAAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x258A566D0136C816ULL,
		0x3EA8FA9FD68A3D04ULL,
		0xD70598AD6940077BULL,
		0x34E941B47669C6D6ULL,
		0x2A62A5E636230A38ULL,
		0x86DE7FD5CCF862BDULL,
		0xA2207A6CE492D2E3ULL,
		0x1F0B6C5CA39AF33AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x048A124000308002ULL,
		0x20A09A9A00003404ULL,
		0x010188254840033AULL,
		0x3480012026004086ULL,
		0x224085A602200210ULL,
		0x84D85C108C306280ULL,
		0x80201200A48042C3ULL,
		0x070048002318612AULL
	}};
	printf("Test Case 211\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 211 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -211;
	} else {
		printf("Test Case 211 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB5BB8BCC83345CC2ULL,
		0x626B0F89914C0ED5ULL,
		0x284C5F3E0085B37CULL,
		0x38B39A161347B120ULL,
		0x7975F40C1FB63A2BULL,
		0xC14F4EDC791996ABULL,
		0x3E825CD83504CD93ULL,
		0x67C5C0658EEDCBEAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0D3E0C569A210F06ULL,
		0x9DF46F826EA61AE8ULL,
		0x770C8E2C7DA3B402ULL,
		0xE55A0133BC6D16F0ULL,
		0xE98D0ADEC20504F8ULL,
		0x86EBBE924D799A2AULL,
		0x0B42C429035006ECULL,
		0x8AF223C8EE23289CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x053A084482200C02ULL,
		0x00600F8000040AC0ULL,
		0x200C0E2C0081B000ULL,
		0x2012001210451020ULL,
		0x6905000C02040028ULL,
		0x804B0E904919922AULL,
		0x0A02440801000480ULL,
		0x02C000408E210888ULL
	}};
	printf("Test Case 212\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 212 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -212;
	} else {
		printf("Test Case 212 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x802D0565EC9CC8A7ULL,
		0x00B61BDF0C3F983DULL,
		0x88DB61754DA85E13ULL,
		0x7B57E185A91A9362ULL,
		0x905A01A192F6B993ULL,
		0xEDDD72F111AF6306ULL,
		0x8BA82AC6D7AF2C94ULL,
		0x5A87B8C2995001FBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x386D6A7ADB9743BEULL,
		0x16B7A2755571537DULL,
		0x123B250CBB8C8A1FULL,
		0xFE0455BDCED15A84ULL,
		0xA06AE2C822C24495ULL,
		0xE69363E8BC2318A4ULL,
		0xF6E18836191D1E7EULL,
		0x294DB2130F5BD4D3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x002D0060C89440A6ULL,
		0x00B602550431103DULL,
		0x001B210409880A13ULL,
		0x7A04418588101200ULL,
		0x804A008002C20091ULL,
		0xE49162E010230004ULL,
		0x82A00806110D0C14ULL,
		0x0805B002095000D3ULL
	}};
	printf("Test Case 213\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 213 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -213;
	} else {
		printf("Test Case 213 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x97D4688767048A0FULL,
		0xB704AF3D8E06B586ULL,
		0xDDADD40BD208D4CBULL,
		0xBACDB36CDF3BBCB1ULL,
		0xCEA80E9A8B100599ULL,
		0xCDD02C3613DD1AC9ULL,
		0xEB6EF3C5BAB6F715ULL,
		0x09AB32A6BAE4A9EEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1743FAF72204806EULL,
		0x445CFB1248717E22ULL,
		0xF3B001E3714206EAULL,
		0xE4722F4B974903A4ULL,
		0x5E4914AC9D2B9CFFULL,
		0x419A48FF51CB0DB2ULL,
		0x8D498D10C59E216DULL,
		0x672A6707FD13AAF8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x174068872204800EULL,
		0x0404AB1008003402ULL,
		0xD1A00003500004CAULL,
		0xA0402348970900A0ULL,
		0x4E08048889000499ULL,
		0x4190083611C90880ULL,
		0x8948810080962105ULL,
		0x012A2206B800A8E8ULL
	}};
	printf("Test Case 214\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 214 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -214;
	} else {
		printf("Test Case 214 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4CF68ECEC1384988ULL,
		0x9B2210EEA0CF1D2CULL,
		0xA9D84291F8BE38E5ULL,
		0x1ED673CE2ADA44BFULL,
		0xB52761212E1C0180ULL,
		0x242B88F87BEE1563ULL,
		0x9AA7B9F1A6BDD30BULL,
		0x2019D99A1A0248E5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCA4632ECBF500430ULL,
		0x1ACCF9CE9004826CULL,
		0xBF7561DA23298A21ULL,
		0x7F5A748BEDF4E721ULL,
		0x4640DC3A9C91B2FCULL,
		0xD170BFE2BB5FB855ULL,
		0xA184694DBE25E51FULL,
		0x02A91CA44A6A4D8AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x484602CC81100000ULL,
		0x1A0010CE8004002CULL,
		0xA950409020280821ULL,
		0x1E52708A28D04421ULL,
		0x040040200C100080ULL,
		0x002088E03B4E1041ULL,
		0x80842941A625C10BULL,
		0x000918800A024880ULL
	}};
	printf("Test Case 215\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 215 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -215;
	} else {
		printf("Test Case 215 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCF977BE13B659094ULL,
		0x97DDA5BA2919BD59ULL,
		0x286000F96BEE631FULL,
		0x3F71B9495431E685ULL,
		0x40FC5CA6F6CD0EEAULL,
		0x6E1D47E9576CBEBFULL,
		0x2E3DDC16D3164B89ULL,
		0x344CCFA38FEA397AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6BC05E739222A3F2ULL,
		0x99D475D45F657512ULL,
		0x20353933C95E3106ULL,
		0x1082053783D09630ULL,
		0x7E562A466F58395EULL,
		0x1738AB38D2E7A2A7ULL,
		0x3E9F667D16C7CD19ULL,
		0x21A84303199AD641ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4B805A6112208090ULL,
		0x91D4259009013510ULL,
		0x20200031494E2106ULL,
		0x1000010100108600ULL,
		0x405408066648084AULL,
		0x061803285264A2A7ULL,
		0x2E1D441412064909ULL,
		0x20084303098A1040ULL
	}};
	printf("Test Case 216\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 216 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -216;
	} else {
		printf("Test Case 216 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7B3EE2FFA11965D5ULL,
		0xCE6FB02E0D95ECE4ULL,
		0x698413A5BDB44577ULL,
		0x5C33A396B4BE9B0CULL,
		0xD75B7DF93D8C4500ULL,
		0x0D77A25ED449C86BULL,
		0x65A62613DF6991E8ULL,
		0x2B5345F84019460AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0450D6AE6BE67E49ULL,
		0xC4D70F7A247FBA63ULL,
		0xDAE817F3032C3256ULL,
		0x6973A035FB522CBDULL,
		0xCA4AF90A1C07913EULL,
		0x0F60100D986D1BDCULL,
		0x5729D06E603DD018ULL,
		0xA5EF6811A26B6C0BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0010C2AE21006441ULL,
		0xC447002A0415A860ULL,
		0x488013A101240056ULL,
		0x4833A014B012080CULL,
		0xC24A79081C040100ULL,
		0x0D60000C90490848ULL,
		0x4520000240299008ULL,
		0x214340100009440AULL
	}};
	printf("Test Case 217\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 217 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -217;
	} else {
		printf("Test Case 217 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFFEC40DD412CA37AULL,
		0xA60F4D5363A1335DULL,
		0xF636C39D80CCFFA2ULL,
		0x5BBAFE1EAE8192F8ULL,
		0x5CCA0A2F4F648430ULL,
		0x0C50556B74B99734ULL,
		0x56099EF5A4DFB3EAULL,
		0xC5210DAFB8E2392DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE073B129F9AEE204ULL,
		0x7934F307D8750B25ULL,
		0x589607FFC4099E6AULL,
		0x9750EE57CC7B6434ULL,
		0xD9751B71805514ECULL,
		0x0DD8A4F8C0A3F11BULL,
		0xDF9E38FB5BEB0032ULL,
		0xC582FA4B1DCE25E1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE0600009412CA200ULL,
		0x2004410340210305ULL,
		0x5016039D80089E22ULL,
		0x1310EE168C010030ULL,
		0x58400A2100440420ULL,
		0x0C50046840A19110ULL,
		0x560818F100CB0022ULL,
		0xC500080B18C22121ULL
	}};
	printf("Test Case 218\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 218 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -218;
	} else {
		printf("Test Case 218 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDE74C40C10FD2508ULL,
		0x4D7EBBED0D87A4ACULL,
		0xEBA1C48E819BBA9FULL,
		0x1C0615CEB31936D2ULL,
		0x1AEC7878086377E8ULL,
		0x31A2A6F578BFE0E4ULL,
		0xD5B6AD25A988AA65ULL,
		0x698E2EF59415AD09ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x34B0B195D7EF0C15ULL,
		0x56FF1F42E1B113F2ULL,
		0xA0FB3E80E94C931EULL,
		0x9A8987507D5ECA4AULL,
		0x88D9B026E64F54A9ULL,
		0xEE37A358D79BFC88ULL,
		0xF749AEC57994ECFEULL,
		0x8DAA7DB828307A07ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1430800410ED0400ULL,
		0x447E1B40018100A0ULL,
		0xA0A104808108921EULL,
		0x1800054031180242ULL,
		0x08C83020004354A8ULL,
		0x2022A250509BE080ULL,
		0xD500AC052980A864ULL,
		0x098A2CB000102801ULL
	}};
	printf("Test Case 219\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 219 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -219;
	} else {
		printf("Test Case 219 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x26EA7F565A30054CULL,
		0x9376CD2D7A6DA8F7ULL,
		0xF2BCA911BBFE9675ULL,
		0xC79E45F737C41015ULL,
		0xE34BAA665356EB71ULL,
		0xF5DC39C0114F3638ULL,
		0xF94320BB8A2F2FABULL,
		0x645A1CFBA0E059D5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x30397F3BA9F36AF3ULL,
		0x65CC986D16CB2953ULL,
		0xF173AB1012B6F7DCULL,
		0x0B365BDF593B1CDBULL,
		0x021D85C95C9BD1AEULL,
		0x4D913CFA42CF6DA6ULL,
		0x15633372129635FAULL,
		0xF05ADFFBA40F3FB9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x20287F1208300040ULL,
		0x0144882D12492853ULL,
		0xF030A91012B69654ULL,
		0x031641D711001011ULL,
		0x020980405012C120ULL,
		0x459038C0004F2420ULL,
		0x11432032020625AAULL,
		0x605A1CFBA0001991ULL
	}};
	printf("Test Case 220\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 220 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -220;
	} else {
		printf("Test Case 220 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5F9D0F4941DFFDC9ULL,
		0xBEE1C18638FE00B8ULL,
		0x633FCA22B211E0D3ULL,
		0x0E6FDFED0A236DCEULL,
		0x744E18337764E74BULL,
		0xCE62AD66A98C352BULL,
		0x06DE25EFB226D5B8ULL,
		0xD42139AD7EFB1EAEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6CA8792E5C24CF0CULL,
		0xCDFA98DE8F6F9AE4ULL,
		0x450C2CF960531D50ULL,
		0x1C5C96D51DE00243ULL,
		0x30319C8AAC6C97E4ULL,
		0x3A750A6D4030A70AULL,
		0xFF3E3B12E9501345ULL,
		0x1F4E94F5B2C84BF2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4C8809084004CD08ULL,
		0x8CE08086086E00A0ULL,
		0x410C082020110050ULL,
		0x0C4C96C508200042ULL,
		0x3000180224648740ULL,
		0x0A6008640000250AULL,
		0x061E2102A0001100ULL,
		0x140010A532C80AA2ULL
	}};
	printf("Test Case 221\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 221 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -221;
	} else {
		printf("Test Case 221 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7B9BF14916FA8285ULL,
		0xC79DDC1BF1A6F710ULL,
		0x5C935B940F1FFD1CULL,
		0xE6D9067F4E0888DDULL,
		0x16631EC7836C23B8ULL,
		0x75C69617218DC58AULL,
		0x520A36DFAF200F90ULL,
		0x8341BB3F37A649E5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB19A22FA3E3A674AULL,
		0xF4D93AD5570574C1ULL,
		0xD05E4DA02BE3A30AULL,
		0x24A178334226F721ULL,
		0xFE6AB449C010B781ULL,
		0x52EFD9DAC09A1FB9ULL,
		0xB6774A47C9C92034ULL,
		0x672639D3A17E3543ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x319A2048163A0200ULL,
		0xC499181151047400ULL,
		0x501249800B03A108ULL,
		0x2481003342008001ULL,
		0x1662144180002380ULL,
		0x50C6901200880588ULL,
		0x1202024789000010ULL,
		0x0300391321260141ULL
	}};
	printf("Test Case 222\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 222 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -222;
	} else {
		printf("Test Case 222 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6EDD48A47D806F19ULL,
		0x61953B9B3C423B8AULL,
		0xD3CC9585396289BBULL,
		0xC3B2C8EDE3B9F94AULL,
		0x186005429743FB13ULL,
		0xBB5F79FD86BA93C1ULL,
		0x3B32C2D5DD1C5B50ULL,
		0xB4E4C713D06E66FFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x55D6561EC2A11E68ULL,
		0x14C96F32265A22BAULL,
		0xACCC0640289BF31CULL,
		0xAED4EA72F6903C85ULL,
		0xE96AB80D743B6268ULL,
		0x195FD9C2C3531A74ULL,
		0xAC71428F58838489ULL,
		0xECC663DEDD5580E3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x44D4400440800E08ULL,
		0x00812B122442228AULL,
		0x80CC040028028118ULL,
		0x8290C860E2903800ULL,
		0x0860000014036200ULL,
		0x195F59C082121240ULL,
		0x2830428558000000ULL,
		0xA4C44312D04400E3ULL
	}};
	printf("Test Case 223\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 223 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -223;
	} else {
		printf("Test Case 223 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x718C960996006877ULL,
		0x1DF44EA7D4966FE2ULL,
		0x4A57D00144006D88ULL,
		0x97A7E6E3B9D91726ULL,
		0x8638A7E95DCD2073ULL,
		0x247B25052A8D308DULL,
		0x4B2D2103E2AE7AADULL,
		0xE668EAE1F36280C0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAAA3B78A857EA5DBULL,
		0x053F59AE202C90A7ULL,
		0xE91E4998137354B6ULL,
		0x0F87A05497C3FB1AULL,
		0x5BA2A6019CE29B7BULL,
		0xDB4409B967EF99F0ULL,
		0x25101AEFEC0B8CBBULL,
		0xC03090BBE0F790A7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2080960884002053ULL,
		0x053448A6000400A2ULL,
		0x4816400000004480ULL,
		0x0787A04091C11302ULL,
		0x0220A6011CC00073ULL,
		0x00400101228D1080ULL,
		0x01000003E00A08A9ULL,
		0xC02080A1E0628080ULL
	}};
	printf("Test Case 224\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 224 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -224;
	} else {
		printf("Test Case 224 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC14DF64D81458CDBULL,
		0x9C876FF5A6906179ULL,
		0xD7818D4070785884ULL,
		0xF723DE7B24FD92EBULL,
		0x445CBB87CCB60B08ULL,
		0x78AB0E5FAD721515ULL,
		0xB85716074B15B10EULL,
		0xD2485D5AF039A253ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xECC8B06D1D742694ULL,
		0xF9815DBEFB0E618FULL,
		0x40CA0045C90AA32AULL,
		0xEB3A7DCA4BA87C3EULL,
		0x911B4E0B63DD0B07ULL,
		0x169C1EB80374FECAULL,
		0xEB9BF7F33511F333ULL,
		0xA1C1238ECC201132ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC048B04D01440490ULL,
		0x98814DB4A2006109ULL,
		0x4080004040080000ULL,
		0xE3225C4A00A8102AULL,
		0x00180A0340940B00ULL,
		0x10880E1801701400ULL,
		0xA81316030111B102ULL,
		0x8040010AC0200012ULL
	}};
	printf("Test Case 225\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 225 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -225;
	} else {
		printf("Test Case 225 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x34313000E59B90EBULL,
		0x770D4217024E283EULL,
		0xB51B300ADBE7D976ULL,
		0xCE641D56006EC1DCULL,
		0x32EEB9B5858E1ADFULL,
		0x2C6CC7C2BC79F790ULL,
		0x2A696854516CE2EFULL,
		0x1DBFA68F3372C0B0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7CE454AA97369EF0ULL,
		0xEDC4C2545871EBECULL,
		0x5473E84BBB8D352EULL,
		0x1AB53CE76F5735B2ULL,
		0x9BE32FFFDDD28AAFULL,
		0xB84650F3239BC0DDULL,
		0xF9464FE8DCB5323FULL,
		0x6EB0EE8D128C503AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x34201000851290E0ULL,
		0x650442140040282CULL,
		0x1413200A9B851126ULL,
		0x0A241C4600460190ULL,
		0x12E229B585820A8FULL,
		0x284440C22019C090ULL,
		0x284048405024222FULL,
		0x0CB0A68D12004030ULL
	}};
	printf("Test Case 226\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 226 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -226;
	} else {
		printf("Test Case 226 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x48E17C2C0DCEC98AULL,
		0x7E65BBA4B32EE801ULL,
		0x5D35353B9BCAFDF7ULL,
		0xFD33CD5D1FAB9466ULL,
		0xA9C7A7BA1D7039A6ULL,
		0x0BE7D8C62B4C8736ULL,
		0x03467416D5EDF701ULL,
		0x4E12A1055E32A0C4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD8C464383746C7CCULL,
		0x0D065EA931AF4993ULL,
		0xA86D565863F6991BULL,
		0xD72F89432D7043C1ULL,
		0xE214FF8C6F7C0AE3ULL,
		0x963691D792271AACULL,
		0x49893A5C26AB399BULL,
		0x83AA37067D328776ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x48C064280546C188ULL,
		0x0C041AA0312E4801ULL,
		0x0825141803C29913ULL,
		0xD52389410D200040ULL,
		0xA004A7880D7008A2ULL,
		0x022690C602040224ULL,
		0x0100301404A93101ULL,
		0x020221045C328044ULL
	}};
	printf("Test Case 227\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 227 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -227;
	} else {
		printf("Test Case 227 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x211397565F6C148FULL,
		0x1AAD12793DDD1C10ULL,
		0xAA1DDD72B0DEA50DULL,
		0x86084861CD527228ULL,
		0x4F68933BE34FEFA9ULL,
		0xE0B308F58A15B802ULL,
		0x5FAA9AD36424F66AULL,
		0x208DC841412ECF95ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCD3E5C7AF496692BULL,
		0x011E19A8896CEBA6ULL,
		0x0A35A4B3C2074F40ULL,
		0x4949180B2603A664ULL,
		0x7A643214E4F101A1ULL,
		0xE48D99FDDC93CD2AULL,
		0x83F6F5718103AB61ULL,
		0x1BE856F0605FF269ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x011214525404000BULL,
		0x000C1028094C0800ULL,
		0x0A15843280060500ULL,
		0x0008080104022220ULL,
		0x4A601210E04101A1ULL,
		0xE08108F588118802ULL,
		0x03A290510000A260ULL,
		0x00884040400EC201ULL
	}};
	printf("Test Case 228\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 228 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -228;
	} else {
		printf("Test Case 228 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB04E26F2F182D972ULL,
		0x9475F4518C27596CULL,
		0x13C13CD537429BC4ULL,
		0x97565BDFC858CCB3ULL,
		0x889DD55431E1A36FULL,
		0x0B90B88A999E03AAULL,
		0x138B8D86FA5EAAC1ULL,
		0x94FC5250452E040AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x48C747BFB8DE824CULL,
		0x91005FC3C741BDB6ULL,
		0x40F6EFB72088E465ULL,
		0x237C63A40DE3D4A7ULL,
		0x68C8E9C8F8E4431EULL,
		0x04640F909D967209ULL,
		0xE35C53607EC0CCEBULL,
		0x0D1F6BBD61150C7EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x004606B2B0828040ULL,
		0x9000544184011924ULL,
		0x00C02C9520008044ULL,
		0x035443840840C4A3ULL,
		0x0888C14030E0030EULL,
		0x0000088099960208ULL,
		0x030801007A4088C1ULL,
		0x041C42104104040AULL
	}};
	printf("Test Case 229\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 229 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -229;
	} else {
		printf("Test Case 229 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6DB03ACED2883598ULL,
		0xB762876485F17A93ULL,
		0x3E10AFE0C516D2C2ULL,
		0x5827C594876DEF20ULL,
		0x38FF4886BC770FD4ULL,
		0x745DB1720DFB8A28ULL,
		0x8E2863742095F719ULL,
		0xDB5B3C879C7760E8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x53C8C52E7CB7A841ULL,
		0x047686453D73786FULL,
		0x74559F452C8AD516ULL,
		0x3D45FD3F204078B3ULL,
		0xB2785618AA4F7A3DULL,
		0xBAB54E1642D6AE08ULL,
		0x1043FA8F4D4646F8ULL,
		0x87F6E3B91E84DD53ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4180000E50802000ULL,
		0x0462864405717803ULL,
		0x34108F400402D002ULL,
		0x1805C51400406820ULL,
		0x30784000A8470A14ULL,
		0x3015001200D28A08ULL,
		0x0000620400044618ULL,
		0x835220811C044040ULL
	}};
	printf("Test Case 230\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 230 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -230;
	} else {
		printf("Test Case 230 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x67EB839F0E772449ULL,
		0xA865D4F2F128A636ULL,
		0x8399C68707BAD17BULL,
		0x513A5257EF7C208BULL,
		0x114280482B89C249ULL,
		0xF4C0FB5A5A1AE23DULL,
		0xD1C716B161965B39ULL,
		0x387F53DE8311DC90ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCB206F5AB3BF31BFULL,
		0xDB96CBC621813452ULL,
		0x7094D778D884E8D5ULL,
		0x2A5B359F1A8A98DEULL,
		0xC9DBE4E3291D6DB9ULL,
		0x77BB200DB2D33186ULL,
		0x5E2082A23F7FCA8AULL,
		0xD96074A6623E7B64ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4320031A02372009ULL,
		0x8804C0C221002412ULL,
		0x0090C6000080C051ULL,
		0x001A10170A08008AULL,
		0x0142804029094009ULL,
		0x7480200812122004ULL,
		0x500002A021164A08ULL,
		0x1860508602105800ULL
	}};
	printf("Test Case 231\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 231 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -231;
	} else {
		printf("Test Case 231 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x40A31D1B421960E1ULL,
		0xE3E1CC0E13BD9DE7ULL,
		0x9BC4AA19C082E609ULL,
		0xE9F10DD34726A926ULL,
		0xF96E3C353F6A2264ULL,
		0x268DEBD346FC7598ULL,
		0x3AE6FC7A26F60958ULL,
		0xEECC54F17FC08776ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAC57E118D800C525ULL,
		0x81AE5B5E28ED128AULL,
		0x3EBF9038466D4BA5ULL,
		0xF19AAA192494C153ULL,
		0x09617333589D8C02ULL,
		0xA1D5CAFA95287244ULL,
		0x9A2A57C32E5BB984ULL,
		0x5289F1F1F92DCAA5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0003011840004021ULL,
		0x81A0480E00AD1082ULL,
		0x1A84801840004201ULL,
		0xE190081104048102ULL,
		0x0960303118080000ULL,
		0x2085CAD204287000ULL,
		0x1A22544226520900ULL,
		0x428850F179008224ULL
	}};
	printf("Test Case 232\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 232 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -232;
	} else {
		printf("Test Case 232 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6098B14C36AD4ACEULL,
		0xD0D7278FE69140FFULL,
		0xC838E23BFD4B2756ULL,
		0x779A2872AF8F9960ULL,
		0x5D51F10CC677A871ULL,
		0x881EB9E7992961EAULL,
		0x9B757491E6CF37FAULL,
		0xA22033122CE80BC3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC91741A349DD0A80ULL,
		0xD7851BF1E4BF31F8ULL,
		0x991B63C96302FAE3ULL,
		0xA787818B1FED65F1ULL,
		0xF7F69105A4B653ABULL,
		0xA30795C6831745AEULL,
		0x8194DE350FA32BE0ULL,
		0x286B87F657B51720ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x40100100008D0A80ULL,
		0xD0850381E49100F8ULL,
		0x8818620961022242ULL,
		0x278200020F8D0160ULL,
		0x5550910484360021ULL,
		0x800691C6810141AAULL,
		0x81145411068323E0ULL,
		0x2020031204A00300ULL
	}};
	printf("Test Case 233\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 233 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -233;
	} else {
		printf("Test Case 233 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3EE3E0BE219B3AC5ULL,
		0x49062C2C38227A22ULL,
		0xD050AB2C9B62378BULL,
		0x16479B479081BEF6ULL,
		0x606BA23FFFCB04D2ULL,
		0xBB7718A2E5D73621ULL,
		0x18CFF9413801446AULL,
		0x50129B1D825601C5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF08074274BFB7400ULL,
		0xAF7E076E4B42B2C2ULL,
		0x1CDF90C2195379EEULL,
		0x32A3A98D80A97B3FULL,
		0xCBAECEF313FB13C0ULL,
		0x3229C9E48171F5E4ULL,
		0x84AD017CF876B7F1ULL,
		0xE0AFB1A1DFA0DB35ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x30806026019B3000ULL,
		0x0906042C08023202ULL,
		0x105080001942318AULL,
		0x1203890580813A36ULL,
		0x402A823313CB00C0ULL,
		0x322108A081513420ULL,
		0x008D014038000460ULL,
		0x4002910182000105ULL
	}};
	printf("Test Case 234\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 234 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -234;
	} else {
		printf("Test Case 234 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCD9E1462F437284DULL,
		0x97B0FF0D917CE404ULL,
		0x421078CD407DDC87ULL,
		0xB915CCDA3F108EB1ULL,
		0x1525AFF441E83C93ULL,
		0xBE1A3837B078B8EBULL,
		0x48BEE320EDB3D21BULL,
		0x5C32D340DF335DDBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x844095C8526DE9E9ULL,
		0x8D55E7E071522D50ULL,
		0x8C645360962C578EULL,
		0x0F7591F0283C18A3ULL,
		0x3D96AC33FF75BBEFULL,
		0x047E826D1B8B6E45ULL,
		0x24430B174B6691D8ULL,
		0x65F68D61EDA7D6EFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8400144050252849ULL,
		0x8510E70011502400ULL,
		0x00005040002C5486ULL,
		0x091580D0281008A1ULL,
		0x1504AC3041603883ULL,
		0x041A002510082841ULL,
		0x0002030049229018ULL,
		0x44328140CD2354CBULL
	}};
	printf("Test Case 235\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 235 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -235;
	} else {
		printf("Test Case 235 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x210296D218F12478ULL,
		0x28B19AD69CA5C3FAULL,
		0x0FD613F24E19CC78ULL,
		0x8BD685A540767153ULL,
		0x0F59E6B57799BEA3ULL,
		0xD79F83ED4B950614ULL,
		0x792DAF1CF63C0A91ULL,
		0xF13B9F58634EFF49ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x516163D008352C38ULL,
		0x03CD484CEAD9140AULL,
		0x287920E0803E0063ULL,
		0x220CF9355C5A4711ULL,
		0x79769E375507B255ULL,
		0x33A37B1FD837ED37ULL,
		0xAC8BD448874A445CULL,
		0x9297E9A6375EEDC8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x010002D008312438ULL,
		0x008108448881000AULL,
		0x085000E000180060ULL,
		0x0204812540524111ULL,
		0x095086355501B201ULL,
		0x1383030D48150414ULL,
		0x2809840886080010ULL,
		0x90138900234EED48ULL
	}};
	printf("Test Case 236\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 236 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -236;
	} else {
		printf("Test Case 236 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBD186A8A52387864ULL,
		0x89333F78063012D8ULL,
		0xE1C052EBB3DC6DB1ULL,
		0xF377ECCCA9F6B0FCULL,
		0xAB302B14D12C40AAULL,
		0x1806E703C9256837ULL,
		0x72EDE6AC0DF51B5FULL,
		0xD3A82B4730E58D20ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2E1F41A11F85310CULL,
		0x8ACFBE57F36F65ABULL,
		0x708236F60AF27D21ULL,
		0xD9AF2EA22E25C4A9ULL,
		0xA4ED4D5C1630395BULL,
		0xF7AFB56B3428E99BULL,
		0xAA3AFAF9B60BEF7FULL,
		0xEE7239C233D93EB7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2C18408012003004ULL,
		0x88033E5002200088ULL,
		0x608012E202D06D21ULL,
		0xD1272C80282480A8ULL,
		0xA02009141020000AULL,
		0x1006A50300206813ULL,
		0x2228E2A804010B5FULL,
		0xC220294230C10C20ULL
	}};
	printf("Test Case 237\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 237 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -237;
	} else {
		printf("Test Case 237 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCDB03B02AB5AA8DAULL,
		0x76CE609AF0890D0AULL,
		0x0A5AAEB64DC32031ULL,
		0x7B239D281697DE4FULL,
		0xC1567211D0280DFDULL,
		0x8BC4513E3C8F7B7DULL,
		0x9D01E632E5952ABAULL,
		0x96B59BAA24EBC205ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x715362A6B976E45CULL,
		0x956B3C7F2A81FAF1ULL,
		0xC59D5016951C4B2FULL,
		0xEE1123888F74C659ULL,
		0xD99892F66990FE98ULL,
		0x4537C239929A9EE8ULL,
		0xC76D3CA6D6356A75ULL,
		0x4DE4E6126616CEE4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x41102202A952A058ULL,
		0x144A201A20810800ULL,
		0x0018001605000021ULL,
		0x6A0101080614C649ULL,
		0xC110121040000C98ULL,
		0x01044038108A1A68ULL,
		0x85012422C4152A30ULL,
		0x04A482022402C204ULL
	}};
	printf("Test Case 238\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 238 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -238;
	} else {
		printf("Test Case 238 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAC91B88060E90A45ULL,
		0x3F1B8F0E79B0C4ACULL,
		0xCFB7A52BD52B9EA6ULL,
		0x18732A28A266A55FULL,
		0x2E8FDB32731B886FULL,
		0x0BFC52CCBCF214F0ULL,
		0xF3339567B4B78308ULL,
		0x4B41BE9C2BBEF376ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2A48856B7E3AEF3BULL,
		0x72B246056D6EA9A8ULL,
		0x61ABA2609BC31EEBULL,
		0xE9D2A3D13DF54A40ULL,
		0xFAEB5739CB8F492EULL,
		0x079F801B368E410EULL,
		0x8AFEC14E3922E896ULL,
		0x91CCE2AFC0CE5C43ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2800800060280A01ULL,
		0x32120604692080A8ULL,
		0x41A3A02091031EA2ULL,
		0x0852220020640040ULL,
		0x2A8B5330430B082EULL,
		0x039C000834820000ULL,
		0x8232814630228000ULL,
		0x0140A28C008E5042ULL
	}};
	printf("Test Case 239\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 239 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -239;
	} else {
		printf("Test Case 239 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x73EA6624C0AC40F1ULL,
		0xF6CDAA672E9D3EB2ULL,
		0x613434555D17F1C0ULL,
		0x6A19148F5F05B93BULL,
		0x1EF8BBBE675F5AC5ULL,
		0x917605976F25DC12ULL,
		0x214D3D67F4BF9DABULL,
		0xC77871817B3D78D0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF2743AE7E7C0CE6BULL,
		0x8FBAE8F23527EC4CULL,
		0x2AEA310776199E56ULL,
		0x7A61703B984DFBB8ULL,
		0x1CBEEFC86C23C15EULL,
		0x830B4A9C34FE02E3ULL,
		0x767169369E8A583FULL,
		0xF39259AE24ABEE76ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x72602224C0804061ULL,
		0x8688A86224052C00ULL,
		0x2020300554119040ULL,
		0x6A01100B1805B938ULL,
		0x1CB8AB8864034044ULL,
		0x8102009424240002ULL,
		0x20412926948A182BULL,
		0xC310518020296850ULL
	}};
	printf("Test Case 240\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 240 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -240;
	} else {
		printf("Test Case 240 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5762730369D1D426ULL,
		0x13AC30A319936311ULL,
		0xC3862A96E11BA51DULL,
		0x881B70EA2A700C90ULL,
		0x9AF0A669E48E9A91ULL,
		0x4AE28C194241303EULL,
		0x203CB1B24751BCDFULL,
		0x84884415FDA6DC4CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x432B2866B346B8FDULL,
		0x713D445594D321D3ULL,
		0x463189F19B6FE484ULL,
		0xE5B53FA6F830DD19ULL,
		0x83EA101255A6AFBAULL,
		0x076710CB36A3B4BEULL,
		0xCA33C43299A92B55ULL,
		0x20C884BC1FCA56ABULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4322200221409024ULL,
		0x112C000110932111ULL,
		0x42000890810BA404ULL,
		0x801130A228300C10ULL,
		0x82E0000044868A90ULL,
		0x026200090201303EULL,
		0x0030803201012855ULL,
		0x008804141D825408ULL
	}};
	printf("Test Case 241\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 241 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -241;
	} else {
		printf("Test Case 241 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x49320E1108DF002EULL,
		0x3A8F66D3CC3CB4FDULL,
		0xA47827D8994E704DULL,
		0x1074CA070633D269ULL,
		0x1D2D017814E37C58ULL,
		0x47D270F7825789B3ULL,
		0x1340DBABB8FA43EEULL,
		0x3EE037FA874522EDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCCE667E3D89C0A61ULL,
		0x9A8315AA221AF5FCULL,
		0x9E104A1B245C65BDULL,
		0x065F8C33B32EB43EULL,
		0x1607A2930587F17CULL,
		0x89B4B5940E95A7D4ULL,
		0x2C1D73D2F6A1DCB2ULL,
		0x3F042BA01176FABAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x48220601089C0020ULL,
		0x1A8304820018B4FCULL,
		0x84100218004C600DULL,
		0x0054880302229028ULL,
		0x1405001004837058ULL,
		0x0190309402158190ULL,
		0x00005382B0A040A2ULL,
		0x3E0023A0014422A8ULL
	}};
	printf("Test Case 242\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 242 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -242;
	} else {
		printf("Test Case 242 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0201B190E0686368ULL,
		0x0ED544A56080393CULL,
		0xBF6A76907BA53F4BULL,
		0x7D48F3D6BC155B95ULL,
		0x90F22D6B279E6D0BULL,
		0xCE5851C735EE00A1ULL,
		0x0E6AA13026171CEFULL,
		0xEAD4A3D9BC0FACBEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBD612128B21E152CULL,
		0xE41709743E3829BCULL,
		0x8133C658A7CF9A31ULL,
		0xE94714F438EEE781ULL,
		0xB8C03FE919838324ULL,
		0xF781BA77D270A2AEULL,
		0x39288F7C5647A956ULL,
		0x06640755E9FB58F4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x00012100A0080128ULL,
		0x041500242000293CULL,
		0x8122461023851A01ULL,
		0x694010D438044381ULL,
		0x90C02D6901820100ULL,
		0xC6001047106000A0ULL,
		0x0828813006070846ULL,
		0x02440351A80B08B4ULL
	}};
	printf("Test Case 243\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 243 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -243;
	} else {
		printf("Test Case 243 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF05BB95FA6A7859BULL,
		0xA8C62327E02D9471ULL,
		0x6F840A09EB6A1339ULL,
		0x14C8FFDC337D8D71ULL,
		0xCCF9497AD9991CC9ULL,
		0xDEADD4D6ABDFBD52ULL,
		0xC81F4DFD8CD863FBULL,
		0x3E92340AE05B848FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x930541BFACA9E2FBULL,
		0xB6DD1D97974CAB14ULL,
		0xB59119B7DCCD8945ULL,
		0x603252C39D82069DULL,
		0x9099112BE425B7DEULL,
		0x83F29D0E53F06C06ULL,
		0x020B1E7D2008F4ECULL,
		0x260E5E93963E3CA2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9001011FA4A1809BULL,
		0xA0C40107800C8010ULL,
		0x25800801C8480101ULL,
		0x000052C011000411ULL,
		0x8099012AC00114C8ULL,
		0x82A0940603D02C02ULL,
		0x000B0C7D000860E8ULL,
		0x26021402801A0482ULL
	}};
	printf("Test Case 244\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 244 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -244;
	} else {
		printf("Test Case 244 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x895ABBF89ABE13FEULL,
		0x607F8AA78F4830AAULL,
		0x507A275CB50810D7ULL,
		0xD119F2FF31C213DBULL,
		0x65DD4D1F14542D53ULL,
		0x9DCFDC7F1732EE63ULL,
		0x53DB7D358134E1C3ULL,
		0x134457C18DCC7D8AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA867FC30578DDE5EULL,
		0xED5E475147147528ULL,
		0xABF83EC579C26A6DULL,
		0xEA64242F373A124CULL,
		0xBB94D3EF5E9CB898ULL,
		0x5823A4AE2539636EULL,
		0xC590F41CDFC51386ULL,
		0x321163A200E7AEF4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8842B830128C125EULL,
		0x605E020107003028ULL,
		0x0078264431000045ULL,
		0xC000202F31021248ULL,
		0x2194410F14142810ULL,
		0x1803842E05306262ULL,
		0x4190741481040182ULL,
		0x1200438000C42C80ULL
	}};
	printf("Test Case 245\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 245 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -245;
	} else {
		printf("Test Case 245 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x03B7803D8B694EAEULL,
		0xBA9B353669BA2F9EULL,
		0xA65788EFD9D0FBF2ULL,
		0xDF0496004B94CAC1ULL,
		0xA54D6C488D02858CULL,
		0xFA0D6C23AE2DD507ULL,
		0xF3882922560F64C7ULL,
		0x29CEDD6AFE1BA82CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x067E7FAADC5C2CB6ULL,
		0x28E32306EC466803ULL,
		0x69B5D51185972227ULL,
		0xA99AE4C92A10582CULL,
		0x84507B9B1C8A2B0DULL,
		0x1592565DD159B865ULL,
		0xFE377884122E93E2ULL,
		0x5FB164353A1ED67BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0236002888480CA6ULL,
		0x2883210668022802ULL,
		0x2015800181902222ULL,
		0x890084000A104800ULL,
		0x844068080C02010CULL,
		0x1000440180099005ULL,
		0xF2002800120E00C2ULL,
		0x098044203A1A8028ULL
	}};
	printf("Test Case 246\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 246 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -246;
	} else {
		printf("Test Case 246 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4C2274CDA49CC392ULL,
		0x5A8E5F0AFEE5AF91ULL,
		0xAA123E9F1D092634ULL,
		0xA03B5E5C04C068A0ULL,
		0x1E851F099E89DD37ULL,
		0xC6011383A5E669DDULL,
		0x6DC5497E0EECF36DULL,
		0x5C9B3641558D9316ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9A82B0CCEABD51DBULL,
		0x0C41FC966BC5310EULL,
		0xC08C79D10267A059ULL,
		0x15DDE4D3D35B46B2ULL,
		0x759BD9073FC9B936ULL,
		0xA85BFF319F9CC568ULL,
		0xBFAE3A58D1D5F64EULL,
		0x7610499ECA35A062ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x080230CCA09C4192ULL,
		0x08005C026AC52100ULL,
		0x8000389100012010ULL,
		0x00194450004040A0ULL,
		0x148119011E899936ULL,
		0x8001130185844148ULL,
		0x2D84085800C4F24CULL,
		0x5410000040058002ULL
	}};
	printf("Test Case 247\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 247 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -247;
	} else {
		printf("Test Case 247 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDF0AE920AE6105E8ULL,
		0x10F7F0867269F9AEULL,
		0x3901C5C79A1D9EC3ULL,
		0x5B4C12869581750DULL,
		0xE05517D7379F0096ULL,
		0x43BD1E8DD497576FULL,
		0x3591C575ED82B073ULL,
		0x056C9A593CD96C5BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEF3E5C98F4B999A3ULL,
		0x02DD0FD8DA143F5DULL,
		0xEFE4490CED4F63E4ULL,
		0x0677A4C0B5444ACEULL,
		0x025EA0244D8CD92EULL,
		0xCDFB034F1E899097ULL,
		0xC3332673DD134F57ULL,
		0x28A7B8A22F5858B3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCF0A4800A42101A0ULL,
		0x00D500805200390CULL,
		0x29004104880D02C0ULL,
		0x024400809500400CULL,
		0x00540004058C0006ULL,
		0x41B9020D14811007ULL,
		0x01110471CD020053ULL,
		0x002498002C584813ULL
	}};
	printf("Test Case 248\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 248 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -248;
	} else {
		printf("Test Case 248 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA701A72A18B93BD7ULL,
		0x4BF05706F9AD1AADULL,
		0xC987DEF5E81CEC56ULL,
		0x77E0C9FC36E0F9FCULL,
		0xF0619C4BA15823EDULL,
		0xC2E754B4976CECC5ULL,
		0x8A1EF83556F46B95ULL,
		0x76FA3C7382BBC950ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x39CEF978A5775B3EULL,
		0x93CE28B617599083ULL,
		0x3AF2087B95C73899ULL,
		0x005039D3D605AA05ULL,
		0x883C2BD16A4C0D59ULL,
		0x906DB3D196DD9228ULL,
		0x07848E63A4E9469EULL,
		0x685B79BA4318E31EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2100A12800311B16ULL,
		0x03C0000611091081ULL,
		0x0882087180042810ULL,
		0x004009D01600A804ULL,
		0x8020084120480149ULL,
		0x80651090964C8000ULL,
		0x0204882104E04294ULL,
		0x605A38320218C110ULL
	}};
	printf("Test Case 249\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 249 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -249;
	} else {
		printf("Test Case 249 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x610331FE3EFC6A84ULL,
		0x9905CA60F90CD8C7ULL,
		0x924FE057D9908715ULL,
		0xB8638E6D2A997848ULL,
		0xD2F1123245A281A8ULL,
		0xCB1AE1F7E8666A00ULL,
		0xB0E2701B400CE3DBULL,
		0x0699F226FA85F99BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB2232A4218B385BDULL,
		0x735648742FB47534ULL,
		0x33817278521A04CFULL,
		0xCCC6B92F2791EB90ULL,
		0x9C37B82A64A16C79ULL,
		0x13DDF51DE6C8B9EBULL,
		0xB85886475593A5DDULL,
		0x5B89A5C4930C5DF4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2003204218B00084ULL,
		0x1104486029045004ULL,
		0x1201605050100405ULL,
		0x8842882D22916800ULL,
		0x9031102244A00028ULL,
		0x0318E115E0402800ULL,
		0xB04000034000A1D9ULL,
		0x0289A00492045990ULL
	}};
	printf("Test Case 250\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 250 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -250;
	} else {
		printf("Test Case 250 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC8E217623DDEC408ULL,
		0xC4E2CF70934D344EULL,
		0x1B502DD9373E9868ULL,
		0x23163A10FBE61D62ULL,
		0xD9DA75C1676B3371ULL,
		0xEB8B87A76668F00CULL,
		0xBE38D11EC68949F3ULL,
		0x050A15356F78E45CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF630D8D88D98B6C5ULL,
		0x63D74739D92FCA1EULL,
		0xDB8B28DB2B6AC499ULL,
		0x531004A451DB2308ULL,
		0x73B526C32B70F3F1ULL,
		0x86686336E0409FE7ULL,
		0x91D4E40560A591CCULL,
		0x4ABE2BDA96CEFF60ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC02010400D988400ULL,
		0x40C24730910D000EULL,
		0x1B0028D9232A8008ULL,
		0x0310000051C20100ULL,
		0x519024C123603371ULL,
		0x8208032660409004ULL,
		0x9010C004408101C0ULL,
		0x000A01100648E440ULL
	}};
	printf("Test Case 251\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 251 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -251;
	} else {
		printf("Test Case 251 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x866EB8AEEB143535ULL,
		0xBCDFBAF95A56115FULL,
		0xFBEA81705E5DD17BULL,
		0x1F75DE1A6BD02BFAULL,
		0x0A07772D758AEE55ULL,
		0xE7021946E335DBBAULL,
		0x937AD9CFE3DFF132ULL,
		0xD9F4F8483E78A7B2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4ECA8526FD628FE7ULL,
		0x3CA34997DDDB813BULL,
		0x0D13BE28A2C16E8AULL,
		0x0DF517DF52B9C22BULL,
		0x6511185FBCF30962ULL,
		0x0CF6CE2F54F13E7AULL,
		0x86F682E806A091CDULL,
		0x3344B91DF945E5BAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x064A8026E9000525ULL,
		0x3C8308915852011BULL,
		0x090280200241400AULL,
		0x0D75161A4290022AULL,
		0x0001100D34820840ULL,
		0x0402080640311A3AULL,
		0x827280C802809100ULL,
		0x1144B8083840A5B2ULL
	}};
	printf("Test Case 252\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 252 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -252;
	} else {
		printf("Test Case 252 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x94C8CF1D3E6DDFD9ULL,
		0x5E9FF74BAD4A0235ULL,
		0x1283559CACCB48E5ULL,
		0xC160E11D542D1767ULL,
		0x0648C68AE2AD26E4ULL,
		0x7CCEF8B2A074369FULL,
		0x99DE48DD8B2ED9B1ULL,
		0xDC22D7DDF8340612ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFBDA9BC985028283ULL,
		0xED315C84CCDEC258ULL,
		0x3D51A4ADDC784AB7ULL,
		0xC1F0E6AE958023FCULL,
		0xE27CB89DBCA4C14EULL,
		0xA04F6CC0E2FC50EFULL,
		0x59610B8AE8C1C386ULL,
		0x6436009B1F2D773EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x90C88B0904008281ULL,
		0x4C1154008C4A0210ULL,
		0x1001048C8C4848A5ULL,
		0xC160E00C14000364ULL,
		0x02488088A0A40044ULL,
		0x204E6880A074108FULL,
		0x194008888800C180ULL,
		0x4422009918240612ULL
	}};
	printf("Test Case 253\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 253 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -253;
	} else {
		printf("Test Case 253 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFBC467CD133C4605ULL,
		0x6C44F7B0C2A8596BULL,
		0x0DB65B8F515F3061ULL,
		0xDFA605C9D7F912CCULL,
		0xB37CC393AAEC91E5ULL,
		0x77BE0FC50056CD70ULL,
		0xB6BEDB6C631970CCULL,
		0x1F772DAB45849727ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x115FD6CF5E04E205ULL,
		0xA512553520CE892DULL,
		0xA6EFEAF76F8889EAULL,
		0xE6B9975ADE9E3CAEULL,
		0x39F5FE6AAD8E6FC6ULL,
		0x3CFF3080BA7C88A3ULL,
		0x6BCA68B6D3B23C83ULL,
		0x989546271FF3A1FDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x114446CD12044205ULL,
		0x2400553000880929ULL,
		0x04A64A8741080060ULL,
		0xC6A00548D698108CULL,
		0x3174C202A88C01C4ULL,
		0x34BE008000548820ULL,
		0x228A482443103080ULL,
		0x1815042305808125ULL
	}};
	printf("Test Case 254\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 254 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -254;
	} else {
		printf("Test Case 254 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x768203847C9264FBULL,
		0x46E1F2C39F304985ULL,
		0x4AD9029D9F34FD53ULL,
		0x0A5CA103437C0432ULL,
		0xAB28127D402FDFA7ULL,
		0x279425541800CA25ULL,
		0x0E87F6A8E6ADB6AAULL,
		0x8F64FDA15F7483F8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB5DFA8B374C6BEE9ULL,
		0x7FF2290EB4FF9789ULL,
		0x6069A5AC3B044055ULL,
		0x4A2D3F974A0DCF0DULL,
		0xCFAAC24D8C20DB8CULL,
		0x9CDFB375E158468EULL,
		0xD7E2B5806322C059ULL,
		0x911EE60ED983925AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x34820080748224E9ULL,
		0x46E0200294300181ULL,
		0x4049008C1B044051ULL,
		0x0A0C2103420C0400ULL,
		0x8B28024D0020DB84ULL,
		0x0494215400004204ULL,
		0x0682B48062208008ULL,
		0x8104E40059008258ULL
	}};
	printf("Test Case 255\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 255 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -255;
	} else {
		printf("Test Case 255 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6E9427D750ABD951ULL,
		0x5C2F23C47A3E059BULL,
		0x934909D7CBD5C1A9ULL,
		0x69325A978D24A6A1ULL,
		0x139A84F6D1435538ULL,
		0xDD1C6FBB0CC4310EULL,
		0x00269CD86E49C9BDULL,
		0x3F8A7F3F7B4EFC9FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEDAE8E3F452C4D56ULL,
		0x295FDC5E6F7B2CC0ULL,
		0xC528E91F5350D252ULL,
		0x3A693142EBD1FAF9ULL,
		0xD75FCFA56AC9BDD0ULL,
		0x7CFC8C64F5AB34ACULL,
		0xBC9B3C7501BA0432ULL,
		0x7F02F252B5052954ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6C84061740284950ULL,
		0x080F00446A3A0480ULL,
		0x810809174350C000ULL,
		0x282010028900A2A1ULL,
		0x131A84A440411510ULL,
		0x5C1C0C200480300CULL,
		0x00021C5000080030ULL,
		0x3F02721231042814ULL
	}};
	printf("Test Case 256\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 256 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -256;
	} else {
		printf("Test Case 256 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x163906EE3ACFF8EBULL,
		0x07321E79DD3876D9ULL,
		0x22B394F10ABD0BFAULL,
		0xB97841CD92E781F5ULL,
		0xFC993BC085706E6BULL,
		0x953A49B0D126707CULL,
		0x6192E11DE59E9F5BULL,
		0x3C9F69B0DD792589ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE9C12DDEA6EEBD66ULL,
		0x88C2484168EB6A27ULL,
		0x093DE9E32EAC5371ULL,
		0x31F688468AC81AAAULL,
		0xAB0B6719E024A3FAULL,
		0xAA0683FF41C22700ULL,
		0x28C5D77EAEC308AEULL,
		0x371D2D77D2FC3B96ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x000104CE22CEB862ULL,
		0x0002084148286201ULL,
		0x003180E10AAC0370ULL,
		0x3170004482C000A0ULL,
		0xA80923008020226AULL,
		0x800201B041022000ULL,
		0x2080C11CA482080AULL,
		0x341D2930D0782180ULL
	}};
	printf("Test Case 257\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 257 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -257;
	} else {
		printf("Test Case 257 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xACFF4B292988F483ULL,
		0x1CDD36359838A5B3ULL,
		0x6DFE182023B73406ULL,
		0xBC6420890F7EA5D8ULL,
		0x8CD7994051179C49ULL,
		0x6357E1827A3098E3ULL,
		0x16542ABABFE442F9ULL,
		0x6BA8D6446D19A476ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x58A2B4CAE6FEB2B4ULL,
		0x979E1CB2BB881FB8ULL,
		0x1A5018EB74ADD7D5ULL,
		0x85672D0EF261F84EULL,
		0x938EAA32CB50C0E5ULL,
		0xBF90289BD7A22151ULL,
		0x209642178E7950ECULL,
		0x972DD93477EB9870ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x08A200082088B080ULL,
		0x149C1430980805B0ULL,
		0x0850182020A51404ULL,
		0x846420080260A048ULL,
		0x8086880041108041ULL,
		0x2310208252200041ULL,
		0x001402128E6040E8ULL,
		0x0328D00465098070ULL
	}};
	printf("Test Case 258\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 258 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -258;
	} else {
		printf("Test Case 258 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9B226CEBAEFEF073ULL,
		0x40BC725BCDCAFA5AULL,
		0x24A1C13C80C6B1C8ULL,
		0x64B6E62EE9BDAA33ULL,
		0xCFBBF8BFB96D65D0ULL,
		0x144165811CB8B65EULL,
		0x81C4E93EC27BBDC3ULL,
		0x3B7A1EBFF7E14B10ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3CBC8D8082FF0008ULL,
		0x1E784523098772BEULL,
		0xE70764714BC94323ULL,
		0x0E2D75F10FB5E216ULL,
		0x0B7763751B45E5BDULL,
		0x67AA1BBFE5B64DAAULL,
		0x0BBD6A2FF2253F41ULL,
		0xB28B56832207D07CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x18200C8082FE0000ULL,
		0x003840030982721AULL,
		0x2401403000C00100ULL,
		0x0424642009B5A212ULL,
		0x0B33603519456590ULL,
		0x0400018104B0040AULL,
		0x0184682EC2213D41ULL,
		0x320A168322014010ULL
	}};
	printf("Test Case 259\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 259 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -259;
	} else {
		printf("Test Case 259 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x64E8865A19176FE4ULL,
		0x47EAA1197EB15FA7ULL,
		0x12368BFF291AB0F7ULL,
		0x3DBA415B3CD55048ULL,
		0x1D7AA295E690D062ULL,
		0x39C0BFF8AAA58E0AULL,
		0x0794B9C964104CC9ULL,
		0x34B005FFF0D7B991ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBAEF0C179F04BB8FULL,
		0x9B713F72D1F4DE8CULL,
		0xF2781ABE50C681F5ULL,
		0xEF74AE645C0235F7ULL,
		0xFBD981BD80B30BB6ULL,
		0x19E18B1361038982ULL,
		0x5D11B28FB5F269A9ULL,
		0x1B54693C26D9C777ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x20E8041219042B84ULL,
		0x0360211050B05E84ULL,
		0x12300ABE000280F5ULL,
		0x2D3000401C001040ULL,
		0x1958809580900022ULL,
		0x19C08B1020018802ULL,
		0x0510B08924104889ULL,
		0x1010013C20D18111ULL
	}};
	printf("Test Case 260\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 260 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -260;
	} else {
		printf("Test Case 260 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x25323743A64F8117ULL,
		0xD66EA3BEF1695808ULL,
		0xBE0287C296EB8DF8ULL,
		0x11DDBCA1C2F64FB9ULL,
		0x9BD04D844BFB6A68ULL,
		0x8467711813462FB1ULL,
		0x603F89862337E417ULL,
		0xF7E2F0BE9F168761ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x665175E25AB0DB01ULL,
		0x2AE904F8AA397D89ULL,
		0x8B4E137FB6871C93ULL,
		0xC46B47A22A561569ULL,
		0x65568F4F95B29CB0ULL,
		0x7ECACCB6ED98C5D3ULL,
		0x3744B23AE0A40E0AULL,
		0x0120D2CDF4CD0E2DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2410354202008101ULL,
		0x026800B8A0295808ULL,
		0x8A02034296830C90ULL,
		0x004904A002560529ULL,
		0x01500D0401B20820ULL,
		0x0442401001000591ULL,
		0x2004800220240402ULL,
		0x0120D08C94040621ULL
	}};
	printf("Test Case 261\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 261 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -261;
	} else {
		printf("Test Case 261 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x409F4152555D79FEULL,
		0x0D41B313BA149782ULL,
		0xE4B7D3172D62B33AULL,
		0x7FC5CD68DBC2AF10ULL,
		0xBF9D003BAE3EACADULL,
		0xC40B4AA3F0828808ULL,
		0x84608B8E818E64B7ULL,
		0xBFC7D1C9C591E2ECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8439E0A5E3A35169ULL,
		0x48FB9CFE5185F8D8ULL,
		0xD946C7E686B0D84DULL,
		0xD6FDA514A4CA9DCBULL,
		0xC3934A4EED5022C0ULL,
		0x73EB364BED0D1337ULL,
		0x8DD2D132C547B923ULL,
		0xBB507719D09EB5D3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0019400041015168ULL,
		0x0841901210049080ULL,
		0xC006C30604209008ULL,
		0x56C5850080C28D00ULL,
		0x8391000AAC102080ULL,
		0x400B0203E0000000ULL,
		0x8440810281062023ULL,
		0xBB405109C090A0C0ULL
	}};
	printf("Test Case 262\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 262 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -262;
	} else {
		printf("Test Case 262 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCCDB889514541E55ULL,
		0x62947CBFDA1E85FFULL,
		0x2318DEC6F0B8F656ULL,
		0x2FB56B13E22F9256ULL,
		0x08E715015C92B3C4ULL,
		0xF8AB90E1A4BFEFFFULL,
		0xE7D99A0CED63B653ULL,
		0x4B6BCF2512176E1FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x36A9F01203BB2EDBULL,
		0x157315701D26369FULL,
		0x52948AECD8CB26DBULL,
		0x596899020FEF444CULL,
		0x67288E1C66476DE6ULL,
		0x0903414D9D85410EULL,
		0x8B00F10A96BE1CA0ULL,
		0xC46750A49F4EC0DFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0489801000100E51ULL,
		0x001014301806049FULL,
		0x02108AC4D0882652ULL,
		0x09200902022F0044ULL,
		0x00200400440221C4ULL,
		0x080300418485410EULL,
		0x8300900884221400ULL,
		0x406340241206401FULL
	}};
	printf("Test Case 263\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 263 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -263;
	} else {
		printf("Test Case 263 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x34E05F8E4144EC3DULL,
		0x40C624D245F3B9B7ULL,
		0xA25C24BED895BBECULL,
		0xD87738AAC547CF0AULL,
		0x93E65401B9799C8CULL,
		0xD33F3C0FA1C8B0D1ULL,
		0x79A23F8B1BE445E9ULL,
		0xB5CA30EF71A11F1EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9D46B573BD7B2639ULL,
		0x39D2146A8834A1C6ULL,
		0x50E02330CBABB92CULL,
		0xB0C5714823528DB9ULL,
		0xD11DE5014F5C9F06ULL,
		0xBA60616556AA2D17ULL,
		0x9A1222C8B11C85BDULL,
		0x1C8559E8B82F3FB4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1440150201402439ULL,
		0x00C204420030A186ULL,
		0x00402030C881B92CULL,
		0x9045300801428D08ULL,
		0x9104440109589C04ULL,
		0x9220200500882011ULL,
		0x18022288110405A9ULL,
		0x148010E830211F14ULL
	}};
	printf("Test Case 264\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 264 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -264;
	} else {
		printf("Test Case 264 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x774F39CC7856000EULL,
		0x98ECC79489693D69ULL,
		0x365FE16BE85F7CDCULL,
		0xE78E3F57110FC2D3ULL,
		0xBA67E0C7B5D9C565ULL,
		0xABA80D1D76333786ULL,
		0xBBC86EBB132B8003ULL,
		0x3947C86B7F9BCDEBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD7E73978B68423AFULL,
		0x01CA597305532432ULL,
		0x30EE8D3A81F2DBEAULL,
		0x192A7B9B09143BB0ULL,
		0x6874008DA8B2F21EULL,
		0x51CE0FE085DE7939ULL,
		0xE1E85ADF28E52B41ULL,
		0xC27D067D8DDB2BC5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x574739483004000EULL,
		0x00C8411001412420ULL,
		0x304E812A805258C8ULL,
		0x010A3B1301040290ULL,
		0x28640085A090C004ULL,
		0x01880D0004123100ULL,
		0xA1C84A9B00210001ULL,
		0x004500690D9B09C1ULL
	}};
	printf("Test Case 265\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 265 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -265;
	} else {
		printf("Test Case 265 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5E8B2A68D5B9B84FULL,
		0x05F50B90BF930A04ULL,
		0xA77D34EA68503FC0ULL,
		0x4650BFBA6E35C227ULL,
		0xA8F085F0B0F2C8AFULL,
		0xA4558423676C764DULL,
		0x8C30C302FEB7E271ULL,
		0xE0BD1821DEADBA96ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA62C4A3E476CBA36ULL,
		0x2A36E701C9109BF8ULL,
		0xCE5EC6C912FE7D94ULL,
		0xF10540D35CB9FA3AULL,
		0x4EEFFB12397FF7BBULL,
		0x4F7EBD581FEA1508ULL,
		0x7ED24040BBDCC798ULL,
		0x0BFB3CC5D7A10B87ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x06080A284528B806ULL,
		0x0034030089100A00ULL,
		0x865C04C800503D80ULL,
		0x400000924C31C222ULL,
		0x08E081103072C0ABULL,
		0x0454840007681408ULL,
		0x0C104000BA94C210ULL,
		0x00B91801D6A10A86ULL
	}};
	printf("Test Case 266\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 266 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -266;
	} else {
		printf("Test Case 266 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x728A0C600B5D3821ULL,
		0x1DB48EAC357F3C74ULL,
		0x2B1A3FB66EC0DCA9ULL,
		0xB2EF7C68B4050430ULL,
		0x7D4A30A88EC4A3FAULL,
		0x8A1E069CCF76FEBBULL,
		0x97F651E9B341CF02ULL,
		0x2226D67C139C9BE2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD949D925E3DBD72BULL,
		0x28BE8E0A9C800C27ULL,
		0xF8A290E6FDA36C8EULL,
		0xA19747592FC22534ULL,
		0xE299BBF49CBF3327ULL,
		0x518C1EB07877C15CULL,
		0x9E6E7EAFB237538EULL,
		0xD0AFA3F86F3D9BA5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5008082003591021ULL,
		0x08B48E0814000C24ULL,
		0x280210A66C804C88ULL,
		0xA087444824000430ULL,
		0x600830A08C842322ULL,
		0x000C06904876C018ULL,
		0x966650A9B2014302ULL,
		0x00268278031C9BA0ULL
	}};
	printf("Test Case 267\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 267 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -267;
	} else {
		printf("Test Case 267 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF0E58214E5D40F9CULL,
		0x841F281859FE52A8ULL,
		0x2F21CCDCBF62E0A4ULL,
		0x6B0EE6E7A3E01933ULL,
		0x971029530E76220FULL,
		0xBCBCCF70AFB42763ULL,
		0x2EE3702AEDACD684ULL,
		0x65D2E25B0AFC8B3BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0E2ED58569E57405ULL,
		0x4F05544DEB76A9E6ULL,
		0x8DE7CA158C159C39ULL,
		0x8445593E29B7BA64ULL,
		0x049F3FD4A50AFC07ULL,
		0xB7DAA33EE999DF98ULL,
		0x4E02644A249FDEE4ULL,
		0x33DFBB25188941C9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0024800461C40404ULL,
		0x04050008497600A0ULL,
		0x0D21C8148C008020ULL,
		0x0004402621A01820ULL,
		0x0410295004022007ULL,
		0xB4988330A9900700ULL,
		0x0E02600A248CD684ULL,
		0x21D2A20108880109ULL
	}};
	printf("Test Case 268\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 268 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -268;
	} else {
		printf("Test Case 268 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x45549DA1434BB47CULL,
		0xCC9B7C32A8CB1A9CULL,
		0x270D1E06AF98BD79ULL,
		0x7034DF0AAA0AD7E2ULL,
		0xC476E3BB1DD69C20ULL,
		0x7BFE92469BAB4F16ULL,
		0x8C954FA88C0D2B9EULL,
		0xB0BC36A68D8F8014ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0C8957A1C81E61CEULL,
		0x53C88CC269673A31ULL,
		0xF93F8748D69F276EULL,
		0xC06664D1447F72A5ULL,
		0x107DBCAA39474D21ULL,
		0x15C5C44039434E6AULL,
		0xA033AF6564BFB01DULL,
		0x3F92021E22306EB4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x040015A1400A204CULL,
		0x40880C0228431A10ULL,
		0x210D060086982568ULL,
		0x40244400000A52A0ULL,
		0x0074A0AA19460C20ULL,
		0x11C4804019034E02ULL,
		0x80110F20040D201CULL,
		0x3090020600000014ULL
	}};
	printf("Test Case 269\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 269 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -269;
	} else {
		printf("Test Case 269 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x38ED71AAF7ACA901ULL,
		0xCE56C5F8E9DC94E3ULL,
		0xD9E3693ADD3517A2ULL,
		0xC87BE3C757103151ULL,
		0x087FDCAE89F0522FULL,
		0xADDF5B8B941BC58DULL,
		0xD176A3D6BB628CC1ULL,
		0x22FC4882FF0E011BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA7031B1D0EF33322ULL,
		0x6FE536DF6FA8A931ULL,
		0xB0A69DBBBD8D7354ULL,
		0xA794A49995553953ULL,
		0xBB03AD75B2130B9FULL,
		0xD205C89E4D1633FFULL,
		0x6DE4B71E733AD050ULL,
		0x623A23907DCCBECCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2001110806A02100ULL,
		0x4E4404D869888021ULL,
		0x90A2093A9D051300ULL,
		0x8010A08115103151ULL,
		0x08038C248010020FULL,
		0x8005488A0412018DULL,
		0x4164A31633228040ULL,
		0x223800807D0C0008ULL
	}};
	printf("Test Case 270\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 270 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -270;
	} else {
		printf("Test Case 270 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x657E35390225F4E9ULL,
		0x618466A530B8663CULL,
		0x2644B22C9DB3D686ULL,
		0x5B995BB0A54E0D80ULL,
		0x2BB52FC4285A47E1ULL,
		0xCDB7C9448E622579ULL,
		0xB471CC1668AFC3A2ULL,
		0x16503D7C16F76C87ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB0725C0F70B5C95DULL,
		0x4A5CC1864374B627ULL,
		0x78021185B2F65493ULL,
		0x771C57134833B531ULL,
		0xD932EA13C3D50162ULL,
		0x80281979A12291BBULL,
		0x15BD60C4CD992DA1ULL,
		0x7EF736912822DAE6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x207214090025C049ULL,
		0x4004408400302624ULL,
		0x2000100490B25482ULL,
		0x5318531000020500ULL,
		0x09302A0000500160ULL,
		0x8020094080220139ULL,
		0x14314004488901A0ULL,
		0x1650341000224886ULL
	}};
	printf("Test Case 271\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 271 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -271;
	} else {
		printf("Test Case 271 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0373FB05BBEA44FCULL,
		0xD6FD5170C721C19EULL,
		0x642CEC3A2FF27D1CULL,
		0xDF7422F01F6E44A5ULL,
		0xCE34313EDD1CEABFULL,
		0x042F4D238303047DULL,
		0x37C392CF4EA9F91EULL,
		0x3FF2A6DD10130815ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE67A53A98350E903ULL,
		0x6E8B24CE281ED002ULL,
		0xA34495816933F353ULL,
		0x3DFF4A0ECB5B7235ULL,
		0x21C3CB0DE86149DCULL,
		0x664C35D5E242A388ULL,
		0x309B6DA787E6F1F5ULL,
		0xDEA417F0794A60EBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0272530183404000ULL,
		0x468900400000C002ULL,
		0x2004840029327110ULL,
		0x1D7402000B4A4025ULL,
		0x0000010CC800489CULL,
		0x040C050182020008ULL,
		0x3083008706A0F114ULL,
		0x1EA006D010020001ULL
	}};
	printf("Test Case 272\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 272 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -272;
	} else {
		printf("Test Case 272 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x89552B91E3F86504ULL,
		0x41B7EBD8AF520B9BULL,
		0x1CF9D1D9642DAD7DULL,
		0x2069633DB9417B54ULL,
		0x9F55DE57BBB4A610ULL,
		0xC54A91D3B114E18BULL,
		0x29CFC0DFD7A9B506ULL,
		0x83DE3987E2B1FCD1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE254044192CDA523ULL,
		0x4E99F2990C8D5D3DULL,
		0x6237BB612C157C41ULL,
		0x30EF7D3F086DFE87ULL,
		0x0CA6248630D3DFCCULL,
		0x68368225C8124F03ULL,
		0x74495D43D060B710ULL,
		0x814007B4D40A133EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8054000182C82500ULL,
		0x4091E2980C000919ULL,
		0x0031914124052C41ULL,
		0x2069613D08417A04ULL,
		0x0C04040630908600ULL,
		0x4002800180104103ULL,
		0x20494043D020B500ULL,
		0x81400184C0001010ULL
	}};
	printf("Test Case 273\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 273 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -273;
	} else {
		printf("Test Case 273 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x09B4EC44E0F1AA84ULL,
		0xF9B14D9E0AF43EFEULL,
		0x79A24A8771D36959ULL,
		0xFDB6D366BDFF4CC4ULL,
		0x89818006FA85D61AULL,
		0x29CEB7CF05778391ULL,
		0x1837382B36A1DF39ULL,
		0x57684B6EDF0CA359ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4C0E8B6217A3A2A7ULL,
		0xED069C53A0327B84ULL,
		0x8980CF182F7D447DULL,
		0x3837D33D048DB1CCULL,
		0x74E17CAE0AC668ADULL,
		0x8DDB90BE10E4A454ULL,
		0xC2FC8CACA5EDE5A4ULL,
		0x6EC0415F5D006EAFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0804884000A1A284ULL,
		0xE9000C1200303A84ULL,
		0x09804A0021514059ULL,
		0x3836D324048D00C4ULL,
		0x008100060A844008ULL,
		0x09CA908E00648010ULL,
		0x0034082824A1C520ULL,
		0x4640414E5D002209ULL
	}};
	printf("Test Case 274\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 274 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -274;
	} else {
		printf("Test Case 274 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x870A843A6B18F010ULL,
		0x3A713A3F29AABA40ULL,
		0x9DBBECFE1711DDFBULL,
		0x32799EA0B691227CULL,
		0xFBFDD111A62DDF8CULL,
		0x84EEBDE88216D349ULL,
		0x8A91F0B75BDA9314ULL,
		0xBB1F5955D0045073ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6FFB0FB9E170943EULL,
		0x92A53332DB2C4643ULL,
		0xAD6357DE460EE506ULL,
		0xBDBBADAFF0684F3BULL,
		0xB188A8B4848E8C47ULL,
		0x954F30C123E461A8ULL,
		0xEC186B97A29D9935ULL,
		0x5106C8CC2FAAA80CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x070A043861109010ULL,
		0x1221323209280240ULL,
		0x8D2344DE0600C502ULL,
		0x30398CA0B0000238ULL,
		0xB1888010840C8C04ULL,
		0x844E30C002044108ULL,
		0x8810609702989114ULL,
		0x1106484400000000ULL
	}};
	printf("Test Case 275\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 275 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -275;
	} else {
		printf("Test Case 275 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAE666734DB784EBEULL,
		0xFEAAD9C723D87460ULL,
		0x980AD7EABCE7FAA7ULL,
		0x1003CCE74D0662F0ULL,
		0xAB2C22C84C54E569ULL,
		0xD48EB958343EF365ULL,
		0x3CAB14D58A70D81AULL,
		0xA94918AAEFB1A51CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x076EC7A72F81BEDDULL,
		0xA5578B763E1D82DDULL,
		0xAA225C0F516FBBB6ULL,
		0x4BFF9F24F202D7B9ULL,
		0x43F6A954619DCFDAULL,
		0x812D3D254C144C32ULL,
		0x27050019D2128CCDULL,
		0x87D202A1867F5625ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x066647240B000E9CULL,
		0xA402894622180040ULL,
		0x8802540A1067BAA6ULL,
		0x00038C24400242B0ULL,
		0x032420404014C548ULL,
		0x800C390004144020ULL,
		0x2401001182108808ULL,
		0x814000A086310404ULL
	}};
	printf("Test Case 276\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 276 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -276;
	} else {
		printf("Test Case 276 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1DC8FC04B1A24956ULL,
		0x2F9487E200EAD1F1ULL,
		0x72BEAA37D178D719ULL,
		0x2DF6EFE28651B924ULL,
		0xBBE2989CDA074EA7ULL,
		0xDBCB47E7C6003C2FULL,
		0x76E047AECDE1A7E7ULL,
		0xD62B25EA97FA3C13ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x401F22417043EB59ULL,
		0x74557E77EB4D77A6ULL,
		0x73EEDCE3ED217DFAULL,
		0x2A3246F42D7690FAULL,
		0x9DA394D01AED821AULL,
		0x85FB70E58847F34FULL,
		0x6C2B7D61F1E514D2ULL,
		0x89281ED8279ABA2EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0008200030024950ULL,
		0x24140662004851A0ULL,
		0x72AE8823C1205518ULL,
		0x283246E004509020ULL,
		0x99A290901A050202ULL,
		0x81CB40E58000300FULL,
		0x64204520C1E104C2ULL,
		0x802804C8079A3802ULL
	}};
	printf("Test Case 277\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 277 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -277;
	} else {
		printf("Test Case 277 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC344DD436DF20BA3ULL,
		0xF33C1050CB6A602EULL,
		0xD7C588084C9ED8F7ULL,
		0x7637B93F077719BBULL,
		0x1D3325830D9A3EBAULL,
		0x31A571EE539BF286ULL,
		0x524FB03715B7DC94ULL,
		0x38C41E17B9E1E2A7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x90A86184AE22C753ULL,
		0x20C51CB4E51B2D94ULL,
		0xBD8F54B78F8267B0ULL,
		0xDD32AA6742EDDCEBULL,
		0x264BAA17227196F1ULL,
		0x20C05F00DD9F1CF2ULL,
		0x8BF2187B8A2C3EFAULL,
		0xFD9C6972830529C2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x800041002C220303ULL,
		0x20041010C10A2004ULL,
		0x958500000C8240B0ULL,
		0x5432A827026518ABULL,
		0x04032003001016B0ULL,
		0x20805100519B1082ULL,
		0x0242103300241C90ULL,
		0x3884081281012082ULL
	}};
	printf("Test Case 278\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 278 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -278;
	} else {
		printf("Test Case 278 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6C1C66469FA20AD4ULL,
		0x9AAD654C9869F661ULL,
		0x24A75542D6560C94ULL,
		0xBAFE25A085B7E21FULL,
		0xEA44524C1B372B28ULL,
		0xE6A1C0FD9AA3D2A6ULL,
		0xA70829084DC895A1ULL,
		0x5607D6EC06E8D8C2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x409C49BAFA95B62AULL,
		0xF0CC71B5A05014CDULL,
		0xA3ECF549F9189A01ULL,
		0x7B30F2B0A3D91DC0ULL,
		0x8141BA2270A67615ULL,
		0xB15824340E0F7E36ULL,
		0x3DB83FA495BD664DULL,
		0xF998648499E5CFDFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x401C40029A800200ULL,
		0x908C610480401441ULL,
		0x20A45540D0100800ULL,
		0x3A3020A081910000ULL,
		0x8040120010262200ULL,
		0xA00000340A035226ULL,
		0x2508290005880401ULL,
		0x5000448400E0C8C2ULL
	}};
	printf("Test Case 279\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 279 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -279;
	} else {
		printf("Test Case 279 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x05AE16EAA155F182ULL,
		0x600A7E1A0DF0133BULL,
		0x91B6089952F6D320ULL,
		0x9E8A6299EA9612C5ULL,
		0x898F1A4FAFF88735ULL,
		0xC56F5BC568741A06ULL,
		0xF96A04B440956B82ULL,
		0xF0829CC7FFDAF0C3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE0C68FACB18DD808ULL,
		0xCE5A76A7FB5045F6ULL,
		0x076D21474620BCB4ULL,
		0x689821E07EB7C230ULL,
		0x7744ACFDCEC9F9E6ULL,
		0xA28639B4B15CD513ULL,
		0xA697F8B988318D27ULL,
		0xA1B451BA7A34B186ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x008606A8A105D000ULL,
		0x400A760209500132ULL,
		0x0124000142209020ULL,
		0x088820806A960200ULL,
		0x0104084D8EC88124ULL,
		0x8006198420541002ULL,
		0xA00200B000110902ULL,
		0xA08010827A10B082ULL
	}};
	printf("Test Case 280\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 280 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -280;
	} else {
		printf("Test Case 280 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCFC00AC6C636DA67ULL,
		0x907662BCCF768398ULL,
		0xCAF7A949E6A2A657ULL,
		0x4B954E26C220D426ULL,
		0x3CB3CBC4A172E677ULL,
		0xFD10316798FD37FFULL,
		0x3BCB8578B7698889ULL,
		0x853D4DCAAF47FE6FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAC7582C4BF62114DULL,
		0x94F8C6C003B0B6B9ULL,
		0x5ADEA4865D3CA3FAULL,
		0xDD8273D3BC67B04EULL,
		0x756CFFA02771064AULL,
		0x7D33B7730B1FFF2EULL,
		0xEBB3C60C0711C5D0ULL,
		0x4719FCD0598E56B7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8C4002C486221045ULL,
		0x9070428003308298ULL,
		0x4AD6A0004420A252ULL,
		0x4980420280209006ULL,
		0x3420CB8021700642ULL,
		0x7D103163081D372EULL,
		0x2B83840807018080ULL,
		0x05194CC009065627ULL
	}};
	printf("Test Case 281\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 281 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -281;
	} else {
		printf("Test Case 281 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x464B4728A5B03D6AULL,
		0x73CD07DCFBB0462AULL,
		0xC0D4136A2EEB4E10ULL,
		0x7A117A3829D82B09ULL,
		0xFC876C8AB0987263ULL,
		0x586838A444221A2EULL,
		0x2B5B11A905725358ULL,
		0x2BF2D2BEE375D9A8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDDAF56A5073E46CDULL,
		0x398D0E74D401741FULL,
		0xC12B55A56E4764D6ULL,
		0xC0487BAE7F8550CCULL,
		0x112C754B61037613ULL,
		0x3C5AD17E2DB39B41ULL,
		0x6509E1DE653830E5ULL,
		0xE8D731FD882584A4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x440B462005300448ULL,
		0x318D0654D000440AULL,
		0xC00011202E434410ULL,
		0x40007A2829800008ULL,
		0x1004640A20007203ULL,
		0x1848102404221A00ULL,
		0x2109018805301040ULL,
		0x28D210BC802580A0ULL
	}};
	printf("Test Case 282\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 282 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -282;
	} else {
		printf("Test Case 282 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAE533050DB42F49DULL,
		0xC2220D95B4A1A5FAULL,
		0xED4D7C97CC1E00CEULL,
		0xCC0161652E30FE4DULL,
		0xAB1A04C9AF5C311DULL,
		0xAED0A08FDB94EB8DULL,
		0xAFB73248BB7BEAF1ULL,
		0xAFE9B64A309FA88BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x098A5837B0BE330BULL,
		0x4056E6C53255E995ULL,
		0xE3C7AB0FF9CD0312ULL,
		0x4B8750E50D8B2BDAULL,
		0xA1AC87C3B1755EA6ULL,
		0x31EC6B0738D2378FULL,
		0x9881A52CC9CFC3EBULL,
		0x4BE3828B396F58BBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0802101090023009ULL,
		0x400204853001A190ULL,
		0xE1452807C80C0002ULL,
		0x480140650C002A48ULL,
		0xA10804C1A1541004ULL,
		0x20C020071890238DULL,
		0x88812008894BC2E1ULL,
		0x0BE1820A300F088BULL
	}};
	printf("Test Case 283\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 283 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -283;
	} else {
		printf("Test Case 283 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBA25481606D99CB6ULL,
		0x6FA4CAB48BFC0925ULL,
		0x6EF2F181742F68B0ULL,
		0xFAD88FD9626F9329ULL,
		0xCF3C6F28E7493669ULL,
		0xB1DF7C2C88F9BC1FULL,
		0xEAFAF20EBB628B9AULL,
		0x1E8B6DB9E02C2373ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x988F09DE159AE8BFULL,
		0xE00BA9A79893DA1AULL,
		0x18D15940F62011F9ULL,
		0x0034433FAAB8B2DFULL,
		0xE032E367652A2BFDULL,
		0xCCF065B9CD833123ULL,
		0x9CB4EB7C4F4FB00FULL,
		0x917BDF3B67337283ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x98050816049888B6ULL,
		0x600088A488900800ULL,
		0x08D05100742000B0ULL,
		0x0010031922289209ULL,
		0xC030632065082269ULL,
		0x80D0642888813003ULL,
		0x88B0E20C0B42800AULL,
		0x100B4D3960202203ULL
	}};
	printf("Test Case 284\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 284 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -284;
	} else {
		printf("Test Case 284 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2D6DA6E9C372D0B7ULL,
		0xAE5BF64BD6D890ADULL,
		0xC350F6D32883C772ULL,
		0x31A6726922809BDEULL,
		0x484337D1195647ADULL,
		0xD37310F5F83ED3B4ULL,
		0x92904A5D0B61CD4CULL,
		0x9A5951BF53EBCA8CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAE07D8E7C9F878BFULL,
		0xBC3FA43EF51DB157ULL,
		0x334B9C55CD9E405AULL,
		0x73B0FB7CD98E7C71ULL,
		0x77A356BA737394A7ULL,
		0x30A509AAF3773AEDULL,
		0x11F68436B92AFC48ULL,
		0xCC9123E39AD7E002ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2C0580E1C17050B7ULL,
		0xAC1BA40AD4189005ULL,
		0x0340945108824052ULL,
		0x31A0726800801850ULL,
		0x40031690115204A5ULL,
		0x102100A0F03612A4ULL,
		0x109000140920CC48ULL,
		0x881101A312C3C000ULL
	}};
	printf("Test Case 285\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 285 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -285;
	} else {
		printf("Test Case 285 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5B922639F7D97BEBULL,
		0x4388BCC285046092ULL,
		0x7595ABDDD759B2F1ULL,
		0x06FD68056E49C2BCULL,
		0x82BED6245E4AB7EDULL,
		0xD92DC390D382697CULL,
		0x35285FB3541DFA69ULL,
		0xF28ECFC2851DBE86ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA28F018E7C22F26AULL,
		0xAED1A4F7DE483516ULL,
		0xD64CF192B5953240ULL,
		0x260ADD2048D03652ULL,
		0xEE9931A3052062CEULL,
		0x9B4AC98708740DE5ULL,
		0xA3FA7B897DB06F5DULL,
		0x90C7C5BD104BAB03ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x028200087400726AULL,
		0x0280A4C284002012ULL,
		0x5404A19095113240ULL,
		0x0608480048400210ULL,
		0x82981020040022CCULL,
		0x9908C18000000964ULL,
		0x21285B8154106A49ULL,
		0x9086C5800009AA02ULL
	}};
	printf("Test Case 286\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 286 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -286;
	} else {
		printf("Test Case 286 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7EFE825A8CEC4CC3ULL,
		0x0DF2DF91D2E9D043ULL,
		0xE53DDA23A9245B2FULL,
		0x18214B9173C9553DULL,
		0x0298626F089EBBFAULL,
		0x4C29608014B584F6ULL,
		0xD782ED4E2627503FULL,
		0x0CC8AEE896FCD008ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB04F01C426BC105EULL,
		0x8683EF75D752747CULL,
		0xB75FCB99416B014DULL,
		0x2AE7D3CC1FF9E094ULL,
		0xB81ED45D2115FE1BULL,
		0x27DB39DC5C34BC6DULL,
		0x28A603E6A74C94FFULL,
		0xF9DC3B62061BD18DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x304E004004AC0042ULL,
		0x0482CF11D2405040ULL,
		0xA51DCA010120010DULL,
		0x0821438013C94014ULL,
		0x0018404D0014BA1AULL,
		0x0409208014348464ULL,
		0x008201462604103FULL,
		0x08C82A600618D008ULL
	}};
	printf("Test Case 287\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 287 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -287;
	} else {
		printf("Test Case 287 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3D73850AB57996C5ULL,
		0x5184B85C98804878ULL,
		0xAF82B6A8AA80BE20ULL,
		0xF6196CD2E1883E5DULL,
		0x2B3EB45766C9D4B6ULL,
		0xDEE542B3247DF7F1ULL,
		0x79C9F48702C55A75ULL,
		0xDB1568410723A082ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF4DB595FEBE11F41ULL,
		0x7FE36FE2A8787158ULL,
		0x5F98524A46D262CFULL,
		0x95F77C6BE3140E31ULL,
		0x5315426C6D24E9ABULL,
		0x0ACF596223F30653ULL,
		0xD0BAB0F5848AA196ULL,
		0x8FA69E598AD852C4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3453010AA1611641ULL,
		0x5180284088004058ULL,
		0x0F80120802802200ULL,
		0x94116C42E1000E11ULL,
		0x031400446400C0A2ULL,
		0x0AC5402220710651ULL,
		0x5088B08500800014ULL,
		0x8B04084102000080ULL
	}};
	printf("Test Case 288\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 288 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -288;
	} else {
		printf("Test Case 288 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x05221CE16D874D00ULL,
		0x9257A9B7BBDB83F8ULL,
		0x6763BC431627EE70ULL,
		0x214B65090D56021EULL,
		0x0A325A2704E5F37CULL,
		0x92BE37BA51DFFC13ULL,
		0x4C2E27317DB92278ULL,
		0xDE63C220BF5F7B14ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x21134E32CD13D3B3ULL,
		0xFFCDF14608709828ULL,
		0x21AC5E7E9E84B94EULL,
		0x2EFB78101CBB6EDCULL,
		0xFE50803C958AA395ULL,
		0x230613DEC20AFE40ULL,
		0x818A9B23E5C0963CULL,
		0xEBBCAE8B2F29D8FCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x01020C204D034100ULL,
		0x9245A10608508028ULL,
		0x21201C421604A840ULL,
		0x204B60000C12021CULL,
		0x0A1000240480A314ULL,
		0x0206139A400AFC00ULL,
		0x000A032165800238ULL,
		0xCA2082002F095814ULL
	}};
	printf("Test Case 289\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 289 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -289;
	} else {
		printf("Test Case 289 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2CBDE02FE32D4C79ULL,
		0xD5CB74E42566DD82ULL,
		0xEC483C43F14BCE96ULL,
		0x845430D88650D27EULL,
		0x6AD006E10449CA4CULL,
		0xD6066C84386487B3ULL,
		0xB5A83854310C98F6ULL,
		0xAF510DCBCF9D359AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8F0A63AE49C30466ULL,
		0xE1307254DD00A492ULL,
		0xDB81000035A747A2ULL,
		0x161F43DD2A5ADA24ULL,
		0x7E85F9606692A5C7ULL,
		0xDE2F3CBDF0F6AB6DULL,
		0x5E77D63B2C7BC1FAULL,
		0x0AA9458A4069865BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0C08602E41010460ULL,
		0xC100704405008482ULL,
		0xC800000031034682ULL,
		0x041400D80250D224ULL,
		0x6A80006004008044ULL,
		0xD6062C8430648321ULL,
		0x14201010200880F2ULL,
		0x0A01058A4009041AULL
	}};
	printf("Test Case 290\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 290 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -290;
	} else {
		printf("Test Case 290 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1C893E3F4C7C8CDAULL,
		0xD2799C09C9E1AFC3ULL,
		0xF8C77E7C8910D710ULL,
		0x86375C745805D736ULL,
		0x3FAF5129DA8C8771ULL,
		0x26714DCD9F92F6F2ULL,
		0x6FBE01706D92BD96ULL,
		0x6D4C8A9275279084ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x93C1D223DFD556E9ULL,
		0xD6CBDB1B1D131BB1ULL,
		0xC7666491AD2AC726ULL,
		0x31A032E57FA8ED99ULL,
		0xF29C3BC8AAAF7846ULL,
		0x0979E8B3ED2E0324ULL,
		0xC214908E33B3A091ULL,
		0x71B88E991224BB95ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x108112234C5404C8ULL,
		0xD249980909010B81ULL,
		0xC04664108900C700ULL,
		0x002010645800C510ULL,
		0x328C11088A8C0040ULL,
		0x007148818D020220ULL,
		0x421400002192A090ULL,
		0x61088A9010249084ULL
	}};
	printf("Test Case 291\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 291 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -291;
	} else {
		printf("Test Case 291 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x67973EE89AD92775ULL,
		0x8D0452657A2AF610ULL,
		0x5112DCA70CE1A422ULL,
		0xAA922F14DB2835EFULL,
		0x63078233BA1C747EULL,
		0x228BF515D0CB4D91ULL,
		0xDC2DE9ACBAB6FBECULL,
		0xBC6467B9C0AAE526ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD59BCAF7809E6E75ULL,
		0xFA8BB3D82E82195AULL,
		0x3133BE9704B5D5B1ULL,
		0x73D4E3BFBBDFACDCULL,
		0xA8477764783CC780ULL,
		0xBF298B8E650A7B9BULL,
		0xA19D2460CC58615BULL,
		0x1550739E4DCC4648ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x45930AE080982675ULL,
		0x880012402A021010ULL,
		0x11129C8704A18420ULL,
		0x229023149B0824CCULL,
		0x20070220381C4400ULL,
		0x22098104400A4991ULL,
		0x800D202088106148ULL,
		0x1440639840884400ULL
	}};
	printf("Test Case 292\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 292 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -292;
	} else {
		printf("Test Case 292 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3559B4275E7469F5ULL,
		0x96C2890F2E2F535AULL,
		0x24AA46FE268F44C1ULL,
		0x70B40EF6C8F9B2D5ULL,
		0xB18BAA0F8D2FCFE4ULL,
		0xFDC54BC309D3FA93ULL,
		0x32024F02F4965FC6ULL,
		0x277903ECFFB4A0C4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6CAA7F43EAD03719ULL,
		0xA94214E456ADF6FAULL,
		0x80DC0AE717A71F73ULL,
		0xFF160D34C9E0EBFEULL,
		0x42FAC4BE10ED0889ULL,
		0x9A6CA81521E53A4CULL,
		0xCB3186B0D0DE7DE8ULL,
		0xA90F2D5CDF460F97ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x240834034A502111ULL,
		0x80420004062D525AULL,
		0x008802E606870441ULL,
		0x70140C34C8E0A2D4ULL,
		0x008A800E002D0880ULL,
		0x9844080101C13A00ULL,
		0x02000600D0965DC0ULL,
		0x2109014CDF040084ULL
	}};
	printf("Test Case 293\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 293 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -293;
	} else {
		printf("Test Case 293 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1D6534C54B4F35D4ULL,
		0x15AF708BC9A0C4EDULL,
		0x06E624F7749F7F37ULL,
		0x23D0499C99C88D4EULL,
		0xE98A1ADB61282E6DULL,
		0x07374BBFBF54CBA8ULL,
		0x24D13891C307FD88ULL,
		0x16EC1CE6673A5EF3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x49C9B750DD0C1458ULL,
		0x3B53D6FAA707C3C3ULL,
		0xF62C8FCF1F14ABDAULL,
		0x318B12FF744DC210ULL,
		0x06E43B7C85759C2DULL,
		0xA028E42522568B49ULL,
		0xA16AAD8397ADC731ULL,
		0x4496E2B86F2F21E1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x09413440490C1450ULL,
		0x1103508A8100C0C1ULL,
		0x062404C714142B12ULL,
		0x2180009C10488000ULL,
		0x00801A5801200C2DULL,
		0x0020402522548B08ULL,
		0x204028818305C500ULL,
		0x048400A0672A00E1ULL
	}};
	printf("Test Case 294\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 294 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -294;
	} else {
		printf("Test Case 294 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5D320A4A478AA3CEULL,
		0xDBEFF66284E2EB20ULL,
		0xCAB40D250AB6C271ULL,
		0xB2FB62C591D15969ULL,
		0xECE3A8A611843B8BULL,
		0x724CB897DB4289CDULL,
		0x3DEE0CAF1B0E9453ULL,
		0xEC6B45EE8F6AEC9FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x373F62077D41DAB3ULL,
		0x0557ABA30F7EC264ULL,
		0x2147278FA1C199A4ULL,
		0xDC5AF71AC2AE684BULL,
		0x10668011C85C537AULL,
		0x89C8591AB0460FFAULL,
		0x4B3DEF188B387111ULL,
		0x86E8C3995B57E878ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1532020245008282ULL,
		0x0147A2220462C220ULL,
		0x0004050500808020ULL,
		0x905A620080804849ULL,
		0x006280000004130AULL,
		0x00481812904209C8ULL,
		0x092C0C080B081011ULL,
		0x846841880B42E818ULL
	}};
	printf("Test Case 295\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 295 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -295;
	} else {
		printf("Test Case 295 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x062F369D67273665ULL,
		0xE0BBE0F902F544DCULL,
		0xBA7C9A4D5EC2309AULL,
		0x06F44CDA1E6E1894ULL,
		0x1D1B44566B12ABCBULL,
		0x2F5695F4B0094327ULL,
		0xAE0C14BAE28690E6ULL,
		0x9CBD652627C27E0FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB86D97B4E3BD2CEEULL,
		0x47C6F1650DD2910FULL,
		0x32D9A3937C47F362ULL,
		0xD5C3CB4589744E2EULL,
		0x3347FF7DD26BF5F4ULL,
		0x48A08E19ED9B9502ULL,
		0x675482A1C477A63EULL,
		0xFE491B3A429B9B89ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x002D169463252464ULL,
		0x4082E06100D0000CULL,
		0x325882015C423002ULL,
		0x04C0484008640804ULL,
		0x110344544202A1C0ULL,
		0x08008410A0090102ULL,
		0x260400A0C0068026ULL,
		0x9C09012202821A09ULL
	}};
	printf("Test Case 296\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 296 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -296;
	} else {
		printf("Test Case 296 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0A1FDF02A4441AF3ULL,
		0xEF4E15F14859BA0AULL,
		0x171ED50FEB69609FULL,
		0x07AAEC77A6DB8755ULL,
		0x50198F8AA3924F20ULL,
		0x77D94A3D8BCA0A7BULL,
		0xA4A65C2EB79A6F0FULL,
		0xF48F61700DE460B5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x72850EA614DBD708ULL,
		0x8302273EB137CC94ULL,
		0x467017FDC7EEF32BULL,
		0x85DD0052F9605FD0ULL,
		0x93271F4BC4F1877BULL,
		0x3D48D6C49E294B9AULL,
		0xF25958695A3B0B1DULL,
		0x032B7DCAAD93F488ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x02050E0204401200ULL,
		0x8302053000118800ULL,
		0x0610150DC368600BULL,
		0x05880052A0400750ULL,
		0x10010F0A80900720ULL,
		0x354842048A080A1AULL,
		0xA0005828121A0B0DULL,
		0x000B61400D806080ULL
	}};
	printf("Test Case 297\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 297 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -297;
	} else {
		printf("Test Case 297 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD687C8408DD57CCDULL,
		0xD5219CA5A77D30B4ULL,
		0xA4A946B924E9F8CDULL,
		0xFA8CE8C89812A8C6ULL,
		0xF0F2F8C8BBF42B7BULL,
		0x938CA749CADCFD9FULL,
		0x3E423AC7F1BD7E2EULL,
		0xB05B0433B125B31BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3477542DE9BA6E11ULL,
		0x30F3C4A90D6B6AA8ULL,
		0xE6349841DC505732ULL,
		0x288DFCB4C0FC6B90ULL,
		0x290003B4E17B4C38ULL,
		0xBE90FFA977D7AA92ULL,
		0x426C184884FFC3FCULL,
		0xA52595FA224CAFC1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1407400089906C01ULL,
		0x102184A1056920A0ULL,
		0xA420000104405000ULL,
		0x288CE88080102880ULL,
		0x20000080A1700838ULL,
		0x9280A70942D4A892ULL,
		0x0240184080BD422CULL,
		0xA00104322004A301ULL
	}};
	printf("Test Case 298\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 298 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -298;
	} else {
		printf("Test Case 298 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC22285B8FFFA2332ULL,
		0x5EB3A0C5C12230B5ULL,
		0x691CF08FF8B8CE33ULL,
		0xD3B27EA1DA34F9DEULL,
		0x4A0F37754ADC0BEDULL,
		0xC592828CEB7423DCULL,
		0x98ED1782963C42D1ULL,
		0x164369FA152DED0DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x180BEAEDEB52AFF3ULL,
		0x61EFA5EE95FD5AD3ULL,
		0xE3D4F3760DF7D796ULL,
		0x11039679BC9D3949ULL,
		0xD9B9908880E0D2BCULL,
		0x4E92EB71F61B874AULL,
		0xC3D78DBF2C9EA7ECULL,
		0xBC616AE9D1A1D99FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x000280A8EB522332ULL,
		0x40A3A0C481201091ULL,
		0x6114F00608B0C612ULL,
		0x1102162198143948ULL,
		0x4809100000C002ACULL,
		0x44928200E2100348ULL,
		0x80C50582041C02C0ULL,
		0x144168E81121C90DULL
	}};
	printf("Test Case 299\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 299 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -299;
	} else {
		printf("Test Case 299 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD936166783ECE73BULL,
		0x2BD4BA4AD0F10C2EULL,
		0xCE74158B3ED2038BULL,
		0x48DCAF7F57FDD523ULL,
		0x7464B050DDB6BC66ULL,
		0x274D5A297EF5B5E5ULL,
		0x19BBC9CC167D2E7CULL,
		0xB0474387F3F7F42DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0FBEF5A46AAD0832ULL,
		0x5DD9DDADC26DC4F0ULL,
		0x426B7D555DD916ACULL,
		0xFF6BBFDC386D5B47ULL,
		0xACAE0A4D2F922E09ULL,
		0x3B25A41242C40D91ULL,
		0x448BA448875285D8ULL,
		0xC2C863676856F6D0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0936142402AC0032ULL,
		0x09D09808C0610420ULL,
		0x426015011CD00288ULL,
		0x4848AF5C106D5103ULL,
		0x242400400D922C00ULL,
		0x2305000042C40581ULL,
		0x008B804806500458ULL,
		0x804043076056F400ULL
	}};
	printf("Test Case 300\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 300 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -300;
	} else {
		printf("Test Case 300 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA43CAA6AFA0D0A53ULL,
		0x3CD47F28543E1E6FULL,
		0xD5FBACD92DB64DA9ULL,
		0x3ECF5AA17F9A449FULL,
		0x8142F891D49BA89CULL,
		0xB49DFC0A15BEBDD8ULL,
		0x60A93C745DD1F1BDULL,
		0x939EE22D635334E4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x19894CBC921092FCULL,
		0x3F99E6A8E2C610F2ULL,
		0x40BE9752DFF6F6B0ULL,
		0x1A53B4E935E19F41ULL,
		0x8B00649968974974ULL,
		0x7BCA5EC9A95FDB5CULL,
		0x32C9029415011AB3ULL,
		0x23EA8921BE239F06ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0008082892000250ULL,
		0x3C90662840061062ULL,
		0x40BA84500DB644A0ULL,
		0x1A4310A135800401ULL,
		0x8100609140930814ULL,
		0x30885C08011E9958ULL,
		0x20890014150110B1ULL,
		0x038A802122031404ULL
	}};
	printf("Test Case 301\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 301 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -301;
	} else {
		printf("Test Case 301 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x08FD281353C38507ULL,
		0xA8FD833927928AFBULL,
		0x082B06C49C56D124ULL,
		0x2DF14849B77370D2ULL,
		0x7826570BFF3278C4ULL,
		0xE5ED8FCDA26411D6ULL,
		0xC551545F54685FCAULL,
		0xBB06EC37510290E9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8A641D357FE33587ULL,
		0xABE6A6BEE1ED3D41ULL,
		0x7E76F4863AB8B384ULL,
		0xC582681801C1EFBDULL,
		0x68C9A12F7E11069DULL,
		0x94088FB881D31C6CULL,
		0xCA073F754D8987B1ULL,
		0x8F7BE3DA45BD1D96ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0864081153C30507ULL,
		0xA8E4823821800841ULL,
		0x0822048418109104ULL,
		0x0580480801416090ULL,
		0x6800010B7E100084ULL,
		0x84088F8880401044ULL,
		0xC001145544080780ULL,
		0x8B02E01241001080ULL
	}};
	printf("Test Case 302\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 302 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -302;
	} else {
		printf("Test Case 302 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD1DAAD12547FF0A2ULL,
		0x574409C4F347919AULL,
		0xDE86CB9C9D11A42DULL,
		0xAA9B7D7854E96DEFULL,
		0xECE9742813B88FE8ULL,
		0xF171119F8688D732ULL,
		0xF31EC092F07AFF88ULL,
		0xD0C812F5505B7ECEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x79DDDDAC3D6B86ECULL,
		0xB556CF4929D580DBULL,
		0xE4A4D742F9240AF1ULL,
		0x29852D0F09DBC395ULL,
		0xE4AD674161AB55B5ULL,
		0x85AD376D43E07220ULL,
		0x0E1C2916AB234475ULL,
		0x54BB75E81B230B34ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x51D88D00146B80A0ULL,
		0x154409402145809AULL,
		0xC484C30099000021ULL,
		0x28812D0800C94185ULL,
		0xE4A9640001A805A0ULL,
		0x8121110D02805220ULL,
		0x021C0012A0224400ULL,
		0x508810E010030A04ULL
	}};
	printf("Test Case 303\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 303 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -303;
	} else {
		printf("Test Case 303 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2AB2A75566239D0BULL,
		0x9E423E0AB8CD8B09ULL,
		0x9033FC6829602567ULL,
		0x81196E989A0065BBULL,
		0xF65DF7DC9FEDE246ULL,
		0x24A8CA008D74318BULL,
		0x0898EEC88465E8FDULL,
		0x95C32F6CA2502EE4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1BFC537EE6D123A3ULL,
		0x85FB9420DD3DD0B2ULL,
		0x8F12D722D34C6417ULL,
		0x33E992D67BD4F342ULL,
		0x14368BD1FC6E2E93ULL,
		0xCCD1D2F073FC878EULL,
		0xFE23A12360C6DDC6ULL,
		0x25F521CE1F6C0D99ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0AB0035466010103ULL,
		0x84421400980D8000ULL,
		0x8012D42001402407ULL,
		0x010902901A006102ULL,
		0x141483D09C6C2202ULL,
		0x0480C2000174018AULL,
		0x0800A0000044C8C4ULL,
		0x05C1214C02400C80ULL
	}};
	printf("Test Case 304\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 304 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -304;
	} else {
		printf("Test Case 304 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE9ACF2C650A3D0E4ULL,
		0x6D08C56DBF8AFB3AULL,
		0xE5FBD4D5B57CCC74ULL,
		0xBB39F28D38626574ULL,
		0x8EB2F73F5E315C7FULL,
		0x739970E153BE0085ULL,
		0x68FDEEC560F9AC2FULL,
		0x4B54D6DA2FA511E0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDCDBDC4DC22608F0ULL,
		0x7667E3B5662ABAF6ULL,
		0x1834CAE86E3660A8ULL,
		0x208005F9367CC81EULL,
		0x8D9233056BBBC0A7ULL,
		0x00990F3EE24F6029ULL,
		0x73CCE17D7AA82262ULL,
		0x3383155B4AE0160CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC888D044402200E0ULL,
		0x6400C125260ABA32ULL,
		0x0030C0C024344020ULL,
		0x2000008930604014ULL,
		0x8C9233054A314027ULL,
		0x00990020420E0001ULL,
		0x60CCE04560A82022ULL,
		0x0300145A0AA01000ULL
	}};
	printf("Test Case 305\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 305 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -305;
	} else {
		printf("Test Case 305 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0B5185C4FAB8CBABULL,
		0xC123CA5675A8C3F1ULL,
		0x4D94CD62AA24DDF9ULL,
		0xECD64E2275E13D89ULL,
		0x89A7438F594B58D8ULL,
		0xD49FED6C412F8DA5ULL,
		0x2478769EB7375C40ULL,
		0xD9F3CF97F1701E72ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x95D2F6478911044FULL,
		0x0A99F6B288213954ULL,
		0x966AAF119EAC63F2ULL,
		0x80A82826315E8607ULL,
		0x8C83A16365A8F3CDULL,
		0x711C2F98E4E0A70DULL,
		0xBEAF773532B3EF9DULL,
		0x7D713666163F0A7EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x015084448810000BULL,
		0x0001C21200200150ULL,
		0x04008D008A2441F0ULL,
		0x8080082231400401ULL,
		0x88830103410850C8ULL,
		0x501C2D0840208505ULL,
		0x2428761432334C00ULL,
		0x5971060610300A72ULL
	}};
	printf("Test Case 306\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 306 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -306;
	} else {
		printf("Test Case 306 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC9A0974B3B1F70A6ULL,
		0x95840FEA4A20701AULL,
		0x40EA56547EF70879ULL,
		0x3A2DEC1B6E97EFA9ULL,
		0xE15A2073BB1AB434ULL,
		0x313B90D3BA6ED60FULL,
		0xD28F8377E34B15F5ULL,
		0x2287BA4F2EBE3F9FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD7360B7858ED0932ULL,
		0x9762884895BA31A6ULL,
		0x4F631C250C4A3EB4ULL,
		0xC986943918C83143ULL,
		0xC38F7601C862249BULL,
		0x8E4C4F5500DEAF7DULL,
		0x24B59428035DC98BULL,
		0x6119B79F948C01BAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC1200348180D0022ULL,
		0x9500084800203002ULL,
		0x406214040C420830ULL,
		0x0804841908802101ULL,
		0xC10A200188022410ULL,
		0x00080051004E860DULL,
		0x0085802003490181ULL,
		0x2001B20F048C019AULL
	}};
	printf("Test Case 307\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 307 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -307;
	} else {
		printf("Test Case 307 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9539B5A87B6E21C5ULL,
		0xBAA05F050A72388DULL,
		0x0C1EFB54D04629EBULL,
		0xA4F3FB4052F08DAAULL,
		0x6880CFCEBC4915A1ULL,
		0x7EDC3A1E011EACFDULL,
		0x6E1152C3F4D3B358ULL,
		0x8C0D83F34DD0F081ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x005DBB20A80D9D80ULL,
		0x420ADA0F2C5743CEULL,
		0x18B55E0B7F631642ULL,
		0x5EAD1E84B56DD331ULL,
		0x1DBD7864FFC24951ULL,
		0xC79B6CF54E0E187DULL,
		0xD59FAB84E1DB68B2ULL,
		0x3755FF9DAF7FFD38ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0019B120280C0180ULL,
		0x02005A050852008CULL,
		0x08145A0050420042ULL,
		0x04A11A0010608120ULL,
		0x08804844BC400101ULL,
		0x46982814000E087DULL,
		0x44110280E0D32010ULL,
		0x040583910D50F000ULL
	}};
	printf("Test Case 308\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 308 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -308;
	} else {
		printf("Test Case 308 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6934EAD9BE959F38ULL,
		0x7F550DDCCE135845ULL,
		0x8A2969ECB5B9DC41ULL,
		0x0C5EAB9D4069694BULL,
		0x19BC0C80A186CE32ULL,
		0xFDF97ED0D9AD1D11ULL,
		0xC185AD35D95952B4ULL,
		0x96052CC15B1AF342ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA5F2063113AA0128ULL,
		0x53C7F6ECE50E3EFEULL,
		0x578D11AC04544951ULL,
		0xD4E3383DFD7A3FF6ULL,
		0x803E36DE6C9E1E1FULL,
		0x379A53E5580A02B8ULL,
		0xD69F62885350E8D6ULL,
		0x073ACEDF18FD1A4AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2130021112800128ULL,
		0x534504CCC4021844ULL,
		0x020901AC04104841ULL,
		0x0442281D40682942ULL,
		0x003C048020860E12ULL,
		0x359852C058080010ULL,
		0xC085200051504094ULL,
		0x06000CC118181242ULL
	}};
	printf("Test Case 309\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 309 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -309;
	} else {
		printf("Test Case 309 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA9F6CEA4141B31C4ULL,
		0x3DC18A2113623099ULL,
		0xF6A6D43B56B5FAF0ULL,
		0x6BA2FF70C49F9A9FULL,
		0xAFA999DEE4D42628ULL,
		0xE299BA9BDDDC7DFBULL,
		0x3A840351301BCA47ULL,
		0xFE47E2A58035E65EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x96E5CD7C1745004AULL,
		0x49DEB46BF0BBCB62ULL,
		0x0E25D135493740F0ULL,
		0xD9A9FBF2AB6CFF32ULL,
		0xB6E7C15177996C6CULL,
		0xFD29C82574B1AC2AULL,
		0x7E673FAEFA0ABD2EULL,
		0x544B5B686094C3CAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x80E4CC2414010040ULL,
		0x09C0802110220000ULL,
		0x0624D031403540F0ULL,
		0x49A0FB70800C9A12ULL,
		0xA6A1815064902428ULL,
		0xE009880154902C2AULL,
		0x3A040300300A8806ULL,
		0x544342200014C24AULL
	}};
	printf("Test Case 310\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 310 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -310;
	} else {
		printf("Test Case 310 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x349A46A9A9373A3CULL,
		0x1A9A385AA344B703ULL,
		0xA9EA1FF0590E1457ULL,
		0xB286B3A86626CB5CULL,
		0xEF445D1DBBBB59B4ULL,
		0xC28B1E6151BEB687ULL,
		0x97D6F8E4A5B046ABULL,
		0xD9F6FAF18439B69FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD78B635FA955E134ULL,
		0xA15270076E586018ULL,
		0x2A2F50ED4230ECF5ULL,
		0xBDE39BC9DA91386BULL,
		0xA84333B6E0473D0EULL,
		0xE00AE623F1E4C407ULL,
		0xE610897382E49DBFULL,
		0xC6C812A57A562648ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x148A4209A9152034ULL,
		0x0012300222402000ULL,
		0x282A10E040000455ULL,
		0xB082938842000848ULL,
		0xA8401114A0031904ULL,
		0xC00A062151A48407ULL,
		0x8610886080A004ABULL,
		0xC0C012A100102608ULL
	}};
	printf("Test Case 311\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 311 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -311;
	} else {
		printf("Test Case 311 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAD46C1A701E7F013ULL,
		0xA863F4D30CC964F5ULL,
		0xF29D01AA20F90D3EULL,
		0xD2AE2DCE3390FDEEULL,
		0x8F536D94A5C0C268ULL,
		0xF5146ED0228C17C2ULL,
		0xD514677298275559ULL,
		0x4ED18091AE514C76ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8C93544CBDF0AE37ULL,
		0x972C36CA48F28DACULL,
		0xB58983E26321A159ULL,
		0x1BED57005251F715ULL,
		0x674E39E177DFFE2DULL,
		0x9608D67AC506AA41ULL,
		0xFCAF40450EEC87D2ULL,
		0xADEB58248463A799ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8C02400401E0A013ULL,
		0x802034C208C004A4ULL,
		0xB08901A220210118ULL,
		0x12AC05001210F504ULL,
		0x0742298025C0C228ULL,
		0x9400465000040240ULL,
		0xD404404008240550ULL,
		0x0CC1000084410410ULL
	}};
	printf("Test Case 312\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 312 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -312;
	} else {
		printf("Test Case 312 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2A055E94AA8E0810ULL,
		0xE49565ED5202EA28ULL,
		0x188400B0F5964E54ULL,
		0x9EBBAF4EAD0CD465ULL,
		0xFE06AB2A52CE75FDULL,
		0x08D33D91982CE092ULL,
		0xFC47AF5C2F1AAD1EULL,
		0xED41B89EDE5ADCDBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDFB96FC286FFA2F1ULL,
		0x2AC299B34E13FDD6ULL,
		0x3AEA0D781CF74260ULL,
		0x1EF6A47E4EFE4A56ULL,
		0xEAD9FF987D0389D7ULL,
		0xBD895321657A7DA2ULL,
		0x1E6F02398C55A58DULL,
		0x8AFE618ABBE2B180ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0A014E80828E0010ULL,
		0x208001A14202E800ULL,
		0x1880003014964240ULL,
		0x1EB2A44E0C0C4044ULL,
		0xEA00AB08500201D5ULL,
		0x0881110100286082ULL,
		0x1C4702180C10A50CULL,
		0x8840208A9A429080ULL
	}};
	printf("Test Case 313\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 313 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -313;
	} else {
		printf("Test Case 313 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA7D906CFDCBC20E9ULL,
		0xBFEA2254E023F4A5ULL,
		0x2AFB3224F797D0E4ULL,
		0xCA63A7E4A5795C92ULL,
		0xD121F4AA05BB4B22ULL,
		0x8E17A9D37A52B3D3ULL,
		0x78ACA66322F4D37DULL,
		0x0B2F7FFA3FE5AFEAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEE796EA2A54A04CCULL,
		0x29A49547E57BBAF5ULL,
		0x0BCA18BDC9567324ULL,
		0xB1F276AFBE4ECCB7ULL,
		0xB341F4261CCFA481ULL,
		0x68E6B4BBD51E1554ULL,
		0xD6575974B0C51E39ULL,
		0x7932B868D3410F25ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA6590682840800C8ULL,
		0x29A00044E023B0A5ULL,
		0x0ACA1024C1165024ULL,
		0x806226A4A4484C92ULL,
		0x9101F422048B0000ULL,
		0x0806A09350121150ULL,
		0x5004006020C41239ULL,
		0x0922386813410F20ULL
	}};
	printf("Test Case 314\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 314 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -314;
	} else {
		printf("Test Case 314 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5B70CB11DC806DC1ULL,
		0xCF9BA112DDF2A517ULL,
		0x618F36029CFA80FEULL,
		0x146951166DA3DE8AULL,
		0x52AC11C1EE12549AULL,
		0xD6A87336C60D864BULL,
		0x312E56E755DEBEFBULL,
		0xBCF35F86B5C8510AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x07A2786D42C387FCULL,
		0xC63308534D189F54ULL,
		0xAC24D8DC1A37D353ULL,
		0x5F84F27551A454DEULL,
		0xD06214A0A2A49507ULL,
		0x0E7A10DC272BB2FCULL,
		0x94859DA963AD143CULL,
		0x2F82242D615A1148ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x03204801408005C0ULL,
		0xC61300124D108514ULL,
		0x2004100018328052ULL,
		0x1400501441A0548AULL,
		0x50201080A2001402ULL,
		0x0628101406098248ULL,
		0x100414A1418C1438ULL,
		0x2C82040421481108ULL
	}};
	printf("Test Case 315\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 315 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -315;
	} else {
		printf("Test Case 315 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7662BE8266E2124CULL,
		0x7EC7B09CCF3B94CCULL,
		0xF478896F77FC86F0ULL,
		0x8FEABEAB648C0C39ULL,
		0x0990604E6B0BC172ULL,
		0xF64D7891AF38E11CULL,
		0x581B912B10391E5BULL,
		0xEE033E138FE5D803ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE3110C4E5E86F03EULL,
		0x958269893D68198BULL,
		0x33A9C4E61C62A578ULL,
		0x8BA3FD078212245EULL,
		0xB2353821CF929B6DULL,
		0x3EEB33B628E82953ULL,
		0xAED17FE8D33BAC15ULL,
		0xA657E441171BC12CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x62000C024682100CULL,
		0x148220880D281088ULL,
		0x3028806614608470ULL,
		0x8BA2BC0300000418ULL,
		0x001020004B028160ULL,
		0x3649309028282110ULL,
		0x0811112810390C11ULL,
		0xA60324010701C000ULL
	}};
	printf("Test Case 316\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 316 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -316;
	} else {
		printf("Test Case 316 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x86F2D9E556133F21ULL,
		0x6A607B32C1D15453ULL,
		0x52F2703990D6FB9CULL,
		0x26B40C13C2364C0EULL,
		0x280AC6FB81C734A2ULL,
		0xC4B8317338D637AFULL,
		0x639EC49DBB67E61BULL,
		0x7B48CE06E00991F6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD24ED3FC0FC27DF9ULL,
		0x0FFB76179843A3DBULL,
		0xA560A9F59750EB51ULL,
		0xF1B40D93D06714B9ULL,
		0xEF38C1B3EAD9B770ULL,
		0xAED81E159EA0162CULL,
		0x7AD2E1D2991BA5C5ULL,
		0xAD856A7B46088EF6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8242D1E406023D21ULL,
		0x0A60721280410053ULL,
		0x006020319050EB10ULL,
		0x20B40C13C0260408ULL,
		0x2808C0B380C13420ULL,
		0x849810111880162CULL,
		0x6292C0909903A401ULL,
		0x29004A02400880F6ULL
	}};
	printf("Test Case 317\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 317 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -317;
	} else {
		printf("Test Case 317 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6B50DC0B82CAE01DULL,
		0xB3D9D05D5FA5B899ULL,
		0x3041F7D5C90E8D63ULL,
		0x11FD70910581C117ULL,
		0x2C3C7BA944555D65ULL,
		0x948B66900470021AULL,
		0x8B6B5252461467E0ULL,
		0x28618FF0B0C00523ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB90DA4EC186BCD93ULL,
		0xB4BB6E48E9888053ULL,
		0x792476AEE00F2BDAULL,
		0x9810825014004935ULL,
		0xE7A68EAF824A40C6ULL,
		0x5F0C74F3D4257505ULL,
		0xD396FC71728604D2ULL,
		0x83BCBEBA69F96AEAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x29008408004AC011ULL,
		0xB099404849808011ULL,
		0x30007684C00E0942ULL,
		0x1010001004004115ULL,
		0x24240AA900404044ULL,
		0x1408649004200000ULL,
		0x83025050420404C0ULL,
		0x00208EB020C00022ULL
	}};
	printf("Test Case 318\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 318 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -318;
	} else {
		printf("Test Case 318 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB1141707D451BF1DULL,
		0xA153FFC258B8AEB3ULL,
		0x18CEF3436CFED4C8ULL,
		0xBE8872E099C1C8AEULL,
		0x98063B6D348F0F94ULL,
		0x5ADA6E42CEE796BFULL,
		0x91944576195AC633ULL,
		0xA6D94906E9874205ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9B6FD9B037474773ULL,
		0x48D96DEBABE1390BULL,
		0x7B09543CCA7B8634ULL,
		0xEC08A7D646600C3DULL,
		0xBE050D2CC0166D28ULL,
		0xDC8319CBF027B88FULL,
		0x58EC881A0E51ACF7ULL,
		0xAD9622008E5BD76CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9104110014410711ULL,
		0x00516DC208A02803ULL,
		0x18085000487A8400ULL,
		0xAC0822C00040082CULL,
		0x9804092C00060D00ULL,
		0x58820842C027908FULL,
		0x1084001208508433ULL,
		0xA490000088034204ULL
	}};
	printf("Test Case 319\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 319 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -319;
	} else {
		printf("Test Case 319 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA7356DB99107C583ULL,
		0xA91EFC99DF59B525ULL,
		0x9EBEF3E07DC3AC42ULL,
		0x95F61DFAF35E74D5ULL,
		0xFC6486AF6B1A5564ULL,
		0xF251DB95AAF8B6BAULL,
		0x3C9CAE9CBBAB3874ULL,
		0xFBBFE316E91DAC01ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE2585B22B9F7538BULL,
		0xA31A6CA37F2E814BULL,
		0x0D58BCF8968FF89CULL,
		0x4664F6996CEEB378ULL,
		0xE679E4A5E1D94794ULL,
		0x3C64AFE34C0EE45FULL,
		0x8D55DDB1DFC87573ULL,
		0x8271E1388419DBE9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA210492091074183ULL,
		0xA11A6C815F088101ULL,
		0x0C18B0E01483A800ULL,
		0x04641498604E3050ULL,
		0xE46084A561184504ULL,
		0x30408B810808A41AULL,
		0x0C148C909B883070ULL,
		0x8231E11080198801ULL
	}};
	printf("Test Case 320\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 320 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -320;
	} else {
		printf("Test Case 320 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x64CC77E3DACCA3FEULL,
		0x1FEE01DB1DD6342EULL,
		0xEDE71288D3ACF065ULL,
		0xC0C7D5912176E18DULL,
		0x1D36EAC48AE8D805ULL,
		0x0AC24E8CF042A5B1ULL,
		0x040580C85D065930ULL,
		0x1B479D6348B1591EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x35465C44A5D10D2AULL,
		0xE4CD43F5E132D07EULL,
		0xDC115BA88F0A1050ULL,
		0x475F33229F517420ULL,
		0x26B852A47D94B462ULL,
		0x914A43C1CA519E9CULL,
		0xAE17418238A1049BULL,
		0xE57C76E1023F27BFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2444544080C0012AULL,
		0x04CC01D10112102EULL,
		0xCC01128883081040ULL,
		0x4047110001506000ULL,
		0x0430428408809000ULL,
		0x00424280C0408490ULL,
		0x0405008018000010ULL,
		0x014414610031011EULL
	}};
	printf("Test Case 321\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 321 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -321;
	} else {
		printf("Test Case 321 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAB640A78C0C9FF4CULL,
		0x11219DF5CEAD3725ULL,
		0xAD091F8FB1323585ULL,
		0x03E44FF5A9531D55ULL,
		0x71CC439D114347B6ULL,
		0x1292B51300332DDDULL,
		0xC562C9E50B18FC56ULL,
		0x3FEBCEA1E93B4899ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x83062F9562685784ULL,
		0xDDECCC8AF9D1B0CDULL,
		0xF05B192E3346260AULL,
		0x8E1F271342042278ULL,
		0xE273F22A3B061E1DULL,
		0xEE548270825E0322ULL,
		0x2537E65EFB425502ULL,
		0xA05058D19AE0E210ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x83040A1040485704ULL,
		0x11208C80C8813005ULL,
		0xA009190E31022400ULL,
		0x0204071100000050ULL,
		0x6040420811020614ULL,
		0x0210801000120100ULL,
		0x0522C0440B005402ULL,
		0x2040488188204010ULL
	}};
	printf("Test Case 322\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 322 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -322;
	} else {
		printf("Test Case 322 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x087C329F2AA0D244ULL,
		0x7ED3F755C50BBFC8ULL,
		0xCD99F91CD35AD839ULL,
		0x5149A93B4844770BULL,
		0x925834E0E3E3EE75ULL,
		0x88BA96C9C87525CFULL,
		0x9A1617A96C2FBD60ULL,
		0xB7E0F52C646608B1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD77085720353580CULL,
		0x8CF66BB43F43B747ULL,
		0x7BBB902B0C2417F8ULL,
		0x5F1ECF70D961E85EULL,
		0x49D52A44397AC6FEULL,
		0x8D34C37FA88FDCD9ULL,
		0x9F5BCECEF23267D7ULL,
		0x4F93F6BD668DA5A1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0070001202005004ULL,
		0x0CD263140503B740ULL,
		0x4999900800001038ULL,
		0x510889304840600AULL,
		0x005020402162C674ULL,
		0x88308249880504C9ULL,
		0x9A12068860222540ULL,
		0x0780F42C640400A1ULL
	}};
	printf("Test Case 323\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 323 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -323;
	} else {
		printf("Test Case 323 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1F986DB26880F1B5ULL,
		0x26943A62E9D0ADC6ULL,
		0x40644F253F2D6128ULL,
		0x0E51B4F9A5B78ED1ULL,
		0xFD61A76AC7762736ULL,
		0xB6EED31AF4DDB96BULL,
		0xAD2207733D4ED176ULL,
		0xA028E6E79A2CBE4FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCADF10666CCC7F16ULL,
		0x7D1C791B1BAF90E8ULL,
		0xA6E1C0C59C697E60ULL,
		0xEFA1D91D0B05A9C9ULL,
		0x77782FCB22EDE69FULL,
		0x409963A8173BA3F3ULL,
		0x0A609E584F0A2F42ULL,
		0xBF968C1A4F1B65A2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0A98002268807114ULL,
		0x24143802098080C0ULL,
		0x006040051C296020ULL,
		0x0E019019010588C1ULL,
		0x7560274A02642616ULL,
		0x008843081419A163ULL,
		0x082006500D0A0142ULL,
		0xA00084020A082402ULL
	}};
	printf("Test Case 324\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 324 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -324;
	} else {
		printf("Test Case 324 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD6B8A6644CC6B063ULL,
		0x0D5297299F0590CDULL,
		0xCD146BFCD7CE5957ULL,
		0xA4714B58E7284284ULL,
		0xDFD7A21640870EDDULL,
		0x693B785A4B2870E1ULL,
		0xA13D04135206AE29ULL,
		0x79FEA691453B47A8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB2DDBB60067823D7ULL,
		0x3A45E2A0AE988388ULL,
		0x2DCBE83289ACE607ULL,
		0x24D748602F1517E8ULL,
		0x8F4CD891E0814CFDULL,
		0x336895086FB5635CULL,
		0xC94BBF80F2270146ULL,
		0x41C16E8F872FE6CEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9298A26004402043ULL,
		0x084082208E008088ULL,
		0x0D006830818C4007ULL,
		0x2451484027000280ULL,
		0x8F44801040810CDDULL,
		0x212810084B206040ULL,
		0x8109040052060000ULL,
		0x41C02681052B4688ULL
	}};
	printf("Test Case 325\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 325 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -325;
	} else {
		printf("Test Case 325 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7B7963AD7F9BD22BULL,
		0x399C474B5CCD766CULL,
		0x98B1CF99F8E340FFULL,
		0x29EE6C56999B21BFULL,
		0x4619484B6CE0CAE0ULL,
		0xEFED71DD746B0C77ULL,
		0xC1C19B8700BE948CULL,
		0xD25F73825C24B7E0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBC6497FDE5ABB761ULL,
		0x2785B9A10BE6A285ULL,
		0x8613C971CC542380ULL,
		0xCA20F7DB265C764BULL,
		0x3B479F77A2A0924DULL,
		0x76F76A8A9C8DA5B0ULL,
		0x2AF498235A484F9CULL,
		0x2DA29E86A38633B4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x386003AD658B9221ULL,
		0x2184010108C42204ULL,
		0x8011C911C8400080ULL,
		0x082064520018200BULL,
		0x0201084320A08240ULL,
		0x66E5608814090430ULL,
		0x00C098030008048CULL,
		0x00021282000433A0ULL
	}};
	printf("Test Case 326\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 326 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -326;
	} else {
		printf("Test Case 326 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x23A1133F97477CA3ULL,
		0x82466349B32EC22FULL,
		0x2721ECC3E82BA4C0ULL,
		0xA18D4599CB79A32CULL,
		0x84D36E13CC0EA9F4ULL,
		0x078BFFEEFE2CD5A6ULL,
		0x3C9A852EC8052475ULL,
		0xF9DB72E78C4492F5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0B2D788C16C680B0ULL,
		0x40B5CAEFCBD69E9AULL,
		0x27319E4772B137F1ULL,
		0x85C56DD740417502ULL,
		0x37B7DF73AACE5323ULL,
		0x011BA192ABB54230ULL,
		0x246407B6EC3A3356ULL,
		0x368ED423D7E1AC33ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0321100C164600A0ULL,
		0x000442498306820AULL,
		0x27218C43602124C0ULL,
		0x8185459140412100ULL,
		0x04934E13880E0120ULL,
		0x010BA182AA244020ULL,
		0x24000526C8002054ULL,
		0x308A502384408031ULL
	}};
	printf("Test Case 327\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 327 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -327;
	} else {
		printf("Test Case 327 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0DCC4931CF93A812ULL,
		0x391CAE0EDB784635ULL,
		0xC01AE4E8065A1F9CULL,
		0x8E62014F55EBFE0DULL,
		0xF986AFCE1E7BF12AULL,
		0xE6AC5A7654C43AD8ULL,
		0x02B3BEF7D7ACDA9AULL,
		0x5A4185EF29CF7A22ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF09547FE030D0909ULL,
		0xFAFB5EFEF2F50E4BULL,
		0x5897E3B6B396548AULL,
		0x36BAAC9CD7AFEEA1ULL,
		0x6E565415B733889EULL,
		0x815801A08CC2C892ULL,
		0x37CA6771D4C220D9ULL,
		0x7513B0DFC8D5544FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0084413003010800ULL,
		0x38180E0ED2700601ULL,
		0x4012E0A002121488ULL,
		0x0622000C55ABEE01ULL,
		0x680604041633800AULL,
		0x8008002004C00890ULL,
		0x02822671D4800098ULL,
		0x500180CF08C55002ULL
	}};
	printf("Test Case 328\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 328 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -328;
	} else {
		printf("Test Case 328 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC61D5829F6EAE412ULL,
		0x0AF0F8E046328A7CULL,
		0x35A021B2F4647B16ULL,
		0xA5F17E29705CB721ULL,
		0x2E35CF18F6B21649ULL,
		0x73912183C9EB72B7ULL,
		0xEAC5715392D56C45ULL,
		0xEB72BBE4A4A19B57ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x361A5531399A45BEULL,
		0xBE15E275DB3F417CULL,
		0x24003E65D6932AB9ULL,
		0xCAA4A7F5BD26173DULL,
		0x4556F2A3EBA2CBCAULL,
		0x8334363806F13C3FULL,
		0xA3BF09FA870F918DULL,
		0x6C136392F3C8268DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x06185021308A4412ULL,
		0x0A10E0604232007CULL,
		0x24002020D4002A10ULL,
		0x80A0262130041721ULL,
		0x0414C200E2A20248ULL,
		0x0310200000E13037ULL,
		0xA285015282050005ULL,
		0x68122380A0800205ULL
	}};
	printf("Test Case 329\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 329 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -329;
	} else {
		printf("Test Case 329 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x13046ACF7A5614A4ULL,
		0x4C866FD3A68DDA21ULL,
		0x54327C7BF7FC1C68ULL,
		0xBB61CF3BB60947AFULL,
		0xDC7DCB06FBFFEFB8ULL,
		0xD1E81F68E22BD2DDULL,
		0xEFF3CD5074BEB082ULL,
		0x0DBFC435E841354AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE305C7495837966FULL,
		0x6A594644EE12C12EULL,
		0xC5C5F5CCEE75F176ULL,
		0xA225D35576077ACCULL,
		0x9FB945D59838AAADULL,
		0xF44E46D9172E8F94ULL,
		0x18977F571807E1B1ULL,
		0x762D0E698AD35089ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0304424958161424ULL,
		0x48004640A600C020ULL,
		0x44007448E6741060ULL,
		0xA221C3113601428CULL,
		0x9C3941049838AAA8ULL,
		0xD0480648022A8294ULL,
		0x08934D501006A080ULL,
		0x042D042188411008ULL
	}};
	printf("Test Case 330\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 330 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -330;
	} else {
		printf("Test Case 330 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x975D10DBF12B734CULL,
		0x1BBEAF062C6323E1ULL,
		0xE26CECC72ACB011CULL,
		0xFDDBB6DA887E1289ULL,
		0x1E32C18FCF215CEEULL,
		0x386707F169F6EA40ULL,
		0x48599F64D824EB80ULL,
		0x47D2FA2DA9DFA09DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x50A6BB8711D9B5FFULL,
		0x742F6EE7AAC31BF8ULL,
		0xF91F90415A8ACBB5ULL,
		0xE4B751DBBAD83D18ULL,
		0x7451C1EC28DA546BULL,
		0xDF6234543016827AULL,
		0x727371D03420EE8FULL,
		0x2C8A07C753C0C7ACULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x100410831109314CULL,
		0x102E2E06284303E0ULL,
		0xE00C80410A8A0114ULL,
		0xE49310DA88581008ULL,
		0x1410C18C0800546AULL,
		0x1862045020168240ULL,
		0x405111401020EA80ULL,
		0x0482020501C0808CULL
	}};
	printf("Test Case 331\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 331 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -331;
	} else {
		printf("Test Case 331 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB463A5FD79B16118ULL,
		0x3EC7E122EF8F2495ULL,
		0xB0A2FFED17666153ULL,
		0x9CEDCEF20247B598ULL,
		0x999E85E01FE89693ULL,
		0x5BC17278F4EE8FCAULL,
		0xB30658A3ECC49DACULL,
		0x5CA5B018E28463D3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE0B0399EDFA541B6ULL,
		0x7DA8BDB2809606AFULL,
		0x3CFA444A29B39AB3ULL,
		0xB88D5E216C820B61ULL,
		0xA31753E486088057ULL,
		0x9C0FE1FBCD15A482ULL,
		0x1CA4AE37AFD629D1ULL,
		0xB52E55EAE8911391ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA020219C59A14110ULL,
		0x3C80A12280860485ULL,
		0x30A2444801220013ULL,
		0x988D4E2000020100ULL,
		0x811601E006088013ULL,
		0x18016078C4048482ULL,
		0x10040823ACC40980ULL,
		0x14241008E0800391ULL
	}};
	printf("Test Case 332\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 332 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -332;
	} else {
		printf("Test Case 332 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8947D3B40A1BFF0BULL,
		0x9F6D3DF822585F28ULL,
		0x400805E908F40E2FULL,
		0x12AFB4E7ADB0B628ULL,
		0x7C8B1785F63BAA65ULL,
		0xE8DE0CA3A660C154ULL,
		0xD73C371EE8D689A9ULL,
		0xED0E00CA4D1715B9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x54318FBA16AC80C9ULL,
		0x26CA117917CEF8F8ULL,
		0x687371861D70D23CULL,
		0x6E856A5B8386D256ULL,
		0x9011A9F25E54F2D8ULL,
		0xB74F5F9FFD53FFE5ULL,
		0x5803605ABCA427E2ULL,
		0x5A8DE9AB8BE68716ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x000183B002088009ULL,
		0x0648117802485828ULL,
		0x400001800870022CULL,
		0x0285204381809200ULL,
		0x100101805610A240ULL,
		0xA04E0C83A440C144ULL,
		0x5000201AA88401A0ULL,
		0x480C008A09060510ULL
	}};
	printf("Test Case 333\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 333 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -333;
	} else {
		printf("Test Case 333 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCA6C75920242A0D9ULL,
		0x5E681210A2846E11ULL,
		0xFF273CF60408F37BULL,
		0x0D9820F503497AA3ULL,
		0x92B554DFDB59D76FULL,
		0x74FBCB8427BBC69CULL,
		0xF0A316BF3942EF47ULL,
		0x15E0F375F1B39872ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3F4DCFC2AB319F62ULL,
		0x3E2BA96BFC1452A7ULL,
		0x6958F9013B78DBE9ULL,
		0x81F0AC67B10F88CEULL,
		0xE9C021CF2227C537ULL,
		0x11259C569123BBE9ULL,
		0x354F47B22883DCE8ULL,
		0x0C6544AEC4860428ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0A4C458202008040ULL,
		0x1E280000A0044201ULL,
		0x690038000008D369ULL,
		0x0190206501090882ULL,
		0x808000CF0201C527ULL,
		0x1021880401238288ULL,
		0x300306B22802CC40ULL,
		0x04604024C0820020ULL
	}};
	printf("Test Case 334\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 334 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -334;
	} else {
		printf("Test Case 334 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCE9C3DAC7691BBC0ULL,
		0x50D2C5E45FE7D21FULL,
		0x32D751C5FAC35858ULL,
		0xAA5303C94344721BULL,
		0x510EBA666597F1D7ULL,
		0x0D55B3030B00AC7FULL,
		0x50A67ACFECD656DEULL,
		0xB3F56E3F7B59EEE4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE0B2DB7CB8F15023ULL,
		0xF31FCC03A006D0E1ULL,
		0x26FF75441E951A06ULL,
		0xA79DD050BC27A0E8ULL,
		0x4D7D99FC4307DCC7ULL,
		0x70300134D453A36EULL,
		0x82E99F2C1D753742ULL,
		0x915C07B140B5F7D2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC090192C30911000ULL,
		0x5012C4000006D001ULL,
		0x22D751441A811800ULL,
		0xA211004000042008ULL,
		0x410C98644107D0C7ULL,
		0x001001000000A06EULL,
		0x00A01A0C0C541642ULL,
		0x915406314011E6C0ULL
	}};
	printf("Test Case 335\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 335 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -335;
	} else {
		printf("Test Case 335 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE6DA95ADE3AD3DE4ULL,
		0xD4EC70EA8BFF6419ULL,
		0x665061C077654438ULL,
		0x31B8CB2C9D65BE7BULL,
		0x1130C68E461C4B42ULL,
		0x3F7629DCA20FE0D0ULL,
		0xB131633D0AD7AC47ULL,
		0x98E02793A0A253ECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCA001B2C1785D326ULL,
		0x006B6C56612AC127ULL,
		0x8E49BFE9BD4591ADULL,
		0x250B5DBFE3A54F0FULL,
		0xB624B8F9C40CA913ULL,
		0x5044E49BDB7243A7ULL,
		0xC5E2A50117F841FCULL,
		0xF0FB467DE09D73B8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC200112C03851124ULL,
		0x00686042012A4001ULL,
		0x064021C035450028ULL,
		0x2108492C81250E0BULL,
		0x10208088440C0902ULL,
		0x1044209882024080ULL,
		0x8120210102D00044ULL,
		0x90E00611A08053A8ULL
	}};
	printf("Test Case 336\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 336 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -336;
	} else {
		printf("Test Case 336 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6CB6463EEA7911FCULL,
		0xA4E5450A22C147DBULL,
		0x01064B937C2AED5BULL,
		0x975466687CB6D3E9ULL,
		0x7DF7D9DB338925EBULL,
		0x45B2412A78FA7885ULL,
		0xD697180184EFFB11ULL,
		0x5E9D06D4B176E342ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1D2A56E1FF996AACULL,
		0xE885789A0A09334DULL,
		0x8E20D1900C365027ULL,
		0x404960C174CEC216ULL,
		0x7EE1EDBFE22538AEULL,
		0xD0AC6FB3B013CFC8ULL,
		0xCE8F1CFCC3A4CA96ULL,
		0xA6A06B9C4F6ED2E5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0C224620EA1900ACULL,
		0xA085400A02010349ULL,
		0x000041900C224003ULL,
		0x004060407486C200ULL,
		0x7CE1C99B220120AAULL,
		0x40A0412230124880ULL,
		0xC687180080A4CA10ULL,
		0x068002940166C240ULL
	}};
	printf("Test Case 337\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 337 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -337;
	} else {
		printf("Test Case 337 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF3293FAF6FC57B5DULL,
		0x7F808D4A50A1FFF9ULL,
		0x376C2E78D323F93EULL,
		0x51ECEFB65193FAA7ULL,
		0x327D9D0FB256F2EAULL,
		0xFCBC60F02949FE66ULL,
		0x832F4DBCF176BB14ULL,
		0x58A1FBACF7864E63ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA11B2EEBCC0E2619ULL,
		0x9D79ACECE3B65D7FULL,
		0x4AFB3450C7EA6DA5ULL,
		0x53204544ECAEE3AFULL,
		0x5EDD4253A2000479ULL,
		0x2CDE0C18A2E2947DULL,
		0xAAD1D4B0FD4862AAULL,
		0x87F69AE2562A8A5EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA1092EAB4C042219ULL,
		0x1D008C4840A05D79ULL,
		0x02682450C3226924ULL,
		0x512045044082E2A7ULL,
		0x125D0003A2000068ULL,
		0x2C9C001020409464ULL,
		0x820144B0F1402200ULL,
		0x00A09AA056020A42ULL
	}};
	printf("Test Case 338\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 338 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -338;
	} else {
		printf("Test Case 338 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x12CBD79E62B127DCULL,
		0xD354B9747ED1F9FFULL,
		0x6D944381838830F8ULL,
		0x86E602E557DC800EULL,
		0x151286C7B58166B3ULL,
		0x912DCF1A1AD1B581ULL,
		0x660F6D8FD94527CFULL,
		0xFB18CD732791109EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFDFB6CFC7D89D43AULL,
		0xA5371F423870228BULL,
		0xFBEB3CF10D918C78ULL,
		0xBDD4F0FB39B0B137ULL,
		0xE8DD65741608AAE4ULL,
		0x72B7C6FEED85D8A3ULL,
		0xB4F26058831547F9ULL,
		0xBF5D3BC1F6D99CBBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x10CB449C60810418ULL,
		0x811419403850208BULL,
		0x6980008101800078ULL,
		0x84C400E111908006ULL,
		0x00100444140022A0ULL,
		0x1025C61A08819081ULL,
		0x24026008810507C9ULL,
		0xBB1809412691109AULL
	}};
	printf("Test Case 339\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 339 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -339;
	} else {
		printf("Test Case 339 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0794471053A5E12DULL,
		0x74BB63FC02BDB635ULL,
		0x3842E8065B2F0430ULL,
		0x75ED03512BF0F616ULL,
		0x3D02BCAAE9C5788EULL,
		0xB1704FFE4CC9CF83ULL,
		0xD8A8EF1890BD3FB3ULL,
		0x398986189BEF99BDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB32047598FEBF70AULL,
		0x03AC1307C9EED7ABULL,
		0x4B6C3A71C2646297ULL,
		0x445BB4E97D299D51ULL,
		0x1E25F1AEF5EDB52CULL,
		0x6859E4236F734138ULL,
		0x16C2F951AA1337D6ULL,
		0x03965AC822AD0EF7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0300471003A1E108ULL,
		0x00A8030400AC9621ULL,
		0x0840280042240010ULL,
		0x4449004129209410ULL,
		0x1C00B0AAE1C5300CULL,
		0x205044224C414100ULL,
		0x1080E91080113792ULL,
		0x0180020802AD08B5ULL
	}};
	printf("Test Case 340\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 340 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -340;
	} else {
		printf("Test Case 340 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x98162E3A672D225BULL,
		0xC1AC3822021FA625ULL,
		0x9309B688AE47F3CEULL,
		0xD2B9F29404FD5DC6ULL,
		0x3A43A2E5E2BE83DCULL,
		0x6CF8A657C356B106ULL,
		0x892832A0597DF2EEULL,
		0x775146FCCBBD7B43ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFE0BED1294AEC2E5ULL,
		0xB79D11A455E0B7A2ULL,
		0x962DB3E93CE8440DULL,
		0x0D380E0ADECAF7D5ULL,
		0x7827AD65D04A547BULL,
		0x2CA59DDF3674949DULL,
		0xE7430ADAD5EE5FDAULL,
		0xFDE88BBD633C14BDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x98022C12042C0241ULL,
		0x818C10200000A620ULL,
		0x9209B2882C40400CULL,
		0x0038020004C855C4ULL,
		0x3803A065C00A0058ULL,
		0x2CA0845702549004ULL,
		0x81000280516C52CAULL,
		0x754002BC433C1001ULL
	}};
	printf("Test Case 341\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 341 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -341;
	} else {
		printf("Test Case 341 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7860E00DE4D4F437ULL,
		0x2CDCACFE128562AEULL,
		0xA8C9EAE837AA0834ULL,
		0x856AAF95BCF78CEEULL,
		0x5759FECF68BE5ACDULL,
		0x954F59C1B97202B3ULL,
		0x1578E1B5397B3332ULL,
		0xF18D04FE35DB414BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F06143619A850CCULL,
		0x858730C99F0E8931ULL,
		0xD0EF6F9F669FD603ULL,
		0x82620274D316B7BCULL,
		0x75616DD0CD018F49ULL,
		0x8F7FD1657509A746ULL,
		0x02D0F61AACFFF00AULL,
		0xFAED4381CC50A20FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0800000400805004ULL,
		0x048420C812040020ULL,
		0x80C96A88268A0000ULL,
		0x80620214901684ACULL,
		0x55416CC048000A49ULL,
		0x854F514131000202ULL,
		0x0050E010287B3002ULL,
		0xF08D00800450000BULL
	}};
	printf("Test Case 342\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 342 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -342;
	} else {
		printf("Test Case 342 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD2D30AC0E408F743ULL,
		0x7A9B0D9106950647ULL,
		0xA43C816A7A1BB1F6ULL,
		0x44C5D1C9C123C14BULL,
		0x33798748E23325C9ULL,
		0x43CB135A2A5EB14CULL,
		0x23BCCB74322B7EC4ULL,
		0x2F1740F4558460C5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x721E401A557DAF4DULL,
		0xB6F68182FCCB76BAULL,
		0x71FBAE84892D6979ULL,
		0xA8815220F672F326ULL,
		0x3F797A5FE3976407ULL,
		0xE69732AEE0E61BD4ULL,
		0x8A7F2A86A86385B5ULL,
		0x6C974475B6DC7642ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x521200004408A741ULL,
		0x3292018004810602ULL,
		0x2038800008092170ULL,
		0x00815000C022C102ULL,
		0x33790248E2132401ULL,
		0x4283120A20461144ULL,
		0x023C0A0420230484ULL,
		0x2C17407414846040ULL
	}};
	printf("Test Case 343\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 343 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -343;
	} else {
		printf("Test Case 343 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD22D419C1BBEC2F7ULL,
		0xCC13E85BDA606AF5ULL,
		0x70FE1399E17639F9ULL,
		0xE167341A9728A5C3ULL,
		0x8601C65360A76FB1ULL,
		0xC9BE2526E0E6768AULL,
		0x0DE6C7F08D424EDFULL,
		0xABFF20B5AEB477D4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x50D541ACBA0CEF0BULL,
		0x724A83C3878147EDULL,
		0xF751B575C201947EULL,
		0xF3C2DDA4C43306DCULL,
		0x32851F18B29C99C7ULL,
		0x92B451DE2841CEC9ULL,
		0xA6F08DCAD1E79019ULL,
		0x1380DFFB551FFE61ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5005418C1A0CC203ULL,
		0x40028043820042E5ULL,
		0x70501111C0001078ULL,
		0xE1421400842004C0ULL,
		0x0201061020840981ULL,
		0x80B4010620404688ULL,
		0x04E085C081420019ULL,
		0x038000B104147640ULL
	}};
	printf("Test Case 344\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 344 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -344;
	} else {
		printf("Test Case 344 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAADE6357863B45B3ULL,
		0x372216520D334E69ULL,
		0x86306D0BBDEB58F6ULL,
		0xE25E5A4F466E56DBULL,
		0x12E88F28D0B03AAEULL,
		0x4231D49D19911089ULL,
		0xA7E88A458199D6D6ULL,
		0x5ABFF3098A23DFE8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x39ADB886254A7315ULL,
		0x278CB25A0FEB56A1ULL,
		0xD6DF8789FECB55CCULL,
		0xC89E7294410F81A7ULL,
		0xAD020232FF5331D5ULL,
		0xF59F530F6085E53EULL,
		0xDEF0C34DDB72EB03ULL,
		0xCD6F8966607CD9FAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x288C2006040A4111ULL,
		0x270012520D234621ULL,
		0x86100509BCCB50C4ULL,
		0xC01E5204400E0083ULL,
		0x00000220D0103084ULL,
		0x4011500D00810008ULL,
		0x86E082458110C202ULL,
		0x482F81000020D9E8ULL
	}};
	printf("Test Case 345\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 345 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -345;
	} else {
		printf("Test Case 345 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3DEB08D98A676CA6ULL,
		0x3B29E9F9131477FAULL,
		0x204771FD2ACAE5EDULL,
		0x39448F3036BF432EULL,
		0x0CD65345D1EECDCCULL,
		0xBCFE09EB9658D091ULL,
		0xA78DE23C4435FE41ULL,
		0xF838DFA984BA2C41ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3E8558A9F02F4565ULL,
		0x554621EC809F867EULL,
		0xF590A58A69940EEBULL,
		0x8DCE299D129FF8D5ULL,
		0x5B8DF5EEE4DE2026ULL,
		0x3907371D583DE2CEULL,
		0x4EBED19F8AA5EDA7ULL,
		0x3DCE4A8F1FEC7FA0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3C81088980274424ULL,
		0x110021E80014067AULL,
		0x20002188288004E9ULL,
		0x09440910129F4004ULL,
		0x08845144C0CE0004ULL,
		0x380601091018C080ULL,
		0x068CC01C0025EC01ULL,
		0x38084A8904A82C00ULL
	}};
	printf("Test Case 346\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 346 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -346;
	} else {
		printf("Test Case 346 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3A5E1524A527E8CEULL,
		0x0CEA1610D545FCA6ULL,
		0x7656884F274CC423ULL,
		0x8A71BDE69AA502E1ULL,
		0xC78AB96F19C3F9E0ULL,
		0xA9C9ADE8FB6A5053ULL,
		0x897362C82853B769ULL,
		0x0CABA8CDCAB55DCFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDFBC7D55D41CD994ULL,
		0x580CCD76DDA00A3FULL,
		0x3A63B67AE673D4B3ULL,
		0x91D4A0213CEFCD35ULL,
		0xF469F0B5436E3966ULL,
		0xA815A9AA1730C49DULL,
		0xF818E88A9F823A2AULL,
		0x14EFEC0C7A0C54C9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1A1C15048404C884ULL,
		0x08080410D5000826ULL,
		0x3242804A2640C423ULL,
		0x8050A02018A50021ULL,
		0xC408B02501423960ULL,
		0xA801A9A813204011ULL,
		0x8810608808023228ULL,
		0x04ABA80C4A0454C9ULL
	}};
	printf("Test Case 347\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 347 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -347;
	} else {
		printf("Test Case 347 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x18A2A48FB569EDDFULL,
		0xAF2515AE86EC0EFFULL,
		0xAAA5E467DD818156ULL,
		0x133A5AB8B41D3957ULL,
		0x47C98513EA173A46ULL,
		0x5FE02B763468A65BULL,
		0x9DF7DC5A3E549661ULL,
		0xEE150EA99228DEA7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x933A5C9AC345FD6CULL,
		0xAAD5CFBC72162F83ULL,
		0x97A99F2B36A5FDD4ULL,
		0x0A85D06DC968D0F3ULL,
		0x5B11B2CC422261E0ULL,
		0xBF9902BE91ABCE5DULL,
		0x59C6BEC749B8A93AULL,
		0x2185332CD6277AAAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1022048A8141ED4CULL,
		0xAA0505AC02040E83ULL,
		0x82A1842314818154ULL,
		0x0200502880081053ULL,
		0x4301800042022040ULL,
		0x1F80023610288659ULL,
		0x19C69C4208108020ULL,
		0x2005022892205AA2ULL
	}};
	printf("Test Case 348\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 348 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -348;
	} else {
		printf("Test Case 348 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA757D2BEC326F711ULL,
		0xAB020D0CCAEC1C84ULL,
		0xF40E8F7FF4E67497ULL,
		0x3A8B3B6DA1AB900DULL,
		0xD0ED49E9FBA7F248ULL,
		0xAFD8A2B35FDD8F02ULL,
		0x265EC0CE118CCFF9ULL,
		0xAA59EBEBEEA1DEF1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x71421C657F3E18EAULL,
		0xB5ACFB8F91201E2CULL,
		0xD80104A454D84BBAULL,
		0xF2816A6794F049ECULL,
		0x37E44E6B8F607779ULL,
		0xF04A4AC4D3D84713ULL,
		0xBF6746F01F11A51AULL,
		0x4F041045B55C68C0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2142102443261000ULL,
		0xA100090C80201C04ULL,
		0xD000042454C04092ULL,
		0x32812A6580A0000CULL,
		0x10E448698B207248ULL,
		0xA048028053D80702ULL,
		0x264640C011008518ULL,
		0x0A000041A40048C0ULL
	}};
	printf("Test Case 349\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 349 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -349;
	} else {
		printf("Test Case 349 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF39BF82858587F7CULL,
		0x4C6020EC2A303816ULL,
		0xB3883CAF1EBB038DULL,
		0x19DA32DE0A869978ULL,
		0x4343913CCE33D37DULL,
		0x3D2B589E359755B1ULL,
		0xE4B216A97373A23AULL,
		0x07FA40FA3D3228DCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x871BDC5E2E8CC6F7ULL,
		0x5A7C9593E9D5A8B9ULL,
		0xF7014983378AFB18ULL,
		0xEF715BB4521FC027ULL,
		0xC82CA9EF549D3155ULL,
		0x960882ADE19F69DAULL,
		0x874C2A82A433C6B4ULL,
		0x7318FEA6B7E0075FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x831BD80808084674ULL,
		0x4860008028102810ULL,
		0xB3000883168A0308ULL,
		0x0950129402068020ULL,
		0x4000812C44111155ULL,
		0x1408008C21974190ULL,
		0x8400028020338230ULL,
		0x031840A23520005CULL
	}};
	printf("Test Case 350\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 350 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -350;
	} else {
		printf("Test Case 350 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6EA25DB019FF3031ULL,
		0x051CCE148AB66842ULL,
		0xE4750527DADE406AULL,
		0x8503EFC3FEAF6D0FULL,
		0x42D4EA432A470202ULL,
		0x96E662222F67675CULL,
		0x5EA4B0FDDBAB369FULL,
		0x38125478F8C7E303ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0B2359C358540FAEULL,
		0x6D5FC81A6A4AE351ULL,
		0x7C1AC3CF621575BEULL,
		0x76CD89B90F26383CULL,
		0xC55F96F68057B8B7ULL,
		0x746C2B3CC30243D0ULL,
		0x1DCA67DBFEDE0EBFULL,
		0xD4E7CAFFAF4D3431ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0A22598018540020ULL,
		0x051CC8100A026040ULL,
		0x641001074214402AULL,
		0x040189810E26280CULL,
		0x4054824200470002ULL,
		0x1464222003024350ULL,
		0x1C8020D9DA8A069FULL,
		0x10024078A8452001ULL
	}};
	printf("Test Case 351\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 351 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -351;
	} else {
		printf("Test Case 351 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF33B31641C4B1A74ULL,
		0xCB278B5B86D74A8BULL,
		0x0F75A3D19F3C1695ULL,
		0x8EE2519E3634AE96ULL,
		0x5BA5CB8AEF39A299ULL,
		0xAA45F94818426EFDULL,
		0x6E6101A609424D84ULL,
		0x529888D9688B3F6AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6A62A1A76845CD55ULL,
		0xB37654137DCC8A4DULL,
		0xC88FAD93A6C9CD6AULL,
		0x7E1EE6CCAE725903ULL,
		0xF8AB3FE147E6FB1DULL,
		0xE3A50A26774C632AULL,
		0x242C9F231BB03AB6ULL,
		0xFD44F8BFC02DD6AEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6222212408410854ULL,
		0x8326001304C40A09ULL,
		0x0805A19186080400ULL,
		0x0E02408C26300802ULL,
		0x58A10B804720A219ULL,
		0xA205080010406228ULL,
		0x2420012209000884ULL,
		0x500088994009162AULL
	}};
	printf("Test Case 352\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 352 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -352;
	} else {
		printf("Test Case 352 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x78EE14D227B71DC7ULL,
		0x96788C58D2E09220ULL,
		0xDD0A30E64DAB10CDULL,
		0xE5C9D5CB5490E323ULL,
		0x661D6E571518C7D1ULL,
		0x2C41334B1CEDFB35ULL,
		0x0FFD2886310BF39FULL,
		0x50A49B011615499CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6E4BCCECE4B3B137ULL,
		0x1D98EE3DF47CBEFDULL,
		0xBEAADDC25F5C79C9ULL,
		0x41BB6D352FEE6A4FULL,
		0x0023920A6F9E27B0ULL,
		0x929228FEE67FF4ACULL,
		0xEB09198C86A48766ULL,
		0xD8FB9F2E78DE7D2DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x684A04C024B31107ULL,
		0x14188C18D0609220ULL,
		0x9C0A10C24D0810C9ULL,
		0x4189450104806203ULL,
		0x0001020205180790ULL,
		0x0000204A046DF024ULL,
		0x0B09088400008306ULL,
		0x50A09B001014490CULL
	}};
	printf("Test Case 353\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 353 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -353;
	} else {
		printf("Test Case 353 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8B8404EB903C2277ULL,
		0x58F6D0E1B653A358ULL,
		0x574B0F23AA97357DULL,
		0x5790534B24FBAB90ULL,
		0x1D2971DBA0D9FDF3ULL,
		0xF895CF9803947650ULL,
		0x0D26C24D459724D8ULL,
		0x953252032011B4CCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9A87D2B0E9675D08ULL,
		0x7ADD7950984E911CULL,
		0x6C6A27A82841B212ULL,
		0x1C7E32E9412DFF99ULL,
		0x5FBF5A37DA57F025ULL,
		0x06F74635F884A297ULL,
		0x5C7FF79E5ED9D4EAULL,
		0x35225F04688F086DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8A8400A080240000ULL,
		0x58D4504090428118ULL,
		0x444A072028013010ULL,
		0x141012490029AB90ULL,
		0x1D2950138051F021ULL,
		0x0095461000842210ULL,
		0x0C26C20C449104C8ULL,
		0x152252002001004CULL
	}};
	printf("Test Case 354\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 354 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -354;
	} else {
		printf("Test Case 354 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAA8D24997EF5EC99ULL,
		0x70D6CFE81676F081ULL,
		0x18EA63879A2B2690ULL,
		0x526690652E2351BDULL,
		0x7B4F0877CC51304BULL,
		0x38F8B33273B3D54FULL,
		0x74671867177DFE3CULL,
		0x1344AB2BB63F7972ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCA365253C8F36E9FULL,
		0x40CD293E87C8B73FULL,
		0x48C6A526A505783FULL,
		0xE30F21D54C71C534ULL,
		0x8481136069E62410ULL,
		0x3D004098CCA6D2A5ULL,
		0xA2518E41FA874151ULL,
		0xCD2372BF6E16AB81ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8A04001148F16C99ULL,
		0x40C409280640B001ULL,
		0x08C2210680012010ULL,
		0x420600450C214134ULL,
		0x0001006048402000ULL,
		0x3800001040A2D005ULL,
		0x2041084112054010ULL,
		0x0100222B26162900ULL
	}};
	printf("Test Case 355\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 355 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -355;
	} else {
		printf("Test Case 355 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDC196DD342FDC5DFULL,
		0x240CF9ECA32BB4A1ULL,
		0xE4C80037469ACD79ULL,
		0x2E59DF79303A9CFCULL,
		0x6BDEE4ED803884CAULL,
		0x0894394C4CE97E30ULL,
		0x347BA0ADADA820C4ULL,
		0xD5F233D7A8F8FBD3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2B1CE5A260C39B20ULL,
		0x2D1094408AF2AC51ULL,
		0x63F075FADF2F6697ULL,
		0xA706838974A4721AULL,
		0x0DEE857F3533F53BULL,
		0x0EEDB28FCE815CC4ULL,
		0x921B80656214A4C5ULL,
		0x198D5E988CC774D7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0818658240C18100ULL,
		0x240090408222A401ULL,
		0x60C00032460A4411ULL,
		0x2600830930201018ULL,
		0x09CE846D0030840AULL,
		0x0884300C4C815C00ULL,
		0x101B8025200020C4ULL,
		0x1180129088C070D3ULL
	}};
	printf("Test Case 356\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 356 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -356;
	} else {
		printf("Test Case 356 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC131BCFC520A1DBEULL,
		0xAE9B23D93B3AA0D7ULL,
		0x4C6BF21B6DB7A2AFULL,
		0xD66F4D2280AF6A3FULL,
		0xCD91FD128691E92AULL,
		0xF88E9E2D56A268CCULL,
		0x0A42A21201D363F7ULL,
		0x5AB8311E7A6E6555ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCCE360490FA001D6ULL,
		0x6ED24D9B53FDE167ULL,
		0x7E51BFB08B5A5316ULL,
		0x9BD957BAC7999E4CULL,
		0xB411DBF70923DAC3ULL,
		0x109E13B144CFDE3DULL,
		0x4B2BCF7FBB7C7E40ULL,
		0xA0F08989D3530439ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC021204802000196ULL,
		0x2E9201991338A047ULL,
		0x4C41B21009120206ULL,
		0x9249452280890A0CULL,
		0x8411D9120001C802ULL,
		0x108E12214482480CULL,
		0x0A02821201506240ULL,
		0x00B0010852420411ULL
	}};
	printf("Test Case 357\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 357 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -357;
	} else {
		printf("Test Case 357 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD7489C75426091DFULL,
		0xCE5ACB7EA06DB66BULL,
		0xB86A29B70E26EF66ULL,
		0x256FA0F3B5327E90ULL,
		0xE85D27917032F3C4ULL,
		0x125A8BB067BDBD3BULL,
		0x3BED58949C8723D5ULL,
		0x37621B5C92758E00ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x86C73F664EE7C132ULL,
		0xDAD4238337BA5902ULL,
		0x973F1FF9B1CA620BULL,
		0xED347216663E5B25ULL,
		0x3C738033C25BED5EULL,
		0x4C8066CD4A7D077DULL,
		0x84135760AAC93615ULL,
		0x42B3454165FD1BC2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x86401C6442608112ULL,
		0xCA50030220281002ULL,
		0x902A09B100026202ULL,
		0x2524201224325A00ULL,
		0x285100114012E144ULL,
		0x00000280423D0539ULL,
		0x0001500088812215ULL,
		0x0222014000750A00ULL
	}};
	printf("Test Case 358\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 358 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -358;
	} else {
		printf("Test Case 358 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF81A326F93D78D1DULL,
		0x86336B2DB63ABDC6ULL,
		0x7E795FCD99168A2AULL,
		0xCFC4D9D11819649AULL,
		0xDB21C1FB29C6A055ULL,
		0x52AE7362EB57911AULL,
		0x1817DF2EAE4F8942ULL,
		0x39061F3EDC31BE17ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x89162D89A09E0C23ULL,
		0x5D3E55B62F231C5EULL,
		0xC2E9363806211975ULL,
		0xF0C9B11C1EC2F8EBULL,
		0x1D0097C7DD415CDCULL,
		0xF8873C0B18CEA629ULL,
		0x4E58E34C1B16F25EULL,
		0xC0C1DA124F902CDFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8812200980960C01ULL,
		0x0432412426221C46ULL,
		0x4269160800000820ULL,
		0xC0C091101800608AULL,
		0x190081C309400054ULL,
		0x5086300208468008ULL,
		0x0810C30C0A068042ULL,
		0x00001A124C102C17ULL
	}};
	printf("Test Case 359\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 359 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -359;
	} else {
		printf("Test Case 359 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9556C5186C1D29EEULL,
		0xBA43C7747C347D5CULL,
		0x139792F96EB5F8D8ULL,
		0x15B52268ED0FC8F3ULL,
		0x001DB73BF5EE3D45ULL,
		0x5740D827225DE33DULL,
		0x85BE4B4FB8E63FD9ULL,
		0xFCAB393FFC01030DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x74557F944621132EULL,
		0xC4E0B5853F68B496ULL,
		0x2F3C3A11AEAF2570ULL,
		0x0AFD4DD823B00E2AULL,
		0x9B16861148A3DE73ULL,
		0x62AB0FAC7B62903EULL,
		0xA6822945E5504EEAULL,
		0x94A554C84920FB86ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x145445104401012EULL,
		0x804085043C203414ULL,
		0x031412112EA52050ULL,
		0x00B5004821000822ULL,
		0x0014861140A21C41ULL,
		0x420008242240803CULL,
		0x84820945A0400EC8ULL,
		0x94A1100848000304ULL
	}};
	printf("Test Case 360\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 360 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -360;
	} else {
		printf("Test Case 360 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x517212AB681F2148ULL,
		0x9390BF8E87672628ULL,
		0x55D7C24ACBFAC745ULL,
		0x073A1662CFF677CAULL,
		0x8DE38D560FF199BBULL,
		0x529CFC72E4085C1FULL,
		0x82DB99F3AFDF512AULL,
		0x978F365F78BF7178ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0B85F9A782A66EAEULL,
		0x75D0D8039FC38652ULL,
		0x9B6EC1B493AF0417ULL,
		0x2F697E60F6A30CE8ULL,
		0x9F77C7B8117F7C68ULL,
		0x30610D1EB2A056DEULL,
		0x9E71E53D3AC4FC95ULL,
		0xAEF33F7A1B890D2DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x010010A300062008ULL,
		0x1190980287430600ULL,
		0x1146C00083AA0405ULL,
		0x07281660C6A204C8ULL,
		0x8D63851001711828ULL,
		0x10000C12A000541EULL,
		0x825181312AC45000ULL,
		0x8683365A18890128ULL
	}};
	printf("Test Case 361\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 361 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -361;
	} else {
		printf("Test Case 361 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF1D645C22011BEBEULL,
		0x293977B83DC668A0ULL,
		0xA9D637DC0EC61C10ULL,
		0x7299E2F8F65EC63CULL,
		0x231B5BB83D7AF2A7ULL,
		0x001E56CB0D1D5266ULL,
		0x60E7FDD7A3666CAAULL,
		0xBE5B83152CD84427ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x709A66E30E8984E6ULL,
		0xE8CF3861344B93FAULL,
		0xA326F30C181B0BAAULL,
		0xBB87807D3AA3EBD9ULL,
		0x7A90C1A1CEBAF1BBULL,
		0xA12ABE84A75AD914ULL,
		0x35DA6A61350B1A0FULL,
		0x8E5F85EE5E0D9183ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x709244C2000184A6ULL,
		0x28093020344200A0ULL,
		0xA106330C08020800ULL,
		0x328180783202C218ULL,
		0x221041A00C3AF0A3ULL,
		0x000A168005185004ULL,
		0x20C268412102080AULL,
		0x8E5B81040C080003ULL
	}};
	printf("Test Case 362\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 362 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -362;
	} else {
		printf("Test Case 362 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x584EB79A2276500FULL,
		0x8AA2CB987530F22DULL,
		0xF64B3F6D2138B766ULL,
		0xBBB364C2D1C9ADD4ULL,
		0xD8773B107DDB09BAULL,
		0x7E8A25F07CC02E9AULL,
		0x2BB0175C81E0AB67ULL,
		0x74CB7090F8DE2BBFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB3543F071CBFA09EULL,
		0x33C1E6328F14BD01ULL,
		0xB8C915D24D0F473CULL,
		0x7D4F448ABBE6D255ULL,
		0x102140A242ACDA84ULL,
		0x8B69ADAA11D60090ULL,
		0xC2D54DADE51A080FULL,
		0x6385712C00D024A5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x104437020036000EULL,
		0x0280C2100510B001ULL,
		0xB049154001080724ULL,
		0x3903448291C08054ULL,
		0x1021000040880880ULL,
		0x0A0825A010C00090ULL,
		0x0290050C81000807ULL,
		0x6081700000D020A5ULL
	}};
	printf("Test Case 363\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 363 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -363;
	} else {
		printf("Test Case 363 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE8992ACFF4D2A212ULL,
		0x5CC824B82181BE3AULL,
		0xD300A0787D9B5FC6ULL,
		0x57D9AE84CB50CA48ULL,
		0xB5044430E7051D5CULL,
		0x4355C72256EEFE32ULL,
		0xFA492AACB4137980ULL,
		0xA3D401610520A80BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8B7496C1DD181E7DULL,
		0xACF4F3C575D75388ULL,
		0x25CD5A02B01F8DBCULL,
		0x76784B9F4B594195ULL,
		0xD27809022CEC5F1FULL,
		0x7F7CC545127A66D3ULL,
		0x4EFBAF49763F222AULL,
		0x128D8D96EE9F622BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x881002C1D4100210ULL,
		0x0CC0208021811208ULL,
		0x01000000301B0D84ULL,
		0x56580A844B504000ULL,
		0x9000000024041D1CULL,
		0x4354C500126A6612ULL,
		0x4A492A0834132000ULL,
		0x028401000400200BULL
	}};
	printf("Test Case 364\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 364 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -364;
	} else {
		printf("Test Case 364 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3B6AE05A01F41FFEULL,
		0xBFD2060CB4A74849ULL,
		0x45E4EBB29E5D8FE6ULL,
		0x1A8298466DE1CF09ULL,
		0xB817E696B5B2B7B1ULL,
		0x2154DCB2B0A5FFFCULL,
		0x54055D2E2BA6A41EULL,
		0x26EC52D9D3CD9EC2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5F2D3C40FB6776EEULL,
		0xC5FA34D3EA0D6617ULL,
		0x50C032955DD8191EULL,
		0xE1EA4718B9460397ULL,
		0x817379B5E45FE250ULL,
		0x6BE5B4DE72F6738CULL,
		0xA4F343A9F875D454ULL,
		0x1B922A3D98CD6ACDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1B282040016416EEULL,
		0x85D20400A0054001ULL,
		0x40C022901C580906ULL,
		0x0082000029400301ULL,
		0x80136094A412A210ULL,
		0x2144949230A4738CULL,
		0x0401412828248414ULL,
		0x0280021990CD0AC0ULL
	}};
	printf("Test Case 365\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 365 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -365;
	} else {
		printf("Test Case 365 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDB99067EE941A7B0ULL,
		0x0FF3549A1C2290B2ULL,
		0xD11493FD5A896F3CULL,
		0xA370393277B8BEF1ULL,
		0xF117B4F9D701301CULL,
		0x2370D1B60857F4D2ULL,
		0x9D705137EBCAA0D9ULL,
		0x9D0D2491B2EC148CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0AC4329165D68147ULL,
		0x33A9E75FF22CBAA8ULL,
		0x26719C2E5AE9271BULL,
		0xC9D164082268D95EULL,
		0xB9CDE62C8D38B583ULL,
		0xC5482C6905792B3DULL,
		0xF559A7340B1C170AULL,
		0x43D943AD31865731ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0A80021061408100ULL,
		0x03A1441A102090A0ULL,
		0x0010902C5A892718ULL,
		0x8150200022289850ULL,
		0xB105A42885003000ULL,
		0x0140002000512010ULL,
		0x955001340B080008ULL,
		0x0109008130841400ULL
	}};
	printf("Test Case 366\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 366 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -366;
	} else {
		printf("Test Case 366 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x001F5457A6E0D0BFULL,
		0xCF584B2114E8FFE2ULL,
		0xDE256016332ADD3FULL,
		0xA0AD92C053137F43ULL,
		0xE2240A981DF03E77ULL,
		0x44D56F6EB3F683EFULL,
		0x3A9E05E1838708D2ULL,
		0xCADC171C8D4FA2B6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0D7C79F0932E1678ULL,
		0x668CCD9E6F62BB3EULL,
		0xEE621EFCEC4C8F75ULL,
		0xC64CAFE92E3D68C0ULL,
		0xF021CA67F84708B6ULL,
		0x8301082815E9A093ULL,
		0x6855C0A54399F128ULL,
		0x75EDC15BF9A8FAFAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x001C505082201038ULL,
		0x460849000460BB22ULL,
		0xCE20001420088D35ULL,
		0x800C82C002116840ULL,
		0xE0200A0018400836ULL,
		0x0001082811E08083ULL,
		0x281400A103810000ULL,
		0x40CC01188908A2B2ULL
	}};
	printf("Test Case 367\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 367 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -367;
	} else {
		printf("Test Case 367 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDFEA8637C217CC03ULL,
		0xDBF71D85ADEFC85EULL,
		0x4454BAB9753B03D0ULL,
		0x9F73B2D362448ED4ULL,
		0x98CCBADF757F1864ULL,
		0x36954A01826720D0ULL,
		0x7DD1B5381348066EULL,
		0xDA5F8EEFA1452C62ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7C019FC10E05EAF8ULL,
		0x31A1DA710D20A75BULL,
		0xCCE577687127A331ULL,
		0xD2712F39597C180FULL,
		0x9142C42ABFE1D7B7ULL,
		0x7CF76647BD21BA59ULL,
		0x4C433AC35F613218ULL,
		0x9A556B2A4E608F60ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5C0086010205C800ULL,
		0x11A118010D20805AULL,
		0x4444322871230310ULL,
		0x9271221140440804ULL,
		0x9040800A35611024ULL,
		0x3495420180212050ULL,
		0x4C41300013400208ULL,
		0x9A550A2A00400C60ULL
	}};
	printf("Test Case 368\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 368 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -368;
	} else {
		printf("Test Case 368 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2C8DD197B64DC268ULL,
		0xE4C9548745B38291ULL,
		0x5E0FA773FF782372ULL,
		0xE3D1D00C9E00E0D5ULL,
		0x171C4B97014058B0ULL,
		0x9F38EB91D851C6A1ULL,
		0xDC59D475ADB5718EULL,
		0xEF181380A83AC949ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1E2BA01FE874D95DULL,
		0x3B93F6387A5ED6EEULL,
		0xB2117E899AD0B05EULL,
		0x7F96FE71EB9A0AE0ULL,
		0x68CF6628291E6874ULL,
		0x0C4FF2BCB5288875ULL,
		0x79E04C3B4BFD4E31ULL,
		0x24EDF895BED10DB1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0C098017A044C048ULL,
		0x2081540040128280ULL,
		0x120126019A502052ULL,
		0x6390D0008A0000C0ULL,
		0x000C420001004830ULL,
		0x0C08E29090008021ULL,
		0x5840443109B54000ULL,
		0x24081080A8100901ULL
	}};
	printf("Test Case 369\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 369 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -369;
	} else {
		printf("Test Case 369 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA4FE575998D1DBEFULL,
		0x46E0DB9E2BDF7941ULL,
		0x2120F0308F11DDE5ULL,
		0x8C3A129F809DB46AULL,
		0xC5B34D542C4E3D1EULL,
		0x47449CC1A3598DE6ULL,
		0x2C53262D99588FFAULL,
		0xA749FD23D33E67ADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8CE1DF4ECB7D0863ULL,
		0xDDFA6BA8CE234D43ULL,
		0x8D7DE8805E2096C7ULL,
		0x5EC2C346CE05EB8BULL,
		0xF4EE7695717BB20CULL,
		0x1F7BA5C23E57E608ULL,
		0x4F4BB52ED8567415ULL,
		0xAA5E5BC3376067DFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x84E0574888510863ULL,
		0x44E04B880A034941ULL,
		0x0120E0000E0094C5ULL,
		0x0C0202068005A00AULL,
		0xC4A24414204A300CULL,
		0x074084C022518400ULL,
		0x0C43242C98500410ULL,
		0xA24859031320678DULL
	}};
	printf("Test Case 370\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 370 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -370;
	} else {
		printf("Test Case 370 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x002708B9B5869D3CULL,
		0xF8967B5E7D8BEE49ULL,
		0x2A2229216091A3A0ULL,
		0x07F570C5CD511F12ULL,
		0x9645A08522B0D2CDULL,
		0x1E75AECD72B6950CULL,
		0xD1ADFDDAD8CEB21FULL,
		0x05F582CA61729481ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEF9C6ABB732EE6A0ULL,
		0x70CA7924BA91BF79ULL,
		0x7A26B0702E78BBCDULL,
		0xECF423ED9DC31A52ULL,
		0x51C36A05747DD81FULL,
		0x2975D9DA61D12690ULL,
		0x01BFA086B70790C2ULL,
		0x97BB75A0DE4F9EF6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x000408B931068420ULL,
		0x708279043881AE49ULL,
		0x2A2220202010A380ULL,
		0x04F420C58D411A12ULL,
		0x104120052030D00DULL,
		0x087588C860900400ULL,
		0x01ADA08290069002ULL,
		0x05B1008040429480ULL
	}};
	printf("Test Case 371\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 371 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -371;
	} else {
		printf("Test Case 371 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5E839C7A7BA24709ULL,
		0x439CC908664A4809ULL,
		0xC4F4BD9B6BBB57B6ULL,
		0x91BA1524B53F08D2ULL,
		0x0771F69186590B78ULL,
		0x06B344957D31090DULL,
		0x99A20FAF6C21908FULL,
		0xF8B5124F21B7C6FDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF1A1E115A1D87D6DULL,
		0xAD5BAB72F01C974FULL,
		0x60B3CB327B8E8AF3ULL,
		0x97014F232D08F4F3ULL,
		0xFE4BEDD3BA7D129BULL,
		0xA0D28C945D0B1584ULL,
		0x6AFAF7C3CF04569DULL,
		0x48DA18B25A02627AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5081801021804509ULL,
		0x0118890060080009ULL,
		0x40B089126B8A02B2ULL,
		0x91000520250800D2ULL,
		0x0641E49182590218ULL,
		0x009204945D010104ULL,
		0x08A207834C00108DULL,
		0x4890100200024278ULL
	}};
	printf("Test Case 372\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 372 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -372;
	} else {
		printf("Test Case 372 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8FA3566744BC18CCULL,
		0x0FB0AC83213824FAULL,
		0xF478F77E93747571ULL,
		0x2F9959931DE09A73ULL,
		0x1CF6FB3253E57AC0ULL,
		0x4012577F9A60F092ULL,
		0x267B5F1DE7DA716DULL,
		0x29D88F61F2AB7548ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5FC10CE894F240D2ULL,
		0xCD2350966BF34F40ULL,
		0xAD8855966CC7BA29ULL,
		0x8C037C4A9B18E7E4ULL,
		0xEC9FDCF9A2D9020CULL,
		0x155644065B86F503ULL,
		0x876BE5DD8AE7CB64ULL,
		0x1C23D52DC28FB2B6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0F81046004B000C0ULL,
		0x0D20008221300440ULL,
		0xA408551600443021ULL,
		0x0C01580219008260ULL,
		0x0C96D83002C10200ULL,
		0x001244061A00F002ULL,
		0x066B451D82C24164ULL,
		0x08008521C28B3000ULL
	}};
	printf("Test Case 373\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 373 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -373;
	} else {
		printf("Test Case 373 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC15051439F21B6ABULL,
		0xA9AA0FEC71517075ULL,
		0x94305CBD85439290ULL,
		0xCB852C4C209217A8ULL,
		0x3D0E071F1C548266ULL,
		0xE53E61A3577E6CF0ULL,
		0xCF700469AD1C3C1FULL,
		0x2B5B473E45D55708ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x14566E37D6096010ULL,
		0x9FFF91C130BDC063ULL,
		0xAFF40B41042BD172ULL,
		0x31314C45432ABB89ULL,
		0xCEA129BF907CA329ULL,
		0x45A382FEA21BA97AULL,
		0x064B13458840DE09ULL,
		0x361A4AD9516AC286ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0050400396012000ULL,
		0x89AA01C030114061ULL,
		0x8430080104039010ULL,
		0x01010C4400021388ULL,
		0x0C00011F10548220ULL,
		0x452200A2021A2870ULL,
		0x0640004188001C09ULL,
		0x221A421841404200ULL
	}};
	printf("Test Case 374\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 374 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -374;
	} else {
		printf("Test Case 374 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC9D2798B7134165BULL,
		0x2EC002095207E02EULL,
		0xF478E866467C9E19ULL,
		0xEAC5D612F2280BB0ULL,
		0xD2096648441C338BULL,
		0xAE92ED676FDDDD14ULL,
		0x3EC556FAB57EA2D0ULL,
		0xE3915DA178F9A4A1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7E22ED4E2275CFB2ULL,
		0x9D0060DF4A08CB4DULL,
		0x7376197E09E92A30ULL,
		0x9DB52E3E4343E037ULL,
		0xD552CD0176FC2263ULL,
		0x594E824BB3215299ULL,
		0xE8DB4BD8E4B1434FULL,
		0x673B6CCFAF798C78ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4802690A20340612ULL,
		0x0C0000094200C00CULL,
		0x7070086600680A10ULL,
		0x8885061242000030ULL,
		0xD0004400441C2203ULL,
		0x0802804323015010ULL,
		0x28C142D8A4300240ULL,
		0x63114C8128798420ULL
	}};
	printf("Test Case 375\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 375 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -375;
	} else {
		printf("Test Case 375 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0192C2AAADE60C58ULL,
		0x234F1A865561832CULL,
		0xC7A7F94DF02691BEULL,
		0xB20EF1D44C7FEEC7ULL,
		0xB0CCD09D35CE2AC8ULL,
		0xCCF7F0B4671DB1ECULL,
		0x63D33A32CED1B755ULL,
		0xDCA0F11C6417B0AEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7D198F4D2DDF024CULL,
		0x287D453E728A8D1BULL,
		0xD001893A96BE12FAULL,
		0x99DB755B0D1A4B86ULL,
		0x4FCF910E77396031ULL,
		0x6B905C9F4D30A35FULL,
		0x87631DC9613E1495ULL,
		0x0968520BA1B87350ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x011082082DC60048ULL,
		0x204D000650008108ULL,
		0xC0018908902610BAULL,
		0x900A71500C1A4A86ULL,
		0x00CC900C35082000ULL,
		0x489050944510A14CULL,
		0x0343180040101415ULL,
		0x0820500820103000ULL
	}};
	printf("Test Case 376\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 376 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -376;
	} else {
		printf("Test Case 376 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xED238781F51DBAFCULL,
		0xEDD48E4E124DF7EAULL,
		0x7449D1F17F606DE5ULL,
		0xB3CDEB1ED482C3E9ULL,
		0x0501330ABD74309CULL,
		0x9D12E98FCD1FB9D4ULL,
		0xB5C6DC3E3F2E0520ULL,
		0x8411B9CB41AE55A8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5F2E97916ABC2A85ULL,
		0x35228D0A2C714ED0ULL,
		0x0780F68CCBE25151ULL,
		0x02BB86059C40125BULL,
		0x9251CEBD23BFF93AULL,
		0x1812C265220CD266ULL,
		0x7C62268B2759D08FULL,
		0x576A6B16067B89C0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4D228781601C2A84ULL,
		0x25008C0A004146C0ULL,
		0x0400D0804B604141ULL,
		0x0289820494000249ULL,
		0x0001020821343018ULL,
		0x1812C005000C9044ULL,
		0x3442040A27080000ULL,
		0x04002902002A0180ULL
	}};
	printf("Test Case 377\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 377 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -377;
	} else {
		printf("Test Case 377 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9D8B8B5A44CF2D64ULL,
		0x5D7269348AEEC1BDULL,
		0xB4E3008F39E0431AULL,
		0x43A1E0C1F54A2844ULL,
		0x8317FEF2787746AAULL,
		0xB0B771DF448C03ADULL,
		0x3CF2DFCA00D52713ULL,
		0x0C20FE9956954F43ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x73CFC80AE132CF89ULL,
		0xF85EAB8BBFC9D41CULL,
		0xC127E0931CECC28EULL,
		0x6038F44F99123E42ULL,
		0x49A3AB6DD74DD93AULL,
		0xDC41E271671B62B2ULL,
		0x2DBF95C6A82AD02AULL,
		0x6CC1B531E1BC4BDEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x118B880A40020D00ULL,
		0x585229008AC8C01CULL,
		0x8023008318E0420AULL,
		0x4020E04191022840ULL,
		0x0103AA605045402AULL,
		0x90016051440802A0ULL,
		0x2CB295C200000002ULL,
		0x0C00B41140944B42ULL
	}};
	printf("Test Case 378\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 378 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -378;
	} else {
		printf("Test Case 378 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x07BC9388FC87E92EULL,
		0x9C0A3A9477907096ULL,
		0x735A9369398F2678ULL,
		0x03A74C3E0B93541CULL,
		0xDB2B92931C3DC22AULL,
		0x030E54A02F31B313ULL,
		0x74A77835B3119764ULL,
		0x480F18B06DA1A3C0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF63E233E93A04C49ULL,
		0x19300AE4A8805EF9ULL,
		0x9580CEB9F8CF2D40ULL,
		0xA92B668C7407BAAEULL,
		0x7BF3A951089847A6ULL,
		0x0BBE4E1B01F651A5ULL,
		0x2D18B6C69E991DBEULL,
		0x04F219FAE085EF82ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x063C030890804808ULL,
		0x18000A8420805090ULL,
		0x11008229388F2440ULL,
		0x0123440C0003100CULL,
		0x5B23801108184222ULL,
		0x030E440001301101ULL,
		0x2400300492111524ULL,
		0x000218B06081A380ULL
	}};
	printf("Test Case 379\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 379 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -379;
	} else {
		printf("Test Case 379 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x71956439B377A5E9ULL,
		0x749A5221D530A59FULL,
		0x520EDF9D54D7D89CULL,
		0xA9CBA933581AB253ULL,
		0xD11502F494F95F7DULL,
		0x5E202FEE7E0D87F5ULL,
		0x5AB3C5C1951EC07AULL,
		0xB20E887F2F78AC15ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE6237A9B7CB0825DULL,
		0xB244AA2B32E549D2ULL,
		0x0DC55916D3CFA9B4ULL,
		0xCEDBBB040798D5A7ULL,
		0x6E8658047592BD07ULL,
		0x22818A345FCDFCDAULL,
		0x9716044CE2DEA7C2ULL,
		0x9B77C9C314B375E8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6001601930308049ULL,
		0x3000022110200192ULL,
		0x0004591450C78894ULL,
		0x88CBA90000189003ULL,
		0x4004000414901D05ULL,
		0x02000A245E0D84D0ULL,
		0x12120440801E8042ULL,
		0x9206884304302400ULL
	}};
	printf("Test Case 380\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 380 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -380;
	} else {
		printf("Test Case 380 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA3B612A90E45BEFCULL,
		0xBAD4C7E10AAECFF5ULL,
		0x6888BEA3A80E4163ULL,
		0x3FA4F8BB877AD205ULL,
		0x900ACE7C582AA6C9ULL,
		0xF2981C8E996B2CBDULL,
		0x9A465ED01EB933ABULL,
		0x9CDF12FBB8B6CD22ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9215D019C96474F7ULL,
		0x31C01E721AA88839ULL,
		0x7448E44B211725F3ULL,
		0x6A00E844CA5BBB4EULL,
		0x883B9CD447A4C56AULL,
		0x4C0B8ACD43009FE6ULL,
		0xABE63D84481B8366ULL,
		0x252567F2D1447146ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x82141009084434F4ULL,
		0x30C006600AA88831ULL,
		0x6008A40320060163ULL,
		0x2A00E800825A9204ULL,
		0x800A8C5440208448ULL,
		0x4008088C01000CA4ULL,
		0x8A461C8008190322ULL,
		0x040502F290044102ULL
	}};
	printf("Test Case 381\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 381 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -381;
	} else {
		printf("Test Case 381 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBB4ADA33812ACBF6ULL,
		0x8D82C6A061261FF6ULL,
		0x0165AF47CC459105ULL,
		0x0F131D41689CE1D0ULL,
		0xF545428A7A13C53EULL,
		0x099F0F44DD167448ULL,
		0x03FB051D24210D89ULL,
		0x4E3C41807F01367FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB143993F06FD9D39ULL,
		0x62541D6725E981EEULL,
		0x3F20A61D707DA72FULL,
		0xFABDAC83A89D1466ULL,
		0x505B94A41441323CULL,
		0x3AECC4615FA9C259ULL,
		0xEBF62E68F3B4A660ULL,
		0x916AC1A1E056A715ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB142983300288930ULL,
		0x00000420212001E6ULL,
		0x0120A60540458105ULL,
		0x0A110C01289C0040ULL,
		0x504100801001003CULL,
		0x088C04405D004048ULL,
		0x03F2040820200400ULL,
		0x0028418060002615ULL
	}};
	printf("Test Case 382\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 382 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -382;
	} else {
		printf("Test Case 382 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x76E8C47E18050A86ULL,
		0xED3B5ED9550E70EAULL,
		0xEF862F8A8053D263ULL,
		0xC413D064E65ED26EULL,
		0x75A22ECBF248ABAAULL,
		0x5C448D078C9465CAULL,
		0x13CE6F99BCB0290EULL,
		0x055383A66691EAC2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB1B34A6A08BFB0DDULL,
		0x69254E6B9BBC999EULL,
		0xB5B230D2F9121D5AULL,
		0x3B19AE9DB6FFE3A7ULL,
		0x1DF77A39FE8DCA61ULL,
		0x510637B5B9B31E33ULL,
		0x2EDA9FC45D31C767ULL,
		0x25E47DFEEED2D94CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x30A0406A08050084ULL,
		0x69214E49110C108AULL,
		0xA582208280121042ULL,
		0x00118004A65EC226ULL,
		0x15A22A09F2088A20ULL,
		0x5004050588900402ULL,
		0x02CA0F801C300106ULL,
		0x054001A66690C840ULL
	}};
	printf("Test Case 383\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 383 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -383;
	} else {
		printf("Test Case 383 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x06E4E0B9E06B8E4CULL,
		0x53DE0F51BE83FAC4ULL,
		0x9FA10DF0D2C15D81ULL,
		0xD090B04296E89BC1ULL,
		0x5A3EE0204DD57111ULL,
		0x06571D8FA5AA7203ULL,
		0x5FFB50AB63BBE91FULL,
		0x9DB66287F2635B89ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6C65B46AC966411FULL,
		0x09330F5701D1250EULL,
		0xD4A5A69D6E86F65EULL,
		0x772BF30421B8FEDFULL,
		0x290F83A267CADB5EULL,
		0xDC34592AF1D71C24ULL,
		0x2B43FC246F107C3AULL,
		0x60BA9DE5A13E991FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0464A028C062000CULL,
		0x01120F5100812004ULL,
		0x94A1049042805400ULL,
		0x5000B00000A89AC1ULL,
		0x080E802045C05110ULL,
		0x0414190AA1821000ULL,
		0x0B4350206310681AULL,
		0x00B20085A0221909ULL
	}};
	printf("Test Case 384\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 384 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -384;
	} else {
		printf("Test Case 384 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB15A2F4216093C5DULL,
		0xF6211EEB6AA9FAB9ULL,
		0xC821632445557236ULL,
		0x99B322244A5D0BCEULL,
		0x9E28BC0D0CE0DA3BULL,
		0xFFF8776456BFCE1CULL,
		0xA91A767E8AD14C89ULL,
		0x23F84C61954FAFC4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD5CF9D817495A4D6ULL,
		0xE211160E9D97FD8EULL,
		0x13FF1E171DC6391DULL,
		0x76C6FAA38497C5CEULL,
		0xF47F1AF3A8331388ULL,
		0x4EC54FC4D9FAEE0AULL,
		0xD8ADA9CDC65B8B66ULL,
		0x0C27B9B05524E008ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x914A0D0014012454ULL,
		0xE201160A0881F888ULL,
		0x0021020405443014ULL,
		0x10822220001501CEULL,
		0x9428180108201208ULL,
		0x4EC0474450BACE08ULL,
		0x8808204C82510800ULL,
		0x002008201504A000ULL
	}};
	printf("Test Case 385\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 385 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -385;
	} else {
		printf("Test Case 385 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x234DC5FA4B424920ULL,
		0xC544E287E49DFAF5ULL,
		0x1EA5733932D0388AULL,
		0x621A6ABB49606CB9ULL,
		0xA6EA07FA584C9D0AULL,
		0xA192B6E72FCAF031ULL,
		0x75FB0940BEE55E51ULL,
		0x31957FCF89A6AB67ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8F44075C2F3CD0FBULL,
		0x66A044B33ADC25BFULL,
		0x926D71087D51EFEAULL,
		0x72FAA6C1E0BB247AULL,
		0xD71281629711261CULL,
		0x4585EC38B4983F44ULL,
		0xD447283236E03B7FULL,
		0xCEEA1C3BBC2FECA3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x034405580B004020ULL,
		0x44004083209C20B5ULL,
		0x122571083050288AULL,
		0x621A228140202438ULL,
		0x8602016210000408ULL,
		0x0180A42024883000ULL,
		0x5443080036E01A51ULL,
		0x00801C0B8826A823ULL
	}};
	printf("Test Case 386\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 386 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -386;
	} else {
		printf("Test Case 386 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x11EDBA2BB0D5A522ULL,
		0x28A715E71D068D90ULL,
		0x0EF086418AB2C40BULL,
		0x5F829D930ED21F0EULL,
		0x4971E9F485E8FDDAULL,
		0x68EB34577A7931ABULL,
		0x3C4A046509A620C9ULL,
		0xFEDE0549A2E4F6CFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x54262A102A580514ULL,
		0xD4DA0288EE7356DCULL,
		0x98F61934D18D9EEFULL,
		0xDFA444F3CA041F7CULL,
		0x5A3372A9B42FD553ULL,
		0x3B0382FD8C27B420ULL,
		0x9E33627CC44DB690ULL,
		0x50F203B51A004428ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x10242A0020500500ULL,
		0x008200800C020490ULL,
		0x08F000008080840BULL,
		0x5F8004930A001F0CULL,
		0x483160A08428D552ULL,
		0x2803005508213020ULL,
		0x1C02006400042080ULL,
		0x50D2010102004408ULL
	}};
	printf("Test Case 387\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 387 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -387;
	} else {
		printf("Test Case 387 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x26C8DAF6B116DDECULL,
		0xEBE7D161EC14CE1EULL,
		0xBE16F1F34EC0BF9CULL,
		0x0B02710EF6CF1075ULL,
		0xC749B9881F4A1AA7ULL,
		0x17A257CBA2093FEDULL,
		0x4EDABE6455C53F26ULL,
		0x32C193880ECDC884ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA5EA5ECB0807BA1AULL,
		0xCE7C872E9184EA37ULL,
		0x551258745211D129ULL,
		0x8202CC0F6AB1159BULL,
		0xC2F19937DD4F286BULL,
		0xA7939D9FBDFB8E55ULL,
		0xDF6B6DD6C6770636ULL,
		0xE7865C68825369B1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x24C85AC200069808ULL,
		0xCA6481208004CA16ULL,
		0x1412507042009108ULL,
		0x0202400E62811011ULL,
		0xC24199001D4A0823ULL,
		0x0782158BA0090E45ULL,
		0x4E4A2C4444450626ULL,
		0x2280100802414880ULL
	}};
	printf("Test Case 388\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 388 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -388;
	} else {
		printf("Test Case 388 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1952CE76DC7EB6E8ULL,
		0x8112B80DBC6B88CFULL,
		0xDC2229340FD4AA1BULL,
		0xF99154E0E35B1D95ULL,
		0xA7EA381BC453D18EULL,
		0x38199F12C97A4885ULL,
		0x9A67D5D687FD47C5ULL,
		0xD81798A9E5A0A51CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x930BD926975F0687ULL,
		0x5C5F5CC12E373511ULL,
		0xD301927B4D721346ULL,
		0xFACBBFC49AED7FC1ULL,
		0x3D827AF0F9F8F0FEULL,
		0x0A61DD2BAB39BA6AULL,
		0x49E6B6FB80738F3BULL,
		0x25A2F6F28FC3CA5BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1102C826945E0680ULL,
		0x001218012C230001ULL,
		0xD00000300D500202ULL,
		0xF88114C082491D81ULL,
		0x25823810C050D08EULL,
		0x08019D0289380800ULL,
		0x086694D280710701ULL,
		0x000290A085808018ULL
	}};
	printf("Test Case 389\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 389 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -389;
	} else {
		printf("Test Case 389 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBF22CA24EAF9CD90ULL,
		0xE4FBD197DAE71DE0ULL,
		0x1BE15A9DC9015BABULL,
		0xE9000B9EDC9F054BULL,
		0x06E25BCF1E858AD4ULL,
		0xE1645B28AC94CB02ULL,
		0x20F88F5B559AC8BBULL,
		0x1C51B911546137EDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5D23A132C76BF2E8ULL,
		0xC7E43FC9BF432616ULL,
		0xEC5F03C5DF020852ULL,
		0x71606A367A546B62ULL,
		0x07B1162DF32273B5ULL,
		0xF8DC55AA860D0170ULL,
		0x438D7392EDA03BFDULL,
		0x7744880F0C2679AFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1D228020C269C080ULL,
		0xC4E011819A430400ULL,
		0x08410285C9000802ULL,
		0x61000A1658140142ULL,
		0x06A0120D12000294ULL,
		0xE044512884040100ULL,
		0x00880312458008B9ULL,
		0x14408801042031ADULL
	}};
	printf("Test Case 390\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 390 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -390;
	} else {
		printf("Test Case 390 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCA9F4DF16301F11CULL,
		0x652BC3F50FC3D535ULL,
		0xCDA8301F50EE6B4EULL,
		0xB55833AE970DD344ULL,
		0x59A4DB29CE584EBDULL,
		0xBCACF30EC9ECCB57ULL,
		0xC4A912F88A611C03ULL,
		0xC9476259D05391A9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4C25CD5C0E64F5A1ULL,
		0xFEB26B0F29B4AFF9ULL,
		0xE7EBCB0EF2D3295DULL,
		0x934EB092E0267D37ULL,
		0x2FAF93733434145FULL,
		0x5A0685673B69FB81ULL,
		0xA38ACBFBAEAA3221ULL,
		0xDCB81E9DD8B303F3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x48054D500200F100ULL,
		0x6422430509808531ULL,
		0xC5A8000E50C2294CULL,
		0x9148308280045104ULL,
		0x09A493210410041DULL,
		0x180481060968CB01ULL,
		0x808802F88A201001ULL,
		0xC8000219D01301A1ULL
	}};
	printf("Test Case 391\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 391 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -391;
	} else {
		printf("Test Case 391 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x448D709E6DB47E67ULL,
		0xEC624CCFD829AF9AULL,
		0x2FA40D2BF0F69326ULL,
		0x8468DD7BC44C6A88ULL,
		0xC4B64DDEFBACB6A7ULL,
		0x9D7799F0C34A4ECAULL,
		0x06CD09B4376548E9ULL,
		0x2E72ECD966B1A03DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDEE48674C13A9771ULL,
		0x090EFA6686534B7CULL,
		0xDB8A1705A6C9FC70ULL,
		0x83A5509013476B68ULL,
		0x744047372CF09B5AULL,
		0x8F203AC1959C4841ULL,
		0xCD4D375689257B6DULL,
		0x7FC3EE772E5470ABULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4484001441301661ULL,
		0x0802484680010B18ULL,
		0x0B800501A0C09020ULL,
		0x8020501000446A08ULL,
		0x4400451628A09202ULL,
		0x8D2018C081084840ULL,
		0x044D011401254869ULL,
		0x2E42EC5126102029ULL
	}};
	printf("Test Case 392\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 392 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -392;
	} else {
		printf("Test Case 392 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x53702643474B47B8ULL,
		0x791A0473B7CC866CULL,
		0x5D61FC9B30A6C37AULL,
		0x175D5D7D4700E87AULL,
		0xFDFC9DA676B03A1AULL,
		0xAEA0011F877D078BULL,
		0x71AFD6ABE3B6D56EULL,
		0xA79A3D3641BD9BF7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC49BF331BF1E6EB2ULL,
		0xCB0D4017612ECDEBULL,
		0xD82673C714F58461ULL,
		0x8A07EC4628D60471ULL,
		0xDA58AADC7FF28E08ULL,
		0x2F9357900BCEADFAULL,
		0xDA77BA81E4180E73ULL,
		0xC51F1C805615E361ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x40102201070A46B0ULL,
		0x49080013210C8468ULL,
		0x5820708310A48060ULL,
		0x02054C4400000070ULL,
		0xD858888476B00A08ULL,
		0x2E800110034C058AULL,
		0x50279281E0100462ULL,
		0x851A1C0040158361ULL
	}};
	printf("Test Case 393\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 393 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -393;
	} else {
		printf("Test Case 393 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x01D5E1B270B67C1FULL,
		0x6F7466F6636F348CULL,
		0x5F69B86A0E228086ULL,
		0x4F762E28DBA07C2BULL,
		0x1EDD73BA2CFF2609ULL,
		0xB7717E79F719CEB7ULL,
		0xC94943093A2EBCC1ULL,
		0x0DECF419B0BC8164ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x873E0C2E64546A5DULL,
		0x55A2E9E009907006ULL,
		0xBE2315D539B1D280ULL,
		0x972D6A48BFE2E6D7ULL,
		0x1E2D048E820D5326ULL,
		0x4D53ED0B003D00B4ULL,
		0x3A14412310846928ULL,
		0x371E0013405D8A81ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x011400226014681DULL,
		0x452060E001003004ULL,
		0x1E21104008208080ULL,
		0x07242A089BA06403ULL,
		0x1E0D008A000D0200ULL,
		0x05516C09001900B4ULL,
		0x0800410110042800ULL,
		0x050C0011001C8000ULL
	}};
	printf("Test Case 394\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 394 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -394;
	} else {
		printf("Test Case 394 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA9C080B69D7CFF05ULL,
		0xE7A84CE6390F7FC5ULL,
		0xE7FBF81F46045D9DULL,
		0x6C1E088C8B633929ULL,
		0xBE51893A6B8758B4ULL,
		0x7C508790CB96DA6EULL,
		0x5DE4BA45C0C5791CULL,
		0x38A65FAE62204522ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x84CFE977B945062DULL,
		0x324C7ADAFCFB1C6CULL,
		0x7EAA8E5900BABACDULL,
		0xD88D79DAE99495BFULL,
		0x9445D6F3E8A0F586ULL,
		0x4AB002EDAA7EB2DDULL,
		0xCAA5DADE37E90492ULL,
		0x99D92CC999FEFC1EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x80C0803699440605ULL,
		0x220848C2380B1C44ULL,
		0x66AA88190000188DULL,
		0x480C088889001129ULL,
		0x9441803268805084ULL,
		0x481002808A16924CULL,
		0x48A49A4400C10010ULL,
		0x18800C8800204402ULL
	}};
	printf("Test Case 395\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 395 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -395;
	} else {
		printf("Test Case 395 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8A9A6F1F1A086102ULL,
		0x0A2B38DEAD255459ULL,
		0x3144BFE421AB871CULL,
		0x2AA89532EA7E6200ULL,
		0x732890098BD735BEULL,
		0xED3AE9396B82BAD0ULL,
		0x9366EB5483525E34ULL,
		0x0F3FEAE832A181D4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x08AA1BA200EBE818ULL,
		0xA3EA1FF450818CD1ULL,
		0x47EE4443347D0E4AULL,
		0xB9EA71C0073F25E6ULL,
		0xD2337936D2C91BACULL,
		0x01120638460F3219ULL,
		0xA01ECA8241806C97ULL,
		0x7F6DA06928B5DD70ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x088A0B0200086000ULL,
		0x022A18D400010451ULL,
		0x0144044020290608ULL,
		0x28A81100023E2000ULL,
		0x5220100082C111ACULL,
		0x0112003842023210ULL,
		0x8006CA0001004C14ULL,
		0x0F2DA06820A18150ULL
	}};
	printf("Test Case 396\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 396 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -396;
	} else {
		printf("Test Case 396 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE0DA027B6E95EB8AULL,
		0x0E27587AB7D382CFULL,
		0x279F48DB0DD3C42EULL,
		0x7F4BDB9370663F25ULL,
		0x79158D52267C5DE7ULL,
		0x5D90D7B40136BEAAULL,
		0x374E3C5B95352733ULL,
		0x5FBDB49060E5A067ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0478C6A1DA0CBEB3ULL,
		0x34C9B031327A95AFULL,
		0xC9B4A1E9EEB556CCULL,
		0xB1C6B278C58B3A4FULL,
		0x36F485C4FF3BC5C7ULL,
		0x32964C8203D5A4E2ULL,
		0xE52C8D4B430552FBULL,
		0x7BA834DDED4DBF0FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x005802214A04AA82ULL,
		0x040110303252808FULL,
		0x019400C90C91440CULL,
		0x3142921040023A05ULL,
		0x30148540263845C7ULL,
		0x109044800114A4A2ULL,
		0x250C0C4B01050233ULL,
		0x5BA834906045A007ULL
	}};
	printf("Test Case 397\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 397 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -397;
	} else {
		printf("Test Case 397 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDB1E1D5F1869461EULL,
		0xE4F52A32A9FE906FULL,
		0xFE1E3188985750E7ULL,
		0x2A5A9BD7C61DAD58ULL,
		0xAB80E994C6CA8F05ULL,
		0xBF68F2A8335080DCULL,
		0xD006B8B5A266F784ULL,
		0x9C5C0602E969C476ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x605202D976919BCCULL,
		0x9B7D602A34B5366EULL,
		0x1D4EE0F21747D19BULL,
		0x777B56AC4B012081ULL,
		0x5D6E4E83F555FC84ULL,
		0xD0A698ABB7967E1CULL,
		0x15AB0465EB6955CCULL,
		0x92DFD4655278DBA8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x401200591001020CULL,
		0x8075202220B4106EULL,
		0x1C0E208010475083ULL,
		0x225A128442012000ULL,
		0x09004880C4408C04ULL,
		0x902090A83310001CULL,
		0x10020025A2605584ULL,
		0x905C04004068C020ULL
	}};
	printf("Test Case 398\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 398 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -398;
	} else {
		printf("Test Case 398 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0DCF1880F6AC08E3ULL,
		0xE80FAA7006120663ULL,
		0x58EB15BD96CCB0EBULL,
		0xEC050393371CEDF3ULL,
		0x381B0971854B604FULL,
		0x8079E4178B18C5DDULL,
		0x5658C89F2B2048FBULL,
		0xDE71FB362E625D9FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1065E121518F6003ULL,
		0xD8CB3F99A3F489FBULL,
		0x907CFCD4BC8B6BA9ULL,
		0x536899B0E3537111ULL,
		0x9EB14CE76824ACF6ULL,
		0x224D52625361B45BULL,
		0x5FFFACB55A2F0913ULL,
		0x5C437CCC7A25BDB7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x00450000508C0003ULL,
		0xC80B2A1002100063ULL,
		0x10681494948820A9ULL,
		0x4000019023106111ULL,
		0x1811086100002046ULL,
		0x0049400203008459ULL,
		0x565888950A200813ULL,
		0x5C4178042A201D97ULL
	}};
	printf("Test Case 399\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 399 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -399;
	} else {
		printf("Test Case 399 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5D6EB610720F0886ULL,
		0xECC0077026BD97F5ULL,
		0x56BF3119234E7BF6ULL,
		0x36087F69A7360E68ULL,
		0x3B5BBFF1C99BB137ULL,
		0xC1F7F078EA9F530EULL,
		0x711A6639CAD7C0E8ULL,
		0xEF38A4F28CECBB83ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC7825C1E186015B3ULL,
		0xE51CC0CB98CF1349ULL,
		0xAFD806322EDF9BA0ULL,
		0xAC20E2F5E5A36495ULL,
		0x698088977C43E728ULL,
		0x0228FF753A4BD841ULL,
		0xD1EB5E7D2B664FBAULL,
		0xD6CB0810C14587C3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4502141010000082ULL,
		0xE4000040008D1341ULL,
		0x06980010224E1BA0ULL,
		0x24006261A5220400ULL,
		0x290088914803A120ULL,
		0x0020F0702A0B5000ULL,
		0x510A46390A4640A8ULL,
		0xC608001080448383ULL
	}};
	printf("Test Case 400\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 400 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -400;
	} else {
		printf("Test Case 400 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF4905D00E1EFBE60ULL,
		0x9CC2BC597520EC47ULL,
		0xD44B7CE0E74805B0ULL,
		0x2AA8E325E2E2D8B8ULL,
		0xA7DCB86E4DA25735ULL,
		0xA25A9510AF275E52ULL,
		0xBCFE9B0531B30E9FULL,
		0x5434BF99D60A08F3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x70C2FF64FCE3F91AULL,
		0x23C47AFAD13A1485ULL,
		0x67169ED5FCE380D6ULL,
		0x227E552EFB179906ULL,
		0x5B774A7D31F7DD0DULL,
		0x003DF1AAB7308C1EULL,
		0xFD4533BC4DA71F14ULL,
		0x2D3E5CCCC09313F5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x70805D00E0E3B800ULL,
		0x00C0385851200405ULL,
		0x44021CC0E4400090ULL,
		0x22284124E2029800ULL,
		0x0354086C01A25505ULL,
		0x00189100A7200C12ULL,
		0xBC44130401A30E14ULL,
		0x04341C88C00200F1ULL
	}};
	printf("Test Case 401\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 401 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -401;
	} else {
		printf("Test Case 401 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2D29A5DFD344D800ULL,
		0xD96C7F996F48687FULL,
		0xE953E4B27BC860D7ULL,
		0xCBB2792FD8DF832DULL,
		0xC0E38DD04D0A3E7AULL,
		0xFBC1E5EA12B19383ULL,
		0xCD17D44E749861CBULL,
		0x263B1269FDAE5C9BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x20172F3BA50C4CD4ULL,
		0xBF81C367E2CE9E3FULL,
		0xB84A24FC814B0FAAULL,
		0xB62545BFA6FDF746ULL,
		0xA1AFBD06FC9BFFC4ULL,
		0x70B8D81122C00FC2ULL,
		0xAD4F1322BC70B1CBULL,
		0x1CF53EE5C0C5DD89ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2001251B81044800ULL,
		0x990043016248083FULL,
		0xA84224B001480082ULL,
		0x8220412F80DD8304ULL,
		0x80A38D004C0A3E40ULL,
		0x7080C00002800382ULL,
		0x8D071002341021CBULL,
		0x04311261C0845C89ULL
	}};
	printf("Test Case 402\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 402 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -402;
	} else {
		printf("Test Case 402 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB416D49C4EAD495FULL,
		0x094431DE3C13A72AULL,
		0x77EC81E762BC3649ULL,
		0x8132F012284C01E3ULL,
		0x4DE53340DD246B5EULL,
		0x0EB801798D090569ULL,
		0x0967EF15023E0FBCULL,
		0x9B1543C75E2E2B36ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x51512A9A83B30AA8ULL,
		0x3A12EB377EB44790ULL,
		0xB11C020233E35135ULL,
		0x2B1974E885C34DCDULL,
		0xEF604A0560203F27ULL,
		0x8380AB466B07CFF6ULL,
		0xD1BAC03CD54BAE02ULL,
		0xF87DFF82DBB6BFADULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1010009802A10808ULL,
		0x080021163C100700ULL,
		0x310C000222A01001ULL,
		0x01107000004001C1ULL,
		0x4D60020040202B06ULL,
		0x0280014009010560ULL,
		0x0122C014000A0E00ULL,
		0x981543825A262B24ULL
	}};
	printf("Test Case 403\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 403 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -403;
	} else {
		printf("Test Case 403 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2386C4C8D8CDAA86ULL,
		0xC6963FFC1D2A5AB5ULL,
		0x2B13D2E7C30A7B1CULL,
		0xEFBFB4E3737181C8ULL,
		0xDF19B09235050584ULL,
		0x0A0ECDCD4B12C856ULL,
		0xF2058ECE7A394BE3ULL,
		0x56C10BA8160DD776ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x334AB50CE5F99935ULL,
		0xDFEE76BA3C62905FULL,
		0x52D5A02195790377ULL,
		0x3530B92535982241ULL,
		0x349572580D7C4991ULL,
		0xC8CB872CA4C362BDULL,
		0x0DBD67F3CC704C30ULL,
		0xF59E2A2D4C88A1C3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x23028408C0C98804ULL,
		0xC68636B81C221015ULL,
		0x0211802181080314ULL,
		0x2530B02131100040ULL,
		0x1411301005040180ULL,
		0x080A850C00024014ULL,
		0x000506C248304820ULL,
		0x54800A2804088142ULL
	}};
	printf("Test Case 404\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 404 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -404;
	} else {
		printf("Test Case 404 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD4CB9192B38AA552ULL,
		0xC70977F052DA8944ULL,
		0xE9656AFC63C45354ULL,
		0xF7F5B6CDCEF5C2F2ULL,
		0xA35FC5322490EDDDULL,
		0x5EEE9D3D3DA8D818ULL,
		0x507547BCF9854B66ULL,
		0x06F65A11D862EF3FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x48FCAC331E1DD0AEULL,
		0x0A2B463443B32D92ULL,
		0xC1372C3E98BB77E2ULL,
		0xB4C00DFFCD62B4BAULL,
		0x2D3E142FDDB1D7EDULL,
		0x1E0F06A6CEEFE201ULL,
		0x6C3198BB4CC1183EULL,
		0x765787505E9BBF38ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x40C8801212088002ULL,
		0x0209463042920900ULL,
		0xC125283C00805340ULL,
		0xB4C004CDCC6080B2ULL,
		0x211E04220490C5CDULL,
		0x1E0E04240CA8C000ULL,
		0x403100B848810826ULL,
		0x065602105802AF38ULL
	}};
	printf("Test Case 405\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 405 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -405;
	} else {
		printf("Test Case 405 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB41CB7B524B7CE6DULL,
		0x1341E447D5C18FEFULL,
		0x035F4953CD1213F7ULL,
		0xDCEF82C6BF120A01ULL,
		0x2310F941912C8156ULL,
		0xE2C5A6463FE9BD84ULL,
		0xCB1089429C751372ULL,
		0x7FAA29DB08AE91A2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x04F0D35ACC802501ULL,
		0x5A0F187075D92FBBULL,
		0x9CFC71AD40873FEEULL,
		0x93E2F36ABAFC5EEDULL,
		0x9FE741AF325194C2ULL,
		0x09D058920919F413ULL,
		0x8C64F12101D4C60CULL,
		0x96EE882B2242A7D7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0410931004800401ULL,
		0x1201004055C10FABULL,
		0x005C4101400213E6ULL,
		0x90E28242BA100A01ULL,
		0x0300410110008042ULL,
		0x00C000020909B400ULL,
		0x8800810000540200ULL,
		0x16AA080B00028182ULL
	}};
	printf("Test Case 406\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 406 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -406;
	} else {
		printf("Test Case 406 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA88E6FBD187AC698ULL,
		0x85DAC1359FDB3A75ULL,
		0x0C0F03AED4183EC0ULL,
		0x54705B5C7F465E9CULL,
		0x7F0A4EFA9BB84C43ULL,
		0xF262E9816F3E827AULL,
		0xDE28823E6671A30AULL,
		0x7ACCDC7A70B142E4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF8156DB9F0D0ABA0ULL,
		0xE12B74F71FD2DC4DULL,
		0x3FC408A17CE1D534ULL,
		0xE6720F38BDE34BDAULL,
		0xA1695299141AF86FULL,
		0x3E61820249AE0F0EULL,
		0xE5DDB2B615AC60BCULL,
		0xE69B84082966763AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA8046DB910508280ULL,
		0x810A40351FD21845ULL,
		0x0C0400A054001400ULL,
		0x44700B183D424A98ULL,
		0x2108429810184843ULL,
		0x32608000492E020AULL,
		0xC408823604202008ULL,
		0x6288840820204220ULL
	}};
	printf("Test Case 407\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 407 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -407;
	} else {
		printf("Test Case 407 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2D671B290135C89BULL,
		0x6BFE37720666BF6AULL,
		0xA127331D1518DAB3ULL,
		0xFC69C0E42B8F3344ULL,
		0x01E7582C5971CBABULL,
		0x7CE65D38000ADA39ULL,
		0xB71A40C648FA2FA1ULL,
		0x8EDEE9363D29C048ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD22D5A1973ADC440ULL,
		0x66CD27AF9E0FF173ULL,
		0x124FC63926C33DB3ULL,
		0x45067A62D22FD2C2ULL,
		0x095C8C39E4D43BDCULL,
		0x82C29B14DC57E72EULL,
		0x34502AB5B0A5F8EEULL,
		0x89133ED8B3AD2318ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x00251A090125C000ULL,
		0x62CC27220606B162ULL,
		0x00070219040018B3ULL,
		0x44004060020F1240ULL,
		0x0144082840500B88ULL,
		0x00C219100002C228ULL,
		0x3410008400A028A0ULL,
		0x8812281031290008ULL
	}};
	printf("Test Case 408\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 408 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -408;
	} else {
		printf("Test Case 408 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCA3FAB10D34BBFCDULL,
		0x98AE1B3E856173F9ULL,
		0x8F68A04A59E56771ULL,
		0x2EA9E786E47B38AEULL,
		0x65C5987065A14C0FULL,
		0x48575437B9D4C6AFULL,
		0x6B8A31D8A9C0E559ULL,
		0x14021EB3C5D6F122ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5DD440200B983B52ULL,
		0x59614AB3CCD4D4C6ULL,
		0xCA0814385E737299ULL,
		0x26369D8F84EB759BULL,
		0x95417733CE63FCC4ULL,
		0xC2561E90A7930C2AULL,
		0x36425391C9EA9DE5ULL,
		0x47A6F76E9B3CC9FBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4814000003083B40ULL,
		0x18200A32844050C0ULL,
		0x8A08000858616211ULL,
		0x26208586846B308AULL,
		0x0541103044214C04ULL,
		0x40561410A190042AULL,
		0x2202119089C08541ULL,
		0x040216228114C122ULL
	}};
	printf("Test Case 409\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 409 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -409;
	} else {
		printf("Test Case 409 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCC08FE90803ADFC2ULL,
		0x9CDA068B6B012800ULL,
		0x08D31868BA58AAAFULL,
		0x27AA7DF28A3AE6FFULL,
		0xB82EA9424E145439ULL,
		0x39D15769006BA0CAULL,
		0xC7F1030425B831E6ULL,
		0x55B99BB3D9470BE9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBDC93CA4E060EA36ULL,
		0xB1DC918053C04424ULL,
		0xB8638CA6630F8FBEULL,
		0x8412FFD5121F0701ULL,
		0x4E0E4AA89B6BEB76ULL,
		0x2976B6FF676420A5ULL,
		0x143C9AEF03DF410AULL,
		0x26DA30B39B24D022ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8C083C808020CA02ULL,
		0x90D8008043000000ULL,
		0x0843082022088AAEULL,
		0x04027DD0021A0601ULL,
		0x080E08000A004030ULL,
		0x2950166900602080ULL,
		0x0430020401980102ULL,
		0x049810B399040020ULL
	}};
	printf("Test Case 410\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 410 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -410;
	} else {
		printf("Test Case 410 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4EEE7878EF8F15DBULL,
		0xF69BA6EE43D4F3F9ULL,
		0x9DE4159980F6286EULL,
		0x4BC9D44C16817199ULL,
		0x49A101116B5A2AB9ULL,
		0xA82DBB8285F24B4AULL,
		0x96A6301409E745A8ULL,
		0xB4BB0A46E1A37A76ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x490F687E7A76514CULL,
		0x1CE341772E9AAEDCULL,
		0x2D32FD0687777EABULL,
		0x1D1BA100A06FFA63ULL,
		0x9EA33383CCEF705FULL,
		0x8D4D524CF6005FFFULL,
		0x940A234E9B37293AULL,
		0xFD87AB5BBF5B982AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x480E68786A061148ULL,
		0x148300660290A2D8ULL,
		0x0D2015008076282AULL,
		0x0909800000017001ULL,
		0x08A10101484A2019ULL,
		0x880D120084004B4AULL,
		0x9402200409270128ULL,
		0xB4830A42A1031822ULL
	}};
	printf("Test Case 411\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 411 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -411;
	} else {
		printf("Test Case 411 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE79CD33BBA5996E5ULL,
		0x9CA634F8EBBA78F6ULL,
		0xA6C74FDF4DE7FEEAULL,
		0x574ADA8DEA482D95ULL,
		0x02FF5BAAEC99BA19ULL,
		0x2A86DE83167FE26BULL,
		0x05DDA61AD6E87B1DULL,
		0xEB6729226541FF9CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAEC3E2988A3FB8E8ULL,
		0x3CA8CB6A3FEC740DULL,
		0x8E7D0EBC131E1FEAULL,
		0xE109C29C6C780E3CULL,
		0xA146FCD0055A8D40ULL,
		0xFA273D400068ED07ULL,
		0x9B2F56BD9B63ECD8ULL,
		0x5654962829E1E07CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA680C2188A1990E0ULL,
		0x1CA000682BA87004ULL,
		0x86450E9C01061EEAULL,
		0x4108C28C68480C14ULL,
		0x0046588004188800ULL,
		0x2A061C000068E003ULL,
		0x010D061892606818ULL,
		0x424400202141E01CULL
	}};
	printf("Test Case 412\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 412 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -412;
	} else {
		printf("Test Case 412 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF31343C3E406AB34ULL,
		0x6E779C3AEA63F97EULL,
		0x1929AAF7CA712E00ULL,
		0x1C7E1256E006FB7CULL,
		0xBFD8E8BE76110AA5ULL,
		0x7DA209C62E2ED805ULL,
		0x2B75AF98198434EAULL,
		0x79F2168A8C36AF90ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD359D1FD8434EEE1ULL,
		0x2A701CBA9FC592DCULL,
		0x6FECC9DEFACD8244ULL,
		0xE837CED91B1B4B8FULL,
		0x8BCB02111F93CA30ULL,
		0x6BA6CB1A06F4E3F4ULL,
		0xF23DECBFDC079D3AULL,
		0xEB79404A12C1A82EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD31141C18404AA20ULL,
		0x2A701C3A8A41905CULL,
		0x092888D6CA410200ULL,
		0x0836025000024B0CULL,
		0x8BC8001016110A20ULL,
		0x69A209020624C004ULL,
		0x2235AC981804142AULL,
		0x6970000A0000A800ULL
	}};
	printf("Test Case 413\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 413 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -413;
	} else {
		printf("Test Case 413 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x76DA934085C668B0ULL,
		0x4CA904DAB6B5DE79ULL,
		0x9C56E2883700E030ULL,
		0xBA27D5DD12A9D6A1ULL,
		0x693CD79F9A971383ULL,
		0x6EF827D70CA152CEULL,
		0x77D8B9C1C4632E73ULL,
		0x27B1CBD7915A82A5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFB486C10B504295FULL,
		0xFE525E47F409844DULL,
		0x71CD16720DE73D3CULL,
		0x6838912123CC0D4BULL,
		0x6B6DDFB5ABBDD768ULL,
		0x6DECFE8DE5DEB7D8ULL,
		0x5CDC4C07F6BC5CF2ULL,
		0xDC01DBE901C3E4E9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7248000085042810ULL,
		0x4C000442B4018449ULL,
		0x1044020005002030ULL,
		0x2820910102880401ULL,
		0x692CD7958A951300ULL,
		0x6CE82685048012C8ULL,
		0x54D80801C4200C72ULL,
		0x0401CBC1014280A1ULL
	}};
	printf("Test Case 414\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 414 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -414;
	} else {
		printf("Test Case 414 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x19406A53AD0955A1ULL,
		0x2C3D5321FBBD8825ULL,
		0xC1F2ADE22AFE0EF6ULL,
		0x470BC060161906FEULL,
		0x625A7D909E4DBDB6ULL,
		0xBE872EE2ADB639BAULL,
		0x38C8543074D28C9AULL,
		0xD1418F46B265E607ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2D32EA8FAE7EF94AULL,
		0x76008A59B6D3BA56ULL,
		0x78C7E14EDB159984ULL,
		0x99F8E918018F15B3ULL,
		0xAF4A91838E0E62C1ULL,
		0xCA48E24295E1CFE9ULL,
		0x93BFBA233574A5B5ULL,
		0x7D2A371C79B6389AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x09006A03AC085100ULL,
		0x24000201B2918804ULL,
		0x40C2A1420A140884ULL,
		0x0108C000000904B2ULL,
		0x224A11808E0C2080ULL,
		0x8A00224285A009A8ULL,
		0x1088102034508490ULL,
		0x5100070430242002ULL
	}};
	printf("Test Case 415\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 415 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -415;
	} else {
		printf("Test Case 415 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7A7C141D84BF6A4AULL,
		0x706063ED1FB8943CULL,
		0xB0F911821964D91AULL,
		0x88CE81340A22A989ULL,
		0x011721F1469F586AULL,
		0xBC898CB7E7ADCBF9ULL,
		0x2F34A8B07E53EE97ULL,
		0x787CD5A8A5280978ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD85E9854B5EBFF6FULL,
		0xDC1A6CD6C3700F1FULL,
		0x32F56299B88E94E8ULL,
		0xFBC6B881EC64B592ULL,
		0xEE2CFCD0E96065E0ULL,
		0x48BC41CCF8652B3AULL,
		0x468EFDC2E2561232ULL,
		0x985514DB75624A6BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x585C101484AB6A4AULL,
		0x500060C40330041CULL,
		0x30F1008018049008ULL,
		0x88C680000820A180ULL,
		0x000420D040004060ULL,
		0x08880084E0250B38ULL,
		0x0604A88062520212ULL,
		0x1854148825200868ULL
	}};
	printf("Test Case 416\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 416 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -416;
	} else {
		printf("Test Case 416 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4D2809EFB9B48B3AULL,
		0x856210641A2F8B04ULL,
		0x2D57D543A554194CULL,
		0xD9676F24691C81F7ULL,
		0x54A526933400BA69ULL,
		0xBFCAC5D313BFAC6DULL,
		0x907F86A84798CCAFULL,
		0x510258830F526212ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x57167175D3C077C4ULL,
		0xBBA77B3E959243FEULL,
		0x51164A7781151554ULL,
		0x09ADC78DDC41B207ULL,
		0x1F9D42659196BA61ULL,
		0x55680771F2D8D05EULL,
		0x5DEBD810F6920FD5ULL,
		0x77B78724DA4DFFFBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4500016591800300ULL,
		0x8122102410020304ULL,
		0x0116404381141144ULL,
		0x0925470448008007ULL,
		0x148502011000BA61ULL,
		0x154805511298804CULL,
		0x106B800046900C85ULL,
		0x510200000A406212ULL
	}};
	printf("Test Case 417\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 417 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -417;
	} else {
		printf("Test Case 417 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA72C32412ABE8969ULL,
		0x904B25C60ECE51C5ULL,
		0x1ADB9993C346B5CBULL,
		0x3BD76747E6F85BCFULL,
		0x23FE097AB26A93DFULL,
		0xB3B9EE8A7B40AEAFULL,
		0x0BB942C39A3A01F9ULL,
		0x52B919DBF68660C1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD8432E3D38AFCAAFULL,
		0xF5A3B95CF3DF3A2FULL,
		0x2A29D2EABD044036ULL,
		0xE05FA2AF729FE221ULL,
		0x661009F86575C425ULL,
		0xB3ACB71F9A0F4281ULL,
		0xE7F851426B3AD568ULL,
		0xE06095DF4EA87929ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8000220128AE8829ULL,
		0x9003214402CE1005ULL,
		0x0A09908281040002ULL,
		0x2057220762984201ULL,
		0x2210097820608005ULL,
		0xB3A8A60A1A000281ULL,
		0x03B840420A3A0168ULL,
		0x402011DB46806001ULL
	}};
	printf("Test Case 418\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 418 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -418;
	} else {
		printf("Test Case 418 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x295F79E1CE935E3DULL,
		0xA7EC330D7500456FULL,
		0x63A0AF52B6F0BBC5ULL,
		0x2BB0A1C0C9703FB8ULL,
		0xB12F3E845DDDB47CULL,
		0x3630677F9A5A58F1ULL,
		0x43086B2918E2D008ULL,
		0x54E12594CC97F2A0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC3EED8D3DD9AB06EULL,
		0x7019D6B34A050F5AULL,
		0x53DE359320FEAB85ULL,
		0x61F063F0E0D4DDC0ULL,
		0xCE120F7B29219638ULL,
		0xA09C685FC0530B88ULL,
		0xF997666DC90CE63DULL,
		0x48AC4C77D303E0DEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x014E58C1CC92102CULL,
		0x200812014000054AULL,
		0x4380251220F0AB85ULL,
		0x21B021C0C0501D80ULL,
		0x80020E0009019438ULL,
		0x2010605F80520880ULL,
		0x410062290800C008ULL,
		0x40A00414C003E080ULL
	}};
	printf("Test Case 419\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 419 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -419;
	} else {
		printf("Test Case 419 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xABD5D385D8090D0BULL,
		0x609C67D98DD1BD0FULL,
		0x8892C735F953F3F8ULL,
		0x3AEEE23B6EEF70EBULL,
		0x9960CFC5B7A4D5EFULL,
		0xCC627E4803AAE2D5ULL,
		0xE7D0553322718E5EULL,
		0x3987DB2743A2255EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF3587C45CB2CAE9CULL,
		0xE4D2F06931BEE424ULL,
		0x1C931740FC05D71AULL,
		0xF90E4093EFE0CD90ULL,
		0xE4748A59649912C6ULL,
		0x9FA677842A5E1449ULL,
		0x886FA2AA77CFBEC4ULL,
		0x5A118267DBA39751ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA3505005C8080C08ULL,
		0x609060490190A404ULL,
		0x08920700F801D318ULL,
		0x380E40136EE04080ULL,
		0x80608A41248010C6ULL,
		0x8C227600020A0041ULL,
		0x8040002222418E44ULL,
		0x1801822743A20550ULL
	}};
	printf("Test Case 420\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 420 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -420;
	} else {
		printf("Test Case 420 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE9B49656127E254CULL,
		0xA5F3138334DB6E67ULL,
		0x3AF67E48A6F5A0C3ULL,
		0x7ED893B7A9205F20ULL,
		0x01F22357DBD8A072ULL,
		0x71D3922C55205F8EULL,
		0xDE44A3DF18BD54C9ULL,
		0xBBD753B65D9F400FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x63581BFAC6D492C1ULL,
		0xFD74F8588BFA61EDULL,
		0x5815E40EA8BD7B57ULL,
		0xFB7B8F4E48E6D382ULL,
		0x71726EFACFB94A52ULL,
		0x6D5514ADF1A61E4BULL,
		0xC63A27908B99A184ULL,
		0xC94F24057F85FB6DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6110125202540040ULL,
		0xA570100000DA6065ULL,
		0x18146408A0B52043ULL,
		0x7A58830608205300ULL,
		0x01722252CB980052ULL,
		0x6151102C51201E0AULL,
		0xC600239008990080ULL,
		0x894700045D85400DULL
	}};
	printf("Test Case 421\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 421 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -421;
	} else {
		printf("Test Case 421 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3A3D9850E412BC2BULL,
		0x318D4C35F40DF320ULL,
		0xB1DD6981B309A97FULL,
		0x66E41048D5E70185ULL,
		0x85AAA8628103DB61ULL,
		0xC932F2C2D6A57E9DULL,
		0x8E4D7ED11AFC1688ULL,
		0x5FA3163C2B5C3631ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1818C44631C2BBB7ULL,
		0x4F53EFF2C11D061FULL,
		0x765C26C485E38BB5ULL,
		0xE1C89CF82B64E0AFULL,
		0x34C4767D462152ABULL,
		0x29C7206A86C1FA7DULL,
		0x59CE3AB54A420F67ULL,
		0x4FB9EA6DBA920C75ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x181880402002B823ULL,
		0x01014C30C00D0200ULL,
		0x305C208081018935ULL,
		0x60C0104801640085ULL,
		0x0480206000015221ULL,
		0x0902204286817A1DULL,
		0x084C3A910A400600ULL,
		0x4FA1022C2A100431ULL
	}};
	printf("Test Case 422\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 422 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -422;
	} else {
		printf("Test Case 422 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x55E332D107FBE49CULL,
		0xA3F59C3E8CFF3570ULL,
		0xC5EE19B760E934DAULL,
		0xF8BA4E7301281C61ULL,
		0xF2DBC5A54CEB9661ULL,
		0x9394F480BE5DA0C3ULL,
		0x5C4324EB7B3651D0ULL,
		0x56322795CE35E0DFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFDD5B931ED5DD67EULL,
		0x7C899D5890A1DCF3ULL,
		0x4BEFA6B2D8355C9FULL,
		0x80B0DA8C32F904A1ULL,
		0x882BE548B55CD5D9ULL,
		0x91E27D7F7BA57BF7ULL,
		0xBA7ECF866BC0E005ULL,
		0x87DAEBB477D2C51BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x55C130110559C41CULL,
		0x20819C1880A11470ULL,
		0x41EE00B24021149AULL,
		0x80B04A0000280421ULL,
		0x800BC50004489441ULL,
		0x918074003A0520C3ULL,
		0x184204826B004000ULL,
		0x061223944610C01BULL
	}};
	printf("Test Case 423\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 423 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -423;
	} else {
		printf("Test Case 423 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6E37A7944363009FULL,
		0x2A181485DC225526ULL,
		0x29B0F9B0AD5FCEB8ULL,
		0x861ED030A455AF14ULL,
		0x4BCE6DC500121CECULL,
		0x3A2BCF75BC703C27ULL,
		0x63F3F14EA4C1588DULL,
		0x6DC3EEE1E9CD8B77ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x357E8BA9B6827547ULL,
		0xD0191BA060DAFB6CULL,
		0xD489DADF0C0A13E9ULL,
		0x16415EBD3073D053ULL,
		0x3AE9BC94302AFD8AULL,
		0x6C828B2E5E9663C9ULL,
		0x01953C97BC005E5BULL,
		0x352369A45D2794FDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2436838002020007ULL,
		0x0018108040025124ULL,
		0x0080D8900C0A02A8ULL,
		0x0600503020518010ULL,
		0x0AC82C8400021C88ULL,
		0x28028B241C102001ULL,
		0x01913006A4005809ULL,
		0x250368A049058075ULL
	}};
	printf("Test Case 424\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 424 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -424;
	} else {
		printf("Test Case 424 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x63CCC7ED60BE8943ULL,
		0xF5DDB21ECFD8F3A9ULL,
		0x06AF68ACC9619B2BULL,
		0xA18E5D79F5D5E84FULL,
		0xF54BDB7E9C513AC8ULL,
		0x244972506FD64EDCULL,
		0xCCD27284A1A3A5F6ULL,
		0xF5D9A9A106191FC0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x102181E741E9318EULL,
		0xC2CAE8AFBFD30243ULL,
		0xDCFF724591D02CD2ULL,
		0x6730943CC1CEE6B0ULL,
		0xC691DED455B0F48EULL,
		0x3B1E70481F7A4FDDULL,
		0x2ED866303CCB230DULL,
		0x73F52542FA7A477BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x000081E540A80102ULL,
		0xC0C8A00E8FD00201ULL,
		0x04AF600481400802ULL,
		0x21001438C1C4E000ULL,
		0xC401DA5414103088ULL,
		0x200870400F524EDCULL,
		0x0CD0620020832104ULL,
		0x71D1210002180740ULL
	}};
	printf("Test Case 425\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 425 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -425;
	} else {
		printf("Test Case 425 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4BFA25129766E89FULL,
		0xA5A4579EE91ED970ULL,
		0x11BDA5A0B445516EULL,
		0xF6BF727D5AD1030BULL,
		0x61460E96D119F01EULL,
		0x951BD93148A478BFULL,
		0x401F9D4A4FBEB175ULL,
		0x061E96742F4686A3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x669016200D35EAA0ULL,
		0x0CE5F052D0EC4476ULL,
		0x9D276B74D148556CULL,
		0x9B866C049333D959ULL,
		0x9953177259CF538BULL,
		0xA9D99B84BD6D5A1BULL,
		0x3229A872E784E78DULL,
		0x9171DEE8FD75DB48ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x429004000524E880ULL,
		0x04A45012C00C4070ULL,
		0x112521209040516CULL,
		0x9286600412110109ULL,
		0x014206125109500AULL,
		0x811999000824581BULL,
		0x000988424784A105ULL,
		0x001096602D448200ULL
	}};
	printf("Test Case 426\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 426 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -426;
	} else {
		printf("Test Case 426 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEE74CE1F99276FD6ULL,
		0x664AC69D0019200DULL,
		0xCDC837D835AC76FAULL,
		0xC1FCFB275F1C5A6BULL,
		0xE0A3248A8D546BE5ULL,
		0xD807A92CF91FA5C3ULL,
		0xED440AD6C18C4C5EULL,
		0xECA46C0081F4DA7AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8257569A907009AAULL,
		0x52206F2C23DB8A36ULL,
		0x2405E11031D34104ULL,
		0xABE271D8503E8A64ULL,
		0x7B03A975EE7867D9ULL,
		0xEA0B6A6D46FD6E2FULL,
		0x792F72DDBEFC3F32ULL,
		0x33D49E1ECA5B07FBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8254461A90200982ULL,
		0x4200460C00190004ULL,
		0x0400211031804000ULL,
		0x81E07100501C0A60ULL,
		0x600320008C5063C1ULL,
		0xC803282C401D2403ULL,
		0x690402D4808C0C12ULL,
		0x20840C008050027AULL
	}};
	printf("Test Case 427\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 427 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -427;
	} else {
		printf("Test Case 427 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA3BF8B67ED1F283FULL,
		0x9FCFBCE1B6702371ULL,
		0x75FB6802B05B49F8ULL,
		0x20204D0B3DB268C2ULL,
		0x01EFB1CE2733278EULL,
		0x8CD34E1368BD77B5ULL,
		0x880F66B50B65AF2BULL,
		0x7B70393CA1E50D6FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF5881E53F60BF58AULL,
		0x3AA18011191700CCULL,
		0x1F73A817C0F016D8ULL,
		0x1CB3506E8C84CE7BULL,
		0xB9D57A6A5FCF4538ULL,
		0xC3EC93DA621FD7CFULL,
		0x9CA050E1D4EECBC9ULL,
		0xB36ADE622E259021ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA1880A43E40B200AULL,
		0x1A81800110100040ULL,
		0x15732802805000D8ULL,
		0x0020400A0C804842ULL,
		0x01C5304A07030508ULL,
		0x80C00212601D5785ULL,
		0x880040A100648B09ULL,
		0x3360182020250021ULL
	}};
	printf("Test Case 428\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 428 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -428;
	} else {
		printf("Test Case 428 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x562C0B77C5DD7983ULL,
		0xA7AA7F07398DAE80ULL,
		0x5A57AFEFBADA52FDULL,
		0xBE8F18B0E176328AULL,
		0x4D481180B335F8CAULL,
		0x0931EB62E5CBD388ULL,
		0x9B938203A7967AE4ULL,
		0xBA6A304BE3388AC3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x72735C530D075C4AULL,
		0x7BDAC76DC0F4B93EULL,
		0xA433946500FE5A51ULL,
		0xF85B0F4CC71AF3ECULL,
		0xAFC525EFBA64F367ULL,
		0x0CC77C56E7B881E3ULL,
		0x3B4BF28A9408FB32ULL,
		0x059CA94EA58B041EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5220085305055802ULL,
		0x238A47050084A800ULL,
		0x0013846500DA5251ULL,
		0xB80B0800C1123288ULL,
		0x0D400180B224F042ULL,
		0x08016842E5888180ULL,
		0x1B03820284007A20ULL,
		0x0008204AA1080002ULL
	}};
	printf("Test Case 429\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 429 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -429;
	} else {
		printf("Test Case 429 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCF5F0C6CED5FEBFAULL,
		0xE45EBFC27710E77CULL,
		0xCC9E1062440FCA75ULL,
		0xA7485FAD52F50E1FULL,
		0x419D4DF2952B49D3ULL,
		0x4D26BEE51E4CD456ULL,
		0xF797D10442DFDE54ULL,
		0x79E01F3083FD5811ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3D7939C30DC655ABULL,
		0x89672AD0BF425524ULL,
		0x7A7AA550F2179BB1ULL,
		0x7E4954F7CA207E2DULL,
		0x7DDF2FF3BEBCBB53ULL,
		0x348CD74CA0AE5A0FULL,
		0x5CA9D6BBB1D5ACA9ULL,
		0xEC4DB24EEE37A93EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0D5908400D4641AAULL,
		0x80462AC037004524ULL,
		0x481A004040078A31ULL,
		0x264854A542200E0DULL,
		0x419D0DF294280953ULL,
		0x04049644000C5006ULL,
		0x5481D00000D58C00ULL,
		0x6840120082350810ULL
	}};
	printf("Test Case 430\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 430 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -430;
	} else {
		printf("Test Case 430 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8773F70EC77E4098ULL,
		0x2E0FE9FF046259BDULL,
		0xBA3E6CD46F5ECC6BULL,
		0x582EDE1FE274E43DULL,
		0x348F52945DA69329ULL,
		0x8FF930642EFD2747ULL,
		0xC6408455CA4A5F82ULL,
		0x9204608C420C17E1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCD84A7695132BD90ULL,
		0xAAAFC045DE3C9FB6ULL,
		0xA5AFA072DE53CE9CULL,
		0x27AC611669C4F2F1ULL,
		0x4CC141858DEED105ULL,
		0xCE2DEC9892FA1D02ULL,
		0x3D3FB94508361AD5ULL,
		0x37EC8853CD4AA328ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8500A70841320090ULL,
		0x2A0FC045042019B4ULL,
		0xA02E20504E52CC08ULL,
		0x002C40166044E031ULL,
		0x048140840DA69101ULL,
		0x8E29200002F80502ULL,
		0x0400804508021A80ULL,
		0x1204000040080320ULL
	}};
	printf("Test Case 431\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 431 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -431;
	} else {
		printf("Test Case 431 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC829248C30469C77ULL,
		0xCEA2C612F54F2B9FULL,
		0xB1337B4BE63FCD89ULL,
		0x1A2BEC72031E4741ULL,
		0x63590B6BBB0BF88CULL,
		0xD45ACDCAA0358CB3ULL,
		0xF6159CAE6D0158D7ULL,
		0x6A82262DD5F197E9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC9E1B44D8E90BC57ULL,
		0x5E79486D1FBCCC62ULL,
		0x09EAE67AFC2DB4B3ULL,
		0x7457232AF06D9EE2ULL,
		0xC88F39EE12BCA738ULL,
		0x431AE8A1768F67CDULL,
		0x3471D358261A4514ULL,
		0x51D226BDB487BF1CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC821240C00009C57ULL,
		0x4E204000150C0802ULL,
		0x0122624AE42D8481ULL,
		0x10032022000C0640ULL,
		0x4009096A1208A008ULL,
		0x401AC88020050481ULL,
		0x3411900824004014ULL,
		0x4082262D94819708ULL
	}};
	printf("Test Case 432\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 432 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -432;
	} else {
		printf("Test Case 432 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4DA9D9592A1CFD54ULL,
		0x6A47146C0C1BED63ULL,
		0x5E1122573B2D7975ULL,
		0xD00BDB97EAAD5E7FULL,
		0xDD8B63B9AE27D7BEULL,
		0x32E4313CA8B051C7ULL,
		0x750C51538D6CD184ULL,
		0xB5EFFB410117B131ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEF8EEF32CA321073ULL,
		0x37B3EEF922E9BDF8ULL,
		0xB247405064B9E46DULL,
		0xF5C28F5D1BD6887DULL,
		0xC39DC94805B75FB8ULL,
		0xF9BB59AA4477A8C5ULL,
		0x4D9BFCD63CC241CDULL,
		0xBF43F63395FA8C18ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4D88C9100A101050ULL,
		0x220304680009AD60ULL,
		0x1201005020296065ULL,
		0xD0028B150A84087DULL,
		0xC1894108042757B8ULL,
		0x30A01128003000C5ULL,
		0x450850520C404184ULL,
		0xB543F20101128010ULL
	}};
	printf("Test Case 433\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 433 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -433;
	} else {
		printf("Test Case 433 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x670A50B0D7ED88E2ULL,
		0xB7D01F40263B425AULL,
		0x77CB53253A178B0EULL,
		0x36BE1C74B22DDFD3ULL,
		0xA8302937EE905170ULL,
		0x7890C633844FE530ULL,
		0x1CF5BFFCEED3468EULL,
		0xEEE5357C8A8286F0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x56EDD1109231D683ULL,
		0x1B971937D37E1328ULL,
		0xC7D36E88B8E6A630ULL,
		0xD25948FDEDFA15C2ULL,
		0x5B089402C1667E02ULL,
		0xB5C8506263E666F1ULL,
		0xB6174793623D82BBULL,
		0x88C99BDC3FCCC717ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4608501092218082ULL,
		0x13901900023A0208ULL,
		0x47C3420038068200ULL,
		0x12180874A02815C2ULL,
		0x08000002C0005000ULL,
		0x3080402200466430ULL,
		0x141507906211028AULL,
		0x88C1115C0A808610ULL
	}};
	printf("Test Case 434\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 434 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -434;
	} else {
		printf("Test Case 434 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3DE28964CF6E7F6CULL,
		0xE4A78DB135D88031ULL,
		0x379C28AB86A4D517ULL,
		0x8C8C36ECFA489BB3ULL,
		0x6C5C8DB18F77EA80ULL,
		0x8404B67E9B083FA9ULL,
		0xC18B534315AB4AB9ULL,
		0x35B97C6E4916AB80ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAEF2E68A89D4964BULL,
		0xAE4C29B3747F5845ULL,
		0x71B42F247B541B73ULL,
		0xF2933AAF053FBFB5ULL,
		0x642E09D8D8DAB16EULL,
		0x0A0EC809FAFAFD76ULL,
		0x3ACFDD6270EDB193ULL,
		0x8CBE11974985995BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2CE2800089441648ULL,
		0xA40409B134580001ULL,
		0x3194282002041113ULL,
		0x808032AC00089BB1ULL,
		0x640C09908852A000ULL,
		0x000480089A083D20ULL,
		0x008B514210A90091ULL,
		0x04B8100649048900ULL
	}};
	printf("Test Case 435\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 435 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -435;
	} else {
		printf("Test Case 435 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6CF7CFB458EAD35BULL,
		0xF6C7EDA976C1B6E0ULL,
		0xCAF5D5DBC14D90BDULL,
		0xC2D3DA6AF97AE2C2ULL,
		0x2814E283EFBA40B0ULL,
		0x48FDDAABB1A96A48ULL,
		0xB9BE83CCFEAD7309ULL,
		0x62AEB988836A6113ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x237BE89D94B35090ULL,
		0x07B162AB3DC99174ULL,
		0x846489C2A027824DULL,
		0x0151AC87C271EDB0ULL,
		0x901712EE4A828FDDULL,
		0xA582EA7A508BAD61ULL,
		0x10F8FD5056A01264ULL,
		0x676A7E39972BB945ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2073C89410A25010ULL,
		0x068160A934C19060ULL,
		0x806481C28005800DULL,
		0x00518802C070E080ULL,
		0x001402824A820090ULL,
		0x0080CA2A10892840ULL,
		0x10B8814056A01200ULL,
		0x622A3808832A2101ULL
	}};
	printf("Test Case 436\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 436 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -436;
	} else {
		printf("Test Case 436 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5A39F97663FB2FB7ULL,
		0xBA5ED5BB75B24A6EULL,
		0x6B4547224F95DA8EULL,
		0x70F05C01335EC438ULL,
		0x850CA0DC1AAF32E6ULL,
		0x52618830DEA46003ULL,
		0xDE5858E74792F344ULL,
		0x16CE2E7AD3E8913BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB7D8B4EA157384F8ULL,
		0x641E9C995D78E3FCULL,
		0x0A327500FD387A48ULL,
		0x6006449E12FD0126ULL,
		0xA4F5006732BB23ABULL,
		0x2FE324363FACBCBCULL,
		0x9DE0F6A5D79D597CULL,
		0x949CB3F0F2C71D24ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1218B062017304B0ULL,
		0x201E94995530426CULL,
		0x0A0045004D105A08ULL,
		0x60004400125C0020ULL,
		0x8404004412AB22A2ULL,
		0x026100301EA42000ULL,
		0x9C4050A547905144ULL,
		0x148C2270D2C01120ULL
	}};
	printf("Test Case 437\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 437 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -437;
	} else {
		printf("Test Case 437 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1B6423069E84962FULL,
		0xA9BB1152523952C9ULL,
		0x31EE8A1DB7CADA59ULL,
		0xB2D249B42521DF21ULL,
		0x74AB730B823B77EBULL,
		0x4DF8996D39E7F697ULL,
		0x3C44C321E3C3AB50ULL,
		0xFD22759DDA8A221BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA8C72884EF025A5EULL,
		0x557ECBFF7312BD7BULL,
		0x2F2809483D9F797BULL,
		0xCAC57AFC2FCB28C3ULL,
		0x9DB51C57A1D139CAULL,
		0x3DB44F42435584D8ULL,
		0xD520AD7635A8EFA3ULL,
		0x055B1A0A2964641CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x084420048E00120EULL,
		0x013A015252101049ULL,
		0x21280808358A5859ULL,
		0x82C048B425010801ULL,
		0x14A11003801131CAULL,
		0x0DB0094001458490ULL,
		0x140081202180AB00ULL,
		0x0502100808002018ULL
	}};
	printf("Test Case 438\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 438 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -438;
	} else {
		printf("Test Case 438 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2FB994F0157ACF40ULL,
		0xCAED9F807660A563ULL,
		0x4AA7FE96AED0A1C9ULL,
		0x8716D2B2BEEE538EULL,
		0xF51F57467A4A9F63ULL,
		0xC3F8910F5471C3D8ULL,
		0xDC497C23369F6757ULL,
		0x2D17B516518403DAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB7F0A9DD45C110E3ULL,
		0xBE25EAE57FA3611AULL,
		0x4C5D39324D9B56D2ULL,
		0x431333B66713C53EULL,
		0xD4CA1E5DFF45EA5FULL,
		0x4BD4428379F052EBULL,
		0xD734EDB16E1437EBULL,
		0x8DF31405E0207B4CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x27B080D005400040ULL,
		0x8A258A8076202102ULL,
		0x480538120C9000C0ULL,
		0x031212B22602410EULL,
		0xD40A16447A408A43ULL,
		0x43D00003507042C8ULL,
		0xD4006C2126142743ULL,
		0x0D13140440000348ULL
	}};
	printf("Test Case 439\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 439 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -439;
	} else {
		printf("Test Case 439 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3FB2D93427362649ULL,
		0x0B7825C0B383DA8EULL,
		0x804478090B6959DBULL,
		0x7453975A1066018CULL,
		0x4AE299CA259DE15FULL,
		0x6E355BE1F9C615DBULL,
		0xBCE5C84EA0AF65A1ULL,
		0x1B28657547A4FEDDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFFFE4B6388A014E5ULL,
		0xA02793C9A5F17FF9ULL,
		0x8361F72EDFD71357ULL,
		0xC944A550E57A6942ULL,
		0xF825A462096E17CFULL,
		0x3C17146AD38555E0ULL,
		0x14284F66CC414451ULL,
		0xD01AA308F80D42EFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3FB2492000200441ULL,
		0x002001C0A1815A88ULL,
		0x804070080B411153ULL,
		0x4040855000620100ULL,
		0x48208042010C014FULL,
		0x2C151060D18415C0ULL,
		0x1420484680014401ULL,
		0x10082100400442CDULL
	}};
	printf("Test Case 440\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 440 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -440;
	} else {
		printf("Test Case 440 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF4CBD11DF7A14F87ULL,
		0xBFA7664CA0D8F317ULL,
		0x4C03A180EFFF7E01ULL,
		0x71E4482CA4F9A742ULL,
		0x0536EB84539B4AE2ULL,
		0x4334E32817BD3A81ULL,
		0x891BE06A88E82F8EULL,
		0x81B4A3493D6D9CAEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x24E662B89BAE4085ULL,
		0x38B873BF6F76A0B3ULL,
		0x3B388E4731661789ULL,
		0x41C50DA8C0CB7758ULL,
		0x08201167D933B8FDULL,
		0xDD455CD10996EA80ULL,
		0x0EA48F1B707460FCULL,
		0x26824CFE9E3B7A3DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x24C2401893A04085ULL,
		0x38A0620C2050A013ULL,
		0x0800800021661601ULL,
		0x41C4082880C92740ULL,
		0x00200104511308E0ULL,
		0x4104400001942A80ULL,
		0x0800800A0060208CULL,
		0x008000481C29182CULL
	}};
	printf("Test Case 441\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 441 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -441;
	} else {
		printf("Test Case 441 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x99466199A423323EULL,
		0x8D14ABD4E29B76DBULL,
		0x6415FCF94E0D29BFULL,
		0xAD63C3FE1B13C099ULL,
		0x833B39498EE56A53ULL,
		0x85B1BB0ABD265E02ULL,
		0xD4ED297838DF6A3BULL,
		0x083132A7F01DC230ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x93B027CE3E4D626FULL,
		0xC20DFF84D99C588FULL,
		0xF6B15E2335213051ULL,
		0x60DDABFC3F0BD5C5ULL,
		0xA63E05DFD9A84823ULL,
		0x92CEE1251CE78509ULL,
		0x649467C4577C1578ULL,
		0x51F6F2489214060AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x910021882401222EULL,
		0x8004AB84C098508BULL,
		0x64115C2104012011ULL,
		0x204183FC1B03C081ULL,
		0x823A014988A04803ULL,
		0x8080A1001C260400ULL,
		0x44842140105C0038ULL,
		0x0030320090140200ULL
	}};
	printf("Test Case 442\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 442 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -442;
	} else {
		printf("Test Case 442 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBB14981BE393EC5EULL,
		0x3A965A0DFD9ED062ULL,
		0x8575FE8BD9B80883ULL,
		0xB837066DFB95BBADULL,
		0x3AFD252CF0186841ULL,
		0xC94D2937537E660BULL,
		0x129B3733598FEA29ULL,
		0x05CDF43204EABC0FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB2A255F6471B4629ULL,
		0xC85239D672F8925CULL,
		0xBED352F2283933EAULL,
		0xFC9CA317E9636C04ULL,
		0xEB1D82B6C954E895ULL,
		0x1948BBF8F7992C0AULL,
		0x27DBFC7E62B76356ULL,
		0x7E85F8971160AC83ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB200101243134408ULL,
		0x0812180470989040ULL,
		0x8451528208380082ULL,
		0xB8140205E9012804ULL,
		0x2A1D0024C0106801ULL,
		0x094829305318240AULL,
		0x029B343240876200ULL,
		0x0485F0120060AC03ULL
	}};
	printf("Test Case 443\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 443 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -443;
	} else {
		printf("Test Case 443 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF82D52E0C19AB7F3ULL,
		0xFE161879321D9537ULL,
		0x5DF74AD1ACFDBB30ULL,
		0x419F14856BEAF049ULL,
		0x4C84F8F897CF7DDEULL,
		0xCF7C9EB6455018EEULL,
		0x7F3D31F617B0268AULL,
		0x596CE54D35C6CFE6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBD61DF7648C1574EULL,
		0xBE22D31C6B8D5B97ULL,
		0x3F71882A0E444FCEULL,
		0x25B062CD0E05F812ULL,
		0x8196672847B1493FULL,
		0xD4B5B9671378B560ULL,
		0x0F7CFB627230790EULL,
		0x155C8436E5D51C59ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB821526040801742ULL,
		0xBE021018220D1117ULL,
		0x1D7108000C440B00ULL,
		0x019000850A00F000ULL,
		0x008460280781491EULL,
		0xC434982601501060ULL,
		0x0F3C31621230200AULL,
		0x114C840425C40C40ULL
	}};
	printf("Test Case 444\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 444 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -444;
	} else {
		printf("Test Case 444 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x84C9DBBCAEB96144ULL,
		0xAF8862F689C928A2ULL,
		0xD191DCCBE55837FDULL,
		0x05CD2BE0A33D290BULL,
		0x93C12311D90FCED4ULL,
		0xB81E17F4583198C2ULL,
		0xF361A184663BF5A5ULL,
		0x848B85A15B6D4DD7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2B77D7763E00A146ULL,
		0x48F025145310A9E3ULL,
		0x0380B30912508706ULL,
		0xC82FB23B86C72C78ULL,
		0x81F613872EF5C6D5ULL,
		0x2045B92B11AF8FDDULL,
		0xAC18A5321609895EULL,
		0x2EB6919B837F77C9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0041D3342E002144ULL,
		0x08802014010028A2ULL,
		0x0180900900500704ULL,
		0x000D222082052808ULL,
		0x81C003010805C6D4ULL,
		0x20041120102188C0ULL,
		0xA000A10006098104ULL,
		0x04828181036D45C1ULL
	}};
	printf("Test Case 445\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 445 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -445;
	} else {
		printf("Test Case 445 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x811B47651353FA28ULL,
		0x681C784F674183F9ULL,
		0xA8F1FC04B4AD396BULL,
		0xBC937BA5F70A7982ULL,
		0xFFD77C298450C971ULL,
		0x6E243907B7A67AE7ULL,
		0x65EE18F541884156ULL,
		0xE76C676DEED09F56ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA4475B26903B757EULL,
		0xCFB69EBF8046454CULL,
		0xF50E0C671464ABEDULL,
		0xE588A1C7B3E5D839ULL,
		0x6F076BF92DF68789ULL,
		0x828CE6738EABA60EULL,
		0x49FED762F7969AC0ULL,
		0xB5C4AF0D3711CB2FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8003432410137028ULL,
		0x4814180F00400148ULL,
		0xA0000C0414242969ULL,
		0xA4802185B3005800ULL,
		0x6F07682904508101ULL,
		0x0204200386A22206ULL,
		0x41EE106041800040ULL,
		0xA544270D26108B06ULL
	}};
	printf("Test Case 446\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 446 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -446;
	} else {
		printf("Test Case 446 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFF558DF198DE648CULL,
		0x5641C0AC89C841D9ULL,
		0xD066B582379E0B77ULL,
		0x4B81834B3B1B4C48ULL,
		0xF3A937FEC740FF52ULL,
		0xC45505628EA71850ULL,
		0xAB72E280BE9A371FULL,
		0x7EAC879D0508C5D2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x92BFD5AD693599B7ULL,
		0x216CF5E12629E33CULL,
		0xEA56E30EDE0971E9ULL,
		0xF3134A8EFEE01370ULL,
		0x3C428D41108C9306ULL,
		0x96154F219A79BB85ULL,
		0x46AD72E8C550F1ADULL,
		0x5F6951D62797797AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x921585A108140084ULL,
		0x0040C0A000084118ULL,
		0xC046A10216080161ULL,
		0x4301020A3A000040ULL,
		0x3000054000009302ULL,
		0x841505208A211800ULL,
		0x022062808410310DULL,
		0x5E28019405004152ULL
	}};
	printf("Test Case 447\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 447 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -447;
	} else {
		printf("Test Case 447 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE02EC7E3BE67CD64ULL,
		0xD5E86D6767DB90ADULL,
		0xEF7B179B5FB07CE6ULL,
		0x2277218F8B2E904FULL,
		0x94DBC9A710AC3964ULL,
		0xD3B5FC59AD2A46CFULL,
		0xF5BDA7D5EC56BA78ULL,
		0x8AB6632A470DB77AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x74E3467C3F3AFF9CULL,
		0xBC9692E799D89764ULL,
		0x5122BF8D7E23F434ULL,
		0x050A041876BC4A3EULL,
		0xDE7F6C4115E8B01AULL,
		0x43E702C105B174EBULL,
		0x8BAC67015728CD16ULL,
		0x413DA3EB4FDE635FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x602246603E22CD04ULL,
		0x9480006701D89024ULL,
		0x412217895E207424ULL,
		0x00020008022C000EULL,
		0x945B480110A83000ULL,
		0x43A50041052044CBULL,
		0x81AC270144008810ULL,
		0x0034232A470C235AULL
	}};
	printf("Test Case 448\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 448 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -448;
	} else {
		printf("Test Case 448 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x30A4A09214F3ED60ULL,
		0xAF8704606DB1763FULL,
		0x90EE03D3AFE5CAC5ULL,
		0x56E7E9B3B86ABFEFULL,
		0x60F4A326A4B84E5DULL,
		0xEF40C46BF554C6C9ULL,
		0xF7FB52425828E5A1ULL,
		0xE67669CECA45D4A3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0193AF0F5EACD8F5ULL,
		0x9E2A2F044D0CA08BULL,
		0xCA032CF068F1ACB5ULL,
		0x899D783B54E4DCC1ULL,
		0xB3A31B044ED74EF9ULL,
		0x641598FDFDDDB36AULL,
		0xB4E5FFB7E1F02F55ULL,
		0x097B1D146DA15B13ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0080A00214A0C860ULL,
		0x8E0204004D00200BULL,
		0x800200D028E18885ULL,
		0x0085683310609CC1ULL,
		0x20A0030404904E59ULL,
		0x64008069F5548248ULL,
		0xB4E1520240202501ULL,
		0x0072090448015003ULL
	}};
	printf("Test Case 449\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 449 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -449;
	} else {
		printf("Test Case 449 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE085CF9D8B9A1740ULL,
		0xB33D66EFD0EF560AULL,
		0xE5222C16986569E9ULL,
		0xE06CA4C1922E7998ULL,
		0xF45B884CF2235A1CULL,
		0x22E7A9903D1273D3ULL,
		0x77A9AAA770B59336ULL,
		0x9FF192D5FCC340F3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x57608DFFCDEEDF07ULL,
		0x4431403DC4772862ULL,
		0xE95727AE4DE6AA83ULL,
		0x0F4A68164E6DAC1AULL,
		0x43BC3986BEF465A9ULL,
		0x45EFB9335C1C667AULL,
		0xFFD7752894A343B2ULL,
		0x7CB9453B3AD46510ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x40008D9D898A1700ULL,
		0x0031402DC0670002ULL,
		0xE102240608642881ULL,
		0x00482000022C2818ULL,
		0x40180804B2204008ULL,
		0x00E7A9101C106252ULL,
		0x7781202010A10332ULL,
		0x1CB1001138C04010ULL
	}};
	printf("Test Case 450\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 450 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -450;
	} else {
		printf("Test Case 450 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB548FDD5C7318E40ULL,
		0xC4090A13EE191047ULL,
		0xE46A21A34F44DFF6ULL,
		0x546834E35060CF93ULL,
		0x70BF520B13352832ULL,
		0x4A6272D954EF9A90ULL,
		0x048E896D5EFB27E2ULL,
		0xA8ED8DA7B09AAB9BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC7D04905F5CF6CC0ULL,
		0x2227B6742F663BDBULL,
		0xB774FBA3A9AEC54FULL,
		0x0E38B576F1B10984ULL,
		0xB8DDFF32956FB37AULL,
		0xD74C890BA385DF67ULL,
		0x0912B2B9AA7300CDULL,
		0xB4A98ED841C05675ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x85404905C5010C40ULL,
		0x000102102E001043ULL,
		0xA46021A30904C546ULL,
		0x0428346250200980ULL,
		0x309D520211252032ULL,
		0x4240000900859A00ULL,
		0x000280290A7300C0ULL,
		0xA0A98C8000800211ULL
	}};
	printf("Test Case 451\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 451 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -451;
	} else {
		printf("Test Case 451 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x778FC9007BB1080BULL,
		0xE3B1DBDA031E729FULL,
		0x0D6C11FE301B51C1ULL,
		0xD54B2FF2F0E312BAULL,
		0xF53E4D7574EAF47AULL,
		0x0BE4F8A7B7A34288ULL,
		0xBA50914D82CAD971ULL,
		0x1069C718ADC8CEECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCCC3A64EC2D36431ULL,
		0x316CA18BFC0F01BEULL,
		0x19FCE97B701B0F84ULL,
		0x1FA457A037FD5D14ULL,
		0x4872AFA966B114E8ULL,
		0x008174AE7F7EC06DULL,
		0x328102ACD1F9F0C5ULL,
		0xE2F5B8DE84D9A2D8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4483800042910001ULL,
		0x2120818A000E009EULL,
		0x096C017A301B0180ULL,
		0x150007A030E11010ULL,
		0x40320D2164A01468ULL,
		0x008070A637224008ULL,
		0x3200000C80C8D041ULL,
		0x0061801884C882C8ULL
	}};
	printf("Test Case 452\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 452 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -452;
	} else {
		printf("Test Case 452 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5CF41F431443F50CULL,
		0x906554847155C7E0ULL,
		0x55AF3D4F0882C323ULL,
		0xC0564B360F4411CFULL,
		0xCA380B6B5CFBA158ULL,
		0x028ED2F89C706436ULL,
		0x88B07811F29CE4A3ULL,
		0xEBDF04460C5795AAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x146A7112D3229836ULL,
		0x7DF0CC09F2B95642ULL,
		0x2B6CC22AC25DF00BULL,
		0x6003B69EAE0DDAFCULL,
		0xF02A021B7EDD9687ULL,
		0xB44153F908A7D347ULL,
		0x4D4ED0DF6377A4C5ULL,
		0x5B70BC777DDD4F85ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1460110210029004ULL,
		0x1060440070114640ULL,
		0x012C000A0000C003ULL,
		0x400202160E0410CCULL,
		0xC028020B5CD98000ULL,
		0x000052F808204006ULL,
		0x080050116214A481ULL,
		0x4B5004460C550580ULL
	}};
	printf("Test Case 453\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 453 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -453;
	} else {
		printf("Test Case 453 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x87D47C6CCC47C9D0ULL,
		0xEB88C95404F17829ULL,
		0xCB15BE79B22B6C10ULL,
		0xE27CF8AB83B8A66EULL,
		0x857A5CD4996503EBULL,
		0x48E6C9E8BE73C4BFULL,
		0x37DDBE358CEA4DECULL,
		0xCBD201D6DCF57374ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDA00103AD8B16D37ULL,
		0x5EB516C1EEFC888CULL,
		0x233DD8A92B78B87AULL,
		0xC88A30EE5B43B04DULL,
		0x5D364FF09F219C80ULL,
		0xC930830925FB9C02ULL,
		0x32EE494B1A90886CULL,
		0x25484B7DB0D9BE12ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x82001028C8014910ULL,
		0x4A80004004F00808ULL,
		0x0315982922282810ULL,
		0xC00830AA0300A04CULL,
		0x05324CD099210080ULL,
		0x4820810824738402ULL,
		0x32CC08010880086CULL,
		0x0140015490D13210ULL
	}};
	printf("Test Case 454\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 454 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -454;
	} else {
		printf("Test Case 454 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCFE3600334234550ULL,
		0x24BC808123D892A3ULL,
		0x309A6680047B425BULL,
		0xB0E685D6D3E61A68ULL,
		0xCDD390140688314EULL,
		0x3F5F590560BA74F9ULL,
		0x521925574CBF975FULL,
		0xAC83B0BDF7C11551ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8F4304C12BC9AF05ULL,
		0x9FCD3E560BFE7A3DULL,
		0xC9751D4848773623ULL,
		0x45B647B7B5AF850FULL,
		0xFE30C38C8D63DD5EULL,
		0x6EDC20060FE412A0ULL,
		0x8123F02204F591BBULL,
		0x0843D85BE1DFC757ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8F43000120010500ULL,
		0x048C000003D81221ULL,
		0x0010040000730203ULL,
		0x00A6059691A60008ULL,
		0xCC1080040400114EULL,
		0x2E5C000400A010A0ULL,
		0x0001200204B5911BULL,
		0x08039019E1C10551ULL
	}};
	printf("Test Case 455\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 455 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -455;
	} else {
		printf("Test Case 455 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4451AF3FDCF1B237ULL,
		0xBED4D682CC3B9580ULL,
		0xE8BAF0EB71D8F060ULL,
		0xA413FBC62869E732ULL,
		0x71D521E1CC0D975EULL,
		0xC84EF2CFF7D2E4F3ULL,
		0x1095E577CAFBAC92ULL,
		0xDC452F5ED69A7465ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC644BCA2BCE9CB7AULL,
		0x860472AA10EA60FFULL,
		0xCD78FD214A474FC3ULL,
		0x9BA8EE4C63571D05ULL,
		0xE54966B638C0154FULL,
		0xDD01E6151E206EC9ULL,
		0x08B659D9011EA91AULL,
		0x8DD89D8D4CD8D76AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4440AC229CE18232ULL,
		0x86045282002A0080ULL,
		0xC838F02140404040ULL,
		0x8000EA4420410500ULL,
		0x614120A00800154EULL,
		0xC800E205160064C1ULL,
		0x00944151001AA812ULL,
		0x8C400D0C44985460ULL
	}};
	printf("Test Case 456\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 456 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -456;
	} else {
		printf("Test Case 456 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9D5535FF9926FD49ULL,
		0x835F7672313EE103ULL,
		0x0722703C70A2641BULL,
		0xEAA3839AB8569AF3ULL,
		0x541AB1378416F476ULL,
		0x2E040AD129F1A588ULL,
		0x55436904FD2962F7ULL,
		0xFF315CD937E4F27BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF501052926E12C93ULL,
		0x97442FF15D3CA7B1ULL,
		0xF15823142CE11CE5ULL,
		0xC8E58C784F5FE52FULL,
		0xBDCA804DCE88B109ULL,
		0xEF8DD027C657EED1ULL,
		0xE4FD4E5E9DA06419ULL,
		0xB250CA088A566FBEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9501052900202C01ULL,
		0x83442670113CA101ULL,
		0x0100201420A00401ULL,
		0xC8A1801808568023ULL,
		0x140A80058400B000ULL,
		0x2E0400010051A480ULL,
		0x444148049D206011ULL,
		0xB21048080244623AULL
	}};
	printf("Test Case 457\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 457 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -457;
	} else {
		printf("Test Case 457 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFE90491E548E06ADULL,
		0x4363115AFE13F788ULL,
		0x8760F7C18A330683ULL,
		0xFCD1164C52F76F83ULL,
		0xA7F319317B690237ULL,
		0x0AF94F65666CE4FCULL,
		0xFEC1633026D7D347ULL,
		0x10B954FD7248A47DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0DE4C4790FA2D4E0ULL,
		0x040FFD870C72CB94ULL,
		0x8209D693FF6C9CF5ULL,
		0x049827F328D665FAULL,
		0xC188DFE8177146E2ULL,
		0xCC862C78335763DCULL,
		0x792BAED14F68DE4EULL,
		0x14603E098139777FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0C804018048204A0ULL,
		0x000311020C12C380ULL,
		0x8200D6818A200481ULL,
		0x0490064000D66582ULL,
		0x8180192013610222ULL,
		0x08800C60224460DCULL,
		0x780122100640D246ULL,
		0x102014090008247DULL
	}};
	printf("Test Case 458\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 458 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -458;
	} else {
		printf("Test Case 458 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB9FFEB8304DADB9BULL,
		0x01460C2551820C24ULL,
		0xBE518F317725A031ULL,
		0xFDF8E9FEE2FC16B0ULL,
		0xDF6C3AD2ED4590CAULL,
		0x3E343C330163FA0AULL,
		0x7FA2002A7F04CB8CULL,
		0xEDE2B4793A811302ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA5F82E57D6920058ULL,
		0x98F26A30560755C5ULL,
		0xED06973F8DF79E0FULL,
		0xC37C0E0853A66D9EULL,
		0x5A73EE6B016BF667ULL,
		0x110CCF4276AFF4D4ULL,
		0x1A0C36E277652E17ULL,
		0x8680EF3D6268100BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA1F82A0304920018ULL,
		0x0042082050020404ULL,
		0xAC00873105258001ULL,
		0xC178080842A40490ULL,
		0x5A602A4201419042ULL,
		0x10040C020023F000ULL,
		0x1A00002277040A04ULL,
		0x8480A43922001002ULL
	}};
	printf("Test Case 459\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 459 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -459;
	} else {
		printf("Test Case 459 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3E8FF30653DB05B4ULL,
		0xF45077D944743C9EULL,
		0xFAE21D4AA709B7C7ULL,
		0xEF80952903FF5BA2ULL,
		0x61190FD164CFC4E2ULL,
		0x9CDB5AB0F786B2B5ULL,
		0xE355FC89E6A0E932ULL,
		0x669A941CCF6AEB86ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC58E7745C4A1618BULL,
		0xDA38450FE8203C62ULL,
		0xFAEA8E6856644D98ULL,
		0x409CABF04C07DF1EULL,
		0xF807DC0016FA7D22ULL,
		0xE7010E636088960EULL,
		0x058391FDA116FE42ULL,
		0x7E71893313BA7295ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x048E730440810180ULL,
		0xD010450940203C02ULL,
		0xFAE20C4806000580ULL,
		0x4080812000075B02ULL,
		0x60010C0004CA4422ULL,
		0x84010A2060809204ULL,
		0x01019089A000E802ULL,
		0x66108010032A6284ULL
	}};
	printf("Test Case 460\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 460 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -460;
	} else {
		printf("Test Case 460 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFF8D6B26A38F9EEFULL,
		0x86DD77D7128501CBULL,
		0xF3DB6B9F49480FCFULL,
		0x31AB52A1224C2189ULL,
		0x7B772026D8CB1FB0ULL,
		0x35650EDB0E6BC327ULL,
		0xAE07F7F2967E32CCULL,
		0x03A37B6C247AA5E0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB737F3FA47D6F1D3ULL,
		0x48270C4565C1BF13ULL,
		0x424FA087369871ABULL,
		0x69F7A1E5A95823A0ULL,
		0x498F29D229DCC25BULL,
		0xF740E0D7B9A62D5FULL,
		0x419A57C1158D3676ULL,
		0x4806827E944804C2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB7056322038690C3ULL,
		0x0005044500810103ULL,
		0x424B20870008018BULL,
		0x21A300A120482180ULL,
		0x4907200208C80210ULL,
		0x354000D308220107ULL,
		0x000257C0140C3244ULL,
		0x0002026C044804C0ULL
	}};
	printf("Test Case 461\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 461 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -461;
	} else {
		printf("Test Case 461 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x593D8B1F997E2ABEULL,
		0xC6AD833FB225E8E5ULL,
		0xE9B66CFB9DC2848CULL,
		0xBCAD630ACE05E643ULL,
		0xF2AE0A6B1994BBA2ULL,
		0x92C8C884C8449CB5ULL,
		0x31D97026813C7156ULL,
		0x442586EDDE013F08ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x77AD238821598221ULL,
		0xABA15C608BFF6E7FULL,
		0x1E14EDE30F216BFBULL,
		0xD2A5DE3DFBCB7E2EULL,
		0x0FBDA7E13C65F105ULL,
		0x4EC9D6589B1BA4AEULL,
		0x4EB9E46449D832FCULL,
		0x4C8171918D129215ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x512D030801580220ULL,
		0x82A1002082256865ULL,
		0x08146CE30D000088ULL,
		0x90A54208CA016602ULL,
		0x02AC02611804B100ULL,
		0x02C8C000880084A4ULL,
		0x0099602401183054ULL,
		0x440100818C001200ULL
	}};
	printf("Test Case 462\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 462 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -462;
	} else {
		printf("Test Case 462 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6B664F41963A4982ULL,
		0x7BDE7E0E3B0F74A0ULL,
		0xCF88FE0B38E35F30ULL,
		0xF1E75846FE2351EEULL,
		0xD60BFC15590A3CFFULL,
		0x243F9926FC720EC2ULL,
		0xBD2CB6E1DBB091BCULL,
		0x1AB39E0A4A716C5BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3F8AEEF953668E77ULL,
		0x7EEE123C6D6CB8A3ULL,
		0x3EC912EEA783B64CULL,
		0x38B4036045AC2DF8ULL,
		0xDB1E8E0376B32736ULL,
		0x1159571A33B33FF7ULL,
		0xAD89F3E1D5C9D1CAULL,
		0xF2B4BF86A0551002ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2B024E4112220802ULL,
		0x7ACE120C290C30A0ULL,
		0x0E88120A20831600ULL,
		0x30A40040442001E8ULL,
		0xD20A8C0150022436ULL,
		0x0019110230320EC2ULL,
		0xAD08B2E1D1809188ULL,
		0x12B09E0200510002ULL
	}};
	printf("Test Case 463\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 463 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -463;
	} else {
		printf("Test Case 463 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0203396625E87650ULL,
		0xABD43753DB46D360ULL,
		0x20F589312AB0A67DULL,
		0x649B0CF5402AEE76ULL,
		0xD8BFB79645F7E726ULL,
		0x6BF14887F70C871DULL,
		0x9B8587CA4EBBC681ULL,
		0x6617D9CD1D923EC4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x84A1BA8B35F378A6ULL,
		0xD02F1EB5237DDF09ULL,
		0xC904A614A90D3AF4ULL,
		0xF42E0614D9C4ADD8ULL,
		0x3F1C0FD82C071ABAULL,
		0x217F5421DA9B1D97ULL,
		0x8AF2117E7C5D2B86ULL,
		0x57F3306EB3081587ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0001380225E07000ULL,
		0x800416110344D300ULL,
		0x0004801028002274ULL,
		0x640A04144000AC50ULL,
		0x181C079004070222ULL,
		0x21714001D2080515ULL,
		0x8A80014A4C190280ULL,
		0x4613104C11001484ULL
	}};
	printf("Test Case 464\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 464 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -464;
	} else {
		printf("Test Case 464 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4AAD68D3009CD153ULL,
		0xBFF2193BD1BF542EULL,
		0x10DA1A9E0E50749AULL,
		0xB27BB625E0D0F5AEULL,
		0x28FFD95A656FAA3FULL,
		0xEC72D49F2C08632EULL,
		0xBE99E9834C47BC8FULL,
		0xC766FC1C61DAC07FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2B4D82213C135D9CULL,
		0x98FC6B1776AF6C5CULL,
		0xED67C1F12437FC58ULL,
		0xC0F00B2918F650B9ULL,
		0x05DC04BF4747332EULL,
		0x83A0064C916CE700ULL,
		0x42671561D586BBACULL,
		0xBFE916D6D1C8FCB9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0A0D000100105110ULL,
		0x98F0091350AF440CULL,
		0x0042009004107418ULL,
		0x8070022100D050A8ULL,
		0x00DC001A4547222EULL,
		0x8020040C00086300ULL,
		0x020101014406B88CULL,
		0x8760141441C8C039ULL
	}};
	printf("Test Case 465\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 465 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -465;
	} else {
		printf("Test Case 465 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6397083A64C53D71ULL,
		0xB06849842FC2E781ULL,
		0x1F70D5F8ACF1BF52ULL,
		0x53DE073C1A169AAAULL,
		0x2BA75A7D974E316AULL,
		0x03A844EA0B2D566AULL,
		0x15BB04891B360C0AULL,
		0x1F002B59026CBA52ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBD8A9E9CA3B63274ULL,
		0xA676EE609B68DB0CULL,
		0x72F409779590F309ULL,
		0x458A3E980C7ACF07ULL,
		0x99C44BF30B42BB6DULL,
		0xB01F0F6FB203B5ACULL,
		0x0EB079D2C57DB886ULL,
		0x813C7BB594AA7AF9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2182081820843070ULL,
		0xA06048000B40C300ULL,
		0x127001708490B300ULL,
		0x418A061808128A02ULL,
		0x09844A7103423168ULL,
		0x0008046A02011428ULL,
		0x04B0008001340802ULL,
		0x01002B1100283A50ULL
	}};
	printf("Test Case 466\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 466 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -466;
	} else {
		printf("Test Case 466 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7E33CFC62AAB82CAULL,
		0x9F08783C95EF2CF2ULL,
		0x81A1FEC67E7ACB36ULL,
		0x32E165265E01F6E8ULL,
		0x822204D17E774907ULL,
		0xA5E45DDDAAA11833ULL,
		0x2CB039F74F90105BULL,
		0xD791DC098EE92973ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3AE6B3C1B4C8EE9AULL,
		0xE9BCCA8070FE4D82ULL,
		0xCAB999CF5B3722C0ULL,
		0x7B6129BEF5C59EF9ULL,
		0x4BB67C39E919789CULL,
		0x1A6847F02D4179DDULL,
		0x190A5772D387373DULL,
		0xE87F80B103AB564AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3A2283C02088828AULL,
		0x8908480010EE0C82ULL,
		0x80A198C65A320200ULL,
		0x32612126540196E8ULL,
		0x0222041168114804ULL,
		0x006045D028011811ULL,
		0x0800117243801019ULL,
		0xC011800102A90042ULL
	}};
	printf("Test Case 467\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 467 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -467;
	} else {
		printf("Test Case 467 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDBAD89D054617927ULL,
		0x701132D652E0AC76ULL,
		0x0EE7695B1800832EULL,
		0x0F0BC9A6E9943A28ULL,
		0x0AEDD0A299947C2AULL,
		0xF9584EBAFC43318EULL,
		0x372CDD22AC569AD2ULL,
		0xDAB0C0D114756304ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE1EC56EC918477C6ULL,
		0x8686A95016557CD8ULL,
		0xEBE65C699FF0923FULL,
		0x6C1FFD3AECA6DBE0ULL,
		0x9062E069B1D47065ULL,
		0x6A90E39D64019185ULL,
		0x2B67233FB64219B6ULL,
		0x7D3BCB3D89B7E383ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC1AC00C010007106ULL,
		0x0000205012402C50ULL,
		0x0AE648491800822EULL,
		0x0C0BC922E8841A20ULL,
		0x0060C02091947020ULL,
		0x6810429864011184ULL,
		0x23240122A4421892ULL,
		0x5830C01100356300ULL
	}};
	printf("Test Case 468\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 468 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -468;
	} else {
		printf("Test Case 468 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7C41C26D27A9E138ULL,
		0xDC913588D1E881C2ULL,
		0x5BC61F284D2DC86AULL,
		0x913A7814E3EBE709ULL,
		0x5F4BF4173F416EF9ULL,
		0xDC7CE90C082C279FULL,
		0x5D47F0417E95E1A2ULL,
		0x449FE624EEB708BEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x39FA9BAE91011B87ULL,
		0x2BD28E32773EF272ULL,
		0x302E0AC2A8F14B70ULL,
		0xC20A1BB2EA5EE3BBULL,
		0xD22A9A94E9428B52ULL,
		0xE7496483F9666C19ULL,
		0xD68058E92BC7D150ULL,
		0xAC9860923801793EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3840822C01010100ULL,
		0x0890040051288042ULL,
		0x10060A0008214860ULL,
		0x800A1810E24AE309ULL,
		0x520A901429400A50ULL,
		0xC448600008242419ULL,
		0x540050412A85C100ULL,
		0x049860002801083EULL
	}};
	printf("Test Case 469\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 469 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -469;
	} else {
		printf("Test Case 469 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2E699EFD8EED64EBULL,
		0xAD88B25AE2024BA0ULL,
		0x7433F8EF302B8BAFULL,
		0x218679633147FD03ULL,
		0xDAB7C87C0B4CA3CEULL,
		0xA22840B340BAB035ULL,
		0xDF237A843257752CULL,
		0x4233091ACD6C2B38ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x30C0621E894E0733ULL,
		0x4838123A13A96584ULL,
		0x7306923C8919C341ULL,
		0x81E9E120C969A628ULL,
		0x0E11B002689A7C21ULL,
		0x34D46FC85D0D1A6EULL,
		0x9C7B1A9B68252223ULL,
		0xE44DECFB6D32FECEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2040021C884C0423ULL,
		0x0808121A02004180ULL,
		0x7002902C00098301ULL,
		0x018061200141A400ULL,
		0x0A11800008082000ULL,
		0x2000408040081024ULL,
		0x9C231A8020052020ULL,
		0x4001081A4D202A08ULL
	}};
	printf("Test Case 470\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 470 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -470;
	} else {
		printf("Test Case 470 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x52B9E171195FFEECULL,
		0x771B89374ABF86F3ULL,
		0xEC39E9022D539144ULL,
		0x37B7426C0743AE43ULL,
		0x0436B07B9DBA2FA0ULL,
		0xFDC7BD0BF6BC9759ULL,
		0x97ED9D67CFB3F76BULL,
		0xEB0A7D5EB96E0410ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4E81072C6B9A497CULL,
		0x7A9A41166BB266BFULL,
		0xE8698F44BBA16010ULL,
		0x70C22827C7A76B4EULL,
		0x8B1883962F47AB19ULL,
		0x58B02BB6B0A37F98ULL,
		0xF13A0030023A0B3DULL,
		0xF112769EF1A4145FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x42810120091A486CULL,
		0x721A01164AB206B3ULL,
		0xE829890029010000ULL,
		0x3082002407032A42ULL,
		0x001080120D022B00ULL,
		0x58802902B0A01718ULL,
		0x9128002002320329ULL,
		0xE102741EB1240410ULL
	}};
	printf("Test Case 471\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 471 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -471;
	} else {
		printf("Test Case 471 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAA3F549DADE15ACCULL,
		0x76F6F0C151CCC640ULL,
		0xAEAE2E162C6847E0ULL,
		0x6E946E40D0BFCFC5ULL,
		0x91363FC79B6C2BE9ULL,
		0x605890A643CDC4C6ULL,
		0x873DF1944F2B93E0ULL,
		0xF544BA88027817ECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEB6F42484DA4CCF3ULL,
		0x36258A19EDF69EFFULL,
		0x9BD78EC4F78EFD4AULL,
		0x663CFB20AA8AE792ULL,
		0xCF09D91A01C76A22ULL,
		0x90ADBE9F25C4BAC0ULL,
		0xEB1DEA4A938B2174ULL,
		0xACC0CE027EE9AA06ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAA2F40080DA048C0ULL,
		0x3624800141C48640ULL,
		0x8A860E0424084540ULL,
		0x66146A00808AC780ULL,
		0x8100190201442A20ULL,
		0x0008908601C480C0ULL,
		0x831DE000030B0160ULL,
		0xA4408A0002680204ULL
	}};
	printf("Test Case 472\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 472 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -472;
	} else {
		printf("Test Case 472 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE8B77E90BB55C460ULL,
		0x55EEF4752B3C2719ULL,
		0xF23E80C8A83742EAULL,
		0x61B1049A1EBE90FEULL,
		0x22B425B56CFBF252ULL,
		0x3F5BC163DDC4838EULL,
		0x68A7DA717B894EB0ULL,
		0xEF8FDC04A05A3183ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x178CB3A9276762B2ULL,
		0x01D84B6BF81ED38CULL,
		0x723B5751091F58E7ULL,
		0x705634212AE27516ULL,
		0xC636B58CF634A34BULL,
		0x624F768CD96F2009ULL,
		0x10710F54677ADD3DULL,
		0x9D6B67CE57A9B2DAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0084328023454020ULL,
		0x01C84061281C0308ULL,
		0x723A0040081740E2ULL,
		0x601004000AA21016ULL,
		0x023425846430A242ULL,
		0x224B4000D9440008ULL,
		0x00210A5063084C30ULL,
		0x8D0B440400083082ULL
	}};
	printf("Test Case 473\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 473 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -473;
	} else {
		printf("Test Case 473 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1EA86D208453B1FEULL,
		0x3506F573C067B255ULL,
		0x4D54199B70DC3DCEULL,
		0x6D5797101A63BC49ULL,
		0x0BC6A16E52123E7DULL,
		0x2B2D2B354EDF8682ULL,
		0xDE73105C64F1639DULL,
		0x35886BB8360971F1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3AA5A9438E2A3125ULL,
		0x987C3555309CC89DULL,
		0x97AB675F2B48AB79ULL,
		0xF1DDFC45D20CC95BULL,
		0xFEF86AD4A46FDE83ULL,
		0x80E2BCDABF2A8745ULL,
		0x998BC8FF949E875BULL,
		0x9EB97E00C2392C23ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1AA0290084023124ULL,
		0x1004355100048015ULL,
		0x0500011B20482948ULL,
		0x6155940012008849ULL,
		0x0AC0204400021E01ULL,
		0x002028100E0A8600ULL,
		0x9803005C04900319ULL,
		0x14886A0002092021ULL
	}};
	printf("Test Case 474\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 474 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -474;
	} else {
		printf("Test Case 474 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAC21A400A4378FF5ULL,
		0x5608336B81BA5F52ULL,
		0xB20B8C373B9F965FULL,
		0x91425FFDE4B9DD58ULL,
		0x1672793DD05AF5BDULL,
		0x1CB7B4A1D44BAEEEULL,
		0xA61E9089D78C174FULL,
		0x37561E57890C5A03ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x132E455C37E9FF8FULL,
		0xA0170829512A2625ULL,
		0xEA53FD4D20B5C7D1ULL,
		0x03548731E4D0BD6DULL,
		0xCE330B4F05A4497AULL,
		0x820ABA8454B5A67EULL,
		0x21B4F0C9AB544A8DULL,
		0xD091376B657E88C8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0020040024218F85ULL,
		0x00000029012A0600ULL,
		0xA2038C0520958651ULL,
		0x01400731E4909D48ULL,
		0x0632090D00004138ULL,
		0x0002B0805401A66EULL,
		0x201490898304020DULL,
		0x10101643010C0800ULL
	}};
	printf("Test Case 475\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 475 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -475;
	} else {
		printf("Test Case 475 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA9E41DFCC6ACE75DULL,
		0xEA5C286C34EE4D54ULL,
		0x0FFF40AFAA0D7848ULL,
		0x55856B7694066A7EULL,
		0x19F99D6DECDE3155ULL,
		0x1A794659B9083ABBULL,
		0x99E2A18B35B7BE52ULL,
		0x7A2B18441EDE9A19ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBF0CEE3F179D4322ULL,
		0x329623BBA81EAA5FULL,
		0xAECCA7FD22510DF7ULL,
		0x2F81A99CCFFAF268ULL,
		0x2126AED6EE009658ULL,
		0x4D7694887E0C601BULL,
		0x264991DA39140B71ULL,
		0x07EF200F58434AC2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA9040C3C068C4300ULL,
		0x22142028200E0854ULL,
		0x0ECC00AD22010840ULL,
		0x0581291484026268ULL,
		0x01208C44EC001050ULL,
		0x087004083808201BULL,
		0x0040818A31140A50ULL,
		0x022B000418420A00ULL
	}};
	printf("Test Case 476\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 476 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -476;
	} else {
		printf("Test Case 476 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x385DC99FE81AF33BULL,
		0x4F2F5F7C35304BE8ULL,
		0x5529A116EF87F1A7ULL,
		0xC627FFB9A15F8B46ULL,
		0x38DF41C72EB60158ULL,
		0x870F086F344BF8F2ULL,
		0x58CC2D344FC12ED1ULL,
		0x9676E12A24053776ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDC411F3C55989ABEULL,
		0x7F115C2A077AF809ULL,
		0x9105B530365C2CF5ULL,
		0x7E866990025EC81FULL,
		0xE2A37EE01DC1D5E2ULL,
		0x9BA0445FBCE31C4FULL,
		0x666A5100D8CCDEBCULL,
		0x9C4434BF36FCD3EBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1841091C4018923AULL,
		0x4F015C2805304808ULL,
		0x1101A110260420A5ULL,
		0x46066990005E8806ULL,
		0x208340C00C800140ULL,
		0x8300004F34431842ULL,
		0x4048010048C00E90ULL,
		0x9444202A24041362ULL
	}};
	printf("Test Case 477\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 477 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -477;
	} else {
		printf("Test Case 477 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x011674CA8126EB05ULL,
		0xA01F1DE26EC1111AULL,
		0xAF2FD9B0F30EC31DULL,
		0xBD298C0C21729A87ULL,
		0x4DFDBE6162BFDDE6ULL,
		0xB196F2283C6A3B77ULL,
		0xB8BB9649E7675422ULL,
		0x9B4D8642347623E6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x24BBEB0E35972A07ULL,
		0x631EE9A1372E516DULL,
		0x7F00801DE53F2198ULL,
		0xA245F764946631E9ULL,
		0x06E8B2B40A5A0445ULL,
		0x747333FBAF32BECDULL,
		0x989193C50B33DCFDULL,
		0xE4518010E56CF648ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0012600A01062A05ULL,
		0x201E09A026001108ULL,
		0x2F008010E10E0118ULL,
		0xA001840400621081ULL,
		0x04E8B220021A0444ULL,
		0x301232282C223A45ULL,
		0x9891924103235420ULL,
		0x8041800024642240ULL
	}};
	printf("Test Case 478\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 478 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -478;
	} else {
		printf("Test Case 478 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x433689D916D6521FULL,
		0x99FCD5F23DF862A2ULL,
		0xCAD8A1FEE7C4D915ULL,
		0xE578A3FA912FC39CULL,
		0x5C0765941448E114ULL,
		0xC2A7D5FC1038742BULL,
		0xF3DFE8CAE5BFD7DCULL,
		0xA091A5661B903913ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCC20727B6876E81DULL,
		0xDF13061C5357A72AULL,
		0xB9198663B2E23952ULL,
		0xFB7744DCAF783E23ULL,
		0x41711A8FD93E5075ULL,
		0x494CE1842B25E26CULL,
		0x88C6E8AE8E09EB3DULL,
		0xB1A3896F113EB4A6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x402000590056401DULL,
		0x9910041011502222ULL,
		0x88188062A2C01910ULL,
		0xE17000D881280200ULL,
		0x4001008410084014ULL,
		0x4004C18400206028ULL,
		0x80C6E88A8409C31CULL,
		0xA081816611103002ULL
	}};
	printf("Test Case 479\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 479 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -479;
	} else {
		printf("Test Case 479 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x81B18E655803EC1EULL,
		0xECF2088029E496CBULL,
		0xDAD0D8ADD71E1D93ULL,
		0xC772953C7D702330ULL,
		0xD44E391DE902820EULL,
		0x150E73A52E59C471ULL,
		0xBB4A489935F8ED68ULL,
		0x66EF93EF7BB5C786ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC350F3749E505CEEULL,
		0x65EC399E1D6686C7ULL,
		0x147EB899C5E954C4ULL,
		0x341F76AFAF680A2BULL,
		0x00DD47CECC66FB7BULL,
		0x06DFE0184B94DB90ULL,
		0xF71295204FD3450CULL,
		0x75FF75468C3D91D2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8110826418004C0EULL,
		0x64E00880096486C3ULL,
		0x10509889C5081480ULL,
		0x0412142C2D600220ULL,
		0x004C010CC802820AULL,
		0x040E60000A10C010ULL,
		0xB302000005D04508ULL,
		0x64EF114608358182ULL
	}};
	printf("Test Case 480\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 480 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -480;
	} else {
		printf("Test Case 480 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB739610F1905CFD2ULL,
		0x031C8F6BC86439E2ULL,
		0xC52B1F345AB57464ULL,
		0xE10174AF52FC8008ULL,
		0x277DFF156BAA14F5ULL,
		0x0956012F4B03448FULL,
		0x60CFE9EE8FFAEA72ULL,
		0x60E47CA8BB44AF99ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF522BA0DA25440B4ULL,
		0xA15E1606F75C720EULL,
		0xC641BA02310C702BULL,
		0xEB5E411652288990ULL,
		0x46A2476BC5DB8DEAULL,
		0x6862740533CEB75AULL,
		0x40181CCD250AF600ULL,
		0xE1DAB7B8257EF206ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB520200D00044090ULL,
		0x011C0602C0443002ULL,
		0xC4011A0010047020ULL,
		0xE100400652288000ULL,
		0x06204701418A04E0ULL,
		0x084200050302040AULL,
		0x400808CC050AE200ULL,
		0x60C034A82144A200ULL
	}};
	printf("Test Case 481\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 481 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -481;
	} else {
		printf("Test Case 481 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAFFB645AE00F716FULL,
		0x7EE9219B3ED61816ULL,
		0x61F2F22E4BC72403ULL,
		0x689A7890715DEAF4ULL,
		0xE49404673FBC7CDDULL,
		0xBFCEDE9D8B66C301ULL,
		0x88E14065EAF91833ULL,
		0x3C95CFC632C30224ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC241CD216701EE02ULL,
		0x369FC21FE292D253ULL,
		0xC37F794AE66F93F1ULL,
		0xA80028AB1429BAF9ULL,
		0xFF1CD6F1DE16841EULL,
		0x0E584C2D6D64A9A0ULL,
		0xA6FE344FA3FF3469ULL,
		0xBDABFEAC1A807975ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8241440060016002ULL,
		0x3689001B22921012ULL,
		0x4172700A42470001ULL,
		0x280028801009AAF0ULL,
		0xE41404611E14041CULL,
		0x0E484C0D09648100ULL,
		0x80E00045A2F91021ULL,
		0x3C81CE8412800024ULL
	}};
	printf("Test Case 482\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 482 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -482;
	} else {
		printf("Test Case 482 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x75D4A11EF90A07E2ULL,
		0xA1FE585FCD05770DULL,
		0x76C9921D4C87FF0AULL,
		0x89AAC96C9F1542D8ULL,
		0x1A9461DEF6E3138AULL,
		0x1D3ED3714AAF4153ULL,
		0xCFEA4B81F0F89EE5ULL,
		0x8919E66C3FCCB328ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x30767A62691078C4ULL,
		0xAB54FB717525A99DULL,
		0xE62B0EA5A1C0BD43ULL,
		0x4046DA9F3E37FEBAULL,
		0xA32B81B3701F1CD5ULL,
		0x002BFBCCD13503CCULL,
		0x897729157C0BD481ULL,
		0x5609DEDB26CD7E42ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x30542002690000C0ULL,
		0xA15458514505210DULL,
		0x660902050080BD02ULL,
		0x0002C80C1E154298ULL,
		0x0200019270031080ULL,
		0x002AD34040250140ULL,
		0x8962090170089481ULL,
		0x0009C64826CC3200ULL
	}};
	printf("Test Case 483\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 483 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -483;
	} else {
		printf("Test Case 483 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF6B0FF15EFCCF3E3ULL,
		0x6DF157DA740F8428ULL,
		0x7CD05C04EF755676ULL,
		0x0F600D831AEF3243ULL,
		0xE38C622AB46569C3ULL,
		0x212B49FE1B4F7B5CULL,
		0x4CD48B375F5E3146ULL,
		0xB2BA2435060ADE67ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x21C5632F121B4BF4ULL,
		0x4376304B71F90723ULL,
		0x7FCB31212C09D133ULL,
		0x89DD56EE66E29BCBULL,
		0x72DE3C60AED32A37ULL,
		0x6AA2AF3C31654D69ULL,
		0xF23B96F4D7596C85ULL,
		0xFDFE8FF580807535ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x20806305020843E0ULL,
		0x4170104A70090420ULL,
		0x7CC010002C015032ULL,
		0x0940048202E21243ULL,
		0x628C2020A4412803ULL,
		0x2022093C11454948ULL,
		0x4010823457582004ULL,
		0xB0BA043500005425ULL
	}};
	printf("Test Case 484\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 484 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -484;
	} else {
		printf("Test Case 484 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEC5E0078070564EBULL,
		0xDC07A6EE75286070ULL,
		0xB11B2CAE54B861BCULL,
		0xAAD78C9D87EFB99DULL,
		0x41A097DE47F19163ULL,
		0x2B604CFE985F6A4AULL,
		0x0EDC437FC47262FEULL,
		0xFE920536D0693FC1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x58AEA7E1159D20AFULL,
		0x84110098BA14D95BULL,
		0x7BDE258691A57312ULL,
		0xD4ABFEA8988E5B29ULL,
		0xD6C0835011E9C3A4ULL,
		0x25BDCE56B589D097ULL,
		0x2B06D2E470D47608ULL,
		0xB1D12E00DF4ADE70ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x480E0060050520ABULL,
		0x8401008830004050ULL,
		0x311A248610A06110ULL,
		0x80838C88808E1909ULL,
		0x4080835001E18120ULL,
		0x21204C5690094002ULL,
		0x0A04426440506208ULL,
		0xB0900400D0481E40ULL
	}};
	printf("Test Case 485\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 485 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -485;
	} else {
		printf("Test Case 485 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA10839734D1E5690ULL,
		0xFFA8EF7F71604EABULL,
		0xC1FCCAA6503CF77EULL,
		0x0CEAF240CDC7AB81ULL,
		0x921A938EC4CF2173ULL,
		0x5BF8625419FF556FULL,
		0xCB04EC84F79FBA84ULL,
		0x07D7E63FAF5F9FFFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF2C5C7C297360955ULL,
		0xC4C381640372DFE1ULL,
		0xCB6F2990C8B3B588ULL,
		0x59358C6A0693347AULL,
		0x674C91A3810B7B42ULL,
		0x8B9308C1B4AC4478ULL,
		0xA673541D064506EFULL,
		0xA16DE930BE00A4A8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA000014205160010ULL,
		0xC480816401604EA1ULL,
		0xC16C08804030B508ULL,
		0x0820804004832000ULL,
		0x02089182800B2142ULL,
		0x0B90004010AC4468ULL,
		0x8200440406050284ULL,
		0x0145E030AE0084A8ULL
	}};
	printf("Test Case 486\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 486 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -486;
	} else {
		printf("Test Case 486 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA76B29E42613C1A7ULL,
		0x859EB576072CC57BULL,
		0x3F1622B345DF128EULL,
		0x54617DE8DB9C1221ULL,
		0x4E7E42BCFDA4D31AULL,
		0xC4E3A8D199812FFCULL,
		0x17BB9C106C5F7381ULL,
		0xE91894C694757265ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAA014B45FBE2EBEEULL,
		0xB1395C23C9911BD9ULL,
		0x1F2A627B2C5E900FULL,
		0x16687CC3014D09CDULL,
		0xA9217C3FD32C4401ULL,
		0x471305CCDF9A4D38ULL,
		0xCFAA6DD3D55B029BULL,
		0xA6681F7146356315ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA20109442202C1A6ULL,
		0x8118142201000159ULL,
		0x1F022233045E100EULL,
		0x14607CC0010C0001ULL,
		0x0820403CD1244000ULL,
		0x440300C099800D38ULL,
		0x07AA0C10445B0281ULL,
		0xA008144004356205ULL
	}};
	printf("Test Case 487\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 487 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -487;
	} else {
		printf("Test Case 487 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1A8BACD0DF9BAD89ULL,
		0xCA22247394ADC063ULL,
		0x7EAF747419665DD0ULL,
		0xC2497853152981F1ULL,
		0x4F689726C1BE4069ULL,
		0x96DDED726A6746AAULL,
		0xDB862C906EAAD55AULL,
		0x19680F3FD5B835A4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3EACB83FCE5F84FDULL,
		0xF6E8D04B670A004CULL,
		0x3F77F33DB76FFA32ULL,
		0x85AC85D70D82D2D5ULL,
		0xD1940BFCE1E2C601ULL,
		0x24F26B63FD99DA27ULL,
		0x93DEB75EB9221A4AULL,
		0xE076DC35C95A1243ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1A88A810CE1B8489ULL,
		0xC220004304080040ULL,
		0x3E27703411665810ULL,
		0x80080053050080D1ULL,
		0x41000324C1A24001ULL,
		0x04D0696268014222ULL,
		0x938624102822104AULL,
		0x00600C35C1181000ULL
	}};
	printf("Test Case 488\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 488 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -488;
	} else {
		printf("Test Case 488 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCFE9277432793EBDULL,
		0xABF9577DF8EAC217ULL,
		0xA8421825E94466D1ULL,
		0x7B19E57CCEF5814DULL,
		0x38E914F0FA975331ULL,
		0x1AC5D013CAA75FBEULL,
		0xA83B3DC9FBD64553ULL,
		0x3A0C0EEF4EA5AA1DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3B5271D025ACD845ULL,
		0x8B955FB5B4E8380CULL,
		0xE152ABC39E807020ULL,
		0xDBF4A959D98C81DAULL,
		0x47170FB2D02D43FFULL,
		0xFC8B7C25671A0331ULL,
		0xEF1F68865281DF79ULL,
		0x2C47887EDABE905FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0B40215020281805ULL,
		0x8B915735B0E80004ULL,
		0xA042080188006000ULL,
		0x5B10A158C8848148ULL,
		0x000104B0D0054331ULL,
		0x1881500142020330ULL,
		0xA81B288052804551ULL,
		0x2804086E4AA4801DULL
	}};
	printf("Test Case 489\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 489 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -489;
	} else {
		printf("Test Case 489 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x62058E63F4CD1E54ULL,
		0xBD7052F65FB2CB30ULL,
		0xCF4A746EAF4718CDULL,
		0x5C943C8476E90CFEULL,
		0x9480AFEBB50FCFE6ULL,
		0x752472A7BD623D29ULL,
		0xAA69BE6AB90A96BBULL,
		0x25815B26D118728CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x543E76FA41E3C72CULL,
		0xEA17910D2E101996ULL,
		0x9D4A008FD75BABAFULL,
		0xB5EE8DAFAEAAC8C7ULL,
		0x173E9C03C3DD02E3ULL,
		0x5717F6941CD6C54FULL,
		0xA0CFEF1E595D9329ULL,
		0xD4B566AAEE9453E4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4004066240C10604ULL,
		0xA81010040E100910ULL,
		0x8D4A000E8743088DULL,
		0x14840C8426A808C6ULL,
		0x14008C03810D02E2ULL,
		0x550472841C420509ULL,
		0xA049AE0A19089229ULL,
		0x04814222C0105284ULL
	}};
	printf("Test Case 490\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 490 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -490;
	} else {
		printf("Test Case 490 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x82DA5DAEC79944A1ULL,
		0xBE3A7CE2CEE2BB39ULL,
		0x29B0E29D4B768A02ULL,
		0xBC46A2DECD4D403EULL,
		0x1A8D22CA9D7860C6ULL,
		0x7C09C7889B4652C7ULL,
		0x554DA40EA149A46DULL,
		0xB783DEABD74C658AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2B8890DE7D82E9A2ULL,
		0x64DE99F1AC7E083AULL,
		0xFA64A0B1043F25CFULL,
		0x53F184D4D50D7667ULL,
		0x862964A3C4A272BEULL,
		0xC8AEFB3D0478C896ULL,
		0xB28AEFE215B32C1FULL,
		0x14C5572F44936655ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0288108E458040A0ULL,
		0x241A18E08C620838ULL,
		0x2820A09100360002ULL,
		0x104080D4C50D4026ULL,
		0x0209208284206086ULL,
		0x4808C30800404086ULL,
		0x1008A4020101240DULL,
		0x1481562B44006400ULL
	}};
	printf("Test Case 491\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 491 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -491;
	} else {
		printf("Test Case 491 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9BAB41BE9D7235AFULL,
		0x3C5A02282F67C9D2ULL,
		0x294C88B80794179BULL,
		0x68023A32E340D1A8ULL,
		0x449649925691D420ULL,
		0xC45E838A76965BD7ULL,
		0x4A36E90E703772BDULL,
		0xC5C79A896BE3B78EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x758875D2BA3AC158ULL,
		0xFDE2624A0403DFDCULL,
		0xA46034676542C779ULL,
		0x8363DA15EFB6A98AULL,
		0x4ABEFD53FB158271ULL,
		0xB27157EBDC9116BCULL,
		0x820B94FD38274CC5ULL,
		0xFA3A4C8F33AB61E0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1188419298320108ULL,
		0x3C4202080403C9D0ULL,
		0x2040002005000719ULL,
		0x00021A10E3008188ULL,
		0x4096491252118020ULL,
		0x8050038A54901294ULL,
		0x0202800C30274085ULL,
		0xC002088923A32180ULL
	}};
	printf("Test Case 492\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 492 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -492;
	} else {
		printf("Test Case 492 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3608076C20A89BAAULL,
		0xCB3BF249EBA5AD1AULL,
		0xA265F9748E7517CAULL,
		0xF57DA0CD9F04EE4EULL,
		0x402BC21AD9C87BA2ULL,
		0x95359AF5CE9D855BULL,
		0x580FDA8BE2205A24ULL,
		0x7866698F45E8E09AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x695AAB110E3AC80EULL,
		0x77E3A89539354C57ULL,
		0x0FCD15E6A783333DULL,
		0x0B8359319044B66EULL,
		0x504186149AD6FCB8ULL,
		0xAA41C48084498303ULL,
		0xFEEED411A8CD41A3ULL,
		0x96B12245AAA4D228ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x200803000028880AULL,
		0x4323A00129250C12ULL,
		0x0245116486011308ULL,
		0x010100019004A64EULL,
		0x4001821098C078A0ULL,
		0x8001808084098103ULL,
		0x580ED001A0004020ULL,
		0x1020200500A0C008ULL
	}};
	printf("Test Case 493\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 493 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -493;
	} else {
		printf("Test Case 493 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDE9D271B33EE0F46ULL,
		0x64601C676B8457E6ULL,
		0x092CCC172E03A7A4ULL,
		0x696C866E4493BCE5ULL,
		0xE45D9D1FD5A5BF63ULL,
		0xF1469C1CA755E29DULL,
		0x94217ECB74B36B48ULL,
		0x904776B2EDDC67C9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x96A0D5071B16CDF6ULL,
		0xF3BB09A497348079ULL,
		0xA9B8EC682981B6BFULL,
		0x0B3C648BC52335B3ULL,
		0xF96852738DA170C9ULL,
		0x1A449B44D83522DBULL,
		0x71999FD1E95AA46FULL,
		0xCE8AC0157B406399ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9680050313060D46ULL,
		0x6020082403040060ULL,
		0x0928CC002801A6A4ULL,
		0x092C040A440334A1ULL,
		0xE048101385A13041ULL,
		0x1044980480152299ULL,
		0x10011EC160122048ULL,
		0x8002401069406389ULL
	}};
	printf("Test Case 494\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 494 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -494;
	} else {
		printf("Test Case 494 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD3E6B3DF63C023C2ULL,
		0xA6CE2922F8EA91C7ULL,
		0x39F99D5A6EA9D33DULL,
		0x49F2493C2499252FULL,
		0xE490C5BFB4CB1F05ULL,
		0xA89FAB44BC38FE05ULL,
		0x8182A411D3B9E540ULL,
		0x3A2643CBED5BD6BDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC30E29FE5EC2820AULL,
		0x17210B075EB5DE3CULL,
		0xD0CE77C2EA58ADE3ULL,
		0x19CACC2A84655623ULL,
		0xC82AF583FE6ABF7AULL,
		0x6F5B84B92C76CB4BULL,
		0x2BB21DB34B3EE726ULL,
		0x79DD9857BC812AD1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC30621DE42C00202ULL,
		0x0600090258A09004ULL,
		0x10C815426A088121ULL,
		0x09C2482804010423ULL,
		0xC000C583B44A1F00ULL,
		0x281B80002C30CA01ULL,
		0x018204114338E500ULL,
		0x38040043AC010291ULL
	}};
	printf("Test Case 495\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 495 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -495;
	} else {
		printf("Test Case 495 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x11F9704758C24D2EULL,
		0x1D01CF12286D6975ULL,
		0x6FD2E29207E442D0ULL,
		0xE8524478F9148FF8ULL,
		0xDED5DE8966147D3FULL,
		0xC31812C84CB82B77ULL,
		0x05FF23C8F7E7FB17ULL,
		0xFD744D25FE8F04FBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA8834C8F021D9484ULL,
		0x340BFDC6E1F346C2ULL,
		0x1DFBA78056E3A592ULL,
		0xEFE3A10BC6AF72AAULL,
		0xF12909033D0C9265ULL,
		0x3048587F21C06A02ULL,
		0x374FB5DF2DBDBC12ULL,
		0x8453D9215CF2EEE9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0081400700000404ULL,
		0x1401CD0220614040ULL,
		0x0DD2A28006E00090ULL,
		0xE8420008C00402A8ULL,
		0xD001080124041025ULL,
		0x0008104800802A02ULL,
		0x054F21C825A5B812ULL,
		0x845049215C8204E9ULL
	}};
	printf("Test Case 496\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 496 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -496;
	} else {
		printf("Test Case 496 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2ADC856C1B3CC898ULL,
		0xA43C9710C631BFDDULL,
		0xF3887133FF2CC898ULL,
		0xF5EBC3AFA7209673ULL,
		0x1A4DF3AC6383EC78ULL,
		0x023297AE19311176ULL,
		0x682372534DCC4C3CULL,
		0x3EBD56B9DB7F3966ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9A9518F3601BB771ULL,
		0x5FA3CAD3C227A17DULL,
		0x09FA9888A9D25935ULL,
		0xA63BF05A56EA3E11ULL,
		0x630ED8D8C6D38566ULL,
		0x4198C84F328EF211ULL,
		0x0303C9074C986F19ULL,
		0x6056565A6922F858ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0A94006000188010ULL,
		0x04208210C221A15DULL,
		0x01881000A9004810ULL,
		0xA42BC00A06201611ULL,
		0x020CD08842838460ULL,
		0x0010800E10001010ULL,
		0x000340034C884C18ULL,
		0x2014561849223840ULL
	}};
	printf("Test Case 497\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 497 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -497;
	} else {
		printf("Test Case 497 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB3E0436A6A2224B5ULL,
		0x11763DF812C37604ULL,
		0x8F6D9D22BBCA9C0DULL,
		0x38285435510FF595ULL,
		0x82FBAC5AED3A1EF1ULL,
		0x4F479711059C021BULL,
		0xF3099ED4E2CD9E6AULL,
		0x5ACAD9D8F50A784AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4300D63E2EEE6625ULL,
		0x5D61A8E8FDF321F8ULL,
		0x453494430D5B5587ULL,
		0xFEFDBDB52FE63A24ULL,
		0xB987A95ED9D21456ULL,
		0x423C7DC9BB90EC6FULL,
		0x00485EE8BB63ACAFULL,
		0x54A790138B1BA8B8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0300422A2A222425ULL,
		0x116028E810C32000ULL,
		0x05249402094A1405ULL,
		0x3828143501063004ULL,
		0x8083A85AC9121450ULL,
		0x420415010190000BULL,
		0x00081EC0A2418C2AULL,
		0x50829010810A2808ULL
	}};
	printf("Test Case 498\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 498 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -498;
	} else {
		printf("Test Case 498 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x35622B5F52415EE0ULL,
		0x29F36AFAF06F57A0ULL,
		0x6F615B244A1C8881ULL,
		0x71DF3594F5FC7848ULL,
		0x065EC0B4469A02E4ULL,
		0xA955D707416EC90BULL,
		0xE8813C66172A3DF2ULL,
		0xBE566CE3CEE9E72DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x03D81A1082D42C72ULL,
		0xEFAD005E980BF924ULL,
		0x2EB0D246AC59C5A3ULL,
		0xE9B77CAA5CCB2070ULL,
		0x45C93D26198C1C9BULL,
		0x970339B6B4920053ULL,
		0x1C29B2E7D4D3D92DULL,
		0x915107A559A1BD35ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x01400A1002400C60ULL,
		0x29A1005A900B5120ULL,
		0x2E20520408188081ULL,
		0x6197348054C82040ULL,
		0x0448002400880080ULL,
		0x8101110600020003ULL,
		0x0801306614021920ULL,
		0x905004A148A1A525ULL
	}};
	printf("Test Case 499\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 499 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -499;
	} else {
		printf("Test Case 499 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5FCD5FB611ABB9C5ULL,
		0x7D315393F77A93A4ULL,
		0xA4AA27286A7BFA7AULL,
		0x62BC50493A961BF6ULL,
		0x86E9F1CFA2A8D3B2ULL,
		0x658DC3CFF054CDD9ULL,
		0x1A8E7C71EC39846CULL,
		0x366B1A769ADBD41BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x08B4AAF0F23E936EULL,
		0xA7504370C8F36B7CULL,
		0x6F91CB2C7397F254ULL,
		0x92811CB2B38FF370ULL,
		0x5093C9F54833CFFCULL,
		0x95372FCF0D7BD0FBULL,
		0x9B544129E824D0EAULL,
		0xCD7291D5FF9832B7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x08840AB0102A9144ULL,
		0x25104310C0720324ULL,
		0x248003286213F250ULL,
		0x0280100032861370ULL,
		0x0081C1C50020C3B0ULL,
		0x050503CF0050C0D9ULL,
		0x1A044021E8208068ULL,
		0x046210549A981013ULL
	}};
	printf("Test Case 500\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 500 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -500;
	} else {
		printf("Test Case 500 PASSED\n");
	}
	printf("---\n\n");
	return 0;
}