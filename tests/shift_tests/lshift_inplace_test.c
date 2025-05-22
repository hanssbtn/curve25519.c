#include "../tests.h"

int32_t curve25519_key_lshift_inplace_test(void) {
	printf("Inplace Key Left Shift Test\n");
	curve25519_key_t k1 = {.key64 = {
		0xD116A845BEC1B99EULL,
		0x77B879A93D8706B0ULL,
		0x805453B98A36EA20ULL,
		0x38D7FBF9A5D97F79ULL,
		0x21B92AF418B1BBC7ULL,
		0x5D8452501A186238ULL,
		0x78977DF62F60328CULL,
		0x0000000000000000ULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0x0000000000000000ULL,
		0x688B5422DF60DCCFULL,
		0x3BDC3CD49EC38358ULL,
		0xC02A29DCC51B7510ULL,
		0x9C6BFDFCD2ECBFBCULL,
		0x10DC957A0C58DDE3ULL,
		0x2EC229280D0C311CULL,
		0x3C4BBEFB17B01946ULL
	}};
	int shift = 63;
	printf("Test Case 1\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x365FE0271B76315EULL,
		0x94A21D21A6BCF930ULL,
		0xD1C6EFAF240EFD0AULL,
		0x3510F84E4C4EB798ULL,
		0xCBF37C8B50A2E33CULL,
		0x996FD56E59C9BCACULL,
		0x892AC151CFCC05B7ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x62BC000000000000ULL,
		0xF2606CBFC04E36ECULL,
		0xFA1529443A434D79ULL,
		0x6F31A38DDF5E481DULL,
		0xC6786A21F09C989DULL,
		0x795997E6F916A145ULL,
		0x0B6F32DFAADCB393ULL,
		0x0001125582A39F98ULL
	}};
	shift = 49;
	printf("Test Case 2\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x83CA445C158AB418ULL,
		0xFB5A61A0B2AD867CULL,
		0x2756BB14DD99CA23ULL,
		0x1A281A5036113B72ULL,
		0x5B40A101D710BDD0ULL,
		0x753D0C28835871ADULL,
		0xE44FD5DDB25F529DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE5222E0AC55A0C00ULL,
		0xAD30D05956C33E41ULL,
		0xAB5D8A6ECCE511FDULL,
		0x140D281B089DB913ULL,
		0xA05080EB885EE80DULL,
		0x9E861441AC38D6ADULL,
		0x27EAEED92FA94EBAULL,
		0x0000000000000072ULL
	}};
	shift = 7;
	printf("Test Case 3\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x31D48C5276F3BBC8ULL,
		0x30DCA52C5DC9E195ULL,
		0xA88D78D7C1CAFEFFULL,
		0x9DCDE77F886C5190ULL,
		0x722128108AB451C5ULL,
		0xDA421AA7C941203CULL,
		0x13D53A1A12A1390EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x523149DBCEEF2000ULL,
		0x7294B177278654C7ULL,
		0x35E35F072BFBFCC3ULL,
		0x379DFE21B14642A2ULL,
		0x84A0422AD1471677ULL,
		0x086A9F250480F1C8ULL,
		0x54E8684A84E43B69ULL,
		0x000000000000004FULL
	}};
	shift = 10;
	printf("Test Case 4\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xC72F79B10756D2B5ULL,
		0xF3450BD8026E47D3ULL,
		0x6AC63835F3B22BC8ULL,
		0xA1080E303AFB55C3ULL,
		0xA70053CDDC803B16ULL,
		0x2989D583E1316A80ULL,
		0x180679738780AFEDULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDA56A00000000000ULL,
		0xC8FA78E5EF3620EAULL,
		0x45791E68A17B004DULL,
		0x6AB86D58C706BE76ULL,
		0x0762D42101C6075FULL,
		0x2D5014E00A79BB90ULL,
		0x15FDA5313AB07C26ULL,
		0x00000300CF2E70F0ULL
	}};
	shift = 45;
	printf("Test Case 5\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x5A1A9612D38475C7ULL,
		0x2D278C1F7DC48EABULL,
		0x2B11C887B0699BA9ULL,
		0x9B4DAF6C5C4FF10DULL,
		0x196938C1EDB2AA8BULL,
		0x6E7512FEDA04B94DULL,
		0xC3B89DF3986010B5ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9C23AE3800000000ULL,
		0xEE24755AD0D4B096ULL,
		0x834CDD49693C60FBULL,
		0xE27F8869588E443DULL,
		0x6D95545CDA6D7B62ULL,
		0xD025CA68CB49C60FULL,
		0xC30085AB73A897F6ULL,
		0x000000061DC4EF9CULL
	}};
	shift = 35;
	printf("Test Case 6\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xB819B4B243D50AB1ULL,
		0x7080797C20278D43ULL,
		0x557B422263DC95C0ULL,
		0xA58965684FF9755DULL,
		0x325445C0EE5591ECULL,
		0x57D358C2E77256CDULL,
		0x92E8BA0FF742F9F8ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7AA1562000000000ULL,
		0x04F1A87703369648ULL,
		0x7B92B80E100F2F84ULL,
		0xFF2EABAAAF68444CULL,
		0xCAB23D94B12CAD09ULL,
		0xEE4AD9A64A88B81DULL,
		0xE85F3F0AFA6B185CULL,
		0x000000125D1741FEULL
	}};
	shift = 37;
	printf("Test Case 7\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xCAD1FAD25030FFF1ULL,
		0x2969FEE943DDCE51ULL,
		0xDDD46D30154DA3B8ULL,
		0x0F14B35291F58F4EULL,
		0x6CF2E71AFBBDC78CULL,
		0x2DDDDE553DEE66C2ULL,
		0x6F700583FAC25407ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x061FFE2000000000ULL,
		0x7BB9CA395A3F5A4AULL,
		0xA9B477052D3FDD28ULL,
		0x3EB1E9DBBA8DA602ULL,
		0x77B8F181E2966A52ULL,
		0xBDCCD84D9E5CE35FULL,
		0x584A80E5BBBBCAA7ULL,
		0x0000000DEE00B07FULL
	}};
	shift = 37;
	printf("Test Case 8\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xD395FB7767B56DBEULL,
		0xC804450A3E31399AULL,
		0xD4AD48E901007126ULL,
		0x5D6DE33AFBF19428ULL,
		0xF02B3915322F8C61ULL,
		0xAD061AED5FD427FDULL,
		0xFA0C6E8E48921188ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4E57EDDD9ED5B6F8ULL,
		0x20111428F8C4E66BULL,
		0x52B523A40401C49BULL,
		0x75B78CEBEFC650A3ULL,
		0xC0ACE454C8BE3185ULL,
		0xB4186BB57F509FF7ULL,
		0xE831BA3922484622ULL,
		0x0000000000000003ULL
	}};
	shift = 2;
	printf("Test Case 9\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xC597B7E32F549AE3ULL,
		0xD8DD6CA58CDBD482ULL,
		0xDEA0ECD3D316BDBFULL,
		0x859ACDEE5704D691ULL,
		0x4AB7AD5854E6EE38ULL,
		0x1E4215D9C9172648ULL,
		0x5D3C2538CBAE8585ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x49AE300000000000ULL,
		0xBD482C597B7E32F5ULL,
		0x6BDBFD8DD6CA58CDULL,
		0x4D691DEA0ECD3D31ULL,
		0x6EE38859ACDEE570ULL,
		0x726484AB7AD5854EULL,
		0xE85851E4215D9C91ULL,
		0x000005D3C2538CBAULL
	}};
	shift = 44;
	printf("Test Case 10\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xB2DA7BB06DDD4A4EULL,
		0x6ABBBF63AE353336ULL,
		0x57CC47412160116CULL,
		0x9413CA65782E95B1ULL,
		0x0ADFB579AD8BAE32ULL,
		0x9EBB5873D4DFF570ULL,
		0xA6EBE303EA364F26ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3800000000000000ULL,
		0xDACB69EEC1B77529ULL,
		0xB1AAEEFD8EB8D4CCULL,
		0xC55F311D04858045ULL,
		0xCA504F2995E0BA56ULL,
		0xC02B7ED5E6B62EB8ULL,
		0x9A7AED61CF537FD5ULL,
		0x029BAF8C0FA8D93CULL
	}};
	shift = 58;
	printf("Test Case 11\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x5FB89D2CD7D3351DULL,
		0x2D172BB50ED7FB5BULL,
		0x7EDEF297EF8F1319ULL,
		0xD3685CA04E7BFF3EULL,
		0x6916258BB146FCA7ULL,
		0xD818EBA126E51327ULL,
		0xA7D0F7D7C2700DA7ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA3A0000000000000ULL,
		0x6B6BF713A59AFA66ULL,
		0x6325A2E576A1DAFFULL,
		0xE7CFDBDE52FDF1E2ULL,
		0x94FA6D0B9409CF7FULL,
		0x64ED22C4B17628DFULL,
		0xB4FB031D7424DCA2ULL,
		0x0014FA1EFAF84E01ULL
	}};
	shift = 53;
	printf("Test Case 12\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x1788E7198B62FE0FULL,
		0x23AB314AFC19542AULL,
		0x6E440521462A11D0ULL,
		0x9891D74B7B6B3BB9ULL,
		0xFF207F600BA520DCULL,
		0xA8A33C0BBB06AA21ULL,
		0x82141737678B087CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFC1E000000000000ULL,
		0xA8542F11CE3316C5ULL,
		0x23A047566295F832ULL,
		0x7772DC880A428C54ULL,
		0x41B93123AE96F6D6ULL,
		0x5443FE40FEC0174AULL,
		0x10F951467817760DULL,
		0x000104282E6ECF16ULL
	}};
	shift = 49;
	printf("Test Case 13\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xA8FEDB2AB406D19CULL,
		0xCBF6B9F5A8931E58ULL,
		0x39B1ED1BFAD1111BULL,
		0x6184E8CDE9468B42ULL,
		0x35D6BFC4E0004AE3ULL,
		0xF956C69303AAA359ULL,
		0x4CEA19BF0485101EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCAAD01B467000000ULL,
		0x7D6A24C7962A3FB6ULL,
		0x46FEB44446F2FDAEULL,
		0x337A51A2D08E6C7BULL,
		0xF1380012B8D8613AULL,
		0xA4C0EAA8D64D75AFULL,
		0x6FC1214407BE55B1ULL,
		0x0000000000133A86ULL
	}};
	shift = 22;
	printf("Test Case 14\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xA464DDB062E1357FULL,
		0x06A61D775EE0BCFEULL,
		0x2D3D7F9322101E21ULL,
		0x7AC4ADEC37FAB973ULL,
		0x834C2B0A57AA7CB8ULL,
		0xDC4D5524DEE3009CULL,
		0x346EEEB093F2DA9FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9376C18B84D5FC00ULL,
		0x9875DD7B82F3FA91ULL,
		0xF5FE4C884078841AULL,
		0x12B7B0DFEAE5CCB4ULL,
		0x30AC295EA9F2E1EBULL,
		0x3554937B8C02720DULL,
		0xBBBAC24FCB6A7F71ULL,
		0x00000000000000D1ULL
	}};
	shift = 10;
	printf("Test Case 15\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xCC9E1513248C525BULL,
		0x4DCDDCE0C1932E77ULL,
		0xC5DF0A83C8880C0CULL,
		0xAF3BB550E67743FBULL,
		0x6EFB541E3BAA4101ULL,
		0x01FC2C581333F5EEULL,
		0x89112B560BD6A63EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF0A899246292D800ULL,
		0x6EE7060C9973BE64ULL,
		0xF8541E444060626EULL,
		0xDDAA8733BA1FDE2EULL,
		0xDAA0F1DD52080D79ULL,
		0xE162C0999FAF7377ULL,
		0x895AB05EB531F00FULL,
		0x0000000000000448ULL
	}};
	shift = 11;
	printf("Test Case 16\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xE053BC9C6B0BDFAFULL,
		0xF6DD4B75B00F82D9ULL,
		0x6BE3CA4918DE597FULL,
		0x90BE0150BDDA3249ULL,
		0x03C3C2D9B208199DULL,
		0x0880A45C1016C9B9ULL,
		0x0E1C2EDF36704E72ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5EFD780000000000ULL,
		0x7C16CF029DE4E358ULL,
		0xF2CBFFB6EA5BAD80ULL,
		0xD1924B5F1E5248C6ULL,
		0x40CCEC85F00A85EEULL,
		0xB64DC81E1E16CD90ULL,
		0x827390440522E080ULL,
		0x00000070E176F9B3ULL
	}};
	shift = 43;
	printf("Test Case 17\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x1AEF3EFD38B47DF2ULL,
		0x79E522222AB70481ULL,
		0xCB5DD84771074F38ULL,
		0x831706CA848F7BBAULL,
		0x25DDB59859987F39ULL,
		0x839CA67DE3597EB1ULL,
		0x94AE0B8E678564CEULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBF4E2D1F7C800000ULL,
		0x888AADC12046BBCFULL,
		0x11DC41D3CE1E7948ULL,
		0xB2A123DEEEB2D776ULL,
		0x6616661FCE60C5C1ULL,
		0x9F78D65FAC49776DULL,
		0xE399E15933A0E729ULL,
		0x0000000000252B82ULL
	}};
	shift = 22;
	printf("Test Case 18\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xE32712C7AF661145ULL,
		0x7D4F3F25DC988CC3ULL,
		0x02BEF20BB3DD7D4AULL,
		0x460282FBA639B9E9ULL,
		0x4F1FDE656259D182ULL,
		0x738E7D874CAF67FBULL,
		0x27C41CFAECB3DC81ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5ECC228A00000000ULL,
		0xB9311987C64E258FULL,
		0x67BAFA94FA9E7E4BULL,
		0x4C7373D2057DE417ULL,
		0xC4B3A3048C0505F7ULL,
		0x995ECFF69E3FBCCAULL,
		0xD967B902E71CFB0EULL,
		0x000000004F8839F5ULL
	}};
	shift = 33;
	printf("Test Case 19\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x380527512547F16CULL,
		0x803922061C107173ULL,
		0x83CAC4EC4A2E0F2DULL,
		0x6A2CDD5D50ABF5C3ULL,
		0x3B45BBDA896EEA69ULL,
		0xA517EC94F3D7D6CEULL,
		0x28D91B46A213C7FEULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x47F16C0000000000ULL,
		0x1071733805275125ULL,
		0x2E0F2D803922061CULL,
		0xABF5C383CAC4EC4AULL,
		0x6EEA696A2CDD5D50ULL,
		0xD7D6CE3B45BBDA89ULL,
		0x13C7FEA517EC94F3ULL,
		0x00000028D91B46A2ULL
	}};
	shift = 40;
	printf("Test Case 20\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x58245BFAA7735A9EULL,
		0x5143E4F19DFD1828ULL,
		0x7F2A5CD19E8AE1EFULL,
		0x5ED8F64F7F42E1EAULL,
		0x67CE204D1760B524ULL,
		0x122817A8AD2777B5ULL,
		0x7E966F07385F4064ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8B7F54EE6B53C000ULL,
		0x7C9E33BFA3050B04ULL,
		0x4B9A33D15C3DEA28ULL,
		0x1EC9EFE85C3D4FE5ULL,
		0xC409A2EC16A48BDBULL,
		0x02F515A4EEF6ACF9ULL,
		0xCDE0E70BE80C8245ULL,
		0x0000000000000FD2ULL
	}};
	shift = 13;
	printf("Test Case 21\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x29F560B23E56AEA6ULL,
		0x16CC48244BFE7FB0ULL,
		0x5BE06073638EDBD7ULL,
		0xED8B63840150D890ULL,
		0xDA64AAA14C2A78AFULL,
		0x0E4E551A817124BFULL,
		0x347B8787F777C25FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6AEA600000000000ULL,
		0xE7FB029F560B23E5ULL,
		0xEDBD716CC48244BFULL,
		0x0D8905BE06073638ULL,
		0xA78AFED8B6384015ULL,
		0x124BFDA64AAA14C2ULL,
		0x7C25F0E4E551A817ULL,
		0x00000347B8787F77ULL
	}};
	shift = 44;
	printf("Test Case 22\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xE61D7986E88273D7ULL,
		0x559F185F87011DEFULL,
		0x264B931C5DEF54A0ULL,
		0xD3477A4755B1A3E2ULL,
		0x82264C502C275778ULL,
		0xA86BEB98E8840EFBULL,
		0x8E91C0BEF41DE447ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x86E88273D7000000ULL,
		0x5F87011DEFE61D79ULL,
		0x1C5DEF54A0559F18ULL,
		0x4755B1A3E2264B93ULL,
		0x502C275778D3477AULL,
		0x98E8840EFB82264CULL,
		0xBEF41DE447A86BEBULL,
		0x00000000008E91C0ULL
	}};
	shift = 24;
	printf("Test Case 23\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x1B44A22F294F502AULL,
		0x9E099C1B20E791ACULL,
		0x30A06A2C38CA829AULL,
		0x27AD7CAB01499E41ULL,
		0xF9350435B3BE6A23ULL,
		0xC24CDD490967F066ULL,
		0x68915F019CF81BC2ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x02A0000000000000ULL,
		0x1AC1B44A22F294F5ULL,
		0x29A9E099C1B20E79ULL,
		0xE4130A06A2C38CA8ULL,
		0xA2327AD7CAB01499ULL,
		0x066F9350435B3BE6ULL,
		0xBC2C24CDD490967FULL,
		0x00068915F019CF81ULL
	}};
	shift = 52;
	printf("Test Case 24\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x07D43E4F09147578ULL,
		0x221C80D80E72FC47ULL,
		0x10E6CE32A2E9E8CBULL,
		0xBCA7EE534B321EB5ULL,
		0x0F9FDB119D43BB94ULL,
		0x1D443194A862F6B1ULL,
		0xE499DDD533F7F75BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF091475780000000ULL,
		0x80E72FC4707D43E4ULL,
		0x2A2E9E8CB221C80DULL,
		0x34B321EB510E6CE3ULL,
		0x19D43BB94BCA7EE5ULL,
		0x4A862F6B10F9FDB1ULL,
		0x533F7F75B1D44319ULL,
		0x000000000E499DDDULL
	}};
	shift = 28;
	printf("Test Case 25\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x102A8DDD16BE1850ULL,
		0x4FB368B66EDAD7E5ULL,
		0x6DA2586D5657F3E6ULL,
		0xDB570C72621DCAE5ULL,
		0x24CB7229683EEDADULL,
		0xA7954F7DADC4D854ULL,
		0x049A361CA7801A33ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0AA37745AF861400ULL,
		0xECDA2D9BB6B5F944ULL,
		0x68961B5595FCF993ULL,
		0xD5C31C988772B95BULL,
		0x32DC8A5A0FBB6B76ULL,
		0xE553DF6B71361509ULL,
		0x268D8729E0068CE9ULL,
		0x0000000000000001ULL
	}};
	shift = 6;
	printf("Test Case 26\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x2E2A6136FB58AD3EULL,
		0x2AFC1174FA3965A6ULL,
		0x532C2B151003456DULL,
		0xD9BF97676800FD9BULL,
		0x27EC5F40BF4F981EULL,
		0xB9D473F7533EF0A6ULL,
		0x932C81DF0E7584D6ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2B4F800000000000ULL,
		0x59698B8A984DBED6ULL,
		0xD15B4ABF045D3E8EULL,
		0x3F66D4CB0AC54400ULL,
		0xE607B66FE5D9DA00ULL,
		0xBC2989FB17D02FD3ULL,
		0x6135AE751CFDD4CFULL,
		0x000024CB2077C39DULL
	}};
	shift = 46;
	printf("Test Case 27\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xE64DDD5959AFEEB6ULL,
		0x391ADA2FE663DBFCULL,
		0x0FE08E6D7FC5FC78ULL,
		0xA7E982461F731756ULL,
		0x1CD47F2F1D80DED1ULL,
		0x2DEA13D3392B3E29ULL,
		0xC3A1F28E9FD8808EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9937756566BFBAD8ULL,
		0xE46B68BF998F6FF3ULL,
		0x3F8239B5FF17F1E0ULL,
		0x9FA609187DCC5D58ULL,
		0x7351FCBC76037B46ULL,
		0xB7A84F4CE4ACF8A4ULL,
		0x0E87CA3A7F620238ULL,
		0x0000000000000003ULL
	}};
	shift = 2;
	printf("Test Case 28\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xC334ACDAD1A84B46ULL,
		0xD59C349FFB9755AAULL,
		0xAB39441644286BE8ULL,
		0xCAE8DB00F2BDAA72ULL,
		0x5D16A40CC27A10E9ULL,
		0x1279FA9E600E7B34ULL,
		0x7E8249222A25643CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x566D68D425A30000ULL,
		0x1A4FFDCBAAD5619AULL,
		0xA20B221435F46ACEULL,
		0x6D80795ED539559CULL,
		0x5206613D0874E574ULL,
		0xFD4F30073D9A2E8BULL,
		0x24911512B21E093CULL,
		0x0000000000003F41ULL
	}};
	shift = 15;
	printf("Test Case 29\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x9B4FE8481721F166ULL,
		0xF7D1C15165C06D9CULL,
		0xADF1D6A1C76102AFULL,
		0xF07057FDE8BD847CULL,
		0xE13EE4925E312F7DULL,
		0xE07AEE410A2029DFULL,
		0x04F34B24EFD1CD1CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF4240B90F8B30000ULL,
		0xE0A8B2E036CE4DA7ULL,
		0xEB50E3B08157FBE8ULL,
		0x2BFEF45EC23E56F8ULL,
		0x72492F1897BEF838ULL,
		0x7720851014EFF09FULL,
		0xA59277E8E68E703DULL,
		0x0000000000000279ULL
	}};
	shift = 15;
	printf("Test Case 30\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x865ECBB46C88950FULL,
		0x9DB445D1B2CA05B5ULL,
		0x15D52E174F8A9072ULL,
		0x4091435D9820B08EULL,
		0xBF3CF522C852176CULL,
		0xD2BB34914665DCDBULL,
		0x21958B7B4981C99FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB222543C00000000ULL,
		0xCB2816D6197B2ED1ULL,
		0x3E2A41CA76D11746ULL,
		0x6082C2385754B85DULL,
		0x21485DB102450D76ULL,
		0x1997736EFCF3D48BULL,
		0x2607267F4AECD245ULL,
		0x0000000086562DEDULL
	}};
	shift = 34;
	printf("Test Case 31\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xBD11BE1D1046FD08ULL,
		0x3D3A11A845722006ULL,
		0xA979186CA5AAD3C9ULL,
		0xE3A4B96CE59CA222ULL,
		0xA858A42F64D3BE9DULL,
		0x99449AE741EE5FDBULL,
		0x15CF70BFC1B09E4EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3A208DFA10000000ULL,
		0x508AE4400D7A237CULL,
		0xD94B55A7927A7423ULL,
		0xD9CB39444552F230ULL,
		0x5EC9A77D3BC74972ULL,
		0xCE83DCBFB750B148ULL,
		0x7F83613C9D328935ULL,
		0x00000000002B9EE1ULL
	}};
	shift = 25;
	printf("Test Case 32\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x70836C2D71D8A867ULL,
		0x87B4154B72F52338ULL,
		0x517681122821BE52ULL,
		0x0777D25606CDBF45ULL,
		0x06C6E4B4FFA70723ULL,
		0xB353589AF2B92EBCULL,
		0x540E0EF3B005D1D0ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3B150CE000000000ULL,
		0x5EA4670E106D85AEULL,
		0x0437CA50F682A96EULL,
		0xD9B7E8AA2ED02245ULL,
		0xF4E0E460EEFA4AC0ULL,
		0x5725D780D8DC969FULL,
		0x00BA3A166A6B135EULL,
		0x0000000A81C1DE76ULL
	}};
	shift = 37;
	printf("Test Case 33\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xB3303E423E8F4F09ULL,
		0xD26D9F4C8A3DEE21ULL,
		0xAC0BF5E5F06585DCULL,
		0xAE645E229C941208ULL,
		0x5570CC58DA5876F5ULL,
		0xA8429CEF1433F769ULL,
		0x2D4B9681A3B672C1ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE8F4F09000000000ULL,
		0xA3DEE21B3303E423ULL,
		0x06585DCD26D9F4C8ULL,
		0xC941208AC0BF5E5FULL,
		0xA5876F5AE645E229ULL,
		0x433F7695570CC58DULL,
		0x3B672C1A8429CEF1ULL,
		0x00000002D4B9681AULL
	}};
	shift = 36;
	printf("Test Case 34\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xE3C382B3CD75CAAAULL,
		0xB24A3FACC5A61634ULL,
		0xE23AF35A464153A6ULL,
		0xF0BDB3946A409EF7ULL,
		0xCC9B3E602D374CAAULL,
		0x94A51146F2A0C579ULL,
		0xD304B7CE2356244AULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB3CD75CAAA000000ULL,
		0xACC5A61634E3C382ULL,
		0x5A464153A6B24A3FULL,
		0x946A409EF7E23AF3ULL,
		0x602D374CAAF0BDB3ULL,
		0x46F2A0C579CC9B3EULL,
		0xCE2356244A94A511ULL,
		0x0000000000D304B7ULL
	}};
	shift = 24;
	printf("Test Case 35\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xA277A05E312CC84FULL,
		0xA4286382C328C7F6ULL,
		0xD14699712CDFFEB7ULL,
		0x0CA4FEAE8042431AULL,
		0x491C8AE7CD93C7C4ULL,
		0x7869769856AD15A5ULL,
		0x2DADDBAC7FF8EFF1ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA05E312CC84F0000ULL,
		0x6382C328C7F6A277ULL,
		0x99712CDFFEB7A428ULL,
		0xFEAE8042431AD146ULL,
		0x8AE7CD93C7C40CA4ULL,
		0x769856AD15A5491CULL,
		0xDBAC7FF8EFF17869ULL,
		0x0000000000002DADULL
	}};
	shift = 16;
	printf("Test Case 36\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xD7B41B538DB3D7E5ULL,
		0x8FBD635B252F9053ULL,
		0xC931915239F07A35ULL,
		0x1CE3A2520B23DB56ULL,
		0xF3F6C4FB1C6AA170ULL,
		0xDE167747F39406BCULL,
		0xEA947DA0F86601ACULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB67AFCA000000000ULL,
		0xA5F20A7AF6836A71ULL,
		0x3E0F46B1F7AC6B64ULL,
		0x647B6AD926322A47ULL,
		0x8D542E039C744A41ULL,
		0x7280D79E7ED89F63ULL,
		0x0CC0359BC2CEE8FEULL,
		0x0000001D528FB41FULL
	}};
	shift = 37;
	printf("Test Case 37\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x7C8D1B3C40915C7DULL,
		0x52A626372E07EF5FULL,
		0xF8FCC6907653D453ULL,
		0xE3D04FB504EDA634ULL,
		0xB3520E988CD1885FULL,
		0xEC84C6E72A4A3D3AULL,
		0xDDC0E87E04CC85CDULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x15C7D00000000000ULL,
		0x7EF5F7C8D1B3C409ULL,
		0x3D45352A626372E0ULL,
		0xDA634F8FCC690765ULL,
		0x1885FE3D04FB504EULL,
		0xA3D3AB3520E988CDULL,
		0xC85CDEC84C6E72A4ULL,
		0x00000DDC0E87E04CULL
	}};
	shift = 44;
	printf("Test Case 38\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x0F0042A34C56045EULL,
		0x5BFE30916A92E0B3ULL,
		0x4B482E2BDE82AA43ULL,
		0xAF786B5BE1281858ULL,
		0xB22C496A276A4B2BULL,
		0x1D3C188E92799405ULL,
		0xACB97DE5ED24FCD1ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x34C56045E0000000ULL,
		0x16A92E0B30F0042AULL,
		0xBDE82AA435BFE309ULL,
		0xBE12818584B482E2ULL,
		0xA276A4B2BAF786B5ULL,
		0xE92799405B22C496ULL,
		0x5ED24FCD11D3C188ULL,
		0x000000000ACB97DEULL
	}};
	shift = 28;
	printf("Test Case 39\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xD240B600C3793C6DULL,
		0xEABD778641808B2DULL,
		0xC03877BB038703F1ULL,
		0xA160AEAF09362A6BULL,
		0x474C582051549DC6ULL,
		0xB3813E6BB9E05D75ULL,
		0xF108412FBFB7D8E3ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0DE4F1B400000000ULL,
		0x06022CB74902D803ULL,
		0x0E1C0FC7AAF5DE19ULL,
		0x24D8A9AF00E1DEECULL,
		0x4552771A8582BABCULL,
		0xE78175D51D316081ULL,
		0xFEDF638ECE04F9AEULL,
		0x00000003C42104BEULL
	}};
	shift = 34;
	printf("Test Case 40\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x9EED41EE2910CBEDULL,
		0xFEC66B871AA8AF47ULL,
		0x38D0205928981EBCULL,
		0x1B54E6607119C9F1ULL,
		0x688BF2122BEE2D64ULL,
		0x3BE04394546EA6EBULL,
		0xADA604D0E4B0C8A7ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB507B8A4432FB400ULL,
		0x19AE1C6AA2BD1E7BULL,
		0x408164A2607AF3FBULL,
		0x539981C46727C4E3ULL,
		0x2FC848AFB8B5906DULL,
		0x810E5151BA9BADA2ULL,
		0x98134392C3229CEFULL,
		0x00000000000002B6ULL
	}};
	shift = 10;
	printf("Test Case 41\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x2F09169679902719ULL,
		0x347D7D960AC5C081ULL,
		0x95F2A56851502CD1ULL,
		0x9B1D14D75095D396ULL,
		0x2406881200080226ULL,
		0x934F351AC8CBF0F0ULL,
		0xF26DC136BF012859ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6967990271900000ULL,
		0xD960AC5C0812F091ULL,
		0x56851502CD1347D7ULL,
		0x4D75095D39695F2AULL,
		0x812000802269B1D1ULL,
		0x51AC8CBF0F024068ULL,
		0x136BF012859934F3ULL,
		0x00000000000F26DCULL
	}};
	shift = 20;
	printf("Test Case 42\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x1DA513E3A05DAB42ULL,
		0x60EA06A236FD6536ULL,
		0xBCA101185987E173ULL,
		0xF40BB0B35BF5F997ULL,
		0x6878905C67B8F181ULL,
		0x6A0F3804FB1D38C2ULL,
		0xB48AAAEC14F975C8ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0ED289F1D02ED5A1ULL,
		0xB07503511B7EB29BULL,
		0xDE50808C2CC3F0B9ULL,
		0xFA05D859ADFAFCCBULL,
		0x343C482E33DC78C0ULL,
		0x35079C027D8E9C61ULL,
		0x5A4555760A7CBAE4ULL
	}};
	shift = 63;
	printf("Test Case 43\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x06396BE43D38A208ULL,
		0xD02AFF26EBFBFE12ULL,
		0x66493BE5F7004695ULL,
		0xACD79BC7CEEA1C8BULL,
		0x378B0045ADFCF7D5ULL,
		0xAB1D1A9E9A7BA81FULL,
		0xE77D5F8310BB466AULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7A71441000000000ULL,
		0xD7F7FC240C72D7C8ULL,
		0xEE008D2BA055FE4DULL,
		0x9DD43916CC9277CBULL,
		0x5BF9EFAB59AF378FULL,
		0x34F7503E6F16008BULL,
		0x21768CD5563A353DULL,
		0x00000001CEFABF06ULL
	}};
	shift = 33;
	printf("Test Case 44\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x8C46D801066906A8ULL,
		0x49A546337018AE8CULL,
		0xAA5BC6AB3875A4B5ULL,
		0x03B75C9951C3B138ULL,
		0x7627273EF7B384B6ULL,
		0xDDEE50EA3E9650C2ULL,
		0x1C22A7E1748738CCULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5400000000000000ULL,
		0x4646236C00833483ULL,
		0x5AA4D2A319B80C57ULL,
		0x9C552DE3559C3AD2ULL,
		0x5B01DBAE4CA8E1D8ULL,
		0x613B13939F7BD9C2ULL,
		0x666EF728751F4B28ULL,
		0x000E1153F0BA439CULL
	}};
	shift = 55;
	printf("Test Case 45\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xC8C887CBE1929508ULL,
		0xEB942B5D1F929F83ULL,
		0x29EFD324EFF7B692ULL,
		0x524B4ECC1C2994C7ULL,
		0x0CDC5F0DC64B4218ULL,
		0xF5C18DAEAF3BB4A8ULL,
		0xB992DA9B0BB9BE09ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8400000000000000ULL,
		0xC1E46443E5F0C94AULL,
		0x4975CA15AE8FC94FULL,
		0x6394F7E99277FBDBULL,
		0x0C2925A7660E14CAULL,
		0x54066E2F86E325A1ULL,
		0x04FAE0C6D7579DDAULL,
		0x005CC96D4D85DCDFULL
	}};
	shift = 55;
	printf("Test Case 46\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x8D7F6B49BF3FDBB3ULL,
		0x2728CAC826FD4585ULL,
		0x53BD45BFF1E891AEULL,
		0x63A67B8315355D4EULL,
		0x21E484E04D4A751EULL,
		0x04DC9DD59786DFA3ULL,
		0xCEA8FC799E32F21DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD7F6B49BF3FDBB30ULL,
		0x728CAC826FD45858ULL,
		0x3BD45BFF1E891AE2ULL,
		0x3A67B8315355D4E5ULL,
		0x1E484E04D4A751E6ULL,
		0x4DC9DD59786DFA32ULL,
		0xEA8FC799E32F21D0ULL,
		0x000000000000000CULL
	}};
	shift = 4;
	printf("Test Case 47\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x9D1041DEAD6AD5F2ULL,
		0x456C722360C0056AULL,
		0xBBA119400B0CEBE1ULL,
		0x8CE1B69EF6858C62ULL,
		0x761A7B2BA37B195DULL,
		0xD3A33FE1AE3B4628ULL,
		0xF2E410AC1DAFD105ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x041DEAD6AD5F2000ULL,
		0xC722360C0056A9D1ULL,
		0x119400B0CEBE1456ULL,
		0x1B69EF6858C62BBAULL,
		0xA7B2BA37B195D8CEULL,
		0x33FE1AE3B4628761ULL,
		0x410AC1DAFD105D3AULL,
		0x0000000000000F2EULL
	}};
	shift = 12;
	printf("Test Case 48\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xC9E9436373759336ULL,
		0xEB022F05880CF9B4ULL,
		0x3AF9B3BDFEBF8A74ULL,
		0x3863B84DF78BB06EULL,
		0xE442041DDB7BE702ULL,
		0x1DBD7E24538E9FC6ULL,
		0xD2A139FE91D824DFULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3637375933600000ULL,
		0xF05880CF9B4C9E94ULL,
		0x3BDFEBF8A74EB022ULL,
		0x84DF78BB06E3AF9BULL,
		0x41DDB7BE7023863BULL,
		0xE24538E9FC6E4420ULL,
		0x9FE91D824DF1DBD7ULL,
		0x00000000000D2A13ULL
	}};
	shift = 20;
	printf("Test Case 49\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xDA49EAB2BE8B576EULL,
		0xB0C850F149694DBDULL,
		0xD14FBBC1173F5922ULL,
		0x1C6E47A188703FA0ULL,
		0xE2B71D5212CEFADEULL,
		0x0592C11DCB76B733ULL,
		0xA98276145D750EB3ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBE8B576E00000000ULL,
		0x49694DBDDA49EAB2ULL,
		0x173F5922B0C850F1ULL,
		0x88703FA0D14FBBC1ULL,
		0x12CEFADE1C6E47A1ULL,
		0xCB76B733E2B71D52ULL,
		0x5D750EB30592C11DULL,
		0x00000000A9827614ULL
	}};
	shift = 32;
	printf("Test Case 50\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x2057601C65078B40ULL,
		0x4E41DEE93E962E17ULL,
		0xAD237C78A3B98CF6ULL,
		0x5BEB7C64F9933F1AULL,
		0x6BB975269DC93CBDULL,
		0x660C333BA0086C1CULL,
		0x2AF6B23476D95AA7ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB00E3283C5A0000ULL,
		0x0EF749F4B170B902ULL,
		0x1BE3C51DCC67B272ULL,
		0x5BE327CC99F8D569ULL,
		0xCBA934EE49E5EADFULL,
		0x6199DD004360E35DULL,
		0xB591A3B6CAD53B30ULL,
		0x0000000000000157ULL
	}};
	shift = 11;
	printf("Test Case 51\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xDBCBEE1DA1843AAEULL,
		0x0AAC931731E59180ULL,
		0x9B5CFEAF42CA6AA0ULL,
		0x8DF5393766CFC440ULL,
		0x5F52AF53EAABAF12ULL,
		0xAC8A635F6B0E7C06ULL,
		0x301DD27221C830A3ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3B4308755C000000ULL,
		0x2E63CB2301B797DCULL,
		0x5E8594D540155926ULL,
		0x6ECD9F888136B9FDULL,
		0xA7D5575E251BEA72ULL,
		0xBED61CF80CBEA55EULL,
		0xE4439061475914C6ULL,
		0x0000000000603BA4ULL
	}};
	shift = 25;
	printf("Test Case 52\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x7ECBE02198CCE06EULL,
		0xC8A0F6F988FDDA46ULL,
		0xE77C9DD2C21F3037ULL,
		0x4892D0849B0047F4ULL,
		0x06862990CD354BB5ULL,
		0xCCFAF0A407BC2E38ULL,
		0x193970683AA8F8AAULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x3F65F010CC667037ULL,
		0xE4507B7CC47EED23ULL,
		0x73BE4EE9610F981BULL,
		0xA44968424D8023FAULL,
		0x034314C8669AA5DAULL,
		0x667D785203DE171CULL,
		0x0C9CB8341D547C55ULL
	}};
	shift = 63;
	printf("Test Case 53\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x3501AF424057033FULL,
		0x27E5B02A70AF8E9DULL,
		0xACEFB7AD7EC8CC8EULL,
		0x71038DE84FDEC205ULL,
		0xDAA1C20B98408DF9ULL,
		0xBC9EB8AE30A72E2BULL,
		0x2F50DBD0225BEAACULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7A1202B819F80000ULL,
		0x8153857C74E9A80DULL,
		0xBD6BF64664713F2DULL,
		0x6F427EF6102D677DULL,
		0x105CC2046FCB881CULL,
		0xC5718539715ED50EULL,
		0xDE8112DF5565E4F5ULL,
		0x0000000000017A86ULL
	}};
	shift = 19;
	printf("Test Case 54\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x02E0D9664378D263ULL,
		0xFD33CB6CF9E9FDBCULL,
		0x71E793B9F8192FE1ULL,
		0xE559C8EF8F2A08F9ULL,
		0x9FFC499687F99D53ULL,
		0x4D61DF719E2B7DAFULL,
		0x755A76027CC82968ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6F1A4C6000000000ULL,
		0x3D3FB7805C1B2CC8ULL,
		0x0325FC3FA6796D9FULL,
		0xE5411F2E3CF2773FULL,
		0xFF33AA7CAB391DF1ULL,
		0xC56FB5F3FF8932D0ULL,
		0x99052D09AC3BEE33ULL,
		0x0000000EAB4EC04FULL
	}};
	shift = 37;
	printf("Test Case 55\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x44CB14D4F171E53DULL,
		0xEC7660906FFDECA5ULL,
		0xB8162D72EBE7DC14ULL,
		0x0B5047F778FD697CULL,
		0xEFE98D3CD2526141ULL,
		0x0582313689D36901ULL,
		0x4467CD0B2CC59B5CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x53C5C794F4000000ULL,
		0x41BFF7B295132C53ULL,
		0xCBAF9F7053B1D982ULL,
		0xDDE3F5A5F2E058B5ULL,
		0xF3494985042D411FULL,
		0xDA274DA407BFA634ULL,
		0x2CB3166D701608C4ULL,
		0x0000000001119F34ULL
	}};
	shift = 26;
	printf("Test Case 56\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x30E4A2D43A9A611FULL,
		0x574649174AFB8ED4ULL,
		0x1136C586E156BA5CULL,
		0x22C3607FA36AAF8EULL,
		0xFC6960ED81382F49ULL,
		0x014CB490082A32AFULL,
		0x7A824446F4F860D0ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x534C23E000000000ULL,
		0x5F71DA861C945A87ULL,
		0x2AD74B8AE8C922E9ULL,
		0x6D55F1C226D8B0DCULL,
		0x2705E924586C0FF4ULL,
		0x054655FF8D2C1DB0ULL,
		0x9F0C1A0029969201ULL,
		0x0000000F504888DEULL
	}};
	shift = 37;
	printf("Test Case 57\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x3417B9C20DFB21DEULL,
		0x706A81EB269DD7EFULL,
		0xB77F6FD0F64DFB93ULL,
		0xAE74B60CACE0BB92ULL,
		0x0801E2567270F3EDULL,
		0xA71BF31966403288ULL,
		0x118E7073A10C8465ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE70837EC87780000ULL,
		0x07AC9A775FBCD05EULL,
		0xBF43D937EE4DC1AAULL,
		0xD832B382EE4ADDFDULL,
		0x8959C9C3CFB6B9D2ULL,
		0xCC659900CA202007ULL,
		0xC1CE843211969C6FULL,
		0x0000000000004639ULL
	}};
	shift = 18;
	printf("Test Case 58\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x5639726C343C6B33ULL,
		0x4C8E276DED35D38CULL,
		0x45A7A487942872AFULL,
		0xEE6980FABA7B651FULL,
		0x3BAD636C37C59271ULL,
		0x80204FA3219543A8ULL,
		0xFE8281BEAF946AB0ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCC00000000000000ULL,
		0x3158E5C9B0D0F1ACULL,
		0xBD32389DB7B4D74EULL,
		0x7D169E921E50A1CAULL,
		0xC7B9A603EAE9ED94ULL,
		0xA0EEB58DB0DF1649ULL,
		0xC200813E8C86550EULL,
		0x03FA0A06FABE51AAULL
	}};
	shift = 58;
	printf("Test Case 59\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x38ACE3E72315DC19ULL,
		0x8849420E32BCDA08ULL,
		0xF0193993CD482578ULL,
		0x7395FC5B74386730ULL,
		0xED7DE82B804995FBULL,
		0x62EAF711A2603661ULL,
		0x51FC32F88515283FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC5671F3918AEE0C8ULL,
		0x424A107195E6D041ULL,
		0x80C9CC9E6A412BC4ULL,
		0x9CAFE2DBA1C33987ULL,
		0x6BEF415C024CAFDBULL,
		0x1757B88D1301B30FULL,
		0x8FE197C428A941FBULL,
		0x0000000000000002ULL
	}};
	shift = 3;
	printf("Test Case 60\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x9DE54FD463C35007ULL,
		0xD3C2CA093AF6A129ULL,
		0xF7CD02C23AE0EF1CULL,
		0x3DDE51656D41A8ACULL,
		0xC4BC50236E852F6DULL,
		0xC52B872ADA2676C8ULL,
		0x0BF5B08AFD3038A2ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x53F518F0D401C000ULL,
		0xB2824EBDA84A6779ULL,
		0x40B08EB83BC734F0ULL,
		0x94595B506A2B3DF3ULL,
		0x1408DBA14BDB4F77ULL,
		0xE1CAB6899DB2312FULL,
		0x6C22BF4C0E28B14AULL,
		0x00000000000002FDULL
	}};
	shift = 14;
	printf("Test Case 61\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x10970D166B53760CULL,
		0x3937382EF61CC9F6ULL,
		0x9632B6C08291F13FULL,
		0x29BDAF03FB1AE4E0ULL,
		0x4B7B8A8F1124FE56ULL,
		0x745AD541DB8C2641ULL,
		0x3BE5E822F3CB39FEULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB060000000000000ULL,
		0x4FB084B868B35A9BULL,
		0x89F9C9B9C177B0E6ULL,
		0x2704B195B604148FULL,
		0xF2B14DED781FD8D7ULL,
		0x320A5BDC54788927ULL,
		0xCFF3A2D6AA0EDC61ULL,
		0x0001DF2F41179E59ULL
	}};
	shift = 51;
	printf("Test Case 62\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x051EFB1E953BD0B8ULL,
		0x3D872509D7878DE8ULL,
		0x97E21CF3085BD4ADULL,
		0xD422F3BD34E2E5D6ULL,
		0xB27EF701F1AA13CFULL,
		0x26F3052F87BF8429ULL,
		0x4261BBD85BDEF505ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x00A3DF63D2A77A17ULL,
		0xA7B0E4A13AF0F1BDULL,
		0xD2FC439E610B7A95ULL,
		0xFA845E77A69C5CBAULL,
		0x364FDEE03E354279ULL,
		0xA4DE60A5F0F7F085ULL,
		0x084C377B0B7BDEA0ULL
	}};
	shift = 61;
	printf("Test Case 63\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xBC731ADEAD30FD89ULL,
		0x53A502C94D706494ULL,
		0x86E5848A4FFFE935ULL,
		0x7BAE29C1E6DEA992ULL,
		0x52139F31690167A0ULL,
		0xDAEA8C8E318BA555ULL,
		0xEB6F0702BE7DAF13ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x30FD890000000000ULL,
		0x706494BC731ADEADULL,
		0xFFE93553A502C94DULL,
		0xDEA99286E5848A4FULL,
		0x0167A07BAE29C1E6ULL,
		0x8BA55552139F3169ULL,
		0x7DAF13DAEA8C8E31ULL,
		0x000000EB6F0702BEULL
	}};
	shift = 40;
	printf("Test Case 64\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x3D59D97D4D52E859ULL,
		0xCDBD756078794EF9ULL,
		0xED96E0B19230F900ULL,
		0x8FC87E0AADF10736ULL,
		0xD0E8E4399C98DAA4ULL,
		0x46F973BEAF01722AULL,
		0x06501038AF1770F1ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA9AA5D0B20000000ULL,
		0x0F0F29DF27AB3B2FULL,
		0x32461F2019B7AEACULL,
		0x55BE20E6DDB2DC16ULL,
		0x33931B5491F90FC1ULL,
		0xD5E02E455A1D1C87ULL,
		0x15E2EE1E28DF2E77ULL,
		0x0000000000CA0207ULL
	}};
	shift = 29;
	printf("Test Case 65\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x5051E82D003038D9ULL,
		0x1E87F43C8F215BBEULL,
		0xCFE63B15F84AB76FULL,
		0x27D78C3FD41D1715ULL,
		0xD045CFC2F8F2AF7AULL,
		0x19234EB49D966A7AULL,
		0x74E0F5A6E776BBC1ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x28F41680181C6C80ULL,
		0x43FA1E4790ADDF28ULL,
		0xF31D8AFC255BB78FULL,
		0xEBC61FEA0E8B8AE7ULL,
		0x22E7E17C7957BD13ULL,
		0x91A75A4ECB353D68ULL,
		0x707AD373BB5DE08CULL,
		0x000000000000003AULL
	}};
	shift = 7;
	printf("Test Case 66\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x08395DF91444D0B1ULL,
		0xA1C2CA6260C97B59ULL,
		0x97DBDED052EADCDEULL,
		0xB598B1D2C7794970ULL,
		0x8A5E8AE2285FCD4CULL,
		0x0C4197F52400C09AULL,
		0xEDE736390BAEF8C6ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCAEFC8A226858800ULL,
		0x165313064BDAC841ULL,
		0xDEF6829756E6F50EULL,
		0xC58E963BCA4B84BEULL,
		0xF4571142FE6A65ACULL,
		0x0CBFA9200604D452ULL,
		0x39B1C85D77C63062ULL,
		0x000000000000076FULL
	}};
	shift = 11;
	printf("Test Case 67\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x0106BBFC69B23343ULL,
		0x95664AEC217C144DULL,
		0x24BB284061210E93ULL,
		0x4640655793F46865ULL,
		0x9E4B47A98928DC8DULL,
		0x750D73EBFE836740ULL,
		0xDD9F1D4CBBF2EA46ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0835DFE34D919A18ULL,
		0xAB3257610BE0A268ULL,
		0x25D942030908749CULL,
		0x32032ABC9FA34329ULL,
		0xF25A3D4C4946E46AULL,
		0xA86B9F5FF41B3A04ULL,
		0xECF8EA65DF975233ULL,
		0x0000000000000006ULL
	}};
	shift = 3;
	printf("Test Case 68\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xBE2A2E3D80D8B121ULL,
		0xC1EA163D4C91C056ULL,
		0x200F7A73129D2261ULL,
		0xB639B41E0BC12ADFULL,
		0x70703DBBFAB07A3AULL,
		0x5E81B8F6A9656101ULL,
		0x5B1BD9A3E519469FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x06C5890800000000ULL,
		0x648E02B5F15171ECULL,
		0x94E9130E0F50B1EAULL,
		0x5E0956F9007BD398ULL,
		0xD583D1D5B1CDA0F0ULL,
		0x4B2B080B8381EDDFULL,
		0x28CA34FAF40DC7B5ULL,
		0x00000002D8DECD1FULL
	}};
	shift = 35;
	printf("Test Case 69\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xED58423DBF41FF73ULL,
		0x823327577CA3D3D9ULL,
		0x4B314BABD0D6A289ULL,
		0x97CFC9455DC514B3ULL,
		0x9D1AC4B2E54ADD0EULL,
		0xBDD30177BBFEE0AFULL,
		0xB61C8C00F72D8992ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x211EDFA0FFB98000ULL,
		0x93ABBE51E9ECF6ACULL,
		0xA5D5E86B5144C119ULL,
		0xE4A2AEE28A59A598ULL,
		0x625972A56E874BE7ULL,
		0x80BBDDFF7057CE8DULL,
		0x46007B96C4C95EE9ULL,
		0x0000000000005B0EULL
	}};
	shift = 15;
	printf("Test Case 70\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x1370F201FD4639A2ULL,
		0x296336EAB18AB47CULL,
		0x7BABA001E121245EULL,
		0x401CD98E15EDC532ULL,
		0x6FF28E621A46D04BULL,
		0x190FBC3E4003E965ULL,
		0x4BE44FE9BF0A50E7ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC3C807F518E68800ULL,
		0x8CDBAAC62AD1F04DULL,
		0xAE800784849178A5ULL,
		0x73663857B714C9EEULL,
		0xCA3988691B412D00ULL,
		0x3EF0F9000FA595BFULL,
		0x913FA6FC29439C64ULL,
		0x000000000000012FULL
	}};
	shift = 10;
	printf("Test Case 71\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xA2208E1EB3E13C1DULL,
		0x7C8B21618FE3D24AULL,
		0x84BEAF7CC0C90C7DULL,
		0xECE6A5818D6041A0ULL,
		0x31AAA74D24C35DC9ULL,
		0xF0B615A1E9F5026AULL,
		0xF06995F1D0FF10F1ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2783A00000000000ULL,
		0x7A49544411C3D67CULL,
		0x218FAF91642C31FCULL,
		0x08341097D5EF9819ULL,
		0x6BB93D9CD4B031ACULL,
		0xA04D463554E9A498ULL,
		0xE21E3E16C2B43D3EULL,
		0x00001E0D32BE3A1FULL
	}};
	shift = 45;
	printf("Test Case 72\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x2BCF1D47330469A2ULL,
		0x967633270CE4F203ULL,
		0x23EA9E185B1745B5ULL,
		0x56D6EBC497E2AF43ULL,
		0xBD43DAD25F42AD42ULL,
		0x95BA46C95B572B77ULL,
		0xBB91C290E05F7BDEULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5E78EA3998234D10ULL,
		0xB3B1993867279019ULL,
		0x1F54F0C2D8BA2DACULL,
		0xB6B75E24BF157A19ULL,
		0xEA1ED692FA156A12ULL,
		0xADD2364ADAB95BBDULL,
		0xDC8E148702FBDEF4ULL,
		0x0000000000000005ULL
	}};
	shift = 3;
	printf("Test Case 73\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x15A31CA624C34EC1ULL,
		0x5F4069B611DA02B6ULL,
		0xCAFF283205B72507ULL,
		0x8FAC0D7EF7588A55ULL,
		0x38AEF20F52FC7CF8ULL,
		0xC6D800573679F1EAULL,
		0x5A1B9D2FBF6995AEULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0D3B040000000000ULL,
		0x680AD8568C729893ULL,
		0xDC941D7D01A6D847ULL,
		0x6229572BFCA0C816ULL,
		0xF1F3E23EB035FBDDULL,
		0xE7C7A8E2BBC83D4BULL,
		0xA656BB1B60015CD9ULL,
		0x000001686E74BEFDULL
	}};
	shift = 42;
	printf("Test Case 74\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x2D8E4E8BC1C3D019ULL,
		0xBD9F9B826553CC2FULL,
		0x439AA5AD0B4A3890ULL,
		0xA8BB33A8597D36DBULL,
		0x85B856661EA4486AULL,
		0xAA63994D46B459DEULL,
		0xEAF36B9C60FD2922ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0640000000000000ULL,
		0x0BCB6393A2F070F4ULL,
		0x242F67E6E09954F3ULL,
		0xB6D0E6A96B42D28EULL,
		0x1AAA2ECCEA165F4DULL,
		0x77A16E159987A912ULL,
		0x48AA98E65351AD16ULL,
		0x003ABCDAE7183F4AULL
	}};
	shift = 54;
	printf("Test Case 75\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x23CF5027B6C28FDCULL,
		0x1E50434E113CC87FULL,
		0xADF8F80D9ABDFE40ULL,
		0x4910507CD70F683AULL,
		0xBA1B78240A8E5D7FULL,
		0x5CEF110E81AB54DDULL,
		0xF5C213271201C053ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB800000000000000ULL,
		0xFE479EA04F6D851FULL,
		0x803CA0869C227990ULL,
		0x755BF1F01B357BFCULL,
		0xFE9220A0F9AE1ED0ULL,
		0xBB7436F048151CBAULL,
		0xA6B9DE221D0356A9ULL,
		0x01EB84264E240380ULL
	}};
	shift = 57;
	printf("Test Case 76\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x8467D2F079195658ULL,
		0x3EEC0C6FF3026E94ULL,
		0x20EBEFB769775082ULL,
		0xB9312FEEDC198E4CULL,
		0x36EC9CE444CC0652ULL,
		0x188168EA3A087974ULL,
		0xF9BCE739AEC7D83AULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF079195658000000ULL,
		0x6FF3026E948467D2ULL,
		0xB7697750823EEC0CULL,
		0xEEDC198E4C20EBEFULL,
		0xE444CC0652B9312FULL,
		0xEA3A08797436EC9CULL,
		0x39AEC7D83A188168ULL,
		0x0000000000F9BCE7ULL
	}};
	shift = 24;
	printf("Test Case 77\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xFC692DA1ACB7C946ULL,
		0x9E31BE6DFACBF131ULL,
		0x0708AEA73385B122ULL,
		0xA5386CF2CD3F035FULL,
		0x4D28CCAC09E667DBULL,
		0x4CCAC7EF4DC33BE4ULL,
		0x9459938CA8307D13ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD0D65BE4A3000000ULL,
		0x36FD65F898FE3496ULL,
		0x5399C2D8914F18DFULL,
		0x79669F81AF838457ULL,
		0x5604F333EDD29C36ULL,
		0xF7A6E19DF2269466ULL,
		0xC654183E89A66563ULL,
		0x00000000004A2CC9ULL
	}};
	shift = 23;
	printf("Test Case 78\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xF68251A1D26587FAULL,
		0xF0772419C9E9BAA1ULL,
		0x1936E2DDEFB78EA3ULL,
		0x927CD91429A2DC62ULL,
		0x5CF016100D38AB74ULL,
		0xCA35D3BE8C59C893ULL,
		0x6A55C6CA0CD7556FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3A4CB0FF40000000ULL,
		0x393D37543ED04A34ULL,
		0xBDF6F1D47E0EE483ULL,
		0x85345B8C4326DC5BULL,
		0x01A7156E924F9B22ULL,
		0xD18B39126B9E02C2ULL,
		0x419AEAADF946BA77ULL,
		0x000000000D4AB8D9ULL
	}};
	shift = 29;
	printf("Test Case 79\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xE9BAE3F849C7E84FULL,
		0xA0231E55D3334A39ULL,
		0x5E1BD9DF7A6D4D1BULL,
		0x68DDBDD30C4F66BEULL,
		0xB4031F80C703A6E8ULL,
		0x74BC11D29EAF8AF1ULL,
		0x66D5743D92EE1AB2ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4F00000000000000ULL,
		0x39E9BAE3F849C7E8ULL,
		0x1BA0231E55D3334AULL,
		0xBE5E1BD9DF7A6D4DULL,
		0xE868DDBDD30C4F66ULL,
		0xF1B4031F80C703A6ULL,
		0xB274BC11D29EAF8AULL,
		0x0066D5743D92EE1AULL
	}};
	shift = 56;
	printf("Test Case 80\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x78862D8C21B2E081ULL,
		0x0E5BA3F1EEDD61E4ULL,
		0xB6EC68BF6F682340ULL,
		0x8143EA9C943ED2CFULL,
		0xADC5E36C10FC9F8CULL,
		0x89EF135D5E489851ULL,
		0xE1EEEF51D3406911ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCB82040000000000ULL,
		0x758791E218B63086ULL,
		0xA08D00396E8FC7BBULL,
		0xFB4B3EDBB1A2FDBDULL,
		0xF27E32050FAA7250ULL,
		0x226146B7178DB043ULL,
		0x01A44627BC4D7579ULL,
		0x00000387BBBD474DULL
	}};
	shift = 42;
	printf("Test Case 81\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x9FE6E77908BD506CULL,
		0x47047D5892356D87ULL,
		0x0648025EB8A23711ULL,
		0x405AF5D623CE66B7ULL,
		0xDA54398EA18097AEULL,
		0x1EFFFFFEE5D1D8ABULL,
		0xECAC714A2E6B2C51ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6E77908BD506C000ULL,
		0x47D5892356D879FEULL,
		0x8025EB8A23711470ULL,
		0xAF5D623CE66B7064ULL,
		0x4398EA18097AE405ULL,
		0xFFFFEE5D1D8ABDA5ULL,
		0xC714A2E6B2C511EFULL,
		0x0000000000000ECAULL
	}};
	shift = 12;
	printf("Test Case 82\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xA09BA29A461E8A1FULL,
		0xB1B8BAE734E1856FULL,
		0x26888A6830E2B78BULL,
		0x5D7D4FDD340F8E95ULL,
		0x57BDC9DEBFA1D492ULL,
		0x95B728D1CD35A896ULL,
		0xF06E5A6608573851ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6E8A69187A287C00ULL,
		0xE2EB9CD38615BE82ULL,
		0x2229A0C38ADE2EC6ULL,
		0xF53F74D03E3A549AULL,
		0xF7277AFE87524975ULL,
		0xDCA34734D6A2595EULL,
		0xB96998215CE14656ULL,
		0x00000000000003C1ULL
	}};
	shift = 10;
	printf("Test Case 83\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xC42D4357729BC941ULL,
		0x75C385DB2F842427ULL,
		0xB8164BB4E8E734B3ULL,
		0xFE219E06326FBD49ULL,
		0x162A691BBA9A9B21ULL,
		0x2EB4F7C07531F8F9ULL,
		0xA6D9E80B0CE21039ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9410000000000000ULL,
		0x427C42D4357729BCULL,
		0x4B375C385DB2F842ULL,
		0xD49B8164BB4E8E73ULL,
		0xB21FE219E06326FBULL,
		0x8F9162A691BBA9A9ULL,
		0x0392EB4F7C07531FULL,
		0x000A6D9E80B0CE21ULL
	}};
	shift = 52;
	printf("Test Case 84\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x1002892773B0F101ULL,
		0xBE24DD4453B662C5ULL,
		0xE7E648DFE6F06153ULL,
		0xECCA8C31408B1FBDULL,
		0xE2B26F3EC6EA8BA5ULL,
		0x94F81F919702481FULL,
		0x9DA6AF6CC21B8465ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1002892773B0F101ULL,
		0xBE24DD4453B662C5ULL,
		0xE7E648DFE6F06153ULL,
		0xECCA8C31408B1FBDULL,
		0xE2B26F3EC6EA8BA5ULL,
		0x94F81F919702481FULL,
		0x9DA6AF6CC21B8465ULL,
		0x0000000000000000ULL
	}};
	shift = 0;
	printf("Test Case 85\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x41544060560D2467ULL,
		0x2453BB9619210B52ULL,
		0x9B1D5FFBC3CA6588ULL,
		0x4F4035801A9C2653ULL,
		0x9E27A2265668E2DBULL,
		0xDEF93E961960D82FULL,
		0x42C93B446F896C35ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x01815834919C0000ULL,
		0xEE5864842D490551ULL,
		0x7FEF0F299620914EULL,
		0xD6006A70994E6C75ULL,
		0x889959A38B6D3D00ULL,
		0xFA58658360BE789EULL,
		0xED11BE25B0D77BE4ULL,
		0x0000000000010B24ULL
	}};
	shift = 18;
	printf("Test Case 86\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xD1F29B3DFF2A0084ULL,
		0x4C0123274F870B83ULL,
		0x45C324C1931DFF96ULL,
		0x646ADD7D542892F9ULL,
		0xF0082C4461BC7DAEULL,
		0x8C48A6B6CB71FDC9ULL,
		0xE9614919C827704CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1F29B3DFF2A00840ULL,
		0xC0123274F870B83DULL,
		0x5C324C1931DFF964ULL,
		0x46ADD7D542892F94ULL,
		0x0082C4461BC7DAE6ULL,
		0xC48A6B6CB71FDC9FULL,
		0x9614919C827704C8ULL,
		0x000000000000000EULL
	}};
	shift = 4;
	printf("Test Case 87\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x5E8B55CE3A05BC22ULL,
		0x85D1341AD841BEFDULL,
		0x427BE4790CE18094ULL,
		0xB981AA7A25682337ULL,
		0x473A218F9B806275ULL,
		0xFE500817C5221061ULL,
		0x8E82480F54239AD2ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x55CE3A05BC220000ULL,
		0x341AD841BEFD5E8BULL,
		0xE4790CE1809485D1ULL,
		0xAA7A25682337427BULL,
		0x218F9B806275B981ULL,
		0x0817C5221061473AULL,
		0x480F54239AD2FE50ULL,
		0x0000000000008E82ULL
	}};
	shift = 16;
	printf("Test Case 88\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x0ED6C0D2E7C5B208ULL,
		0xD33D13584CD5DDFDULL,
		0x250F0B31D7BD9694ULL,
		0xF3C11A849791137BULL,
		0xA3D10A0558C3F98BULL,
		0xBCEE780D7F5ED921ULL,
		0xA381CFEB777DB3DFULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0400000000000000ULL,
		0xFE876B606973E2D9ULL,
		0x4A699E89AC266AEEULL,
		0xBD92878598EBDECBULL,
		0xC5F9E08D424BC889ULL,
		0x90D1E88502AC61FCULL,
		0xEFDE773C06BFAF6CULL,
		0x0051C0E7F5BBBED9ULL
	}};
	shift = 55;
	printf("Test Case 89\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xB5CC7A76CDC5235CULL,
		0x3B3F80174353FD0DULL,
		0x0F5C9A32313927E6ULL,
		0x0B7F0D8BD130A925ULL,
		0x0C4966A5C0F9AA23ULL,
		0xA57BB834A2BE4E2FULL,
		0x96BD07439B520E67ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6B98F4ED9B8A46B8ULL,
		0x767F002E86A7FA1BULL,
		0x1EB9346462724FCCULL,
		0x16FE1B17A261524AULL,
		0x1892CD4B81F35446ULL,
		0x4AF77069457C9C5EULL,
		0x2D7A0E8736A41CCFULL,
		0x0000000000000001ULL
	}};
	shift = 1;
	printf("Test Case 90\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xB9CA5E84560D06D4ULL,
		0x04FF82EA17AA747DULL,
		0x635486A43CB3EF41ULL,
		0xC4898B2C53292D80ULL,
		0xB5FB35A2AE2FB0E3ULL,
		0x32C54F9417061A88ULL,
		0x18CA3E960977A5E2ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD08AC1A0DA800000ULL,
		0x5D42F54E8FB7394BULL,
		0xD487967DE8209FF0ULL,
		0x658A6525B00C6A90ULL,
		0xB455C5F61C789131ULL,
		0xF282E0C35116BF66ULL,
		0xD2C12EF4BC4658A9ULL,
		0x0000000000031947ULL
	}};
	shift = 21;
	printf("Test Case 91\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x6B68794F0273CCFFULL,
		0xD827260E51DD5A98ULL,
		0xE43FB7ADDD2AA8BBULL,
		0xD1EC95C29F776822ULL,
		0xD0B19E043EA32509ULL,
		0xB3F5DBD288536904ULL,
		0xEF3BC4DA7812D797ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x53C09CF33FC00000ULL,
		0x83947756A61ADA1EULL,
		0xEB774AAA2EF609C9ULL,
		0x70A7DDDA08B90FEDULL,
		0x810FA8C942747B25ULL,
		0xF4A214DA41342C67ULL,
		0x369E04B5E5ECFD76ULL,
		0x00000000003BCEF1ULL
	}};
	shift = 22;
	printf("Test Case 92\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x864462D2E5F70EA0ULL,
		0x089A4EEA86B146B7ULL,
		0x36A34F1CDC3CCEB2ULL,
		0xD3C2A852DCB565AEULL,
		0x8195989FC7F95C67ULL,
		0xFC317887783E080EULL,
		0xED7EBBB1FCB3C923ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x316972FB87500000ULL,
		0x27754358A35BC322ULL,
		0xA78E6E1E6759044DULL,
		0x54296E5AB2D71B51ULL,
		0xCC4FE3FCAE33E9E1ULL,
		0xBC43BC1F040740CAULL,
		0x5DD8FE59E491FE18ULL,
		0x00000000000076BFULL
	}};
	shift = 15;
	printf("Test Case 93\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x8B77B8A1420B48E6ULL,
		0xE301F351ECE07704ULL,
		0x56D515C47C322ED5ULL,
		0x21DB1C5490FA0D85ULL,
		0xB9AC0E68B275AA09ULL,
		0x893E47A7712C418FULL,
		0x25573A7FF794D15CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x50A105A473000000ULL,
		0xA8F6703B8245BBDCULL,
		0xE23E19176AF180F9ULL,
		0x2A487D06C2AB6A8AULL,
		0x34593AD50490ED8EULL,
		0xD3B89620C7DCD607ULL,
		0x3FFBCA68AE449F23ULL,
		0x000000000012AB9DULL
	}};
	shift = 23;
	printf("Test Case 94\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xE6496505A34A0CC6ULL,
		0xF58363662C16E649ULL,
		0xBBF58B32035292F1ULL,
		0x413537944FD8E69EULL,
		0x5DDE58BD74006DA0ULL,
		0x27B6ECABA3A1C37FULL,
		0x8C1893DCF6DDFF6CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC600000000000000ULL,
		0x49E6496505A34A0CULL,
		0xF1F58363662C16E6ULL,
		0x9EBBF58B32035292ULL,
		0xA0413537944FD8E6ULL,
		0x7F5DDE58BD74006DULL,
		0x6C27B6ECABA3A1C3ULL,
		0x008C1893DCF6DDFFULL
	}};
	shift = 56;
	printf("Test Case 95\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xA995215766048FCEULL,
		0x4A9C12C16FA13A9DULL,
		0x0D8EFB5BF4EFC7CCULL,
		0x0875969C8DC76F51ULL,
		0xA2AD0DBAB48716A3ULL,
		0x73CCD1584E850607ULL,
		0x269F545E21664AE7ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x42AECC091F9C0000ULL,
		0x2582DF42753B532AULL,
		0xF6B7E9DF8F989538ULL,
		0x2D391B8EDEA21B1DULL,
		0x1B75690E2D4610EBULL,
		0xA2B09D0A0C0F455AULL,
		0xA8BC42CC95CEE799ULL,
		0x0000000000004D3EULL
	}};
	shift = 17;
	printf("Test Case 96\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xCB82FA8F36EFADD2ULL,
		0x51E1E300D32D70E2ULL,
		0x47229E1467019047ULL,
		0x69C3E8B9F2F9BDB4ULL,
		0x7ED9B07C8CEADA40ULL,
		0x25DBBF0895358CA9ULL,
		0x63B2AEB346E911DCULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF51E6DDF5BA40000ULL,
		0xC601A65AE1C59705ULL,
		0x3C28CE03208EA3C3ULL,
		0xD173E5F37B688E45ULL,
		0x60F919D5B480D387ULL,
		0x7E112A6B1952FDB3ULL,
		0x5D668DD223B84BB7ULL,
		0x000000000000C765ULL
	}};
	shift = 17;
	printf("Test Case 97\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x976BB82870E99997ULL,
		0xBFFB7CDBB8109CFBULL,
		0x3B28A4C5978CBC0BULL,
		0x51A19C64A3BA56B5ULL,
		0xB9546A62CF307301ULL,
		0xD83F8301B0F5DBEBULL,
		0xFFAA65CBC3845969ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDAEE0A1C3A6665C0ULL,
		0xFEDF36EE04273EE5ULL,
		0xCA293165E32F02EFULL,
		0x68671928EE95AD4EULL,
		0x551A98B3CC1CC054ULL,
		0x0FE0C06C3D76FAEEULL,
		0xEA9972F0E1165A76ULL,
		0x000000000000003FULL
	}};
	shift = 6;
	printf("Test Case 98\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x32E060A10A9E9DEAULL,
		0x3D1C68498FB0261AULL,
		0xA64679C0F6085B86ULL,
		0x2882B8689932424BULL,
		0x57FC15C20FA09E76ULL,
		0x00E0D1402B76F475ULL,
		0x2524D59FF587DF83ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF500000000000000ULL,
		0x0D19703050854F4EULL,
		0xC31E8E3424C7D813ULL,
		0x25D3233CE07B042DULL,
		0x3B14415C344C9921ULL,
		0x3AABFE0AE107D04FULL,
		0xC1807068A015BB7AULL,
		0x0012926ACFFAC3EFULL
	}};
	shift = 55;
	printf("Test Case 99\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x1C91153E2B8BB58EULL,
		0x11AD95F967FA0FB3ULL,
		0xFA8342BB17571B34ULL,
		0x0CBF4806C8E621C9ULL,
		0xFD937451081F73CDULL,
		0x528C089823B4FA7AULL,
		0x18C40121ED840E80ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x153E2B8BB58E0000ULL,
		0x95F967FA0FB31C91ULL,
		0x42BB17571B3411ADULL,
		0x4806C8E621C9FA83ULL,
		0x7451081F73CD0CBFULL,
		0x089823B4FA7AFD93ULL,
		0x0121ED840E80528CULL,
		0x00000000000018C4ULL
	}};
	shift = 16;
	printf("Test Case 100\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xBA2416DB7B01CBF1ULL,
		0x669F65501FA19062ULL,
		0xD9FCC5294FDACE96ULL,
		0xA2D4DBC0DED0CB04ULL,
		0xD50A22EBF23201B5ULL,
		0x8577D86613705842ULL,
		0x54A35A2274F967BDULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF100000000000000ULL,
		0x62BA2416DB7B01CBULL,
		0x96669F65501FA190ULL,
		0x04D9FCC5294FDACEULL,
		0xB5A2D4DBC0DED0CBULL,
		0x42D50A22EBF23201ULL,
		0xBD8577D866137058ULL,
		0x0054A35A2274F967ULL
	}};
	shift = 56;
	printf("Test Case 101\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xCADA65A343B48CF7ULL,
		0x7D5448FE7FB4A6A7ULL,
		0xB7C6E46F22CCE30DULL,
		0x8314D448F9069006ULL,
		0x40A05F3DAE921B8EULL,
		0x107C6F6C4C531E59ULL,
		0x3AB2102A1068FD94ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA467B80000000000ULL,
		0xA5353E56D32D1A1DULL,
		0x67186BEAA247F3FDULL,
		0x348035BE37237916ULL,
		0x90DC7418A6A247C8ULL,
		0x98F2CA0502F9ED74ULL,
		0x47ECA083E37B6262ULL,
		0x000001D590815083ULL
	}};
	shift = 43;
	printf("Test Case 102\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x65F4590639348055ULL,
		0xC181794A2D4F6FC5ULL,
		0x57BE5FBBAC9B1D5AULL,
		0x57F137DD571FCE24ULL,
		0x0103EBFDDEC433D5ULL,
		0x9B680BB24882A3DAULL,
		0x455CFEAC92E840D5ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6900AA0000000000ULL,
		0x9EDF8ACBE8B20C72ULL,
		0x363AB58302F2945AULL,
		0x3F9C48AF7CBF7759ULL,
		0x8867AAAFE26FBAAEULL,
		0x0547B40207D7FBBDULL,
		0xD081AB36D0176491ULL,
		0x0000008AB9FD5925ULL
	}};
	shift = 41;
	printf("Test Case 103\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x253368E26D39ADA4ULL,
		0x6ECB15DEEE04B120ULL,
		0xF8B10780DDD828B2ULL,
		0x2EB215D768C4F0A0ULL,
		0xCD0C6BEE2D4DF360ULL,
		0xEF597DA8CD20AEEFULL,
		0x48EE004954D87794ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDA735B4800000000ULL,
		0xDC0962404A66D1C4ULL,
		0xBBB05164DD962BBDULL,
		0xD189E141F1620F01ULL,
		0x5A9BE6C05D642BAEULL,
		0x9A415DDF9A18D7DCULL,
		0xA9B0EF29DEB2FB51ULL,
		0x0000000091DC0092ULL
	}};
	shift = 33;
	printf("Test Case 104\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x8462EBCB635FDCD3ULL,
		0xB9C747F4FFE87607ULL,
		0xA1B6F1B2EE02E4BDULL,
		0x44C90B99EEAE0973ULL,
		0x7DFC0588673268E6ULL,
		0x57D1AAB4AE9043A5ULL,
		0x260F362D110D9DFBULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x23175E5B1AFEE698ULL,
		0xCE3A3FA7FF43B03CULL,
		0x0DB78D97701725EDULL,
		0x26485CCF75704B9DULL,
		0xEFE02C4339934732ULL,
		0xBE8D55A574821D2BULL,
		0x3079B168886CEFDAULL,
		0x0000000000000001ULL
	}};
	shift = 3;
	printf("Test Case 105\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xADB1F1E1564FF676ULL,
		0xA93C2253FCDCB380ULL,
		0x57A3E11009A0AD51ULL,
		0xAC693B507CDAEDEAULL,
		0x7E43C564699C83EDULL,
		0xDF04FC63D106AD1EULL,
		0x6D1991F3CA357F74ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD9D8000000000000ULL,
		0xCE02B6C7C785593FULL,
		0xB546A4F0894FF372ULL,
		0xB7A95E8F84402682ULL,
		0x0FB6B1A4ED41F36BULL,
		0xB479F90F1591A672ULL,
		0xFDD37C13F18F441AULL,
		0x0001B46647CF28D5ULL
	}};
	shift = 50;
	printf("Test Case 106\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x6AA820696618AD42ULL,
		0x13FB49B9AB318CE2ULL,
		0xB12582652FB0D702ULL,
		0x97FA22A9A8D9B1FFULL,
		0x9854E84B89F3DB22ULL,
		0x7055EED8E121309AULL,
		0xDB2B9D1E49A8E44DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0C56A10000000000ULL,
		0x98C67135541034B3ULL,
		0xD86B8109FDA4DCD5ULL,
		0x6CD8FFD892C13297ULL,
		0xF9ED914BFD1154D4ULL,
		0x90984D4C2A7425C4ULL,
		0xD47226B82AF76C70ULL,
		0x0000006D95CE8F24ULL
	}};
	shift = 39;
	printf("Test Case 107\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xEFC233AE4086DDD4ULL,
		0x26AB2664A94BAB97ULL,
		0x09CC26D10EEC3CFFULL,
		0x3D98EC3D4F037099ULL,
		0xAB56F2C23A1B82ADULL,
		0xD8588E67176B469AULL,
		0x91626FA6ED8A8593ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x33AE4086DDD40000ULL,
		0x2664A94BAB97EFC2ULL,
		0x26D10EEC3CFF26ABULL,
		0xEC3D4F03709909CCULL,
		0xF2C23A1B82AD3D98ULL,
		0x8E67176B469AAB56ULL,
		0x6FA6ED8A8593D858ULL,
		0x0000000000009162ULL
	}};
	shift = 16;
	printf("Test Case 108\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x0933B7641EBF7CF3ULL,
		0xD6EB0FDB6B196920ULL,
		0x5F8150B65B7D2E87ULL,
		0xA467D2E3BC677BB7ULL,
		0xA69F80B448B28792ULL,
		0x1E0D8E9C8C9F1FC5ULL,
		0x9292F77CE08BE641ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3B7641EBF7CF3000ULL,
		0xB0FDB6B196920093ULL,
		0x150B65B7D2E87D6EULL,
		0x7D2E3BC677BB75F8ULL,
		0xF80B448B28792A46ULL,
		0xD8E9C8C9F1FC5A69ULL,
		0x2F77CE08BE6411E0ULL,
		0x0000000000000929ULL
	}};
	shift = 12;
	printf("Test Case 109\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x043E2C27F9E2B6C4ULL,
		0xCE717579092895BEULL,
		0xE167D05281D47ED1ULL,
		0x704CA1FE4D583B0AULL,
		0xA6A33D659D92EC08ULL,
		0x47BDE437B7078D22ULL,
		0x6482311613C29F89ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE2B6C40000000000ULL,
		0x2895BE043E2C27F9ULL,
		0xD47ED1CE71757909ULL,
		0x583B0AE167D05281ULL,
		0x92EC08704CA1FE4DULL,
		0x078D22A6A33D659DULL,
		0xC29F8947BDE437B7ULL,
		0x0000006482311613ULL
	}};
	shift = 40;
	printf("Test Case 110\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x668198E858D71584ULL,
		0x20335CF6786B1E48ULL,
		0x3CB52F105A340B53ULL,
		0x236A89FA3C51F4B0ULL,
		0xF1AB25B5DF76C3DBULL,
		0x10F58E10627FD20EULL,
		0x665ADA0F54DB79D2ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3A1635C561000000ULL,
		0x3D9E1AC79219A066ULL,
		0xC4168D02D4C80CD7ULL,
		0x7E8F147D2C0F2D4BULL,
		0x6D77DDB0F6C8DAA2ULL,
		0x84189FF483BC6AC9ULL,
		0x83D536DE74843D63ULL,
		0x00000000001996B6ULL
	}};
	shift = 22;
	printf("Test Case 111\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x6C4536D6774076CFULL,
		0x051D79FB8FA99615ULL,
		0xB5ADA688B2EFA169ULL,
		0x840F2853CA8CC95EULL,
		0x6C154053EA06E887ULL,
		0xF84A7482F85E1158ULL,
		0xF42FF30A998E0451ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCEE80ED9E0000000ULL,
		0x71F532C2AD88A6DAULL,
		0x165DF42D20A3AF3FULL,
		0x7951992BD6B5B4D1ULL,
		0x7D40DD10F081E50AULL,
		0x5F0BC22B0D82A80AULL,
		0x5331C08A3F094E90ULL,
		0x000000001E85FE61ULL
	}};
	shift = 29;
	printf("Test Case 112\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xA6AA6F42BA71F36DULL,
		0x3B495ABCBB9AD677ULL,
		0xA255F2711CF3478BULL,
		0x85F15D7C3DEEE77AULL,
		0x8656F1022AC6506CULL,
		0xDEE305FA13055832ULL,
		0x2FBF17038A5C558CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA9BD0AE9C7CDB400ULL,
		0x256AF2EE6B59DE9AULL,
		0x57C9C473CD1E2CEDULL,
		0xC575F0F7BB9DEA89ULL,
		0x5BC408AB1941B217ULL,
		0x8C17E84C1560CA19ULL,
		0xFC5C0E297156337BULL,
		0x00000000000000BEULL
	}};
	shift = 10;
	printf("Test Case 113\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x1FBEA680D80C2BADULL,
		0xBFD0F59A65066987ULL,
		0x48E815D5A30AB132ULL,
		0xAEEC5A019E11FA57ULL,
		0xEF30C1A7F24CD04FULL,
		0x202CE15629B996E7ULL,
		0xA9982EA4D870BF0FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD4D01B018575A000ULL,
		0x1EB34CA0CD30E3F7ULL,
		0x02BAB461562657FAULL,
		0x8B4033C23F4AE91DULL,
		0x1834FE499A09F5DDULL,
		0x9C2AC53732DCFDE6ULL,
		0x05D49B0E17E1E405ULL,
		0x0000000000001533ULL
	}};
	shift = 13;
	printf("Test Case 114\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x1641BB2D70A4B299ULL,
		0xDE13B0874ED68AA7ULL,
		0xDE0D6B8A4FE5929EULL,
		0xA552FDF73542C549ULL,
		0x883C8B94EF4CEA7FULL,
		0x1D2AA77893404F71ULL,
		0xC22B3F18AE9AD962ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6532000000000000ULL,
		0x154E2C83765AE149ULL,
		0x253DBC27610E9DADULL,
		0x8A93BC1AD7149FCBULL,
		0xD4FF4AA5FBEE6A85ULL,
		0x9EE310791729DE99ULL,
		0xB2C43A554EF12680ULL,
		0x000184567E315D35ULL
	}};
	shift = 49;
	printf("Test Case 115\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x4BF636A7B78C2F95ULL,
		0x3C6D0051C6AE39B0ULL,
		0xB8910DDBE6A8999AULL,
		0x2C273B6D14F00CD9ULL,
		0x27B1FD6A923D965DULL,
		0xE217F1672470D4ABULL,
		0x8C8AEBD2AD648841ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE540000000000000ULL,
		0x6C12FD8DA9EDE30BULL,
		0x668F1B401471AB8EULL,
		0x366E244376F9AA26ULL,
		0x974B09CEDB453C03ULL,
		0x2AC9EC7F5AA48F65ULL,
		0x107885FC59C91C35ULL,
		0x002322BAF4AB5922ULL
	}};
	shift = 54;
	printf("Test Case 116\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x1137FCB446DFAFA7ULL,
		0xEF7F206966B7EC8DULL,
		0xB38B05FBD6E53954ULL,
		0xB85011EA69791BDCULL,
		0x0580AB1463367F15ULL,
		0x280C8BB19898F6E5ULL,
		0x090562265A2E22D9ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8DBF5F4E00000000ULL,
		0xCD6FD91A226FF968ULL,
		0xADCA72A9DEFE40D2ULL,
		0xD2F237B967160BF7ULL,
		0xC66CFE2B70A023D4ULL,
		0x3131EDCA0B015628ULL,
		0xB45C45B250191763ULL,
		0x00000000120AC44CULL
	}};
	shift = 33;
	printf("Test Case 117\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x1A18D42397400F2CULL,
		0xC02E577372634691ULL,
		0x1DC0573B5D459A4EULL,
		0x7D4DCAA199E467ACULL,
		0x98BBC4813C0332CDULL,
		0x1EAF37C2ED2DDA6FULL,
		0xDF5F92A46BBD88FFULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA18D42397400F2C0ULL,
		0x02E5773726346911ULL,
		0xDC0573B5D459A4ECULL,
		0xD4DCAA199E467AC1ULL,
		0x8BBC4813C0332CD7ULL,
		0xEAF37C2ED2DDA6F9ULL,
		0xF5F92A46BBD88FF1ULL,
		0x000000000000000DULL
	}};
	shift = 4;
	printf("Test Case 118\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x8BDE74FC996DB48CULL,
		0xA0B2A6A728091E6CULL,
		0xE6416E5A31FE3EF8ULL,
		0xA0ED71378135BFDBULL,
		0xACFA6B88EB760091ULL,
		0xC511955E297614ABULL,
		0x1D0DE6F729A81A75ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8BDE74FC996DB48CULL,
		0xA0B2A6A728091E6CULL,
		0xE6416E5A31FE3EF8ULL,
		0xA0ED71378135BFDBULL,
		0xACFA6B88EB760091ULL,
		0xC511955E297614ABULL,
		0x1D0DE6F729A81A75ULL,
		0x0000000000000000ULL
	}};
	shift = 0;
	printf("Test Case 119\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xFBDDA7947645C649ULL,
		0x43F7F8D9D4B63125ULL,
		0x0875D7BE8AE37577ULL,
		0x6228268EF2F5E90CULL,
		0x70523FF827306995ULL,
		0x494AEDFD45E1A11BULL,
		0xEF0E20EC141CBD5FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC920000000000000ULL,
		0x24BF7BB4F28EC8B8ULL,
		0xAEE87EFF1B3A96C6ULL,
		0x21810EBAF7D15C6EULL,
		0x32AC4504D1DE5EBDULL,
		0x236E0A47FF04E60DULL,
		0xABE9295DBFA8BC34ULL,
		0x001DE1C41D828397ULL
	}};
	shift = 53;
	printf("Test Case 120\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x33BB949EAF4B2F8FULL,
		0xA56F70A5F734F776ULL,
		0x766A884C6D7786C9ULL,
		0x8E88613A326575FDULL,
		0x08B8E8A8E8167AD5ULL,
		0x6D67F6FB09800F67ULL,
		0x5616EE90630651A8ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7800000000000000ULL,
		0xB19DDCA4F57A597CULL,
		0x4D2B7B852FB9A7BBULL,
		0xEBB35442636BBC36ULL,
		0xAC744309D1932BAFULL,
		0x3845C7454740B3D6ULL,
		0x436B3FB7D84C007BULL,
		0x02B0B7748318328DULL
	}};
	shift = 59;
	printf("Test Case 121\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x806133A46A69A867ULL,
		0x66A2E52020F6CE09ULL,
		0xEB99537DFF5B1E44ULL,
		0x8338548E5D331C20ULL,
		0x1D888017FA7B0B25ULL,
		0xBA50FB37ECD5A96CULL,
		0x68939B3CBC6F8378ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7000000000000000ULL,
		0x9806133A46A69A86ULL,
		0x466A2E52020F6CE0ULL,
		0x0EB99537DFF5B1E4ULL,
		0x58338548E5D331C2ULL,
		0xC1D888017FA7B0B2ULL,
		0x8BA50FB37ECD5A96ULL,
		0x068939B3CBC6F837ULL
	}};
	shift = 60;
	printf("Test Case 122\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x83CAE72E16EE5094ULL,
		0x95B66ACF63119B09ULL,
		0x85A8932A5C2EBD09ULL,
		0xDF1AE80E1EAF01B0ULL,
		0xE55EC59A755A4154ULL,
		0x8DD00942909F11FDULL,
		0xF464CCA9DE8C6030ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3CAE72E16EE50940ULL,
		0x5B66ACF63119B098ULL,
		0x5A8932A5C2EBD099ULL,
		0xF1AE80E1EAF01B08ULL,
		0x55EC59A755A4154DULL,
		0xDD00942909F11FDEULL,
		0x464CCA9DE8C60308ULL,
		0x000000000000000FULL
	}};
	shift = 4;
	printf("Test Case 123\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x627BA28622FA91ABULL,
		0x9F1F953486BEF1E0ULL,
		0x687C77141AFDF103ULL,
		0x309F6197618371D6ULL,
		0x265B147DBC6CAF36ULL,
		0xB3A7F0C310F11D8BULL,
		0xB4122061AC360481ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA188BEA46AC00000ULL,
		0x4D21AFBC78189EE8ULL,
		0xC506BF7C40E7C7E5ULL,
		0x65D860DC759A1F1DULL,
		0x1F6F1B2BCD8C27D8ULL,
		0x30C43C4762C996C5ULL,
		0x186B0D81206CE9FCULL,
		0x00000000002D0488ULL
	}};
	shift = 22;
	printf("Test Case 124\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xE49D058680230D17ULL,
		0x1A9F5DF2528AB03DULL,
		0xA70E64EB60047D24ULL,
		0x879C7047DAC30259ULL,
		0xE04CE1EF4A751807ULL,
		0xE9649FAE0EF75B6DULL,
		0x7E98D4183F9A03D3ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x45C0000000000000ULL,
		0x0F79274161A008C3ULL,
		0x4906A7D77C94A2ACULL,
		0x9669C3993AD8011FULL,
		0x01E1E71C11F6B0C0ULL,
		0xDB7813387BD29D46ULL,
		0xF4FA5927EB83BDD6ULL,
		0x001FA635060FE680ULL
	}};
	shift = 54;
	printf("Test Case 125\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xAD93C0322D2F0A71ULL,
		0x5962A4F4F92C3146ULL,
		0x3A575325901310AEULL,
		0x2C754C4BCD8C85CAULL,
		0xE229D1C294831C64ULL,
		0x7C5EE73B4605038AULL,
		0x10DA8DC3505F027EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x64F00C8B4BC29C40ULL,
		0x58A93D3E4B0C51ABULL,
		0x95D4C96404C42B96ULL,
		0x1D5312F36321728EULL,
		0x8A7470A520C7190BULL,
		0x17B9CED18140E2B8ULL,
		0x36A370D417C09F9FULL,
		0x0000000000000004ULL
	}};
	shift = 6;
	printf("Test Case 126\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xFFB3360CC44A2C01ULL,
		0x2844D863732297E2ULL,
		0x66E08EC16BF60F9FULL,
		0xDD62BE00494E52F4ULL,
		0x473C63FDD9C570B8ULL,
		0xBDC9AA4DF49DE3DCULL,
		0x49A3E5F5B562B108ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD8331128B0040000ULL,
		0x618DCC8A5F8BFECCULL,
		0x3B05AFD83E7CA113ULL,
		0xF80125394BD19B82ULL,
		0x8FF76715C2E3758AULL,
		0xA937D2778F711CF1ULL,
		0x97D6D58AC422F726ULL,
		0x000000000001268FULL
	}};
	shift = 18;
	printf("Test Case 127\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x075812F67B70B15DULL,
		0xC15A08858CB0F38CULL,
		0xFA27E6CAC9845AD4ULL,
		0x3FD5702E77F15207ULL,
		0x7841F125435250BEULL,
		0xFF8F7E95A1369FE2ULL,
		0x0046B7B746E2D540ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF67B70B15D000000ULL,
		0x858CB0F38C075812ULL,
		0xCAC9845AD4C15A08ULL,
		0x2E77F15207FA27E6ULL,
		0x25435250BE3FD570ULL,
		0x95A1369FE27841F1ULL,
		0xB746E2D540FF8F7EULL,
		0x00000000000046B7ULL
	}};
	shift = 24;
	printf("Test Case 128\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xAC395AC2540C2C57ULL,
		0xC17E2C4E4B43F6A2ULL,
		0xBEBD5578CED759CBULL,
		0x5AA77C5422409C45ULL,
		0xED86D2C54C7209AFULL,
		0xE85455876982E19EULL,
		0x1965BEF2C4821FFDULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x81858AE000000000ULL,
		0x687ED455872B584AULL,
		0xDAEB39782FC589C9ULL,
		0x481388B7D7AAAF19ULL,
		0x8E4135EB54EF8A84ULL,
		0x305C33DDB0DA58A9ULL,
		0x9043FFBD0A8AB0EDULL,
		0x000000032CB7DE58ULL
	}};
	shift = 37;
	printf("Test Case 129\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x62BB5536AB528335ULL,
		0x07F6205C49483906ULL,
		0xED0875EB638E6DF3ULL,
		0x2D928EAA55C7A97EULL,
		0x389F378D23B91867ULL,
		0x8D64BBF8141FF728ULL,
		0xDC74362DC461934BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDAAD4A0CD4000000ULL,
		0x712520E4198AED54ULL,
		0xAD8E39B7CC1FD881ULL,
		0xA9571EA5FBB421D7ULL,
		0x348EE4619CB64A3AULL,
		0xE0507FDCA0E27CDEULL,
		0xB711864D2E3592EFULL,
		0x000000000371D0D8ULL
	}};
	shift = 26;
	printf("Test Case 130\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x5C069BA8A6B49924ULL,
		0x20A24E66B1C933A1ULL,
		0x02FBDDF9F7E2B452ULL,
		0xC1C7E357B028CF36ULL,
		0x0234772A9114EC12ULL,
		0xA6376271BBD34171ULL,
		0x094476A3690358D4ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD264900000000000ULL,
		0x24CE85701A6EA29AULL,
		0x8AD1488289399AC7ULL,
		0xA33CD80BEF77E7DFULL,
		0x53B04B071F8D5EC0ULL,
		0x4D05C408D1DCAA44ULL,
		0x0D635298DD89C6EFULL,
		0x0000002511DA8DA4ULL
	}};
	shift = 42;
	printf("Test Case 131\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x3D2274D52AAD5096ULL,
		0xB885634E9893F685ULL,
		0x7C26CB05BDB8ACC1ULL,
		0x8B40D09D74E2E4F2ULL,
		0x2B97D7D5668F3EDDULL,
		0x364D0FB21FAB1B4CULL,
		0x15DBEE9145882E85ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x354AAB5425800000ULL,
		0xD3A624FDA14F489DULL,
		0xC16F6E2B306E2158ULL,
		0x275D38B93C9F09B2ULL,
		0xF559A3CFB762D034ULL,
		0xEC87EAC6D30AE5F5ULL,
		0xA451620BA14D9343ULL,
		0x00000000000576FBULL
	}};
	shift = 22;
	printf("Test Case 132\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x48522504D93A2507ULL,
		0xB9B9537B07794337ULL,
		0x2B0FC8E4040861ADULL,
		0x04DA0EE18780AF1FULL,
		0x3ECAB0F43D87C72FULL,
		0xBC4F3047026FDF5FULL,
		0x495A1919F3DEBDBCULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4D93A25070000000ULL,
		0xB077943374852250ULL,
		0x4040861ADB9B9537ULL,
		0x18780AF1F2B0FC8EULL,
		0x43D87C72F04DA0EEULL,
		0x7026FDF5F3ECAB0FULL,
		0x9F3DEBDBCBC4F304ULL,
		0x000000000495A191ULL
	}};
	shift = 28;
	printf("Test Case 133\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xB377DAEA61592AE9ULL,
		0xE6F25230921E54D4ULL,
		0xD6EFBDCDC3334F0EULL,
		0xF23E1ED189C723D0ULL,
		0xEE9FC0BA60430A0DULL,
		0xB44A6BBCC8A2D05DULL,
		0x14E7DA7227C39AB0ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9BBED7530AC95748ULL,
		0x3792918490F2A6A5ULL,
		0xB77DEE6E199A7877ULL,
		0x91F0F68C4E391E86ULL,
		0x74FE05D30218506FULL,
		0xA2535DE6451682EFULL,
		0xA73ED3913E1CD585ULL,
		0x0000000000000000ULL
	}};
	shift = 3;
	printf("Test Case 134\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xD99C1C675BB4972EULL,
		0x2D0638C58489DD89ULL,
		0x96D4A1904BCF986CULL,
		0xC4B247E60855630CULL,
		0x49DE13AF0004C492ULL,
		0x6D3065496D09D115ULL,
		0x04CD2B7519D91517ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0719D6ED25CB8000ULL,
		0x8E31612277627667ULL,
		0x286412F3E61B0B41ULL,
		0x91F9821558C325B5ULL,
		0x84EBC0013124B12CULL,
		0x19525B4274455277ULL,
		0x4ADD46764545DB4CULL,
		0x0000000000000133ULL
	}};
	shift = 14;
	printf("Test Case 135\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x7BE66806FFA281A3ULL,
		0x4201C38DCDB0454BULL,
		0x22EA3B3B73879271ULL,
		0x9A2377F2835794CDULL,
		0x2E332EEDC2C402D5ULL,
		0xF628EE7A9380942AULL,
		0x057CE11A59997D02ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0346000000000000ULL,
		0x8A96F7CCD00DFF45ULL,
		0x24E28403871B9B60ULL,
		0x299A45D47676E70FULL,
		0x05AB3446EFE506AFULL,
		0x28545C665DDB8588ULL,
		0xFA05EC51DCF52701ULL,
		0x00000AF9C234B332ULL
	}};
	shift = 49;
	printf("Test Case 136\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x08BB9AB9072414B8ULL,
		0xBE08D07A7B74EB02ULL,
		0xED63CDA204824440ULL,
		0xB889EFEB3AFE82A9ULL,
		0x0D40E5D498D81733ULL,
		0x9C8E349D36F80EF5ULL,
		0xCDAAF141803036BEULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9072414B80000000ULL,
		0xA7B74EB0208BB9ABULL,
		0x204824440BE08D07ULL,
		0xB3AFE82A9ED63CDAULL,
		0x498D81733B889EFEULL,
		0xD36F80EF50D40E5DULL,
		0x1803036BE9C8E349ULL,
		0x000000000CDAAF14ULL
	}};
	shift = 28;
	printf("Test Case 137\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xBA5B0B02CCE2B33CULL,
		0x9DB489151579C6ECULL,
		0x9F615879DA642BB0ULL,
		0x5F9080A2957D9705ULL,
		0x0AC451B7F4106F56ULL,
		0x36A13B481D69EC5EULL,
		0xD682AE5079FE5B11ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6160599C56678000ULL,
		0x9122A2AF38DD974BULL,
		0x2B0F3B4C857613B6ULL,
		0x101452AFB2E0B3ECULL,
		0x8A36FE820DEACBF2ULL,
		0x276903AD3D8BC158ULL,
		0x55CA0F3FCB6226D4ULL,
		0x0000000000001AD0ULL
	}};
	shift = 13;
	printf("Test Case 138\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x29235CC499CBC03EULL,
		0xCD18C653731B8693ULL,
		0x5740E4A54BE44A1EULL,
		0x51D187FB0CF2BA8FULL,
		0xCF165C307C8B068CULL,
		0xC265F3F859296013ULL,
		0x894072FC5958CBE4ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCBC03E0000000000ULL,
		0x1B869329235CC499ULL,
		0xE44A1ECD18C65373ULL,
		0xF2BA8F5740E4A54BULL,
		0x8B068C51D187FB0CULL,
		0x296013CF165C307CULL,
		0x58CBE4C265F3F859ULL,
		0x000000894072FC59ULL
	}};
	shift = 40;
	printf("Test Case 139\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x5859C7C35C57E173ULL,
		0xA44C9E90BC8F9A91ULL,
		0xDC872515E1780FD4ULL,
		0x2F25BD9F33D584E9ULL,
		0x277217F8439C5691ULL,
		0x3FB70DAFAAC4429EULL,
		0x4235CB89F785B924ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2E60000000000000ULL,
		0x522B0B38F86B8AFCULL,
		0xFA948993D21791F3ULL,
		0x9D3B90E4A2BC2F01ULL,
		0xD225E4B7B3E67AB0ULL,
		0x53C4EE42FF08738AULL,
		0x2487F6E1B5F55888ULL,
		0x000846B9713EF0B7ULL
	}};
	shift = 53;
	printf("Test Case 140\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x2F0DCF35F40F964CULL,
		0x9034909C25915648ULL,
		0x386989F6A065467DULL,
		0xF94795A65A1914EBULL,
		0x49D4A8494922C8B1ULL,
		0x001E20F5BA37DEB5ULL,
		0xB2B8D96F50989E3AULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8000000000000000ULL,
		0x05E1B9E6BE81F2C9ULL,
		0xB206921384B22AC9ULL,
		0x670D313ED40CA8CFULL,
		0x3F28F2B4CB43229DULL,
		0xA93A950929245916ULL,
		0x4003C41EB746FBD6ULL,
		0x16571B2DEA1313C7ULL
	}};
	shift = 61;
	printf("Test Case 141\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xF0DB2A0E386CDFFEULL,
		0x12DF8A58E1701A70ULL,
		0xF47CD9DD3EE40167ULL,
		0xC0582B9E34C691A3ULL,
		0x3ADA78E514349779ULL,
		0xD75FD0A9D2024BF0ULL,
		0x0B9BA3EBF77F1BCFULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC36CA838E1B37FF8ULL,
		0x4B7E296385C069C3ULL,
		0xD1F36774FB90059CULL,
		0x0160AE78D31A468FULL,
		0xEB69E39450D25DE7ULL,
		0x5D7F42A748092FC0ULL,
		0x2E6E8FAFDDFC6F3FULL,
		0x0000000000000000ULL
	}};
	shift = 2;
	printf("Test Case 142\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x633A51E4A0AB335CULL,
		0x018D9AC1861FB0C2ULL,
		0xABE8A8A8E136F0A4ULL,
		0xEB7895BC1F86E5CEULL,
		0x95ECAB9B13EBC5D5ULL,
		0xEA91EAFBD68DCBF1ULL,
		0x0CE62AB346E3A9A2ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x666B800000000000ULL,
		0xF6184C674A3C9415ULL,
		0xDE148031B35830C3ULL,
		0xDCB9D57D15151C26ULL,
		0x78BABD6F12B783F0ULL,
		0xB97E32BD9573627DULL,
		0x75345D523D5F7AD1ULL,
		0x0000019CC55668DCULL
	}};
	shift = 45;
	printf("Test Case 143\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xEDFB3FB79B03B3B5ULL,
		0x2D875992205DBE1DULL,
		0xD4CDF17EE1985690ULL,
		0xD5D1E475B85552DEULL,
		0xC9B256A249EA710AULL,
		0xA70B2524B0E09B4DULL,
		0x0209C4C44D421970ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDBF67F6F3607676AULL,
		0x5B0EB32440BB7C3BULL,
		0xA99BE2FDC330AD20ULL,
		0xABA3C8EB70AAA5BDULL,
		0x9364AD4493D4E215ULL,
		0x4E164A4961C1369BULL,
		0x041389889A8432E1ULL,
		0x0000000000000000ULL
	}};
	shift = 1;
	printf("Test Case 144\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xC0B3DA65EA11DC8BULL,
		0xF08764731CDCC231ULL,
		0x584FF429A4CF5BE5ULL,
		0x50CEDEEAF4C58D47ULL,
		0xCE5756F6B63AAEF7ULL,
		0xA6B905C4F20C6494ULL,
		0x84EBF1F135B5D693ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1DC8B00000000000ULL,
		0xCC231C0B3DA65EA1ULL,
		0xF5BE5F08764731CDULL,
		0x58D47584FF429A4CULL,
		0xAAEF750CEDEEAF4CULL,
		0xC6494CE5756F6B63ULL,
		0x5D693A6B905C4F20ULL,
		0x0000084EBF1F135BULL
	}};
	shift = 44;
	printf("Test Case 145\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xA0A66A8D33BF878AULL,
		0xAFBD7145322B169BULL,
		0x31772DDD87A99DA6ULL,
		0x23900DF065F9CF72ULL,
		0x5D8140C281EE669DULL,
		0xB004204A6DF4CA0AULL,
		0xEA9A4AAC342F4ACFULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC3C5000000000000ULL,
		0x8B4DD053354699DFULL,
		0xCED357DEB8A29915ULL,
		0xE7B918BB96EEC3D4ULL,
		0x334E91C806F832FCULL,
		0x65052EC0A06140F7ULL,
		0xA567D802102536FAULL,
		0x0000754D25561A17ULL
	}};
	shift = 47;
	printf("Test Case 146\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xA235C42A6F018895ULL,
		0x9BBB6F5BFD473526ULL,
		0x1052DA0F72868EC3ULL,
		0xEC6F6A447B8776B5ULL,
		0xDE4E5330630E179BULL,
		0x648A02977B647BB0ULL,
		0x037A7E833D83F88EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDE03112A00000000ULL,
		0xFA8E6A4D446B8854ULL,
		0xE50D1D873776DEB7ULL,
		0xF70EED6A20A5B41EULL,
		0xC61C2F37D8DED488ULL,
		0xF6C8F761BC9CA660ULL,
		0x7B07F11CC914052EULL,
		0x0000000006F4FD06ULL
	}};
	shift = 33;
	printf("Test Case 147\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x0D58E35DE9544C3FULL,
		0xD817728191266F1DULL,
		0x486456A89E33C06DULL,
		0x0176A4A4CEB52443ULL,
		0x79D2C7C94A738582ULL,
		0x458F42F66369C878ULL,
		0xDE521C18B1EA7EA2ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBBD2A8987E000000ULL,
		0x03224CDE3A1AB1C6ULL,
		0x513C6780DBB02EE5ULL,
		0x499D6A488690C8ADULL,
		0x9294E70B0402ED49ULL,
		0xECC6D390F0F3A58FULL,
		0x3163D4FD448B1E85ULL,
		0x0000000001BCA438ULL
	}};
	shift = 25;
	printf("Test Case 148\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xC5225228362339BAULL,
		0x441EB8AF9A2C3988ULL,
		0xCDCC13557BF73392ULL,
		0x6DE0BEF1CCCFFE39ULL,
		0x2A89011263030947ULL,
		0x43E8D17B9EAD9D49ULL,
		0xEB8337705EC8EA4DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6737400000000000ULL,
		0x873118A44A4506C4ULL,
		0xE6724883D715F345ULL,
		0xFFC739B9826AAF7EULL,
		0x6128EDBC17DE3999ULL,
		0xB3A9255120224C60ULL,
		0x1D49A87D1A2F73D5ULL,
		0x00001D7066EE0BD9ULL
	}};
	shift = 45;
	printf("Test Case 149\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xF83FA344EC0D684AULL,
		0xBB8A9E903BFAB680ULL,
		0x6F626482A31A23BDULL,
		0x21B6741E2BA64AE6ULL,
		0xEE0C5EC0BC64A4B1ULL,
		0xF5BDAF2171D90DB3ULL,
		0x34429FEFC312390DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD094000000000000ULL,
		0x6D01F07F4689D81AULL,
		0x477B77153D2077F5ULL,
		0x95CCDEC4C9054634ULL,
		0x4962436CE83C574CULL,
		0x1B67DC18BD8178C9ULL,
		0x721BEB7B5E42E3B2ULL,
		0x000068853FDF8624ULL
	}};
	shift = 49;
	printf("Test Case 150\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xB975DD46FE448F06ULL,
		0x8C4BCFB9D804D294ULL,
		0x5A5C2412ADB3A947ULL,
		0xF43BE9F0F1FB22ACULL,
		0xEB8C4A70C7A39B5AULL,
		0x6426344C5D142BA7ULL,
		0xF1628738D63976E4ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE0C0000000000000ULL,
		0x52972EBBA8DFC891ULL,
		0x28F18979F73B009AULL,
		0x558B4B848255B675ULL,
		0x6B5E877D3E1E3F64ULL,
		0x74FD71894E18F473ULL,
		0xDC8C84C6898BA285ULL,
		0x001E2C50E71AC72EULL
	}};
	shift = 53;
	printf("Test Case 151\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x528BD503B0AEB00BULL,
		0x73F9337A59A99C1EULL,
		0x89EA2D94097B37FCULL,
		0x7ECD9E25320BB8CBULL,
		0x89FFDED8A2A7AD78ULL,
		0x645F8BA9E355B7EBULL,
		0xB1D0FAC04C66F394ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6016000000000000ULL,
		0x383CA517AA07615DULL,
		0x6FF8E7F266F4B353ULL,
		0x719713D45B2812F6ULL,
		0x5AF0FD9B3C4A6417ULL,
		0x6FD713FFBDB1454FULL,
		0xE728C8BF1753C6ABULL,
		0x000163A1F58098CDULL
	}};
	shift = 49;
	printf("Test Case 152\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xF0BA88AE5952D894ULL,
		0xF4E0AF5972B3BE52ULL,
		0xFB35B690DD52DBFAULL,
		0x4AFD19314A3F071EULL,
		0x6D0C30B705FD9000ULL,
		0x0BDAFC99D4BC0BC9ULL,
		0xE00434C02D3FAC92ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x88AE5952D8940000ULL,
		0xAF5972B3BE52F0BAULL,
		0xB690DD52DBFAF4E0ULL,
		0x19314A3F071EFB35ULL,
		0x30B705FD90004AFDULL,
		0xFC99D4BC0BC96D0CULL,
		0x34C02D3FAC920BDAULL,
		0x000000000000E004ULL
	}};
	shift = 16;
	printf("Test Case 153\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xACE2582A72729556ULL,
		0xE3037A7DB50616A7ULL,
		0xEF54DADEC397C5E1ULL,
		0x12BEC3100B807DBCULL,
		0x8411D2CBAD2D039CULL,
		0x378147C930783D49ULL,
		0xCB6F80E91536BE4EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4E52AAC000000000ULL,
		0xA0C2D4F59C4B054EULL,
		0x72F8BC3C606F4FB6ULL,
		0x700FB79DEA9B5BD8ULL,
		0xA5A0738257D86201ULL,
		0x0F07A930823A5975ULL,
		0xA6D7C9C6F028F926ULL,
		0x000000196DF01D22ULL
	}};
	shift = 37;
	printf("Test Case 154\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xF55BAADC42974103ULL,
		0xAA606DB1BFACDDFEULL,
		0xBD70546B97D27FE1ULL,
		0xB41D4C334FB3EEDDULL,
		0x8AF5B0DFCBA5F7A4ULL,
		0x52E17E4F7D47A05FULL,
		0xC50F5220DEE7F0EAULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8180000000000000ULL,
		0xFF7AADD56E214BA0ULL,
		0xF0D53036D8DFD66EULL,
		0x6EDEB82A35CBE93FULL,
		0xD25A0EA619A7D9F7ULL,
		0x2FC57AD86FE5D2FBULL,
		0x752970BF27BEA3D0ULL,
		0x006287A9106F73F8ULL
	}};
	shift = 55;
	printf("Test Case 155\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xADE02315FADD3ACFULL,
		0xE35D996CC17B7D3CULL,
		0x9D876DE392BFFBE3ULL,
		0xE3D74B2D3E2E79CAULL,
		0x7550A19B35F963B2ULL,
		0x231A6548624DEBBDULL,
		0x338ADA5251949EF4ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x74EB3C0000000000ULL,
		0xEDF4F2B7808C57EBULL,
		0xFFEF8F8D7665B305ULL,
		0xB9E72A761DB78E4AULL,
		0xE58ECB8F5D2CB4F8ULL,
		0x37AEF5D542866CD7ULL,
		0x527BD08C69952189ULL,
		0x000000CE2B694946ULL
	}};
	shift = 42;
	printf("Test Case 156\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xF6FBE339C16ACFCBULL,
		0x708786E6843C3990ULL,
		0x994E61ED40F992EFULL,
		0x4AD388EB310F49B5ULL,
		0xC0AAA14DFF7BA779ULL,
		0x51EC04E5BA7375C2ULL,
		0xA7305DCBB40F02E6ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC67382D59F960000ULL,
		0x0DCD08787321EDF7ULL,
		0xC3DA81F325DEE10FULL,
		0x11D6621E936B329CULL,
		0x429BFEF74EF295A7ULL,
		0x09CB74E6EB858155ULL,
		0xBB97681E05CCA3D8ULL,
		0x0000000000014E60ULL
	}};
	shift = 17;
	printf("Test Case 157\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x30BDFE5B24896A44ULL,
		0x66304624AA09F706ULL,
		0xED730E1DE10AC745ULL,
		0x65FC0030A7EEEC5DULL,
		0xA200DCCD233D8870ULL,
		0xCF1D78DF83282607ULL,
		0xAE653237A99857FBULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFE5B24896A440000ULL,
		0x4624AA09F70630BDULL,
		0x0E1DE10AC7456630ULL,
		0x0030A7EEEC5DED73ULL,
		0xDCCD233D887065FCULL,
		0x78DF83282607A200ULL,
		0x3237A99857FBCF1DULL,
		0x000000000000AE65ULL
	}};
	shift = 16;
	printf("Test Case 158\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xAFDA2BD2FEDD8837ULL,
		0xFB32BAF3167A0E18ULL,
		0x50BC85AC2A9E8BC5ULL,
		0xF6D8F697D91E5830ULL,
		0xA029796BBC586CBDULL,
		0x1C877EF32A5FE5AFULL,
		0xC87C3E4A21405434ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEDD8837000000000ULL,
		0x67A0E18AFDA2BD2FULL,
		0xA9E8BC5FB32BAF31ULL,
		0x91E583050BC85AC2ULL,
		0xC586CBDF6D8F697DULL,
		0xA5FE5AFA029796BBULL,
		0x14054341C877EF32ULL,
		0x0000000C87C3E4A2ULL
	}};
	shift = 36;
	printf("Test Case 159\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x283910D289EC77BFULL,
		0x414021F0F7027F98ULL,
		0x145F6265D79F0AB3ULL,
		0x1347CCD07FBC98E5ULL,
		0x96473F45924CF386ULL,
		0xFFD2634A5C1382F7ULL,
		0xE0DFC4B474CC3506ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0E4434A27B1DEFC0ULL,
		0x50087C3DC09FE60AULL,
		0x17D89975E7C2ACD0ULL,
		0xD1F3341FEF263945ULL,
		0x91CFD164933CE184ULL,
		0xF498D29704E0BDE5ULL,
		0x37F12D1D330D41BFULL,
		0x0000000000000038ULL
	}};
	shift = 6;
	printf("Test Case 160\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x0AA86FF5927AE1C0ULL,
		0x92B79602DA4B6DC2ULL,
		0x9379FC567AAC6C4DULL,
		0x1E614308E5881F09ULL,
		0xD466DA7674FC8686ULL,
		0x9B5B8E3BC990A516ULL,
		0xE7F4398931D0645FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3D70E00000000000ULL,
		0x25B6E1055437FAC9ULL,
		0x563626C95BCB016DULL,
		0xC40F84C9BCFE2B3DULL,
		0x7E43430F30A18472ULL,
		0xC8528B6A336D3B3AULL,
		0xE8322FCDADC71DE4ULL,
		0x00000073FA1CC498ULL
	}};
	shift = 39;
	printf("Test Case 161\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x57BE32EA1CD34989ULL,
		0x65FA5F06B605FC16ULL,
		0xB8635495AF5A3DF1ULL,
		0x9EB7BF655FF522C9ULL,
		0x9CBABDC3835665ACULL,
		0x0C6EF7C8E566203AULL,
		0x9F0B131EBA07B8DDULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF8CBA8734D262400ULL,
		0xE97C1AD817F0595EULL,
		0x8D5256BD68F7C597ULL,
		0xDEFD957FD48B26E1ULL,
		0xEAF70E0D5996B27AULL,
		0xBBDF23959880EA72ULL,
		0x2C4C7AE81EE37431ULL,
		0x000000000000027CULL
	}};
	shift = 10;
	printf("Test Case 162\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x245F2140A12EE6A9ULL,
		0xC8A17D4B503046ABULL,
		0x18A18CE64682420EULL,
		0x545557CFC70BB9C2ULL,
		0xD93CC366CFE51849ULL,
		0x358C64A6F7946D59ULL,
		0x4C16FD86F58CEB39ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCD52000000000000ULL,
		0x8D5648BE4281425DULL,
		0x841D9142FA96A060ULL,
		0x7384314319CC8D04ULL,
		0x3092A8AAAF9F8E17ULL,
		0xDAB3B27986CD9FCAULL,
		0xD6726B18C94DEF28ULL,
		0x0000982DFB0DEB19ULL
	}};
	shift = 49;
	printf("Test Case 163\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x5D68E55CDE3CB9DCULL,
		0xDF1DB2EC94CBEC5FULL,
		0x15B69391862F20B4ULL,
		0xF35845C240B97848ULL,
		0xFAF7E10AD6DEEF30ULL,
		0xA0659E08076D88E0ULL,
		0x6793356E66F9A99FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD1CAB9BC7973B800ULL,
		0x3B65D92997D8BEBAULL,
		0x6D27230C5E4169BEULL,
		0xB08B848172F0902BULL,
		0xEFC215ADBDDE61E6ULL,
		0xCB3C100EDB11C1F5ULL,
		0x266ADCCDF3533F40ULL,
		0x00000000000000CFULL
	}};
	shift = 9;
	printf("Test Case 164\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x34232BC1B0CB260AULL,
		0x130AE8F6009E0C02ULL,
		0xCD1F7196BF1E5D15ULL,
		0x104715333645BCBDULL,
		0x7DC6D47D09FBE16CULL,
		0xCBC2729FCFD0F675ULL,
		0xAED6F32CBBE6D3D6ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x232BC1B0CB260A00ULL,
		0x0AE8F6009E0C0234ULL,
		0x1F7196BF1E5D1513ULL,
		0x4715333645BCBDCDULL,
		0xC6D47D09FBE16C10ULL,
		0xC2729FCFD0F6757DULL,
		0xD6F32CBBE6D3D6CBULL,
		0x00000000000000AEULL
	}};
	shift = 8;
	printf("Test Case 165\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xD928C1A1626212DAULL,
		0xEBE7EB6655581E48ULL,
		0xBF2FF2C6022E534DULL,
		0xBD29959ED4C0AFEAULL,
		0x5EB6C7F17F12713AULL,
		0xC27F7419FEB5AEA7ULL,
		0x91241869B417B8C4ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD0B131096D000000ULL,
		0xB32AAC0F246C9460ULL,
		0x63011729A6F5F3F5ULL,
		0xCF6A6057F55F97F9ULL,
		0xF8BF89389D5E94CAULL,
		0x0CFF5AD753AF5B63ULL,
		0x34DA0BDC62613FBAULL,
		0x000000000048920CULL
	}};
	shift = 23;
	printf("Test Case 166\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x713875F0E99C2B6FULL,
		0x7235626000168792ULL,
		0xB65E001E6B972689ULL,
		0x7F340704B43D1FD0ULL,
		0xB500F197C99ADCBDULL,
		0x8C46DF9370A85591ULL,
		0x3B759A5A191AA674ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x13875F0E99C2B6F0ULL,
		0x2356260001687927ULL,
		0x65E001E6B9726897ULL,
		0xF340704B43D1FD0BULL,
		0x500F197C99ADCBD7ULL,
		0xC46DF9370A85591BULL,
		0xB759A5A191AA6748ULL,
		0x0000000000000003ULL
	}};
	shift = 4;
	printf("Test Case 167\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x386B997724ABDD75ULL,
		0x32C61CB54C5F9EC7ULL,
		0xA96E7C8B5802D7E7ULL,
		0x83BEA64DCA81E89FULL,
		0x2637AA9BCC3377BCULL,
		0x607C91AA3829B634ULL,
		0xFB7FD25EDC31C21EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x55EEBA8000000000ULL,
		0x2FCF639C35CCBB92ULL,
		0x016BF399630E5AA6ULL,
		0x40F44FD4B73E45ACULL,
		0x19BBDE41DF5326E5ULL,
		0x14DB1A131BD54DE6ULL,
		0x18E10F303E48D51CULL,
		0x0000007DBFE92F6EULL
	}};
	shift = 39;
	printf("Test Case 168\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x9E739A0C9D77CAE6ULL,
		0x3BE1ABF6831DA7D2ULL,
		0x7851D51E0E4A8ED5ULL,
		0x40B14D017C067FA6ULL,
		0x0420DF204F9B29D0ULL,
		0x402705BFE1A9C1A2ULL,
		0x1A056D45811F5224ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8000000000000000ULL,
		0xA79CE683275DF2B9ULL,
		0x4EF86AFDA0C769F4ULL,
		0x9E1475478392A3B5ULL,
		0x102C53405F019FE9ULL,
		0x810837C813E6CA74ULL,
		0x1009C16FF86A7068ULL,
		0x06815B516047D489ULL
	}};
	shift = 62;
	printf("Test Case 169\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x74223E3B4DD5C5D5ULL,
		0x0397BAF8C8A55445ULL,
		0x2941612E462DE661ULL,
		0xB5C87B1BAB4EDFF7ULL,
		0x53EA2672216ABA53ULL,
		0x9E8FD55986628A25ULL,
		0x09C81E135754C546ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3B4DD5C5D5000000ULL,
		0xF8C8A5544574223EULL,
		0x2E462DE6610397BAULL,
		0x1BAB4EDFF7294161ULL,
		0x72216ABA53B5C87BULL,
		0x5986628A2553EA26ULL,
		0x135754C5469E8FD5ULL,
		0x000000000009C81EULL
	}};
	shift = 24;
	printf("Test Case 170\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x05436928DFDFD47AULL,
		0x6F66C5C63E7FF980ULL,
		0x5651762CF928B096ULL,
		0x8FB825668DD8D84FULL,
		0x710B829423B05B51ULL,
		0xD888BE620062272EULL,
		0x4A0AA34DEAD543E1ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x02A1B4946FEFEA3DULL,
		0x37B362E31F3FFCC0ULL,
		0xAB28BB167C94584BULL,
		0xC7DC12B346EC6C27ULL,
		0x3885C14A11D82DA8ULL,
		0xEC445F3100311397ULL,
		0x250551A6F56AA1F0ULL
	}};
	shift = 63;
	printf("Test Case 171\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x0E9DEAFC662A05D0ULL,
		0xDB68C200A8E13AA6ULL,
		0x31066E88E3717271ULL,
		0x911784562F1D06C3ULL,
		0xDE897C2808B22400ULL,
		0xF396853A0E0F6EC6ULL,
		0x252F66864AA11586ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x98A8174000000000ULL,
		0xA384EA983A77ABF1ULL,
		0x8DC5C9C76DA30802ULL,
		0xBC741B0CC419BA23ULL,
		0x22C89002445E1158ULL,
		0x383DBB1B7A25F0A0ULL,
		0x2A84561BCE5A14E8ULL,
		0x0000000094BD9A19ULL
	}};
	shift = 34;
	printf("Test Case 172\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xE0B0BC5C6C851481ULL,
		0xC76968C533AAC37EULL,
		0x4553D8F8D7454013ULL,
		0xB44C4D577E858D02ULL,
		0x41880BB017B718ECULL,
		0x25B99079363522C3ULL,
		0x6CE4D3EF99BE273EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE36428A408000000ULL,
		0x299D561BF70585E2ULL,
		0xC6BA2A009E3B4B46ULL,
		0xBBF42C68122A9EC7ULL,
		0x80BDB8C765A2626AULL,
		0xC9B1A9161A0C405DULL,
		0x7CCDF139F12DCC83ULL,
		0x000000000367269FULL
	}};
	shift = 27;
	printf("Test Case 173\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x7173A23F543B3A56ULL,
		0xBACDD1AA3156FAC3ULL,
		0x57C16A4884D498AEULL,
		0xA98737BF1BD1A72AULL,
		0x4217DE9551BF2AF9ULL,
		0x861E76AE682486FDULL,
		0xFBBC89765BC45D49ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD9D2B00000000000ULL,
		0xB7D61B8B9D11FAA1ULL,
		0xA4C575D66E8D518AULL,
		0x8D3952BE0B524426ULL,
		0xF957CD4C39BDF8DEULL,
		0x2437EA10BEF4AA8DULL,
		0x22EA4C30F3B57341ULL,
		0x000007DDE44BB2DEULL
	}};
	shift = 43;
	printf("Test Case 174\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x0261532E21BB319FULL,
		0xE138C258ADAB9C87ULL,
		0xB0CAC39D2A4BA5DAULL,
		0xA25266E74861B314ULL,
		0x2D386D5455305CDBULL,
		0x184B61C6AC86844CULL,
		0xF77658F931B24133ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE21BB319F0000000ULL,
		0x8ADAB9C870261532ULL,
		0xD2A4BA5DAE138C25ULL,
		0x74861B314B0CAC39ULL,
		0x455305CDBA25266EULL,
		0x6AC86844C2D386D5ULL,
		0x931B24133184B61CULL,
		0x000000000F77658FULL
	}};
	shift = 28;
	printf("Test Case 175\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x91744C88F56BE781ULL,
		0x7256A8BA5B812223ULL,
		0xDCFE34B706A893E7ULL,
		0x6F9358958ED453E7ULL,
		0x20EA9F9B55431866ULL,
		0x7F5B0BEC0270A8C9ULL,
		0x384EC5884F76749FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x47AB5F3C08000000ULL,
		0xD2DC09111C8BA264ULL,
		0xB835449F3B92B545ULL,
		0xAC76A29F3EE7F1A5ULL,
		0xDAAA18C3337C9AC4ULL,
		0x60138546490754FCULL,
		0x427BB3A4FBFAD85FULL,
		0x0000000001C2762CULL
	}};
	shift = 27;
	printf("Test Case 176\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x73A3E077D3153091ULL,
		0xD4FEDB9650F51A9BULL,
		0x8F642BF0749E64ADULL,
		0xB4DC274439BC892EULL,
		0x208FDCE2B27C8C49ULL,
		0x8894CDC8420B057CULL,
		0xF77D18482D2EF0AAULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2200000000000000ULL,
		0x36E747C0EFA62A61ULL,
		0x5BA9FDB72CA1EA35ULL,
		0x5D1EC857E0E93CC9ULL,
		0x9369B84E88737912ULL,
		0xF8411FB9C564F918ULL,
		0x5511299B9084160AULL,
		0x01EEFA30905A5DE1ULL
	}};
	shift = 57;
	printf("Test Case 177\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x5EA4F9BA93DC9D0FULL,
		0x383DE8F2133CD83CULL,
		0x182330C2C65F5644ULL,
		0xEE201F8847B63FDDULL,
		0xD3B1BF451E83E17AULL,
		0xE5FDAD5CF0D7DE2AULL,
		0x3B8CB02F93A34494ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x72743C0000000000ULL,
		0xF360F17A93E6EA4FULL,
		0x7D5910E0F7A3C84CULL,
		0xD8FF74608CC30B19ULL,
		0x0F85EBB8807E211EULL,
		0x5F78AB4EC6FD147AULL,
		0x8D125397F6B573C3ULL,
		0x000000EE32C0BE4EULL
	}};
	shift = 42;
	printf("Test Case 178\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xD4259B0DCEABC23CULL,
		0xD6B02067075FDA06ULL,
		0x88CBFCC05620AB49ULL,
		0x6662FB5AFFFDECCEULL,
		0x990DA8618E859F82ULL,
		0x9269E6143EEEE87CULL,
		0xFD2C4B8BA999F8E9ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB0DCEABC23C00000ULL,
		0x067075FDA06D4259ULL,
		0xCC05620AB49D6B02ULL,
		0xB5AFFFDECCE88CBFULL,
		0x8618E859F826662FULL,
		0x6143EEEE87C990DAULL,
		0xB8BA999F8E99269EULL,
		0x00000000000FD2C4ULL
	}};
	shift = 20;
	printf("Test Case 179\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xF284FEA1605E389AULL,
		0x73EE46AEA04DB2CAULL,
		0x7230335A2AE0E638ULL,
		0x0F462DD6AA8A70D5ULL,
		0xACC402D39B88C436ULL,
		0xCD930C19D7C4DD61ULL,
		0xCB096B1BF77C6995ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFEA1605E389A0000ULL,
		0x46AEA04DB2CAF284ULL,
		0x335A2AE0E63873EEULL,
		0x2DD6AA8A70D57230ULL,
		0x02D39B88C4360F46ULL,
		0x0C19D7C4DD61ACC4ULL,
		0x6B1BF77C6995CD93ULL,
		0x000000000000CB09ULL
	}};
	shift = 16;
	printf("Test Case 180\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x1E4ADC6F356DB1FBULL,
		0x2F05C105EFB74295ULL,
		0x567682D3BE8E616BULL,
		0xC3F98B544C42560BULL,
		0x3189C5FB0BC01879ULL,
		0x715B812762FD629AULL,
		0xEEF44D6B84BD3F28ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAB6D8FD800000000ULL,
		0x7DBA14A8F256E379ULL,
		0xF4730B59782E082FULL,
		0x6212B05AB3B4169DULL,
		0x5E00C3CE1FCC5AA2ULL,
		0x17EB14D18C4E2FD8ULL,
		0x25E9F9438ADC093BULL,
		0x0000000777A26B5CULL
	}};
	shift = 35;
	printf("Test Case 181\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xBCE141012B8D90F5ULL,
		0xF091D04CE778D908ULL,
		0x64E4B50315A6FA06ULL,
		0xCA29C3BC1122671FULL,
		0x86BB8E750979AAE6ULL,
		0xFB2500CA5F7535ABULL,
		0x6C80E8C2780F881DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x21EA000000000000ULL,
		0xB21179C28202571BULL,
		0xF40DE123A099CEF1ULL,
		0xCE3EC9C96A062B4DULL,
		0x55CD945387782244ULL,
		0x6B570D771CEA12F3ULL,
		0x103BF64A0194BEEAULL,
		0x0000D901D184F01FULL
	}};
	shift = 49;
	printf("Test Case 182\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x404CA19E79EA289BULL,
		0x75517E376A6B4938ULL,
		0x9EAF86CA9797CFECULL,
		0x0B2E3A1527A90381ULL,
		0xD8EFCC184BC916D9ULL,
		0xDE800BB15363710EULL,
		0x4FCDF6EE8947F288ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA19E79EA289B0000ULL,
		0x7E376A6B4938404CULL,
		0x86CA9797CFEC7551ULL,
		0x3A1527A903819EAFULL,
		0xCC184BC916D90B2EULL,
		0x0BB15363710ED8EFULL,
		0xF6EE8947F288DE80ULL,
		0x0000000000004FCDULL
	}};
	shift = 16;
	printf("Test Case 183\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xD5F203A119177591ULL,
		0xD91A09D878ACC948ULL,
		0x32F1DC5888595F4DULL,
		0x778402AC389E4256ULL,
		0x915DE136E5509851ULL,
		0x712B721B3086F326ULL,
		0xE2E0782E6B8DEF7EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7C80E84645DD6440ULL,
		0x4682761E2B325235ULL,
		0xBC7716221657D376ULL,
		0xE100AB0E2790958CULL,
		0x57784DB95426145DULL,
		0x4ADC86CC21BCC9A4ULL,
		0xB81E0B9AE37BDF9CULL,
		0x0000000000000038ULL
	}};
	shift = 6;
	printf("Test Case 184\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xB63CB552B70ED739ULL,
		0xE336692A399E960BULL,
		0x846AE5D8D199430BULL,
		0x9F0559D0D860F045ULL,
		0x5A501A070B18FA81ULL,
		0x11E90F42C56AE734ULL,
		0x5136EB9985A08361ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8F2D54ADC3B5CE40ULL,
		0xCD9A4A8E67A582EDULL,
		0x1AB976346650C2F8ULL,
		0xC1567436183C1161ULL,
		0x940681C2C63EA067ULL,
		0x7A43D0B15AB9CD16ULL,
		0x4DBAE6616820D844ULL,
		0x0000000000000014ULL
	}};
	shift = 6;
	printf("Test Case 185\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xB2060913776B538EULL,
		0xD2D4DBFA1EE25761ULL,
		0x5EE999C4DC6674D4ULL,
		0xD7BD56D44C3C1E9AULL,
		0x56E5234BBF016ECFULL,
		0xFF343964CC025A68ULL,
		0x757618B87AAAE1E9ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB5A9C70000000000ULL,
		0x712BB0D9030489BBULL,
		0x333A6A696A6DFD0FULL,
		0x1E0F4D2F74CCE26EULL,
		0x80B767EBDEAB6A26ULL,
		0x012D342B7291A5DFULL,
		0x5570F4FF9A1CB266ULL,
		0x0000003ABB0C5C3DULL
	}};
	shift = 39;
	printf("Test Case 186\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x1D935D28A8586710ULL,
		0x0C67CED66CC6EABDULL,
		0xFB575F85A99065EBULL,
		0xE363BDD4D6E4354EULL,
		0xD377C5943A0A581DULL,
		0x3077DED254203F42ULL,
		0x3BEA2EB6822E221EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8800000000000000ULL,
		0x5E8EC9AE94542C33ULL,
		0xF58633E76B366375ULL,
		0xA77DABAFC2D4C832ULL,
		0x0EF1B1DEEA6B721AULL,
		0xA169BBE2CA1D052CULL,
		0x0F183BEF692A101FULL,
		0x001DF5175B411711ULL
	}};
	shift = 55;
	printf("Test Case 187\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xC7287C4E00CC9EA1ULL,
		0x5DDAFC8BD8A38AD7ULL,
		0xBAA6A4040C4C4804ULL,
		0x703FB6EE728CD3BFULL,
		0x942CC97B23753B5AULL,
		0x9D8E67961A44F199ULL,
		0xD28F4A115A4D1855ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8400000000000000ULL,
		0x5F1CA1F13803327AULL,
		0x11776BF22F628E2BULL,
		0xFEEA9A9010313120ULL,
		0x69C0FEDBB9CA334EULL,
		0x6650B325EC8DD4EDULL,
		0x5676399E586913C6ULL,
		0x034A3D2845693461ULL
	}};
	shift = 58;
	printf("Test Case 188\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xFDD127607D94FD10ULL,
		0xCE0C04C499D8B305ULL,
		0x7CFB4EE93D8E7B0DULL,
		0x989B80ECD98AC4A6ULL,
		0x5E51FA29C72EAA38ULL,
		0xD14F6418DAD346E0ULL,
		0xDF65819EC3C9E0DBULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0FB29FA200000000ULL,
		0x933B1660BFBA24ECULL,
		0x27B1CF61B9C18098ULL,
		0x9B315894CF9F69DDULL,
		0x38E5D5471313701DULL,
		0x1B5A68DC0BCA3F45ULL,
		0xD8793C1B7A29EC83ULL,
		0x000000001BECB033ULL
	}};
	shift = 29;
	printf("Test Case 189\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x3370E06BA834678DULL,
		0x16CB476C8C75BB93ULL,
		0xE42A1EAF40DDE7C5ULL,
		0x6318066FF5AFD6BFULL,
		0xCCF38296A2D50EC7ULL,
		0xFE96BA53CE12D7A7ULL,
		0xFF2E5BF50BBA4F1DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x66E1C0D75068CF1AULL,
		0x2D968ED918EB7726ULL,
		0xC8543D5E81BBCF8AULL,
		0xC6300CDFEB5FAD7FULL,
		0x99E7052D45AA1D8EULL,
		0xFD2D74A79C25AF4FULL,
		0xFE5CB7EA17749E3BULL,
		0x0000000000000001ULL
	}};
	shift = 1;
	printf("Test Case 190\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x725C66AB1B45D8EDULL,
		0x6DCE8FBA7E1D76B3ULL,
		0xC6E2385AE1C3E101ULL,
		0x4D092D3F7509D46FULL,
		0xCD5BE93829A732B4ULL,
		0x06BA1632867548D9ULL,
		0x1B9F29AFBD8D5359ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9719AAC6D1763B40ULL,
		0x73A3EE9F875DACDCULL,
		0xB88E16B870F8405BULL,
		0x424B4FDD42751BF1ULL,
		0x56FA4E0A69CCAD13ULL,
		0xAE858CA19D523673ULL,
		0xE7CA6BEF6354D641ULL,
		0x0000000000000006ULL
	}};
	shift = 6;
	printf("Test Case 191\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x9E0563522C46ECBEULL,
		0xA94EAA8F4F0CD70FULL,
		0x09F84C159CCF952BULL,
		0x21CE305FDA695296ULL,
		0xC8B213A5F8007CB2ULL,
		0x5CF22ED6F83198BFULL,
		0x953F41BCF8851A85ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC46ECBE000000000ULL,
		0xF0CD70F9E0563522ULL,
		0xCCF952BA94EAA8F4ULL,
		0xA69529609F84C159ULL,
		0x8007CB221CE305FDULL,
		0x83198BFC8B213A5FULL,
		0x8851A855CF22ED6FULL,
		0x0000000953F41BCFULL
	}};
	shift = 36;
	printf("Test Case 192\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xC3BDD5BCE2C4E318ULL,
		0x4D215CEADD56DDB7ULL,
		0x7239DC16820222D1ULL,
		0xC7E682D26AAE01D0ULL,
		0xEFB91691AA95199DULL,
		0xE94A2A0A6AD142E8ULL,
		0x78AF27C60E21AC69ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB138C60000000000ULL,
		0x55B76DF0EF756F38ULL,
		0x8088B45348573AB7ULL,
		0xAB80741C8E7705A0ULL,
		0xA5466771F9A0B49AULL,
		0xB450BA3BEE45A46AULL,
		0x886B1A7A528A829AULL,
		0x0000001E2BC9F183ULL
	}};
	shift = 38;
	printf("Test Case 193\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xBB941E2D77DB2C3BULL,
		0xCFC78737BDC45296ULL,
		0xCBB1764B0F880D55ULL,
		0x2748DEF1DC5975ABULL,
		0x5D44F555EF27288FULL,
		0x355F8E6C9A11A718ULL,
		0xEC01C40FF3A6178EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEC00000000000000ULL,
		0x5AEE5078B5DF6CB0ULL,
		0x573F1E1CDEF7114AULL,
		0xAF2EC5D92C3E2035ULL,
		0x3C9D237BC77165D6ULL,
		0x617513D557BC9CA2ULL,
		0x38D57E39B268469CULL,
		0x03B007103FCE985EULL
	}};
	shift = 58;
	printf("Test Case 194\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x459C70C41245FEADULL,
		0x33C8E75215225BA7ULL,
		0xD9E23E1F8A1615DBULL,
		0xC90AE95E74F38E8AULL,
		0x8B5FAF37FFF62CECULL,
		0x77B2E29E1C59D2B7ULL,
		0xF6C1CB88ECA6ED2DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFD5A000000000000ULL,
		0xB74E8B38E188248BULL,
		0x2BB66791CEA42A44ULL,
		0x1D15B3C47C3F142CULL,
		0x59D99215D2BCE9E7ULL,
		0xA56F16BF5E6FFFECULL,
		0xDA5AEF65C53C38B3ULL,
		0x0001ED839711D94DULL
	}};
	shift = 49;
	printf("Test Case 195\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x32C0E748E5F6C884ULL,
		0xB5DE0CF3D3780A21ULL,
		0x5C07F49CE7EE95BBULL,
		0xB14F8A22B4E22B31ULL,
		0xE1650593892A1EB3ULL,
		0xA4062C8AE13CDBB4ULL,
		0x47663EFD16A97D37ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3A472FB644200000ULL,
		0x679E9BC051099607ULL,
		0xA4E73F74ADDDAEF0ULL,
		0x5115A711598AE03FULL,
		0x2C9C4950F59D8A7CULL,
		0x645709E6DDA70B28ULL,
		0xF7E8B54BE9BD2031ULL,
		0x0000000000023B31ULL
	}};
	shift = 19;
	printf("Test Case 196\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x6BE1356276585353ULL,
		0x9247D6D52E9C4EFCULL,
		0x5FFA082EE5A52C78ULL,
		0x4EF4CF90EFA90F43ULL,
		0x042435EA3C95DB07ULL,
		0xF6DE1F7EFBCA542DULL,
		0x21ADF0A61F653F83ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3B2C29A980000000ULL,
		0x974E277E35F09AB1ULL,
		0x72D2963C4923EB6AULL,
		0x77D487A1AFFD0417ULL,
		0x1E4AED83A77A67C8ULL,
		0x7DE52A1682121AF5ULL,
		0x0FB29FC1FB6F0FBFULL,
		0x0000000010D6F853ULL
	}};
	shift = 31;
	printf("Test Case 197\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x3B7F1423A0C8B6C1ULL,
		0x12EC6BC6E1AC99DAULL,
		0xFCF2DD8A1AFEE29EULL,
		0x75CC57F1BB520187ULL,
		0x09752101C3234E69ULL,
		0xE97E7554237AD785ULL,
		0x50F719D2DE476F36ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB7F1423A0C8B6C10ULL,
		0x2EC6BC6E1AC99DA3ULL,
		0xCF2DD8A1AFEE29E1ULL,
		0x5CC57F1BB520187FULL,
		0x9752101C3234E697ULL,
		0x97E7554237AD7850ULL,
		0x0F719D2DE476F36EULL,
		0x0000000000000005ULL
	}};
	shift = 4;
	printf("Test Case 198\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xEC551F2592ED64FFULL,
		0x2F00C73173B548B3ULL,
		0xC5D3C01B2ECF0718ULL,
		0x516176F75DBB8F5CULL,
		0x4B417CD027875E90ULL,
		0x8D30F19575F42369ULL,
		0x518BABF1A2E9C88DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB593FC0000000000ULL,
		0xD522CFB1547C964BULL,
		0x3C1C60BC031CC5CEULL,
		0xEE3D73174F006CBBULL,
		0x1D7A414585DBDD76ULL,
		0xD08DA52D05F3409EULL,
		0xA7223634C3C655D7ULL,
		0x000001462EAFC68BULL
	}};
	shift = 42;
	printf("Test Case 199\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x58053D59C4F56E60ULL,
		0xC61148F263E12502ULL,
		0x000F626E0BFF97A4ULL,
		0xFEC4E6D76489EA36ULL,
		0xA3FE5D62215EAB3EULL,
		0x2EAEDD95CEB9A36EULL,
		0x5657097DFA0A147BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x27AB730000000000ULL,
		0x1F092812C029EACEULL,
		0x5FFCBD26308A4793ULL,
		0x244F51B0007B1370ULL,
		0x0AF559F7F62736BBULL,
		0x75CD1B751FF2EB11ULL,
		0xD050A3D97576ECAEULL,
		0x00000002B2B84BEFULL
	}};
	shift = 35;
	printf("Test Case 200\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 200 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -200;
	} else {
		printf("Test Case 200 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000020ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0002000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 44;
	printf("Test Case 201\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x0000000000000002ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000020000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 40;
	printf("Test Case 202\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000002000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 48;
	printf("Test Case 203\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x0080000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0800000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 4;
	printf("Test Case 204\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x0000000010000000ULL,
		0x0000000000000000ULL,
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
	shift = 0;
	printf("Test Case 205\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x0020000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0020000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 0;
	printf("Test Case 206\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x0000010000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 20;
	printf("Test Case 207\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000002000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0200000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 20;
	printf("Test Case 208\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000080000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000008000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 60;
	printf("Test Case 209\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0400000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 4;
	printf("Test Case 210\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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