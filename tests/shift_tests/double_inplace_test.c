#include "../tests.h"

int32_t curve25519_key_x2_inplace_test(void) {
	printf("Inplace Key Doubling Test\n");
	curve25519_key_t k1 = {.key64 = {
		0x73240311839FE664ULL,
		0xC1648A70D54393B6ULL,
		0x04BF03D42C535F12ULL,
		0x407FACF86496E3D5ULL,
		0x29C95EF4FA2E181BULL,
		0x6245173F15CE20A2ULL,
		0x6ED98334C755315FULL,
		0x1600078B4D8A4F38ULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0xE6480623073FCCC8ULL,
		0x82C914E1AA87276CULL,
		0x097E07A858A6BE25ULL,
		0x80FF59F0C92DC7AAULL,
		0x5392BDE9F45C3036ULL,
		0xC48A2E7E2B9C4144ULL,
		0xDDB306698EAA62BEULL,
		0x2C000F169B149E70ULL
	}};
	printf("Test Case 1\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x3A862EEDF95461FFULL,
		0x5B0D80470059F227ULL,
		0x2E725A863370E925ULL,
		0x8FA646CCB166CBB9ULL,
		0xE3A1B58AC099BE28ULL,
		0x024F4D53452DA0A0ULL,
		0xF96C2F52A18C9C1BULL,
		0x259137A036856F4AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x750C5DDBF2A8C3FEULL,
		0xB61B008E00B3E44EULL,
		0x5CE4B50C66E1D24AULL,
		0x1F4C8D9962CD9772ULL,
		0xC7436B1581337C51ULL,
		0x049E9AA68A5B4141ULL,
		0xF2D85EA543193836ULL,
		0x4B226F406D0ADE95ULL
	}};
	printf("Test Case 2\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xF521918D358C7BC6ULL,
		0x80DF81A2B655EEEDULL,
		0x0A602E10770BBCE7ULL,
		0xBF554978AB2D0562ULL,
		0x3926790303CCD2A7ULL,
		0xCB96D096E94076A6ULL,
		0x0C90BC845997D49BULL,
		0x2344542E07D78EB3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEA43231A6B18F78CULL,
		0x01BF03456CABDDDBULL,
		0x14C05C20EE1779CFULL,
		0x7EAA92F1565A0AC4ULL,
		0x724CF2060799A54FULL,
		0x972DA12DD280ED4CULL,
		0x19217908B32FA937ULL,
		0x4688A85C0FAF1D66ULL
	}};
	printf("Test Case 3\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xA2D9E970AC4B1129ULL,
		0x6388455043762CC1ULL,
		0x38B4906368D2830AULL,
		0xDFA3D5F88F886FD4ULL,
		0x3DF782D203A7775BULL,
		0x5B6C91A597245177ULL,
		0x1490F332274579A1ULL,
		0x2BF9300B444555ACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x45B3D2E158962252ULL,
		0xC7108AA086EC5983ULL,
		0x716920C6D1A50614ULL,
		0xBF47ABF11F10DFA8ULL,
		0x7BEF05A4074EEEB7ULL,
		0xB6D9234B2E48A2EEULL,
		0x2921E6644E8AF342ULL,
		0x57F26016888AAB58ULL
	}};
	printf("Test Case 4\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x68433F70D2AE1355ULL,
		0xCAC28EEA6B525A85ULL,
		0x0D328C2B166F9006ULL,
		0xA8F4395EC7825EE7ULL,
		0x9CE3870435BE598CULL,
		0x9A9797FDF6813945ULL,
		0xC65BB32AF28B6E48ULL,
		0x3C5C23CCCAAF0C11ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD0867EE1A55C26AAULL,
		0x95851DD4D6A4B50AULL,
		0x1A6518562CDF200DULL,
		0x51E872BD8F04BDCEULL,
		0x39C70E086B7CB319ULL,
		0x352F2FFBED02728BULL,
		0x8CB76655E516DC91ULL,
		0x78B84799955E1823ULL
	}};
	printf("Test Case 5\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xD588EFE006BB2923ULL,
		0xE0E0A0DD1F24F80DULL,
		0x2B1F1E1777C1CFA8ULL,
		0x600B6F176087C906ULL,
		0xB72A1A50701C4E64ULL,
		0x86DC3B36D1F099C3ULL,
		0x2A30BD688EFD7976ULL,
		0x29B0BBAC9BD4165DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAB11DFC00D765246ULL,
		0xC1C141BA3E49F01BULL,
		0x563E3C2EEF839F51ULL,
		0xC016DE2EC10F920CULL,
		0x6E5434A0E0389CC8ULL,
		0x0DB8766DA3E13387ULL,
		0x54617AD11DFAF2EDULL,
		0x5361775937A82CBAULL
	}};
	printf("Test Case 6\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x102ABB689A16225CULL,
		0x65A5908FD5CA4F97ULL,
		0xF490071889FA4E07ULL,
		0x55E236D3E8A41A33ULL,
		0x72A93D73077D655CULL,
		0xC64C398831B4D652ULL,
		0x047F214B8B4D8C0EULL,
		0x3859F006487B1FDDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x205576D1342C44B8ULL,
		0xCB4B211FAB949F2EULL,
		0xE9200E3113F49C0EULL,
		0xABC46DA7D1483467ULL,
		0xE5527AE60EFACAB8ULL,
		0x8C9873106369ACA4ULL,
		0x08FE4297169B181DULL,
		0x70B3E00C90F63FBAULL
	}};
	printf("Test Case 7\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xDA6C0CDDCB0E563EULL,
		0x42C6B4466F94ACA2ULL,
		0x3C97A4C850088F52ULL,
		0x81F554EC7489EF16ULL,
		0xAF3A6BCCCEB42D3DULL,
		0xA3060A4B142D6FA6ULL,
		0x7C42170D818A2914ULL,
		0x31A3C86B0B2BB778ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB4D819BB961CAC7CULL,
		0x858D688CDF295945ULL,
		0x792F4990A0111EA4ULL,
		0x03EAA9D8E913DE2CULL,
		0x5E74D7999D685A7BULL,
		0x460C1496285ADF4DULL,
		0xF8842E1B03145229ULL,
		0x634790D616576EF0ULL
	}};
	printf("Test Case 8\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x96AD378751EDA8F1ULL,
		0xFE26F2379A588B49ULL,
		0xFF975EB460E48A0EULL,
		0x4BC03658A576429FULL,
		0x82DC5F9E71730D92ULL,
		0x6230AACEC8FAA1DEULL,
		0xB4F08E3C6B1E8E48ULL,
		0x3993710B9041C43AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2D5A6F0EA3DB51E2ULL,
		0xFC4DE46F34B11693ULL,
		0xFF2EBD68C1C9141DULL,
		0x97806CB14AEC853FULL,
		0x05B8BF3CE2E61B24ULL,
		0xC461559D91F543BDULL,
		0x69E11C78D63D1C90ULL,
		0x7326E21720838875ULL
	}};
	printf("Test Case 9\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xA0DA290BE5029BE0ULL,
		0x4B74540D93EE20C9ULL,
		0x5F1F2BA13C780C3AULL,
		0xBC1ED58B6A340FF9ULL,
		0xC819E18E911FCEC5ULL,
		0x63D3A402DA1BE14AULL,
		0xE1543C8DE6D8EB0BULL,
		0x120C5697A5686207ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x41B45217CA0537C0ULL,
		0x96E8A81B27DC4193ULL,
		0xBE3E574278F01874ULL,
		0x783DAB16D4681FF2ULL,
		0x9033C31D223F9D8BULL,
		0xC7A74805B437C295ULL,
		0xC2A8791BCDB1D616ULL,
		0x2418AD2F4AD0C40FULL
	}};
	printf("Test Case 10\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x18D473B22FA29BBAULL,
		0x2EE9763F2858ADC8ULL,
		0xFC16CA5FDE7FBBF0ULL,
		0xF9E166E423FC9810ULL,
		0xA4789EECB01491F2ULL,
		0xFC193BD704371EB5ULL,
		0x7CE0A098190C2F3FULL,
		0x0C3867EF9C127F1EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x31A8E7645F453774ULL,
		0x5DD2EC7E50B15B90ULL,
		0xF82D94BFBCFF77E0ULL,
		0xF3C2CDC847F93021ULL,
		0x48F13DD9602923E5ULL,
		0xF83277AE086E3D6BULL,
		0xF9C1413032185E7FULL,
		0x1870CFDF3824FE3CULL
	}};
	printf("Test Case 11\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x72DD37495BE0A057ULL,
		0xDD719492CFB02CBFULL,
		0x2FEA4D1D81932F1AULL,
		0x7CA553B196CFE211ULL,
		0xFF98C078D51D9000ULL,
		0xEB5BD47776FC128FULL,
		0x10C54B57054A88C9ULL,
		0x165A2A11BD9A4586ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE5BA6E92B7C140AEULL,
		0xBAE329259F60597EULL,
		0x5FD49A3B03265E35ULL,
		0xF94AA7632D9FC422ULL,
		0xFF3180F1AA3B2000ULL,
		0xD6B7A8EEEDF8251FULL,
		0x218A96AE0A951193ULL,
		0x2CB454237B348B0CULL
	}};
	printf("Test Case 12\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x7AD7A54224DE059BULL,
		0x780047C8CE2167F3ULL,
		0x9414A39C23B5AD42ULL,
		0x2DBE907445E16105ULL,
		0xDAB28C8942C774BEULL,
		0xA01AB536359EF35FULL,
		0x50B727DE2A6A6A00ULL,
		0x1AE6678287EB1BEEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF5AF4A8449BC0B36ULL,
		0xF0008F919C42CFE6ULL,
		0x28294738476B5A84ULL,
		0x5B7D20E88BC2C20BULL,
		0xB5651912858EE97CULL,
		0x40356A6C6B3DE6BFULL,
		0xA16E4FBC54D4D401ULL,
		0x35CCCF050FD637DCULL
	}};
	printf("Test Case 13\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x79C2A2FD0EB5E449ULL,
		0x564A8D9C6E880AD2ULL,
		0x9DA26C4CC2099CAFULL,
		0xDB787CF6D83920C0ULL,
		0xF68F832817EA083DULL,
		0x2C20FC8ACF3BAD9BULL,
		0x5308BECBAAF3D4EBULL,
		0x1B6862D18ADC2DF4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF38545FA1D6BC892ULL,
		0xAC951B38DD1015A4ULL,
		0x3B44D8998413395EULL,
		0xB6F0F9EDB0724181ULL,
		0xED1F06502FD4107BULL,
		0x5841F9159E775B37ULL,
		0xA6117D9755E7A9D6ULL,
		0x36D0C5A315B85BE8ULL
	}};
	printf("Test Case 14\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x5AA536F8F882A48BULL,
		0x38C0027BE497CC24ULL,
		0xAABDCFC62F8DA0D1ULL,
		0xC02D7332C59BCD01ULL,
		0xF07E86A796191E7BULL,
		0xFC24F6DE2FF9B06EULL,
		0xB1232D64BFB53FE0ULL,
		0x3E46074F700F6A6CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB54A6DF1F1054916ULL,
		0x718004F7C92F9848ULL,
		0x557B9F8C5F1B41A2ULL,
		0x805AE6658B379A03ULL,
		0xE0FD0D4F2C323CF7ULL,
		0xF849EDBC5FF360DDULL,
		0x62465AC97F6A7FC1ULL,
		0x7C8C0E9EE01ED4D9ULL
	}};
	printf("Test Case 15\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xDE0F04DD94B38D66ULL,
		0xC341F7096C301443ULL,
		0x3C629B3479D3C7E7ULL,
		0xF00BEB77FC8A06F8ULL,
		0x742768B58685EC61ULL,
		0x6DD363883ED9E81AULL,
		0x61798DFE6A8C534EULL,
		0x324C5BD8E439D5CAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBC1E09BB29671ACCULL,
		0x8683EE12D8602887ULL,
		0x78C53668F3A78FCFULL,
		0xE017D6EFF9140DF0ULL,
		0xE84ED16B0D0BD8C3ULL,
		0xDBA6C7107DB3D034ULL,
		0xC2F31BFCD518A69CULL,
		0x6498B7B1C873AB94ULL
	}};
	printf("Test Case 16\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x726721B4AF25C148ULL,
		0x10EDA1FF4E5C59F2ULL,
		0x6DF9DAC6E19637C7ULL,
		0x3C64996EC161ED62ULL,
		0xB73FE813398C3A0EULL,
		0x660E96BF9E77C9BBULL,
		0xB099815318A52D52ULL,
		0x2573254CC293C6B4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE4CE43695E4B8290ULL,
		0x21DB43FE9CB8B3E4ULL,
		0xDBF3B58DC32C6F8EULL,
		0x78C932DD82C3DAC4ULL,
		0x6E7FD0267318741CULL,
		0xCC1D2D7F3CEF9377ULL,
		0x613302A6314A5AA4ULL,
		0x4AE64A9985278D69ULL
	}};
	printf("Test Case 17\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xCDD2DA14684F8A38ULL,
		0x60AEACA00499BB81ULL,
		0x215773DD07104084ULL,
		0x1FA7D8B008FEC680ULL,
		0x6DA96879C4860359ULL,
		0xAE129516604F91D3ULL,
		0xF49048A1A8BDE6B9ULL,
		0x1434F942B748374FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9BA5B428D09F1470ULL,
		0xC15D594009337703ULL,
		0x42AEE7BA0E208108ULL,
		0x3F4FB16011FD8D00ULL,
		0xDB52D0F3890C06B2ULL,
		0x5C252A2CC09F23A6ULL,
		0xE9209143517BCD73ULL,
		0x2869F2856E906E9FULL
	}};
	printf("Test Case 18\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x519FF6E5F3F64365ULL,
		0x67F3CBDF34B3BB62ULL,
		0xBA0877CC42A79803ULL,
		0xD3FB3DAAB678C214ULL,
		0x13DE6B9F77B95946ULL,
		0xFEFFA672C8ACBD9DULL,
		0x0B0A3826559B91F0ULL,
		0x3FD08335498BE53AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA33FEDCBE7EC86CAULL,
		0xCFE797BE696776C4ULL,
		0x7410EF98854F3006ULL,
		0xA7F67B556CF18429ULL,
		0x27BCD73EEF72B28DULL,
		0xFDFF4CE591597B3AULL,
		0x1614704CAB3723E1ULL,
		0x7FA1066A9317CA74ULL
	}};
	printf("Test Case 19\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x6FF45EDDA78AE138ULL,
		0x2A6587D806C7AE78ULL,
		0x520C76A1EC00FAADULL,
		0x1F93D598821CBC2AULL,
		0x85BCA3006752A1D1ULL,
		0xC2738096FD04EB0FULL,
		0xEA5A1BB64C944BB4ULL,
		0x0EF726C7F56DACD1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDFE8BDBB4F15C270ULL,
		0x54CB0FB00D8F5CF0ULL,
		0xA418ED43D801F55AULL,
		0x3F27AB3104397854ULL,
		0x0B794600CEA543A2ULL,
		0x84E7012DFA09D61FULL,
		0xD4B4376C99289769ULL,
		0x1DEE4D8FEADB59A3ULL
	}};
	printf("Test Case 20\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x44748B1FC7B0286EULL,
		0xDEC5A86DFBC177C1ULL,
		0x4A2D9F658E04A356ULL,
		0x35942054DB794D5AULL,
		0xB313075BE8136DD1ULL,
		0x6A7B580E9AA14FE8ULL,
		0x1F689686AA395D27ULL,
		0x008D2E1919B931E5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x88E9163F8F6050DCULL,
		0xBD8B50DBF782EF82ULL,
		0x945B3ECB1C0946ADULL,
		0x6B2840A9B6F29AB4ULL,
		0x66260EB7D026DBA2ULL,
		0xD4F6B01D35429FD1ULL,
		0x3ED12D0D5472BA4EULL,
		0x011A5C32337263CAULL
	}};
	printf("Test Case 21\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x62BC701468B0E582ULL,
		0x3C47552D9B2FD7C1ULL,
		0x67D0693F0D6BA7B8ULL,
		0x6C162EEF36091C69ULL,
		0xA9B822F829E81F7BULL,
		0x4F6C5484562AA192ULL,
		0x9519FB2DCF8D947AULL,
		0x198CA055C40EDC72ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC578E028D161CB04ULL,
		0x788EAA5B365FAF82ULL,
		0xCFA0D27E1AD74F70ULL,
		0xD82C5DDE6C1238D2ULL,
		0x537045F053D03EF6ULL,
		0x9ED8A908AC554325ULL,
		0x2A33F65B9F1B28F4ULL,
		0x331940AB881DB8E5ULL
	}};
	printf("Test Case 22\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x570210C76C7E7CEDULL,
		0x73018C9DA6E3DE99ULL,
		0x8C99BDBB268F56F6ULL,
		0x6BE1D7EBBB1B33E3ULL,
		0x13437862C94F4A18ULL,
		0xB970089968BCB81FULL,
		0xF41D3256AD3FA1C1ULL,
		0x1B35AB8137331452ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAE04218ED8FCF9DAULL,
		0xE603193B4DC7BD32ULL,
		0x19337B764D1EADECULL,
		0xD7C3AFD7763667C7ULL,
		0x2686F0C5929E9430ULL,
		0x72E01132D179703EULL,
		0xE83A64AD5A7F4383ULL,
		0x366B57026E6628A5ULL
	}};
	printf("Test Case 23\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xADE2CD28A42F3421ULL,
		0x046F8E63E73C0F1DULL,
		0x49B37F754AE5629CULL,
		0xBD670B985B1B6BCCULL,
		0x08CBECB98E2FF187ULL,
		0x6EF24FB8B62A8AFAULL,
		0x18E671B0A0911336ULL,
		0x34228382ECB8883CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5BC59A51485E6842ULL,
		0x08DF1CC7CE781E3BULL,
		0x9366FEEA95CAC538ULL,
		0x7ACE1730B636D798ULL,
		0x1197D9731C5FE30FULL,
		0xDDE49F716C5515F4ULL,
		0x31CCE3614122266CULL,
		0x68450705D9711078ULL
	}};
	printf("Test Case 24\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x733DE5549EA6B45EULL,
		0xBE02B46A2F007A35ULL,
		0x77B0F43624FA85BFULL,
		0x8A7E2322A981EA24ULL,
		0x02883C6FCD3ED719ULL,
		0x332C0CE32C583B77ULL,
		0xB5269806163E390BULL,
		0x0DBE1FBF3598325CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE67BCAA93D4D68BCULL,
		0x7C0568D45E00F46AULL,
		0xEF61E86C49F50B7FULL,
		0x14FC46455303D448ULL,
		0x051078DF9A7DAE33ULL,
		0x665819C658B076EEULL,
		0x6A4D300C2C7C7216ULL,
		0x1B7C3F7E6B3064B9ULL
	}};
	printf("Test Case 25\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xC1F36DADBA41ABAAULL,
		0x72CC4509D83E9C4DULL,
		0x0238E047D7285293ULL,
		0x6A5276EC21D2F7CCULL,
		0x1F945E0516AF524DULL,
		0x41EA7AC05F0DF058ULL,
		0xF05ADD73C2E72150ULL,
		0x13BD10C063E6DF69ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x83E6DB5B74835754ULL,
		0xE5988A13B07D389BULL,
		0x0471C08FAE50A526ULL,
		0xD4A4EDD843A5EF98ULL,
		0x3F28BC0A2D5EA49AULL,
		0x83D4F580BE1BE0B0ULL,
		0xE0B5BAE785CE42A0ULL,
		0x277A2180C7CDBED3ULL
	}};
	printf("Test Case 26\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x44DFD9891CD897B2ULL,
		0xD99CB3A9D0BC217BULL,
		0x976093047F0C3B72ULL,
		0xAB5012D9C54E69EFULL,
		0xA18919AFE28AE3E9ULL,
		0x0A537FB24ADFBE44ULL,
		0xA8785A06AD121857ULL,
		0x3566287591C44F0CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x89BFB31239B12F64ULL,
		0xB3396753A17842F6ULL,
		0x2EC12608FE1876E5ULL,
		0x56A025B38A9CD3DFULL,
		0x4312335FC515C7D3ULL,
		0x14A6FF6495BF7C89ULL,
		0x50F0B40D5A2430AEULL,
		0x6ACC50EB23889E19ULL
	}};
	printf("Test Case 27\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x39761013F6F42411ULL,
		0x86125CF10042D65FULL,
		0x0552E25AC7ABA890ULL,
		0xB9576669B2797B66ULL,
		0xB221B03B2E7F5C23ULL,
		0xDE0A23D1B336E073ULL,
		0x0B7C15AC399D5F29ULL,
		0x368FEE4B68675CA5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x72EC2027EDE84822ULL,
		0x0C24B9E20085ACBEULL,
		0x0AA5C4B58F575121ULL,
		0x72AECCD364F2F6CCULL,
		0x644360765CFEB847ULL,
		0xBC1447A3666DC0E7ULL,
		0x16F82B58733ABE53ULL,
		0x6D1FDC96D0CEB94AULL
	}};
	printf("Test Case 28\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xB58475BB928A97F4ULL,
		0x2A2D7C2096CE84DEULL,
		0xC87350959989F955ULL,
		0xD018DD91F257905DULL,
		0xB9892D52849A08AAULL,
		0x97C70DC4AC563E79ULL,
		0x3690A04159F40504ULL,
		0x201CBA652EC75AD3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6B08EB7725152FE8ULL,
		0x545AF8412D9D09BDULL,
		0x90E6A12B3313F2AAULL,
		0xA031BB23E4AF20BBULL,
		0x73125AA509341155ULL,
		0x2F8E1B8958AC7CF3ULL,
		0x6D214082B3E80A09ULL,
		0x403974CA5D8EB5A6ULL
	}};
	printf("Test Case 29\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x54906AD142BAC6D9ULL,
		0xE64C1B69AA76D9E5ULL,
		0x4505ECF0FF5C8C74ULL,
		0xBB4BEEAA5E84A60DULL,
		0xAD27C6E0829DCA52ULL,
		0x30D0D7CD1C42CB0AULL,
		0xA9637849D278CB7DULL,
		0x3479A22E0574EE5CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA920D5A285758DB2ULL,
		0xCC9836D354EDB3CAULL,
		0x8A0BD9E1FEB918E9ULL,
		0x7697DD54BD094C1AULL,
		0x5A4F8DC1053B94A5ULL,
		0x61A1AF9A38859615ULL,
		0x52C6F093A4F196FAULL,
		0x68F3445C0AE9DCB9ULL
	}};
	printf("Test Case 30\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x8254C9B8C31336BBULL,
		0xC43B8C004C7D02E7ULL,
		0xE8D001EB065BF5B9ULL,
		0xAE5267EE89055972ULL,
		0x4777378D90776E9EULL,
		0x07DEB320FDAFCB3FULL,
		0x595E13A1072A3412ULL,
		0x0A1039CCA9A44B60ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x04A9937186266D76ULL,
		0x8877180098FA05CFULL,
		0xD1A003D60CB7EB73ULL,
		0x5CA4CFDD120AB2E5ULL,
		0x8EEE6F1B20EEDD3DULL,
		0x0FBD6641FB5F967EULL,
		0xB2BC27420E546824ULL,
		0x14207399534896C0ULL
	}};
	printf("Test Case 31\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x0A4E5AB9D73B63C2ULL,
		0x6DCBEEE8BBF99035ULL,
		0xC2C67DE23A0BD77FULL,
		0xF7D6695509A025A6ULL,
		0xAA33904532BEA2B8ULL,
		0x93E93E464A0AC12AULL,
		0x57123BB86D8FDB47ULL,
		0x2525A711BB60D534ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x149CB573AE76C784ULL,
		0xDB97DDD177F3206AULL,
		0x858CFBC47417AEFEULL,
		0xEFACD2AA13404B4DULL,
		0x5467208A657D4571ULL,
		0x27D27C8C94158255ULL,
		0xAE247770DB1FB68FULL,
		0x4A4B4E2376C1AA68ULL
	}};
	printf("Test Case 32\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xB92A1FD12F5BC24DULL,
		0xF1F1DFB30B0448A3ULL,
		0x8D0055E11FB7CFB8ULL,
		0xD8B93E6D730DE579ULL,
		0xF3686CD6A5BF144DULL,
		0xA5BAEAA9942F4D5FULL,
		0x21819EC75D697B71ULL,
		0x1C724119BBEA8B41ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x72543FA25EB7849AULL,
		0xE3E3BF6616089147ULL,
		0x1A00ABC23F6F9F71ULL,
		0xB1727CDAE61BCAF3ULL,
		0xE6D0D9AD4B7E289BULL,
		0x4B75D553285E9ABFULL,
		0x43033D8EBAD2F6E3ULL,
		0x38E4823377D51682ULL
	}};
	printf("Test Case 33\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x6AE9A8B63BA51B71ULL,
		0x3EC205DC9AF265D5ULL,
		0x9C08B1CBAD049DC6ULL,
		0xCCBB43CC440D2092ULL,
		0x986699CF1F68E602ULL,
		0xDFCFFA411029F179ULL,
		0x9CA678117C9B65D8ULL,
		0x174A63E74A3BE348ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD5D3516C774A36E2ULL,
		0x7D840BB935E4CBAAULL,
		0x381163975A093B8CULL,
		0x99768798881A4125ULL,
		0x30CD339E3ED1CC05ULL,
		0xBF9FF4822053E2F3ULL,
		0x394CF022F936CBB1ULL,
		0x2E94C7CE9477C691ULL
	}};
	printf("Test Case 34\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x4CC81EEEE0EB964FULL,
		0xB5C2E9F6CF8E6BDFULL,
		0x9191569F6F724FEDULL,
		0x1E55D7708F81A0F0ULL,
		0x9B13C77D96FEE4E1ULL,
		0x86E2D11F3836715EULL,
		0x8AEFBAA47E02942EULL,
		0x38A853CC22D3B824ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x99903DDDC1D72C9EULL,
		0x6B85D3ED9F1CD7BEULL,
		0x2322AD3EDEE49FDBULL,
		0x3CABAEE11F0341E1ULL,
		0x36278EFB2DFDC9C2ULL,
		0x0DC5A23E706CE2BDULL,
		0x15DF7548FC05285DULL,
		0x7150A79845A77049ULL
	}};
	printf("Test Case 35\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x82BABFF09607C5F5ULL,
		0x9D98194EA1A7BFE0ULL,
		0x558CB1D54DA8D630ULL,
		0x0648B46AF16E5FBAULL,
		0x440E0328464DE66CULL,
		0x02527B6F86AF3447ULL,
		0x3E65B0B42350CE95ULL,
		0x1CCBEED38818681BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x05757FE12C0F8BEAULL,
		0x3B30329D434F7FC1ULL,
		0xAB1963AA9B51AC61ULL,
		0x0C9168D5E2DCBF74ULL,
		0x881C06508C9BCCD8ULL,
		0x04A4F6DF0D5E688EULL,
		0x7CCB616846A19D2AULL,
		0x3997DDA71030D036ULL
	}};
	printf("Test Case 36\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x1885223BD1EB9D5EULL,
		0x880146D0CE513CB6ULL,
		0x110BAAA61D2A1C2AULL,
		0x7676576360D8D415ULL,
		0x9ED20327FFB85CCCULL,
		0x39BDD3667E8133DDULL,
		0x726B8B8E84586DD4ULL,
		0x062B9EB195350179ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x310A4477A3D73ABCULL,
		0x10028DA19CA2796CULL,
		0x2217554C3A543855ULL,
		0xECECAEC6C1B1A82AULL,
		0x3DA4064FFF70B998ULL,
		0x737BA6CCFD0267BBULL,
		0xE4D7171D08B0DBA8ULL,
		0x0C573D632A6A02F2ULL
	}};
	printf("Test Case 37\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x68E237F2EB167923ULL,
		0x21E6120308B2681EULL,
		0x3FF1CF5D1599EC3CULL,
		0xF79DDE19CC220F6BULL,
		0x1D04087593B4AFA5ULL,
		0x1F612263FDA4B4C6ULL,
		0xA4153AEDD3D6E1C6ULL,
		0x2F90BAD7E5217244ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD1C46FE5D62CF246ULL,
		0x43CC24061164D03CULL,
		0x7FE39EBA2B33D878ULL,
		0xEF3BBC3398441ED6ULL,
		0x3A0810EB27695F4BULL,
		0x3EC244C7FB49698CULL,
		0x482A75DBA7ADC38CULL,
		0x5F2175AFCA42E489ULL
	}};
	printf("Test Case 38\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x9DE66A0B4CFEE00EULL,
		0x57AFE3AB85CCD9C4ULL,
		0x1DD45CD79A679075ULL,
		0xB5A45E599FCE80C8ULL,
		0xA4950BB1F2FA71A8ULL,
		0xD6ECF67EB4375ACCULL,
		0x472F9366237CE10EULL,
		0x25087E833FFF48D2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3BCCD41699FDC01CULL,
		0xAF5FC7570B99B389ULL,
		0x3BA8B9AF34CF20EAULL,
		0x6B48BCB33F9D0190ULL,
		0x492A1763E5F4E351ULL,
		0xADD9ECFD686EB599ULL,
		0x8E5F26CC46F9C21DULL,
		0x4A10FD067FFE91A4ULL
	}};
	printf("Test Case 39\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xD9E0E3B1F18AF2C1ULL,
		0xD02ECFFBF1EFEF26ULL,
		0x28F3E1065D48D73EULL,
		0xCD14B61D9030BA05ULL,
		0xB006405806BD6AA5ULL,
		0xB575DA7E469C46C1ULL,
		0xD9813E1F573D75A7ULL,
		0x3D6E2FA6EFB17C81ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB3C1C763E315E582ULL,
		0xA05D9FF7E3DFDE4DULL,
		0x51E7C20CBA91AE7DULL,
		0x9A296C3B2061740AULL,
		0x600C80B00D7AD54BULL,
		0x6AEBB4FC8D388D83ULL,
		0xB3027C3EAE7AEB4FULL,
		0x7ADC5F4DDF62F903ULL
	}};
	printf("Test Case 40\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x2FE619312998EA25ULL,
		0xCAE359C94CF47C89ULL,
		0xBB8F3047CCA542D3ULL,
		0xE3B40F921F510C81ULL,
		0xD598EDEF334DF177ULL,
		0x766080EFAE421034ULL,
		0x97E520BFAD2F7242ULL,
		0x2F394B8E5788A4C4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5FCC32625331D44AULL,
		0x95C6B39299E8F912ULL,
		0x771E608F994A85A7ULL,
		0xC7681F243EA21903ULL,
		0xAB31DBDE669BE2EFULL,
		0xECC101DF5C842069ULL,
		0x2FCA417F5A5EE484ULL,
		0x5E72971CAF114989ULL
	}};
	printf("Test Case 41\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x9C452499797C7C2CULL,
		0xDF5F42E006E5D5CBULL,
		0x9669F908CAEBCFF9ULL,
		0x73EF2CE2BD1E3D6DULL,
		0x252990006B1992EDULL,
		0xB4EE733133EFDC77ULL,
		0x883E78924973B93FULL,
		0x127E49E9813825AAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x388A4932F2F8F858ULL,
		0xBEBE85C00DCBAB97ULL,
		0x2CD3F21195D79FF3ULL,
		0xE7DE59C57A3C7ADBULL,
		0x4A532000D63325DAULL,
		0x69DCE66267DFB8EEULL,
		0x107CF12492E7727FULL,
		0x24FC93D302704B55ULL
	}};
	printf("Test Case 42\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x105359A664599F06ULL,
		0xD40C874A8E9DEE5FULL,
		0xFCC2608F5C2AC43EULL,
		0xCD29EE6D1F408473ULL,
		0x8D374D13314BE1CCULL,
		0xEABB6253FD5C1DB6ULL,
		0x24D6660EABBC5754ULL,
		0x2E32619FB22A2415ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x20A6B34CC8B33E0CULL,
		0xA8190E951D3BDCBEULL,
		0xF984C11EB855887DULL,
		0x9A53DCDA3E8108E7ULL,
		0x1A6E9A266297C399ULL,
		0xD576C4A7FAB83B6DULL,
		0x49ACCC1D5778AEA9ULL,
		0x5C64C33F6454482AULL
	}};
	printf("Test Case 43\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x11EA41708AAE90B7ULL,
		0xD197B8D535FD8E5BULL,
		0xB4748826B9F26FFAULL,
		0xEA73BB8E8B6E7150ULL,
		0xBFED0565E84ECFF5ULL,
		0x4EA7BDE096AC697FULL,
		0xA0E357FF4D971292ULL,
		0x3C4460FA43961E62ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x23D482E1155D216EULL,
		0xA32F71AA6BFB1CB6ULL,
		0x68E9104D73E4DFF5ULL,
		0xD4E7771D16DCE2A1ULL,
		0x7FDA0ACBD09D9FEBULL,
		0x9D4F7BC12D58D2FFULL,
		0x41C6AFFE9B2E2524ULL,
		0x7888C1F4872C3CC5ULL
	}};
	printf("Test Case 44\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xE8EDDBD8C2E52F69ULL,
		0xCB581CCC289DE3D4ULL,
		0xB7486830F2F8BEB2ULL,
		0xDB8A0675B42C9B86ULL,
		0x89BA4242F226AD52ULL,
		0x4A33E52B69165B3FULL,
		0x7C7DDB1F5CE9C6D1ULL,
		0x352345B54ED0572BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD1DBB7B185CA5ED2ULL,
		0x96B03998513BC7A9ULL,
		0x6E90D061E5F17D65ULL,
		0xB7140CEB6859370DULL,
		0x13748485E44D5AA5ULL,
		0x9467CA56D22CB67FULL,
		0xF8FBB63EB9D38DA2ULL,
		0x6A468B6A9DA0AE56ULL
	}};
	printf("Test Case 45\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x90F261078836F583ULL,
		0x6BDF93CEA4C17962ULL,
		0xC5E79B3F009E9D5AULL,
		0xD852882156456C57ULL,
		0xC61D56960EB68A52ULL,
		0xB61741BCFB319FE8ULL,
		0x41DD15FE4716FB6FULL,
		0x13AD7F2D61A0EE75ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x21E4C20F106DEB06ULL,
		0xD7BF279D4982F2C5ULL,
		0x8BCF367E013D3AB4ULL,
		0xB0A51042AC8AD8AFULL,
		0x8C3AAD2C1D6D14A5ULL,
		0x6C2E8379F6633FD1ULL,
		0x83BA2BFC8E2DF6DFULL,
		0x275AFE5AC341DCEAULL
	}};
	printf("Test Case 46\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x914420976E673946ULL,
		0xD6E630C30AA72138ULL,
		0xE97584256A7572F9ULL,
		0x6CD3F82996A0AD26ULL,
		0x0AB792488C457531ULL,
		0x742AAC5A6B5DF618ULL,
		0x97F92EBA2149AC59ULL,
		0x109495CCFCF380F4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2288412EDCCE728CULL,
		0xADCC6186154E4271ULL,
		0xD2EB084AD4EAE5F3ULL,
		0xD9A7F0532D415A4DULL,
		0x156F2491188AEA62ULL,
		0xE85558B4D6BBEC30ULL,
		0x2FF25D74429358B2ULL,
		0x21292B99F9E701E9ULL
	}};
	printf("Test Case 47\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x1689A3366CD60D84ULL,
		0xD8AA47696F15088EULL,
		0xC634E2CCD83995A3ULL,
		0xBA4461711012343CULL,
		0xCAE832DB4CFB076AULL,
		0x7A26B4D63FCB36B1ULL,
		0xA9E6F2D600A97B35ULL,
		0x1A87731815FE7B53ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2D13466CD9AC1B08ULL,
		0xB1548ED2DE2A111CULL,
		0x8C69C599B0732B47ULL,
		0x7488C2E220246879ULL,
		0x95D065B699F60ED5ULL,
		0xF44D69AC7F966D63ULL,
		0x53CDE5AC0152F66AULL,
		0x350EE6302BFCF6A7ULL
	}};
	printf("Test Case 48\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x6A9F30B1BF561D33ULL,
		0xB4411EBE27BF8650ULL,
		0x51991BE0DB1B69E0ULL,
		0xA93FABBFE64EA153ULL,
		0x759AD1D96A0A34F4ULL,
		0x4A18628FD2FCD2E8ULL,
		0x7C12E5F06585CEB4ULL,
		0x094FF7920333958BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD53E61637EAC3A66ULL,
		0x68823D7C4F7F0CA0ULL,
		0xA33237C1B636D3C1ULL,
		0x527F577FCC9D42A6ULL,
		0xEB35A3B2D41469E9ULL,
		0x9430C51FA5F9A5D0ULL,
		0xF825CBE0CB0B9D68ULL,
		0x129FEF2406672B16ULL
	}};
	printf("Test Case 49\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x53AA82154763278DULL,
		0x1A5CCC5D0CEE8B22ULL,
		0x408F03548C4D9260ULL,
		0x9D7A34768FD841D9ULL,
		0x80CBA00FE3ECBB34ULL,
		0x13536FDCA4680ACAULL,
		0xA2EFC0932DFBFBCCULL,
		0x0F5F93B0FC7BECA6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA755042A8EC64F1AULL,
		0x34B998BA19DD1644ULL,
		0x811E06A9189B24C0ULL,
		0x3AF468ED1FB083B2ULL,
		0x0197401FC7D97669ULL,
		0x26A6DFB948D01595ULL,
		0x45DF81265BF7F798ULL,
		0x1EBF2761F8F7D94DULL
	}};
	printf("Test Case 50\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xC69600D1DEE3B5A3ULL,
		0x877A878CFCCE38D0ULL,
		0x30F6884EED16F0A5ULL,
		0xEE4256DA717DFAC3ULL,
		0x69A89DD184889589ULL,
		0x19D3655BDE41827EULL,
		0xA1EE0976FCEBE59AULL,
		0x2A46E7260B6E855DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8D2C01A3BDC76B46ULL,
		0x0EF50F19F99C71A1ULL,
		0x61ED109DDA2DE14BULL,
		0xDC84ADB4E2FBF586ULL,
		0xD3513BA309112B13ULL,
		0x33A6CAB7BC8304FCULL,
		0x43DC12EDF9D7CB34ULL,
		0x548DCE4C16DD0ABBULL
	}};
	printf("Test Case 51\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x13F6637DA9CF3D5CULL,
		0x008DD8D20E8C23A8ULL,
		0xE947D51DB4E447FFULL,
		0x3C337591D4CF0604ULL,
		0x31CC9645DB1B8235ULL,
		0x9B65B95C78A92A05ULL,
		0x61D60BD082B3EAA1ULL,
		0x2344AA73F3E4C2F5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x27ECC6FB539E7AB8ULL,
		0x011BB1A41D184750ULL,
		0xD28FAA3B69C88FFEULL,
		0x7866EB23A99E0C09ULL,
		0x63992C8BB637046AULL,
		0x36CB72B8F152540AULL,
		0xC3AC17A10567D543ULL,
		0x468954E7E7C985EAULL
	}};
	printf("Test Case 52\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x3A69112E527F5871ULL,
		0xA5C9251505848829ULL,
		0x4A3E85961A33F225ULL,
		0xFA71DF53FA09E5D6ULL,
		0xF3E461A845C6401FULL,
		0x18FB548AF36381E0ULL,
		0x759CC88E43234718ULL,
		0x0D5A1D1521550A07ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x74D2225CA4FEB0E2ULL,
		0x4B924A2A0B091052ULL,
		0x947D0B2C3467E44BULL,
		0xF4E3BEA7F413CBACULL,
		0xE7C8C3508B8C803FULL,
		0x31F6A915E6C703C1ULL,
		0xEB39911C86468E30ULL,
		0x1AB43A2A42AA140EULL
	}};
	printf("Test Case 53\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xC88B3A8617F6F671ULL,
		0xF2BDBE5CAA8C160AULL,
		0x00C1149E02098AF6ULL,
		0x98F4F3A638ABED4FULL,
		0xD245C61967CD56DCULL,
		0xA5E13E7DE3CE59C9ULL,
		0x12CD046BCB1E9708ULL,
		0x08C65E50AAFD9020ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9116750C2FEDECE2ULL,
		0xE57B7CB955182C15ULL,
		0x0182293C041315EDULL,
		0x31E9E74C7157DA9EULL,
		0xA48B8C32CF9AADB9ULL,
		0x4BC27CFBC79CB393ULL,
		0x259A08D7963D2E11ULL,
		0x118CBCA155FB2040ULL
	}};
	printf("Test Case 54\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xB5F21C76544BD142ULL,
		0xE0AF7061519BF576ULL,
		0xC04F37CA1EE9832DULL,
		0xE3EDDFE1F4DC15F5ULL,
		0xBD34BECE95AE3958ULL,
		0xD1A76132396D6D13ULL,
		0xDB5DCA11473C6B96ULL,
		0x230C16939C7488B5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6BE438ECA897A284ULL,
		0xC15EE0C2A337EAEDULL,
		0x809E6F943DD3065BULL,
		0xC7DBBFC3E9B82BEBULL,
		0x7A697D9D2B5C72B1ULL,
		0xA34EC26472DADA27ULL,
		0xB6BB94228E78D72DULL,
		0x46182D2738E9116BULL
	}};
	printf("Test Case 55\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xC63A499329D22DADULL,
		0x7F4512F3D78A9701ULL,
		0xC42B4765DDBDB83BULL,
		0x2EA300D49A102548ULL,
		0xBCDEC38E1FEC99CEULL,
		0x461D70D1D9D8D9B8ULL,
		0x8E120C005E522524ULL,
		0x2AE91857AF701D37ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8C74932653A45B5AULL,
		0xFE8A25E7AF152E03ULL,
		0x88568ECBBB7B7076ULL,
		0x5D4601A934204A91ULL,
		0x79BD871C3FD9339CULL,
		0x8C3AE1A3B3B1B371ULL,
		0x1C241800BCA44A48ULL,
		0x55D230AF5EE03A6FULL
	}};
	printf("Test Case 56\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xE2A83C940D657574ULL,
		0x9FC1D14021666706ULL,
		0xE2A04F8641CD454CULL,
		0xFCEDE9332279213BULL,
		0x7F6AFDD00ECD540CULL,
		0x2552270147F6B713ULL,
		0xE4DF13D8D94E238FULL,
		0x245DB5D8A977E77EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC55079281ACAEAE8ULL,
		0x3F83A28042CCCE0DULL,
		0xC5409F0C839A8A99ULL,
		0xF9DBD26644F24277ULL,
		0xFED5FBA01D9AA819ULL,
		0x4AA44E028FED6E26ULL,
		0xC9BE27B1B29C471EULL,
		0x48BB6BB152EFCEFDULL
	}};
	printf("Test Case 57\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x6B9AD8DE394665E2ULL,
		0xFC2F61C2CFD05A6AULL,
		0xEA1C7BAFCA2ADFEEULL,
		0x7D9101FF05E55C63ULL,
		0xD96F4F8B1C09CD8DULL,
		0xECC1FC5478870295ULL,
		0xC1D5D30D2DD30598ULL,
		0x05A5152FCF97E56EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD735B1BC728CCBC4ULL,
		0xF85EC3859FA0B4D4ULL,
		0xD438F75F9455BFDDULL,
		0xFB2203FE0BCAB8C7ULL,
		0xB2DE9F1638139B1AULL,
		0xD983F8A8F10E052BULL,
		0x83ABA61A5BA60B31ULL,
		0x0B4A2A5F9F2FCADDULL
	}};
	printf("Test Case 58\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xE17FB17C0E9EC3B9ULL,
		0x17FC33B92286D4A4ULL,
		0x040F7AAF58BBCE5CULL,
		0xE47D13181F2CDDEFULL,
		0x94D7E81F8378C882ULL,
		0x6EC5772B1FCC3AA8ULL,
		0x37F8E4C17E88F257ULL,
		0x2212E7EEC70A0119ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC2FF62F81D3D8772ULL,
		0x2FF86772450DA949ULL,
		0x081EF55EB1779CB8ULL,
		0xC8FA26303E59BBDEULL,
		0x29AFD03F06F19105ULL,
		0xDD8AEE563F987551ULL,
		0x6FF1C982FD11E4AEULL,
		0x4425CFDD8E140232ULL
	}};
	printf("Test Case 59\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x28A15326482D9B8AULL,
		0x9471A739A867664AULL,
		0x0AC95B6B48B7E861ULL,
		0x9C2244DF9D0BD4A3ULL,
		0x54985D099C1E8807ULL,
		0x3492774FB9C3150DULL,
		0x0A8D78824813BDF2ULL,
		0x17C17ACF9898DB62ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5142A64C905B3714ULL,
		0x28E34E7350CECC94ULL,
		0x1592B6D6916FD0C3ULL,
		0x384489BF3A17A946ULL,
		0xA930BA13383D100FULL,
		0x6924EE9F73862A1AULL,
		0x151AF10490277BE4ULL,
		0x2F82F59F3131B6C4ULL
	}};
	printf("Test Case 60\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x14CF4B2B016AE807ULL,
		0x2802C22E17014AC4ULL,
		0xAEC3D8148F43DAFAULL,
		0x8E9121006A82A8E6ULL,
		0x7619CB042CDE9484ULL,
		0x9787E44DA3209DBAULL,
		0x7FF4F9CADE597086ULL,
		0x1924BC95A56A15EEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x299E965602D5D00EULL,
		0x5005845C2E029588ULL,
		0x5D87B0291E87B5F4ULL,
		0x1D224200D50551CDULL,
		0xEC33960859BD2909ULL,
		0x2F0FC89B46413B74ULL,
		0xFFE9F395BCB2E10DULL,
		0x3249792B4AD42BDCULL
	}};
	printf("Test Case 61\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x47223DD06636A4C3ULL,
		0x411EDC1CC8785D9EULL,
		0x1103F0D9BC5596C6ULL,
		0xC3C3CAF134A32B6BULL,
		0x6B6077F8EAE4AE68ULL,
		0x09B7F2FE1C4A9F99ULL,
		0x90ADF4271CF8F4B7ULL,
		0x32FAD6AE77B981E8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8E447BA0CC6D4986ULL,
		0x823DB83990F0BB3CULL,
		0x2207E1B378AB2D8CULL,
		0x878795E2694656D6ULL,
		0xD6C0EFF1D5C95CD1ULL,
		0x136FE5FC38953F32ULL,
		0x215BE84E39F1E96EULL,
		0x65F5AD5CEF7303D1ULL
	}};
	printf("Test Case 62\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xCF83B76C07346B03ULL,
		0x9325877D578C58B8ULL,
		0x4C7FB7EC30C0F4EAULL,
		0x08B5B50D51C570B6ULL,
		0x1BF791854F26EBCAULL,
		0xE993185226487629ULL,
		0xCECCC8EDF9CE5C01ULL,
		0x2446F9EAE8CF7F6EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9F076ED80E68D606ULL,
		0x264B0EFAAF18B171ULL,
		0x98FF6FD86181E9D5ULL,
		0x116B6A1AA38AE16CULL,
		0x37EF230A9E4DD794ULL,
		0xD32630A44C90EC52ULL,
		0x9D9991DBF39CB803ULL,
		0x488DF3D5D19EFEDDULL
	}};
	printf("Test Case 63\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x328EFC5E504583A1ULL,
		0x169C75F202E4E2CBULL,
		0x8417583E8A3CB41DULL,
		0x7F27C911435942CBULL,
		0xCBE470A62B7FC3C7ULL,
		0xB440919D04E41A05ULL,
		0xEC7D9E9BC6364F9EULL,
		0x3FC8250B52A8C34BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x651DF8BCA08B0742ULL,
		0x2D38EBE405C9C596ULL,
		0x082EB07D1479683AULL,
		0xFE4F922286B28597ULL,
		0x97C8E14C56FF878EULL,
		0x6881233A09C8340BULL,
		0xD8FB3D378C6C9F3DULL,
		0x7F904A16A5518697ULL
	}};
	printf("Test Case 64\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xA8116954FBA02C68ULL,
		0x3EE41F070BE1D673ULL,
		0x2836CB7B009A5176ULL,
		0x333FC01576CD91DDULL,
		0x76A74C389716F546ULL,
		0x77CCACA5EECE9A6DULL,
		0x1C36B52B352C8302ULL,
		0x0CA5AFD1964BB66BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5022D2A9F74058D0ULL,
		0x7DC83E0E17C3ACE7ULL,
		0x506D96F60134A2ECULL,
		0x667F802AED9B23BAULL,
		0xED4E98712E2DEA8CULL,
		0xEF99594BDD9D34DAULL,
		0x386D6A566A590604ULL,
		0x194B5FA32C976CD6ULL
	}};
	printf("Test Case 65\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x4C3DCB236AD1272FULL,
		0xC9653B6E451B41B5ULL,
		0xC71BC5DADD533EBAULL,
		0xFD4348F3F5A10D96ULL,
		0x376EF4554CA235C2ULL,
		0xDFD12B0750C999BCULL,
		0x6FDBB26ED473466FULL,
		0x189B588225ADD0F6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x987B9646D5A24E5EULL,
		0x92CA76DC8A36836AULL,
		0x8E378BB5BAA67D75ULL,
		0xFA8691E7EB421B2DULL,
		0x6EDDE8AA99446B85ULL,
		0xBFA2560EA1933378ULL,
		0xDFB764DDA8E68CDFULL,
		0x3136B1044B5BA1ECULL
	}};
	printf("Test Case 66\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x7C2CBBE0E6AE34A9ULL,
		0xA7D3206EF994F717ULL,
		0x659447D1EFAEC111ULL,
		0x3DA13D1FBCF58A44ULL,
		0xE655A91EFAFFBE76ULL,
		0xA551811DA1372222ULL,
		0x13F5379B8F0609E9ULL,
		0x3A22D8763FF10791ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF85977C1CD5C6952ULL,
		0x4FA640DDF329EE2EULL,
		0xCB288FA3DF5D8223ULL,
		0x7B427A3F79EB1488ULL,
		0xCCAB523DF5FF7CECULL,
		0x4AA3023B426E4445ULL,
		0x27EA6F371E0C13D3ULL,
		0x7445B0EC7FE20F22ULL
	}};
	printf("Test Case 67\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x9A830D046638D48AULL,
		0x6A5D6B402A0EC01BULL,
		0xA8A225AC8F954F0CULL,
		0x3EF7F00FC97154EDULL,
		0x689E7FBD3E09D6B4ULL,
		0x312B3699F11F85CFULL,
		0x23E24CBA84990955ULL,
		0x030E495C154A36D3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x35061A08CC71A914ULL,
		0xD4BAD680541D8037ULL,
		0x51444B591F2A9E18ULL,
		0x7DEFE01F92E2A9DBULL,
		0xD13CFF7A7C13AD68ULL,
		0x62566D33E23F0B9EULL,
		0x47C49975093212AAULL,
		0x061C92B82A946DA6ULL
	}};
	printf("Test Case 68\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x63E55293A5259E62ULL,
		0x3E320F84D24B68EBULL,
		0xB85F2B98C3F16627ULL,
		0xA72F902F08216337ULL,
		0xFC03754F47D17DF0ULL,
		0xCFC008F28593F7C2ULL,
		0x2962AB996D090789ULL,
		0x247FCD64FFD6248EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC7CAA5274A4B3CC4ULL,
		0x7C641F09A496D1D6ULL,
		0x70BE573187E2CC4EULL,
		0x4E5F205E1042C66FULL,
		0xF806EA9E8FA2FBE1ULL,
		0x9F8011E50B27EF85ULL,
		0x52C55732DA120F13ULL,
		0x48FF9AC9FFAC491CULL
	}};
	printf("Test Case 69\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xD2766FC90BCB36ABULL,
		0x611EEC49FC590C18ULL,
		0xE94E49E9123D34BDULL,
		0x05742B88E4BA0EB1ULL,
		0x7372F03ACA8B16ACULL,
		0x515231C4141E9799ULL,
		0x4F9D79A43B8C9D21ULL,
		0x0917A4680380AA2FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA4ECDF9217966D56ULL,
		0xC23DD893F8B21831ULL,
		0xD29C93D2247A697AULL,
		0x0AE85711C9741D63ULL,
		0xE6E5E07595162D58ULL,
		0xA2A46388283D2F32ULL,
		0x9F3AF34877193A42ULL,
		0x122F48D00701545EULL
	}};
	printf("Test Case 70\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xB6CED4FD88EF292AULL,
		0x42600242E285ED5AULL,
		0xEE50E3E5D392B7FAULL,
		0x106D23EF718AE882ULL,
		0xDE6BCAA21FAC68A8ULL,
		0x29B3B4C14BB1B1F3ULL,
		0x90DA5367AEFB16C3ULL,
		0x2E8F66D78BE328DCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6D9DA9FB11DE5254ULL,
		0x84C00485C50BDAB5ULL,
		0xDCA1C7CBA7256FF4ULL,
		0x20DA47DEE315D105ULL,
		0xBCD795443F58D150ULL,
		0x53676982976363E7ULL,
		0x21B4A6CF5DF62D86ULL,
		0x5D1ECDAF17C651B9ULL
	}};
	printf("Test Case 71\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x883807D503A6760BULL,
		0xA83290D5A248AEC2ULL,
		0x5F10EE07E52AC862ULL,
		0x48A8FC169B21CCE0ULL,
		0xE5F210052826B76EULL,
		0x4468900941953EDDULL,
		0x3021DBE89DEE9C38ULL,
		0x3EAA82F047225FA6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x10700FAA074CEC16ULL,
		0x506521AB44915D85ULL,
		0xBE21DC0FCA5590C5ULL,
		0x9151F82D364399C0ULL,
		0xCBE4200A504D6EDCULL,
		0x88D12012832A7DBBULL,
		0x6043B7D13BDD3870ULL,
		0x7D5505E08E44BF4CULL
	}};
	printf("Test Case 72\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xAD6EA4245717FBF2ULL,
		0x475D8B4AD77678F1ULL,
		0x7FA41F64767BCF99ULL,
		0xA603F51E49DE7189ULL,
		0x19CB8F66127C8011ULL,
		0xF9DA56D587C354E7ULL,
		0x648F7852578D6E1CULL,
		0x09F576CC25816918ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5ADD4848AE2FF7E4ULL,
		0x8EBB1695AEECF1E3ULL,
		0xFF483EC8ECF79F32ULL,
		0x4C07EA3C93BCE312ULL,
		0x33971ECC24F90023ULL,
		0xF3B4ADAB0F86A9CEULL,
		0xC91EF0A4AF1ADC39ULL,
		0x13EAED984B02D230ULL
	}};
	printf("Test Case 73\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xCFC5F77D873C6E57ULL,
		0xF910B19D026BFEF3ULL,
		0x4D83DABB6715E576ULL,
		0x11A21E4238DDA869ULL,
		0xB1DE94FF2ED4EEF0ULL,
		0x55CC9624F915F948ULL,
		0xE036FF3838877A88ULL,
		0x34A95D9968B69F4BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9F8BEEFB0E78DCAEULL,
		0xF221633A04D7FDE7ULL,
		0x9B07B576CE2BCAEDULL,
		0x23443C8471BB50D2ULL,
		0x63BD29FE5DA9DDE0ULL,
		0xAB992C49F22BF291ULL,
		0xC06DFE70710EF510ULL,
		0x6952BB32D16D3E97ULL
	}};
	printf("Test Case 74\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xFEC34970DFA082AFULL,
		0xDECAE9C2615426F5ULL,
		0x6499EADB9BCBC278ULL,
		0xA2A7A2F50E3AED5CULL,
		0xE9F3AE85B08B2B1AULL,
		0x3556C186B9464DC8ULL,
		0x772BA8F66E8FAEBEULL,
		0x32C1FA106B1EBCE0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFD8692E1BF41055EULL,
		0xBD95D384C2A84DEBULL,
		0xC933D5B7379784F1ULL,
		0x454F45EA1C75DAB8ULL,
		0xD3E75D0B61165635ULL,
		0x6AAD830D728C9B91ULL,
		0xEE5751ECDD1F5D7CULL,
		0x6583F420D63D79C0ULL
	}};
	printf("Test Case 75\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xB500DEE5F9FA4EC4ULL,
		0x3DBE32D81821BE5BULL,
		0xC7E9C5E2DA3CF4E5ULL,
		0x7FD1DF361D5D06BAULL,
		0xCFFCBEC22E193CDFULL,
		0x893575342E3F7F4AULL,
		0x5BDD11669A6F1078ULL,
		0x1F03586C7C8C1D4EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6A01BDCBF3F49D88ULL,
		0x7B7C65B030437CB7ULL,
		0x8FD38BC5B479E9CAULL,
		0xFFA3BE6C3ABA0D75ULL,
		0x9FF97D845C3279BEULL,
		0x126AEA685C7EFE95ULL,
		0xB7BA22CD34DE20F1ULL,
		0x3E06B0D8F9183A9CULL
	}};
	printf("Test Case 76\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x54A165FE3AB16D8CULL,
		0xC7192E6C40D669CBULL,
		0x744776BBF8FC87EAULL,
		0x2EAF339C3439F78CULL,
		0x62CBA52BD86D0D3BULL,
		0xC521CF1294FE994BULL,
		0x5A5C58E3CB5A8113ULL,
		0x0D855E8B51F490A5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA942CBFC7562DB18ULL,
		0x8E325CD881ACD396ULL,
		0xE88EED77F1F90FD5ULL,
		0x5D5E67386873EF18ULL,
		0xC5974A57B0DA1A76ULL,
		0x8A439E2529FD3296ULL,
		0xB4B8B1C796B50227ULL,
		0x1B0ABD16A3E9214AULL
	}};
	printf("Test Case 77\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x3676395BE8E1BB5FULL,
		0x1DE772BF2F7C2311ULL,
		0xB3FFF1D0B2994C43ULL,
		0xD296C13C375A081BULL,
		0x3AFAB703F7FF25C7ULL,
		0xCADFDB0795DF1644ULL,
		0x3F9ADE0C7CF29575ULL,
		0x016DB169897B1011ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6CEC72B7D1C376BEULL,
		0x3BCEE57E5EF84622ULL,
		0x67FFE3A165329886ULL,
		0xA52D82786EB41037ULL,
		0x75F56E07EFFE4B8FULL,
		0x95BFB60F2BBE2C88ULL,
		0x7F35BC18F9E52AEBULL,
		0x02DB62D312F62022ULL
	}};
	printf("Test Case 78\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x00FA4B31850A6B2BULL,
		0xE2AA865577B1B7F2ULL,
		0xC5C38ABF549EEF6AULL,
		0x0609709EB24A2A80ULL,
		0xEAD2C4E923BBCBF4ULL,
		0x68906293C4ED6EB0ULL,
		0xDC8899439630CDE2ULL,
		0x3245CA69B71D802BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x01F496630A14D656ULL,
		0xC5550CAAEF636FE4ULL,
		0x8B87157EA93DDED5ULL,
		0x0C12E13D64945501ULL,
		0xD5A589D2477797E8ULL,
		0xD120C52789DADD61ULL,
		0xB91132872C619BC4ULL,
		0x648B94D36E3B0057ULL
	}};
	printf("Test Case 79\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x368111CA41759B1FULL,
		0xD47819B18CFE8C6CULL,
		0xCF33469C07497FACULL,
		0xC0617B6DA075921CULL,
		0xB1ACBD0E575A5887ULL,
		0xEFBFD1C1839BB177ULL,
		0x556489C43B4AF136ULL,
		0x3BE0515AB0B3D01FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6D02239482EB363EULL,
		0xA8F0336319FD18D8ULL,
		0x9E668D380E92FF59ULL,
		0x80C2F6DB40EB2439ULL,
		0x63597A1CAEB4B10FULL,
		0xDF7FA383073762EFULL,
		0xAAC913887695E26DULL,
		0x77C0A2B56167A03EULL
	}};
	printf("Test Case 80\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xD73CCFA205C1492CULL,
		0x9CA67103600FB5CAULL,
		0x61DBD0919EC19CDBULL,
		0x5A5800B9C0B085FAULL,
		0x7583715FE1F52FA5ULL,
		0x9323DC39220C1571ULL,
		0x6705BD151F6A6A16ULL,
		0x24E6472326D94F92ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAE799F440B829258ULL,
		0x394CE206C01F6B95ULL,
		0xC3B7A1233D8339B7ULL,
		0xB4B0017381610BF4ULL,
		0xEB06E2BFC3EA5F4AULL,
		0x2647B87244182AE2ULL,
		0xCE0B7A2A3ED4D42DULL,
		0x49CC8E464DB29F24ULL
	}};
	printf("Test Case 81\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x57B9877F92AD00DDULL,
		0x7890F7BA3C22E8DEULL,
		0x7D79099E561D5C3CULL,
		0x91680EB53BAAF86EULL,
		0x0868B8D2837158BEULL,
		0xF83E406D7D8284A5ULL,
		0x82724DD2A9ACC1E5ULL,
		0x13DAD9E941A31A15ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF730EFF255A01BAULL,
		0xF121EF747845D1BCULL,
		0xFAF2133CAC3AB878ULL,
		0x22D01D6A7755F0DCULL,
		0x10D171A506E2B17DULL,
		0xF07C80DAFB05094AULL,
		0x04E49BA5535983CBULL,
		0x27B5B3D28346342BULL
	}};
	printf("Test Case 82\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x04026F5AF650CE9AULL,
		0x893DD4277064D03CULL,
		0x5D93F751C1AB445DULL,
		0x001F55AF83707194ULL,
		0xCF58418350417419ULL,
		0x58F7A70245CE4FF3ULL,
		0x0E2406E51B81A28CULL,
		0x26B685378F5BAE02ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0804DEB5ECA19D34ULL,
		0x127BA84EE0C9A078ULL,
		0xBB27EEA3835688BBULL,
		0x003EAB5F06E0E328ULL,
		0x9EB08306A082E832ULL,
		0xB1EF4E048B9C9FE7ULL,
		0x1C480DCA37034518ULL,
		0x4D6D0A6F1EB75C04ULL
	}};
	printf("Test Case 83\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x77597BDDD2D3E80DULL,
		0x9F0186D6EC1D3965ULL,
		0xFA4E579BB1BA2D4BULL,
		0x13EA28E5923ECD0AULL,
		0x6CE5509BF00A76AEULL,
		0x6130593E4CB48BEBULL,
		0x1E9467FD30EBD795ULL,
		0x18F0550F36B6118EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEEB2F7BBA5A7D01AULL,
		0x3E030DADD83A72CAULL,
		0xF49CAF3763745A97ULL,
		0x27D451CB247D9A15ULL,
		0xD9CAA137E014ED5CULL,
		0xC260B27C996917D6ULL,
		0x3D28CFFA61D7AF2AULL,
		0x31E0AA1E6D6C231CULL
	}};
	printf("Test Case 84\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xA723EAE762203C96ULL,
		0x611F20A89C98C205ULL,
		0x455BDC87C4D60CD8ULL,
		0x97996A8E0F61B611ULL,
		0x663374FE4ECDC943ULL,
		0x73ED2E6DD2E08910ULL,
		0x98D30E2CA63AC37BULL,
		0x296C917DCF08EB2BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4E47D5CEC440792CULL,
		0xC23E41513931840BULL,
		0x8AB7B90F89AC19B0ULL,
		0x2F32D51C1EC36C22ULL,
		0xCC66E9FC9D9B9287ULL,
		0xE7DA5CDBA5C11220ULL,
		0x31A61C594C7586F6ULL,
		0x52D922FB9E11D657ULL
	}};
	printf("Test Case 85\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xB51CF2EB950161F2ULL,
		0x7087C7F197151B60ULL,
		0xB94BCDC56BACFC0CULL,
		0xDC87B050F5F6136AULL,
		0x3DD402FAC7CA1903ULL,
		0xA7F2665E9011C690ULL,
		0xA7E97DEF9105D99AULL,
		0x05AF9B2FA92F1402ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6A39E5D72A02C3E4ULL,
		0xE10F8FE32E2A36C1ULL,
		0x72979B8AD759F818ULL,
		0xB90F60A1EBEC26D5ULL,
		0x7BA805F58F943207ULL,
		0x4FE4CCBD20238D20ULL,
		0x4FD2FBDF220BB335ULL,
		0x0B5F365F525E2805ULL
	}};
	printf("Test Case 86\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x246F6B5919E7F29AULL,
		0x86025721DCA89F6BULL,
		0x54FB4C0ECBC37126ULL,
		0x701C8463DEC22794ULL,
		0x99767C8B86C0194DULL,
		0xA86776D858EFAA4AULL,
		0x02A743A85CE3FBBBULL,
		0x2377DE1E078D9BF3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x48DED6B233CFE534ULL,
		0x0C04AE43B9513ED6ULL,
		0xA9F6981D9786E24DULL,
		0xE03908C7BD844F28ULL,
		0x32ECF9170D80329AULL,
		0x50CEEDB0B1DF5495ULL,
		0x054E8750B9C7F777ULL,
		0x46EFBC3C0F1B37E6ULL
	}};
	printf("Test Case 87\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xBB0611EF23902C57ULL,
		0x23F5743F948407B0ULL,
		0xC7496692947A07D1ULL,
		0xAF400891EC8CDD4BULL,
		0xD0CED4864F0E64CEULL,
		0x750346AF1739D2E9ULL,
		0x28E2A31F8C50DBE6ULL,
		0x02EAF60A4C2DCF56ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x760C23DE472058AEULL,
		0x47EAE87F29080F61ULL,
		0x8E92CD2528F40FA2ULL,
		0x5E801123D919BA97ULL,
		0xA19DA90C9E1CC99DULL,
		0xEA068D5E2E73A5D3ULL,
		0x51C5463F18A1B7CCULL,
		0x05D5EC14985B9EACULL
	}};
	printf("Test Case 88\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x05E83119902EB581ULL,
		0xE8F22B02FA5EFCF7ULL,
		0x6BF13C8B4DC64483ULL,
		0x7EEB3E5E99606CF5ULL,
		0x3C32843633491271ULL,
		0x7EB2CC4DC3944F3DULL,
		0x36F7EBF8F53E55A2ULL,
		0x15809154E18344F5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0BD06233205D6B02ULL,
		0xD1E45605F4BDF9EEULL,
		0xD7E279169B8C8907ULL,
		0xFDD67CBD32C0D9EAULL,
		0x7865086C669224E2ULL,
		0xFD65989B87289E7AULL,
		0x6DEFD7F1EA7CAB44ULL,
		0x2B0122A9C30689EAULL
	}};
	printf("Test Case 89\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xC60E19DCF7E5CD7FULL,
		0x61F37536E2C970D0ULL,
		0x3C9A613BB487A07DULL,
		0x43388031AA457103ULL,
		0xD32C96510071FB19ULL,
		0x7D71381C5CF10FA9ULL,
		0x08595490E592C59FULL,
		0x1E1672A84E358ADAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8C1C33B9EFCB9AFEULL,
		0xC3E6EA6DC592E1A1ULL,
		0x7934C277690F40FAULL,
		0x86710063548AE206ULL,
		0xA6592CA200E3F632ULL,
		0xFAE27038B9E21F53ULL,
		0x10B2A921CB258B3EULL,
		0x3C2CE5509C6B15B4ULL
	}};
	printf("Test Case 90\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x4B0DF522EF866FB0ULL,
		0x0E3FB105CAC26972ULL,
		0x1364897CC5B1E71CULL,
		0x01BD7F032B207825ULL,
		0xFDABA376FCCE1402ULL,
		0x4997ED03C51687F0ULL,
		0x2637CBFFCD1E1B05ULL,
		0x11467A0F533A8FD0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x961BEA45DF0CDF60ULL,
		0x1C7F620B9584D2E4ULL,
		0x26C912F98B63CE38ULL,
		0x037AFE065640F04AULL,
		0xFB5746EDF99C2804ULL,
		0x932FDA078A2D0FE1ULL,
		0x4C6F97FF9A3C360AULL,
		0x228CF41EA6751FA0ULL
	}};
	printf("Test Case 91\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xC48374151CC87ED5ULL,
		0x2860796BC33D2DDFULL,
		0x97D860DB4F4ADD91ULL,
		0x023CC414AB192B6EULL,
		0xF045AB40189454ABULL,
		0xC05D228E8A4E5350ULL,
		0x60A66BFAAA2CA182ULL,
		0x3360287BC2FF5180ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8906E82A3990FDAAULL,
		0x50C0F2D7867A5BBFULL,
		0x2FB0C1B69E95BB22ULL,
		0x04798829563256DDULL,
		0xE08B56803128A956ULL,
		0x80BA451D149CA6A1ULL,
		0xC14CD7F554594305ULL,
		0x66C050F785FEA300ULL
	}};
	printf("Test Case 92\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x7988EF704E6C6F23ULL,
		0x75BE5A75A3AC3199ULL,
		0xE1DACFD301E3E8A0ULL,
		0x38A4EF7AA41B6CBDULL,
		0x13E6ABBF32E16E33ULL,
		0x70F5DC0026E89264ULL,
		0xDED4B0B12F8841D3ULL,
		0x138FB620EBAA4ED6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF311DEE09CD8DE46ULL,
		0xEB7CB4EB47586332ULL,
		0xC3B59FA603C7D140ULL,
		0x7149DEF54836D97BULL,
		0x27CD577E65C2DC66ULL,
		0xE1EBB8004DD124C8ULL,
		0xBDA961625F1083A6ULL,
		0x271F6C41D7549DADULL
	}};
	printf("Test Case 93\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x276C10BF872602E4ULL,
		0x34DB94B69C055D0CULL,
		0x4E754D6680953EAAULL,
		0x0D405FF7376D4330ULL,
		0x244487FDA6E154E9ULL,
		0xE7CA7DCF2AE94AEBULL,
		0xDC2C4C07B2DEA778ULL,
		0x2CA6106920225BCFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4ED8217F0E4C05C8ULL,
		0x69B7296D380ABA18ULL,
		0x9CEA9ACD012A7D54ULL,
		0x1A80BFEE6EDA8660ULL,
		0x48890FFB4DC2A9D2ULL,
		0xCF94FB9E55D295D6ULL,
		0xB858980F65BD4EF1ULL,
		0x594C20D24044B79FULL
	}};
	printf("Test Case 94\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xCBB6876FACF6AEEEULL,
		0xB9A721D6A6619903ULL,
		0xEAA132CE9C778ACEULL,
		0xFF9F339FDDEF6CA6ULL,
		0x20806ED82422BBF3ULL,
		0xC0601298080BF106ULL,
		0xCA43F99E4B310831ULL,
		0x15747ABBE69E890DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x976D0EDF59ED5DDCULL,
		0x734E43AD4CC33207ULL,
		0xD542659D38EF159DULL,
		0xFF3E673FBBDED94DULL,
		0x4100DDB0484577E7ULL,
		0x80C025301017E20CULL,
		0x9487F33C96621063ULL,
		0x2AE8F577CD3D121BULL
	}};
	printf("Test Case 95\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x6B32CBCED1149F0EULL,
		0xD206D7A8C275DFACULL,
		0x043D3B4B9BB0C66AULL,
		0x1B997C0B7C49C8C1ULL,
		0x5A808AD3F7A38FE4ULL,
		0x056306D4EEC9E67EULL,
		0xB544ED8C7BE42886ULL,
		0x127C603A24E7960DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD665979DA2293E1CULL,
		0xA40DAF5184EBBF58ULL,
		0x087A769737618CD5ULL,
		0x3732F816F8939182ULL,
		0xB50115A7EF471FC8ULL,
		0x0AC60DA9DD93CCFCULL,
		0x6A89DB18F7C8510CULL,
		0x24F8C07449CF2C1BULL
	}};
	printf("Test Case 96\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xE2B3B6D7E00B3850ULL,
		0x1C610EED82513E84ULL,
		0xD7C813DAC51C3789ULL,
		0xB36B69239D0C8FEFULL,
		0x6D8CE9713915F3D1ULL,
		0x72841797E2D102E7ULL,
		0xA4DD9C32311106E4ULL,
		0x230EF8BBA7E1F4CAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC5676DAFC01670A0ULL,
		0x38C21DDB04A27D09ULL,
		0xAF9027B58A386F12ULL,
		0x66D6D2473A191FDFULL,
		0xDB19D2E2722BE7A3ULL,
		0xE5082F2FC5A205CEULL,
		0x49BB386462220DC8ULL,
		0x461DF1774FC3E995ULL
	}};
	printf("Test Case 97\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x8CBBE1B834FE714BULL,
		0x99E7DF30FAF2D33CULL,
		0x0F27B0F01AF5B460ULL,
		0xB4314D07CDFBF3E2ULL,
		0x101152A5D7D7F2E8ULL,
		0xD6C681EEC1715BC7ULL,
		0x78D58A5EE3E9BF4EULL,
		0x361A2F1FB5580F38ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1977C37069FCE296ULL,
		0x33CFBE61F5E5A679ULL,
		0x1E4F61E035EB68C1ULL,
		0x68629A0F9BF7E7C4ULL,
		0x2022A54BAFAFE5D1ULL,
		0xAD8D03DD82E2B78EULL,
		0xF1AB14BDC7D37E9DULL,
		0x6C345E3F6AB01E70ULL
	}};
	printf("Test Case 98\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x92DC7F3442084894ULL,
		0xEB5727A4FBC09A6EULL,
		0x348549B25C792C9DULL,
		0x1AECF99F09FB5EBAULL,
		0xDF80B79EBB54EED3ULL,
		0x9F1B574D191A4CDBULL,
		0x11004303BD7FD77DULL,
		0x062DDE3F61EF1C9AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x25B8FE6884109128ULL,
		0xD6AE4F49F78134DDULL,
		0x690A9364B8F2593BULL,
		0x35D9F33E13F6BD74ULL,
		0xBF016F3D76A9DDA6ULL,
		0x3E36AE9A323499B7ULL,
		0x220086077AFFAEFBULL,
		0x0C5BBC7EC3DE3934ULL
	}};
	printf("Test Case 99\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x8F04C8E39322AFDCULL,
		0xFE5ACF3159D7C230ULL,
		0x60BD6E295AFC59C1ULL,
		0x5905F3BF9B618013ULL,
		0xC20A18AC3C90F23BULL,
		0x366517A9CB5AE938ULL,
		0xB58429E6CF436084ULL,
		0x1FD88E1BDED28466ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1E0991C726455FB8ULL,
		0xFCB59E62B3AF8461ULL,
		0xC17ADC52B5F8B383ULL,
		0xB20BE77F36C30026ULL,
		0x841431587921E476ULL,
		0x6CCA2F5396B5D271ULL,
		0x6B0853CD9E86C108ULL,
		0x3FB11C37BDA508CDULL
	}};
	printf("Test Case 100\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xC8AE8EEBF061AF48ULL,
		0x6783652A2FD7300AULL,
		0x38B6D0C4617A8410ULL,
		0x4922DAFF52DE6A1FULL,
		0x102558A80E512434ULL,
		0x0F33D7FCFD1B5BABULL,
		0x1CC7A18A0111B394ULL,
		0x1686BFB874C71058ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x915D1DD7E0C35E90ULL,
		0xCF06CA545FAE6015ULL,
		0x716DA188C2F50820ULL,
		0x9245B5FEA5BCD43EULL,
		0x204AB1501CA24868ULL,
		0x1E67AFF9FA36B756ULL,
		0x398F431402236728ULL,
		0x2D0D7F70E98E20B0ULL
	}};
	printf("Test Case 101\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x550DDD3ECA604796ULL,
		0x91219D5F47C7236EULL,
		0x1780519B24622DC6ULL,
		0xA903544E8E8FCCF1ULL,
		0xC7DEA482CA812715ULL,
		0x0AA28D55934C9B09ULL,
		0x8FD3233DD0DFFCADULL,
		0x10D993FCEED82D67ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAA1BBA7D94C08F2CULL,
		0x22433ABE8F8E46DCULL,
		0x2F00A33648C45B8DULL,
		0x5206A89D1D1F99E2ULL,
		0x8FBD490595024E2BULL,
		0x15451AAB26993613ULL,
		0x1FA6467BA1BFF95AULL,
		0x21B327F9DDB05ACFULL
	}};
	printf("Test Case 102\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x32BC6802B538E157ULL,
		0x3CFB2434AD7F29BFULL,
		0xDCFF7911FC25DF37ULL,
		0x3DC7F80FE1722347ULL,
		0x2C150136004E328BULL,
		0x8C94264F6EC06552ULL,
		0x84D06D5C211530BDULL,
		0x28106F3D3271F30EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6578D0056A71C2AEULL,
		0x79F648695AFE537EULL,
		0xB9FEF223F84BBE6EULL,
		0x7B8FF01FC2E4468FULL,
		0x582A026C009C6516ULL,
		0x19284C9EDD80CAA4ULL,
		0x09A0DAB8422A617BULL,
		0x5020DE7A64E3E61DULL
	}};
	printf("Test Case 103\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x0DBC403618EB15D7ULL,
		0x0D3C8F614B0D67CCULL,
		0x04CC96E6ABE83F9EULL,
		0xFCDCDAEAB5A292CFULL,
		0x39F7708022758A08ULL,
		0x91D5A814F12C74D6ULL,
		0x80CF7853D4D6C73CULL,
		0x2F270274AF75F8A5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1B78806C31D62BAEULL,
		0x1A791EC2961ACF98ULL,
		0x09992DCD57D07F3CULL,
		0xF9B9B5D56B45259EULL,
		0x73EEE10044EB1411ULL,
		0x23AB5029E258E9ACULL,
		0x019EF0A7A9AD8E79ULL,
		0x5E4E04E95EEBF14BULL
	}};
	printf("Test Case 104\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xA44404FF43EB7623ULL,
		0x5543693F1223EC2EULL,
		0x9DF00C08733D0420ULL,
		0x4E873B6DB6F9B96CULL,
		0xDB8836014B87574AULL,
		0x7433F344653BF49BULL,
		0x8A40E8E25847EF88ULL,
		0x288724E31850B5F2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x488809FE87D6EC46ULL,
		0xAA86D27E2447D85DULL,
		0x3BE01810E67A0840ULL,
		0x9D0E76DB6DF372D9ULL,
		0xB7106C02970EAE94ULL,
		0xE867E688CA77E937ULL,
		0x1481D1C4B08FDF10ULL,
		0x510E49C630A16BE5ULL
	}};
	printf("Test Case 105\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xAD115D2A8C69ABDDULL,
		0x2ED133AECA91FEDBULL,
		0x6D73A8B0F4667A76ULL,
		0xC22AFBA40E7A015FULL,
		0xF451804BDC2D6FEAULL,
		0xAA02B053BA31DB3AULL,
		0x313A15B272619EB3ULL,
		0x34271379A2711E71ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5A22BA5518D357BAULL,
		0x5DA2675D9523FDB7ULL,
		0xDAE75161E8CCF4ECULL,
		0x8455F7481CF402BEULL,
		0xE8A30097B85ADFD5ULL,
		0x540560A77463B675ULL,
		0x62742B64E4C33D67ULL,
		0x684E26F344E23CE2ULL
	}};
	printf("Test Case 106\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x927604EED25CBB96ULL,
		0xF4033AC57544B7BCULL,
		0xA5BF5A4C9862B1C8ULL,
		0xD10FA8C96E941AAFULL,
		0x2106F13E07E67558ULL,
		0x77F3D78E0D48BEE1ULL,
		0x7E7A0889745055BAULL,
		0x1AFF4DB48F6398D2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x24EC09DDA4B9772CULL,
		0xE806758AEA896F79ULL,
		0x4B7EB49930C56391ULL,
		0xA21F5192DD28355FULL,
		0x420DE27C0FCCEAB1ULL,
		0xEFE7AF1C1A917DC2ULL,
		0xFCF41112E8A0AB74ULL,
		0x35FE9B691EC731A4ULL
	}};
	printf("Test Case 107\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xB09E1F2E247C33AEULL,
		0x4535588410A7CF22ULL,
		0x9BCF54E8273506E7ULL,
		0x2A66A314D5DF0905ULL,
		0x4BFA4B8F68B7D031ULL,
		0xF2980A1B95E224DEULL,
		0xD443D1756EEA40BFULL,
		0x0929CB227B4B5E91ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x613C3E5C48F8675CULL,
		0x8A6AB108214F9E45ULL,
		0x379EA9D04E6A0DCEULL,
		0x54CD4629ABBE120BULL,
		0x97F4971ED16FA062ULL,
		0xE53014372BC449BCULL,
		0xA887A2EADDD4817FULL,
		0x12539644F696BD23ULL
	}};
	printf("Test Case 108\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x19D058FD198805C4ULL,
		0x28A41B631EE6113FULL,
		0x2FD1E56007F5E122ULL,
		0xB6F313E83D3A00DBULL,
		0x7BA2FCB33E4C9D4FULL,
		0x7E23415BB98254D0ULL,
		0xA7174B2FD10CD75AULL,
		0x1051CF8B6C078D13ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x33A0B1FA33100B88ULL,
		0x514836C63DCC227EULL,
		0x5FA3CAC00FEBC244ULL,
		0x6DE627D07A7401B6ULL,
		0xF745F9667C993A9FULL,
		0xFC4682B77304A9A0ULL,
		0x4E2E965FA219AEB4ULL,
		0x20A39F16D80F1A27ULL
	}};
	printf("Test Case 109\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xFD8039F774D7FB1CULL,
		0x1B38A98AF99DFC10ULL,
		0x46A769A16DAB4F59ULL,
		0xE2249F6EB9052392ULL,
		0x887394C9C3BEB837ULL,
		0x2EDE8F0C295473E7ULL,
		0x78B34FF27469CE81ULL,
		0x015038656B7193F8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFB0073EEE9AFF638ULL,
		0x36715315F33BF821ULL,
		0x8D4ED342DB569EB2ULL,
		0xC4493EDD720A4724ULL,
		0x10E72993877D706FULL,
		0x5DBD1E1852A8E7CFULL,
		0xF1669FE4E8D39D02ULL,
		0x02A070CAD6E327F0ULL
	}};
	printf("Test Case 110\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x9778388B403496FDULL,
		0x2D263B8F37F9030CULL,
		0xEB640C94D0F6432EULL,
		0x75F43CC0D89D9085ULL,
		0x20F81BCEAB30B151ULL,
		0x798F1BDFE52358F8ULL,
		0x2104D9EC670BAD69ULL,
		0x109F703916DEB93CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2EF0711680692DFAULL,
		0x5A4C771E6FF20619ULL,
		0xD6C81929A1EC865CULL,
		0xEBE87981B13B210BULL,
		0x41F0379D566162A2ULL,
		0xF31E37BFCA46B1F0ULL,
		0x4209B3D8CE175AD2ULL,
		0x213EE0722DBD7278ULL
	}};
	printf("Test Case 111\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xEFC18954B30A76F1ULL,
		0xCF22877FEC9232C9ULL,
		0xE8F09BC3A348EB42ULL,
		0x9592F47ECA21000EULL,
		0xA2DF3760366D3F28ULL,
		0x23F1FA97552649D3ULL,
		0x86ADE60C2B4D45C3ULL,
		0x31567D4B9E6D4B27ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDF8312A96614EDE2ULL,
		0x9E450EFFD9246593ULL,
		0xD1E137874691D685ULL,
		0x2B25E8FD9442001DULL,
		0x45BE6EC06CDA7E51ULL,
		0x47E3F52EAA4C93A7ULL,
		0x0D5BCC18569A8B86ULL,
		0x62ACFA973CDA964FULL
	}};
	printf("Test Case 112\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x88581245CB3E65E2ULL,
		0x85435E96E071749FULL,
		0x0954B52DA45417F2ULL,
		0xAA3A12EFD9D3FBD9ULL,
		0xFBC735BA1B67EB47ULL,
		0xAFA759FBC97FF910ULL,
		0x82A07106A4A972C7ULL,
		0x32924D2600FF359BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x10B0248B967CCBC4ULL,
		0x0A86BD2DC0E2E93FULL,
		0x12A96A5B48A82FE5ULL,
		0x547425DFB3A7F7B2ULL,
		0xF78E6B7436CFD68FULL,
		0x5F4EB3F792FFF221ULL,
		0x0540E20D4952E58FULL,
		0x65249A4C01FE6B37ULL
	}};
	printf("Test Case 113\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x23E8EE02B8C1E213ULL,
		0x01075990BE6C2271ULL,
		0x9B0CB16F5C5D588BULL,
		0x613598AFDE31C24CULL,
		0xC3E936F4E5574C26ULL,
		0x9BF5B16559788109ULL,
		0x0DBB771AD03A8BBEULL,
		0x0B949307552CC2BAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x47D1DC057183C426ULL,
		0x020EB3217CD844E2ULL,
		0x361962DEB8BAB116ULL,
		0xC26B315FBC638499ULL,
		0x87D26DE9CAAE984CULL,
		0x37EB62CAB2F10213ULL,
		0x1B76EE35A075177DULL,
		0x1729260EAA598574ULL
	}};
	printf("Test Case 114\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x97B47ED6471525D0ULL,
		0x0507EBA463C5B916ULL,
		0x73CF2BF35AF9813BULL,
		0xEBFD9C14C4239D23ULL,
		0x4478C49452E034C6ULL,
		0x3A197FDE0923C84AULL,
		0xF5D3B4A6A67067FCULL,
		0x38945CB503DCB217ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2F68FDAC8E2A4BA0ULL,
		0x0A0FD748C78B722DULL,
		0xE79E57E6B5F30276ULL,
		0xD7FB382988473A46ULL,
		0x88F18928A5C0698DULL,
		0x7432FFBC12479094ULL,
		0xEBA7694D4CE0CFF8ULL,
		0x7128B96A07B9642FULL
	}};
	printf("Test Case 115\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x9DD4BE2A086DFC02ULL,
		0x541169A00FE40CC8ULL,
		0x5099FB786A5BDAF7ULL,
		0x365EFCD94EA11B64ULL,
		0x1457A97D8863ECEFULL,
		0xB53AE510E17278B6ULL,
		0x35AAC4DC20EFA774ULL,
		0x07B59D97C75FB836ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3BA97C5410DBF804ULL,
		0xA822D3401FC81991ULL,
		0xA133F6F0D4B7B5EEULL,
		0x6CBDF9B29D4236C8ULL,
		0x28AF52FB10C7D9DEULL,
		0x6A75CA21C2E4F16CULL,
		0x6B5589B841DF4EE9ULL,
		0x0F6B3B2F8EBF706CULL
	}};
	printf("Test Case 116\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x048AE75DD3191FECULL,
		0xEC455E3ABE7CBBD6ULL,
		0x23E48CF6F2370A3EULL,
		0x925C44B5F9242BCFULL,
		0x1249EAD06D0D44F3ULL,
		0x1C1A95B3D8B18CC3ULL,
		0x3BA4D8ECE28FF7ACULL,
		0x2FC48292869F5668ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0915CEBBA6323FD8ULL,
		0xD88ABC757CF977ACULL,
		0x47C919EDE46E147DULL,
		0x24B8896BF248579EULL,
		0x2493D5A0DA1A89E7ULL,
		0x38352B67B1631986ULL,
		0x7749B1D9C51FEF58ULL,
		0x5F8905250D3EACD0ULL
	}};
	printf("Test Case 117\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xF959C4025CF1CA5AULL,
		0x2707564A7B4C1DC1ULL,
		0x3873A9D3099ECD19ULL,
		0xCBC18299312D7DEBULL,
		0x62AE4809CF9D3B15ULL,
		0x85891B09F97C3F50ULL,
		0x1FB9E0859289352FULL,
		0x3303950AB363A040ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF2B38804B9E394B4ULL,
		0x4E0EAC94F6983B83ULL,
		0x70E753A6133D9A32ULL,
		0x97830532625AFBD6ULL,
		0xC55C90139F3A762BULL,
		0x0B123613F2F87EA0ULL,
		0x3F73C10B25126A5FULL,
		0x66072A1566C74080ULL
	}};
	printf("Test Case 118\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x27632C80695A01CAULL,
		0x8410E562DEC30ED1ULL,
		0xA2BCE8007341DF96ULL,
		0x0F819CAE22EB7966ULL,
		0x81B83834D088FBEDULL,
		0x9F3EB1DF5A34179FULL,
		0x268436ADF03D77E2ULL,
		0x252E1B664D9162E9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4EC65900D2B40394ULL,
		0x0821CAC5BD861DA2ULL,
		0x4579D000E683BF2DULL,
		0x1F03395C45D6F2CDULL,
		0x03707069A111F7DAULL,
		0x3E7D63BEB4682F3FULL,
		0x4D086D5BE07AEFC5ULL,
		0x4A5C36CC9B22C5D2ULL
	}};
	printf("Test Case 119\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xA54AC959F2FDB2BBULL,
		0xC9E4CA82BC97B7BAULL,
		0x24033F5D8427AAD4ULL,
		0x2CA8B3A994AC3FE6ULL,
		0x230A787A8B7D0AECULL,
		0x1BACCCA572B2E2F3ULL,
		0xD3DBBE1BAA59A5EAULL,
		0x3F1E8CA325D437D2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4A9592B3E5FB6576ULL,
		0x93C99505792F6F75ULL,
		0x48067EBB084F55A9ULL,
		0x5951675329587FCCULL,
		0x4614F0F516FA15D8ULL,
		0x3759994AE565C5E6ULL,
		0xA7B77C3754B34BD4ULL,
		0x7E3D19464BA86FA5ULL
	}};
	printf("Test Case 120\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xA03ACDC188E2F6CCULL,
		0xA0B39A79069B692BULL,
		0xDA87134724FA922DULL,
		0x5888254378DC1545ULL,
		0xD149FCB31F06CCCFULL,
		0xFC735FFA01556E27ULL,
		0x210E0D8E04EC9F63ULL,
		0x27A7A09151C3597CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x40759B8311C5ED98ULL,
		0x416734F20D36D257ULL,
		0xB50E268E49F5245BULL,
		0xB1104A86F1B82A8BULL,
		0xA293F9663E0D999EULL,
		0xF8E6BFF402AADC4FULL,
		0x421C1B1C09D93EC7ULL,
		0x4F4F4122A386B2F8ULL
	}};
	printf("Test Case 121\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x4BED33EAD43AD4FDULL,
		0x22FB709DFD53F04DULL,
		0x449877C078652503ULL,
		0x42158FEBDD0D6917ULL,
		0x1D05E13AFA6640E8ULL,
		0xE25E39BD38E012EAULL,
		0x454F7656A2E92A7DULL,
		0x3445635756AAF7EBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x97DA67D5A875A9FAULL,
		0x45F6E13BFAA7E09AULL,
		0x8930EF80F0CA4A06ULL,
		0x842B1FD7BA1AD22EULL,
		0x3A0BC275F4CC81D0ULL,
		0xC4BC737A71C025D4ULL,
		0x8A9EECAD45D254FBULL,
		0x688AC6AEAD55EFD6ULL
	}};
	printf("Test Case 122\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x4005C9F3E4A74E89ULL,
		0xDB5389E90542B1F8ULL,
		0x47FDE7B20F6D29D6ULL,
		0x7F5BF35F8719D60AULL,
		0x853B53389156D2D9ULL,
		0x14E233F3FA3F7CE2ULL,
		0x220354E1E6F4FFCAULL,
		0x0AD47F90297716A1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x800B93E7C94E9D12ULL,
		0xB6A713D20A8563F0ULL,
		0x8FFBCF641EDA53ADULL,
		0xFEB7E6BF0E33AC14ULL,
		0x0A76A67122ADA5B2ULL,
		0x29C467E7F47EF9C5ULL,
		0x4406A9C3CDE9FF94ULL,
		0x15A8FF2052EE2D42ULL
	}};
	printf("Test Case 123\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x24BC5025F9F8018AULL,
		0xF71F9C589CBC59ADULL,
		0x27BA9474E6BB8D91ULL,
		0x685C4A159271A125ULL,
		0x46F0FFF27EF758C5ULL,
		0xA9AB1FC1D4A72E05ULL,
		0x3A5DD6585A9C307EULL,
		0x0106A243CC665066ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4978A04BF3F00314ULL,
		0xEE3F38B13978B35AULL,
		0x4F7528E9CD771B23ULL,
		0xD0B8942B24E3424AULL,
		0x8DE1FFE4FDEEB18AULL,
		0x53563F83A94E5C0AULL,
		0x74BBACB0B53860FDULL,
		0x020D448798CCA0CCULL
	}};
	printf("Test Case 124\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x464FDBEC01365745ULL,
		0xB0BBC06D95855C4EULL,
		0x6D42F220499F6E70ULL,
		0xF0B54306D44E6F64ULL,
		0xE40F9EA290E55573ULL,
		0xB873CAE52F78B07BULL,
		0xB426E3DDB501B1FAULL,
		0x202DE8DFF4999DDAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8C9FB7D8026CAE8AULL,
		0x617780DB2B0AB89CULL,
		0xDA85E440933EDCE1ULL,
		0xE16A860DA89CDEC8ULL,
		0xC81F3D4521CAAAE7ULL,
		0x70E795CA5EF160F7ULL,
		0x684DC7BB6A0363F5ULL,
		0x405BD1BFE9333BB5ULL
	}};
	printf("Test Case 125\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x7BB0C6074E7CB6DAULL,
		0x280684598DC4C01AULL,
		0xADEDF6CD202A5A36ULL,
		0xE20FFA2DC798052AULL,
		0x087707AA06336DD1ULL,
		0x05CEC541DF1B58FCULL,
		0x2A514A4F2893017AULL,
		0x08B8564C00851ECCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF7618C0E9CF96DB4ULL,
		0x500D08B31B898034ULL,
		0x5BDBED9A4054B46CULL,
		0xC41FF45B8F300A55ULL,
		0x10EE0F540C66DBA3ULL,
		0x0B9D8A83BE36B1F8ULL,
		0x54A2949E512602F4ULL,
		0x1170AC98010A3D98ULL
	}};
	printf("Test Case 126\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xCB0B4B76087246E5ULL,
		0x3C7D8DDC785E81C7ULL,
		0x420F37343D7B11E4ULL,
		0x01C5B11926F3179AULL,
		0x9EB1BD1BC4312E27ULL,
		0xB496550B06D718AAULL,
		0xB44E3D326AD2F9E5ULL,
		0x38BE67971D375DB7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x961696EC10E48DCAULL,
		0x78FB1BB8F0BD038FULL,
		0x841E6E687AF623C8ULL,
		0x038B62324DE62F34ULL,
		0x3D637A3788625C4EULL,
		0x692CAA160DAE3155ULL,
		0x689C7A64D5A5F3CBULL,
		0x717CCF2E3A6EBB6FULL
	}};
	printf("Test Case 127\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x8EF7BA60920455DEULL,
		0xE1C6A32B77628B86ULL,
		0x24EF28C786456992ULL,
		0x429BD8ABDEC38793ULL,
		0xDADD889B9B6C6D23ULL,
		0x24E4843536F4BCEFULL,
		0x5A99EFB2993BE222ULL,
		0x3D2256D406C75F08ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1DEF74C12408ABBCULL,
		0xC38D4656EEC5170DULL,
		0x49DE518F0C8AD325ULL,
		0x8537B157BD870F26ULL,
		0xB5BB113736D8DA46ULL,
		0x49C9086A6DE979DFULL,
		0xB533DF653277C444ULL,
		0x7A44ADA80D8EBE10ULL
	}};
	printf("Test Case 128\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xED125004AB6B7F41ULL,
		0x0C6E71E97A79BF32ULL,
		0x3816B3E2157E4C2AULL,
		0x4B75CCD37DD6A02FULL,
		0x6F743EFC7C9288A0ULL,
		0xD860A192DFD287F6ULL,
		0x024673F850354B44ULL,
		0x3CAA2E7A5230A28EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDA24A00956D6FE82ULL,
		0x18DCE3D2F4F37E65ULL,
		0x702D67C42AFC9854ULL,
		0x96EB99A6FBAD405EULL,
		0xDEE87DF8F9251140ULL,
		0xB0C14325BFA50FECULL,
		0x048CE7F0A06A9689ULL,
		0x79545CF4A461451CULL
	}};
	printf("Test Case 129\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xA3C8123AF54D1F31ULL,
		0xB08925030301660CULL,
		0x1B4529D632659A54ULL,
		0x103D68FF994B6909ULL,
		0xB3A7723F127CF586ULL,
		0x92B13BB358F9940AULL,
		0xD097A9891AB8577FULL,
		0x277E3B40E3D870D5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x47902475EA9A3E62ULL,
		0x61124A060602CC19ULL,
		0x368A53AC64CB34A9ULL,
		0x207AD1FF3296D212ULL,
		0x674EE47E24F9EB0CULL,
		0x25627766B1F32815ULL,
		0xA12F53123570AEFFULL,
		0x4EFC7681C7B0E1ABULL
	}};
	printf("Test Case 130\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x7E5889B659F1C559ULL,
		0xC1C999F06CAA2FBAULL,
		0xE05791C1EA679730ULL,
		0x828BCB9FA90729E7ULL,
		0x7764B537E6FA0259ULL,
		0x9F215DBC0AC93AD5ULL,
		0x1703627083E6A392ULL,
		0x09800066A99BF054ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFCB1136CB3E38AB2ULL,
		0x839333E0D9545F74ULL,
		0xC0AF2383D4CF2E61ULL,
		0x0517973F520E53CFULL,
		0xEEC96A6FCDF404B3ULL,
		0x3E42BB78159275AAULL,
		0x2E06C4E107CD4725ULL,
		0x130000CD5337E0A8ULL
	}};
	printf("Test Case 131\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x8190D2DB3914E449ULL,
		0x3019C445B1116EC5ULL,
		0x4EB5FEA2C9BA2FE1ULL,
		0x3701A672B2A6A202ULL,
		0xF699A120016BA1B6ULL,
		0x4F5F127D379E70D0ULL,
		0x953C135E067A86F7ULL,
		0x20452715157D3B73ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0321A5B67229C892ULL,
		0x6033888B6222DD8BULL,
		0x9D6BFD4593745FC2ULL,
		0x6E034CE5654D4404ULL,
		0xED33424002D7436CULL,
		0x9EBE24FA6F3CE1A1ULL,
		0x2A7826BC0CF50DEEULL,
		0x408A4E2A2AFA76E7ULL
	}};
	printf("Test Case 132\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x666A09447604AF58ULL,
		0xC4E4716BC9662CF8ULL,
		0x9C0FA1D75F2F812EULL,
		0xFFA8E30DD3CBD707ULL,
		0xFB93DB50411A7BD6ULL,
		0x6224C3617FE98FEAULL,
		0x20D47104EC2A8A9FULL,
		0x1DC76552FD78FF8EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCCD41288EC095EB0ULL,
		0x89C8E2D792CC59F0ULL,
		0x381F43AEBE5F025DULL,
		0xFF51C61BA797AE0FULL,
		0xF727B6A08234F7ADULL,
		0xC44986C2FFD31FD5ULL,
		0x41A8E209D855153EULL,
		0x3B8ECAA5FAF1FF1CULL
	}};
	printf("Test Case 133\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x2D7273154218C082ULL,
		0x9A002AAD831B7727ULL,
		0xADDF4B4661CEB082ULL,
		0x01FACE1EC73A8640ULL,
		0xAC1889494BF0FE94ULL,
		0x0E556ED104A088EBULL,
		0xE5BA62ADE2D0EC0BULL,
		0x38EA64BC339588AFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5AE4E62A84318104ULL,
		0x3400555B0636EE4EULL,
		0x5BBE968CC39D6105ULL,
		0x03F59C3D8E750C81ULL,
		0x5831129297E1FD28ULL,
		0x1CAADDA2094111D7ULL,
		0xCB74C55BC5A1D816ULL,
		0x71D4C978672B115FULL
	}};
	printf("Test Case 134\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x925F54A190BA86C2ULL,
		0x33E45C875546D45CULL,
		0x78741CF0DCB88B8AULL,
		0xD482763515D3C65EULL,
		0x4D245294F8B16933ULL,
		0xF4A9D0DBFB88EF45ULL,
		0xA189C48AEF69535CULL,
		0x3E094D3EE65940B2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x24BEA94321750D84ULL,
		0x67C8B90EAA8DA8B9ULL,
		0xF0E839E1B9711714ULL,
		0xA904EC6A2BA78CBCULL,
		0x9A48A529F162D267ULL,
		0xE953A1B7F711DE8AULL,
		0x43138915DED2A6B9ULL,
		0x7C129A7DCCB28165ULL
	}};
	printf("Test Case 135\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x05E5C77D98A9D81AULL,
		0x125202C93981723AULL,
		0x2ECEB9FC879ECEABULL,
		0x08E8A2EA7E654C4FULL,
		0xC7A4131D2D2A1025ULL,
		0xB1D4FF54E58F3B5FULL,
		0x0C66BDD23652502DULL,
		0x1E004FFF4893AB3FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0BCB8EFB3153B034ULL,
		0x24A405927302E474ULL,
		0x5D9D73F90F3D9D56ULL,
		0x11D145D4FCCA989EULL,
		0x8F48263A5A54204AULL,
		0x63A9FEA9CB1E76BFULL,
		0x18CD7BA46CA4A05BULL,
		0x3C009FFE9127567EULL
	}};
	printf("Test Case 136\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x68C63BF9F94848D5ULL,
		0x534F7A14C0DBD082ULL,
		0x7632686A93B59D8AULL,
		0x4623BD4B229CF216ULL,
		0xDDDF31B68BC577ACULL,
		0x06B759FB40CD9355ULL,
		0xCF45AC42252189CBULL,
		0x1A8C080EA1BD4217ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD18C77F3F29091AAULL,
		0xA69EF42981B7A104ULL,
		0xEC64D0D5276B3B14ULL,
		0x8C477A964539E42CULL,
		0xBBBE636D178AEF58ULL,
		0x0D6EB3F6819B26ABULL,
		0x9E8B58844A431396ULL,
		0x3518101D437A842FULL
	}};
	printf("Test Case 137\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x9BC24DC3DF1706A5ULL,
		0xBEAECD5E5AF3C59BULL,
		0xFB7D0A76F982C1E3ULL,
		0x00FF00CA54528219ULL,
		0x24D479CB451FD162ULL,
		0xAEB298452E29E30DULL,
		0x536F408E08A76A4FULL,
		0x138F7825A51E9705ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x37849B87BE2E0D4AULL,
		0x7D5D9ABCB5E78B37ULL,
		0xF6FA14EDF30583C7ULL,
		0x01FE0194A8A50433ULL,
		0x49A8F3968A3FA2C4ULL,
		0x5D65308A5C53C61AULL,
		0xA6DE811C114ED49FULL,
		0x271EF04B4A3D2E0AULL
	}};
	printf("Test Case 138\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x6F24A3D43D323FDBULL,
		0xC7171CF25F713B0DULL,
		0x63E2773B2B407A2CULL,
		0x2FB86CB602EBB6CFULL,
		0xF1B7A7247E1B3E28ULL,
		0xA14670F87989E051ULL,
		0x60CD8EFFEBA49ECBULL,
		0x03E2B5EE11F06B56ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDE4947A87A647FB6ULL,
		0x8E2E39E4BEE2761AULL,
		0xC7C4EE765680F459ULL,
		0x5F70D96C05D76D9EULL,
		0xE36F4E48FC367C50ULL,
		0x428CE1F0F313C0A3ULL,
		0xC19B1DFFD7493D97ULL,
		0x07C56BDC23E0D6ACULL
	}};
	printf("Test Case 139\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x009560E6C4E3918CULL,
		0xA622D36A319C01D1ULL,
		0xC5961013D0E64EAFULL,
		0x0D32AAA0F3DF0E7DULL,
		0x7CAC80D19B52883BULL,
		0xC83026F07322387EULL,
		0x20754C9AF44F3270ULL,
		0x161B6CC243EF6CB2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x012AC1CD89C72318ULL,
		0x4C45A6D4633803A2ULL,
		0x8B2C2027A1CC9D5FULL,
		0x1A655541E7BE1CFBULL,
		0xF95901A336A51076ULL,
		0x90604DE0E64470FCULL,
		0x40EA9935E89E64E1ULL,
		0x2C36D98487DED964ULL
	}};
	printf("Test Case 140\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x551C426CDBF8AF5BULL,
		0x99BE45798706C903ULL,
		0x3578E4EE2510B344ULL,
		0xEA16E3A50CB0EA21ULL,
		0xF694DDA7185D165AULL,
		0x830F2A6C86845F3EULL,
		0xC508E23C6A67C543ULL,
		0x2918220134FF1204ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAA3884D9B7F15EB6ULL,
		0x337C8AF30E0D9206ULL,
		0x6AF1C9DC4A216689ULL,
		0xD42DC74A1961D442ULL,
		0xED29BB4E30BA2CB5ULL,
		0x061E54D90D08BE7DULL,
		0x8A11C478D4CF8A87ULL,
		0x5230440269FE2409ULL
	}};
	printf("Test Case 141\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x8638C2042521227FULL,
		0x306B80DA464E6277ULL,
		0x4D92393E255B3E1CULL,
		0x48D6677AE347D0FDULL,
		0x0656630E76B39589ULL,
		0x98D0CDB0AA91B89CULL,
		0xEC1DC45552AF94B3ULL,
		0x101C34637CDD6149ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0C7184084A4244FEULL,
		0x60D701B48C9CC4EFULL,
		0x9B24727C4AB67C38ULL,
		0x91ACCEF5C68FA1FAULL,
		0x0CACC61CED672B12ULL,
		0x31A19B6155237138ULL,
		0xD83B88AAA55F2967ULL,
		0x203868C6F9BAC293ULL
	}};
	printf("Test Case 142\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x219758D29AD45F04ULL,
		0xFA01EDE04DEBEFD7ULL,
		0x27FC6B097EEEBF18ULL,
		0xBDDE7741B882AE35ULL,
		0x7AE055A5B352330DULL,
		0x9C51E9D4233AFDF9ULL,
		0x9CC3F7C7E181A971ULL,
		0x06B8CAE52BCC66CBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x432EB1A535A8BE08ULL,
		0xF403DBC09BD7DFAEULL,
		0x4FF8D612FDDD7E31ULL,
		0x7BBCEE8371055C6AULL,
		0xF5C0AB4B66A4661BULL,
		0x38A3D3A84675FBF2ULL,
		0x3987EF8FC30352E3ULL,
		0x0D7195CA5798CD97ULL
	}};
	printf("Test Case 143\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x90E24FE9C988FB35ULL,
		0x692F78D7A65DFE68ULL,
		0x52298CAF5C37657FULL,
		0xB156508D4279BCD9ULL,
		0xB4DE148FEEE90C0CULL,
		0x83C9696780017E9DULL,
		0xF0889E653BF12993ULL,
		0x34F1EC20D442E243ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x21C49FD39311F66AULL,
		0xD25EF1AF4CBBFCD1ULL,
		0xA453195EB86ECAFEULL,
		0x62ACA11A84F379B2ULL,
		0x69BC291FDDD21819ULL,
		0x0792D2CF0002FD3BULL,
		0xE1113CCA77E25327ULL,
		0x69E3D841A885C487ULL
	}};
	printf("Test Case 144\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x5AF78561D3460BCAULL,
		0x890BAB1012DE5646ULL,
		0xDBA8C61329703C8AULL,
		0x74D4D1E5AAB87A72ULL,
		0xE4C57885509FC3D5ULL,
		0x4CB2C11E30DB6BEBULL,
		0x644776095746CCC1ULL,
		0x08995E5E930D12D6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB5EF0AC3A68C1794ULL,
		0x1217562025BCAC8CULL,
		0xB7518C2652E07915ULL,
		0xE9A9A3CB5570F4E5ULL,
		0xC98AF10AA13F87AAULL,
		0x9965823C61B6D7D7ULL,
		0xC88EEC12AE8D9982ULL,
		0x1132BCBD261A25ACULL
	}};
	printf("Test Case 145\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x103A920A0BE449B0ULL,
		0x5DB1C288A4A0F390ULL,
		0x62131A00D210C223ULL,
		0xA966D08F494C34D5ULL,
		0x594C8AE16DD1F704ULL,
		0x57BF6C9D0506534AULL,
		0x0AC5E283BB71DC11ULL,
		0x161AA01A192D6DFEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2075241417C89360ULL,
		0xBB6385114941E720ULL,
		0xC4263401A4218446ULL,
		0x52CDA11E929869AAULL,
		0xB29915C2DBA3EE09ULL,
		0xAF7ED93A0A0CA694ULL,
		0x158BC50776E3B822ULL,
		0x2C354034325ADBFCULL
	}};
	printf("Test Case 146\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xACCC905A9B7CBC43ULL,
		0xF8439695702381F7ULL,
		0xF34FA0CB61419543ULL,
		0xC6549237785C4BC3ULL,
		0xFFCBB5546AE319DDULL,
		0x697BE8455FC1DD09ULL,
		0x0C8403D053133A02ULL,
		0x2B8009C34B97131CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x599920B536F97886ULL,
		0xF0872D2AE04703EFULL,
		0xE69F4196C2832A87ULL,
		0x8CA9246EF0B89787ULL,
		0xFF976AA8D5C633BBULL,
		0xD2F7D08ABF83BA13ULL,
		0x190807A0A6267404ULL,
		0x57001386972E2638ULL
	}};
	printf("Test Case 147\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xF5F2D76FFA0668B4ULL,
		0xE920DAAA0D07D3E9ULL,
		0xD2B6F48F5B0A6988ULL,
		0x30F5D8A2D4FEB338ULL,
		0x105DA2C1797DEECAULL,
		0xE5CD159E0D82A3E0ULL,
		0x33474A9B47ECEF08ULL,
		0x3584CE9BBB79C9A4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEBE5AEDFF40CD168ULL,
		0xD241B5541A0FA7D3ULL,
		0xA56DE91EB614D311ULL,
		0x61EBB145A9FD6671ULL,
		0x20BB4582F2FBDD94ULL,
		0xCB9A2B3C1B0547C0ULL,
		0x668E95368FD9DE11ULL,
		0x6B099D3776F39348ULL
	}};
	printf("Test Case 148\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x2AA187508D177E0DULL,
		0x4C3CE273F3894510ULL,
		0x493DD42250090D79ULL,
		0xA4F1E5F4F5BF6722ULL,
		0x8180665A0257191BULL,
		0x0B4E2D88FBBEE62EULL,
		0xF9136271E207717AULL,
		0x2A3E3A22DCCF6E28ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x55430EA11A2EFC1AULL,
		0x9879C4E7E7128A20ULL,
		0x927BA844A0121AF2ULL,
		0x49E3CBE9EB7ECE44ULL,
		0x0300CCB404AE3237ULL,
		0x169C5B11F77DCC5DULL,
		0xF226C4E3C40EE2F4ULL,
		0x547C7445B99EDC51ULL
	}};
	printf("Test Case 149\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x0C441485AFB569A6ULL,
		0xD91E973E43D8E6ADULL,
		0x32085E40E646D5F3ULL,
		0x5C9625AE3E1A810CULL,
		0x1AC75CF6168EC214ULL,
		0xC56FF8A13C0D9544ULL,
		0x63224471373F0EADULL,
		0x1F8650F91C8E00FFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1888290B5F6AD34CULL,
		0xB23D2E7C87B1CD5AULL,
		0x6410BC81CC8DABE7ULL,
		0xB92C4B5C7C350218ULL,
		0x358EB9EC2D1D8428ULL,
		0x8ADFF142781B2A88ULL,
		0xC64488E26E7E1D5BULL,
		0x3F0CA1F2391C01FEULL
	}};
	printf("Test Case 150\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xFEEE0E5F7397527CULL,
		0x5CE0647705557733ULL,
		0x41259D77436CE965ULL,
		0xFF70C66BEC7A79D4ULL,
		0x4DE1E30409B2ADA1ULL,
		0xBE75994896BB4898ULL,
		0x6A4BD7E37FD0B326ULL,
		0x222A0D4D55B8664DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFDDC1CBEE72EA4F8ULL,
		0xB9C0C8EE0AAAEE67ULL,
		0x824B3AEE86D9D2CAULL,
		0xFEE18CD7D8F4F3A8ULL,
		0x9BC3C60813655B43ULL,
		0x7CEB32912D769130ULL,
		0xD497AFC6FFA1664DULL,
		0x44541A9AAB70CC9AULL
	}};
	printf("Test Case 151\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x04FFCDC699359537ULL,
		0xCD5E048465ED38E4ULL,
		0x84815D9193DB9D30ULL,
		0x7169A5DFE821FC8DULL,
		0xA191FE4745D305F1ULL,
		0x03E7E1234AF8AFC2ULL,
		0xC5E72A2CFE72DB7CULL,
		0x1A4E9A6C6601FC24ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x09FF9B8D326B2A6EULL,
		0x9ABC0908CBDA71C8ULL,
		0x0902BB2327B73A61ULL,
		0xE2D34BBFD043F91BULL,
		0x4323FC8E8BA60BE2ULL,
		0x07CFC24695F15F85ULL,
		0x8BCE5459FCE5B6F8ULL,
		0x349D34D8CC03F849ULL
	}};
	printf("Test Case 152\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x6DC50E0F55970E4CULL,
		0xDCAC103B189FD8DCULL,
		0xECF648456E2C5409ULL,
		0x7E27A90C564A151DULL,
		0x54229D166BC822FFULL,
		0x6F900992065EC903ULL,
		0xFE0BF60967FF258CULL,
		0x3EEB3C32F948D036ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDB8A1C1EAB2E1C98ULL,
		0xB9582076313FB1B8ULL,
		0xD9EC908ADC58A813ULL,
		0xFC4F5218AC942A3BULL,
		0xA8453A2CD79045FEULL,
		0xDF2013240CBD9206ULL,
		0xFC17EC12CFFE4B18ULL,
		0x7DD67865F291A06DULL
	}};
	printf("Test Case 153\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xF9CC0D239C51F085ULL,
		0xB709D2BDF505D061ULL,
		0x597FE53C7A657093ULL,
		0x1644A7F16D0BFF5CULL,
		0xD82B344812E22F8BULL,
		0xC370A103E72A7C8AULL,
		0xF5D478B35304EE1BULL,
		0x207208453402ACDCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF3981A4738A3E10AULL,
		0x6E13A57BEA0BA0C3ULL,
		0xB2FFCA78F4CAE127ULL,
		0x2C894FE2DA17FEB8ULL,
		0xB056689025C45F16ULL,
		0x86E14207CE54F915ULL,
		0xEBA8F166A609DC37ULL,
		0x40E4108A680559B9ULL
	}};
	printf("Test Case 154\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xCA94F07D6D77B3FCULL,
		0xA27569483F4E3D91ULL,
		0xBC6D72BFF7B01DA1ULL,
		0xF8FE7E84DCFFA847ULL,
		0xA7E1D8002CF12CB8ULL,
		0x0546623252E3697EULL,
		0x8DA1C147CF8EDABAULL,
		0x054FB4B24243AFC2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9529E0FADAEF67F8ULL,
		0x44EAD2907E9C7B23ULL,
		0x78DAE57FEF603B43ULL,
		0xF1FCFD09B9FF508FULL,
		0x4FC3B00059E25971ULL,
		0x0A8CC464A5C6D2FDULL,
		0x1B43828F9F1DB574ULL,
		0x0A9F696484875F85ULL
	}};
	printf("Test Case 155\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x73F179A3AA3F6247ULL,
		0xC3D68C5B38027548ULL,
		0xB332E12207BB81A3ULL,
		0xB7FBD96C0A8A63BAULL,
		0xE5C3C0A243C4DD0AULL,
		0x74171367565624C0ULL,
		0x89275A563632F01CULL,
		0x04690CD0047F4C14ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE7E2F347547EC48EULL,
		0x87AD18B67004EA90ULL,
		0x6665C2440F770347ULL,
		0x6FF7B2D81514C775ULL,
		0xCB8781448789BA15ULL,
		0xE82E26CEACAC4981ULL,
		0x124EB4AC6C65E038ULL,
		0x08D219A008FE9829ULL
	}};
	printf("Test Case 156\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x4AA0FC9617861299ULL,
		0xDF7BA1194E96E87AULL,
		0xC4C2C80422F00F65ULL,
		0xC756298F0ED130A0ULL,
		0x766DFCC9AFDC9C99ULL,
		0xCF3FE590BD48D291ULL,
		0x4282D292BEC33A91ULL,
		0x13410FF582C695E5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9541F92C2F0C2532ULL,
		0xBEF742329D2DD0F4ULL,
		0x8985900845E01ECBULL,
		0x8EAC531E1DA26141ULL,
		0xECDBF9935FB93933ULL,
		0x9E7FCB217A91A522ULL,
		0x8505A5257D867523ULL,
		0x26821FEB058D2BCAULL
	}};
	printf("Test Case 157\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xCFA06E698661E28AULL,
		0x66CEB58E4292463BULL,
		0x408D0A3285ED233DULL,
		0xA4BFB8333E132676ULL,
		0xCC27DB47E22C6D4AULL,
		0xC5532F1D3D6D3C8BULL,
		0x49F8B565F2008EF7ULL,
		0x342B3551B47D9858ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9F40DCD30CC3C514ULL,
		0xCD9D6B1C85248C77ULL,
		0x811A14650BDA467AULL,
		0x497F70667C264CECULL,
		0x984FB68FC458DA95ULL,
		0x8AA65E3A7ADA7917ULL,
		0x93F16ACBE4011DEFULL,
		0x68566AA368FB30B0ULL
	}};
	printf("Test Case 158\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x2151C3C16DCDE9F1ULL,
		0x504D6EEFE06BDCD5ULL,
		0x7B34855333F4E406ULL,
		0x080F59453C8A0FB8ULL,
		0x87063BF27D1E2EABULL,
		0xFF9C72ABDCE65A07ULL,
		0x2A527BDA01AB9DE8ULL,
		0x326EAF01E9A65FDAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x42A38782DB9BD3E2ULL,
		0xA09ADDDFC0D7B9AAULL,
		0xF6690AA667E9C80CULL,
		0x101EB28A79141F70ULL,
		0x0E0C77E4FA3C5D56ULL,
		0xFF38E557B9CCB40FULL,
		0x54A4F7B403573BD1ULL,
		0x64DD5E03D34CBFB4ULL
	}};
	printf("Test Case 159\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xE46C6F41978369DFULL,
		0x10F0B375CC167BC4ULL,
		0xA280AB21B417853BULL,
		0xD6FF3256E97A5B03ULL,
		0xCDB8BE5113ADFA5FULL,
		0xF0898B7E85BE524AULL,
		0x897C97D2B36AE3CEULL,
		0x0DEC34C613FF8234ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC8D8DE832F06D3BEULL,
		0x21E166EB982CF789ULL,
		0x45015643682F0A76ULL,
		0xADFE64ADD2F4B607ULL,
		0x9B717CA2275BF4BFULL,
		0xE11316FD0B7CA495ULL,
		0x12F92FA566D5C79DULL,
		0x1BD8698C27FF0469ULL
	}};
	printf("Test Case 160\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xBFBD12DFD62F2171ULL,
		0xDE007411BC42F8F9ULL,
		0xFE2DCD17747E79CCULL,
		0x646B42388ABDC954ULL,
		0x57C5AF859736A361ULL,
		0xCF6175573D2C31B5ULL,
		0xDCA369F832ED54DFULL,
		0x2D9DC1702CC741E6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7F7A25BFAC5E42E2ULL,
		0xBC00E8237885F1F3ULL,
		0xFC5B9A2EE8FCF399ULL,
		0xC8D68471157B92A9ULL,
		0xAF8B5F0B2E6D46C2ULL,
		0x9EC2EAAE7A58636AULL,
		0xB946D3F065DAA9BFULL,
		0x5B3B82E0598E83CDULL
	}};
	printf("Test Case 161\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x80A6518446C8813AULL,
		0x583C213503816BF8ULL,
		0x151D8A40162525FCULL,
		0x892807464C1705E3ULL,
		0xCFFFF8C7C0FE54A6ULL,
		0xC36A9EB483F32A8FULL,
		0x2819CCB198D61693ULL,
		0x392C1C1B2C20F82EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x014CA3088D910274ULL,
		0xB078426A0702D7F1ULL,
		0x2A3B14802C4A4BF8ULL,
		0x12500E8C982E0BC6ULL,
		0x9FFFF18F81FCA94DULL,
		0x86D53D6907E6551FULL,
		0x5033996331AC2D27ULL,
		0x725838365841F05CULL
	}};
	printf("Test Case 162\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x3D4DF7E8EEDCC4B1ULL,
		0x49286D9411599EB2ULL,
		0x61223A6F8BAA855FULL,
		0x79792DD087D52D41ULL,
		0x40F05BAEAE368B47ULL,
		0x3B3D106D8BC43C2CULL,
		0xF940AAEE81F59BE0ULL,
		0x2403019F8FB96870ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7A9BEFD1DDB98962ULL,
		0x9250DB2822B33D64ULL,
		0xC24474DF17550ABEULL,
		0xF2F25BA10FAA5A82ULL,
		0x81E0B75D5C6D168EULL,
		0x767A20DB17887858ULL,
		0xF28155DD03EB37C0ULL,
		0x4806033F1F72D0E1ULL
	}};
	printf("Test Case 163\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x2B46869DAF4C7A50ULL,
		0x15BDDCEFE7473D87ULL,
		0x9BAF15029F5B18FAULL,
		0x36F3DCB21806702DULL,
		0x02A59AB17D87D633ULL,
		0x9A5803FCABA42317ULL,
		0x2BC3A880CE5B3BBBULL,
		0x29CC0253945F8CCDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x568D0D3B5E98F4A0ULL,
		0x2B7BB9DFCE8E7B0EULL,
		0x375E2A053EB631F4ULL,
		0x6DE7B964300CE05BULL,
		0x054B3562FB0FAC66ULL,
		0x34B007F95748462EULL,
		0x578751019CB67777ULL,
		0x539804A728BF199AULL
	}};
	printf("Test Case 164\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x7C0411A86C3FE64AULL,
		0x721F7600DB23ECCDULL,
		0x4D3F9B0626C06E46ULL,
		0x52FA6E6E17B16B3DULL,
		0x83BE4C711E6C90F7ULL,
		0x89AB88C140FC5258ULL,
		0x754D331A79228FD0ULL,
		0x36329C65E2A2B3B0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF8082350D87FCC94ULL,
		0xE43EEC01B647D99AULL,
		0x9A7F360C4D80DC8CULL,
		0xA5F4DCDC2F62D67AULL,
		0x077C98E23CD921EEULL,
		0x1357118281F8A4B1ULL,
		0xEA9A6634F2451FA1ULL,
		0x6C6538CBC5456760ULL
	}};
	printf("Test Case 165\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xF99EA3E5E2612433ULL,
		0x3DE9CA9423411B24ULL,
		0x2357AFD95A150467ULL,
		0x51994AF5470373EEULL,
		0xE002C283660170E3ULL,
		0x161E14EAC86E6B40ULL,
		0x8B850E602C26FD7AULL,
		0x1F6898EB8C0CDCA0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF33D47CBC4C24866ULL,
		0x7BD3952846823649ULL,
		0x46AF5FB2B42A08CEULL,
		0xA33295EA8E06E7DCULL,
		0xC0058506CC02E1C6ULL,
		0x2C3C29D590DCD681ULL,
		0x170A1CC0584DFAF4ULL,
		0x3ED131D71819B941ULL
	}};
	printf("Test Case 166\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xBAC240F22B1B883DULL,
		0x686050B9E03F52DCULL,
		0x2B0624EB1D07FFC1ULL,
		0x622BDBBD6F42F986ULL,
		0x02CBD95D5ABBB3C0ULL,
		0xFAE4FD82597EA75CULL,
		0xD6835E28B8CECAEEULL,
		0x0EC8427F3D0F4785ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x758481E45637107AULL,
		0xD0C0A173C07EA5B9ULL,
		0x560C49D63A0FFF82ULL,
		0xC457B77ADE85F30CULL,
		0x0597B2BAB5776780ULL,
		0xF5C9FB04B2FD4EB8ULL,
		0xAD06BC51719D95DDULL,
		0x1D9084FE7A1E8F0BULL
	}};
	printf("Test Case 167\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xA96D7DE9878F5881ULL,
		0x42F64B9F6877D1C5ULL,
		0xFE08D98FEB93DBCEULL,
		0x0C22928915C8148AULL,
		0xE69D507111DD8DC4ULL,
		0xC1FAC4A9DD2CBE6EULL,
		0xC0522ED5FD807CD6ULL,
		0x219D61EF6E836DD6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x52DAFBD30F1EB102ULL,
		0x85EC973ED0EFA38BULL,
		0xFC11B31FD727B79CULL,
		0x184525122B902915ULL,
		0xCD3AA0E223BB1B88ULL,
		0x83F58953BA597CDDULL,
		0x80A45DABFB00F9ADULL,
		0x433AC3DEDD06DBADULL
	}};
	printf("Test Case 168\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x4E34E57E9E959A4EULL,
		0x44DBB6F8FC9ED291ULL,
		0xA1B21C0A85F2C0AEULL,
		0x10AA38AB2C45C0BCULL,
		0xDC39B125ED59FC19ULL,
		0x8B9979CA55F9BF8AULL,
		0x18DAA2687A3948A0ULL,
		0x01D5DA17858D3A3EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9C69CAFD3D2B349CULL,
		0x89B76DF1F93DA522ULL,
		0x436438150BE5815CULL,
		0x21547156588B8179ULL,
		0xB873624BDAB3F832ULL,
		0x1732F394ABF37F15ULL,
		0x31B544D0F4729141ULL,
		0x03ABB42F0B1A747CULL
	}};
	printf("Test Case 169\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xD03D605C5E3263FAULL,
		0x3086DA7DE0178E8BULL,
		0xA5E76F2B9BDA370AULL,
		0xD725F1B738342A7DULL,
		0xA622382A714C6903ULL,
		0x38CFFABD15EB849BULL,
		0x6DF21EF9FC79CC5DULL,
		0x124713A65FCECC55ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA07AC0B8BC64C7F4ULL,
		0x610DB4FBC02F1D17ULL,
		0x4BCEDE5737B46E14ULL,
		0xAE4BE36E706854FBULL,
		0x4C447054E298D207ULL,
		0x719FF57A2BD70937ULL,
		0xDBE43DF3F8F398BAULL,
		0x248E274CBF9D98AAULL
	}};
	printf("Test Case 170\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x5CC7FB3A42BA1C2EULL,
		0x3927837F56C2F67AULL,
		0x3A986FA594915C5DULL,
		0x03D4AEDA79A531F7ULL,
		0x69D17A3B2AD51C42ULL,
		0x555999CCC409C10DULL,
		0xACF540E80D70080FULL,
		0x0471571FB94C77CCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB98FF6748574385CULL,
		0x724F06FEAD85ECF4ULL,
		0x7530DF4B2922B8BAULL,
		0x07A95DB4F34A63EEULL,
		0xD3A2F47655AA3884ULL,
		0xAAB333998813821AULL,
		0x59EA81D01AE0101EULL,
		0x08E2AE3F7298EF99ULL
	}};
	printf("Test Case 171\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xA2D79AF1BE4AD04FULL,
		0xB6773CBD9EBDEAD9ULL,
		0x277526B1A6A5570BULL,
		0x4CCE40BD2CD605F2ULL,
		0x695C2AE4AF5E7B55ULL,
		0xAEB463E63CA78BC1ULL,
		0x1BD5614D48DC7FE8ULL,
		0x20CF7EEE57411BD6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x45AF35E37C95A09EULL,
		0x6CEE797B3D7BD5B3ULL,
		0x4EEA4D634D4AAE17ULL,
		0x999C817A59AC0BE4ULL,
		0xD2B855C95EBCF6AAULL,
		0x5D68C7CC794F1782ULL,
		0x37AAC29A91B8FFD1ULL,
		0x419EFDDCAE8237ACULL
	}};
	printf("Test Case 172\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x5F485125675467E3ULL,
		0xDBA48C531FB7C9D6ULL,
		0x00B00BEDF83269C1ULL,
		0x503692C21D02028CULL,
		0xBD07EEB350D63A05ULL,
		0x25B48A57EF3E872BULL,
		0x8D4C9CC8E2BE8AF4ULL,
		0x38BE06000676BD9DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBE90A24ACEA8CFC6ULL,
		0xB74918A63F6F93ACULL,
		0x016017DBF064D383ULL,
		0xA06D25843A040518ULL,
		0x7A0FDD66A1AC740AULL,
		0x4B6914AFDE7D0E57ULL,
		0x1A993991C57D15E8ULL,
		0x717C0C000CED7B3BULL
	}};
	printf("Test Case 173\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xE7AC5D9E10371591ULL,
		0xA6C412DC648277BCULL,
		0xDF98037BA8E0B11DULL,
		0x079DB2DFF6A31B62ULL,
		0xF6E77DF72E27FDA6ULL,
		0x81E59E47B12A5452ULL,
		0x9989A0D51D7E4414ULL,
		0x3725F7982E2AF0A7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCF58BB3C206E2B22ULL,
		0x4D8825B8C904EF79ULL,
		0xBF3006F751C1623BULL,
		0x0F3B65BFED4636C5ULL,
		0xEDCEFBEE5C4FFB4CULL,
		0x03CB3C8F6254A8A5ULL,
		0x331341AA3AFC8829ULL,
		0x6E4BEF305C55E14FULL
	}};
	printf("Test Case 174\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x21F6F15270209ECEULL,
		0x58CCF1262104E0DBULL,
		0xBA15250778234BDFULL,
		0x4C3803AA9E600061ULL,
		0xFEFF585A3655063AULL,
		0x7AA9FA9A5DA94D98ULL,
		0xF19BBAD51634F05CULL,
		0x3A29E361064C8AA2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x43EDE2A4E0413D9CULL,
		0xB199E24C4209C1B6ULL,
		0x742A4A0EF04697BEULL,
		0x987007553CC000C3ULL,
		0xFDFEB0B46CAA0C74ULL,
		0xF553F534BB529B31ULL,
		0xE33775AA2C69E0B8ULL,
		0x7453C6C20C991545ULL
	}};
	printf("Test Case 175\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x162F92064C702D28ULL,
		0x6F612E23C923BCB4ULL,
		0x644ED65A61C1FFE7ULL,
		0xFBC2C16B107820CCULL,
		0x2F87507D8ACDEBDDULL,
		0xC6269591EC3372E2ULL,
		0x3AA478AF881B6237ULL,
		0x34B5712817CA6ECFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2C5F240C98E05A50ULL,
		0xDEC25C4792477968ULL,
		0xC89DACB4C383FFCEULL,
		0xF78582D620F04198ULL,
		0x5F0EA0FB159BD7BBULL,
		0x8C4D2B23D866E5C4ULL,
		0x7548F15F1036C46FULL,
		0x696AE2502F94DD9EULL
	}};
	printf("Test Case 176\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xE5B84A1BF6A1770FULL,
		0x0750149A7C7A3A64ULL,
		0xC8C18212B44492F7ULL,
		0x461BAA28B86519B4ULL,
		0x6105343FE12D1F93ULL,
		0x4229C8BA5FA025D2ULL,
		0x67369DF866CACD4AULL,
		0x20E261BDE65F9A38ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCB709437ED42EE1EULL,
		0x0EA02934F8F474C9ULL,
		0x91830425688925EEULL,
		0x8C37545170CA3369ULL,
		0xC20A687FC25A3F26ULL,
		0x84539174BF404BA4ULL,
		0xCE6D3BF0CD959A94ULL,
		0x41C4C37BCCBF3470ULL
	}};
	printf("Test Case 177\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xE32FF17D83E5CD09ULL,
		0xE9C96E8FDB50EFF0ULL,
		0xF687DF8DAF45C0BCULL,
		0xA7303AFE337DB2F3ULL,
		0xB9AC8B9E08C68C3CULL,
		0x0335930EF3E2C9E2ULL,
		0x490E64A87EDA7FC8ULL,
		0x282DF756F8EE90F5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC65FE2FB07CB9A12ULL,
		0xD392DD1FB6A1DFE1ULL,
		0xED0FBF1B5E8B8179ULL,
		0x4E6075FC66FB65E7ULL,
		0x7359173C118D1879ULL,
		0x066B261DE7C593C5ULL,
		0x921CC950FDB4FF90ULL,
		0x505BEEADF1DD21EAULL
	}};
	printf("Test Case 178\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xFEEEFD3A6EF9196FULL,
		0xE63C0948B5E34809ULL,
		0xAE3C484F7B025D52ULL,
		0x6DA23229021D47F6ULL,
		0x8C4AA7518E3F98BBULL,
		0xA60E94D7D348AC35ULL,
		0x5A1E0FCD3C62154CULL,
		0x0CF7663FE226D1E3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFDDDFA74DDF232DEULL,
		0xCC7812916BC69013ULL,
		0x5C78909EF604BAA5ULL,
		0xDB446452043A8FEDULL,
		0x18954EA31C7F3176ULL,
		0x4C1D29AFA691586BULL,
		0xB43C1F9A78C42A99ULL,
		0x19EECC7FC44DA3C6ULL
	}};
	printf("Test Case 179\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xE5E3F681531CAC92ULL,
		0x415C84B5ADC818DEULL,
		0xDD32317E26B359BFULL,
		0x8E2A880E86CF1584ULL,
		0x73A99102856DF6D6ULL,
		0x506B335D3F620895ULL,
		0x5D5878193BFBC042ULL,
		0x34FA4EB4FB1B1A65ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCBC7ED02A6395924ULL,
		0x82B9096B5B9031BDULL,
		0xBA6462FC4D66B37EULL,
		0x1C55101D0D9E2B09ULL,
		0xE75322050ADBEDADULL,
		0xA0D666BA7EC4112AULL,
		0xBAB0F03277F78084ULL,
		0x69F49D69F63634CAULL
	}};
	printf("Test Case 180\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x1C8AB873DD46DFDCULL,
		0xB6E9B12D949A7AC9ULL,
		0x5E27804CE45A83B0ULL,
		0xE5E52CABAACA2B74ULL,
		0xB9260903884EECFDULL,
		0x77407CB269DF18CBULL,
		0x624F0B2F3C24A886ULL,
		0x03E4A5E8521726FEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x391570E7BA8DBFB8ULL,
		0x6DD3625B2934F592ULL,
		0xBC4F0099C8B50761ULL,
		0xCBCA5957559456E8ULL,
		0x724C1207109DD9FBULL,
		0xEE80F964D3BE3197ULL,
		0xC49E165E7849510CULL,
		0x07C94BD0A42E4DFCULL
	}};
	printf("Test Case 181\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xC5618E88C5B5FF7EULL,
		0x0BA7F653FE198901ULL,
		0xC81449DEEDFE6036ULL,
		0x5A9CAC211CC67D88ULL,
		0xC227E3631FE87470ULL,
		0xFFBECFDD659F8ACFULL,
		0xC3DC83CE0CB64A09ULL,
		0x0808D6B5F20017C1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8AC31D118B6BFEFCULL,
		0x174FECA7FC331203ULL,
		0x902893BDDBFCC06CULL,
		0xB5395842398CFB11ULL,
		0x844FC6C63FD0E8E0ULL,
		0xFF7D9FBACB3F159FULL,
		0x87B9079C196C9413ULL,
		0x1011AD6BE4002F83ULL
	}};
	printf("Test Case 182\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x3B671BD93B9D718EULL,
		0x2752118600D0E711ULL,
		0xF04EE30F641B0AA7ULL,
		0x1AF31135B741553BULL,
		0x92E59053E8F4ABCEULL,
		0x07F82CC66079C515ULL,
		0x173CB0529C9B14A7ULL,
		0x0534FF47C501619CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x76CE37B2773AE31CULL,
		0x4EA4230C01A1CE22ULL,
		0xE09DC61EC836154EULL,
		0x35E6226B6E82AA77ULL,
		0x25CB20A7D1E9579CULL,
		0x0FF0598CC0F38A2BULL,
		0x2E7960A53936294EULL,
		0x0A69FE8F8A02C338ULL
	}};
	printf("Test Case 183\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x6FC1E0DCDD342FFDULL,
		0x4EFF492214A329C3ULL,
		0x00F97E973CFD3F50ULL,
		0x24CE5AFF6E7D4AE2ULL,
		0x6B7B0D4922A08320ULL,
		0x7A59434E6788B805ULL,
		0x69E7F09BFB97DCCBULL,
		0x3A85925A9C9513DAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDF83C1B9BA685FFAULL,
		0x9DFE924429465386ULL,
		0x01F2FD2E79FA7EA0ULL,
		0x499CB5FEDCFA95C4ULL,
		0xD6F61A9245410640ULL,
		0xF4B2869CCF11700AULL,
		0xD3CFE137F72FB996ULL,
		0x750B24B5392A27B4ULL
	}};
	printf("Test Case 184\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x0F90991EE14677D6ULL,
		0xA7EB57E9F15A2632ULL,
		0x7D15CE4C07E098F8ULL,
		0x234F9B9283CC3067ULL,
		0x5771E6CE68F7CCAEULL,
		0xDAE31D20E242A3CFULL,
		0x9C3FFAD31F584E49ULL,
		0x3F53A24165D8E294ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1F21323DC28CEFACULL,
		0x4FD6AFD3E2B44C64ULL,
		0xFA2B9C980FC131F1ULL,
		0x469F3725079860CEULL,
		0xAEE3CD9CD1EF995CULL,
		0xB5C63A41C485479EULL,
		0x387FF5A63EB09C93ULL,
		0x7EA74482CBB1C529ULL
	}};
	printf("Test Case 185\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x85053EA8733E87A7ULL,
		0x830BA81F20678516ULL,
		0x9DBEB5F348D66A7DULL,
		0x6D459D017E0D37F2ULL,
		0xDB28C13123D41E03ULL,
		0xD324C2A8F797B3A6ULL,
		0x61C0402436322107ULL,
		0x2733667F9348BE57ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0A0A7D50E67D0F4EULL,
		0x0617503E40CF0A2DULL,
		0x3B7D6BE691ACD4FBULL,
		0xDA8B3A02FC1A6FE5ULL,
		0xB651826247A83C06ULL,
		0xA6498551EF2F674DULL,
		0xC38080486C64420FULL,
		0x4E66CCFF26917CAEULL
	}};
	printf("Test Case 186\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x6FDD00EC5455F62DULL,
		0x0094C47F0B7A4413ULL,
		0xA639857625EB271CULL,
		0xE50E46CD6D1C9B3BULL,
		0x39C4AEB409C3EF5AULL,
		0x677E545627FB0007ULL,
		0x6B69DC4A92E383A6ULL,
		0x184C207E0EC88AF4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDFBA01D8A8ABEC5AULL,
		0x012988FE16F48826ULL,
		0x4C730AEC4BD64E38ULL,
		0xCA1C8D9ADA393677ULL,
		0x73895D681387DEB5ULL,
		0xCEFCA8AC4FF6000EULL,
		0xD6D3B89525C7074CULL,
		0x309840FC1D9115E8ULL
	}};
	printf("Test Case 187\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x9ADC5ACEE0023D67ULL,
		0x1465E4F830DB0935ULL,
		0x07DEF30D258C6229ULL,
		0xB0A78F0292291CCAULL,
		0x7D7990FD0A0C1983ULL,
		0xCC45E84A0D730640ULL,
		0xC21C559B5DE9D46EULL,
		0x1A1EC77EBD5B28BAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x35B8B59DC0047ACEULL,
		0x28CBC9F061B6126BULL,
		0x0FBDE61A4B18C452ULL,
		0x614F1E0524523994ULL,
		0xFAF321FA14183307ULL,
		0x988BD0941AE60C80ULL,
		0x8438AB36BBD3A8DDULL,
		0x343D8EFD7AB65175ULL
	}};
	printf("Test Case 188\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x0CAAB7EABE9EC7DAULL,
		0x81F1CC0BAC3B3BFEULL,
		0xE8D3B56B4A0D2704ULL,
		0x50B96FE2EC6FC58BULL,
		0x4C1DC81DC72A73E2ULL,
		0x400AC29C2BD65765ULL,
		0x11C4FD24B74FBD63ULL,
		0x15B5A588A420AE41ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x19556FD57D3D8FB4ULL,
		0x03E39817587677FCULL,
		0xD1A76AD6941A4E09ULL,
		0xA172DFC5D8DF8B17ULL,
		0x983B903B8E54E7C4ULL,
		0x8015853857ACAECAULL,
		0x2389FA496E9F7AC6ULL,
		0x2B6B4B1148415C82ULL
	}};
	printf("Test Case 189\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xFB20C2036D5DFC16ULL,
		0xAE1ED1A5659EE6AEULL,
		0x24FE9626A945E38AULL,
		0x6F0C2FBB2F860F01ULL,
		0xDE653D197F1CE0F9ULL,
		0x4CE46DF7DB62D220ULL,
		0x0630CC7A4F9B07CBULL,
		0x29B97B2DE57FD3C9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF6418406DABBF82CULL,
		0x5C3DA34ACB3DCD5DULL,
		0x49FD2C4D528BC715ULL,
		0xDE185F765F0C1E02ULL,
		0xBCCA7A32FE39C1F2ULL,
		0x99C8DBEFB6C5A441ULL,
		0x0C6198F49F360F96ULL,
		0x5372F65BCAFFA792ULL
	}};
	printf("Test Case 190\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x37CE6688674D95E9ULL,
		0xE4080B8F6D097134ULL,
		0x087BC566925930B2ULL,
		0xEE93DA09D2E7BC75ULL,
		0x2D3E3F5CF2FE9A05ULL,
		0x0C946E8D7524228AULL,
		0x7C3E63AEC5F630A0ULL,
		0x2A64C6D2ADCE6275ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6F9CCD10CE9B2BD2ULL,
		0xC810171EDA12E268ULL,
		0x10F78ACD24B26165ULL,
		0xDD27B413A5CF78EAULL,
		0x5A7C7EB9E5FD340BULL,
		0x1928DD1AEA484514ULL,
		0xF87CC75D8BEC6140ULL,
		0x54C98DA55B9CC4EAULL
	}};
	printf("Test Case 191\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x1951830FD50EB300ULL,
		0x92998E1740DBE1A8ULL,
		0xC90B3FA8CD5F4A14ULL,
		0x7C2D1C698D53ADABULL,
		0x5E423DBF20E67ED3ULL,
		0x5170EDE19AB52124ULL,
		0x8E75B8B55AECC202ULL,
		0x0F9C45482EC9D721ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x32A3061FAA1D6600ULL,
		0x25331C2E81B7C350ULL,
		0x92167F519ABE9429ULL,
		0xF85A38D31AA75B57ULL,
		0xBC847B7E41CCFDA6ULL,
		0xA2E1DBC3356A4248ULL,
		0x1CEB716AB5D98404ULL,
		0x1F388A905D93AE43ULL
	}};
	printf("Test Case 192\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x82C1E5A7F873D016ULL,
		0x5E99A2F20F5C74DFULL,
		0x5A9B845835B94E9EULL,
		0xF532D2CE80A98C94ULL,
		0x8F10161548E9E05BULL,
		0x62FBEA67DBC8D7D5ULL,
		0x404B78528BC9F5D2ULL,
		0x2114F9D4E0340923ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0583CB4FF0E7A02CULL,
		0xBD3345E41EB8E9BFULL,
		0xB53708B06B729D3CULL,
		0xEA65A59D01531928ULL,
		0x1E202C2A91D3C0B7ULL,
		0xC5F7D4CFB791AFABULL,
		0x8096F0A51793EBA4ULL,
		0x4229F3A9C0681246ULL
	}};
	printf("Test Case 193\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x16D630374FCF8A9CULL,
		0xD74A79A8E7458D38ULL,
		0xBA198E963361D1BAULL,
		0x5CFAB5EF15406866ULL,
		0x62C236AD79CE9CBDULL,
		0xD304E3A06B41F825ULL,
		0xAFADA78F14878557ULL,
		0x185390A241AAE827ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2DAC606E9F9F1538ULL,
		0xAE94F351CE8B1A70ULL,
		0x74331D2C66C3A375ULL,
		0xB9F56BDE2A80D0CDULL,
		0xC5846D5AF39D397AULL,
		0xA609C740D683F04AULL,
		0x5F5B4F1E290F0AAFULL,
		0x30A721448355D04FULL
	}};
	printf("Test Case 194\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xEF1FA789C7ED99DBULL,
		0xEBBDF64D014EACE5ULL,
		0xAC4B00712BD0AAD2ULL,
		0xFCE6BFA233D04EAAULL,
		0x307C60332797C300ULL,
		0x7AD9CA906BB345C6ULL,
		0xB2BD3D1FA47A979BULL,
		0x275AF5DA2D5DCC29ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDE3F4F138FDB33B6ULL,
		0xD77BEC9A029D59CBULL,
		0x589600E257A155A5ULL,
		0xF9CD7F4467A09D55ULL,
		0x60F8C0664F2F8601ULL,
		0xF5B39520D7668B8CULL,
		0x657A7A3F48F52F36ULL,
		0x4EB5EBB45ABB9853ULL
	}};
	printf("Test Case 195\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x2E1CC49A61FFA415ULL,
		0x05764DABD271AF33ULL,
		0x3FEBB0BE88BFAC65ULL,
		0xF6E6B18E71CAF065ULL,
		0xF7306954E8C1308BULL,
		0xF011AD5ED971877CULL,
		0xAFCE62B8B39A9295ULL,
		0x05DB4F2F874BE22BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5C398934C3FF482AULL,
		0x0AEC9B57A4E35E66ULL,
		0x7FD7617D117F58CAULL,
		0xEDCD631CE395E0CAULL,
		0xEE60D2A9D1826117ULL,
		0xE0235ABDB2E30EF9ULL,
		0x5F9CC5716735252BULL,
		0x0BB69E5F0E97C457ULL
	}};
	printf("Test Case 196\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xD6B430637DA11798ULL,
		0x18B53CAEB664D153ULL,
		0x6A2715D51D3FBB07ULL,
		0x7835770C57A88036ULL,
		0xCEC3A6B33D39E0BCULL,
		0x691E3A06DC5F4AB3ULL,
		0x0F3675A54B6D917CULL,
		0x3DCF75E32118F9C1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAD6860C6FB422F30ULL,
		0x316A795D6CC9A2A7ULL,
		0xD44E2BAA3A7F760EULL,
		0xF06AEE18AF51006CULL,
		0x9D874D667A73C178ULL,
		0xD23C740DB8BE9567ULL,
		0x1E6CEB4A96DB22F8ULL,
		0x7B9EEBC64231F382ULL
	}};
	printf("Test Case 197\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xD87A502CB08B3935ULL,
		0x119074691345A9CCULL,
		0x2585D40E230CDBA0ULL,
		0xCE54B74588B451DAULL,
		0xE9D9101441A44F19ULL,
		0x13A721201E84F682ULL,
		0x7AAFC1556714B23CULL,
		0x28265075E8F9ED1AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB0F4A0596116726AULL,
		0x2320E8D2268B5399ULL,
		0x4B0BA81C4619B740ULL,
		0x9CA96E8B1168A3B4ULL,
		0xD3B2202883489E33ULL,
		0x274E42403D09ED05ULL,
		0xF55F82AACE296478ULL,
		0x504CA0EBD1F3DA34ULL
	}};
	printf("Test Case 198\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xCCBBE6B86B1A1AC0ULL,
		0x0C3D405E555E4D5DULL,
		0xE46A6690AED0B0CEULL,
		0xC2397BD49EA35746ULL,
		0x000D950C79B6E43BULL,
		0x54FDE1263C2E12E4ULL,
		0x9BE2BB4BC5510C89ULL,
		0x158B0FE84A346B6FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9977CD70D6343580ULL,
		0x187A80BCAABC9ABBULL,
		0xC8D4CD215DA1619CULL,
		0x8472F7A93D46AE8DULL,
		0x001B2A18F36DC877ULL,
		0xA9FBC24C785C25C8ULL,
		0x37C576978AA21912ULL,
		0x2B161FD09468D6DFULL
	}};
	printf("Test Case 199\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xF8FE23205178CE53ULL,
		0xA26240103472DEC0ULL,
		0x38F8FF454A81044EULL,
		0xEB4BFD8516EC6877ULL,
		0x71EC16F5A47B7BB8ULL,
		0x30B9AFEA2513F8DAULL,
		0xBB031028BCDF43A4ULL,
		0x25119877E557BB92ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF1FC4640A2F19CA6ULL,
		0x44C4802068E5BD81ULL,
		0x71F1FE8A9502089DULL,
		0xD697FB0A2DD8D0EEULL,
		0xE3D82DEB48F6F771ULL,
		0x61735FD44A27F1B4ULL,
		0x7606205179BE8748ULL,
		0x4A2330EFCAAF7725ULL
	}};
	printf("Test Case 200\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
}