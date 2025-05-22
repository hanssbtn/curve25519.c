#include "../tests.h"

int32_t curve25519_key_log2_test(void) {
	printf("Key Log2 Test\n");
	curve25519_key_t k1 = {.key64 = {
		0xAE101888EC1D97B8ULL,
		0x57107F74409A1950ULL,
		0x6761CC32070C9D03ULL,
		0x880BCD51B65152FFULL,
		0xCA19E6708DB219DFULL,
		0x543243E06ABD64B3ULL,
		0x7AFD8B7520956343ULL,
		0xD4972C319D9F6200ULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	curve25519_key_t r = {};
	printf("Test Case 1\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xBCF3F1156B216D37ULL,
		0xC4EC6724A29DF52BULL,
		0xC4D0CFADED0303F8ULL,
		0x0DD5D59C8AAF1718ULL,
		0xF1365ADE1FA0D2DEULL,
		0xA164D41207819201ULL,
		0x98BA7A865D69B0B8ULL,
		0x37F87FBF2CF1A507ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 2\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x12AD6D48E2ECE67CULL,
		0x0D334026F32D3195ULL,
		0xF492C68D19EC8976ULL,
		0x1E721FB9CD382DC5ULL,
		0xEF626CA593FDD5B9ULL,
		0xC719B1503687CAC0ULL,
		0xE504CF2AE38271F7ULL,
		0x2E01A113432A9417ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 3\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xFF2E6F2714CD9083ULL,
		0xBE0960AA38DCD0C4ULL,
		0x451C4B5288AD5F3EULL,
		0x36C3E961406A98AAULL,
		0x8D63F32DBBA7B6C2ULL,
		0x7365F4D568341310ULL,
		0x21FDAF1C81B742C0ULL,
		0x2576A21C5440C47EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 4\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x1EC736BDFBAABDC4ULL,
		0x2CE81AA7D55B9CDBULL,
		0xCDCEC653C3ABC694ULL,
		0x2BC022CDDB0BC3EAULL,
		0x824BA8A3638CCDDCULL,
		0x357795FD0D4E4579ULL,
		0x285F981327911165ULL,
		0x15A54EF8EDF646A9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	printf("Test Case 5\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xFA8E7D9A967CA588ULL,
		0xBDA1D20859797A62ULL,
		0xB51A6631947CFCBCULL,
		0x2D2EE5BE09A4A341ULL,
		0xA9CEB6DF594BAC24ULL,
		0x2246CD7D704D93C0ULL,
		0x90B6D37FF019498BULL,
		0x3BC921B7AFC7EA09ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 6\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xA8B15B8FC9E3C620ULL,
		0x9261BB5854A272EEULL,
		0xE2144377D43647ADULL,
		0xDD5AAC47FD6834F3ULL,
		0x69CE213270E73CEAULL,
		0xEBC5B998B0865513ULL,
		0x00441A6531FBFE03ULL,
		0xC94E28934D2A8B82ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 7\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x2D2D96BB1B49EA27ULL,
		0x4ACD16DCD4A6AEA4ULL,
		0x68E4ACF2A2D685D3ULL,
		0x27A548A061FB76EEULL,
		0x1AECC2A98A97FA95ULL,
		0x3CC69900674B0698ULL,
		0xB5D5FDF9363C117CULL,
		0x35D1A535C82EFCD1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 8\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x32B409686BAE9AC5ULL,
		0xA46526E9D93D7683ULL,
		0xC97C033DFE7A3E33ULL,
		0x76661B859CE791C6ULL,
		0x8BB9336A0A3249C2ULL,
		0x91A11045484D8DC9ULL,
		0x6E123B09AEC27DEEULL,
		0xB564BFB7E6EE47B8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 9\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xC7FF86FEBDF876A7ULL,
		0xE8B82A4614F311A1ULL,
		0x90B109F3ED5BF0D8ULL,
		0x0A6248B363997888ULL,
		0x3A885C75B1316706ULL,
		0xBB7625E48B9AD115ULL,
		0xD3D9CEFBC7466B3BULL,
		0xEFB7C3D067C17A39ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 10\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xB6D92CA15B3784E7ULL,
		0xFDDE37068A47C0F1ULL,
		0xFD87BF415B28D6BAULL,
		0x2C794A037A53FEDFULL,
		0xFFD8DC66F844CEB9ULL,
		0xBF1317AF41141E99ULL,
		0x115EF498D699007BULL,
		0x64D628A35CDD107BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 11\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xB7339186C1D7A5D1ULL,
		0x2798B3C3F2C6A235ULL,
		0x3B315F3743AF514DULL,
		0x1645A836C1939649ULL,
		0x34B974FC4201F7ADULL,
		0x0212B5D8BBB4339CULL,
		0xD260C9F0C26ED1FBULL,
		0x0DA83A1689F9F33FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0800000000000000ULL
	}};
	printf("Test Case 12\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x994C5ECB21A06D42ULL,
		0xA66EAA7F0B9A5065ULL,
		0xCF2172CCB6F72FD0ULL,
		0xB1BCCE543C0E5AFDULL,
		0x6E56061F19A28B2CULL,
		0x346AF488EF5ACDBEULL,
		0xAAD3020FB51F9CF6ULL,
		0x8627169DED103461ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 13\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x051DF5CB4B8D4929ULL,
		0x9B635A4182E56117ULL,
		0xFC9F7E8569E3BF3EULL,
		0x92D7384F8B714BEEULL,
		0x4B9CB7ADEE1D5685ULL,
		0xBBC8FA1E76EAC845ULL,
		0xD49F87528E89EBE0ULL,
		0x0274734402B72504ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0200000000000000ULL
	}};
	printf("Test Case 14\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x53A99A299ACCC40BULL,
		0xD3DD34C784E9E1F9ULL,
		0xB483EE840EC8D0CEULL,
		0xDA18D1A93B848968ULL,
		0xFDF80F4FE8F1C261ULL,
		0x0EB060EB4641E48BULL,
		0x748A4B111ACDA5E5ULL,
		0x1DD90AB7FC766A55ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	printf("Test Case 15\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x6B746773DB52F7E8ULL,
		0x8381DDEF41E554B4ULL,
		0x508EDB5D0C2A886CULL,
		0xD546655987831071ULL,
		0x985A45710B6E7E77ULL,
		0xC8981F64818880BAULL,
		0xD6F91061EC2FE639ULL,
		0x0E5508619613C80DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0800000000000000ULL
	}};
	printf("Test Case 16\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x07818384A5C8390AULL,
		0x95ACAB19630B5986ULL,
		0xF8E8EE46F9F89CD2ULL,
		0x7DBAEC457B9E124BULL,
		0x653E67E6A5998DC9ULL,
		0xFDD20A128C37337EULL,
		0xD6862568AD449D48ULL,
		0x30380398B9D2278DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 17\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xBE6B8C9A7E693A71ULL,
		0x0705D34B5B85D7FFULL,
		0x20C14B9909F28E9AULL,
		0x7A14F37F1AE66B9DULL,
		0x7FD26A0FBA6EE947ULL,
		0x2CD6179B1424B384ULL,
		0x0480C526FC845F2EULL,
		0xA772E7EA7D3E6964ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 18\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xF0A0F1B4F0E03CFCULL,
		0xA843AA05A8894DA8ULL,
		0x822C9FF1B4C50844ULL,
		0xB4E58F7246BE82ADULL,
		0x3C4406D462AF4F6CULL,
		0x87773533E1AD23F9ULL,
		0xB9C269896C7E3B51ULL,
		0x756788A7B30581DBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 19\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x0566F4BB269C26B9ULL,
		0xE8D25927CD04D15DULL,
		0x5EB5FD95D313AF1FULL,
		0x9C9389FBED7BFABAULL,
		0xF8E3B0BB84D6E38DULL,
		0xD34D8A896E039289ULL,
		0x96EDC0887D176B99ULL,
		0x121E7FED7518D045ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	printf("Test Case 20\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xDB5284ED59AC23EBULL,
		0x9E177D65B8B1D537ULL,
		0x5A8E98CC38057905ULL,
		0xDE9DFE9BE2FFE055ULL,
		0x1B160B4A8E8C0225ULL,
		0x60CDF980EEE5522EULL,
		0xA8855EBBE858E8EBULL,
		0x417DA95DF2DC23E2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 21\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x5AA82B3C0C6E4E21ULL,
		0x721F67A1E58D9C8EULL,
		0xB0157130CD9CD440ULL,
		0xEF22709EAE7B5A67ULL,
		0x835D98CED7B7874EULL,
		0xFF6F85C770AAE8A6ULL,
		0xB0D2F282D828CD10ULL,
		0x05AD92F48A771989ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0400000000000000ULL
	}};
	printf("Test Case 22\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xED0CFB6C6E9D2FDEULL,
		0xECF19673068972E9ULL,
		0x7AE9CDE530042286ULL,
		0x963744E7A79CBB2AULL,
		0x5D08ACA291039EFDULL,
		0xFCCD820A8F097B19ULL,
		0x413F6CB9D2C1487CULL,
		0xADE5954A87A98CF1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 23\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x3BF953BEC984C605ULL,
		0xF68BA184C0792C48ULL,
		0x6FBFFB26C286D195ULL,
		0x654BB296AD0429F2ULL,
		0x7022A0DB6348B284ULL,
		0x0D57ED7CAF636181ULL,
		0x0B64DEE2D3E87E8EULL,
		0x40CB4D41C3A59D37ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 24\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x4EFC149C8BC8C30DULL,
		0x89AB9BFD26CDE56FULL,
		0xCDB79B1BC686C947ULL,
		0x287A4D4DC2E68D6EULL,
		0xC93C922BF691C5E6ULL,
		0x4669CEAE8412B35FULL,
		0x42630670BAD53411ULL,
		0x6E653E834A7FFDE3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 25\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x3A8AF1BB72B9295DULL,
		0x55683945DF0156EDULL,
		0x06A47BCD632C0EB7ULL,
		0xD27A031D483AFF7DULL,
		0x8B11512B50B813F2ULL,
		0x0D3E77C3DE753788ULL,
		0x93C7E0E7A795CCEEULL,
		0x0454B7487AD82B47ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0400000000000000ULL
	}};
	printf("Test Case 26\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xD1292D60BDCCC8F0ULL,
		0x6F3E0E7321757AFCULL,
		0x12D1BA73A1A1ED06ULL,
		0x39F7DA4BE3C3FB0DULL,
		0x3E222F73BFF6DFC9ULL,
		0x78C51CFAAA3001BCULL,
		0x3135A5B90E6186B4ULL,
		0x4794D97BBE732AEFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 27\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xCAFDD579C30248A9ULL,
		0xF0300D266645B700ULL,
		0xB00FE9835BDDD584ULL,
		0xAE0F915B5BB59982ULL,
		0xC8CA229666953654ULL,
		0xF383CB80EA0683F4ULL,
		0x3C1ECBC347E06F36ULL,
		0x81B0F9332063063FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 28\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x3604E74C2EC58A68ULL,
		0x7751F19B527E87FFULL,
		0x3FCEF96E70D3273FULL,
		0x1FC70941FD75DC64ULL,
		0x08756A0C5CD09AA5ULL,
		0x3DD9549F3D088112ULL,
		0xDC84299CD40E1359ULL,
		0x5645D865C008A8D0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 29\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x7CFCCEE34AA3D63DULL,
		0x8EA573B2A9E3E64BULL,
		0xF5BFA69982AD40B8ULL,
		0x975AE092EDE3BC02ULL,
		0x0BF3B2A8F491A569ULL,
		0x7F086EBF9F0BFEEFULL,
		0x60ED6A608068D74DULL,
		0x0CE9F1AACAB059A2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0800000000000000ULL
	}};
	printf("Test Case 30\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xFD9EEAB971A43D2DULL,
		0xB0E3B95FE6A90162ULL,
		0xF11F0C12D7C2C03DULL,
		0xDEED141CD705C5A1ULL,
		0xA577C2516317034AULL,
		0x2DD4C649936B31E7ULL,
		0x88D3E16B66C61FB7ULL,
		0x8CDD14D5CF1F0569ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 31\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xD145E221587486CAULL,
		0x8C7E3D9BF37B9548ULL,
		0x53FEC6CF7C9ADE46ULL,
		0x147E410E112BB3B0ULL,
		0x6C714590871BC4C0ULL,
		0xC9A086B7519CF36FULL,
		0x29586258928FDE44ULL,
		0xF20DBBF57DE57533ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 32\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x35A5D64F2AE4310DULL,
		0x570A456D7DB46DDFULL,
		0xE85DF37F75DEB8F8ULL,
		0x1E0FCE3A31FC9D31ULL,
		0xFE434DFF74872CF3ULL,
		0x0E226526DEB531BEULL,
		0x3BCA6D64FD51EBE8ULL,
		0x74F102F8B2C56577ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 33\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xF466AED8E1407D2DULL,
		0x5ACA7F84930E3FC9ULL,
		0x96D5C196486015CAULL,
		0xC73B3C70AF3B523EULL,
		0x41EBE4B222A387C1ULL,
		0x77CFACDC85B71FA3ULL,
		0xCF72EB851A95BA75ULL,
		0x7C910945DF708C04ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 34\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x3873878D2D08E395ULL,
		0xDDCFF13B1703C98CULL,
		0x23FCD7AD6FB53291ULL,
		0xCA5DD93D52464301ULL,
		0x8F3A2D466B7E4B1DULL,
		0xF211F64D9C13BACAULL,
		0xA2CA1CEBD89FD68DULL,
		0x1F378CDFABCFC4B8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	printf("Test Case 35\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x199C98AC94AD3CE8ULL,
		0xA7A8EDA2DB1FB159ULL,
		0x6EB864CD3E54D464ULL,
		0x8CA5D818702B067FULL,
		0x9E43F92FB2A62118ULL,
		0xBD776A162C63CAC0ULL,
		0xFC09ECEF070521F1ULL,
		0x5A8E55BC12266FE6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 36\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xDCBA4E90E827C9E5ULL,
		0x500BCA895A7BF136ULL,
		0x0026C798D5F79EF0ULL,
		0x607B9A8A0DD50070ULL,
		0x6D0F9A166B41D399ULL,
		0xDFA310FCE574BCCBULL,
		0x2CF72F3B87BDB3F9ULL,
		0x5137FA3198E2CB83ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 37\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x5D4C0D49FC4B3088ULL,
		0x1829D70FB062674CULL,
		0xB46F1A201C138969ULL,
		0xA70A8FDD5E1F4850ULL,
		0xF558DDF78D38B0D6ULL,
		0x24910AE4FEB761B3ULL,
		0x595C17AEC7FDD16AULL,
		0x15568648DE8D381EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	printf("Test Case 38\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x50442877B03D2915ULL,
		0x160967A7E0BE1B58ULL,
		0xD85DDB9BDF4061ABULL,
		0x6FA9F1765D9D87BBULL,
		0xECF56A6AD3B0AA1BULL,
		0x523F7942D5B7C2CEULL,
		0xBA08AF5A57C78A0EULL,
		0x6D030F327B53B2A4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 39\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xFF6A5CD43E6241F6ULL,
		0x6D2550DAC8C30E72ULL,
		0x5AFC65AE30726170ULL,
		0x048CD38F648BB654ULL,
		0x18EC840F15727D8AULL,
		0x083E3CA9CB55C269ULL,
		0x93EC2AD49E3FEE05ULL,
		0x75781E6AFD6D5714ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 40\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x8E9D9990378BDBE9ULL,
		0x11FB53A16467A18BULL,
		0xDDC693C96B5F78F1ULL,
		0x5C0CF5760B533115ULL,
		0x180B544F21B68123ULL,
		0x7112470110B04BB6ULL,
		0x9EA1220C70D53A9AULL,
		0xA34CD35CE3313367ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 41\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xD43D361A628E882FULL,
		0x06588A70BEDD1E1CULL,
		0x6E2C6FD6E2B93FB5ULL,
		0xCDCD8C6AD005F530ULL,
		0x01C1C1A6AC33B872ULL,
		0xE493579E67499388ULL,
		0x9216CADE94BFA337ULL,
		0xAC9AF3308552D2F4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 42\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xA453548A37B70D16ULL,
		0x109C5E345431F68EULL,
		0x4B4A3CA3C68DD324ULL,
		0x28F2D5E20433DE22ULL,
		0x2A78886973D23F13ULL,
		0x56BA20292F4EF065ULL,
		0x04CE6B1DE9FBF91EULL,
		0x0C3A2D43214FA313ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0800000000000000ULL
	}};
	printf("Test Case 43\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xC02E3D5F97F9378CULL,
		0x7A833C8A5D834253ULL,
		0x3FD671528F3C15CAULL,
		0xF9998C6379CDA27FULL,
		0x51036DE659B3B08BULL,
		0x8EE4E2BDF7E4C9A4ULL,
		0xE7C87E7CB0EA8125ULL,
		0xDE2BA516ED737EE0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 44\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xE813EA1491B1CEA2ULL,
		0x0DC806275994970CULL,
		0x8C53034898D4AB90ULL,
		0xAA801FD69A740C89ULL,
		0x07656290D8F4B477ULL,
		0x362AED83F14F0402ULL,
		0xBC04A6C0DCD0F311ULL,
		0xFD1C02243DBCF1F8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 45\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xBF388E4AF0F30F72ULL,
		0x4150449A50684951ULL,
		0xEDE5DF7B02299783ULL,
		0x79928EE4ABFAC8FBULL,
		0x0D2911E02D1C61DEULL,
		0xDE4316E8DFACCA0EULL,
		0xEF9BA08AB65C6321ULL,
		0x4C3C02D29B227A3EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 46\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x9AA2952D87D0FB02ULL,
		0x096C36DC0B3A3E4FULL,
		0xAE781F2D3D084A88ULL,
		0xDCBCA7F1424F4591ULL,
		0xFA9B70CD5EC06D18ULL,
		0x8D68D57817D8AB17ULL,
		0xF76C682536A8B683ULL,
		0x486F8F30FF6F685CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 47\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xEEE53650DBB106D8ULL,
		0xC54BE8F0706A2D6FULL,
		0xA12F20B75D0F11FAULL,
		0x4B3DB473CDEB890BULL,
		0x9EDC306359A7CEC1ULL,
		0xC280542F7C6574B8ULL,
		0xC495C563EF4BDE1CULL,
		0x3E5FCBEBA524E891ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 48\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xAA3BCB11113D67D6ULL,
		0xD3F98D2707CD07A6ULL,
		0x3396691EB8DBB1C1ULL,
		0xF1E8356A64A307FCULL,
		0x73576E7C34CDEECAULL,
		0xABA8BB941CE75006ULL,
		0xE05C91341462029FULL,
		0xF5EC1C445A650D0EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 49\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x53CBC6C0CDFBE26CULL,
		0x670D7C3845D17757ULL,
		0xA7DE6E8CA4F77FE6ULL,
		0x1A768D38509115A2ULL,
		0x0B962AFEA95840FDULL,
		0x6ECFD9AC93FE7B3BULL,
		0xC69BF79138A26C79ULL,
		0xC677B27FE2E900BAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 50\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xD741E5B49FE5EFF8ULL,
		0x968ECA55427127D1ULL,
		0x4B9CDA502E568616ULL,
		0xF141D842B5626CC0ULL,
		0x7A116F79391401BDULL,
		0x915910E640DF9D0DULL,
		0xC9A82F1C640DBEE2ULL,
		0x2C3DE30CC7E7821AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 51\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x99D7E24F81E0C97BULL,
		0x3DA9B886AB99FC68ULL,
		0xFC17F6674EC5E829ULL,
		0x07F64D7BE4046090ULL,
		0x5495FC8F9E21ABBFULL,
		0x2E330C8CFC6E5404ULL,
		0xAB241A05A8D75209ULL,
		0x4B592F264A07CFCBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 52\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xE99EFC8DAD4C24A5ULL,
		0x8AB271DC84511805ULL,
		0x4858C97871743D23ULL,
		0x288B7F116E031E11ULL,
		0xE1A24AC2DBF3D955ULL,
		0xB5199259E94483BBULL,
		0x6E4C36A479987E02ULL,
		0x80A5E28A19A6D341ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 53\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x99E8AFE232018FB0ULL,
		0xAEAC84326976577EULL,
		0xA1091784793520D8ULL,
		0x7AB26FE707DF857AULL,
		0x2ACF3B883C14484CULL,
		0x93E60D4D890265C6ULL,
		0x2169570B8CF27398ULL,
		0xE8B40B70EDF0D37AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 54\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x7F3111ECE5AAB55BULL,
		0xE6E226C9CADBAEC5ULL,
		0x5B0272DAA7BA7CAFULL,
		0xCFD493CC4357BA47ULL,
		0xE41CBBE3B12AC081ULL,
		0xDDC0C96E21957978ULL,
		0x4DB43F3A6C8D5B08ULL,
		0xC5AAD6B0A4985FD0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 55\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x2825F000D340E946ULL,
		0x9763CD02DD634227ULL,
		0x92A93A579BEB8598ULL,
		0xE934E6C139FA4184ULL,
		0xA75D8956A996BC65ULL,
		0x26A5E59BFD72163FULL,
		0xD30EE625742AC4F8ULL,
		0x347C947B89F02E8DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 56\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xDEED61144D14B9D7ULL,
		0x020AAAC3D3CFF069ULL,
		0x77D981E6799C5F24ULL,
		0xE33FCCA608D85258ULL,
		0x142880223DC89277ULL,
		0x2B4EEDBA45FD3C3FULL,
		0xB18E11493C41EE64ULL,
		0x1DB2F56E00F45F21ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	printf("Test Case 57\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x24FCA4731E996E46ULL,
		0xFC8EC2AB0EA6C8AEULL,
		0x5F3C4BFD5EC9CC92ULL,
		0x9392E8C23481CEEFULL,
		0x7F654A9C8DDF0872ULL,
		0xC7DA43FFB2DB2D44ULL,
		0x7F97ACFC8EC1F0E3ULL,
		0xF47C17461E8A71D9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 58\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x51CC25C1D0B371D3ULL,
		0x7E69B9304486D6F4ULL,
		0x17A01D73A0E8D47FULL,
		0x4E3BD3776FD90945ULL,
		0xCDC7BDA1B5E8CAA7ULL,
		0xD845EE7CD048CAC9ULL,
		0x7CA9213A637FE5CFULL,
		0xB3A14744B2607CEDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 59\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x5D8270BACA19CE1BULL,
		0x93E0ED34FABD96BCULL,
		0x80427CE7DF8CE890ULL,
		0x84891221A7BE01F6ULL,
		0xA6F73AB32B127C88ULL,
		0x3AB2C542883FDBDFULL,
		0xA64A7BD46B9843C8ULL,
		0x93B50046C29F8DDEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 60\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x99E5F13939B0EE4BULL,
		0x62E00D54757F2DD8ULL,
		0xD72C38BFF0A74C76ULL,
		0x0B1B969D3BBD9F0AULL,
		0x490CC94ECA7F2B29ULL,
		0xB63DBB6338A446F9ULL,
		0xEE644DF28BA2FB11ULL,
		0xBF65E7C539F37451ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 61\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xB7FC6654EB1CF3A7ULL,
		0x6147EBAFF4F3D239ULL,
		0x3FAD66B8BCFCBEB9ULL,
		0xB19E2F89BC801EB7ULL,
		0xFA86E934B8B10320ULL,
		0x5873949B32FACD97ULL,
		0x13C7DD1D3EA49B86ULL,
		0xDAB8B052B0936E3BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 62\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xDA576CE6F47337FAULL,
		0x89CB7C71F866E8BFULL,
		0x442B1AC69F7C2664ULL,
		0xD810E9583C50C766ULL,
		0x87037B31A4DED32CULL,
		0x122EDF4802760390ULL,
		0x8A62D6C88B1CC7FAULL,
		0xDC44C8E0189C9069ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 63\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x22930514B272EEEEULL,
		0x2A739E7D70697167ULL,
		0x046D6C138F68ED1AULL,
		0xB25243A71FFC356DULL,
		0x65FBB05C02610ED1ULL,
		0x4A9E09179C750E22ULL,
		0x9576D027E31FA3A8ULL,
		0x3592A90CD92EF710ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 64\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x4CF727A22578D4A5ULL,
		0x267ED7A00A0B67E6ULL,
		0x558A28567A973FBAULL,
		0x85A00F4CA9CC4BCDULL,
		0x894DC6812F652359ULL,
		0xEC2173FCC1E01A65ULL,
		0xE300260B8E90609BULL,
		0x3B2C4F62834E7A0DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 65\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x34F2DA8639E90250ULL,
		0xAA4978A691807EF4ULL,
		0xDD72882557FC1F66ULL,
		0x201453CE18308332ULL,
		0xE68DECE3F2E2F967ULL,
		0x90A7F6C18D632B32ULL,
		0x5F838286BC186F56ULL,
		0x99D45A3D4AB65462ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 66\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x332B0288391BBCE9ULL,
		0x2FC6997E5A017B65ULL,
		0x02F087DA2C8E9A40ULL,
		0xC8870DAECE2B8996ULL,
		0xBDBF0B046E84E19DULL,
		0xD4FF0138A5F2FFFFULL,
		0xD031F67CCEB3C72DULL,
		0x3A692F1B09AEA41BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 67\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xF1AE2DBACECAAFEAULL,
		0x4E25B8B581F9F073ULL,
		0x3BE0DE07260D2B5CULL,
		0xF45B010B9B6EF753ULL,
		0x2AE2085415A27FAFULL,
		0x56DF55531E648366ULL,
		0xF25003FBAD3DCD23ULL,
		0xEF3E8C61FE5C5890ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 68\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x0678F608E5127BFBULL,
		0xC327FD78C1355894ULL,
		0x7B51C8D33939B015ULL,
		0x53C9BCD57D61E6C2ULL,
		0xBE7900DA34C9714BULL,
		0x977BC77E7FC22F7EULL,
		0xC609E1D1D22E3B82ULL,
		0xF5563CDCC5B0123AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 69\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x47F6CB6F2729EFBBULL,
		0x35AF2E12212A5CE3ULL,
		0x63D98DB9A9A8A840ULL,
		0xA31C92EB6FE3FE78ULL,
		0x41D2B850ADA18113ULL,
		0x71AB5DA09EE1D0AAULL,
		0x3E9B415B88D116DAULL,
		0x6FC24AE0C3BB3FADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 70\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xA30D40308E07D316ULL,
		0xCBE1A0DA086F6074ULL,
		0x1419B3A84C31F5F2ULL,
		0x40E8E27A0DB9AF67ULL,
		0xDE265463AD55EC4AULL,
		0x4CC3BFCFD2AA8F6CULL,
		0x3E5D8772CED7831AULL,
		0xF99B7A81B925571BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 71\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xCFD5AC79A1B8641EULL,
		0x3028A3A4B5CEFEE6ULL,
		0x50AE134239E81F82ULL,
		0x6BE1F8F86A889AFFULL,
		0xE61888C9A1DCF4B2ULL,
		0xA07AC44525FD0AC7ULL,
		0x29450B89DA6D3795ULL,
		0xD364B874280653A3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 72\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x8C50CD2350B36BDCULL,
		0x5AFF242976C64EF3ULL,
		0x36B50A8051C6FF12ULL,
		0x1F0B44732F0B4637ULL,
		0xFAF182E826DDDB48ULL,
		0xECB436988B255367ULL,
		0xE1793A205C4F14E6ULL,
		0x0A334B7E90829A74ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0800000000000000ULL
	}};
	printf("Test Case 73\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x1FC575EB83169E5DULL,
		0x265BE9FC2D69469BULL,
		0x623AFF5522025473ULL,
		0x97DBA2E4B11BAD96ULL,
		0x536483A7156D7EE8ULL,
		0x750266908F0C30ADULL,
		0xA4ADC25760062563ULL,
		0xE73B6988ED50A4FAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 74\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x6152D62BCD51EBFEULL,
		0x9C84F6BE9B51705BULL,
		0x44F591C0D9F3A64DULL,
		0xE7CDD67D1E948391ULL,
		0x920021898AD2CD5FULL,
		0x04F184927D605966ULL,
		0x8274243A98194DBDULL,
		0x65AF952D952822A0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 75\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xA946CBA8ACD60C01ULL,
		0xEC6466FF6925E899ULL,
		0x03080F05947B493DULL,
		0x9FE9F7D111EF13CFULL,
		0xA9673C859E082E72ULL,
		0xFC02DE87B0CAF956ULL,
		0x465DEAA38BA3B3B7ULL,
		0xDAE894915FC8AA02ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 76\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x833512782E27DBE8ULL,
		0x34C9F9A2D81AEC71ULL,
		0x4309E906BCBC8201ULL,
		0x1463FC26692CE7CEULL,
		0xA8439DA4D8009095ULL,
		0x20AAD27208F7F9C8ULL,
		0x608804F87F16CCC1ULL,
		0x73463FE12A30F581ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 77\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xB581021CB203DF63ULL,
		0xD296E12A71D6AE9FULL,
		0x3A254BD3CB217DF7ULL,
		0xC76078EA11A040C7ULL,
		0x18FF87BCDF5A87B5ULL,
		0x06459DE746614C44ULL,
		0x3472EE1B7F7C5758ULL,
		0xB2FD896772DB91BFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 78\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xEE85745BBF8D7FD7ULL,
		0xDFD285B9DFE1A7D0ULL,
		0x653E2359CE8D5AF4ULL,
		0x9B5EDB6A5CAE5C0BULL,
		0xD26B807A7446B976ULL,
		0x03B8AC2B1B4C1E24ULL,
		0xC28A4A11AF773491ULL,
		0xFE2A62399A07F7A6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 79\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x87345693A831C41CULL,
		0x7F087E3232BB6661ULL,
		0x4C1E557A568DBC45ULL,
		0x945BEFE1EDF5F07AULL,
		0xB606EBF23269FECCULL,
		0x7E7E959E67161EECULL,
		0xF0062C37A17BC385ULL,
		0xE359C489B85AC0F9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 80\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x452752DA6A1FBE62ULL,
		0x938CA448493C873DULL,
		0xBDB81B1A28A7DE4CULL,
		0x517A11020C89FF28ULL,
		0x65E972CBB8553C18ULL,
		0x247F342FF22898D8ULL,
		0x5FDBD0A523526F52ULL,
		0xC98C5A5F2BDA8233ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 81\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xB569CF228068EC6CULL,
		0xE2DD546C24692152ULL,
		0xCD8C9030B90AC1A2ULL,
		0x0392BF411804621BULL,
		0xCE91273EDE0E6E8EULL,
		0x37701BE2E7EF5EE5ULL,
		0xB8612F47655E272CULL,
		0xC01A969AD6515316ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 82\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x18CE7224805F999BULL,
		0xD10A99F6DDB71956ULL,
		0xA0F09FE30568C05FULL,
		0x832954228945C2EBULL,
		0xC2B686597A331DD8ULL,
		0x6EDC81C8CF156F29ULL,
		0xB8D6D1657AF473BEULL,
		0x5ABDDD41D56CEEFCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 83\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x79DDD09C62B424F6ULL,
		0x0D40EAB38FAF5588ULL,
		0x32174826ECC5B1C4ULL,
		0x63251E0FC2AA54E8ULL,
		0x3F459770846B75B1ULL,
		0xC1E0D151593E296EULL,
		0x34F755ED9D4D4E9EULL,
		0x39FE27FFAD770CE6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 84\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xF952BA3BA5898314ULL,
		0x10B48A37540B5FF5ULL,
		0xD73B07E3A61866BDULL,
		0xAD1629FEDF2718E2ULL,
		0x3AE3504ABF62EDEAULL,
		0x9E8B3F2FA4D2C281ULL,
		0xD0DC9C0ABDD70D60ULL,
		0x68E72F24D4F0C46DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 85\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xDB8584FA8985B206ULL,
		0xEEC3F0EC0AD38899ULL,
		0xCFA6DF346A1246D8ULL,
		0x703DCDEA7AB419A5ULL,
		0x646ED676F529A5D6ULL,
		0x54B2FC3D19B242B4ULL,
		0xD12408BB21CBEE42ULL,
		0xB9B8BA7A0D289C0DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 86\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x24AE35737115C329ULL,
		0x2890FAC8F894E390ULL,
		0x3B1A69B5C7786697ULL,
		0xBC9F00101BE31F79ULL,
		0x2B0BBAA7D2EE4D7CULL,
		0x66B94836B7325DFAULL,
		0x092CB240CBC26507ULL,
		0x7CEDE94247B1362EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 87\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x4A711AA259B1A11DULL,
		0x32BC200CC5C9F02CULL,
		0xC68FC608E6FA2599ULL,
		0xB0EF083D2FA9AB08ULL,
		0x59AD51E4F9BEBDE9ULL,
		0x012AECB3AB62B8F5ULL,
		0x8259FBF3E1A7460FULL,
		0x1E904386B1A92AE5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	printf("Test Case 88\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x05F80501372BD666ULL,
		0x7949AC1CF6C983C9ULL,
		0xBDFF4DFADC79A61CULL,
		0x912589ED3334D1C0ULL,
		0xD5573ACA0EE8B38AULL,
		0xFA98016C54473E50ULL,
		0xD116EE7B1D3719D6ULL,
		0xAD5651E7481A2ED9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 89\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x4301FDCC5F7A3702ULL,
		0x1F3726F80C2F8536ULL,
		0xC43887123040513BULL,
		0x71CF0BACA02F562DULL,
		0x46668C30593DFC36ULL,
		0x1D0E85035F7171AFULL,
		0x486693055A6B8634ULL,
		0x18A6567EF076095BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	printf("Test Case 90\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x71DABE08F0D5FCD5ULL,
		0x0EDC9F5309BAD7FAULL,
		0x74B97A98B9537599ULL,
		0x36DB4B439946004BULL,
		0xC44B499146097413ULL,
		0xC7FC2674E7F20342ULL,
		0x6C998BBF55775EC6ULL,
		0xB95052629EAFCA42ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 91\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xAF91F968A610BBE2ULL,
		0x846B4A8F4C8345A8ULL,
		0xB473597E3FDE14BCULL,
		0x1C4AF7B94488C7BDULL,
		0xFECF8A203D838EA6ULL,
		0x338795B0B39BDF9BULL,
		0x3A0A71CA6B193557ULL,
		0xC650F48B454F64B4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 92\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x9E35319CE6072F03ULL,
		0x25AF161C62327B91ULL,
		0x24108F638B728345ULL,
		0xD610DA7E2BDC2596ULL,
		0x0251DCBE488DDC68ULL,
		0x6296BD90848D700DULL,
		0xE4CF5447974E9F92ULL,
		0x9E1C52932D601F3AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 93\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xDC0BC195048721CBULL,
		0xBDFB4EC7CC5AC814ULL,
		0xA759679975615C8BULL,
		0xB65D379DC4DE2C9BULL,
		0xBBA5ED695D96FC23ULL,
		0xAAF08576F6CC8DCBULL,
		0x8BA8F671D68BD03AULL,
		0xC3030519C7F869DBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 94\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x752E34DBFB36F3BFULL,
		0xE99DC2FA00B9E9D5ULL,
		0x91B83F282ACB0E56ULL,
		0x7BC48194E415F6E8ULL,
		0x3B7D4BED9F8116DDULL,
		0x6F861995A0C102BCULL,
		0x3FFEB1957D38F145ULL,
		0x5B8E00AC846A0998ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 95\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xD2F97AB6584BA69FULL,
		0x7D795600CB333F90ULL,
		0x55CBD9C499AB0E1AULL,
		0x684A0F79BF75543BULL,
		0xC8F0908662B8B169ULL,
		0x9E8C065DB69599F4ULL,
		0x828A2D3203039706ULL,
		0xCF38C145A7594669ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 96\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x21E16AB9D93430B4ULL,
		0x48090E1E93DF9CAFULL,
		0x6EA685B5D999B5A1ULL,
		0x878BC16C75AF0A05ULL,
		0xBEDC3374704B702FULL,
		0x913FBA72ED4456FDULL,
		0xAB0BA49A2F5ED5A6ULL,
		0xBF58BDEABB6B4080ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 97\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x1CBAEA23B944A558ULL,
		0x8D7C852F6CD92B0DULL,
		0xC2B0161F18F41512ULL,
		0x39BB777C21C11DAFULL,
		0x3CD800D9A4FD4BBDULL,
		0x1F6AE9F978BB18D7ULL,
		0x4E0B39D97080CAC0ULL,
		0xCCC974B8B213117BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 98\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x1C5FD065874DEB27ULL,
		0xF6298485F292D58BULL,
		0x0E4A79292684BE75ULL,
		0xE4005C1DC43F931DULL,
		0x79B6B9AECC1E1C64ULL,
		0x066273F45E8C096FULL,
		0x642B50435F80A4F8ULL,
		0x85F98FF18939A056ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 99\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x5931ABD7C989F4B6ULL,
		0x5B84DE20F0AE7AC0ULL,
		0x280C119CA48B15CAULL,
		0x11456C1F9E2DC773ULL,
		0x28C81D525E0BF799ULL,
		0x24F174554BA5E433ULL,
		0xB35F2910131CC85FULL,
		0x56E01A714C3F1B10ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 100\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x606DC4D77BA04F0FULL,
		0x8A32D4A3BFD63F9EULL,
		0x5EB99710CB36CEFCULL,
		0x0DBC56E9F631605EULL,
		0x2336199863C45108ULL,
		0xB352E38D6AF82043ULL,
		0x0621203865F4E9A7ULL,
		0x009F3E6A6A67E036ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0080000000000000ULL
	}};
	printf("Test Case 101\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xEE435E81D05EC0ACULL,
		0x4AF43C98C3559C24ULL,
		0xD6978C4212D7F86DULL,
		0xC1ECA0D8DC1CF443ULL,
		0xDE03F7A4342F9ED1ULL,
		0xB88267312BB5C683ULL,
		0xAF4DE35966BFE541ULL,
		0x0EF5D52B9916E904ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0800000000000000ULL
	}};
	printf("Test Case 102\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x11051C7922AE3916ULL,
		0xD1026DC539BE4D34ULL,
		0x36438E22ACD4D9CEULL,
		0x3FC4FCDE37313192ULL,
		0x7EC6EEAA76E0E32CULL,
		0xD0943062C4D4FD49ULL,
		0x7EA3F5CD038FFC08ULL,
		0xB7D50153A3F15D02ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 103\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x7986C90C8117B0BDULL,
		0x367B0D440519EC62ULL,
		0xE6A4E2CB7ADC7568ULL,
		0x115F3875A873C072ULL,
		0xA05FB33615DA7583ULL,
		0xD5A746068EF0AD19ULL,
		0x7BA6B53CD3136381ULL,
		0xD6D52B8EE4A8D3FEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 104\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x7991236865DB9F37ULL,
		0x5A0DD76FB7000CC4ULL,
		0x24CFD3B8974A7119ULL,
		0x0560B8F38B331644ULL,
		0x4135AAE27AC7C3A7ULL,
		0x441940BF0C9F41EFULL,
		0xCE503B8DC363DB68ULL,
		0x123B9F820C043AAEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	printf("Test Case 105\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xAA03FD920451D365ULL,
		0xE5384E10D2E5D541ULL,
		0x5BA64D26AA173773ULL,
		0xAD3C9553E554598EULL,
		0xBA3646DA10E30FE6ULL,
		0xD44A4ED4EFEC7093ULL,
		0xF0E0807DCAE37A13ULL,
		0x92D251097A0C821BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 106\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xC09A8C87BD710CBCULL,
		0xE56CAB7676F29574ULL,
		0x5B0D7D1A260FBF64ULL,
		0x7CCF47407F826E90ULL,
		0x163CA018BAD890A7ULL,
		0x4A2A36F760DE6EBFULL,
		0x50EA175731B56379ULL,
		0xE032AED2D547777AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 107\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xB45B4C1119B67552ULL,
		0xDE6DFC9CE18632A4ULL,
		0x7433AB0A67CA25A6ULL,
		0x159C138133FB45DDULL,
		0x74CE39580F668B34ULL,
		0x9713A946A168EB00ULL,
		0x7659E9C5F85AF436ULL,
		0x2DA4F4C0CA64089EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 108\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x94D55F040602499BULL,
		0xEE8ABF45C1DF3D1BULL,
		0x8FC058CBFDB3AD9BULL,
		0x7865F3004DA76AABULL,
		0x3D8EAACEAAF26CE8ULL,
		0x9E90B56E16669FD0ULL,
		0x6EC6C65CD0181E43ULL,
		0xB3E63F79C26C8B2EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 109\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x809C80521299C73CULL,
		0xC1819B5B548917B5ULL,
		0x43DDEBEF393B67D8ULL,
		0xAD648566A7AADCDDULL,
		0x63F34F79E2A76823ULL,
		0x3385A1F88EECFD6FULL,
		0x20C681009BDD597FULL,
		0x365675222EB091E1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 110\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x30BC9A53BCEC5924ULL,
		0xECFC493AAF7FE703ULL,
		0x55310D339FB9EB92ULL,
		0x9164D8BC0B563A80ULL,
		0x056DFBE9C64C53A1ULL,
		0xD5A34D1B2DC77C5BULL,
		0x59AD3F968442C93FULL,
		0x20A915A37F8ECEC8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 111\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x1147C6631EDB067CULL,
		0xCDD2604559DA3881ULL,
		0xAE7435555F66C54BULL,
		0xAD50198DE44D72FBULL,
		0xF2A52D686EE7F620ULL,
		0x1BE86D8BC551D695ULL,
		0x4BCA8B6829BE4C76ULL,
		0xE895978977952BBFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 112\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x1B9DCDB8732A5E55ULL,
		0xE32515CD648B6354ULL,
		0xEC1CB389C896C27AULL,
		0x104C42DEF7BFD6A0ULL,
		0xA9F0D859270AB00FULL,
		0x6640A58B7B27323CULL,
		0xB2E0C16A2640D3A4ULL,
		0x93FD867BE926F186ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 113\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xAD7FD68962FADE41ULL,
		0x33C42E7D6FE69879ULL,
		0x7EC9164349D9A79AULL,
		0x573806132DBE80A0ULL,
		0x1B5F1DF9BE8B83B0ULL,
		0xC6E6FDF63064CF00ULL,
		0x06DE5951140CCCB9ULL,
		0x466D56D0665A6615ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 114\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x873631F3E9FFC64DULL,
		0xC6C82BCDE62EB478ULL,
		0x1294F214641D46A1ULL,
		0x3B048A0802A63653ULL,
		0xBA7A95B7C6B70F7DULL,
		0x31772D825B64725CULL,
		0xDE95FAE92C27AAC6ULL,
		0xD1D0C1974756A759ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 115\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x1F85ADB55C9EA28DULL,
		0x59F42898C4FFD13AULL,
		0x65475F6BAAC4C242ULL,
		0x64DAB3E42A3295B6ULL,
		0xEAF059426C2B1437ULL,
		0xB815955DB59811A0ULL,
		0x8486F3897431E7C5ULL,
		0x5F6E4A044632D04CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 116\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x6525B7FD2B1DDDBAULL,
		0xB379D73C456FECCAULL,
		0x721774493643E385ULL,
		0x9189B66857E42465ULL,
		0x12B136556363CE22ULL,
		0x5B2DCDDCE2811834ULL,
		0xB5949294481EF35FULL,
		0x495C4BA6A9F688D6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 117\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xE7B6594E208F393BULL,
		0x961E74144B855621ULL,
		0x614B4DAFFB49247DULL,
		0xD70635ED064B32D6ULL,
		0xEDBAC0BB0D013A52ULL,
		0x79E2B02B7D1FB10EULL,
		0xCC8DE99C767B626FULL,
		0xE6AA48AEB1D3E84BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 118\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xC199AB5C8C69E6E0ULL,
		0x7ECE3481B5E2AAF2ULL,
		0xDF0E47CD3B84F8DAULL,
		0x7294718C4FF72AAAULL,
		0xA0BFA23A1CBF5714ULL,
		0x9EAC5B9092722D3EULL,
		0xC0611C673EF3B088ULL,
		0xA7ED0979494D5D4CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 119\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x81F60FEB4B3FFFDFULL,
		0x373CD985CBB5E174ULL,
		0xB24CE6A7F0D2EC1CULL,
		0x2024BDB9CA97C71CULL,
		0x9C2C01791264A6CEULL,
		0x39A357F587854D65ULL,
		0x758A03287D3FE071ULL,
		0x81A8137AD104A3D0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 120\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x3E3A173253FF90CFULL,
		0x847E0D0FB6CAFAA2ULL,
		0xA4A4976C3DBF43EEULL,
		0xBC83D40127B95818ULL,
		0xDA3F64B997AE35B6ULL,
		0x233E406A0AAD890EULL,
		0x539EF1AEB1597CAEULL,
		0xA6962E3E49259533ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 121\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xB24AD564D7402976ULL,
		0xB9235CB53320A1CCULL,
		0xF968E8427FF1A59DULL,
		0xF45ED5E9264695ABULL,
		0xD952E801BC622A2DULL,
		0xE4C132D5C1128314ULL,
		0x7985F9284C131CC7ULL,
		0x8C56C3D8D3062434ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 122\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xA4EC458493ED2F1DULL,
		0xB86FBE3A5C5EC48FULL,
		0x725233594A2EC22BULL,
		0x52E9F191F8FEDD72ULL,
		0x4BAA1CF81068BB31ULL,
		0x576FB62933B5F920ULL,
		0x96AEB5B601C4E8FDULL,
		0xFF2C087C924A17D1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 123\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x5909C0058996847FULL,
		0x73DB9431C245B5D5ULL,
		0x90C8D9F09A0FE3E9ULL,
		0xDCE9E67C07E6A75FULL,
		0xCC54FEB87BD5A35DULL,
		0xA7D1CD348C15D575ULL,
		0x80B0F2102A35F11FULL,
		0xE8F1610EBF6B7D0DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 124\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x03FDA3AD3BEFAF4EULL,
		0x2BED9283EF88F3FBULL,
		0xB62DA2D3EA671A82ULL,
		0x773A38FC7FFBDC49ULL,
		0xB6B4D6DD303ADFCEULL,
		0x228A40C1049BED0BULL,
		0x062848C3BB81F6ABULL,
		0x7B6495098B5A15AFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 125\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xDF4C102BB2EBDA22ULL,
		0x54674F374B779B6BULL,
		0x7789FF9504915926ULL,
		0x86EA9E0B7D42B63AULL,
		0x61096631C7D71B06ULL,
		0xCB647C3287B70AB1ULL,
		0x2866DBF040DCAC7AULL,
		0x19C532D9A5BA8563ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	printf("Test Case 126\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x429346987EBD0FAAULL,
		0xAD1B9B43133662B9ULL,
		0x599051AA920A5CC8ULL,
		0x3D070A14DE0C5C4DULL,
		0x73B797F4E6B35325ULL,
		0x3D95C552ACD8D28EULL,
		0x349AA3543968BDC4ULL,
		0xDF5E69353B50985EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 127\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x7CA3E253EB41E8FDULL,
		0xC231AB3BC4AF8E41ULL,
		0xC55FBD1116AE9D36ULL,
		0x2C163FB8454D8C0DULL,
		0x0D98B800B785E61FULL,
		0x1F61F50E1E067B39ULL,
		0x3C1912F9DEBC9957ULL,
		0xBE04C355B03424D2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 128\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x1C67438D61F22255ULL,
		0xAB0A45EC5AFC7967ULL,
		0x9675CBB4AA0F64B3ULL,
		0x5FAD8131AA5D3B8EULL,
		0x2952B357D425C52CULL,
		0x6C53C413FE23EA61ULL,
		0x2A09F06D16736E72ULL,
		0x4B4D6B6C9E7ECEE2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 129\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x1B916AEB0F02577AULL,
		0x7E8C56AFE63A6E56ULL,
		0x680F38C2B12B8D0CULL,
		0xE5F42706E2BB6D38ULL,
		0x29A370C4DE98CD1DULL,
		0xF16ED26BD9D302EAULL,
		0xE1C27F4B8BB08D1EULL,
		0x2B58A0ACEBE2B23BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 130\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x9D44B89C6ED8D411ULL,
		0xB3B753BC64E4B46CULL,
		0x20769B038553F818ULL,
		0xEACCB08CD81B6838ULL,
		0x011B606D5C233484ULL,
		0x9156F46EE4F413DFULL,
		0xC94824BC05B18978ULL,
		0x567A8A4EDB60EA80ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 131\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x9DF504510105C5B1ULL,
		0xB02DDCD6F75C965DULL,
		0x94E6DB404150DF4DULL,
		0x046DCC5199587CB8ULL,
		0xB25CFEC42019BB6EULL,
		0xE88BBB19716FF6E4ULL,
		0x0D706AED39421E3FULL,
		0x5C57155889F9F3A7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 132\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x7E04E6BF2C5D2F23ULL,
		0x323AE814BD74778CULL,
		0x8EA916BFE2E9E02EULL,
		0x9F2B209BF4A29B9FULL,
		0x1A22AEAADD4B13D5ULL,
		0x24E91A84FD29A04FULL,
		0x4C12CABDE237DC15ULL,
		0x450141040A89B035ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 133\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xD5D0071F06405D27ULL,
		0x16E353DAE2A3346DULL,
		0x683BA2689AF68041ULL,
		0x2A90FA1B4C7224EDULL,
		0xEC5BAFA03631FCE8ULL,
		0xB692D8369A628F12ULL,
		0xB4D5A039103165CBULL,
		0xE20CCBF2E2228EBBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 134\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x208D99555EE4AEF7ULL,
		0x223BD1CF1743C7EFULL,
		0x2784CFCB3D8F094DULL,
		0x813FBCA4CF8B6D87ULL,
		0x83584A01C988F1FAULL,
		0x16617AEF7B2F5DDCULL,
		0xE37649672EC43B4FULL,
		0x41E75FBDCDFA025EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 135\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x576C5A8DADC1BA50ULL,
		0x05C58DF43E02565CULL,
		0xA73656FE3A29683BULL,
		0x37CCF985CFB8459DULL,
		0x915832F3AE64E320ULL,
		0xDDF4B4797D7E15FFULL,
		0x5C7907E3BAE6F689ULL,
		0x9B1CD98954D78F87ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 136\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xBC3E8B27897BD2D1ULL,
		0x6FCE7042A3535268ULL,
		0xDF44EE2F99D85550ULL,
		0x433851AFE1FB851FULL,
		0x9F0F5BB2045570EFULL,
		0x1ABF3FBD6E21743BULL,
		0xE6CCDA086C71B4E3ULL,
		0xE2F2DD038663412FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 137\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x55E83B6E4BE2E095ULL,
		0x915679ECEC43B1E0ULL,
		0x29B65AA042D2F76EULL,
		0x9CD28D2F84412B50ULL,
		0xF59BA5A6DDDBC995ULL,
		0xB9318E68A0DE0C0EULL,
		0xC9AD011704C31879ULL,
		0xF863C6A9EB6E089CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 138\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x8FC44A93EEF9A6C6ULL,
		0x3F100805F3B6C6B6ULL,
		0xD805E72D1E033994ULL,
		0x2611281BE61C0458ULL,
		0xA4F2F02FE6D63014ULL,
		0x78B28FA03FDF3978ULL,
		0x235345367A6DE381ULL,
		0xEE2892F261D807B1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 139\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x8C692496918A6704ULL,
		0x0DD6A7B5D90B3A0CULL,
		0x1909559D1DDA1818ULL,
		0x8C4D03AD8D4FE777ULL,
		0x0819AB5271105690ULL,
		0xE1695E44CB724BC8ULL,
		0x2B57D51E20B25FCEULL,
		0x8AB83D370AB0E221ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 140\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x801E4632F1C33B51ULL,
		0x58CF1913183BD9BDULL,
		0x8201765663841EA7ULL,
		0x8856327B303229D1ULL,
		0xEE3A7ABEE42897D6ULL,
		0x962F88F5D6C8702FULL,
		0xDCF9D96609C498E4ULL,
		0xD09AD226EFA23F14ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 141\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x65D40FDB8589DA45ULL,
		0x15E067A16EF3FD95ULL,
		0xA1EFC9F7075E51F5ULL,
		0x0E4E140DB1BAA78EULL,
		0x2E18EDE6D6D8A5BDULL,
		0x8B07DAC3F39AEEF1ULL,
		0xF89385E3A16A5F4EULL,
		0xFE34B04034679555ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 142\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x351C6F4342ECCAFBULL,
		0x6DE3417EA8C57208ULL,
		0x0C3680626DD0BF98ULL,
		0x0AC8BCF1BD6FD6E4ULL,
		0x2E2E5480CA77AC2DULL,
		0x79BAE1E0BB28AD2EULL,
		0x497087DF58997AC6ULL,
		0x3A269607AEF8822DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 143\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xEDF783828655D1B5ULL,
		0x67C8A2A4B0D51935ULL,
		0x828418749824A783ULL,
		0xACBF2162547E4806ULL,
		0xD4CB24892F4128CFULL,
		0x3C30B926E2CCC254ULL,
		0xDC2D83CB220A872BULL,
		0xC7BC4B65A24F9F6CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 144\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x369C09980437E93FULL,
		0x05243D952A99CEF3ULL,
		0xBAA57218E5F30FDFULL,
		0x1942FA3A5091E432ULL,
		0x02FF2335ABAAB81FULL,
		0x2BA885F34B9D01F2ULL,
		0xCAE4721790CFFE33ULL,
		0x39396FAA5D1D65ABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 145\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x121479F0081897B1ULL,
		0x45CB1631B6F5D23BULL,
		0xBA09E1B0ABD23D3DULL,
		0xB9954F7DBC1B9A6BULL,
		0xF5977CCF22BDE1DDULL,
		0xBC4BBBB9D8720161ULL,
		0xDD0C5429A3B08249ULL,
		0xF5C3AC09FBD8146BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 146\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x5B0606737D94A797ULL,
		0x083F2D11AB9D79A0ULL,
		0x3BD44F3CCAFC1102ULL,
		0x2AD98F1499122564ULL,
		0x73F55A2EE01627E5ULL,
		0x60DC51A00178E1CEULL,
		0x7CD769BA23626E13ULL,
		0xF7F8D9AB25BEF80CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 147\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x97E548D8B6E1B010ULL,
		0x225480992E850056ULL,
		0x669AD90286E197C7ULL,
		0x3F854A7E7F680E3DULL,
		0xE66CA647CE7D906FULL,
		0x992EF34D401F4C14ULL,
		0x93539DC4A2A38BA8ULL,
		0x06AE3068C8D9AE64ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0400000000000000ULL
	}};
	printf("Test Case 148\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x1C0B35BACD310673ULL,
		0x2B9662E0EABA7082ULL,
		0x82E42094EE55136FULL,
		0xB4A3768AD761430FULL,
		0xEC6DEA5DDA5BCF77ULL,
		0x43DBD9E3B7CB03D5ULL,
		0x224C37E2DD12A002ULL,
		0x3EF7218C93B56A01ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 149\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x795D2950B3050B45ULL,
		0xC6B58EFABE907822ULL,
		0x15A1A097B7ABD343ULL,
		0x2CCC8552596CFDECULL,
		0x0F1C53E803517B77ULL,
		0x5831562BCAD3463BULL,
		0xCEC6EC0DF436375FULL,
		0x9A730EC9C71DA90EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 150\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xFFD5AFFC6FB933C3ULL,
		0xB30491871B71BC4AULL,
		0x16C877B31AA948AFULL,
		0x113DC5E5C6DD8263ULL,
		0xCDDCF8FF1D360613ULL,
		0xFA919D5B1755D805ULL,
		0x11AFE47522A389DDULL,
		0x9019AF7611EE82BFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 151\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x1F6E129E9265574DULL,
		0x85DB4BBDC5FCD60BULL,
		0x2477078AB4BD66FCULL,
		0x1B4339E57DD6A5A3ULL,
		0x13EA50C9F56F3DC4ULL,
		0xC9CCAC8A491B17D9ULL,
		0x0309C595253A46AEULL,
		0x94FC9780BBD67E93ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 152\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xBD0D3CC4934A498CULL,
		0xED0C05CDA9B8E299ULL,
		0x643522381F86B63BULL,
		0x763F245B2BA15187ULL,
		0x9C0A1F1162690DA1ULL,
		0x8F9E221BB2168FB4ULL,
		0xB50864CCC7E92853ULL,
		0x026C0F1831C44E98ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0200000000000000ULL
	}};
	printf("Test Case 153\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x129ED410A60D61FEULL,
		0x85E7A44C2B84462FULL,
		0xF43BC3F4CA3F421BULL,
		0xAA379E8B0C5CF5F3ULL,
		0x835B02B9C0118346ULL,
		0x13C2CF03088C32FBULL,
		0xA6482AC060F7D386ULL,
		0xCABA8250834EB1B5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 154\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x63662916DC25FDA1ULL,
		0x30FF63A7A6613033ULL,
		0x55531CB34CF60FDCULL,
		0xB306C05915EBBEFAULL,
		0x7B8514DF861C3B2EULL,
		0x26B59F1C4BE55E72ULL,
		0x63C698C59266F1B4ULL,
		0x5AF0CF9EC26FE6CAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 155\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xB3839294B274389FULL,
		0x2B90F6C084F39704ULL,
		0x293491AA997CB597ULL,
		0xE92BBD955C44BC4DULL,
		0x2058E3F57F9B7B56ULL,
		0x4663A53F15B79AB8ULL,
		0xD3366A063C4B3F83ULL,
		0x1FA9AC729797AD5FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	printf("Test Case 156\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xE21AE7E3C0B8B378ULL,
		0x3D23519FD6CFD677ULL,
		0xA5FE6CAD42935057ULL,
		0xFC89968EC0E16328ULL,
		0x84523FCFE3EB4676ULL,
		0x44F46C35DF583F35ULL,
		0x622C54B077A07735ULL,
		0xE5E1CBE5B276AA91ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 157\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x95D9AFA0F34DFD04ULL,
		0x7B6C6C6F3B8FCF74ULL,
		0x99662F7B5AA997D2ULL,
		0xBC28FF146188FDE0ULL,
		0xC02AD40BD664ED06ULL,
		0x0B9FB362BAAF363BULL,
		0x1DB2EA8D5A3B7983ULL,
		0x41BCF807E0B63EC6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 158\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x23891291C8BE21EDULL,
		0x03715DB3C05A3039ULL,
		0xA14E5A9A2D856744ULL,
		0xFFBC6DA710B5DB60ULL,
		0x9B78418A33FF5FF7ULL,
		0x9255D1369BB3E641ULL,
		0x921B381B8E6FCAFDULL,
		0xD003F5514170C2CDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 159\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x1E538FB9054660A1ULL,
		0xAEEACD4467806A0CULL,
		0x77DBE242427D0388ULL,
		0xD407CAEFE228AA19ULL,
		0x73D9F04046CB7A1BULL,
		0x273574C3922EBDC8ULL,
		0x148CAD63D46FA31CULL,
		0xB3F474C25DE4C4DFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 160\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xF1FCD429CF718484ULL,
		0x6DC993B9AEEF1EFCULL,
		0x6F580A0C5A11BC73ULL,
		0x205844719B48957AULL,
		0x5D3F19C7204DC6F9ULL,
		0x45620CD0F79A64F6ULL,
		0xF356C87F0188101CULL,
		0xF87071ED8CF1DEC4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 161\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xB915D2EA35D64065ULL,
		0x2AE1020938770A18ULL,
		0x745B1607CE67181EULL,
		0x8E3877ED62400AC9ULL,
		0xC4AB8B6B7C1E0963ULL,
		0xA90309BF37E6E51FULL,
		0x39E23B0A9511029FULL,
		0xAC84DFAC5FDD94EAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 162\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xEA45E0281921B0F2ULL,
		0x38CE8139B088C842ULL,
		0xA29818591BB2EF7CULL,
		0x043A4A69170C01ACULL,
		0x025F917893DD0B4CULL,
		0x63077869B743B412ULL,
		0xC81475C07F08AA9AULL,
		0x95F7FAE814FD2D33ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 163\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x705F12B728416501ULL,
		0xD8E2A571F627C384ULL,
		0xC92F1C9FB5FA5C9CULL,
		0xF9A10C6817ECE4B5ULL,
		0x838214014652409AULL,
		0x84F3867A604B8A82ULL,
		0x7AE20DCBF202384BULL,
		0x36CFD8AD3102A8C6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 164\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xBCEECBE0C3548095ULL,
		0xC43C60EAF593B1A6ULL,
		0x933A926D28E38383ULL,
		0x3DACC8D719F7A8A3ULL,
		0x9C168136B302DD38ULL,
		0x92F49FCC2FF5F5E2ULL,
		0xCB3B9858DBE8188FULL,
		0xA27BD5E03A4B1F39ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 165\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x0DE8AB8467735FDCULL,
		0x3125867134B2AA57ULL,
		0x89918177E058AA7DULL,
		0x31C927ECCA527AFCULL,
		0xAD2B54097E1AB0DDULL,
		0x468E2D7395E6D297ULL,
		0x57E37BA2B4D6E7F6ULL,
		0x51B39BDA86167DC4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 166\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x00FC02250FBE44C5ULL,
		0xF50DCC5A3C34E8E0ULL,
		0xB0797FC64149D476ULL,
		0x6D0B32E721A221F8ULL,
		0xEB0C73F07B05F48EULL,
		0x5A2968CD6DCAEE4DULL,
		0xCFFC542800F63E58ULL,
		0x9115DDF112934632ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 167\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x9303F08C289EC4E3ULL,
		0xDF0301EC95A581B4ULL,
		0x88B6822FAC11F1AEULL,
		0x8393546B0AFAAD2FULL,
		0xDAD572E5E1F72F8FULL,
		0xC3549AA9C562DE54ULL,
		0x1E8BEBCD2A9B1937ULL,
		0x5A0D0EAC0B1B382AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 168\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xA560329B77C38965ULL,
		0xE659721D78781E2FULL,
		0x4F461078C4C981DDULL,
		0x557BAD6B67CC90DFULL,
		0xB0FF287009219FF9ULL,
		0xB2921D74C107A7C1ULL,
		0x73DE04DD2AA84FC9ULL,
		0x1059FF28E17FE753ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	printf("Test Case 169\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x38BD2EDD46678F0BULL,
		0x9A6E8F3FF3A52E23ULL,
		0xC2BEF1412DCA6C40ULL,
		0x744BAB55B7166C77ULL,
		0xD2DB67520EEED5C0ULL,
		0x00F370CF636CDBD9ULL,
		0x3031E9F54F85CAF5ULL,
		0x2F5A70F6385F5411ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 170\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xB9F446CBD95A6542ULL,
		0xF8A96BF985A267DEULL,
		0xFE9F1DDD15584C06ULL,
		0x71BFDD28D06FDCE9ULL,
		0xA381836F37B415D6ULL,
		0xA29B67DD91AFF4D3ULL,
		0x1E27668FFFD459B6ULL,
		0xC014108B7646D0FFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 171\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xF0F2821898CE8E5EULL,
		0x2FA9D63E8FAF52F2ULL,
		0xD91BA94AC60791D4ULL,
		0x0072C7AE66F249A9ULL,
		0x7E2F54CB250A89B8ULL,
		0x9364FF430B29368BULL,
		0xA5A6ED72FE222E5CULL,
		0x8E6C6F0DB30E2464ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 172\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x32DB48366202D494ULL,
		0x85505CE87C8291B0ULL,
		0x7A508C4AAAE02031ULL,
		0x06ACCC3C1D6C2FABULL,
		0xCBC90CB353B681FFULL,
		0xDB9E84CCB2AEB5E3ULL,
		0x9AC9448FF439DDDCULL,
		0x967EC1DEACE00E2AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 173\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x8B3C3C812B30836AULL,
		0xDB48DDB5FCB4629CULL,
		0x1FC6E26F5FE9F442ULL,
		0xBD22ECDA0F20E6CAULL,
		0xD4E5B6A82300D7DFULL,
		0x17D44BA386EFC967ULL,
		0xB4CC31A93C8EB7C8ULL,
		0x0838C1D041F26ED9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0800000000000000ULL
	}};
	printf("Test Case 174\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xAE4AA1DAD76DEFB0ULL,
		0xD8513E54F51DA27AULL,
		0x67E0FE0F5CA9AC25ULL,
		0xDC3DF5E449CD284AULL,
		0xDBDA7D47DB4AF053ULL,
		0x3B88A010051C98EBULL,
		0xE1B855EE40B15ED3ULL,
		0xA673152C4308F624ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 175\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xBD6097B7A5E987C4ULL,
		0x2DFCE335F5210B21ULL,
		0xC5AF46D7536F2C42ULL,
		0xFA21D1724DE29670ULL,
		0xC6B90DA7EB5AB3BFULL,
		0x2A6196C3173E5CECULL,
		0x16BD859BF30E6ED6ULL,
		0x71417BFD5F38DE67ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 176\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x1EF5A8910E1124FCULL,
		0xCF8C82349791B3F5ULL,
		0xABAA5BAAF027DF96ULL,
		0x2285068012CE2F3DULL,
		0x19FF3C4C05CFCDECULL,
		0x95B92378D68BA7D7ULL,
		0x532DA5EAC68C64F2ULL,
		0x705A3BF2C0A8A09AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 177\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x3CC86ED369AC319FULL,
		0x90580444B25FA0A2ULL,
		0xCCD9535DAC64842FULL,
		0xA033157EB0876A67ULL,
		0xBA75801D8427D2DDULL,
		0x1412EE074CF6DDB2ULL,
		0x39C4C2C2D35E0B0EULL,
		0x86165D7DAB5E5064ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 178\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x2DDBED1E5BEFE74EULL,
		0x737AFAA975B4AA13ULL,
		0xCC1A819F5B1F0E33ULL,
		0xDB4CAF024C67FF23ULL,
		0x95D1F220CC86D161ULL,
		0x35247A89BEDA8BCCULL,
		0x27BC86F6726F058DULL,
		0x9191E1C11F112270ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 179\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xA91F4DBCEE265A0CULL,
		0x9FF0735FBA9E1C49ULL,
		0x9F06C7147E12FCD8ULL,
		0x8253D091D3507A12ULL,
		0xAE94D10ACC10FC8FULL,
		0xFEF7D8ECA3A65D01ULL,
		0x051D1C9E03699CB5ULL,
		0x09795CCE707353CCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0800000000000000ULL
	}};
	printf("Test Case 180\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x3EC788A4217844D3ULL,
		0xF5568FA7F2E0436BULL,
		0xDD73ED416E8A887EULL,
		0xBB558234D4D7AA63ULL,
		0x341DBD15F34D043BULL,
		0x3BB24F6088ED2256ULL,
		0x6C5A330F1A1916DFULL,
		0xE9B2792962A7A501ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 181\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xFB6829590E6B544FULL,
		0x5D67B2EBE03F6D38ULL,
		0xB6CD38714176292FULL,
		0xF523D1F3758A91E6ULL,
		0xD5E877502E63E4DFULL,
		0x0C999AA417856F29ULL,
		0x3B50F1D1E2BAA3B6ULL,
		0x1A1E304F099CC5DCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	printf("Test Case 182\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x52E6219C6BB7373DULL,
		0xF5165CDC5E8E07A7ULL,
		0x8B5EBD630E92C404ULL,
		0xEC3C7FAFFB95C108ULL,
		0x00F1EDA37A580C6BULL,
		0x163942E2860BCA22ULL,
		0x4E72D76AB166173FULL,
		0x4ED27B0758263A1CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 183\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x9689F88D145AE7AAULL,
		0xC2E9E8F003F4D0ADULL,
		0x0390EFA5D94661F2ULL,
		0xA0921B2C9235EB9CULL,
		0x4B526AE5E9390AE5ULL,
		0xC63B0AF541A985E1ULL,
		0x755C8B6AE1C86241ULL,
		0x3FCCD1FC02D96CFEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 184\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x63F109F0CF3495CEULL,
		0x9984FB98776F959AULL,
		0xC68901AB29191CA0ULL,
		0x4CEF271B9A7787C2ULL,
		0x4BCB9CFE982B196CULL,
		0x83F8B19ED2C5E22AULL,
		0xE064F8AFBD57EDEFULL,
		0xD348326867CEE274ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 185\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xE056F8519ECFB725ULL,
		0x69023BFA975B021EULL,
		0x61AE20E2EBBF2126ULL,
		0x8ABEF50A5A9D6122ULL,
		0x1E42434D0502FCACULL,
		0x1BD470E3C06B96A3ULL,
		0x5089F55B20222C86ULL,
		0x3BDF6CBE2CBD97DFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 186\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x66BC1C7A3AC1C132ULL,
		0xF207166ACE653A09ULL,
		0x93C02E1A7B80C67BULL,
		0x2AC2ADC17CEF8588ULL,
		0x2BADA8D25CE66A40ULL,
		0x2A4F0E01BBCAC866ULL,
		0x4DA45088BBCE883AULL,
		0x0763C31CED29C140ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0400000000000000ULL
	}};
	printf("Test Case 187\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xB7B1F1A1B3EF2ED3ULL,
		0x63FBECEC1F36F6CEULL,
		0xFDE6192A9C5F100FULL,
		0x0156475D60F3360AULL,
		0xF381B2787E169671ULL,
		0xA360EDE483FFB7EEULL,
		0x001676AF4F4A26F2ULL,
		0x62A287C86AA63AEEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 188\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x0644E03EB533CB95ULL,
		0xF8BDC6198F154A70ULL,
		0x27F4AEDB91D72102ULL,
		0xE07B7600EC92995DULL,
		0xC9CA6685CCB00045ULL,
		0x91082623D8F3A84DULL,
		0x050F918271A1804EULL,
		0x3F7EFC765FB1CD3DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 189\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xBD70E4384C6296DCULL,
		0x3BBE2613E705DF1BULL,
		0xF15AA6D57E0CBE2CULL,
		0x73397178BFB59ABBULL,
		0x84D1EB9D6ED4BC84ULL,
		0xEC21DAD2B2244F4CULL,
		0x94580E57D29BFD20ULL,
		0xCF19AD39B7D4FD5FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 190\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xE0640A432493F2F2ULL,
		0xC2AE33B3A55EEB5FULL,
		0x57323E7F8A210F2FULL,
		0x34E2BE61472D878FULL,
		0xC7A6DD6862936F3DULL,
		0x7AF08DD38F6D7EC6ULL,
		0xFC2E49845E896FB3ULL,
		0xABFE1C81E915BD85ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 191\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xE5B4052FB8C25712ULL,
		0xA824F8D91BAF1FC8ULL,
		0x9FC47FB3E4C5A80AULL,
		0xA804636A5DF0DEC4ULL,
		0x7EAFB17C0D0A5BE0ULL,
		0x45F9263EA3D6BD30ULL,
		0xF0BB1EDC4292FB63ULL,
		0xDF5F9170334EA0D1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 192\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x37FF60ABF156957DULL,
		0x0FC2BA467558CE74ULL,
		0x6493EC2853083157ULL,
		0x1D7796882D883696ULL,
		0xA48A3C3D5C660D77ULL,
		0x492B5917EB739A34ULL,
		0xFE0B5F82842E763FULL,
		0x5B7FC29D7F3BD8B8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 193\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xAC4BCAB30A7111EBULL,
		0x84FF568A0ADFC197ULL,
		0xA76673BEA85D90DFULL,
		0x50A1272909F50492ULL,
		0xA7D0C1B71914BB46ULL,
		0xE58AF53FC60D069EULL,
		0x0D3DA9CFB4454FEDULL,
		0xF38C7F4476FDDEFFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 194\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xD3317949E1EC32D1ULL,
		0x01DE751E7F1DE30CULL,
		0x2BE5758428894C4DULL,
		0x6574C19038062ADCULL,
		0x981CF6B2B805D92DULL,
		0x9D5B56FF6A3AB0B5ULL,
		0xD6F0DD0C68E340C6ULL,
		0xD22030FAC870C25CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 195\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xBE4112DA26FC3754ULL,
		0x27DEE29B80430CB7ULL,
		0x1ECC6A45D47B74F4ULL,
		0x92B756D0DF382FAAULL,
		0x934CB4E6B80A206DULL,
		0xED1321647C438D2FULL,
		0xE088C5A5B7B0651BULL,
		0x18D6FD4F1DEBB7BFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	printf("Test Case 196\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xB1864ED10274DA3AULL,
		0xE9C78B1D3E8D2D31ULL,
		0x7A95C9A9A8975311ULL,
		0x34F7A3123C7F0309ULL,
		0xB07C7BBA4F740B60ULL,
		0x2DCECF485472C83EULL,
		0xACB8DB3BD72523AFULL,
		0x925EB3D99D4AD943ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 197\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x2DDA0EB4D2E041B7ULL,
		0x1C937ACA1DBE6DE2ULL,
		0x74855397AC090A40ULL,
		0x1AB66DC32527E827ULL,
		0x5C75311A50A6488BULL,
		0x0AF59F256E7F4FCFULL,
		0x8F920E2EEE6F1DEDULL,
		0x12CF1278EE01415AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	printf("Test Case 198\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xAAA7D35E5659BBB4ULL,
		0x99576C1D7B7C8E2FULL,
		0x9037E1C59B04705EULL,
		0x36C6E6C352444F1FULL,
		0xFF9AA2D89EBD1934ULL,
		0x23EDDD5E5EB109C2ULL,
		0x4D7EC597F938212BULL,
		0x515C8C0823D24D02ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 199\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x456801BE5CEDB626ULL,
		0x1C178A61AFEEF9E4ULL,
		0x75E70B653C8EB30AULL,
		0x9C443664CAFAD9BEULL,
		0xA859E0521C8398EDULL,
		0x8883CA7330226020ULL,
		0x8A82D3ACBF2939C2ULL,
		0x185F40119ADA2B18ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	printf("Test Case 200\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xE51F06F5FFCFFC54ULL,
		0xB51936C7AB89C0B3ULL,
		0x26513D68139035B0ULL,
		0x8A0EE82A55CCF820ULL,
		0x0B4800DB3427EA83ULL,
		0xA50293140FA668A7ULL,
		0xE4117B5EFF070E88ULL,
		0x929DA0FA36147211ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 201\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x2155986FEF909919ULL,
		0x95B8378E6CEEDEFAULL,
		0x66760620B390F516ULL,
		0xBED7C3B0582DBE6AULL,
		0xAA1F6D99E8975808ULL,
		0x22BE8FF784E22B2DULL,
		0x168207B7BEBAD394ULL,
		0x4EF3201D590C79F5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 202\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x4A1EEC8686142D36ULL,
		0x5926B0E1B5638BDCULL,
		0x580D8BD8B6646E5CULL,
		0xEFB882D78E6542AFULL,
		0x5E2358B9B69588B3ULL,
		0x28592BDAAC7C326BULL,
		0xA2341076CA6F1315ULL,
		0x79BC1F20560D6DA4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 203\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x3CAA231AF5331E69ULL,
		0xBCD522ECB251AE8FULL,
		0xD2BEE5D32A25927CULL,
		0xFE964FBFBDFADC15ULL,
		0xDBBF8C3F4C3A231DULL,
		0x2AA852A832EA95BDULL,
		0x36767B0478932446ULL,
		0xDF25880699E3649DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 204\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x76E63727EA64AD6EULL,
		0x4FC799D2683298A6ULL,
		0x8EE5DD8570474E4BULL,
		0x15D20BBECCA21536ULL,
		0xB917BA763465E9CBULL,
		0xA02A2A32C51BA877ULL,
		0x16E446C46A81558CULL,
		0xAD863865A3F611C9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 205\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x951E88315283B2EBULL,
		0x62C05FC911CB7B89ULL,
		0xF4C854D9C6ACD005ULL,
		0x882C77D71D9DDD6CULL,
		0xC2F0EE5B1C04171AULL,
		0x277DA246145BC29EULL,
		0x96EDE1FC52B30919ULL,
		0xD8568BB0A37C8E45ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 206\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x2F9960CAE28BE176ULL,
		0xA7144538BD571BE4ULL,
		0xD9ABF6C0FE440244ULL,
		0x4C07C1ED41FA124FULL,
		0xA38A2390B872B871ULL,
		0x3F87D8076DFAC295ULL,
		0x78451A8FBF24F521ULL,
		0x01DD4D006776F757ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0100000000000000ULL
	}};
	printf("Test Case 207\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x111BEF68C3D10DD5ULL,
		0x51CB13FB9E2916CDULL,
		0x4812DCB213DF798BULL,
		0xA55CC44E0D6A50FCULL,
		0xA079507865C8F0F2ULL,
		0xCE97019EC3CBBA52ULL,
		0x17019C5B89FDCEA9ULL,
		0xE937663105D17D36ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 208\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x2FC0A41CF888ED12ULL,
		0x6742B92AA8BF8113ULL,
		0xFFE55A22E038B9B5ULL,
		0xA31A3954AF0AB448ULL,
		0x105FD482F8219187ULL,
		0x156F8EB44D66BA64ULL,
		0x72CE1A0B2518774FULL,
		0xD84CD52EA1642C60ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 209\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xF0D317E6E8F21E1EULL,
		0x014E4E104008EA59ULL,
		0x8425101E83CA9005ULL,
		0x4CFF7208DE7F98D9ULL,
		0xA9F4230CC9D01ECCULL,
		0x82A02D267D3CB64FULL,
		0x2C9BA62E25866857ULL,
		0x54F3E5F4ABF7D453ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 210\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x9E279EC90152ABC1ULL,
		0x5855FC91E00D5893ULL,
		0x8D710C84833F19B0ULL,
		0xDB51E654DD3A897BULL,
		0xC36C43E4C58FC686ULL,
		0x7647AD8F769C6F8CULL,
		0x63891D1A0EDCC796ULL,
		0x0B04A2E4440803BBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0800000000000000ULL
	}};
	printf("Test Case 211\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xB09DB17E67756B88ULL,
		0x03BA70E5544604C8ULL,
		0xEFA9AC5619A77F44ULL,
		0x603E374401058BEDULL,
		0xEB451252FEEC0B24ULL,
		0xD461781AC716FE37ULL,
		0x38DCD9271E1CBDDEULL,
		0xCCA4380CC66AEE62ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 212\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x8CF2EE37FDD8D952ULL,
		0x82A91354A09FE7D6ULL,
		0x0494A3D4DF89D95AULL,
		0x3EEB536A9F9DBDAFULL,
		0x3A23412167D68CFCULL,
		0xA9A7850EB373F505ULL,
		0xA7FB0182D81D54BDULL,
		0xE37B27077023088BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 213\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x3C6BE83244F192D0ULL,
		0x9ECA3AE8607E1460ULL,
		0x6881AC2A7C52F482ULL,
		0x392404293E597B47ULL,
		0x7F67D10F6FBC646BULL,
		0x8A33D2B796DE5F3BULL,
		0x6F70E84E77A7816DULL,
		0x5D152EDBEA93B5E6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 214\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xDFCD4C605079A0A5ULL,
		0xDDD66CDE09D320D7ULL,
		0x424F2D0F91FA185BULL,
		0xA418F1EFE84FAAEFULL,
		0x6891B326091F88FFULL,
		0x20B236A53DD7EA78ULL,
		0x7EB78D3E033BCFDDULL,
		0x9D03D9B55804838AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 215\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xC77774481048D8DEULL,
		0xFD5E29A5821EA9F1ULL,
		0x70E578F64418E99CULL,
		0x60A0225586E09C08ULL,
		0x4542980248C0691DULL,
		0x4E42FA1CB44E479DULL,
		0x4A3DA98BD62E170CULL,
		0x7C538BD4FE2AD220ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 216\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xE8036BA586419E7EULL,
		0xEC492DBAAC0CC942ULL,
		0x70F908196D326DB8ULL,
		0x6B6D00BD906695C1ULL,
		0x79CD19C2B3BA933CULL,
		0x3C94E19F1853AA6CULL,
		0xE12510A4D29F110FULL,
		0xE4927879ACFC088FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 217\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x4EB26DB40FF6057BULL,
		0x040B935D02E44F0DULL,
		0x9D945FE385235074ULL,
		0x99D6DFA03B751BACULL,
		0x8FE44B660EF4B922ULL,
		0x83C2D9E8B9BBC0DDULL,
		0x3BC0BD64AD5FB24BULL,
		0xE231736C0079F38EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 218\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xA8CA9D69040598A5ULL,
		0x62D8ABEF3A3A4699ULL,
		0x266E489BBEF06008ULL,
		0x088AA23484477270ULL,
		0xC74E80706E6B4478ULL,
		0x113DC2238D0DAA61ULL,
		0x7C1B8096FA20A55EULL,
		0x2C06632BC9276E70ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 219\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xABF878E37A32FB3BULL,
		0x24CC46DF10F172C1ULL,
		0xC74FD403419FA016ULL,
		0x86A7B13A79609711ULL,
		0x85FA4203E5AA8C08ULL,
		0x648B601C8AC3E3E3ULL,
		0x9C9A567AD2D40F57ULL,
		0x95AC133DD1BA1A5CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 220\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xDC39838671A64666ULL,
		0x30F695D09F312430ULL,
		0x100957F15D8F862EULL,
		0x7609737D6BC459D8ULL,
		0xCB12B5910C903F52ULL,
		0x151E4FEF7B19606BULL,
		0x8B68D42CAB9EEA1EULL,
		0x7C4927125CA73EE2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 221\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xC9B0D5E428A77D65ULL,
		0xD887D59995E21C83ULL,
		0xF86F7CA3CABC2E12ULL,
		0x99499A595C62CF88ULL,
		0x63E5D68F32357134ULL,
		0x09B0AFDF57590279ULL,
		0x6547A0BBDF8D107EULL,
		0xDC5D879FF00836A0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 222\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x3388D9C1AA263445ULL,
		0x1F4C62BB4439B1D7ULL,
		0xD78B1D161F22AFC4ULL,
		0xCBCC23DD9C83DE5EULL,
		0x7E9E0A286F5DBB1DULL,
		0x371C76D8E4D9C9D9ULL,
		0x4E101C9D7EC4A97AULL,
		0xB56DF5DA357D1D3EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 223\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x7EF63AAD8EA039DFULL,
		0x5C9854BEC1073489ULL,
		0xBFCE70C7E4187FD9ULL,
		0x928B872F86262893ULL,
		0x19DE93F5B363DBC9ULL,
		0x07B7E08849BCB6A1ULL,
		0xF600A883488B5688ULL,
		0xAD3CA7B2A878084DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 224\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x03E21DB2EF9E3284ULL,
		0xB7B08E9467114018ULL,
		0x2072920E8DC5537CULL,
		0x213D36C63E93C7B2ULL,
		0x4C14A765237AC561ULL,
		0xF6F82CD5A579121CULL,
		0xFCD4BF66669B332CULL,
		0x9C69B1336D282A30ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 225\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x3B9329DCEDFA692CULL,
		0x207CC78E9B7ADE07ULL,
		0xEEF7EBFD89985783ULL,
		0xEAC5D429E66F6668ULL,
		0x446DCCFD8AD49D1CULL,
		0x9F148537F0E5B5BBULL,
		0x576FF2E5E2A7699AULL,
		0xEDFCDD7B0B599FB6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 226\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x0C8E11D3BD2F273DULL,
		0x33E4E018CD3A13ABULL,
		0x4D294620A1DDC295ULL,
		0x181DD145580D9330ULL,
		0x69DE2FF76F425A6DULL,
		0x446403C934F9AB39ULL,
		0xF96E1328C857BB20ULL,
		0x8510A4D2CBC35F6EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 227\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xA10910122417CD27ULL,
		0xF1CF40E4F9C5057AULL,
		0x6D1CAF0D2E6F23E9ULL,
		0xC58D6E482E20B45DULL,
		0xB3017E202E065F79ULL,
		0xAC984678C72FD792ULL,
		0xCE87654CE4602FEEULL,
		0xBD0F802515831186ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 228\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x65CA8494DEFBF89EULL,
		0x1336A961D37D243FULL,
		0xF764905122AA3EB8ULL,
		0xDBAC35160F2D833BULL,
		0x9064D4475635C505ULL,
		0xC3913F1F4BDB9B3BULL,
		0xB27D8947AF303267ULL,
		0x34B54A5521E63106ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 229\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x368C2C65A05E6260ULL,
		0x54A4C3BF98D89D4FULL,
		0x2CA1587C6F97D220ULL,
		0x98E5212F56932EBAULL,
		0xD8CE9504653BDEC8ULL,
		0xB882CD4560A91220ULL,
		0x87432DF7B7A49E3CULL,
		0x239D5E71B5EF1701ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 230\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x91272DB2043A61E2ULL,
		0xC2572B26DBDA2A17ULL,
		0x4C6D2CCF6DB37668ULL,
		0xA85D583287096B1FULL,
		0x549B6A15E1F63BB8ULL,
		0x8DBF6DD74306144EULL,
		0x9B1EDC3E2DF3747DULL,
		0x51962D59A065C979ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 231\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x4EB7C445DE4DFCD4ULL,
		0xDA576799B63388C3ULL,
		0x6517350B834AE54CULL,
		0xB2DB493D9DA2FDD4ULL,
		0x0D5CFE529293E624ULL,
		0xFD7EE35AC1CC1948ULL,
		0xB8D37EBCEE71E303ULL,
		0x963248EBD91AE0B6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 232\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xDE31B8C56FEAC5B7ULL,
		0xEFA69A60A36440EAULL,
		0xCA3E3566892D54AAULL,
		0x1C0876F7DE07A851ULL,
		0xB3CB54140E73D334ULL,
		0xA064FB85A2E8DBC2ULL,
		0xE7DCD43C9FC26313ULL,
		0x353B6E040D8AAD1DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 233\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x4964758C0E2FAED0ULL,
		0xC9A898630A612846ULL,
		0x9E5F5644E39A7D4CULL,
		0x21A40A8E8D651193ULL,
		0x4283E0344E54935FULL,
		0x71ABECBE89259707ULL,
		0x125478AFC913DC28ULL,
		0x86C01DE701DF67F0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 234\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x1E70B63DB5F89207ULL,
		0xA273AAE623F8121EULL,
		0x0139C3C9DBA71C53ULL,
		0x89518DEE51B7DCB7ULL,
		0x4618B6700892348DULL,
		0xA4A8F9AE7F9D2141ULL,
		0xCBF2503A6892773BULL,
		0xBEF78BD7BE8B4437ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 235\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x640A5049E09006C3ULL,
		0xF8EC6DA4C69C5D58ULL,
		0x1B1ABCB602C34DBEULL,
		0xEA21272BA798E1C0ULL,
		0x13A9FA6B2DFFFE1CULL,
		0xD0EEDB31CD42C186ULL,
		0xACC5B29F550B5337ULL,
		0x5DB46BB7C6E95367ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 236\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x0BFBE913595ADDDDULL,
		0x9A62F87532F77B42ULL,
		0x645B10F849A54D91ULL,
		0x7393B2395F53CBC2ULL,
		0xDAB7A4B2E0E8A20DULL,
		0xB130D774553F7BE4ULL,
		0x53B76DEF89AD5181ULL,
		0x4C8A7A78480C27F0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 237\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x81DF446E430B6BA9ULL,
		0x475F252F305461B0ULL,
		0x61D985B0E4F25B81ULL,
		0x4AB71AB663057260ULL,
		0x9FA26D0C1E7B8EFCULL,
		0xE4E4B8DACAFBE7E8ULL,
		0x24B0F29923E9C61CULL,
		0x9EC0D6D40EF14E7FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 238\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x396260C45A85B2D0ULL,
		0xBE6350AFF303FAC6ULL,
		0x29D66629570353CDULL,
		0x87901A06428FC621ULL,
		0xC28713EAFF6D51EBULL,
		0x39E648C2B692D3C4ULL,
		0x32708DC0F6E4B05FULL,
		0x523A435E83994647ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 239\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xEDCACB60B6AD5EA1ULL,
		0xC43F2EF709508CB4ULL,
		0xEB6D1522EF86BBA7ULL,
		0x45D4229C9E7E5053ULL,
		0xAEF0C5213C4BFE16ULL,
		0x6D50995003747326ULL,
		0x07C8D2BA29396205ULL,
		0x846A3C17A4F0A9E9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 240\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xFC214581EF36CD27ULL,
		0x4FA90BE5478713DCULL,
		0xE516F5D01C1A5768ULL,
		0x3180AB9DDEBBD944ULL,
		0xF3744CED68F3A959ULL,
		0x1276E2F4A1E6E897ULL,
		0x7610E1D81AD5C2B7ULL,
		0x61AC4E8EB1223A41ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 241\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x19EB99A600C37203ULL,
		0xB8834FE94D8438EAULL,
		0x2D3D1816C8DE4503ULL,
		0xDA4089E92E2547C2ULL,
		0xC011DE6BF78B4270ULL,
		0xE1C89DCD3298B26BULL,
		0xF66A4E10CFEAB4EEULL,
		0x4EF728D0C480F850ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 242\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x9FDFD6DC25C390CCULL,
		0x6B79D18D0C4B7ED8ULL,
		0x2E601A0DF4289552ULL,
		0x74F4C2AF34A19C09ULL,
		0x1D347FB7C82576E9ULL,
		0x5529953AA13DD27AULL,
		0xE70CDD75A97C3044ULL,
		0x8BD0F82DE5D76DE0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 243\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x38B08BCFBC666F47ULL,
		0xAA36081EBB33512CULL,
		0x3544A0A7BAC9FD6AULL,
		0xE6E93696AC201F32ULL,
		0x91A8BFACCD415394ULL,
		0x18FFFA660B7C08D5ULL,
		0xCFDD6867BBB1D125ULL,
		0xE18ABD1B89C88995ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 244\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xC9F4EB3A91BCF63AULL,
		0xB1BA809C3BF10796ULL,
		0xC476E0399B314302ULL,
		0x9D72B3DC56FB84AAULL,
		0xBEA4E6B0F44E7474ULL,
		0x019F157112EDE712ULL,
		0x1AE475FBD48C99F3ULL,
		0xB339CA254D1F4A6DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 245\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x0FF5A1CC0E5ED0B1ULL,
		0x054881BF3DBCC824ULL,
		0x045289035935DC39ULL,
		0x02C2B7580A4A56A1ULL,
		0x158DEBEAA583895EULL,
		0x400387F43A462C20ULL,
		0x91228FFF3703570AULL,
		0x0C14F8032D40D967ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0800000000000000ULL
	}};
	printf("Test Case 246\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x08C0E8EA7232255AULL,
		0x039A3D1567E86250ULL,
		0xD7381DAE7BF7DB6FULL,
		0x7A5CA9FFAAB14CA0ULL,
		0x04E7A6F05D59B50CULL,
		0xA455EF1FCF0022A1ULL,
		0x635A450FB69A0804ULL,
		0xD3BA5595B1F79996ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 247\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xC8EDD193ACB83D5AULL,
		0x0D7FA219474E1E64ULL,
		0xE93E3FD4BA7D7A2EULL,
		0x1D5E01B3104E171AULL,
		0x28FED4623F7A464EULL,
		0x80DABFB806D09F64ULL,
		0x0D839872FD50E09CULL,
		0x593D37FBF7A8D1E0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 248\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x37BD2385375445CFULL,
		0x8A4F0D183232F273ULL,
		0x3E2C93480FA09A4BULL,
		0xC9EEF7D4ABC175D1ULL,
		0xBF9C26F4D7425BE6ULL,
		0x238443537C7AD7E3ULL,
		0xC93A0F768060C423ULL,
		0x43B46D785D590FB6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 249\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x7D3E35DB5CD42C1AULL,
		0x44D0CEACB0498973ULL,
		0x61B606C83A13716AULL,
		0x8395CF5947448A0EULL,
		0xF80132BA16E1EB97ULL,
		0x6BB9A5DDB77838BBULL,
		0xFE6AC850A3CEFDC7ULL,
		0x27BCC3F060CA5B23ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 250\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xBEF1C4845FBD34ADULL,
		0x2802145DFF3E8E99ULL,
		0x816EFB7233A59493ULL,
		0x022995B489A79BE1ULL,
		0x9416E26A9D9BBA09ULL,
		0x68D0E96FB8F166E0ULL,
		0x741BB518DB7A5E00ULL,
		0x01E7DCC871718BB6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0100000000000000ULL
	}};
	printf("Test Case 251\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xC84269128BBB88E0ULL,
		0x22C1A887C63469E1ULL,
		0x4C2776C192910D85ULL,
		0x65A951137D1B649FULL,
		0x4622C38560E5BF22ULL,
		0x8686E057B89F884FULL,
		0xE40266D71AD0C56EULL,
		0xAE805DB03BF754B2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 252\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x1B86A594E9AAAF02ULL,
		0xA5FC480C2B63A191ULL,
		0x448CAC4482429589ULL,
		0xCCFE2BF0166CB2D5ULL,
		0x6AD40538F2355773ULL,
		0xD225B5FB27FA3388ULL,
		0x94AE99234D732D5EULL,
		0xAD03A572EA1B8572ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 253\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xB70F07BAA3E050ADULL,
		0xDF5CA6C6C923008DULL,
		0x35EA76E45DCDC9E6ULL,
		0x7897773F22BEB62AULL,
		0x2C34EF074CD07D85ULL,
		0xCC304141B1B0D5C8ULL,
		0xD93E4FB1C467120DULL,
		0xC381D2845AD9A3C1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 254\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xB58F61C4E951DBDFULL,
		0xC7749FFAF339163AULL,
		0x9176C1F16ABD16C8ULL,
		0x6AE6CB48BDEE170AULL,
		0x21E0271C7C51C3A8ULL,
		0xD80D95E550BD735DULL,
		0x7631C33744DE28CCULL,
		0x0339B7F266CF05BAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0200000000000000ULL
	}};
	printf("Test Case 255\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x4A9B908626A01466ULL,
		0x0A68A39A94B0D09DULL,
		0xE52B3E2D77C621FEULL,
		0x62DD44EAD376C1A7ULL,
		0x32AA8ADD0C600A90ULL,
		0x9CEB77354D4CF7F7ULL,
		0x0BDAC1E39D37915DULL,
		0x8DE886AD129B21BEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 256\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x8F427533B73AB001ULL,
		0x5CC77B13F9902CAFULL,
		0x2AED81895B7EFA37ULL,
		0xFA1DCE50570DF73AULL,
		0xD93589BC36E52DA3ULL,
		0xED2DF6251DABE074ULL,
		0x9F05403C68C95E02ULL,
		0x1B65B9108F1B7E46ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	printf("Test Case 257\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x2D055E1FC49DFAFCULL,
		0xA8AEF5E60D88F457ULL,
		0x1098AA36B6801D8AULL,
		0x8881F3C0A69E5EBFULL,
		0x7053717687BC4941ULL,
		0xCD0E6BECF64EC889ULL,
		0x3C61874E9C331702ULL,
		0xEE7DFB4D6BB90F6BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 258\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x2C12D394D9246197ULL,
		0x8E50C0F0745013D2ULL,
		0xC5ECD9BC5FD7485AULL,
		0xCF0C543CA32D48B0ULL,
		0x797E1B22A106B59BULL,
		0xC3C1C9AF6D7FAB89ULL,
		0x8F610EA1877C8568ULL,
		0xFF9C9FF0080419BCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 259\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xC52D41D613775892ULL,
		0xB6BF9226C2C9C3EFULL,
		0xAE5EA5086B854DE9ULL,
		0xE6A5252F02ACFFB0ULL,
		0x436227B4B5F946CAULL,
		0xFED8E3B489E798C5ULL,
		0x1B683507C07C986DULL,
		0x95C1951C2325033DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 260\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xC15FA25DE66D54A1ULL,
		0x3CDCE0B67644AE02ULL,
		0x22C0EE1BE2535F12ULL,
		0xB344CE9669D30C0BULL,
		0x98EB57686EB5C976ULL,
		0xCAB246783955766DULL,
		0xA67E152F6D09CDB7ULL,
		0xB83A35CAC2630ED6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 261\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x82E7517EB661A759ULL,
		0x9515B37E4693CF22ULL,
		0x856F5A9A749757F7ULL,
		0x0B83B6B4E4470C09ULL,
		0x0FE4240EE6907738ULL,
		0xBCC7F84D7D9F41CCULL,
		0x07762F7D6DE0A6E9ULL,
		0xB557C266CE764013ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 262\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x3504866637E3152BULL,
		0x4C2D6DBEACCA9A03ULL,
		0xA87841A54CCD5FC3ULL,
		0xBEBD29C47C8BA02FULL,
		0x63D1F17B571BA344ULL,
		0x487023B6C30BA9D6ULL,
		0x3C12E2105C73E107ULL,
		0xDB7DAE95D082F1E5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 263\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x02FEC1B136016E9DULL,
		0xD4379764BD405F79ULL,
		0x8668B039FCE15C25ULL,
		0x5D7943AF33F39929ULL,
		0x24B25FD2869C7D32ULL,
		0x3F56543F03B19F25ULL,
		0xE4A068709D1F5F14ULL,
		0xA578148AF2BD60C8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 264\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x7BE135C50E2F2BDDULL,
		0x3D484FA2C794D872ULL,
		0x74F75F527CADD97AULL,
		0x5FCD981DBCF13764ULL,
		0x2F10C344238C91F0ULL,
		0x659B951962603516ULL,
		0x8677FFF16FCBB7CBULL,
		0x71B53841AB807EF0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 265\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x43458E0955775D72ULL,
		0x7580AFD60A07B000ULL,
		0xF7D91E8A1186AD56ULL,
		0xEA1AAB7093B73FFBULL,
		0x3916875F15781A56ULL,
		0x8AE6F9310EAF76BAULL,
		0x5906B62FB6D44088ULL,
		0x1B232F8308CC31C7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	printf("Test Case 266\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xC6D043F74D1711F3ULL,
		0xEC5B26C74890DFBFULL,
		0x37E37952A968C38AULL,
		0xE17A4E727078BA38ULL,
		0x1FC8A2992BB3F3B2ULL,
		0xCA786F9B5072BAB5ULL,
		0x4B554E194126BDF2ULL,
		0x87BCB07DD6DEEFBFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 267\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x4C951CA1F30762F3ULL,
		0x7C7178C0DB038724ULL,
		0xEF3620395B30DF38ULL,
		0x4E48D00ACCAFFE84ULL,
		0xEDD01057073AC2B6ULL,
		0x11BDFB82DBAE5185ULL,
		0x6C035692551657A3ULL,
		0x2418E7A06E76966CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 268\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xD81477C70B9ECF33ULL,
		0xC89EB34716017C66ULL,
		0x8A20053A5FC2A7FDULL,
		0x407E4B7246D4ACD0ULL,
		0x316F64E6C6E4E84EULL,
		0x568EC5B5BE9923ECULL,
		0xDF84D12E8F0D763DULL,
		0xBDFDCABBB039D46AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 269\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xC0883A1B7DD3CCBBULL,
		0x17753AD800FC761AULL,
		0x619488B3F40D8080ULL,
		0x94039CE495471403ULL,
		0xA214DE78F2A8E894ULL,
		0xCB8C31E263A4CFE8ULL,
		0xC4D1A869C42C0309ULL,
		0x62EDEF816130CC94ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 270\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xD2E4678F3A9E8B0FULL,
		0x875ABB56BCC5B629ULL,
		0xF5CE6FE6829524A8ULL,
		0xA828D2EB00C54B5FULL,
		0xB6226265FAFF7F06ULL,
		0x5582DCF5BA964479ULL,
		0x873D44E056FC220AULL,
		0xED00F45FD5F7B760ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 271\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xA878BA0EDC27E710ULL,
		0x433B78251036AB40ULL,
		0x9E156B58B0B222C6ULL,
		0xA031D872069FBBD0ULL,
		0xA849ADFF2409F7A8ULL,
		0xA83AAD582CBED601ULL,
		0x7674827834EF467CULL,
		0x7ADA8CD5244BB098ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 272\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x926144BBD1710FE9ULL,
		0xF39EF425809395B2ULL,
		0x7492BA07EE56DA65ULL,
		0xB4A5026305EBFAADULL,
		0x81DECB2BD6BFD56BULL,
		0xADA38DCD4BC36D2CULL,
		0x6CF68CA17F0A2822ULL,
		0xD32166CAEB613D25ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 273\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x685DE19396CECD13ULL,
		0x6752FC464DD6BB96ULL,
		0x25DC2AC763E8C864ULL,
		0x72645885E4D6E8A8ULL,
		0xE319710EC59844CBULL,
		0x3B7F36248A67A214ULL,
		0xC18AAF1DF27A0B11ULL,
		0x5BC86D7A89DCE189ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 274\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x3D8BFA60D3AF5353ULL,
		0xC7DFBBCAE15D317DULL,
		0xCE6C38D277EB1B81ULL,
		0x974CC024C631CD55ULL,
		0x1FBF5D7BDC99FBC4ULL,
		0x242290E0F0C9E970ULL,
		0xF183353FD54D341FULL,
		0xB376DF2D610E667AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 275\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x177A08E6171895C0ULL,
		0x799D475AA9984794ULL,
		0x6CC52E3C62AE4152ULL,
		0x6F03E48004CC806FULL,
		0x39BD51ABD65677D2ULL,
		0x3EB1550CD7BA656FULL,
		0xA8FD32ADA67A2721ULL,
		0x7EA7674DD0C35628ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 276\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xEC6F37074F15AB29ULL,
		0xA2B8D92A12444DDEULL,
		0xEDE5E2119624C484ULL,
		0x3E12DF456EA8C5D2ULL,
		0x899CF7082C027CC9ULL,
		0x2133B5745910DD57ULL,
		0xB90941772001045CULL,
		0xCE92FE8ED9B6F33CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 277\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xB9F2093A00932A37ULL,
		0xF29608B7511C8B1FULL,
		0xE3505675D58AD742ULL,
		0xC941EA552285CFB9ULL,
		0x479F364B3964ABD6ULL,
		0xA9229CE7EBE994DFULL,
		0x0A4D264AFC30A915ULL,
		0x7A199FD04278C1D5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 278\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xC398C6B8E62EC113ULL,
		0xB00D55F6FAD1F09CULL,
		0xF8029D712979EADFULL,
		0xF0AE96B1C51DE54AULL,
		0xB1A88446B9901E05ULL,
		0x215215A203DB1A53ULL,
		0x048AACCF7B533AB9ULL,
		0x660723042DA23D98ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 279\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xF241119708C2B411ULL,
		0x00A379B056329C67ULL,
		0xE19045100DCE2BE8ULL,
		0x154E0C965C45AB19ULL,
		0x9D856580BFE8EDD7ULL,
		0xA3FD003F6589C3E0ULL,
		0xAF31A0D02CB63C50ULL,
		0x3879F6FAB109C5F8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 280\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xADFB98C601F3CFB5ULL,
		0x7E7ABEFBE2D2F15BULL,
		0x46C04ACE40C54AD7ULL,
		0x7D4B2DCB4DDAF812ULL,
		0x07A83CA30588BB3FULL,
		0x82740A00044CBD69ULL,
		0xF1937F3C5D15EB6BULL,
		0xCBC7EBDDA207443BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 281\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x5E86D6852A52C60DULL,
		0x77AAD6BDA1F9FDCCULL,
		0x1BF4C280C517A602ULL,
		0x0A9D846A48DAABEAULL,
		0x401E0DF2E2CA23BBULL,
		0xFA4D016F6EF0041CULL,
		0x86673CB4EF8C9A52ULL,
		0xFF679DD9CC43B5D1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 282\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x924D6E928A137527ULL,
		0xADFE7B476AEFE194ULL,
		0x8B554DAE5C76A8EDULL,
		0xA94B1B3D4BE15D0EULL,
		0xD0288CEA3BA71538ULL,
		0x47B1B2F6F1387806ULL,
		0x1F3607B41A3072B0ULL,
		0xA669F547B360177BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 283\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x178B21B3AB820405ULL,
		0x2BBDCF0EB6F6A280ULL,
		0x67B3370A3D9DF185ULL,
		0x5C7E22A65B5C4392ULL,
		0xDAB66B228DE0B362ULL,
		0x4CF8A56877096B2DULL,
		0x0C6EE546B2A9663FULL,
		0x9E6DE0C3D340DC64ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 284\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x7F110D305E177380ULL,
		0x34A4A5F213DF7FB2ULL,
		0x392C918A3DADE8DFULL,
		0xD9B1EFFE67ABA09EULL,
		0xAAD5A98A8A855279ULL,
		0xAB9CF6BB882BB958ULL,
		0x6A53349379E39CC7ULL,
		0xDE1A6958536C3404ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 285\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xE2F63ABC6B8CEB68ULL,
		0x161053D4A7B47182ULL,
		0xDC772A56BC716675ULL,
		0x71E50277B2A292BEULL,
		0x3790122A42790AAEULL,
		0x39235FFA88F4E48FULL,
		0xAE1AA1D42352F595ULL,
		0x6EB646D04CB40D4FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 286\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x6503EAD16E0A1DB3ULL,
		0x67EC511FF11BFA4FULL,
		0x7C2CC359921202AAULL,
		0x3EDA7BC77080EE90ULL,
		0xB10279B611D52C71ULL,
		0xA88A004BAE84FFE5ULL,
		0x94FAF92EDC668005ULL,
		0xA7F63E90849FAF11ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 287\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x4A30A2878CF5EE5DULL,
		0xDEC30E4879E49B7EULL,
		0xC3A38A92D5964509ULL,
		0x419EFA6209E319B4ULL,
		0xC47C99BCDE4C746AULL,
		0x4CCC3843C7C03CB5ULL,
		0x5166F5ED559DDB7AULL,
		0x9FDCB1664C0D853BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 288\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x65C0707EE7AA96DFULL,
		0xEE459A5E3339A9C3ULL,
		0xEFB02AE967643F80ULL,
		0x0C670EFC6B1A0A25ULL,
		0x679496CE6212B910ULL,
		0x52542AA48FEE7555ULL,
		0x24209982954A74A3ULL,
		0x59DBD61B2293D183ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 289\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xB9745D4F42C5A072ULL,
		0x7B338B3E2BE8C364ULL,
		0x56D1C4824EF8CE1BULL,
		0x8698CF289DECF959ULL,
		0x380CCB7862B0E29FULL,
		0xD19BA2873A07FCACULL,
		0x4252F360B1C07772ULL,
		0xD3D33B8528D4B28DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 290\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x545597722B067F52ULL,
		0xA9476E6D33BA89D1ULL,
		0x30E0799254430EA1ULL,
		0x5C2A414ACE6A5A62ULL,
		0x724709DDA7CA6D95ULL,
		0xDA2E542F6A0B0271ULL,
		0x75B79FD0A8F55030ULL,
		0x3F7C11376A6798A9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 291\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x422AA576ABE8BC7CULL,
		0xB80E3ADCFB20BF9BULL,
		0x50DC5401B9C72E44ULL,
		0xCDF71922D9021FF5ULL,
		0xA4B7EE8E75193D61ULL,
		0x44172B0B0D374771ULL,
		0xAF732703BAF5825CULL,
		0x52585EAC44D2B94BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 292\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x7048457B16548830ULL,
		0x9ADF3425E683943EULL,
		0x099A47051D157C1DULL,
		0x9627FE10CD076FF0ULL,
		0x74C6DCEE3268DD6EULL,
		0x5EB9260CFB28497FULL,
		0xDACA8B6CFCD0D667ULL,
		0x8834632C52A3E16CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 293\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x03019E4A6429CE3DULL,
		0xF1CF35A161598949ULL,
		0x26C4756B447327CDULL,
		0xDF7E0953B4D3B55DULL,
		0xC74F62E2C263035EULL,
		0x3C618D083286785EULL,
		0x79EBBFF55A5462A0ULL,
		0x819D687D4F4CAD8DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 294\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x554DCA718EDC61BBULL,
		0xDB5413923DFA3253ULL,
		0x970A1F59C920AECAULL,
		0x9850CD7F3E8CE0E1ULL,
		0x327DBCA9ABFFDA33ULL,
		0x46B774F832FFB7E1ULL,
		0xE48D53D5E6E80039ULL,
		0xC4D407755E52EF6BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 295\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x81A75576945580B5ULL,
		0x6CF04C98EF765C60ULL,
		0x486B2A94BD966758ULL,
		0xBABEF82C49F93482ULL,
		0xBBFA212D7BFF8C73ULL,
		0xEA255AD1FBE7D24AULL,
		0xCCD7E255EBA1C9A3ULL,
		0x1A03C35590FD9467ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	printf("Test Case 296\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x483D575DA8B0C82EULL,
		0x18134132F83C77E0ULL,
		0x833CA46CADB8E72EULL,
		0x56CBB7957F210A49ULL,
		0x24ADAD9990AEA561ULL,
		0x7E779DCB76A8DC1BULL,
		0x30CD83F9157F6C14ULL,
		0xE050C70EEDC34C83ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 297\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x3AA4D6A08CB16B1DULL,
		0xB19AE4947DE73E5FULL,
		0xCFBBE567E726783BULL,
		0x10C0C0BFEE4E904DULL,
		0x6A36A223A599787EULL,
		0xFB8C242BE3665146ULL,
		0x7EB3FC94178F67D9ULL,
		0x4A4E12A880D436E1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 298\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x91094018E4C56262ULL,
		0x1DCD88F2822FAD1EULL,
		0x2DEF6B732DF15B07ULL,
		0x66E9F39D95852279ULL,
		0xD250A8F7978B2DDCULL,
		0xFCD50754E3A78FFAULL,
		0xA1864BC93ADB146EULL,
		0x258B71C08AC2EA93ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 299\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x7F95F77A60832AEBULL,
		0x624C3B5B3A6E67C5ULL,
		0x0C88EDB25259B84BULL,
		0x437FA41B4AD30407ULL,
		0xA51E274DC841163BULL,
		0x7CE0F332AE8EEF8EULL,
		0xFF0677D45686ED7EULL,
		0xF568153B58853B71ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 300\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x2C3EDBAEE60F8FBBULL,
		0x9AAFB1735CDF78DEULL,
		0x0523CC84D70E2BF2ULL,
		0x27752DBD66889E6CULL,
		0xB322ACA460245F29ULL,
		0xCE2B010634931AA2ULL,
		0x775E91D482949F4AULL,
		0xCE711C2924506D6DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 301\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x6A4EA07D680BEA41ULL,
		0xCA22B0D937407DEEULL,
		0xAF1A1007247AC008ULL,
		0x9C5C79F377524A90ULL,
		0x75565A5A8E182CFBULL,
		0xBD91B3500CD69965ULL,
		0x43182E21DB5578B5ULL,
		0x8B07ED5BF810C9D1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 302\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x5FA59185487707E7ULL,
		0x32D7774E8DE889D6ULL,
		0xF8DAD1D83A2BB2DCULL,
		0x188ADE38E25AFA28ULL,
		0xAE57719B8893F097ULL,
		0xFA5B17EB90B9A9F7ULL,
		0x28F3CB6168D8E9B1ULL,
		0xEC053E12DD40B7C2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 303\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xD1990903DF508AC9ULL,
		0x1F28B528195BDA43ULL,
		0x6D964AD7CDCED896ULL,
		0xF940CBBC4711EF08ULL,
		0xBA3052A0805BB560ULL,
		0x7174C97B3EAA1ADBULL,
		0x7BDBC2D336843EECULL,
		0x66271A15A3402527ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 304\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x365F6C2FD079F9CFULL,
		0x4F3A5F06C9D99C95ULL,
		0x60398073A623B218ULL,
		0xAAF57E88DA00928EULL,
		0xCC265170711ABCA8ULL,
		0xAB30E03C9044AADCULL,
		0x8F585FDF5C254BF2ULL,
		0x651C1AD8B36DAA1AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 305\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x12EE71CF909FAF7BULL,
		0x34CD4E1466FFDDFFULL,
		0x65EA17F3803B0727ULL,
		0xE67E45CCFDB5CCEDULL,
		0xBBB9584F6E4871D1ULL,
		0x96D3CAC7B75F9D03ULL,
		0x67EA30C2A0A1A5A4ULL,
		0xAF3FF1FE4E02D08EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 306\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x235DD413B90AC45FULL,
		0x52C380EF5F4D9B07ULL,
		0x9F98F026FD6C16C8ULL,
		0x613C5EAB08F71563ULL,
		0x94091384BEBFC2D4ULL,
		0xE995262B437DB8B9ULL,
		0x649D742A21210BDEULL,
		0xD590CFDD05F66E0CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 307\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x78C02E87613720BBULL,
		0xD4799B6F01DB59E7ULL,
		0x0C97608180F214A6ULL,
		0x1D5E00BD40E49854ULL,
		0x1F4ADC5761CCDDB7ULL,
		0xD717043567CC4AF4ULL,
		0x073E454B68D42BA3ULL,
		0xE5F32027159E0495ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 308\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x403BBC021BB18E3FULL,
		0xB20725C58EAB403BULL,
		0x38022A4D02457711ULL,
		0x6501E25DA4CEA986ULL,
		0x86E1107304155DA0ULL,
		0xC4A9D867E41966E4ULL,
		0x35F43D0612BDD83EULL,
		0xB5A8EB74A1222F49ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 309\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x751E6D34543DCEABULL,
		0xAF91F84B387C8056ULL,
		0x40478B9B166289C4ULL,
		0x48CA63DAC169D687ULL,
		0xD71D1355C756A2A4ULL,
		0x473300934977301DULL,
		0x83A92817BABA2F63ULL,
		0xEF89D1ACEEC259A7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 310\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x795D88E974585537ULL,
		0xEE1BE671C1F38C55ULL,
		0x7B84B7F532972F90ULL,
		0x35FE16EADB7E9456ULL,
		0x201AEFD9048ECA7FULL,
		0x1E8D87C3EA338E80ULL,
		0x72C0B40DB3949EE5ULL,
		0xD6E08C695DEAE4DDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 311\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xEBC02701B3BD3BF4ULL,
		0xCA1E764ED7559E2EULL,
		0x08C58B3CD0820231ULL,
		0xB56F7882F415E79BULL,
		0x0597B51CEAE3CC9FULL,
		0xD63BD22F9C9039B9ULL,
		0x85644331BCD8B956ULL,
		0xFEF5D49E4444A258ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 312\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x64FD435A4809B8B1ULL,
		0xC6742701C32B26B8ULL,
		0x7A4E6BC1ACDB32B4ULL,
		0x60043BEC187D7BD9ULL,
		0xEAA829FDB641997CULL,
		0x3DC088003AB06436ULL,
		0x1D04AC2D5A6AB886ULL,
		0x073F1182978C950FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0400000000000000ULL
	}};
	printf("Test Case 313\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x8F2E27FD87BBF847ULL,
		0x84A2AC1E6B4C5F66ULL,
		0xA7FF7FC41D264F7BULL,
		0xF55F4F7B2428D0B0ULL,
		0x205871CDC5F857A4ULL,
		0xA279085AE9F4BA4DULL,
		0xC387E790F300C3A5ULL,
		0x5D6BA60616DFEC45ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 314\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xEB275DE0423D1206ULL,
		0x447902D338A9E795ULL,
		0x1C03A80E244D2274ULL,
		0x75E413ABE40BD433ULL,
		0x49EDBDB571DE0F59ULL,
		0x75FE50C0B9078F71ULL,
		0x29F97DBD1BBDFB03ULL,
		0xB005769831DBBB88ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 315\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xFEAEDBFCD4E63A34ULL,
		0xA5A71DA54DBBF050ULL,
		0xA2B5FEE63586033BULL,
		0x55CBB7C09FBBDD9FULL,
		0x2CB45D206F2AE635ULL,
		0x6E8052BA18F41F0CULL,
		0xA53E70BE12D59960ULL,
		0x14CAFA9B96B542C5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	printf("Test Case 316\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xC127097951BFBDE2ULL,
		0xFE0A53683B80DFF3ULL,
		0xAA962785753FA433ULL,
		0xF04746092BC36900ULL,
		0xB402C4A55D33D73DULL,
		0x8D204BFED1D2BEF9ULL,
		0x5CED828711C20D1BULL,
		0x5041BFDBAF32979AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 317\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xA21247029A428962ULL,
		0x2B6B928EAEAB1A4AULL,
		0xD16BF640B3BBE93AULL,
		0x6F81053CBAA9ED85ULL,
		0xC15F4A8903F6D910ULL,
		0xAE631598F8896DFCULL,
		0xC458D656F2699A49ULL,
		0x2E5D4B8A224394FDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 318\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x080CC688413FEE60ULL,
		0x5F70CA80CAD0E9E4ULL,
		0x7CD16FD3CB17E58EULL,
		0xF8FEEDF92F3E12A5ULL,
		0xAD8E42AC21CB293FULL,
		0x7F4B0C8BC7A614F5ULL,
		0xA68E3F33070E367DULL,
		0x244EE24CDA98EC6DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 319\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x7CD7A4C37031D5D9ULL,
		0x9601EF66AA9000C9ULL,
		0x65A9F1985BD113BFULL,
		0x04C84E753F5304B6ULL,
		0x2EF5BA80062461E4ULL,
		0xA32E6056E8635645ULL,
		0x2BB220E538E48D34ULL,
		0x671EF64716834F45ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 320\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xAEB26EFBBB102E6EULL,
		0x8EE7A68E6905D01BULL,
		0xA72859B9A282AB1AULL,
		0x420C819D89846418ULL,
		0xE0229DCFB9AF7F58ULL,
		0x3675FC7E03BA71BDULL,
		0xD34B9ADD1C3E0316ULL,
		0x84D0C1B375110543ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 321\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x65F537125526284DULL,
		0xD30DFA84BD6424B5ULL,
		0x27DB5F55E6B3172FULL,
		0x5F182FBDB30D63C5ULL,
		0xA760939137910A30ULL,
		0xB3C9DE28D1E2A69FULL,
		0xD71E33D1A6DA1B06ULL,
		0xD429DFE75E34DD53ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 322\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x81CDDE1672F02B19ULL,
		0xC73D7EED9D3D84A4ULL,
		0x4E0C2BF064191BF9ULL,
		0xAF4EC5974A0B9813ULL,
		0x1C3B250CCC35AD0EULL,
		0xA2E1015EAF874B1EULL,
		0x6E21C879047376B9ULL,
		0xDAA8AC301D3C8CE7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 323\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xB2D9321CEED66AFDULL,
		0xDB71A6EB062B5270ULL,
		0x1091DE9E2F1DB15DULL,
		0x6993CF1DE6076267ULL,
		0xD00D9EBE21583F83ULL,
		0x00F58A9A3CACD0A4ULL,
		0x9E3BD52801704544ULL,
		0x232C310362D91306ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 324\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xA05B5FF6E342116DULL,
		0xBEFD6E23BC95FA43ULL,
		0x6BD2291FD62B8818ULL,
		0xC6AD938685AA721AULL,
		0x0E48EEC2DE37E0FEULL,
		0x0C1213F1351407C0ULL,
		0xFEBC495BC46E5224ULL,
		0xFC9277355259C708ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 325\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xCC58D6BCA8DD3F02ULL,
		0xB57D20D343AA6100ULL,
		0x1B862D0BB1379E5CULL,
		0x4063B30B11FF46CEULL,
		0x7866BFA5043E0A30ULL,
		0xC6E20C5821B870C3ULL,
		0xA2A729E60C5CDD66ULL,
		0x10982CF6B951BB03ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	printf("Test Case 326\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x49C7827BD593FA80ULL,
		0x325387114DB5CDFBULL,
		0x13FE3B22F95D70C6ULL,
		0xC35E81A0B8186CD8ULL,
		0x3C19D06B50323DCFULL,
		0x89A054CA306C664EULL,
		0x9C9A8AA0FB9E306AULL,
		0x06009546CBB52FDCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0400000000000000ULL
	}};
	printf("Test Case 327\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x9FB6F18EC3B7EE86ULL,
		0xE21DC642EEC37F93ULL,
		0x0429540E6078A0A3ULL,
		0x2C2DA3BA683A488AULL,
		0x3136D720B34755BFULL,
		0xCD7EF4747CFC8B02ULL,
		0x095607369B87E2B6ULL,
		0xEBB5D860873DD87DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 328\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x89F31F8848F66D0CULL,
		0x9252018F64B9CB42ULL,
		0xB425A3271CA51052ULL,
		0xCA7B48208D7E6655ULL,
		0xDB36DEE304FE6505ULL,
		0x0A6C7CB407A1DC0AULL,
		0x18EC021E9C498426ULL,
		0xE3CABB175B1E75C9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 329\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xB16461B1D8AAB91AULL,
		0x5961D8CDDEA41767ULL,
		0xA2B756261FBEB1EDULL,
		0x2AA21F0193222B24ULL,
		0x4DC7ACF01B88DE46ULL,
		0x4ECCA7430BE26D51ULL,
		0xC6F430DD46E28BABULL,
		0x8770D6CAC4939A03ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 330\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xFFC6B9B94F21B88EULL,
		0x58C912E59620C58EULL,
		0x903179CCD08BF5C0ULL,
		0x7975CBBB75B90422ULL,
		0xF9CDF29D9B1580F4ULL,
		0x06430FD167102A12ULL,
		0x5DDB214DED54415FULL,
		0xFCEB39C3265248BFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 331\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xE6AC36B2F0542814ULL,
		0x1F4994C51EDA01B4ULL,
		0x30094AB32080E89EULL,
		0x9282F48EBF79CB4FULL,
		0x2B00BF756B4238ACULL,
		0xA06724D4443A2ACAULL,
		0x0DC60E04707298E4ULL,
		0x0A8FF76223EEAB62ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0800000000000000ULL
	}};
	printf("Test Case 332\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xA19A1944D78A3D67ULL,
		0xD935920344D37409ULL,
		0xF694C7C8B09F3708ULL,
		0x48DF2D1FC7E307ABULL,
		0x748823F77AF2AB83ULL,
		0x87E417EE4A7DD118ULL,
		0x7767726A402D3D8AULL,
		0xBCE6EDC89044428CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 333\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xC469494E2A5ABB17ULL,
		0x83FB87EAF8BDB613ULL,
		0x7D33C749932B53F8ULL,
		0x9AAFEA8606DC136DULL,
		0xD5C3B63D9B65CEF9ULL,
		0xDC3A0B62AE817644ULL,
		0x519519879ED41E73ULL,
		0xDDD60EA8ECDBADC2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 334\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xA312C9F629332A43ULL,
		0xB05C25E3214FA501ULL,
		0x4ECC779738E323E1ULL,
		0x1FEC6C071660EB2EULL,
		0x68A9A6CA573B3694ULL,
		0x81802D7FA5021C72ULL,
		0xE37750EBD166F467ULL,
		0x5416609D55E95333ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 335\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x5EE3A7C10A095AA4ULL,
		0x265F97FA7C0C119FULL,
		0xF0D4FD59712B78B4ULL,
		0x44042FA724913FB0ULL,
		0x6A45790F104E7920ULL,
		0x247B1FE6455128CDULL,
		0x6B60BA4FEECBE3D7ULL,
		0xF58487896F97D232ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 336\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xE199FEE2596E5C09ULL,
		0xD2108A11472AA3DEULL,
		0xB15A7A9B27801C81ULL,
		0x45C1FF032493F0C8ULL,
		0xC047CB8FA2C46515ULL,
		0xDD2614D70FB2D0CCULL,
		0xE6D867235AD6892BULL,
		0xE0C043B5D112317FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 337\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xD633E8E7F7F948A2ULL,
		0xF362F96D3244118BULL,
		0xAAE5BECF94295EEDULL,
		0x5C88F16E5FF18E51ULL,
		0x80BF11C99A5C5F95ULL,
		0x8C1C78F7B97C8A1FULL,
		0xC0B87639D4F9131EULL,
		0xA2D9E40BD9D22802ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 338\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x9A394C115439C36EULL,
		0x4E69F909B43A7522ULL,
		0xE18FBFD52B192E6EULL,
		0x2D530C139AD38C4AULL,
		0x7CD3D25B8408C025ULL,
		0x8A3C491A34AFD983ULL,
		0x01C71D15A34CC4C9ULL,
		0x3BC5BAD29923CF84ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 339\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x498C2E496B3B0C2AULL,
		0x07CC379EB1CE0EC7ULL,
		0x35289B8E264A7BDEULL,
		0x323DD50E0F585123ULL,
		0x07D07C4FC9BE40B3ULL,
		0x0EA8DBEB4450DF08ULL,
		0xB69C5B766BA408DDULL,
		0x1626C6500CF5E447ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	printf("Test Case 340\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x1733704DEAC48A40ULL,
		0xA251C67BC5A2B999ULL,
		0xA21A59FB91772CBEULL,
		0x1046307ED8C17E8EULL,
		0x26D51243CD9C4EFDULL,
		0x338A9A116426BE2DULL,
		0x6C795FE17061108FULL,
		0xF559C5A62FE5FE16ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 341\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xBFCD9BDD7D6968EAULL,
		0x23DAC87F6C9D6EDCULL,
		0x482B1AF6AD8F263EULL,
		0xE6ED649F8631628DULL,
		0x22FF1DDED4D9CCB5ULL,
		0xC1E5A45D19089244ULL,
		0x1400F5F44AE25C3BULL,
		0xF68F1773E6BFCD84ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 342\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xB6A0CA190289E233ULL,
		0x5E8244238CEE750EULL,
		0x853A3D44A2438474ULL,
		0x5AF243B59FF30111ULL,
		0xC420D7B3CBB15E9DULL,
		0xC332E9596D2F97AFULL,
		0xBF6EA9025FEFEDCEULL,
		0x4D6302C4715553FDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 343\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xBAB882117D6FC7A2ULL,
		0xBA2D08734EF5863CULL,
		0x7ACD6DFA4D4FAFC5ULL,
		0x8C7D29A38F166A0AULL,
		0xD2036D4AAEBF8D11ULL,
		0x447BAE4EF23C705EULL,
		0xA7C34030F8FE4AB3ULL,
		0x999DF993C82FC2F4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 344\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xC2CBBCFC5081A7B3ULL,
		0x983BA3D57C5F2052ULL,
		0x796DB2D4CB99B3AAULL,
		0x9E7A36D417AFDE9CULL,
		0xA983DE4687DDCF27ULL,
		0xFF5E3E202D6D808DULL,
		0xF5E82EABB0BEB85DULL,
		0xA97E001B057ACE47ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 345\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x7F7478D52AE136A8ULL,
		0xA2846CA9CC7FCA09ULL,
		0x58FB1B5A3BFFCF4FULL,
		0x883148CFD8696A36ULL,
		0xCEA41A8BD8EB1F01ULL,
		0x77300EB257948F25ULL,
		0x98D0834162457AE2ULL,
		0x521E31843A26A611ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 346\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x90B56F3C4554DCF2ULL,
		0x9A0710C9491AD9B6ULL,
		0x010DCD4136EF3102ULL,
		0xFF703711BB6AF1E1ULL,
		0xD14C4A4348A2C4C7ULL,
		0xE3EDF08FAE772504ULL,
		0x45D97BC1CA21DA56ULL,
		0x68243268B35C37E4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 347\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xBBA5BDFC674E742FULL,
		0x50507E55B3F1EEE6ULL,
		0x17C0159FA766A7A2ULL,
		0x2B850F880D5C3C8DULL,
		0xDFBAF24563BCDD86ULL,
		0x6EBACCCF0AD04B7FULL,
		0x241FE26A996581E9ULL,
		0x56C1A8A4D79B6F05ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 348\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x9148108B4449CD40ULL,
		0x7CAD6C0AEF4FA219ULL,
		0xEE71A5A99A7CBFA1ULL,
		0x60F4001C639151E4ULL,
		0x1DC4BDAEC2A9360EULL,
		0xF5CF4F8F2B374917ULL,
		0x18AE27D28DC5D3E6ULL,
		0x54D70C121EA03B59ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 349\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xD73D509B9B8CA80AULL,
		0x004871A7F05B2FFCULL,
		0xA5ACA3BAB799595CULL,
		0xB044AD081E07D166ULL,
		0x1E29EA180104E702ULL,
		0xC2AC1498826AC60CULL,
		0xEFE2E73B1F2A3D4AULL,
		0x2FDEE996AA0D34D3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 350\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xA17368B671A6EE46ULL,
		0x832C80985A3B9E42ULL,
		0xBC6755C2AE579D9EULL,
		0x5A10D1364C848651ULL,
		0x846B07B14BBA7716ULL,
		0xDC1FFCDAC64C6470ULL,
		0x5FA8ED2E3E72087FULL,
		0x9B03B58EB2A1472EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 351\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x7C438D92E03A27A0ULL,
		0xBEF163E803CF5538ULL,
		0xF48E3A13F65F5B9CULL,
		0x4E188B1775499051ULL,
		0x88C7AA510B733F88ULL,
		0xABCE01FF44D33D89ULL,
		0x1A3416F29781CDF9ULL,
		0x4F214435FD8D08BCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 352\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xA5D68DD0C0EA79B6ULL,
		0x74E33688FFF02D13ULL,
		0xC66069E9490AFF00ULL,
		0x9C810465C4C8BEFEULL,
		0x459A22C987D5CE6EULL,
		0x4CABF4FF7A5EB8B2ULL,
		0xF391B57C582B99D4ULL,
		0x5072790229B3391EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 353\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xD1B7B1F730431FE9ULL,
		0x33D1232A0A47BB5DULL,
		0xF86D867715F97A1AULL,
		0xD6F3D2AE0DD7D3B8ULL,
		0xFE77F1F08C12C6EEULL,
		0x636BEDF0BB3D9C51ULL,
		0xF960563B5DC354A3ULL,
		0x4ADBB30DE90B9E46ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 354\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x15D55E1062B9FCDDULL,
		0x4556674068DBA7C0ULL,
		0xDFD17E7DE29E438AULL,
		0x78A2E0BD026013AEULL,
		0x1C3AFA211CDEA945ULL,
		0x2CF1ED0C6BC79BDAULL,
		0x59645AC96263A69FULL,
		0xDDA27B30437DB1B8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 355\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x78DE32D85CF35612ULL,
		0xDCCE14740ABEF4AAULL,
		0x0DD0BB77F2931353ULL,
		0xA52D2D27D2674D1CULL,
		0xEE5B3C91C326D0EEULL,
		0xD87566A22D124FBBULL,
		0xF1E9369E689CA898ULL,
		0x1882B693898F3362ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	printf("Test Case 356\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x7DCDDEE168EABC8DULL,
		0x894E82617C95ECDFULL,
		0x5E441CBAE176EF28ULL,
		0x1A239FDAB175C5B0ULL,
		0xB645025A4CE55295ULL,
		0x48566C849649EF9BULL,
		0xDA229853FEAB2FF8ULL,
		0xA49305C6D01168DFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 357\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xFD0B49427D30FB10ULL,
		0x589B80F3CAEC1889ULL,
		0x883F36F2EA36E2C8ULL,
		0x2E3356FCBF93117FULL,
		0x86483FD3B166EF7EULL,
		0x6F521E7CC84CC543ULL,
		0xEDBDDF52A86F89D0ULL,
		0x916E34348D2C493DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 358\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xDF74EB5401E01C8AULL,
		0x043940F899D62572ULL,
		0x1C34E579B7516963ULL,
		0x241D54744F8B1513ULL,
		0x1F868AB154220C59ULL,
		0x2B9EC4F1F0CDD93EULL,
		0x5300F66DB0C8ED50ULL,
		0x80D949D862530EA3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 359\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xD419DEFB22EB9949ULL,
		0xF4EBF93E9FF0A2E3ULL,
		0xAE2618AA4233A634ULL,
		0x6873CABCE1E7717EULL,
		0x51E7D175DC2B394DULL,
		0x68F7C0039CCC3888ULL,
		0xAA471D9207650B75ULL,
		0x18C2EE88579EA253ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	printf("Test Case 360\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x75301C6B47EECF30ULL,
		0x15788A31A5F3DA9CULL,
		0x5850EEAEAB3F1706ULL,
		0x6D8D047971D50AC0ULL,
		0x21CD52B27A186BA9ULL,
		0x537BF76971D0D954ULL,
		0xCE226DFEBB06565AULL,
		0xA1E7477CF375CDD6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 361\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x8D82B166F98B47EEULL,
		0x8E2FD2C8C17F2266ULL,
		0x3DEDD9205CF5A4D1ULL,
		0x030E6179054C0D30ULL,
		0x9E62B5FD9315A52BULL,
		0x27A3EB5AE3190595ULL,
		0x315C684806BE71BCULL,
		0x7A0914DFD1B88AC2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 362\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x07FD5B28819EB996ULL,
		0x8C9106BB6904428EULL,
		0x34A740909B4ED3D7ULL,
		0x166A0747895712C1ULL,
		0xA2039ACEA3E7BB9BULL,
		0xDF928285A2C5FC03ULL,
		0x47F26EB76287A7E4ULL,
		0x54C3BC39516B0A42ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 363\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x799391A67E2BFD83ULL,
		0x0B4736717B8CC20AULL,
		0x0A1264D679ABEF42ULL,
		0x99F110F691B078C6ULL,
		0x6E311C2083B68894ULL,
		0x0DFEB863ECE0AF1BULL,
		0x98034CD95EC52910ULL,
		0x7A59C3CC2B6B2EA1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 364\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x16AF8EC73486CBB7ULL,
		0x5A1ECCA9A8C4FADFULL,
		0x3FEFFF66DB4A1B4DULL,
		0xCB9FECB35DE90260ULL,
		0x2CF47E12E8C17D35ULL,
		0x3B2DED02224C7C98ULL,
		0xA291C22CC7763358ULL,
		0xFB38A7DFC56DDAEEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 365\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x903485405334F3C5ULL,
		0x0CA2BF8E63A90F26ULL,
		0x6C398F635613CDA8ULL,
		0x9533D22F6EAB7285ULL,
		0x57EF4DDBD4A1A4EEULL,
		0x9B88C8F93C3F5106ULL,
		0x471FDFA27D51A077ULL,
		0x2BB835028C08A6A4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 366\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x0824BF0732909A63ULL,
		0x78D106A604AB6DBCULL,
		0x31D3C39093DB6BD1ULL,
		0xF5723529826C067AULL,
		0xEA8BD230A7506553ULL,
		0x2B6CE7E2DAD61EA5ULL,
		0x9186121D3AE94764ULL,
		0xE841335F71680B89ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 367\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x84DEE273EA4885B9ULL,
		0x2ED23A79A68F32F0ULL,
		0xD4B73BAD725182D0ULL,
		0xA7CDBD437494776DULL,
		0x63455E6DF0922C96ULL,
		0x828C8C9AA2190C0AULL,
		0x6863D881E318DDF9ULL,
		0xE8A7A72B049039F5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 368\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x28B75A87E46FDAC5ULL,
		0xE08687D3357C4EEEULL,
		0x5BF1D5FC75EB2CD3ULL,
		0xAC51156BA5A71DE8ULL,
		0xBD2343EA93B8F2E7ULL,
		0xD0CE26C11ED09F59ULL,
		0x667524E57ADF6E61ULL,
		0xDA0FD9EE3DAB0218ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 369\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x5014C4E100B0CAD1ULL,
		0x62E914AC47341F77ULL,
		0x22FEF655DFECC5F4ULL,
		0x08BA07C8DD358779ULL,
		0x2B0DCA6492E29605ULL,
		0xBED6F217C1095607ULL,
		0x1DF30BD6D9628682ULL,
		0xC7AEA914133B1E04ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 370\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xEAB5FD64A7A140C0ULL,
		0x0F782DFF655305ACULL,
		0xC1AAE0D1E7F55777ULL,
		0xFBC530F355FED4DAULL,
		0xA6DBACB9F5C921C3ULL,
		0x7D40208087BB2F9AULL,
		0x11A50EA5B2A6ADD1ULL,
		0xB85AEE0FE881EE11ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 371\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x5FF594F8602FE6C1ULL,
		0x06A401A28C68CC5FULL,
		0x79C19BAB936A16ACULL,
		0xACBAC434437E519EULL,
		0x13634F095FC3DC6EULL,
		0x91C5E49FF0945F9EULL,
		0x20CC1C24050DE41BULL,
		0x2B5D64D55222B951ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 372\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xC8C244114C965E32ULL,
		0xF0A1D7C352A14704ULL,
		0x14C43BDBF6462C5AULL,
		0x70D1A49318C58891ULL,
		0xB1E0FD7B0B6C5049ULL,
		0xC3AC9190321C838BULL,
		0x0E3D10F8C93E416EULL,
		0x131FA12B60D29F8CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	printf("Test Case 373\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x421A84987A7DC02BULL,
		0x5C3444528C5FE64AULL,
		0xB310264984F92498ULL,
		0x4C6A608F36AD5418ULL,
		0x9DAA38744960C70BULL,
		0x4AF2A42D0AE4B156ULL,
		0x3D388391A88B56B5ULL,
		0xEFAD419DD4C7648AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 374\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x78AF8BD1D28AE7DDULL,
		0x460195FDAAC9E135ULL,
		0x15199DA51DFCEAA7ULL,
		0x7549A78B6F09A27EULL,
		0x7F5BD1EF571F3932ULL,
		0x38417B04360CA5E5ULL,
		0x525BB5D4E0A7E22AULL,
		0x5F675EEB78AB98E9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 375\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x1E45AA90027849E3ULL,
		0x78CCC006EB7FDA99ULL,
		0xF7BDAA20B20951EBULL,
		0x412B393DD736DA3EULL,
		0x7625307A9E9EBCFAULL,
		0x213E76A7A9F7EAC1ULL,
		0x50D392737E39A7E1ULL,
		0x64C053C4ECF8A50EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 376\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xBDD4DBD4E2AFCAC1ULL,
		0x92668C1289BAD2E0ULL,
		0x62FFC5E6377555F8ULL,
		0x3A328789F5E47AC0ULL,
		0xF85699E8F99E47E4ULL,
		0xAF0CF6F83C425C35ULL,
		0x51EBD2732C8D6AEFULL,
		0xD2A378DD58E94845ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 377\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xA77AC799FC06258CULL,
		0xC808BF16EEA16328ULL,
		0x48A5F3764016E4D5ULL,
		0x7D592264A53FEF8CULL,
		0x77F856492007246DULL,
		0xDF66ED2D4E4F80DAULL,
		0x84F230F99251F48AULL,
		0xCF766A47096C4B96ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 378\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x7C31072D8D188A43ULL,
		0x18AD3DD2AFA6D4C5ULL,
		0x0DCA32EFAABD0EE8ULL,
		0x43AFE4531D85A486ULL,
		0x39FE796B4279921EULL,
		0xDE1E749855E9974EULL,
		0x3EDD01C8708E4624ULL,
		0x8F87B0151AAAD0CFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 379\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xC4AD57EF03B010E4ULL,
		0x956D5EE2784369B6ULL,
		0x25394214CE2B0270ULL,
		0xDBB3B48DD450AA45ULL,
		0xB3115F79EBBB8BB1ULL,
		0xEBFE28B25032B4D6ULL,
		0x250B2135C03102DAULL,
		0xFFC957094ABDE985ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 380\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x5A3275173C0FC7B8ULL,
		0xC9C8575B935AAE77ULL,
		0x49246A56328608D1ULL,
		0x84E5D21FEDB4C46DULL,
		0x8E894EC0DF3C0ADBULL,
		0x13D36FF27E3601A3ULL,
		0x89F60DF19C195FA7ULL,
		0xF3B1803A049D4D76ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 381\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xF29A2D2FA6CA2056ULL,
		0x42659589E5F05932ULL,
		0x5440513C7C1E078FULL,
		0x4287049DA4235201ULL,
		0x9E90B29E3FF37EE1ULL,
		0xE9552FF4D9545E26ULL,
		0x970E1BD24EE9D763ULL,
		0x0431140F81806197ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0400000000000000ULL
	}};
	printf("Test Case 382\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xBA75498551EF5834ULL,
		0xB288E1FE1D1AE071ULL,
		0x6593FABBF5D9A438ULL,
		0xC6F62B82DF18F523ULL,
		0x2A18D96658120961ULL,
		0x776ED094BDC29AA7ULL,
		0x7E1A62D465F76476ULL,
		0x6EDBF669B40FAD0BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 383\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x0D8835BB1DF3EDA3ULL,
		0x0A5559CEABDE53B7ULL,
		0xF004A2C023E10F9BULL,
		0x729BF888EE8BBAD8ULL,
		0x994BF344EECE36CAULL,
		0x8759C5D26667940DULL,
		0x5D85A7A1C1427816ULL,
		0xD51C1F95F8E2E7B8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 384\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x5FFBB43FB0CE8654ULL,
		0x8DDAC686C2F48A46ULL,
		0x4F74A8337B4B06A9ULL,
		0x8BC9616CF48D63EAULL,
		0xA02E94CEF625646AULL,
		0x45AF8023EB1060F9ULL,
		0x853E5F779E8E8D56ULL,
		0xE25796FE41008898ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 385\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x238AC52B6FF1D0F8ULL,
		0xB6F6416B33D947CBULL,
		0xCBAC0BBA5396E4A8ULL,
		0x7AEA5E7B35371860ULL,
		0xD3EBF6B79B79980DULL,
		0x3C940554D37B22FEULL,
		0xA7F3FE57AAF8D9F4ULL,
		0xFB9A4509E7C5D56FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 386\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x32319191E2BC553BULL,
		0x784CFDB0F8E08013ULL,
		0x09E6EFF1DE73704AULL,
		0x0127DE3F75E4D92FULL,
		0xE1D7C2F0DEC9234DULL,
		0xEAC2D7FA07BB7FF0ULL,
		0xACBCC4DBD6446864ULL,
		0x2464809155EB2F8BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 387\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xC030DE983F2AC7D8ULL,
		0x4224CF22ACD68A40ULL,
		0xB212D8105C82B42DULL,
		0x8F0B597F86CB83F4ULL,
		0xF34D654438B54C0FULL,
		0x6848E7832220FF63ULL,
		0xA8054E9F23595B74ULL,
		0x06D8F75CEED5BD3EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0400000000000000ULL
	}};
	printf("Test Case 388\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x031AA008A3B34399ULL,
		0x3ABD9E44A92BF0EFULL,
		0xAC131230CCE822A1ULL,
		0x16893E52681FBAB6ULL,
		0x32F9E3C9774B1778ULL,
		0x013011F9A1DC793EULL,
		0xD79BD3E193789446ULL,
		0x7E02401D6A0626E5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 389\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x8B2D516E9D021EF7ULL,
		0xCFAB81526512E1D6ULL,
		0x6219EE78D18830CEULL,
		0x8AE7C4658B1F26E2ULL,
		0x31FF44F446F7C8AEULL,
		0x95D83053B8246299ULL,
		0x9DC4338E5CF276ADULL,
		0xF8D7E00DC75ED718ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 390\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xAB789B82A82A458CULL,
		0x5740747FF0AFC5F5ULL,
		0xFAF3BD3AA41F923EULL,
		0x4343835FD8FB03F4ULL,
		0x5B22CA6FBC362E64ULL,
		0x6870B3D3D45EE894ULL,
		0x30E99130458E5628ULL,
		0xC4C4C07223A1236DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 391\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x94E7BEB8761655D7ULL,
		0x51E6FD9CFFF35F18ULL,
		0x5841AD3FF1D31702ULL,
		0x38A249F59CCE9F8CULL,
		0x81A19CF95581A428ULL,
		0xF4C5A332FF99A47EULL,
		0xF8526864B82EC570ULL,
		0x9F4BF7395D80BE9BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 392\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x154B343064627BD9ULL,
		0xE0FF77888E7E4D23ULL,
		0x4943C1139324F9DEULL,
		0x75EBE60127BF5056ULL,
		0xE4D1B35587CD1B51ULL,
		0x2CF3A9DC23759B39ULL,
		0xAFCD7AC5FC939188ULL,
		0xED217AFF2E2001C3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 393\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x3187AC3662AB176EULL,
		0x8D74678360A99594ULL,
		0xF5A9DB9E1F7F859FULL,
		0x92A25EEBDA3CE275ULL,
		0x934B13D695CF797EULL,
		0x7FE6852CBB6886EAULL,
		0x44F51894F71A997AULL,
		0x370E034B612EED63ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 394\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xACD45F14D88711E1ULL,
		0x8A36F544A67F2107ULL,
		0x04DA7615F937F45EULL,
		0x726B9470975FDBC8ULL,
		0x36C8CD0D08D09868ULL,
		0x33376546C03DB3FFULL,
		0x21FE2BD881D1242DULL,
		0x9836D57E85561ECAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 395\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xA20C34E6825C8B52ULL,
		0x79D4016B9265119FULL,
		0x4E59DE6ED47D9C8AULL,
		0xAC4DFA4DD805FE71ULL,
		0xD3B25FE82A008989ULL,
		0x4E6AFE2E3A1A21B2ULL,
		0x83B5277A9FD82428ULL,
		0x2744AA26A8EE916BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 396\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x7EB047C2F51BB857ULL,
		0xFA5F2FBAF2F9F797ULL,
		0x20A2A1DB26C7F997ULL,
		0xCE83A2BDE098D28BULL,
		0xA69511A1C53A38B8ULL,
		0x507A5F1756EF6550ULL,
		0xD39C7CC2BC7CF6E8ULL,
		0x10EE9E806108E4FAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	printf("Test Case 397\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x8D3DC30406BA12F8ULL,
		0x2CB99B23383DEBE2ULL,
		0x52BFF2D796AF7F48ULL,
		0xE0664792E015B127ULL,
		0xB8CC3C8FEFFE62DFULL,
		0x2045E810CD3C60A3ULL,
		0x45933A2BFFD292F4ULL,
		0x066C08AD89C1DE4AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0400000000000000ULL
	}};
	printf("Test Case 398\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x4067EED66F01D6F7ULL,
		0xB4D4A54797473948ULL,
		0x2C53A1E5DBA73130ULL,
		0x9A858839296B2FFAULL,
		0x5F8D0A373DA9C24BULL,
		0x4C3333F0F8459D10ULL,
		0x03D5B95B4ED55431ULL,
		0x64ABCC7A2FDF17AAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 399\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xA37931F6A368EAF8ULL,
		0x315BDCBF6A0F5FD6ULL,
		0xB28134CEEF7B7383ULL,
		0x6F446D8299E954E8ULL,
		0x1578EFAAC378B4AFULL,
		0x31935F73131D2D54ULL,
		0x04A18F4D51B231D3ULL,
		0xFA9E102B7E731666ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 400\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x53EE5D39E3D3A7DCULL,
		0x68DFD75533F22A3BULL,
		0xD88363B3A6A36B58ULL,
		0x573F3E27EDB851D9ULL,
		0x233E26F09A66BB63ULL,
		0x3CC5D24EE4A5EFCFULL,
		0x317C0417B53CC005ULL,
		0xD49AAD229BD97BD2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 401\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x148DD73CB13D7B10ULL,
		0xA1AB0EB35D4949D5ULL,
		0xE5C8254D4142C111ULL,
		0x8E06C4F47E230144ULL,
		0x84E545A620FA340DULL,
		0x2F45E711FEE5B2BDULL,
		0x1C1B7BE188E1E183ULL,
		0xBD7B78F144048D1DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 402\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x269E2C51A916F9BAULL,
		0x20DED3D68EC3670AULL,
		0x2591D514D0C7B356ULL,
		0xCC854AC6FD3D1461ULL,
		0x8A1FE0E7D2AD3200ULL,
		0x140398BA6FD1388AULL,
		0x67BDE65B02D19BA6ULL,
		0xB4690E00166AAE02ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 403\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xE225551A8BF08D04ULL,
		0xDC405DA83E61E1DBULL,
		0x4635F25BB0D077D6ULL,
		0x85E9E7144E448E4AULL,
		0xD6792B7E5C22B2A1ULL,
		0x5A7A1AC671615B20ULL,
		0x248DFD29A8BDB7E0ULL,
		0x4D5041414F7A2E33ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 404\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xF12CF52BCB70D28CULL,
		0xAD0F749A635DB13CULL,
		0x3F392B4768CA8D51ULL,
		0xCA89E5B197A6127EULL,
		0xD7668F57D7961273ULL,
		0xC173532D16E9C5F8ULL,
		0x5C9434BC640E1BD6ULL,
		0x828F3D4BCF9FFCDEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 405\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xA81B9248E50F6E07ULL,
		0xA0A77B61074D8D10ULL,
		0x4172AEC18912F27EULL,
		0x77001135885F27C1ULL,
		0xEF23937F64CA72D4ULL,
		0x8A0D97EDF8A5B661ULL,
		0xD7D6240D0BE7B856ULL,
		0x09EF0B1CC2298EA7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0800000000000000ULL
	}};
	printf("Test Case 406\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x241159962F1BB85DULL,
		0x82619C7BD51C7943ULL,
		0x5FB1893D2BAA9CC8ULL,
		0x87060D46F60D946CULL,
		0x17153A73ACC4762CULL,
		0xB7BBDD5A3B938FC3ULL,
		0x8A8C6C26BDE3955CULL,
		0xFE69155980DDD99FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 407\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xFD3D8DD5C5E935D0ULL,
		0x09610841EFB45923ULL,
		0x6DDA0CC842D8C428ULL,
		0xFD1C230A33943F8DULL,
		0xDD5FB69BE0DA4013ULL,
		0x3B4DDF3577315276ULL,
		0x74ECBA7B977FD067ULL,
		0xC1CA39B9674A0DF1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 408\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x13CADA071B618B4AULL,
		0xFF1840C1D73DB8CCULL,
		0x47C8CC70D4F6D3A0ULL,
		0x815C6B13CC0D4AF0ULL,
		0x5B45BFE550058AB1ULL,
		0xA1B5DEDC635D4325ULL,
		0xD55A0B43C0548B36ULL,
		0x9684082573B0F191ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 409\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x47DE495D3CB49F2EULL,
		0x165BECDF380F1769ULL,
		0x339CC53A03057839ULL,
		0x2FB72060507C8C80ULL,
		0x6AC89DB16ACD740CULL,
		0x1FF79848CD445CAEULL,
		0x26E9359F0253DFF6ULL,
		0xEA0DF6B8D3E39D00ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 410\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x776E752099768108ULL,
		0x92FC705C1ED951CDULL,
		0xF8C6A5F8138B1FE8ULL,
		0x4576B47D2E63FCF1ULL,
		0xF4AEAA9B16AD5DF0ULL,
		0x3780A2BA18204EE2ULL,
		0x73E7BBF7A1AE3FA4ULL,
		0x6CF881824F8EEF6BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 411\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x93EECDDCFF7D64AAULL,
		0xADE6B543F073DEDBULL,
		0x48D2CDC0F8BA2CD9ULL,
		0x007D5735D99A73F8ULL,
		0xA4AF73C6682FF432ULL,
		0x8A7EFF26995BA0E9ULL,
		0x9CC95B0228183988ULL,
		0xEC74810EA3C4B64FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 412\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x674B720623736C1CULL,
		0x0D0425256EA49BB9ULL,
		0x92F80D77F3531354ULL,
		0x17731C6C16CB2403ULL,
		0xB2CFDC6D3ED63A02ULL,
		0x1C84A4C2C9E716A0ULL,
		0xDE4DA5C6A7C1B2C2ULL,
		0x60EA9E88912D7145ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 413\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x49E8AA24BDC1F5EAULL,
		0xE6072C067409E265ULL,
		0x259CFDEC4C280BDAULL,
		0x28C41C1F09F11BB9ULL,
		0x7C1BF56EB51D2B3CULL,
		0x21C941C2A1E674E9ULL,
		0x7180E652B02A9396ULL,
		0xC01E990F3AF6B5B3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 414\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x36A230B8CD2EDEA7ULL,
		0x8CDD7AEB7840A78FULL,
		0x0628D93D9479F6FBULL,
		0x025B7A882F952FFCULL,
		0xEDC69C986D6051BBULL,
		0xA70951CF000A2C9EULL,
		0x47FF8401D3A6E835ULL,
		0xD293385B6D150B09ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 415\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x685ACBBC4C19BC17ULL,
		0x141B0242D463F999ULL,
		0x2910EE1674CB8088ULL,
		0x2FE873F359091559ULL,
		0x408B4E3CC7F1F634ULL,
		0x2A02221CE8EEDF13ULL,
		0x6449D3A0EFB09C37ULL,
		0x5BD60C011F9B705CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 416\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xF47E2D43F6D2D2F9ULL,
		0x720E545D46CF90DFULL,
		0xD38483FA4A3E675FULL,
		0xFDD0E26CA7342035ULL,
		0xE2AAAA60691AAE2DULL,
		0x24673774C326CC1DULL,
		0x945C73CF1C50499FULL,
		0xEF669509F8C13E8EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 417\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x829568E25CB74CC9ULL,
		0xA768F088778E2A0CULL,
		0x83E2468871FAF92AULL,
		0x17F4BF5FCB845B4CULL,
		0x4C0297880FC04BE5ULL,
		0x70AEB541E4B46E45ULL,
		0xDC02F743A8D75B63ULL,
		0x2E6D9E5018B36BC7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 418\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x8FB2CC52FF6D9CFAULL,
		0x6306C9A53AD8AD3FULL,
		0x4ADC55FD2571E458ULL,
		0x007DEF5A34F97EDEULL,
		0x92F4A28E098CD274ULL,
		0x9D6C796F27E7E68CULL,
		0x325AAC88823C33FAULL,
		0x07403ED12CE1C0F4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0400000000000000ULL
	}};
	printf("Test Case 419\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xC3B0B2C55A714008ULL,
		0x75C0540C0B6345E4ULL,
		0x71327A4651CEB5F2ULL,
		0xF61C637EF5330B5EULL,
		0x4818C40E89F3A799ULL,
		0x9F632D67D732CD3AULL,
		0x62ED029BB8FC2507ULL,
		0x4FAE01FF26825725ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 420\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x8B1768069B337FB0ULL,
		0xC0A6AFF6E56E63FDULL,
		0x798F8FA3B7B78320ULL,
		0x99D66D99E1AF0396ULL,
		0x64766D4273958429ULL,
		0x6C336574AC13105AULL,
		0x932ED8D7D204307FULL,
		0xE448C198E964F5E5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 421\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x8A22103207356D8DULL,
		0x07669854A18DE447ULL,
		0x882138F4A8213CBDULL,
		0xC74A93BE435AEF59ULL,
		0x3727E4C36841C917ULL,
		0x077C72F617D7DB96ULL,
		0xEF96B45BEF1B056AULL,
		0x8B5937C13CFF7DF6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 422\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x56376D0EA50C812FULL,
		0x70C96AD197392021ULL,
		0x8B9433DB0B555649ULL,
		0xE698708EDBACB27BULL,
		0x233E07BF5307B301ULL,
		0x7977B54EF256519AULL,
		0x123986F5D808A21FULL,
		0x76571F0C9F4DF08BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 423\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xD58499A166B87352ULL,
		0xE350CD63A2ED0BC7ULL,
		0x75EC6E7CFBA8977EULL,
		0x6EFA423E22DA25B0ULL,
		0x37FB953F499F41D1ULL,
		0x499AE1AAE1C88B5BULL,
		0xF1DA2BE58B5E4381ULL,
		0x54986EC643B9B5E7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 424\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x529FA0C86329C702ULL,
		0x9C831C5A19061CD8ULL,
		0x1E446775B4AE2D38ULL,
		0x1971D6FF4FA6A263ULL,
		0x2BC1ABC01A924D0BULL,
		0x1836A23A172A9992ULL,
		0x4A125CE8E818DBEAULL,
		0x7CD75B3056290BAEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 425\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x11135A508AC82E72ULL,
		0xEAA1B7B697195322ULL,
		0x3F634FFD14082FA8ULL,
		0xA42C790A891D9B8FULL,
		0x7A0734D966AA3A5CULL,
		0xFD3AA2CDD1EE4574ULL,
		0x32080B0590F6742AULL,
		0xD8ECB07547C93DC6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 426\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xC0128340B3D6028FULL,
		0x9A1CA7C856A35DE7ULL,
		0x01BF9595C858D3C1ULL,
		0xB859A8077CA15C1BULL,
		0x268B0B26D929F688ULL,
		0xDD12C3A2DC411428ULL,
		0x005A32035237A6D5ULL,
		0x079F522F48A0F23EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0400000000000000ULL
	}};
	printf("Test Case 427\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x78B47A78B6860B5AULL,
		0x0646424FA7FC7FF8ULL,
		0x9F8A049D8AF19E31ULL,
		0xCDE85336187DF260ULL,
		0x75175C642110A3FDULL,
		0x37BD77D89E79742AULL,
		0x6EF99555F3A8D108ULL,
		0x3BDB3538C4E0C74FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 428\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xC5B9D2A91F270D69ULL,
		0x4E4C006040C8992FULL,
		0x86C9E6367C7431BBULL,
		0x6D7B95BB9B23B97AULL,
		0xF1A11A39C92D4E79ULL,
		0x4732FAEE7EA60665ULL,
		0x8FEBB88853D671EAULL,
		0x6C58918998DCBD26ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 429\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x728585829BF16BE5ULL,
		0xB3A8322738DDAE96ULL,
		0xD9E6109DB1FA5D97ULL,
		0x7EDF2FB068EC4031ULL,
		0x07FC2CE5FBCD687BULL,
		0x616159BCBF9352CAULL,
		0x3A8AEA41E89DEA3CULL,
		0x70FA5E052F002B3DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 430\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xF2C3C278C8B0751EULL,
		0xFFFC188905BE3629ULL,
		0x0567D1AADEBA46ECULL,
		0x47DEEC8385EA1F0AULL,
		0x2EE6AB8DF0C5846BULL,
		0x82E39DAEEF5FDC47ULL,
		0x673F386F6E806B1BULL,
		0x404EAAF1CE8D2832ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 431\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x5ACED91A92AE670BULL,
		0xA54279FF2DE64FB2ULL,
		0xFB783CE408DCD311ULL,
		0x42F19570C3ECBD9DULL,
		0xF327E59614274B40ULL,
		0xAF129D87C31D6315ULL,
		0x7FFE7D72842E95D1ULL,
		0xE231BF38E6437DE1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 432\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x5EB0D11879ABEE8BULL,
		0x11EDA33336BA8F8AULL,
		0xA515097809F4F6F0ULL,
		0x5082A32B399DD2E2ULL,
		0xB6630660816F68DAULL,
		0xD30B4EC2B7099AADULL,
		0x6DC0C691D3A47E4EULL,
		0x65583C8A11517D24ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 433\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xC0FF8EF6AD309902ULL,
		0xF40CAA5EE8CB3E97ULL,
		0xB5B465D7AB1DFBBFULL,
		0xCD81CACFFEB05F6CULL,
		0x14AE5B88879CFF3BULL,
		0x120F370A38EA718FULL,
		0x787EBCE6CF9168B6ULL,
		0xDBD9396C9A03FC0FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 434\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x2E665B56B9F0032EULL,
		0x1902CEB60203589BULL,
		0x2FC57C266CAA1E5CULL,
		0xBD107504C66AC623ULL,
		0x6DBAAF40575A25DDULL,
		0x550CF9E03BF38B83ULL,
		0x4ACA204492C196E4ULL,
		0x32A27BD7E44B9E18ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 435\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x8AADB58A4ABA0E4CULL,
		0x233040566BFE03A3ULL,
		0xA34D4DA8912ACB80ULL,
		0xB54B429C7B0DFFC9ULL,
		0x844AAB612BFF5848ULL,
		0xCA28D0B6B3621E39ULL,
		0xEB5DB6E80EE2E7E0ULL,
		0x428B7225CEC50105ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 436\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x00F0D94305F79B6FULL,
		0x1E3ECF1BA2A301B0ULL,
		0x7BCE4244ADDCBCC8ULL,
		0x5A3826827F081624ULL,
		0xE98C3B4C53C72191ULL,
		0x95449411BB9AB78EULL,
		0x78C881A0212CE35CULL,
		0x5AEF09FD0C06E109ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 437\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x55484806A5D945AAULL,
		0xF1CF812374534734ULL,
		0x9AE0FF1446237470ULL,
		0x54563251F50C3BB8ULL,
		0x27C09536A415A1E8ULL,
		0xDFD4A681A3C90945ULL,
		0x172FD8C5E5DDC1A8ULL,
		0xE405E48F017B4D3AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 438\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xB1AC8BC15664C69EULL,
		0x2284934E2D3255D1ULL,
		0x0B9685B5B90BDAD3ULL,
		0x8B265CA2AA6D1E08ULL,
		0x04D9B5FC7968E38DULL,
		0xCFA627598BE2EB59ULL,
		0xFE7A8EF226A256EAULL,
		0x295B6C2E3EC29DC1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 439\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xB1AEE5A5E398F7A2ULL,
		0x2BAA4E1B244AF326ULL,
		0x9425BE3F59AEA676ULL,
		0x487ADF80B4844DCBULL,
		0x0899BC54212372B2ULL,
		0x31D9DCEC2BBE1CD8ULL,
		0x7F19895B7DB32110ULL,
		0x4CBA481F2C4B0EDAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 440\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x7C169DB254BC0B2EULL,
		0x7DDF29ED9D9D2605ULL,
		0x7709EBEB1C3E42DDULL,
		0x3F64099E56254F75ULL,
		0xF3F0F84DE727CEF5ULL,
		0x5292AC32456E8463ULL,
		0x41F3AD0351EA6404ULL,
		0x6C619D7F8EC1E008ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 441\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x9E2D49409E77AFBAULL,
		0x651C85CFED6A5D22ULL,
		0x8EB67CF40FD540D1ULL,
		0xB7C71AE97AE86D1EULL,
		0xA44FC41A833DFA80ULL,
		0xD11E16F7B13FEE5EULL,
		0x4345A7E0AAC6F94AULL,
		0x6CD90861AE5A51E5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 442\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x642DFDD48F0A8A69ULL,
		0xC4BABBB6F742CA0BULL,
		0x0AA491997F71AD39ULL,
		0x2DED3F49FB5602D8ULL,
		0xF01089435C50B2A9ULL,
		0x1AA730F598C0BAF9ULL,
		0x3FB051967B9FC233ULL,
		0x4ECDC7CDA19FCF0FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 443\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x4C38042A75D86FFDULL,
		0xD56C4B33EBF69E87ULL,
		0x0EEBFD10363106ABULL,
		0x1F5BD53D5A1F524AULL,
		0x177F7A3DC719BEACULL,
		0x906F66B9FAEAC345ULL,
		0x2FFAFD0C539A6C70ULL,
		0x67833359DF9480F5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 444\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x66E4EFE590FBD833ULL,
		0x5FC5345E9A399D11ULL,
		0xE864FA341EFDA379ULL,
		0x23ABE092A7CCC0F6ULL,
		0x4A052D9C51AEC84AULL,
		0x78FD72F2A0B9566DULL,
		0x447800D86BB9CE26ULL,
		0x02C1ED0604509438ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0200000000000000ULL
	}};
	printf("Test Case 445\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x4887FBFBCFCC4BD3ULL,
		0x05930155403C6C5CULL,
		0xDD3C2BFA9287E569ULL,
		0xC12E7FEA04B59348ULL,
		0xC643C0EC0E8DF3C2ULL,
		0x13759E866F3E9E10ULL,
		0x06E613F68ECD09A7ULL,
		0x23AA16E557442633ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 446\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x2F679A06A1A36261ULL,
		0x8B829DCE4E08E033ULL,
		0x8B78E14E89A08283ULL,
		0x888516B7227890B0ULL,
		0x26631E40A12BB991ULL,
		0x3254D2C872653AE1ULL,
		0x56748023C5A2CC79ULL,
		0x07DD3C505D043964ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0400000000000000ULL
	}};
	printf("Test Case 447\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x5CB5C81C79B2B1B7ULL,
		0xE34129D9A797527AULL,
		0x102C35DE28C66FF0ULL,
		0x550927625EB1F453ULL,
		0x8DEF478BE031E92CULL,
		0x655B2792564F1B24ULL,
		0xF115480E5F03A660ULL,
		0x2C2CEDD1A1766C16ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 448\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x9751FE27B2E45FDCULL,
		0x7F5CB2F94CC94D05ULL,
		0xAD723AC8E0288C22ULL,
		0xC6B38E4549E5DB40ULL,
		0x91BFB9E968D14EA2ULL,
		0xFB81B9DAD064ECC3ULL,
		0x880BDAC81B4AD0E7ULL,
		0x29CF9ECD376C2BA5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 449\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xA663196F228B12E9ULL,
		0x992222E6DE33A70BULL,
		0xD967ACF119448CD4ULL,
		0x4532666B84BCA66CULL,
		0x3D77F2A21219936CULL,
		0x87C129607272A536ULL,
		0x59277AEC7BC7D3CCULL,
		0xA7C4C81A86D4769EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 450\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x5CBA1070F4DE7912ULL,
		0x254F87FA079620FFULL,
		0x95149E5B618106ACULL,
		0xC26D7C7806C7FF79ULL,
		0x0EFF118F98BD1BE7ULL,
		0x00259867EA912834ULL,
		0xD3B81A102AF6B98AULL,
		0xE435507A45970CA5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 451\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xFC78991E04558B24ULL,
		0xCB5D7C825F6C02AFULL,
		0xAB057930BE1E3677ULL,
		0xCC3AD4A4675F9116ULL,
		0x6DC44EEF514A0011ULL,
		0x049B08D269543420ULL,
		0xDB0EFC7353D37458ULL,
		0x55ECF120E975C4F0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 452\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x481CD910A1B4BCCCULL,
		0x6B46F1BEE0EF2EB6ULL,
		0x82E9A3852F32D6E3ULL,
		0x9346BAF498386A3FULL,
		0x14AFEEB91BBEB9C2ULL,
		0xDBE2F1E1567B7664ULL,
		0x297ADFF8DDF02766ULL,
		0xA5BE79DBFE9CEADAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 453\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xEAADB1D5B63A1323ULL,
		0xAD2A81F56A85707EULL,
		0xC303A9F14D726E40ULL,
		0x706C91B7E058C468ULL,
		0x2C3E58AB7AD95B7DULL,
		0x017721C903F55025ULL,
		0xD33DBBDE47B318E1ULL,
		0xB281A114FEE8A1D6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 454\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x17E8E632F8FCA8F7ULL,
		0xF4985433E83EB39CULL,
		0x6EDA2AD0FEEADBA4ULL,
		0x02CED6855CB6E8BAULL,
		0xB07D993E7B0C972CULL,
		0xE7BBC9FFB0DA1B3FULL,
		0x59D8815A2C0DD322ULL,
		0xB4BF8EFE0F595E73ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 455\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xEF90B4A39BD653EDULL,
		0xE25B2B109889B1AAULL,
		0x07CE1F7721048C8EULL,
		0xC237C415FBC288F4ULL,
		0x1FFC3F315CACE4DEULL,
		0x196FFB918EF86799ULL,
		0x4C227CC6704DEE76ULL,
		0xE83E3D06DEACA33AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 456\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xE77C019B1E442543ULL,
		0xEDD5603DD41B1E78ULL,
		0x07245ECD5BDF0859ULL,
		0x850147A6F9851461ULL,
		0x311443FCC7AA15D7ULL,
		0x9379B9014ACFFFFDULL,
		0x0CF4A488B8661EF6ULL,
		0xFD195A429F4E5EE3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 457\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xA96C09FE10AE400EULL,
		0x4E5BD69F82FFC573ULL,
		0xC3AA5560FD918E2CULL,
		0x1B0D95664DE63EBAULL,
		0xD7DC2E8912E595CAULL,
		0x118D2ABA51F2E48DULL,
		0xEE0687D12D20F46CULL,
		0xAA8FDC7F124AECB9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 458\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x01278C8E3785470EULL,
		0xED030284B57C7E58ULL,
		0xA86C0E0D43ADD532ULL,
		0x0E1AE9BBD362F102ULL,
		0x4F92BB1A1D58AC7FULL,
		0x7AD68B08E8FD5AD8ULL,
		0x4AD497BDAD719151ULL,
		0x6228E8B598A746EEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 459\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x9E936312B7965CCBULL,
		0x7B0B758D21CA2AA2ULL,
		0xBFDB4652774F99A0ULL,
		0xB05E10B9CC44BA9FULL,
		0x88ECAD382BC219AAULL,
		0x01651A8E1F3E3E1BULL,
		0x901C7E4F2AFC5584ULL,
		0x67D24089C3842336ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 460\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xA92E23F2E694CB7EULL,
		0xA79EE5F48792326DULL,
		0x577ED869F5401CF1ULL,
		0x1FE12F50C7111395ULL,
		0x5FEE8D6D5786B73DULL,
		0xC81D158A25336C0EULL,
		0x02355A982077359AULL,
		0xA8904F4A81A5117FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 461\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xABF9DFEC8D0ADF34ULL,
		0xA8350A9817564E8AULL,
		0x21CAC0EC3F3A95E0ULL,
		0x4A4201F89E808F74ULL,
		0xF0C65DC055AAAA4EULL,
		0x3197674229D35C54ULL,
		0xCD4A5700B5106100ULL,
		0x2E78B240E64B5713ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 462\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x389A539A4BCD00D8ULL,
		0xF62F7F24594612D9ULL,
		0x226701AD44EE928BULL,
		0x1F95A2DF831C1460ULL,
		0x0639F963BF0DE277ULL,
		0x3234E87979687C1CULL,
		0x6417A65275211A8EULL,
		0x02DC4966F2EFFE71ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0200000000000000ULL
	}};
	printf("Test Case 463\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x14DEFF0C592AD83EULL,
		0x479FFA2C7BDF9E3DULL,
		0x79A763E2BA60171DULL,
		0x486121C33F5D3EA1ULL,
		0xFB1836E08A34F1F4ULL,
		0x7D8B54373A43D325ULL,
		0x20F2E2CDFC72299CULL,
		0xCB061CD5382B85D8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 464\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xF5E63D693EAE1C4DULL,
		0xA2A05158CE648434ULL,
		0x760A907CC182BE6CULL,
		0x5ABEB15198CE7593ULL,
		0x42F1B733550EFA38ULL,
		0xD103044337AD9A40ULL,
		0x12728D16E1926857ULL,
		0xE2DB803C88A53DA9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 465\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xB20DA4A4D118121AULL,
		0x6EB361FF79D5932CULL,
		0xAFE7269D7AECDB8FULL,
		0x665D05CF034DA9CEULL,
		0xCEECB3AFD06E12E1ULL,
		0x3CF5D652DCE54629ULL,
		0x97797E2037746409ULL,
		0xD874590CD56B3003ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 466\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x3FC2FB9E4ACE0A20ULL,
		0x2EC74016E8228A3CULL,
		0xECB4EA5F5E936585ULL,
		0xB92B3FB03434120DULL,
		0xA729A121B57DB3F9ULL,
		0x0720B094D4D73BCBULL,
		0x766E389A6F912FC3ULL,
		0xC0D98D7C9863D82FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 467\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xD05815ECEDF74EF8ULL,
		0x3CE4DA0E916BF49EULL,
		0x94CAECB41BC80F4EULL,
		0x0B2D180716147108ULL,
		0x64B898B68350CBC4ULL,
		0x39FF1CFB96904050ULL,
		0x87328D95162DC716ULL,
		0xD2D22A3CB71C4CDCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 468\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x111997734E0D38C3ULL,
		0xAD26087C89E964A1ULL,
		0x9D1A8350FCA2F692ULL,
		0xD7245A93522EC45DULL,
		0x8133FD8550627773ULL,
		0xA7B9B9858C5F2CD3ULL,
		0xF67F07A82DE8D4EAULL,
		0xBC0198385802EBCCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 469\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xAC4F3C954CA49E28ULL,
		0x84533C2DC29B0805ULL,
		0xCBFAA64EC8689CADULL,
		0x0C004F62E103087CULL,
		0x31E92DB673878A36ULL,
		0xE490FE4CFEA1503BULL,
		0xE50F61A5AB443F86ULL,
		0xA6254775050D4C31ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 470\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x2E3878F390DF646DULL,
		0x47C4C77911F9F7A9ULL,
		0x098E362EF313DC54ULL,
		0x0C468ADB61B4F0C3ULL,
		0x89F0005C8750E7BFULL,
		0x29F695E4EEE7E3F7ULL,
		0xB1625F6E6AC5B047ULL,
		0x4623C157ECEBDD76ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 471\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x04BA300C1D363BEBULL,
		0xB4D2C75EB9501DBDULL,
		0x24BDD6A8896C69E9ULL,
		0x2F941EADF77D16DAULL,
		0x4B84481C42B24993ULL,
		0x87DB495FD585CE8DULL,
		0x7A4C0EDA58263BC7ULL,
		0xB8D199B7021C49B0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 472\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x1C19B1768FF35088ULL,
		0x9E3FD9DC40230D73ULL,
		0xF093BA0A5A9392BEULL,
		0xCB64AD6E9D077EDBULL,
		0x76A0AAE85A5EC059ULL,
		0x7959991F3FB53C54ULL,
		0xDDB06E450BB63266ULL,
		0x02C7F8958DD380CDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0200000000000000ULL
	}};
	printf("Test Case 473\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xC960DA5239816786ULL,
		0x6B0E34D66766B01DULL,
		0x45FCD17A869B5E72ULL,
		0x0132BCFAC006B327ULL,
		0xE8400CE102E73A8AULL,
		0xC810383DEC1DAC71ULL,
		0xEC6C44832D7CA0A7ULL,
		0xD0535DDED566BCB8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 474\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x0DFC49064CED3FEAULL,
		0x88C3D78EB42C74BBULL,
		0x0464A295DACCF177ULL,
		0xCFD56386B147F36CULL,
		0x6097EE0D743A7C08ULL,
		0x6DDC0ACE21C05CC6ULL,
		0x4D6CC24307A8A5EAULL,
		0xF26AC89423A19FE6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 475\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x44ED25E856B58B8EULL,
		0x41363F6D63003CE4ULL,
		0x51A9224686E1F731ULL,
		0x5DC69AA688281B99ULL,
		0x13786DF70FCA7772ULL,
		0xF95B9139C957FCD4ULL,
		0xF3601BFCD163ABA9ULL,
		0x094418326423AC0CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0800000000000000ULL
	}};
	printf("Test Case 476\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x1DF8CCEFCCF92CC6ULL,
		0x73E7156720393B78ULL,
		0xF9AC255EFF7EB2FCULL,
		0x37708613D31AE182ULL,
		0x02023C75004BA38CULL,
		0x1AB422B6F5C558B8ULL,
		0x9446B8E582CAA211ULL,
		0x397A01DB677D726CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 477\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xDE5E0A1A3A065FCAULL,
		0x0F3333B0D04ABCBDULL,
		0x9F1AECCCBEB9C23DULL,
		0xB58B3FCCD7C6D9CFULL,
		0x4D3E0EA9BE9BB8C8ULL,
		0x98285F1B4691D16EULL,
		0x7F9EB72A8913FE9DULL,
		0x881AD76DD02D052BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 478\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x23B9F32613E6FB6FULL,
		0xE25B8377146F1537ULL,
		0x28D16025A30C7D81ULL,
		0x17FD0A0E8CC58CC7ULL,
		0x7653BDA649BF8961ULL,
		0x57C7ADFD11166F76ULL,
		0x4A3877C1EA70531DULL,
		0x4FD66C8642D8616DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 479\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xAB2BED7B79BCDB7EULL,
		0x0C7CA663D2C033F7ULL,
		0x5DE00A5F68369437ULL,
		0x73CA6F58A85062A4ULL,
		0xEBC9403A7C9CA912ULL,
		0x07D9D7FAD6CB5021ULL,
		0x2A89F66EA275DEBFULL,
		0x5423444614B426B1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 480\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x5EDDE89B218A2170ULL,
		0x90AA01627FE01EADULL,
		0xAF77CB3B85178EC7ULL,
		0x466EBF5D37374CAFULL,
		0x43981FE72BAE9814ULL,
		0x645567C7B487D4CAULL,
		0x78A3C466B9B7115EULL,
		0xEA49C7E98B196FF1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 481\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xEC893F71402DD2A5ULL,
		0x2CD96BC8761AC180ULL,
		0x0DC439BA762639EBULL,
		0xE272FBF709C99495ULL,
		0x947E0FB634243AA5ULL,
		0xF4180D7C02FB945CULL,
		0xF6EFF3FB9BA14184ULL,
		0xCB2E1C9A68732A6EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 482\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xEC94C1CA872FCF00ULL,
		0x7246DB823F7E3663ULL,
		0xAE57DE6876318C25ULL,
		0x4DDB90B047C41638ULL,
		0x5F8CE40A9ED89198ULL,
		0xF64847324EFBF535ULL,
		0xCAB922E242028AB0ULL,
		0x13A9D1757249C0ACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	printf("Test Case 483\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xD1C684FBBBA7AFB9ULL,
		0x80834EC2031DBAA1ULL,
		0x01C9F85A1E5C5947ULL,
		0xB215C4627DAF3F27ULL,
		0x6015A7D803EF6E85ULL,
		0xF1CCA589274DE297ULL,
		0x773FA483BFAC7744ULL,
		0x02B821E9A220A1F2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0200000000000000ULL
	}};
	printf("Test Case 484\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xB75D6A4C2282D02BULL,
		0x4F8B16159AE73154ULL,
		0x6005CEEDAA168FABULL,
		0xD9E2C3D1F97E520EULL,
		0x6AE6E538778D5959ULL,
		0x9C31716D621DBDE9ULL,
		0x2435B032145A1FD1ULL,
		0xAE9E041538F0BF62ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 485\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x63FBCB2AF48B0672ULL,
		0x4AA666BAD19E27E6ULL,
		0xFE0F49FDB50A19A8ULL,
		0x2635DE12577A9536ULL,
		0x20DC7947DA3016E7ULL,
		0x5DC55486410E8A2CULL,
		0xB51CE8F986EB5C18ULL,
		0xE8A6C1832A5EB52DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 486\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x06BF65DEE638AA1FULL,
		0x14BFC1B27E6940DDULL,
		0x4A26A3CDE722C212ULL,
		0x5AB33226BAB341EFULL,
		0xF0C7EF30A1C82024ULL,
		0xB7D09EA3C2EDD427ULL,
		0x67CE38AF22F5E051ULL,
		0x77CD6D8A51940188ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 487\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x146FF1306D46F341ULL,
		0x82B51B5FC40AD631ULL,
		0xD825C258BB64AB19ULL,
		0xE296C8BA424A6C7AULL,
		0x4FE51D7BB9F84138ULL,
		0x0BE77E901D9E34CCULL,
		0xDF717B5C2887F035ULL,
		0x70E30A255C2AFAECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 488\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x28BE4A4D832F0FA1ULL,
		0xC44459C2B5A4BA3DULL,
		0xA79D967F5A4A6CF6ULL,
		0x5207B579E80448A5ULL,
		0x5E3B29AFED003BF3ULL,
		0x96E11A29B1940917ULL,
		0x06EA16597C288379ULL,
		0xBC4E804136F1E179ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 489\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x4EAED0A88AF4A58AULL,
		0x3C462F54A54F1249ULL,
		0x49762C54199FFFF2ULL,
		0x7B85268C787A8F8FULL,
		0xD3C37562F9CD580EULL,
		0xA144688A2A2887A3ULL,
		0x95261528E8D379E2ULL,
		0x3DE0AC987F0E79D7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 490\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x080735F6A9E38B15ULL,
		0xAB4845D21E725ADCULL,
		0x5D1CF011E74E07FAULL,
		0x8B039502C6A5F62BULL,
		0x0930283BFF2B6BB0ULL,
		0xB20316480A8A7097ULL,
		0x986CB5C429037FEDULL,
		0x4318D075F02E5EFDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 491\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x6D342FB1002F9DB4ULL,
		0x1D74514111ADD2D0ULL,
		0x4F589121EC57AAC7ULL,
		0xD8D5ED70ACB4A84AULL,
		0xCB171386798B4421ULL,
		0x7FB051467FD60A97ULL,
		0x7F651DA4EB4A2467ULL,
		0x7232030A71C5B573ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 492\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x5C8F53E5DB38D375ULL,
		0xDDC0B3683ED77708ULL,
		0x203C7B9C21865371ULL,
		0x5B8764CF05E14006ULL,
		0x111337DEA7F8D674ULL,
		0x8AF55C757CFBE505ULL,
		0xB44910173FFB0C04ULL,
		0x1A161460FB902D32ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	printf("Test Case 493\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x3896AABEF2C4581AULL,
		0xB5AB4ABDCC951D9CULL,
		0xAEDBC3B3901077CFULL,
		0xD26C72DFB6793B30ULL,
		0x8DAD101FBAE6814EULL,
		0x38B07C49A02452A2ULL,
		0x66549B944E93BEB3ULL,
		0xFD9D6280A80279A4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 494\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x137F59CEF03AF6A1ULL,
		0x6D4161E5C5FF8872ULL,
		0xA237A693A31E2CE0ULL,
		0x4A5499ADC7AA1FA7ULL,
		0xB40A67B35F650F91ULL,
		0x94A177A5C18CC589ULL,
		0xC8D585D68562683EULL,
		0x75E907A0CC4DFB4CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 495\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x794C4E121B16D1A9ULL,
		0xD0AE851BF3B93C31ULL,
		0xB84DB25CE39F877FULL,
		0xE0F1F64992AF1BEFULL,
		0x4B5D23174EEF97A5ULL,
		0xD661D6CA45814924ULL,
		0x25CAED080596E01FULL,
		0xF8E0874FF485FED9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 496\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x1B85B575B1E76FE2ULL,
		0xDEC751DE0FA3AF7DULL,
		0x7D6F60C6D83E4BECULL,
		0x843F04DF08C145B1ULL,
		0x0736B775FCF69AFFULL,
		0x0BE4570C6EACCE08ULL,
		0xB1AB437D52BE7827ULL,
		0xAC2CD8C51F156642ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 497\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0xC9B6A610EC7E29B9ULL,
		0xB66D1A67529B2CDBULL,
		0x95608953222A7AC2ULL,
		0x965593D8592120F4ULL,
		0x223F5439B6D7BC62ULL,
		0x35F34A0D13643EE9ULL,
		0x6AE7505ECFC05BE0ULL,
		0x5CB63E95272A10A6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 498\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x3671A18EC204D35FULL,
		0x86D107C68DF6C65DULL,
		0xA709CE21EB8C75E3ULL,
		0x38A4236322C0EFD9ULL,
		0x405615AE6C9E3FC3ULL,
		0xBD2AFDE4553F784DULL,
		0x7ABAE7EBC16527B5ULL,
		0xE3444FBBFBC0EC26ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 499\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
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
		0x4C91EBFE7D9B3B8CULL,
		0x5A9CA02E29BF6714ULL,
		0x8A954105841C2CC1ULL,
		0xF2C3B97D75FB0070ULL,
		0x31336E85ADB8E092ULL,
		0x24E8F6523C1A0A1FULL,
		0xEC997C4231C1F54AULL,
		0xEB06F1917ED43775ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 500\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 500 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -500;
	} else {
		printf("Test Case 500 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x30AD36B73003A2FEULL,
		0xC5D9333923996646ULL,
		0x263E37A2FC02CFF7ULL,
		0x9CCB1F33F2897CC2ULL,
		0x145D1C0D396E06EEULL,
		0x1CC4ED0C38BBF6F7ULL,
		0x6E7A480268293AEBULL,
		0x91436D69782C517AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 501\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 501 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -501;
	} else {
		printf("Test Case 501 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7D8728C89B2C4449ULL,
		0xACADEEE38C23FBE6ULL,
		0x1AEDF21BF5D300C5ULL,
		0x42E51EA3A51B8CA9ULL,
		0x0638888C63B5DCC3ULL,
		0x4186580DC0165A29ULL,
		0x7E29FDC49D1183ADULL,
		0x65324C2BB2BF206EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 502\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 502 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -502;
	} else {
		printf("Test Case 502 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2F1D16C4A667E18DULL,
		0xB5345FA58A6944EBULL,
		0x61D09F5285084A6CULL,
		0x1FE3BD293B877E56ULL,
		0xC2B2E19265CD7E31ULL,
		0x91890F9155456443ULL,
		0x505F800C9FD470ECULL,
		0x621921CF077AF90CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 503\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 503 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -503;
	} else {
		printf("Test Case 503 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x035D2BCD110AC2E0ULL,
		0x940131784A30FD26ULL,
		0x1A807C6A0F74FBA1ULL,
		0x44F6E3D59953FD27ULL,
		0x55EC07FF3FD076B3ULL,
		0xA55F9EBA23435D35ULL,
		0x9C4845FB44BFA1B1ULL,
		0x855A64AE666470CEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 504\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 504 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -504;
	} else {
		printf("Test Case 504 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x024D0122CC5BEEA4ULL,
		0x8D3778F35F7F3DD6ULL,
		0xD87C0FD82177E018ULL,
		0x898533B58360D5F4ULL,
		0x7F5CF194D1D04361ULL,
		0x2829CAD3868DD65FULL,
		0x1DA383B184740E5CULL,
		0x0A8A7F86CAA08EE1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0800000000000000ULL
	}};
	printf("Test Case 505\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 505 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -505;
	} else {
		printf("Test Case 505 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8A9215483CE32A19ULL,
		0x8971FBFAE6801500ULL,
		0x172249BA241A09C3ULL,
		0x4A25B0C1468A668AULL,
		0xF5BFD1BE3E19848DULL,
		0x788522F8BE60F973ULL,
		0x029F12570BB8516DULL,
		0xDC97075BEBBEFA60ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 506\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 506 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -506;
	} else {
		printf("Test Case 506 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x61F1681C3035620DULL,
		0x4A744BB10B251A14ULL,
		0xFFE47C429FB6B321ULL,
		0x8F18495EC56D0925ULL,
		0x5413CEC999EBA46CULL,
		0xACFB30BA02C1DADCULL,
		0x65A66256D03465FBULL,
		0x40680309DBB1B229ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 507\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 507 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -507;
	} else {
		printf("Test Case 507 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD8874713A667650FULL,
		0x2C5B67E0DB878D97ULL,
		0x90D0822FBEF6DCADULL,
		0x5BE10C4657F8C44DULL,
		0xA07A1D1B3A478D79ULL,
		0xA58B5814B0574FEDULL,
		0x6AA66FE490D272D2ULL,
		0x8CFBA8E9CD94D69CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 508\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 508 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -508;
	} else {
		printf("Test Case 508 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x68320870958A4D20ULL,
		0x9B41B6E437B5679FULL,
		0xFAF312AFF21607CCULL,
		0xC710EB484E8C82EEULL,
		0x2D13034919FA6986ULL,
		0xF79A5AC583249045ULL,
		0x87C3FB6A886EFD59ULL,
		0xBF460753429CC854ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 509\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 509 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -509;
	} else {
		printf("Test Case 509 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC87B8323505B3242ULL,
		0x9684F3CC440B409CULL,
		0x08205F00078DAF8DULL,
		0xAF57CFB885C0716CULL,
		0x2A27C86A1C2A571CULL,
		0x814599FDD184F198ULL,
		0x0EDA6C9DC3A6A07BULL,
		0xD7F6E3547CA501D4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 510\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 510 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -510;
	} else {
		printf("Test Case 510 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x73924BE1C95F863CULL,
		0x3DA0D0E32473DDDEULL,
		0xF091B13AD71FFD19ULL,
		0x0BA83E56A30D1408ULL,
		0x8708E2B5AD05B1ABULL,
		0x611EDAE29F60BE1CULL,
		0x5DED8B83A200A65CULL,
		0x09455F2A43530B69ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0800000000000000ULL
	}};
	printf("Test Case 511\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 511 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -511;
	} else {
		printf("Test Case 511 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x51D2878E7B8BB6CDULL,
		0x02D3D49F71DD2450ULL,
		0xF9F6CE4D3216526FULL,
		0x13CC2C5C35983881ULL,
		0xF8D7DD15CC1894ADULL,
		0xEDECB22911C901DBULL,
		0x029E724238E5165BULL,
		0x746BB879B82B9C69ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 512\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 512 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -512;
	} else {
		printf("Test Case 512 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4E9DFA6002253EEBULL,
		0xA6EE008F25A6129BULL,
		0x8A14CFB6D3A6D9B9ULL,
		0x0AB6293D1D9F52CEULL,
		0x79AB6F38AF9A1E74ULL,
		0xA3A9F0BB18BA0238ULL,
		0xD50644F333D987C8ULL,
		0x673D8C0BDB7EF55DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 513\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 513 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -513;
	} else {
		printf("Test Case 513 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC1F8A270C9DD0707ULL,
		0xEFF40DF55CE0F70DULL,
		0x282C30E7A2B2E0B0ULL,
		0xC0D04CF1B63A0FFEULL,
		0x37761708E26EA82FULL,
		0xE444A0ED1A9612BDULL,
		0x8AA3ADB68B26B9C5ULL,
		0x1AE11853EEBB6A08ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	printf("Test Case 514\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 514 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -514;
	} else {
		printf("Test Case 514 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x85551287F71C2143ULL,
		0xDEF4A70E1F88466BULL,
		0xE67CDA7F1378AC54ULL,
		0x2747E36601FD111BULL,
		0xC6B096CC7917A9F5ULL,
		0x7A518599EE0278BFULL,
		0xE40B5A59297B9C9FULL,
		0x58FC106BBEAB252FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 515\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 515 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -515;
	} else {
		printf("Test Case 515 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8875A95715987772ULL,
		0xEAFEA325F1D84149ULL,
		0x9D1FC40BA14E7F20ULL,
		0xD823BFF69B5EF738ULL,
		0x955EB755F2D41E66ULL,
		0x9C8F7FD5FF7CD241ULL,
		0x4DD680401C1B68B7ULL,
		0x404D39D6BA90204AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 516\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 516 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -516;
	} else {
		printf("Test Case 516 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDE5976C038ADB3E3ULL,
		0x2EF2A4E8E12EE812ULL,
		0xAC7536F3ECF5D672ULL,
		0xF1ACC572069706D3ULL,
		0x6F186EDDB9BCDE3AULL,
		0x934D6CF468F9F827ULL,
		0x5653B4169469644BULL,
		0x507F8C045CFBEBF1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 517\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 517 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -517;
	} else {
		printf("Test Case 517 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE55B95DBA581309FULL,
		0x39DCB2F470B6A0D4ULL,
		0xD69AA53EA2AC47B0ULL,
		0xF4DF9C05F5D1F2B4ULL,
		0x291E886DC7DA42ECULL,
		0xB7DA2031F0B613C3ULL,
		0x0BCCEE727D2E9BE1ULL,
		0x77D27EEBDEE51664ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 518\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 518 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -518;
	} else {
		printf("Test Case 518 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB75536E12F49C6A3ULL,
		0x473952A80BDE9DF8ULL,
		0xA4EEDE23E7798A75ULL,
		0xA89B6170CB3A3825ULL,
		0xAA66FCF5C3255123ULL,
		0x770D4C0EF1C712EAULL,
		0xC87D6464EE1B1AA3ULL,
		0x87E08BF97DE12686ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 519\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 519 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -519;
	} else {
		printf("Test Case 519 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8B4DEB70D9FE0430ULL,
		0x42BA82CE215737D5ULL,
		0xC2CBE4230AE0FCA7ULL,
		0xE9006E3A160A6F8EULL,
		0x438C16B715FC2ECDULL,
		0x48146A5712FEF857ULL,
		0x4CAB0E9A2982CF5FULL,
		0x15704B41D7585E3BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	printf("Test Case 520\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 520 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -520;
	} else {
		printf("Test Case 520 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3FD775B0461060D4ULL,
		0x88E646881D96BAE4ULL,
		0xBF1730E2207175D9ULL,
		0x0302339350A55470ULL,
		0x4EC8D93D7C7941B1ULL,
		0x23226068B4504331ULL,
		0x1EA38C34E1DE149AULL,
		0xEAE659A309F23A90ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 521\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 521 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -521;
	} else {
		printf("Test Case 521 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD726159B6820D0C9ULL,
		0x6C77D71F9EA733F3ULL,
		0x2ED2362F03AE032EULL,
		0x906450D7646FC58EULL,
		0x51C2E30F5D0690EEULL,
		0xE2772F244570CBFBULL,
		0x090C8224C82F9E28ULL,
		0xA2ADEAE54B02CCB9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 522\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 522 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -522;
	} else {
		printf("Test Case 522 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x30EEF838CC953EADULL,
		0x7A1DB8E4CB5036F2ULL,
		0x4BEBF9AE62E4FED1ULL,
		0xF43EACF93E8FA76DULL,
		0x7B192B29056172ACULL,
		0xFBC0A1D62C3734B5ULL,
		0xC4CD4CCB4DB8438CULL,
		0x256A6FD46A08C98BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 523\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 523 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -523;
	} else {
		printf("Test Case 523 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD9D1E9785686FD7FULL,
		0x6FB126AFA26EDF22ULL,
		0xC6ADB7140AEFB4B9ULL,
		0xC0B0C5D6397A3FEEULL,
		0x50A7CF0287C9437AULL,
		0x5FE45B4C87D083A0ULL,
		0x860E3C1C934A576EULL,
		0xA0F2A44F68F4D8C8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 524\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 524 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -524;
	} else {
		printf("Test Case 524 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA1C27F0DC1AAC3ABULL,
		0x7AB55D7A91F63954ULL,
		0x4656BD235848E7A8ULL,
		0xC3C80590CAE7433DULL,
		0x8C796B227F7C2330ULL,
		0xAB05B33326A81C64ULL,
		0x9D0E589305541834ULL,
		0x67109A90FC8FE8D3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 525\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 525 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -525;
	} else {
		printf("Test Case 525 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6FBB0B7977A9DA23ULL,
		0x2CDCAA75838F9A96ULL,
		0x9D4ED815D768AF82ULL,
		0xBFBD60AE08E5B19EULL,
		0xC8EBD093663D607FULL,
		0x74FEA2AB7C511BD0ULL,
		0x412A46558122538FULL,
		0x84F84954120609AFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 526\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 526 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -526;
	} else {
		printf("Test Case 526 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5E5D6FE44641B1A0ULL,
		0x728F1021C34F74C9ULL,
		0x68B6D2E24D34E1ABULL,
		0xA809A171B1DF8DC5ULL,
		0xEDB83FD2170B9A79ULL,
		0x59F90EAF745865BBULL,
		0xD76C3EBEFDAE1D30ULL,
		0x2D1B9A044A4D648CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 527\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 527 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -527;
	} else {
		printf("Test Case 527 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAC81F6081C894E21ULL,
		0x2363199A5369A1B7ULL,
		0x1F5422FBED20128AULL,
		0x8056E49008F44D80ULL,
		0x4FB47FA4CCA3BE94ULL,
		0x1504E70CA6868EECULL,
		0xD0F5C707647485B0ULL,
		0x7B29AB9DCE85A974ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 528\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 528 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -528;
	} else {
		printf("Test Case 528 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x03DA885D248B5234ULL,
		0x6FDB6BB151532BDDULL,
		0x3FA697A140EBC9E5ULL,
		0x29932C90E62D0C4EULL,
		0x30DB3386F97119F5ULL,
		0x33936F3FD3063F92ULL,
		0x8C105631F72C6F92ULL,
		0x4E3B2CB942B9A253ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 529\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 529 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -529;
	} else {
		printf("Test Case 529 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1E0873A753EDB19BULL,
		0x033A90C726427844ULL,
		0x0D5D2860938E8982ULL,
		0x0707E00FA330CF7EULL,
		0xBC013FFC18D0CD83ULL,
		0x0BECD3BED790117EULL,
		0x7A192AAAC9B26908ULL,
		0x575C2C303F5F3BB8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 530\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 530 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -530;
	} else {
		printf("Test Case 530 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x721AF5F5D7EE54F9ULL,
		0xA7522875F075EE9FULL,
		0xE69204C74927DAEDULL,
		0x09F272D25224F276ULL,
		0x7A2B9E8416B12D6AULL,
		0x8DB6D122C816C4C9ULL,
		0x28717C0448B7DB48ULL,
		0xD2A14BE49DAF010FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 531\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 531 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -531;
	} else {
		printf("Test Case 531 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDC2F7ADA496AF572ULL,
		0xFF4B9AEC57241E97ULL,
		0x21849CEE9E39F60AULL,
		0x378DA8F488C62E25ULL,
		0xFDDDF4239D709FC0ULL,
		0xF3DBB2911C18FC19ULL,
		0x4F949529B0BE848EULL,
		0xE4A3525E2378152BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 532\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 532 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -532;
	} else {
		printf("Test Case 532 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9B16494D4D4BA95EULL,
		0x0C31B758C9F2B748ULL,
		0xD793083C95043E7EULL,
		0x9ACD9F231F81A3EDULL,
		0x6CCDF104433D236DULL,
		0x8B9BF047DE5DA9FAULL,
		0x7BF8A5FE487CA533ULL,
		0x2C4293EBD92745FEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 533\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 533 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -533;
	} else {
		printf("Test Case 533 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9832777DD9DB7F8CULL,
		0x3337C0182A771086ULL,
		0x401909E0232ED6AEULL,
		0xBA584CAD92B6BF51ULL,
		0x2A1BB7B6A5E701B9ULL,
		0x389E58A62061F464ULL,
		0x4328E88478314E20ULL,
		0x5CB0E0A586013576ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 534\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 534 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -534;
	} else {
		printf("Test Case 534 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF3E9C2B87D051A91ULL,
		0x8849E88E908B7EA7ULL,
		0xCADD94DDC41561EEULL,
		0xAD7C445C4F26784BULL,
		0x53E93CC83F89F825ULL,
		0x8E46510374D95E05ULL,
		0x188920B2A546582AULL,
		0xF14620F812B2983EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 535\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 535 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -535;
	} else {
		printf("Test Case 535 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAB3B1461D0E3D627ULL,
		0xD85A4FAF8744C83CULL,
		0xD06816891626DF55ULL,
		0x580537A5E54BC6F1ULL,
		0x3061F29C494A8DDCULL,
		0xFBFBAF15D434E330ULL,
		0x278B2246F4D01800ULL,
		0xBDE9A38AEABFF038ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 536\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 536 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -536;
	} else {
		printf("Test Case 536 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA2D857B15DF5352DULL,
		0xCC1817AA19AE22DBULL,
		0x466A76AB5CB340A3ULL,
		0x6EDDB5BDA30E64C6ULL,
		0xED3B82981A1B6E09ULL,
		0xA99F699B82436E9EULL,
		0x6BBEA5A89099AD7AULL,
		0xF060BDDC2825EDF3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 537\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 537 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -537;
	} else {
		printf("Test Case 537 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFDDC03A7C49B9E57ULL,
		0xEFC561E6CCD90F48ULL,
		0x902ED846EA054EBCULL,
		0x578E5DDA6836B422ULL,
		0xD7A8271238FD13D4ULL,
		0x8B4AB2AC677379B8ULL,
		0xA275D6229859F0DFULL,
		0x46E81DBAB081D6E9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 538\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 538 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -538;
	} else {
		printf("Test Case 538 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4BE51A71A008FD70ULL,
		0xBDDFABD5D5B4E21AULL,
		0x1FC0D5DEB13F77ABULL,
		0xE093D160D4C23008ULL,
		0x0FE1C1F99F772A4FULL,
		0x4DEA9F8837861F37ULL,
		0x676FFD3CC6248307ULL,
		0xC98AC1FC5AA76BBAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 539\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 539 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -539;
	} else {
		printf("Test Case 539 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE06970BA5A6FD105ULL,
		0x0F75A1AFDEAD0418ULL,
		0x22D30AF1333F2A0EULL,
		0x8D78B01C01BCC824ULL,
		0x6CB995ECA4261E42ULL,
		0x0209F142C267F2CFULL,
		0xBE4170AC0C73AD7BULL,
		0xFD43881F2246AA90ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 540\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 540 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -540;
	} else {
		printf("Test Case 540 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x58D4CEEC47499459ULL,
		0x1306766986390E49ULL,
		0x640BD62F082BA829ULL,
		0xAE9732D444B39E23ULL,
		0x70D854DB72570512ULL,
		0x8E8B762D6DC6787DULL,
		0x09323988C1D5D46EULL,
		0x6822D959693684A6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 541\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 541 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -541;
	} else {
		printf("Test Case 541 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0D7DFA38A0B0CD08ULL,
		0x18C9E66F8D3E6630ULL,
		0xC55F31A150971657ULL,
		0xC6012E2A6D1CC32DULL,
		0xF1955A98C9F8324FULL,
		0xE745FBA1016BD8AFULL,
		0x486228F571679EDDULL,
		0xD6A6379CC01A3EAFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 542\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 542 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -542;
	} else {
		printf("Test Case 542 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x85D7A4F568153832ULL,
		0x240E332BFA251DE2ULL,
		0x0C8B789B88F8A770ULL,
		0x82DF61429D20167BULL,
		0x31A21F5690699410ULL,
		0x7B6C11F4232279C3ULL,
		0x38E491489158E79BULL,
		0x1A5003DD4E9A2E81ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	printf("Test Case 543\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 543 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -543;
	} else {
		printf("Test Case 543 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8C03F1F0D48559C5ULL,
		0xFD6A8A112F47F4B9ULL,
		0x70548B1E925D1D91ULL,
		0x936BD7714452A9BEULL,
		0xBAEC9ABECE0E8A1CULL,
		0x106F7D055E0F0261ULL,
		0xB0FA66C0ED5CFD87ULL,
		0xA95B8BE28BAD5175ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 544\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 544 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -544;
	} else {
		printf("Test Case 544 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x172D0FF4B47EAE8CULL,
		0xDF4247F01C386EF3ULL,
		0x6CA8BA3C1ACA0031ULL,
		0xB45940F74268D01FULL,
		0xAED36BB762441293ULL,
		0xF7157C021E01284BULL,
		0x3B10998FDC4FD72CULL,
		0x7620B6A4E5304EBCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 545\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 545 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -545;
	} else {
		printf("Test Case 545 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3B8564E2A2062BE0ULL,
		0xE6BF70A892883E78ULL,
		0xE4D5B3D4AD36DEC8ULL,
		0x78B6DE6B74E1A94AULL,
		0xC19DC8459F89DA82ULL,
		0xA090108AFED4A329ULL,
		0xE9C1124DF0C1A73BULL,
		0x4BF5ECDEE5B3DA42ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 546\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 546 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -546;
	} else {
		printf("Test Case 546 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x52CB5C35980354D5ULL,
		0xC51B638BDFFE023BULL,
		0xACC55F554C0A0B47ULL,
		0xE2BF9A64DD29F688ULL,
		0xB70E44323F3749D7ULL,
		0x93BD05BEF8DD629CULL,
		0x5C8BA7F3958051F8ULL,
		0x6FF45D39E0297A80ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 547\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 547 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -547;
	} else {
		printf("Test Case 547 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA834254A0064AF27ULL,
		0xC74215CECD58BBFEULL,
		0x9B97D051C00206F1ULL,
		0xE3E2782856B4953EULL,
		0x73A22B1B520BA822ULL,
		0x8D2A34AB87C2CDD3ULL,
		0x37E65475C7AB905EULL,
		0x3A0E0DCCD558825FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 548\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 548 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -548;
	} else {
		printf("Test Case 548 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3D7E03AF1AA84B3AULL,
		0x01371E6375446DE7ULL,
		0xE9E198BABB7C6B50ULL,
		0x9CDD5A57994B27B8ULL,
		0x8FF876C094167ADEULL,
		0xF5117303BE522008ULL,
		0xEF333F8842D1B29AULL,
		0xD711A64A8BB2E623ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 549\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 549 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -549;
	} else {
		printf("Test Case 549 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5A4B50E1ED56824EULL,
		0x36A33E58B353CA31ULL,
		0x793FAC4E4F837B09ULL,
		0x5DF6385405B94B89ULL,
		0x3B7719D5131EEF66ULL,
		0xC655DC75291343F2ULL,
		0x1732136F691EC3F6ULL,
		0x05EED998AA80BC7FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0400000000000000ULL
	}};
	printf("Test Case 550\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 550 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -550;
	} else {
		printf("Test Case 550 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB29D86AAA4BE37F6ULL,
		0xC91C07E23D68417FULL,
		0x71037BC3EB00E496ULL,
		0xC7F77D67C8950B1EULL,
		0xB05D7FCF6B2E1123ULL,
		0x5E23EBB6604DA630ULL,
		0xE231423A2BCD9317ULL,
		0x2B56D171E752D059ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 551\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 551 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -551;
	} else {
		printf("Test Case 551 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8008B681D03CFB22ULL,
		0xE16160C81D98DF38ULL,
		0xE4A6E7C384B807A7ULL,
		0xBDABF05794280ED5ULL,
		0xA0A6818D1E2717EDULL,
		0x137E912B9974B60CULL,
		0x3D046E64A858B9FEULL,
		0xF72CF8F3BB5AD003ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 552\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 552 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -552;
	} else {
		printf("Test Case 552 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x16D4A226A977492CULL,
		0x9D714669D58DF72EULL,
		0xCC2DE9448CC00FCEULL,
		0x01953EDBCA849921ULL,
		0x5D051C75C8D4F831ULL,
		0xC3D8E4ABC7393C3DULL,
		0x5CA511E5D6C0A0F7ULL,
		0x699187A80CF81879ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 553\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 553 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -553;
	} else {
		printf("Test Case 553 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF25B210140B119A2ULL,
		0x671E7FD5DF235586ULL,
		0xDBCD01BB225749C5ULL,
		0xCAB776FD80097AEBULL,
		0x7DEF4E2627A3001DULL,
		0x4284298338FCE4F2ULL,
		0xF40EAE1E51E78A9FULL,
		0x98AAB4478DED11D8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 554\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 554 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -554;
	} else {
		printf("Test Case 554 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8872060B8319EADFULL,
		0x7A2ACC7851755E16ULL,
		0xCBD0F94D24E27147ULL,
		0x4CBA69ED43C0DB27ULL,
		0x38DD473E01D35391ULL,
		0xE97B0D08A83FA285ULL,
		0xEAF56746258E6554ULL,
		0x289140DB088E920EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 555\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 555 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -555;
	} else {
		printf("Test Case 555 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7D9208AAF0DC2791ULL,
		0x4936A5470CF4C2C6ULL,
		0xA7B8B2AAC8A3E971ULL,
		0x25FB932F1B31FE5DULL,
		0x5444183777089630ULL,
		0xABC8FE2B75735A6CULL,
		0xFBC509A3B264FA25ULL,
		0x63579E27A613D670ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 556\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 556 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -556;
	} else {
		printf("Test Case 556 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x51588D8AB44CC0F8ULL,
		0x0405707B02025C34ULL,
		0xC758501443992C63ULL,
		0x3A56239F1B1275BCULL,
		0x56884AE698EC1417ULL,
		0x44B91EB8B2D13A62ULL,
		0xD0EA55D62A566FABULL,
		0x174D89AFAF4070B0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	printf("Test Case 557\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 557 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -557;
	} else {
		printf("Test Case 557 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC019F62F51414BBBULL,
		0xF6E61501459DEC1DULL,
		0xACA71CBD4E572BA0ULL,
		0xEB301EF66A6F8AB2ULL,
		0x335727F2D34904A6ULL,
		0xAF05BEC580DC2A3AULL,
		0x38172FD1569E365FULL,
		0x917ACA693432D41BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 558\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 558 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -558;
	} else {
		printf("Test Case 558 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4B234BDF010EE6ACULL,
		0xC7F63DE886A6D12DULL,
		0x3331847E1E4336EEULL,
		0xC0DD9AA4309E4ABAULL,
		0x620A4B3AC0638724ULL,
		0x39FFDE6B3A929EA5ULL,
		0x01964318B9388C95ULL,
		0x0B538E430535978DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0800000000000000ULL
	}};
	printf("Test Case 559\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 559 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -559;
	} else {
		printf("Test Case 559 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6BEEA6C21CEFC95BULL,
		0xC105DC8291786423ULL,
		0x1A415D6F40DD9C67ULL,
		0x8579724C7975EF7AULL,
		0x9B5D59BE95EACB1CULL,
		0x2ACDF8E52285D4B7ULL,
		0x04096DA13C5B57FAULL,
		0x735427B701A89880ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 560\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 560 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -560;
	} else {
		printf("Test Case 560 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6224650A819E0CF3ULL,
		0x22752AEA793406EFULL,
		0x7F5EC119E94428DBULL,
		0xD44827409B487FF8ULL,
		0x6ECABEE323C97AE9ULL,
		0x53D2AC3F8FBF93F1ULL,
		0x47F21E2B8466E452ULL,
		0x42F882E29C92F6D2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 561\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 561 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -561;
	} else {
		printf("Test Case 561 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xED57A705491CF857ULL,
		0xCDB1222FAD1D533BULL,
		0x41C47D3E2C7EA4F2ULL,
		0x7097EE2E7E1FDBABULL,
		0x7F116C8B557A20DDULL,
		0x802859122F694D19ULL,
		0xF9790EF01E7527DBULL,
		0x6F27FB92407E1539ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 562\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 562 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -562;
	} else {
		printf("Test Case 562 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC66464457D35E847ULL,
		0x3CA84C722A84E78FULL,
		0xC545353F8C65E176ULL,
		0x27B8DD257CBCD235ULL,
		0x32119C0D30582B81ULL,
		0x2416020027185FBCULL,
		0xADA28D87018FCB1BULL,
		0xC29CBB290609E075ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 563\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 563 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -563;
	} else {
		printf("Test Case 563 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x084C7541545F47ADULL,
		0xB836834BC13E57EAULL,
		0x6D8924458B28CA2BULL,
		0xF756528BDF98936EULL,
		0x110BE08BBD1C3458ULL,
		0x93316ED4F622A2D8ULL,
		0x84472A1653564835ULL,
		0x79DA7463DBF0CFB6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 564\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 564 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -564;
	} else {
		printf("Test Case 564 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6FF86D5BB602B6A8ULL,
		0x112443BCDE7F3A14ULL,
		0x6AC411CE5CC1931EULL,
		0x383810A0E8C8D877ULL,
		0xBE8CA5FA32714742ULL,
		0x0946619AAD88887BULL,
		0xB01A087BB992A63AULL,
		0x6A568A205C0DC788ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 565\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 565 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -565;
	} else {
		printf("Test Case 565 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBCBEB566B7C602F7ULL,
		0x897078CBC0E34D5DULL,
		0xEAAB5EAD071F37AAULL,
		0xC16440849E1BC66FULL,
		0x703F02C63FD02B09ULL,
		0x5EBBF76E9E79608BULL,
		0x7217121B4994127AULL,
		0x955E72FEAD132691ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 566\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 566 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -566;
	} else {
		printf("Test Case 566 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x61DF455465E90B82ULL,
		0xEA953DB522CAC0E2ULL,
		0xE4C091E359A03FA5ULL,
		0x1A0E81A3F654EAEBULL,
		0x43E14CD7FEF5E396ULL,
		0xBFEDA2E961A1B3F9ULL,
		0x02E30028A5944205ULL,
		0x0DCDAB76E6AE97D4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0800000000000000ULL
	}};
	printf("Test Case 567\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 567 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -567;
	} else {
		printf("Test Case 567 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4EFBD77D598A5C3BULL,
		0x1E1BB7279EB53382ULL,
		0x1914AFA95CB583D7ULL,
		0x4B585D5B19FD1B5EULL,
		0xC7541A55548104F9ULL,
		0x7CAEDEFBB0828D5DULL,
		0x48A53CDAFF75EC13ULL,
		0xF3AEFDF44C4ED86AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 568\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 568 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -568;
	} else {
		printf("Test Case 568 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6A6965D39F9C72E1ULL,
		0x2A6CEE72661036E4ULL,
		0x963EA5D4CA1C3B82ULL,
		0x9DDD771323FF8E23ULL,
		0xC9EB1A29F07A9790ULL,
		0xE206CA9F606D7B3AULL,
		0xE149132F8ED0F9ABULL,
		0xDF3EFEB0E4BE4B4AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 569\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 569 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -569;
	} else {
		printf("Test Case 569 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x23F45111A4167C87ULL,
		0xD6C4E345A30FFFE5ULL,
		0xA1BB872AEB014B7FULL,
		0xD6884B18542EB3D6ULL,
		0x072C66755D444D92ULL,
		0x6DF00D7CCB56352AULL,
		0xBE2DE28933FF6B9CULL,
		0x41F6281C8E14CCB3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 570\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 570 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -570;
	} else {
		printf("Test Case 570 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x18517C8603F3104FULL,
		0x65C6A8119D88EBC6ULL,
		0x90EE7B8517D3D7AFULL,
		0x7BA98E6848290172ULL,
		0xEB7951E95181C508ULL,
		0xE2AE83DEA0DF2E87ULL,
		0x4A4257FC13CCFC98ULL,
		0x1458BC2EF9A80C8EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	printf("Test Case 571\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 571 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -571;
	} else {
		printf("Test Case 571 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC18BB1D130C33A18ULL,
		0xFC94009151785708ULL,
		0x79FBC50B1B6E2A1EULL,
		0x6A2E06A6AB016FF9ULL,
		0x20EDBB2DEA390088ULL,
		0x73C1EB5BAC65EE33ULL,
		0xC3B2CEFAB7811B47ULL,
		0x3E0A214E33EAC943ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 572\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 572 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -572;
	} else {
		printf("Test Case 572 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8A408703741DBD62ULL,
		0x0E3AB31378E9D66EULL,
		0x306ACC60945C8973ULL,
		0x329D4CF0559604ADULL,
		0x6691BC073505C222ULL,
		0x296A1C70DD22B6DBULL,
		0x1D78F5EDAD72C00AULL,
		0xC611B0FEFCBFD4BFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 573\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 573 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -573;
	} else {
		printf("Test Case 573 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB65CC21C7918B29AULL,
		0x7295627065EF80EBULL,
		0xDE0122BCE0779AD8ULL,
		0xFB4818A1C3665E12ULL,
		0x255D3529ECFBF858ULL,
		0x6185B27A9FBE6934ULL,
		0xBE02995FF5BA2006ULL,
		0x1FC78BD257CCE1B1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	printf("Test Case 574\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 574 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -574;
	} else {
		printf("Test Case 574 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3119B91AF5E01205ULL,
		0x0702753AA7CF620DULL,
		0x3043A3A3F8E3837BULL,
		0x93A5CD6D4BD11C18ULL,
		0x19E0CC45C6FAE47BULL,
		0xDB3BCE063CEA5814ULL,
		0xC4A0B4F484BC78ACULL,
		0x470784EB3CA798D3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 575\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 575 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -575;
	} else {
		printf("Test Case 575 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x356637BE4142948DULL,
		0x84B4213A875A5D95ULL,
		0xAE1954B860EEDBB3ULL,
		0x1117CB66A1B5EEABULL,
		0x7FED7D504486D505ULL,
		0x4F8E6287B062D7A4ULL,
		0x21A0149F2E3D56A3ULL,
		0x5B869D5F10094CF8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 576\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 576 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -576;
	} else {
		printf("Test Case 576 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x36558B0CBB3EE140ULL,
		0x28ADBF36A615945CULL,
		0xD164A7A01FD81D4CULL,
		0x7B710A8644E15A3CULL,
		0x3303BDA1CD32D717ULL,
		0x1FFB0E04416F4466ULL,
		0x87DD4FE0B87C4C09ULL,
		0xA9F7D73C5068191FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 577\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 577 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -577;
	} else {
		printf("Test Case 577 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xED21198DF3FDEB1DULL,
		0x22638ED099A34737ULL,
		0x6444E561F842FC9CULL,
		0x98F2F9DD0753DC79ULL,
		0xE73174E6AE51D5F3ULL,
		0x7EC8A92320E2C8D6ULL,
		0x23BF4DF6CDFAE94DULL,
		0x4AACC80466A69AB7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 578\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 578 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -578;
	} else {
		printf("Test Case 578 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0DC22F231FC655EFULL,
		0x383D1607159B7783ULL,
		0xC1CB691CA600EF47ULL,
		0xD29D0EA5916FAFC6ULL,
		0xF891FD83C3C2CC6EULL,
		0x592C662F67A35AEFULL,
		0xA513FB1D47BB7929ULL,
		0x07E1DEEAC41EF8ABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0400000000000000ULL
	}};
	printf("Test Case 579\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 579 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -579;
	} else {
		printf("Test Case 579 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x52EDD75A85667D08ULL,
		0x3E29DD5D95E271D0ULL,
		0x0249DBB03E101B1BULL,
		0x9CD7DC5BF4A59746ULL,
		0x3AFE4A990EF45A8CULL,
		0xD15EC667A7D0B22EULL,
		0x4DBFD686031572EEULL,
		0x67F522706A913AC5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 580\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 580 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -580;
	} else {
		printf("Test Case 580 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAFD6AC16685D44B3ULL,
		0x846EAE5A581784C2ULL,
		0xB5A144C44C85F3F9ULL,
		0x2F400E45FDE7DF3CULL,
		0xEF7E1D9B9C3F21E2ULL,
		0x83DF1C9E1A0FA9D2ULL,
		0xEB994B2A237B50C7ULL,
		0xA65C2B65ABB45EECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 581\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 581 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -581;
	} else {
		printf("Test Case 581 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC77BA39D2590AB34ULL,
		0x9800AA372ADF62EFULL,
		0x04E6B4065E9FF7B1ULL,
		0xF37EA5E91E569FC7ULL,
		0xCD33A3612600E473ULL,
		0x5DA3E35E3922FADBULL,
		0xFC1CE9299F8FEAD2ULL,
		0x971479794896A111ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 582\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 582 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -582;
	} else {
		printf("Test Case 582 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBE5743583ABF206DULL,
		0xAEF9A3BBF8EBD540ULL,
		0x76749361A0337C00ULL,
		0xE843FF53E296B810ULL,
		0x0D9FA2835679EE87ULL,
		0x1FD0FB12FA3D97E4ULL,
		0xF549577575EEF89EULL,
		0x8BBC28B0D83679C9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 583\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 583 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -583;
	} else {
		printf("Test Case 583 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB602E312E980B9C2ULL,
		0x910CA70942903C82ULL,
		0x2EBD68C2B9C56296ULL,
		0x4E6967A47DDA2732ULL,
		0x91DB90C7B6120201ULL,
		0x3D8E887F8473AE85ULL,
		0xA57DBC11CF43BA42ULL,
		0xF7F3F626C254EF4AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 584\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 584 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -584;
	} else {
		printf("Test Case 584 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x592EC0903BA5562AULL,
		0xBEF1048D806ADD38ULL,
		0xCF03EC946031BFAEULL,
		0x95B284CE0464C1DAULL,
		0x4CCBBE4D50CD6A55ULL,
		0xE10C9127F79A98B3ULL,
		0xEDFF85D8B9192966ULL,
		0x1F70539D71A1A585ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	printf("Test Case 585\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 585 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -585;
	} else {
		printf("Test Case 585 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB3E675FFF0D4DCDAULL,
		0x1F550C9F7F641EC7ULL,
		0xAB3B2CB0686FEDD3ULL,
		0xD621BEC0DB0BC8D3ULL,
		0x0415E2A9BE5D4913ULL,
		0xD34AC5D178733390ULL,
		0x258E98C5DC244837ULL,
		0xCED41F0D9D1AC28FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 586\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 586 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -586;
	} else {
		printf("Test Case 586 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xABCB5656FBF3B689ULL,
		0x46B8B6F3F8F1D236ULL,
		0xC0F7BCE07299BA26ULL,
		0x26CB53862167ACACULL,
		0x670A8392BB5FA994ULL,
		0x12D2A3444EA0004FULL,
		0x0EB6B9FA70562139ULL,
		0xC50898DC202BBB0EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 587\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 587 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -587;
	} else {
		printf("Test Case 587 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5970E817F3E6217BULL,
		0x68400082F9D6ECD1ULL,
		0x84BA40CB86FC2FD5ULL,
		0x391502E49AE1BEDDULL,
		0x4467C855C23F97E5ULL,
		0x2C6DC5A39C8B97B2ULL,
		0xD7BE08931A45A9CDULL,
		0xC478C172C3C3E7E5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 588\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 588 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -588;
	} else {
		printf("Test Case 588 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA263E3A11DE32E5EULL,
		0x2A0C5C8388B59EBFULL,
		0x96F707B97EA186FDULL,
		0x63614D42ECFCE558ULL,
		0x3ABFC91865E7A807ULL,
		0xA8740A093812BC39ULL,
		0xF0EF35BA8291E908ULL,
		0x77DA8A1003168CBCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 589\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 589 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -589;
	} else {
		printf("Test Case 589 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDD8F7B82D2DD452DULL,
		0x572A3EF51CA0C190ULL,
		0xCC4EBF0D651FD0A1ULL,
		0x6CC3A54C8A3E751CULL,
		0xF576D9038C1381D6ULL,
		0x81E484E69A66CF6CULL,
		0x3B50C0EE4592E314ULL,
		0x37085E381031A4F3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 590\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 590 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -590;
	} else {
		printf("Test Case 590 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7A25FA95F5EC6A0DULL,
		0x6642C51BC08FE69CULL,
		0xA2F900010DCCD21FULL,
		0xD942BDD886D71676ULL,
		0x15673235BFAC81C0ULL,
		0xB206F92E5B533574ULL,
		0x4B552CC26C1F26FDULL,
		0x4D43BCBE565132F2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 591\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 591 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -591;
	} else {
		printf("Test Case 591 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1E180FAC196CAA0CULL,
		0x0F752A890F4A2349ULL,
		0x04FB55A11254FAB7ULL,
		0x5813B08A7DD62BE2ULL,
		0xA136FA90145EE4B4ULL,
		0x7B48DBD6723B9C01ULL,
		0x255260906BCD30F6ULL,
		0x59D92902341B0471ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 592\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 592 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -592;
	} else {
		printf("Test Case 592 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x98EE05827975904FULL,
		0xDFE64406E4F7D41BULL,
		0xA1323AD4AEBB1910ULL,
		0xF2E9F68E86F28F9CULL,
		0x1E0AE83995B9A1EEULL,
		0xDD7DE87BA102931AULL,
		0xD0AA33F55ABC2C8FULL,
		0x96118C0FA45FFC4CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 593\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 593 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -593;
	} else {
		printf("Test Case 593 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1B718FDC3FFFEA6DULL,
		0x6F4F93348CAF7C89ULL,
		0xCF555756C71BDBBBULL,
		0xB8D71F51231122FBULL,
		0x73685270C3B2FA43ULL,
		0x86F46357E038D802ULL,
		0x5BB1392934FABB25ULL,
		0x239FCBD6F3FEA339ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 594\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 594 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -594;
	} else {
		printf("Test Case 594 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAE28E29F72187641ULL,
		0xF0A2FB606D8E3BEBULL,
		0x6206A7076BBE54E7ULL,
		0xC857EBB4B3B28F8CULL,
		0x1955DCC1ADC80DCDULL,
		0x17004573DF279939ULL,
		0x6A81370B194F3A77ULL,
		0x880F542F3BA8CD7AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 595\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 595 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -595;
	} else {
		printf("Test Case 595 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAD125C1FD3BDA984ULL,
		0x63E0F0E3D60AD34DULL,
		0x14C208D412B7D68FULL,
		0x727739D47CE1C50AULL,
		0xCF4B156B2C2E15DFULL,
		0xA5696EFFA45D526AULL,
		0xC390B1C7D4E7ECE2ULL,
		0x0B5D38D3C9221D40ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0800000000000000ULL
	}};
	printf("Test Case 596\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 596 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -596;
	} else {
		printf("Test Case 596 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x25B9CD2EB7A7E5DAULL,
		0x399444B45F4EA67AULL,
		0xDF643CF7EF2E7C85ULL,
		0x230D0CBC962DB313ULL,
		0xCF7C42656B9BBD00ULL,
		0xB51D6EEB58E858FBULL,
		0x95CB855298B6B76AULL,
		0xB5B8A23C621D6BF3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 597\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 597 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -597;
	} else {
		printf("Test Case 597 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAA73E953211FAB2BULL,
		0xEBF3A928004FFC4FULL,
		0xDE623DB03EC429FAULL,
		0xD8CE3903B92C7C88ULL,
		0x98BCA3628083D3D8ULL,
		0xBFCA45DAABBC6692ULL,
		0xA7668869170A38C4ULL,
		0x898E54C13FE84B6DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 598\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 598 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -598;
	} else {
		printf("Test Case 598 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x41E5D2D8B7AB1FB1ULL,
		0x83EDAA10A9BCD25DULL,
		0x11B9681F6A793C7AULL,
		0xEB37F3DC64860A50ULL,
		0x3BC6F0F01F38CA27ULL,
		0xAED415EC3936960DULL,
		0xA91CFBE73D22C9EFULL,
		0x21693C3028E4E66CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 599\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 599 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -599;
	} else {
		printf("Test Case 599 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5D418A6C080017EFULL,
		0x8606E8AB1B17FE7FULL,
		0xD492502F2F15D96DULL,
		0xB6CF47B6D1A2F7C2ULL,
		0x563936106CE23BAEULL,
		0x948E51C2B90AE9AFULL,
		0xA260C5260C0BB285ULL,
		0x1E03DCFF538C6C87ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	printf("Test Case 600\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 600 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -600;
	} else {
		printf("Test Case 600 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA01CB9B94B83596EULL,
		0x084784D278C31FA0ULL,
		0x974722CD10FDEAB5ULL,
		0xCA531B5C1A8CAD72ULL,
		0x963CE79272A18D5BULL,
		0x5FB3C445A256DF64ULL,
		0x25C984CF94CF0EB4ULL,
		0xF4B4BB048D329518ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 601\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 601 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -601;
	} else {
		printf("Test Case 601 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x708D4579D1A9D1D3ULL,
		0x7FBDDA9AA248F4A0ULL,
		0x886907FADB048674ULL,
		0x0C228E2076C47D86ULL,
		0xD0319BD44ABABB4FULL,
		0x87D1EA6B0F856B82ULL,
		0xBDDA32DDC177A3A6ULL,
		0xA48E03A23A78E461ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 602\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 602 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -602;
	} else {
		printf("Test Case 602 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0EE5AE3ECE53B488ULL,
		0x27F299A3C61F1381ULL,
		0x42F60B22FBFC0395ULL,
		0x8770D0C6367039B3ULL,
		0xC0DC20B1D9E2F658ULL,
		0x2E7979D902702143ULL,
		0xF398A2FEB2D0DA09ULL,
		0x47AD089A6381FDF7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 603\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 603 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -603;
	} else {
		printf("Test Case 603 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8FCB698EE7BDD735ULL,
		0x11436B14127DEDC3ULL,
		0xAEE5AD632B2DEB1CULL,
		0xFCDFF3F7194D0BBBULL,
		0x4F59A4C01E36FAFFULL,
		0x20A22E1C660F1393ULL,
		0xB4302C7C90793A77ULL,
		0x62B2BCDF89D516B9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 604\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 604 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -604;
	} else {
		printf("Test Case 604 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6F54A991ECBD8871ULL,
		0x4A6532D0A2C753C0ULL,
		0xAE12558FAF26895FULL,
		0x2D96007E685A3EFAULL,
		0x2DE6FA7039DB6CA4ULL,
		0xE7A467444A008C21ULL,
		0x4CE2367B7F9B8A45ULL,
		0x17D78D7334866E53ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	printf("Test Case 605\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 605 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -605;
	} else {
		printf("Test Case 605 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0E8254EEA3EF05F4ULL,
		0x3F08337A5B0D7EA5ULL,
		0x2482CACD2B3E424CULL,
		0x96DBC808E3DA1A32ULL,
		0x889F52711BD700F4ULL,
		0x8E197ADC77833967ULL,
		0x4693FBD4A6FB5F2BULL,
		0x9F8E1C8A5D0AF24DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 606\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 606 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -606;
	} else {
		printf("Test Case 606 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x058F7E8A626056B4ULL,
		0x73E4B15F4C54FC71ULL,
		0xE08CE69C67771792ULL,
		0xBDDFC1654C710665ULL,
		0x059957F19435971CULL,
		0x904238F7DBAD3D7EULL,
		0xD614426A54A9A461ULL,
		0xE02B6929AAD82594ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 607\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 607 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -607;
	} else {
		printf("Test Case 607 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4AC25D123F0B12B0ULL,
		0x38E28E682DA01D9EULL,
		0xD1CD9DBFE60D1127ULL,
		0x2B6A01A9142FE997ULL,
		0x7E2FEC64C4E92019ULL,
		0x3E2258A1112949A1ULL,
		0x7F712AEB0B4471CCULL,
		0xFB8617F2168C5E36ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 608\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 608 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -608;
	} else {
		printf("Test Case 608 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x958818B789FF8D05ULL,
		0x6CED84E393F0B1B7ULL,
		0xD31C5261A3C9B20CULL,
		0x5F6E64729380F075ULL,
		0x046B290C356239C8ULL,
		0x51FFF9B1D6303264ULL,
		0x9ECD66118AA68B75ULL,
		0xA4CD44C719FEB7F5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 609\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 609 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -609;
	} else {
		printf("Test Case 609 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x346781DB8558407DULL,
		0x91B064EAB5DB8EA3ULL,
		0x9F1A14B5EE15DBC8ULL,
		0x4747734770F3C9AFULL,
		0x6F326EA6B4AE2DDDULL,
		0x583D9967E79F3C54ULL,
		0xF027B24F7F64979FULL,
		0x6B918562936B73E3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 610\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 610 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -610;
	} else {
		printf("Test Case 610 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB354A2BF5199195CULL,
		0xF8BBF13F4B285A14ULL,
		0x815D8A6BCA74B36EULL,
		0x6DEE15FF4F187E41ULL,
		0xDCF0DEF8CEE071D4ULL,
		0xEC320E799D2A4569ULL,
		0x4C16A61149CDCC0BULL,
		0xDD1E9A3BBCAB4AE0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 611\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 611 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -611;
	} else {
		printf("Test Case 611 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD356B68B4038736EULL,
		0x3F1AE3982928D816ULL,
		0x2AAB5B5BC72D5BF0ULL,
		0xDE2C8EB1556FC62DULL,
		0x65794F94D362A4E1ULL,
		0xF5C5EEA2652CC0A7ULL,
		0x7D6DC2EE30C329ADULL,
		0x3B99508E71A6EA7CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 612\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 612 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -612;
	} else {
		printf("Test Case 612 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x15163C538712B771ULL,
		0x788E3913CE6C3A5AULL,
		0x5DFDC8E8C9E03747ULL,
		0x8E626806AC1D8E15ULL,
		0x5830E3991658EA58ULL,
		0xB5F0636894831DFCULL,
		0xE9371DE57102ACEEULL,
		0x89525B44C9523795ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 613\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 613 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -613;
	} else {
		printf("Test Case 613 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7E7BFEFDD6B56BA3ULL,
		0xBD1441825B93F13AULL,
		0x4A53811168AE1C0EULL,
		0xCE660FDAE7DF651FULL,
		0xD6914150E2D2C0A8ULL,
		0xB451B4CA9FD08195ULL,
		0x2312AD1DF5E3FC41ULL,
		0x19B8358E13EDF20FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	printf("Test Case 614\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 614 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -614;
	} else {
		printf("Test Case 614 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2B74A911F830D701ULL,
		0xC974781725932299ULL,
		0xDBC730CBB5D89B9EULL,
		0xA50FACDB3226051BULL,
		0x86AD4FED8E564855ULL,
		0x2833A9205E055FFBULL,
		0xE03C5703671C1D28ULL,
		0x501CCCCE83AFDB1DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 615\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 615 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -615;
	} else {
		printf("Test Case 615 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x11A1EDD9C678AE66ULL,
		0xA4A438047448F1BCULL,
		0x212B30FA8CA4BA86ULL,
		0x14EE262AA1DEA6E6ULL,
		0xD6FED2D64BC742A8ULL,
		0x614E507097B685F1ULL,
		0xAA35F065A507C11BULL,
		0x87C921784B1F82F1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 616\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 616 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -616;
	} else {
		printf("Test Case 616 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFBF3C4255F6B8A53ULL,
		0xA7FBEEA4D288184EULL,
		0xB125A9D9BAF9E101ULL,
		0x93200A181211A36BULL,
		0x7DC872AAFDA31FABULL,
		0xC06664A94887697AULL,
		0xD3C61121DB1835C5ULL,
		0xC3713FA7B6E3EE21ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 617\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 617 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -617;
	} else {
		printf("Test Case 617 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2BFD4FDA18306FB4ULL,
		0x3CEC9342A4266935ULL,
		0x3F45660381FD9F34ULL,
		0xA89C45760AD8253AULL,
		0x20C210D274FC33F6ULL,
		0x00878DB90358ED24ULL,
		0x21830FA67EEBA089ULL,
		0x24DBD87E02248DB4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 618\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 618 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -618;
	} else {
		printf("Test Case 618 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x928C123BDAC95B3BULL,
		0x22D0B46577F34524ULL,
		0x5FEE807DCD0A2417ULL,
		0xB4C51A3625FD8D01ULL,
		0x297BC296482B92DBULL,
		0x1E8621EF321AA7CCULL,
		0x07C7E26927A94257ULL,
		0xE709FF7AFB7DBCF4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 619\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 619 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -619;
	} else {
		printf("Test Case 619 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x434CAB024E56F8AEULL,
		0x79362267D5CD5F5CULL,
		0x205FA113BE71A504ULL,
		0xFD88EDD73012A27FULL,
		0x4E6392B4BE233B0EULL,
		0xB2737798FA31A00FULL,
		0x87C6CA7F66E57540ULL,
		0xB61F1E3A12436033ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 620\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 620 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -620;
	} else {
		printf("Test Case 620 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4DF3565F39D61DE4ULL,
		0x90DA9F9196F9750CULL,
		0x5F91A029FD0977F4ULL,
		0xAFBEDAD0BAB48210ULL,
		0x1C346CFD793BF4EEULL,
		0x6D54239C4DF30AF5ULL,
		0x904B3B1D29EE3E7BULL,
		0xDB0C20695CEF0882ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 621\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 621 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -621;
	} else {
		printf("Test Case 621 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7053BA0BDC8CE7EAULL,
		0xB88B98565EFB7696ULL,
		0x8D6678B50278E00BULL,
		0x9D80434124231B39ULL,
		0xCC4B73FB5C0CC274ULL,
		0xB118C39E4F5E8A1EULL,
		0xD1992F6F3757B7A0ULL,
		0xF34BB3D732AB6B6CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 622\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 622 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -622;
	} else {
		printf("Test Case 622 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x061890C9A7B65F13ULL,
		0x8F66331099601E6EULL,
		0xFC96A74C0C40237AULL,
		0x7FFC06CA3C1BF208ULL,
		0xF33F6BD669EA7F8DULL,
		0x8F826270E10C4D64ULL,
		0x4A452F5690234270ULL,
		0xE799F9D2AE57827FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 623\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 623 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -623;
	} else {
		printf("Test Case 623 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x72399B15BC86112EULL,
		0xF1873352BC346E68ULL,
		0x502E123694C6C610ULL,
		0xC02876F4DF2E9A55ULL,
		0xD11C1377F1177100ULL,
		0x082AC96C2975B030ULL,
		0xD1DB613A97068638ULL,
		0x6BC82E4A1D859269ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 624\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 624 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -624;
	} else {
		printf("Test Case 624 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x600BDF7D4B07F184ULL,
		0x5526939799716CFFULL,
		0xB90BBDD4AD043B94ULL,
		0x4A7B012F851EAEBBULL,
		0x250D464B97C1C253ULL,
		0x613AFD742CA31DEDULL,
		0xF03F7C8847710C02ULL,
		0x1714F78E78F1C45CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	printf("Test Case 625\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 625 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -625;
	} else {
		printf("Test Case 625 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0CA19067B8CFD93CULL,
		0xDDFB7217A1E876A1ULL,
		0x0281C88F38AA5F5AULL,
		0x257AD004E9E8763EULL,
		0x0A5681D0AC1FF697ULL,
		0x56C2D21F73D98A34ULL,
		0x59985708E6D50794ULL,
		0x15559BC06B16F859ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	printf("Test Case 626\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 626 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -626;
	} else {
		printf("Test Case 626 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5CC4A17669205D51ULL,
		0xDD26BE49B0588EFEULL,
		0x20B821D437FA5D5AULL,
		0x0C178D0F08B97E47ULL,
		0xC653BD871075662CULL,
		0xEC5D5677F5CD68F8ULL,
		0xD5C78367ECFF585DULL,
		0x00386DB3EE62C1F3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0020000000000000ULL
	}};
	printf("Test Case 627\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 627 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -627;
	} else {
		printf("Test Case 627 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1556FA5D623763B0ULL,
		0xC4DAD6D2894C7043ULL,
		0xDD1953225616B1ADULL,
		0xD22762DAB9C88EF8ULL,
		0x0EF4FE4230D931A8ULL,
		0x819155AEFBCEC2F3ULL,
		0x57E5C9E44C44A365ULL,
		0x26E114CCA16D83F6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 628\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 628 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -628;
	} else {
		printf("Test Case 628 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x62267468BFF0E15CULL,
		0xA67C5DE1D8FA7D81ULL,
		0xC378742A98BCC66CULL,
		0x9F9AA1AE6DB29318ULL,
		0x8F8203C89D169399ULL,
		0x7A23107011270317ULL,
		0x8350A511DB7B3305ULL,
		0x8E28841760443B09ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 629\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 629 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -629;
	} else {
		printf("Test Case 629 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x633505A4071399C6ULL,
		0xD4304E0BB1EF9A37ULL,
		0x2E54F9534ABA6280ULL,
		0x9A00C0FAD600D420ULL,
		0xA6C75EF06186372EULL,
		0x4C3EA12B2D340B4BULL,
		0xB0489374D59CBD8CULL,
		0x03515E2C1FA334F5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0200000000000000ULL
	}};
	printf("Test Case 630\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 630 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -630;
	} else {
		printf("Test Case 630 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBBC17F02DFEC34CFULL,
		0x1A3BEC96F674FCBDULL,
		0xDB19D0E894ECA524ULL,
		0xF7911F03E8B4DAF9ULL,
		0xB8CD485BE92BC3F4ULL,
		0x6CC95AFAB62AF591ULL,
		0x7D5D9D77A455D466ULL,
		0x31CCCCF9DD8DA169ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 631\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 631 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -631;
	} else {
		printf("Test Case 631 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2E6B7710CF8A9EE7ULL,
		0x6C07132FA0E09635ULL,
		0x3CFD1013104FB933ULL,
		0xA3AEA0A906A775CAULL,
		0x4420EAE024018E86ULL,
		0x693FF4DFE419F0C5ULL,
		0x7F9B6C79F57A7393ULL,
		0x9CD00E4E495ADE82ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 632\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 632 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -632;
	} else {
		printf("Test Case 632 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x629152C89911A502ULL,
		0x2FEBAE0DDFBF3B14ULL,
		0x6E2CFB8C16C154E0ULL,
		0x909F8AACB5A58543ULL,
		0x8ED8D6CEC8A77F33ULL,
		0x49AAED7629DF2485ULL,
		0xD9A9760A0B1FD9E4ULL,
		0xE3498285C2724E43ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 633\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 633 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -633;
	} else {
		printf("Test Case 633 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA9954D4321F4EA2FULL,
		0x568C0CD5E2E0CDA4ULL,
		0xAEB44832089487B7ULL,
		0x1D674617AD87B3DBULL,
		0xCF1776C60265B49EULL,
		0x28078995327CF2B3ULL,
		0xFD7E715DFFD6B585ULL,
		0x6049C29E6CE5F22BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 634\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 634 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -634;
	} else {
		printf("Test Case 634 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3A9F08A31A1C772DULL,
		0x257DFB5FF71E8BFEULL,
		0xEFFF8AD452BEFB37ULL,
		0x75A16FB459794F1DULL,
		0xF70A84C8090FFFDBULL,
		0xEA9E682A33A4C20DULL,
		0xBF7FB49B21139EACULL,
		0x66DBE56F30F1A8F7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 635\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 635 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -635;
	} else {
		printf("Test Case 635 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA357F2B158A7FB06ULL,
		0xD5C2979E3367FE12ULL,
		0xFD6664742CAAE122ULL,
		0xFDFBA0D1D9CFEAB1ULL,
		0x976D00CA52BC1B1EULL,
		0xC5310811DDB84ED0ULL,
		0x0F457EA2A0996596ULL,
		0x0371321FBC3506B5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0200000000000000ULL
	}};
	printf("Test Case 636\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 636 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -636;
	} else {
		printf("Test Case 636 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB133A0A483E65E9EULL,
		0xAC847E3A6A2F2964ULL,
		0xCC8632B67FAB83B1ULL,
		0x5112649BD5876E30ULL,
		0xB2CACAC2246E77DDULL,
		0xB13BC3F3288B2E03ULL,
		0xD412B2E18D104885ULL,
		0x32B512717A3A9986ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 637\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 637 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -637;
	} else {
		printf("Test Case 637 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1C680B2083302152ULL,
		0x498B861F2B2D174AULL,
		0xDF74D609E9E3379BULL,
		0x4DD71BA9B6BAA255ULL,
		0xF388181579F09248ULL,
		0x69573D8338CBB6E9ULL,
		0xC5B71D231C05F5A8ULL,
		0xAA6FDA55754981C8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 638\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 638 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -638;
	} else {
		printf("Test Case 638 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1FC04225C95CE485ULL,
		0x6212EFDCE5A6F48DULL,
		0xE8F7AC82C9157236ULL,
		0xD580107E7E55D840ULL,
		0x740AA84811F5B6EDULL,
		0xED0545E1038C3162ULL,
		0xEDE9DDC432ED8DA5ULL,
		0x865BF80F90DC5172ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 639\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 639 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -639;
	} else {
		printf("Test Case 639 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA6241721EEFB8B2FULL,
		0xD164C1DAA068DCB9ULL,
		0xE63FB3B58B10A24CULL,
		0xBFBEEAA626FF7D7BULL,
		0xF1C882C7A72D70E3ULL,
		0xC89B3BB52B3B7200ULL,
		0xB5EDF5933EB50776ULL,
		0x251589F850376DBFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 640\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 640 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -640;
	} else {
		printf("Test Case 640 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3F448FD4A41F450DULL,
		0x1BAF14E86B39CEE8ULL,
		0x827F9FACF8C06287ULL,
		0x99BAAF334302421DULL,
		0x9D39D7D6BABEA4B9ULL,
		0x609D3A6279A0306DULL,
		0xBAA6139DBE5CE591ULL,
		0x06E4311C9E2F8AA2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0400000000000000ULL
	}};
	printf("Test Case 641\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 641 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -641;
	} else {
		printf("Test Case 641 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x02AC6A437EF63EA8ULL,
		0x2C8B362ACA3422DFULL,
		0x4F2D720C91C29377ULL,
		0x06C818C3D4813B80ULL,
		0x610228AC380E43A4ULL,
		0x083B9CC7C552EFE4ULL,
		0x8EF49DBF8B894158ULL,
		0x3ED47C2C0A5987A4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 642\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 642 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -642;
	} else {
		printf("Test Case 642 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC96C38589E974386ULL,
		0x8B3B4945CBD3C922ULL,
		0x83F140FE7F0084CCULL,
		0x9FCE30C0380E7954ULL,
		0xE4ACE51EA42626BFULL,
		0xF5AFEB8A43468883ULL,
		0x13FCA8C7F99E42F7ULL,
		0x4B409B243519B80EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 643\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 643 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -643;
	} else {
		printf("Test Case 643 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAD361CE45D4C0FFDULL,
		0x35CA34F27F0A183BULL,
		0x44738C26AEF62911ULL,
		0xC2B3C56B65250303ULL,
		0x1C9D74DE920FCE81ULL,
		0xAC83867E967E30BAULL,
		0xC6A35C97F06E293BULL,
		0x452FBBAE79919CCAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 644\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 644 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -644;
	} else {
		printf("Test Case 644 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD8E97DDDCCD8F677ULL,
		0x721EEE7B40EB7C9EULL,
		0x0520E00A821949C2ULL,
		0x4897317AD506914FULL,
		0x8B9C51B08C8B68A7ULL,
		0x5A748460F45C3294ULL,
		0x9DD1396170AD4632ULL,
		0x1376D7B8009C241BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	printf("Test Case 645\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 645 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -645;
	} else {
		printf("Test Case 645 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDD9C8FDFE6B78970ULL,
		0x5F7DD97458F23CACULL,
		0x39CC4682A5EDE227ULL,
		0xEDFEAE5E7A16E522ULL,
		0xA1C949D2384CBFB4ULL,
		0xD1BACEC4666C866AULL,
		0x803FA6DD8B53BB0BULL,
		0xB9AE67D65575EED5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 646\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 646 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -646;
	} else {
		printf("Test Case 646 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBB6001BE5787FC66ULL,
		0xB62C139FA492813FULL,
		0x182FD9BE13F33E3FULL,
		0x06EDB0BABB1F2700ULL,
		0xAFD4A8A3B7E26DC8ULL,
		0xE1002994C4990930ULL,
		0xBA31BDBD0F3D01ECULL,
		0x380E5E1D5ABF99FAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 647\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 647 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -647;
	} else {
		printf("Test Case 647 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB4F269865ED5C936ULL,
		0x86D8E652C0BEE4DDULL,
		0x6F3D81D9B7ED8547ULL,
		0x5E91AC7EF91483EEULL,
		0x033036CBF146CE45ULL,
		0xB0A1B9C138C41D51ULL,
		0x965BE3FF71199114ULL,
		0x943AF72BB6D1B093ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 648\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 648 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -648;
	} else {
		printf("Test Case 648 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE81282F5510879E8ULL,
		0xC3A8556F126F0A9DULL,
		0x4124DD30AB519CE0ULL,
		0xE98B3D48D93B5085ULL,
		0x9D52B00E29B6D973ULL,
		0x2EDEA38C4A0A2AA3ULL,
		0x9F952EDDFD6585B9ULL,
		0x110E8DFF680DE6CDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	printf("Test Case 649\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 649 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -649;
	} else {
		printf("Test Case 649 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x590AA366BDBFEB9EULL,
		0x2A462ECE2B2075D9ULL,
		0x050F51C23CD60D4FULL,
		0xFE5438E29F117621ULL,
		0xB5053D1BD88ABDA4ULL,
		0xFB6CC25697E008E4ULL,
		0x5A9A78345CC32DABULL,
		0xB0950825F68EDA09ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 650\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 650 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -650;
	} else {
		printf("Test Case 650 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x73944973029CFC32ULL,
		0x3B36E977B294A880ULL,
		0xD7F26761C8D24A64ULL,
		0x01AEF86C906BB455ULL,
		0x0C1A4DA1675A83A4ULL,
		0x2D3D774EEC3323B3ULL,
		0x336AA3F8B86B6BF0ULL,
		0xD81C1BDC087A8FDEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 651\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 651 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -651;
	} else {
		printf("Test Case 651 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB72EFE6348C11997ULL,
		0x969D4B6665765819ULL,
		0xD44FBE9B04C9A703ULL,
		0xAE13F54902CA01C9ULL,
		0xA84C0C86DF79E980ULL,
		0xA637012754383FD8ULL,
		0x8A551DA7073C0BA5ULL,
		0x5E939EC384607E46ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 652\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 652 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -652;
	} else {
		printf("Test Case 652 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC1D2FFC89E6283A7ULL,
		0x820509480E0100A4ULL,
		0xF77CB30662F700A3ULL,
		0x74CB244F296C06ABULL,
		0x2785A544BB05EA4DULL,
		0x8AA81CE699686F62ULL,
		0xDF77C026D60F8665ULL,
		0xB6DEB96F2976C044ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 653\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 653 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -653;
	} else {
		printf("Test Case 653 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x482D7AB9DC42F148ULL,
		0x330FDF26EBB3D6D0ULL,
		0xCB8DA609E1945C19ULL,
		0x460E01A209E8847CULL,
		0x2E3412BD8DADDABBULL,
		0x08C240AF80067DDEULL,
		0x8A2BDA3F00521D6EULL,
		0xCF08DDAC1710A53AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 654\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 654 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -654;
	} else {
		printf("Test Case 654 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8CC7D01D2EB4BE94ULL,
		0xE999863229C93E50ULL,
		0x3F5898F8F6670DC4ULL,
		0x91AFE4B0A8444DDAULL,
		0x867C264C4DA8A7ADULL,
		0x85549EA7D3486417ULL,
		0xDDC2DCEE412935A6ULL,
		0x316B48D8A401AB80ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 655\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 655 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -655;
	} else {
		printf("Test Case 655 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x67589B8997C1F1E8ULL,
		0xD1D5BF7F0672535DULL,
		0x7475877813B51D84ULL,
		0x3BF3395A762503E9ULL,
		0x410CD78E3B78F8BCULL,
		0x4D4DEAFC7557027CULL,
		0x1728ABBFAB5D7CD3ULL,
		0xABBF1189AB429A2DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 656\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 656 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -656;
	} else {
		printf("Test Case 656 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4CDFBB1B7A036B50ULL,
		0x91843A6E070BD56EULL,
		0x65869071DA3729AEULL,
		0xC25CACBF2F7B23BDULL,
		0xB07B8479A0F5A987ULL,
		0x9C324EAAA8139FFBULL,
		0xA7639A54B20BD79DULL,
		0xAEC0A1A4B4ED9637ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 657\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 657 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -657;
	} else {
		printf("Test Case 657 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xACD9D35BFE1179B9ULL,
		0x2BC3B9FD1F2EC417ULL,
		0xC90E3F4CE718242CULL,
		0x5267C21D10F9C7FDULL,
		0xE45DF33170D38023ULL,
		0x5D73C089C931C52CULL,
		0x7FB0E31C65F2FF49ULL,
		0x043CD83B2694BEEEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0400000000000000ULL
	}};
	printf("Test Case 658\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 658 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -658;
	} else {
		printf("Test Case 658 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x64A3D218450B75D5ULL,
		0xEB69CB9ECEE15A81ULL,
		0x1814015CF26DE2FEULL,
		0x316E1B95C8CFA4D5ULL,
		0x05CBBFB42F2FB656ULL,
		0xAAC7CB08F23DF352ULL,
		0x991A461D8F239191ULL,
		0x7375DE05B9DE6814ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 659\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 659 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -659;
	} else {
		printf("Test Case 659 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9B8C86069DE8F33EULL,
		0x1F543ED334D0CA42ULL,
		0x2630AD4B015D3249ULL,
		0x54FA03320AD80C0BULL,
		0xFE4D08B017F004F5ULL,
		0x8FAC5D05987EBF1AULL,
		0x6DBD4702A3A07246ULL,
		0xED05DABA54DB1900ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 660\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 660 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -660;
	} else {
		printf("Test Case 660 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE907EC1427E379E5ULL,
		0xF03175C8654E96D4ULL,
		0xCE80EBAA3EE7A160ULL,
		0xFA0FC6729C7BD613ULL,
		0xF13A292D5D2DA583ULL,
		0xC461441BBA679C74ULL,
		0x41B23F50A3024652ULL,
		0xE094E9B05581773FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 661\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 661 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -661;
	} else {
		printf("Test Case 661 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8940BC9E2EDB74A9ULL,
		0xF5223E378B8ABF91ULL,
		0xDCD78989070B310CULL,
		0xCF7A211037AE7E9CULL,
		0x484C29A21AB1863FULL,
		0xE8C36718C5631B03ULL,
		0xB2AA46F6C479C83AULL,
		0xE4818AB591505CA7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 662\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 662 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -662;
	} else {
		printf("Test Case 662 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE95D2BCBDE0376E4ULL,
		0xB4C3594ACC270A75ULL,
		0x402F2D42F8077DE7ULL,
		0x2B596B001646ABA2ULL,
		0xA2257F7D86A6B348ULL,
		0x52B1CA0E2AF2E4ECULL,
		0xE2E08A1DA6B19019ULL,
		0x97D8CABD120E9AE4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 663\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 663 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -663;
	} else {
		printf("Test Case 663 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x33C75DAEEAEA78B4ULL,
		0x3610D45F5FDF3DEDULL,
		0x923061638DC5EF57ULL,
		0xF3F150DED54801DCULL,
		0x17E9CE3D1E0465CDULL,
		0xE9DA9FD6F1350527ULL,
		0xE6AAE1868AE39361ULL,
		0xAC458BCD9C194727ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 664\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 664 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -664;
	} else {
		printf("Test Case 664 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3C0CD304092C01F7ULL,
		0xA655A1B8B7E0D30CULL,
		0x897B915960BF806EULL,
		0xB853DC8CC775EE4AULL,
		0xA1D743DB2B6868A5ULL,
		0xB6BDD5C4A3892FBBULL,
		0xADA2B2D0D98F01F3ULL,
		0xC168E7356790AFEFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 665\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 665 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -665;
	} else {
		printf("Test Case 665 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x154EE1E70E71C65DULL,
		0x859D2B92ACB2D73EULL,
		0xB328EBFAD5048E94ULL,
		0x05F73A146FE367F5ULL,
		0x76CB2385DE0F8B8BULL,
		0xF249DEB4382F3E76ULL,
		0x9D7C9D35A5D50422ULL,
		0x8DA0F9DC36838BDDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 666\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 666 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -666;
	} else {
		printf("Test Case 666 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3D45A84EAF4C2B65ULL,
		0x3FC9F1D98C7FA08AULL,
		0x19BD758EFF4F5B5DULL,
		0xEE730D848C454078ULL,
		0xDC3145FC4351BD32ULL,
		0xB49D79D829FC2C2EULL,
		0x24D5DC9B73C7AE53ULL,
		0x246A20E522D7E543ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 667\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 667 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -667;
	} else {
		printf("Test Case 667 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x77F4BFFBD6493910ULL,
		0x39EB5D8ADF2A51E4ULL,
		0x6E5A7BD9B7B45A25ULL,
		0x8115FE1EF36ABC1BULL,
		0xABBE7AC6C7CCBD0DULL,
		0xF36BC66EE7A992B7ULL,
		0x34BFD0357D02C09BULL,
		0xFEAE3B19F6DB69A7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 668\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 668 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -668;
	} else {
		printf("Test Case 668 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x21D9B7E792AB2AEBULL,
		0xD038B0A05A53A4B9ULL,
		0x565EEC2C88A499E6ULL,
		0x677F4FE5B5EDFE92ULL,
		0x3F9F69AFCFB36F22ULL,
		0xC0BB0D15BC11BFCDULL,
		0x8B935BA6AD3B2AAEULL,
		0xE34584EE644DE0D4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 669\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 669 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -669;
	} else {
		printf("Test Case 669 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x869C5EFE3A4E3174ULL,
		0x49CAA3A5DA5F5650ULL,
		0x0BBAC00C93A55C21ULL,
		0x0BEF8ACDB87C2DA6ULL,
		0x3BDE585A129CE0BFULL,
		0x75A3BC3A72BFFBEDULL,
		0xDFF9E352D01DEF93ULL,
		0xE32B590C43E3A992ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 670\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 670 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -670;
	} else {
		printf("Test Case 670 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5B960D172660EC61ULL,
		0x4886F16164E87A82ULL,
		0x6B0F99D721AA66D0ULL,
		0x06F16995702E83ECULL,
		0xCCBA7A25239C8403ULL,
		0x04F3B6A0BE4D60F3ULL,
		0xABAE1937244B5D7AULL,
		0x16E26E84E614181EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	printf("Test Case 671\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 671 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -671;
	} else {
		printf("Test Case 671 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFE4BCB6A76AFC758ULL,
		0xE7FA5622216FD83DULL,
		0xF401F7003E31736BULL,
		0x4A02382EC2D98177ULL,
		0xF877836E55C9EB88ULL,
		0x03BE19A9329A35E5ULL,
		0xBCFFF2F090915632ULL,
		0xCCEB65EFC537DB3AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 672\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 672 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -672;
	} else {
		printf("Test Case 672 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x04465C9D102B02E9ULL,
		0x488A85B5F9A2632EULL,
		0x4BFC9B1B5D8CA85CULL,
		0x28262FAF739CC9CDULL,
		0x5ECAF74230C81C63ULL,
		0x0C62E7BDA86F4C56ULL,
		0xAA39555A39A6972EULL,
		0x96DA12F3F477C5ABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 673\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 673 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -673;
	} else {
		printf("Test Case 673 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF07AD868C7D4D3ACULL,
		0x5931D1C4D26CDA0AULL,
		0x8FB9EDB0D28B2412ULL,
		0x6A5CB2451A3E66AEULL,
		0xDD09678D8BC84F79ULL,
		0xA47E0E2BA50C1749ULL,
		0xBBD1A01D1951ADD5ULL,
		0x7410D8FD2A579E57ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 674\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 674 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -674;
	} else {
		printf("Test Case 674 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE1270893F4AD9574ULL,
		0x1193D434C435B801ULL,
		0xABF4AED208A845E0ULL,
		0xDB0006C8280FC5D0ULL,
		0x5EC8B7E0FC2A11C8ULL,
		0xAA4752817C800E3FULL,
		0xD9437C616E4119C3ULL,
		0x18ADBB03FD2E16A0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	printf("Test Case 675\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 675 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -675;
	} else {
		printf("Test Case 675 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x967F87F743B1C1A4ULL,
		0x9BF8A30CBC0D6592ULL,
		0x19CF42E8DCE6ECFCULL,
		0x3B40E5B49C5609C5ULL,
		0xD5EC2915FD993BABULL,
		0xC79C019DC7EF4CE2ULL,
		0x5BDE3F2898CC0730ULL,
		0x48035B222CA6EC6FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 676\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 676 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -676;
	} else {
		printf("Test Case 676 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0A7361A66ED07B75ULL,
		0x8510BE11F366AD7BULL,
		0xD72BC2C2F1E2280EULL,
		0xD1D83C8A6300089DULL,
		0x8CE545A7EB8E0811ULL,
		0x80B443D8F807B9BCULL,
		0x689FCBF3BBAA2BF0ULL,
		0x1D53E108974F3296ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	printf("Test Case 677\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 677 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -677;
	} else {
		printf("Test Case 677 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8E5EA202EDAA2B2CULL,
		0x69BB11D0176DC53CULL,
		0x257740A47FEE5D72ULL,
		0x8C231266779D9333ULL,
		0x2DA66767C9DD7DBDULL,
		0x8980106A4D51E826ULL,
		0x9C5A559E7A580B8EULL,
		0x4985AAF99C692A36ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 678\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 678 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -678;
	} else {
		printf("Test Case 678 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE8EAFDC3AC8AC45AULL,
		0x6323AE7985306ED8ULL,
		0xF13E49D9B662ED4BULL,
		0x3AACA737BDBD60EFULL,
		0x120356F0F898DF3BULL,
		0x51C333EB9767C201ULL,
		0x2174DF5D5AB47C3EULL,
		0x2ECD5FEF743A287BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 679\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 679 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -679;
	} else {
		printf("Test Case 679 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x80757585E739C134ULL,
		0x2566EF0337F0A61BULL,
		0x0486C11D16188722ULL,
		0xB62B039DA1F71366ULL,
		0x1A284CC50C27CD3CULL,
		0x8352F85F48375C4FULL,
		0x9A82A809FB808604ULL,
		0x653B41D3428536DCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 680\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 680 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -680;
	} else {
		printf("Test Case 680 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDADDAC631D08B05CULL,
		0x195C3CA249F0C305ULL,
		0x310D208639AA4856ULL,
		0xB92CF09F3B245553ULL,
		0x03F5F585C61AB658ULL,
		0x1366A12B48732E69ULL,
		0xA02B550BC1211D39ULL,
		0x1DD3FA4EAD5CD76DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	printf("Test Case 681\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 681 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -681;
	} else {
		printf("Test Case 681 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4C6EA3CFACA60E0FULL,
		0x757DC812B19225D7ULL,
		0xCE77CE9100C3C7FEULL,
		0x115019C7C7D0055DULL,
		0xCA2FEAE3482B311FULL,
		0xB1ADBADDF05A117DULL,
		0x580537F8FD6E356EULL,
		0x2A4025D5054B1755ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 682\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 682 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -682;
	} else {
		printf("Test Case 682 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x72F217111E8C892DULL,
		0x036126CFF76E90E0ULL,
		0xD91CCC86750620CDULL,
		0x25CE9274D7B01A61ULL,
		0x8D4B93693C2C130CULL,
		0x3E93C4B3294E0A0FULL,
		0xA91F87106001A517ULL,
		0x61770B5D4C38374EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 683\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 683 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -683;
	} else {
		printf("Test Case 683 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x630CAB1F1E9C82D6ULL,
		0xF6CE32BFE050151CULL,
		0x3C3D3C4FF4746265ULL,
		0x0CCC4A30F1CBBC83ULL,
		0x20304CB487A67A29ULL,
		0x79CC7327D6473CD0ULL,
		0x3CFCF7639EBE0E01ULL,
		0x33CB1A4895B194CCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 684\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 684 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -684;
	} else {
		printf("Test Case 684 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1AB35BC7EC299FFAULL,
		0x9DA1723F9DCFA920ULL,
		0x4BAF90091946259BULL,
		0x2C52A1F409C9C3E2ULL,
		0x2F1E879847C34A34ULL,
		0xCAFA2775E4EE04C7ULL,
		0x156202B52FEE6050ULL,
		0x19C43253850C2A08ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	printf("Test Case 685\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 685 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -685;
	} else {
		printf("Test Case 685 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7EA34EFE01557DBAULL,
		0x78B4497F7D64BB26ULL,
		0x3C9CDF2BE85CB93CULL,
		0x9FC3A2465DB4C071ULL,
		0xD145C952621113E6ULL,
		0x299088067C209D05ULL,
		0x337A8777BDCCE291ULL,
		0xEDA9A6FD0D6C3792ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 686\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 686 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -686;
	} else {
		printf("Test Case 686 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x163B6C49B362FFCAULL,
		0xFE5D1563778E51C4ULL,
		0x86F5BFA78F286384ULL,
		0x960D33FF979C1B1DULL,
		0xEC696AC97EAA79C4ULL,
		0x1FB550DC897E954DULL,
		0xBCEB3B6D98471D95ULL,
		0xB940E942AA415B2EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 687\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 687 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -687;
	} else {
		printf("Test Case 687 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAF8355D5B321C66DULL,
		0xB2C6CDBB193F4288ULL,
		0xFD0972762DCEF5F9ULL,
		0xB2AD101448341E90ULL,
		0x34A9595B466315A2ULL,
		0x4BFF4F4DDC5A3250ULL,
		0x9449D4FFCD5A7E4CULL,
		0x0C1256BD9F662933ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0800000000000000ULL
	}};
	printf("Test Case 688\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 688 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -688;
	} else {
		printf("Test Case 688 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x42C1DFBA3DF59206ULL,
		0x8895428E73EEFEEDULL,
		0xE384405F2618915CULL,
		0x5336774497E48BD2ULL,
		0xD9F0AA21FD3A27CCULL,
		0x5AA5A1E63FAD40E5ULL,
		0x1190DB67BE639C03ULL,
		0x1F8FABF33F0DE5D3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	printf("Test Case 689\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 689 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -689;
	} else {
		printf("Test Case 689 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9DC2B080FB73EEEFULL,
		0xA24ED1F3536563E5ULL,
		0xA9C19906D6AC6E84ULL,
		0xB2ADA6D787CCF9C2ULL,
		0x46376B8B24A6B668ULL,
		0x9844F8A9F5D44851ULL,
		0x56D78B0531B30F13ULL,
		0x1BCFEBE3E46B9E04ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	printf("Test Case 690\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 690 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -690;
	} else {
		printf("Test Case 690 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCD1370E9DC56CA57ULL,
		0xF680A239BFE014B3ULL,
		0xC9DFDFA83D511CE3ULL,
		0x5429FBD3661DADBDULL,
		0x9C6B17AC74B72966ULL,
		0xDFCDCDFD99319265ULL,
		0x9260D90AF3898965ULL,
		0xE966409C000EDE85ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 691\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 691 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -691;
	} else {
		printf("Test Case 691 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB64EF24442661EDAULL,
		0x091E9B8E57E4E248ULL,
		0x337A2308FCE6ED80ULL,
		0x18F252BA99D6197CULL,
		0x1937E0051221472AULL,
		0xAB941015F3E3D6F9ULL,
		0x64DB76414A560CEFULL,
		0xA5529E295C735B7AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 692\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 692 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -692;
	} else {
		printf("Test Case 692 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4B98319DB622C7D9ULL,
		0xC85DF251FF9337CEULL,
		0x2D32D3122DEBEB3FULL,
		0x92BA6C95F9237DE0ULL,
		0xEED6DA53FABDDEE8ULL,
		0x867792BD93AF7CB1ULL,
		0x772542A760166E26ULL,
		0x9D45AE571CAB9B4FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 693\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 693 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -693;
	} else {
		printf("Test Case 693 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x040973AFB1319E93ULL,
		0x0C9756B1A7B963D1ULL,
		0x293517C6D227B64FULL,
		0x2085C126E5652BAEULL,
		0x6AFDCDCFD04B764EULL,
		0xE71DC94DAC48F335ULL,
		0xB4B05767B091A36DULL,
		0x0FC380518907780BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0800000000000000ULL
	}};
	printf("Test Case 694\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 694 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -694;
	} else {
		printf("Test Case 694 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE193F270F05BC650ULL,
		0xF9C07D9A3CB3D2B4ULL,
		0x847FB21FC64B8A7DULL,
		0x98F1D6F86C54D3B3ULL,
		0xCE825AA73F921187ULL,
		0xAC32D39964D972F5ULL,
		0x60C0B432CF5EACD5ULL,
		0xE21B0E561EE5B331ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 695\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 695 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -695;
	} else {
		printf("Test Case 695 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x53C7FED4DFE797EEULL,
		0x656FDB2C1642D66DULL,
		0x096A7251229C6DB2ULL,
		0x30E567AA03719385ULL,
		0x2414BA937D26DAFFULL,
		0xEBC181AA34AA4DEAULL,
		0x1307B52C760F7D2DULL,
		0xADFC7A5DB1E2FAC4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 696\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 696 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -696;
	} else {
		printf("Test Case 696 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x18C6D19172DD2D71ULL,
		0x577AED25C010A787ULL,
		0x7BD5D7A6F5A65183ULL,
		0x66071A8F79D3F221ULL,
		0x07108DF96B490C80ULL,
		0xC67073C1097DF2BBULL,
		0xA6EBD7CAB195DE26ULL,
		0xCE713900362D324FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 697\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 697 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -697;
	} else {
		printf("Test Case 697 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3DD926A39467F49FULL,
		0x171E838DCA6D5D70ULL,
		0x4BE6CD023F8D1E9AULL,
		0x66FB0801028075CBULL,
		0x9B5DC1C1059C098DULL,
		0x7F1C7C229FAC073DULL,
		0x8360326803E695E5ULL,
		0x26EC8E7E9E7A9FA6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 698\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 698 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -698;
	} else {
		printf("Test Case 698 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x19335C9E6433A862ULL,
		0xC85DDF21062A4A33ULL,
		0x5A8C92EE9DEA39B2ULL,
		0xE3AE7BE5DCC2BD28ULL,
		0x8BD21BEF4BD16347ULL,
		0x52704B8FE8E7962EULL,
		0x5944A03642CB0B9BULL,
		0xB19ADA83D8248FFFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 699\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 699 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -699;
	} else {
		printf("Test Case 699 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1568081206D30D7AULL,
		0x9DA899A9CCF7D2FDULL,
		0x5EF82A077506F5DBULL,
		0x2845B517FBB25CCFULL,
		0x3A99CCC594465225ULL,
		0xF87E26B413B35B1BULL,
		0x7B3ACD65A3845A35ULL,
		0x3EF9CD5AB8CF81DBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 700\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 700 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -700;
	} else {
		printf("Test Case 700 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA1572EE5C31E10C0ULL,
		0xDB81995C447A25BFULL,
		0x630BC5D70D504D84ULL,
		0x103480CA54190715ULL,
		0xD9647C07CEFDFC3DULL,
		0xF3ADEF1786FED157ULL,
		0x96A8B201DF3C937BULL,
		0x49D7D043D5F8FEC5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 701\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 701 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -701;
	} else {
		printf("Test Case 701 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x154A601B6A70E305ULL,
		0x5E54F00A1E62B37EULL,
		0x7075F64AAA06BA50ULL,
		0x731DB37DD30F10A2ULL,
		0xDEF35809B9A160EFULL,
		0xD0AB74C3DEB7CCC3ULL,
		0x9BAE555EB747FCFBULL,
		0xC161888CDCEEB8A5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 702\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 702 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -702;
	} else {
		printf("Test Case 702 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE947A536656F35D9ULL,
		0x7D646DB141DBA8ABULL,
		0x543BCCDFE4A88D17ULL,
		0x7D0BA7BEBE37F1B7ULL,
		0x30ABB37D9323E855ULL,
		0x275048B30B435B89ULL,
		0xD73637DAC2811CA2ULL,
		0xB25726998A927085ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 703\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 703 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -703;
	} else {
		printf("Test Case 703 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x096D7F785FF5873DULL,
		0x47963DB6A109BC4DULL,
		0x8480FC17E18617D2ULL,
		0xC05D67C723E32CD4ULL,
		0x018BFAF67C5EA57FULL,
		0x8942B7907E99512FULL,
		0x77FBC656A6707346ULL,
		0xB40449979791E92BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 704\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 704 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -704;
	} else {
		printf("Test Case 704 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x51531C8A83FDE115ULL,
		0xFC441FB03DB9AF0DULL,
		0x78056F45E6BB559BULL,
		0x216310A2FF7690F9ULL,
		0xC408F50F15FA8F33ULL,
		0xEA9538CC9BEBE5F9ULL,
		0x755A824881B7556EULL,
		0xE752A1885E1AADD2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 705\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 705 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -705;
	} else {
		printf("Test Case 705 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9D2BA80FB2B76770ULL,
		0x6728844E067F79C6ULL,
		0x77CE23B69DA8190DULL,
		0xC08A98A15D34C4C1ULL,
		0x583C0E6EE5D94691ULL,
		0x2212BAF74AC1F189ULL,
		0x6CD8AF057F1C7AD8ULL,
		0xDC975AD7DB46451EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 706\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 706 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -706;
	} else {
		printf("Test Case 706 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2E3F7D7EBCD7C588ULL,
		0x754F69AF010B62C7ULL,
		0x363980CDBB740C41ULL,
		0x7BC5500255B90EC5ULL,
		0xEAC8D9F490FA297DULL,
		0x16750BBECC1F7E2FULL,
		0x6E4ECD813DE091DAULL,
		0xA2D1E9F7944B6DA2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 707\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 707 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -707;
	} else {
		printf("Test Case 707 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA833463F88CFE6D5ULL,
		0xFCB7549C5E9F203FULL,
		0x79C030B252F8560EULL,
		0xBB1533E4056B261AULL,
		0xA06DE2C8A06A96B5ULL,
		0x80F94FDB680E2159ULL,
		0x6E356E89E279D686ULL,
		0x8F55EAAFF757EBC9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 708\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 708 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -708;
	} else {
		printf("Test Case 708 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x89460CF1C0F80199ULL,
		0x7AA3688AF374671EULL,
		0xBC366A405619532AULL,
		0xD739F82D2AD080C5ULL,
		0xA2FB433971B67832ULL,
		0xB193BACD00CC74DEULL,
		0x35CAE284367FA7CEULL,
		0x53ED700CC1D9DCC9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 709\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 709 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -709;
	} else {
		printf("Test Case 709 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x53BDFDBB77F5C086ULL,
		0xC5D48ABF33E81B8AULL,
		0x2E011B07C7E55F56ULL,
		0xEB4920B5168A8EC8ULL,
		0x744D71FA9DF51333ULL,
		0xDE04954A9F09F29FULL,
		0xFDCC2BBE79E11449ULL,
		0xBF196B980C2FC0CFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 710\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 710 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -710;
	} else {
		printf("Test Case 710 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x543BE748B9AE59FAULL,
		0x122147B45431D389ULL,
		0xBBEBE490896BC5B3ULL,
		0xB59B5738E888FE0EULL,
		0x014480658F879D82ULL,
		0xFF54950C718C9707ULL,
		0x7F0927DDE0BC0B35ULL,
		0xA56040AAC02F1935ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 711\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 711 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -711;
	} else {
		printf("Test Case 711 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4FB88640ADF44F82ULL,
		0xD7DED62E5CF913A9ULL,
		0xC1DB7D888EABE2C4ULL,
		0x3DFD226E066B29CAULL,
		0x943ED20276078E02ULL,
		0x37B4386444CCAED7ULL,
		0x05CF2537296627A5ULL,
		0xA628F9FA44E8183DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 712\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 712 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -712;
	} else {
		printf("Test Case 712 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEB5AF1E68337888FULL,
		0xA755E9AA11EBD532ULL,
		0xA82AACAA780F6337ULL,
		0xA2744050C7B2697AULL,
		0xBD916FB0BD7912B4ULL,
		0x2A7BEEADF483F5FDULL,
		0x361C5B719C30C123ULL,
		0xBDEAD5BCC56C50F4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 713\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 713 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -713;
	} else {
		printf("Test Case 713 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE182D15903B4CF2EULL,
		0x17708F3E21E702B4ULL,
		0x0EB1840CD6E35327ULL,
		0x5CE1D8437F28B90DULL,
		0x9E38FDAB5B6FBA82ULL,
		0x3D3ACD9335F80A70ULL,
		0x2659CF1D2921943AULL,
		0x3D64C529A5957213ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 714\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 714 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -714;
	} else {
		printf("Test Case 714 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1C60DCB1DA3AF958ULL,
		0xD7FE295A5959EACBULL,
		0xF678FF1E07DB7482ULL,
		0x2CB5D6DBA11AAB48ULL,
		0x26FF142952B6DE0FULL,
		0xFDCB80B1B7B6AD97ULL,
		0x6154CA9E15640E28ULL,
		0x86FB70639AE1CC1CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 715\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 715 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -715;
	} else {
		printf("Test Case 715 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x899BC98C04D2BECBULL,
		0x32D337DF2660F144ULL,
		0x9C687BDBC36FEE16ULL,
		0x30A26C4902100B2CULL,
		0x1F81AD1F2C6A7782ULL,
		0x45B019E6967AE69EULL,
		0xE8893BAE3FAE28FDULL,
		0xCD5BFBDFE7204A46ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 716\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 716 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -716;
	} else {
		printf("Test Case 716 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x349EAE43C79B9290ULL,
		0xF6BFE560C34B6059ULL,
		0xE60A7335464A7649ULL,
		0xC5B3877D1EBCB470ULL,
		0xBFE150FB21AC3374ULL,
		0x27945EBD3283ADD9ULL,
		0x31749A92A3268EDAULL,
		0x18E5D4CE1E84BE8AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	printf("Test Case 717\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 717 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -717;
	} else {
		printf("Test Case 717 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEF252B226240F072ULL,
		0xA08719015D4ACA46ULL,
		0x5DF544B26488EE03ULL,
		0xDE78D8AA67D70468ULL,
		0x9ADC8577D71D5DC8ULL,
		0x21E556D139CF5BE7ULL,
		0x1E8EFB99089E067AULL,
		0x55AA8F4DAAA6D50EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 718\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 718 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -718;
	} else {
		printf("Test Case 718 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAF2AEB36C3ED259FULL,
		0x267F756E1ADCD0C5ULL,
		0x2E0387E747A57429ULL,
		0x7007BA6EEE8EA9C9ULL,
		0x7920D3846F527E77ULL,
		0x7D21F077721868F9ULL,
		0xC023883CE15C6607ULL,
		0xA056431920207626ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 719\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 719 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -719;
	} else {
		printf("Test Case 719 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x51CEBADBA8BC9812ULL,
		0x7DFF7ABC2FD39392ULL,
		0xFE830EB42D19D668ULL,
		0x79E7C33871B9DB80ULL,
		0x540DB0BCEE9F7617ULL,
		0x245F9C0828ED8CC1ULL,
		0x9519B4E271A3DAC9ULL,
		0x86861FAD460D11EDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 720\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 720 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -720;
	} else {
		printf("Test Case 720 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8CF6CDA20D7ADA07ULL,
		0x017F7885CE08C596ULL,
		0xD15C918F62BFD1D8ULL,
		0x4D631047D88908D7ULL,
		0xE3D19863B60381BEULL,
		0x064DF1C3CCD94E57ULL,
		0x5E6BF071F2E61343ULL,
		0xA1F5D01808D1BFBCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 721\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 721 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -721;
	} else {
		printf("Test Case 721 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAE958C01F59CA7E3ULL,
		0x0DFFB85F3D3478C5ULL,
		0x77F3A9AB3A30DAD6ULL,
		0x48B57F5E20349AB6ULL,
		0xF3D6DBD2E691E3BBULL,
		0xF9153BA113B39986ULL,
		0x88121B7E50157DBDULL,
		0x3C940A8CBD555C79ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 722\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 722 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -722;
	} else {
		printf("Test Case 722 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3F758F459731A96FULL,
		0x55D4576EC3B9BF12ULL,
		0xFB826C52F650DA94ULL,
		0x7F680496A010CF2EULL,
		0x83FE8B27D79DABBFULL,
		0xC71A28CE8FC88DBBULL,
		0xC89B23527FBA1D47ULL,
		0x28E09B58298A3B16ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 723\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 723 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -723;
	} else {
		printf("Test Case 723 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6D57D14AC4510897ULL,
		0xDFA68BF79FE7492CULL,
		0x4708827A9125E1A5ULL,
		0xE5385E4AAAF0294FULL,
		0x3FD5322870797F76ULL,
		0xB3F065A7DD4BA259ULL,
		0xB2D58C8D6BC2F9E6ULL,
		0x4C30FE0AF139595DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 724\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 724 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -724;
	} else {
		printf("Test Case 724 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x62E8B4817A48F774ULL,
		0xFDF861BA3E1F34F0ULL,
		0x0ADEEABCDE4CACD3ULL,
		0xEDBED4FE3915E222ULL,
		0xED364A6E83BCA18DULL,
		0xD3B441B6AF330823ULL,
		0x49854668387383BCULL,
		0x276EC2810058F48DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 725\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 725 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -725;
	} else {
		printf("Test Case 725 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAF2B0D276D701329ULL,
		0xB539781666EE0D7AULL,
		0x024927F85DA4494AULL,
		0xA02FC3D254D560D2ULL,
		0xC7AFD3FB3704695FULL,
		0xAE08918ABFBC106FULL,
		0x2A89601914964DC3ULL,
		0xC17A34F937F7CA34ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 726\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 726 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -726;
	} else {
		printf("Test Case 726 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x83869A450989B47CULL,
		0x76853F6F69242F75ULL,
		0xDC49301D1856F3F6ULL,
		0x34652BF9DDFBB1D7ULL,
		0xEDC9E58E94E5E0A8ULL,
		0xFB026127CDFA4CA3ULL,
		0xCE5D11F6FE3B0BA5ULL,
		0xC723B0D30FCE815CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 727\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 727 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -727;
	} else {
		printf("Test Case 727 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8BF1E291770EEC30ULL,
		0x8AEE9595F7D87FA5ULL,
		0x8BF882AFDB27CE2FULL,
		0x398C443D5653EEF2ULL,
		0x29329FC584E908BDULL,
		0x970DC1DE6955AA00ULL,
		0x08DF21782592DC00ULL,
		0x16745F3644C4D4ADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	printf("Test Case 728\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 728 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -728;
	} else {
		printf("Test Case 728 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9CAD5F8A062CF0F8ULL,
		0xC227BB080AF9EC7EULL,
		0x6406708D407A9AC5ULL,
		0x373257587F180E14ULL,
		0x4C7636C8F12F9701ULL,
		0xDD25D4DD0D0E48A0ULL,
		0xC2F9F382759536E2ULL,
		0x5DBD323F58921B6FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 729\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 729 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -729;
	} else {
		printf("Test Case 729 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCDD461FD206C3246ULL,
		0x0288AE0F372282D0ULL,
		0x1902280158A35EEDULL,
		0x457BB03F6246159FULL,
		0x392F22FEDEA0DEB2ULL,
		0xA9EFCDE0163F9969ULL,
		0x56BE986CD56050A7ULL,
		0x3CD0CA8A23B82C46ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 730\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 730 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -730;
	} else {
		printf("Test Case 730 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0D599209C97909F9ULL,
		0x95E3365B8EC122D4ULL,
		0x0AADF8ADB64339D6ULL,
		0x57AD6E286827C905ULL,
		0x947896C8BA298719ULL,
		0xDF491F70064796F8ULL,
		0xD7612B1294D44504ULL,
		0xEB99DD9DC2804106ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 731\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 731 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -731;
	} else {
		printf("Test Case 731 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9918C6B1097B2CA5ULL,
		0x721435050D25F554ULL,
		0x38ECCFB21BD4BAF8ULL,
		0xF020DF83FB140738ULL,
		0x8F4953AB9D577DE9ULL,
		0x0449AF855E7CBC72ULL,
		0xFC219DEEA28AA81CULL,
		0xC543F9A29B2CFD60ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 732\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 732 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -732;
	} else {
		printf("Test Case 732 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAF3D5CB793B368C0ULL,
		0x8DB813A00CD38390ULL,
		0x1D9490E5F24DE723ULL,
		0xDC8A33858256D927ULL,
		0x815E22A7CCD6DDA3ULL,
		0xDF28E58D715EB7B4ULL,
		0x57D60966353ACD67ULL,
		0x9C8295D3A6DF9A51ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 733\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 733 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -733;
	} else {
		printf("Test Case 733 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5EFFE35D19C28B07ULL,
		0x2D523D5EA7DE1B8EULL,
		0x75251DB518CEF452ULL,
		0xFF02D51FE38E9442ULL,
		0x74A73FE620096C55ULL,
		0x3DDA4DC79CFE563DULL,
		0x698F66DDFD07CC7FULL,
		0x81A513037D71F062ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 734\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 734 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -734;
	} else {
		printf("Test Case 734 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4C2EF292CCC6AB8EULL,
		0x1BAE5D31BBD4CC02ULL,
		0x328C475B4583E73AULL,
		0x037613B8277B800DULL,
		0xB2E3D764C0947CFFULL,
		0xBB72CE7CCCE5B90BULL,
		0x47A52AD65AD33795ULL,
		0xAAF1EC258D7C6657ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 735\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 735 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -735;
	} else {
		printf("Test Case 735 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9A99902F6788FDD9ULL,
		0xCCADA75A9E96BF7DULL,
		0x3CE56E92C386D265ULL,
		0xAF4FB569DE3D4CA8ULL,
		0xF78B6E2BB444F218ULL,
		0x17ACC35C2088713FULL,
		0xFC964CAD251D0D58ULL,
		0x29E7EA8226857942ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 736\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 736 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -736;
	} else {
		printf("Test Case 736 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAD19B75F73D9E426ULL,
		0xDE7C9A89FDFB6972ULL,
		0x4D2E0B8BA1589BF3ULL,
		0xA9ECF18E79D34C39ULL,
		0x002C1783A1C61981ULL,
		0x585C528825DF7A89ULL,
		0xD853C841447A9F9EULL,
		0x2C42888E81FAFE9DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 737\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 737 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -737;
	} else {
		printf("Test Case 737 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF2BEB10E49EC9AE6ULL,
		0x7889CD8C66B933D5ULL,
		0x6320371130BF601FULL,
		0xF02ED8B71CA0DB31ULL,
		0xFEE31AC980A01E94ULL,
		0x991975B317D9FCF2ULL,
		0x030EB4B3460E4EADULL,
		0x9ECFA60B29AC2102ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 738\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 738 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -738;
	} else {
		printf("Test Case 738 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x66CAFC414263E604ULL,
		0x8F0D9AE86D396CA0ULL,
		0xE399CF0961BAE6C9ULL,
		0xC16D08C897B9E529ULL,
		0xA5A4E27C3565E9EAULL,
		0x6DC44330126BEF9EULL,
		0x6C514246F3736CEAULL,
		0x28BA630494C18819ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 739\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 739 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -739;
	} else {
		printf("Test Case 739 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x925A17541892FD75ULL,
		0x4A61DCCCB6B15C28ULL,
		0xF0215049ED099665ULL,
		0xB60F21A8A06A2EE1ULL,
		0x412225DBE1A42FACULL,
		0x3910C0C90F63A9B6ULL,
		0xA71E3F5ABFB3CEE9ULL,
		0xDDB8470471819FBAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 740\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 740 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -740;
	} else {
		printf("Test Case 740 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3C1FAB3D03A428B6ULL,
		0x050EEB75AA9ACD47ULL,
		0x3FA445EC834C8FD5ULL,
		0xFB62B8F1345D9484ULL,
		0xB9CCD9A4CE8FCE36ULL,
		0x5129A4879180BAB4ULL,
		0xF8C5B6EA49ABB80CULL,
		0x7CE94899E43A5ACAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 741\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 741 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -741;
	} else {
		printf("Test Case 741 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6DAC50EABC926E7FULL,
		0xB6F07E58EDB9BB01ULL,
		0xC1A244EFB4ED80B7ULL,
		0x6ABED40EE0F46E6DULL,
		0xC1EBC6B9345A072CULL,
		0x12746ED2406D0336ULL,
		0xC60B55CE7BE37AF3ULL,
		0x85700C581FA567F2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 742\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 742 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -742;
	} else {
		printf("Test Case 742 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEBA6C1FB1CB4277AULL,
		0xF4964206B761559AULL,
		0xBA168E1AA98A5198ULL,
		0xADF7E4921D255320ULL,
		0xB8F94DA12B44BB17ULL,
		0xC0EE57D51D0B6736ULL,
		0x3002650DFF9E4AAFULL,
		0x8C2390FA32DD2DA1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 743\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 743 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -743;
	} else {
		printf("Test Case 743 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFCA10FDB1A38A114ULL,
		0x08B6A32A9628CD83ULL,
		0x323A9D0402CFBB99ULL,
		0xF272D5766258D38FULL,
		0x095B8E19D6B08DE2ULL,
		0x1F2CE1D900B6CD71ULL,
		0x40021185B1650AE3ULL,
		0xDD13775C46E9AF0FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 744\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 744 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -744;
	} else {
		printf("Test Case 744 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9D9E5EEAF79006C5ULL,
		0xC0F62D69BE57C5E9ULL,
		0xF8C5E2DAD8B25C58ULL,
		0xF7DCCF8294F3B7D7ULL,
		0xA06B66CA6CA9D55CULL,
		0xC37D1B4ABECFE4C0ULL,
		0x638232E73E68CA95ULL,
		0x9720BDE7D5ECD7A0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 745\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 745 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -745;
	} else {
		printf("Test Case 745 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC8BCF38B45C2A882ULL,
		0x1EFC1D0A419B7063ULL,
		0xEF0CDD82ED7E6DC9ULL,
		0x92E43B9C538086D9ULL,
		0x161E07A7D56E01B8ULL,
		0xF862D63C17D79CE6ULL,
		0x7960E8A4C50DFBFAULL,
		0x7B2C4586B94910A4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 746\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 746 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -746;
	} else {
		printf("Test Case 746 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF048CD3CB1FE1440ULL,
		0x28E34B4CAD39CF6DULL,
		0x8279B6D3A838AFDEULL,
		0x28BB8709F028EA14ULL,
		0xAF004E1651FC7256ULL,
		0xB1DC31EDA9CDC066ULL,
		0xF4D7AD910955FB27ULL,
		0x01B0441F31FC6605ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0100000000000000ULL
	}};
	printf("Test Case 747\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 747 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -747;
	} else {
		printf("Test Case 747 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x211FC680A358DE5CULL,
		0x4978C0363D0B0E20ULL,
		0x9117BA0D46F263F1ULL,
		0x0C4F23D4D50B6830ULL,
		0x4B46480FDFA3C317ULL,
		0xD51F6531F24B1559ULL,
		0xE24DB20E6312E539ULL,
		0x1304B0CB39CE3630ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	printf("Test Case 748\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 748 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -748;
	} else {
		printf("Test Case 748 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE21E5548CAF13AE1ULL,
		0x704F3A3B7A8AD5E4ULL,
		0x62E432324D477B4BULL,
		0xA3AF805F8BC61891ULL,
		0x6945D925D998D3AAULL,
		0x53ED2430BC3C7DCFULL,
		0x1BECC9623AB33B1FULL,
		0x6DB845C77DAB4865ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 749\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 749 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -749;
	} else {
		printf("Test Case 749 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE37D9FD53D41DCCCULL,
		0xA832B0CA96F40FBAULL,
		0xFBEBCD348B9E69DBULL,
		0x04B704587A28F71DULL,
		0xB0479ECD13FDFD07ULL,
		0xEA5EB89353EBCB6CULL,
		0xD5CF40388658CB90ULL,
		0xDD05C9A8CEE5683EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 750\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 750 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -750;
	} else {
		printf("Test Case 750 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB60B0FA3D684B037ULL,
		0x897D63B8CC03231EULL,
		0xEB48ECF6898CB04CULL,
		0xED9301C0C60BBB15ULL,
		0x833981384507C60EULL,
		0xAE5DA4D08C16A274ULL,
		0x4E67D06D6BDD5B14ULL,
		0xBF94B08D977C1578ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 751\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 751 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -751;
	} else {
		printf("Test Case 751 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9A209586CA48E55FULL,
		0x73EBB2B437855380ULL,
		0x808F03934CAC2093ULL,
		0x32E653B57888E8AAULL,
		0x92E1DCC60D526CAEULL,
		0x6B4EABF12BFF309AULL,
		0x738949B8D217D246ULL,
		0xD519880028B0C073ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 752\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 752 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -752;
	} else {
		printf("Test Case 752 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x30FCB3708B698E76ULL,
		0xC870A746A0BA012EULL,
		0xC4EC0476AD1DB02DULL,
		0x672CD049F784CAFEULL,
		0x009357ADBBA69D54ULL,
		0x140CE740926D6826ULL,
		0x0469CF6C5F47EA08ULL,
		0xF7A97FB73B482FABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 753\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 753 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -753;
	} else {
		printf("Test Case 753 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA2727EBB527B6858ULL,
		0x8175E9FF41EE7E43ULL,
		0x81D551F63B667C5BULL,
		0xC290D052767440B2ULL,
		0xF75567937B364C8EULL,
		0x6D9FA013A920A942ULL,
		0xA38F8B96954FBC2CULL,
		0x1F1DE4FD3F4FE9B9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	printf("Test Case 754\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 754 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -754;
	} else {
		printf("Test Case 754 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCC292CF707199A2EULL,
		0x3F88D99B0E9C43F1ULL,
		0x5DA09D5DAF11B1DEULL,
		0x31406C5335403A5FULL,
		0xE74F5489DEB4605EULL,
		0xBC9D84B989C8809EULL,
		0x33E61F238426E251ULL,
		0x8C8B057FA5167D8CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 755\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 755 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -755;
	} else {
		printf("Test Case 755 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2EF015B4C32BB0A3ULL,
		0xD0DCC70870F26371ULL,
		0xD0AAB86A27C9BFA1ULL,
		0x4F64C61A260A7067ULL,
		0x629E37420F877D6EULL,
		0x50A2BC924160A155ULL,
		0xA65D0EEF298F734EULL,
		0x6716E4763BCC454EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 756\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 756 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -756;
	} else {
		printf("Test Case 756 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD2B77F3C29F1FE85ULL,
		0x2E4FED5D38BBF3BAULL,
		0xE52D8A8785B2F710ULL,
		0x9D47C96C709D599EULL,
		0xF267A73A14608467ULL,
		0x1D0154A192B8B95CULL,
		0x9E1CA4A9D0DFF07CULL,
		0xDFFE444CEDC8384FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 757\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 757 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -757;
	} else {
		printf("Test Case 757 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC858B1F05685F49BULL,
		0xA65599A60FAA1220ULL,
		0xEF8F825FA05BE716ULL,
		0x750909304CD38D8DULL,
		0x3486148E26A98FC6ULL,
		0x68009966F4854E94ULL,
		0xF26A1218DC7ABF02ULL,
		0xD399B34B269C9B33ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 758\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 758 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -758;
	} else {
		printf("Test Case 758 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC8EB593CDBE89D62ULL,
		0x29F843016A8B6DD2ULL,
		0x155DA0150E5AA791ULL,
		0x495BB2FA6C384DF3ULL,
		0x4ED17EA2E88679D5ULL,
		0x56E030DE130E59F9ULL,
		0xD18866A6A26112D3ULL,
		0x6CE413933522ED92ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 759\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 759 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -759;
	} else {
		printf("Test Case 759 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6CDD87E6FE266701ULL,
		0xCA7A1217FAE6FB32ULL,
		0xC66706EF0406E649ULL,
		0x000F58434F90ED1EULL,
		0x6C719A9C6A3EFC0CULL,
		0xF774B70AA8610C5CULL,
		0x4732E352726460C5ULL,
		0x6FD0BD0F962CDD94ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 760\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 760 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -760;
	} else {
		printf("Test Case 760 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF36C8CA06FA4828EULL,
		0xB5926BF68379EE03ULL,
		0xAF6F8A659B4C3816ULL,
		0x8F1F6ED8B8F7A530ULL,
		0xAB84BF839073A802ULL,
		0x10D0BAC1D19F97FBULL,
		0xA1E1E7B2B758DD74ULL,
		0xAF10C96E5DBE4061ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 761\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 761 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -761;
	} else {
		printf("Test Case 761 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEA3FEA0B6D716FB4ULL,
		0x4EDF03F46D165AFBULL,
		0x927B1EE9E4AD277CULL,
		0x9C855B094AC79C7FULL,
		0x3A4AE1CD4FE17915ULL,
		0xB5DED09CB1D7957FULL,
		0xC60B5DF347869E85ULL,
		0x2A502B6847D0847BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 762\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 762 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -762;
	} else {
		printf("Test Case 762 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x208A924B6D9E847CULL,
		0x52F5525FCBAF0827ULL,
		0x3D014C768A19BFDCULL,
		0xEEF46F5A78CA4A98ULL,
		0x909BB4039829C72FULL,
		0xB8132A8AEE861631ULL,
		0x8673705C5294DE84ULL,
		0x8C4BCE9BF219EE07ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 763\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 763 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -763;
	} else {
		printf("Test Case 763 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x867B96EA8E794393ULL,
		0xAA45E4ADB4F0B8BEULL,
		0x9C15C2F11767235FULL,
		0x27205AC50CEC7F3CULL,
		0xDE5016348A27545FULL,
		0x96C1A7D1E3B6A6BCULL,
		0x360C79D1B812C3D5ULL,
		0x976823EFD417862CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 764\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 764 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -764;
	} else {
		printf("Test Case 764 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8EADB74597F3DA81ULL,
		0x281C88407C8D1F66ULL,
		0x6D873D053CF03361ULL,
		0xE6F469148663149AULL,
		0xA1EFDD2C952B0666ULL,
		0x41AFDAD7C82280E1ULL,
		0x91EAC3E6A694E487ULL,
		0x24749671F4966CB8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 765\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 765 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -765;
	} else {
		printf("Test Case 765 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC9EB5543D737826BULL,
		0x4D2C33FE2E30E14AULL,
		0xA66769A5835D719EULL,
		0x4B5D52AEEAE93F84ULL,
		0xACCAB71410F320BBULL,
		0x430018A69C03DB76ULL,
		0x1246A32A20D7593BULL,
		0xCC4CF1E9D5BCF549ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 766\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 766 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -766;
	} else {
		printf("Test Case 766 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9F10F87239508278ULL,
		0x663970D154186F1EULL,
		0x6E6896A9E134E36AULL,
		0x04024F69B77E5D63ULL,
		0x161B1FF3A7FD1636ULL,
		0x11D6847A0E18C803ULL,
		0x86026AF3322DBB65ULL,
		0x53A23801CA44F547ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 767\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 767 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -767;
	} else {
		printf("Test Case 767 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x93A917BABA92818BULL,
		0xFA8013CB58AF04BFULL,
		0x3E89C8BAB9DA2D97ULL,
		0x1A84244F5F43D638ULL,
		0x269EFCF0BEDCCCD7ULL,
		0x030853CBB9988F13ULL,
		0xA9B3DF034F8B3073ULL,
		0xE8F15E64E645444DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 768\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 768 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -768;
	} else {
		printf("Test Case 768 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x38EF3E94934D8EE2ULL,
		0x9864DD9A38CD6656ULL,
		0x4A7415CC813218D1ULL,
		0x84A85E74ED8545E8ULL,
		0x6484D9DD2507CD27ULL,
		0x7FEEF27EE3FC3AB8ULL,
		0x3BBB431FC8459C23ULL,
		0x0FF114B7D7B0912DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0800000000000000ULL
	}};
	printf("Test Case 769\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 769 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -769;
	} else {
		printf("Test Case 769 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x62E0408A8E3F8D3AULL,
		0x3854C09632AACBA6ULL,
		0x7258CB5D89421592ULL,
		0x790CED50E1EFF32CULL,
		0x9999EC777CC3BF1BULL,
		0x48E170EF132DB890ULL,
		0xB2DE19A0B9C36B39ULL,
		0x6BDCE867EC95C9ABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 770\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 770 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -770;
	} else {
		printf("Test Case 770 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDFEC7741288440E2ULL,
		0x41B74E9BE626B0FAULL,
		0xC8815B430246BECDULL,
		0x22298BE17B0FC908ULL,
		0x3EA046A7238D3F53ULL,
		0x2C6732F0D224083FULL,
		0xC2E35D16A0B18E35ULL,
		0x750AA35658F9486FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 771\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 771 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -771;
	} else {
		printf("Test Case 771 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA938C021B9964AF7ULL,
		0x2532BCE7F6CCB2AEULL,
		0xCED8E76CCF1D4EA8ULL,
		0xA660611A18F9BD9EULL,
		0xD4BEA6A760949CE1ULL,
		0x57030EB1F863A7C0ULL,
		0x043BD2C89F8B34C4ULL,
		0xD3FB52D0B08DEAFCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 772\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 772 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -772;
	} else {
		printf("Test Case 772 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x21EFBF934ED5FFC6ULL,
		0x142FEFE324674078ULL,
		0x7951E27DD4D33605ULL,
		0xF48CCB862A31F615ULL,
		0x3508F6F77FE73A1CULL,
		0xECF0CCD73B9D561AULL,
		0x41C9F757B7F9D337ULL,
		0x87CD5A27327AE8CDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 773\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 773 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -773;
	} else {
		printf("Test Case 773 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x870A78EA1F036188ULL,
		0xC91385614EDD4270ULL,
		0xC09D6585DEB5F280ULL,
		0xAB22DF6D32585CEDULL,
		0x7D842802910E4E92ULL,
		0x7DC70122433E10DFULL,
		0xF258AD1F20FC79E0ULL,
		0xE05BCFDE4B87AA73ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 774\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 774 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -774;
	} else {
		printf("Test Case 774 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC4F9B14D53763D47ULL,
		0x3D7113307A259B43ULL,
		0x96243F072DF1965BULL,
		0x98D3E27C9D7C5759ULL,
		0x52BCC66CF912665EULL,
		0x7C3FE197439C3363ULL,
		0x47A512C481F03993ULL,
		0xE725D44A6E689C9BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 775\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 775 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -775;
	} else {
		printf("Test Case 775 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x184D2E52715339D2ULL,
		0x2D43BA633841FFB1ULL,
		0x1E76DE45541AF9E2ULL,
		0x57FA6F51A2360874ULL,
		0x6CC551809CCAA3C8ULL,
		0xD4D1EDD01E49897CULL,
		0xEAF0F4072D53FB28ULL,
		0xA67FE7F58422F8ACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 776\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 776 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -776;
	} else {
		printf("Test Case 776 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB2D210C6B5419AF8ULL,
		0x91C0D43A0BCA7610ULL,
		0x55D965F6DDA33BE4ULL,
		0xD4769A191EF0CB49ULL,
		0x5A1DFFAFB6EC8075ULL,
		0x326A5EE14E4DB3CEULL,
		0xDF4A77B650B8C233ULL,
		0x6E200FE7D5E89D28ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 777\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 777 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -777;
	} else {
		printf("Test Case 777 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1973C3E3F95594E5ULL,
		0x8BE0E12F60BF41F3ULL,
		0xB175487C54E6007AULL,
		0x6A1617D3C4956790ULL,
		0xEE62F31D3CE0EA06ULL,
		0xCBDC34F3E15FA273ULL,
		0xAD73DE90C12EE9C2ULL,
		0x41FDF446C4D91A0BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 778\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 778 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -778;
	} else {
		printf("Test Case 778 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1BF1B95E1BD11BC7ULL,
		0x8804622F396FFA44ULL,
		0x99C3ECC167B70B63ULL,
		0x730B7A3DB6C90120ULL,
		0x5331ED7975FA6513ULL,
		0xCCCC549444F8F2D8ULL,
		0x3521DF85E0C5C368ULL,
		0xA419C5CB3C23E501ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 779\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 779 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -779;
	} else {
		printf("Test Case 779 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x414B6A7FC1090943ULL,
		0x6CFABA9B8293121AULL,
		0x16586759C23253F7ULL,
		0x3012338EA3256328ULL,
		0xFB3E419B774BA68CULL,
		0xCF5A0EABB6C8A4EDULL,
		0x722075559FE66B72ULL,
		0x7BCDCED97593235AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 780\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 780 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -780;
	} else {
		printf("Test Case 780 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD086D8B9F835297FULL,
		0xF6AAD309EF1DA9CFULL,
		0x13E194817130F879ULL,
		0x6DDFC9CD2963D95EULL,
		0x2159983CE4DA8AEDULL,
		0x57CCB8FFB6ECB27CULL,
		0x25118345228FB1F0ULL,
		0x01BD47232E6DDC16ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0100000000000000ULL
	}};
	printf("Test Case 781\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 781 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -781;
	} else {
		printf("Test Case 781 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x16A66EDE31B0AB5FULL,
		0x4EB1FDFE15237EF0ULL,
		0x30A25981106762C6ULL,
		0x8F21094A13A897B6ULL,
		0x075B6D04251FEF19ULL,
		0x358384A48E1A4B1FULL,
		0x272CA8FC421CB016ULL,
		0x8154E1C00D52206DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 782\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 782 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -782;
	} else {
		printf("Test Case 782 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x73733544858750B7ULL,
		0xE9C805567FCC9FA1ULL,
		0x1750B934AEB5E60EULL,
		0x5696B5D62D0829FDULL,
		0xA8FEB2516ABD3F50ULL,
		0xF1C947C992422C47ULL,
		0x098FD23E74249C77ULL,
		0x5A9FCD45C6FB7837ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 783\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 783 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -783;
	} else {
		printf("Test Case 783 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x092C4EB4A650CCAAULL,
		0x0D66509FD70D7922ULL,
		0x0B84C11183D08E73ULL,
		0x1AFE1E8F06978B5CULL,
		0x6EF99CD98154B1BFULL,
		0x8096834934952EBCULL,
		0xD3183879658BE7B0ULL,
		0x866391E1070206C0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 784\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 784 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -784;
	} else {
		printf("Test Case 784 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6846AC94CD16DAC9ULL,
		0x89D6667D6085EAABULL,
		0xF24D05F545D5C7E6ULL,
		0x918E4DC70649ECFFULL,
		0xFA8D9468820640F2ULL,
		0xFC8234C551A3EA11ULL,
		0x3568465E11150B34ULL,
		0x1F0E454C68F27F33ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	printf("Test Case 785\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 785 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -785;
	} else {
		printf("Test Case 785 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x68924BEDAB29A33AULL,
		0xAB09ADF1B379BA39ULL,
		0xD9A5D7FB353D1D46ULL,
		0x2FE36DC3949C3FDFULL,
		0x7AA7A00A81AA6692ULL,
		0x0240246DA767DE5FULL,
		0xE7C38995AB44580BULL,
		0xD76F7D383100DC81ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 786\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 786 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -786;
	} else {
		printf("Test Case 786 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x02C81E5C60F0E810ULL,
		0xEA2DDE9E42E8D2E9ULL,
		0xC9AB5C7BDC518A91ULL,
		0xFCDFDBB9AB7E94DDULL,
		0x75F625C17F8A2E6DULL,
		0xD666E68BC3D673EBULL,
		0x4937B31801213BF3ULL,
		0x7601876EEB1297AAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 787\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 787 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -787;
	} else {
		printf("Test Case 787 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0A5B07AFEDAA6E21ULL,
		0xB27EFA5A5DF522F4ULL,
		0x1BBC52187F125369ULL,
		0x6FE7087B02534EEBULL,
		0xDBF1AAAEA39514B4ULL,
		0x72BBA066BC2B8743ULL,
		0x76B502B3416404B6ULL,
		0xCF59CEC777B6F1E3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 788\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 788 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -788;
	} else {
		printf("Test Case 788 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA23971964719C603ULL,
		0x1BB192A1AB99A1CDULL,
		0x94F144B44CCD1B27ULL,
		0x6B9ED2756C282DD5ULL,
		0x79D93172CA92C444ULL,
		0xF54D11CA84C27033ULL,
		0x169DCA205C9B0F80ULL,
		0xE770D2316930D6A9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 789\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 789 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -789;
	} else {
		printf("Test Case 789 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x09AC08E5EEAF549FULL,
		0x0D739344E07DF9E6ULL,
		0x301CE864554F8A49ULL,
		0x76E7BE73023905EFULL,
		0xF71EF48FD3289520ULL,
		0xAAC3833244300889ULL,
		0xE0017234B673FBD7ULL,
		0x0FF11C6F58AE0C32ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0800000000000000ULL
	}};
	printf("Test Case 790\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 790 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -790;
	} else {
		printf("Test Case 790 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x83E26E2C8C89F59EULL,
		0x11BC13528D612B95ULL,
		0x4419EBE9F7B6290EULL,
		0x517386E4EB20A404ULL,
		0x6303A50E5AD6878AULL,
		0x5E3F59E064A67375ULL,
		0xC072C0AE188D1126ULL,
		0x6780E5E2871A29D7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 791\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 791 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -791;
	} else {
		printf("Test Case 791 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x90A80DB108D8B97CULL,
		0x3A26E44509E3DD73ULL,
		0x1D8795BB0B1CAC9EULL,
		0xB7B82C331E3CC019ULL,
		0x5A94EB0E928CAB06ULL,
		0xA2DD6725CDEFAA85ULL,
		0x0BE7F421E3210AF6ULL,
		0x076F82F8179A42C5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0400000000000000ULL
	}};
	printf("Test Case 792\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 792 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -792;
	} else {
		printf("Test Case 792 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEFB82BCFFC83C83FULL,
		0x5D8A139089929F45ULL,
		0x19816061DEF4A557ULL,
		0xBB73F0FA179EDD7BULL,
		0xC3391D59A83A5C1CULL,
		0xBC3D33549FFC14F3ULL,
		0x6130C5561FD487F3ULL,
		0x5D5B59FB3936D4F7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 793\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 793 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -793;
	} else {
		printf("Test Case 793 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2630D62ED58DE059ULL,
		0xE8701FD91C6669E1ULL,
		0xE36A7023EEA429DEULL,
		0x861435C73C12BE60ULL,
		0x22D82B21C421B1EAULL,
		0xCBE4BC0BD703BA05ULL,
		0xEEF388C78A3920B7ULL,
		0x495C73E1B61563DFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 794\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 794 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -794;
	} else {
		printf("Test Case 794 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x51F6B1EC73527A0DULL,
		0xF9ADC6F0BFCEEB86ULL,
		0xA5340BBE49EE7D8AULL,
		0x839FAF1C10D705FEULL,
		0xF6E2D778A89221A6ULL,
		0xCB9E54EADD589D31ULL,
		0xDC3DC056BEE4A526ULL,
		0x1FFC8DD97006565DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	printf("Test Case 795\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 795 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -795;
	} else {
		printf("Test Case 795 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDDB77B2A906B9ADAULL,
		0xA8D4FB38005B85BDULL,
		0x8B59B7F26ABE0C77ULL,
		0xA32A736A3722EC8DULL,
		0x23AAA9CF295BDAEEULL,
		0x0790355FAD91F056ULL,
		0x4BE316BF6C347FC8ULL,
		0x912A38C6D9171FD1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 796\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 796 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -796;
	} else {
		printf("Test Case 796 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x89E8AC6FEF51A290ULL,
		0xF618EBD04D02260CULL,
		0x5F235486BD23B70EULL,
		0x74C80AA75B00BF5DULL,
		0xF877E838826F0C25ULL,
		0x502F70FACCF78B7DULL,
		0x2886BBF5A4A653CFULL,
		0x4F59762D290CFB6EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 797\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 797 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -797;
	} else {
		printf("Test Case 797 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4722BFF9062125D6ULL,
		0xBB84B81C5ABB417AULL,
		0xEC2441D60E7D1808ULL,
		0x64A13E1C6452B384ULL,
		0x44512CB9C7B30117ULL,
		0xFCA9D66C7D58991CULL,
		0x535FA6EA7483576CULL,
		0x593AE4D84F014930ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 798\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 798 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -798;
	} else {
		printf("Test Case 798 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x303EFC432B78DC49ULL,
		0xFFADF5C3566160ACULL,
		0x050BB035C627947EULL,
		0xFB129BD6AFD40694ULL,
		0xF8EF843DA06DB1BDULL,
		0x3E2344D5A0731113ULL,
		0x41DAB7C0EA4619DCULL,
		0x0AB438AF30B19D3DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0800000000000000ULL
	}};
	printf("Test Case 799\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 799 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -799;
	} else {
		printf("Test Case 799 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB551BA7598A209D1ULL,
		0x2EAC9C79BDBCBF60ULL,
		0x6026FF6195F0C9EAULL,
		0xABEBF97C9D41632CULL,
		0x3A5975E9E107CBE2ULL,
		0x044E173A20842C20ULL,
		0x396993DB6C82E7AFULL,
		0x0CDCF399601FB066ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0800000000000000ULL
	}};
	printf("Test Case 800\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 800 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -800;
	} else {
		printf("Test Case 800 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD9F17EABEDCA971CULL,
		0x18F14CFBEDD8CB74ULL,
		0x94C7C4CC24B56271ULL,
		0xAD9A3AD5C7E2B6B0ULL,
		0x0C77211A0EFEBA88ULL,
		0xC875C869D5E2F7C3ULL,
		0xF9E0A32885759399ULL,
		0x541805F0E27B8672ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 801\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 801 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -801;
	} else {
		printf("Test Case 801 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1F7E06D793C8F0D3ULL,
		0x7C57053A001B0119ULL,
		0x72782BC2E08ED101ULL,
		0x75B01D5AA2EA1885ULL,
		0x8FAE1F5CEFDF5B1BULL,
		0x18F5773C5C88722EULL,
		0x05374004E2687C28ULL,
		0x4D5196FD4E0419CDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 802\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 802 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -802;
	} else {
		printf("Test Case 802 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8F9EE5A8BFB26301ULL,
		0x015B65505B4401DEULL,
		0x1B33476D77A91E41ULL,
		0xB6A47E1F85B728AFULL,
		0x914D69E455E10C20ULL,
		0x4F9A12E7BAC61F53ULL,
		0xBCE61AA771831DCDULL,
		0xCF5A7CC768EC18F8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 803\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 803 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -803;
	} else {
		printf("Test Case 803 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x26F8A1703505E478ULL,
		0x1A57978686986FE1ULL,
		0xA713E775B8E6AE85ULL,
		0x765B5A1A14AE606EULL,
		0xF3A078BDC70E5ACBULL,
		0x4887489351B77FF9ULL,
		0x1ECE73B80666DE1FULL,
		0x1EA6B6F8C1D28F40ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	printf("Test Case 804\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 804 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -804;
	} else {
		printf("Test Case 804 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0AF55C47AF70BE34ULL,
		0x612F1613B64A2F1BULL,
		0xB5CF3FE8EEDB0D35ULL,
		0xCDB96147BE1EA4C6ULL,
		0x88418A2E859F9C1BULL,
		0xD2F399CD81277A0BULL,
		0xDF01340F7C736886ULL,
		0x12065C9222551B07ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	printf("Test Case 805\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 805 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -805;
	} else {
		printf("Test Case 805 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4D97F73168BDE8C6ULL,
		0x8C219C1160DB255BULL,
		0x8EF1E9E96E7DCD14ULL,
		0x79C87F8F26A5FC11ULL,
		0xC4B40770DB1D1467ULL,
		0xC354C84EABAA4AF0ULL,
		0x13888B772453ADC6ULL,
		0xD093384DA739BD21ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 806\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 806 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -806;
	} else {
		printf("Test Case 806 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x96EF1B9BE03F037FULL,
		0xF6514672187DEB49ULL,
		0xDDBB12BB81C897DFULL,
		0x9A35489EFC2EC647ULL,
		0x57F035D3C7B48DCEULL,
		0xF7539E4EB1686EF1ULL,
		0xE3661572D8964D8CULL,
		0x36DBA1A1F1C6534FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 807\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 807 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -807;
	} else {
		printf("Test Case 807 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5BC49470C931AB88ULL,
		0x332C15B66B336960ULL,
		0x5B0112753C16A74FULL,
		0x67DEF03322E4921AULL,
		0x52B5952AA7B2E922ULL,
		0x7C6D44608770021CULL,
		0xA8DBE7D36E2417EFULL,
		0x6D3E1625B3445946ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 808\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 808 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -808;
	} else {
		printf("Test Case 808 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x98F94AE21CDD94D5ULL,
		0x110309F88524277EULL,
		0x5D419607AB156138ULL,
		0xA877BD3900D030AFULL,
		0x5A3FFDA9F8DEDD8CULL,
		0x99FBFF188F0DDDDAULL,
		0x9BC48118D058A19DULL,
		0x584B7C65657C221AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 809\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 809 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -809;
	} else {
		printf("Test Case 809 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6FE369DD21A7F3EDULL,
		0xC0E7C4D7F5C825AFULL,
		0xD50C0BCDCAB5B29BULL,
		0xFCDB0B7FAA2797B8ULL,
		0xC447E38FE44AE971ULL,
		0x08A0F09550B38B38ULL,
		0xB47CB80CC6AF9A90ULL,
		0x818C8726482DA9F3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 810\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 810 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -810;
	} else {
		printf("Test Case 810 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA9D9F4658F1C6B77ULL,
		0x3F9451D6FA733005ULL,
		0x94FB70EBB1C8FC8AULL,
		0x2AEF34D68ED5246BULL,
		0x3130C8747B7BA11DULL,
		0x6B6BF67774D7FB58ULL,
		0x9CE469D66C3C8000ULL,
		0x3D3D6A19CA9C3988ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 811\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 811 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -811;
	} else {
		printf("Test Case 811 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2B2AF25E1AE11498ULL,
		0x9CD4EEB384CC89BCULL,
		0xFD2247D94937BF61ULL,
		0xECB83E42CEDBD759ULL,
		0x8A3CEC68A120B744ULL,
		0x8C55FCCA5D1EC60FULL,
		0xE081F883089CA558ULL,
		0xEE92D2CC33F7F818ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 812\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 812 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -812;
	} else {
		printf("Test Case 812 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAB815C7A9CD724D5ULL,
		0x089C8A2F6F9D8EEAULL,
		0xC209514B4D8FF437ULL,
		0xB0897DB4C6A5C813ULL,
		0x8FCF0A9A60061F4EULL,
		0xF8F11FFC63B0D35EULL,
		0x9D6EE69DDE54505EULL,
		0x169483EC3B8ECE5AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	printf("Test Case 813\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 813 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -813;
	} else {
		printf("Test Case 813 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8F6CD5E63DD2543BULL,
		0x45BE4C8C080FAF37ULL,
		0x84CC5DF6ED3080AAULL,
		0x8738309CD5E285C7ULL,
		0x3921EFBF8028BEC3ULL,
		0x0D9CA5F39E7A2F54ULL,
		0x21880FA3C50577A1ULL,
		0xF8DA31FAE1114D25ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 814\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 814 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -814;
	} else {
		printf("Test Case 814 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBEB0E2149DCACBDAULL,
		0x0644E28DA4816DD7ULL,
		0xAC67D72715D38006ULL,
		0x25041CE0ADF7552DULL,
		0xFE0A9374F6937541ULL,
		0xE575B01DE4662891ULL,
		0xF678FAF72D5942CCULL,
		0x72CD1DA352B0116DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 815\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 815 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -815;
	} else {
		printf("Test Case 815 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7176A04077478238ULL,
		0x69A2690FA117855FULL,
		0x967C5FBA29B29324ULL,
		0xA6343281AACF261EULL,
		0x91F9F12F58D348B5ULL,
		0x2A31F16761410D9BULL,
		0x67123C61D20DE44FULL,
		0x284362B3582B81B5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 816\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 816 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -816;
	} else {
		printf("Test Case 816 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x11F4D7DF02CC3BACULL,
		0xAA191C0AC86B56D1ULL,
		0x7A33AF99182C5A14ULL,
		0xBE3BC673E000DB64ULL,
		0xA7B3E43CFD911BC7ULL,
		0x2E7BEB0BFEDCBB4AULL,
		0xDC2A2B7F347DCB4EULL,
		0xF5AA0BD7A148F70FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 817\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 817 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -817;
	} else {
		printf("Test Case 817 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFABEE3A326DB5E30ULL,
		0x2EB09F1B5D0971C4ULL,
		0x6E1D3240BF8F6E35ULL,
		0x3A075E02602727A5ULL,
		0xC6935C925F03BDA2ULL,
		0x28D53D9897DBCD20ULL,
		0x93049A116629A5F9ULL,
		0x0FF820B8A607415CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0800000000000000ULL
	}};
	printf("Test Case 818\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 818 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -818;
	} else {
		printf("Test Case 818 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA1F1F6DECE770689ULL,
		0x413A1D92BECD5239ULL,
		0xB77D07AFA83F811BULL,
		0x2399B64A43DC61EAULL,
		0x279266830458AC6EULL,
		0x1F969C1C201CEC99ULL,
		0xCBB62F792DF917A7ULL,
		0xAB258A6A93FABC53ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 819\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 819 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -819;
	} else {
		printf("Test Case 819 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD5FBEFE8B8C47FB2ULL,
		0xF697455F5E16E54EULL,
		0xEC047B269B5336FCULL,
		0x05430FBF2A027044ULL,
		0x9198CFFD7BA2D141ULL,
		0xA8A4A0E0AD0D5D38ULL,
		0xF21A23539306F7DCULL,
		0x6E60555AFD933559ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 820\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 820 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -820;
	} else {
		printf("Test Case 820 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x070E44F0A81CEDE9ULL,
		0xC466798F5A222C01ULL,
		0x7A8CEF5BAF067775ULL,
		0x47B240EE6CB3D50BULL,
		0x49020E49B16F5E2EULL,
		0x7FB6F7C6F967E5A8ULL,
		0x0E553CE2958CED5EULL,
		0x052F62C0FA7B6DC7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0400000000000000ULL
	}};
	printf("Test Case 821\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 821 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -821;
	} else {
		printf("Test Case 821 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE9D3D4AA0EF60B93ULL,
		0x46AEF337793CE4CAULL,
		0xA2DA4785AFE91A42ULL,
		0xBB2D49BEA30C880EULL,
		0xE022B30054954427ULL,
		0x35CDD082674C010AULL,
		0xD2B7F3E9B648A432ULL,
		0x6AEEFC8B7FE0D1F2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 822\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 822 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -822;
	} else {
		printf("Test Case 822 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2E6F15755DAD3478ULL,
		0x947EE07E14645010ULL,
		0x2176021FCEA897C7ULL,
		0xC3E74B7148FA1F9EULL,
		0x24BEEC3892441FB5ULL,
		0x89D50A278E95BC37ULL,
		0x6C0CA69A1F4B3222ULL,
		0x9B50A6998D761E47ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 823\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 823 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -823;
	} else {
		printf("Test Case 823 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA5E91EB3DEF11F1EULL,
		0x6C8EDA67A6AFB491ULL,
		0xA8586874608EAF35ULL,
		0x20ED51BDE48B901EULL,
		0x90505A59C19F1E05ULL,
		0x04DE2AAC03AEBD59ULL,
		0x890BEE113DE0B964ULL,
		0x282519CA85D6F34FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 824\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 824 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -824;
	} else {
		printf("Test Case 824 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2147B4536B85F756ULL,
		0x2B053F7C48E3CF6DULL,
		0xA90315A514D89A25ULL,
		0x402E0AC6E5A9F884ULL,
		0xA2A7B5348FFD74F2ULL,
		0xBEB59D83547DF105ULL,
		0x264797DC966800D0ULL,
		0x2BE235A858264615ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 825\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 825 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -825;
	} else {
		printf("Test Case 825 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x67844727A96C870AULL,
		0x1FC28A526F917CB1ULL,
		0x4D91E46A16716E40ULL,
		0xCB13C6EF7872045DULL,
		0xF372697576F1813AULL,
		0x6149830A58E8EB16ULL,
		0xB0EB270C7785A3A5ULL,
		0xB91E0614EF0E10EBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 826\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 826 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -826;
	} else {
		printf("Test Case 826 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x09B2F94456303BF3ULL,
		0x5F72EE6310AB4229ULL,
		0xDCE4ED826F225AE9ULL,
		0x18534B285C9F766EULL,
		0x5A0A0B5CF69786C5ULL,
		0xB242ED211D46B8A3ULL,
		0xFF0756BDAF4D1DFCULL,
		0x51C1C9190AE46CF8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 827\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 827 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -827;
	} else {
		printf("Test Case 827 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCA305F6080F3DC3FULL,
		0x8FBBF9AB2AE2A2DEULL,
		0x2D76A8C6FC3C19F6ULL,
		0xB66E004470B70107ULL,
		0x7543E5AE87238B8FULL,
		0xB996157F70B89F70ULL,
		0x1F6EA56A6EAB8917ULL,
		0x765274A7083F882DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 828\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 828 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -828;
	} else {
		printf("Test Case 828 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x15A419FDF62D1E8DULL,
		0x80834785D55823DFULL,
		0x3312678ACD416150ULL,
		0x338074AE1DEF4502ULL,
		0x825BC60D56C50862ULL,
		0x62428B90E7284D63ULL,
		0x4BA72A2DE58AE8C7ULL,
		0xD4876FAC87E363B1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 829\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 829 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -829;
	} else {
		printf("Test Case 829 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD82BA6ED16B105E6ULL,
		0x917CA907A4999BA1ULL,
		0x4A9CC1DB2BB6870EULL,
		0xB22C909C868FB798ULL,
		0x719CE5ADD526E00BULL,
		0xCF1B52CC90E0A1C3ULL,
		0x67522C576B049B49ULL,
		0xA60BF46BBC1C7F24ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 830\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 830 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -830;
	} else {
		printf("Test Case 830 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x84A7EC9AE9BF9A8EULL,
		0x427448EEB0D300F1ULL,
		0x98A791E03974F55BULL,
		0x1BFE813B8CE84018ULL,
		0x51BF933DC0BC6266ULL,
		0xC34C80EF61A4E794ULL,
		0xBB4E343636C40F0DULL,
		0x094E8F041C344EC9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0800000000000000ULL
	}};
	printf("Test Case 831\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 831 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -831;
	} else {
		printf("Test Case 831 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8C33CA81D779DCB2ULL,
		0x85F1070F7F04C2CCULL,
		0x95410A98D4E9AE3FULL,
		0xB546530E32F27E98ULL,
		0xA94798320C712C99ULL,
		0xBF1F116FEF4FD1BDULL,
		0x4C86BA2ABCE2BD4AULL,
		0xF89B244892CBBD09ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 832\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 832 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -832;
	} else {
		printf("Test Case 832 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0705B729E55E80D6ULL,
		0x0CEFD79DE57E8CF2ULL,
		0xC0654C21CEF2D522ULL,
		0x6EE09D144D780423ULL,
		0xEF49092470EBB708ULL,
		0x78C7CB5CF0A22C34ULL,
		0x9ADFA4CD231FC2DDULL,
		0x7D73F1E0C05DF6B5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 833\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 833 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -833;
	} else {
		printf("Test Case 833 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x83B8E739725EC2C2ULL,
		0xEA8D0098263284EBULL,
		0x0402F6A7920DF3ACULL,
		0x7EE86AD3F2010A0EULL,
		0x2B4AC9AC7868CE14ULL,
		0x279786C3C09AF9C6ULL,
		0x300E9F1FF33D8DF1ULL,
		0x6036F139F339FA94ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 834\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 834 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -834;
	} else {
		printf("Test Case 834 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x22E15DD9000A8834ULL,
		0xF9601393D82B710EULL,
		0x0B85ECC30A14116DULL,
		0x6A278261B65920D0ULL,
		0xB79297937977033EULL,
		0xC64C60C45F1E5058ULL,
		0xAB5B00ED702AB3E0ULL,
		0xD90763DEA398EF8BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 835\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 835 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -835;
	} else {
		printf("Test Case 835 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7B7B0621E501B134ULL,
		0xE5133980E4562435ULL,
		0xD42C0B497F93011DULL,
		0x1FB658C3A0785141ULL,
		0x17DD691A5F48BAB3ULL,
		0x422D457A908EED6EULL,
		0x3374D09B3B6B7D71ULL,
		0x7615138A9B8AC067ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 836\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 836 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -836;
	} else {
		printf("Test Case 836 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8287E5087890A238ULL,
		0x3CFCE427E9298A44ULL,
		0x174CF4DB2795EAEDULL,
		0xFE951F75CE2B2871ULL,
		0x13A18FA46F75C609ULL,
		0x4A0948C9F45736F7ULL,
		0x26330766D5A42420ULL,
		0x623D96BD151AA496ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 837\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 837 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -837;
	} else {
		printf("Test Case 837 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB6CC327A20A2DC97ULL,
		0x882F85928F239BD8ULL,
		0x79C838F13D0648BAULL,
		0x287CCD13FFE3E8B5ULL,
		0x34F68C0F8CC4BDD0ULL,
		0x44255F8DC57BB836ULL,
		0x815DE4641E60478EULL,
		0xBB88060B3559EE05ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 838\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 838 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -838;
	} else {
		printf("Test Case 838 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE1E656CD239B6765ULL,
		0xC4A55A1CBAB0D74FULL,
		0xF5C18A5263E48F4FULL,
		0xCD8B1D60CE318E72ULL,
		0xC66C177C6EF7316EULL,
		0xCDF0CEBF54992CBFULL,
		0xA0C820585F1104D9ULL,
		0x706E76E6229AEB5FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 839\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 839 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -839;
	} else {
		printf("Test Case 839 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9825DBDDD1C81B94ULL,
		0xF6BEA519FAE1B54BULL,
		0x0B57A36DA3E50EC8ULL,
		0x176E8A15B9E3E7C3ULL,
		0x39C0ACE512734351ULL,
		0xB35A583229161E54ULL,
		0xD5D1FB6732AC43AAULL,
		0x3C49F30669A76183ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 840\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 840 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -840;
	} else {
		printf("Test Case 840 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7449063C7343822BULL,
		0x241ACE21687943D3ULL,
		0x980B55DE7D147F8AULL,
		0x886CEA4CA5E7DD5DULL,
		0x4DCA01BD7D430339ULL,
		0x91C791C83F219A34ULL,
		0x89D85CEB1E861FD2ULL,
		0x40B0CC7C8D7DBD33ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 841\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 841 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -841;
	} else {
		printf("Test Case 841 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD517314318B6E8FFULL,
		0x4A4F2785012AFB69ULL,
		0x94C37937E119BD3AULL,
		0xEAC2C4E549135913ULL,
		0x482C6F5053A75C69ULL,
		0xC84351C14DA48B3FULL,
		0xF1397BF8C7C5B640ULL,
		0x0907082085228CD3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0800000000000000ULL
	}};
	printf("Test Case 842\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 842 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -842;
	} else {
		printf("Test Case 842 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD030A8CDF4D62F2AULL,
		0xEAC374E84E85D6DBULL,
		0xD619B5A47D2C3D8EULL,
		0x2BCBF83FC80F9760ULL,
		0x1F9B95556A58B3FBULL,
		0xD9A2F0B19125DDDEULL,
		0x386E682845F4ED23ULL,
		0x9B2AC59BF23A562FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 843\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 843 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -843;
	} else {
		printf("Test Case 843 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x65F98F7AEF2C45BBULL,
		0x17A34B6A1709192AULL,
		0xD124B32EFAB7F68EULL,
		0x3649D6865A3FCFCAULL,
		0xE259C645D2D33E57ULL,
		0xD2F33EB3D07CF7B9ULL,
		0x24B6619F677D3032ULL,
		0x5D4A77EED2D65D76ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 844\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 844 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -844;
	} else {
		printf("Test Case 844 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x807542819224F620ULL,
		0x344E933E0825642CULL,
		0x37126294366FC50BULL,
		0x37559ACA7332FC48ULL,
		0xC0E16797407F5CF1ULL,
		0x904990B2E702C689ULL,
		0xE971161613E35469ULL,
		0x58CA007FA19F262FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 845\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 845 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -845;
	} else {
		printf("Test Case 845 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7075F6F26EB39659ULL,
		0x06032F33B99AB20BULL,
		0xCE3F166D564B3BB5ULL,
		0xBF41C20492A59113ULL,
		0xC5A9BF92A1E03E67ULL,
		0x3317839DA533E25EULL,
		0x3A739EED771EF1B1ULL,
		0x27612648431A08ECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 846\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 846 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -846;
	} else {
		printf("Test Case 846 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB064B03D1EF33AFEULL,
		0x8020086588124994ULL,
		0x304EFC2FBEA0165AULL,
		0xEE7559AD331C08CAULL,
		0xEAF04C21987EDB24ULL,
		0x33256D01870FA35BULL,
		0xAAE290E642BF9DEBULL,
		0x42216BE3D9056850ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 847\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 847 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -847;
	} else {
		printf("Test Case 847 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7D0522713C13DB59ULL,
		0xB474DEBF054C0533ULL,
		0x95A961C9176D7767ULL,
		0xAE2914F1F1885182ULL,
		0xAEA9C6686F798523ULL,
		0x4F931CA619EEC621ULL,
		0xFCA84F61BE37320EULL,
		0x8D6D0EA7F6E2EF2CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 848\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 848 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -848;
	} else {
		printf("Test Case 848 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x03FADF8A8B762193ULL,
		0x643D5CA2D0841EE2ULL,
		0x278EFC3F55147EE3ULL,
		0xF2D97FAFD695B20AULL,
		0xC53863CB7D6B3DB7ULL,
		0x35DEA949E16AD4ACULL,
		0x4A1EF4E41AD0928AULL,
		0xF1829BD21B24A035ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 849\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 849 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -849;
	} else {
		printf("Test Case 849 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5C0753608246142AULL,
		0xE0E1E430D08B6264ULL,
		0x0949E91D75242F55ULL,
		0xA3E4B921596865A1ULL,
		0x18B2B5055D88473CULL,
		0xC825B32F7698BD9EULL,
		0xD093913E02D452EFULL,
		0x588431D36DEEA9A1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 850\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 850 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -850;
	} else {
		printf("Test Case 850 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x56AFA6A9A966AF55ULL,
		0x4D37E58E36ABD3AFULL,
		0x210286B0CF371B25ULL,
		0xEBB1022B27A1B946ULL,
		0x1C1C2458649E43D5ULL,
		0xB3D10A1681E8BA85ULL,
		0x46A22C3165B17AB1ULL,
		0x347FE5A6B56D8EEDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 851\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 851 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -851;
	} else {
		printf("Test Case 851 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x387AD1418408656CULL,
		0xF3D04EE1DFCE288CULL,
		0x433F388230F8F353ULL,
		0x1B43E60588919DBFULL,
		0x6B7DC4CBB12A3374ULL,
		0x6D0133CD743C3AE3ULL,
		0xDE28D2FE01809031ULL,
		0x90D5ED0DBDC0C7D9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 852\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 852 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -852;
	} else {
		printf("Test Case 852 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x256EA4DB0AC690DCULL,
		0xA05863E60D3A88DFULL,
		0x611B6173F3BB7D78ULL,
		0x05651C826D7D2C43ULL,
		0x7161400A09041858ULL,
		0x39CA6A9828C78730ULL,
		0x6A8634816C886E65ULL,
		0xB7E1B5F8E1B16600ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 853\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 853 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -853;
	} else {
		printf("Test Case 853 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3CAF5369DB963453ULL,
		0x5D5A73C0E3EEB3C1ULL,
		0xA88C0AF805E10F33ULL,
		0xED80752A111CDE61ULL,
		0x6D68BA252785C3A2ULL,
		0xCE26614059FE0D11ULL,
		0x386E48AA2FDCB296ULL,
		0xA085F09481A7454CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 854\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 854 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -854;
	} else {
		printf("Test Case 854 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA85D16B98E4A4386ULL,
		0x33AF5BFDC2C6599FULL,
		0x7CB5C9F68BE3F8CDULL,
		0x42CFDF7CEE9C654FULL,
		0xC4B8CA663AD3E380ULL,
		0xE6DB29F087B999C5ULL,
		0xA2F93B5D00EA4967ULL,
		0xDA2883FF5A1C1FAFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 855\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 855 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -855;
	} else {
		printf("Test Case 855 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x002FE98BB46252D4ULL,
		0x03EFE5E6361ABED9ULL,
		0xC713E255BE24430CULL,
		0x05B11E8109524BB5ULL,
		0x06EFC09B2894C4CAULL,
		0xC4B5AEC5DFFDE9E9ULL,
		0xCDB8649FEFA675C8ULL,
		0xE04175E26B336F03ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 856\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 856 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -856;
	} else {
		printf("Test Case 856 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5B50FCC5074ABCABULL,
		0xBC633D258C126EFEULL,
		0x832D13672FCA8759ULL,
		0xEBD000C9B430CBD5ULL,
		0xE8B28BED7618B3F6ULL,
		0x5C325C98ED1FCE55ULL,
		0xFB06B3314607E85AULL,
		0xA1DDDEEA16885611ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 857\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 857 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -857;
	} else {
		printf("Test Case 857 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6AA17B050343747BULL,
		0x2D0B30F10708917DULL,
		0x1CEA461CEC41242CULL,
		0x4EB5D132D8748EC9ULL,
		0xB8E375FBF526F45DULL,
		0x4A01824FB89331C5ULL,
		0x5F029170F735A8D4ULL,
		0xF6F8A91B1C21D596ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 858\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 858 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -858;
	} else {
		printf("Test Case 858 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFF053FA7E7134CF4ULL,
		0x70929BD025E7E938ULL,
		0x9A874CE6DFA189EEULL,
		0x13BB36A3B80C2E99ULL,
		0x0B67B0E9A917A151ULL,
		0x03C69598C4922656ULL,
		0x9D5C704078D4C679ULL,
		0x953BBAE144846729ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 859\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 859 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -859;
	} else {
		printf("Test Case 859 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x68B3DC29E7AD8EB1ULL,
		0x3B9F80489281E66FULL,
		0x582044B617A83EB0ULL,
		0x0B71A881170A4370ULL,
		0x54881120E82C31ADULL,
		0x38095143DB7887DFULL,
		0xB7823B1E8A4B9B58ULL,
		0xE7A6D808DB784883ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 860\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 860 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -860;
	} else {
		printf("Test Case 860 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0D00B22122C28F67ULL,
		0xA43BE090322CA21CULL,
		0xCB9D1851B0503E20ULL,
		0xA7BAF81DD42C06D5ULL,
		0xCB9C2EC61E6A276BULL,
		0xDCD733974C8DC3ABULL,
		0xFC85DA3CFA1AFAB9ULL,
		0xFFAA92AE7779D647ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 861\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 861 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -861;
	} else {
		printf("Test Case 861 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7137089848B9CBCEULL,
		0x60E9725865BE78F4ULL,
		0xBA14917CF17414CCULL,
		0x62443EBF50BAEF01ULL,
		0x829CE60E8484A780ULL,
		0xC460491DB88D91F1ULL,
		0x229392F3993E0448ULL,
		0xE4AA4D311B0A78E6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 862\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 862 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -862;
	} else {
		printf("Test Case 862 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFACCBB73F1E352DEULL,
		0x14D41870C4932D7AULL,
		0x72F97AAAA1191BCAULL,
		0xCB8E03BD7ABF4308ULL,
		0x2F94BE13933A0A3DULL,
		0x802989A059580442ULL,
		0x9BE27ADADC53B778ULL,
		0x39D2F4185AAC6BB4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 863\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 863 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -863;
	} else {
		printf("Test Case 863 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6865F246405728F7ULL,
		0x85CBEBC95A2D66A7ULL,
		0xF189261A07B25676ULL,
		0xD2DBCC6C23CA1D95ULL,
		0x41B54052D3028148ULL,
		0x9F6BE0E8B4DF6C78ULL,
		0x4A1E9FB1EABDA2A9ULL,
		0x1CC3A2CB6852D09AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	printf("Test Case 864\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 864 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -864;
	} else {
		printf("Test Case 864 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x12B4A5D46D3AA0B7ULL,
		0x2AEE9A100E20DF62ULL,
		0x6F972DC94F161AC0ULL,
		0xC98B20004BC1E3AFULL,
		0x65EE9E4357942CC8ULL,
		0x27E84863E1339927ULL,
		0x217A1A7C77A6F6ADULL,
		0x8EFE6A9D2B880CE9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 865\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 865 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -865;
	} else {
		printf("Test Case 865 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x516FE165045EDC53ULL,
		0x3F86D616E519E0E0ULL,
		0xFD9E35B5015EBE95ULL,
		0xD5869AF51F669E52ULL,
		0x5A735F3754CD4611ULL,
		0x7CDDB2DE8C693A1EULL,
		0xCFD3C6311FF6E51EULL,
		0xB08CB7FA135C6FE7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 866\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 866 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -866;
	} else {
		printf("Test Case 866 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3F5AAACC1913ACC6ULL,
		0xA2F4B5EC4EAB06F0ULL,
		0xEA3CA24263867525ULL,
		0x75D9B8039E882F7DULL,
		0xFC441C22F3E2517BULL,
		0xEBD4E4F24EF78222ULL,
		0x56AD80728BC5F6F2ULL,
		0x78DFBB7391BACD94ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 867\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 867 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -867;
	} else {
		printf("Test Case 867 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB0A2AC0970631972ULL,
		0x05B97F91191964D4ULL,
		0x239D1EA16B6AF7F6ULL,
		0x42EDC4D9A856B66DULL,
		0x2DB0E35ECAE230A7ULL,
		0x33D1E725109696A6ULL,
		0x17878FEB9A002A9DULL,
		0xADC402B519412DD6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 868\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 868 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -868;
	} else {
		printf("Test Case 868 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4BA2AF4E0EB294AEULL,
		0xDBC49D9D111DCE5EULL,
		0xFBE26542B1262459ULL,
		0x9E88C7B6A0C604ECULL,
		0xF53FA8D32531D3F2ULL,
		0x45DE09CE5A92296EULL,
		0x746870A9E7664DD9ULL,
		0xA5B5A800A5DB5ACDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 869\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 869 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -869;
	} else {
		printf("Test Case 869 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC7D6BFFF3EE3630BULL,
		0x06AB42658BC35235ULL,
		0xE2A127AF3AFC6C9BULL,
		0x78EDBE932581DE9FULL,
		0xE400871686286532ULL,
		0x73CBFE4386ADBE11ULL,
		0x39C4858591E3F16AULL,
		0xE429DA9DC6724856ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 870\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 870 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -870;
	} else {
		printf("Test Case 870 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE79243ED5DAD2055ULL,
		0x229ACC5436E5EFB2ULL,
		0xE36D907A4F5DCB6BULL,
		0x00D95A1F9998EBFDULL,
		0x02640AF70276D2C0ULL,
		0x481A3C862FED8692ULL,
		0xC0BC4520270B8C46ULL,
		0x9C22C253902B2E60ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 871\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 871 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -871;
	} else {
		printf("Test Case 871 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x30219964120BBF4FULL,
		0x7BFF3C9B74632856ULL,
		0x18A9E06B858DF2D2ULL,
		0x2FD28DD1D96267BDULL,
		0xA1A09DB22F33EE11ULL,
		0x0FC0FE20DE7766F4ULL,
		0x49F5C64D15FF5648ULL,
		0x7A2A04B016A09A70ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 872\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 872 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -872;
	} else {
		printf("Test Case 872 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x20CBE5DFB2839C3BULL,
		0xA2EB0A940AE827C2ULL,
		0x7D01908F55D52700ULL,
		0x987B24D668EEDF3BULL,
		0x35C3111A9A48A5A3ULL,
		0xB8EC30309C0C4E14ULL,
		0xE072D8C335CDB3CDULL,
		0x81A164F6F1F545C7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 873\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 873 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -873;
	} else {
		printf("Test Case 873 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDA00A20AE424BCEEULL,
		0xA4083AE54DE9CAF0ULL,
		0x32EE19578D9CCFBAULL,
		0xAD5E333517167F1EULL,
		0x5C7837A384161340ULL,
		0xE4E31DEB0312F7F2ULL,
		0xCD0A4DFCE56451CFULL,
		0xCF738665F0778C53ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 874\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 874 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -874;
	} else {
		printf("Test Case 874 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDDD10FB946D896F7ULL,
		0x7932DFEE7701980AULL,
		0x7EC82D0359CB7DFBULL,
		0x5051FD9960A462E9ULL,
		0xA7C80FCA554890D2ULL,
		0xC6B83503AB980DADULL,
		0x4FD9B17C58557597ULL,
		0x70EA5642668EBBC6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 875\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 875 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -875;
	} else {
		printf("Test Case 875 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCE8C21BD5B56595CULL,
		0xE34B50B6CCE2AFF0ULL,
		0x84D244DB6C3EE217ULL,
		0xC4565727720807C1ULL,
		0x7AF4CDAA6178E648ULL,
		0x7AD135B89F029C0BULL,
		0xB80360734B7F6B83ULL,
		0x0EBA46364D8F75B6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0800000000000000ULL
	}};
	printf("Test Case 876\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 876 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -876;
	} else {
		printf("Test Case 876 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xABA2598D10D7C1C6ULL,
		0xC79C207C9831C59BULL,
		0x90C3A288F6DF7EBFULL,
		0x2B796E62DC4CDD99ULL,
		0xE0A8F93927F9B6BAULL,
		0x20C8D603ADB79C71ULL,
		0x63988F9BA85E5138ULL,
		0xD8F39418B3585C01ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 877\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 877 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -877;
	} else {
		printf("Test Case 877 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5C399B69CD21A079ULL,
		0xD2F82A07A3870A57ULL,
		0x8F62F08B1472AB1BULL,
		0x3227DABA56539DE7ULL,
		0xCD3F2BEDE941FFD2ULL,
		0x630894CD0371D627ULL,
		0xC6065D72499B5EECULL,
		0x5DBD3453B4EBC236ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 878\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 878 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -878;
	} else {
		printf("Test Case 878 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF8646DAE220B0E5EULL,
		0x65DC1DD6F34BF8F2ULL,
		0xA20F5C747F8B0247ULL,
		0xC1091EA8F41D4E82ULL,
		0xE441334E03E5B796ULL,
		0x78C860DFC68F20B3ULL,
		0x300A681C36FF9C07ULL,
		0x80C118C972F3A62FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 879\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 879 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -879;
	} else {
		printf("Test Case 879 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA38FD34EE915EC70ULL,
		0xFEA5C34AD28DA29BULL,
		0x84C4DECCC458DD8FULL,
		0x99F2FB8309485F07ULL,
		0x057CFA636805DD3DULL,
		0x5150778F0976EE1CULL,
		0xD1FCFB4D00A8738FULL,
		0x1163A5527F2C1D43ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	printf("Test Case 880\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 880 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -880;
	} else {
		printf("Test Case 880 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEC23456920917E62ULL,
		0x02B2359050F185A7ULL,
		0x15EDC04A086FFD8BULL,
		0x0EFFEA3B2CA5095BULL,
		0xCEAAB797396CDCFBULL,
		0x4B9325B65DD382E0ULL,
		0xC83F64D458222E29ULL,
		0xA17BD09265CD7A04ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 881\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 881 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -881;
	} else {
		printf("Test Case 881 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8A8C75641F28197AULL,
		0xD9D4333DC32026A0ULL,
		0xA27935341BC64E41ULL,
		0xD4EA20A97F525C44ULL,
		0xB60CDDB93C9CDCF8ULL,
		0xE96753E965A8BA24ULL,
		0xDEAE4D713E4BF879ULL,
		0x4317EAA9B477166DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 882\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 882 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -882;
	} else {
		printf("Test Case 882 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4CF78ECFCFC5A6B0ULL,
		0x6103439367F7B7F8ULL,
		0xC0A967D1F6DE6F2BULL,
		0x93A5B148E3D73B13ULL,
		0x7DB93BE09D989775ULL,
		0x33A41BE1D9B5A7F7ULL,
		0x070B5A292B8A87A7ULL,
		0x2E6C1E8F70DE19D0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 883\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 883 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -883;
	} else {
		printf("Test Case 883 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x045F3DB7AE7FD262ULL,
		0xCFCD4A4196B617DFULL,
		0x8444D5DF955E1DBCULL,
		0x3DBF27F5A97CC7DFULL,
		0xA4AAF1310D3F2B16ULL,
		0x25F23485BED17D4CULL,
		0x6377C50A40F2288FULL,
		0x65AA828B863FF958ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 884\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 884 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -884;
	} else {
		printf("Test Case 884 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x10040ABD96A542EAULL,
		0x91CC78D7C0599D51ULL,
		0xFB74BFC2CFEA76CBULL,
		0x4EF8E5CD30A29E79ULL,
		0x826899411FAF5436ULL,
		0xD59959C9486B0ED6ULL,
		0xF635613805E1FF6EULL,
		0x9FB06C49CA0B3A83ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 885\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 885 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -885;
	} else {
		printf("Test Case 885 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3B845543CCAD0136ULL,
		0xBE2DF43F5E21DFA5ULL,
		0x116BC71B9E2412B2ULL,
		0x1EC313157B4654E4ULL,
		0x34E66CD94E731E9AULL,
		0x9E5080A26CF788B5ULL,
		0x22F3D29D6036E578ULL,
		0x28CC5323DA9A0E03ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 886\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 886 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -886;
	} else {
		printf("Test Case 886 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x73994C4723E6DB18ULL,
		0xE5181D8319500D3FULL,
		0xD30E5F4BEA677DE5ULL,
		0xEA66DAD2D5A9F439ULL,
		0x127A607A091F0BE9ULL,
		0x8D2EBB32A8E72A99ULL,
		0x73F039A1A448E8D4ULL,
		0x7228275A27F22940ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 887\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 887 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -887;
	} else {
		printf("Test Case 887 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x374AA4808830F069ULL,
		0x64CDC087D78E9AEBULL,
		0xD4EA66A755DD5B5AULL,
		0x4817A3A77868C831ULL,
		0x4EFBF7D7D44B08FCULL,
		0xA08C88B0D3C3A644ULL,
		0x600254015600AB85ULL,
		0x943C8E4D5A61D85BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 888\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 888 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -888;
	} else {
		printf("Test Case 888 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x04EB0BD7421E2100ULL,
		0xF04FA75C793945F3ULL,
		0x905E11A981814983ULL,
		0xEC5A6D30C0D4CD7BULL,
		0xD4C413ED21BEDE43ULL,
		0x62E175DC972A4554ULL,
		0x5FB35D4AA46D992EULL,
		0x46D8A4FBE11186D9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 889\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 889 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -889;
	} else {
		printf("Test Case 889 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6870763B096E39D0ULL,
		0x2B77E92015A9A4B3ULL,
		0x3CFCB769C7935882ULL,
		0xD297DC443F673F57ULL,
		0xFEBB7452D416E1CCULL,
		0xB09D369F9BC6EB32ULL,
		0x2AE90D2A1B945A37ULL,
		0x542A57E1FB78EDCEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 890\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 890 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -890;
	} else {
		printf("Test Case 890 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE128F9A9F446BC44ULL,
		0xD01722497B574707ULL,
		0x9EA88A7949A6C46AULL,
		0xB012F85AA23F0977ULL,
		0x2CFC5E0A23426462ULL,
		0x919A32033F4D2B20ULL,
		0xAD4DE05B3D89E1CBULL,
		0x358406384D9465C8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 891\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 891 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -891;
	} else {
		printf("Test Case 891 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFEDC9BA1E12A4CBEULL,
		0xEE86B8924D663DCCULL,
		0x11A32D19553348F1ULL,
		0x11E68332392CCADFULL,
		0xCC15C8FF7E84765BULL,
		0x15D35EDC3B2AD20CULL,
		0x952590CDCC69E1E1ULL,
		0x4F32A6D4EBDA7AF9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 892\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 892 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -892;
	} else {
		printf("Test Case 892 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB2FACAAF3A1C099CULL,
		0x463E75FFEFF50F0AULL,
		0xD3214132BC4E7809ULL,
		0xF42BF54E75D9FB3BULL,
		0xE7211E7A67CE407BULL,
		0x1CA641FFE8A22DE6ULL,
		0xC34A2F59555DE558ULL,
		0x07D0700F100A4EBCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0400000000000000ULL
	}};
	printf("Test Case 893\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 893 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -893;
	} else {
		printf("Test Case 893 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBC4BE896D5C833F2ULL,
		0x91DCE751AAC3FC42ULL,
		0xEAE1BBF455811160ULL,
		0xB0867B22A41163C0ULL,
		0xC0E699B92C3D0C1FULL,
		0xBE606C03C8C1A325ULL,
		0x3BE57B6500FFFF7BULL,
		0x56A5FDA326EE98D3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 894\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 894 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -894;
	} else {
		printf("Test Case 894 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3D43F4FE3B61552AULL,
		0x492F86463C3139C8ULL,
		0xAFE2C6D3AB36F924ULL,
		0xEDE16F1682DE1674ULL,
		0xC524D9B08DBD9B87ULL,
		0xDC35EAFD91B77A1DULL,
		0x4FBB6D5D404AE397ULL,
		0x11AECBFF78422672ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	printf("Test Case 895\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 895 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -895;
	} else {
		printf("Test Case 895 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4F222AC2902EF6D1ULL,
		0xC8076224ECD767A7ULL,
		0x1E2C76CF0FBC71B7ULL,
		0xDD7BE19F0CB4E372ULL,
		0x3221F11160A00D22ULL,
		0xC4DE9F8CDD5C620EULL,
		0x8A98E4F13311C606ULL,
		0x5C8587161D0345B7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 896\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 896 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -896;
	} else {
		printf("Test Case 896 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA2B65642C0CFB37FULL,
		0x8FE2742756EBEB86ULL,
		0x35451F7798C40799ULL,
		0x4465B7460004BF5DULL,
		0x7CAB1E35272AA310ULL,
		0x3CA9C4BCEDE4777FULL,
		0xA877A201783B8091ULL,
		0xE69F427A34468C42ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 897\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 897 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -897;
	} else {
		printf("Test Case 897 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA78DEC6477C8DFAAULL,
		0xF453CF231427FBAEULL,
		0x2453CAE299D79E36ULL,
		0x59ED7B53B91E2ADAULL,
		0xA1F992C720CCFCACULL,
		0xBE6E7AE4C4E42B57ULL,
		0x0283695CCD49A502ULL,
		0x1148B3CC6333766BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	printf("Test Case 898\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 898 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -898;
	} else {
		printf("Test Case 898 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC62E19FB7918D49AULL,
		0x85A0DA4FD739B5F1ULL,
		0xB7A75A3E45E6CE53ULL,
		0x4B873B837CD476B6ULL,
		0xA52683D817788640ULL,
		0x80CF0AC2ABFE036CULL,
		0x5D47D4BA38CB545FULL,
		0x80D21D40C5DA7569ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 899\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 899 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -899;
	} else {
		printf("Test Case 899 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF1CDB3B06A1AB38AULL,
		0xB81FCD49ED6AF1B0ULL,
		0x78DD6F3C0035E374ULL,
		0x292AE600C124DFC4ULL,
		0xE79F6EDF76BFF8BEULL,
		0xDA0CA1133758B3A2ULL,
		0xE75D0BD3CE1E10E0ULL,
		0x2F60625D38B17BF1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 900\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 900 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -900;
	} else {
		printf("Test Case 900 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x40B95C8687C564FAULL,
		0x1172C7B55DE2E3D9ULL,
		0x0BEE1DC7A70AAF96ULL,
		0x7F2513A5F0ECD720ULL,
		0x3FB965D4D6503508ULL,
		0xF4C6D115F9C21630ULL,
		0x446EF2E08ECCBFBCULL,
		0xBDC5A52D5A204575ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 901\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 901 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -901;
	} else {
		printf("Test Case 901 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x77E373A2618E0FDEULL,
		0xDF12C82EB8CEBF48ULL,
		0x32B591FF78BCD43EULL,
		0x35399D93A7CFBD68ULL,
		0x3C5E007F8AEA8315ULL,
		0x5B542744705111E3ULL,
		0x05DAC88DC2D0F24CULL,
		0x4C46DCACFCD6FB90ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 902\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 902 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -902;
	} else {
		printf("Test Case 902 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x296E758E69C842D5ULL,
		0x5EB4BC2E440753DEULL,
		0x52053C4FCAB67C35ULL,
		0xAD0FAD2D357B8BB5ULL,
		0xF4721135D856533DULL,
		0xEA14F463FF841397ULL,
		0x495FE3476DB3E3E2ULL,
		0xDCE153F8B3D31AE4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 903\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 903 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -903;
	} else {
		printf("Test Case 903 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEA43D2F8484AA101ULL,
		0xCE766DD4AFF00B6DULL,
		0x112428FF5332EAFDULL,
		0x854A3DE281725210ULL,
		0x52995914C230520FULL,
		0xE5E11C5A8AC87B96ULL,
		0x37CD36BC8259BFB2ULL,
		0xB1084F3293305265ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 904\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 904 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -904;
	} else {
		printf("Test Case 904 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2EB75DEE103461CBULL,
		0x4AA429541FA1A171ULL,
		0x5726401E0319F0CCULL,
		0xBE0FCDD844433596ULL,
		0x5100F83AC563709EULL,
		0x85F6F1372B765037ULL,
		0xDCF56A56C71B1A18ULL,
		0xE8DA215E4C4DC993ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 905\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 905 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -905;
	} else {
		printf("Test Case 905 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x810588C1F59B352AULL,
		0xB0421F06E657DD6DULL,
		0xA4D2C347685E366EULL,
		0x95380EF2A65F055EULL,
		0x040D9DD156D5419DULL,
		0x3C0EAC381CF01BFDULL,
		0xD539E1F5DD475207ULL,
		0x3107D1C664821463ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 906\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 906 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -906;
	} else {
		printf("Test Case 906 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x55A515E6F55335C9ULL,
		0x271A314BB30EEE2DULL,
		0xE4785FD52E7D772DULL,
		0x4EE2606DD2A77721ULL,
		0xAA5A855A2218D0ACULL,
		0xACD151F21AD56F59ULL,
		0xF3EE0A3F5397239BULL,
		0xB4ECD63550E0E245ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 907\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 907 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -907;
	} else {
		printf("Test Case 907 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x09A2899ADF481F0AULL,
		0xB542FE9159116B09ULL,
		0x3D07DA9D0DC350E0ULL,
		0x815EE488C2AD8687ULL,
		0x7FAA3A4BD874CDD6ULL,
		0x6E89F3FB17CF52ECULL,
		0xDD4F861201A4D3F0ULL,
		0xC2707541F8141121ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 908\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 908 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -908;
	} else {
		printf("Test Case 908 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0B29EFC989EC1062ULL,
		0xD59183CDFA0926AFULL,
		0x41A49092EF402E3DULL,
		0x11910C983D49630BULL,
		0xB4DEB8A92A1A686FULL,
		0x1B2FC5633007703EULL,
		0x3AFBC9E28F4E2699ULL,
		0x02D1252E067C6864ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0200000000000000ULL
	}};
	printf("Test Case 909\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 909 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -909;
	} else {
		printf("Test Case 909 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAB58C37166F87A49ULL,
		0x5C10D1C974B8590AULL,
		0xFAD29562F29ED9BDULL,
		0x822A0EBC70FE1C07ULL,
		0x98E7ADDB44557CE6ULL,
		0xFF235C49E2CCD932ULL,
		0xE71C2462D4A146BFULL,
		0x34089E2F07B47C72ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 910\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 910 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -910;
	} else {
		printf("Test Case 910 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2E645700FFA96A0BULL,
		0xE3151E110A64CFD5ULL,
		0xB87C74D8825D4851ULL,
		0xECC0BD368EBA1E23ULL,
		0x47B77E456A5EF395ULL,
		0x08106C85CC1C4AF9ULL,
		0xDAAA414025FA3B30ULL,
		0x3CBE4D3DBFE530BBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 911\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 911 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -911;
	} else {
		printf("Test Case 911 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBCA1358E0C892488ULL,
		0xCE3755AFD0BC022CULL,
		0xF97F37311FD9811FULL,
		0x22C79D2A77D65EA6ULL,
		0x4B5F470166784CDDULL,
		0x89E2F1712A5E9D33ULL,
		0x3DE710037882147FULL,
		0xC01ABD6547441628ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 912\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 912 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -912;
	} else {
		printf("Test Case 912 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8F1A146DC64CE7E3ULL,
		0xC05E4CACB925C9E4ULL,
		0x27D3752FB5E076FEULL,
		0xFEEB1DBB4DCDFCE5ULL,
		0x07A85E72EC29848AULL,
		0x01324750C1854AE3ULL,
		0x7BB32B914F4CAB9DULL,
		0x259F60EAB66D44BFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 913\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 913 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -913;
	} else {
		printf("Test Case 913 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x799D3D54F58C73AEULL,
		0xBC457399E41CD96BULL,
		0x9F12E04EB81A6194ULL,
		0x8C89E29B2C245DC1ULL,
		0x49274BE8CAA289F6ULL,
		0x23FD3CAFDB5FD18BULL,
		0x3F310C830F23A535ULL,
		0x560F516028E7A495ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 914\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 914 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -914;
	} else {
		printf("Test Case 914 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAECDF543825E1E1CULL,
		0xB4F385F2DF56F362ULL,
		0x8DB4AAAD4BBEE039ULL,
		0xDCC9CBED8012093DULL,
		0x33303FBB53F90789ULL,
		0x5478FC2C3E4ED779ULL,
		0x1AB088C67E7EEE5CULL,
		0x41ECE704ECA8448BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 915\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 915 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -915;
	} else {
		printf("Test Case 915 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF86DD9ED1FA971AAULL,
		0xC6E612C92C6FCD4AULL,
		0x73350D3A3A168F83ULL,
		0xDE63732B118B64D6ULL,
		0x1DB10D79C81A7E54ULL,
		0x0B9122555AE41075ULL,
		0xC517C4505A38FA51ULL,
		0x38EBBC539713190EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 916\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 916 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -916;
	} else {
		printf("Test Case 916 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCE7F9EA866B52FA5ULL,
		0x0095FB08611CD4E6ULL,
		0xCC4F5C7C42337230ULL,
		0x4E56DF4C6ADCA3A4ULL,
		0x9108805DE660B587ULL,
		0xBA71CD715AF0F715ULL,
		0x0B429820E910E99DULL,
		0xDB94AD4C6ECF09CBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 917\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 917 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -917;
	} else {
		printf("Test Case 917 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF459345F38874E63ULL,
		0xBAB38F6491B09FF5ULL,
		0x7CC7C722BEB9607DULL,
		0xA6B975E83A88FF1EULL,
		0xC5B98FAAF9438249ULL,
		0xBDDBE929EB1D0041ULL,
		0xFE77BF30D3414EEDULL,
		0x1B698AEDE7A79CF7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	printf("Test Case 918\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 918 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -918;
	} else {
		printf("Test Case 918 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFA5A8F23730E4653ULL,
		0xAE0E3C49709F4CAFULL,
		0x8A9D0A9D5BCA620FULL,
		0x47264F5DF88A36E0ULL,
		0xFACD891CB8A74B60ULL,
		0x6B0E2B975B4C44ECULL,
		0x3C4FA1F4DB80F183ULL,
		0xC50AB03F8E30B68AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 919\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 919 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -919;
	} else {
		printf("Test Case 919 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFFEEBC3FFB66E4C2ULL,
		0x71BD5AA282066C77ULL,
		0xBD41561128DF2C6FULL,
		0x27E064D1B7295E57ULL,
		0x2C2B88097EAD4FCFULL,
		0xF3565CAD503DF09AULL,
		0xC95BE2EC2EEE28C4ULL,
		0x83ED66F586A79ABDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 920\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 920 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -920;
	} else {
		printf("Test Case 920 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x08121C737D06B1D9ULL,
		0x1281D12C1F725DB6ULL,
		0xBA0BA9A4DC7C048CULL,
		0x9A66660495148688ULL,
		0x031A4369670A0B94ULL,
		0x307AA2483C60715CULL,
		0xB26884CEC6E39799ULL,
		0x4F459E4FA27E6326ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 921\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 921 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -921;
	} else {
		printf("Test Case 921 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC13FE53901DC5183ULL,
		0x76823936D704E2AFULL,
		0xC303B5FEC08A4CEDULL,
		0xB3ECD6EBCD986237ULL,
		0x20B4C705A23D9BDDULL,
		0xE20AF4ABFE84B0FAULL,
		0x7CD6C650A8422FCDULL,
		0xA70C5BE430257E93ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 922\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 922 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -922;
	} else {
		printf("Test Case 922 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF08B16BF6F4DC98BULL,
		0x44A92786A76F6916ULL,
		0xAA2AF12E5F4AB136ULL,
		0x6841AF9116B803CAULL,
		0xF90DC766851FE971ULL,
		0x8185521161CE5233ULL,
		0x0758510BB9BA00DBULL,
		0x4BC301926CE71868ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 923\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 923 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -923;
	} else {
		printf("Test Case 923 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAFB4303C63C6F5F3ULL,
		0xA78904CDA283DF21ULL,
		0x5EC2FBB5E497F5CDULL,
		0x57FC0C4B7B089FF6ULL,
		0x22EF62AC19A8A591ULL,
		0x0FDA948E5E025368ULL,
		0xC45B74D79F55DA64ULL,
		0xC67D2B0F6D57C10FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 924\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 924 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -924;
	} else {
		printf("Test Case 924 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7E87AF685EBC4F5BULL,
		0x2478FFEB4F190031ULL,
		0x4DD7032A8879EF67ULL,
		0x94A78AEC524A641DULL,
		0x1A5192DD55A7075EULL,
		0xA8E2C0C0E1127510ULL,
		0xC06D89BEE9F345CDULL,
		0xF306EA767A681893ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 925\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 925 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -925;
	} else {
		printf("Test Case 925 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7388AB9C615ECFADULL,
		0xEBB836B318134734ULL,
		0x78936907FA8471C3ULL,
		0x6EA57017BFE4093EULL,
		0xA01DC304E4EB3B26ULL,
		0x8A1566A5E9E6DF9EULL,
		0xB01286FEC1BA0256ULL,
		0x5E2C98EF43C8AA13ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 926\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 926 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -926;
	} else {
		printf("Test Case 926 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x39BECB5B53A40BBAULL,
		0x573698A2F8ECE7CBULL,
		0x0679A5E6684D947FULL,
		0x87A94852A3123167ULL,
		0xA2B92362C50687EEULL,
		0x081AC3C4F3E94A72ULL,
		0xF1EFB15822235150ULL,
		0xD7AAD4A7D7D1A280ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 927\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 927 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -927;
	} else {
		printf("Test Case 927 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x905178E73565A412ULL,
		0x2CA17C9D9ED42716ULL,
		0xA305E78A9D4F733FULL,
		0x3E742219F22E97D9ULL,
		0x14C3937EB345CD35ULL,
		0x01A14E6C5AE238B3ULL,
		0x0D4FEB48E11DED35ULL,
		0xE27EC367F1A823DCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 928\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 928 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -928;
	} else {
		printf("Test Case 928 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x17372FCDBAD5E760ULL,
		0xE8DB3CC74DB62E79ULL,
		0x4E146EF562DC8FECULL,
		0x2F2D833921BD99D8ULL,
		0x752302505846472FULL,
		0x16550C0BD1B169EFULL,
		0x5B5936FD0278D421ULL,
		0x7BE0DAD1B795FD62ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 929\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 929 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -929;
	} else {
		printf("Test Case 929 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x537A665F427CA6C4ULL,
		0x960DCD4BE3665580ULL,
		0xF55BC2B278E02EAEULL,
		0x0CC64DA7071A5D19ULL,
		0xF3DE07B34446473CULL,
		0xA4534F1BA2A08B20ULL,
		0x741F29DD2C2DA49AULL,
		0x10973AC97E4D4ECEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	printf("Test Case 930\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 930 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -930;
	} else {
		printf("Test Case 930 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3B0F20039D8350B7ULL,
		0x100404DED0C37E49ULL,
		0xC6106F2627384C01ULL,
		0x9C170DC4349EC56FULL,
		0x3E8AE9528903CC52ULL,
		0x679FB50C0A82DEE4ULL,
		0xECDCDB595A1CDC13ULL,
		0x2ED56A683444F070ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 931\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 931 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -931;
	} else {
		printf("Test Case 931 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x24C749BBDA93FB1CULL,
		0xBAE3D4BE6B1FAF56ULL,
		0xAC7D52E004321B71ULL,
		0x426BC6C4258288C3ULL,
		0x4BBF4C7DCDBCC16CULL,
		0x5B84733FD990A980ULL,
		0xE1F70A2400F6F1FCULL,
		0x3B955798B7D85ADDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 932\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 932 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -932;
	} else {
		printf("Test Case 932 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x680A68E552D316DBULL,
		0x99CEFEE348616375ULL,
		0xEFBCFF054C94E67FULL,
		0xE8D889437F129606ULL,
		0x28D7AF3DFCE3F68BULL,
		0x5863DDF351FDFAAFULL,
		0xC80CA5C11B1A6EA7ULL,
		0x87C1E2A327B11974ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 933\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 933 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -933;
	} else {
		printf("Test Case 933 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7C86F50CE0B2D7D5ULL,
		0xC26DDB349BB3999EULL,
		0xBC16BD1BBC6A67C2ULL,
		0x7D13DD68B0830C13ULL,
		0x1BFB13122052CC20ULL,
		0x9C8E9A8CA3F4D72CULL,
		0xFDDEDF537C97FAF6ULL,
		0x56A2BE731F0E6571ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 934\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 934 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -934;
	} else {
		printf("Test Case 934 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1AB5E2397E9F4651ULL,
		0xE8C4B98548F00029ULL,
		0x35D2C7B832157B50ULL,
		0x0B647B4FDA3BCD6BULL,
		0x55B6E84C319AE485ULL,
		0xF7C0FA47B3CF37F3ULL,
		0x3E14CD7A20A4C824ULL,
		0x66BAFA6063D28630ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 935\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 935 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -935;
	} else {
		printf("Test Case 935 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC5B488CA1C575CBFULL,
		0x638631C18BDE040FULL,
		0x08BE0AA6B443ADBCULL,
		0x83C13DD202C5C2C8ULL,
		0xBB39581C2214BDBDULL,
		0xF678910A0CFF7964ULL,
		0x5B5BADE4672817ECULL,
		0xA00D8DBB8C6DD2D5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 936\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 936 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -936;
	} else {
		printf("Test Case 936 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x087A535E8C415976ULL,
		0x0BC3E900D7C0930CULL,
		0x2B454D129E67917FULL,
		0xAFEE27D98545E969ULL,
		0xAD8139B3B2D0260CULL,
		0xC300F2971BB3E412ULL,
		0xA13B09D418EB36E1ULL,
		0x4D316D97E27C74A0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 937\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 937 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -937;
	} else {
		printf("Test Case 937 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFE990461985EABBBULL,
		0x60CFD224F4783A2FULL,
		0xA493AAA49192D19EULL,
		0x8E7ECB381E1F33D0ULL,
		0x4211C1B96C407354ULL,
		0xB5D9CFB2D53DA5C3ULL,
		0xFD2A7C6D0C0B0569ULL,
		0xBA6C13E5BC34FBCFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 938\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 938 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -938;
	} else {
		printf("Test Case 938 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x39B75C8B16FFD75FULL,
		0x90152444AC839197ULL,
		0xFC0FCF3B2EA96326ULL,
		0xB41DA3FFDC807239ULL,
		0x9CC915878E84D462ULL,
		0x29E6A574302A594EULL,
		0xD87F94E58A69FB98ULL,
		0x8E599E628669BEE0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 939\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 939 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -939;
	} else {
		printf("Test Case 939 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF29E9DF764132EF5ULL,
		0x3A7E8F4FBEB015E6ULL,
		0xF79CB8D307F0F41CULL,
		0x96914F88E1B67E4FULL,
		0x528F3644438E0B14ULL,
		0xC8618A8A9A7D3233ULL,
		0xEBC3ABA9CA6121EFULL,
		0x01D074D24BD886F8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0100000000000000ULL
	}};
	printf("Test Case 940\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 940 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -940;
	} else {
		printf("Test Case 940 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE35BB64A493D1B18ULL,
		0x7BD440EED56FBD4AULL,
		0x9350E6E0F615B7D1ULL,
		0x7E665DAB92A774E8ULL,
		0xF65DFF0F61DCE3BBULL,
		0x3D62E48BF9B0DE15ULL,
		0xA08CE0F01E823451ULL,
		0xC5BC4D24DBAEDDB7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 941\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 941 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -941;
	} else {
		printf("Test Case 941 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBF270C1257E7F270ULL,
		0xD3989EE1BA250F8CULL,
		0x373E0390AC20D21CULL,
		0x616BE3EBF6C790B3ULL,
		0xB33C596F79313A1AULL,
		0x8B5F1EF4C53D4238ULL,
		0x25106D0E214FF7DCULL,
		0x7FC4F7CABBF1E298ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 942\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 942 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -942;
	} else {
		printf("Test Case 942 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD6E3EB4F7ADC1A98ULL,
		0x4CE289B5B4581CC3ULL,
		0xB409ED7947D2002FULL,
		0x8FB48537515FE5B7ULL,
		0x47C2E5D50436B624ULL,
		0xEA41ED3C190A81E8ULL,
		0xD1195AD1E1091E74ULL,
		0x959C67F278CD7A15ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 943\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 943 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -943;
	} else {
		printf("Test Case 943 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA3492F59295564D6ULL,
		0x9A88687CD302651EULL,
		0x49BECCF5551418EFULL,
		0x26B8E85B6379E0B2ULL,
		0xB1D4B016F7327DDCULL,
		0xD33C828D3A5AEDECULL,
		0x2A13B105CE710BE4ULL,
		0xE2F4D7432AB43916ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 944\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 944 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -944;
	} else {
		printf("Test Case 944 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD9EAA95B6C87DBBBULL,
		0x44AD99C98AE49517ULL,
		0x4046DC4C121FB6F7ULL,
		0xB2DD1E25E0AF402AULL,
		0xF5CCEB1B5E40B3DBULL,
		0xBEE2F3C8D27BF64BULL,
		0x5111BE619142243DULL,
		0x261A421C2750DF75ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 945\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 945 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -945;
	} else {
		printf("Test Case 945 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1F95773A566F7472ULL,
		0x2F5481FD1B64AF4BULL,
		0xDC7B96023F1CB9A1ULL,
		0x39D3A5D5D7B07609ULL,
		0xA154B149655C9307ULL,
		0x86B2159079FF918BULL,
		0xB2C5F52B33F1780CULL,
		0x15F30198EC8162F9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	printf("Test Case 946\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 946 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -946;
	} else {
		printf("Test Case 946 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA95B929B5CF81C1EULL,
		0xA496E682213BBDDAULL,
		0xA71E8ABC609B2066ULL,
		0x53F4CC82FF2345BEULL,
		0x123843036CC1854AULL,
		0x982DC2344FB260F5ULL,
		0xB9634B53F7C8301AULL,
		0x01F8555378F17730ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0100000000000000ULL
	}};
	printf("Test Case 947\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 947 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -947;
	} else {
		printf("Test Case 947 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x58AEA3E5F2FA3D3DULL,
		0x80AC492D34091D45ULL,
		0xFF86D7B60010B694ULL,
		0xE8D75BD9129A5677ULL,
		0x374FBE3F00A4BD78ULL,
		0x67AA5AB2AE9BB517ULL,
		0x17B49201D5AC4360ULL,
		0xC3096C63F2927746ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 948\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 948 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -948;
	} else {
		printf("Test Case 948 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x714355F0D121E97FULL,
		0xFF2C503035B3D491ULL,
		0x1C94CC657A940F13ULL,
		0xE049A5FE5C815B46ULL,
		0xAADA349A6DECB98FULL,
		0xB7BF39071C4D8F05ULL,
		0xA3F59DBB2A84655BULL,
		0x75482FEFB4621F30ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 949\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 949 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -949;
	} else {
		printf("Test Case 949 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCBDB9B947C18F7F5ULL,
		0xF18537613A9A9E4BULL,
		0x0ABFAE9801F9857AULL,
		0xEB968E48FB10802EULL,
		0x81A4A36F80C7F76CULL,
		0x9BBF4E39F46CC270ULL,
		0x2D47AE2BCB1BD228ULL,
		0x6283389A79F39761ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 950\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 950 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -950;
	} else {
		printf("Test Case 950 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD3FC2BB990783BFFULL,
		0x3432791758CE081AULL,
		0x87EFD26E09068E36ULL,
		0x851BCDC140FBA08AULL,
		0xB3F3C616750F85EBULL,
		0x804E1A444CB716CBULL,
		0xEAA252A388BCE3C1ULL,
		0xC86EA0B1CEFFCF99ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 951\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 951 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -951;
	} else {
		printf("Test Case 951 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x94FFD396195E74D8ULL,
		0xCF5A277034E8417CULL,
		0x104E442039869F0BULL,
		0x5A945C9F05227A1FULL,
		0x74B7B4BBC169F816ULL,
		0x5A8D33403D728175ULL,
		0xA6184498E6C2DA3AULL,
		0xC369D5DE7632DF87ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 952\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 952 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -952;
	} else {
		printf("Test Case 952 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5E0BAA7654277E3EULL,
		0x2F1C9A6E89FB440DULL,
		0xCA2E46112D618FB2ULL,
		0x5580A08AB54D818EULL,
		0x2B0D3C3DC6B1F04DULL,
		0xD8900FD90878D787ULL,
		0x15557B0E509F03BCULL,
		0x06A4C72ECF112678ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0400000000000000ULL
	}};
	printf("Test Case 953\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 953 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -953;
	} else {
		printf("Test Case 953 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0688240A2D88AFA9ULL,
		0x3C96A1762A6C87C1ULL,
		0x1227461FCC56A6A5ULL,
		0x1651040F424D7AECULL,
		0x5FC4D06F32C638B7ULL,
		0xB7F6CB62D7DB67C3ULL,
		0xB98C9816EF2293D3ULL,
		0xD5AD8D3CC8F28CD1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 954\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 954 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -954;
	} else {
		printf("Test Case 954 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x10434776E4B0260EULL,
		0xB1DF2423A9B8C639ULL,
		0x2998CA64A1AC73CCULL,
		0x715171E07A8E3B68ULL,
		0x37E46FDE5E9F75D9ULL,
		0x360040AAA782F7CAULL,
		0x64CB57AE93ECACE0ULL,
		0x23D8A003F2A7360EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 955\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 955 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -955;
	} else {
		printf("Test Case 955 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x95AD756E07DBA737ULL,
		0x01CCAEED78DDF6AAULL,
		0x8FAAEFEF86541970ULL,
		0xB7F8626C6B2DC2E0ULL,
		0xDE387751CC589FCFULL,
		0x60A501D3F5DDBB39ULL,
		0x10493710079CD076ULL,
		0xA0D4671BAD00C7BEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 956\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 956 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -956;
	} else {
		printf("Test Case 956 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x71B81CCF9BB96309ULL,
		0xB2610ED7AD92B6F2ULL,
		0x7E8EEEE192F9E7C9ULL,
		0x9952188A387AFE79ULL,
		0x7CAA5209C3C61EE8ULL,
		0x9906D47F1CB47718ULL,
		0x443C01AA04E7E943ULL,
		0x9A2809F48E15CABBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 957\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 957 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -957;
	} else {
		printf("Test Case 957 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3ABD3784FE2E91CFULL,
		0xAF9AB712C0F4DC84ULL,
		0x74B57812D3D67EAAULL,
		0xC3502AD3B9BC6AFBULL,
		0x4E92EF17200E91C7ULL,
		0x5A0598A9F0B29073ULL,
		0x9F23CFB12F30591CULL,
		0x0CB3A7D0209B56D3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0800000000000000ULL
	}};
	printf("Test Case 958\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 958 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -958;
	} else {
		printf("Test Case 958 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x67503194BA7DA5FCULL,
		0xD2FBA641D41368DCULL,
		0xBA4D65B31AD7803DULL,
		0x36500ED6C7C0328FULL,
		0xC5A4BE624E3CABDAULL,
		0xBFEAE7CE7575D6BAULL,
		0xC318BFD040AD029EULL,
		0xF45F4E36C3D29B4AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 959\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 959 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -959;
	} else {
		printf("Test Case 959 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x643BFA1A9ACFBE6DULL,
		0xADAAC2C376C408A4ULL,
		0xE5EF904F6279E252ULL,
		0xC2549A584A4D68FCULL,
		0xCA9B5F617807D70AULL,
		0xDC9D4627B409C408ULL,
		0x5B7EF0B7A94FF265ULL,
		0xCA321386FCD07D0EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 960\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 960 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -960;
	} else {
		printf("Test Case 960 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3F7A64306BA77448ULL,
		0x06D9F078CAD8D4D0ULL,
		0x876C1DEEAD3F1C9DULL,
		0xD2E981D33356BA7AULL,
		0xAF1F62DCBEE1761EULL,
		0x29DA16EBF653ABBFULL,
		0xE15B03CBBA6FA9ADULL,
		0xF0C519BC6A753B38ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 961\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 961 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -961;
	} else {
		printf("Test Case 961 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0F600EBB671E398BULL,
		0x9DCE4C82C20202B2ULL,
		0xB35426A0EA388B92ULL,
		0xEAFFB0FDA41B0FC9ULL,
		0xACE74CC8792363CDULL,
		0x79496C50FB01FA14ULL,
		0x6774728495497ED9ULL,
		0x4CB5532784146625ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 962\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 962 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -962;
	} else {
		printf("Test Case 962 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4D43E33242D70BB8ULL,
		0xA8E0297B3C96ACD3ULL,
		0x2E12DFE3ED16F0EEULL,
		0x410C0CC80E72D8F4ULL,
		0x06BF82F43BBB802CULL,
		0x5C58077AE497663CULL,
		0xA718587D4CD02AF1ULL,
		0x49FD6CFFAC2843E3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 963\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 963 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -963;
	} else {
		printf("Test Case 963 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEF8BDDF18A365FEFULL,
		0x6895BD638DFEA2B1ULL,
		0x74D16117B5E539F4ULL,
		0xD268C00CF1C2649BULL,
		0xCA912AAD1CA7517AULL,
		0x8B80062591F60CE5ULL,
		0x9A48FABD0F991572ULL,
		0x8770D64FE5E93737ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 964\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 964 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -964;
	} else {
		printf("Test Case 964 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC56654DCF1EE9F3EULL,
		0x29F7BFE4DB402584ULL,
		0x7CCAD6F169E20326ULL,
		0xD461E8286A07B6C5ULL,
		0x794E509DAD8B4DB6ULL,
		0xD85EBBA3D7017357ULL,
		0xAE516B423B2C8DDCULL,
		0x893898C9FDECCED7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 965\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 965 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -965;
	} else {
		printf("Test Case 965 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7018259145C056E1ULL,
		0x305BA0AF8C068EDCULL,
		0xAE14F69B7E78F242ULL,
		0xC7CCF20E62A0D4D2ULL,
		0x65FEF96C3F29BB1FULL,
		0xFCD62F950EC68CA3ULL,
		0x1220C952C625E307ULL,
		0x739D8E41786EEF57ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 966\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 966 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -966;
	} else {
		printf("Test Case 966 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x04A71EFA7146C3F6ULL,
		0x2A8607E9FB042D5FULL,
		0x6A9DA8B472E33629ULL,
		0x07C20CE8268A3A80ULL,
		0xFE7171CDE539423AULL,
		0x0F437408FAD4F814ULL,
		0x41D3A7B65AD325CEULL,
		0x77E2BBC926BEE4E7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 967\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 967 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -967;
	} else {
		printf("Test Case 967 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBBDAB589ECDB0524ULL,
		0x229A9300C6F2BD4AULL,
		0xCBFF3ABEAD03B919ULL,
		0x38372BEBB15E7AFDULL,
		0x73784DE9B6A771FAULL,
		0x5C3091DCC49304B9ULL,
		0x8F409866EB384585ULL,
		0x9C60E0EE892E8E80ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 968\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 968 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -968;
	} else {
		printf("Test Case 968 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE458105E361E57BBULL,
		0x54B537C459A96A59ULL,
		0x5A5D142667FA0923ULL,
		0x470E48329BCCF925ULL,
		0x6859DB50E0FCB49FULL,
		0x0A182639AEB9D4DDULL,
		0xF2A13F6CA18031E3ULL,
		0x7DD07944EBF0D1A0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 969\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 969 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -969;
	} else {
		printf("Test Case 969 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE8D77CA7ABF6C301ULL,
		0xFB3EEB29B5B79037ULL,
		0x03BF491FB3C77B25ULL,
		0x23B416C865F2E78BULL,
		0x8B485092ACFC7D0BULL,
		0xA559C5C5AB627EB6ULL,
		0xB54278A792B8D88FULL,
		0xCA5B69DBFB6517C4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 970\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 970 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -970;
	} else {
		printf("Test Case 970 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x670B6BB496C29677ULL,
		0xD7374054365EBE3AULL,
		0x4D9B86E1D2F9D520ULL,
		0x57D05A0B26360024ULL,
		0x29A1CCFDDDBF4DE4ULL,
		0x8ABAF15EE86A96E2ULL,
		0x68103964DCCDD77CULL,
		0xB6577D18BBCB0D32ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 971\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 971 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -971;
	} else {
		printf("Test Case 971 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0B242A0172C82CA4ULL,
		0x2C108B6DFED68DCAULL,
		0xC6AFE973FFB4897AULL,
		0x5871F45A2BC3B2FEULL,
		0xBBD37C41A2E90A48ULL,
		0x7C018AB451B3B35EULL,
		0xCCC9E6682D5319CFULL,
		0xC1689C7FB38137A1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 972\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 972 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -972;
	} else {
		printf("Test Case 972 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x743B158BFECB8B9DULL,
		0xC2797ED814D61DDEULL,
		0xFA110ACC79BE7AA0ULL,
		0x34D431EEFBC34419ULL,
		0xE22C105CD8018ED6ULL,
		0x57A30B94394BCF4EULL,
		0x8F81209708652149ULL,
		0x970DE60D1CEA1B6AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 973\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 973 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -973;
	} else {
		printf("Test Case 973 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x77BF9A1BBFD0A2E1ULL,
		0x22F87ECA612047B3ULL,
		0x46DD7559DCCE5508ULL,
		0x01F9434A2AE86F11ULL,
		0x2720BE27F39E8303ULL,
		0x02EB5DBEF77E6C40ULL,
		0x70E45E189DCC360BULL,
		0xEC11F32EB696898BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 974\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 974 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -974;
	} else {
		printf("Test Case 974 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3B8B63A47B7838ECULL,
		0x36178A722BECA228ULL,
		0x43962BFF5218AE25ULL,
		0xD61114CA76732A43ULL,
		0x0C78E915260B6F17ULL,
		0xF2A9BED6DA5525FFULL,
		0x04241E45BB54F6D7ULL,
		0x79143DC07D5F685FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 975\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 975 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -975;
	} else {
		printf("Test Case 975 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x80806FFBB769BBAEULL,
		0x29FCC8C07E3D66B3ULL,
		0xC596EB4BDD251C42ULL,
		0xCDF97E775EFB72DEULL,
		0x96901ADDFDF0A8A0ULL,
		0x482D366A6B851101ULL,
		0xB3EF36B9BB116831ULL,
		0x8262818C653015AAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 976\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 976 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -976;
	} else {
		printf("Test Case 976 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x083C2AF793CC56C0ULL,
		0x974DEDEAC2A26520ULL,
		0x8ADBFBE2150581AAULL,
		0x1A2DE80273046211ULL,
		0x0A6AE5FDC2A0B458ULL,
		0xCEF9D3C08DE1FF91ULL,
		0xCF5AE367B27C32DEULL,
		0x1C27EFBCB0297F59ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	printf("Test Case 977\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 977 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -977;
	} else {
		printf("Test Case 977 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5B317BF748B5262CULL,
		0xD749DDF6B2783737ULL,
		0xAE2D39C009381041ULL,
		0xD5F70AD1ED8D6759ULL,
		0x51463718480F2F73ULL,
		0xF8E1C46A81B73774ULL,
		0xEAAC810E2072FDE8ULL,
		0x0B3CD3E3D72467BFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0800000000000000ULL
	}};
	printf("Test Case 978\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 978 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -978;
	} else {
		printf("Test Case 978 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x866CF73AC6A3E92FULL,
		0x861E8032B7D3EE8FULL,
		0xB84316D5198D6C7CULL,
		0x0A559EB98233FC4AULL,
		0xA500265280646169ULL,
		0xF6EEAF140390F054ULL,
		0x9D1BFF1F351BFF64ULL,
		0xF3ED4E87C4DFAF50ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 979\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 979 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -979;
	} else {
		printf("Test Case 979 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF97AFAF365F46EACULL,
		0xCA7A706C4B0376C3ULL,
		0x244AE9E68312A000ULL,
		0x05023533B0237861ULL,
		0xF1CB693D053E191DULL,
		0x42CCE1DE6EABF97EULL,
		0x2C3971FB8771642FULL,
		0xEBD98EB50B4A1C97ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 980\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 980 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -980;
	} else {
		printf("Test Case 980 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB2F2F97B7B571622ULL,
		0x20FE3B5B1522E32DULL,
		0x3C858ABE16EF2887ULL,
		0x083EAF35A3A59439ULL,
		0x0BC620E1E6B40C27ULL,
		0x084DC7606628770AULL,
		0x6C1722963DA1639CULL,
		0xB3EC34564750EB98ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 981\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 981 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -981;
	} else {
		printf("Test Case 981 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x24207CA375755824ULL,
		0x5C49A0645718FFF1ULL,
		0x1DDD0B71002D92C0ULL,
		0x393F7A8B898B0B60ULL,
		0x369CA511E0BF633CULL,
		0xCC66F1D1BC1E8837ULL,
		0x0F33588BAC1C1DF2ULL,
		0x23E0C032D7CB9728ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 982\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 982 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -982;
	} else {
		printf("Test Case 982 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF7DD191A471BBC3CULL,
		0xEBE60E901D4BD24BULL,
		0x6E2E828E83414255ULL,
		0x0EF7376821F4072EULL,
		0x5F8A3040645AB81FULL,
		0x55C219EC6BF008ACULL,
		0x458FBB0DFC45B69EULL,
		0xEF9833E130BAF7A7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 983\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 983 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -983;
	} else {
		printf("Test Case 983 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x46D3C8BF1771F481ULL,
		0xA755051143D48A34ULL,
		0x59623742F9CCFEC6ULL,
		0xC9970754692C7264ULL,
		0x2ACDD5274DF6FCF0ULL,
		0xBBCC41B1F77B51C3ULL,
		0x524DF6A46CFB952CULL,
		0x33A0CD3496B28872ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 984\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 984 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -984;
	} else {
		printf("Test Case 984 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE21EF49AFEFDC7E7ULL,
		0x0A2DF3FF0EDB15EFULL,
		0x33B7C7F28A041030ULL,
		0xF8718EAA2454E11CULL,
		0x4AC974A8E81EA60EULL,
		0xD663C96B1B045E20ULL,
		0x488B933F3F129455ULL,
		0xC3BB9D314EF27B3EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 985\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 985 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -985;
	} else {
		printf("Test Case 985 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEB5473967C36F14BULL,
		0x7D987619FC5894C1ULL,
		0xE80FFD8EC0C0E0CCULL,
		0x17B260C6F41A39D9ULL,
		0xCF0903496C82A17EULL,
		0x0FA08AA7B49DC5F7ULL,
		0x85D073C0CEAAB35AULL,
		0xC859B5C55BFCC09DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 986\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 986 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -986;
	} else {
		printf("Test Case 986 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9F43503BAED000C0ULL,
		0x9C40393E85F22D13ULL,
		0x172F20089D1F6E29ULL,
		0xD9D2785380BBA79EULL,
		0x83974C5D03279477ULL,
		0xD40843583A9D47D0ULL,
		0x6FE08795EB70F5B4ULL,
		0x139AA4ED8F824EC5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	printf("Test Case 987\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 987 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -987;
	} else {
		printf("Test Case 987 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD23B4C29BA1D3469ULL,
		0x0B783FD9757A60E4ULL,
		0xAAAC1FAAFF5058C9ULL,
		0x2D2505088650355FULL,
		0xF4A9990A013B62B6ULL,
		0xC7BAC5773A012A89ULL,
		0x8A58B7547F2CF64EULL,
		0x1E01AB080BF59EAEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	printf("Test Case 988\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 988 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -988;
	} else {
		printf("Test Case 988 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x345AF80E20E3C628ULL,
		0xF33A4C374A46CA72ULL,
		0x423EDFA9302B9A97ULL,
		0xBED60BF85B5DC236ULL,
		0x15B8E08DA62D1292ULL,
		0x78D8641D1F29A76FULL,
		0x2E846C4CD0A08557ULL,
		0x1C4A88A08E243D68ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	printf("Test Case 989\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 989 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -989;
	} else {
		printf("Test Case 989 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB83DAB1A95996409ULL,
		0x7F1DF248805EC816ULL,
		0x16D589D3C2751685ULL,
		0x7030D3535E3DF7FAULL,
		0x39C6452B3432CF9EULL,
		0xAB78713C659EA9CCULL,
		0x0201FCF3BB0B057EULL,
		0x15D8AE4DEEC27E04ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	printf("Test Case 990\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 990 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -990;
	} else {
		printf("Test Case 990 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x701F2742199F3A78ULL,
		0x23EF6AFDE736BB0AULL,
		0xB5F4309E83D704D4ULL,
		0xBB8A5F2FD5CE019EULL,
		0xC598F5ABCE575B8AULL,
		0x8809B7B702032438ULL,
		0x598F5E061BA647C8ULL,
		0xE4A0FF32FBE3B84DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 991\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 991 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -991;
	} else {
		printf("Test Case 991 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB218F02C91C85739ULL,
		0xD55DFBA3FDA9D74BULL,
		0xE9D1E2F30A5DA428ULL,
		0x80788AA1B24E338BULL,
		0xA4328EF3914145ADULL,
		0x16ACF7D6B107871AULL,
		0xEB951F6B243574E0ULL,
		0xA1F69F2C7AE28669ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 992\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 992 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -992;
	} else {
		printf("Test Case 992 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFB747E866E4F0FABULL,
		0xC71CCF981789B727ULL,
		0x2B259404B20DABA0ULL,
		0xA1B88CBBD0C584C0ULL,
		0x295352C821EC36F1ULL,
		0xFD0B0EFFF1EC0391ULL,
		0xA3629E5E0664BDB8ULL,
		0x5C96775F1E477CD5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 993\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 993 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -993;
	} else {
		printf("Test Case 993 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC564ECD5057CF47CULL,
		0x69CEDCF8F385DFB7ULL,
		0x84AC070DFBCE9ADFULL,
		0x3E8823D9316A403BULL,
		0x8D8FC5D634F9F519ULL,
		0x6329B51CD6C7BA9EULL,
		0x7B84A5EFED9E392FULL,
		0xB8837DBA1027BC5EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 994\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 994 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -994;
	} else {
		printf("Test Case 994 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEE3BD4C5097924A0ULL,
		0x385E03D218FF15FAULL,
		0xF7D61F45A684BB24ULL,
		0xF0CD5323F0FB995AULL,
		0x39B5B5535EE4A789ULL,
		0x066E1899071A5C81ULL,
		0x70EF3944C1351E15ULL,
		0x9804B1C67F74B4B9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 995\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 995 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -995;
	} else {
		printf("Test Case 995 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA446F81644E320BBULL,
		0x126CDD99FB8586ABULL,
		0x09C4A9B52E97562FULL,
		0x00CF74FD2A804270ULL,
		0xA64BC083124246C7ULL,
		0x633AAB606B411A8BULL,
		0x78FCD55987AB884EULL,
		0x2B3FAF51D9AA6BD4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 996\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 996 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -996;
	} else {
		printf("Test Case 996 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2AAFD26DF93F915DULL,
		0x1FA86FB66DB2A0DCULL,
		0xFA2F39910B552C2EULL,
		0xABD575926382D503ULL,
		0xDB525A683C2631DCULL,
		0x05716874DE48191AULL,
		0x489D670404B5EEF3ULL,
		0xA39EC9507C99298DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 997\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 997 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -997;
	} else {
		printf("Test Case 997 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x32152DE0A72D8785ULL,
		0x9A8A34BBB5B7249CULL,
		0x1969E0E4FFE70B62ULL,
		0x9CED8EE4FEA29704ULL,
		0xE9CDEE6F9AC220EFULL,
		0xBC8D44B451D5485EULL,
		0x80D2A13F10B90CF8ULL,
		0x54DCB7832A63B40AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 998\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 998 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -998;
	} else {
		printf("Test Case 998 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x18CDC42718ED5086ULL,
		0x215DE920377825DFULL,
		0xD221736FEE466E16ULL,
		0x03EDB60F6A0CAFD1ULL,
		0xBABDA7EA8B96DB90ULL,
		0xBC465283AF2763FFULL,
		0x9AA7869C5D59CF31ULL,
		0x3AECFF73DAB29A5AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 999\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 999 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -999;
	} else {
		printf("Test Case 999 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1578D2261D4A1F71ULL,
		0xE3CAEC94F59619DDULL,
		0x53A538E0CA6A9DCAULL,
		0x504CD4F523D4C37EULL,
		0x1AC3E1BACA4E3553ULL,
		0xB8C7CF3D85F04F58ULL,
		0x1019E00DD103DC45ULL,
		0x3FAC8E3DA574A6DDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 1000\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 1000 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -1000;
	} else {
		printf("Test Case 1000 PASSED\n");
	}
	printf("---\n\n");
	return 0;
}